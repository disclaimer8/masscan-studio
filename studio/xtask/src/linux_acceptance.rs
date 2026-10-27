//! Disposable GitHub VM acceptance only; never a product polkit policy.
use super::*;
use studio_platform::{linux, trusted, unix::Identity};

struct Policy(PathBuf, PathBuf);
impl Drop for Policy {
    fn drop(&mut self) {
        let _ = Command::new("sudo")
            .args(["-n", "/usr/bin/rm", "-f", "--"])
            .arg(&self.0)
            .status();
        let _ = fs::remove_file(&self.1);
    }
}

pub fn verify(root: &Path) -> Result<()> {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") || Identity::current()?.uid == 0 {
        return Err(
            "Acceptance requires an unprivileged user in a disposable GitHub Actions VM".into(),
        );
    }
    if studio_protocol::raw_profile_enabled(studio_protocol::Backend::MacFeth)
        || !studio_protocol::RAW_PROFILES.is_empty()
    {
        return Err("Raw scanning must remain disabled".into());
    }
    run(Command::new("cargo").args(["build", "--locked", "-p", "studio-runner"]))?;
    // CI uses the repository's default target directory. Explicitly refuse an
    // override rather than testing a stale unrelated runner from another build.
    if std::env::var_os("CARGO_TARGET_DIR").is_some() {
        return Err("CI acceptance requires default target directory".into());
    }
    let source = root.join("target/debug/studio-runner");
    let prepared = runner_setup::prepare_source(root, &source)?;
    let source = prepared.join("studio-runner");
    let hash = trusted::file_hash(&source)?;
    let destination = linux::installed_path(&hash)?;
    let script = linux::install_script(&source, &hash)?;
    if !destination.exists() {
        run(Command::new("sudo").args(["-n", "/bin/sh", "-c", &script]))?;
    }
    trusted::verify(&destination, &hash)?;
    let policy_path = PathBuf::from(format!(
        "/usr/share/polkit-1/actions/dev.masscanstudio.ci.{hash}.policy"
    ));
    if policy_path.exists() {
        return Err("CI policy already exists; refusing replacement".into());
    }
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig><action id="dev.masscanstudio.ci.h{hash}">
<description>Disposable Studio CI runner only</description><message>Studio CI bootstrap</message>
<defaults><allow_any>yes</allow_any><allow_inactive>yes</allow_inactive><allow_active>yes</allow_active></defaults>
<annotate key="org.freedesktop.policykit.exec.path">{}</annotate>
</action></policyconfig>
"#,
        destination.display()
    );
    let xml_path = std::env::temp_dir().join(format!("studio-ci-{hash}.policy"));
    // Never include the permissive test-only policy in distributable artifacts.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&xml_path)?;
    use std::io::Write;
    file.write_all(xml.as_bytes())?;
    drop(file);
    let policy = Policy(policy_path, xml_path.clone());
    run(Command::new("sudo")
        .args([
            "-n",
            "/usr/bin/install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0644",
        ])
        .arg(&xml_path)
        .arg(&policy.0))?;
    // Restart only the disposable CI VM's system polkit authority so it has
    // loaded this exact policy before the real launcher probe begins.
    run(Command::new("sudo").args(["-n", "systemctl", "restart", "polkit"]))?;
    runner_setup::probe_source(&source)?;
    verify_owner_death(&source, &prepared)?;
    drop(policy);
    if Path::new(&format!(
        "/usr/share/polkit-1/actions/dev.masscanstudio.ci.{hash}.policy"
    ))
    .exists()
    {
        return Err("CI authorization policy cleanup failed".into());
    }
    println!(
        "PASS: actual pkexec, UID/PID authentication, handshake, closed raw gate, session exit, endpoint and policy cleanup"
    );
    Ok(())
}

fn verify_owner_death(source: &Path, prepared: &Path) -> Result<()> {
    use std::time::{Duration, Instant};
    let ready = prepared.join("owner-ready.json");
    let mut owner = Command::new(std::env::current_exe()?)
        .arg("linux-authorization-owner-fixture")
        .arg(source)
        .arg(&ready)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let result = (|| -> Result<()> {
        while !ready.exists() {
            if let Some(status) = owner.try_wait()? {
                return Err(format!("Owner fixture exited: {status}").into());
            }
            if Instant::now() >= deadline {
                return Err("Owner fixture timeout".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let record: serde_json::Value = serde_json::from_slice(&fs::read(&ready)?)?;
        let pid = record["pid"].as_u64().ok_or("Missing runner pid")?;
        let birth = record["birth"].as_str().ok_or("Missing runner birth")?;
        owner.kill()?;
        owner.wait()?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat"));
            match stat {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Ok(stat) => {
                    let fields: Vec<_> = stat
                        .rsplit_once(')')
                        .ok_or("Bad process stat")?
                        .1
                        .split_whitespace()
                        .collect();
                    if fields.first() == Some(&"Z") || fields.get(19).copied() != Some(birth) {
                        break;
                    }
                }
                Err(e) => return Err(e.into()),
            }
            if Instant::now() >= deadline {
                return Err("Root runner survived owner SIGKILL beyond 2 seconds".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        println!("PASS: actual elevated runner exits within 2 seconds after owner SIGKILL");
        Ok(())
    })();
    let _ = owner.kill();
    let _ = owner.wait();
    result
}

pub fn owner_fixture() -> Result<()> {
    use std::{
        io::{BufReader, BufWriter},
        sync::atomic::AtomicBool,
        time::Duration,
    };
    use studio_protocol::*;
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
        return Err("CI-only fixture".into());
    }
    let source = PathBuf::from(std::env::args().nth(2).ok_or("Runner source missing")?);
    let ready = PathBuf::from(std::env::args().nth(3).ok_or("Ready path missing")?);
    let hash = trusted::file_hash(&source)?;
    let auth = linux::Authorized::open(
        &linux::installed_path(&hash)?,
        &hash,
        &AtomicBool::new(false),
    )?;
    auth.stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let session = new_id()?;
    let mut input = BufWriter::new(auth.stream.try_clone()?);
    let mut output = BufReader::new(auth.stream.try_clone()?);
    write_frame(
        &mut input,
        &Envelope::new(
            session,
            [0; 16],
            [0; 16],
            1,
            studio_protocol::Command::Hello,
        ),
    )?;
    let hello = read_frame::<Event>(&mut output)?;
    ReceiveOrder::new(session, [0; 16], [0; 16]).accept(&hello)?;
    if hello.payload
        != (Event::Hello {
            engine: ENGINE_VERSION,
        })
    {
        return Err("Bad fixture handshake".into());
    }
    let stat = fs::read_to_string(format!("/proc/{}/stat", auth.runner_pid()))?;
    let birth = stat
        .rsplit_once(')')
        .ok_or("Bad runner stat")?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or("Missing birth")?;
    let staging = ready.with_extension("tmp");
    fs::write(
        &staging,
        serde_json::to_vec(&serde_json::json!({"pid":auth.runner_pid(),"birth":birth}))?,
    )?;
    fs::rename(staging, ready)?;
    std::thread::sleep(Duration::from_secs(20));
    Err("Owner fixture was not killed by acceptance".into())
}
