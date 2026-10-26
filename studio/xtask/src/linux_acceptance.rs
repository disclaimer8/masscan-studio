//! Disposable GitHub VM acceptance only; never a product polkit policy.
use super::*;
use studio_platform::{linux, trusted, unix::Identity};

struct Policy(PathBuf);
impl Drop for Policy {
    fn drop(&mut self) {
        let _ = Command::new("sudo")
            .args(["-n", "/usr/bin/rm", "-f", "--"])
            .arg(&self.0)
            .status();
    }
}

pub fn verify(root: &Path) -> Result<()> {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") || Identity::current()?.uid == 0 {
        return Err(
            "Acceptance requires an unprivileged user in a disposable GitHub Actions VM".into(),
        );
    }
    if studio_protocol::RAW_SCANNING_ENABLED {
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
    let xml_path = prepared.join("ci-only.policy");
    fs::write(&xml_path, xml)?;
    let policy = Policy(policy_path);
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
