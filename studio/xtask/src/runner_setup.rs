use super::*;
use studio_platform::{macos, trusted};

pub fn prepare(root: &Path) -> Result<()> {
    let source = match std::env::args().nth(2) {
        Some(p) => fs::canonicalize(p)?,
        None => {
            let output = Command::new("cargo")
                .args([
                    "build",
                    "--locked",
                    "-p",
                    "studio-runner",
                    "--message-format=json-render-diagnostics",
                ])
                .output()?;
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
            if !output.status.success() {
                return Err("Runner build failed".into());
            }
            String::from_utf8(output.stdout)?
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .filter(|v| {
                    v["reason"] == "compiler-artifact" && v["target"]["name"] == "studio-runner"
                })
                .filter_map(|v| v["executable"].as_str().map(PathBuf::from))
                .next_back()
                .ok_or("Cargo did not report the runner executable")?
        }
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let dir = root.join("dist").join(format!("runner-{stamp}"));
    fs::create_dir_all(&dir)?;
    let copy = dir.join("studio-runner");
    fs::copy(&source, &copy)?;
    // Preserve already-signed package bytes: the UI pins their exact SHA-256.
    run(Command::new("codesign")
        .args(["--verify", "--strict"])
        .arg(&copy))?;
    let deps = text(Command::new("otool").arg("-L").arg(&copy))?;
    for line in deps.lines().skip(1) {
        let lib = line
            .split_whitespace()
            .next()
            .ok_or("Empty library dependency")?;
        if !lib.starts_with("/usr/lib/") && !lib.starts_with("/System/Library/") {
            return Err(format!("Privileged runner depends on non-system library: {lib}").into());
        }
    }
    let hash = trusted::file_hash(&copy)?;
    let script = macos::install_script(&copy, &hash)?;
    fs::write(dir.join("install.sh"), &script)?;
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "sha256":hash,"destination":macos::installed_path(&hash)?,"source_commit":text(Command::new("git").args(["rev-parse","HEAD"]))?,
            "dirty":!text(Command::new("git").args(["status","--porcelain"]))?.is_empty(),
            "cargo_lock_sha256":digest(&root.join("Cargo.lock"))?,"raw_enabled":studio_protocol::RAW_SCANNING_ENABLED,
            "install_script_sha256":digest(&dir.join("install.sh"))?
        }))?,
    )?;
    println!(
        "Prepared runner: {}\nSHA-256: {hash}\nInstallation script: {}\nNo system files changed.",
        copy.display(),
        dir.join("install.sh").display()
    );
    Ok(())
}
pub fn install() -> Result<()> {
    let dir = fs::canonicalize(
        std::env::args()
            .nth(2)
            .ok_or("Supply prepared runner directory")?,
    )?;
    let source = dir.join("studio-runner");
    let m: serde_json::Value = serde_json::from_slice(&fs::read(dir.join("manifest.json"))?)?;
    let hash = trusted::file_hash(&source)?;
    if m["sha256"].as_str() != Some(&hash) {
        return Err("Prepared runner hash changed".into());
    }
    let script = macos::install_script(&source, &hash)?;
    if fs::read_to_string(dir.join("install.sh"))? != script {
        return Err("Reviewed installation script changed".into());
    }
    let destination = macos::installed_path(&hash)?;
    if destination.exists() {
        trusted::verify(&destination, &hash)?;
        println!("This runner is already installed and verified");
        return Ok(());
    }
    // Pass the reviewed text, not a mutable user-owned script path, to the OS.
    run(Command::new("/usr/bin/osascript")
        .args(["-e", &macos::applescript(&script)])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C"))?;
    trusted::verify(&destination, &hash)?;
    println!("Installed and hash-verified: {}", destination.display());
    Ok(())
}
pub fn probe() -> Result<()> {
    use std::{
        io::{BufReader, BufWriter},
        sync::atomic::AtomicBool,
        time::Duration,
    };
    use studio_protocol::*;
    let source = PathBuf::from(
        std::env::args()
            .nth(2)
            .ok_or("Supply runner path from the prepared build or app bundle")?,
    );
    let hash = trusted::file_hash(&source)?;
    let destination = macos::installed_path(&hash)?;
    let auth = macos::Authorized::open(&destination, &hash, &AtomicBool::new(false))?;
    auth.stream
        .set_read_timeout(Some(Duration::from_secs(60)))?;
    auth.stream
        .set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut input = BufWriter::new(auth.stream.try_clone()?);
    let mut output = BufReader::new(auth.stream.try_clone()?);
    let session = new_id()?;
    let mut order = ReceiveOrder::new(session, [0; 16], [0; 16]);
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
    order.accept(&hello)?;
    if hello.payload
        != (Event::Hello {
            engine: ENGINE_VERSION,
        })
    {
        return Err("Incompatible runner Hello".into());
    }
    println!(
        "Authenticated root runner: pid={}, uid={}, SHA-256={hash}; protocol={VERSION}",
        auth.peer.pid, auth.peer.uid
    );
    write_frame(
        &mut input,
        &Envelope::new(
            session,
            [0; 16],
            [0; 16],
            2,
            studio_protocol::Command::CheckNetwork,
        ),
    )?;
    let reply = read_frame::<Event>(&mut output)?;
    order.accept(&reply)?;
    if let Event::NetworkChecked { ready, detail } = reply.payload {
        println!("Network preflight ready={ready}: {detail}");
    } else {
        return Err("Unexpected preflight response".into());
    }
    write_frame(
        &mut input,
        &Envelope::new(
            session,
            [0; 16],
            [0; 16],
            3,
            studio_protocol::Command::CloseSession,
        ),
    )?;
    drop(input);
    drop(output);
    let peer = auth.peer.clone();
    let endpoint = auth.endpoint_path().to_owned();
    drop(auth);
    if endpoint.exists() {
        return Err("Socket endpoint survived session close".into());
    }
    if studio_platform::unix::Identity::read(peer.pid).is_ok_and(|p| p == peer) {
        return Err("Root runner survived session close".into());
    }
    println!("Root runner exited; socket endpoint removed.");
    println!("Authorization probe complete. No packets sent; raw gate remains closed.");
    Ok(())
}
