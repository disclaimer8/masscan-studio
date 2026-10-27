use super::*;
use studio_platform::{
    trusted, win_setup,
    windows::install::{Installed, installed_path},
};

pub fn prepare(root: &Path) -> Result<()> {
    let source = match std::env::args().nth(2) {
        Some(path) => fs::canonicalize(path)?,
        None => build_runner()?,
    };
    prepare_source(root, &source)?;
    Ok(())
}
fn build_runner() -> Result<PathBuf> {
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
        .filter(|v| v["reason"] == "compiler-artifact" && v["target"]["name"] == "studio-runner")
        .filter_map(|v| v["executable"].as_str().map(PathBuf::from))
        .next_back()
        .ok_or_else(|| "Cargo did not report the runner executable".into())
}
fn prepare_source(root: &Path, source: &Path) -> Result<PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let dir = root.join("dist").join(format!("runner-{stamp}"));
    fs::create_dir_all(&dir)?;
    let copy = dir.join("studio-runner.exe");
    fs::copy(source, &copy)?;
    let hash = trusted::file_hash(&copy)?;
    let canonical = fs::canonicalize(&copy)?;
    let path = canonical
        .to_str()
        .ok_or("Runner path must be valid Unicode")?;
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    let script = win_setup::install_script(path, &hash)?;
    fs::write(dir.join("install.ps1"), &script)?;
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "sha256":hash,"destination":installed_path(&hash)?,
            "source_commit":text(Command::new("git").args(["rev-parse","HEAD"])).ok(),
            "dirty":text(Command::new("git").args(["status","--porcelain"])).ok().map(|s|!s.is_empty()),
            "cargo_lock_sha256":root.join("Cargo.lock").is_file().then(||digest(&root.join("Cargo.lock"))).transpose()?,
            "package_manifest_sha256":source.parent().map(|p|p.join("manifest.json")).filter(|p|p.is_file()).map(|p|digest(&p)).transpose()?,
            "install_script_sha256":digest(&dir.join("install.ps1"))?,
            "raw_profiles":studio_protocol::RAW_PROFILES,
            "session_uac_enabled":true
        }))?,
    )?;
    println!(
        "Prepared runner: {}\nSHA-256: {hash}\nReview: {}\nRun the script in an elevated 64-bit PowerShell, then cargo xtask verify-installed-runner {hash}.\nNo system files changed.",
        copy.display(),
        dir.join("install.ps1").display()
    );
    Ok(dir)
}
pub fn verify_installed() -> Result<()> {
    let hash = std::env::args().nth(2).ok_or("Supply runner SHA-256")?;
    let installation = Installed::open(&hash)?;
    println!(
        "Trusted immutable runner: {}\nSHA-256: {hash}\nStart Studio as an ordinary user and select Authorize. Raw scanning remains disabled.",
        installation.path().display()
    );
    Ok(())
}
pub fn verify_ci(root: &Path) -> Result<()> {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
        return Err("Requires disposable GitHub Windows VM".into());
    }
    if studio_protocol::raw_profile_enabled(studio_protocol::Backend::MacFeth)
        || !studio_protocol::RAW_PROFILES.is_empty()
    {
        return Err("Raw gate must stay closed".into());
    }
    let dir = prepare_source(root, &build_runner()?)?;
    let source = dir.join("studio-runner.exe");
    let hash = trusted::file_hash(&source)?;
    let outside = std::env::temp_dir().join(format!(
        "studio-standalone-{}",
        studio_protocol::id_text(studio_protocol::new_id()?)
    ));
    fs::create_dir(&outside)?;
    let tool = outside.join("studio-tools.exe");
    fs::copy(std::env::current_exe()?, &tool)?;
    run(Command::new(&tool)
        .arg("prepare-runner")
        .arg(fs::canonicalize(&source)?)
        .current_dir(&outside))?;
    let prepared = fs::read_dir(outside.join("dist"))?
        .next()
        .ok_or("Standalone preparation missing")??
        .path();
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(prepared.join("manifest.json"))?)?;
    if metadata["sha256"] != hash
        || !metadata["source_commit"].is_null()
        || !metadata["cargo_lock_sha256"].is_null()
    {
        return Err("Standalone preparation fabricated checkout provenance".into());
    }
    fs::remove_dir_all(outside)?;
    let destination = installed_path(&hash)?;
    if destination.exists() {
        return Err("CI installation already exists; refusing replacement".into());
    }
    run(Command::new("pwsh")
        .args(["-NoProfile", "-NonInteractive", "-File"])
        .arg(dir.join("install.ps1")))?;
    let pinned = Installed::open(&hash)?;
    if fs::OpenOptions::new()
        .write(true)
        .open(pinned.path())
        .is_ok()
    {
        return Err("Pinned executable remains writable".into());
    }
    let renamed = destination.with_extension("moved");
    if fs::rename(&destination, &renamed).is_ok() {
        fs::rename(&renamed, &destination)?;
        return Err("Pinned executable could be renamed".into());
    }
    drop(pinned);
    // Existing versions must not be overwritten, even by the installer.
    let status = Command::new("pwsh")
        .args(["-NoProfile", "-NonInteractive", "-File"])
        .arg(dir.join("install.ps1"))
        .status()?;
    if status.success() {
        return Err("Installer overwrote existing version".into());
    }
    Installed::open(&hash)?;
    // Tampering after releasing the pins is detected by hashing the new handle.
    use std::io::Write;
    fs::OpenOptions::new()
        .append(true)
        .open(&destination)?
        .write_all(b"tampered")?;
    if Installed::open(&hash).is_ok() {
        return Err("Modified executable hash accepted".into());
    }
    fs::copy(&source, &destination)?;
    Installed::open(&hash)?;
    // A junction/symlink at the version directory must never bypass ancestry checks.
    let version = destination.parent().ok_or("Missing version directory")?;
    let backup = version.with_file_name(format!("{hash}-ci-backup"));
    fs::rename(version, &backup)?;
    let test = (|| -> Result<()> {
        std::os::windows::fs::symlink_dir(&backup, version)?;
        if Installed::open(&hash).is_ok() {
            return Err("Reparse version directory accepted".into());
        }
        Ok(())
    })();
    if fs::symlink_metadata(version).is_ok() {
        fs::remove_dir(version)?;
    }
    fs::rename(&backup, version)?;
    test?;
    Installed::open(&hash)?;
    println!(
        "PASS: actual Program Files installation, native owner/DACL trust, pinned write/rename refusal, no overwrite, hash tamper and reparse rejection. No UAC or packets."
    );
    Ok(())
}
