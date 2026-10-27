//! Explicit, hash-pinned installation of this application's bundled runner.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
use crate::linux as platform;
#[cfg(target_os = "macos")]
use crate::macos as platform;
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
type Result<T> = std::result::Result<T, String>;

pub struct Prepared {
    source: PathBuf,
    hash: String,
}
impl Prepared {
    pub fn new(source: &Path, cancelled: &AtomicBool) -> Result<Self> {
        check_cancel(cancelled)?;
        let source = std::fs::canonicalize(source)
            .map_err(|e| format!("Cannot find the bundled scanner helper: {e}"))?;
        let hash = crate::trusted::file_hash(&source)?;
        validate(&source, cancelled)?;
        let prepared = Self { source, hash };
        prepared.unchanged(cancelled)?;
        Ok(prepared)
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn destination(&self) -> Result<PathBuf> {
        #[cfg(unix)]
        {
            platform::installed_path(&self.hash)
        }
        #[cfg(windows)]
        {
            crate::windows::install::installed_path(&self.hash)
        }
    }
    /// Missing is installable; an existing invalid installation is an error,
    /// never an invitation to overwrite an administrator-owned file.
    pub fn installed(&self) -> Result<bool> {
        match std::fs::symlink_metadata(self.destination()?) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(format!("Cannot inspect scanner installation: {e}")),
            Ok(_) => {}
        }
        #[cfg(unix)]
        crate::trusted::verify(&self.destination()?, &self.hash)?;
        #[cfg(windows)]
        crate::windows::install::Installed::open(&self.hash)?;
        Ok(true)
    }
    fn unchanged(&self, cancelled: &AtomicBool) -> Result<()> {
        check_cancel(cancelled)?;
        if crate::trusted::file_hash(&self.source)? != self.hash {
            return Err(
                "Bundled scanner helper changed. Check setup again before installing.".into(),
            );
        }
        Ok(())
    }
    pub fn install(&self, cancelled: &AtomicBool) -> Result<()> {
        self.unchanged(cancelled)?;
        if self.installed()? {
            return Ok(());
        }
        validate(&self.source, cancelled)?;
        self.unchanged(cancelled)?;
        #[cfg(unix)]
        {
            let script = platform::install_script(&self.source, &self.hash)?;
            #[cfg(target_os = "macos")]
            command(
                "/usr/bin/osascript",
                &["-e".as_ref(), platform::applescript(&script).as_ref()],
                cancelled,
                std::time::Duration::from_secs(180),
            )?;
            #[cfg(target_os = "linux")]
            {
                let pkexec = Path::new("/usr/bin/pkexec");
                crate::trusted::verify(pkexec, &crate::trusted::file_hash(pkexec)?)?;
                command(
                    "/usr/bin/pkexec",
                    &[
                        "--disable-internal-agent".as_ref(),
                        "/bin/sh".as_ref(),
                        "-c".as_ref(),
                        script.as_ref(),
                    ],
                    cancelled,
                    std::time::Duration::from_secs(180),
                )?;
            }
        }
        #[cfg(windows)]
        command(
            self.source.to_str().ok_or("Runner path is not Unicode")?,
            &["--setup-install".as_ref(), self.hash.as_ref()],
            cancelled,
            std::time::Duration::from_secs(180),
        )?;
        check_cancel(cancelled)?;
        if !self.installed()? {
            return Err("Installation finished without a verified scanner helper".into());
        }
        Ok(())
    }
}

fn check_cancel(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        return Err("Setup wait cancelled. Dismiss any remaining system dialog. An installation already approved may still finish; check setup again.".into());
    }
    Ok(())
}

fn validate(source: &Path, cancelled: &AtomicBool) -> Result<()> {
    check_cancel(cancelled)?;
    if !std::fs::metadata(source)
        .map_err(|e| e.to_string())?
        .is_file()
    {
        return Err("Bundled scanner helper is not a file".into());
    }
    #[cfg(target_os = "macos")]
    {
        command(
            "/usr/bin/codesign",
            &["--verify".as_ref(), "--strict".as_ref(), source.as_os_str()],
            cancelled,
            std::time::Duration::from_secs(10),
        )?;
        let deps = command(
            "/usr/bin/otool",
            &["-L".as_ref(), source.as_os_str()],
            cancelled,
            std::time::Duration::from_secs(10),
        )?;
        for line in deps.lines().skip(1) {
            let lib = line
                .split_whitespace()
                .next()
                .ok_or("Empty library dependency")?;
            if !lib.starts_with("/usr/lib/") && !lib.starts_with("/System/Library/") {
                return Err(format!(
                    "Scanner helper depends on a non-system library: {lib}"
                ));
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let headers = command(
            "/usr/bin/readelf",
            &[
                "--wide".as_ref(),
                "--program-headers".as_ref(),
                source.as_os_str(),
            ],
            cancelled,
            std::time::Duration::from_secs(10),
        )?;
        let dynamic = command(
            "/usr/bin/readelf",
            &["--wide".as_ref(), "--dynamic".as_ref(), source.as_os_str()],
            cancelled,
            std::time::Duration::from_secs(10),
        )?;
        crate::linux::validate_elf(&headers, &dynamic)?;
    }
    #[cfg(windows)]
    crate::windows::install::PowerShell::open()?;
    Ok(())
}

/// Entry for the bundled runner's dedicated, unprivileged setup subprocess.
/// This is never called inside the UI: the clean process environment must exist
/// before starting PowerShell/.NET with administrator rights.
#[cfg(windows)]
pub fn windows_install_entry(expected_hash: &str) -> Result<()> {
    crate::windows::runner_environment::initialize()?;
    crate::win_setup::validate_hash(expected_hash)?;
    let source = std::env::current_exe().map_err(|e| e.to_string())?;
    let cancelled = AtomicBool::new(false);
    let prepared = Prepared::new(&source, &cancelled)?;
    if prepared.hash() != expected_hash {
        return Err("Setup runner hash changed".into());
    }
    if prepared.installed()? {
        return Ok(());
    }
    crate::windows::uac::install_runner(&source, expected_hash, &cancelled)
}

fn command(
    exe: &str,
    args: &[&std::ffi::OsStr],
    cancelled: &AtomicBool,
    timeout: std::time::Duration,
) -> Result<String> {
    use std::{
        io::Read,
        process::{Command, Stdio},
        sync::mpsc,
        time::{Duration, Instant},
    };
    check_cancel(cancelled)?;
    let mut process = Command::new(exe);
    process.args(args).env_clear();
    #[cfg(unix)]
    process
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let windows = crate::windows::runner_environment::directory(false)?;
        process
            .env("SYSTEMROOT", &windows)
            .env("WINDIR", &windows)
            .env("PATH", crate::windows::runner_environment::directory(true)?)
            .creation_flags(0x08000000); // CREATE_NO_WINDOW; UAC owns its prompt.
    }
    let mut child = process
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Cannot start {exe}: {e}"))?;
    let stdout = child.stdout.take().ok_or("Missing setup stdout")?;
    let (tx, rx) = mpsc::sync_channel(1);
    // Bound memory and waiting separately. Never join a reader whose pipe may
    // still be held by an elevated child after cancelling the launcher.
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = tx.send(result);
    });
    let deadline = Instant::now() + timeout;
    let result = (|| {
        let mut output = None;
        loop {
            check_cancel(cancelled)?;
            if Instant::now() >= deadline {
                return Err("Setup timed out. Dismiss any remaining system dialog. Installation may still finish; check setup again.".into());
            }
            if let Ok(bytes) = rx.try_recv() {
                let bytes = bytes.map_err(|e| e.to_string())?;
                if bytes.len() > 2 * 1024 * 1024 {
                    return Err("Setup command output exceeded its limit".into());
                }
                output = Some(bytes);
            }
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                if !status.success() {
                    return Err(format!(
                        "{exe} failed or authorization was declined ({status}). Check the bundled helper and system permissions."
                    ));
                }
                if let Some(bytes) = output {
                    return String::from_utf8(bytes).map_err(|e| e.to_string());
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        cleanup(child, std::process::Child::kill);
    }
    result
}

fn cleanup(
    mut child: std::process::Child,
    terminate: impl FnOnce(&mut std::process::Child) -> std::io::Result<()>,
) {
    let _ = terminate(&mut child);
    // pkexec may already be root; kill can fail with EPERM. Never join that
    // process on the controller thread, including during Controller::drop.
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("studio-setup-reaper".into())
        .spawn(move || {
            let _ = child.wait();
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    #[cfg(unix)]
    #[test]
    fn setup_failed_termination_does_not_block_cancellation() {
        let child = std::process::Command::new("/bin/sleep")
            .arg("0.5")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        cleanup(child, |_| {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        });
        assert!(
            start.elapsed() < std::time::Duration::from_millis(300),
            "cleanup waited for an unkillable elevated child"
        );
    }
    #[cfg(unix)]
    fn shell(script: &str, cancel: &AtomicBool, timeout: std::time::Duration) -> Result<String> {
        command(
            "/bin/sh",
            &["-c".as_ref(), script.as_ref()],
            cancel,
            timeout,
        )
    }
    #[cfg(unix)]
    #[test]
    fn setup_command_reports_failure_and_bounds_output() {
        let c = AtomicBool::new(false);
        assert!(shell("exit 7", &c, std::time::Duration::from_secs(2)).is_err());
        assert!(
            shell(
                "/usr/bin/yes x | /usr/bin/head -c 2097153",
                &c,
                std::time::Duration::from_secs(2)
            )
            .is_err()
        );
        assert_eq!(
            shell("printf ok", &c, std::time::Duration::from_secs(2)).unwrap(),
            "ok"
        );
    }
    #[cfg(unix)]
    #[test]
    fn setup_command_timeout_does_not_wait_for_inherited_pipe() {
        let start = std::time::Instant::now();
        assert!(
            shell(
                "sleep 1 & wait",
                &AtomicBool::new(false),
                std::time::Duration::from_millis(20)
            )
            .is_err()
        );
        assert!(start.elapsed() < std::time::Duration::from_millis(700));
    }
    fn fixture() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "studio-setup-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, b"not an executable").unwrap();
        path
    }
    #[test]
    fn setup_cancellation_precedes_source_access() {
        let cancel = AtomicBool::new(true);
        let error = Prepared::new(Path::new("/missing/runner"), &cancel)
            .err()
            .unwrap();
        assert!(error.to_lowercase().contains("cancel"), "{error}");
    }
    #[test]
    fn setup_source_changed_after_check_never_elevates() {
        let path = fixture();
        let p = Prepared {
            hash: crate::trusted::file_hash(&path).unwrap(),
            source: path.clone(),
        };
        std::fs::write(&path, b"replacement").unwrap();
        let result = p.install(&AtomicBool::new(false));
        std::fs::remove_file(path).unwrap();
        assert!(result.unwrap_err().contains("changed"));
    }
    #[test]
    fn setup_cancelled_install_never_elevates() {
        let path = fixture();
        let p = Prepared {
            hash: crate::trusted::file_hash(&path).unwrap(),
            source: path.clone(),
        };
        let cancel = AtomicBool::new(false);
        cancel.store(true, Ordering::Release);
        let result = p.install(&cancel);
        std::fs::remove_file(path).unwrap();
        assert!(result.unwrap_err().to_lowercase().contains("cancel"));
    }
    #[cfg(unix)]
    #[test]
    fn setup_invalid_executable_is_rejected_before_elevation() {
        let path = fixture();
        let result = Prepared::new(&path, &AtomicBool::new(false));
        std::fs::remove_file(path).unwrap();
        assert!(result.is_err());
    }
}
