//! Bounded, cancellable subprocess execution. No shell or privileged runner.
use crate::{Request, Result};
use command_group::{CommandGroup, GroupChild};
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
struct OwnedChild(GroupChild);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn reader(
    stream: impl Read + Send + 'static,
    limit: usize,
    overflow: Arc<AtomicBool>,
) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut data = Vec::new();
        stream.take(limit as u64 + 1).read_to_end(&mut data)?;
        if data.len() > limit {
            overflow.store(true, Ordering::Release);
        }
        Ok(data)
    })
}
pub fn capture(
    path: &Path,
    args: &[String],
    timeout: Duration,
    limit: usize,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    if cancelled.load(Ordering::Acquire) {
        return Err("Cancelled".into());
    }
    let mut cmd = Command::new(path);
    cmd.args(args)
        .env("LC_ALL", "C")
        .env_remove("NMAP_PRIVILEGED")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        // The group builder applies CREATE_SUSPENDED as well, assigning the
        // process to its Job Object before it can create descendants.
    }
    let mut group = cmd.group();
    #[cfg(windows)]
    group.creation_flags(0x08000000).kill_on_drop(true);
    let mut child = OwnedChild(group.spawn().map_err(|e| {
        format!(
            "Cannot start {}: {e}",
            path.file_name().unwrap_or_default().to_string_lossy()
        )
    })?);
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout = reader(
        child.0.inner().stdout.take().ok_or("Missing stdout")?,
        limit,
        overflow.clone(),
    );
    let stderr = reader(
        child.0.inner().stderr.take().ok_or("Missing stderr")?,
        16384,
        overflow.clone(),
    );
    let deadline = Instant::now() + timeout;
    let status = loop {
        let error = if cancelled.load(Ordering::Acquire) {
            Some("Cancelled".to_string())
        } else if overflow.load(Ordering::Acquire) {
            Some("Tool output exceeded its size limit".into())
        } else if Instant::now() >= deadline {
            Some("Tool deadline exceeded".into())
        } else {
            None
        };
        if let Some(e) = error {
            let _ = child.0.kill();
            let _ = child.0.wait();
            let _ = stdout.join();
            let _ = stderr.join();
            return Err(e);
        }
        match child.0.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => {
                let _ = child.0.kill();
                let _ = child.0.wait();
                let _ = stdout.join();
                let _ = stderr.join();
                return Err(e.to_string());
            }
        }
        thread::sleep(Duration::from_millis(10));
    };
    // No descendant may retain the pipes once the requested tool has exited.
    // kill targets its dedicated Unix process group / Windows Job Object.
    let _ = child.0.kill();
    let out = stdout
        .join()
        .map_err(|_| "Output reader failed")?
        .map_err(|e| e.to_string())?;
    let err = stderr
        .join()
        .map_err(|_| "Error reader failed")?
        .map_err(|e| e.to_string())?;
    if overflow.load(Ordering::Acquire) {
        return Err("Tool output exceeded its size limit".into());
    }
    if !status.success() {
        return Err(format!(
            "Tool failed ({status}): {}",
            crate::clean(&String::from_utf8_lossy(&err))
        ));
    }
    Ok(out)
}
pub fn inspect(nmap: &Path, request: &Request, cancel: &AtomicBool) -> Result<crate::Inspection> {
    let validated = Request::new(&request.ip.to_string(), request.ports.clone())?;
    let bytes = capture(
        nmap,
        &validated.args(),
        Duration::from_secs(55),
        crate::MAX_XML,
        cancel,
    )?;
    crate::parse_xml(&bytes, &validated)
}
pub fn resolve(
    worker: &Path,
    ip: std::net::Ipv4Addr,
    cancel: &AtomicBool,
) -> Result<Option<String>> {
    let bytes = capture(
        worker,
        &["--reverse".into(), ip.to_string()],
        Duration::from_secs(3),
        4096,
        cancel,
    )?;
    let name: Option<String> =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid DNS worker response")?;
    match name {
        Some(s) => crate::valid_hostname(&s)
            .map(Some)
            .ok_or("Resolver returned an invalid hostname".into()),
        None => Ok(None),
    }
}
pub fn find_nmap() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("STUDIO_NMAP_PATH") {
        let p = PathBuf::from(p);
        return p.is_file().then(|| p.canonicalize().ok()).flatten();
    }
    let mut paths: Vec<PathBuf> = vec![];
    #[cfg(target_os = "macos")]
    paths.extend(["/opt/homebrew/bin/nmap", "/usr/local/bin/nmap"].map(PathBuf::from));
    #[cfg(windows)]
    for key in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(p) = std::env::var_os(key) {
            paths.push(PathBuf::from(p).join("Nmap/nmap.exe"));
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        paths.extend(
            std::env::split_paths(&path)
                .map(|p| p.join(format!("nmap{}", std::env::consts::EXE_SUFFIX))),
        );
    }
    paths
        .into_iter()
        .find(|p| p.is_file())
        .and_then(|p| p.canonicalize().ok())
}
