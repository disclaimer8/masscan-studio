//! Hash-addressed personal installation and session-only polkit launcher.
use std::path::{Path, PathBuf};
type Result<T> = std::result::Result<T, String>;

/// Restrict the initial Linux runner to the system x86-64 glibc loader and
/// runtime. No Qt, user library search paths, plugins or bundled loader.
pub fn validate_elf(headers: &str, dynamic: &str) -> Result<()> {
    if !headers.contains("[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]") {
        return Err("Runner requires the system x86-64 glibc loader".into());
    }
    for line in dynamic.lines() {
        if [
            "(RPATH)",
            "(RUNPATH)",
            "(AUDIT)",
            "(DEPAUDIT)",
            "(FILTER)",
            "(AUXILIARY)",
        ]
        .iter()
        .any(|tag| line.contains(tag))
        {
            return Err("Runner contains a custom loader search path or hook".into());
        }
        if line.contains("(NEEDED)") {
            let lib = line
                .split_once('[')
                .and_then(|(_, v)| v.split_once(']'))
                .map(|(v, _)| v)
                .ok_or("Malformed dependency")?;
            if ![
                "libgcc_s.so.1",
                "libc.so.6",
                "libm.so.6",
                "libpthread.so.0",
                "libdl.so.2",
                "librt.so.1",
                "ld-linux-x86-64.so.2",
            ]
            .contains(&lib)
            {
                return Err(format!("Runner depends on unsupported library: {lib}"));
            }
        }
    }
    Ok(())
}

pub fn shell_quote(value: &str) -> Result<String> {
    if value.contains('\0') {
        return Err("NUL in installation argument".into());
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}
pub fn installed_path(hash: &str) -> Result<PathBuf> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("Invalid runner SHA-256".into());
    }
    Ok(Path::new("/usr/local/libexec/masscan-studio")
        .join(hash)
        .join("studio-runner"))
}
pub fn install_script(source: &Path, hash: &str) -> Result<String> {
    let destination = installed_path(hash)?;
    let source = shell_quote(
        source
            .to_str()
            .filter(|_| source.is_absolute())
            .ok_or("Absolute UTF-8 runner source required")?,
    )?;
    let dest = shell_quote(destination.parent().unwrap().to_str().unwrap())?;
    Ok(format!(
        r#"set -eu
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C
[ "$(/usr/bin/id -u)" = 0 ] || exit 70
for p in / /usr /usr/local /usr/local/libexec /usr/local/libexec/masscan-studio; do
  if [ ! -e "$p" ] && [ ! -L "$p" ]; then /usr/bin/mkdir "$p"; /usr/bin/chmod 0755 "$p"; fi
  [ -d "$p" ] && [ ! -L "$p" ] || exit 71
  [ "$(/usr/bin/stat -c %u "$p")" = 0 ] || exit 72
  mode=$(/usr/bin/stat -c %a "$p")
  [ "$((0$mode & 022))" -eq 0 ] || exit 73
done
dest={dest}
if [ -e "$dest" ] || [ -L "$dest" ]; then
  echo 'Version already exists. No overwrite.' >&2
  exit 74
fi
stage=$(/usr/bin/mktemp -d /usr/local/libexec/masscan-studio/.install.XXXXXX)
trap '/usr/bin/rm -f "$stage/studio-runner"; /usr/bin/rmdir "$stage" 2>/dev/null || true' EXIT
/usr/bin/cp {source} "$stage/studio-runner"
/usr/bin/chown 0:0 "$stage/studio-runner" "$stage"
/usr/bin/chmod 0755 "$stage/studio-runner" "$stage"
actual=$(/usr/bin/sha256sum "$stage/studio-runner")
[ "${{actual%% *}}" = '{hash}' ] || exit 75
/usr/bin/mv -T "$stage" "$dest"
echo "Installed $dest/studio-runner"
"#
    ))
}

#[cfg(target_os = "linux")]
pub use launcher::{Authorized, arm_parent_death};
#[cfg(target_os = "linux")]
mod launcher {
    use super::*;
    use crate::{
        trusted,
        unix::{Endpoint, Identity},
    };
    use std::{
        os::unix::net::UnixStream,
        process::{Child, Command, Stdio},
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };

    /// The runner sets this after pkexec has finished changing credentials.
    pub fn arm_parent_death(expected: u32) -> Result<()> {
        // SAFETY: getppid has no pointer arguments and only observes this process.
        if expected == 0 || unsafe { libc::getppid() } as u32 != expected {
            return Err("Runner must be the direct child of its UI".into());
        }
        // SAFETY: PR_SET_PDEATHSIG takes a signal number, no pointers. SIGKILL
        // affects only this process if its spawning parent thread disappears.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: re-check closes the death/reparenting race before prctl armed.
        if unsafe { libc::getppid() } as u32 != expected {
            return Err("UI exited before parent-death protection was armed".into());
        }
        Ok(())
    }
    pub struct Authorized {
        pub stream: UnixStream,
        endpoint: Endpoint,
        launcher: Option<Child>,
        pid: u32,
    }
    impl Authorized {
        pub fn wait_closed(&mut self, timeout: Duration) -> Result<()> {
            let deadline = Instant::now() + timeout;
            loop {
                if let Some(child) = self.launcher.as_mut() {
                    if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                        self.launcher.take();
                        return if status.success() {
                            Ok(())
                        } else {
                            Err(format!("Runner exited: {status}"))
                        };
                    }
                } else {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err("Root runner did not exit before deadline".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        pub fn runner_pid(&self) -> u32 {
            self.pid
        }
        pub fn endpoint_path(&self) -> &Path {
            self.endpoint.path()
        }
        pub fn open(path: &Path, hash: &str, cancelled: &AtomicBool) -> Result<Self> {
            if cancelled.load(Ordering::Acquire) {
                return Err("Authorization cancelled".into());
            }
            if path != installed_path(hash)? {
                return Err("Runner is not in its versioned installation directory".into());
            }
            trusted::verify(path, hash)?;
            let owner = Identity::current()?;
            if owner.uid == 0 {
                return Err("Studio must run without administrator privileges".into());
            }
            let pkexec = Path::new("/usr/bin/pkexec");
            trusted::verify(pkexec, &trusted::file_hash(pkexec)?)?;
            let endpoint = Endpoint::create()?;
            let mut launcher = Command::new(pkexec)
                .arg("--disable-internal-agent")
                .arg(path)
                .arg("--connect")
                .arg(endpoint.path())
                .arg(serde_json::to_string(&owner).map_err(|e| e.to_string())?)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("Cannot request polkit authorization: {e}"))?;
            let connected =
                endpoint.accept_root_child(&mut launcher, Duration::from_secs(180), cancelled);
            match connected {
                Ok(stream) => {
                    let pid = launcher.id();
                    Ok(Self {
                        stream,
                        endpoint,
                        launcher: Some(launcher),
                        pid,
                    })
                }
                Err(e) => {
                    // Remove the endpoint before cancelling/reaping: a late root
                    // exec must not be able to connect to this abandoned session.
                    drop(endpoint);
                    reap(launcher);
                    Err(format!(
                        "{e}. A desktop polkit authentication agent is required."
                    ))
                }
            }
        }
    }
    fn reap(mut child: Child) {
        let _ = child.kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // After credentials change, an ordinary UI cannot SIGKILL a root child.
        // Keep UI responsive; EOF + runner lifetime checks govern its shutdown.
        // A waiter only reaps; it does not become the child's kernel parent.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
    impl Drop for Authorized {
        fn drop(&mut self) {
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
            if let Some(child) = self.launcher.take() {
                reap(child);
            }
        }
    }
}
