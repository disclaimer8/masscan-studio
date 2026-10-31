//! Session-only elevation. The password belongs to the OS dialog, never Studio.
#![forbid(unsafe_code)]
use crate::unix::{Endpoint, Identity};
use std::{
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, String>;
/// POSIX mode bits do not account for macOS extended ACL grants. Refuse them
/// entirely for this personal installation, including inherited ACL entries.
pub fn reject_extended_acl(path: &Path) -> Result<()> {
    let out = Command::new("/bin/ls")
        .args(["-lde", "-n"])
        .arg(path)
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success()
        || String::from_utf8(out.stdout)
            .map_err(|e| e.to_string())?
            .lines()
            .count()
            != 1
    {
        return Err("Extended ACL or unreadable permissions on trusted path".into());
    }
    Ok(())
}

pub fn shell_quote(s: &str) -> Result<String> {
    if s.contains('\0') {
        return Err("NUL in launch argument".into());
    }
    Ok(format!("'{}'", s.replace('\'', "'\\''")))
}
pub fn applescript(shell: &str) -> String {
    format!(
        "do shell script \"{}\" with administrator privileges",
        shell
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    )
}
pub fn installed_path(hash: &str) -> Result<PathBuf> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Invalid runner SHA-256".into());
    }
    Ok(Path::new("/Library/PrivilegedHelperTools/MasscanStudio")
        .join(hash)
        .join("studio-runner"))
}
/// Materialises a reviewable one-time copy, not a daemon or a service registration.
/// A new version has a new directory. The existing version is never overwritten.
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
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C
for p in / /Library /Library/PrivilegedHelperTools /Library/PrivilegedHelperTools/MasscanStudio; do
  if [ ! -e "$p" ] && [ ! -L "$p" ]; then /bin/mkdir "$p"; /bin/chmod 0755 "$p"; fi
  [ -d "$p" ] && [ ! -L "$p" ] || exit 71
  [ "$(/usr/bin/stat -f %u "$p")" = 0 ] || exit 72
  mode=$(/usr/bin/stat -f %Lp "$p")
  [ "$((0$mode & 022))" -eq 0 ] || exit 73
  [ "$(/bin/ls -lde -n "$p" | /usr/bin/wc -l | /usr/bin/tr -d ' ')" = 1 ] || exit 76
done
dest={dest}
if [ -e "$dest" ] || [ -L "$dest" ]; then
  echo 'Version already exists; verify it from Studio. No overwrite.' >&2
  exit 74
fi
stage=$(/usr/bin/mktemp -d /Library/PrivilegedHelperTools/MasscanStudio/.install.XXXXXX)
trap '/bin/rm -f "$stage/studio-runner"; /bin/rmdir "$stage" 2>/dev/null || true' EXIT
/bin/cp {source} "$stage/studio-runner"
/usr/sbin/chown 0:0 "$stage/studio-runner"
/bin/chmod 0755 "$stage/studio-runner"
/bin/chmod -N "$stage/studio-runner" "$stage"
actual=$(/usr/bin/shasum -a 256 "$stage/studio-runner")
[ "${{actual%% *}}" = '{hash}' ] || exit 75
/usr/bin/codesign --verify --strict "$stage/studio-runner"
/bin/chmod 0755 "$stage"
/bin/mv "$stage" "$dest"
echo "Installed $dest/studio-runner"
"#
    ))
}

pub struct Authorized {
    pub stream: UnixStream,
    pub peer: crate::audit::Peer,
    _endpoint: Endpoint,
    launcher: Option<Child>,
    work_session: Option<crate::work_session::Watch>,
}
impl Authorized {
    pub fn endpoint_path(&self) -> &Path {
        self._endpoint.path()
    }
    pub fn open(path: &Path, hash: &str, cancelled: &AtomicBool) -> Result<Self> {
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            return Err("Authorization cancelled".into());
        }
        if path != installed_path(hash)? {
            return Err("Runner is not in its versioned installation directory".into());
        }
        crate::trusted::verify(path, hash)?;
        let owner = Identity::current()?;
        if owner.uid == 0 {
            return Err("Studio must run without administrator privileges".into());
        }
        let endpoint = Endpoint::create()?;
        if let Some(mut lease) =
            crate::work_session::helper(path, hash, endpoint.path(), &owner, cancelled)?
        {
            let (stream, peer) =
                endpoint.accept_trusted(Duration::from_secs(10), path, hash, cancelled, || {
                    lease.check()
                })?;
            let watch = lease.watch(&stream)?;
            return Ok(Self {
                stream,
                peer,
                _endpoint: endpoint,
                launcher: None,
                work_session: Some(watch),
            });
        }
        let line = format!(
            "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C {} --connect {} {}",
            shell_quote(path.to_str().ok_or("Runner path is not UTF-8")?)?,
            shell_quote(endpoint.path().to_str().ok_or("Socket path is not UTF-8")?)?,
            shell_quote(&serde_json::to_string(&owner).map_err(|e| e.to_string())?)?
        );
        let mut launcher = Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(applescript(&line))
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Cannot request system authorization: {e}"))?;
        let connected =
            endpoint.accept_trusted(Duration::from_secs(180), path, hash, cancelled, || {
                if let Some(status) = launcher.try_wait().map_err(|e| e.to_string())? {
                    return Err(format!(
                        "System authorization was cancelled or runner exited ({status})"
                    ));
                }
                Ok(())
            });
        match connected {
            Ok((stream, peer)) => Ok(Self {
                stream,
                peer,
                _endpoint: endpoint,
                launcher: Some(launcher),
                work_session: None,
            }),
            Err(e) => {
                let _ = launcher.kill();
                let _ = launcher.wait();
                Err(e)
            }
        }
    }
}
impl Drop for Authorized {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        self.work_session.take();
        let deadline = Instant::now() + Duration::from_secs(2);
        if let Some(launcher) = self.launcher.as_mut() {
            while launcher.try_wait().ok().flatten().is_none() {
                if Instant::now() >= deadline {
                    let _ = launcher.kill();
                    let _ = launcher.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        } else {
            while self.peer.is_alive().unwrap_or(false) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
