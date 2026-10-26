//! OS-bound local session transport. No session secret travels in argv/environment.
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub pid: u32,
    pub uid: u32,
    pub birth: [u64; 2],
    pub executable: PathBuf,
}
type Result<T> = std::result::Result<T, String>;
#[cfg(target_os = "macos")]
pub type TrustedPeer = crate::audit::Peer;
#[cfg(target_os = "linux")]
pub type TrustedPeer = Identity;
impl Identity {
    pub fn current() -> Result<Self> {
        Self::read(std::process::id())
    }
    pub fn read(pid: u32) -> Result<Self> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err("Invalid process id".into());
        }
        identity(pid)
    }
    pub fn verify(&self, stream: &UnixStream) -> Result<()> {
        if peer_identity(stream)? != *self {
            return Err("Peer account/process/birth does not match this launch".into());
        }
        Ok(())
    }
}
#[cfg(target_os = "macos")]
fn identity(pid: u32) -> Result<Identity> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    // SAFETY: pid fits pid_t; exact libc layout, writable sized out-buffer. No
    // uninitialised bytes are read unless libproc returned the complete structure.
    let n = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            std::mem::size_of_val(&info) as i32,
        )
    };
    if n != std::mem::size_of_val(&info) as i32 {
        return Err(format!(
            "Cannot inspect process {pid}: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: exact successful byte count checked above.
    let info = unsafe { info.assume_init() };
    let mut path = vec![0u8; 4096];
    // SAFETY: the buffer is writable for its declared size; no pointers escape.
    let n = unsafe { libc::proc_pidpath(pid as i32, path.as_mut_ptr().cast(), path.len() as u32) };
    if n <= 0 {
        return Err("Cannot inspect peer executable".into());
    }
    let end = path
        .iter()
        .position(|b| *b == 0)
        .ok_or("Unterminated executable path")?;
    let mut again = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    // SAFETY: same sized writable output buffer and byte-count check as above.
    let n = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            again.as_mut_ptr().cast(),
            std::mem::size_of_val(&again) as i32,
        )
    };
    if n != std::mem::size_of_val(&again) as i32 {
        return Err("Process disappeared during inspection".into());
    }
    // SAFETY: complete successful structure write checked above.
    let again = unsafe { again.assume_init() };
    if (info.pbi_uid, info.pbi_start_tvsec, info.pbi_start_tvusec)
        != (again.pbi_uid, again.pbi_start_tvsec, again.pbi_start_tvusec)
    {
        return Err("Process changed during inspection".into());
    }
    use std::os::unix::ffi::OsStrExt;
    Ok(Identity {
        pid,
        uid: info.pbi_uid,
        birth: [info.pbi_start_tvsec, info.pbi_start_tvusec],
        executable: PathBuf::from(std::ffi::OsStr::from_bytes(&path[..end])),
    })
}
#[cfg(target_os = "linux")]
fn identity(pid: u32) -> Result<Identity> {
    let dir = PathBuf::from(format!("/proc/{pid}"));
    let stat = fs::read_to_string(dir.join("stat")).map_err(|e| e.to_string())?;
    let start = stat
        .rsplit_once(')')
        .ok_or("Malformed process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or("Missing process birth")?
        .parse()
        .map_err(|_| "Bad process birth")?;
    let status = fs::read_to_string(dir.join("status")).map_err(|e| e.to_string())?;
    let uid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .ok_or("Missing peer uid")?
        .parse()
        .map_err(|_| "Bad peer uid")?;
    let executable = fs::read_link(dir.join("exe")).map_err(|e| e.to_string())?;
    let again = fs::read_to_string(dir.join("stat")).map_err(|e| e.to_string())?;
    let after = again
        .rsplit_once(')')
        .ok_or("Malformed process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or("Missing process birth")?
        .parse::<u64>()
        .map_err(|_| "Bad process birth")?;
    if after != start {
        return Err("Process changed during inspection".into());
    }
    Ok(Identity {
        pid,
        uid,
        birth: [start, 0],
        executable,
    })
}

pub fn peer_identity(stream: &UnixStream) -> Result<Identity> {
    let (pid, uid) = credentials(stream)?;
    let identity = Identity::read(pid)?;
    if identity.uid != uid {
        return Err("Peer credentials changed after connect".into());
    }
    Ok(identity)
}
#[cfg(target_os = "macos")]
fn credentials(stream: &UnixStream) -> Result<(u32, u32)> {
    let mut pid: libc::pid_t = 0;
    let mut n = std::mem::size_of_val(&pid) as libc::socklen_t;
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: borrowed live socket fd; correctly sized scalar output pointers.
    let r = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            0,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut n,
        )
    };
    // SAFETY: uid/gid are writable libc-compatible scalars, stream remains live.
    let c = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if r != 0 || c != 0 || n as usize != std::mem::size_of_val(&pid) || pid <= 0 {
        return Err(format!(
            "Cannot authenticate socket peer: {}",
            io::Error::last_os_error()
        ));
    }
    Ok((pid as u32, uid))
}
#[cfg(target_os = "linux")]
fn credentials(stream: &UnixStream) -> Result<(u32, u32)> {
    let mut value = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut n = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: live fd and exact writable ucred output allocation; initialisation
    // is checked using both the return value and returned byte count.
    let r = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            value.as_mut_ptr().cast(),
            &mut n,
        )
    };
    if r != 0 || n as usize != std::mem::size_of_val(&value) {
        return Err(io::Error::last_os_error().to_string());
    }
    // SAFETY: complete successful ucred write established above.
    let value = unsafe { value.assume_init() };
    if value.pid <= 0 {
        return Err("Invalid peer pid".into());
    }
    Ok((value.pid as u32, value.uid))
}

pub struct Endpoint {
    listener: UnixListener,
    path: PathBuf,
    inode: u64,
    device: u64,
}
impl Endpoint {
    pub fn create() -> Result<Self> {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
        let name = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let base = fs::canonicalize(std::env::temp_dir()).map_err(|e| e.to_string())?;
        let dir = base.join(format!("ms-{name}"));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| e.to_string())?;
        let path = dir.join("s");
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                let _ = fs::remove_dir(&dir);
                return Err(e.to_string());
            }
        };
        let md = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        let endpoint = Self {
            listener,
            path,
            inode: md.ino(),
            device: md.dev(),
        };
        fs::set_permissions(&endpoint.path, fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        endpoint
            .listener
            .set_nonblocking(true)
            .map_err(|e| e.to_string())?;
        #[cfg(target_os = "macos")]
        {
            crate::macos::reject_extended_acl(endpoint.path.parent().unwrap())?;
            crate::macos::reject_extended_acl(&endpoint.path)?;
        }
        Ok(endpoint)
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn accept_trusted(
        &self,
        timeout: Duration,
        path: &Path,
        hash: &str,
        cancelled: &std::sync::atomic::AtomicBool,
        mut check_launcher: impl FnMut() -> Result<()>,
    ) -> Result<(UnixStream, TrustedPeer)> {
        crate::trusted::verify(path, hash)?;
        let deadline = Instant::now() + timeout;
        loop {
            if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                return Err("Authorization cancelled".into());
            }
            check_launcher()?;
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
                    #[cfg(target_os = "macos")]
                    let peer = TrustedPeer::from_stream(&stream)?;
                    #[cfg(target_os = "linux")]
                    let peer = peer_identity(&stream)?;
                    if peer.uid != 0 || peer.executable != path {
                        return Err("Unexpected elevated runner process".into());
                    }
                    crate::trusted::verify(path, hash)?;
                    peer.verify(&stream)?;
                    return Ok((stream, peer));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.to_string()),
            }
            if Instant::now() >= deadline {
                return Err("Authorization timed out".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    pub fn accept(&self, timeout: Duration, expected: &Identity) -> Result<UnixStream> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.listener.accept() {
                Ok((s, _)) => {
                    s.set_nonblocking(false).map_err(|e| e.to_string())?;
                    expected.verify(&s)?;
                    return Ok(s);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.to_string()),
            }
            if Instant::now() >= deadline {
                return Err("Runner connect timed out".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    pub fn connect(path: &Path, expected: &Identity) -> Result<UnixStream> {
        let parent = path.parent().ok_or("Missing socket directory")?;
        #[cfg(target_os = "macos")]
        {
            crate::macos::reject_extended_acl(parent)?;
            crate::macos::reject_extended_acl(path)?;
        }
        let dir = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
        let socket = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !dir.is_dir()
            || dir.uid() != expected.uid
            || dir.mode() & 0o777 != 0o700
            || !socket.file_type().is_socket()
            || socket.uid() != expected.uid
            || socket.mode() & 0o777 != 0o600
        {
            return Err("Untrusted socket owner/type/permissions".into());
        }
        let s = UnixStream::connect(path).map_err(|e| e.to_string())?;
        expected.verify(&s)?;
        Ok(s)
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|m| {
            m.ino() == self.inode && m.dev() == self.device && m.file_type().is_socket()
        }) {
            let _ = fs::remove_file(&self.path);
            if let Some(p) = self.path.parent() {
                let _ = fs::remove_dir(p);
            }
        }
    }
}
