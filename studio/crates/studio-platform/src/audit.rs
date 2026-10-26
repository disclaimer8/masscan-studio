//! macOS socket peer identity without privileged PROC_PIDTBSDINFO access.
//! LOCAL_PEERTOKEN is kernel-supplied; proc_pidpath_audittoken compares PID
//! incarnation in the kernel (PIF_COMPARE_IDVERSION), not merely a numeric PID.
use std::{
    io,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::PathBuf,
};
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AuditToken {
    val: [u32; 8],
}
#[link(name = "proc")]
unsafe extern "C" {
    fn proc_pidpath_audittoken(
        token: *mut AuditToken,
        buffer: *mut libc::c_void,
        size: u32,
    ) -> libc::c_int;
}
#[link(name = "bsm")]
unsafe extern "C" {
    fn audit_token_to_pid(token: AuditToken) -> libc::pid_t;
    fn audit_token_to_euid(token: AuditToken) -> libc::uid_t;
}
fn socket_token(stream: &UnixStream) -> io::Result<AuditToken> {
    let mut token = AuditToken { val: [0; 8] };
    let mut size = std::mem::size_of::<AuditToken>() as libc::socklen_t;
    // SAFETY: socket remains borrowed/alive; token and size are correctly sized
    // writable C-layout outputs. Reject a short/failed write before use.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            0,
            libc::LOCAL_PEERTOKEN,
            (&mut token as *mut AuditToken).cast(),
            &mut size,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of::<AuditToken>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Incomplete peer audit token",
        ));
    }
    Ok(token)
}
fn path(mut token: AuditToken) -> io::Result<PathBuf> {
    let mut bytes = [0u8; 4096];
    // SAFETY: token matches SDK audit_token_t layout; path buffer is writable
    // for declared size. API available since macOS 11, below our macOS 14 floor.
    let n = unsafe {
        proc_pidpath_audittoken(&mut token, bytes.as_mut_ptr().cast(), bytes.len() as u32)
    };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;
    if n >= bytes.len() || bytes[n] != 0 || bytes[..n].contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid audited process path",
        ));
    }
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&bytes[..n])))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub pid: u32,
    pub uid: u32,
    pub executable: PathBuf,
    token: AuditToken,
}
impl Peer {
    pub fn from_stream(stream: &UnixStream) -> Result<Self, String> {
        let token = socket_token(stream).map_err(|e| e.to_string())?;
        // SAFETY: by-value SDK-compatible initialized audit token. Accessors
        // avoid depending on the private field meanings for UID/PID extraction.
        let (pid, uid) = unsafe { (audit_token_to_pid(token), audit_token_to_euid(token)) };
        if pid <= 0 {
            return Err("Invalid audited peer PID".into());
        }
        let executable = path(token).map_err(|e| format!("Cannot resolve audited peer: {e}"))?;
        if token != socket_token(stream).map_err(|e| e.to_string())? {
            return Err("Socket peer changed during inspection".into());
        }
        Ok(Self {
            pid: pid as u32,
            uid,
            executable,
            token,
        })
    }
    pub fn verify(&self, stream: &UnixStream) -> Result<(), String> {
        if Self::from_stream(stream)? != *self {
            return Err("Audited peer changed".into());
        }
        Ok(())
    }
    pub fn is_alive(&self) -> Result<bool, String> {
        match path(self.token) {
            Ok(p) => Ok(p == self.executable),
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(false),
            Err(e) => Err(format!("Cannot establish audited process exit: {e}")),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrong_pid_incarnation_is_rejected_by_kernel() {
        let endpoint = crate::unix::Endpoint::create().unwrap();
        let stream = UnixStream::connect(endpoint.path()).unwrap();
        let token = socket_token(&stream).unwrap();
        assert!(path(token).is_ok());
        let mut stale = token;
        // XNU's proc_pidpath_audittoken implementation identifies val[7] as
        // idversion; perturb only that value to keep a real, live numeric PID.
        stale.val[7] ^= 1;
        assert!(
            path(stale).is_err(),
            "reused numeric PID must not authenticate"
        );
    }
}
