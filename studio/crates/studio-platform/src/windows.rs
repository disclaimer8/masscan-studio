//! Local Windows session transport. Peer identity is bound to retained process
//! handles. This module does not elevate, install, or authorize raw scanning.
pub mod install;
use serde::{Deserialize, Serialize};
use std::{
    ffi::c_void,
    io::{self, Read, Write},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::PathBuf,
    ptr::{null, null_mut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{IO::*, Pipes::*, Threading::*},
};
type Result<T> = std::result::Result<T, String>;
const PREFIX: &str = r"\\.\pipe\MasscanStudio-";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn error() -> String {
    io::Error::last_os_error().to_string()
}
fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: caller transfers a newly acquired, valid, uniquely owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: this allocation was returned by a LocalAlloc-based Win32 API.
        unsafe {
            LocalFree(self.0);
        }
    }
}
// Only used with trusted, null-terminated strings allocated by Win32.
unsafe fn local_string(ptr: *mut u16) -> Result<String> {
    let allocation = Local(ptr.cast());
    let mut len = 0;
    // SAFETY: API returned a valid NUL-terminated UTF-16 allocation.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: length was measured within that live allocation.
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(ptr, len) })
        .map_err(|e| e.to_string());
    drop(allocation);
    result
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub pid: u32,
    pub birth: u64,
    pub sid: String,
    pub logon: [u32; 2],
    pub executable: PathBuf,
}
impl Identity {
    pub fn current() -> Result<Self> {
        Ok(Process::open(std::process::id())?.identity)
    }
}

pub struct Process {
    handle: OwnedHandle,
    identity: Identity,
}
impl Process {
    pub fn open(pid: u32) -> Result<Self> {
        if pid == 0 {
            return Err("Invalid peer PID".into());
        }
        // SAFETY: scalar PID/access mask; successful handle is transferred to RAII.
        let handle =
            owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) })
                .map_err(|e| e.to_string())?;
        let (mut birth, mut exit, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        // SAFETY: retained process handle, four correctly sized writable outputs.
        if unsafe {
            GetProcessTimes(
                handle.as_raw_handle(),
                &mut birth,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(error());
        }
        let mut path = vec![0u16; 32768];
        let mut size = path.len() as u32;
        // SAFETY: sized UTF-16 buffer lives throughout the synchronous call.
        if unsafe {
            QueryFullProcessImageNameW(handle.as_raw_handle(), 0, path.as_mut_ptr(), &mut size)
        } == 0
        {
            return Err(error());
        }
        if size as usize > path.len() {
            return Err("Invalid executable path length".into());
        }
        let executable =
            PathBuf::from(String::from_utf16(&path[..size as usize]).map_err(|e| e.to_string())?);
        let mut token = null_mut();
        // SAFETY: valid process handle and writable HANDLE output.
        if unsafe { OpenProcessToken(handle.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(error());
        }
        let token = owned(token).map_err(|e| e.to_string())?;
        let mut length = 0;
        // SAFETY: size query uses a null buffer with length zero.
        unsafe {
            GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut length);
        }
        if length < std::mem::size_of::<TOKEN_USER>() as u32 || length > 65536 {
            return Err("Invalid token user size".into());
        }
        // usize provides the alignment required for TOKEN_USER (including its pointer).
        let mut storage = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: aligned buffer with at least the advertised writable byte length.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                storage.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        } == 0
        {
            return Err(error());
        }
        // SAFETY: successful TokenUser output starts with TOKEN_USER; SID points
        // inside storage, which remains live through ConvertSidToStringSidW.
        let sid = unsafe { (*storage.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut sid_text = null_mut();
        // SAFETY: valid SID from live token buffer and writable PWSTR output.
        if unsafe { ConvertSidToStringSidW(sid, &mut sid_text) } == 0 {
            return Err(error());
        }
        // SAFETY: successful Win32 conversion returned a LocalAlloc-owned string.
        let sid = unsafe { local_string(sid_text)? };
        let mut statistics = TOKEN_STATISTICS::default();
        // SAFETY: output type matches TokenStatistics and has its exact size.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenStatistics,
                (&mut statistics as *mut TOKEN_STATISTICS).cast(),
                std::mem::size_of_val(&statistics) as u32,
                &mut length,
            )
        } == 0
        {
            return Err(error());
        }
        let identity = Identity {
            pid,
            birth: ((birth.dwHighDateTime as u64) << 32) | birth.dwLowDateTime as u64,
            sid,
            logon: [
                statistics.AuthenticationId.LowPart,
                statistics.AuthenticationId.HighPart as u32,
            ],
            executable,
        };
        let process = Self { handle, identity };
        process.ensure_alive()?;
        Ok(process)
    }
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn ensure_alive(&self) -> Result<()> {
        // SAFETY: retained process handle supports SYNCHRONIZE; zero wait is a probe.
        match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(()),
            WAIT_OBJECT_0 => Err("Peer process exited".into()),
            _ => Err(error()),
        }
    }
    pub fn verify(&self, expected: &Identity) -> Result<()> {
        self.ensure_alive()?;
        if self.identity != *expected {
            return Err("Peer account/process/birth does not match this launch".into());
        }
        Ok(())
    }
    fn verify_pipe(&self, pipe: HANDLE, server: bool) -> Result<()> {
        self.ensure_alive()?;
        let mut pid = 0;
        // SAFETY: live named-pipe handle and writable DWORD. Direction describes
        // the local end, so the query retrieves the opposite process.
        let ok = unsafe {
            if server {
                GetNamedPipeClientProcessId(pipe, &mut pid)
            } else {
                GetNamedPipeServerProcessId(pipe, &mut pid)
            }
        };
        if ok == 0 {
            return Err(error());
        }
        if pid != self.identity.pid {
            return Err("Unexpected pipe peer process".into());
        }
        self.ensure_alive()
    }
}

/// Execute one operation, waiting synchronously on its overlapped completion.
/// The caller's buffer and this stack's OVERLAPPED remain live until completion,
/// including after cancellation. No pending Win32 request escapes this function.
fn operation(
    handle: HANDLE,
    timeout: Option<Duration>,
    cancelled: impl Fn() -> bool,
    issue: impl FnOnce(*mut OVERLAPPED) -> io::Result<()>,
) -> io::Result<u32> {
    // SAFETY: null security attributes => non-inherited unnamed manual-reset event.
    let event = owned(unsafe { CreateEventW(null(), 1, 0, null()) })?;
    let mut overlapped = OVERLAPPED {
        hEvent: event.as_raw_handle(),
        ..Default::default()
    };
    if cancelled() {
        return Err(io::Error::other("Pipe operation cancelled"));
    }
    issue(&mut overlapped)?;
    let mut transferred = 0;
    // SAFETY: query the issued request without waiting. Immediate completion
    // need not signal the event; only IO_INCOMPLETE requires the wait loop.
    // Completed requests no longer borrow the caller's buffer/OVERLAPPED.
    if unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, 0) } != 0 {
        return Ok(transferred);
    }
    let current = io::Error::last_os_error();
    if current.raw_os_error() != Some(ERROR_IO_INCOMPLETE as i32) {
        return Err(current);
    }
    let deadline = timeout.map(|d| Instant::now() + d);
    let interrupted = loop {
        // SAFETY: event and OVERLAPPED remain alive; completion owns no Rust data.
        match unsafe { WaitForSingleObject(event.as_raw_handle(), 20) } {
            WAIT_OBJECT_0 => break None,
            WAIT_TIMEOUT => {}
            _ => break Some(io::Error::last_os_error()),
        }
        if cancelled() {
            break Some(io::Error::other("Pipe operation cancelled or peer exited"));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            break Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "Pipe operation timed out",
            ));
        }
    };
    if interrupted.is_some() {
        // SAFETY: cancel only this still-live OVERLAPPED; cancellation is not
        // completion, so GetOverlappedResult below must run before stack release.
        unsafe {
            CancelIoEx(handle, &overlapped);
        }
    }
    // SAFETY: same handle/OVERLAPPED as issued; TRUE drains completion even on
    // cancellation. Buffers and event remain alive until this call returns.
    let ok = unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, 1) };
    if let Some(e) = interrupted {
        return Err(e);
    }
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(transferred)
}
fn pending(ok: i32) -> io::Result<()> {
    if ok != 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(ERROR_IO_PENDING as i32) {
        Ok(())
    } else {
        Err(e)
    }
}

pub struct Endpoint {
    handle: OwnedHandle,
    name: String,
    owner: Identity,
}
impl Endpoint {
    pub fn create() -> Result<Self> {
        let owner = Identity::current()?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
        let name = format!(
            "{PREFIX}{}",
            nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let descriptor = wide(&format!("D:P(A;;GA;;;{})", owner.sid));
        let mut security = null_mut();
        // SAFETY: NUL-terminated SDDL built with the OS-produced SID, valid output.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor.as_ptr(),
                SDDL_REVISION_1,
                &mut security,
                null_mut(),
            )
        } == 0
        {
            return Err(error());
        }
        let security = Local(security);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.0,
            bInheritHandle: 0,
        };
        let text = wide(&name);
        // SAFETY: valid name/security live through the call; result uniquely owned.
        let handle = owned(unsafe {
            CreateNamedPipeW(
                text.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                0,
                &attributes,
            )
        })
        .map_err(|e| e.to_string())?;
        Ok(Self {
            handle,
            name,
            owner,
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn accept(
        self,
        expected: Process,
        timeout: Duration,
        cancelled: &AtomicBool,
    ) -> Result<Stream> {
        if expected.identity.sid != self.owner.sid || expected.identity.logon != self.owner.logon {
            return Err("Runner must belong to this user and logon session".into());
        }
        let handle = self.handle.as_raw_handle();
        operation(
            handle,
            Some(timeout),
            || cancelled.load(Ordering::Acquire) || expected.ensure_alive().is_err(),
            |overlapped| {
                // SAFETY: operation owns the live OVERLAPPED until completion.
                let ok = unsafe { ConnectNamedPipe(handle, overlapped) };
                if ok == 0
                    && io::Error::last_os_error().raw_os_error()
                        == Some(ERROR_PIPE_CONNECTED as i32)
                {
                    // Connected before ConnectNamedPipe: there is no pending request.
                    // Treat it separately outside operation's completion machinery.
                    return Err(io::Error::from_raw_os_error(ERROR_PIPE_CONNECTED as i32));
                }
                pending(ok)
            },
        )
        .or_else(|e| {
            if e.raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32) {
                Ok(0)
            } else {
                Err(e)
            }
        })
        .map_err(|e| e.to_string())?;
        expected.verify_pipe(handle, true)?;
        Ok(Stream(Arc::new(Connected {
            handle: self.handle,
            peer: expected,
            closed: AtomicBool::new(false),
            server: true,
        })))
    }
}
struct Connected {
    handle: OwnedHandle,
    peer: Process,
    closed: AtomicBool,
    server: bool,
}
#[derive(Clone)]
pub struct Stream(Arc<Connected>);
impl Stream {
    pub fn connect(
        name: &str,
        expected: &Identity,
        timeout: Duration,
        cancelled: &AtomicBool,
    ) -> Result<Self> {
        let suffix = name
            .strip_prefix(PREFIX)
            .ok_or("Only a local Studio pipe is accepted")?;
        if suffix.len() != 32 || !suffix.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("Invalid Studio pipe name".into());
        }
        let peer = Process::open(expected.pid)?;
        peer.verify(expected)?;
        let me = Identity::current()?;
        if me.sid != expected.sid || me.logon != expected.logon {
            return Err("UI must belong to this user and logon session".into());
        }
        let text = wide(name);
        let deadline = Instant::now() + timeout;
        let handle = loop {
            if cancelled.load(Ordering::Acquire) {
                return Err("Pipe connection cancelled".into());
            }
            peer.ensure_alive()?;
            // SAFETY: valid local pipe path, no inherited handle, overlapped mode.
            // Identification SQOS prevents the server impersonating this client.
            let raw = unsafe {
                CreateFileW(
                    text.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    null_mut(),
                )
            };
            match owned(raw) {
                Ok(h) => break h,
                Err(e) if matches!(e.raw_os_error(), Some(v) if v == ERROR_PIPE_BUSY as i32 || v == ERROR_FILE_NOT_FOUND as i32) =>
                    {}
                Err(e) => return Err(e.to_string()),
            }
            if Instant::now() >= deadline {
                return Err("Pipe connection timed out".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        peer.verify_pipe(handle.as_raw_handle(), false)?;
        Ok(Self(Arc::new(Connected {
            handle,
            peer,
            closed: AtomicBool::new(false),
            server: false,
        })))
    }
    pub fn ensure_peer_alive(&self) -> Result<()> {
        self.0.peer.ensure_alive()
    }
    pub fn shutdown(&self) {
        self.0.closed.store(true, Ordering::Release);
        // SAFETY: retained pipe handle. Operations also poll closed to cover a
        // race where cancellation occurs just before ReadFile/WriteFile issues.
        unsafe {
            CancelIoEx(self.0.handle.as_raw_handle(), null());
            if self.0.server {
                DisconnectNamedPipe(self.0.handle.as_raw_handle());
            }
        }
    }
    fn cancelled(&self) -> bool {
        self.0.closed.load(Ordering::Acquire) || self.0.peer.ensure_alive().is_err()
    }
}
impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let handle = self.0.handle.as_raw_handle();
        let len = buf.len().min(u32::MAX as usize) as u32;
        let result = operation(
            handle,
            None,
            || self.cancelled(),
            |overlapped| {
                // SAFETY: writable buffer and OVERLAPPED remain alive until operation
                // drains completion; only its byte count is returned to Read's caller.
                pending(unsafe { ReadFile(handle, buf.as_mut_ptr(), len, null_mut(), overlapped) })
            },
        );
        match result {
            Ok(n) => Ok(n as usize),
            Err(e) if e.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => Ok(0),
            Err(e) => Err(e),
        }
    }
}
impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let handle = self.0.handle.as_raw_handle();
        let len = buf.len().min(u32::MAX as usize) as u32;
        operation(
            handle,
            None,
            || self.cancelled(),
            |overlapped| {
                // SAFETY: immutable buffer remains live until completion is drained.
                pending(unsafe { WriteFile(handle, buf.as_ptr(), len, null_mut(), overlapped) })
            },
        )
        .map(|n| n as usize)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn synchronous_completion_does_not_require_event_signaling() {
        let endpoint = Endpoint::create().unwrap();
        // Model the documented synchronous completion case: completed status
        // and byte count are available, but no event was signaled.
        let bytes = operation(
            endpoint.handle.as_raw_handle(),
            Some(Duration::from_millis(30)),
            || false,
            |overlapped| {
                // SAFETY: operation supplies its live writable OVERLAPPED.
                unsafe {
                    (*overlapped).InternalHigh = 7;
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(bytes, 7);
    }
    #[test]
    fn endpoint_has_one_explicit_owner_ace_and_rejects_second_instance() {
        let endpoint = Endpoint::create().unwrap();
        let mut descriptor = null_mut();
        let mut acl = null_mut();
        // SAFETY: valid pipe handle, correctly typed writable pointer outputs.
        let status = unsafe {
            GetSecurityInfo(
                endpoint.handle.as_raw_handle(),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        let descriptor = Local(descriptor);
        assert!(!acl.is_null(), "a NULL DACL grants everyone access");
        // SAFETY: GetSecurityInfo returned an ACL within the live descriptor.
        assert_eq!(unsafe { (*acl).AceCount }, 1);
        let mut ace = null_mut();
        // SAFETY: index zero exists; output points within live ACL allocation.
        assert_ne!(unsafe { GetAce(acl, 0, &mut ace) }, 0);
        let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
        // SAFETY: inspect ACE header before interpreting its SID layout.
        assert_eq!(unsafe { (*ace).Header.AceType }, 0); // ACCESS_ALLOWED_ACE_TYPE
        let mut text = null_mut();
        // SAFETY: access-allowed ACE SID starts at SidStart, variable length
        // resides within the descriptor, which remains live during conversion.
        assert_ne!(
            unsafe {
                ConvertSidToStringSidW(
                    std::ptr::addr_of!((*ace).SidStart).cast_mut().cast(),
                    &mut text,
                )
            },
            0
        );
        // SAFETY: successful Win32 conversion owns a terminated LocalAlloc string.
        assert_eq!(unsafe { local_string(text) }.unwrap(), endpoint.owner.sid);
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: valid descriptor and scalar output pointers.
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) },
            0
        );
        assert_ne!(control & SE_DACL_PROTECTED, 0);
        let name = wide(endpoint.name());
        // SAFETY: attempt another first instance with the same bounded name;
        // a valid unexpected handle is still transferred to RAII before panic.
        let duplicate = owned(unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                null(),
            )
        });
        assert!(duplicate.is_err());
    }
}
