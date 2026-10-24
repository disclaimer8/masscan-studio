//! Safe, laboratory-only socket primitives. All OS operations stay in this crate.
use std::{
    io,
    net::{Ipv4Addr, TcpListener},
    time::Duration,
};
#[derive(Debug, Clone, Copy)]
pub struct Received {
    pub len: usize,
    pub original_len: usize,
    pub truncated: bool,
    pub outgoing: bool,
}
#[derive(Debug, Clone, Copy)]
pub struct PacketStats {
    pub packets: u32,
    pub drops: u32,
}

/// Cryptographically random ownership nonce, from the operating system RNG.
#[cfg(unix)]
pub fn random_bytes_16() -> io::Result<[u8; 16]> {
    use std::io::Read;
    let mut bytes = [0; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_rng {
    use super::*;
    #[link(name = "bcrypt", kind = "raw-dylib")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut core::ffi::c_void,
            output: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }
    pub fn random_bytes_16() -> io::Result<[u8; 16]> {
        let mut bytes = [0; 16];
        // SAFETY: the system-preferred RNG accepts a null algorithm handle with
        // flag 2; output points to a live, writable 16-byte array for this call.
        let status = unsafe { BCryptGenRandom(core::ptr::null_mut(), bytes.as_mut_ptr(), 16, 2) };
        if status < 0 {
            return Err(io::Error::other(format!(
                "BCryptGenRandom failed: {status:#x}"
            )));
        }
        Ok(bytes)
    }
}
#[cfg(windows)]
pub use windows_rng::random_bytes_16;
#[cfg(not(any(unix, windows)))]
pub fn random_bytes_16() -> io::Result<[u8; 16]> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "OS random source unavailable",
    ))
}

/// Preserve ownership when sudo atomically replaces an unprivileged user's report.
/// Uses the already-open descriptor, so a pathname race cannot redirect chown.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn restore_sudo_owner(file: &std::fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: geteuid has no arguments or memory preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let Some(uid) = std::env::var_os("SUDO_UID") else {
        return Ok(());
    };
    let gid = std::env::var_os("SUDO_GID").unwrap_or_else(|| uid.clone());
    let parse = |s: &std::ffi::OsStr| -> io::Result<u32> {
        s.to_str()
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|id| *id != u32::MAX)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid SUDO_UID/SUDO_GID"))
    };
    let uid = parse(&uid)?;
    let gid = parse(&gid)?;
    // SAFETY: the borrowed File owns a live descriptor; numeric IDs were validated.
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
pub fn restore_sudo_owner(_file: &std::fs::File) -> io::Result<()> {
    Ok(())
}
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod platform {
    use super::*;
    use std::{
        ffi::CString,
        mem,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        sync::atomic::{AtomicBool, Ordering},
    };
    static STOP: AtomicBool = AtomicBool::new(false);
    extern "C" fn signal_handler(_: libc::c_int) {
        STOP.store(true, Ordering::Relaxed);
    }
    pub fn install_signal_handlers() -> io::Result<()> {
        STOP.store(false, Ordering::Relaxed);
        // SAFETY: handler is an extern C function performing only an atomic store.
        unsafe {
            if libc::signal(
                libc::SIGINT,
                signal_handler as *const () as libc::sighandler_t,
            ) == libc::SIG_ERR
                || libc::signal(
                    libc::SIGTERM,
                    signal_handler as *const () as libc::sighandler_t,
                ) == libc::SIG_ERR
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    pub fn stop_requested() -> bool {
        STOP.load(Ordering::Relaxed)
    }
    pub struct RawSocket(OwnedFd);
    impl RawSocket {
        pub fn open(iface: &str) -> io::Result<Self> {
            let name = CString::new(iface).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "interface contains NUL")
            })?;
            // SAFETY: name is a terminated CString.
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if index == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: socket has no pointer arguments and creates a fresh descriptor.
            let raw = unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    i32::from(3_u16.to_be()),
                )
            };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful socket returned a unique owned descriptor.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            // SAFETY: zero is valid for sockaddr_ll fields before assigning family/index/protocol.
            let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
            addr.sll_family = libc::AF_PACKET as u16;
            addr.sll_protocol = 3_u16.to_be();
            addr.sll_ifindex = index as i32;
            // SAFETY: pointer refers to a fully initialized sockaddr_ll with its exact size.
            if unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&addr as *const libc::sockaddr_ll).cast(),
                    mem::size_of_val(&addr) as _,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            let size: libc::c_int = 64 * 1024 * 1024;
            // SAFETY: option pointer/length reference a live integer; failure is reported.
            if unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&size as *const libc::c_int).cast(),
                    mem::size_of_val(&size) as _,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(fd))
        }
        pub fn send(&self, data: &[u8]) -> io::Result<usize> {
            // SAFETY: data pointer remains valid for data.len bytes during send.
            let n = unsafe { libc::send(self.0.as_raw_fd(), data.as_ptr().cast(), data.len(), 0) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
        pub fn recv(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<Received>> {
            let mut p = libc::pollfd {
                fd: self.0.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll gets a valid single pollfd and a bounded millisecond timeout.
            let ready =
                unsafe { libc::poll(&mut p, 1, timeout.as_millis().min(i32::MAX as u128) as i32) };
            if ready < 0 {
                let e = io::Error::last_os_error();
                return if e.kind() == io::ErrorKind::Interrupted {
                    Ok(None)
                } else {
                    Err(e)
                };
            }
            if ready == 0 {
                return Ok(None);
            }
            // SAFETY: zero is valid initialization for the output sockaddr_ll.
            let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
            let mut len = mem::size_of_val(&addr) as libc::socklen_t;
            // SAFETY: writable buffer and output address have their declared lengths. MSG_TRUNC returns wire length.
            let n = unsafe {
                libc::recvfrom(
                    self.0.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    libc::MSG_TRUNC,
                    (&mut addr as *mut libc::sockaddr_ll).cast(),
                    &mut len,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                return if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    Ok(None)
                } else {
                    Err(e)
                };
            }
            Ok(Some(Received {
                len: (n as usize).min(buf.len()),
                original_len: n as usize,
                truncated: n as usize > buf.len(),
                outgoing: addr.sll_pkttype == libc::PACKET_OUTGOING,
            }))
        }
        pub fn stats(&self) -> io::Result<PacketStats> {
            // SAFETY: zero is valid initialization for packet statistics output.
            let mut s: libc::tpacket_stats = unsafe { mem::zeroed() };
            let mut len = mem::size_of_val(&s) as libc::socklen_t;
            // SAFETY: output pointer and length refer to a live tpacket_stats.
            if unsafe {
                libc::getsockopt(
                    self.0.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_STATISTICS,
                    (&mut s as *mut libc::tpacket_stats).cast(),
                    &mut len,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(PacketStats {
                packets: s.tp_packets,
                drops: s.tp_drops,
            })
        }
    }
    pub fn listen(ip: Ipv4Addr, port: u16, backlog: i32) -> io::Result<TcpListener> {
        // SAFETY: creates a fresh IPv4 TCP descriptor.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is fresh and exclusively owned.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let one: libc::c_int = 1;
        // SAFETY: option pointer references a valid integer.
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                (&one as *const libc::c_int).cast(),
                mem::size_of_val(&one) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: all-zero sockaddr_in is a valid initialized representation.
        let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
        addr.sin_family = libc::AF_INET as u16;
        addr.sin_port = port.to_be();
        addr.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
        // SAFETY: initialized sockaddr and exact length; descriptor is a live TCP socket.
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_in).cast(),
                mem::size_of_val(&addr) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: listen operates on our successfully bound socket.
        if unsafe { libc::listen(fd.as_raw_fd(), backlog) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(TcpListener::from(fd))
    }
}
#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;
    fn unsupported() -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, "Linux laboratory sockets only")
    }
    pub struct RawSocket;
    impl RawSocket {
        pub fn open(_iface: &str) -> io::Result<Self> {
            Err(unsupported())
        }
        pub fn send(&self, _data: &[u8]) -> io::Result<usize> {
            Err(unsupported())
        }
        pub fn recv(&self, _buf: &mut [u8], _timeout: Duration) -> io::Result<Option<Received>> {
            Err(unsupported())
        }
        pub fn stats(&self) -> io::Result<PacketStats> {
            Err(unsupported())
        }
    }
    pub fn listen(_ip: Ipv4Addr, _port: u16, _backlog: i32) -> io::Result<TcpListener> {
        Err(unsupported())
    }
    pub fn install_signal_handlers() -> io::Result<()> {
        Err(unsupported())
    }
    pub fn stop_requested() -> bool {
        false
    }
}
pub use platform::{RawSocket, install_signal_handlers, listen, stop_requested};
