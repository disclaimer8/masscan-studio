//! Laboratory-only process primitives, behind the non-default `lab` feature that only
//! `rmasscan-lab` enables. Everything the lab harness can do with the standard library lives
//! in `rmasscan-lab` (which forbids `unsafe`); what remains here needs a libc call:
//!
//! * a flag-only SIGINT/SIGTERM/SIGHUP handler (a closed terminal or a dropped ssh session is a stop too) installed with `sigaction` (graceful Ctrl-C for the
//!   orchestrator and cooperative stop for the peer helpers);
//! * the backlog-0 "silent" listener the VM lab uses to prove a port that accepts one
//!   connection and then lets further SYNs go unanswered.
//!
//! Raw frames are NOT sent or received here: the lab uses `open_explicit` like the product, and
//! captures with the independent `tcpdump`.
use std::{
    io,
    net::{Ipv4Addr, TcpListener},
};

/// Install a flag-only handler for SIGINT, SIGTERM and SIGHUP (unix) and clear the flag. Off unix there
/// is nothing to install and [`stop_requested`] stays false.
pub fn install_signal_handlers() -> io::Result<()> {
    imp::install()
}

/// Whether a handled signal arrived since [`install_signal_handlers`].
pub fn stop_requested() -> bool {
    imp::stop_requested()
}

/// A TCP listener on `ip:port` whose accept queue holds at most one completed connection
/// (listen backlog 0). The first connection is accepted by the kernel and kept; later SYNs are
/// dropped silently, so a second connect times out instead of being refused.
pub fn silent_listener(ip: Ipv4Addr, port: u16) -> io::Result<TcpListener> {
    let listener = TcpListener::bind((ip, port))?;
    imp::set_backlog(&listener, 0)?;
    Ok(listener)
}

#[cfg(unix)]
#[allow(unsafe_code)]
mod imp {
    use std::{
        io, mem,
        net::TcpListener,
        os::fd::AsRawFd,
        sync::atomic::{AtomicBool, Ordering},
    };

    static STOP: AtomicBool = AtomicBool::new(false);

    /// Async-signal-safe: a single store to a lock-free atomic.
    extern "C" fn on_signal(_: libc::c_int) {
        STOP.store(true, Ordering::Relaxed);
    }

    pub fn install() -> io::Result<()> {
        STOP.store(false, Ordering::Relaxed);
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: an all-zero `sigaction` is a valid starting value; `sa_mask` is then
            // initialised by `sigemptyset` on that same live local, `on_signal` is an
            // `extern "C"` function that only stores to a static atomic, and the pointer
            // passed to `sigaction` refers to the live, fully initialised local. The old
            // action pointer is null, which `sigaction` permits.
            let rc = unsafe {
                let mut action: libc::sigaction = mem::zeroed();
                action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
                action.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&mut action.sa_mask);
                libc::sigaction(signal, &action, std::ptr::null_mut())
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub fn stop_requested() -> bool {
        STOP.load(Ordering::Relaxed)
    }

    /// `listen` on an already-listening socket only updates its backlog.
    pub fn set_backlog(listener: &TcpListener, backlog: i32) -> io::Result<()> {
        // SAFETY: the descriptor belongs to the borrowed live listener; `listen` takes no
        // pointers.
        if unsafe { libc::listen(listener.as_raw_fd(), backlog) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(not(unix))]
mod imp {
    use std::{io, net::TcpListener};
    pub fn install() -> io::Result<()> {
        Ok(())
    }
    pub fn stop_requested() -> bool {
        false
    }
    pub fn set_backlog(_: &TcpListener, _: i32) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "silent listener needs a unix host",
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        net::{SocketAddr, TcpStream},
        time::Duration,
    };

    /// No root, no packets, no namespaces: loopback only. Linux accept-queue semantics (queue
    /// length must exceed the backlog to drop): this test cannot assert silence on macOS, whose
    /// kernel keeps completing connections, so it is Linux-only and runs in the Linux CI job.
    #[cfg(target_os = "linux")]
    #[test]
    fn silent_listener_accepts_one_connection_then_goes_quiet() {
        let l = silent_listener(Ipv4Addr::LOCALHOST, 0).unwrap();
        let addr = l.local_addr().unwrap();
        // The kernel completes the first handshake into the accept queue.
        let first = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        // Backlog 0 holds one connection; the next SYN is dropped, not refused. Linux and
        // macOS differ in how long the queue overflow takes to show, so allow a few tries.
        let mut silent = false;
        for _ in 0..6 {
            match TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    silent = true;
                    break;
                }
                Ok(_) | Err(_) => {}
            }
        }
        drop(first);
        assert!(
            silent,
            "a connection beyond the backlog must time out silently"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_silent_listener_binds_and_completes_the_first_handshake_on_any_unix() {
        let l = silent_listener(Ipv4Addr::LOCALHOST, 0).unwrap();
        let addr = l.local_addr().unwrap();
        assert!(TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok());
        // A port already in use is an error, not a silent success.
        assert!(silent_listener(Ipv4Addr::LOCALHOST, addr.port()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_listener_semantics_are_those_of_the_standard_library() {
        // The open ports of the lab peer use std::net::TcpListener::bind (SO_REUSEADDR,
        // backlog 128): many connections complete.
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr: SocketAddr = l.local_addr().unwrap();
        let clients: Vec<_> = (0..8)
            .map(|_| TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap())
            .collect();
        assert_eq!(clients.len(), 8);
    }

    /// The only test in this crate that touches the process-wide flag, so no race.
    #[cfg(unix)]
    #[test]
    fn sigterm_sigint_and_sighup_set_the_flag_and_install_clears_it() {
        for signal in ["-TERM", "-INT", "-HUP"] {
            install_signal_handlers().unwrap();
            assert!(!stop_requested(), "installing clears the flag");
            // `kill` runs as a child process so the test needs no unsafe code; the handler
            // is installed, so the signal only sets the flag.
            let status = std::process::Command::new("kill")
                .args([signal, &std::process::id().to_string()])
                .status()
                .unwrap();
            assert!(status.success());
            for _ in 0..300 {
                if stop_requested() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(stop_requested(), "{signal} must set the stop flag");
        }
    }
}
