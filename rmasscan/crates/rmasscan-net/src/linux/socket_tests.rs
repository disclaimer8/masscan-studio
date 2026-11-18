//! The receive buffer `PacketFd::open` asks for on the RX socket (P5): the `setsockopt` helper on an ordinary
//! AF_INET datagram socket (no privileges needed) and the order of the two requests through their seam. AF_PACKET
//! itself needs CAP_NET_RAW: the privileged check of both adapter sockets is `lab_rx_socket_buffer_is_raised` in
//! `tests/linux_io.rs`.

use std::ffi::c_int;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

use super::{Errno, RX_SOCKET_BUFFER, TX_SOCKET_BUFFER, ioctl_socket, request_rx_buffer};
// The helper of task 2b moved to the shared Unix primitives; these tests keep its old name.
use crate::unix_sys::setsockopt_int as set_int_opt;

/// `getsockopt` of one `c_int` option of `fd`.
fn get_int_opt(fd: BorrowedFd<'_>, level: c_int, name: c_int) -> c_int {
    let mut value: c_int = 0;
    let mut len = mem::size_of::<c_int>() as libc::socklen_t;
    // SAFETY: `value` and `len` are live locals and `len` holds the size of `value`, so the kernel writes at most
    // that many bytes; `fd` is borrowed, so it stays open for the whole call.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&raw mut value).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    assert_eq!(
        rc,
        0,
        "getsockopt({level}, {name}): {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(len as usize, mem::size_of::<c_int>(), "option length");
    value
}

#[test]
fn rx_socket_buffer_is_4_mib() {
    assert_eq!(RX_SOCKET_BUFFER, 4 * 1024 * 1024);
}

/// P3: the TX socket asks for the same 4 MiB as its send buffer (`SO_SNDBUF`); the read-back on a real TX socket is
/// `lab_tx_socket_send_buffer_is_raised` in `tests/linux_io.rs`.
#[test]
fn tx_socket_buffer_is_4_mib() {
    assert_eq!(TX_SOCKET_BUFFER, 4 * 1024 * 1024);
}

/// Without CAP_NET_ADMIN the kernel caps `SO_RCVBUF` at `net.core.rmem_max` and stores double the capped value, so
/// a read-back of at least 4 MiB is not guaranteed here. It is always above the default of a fresh socket
/// (`net.core.rmem_default`, stored as is), unless the host sets `rmem_default` above `2 * rmem_max`.
#[test]
fn set_int_opt_raises_the_receive_buffer_of_an_ordinary_socket() {
    let sock = ioctl_socket().expect("AF_INET datagram socket");
    let fd = sock.as_fd();
    let before = get_int_opt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF);
    assert_eq!(
        set_int_opt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, RX_SOCKET_BUFFER),
        Ok(())
    );
    let after = get_int_opt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF);
    assert!(after > before, "SO_RCVBUF {before} -> {after}");
}

/// The helper hands the errno of a failing `setsockopt` to its caller: the fallback below depends on it.
#[test]
fn set_int_opt_returns_the_errno_of_a_failing_setsockopt() {
    let sock = ioctl_socket().expect("AF_INET datagram socket");
    assert_eq!(
        set_int_opt(sock.as_fd(), libc::SOL_SOCKET, -1, 1),
        Err(libc::ENOPROTOOPT)
    );
}

const FORCE: (c_int, c_int) = (libc::SO_RCVBUFFORCE, RX_SOCKET_BUFFER);
const PLAIN: (c_int, c_int) = (libc::SO_RCVBUF, RX_SOCKET_BUFFER);

/// `request_rx_buffer` against scripted `setsockopt(SOL_SOCKET, …)` results: its result and every call made.
fn request(script: &[Result<(), Errno>]) -> (Result<(), Errno>, Vec<(c_int, c_int)>) {
    let mut results = script.iter().copied();
    let mut calls = Vec::new();
    let r = request_rx_buffer(|name, value| {
        calls.push((name, value));
        results.next().expect("one setsockopt more than scripted")
    });
    assert!(results.next().is_none(), "scripted results left: {calls:?}");
    (r, calls)
}

#[test]
fn rx_buffer_is_forced_first_and_a_success_ends_the_request() {
    assert_eq!(request(&[Ok(())]), (Ok(()), vec![FORCE]));
}

#[test]
fn rx_buffer_without_cap_net_admin_falls_back_to_so_rcvbuf() {
    assert_eq!(
        request(&[Err(libc::EPERM), Ok(())]),
        (Ok(()), vec![FORCE, PLAIN])
    );
    // A failing fallback is reported (open ignores it) and not retried.
    assert_eq!(
        request(&[Err(libc::EPERM), Err(libc::ENOBUFS)]),
        (Err(libc::ENOBUFS), vec![FORCE, PLAIN])
    );
}

#[test]
fn rx_buffer_falls_back_only_on_eperm() {
    for e in [
        libc::EACCES,
        libc::EINVAL,
        libc::ENOPROTOOPT,
        libc::ENOMEM,
        libc::EBADF,
    ] {
        assert_eq!(request(&[Err(e)]), (Err(e), vec![FORCE]), "errno {e}");
    }
}
