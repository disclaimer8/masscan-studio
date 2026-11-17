//! The Unix primitives of `unix_sys` on real descriptors of this process: the flags `socket` passes through, the
//! errno of a failing call, the `(n, revents)` pair of `poll_one` and the Linux helpers. Flags are read from ONE
//! descriptor (`unix_fd_tests::fd_flags`); nothing counts the descriptors of the process.

use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::AsFd;

use super::{mac_from_c_chars, poll_one, setsockopt_int, socket};
use crate::unix_fd_tests::fd_flags;

/// An idle UDP socket on loopback: nothing arrives unless a test sends it.
fn udp() -> UdpSocket {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("loopback UDP socket")
}

#[test]
fn socket_passes_flags_through() {
    #[cfg(target_os = "linux")]
    {
        let fd = socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
        .unwrap();
        let (status, cloexec) = fd_flags(fd.as_fd());
        assert!(cloexec, "SOCK_CLOEXEC sets FD_CLOEXEC");
        assert_ne!(
            status & libc::O_NONBLOCK,
            0,
            "SOCK_NONBLOCK sets O_NONBLOCK"
        );
        let fd = socket(libc::AF_INET, libc::SOCK_DGRAM, 0).unwrap();
        let (status, cloexec) = fd_flags(fd.as_fd());
        assert!(!cloexec, "without SOCK_CLOEXEC there is no FD_CLOEXEC");
        assert_eq!(
            status & libc::O_NONBLOCK,
            0,
            "without SOCK_NONBLOCK the socket blocks"
        );
    }
    #[cfg(target_os = "macos")]
    {
        let fd = socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_INET).unwrap();
        let (status, cloexec) = fd_flags(fd.as_fd());
        assert!(!cloexec, "PF_ROUTE without a flag has no FD_CLOEXEC");
        assert_eq!(
            status & libc::O_NONBLOCK,
            0,
            "PF_ROUTE without a flag blocks"
        );
    }
}

/// No such address family: the call fails before a descriptor exists, so the result carries only the errno.
#[test]
fn socket_error_is_errno() {
    assert_eq!(
        socket(-1, libc::SOCK_DGRAM, 0).err(),
        Some(libc::EAFNOSUPPORT)
    );
}

#[test]
fn poll_one_times_out_on_an_idle_udp_socket() {
    let sock = udp();
    assert_eq!(poll_one(sock.as_fd(), libc::POLLIN, 0), Ok((0, 0)));
}

#[test]
fn poll_one_reports_pollout_on_a_fresh_udp_socket() {
    let sock = udp();
    let (n, revents) = poll_one(sock.as_fd(), libc::POLLOUT, 0).unwrap();
    assert_eq!(n, 1, "one descriptor is ready");
    assert_ne!(revents & libc::POLLOUT, 0, "revents {revents:#x}");
}

#[test]
fn setsockopt_int_reports_enoprotoopt() {
    let sock = udp();
    assert_eq!(
        setsockopt_int(sock.as_fd(), libc::SOL_SOCKET, -1, 1),
        Err(libc::ENOPROTOOPT)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn nl_kernel_addr_is_the_kernel() {
    let addr = super::nl_kernel_addr();
    assert_eq!(i32::from(addr.nl_family), libc::AF_NETLINK);
    assert_eq!(addr.nl_pid, 0, "port id 0 is the kernel");
    assert_eq!(addr.nl_groups, 0, "no multicast groups");
}

#[test]
fn mac_from_c_chars_copies_six_bytes() {
    let src = [0x02u8, 0xaa, 0x00, 0xff, 0x80, 0x01, 0x77, 0x88].map(|b| b as libc::c_char);
    assert_eq!(mac_from_c_chars(&src), [0x02, 0xaa, 0x00, 0xff, 0x80, 0x01]);
}
