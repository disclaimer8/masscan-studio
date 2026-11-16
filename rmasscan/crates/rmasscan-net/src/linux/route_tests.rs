//! Route/interface observations only: no packet adapters and no network mutation.
use super::*;
use std::time::{Duration, Instant};

#[test]
fn network_plan_route_rejects_cancelled_or_expired_observation() {
    for cancelled in [true, false] {
        let result = OsRoutes.lookup_until(
            Ipv4Addr::LOCALHOST,
            if cancelled {
                Instant::now() + Duration::from_secs(1)
            } else {
                Instant::now()
            },
            &|| cancelled,
        );
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains(if cancelled { "cancelled" } else { "deadline" }),
            "{error}"
        );
    }
}

#[test]
fn network_plan_interfaces_reject_cancelled_or_expired_observation() {
    for cancelled in [true, false] {
        let result = OsIfaces.observe(
            if cancelled {
                Instant::now() + Duration::from_secs(1)
            } else {
                Instant::now()
            },
            &|| cancelled,
        );
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains(if cancelled { "cancelled" } else { "deadline" }),
            "{error}"
        );
    }
}

#[test]
fn network_plan_read_only_kernel_loopback_observations() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let route = OsRoutes
        .lookup_until(Ipv4Addr::LOCALHOST, deadline, &|| false)
        .unwrap()
        .expect("Linux always has the loopback route");
    assert!(route.local);
    let interfaces = OsIfaces.observe(deadline, &|| false).unwrap();
    let loopback = interfaces
        .iter()
        .find(|i| i.iface.index == route.ifindex)
        .unwrap();
    assert!(loopback.iface.ipv4.contains(&Ipv4Addr::LOCALHOST));
    assert!(
        loopback
            .ipv4_prefixes
            .contains(&crate::network_plan::Ipv4Prefix {
                address: Ipv4Addr::LOCALHOST,
                length: 8,
            })
    );
    assert!(!loopback.iface.ethernet);
}

#[test]
fn netlink_sockets_keep_their_flags() {
    use std::os::fd::AsFd;
    let netlink = Netlink::open().unwrap();
    let (status, cloexec) = crate::unix_fd_tests::fd_flags(netlink.fd.as_fd());
    assert!(cloexec, "Netlink::open must set FD_CLOEXEC");
    assert_eq!(status & libc::O_NONBLOCK, 0, "Netlink::open must block");
    let ioctl = IfSock::open().unwrap();
    let (status, cloexec) = crate::unix_fd_tests::fd_flags(ioctl.0.as_fd());
    assert!(cloexec, "IfSock::open must set FD_CLOEXEC");
    assert_eq!(status & libc::O_NONBLOCK, 0, "IfSock::open must block");
}
