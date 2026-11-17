//! The netlink and AF_PACKET ABI that the Linux backend spells out by hand, checked against `libc`: a later refactor
//! may move these constants, and each one must keep the value of the kernel header it encodes.

use std::mem::{offset_of, size_of};

use super::socket::SLL_MIN_LEN;
use crate::route_parse::{
    AF_INET, AF_INET6_LINUX, IFA_ADDRESS, IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_TENTATIVE,
    IFA_FLAGS, IFA_LOCAL, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NLMSG_HDRLEN,
    RT_TABLE_MAIN, RTA_DST, RTA_GATEWAY, RTA_HDRLEN, RTA_OIF, RTA_PREFSRC, RTA_PRIORITY, RTA_TABLE,
    RTM_GETADDR, RTM_GETROUTE, RTM_NEWADDR, RTM_NEWROUTE, RTN_BLACKHOLE, RTN_LOCAL, RTN_PROHIBIT,
    RTN_UNICAST, RTN_UNREACHABLE,
};

#[test]
fn netlink_constants_match_libc() {
    assert_eq!(NLMSG_HDRLEN, size_of::<libc::nlmsghdr>());
    assert_eq!(RTA_HDRLEN, size_of::<libc::rtattr>());
    assert_eq!(i32::from(NLMSG_ERROR), libc::NLMSG_ERROR);
    assert_eq!(i32::from(NLMSG_DONE), libc::NLMSG_DONE);
    assert_eq!(
        [RTM_NEWROUTE, RTM_GETROUTE, RTM_NEWADDR, RTM_GETADDR],
        [
            libc::RTM_NEWROUTE,
            libc::RTM_GETROUTE,
            libc::RTM_NEWADDR,
            libc::RTM_GETADDR
        ]
    );
    assert_eq!(i32::from(NLM_F_REQUEST), libc::NLM_F_REQUEST);
    assert_eq!(i32::from(NLM_F_DUMP), libc::NLM_F_DUMP);
    assert_eq!(
        [
            RTA_DST,
            RTA_OIF,
            RTA_GATEWAY,
            RTA_PRIORITY,
            RTA_TABLE,
            RTA_PREFSRC
        ],
        [
            libc::RTA_DST,
            libc::RTA_OIF,
            libc::RTA_GATEWAY,
            libc::RTA_PRIORITY,
            libc::RTA_TABLE,
            libc::RTA_PREFSRC
        ]
    );
    assert_eq!(
        [
            RTN_UNICAST.0,
            RTN_LOCAL.0,
            RTN_BLACKHOLE.0,
            RTN_UNREACHABLE.0,
            RTN_PROHIBIT.0
        ],
        [
            libc::RTN_UNICAST,
            libc::RTN_LOCAL,
            libc::RTN_BLACKHOLE,
            libc::RTN_UNREACHABLE,
            libc::RTN_PROHIBIT
        ]
    );
    assert_eq!(RT_TABLE_MAIN, u32::from(libc::RT_TABLE_MAIN));
    assert_eq!(
        [IFA_ADDRESS, IFA_LOCAL, IFA_FLAGS],
        [libc::IFA_ADDRESS, libc::IFA_LOCAL, libc::IFA_FLAGS]
    );
    assert_eq!(
        [IFA_F_DADFAILED.0, IFA_F_DEPRECATED.0, IFA_F_TENTATIVE.0],
        [
            libc::IFA_F_DADFAILED,
            libc::IFA_F_DEPRECATED,
            libc::IFA_F_TENTATIVE
        ]
    );
    assert_eq!(i32::from(AF_INET), libc::AF_INET);
    assert_eq!(i32::from(AF_INET6_LINUX), libc::AF_INET6);
    // `recvfrom` needs the address up to `sll_addr` to read `sll_ifindex` and `sll_pkttype`.
    assert_eq!(SLL_MIN_LEN, offset_of!(libc::sockaddr_ll, sll_addr));
    assert_eq!(SLL_MIN_LEN, 12);
}
