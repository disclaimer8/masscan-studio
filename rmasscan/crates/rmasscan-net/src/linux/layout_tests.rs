//! The netlink and AF_PACKET ABI that the Linux backend spells out by hand, checked against `libc`: a later refactor
//! may move these constants, and each one must keep the value of the kernel header it encodes.

use std::mem::{offset_of, size_of};

use super::abi::{self, errno};
use super::socket::SLL_MIN_LEN;
use crate::route_parse::{
    AF_INET, AF_INET6_LINUX, AF_UNSPEC, ARPHRD_ETHER, IFA_ADDRESS, IFA_F_DADFAILED,
    IFA_F_DEPRECATED, IFA_F_TENTATIVE, IFA_FLAGS, IFA_LOCAL, IFADDRMSG_LEN, IFF_UP, IFINFOMSG_LEN,
    IFLA_ADDRESS, IFLA_IFNAME, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR,
    NLMSG_HDRLEN, OFF_IFA_FAMILY, OFF_IFA_INDEX, OFF_IFA_PREFIXLEN, OFF_IFI_FAMILY, OFF_IFI_FLAGS,
    OFF_IFI_INDEX, OFF_IFI_TYPE, OFF_NLMSG_FLAGS, OFF_NLMSG_LEN, OFF_NLMSG_SEQ, OFF_NLMSG_TYPE,
    RT_TABLE_MAIN, RTA_DST, RTA_GATEWAY, RTA_HDRLEN, RTA_OIF, RTA_PREFSRC, RTA_PRIORITY, RTA_TABLE,
    RTM_GETADDR, RTM_GETLINK, RTM_GETROUTE, RTM_NEWADDR, RTM_NEWLINK, RTM_NEWROUTE, RTN_BLACKHOLE,
    RTN_LOCAL, RTN_PROHIBIT, RTN_UNICAST, RTN_UNREACHABLE,
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

/// Разбор наблюдения (`route_parse::observation_*`): константы и смещения полей, которые прежде были литералами в
/// `linux::route::observation` (тест задачи 1 сверял `libc` с литералами).
#[test]
fn observation_constants_and_offsets_match_libc() {
    assert_eq!(
        [RTM_NEWLINK, RTM_GETLINK],
        [libc::RTM_NEWLINK, libc::RTM_GETLINK]
    );
    assert_eq!(i32::from(NLM_F_DUMP_INTR), libc::NLM_F_DUMP_INTR);
    assert_eq!(ARPHRD_ETHER, libc::ARPHRD_ETHER);
    assert_eq!(IFF_UP, libc::IFF_UP.cast_unsigned());
    assert_eq!(i32::from(AF_UNSPEC), libc::AF_UNSPEC);
    assert_eq!(
        [IFLA_ADDRESS, IFLA_IFNAME],
        [libc::IFLA_ADDRESS, libc::IFLA_IFNAME]
    );
    assert_eq!(
        [
            OFF_NLMSG_LEN,
            OFF_NLMSG_TYPE,
            OFF_NLMSG_FLAGS,
            OFF_NLMSG_SEQ
        ],
        [
            offset_of!(libc::nlmsghdr, nlmsg_len),
            offset_of!(libc::nlmsghdr, nlmsg_type),
            offset_of!(libc::nlmsghdr, nlmsg_flags),
            offset_of!(libc::nlmsghdr, nlmsg_seq)
        ]
    );
    // Код `nlmsgerr` сразу за заголовком: разбор читает его по смещению `NLMSG_HDRLEN`.
    assert_eq!(offset_of!(libc::nlmsgerr, error), 0);
    assert_eq!(IFINFOMSG_LEN, size_of::<libc::ifinfomsg>());
    assert_eq!(
        [OFF_IFI_FAMILY, OFF_IFI_TYPE, OFF_IFI_INDEX, OFF_IFI_FLAGS],
        [
            offset_of!(libc::ifinfomsg, ifi_family),
            offset_of!(libc::ifinfomsg, ifi_type),
            offset_of!(libc::ifinfomsg, ifi_index),
            offset_of!(libc::ifinfomsg, ifi_flags)
        ]
    );
    assert_eq!(IFADDRMSG_LEN, size_of::<libc::ifaddrmsg>());
    assert_eq!(
        [OFF_IFA_FAMILY, OFF_IFA_PREFIXLEN, OFF_IFA_INDEX],
        [
            offset_of!(libc::ifaddrmsg, ifa_family),
            offset_of!(libc::ifaddrmsg, ifa_prefixlen),
            offset_of!(libc::ifaddrmsg, ifa_index)
        ]
    );
}

/// Номера `linux::abi`: переносимая логика адаптера (`TxHalf`, `RxHalf`, `verify_binding`) и её тесты читают их без
/// `libc`, поэтому собираются на любой ОС; здесь каждый сверяется с `libc` Linux.
#[test]
fn abi_numbers_match_libc() {
    assert_eq!(abi::ARPHRD_ETHER, libc::ARPHRD_ETHER);
    assert_eq!(abi::PACKET_OUTGOING, libc::PACKET_OUTGOING);
    assert_eq!(
        [
            errno::EPERM,
            errno::EINTR,
            errno::EIO,
            errno::ENXIO,
            errno::EBADF,
            errno::EAGAIN,
            errno::EWOULDBLOCK,
            errno::EINVAL,
            errno::EACCES,
            errno::ENODEV,
            errno::EPROTO,
            errno::ENOPROTOOPT,
            errno::ENETDOWN,
            errno::ENOBUFS
        ],
        [
            libc::EPERM,
            libc::EINTR,
            libc::EIO,
            libc::ENXIO,
            libc::EBADF,
            libc::EAGAIN,
            libc::EWOULDBLOCK,
            libc::EINVAL,
            libc::EACCES,
            libc::ENODEV,
            libc::EPROTO,
            libc::ENOPROTOOPT,
            libc::ENETDOWN,
            libc::ENOBUFS
        ]
    );
}
