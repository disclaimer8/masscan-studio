//! Разбор ответов ядра о маршрутах и адресах IPv6 на синтетических байтах (любая ОС): Linux rtnetlink
//! (`RTM_GETROUTE`/`RTM_GETADDR` `AF_INET6`), Darwin route socket (`RTM_GET` с `sockaddr_in6`, KAME scope), Windows
//! IP Helper (`GetBestRoute2` `AF_INET6`). Адреса только ULA `fd00::/8`, документационные `2001:db8::/32` и
//! link-local.

use std::net::Ipv6Addr;

use super::*;
use crate::discover::{Iface, RouteV6};

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn pad4(b: &mut Vec<u8>) {
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
}

// ---------- Linux rtnetlink ----------

const LINUX_AF_INET6: u8 = 10;

fn nlmsg(ty: u16, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(((NLMSG_HDRLEN + body.len()) as u32).to_ne_bytes());
    b.extend(ty.to_ne_bytes());
    b.extend(flags.to_ne_bytes());
    b.extend(1u32.to_ne_bytes());
    b.extend(4242u32.to_ne_bytes());
    b.extend(body);
    pad4(&mut b);
    b
}

fn rtattr(ty: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(((4 + payload.len()) as u16).to_ne_bytes());
    b.extend(ty.to_ne_bytes());
    b.extend(payload);
    pad4(&mut b);
    b
}

fn route6_msg(kind: u8, dst_len: u8, table: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![LINUX_AF_INET6, dst_len, 0, 0, table, 3, 0, kind];
    b.extend(0u32.to_ne_bytes());
    for a in attrs {
        b.extend(a);
    }
    nlmsg(RTM_NEWROUTE, 0, &b)
}

fn addr6_msg(index: u32, flags8: u8, scope: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![LINUX_AF_INET6, 64, flags8, scope];
    b.extend(index.to_ne_bytes());
    for a in attrs {
        b.extend(a);
    }
    nlmsg(RTM_NEWADDR, 2, &b)
}

fn done() -> Vec<u8> {
    nlmsg(NLMSG_DONE, 2, &0i32.to_ne_bytes())
}

#[test]
fn netlink_ipv6_requests_are_well_formed() {
    let get = netlink_route_request6(9, Some(v6("2001:db8::7")));
    assert_eq!(get.len(), NLMSG_HDRLEN + RTMSG_LEN + 4 + 16);
    assert_eq!(
        u32::from_ne_bytes(get[0..4].try_into().unwrap()) as usize,
        get.len()
    );
    assert_eq!(u16::from_ne_bytes([get[4], get[5]]), RTM_GETROUTE);
    assert_eq!(u16::from_ne_bytes([get[6], get[7]]), NLM_F_REQUEST);
    assert_eq!(u32::from_ne_bytes(get[8..12].try_into().unwrap()), 9);
    let rt = &get[16..28];
    assert_eq!(
        (rt[0], rt[1]),
        (LINUX_AF_INET6, 128),
        "AF_INET6, dst_len 128"
    );
    assert_eq!(&rt[2..], &[0; 10]);
    assert_eq!(u16::from_ne_bytes([get[28], get[29]]), 20);
    assert_eq!(u16::from_ne_bytes([get[30], get[31]]), RTA_DST);
    assert_eq!(
        &get[32..48],
        &v6("2001:db8::7").octets(),
        "RTA_DST, network order"
    );

    let dump = netlink_route_request6(10, None);
    assert_eq!(dump.len(), NLMSG_HDRLEN + RTMSG_LEN);
    assert_eq!(
        u16::from_ne_bytes([dump[6], dump[7]]),
        NLM_F_REQUEST | NLM_F_DUMP
    );
    assert_eq!((dump[16], dump[17]), (LINUX_AF_INET6, 0));

    let addrs = netlink_addr_request6(11);
    assert_eq!(addrs.len(), NLMSG_HDRLEN + 8);
    assert_eq!(u16::from_ne_bytes([addrs[4], addrs[5]]), RTM_GETADDR);
    assert_eq!(
        u16::from_ne_bytes([addrs[6], addrs[7]]),
        NLM_F_REQUEST | NLM_F_DUMP
    );
    assert_eq!(&addrs[16..24], &[LINUX_AF_INET6, 0, 0, 0, 0, 0, 0, 0]);
}

/// Ответ lookup IPv6: `RTA_OIF`, `RTA_GATEWAY` (link-local роутера), `RTA_PREFSRC` (выбор источника ядром) и
/// атрибуты, которые разбор пропускает; маршруты `AF_INET` в той же датаграмме не попадают в ответ IPv6.
#[test]
fn netlink_ipv6_route_reply_parses_oif_gateway_and_prefsrc() {
    let mut buf = route6_msg(
        RTN_UNICAST,
        128,
        254,
        &[
            rtattr(RTA_DST, &v6("2001:db8:9::1").octets()),
            rtattr(12, &[0; 32]), // RTA_CACHEINFO
            rtattr(RTA_OIF, &3u32.to_ne_bytes()),
            rtattr(RTA_GATEWAY, &v6("fe80::1").octets()),
            rtattr(RTA_PREFSRC, &v6("2001:db8:1::5").octets()),
            rtattr(RTA_PRIORITY, &1024u32.to_ne_bytes()),
            rtattr(RTA_TABLE, &254u32.to_ne_bytes()),
            rtattr(20, &[0]), // RTA_PREF
        ],
    );
    // Чужое семейство (IPv4) в той же датаграмме: не маршрут IPv6.
    let mut v4 = vec![AF_INET, 32, 0, 0, 254, 3, 0, RTN_UNICAST];
    v4.extend(0u32.to_ne_bytes());
    v4.extend(rtattr(RTA_OIF, &7u32.to_ne_bytes()));
    buf.extend(nlmsg(RTM_NEWROUTE, 0, &v4));
    let routes = parse_netlink_routes6(&buf).unwrap();
    assert_eq!(
        routes,
        vec![NlRoute6 {
            kind: RTN_UNICAST,
            dst_len: 128,
            table: 254,
            oif: Some(3),
            gateway: Some(v6("fe80::1")),
            prefsrc: Some(v6("2001:db8:1::5")),
            priority: 1024,
        }]
    );
    let r = route6_from_nl(&routes[0], |i| format!("eth{i}")).unwrap();
    assert_eq!(
        r,
        RouteV6 {
            ifindex: 3,
            ifname: "eth3".into(),
            gateway: Some(v6("fe80::1")),
            source: Some(v6("2001:db8:1::5")),
            local: false,
        }
    );
    // Разбор IPv4 той же датаграммы не видит маршрут IPv6 (семейства не смешиваются).
    assert_eq!(parse_netlink_routes(&buf).unwrap().len(), 1);
}

#[test]
fn netlink_ipv6_route_kinds_local_unreachable_and_short_attributes() {
    let local = parse_netlink_routes6(&route6_msg(
        RTN_LOCAL,
        128,
        255,
        &[
            rtattr(RTA_OIF, &1u32.to_ne_bytes()),
            rtattr(RTA_PREFSRC, &v6("fd00::5").octets()),
        ],
    ))
    .unwrap();
    let r = route6_from_nl(&local[0], |_| "lo".into()).unwrap();
    assert!(r.local);
    assert_eq!(r.gateway, None);
    for kind in [RTN_UNREACHABLE, RTN_BLACKHOLE, RTN_PROHIBIT] {
        let x = parse_netlink_routes6(&route6_msg(
            kind,
            0,
            254,
            &[rtattr(RTA_OIF, &1u32.to_ne_bytes())],
        ))
        .unwrap();
        assert_eq!(route6_from_nl(&x[0], |_| "lo".into()), None, "kind {kind}");
    }
    // Без RTA_OIF (например RTA_MULTIPATH) маршрута нет.
    let multi =
        parse_netlink_routes6(&route6_msg(RTN_UNICAST, 0, 254, &[rtattr(9, &[0; 8])])).unwrap();
    assert_eq!(route6_from_nl(&multi[0], |_| "x".into()), None);
    // Шлюз короче 16 байт это искажённый ответ, а не чтение за границей.
    let short = route6_msg(
        RTN_UNICAST,
        0,
        254,
        &[rtattr(RTA_GATEWAY, &[0xfe, 0x80, 0, 0])],
    );
    assert!(matches!(
        parse_netlink_routes6(&short),
        Err(NlError::Malformed(_))
    ));
    // NLMSG_ERROR lookup это Kernel(errno).
    let mut err = (-101i32).to_ne_bytes().to_vec();
    err.extend([0u8; 16 + RTMSG_LEN]);
    assert_eq!(
        parse_netlink_routes6(&nlmsg(NLMSG_ERROR, 0, &err)),
        Err(NlError::Kernel(101))
    );
}

#[test]
fn netlink_ipv6_defaults_are_main_table_unicast_with_oif_by_priority() {
    let mut buf = Vec::new();
    for (prio, table, oif, gw) in [
        (1024u32, 254u8, 3u32, "fe80::3"),
        (100, 254, 2, "fe80::2"),
        (5, 255, 1, "fe80::9"), // таблица local
    ] {
        buf.extend(route6_msg(
            RTN_UNICAST,
            0,
            table,
            &[
                rtattr(RTA_OIF, &oif.to_ne_bytes()),
                rtattr(RTA_GATEWAY, &v6(gw).octets()),
                rtattr(RTA_PRIORITY, &prio.to_ne_bytes()),
            ],
        ));
    }
    buf.extend(route6_msg(
        RTN_UNICAST,
        64,
        254,
        &[rtattr(RTA_OIF, &4u32.to_ne_bytes())],
    ));
    buf.extend(done());
    let d = netlink_defaults6(parse_netlink_routes6(&buf).unwrap());
    let gws: Vec<_> = d.iter().map(|r| (r.oif, r.gateway)).collect();
    assert_eq!(
        gws,
        vec![
            (Some(2), Some(v6("fe80::2"))),
            (Some(3), Some(v6("fe80::3")))
        ]
    );
}

/// `RTM_GETADDR` `AF_INET6`: адреса по интерфейсам в порядке ядра; tentative (DAD ещё идёт) и dadfailed непригодны,
/// deprecated уходят в конец; расширенные флаги `IFA_FLAGS` сильнее 8-битного `ifa_flags`.
#[test]
fn netlink_ipv6_addr_dump_skips_tentative_and_dadfailed() {
    let mut buf = Vec::new();
    buf.extend(addr6_msg(
        2,
        0x80,
        253,
        &[rtattr(IFA_ADDRESS, &v6("fe80::aa").octets())],
    ));
    buf.extend(addr6_msg(
        2,
        IFA_F_TENTATIVE as u8,
        0,
        &[rtattr(IFA_ADDRESS, &v6("2001:db8:1::4").octets())],
    ));
    buf.extend(addr6_msg(
        2,
        0,
        0,
        &[
            rtattr(IFA_ADDRESS, &v6("2001:db8:1::5").octets()),
            rtattr(IFA_FLAGS, &IFA_F_DEPRECATED.to_ne_bytes()),
        ],
    ));
    buf.extend(addr6_msg(
        2,
        0,
        0,
        &[
            rtattr(IFA_ADDRESS, &v6("2001:db8:1::6").octets()),
            rtattr(IFA_FLAGS, &(IFA_F_DADFAILED | 0x100).to_ne_bytes()),
        ],
    ));
    buf.extend(addr6_msg(
        2,
        0,
        0,
        &[rtattr(IFA_ADDRESS, &v6("fd00:198:18::1").octets())],
    ));
    buf.extend(addr6_msg(
        3,
        0,
        0,
        &[rtattr(IFA_ADDRESS, &v6("2001:db8:3::1").octets())],
    ));
    buf.extend(done());
    let addrs = parse_netlink_addrs6(&buf).unwrap();
    assert_eq!(addrs.len(), 6);
    assert_eq!(
        usable_addrs6(&addrs, 2),
        vec![v6("fe80::aa"), v6("fd00:198:18::1"), v6("2001:db8:1::5")]
    );
    assert_eq!(usable_addrs6(&addrs, 3), vec![v6("2001:db8:3::1")]);
    assert_eq!(usable_addrs6(&addrs, 9), Vec::<Ipv6Addr>::new());
    // Адрес короче 16 байт это искажённый ответ.
    assert!(matches!(
        parse_netlink_addrs6(&addr6_msg(2, 0, 0, &[rtattr(IFA_ADDRESS, &[0xfe, 0x80])])),
        Err(NlError::Malformed(_))
    ));
}

// ---------- Darwin route socket ----------

const DARWIN_AF_INET6: u8 = 30;

fn sin6(addr: [u8; 16], scope_id: u32) -> Vec<u8> {
    let mut b = vec![28, DARWIN_AF_INET6, 0, 0, 0, 0, 0, 0];
    b.extend(addr);
    b.extend(scope_id.to_ne_bytes());
    b
}

fn sdl(index: u16, name: &str) -> Vec<u8> {
    let mut b = vec![0u8; 8];
    b[0] = (8 + name.len() + 6) as u8;
    b[1] = AF_LINK;
    b[2..4].copy_from_slice(&index.to_ne_bytes());
    b[4] = 6;
    b[5] = name.len() as u8;
    b[6] = 6;
    b.extend(name.as_bytes());
    b.extend([2, 0, 0, 0, 0, 1]);
    pad4(&mut b);
    b
}

fn rt_reply(flags: i32, index: u16, addrs: i32, sockaddrs: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0u8; RT_MSGHDR_LEN];
    b[OFF_VERSION] = RTM_VERSION;
    b[OFF_TYPE] = RTM_GET;
    b[OFF_INDEX..OFF_INDEX + 2].copy_from_slice(&index.to_ne_bytes());
    b[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&flags.to_ne_bytes());
    b[OFF_ADDRS..OFF_ADDRS + 4].copy_from_slice(&addrs.to_ne_bytes());
    b[OFF_PID..OFF_PID + 4].copy_from_slice(&77i32.to_ne_bytes());
    b[OFF_SEQ..OFF_SEQ + 4].copy_from_slice(&5i32.to_ne_bytes());
    for sa in sockaddrs {
        b.extend(sa);
    }
    let len = b.len() as u16;
    b[OFF_MSGLEN..OFF_MSGLEN + 2].copy_from_slice(&len.to_ne_bytes());
    b
}

/// Review Focus 3: адреса link-local в ответах KAME (route socket Darwin) несут индекс зоны в `s6_addr[2..4]`
/// (измерено на macOS 27: шлюз по умолчанию `fe80:e::…` при `sin6_scope_id` 14). В NDP-кадр и в `[+]` уходит
/// чистый `fe80::…`.
#[test]
fn macos_kame_scope_id_is_stripped() {
    let mut a = [0u8; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    a[2] = 0x00;
    a[3] = 0x04;
    a[15] = 0x01;
    assert_eq!(
        in6_from_sockaddr(&sin6(a, 0)),
        Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
    );
    assert_eq!(
        in6_from_sockaddr(&sin6(a, 4)),
        Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
    );
    // Multicast link-local и interface-local тоже несут зону.
    let mut m = [0u8; 16];
    m[0] = 0xff;
    m[1] = 0x02;
    m[3] = 0x0e;
    m[15] = 1;
    assert_eq!(in6_from_sockaddr(&sin6(m, 0)), Some(v6("ff02::1")));
    // Глобальный адрес и ULA не трогаются, даже если байты 2..4 ненулевые.
    assert_eq!(
        in6_from_sockaddr(&sin6(v6("2001:db8:4::1").octets(), 0)),
        Some(v6("2001:db8:4::1"))
    );
    assert_eq!(
        in6_from_sockaddr(&sin6(v6("fd00:198:18::1").octets(), 0)),
        Some(v6("fd00:198:18::1"))
    );
    // Не sockaddr_in6 или короче 24 байт: `None`.
    assert_eq!(in6_from_sockaddr(&sin6(a, 0)[..20]), None);
    let mut wrong = sin6(a, 0);
    wrong[1] = AF_INET;
    assert_eq!(in6_from_sockaddr(&wrong), None);
}

#[test]
fn rtm_get_ipv6_request_is_well_formed() {
    let b = rt_get_request6(5, 77, v6("fd00:198:18::2"));
    assert_eq!(b.len(), RT_MSGHDR_LEN + 28);
    assert_eq!(u16::from_ne_bytes([b[0], b[1]]) as usize, b.len());
    assert_eq!((b[OFF_VERSION], b[OFF_TYPE]), (RTM_VERSION, RTM_GET));
    assert_eq!(
        i32::from_ne_bytes(b[OFF_ADDRS..OFF_ADDRS + 4].try_into().unwrap()),
        RTA_DST_BIT | RTA_IFP_BIT
    );
    let sa = &b[RT_MSGHDR_LEN..];
    assert_eq!((sa[0], sa[1]), (28, DARWIN_AF_INET6));
    assert_eq!(&sa[8..24], &v6("fd00:198:18::2").octets());
    assert_eq!(&sa[24..28], &[0; 4], "scope id 0");
}

/// `RTM_GET` IPv6 к цели за шлюзом: шлюз `sockaddr_in6` с KAME-зоной очищается, интерфейс из `RTAX_IFP`, нулевой
/// netmask (`sa_len` 0) занимает 4 байта; on-link (`sockaddr_dl` шлюза) и local дают свои маршруты.
#[test]
fn rtm_get_ipv6_reply_strips_the_kame_gateway_scope() {
    let mut gw = v6("fe80::1").octets();
    gw[3] = 0x0e;
    let reply = rt_reply(
        RTF_UP | RTF_GATEWAY,
        14,
        RTA_DST_BIT | 0x2 | 0x4 | RTA_IFP_BIT,
        &[
            sin6(v6("::").octets(), 0),
            sin6(gw, 14),
            vec![0, 0, 0, 0],
            sdl(14, "en0"),
        ],
    );
    let r = parse_rt_reply(&reply, 5, 77).unwrap().unwrap();
    assert_eq!(r.gateway_in6, Some(v6("fe80::1")));
    assert_eq!(r.ifp.as_deref(), Some("en0"));
    let route = route6_from_rt(&r).unwrap();
    assert_eq!(
        route,
        RouteV6 {
            ifindex: 14,
            ifname: "en0".into(),
            gateway: Some(v6("fe80::1")),
            source: None,
            local: false,
        }
    );
    assert_eq!(defaults6_from_rt(Some(&r)), vec![route.clone()]);
    // IPv4-разбор того же ответа не видит IPv6-шлюза.
    assert_eq!(r.gateway_in, None);

    // On-link: шлюз `sockaddr_dl`.
    let onlink = rt_reply(
        RTF_UP,
        4,
        RTA_DST_BIT | 0x2 | RTA_IFP_BIT,
        &[
            sin6(v6("fd00:198:18::2").octets(), 0),
            sdl(4, "en1"),
            sdl(4, "en1"),
        ],
    );
    let r = parse_rt_reply(&onlink, 5, 77).unwrap().unwrap();
    let route = route6_from_rt(&r).unwrap();
    assert_eq!(
        (route.gateway, route.local, route.ifindex),
        (None, false, 4)
    );

    // Адрес интерфейса: local через lo0, что бы ни ответил RTM_GET.
    let own = [v6("fd00:198:18::1")];
    let l = lookup6_from_rt(Some(&r), v6("fd00:198:18::1"), &own, 1).unwrap();
    assert!(l.local);
    assert_eq!((l.ifname.as_str(), l.ifindex), ("lo0", 1));
    assert_eq!(
        lookup6_from_rt(Some(&r), v6("fd00:198:18::2"), &own, 1),
        Some(route)
    );
    assert_eq!(lookup6_from_rt(None, v6("fd00:198:18::2"), &own, 1), None);

    // Reject без LLINFO это «нет маршрута».
    let reject = rt_reply(
        RTF_UP | RTF_REJECT,
        4,
        RTA_DST_BIT | RTA_IFP_BIT,
        &[sin6(v6("2001:db8::1").octets(), 0), sdl(4, "en1")],
    );
    let r = parse_rt_reply(&reject, 5, 77).unwrap().unwrap();
    assert_eq!(route6_from_rt(&r), None);
}

// ---------- Windows IP Helper ----------

fn win_iface(name: &str, index: u32) -> Iface {
    Iface {
        name: name.into(),
        index,
        device_id: format!("\\Device\\NPF_{{{name}}}"),
        description: Some(name.into()),
        mac: Some([2, 0, 0, 0, 0, index as u8]),
        mac_masked: false,
        ethernet: true,
        up: true,
        ipv4: Vec::new(),
    }
}

#[test]
fn windows_best_route_ipv6_gateway_source_and_local() {
    let ifaces = [win_iface("Ethernet 2", 7), win_iface("Loopback", 1)];
    let row = Fwd6 {
        ifindex: 7,
        prefix_len: 0,
        next_hop: v6("fe80::1"),
        metric: 25,
        mib_loopback: false,
        loopback_if: false,
    };
    let r = route6_from_best(
        &row,
        Some(v6("2001:db8:1::5")),
        v6("2001:db8:9::1"),
        &[],
        &ifaces,
    );
    assert_eq!(
        r,
        RouteV6 {
            ifindex: 7,
            ifname: "Ethernet 2".into(),
            gateway: Some(v6("fe80::1")),
            source: Some(v6("2001:db8:1::5")),
            local: false,
        }
    );
    // On-link: next hop `::`.
    let onlink = Fwd6 {
        next_hop: Ipv6Addr::UNSPECIFIED,
        prefix_len: 64,
        ..row
    };
    let r = route6_from_best(&onlink, None, v6("fd00:198:18::2"), &[], &ifaces);
    assert_eq!((r.gateway, r.local), (None, false));
    // Свой адрес или loopback-интерфейс: local, без шлюза.
    let own = [v6("fd00:198:18::1")];
    let r = route6_from_best(&onlink, None, v6("fd00:198:18::1"), &own, &ifaces);
    assert!(r.local);
    let lo = Fwd6 {
        ifindex: 1,
        loopback_if: true,
        ..row
    };
    let r = route6_from_best(&lo, None, v6("2001:db8::1"), &[], &ifaces);
    assert!(r.local);
    assert_eq!(r.gateway, None);
    // Маршруты по умолчанию IPv6: prefix 0, не loopback, по метрике.
    let rows = [
        Fwd6 {
            ifindex: 9,
            metric: 50,
            ..row
        },
        row,
        Fwd6 {
            prefix_len: 64,
            ..row
        },
        lo,
    ];
    let d = defaults6_from_table(&rows, &ifaces);
    let got: Vec<_> = d.iter().map(|r| (r.ifindex, r.gateway)).collect();
    assert_eq!(
        got,
        vec![(7, Some(v6("fe80::1"))), (9, Some(v6("fe80::1")))]
    );
}

/// Адреса `GetAdaptersAddresses(AF_INET6)` по DAD: tentative и duplicate непригодны, deprecated в конце.
#[test]
fn windows_ipv6_addresses_follow_dad_state() {
    let entries = [
        (v6("fe80::aa"), WIN_DAD_PREFERRED),
        (v6("2001:db8:1::4"), WIN_DAD_TENTATIVE),
        (v6("2001:db8:1::5"), WIN_DAD_DEPRECATED),
        (v6("2001:db8:1::6"), WIN_DAD_DUPLICATE),
        (v6("fd00:198:18::1"), WIN_DAD_PREFERRED),
        (v6("2001:db8:1::7"), 0),
    ];
    assert_eq!(
        usable_win_addrs6(&entries),
        vec![v6("fe80::aa"), v6("fd00:198:18::1"), v6("2001:db8:1::5")]
    );
}

/// Склейка строк IPv6 с адаптерами (`GetAdaptersAddresses(AF_INET)`): строка через адаптер IfType 24 это loopback
/// (local, не маршрут по умолчанию), имя интерфейса берётся из FriendlyName.
#[test]
fn windows_ipv6_rows_are_joined_with_the_adapters() {
    let adapter = |if_index: u32, if_type: u32, name: &str| WinAdapter {
        if_index,
        if_type,
        oper_up: true,
        adapter_name: format!("{{{name}}}"),
        friendly_name: Some(name.into()),
        mac: (if_type == IF_TYPE_ETHERNET_CSMACD).then_some([2, 0, 0, 0, 0, 7]),
        ipv4: Vec::new(),
    };
    let adapters = [
        adapter(1, IF_TYPE_SOFTWARE_LOOPBACK, "Loopback Pseudo-Interface 1"),
        adapter(7, IF_TYPE_ETHERNET_CSMACD, "Ethernet 2"),
    ];
    let row = |ifindex: u32, next_hop: &str| Fwd6 {
        ifindex,
        prefix_len: 0,
        next_hop: v6(next_hop),
        metric: 10,
        mib_loopback: false,
        loopback_if: false,
    };
    let r = lookup6_from_best(row(7, "fe80::1"), None, v6("2001:db8::1"), &[], &adapters);
    assert_eq!(
        (r.ifname.as_str(), r.gateway, r.local),
        ("Ethernet 2", Some(v6("fe80::1")), false)
    );
    let r = lookup6_from_best(row(1, "::"), None, v6("2001:db8::1"), &[], &adapters);
    assert!(r.local);
    let d = defaults6_from_rows(vec![row(1, "::"), row(7, "fe80::1")], &adapters);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].ifindex, 7);
}
