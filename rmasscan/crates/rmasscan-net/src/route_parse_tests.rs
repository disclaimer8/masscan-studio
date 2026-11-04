//! Разбор ответов ядра на синтетических байтах (любая ОС). Адреса только из документационных диапазонов, кроме разделов
//! стенда m1 (macOS: 198.18.0.0/30 и MAC `02:ac:…` пары feth) и гостя n2 (лабораторный стенд 198.18.0.0/30, RFC 2544, и
//! NIC управления QEMU 10.0.2.0/24): они воспроизводят стенды дословно.

use std::net::Ipv4Addr;

use rmasscan_core::massip::MassIp;

use super::*;
use crate::discover::{
    DetectError, Detected, Iface, Interfaces, NextHop, NextHopWhy, Overrides, ROUTER_HINTS, Route,
    RouteTable, Source, Targets, detect, detect_offline, iflist_text, probe_targets,
};

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

fn pad4(b: &mut Vec<u8>) {
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
}

// ---------- Linux rtnetlink ----------

const RTA_PREFSRC: u16 = 7;
const RTA_CACHEINFO: u16 = 12;
const RTA_UID: u16 = 25;
const RT_TABLE_LOCAL: u8 = 255;

fn nlmsg(ty: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(((NLMSG_HDRLEN + body.len()) as u32).to_ne_bytes());
    b.extend(ty.to_ne_bytes());
    b.extend(flags.to_ne_bytes());
    b.extend(seq.to_ne_bytes());
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

fn u32_attr(ty: u16, v: u32) -> Vec<u8> {
    rtattr(ty, &v.to_ne_bytes())
}

fn ip_attr(ty: u16, a: Ipv4Addr) -> Vec<u8> {
    rtattr(ty, &a.octets())
}

fn route_body(kind: u8, dst_len: u8, table: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![AF_INET, dst_len, 0, 0, table, 4, 0, kind];
    b.extend(0u32.to_ne_bytes());
    for a in attrs {
        b.extend(a);
    }
    b
}

fn route_msg(kind: u8, dst_len: u8, table: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
    nlmsg(RTM_NEWROUTE, 0, 1, &route_body(kind, dst_len, table, attrs))
}

fn done_msg() -> Vec<u8> {
    nlmsg(NLMSG_DONE, 2, 1, &0i32.to_ne_bytes())
}

fn error_msg(code: i32) -> Vec<u8> {
    let mut body = code.to_ne_bytes().to_vec();
    body.extend(nlmsg(RTM_GETROUTE, NLM_F_REQUEST, 1, &[0; RTMSG_LEN]));
    nlmsg(NLMSG_ERROR, 0, 1, &body)
}

fn nl(
    kind: u8,
    dst_len: u8,
    table: u32,
    oif: Option<u32>,
    gw: Option<Ipv4Addr>,
    prio: u32,
) -> NlRoute {
    NlRoute {
        kind,
        dst_len,
        table,
        oif,
        gateway: gw,
        priority: prio,
    }
}

#[test]
fn netlink_requests_are_well_formed() {
    let get = netlink_route_request(7, Some(ip(198, 51, 100, 7)));
    assert_eq!(get.len(), NLMSG_HDRLEN + RTMSG_LEN + 8);
    assert_eq!(
        u32::from_ne_bytes(get[0..4].try_into().unwrap()) as usize,
        get.len()
    );
    assert_eq!(u16::from_ne_bytes([get[4], get[5]]), RTM_GETROUTE);
    assert_eq!(u16::from_ne_bytes([get[6], get[7]]), NLM_F_REQUEST);
    assert_eq!(u32::from_ne_bytes(get[8..12].try_into().unwrap()), 7);
    assert_eq!(&get[12..16], &[0; 4], "nlmsg_pid 0: the kernel fills it");
    let rt = &get[16..28];
    assert_eq!((rt[0], rt[1]), (AF_INET, 32), "family AF_INET, dst_len 32");
    assert_eq!(&rt[2..], &[0; 10]);
    assert_eq!(u16::from_ne_bytes([get[28], get[29]]), 8);
    assert_eq!(u16::from_ne_bytes([get[30], get[31]]), RTA_DST);
    assert_eq!(&get[32..36], &[198, 51, 100, 7], "RTA_DST in network order");

    let dump = netlink_route_request(8, None);
    assert_eq!(dump.len(), NLMSG_HDRLEN + RTMSG_LEN);
    assert_eq!(
        u32::from_ne_bytes(dump[0..4].try_into().unwrap()) as usize,
        dump.len()
    );
    assert_eq!(u16::from_ne_bytes([dump[4], dump[5]]), RTM_GETROUTE);
    assert_eq!(
        u16::from_ne_bytes([dump[6], dump[7]]),
        NLM_F_REQUEST | NLM_F_DUMP
    );
    assert_eq!(
        (dump[16], dump[17]),
        (AF_INET, 0),
        "dump: family AF_INET, dst_len 0"
    );
}

#[test]
fn netlink_reply_with_oif_gateway_prefsrc_is_parsed() {
    // Ответ ядра на `ip route get` с RTA_TABLE, RTA_DST, RTA_OIF, RTA_PREFSRC, RTA_GATEWAY, RTA_UID и RTA_CACHEINFO
    // (лишние атрибуты пропускаются; нечётный по длине атрибут выравнивается до 4).
    let reply = route_msg(
        RTN_UNICAST,
        32,
        RT_TABLE_MAIN as u8,
        &[
            u32_attr(RTA_TABLE, RT_TABLE_MAIN),
            ip_attr(RTA_DST, ip(198, 51, 100, 7)),
            u32_attr(RTA_OIF, 2),
            ip_attr(RTA_PREFSRC, ip(192, 0, 2, 10)),
            ip_attr(RTA_GATEWAY, ip(192, 0, 2, 1)),
            rtattr(99, &[1, 2, 3]),
            u32_attr(RTA_UID, 1000),
            rtattr(RTA_CACHEINFO, &[0; 32]),
        ],
    );
    let routes = parse_netlink_routes(&reply).unwrap();
    assert_eq!(
        routes,
        vec![nl(
            RTN_UNICAST,
            32,
            RT_TABLE_MAIN,
            Some(2),
            Some(ip(192, 0, 2, 1)),
            0
        )]
    );
    assert!(
        !netlink_done(&reply),
        "a lookup reply carries no NLMSG_DONE: the caller reads exactly one datagram"
    );
    let r = route_from_nl(&routes[0], |i| format!("eth{i}")).unwrap();
    assert_eq!(
        r,
        Route {
            ifindex: 2,
            ifname: "eth2".into(),
            gateway: Some(ip(192, 0, 2, 1)),
            local: false,
        }
    );
    // On-link: без RTA_GATEWAY.
    let onlink = route_msg(RTN_UNICAST, 32, 254, &[u32_attr(RTA_OIF, 3)]);
    let r = route_from_nl(&parse_netlink_routes(&onlink).unwrap()[0], |_| {
        "eth3".into()
    })
    .unwrap();
    assert_eq!((r.ifindex, r.gateway, r.local), (3, None, false));
    // RTA_TABLE побеждает rtm_table (таблицы > 255).
    let big = route_msg(
        RTN_UNICAST,
        0,
        252,
        &[u32_attr(RTA_TABLE, 1000), u32_attr(RTA_OIF, 3)],
    );
    assert_eq!(parse_netlink_routes(&big).unwrap()[0].table, 1000);
    // Маршрут не AF_INET пропускается.
    let mut v6 = route_body(RTN_UNICAST, 128, 254, &[u32_attr(RTA_OIF, 3)]);
    v6[0] = 10;
    assert_eq!(
        parse_netlink_routes(&nlmsg(RTM_NEWROUTE, 0, 1, &v6)).unwrap(),
        vec![]
    );
}

#[test]
fn netlink_local_and_unreachable_kinds_are_kept() {
    let mut buf = route_msg(
        RTN_LOCAL,
        32,
        RT_TABLE_LOCAL,
        &[
            u32_attr(RTA_TABLE, 255),
            u32_attr(RTA_OIF, 1),
            ip_attr(RTA_PREFSRC, ip(127, 0, 0, 1)),
        ],
    );
    buf.extend(route_msg(RTN_UNREACHABLE, 32, 254, &[]));
    buf.extend(route_msg(RTN_BLACKHOLE, 32, 254, &[]));
    buf.extend(route_msg(RTN_PROHIBIT, 32, 254, &[u32_attr(RTA_OIF, 1)]));
    buf.extend(route_msg(
        RTN_UNICAST,
        32,
        254,
        &[ip_attr(RTA_GATEWAY, ip(192, 0, 2, 1))],
    ));
    let routes = parse_netlink_routes(&buf).unwrap();
    let kinds: Vec<u8> = routes.iter().map(|r| r.kind).collect();
    assert_eq!(
        kinds,
        vec![
            RTN_LOCAL,
            RTN_UNREACHABLE,
            RTN_BLACKHOLE,
            RTN_PROHIBIT,
            RTN_UNICAST
        ],
        "the parser keeps every kind; the lookup mapping decides"
    );
    let local = route_from_nl(&routes[0], |_| "lo".into()).unwrap();
    assert_eq!(
        local,
        Route {
            ifindex: 1,
            ifname: "lo".into(),
            gateway: None,
            local: true,
        }
    );
    for r in &routes[1..] {
        assert_eq!(
            route_from_nl(r, |_| "x".into()),
            None,
            "kind {} / oif {:?}",
            r.kind,
            r.oif
        );
    }
}

#[test]
fn netlink_error_message_is_err() {
    let e = error_msg(-101);
    assert_eq!(parse_netlink_routes(&e), Err(NlError::Kernel(101)));
    assert!(netlink_done(&e));
    // ACK (код 0) это не ошибка.
    assert_eq!(parse_netlink_routes(&error_msg(0)), Ok(vec![]));
    // Короткое тело NLMSG_ERROR.
    assert!(matches!(
        parse_netlink_routes(&nlmsg(NLMSG_ERROR, 0, 1, &[1, 2])),
        Err(NlError::Malformed(_))
    ));
    // nlmsg_len больше датаграммы, меньше заголовка, обрезанный заголовок, обрезанный атрибут.
    let mut long = route_msg(RTN_UNICAST, 32, 254, &[u32_attr(RTA_OIF, 2)]);
    long[0..4].copy_from_slice(&200u32.to_ne_bytes());
    assert!(matches!(
        parse_netlink_routes(&long),
        Err(NlError::Malformed(_))
    ));
    let mut short = route_msg(RTN_UNICAST, 32, 254, &[]);
    short[0..4].copy_from_slice(&8u32.to_ne_bytes());
    assert!(matches!(
        parse_netlink_routes(&short),
        Err(NlError::Malformed(_))
    ));
    assert!(matches!(
        parse_netlink_routes(&[0; 9]),
        Err(NlError::Malformed(_))
    ));
    let mut bad_attr = route_msg(RTN_UNICAST, 32, 254, &[u32_attr(RTA_OIF, 2)]);
    let at = NLMSG_HDRLEN + RTMSG_LEN;
    bad_attr[at..at + 2].copy_from_slice(&64u16.to_ne_bytes());
    assert!(matches!(
        parse_netlink_routes(&bad_attr),
        Err(NlError::Malformed(_))
    ));
    let mut short_oif = route_msg(RTN_UNICAST, 32, 254, &[rtattr(RTA_OIF, &[1, 0])]);
    short_oif.truncate(short_oif.len());
    assert!(matches!(
        parse_netlink_routes(&short_oif),
        Err(NlError::Malformed(_))
    ));
    // Короткий rtmsg.
    assert!(matches!(
        parse_netlink_routes(&nlmsg(RTM_NEWROUTE, 0, 1, &[AF_INET, 0, 0, 0])),
        Err(NlError::Malformed(_))
    ));
    // Текст ошибки ядра называет errno.
    assert!(NlError::Kernel(101).to_string().starts_with("netlink: "));
}

#[test]
fn netlink_dump_keeps_only_dst_len_zero_sorted_by_priority() {
    let mut part1 = route_msg(
        RTN_UNICAST,
        0,
        254,
        &[
            u32_attr(RTA_TABLE, 254),
            u32_attr(RTA_PRIORITY, 600),
            ip_attr(RTA_GATEWAY, ip(192, 0, 2, 1)),
            u32_attr(RTA_OIF, 3),
        ],
    );
    part1.extend(route_msg(
        RTN_UNICAST,
        24,
        254,
        &[ip_attr(RTA_DST, ip(192, 0, 2, 0)), u32_attr(RTA_OIF, 3)],
    ));
    // Без NLMSG_DONE: dump продолжается следующей датаграммой.
    assert!(!netlink_done(&part1));
    let mut part2 = route_msg(
        RTN_UNICAST,
        0,
        254,
        &[
            u32_attr(RTA_PRIORITY, 100),
            ip_attr(RTA_GATEWAY, ip(198, 51, 100, 1)),
            u32_attr(RTA_OIF, 2),
        ],
    );
    // Другая таблица, unreachable default, default без интерфейса (multipath), default без шлюза.
    part2.extend(route_msg(
        RTN_UNICAST,
        0,
        100,
        &[u32_attr(RTA_TABLE, 100), u32_attr(RTA_OIF, 2)],
    ));
    part2.extend(route_msg(
        RTN_UNREACHABLE,
        0,
        254,
        &[u32_attr(RTA_PRIORITY, 1)],
    ));
    part2.extend(route_msg(RTN_UNICAST, 0, 254, &[u32_attr(RTA_PRIORITY, 5)]));
    part2.extend(route_msg(
        RTN_UNICAST,
        0,
        254,
        &[u32_attr(RTA_PRIORITY, 600), u32_attr(RTA_OIF, 9)],
    ));
    part2.extend(done_msg());
    // Сообщения после NLMSG_DONE не читаются.
    part2.extend(route_msg(RTN_UNICAST, 0, 254, &[u32_attr(RTA_OIF, 4)]));
    assert!(netlink_done(&part2));

    let mut all = parse_netlink_routes(&part1).unwrap();
    all.extend(parse_netlink_routes(&part2).unwrap());
    assert_eq!(all.len(), 7);
    assert_eq!(
        netlink_defaults(all),
        vec![
            nl(RTN_UNICAST, 0, 254, Some(2), Some(ip(198, 51, 100, 1)), 100),
            nl(RTN_UNICAST, 0, 254, Some(3), Some(ip(192, 0, 2, 1)), 600),
            nl(RTN_UNICAST, 0, 254, Some(9), None, 600),
        ],
        "dst_len 0, table main, unicast with an interface; by priority, ties in dump order"
    );
}

/// Константы своей раскладки совпадают с `libc` той ОС, где они нужны.
#[cfg(target_os = "linux")]
#[test]
fn netlink_constants_match_libc() {
    assert_eq!(std::mem::size_of::<libc::nlmsghdr>(), NLMSG_HDRLEN);
    assert_eq!(std::mem::size_of::<libc::rtattr>(), 4);
    assert_eq!(i32::from(NLMSG_ERROR), libc::NLMSG_ERROR);
    assert_eq!(i32::from(NLMSG_DONE), libc::NLMSG_DONE);
    assert_eq!(RTM_NEWROUTE, libc::RTM_NEWROUTE);
    assert_eq!(RTM_GETROUTE, libc::RTM_GETROUTE);
    assert_eq!(i32::from(NLM_F_REQUEST), libc::NLM_F_REQUEST);
    assert_eq!(i32::from(NLM_F_DUMP), libc::NLM_F_DUMP);
    assert_eq!(i32::from(AF_INET), libc::AF_INET);
    assert_eq!(
        [RTA_DST, RTA_OIF, RTA_GATEWAY, RTA_PRIORITY, RTA_TABLE],
        [
            libc::RTA_DST,
            libc::RTA_OIF,
            libc::RTA_GATEWAY,
            libc::RTA_PRIORITY,
            libc::RTA_TABLE
        ]
    );
    assert_eq!(
        [
            RTN_UNICAST,
            RTN_LOCAL,
            RTN_BLACKHOLE,
            RTN_UNREACHABLE,
            RTN_PROHIBIT
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
}

// ---------- Darwin route socket ----------

const RTA_GATEWAY_BIT: i32 = 0x2;
const RTA_NETMASK_BIT: i32 = 0x4;
const RTA_IFA_BIT: i32 = 0x20;
const RTF_HOST: i32 = 0x4;
const SEQ: i32 = 5;
const PID: i32 = 4100;

fn sin(a: Ipv4Addr) -> Vec<u8> {
    let mut b = vec![16, AF_INET, 0, 0];
    b.extend(a.octets());
    b.extend([0; 8]);
    b
}

/// `sockaddr_dl` с точной длиной `8 + nlen + alen` (без округления; округляет [`rt_msg`]).
fn sdl(index: u16, name: &str, mac: Option<[u8; 6]>) -> Vec<u8> {
    let alen = if mac.is_some() { 6 } else { 0 };
    let len = 8 + name.len() + alen;
    let mut b = vec![len as u8, AF_LINK];
    b.extend(index.to_ne_bytes());
    b.extend([6, name.len() as u8, alen as u8, 0]);
    b.extend(name.as_bytes());
    if let Some(m) = mac {
        b.extend(m);
    }
    b
}

/// Сообщение route socket: заголовок и sockaddr по возрастанию бита, каждый дополнен до `ROUNDUP(sa_len)`.
fn rt_msg(
    flags: i32,
    index: u16,
    sas: &[(i32, Vec<u8>)],
    pid: i32,
    seq: i32,
    errno: i32,
) -> Vec<u8> {
    let mut body = Vec::new();
    let mut addrs = 0;
    for (bit, sa) in sas {
        addrs |= bit;
        body.extend(sa);
        let step = if sa[0] == 0 {
            4
        } else {
            (usize::from(sa[0]) + 3) & !3
        };
        body.resize(body.len() + step - sa.len(), 0);
    }
    let mut b = vec![0u8; RT_MSGHDR_LEN];
    let msglen = (RT_MSGHDR_LEN + body.len()) as u16;
    b[OFF_MSGLEN..OFF_MSGLEN + 2].copy_from_slice(&msglen.to_ne_bytes());
    b[OFF_VERSION] = RTM_VERSION;
    b[OFF_TYPE] = RTM_GET;
    b[OFF_INDEX..OFF_INDEX + 2].copy_from_slice(&index.to_ne_bytes());
    b[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&flags.to_ne_bytes());
    b[OFF_ADDRS..OFF_ADDRS + 4].copy_from_slice(&addrs.to_ne_bytes());
    b[OFF_PID..OFF_PID + 4].copy_from_slice(&pid.to_ne_bytes());
    b[OFF_SEQ..OFF_SEQ + 4].copy_from_slice(&seq.to_ne_bytes());
    b[OFF_ERRNO..OFF_ERRNO + 4].copy_from_slice(&errno.to_ne_bytes());
    b.extend(body);
    b
}

fn default_reply(netmask: Vec<u8>) -> Vec<u8> {
    rt_msg(
        RTF_UP | RTF_GATEWAY,
        3,
        &[
            (RTA_DST_BIT, sin(Ipv4Addr::UNSPECIFIED)),
            (RTA_GATEWAY_BIT, sin(ip(192, 0, 2, 1))),
            (RTA_NETMASK_BIT, netmask),
            (RTA_IFP_BIT, sdl(7, "en12", Some([2, 0xac, 0, 0, 0, 1]))),
            (RTA_IFA_BIT, sin(ip(192, 0, 2, 10))),
        ],
        PID,
        SEQ,
        0,
    )
}

#[test]
fn rt_get_request_mirrors_the_c_oracle() {
    let req = rt_get_request(SEQ, PID, ip(198, 51, 100, 7));
    assert_eq!(req.len(), RT_MSGHDR_LEN + 16);
    assert_eq!(usize::from(u16::from_ne_bytes([req[0], req[1]])), req.len());
    assert_eq!((req[OFF_VERSION], req[OFF_TYPE]), (RTM_VERSION, RTM_GET));
    let i32_at = |o: usize| i32::from_ne_bytes(req[o..o + 4].try_into().unwrap());
    assert_eq!(i32_at(OFF_FLAGS), RTF_UP);
    assert_eq!(i32_at(OFF_ADDRS), RTA_DST_BIT | RTA_IFP_BIT);
    assert_eq!(
        (i32_at(OFF_PID), i32_at(OFF_SEQ), i32_at(OFF_ERRNO)),
        (PID, SEQ, 0)
    );
    assert_eq!(&req[RT_MSGHDR_LEN..], sin(ip(198, 51, 100, 7)).as_slice());
}

#[test]
fn rt_reply_sockaddrs_are_rounded_to_four_bytes() {
    for (len, step) in [
        (0, 4),
        (1, 4),
        (4, 4),
        (5, 8),
        (7, 8),
        (16, 16),
        (17, 20),
        (18, 20),
    ] {
        assert_eq!(sa_roundup(len), step, "sa_len {len}");
    }
    // Нулевая маска маршрута по умолчанию (sa_len 0 → 4 байта), сжатая маска (sa_len 5 → 8), sockaddr_dl на 18 байт.
    for netmask in [vec![0, 0, 0, 0], vec![5, AF_INET, 0, 0, 255]] {
        let r = parse_rt_reply(&default_reply(netmask), SEQ, PID)
            .unwrap()
            .unwrap();
        assert_eq!(
            r,
            RtReply {
                flags: RTF_UP | RTF_GATEWAY,
                ifp: Some("en12".into()),
                ifindex: 7,
                gateway_in: Some(ip(192, 0, 2, 1)),
                gateway_is_link: false,
            }
        );
        assert_eq!(
            route_from_rt(&r),
            Some(Route {
                ifindex: 7,
                ifname: "en12".into(),
                gateway: Some(ip(192, 0, 2, 1)),
                local: false,
            })
        );
    }
    // Без RTAX_IFP индекс берётся из rtm_index.
    let no_ifp = rt_msg(
        RTF_UP,
        3,
        &[(RTA_DST_BIT, sin(ip(192, 0, 2, 20)))],
        PID,
        SEQ,
        0,
    );
    let r = parse_rt_reply(&no_ifp, SEQ, PID).unwrap().unwrap();
    assert_eq!((r.ifindex, r.ifp.as_deref()), (3, None));
    // sockaddr выходит за rtm_msglen.
    let mut over = default_reply(vec![0, 0, 0, 0]);
    let ifp_at = over.len() - 16 - 20;
    over[ifp_at] = 200;
    assert!(parse_rt_reply(&over, SEQ, PID).is_err());
}

#[test]
fn rt_reply_with_foreign_seq_or_pid_is_skipped() {
    let ours = default_reply(vec![0, 0, 0, 0]);
    assert!(parse_rt_reply(&ours, SEQ, PID).unwrap().is_some());
    assert_eq!(parse_rt_reply(&ours, SEQ + 1, PID), Ok(None), "foreign seq");
    assert_eq!(parse_rt_reply(&ours, SEQ, PID + 1), Ok(None), "foreign pid");
    // Своё сообщение с rtm_errno, обрезанное, с чужой версией.
    let failed = rt_msg(
        RTF_UP,
        0,
        &[(RTA_DST_BIT, sin(ip(192, 0, 2, 20)))],
        PID,
        SEQ,
        3,
    );
    assert!(parse_rt_reply(&failed, SEQ, PID).is_err());
    assert!(parse_rt_reply(&ours[..40], SEQ, PID).is_err());
    assert!(
        parse_rt_reply(&ours[..ours.len() - 4], SEQ, PID).is_err(),
        "rtm_msglen past the read"
    );
    let mut v4 = ours.clone();
    v4[OFF_VERSION] = 4;
    assert!(parse_rt_reply(&v4, SEQ, PID).is_err());
}

#[test]
fn rt_reply_gateway_sockaddr_dl_means_on_link() {
    // Клонированный маршрут к соседу: шлюз это sockaddr_dl (link#7), RTF_GATEWAY нет.
    let link = rt_msg(
        RTF_UP | RTF_HOST,
        7,
        &[
            (RTA_DST_BIT, sin(ip(192, 0, 2, 20))),
            (RTA_GATEWAY_BIT, sdl(7, "", Some([2, 0xbb, 0, 0, 0, 2]))),
            (RTA_IFP_BIT, sdl(7, "en12", Some([2, 0xac, 0, 0, 0, 1]))),
        ],
        PID,
        SEQ,
        0,
    );
    let r = parse_rt_reply(&link, SEQ, PID).unwrap().unwrap();
    assert!(r.gateway_is_link);
    assert_eq!(r.gateway_in, None);
    let route = route_from_rt(&r).unwrap();
    assert_eq!(
        (route.gateway, route.local, route.ifindex),
        (None, false, 7)
    );
    // Интерфейсный маршрут: sockaddr_in в RTAX_GATEWAY без RTF_GATEWAY это адрес интерфейса, не шлюз.
    let iface_route = rt_msg(
        RTF_UP,
        9,
        &[
            (RTA_DST_BIT, sin(ip(192, 0, 2, 20))),
            (RTA_GATEWAY_BIT, sin(ip(192, 0, 2, 10))),
            (RTA_IFP_BIT, sdl(9, "utun3", None)),
        ],
        PID,
        SEQ,
        0,
    );
    let r = parse_rt_reply(&iface_route, SEQ, PID).unwrap().unwrap();
    assert_eq!(r.gateway_in, Some(ip(192, 0, 2, 10)));
    assert_eq!(route_from_rt(&r).unwrap().gateway, None);
}

#[test]
fn rt_reply_rtf_local_or_lo0_is_local() {
    let reply = |flags: i32, ifname: &str| {
        let m = rt_msg(
            flags,
            1,
            &[
                (RTA_DST_BIT, sin(ip(192, 0, 2, 10))),
                (RTA_GATEWAY_BIT, sin(ip(127, 0, 0, 1))),
                (RTA_IFP_BIT, sdl(1, ifname, None)),
            ],
            PID,
            SEQ,
            0,
        );
        route_from_rt(&parse_rt_reply(&m, SEQ, PID).unwrap().unwrap()).unwrap()
    };
    let lo0 = reply(RTF_UP | RTF_HOST, "lo0");
    assert_eq!(
        (lo0.local, lo0.gateway, lo0.ifname.as_str()),
        (true, None, "lo0")
    );
    let flag = reply(RTF_UP | RTF_HOST | RTF_LOCAL, "en12");
    assert!(flag.local);
    let flag_gw = reply(RTF_UP | RTF_GATEWAY | RTF_LOCAL, "en12");
    assert_eq!(
        (flag_gw.local, flag_gw.gateway),
        (true, None),
        "a local route has no next hop"
    );
    assert!(!reply(RTF_UP | RTF_HOST, "en12").local);
}

#[test]
fn rt_reply_reject_or_blackhole_is_no_route() {
    // Без RTF_LLINFO reject/blackhole это «нет маршрута», и с on-link шлюзом тоже (ср. llinfo-тест ниже).
    for flags in [RTF_REJECT, RTF_BLACKHOLE, RTF_REJECT | RTF_HOST] {
        let m = rt_msg(
            RTF_UP | flags,
            3,
            &[
                (RTA_DST_BIT, sin(ip(192, 0, 2, 20))),
                (RTA_GATEWAY_BIT, sdl(3, "", None)),
                (RTA_IFP_BIT, sdl(3, "en12", None)),
            ],
            PID,
            SEQ,
            0,
        );
        assert_eq!(
            route_from_rt(&parse_rt_reply(&m, SEQ, PID).unwrap().unwrap()),
            None
        );
    }
}

const RTM_NEWADDR: u8 = 0xc;
const RTM_NEWMADDR: u8 = 0xf;

/// Сообщение `ifa_msghdr` (20 байт) или `ifma_msghdr` (16 байт) и его sockaddr: общий заголовок `msglen, version, type`,
/// затем `addrs` по смещению 4; полей seq/pid у них нет.
fn if_msg(ty: u8, hdr_len: usize, sas: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0u8; hdr_len];
    for sa in sas {
        b.extend(sa);
        let step = if sa[0] == 0 {
            4
        } else {
            (usize::from(sa[0]) + 3) & !3
        };
        b.resize(b.len() + step - sa.len(), 0);
    }
    let len = b.len() as u16;
    b[0..2].copy_from_slice(&len.to_ne_bytes());
    b[2] = RTM_VERSION;
    b[3] = ty;
    b[4..8].copy_from_slice(&(RTA_NETMASK_BIT | RTA_IFP_BIT | RTA_IFA_BIT).to_ne_bytes());
    b
}

#[test]
fn rt_reply_foreign_short_messages_are_skipped() {
    // RTM_NEWADDR (ifa_msghdr 20 байт + маска, sockaddr_dl, адрес) = 72 байта, короче rt_msghdr.
    let newaddr = if_msg(
        RTM_NEWADDR,
        20,
        &[
            vec![7, AF_INET, 0, 0, 255, 255, 255],
            sdl(7, "en12", Some([2, 0xac, 0, 0, 0, 1])),
            sin(ip(192, 0, 2, 10)),
        ],
    );
    assert!(newaddr.len() < RT_MSGHDR_LEN, "{} bytes", newaddr.len());
    assert_eq!(parse_rt_reply(&newaddr, SEQ, PID), Ok(None));
    // RTM_NEWMADDR (ifma_msghdr 16 байт + sockaddr_dl группы, sockaddr_dl интерфейса, адрес группы).
    let newmaddr = if_msg(
        RTM_NEWMADDR,
        16,
        &[
            sdl(0, "", Some([1, 0, 0x5e, 0, 0, 1])),
            sdl(7, "en12", None),
            sin(ip(224, 0, 0, 1)),
        ],
    );
    assert!(newmaddr.len() < RT_MSGHDR_LEN, "{} bytes", newmaddr.len());
    assert_eq!(parse_rt_reply(&newmaddr, SEQ, PID), Ok(None));
    // Только заголовок ifma_msghdr.
    assert_eq!(
        parse_rt_reply(&if_msg(RTM_NEWMADDR, 16, &[]), SEQ, PID),
        Ok(None)
    );
    // Обрезанное чтение остаётся ошибкой и у короткого чужого сообщения: rtm_msglen больше прочитанного.
    assert!(parse_rt_reply(&newaddr[..40], SEQ, PID).is_err());
    // Меньше общего заголовка, msglen меньше заголовка, чужая версия.
    assert!(parse_rt_reply(&newaddr[..3], SEQ, PID).is_err());
    let mut tiny = newaddr.clone();
    tiny[0..2].copy_from_slice(&3u16.to_ne_bytes());
    assert!(parse_rt_reply(&tiny, SEQ, PID).is_err());
    let mut v4 = newaddr.clone();
    v4[2] = 4;
    assert!(parse_rt_reply(&v4, SEQ, PID).is_err());
    // RTM_GET короче rt_msghdr это искажённый ответ, а не чужое сообщение.
    let mut short_get = newaddr.clone();
    short_get[3] = RTM_GET;
    assert!(parse_rt_reply(&short_get, SEQ, PID).is_err());
}

#[test]
fn rt_reply_llinfo_reject_route_stays_on_link() {
    // XNU после неудачного ARP помечает llinfo-маршрут хоста RTF_REJECT на arpt_down: это всё ещё on-link сосед.
    let m = rt_msg(
        RTF_UP | RTF_HOST | RTF_LLINFO | RTF_REJECT,
        7,
        &[
            (RTA_DST_BIT, sin(ip(192, 0, 2, 20))),
            (RTA_GATEWAY_BIT, sdl(7, "", None)),
            (RTA_IFP_BIT, sdl(7, "en12", Some([2, 0xac, 0, 0, 0, 1]))),
        ],
        PID,
        SEQ,
        0,
    );
    let r = parse_rt_reply(&m, SEQ, PID).unwrap().unwrap();
    assert!(r.gateway_is_link);
    assert_eq!(
        route_from_rt(&r),
        Some(Route {
            ifindex: 7,
            ifname: "en12".into(),
            gateway: None,
            local: false,
        })
    );
}

#[cfg(target_os = "macos")]
#[test]
fn rt_msghdr_layout_and_constants_match_libc() {
    use std::mem::{offset_of, size_of};
    assert_eq!(size_of::<libc::rt_msghdr>(), RT_MSGHDR_LEN);
    assert_eq!(offset_of!(libc::rt_msghdr, rtm_msglen), OFF_MSGLEN);
    assert_eq!(offset_of!(libc::rt_msghdr, rtm_version), OFF_VERSION);
    assert_eq!(offset_of!(libc::rt_msghdr, rtm_type), OFF_TYPE);
    assert_eq!(offset_of!(libc::rt_msghdr, rtm_index), OFF_INDEX);
    assert_eq!(offset_of!(libc::rt_msghdr, rtm_flags), OFF_FLAGS);
    assert_eq!(offset_of!(libc::rt_msghdr, rtm_addrs), OFF_ADDRS);
    assert_eq!(offset_of!(libc::rt_msghdr, rtm_pid), OFF_PID);
    assert_eq!(offset_of!(libc::rt_msghdr, rtm_seq), OFF_SEQ);
    assert_eq!(offset_of!(libc::rt_msghdr, rtm_errno), OFF_ERRNO);
    assert_eq!(i32::from(RTM_VERSION), libc::RTM_VERSION);
    assert_eq!(i32::from(RTM_GET), libc::RTM_GET);
    assert_eq!((RTA_DST_BIT, RTA_IFP_BIT), (libc::RTA_DST, libc::RTA_IFP));
    assert_eq!(
        [
            RTF_UP,
            RTF_GATEWAY,
            RTF_REJECT,
            RTF_LLINFO,
            RTF_BLACKHOLE,
            RTF_LOCAL
        ],
        [
            libc::RTF_UP,
            libc::RTF_GATEWAY,
            libc::RTF_REJECT,
            libc::RTF_LLINFO,
            libc::RTF_BLACKHOLE,
            libc::RTF_LOCAL
        ]
    );
    assert_eq!(
        (i32::from(AF_INET), i32::from(AF_LINK)),
        (libc::AF_INET, libc::AF_LINK)
    );
    assert_eq!(size_of::<libc::sockaddr_in>(), 16);
    assert_eq!(offset_of!(libc::sockaddr_dl, sdl_data), 8);
    assert_eq!(
        (i32::from(RTM_NEWADDR), i32::from(RTM_NEWMADDR)),
        (libc::RTM_NEWADDR, libc::RTM_NEWMADDR)
    );
    assert_eq!(size_of::<libc::ifa_msghdr>(), 20);
    assert_eq!(size_of::<libc::ifma_msghdr>(), 16);
}

// ---------- macOS: стенд m1 (PF4) ----------

/// Индексы интерфейсов Mac в окне (`if_nameindex`; маршрут подсети в `netstat -rn` это `link#36`, то есть feth4202).
const M1_LO0: u16 = 1;
const M1_EN0: u16 = 14;
const M1_SCANNER: u16 = 35;
const M1_PEER: u16 = 36;
const M1_SCANNER_MAC: [u8; 6] = [0x02, 0xac, 0, 0, 0, 1];
const M1_PEER_MAC: [u8; 6] = [0x02, 0xac, 0, 0, 0, 2];
/// Uplink en0 (VPN выключен). Окно записало только стенд, поэтому адрес, шлюз и MAC en0 это документационные
/// заменители; ни один случай таблицы через en0 не идёт.
const M1_EN0_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const M1_EN0_GW: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const M1_EN0_MAC: [u8; 6] = [0x02, 0xbb, 0, 0, 0, 14];
const RTF_DONE: i32 = 0x40;
const RTF_CLONING: i32 = 0x100;
const RTF_STATIC: i32 = 0x800;
const RTF_WASCLONED: i32 = 0x2_0000;
const RTF_IFSCOPE: i32 = 0x100_0000;

/// Тексты таблицы случаев дословно (rmasscan-lab `autodetect_verify.rs`): `LOCAL_TARGET` это текст после `[-] FAIL: `
/// строки m05_user_no_adapter и её `Preflight::Refusal` (его ждёт `preflight_expectation("m05_user_no_adapter")`),
/// дальше подсказки `LOCAL_HINT`, `MASKED_HINT`, `SPELL_HINT`, `NO_IP_HINT`.
const LOCAL_TARGET: &str = "198.18.0.2 is an address of this host (route via lo0)";
const LOCAL_HINT: &str = "    [hint] try \"--interface ethX\" and \"--router-ip 192.0.2.1\"";
const MASKED_HINT: &str =
    "    [hint] run as root, or try something like \"--source-mac 00-11-22-33-44-55\"";
const SPELL_HINT: &str = "    [hint] did you spell the name correctly?";
const NO_IP_HINT: &str = "    [hint] if it has no IP address, manually set with something like \"--source-ip 198.51.100.17\"";

/// Mac стенда m1 в живом окне macOS на b7e397a: feth4201 (сторона сканера, без IPv4, только BPF с
/// `--adapter-ip 198.18.0.1`), feth4202 (198.18.0.2/30, собственный IP-стек Mac в роли пира), lo0 и uplink en0 с
/// единственным маршрутом по умолчанию. Маршруты стенда дословно из окна:
///
/// ```text
/// $ route -n get 198.18.0.2   (destination 198.18.0.0, mask 255.255.255.252, interface feth4202, flags <UP,DONE,CLONING>)
/// $ netstat -rn -f inet | grep 198.18.
/// 198.18.0/30        link#36            UC               feth4202      !
/// 198.18.0.1         2:ac:0:0:0:1       UHLSI            feth4202
/// ```
///
/// `cloned`: состояние после того, как Mac сам отправил на 198.18.0.2. Darwin клонировал маршрут хоста
/// `198.18.0.2 … lo0` (`RTF_LOCAL`), и `RTM_GET` отвечает им (окно этот ответ не записало: флаги это обычные флаги
/// клона адреса хоста, разбор читает из них только `RTF_LOCAL`, `RTF_GATEWAY`, `RTF_REJECT`/`RTF_BLACKHOLE`,
/// `RTF_LLINFO`). `root`: MAC интерфейсов видны; без root Darwin отдаёт плейсхолдер `02:00:00:00:00:00`, и
/// `ifinfo::iface_list` даёт `mac: None, mac_masked: true`.
///
/// `lookup` собирает байты ответа `RTM_GET`, разбирает их `parse_rt_reply` и классифицирует тем же кодом, что
/// `macos::route::OsRoutes` ([`lookup_from_rt`], [`defaults_from_rt`]); `list` это `OsIfaces`.
struct MacM1 {
    cloned: bool,
    root: bool,
    lookups: std::cell::RefCell<Vec<Ipv4Addr>>,
}

impl MacM1 {
    fn new(cloned: bool, root: bool) -> Self {
        MacM1 {
            cloned,
            root,
            lookups: Default::default(),
        }
    }

    fn lookups(&self) -> Vec<Ipv4Addr> {
        self.lookups.borrow().clone()
    }

    /// Ответ `RTM_GET` ядра к `dst` (самый длинный префикс). MAC в `RTAX_IFP` разбор не читает.
    fn reply(&self, dst: Ipv4Addr) -> Vec<u8> {
        let msg = |flags: i32, index: u16, sas: &[(i32, Vec<u8>)]| {
            rt_msg(flags | RTF_DONE, index, sas, PID, SEQ, 0)
        };
        let mask = |len: u32| sin(Ipv4Addr::from(u32::MAX << (32 - len)));
        let ifp = |index: u16, name: &str, mac| (RTA_IFP_BIT, sdl(index, name, mac));
        let feth4202 = || ifp(M1_PEER, "feth4202", Some(M1_PEER_MAC));
        let lo0 = || ifp(M1_LO0, "lo0", None);
        let en0 = || ifp(M1_EN0, "en0", Some(M1_EN0_MAC));
        match dst.octets() {
            [198, 18, 0, 2] if self.cloned => msg(
                RTF_UP | RTF_HOST | RTF_LLINFO | RTF_WASCLONED | RTF_IFSCOPE | RTF_LOCAL,
                M1_LO0,
                &[
                    (RTA_DST_BIT, sin(dst)),
                    (RTA_GATEWAY_BIT, sdl(M1_PEER, "", Some(M1_PEER_MAC))),
                    lo0(),
                    (RTA_IFA_BIT, sin(dst)),
                ],
            ),
            // 198.18.0.1  2:ac:0:0:0:1  UHLSI  feth4202
            [198, 18, 0, 1] => msg(
                RTF_UP | RTF_HOST | RTF_LLINFO | RTF_STATIC | RTF_IFSCOPE,
                M1_PEER,
                &[
                    (RTA_DST_BIT, sin(dst)),
                    (RTA_GATEWAY_BIT, sdl(M1_PEER, "", Some(M1_SCANNER_MAC))),
                    feth4202(),
                    (RTA_IFA_BIT, sin(ip(198, 18, 0, 2))),
                ],
            ),
            // 198.18.0/30  link#36  UC  feth4202 (route get: <UP,DONE,CLONING>)
            [198, 18, 0, _] => msg(
                RTF_UP | RTF_CLONING,
                M1_PEER,
                &[
                    (RTA_DST_BIT, sin(ip(198, 18, 0, 0))),
                    (RTA_GATEWAY_BIT, sdl(M1_PEER, "", None)),
                    (RTA_NETMASK_BIT, mask(30)),
                    feth4202(),
                    (RTA_IFA_BIT, sin(ip(198, 18, 0, 2))),
                ],
            ),
            [127, 0, 0, 1] => msg(
                RTF_UP | RTF_HOST,
                M1_LO0,
                &[
                    (RTA_DST_BIT, sin(dst)),
                    (RTA_GATEWAY_BIT, sin(dst)),
                    lo0(),
                    (RTA_IFA_BIT, sin(dst)),
                ],
            ),
            [127, ..] => msg(
                RTF_UP | RTF_CLONING | RTF_STATIC,
                M1_LO0,
                &[
                    (RTA_DST_BIT, sin(ip(127, 0, 0, 0))),
                    (RTA_GATEWAY_BIT, sin(Ipv4Addr::LOCALHOST)),
                    (RTA_NETMASK_BIT, mask(8)),
                    lo0(),
                    (RTA_IFA_BIT, sin(Ipv4Addr::LOCALHOST)),
                ],
            ),
            [192, 0, 2, _] => msg(
                RTF_UP | RTF_CLONING | RTF_STATIC,
                M1_EN0,
                &[
                    (RTA_DST_BIT, sin(ip(192, 0, 2, 0))),
                    (RTA_GATEWAY_BIT, sdl(M1_EN0, "", None)),
                    (RTA_NETMASK_BIT, mask(24)),
                    en0(),
                    (RTA_IFA_BIT, sin(M1_EN0_IP)),
                ],
            ),
            _ => msg(
                RTF_UP | RTF_GATEWAY | RTF_STATIC,
                M1_EN0,
                &[
                    (RTA_DST_BIT, sin(Ipv4Addr::UNSPECIFIED)),
                    (RTA_GATEWAY_BIT, sin(M1_EN0_GW)),
                    (RTA_NETMASK_BIT, vec![0, 0, 0, 0]),
                    en0(),
                    (RTA_IFA_BIT, sin(M1_EN0_IP)),
                ],
            ),
        }
    }

    fn parsed(&self, dst: Ipv4Addr) -> RtReply {
        parse_rt_reply(&self.reply(dst), SEQ, PID).unwrap().unwrap()
    }
}

impl RouteTable for MacM1 {
    fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, crate::NetError> {
        self.lookups.borrow_mut().push(dst);
        Ok(lookup_from_rt(Some(&self.parsed(dst)), dst, &self.list()?))
    }

    fn default_routes(&self) -> Result<Vec<Route>, crate::NetError> {
        Ok(defaults_from_rt(Some(&self.parsed(Ipv4Addr::UNSPECIFIED))))
    }
}

impl Interfaces for MacM1 {
    /// Порядок `getifaddrs`; feth подняты (`flags=8843<UP,…>`) и Ethernet (IFT_ETHER), lo0 нет.
    fn list(&self) -> Result<Vec<Iface>, crate::NetError> {
        let nic = |name: &str, index: u16, mac: Option<[u8; 6]>, ethernet, ipv4| Iface {
            name: name.into(),
            index: u32::from(index),
            device_id: name.into(),
            description: None,
            mac: mac.filter(|_| self.root),
            mac_masked: mac.is_some() && !self.root,
            ethernet,
            up: true,
            ipv4,
        };
        Ok(vec![
            nic("lo0", M1_LO0, None, false, vec![Ipv4Addr::LOCALHOST]),
            nic("en0", M1_EN0, Some(M1_EN0_MAC), true, vec![M1_EN0_IP]),
            nic("feth4201", M1_SCANNER, Some(M1_SCANNER_MAC), true, vec![]),
            nic(
                "feth4202",
                M1_PEER,
                Some(M1_PEER_MAC),
                true,
                vec![ip(198, 18, 0, 2)],
            ),
        ])
    }
}

/// Единственная цель-проба, как её строит CLI из позиционной цели.
fn m1_target(a: Ipv4Addr) -> Targets {
    n2_targets(&[(a, a)]).unwrap()
}

/// Что печатает CLI: отказ обнаружения это `[-] ` и его текст (`rmasscan-cli`: `live::refusal`, `error_text` без
/// обёртки), успех это строка интерфейса.
fn m1_printed(r: &Result<Detected, DetectError>) -> String {
    match r {
        Err(e) => format!("[-] {e}"),
        Ok(d) => format!("[+] interface = {} ({:?})", d.iface.name, d.iface_source),
    }
}

/// Отказ строки таблицы: `[-] FAIL: ` + `fail`, затем строки `hints`.
fn m1_refusal(fail: &str, hints: &[&str]) -> String {
    format!("[-] FAIL: {fail}\n{}", hints.join("\n"))
}

/// Флаги адаптера строки таблицы → [`Overrides`] (пять флагов, которые зовут суиты macOS; иной это ошибка теста).
fn m1_overrides(flags: &[&str]) -> Overrides {
    let mac = |s: &str| -> [u8; 6] {
        let v: Vec<u8> = s
            .split('-')
            .map(|h| u8::from_str_radix(h, 16).unwrap())
            .collect();
        v.try_into().unwrap()
    };
    let mut ov = Overrides::default();
    for pair in flags.chunks(2) {
        let [flag, value] = pair else {
            panic!("{flags:?}")
        };
        match *flag {
            "--adapter" => ov.adapter = Some((*value).into()),
            "--adapter-ip" => ov.adapter_ip = Some(value.parse().unwrap()),
            "--adapter-mac" => ov.adapter_mac = Some(mac(value)),
            "--router-ip" => ov.router_ip = Some(value.parse().unwrap()),
            "--router-mac" => ov.router_mac = Some(mac(value)),
            other => panic!("flag {other}"),
        }
    }
    ov
}

/// m05_user_no_adapter, его preflight: `--offline` и argv строки (цель 198.18.0.2, флагов адаптера нет) в окне без
/// root на ответе `RTM_GET` из окна (маршрут подсети через feth4202, `<UP,DONE,CLONING>`; маршрута хоста через lo0 ещё
/// нет). Печатается ровно отказ и подсказка строки m05. На b7e397a тот же preflight в окне напечатал
/// `[-] FAIL: MAC of interface "feth4202" is os-masked (…)`: ответ не через lo0 и без `RTF_LOCAL` вёл к feth4202.
#[test]
fn mac_m1_m05_preflight_on_the_subnet_route_reply_refuses_local_target() {
    let m = MacM1::new(false, false);
    let reply = m.parsed(ip(198, 18, 0, 2));
    assert_eq!(
        (
            reply.flags,
            reply.ifp.as_deref(),
            reply.ifindex,
            reply.gateway_is_link
        ),
        (
            RTF_UP | RTF_DONE | RTF_CLONING,
            Some("feth4202"),
            u32::from(M1_PEER),
            true
        ),
        "the RTM_GET reply of the window"
    );
    let r = detect_offline(&m1_target(ip(198, 18, 0, 2)), &Overrides::default(), &m, &m);
    let printed = m1_printed(&r);
    assert_eq!(
        printed,
        m1_refusal(LOCAL_TARGET, &[LOCAL_HINT]),
        "the preflight printed:\n{printed}"
    );
    assert_eq!(
        r.unwrap_err(),
        DetectError::LocalTarget {
            ip: ip(198, 18, 0, 2),
            ifname: "lo0".into(),
            with_adapter: false,
        }
    );
    assert_eq!(m.lookups(), [ip(198, 18, 0, 2)]);
}

/// Тот же отказ при уже клонированном маршруте хоста (`RTM_GET` отвечает `198.18.0.2 … lo0` с `RTF_LOCAL`; его ловило
/// и прежнее правило), в окне root и без `--offline` (у живого m05 `fail` и `hints` те же): текст не зависит ни от
/// истории кеша маршрутов, ни от привилегий.
#[test]
fn mac_m1_m05_refusal_is_the_same_on_the_cloned_lo0_reply_under_root_and_live() {
    let reply = MacM1::new(true, false).parsed(ip(198, 18, 0, 2));
    assert_eq!(
        route_from_rt(&reply),
        Some(Route {
            ifindex: u32::from(M1_LO0),
            ifname: "lo0".into(),
            gateway: None,
            local: true,
        }),
        "the cloned reply alone is local"
    );
    let want = m1_refusal(LOCAL_TARGET, &[LOCAL_HINT]);
    let mut wrong = Vec::new();
    for cloned in [false, true] {
        for root in [false, true] {
            for offline in [true, false] {
                let m = MacM1::new(cloned, root);
                let t = m1_target(ip(198, 18, 0, 2));
                let r = if offline {
                    detect_offline(&t, &Overrides::default(), &m, &m)
                } else {
                    detect(&t, &Overrides::default(), &m, &m)
                };
                let printed = m1_printed(&r);
                if printed != want || m.lookups() != [ip(198, 18, 0, 2)] {
                    wrong.push(format!(
                        "cloned {cloned}, root {root}, offline {offline}: {printed}"
                    ));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "\n{}", wrong.join("\n"));
}

/// Классификация адресов m1 (её зашивает CLI-тест `live_fake::mac_m1`): 198.18.0.2, адрес feth4202, это адрес хоста
/// через lo0 при обоих ответах `RTM_GET`, и 127.0.0.1 и адрес en0 тоже. Адрес сканера 198.18.0.1 (статический
/// llinfo-маршрут хоста `UHLSI`, ни на одном интерфейсе этого адреса нет), сеть и широковещательный адрес /30 идут
/// on-link через feth4202; маршрут по умолчанию один, через en0. На пути `--adapter` без `--router-ip`/`--router-mac`
/// цель 198.18.0.2 тоже `LocalTarget`, с подсказками маршрутизатора C (на b7e397a в состоянии подсети это был
/// `RouteNotViaAdapter`: «маршрут через feth4202, не feth4201»).
#[test]
fn mac_m1_only_addresses_of_this_host_are_local_and_they_route_via_lo0() {
    let lo0 = Route {
        ifindex: u32::from(M1_LO0),
        ifname: "lo0".into(),
        gateway: None,
        local: true,
    };
    let peer = Route {
        ifindex: u32::from(M1_PEER),
        ifname: "feth4202".into(),
        gateway: None,
        local: false,
    };
    let en0 = |gateway| Route {
        ifindex: u32::from(M1_EN0),
        ifname: "en0".into(),
        gateway,
        local: false,
    };
    for cloned in [false, true] {
        let m = MacM1::new(cloned, false);
        for (dst, want) in [
            (ip(198, 18, 0, 2), &lo0),
            (ip(198, 18, 0, 1), &peer),
            (ip(198, 18, 0, 0), &peer),
            (ip(198, 18, 0, 3), &peer),
            (Ipv4Addr::LOCALHOST, &lo0),
            (ip(127, 0, 0, 2), &lo0),
            (M1_EN0_IP, &lo0),
            (ip(192, 0, 2, 20), &en0(None)),
            (ip(203, 0, 113, 5), &en0(Some(M1_EN0_GW))),
        ] {
            assert_eq!(
                m.lookup(dst).unwrap().as_ref(),
                Some(want),
                "{dst}, cloned {cloned}"
            );
        }
        assert_eq!(m.default_routes().unwrap(), [en0(Some(M1_EN0_GW))]);

        let m = MacM1::new(cloned, false);
        let ov = m1_overrides(&[
            "--adapter",
            "feth4201",
            "--adapter-ip",
            "198.18.0.1",
            "--adapter-mac",
            "02-ac-00-00-00-01",
        ]);
        let e = detect(&m1_target(ip(198, 18, 0, 2)), &ov, &m, &m).unwrap_err();
        assert_eq!(
            e,
            DetectError::LocalTarget {
                ip: ip(198, 18, 0, 2),
                ifname: "lo0".into(),
                with_adapter: true,
            },
            "cloned {cloned}: [-] {e}"
        );
        assert_eq!(e.to_string(), format!("FAIL: {LOCAL_TARGET}{ROUTER_HINTS}"));
    }
}

/// Правило адреса хоста не зависит от ответа `RTM_GET`: без ответа (ESRCH), с reject-маршрутом или маршрутом через
/// шлюз адрес интерфейса это адрес хоста через lo0 (индекс lo0 из списка интерфейсов, 0 без lo0). Чужой адрес без
/// ответа это «нет маршрута», а `RTF_LOCAL`/lo0 ответа делают локальным и чужой адрес, как прежде.
#[test]
fn mac_own_address_is_local_whatever_rtm_get_returned() {
    let ifaces = MacM1::new(false, false).list().unwrap();
    let own = ip(198, 18, 0, 2);
    let lo0 = Route {
        ifindex: u32::from(M1_LO0),
        ifname: "lo0".into(),
        gateway: None,
        local: true,
    };
    let feth = |flags: i32, gateway: Vec<u8>| {
        let m = rt_msg(
            RTF_UP | RTF_DONE | flags,
            M1_PEER,
            &[
                (RTA_DST_BIT, sin(own)),
                (RTA_GATEWAY_BIT, gateway),
                (RTA_IFP_BIT, sdl(M1_PEER, "feth4202", None)),
            ],
            PID,
            SEQ,
            0,
        );
        parse_rt_reply(&m, SEQ, PID).unwrap().unwrap()
    };
    let reject = feth(RTF_REJECT | RTF_HOST, sdl(M1_PEER, "", None));
    let via_gateway = feth(RTF_GATEWAY, sin(ip(198, 18, 0, 1)));
    assert_eq!(route_from_rt(&reject), None);
    assert!(!route_from_rt(&via_gateway).unwrap().local);
    for reply in [None, Some(&reject), Some(&via_gateway)] {
        assert_eq!(
            lookup_from_rt(reply, own, &ifaces),
            Some(lo0.clone()),
            "{reply:?}"
        );
    }
    let no_lo0: Vec<Iface> = ifaces.iter().filter(|i| i.name != "lo0").cloned().collect();
    assert_eq!(
        lookup_from_rt(None, own, &no_lo0),
        Some(Route {
            ifindex: 0,
            ..lo0.clone()
        })
    );
    assert_eq!(lookup_from_rt(None, ip(198, 18, 0, 1), &ifaces), None);
    let foreign = ip(192, 0, 2, 99);
    let local_reply = |flags: i32, ifname: &str| {
        let m = rt_msg(
            RTF_UP | RTF_DONE | flags,
            M1_EN0,
            &[
                (RTA_DST_BIT, sin(foreign)),
                (RTA_IFP_BIT, sdl(M1_EN0, ifname, None)),
            ],
            PID,
            SEQ,
            0,
        );
        parse_rt_reply(&m, SEQ, PID).unwrap().unwrap()
    };
    let by_flag = lookup_from_rt(Some(&local_reply(RTF_LOCAL, "en0")), foreign, &ifaces).unwrap();
    assert_eq!((by_flag.local, by_flag.ifname.as_str()), (true, "en0"));
    let by_lo0 = lookup_from_rt(Some(&local_reply(RTF_HOST, "lo0")), foreign, &ifaces).unwrap();
    assert!(by_lo0.local);
    let on_link = lookup_from_rt(Some(&local_reply(RTF_HOST, "en0")), foreign, &ifaces).unwrap();
    assert!(!on_link.local);
}

/// Флаги строк `MACOS_CASES` и `MACOS_ROOT_CASES` (rmasscan-lab `autodetect_verify.rs`, между `-pPORTS` и
/// `COMMON_ARGS`) дословно; цель у всех 198.18.0.2, у `--iflist` (m07, m11) argv только `--iflist`. `true`: окно root.
const M1_CASES: [(&str, bool, &[&str]); 9] = [
    (
        "m01_user_masked",
        false,
        &[
            "--adapter",
            "feth4201",
            "--adapter-ip",
            "198.18.0.1",
            "--router-ip",
            "198.18.0.2",
        ],
    ),
    (
        "m02_user_explicit",
        false,
        &[
            "--adapter",
            "feth4201",
            "--adapter-ip",
            "198.18.0.1",
            "--adapter-mac",
            "02-ac-00-00-00-01",
            "--router-ip",
            "198.18.0.2",
        ],
    ),
    (
        "m03_user_router_mac",
        false,
        &[
            "--adapter",
            "feth4201",
            "--adapter-ip",
            "198.18.0.1",
            "--adapter-mac",
            "02-ac-00-00-00-01",
            "--router-ip",
            "198.18.0.2",
            "--router-mac",
            "02-ac-00-00-00-02",
        ],
    ),
    (
        "m04_user_arp_timeout",
        false,
        &[
            "--adapter",
            "feth4201",
            "--adapter-ip",
            "198.18.0.1",
            "--adapter-mac",
            "02-ac-00-00-00-01",
            "--router-ip",
            "198.18.0.3",
        ],
    ),
    ("m05_user_no_adapter", false, &[]),
    (
        "m06_user_no_ip",
        false,
        &[
            "--adapter",
            "feth4201",
            "--adapter-mac",
            "02-ac-00-00-00-01",
            "--router-ip",
            "198.18.0.2",
        ],
    ),
    ("m07_user_iflist", false, &[]),
    (
        "m10_root_auto_mac",
        true,
        &[
            "--adapter",
            "feth4201",
            "--adapter-ip",
            "198.18.0.1",
            "--router-ip",
            "198.18.0.2",
        ],
    ),
    ("m11_root_iflist", true, &[]),
];

/// Каждая строка `MACOS_CASES` и `MACOS_ROOT_CASES` на таблице m1 при обоих ответах `RTM_GET` (живой путь обнаружения,
/// как в окне). Случаи с `--adapter` и `--router-ip`/`--router-mac` маршрутов не ищут вовсе и дают то же, что на
/// b7e397a: m01 `MacMasked`, m02-m04 и m10 интерфейс, IP и MAC по источникам строки (`detection`) и следующий хоп
/// `--router-ip`/`--router-mac`, m06 `NoIpv4`; отказы печатают `fail` и `hints` строк. `--iflist` (m07, m11) показывает
/// строку стенда feth4201 с MAC `masked` без root и настоящим MAC под root. Иначе только m05: один lookup и
/// `LocalTarget`.
#[test]
fn mac_m1_every_macos_case_detects_as_before_and_only_m05_reads_a_route() {
    let given = |ip| NextHop::Resolve {
        ip,
        why: NextHopWhy::Given,
    };
    let mut wrong = Vec::new();
    for cloned in [false, true] {
        for (tag, root, flags) in M1_CASES {
            let m = MacM1::new(cloned, root);
            if tag.ends_with("_iflist") {
                let text = iflist_text(&m.list().unwrap(), &m.default_routes().unwrap());
                let macs = if root {
                    [
                        "02-bb-00-00-00-0e",
                        "02-ac-00-00-00-01",
                        "02-ac-00-00-00-02",
                    ]
                } else {
                    ["masked"; 3]
                };
                let want = format!(
                    "lo0 index=1 mac=none ipv4=127.0.0.1 up other\n\
                     en0 index=14 mac={} ipv4=192.0.2.10 up ethernet\n\
                     feth4201 index=35 mac={} ipv4=- up ethernet\n\
                     feth4202 index=36 mac={} ipv4=198.18.0.2 up ethernet\n\
                     default via 192.0.2.1 dev en0\n",
                    macs[0], macs[1], macs[2]
                );
                if text != want || !m.lookups().is_empty() {
                    wrong.push(format!("{tag} (cloned {cloned}):\n{text}"));
                }
                continue;
            }
            let scanner = m
                .list()
                .unwrap()
                .into_iter()
                .find(|i| i.name == "feth4201")
                .unwrap();
            let found = |mac_source, next_hop| {
                Ok(Detected {
                    iface: scanner.clone(),
                    iface_source: Source::Given,
                    source_ipv4: (ip(198, 18, 0, 1), Source::Given),
                    source_mac: (M1_SCANNER_MAC, mac_source),
                    next_hop,
                })
            };
            let (want, text) = match tag {
                "m01_user_masked" => (
                    Err(DetectError::MacMasked("feth4201".into())),
                    Some(m1_refusal(
                        "MAC of interface \"feth4201\" is os-masked (Darwin hides MACs from unprivileged processes)",
                        &[MASKED_HINT],
                    )),
                ),
                "m02_user_explicit" => (found(Source::Given, given(ip(198, 18, 0, 2))), None),
                "m03_user_router_mac" => (
                    found(Source::Given, NextHop::Mac(M1_PEER_MAC, Source::Given)),
                    None,
                ),
                "m04_user_arp_timeout" => (found(Source::Given, given(ip(198, 18, 0, 3))), None),
                "m05_user_no_adapter" => (
                    Err(DetectError::LocalTarget {
                        ip: ip(198, 18, 0, 2),
                        ifname: "lo0".into(),
                        with_adapter: false,
                    }),
                    Some(m1_refusal(LOCAL_TARGET, &[LOCAL_HINT])),
                ),
                "m06_user_no_ip" => (
                    Err(DetectError::NoIpv4("feth4201".into())),
                    Some(m1_refusal(
                        "failed to detect IP of interface \"feth4201\"",
                        &[SPELL_HINT, NO_IP_HINT],
                    )),
                ),
                "m10_root_auto_mac" => (found(Source::Detected, given(ip(198, 18, 0, 2))), None),
                other => panic!("case {other}"),
            };
            let got = detect(&m1_target(ip(198, 18, 0, 2)), &m1_overrides(flags), &m, &m);
            let reads: &[Ipv4Addr] = if tag == "m05_user_no_adapter" {
                &[ip(198, 18, 0, 2)]
            } else {
                &[]
            };
            if got != want || text.is_some_and(|t| t != m1_printed(&got)) || m.lookups() != reads {
                wrong.push(format!(
                    "{tag} (cloned {cloned}): {} / lookups {:?}",
                    m1_printed(&got),
                    m.lookups()
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "\n{}", wrong.join("\n"));
}

#[cfg(target_os = "macos")]
#[test]
fn m1_reply_flags_match_libc() {
    assert_eq!(
        [
            RTF_HOST,
            RTF_DONE,
            RTF_CLONING,
            RTF_STATIC,
            RTF_WASCLONED,
            RTF_IFSCOPE
        ],
        [
            libc::RTF_HOST,
            libc::RTF_DONE,
            libc::RTF_CLONING,
            libc::RTF_STATIC,
            libc::RTF_WASCLONED,
            libc::RTF_IFSCOPE
        ]
    );
}

// ---------- Windows IP Helper ----------

const GUID_ETH: &str = "{00000000-0000-0000-0000-00000000000A}";

fn adapter(if_index: u32, if_type: u32, friendly: &str, ipv4: &[Ipv4Addr]) -> WinAdapter {
    WinAdapter {
        if_index,
        if_type,
        oper_up: true,
        adapter_name: format!("{{00000000-0000-0000-0000-{if_index:012}}}"),
        friendly_name: Some(friendly.into()),
        mac: (if_type != IF_TYPE_SOFTWARE_LOOPBACK).then_some([2, 0x57, 0, 0, 0, if_index as u8]),
        ipv4: ipv4.to_vec(),
    }
}

fn fwd(ifindex: u32, prefix_len: u8, next_hop: Ipv4Addr, metric: u32) -> Fwd {
    Fwd {
        ifindex,
        prefix_len,
        next_hop,
        metric,
        mib_loopback: false,
        loopback_if: false,
    }
}

fn host_adapters() -> Vec<WinAdapter> {
    vec![
        adapter(
            12,
            IF_TYPE_ETHERNET_CSMACD,
            "Ethernet",
            &[ip(192, 0, 2, 10)],
        ),
        adapter(
            1,
            IF_TYPE_SOFTWARE_LOOPBACK,
            "Loopback Pseudo-Interface 1",
            &[ip(127, 0, 0, 1)],
        ),
        adapter(15, IF_TYPE_IEEE80211, "Wi-Fi", &[ip(198, 51, 100, 20)]),
    ]
}

fn ifaces_of(a: &[WinAdapter]) -> Vec<Iface> {
    a.iter().map(iface_from_adapter).collect()
}

#[test]
fn win_adapter_iftype_71_is_ethernet_and_24_is_loopback() {
    for (t, eth) in [
        (6, true),
        (71, true),
        (24, false),
        (23, false),
        (131, false),
        (53, false),
    ] {
        assert_eq!(if_type_is_ethernet(t), eth, "IfType {t}");
    }
    let mut a = adapter(
        12,
        IF_TYPE_ETHERNET_CSMACD,
        "Ethernet 2",
        &[ip(192, 0, 2, 10), ip(192, 0, 2, 11)],
    );
    a.adapter_name = GUID_ETH.into();
    let i = iface_from_adapter(&a);
    assert_eq!(
        i,
        Iface {
            name: "Ethernet 2".into(),
            index: 12,
            device_id: format!("\\Device\\NPF_{GUID_ETH}"),
            description: Some("Ethernet 2".into()),
            mac: Some([2, 0x57, 0, 0, 0, 12]),
            mac_masked: false,
            ethernet: true,
            up: true,
            ipv4: vec![ip(192, 0, 2, 10), ip(192, 0, 2, 11)],
        }
    );
    let wifi = iface_from_adapter(&adapter(15, IF_TYPE_IEEE80211, "Wi-Fi", &[]));
    assert!(
        wifi.ethernet,
        "IfType 71 (Wi-Fi) carries Ethernet frames under Npcap"
    );
    let lo = iface_from_adapter(&adapter(
        1,
        IF_TYPE_SOFTWARE_LOOPBACK,
        "Loopback Pseudo-Interface 1",
        &[],
    ));
    assert!(!lo.ethernet);
    // Без FriendlyName имя это AdapterName; OperStatus не Up это down.
    let mut bare = a.clone();
    bare.friendly_name = None;
    bare.oper_up = false;
    let b = iface_from_adapter(&bare);
    assert_eq!(
        (b.name.as_str(), b.description, b.up),
        (GUID_ETH, None, false)
    );
    // IfType 24 помечает строки маршрутов своего интерфейса.
    let mut rows = [
        fwd(1, 32, Ipv4Addr::UNSPECIFIED, 256),
        fwd(12, 32, Ipv4Addr::UNSPECIFIED, 256),
    ];
    mark_loopback(&mut rows, &host_adapters());
    assert_eq!((rows[0].loopback_if, rows[1].loopback_if), (true, false));
    assert_eq!(
        (rows[0].mib_loopback, rows[1].mib_loopback),
        (false, false),
        "IfType 24 never sets the row's MIB flag"
    );
}

#[test]
fn fwd_row_iftype_24_or_own_unicast_is_local_the_mib_flag_alone_is_not() {
    let adapters = host_adapters();
    let ifaces = ifaces_of(&adapters);
    // Флаг MIB `Loopback` строки сам по себе не делает чужой адрес локальным: это on-link маршрут интерфейса строки
    // (так Windows помечает /32 широковещательного адреса подсети), как RTN_BROADCAST на Linux.
    let mut flagged = fwd(12, 32, Ipv4Addr::UNSPECIFIED, 256);
    flagged.mib_loopback = true;
    assert_eq!(
        route_from_best(&flagged, ip(192, 0, 2, 255), &ifaces),
        Route {
            ifindex: 12,
            ifname: "Ethernet".into(),
            gateway: None,
            local: false,
        },
        "a MIB-flagged row to a foreign address is on-link"
    );
    // С флагом MIB и адресом адаптера назначение локально по адресу.
    assert!(route_from_best(&flagged, ip(192, 0, 2, 10), &ifaces).local);
    // IfType 24 интерфейса строки.
    let mut rows = [fwd(1, 8, Ipv4Addr::UNSPECIFIED, 256)];
    mark_loopback(&mut rows, &adapters);
    let lo = route_from_best(&rows[0], ip(127, 0, 0, 1), &ifaces);
    assert_eq!(
        lo,
        Route {
            ifindex: 1,
            ifname: "Loopback Pseudo-Interface 1".into(),
            gateway: None,
            local: true,
        }
    );
    // dst равен unicast-адресу адаптера (любого).
    assert!(
        route_from_best(
            &fwd(12, 32, Ipv4Addr::UNSPECIFIED, 256),
            ip(192, 0, 2, 10),
            &ifaces
        )
        .local
    );
    assert!(
        route_from_best(
            &fwd(12, 32, Ipv4Addr::UNSPECIFIED, 256),
            ip(198, 51, 100, 20),
            &ifaces
        )
        .local
    );
    // Чужой адрес: on-link без шлюза, через шлюз со шлюзом.
    let onlink = route_from_best(
        &fwd(12, 24, Ipv4Addr::UNSPECIFIED, 256),
        ip(192, 0, 2, 20),
        &ifaces,
    );
    assert_eq!(
        onlink,
        Route {
            ifindex: 12,
            ifname: "Ethernet".into(),
            gateway: None,
            local: false,
        }
    );
    let via = route_from_best(
        &fwd(12, 0, ip(192, 0, 2, 1), 25),
        ip(203, 0, 113, 5),
        &ifaces,
    );
    assert_eq!((via.gateway, via.local), (Some(ip(192, 0, 2, 1)), false));
    // Флаг MIB со шлюзом: строка не локальна, шлюз остаётся.
    let mut lgw = fwd(12, 0, ip(192, 0, 2, 1), 25);
    lgw.mib_loopback = true;
    let r = route_from_best(&lgw, ip(203, 0, 113, 5), &ifaces);
    assert_eq!((r.gateway, r.local), (Some(ip(192, 0, 2, 1)), false));
    // Интерфейс IfType 24 отменяет шлюз.
    let mut rows = [fwd(1, 0, ip(192, 0, 2, 1), 25)];
    mark_loopback(&mut rows, &adapters);
    let r = route_from_best(&rows[0], ip(203, 0, 113, 5), &ifaces);
    assert_eq!((r.gateway, r.local), (None, true));
}

#[test]
fn fwd_rows_prefix_zero_sorted_by_metric() {
    let adapters = host_adapters();
    let ifaces = ifaces_of(&adapters);
    // Строка с префиксом 0 и флагом MIB `Loopback` на Ethernet: фильтр маршрутов по умолчанию её отбрасывает, как и
    // строку через IfType 24 (флаг MIB здесь значит то же, что до PF3).
    let mut mib_flagged = fwd(12, 0, ip(192, 0, 2, 254), 5);
    mib_flagged.mib_loopback = true;
    let table = vec![
        fwd(12, 24, Ipv4Addr::UNSPECIFIED, 1),
        fwd(12, 0, ip(192, 0, 2, 1), 50),
        fwd(15, 0, ip(198, 51, 100, 1), 10),
        fwd(1, 0, Ipv4Addr::UNSPECIFIED, 0),
        mib_flagged,
        fwd(15, 0, Ipv4Addr::UNSPECIFIED, 25),
        fwd(99, 0, ip(203, 0, 113, 1), 30),
        fwd(12, 32, ip(192, 0, 2, 1), 2),
    ];
    let mut rows = table.clone();
    mark_loopback(&mut rows, &adapters);
    assert_eq!(
        defaults_from_rows(table, &adapters),
        defaults_from_table(&rows, &ifaces),
        "OsRoutes::default_routes is mark_loopback + defaults_from_table"
    );
    let r = |ifindex: u32, ifname: &str, gateway: Option<Ipv4Addr>| Route {
        ifindex,
        ifname: ifname.into(),
        gateway,
        local: false,
    };
    assert_eq!(
        defaults_from_table(&rows, &ifaces),
        vec![
            r(15, "Wi-Fi", Some(ip(198, 51, 100, 1))),
            r(15, "Wi-Fi", None),
            r(99, "ifindex 99", Some(ip(203, 0, 113, 1))),
            r(12, "Ethernet", Some(ip(192, 0, 2, 1))),
        ],
        "prefix 0, neither the MIB Loopback flag nor IfType 24, by Metric; an unknown interface keeps its index as the name"
    );
}

// ---------- Windows: гость n2 (PF3) ----------

const N2_LAB: u32 = 14;
const N2_MGMT: u32 = 3;
const N2_LO: u32 = 1;
const N2_LAB_GUID: &str = "{C4617223-A264-44F4-BDC8-0EA27F02CC40}";
const N2_LAB_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x04, 0x80, 0xa9];

/// Строка таблицы гостя: префикс назначения и [`Fwd`] с флагом MIB `Loopback`, как его отдаёт IP Helper.
fn n2_row(
    prefix: Ipv4Addr,
    prefix_len: u8,
    ifindex: u32,
    next_hop: Ipv4Addr,
    metric: u32,
    mib_loopback: bool,
) -> (Ipv4Addr, Fwd) {
    (
        prefix,
        Fwd {
            ifindex,
            prefix_len,
            next_hop,
            metric,
            mib_loopback,
            loopback_if: false,
        },
    )
}

/// Гость n2 (Windows 11, стенд w01–w08b): лабораторный NIC «Ethernet 2» 198.18.0.1/30 без шлюза, NIC управления
/// «Ethernet» 10.0.2.15 с единственным маршрутом по умолчанию через 10.0.2.2 и Loopback Pseudo-Interface 1. Строки
/// «Ethernet 2» дословно из `Get-NetRoute` гостя (живое окно 2026-11-03), маршрут по умолчанию из записи гостя
/// (ifIndex 3, NextHop 10.0.2.2, Metric 0), строки loopback это стандартные строки Windows (не сняты).
///
/// Флаг MIB `Loopback` (`Get-NetRoute` его не показывает): у 198.18.0.3/32 он стоит, иначе в окне не было бы
/// `is an address of this host` (это не адрес адаптера и не IfType 24); у /30 его нет (w01 к 198.18.0.2 прошёл); у
/// остальных строк хоста он стоит, как Windows помечает локальные строки, и ни на что не влияет: 198.18.0.1 это адрес
/// адаптера, 224.0.0.0/4 и 255.255.255.255 не бывают целями-пробами, 127.0.0.0/8 идёт через IfType 24.
///
/// `lookup` выбирает строку как `GetBestRoute2` (самый длинный префикс, затем меньшая метрика) и классифицирует её тем
/// же кодом, что `windows::os::OsRoutes` ([`lookup_from_best`], [`defaults_from_rows`]); `list` как `OsIfaces`.
struct GuestN2 {
    rows: Vec<(Ipv4Addr, Fwd)>,
    adapters: Vec<WinAdapter>,
    lookups: std::cell::RefCell<Vec<Ipv4Addr>>,
}

impl GuestN2 {
    fn best(&self, dst: Ipv4Addr) -> Option<&(Ipv4Addr, Fwd)> {
        self.rows
            .iter()
            .filter(|(p, f)| {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(f.prefix_len))
                    .unwrap_or(0);
                u32::from(dst) & mask == u32::from(*p) & mask
            })
            .min_by_key(|(_, f)| (std::cmp::Reverse(f.prefix_len), f.metric))
    }

    fn lookups(&self) -> Vec<Ipv4Addr> {
        self.lookups.borrow().clone()
    }
}

impl RouteTable for GuestN2 {
    fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, crate::NetError> {
        self.lookups.borrow_mut().push(dst);
        Ok(self
            .best(dst)
            .map(|(_, f)| lookup_from_best(*f, dst, &self.adapters)))
    }

    fn default_routes(&self) -> Result<Vec<Route>, crate::NetError> {
        let rows = self.rows.iter().map(|(_, f)| *f).collect();
        Ok(defaults_from_rows(rows, &self.adapters))
    }
}

impl Interfaces for GuestN2 {
    fn list(&self) -> Result<Vec<Iface>, crate::NetError> {
        Ok(self.adapters.iter().map(iface_from_adapter).collect())
    }
}

fn guest_n2() -> GuestN2 {
    let on_link = Ipv4Addr::UNSPECIFIED;
    let mut lab = adapter(
        N2_LAB,
        IF_TYPE_ETHERNET_CSMACD,
        "Ethernet 2",
        &[ip(198, 18, 0, 1)],
    );
    lab.adapter_name = N2_LAB_GUID.into();
    lab.mac = Some(N2_LAB_MAC);
    let mut mgmt = adapter(
        N2_MGMT,
        IF_TYPE_ETHERNET_CSMACD,
        "Ethernet",
        &[ip(10, 0, 2, 15)],
    );
    mgmt.mac = Some([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    GuestN2 {
        rows: vec![
            // Get-NetRoute -AddressFamily IPv4 -InterfaceAlias 'Ethernet 2' (RouteMetric 256, TypeOfRoute 3).
            n2_row(ip(198, 18, 0, 0), 30, N2_LAB, on_link, 256, false),
            n2_row(ip(198, 18, 0, 1), 32, N2_LAB, on_link, 256, true),
            n2_row(ip(198, 18, 0, 3), 32, N2_LAB, on_link, 256, true),
            n2_row(ip(224, 0, 0, 0), 4, N2_LAB, on_link, 256, true),
            n2_row(ip(255, 255, 255, 255), 32, N2_LAB, on_link, 256, true),
            // Единственный маршрут по умолчанию гостя: NIC управления.
            n2_row(ip(0, 0, 0, 0), 0, N2_MGMT, ip(10, 0, 2, 2), 0, false),
            // Loopback Pseudo-Interface 1.
            n2_row(ip(127, 0, 0, 0), 8, N2_LO, on_link, 256, true),
            n2_row(ip(127, 0, 0, 1), 32, N2_LO, on_link, 256, true),
        ],
        adapters: vec![
            mgmt,
            lab,
            adapter(
                N2_LO,
                IF_TYPE_SOFTWARE_LOOPBACK,
                "Loopback Pseudo-Interface 1",
                &[ip(127, 0, 0, 1)],
            ),
        ],
        lookups: Default::default(),
    }
}

fn n2_targets(ranges: &[(Ipv4Addr, Ipv4Addr)]) -> Option<Targets> {
    let mut m = MassIp::new();
    for (a, b) in ranges {
        m.ipv4_mut().add_range(u32::from(*a), u32::from(*b));
    }
    probe_targets(&m)
}

fn n2_lab(local: bool) -> Route {
    Route {
        ifindex: N2_LAB,
        ifname: "Ethernet 2".into(),
        gateway: None,
        local,
    }
}

/// Классификация адресов стенда (её же зашивает герметичный CLI-тест `live_fake::guest_n2`): сосед 198.18.0.2 и
/// широковещательный 198.18.0.3 идут on-link через «Ethernet 2», адрес адаптера 198.18.0.1 и 127.0.0.1 (IfType 24)
/// локальны, маршрут по умолчанию один, через «Ethernet». Выбор строк совпадает с `Find-NetRoute` гостя.
#[test]
fn guest_n2_broadcast_is_on_link_own_address_and_loopback_interface_are_local() {
    let g = guest_n2();
    for (dst, picked) in [
        (ip(198, 18, 0, 2), (ip(198, 18, 0, 0), 30)),
        (ip(198, 18, 0, 0), (ip(198, 18, 0, 0), 30)),
        (ip(198, 18, 0, 3), (ip(198, 18, 0, 3), 32)),
        (ip(198, 18, 0, 1), (ip(198, 18, 0, 1), 32)),
    ] {
        let (p, f) = g.best(dst).unwrap();
        assert_eq!((*p, f.prefix_len), picked, "Find-NetRoute {dst}");
    }
    assert_eq!(
        g.lookup(ip(198, 18, 0, 3)).unwrap(),
        Some(n2_lab(false)),
        "the subnet broadcast is an on-link destination, as on Linux and macOS"
    );
    assert_eq!(g.lookup(ip(198, 18, 0, 2)).unwrap(), Some(n2_lab(false)));
    assert_eq!(
        g.lookup(ip(198, 18, 0, 1)).unwrap(),
        Some(n2_lab(true)),
        "the adapter's own unicast address"
    );
    assert_eq!(
        g.lookup(Ipv4Addr::LOCALHOST).unwrap(),
        Some(Route {
            ifindex: N2_LO,
            ifname: "Loopback Pseudo-Interface 1".into(),
            gateway: None,
            local: true,
        })
    );
    assert_eq!(
        g.default_routes().unwrap(),
        vec![Route {
            ifindex: N2_MGMT,
            ifname: "Ethernet".into(),
            gateway: Some(ip(10, 0, 2, 2)),
            local: false,
        }],
        "MIB-flagged and loopback rows are never default routes"
    );
}

/// w06_multi_no_gateway (lab `WINDOWS_CASES`), его preflight `--offline`: цели 198.18.0.2-198.18.0.3, интерфейс
/// «Ethernet 2» по маршруту к первой цели. В живом окне на 9496cd7 он отказал `[-] FAIL: 198.18.0.3 is an address of
/// this host (route via Ethernet 2)`: флаг MIB строки 198.18.0.3/32 (широковещательный адрес /30) делал её локальной.
#[test]
fn guest_n2_w06_preflight_detects_ethernet_2_through_the_broadcast_row() {
    let g = guest_n2();
    let t = n2_targets(&[(ip(198, 18, 0, 2), ip(198, 18, 0, 3))]).unwrap();
    assert_eq!(
        (t.first, t.last, t.single),
        (ip(198, 18, 0, 2), ip(198, 18, 0, 3), false)
    );
    let d = detect_offline(&t, &Overrides::default(), &g, &g).unwrap_or_else(|e| panic!("[-] {e}"));
    assert_eq!(
        (d.iface.name.as_str(), d.iface_source),
        ("Ethernet 2", Source::Detected)
    );
    assert_eq!(d.iface.device_id, format!("\\Device\\NPF_{N2_LAB_GUID}"));
    assert_eq!(d.source_ipv4, (ip(198, 18, 0, 1), Source::Detected));
    assert_eq!(d.source_mac, (N2_LAB_MAC, Source::Detected));
    assert_eq!(
        d.next_hop,
        NextHop::Mac([0x66, 0x55, 0x44, 0x33, 0x22, 0x11], Source::Given)
    );
    assert_eq!(g.lookups(), [ip(198, 18, 0, 2), ip(198, 18, 0, 3)]);
}

/// Живой w06: та же пара целей без `--offline`. Обе идут on-link через «Ethernet 2» без шлюза, а маршрут по умолчанию
/// есть только у «Ethernet», поэтому отказ `NoGateway` с подсказками маршрутизатора C, как требует таблица случаев.
#[test]
fn guest_n2_w06_live_refuses_no_gateway_on_ethernet_2() {
    let g = guest_n2();
    let t = n2_targets(&[(ip(198, 18, 0, 2), ip(198, 18, 0, 3))]).unwrap();
    let e = detect(&t, &Overrides::default(), &g, &g).unwrap_err();
    assert_eq!(
        e,
        DetectError::NoGateway {
            ifname: "Ethernet 2".into()
        },
        "[-] {e}"
    );
    assert_eq!(
        e.to_string(),
        "FAIL: no default gateway on interface \"Ethernet 2\" for several on-link targets\n    \
         [hint] try \"--router-ip 192.0.2.1\" to specify different router\n    \
         [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP\n    \
         [hint] try \"--interface eth0\" to change interface"
    );
}

/// Одна цель 198.18.0.3 (широковещательный адрес /30) теперь on-link: следующий хоп это сама цель (ARP к ней, как на
/// Linux). Адрес адаптера 198.18.0.1 остаётся `LocalTarget`, и цель, чей лучший маршрут идёт через интерфейс IfType 24,
/// тоже, без флага MIB на строке.
#[test]
fn guest_n2_single_broadcast_target_is_on_link_own_and_loopback_routed_targets_are_local() {
    let one = |a: Ipv4Addr| n2_targets(&[(a, a)]).unwrap();
    let g = guest_n2();
    let d = detect(&one(ip(198, 18, 0, 3)), &Overrides::default(), &g, &g)
        .unwrap_or_else(|e| panic!("[-] {e}"));
    assert_eq!(d.iface.name, "Ethernet 2");
    assert_eq!(
        d.next_hop,
        NextHop::Resolve {
            ip: ip(198, 18, 0, 3),
            why: NextHopWhy::OnLinkTarget,
        }
    );

    for offline in [false, true] {
        let g = guest_n2();
        let t = one(ip(198, 18, 0, 1));
        let r = if offline {
            detect_offline(&t, &Overrides::default(), &g, &g)
        } else {
            detect(&t, &Overrides::default(), &g, &g)
        };
        let e = r.unwrap_err();
        assert_eq!(
            e,
            DetectError::LocalTarget {
                ip: ip(198, 18, 0, 1),
                ifname: "Ethernet 2".into(),
                with_adapter: false,
            },
            "offline {offline}"
        );
        assert_eq!(
            e.to_string(),
            "FAIL: 198.18.0.1 is an address of this host (route via Ethernet 2)\n    \
             [hint] try \"--interface ethX\" and \"--router-ip 192.0.2.1\""
        );
    }

    let mut g = guest_n2();
    g.rows.push(n2_row(
        ip(192, 0, 2, 0),
        24,
        N2_LO,
        Ipv4Addr::UNSPECIFIED,
        256,
        false,
    ));
    let e = detect(&one(ip(192, 0, 2, 7)), &Overrides::default(), &g, &g).unwrap_err();
    assert_eq!(
        e,
        DetectError::LocalTarget {
            ip: ip(192, 0, 2, 7),
            ifname: "Loopback Pseudo-Interface 1".into(),
            with_adapter: false,
        }
    );
}

/// 224.0.0.0/4 и 255.255.255.255 гостя (строки «Ethernet 2» с флагом MIB) не становятся целями-пробами, как и до PF3:
/// таблица их не ищет.
#[test]
fn guest_n2_multicast_and_limited_broadcast_stay_out_of_probe_targets() {
    let bcast = ip(255, 255, 255, 255);
    let mcast = ip(224, 0, 0, 1);
    assert_eq!(
        n2_targets(&[(ip(224, 0, 0, 0), ip(239, 255, 255, 255))]),
        None
    );
    assert_eq!(n2_targets(&[(bcast, bcast)]), None);
    assert_eq!(n2_targets(&[(mcast, mcast), (bcast, bcast)]), None);
    let t = n2_targets(&[
        (mcast, mcast),
        (ip(198, 18, 0, 2), ip(198, 18, 0, 2)),
        (bcast, bcast),
    ])
    .unwrap();
    assert_eq!(
        t,
        Targets {
            first: ip(198, 18, 0, 2),
            last: ip(198, 18, 0, 2),
            single: true,
        }
    );
    let g = guest_n2();
    let d = detect(&t, &Overrides::default(), &g, &g).unwrap();
    assert_eq!(
        d.next_hop,
        NextHop::Resolve {
            ip: ip(198, 18, 0, 2),
            why: NextHopWhy::OnLinkTarget,
        }
    );
    assert_eq!(g.lookups(), [ip(198, 18, 0, 2)]);
}

#[cfg(windows)]
#[test]
fn if_type_constants_match_windows_sys() {
    use windows_sys::Win32::NetworkManagement::IpHelper as h;
    assert_eq!(IF_TYPE_ETHERNET_CSMACD, h::IF_TYPE_ETHERNET_CSMACD);
    assert_eq!(IF_TYPE_SOFTWARE_LOOPBACK, h::IF_TYPE_SOFTWARE_LOOPBACK);
    assert_eq!(IF_TYPE_IEEE80211, h::IF_TYPE_IEEE80211);
}
