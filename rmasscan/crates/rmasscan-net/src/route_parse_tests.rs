//! Разбор ответов ядра на синтетических байтах (любая ОС). Адреса только из документационных диапазонов, кроме раздела
//! гостя n2: он воспроизводит лабораторный стенд (198.18.0.0/30, RFC 2544) и NIC управления QEMU (10.0.2.0/24) дословно.

use std::net::Ipv4Addr;

use rmasscan_core::massip::MassIp;

use super::*;
use crate::discover::{
    DetectError, Iface, Interfaces, NextHop, NextHopWhy, Overrides, Route, RouteTable, Source,
    Targets, detect, detect_offline, probe_targets,
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
