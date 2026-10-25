//! RX-парсер и ARP-кодек на враждебном входе (AGPL-3.0, masscan © Robert David
//! Graham). Кадры строятся здесь независимо от парсера (своя сумма RFC 1071),
//! cookie берётся из `syn_cookie_ipv4` и из `ProbeCursor`.

use proptest::prelude::*;
use rmasscan_core::arp::{
    ARP_FRAME_LEN, ArpError, ArpOp, PendingResolve, decode, encode_reply, encode_request,
};
use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::cookie::syn_cookie_ipv4;
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::{LinkType, TcpSynTemplate};
use rmasscan_core::probe::{AdapterBinding, ProbeCursor, ReadyPlan};
use rmasscan_core::receive::{
    ChecksumPolicy, MAX_FRAME_LEN, ParseError, PortStatus, Unsupported, link_type_from_dlt,
    parse_reply, parse_reply_with,
};
use rmasscan_core::targets::{add_target_string, parse_ports};

const IP_ME: u32 = 0x0aff_0001;
const IP_THEM: u32 = 0x0a00_0005;
const PORT_THEM: u16 = 80;
const FIRST: u16 = 40000;
const LAST: u16 = 40015;
const PORT_ME: u16 = 40007;
const SEED: u64 = 0x1234_5678_9abc;
const MAC_ME: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_NH: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

fn plan_for(link: LinkType) -> ReadyPlan {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), "10.0.0.0/29").unwrap();
    parse_ports(m.ports_mut(), "80,443").unwrap();
    let cfg = ScanConfig {
        targets: m,
        seed: SEED,
        max_rate: 100.0,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).unwrap();
    ReadyPlan::new(
        eff,
        AdapterBinding {
            interface_id: "t0".into(),
            link_type: link,
            source_ipv4: IP_ME,
            source_mac: MAC_ME,
            next_hop_mac: MAC_NH,
            source_ports: (FIRST, LAST),
        },
    )
    .unwrap()
}

fn cookie(ip_them: u32, port_them: u16, ip_me: u32, port_me: u16) -> u32 {
    syn_cookie_ipv4(
        ip_them,
        u32::from(port_them),
        ip_me,
        u32::from(port_me),
        SEED,
    ) as u32
}

fn rfc1071(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let all: Vec<u8> = parts.concat();
    for c in all.chunks(2) {
        sum += u32::from(c[0]) << 8 | u32::from(*c.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Описание входящего кадра; поля можно портить до сборки.
#[derive(Clone)]
struct Spec {
    ip_them: u32,
    port_them: u16,
    ip_me: u32,
    port_me: u16,
    ack: u32,
    flags: u8,
    proto: u8,
    ttl: u8,
    ip_options: Vec<u8>,
    tcp_options: Vec<u8>,
}

impl Spec {
    fn synack() -> Spec {
        Spec {
            ip_them: IP_THEM,
            port_them: PORT_THEM,
            ip_me: IP_ME,
            port_me: PORT_ME,
            ack: cookie(IP_THEM, PORT_THEM, IP_ME, PORT_ME).wrapping_add(1),
            flags: 0x12,
            proto: 6,
            ttl: 57,
            ip_options: vec![],
            tcp_options: vec![],
        }
    }
    fn with_flags(mut self, f: u8) -> Spec {
        self.flags = f;
        self
    }

    /// IP + TCP без канального заголовка, с верными суммами.
    fn ip_packet(&self) -> Vec<u8> {
        let ihl = 5 + self.ip_options.len() / 4;
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&self.port_them.to_be_bytes());
        tcp[2..4].copy_from_slice(&self.port_me.to_be_bytes());
        tcp[4..8].copy_from_slice(&0x0badf00du32.to_be_bytes());
        tcp[8..12].copy_from_slice(&self.ack.to_be_bytes());
        tcp[12] = ((5 + self.tcp_options.len() / 4) as u8) << 4;
        tcp[13] = self.flags;
        tcp[14..16].copy_from_slice(&1024u16.to_be_bytes());
        tcp.extend_from_slice(&self.tcp_options);
        let mut ip = vec![0u8; 20];
        ip[0] = 0x40 | ihl as u8;
        ip[2..4].copy_from_slice(&((ihl * 4 + tcp.len()) as u16).to_be_bytes());
        ip[8] = self.ttl;
        ip[9] = self.proto;
        ip[12..16].copy_from_slice(&self.ip_them.to_be_bytes());
        ip[16..20].copy_from_slice(&self.ip_me.to_be_bytes());
        ip.extend_from_slice(&self.ip_options);
        let x = rfc1071(&[&ip]);
        ip[10..12].copy_from_slice(&x.to_be_bytes());
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&self.ip_them.to_be_bytes());
        pseudo.extend_from_slice(&self.ip_me.to_be_bytes());
        pseudo.extend_from_slice(&[0, self.proto]);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        let x = rfc1071(&[&pseudo, &tcp]);
        tcp[16..18].copy_from_slice(&x.to_be_bytes());
        ip.extend_from_slice(&tcp);
        ip
    }

    fn frame(&self, link: LinkType) -> Vec<u8> {
        wrap(link, &self.ip_packet())
    }
}

fn wrap(link: LinkType, ip: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    match link {
        LinkType::Ethernet => {
            f.extend_from_slice(&MAC_ME);
            f.extend_from_slice(&MAC_NH);
            f.extend_from_slice(&[0x08, 0x00]);
        }
        LinkType::Null => f.extend_from_slice(&2u32.to_ne_bytes()),
        LinkType::Raw => {}
    }
    f.extend_from_slice(ip);
    f
}

const LINKS: [LinkType; 3] = [LinkType::Ethernet, LinkType::Null, LinkType::Raw];

/// Смещение IP-заголовка в кадре.
fn ip_off(link: LinkType) -> usize {
    match link {
        LinkType::Ethernet => 14,
        LinkType::Null => 4,
        LinkType::Raw => 0,
    }
}

fn parse(f: &[u8], link: LinkType) -> Result<Option<rmasscan_core::receive::Reply>, ParseError> {
    parse_reply(f, link, &plan_for(link))
}

// ---------- RED: приём и отказ ----------

#[test]
fn synack_is_open_on_every_link_type() {
    for link in LINKS {
        let r = parse(&Spec::synack().frame(link), link).unwrap().unwrap();
        assert_eq!(r.status, PortStatus::Open, "{link:?}");
        assert_eq!(
            (r.remote_ip, r.remote_port, r.local_ip, r.local_port),
            (IP_THEM, PORT_THEM, IP_ME, PORT_ME)
        );
        assert_eq!((r.tcp_flags, r.ttl), (0x12, 57));
    }
}

#[test]
fn rst_with_valid_cookie_is_closed() {
    // main.c:1054: любой RST, cookie сверяется с ackno.
    for flags in [0x14u8, 0x04, 0x16, 0x17] {
        let r = parse(
            &Spec::synack().with_flags(flags).frame(LinkType::Ethernet),
            LinkType::Ethernet,
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.status, PortStatus::Closed, "flags {flags:#x}");
        assert_eq!(r.tcp_flags, flags);
    }
}

#[test]
fn rst_without_matching_ackno_is_not_a_reply() {
    // RST без ACK несёт ackno 0: cookie не совпадает (main.c:1059).
    let mut s = Spec::synack().with_flags(0x04);
    s.ack = 0;
    assert_eq!(
        parse(&s.frame(LinkType::Ethernet), LinkType::Ethernet),
        Ok(None)
    );
}

#[test]
fn wrong_ack_wrong_tuple_wrong_destination_yield_none() {
    let base = Spec::synack();
    let mut cases: Vec<(&str, Spec)> = Vec::new();
    for (name, d) in [
        ("ack=cookie+2", 2u32),
        ("ack=cookie-1", u32::MAX),
        ("ack=cookie", 0),
        ("ack=cookie+2^31", 0x8000_0000),
    ] {
        let mut s = base.clone();
        s.ack = cookie(IP_THEM, PORT_THEM, IP_ME, PORT_ME).wrapping_add(d);
        cases.push((name, s));
    }
    let mut s = base.clone();
    s.ip_them ^= 1;
    cases.push(("other remote ip (cookie for original)", s));
    let mut s = base.clone();
    s.port_them = 81;
    cases.push(("other remote port", s));
    let mut s = base.clone();
    s.port_me = PORT_ME - 1;
    cases.push(("other local port in range (cookie for original)", s));
    let mut s = base.clone();
    s.ip_me = IP_ME + 1;
    cases.push(("other local ip", s));
    for (port, name) in [
        (FIRST - 1, "below range"),
        (LAST + 1, "above range"),
        (0, "port 0"),
    ] {
        let mut s = base.clone();
        s.port_me = port;
        s.ack = cookie(IP_THEM, PORT_THEM, IP_ME, port).wrapping_add(1);
        cases.push((name, s));
    }
    // ack=cookie без +1 это as is в `cases` с d=0: все должны быть None.
    for (name, s) in cases {
        assert_eq!(
            parse(&s.frame(LinkType::Ethernet), LinkType::Ethernet),
            Ok(None),
            "{name}"
        );
    }
}

#[test]
fn range_edges_are_inclusive() {
    for port in [FIRST, LAST] {
        let mut s = Spec::synack();
        s.port_me = port;
        s.ack = cookie(IP_THEM, PORT_THEM, IP_ME, port).wrapping_add(1);
        assert!(
            parse(&s.frame(LinkType::Raw), LinkType::Raw)
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn non_synack_non_rst_flags_yield_none() {
    for flags in [
        0x00u8,
        0x01,
        0x02,
        0x10,
        0x11,
        0x18,
        0x29,
        0x3f & !0x04 & !0x12,
    ] {
        let f = Spec::synack().with_flags(flags).frame(LinkType::Ethernet);
        assert_eq!(parse(&f, LinkType::Ethernet), Ok(None), "flags {flags:#x}");
    }
}

#[test]
fn own_transmitted_syn_yields_none() {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), "10.0.0.0/29").unwrap();
    parse_ports(m.ports_mut(), "80").unwrap();
    for link in LINKS {
        let plan = plan_for(link);
        let tmpl = TcpSynTemplate::new(MAC_ME, MAC_NH, link);
        let seq = cookie(IP_THEM, 80, IP_ME, PORT_ME);
        let mut f = Vec::new();
        tmpl.build_syn(IP_THEM, 80, IP_ME, PORT_ME, seq, &mut f);
        assert_eq!(parse_reply(&f, link, &plan), Ok(None), "{link:?}");
    }
}

#[test]
fn udp_icmp_and_other_protocols_yield_none() {
    for proto in [17u8, 1, 132, 2, 0, 255] {
        let mut s = Spec::synack();
        s.proto = proto;
        for link in LINKS {
            assert_eq!(parse(&s.frame(link), link), Ok(None), "proto {proto}");
        }
    }
}

#[test]
fn arp_and_ipv6_ethertype_yield_none() {
    for et in [[0x08u8, 0x06], [0x86, 0xdd], [0x88, 0x47], [0x05, 0xdc]] {
        let mut f = Spec::synack().frame(LinkType::Ethernet);
        f[12..14].copy_from_slice(&et);
        assert_eq!(parse(&f, LinkType::Ethernet), Ok(None));
    }
    // RAW и NULL с IPv6.
    let mut f = Spec::synack().frame(LinkType::Raw);
    f[0] = 0x60;
    assert_eq!(parse(&f, LinkType::Raw), Ok(None));
    let mut f = vec![0x1c, 0, 0, 0];
    f.extend_from_slice(&[0u8; 40]);
    assert_eq!(parse(&f, LinkType::Null), Ok(None));
}

#[test]
fn real_probe_from_cursor_is_answered_by_matching_synack() {
    let plan = plan_for(LinkType::Ethernet);
    let mut cur = ProbeCursor::new(&plan, 0).unwrap();
    let mut seen = 0;
    while let Some(p) = cur.current() {
        let p = p.clone();
        // Собственный SYN не ответ.
        assert_eq!(parse_reply(&p.frame, LinkType::Ethernet, &plan), Ok(None));
        let s = Spec {
            ip_them: p.ip_them,
            port_them: p.port_them,
            ip_me: p.ip_me,
            port_me: p.port_me,
            ack: p.seqno.wrapping_add(1),
            ..Spec::synack()
        };
        let r = parse_reply(&s.frame(LinkType::Ethernet), LinkType::Ethernet, &plan)
            .unwrap()
            .unwrap();
        assert_eq!(
            (r.remote_ip, r.remote_port, r.local_port),
            (p.ip_them, p.port_them, p.port_me)
        );
        assert_eq!(r.status, PortStatus::Open);
        // seqno, а не seqno+2.
        let bad = Spec {
            ack: p.seqno.wrapping_add(2),
            ..s
        };
        assert_eq!(
            parse_reply(&bad.frame(LinkType::Ethernet), LinkType::Ethernet, &plan),
            Ok(None)
        );
        cur.advance_sent();
        seen += 1;
    }
    assert_eq!(seen, plan.range());
}

// ---------- RED: враждебные длины ----------

#[test]
fn every_strict_prefix_of_a_valid_frame_is_an_error_not_a_panic() {
    for link in LINKS {
        for flags in [0x12u8, 0x14] {
            let f = Spec::synack().with_flags(flags).frame(link);
            assert!(parse(&f, link).unwrap().is_some());
            for n in 0..f.len() {
                assert!(parse(&f[..n], link).is_err(), "{link:?} prefix {n}");
            }
        }
    }
}

#[test]
fn every_strict_prefix_with_options_is_an_error() {
    let mut s = Spec::synack();
    s.ip_options = vec![1, 1, 1, 0];
    s.tcp_options = vec![2, 4, 5, 0xb4];
    for link in LINKS {
        let f = s.frame(link);
        assert!(parse(&f, link).unwrap().is_some());
        for n in 0..f.len() {
            assert!(parse(&f[..n], link).is_err(), "{link:?} prefix {n}");
        }
    }
}

#[test]
fn ethernet_padding_after_total_length_is_ignored() {
    let mut f = Spec::synack().frame(LinkType::Ethernet);
    f.resize(60, 0xaa);
    assert!(parse(&f, LinkType::Ethernet).unwrap().is_some());
}

#[test]
fn frame_longer_than_1514_is_rejected() {
    let mut f = Spec::synack().frame(LinkType::Ethernet);
    f.resize(MAX_FRAME_LEN + 1, 0);
    assert_eq!(
        parse(&f, LinkType::Ethernet),
        Err(ParseError::FrameTooLong(MAX_FRAME_LEN + 1))
    );
    f.truncate(MAX_FRAME_LEN);
    assert!(parse(&f, LinkType::Ethernet).unwrap().is_some());
}

#[test]
fn bad_ihl_never_panics_and_small_ihl_is_rejected() {
    for ihl in 0u8..=15 {
        for link in LINKS {
            let mut f = Spec::synack().frame(link);
            let o = ip_off(link);
            f[o] = 0x40 | ihl;
            let r = parse(&f, link);
            match ihl {
                0..=4 => assert_eq!(r, Err(ParseError::BadIpv4HeaderLength(ihl))),
                5 => assert!(r.unwrap().is_some()),
                // IHL больше фактического заголовка: TCP съезжает, но не паника.
                _ => {
                    let _ = r;
                }
            }
        }
    }
}

#[test]
fn ipv4_options_within_ihl_are_skipped() {
    let mut s = Spec::synack();
    s.ip_options = vec![0x94, 0x04, 0, 0, 1, 1, 1, 0];
    for link in LINKS {
        assert!(parse(&s.frame(link), link).unwrap().is_some());
    }
}

#[test]
fn total_length_below_header_or_beyond_frame_is_rejected() {
    for link in LINKS {
        let f0 = Spec::synack().frame(link);
        let o = ip_off(link);
        for total in [0u16, 1, 19, 20, 21, 39, 40, 58, 65535] {
            let mut f = f0.clone();
            f[o + 2..o + 4].copy_from_slice(&total.to_be_bytes());
            let r = parse(&f, link);
            if total == 40 {
                assert!(r.unwrap().is_some());
            } else if total < 20 {
                assert!(
                    matches!(r, Err(ParseError::TotalLengthBelowHeader { .. })),
                    "{total}"
                );
            } else if total > 40 {
                assert!(
                    matches!(r, Err(ParseError::TotalLengthBeyondFrame { .. })),
                    "{total}"
                );
            } else {
                // 20..39: влезает только часть TCP
                assert!(matches!(r, Err(ParseError::Truncated(_))), "{total}: {r:?}");
            }
        }
    }
}

#[test]
fn bad_tcp_data_offset_is_rejected_without_oob() {
    for link in LINKS {
        let o = ip_off(link) + 20;
        for off in 0u8..=15 {
            let mut f = Spec::synack().frame(link);
            f[o + 12] = off << 4 | (f[o + 12] & 0x0f);
            let r = parse(&f, link);
            match off {
                0..=4 => assert_eq!(r, Err(ParseError::BadTcpDataOffset(off))),
                // Заявлены опции, которых нет в сегменте (checksum тоже не сойдётся).
                6..=15 => assert!(matches!(r, Err(ParseError::Truncated(_))), "{off}: {r:?}"),
                _ => {}
            }
        }
    }
}

#[test]
fn tcp_options_with_matching_data_offset_are_accepted() {
    let mut s = Spec::synack();
    s.tcp_options = vec![2, 4, 5, 0xb4, 1, 1, 1, 0];
    for link in LINKS {
        assert!(parse(&s.frame(link), link).unwrap().is_some());
    }
}

#[test]
fn ipv4_fragments_are_rejected() {
    for (name, v) in [
        ("MF", 0x2000u16),
        ("offset 1", 0x0001),
        ("offset max", 0x1fff),
        ("MF+offset", 0x2005),
    ] {
        let mut f = Spec::synack().frame(LinkType::Ethernet);
        f[14 + 6..14 + 8].copy_from_slice(&v.to_be_bytes());
        assert_eq!(
            parse(&f, LinkType::Ethernet),
            Err(ParseError::Fragment),
            "{name}"
        );
    }
    // DF сам по себе фрагментом не является (в C маска 0x3FFF).
    let mut f = Spec::synack().frame(LinkType::Ethernet);
    f[14 + 6..14 + 8].copy_from_slice(&0x4000u16.to_be_bytes());
    let plan = plan_for(LinkType::Ethernet);
    // Сумма заголовка теперь не сходится: смотрим только на фрагментацию.
    let r = parse_reply_with(&f, LinkType::Ethernet, &plan, ChecksumPolicy::TrustHardware);
    assert!(r.unwrap().is_some());
}

#[test]
fn bad_ip_version_is_rejected() {
    for v in [0u8, 1, 3, 5, 6, 15] {
        let mut f = Spec::synack().frame(LinkType::Ethernet);
        f[14] = v << 4 | 5;
        assert_eq!(
            parse(&f, LinkType::Ethernet),
            Err(ParseError::BadIpVersion(v))
        );
    }
}

#[test]
fn vlan_is_never_read_as_ipv4() {
    // Тег 802.1Q перед настоящим IPv4: должен быть Unsupported, не Open.
    let inner = Spec::synack().frame(LinkType::Ethernet);
    for tpid in [[0x81u8, 0x00], [0x88, 0xa8], [0x91, 0x00]] {
        let mut f = inner[..12].to_vec();
        f.extend_from_slice(&tpid);
        f.extend_from_slice(&[0x00, 0x05]); // TCI
        f.extend_from_slice(&inner[12..]); // ethertype 0800 + IP
        assert_eq!(
            parse(&f, LinkType::Ethernet),
            Err(ParseError::Unsupported(Unsupported::Vlan))
        );
    }
    // Даже если "тип" в 12..14 подменён на VLAN у кадра, где дальше нет тела.
    let mut short = vec![0u8; 14];
    short[12..14].copy_from_slice(&[0x81, 0x00]);
    assert_eq!(
        parse(&short, LinkType::Ethernet),
        Err(ParseError::Unsupported(Unsupported::Vlan))
    );
}

#[test]
fn unknown_link_types_and_families() {
    assert_eq!(link_type_from_dlt(0), Ok(LinkType::Null));
    assert_eq!(link_type_from_dlt(1), Ok(LinkType::Ethernet));
    assert_eq!(link_type_from_dlt(12), Ok(LinkType::Raw));
    for dlt in [2u32, 113, 127, 119, 0x69, 228, u32::MAX] {
        assert_eq!(
            link_type_from_dlt(dlt),
            Err(ParseError::UnsupportedLinkType(dlt))
        );
    }
    let mut f = vec![0x55, 0x66, 0x77, 0x88];
    f.extend_from_slice(&Spec::synack().ip_packet());
    assert_eq!(
        parse(&f, LinkType::Null),
        Err(ParseError::UnknownNullFamily(0x5566_7788))
    );
    // Оба порядка байт AF_INET принимаются.
    let mut f = vec![0x02, 0, 0, 0];
    f.extend_from_slice(&Spec::synack().ip_packet());
    assert!(parse(&f, LinkType::Null).unwrap().is_some());
    f[0..4].copy_from_slice(&[0, 0, 0, 2]);
    assert!(parse(&f, LinkType::Null).unwrap().is_some());
    for link in LINKS {
        assert!(parse(&[], link).is_err());
    }
}

// ---------- checksum policy ----------

#[test]
fn checksums_are_verified_by_default_and_policy_is_explicit() {
    for link in LINKS {
        let plan = plan_for(link);
        let o = ip_off(link);
        let good = Spec::synack().frame(link);

        let mut bad_ip = good.clone();
        bad_ip[o + 8] ^= 0x01; // ttl без пересчёта суммы
        assert_eq!(
            parse_reply(&bad_ip, link, &plan),
            Err(ParseError::BadIpChecksum)
        );
        assert_eq!(
            parse_reply_with(&bad_ip, link, &plan, ChecksumPolicy::Verify),
            Err(ParseError::BadIpChecksum)
        );
        assert!(
            parse_reply_with(&bad_ip, link, &plan, ChecksumPolicy::TrustHardware)
                .unwrap()
                .is_some()
        );

        let mut bad_tcp = good.clone();
        bad_tcp[o + 20 + 14] ^= 0x40; // window
        assert_eq!(
            parse_reply(&bad_tcp, link, &plan),
            Err(ParseError::BadTcpChecksum)
        );
        assert!(
            parse_reply_with(&bad_tcp, link, &plan, ChecksumPolicy::TrustHardware)
                .unwrap()
                .is_some()
        );

        // Cookie проверяется при любой политике.
        let mut wrong = Spec::synack();
        wrong.ack = wrong.ack.wrapping_add(7);
        assert_eq!(
            parse_reply_with(
                &wrong.frame(link),
                link,
                &plan,
                ChecksumPolicy::TrustHardware
            ),
            Ok(None)
        );
        assert_eq!(ChecksumPolicy::default(), ChecksumPolicy::Verify);
    }
}

#[test]
fn bad_checksum_on_a_foreign_packet_is_not_an_error() {
    // Суммы проверяются только после совпадения cookie.
    let mut f = Spec::synack().frame(LinkType::Ethernet);
    f[14 + 20 + 8] ^= 0xff; // ackno
    f[14 + 10] ^= 0xff;
    assert_eq!(parse(&f, LinkType::Ethernet), Ok(None));
}

// ---------- property tests ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1600), li in 0usize..3) {
        let link = LINKS[li];
        let plan = plan_for(link);
        for pol in [ChecksumPolicy::Verify, ChecksumPolicy::TrustHardware] {
            let _ = parse_reply_with(&bytes, link, &plan, pol);
        }
    }

    /// Случайные заголовки за валидным Ethernet/IPv4 префиксом: добираются
    /// до TCP-разбора, где живёт большая часть арифметики длин.
    #[test]
    fn random_headers_behind_valid_prefix_never_panic(
        ip in proptest::collection::vec(any::<u8>(), 20..=60),
        tcp in proptest::collection::vec(any::<u8>(), 0..=80),
        ihl in 0u8..16, doff in 0u8..16, total in any::<u16>(), li in 0usize..3,
        fix_total in any::<bool>(), proto6 in any::<bool>(),
    ) {
        let link = LINKS[li];
        let plan = plan_for(link);
        let mut ip = ip;
        ip[0] = 0x40 | ihl;
        if proto6 { ip[9] = 6; }
        ip[6] &= 0x40; ip[7] = 0; // не фрагмент
        ip[16..20].copy_from_slice(&IP_ME.to_be_bytes());
        let mut tcp = tcp;
        tcp.resize(tcp.len().max(14), 0);
        tcp[12] = doff << 4;
        let mut packet = ip;
        packet.extend_from_slice(&tcp);
        let t = if fix_total { packet.len() as u16 } else { total };
        packet[2..4].copy_from_slice(&t.to_be_bytes());
        let f = wrap(link, &packet);
        for pol in [ChecksumPolicy::Verify, ChecksumPolicy::TrustHardware] {
            let _ = parse_reply_with(&f, link, &plan, pol);
        }
    }

    /// Любое принятое равно правилу приёма, независимо пересчитанному.
    #[test]
    fn mutated_valid_frames_only_accept_by_rule(
        muts in proptest::collection::vec((0usize..80, any::<u8>()), 0..4),
        cut in 0usize..80, li in 0usize..3,
    ) {
        let link = LINKS[li];
        let plan = plan_for(link);
        let mut f = Spec::synack().frame(link);
        for (i, b) in muts { if let Some(x) = f.get_mut(i) { *x = b; } }
        f.truncate(f.len().saturating_sub(cut % 3));
        if let Ok(Some(r)) = parse_reply_with(&f, link, &plan, ChecksumPolicy::TrustHardware) {
            prop_assert_eq!(r.local_ip, IP_ME);
            prop_assert!((FIRST..=LAST).contains(&r.local_port));
            let o = ip_off(link) + 20;
            let ack = u32::from_be_bytes(f[o + 8..o + 12].try_into().unwrap());
            prop_assert_eq!(ack.wrapping_sub(1), cookie(r.remote_ip, r.remote_port, r.local_ip, r.local_port));
            prop_assert!(r.tcp_flags & 0x12 == 0x12 || r.tcp_flags & 0x04 != 0);
        }
    }
}

// ---------- ARP ----------

const A_IP_ME: u32 = 0xc0a8_0102;
const A_IP_GW: u32 = 0xc0a8_0101;
const GW_MAC: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];

#[test]
fn arp_request_has_the_c_layout() {
    // stack-arpv4.c:121-160, 60 байт с нулевым дополнением.
    let f = encode_request(MAC_ME, A_IP_ME, A_IP_GW);
    let mut want = vec![0xffu8; 6];
    want.extend_from_slice(&MAC_ME);
    want.extend_from_slice(&[0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 1]);
    want.extend_from_slice(&MAC_ME);
    want.extend_from_slice(&A_IP_ME.to_be_bytes());
    want.extend_from_slice(&[0; 6]);
    want.extend_from_slice(&A_IP_GW.to_be_bytes());
    want.resize(60, 0);
    assert_eq!(f.to_vec(), want);
    let p = decode(&f).unwrap();
    assert_eq!(
        (p.op, p.sender_mac, p.sender_ip, p.target_ip),
        (ArpOp::Request, MAC_ME, A_IP_ME, A_IP_GW)
    );
}

#[test]
fn arp_reply_round_trips_and_resolves() {
    let mut pend = PendingResolve::new(MAC_ME, A_IP_ME, A_IP_GW);
    assert_eq!(
        pend.request_frame(),
        encode_request(MAC_ME, A_IP_ME, A_IP_GW)
    );
    let reply = encode_reply(GW_MAC, A_IP_GW, MAC_ME, A_IP_ME);
    let p = decode(&reply).unwrap();
    assert_eq!(
        (
            p.op,
            p.eth_src,
            p.sender_mac,
            p.sender_ip,
            p.target_mac,
            p.target_ip
        ),
        (ArpOp::Reply, GW_MAC, GW_MAC, A_IP_GW, MAC_ME, A_IP_ME)
    );
    assert_eq!(pend.offer(&reply), Some(GW_MAC));
    assert_eq!(pend.resolved(), Some(GW_MAC));
}

#[test]
fn unsuitable_arp_replies_do_not_resolve() {
    let other_mac = [0x02, 1, 2, 3, 4, 5];
    let mut bad: Vec<(&str, Vec<u8>)> = vec![
        (
            "other sender ip",
            encode_reply(GW_MAC, A_IP_GW + 1, MAC_ME, A_IP_ME).to_vec(),
        ),
        (
            "addressed to other ip",
            encode_reply(GW_MAC, A_IP_GW, MAC_ME, A_IP_ME + 1).to_vec(),
        ),
        (
            "addressed to other mac",
            encode_reply(GW_MAC, A_IP_GW, other_mac, A_IP_ME).to_vec(),
        ),
        (
            "request, not reply",
            encode_request(GW_MAC, A_IP_GW, A_IP_ME).to_vec(),
        ),
        (
            "multicast sender mac",
            encode_reply([0x01, 0, 0x5e, 0, 0, 1], A_IP_GW, MAC_ME, A_IP_ME).to_vec(),
        ),
        (
            "zero sender mac",
            encode_reply([0; 6], A_IP_GW, MAC_ME, A_IP_ME).to_vec(),
        ),
    ];
    let mut spoof = encode_reply(GW_MAC, A_IP_GW, MAC_ME, A_IP_ME).to_vec();
    spoof[6..12].copy_from_slice(&other_mac); // ethernet src != arp sender
    bad.push(("ethernet source differs", spoof));
    for (field, off, val) in [
        ("hw type", 14usize, 6u8),
        ("proto type", 16, 0x86),
        ("hlen", 18, 8),
        ("plen", 19, 16),
        ("opcode", 21, 9),
    ] {
        let mut f = encode_reply(GW_MAC, A_IP_GW, MAC_ME, A_IP_ME).to_vec();
        f[off + usize::from(field == "hw type")] ^= val; // hw type: low byte at 15
        bad.push((field, f));
    }
    let mut vlan = encode_reply(GW_MAC, A_IP_GW, MAC_ME, A_IP_ME).to_vec();
    vlan[12..14].copy_from_slice(&[0x81, 0x00]);
    bad.push(("vlan", vlan));
    let mut pend = PendingResolve::new(MAC_ME, A_IP_ME, A_IP_GW);
    for (name, f) in &bad {
        assert_eq!(pend.offer(f), None, "{name}");
        assert_eq!(pend.resolved(), None, "{name}");
    }
    // Подходящий после мусора всё ещё принимается.
    assert_eq!(
        pend.offer(&encode_reply(GW_MAC, A_IP_GW, MAC_ME, A_IP_ME)),
        Some(GW_MAC)
    );
    // Второй подходящий ответ с другим MAC не перезаписывает.
    let usurper = [0x02, 9, 9, 9, 9, 9];
    assert_eq!(
        pend.offer(&encode_reply(usurper, A_IP_GW, MAC_ME, A_IP_ME)),
        Some(GW_MAC)
    );
}

#[test]
fn arp_fixed_field_errors_are_typed() {
    let good = encode_reply(GW_MAC, A_IP_GW, MAC_ME, A_IP_ME);
    let mut f = good;
    f[15] = 6;
    assert_eq!(decode(&f), Err(ArpError::BadHardwareType(6)));
    let mut f = good;
    f[16] = 0x86;
    assert_eq!(decode(&f), Err(ArpError::BadProtocolType(0x8600)));
    // C пропускает одну неверную длину (&&); здесь нет.
    let mut f = good;
    f[18] = 8;
    assert_eq!(decode(&f), Err(ArpError::BadLengths { hw: 8, proto: 4 }));
    let mut f = good;
    f[19] = 16;
    assert_eq!(decode(&f), Err(ArpError::BadLengths { hw: 6, proto: 16 }));
    let mut f = good;
    f[21] = 3;
    assert_eq!(decode(&f), Err(ArpError::BadOpcode(3)));
    let mut f = good;
    f[12..14].copy_from_slice(&[0x08, 0x00]);
    assert_eq!(decode(&f), Err(ArpError::NotArp(0x0800)));
    let mut f = good;
    f[12..14].copy_from_slice(&[0x81, 0x00]);
    assert_eq!(decode(&f), Err(ArpError::Vlan));
}

#[test]
fn every_truncated_arp_prefix_is_an_error() {
    let f = encode_reply(GW_MAC, A_IP_GW, MAC_ME, A_IP_ME);
    assert_eq!(f.len(), ARP_FRAME_LEN);
    for n in 0..42 {
        assert!(decode(&f[..n]).is_err(), "prefix {n}");
        let mut pend = PendingResolve::new(MAC_ME, A_IP_ME, A_IP_GW);
        assert_eq!(pend.offer(&f[..n]), None);
    }
    assert!(decode(&f[..42]).is_ok());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]
    #[test]
    fn arbitrary_arp_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..120)) {
        let _ = decode(&bytes);
        let mut pend = PendingResolve::new(MAC_ME, A_IP_ME, A_IP_GW);
        let _ = pend.offer(&bytes);
    }

    #[test]
    fn arp_mutations_resolve_only_when_tuple_matches(
        muts in proptest::collection::vec((0usize..60, any::<u8>()), 0..4)
    ) {
        let mut f = encode_reply(GW_MAC, A_IP_GW, MAC_ME, A_IP_ME);
        for (i, b) in muts { f[i] = b; }
        let mut pend = PendingResolve::new(MAC_ME, A_IP_ME, A_IP_GW);
        if let Some(mac) = pend.offer(&f) {
            let p = decode(&f).unwrap();
            prop_assert_eq!((p.op, p.sender_ip, p.target_ip, p.target_mac), (ArpOp::Reply, A_IP_GW, A_IP_ME, MAC_ME));
            prop_assert_eq!(mac, p.sender_mac);
        }
    }
}

// ---------- Фильтр по итоговому набору целей текущего задания ----------

fn plan_with(targets: &str, ports: &str, excl_ips: &str, excl_ports: &str) -> ReadyPlan {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), targets).unwrap();
    parse_ports(m.ports_mut(), ports).unwrap();
    let mut ex = MassIp::new();
    if !excl_ips.is_empty() {
        add_target_string(ex.ipv4_mut(), excl_ips).unwrap();
    }
    if !excl_ports.is_empty() {
        parse_ports(ex.ports_mut(), excl_ports).unwrap();
    }
    let cfg = ScanConfig {
        targets: m,
        excludes: ex,
        seed: SEED,
        max_rate: 100.0,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).unwrap();
    ReadyPlan::new(
        eff,
        AdapterBinding {
            interface_id: "t0".into(),
            link_type: LinkType::Ethernet,
            source_ipv4: IP_ME,
            source_mac: MAC_ME,
            next_hop_mac: MAC_NH,
            source_ports: (FIRST, LAST),
        },
    )
    .unwrap()
}

fn reply_from(
    plan: &ReadyPlan,
    ip: u32,
    port: u16,
    flags: u8,
) -> Result<Option<rmasscan_core::receive::Reply>, ParseError> {
    let mut s = Spec::synack().with_flags(flags);
    s.ip_them = ip;
    s.port_them = port;
    s.ack = cookie(ip, port, IP_ME, PORT_ME).wrapping_add(1);
    parse_reply(&s.frame(LinkType::Ethernet), LinkType::Ethernet, plan)
}

#[test]
fn reject_previous_job_target_with_valid_cookie() {
    // Прошлое задание сканировало 10.0.1.5; текущее только 10.0.0.0/29.
    let plan = plan_for(LinkType::Ethernet);
    assert_eq!(reply_from(&plan, 0x0a00_0105, PORT_THEM, 0x12), Ok(None));
    assert_eq!(reply_from(&plan, 0x0a00_0105, PORT_THEM, 0x04), Ok(None));
}

#[test]
fn reject_previous_job_port_with_valid_cookie() {
    let plan = plan_for(LinkType::Ethernet);
    assert_eq!(reply_from(&plan, IP_THEM, 8080, 0x12), Ok(None));
    assert_eq!(reply_from(&plan, IP_THEM, 8080, 0x04), Ok(None));
}

#[test]
fn reject_excluded_target() {
    let plan = plan_with("10.0.0.0/29", "80,443", "10.0.0.5", "");
    assert_eq!(reply_from(&plan, 0x0a00_0005, 80, 0x12), Ok(None));
    assert!(reply_from(&plan, 0x0a00_0004, 80, 0x12).unwrap().is_some());
    assert!(reply_from(&plan, 0x0a00_0006, 80, 0x12).unwrap().is_some());
}

#[test]
fn reject_excluded_port() {
    let plan = plan_with("10.0.0.0/29", "80,443", "", "443");
    assert_eq!(reply_from(&plan, IP_THEM, 443, 0x12), Ok(None));
    assert!(reply_from(&plan, IP_THEM, 80, 0x12).unwrap().is_some());
}

#[test]
fn target_and_port_range_boundaries_are_inclusive() {
    let plan = plan_with("10.0.0.2-10.0.0.6,10.0.0.20", "80-82,443", "", "");
    for ip in [0x0a00_0002u32, 0x0a00_0006, 0x0a00_0014] {
        for port in [80u16, 82, 443] {
            for flags in [0x12u8, 0x14] {
                assert!(
                    reply_from(&plan, ip, port, flags).unwrap().is_some(),
                    "{ip:#x}:{port}"
                );
            }
        }
    }
    for ip in [
        0x0a00_0001u32,
        0x0a00_0007,
        0x0a00_0013,
        0x0a00_0015,
        0,
        u32::MAX,
    ] {
        assert_eq!(reply_from(&plan, ip, 80, 0x12), Ok(None), "{ip:#x}");
    }
    for port in [0u16, 79, 83, 442, 444, u16::MAX] {
        assert_eq!(
            reply_from(&plan, 0x0a00_0003, port, 0x12),
            Ok(None),
            "{port}"
        );
    }
}

#[test]
fn full_address_space_target_accepts_both_extremes() {
    let plan = plan_with("0.0.0.0/0", "0-65535", "10.0.0.0/8", "");
    assert!(reply_from(&plan, 0, 0, 0x12).unwrap().is_some());
    assert!(
        reply_from(&plan, u32::MAX, u16::MAX, 0x12)
            .unwrap()
            .is_some()
    );
    assert_eq!(reply_from(&plan, 0x0a00_0001, 80, 0x12), Ok(None));
}
