//! Дифференциальные тесты страховки native-рефакторинга ядра (AGPL-3.0, порт masscan © Robert David Graham):
//! код ядра сравнивается с эталонными копиями базы `a275ea9e` из `tests/common/reference.rs`. Ни ожидаемые значения,
//! ни копии не правятся, чтобы тест прошёл: расхождение значит ошибку в рефакторинге (или в копии, тогда она не
//! дословна).
//!
//! Failure persistence как в `tests/proptest_order.rs`: регрессии пишутся в
//! `tests/proptest-regressions/native_reference.txt`; файл появляется только при падении и коммитится вместе с
//! исправлением.

#[path = "common/reference.rs"]
mod reference;

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use reference::{
    RefBlackRock, RefIcmpEcho, RefSctp, RefTcpSyn, RefUdp, ref_icmp_echo_cookie,
    ref_ip_header_checksum, ref_siphash24, ref_syn_cookie_ipv4, ref_syn_cookie_ipv6,
};
use rmasscan_core::blackrock::BlackRock;
use rmasscan_core::checksum::ip_header_checksum;
use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::cookie::{icmp_echo_cookie, siphash24, syn_cookie_ipv4, syn_cookie_ipv6};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::{
    IcmpEchoTemplate, LinkType, PacketModifiers, SctpTemplate, TcpHeaderOptions, TcpSynTemplate,
    UdpTemplate,
};
use rmasscan_core::payloads::{PayloadEntry, PayloadTable};
use rmasscan_core::probe::{AdapterBinding, NicBinding, ProbeCursor, ReadyPlan};
use rmasscan_core::targets::{
    TEMPL_ICMP_ECHO, TEMPL_SCTP, TEMPL_SCTP_LAST, TEMPL_UDP, TEMPL_UDP_LAST, parse_ports,
};
use std::sync::Arc;

fn cfg(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/proptest-regressions/native_reference.txt"
        )))),
        ..ProptestConfig::default()
    }
}

fn link_of(i: u8) -> LinkType {
    match i % 3 {
        0 => LinkType::Ethernet,
        1 => LinkType::Null,
        _ => LinkType::Raw,
    }
}

// ---------------------------------------------------------------------
// BlackRock
// ---------------------------------------------------------------------

fn blackrock_range() -> impl Strategy<Value = u64> {
    prop_oneof![
        1u64..=64,
        1u64..=(1u64 << 40),
        Just((1u64 << 63) - 1),
        Just(290_112u64),
        Just(1_000_003u64),
    ]
}

proptest! {
    #![proptest_config(cfg(2048))]

    #[test]
    fn blackrock_matches_reference(
        range in blackrock_range(),
        seed in any::<u64>(),
        rounds in 0u32..=63,
        pick in any::<u64>(),
    ) {
        let m = pick % range;
        let br = BlackRock::new(range, seed, rounds);
        let rf = RefBlackRock::new(range, seed, rounds);
        prop_assert_eq!(br.domain(), rf.domain());
        let s = br.shuffle(m);
        prop_assert_eq!(s, rf.shuffle(m));
        prop_assert_eq!(br.unshuffle(m), rf.unshuffle(m));
        prop_assert_eq!(br.unshuffle(s), m);
        prop_assert_eq!(rf.unshuffle(rf.shuffle(m)), m);
    }
}

/// Направленный случай для ветки `tmp <= rr` в `unencrypt` (`(rr - tmp) % modulus`): на случайных входах она почти не
/// достигается, потому что `read` почти всегда даёт значение выше `rr`. Параметры найдены перебором: при `rounds = 1`
/// и `range = 2^62` байты 4..7 индекса S-box попадают на нулевые элементы `SBOX[31]`/`SBOX[39]`, и `read` не выше
/// `2^32`; `rr = a - 1`, `l = m / a` подобран так, что `read(1, l) <= rr` (проверено временной
/// инструментацией ветки). Значения `m` такие, что `m % a == a - 1`.
#[test]
fn blackrock_unencrypt_tmp_le_rr_branch_matches_reference() {
    const RANGE: u64 = 1 << 62;
    const SEED: u64 = 0xbda1_bda1_b499_225d;
    for m in [
        36_028_799_132_893_181u64,
        180_143_987_074_531_325,
        288_230_378_030_759_933,
        360_287_972_001_579_005,
    ] {
        let br = BlackRock::new(RANGE, SEED, 1);
        let rf = RefBlackRock::new(RANGE, SEED, 1);
        assert!(m < RANGE);
        let s = br.shuffle(m);
        assert_eq!(s, rf.shuffle(m), "shuffle {m}");
        assert_eq!(br.unshuffle(m), rf.unshuffle(m), "unshuffle {m}");
        assert_eq!(br.unshuffle(s), m, "round trip {m}");
        assert_eq!(rf.unshuffle(rf.shuffle(m)), m, "reference round trip {m}");
    }
}

// ---------------------------------------------------------------------
// ip_header_checksum
// ---------------------------------------------------------------------

proptest! {
    #![proptest_config(cfg(8192))]

    #[test]
    fn ip_header_checksum_matches_reference(
        mut buf in prop::collection::vec(any::<u8>(), 0..=80),
        offset in 0usize..=90,
        max in 0usize..=100,
        force_v4 in any::<bool>(),
    ) {
        // В половине случаев байт `offset` получает вид `0x4?` (версия 4, любой IHL).
        if force_v4 && offset < buf.len() {
            buf[offset] = 0x40 | (buf[offset] & 0x0F);
        }
        prop_assert_eq!(
            ip_header_checksum(&buf, offset, max),
            ref_ip_header_checksum(&buf, offset, max)
        );
    }
}

/// Review Focus 5: границы IHL, `max` и буфера: всё равно эталону.
#[test]
fn ip_header_checksum_edge_cases() {
    let fill = |n: usize| -> Vec<u8> { (0..n).map(|i| (i * 37 + 11) as u8).collect() };
    let check = |buf: &[u8], offset: usize, max: usize| {
        assert_eq!(
            ip_header_checksum(buf, offset, max),
            ref_ip_header_checksum(buf, offset, max),
            "len {} offset {offset} max {max}",
            buf.len()
        );
    };
    for offset in [0usize, 1, 14, 20] {
        // IHL 5 при `max` = offset+19, +1, +20, +21 (буфер ровно по заголовку и с запасом).
        for len in [offset + 20, offset + 21, offset + 40] {
            let mut buf = fill(len);
            buf[offset] = 0x45;
            for max in [offset + 19, offset + 1, offset + 20, offset + 21] {
                check(&buf, offset, max);
            }
        }
        // IHL 15 на буфере 30 байт.
        let mut buf = fill(30);
        if offset < buf.len() {
            buf[offset] = 0x4F;
        }
        for max in [
            0usize,
            offset,
            offset + 1,
            offset + 59,
            offset + 60,
            30,
            100,
        ] {
            check(&buf, offset, max);
        }
        // IHL 0.
        let mut buf = fill(40);
        buf[offset] = 0x40;
        for max in [0usize, offset, offset + 1, 40, 100] {
            check(&buf, offset, max);
        }
    }
    // offset >= len.
    let buf = fill(20);
    for offset in [20usize, 21, 40, 90] {
        for max in [0usize, offset, offset + 20, 100] {
            check(&buf, offset, max);
        }
    }
    check(&[], 0, 0);
    check(&[], 0, 100);
    // max меньше offset.
    let mut buf = fill(60);
    buf[14] = 0x45;
    for max in [0usize, 3, 13, 14] {
        check(&buf, 14, max);
    }
}

// ---------------------------------------------------------------------
// TCP SYN
// ---------------------------------------------------------------------

proptest! {
    #![proptest_config(cfg(4096))]

    #[test]
    fn tcp_syn_matches_reference(
        ip_them in any::<u32>(),
        port_them in any::<u16>(),
        ip_me in any::<u32>(),
        port_me in any::<u16>(),
        seqno in any::<u32>(),
        source_mac in any::<[u8; 6]>(),
        router_mac in any::<[u8; 6]>(),
        link in any::<u8>(),
        ttl in any::<u8>(),
        badsum in any::<bool>(),
        mss in any::<Option<u16>>(),
        sackok in any::<bool>(),
        wscale in any::<Option<u8>>(),
        tsecho in any::<Option<u32>>(),
        junk in prop::collection::vec(any::<u8>(), 0..=8),
    ) {
        let link = link_of(link);
        let mods = PacketModifiers {
            ttl,
            badsum,
            tcp: TcpHeaderOptions { mss, sackok, wscale, tsecho },
        };
        let t = TcpSynTemplate::new_with_options(source_mac, router_mac, link, &mods);
        let r = RefTcpSyn::new(source_mac, router_mac, link, &mods);
        // `out` приходит не пустым: `build_syn` обязан его очистить.
        let mut out = junk;
        t.build_syn(ip_them, port_them, ip_me, port_me, seqno, &mut out);
        prop_assert_eq!(out, r.build_syn(ip_them, port_them, ip_me, port_me, seqno));
    }
}

// ---------------------------------------------------------------------
// ICMP, UDP, SCTP
// ---------------------------------------------------------------------

const BUILTIN_PORTS: [u16; 9] = [53, 111, 123, 137, 161, 500, 2049, 5683, 11211];

fn builtin() -> &'static PayloadTable {
    static T: std::sync::OnceLock<PayloadTable> = std::sync::OnceLock::new();
    T.get_or_init(PayloadTable::builtin)
}

proptest! {
    #![proptest_config(cfg(4096))]

    #[test]
    fn ipv4_probe_builders_match_reference(
        ip_them in any::<u32>(),
        port_them in any::<u16>(),
        ip_me in any::<u32>(),
        port_me in any::<u16>(),
        seqno in any::<u32>(),
        entropy in any::<u64>(),
        source_mac in any::<[u8; 6]>(),
        router_mac in any::<[u8; 6]>(),
        link in any::<u8>(),
        ttl in any::<u8>(),
        // 0 - без нагрузки, 1..=9 - встроенные записи, 10 - своя запись без мутатора.
        payload_kind in 0usize..=10,
        custom in prop::collection::vec(any::<u8>(), 0..=1472),
        custom_source_port in any::<u32>(),
        junk in prop::collection::vec(any::<u8>(), 0..=8),
    ) {
        let link = link_of(link);

        // ICMP Echo.
        let t = IcmpEchoTemplate::new(source_mac, router_mac, link, ttl);
        let r = RefIcmpEcho::new(source_mac, router_mac, link, ttl);
        let mut out = junk.clone();
        t.build_echo(ip_them, ip_me, seqno, entropy, &mut out);
        prop_assert_eq!(out, r.build_echo(ip_them, ip_me, seqno, entropy));

        // UDP.
        let entry: Option<PayloadEntry> = match payload_kind {
            0 => None,
            1..=9 => Some(
                builtin()
                    .get(BUILTIN_PORTS[payload_kind - 1])
                    .expect("встроенная запись")
                    .clone(),
            ),
            _ => Some(PayloadEntry {
                payload: Arc::from(custom),
                source_port: custom_source_port,
                set_cookie: None,
            }),
        };
        let t = UdpTemplate::new(source_mac, router_mac, link, ttl);
        let r = RefUdp::new(source_mac, router_mac, link, ttl);
        let mut out = junk.clone();
        t.build_udp((ip_them, port_them), (ip_me, port_me), seqno, entry.as_ref(), &mut out);
        prop_assert_eq!(
            out,
            r.build_udp((ip_them, port_them), (ip_me, port_me), seqno, entry.as_ref())
        );

        // SCTP INIT.
        let t = SctpTemplate::new(source_mac, router_mac, link, ttl);
        let r = RefSctp::new(source_mac, router_mac, link, ttl);
        let mut out = junk;
        t.build_init((ip_them, port_them), (ip_me, port_me), seqno, &mut out);
        prop_assert_eq!(out, r.build_init((ip_them, port_them), (ip_me, port_me), seqno));
    }
}

/// Полная длина IP у UDP зависит от нагрузки, поэтому в сумме заголовка она отдельное слагаемое (у TCP, ICMP и SCTP
/// длина постоянна). Своя запись без мутатора каждой длины 0..=1472 (кадр Ethernet до 1514 байт) на трёх каналах:
/// кадр равен эталону базы, адреса, порты и `seqno` меняются от длины к длине.
#[test]
fn udp_length_term_covers_every_payload_length() {
    const MAC_ME: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAC_NH: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
    let mut out = Vec::new();
    for (link, ttl) in [
        (LinkType::Ethernet, 255u8),
        (LinkType::Null, 64),
        (LinkType::Raw, 1),
    ] {
        let t = UdpTemplate::new(MAC_ME, MAC_NH, link, ttl);
        let r = RefUdp::new(MAC_ME, MAC_NH, link, ttl);
        for len in 0..=1472usize {
            let k = len as u32;
            let entry = PayloadEntry {
                payload: (0..len).map(|i| (i * 131 + len) as u8).collect(),
                source_port: k,
                set_cookie: None,
            };
            let them = (0xc633_6400 ^ k.wrapping_mul(0x9e37_79b9), (k * 7) as u16);
            let me = (0x0aff_0001 + (k & 0xff), 40000 + (k % 16) as u16);
            let seqno = k.wrapping_mul(0x85eb_ca6b);
            t.build_udp(them, me, seqno, Some(&entry), &mut out);
            assert_eq!(
                out,
                r.build_udp(them, me, seqno, Some(&entry)),
                "{link:?}, payload {len}"
            );
        }
    }
}

// ---------------------------------------------------------------------
// SipHash и cookie
// ---------------------------------------------------------------------

proptest! {
    #![proptest_config(cfg(4096))]

    #[test]
    fn siphash_and_cookies_match_reference(
        data in prop::collection::vec(any::<u8>(), 0..=64),
        k0 in any::<u64>(),
        k1 in any::<u64>(),
        ip_them in any::<u32>(),
        port_them in any::<u32>(),
        ip_me in any::<u32>(),
        port_me in any::<u32>(),
        ip6_them in any::<u128>(),
        ip6_me in any::<u128>(),
        entropy in any::<u64>(),
    ) {
        prop_assert_eq!(siphash24(&data, k0, k1), ref_siphash24(&data, k0, k1));
        prop_assert_eq!(
            syn_cookie_ipv4(ip_them, port_them, ip_me, port_me, entropy),
            ref_syn_cookie_ipv4(ip_them, port_them, ip_me, port_me, entropy)
        );
        prop_assert_eq!(
            syn_cookie_ipv6(ip6_them, port_them, ip6_me, port_me, entropy),
            ref_syn_cookie_ipv6(ip6_them, port_them, ip6_me, port_me, entropy)
        );
        prop_assert_eq!(
            icmp_echo_cookie(ip_them, ip_me, entropy),
            ref_icmp_echo_cookie(ip_them, ip_me, entropy)
        );
    }
}

// ---------------------------------------------------------------------
// ProbeCursor: повторное использование буферов кадров (Review Focus 4)
// ---------------------------------------------------------------------

/// Review Focus 4: смесь TCP, UDP с нагрузкой и без, SCTP и ICMP Echo (кадры 58, 42+DNS, 42+SNMP, 42, 66, 90 байт) при
/// переиспользовании буферов: кадр каждого зонда равен кадру эталонного построителя в свежий `Vec` по полям этого же
/// зонда, а короткий кадр не несёт хвоста предыдущего длинного.
#[test]
fn recycled_buffers_leave_no_stale_tail() {
    const SEED: u64 = 42;
    const MAC_ME: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAC_NH: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
    let mut m = MassIp::new();
    m.add_target_string("198.18.0.0/28").unwrap();
    parse_ports(m.ports_mut(), "80,U:53,U:161,U:9999,S:2905,I:0").unwrap();
    let e = validate(
        &ScanConfig {
            targets: m,
            seed: SEED,
            ..ScanConfig::default()
        },
        Operation::Scan,
    )
    .unwrap();
    let mods = e.packet_modifiers();
    let nic = NicBinding::from(AdapterBinding {
        interface_id: "test0".to_string(),
        link_type: LinkType::Ethernet,
        source_ipv4: 0x0aff_0001,
        source_mac: MAC_ME,
        next_hop_mac: MAC_NH,
        source_ports: (40000, 40000),
    });
    let plan = ReadyPlan::new_cli(e, vec![nic]).unwrap();
    let tcp = RefTcpSyn::new(MAC_ME, MAC_NH, LinkType::Ethernet, &mods);
    let udp = RefUdp::new(MAC_ME, MAC_NH, LinkType::Ethernet, mods.ttl);
    let sctp = RefSctp::new(MAC_ME, MAC_NH, LinkType::Ethernet, mods.ttl);
    let icmp = RefIcmpEcho::new(MAC_ME, MAC_NH, LinkType::Ethernet, mods.ttl);

    let mut lens = std::collections::BTreeSet::new();
    let mut checked = 0usize;
    for batch in [3usize, 64] {
        let mut cur = ProbeCursor::new(&plan, 0).unwrap();
        loop {
            let probes = cur.preload(batch).to_vec();
            if probes.is_empty() {
                break;
            }
            for p in &probes {
                let (ip_them, ip_me) = (p.ip_them, p.ip_me);
                let (port_them, port_me) = (p.port_them, p.port_me);
                let want = match p.port_index {
                    TEMPL_UDP..=TEMPL_UDP_LAST => udp.build_udp(
                        (ip_them, port_them),
                        (ip_me, port_me),
                        p.seqno,
                        builtin().get(port_them),
                    ),
                    TEMPL_SCTP..=TEMPL_SCTP_LAST => {
                        sctp.build_init((ip_them, port_them), (ip_me, port_me), p.seqno)
                    }
                    TEMPL_ICMP_ECHO => icmp.build_echo(ip_them, ip_me, p.seqno, SEED),
                    _ => tcp.build_syn(ip_them, port_them, ip_me, port_me, p.seqno),
                };
                assert_eq!(
                    p.frame, want,
                    "batch {batch}, index {}, port_index {}",
                    p.index, p.port_index
                );
                lens.insert(p.frame.len());
                checked += 1;
            }
            let n = probes.len();
            cur.advance_sent_n(n);
        }
    }
    assert_eq!(checked, 2 * 16 * 6);
    // Шесть видов кадров разной длины: без них тест не проверил бы хвосты.
    assert!(lens.len() >= 5, "{lens:?}");
}
