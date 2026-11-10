//! UDP (`U:`) через engine на фиктивном адаптере: передача кадров с нагрузкой и без неё, приём датаграмм и ICMP Port
//! Unreachable `3/3`, dedup по протоколу (AGPL-3.0). Только офлайн.

mod common;

use common::*;
use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{AdapterBinding, NicBinding, ReadyPlan};
use rmasscan_core::receive::{PortStatus, Reply};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_engine::fake::{
    FakeAdapter, ManualClock, port_unreachable_for, reply_to_syn, reply_to_udp,
    reply_to_udp_from_port,
};

fn udp_plan(ports: &str) -> ReadyPlan {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), "10.0.0.0/29").unwrap();
    parse_ports(m.ports_mut(), ports).unwrap();
    let cfg = ScanConfig {
        targets: m,
        seed: SEED,
        max_rate: 1_000_000.0,
        wait_secs: 3,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).unwrap();
    ReadyPlan::new_cli(
        eff,
        vec![NicBinding::from(AdapterBinding {
            interface_id: "fake0".into(),
            link_type: LinkType::Ethernet,
            source_ipv4: IP_ME,
            source_mac: [0, 0x11, 0x22, 0x33, 0x44, 0x55],
            next_hop_mac: [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            source_ports: (40000, 40015),
        })],
    )
    .unwrap()
}

fn is_udp(f: &[u8]) -> bool {
    f.len() >= 42 && f[23] == 17
}

fn dport(f: &[u8]) -> u16 {
    u16::from_be_bytes([f[36], f[37]])
}

fn run(
    ports: &str,
    responder: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
) -> (Vec<Reply>, FakeAdapter, u64) {
    let p = udp_plan(ports);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    fake.set_responder(responder);
    let h = start_manual(&p, &fake, &clock, opts());
    let events = drain_to_finished(&h);
    let out = h.join().unwrap();
    (all_replies(&events), fake, out.progress.duplicates)
}

#[test]
fn udp_scan_sends_payload_frames_and_reports_open_and_closed() {
    // 53 (DNS, 73 байта) отвечает датаграммой, 59999 (без записи, 42 байта) отвечает ICMP Port Unreachable.
    let (replies, fake, dups) = run("U:53,U:59999", |f| {
        if !is_udp(f) {
            return vec![];
        }
        match dport(f) {
            53 => reply_to_udp(f, b"dns-answer").into_iter().collect(),
            _ => port_unreachable_for(f, 0x0a00_00fe).into_iter().collect(),
        }
    });
    let sent = fake.sent_frames();
    assert_eq!(sent.len(), 16);
    assert!(sent.iter().all(|f| is_udp(f)));
    assert_eq!(
        sent.iter()
            .filter(|f| dport(f) == 53 && f.len() == 73)
            .count(),
        8
    );
    assert_eq!(
        sent.iter()
            .filter(|f| dport(f) == 59999 && f.len() == 42)
            .count(),
        8
    );
    assert_eq!(dups, 0);
    assert_eq!(replies.len(), 16);
    let open: Vec<_> = replies
        .iter()
        .filter(|r| r.status == PortStatus::Open)
        .collect();
    let closed: Vec<_> = replies
        .iter()
        .filter(|r| r.status == PortStatus::Closed)
        .collect();
    assert_eq!((open.len(), closed.len()), (8, 8));
    for r in open {
        assert_eq!(
            (r.remote_port, r.ip_proto, r.tcp_flags, r.ttl, r.mac),
            (53, 17, 0, 64, None)
        );
    }
    for r in closed {
        // Closed от ICMP 3/3: внутренний протокол 17, порт цитаты, TTL внешнего пакета (маршрутизатор: 250)
        assert_eq!(
            (r.remote_port, r.ip_proto, r.tcp_flags, r.ttl, r.mac),
            (59999, 17, 0, 250, None)
        );
    }
}

#[test]
fn tcp_and_udp_on_the_same_port_do_not_suppress_each_other() {
    // `-p80,U:80`: SYN-ACK с 80/tcp и датаграмма с 80/udp от одного хоста; обе записи доходят, дублей нет.
    let (replies, fake, dups) = run("80,U:80", |f| {
        if is_udp(f) {
            reply_to_udp(f, b"x").into_iter().collect()
        } else {
            reply_to_syn(f, 0x12).into_iter().collect()
        }
    });
    assert_eq!(fake.sent_count(), 16);
    assert_eq!(dups, 0);
    assert_eq!(replies.iter().filter(|r| r.ip_proto == 6).count(), 8);
    assert_eq!(replies.iter().filter(|r| r.ip_proto == 17).count(), 8);
    // Один и тот же ответ дважды: второй глушится.
    let (replies, _, dups) = run("U:53", |f| {
        let r = reply_to_udp(f, b"x");
        vec![r.clone(), r].into_iter().flatten().collect()
    });
    assert_eq!((replies.len(), dups), (8, 8));
}

#[test]
fn udp_replies_from_unscanned_ports_are_discarded() {
    // Рядом с настоящим ответом тот же хост отвечает с порта 54 (верные суммы): цели плана `U:54` не содержат.
    let (replies, _, _) = run("U:53", |f| {
        if !is_udp(f) {
            return vec![];
        }
        [
            reply_to_udp(f, b"x"),
            reply_to_udp_from_port(f, Some(54), b"x"),
        ]
        .into_iter()
        .flatten()
        .collect()
    });
    assert_eq!(replies.len(), 8);
    assert!(replies.iter().all(|r| r.remote_port == 53));
}
