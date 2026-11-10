//! ICMP Echo (`I:0`) через engine на фиктивном адаптере: передача 90-байтных кадров, приём Echo Reply,
//! dedup и смешанный скан `-p80,I:0` (AGPL-3.0). Только офлайн.

mod common;

use common::*;
use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{AdapterBinding, NicBinding, ReadyPlan};
use rmasscan_core::receive::{PortStatus, Reply};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_engine::DedupCache;
use rmasscan_engine::fake::{FakeAdapter, ManualClock, reply_to_echo, reply_to_syn};

fn icmp_plan(ports: &str) -> ReadyPlan {
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

fn is_echo(f: &[u8]) -> bool {
    f.len() == 90 && f[23] == 1 && f[34] == 8
}

fn run(
    ports: &str,
    responder: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
) -> (Vec<Reply>, FakeAdapter, u64) {
    let p = icmp_plan(ports);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    fake.set_responder(responder);
    let h = start_manual(&p, &fake, &clock, opts());
    let events = drain_to_finished(&h);
    let out = h.join().unwrap();
    (all_replies(&events), fake, out.progress.duplicates)
}

#[test]
fn icmp_echo_scan_sends_90_byte_frames_and_reports_open_hosts() {
    let (replies, fake, dups) = run("I:0", |f| reply_to_echo(f, 0).into_iter().collect());
    let sent = fake.sent_frames();
    assert_eq!(sent.len(), 8);
    assert!(
        sent.iter().all(|f| is_echo(f)),
        "all frames are 90-byte Echo Requests"
    );
    assert_eq!(replies.len(), 8);
    assert_eq!(dups, 0);
    for r in &replies {
        assert_eq!(
            (
                r.remote_port,
                r.local_port,
                r.status,
                r.tcp_flags,
                r.ip_proto,
                r.ttl,
                r.mac
            ),
            (0, 0, PortStatus::Open, 0, 1, 64, None)
        );
    }
    // тот же ответ дважды: второй глушится dedup
    let (replies, _, dups) = run("I:0", |f| {
        let r = reply_to_echo(f, 0);
        vec![r.clone(), r].into_iter().flatten().collect()
    });
    assert_eq!((replies.len(), dups), (8, 8));
}

#[test]
fn icmp_echo_reply_with_wrong_cookie_is_discarded() {
    let (replies, _, _) = run("I:0", |f| reply_to_echo(f, 1).into_iter().collect());
    assert!(replies.is_empty(), "{replies:?}");
}

#[test]
fn icmp_and_tcp_replies_do_not_collide_in_the_current_dedup_key() {
    // Смешанный скан: на ту же пару адрес/порт 0 приходит ICMP, на 80 - SYN-ACK; ничего не глушится.
    let (replies, fake, dups) = run("80,I:0", |f| {
        if is_echo(f) {
            reply_to_echo(f, 0).into_iter().collect()
        } else {
            reply_to_syn(f, 0x12).into_iter().collect()
        }
    });
    assert_eq!(fake.sent_count(), 16);
    assert_eq!(dups, 0);
    assert_eq!(replies.iter().filter(|r| r.ip_proto == 1).count(), 8);
    assert_eq!(replies.iter().filter(|r| r.ip_proto == 6).count(), 8);
    // Ключ DedupCache сегодня (remote ip, remote port, local ip, local port): локальный порт TCP всегда из
    // `source_ports` (>= 1), у ICMP он 0, поэтому ICMP и TCP-запись с `remote_port = 0` не сливаются.
    let mut d = DedupCache::new(8);
    let icmp = replies.iter().find(|r| r.ip_proto == 1).unwrap();
    let tcp = Reply {
        remote_ip: icmp.remote_ip,
        remote_port: 0,
        ..*replies.iter().find(|r| r.ip_proto == 6).unwrap()
    };
    assert!(d.insert(icmp) && d.insert(&tcp));
}
