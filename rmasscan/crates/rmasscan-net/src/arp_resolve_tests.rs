use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use rmasscan_core::arp::{ArpOp, decode, encode_reply, encode_request};
use rmasscan_core::probe::AdapterBinding;
use rmasscan_engine::fake::{FakeAdapter, ManualClock, TxStep};

use super::*;

const MY_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 1];
const MY_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const ROUTER: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
const ROUTER_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 2];

fn setup() -> (FakeAdapter, Arc<ManualClock>) {
    let clock = ManualClock::new();
    (FakeAdapter::new().with_clock(clock.clone()), clock)
}

/// Ответчик: отвечает `encode_reply` на запрос "who has ROUTER".
fn answer_router(fake: &FakeAdapter) {
    fake.set_responder(|frame| {
        let Ok(p) = decode(frame) else { return vec![] };
        if p.op == ArpOp::Request && p.target_ip == u32::from(ROUTER) {
            vec![encode_reply(ROUTER_MAC, u32::from(ROUTER), p.sender_mac, p.sender_ip).to_vec()]
        } else {
            vec![]
        }
    });
}

fn run(fake: &FakeAdapter, clock: &Arc<ManualClock>) -> Result<ArpReport, ArpResolveError> {
    let mut io = fake.pair();
    resolve_next_hop(
        &mut io,
        "veth-a",
        MY_MAC,
        MY_IP,
        ROUTER,
        NextHopKind::Router,
        &ArpPolicy::default(),
        &**clock,
    )
}

#[test]
fn reply_resolves_after_one_request_and_counts_it() {
    let (fake, clock) = setup();
    answer_router(&fake);
    let r = run(&fake, &clock).unwrap();
    assert_eq!(r.mac, ROUTER_MAC);
    assert_eq!(r.requests_sent, 1);
    assert!(r.elapsed < Duration::from_secs(1));
    assert_eq!(fake.sent_count(), 1);
}

#[test]
fn no_reply_times_out_with_exactly_ten_requests() {
    let (fake, clock) = setup();
    let t0 = clock.now_micros();
    let e = run(&fake, &clock).unwrap_err();
    match e {
        ArpResolveError::Timeout {
            ifname,
            target,
            kind,
            requests_sent,
        } => {
            assert_eq!(ifname, "veth-a");
            assert_eq!(target, ROUTER);
            assert_eq!(kind, NextHopKind::Router);
            assert_eq!(requests_sent, 10);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(fake.sent_count(), 10);
    assert_eq!(clock.now_micros() - t0, 10_000_000);
}

#[test]
fn timeout_report_elapsed_is_ten_seconds_on_success_path_too() {
    // Ответ приходит после 3-го запроса (t = 2 с): elapsed >= 2 с, requests_sent == 3.
    let (fake, clock) = setup();
    let mut n = 0;
    fake.set_responder(move |frame| {
        n += 1;
        if n < 3 {
            return vec![];
        }
        let p = decode(frame).unwrap();
        vec![encode_reply(ROUTER_MAC, u32::from(ROUTER), p.sender_mac, p.sender_ip).to_vec()]
    });
    let r = run(&fake, &clock).unwrap();
    assert_eq!(r.requests_sent, 3);
    assert_eq!(r.elapsed, Duration::from_secs(2));
}

#[test]
fn request_bytes_equal_the_core_encoder_and_go_to_broadcast() {
    let (fake, clock) = setup();
    answer_router(&fake);
    run(&fake, &clock).unwrap();
    let frames = fake.sent_frames();
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0],
        encode_request(MY_MAC, u32::from(MY_IP), u32::from(ROUTER)).to_vec()
    );
    assert_eq!(frames[0].len(), 60);
    assert_eq!(&frames[0][0..6], &[0xff; 6]);
}

#[test]
fn gratuitous_and_unsolicited_arp_are_ignored() {
    let (fake, clock) = setup();
    fake.set_responder(|_| {
        vec![
            // Gratuitous: ответ от роутера самому себе.
            encode_reply(ROUTER_MAC, u32::from(ROUTER), ROUTER_MAC, u32::from(ROUTER)).to_vec(),
            // Чужой запрос от роутера в эфире.
            encode_request(ROUTER_MAC, u32::from(ROUTER), u32::from(MY_IP)).to_vec(),
            // Мусор.
            vec![0u8; 5],
        ]
    });
    let e = run(&fake, &clock).unwrap_err();
    assert!(matches!(
        e,
        ArpResolveError::Timeout {
            requests_sent: 10,
            ..
        }
    ));
}

#[test]
fn reply_from_another_ip_or_to_another_mac_is_ignored() {
    let (fake, clock) = setup();
    let other_ip = u32::from(Ipv4Addr::new(198, 18, 0, 3));
    fake.set_responder(move |_| {
        vec![
            // Ответ от другого IP.
            encode_reply(ROUTER_MAC, other_ip, MY_MAC, u32::from(MY_IP)).to_vec(),
            // Ответ другому MAC.
            encode_reply(
                ROUTER_MAC,
                u32::from(ROUTER),
                [0x02, 0xbb, 0, 0, 0, 9],
                u32::from(MY_IP),
            )
            .to_vec(),
            // Ответ другому IP получателя.
            encode_reply(ROUTER_MAC, u32::from(ROUTER), MY_MAC, other_ip).to_vec(),
        ]
    });
    let e = run(&fake, &clock).unwrap_err();
    assert!(matches!(
        e,
        ArpResolveError::Timeout {
            requests_sent: 10,
            ..
        }
    ));
}

#[test]
fn multicast_sender_mac_is_ignored() {
    let (fake, clock) = setup();
    let mcast = [0x01, 0x00, 0x5e, 0, 0, 1];
    fake.set_responder(move |_| {
        vec![encode_reply(mcast, u32::from(ROUTER), MY_MAC, u32::from(MY_IP)).to_vec()]
    });
    let e = run(&fake, &clock).unwrap_err();
    assert!(matches!(
        e,
        ArpResolveError::Timeout {
            requests_sent: 10,
            ..
        }
    ));
}

#[test]
fn would_block_retries_without_double_counting() {
    let (fake, clock) = setup();
    answer_router(&fake);
    fake.script_tx([TxStep::WouldBlockUnsent, TxStep::WouldBlockUnsent]);
    let r = run(&fake, &clock).unwrap();
    assert_eq!(r.requests_sent, 1);
    assert_eq!(fake.send_calls(), 3);
    assert_eq!(fake.sent_count(), 1);
    assert_eq!(clock.sleep_calls(), 2);

    // Без ответа: блокировки не добавляют запросов сверх расписания.
    let (fake, clock) = setup();
    fake.script_tx([TxStep::WouldBlockUnsent, TxStep::WouldBlockUnsent]);
    let e = run(&fake, &clock).unwrap_err();
    assert!(matches!(
        e,
        ArpResolveError::Timeout {
            requests_sent: 10,
            ..
        }
    ));
    assert_eq!(fake.sent_count(), 10);
}

#[test]
fn uncertain_send_fails_without_retry() {
    let (fake, clock) = setup();
    fake.script_tx([TxStep::Uncertain]);
    let e = run(&fake, &clock).unwrap_err();
    assert_eq!(e, ArpResolveError::Uncertain);
    assert_eq!(fake.send_calls(), 1);
}

#[test]
fn io_error_fails() {
    let (fake, clock) = setup();
    fake.script_tx([TxStep::Fail("boom".into())]);
    let e = run(&fake, &clock).unwrap_err();
    match &e {
        ArpResolveError::Io(io) => assert_eq!(io.message, "boom"),
        other => panic!("{other:?}"),
    }
    assert_eq!(fake.send_calls(), 1);
    assert!(e.to_string().starts_with("FAIL: "));

    // Ошибка приёма тоже отказ.
    let (fake, clock) = setup();
    fake.push_rx(rmasscan_engine::fake::RxStep::Fail("rxboom".into()));
    let e = run(&fake, &clock).unwrap_err();
    assert!(matches!(e, ArpResolveError::Io(_)));
}

#[test]
fn only_the_target_ip_is_ever_requested() {
    let (fake, clock) = setup();
    run(&fake, &clock).unwrap_err();
    let frames = fake.sent_frames();
    assert_eq!(frames.len(), 10);
    for f in &frames {
        let p = decode(f).unwrap();
        assert_eq!(p.op, ArpOp::Request);
        assert_eq!(p.target_ip, u32::from(ROUTER));
        assert_eq!(p.sender_ip, u32::from(MY_IP));
        assert_eq!(p.eth_src, MY_MAC);
    }
}

#[test]
fn arp_binding_uses_the_broadcast_next_hop() {
    let b: AdapterBinding = arp_binding("veth-a", MY_IP, MY_MAC, (40000, 40015));
    assert_eq!(b.interface_id, "veth-a");
    assert_eq!(b.source_ipv4, u32::from(MY_IP));
    assert_eq!(b.source_mac, MY_MAC);
    assert_eq!(b.next_hop_mac, [0xff; 6]);
    assert_eq!(b.source_ports, (40000, 40015));
    assert_eq!(b.link_type, rmasscan_core::packet::LinkType::Ethernet);
}

#[test]
fn timeout_text_names_router_or_target_and_three_hints() {
    let mk = |kind| ArpResolveError::Timeout {
        ifname: "eth0".into(),
        target: ROUTER,
        kind,
        requests_sent: 10,
    };
    assert_eq!(
        mk(NextHopKind::Router).to_string(),
        "FAIL: ARP timed-out resolving MAC address for router eth0: \"198.18.0.2\"\n    [hint] try \"--router-ip 192.0.2.1\" to specify different router\n    [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP\n    [hint] try \"--interface eth0\" to change interface"
    );
    let t = mk(NextHopKind::Target).to_string();
    assert!(t.starts_with(
        "FAIL: ARP timed-out resolving MAC address for next hop (target) eth0: \"198.18.0.2\"\n"
    ));
    assert_eq!(t.matches("[hint]").count(), 3);
    assert!(ArpResolveError::Uncertain.to_string().starts_with("FAIL: "));
}
