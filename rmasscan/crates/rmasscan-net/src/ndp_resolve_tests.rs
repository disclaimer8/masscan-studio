use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;

use rmasscan_core::ndp::{
    decode_neighbor_solicitation, encode_neighbor_advertisement, encode_neighbor_solicitation,
};
use rmasscan_engine::fake::{FakeAdapter, ManualClock, RxStep, TxStep};

use super::*;

const MY_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 1];
const MY_IP: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
const ROUTER: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
const ROUTER_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 2];

fn setup() -> (FakeAdapter, Arc<ManualClock>) {
    let clock = ManualClock::new();
    (FakeAdapter::new().with_clock(clock.clone()), clock)
}

fn na(target: Ipv6Addr, mac: [u8; 6]) -> Vec<u8> {
    encode_neighbor_advertisement(mac, u128::from(target), MY_MAC, u128::from(MY_IP)).to_vec()
}

/// Ответчик: на NS "кто имеет ROUTER" отвечает NA с `ROUTER_MAC`.
fn answer_router(fake: &FakeAdapter) {
    fake.set_responder(|frame| match decode_neighbor_solicitation(frame) {
        Ok(ns) if ns.target == u128::from(ROUTER) => vec![na(ROUTER, ROUTER_MAC)],
        _ => vec![],
    });
}

fn run(fake: &FakeAdapter, clock: &Arc<ManualClock>) -> Result<NdpReport, NdpResolveError> {
    let mut io = fake.pair();
    resolve_next_hop_v6(
        &mut io,
        "veth-a",
        MY_MAC,
        MY_IP,
        ROUTER,
        NextHopKind::Router,
        &NdpPolicy::default(),
        &**clock,
    )
}

fn run_until(
    fake: &FakeAdapter,
    clock: &Arc<ManualClock>,
    mut interrupted: impl FnMut() -> bool,
) -> Result<Option<NdpReport>, NdpResolveError> {
    let mut io = fake.pair();
    resolve_next_hop_v6_until(
        &mut io,
        "veth-a",
        MY_MAC,
        MY_IP,
        ROUTER,
        NextHopKind::Router,
        &NdpPolicy::default(),
        &**clock,
        &mut interrupted,
    )
}

fn is_timeout(e: &NdpResolveError, sent: u32) -> bool {
    matches!(e, NdpResolveError::NdpTimeout { requests_sent, .. } if *requests_sent == sent)
}

#[test]
fn advertisement_resolves_after_one_solicitation() {
    let (fake, clock) = setup();
    answer_router(&fake);
    let r = run(&fake, &clock).unwrap();
    assert_eq!(r.mac, ROUTER_MAC);
    assert_eq!(r.requests_sent, 1);
    assert!(r.elapsed < Duration::from_secs(1));
    assert_eq!(fake.sent_count(), 1);
}

#[test]
fn solicitation_bytes_equal_the_core_encoder_and_go_to_solicited_node() {
    let (fake, clock) = setup();
    answer_router(&fake);
    run(&fake, &clock).unwrap();
    let frames = fake.sent_frames();
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0],
        encode_neighbor_solicitation(MY_MAC, u128::from(MY_IP), u128::from(ROUTER)).to_vec()
    );
    assert_eq!(frames[0].len(), 86);
    assert_eq!(&frames[0][0..6], &[0x33, 0x33, 0xff, 0, 0, 2]);
}

#[test]
fn no_reply_times_out_with_exactly_ten_solicitations() {
    let (fake, clock) = setup();
    let t0 = clock.now_micros();
    let e = run(&fake, &clock).unwrap_err();
    match &e {
        NdpResolveError::NdpTimeout {
            ifname,
            target,
            kind,
            requests_sent,
        } => {
            assert_eq!(ifname, "veth-a");
            assert_eq!(*target, ROUTER);
            assert_eq!(*kind, NextHopKind::Router);
            assert_eq!(*requests_sent, 10);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(fake.sent_count(), 10);
    assert_eq!(clock.now_micros() - t0, 10_000_000);
    assert!(e.to_string().starts_with("FAIL: NDP timed-out"));
}

#[test]
fn late_reply_reports_requests_and_elapsed() {
    let (fake, clock) = setup();
    let mut n = 0;
    fake.set_responder(move |_| {
        n += 1;
        if n < 3 {
            vec![]
        } else {
            vec![na(ROUTER, ROUTER_MAC)]
        }
    });
    let r = run(&fake, &clock).unwrap();
    assert_eq!(r.requests_sent, 3);
    assert_eq!(r.elapsed, Duration::from_secs(2));
}

/// RFC 4861 §7.1.2: NA с hop limit != 255, чужой целью, чужим получателем, без опции и с multicast MAC не годятся.
#[test]
fn invalid_or_foreign_advertisements_are_ignored() {
    let (fake, clock) = setup();
    let mut low_hop = na(ROUTER, ROUTER_MAC);
    low_hop[21] = 64;
    // Сумма пересчитана независимо: отбрасывается именно hop limit, а не сумма.
    let sum = {
        let mut sum: u32 = 0;
        let mut b: Vec<u8> = low_hop[22..54].to_vec();
        b.extend_from_slice(&32u32.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 58]);
        let mut icmp = low_hop[54..].to_vec();
        icmp[2] = 0;
        icmp[3] = 0;
        b.extend_from_slice(&icmp);
        for w in b.chunks(2) {
            sum += u32::from(u16::from_be_bytes([w[0], w[1]]));
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    };
    low_hop[56..58].copy_from_slice(&sum.to_be_bytes());
    let other = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3);
    let frames = vec![
        low_hop,
        na(other, ROUTER_MAC),
        na(ROUTER, [0x33, 0x33, 0, 0, 0, 1]),
        // NS соседа в эфире.
        encode_neighbor_solicitation(ROUTER_MAC, u128::from(ROUTER), u128::from(MY_IP)).to_vec(),
        vec![0u8; 5],
    ];
    fake.set_responder(move |_| frames.clone());
    let e = run(&fake, &clock).unwrap_err();
    assert!(is_timeout(&e, 10), "{e:?}");
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
}

#[test]
fn uncertain_and_io_errors_fail_without_retry() {
    let (fake, clock) = setup();
    fake.script_tx([TxStep::Uncertain]);
    assert_eq!(run(&fake, &clock).unwrap_err(), NdpResolveError::Uncertain);
    assert_eq!(fake.send_calls(), 1);

    let (fake, clock) = setup();
    fake.script_tx([TxStep::Fail("boom".into())]);
    let e = run(&fake, &clock).unwrap_err();
    assert!(matches!(&e, NdpResolveError::Io(io) if io.message == "boom"));
    assert!(e.to_string().starts_with("FAIL: "));

    let (fake, clock) = setup();
    fake.push_rx(RxStep::Fail("rxboom".into()));
    assert!(matches!(
        run(&fake, &clock).unwrap_err(),
        NdpResolveError::Io(_)
    ));
}

/// Review Focus 4: молчание соседа укладывается в `timeout` (`NdpTimeout`, текст с подсказками), а Ctrl-C даёт
/// `Ok(None)` сразу, без новых кадров и без ожидания остатка таймаута. C `main.c:1131-1154` (как у ARP).
#[test]
fn ndp_timeout_and_interrupt_abort_cleanly() {
    // Тишина: ровно policy.timeout по часам и NdpTimeout.
    let (fake, clock) = setup();
    let t0 = clock.now_micros();
    let e = run_until(&fake, &clock, || false).unwrap_err();
    assert!(is_timeout(&e, 10), "{e:?}");
    assert_eq!(clock.now_micros() - t0, 10_000_000);
    assert_eq!(
        e.to_string(),
        "FAIL: NDP timed-out resolving MAC address for router veth-a: \"fd00::2\"\n    [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass NDP\n    [hint] try \"--interface eth0\" to change interface"
    );
    // Цель как next hop (target).
    let t = NdpResolveError::NdpTimeout {
        ifname: "eth0".into(),
        target: ROUTER,
        kind: NextHopKind::Target,
        requests_sent: 10,
    };
    assert!(t.to_string().starts_with(
        "FAIL: NDP timed-out resolving MAC address for next hop (target) eth0: \"fd00::2\"\n"
    ));

    // Прерывание до первого кадра: ни кадра, ни секунды часов.
    let (fake, clock) = setup();
    let t0 = clock.now_micros();
    assert_eq!(run_until(&fake, &clock, || true).unwrap(), None);
    assert_eq!(fake.sent_count(), 0);
    assert_eq!(clock.now_micros(), t0);

    // Прерывание посреди молчания: Ok(None) намного раньше таймаута.
    let (fake, clock) = setup();
    let t0 = clock.now_micros();
    let mut polls = 0;
    let r = run_until(&fake, &clock, || {
        polls += 1;
        polls > 2
    })
    .unwrap();
    assert_eq!(r, None);
    assert!(fake.sent_count() <= 2);
    assert!(clock.now_micros() - t0 < 10_000_000);

    // Без прерывания ведёт себя как resolve_next_hop_v6.
    let (fake, clock) = setup();
    answer_router(&fake);
    let r = run_until(&fake, &clock, || false).unwrap().unwrap();
    assert_eq!((r.mac, r.requests_sent), (ROUTER_MAC, 1));
}

#[test]
fn only_the_target_is_ever_solicited() {
    let (fake, clock) = setup();
    run(&fake, &clock).unwrap_err();
    for f in fake.sent_frames() {
        let ns = decode_neighbor_solicitation(&f).unwrap();
        assert_eq!(ns.target, u128::from(ROUTER));
        assert_eq!(ns.src_ip, u128::from(MY_IP));
        assert_eq!(ns.eth_src, MY_MAC);
    }
}
