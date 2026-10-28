use super::*;
use rmasscan_core::arp::{decode, encode_reply};
use rmasscan_engine::fake::{FakeAdapter, ManualClock, TxStep};
use std::sync::{Arc, Mutex};
fn plan(count: u32) -> PhysicalRoutePlan {
    PhysicalRoutePlan {
        interface_name: "en0".into(),
        interface_index: 2,
        source_ipv4: Ipv4Addr::new(192, 168, 1, 10),
        source_mac: Some([2, 1, 2, 3, 4, 5]),
        next_hops: (0..count)
            .map(|n| {
                let ip = Ipv4Addr::from(0x0a000001 + n);
                (ip, ip)
            })
            .collect(),
        excluded: BTreeMap::new(),
    }
}
fn setup() -> (FakeAdapter, Arc<ManualClock>) {
    let c = ManualClock::new();
    (FakeAdapter::new().with_clock(c.clone()), c)
}
#[test]
fn full_1024_hosts_get_three_fair_passes_and_one_second_final_window() {
    let (f, c) = setup();
    let times = Arc::new(Mutex::new(vec![]));
    let ts = times.clone();
    let cc = c.clone();
    f.set_responder(move |frame| {
        ts.lock()
            .unwrap()
            .push((decode(frame).unwrap().target_ip, cc.now_micros()));
        vec![]
    });
    let t0 = c.now_micros();
    let r = resolve_neighbours(&mut f.pair(), &plan(1024), &*c, &|| false).unwrap();
    assert_eq!(r.unresolved_on_link.len(), 1024);
    assert_eq!(r.requests_sent, 3072);
    assert!(r.destinations.is_empty());
    let times = times.lock().unwrap();
    assert!(times.windows(2).all(|p| p[1].1 - p[0].1 >= 10000));
    for i in 0..1024 {
        assert_eq!(times[i].0, times[1024 + i].0);
        assert_eq!(times[i].0, times[2048 + i].0);
        assert!(times[1024 + i].1 - times[i].1 >= 1_000_000);
    }
    assert_eq!(c.now_micros() - times.last().unwrap().1, 1_000_000);
    assert!(c.now_micros() - t0 < 35_000_000);
}
#[test]
fn local_misses_reported_remote_gateway_deduplicated_and_distinct_macs_kept() {
    let (f, c) = setup();
    let mut p = plan(3);
    p.next_hops
        .insert(Ipv4Addr::new(203, 0, 113, 1), Ipv4Addr::from(0x0a000002));
    p.next_hops
        .insert(Ipv4Addr::new(203, 0, 113, 2), Ipv4Addr::from(0x0a000002));
    f.set_responder(|frame| {
        let p = decode(frame).unwrap();
        if p.target_ip == 0x0a000003 {
            return vec![];
        }
        let mac = [2, 0, 0, 0, 1, p.target_ip as u8];
        vec![encode_reply(mac, p.target_ip, p.sender_mac, p.sender_ip).to_vec()]
    });
    let r = resolve_neighbours(&mut f.pair(), &p, &*c, &|| false).unwrap();
    assert_eq!(r.unresolved_on_link, vec![Ipv4Addr::from(0x0a000003)]);
    assert_eq!(r.destinations.len(), 4);
    assert_ne!(
        r.destinations[&Ipv4Addr::from(0x0a000001)],
        r.destinations[&Ipv4Addr::from(0x0a000002)]
    );
    assert_eq!(r.requests_sent, 5);
}
#[test]
fn missing_gateway_fails_whole_preparation() {
    let (f, c) = setup();
    let mut p = plan(1);
    p.next_hops
        .insert(Ipv4Addr::new(203, 0, 113, 1), Ipv4Addr::from(0x0a000001));
    assert!(
        resolve_neighbours(&mut f.pair(), &p, &*c, &|| false)
            .unwrap_err()
            .to_string()
            .contains("gateway")
    );
    assert_eq!(f.sent_count(), 3);
}
#[test]
fn uncertain_cancelled_invalid_and_clock_overflow_never_produce_success() {
    let (f, c) = setup();
    assert!(resolve_neighbours(&mut f.pair(), &plan(1), &*c, &|| true).is_err());
    assert_eq!(f.send_calls(), 0);
    let mut p = plan(1);
    p.source_mac = None;
    assert!(resolve_neighbours(&mut f.pair(), &p, &*c, &|| false).is_err());
    assert_eq!(f.send_calls(), 0);
    f.script_tx([TxStep::Uncertain]);
    assert!(
        resolve_neighbours(&mut f.pair(), &plan(1), &*c, &|| false)
            .unwrap_err()
            .to_string()
            .contains("uncertain")
    );
    assert_eq!(f.send_calls(), 1);
    let (f, c) = setup();
    c.advance_micros(u64::MAX - c.now_micros());
    assert!(resolve_neighbours(&mut f.pair(), &plan(1), &*c, &|| false).is_err());
    assert_eq!(f.send_calls(), 0);
}
#[test]
fn backpressure_not_counted_and_cancellation_checked_between_calls() {
    let (f, c) = setup();
    f.script_tx([TxStep::WouldBlockUnsent, TxStep::WouldBlockUnsent]);
    let r = resolve_neighbours(&mut f.pair(), &plan(1), &*c, &|| false).unwrap();
    assert_eq!(r.requests_sent, 3);
    assert_eq!(f.send_calls(), 5);
    let (f, c) = setup();
    let t = c.now_micros();
    assert!(
        resolve_neighbours(&mut f.pair(), &plan(1024), &*c, &|| c.now_micros()
            >= t + 25_000)
        .is_err()
    );
    assert!(c.now_micros() - t <= 75_000);
    assert!(f.sent_count() < 10);
}
#[test]
fn global_expiry_including_insufficient_final_window_is_error() {
    let (f, c) = setup();
    let cc = c.clone();
    f.set_responder(move |_| {
        cc.advance_micros(20_000);
        vec![]
    });
    assert!(
        resolve_neighbours(&mut f.pair(), &plan(1024), &*c, &|| false)
            .unwrap_err()
            .to_string()
            .contains("deadline")
    );
}
#[test]
fn duplicate_wrong_recipient_and_unsolicited_replies_are_ignored() {
    let (f, c) = setup();
    f.set_responder(|frame| {
        let p = decode(frame).unwrap();
        vec![
            encode_reply([2, 0, 0, 0, 0, 9], 0x0a000099, p.sender_mac, p.sender_ip).to_vec(),
            encode_reply(
                [2, 0, 0, 0, 0, 9],
                p.target_ip,
                [2, 9, 9, 9, 9, 9],
                p.sender_ip,
            )
            .to_vec(),
        ]
    });
    let r = resolve_neighbours(&mut f.pair(), &plan(1), &*c, &|| false).unwrap();
    assert_eq!(r.unresolved_on_link.len(), 1);
    assert_eq!(r.requests_sent, 3);
}
#[test]
fn no_response_classification_waits_for_reply_during_last_second() {
    use rmasscan_engine::{IoError, Rx, RxHealth};
    struct Delayed {
        clock: Arc<ManualClock>,
        at: u64,
        frame: Vec<u8>,
        delivered: bool,
    }
    impl Rx for Delayed {
        fn recv(&mut self, buf: &mut [u8], wait: Duration) -> Result<Option<usize>, IoError> {
            assert!(wait <= Duration::from_millis(50));
            let end = self.clock.now_micros() + wait.as_micros() as u64;
            if !self.delivered && end >= self.at {
                self.clock.advance_micros(self.at - self.clock.now_micros());
                buf[..self.frame.len()].copy_from_slice(&self.frame);
                self.delivered = true;
                Ok(Some(self.frame.len()))
            } else {
                self.clock.advance(wait);
                Ok(None)
            }
        }
        fn health(&mut self, _: Duration) -> Result<RxHealth, IoError> {
            panic!("no TCP coverage claim from ARP health")
        }
    }
    let (f, c) = setup();
    let p = plan(1);
    let start = c.now_micros();
    let mut io = f.pair();
    io.rx = Box::new(Delayed {
        clock: c.clone(),
        at: start + 2_990_000,
        frame: encode_reply(
            [2, 0, 0, 0, 0, 9],
            0x0a000001,
            p.source_mac.unwrap(),
            u32::from(p.source_ipv4),
        )
        .to_vec(),
        delivered: false,
    });
    let r = resolve_neighbours(&mut io, &p, &*c, &|| false).unwrap();
    assert_eq!(r.requests_sent, 3);
    assert_eq!(r.destinations.len(), 1);
    assert!(r.unresolved_on_link.is_empty());
    assert_eq!(r.elapsed, Duration::from_micros(2_990_000));
}
#[test]
fn deadline_before_complete_final_window_aborts_instead_of_reporting_miss() {
    let (f, c) = setup();
    f.script_tx([TxStep::DelayThenSent(32_500_000)]);
    let e = resolve_neighbours(&mut f.pair(), &plan(1), &*c, &|| false).unwrap_err();
    assert!(e.to_string().contains("deadline"));
    assert_eq!(f.sent_count(), 2);
}
#[test]
fn duplicates_cannot_replace_frozen_mac_and_unsent_hop_reply_is_ignored() {
    let (f, c) = setup();
    f.set_responder(|frame| {
        let p = decode(frame).unwrap();
        if p.target_ip == 0x0a000002 {
            return vec![];
        }
        vec![
            encode_reply([2, 0, 0, 0, 1, 1], p.target_ip, p.sender_mac, p.sender_ip).to_vec(),
            encode_reply([2, 0, 0, 0, 1, 2], p.target_ip, p.sender_mac, p.sender_ip).to_vec(),
            encode_reply([2, 0, 0, 0, 1, 3], 0x0a000002, p.sender_mac, p.sender_ip).to_vec(),
        ]
    });
    let r = resolve_neighbours(&mut f.pair(), &plan(2), &*c, &|| false).unwrap();
    assert_eq!(
        r.destinations[&Ipv4Addr::from(0x0a000001)],
        [2, 0, 0, 0, 1, 1]
    );
    assert_eq!(r.unresolved_on_link, vec![Ipv4Addr::from(0x0a000002)]);
    assert_eq!(r.requests_sent, 4);
}
#[test]
fn invalid_public_plans_fail_before_any_adapter_call() {
    for mut p in [plan(0), plan(1025), plan(1), plan(1)] {
        if p.next_hops.len() == 1 {
            p.next_hops.insert(p.source_ipv4, p.source_ipv4);
        }
        let (f, c) = setup();
        assert!(resolve_neighbours(&mut f.pair(), &p, &*c, &|| false).is_err());
        assert_eq!(f.send_calls(), 0);
    }
}
#[test]
fn late_send_near_clock_limit_cannot_wrap_retry_schedule() {
    let (f, c) = setup();
    c.advance_micros(u64::MAX - 35_000_000 - c.now_micros());
    f.script_tx([TxStep::DelayThenSent(34_500_000)]);
    assert!(
        resolve_neighbours(&mut f.pair(), &plan(1), &*c, &|| false)
            .unwrap_err()
            .to_string()
            .contains("deadline")
    );
    assert_eq!(f.sent_count(), 1);
}
