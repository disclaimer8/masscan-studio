//! Authenticated in-memory runner IPC with fake OS/neighbour/packet boundaries.
use super::*;
use crate::guard_tests::{Reader, Writer, pipe};
use crate::network::Environment;
use rmasscan_core::probe::AdapterBinding;
use rmasscan_engine::fake::FakeAdapter;
use rmasscan_net::{NeighbourReport, PhysicalRoutePlan};
use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
};
fn ip(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, n)
}
struct Fake {
    routes: Mutex<PhysicalRoutePlan>,
    resolved: Mutex<BTreeMap<Ipv4Addr, [u8; 6]>>,
    observed: AtomicUsize,
    arp: AtomicUsize,
    opened: AtomicUsize,
    block: AtomicUsize,
    entered: AtomicBool,
    closed: AtomicBool,
    panic: AtomicBool,
    release_open: AtomicBool,
    packet: FakeAdapter,
}
impl Fake {
    fn new() -> Arc<Self> {
        let packet = FakeAdapter::new();
        packet.set_responder(|f| {
            rmasscan_engine::fake::reply_to_syn(f, 0x12)
                .into_iter()
                .collect()
        });
        Arc::new(Self {
            routes: Mutex::new(PhysicalRoutePlan {
                interface_name: "en0".into(),
                interface_index: 1,
                source_ipv4: ip(99),
                source_mac: Some([2, 1, 2, 3, 4, 5]),
                next_hops: [(ip(1), ip(1)), (ip(2), ip(2)), (ip(3), ip(254))].into(),
                excluded: BTreeMap::new(),
            }),
            resolved: Mutex::new([(ip(1), [2, 0, 0, 0, 0, 1]), (ip(3), [2, 0, 0, 0, 0, 3])].into()),
            observed: AtomicUsize::new(0),
            arp: AtomicUsize::new(0),
            opened: AtomicUsize::new(0),
            block: AtomicUsize::new(0),
            entered: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            panic: AtomicBool::new(false),
            release_open: AtomicBool::new(false),
            packet,
        })
    }
    fn wait(&self, stage: usize, cancel: &dyn Fn() -> bool) {
        if self.block.load(Ordering::Acquire) == stage {
            self.entered.store(true, Ordering::Release);
            while !cancel() {
                std::thread::sleep(Duration::from_millis(1));
            }
            self.closed.store(true, Ordering::Release);
            // Deliberately return a stale SUCCESS: owner must discard it after cancellation.
        }
    }
}
impl Environment for Fake {
    fn authorize(&self) -> Result<(), String> {
        Ok(())
    }
    fn observe(
        &self,
        _: &Job,
        _: Instant,
        cancel: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String> {
        self.observed.fetch_add(1, Ordering::AcqRel);
        self.wait(1, cancel);
        Ok(self.routes.lock().unwrap().clone())
    }
    fn neighbours(
        &self,
        p: &PhysicalRoutePlan,
        cancel: &dyn Fn() -> bool,
    ) -> Result<NeighbourReport, String> {
        let _pair = self.packet.pair();
        self.arp.fetch_add(1, Ordering::AcqRel);
        self.wait(2, cancel);
        assert!(
            !self.panic.load(Ordering::Acquire),
            "injected preparation panic"
        );
        let destinations = self
            .resolved
            .lock()
            .unwrap()
            .iter()
            .filter(|(ip, _)| p.next_hops.contains_key(ip))
            .map(|(ip, mac)| (*ip, *mac))
            .collect::<BTreeMap<_, _>>();
        if p.next_hops
            .iter()
            .any(|(ip, hop)| ip != hop && !destinations.contains_key(ip))
        {
            return Err("Gateway did not respond".into());
        }
        Ok(NeighbourReport {
            unresolved_on_link: p
                .next_hops
                .keys()
                .filter(|ip| !destinations.contains_key(ip))
                .copied()
                .collect(),
            destinations,
            requests_sent: 3,
            elapsed: Duration::ZERO,
        })
    }
    fn open(&self, _: &AdapterBinding) -> Result<rmasscan_engine::AdapterPair, String> {
        self.opened.fetch_add(1, Ordering::AcqRel);
        let pair = self.packet.pair();
        if self.block.load(Ordering::Acquire) == 3 {
            self.entered.store(true, Ordering::Release);
            while !self.release_open.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(pair)
    }
}
fn job() -> Job {
    let mut j = Job::example(Backend::MacNetwork);
    j.targets = "10.0.0.1-10.0.0.3".into();
    j.ports = "80".into();
    j
}
struct Harness {
    input: Option<Writer>,
    output: Reader,
    server: Option<JoinHandle<Result<(), String>>>,
    seq: u64,
    attempt: Id,
}
impl Harness {
    fn new(env: Arc<Fake>) -> Self {
        let (mut input, runner_in) = pipe();
        let (runner_out, mut output) = pipe();
        let server = std::thread::spawn(move || {
            serve_with_network(
                Box::new(runner_in),
                Box::new(runner_out),
                Box::new(|| Ok(())),
                raw_adapter,
                env,
            )
        });
        studio_protocol::write_frame(
            &mut input,
            &Envelope::new([1; 16], [0; 16], [0; 16], 1, Command::Hello),
        )
        .unwrap();
        assert!(matches!(
            read_frame::<Event>(&mut output).unwrap().payload,
            Event::Hello { .. }
        ));
        Self {
            input: Some(input),
            output,
            server: Some(server),
            seq: 0,
            attempt: [3; 16],
        }
    }
    fn send(&mut self, cmd: Command) {
        self.seq += 1;
        studio_protocol::write_frame(
            self.input.as_mut().unwrap(),
            &Envelope::new([1; 16], [2; 16], self.attempt, self.seq, cmd),
        )
        .unwrap();
    }
    fn session(&mut self, seq: u64, cmd: Command) {
        studio_protocol::write_frame(
            self.input.as_mut().unwrap(),
            &Envelope::new([1; 16], [0; 16], [0; 16], seq, cmd),
        )
        .unwrap();
    }
    fn event(&mut self) -> Envelope<Event> {
        read_frame(&mut self.output).unwrap()
    }
    fn report(&mut self) -> Envelope<Event> {
        loop {
            let e = self.event();
            match e.payload {
                Event::NetworkPrepared { .. } => return e,
                Event::PreparingNetwork => {}
                other => panic!("unexpected {other:?}"),
            }
        }
    }
    fn finish(&mut self) -> (Status, String) {
        loop {
            match self.event().payload {
                Event::Finished { status, detail } => return (status, detail),
                Event::Checkpoint { .. } => panic!("unexpected pause"),
                _ => {}
            }
        }
    }
    fn disconnect(&mut self) -> Result<(), String> {
        drop(self.input.take());
        self.server.take().unwrap().join().unwrap()
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        drop(self.input.take());
        if let Some(s) = self.server.take() {
            let _ = s.join();
        }
    }
}
fn wait(predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "fake worker did not reach barrier"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}
#[test]
fn lan_and_routed_scan_waits_for_durable_matching_report_ack() {
    let env = Fake::new();
    let mut h = Harness::new(env.clone());
    let j = job();
    h.send(Command::Start(j.clone()));
    let report = h.report();
    assert_eq!(env.opened.load(Ordering::Acquire), 0);
    assert_eq!(env.packet.sent_count(), 0);
    let dir = std::env::temp_dir().join(format!(
        "studio-network-{}",
        studio_protocol::id_text(studio_protocol::new_id().unwrap())
    ));
    let mut store = studio_store::Store::open(&dir).unwrap();
    store.begin([2; 16], [3; 16], &j, false).unwrap();
    // Preparing is the previous authenticated event; reproduce its actual sequence.
    store
        .apply(&Envelope::new(
            [1; 16],
            [2; 16],
            [3; 16],
            1,
            Event::PreparingNetwork,
        ))
        .unwrap();
    store.apply(&report).unwrap();
    h.send(Command::AckNetworkReport {
        through: report.sequence,
    });
    assert_eq!(h.finish().0, Status::Completed);
    let frames = env.packet.sent_frames();
    assert_eq!(frames.len(), 2);
    let macs = frames
        .iter()
        .map(|f| f[..6].to_vec())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(macs.len(), 2);
    assert_eq!(
        store.scans().unwrap().pop().unwrap().network_report,
        match report.payload {
            Event::NetworkPrepared { bytes } => Some(bytes),
            _ => unreachable!(),
        }
    );
    h.disconnect().unwrap();
    drop(store);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn stop_during_observation_or_arp_joins_before_stopped_and_discards_stale_success() {
    for stage in [1, 2] {
        let env = Fake::new();
        env.block.store(stage, Ordering::Release);
        let mut h = Harness::new(env.clone());
        h.send(Command::Start(job()));
        wait(|| env.entered.load(Ordering::Acquire));
        h.send(Command::Stop);
        assert_eq!(h.finish().0, Status::Stopped);
        assert!(env.closed.load(Ordering::Acquire));
        assert_eq!(env.packet.alive_handles(), 0);
        assert_eq!(env.opened.load(Ordering::Acquire), 0);
        assert_eq!(env.packet.sent_count(), 0);
        h.disconnect().unwrap();
    }
}
#[test]
fn close_and_disconnect_join_preparation_workers() {
    for stage in [1, 2] {
        for close in [false, true] {
            let env = Fake::new();
            env.block.store(stage, Ordering::Release);
            let mut h = Harness::new(env.clone());
            h.send(Command::Start(job()));
            wait(|| env.entered.load(Ordering::Acquire));
            if close {
                h.send(Command::CloseSession);
                h.server.take().unwrap().join().unwrap().unwrap();
            } else {
                h.disconnect().unwrap();
            }
            assert!(env.closed.load(Ordering::Acquire));
            assert_eq!(env.packet.sent_count(), 0);
        }
    }
}
#[test]
fn stop_close_disconnect_and_wrong_ack_while_waiting_never_start_tcp() {
    for action in 0..4 {
        let env = Fake::new();
        let mut h = Harness::new(env.clone());
        h.send(Command::Start(job()));
        let report = h.report();
        match action {
            0 => {
                h.send(Command::Stop);
                assert_eq!(h.finish().0, Status::Stopped);
                h.disconnect().unwrap();
            }
            1 => {
                h.send(Command::CloseSession);
                h.server.take().unwrap().join().unwrap().unwrap();
            }
            2 => {
                h.disconnect().unwrap();
            }
            _ => {
                h.send(Command::AckNetworkReport {
                    through: report.sequence + 1,
                });
                assert!(
                    h.server
                        .take()
                        .unwrap()
                        .join()
                        .unwrap()
                        .unwrap_err()
                        .contains("ACK")
                );
            }
        }
        assert_eq!(env.opened.load(Ordering::Acquire), 0);
        assert_eq!(env.packet.sent_count(), 0);
    }
}
#[test]
fn changed_route_after_ack_and_worker_panic_are_failures_without_tcp() {
    for panic in [false, true] {
        let env = Fake::new();
        env.panic.store(panic, Ordering::Release);
        let mut h = Harness::new(env.clone());
        h.send(Command::Start(job()));
        if !panic {
            let report = h.report();
            env.routes.lock().unwrap().next_hops.insert(ip(2), ip(254));
            h.send(Command::AckNetworkReport {
                through: report.sequence,
            });
        }
        let (status, detail) = h.finish();
        assert_eq!(status, Status::Failed);
        assert!(
            detail.contains(if panic { "panicked" } else { "changed" }),
            "{detail}"
        );
        assert_eq!(env.packet.sent_count(), 0);
        h.disconnect().unwrap();
    }
}
#[test]
fn all_unresolved_is_reported_but_gateway_failure_is_not_partial_success() {
    for gateway in [false, true] {
        let env = Fake::new();
        env.resolved.lock().unwrap().clear();
        let mut j = job();
        if !gateway {
            j.targets = "10.0.0.1-10.0.0.2".into();
            env.routes.lock().unwrap().next_hops.remove(&ip(3));
        }
        let mut h = Harness::new(env.clone());
        h.send(Command::Start(j));
        if !gateway {
            let report = h.report();
            h.send(Command::AckNetworkReport {
                through: report.sequence,
            });
        }
        assert_eq!(h.finish().0, Status::Failed);
        assert_eq!(env.packet.sent_count(), 0);
        h.disconnect().unwrap();
    }
}
#[test]
fn job_check_is_read_only_masked_source_allowed_and_close_cancels() {
    let env = Fake::new();
    env.routes.lock().unwrap().source_mac = None;
    let mut h = Harness::new(env.clone());
    let j = job();
    h.session(2, Command::CheckNetworkJob(j.clone()));
    match h.event().payload {
        Event::NetworkPreflight {
            job_digest,
            ready,
            detail,
        } => {
            assert!(ready, "{detail}");
            assert_eq!(job_digest, j.original_digest().unwrap());
            assert!(detail.contains("2 direct, 1 routed"));
        }
        e => panic!("{e:?}"),
    };
    assert_eq!(env.arp.load(Ordering::Acquire), 0);
    assert_eq!(env.opened.load(Ordering::Acquire), 0);
    env.block.store(1, Ordering::Release);
    h.session(3, Command::CheckNetworkJob(j));
    wait(|| env.entered.load(Ordering::Acquire));
    h.session(4, Command::CloseSession);
    h.server.take().unwrap().join().unwrap().unwrap();
    assert!(env.closed.load(Ordering::Acquire));
}

#[test]
fn pause_restart_resume_pins_persisted_report_and_never_adds_formerly_unresolved() {
    let env = Fake::new();
    let mut j = job();
    j.ports = "80-89".into();
    j.rate = 10;
    let directory = std::env::temp_dir().join(format!(
        "studio-network-resume-{}",
        studio_protocol::id_text(studio_protocol::new_id().unwrap())
    ));
    let mut store = studio_store::Store::open(&directory).unwrap();
    store.begin([2; 16], [3; 16], &j, false).unwrap();
    let mut h = Harness::new(env.clone());
    h.send(Command::Start(j.clone()));
    let mut frozen = vec![];
    let mut checkpoint = vec![];
    loop {
        let e = h.event();
        store.apply(&e).unwrap();
        match e.payload {
            Event::NetworkPrepared { bytes } => {
                frozen = bytes;
                h.send(Command::AckNetworkReport {
                    through: e.sequence,
                });
            }
            Event::Started { .. } => {
                wait(|| env.packet.sent_count() > 0);
                h.send(Command::Pause);
            }
            Event::Checkpoint { bytes, .. } => {
                checkpoint = bytes;
                h.send(Command::AckCheckpoint {
                    through: e.sequence,
                });
            }
            Event::Finished { status, .. } => {
                assert_eq!(status, Status::Paused);
                break;
            }
            _ => {}
        }
    }
    assert!(!checkpoint.is_empty());
    h.disconnect().unwrap();
    drop(store);
    let mut store = studio_store::Store::open(&directory).unwrap();
    let saved = store.scans().unwrap().pop().unwrap();
    assert_eq!(saved.network_report.as_ref().unwrap(), &frozen);
    assert_eq!(saved.checkpoint.as_ref().unwrap(), &checkpoint);
    env.resolved
        .lock()
        .unwrap()
        .insert(ip(2), [2, 0, 0, 0, 0, 2]);
    let mut h = Harness::new(env.clone());
    h.attempt = [4; 16];
    store.begin([2; 16], [4; 16], &j, true).unwrap();
    h.send(Command::Resume { job: j, checkpoint });
    loop {
        let e = h.event();
        store.apply(&e).unwrap();
        match e.payload {
            Event::NetworkPrepared { bytes } => {
                assert_eq!(bytes, frozen);
                h.send(Command::AckNetworkReport {
                    through: e.sequence,
                });
            }
            Event::Started { total } => {
                assert_eq!(total, "20");
                h.send(Command::Stop);
            }
            Event::Finished { status, .. } => {
                assert_eq!(status, Status::Stopped);
                break;
            }
            _ => {}
        }
    }
    h.disconnect().unwrap();
    drop(store);
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        env.packet
            .sent_frames()
            .iter()
            .all(|frame| frame[..6] != [2, 0, 0, 0, 0, 2])
    );
}
#[test]
fn second_start_while_preparing_or_waiting_is_rejected_without_a_second_worker() {
    for preparing in [false, true] {
        let env = Fake::new();
        if preparing {
            env.block.store(2, Ordering::Release);
        }
        let mut h = Harness::new(env.clone());
        h.send(Command::Start(job()));
        if preparing {
            wait(|| env.entered.load(Ordering::Acquire));
        } else {
            h.report();
        }
        h.attempt = [4; 16];
        h.seq = 0;
        h.send(Command::Start(job()));
        assert!(
            h.server
                .take()
                .unwrap()
                .join()
                .unwrap()
                .unwrap_err()
                .contains("One active")
        );
        assert_eq!(env.arp.load(Ordering::Acquire), 1);
        assert_eq!(env.opened.load(Ordering::Acquire), 0);
    }
}

#[test]
fn stop_during_final_adapter_open_closes_owned_pair_before_terminal_event() {
    let env = Fake::new();
    env.block.store(3, Ordering::Release);
    let mut h = Harness::new(env.clone());
    h.send(Command::Start(job()));
    let report = h.report();
    h.send(Command::AckNetworkReport {
        through: report.sequence,
    });
    wait(|| env.entered.load(Ordering::Acquire));
    assert_eq!(env.packet.alive_handles(), 2);
    h.send(Command::Stop);
    std::thread::sleep(Duration::from_millis(20));
    env.release_open.store(true, Ordering::Release);
    assert_eq!(h.finish().0, Status::Stopped);
    assert_eq!(env.packet.sent_count(), 0);
    assert_eq!(env.packet.alive_handles(), 0);
    h.disconnect().unwrap();
}
#[test]
fn superseded_job_check_never_publishes_stale_readiness() {
    let env = Fake::new();
    env.block.store(1, Ordering::Release);
    let mut h = Harness::new(env.clone());
    h.session(2, Command::CheckNetworkJob(job()));
    wait(|| env.entered.load(Ordering::Acquire));
    env.block.store(0, Ordering::Release);
    let mut newer = job();
    newer.ports = "81".into();
    h.session(3, Command::CheckNetworkJob(newer.clone()));
    match h.event().payload {
        Event::NetworkPreflight {
            job_digest, ready, ..
        } => {
            assert!(ready);
            assert_eq!(job_digest, newer.original_digest().unwrap());
        }
        event => panic!("{event:?}"),
    };
    assert!(env.closed.load(Ordering::Acquire));
    assert_eq!(env.arp.load(Ordering::Acquire), 0);
    h.disconnect().unwrap();
}

#[test]
fn matching_late_report_ack_after_stop_is_harmless_but_invalid_ack_is_rejected() {
    for valid in [true, false] {
        let env = Fake::new();
        let mut h = Harness::new(env.clone());
        h.send(Command::Start(job()));
        let report = h.report();
        h.send(Command::Stop);
        assert_eq!(h.finish().0, Status::Stopped);
        h.send(Command::AckNetworkReport {
            through: report.sequence + u64::from(!valid),
        });
        if valid {
            h.session(2, Command::CheckNetworkJob(job()));
            assert!(matches!(
                h.event().payload,
                Event::NetworkPreflight { ready: true, .. }
            ));
            h.disconnect().unwrap();
        } else {
            assert!(
                h.server
                    .take()
                    .unwrap()
                    .join()
                    .unwrap()
                    .unwrap_err()
                    .contains("ACK")
            );
        }
        assert_eq!(env.opened.load(Ordering::Acquire), 0);
        assert_eq!(env.packet.sent_count(), 0);
    }
}
