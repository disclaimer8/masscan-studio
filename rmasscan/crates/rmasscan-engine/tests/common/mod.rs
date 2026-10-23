//! Общие помощники интеграционных тестов (AGPL-3.0). Только офлайн.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{AdapterBinding, ProbeCursor, ReadyPlan};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_core::throttle::Clock;
use rmasscan_engine::fake::{FakeAdapter, ManualClock, reply_to_syn};
use rmasscan_engine::{Engine, EngineHandle, EngineOptions, Event, Outcome};
use std::sync::mpsc::TryRecvError;

pub const IP_ME: u32 = 0x0aff_0001;
pub const SEED: u64 = 0x1234_5678_9abc;
/// 8 адресов x 2 порта.
pub const PROBES: u64 = 16;

pub fn plan(rate: f64, wait_secs: u32) -> ReadyPlan {
    plan_with("10.0.0.0/29", rate, wait_secs)
}

pub fn plan_with(targets: &str, rate: f64, wait_secs: u32) -> ReadyPlan {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), targets).unwrap();
    parse_ports(m.ports_mut(), "80,443").unwrap();
    let cfg = ScanConfig {
        targets: m,
        seed: SEED,
        max_rate: rate,
        wait_secs,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).unwrap();
    ReadyPlan::new(
        eff,
        AdapterBinding {
            interface_id: "fake0".into(),
            link_type: LinkType::Ethernet,
            source_ipv4: IP_ME,
            source_mac: [0, 0x11, 0x22, 0x33, 0x44, 0x55],
            next_hop_mac: [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            source_ports: (40000, 40015),
        },
    )
    .unwrap()
}

pub fn opts() -> EngineOptions {
    EngineOptions::new([1; 16], [2; 16])
}

/// Эталонные кадры плана, по порядку (независимый ProbeCursor).
pub fn reference_frames(plan: &ReadyPlan, n: usize) -> Vec<Vec<u8>> {
    let mut c = ProbeCursor::new(plan, 0).unwrap();
    let mut out = Vec::new();
    while out.len() < n {
        let Some(p) = c.current() else { break };
        out.push(p.frame.clone());
        c.advance_sent();
    }
    out
}

/// Ответчик: SYN-ACK на каждый отправленный SYN.
pub fn synack_responder(fake: &FakeAdapter) {
    fake.set_responder(|f| reply_to_syn(f, 0x12).into_iter().collect());
}

pub fn start_manual(
    plan: &ReadyPlan,
    fake: &FakeAdapter,
    clock: &Arc<ManualClock>,
    options: EngineOptions,
) -> EngineHandle {
    let c: Arc<dyn Clock + Send + Sync> = clock.clone();
    Engine::start_with_clock(plan.clone(), fake.pair(), options, c).unwrap()
}

pub fn start_real(plan: &ReadyPlan, fake: &FakeAdapter) -> EngineHandle {
    Engine::start(plan.clone(), fake.pair(), opts()).unwrap()
}

pub fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let t = Instant::now();
    while !cond() {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "timeout waiting: {what}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Читает события до `Finished` (включительно).
pub fn drain_to_finished(h: &EngineHandle) -> Vec<Event> {
    let mut v = Vec::new();
    let t = Instant::now();
    loop {
        match h.recv_event_timeout(Duration::from_millis(50)) {
            Ok(e) => {
                let fin = matches!(e, Event::Finished { .. });
                v.push(e);
                if fin {
                    return v;
                }
            }
            Err(TryRecvError::Empty) => {
                assert!(t.elapsed() < Duration::from_secs(10), "no Finished: {v:?}");
            }
            Err(TryRecvError::Disconnected) => return v,
        }
    }
}

pub fn all_replies(events: &[Event]) -> Vec<rmasscan_core::receive::Reply> {
    events
        .iter()
        .flat_map(|e| match e {
            Event::Results { replies } => replies.clone(),
            _ => vec![],
        })
        .collect()
}

pub fn join_within(h: EngineHandle, limit: Duration) -> Outcome {
    let t = Instant::now();
    let o = h.join().unwrap();
    assert!(t.elapsed() < limit, "join took {:?}", t.elapsed());
    o
}
