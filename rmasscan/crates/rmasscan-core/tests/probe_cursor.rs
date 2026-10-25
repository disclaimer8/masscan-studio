//! Курсор probe и ReadyPlan (AGPL-3.0, masscan © Robert David Graham).
//! Эталон считается здесь независимо из `transmit_scan` и формулы
//! main.c:373-393; курсор обязан дать те же байты.

use std::ops::ControlFlow;

use rmasscan_core::config::{EffectiveConfig, Operation, ScanConfig, validate};
use rmasscan_core::cookie::syn_cookie_ipv4;
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::{LinkType, TcpSynTemplate};
use rmasscan_core::probe::{AdapterBinding, PlanError, ProbeCursor, ReadyPlan, for_each_probe};
use rmasscan_core::scan::transmit_scan;
use rmasscan_core::targets::{add_target_string, parse_ports};

const IP_ME: u32 = 0x0aff_0001;
const MAC_ME: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_NH: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

fn massip(targets: &str, ports: &str) -> MassIp {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), targets).unwrap();
    parse_ports(m.ports_mut(), ports).unwrap();
    m
}

fn config(targets: &str, ports: &str, seed: u64, rate: f64) -> ScanConfig {
    ScanConfig {
        targets: massip(targets, ports),
        seed,
        max_rate: rate,
        ..ScanConfig::default()
    }
}

fn eff(cfg: &ScanConfig) -> EffectiveConfig {
    validate(cfg, Operation::Scan).unwrap()
}

fn binding(first: u16, last: u16) -> AdapterBinding {
    AdapterBinding {
        interface_id: "test0".to_string(),
        link_type: LinkType::Ethernet,
        source_ipv4: IP_ME,
        source_mac: MAC_ME,
        next_hop_mac: MAC_NH,
        source_ports: (first, last),
    }
}

/// (index, ip_them, port_them, port_me, seqno, frame)
type Row = (u64, u32, u16, u16, u32, Vec<u8>);

fn reference(e: &EffectiveConfig, first: u16, last: u16) -> Vec<Row> {
    let mask = u32::from(last - first);
    let tmpl = TcpSynTemplate::new(MAC_ME, MAC_NH, LinkType::Ethernet);
    let mut rows = Vec::new();
    transmit_scan(
        e.massip(),
        e.seed(),
        e.blackrock_rounds(),
        e.shard(),
        1,
        0,
        0,
        None,
        0,
        e.max_rate(),
        |i, repeats, xxx, ip, port| {
            let n = i.wrapping_add(repeats);
            let port_me = if mask != 0 {
                let ck = syn_cookie_ipv4(
                    n as u32,
                    (n >> 32) as u32,
                    xxx as u32,
                    (xxx >> 32) as u32,
                    e.seed(),
                );
                u32::from(first).wrapping_add(ck as u32 & mask)
            } else {
                u32::from(first)
            };
            let seq = syn_cookie_ipv4(ip, port, IP_ME, port_me, e.seed()) as u32;
            let mut frame = Vec::new();
            tmpl.build_syn(ip, port as u16, IP_ME, port_me as u16, seq, &mut frame);
            rows.push((i, ip, port as u16, port_me as u16, seq, frame));
        },
    )
    .unwrap();
    rows
}

fn row(p: &rmasscan_core::probe::Probe) -> Row {
    (
        p.index,
        p.ip_them,
        p.port_them,
        p.port_me,
        p.seqno,
        p.frame.clone(),
    )
}

fn drain(cur: &mut ProbeCursor) -> Vec<Row> {
    let mut v = Vec::new();
    while let Some(p) = cur.current() {
        v.push(row(p));
        cur.advance_sent();
    }
    v
}

#[test]
fn current_repeats_until_advance_and_position_counts_sent() {
    let e = eff(&config("10.0.0.0/29", "80,443", 5, 100.0));
    let plan = ReadyPlan::new(e, binding(40000, 40000)).unwrap();
    let mut cur = ProbeCursor::new(&plan, 0).unwrap();
    assert_eq!(cur.position(), 0);
    let a = row(cur.current().unwrap());
    let b = row(cur.current().unwrap());
    assert_eq!(a, b);
    assert_eq!(cur.position(), 0, "current must not advance");
    for n in 1..=5u64 {
        cur.advance_sent();
        assert_eq!(cur.position(), n);
        // the next current is a different probe, repeated calls agree
        let c = row(cur.current().unwrap());
        assert_eq!(c, row(cur.current().unwrap()));
        assert_eq!(c.0, n);
    }
}

#[test]
fn full_trace_matches_reference_across_matrix() {
    let seeds = [1u64, 5, u64::MAX];
    let rates = [1.0, 100.0, 10_000_000.0];
    let ports = [(40000u16, 40000u16), (40000, 40015)];
    // range = 8 ips * 2 ports = 16; also range = 1.
    for (targets, pl) in [("10.0.0.0/29", "80,443"), ("10.0.0.1", "80")] {
        for &seed in &seeds {
            for &rate in &rates {
                for &(f, l) in &ports {
                    let e = eff(&config(targets, pl, seed, rate));
                    let want = reference(&e, f, l);
                    let plan = ReadyPlan::new(e, binding(f, l)).unwrap();
                    let got = drain(&mut ProbeCursor::new(&plan, 0).unwrap());
                    assert_eq!(got, want, "{targets} seed {seed} rate {rate} ports {f}-{l}");
                    assert_eq!(got.len() as u64, plan.range());
                }
            }
        }
    }
}

#[test]
fn sixteen_wide_range_uses_several_source_ports() {
    let e = eff(&config("10.0.0.0/28", "80", 5, 100.0));
    let plan = ReadyPlan::new(e, binding(40000, 40015)).unwrap();
    let rows = drain(&mut ProbeCursor::new(&plan, 0).unwrap());
    let ports: std::collections::HashSet<u16> = rows.iter().map(|r| r.3).collect();
    assert!(ports.len() > 1);
    assert!(ports.iter().all(|p| (40000..=40015).contains(p)));
}

#[test]
fn restart_at_n_reproduces_exact_suffix() {
    for (f, l) in [(40000u16, 40000u16), (40000, 40003)] {
        let e = eff(&config("10.0.0.0/29", "80,443", u64::MAX, 7.0));
        let want = reference(&e, f, l);
        let plan = ReadyPlan::new(e, binding(f, l)).unwrap();
        for n in 0..=want.len() as u64 {
            let mut cur = ProbeCursor::new(&plan, n).unwrap();
            assert_eq!(cur.position(), n);
            assert_eq!(drain(&mut cur), want[n as usize..], "restart at {n}");
            assert_eq!(cur.position(), want.len() as u64);
        }
    }
}

#[test]
fn index_boundaries() {
    let e = eff(&config("10.0.0.0/30", "80", 9, 1.0));
    let want = reference(&e, 40000, 40000);
    let range = want.len() as u64;
    let plan = ReadyPlan::new(e, binding(40000, 40000)).unwrap();
    // range - 1: exactly the last probe
    let mut cur = ProbeCursor::new(&plan, range - 1).unwrap();
    assert_eq!(row(cur.current().unwrap()), want[range as usize - 1]);
    cur.advance_sent();
    assert!(cur.current().is_none());
    assert_eq!(cur.position(), range);
    // range: the end, nothing left, not an error
    let mut cur = ProbeCursor::new(&plan, range).unwrap();
    assert!(cur.current().is_none());
    cur.advance_sent(); // no probe: must not move past the end
    assert_eq!(cur.position(), range);
    // range + 1: error
    assert!(matches!(
        ProbeCursor::new(&plan, range + 1),
        Err(PlanError::NextIndexBeyondRange { next_index, range: r }) if next_index == range + 1 && r == range
    ));
    assert!(matches!(
        ProbeCursor::new(&plan, u64::MAX),
        Err(PlanError::NextIndexBeyondRange { .. })
    ));
}

#[test]
fn break_after_three_probes_stops_a_huge_range() {
    // 10.0.0.0/8 x 65535 ports is about 1.1e12 probes: walking to the end hangs.
    let e = eff(&config("10.0.0.0/8", "1-65535", 5, 100.0));
    let mut seen = 0u32;
    let r = for_each_probe(&e, &binding(40000, 40015), |_| {
        seen += 1;
        if seen == 3 {
            ControlFlow::Break("stop")
        } else {
            ControlFlow::Continue(())
        }
    })
    .unwrap();
    assert_eq!(r, ControlFlow::Break("stop"));
    assert_eq!(seen, 3);
}

#[test]
fn callback_error_after_three_probes_stops_a_huge_range() {
    let e = eff(&config("10.0.0.0/8", "1-65535", 5, 100.0));
    let mut seen = 0u32;
    let r: ControlFlow<String> = for_each_probe(&e, &binding(40000, 40000), |_| {
        seen += 1;
        if seen == 3 {
            ControlFlow::Break("sink failed".to_string())
        } else {
            ControlFlow::Continue(())
        }
    })
    .unwrap();
    assert_eq!(r, ControlFlow::Break("sink failed".to_string()));
    assert_eq!(seen, 3);
}

#[test]
fn legacy_stream_keeps_retries_and_matches_cookie_formula() {
    // The CLI oracle path supports retries; the runtime plan does not.
    let mut c = config("10.0.0.0/30", "80,443", 5, 100.0);
    c.retries = 1;
    let e = eff(&c);
    let mut n = 0u32;
    let r = for_each_probe(&e, &binding(40000, 40003), |p| {
        assert_eq!(p.ip_me, IP_ME);
        assert_eq!(&p.frame[34..36], &p.port_me.to_be_bytes());
        n += 1;
        ControlFlow::<()>::Continue(())
    })
    .unwrap();
    assert_eq!(r, ControlFlow::Continue(()));
    assert_eq!(n, 32); // 8 targets * (retries+1)^2
}

fn plan_err(c: &ScanConfig, b: AdapterBinding) -> PlanError {
    ReadyPlan::new(eff(c), b).unwrap_err()
}

#[test]
fn plan_rejects_legacy_resume_fields() {
    let mut c = config("10.0.0.0/30", "80", 5, 100.0);
    c.resume_index = 3;
    assert!(matches!(
        plan_err(&c, binding(40000, 40000)),
        PlanError::ResumeIndexNotAllowed(3)
    ));
    let mut c = config("10.0.0.0/30", "80", 5, 100.0);
    c.resume_count = Some(2);
    assert!(matches!(
        plan_err(&c, binding(40000, 40000)),
        PlanError::ResumeCountNotAllowed(2)
    ));
    // "no limit" spellings stay accepted
    for rc in [None, Some(0)] {
        let mut c = config("10.0.0.0/30", "80", 5, 100.0);
        c.resume_count = rc;
        ReadyPlan::new(eff(&c), binding(40000, 40000)).unwrap();
    }
}

#[test]
fn plan_rejects_unsupported_runtime_settings() {
    let b = || binding(40000, 40000);
    let mut c = config("10.0.0.0/30", "80", 5, 100.0);
    c.retries = 1;
    assert!(matches!(
        plan_err(&c, b()),
        PlanError::UnsupportedRetries(1)
    ));
    let mut c = config("10.0.0.0/30", "80", 5, 100.0);
    c.shard = rmasscan_core::scan::Shard { one: 1, of: 2 };
    assert!(matches!(
        plan_err(&c, b()),
        PlanError::UnsupportedShard { one: 1, of: 2 }
    ));
    let mut c = config("10.0.0.0/30", "80", 5, 100.0);
    c.blackrock_rounds = 15;
    assert!(matches!(
        plan_err(&c, b()),
        PlanError::UnsupportedRounds(15)
    ));
}

#[test]
fn plan_rejects_echo_job_and_bad_source_ports_and_non_tcp_ports() {
    let c = config("10.0.0.0/30", "80", 5, 100.0);
    let echo = validate(&c, Operation::Echo).unwrap();
    assert!(matches!(
        ReadyPlan::new(echo, binding(40000, 40000)),
        Err(PlanError::NotScanOperation(_))
    ));
    let list = validate(&c, Operation::List).unwrap();
    assert!(matches!(
        ReadyPlan::new(list, binding(40000, 40000)),
        Err(PlanError::NotScanOperation(_))
    ));
    for (f, l) in [(0u16, 0u16), (40001, 40000), (40000, 40002), (0, 15)] {
        assert!(
            matches!(
                plan_err(&c, binding(f, l)),
                PlanError::InvalidSourcePorts { .. }
            ),
            "{f}-{l}"
        );
    }
    let mut c = config("10.0.0.0/30", "80", 5, 100.0);
    c.targets.ports_mut().add_range(70000, 70000);
    assert!(matches!(
        plan_err(&c, binding(40000, 40000)),
        PlanError::PortNotTcp(70000)
    ));
}

// ---- batched access: preload / advance_sent_n ----

fn preload_rows(cur: &mut ProbeCursor, n: usize) -> Vec<Row> {
    cur.preload(n).iter().map(row).collect()
}

#[test]
fn preload_then_advance_n_matches_single_steps() {
    let e = eff(&config("10.0.0.0/29", "80,443", 7, 100.0));
    let plan = ReadyPlan::new(e, binding(40000, 40015)).unwrap();
    let want = drain(&mut ProbeCursor::new(&plan, 0).unwrap());
    for chunk in [1usize, 2, 3, 5, 16, 40] {
        let mut cur = ProbeCursor::new(&plan, 0).unwrap();
        let mut got = Vec::new();
        loop {
            let rows = preload_rows(&mut cur, chunk);
            if rows.is_empty() {
                break;
            }
            let k = rows.len();
            got.extend(rows);
            cur.advance_sent_n(k);
        }
        assert_eq!(got, want, "chunk {chunk}");
        assert_eq!(cur.position(), plan.range());
    }
}

#[test]
fn preload_is_capped_by_the_range() {
    let e = eff(&config("10.0.0.0/30", "80", 9, 1.0));
    let plan = ReadyPlan::new(e, binding(40000, 40000)).unwrap();
    let range = plan.range() as usize;
    let mut cur = ProbeCursor::new(&plan, 0).unwrap();
    assert_eq!(cur.preload(range + 100).len(), range);
    assert_eq!(cur.preload(0).len(), 0);
    // the loaded probes are still the front of the cursor
    assert_eq!(cur.current().unwrap().index, 0);
    let mut cur = ProbeCursor::new(&plan, range as u64 - 1).unwrap();
    assert_eq!(cur.preload(8).len(), 1);
    let mut cur = ProbeCursor::new(&plan, range as u64).unwrap();
    assert!(cur.preload(8).is_empty());
}

#[test]
fn advance_n_beyond_loaded_is_rejected_by_debug_assert_and_saturates() {
    let e = eff(&config("10.0.0.0/29", "80,443", 7, 100.0));
    let plan = ReadyPlan::new(e, binding(40000, 40000)).unwrap();
    let mut cur = ProbeCursor::new(&plan, 0).unwrap();
    assert_eq!(cur.preload(3).len(), 3);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cur.advance_sent_n(4)));
    if cfg!(debug_assertions) {
        assert!(r.is_err(), "debug build must reject k > loaded");
    } else {
        assert!(r.is_ok());
        assert_eq!(cur.position(), 3, "release saturates at the loaded count");
    }
}

#[test]
fn position_moves_only_in_advance() {
    let e = eff(&config("10.0.0.0/29", "80,443", 7, 100.0));
    let plan = ReadyPlan::new(e, binding(40000, 40000)).unwrap();
    let mut cur = ProbeCursor::new(&plan, 4).unwrap();
    assert_eq!(cur.preload(5).len(), 5);
    assert_eq!(cur.position(), 4);
    assert_eq!(cur.current().unwrap().index, 4);
    assert_eq!(cur.position(), 4);
    cur.advance_sent_n(0);
    assert_eq!(cur.position(), 4);
    cur.advance_sent_n(2);
    assert_eq!(cur.position(), 6);
    // the rest of the loaded probes is still served, in order, once
    let rows = preload_rows(&mut cur, 5);
    assert_eq!(
        rows.iter().map(|r| r.0).collect::<Vec<_>>(),
        [6, 7, 8, 9, 10]
    );
    assert_eq!(cur.position(), 6);
}
