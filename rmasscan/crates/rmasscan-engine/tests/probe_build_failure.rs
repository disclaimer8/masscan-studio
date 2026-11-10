//! Probe, который не построился посреди прохода, это отказ запуска, а не его естественный конец (AGPL-3.0).
//! Офлайн. План строится в обход проверки портов, потому что рабочий вход (`new_cli`) такие порты отклоняет.

mod common;

use common::*;
use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{AdapterBinding, NicBinding, ReadyPlan};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_engine::fake::FakeAdapter;
use rmasscan_engine::{FailReason, Reason};

#[test]
fn unbuildable_port_fails_the_run_instead_of_ending_it_naturally() {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), "10.0.0.0/29").unwrap();
    parse_ports(m.ports_mut(), "80,S:2905").unwrap();
    let cfg = ScanConfig {
        targets: m,
        seed: SEED,
        max_rate: 1_000_000.0,
        wait_secs: 1,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).unwrap();
    let binding = AdapterBinding {
        interface_id: "fake0".into(),
        link_type: LinkType::Ethernet,
        source_ipv4: IP_ME,
        source_mac: [0, 0x11, 0x22, 0x33, 0x44, 0x55],
        next_hop_mac: [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        source_ports: (40000, 40015),
    };
    let plan = ReadyPlan::new_cli_without_port_checks(
        eff.clone(),
        vec![NicBinding::from(binding.clone())],
    )
    .unwrap();
    // Рабочий вход отклоняет тот же план заранее.
    assert!(ReadyPlan::new_cli(eff, vec![NicBinding::from(binding)]).is_err());
    let fake = FakeAdapter::new();
    let h = start_real(&plan, &fake);
    wait_for("outcome", || h.outcome().is_some());
    let (out, _events) = h.join_drain().unwrap();
    let Reason::Failed(FailReason::ProbeBuild(msg)) = out.reason else {
        panic!("expected Failed(ProbeBuild), got {:?}", out.reason);
    };
    assert!(msg.contains("does not fit TCP"), "{msg}");
    // 16 probe (8 адресов x 2 порта): не все ушли
    assert!(out.progress.sent < 16, "sent {}", out.progress.sent);
}
