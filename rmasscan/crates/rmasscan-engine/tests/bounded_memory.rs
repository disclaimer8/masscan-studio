//! Ограниченная память на целевом пространстве масштаба /0 (AGPL-3.0).
//! Только офлайн: сокетов нет, Tx выбрасывает кадры, Rx всегда пуст.
//!
//! Что измеряется: RSS процесса (`ps -o rss=`, Unix) до и после генерации
//! ~1M probe по плану на ~2^32 целей (/0 минус 240/4). Материализация диапазона стоила бы
//! десятки ГиБ (u64 на probe) или хотя бы 512 МиБ (бит на probe), поэтому
//! порог 64 МиБ отличает ленивый курсор от материализующего. Это проверка
//! «не O(range)», а НЕ замер лимита RSS интерфейса или стоимости одного probe.
//! Тесты в одном процессе, поэтому запускаются одним `#[test]` (общий RSS).

mod common;

use std::time::Duration;

use common::*;
use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{AdapterBinding, ProbeCursor, ReadyPlan};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_engine::io::{AdapterPair, IoError, Rx, SendStatus, Tx};
use rmasscan_engine::{Engine, Reason};

const PROBES_TO_DRIVE: u64 = 1_000_000;
const RSS_BUDGET_KIB: u64 = 64 * 1024;

#[cfg(unix)]
fn rss_kib() -> Option<u64> {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    String::from_utf8(out.stdout).ok()?.trim().parse().ok()
}

#[cfg(not(unix))]
fn rss_kib() -> Option<u64> {
    None
}

struct DiscardTx;
impl Tx for DiscardTx {
    fn send(&mut self, frame: &[u8], _t: Duration) -> Result<SendStatus, IoError> {
        assert!(!frame.is_empty());
        Ok(SendStatus::Sent)
    }
}

/// Пустой RX: честно ждёт (не дольше 1 мс), чтобы не крутить ядро впустую.
struct IdleRx;
impl Rx for IdleRx {
    fn recv(&mut self, _b: &mut [u8], t: Duration) -> Result<Option<usize>, IoError> {
        std::thread::sleep(t.min(Duration::from_millis(1)));
        Ok(None)
    }
}

/// 0.0.0.0/0 минус 240.0.0.0/4 (без исключения config отвергает >1e9
/// адресов), один порт: 15/16 от 2^32 probe.
fn slash0_plan() -> ReadyPlan {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), "0.0.0.0/0").unwrap();
    parse_ports(m.ports_mut(), "80").unwrap();
    let mut ex = MassIp::new();
    add_target_string(ex.ipv4_mut(), "240.0.0.0/4").unwrap();
    let cfg = ScanConfig {
        targets: m,
        excludes: ex,
        seed: SEED,
        max_rate: 1e9,
        wait_secs: 0,
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

fn check_delta(what: &str, before: Option<u64>, after: Option<u64>) {
    if let (Some(b), Some(a)) = (before, after) {
        let delta = a.saturating_sub(b);
        eprintln!("bounded_memory {what}: rss {b} -> {a} KiB (delta {delta} KiB)");
        assert!(
            delta < RSS_BUDGET_KIB,
            "{what}: RSS grew {delta} KiB, looks O(range)"
        );
    } else {
        eprintln!("bounded_memory {what}: RSS unavailable on this OS, delta not asserted");
    }
}

#[test]
fn slash0_generation_and_idle_rx_stay_bounded() {
    let p = slash0_plan();
    let total = (u64::from(u32::MAX) + 1) - (1 << 28);
    assert_eq!(p.range(), total, "plan must cover /0 minus 240.0.0.0/4");
    let base = rss_kib();

    // 1. Курсор: лениво отдаёт probe, позиция растёт ровно на число подтверждённых.
    let mut c = ProbeCursor::new(&p, 0).unwrap();
    let mut last = 0;
    for _ in 0..PROBES_TO_DRIVE {
        let pr = c.current().expect("range not exhausted");
        last = pr.frame.len();
        c.advance_sent();
    }
    assert!(last > 0);
    assert_eq!(c.position(), PROBES_TO_DRIVE);
    check_delta("cursor", base, rss_kib());
    // Курсор с середины диапазона тоже O(1): без пролистывания префикса.
    let mut far = ProbeCursor::new(&p, total - 2).unwrap();
    assert!(far.current().is_some());
    far.advance_sent();
    far.advance_sent();
    assert!(far.current().is_none());
    assert_eq!(far.position(), total);

    // 2. Engine с пустым RX: гоним TX, затем Stop; очередь результатов пуста
    // и ограничена result_capacity, прогресс не зависит от размера range.
    let before_engine = rss_kib();
    let h = Engine::start(
        p.clone(),
        AdapterPair {
            tx: Box::new(DiscardTx),
            rx: Box::new(IdleRx),
        },
        opts(),
    )
    .unwrap();
    wait_for("1M probes sent", || h.progress().sent >= PROBES_TO_DRIVE);
    let mid = rss_kib();
    h.stop();
    let out = h.join().unwrap();
    assert_eq!(out.reason, Reason::Stopped);
    assert!(out.progress.sent >= PROBES_TO_DRIVE);
    assert_eq!(out.progress.received, 0, "idle RX produced results");
    assert!(
        out.progress.sent < p.range(),
        "stop must interrupt a 2^32 scan"
    );
    check_delta("engine", before_engine, mid);
}
