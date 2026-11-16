//! Конвейер офлайн-генерации для бенчмарка (AGPL-3.0, masscan © Robert David
//! Graham). Общий для `tests/offline_gen.rs` и `benches/offline_gen.rs`.
//!
//! Аналог `transmit_thread` (main.c:203-448) в режиме `--offline` без I/O:
//! `throttler_next_batch` (:289) -> индекс -> BlackRock shuffle -> pick
//! (`transmit_scan`) -> SYN-cookie (:389) -> `template_set_target_ipv4`
//! (`build_syn` в повторно используемый `Vec`). `rawsock_send_packet` в
//! офлайне ничего не делает, поэтому здесь его нет.
#![allow(dead_code)]

use std::collections::BTreeMap;

use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::cookie::syn_cookie_ipv4;
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::{LinkType, TcpSynTemplate};
use rmasscan_core::probe::{AdapterBinding, NicBinding, ReadyPlan};
use rmasscan_core::scan::{Shard, transmit_scan};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_core::throttle::{SystemClock, Throttler};

/// Оракул: `masscan 0.0.0.0/4 -p80 --rate 100000000 --seed 1 --wait 0`.
pub const ORACLE_RATE: f64 = 100_000_000.0;
pub const ORACLE_SEED: u64 = 1;
/// `--adapter-ip 10.255.0.1 --source-port 40000` оракула.
const IP_ME: u32 = 0x0aff_0001;
const PORT_ME: u16 = 40000;
const MAC_ME: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_NH: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

pub fn build_massip(targets: &str, ports: &str) -> MassIp {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), targets).unwrap();
    parse_ports(m.ports_mut(), ports).unwrap();
    m.optimize();
    m
}

/// Генерирует все пакеты и возвращает их число (плюс «приёмник», чтобы
/// оптимизатор не выбросил работу).
pub fn generate(massip: &MassIp) -> (u64, u64) {
    generate_with(massip, |_, _| {})
}

/// То же, но `on_target(ip, port)` видит каждую цель (для проверки полноты;
/// пустой замыкание в бенчмарке инлайнится).
#[inline(always)]
pub fn generate_with(massip: &MassIp, mut on_target: impl FnMut(u32, u32)) -> (u64, u64) {
    let clock = SystemClock::new();
    let mut throttler = Throttler::start(ORACLE_RATE, &clock); // main.c:249
    let tmpl = TcpSynTemplate::new(MAC_ME, MAC_NH, LinkType::Ethernet);
    let mut frame = Vec::with_capacity(64);
    let mut packets_sent = 0u64;
    let mut batch = 0u64;
    let mut sink = 0u64;
    transmit_scan(
        massip,
        ORACLE_SEED,
        14,
        Shard { one: 1, of: 1 },
        1,
        0,
        0,
        None,
        0,
        ORACLE_RATE,
        |_i, _repeats, _xxx, ip_them, port_them| {
            on_target(ip_them, port_them);
            // main.c:289: новая пачка, когда прежняя исчерпана (`while (batch_size && ...)`).
            while batch == 0 {
                batch = throttler.next_batch(packets_sent, &clock);
            }
            // main.c:389: src.ipv4_mask == 0 && port_mask == 0 -> простой cookie.
            let seqno =
                syn_cookie_ipv4(ip_them, port_them, IP_ME, u32::from(PORT_ME), ORACLE_SEED) as u32;
            tmpl.build_syn(ip_them, port_them as u16, IP_ME, PORT_ME, seqno, &mut frame);
            // Не даёт LTO выбросить запись кадра (чтение двух байтов этого не гарантирует).
            std::hint::black_box(&frame);
            sink = sink.wrapping_add(u64::from(frame[53]) + u64::from(frame[24]));
            batch -= 1; // :408
            packets_sent += 1; // :409
        },
    )
    .unwrap();
    (packets_sent, sink)
}

fn cursor_config(targets: &str, ports: &str) -> rmasscan_core::config::EffectiveConfig {
    let cfg = ScanConfig {
        targets: build_massip(targets, ports),
        seed: ORACLE_SEED,
        max_rate: ORACLE_RATE,
        blackrock_rounds: 14,
        ..ScanConfig::default()
    };
    validate(&cfg, Operation::Scan).unwrap()
}

fn cursor_binding(source_ports: (u16, u16)) -> AdapterBinding {
    AdapterBinding {
        interface_id: "bench0".to_string(),
        link_type: LinkType::Ethernet,
        source_ipv4: IP_ME,
        source_mac: MAC_ME,
        next_hop_mac: MAC_NH,
        source_ports,
    }
}

/// План CLI на один адаптер Ethernet с адресом и MAC оракула, seed 1, rate 1e8, 14 раундов.
pub fn cursor_plan(targets: &str, ports: &str, source_ports: (u16, u16)) -> ReadyPlan {
    let nic = NicBinding::from(cursor_binding(source_ports));
    ReadyPlan::new_cli(cursor_config(targets, ports), vec![nic]).unwrap()
}

/// План с картой назначений: у каждой цели свой одноадресный MAC `02:00:<4 байта адреса>`.
pub fn mapped_plan(targets: &str, ports: &str) -> ReadyPlan {
    let effective = cursor_config(targets, ports);
    let list = effective.massip().ipv4();
    let destinations: BTreeMap<u32, [u8; 6]> = (0..list.count())
        .map(|k| {
            let ip = list.pick(k);
            let b = ip.to_be_bytes();
            (ip, [0x02, 0x00, b[0], b[1], b[2], b[3]])
        })
        .collect();
    ReadyPlan::with_destinations(effective, cursor_binding((PORT_ME, PORT_ME)), destinations)
        .unwrap()
}

/// Гоняет `ProbeCursor` так, как движок: `preload(preload)`, чтение кадров, `advance_sent_n`.
/// Возвращает (число зондов, sink). Без троттлера (у движка свой).
pub fn generate_cursor(plan: &ReadyPlan, preload: usize) -> (u64, u64) {
    let mut cursor = plan.cursor_for_nic(0, None).unwrap();
    let mut sent = 0u64;
    let mut sink = 0u64;
    loop {
        let batch = cursor.preload(preload);
        if batch.is_empty() {
            break;
        }
        for p in batch {
            sink = sink
                .wrapping_add(u64::from(p.seqno) + u64::from(p.frame[24]) + u64::from(p.frame[53]));
        }
        let len = batch.len();
        std::hint::black_box(batch);
        cursor.advance_sent_n(len);
        sent += len as u64;
    }
    (sent, sink)
}
