//! Конвейер офлайн-генерации для бенчмарка (AGPL-3.0, masscan © Robert David
//! Graham). Общий для `tests/offline_gen.rs` и `benches/offline_gen.rs`.
//!
//! Аналог `transmit_thread` (main.c:203-448) в режиме `--offline` без I/O:
//! `throttler_next_batch` (:292) -> индекс -> BlackRock shuffle -> pick
//! (`transmit_scan`) -> SYN-cookie (:389) -> `template_set_target_ipv4`
//! (`build_syn` в повторно используемый `Vec`). `rawsock_send_packet` в
//! офлайне ничего не делает, поэтому здесь его нет.
#![allow(dead_code)]

use rmasscan_core::cookie::syn_cookie_ipv4;
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::{LinkType, TcpSynTemplate};
use rmasscan_core::scan::{Shard, transmit_scan};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_core::throttle::{SystemClock, Throttler};

/// Оракул: `masscan 0.0.0.0/4 -p80 --rate 100000000 --seed 1 --wait 0`.
pub const ORACLE_RATE: f64 = 100_000_000.0;
pub const ORACLE_SEED: u64 = 1;
/// `--adapter-ip 10.255.0.1 --source-port 40000` оракула.
const IP_ME: u32 = 0x0aff_0001;
const PORT_ME: u16 = 40000;

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
    let clock = SystemClock::new();
    let mut throttler = Throttler::start(ORACLE_RATE, &clock); // main.c:260
    let tmpl = TcpSynTemplate::new(
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        LinkType::Ethernet,
    );
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
            // main.c:292: новая пачка, когда прежняя исчерпана (`while (batch_size && ...)`).
            while batch == 0 {
                batch = throttler.next_batch(packets_sent, &clock);
            }
            // main.c:389: src.ipv4_mask == 0 && port_mask == 0 -> простой cookie.
            let seqno =
                syn_cookie_ipv4(ip_them, port_them, IP_ME, u32::from(PORT_ME), ORACLE_SEED) as u32;
            tmpl.build_syn(ip_them, port_them as u16, IP_ME, PORT_ME, seqno, &mut frame);
            sink = sink.wrapping_add(u64::from(frame[53]) + u64::from(frame[24]));
            batch -= 1; // :412
            packets_sent += 1; // :413
        },
    )
    .unwrap();
    (packets_sent, sink)
}
