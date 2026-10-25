//! Windows: проверки публичного API без пакетов. Опт-ин живые испытания
//! Npcap (отправка/приём/счётчик потерь на лабораторном NIC) используют
//! приватные модули crate и поэтому лежат в `src/windows/live.rs`
//! (`#[ignore]`, нужны `RMASSCAN_NPCAP_LAB_*`). Здесь пакетов нет никогда.
#![cfg(windows)]

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;
use rmasscan_net::open_explicit;

fn binding(name: &str) -> AdapterBinding {
    AdapterBinding {
        interface_id: name.into(),
        link_type: LinkType::Ethernet,
        source_ipv4: 0xC612_0001,
        source_mac: [2, 0, 0, 0, 0, 1],
        next_hop_mac: [2, 0, 0, 0, 0, 2],
        source_ports: (40000, 40000),
    }
}

/// Несуществующее устройство не даёт открытого адаптера: без Npcap это
/// `DriverUnavailable`, с Npcap `InterfaceMismatch` (имя вне перечня). Пакетов
/// тест не отправляет.
#[test]
fn a_bogus_device_never_opens_an_adapter() {
    let r = open_explicit(&binding(
        "\\Device\\NPF_{00000000-0000-0000-0000-000000000000}",
    ));
    assert!(r.is_err());
}
