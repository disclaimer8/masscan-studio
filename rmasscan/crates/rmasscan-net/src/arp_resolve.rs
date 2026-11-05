//! Синхронный ARP-резолвер следующего хопа над швами `Tx`/`Rx` (C `stack_arp_resolve`,
//! `stack-arpv4.c`; тексты отказов C `main-initadapter.c:196–198`). Безопасный модуль без ОС: время только
//! через инжектированные [`Clock`], тесты на `FakeAdapter` + `ManualClock`.
//!
//! Единственный передаваемый кадр: `encode_request(my_mac, my_ip, target)` (60 байт, broadcast). Ответом считается
//! только то, что принимает `PendingResolve::offer`. `Rx::health` не вызывается: потери в фазе ARP на результат
//! скана не влияют.
#![forbid(unsafe_code)]

use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

use rmasscan_core::arp::PendingResolve;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;
use rmasscan_core::throttle::Clock;
use rmasscan_engine::engine::MAX_IO_TIMEOUT;
use rmasscan_engine::{AdapterPair, IoError, SendStatus};

use crate::discover::ROUTER_HINTS;

/// Интервал запросов (C: раз в секунду).
pub const ARP_INTERVAL: Duration = Duration::from_secs(1);
/// Общий срок ожидания ответа (C: 10 секунд): запросы в t = 0..9 с, отказ в 10 с.
pub const ARP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPolicy {
    pub interval: Duration,
    pub timeout: Duration,
}

impl Default for ArpPolicy {
    fn default() -> Self {
        Self {
            interval: ARP_INTERVAL,
            timeout: ARP_TIMEOUT,
        }
    }
}

/// Кого разрешаем; влияет только на текст отказа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextHopKind {
    Router,
    Target,
}

impl fmt::Display for NextHopKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Router => "router",
            Self::Target => "next hop (target)",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpReport {
    pub mac: [u8; 6],
    pub requests_sent: u32,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArpResolveError {
    Timeout {
        ifname: String,
        target: Ipv4Addr,
        kind: NextHopKind,
        requests_sent: u32,
    },
    Io(IoError),
    Uncertain,
}

impl fmt::Display for ArpResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout {
                ifname,
                target,
                kind,
                ..
            } => write!(
                f,
                "FAIL: ARP timed-out resolving MAC address for {kind} {ifname}: \"{target}\"{ROUTER_HINTS}"
            ),
            Self::Io(e) => write!(
                f,
                "FAIL: ARP I/O error: {}\n    [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP",
                e.message
            ),
            Self::Uncertain => f.write_str(
                "FAIL: ARP request may or may not have been sent (adapter state unknown)\n    [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP",
            ),
        }
    }
}

impl std::error::Error for ArpResolveError {}

/// Broadcast next hop для короткоживущего адаптера фазы ARP (`check_binding` macOS/Windows требует unicast
/// source, отличный от next hop).
pub fn arp_binding(
    device_id: &str,
    source_ipv4: Ipv4Addr,
    source_mac: [u8; 6],
    source_ports: (u16, u16),
) -> AdapterBinding {
    AdapterBinding {
        interface_id: device_id.to_string(),
        link_type: LinkType::Ethernet,
        source_ipv4: u32::from(source_ipv4),
        source_mac,
        next_hop_mac: [0xff; 6],
        source_ports,
    }
}

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

/// Разрешает MAC следующего хопа ARP-запросами раз в `policy.interval` до `policy.timeout`.
#[allow(clippy::too_many_arguments)]
pub fn resolve_next_hop(
    io: &mut AdapterPair,
    ifname: &str,
    my_mac: [u8; 6],
    my_ip: Ipv4Addr,
    target: Ipv4Addr,
    kind: NextHopKind,
    policy: &ArpPolicy,
    clock: &dyn Clock,
) -> Result<ArpReport, ArpResolveError> {
    let mut pending = PendingResolve::new(my_mac, u32::from(my_ip), u32::from(target));
    let frame = pending.request_frame();
    let timeout_us = micros(policy.timeout);
    let interval_us = micros(policy.interval);
    let max_io_us = micros(MAX_IO_TIMEOUT);
    let t0 = clock.now_micros();
    let mut next_send = t0;
    let mut requests_sent = 0u32;
    let mut buf = [0u8; 2048];
    loop {
        let now = clock.now_micros();
        let elapsed = now.saturating_sub(t0);
        if elapsed >= timeout_us {
            return Err(ArpResolveError::Timeout {
                ifname: ifname.to_string(),
                target,
                kind,
                requests_sent,
            });
        }
        if now >= next_send {
            match io
                .tx
                .send(&frame, MAX_IO_TIMEOUT)
                .map_err(ArpResolveError::Io)?
            {
                SendStatus::Sent => {
                    requests_sent += 1;
                    next_send += interval_us;
                }
                SendStatus::WouldBlockUnsent => {
                    clock.sleep_micros(1000);
                    continue;
                }
                SendStatus::Uncertain => return Err(ArpResolveError::Uncertain),
            }
        }
        let now = clock.now_micros();
        let until_send = next_send.saturating_sub(now);
        let until_end = (t0 + timeout_us).saturating_sub(now);
        let wait = max_io_us.min(until_send).min(until_end);
        let got = io
            .rx
            .recv(&mut buf, Duration::from_micros(wait))
            .map_err(ArpResolveError::Io)?;
        if let Some(n) = got
            && let Some(mac) = pending.offer(&buf[..n])
        {
            return Ok(ArpReport {
                mac,
                requests_sent,
                elapsed: Duration::from_micros(clock.now_micros().saturating_sub(t0)),
            });
        }
    }
}

#[cfg(test)]
#[path = "arp_resolve_tests.rs"]
mod arp_resolve_tests;
