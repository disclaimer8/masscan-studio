//! Синхронный NDP-резолвер следующего хопа IPv6 над швами `Tx`/`Rx` с тем же контрактом, что у
//! [`crate::arp_resolve`] (повторы раз в секунду, срок 10 секунд, прерывание Ctrl-C, те же `Tx`/`Rx`, часы только
//! через [`Clock`]). Кодек в `rmasscan_core::ndp`.
//!
//! Отличие от C: `stack_ndpv6_resolve` (`stack-ndpv6.c:261-415`) не шлёт Neighbor Solicitation, а шлёт Router
//! Solicitation на `ff02::2` и ждёт Router Advertisement (повтор раз в секунду, 10 повторов, :357-374, как у ARP).
//! Здесь резолвер задаёт тот же вопрос "кто имеет адрес", что и ARP (RFC 4861 §7.2.2), и принимает только NA по
//! §7.1.2; интервал и срок взяты у C (`stack_ndpv6_resolve` :355-374: смена секунды, `i++ >= 10`).
//!
//! Единственный передаваемый кадр: `PendingNdp::request_frame` (86 байт, solicited-node multicast). `Rx::health` не
//! вызывается: потери в фазе NDP на результат скана не влияют.
#![forbid(unsafe_code)]

use std::fmt;
use std::net::Ipv6Addr;
use std::time::Duration;

use rmasscan_core::ndp::PendingNdp;
use rmasscan_core::ranges6::format_ipv6_c;
use rmasscan_core::throttle::Clock;
use rmasscan_engine::engine::MAX_IO_TIMEOUT;
use rmasscan_engine::{AdapterPair, IoError, SendStatus};

pub use crate::arp_resolve::NextHopKind;

/// Интервал запросов (как у ARP и C: раз в секунду).
pub const NDP_INTERVAL: Duration = Duration::from_secs(1);
/// Общий срок ожидания ответа (как у ARP и C: 10 секунд): запросы в t = 0..9 с, отказ в 10 с.
pub const NDP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdpPolicy {
    pub interval: Duration,
    pub timeout: Duration,
}

impl Default for NdpPolicy {
    fn default() -> Self {
        Self {
            interval: NDP_INTERVAL,
            timeout: NDP_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpReport {
    /// MAC из опции Target Link-Layer Address принятого Neighbor Advertisement. Кладётся в
    /// `NicBinding::next_hop_mac_ipv6`, а не в IPv4-поле `next_hop_mac`.
    pub mac: [u8; 6],
    pub requests_sent: u32,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdpResolveError {
    NdpTimeout {
        ifname: String,
        target: Ipv6Addr,
        kind: NextHopKind,
        requests_sent: u32,
    },
    Io(IoError),
    Uncertain,
}

impl fmt::Display for NdpResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NdpTimeout {
                ifname,
                target,
                kind,
                ..
            } => write!(
                f,
                "FAIL: NDP timed-out resolving MAC address for {kind} {ifname}: \"{}\"\n    [hint] try \"--router-mac-ipv6 66-55-44-33-22-11\" instead to bypass NDP\n    [hint] try \"--interface eth0\" to change interface",
                format_ipv6_c(u128::from(*target))
            ),
            Self::Io(e) => write!(
                f,
                "FAIL: NDP I/O error: {}\n    [hint] try \"--router-mac-ipv6 66-55-44-33-22-11\" instead to bypass NDP",
                e.message
            ),
            Self::Uncertain => f.write_str(
                "FAIL: NDP solicitation may or may not have been sent (adapter state unknown)\n    [hint] try \"--router-mac-ipv6 66-55-44-33-22-11\" instead to bypass NDP",
            ),
        }
    }
}

impl std::error::Error for NdpResolveError {}

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

/// Разрешает MAC следующего хопа IPv6 запросами Neighbor Solicitation раз в `policy.interval` до `policy.timeout`.
#[allow(clippy::too_many_arguments)]
pub fn resolve_next_hop_v6(
    io: &mut AdapterPair,
    ifname: &str,
    my_mac: [u8; 6],
    my_ip: Ipv6Addr,
    target: Ipv6Addr,
    kind: NextHopKind,
    policy: &NdpPolicy,
    clock: &dyn Clock,
) -> Result<NdpReport, NdpResolveError> {
    match resolve_next_hop_v6_until(
        io,
        ifname,
        my_mac,
        my_ip,
        target,
        kind,
        policy,
        clock,
        &mut || false,
    )? {
        Some(report) => Ok(report),
        // Недостижимо: `interrupted` всегда `false`. Отказ, а не паника, если это когда-нибудь изменится.
        None => Err(NdpResolveError::Uncertain),
    }
}

/// [`resolve_next_hop_v6`] с прерыванием (как `arp_resolve::resolve_next_hop_until`; C `main.c:1131-1154`).
/// `interrupted` опрашивается перед каждой отправкой и перед каждым ожиданием ответа (срез не длиннее
/// `MAX_IO_TIMEOUT`); `true` даёт `Ok(None)` без новых кадров и без ожидания остатка `policy.timeout`.
#[allow(clippy::too_many_arguments)]
pub fn resolve_next_hop_v6_until(
    io: &mut AdapterPair,
    ifname: &str,
    my_mac: [u8; 6],
    my_ip: Ipv6Addr,
    target: Ipv6Addr,
    kind: NextHopKind,
    policy: &NdpPolicy,
    clock: &dyn Clock,
    interrupted: &mut dyn FnMut() -> bool,
) -> Result<Option<NdpReport>, NdpResolveError> {
    let mut pending = PendingNdp::new(my_mac, u128::from(my_ip), u128::from(target));
    let frame = pending.request_frame();
    let timeout_us = micros(policy.timeout);
    let interval_us = micros(policy.interval);
    let max_io_us = micros(MAX_IO_TIMEOUT);
    let t0 = clock.now_micros();
    let mut next_send = t0;
    let mut requests_sent = 0u32;
    let mut buf = [0u8; 2048];
    loop {
        if interrupted() {
            return Ok(None);
        }
        let now = clock.now_micros();
        let elapsed = now.saturating_sub(t0);
        if elapsed >= timeout_us {
            return Err(NdpResolveError::NdpTimeout {
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
                .map_err(NdpResolveError::Io)?
            {
                SendStatus::Sent => {
                    requests_sent += 1;
                    next_send += interval_us;
                }
                SendStatus::WouldBlockUnsent => {
                    clock.sleep_micros(1000);
                    continue;
                }
                SendStatus::Uncertain => return Err(NdpResolveError::Uncertain),
            }
        }
        let now = clock.now_micros();
        let until_send = next_send.saturating_sub(now);
        let until_end = (t0 + timeout_us).saturating_sub(now);
        let wait = max_io_us.min(until_send).min(until_end);
        let got = io
            .rx
            .recv(&mut buf, Duration::from_micros(wait))
            .map_err(NdpResolveError::Io)?;
        if let Some(n) = got
            && let Some(mac) = pending.offer(&buf[..n])
        {
            return Ok(Some(NdpReport {
                mac,
                requests_sent,
                elapsed: Duration::from_micros(clock.now_micros().saturating_sub(t0)),
            }));
        }
    }
}

#[cfg(test)]
#[path = "ndp_resolve_tests.rs"]
mod ndp_resolve_tests;
