//! Fair bounded ARP preparation for a physical route snapshot.
#![forbid(unsafe_code)]
use crate::{
    NetError,
    network_plan::{PhysicalRoutePlan, invalid},
};
use rmasscan_core::arp::{PendingResolve, decode};
use rmasscan_core::throttle::Clock;
use rmasscan_engine::{AdapterPair, SendStatus};
use std::{collections::BTreeMap, net::Ipv4Addr, time::Duration};
pub const NEIGHBOUR_BUDGET: Duration = Duration::from_secs(35);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighbourReport {
    pub destinations: BTreeMap<Ipv4Addr, [u8; 6]>,
    pub unresolved_on_link: Vec<Ipv4Addr>,
    pub requests_sent: u32,
    pub elapsed: Duration,
}
struct Pending {
    arp: PendingResolve,
    sent: u8,
    last: u64,
}
fn check(clock: &dyn Clock, deadline: u64, cancelled: &dyn Fn() -> bool) -> Result<u64, NetError> {
    if cancelled() {
        return Err(invalid("network preparation cancelled"));
    }
    let now = clock.now_micros();
    if now >= deadline {
        return Err(invalid("neighbour preparation deadline expired"));
    }
    Ok(now)
}
/// Uses one interface-bound adapter pair, three fair passes, <=100 requests/s,
/// At least 1s per-hop retry spacing and a full second after each unresolved final send.
/// Every send/receive timeout is <=50ms. Callers own/drop the adapter before
/// acknowledging cancellation, and must re-observe routes before TCP starts.
pub fn resolve_neighbours(
    io: &mut AdapterPair,
    plan: &PhysicalRoutePlan,
    clock: &dyn Clock,
    cancelled: &dyn Fn() -> bool,
) -> Result<NeighbourReport, NetError> {
    plan.validate_executable()?;
    let start = clock.now_micros();
    let deadline = start
        .checked_add(35_000_000)
        .ok_or_else(|| invalid("neighbour deadline overflow"))?;
    check(clock, deadline, cancelled)?;
    let source_mac = plan
        .source_mac
        .ok_or_else(|| invalid("missing source MAC"))?;
    let mut pending: BTreeMap<_, _> = plan
        .next_hops
        .values()
        .map(|&ip| {
            (
                ip,
                Pending {
                    arp: PendingResolve::new(
                        source_mac,
                        u32::from(plan.source_ipv4),
                        u32::from(ip),
                    ),
                    sent: 0,
                    last: 0,
                },
            )
        })
        .collect();
    let mut next_send = start;
    let mut requests_sent = 0;
    let mut buf = [0u8; 2048];
    loop {
        let now = check(clock, deadline, cancelled)?;
        let unresolved: Vec<_> = pending
            .iter()
            .filter(|(_, p)| p.arp.resolved().is_none())
            .map(|(ip, p)| (*ip, p.sent, p.last))
            .collect();
        if unresolved.is_empty() {
            break;
        }
        let pass = unresolved
            .iter()
            .map(|(_, sent, _)| *sent)
            .min()
            .unwrap_or(3);
        let wake = if pass < 3 {
            let (ip, _, last) = *unresolved
                .iter()
                .filter(|(_, sent, _)| *sent == pass)
                .min_by_key(|(_, _, last)| *last)
                .ok_or_else(|| invalid("missing ARP pass"))?;
            let due = next_send.max(if pass == 0 {
                start
            } else {
                last.saturating_add(1_000_000)
            });
            if due <= now {
                // A final attempt without its response opportunity cannot become a local miss.
                if pass == 2 && now.checked_add(1_000_000).is_none_or(|t| t >= deadline) {
                    return Err(invalid(
                        "neighbour deadline cannot provide final response window",
                    ));
                }
                let p = pending
                    .get_mut(&ip)
                    .ok_or_else(|| invalid("missing ARP target"))?;
                let timeout = Duration::from_micros(50_000.min(deadline - now));
                match io
                    .tx
                    .send(&p.arp.request_frame(), timeout)
                    .map_err(|e| invalid(format!("ARP send: {}", e.message)))?
                {
                    SendStatus::Sent => {
                        let sent_at = check(clock, deadline, cancelled)?;
                        p.sent += 1;
                        p.last = sent_at;
                        requests_sent += 1;
                        next_send = sent_at.saturating_add(10_000);
                    }
                    SendStatus::WouldBlockUnsent => {
                        next_send = check(clock, deadline, cancelled)?.saturating_add(1_000);
                    }
                    SendStatus::Uncertain => {
                        return Err(invalid("uncertain ARP send; preparation aborted"));
                    }
                }
                // Recompute scheduling before receiving; this also checks cancellation after send.
                continue;
            }
            due
        } else {
            let end = unresolved
                .iter()
                .map(|(_, _, last)| last.saturating_add(1_000_000))
                .max()
                .unwrap_or(now);
            if end >= deadline {
                return Err(invalid(
                    "neighbour deadline cannot provide final response window",
                ));
            }
            if now >= end {
                break;
            }
            end
        };
        let now = check(clock, deadline, cancelled)?;
        let timeout =
            Duration::from_micros(wake.saturating_sub(now).min(deadline - now).min(50_000));
        let got = io
            .rx
            .recv(&mut buf, timeout)
            .map_err(|e| invalid(format!("ARP receive: {}", e.message)))?;
        check(clock, deadline, cancelled)?;
        if let Some(n) = got {
            let frame = buf
                .get(..n)
                .ok_or_else(|| invalid("ARP receive exceeded buffer"))?;
            if frame.get(..6) != Some(source_mac.as_slice()) {
                continue;
            }
            if let Ok(packet) = decode(frame)
                && let Some(p) = pending.get_mut(&Ipv4Addr::from(packet.sender_ip))
                && p.sent > 0
                && p.arp.resolved().is_none()
            {
                p.arp.offer(frame);
            }
        }
    }
    check(clock, deadline, cancelled)?;
    let mut destinations = BTreeMap::new();
    let mut unresolved_on_link = Vec::new();
    for (&dst, &hop) in &plan.next_hops {
        if let Some(mac) = pending.get(&hop).and_then(|p| p.arp.resolved()) {
            destinations.insert(dst, mac);
        } else if dst == hop {
            unresolved_on_link.push(dst);
        } else {
            return Err(invalid(format!(
                "gateway {hop} did not answer ARP; preparation aborted"
            )));
        }
    }
    Ok(NeighbourReport {
        destinations,
        unresolved_on_link,
        requests_sent,
        elapsed: Duration::from_micros(clock.now_micros() - start),
    })
}
#[cfg(test)]
#[path = "neighbours_tests.rs"]
mod neighbours_tests;
