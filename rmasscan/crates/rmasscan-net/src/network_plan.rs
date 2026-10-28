//! Bounded, read-only physical IPv4 preparation. No adapter is opened here.
#![forbid(unsafe_code)]
use crate::{Iface, Interfaces, NetError, RouteTable};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub const MAX_PHYSICAL_HOSTS: usize = 1024;
/// Bounds expansion before OS observations; effective hosts remain capped at 1024.
pub const MAX_PHYSICAL_CANDIDATES: usize = 2048;
pub const OBSERVATION_BUDGET: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv4Prefix {
    pub address: Ipv4Addr,
    pub length: u8,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceObservation {
    pub iface: Iface,
    pub ipv4_prefixes: Vec<Ipv4Prefix>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExcludedReason {
    OwnAddress,
    NetworkAddress,
    BroadcastAddress,
    ForbiddenAddress,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalRoutePlan {
    pub interface_name: String,
    pub interface_index: u32,
    pub source_ipv4: Ipv4Addr,
    /// None for a read-only unprivileged observation. Execution must call validate_executable.
    pub source_mac: Option<[u8; 6]>,
    pub next_hops: BTreeMap<Ipv4Addr, Ipv4Addr>,
    pub excluded: BTreeMap<Ipv4Addr, ExcludedReason>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalTargets {
    addresses: Vec<Ipv4Addr>,
    explicit: BTreeSet<Ipv4Addr>,
    exclusions: Vec<(Ipv4Addr, Ipv4Addr)>,
}
pub(crate) fn invalid(message: impl Into<String>) -> NetError {
    NetError::System(message.into())
}
pub fn check_observation(deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<(), NetError> {
    if cancelled() {
        return Err(invalid("network preparation cancelled"));
    }
    if Instant::now() >= deadline {
        return Err(invalid("network observation deadline expired"));
    }
    Ok(())
}
impl PhysicalTargets {
    /// Inclusive ranges plus singleton provenance; exclusions apply before expansion.
    /// Inputs are bounded independently of UI parsing, including duplicate selectors.
    pub fn new(
        ranges: &[(Ipv4Addr, Ipv4Addr)],
        explicit: &[Ipv4Addr],
        exclusions: &[(Ipv4Addr, Ipv4Addr)],
    ) -> Result<Self, NetError> {
        if ranges.len() > MAX_PHYSICAL_CANDIDATES
            || explicit.len() > MAX_PHYSICAL_CANDIDATES
            || exclusions.len() > MAX_PHYSICAL_CANDIDATES
        {
            return Err(invalid("too many physical target selectors"));
        }
        let mut input = ranges.to_vec();
        input.extend(explicit.iter().map(|&a| (a, a)));
        let ranges = normalize(&input)?;
        let excluded = normalize(exclusions)?;
        let mut effective = Vec::new();
        let mut count = 0u64;
        for (lo, hi) in ranges {
            let mut cursor = u64::from(lo);
            let end = u64::from(hi);
            for &(a, b) in &excluded {
                let (a, b) = (u64::from(a), u64::from(b));
                if b < cursor || a > end {
                    continue;
                }
                if a > cursor {
                    push_range(&mut effective, &mut count, cursor, a - 1)?;
                }
                cursor = cursor.max(b + 1);
                if cursor > end {
                    break;
                }
            }
            if cursor <= end {
                push_range(&mut effective, &mut count, cursor, end)?;
            }
        }
        if count == 0 {
            return Err(invalid("no physical targets after user exclusions"));
        }
        let addresses: Vec<_> = effective
            .into_iter()
            .flat_map(|(a, b)| a..=b)
            .map(Ipv4Addr::from)
            .collect();
        let explicit = explicit
            .iter()
            .copied()
            .filter(|a| addresses.binary_search(a).is_ok())
            .collect();
        Ok(Self {
            addresses,
            explicit,
            exclusions: excluded
                .into_iter()
                .map(|(a, b)| (a.into(), b.into()))
                .collect(),
        })
    }
    pub fn addresses(&self) -> &[Ipv4Addr] {
        &self.addresses
    }
    pub fn explicit_singletons(&self) -> &BTreeSet<Ipv4Addr> {
        &self.explicit
    }
    pub fn user_exclusions(&self) -> &[(Ipv4Addr, Ipv4Addr)] {
        &self.exclusions
    }
}
impl PhysicalRoutePlan {
    /// Must run before opening the short-lived ARP adapter. A masked GUI snapshot
    /// deliberately cannot pass this check; the helper must observe its own MAC.
    pub fn validate_executable(&self) -> Result<(), NetError> {
        if self.interface_name.is_empty()
            || self.interface_name.len() > 63
            || self
                .interface_name
                .bytes()
                .any(|b| b == 0 || b.is_ascii_whitespace() || b == b'/')
            || self.interface_index == 0
        {
            return Err(invalid("invalid physical interface identity"));
        }
        if !unicast(self.source_ipv4)
            || !self
                .source_mac
                .is_some_and(crate::discover::usable_source_mac)
        {
            return Err(invalid("physical source MAC/IP missing, masked or invalid"));
        }
        if self.next_hops.is_empty()
            || self.next_hops.len() > MAX_PHYSICAL_HOSTS
            || self.next_hops.len() + self.excluded.len() > MAX_PHYSICAL_CANDIDATES
        {
            return Err(invalid("physical host/address bound exceeded"));
        }
        for (dst, hop) in &self.next_hops {
            if !unicast(*dst)
                || !unicast(*hop)
                || *dst == self.source_ipv4
                || *hop == self.source_ipv4
                || self.excluded.contains_key(dst)
            {
                return Err(invalid("invalid physical destination or next hop"));
            }
        }
        Ok(())
    }
}
fn normalize(ranges: &[(Ipv4Addr, Ipv4Addr)]) -> Result<Vec<(u32, u32)>, NetError> {
    let mut ranges: Vec<_> = ranges
        .iter()
        .map(|(a, b)| (u32::from(*a), u32::from(*b)))
        .collect();
    if ranges.iter().any(|(a, b)| a > b) {
        return Err(invalid("reversed IPv4 range"));
    }
    ranges.sort_unstable();
    let mut out: Vec<(u32, u32)> = Vec::new();
    for (a, b) in ranges {
        if let Some(last) = out.last_mut()
            && u64::from(a) <= u64::from(last.1) + 1
        {
            last.1 = last.1.max(b);
        } else {
            out.push((a, b));
        }
    }
    Ok(out)
}
fn push_range(out: &mut Vec<(u32, u32)>, count: &mut u64, a: u64, b: u64) -> Result<(), NetError> {
    *count += b - a + 1;
    if *count > MAX_PHYSICAL_CANDIDATES as u64 {
        return Err(invalid("physical candidate address limit is 2048"));
    }
    out.push((a as u32, b as u32));
    Ok(())
}
pub(crate) fn unicast(a: Ipv4Addr) -> bool {
    let first = a.octets()[0];
    first != 0 && first != 127 && first < 224
}
fn endpoint(a: Ipv4Addr, all: &[InterfaceObservation]) -> Option<ExcludedReason> {
    if !unicast(a) {
        return Some(ExcludedReason::ForbiddenAddress);
    }
    if all.iter().any(|o| o.iface.ipv4.contains(&a)) {
        return Some(ExcludedReason::OwnAddress);
    }
    for o in all.iter().filter(|o| o.iface.up) {
        for p in &o.ipv4_prefixes {
            if p.length >= 31 {
                continue;
            }
            let mask = u32::MAX.checked_shl(32 - u32::from(p.length)).unwrap_or(0);
            let net = u32::from(p.address) & mask;
            let a = u32::from(a);
            // A local prefix never classifies a remote subnet's endpoints.
            if a & mask != net {
                continue;
            }
            if a == net {
                return Some(ExcludedReason::NetworkAddress);
            }
            if a == net | !mask {
                return Some(ExcludedReason::BroadcastAddress);
            }
        }
    }
    None
}
/// Complete snapshot within the caller's absolute deadline, additionally capped at 10s.
/// The read-only result may lack a visible source MAC; validate_executable gates I/O.
pub fn plan_physical(
    targets: &PhysicalTargets,
    routes: &dyn RouteTable,
    interfaces: &dyn Interfaces,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<PhysicalRoutePlan, NetError> {
    let deadline = deadline.min(Instant::now() + OBSERVATION_BUDGET);
    check_observation(deadline, cancelled)?;
    let mut all = interfaces.observe(deadline, cancelled)?;
    check_observation(deadline, cancelled)?;
    for o in &mut all {
        o.iface.ipv4.sort_unstable();
        o.iface.ipv4.dedup();
        if o.ipv4_prefixes
            .iter()
            .any(|p| p.length > 32 || !o.iface.ipv4.contains(&p.address))
        {
            return Err(invalid("invalid interface prefix observation"));
        }
    }
    let mut excluded = BTreeMap::new();
    let mut effective = Vec::new();
    for &a in &targets.addresses {
        if let Some(reason) = endpoint(a, &all) {
            if targets.explicit.contains(&a) {
                return Err(invalid(format!(
                    "explicit target {a} is forbidden: {reason:?}"
                )));
            }
            excluded.insert(a, reason);
        } else {
            effective.push(a);
        }
    }
    if effective.is_empty() || effective.len() > MAX_PHYSICAL_HOSTS {
        return Err(invalid("physical effective host limit is 1..=1024"));
    }
    let mut chosen: Option<&InterfaceObservation> = None;
    let mut next_hops = BTreeMap::new();
    for a in effective {
        check_observation(deadline, cancelled)?;
        let r = routes
            .lookup_until(a, deadline, cancelled)?
            .ok_or_else(|| invalid(format!("no route to {a}")))?;
        check_observation(deadline, cancelled)?;
        if r.local {
            return Err(invalid(format!(
                "route to {a} is local but interface observations disagree"
            )));
        }
        let matches: Vec<_> = all
            .iter()
            .filter(|o| o.iface.index == r.ifindex && o.iface.name == r.ifname)
            .collect();
        if matches.len() != 1 {
            return Err(invalid(format!(
                "ambiguous or missing route interface for {a}"
            )));
        }
        let o = matches[0];
        let i = &o.iface;
        if !i.up || !i.ethernet || i.index == 0 || i.name.is_empty() || i.name.len() > 63 {
            return Err(invalid(format!("unsupported interface {} for {a}", i.name)));
        }
        if i.ipv4.len() != 1
            || !unicast(i.ipv4[0])
            || o.ipv4_prefixes
                .iter()
                .filter(|p| p.address == i.ipv4[0])
                .count()
                != 1
        {
            return Err(invalid(format!(
                "ambiguous or missing source/prefix on {}",
                i.name
            )));
        }
        if let Some(prev) = chosen
            && prev != o
        {
            return Err(invalid(format!("mixed physical interfaces at {a}")));
        }
        chosen = Some(o);
        let hop = r.gateway.unwrap_or(a);
        if endpoint(hop, &all).is_some() {
            return Err(invalid(format!("invalid next hop {hop} for {a}")));
        }
        next_hops.insert(a, hop);
    }
    check_observation(deadline, cancelled)?;
    let i = &chosen
        .ok_or_else(|| invalid("no usable physical route"))?
        .iface;
    Ok(PhysicalRoutePlan {
        interface_name: i.name.clone(),
        interface_index: i.index,
        source_ipv4: i.ipv4[0],
        source_mac: if i.mac_masked {
            None
        } else {
            i.mac.filter(|m| crate::discover::usable_source_mac(*m))
        },
        next_hops,
        excluded,
    })
}
#[cfg(test)]
#[path = "network_plan_tests.rs"]
mod network_plan_tests;
