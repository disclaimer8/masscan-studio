//! Mandatory policy for the unmerged sealed-fixture candidate only.
//! No OS access, state mutation, configuration switch or release bypass.
pub mod ownership;
pub mod topology;
use crate::{Job, NetworkReport};
use ownership::{InterfaceIdentity, OwnedRoute};
use rmasscan_core::probe::AdapterBinding;
use rmasscan_net::{NeighbourReport, PhysicalRoutePlan};
use topology::*;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub version: u8,
    pub generation: String,
    pub created_utc_seconds: u64,
    pub expires_utc_seconds: u64,
    pub tooling_sha256: String,
    pub sealed: bool,
    pub scanner: Option<InterfaceIdentity>,
    pub peer: Option<InterfaceIdentity>,
    pub route: Option<OwnedRoute>,
}

#[derive(Default)]
pub struct Pin(Option<State>);
impl Pin {
    pub fn check(&mut self, state: &State, now: u64) -> Result<u32, String> {
        validate_state(state, now)?;
        if self.0.as_ref().is_some_and(|prior| prior != state) {
            return Err(
                "sealed fixture generation or identity replaced; new helper session required"
                    .into(),
            );
        }
        self.0.get_or_insert_with(|| state.clone());
        Ok(state
            .scanner
            .as_ref()
            .ok_or("sealed fixture scanner absent")?
            .index)
    }
}

pub fn validate_state(state: &State, now: u64) -> Result<(), String> {
    let hex = |s: &str, len| {
        s.len() == len
            && s.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            && s.bytes().any(|c| c != b'0')
    };
    if state.version != 1
        || !state.sealed
        || !hex(&state.generation, 32)
        || !hex(&state.tooling_sha256, 64)
    {
        return Err("sealed fixture invalid or incomplete state".into());
    }
    ownership::fresh_lease(state.created_utc_seconds, state.expires_utc_seconds, now)?;
    let scanner = state
        .scanner
        .as_ref()
        .ok_or("sealed fixture missing scanner")?;
    let peer = state.peer.as_ref().ok_or("sealed fixture missing peer")?;
    for (i, name, mac, other, addresses, prefixes) in [
        (
            scanner,
            SCANNER,
            SOURCE_MAC,
            PEER,
            vec![SOURCE],
            vec![(SOURCE, 29)],
        ),
        (peer, PEER, PEER_MAC, SCANNER, vec![], vec![]),
    ] {
        if i.name != name
            || i.index == 0
            || i.mac != mac
            || i.peer.as_deref() != Some(other)
            || i.ipv4 != addresses
            || i.ipv4_prefixes != prefixes
            || !i.bridges.is_empty()
            || !i.up
        {
            return Err("sealed fixture interface identity differs".into());
        }
    }
    if scanner.index == peer.index {
        return Err("sealed fixture duplicate interface index".into());
    }
    let route = state
        .route
        .as_ref()
        .ok_or("sealed fixture missing host route")?;
    ownership::delete_route(route, Some(route))?.ok_or("sealed fixture route absent")?;
    Ok(())
}

pub fn validate_job(candidate: &Job) -> Result<(), String> {
    if candidate != &job() {
        return Err("sealed fixture fixed job differs".into());
    }
    Ok(())
}
pub fn validate_persisted(job: &Job, bytes: Option<&[u8]>) -> Result<(), String> {
    validate_job(job)?;
    validate_report(&NetworkReport::decode(
        bytes.ok_or("sealed fixture persisted report missing")?,
    )?)
}
pub fn validate_pinned_plan(plan: &PhysicalRoutePlan, index: u32) -> Result<(), String> {
    validate_plan(plan)?;
    if plan.interface_index != index {
        return Err("sealed fixture interface index changed".into());
    }
    Ok(())
}
/// Exactly the initial full plan or the frozen eligible Resume plan; never arbitrary subsets.
pub fn validate_neighbour_plan(plan: &PhysicalRoutePlan, index: u32) -> Result<bool, String> {
    let resume = !plan.next_hops.contains_key(&MISSING);
    let mut full = plan.clone();
    if resume {
        full.next_hops.insert(MISSING, MISSING);
    }
    validate_pinned_plan(&full, index)?;
    Ok(resume)
}
pub fn validate_neighbours(report: &NeighbourReport, resume: bool) -> Result<(), String> {
    if report.destinations != [(A, A_MAC), (B, B_MAC), (ROUTED, GATEWAY_MAC)].into()
        || report.unresolved_on_link != if resume { vec![] } else { vec![MISSING] }
    {
        return Err("sealed fixture neighbour MACs or missing coverage differ".into());
    }
    Ok(())
}
pub fn validate_binding(binding: &AdapterBinding) -> Result<(), String> {
    if binding.interface_id != SCANNER
        || binding.link_type != rmasscan_core::packet::LinkType::Ethernet
        || binding.source_ipv4 != u32::from(SOURCE)
        || binding.source_mac != SOURCE_MAC
        || binding.source_ports != (40000, 40000)
        || ![[0xff; 6], A_MAC, B_MAC, GATEWAY_MAC].contains(&binding.next_hop_mac)
    {
        return Err("sealed fixture adapter binding differs".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
