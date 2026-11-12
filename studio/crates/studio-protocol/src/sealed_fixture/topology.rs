use crate::{Backend, Job, NetworkReport};
use rmasscan_net::PhysicalRoutePlan;
use std::net::Ipv4Addr;

pub const SCANNER: &str = "feth4203";
pub const PEER: &str = "feth4204";
pub const SOURCE: Ipv4Addr = Ipv4Addr::new(198, 18, 42, 1);
pub const A: Ipv4Addr = Ipv4Addr::new(198, 18, 42, 2);
pub const B: Ipv4Addr = Ipv4Addr::new(198, 18, 42, 3);
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(198, 18, 42, 4);
pub const MISSING: Ipv4Addr = Ipv4Addr::new(198, 18, 42, 5);
pub const ROUTED: Ipv4Addr = Ipv4Addr::new(198, 19, 42, 2);
pub const SOURCE_MAC: [u8; 6] = [2, 0xac, 0x42, 0, 0, 1];
pub const PEER_MAC: [u8; 6] = [2, 0xac, 0x42, 0, 0, 2];
pub const A_MAC: [u8; 6] = [2, 0xac, 0x42, 0, 1, 2];
pub const B_MAC: [u8; 6] = [2, 0xac, 0x42, 0, 1, 3];
pub const GATEWAY_MAC: [u8; 6] = [2, 0xac, 0x42, 0, 1, 4];
pub const PORT_FIRST: u16 = 8000;
pub const PORT_LAST: u16 = 8031;

pub fn job() -> Job {
    Job {
        targets: "198.18.42.0/29,198.19.42.2".into(),
        ports: "8000-8031".into(),
        exclusions: "198.18.42.4,198.18.42.6".into(),
        seed: "42".into(),
        rate: 4,
        backend: Backend::MacNetwork,
    }
}

pub fn destination_mac(ip: Ipv4Addr) -> Option<[u8; 6]> {
    match ip {
        A => Some(A_MAC),
        B => Some(B_MAC),
        ROUTED => Some(GATEWAY_MAC),
        _ => None,
    }
}

pub fn validate_plan(plan: &PhysicalRoutePlan) -> Result<(), String> {
    use rmasscan_net::ExcludedReason::*;
    if plan.interface_name != SCANNER
        || plan.interface_index == 0
        || plan.source_ipv4 != SOURCE
        || plan.source_mac != Some(SOURCE_MAC)
        || plan.next_hops != [(A, A), (B, B), (MISSING, MISSING), (ROUTED, GATEWAY)].into()
        || plan.excluded
            != [
                (Ipv4Addr::new(198, 18, 42, 0), NetworkAddress),
                (SOURCE, OwnAddress),
                (Ipv4Addr::new(198, 18, 42, 7), BroadcastAddress),
            ]
            .into()
    {
        return Err("sealed fixture source/interface/routes/exclusions differ".into());
    }
    plan.validate_executable().map_err(|e| e.to_string())
}
pub fn validate_report(report: &NetworkReport) -> Result<(), String> {
    report.validate_for(&job())?;
    validate_plan(&report.routes)?;
    if report.destinations != [(A, A_MAC), (B, B_MAC), (ROUTED, GATEWAY_MAC)].into()
        || report.unresolved != [MISSING]
    {
        return Err("sealed fixture destination MACs or missing-neighbour coverage differ".into());
    }
    Ok(())
}

pub fn validate_interfaces(
    all: &[rmasscan_net::InterfaceObservation],
    sealed: bool,
) -> Result<(), String> {
    let lab_first = u32::from(Ipv4Addr::new(198, 18, 42, 0));
    for o in all {
        let own = sealed && [SCANNER, PEER].contains(&o.iface.name.as_str());
        if !own
            && ([SCANNER, PEER].contains(&o.iface.name.as_str())
                || o.iface.mac.is_some_and(|m| {
                    [SOURCE_MAC, PEER_MAC, A_MAC, B_MAC, GATEWAY_MAC].contains(&m)
                })
                || o.iface
                    .ipv4
                    .iter()
                    .any(|ip| u32::from(*ip) & 0xfffffff8 == lab_first || *ip == ROUTED))
        {
            return Err("fixture name/MAC/address collision".into());
        }
        if !own {
            for prefix in &o.ipv4_prefixes {
                if prefix.length > 32 {
                    return Err("invalid observed prefix".into());
                }
                let mask = if prefix.length == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix.length)
                };
                let first = u32::from(prefix.address) & mask;
                let last = first | !mask;
                if (first <= lab_first + 7 && last >= lab_first)
                    || (first <= u32::from(ROUTED) && last >= u32::from(ROUTED))
                {
                    return Err("existing interface prefix overlaps fixture".into());
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub fn expected_plan() -> PhysicalRoutePlan {
    use rmasscan_net::ExcludedReason::*;
    PhysicalRoutePlan {
        interface_name: SCANNER.into(),
        interface_index: 42,
        source_ipv4: SOURCE,
        source_mac: Some(SOURCE_MAC),
        next_hops: [(A, A), (B, B), (MISSING, MISSING), (ROUTED, GATEWAY)].into(),
        excluded: [
            (Ipv4Addr::new(198, 18, 42, 0), NetworkAddress),
            (SOURCE, OwnAddress),
            (Ipv4Addr::new(198, 18, 42, 7), BroadcastAddress),
        ]
        .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foreign_local_address_prefix_and_mac_collisions_are_refused() {
        use rmasscan_net::{Iface, InterfaceObservation, Ipv4Prefix};
        let mut observation = InterfaceObservation {
            iface: Iface {
                name: "en0".into(),
                index: 4,
                device_id: "en0".into(),
                description: None,
                mac: Some([2, 1, 2, 3, 4, 5]),
                mac_masked: false,
                ethernet: true,
                up: true,
                ipv4: vec![Ipv4Addr::new(192, 0, 2, 2)],
            },
            ipv4_prefixes: vec![Ipv4Prefix {
                address: Ipv4Addr::new(192, 0, 2, 2),
                length: 24,
            }],
        };
        assert!(validate_interfaces(&[observation.clone()], false).is_ok());
        observation.iface.ipv4.push(A);
        assert!(validate_interfaces(&[observation.clone()], true).is_err());
        observation.iface.ipv4.pop();
        observation.ipv4_prefixes.push(Ipv4Prefix {
            address: Ipv4Addr::new(198, 18, 0, 1),
            length: 15,
        });
        assert!(validate_interfaces(&[observation.clone()], false).is_err());
        observation.ipv4_prefixes.pop();
        observation.iface.mac = Some(GATEWAY_MAC);
        assert!(validate_interfaces(&[observation], true).is_err());
    }
    #[test]
    fn fixture_refuses_uplink_missing_route_owned_peer_and_changed_source() {
        let baseline = expected_plan();
        assert!(validate_plan(&baseline).is_ok());
        let mut bad = baseline.clone();
        bad.interface_name = "en0".into();
        assert!(
            validate_plan(&bad).is_err(),
            "uplink must never satisfy fixture"
        );
        let mut bad = baseline.clone();
        bad.next_hops.insert(ROUTED, ROUTED);
        assert!(validate_plan(&bad).is_err());
        let mut bad = baseline.clone();
        bad.next_hops.remove(&B);
        assert!(validate_plan(&bad).is_err());
        let mut bad = baseline;
        bad.source_mac = None;
        assert!(validate_plan(&bad).is_err());
    }
    #[test]
    fn report_requires_two_direct_macs_gateway_and_missing_coverage() {
        let report = NetworkReport {
            job_digest: job().original_digest().unwrap(),
            routes: expected_plan(),
            destinations: [(A, A_MAC), (B, B_MAC), (ROUTED, GATEWAY_MAC)].into(),
            unresolved: vec![MISSING],
        };
        assert!(validate_report(&report).is_ok());
        let mut bad = report.clone();
        bad.destinations.insert(B, A_MAC);
        assert!(
            validate_report(&bad).is_err(),
            "distinct peers must remain distinct"
        );
        let mut bad = report;
        bad.unresolved.clear();
        assert!(validate_report(&bad).is_err());
    }
}
