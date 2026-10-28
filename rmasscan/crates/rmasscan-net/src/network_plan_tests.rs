use super::*;
use crate::Route;
use std::cell::RefCell;
fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}
fn observation() -> InterfaceObservation {
    InterfaceObservation {
        iface: Iface {
            name: "en0".into(),
            index: 2,
            device_id: "en0".into(),
            description: None,
            mac: Some([2, 1, 2, 3, 4, 5]),
            mac_masked: false,
            ethernet: true,
            up: true,
            ipv4: vec![ip("192.168.1.10")],
        },
        ipv4_prefixes: vec![Ipv4Prefix {
            address: ip("192.168.1.10"),
            length: 24,
        }],
    }
}
struct Os {
    interfaces: Vec<InterfaceObservation>,
    overrides: BTreeMap<Ipv4Addr, Route>,
    seen: RefCell<Vec<Ipv4Addr>>,
}
impl Os {
    fn new() -> Self {
        Self {
            interfaces: vec![observation()],
            overrides: BTreeMap::new(),
            seen: RefCell::new(vec![]),
        }
    }
}
impl Interfaces for Os {
    fn list(&self) -> Result<Vec<Iface>, NetError> {
        panic!("unbounded list")
    }
    fn observe(
        &self,
        d: Instant,
        c: &dyn Fn() -> bool,
    ) -> Result<Vec<InterfaceObservation>, NetError> {
        check_observation(d, c)?;
        Ok(self.interfaces.clone())
    }
}
impl RouteTable for Os {
    fn lookup(&self, _: Ipv4Addr) -> Result<Option<Route>, NetError> {
        panic!("unbounded lookup")
    }
    fn default_routes(&self) -> Result<Vec<Route>, NetError> {
        panic!("default route")
    }
    fn lookup_until(
        &self,
        dst: Ipv4Addr,
        d: Instant,
        c: &dyn Fn() -> bool,
    ) -> Result<Option<Route>, NetError> {
        check_observation(d, c)?;
        self.seen.borrow_mut().push(dst);
        Ok(Some(self.overrides.get(&dst).cloned().unwrap_or(Route {
            ifname: "en0".into(),
            ifindex: 2,
            local: false,
            gateway: None,
        })))
    }
}
fn targets(
    a: &str,
    b: &str,
    explicit: &[Ipv4Addr],
    ex: &[(Ipv4Addr, Ipv4Addr)],
) -> PhysicalTargets {
    PhysicalTargets::new(&[(ip(a), ip(b))], explicit, ex).unwrap()
}
fn plan(t: &PhysicalTargets, o: &Os) -> Result<PhysicalRoutePlan, NetError> {
    plan_physical(t, o, o, Instant::now() + OBSERVATION_BUDGET, &|| false)
}
#[test]
fn home_subnet_discloses_endpoints_and_self() {
    let p = plan(
        &targets("192.168.1.0", "192.168.1.255", &[], &[]),
        &Os::new(),
    )
    .unwrap();
    assert_eq!(p.next_hops.len(), 253);
    assert_eq!(
        p.excluded.get(&ip("192.168.1.10")),
        Some(&ExcludedReason::OwnAddress)
    );
    assert_eq!(
        p.excluded.get(&ip("192.168.1.0")),
        Some(&ExcludedReason::NetworkAddress)
    );
    assert_eq!(
        p.excluded.get(&ip("192.168.1.255")),
        Some(&ExcludedReason::BroadcastAddress)
    );
}
#[test]
fn singleton_provenance_survives_overlap_and_exclusion_wins() {
    let me = ip("192.168.1.10");
    assert!(
        plan(
            &targets("192.168.1.0", "192.168.1.255", &[me], &[]),
            &Os::new()
        )
        .is_err()
    );
    let p = plan(
        &targets("192.168.1.0", "192.168.1.255", &[me], &[(me, me)]),
        &Os::new(),
    )
    .unwrap();
    assert!(!p.excluded.contains_key(&me));
}
#[test]
fn every_target_is_routed_and_interior_vpn_is_refused() {
    let t = targets("192.168.1.20", "192.168.1.22", &[], &[]);
    let mut o = Os::new();
    o.overrides.insert(
        ip("192.168.1.21"),
        Route {
            ifname: "utun0".into(),
            ifindex: 8,
            local: false,
            gateway: None,
        },
    );
    assert!(plan(&t, &o).is_err());
    assert!(o.seen.borrow().contains(&ip("192.168.1.21")));
}
#[test]
fn different_gateways_on_same_interface_are_valid_and_remote_endpoints_not_classified() {
    let t = targets("203.0.113.0", "203.0.113.1", &[], &[]);
    let mut o = Os::new();
    for (a, g) in [
        ("203.0.113.0", "192.168.1.1"),
        ("203.0.113.1", "192.168.1.2"),
    ] {
        o.overrides.insert(
            ip(a),
            Route {
                ifname: "en0".into(),
                ifindex: 2,
                local: false,
                gateway: Some(ip(g)),
            },
        );
    }
    let p = plan(&t, &o).unwrap();
    assert_eq!(p.next_hops[&ip("203.0.113.0")], ip("192.168.1.1"));
    assert_eq!(p.next_hops[&ip("203.0.113.1")], ip("192.168.1.2"));
}
#[test]
fn point_to_point_31_and_host_32_have_no_subnet_endpoints() {
    for len in [31, 32] {
        let mut o = Os::new();
        o.interfaces[0].ipv4_prefixes[0].length = len;
        let p = plan(&targets("192.168.1.11", "192.168.1.11", &[], &[]), &o).unwrap();
        assert_eq!(p.next_hops.len(), 1);
    }
}
#[test]
fn forbidden_explicit_addresses_refused_but_range_addresses_disclosed() {
    for s in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"] {
        let a = ip(s);
        assert!(plan(&targets(s, s, &[a], &[]), &Os::new()).is_err());
    }
    let p = plan(&targets("0.255.255.255", "1.0.0.0", &[], &[]), &Os::new()).unwrap();
    assert_eq!(p.next_hops.len(), 1);
    assert_eq!(p.excluded.len(), 1);
}
#[test]
fn physical_limits_apply_before_routes_and_after_readonly_exclusions() {
    assert!(PhysicalTargets::new(&[(ip("0.0.0.0"), ip("255.255.255.255"))], &[], &[]).is_err());
    let o = Os::new();
    assert!(plan(&targets("10.0.0.0", "10.0.4.0", &[], &[]), &o).is_err());
    assert!(o.seen.borrow().is_empty());
    assert_eq!(
        plan(&targets("10.0.0.0", "10.0.3.255", &[], &[]), &o)
            .unwrap()
            .next_hops
            .len(),
        1024
    );
}
#[test]
fn aliases_bad_interfaces_and_invalid_source_mac_fail_executable_validation() {
    let t = targets("192.168.1.20", "192.168.1.20", &[], &[]);
    let mut o = Os::new();
    o.interfaces[0].iface.ipv4.push(ip("192.168.1.11"));
    assert!(plan(&t, &o).is_err());
    for mac in [
        None,
        Some([0; 6]),
        Some([2, 0, 0, 0, 0, 0]),
        Some([1, 2, 3, 4, 5, 6]),
    ] {
        let mut o = Os::new();
        o.interfaces[0].iface.mac = mac;
        let p = plan(&t, &o).unwrap();
        assert!(p.validate_executable().is_err());
    }
    let mut o = Os::new();
    o.interfaces[0].iface.ethernet = false;
    assert!(plan(&t, &o).is_err());
}
#[test]
fn expired_or_cancelled_snapshot_never_looks_up_routes() {
    let t = targets("192.168.1.20", "192.168.1.20", &[], &[]);
    let o = Os::new();
    assert!(plan_physical(&t, &o, &o, Instant::now(), &|| false).is_err());
    assert!(plan_physical(&t, &o, &o, Instant::now() + OBSERVATION_BUDGET, &|| true).is_err());
    assert!(o.seen.borrow().is_empty());
}
#[test]
fn candidate_boundary_and_exclusions_precede_expansion() {
    assert_eq!(
        PhysicalTargets::new(&[(ip("10.0.0.0"), ip("10.0.7.255"))], &[], &[])
            .unwrap()
            .addresses()
            .len(),
        2048
    );
    assert!(PhysicalTargets::new(&[(ip("10.0.0.0"), ip("10.0.8.0"))], &[], &[]).is_err());
    assert_eq!(
        PhysicalTargets::new(
            &[(ip("0.0.0.0"), ip("255.255.255.255"))],
            &[],
            &[
                (ip("0.0.0.0"), ip("9.255.255.255")),
                (ip("10.0.0.1"), ip("255.255.255.255"))
            ]
        )
        .unwrap()
        .addresses(),
        &[ip("10.0.0.0")]
    );
}
#[test]
fn own_addresses_on_other_interfaces_and_explicit_subnet_endpoints_are_refused() {
    let mut o = Os::new();
    let mut other = observation();
    other.iface.index = 3;
    other.iface.name = "en1".into();
    other.iface.ipv4 = vec![ip("10.0.0.1")];
    other.ipv4_prefixes = vec![Ipv4Prefix {
        address: ip("10.0.0.1"),
        length: 24,
    }];
    o.interfaces.push(other);
    for a in ["10.0.0.1", "192.168.1.0", "192.168.1.255"] {
        assert!(plan(&targets(a, a, &[ip(a)], &[]), &o).is_err());
    }
    let p = plan(&targets("10.0.0.1", "10.0.0.2", &[], &[]), &o).unwrap();
    assert_eq!(p.excluded[&ip("10.0.0.1")], ExcludedReason::OwnAddress);
}
#[test]
fn down_interface_prefix_does_not_classify_remote_endpoint() {
    let mut o = Os::new();
    let mut down = observation();
    down.iface.index = 3;
    down.iface.name = "en1".into();
    down.iface.up = false;
    down.iface.ipv4 = vec![ip("10.0.0.1")];
    down.ipv4_prefixes = vec![Ipv4Prefix {
        address: ip("10.0.0.1"),
        length: 24,
    }];
    o.interfaces.push(down);
    o.overrides.insert(
        ip("10.0.0.0"),
        Route {
            ifname: "en0".into(),
            ifindex: 2,
            local: false,
            gateway: Some(ip("192.168.1.1")),
        },
    );
    let p = plan(&targets("10.0.0.0", "10.0.0.0", &[ip("10.0.0.0")], &[]), &o).unwrap();
    assert_eq!(p.next_hops.len(), 1);
}
