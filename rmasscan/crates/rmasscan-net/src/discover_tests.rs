use std::net::Ipv4Addr;

use rmasscan_core::massip::MassIp;

use super::*;

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

fn iface(name: &str, index: u32, mac: Option<[u8; 6]>, addrs: &[Ipv4Addr]) -> Iface {
    Iface {
        name: name.to_string(),
        index,
        device_id: name.to_string(),
        description: None,
        mac,
        mac_masked: false,
        ethernet: true,
        up: true,
        ipv4: addrs.to_vec(),
    }
}

const MAC_A: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 1];
const MAC_B: [u8; 6] = [0x02, 0xbb, 0, 0, 0, 2];

fn route(ifindex: u32, ifname: &str, gateway: Option<Ipv4Addr>, local: bool) -> Route {
    Route {
        ifindex,
        ifname: ifname.to_string(),
        gateway,
        local,
    }
}

/// Синтетическая таблица: правила (от, до, маршрут или None), первое подходящее.
#[derive(Default)]
struct FakeRoutes {
    rules: Vec<(u32, u32, Option<Route>)>,
    defaults: Vec<Route>,
    defaults_panic: bool,
}

impl FakeRoutes {
    fn rule(mut self, from: Ipv4Addr, to: Ipv4Addr, r: Option<Route>) -> Self {
        self.rules.push((u32::from(from), u32::from(to), r));
        self
    }
}

impl RouteTable for FakeRoutes {
    fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, NetError> {
        let d = u32::from(dst);
        for (a, b, r) in &self.rules {
            if *a <= d && d <= *b {
                return Ok(r.clone());
            }
        }
        Ok(None)
    }
    fn default_routes(&self) -> Result<Vec<Route>, NetError> {
        assert!(!self.defaults_panic, "default_routes must not be consulted");
        Ok(self.defaults.clone())
    }
}

struct FakeIfaces(Vec<Iface>);

impl Interfaces for FakeIfaces {
    fn list(&self) -> Result<Vec<Iface>, NetError> {
        Ok(self.0.clone())
    }
}

fn targets(first: Ipv4Addr, last: Ipv4Addr) -> Targets {
    Targets {
        first,
        last,
        single: first == last,
    }
}

fn eth0_world() -> (FakeRoutes, FakeIfaces) {
    // eth0 192.0.2.5/24 (default via 192.0.2.1), eth1 10.1.0.5/16 on-link
    let routes = FakeRoutes::default()
        .rule(
            ip(10, 1, 0, 0),
            ip(10, 1, 255, 255),
            Some(route(3, "eth1", None, false)),
        )
        .rule(
            ip(0, 0, 0, 0),
            ip(255, 255, 255, 255),
            Some(route(2, "eth0", Some(ip(192, 0, 2, 1)), false)),
        );
    let ifs = FakeIfaces(vec![
        iface("eth0", 2, Some(MAC_A), &[ip(192, 0, 2, 5)]),
        iface("eth1", 3, Some(MAC_B), &[ip(10, 1, 0, 5), ip(10, 1, 0, 6)]),
    ]);
    (routes, ifs)
}

#[test]
fn probe_targets_skip_zero_loopback_multicast_and_broadcast() {
    let mut m = MassIp::new();
    m.ipv4_mut().add_range(0, 0xFFFF_FFFE); // 0.0.0.0/0 минус 255.255.255.255
    let t = probe_targets(&m).expect("unicast");
    assert_eq!(t.first, ip(1, 0, 0, 0));
    assert_eq!(t.last, ip(223, 255, 255, 255));
    assert!(!t.single);

    let mut lo = MassIp::new();
    lo.ipv4_mut().add_range(0x7f00_0000, 0x7fff_ffff);
    assert_eq!(probe_targets(&lo), None);

    let mut one = MassIp::new();
    one.ipv4_mut()
        .add_range(u32::from(ip(10, 0, 0, 1)), u32::from(ip(10, 0, 0, 1)));
    let t = probe_targets(&one).expect("one");
    assert!(t.single);
    assert_eq!(t.first, ip(10, 0, 0, 1));
    assert_eq!(probe_targets(&MassIp::new()), None);
}

#[test]
fn probe_targets_clip_ranges_that_straddle_non_unicast_edges() {
    let mut m = MassIp::new();
    m.ipv4_mut().add_range(0x7e00_0000, 0x8100_0000); // 126.0.0.0 .. 129.0.0.0 пересекает 127/8
    m.ipv4_mut().add_range(0xDF00_0000, 0xFFFF_FFFF); // 223.0.0.0 .. broadcast
    let t = probe_targets(&m).expect("unicast");
    assert_eq!(t.first, ip(126, 0, 0, 0));
    assert_eq!(t.last, ip(223, 255, 255, 255));
    let mut edge = MassIp::new();
    edge.ipv4_mut().add_range(0x7fff_ffff, 0x8000_0000);
    let t = probe_targets(&edge).expect("edge");
    assert_eq!(t.first, ip(128, 0, 0, 0));
    assert!(t.single);
}

#[test]
fn route_to_target_picks_its_interface_not_the_default() {
    let (routes, ifs) = eth0_world();
    let t = targets(ip(10, 1, 3, 3), ip(10, 1, 3, 3));
    let d = detect(&t, &Overrides::default(), &routes, &ifs).unwrap();
    assert_eq!(d.iface.name, "eth1");
    assert_eq!(d.iface_source, Source::Detected);
    assert_eq!(d.source_ipv4, (ip(10, 1, 0, 5), Source::Detected));
    assert_eq!(d.source_mac, (MAC_B, Source::Detected));
}

#[test]
fn default_route_is_used_when_the_target_is_remote() {
    let (routes, ifs) = eth0_world();
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let d = detect(&t, &Overrides::default(), &routes, &ifs).unwrap();
    assert_eq!(d.iface.name, "eth0");
    assert_eq!(
        d.next_hop,
        NextHop::Resolve {
            ip: ip(192, 0, 2, 1),
            why: NextHopWhy::RouteGateway
        }
    );
}

#[test]
fn local_target_is_refused_with_the_interface_hint() {
    let routes = FakeRoutes::default().rule(
        ip(0, 0, 0, 0),
        ip(255, 255, 255, 255),
        Some(route(1, "lo0", None, true)),
    );
    let ifs = FakeIfaces(vec![iface("lo0", 1, None, &[ip(127, 0, 0, 1)])]);
    let t = targets(ip(198, 18, 0, 2), ip(198, 18, 0, 2));
    let e = detect(&t, &Overrides::default(), &routes, &ifs).unwrap_err();
    assert_eq!(
        e,
        DetectError::LocalTarget {
            ip: ip(198, 18, 0, 2),
            ifname: "lo0".into()
        }
    );
    assert_eq!(
        e.to_string(),
        "FAIL: 198.18.0.2 is an address of this host (route via lo0)\n    [hint] try \"--interface ethX\" and \"--router-ip 192.0.2.1\""
    );
}

#[test]
fn targets_on_two_interfaces_are_refused() {
    let (routes, ifs) = eth0_world();
    let t = targets(ip(10, 1, 0, 9), ip(11, 0, 0, 1));
    let e = detect(&t, &Overrides::default(), &routes, &ifs).unwrap_err();
    assert_eq!(
        e,
        DetectError::SplitRoutes {
            first: (ip(10, 1, 0, 9), "eth1".into()),
            last: (ip(11, 0, 0, 1), "eth0".into())
        }
    );
    // тот же интерфейс, другой шлюз: тоже отказ
    let routes = FakeRoutes::default()
        .rule(
            ip(1, 0, 0, 0),
            ip(1, 255, 255, 255),
            Some(route(2, "eth0", Some(ip(192, 0, 2, 1)), false)),
        )
        .rule(
            ip(2, 0, 0, 0),
            ip(2, 255, 255, 255),
            Some(route(2, "eth0", Some(ip(192, 0, 2, 2)), false)),
        );
    let t = targets(ip(1, 0, 0, 1), ip(2, 0, 0, 1));
    assert!(matches!(
        detect(&t, &Overrides::default(), &routes, &ifs),
        Err(DetectError::SplitRoutes { .. })
    ));
}

#[test]
fn explicit_adapter_by_name_device_id_and_friendly_name() {
    let mut w = iface("Ethernet 2", 7, Some(MAC_A), &[ip(198, 18, 0, 1)]);
    w.device_id = "\\Device\\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}".into();
    w.description = Some("Ethernet 2".into());
    let ifs = FakeIfaces(vec![iface("lo", 1, None, &[]), w]);
    let routes = FakeRoutes::default();
    let ov = |a: &str| Overrides {
        adapter: Some(a.into()),
        router_mac: Some(MAC_B),
        ..Default::default()
    };
    let t = targets(ip(198, 18, 0, 2), ip(198, 18, 0, 2));
    for a in [
        "Ethernet 2",
        "ethernet 2",
        "\\Device\\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}",
        "\\device\\npf_{c4617223-a264-44f4-bdc8-0ea27f02cc40}",
    ] {
        let d = detect(&t, &ov(a), &routes, &ifs).unwrap();
        assert_eq!(d.iface.index, 7, "{a}");
        assert_eq!(d.iface_source, Source::Given);
    }
}

#[test]
fn unknown_adapter_is_refused_before_anything_else() {
    struct Panics;
    impl RouteTable for Panics {
        fn lookup(&self, _: Ipv4Addr) -> Result<Option<Route>, NetError> {
            panic!("routes consulted")
        }
        fn default_routes(&self) -> Result<Vec<Route>, NetError> {
            panic!("routes consulted")
        }
    }
    let ifs = FakeIfaces(vec![iface("eth0", 2, Some(MAC_A), &[ip(192, 0, 2, 5)])]);
    let ov = Overrides {
        adapter: Some("nosuch0".into()),
        ..Default::default()
    };
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let e = detect(&t, &ov, &Panics, &ifs).unwrap_err();
    assert_eq!(e, DetectError::NoSuchAdapter("nosuch0".into()));
    let e = detect_offline(&t, &ov, &Panics, &ifs).unwrap_err();
    assert_eq!(e, DetectError::NoSuchAdapter("nosuch0".into()));
}

#[test]
fn non_ethernet_or_down_interface_is_refused() {
    let (routes, _) = eth0_world();
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let mut tun = iface("eth0", 2, Some(MAC_A), &[ip(192, 0, 2, 5)]);
    tun.ethernet = false;
    let e = detect(&t, &Overrides::default(), &routes, &FakeIfaces(vec![tun])).unwrap_err();
    assert_eq!(
        e,
        DetectError::NotUsable {
            name: "eth0".into(),
            reason: "not Ethernet"
        }
    );
    let mut down = iface("eth0", 2, Some(MAC_A), &[ip(192, 0, 2, 5)]);
    down.up = false;
    let ov = Overrides {
        adapter: Some("eth0".into()),
        ..Default::default()
    };
    let e = detect(&t, &ov, &routes, &FakeIfaces(vec![down])).unwrap_err();
    assert_eq!(
        e,
        DetectError::NotUsable {
            name: "eth0".into(),
            reason: "down"
        }
    );
}

#[test]
fn wifi_iftype_counts_as_ethernet() {
    // Windows IfType 71 приходит от бэкенда как ethernet = true: логика принимает такой интерфейс.
    let wifi = iface("Wi-Fi", 9, Some(MAC_A), &[ip(192, 168, 1, 7)]);
    let routes = FakeRoutes::default().rule(
        ip(0, 0, 0, 0),
        ip(255, 255, 255, 255),
        Some(route(9, "Wi-Fi", Some(ip(192, 168, 1, 1)), false)),
    );
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let d = detect(&t, &Overrides::default(), &routes, &FakeIfaces(vec![wifi])).unwrap();
    assert_eq!(d.iface.name, "Wi-Fi");
}

#[test]
fn first_ipv4_in_os_order_is_the_source() {
    let (routes, ifs) = eth0_world();
    let t = targets(ip(10, 1, 3, 3), ip(10, 1, 3, 3));
    let d = detect(&t, &Overrides::default(), &routes, &ifs).unwrap();
    assert_eq!(d.source_ipv4.0, ip(10, 1, 0, 5));
    let ov = Overrides {
        adapter_ip: Some(ip(10, 1, 0, 6)),
        ..Default::default()
    };
    let d = detect(&t, &ov, &routes, &ifs).unwrap();
    assert_eq!(d.source_ipv4, (ip(10, 1, 0, 6), Source::Given));
}

#[test]
fn no_ipv4_names_the_source_ip_hint() {
    let (routes, _) = eth0_world();
    let ifs = FakeIfaces(vec![iface("eth0", 2, Some(MAC_A), &[])]);
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let e = detect(&t, &Overrides::default(), &routes, &ifs).unwrap_err();
    assert_eq!(e, DetectError::NoIpv4("eth0".into()));
    assert!(e.to_string().contains("--source-ip 198.51.100.17"));
    // адрес задан вручную: ошибки нет
    let ov = Overrides {
        adapter_ip: Some(ip(192, 0, 2, 9)),
        ..Default::default()
    };
    assert!(detect(&t, &ov, &routes, &ifs).is_ok());
}

#[test]
fn masked_mac_is_refused_never_substituted() {
    let (routes, _) = eth0_world();
    let mut m = iface("eth0", 2, Some([0x02, 0, 0, 0, 0, 0]), &[ip(192, 0, 2, 5)]);
    m.mac_masked = true;
    let ifs = FakeIfaces(vec![m]);
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let e = detect(&t, &Overrides::default(), &routes, &ifs).unwrap_err();
    assert_eq!(e, DetectError::MacMasked("eth0".into()));
    // с --adapter-mac пользователь обходит маскирование
    let ov = Overrides {
        adapter_mac: Some(MAC_A),
        ..Default::default()
    };
    let d = detect(&t, &ov, &routes, &ifs).unwrap();
    assert_eq!(d.source_mac, (MAC_A, Source::Given));
}

#[test]
fn zero_or_multicast_mac_is_refused() {
    let (routes, _) = eth0_world();
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    for mac in [None, Some([0u8; 6]), Some([0x01, 0, 0x5e, 0, 0, 1])] {
        let ifs = FakeIfaces(vec![iface("eth0", 2, mac, &[ip(192, 0, 2, 5)])]);
        let e = detect(&t, &Overrides::default(), &routes, &ifs).unwrap_err();
        assert_eq!(e, DetectError::NoMac("eth0".into()), "{mac:?}");
    }
    let ifs = FakeIfaces(vec![iface("eth0", 2, Some(MAC_A), &[ip(192, 0, 2, 5)])]);
    let ov = Overrides {
        adapter_mac: Some([0; 6]),
        ..Default::default()
    };
    assert_eq!(
        detect(&t, &ov, &routes, &ifs).unwrap_err(),
        DetectError::NoMac("eth0".into())
    );
}

#[test]
fn router_mac_override_skips_resolution_entirely() {
    let (_, ifs) = eth0_world();
    // таблица по умолчанию паникует: разрешение следующего хопа не нужно
    let routes = FakeRoutes {
        defaults_panic: true,
        ..Default::default()
    }
    .rule(
        ip(10, 1, 0, 0),
        ip(10, 1, 255, 255),
        Some(route(3, "eth1", None, false)),
    );
    let t = targets(ip(10, 1, 0, 8), ip(10, 1, 0, 20));
    let ov = Overrides {
        router_mac: Some(MAC_B),
        router_ip: Some(ip(10, 1, 0, 1)),
        ..Default::default()
    };
    let d = detect(&t, &ov, &routes, &ifs).unwrap();
    assert_eq!(d.next_hop, NextHop::Mac(MAC_B, Source::Given));
}

#[test]
fn router_ip_override_is_resolved() {
    let (routes, ifs) = eth0_world();
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let ov = Overrides {
        router_ip: Some(ip(192, 0, 2, 77)),
        ..Default::default()
    };
    let d = detect(&t, &ov, &routes, &ifs).unwrap();
    assert_eq!(
        d.next_hop,
        NextHop::Resolve {
            ip: ip(192, 0, 2, 77),
            why: NextHopWhy::Given
        }
    );
}

#[test]
fn gateway_route_resolves_the_gateway() {
    let (routes, ifs) = eth0_world();
    let t = targets(ip(8, 8, 8, 8), ip(9, 9, 9, 9));
    let d = detect(&t, &Overrides::default(), &routes, &ifs).unwrap();
    assert_eq!(
        d.next_hop,
        NextHop::Resolve {
            ip: ip(192, 0, 2, 1),
            why: NextHopWhy::RouteGateway
        }
    );
}

#[test]
fn on_link_single_target_resolves_the_target_itself() {
    let (routes, ifs) = eth0_world();
    let t = targets(ip(10, 1, 4, 4), ip(10, 1, 4, 4));
    let d = detect(&t, &Overrides::default(), &routes, &ifs).unwrap();
    assert_eq!(
        d.next_hop,
        NextHop::Resolve {
            ip: ip(10, 1, 4, 4),
            why: NextHopWhy::OnLinkTarget
        }
    );
}

#[test]
fn on_link_many_targets_resolve_the_interface_default_gateway_from_the_dump() {
    let (mut routes, ifs) = eth0_world();
    routes.defaults = vec![
        route(2, "eth0", Some(ip(192, 0, 2, 1)), false),
        route(3, "eth1", None, false),
        route(3, "eth1", Some(ip(10, 1, 0, 1)), false),
    ];
    let t = targets(ip(10, 1, 4, 4), ip(10, 1, 4, 9));
    let d = detect(&t, &Overrides::default(), &routes, &ifs).unwrap();
    assert_eq!(
        d.next_hop,
        NextHop::Resolve {
            ip: ip(10, 1, 0, 1),
            why: NextHopWhy::InterfaceDefaultGateway
        }
    );
}

#[test]
fn on_link_many_targets_without_gateway_carry_three_hints() {
    let (mut routes, ifs) = eth0_world();
    routes.defaults = vec![route(2, "eth0", Some(ip(192, 0, 2, 1)), false)];
    let t = targets(ip(10, 1, 4, 4), ip(10, 1, 4, 9));
    let e = detect(&t, &Overrides::default(), &routes, &ifs).unwrap_err();
    assert_eq!(
        e,
        DetectError::NoGateway {
            ifname: "eth1".into()
        }
    );
    let text = e.to_string();
    assert_eq!(text.matches("[hint]").count(), 3);
    assert!(text.contains("\"--router-ip 192.0.2.1\""));
    assert!(text.contains("\"--router-mac 66-55-44-33-22-11\""));
    assert!(text.contains("\"--interface eth0\""));
}

#[test]
fn explicit_adapter_with_a_local_route_still_needs_router_ip() {
    // Mac feth: feth4201 без IPv4, цель 198.18.0.2 локальна (lo0).
    let routes = FakeRoutes::default().rule(
        ip(0, 0, 0, 0),
        ip(255, 255, 255, 255),
        Some(route(1, "lo0", None, true)),
    );
    let ifs = FakeIfaces(vec![
        iface("lo0", 1, None, &[ip(127, 0, 0, 1)]),
        iface("feth4201", 20, Some(MAC_A), &[]),
    ]);
    let t = targets(ip(198, 18, 0, 2), ip(198, 18, 0, 2));
    let mut ov = Overrides {
        adapter: Some("feth4201".into()),
        adapter_ip: Some(ip(198, 18, 0, 1)),
        ..Default::default()
    };
    let e = detect(&t, &ov, &routes, &ifs).unwrap_err();
    assert_eq!(
        e,
        DetectError::LocalTarget {
            ip: ip(198, 18, 0, 2),
            ifname: "lo0".into()
        }
    );
    ov.router_ip = Some(ip(198, 18, 0, 2));
    let d = detect(&t, &ov, &routes, &ifs).unwrap();
    assert_eq!(d.iface.name, "feth4201");
    assert_eq!(
        d.next_hop,
        NextHop::Resolve {
            ip: ip(198, 18, 0, 2),
            why: NextHopWhy::Given
        }
    );
}

#[test]
fn adapter_that_differs_from_the_route_interface_names_the_mismatch() {
    let (routes, ifs) = eth0_world();
    let ov = Overrides {
        adapter: Some("eth1".into()),
        ..Default::default()
    };
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let e = detect(&t, &ov, &routes, &ifs).unwrap_err();
    assert_eq!(
        e,
        DetectError::RouteNotViaAdapter {
            ip: ip(8, 8, 8, 8),
            adapter: "eth1".into(),
            route_ifname: "eth0".into()
        }
    );
    assert_eq!(
        e.to_string(),
        "FAIL: route doesn't match interface: 8.8.8.8 is routed via eth0, not \"eth1\"\n    [hint] try \"--router-ip 192.0.2.1\" to specify different router\n    [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP\n    [hint] try \"--interface eth0\" to change interface"
    );
}

#[test]
fn adapter_whose_interface_matches_the_route_proceeds() {
    let (routes, ifs) = eth0_world();
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let ov = Overrides {
        adapter: Some("eth0".into()),
        ..Default::default()
    };
    let d = detect(&t, &ov, &routes, &ifs).unwrap();
    assert_eq!(d.iface_source, Source::Given);
    assert_eq!(
        d.next_hop,
        NextHop::Resolve {
            ip: ip(192, 0, 2, 1),
            why: NextHopWhy::RouteGateway
        }
    );
    let t = targets(ip(10, 1, 4, 4), ip(10, 1, 4, 4));
    let ov = Overrides {
        adapter: Some("eth1".into()),
        ..Default::default()
    };
    let d = detect(&t, &ov, &routes, &ifs).unwrap();
    assert_eq!(
        d.next_hop,
        NextHop::Resolve {
            ip: ip(10, 1, 4, 4),
            why: NextHopWhy::OnLinkTarget
        }
    );
}

#[test]
fn adapter_with_no_route_to_the_target_is_no_gateway() {
    let ifs = FakeIfaces(vec![iface("eth0", 2, Some(MAC_A), &[ip(192, 0, 2, 5)])]);
    let ov = Overrides {
        adapter: Some("eth0".into()),
        ..Default::default()
    };
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let e = detect(&t, &ov, &FakeRoutes::default(), &ifs).unwrap_err();
    assert_eq!(
        e,
        DetectError::NoGateway {
            ifname: "eth0".into()
        }
    );
}

#[test]
fn route_interface_missing_from_the_list_is_no_such_adapter() {
    let routes = FakeRoutes::default().rule(
        ip(0, 0, 0, 0),
        ip(255, 255, 255, 255),
        Some(route(99, "ghost0", Some(ip(192, 0, 2, 1)), false)),
    );
    let ifs = FakeIfaces(vec![iface("eth0", 2, Some(MAC_A), &[ip(192, 0, 2, 5)])]);
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let e = detect(&t, &Overrides::default(), &routes, &ifs).unwrap_err();
    assert_eq!(e, DetectError::NoSuchAdapter("ghost0".into()));
}

#[test]
fn no_route_and_local_route_on_the_last_target_are_refused() {
    let (_, ifs) = eth0_world();
    let ok = route(2, "eth0", Some(ip(192, 0, 2, 1)), false);
    let no_last =
        FakeRoutes::default().rule(ip(1, 0, 0, 0), ip(1, 255, 255, 255), Some(ok.clone()));
    let t = targets(ip(1, 0, 0, 1), ip(2, 0, 0, 1));
    assert_eq!(
        detect(&t, &Overrides::default(), &no_last, &ifs).unwrap_err(),
        DetectError::NoRoute(ip(2, 0, 0, 1))
    );
    let local_last = FakeRoutes::default()
        .rule(ip(1, 0, 0, 0), ip(1, 255, 255, 255), Some(ok))
        .rule(
            ip(2, 0, 0, 0),
            ip(2, 255, 255, 255),
            Some(route(1, "lo", None, true)),
        );
    assert_eq!(
        detect(&t, &Overrides::default(), &local_last, &ifs).unwrap_err(),
        DetectError::LocalTarget {
            ip: ip(2, 0, 0, 1),
            ifname: "lo".into()
        }
    );
}

#[test]
fn detect_offline_with_router_mac_still_uses_the_fake_gateway_mac() {
    let (routes, ifs) = eth0_world();
    let ov = Overrides {
        router_mac: Some(MAC_B),
        ..Default::default()
    };
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let d = detect_offline(&t, &ov, &routes, &ifs).unwrap();
    assert_eq!(
        d.next_hop,
        NextHop::Mac([0x66, 0x55, 0x44, 0x33, 0x22, 0x11], Source::Given)
    );
}

#[test]
fn os_errors_propagate_from_lookup_list_and_default_routes_with_fail_prefix() {
    struct Failing {
        lookup: bool,
        defaults: bool,
        inner: FakeRoutes,
    }
    impl RouteTable for Failing {
        fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, NetError> {
            if self.lookup {
                Err(NetError::System("lookup".into()))
            } else {
                self.inner.lookup(dst)
            }
        }
        fn default_routes(&self) -> Result<Vec<Route>, NetError> {
            if self.defaults {
                Err(NetError::System("defaults".into()))
            } else {
                self.inner.default_routes()
            }
        }
    }
    struct FailingIfaces;
    impl Interfaces for FailingIfaces {
        fn list(&self) -> Result<Vec<Iface>, NetError> {
            Err(NetError::System("list".into()))
        }
    }
    let (inner, ifs) = eth0_world();
    let single = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let many = targets(ip(10, 1, 4, 4), ip(10, 1, 4, 9));
    let r = Failing {
        lookup: true,
        defaults: false,
        inner: FakeRoutes::default(),
    };
    let e = detect(&single, &Overrides::default(), &r, &ifs).unwrap_err();
    assert_eq!(e.to_string(), "FAIL: system error: lookup");
    let r = Failing {
        lookup: false,
        defaults: false,
        inner: FakeRoutes::default(),
    };
    let e = detect(&single, &Overrides::default(), &r, &FailingIfaces).unwrap_err();
    assert_eq!(e.to_string(), "FAIL: system error: list");
    let r = Failing {
        lookup: false,
        defaults: true,
        inner,
    };
    let e = detect(&many, &Overrides::default(), &r, &ifs).unwrap_err();
    assert_eq!(e.to_string(), "FAIL: system error: defaults");
    assert!(matches!(e, DetectError::Os(NetError::System(_))));
}

#[test]
fn placeholder_and_multicast_adapter_mac_overrides_are_refused() {
    let (routes, ifs) = eth0_world();
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    for m in [[0x02, 0, 0, 0, 0, 0], [0x01, 0, 0x5e, 0, 0, 1]] {
        let ov = Overrides {
            adapter_mac: Some(m),
            ..Default::default()
        };
        let e = detect(&t, &ov, &routes, &ifs).unwrap_err();
        assert_eq!(e, DetectError::NoMac("eth0".into()), "{m:?}");
        assert!(e.to_string().contains("--source-mac"));
    }
}

/// Публичный предикат, который зовёт и `detect`, и герметичный `--offline` CLI: одно правило на оба пути.
#[test]
fn usable_source_mac_refuses_zero_placeholder_and_group_macs() {
    assert!(usable_source_mac(MAC_A));
    assert!(usable_source_mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    for m in [
        [0; 6],
        [0x02, 0, 0, 0, 0, 0],
        [0x01, 0, 0x5e, 0, 0, 1],
        [0x33, 0x33, 0, 0, 0, 1],
        [0xff; 6],
    ] {
        assert!(!usable_source_mac(m), "{m:?}");
    }
}

#[test]
fn placeholder_mac_reported_unmasked_by_a_backend_is_refused() {
    let (routes, _) = eth0_world();
    let ifs = FakeIfaces(vec![iface(
        "eth0",
        2,
        Some([0x02, 0, 0, 0, 0, 0]),
        &[ip(192, 0, 2, 5)],
    )]);
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let e = detect(&t, &Overrides::default(), &routes, &ifs).unwrap_err();
    assert_eq!(e, DetectError::NoMac("eth0".into()));
}

#[test]
fn no_route_is_refused() {
    let ifs = FakeIfaces(vec![iface("eth0", 2, Some(MAC_A), &[ip(192, 0, 2, 5)])]);
    let t = targets(ip(8, 8, 8, 8), ip(8, 8, 8, 8));
    let e = detect(&t, &Overrides::default(), &FakeRoutes::default(), &ifs).unwrap_err();
    assert_eq!(e, DetectError::NoRoute(ip(8, 8, 8, 8)));
}

#[test]
fn detect_offline_never_consults_routes_for_the_next_hop() {
    let (mut routes, ifs) = eth0_world();
    routes.defaults_panic = true;
    // on-link несколько целей без шлюза: detect отказал бы NoGateway, offline шлюз не ищет
    let t = targets(ip(10, 1, 4, 4), ip(10, 1, 4, 9));
    let d = detect_offline(&t, &Overrides::default(), &routes, &ifs).unwrap();
    assert_eq!(d.iface.name, "eth1");
    assert_eq!(d.source_ipv4.0, ip(10, 1, 0, 5));
    // следующий хоп это заглушка C: фиктивный MAC шлюза 66-55-44-33-22-11
    assert_eq!(
        d.next_hop,
        NextHop::Mac([0x66, 0x55, 0x44, 0x33, 0x22, 0x11], Source::Given)
    );
}

#[test]
fn iflist_text_marks_masked_macs_and_lists_ipv4s_and_defaults() {
    let mut m = iface(
        "en0",
        5,
        Some([0x02, 0, 0, 0, 0, 0]),
        &[ip(192, 0, 2, 5), ip(192, 0, 2, 6)],
    );
    m.mac_masked = true;
    let mut dn = iface("utun3", 6, None, &[]);
    dn.ethernet = false;
    dn.up = false;
    let ok = iface("eth0", 2, Some(MAC_A), &[ip(10, 0, 0, 2)]);
    let text = iflist_text(
        &[ok, m, dn],
        &[
            route(2, "eth0", Some(ip(10, 0, 0, 1)), false),
            route(5, "en0", None, false),
        ],
    );
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 5, "{text}");
    assert!(lines[0].starts_with("eth0 ") && lines[0].contains("02-aa-00-00-00-01"));
    assert!(
        lines[0].contains("10.0.0.2") && lines[0].contains(" up") && lines[0].contains("ethernet")
    );
    assert!(lines[1].contains("masked") && !lines[1].contains("02-00-00-00-00-00"));
    assert!(lines[1].contains("192.0.2.5,192.0.2.6"));
    assert!(lines[2].contains("none") && lines[2].contains("down") && lines[2].contains("other"));
    assert_eq!(lines[3], "default via 10.0.0.1 dev eth0");
    assert_eq!(lines[4], "default dev en0");
    assert!(text.ends_with('\n'));
}

#[test]
fn every_detect_error_text_contains_its_masscan_hint() {
    let a = ip(192, 0, 2, 1);
    let table: Vec<(DetectError, Vec<&str>)> = vec![
        (
            DetectError::NoUnicastTargets,
            vec!["FAIL: no unicast target addresses", "\n    [hint] "],
        ),
        (
            DetectError::NoRoute(a),
            vec![
                "FAIL: could not determine default interface\n    [hint] try \"--interface ethX\"",
            ],
        ),
        (
            DetectError::LocalTarget {
                ip: a,
                ifname: "lo0".into(),
            },
            vec![
                "is an address of this host (route via lo0)\n    [hint] try \"--interface ethX\" and \"--router-ip 192.0.2.1\"",
            ],
        ),
        (
            DetectError::SplitRoutes {
                first: (a, "eth0".into()),
                last: (ip(192, 0, 2, 2), "eth1".into()),
            },
            vec![
                "192.0.2.1 via eth0",
                "192.0.2.2 via eth1",
                "\n    [hint] try \"--interface ethX\"",
            ],
        ),
        (
            DetectError::NoSuchAdapter("x".into()),
            vec!["\n    [hint] did you spell the name correctly?"],
        ),
        (
            DetectError::NotUsable {
                name: "x".into(),
                reason: "down",
            },
            vec![
                "interface \"x\" is not usable: down",
                "\n    [hint] try \"--interface ethX\"",
            ],
        ),
        (
            DetectError::NoIpv4("x".into()),
            vec![
                "FAIL: failed to detect IP of interface \"x\"\n    [hint] did you spell the name correctly?\n    [hint] if it has no IP address, manually set with something like \"--source-ip 198.51.100.17\"",
            ],
        ),
        (
            DetectError::MacMasked("x".into()),
            vec![
                "FAIL: MAC of interface \"x\" is os-masked (Darwin hides MACs from unprivileged processes)\n    [hint] run as root, or try something like \"--source-mac 00-11-22-33-44-55\"",
            ],
        ),
        (
            DetectError::NoMac("x".into()),
            vec![
                "FAIL: failed to detect MAC address of interface: \"x\"\n [hint] try something like \"--source-mac 00-11-22-33-44-55\"",
            ],
        ),
        (
            DetectError::NoGateway { ifname: "x".into() },
            vec![
                "    [hint] try \"--router-ip 192.0.2.1\" to specify different router",
                "    [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP",
                "    [hint] try \"--interface eth0\" to change interface",
            ],
        ),
        (
            DetectError::Os(NetError::UnsupportedPlatform),
            vec!["FAIL: raw packet I/O is not implemented"],
        ),
        (
            DetectError::RouteNotViaAdapter {
                ip: a,
                adapter: "x".into(),
                route_ifname: "y".into(),
            },
            vec![
                "FAIL: route doesn't match interface: 192.0.2.1 is routed via y, not \"x\"\n    [hint] try \"--router-ip 192.0.2.1\" to specify different router",
                "    [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP",
                "    [hint] try \"--interface eth0\" to change interface",
            ],
        ),
    ];
    for (e, needles) in table {
        let s = e.to_string();
        for n in needles {
            assert!(s.contains(n), "{s:?} lacks {n:?}");
        }
        assert!(s.starts_with("FAIL: "), "{s:?}");
    }
}
