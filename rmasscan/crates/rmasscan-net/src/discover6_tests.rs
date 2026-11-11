//! Обнаружение IPv6 и смешанного скана на синтетических таблицах (любая ОС). Адреса: ULA `fd00::/8`, документационные
//! `2001:db8::/32`, `192.0.2.0/24`, `203.0.113.0/24`, стенд `198.18.0.0/15`; MAC только локальные `02:…`.

use std::net::{Ipv4Addr, Ipv6Addr};

use rmasscan_core::massip::MassIp;

use super::*;

const MAC_A: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 1];
const MAC_B: [u8; 6] = [0x02, 0xbb, 0, 0, 0, 2];
const MAC_GW: [u8; 6] = [0x02, 0xcc, 0, 0, 0, 3];

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn iface(name: &str, index: u32, ethernet: bool, mac: Option<[u8; 6]>, ipv4: &[&str]) -> Iface {
    Iface {
        name: name.to_string(),
        index,
        device_id: name.to_string(),
        description: None,
        mac,
        mac_masked: false,
        ethernet,
        up: true,
        ipv4: ipv4.iter().map(|s| v4(s)).collect(),
    }
}

fn r6(ifindex: u32, ifname: &str, gateway: Option<&str>, source: Option<&str>) -> RouteV6 {
    RouteV6 {
        ifindex,
        ifname: ifname.to_string(),
        gateway: gateway.map(v6),
        source: source.map(v6),
        local: false,
    }
}

fn r4(ifindex: u32, ifname: &str, gateway: Option<&str>) -> Route {
    Route {
        ifindex,
        ifname: ifname.to_string(),
        gateway: gateway.map(v4),
        local: false,
    }
}

/// Таблица IPv4 и IPv6: правила (от, до, маршрут), первое подходящее; журнал обращений к швам IPv6.
#[derive(Default)]
struct World {
    rules4: Vec<(u32, u32, Option<Route>)>,
    rules6: Vec<(u128, u128, Option<RouteV6>)>,
    defaults6: Vec<RouteV6>,
    ifaces: Vec<Iface>,
    addrs6: Vec<(u32, Vec<Ipv6Addr>)>,
    v6_calls: std::cell::Cell<u32>,
}

impl World {
    fn rule4(mut self, from: &str, to: &str, r: Option<Route>) -> Self {
        self.rules4
            .push((u32::from(v4(from)), u32::from(v4(to)), r));
        self
    }
    fn rule6(mut self, from: &str, to: &str, r: Option<RouteV6>) -> Self {
        self.rules6
            .push((u128::from(v6(from)), u128::from(v6(to)), r));
        self
    }
    fn iface(mut self, i: Iface, addrs6: &[&str]) -> Self {
        self.addrs6
            .push((i.index, addrs6.iter().map(|s| v6(s)).collect()));
        self.ifaces.push(i);
        self
    }
}

impl RouteTable for World {
    fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, NetError> {
        let d = u32::from(dst);
        Ok(self
            .rules4
            .iter()
            .find(|(a, b, _)| *a <= d && d <= *b)
            .and_then(|(_, _, r)| r.clone()))
    }
    fn default_routes(&self) -> Result<Vec<Route>, NetError> {
        Ok(Vec::new())
    }
    fn lookup_v6(&self, dst: Ipv6Addr) -> Result<Option<RouteV6>, NetError> {
        self.v6_calls.set(self.v6_calls.get() + 1);
        let d = u128::from(dst);
        Ok(self
            .rules6
            .iter()
            .find(|(a, b, _)| *a <= d && d <= *b)
            .and_then(|(_, _, r)| r.clone()))
    }
    fn default_routes_v6(&self) -> Result<Vec<RouteV6>, NetError> {
        self.v6_calls.set(self.v6_calls.get() + 1);
        Ok(self.defaults6.clone())
    }
}

impl Interfaces for World {
    fn list(&self) -> Result<Vec<Iface>, NetError> {
        Ok(self.ifaces.clone())
    }
    fn ipv6_addrs(&self, iface: &Iface) -> Result<Vec<Ipv6Addr>, NetError> {
        self.v6_calls.set(self.v6_calls.get() + 1);
        Ok(self
            .addrs6
            .iter()
            .find(|(i, _)| *i == iface.index)
            .map(|(_, a)| a.clone())
            .unwrap_or_default())
    }
}

fn t6(first: &str, last: &str) -> Targets6 {
    Targets6 {
        first: v6(first),
        last: v6(last),
        single: first == last,
    }
}

fn t4(first: &str, last: &str) -> Targets {
    Targets {
        first: v4(first),
        last: v4(last),
        single: first == last,
    }
}

/// Mac стенда: `en0` это NIC стенда (ULA `fd00:198:18::/64`, link-local первым), маршрут по умолчанию IPv6 и IPv4
/// идёт в VPN `utun3` (не Ethernet), `en1` это второй Ethernet с IPv4 `192.0.2.0/24` и IPv6 `2001:db8:1::/64`.
fn stand() -> World {
    World::default()
        .iface(
            iface("lo0", 1, false, None, &["127.0.0.1"]),
            &["::1", "fe80::1"],
        )
        .iface(
            iface("en0", 4, true, Some(MAC_A), &["198.18.0.1"]),
            &["fe80::aa", "fd00:198:18::1"],
        )
        .iface(
            iface("en1", 5, true, Some(MAC_B), &["192.0.2.5"]),
            &["fe80::bb", "2001:db8:1::5"],
        )
        .iface(
            iface("utun3", 9, false, None, &["198.19.0.2"]),
            &["fe80::99", "fd12:3456::2"],
        )
        .rule4("198.18.0.0", "198.18.0.3", Some(r4(4, "en0", None)))
        .rule4("192.0.2.0", "192.0.2.255", Some(r4(5, "en1", None)))
        .rule4("0.0.0.0", "255.255.255.255", Some(r4(9, "utun3", None)))
        .rule6(
            "fd00:198:18::",
            "fd00:198:18::ffff:ffff:ffff:ffff",
            Some(r6(4, "en0", None, None)),
        )
        .rule6(
            "2001:db8:1::",
            "2001:db8:1::ffff:ffff:ffff:ffff",
            Some(r6(5, "en1", None, None)),
        )
        .rule6(
            "::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(r6(9, "utun3", None, None)),
        )
}

/// Review Focus 3: конкретный ULA-маршрут стенда сильнее маршрута по умолчанию в VPN; источник это ULA стенда, а не
/// link-local, стоящий в списке первым; VPN (`utun`, не Ethernet) никогда не выбирается; смешанный скан, чьи семьи
/// уходят разными интерфейсами, это явный отказ (CLI: exit 1).
#[test]
fn route_selection_prefers_ula_and_ignores_vpn() {
    let w = stand();
    let ov = Overrides::default();
    let d = detect_v6(&t6("fd00:198:18::2", "fd00:198:18::2"), &ov, &w, &w).unwrap();
    assert_eq!(
        (d.iface.name.as_str(), d.iface_source),
        ("en0", Source::Detected)
    );
    assert_eq!(d.source_ipv6, (v6("fd00:198:18::1"), Source::Detected));
    assert_eq!(d.source_mac, (MAC_A, Source::Detected));
    assert_eq!(
        d.next_hop,
        NextHop6::Resolve {
            ip: v6("fd00:198:18::2"),
            why: NextHopWhy::OnLinkTarget
        }
    );
    // Цель вне стенда уходит маршрутом по умолчанию в VPN: отказ, а не кадр в туннель.
    let e = detect_v6(&t6("fd12:3456::7", "fd12:3456::7"), &ov, &w, &w).unwrap_err();
    assert_eq!(
        e,
        DetectError::NotUsable {
            name: "utun3".into(),
            reason: "not Ethernet"
        }
    );
    // Смешанный скан через один интерфейс: обе части на en0.
    let (d4, d6) = detect_mixed(
        &t4("198.18.0.2", "198.18.0.2"),
        &t6("fd00:198:18::2", "fd00:198:18::2"),
        &ov,
        &w,
        &w,
        false,
    )
    .unwrap();
    assert_eq!((d4.iface.index, d6.iface.index), (4, 4));
    assert_eq!(d4.source_ipv4, (v4("198.18.0.1"), Source::Detected));
    assert_eq!(d6.source_ipv6.0, v6("fd00:198:18::1"));
    // IPv4 через en1, IPv6 через en0: явный отказ с обоими маршрутами.
    let e = detect_mixed(
        &t4("192.0.2.9", "192.0.2.9"),
        &t6("fd00:198:18::2", "fd00:198:18::2"),
        &ov,
        &w,
        &w,
        false,
    )
    .unwrap_err();
    assert_eq!(
        e,
        DetectError::FamiliesSplit {
            v4: (v4("192.0.2.9"), "en1".into()),
            v6: (v6("fd00:198:18::2"), "en0".into()),
        }
    );
    let text = e.to_string();
    assert!(
        text.starts_with(
            "FAIL: IPv4 and IPv6 targets are routed via different interfaces (192.0.2.9 via en1, \
             [fd00:198:18::2] via en0)"
        ),
        "{text}"
    );
    // То же в офлайн-режиме (preflight живого прогона).
    assert!(matches!(
        detect_mixed(
            &t4("192.0.2.9", "192.0.2.9"),
            &t6("fd00:198:18::2", "fd00:198:18::2"),
            &ov,
            &w,
            &w,
            true,
        ),
        Err(DetectError::FamiliesSplit { .. })
    ));
}

/// Источник IPv6: явный `--adapter-ip` как есть; иначе источник маршрута ОС, если это адрес интерфейса; иначе первый
/// пригодный не link-local адрес интерфейса. ULA и `2001:db8::/32` пригодны (C `rawsock-getip6.c:68-71` их
/// отбрасывает); loopback, multicast и `::` никогда.
#[test]
fn ipv6_source_follows_route_then_interface_and_accepts_ula_and_documentation() {
    let ov = Overrides::default();
    let t = t6("2001:db8:1::9", "2001:db8:1::9");
    // `2001:db8:1::5` (документационный) берётся, хотя C его отбросил бы.
    let w = stand();
    let d = detect_v6(&t, &ov, &w, &w).unwrap();
    assert_eq!(d.iface.name, "en1");
    assert_eq!(d.source_ipv6, (v6("2001:db8:1::5"), Source::Detected));
    // Источник маршрута (Linux RTA_PREFSRC, Windows BestSourceAddress) сильнее порядка адресов интерфейса.
    let w = World::default()
        .iface(
            iface("eth0", 2, true, Some(MAC_A), &[]),
            &["fe80::aa", "2001:db8:1::5", "2001:db8:1::6"],
        )
        .rule6(
            "::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(r6(2, "eth0", Some("fe80::1"), Some("2001:db8:1::6"))),
        );
    let d = detect_v6(&t, &ov, &w, &w).unwrap();
    assert_eq!(d.source_ipv6, (v6("2001:db8:1::6"), Source::Detected));
    // Источник маршрута, которого нет среди пригодных адресов интерфейса, не берётся.
    let w = World::default()
        .iface(
            iface("eth0", 2, true, Some(MAC_A), &[]),
            &["::1", "ff02::1", "::", "fe80::aa", "fd00::5"],
        )
        .rule6(
            "::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(r6(2, "eth0", Some("fe80::1"), Some("2001:db8:9::1"))),
        );
    let d = detect_v6(&t, &ov, &w, &w).unwrap();
    assert_eq!(d.source_ipv6, (v6("fd00::5"), Source::Detected));
    // Явный адрес: как есть, интерфейсные адреса не нужны.
    let given = Overrides {
        adapter_ipv6: Some(v6("2001:db8:7::7")),
        ..Default::default()
    };
    let d = detect_v6(&t, &given, &w, &w).unwrap();
    assert_eq!(d.source_ipv6, (v6("2001:db8:7::7"), Source::Given));
    // Только link-local: для глобальной цели отказ текстом C (main-initadapter.c:221-225).
    let w = World::default()
        .iface(
            iface("eth0", 2, true, Some(MAC_A), &[]),
            &["fe80::aa", "::1"],
        )
        .rule6(
            "::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(r6(2, "eth0", None, None)),
        );
    let e = detect_v6(&t, &ov, &w, &w).unwrap_err();
    assert_eq!(e, DetectError::NoIpv6("eth0".into()));
    assert_eq!(
        e.to_string(),
        "FAIL: failed to detect IPv6 address of interface \"eth0\"\n    [hint] did you spell the name \
         correctly?\n    [hint] if it has no IP address, manually set with something like \"--source-ip \
         2001:3b8::1234\""
    );
    // ...а для цели link-local годится link-local источник.
    let d = detect_v6(&t6("fe80::77", "fe80::77"), &ov, &w, &w).unwrap();
    assert_eq!(d.source_ipv6, (v6("fe80::aa"), Source::Detected));
}

/// Следующий хоп IPv6: `--router-mac-ipv6` обходит NDP, `--router-ip <v6>` задаёт адрес для NS, иначе шлюз маршрута,
/// единственная on-link цель, шлюз по умолчанию интерфейса для нескольких on-link целей.
#[test]
fn ipv6_next_hop_from_route_given_mac_or_given_router() {
    let w = World::default()
        .iface(
            iface("eth0", 2, true, Some(MAC_A), &[]),
            &["fe80::aa", "2001:db8:1::5"],
        )
        .rule6(
            "2001:db8:1::",
            "2001:db8:1::ffff",
            Some(r6(2, "eth0", None, None)),
        )
        .rule6(
            "::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(r6(2, "eth0", Some("fe80::1"), None)),
        );
    let ov = Overrides::default();
    let d = detect_v6(&t6("2001:db8:2::1", "2001:db8:2::9"), &ov, &w, &w).unwrap();
    assert_eq!(
        d.next_hop,
        NextHop6::Resolve {
            ip: v6("fe80::1"),
            why: NextHopWhy::RouteGateway
        }
    );
    // Несколько on-link целей: шлюз по умолчанию интерфейса; без него отказ.
    let several = t6("2001:db8:1::7", "2001:db8:1::9");
    let e = detect_v6(&several, &ov, &w, &w).unwrap_err();
    assert_eq!(
        e,
        DetectError::NoGateway6 {
            ifname: "eth0".into()
        }
    );
    let mut w = w;
    w.defaults6 = vec![
        r6(7, "eth9", Some("fe80::9"), None),
        r6(2, "eth0", Some("fe80::1"), None),
    ];
    let d = detect_v6(&several, &ov, &w, &w).unwrap();
    assert_eq!(
        d.next_hop,
        NextHop6::Resolve {
            ip: v6("fe80::1"),
            why: NextHopWhy::InterfaceDefaultGateway
        }
    );
    let mac = Overrides {
        router_mac_ipv6: Some(MAC_GW),
        ..Default::default()
    };
    let d = detect_v6(&several, &mac, &w, &w).unwrap();
    assert_eq!(d.next_hop, NextHop6::Mac(MAC_GW, Source::Given));
    let router = Overrides {
        router_ipv6: Some(v6("fe80::fe")),
        ..Default::default()
    };
    let d = detect_v6(&several, &router, &w, &w).unwrap();
    assert_eq!(
        d.next_hop,
        NextHop6::Resolve {
            ip: v6("fe80::fe"),
            why: NextHopWhy::Given
        }
    );
    // `--router-mac` IPv4 не трогает IPv6 (C `main-conf.c:2599-2600` ставит оба только для `--router-mac`; здесь
    // Overrides уже разведены по семьям вызывающим).
    let v4_only = Overrides {
        router_mac: Some(MAC_GW),
        ..Default::default()
    };
    let d = detect_v6(&several, &v4_only, &w, &w).unwrap();
    assert!(matches!(d.next_hop, NextHop6::Resolve { .. }));
}

/// Отказы маршрута IPv6: нет маршрута, адрес хоста, первая и последняя цели разными путями, `--adapter` не на
/// маршруте к целям.
#[test]
fn ipv6_route_refusals() {
    let ov = Overrides::default();
    let mut w = World::default()
        .iface(iface("eth0", 2, true, Some(MAC_A), &[]), &["2001:db8:1::5"])
        .iface(iface("eth1", 3, true, Some(MAC_B), &[]), &["2001:db8:3::5"])
        .rule6("2001:db8:9::", "2001:db8:9::ffff", None)
        .rule6(
            "2001:db8:1::5",
            "2001:db8:1::5",
            Some(RouteV6 {
                local: true,
                ..r6(1, "lo", None, None)
            }),
        )
        .rule6(
            "2001:db8:3::",
            "2001:db8:3::ffff",
            Some(r6(3, "eth1", None, None)),
        )
        .rule6(
            "::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some(r6(2, "eth0", Some("fe80::1"), None)),
        );
    let e = detect_v6(&t6("2001:db8:9::1", "2001:db8:9::1"), &ov, &w, &w).unwrap_err();
    assert_eq!(e, DetectError::NoRoute6(v6("2001:db8:9::1")));
    let e = detect_v6(&t6("2001:db8:1::5", "2001:db8:1::5"), &ov, &w, &w).unwrap_err();
    assert_eq!(
        e,
        DetectError::LocalTarget6 {
            ip: v6("2001:db8:1::5"),
            ifname: "lo".into(),
            with_adapter: false
        }
    );
    let e = detect_v6(&t6("2001:db8:3::1", "2001:db8:4::1"), &ov, &w, &w).unwrap_err();
    assert_eq!(
        e,
        DetectError::SplitRoutes6 {
            first: (v6("2001:db8:3::1"), "eth1".into()),
            last: (v6("2001:db8:4::1"), "eth0".into()),
            with_adapter: false
        }
    );
    let on_eth0 = Overrides {
        adapter: Some("eth0".into()),
        ..Default::default()
    };
    let e = detect_v6(&t6("2001:db8:3::1", "2001:db8:3::1"), &on_eth0, &w, &w).unwrap_err();
    assert_eq!(
        e,
        DetectError::RouteNotViaAdapter6 {
            ip: v6("2001:db8:3::1"),
            adapter: "eth0".into(),
            route_ifname: "eth1".into()
        }
    );
    // `--adapter` без маршрута к цели: отказ маршрутизатора, как у IPv4.
    let e = detect_v6(&t6("2001:db8:9::1", "2001:db8:9::1"), &on_eth0, &w, &w).unwrap_err();
    assert_eq!(
        e,
        DetectError::NoGateway6 {
            ifname: "eth0".into()
        }
    );
    // С `--adapter` и `--router-mac-ipv6` маршрут не нужен вовсе.
    let given = Overrides {
        adapter: Some("eth0".into()),
        router_mac_ipv6: Some(MAC_GW),
        ..Default::default()
    };
    w.rules6.clear();
    let d = detect_v6(&t6("2001:db8:9::1", "2001:db8:9::1"), &given, &w, &w).unwrap();
    assert_eq!(d.iface_source, Source::Given);
    assert_eq!(d.next_hop, NextHop6::Mac(MAC_GW, Source::Given));
}

/// `--offline` (C `main-initadapter.c:236-238`): MAC шлюза IPv6 фиктивный `66-55-44-33-22-11` и при
/// `--router-mac-ipv6`, следующий хоп не ищется.
#[test]
fn ipv6_offline_uses_the_fake_router_mac() {
    let w = stand();
    let ov = Overrides {
        router_mac_ipv6: Some(MAC_GW),
        ..Default::default()
    };
    let d = detect_v6_offline(&t6("fd00:198:18::2", "fd00:198:18::3"), &ov, &w, &w).unwrap();
    assert_eq!(d.iface.name, "en0");
    assert_eq!(
        d.next_hop,
        NextHop6::Mac([0x66, 0x55, 0x44, 0x33, 0x22, 0x11], Source::Given)
    );
}

/// Пробы IPv6: первый и последний адреса набора вне `::`, `::1` и `ff00::/8`.
#[test]
fn probe_targets_v6_skip_unspecified_loopback_and_multicast() {
    let mut m = MassIp::new();
    m.add_target_string("::-::1").unwrap();
    assert_eq!(probe_targets_v6(&m), None);
    m.add_target_string("ff02::/16").unwrap();
    assert_eq!(probe_targets_v6(&m), None);
    m.add_target_string("2001:db8::7").unwrap();
    let t = probe_targets_v6(&m).unwrap();
    assert_eq!(
        (t.first, t.last, t.single),
        (v6("2001:db8::7"), v6("2001:db8::7"), true)
    );
    let mut all = MassIp::new();
    all.add_target_string("::/0").unwrap();
    let t = probe_targets_v6(&all).unwrap();
    assert_eq!(t.first, v6("::2"));
    assert_eq!(t.last, v6("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    assert!(!t.single);
    let mut v4_only = MassIp::new();
    v4_only.add_target_string("192.0.2.1").unwrap();
    assert_eq!(probe_targets_v6(&v4_only), None);
}

/// Инвариант: обнаружение IPv4 (`detect`, `detect_offline`) не трогает швы IPv6 вовсе.
#[test]
fn ipv4_detection_never_consults_the_ipv6_seams() {
    let w = stand();
    let d = detect(
        &t4("198.18.0.2", "198.18.0.2"),
        &Overrides::default(),
        &w,
        &w,
    )
    .unwrap();
    assert_eq!(d.iface.name, "en0");
    let d = detect_offline(
        &t4("198.18.0.2", "198.18.0.2"),
        &Overrides::default(),
        &w,
        &w,
    )
    .unwrap();
    assert_eq!(d.iface.name, "en0");
    assert_eq!(
        w.v6_calls.get(),
        0,
        "lookup_v6, default_routes_v6, ipv6_addrs"
    );
}

/// Таблица без IPv6 (умолчания швов) знает ни маршрута, ни адреса: отказ «нет маршрута», а не кадр.
#[test]
fn a_table_without_ipv6_support_refuses_with_no_route() {
    struct V4Only;
    impl RouteTable for V4Only {
        fn lookup(&self, _: Ipv4Addr) -> Result<Option<Route>, NetError> {
            Ok(None)
        }
        fn default_routes(&self) -> Result<Vec<Route>, NetError> {
            Ok(Vec::new())
        }
    }
    struct Ifs;
    impl Interfaces for Ifs {
        fn list(&self) -> Result<Vec<Iface>, NetError> {
            Ok(vec![iface("eth0", 2, true, Some(MAC_A), &["192.0.2.5"])])
        }
    }
    let e = detect_v6(
        &t6("2001:db8::1", "2001:db8::1"),
        &Overrides::default(),
        &V4Only,
        &Ifs,
    )
    .unwrap_err();
    assert_eq!(e, DetectError::NoRoute6(v6("2001:db8::1")));
    let given = Overrides {
        adapter: Some("eth0".into()),
        router_mac_ipv6: Some(MAC_GW),
        ..Default::default()
    };
    let e = detect_v6(&t6("2001:db8::1", "2001:db8::1"), &given, &V4Only, &Ifs).unwrap_err();
    assert_eq!(e, DetectError::NoIpv6("eth0".into()));
}
