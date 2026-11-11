//! Только чтение настоящей таблицы маршрутов и списка интерфейсов ОС через `os_route_table`/`os_interfaces`
//! (AGPL-3.0): ни одного кадра, ни открытия адаптера, ни запуска процессов. `detect` здесь тоже только читает: он
//! выбирает интерфейс и следующий хоп, но ARP не шлёт.
//!
//! `RMASSCAN_EXPECT_DEFAULT_ROUTE=1` (хосты с известным маршрутом по умолчанию через шлюз: dev Mac без VPN, minipc,
//! гость Windows) делает ожидания строгими; без переменной (CI) тесты терпимы к хосту без маршрута по умолчанию.
//! Сообщения проверок называют только признаки, не адреса и не имена: выводы тестов не попадают в evidence.
//!
//! Бинарник запускается только через `spawn_readonly` и только с `--iflist` или `--offline` (оба только читают ОС).

#[path = "common/spawn.rs"]
mod spawn;

use std::net::{Ipv4Addr, Ipv6Addr};

use rmasscan_net::{
    DetectError, NextHop6, Overrides, Targets, Targets6, detect, detect_v6, os_interfaces,
    os_route_table,
};
use spawn::spawn_readonly;

fn strict() -> bool {
    std::env::var("RMASSCAN_EXPECT_DEFAULT_ROUTE").as_deref() == Ok("1")
}

#[test]
fn binary_iflist_lists_interfaces() {
    let out = spawn_readonly(&["--iflist"]);
    assert_eq!(out.status.code(), Some(0), "--iflist exits 0");
    assert!(!out.stdout.is_empty(), "--iflist prints the interfaces");
    assert!(out.stderr.is_empty(), "--iflist writes nothing to stderr");
}

/// `--offline` обнаруживает только чтением: либо строки `[+]` с фиктивным MAC шлюза, либо отказ в форме C одного из
/// видов, допустимых на хосте без доступного Ethernet (VPN, интерфейс без IPv4, MAC скрыт ОС, Darwin без root).
#[test]
fn binary_offline_detects_or_refuses_read_only() {
    let out = spawn_readonly(&["--offline", "8.8.8.8", "-p80", "--seed", "1"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.stdout.is_empty(),
        "--offline without --packet-trace prints nothing to stdout"
    );
    assert!(
        !err.contains("rmasscan: error:"),
        "detection refusals use the C form"
    );
    match out.status.code() {
        Some(0) => {
            for prefix in [
                "[+] interface = ",
                "[+] source-mac = ",
                "[+] source-ip = ",
                "[+] router-ip = none (offline)",
                "[+] router-mac = 66-55-44-33-22-11 (offline)",
                "[+] seed = 1 (given)",
                "[+] source-port = ",
            ] {
                assert!(
                    err.lines().any(|l| l.starts_with(prefix)),
                    "missing stderr line {prefix:?}"
                );
            }
        }
        Some(1) => {
            assert!(
                err.starts_with("[-] FAIL: "),
                "a refusal starts with [-] FAIL:"
            );
            let kinds = [
                ("NoRoute", "could not determine default interface"),
                ("NoIpv4", "failed to detect IP of interface"),
                ("MacMasked", "is os-masked"),
                ("NotUsable", "is not usable"),
            ];
            let kind = kinds
                .iter()
                .find(|(_, text)| err.contains(text))
                .map(|(k, _)| *k);
            assert!(kind.is_some(), "the refusal is one of {kinds:?}");
            assert!(
                !(strict() && kind == Some("NoRoute")),
                "RMASSCAN_EXPECT_DEFAULT_ROUTE=1: 8.8.8.8 must have a route"
            );
        }
        other => panic!("unexpected exit code {other:?}"),
    }
}

#[test]
fn loopback_address_routes_locally() {
    let routes = os_route_table().expect("os_route_table");
    let r = routes
        .lookup(Ipv4Addr::LOCALHOST)
        .expect("lookup(127.0.0.1) must not fail")
        .expect("127.0.0.1 must have a route");
    assert!(r.local, "the route to 127.0.0.1 must be marked local");
    assert!(r.gateway.is_none(), "a local route has no gateway");
}

#[test]
fn default_routes_never_panic_and_are_strict_where_expected() {
    let routes = os_route_table().expect("os_route_table");
    let defaults = routes
        .default_routes()
        .expect("default_routes must not fail");
    assert!(
        defaults.iter().all(|r| !r.local),
        "a default route is never local"
    );
    if strict() {
        let first = defaults
            .first()
            .expect("RMASSCAN_EXPECT_DEFAULT_ROUTE=1: at least one default route");
        assert!(
            first.gateway.is_some(),
            "RMASSCAN_EXPECT_DEFAULT_ROUTE=1: the preferred default route has a gateway \
             (a link-level gateway means a VPN tunnel: run without it)"
        );
        assert!(
            !first.ifname.is_empty(),
            "the default route names its interface"
        );
    }
}

#[test]
fn interfaces_list_is_nonempty_and_loopback_is_not_ethernet() {
    let list = os_interfaces()
        .expect("os_interfaces")
        .list()
        .expect("list");
    assert!(!list.is_empty(), "the host has interfaces");
    let lo_index = os_route_table()
        .expect("os_route_table")
        .lookup(Ipv4Addr::LOCALHOST)
        .expect("lookup(127.0.0.1)")
        .map(|r| r.ifindex);
    let loopbacks: Vec<_> = list
        .iter()
        .filter(|i| i.ipv4.contains(&Ipv4Addr::LOCALHOST) || Some(i.index) == lo_index)
        .collect();
    assert!(
        !loopbacks.is_empty(),
        "a loopback interface (127.0.0.1 or the route to it) is listed"
    );
    assert!(
        loopbacks.iter().all(|i| !i.ethernet),
        "the loopback interface is not Ethernet"
    );
    let mut indexes: Vec<u32> = list.iter().map(|i| i.index).collect();
    indexes.sort_unstable();
    indexes.dedup();
    assert_eq!(indexes.len(), list.len(), "one entry per interface index");
}

#[test]
fn every_ethernet_interface_has_a_six_byte_or_masked_mac() {
    const PLACEHOLDER: [u8; 6] = [2, 0, 0, 0, 0, 0];
    let list = os_interfaces()
        .expect("os_interfaces")
        .list()
        .expect("list");
    for (n, i) in list.iter().filter(|i| i.ethernet).enumerate() {
        match (i.mac, i.mac_masked) {
            (Some(m), false) => assert!(
                m != PLACEHOLDER,
                "ethernet interface #{n}: the Darwin placeholder must be reported as masked"
            ),
            (None, true) => {}
            (mac, masked) => panic!(
                "ethernet interface #{n}: mac present {} / masked {masked}: expected a MAC xor masked",
                mac.is_some()
            ),
        }
    }
}

#[test]
fn remote_lookup_matches_offline_detection() {
    let remote = Ipv4Addr::new(8, 8, 8, 8);
    let routes = os_route_table().expect("os_route_table");
    let ifaces = os_interfaces().expect("os_interfaces");
    let Some(route) = routes
        .lookup(remote)
        .expect("lookup(8.8.8.8) must not fail")
    else {
        assert!(
            !strict(),
            "RMASSCAN_EXPECT_DEFAULT_ROUTE=1: 8.8.8.8 must have a route"
        );
        return;
    };
    assert!(!route.local, "8.8.8.8 is not an address of this host");
    let t = Targets {
        first: remote,
        last: remote,
        single: true,
    };
    match detect(&t, &Overrides::default(), routes.as_ref(), ifaces.as_ref()) {
        Ok(d) => {
            assert!(
                d.iface.index == route.ifindex,
                "detect picks the route's interface"
            );
            assert!(
                d.iface.name == route.ifname,
                "the route names the same interface"
            );
        }
        // Маршрут через VPN-туннель (не Ethernet), интерфейс без IPv4, MAC скрыт ОС (Darwin без root).
        Err(DetectError::NotUsable { .. } | DetectError::NoIpv4(_) | DetectError::MacMasked(_)) => {
        }
        Err(e) => panic!(
            "detect without overrides refused unexpectedly: {}",
            kind(&e)
        ),
    }
}

/// Имя варианта отказа без полей (поля называют адреса и интерфейсы хоста).
fn kind(e: &DetectError) -> &'static str {
    match e {
        DetectError::NoUnicastTargets => "NoUnicastTargets",
        DetectError::NoRoute(_) => "NoRoute",
        DetectError::LocalTarget { .. } => "LocalTarget",
        DetectError::SplitRoutes { .. } => "SplitRoutes",
        DetectError::NoSuchAdapter(_) => "NoSuchAdapter",
        DetectError::NotUsable { .. } => "NotUsable",
        DetectError::NoIpv4(_) => "NoIpv4",
        DetectError::MacMasked(_) => "MacMasked",
        DetectError::NoMac(_) => "NoMac",
        DetectError::NoGateway { .. } => "NoGateway",
        DetectError::RouteNotViaAdapter { .. } => "RouteNotViaAdapter",
        DetectError::NoUnicastTargets6 => "NoUnicastTargets6",
        DetectError::NoRoute6(_) => "NoRoute6",
        DetectError::LocalTarget6 { .. } => "LocalTarget6",
        DetectError::SplitRoutes6 { .. } => "SplitRoutes6",
        DetectError::NoIpv6(_) => "NoIpv6",
        DetectError::NoGateway6 { .. } => "NoGateway6",
        DetectError::RouteNotViaAdapter6 { .. } => "RouteNotViaAdapter6",
        DetectError::RouteIfaceNotListed6 { .. } => "RouteIfaceNotListed6",
        DetectError::FamiliesSplit { .. } => "FamiliesSplit",
        DetectError::Os(_) => "Os",
    }
}

/// IPv6 (T5): маршрут к `::1` локальный; маршрут к документационному адресу (`2001:db8::1`, его ищет только таблица
/// маршрутов, кадров нет) либо отсутствует (хост без IPv6), либо даёт интерфейс, который `detect_v6` выбирает сам, с
/// пригодным адресом источника (не `::`, не `::1`, не multicast, без KAME-зоны в link-local) и шлюзом без зоны.
/// Терпим к хосту без IPv6 (CI), отказы называются только видом.
#[test]
fn ipv6_lookup_and_detection_read_only() {
    let routes = os_route_table().expect("os_route_table");
    let ifaces = os_interfaces().expect("os_interfaces");
    if let Some(r) = routes
        .lookup_v6(Ipv6Addr::LOCALHOST)
        .expect("lookup_v6(::1)")
    {
        assert!(r.local, "the route to ::1 is local");
        assert!(r.gateway.is_none(), "a local route has no gateway");
    }
    let remote: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let Some(route) = routes.lookup_v6(remote).expect("lookup_v6 must not fail") else {
        return;
    };
    assert!(
        !route.local,
        "a documentation address is not an address of this host"
    );
    let no_zone = |a: &Ipv6Addr| {
        let s = a.segments();
        s[0] & 0xffc0 != 0xfe80 || s[1] == 0
    };
    assert!(
        route.gateway.iter().all(no_zone),
        "gateway without an embedded zone"
    );
    let t = Targets6 {
        first: remote,
        last: remote,
        single: true,
    };
    match detect_v6(&t, &Overrides::default(), routes.as_ref(), ifaces.as_ref()) {
        Ok(d) => {
            assert!(
                d.iface.index == route.ifindex,
                "detect_v6 picks the route's interface"
            );
            let src = d.source_ipv6.0;
            assert!(
                !src.is_unspecified() && !src.is_loopback() && !src.is_multicast() && no_zone(&src),
                "a usable source address"
            );
            let addrs = ifaces.ipv6_addrs(&d.iface).expect("ipv6_addrs");
            assert!(
                addrs.contains(&src),
                "the source is an address of the interface"
            );
            if let NextHop6::Resolve { ip, .. } = d.next_hop {
                assert!(no_zone(&ip), "next hop without an embedded zone");
            }
        }
        // VPN-туннель, интерфейс без глобального адреса IPv6, MAC скрыт ОС.
        Err(DetectError::NotUsable { .. } | DetectError::NoIpv6(_) | DetectError::MacMasked(_)) => {
        }
        // Только Windows: маршрут через адаптер без привязки IPv4 (например туннель), которого нет в списке
        // `GetAdaptersAddresses(AF_INET)`. Это должен быть настоящий индекс маршрута, и его действительно нет в списке;
        // на Linux и macOS список полный, и такой отказ это дефект.
        Err(DetectError::RouteIfaceNotListed6 { ifindex, .. }) if cfg!(windows) => {
            assert_route_iface_not_listed(ifindex, route.ifindex);
        }
        Err(e) => panic!("detect_v6 refused unexpectedly: {}", kind(&e)),
    }
}

/// `RouteIfaceNotListed6` (только Windows): индекс из отказа это индекс маршрута, не 0 (строка `GetBestRoute2`
/// заполнена) и его правда нет в списке интерфейсов (адаптер без привязки IPv4).
fn assert_route_iface_not_listed(ifindex: u32, route_ifindex: u32) {
    assert!(ifindex != 0, "a real interface index, not an unfilled row");
    assert_eq!(
        ifindex, route_ifindex,
        "the refusal names the route's interface"
    );
    let list = os_interfaces()
        .expect("os_interfaces")
        .list()
        .expect("list");
    assert!(
        !list.iter().any(|i| i.index == ifindex),
        "the route's interface is really absent from the interface list"
    );
}

/// `--offline` с целью IPv6 обнаруживает только чтением: строки `[+]` IPv6 с фиктивным MAC шлюза IPv6 либо отказ в
/// форме C (хост без IPv6, VPN, MAC скрыт ОС).
#[test]
fn binary_offline_ipv6_detects_or_refuses_read_only() {
    let out = spawn_readonly(&["--offline", "2001:db8::1", "-p80", "--seed", "1"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.stdout.is_empty(), "no stdout without --packet-trace");
    assert!(
        !err.contains("rmasscan: error:"),
        "detection refusals use the C form"
    );
    match out.status.code() {
        Some(0) => {
            for prefix in [
                "[+] interface = ",
                "[+] source-mac = ",
                "[+] source-ip = [",
                "[+] router-mac-ipv6 = 66-55-44-33-22-11 (offline)",
                "[+] seed = 1 (given)",
            ] {
                assert!(
                    err.lines().any(|l| l.starts_with(prefix)),
                    "missing stderr line {prefix:?}"
                );
            }
            assert!(
                !err.lines().any(|l| l.starts_with("[+] router-mac = ")),
                "no IPv4 lines without IPv4 targets"
            );
        }
        Some(1) => {
            assert!(
                err.starts_with("[-] FAIL: "),
                "a refusal starts with [-] FAIL:"
            );
            let kinds = [
                "could not determine default interface",
                "failed to detect IPv6 address of interface",
                "is os-masked",
                "is not usable",
            ];
            // Только Windows: маршрут IPv6 через адаптер без привязки IPv4 (см. `ipv6_lookup_and_detection_read_only`).
            const NOT_LISTED: &str = " uses interface index ";
            if cfg!(windows) && err.contains(NOT_LISTED) {
                let index: u32 = err
                    .split(NOT_LISTED)
                    .nth(1)
                    .and_then(|rest| rest.split(',').next())
                    .and_then(|n| n.parse().ok())
                    .expect("the refusal names the route's interface index");
                let route = os_route_table()
                    .expect("os_route_table")
                    .lookup_v6("2001:db8::1".parse().unwrap())
                    .expect("lookup_v6")
                    .expect("the refusal came from a route");
                assert_route_iface_not_listed(index, route.ifindex);
                return;
            }
            assert!(
                kinds.iter().any(|k| err.contains(k)),
                "the refusal is one of {kinds:?}"
            );
        }
        other => panic!("unexpected exit code {other:?}"),
    }
}
