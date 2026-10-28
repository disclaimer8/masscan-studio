//! Выбор адаптера, источника и следующего хопа по таблице маршрутов и списку интерфейсов (AGPL-3.0).
//!
//! Модуль безопасный, не зависит от ОС и не делает системных вызовов: всё состояние ОС приходит через швы
//! [`RouteTable`] и [`Interfaces`] (их реализуют бэкенды ОС). Одна пара «интерфейс, следующий хоп» на скан;
//! маршруты по умолчанию берутся только из [`RouteTable::default_routes`], lookup `0.0.0.0` не используется.

#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

use rmasscan_core::massip::MassIp;

use crate::NetError;

/// Маршрут к адресу или маршрут по умолчанию.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub ifindex: u32,
    pub ifname: String,
    pub gateway: Option<Ipv4Addr>,
    /// Назначение это адрес самого хоста: Linux RTN_LOCAL; macOS RTF_LOCAL или ifp lo0;
    /// Windows флаг Loopback, или IfType 24 (software loopback), или dst равен unicast-адресу адаптера.
    pub local: bool,
}

/// Сетевой интерфейс в терминах обнаружения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iface {
    pub name: String,
    pub index: u32,
    /// Linux/macOS: имя; Windows: `\Device\NPF_{GUID}`.
    pub device_id: String,
    /// Windows FriendlyName.
    pub description: Option<String>,
    pub mac: Option<[u8; 6]>,
    pub mac_masked: bool,
    /// Ethernet-кадры: Linux ARPHRD_ETHER, macOS IFT_ETHER, Windows IfType 6 или 71 (Wi-Fi, Npcap даёт DLT_EN10MB).
    pub ethernet: bool,
    pub up: bool,
    pub ipv4: Vec<Ipv4Addr>,
}

pub trait RouteTable {
    /// Physical preparation must implement a cancellable, absolute-deadline lookup.
    /// Refuse unsupported implementations rather than calling an unbounded legacy lookup.
    fn lookup_until(
        &self,
        _dst: Ipv4Addr,
        _deadline: std::time::Instant,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<Route>, NetError> {
        Err(NetError::MissingCapability(
            "bounded route observation".into(),
        ))
    }

    /// Маршрут к одному unicast-адресу (Linux RTM_GETROUTE+RTA_DST, macOS RTM_GET, Windows GetBestRoute2); `None` = нет
    /// маршрута (Linux unreachable/blackhole/prohibit; Windows ERROR_NOT_FOUND/NETWORK_UNREACHABLE/HOST_UNREACHABLE;
    /// macOS ESRCH).
    fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, NetError>;
    /// Все маршруты по умолчанию в порядке предпочтения ядра (Linux dump таблицы main, dst_len 0, по priority;
    /// macOS RTM_GET 0.0.0.0 (один); Windows GetIpForwardTable2, prefix 0, по Metric).
    fn default_routes(&self) -> Result<Vec<Route>, NetError>;
}

pub trait Interfaces {
    /// Prefix-aware snapshot for physical planning; no packet handles may be opened.
    fn observe(
        &self,
        _deadline: std::time::Instant,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<crate::network_plan::InterfaceObservation>, NetError> {
        Err(NetError::MissingCapability(
            "bounded interface observation".into(),
        ))
    }

    fn list(&self) -> Result<Vec<Iface>, NetError>;
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Overrides {
    pub adapter: Option<String>,
    pub adapter_ip: Option<Ipv4Addr>,
    pub adapter_mac: Option<[u8; 6]>,
    pub router_ip: Option<Ipv4Addr>,
    pub router_mac: Option<[u8; 6]>,
}

/// Цели-пробы: первый и последний unicast-адреса итогового набора.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Targets {
    pub first: Ipv4Addr,
    pub last: Ipv4Addr,
    pub single: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Given,
    Detected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextHopWhy {
    Given,
    RouteGateway,
    OnLinkTarget,
    InterfaceDefaultGateway,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextHop {
    Mac([u8; 6], Source),
    Resolve { ip: Ipv4Addr, why: NextHopWhy },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    pub iface: Iface,
    pub iface_source: Source,
    pub source_ipv4: (Ipv4Addr, Source),
    pub source_mac: ([u8; 6], Source),
    pub next_hop: NextHop,
}

/// Подсказки masscan для отказов маршрутизатора (C `main-initadapter.c:196–198`).
pub(crate) const ROUTER_HINTS: &str = "\n    [hint] try \"--router-ip 192.0.2.1\" to specify different router\n    [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP\n    [hint] try \"--interface eth0\" to change interface";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DetectError {
    #[error(
        "FAIL: no unicast target addresses to route to\n    [hint] targets must include an address outside 0.0.0.0/8, 127.0.0.0/8 and 224.0.0.0/3"
    )]
    NoUnicastTargets,
    #[error("FAIL: could not determine default interface\n    [hint] try \"--interface ethX\"")]
    NoRoute(Ipv4Addr),
    #[error(
        "FAIL: {ip} is an address of this host (route via {ifname})\n    [hint] try \"--interface ethX\" and \"--router-ip 192.0.2.1\""
    )]
    LocalTarget { ip: Ipv4Addr, ifname: String },
    #[error("FAIL: targets are routed differently ({} via {}, {} via {})\n    [hint] try \"--interface ethX\"", .first.0, .first.1, .last.0, .last.1)]
    /// Первая и последняя цель идут разными маршрутами (только без `--adapter`).
    SplitRoutes {
        first: (Ipv4Addr, String),
        last: (Ipv4Addr, String),
    },
    #[error("FAIL: no such interface \"{0}\"\n    [hint] did you spell the name correctly?")]
    NoSuchAdapter(String),
    #[error(
        "FAIL: interface \"{name}\" is not usable: {reason}\n    [hint] try \"--interface ethX\""
    )]
    NotUsable { name: String, reason: &'static str },
    #[error(
        "FAIL: failed to detect IP of interface \"{0}\"\n    [hint] did you spell the name correctly?\n    [hint] if it has no IP address, manually set with something like \"--source-ip 198.51.100.17\""
    )]
    NoIpv4(String),
    #[error(
        "FAIL: MAC of interface \"{0}\" is os-masked (Darwin hides MACs from unprivileged processes)\n    [hint] run as root, or try something like \"--source-mac 00-11-22-33-44-55\""
    )]
    MacMasked(String),
    #[error(
        "FAIL: failed to detect MAC address of interface: \"{0}\"\n [hint] try something like \"--source-mac 00-11-22-33-44-55\""
    )]
    NoMac(String),
    #[error(
        "FAIL: no default gateway on interface \"{ifname}\" for several on-link targets{}",
        ROUTER_HINTS
    )]
    NoGateway { ifname: String },
    #[error(
        "FAIL: route doesn't match interface: {ip} is routed via {route_ifname}, not \"{adapter}\"{}",
        ROUTER_HINTS
    )]
    RouteNotViaAdapter {
        ip: Ipv4Addr,
        adapter: String,
        route_ifname: String,
    },
    #[error("FAIL: {0}")]
    Os(#[from] NetError),
}

/// Не-unicast IPv4 для проб: `0.0.0.0/8`, `127.0.0.0/8`, `224.0.0.0/3` (включая `255.255.255.255`).
const UNICAST_SEGMENTS: [(u32, u32); 2] = [(0x0100_0000, 0x7eff_ffff), (0x8000_0000, 0xdfff_ffff)];

/// Первый и последний unicast-адреса итогового набора; `None`, если unicast нет.
pub fn probe_targets(massip: &MassIp) -> Option<Targets> {
    let mut lo: Option<u32> = None;
    let mut hi: Option<u32> = None;
    for r in massip.ipv4().as_slice() {
        if r.begin > r.end {
            continue;
        }
        for (a, b) in UNICAST_SEGMENTS {
            let s = r.begin.max(a);
            let e = r.end.min(b);
            if s <= e {
                lo = Some(lo.map_or(s, |v| v.min(s)));
                hi = Some(hi.map_or(e, |v| v.max(e)));
            }
        }
    }
    let (first, last) = (Ipv4Addr::from(lo?), Ipv4Addr::from(hi?));
    Some(Targets {
        first,
        last,
        single: first == last,
    })
}

/// Фиктивный MAC шлюза для `--offline` (C `main-initadapter.c:163`).
const OFFLINE_ROUTER_MAC: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

/// Заполнитель Darwin для скрытого MAC: никогда не становится source MAC.
const DARWIN_PLACEHOLDER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0];

/// Годится ли MAC как source MAC кадров: не нулевой, не заполнитель Darwin `02:00:00:00:00:00` (скрытый ОС MAC) и не
/// групповой/широковещательный (младший бит первого октета). Единое правило для [`detect`]/[`detect_offline`] и для
/// вызывающих, которые берут явный MAC без обнаружения (герметичный `--offline` CLI).
pub fn usable_source_mac(m: [u8; 6]) -> bool {
    m != [0; 6] && m != DARWIN_PLACEHOLDER_MAC && m[0] & 1 == 0
}

/// Маршрут к целям-пробам: первая и последняя цель обязаны дать один интерфейс и один шлюз.
fn route_for_targets(t: &Targets, routes: &dyn RouteTable) -> Result<Route, DetectError> {
    let one = |ip: Ipv4Addr| -> Result<Route, DetectError> {
        let r = routes.lookup(ip)?.ok_or(DetectError::NoRoute(ip))?;
        if r.local {
            return Err(DetectError::LocalTarget {
                ip,
                ifname: r.ifname,
            });
        }
        Ok(r)
    };
    let first = one(t.first)?;
    if !t.single {
        let last = one(t.last)?;
        if last.ifindex != first.ifindex || last.gateway != first.gateway {
            return Err(DetectError::SplitRoutes {
                first: (t.first, first.ifname),
                last: (t.last, last.ifname),
            });
        }
    }
    Ok(first)
}

struct Chosen {
    iface: Iface,
    iface_source: Source,
    source_ipv4: (Ipv4Addr, Source),
    source_mac: ([u8; 6], Source),
    /// Маршрут к целям, если он уже искался (без `--adapter`).
    route: Option<Route>,
}

fn choose(
    t: &Targets,
    ov: &Overrides,
    routes: &dyn RouteTable,
    ifaces: &dyn Interfaces,
) -> Result<Chosen, DetectError> {
    let list = ifaces.list()?;
    let (iface, iface_source, route) = match &ov.adapter {
        Some(a) => {
            let found = list.into_iter().find(|i| {
                i.name == *a
                    || i.device_id.eq_ignore_ascii_case(a)
                    || i.description
                        .as_deref()
                        .is_some_and(|d| d.eq_ignore_ascii_case(a))
            });
            (
                found.ok_or_else(|| DetectError::NoSuchAdapter(a.clone()))?,
                Source::Given,
                None,
            )
        }
        None => {
            let r = route_for_targets(t, routes)?;
            let found = list.into_iter().find(|i| i.index == r.ifindex);
            (
                found.ok_or_else(|| DetectError::NoSuchAdapter(r.ifname.clone()))?,
                Source::Detected,
                Some(r),
            )
        }
    };
    if !iface.ethernet {
        return Err(DetectError::NotUsable {
            name: iface.name,
            reason: "not Ethernet",
        });
    }
    if !iface.up {
        return Err(DetectError::NotUsable {
            name: iface.name,
            reason: "down",
        });
    }
    let source_ipv4 = match (ov.adapter_ip, iface.ipv4.first()) {
        (Some(ip), _) => (ip, Source::Given),
        (None, Some(ip)) => (*ip, Source::Detected),
        (None, None) => return Err(DetectError::NoIpv4(iface.name)),
    };
    let source_mac = match ov.adapter_mac {
        Some(m) if usable_source_mac(m) => (m, Source::Given),
        Some(_) => return Err(DetectError::NoMac(iface.name)),
        None if iface.mac_masked => return Err(DetectError::MacMasked(iface.name)),
        None => match iface.mac {
            Some(m) if usable_source_mac(m) => (m, Source::Detected),
            _ => return Err(DetectError::NoMac(iface.name)),
        },
    };
    Ok(Chosen {
        iface,
        iface_source,
        source_ipv4,
        source_mac,
        route,
    })
}

fn next_hop(
    t: &Targets,
    ov: &Overrides,
    c: &Chosen,
    routes: &dyn RouteTable,
) -> Result<NextHop, DetectError> {
    if let Some(m) = ov.router_mac {
        return Ok(NextHop::Mac(m, Source::Given));
    }
    if let Some(ip) = ov.router_ip {
        return Ok(NextHop::Resolve {
            ip,
            why: NextHopWhy::Given,
        });
    }
    let route = match &c.route {
        Some(r) => r.clone(),
        None => match route_for_targets(t, routes) {
            // `--adapter` без маршрута к цели: поведение C на Linux, отказ маршрутизатора
            Err(DetectError::NoRoute(_)) => {
                return Err(DetectError::NoGateway {
                    ifname: c.iface.name.clone(),
                });
            }
            other => other?,
        },
    };
    if route.ifindex != c.iface.index {
        // `--adapter` указывает не на интерфейс маршрута к целям (C `rawsock-getroute.c:211`)
        return Err(DetectError::RouteNotViaAdapter {
            ip: t.first,
            adapter: c.iface.name.clone(),
            route_ifname: route.ifname,
        });
    }
    if let Some(g) = route.gateway {
        return Ok(NextHop::Resolve {
            ip: g,
            why: NextHopWhy::RouteGateway,
        });
    }
    if t.single {
        return Ok(NextHop::Resolve {
            ip: t.first,
            why: NextHopWhy::OnLinkTarget,
        });
    }
    routes
        .default_routes()?
        .into_iter()
        .find(|r| r.ifindex == route.ifindex && r.gateway.is_some())
        .and_then(|r| r.gateway)
        .map(|ip| NextHop::Resolve {
            ip,
            why: NextHopWhy::InterfaceDefaultGateway,
        })
        .ok_or(DetectError::NoGateway {
            ifname: c.iface.name.clone(),
        })
}

fn finish(c: Chosen, next_hop: NextHop) -> Detected {
    Detected {
        iface: c.iface,
        iface_source: c.iface_source,
        source_ipv4: c.source_ipv4,
        source_mac: c.source_mac,
        next_hop,
    }
}

pub fn detect(
    t: &Targets,
    ov: &Overrides,
    routes: &dyn RouteTable,
    ifaces: &dyn Interfaces,
) -> Result<Detected, DetectError> {
    let c = choose(t, ov, routes, ifaces)?;
    let nh = next_hop(t, ov, &c, routes)?;
    Ok(finish(c, nh))
}

/// Для `--offline`: интерфейс/IP/MAC по тем же правилам, следующий хоп не ищется (C `main-initadapter.c:159–163`):
/// MAC шлюза всегда фиктивный `66-55-44-33-22-11`, и при `--router-mac` тоже.
pub fn detect_offline(
    t: &Targets,
    ov: &Overrides,
    routes: &dyn RouteTable,
    ifaces: &dyn Interfaces,
) -> Result<Detected, DetectError> {
    let c = choose(t, ov, routes, ifaces)?;
    Ok(finish(c, NextHop::Mac(OFFLINE_ROUTER_MAC, Source::Given)))
}

fn fmt_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// Одна строка на интерфейс, затем строки `default via G dev NAME` / `default dev NAME`.
pub fn iflist_text(ifaces: &[Iface], defaults: &[Route]) -> String {
    let mut out = String::new();
    for i in ifaces {
        let mac = if i.mac_masked {
            "masked".to_string()
        } else {
            i.mac.map_or_else(|| "none".to_string(), fmt_mac)
        };
        let addrs = if i.ipv4.is_empty() {
            "-".to_string()
        } else {
            i.ipv4
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        out.push_str(&format!(
            "{} index={} mac={} ipv4={} {} {}",
            i.name,
            i.index,
            mac,
            addrs,
            if i.up { "up" } else { "down" },
            if i.ethernet { "ethernet" } else { "other" },
        ));
        if i.device_id != i.name {
            out.push_str(&format!(" id={}", i.device_id));
        }
        if let Some(d) = &i.description {
            out.push_str(&format!(" desc={d}"));
        }
        out.push('\n');
    }
    for r in defaults {
        match r.gateway {
            Some(g) => out.push_str(&format!("default via {g} dev {}\n", r.ifname)),
            None => out.push_str(&format!("default dev {}\n", r.ifname)),
        }
    }
    out
}

#[cfg(test)]
#[path = "discover_tests.rs"]
mod discover_tests;
