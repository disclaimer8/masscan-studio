//! Выбор адаптера, источника и следующего хопа по таблице маршрутов и списку интерфейсов (AGPL-3.0).
//!
//! Модуль безопасный, не зависит от ОС и не делает системных вызовов: всё состояние ОС приходит через швы
//! [`RouteTable`] и [`Interfaces`] (их реализуют бэкенды ОС). Одна пара «интерфейс, следующий хоп» на скан;
//! маршруты по умолчанию берутся только из [`RouteTable::default_routes`], lookup `0.0.0.0` не используется.
//!
//! IPv6 ([`detect_v6`], [`detect_mixed`]) идёт своими швами ([`RouteTable::lookup_v6`],
//! [`RouteTable::default_routes_v6`], [`Interfaces::ipv6_addrs`]); путь IPv4 их не вызывает, поэтому скан без целей
//! IPv6 опрашивает ОС ровно как раньше. C (`main-initadapter.c:44-57, 212-261`) берёт один интерфейс маршрута IPv4 по
//! умолчанию и для IPv6 тоже (первый адрес интерфейса, `rawsock-getip6.c`, шлюз по Router Advertisement); здесь
//! интерфейс IPv6 выбирает маршрут ОС к целям IPv6, а смешанный скан, чьи семьи уходят разными интерфейсами,
//! отказывает ([`DetectError::FamiliesSplit`]): C отправил бы кадры IPv6 в интерфейс маршрута IPv4.

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, Ipv6Addr};

use rmasscan_core::massip::MassIp;
use rmasscan_core::ranges6::format_ipv6_c;

use crate::NetError;

/// Маршрут к адресу или маршрут по умолчанию.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub ifindex: u32,
    pub ifname: String,
    pub gateway: Option<Ipv4Addr>,
    /// Назначение это адрес самого хоста: Linux RTN_LOCAL; macOS dst равен IPv4-адресу интерфейса (маршрут через lo0,
    /// каким бы ни был ответ RTM_GET), RTF_LOCAL или ifp lo0; Windows dst равен unicast-адресу адаптера или маршрут
    /// идёт через IfType 24 (software loopback); флаг MIB Loopback строки сам по себе нет (Windows ставит его и /32
    /// широковещательного адреса подсети, а это on-link назначение).
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

/// Маршрут IPv6 к адресу или маршрут по умолчанию IPv6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteV6 {
    pub ifindex: u32,
    pub ifname: String,
    /// Следующий хоп (обычно link-local роутера); `None`: цель on-link, следующий хоп она сама.
    pub gateway: Option<Ipv6Addr>,
    /// Адрес источника, который выбрала бы ОС для этого назначения: Linux `RTA_PREFSRC` ответа на lookup, Windows
    /// `BestSourceAddress` `GetBestRoute2`; `None`, где таблица его не даёт (macOS `RTM_GET`, маршруты по умолчанию).
    pub source: Option<Ipv6Addr>,
    /// Назначение это адрес самого хоста: Linux RTN_LOCAL; macOS dst равен IPv6-адресу интерфейса, RTF_LOCAL или
    /// ifp lo0; Windows dst равен unicast-адресу адаптера или маршрут идёт через software loopback.
    pub local: bool,
}

pub trait RouteTable {
    /// Маршрут к одному unicast-адресу (Linux RTM_GETROUTE+RTA_DST, macOS RTM_GET, Windows GetBestRoute2); `None` = нет
    /// маршрута (Linux unreachable/blackhole/prohibit; Windows ERROR_NOT_FOUND/NETWORK_UNREACHABLE/HOST_UNREACHABLE;
    /// macOS ESRCH).
    fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, NetError>;
    /// Все маршруты по умолчанию в порядке предпочтения ядра (Linux dump таблицы main, dst_len 0, по priority;
    /// macOS RTM_GET 0.0.0.0 (один); Windows GetIpForwardTable2, prefix 0, по Metric).
    fn default_routes(&self) -> Result<Vec<Route>, NetError>;
    /// Маршрут IPv6 к одному unicast-адресу (Linux RTM_GETROUTE `AF_INET6`, macOS RTM_GET `sockaddr_in6`, Windows
    /// GetBestRoute2 `AF_INET6`); `None` = нет маршрута. Зовёт только обнаружение IPv6. По умолчанию таблица маршрутов
    /// IPv6 не знает (любая цель IPv6 получит отказ «нет маршрута»).
    fn lookup_v6(&self, dst: Ipv6Addr) -> Result<Option<RouteV6>, NetError> {
        let _ = dst;
        Ok(None)
    }
    /// Маршруты IPv6 по умолчанию в порядке предпочтения ядра (Linux dump `AF_INET6` таблицы main, dst_len 0; macOS
    /// RTM_GET `::`; Windows GetIpForwardTable2 `AF_INET6`, prefix 0, по Metric). По умолчанию нет ни одного.
    fn default_routes_v6(&self) -> Result<Vec<RouteV6>, NetError> {
        Ok(Vec::new())
    }
}

pub trait Interfaces {
    fn list(&self) -> Result<Vec<Iface>, NetError>;
    /// Unicast-адреса IPv6 интерфейса в порядке ОС без адресов, которыми ещё или уже нельзя пользоваться (Linux
    /// `IFA_F_TENTATIVE`/`IFA_F_DADFAILED`, Windows `IpDadStateTentative`/`IpDadStateDuplicate`); link-local без
    /// встроенного KAME scope (macOS). Зовёт только обнаружение IPv6: путь IPv4 и `--iflist` его не вызывают. По
    /// умолчанию адресов нет.
    fn ipv6_addrs(&self, iface: &Iface) -> Result<Vec<Ipv6Addr>, NetError> {
        let _ = iface;
        Ok(Vec::new())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Overrides {
    pub adapter: Option<String>,
    pub adapter_ip: Option<Ipv4Addr>,
    pub adapter_mac: Option<[u8; 6]>,
    pub router_ip: Option<Ipv4Addr>,
    /// MAC шлюза IPv4 (C `router_mac_ipv4`; `--router-mac` ставит его и [`Overrides::router_mac_ipv6`],
    /// `main-conf.c:2599-2600`).
    pub router_mac: Option<[u8; 6]>,
    /// `--adapter-ip <IPv6>` (C `src.ipv6.first`, `main-conf.c:2508-2512`).
    pub adapter_ipv6: Option<Ipv6Addr>,
    /// `--router-ip <IPv6>`: адрес для Neighbor Solicitation вместо шлюза маршрута (у C такого ключа нет:
    /// `--router-ip` только IPv4, `main-conf.c:2626-2641`).
    pub router_ipv6: Option<Ipv6Addr>,
    /// `--router-mac-ipv6` / `--router-ipv6` (C `router_mac_ipv6`, `main-conf.c:2614-2624`): NDP не нужен.
    pub router_mac_ipv6: Option<[u8; 6]>,
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

/// Цели-пробы IPv6: первый и последний unicast-адреса итогового набора.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Targets6 {
    pub first: Ipv6Addr,
    pub last: Ipv6Addr,
    pub single: bool,
}

/// Следующий хоп IPv6: известный MAC или адрес, который резолвит NDP Neighbor Solicitation (R11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextHop6 {
    Mac([u8; 6], Source),
    Resolve { ip: Ipv6Addr, why: NextHopWhy },
}

/// Обнаружение IPv6 одного адаптера (C `main-initadapter.c:212-261`): интерфейс, MAC, адрес источника IPv6 и
/// следующий хоп IPv6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedV6 {
    pub iface: Iface,
    pub iface_source: Source,
    pub source_ipv6: (Ipv6Addr, Source),
    pub source_mac: ([u8; 6], Source),
    pub next_hop: NextHop6,
}

/// Подсказки masscan для отказов маршрутизатора (C `main-initadapter.c:196–198`).
pub(crate) const ROUTER_HINTS: &str = "\n    [hint] try \"--router-ip 192.0.2.1\" to specify different router\n    [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP\n    [hint] try \"--interface eth0\" to change interface";

/// Подсказки отказов маршрутизатора IPv6: C (`main-initadapter.c:255-256`) называет `--router-mac-ipv6` и
/// `--interface`; первая строка про `--router-ip <IPv6>` (ключа у C нет, у NS-резолвера R11 он есть).
pub(crate) const ROUTER_HINTS6: &str = "\n    [hint] try \"--router-ip 2001:db8::1\" to specify different router\n    [hint] try \"--router-mac-ipv6 66-55-44-33-22-11\" instead to bypass NDP\n    [hint] try \"--interface eth0\" to change interface";

/// Адрес IPv6 в строках отказов и `[+]`: `ipv6address_fmt` C в скобках, как `source-ip = [%s]`
/// (`main-initadapter.c:229`).
pub(crate) fn bracket6(ip: &Ipv6Addr) -> String {
    format!("[{}]", format_ipv6_c(u128::from(*ip)))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DetectError {
    #[error(
        "FAIL: no unicast target addresses to route to\n    [hint] targets must include an address outside 0.0.0.0/8, 127.0.0.0/8 and 224.0.0.0/3"
    )]
    NoUnicastTargets,
    #[error("FAIL: could not determine default interface\n    [hint] try \"--interface ethX\"")]
    NoRoute(Ipv4Addr),
    #[error(
        "FAIL: {ip} is an address of this host (route via {ifname}){}",
        if *.with_adapter { ROUTER_HINTS } else { "\n    [hint] try \"--interface ethX\" and \"--router-ip 192.0.2.1\"" }
    )]
    /// Цель это адрес самого хоста. `with_adapter`: отказ на пути `--adapter` (как у `SplitRoutes`), интерфейс уже
    /// задан, поэтому вместо `--interface ethX` подсказки маршрутизатора C.
    LocalTarget {
        ip: Ipv4Addr,
        ifname: String,
        with_adapter: bool,
    },
    #[error(
        "FAIL: targets are routed differently ({} via {}, {} via {}){}",
        .first.0, .first.1, .last.0, .last.1,
        if *.with_adapter { ROUTER_HINTS } else { "\n    [hint] try \"--interface ethX\"" }
    )]
    /// Первая и последняя цель идут разными маршрутами (интерфейс или шлюз): без `--adapter` при выборе интерфейса, с
    /// `--adapter` при поиске следующего хопа, если не заданы `--router-ip`/`--router-mac` (как и `LocalTarget`).
    /// `with_adapter`: интерфейс уже задан, поэтому вместо `--interface ethX` подсказки маршрутизатора C.
    SplitRoutes {
        first: (Ipv4Addr, String),
        last: (Ipv4Addr, String),
        with_adapter: bool,
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
    #[error(
        "FAIL: no unicast IPv6 target addresses to route to\n    [hint] targets must include an IPv6 address other than ::, ::1 and ff00::/8"
    )]
    NoUnicastTargets6,
    /// Нет маршрута IPv6 к цели: текст C для интерфейса, который не найден (`main-initadapter.c:52-53`).
    #[error("FAIL: could not determine default interface\n    [hint] try \"--interface ethX\"")]
    NoRoute6(Ipv6Addr),
    #[error(
        "FAIL: {} is an address of this host (route via {ifname}){}",
        bracket6(.ip),
        if *.with_adapter { ROUTER_HINTS6 } else { "\n    [hint] try \"--interface ethX\" and \"--router-ip 2001:db8::1\"" }
    )]
    LocalTarget6 {
        ip: Ipv6Addr,
        ifname: String,
        with_adapter: bool,
    },
    #[error(
        "FAIL: targets are routed differently ({} via {}, {} via {}){}",
        bracket6(&.first.0), .first.1, bracket6(&.last.0), .last.1,
        if *.with_adapter { ROUTER_HINTS6 } else { "\n    [hint] try \"--interface ethX\"" }
    )]
    SplitRoutes6 {
        first: (Ipv6Addr, String),
        last: (Ipv6Addr, String),
        with_adapter: bool,
    },
    /// Текст C `main-initadapter.c:221-225`.
    #[error(
        "FAIL: failed to detect IPv6 address of interface \"{0}\"\n    [hint] did you spell the name correctly?\n    [hint] if it has no IP address, manually set with something like \"--source-ip 2001:3b8::1234\""
    )]
    NoIpv6(String),
    #[error(
        "FAIL: no IPv6 default gateway on interface \"{ifname}\" for several on-link targets{}",
        ROUTER_HINTS6
    )]
    NoGateway6 { ifname: String },
    #[error(
        "FAIL: route doesn't match interface: {} is routed via {route_ifname}, not \"{adapter}\"{}",
        bracket6(.ip),
        ROUTER_HINTS6
    )]
    RouteNotViaAdapter6 {
        ip: Ipv6Addr,
        adapter: String,
        route_ifname: String,
    },
    /// Маршрут IPv6 к первой цели (а не пользователь) выбрал интерфейс, которого нет в списке интерфейсов. Windows:
    /// адаптер без привязки IPv4 (список это `GetAdaptersAddresses(AF_INET)`); на Linux и macOS список полный, там
    /// это гонка с исчезнувшим интерфейсом. Пользователь имени не называл, поэтому не `NoSuchAdapter` с «did you
    /// spell the name correctly?».
    #[error(
        "FAIL: the IPv6 route to {} uses interface index {ifindex}, which is not in the adapter list (on Windows: an adapter without an IPv4 binding)\n    [hint] try \"--interface ethX\" with \"--source-ip 2001:db8::1\" and \"--router-mac-ipv6 66-55-44-33-22-11\"",
        bracket6(.ip)
    )]
    RouteIfaceNotListed6 { ip: Ipv6Addr, ifindex: u32 },
    /// Смешанный скан: первая цель IPv4 и первая цель IPv6 уходят разными интерфейсами, а адаптер у скана один.
    #[error(
        "FAIL: IPv4 and IPv6 targets are routed via different interfaces ({} via {}, {} via {})\n    [hint] scan the IPv4 and the IPv6 targets separately, or try \"--interface ethX\"",
        .v4.0, .v4.1, bracket6(&.v6.0), .v6.1
    )]
    FamiliesSplit {
        v4: (Ipv4Addr, String),
        v6: (Ipv6Addr, String),
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

/// Маршрут к целям-пробам: первая и последняя цель обязаны дать один интерфейс и один шлюз. `with_adapter`: зов с
/// пути `--adapter` (поиск следующего хопа), влияет только на подсказки отказов.
fn route_for_targets(
    t: &Targets,
    routes: &dyn RouteTable,
    with_adapter: bool,
) -> Result<Route, DetectError> {
    let one = |ip: Ipv4Addr| -> Result<Route, DetectError> {
        let r = routes.lookup(ip)?.ok_or(DetectError::NoRoute(ip))?;
        if r.local {
            return Err(DetectError::LocalTarget {
                ip,
                ifname: r.ifname,
                with_adapter,
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
                with_adapter,
            });
        }
    }
    Ok(first)
}

/// Интерфейс по `--adapter`: имя, `device_id` (Windows `\\Device\\NPF_{GUID}`) или описание, без учёта регистра у
/// последних двух.
fn find_adapter(list: Vec<Iface>, a: &str) -> Result<Iface, DetectError> {
    list.into_iter()
        .find(|i| {
            i.name == a
                || i.device_id.eq_ignore_ascii_case(a)
                || i.description
                    .as_deref()
                    .is_some_and(|d| d.eq_ignore_ascii_case(a))
        })
        .ok_or_else(|| DetectError::NoSuchAdapter(a.to_string()))
}

/// Интерфейс годится для кадров: Ethernet и поднят.
fn check_usable(iface: &Iface) -> Result<(), DetectError> {
    if !iface.ethernet {
        return Err(DetectError::NotUsable {
            name: iface.name.clone(),
            reason: "not Ethernet",
        });
    }
    if !iface.up {
        return Err(DetectError::NotUsable {
            name: iface.name.clone(),
            reason: "down",
        });
    }
    Ok(())
}

/// MAC источника: `--adapter-mac` (пригодный) или MAC интерфейса; скрытый ОС MAC это отказ.
fn pick_source_mac(ov: &Overrides, iface: &Iface) -> Result<([u8; 6], Source), DetectError> {
    match ov.adapter_mac {
        Some(m) if usable_source_mac(m) => Ok((m, Source::Given)),
        Some(_) => Err(DetectError::NoMac(iface.name.clone())),
        None if iface.mac_masked => Err(DetectError::MacMasked(iface.name.clone())),
        None => match iface.mac {
            Some(m) if usable_source_mac(m) => Ok((m, Source::Detected)),
            _ => Err(DetectError::NoMac(iface.name.clone())),
        },
    }
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
        Some(a) => (find_adapter(list, a)?, Source::Given, None),
        None => {
            let r = route_for_targets(t, routes, false)?;
            let found = list.into_iter().find(|i| i.index == r.ifindex);
            (
                found.ok_or_else(|| DetectError::NoSuchAdapter(r.ifname.clone()))?,
                Source::Detected,
                Some(r),
            )
        }
    };
    check_usable(&iface)?;
    let source_ipv4 = match (ov.adapter_ip, iface.ipv4.first()) {
        (Some(ip), _) => (ip, Source::Given),
        (None, Some(ip)) => (*ip, Source::Detected),
        (None, None) => return Err(DetectError::NoIpv4(iface.name)),
    };
    let source_mac = pick_source_mac(ov, &iface)?;
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
        None => match route_for_targets(t, routes, true) {
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

// ------------------------------------------------------------------------------------------------------------ IPv6

/// Unicast IPv6 для проб: всё, кроме `::`, `::1` и `ff00::/8` (`::/0` даёт `::2 .. feff:…:ffff`).
const UNICAST6_SEGMENT: (u128, u128) = (2, 0xfeff_ffff_ffff_ffff_ffff_ffff_ffff_ffff);

/// Первый и последний unicast-адреса IPv6 итогового набора; `None`, если их нет (в том числе без целей IPv6).
pub fn probe_targets_v6(massip: &MassIp) -> Option<Targets6> {
    let (a, b) = UNICAST6_SEGMENT;
    let mut lo: Option<u128> = None;
    let mut hi: Option<u128> = None;
    for r in massip.ipv6().as_slice() {
        let s = r.begin.max(a);
        let e = r.end.min(b);
        if s <= e {
            lo = Some(lo.map_or(s, |v| v.min(s)));
            hi = Some(hi.map_or(e, |v| v.max(e)));
        }
    }
    let (first, last) = (Ipv6Addr::from(lo?), Ipv6Addr::from(hi?));
    Some(Targets6 {
        first,
        last,
        single: first == last,
    })
}

/// `fe80::/10`.
fn is_link_local6(a: &Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

/// Годится как адрес источника IPv6: не `::`, не `::1`, не multicast. ULA (`fc00::/7`) и `2001:db8::/32` годятся
/// (C `rawsock-getip6.c:68-71` их отбрасывает, спека Р3: стенды живут на ULA).
fn usable_source_ipv6(a: &Ipv6Addr) -> bool {
    !a.is_unspecified() && !a.is_loopback() && !a.is_multicast()
}

/// Источник из адресов интерфейса: для цели вне link-local первый пригодный не link-local адрес; для цели link-local
/// первый пригодный link-local, иначе первый пригодный любой. C берёт первый адрес интерфейса с `hi>>56 < 0xFC` вне
/// `2001:db8::/32` (`rawsock-getip6.c:54-75`; Windows последний подходящий, `:155-191`).
fn pick_source_ipv6(addrs: &[Ipv6Addr], target: &Ipv6Addr) -> Option<Ipv6Addr> {
    let usable = || addrs.iter().filter(|a| usable_source_ipv6(a));
    if is_link_local6(target) {
        usable()
            .find(|a| is_link_local6(a))
            .or_else(|| usable().next())
            .copied()
    } else {
        usable().find(|a| !is_link_local6(a)).copied()
    }
}

/// Маршрут IPv6 к целям-пробам: первая и последняя цель обязаны дать один интерфейс и один шлюз.
fn route6_for_targets(
    t: &Targets6,
    routes: &dyn RouteTable,
    with_adapter: bool,
) -> Result<RouteV6, DetectError> {
    let one = |ip: Ipv6Addr| -> Result<RouteV6, DetectError> {
        let r = routes.lookup_v6(ip)?.ok_or(DetectError::NoRoute6(ip))?;
        if r.local {
            return Err(DetectError::LocalTarget6 {
                ip,
                ifname: r.ifname,
                with_adapter,
            });
        }
        Ok(r)
    };
    let first = one(t.first)?;
    if !t.single {
        let last = one(t.last)?;
        if last.ifindex != first.ifindex || last.gateway != first.gateway {
            return Err(DetectError::SplitRoutes6 {
                first: (t.first, first.ifname),
                last: (t.last, last.ifname),
                with_adapter,
            });
        }
    }
    Ok(first)
}

struct ChosenV6 {
    iface: Iface,
    iface_source: Source,
    source_ipv6: (Ipv6Addr, Source),
    source_mac: ([u8; 6], Source),
    /// Маршрут к целям, если он уже искался (без `--adapter`).
    route: Option<RouteV6>,
}

fn choose_v6(
    t: &Targets6,
    ov: &Overrides,
    routes: &dyn RouteTable,
    ifaces: &dyn Interfaces,
) -> Result<ChosenV6, DetectError> {
    let list = ifaces.list()?;
    let (iface, iface_source, route) = match &ov.adapter {
        Some(a) => (find_adapter(list, a)?, Source::Given, None),
        None => {
            let r = route6_for_targets(t, routes, false)?;
            let found = list.into_iter().find(|i| i.index == r.ifindex);
            (
                found.ok_or(DetectError::RouteIfaceNotListed6 {
                    ip: t.first,
                    ifindex: r.ifindex,
                })?,
                Source::Detected,
                Some(r),
            )
        }
    };
    check_usable(&iface)?;
    let source_ipv6 = match ov.adapter_ipv6 {
        Some(ip) => (ip, Source::Given),
        None => {
            let addrs = ifaces.ipv6_addrs(&iface)?;
            // Источник, который выбрала ОС для маршрута (Linux `RTA_PREFSRC`, Windows `BestSourceAddress`), если это
            // пригодный адрес самого интерфейса под тем же правилом link-local, что у `pick_source_ipv6` (link-local
            // только для цели link-local: ядро отдаёт его, когда глобального адреса нет или он ещё tentative, а скан с
            // `fe80::…` роутеры отбрасывают); иначе правило адресов интерфейса или отказ `NoIpv6`, как у C.
            let from_route = route.as_ref().and_then(|r| r.source).filter(|s| {
                usable_source_ipv6(s)
                    && (!is_link_local6(s) || is_link_local6(&t.first))
                    && addrs.contains(s)
            });
            match from_route.or_else(|| pick_source_ipv6(&addrs, &t.first)) {
                Some(ip) => (ip, Source::Detected),
                None => return Err(DetectError::NoIpv6(iface.name)),
            }
        }
    };
    let source_mac = pick_source_mac(ov, &iface)?;
    Ok(ChosenV6 {
        iface,
        iface_source,
        source_ipv6,
        source_mac,
        route,
    })
}

/// Следующий хоп IPv6 (R11): `--router-mac-ipv6`, затем `--router-ip <IPv6>`, затем шлюз маршрута к целям, единственная
/// on-link цель, шлюз IPv6 по умолчанию интерфейса для нескольких on-link целей. Тот же порядок, что у IPv4
/// ([`next_hop`]).
fn next_hop_v6(
    t: &Targets6,
    ov: &Overrides,
    c: &ChosenV6,
    routes: &dyn RouteTable,
) -> Result<NextHop6, DetectError> {
    if let Some(m) = ov.router_mac_ipv6 {
        return Ok(NextHop6::Mac(m, Source::Given));
    }
    if let Some(ip) = ov.router_ipv6 {
        return Ok(NextHop6::Resolve {
            ip,
            why: NextHopWhy::Given,
        });
    }
    let route = match &c.route {
        Some(r) => r.clone(),
        None => match route6_for_targets(t, routes, true) {
            Err(DetectError::NoRoute6(_)) => {
                return Err(DetectError::NoGateway6 {
                    ifname: c.iface.name.clone(),
                });
            }
            other => other?,
        },
    };
    if route.ifindex != c.iface.index {
        return Err(DetectError::RouteNotViaAdapter6 {
            ip: t.first,
            adapter: c.iface.name.clone(),
            route_ifname: route.ifname,
        });
    }
    if let Some(g) = route.gateway {
        return Ok(NextHop6::Resolve {
            ip: g,
            why: NextHopWhy::RouteGateway,
        });
    }
    if t.single {
        return Ok(NextHop6::Resolve {
            ip: t.first,
            why: NextHopWhy::OnLinkTarget,
        });
    }
    routes
        .default_routes_v6()?
        .into_iter()
        .find(|r| r.ifindex == route.ifindex && r.gateway.is_some())
        .and_then(|r| r.gateway)
        .map(|ip| NextHop6::Resolve {
            ip,
            why: NextHopWhy::InterfaceDefaultGateway,
        })
        .ok_or(DetectError::NoGateway6 {
            ifname: c.iface.name.clone(),
        })
}

fn finish_v6(c: ChosenV6, next_hop: NextHop6) -> DetectedV6 {
    DetectedV6 {
        iface: c.iface,
        iface_source: c.iface_source,
        source_ipv6: c.source_ipv6,
        source_mac: c.source_mac,
        next_hop,
    }
}

/// Обнаружение IPv6: интерфейс по маршруту ОС к первой цели IPv6 (или `--adapter`), адрес источника IPv6, MAC и
/// следующий хоп IPv6. Ничего не отправляет.
pub fn detect_v6(
    t: &Targets6,
    ov: &Overrides,
    routes: &dyn RouteTable,
    ifaces: &dyn Interfaces,
) -> Result<DetectedV6, DetectError> {
    let c = choose_v6(t, ov, routes, ifaces)?;
    let nh = next_hop_v6(t, ov, &c, routes)?;
    Ok(finish_v6(c, nh))
}

/// Для `--offline`: интерфейс, адрес источника и MAC по тем же правилам, следующий хоп не ищется; MAC шлюза IPv6
/// фиктивный `66-55-44-33-22-11` и при `--router-mac-ipv6` (C `main-initadapter.c:235-238`).
pub fn detect_v6_offline(
    t: &Targets6,
    ov: &Overrides,
    routes: &dyn RouteTable,
    ifaces: &dyn Interfaces,
) -> Result<DetectedV6, DetectError> {
    let c = choose_v6(t, ov, routes, ifaces)?;
    Ok(finish_v6(
        c,
        NextHop6::Mac(OFFLINE_ROUTER_MAC, Source::Given),
    ))
}

/// Смешанный скан IPv4 + IPv6 на одном адаптере: сначала IPv4, затем IPv6 (порядок C, `main-initadapter.c:122, 212`).
/// Если первые цели семей уходят разными интерфейсами, это [`DetectError::FamiliesSplit`]: у адаптера одна пара
/// TX/RX, а C в этом случае молча отправил бы кадры IPv6 в интерфейс маршрута IPv4 (`main-initadapter.c:44-57`).
pub fn detect_mixed(
    t4: &Targets,
    t6: &Targets6,
    ov: &Overrides,
    routes: &dyn RouteTable,
    ifaces: &dyn Interfaces,
    offline: bool,
) -> Result<(Detected, DetectedV6), DetectError> {
    let (d4, d6) = if offline {
        (
            detect_offline(t4, ov, routes, ifaces)?,
            detect_v6_offline(t6, ov, routes, ifaces)?,
        )
    } else {
        (
            detect(t4, ov, routes, ifaces)?,
            detect_v6(t6, ov, routes, ifaces)?,
        )
    };
    if d4.iface.index != d6.iface.index || d4.iface.name != d6.iface.name {
        return Err(DetectError::FamiliesSplit {
            v4: (t4.first, d4.iface.name),
            v6: (t6.first, d6.iface.name),
        });
    }
    Ok((d4, d6))
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

#[cfg(test)]
#[path = "discover6_tests.rs"]
mod discover6_tests;
