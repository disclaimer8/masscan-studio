//! Сведения об интерфейсе через `if_nametoindex` и `getifaddrs` (AF_LINK /
//! AF_INET / AF_INET6). Без привилегий и без открытия BPF.

use crate::network_plan::{InterfaceObservation, Ipv4Prefix, check_observation};
use std::ffi::{CStr, CString};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;

use super::sys::IFT_ETHER;
use super::{Errno, errno_msg};
use crate::adapter_common::valid_ifname;
use crate::discover::{DARWIN_MASKED_MAC, Iface};
use crate::{IfaceReport, NetError};

/// Канальный уровень интерфейса (из AF_LINK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LinkInfo {
    pub sdl_type: u8,
    pub mac: Option<[u8; 6]>,
}

impl LinkInfo {
    /// Измеренный MAC: плейсхолдер не считается значением.
    pub(crate) fn visible_mac(&self) -> Option<[u8; 6]> {
        self.mac.filter(|m| *m != DARWIN_MASKED_MAC)
    }

    pub(crate) fn masked(&self) -> bool {
        self.mac == Some(DARWIN_MASKED_MAC)
    }
}

/// Шов запросов к ОС об интерфейсе (подменяется в тестах).
pub(crate) trait IfaceInfo {
    /// `Ok(None)`: такого интерфейса нет.
    fn ifindex(&self, name: &str) -> Result<Option<u32>, Errno>;
    /// `Ok(None)`: у интерфейса нет AF_LINK адреса.
    fn link(&self, name: &str) -> Result<Option<LinkInfo>, Errno>;
}

/// Запись `getifaddrs`, скопированная в безопасные типы.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawAddr {
    pub name: String,
    pub flags: u32,
    pub kind: AddrKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AddrKind {
    Link(LinkInfo),
    V4 {
        address: Ipv4Addr,
        prefix: Option<u8>,
    },
    /// Адрес IPv6 без встроенной KAME-зоны (`route_parse::in6_from_sockaddr`). Сводка интерфейсов IPv4 ([`merge`])
    /// его не читает; его берёт только обнаружение IPv6 ([`ipv6_addrs`]).
    V6(Ipv6Addr),
    Other,
}

/// Владеющий список `getifaddrs`: `freeifaddrs` ровно один раз в `Drop`.
struct IfAddrs(*mut libc::ifaddrs);

impl IfAddrs {
    fn get() -> Result<Self, Errno> {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: `head` это валидный out-указатель; при успехе ОС передаёт
        // владение списком, который освобождает только `Drop`.
        let rc = unsafe { libc::getifaddrs(&mut head) };
        if rc != 0 {
            return Err(crate::unix_sys::last_errno());
        }
        Ok(IfAddrs(head))
    }
}

/// Запись списка `getifaddrs` как срезы байт внутри списка (живут не дольше [`IfAddrs`]).
pub(crate) struct Entry<'a> {
    pub name: &'a CStr,
    pub flags: u32,
    /// `max(sa_len, 2)` байт: семейство это байт 1 при любом `sa_len`, как читалось `sa_family`.
    pub addr: Option<&'a [u8]>,
    /// Ровно `sa_len` байт; пустой срез допустим (Darwin шлёт маску 0.0.0.0 с `sa_len` 0).
    pub netmask: Option<&'a [u8]>,
}

impl IfAddrs {
    /// Записи списка с непустым именем, в порядке `getifaddrs`.
    fn entries(&self) -> Vec<Entry<'_>> {
        let mut out = Vec::new();
        let mut cur = self.0;
        while !cur.is_null() {
            // SAFETY: `cur` это элемент списка, который живёт до `Drop` у `self`, а `&self` заимствован на весь
            // срок возвращённых записей.
            let e = unsafe { &*cur };
            cur = e.ifa_next;
            if e.ifa_name.is_null() {
                continue;
            }
            // SAFETY: `ifa_name` не null и это NUL-terminated строка внутри списка.
            let name = unsafe { CStr::from_ptr(e.ifa_name) };
            let addr = (!e.ifa_addr.is_null()).then(|| {
                // SAFETY: `ifa_addr` не null и указывает на `sockaddr` внутри списка. Контракт ОС: `getifaddrs`
                // копирует каждую запись с её `sa_len`, поэтому читаемы `sa_len` байт, а заголовок адреса (`sa_len`,
                // `sa_family`) занимает минимум 2 байта; отсюда читается `max(sa_len, 2)` байт записи.
                unsafe {
                    let len = usize::from((*e.ifa_addr).sa_len).max(2);
                    std::slice::from_raw_parts(e.ifa_addr.cast::<u8>(), len)
                }
            });
            let netmask = (!e.ifa_netmask.is_null()).then(|| {
                // SAFETY: `ifa_netmask` не null и указывает на запись внутри списка. Контракт ОС тот же: `getifaddrs`
                // копирует запись с её `sa_len`, поэтому читаемы `sa_len` байт; Darwin может опустить хвостовые
                // нулевые байты, поэтому читается ровно `sa_len` байт (возможно 0).
                unsafe {
                    let len = usize::from((*e.ifa_netmask).sa_len);
                    std::slice::from_raw_parts(e.ifa_netmask.cast::<u8>(), len)
                }
            });
            out.push(Entry {
                name,
                flags: e.ifa_flags,
                addr,
                netmask,
            });
        }
        out
    }
}

/// Разбор адреса `getifaddrs` из байт записи, без допущений о выравнивании. Длина записи это байт 0 (`sa_len`),
/// семейство байт 1; разбор идёт по первым `sa_len` байтам (но не дальше среза). `None` и записи короче минимума
/// семейства это [`AddrKind::Other`]. Префикс IPv4 берётся из маски (`None` без маски).
pub(crate) fn addr_kind(addr: Option<&[u8]>, netmask: Option<&[u8]>) -> AddrKind {
    const SIN_MIN: usize = std::mem::offset_of!(libc::sockaddr_in, sin_addr) + 4;
    const SIN6_MIN: usize = std::mem::offset_of!(libc::sockaddr_in6, sin6_addr) + 16;
    let Some(addr) = addr else {
        return AddrKind::Other;
    };
    let (Some(&len), Some(&family)) = (addr.first(), addr.get(1)) else {
        return AddrKind::Other;
    };
    let sa_len = usize::from(len);
    let rec = &addr[..sa_len.min(addr.len())];
    match i32::from(family) {
        libc::AF_LINK => link_from_bytes(rec).map_or(AddrKind::Other, AddrKind::Link),
        libc::AF_INET if sa_len >= SIN_MIN && rec.len() >= SIN_MIN => {
            let offset = std::mem::offset_of!(libc::sockaddr_in, sin_addr);
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&rec[offset..offset + 4]);
            AddrKind::V4 {
                address: Ipv4Addr::from(octets),
                prefix: netmask.and_then(prefix_from_sockaddr),
            }
        }
        libc::AF_INET6 if sa_len >= SIN6_MIN && rec.len() >= SIN6_MIN => {
            crate::route_parse::in6_from_sockaddr(rec).map_or(AddrKind::Other, AddrKind::V6)
        }
        _ => AddrKind::Other,
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        // SAFETY: указатель получен из успешного `getifaddrs`, не копируется
        // наружу и освобождается ровно один раз (Drop вызывается один раз).
        unsafe { libc::freeifaddrs(self.0) };
    }
}

/// Разбор записи `sockaddr_dl` из ровно `sdl_len` байт. `None`, если запись
/// короче заголовка (8 байт). `mac` только при `sdl_alen == 6` и если адрес
/// `sdl_data[sdl_nlen..+6]` целиком лежит внутри записи.
pub(crate) fn link_from_bytes(rec: &[u8]) -> Option<LinkInfo> {
    const DATA_OFF: usize = std::mem::offset_of!(libc::sockaddr_dl, sdl_data);
    if rec.len() < DATA_OFF {
        return None;
    }
    let (ty, nlen, alen) = (rec[4], usize::from(rec[5]), usize::from(rec[6]));
    let mac = if alen == 6 && DATA_OFF + nlen + 6 <= rec.len() {
        rec[DATA_OFF + nlen..DATA_OFF + nlen + 6].try_into().ok()
    } else {
        None
    };
    Some(LinkInfo { sdl_type: ty, mac })
}

/// Снимок всех записей `getifaddrs`.
pub(crate) fn raw_addrs() -> Result<Vec<RawAddr>, Errno> {
    raw_addrs_until(Instant::now() + Duration::from_secs(10), &|| false)
}
fn raw_addrs_until(deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<Vec<RawAddr>, Errno> {
    let check = || {
        if cancelled() {
            Err(libc::ECANCELED)
        } else if Instant::now() >= deadline {
            Err(libc::ETIMEDOUT)
        } else {
            Ok(())
        }
    };
    check()?;
    let list = IfAddrs::get()?;
    check()?;
    let mut out = Vec::new();
    for e in list.entries() {
        check()?;
        out.push(RawAddr {
            name: e.name.to_string_lossy().into_owned(),
            flags: e.flags,
            kind: addr_kind(e.addr, e.netmask),
        });
    }
    Ok(out)
}

/// Реальная ОС.
pub(crate) struct OsIface;

impl IfaceInfo for OsIface {
    fn ifindex(&self, name: &str) -> Result<Option<u32>, Errno> {
        let c = CString::new(name).map_err(|_| libc::EINVAL)?;
        // SAFETY: `c` это NUL-terminated строка, живущая весь вызов.
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        if idx != 0 {
            return Ok(Some(idx));
        }
        // Не `unix_sys::last_errno`: здесь errno без номера значит «интерфейса нет», а не `EIO`.
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ENXIO) | Some(libc::ENODEV) | None => Ok(None),
            Some(e) => Err(e),
        }
    }

    fn link(&self, name: &str) -> Result<Option<LinkInfo>, Errno> {
        Ok(raw_addrs()?.into_iter().find_map(|a| match a.kind {
            AddrKind::Link(l) if a.name == name => Some(l),
            _ => None,
        }))
    }
}

/// Адреса IPv6 интерфейса `name` в порядке `getifaddrs` (без KAME-зоны). Флагов DAD `getifaddrs` не даёт: правило
/// выбора источника в `discover` берёт первый пригодный не link-local адрес, как C (`rawsock-getip6.c:230-251`).
pub(crate) fn ipv6_addrs(name: &str) -> Result<Vec<Ipv6Addr>, Errno> {
    Ok(raw_addrs()?
        .into_iter()
        .filter_map(|a| match a.kind {
            AddrKind::V6(ip) if a.name == name => Some(ip),
            _ => None,
        })
        .collect())
}

/// Все адреса IPv6 хоста (любой интерфейс): назначение среди них это адрес самого хоста.
pub(crate) fn all_ipv6_addrs() -> Result<Vec<Ipv6Addr>, Errno> {
    Ok(raw_addrs()?
        .into_iter()
        .filter_map(|a| match a.kind {
            AddrKind::V6(ip) => Some(ip),
            _ => None,
        })
        .collect())
}

/// Сводка по интерфейсам для инвентаря (порядок первого появления имени).
pub(crate) fn interfaces() -> Result<Vec<IfaceReport>, Errno> {
    Ok(merge(&raw_addrs()?, &OsIface))
}

/// Те же интерфейсы в терминах обнаружения ([`Iface`]): `device_id` это имя, описания нет; плейсхолдер MAC это
/// `mac: None, mac_masked: true`.
pub(crate) fn iface_list() -> Result<Vec<Iface>, Errno> {
    Ok(interfaces()?.into_iter().map(iface_from_report).collect())
}

pub(crate) fn iface_from_report(r: IfaceReport) -> Iface {
    Iface {
        device_id: r.name.clone(),
        name: r.name,
        index: r.index,
        description: None,
        mac: r.mac,
        mac_masked: r.mac_masked,
        ethernet: r.ethernet,
        up: r.up,
        ipv4: r.ipv4,
    }
}

pub(crate) fn merge(addrs: &[RawAddr], q: &dyn IfaceInfo) -> Vec<IfaceReport> {
    let mut out: Vec<IfaceReport> = Vec::new();
    for a in addrs {
        let pos = match out.iter().position(|r| r.name == a.name) {
            Some(p) => p,
            None => {
                let index = q.ifindex(&a.name).ok().flatten().unwrap_or(0);
                out.push(IfaceReport {
                    name: a.name.clone(),
                    index,
                    mac: None,
                    mac_masked: false,
                    ethernet: false,
                    up: false,
                    ipv4: Vec::new(),
                });
                out.len() - 1
            }
        };
        let r = &mut out[pos];
        if a.flags & libc::IFF_UP.cast_unsigned() != 0 {
            r.up = true;
        }
        match a.kind {
            AddrKind::Link(l) => {
                r.ethernet = l.sdl_type == IFT_ETHER;
                r.mac = l.visible_mac();
                r.mac_masked = l.masked();
            }
            AddrKind::V4 { address, .. } => r.ipv4.push(address),
            AddrKind::V6(_) | AddrKind::Other => {}
        }
    }
    out
}

/// Проверяет binding через ОС и возвращает ifindex. Без привилегий. Source IP и
/// MAC с ОС не сверяются (как на Linux/Windows).
pub(crate) fn verify_binding(q: &dyn IfaceInfo, binding: &AdapterBinding) -> Result<u32, NetError> {
    if binding.link_type != LinkType::Ethernet {
        return Err(NetError::UnsupportedLink(format!(
            "{:?} (macOS BPF supports Ethernet only)",
            binding.link_type
        )));
    }
    let name = binding.interface_id.as_str();
    if !valid_ifname(name) {
        return Err(NetError::InterfaceMismatch(format!(
            "invalid interface name {name:?}"
        )));
    }
    let sys = |op: &str, e: Errno| NetError::System(errno_msg(op, e));
    let ifindex = q
        .ifindex(name)
        .map_err(|e| sys("if_nametoindex", e))?
        .ok_or_else(|| NetError::InterfaceMismatch(format!("no such interface {name:?}")))?;
    let link = q
        .link(name)
        .map_err(|e| sys("getifaddrs", e))?
        .ok_or_else(|| {
            NetError::InterfaceMismatch(format!("interface {name:?} has no link address"))
        })?;
    if link.sdl_type != IFT_ETHER {
        return Err(NetError::UnsupportedLink(format!(
            "interface {name:?} has IFT type {}, not Ethernet",
            link.sdl_type
        )));
    }
    if link.mac.is_none() {
        return Err(NetError::UnsupportedLink(format!(
            "interface {name:?} has no 6-byte MAC"
        )));
    }
    Ok(ifindex)
}

/// MAC интерфейса по имени; `None`, если неизвестен или скрыт ОС плейсхолдером.
pub(crate) fn nic_mac(name: &str) -> Option<[u8; 6]> {
    OsIface
        .link(name)
        .ok()
        .flatten()
        .and_then(|l| l.visible_mac())
}

/// ОС вернула плейсхолдер вместо MAC.
pub(crate) fn nic_mac_masked(name: &str) -> bool {
    OsIface
        .link(name)
        .ok()
        .flatten()
        .is_some_and(|l| l.masked())
}

/// Существование интерфейса независимо от MAC (`if_nametoindex`).
pub(crate) fn iface_exists(name: &str) -> Option<bool> {
    OsIface.ifindex(name).ok().map(|i| i.is_some())
}

fn prefix_from_mask(mask: Ipv4Addr) -> Option<u8> {
    let mask = u32::from(mask);
    let length = mask.leading_ones();
    let expected = u32::MAX.checked_shl(32 - length).unwrap_or(0);
    // `leading_ones` числа `u32` лежит в 0..=32 и помещается в `u8`.
    (mask == expected).then_some(u8::try_from(length).unwrap_or(u8::MAX))
}
fn prefix_from_sockaddr(bytes: &[u8]) -> Option<u8> {
    let offset = std::mem::offset_of!(libc::sockaddr_in, sin_addr);
    if bytes.len() < 2 {
        return None;
    }
    let mut octets = [0; 4];
    for (i, octet) in octets.iter_mut().enumerate() {
        *octet = bytes.get(offset + i).copied().unwrap_or(0);
    }
    prefix_from_mask(Ipv4Addr::from(octets))
}
fn observations(addrs: Vec<RawAddr>, q: &dyn IfaceInfo) -> Vec<InterfaceObservation> {
    let reports = merge(&addrs, q);
    reports
        .into_iter()
        .map(|r| {
            let mut ipv4_prefixes: Vec<_> = addrs
                .iter()
                .filter(|a| a.name == r.name)
                .filter_map(|a| match a.kind {
                    AddrKind::V4 {
                        address,
                        prefix: Some(length),
                    } => Some(Ipv4Prefix { address, length }),
                    _ => None,
                })
                .collect();
            ipv4_prefixes.sort_unstable();
            ipv4_prefixes.dedup();
            InterfaceObservation {
                iface: iface_from_report(r),
                ipv4_prefixes,
            }
        })
        .collect()
}
pub(crate) fn observe(
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<InterfaceObservation>, NetError> {
    check_observation(deadline, cancelled)?;
    let addrs = raw_addrs_until(deadline, cancelled)
        .map_err(|e| NetError::System(errno_msg("getifaddrs", e)))?;
    check_observation(deadline, cancelled)?;
    let out = observations(addrs, &OsIface);
    check_observation(deadline, cancelled)?;
    Ok(out)
}
#[cfg(test)]
mod prefix_tests {
    use super::*;
    #[test]
    fn network_plan_prefixes_keep_aliases_and_ignore_missing_masks() {
        struct Q;
        impl IfaceInfo for Q {
            fn ifindex(&self, _: &str) -> Result<Option<u32>, Errno> {
                Ok(Some(2))
            }
            fn link(&self, _: &str) -> Result<Option<LinkInfo>, Errno> {
                panic!("records already contain links")
            }
        }
        let addrs = vec![
            RawAddr {
                name: "en0".into(),
                flags: libc::IFF_UP as u32,
                kind: AddrKind::Link(LinkInfo {
                    sdl_type: IFT_ETHER,
                    mac: Some([2, 1, 2, 3, 4, 5]),
                }),
            },
            RawAddr {
                name: "en0".into(),
                flags: libc::IFF_UP as u32,
                kind: AddrKind::V4 {
                    address: "192.168.1.10".parse().unwrap(),
                    prefix: Some(24),
                },
            },
            RawAddr {
                name: "en0".into(),
                flags: 0,
                kind: AddrKind::V4 {
                    address: "10.0.0.1".parse().unwrap(),
                    prefix: Some(31),
                },
            },
            RawAddr {
                name: "en0".into(),
                flags: 0,
                kind: AddrKind::V4 {
                    address: "203.0.113.1".parse().unwrap(),
                    prefix: None,
                },
            },
        ];
        let o = observations(addrs, &Q);
        assert_eq!(o.len(), 1);
        assert_eq!(o[0].iface.ipv4.len(), 3);
        assert_eq!(
            o[0].ipv4_prefixes,
            vec![
                Ipv4Prefix {
                    address: "10.0.0.1".parse().unwrap(),
                    length: 31
                },
                Ipv4Prefix {
                    address: "192.168.1.10".parse().unwrap(),
                    length: 24
                }
            ]
        );
    }
    #[test]
    fn network_plan_short_darwin_netmasks_zero_fill_trailing_octets() {
        assert_eq!(prefix_from_sockaddr(&[7, 2, 0, 0, 255, 255, 255]), Some(24));
        assert_eq!(
            prefix_from_sockaddr(&[8, 2, 0, 0, 255, 255, 255, 254]),
            Some(31)
        );
        assert_eq!(prefix_from_sockaddr(&[8, 2, 0, 0, 255, 0, 255, 0]), None);
        assert_eq!(prefix_from_sockaddr(&[]), None);
    }
    #[test]
    fn real_list_entries_include_loopback_v4_with_its_netmask() {
        let list = IfAddrs::get().unwrap();
        let entries = list.entries();
        let lo = entries
            .iter()
            .find(|e| {
                e.name.to_bytes() == b"lo0" && addr_kind(e.addr, e.netmask) != AddrKind::Other
            })
            .expect("lo0 has addresses");
        assert!(entries.iter().any(|e| {
            e.name.to_bytes() == b"lo0"
                && addr_kind(e.addr, e.netmask)
                    == AddrKind::V4 {
                        address: Ipv4Addr::LOCALHOST,
                        prefix: Some(8),
                    }
        }));
        assert_ne!(lo.flags & (libc::IFF_UP as u32), 0);
    }
    /// Pins the base decoder: Darwin may trim trailing zero octets of a netmask record, so a record of
    /// `sa_len` bytes is zero-filled up to the IPv4 address field; an empty or 1-byte record is no mask.
    #[test]
    fn netmask_records_decode_as_on_base() {
        assert_eq!(prefix_from_sockaddr(&[]), None);
        assert_eq!(prefix_from_sockaddr(&[1]), None);
        assert_eq!(prefix_from_sockaddr(&[5, 2, 0, 0, 255]), Some(8));
        assert_eq!(prefix_from_sockaddr(&[6, 2, 0, 0, 255, 255]), Some(16));
        assert_eq!(prefix_from_sockaddr(&[7, 2, 0, 0, 255, 255, 255]), Some(24));
        assert_eq!(
            prefix_from_sockaddr(&[8, 2, 0, 0, 255, 255, 255, 255]),
            Some(32)
        );
        assert_eq!(
            prefix_from_sockaddr(&[8, 2, 0, 0, 255, 0, 255, 0]),
            None,
            "a gap between the ones is not a mask"
        );
    }
    #[test]
    fn network_plan_prefix_masks_validate_contiguity_and_host_semantics() {
        for (mask, want) in [
            ("255.255.255.0", Some(24)),
            ("255.255.255.254", Some(31)),
            ("255.255.255.255", Some(32)),
            ("0.0.0.0", Some(0)),
            ("255.0.255.0", None),
        ] {
            assert_eq!(prefix_from_mask(mask.parse().unwrap()), want);
        }
    }
}
