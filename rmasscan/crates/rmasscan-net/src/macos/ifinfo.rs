//! Сведения об интерфейсе через `if_nametoindex` и `getifaddrs` (AF_LINK /
//! AF_INET). Без привилегий и без открытия BPF.

use crate::network_plan::{InterfaceObservation, Ipv4Prefix, check_observation};
use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;

use super::sys::IFT_ETHER;
use super::{Errno, errno_msg};
use crate::discover::Iface;
use crate::{IfaceReport, NetError};

/// Канальный уровень интерфейса (из AF_LINK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LinkInfo {
    pub sdl_type: u8,
    pub mac: Option<[u8; 6]>,
}

/// Плейсхолдер, который macOS 27 отдаёт непривилегированному процессу вместо MAC
/// Ethernet-интерфейсов (измерено: `getifaddrs` и `NET_RT_IFLIST`).
pub(crate) const MASKED_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0];

impl LinkInfo {
    /// Измеренный MAC: плейсхолдер не считается значением.
    pub(crate) fn visible_mac(&self) -> Option<[u8; 6]> {
        self.mac.filter(|m| *m != MASKED_MAC)
    }

    pub(crate) fn masked(&self) -> bool {
        self.mac == Some(MASKED_MAC)
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
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO));
        }
        Ok(IfAddrs(head))
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
    let mut cur = list.0;
    while !cur.is_null() {
        check()?;
        // SAFETY: `cur` это элемент списка, живущего до конца `list`.
        let e = unsafe { &*cur };
        cur = e.ifa_next;
        if e.ifa_name.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` не null и это NUL-terminated строка внутри списка.
        let name = unsafe { CStr::from_ptr(e.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let kind = if e.ifa_addr.is_null() {
            AddrKind::Other
        } else {
            // SAFETY: `ifa_addr` не null и указывает на `sockaddr`, чей первый
            // байт `sa_len` это размер записи; заголовок sockaddr (2 байта)
            // всегда валиден.
            let (family, sa_len) = unsafe {
                (
                    i32::from((*e.ifa_addr).sa_family),
                    usize::from((*e.ifa_addr).sa_len),
                )
            };
            const SIN_MIN: usize = std::mem::offset_of!(libc::sockaddr_in, sin_addr) + 4;
            match family {
                libc::AF_LINK => {
                    // SAFETY: запись занимает ровно `sa_len` байт по указателю
                    // `ifa_addr` внутри списка, живущего до конца `list`; срез
                    // копируется в owned-типы до выхода из итерации.
                    let rec =
                        unsafe { std::slice::from_raw_parts(e.ifa_addr.cast::<u8>(), sa_len) };
                    link_from_bytes(rec).map_or(AddrKind::Other, AddrKind::Link)
                }
                libc::AF_INET if sa_len >= SIN_MIN => {
                    // SAFETY: проверено `sa_len >= offsetof(sin_addr) + 4`, то
                    // есть поле `sin_addr` целиком внутри записи. `ifa_addr` выровнен
                    // как `sockaddr` (выделен `getifaddrs`), чего достаточно для `sockaddr_in`
                    // (поля читаются по выровненным смещениям).
                    let s_addr =
                        unsafe { (*e.ifa_addr.cast::<libc::sockaddr_in>()).sin_addr.s_addr };
                    let prefix = if e.ifa_netmask.is_null() {
                        None
                    } else {
                        // SAFETY: getifaddrs owns this netmask. Darwin may omit trailing zero
                        // bytes, so read only sa_len bytes and zero-fill missing IPv4 octets.
                        let len = unsafe { usize::from((*e.ifa_netmask).sa_len) };
                        // SAFETY: sa_len is the size of this owned sockaddr record.
                        let bytes =
                            unsafe { std::slice::from_raw_parts(e.ifa_netmask.cast::<u8>(), len) };
                        prefix_from_sockaddr(bytes)
                    };
                    AddrKind::V4 {
                        address: Ipv4Addr::from(u32::from_be(s_addr)),
                        prefix,
                    }
                }
                _ => AddrKind::Other,
            }
        };
        out.push(RawAddr {
            name,
            flags: e.ifa_flags,
            kind,
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

/// Сводка по интерфейсам для инвентаря (порядок первого появления имени).
pub(crate) fn interfaces() -> Result<Vec<IfaceReport>, Errno> {
    Ok(merge(raw_addrs()?, &OsIface))
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

pub(crate) fn merge(addrs: Vec<RawAddr>, q: &dyn IfaceInfo) -> Vec<IfaceReport> {
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
        if a.flags & (libc::IFF_UP as u32) != 0 {
            r.up = true;
        }
        match a.kind {
            AddrKind::Link(l) => {
                r.ethernet = l.sdl_type == IFT_ETHER;
                r.mac = l.visible_mac();
                r.mac_masked = l.masked();
            }
            AddrKind::V4 { address, .. } => r.ipv4.push(address),
            AddrKind::Other => {}
        }
    }
    out
}

fn valid_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() < libc::IFNAMSIZ
        && name != "."
        && name != ".."
        && !name
            .bytes()
            .any(|b| b == 0 || b == b'/' || b.is_ascii_whitespace())
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
    (mask == expected).then_some(length as u8)
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
    let reports = merge(addrs.clone(), q);
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
