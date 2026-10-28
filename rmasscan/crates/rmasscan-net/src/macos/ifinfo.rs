//! Сведения об интерфейсе через `if_nametoindex` и `getifaddrs` (AF_LINK /
//! AF_INET). Без привилегий и без открытия BPF.

use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;

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
    V4(Ipv4Addr),
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
    let list = IfAddrs::get()?;
    let mut out = Vec::new();
    let mut cur = list.0;
    while !cur.is_null() {
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
                    AddrKind::V4(Ipv4Addr::from(u32::from_be(s_addr)))
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
            AddrKind::V4(ip) => r.ipv4.push(ip),
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
