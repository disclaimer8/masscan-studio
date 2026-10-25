//! Сведения об интерфейсе через `if_nametoindex` и `getifaddrs` (AF_LINK /
//! AF_INET). Без привилегий и без открытия BPF.

use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;

use super::Errno;
use super::sys::IFT_ETHER;
use crate::{IfaceReport, NetError};

/// Канальный уровень интерфейса (из AF_LINK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LinkInfo {
    pub sdl_type: u8,
    pub mac: Option<[u8; 6]>,
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
        // SAFETY: указатель получен из успешного `getifaddrs`, не копируется
        // наружу и освобождается ровно один раз (Drop вызывается один раз).
        unsafe { libc::freeifaddrs(self.0) };
    }
}

/// Разбор `sockaddr_dl`; `None` при некорректной длине.
///
/// # Safety
/// `sa` указывает на валидный `sockaddr` семейства AF_LINK, занимающий
/// `sa_len` байт.
unsafe fn parse_link(sa: *const libc::sockaddr) -> LinkInfo {
    let sdl = sa.cast::<libc::sockaddr_dl>();
    // SAFETY: по контракту функции `sa` это `sockaddr_dl`.
    let (len, ty, nlen, alen) = unsafe {
        (
            usize::from((*sdl).sdl_len),
            (*sdl).sdl_type,
            usize::from((*sdl).sdl_nlen),
            usize::from((*sdl).sdl_alen),
        )
    };
    let data_off = std::mem::offset_of!(libc::sockaddr_dl, sdl_data);
    let mac = if alen == 6 && data_off + nlen + 6 <= len {
        let mut m = [0u8; 6];
        // SAFETY: проверено, что [data_off+nlen, +6) лежит внутри `sdl_len`
        // байт, выделенных ОС под этот адрес.
        unsafe {
            std::ptr::copy_nonoverlapping(sa.cast::<u8>().add(data_off + nlen), m.as_mut_ptr(), 6);
        }
        Some(m)
    } else {
        None
    };
    LinkInfo { sdl_type: ty, mac }
}

/// Снимок всех записей `getifaddrs`.
pub(crate) fn raw_addrs() -> Result<Vec<RawAddr>, Errno> {
    let list = IfAddrs::get()?;
    let mut out = Vec::new();
    let mut cur = list.0;
    while !cur.is_null() {
        // SAFETY: `cur` это элемент списка, живущего до конца `list`.
        let e = unsafe { &*cur };
        // SAFETY: `ifa_name` это NUL-terminated строка внутри списка.
        let name = unsafe { CStr::from_ptr(e.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let kind = if e.ifa_addr.is_null() {
            AddrKind::Other
        } else {
            // SAFETY: `ifa_addr` не null и указывает на `sockaddr` с корректным
            // sa_family; ветви читают структуру того семейства, что объявлено.
            unsafe {
                match i32::from((*e.ifa_addr).sa_family) {
                    libc::AF_LINK => AddrKind::Link(parse_link(e.ifa_addr)),
                    libc::AF_INET => {
                        let sin = e.ifa_addr.cast::<libc::sockaddr_in>();
                        AddrKind::V4(Ipv4Addr::from(u32::from_be((*sin).sin_addr.s_addr)))
                    }
                    _ => AddrKind::Other,
                }
            }
        };
        out.push(RawAddr {
            name,
            flags: e.ifa_flags,
            kind,
        });
        cur = e.ifa_next;
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

fn merge(addrs: Vec<RawAddr>, q: &dyn IfaceInfo) -> Vec<IfaceReport> {
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
                r.mac = l.mac;
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

fn errno_msg(op: &str, e: Errno) -> String {
    format!("{op}: {}", std::io::Error::from_raw_os_error(e))
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

/// MAC интерфейса по имени; `None`, если неизвестен.
pub(crate) fn nic_mac(name: &str) -> Option<[u8; 6]> {
    OsIface.link(name).ok().flatten().and_then(|l| l.mac)
}
