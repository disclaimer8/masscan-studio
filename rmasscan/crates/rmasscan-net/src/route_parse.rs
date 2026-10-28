//! Разбор ответов ядра о маршрутах и интерфейсах (AGPL-3.0): Linux rtnetlink, Darwin route socket, Windows IP Helper.
//!
//! Модуль безопасный и переносимый: ни системных вызовов, ни `unsafe`, ни типов `libc`/`windows-sys`. FFI-модули
//! (`linux::route`, `macos::route`, `windows::sys`) только отправляют собранные здесь байты запросов и отдают сюда
//! байты ответов или поля, уже скопированные в безопасные типы; тесты идут на любой ОС. Поля заголовков в родном
//! порядке байт (как их пишет ядро), адреса IPv4 в сетевом.

#![forbid(unsafe_code)]

#[cfg(any(windows, test))]
pub(crate) use iphlp::*;
#[cfg(any(target_os = "linux", test))]
pub(crate) use netlink::*;
#[cfg(any(target_os = "macos", test))]
pub(crate) use rtsock::*;

/// `AF_INET` одинаков на Linux и Darwin.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) const AF_INET: u8 = 2;

/// Чтение полей с проверкой границ: `None`, если поле не помещается в буфер (ничего не паникует).
#[cfg(any(target_os = "linux", target_os = "macos", test))]
mod bytes {
    use std::net::Ipv4Addr;

    pub(super) fn u16_at(b: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_ne_bytes(
            b.get(at..at.checked_add(2)?)?.try_into().ok()?,
        ))
    }

    pub(super) fn u32_at(b: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_ne_bytes(
            b.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    }

    pub(super) fn i32_at(b: &[u8], at: usize) -> Option<i32> {
        u32_at(b, at).map(|v| v as i32)
    }

    /// Адрес IPv4 в сетевом порядке байт.
    pub(super) fn ipv4_at(b: &[u8], at: usize) -> Option<Ipv4Addr> {
        let o: [u8; 4] = b.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(Ipv4Addr::from(o))
    }
}

/// Linux rtnetlink: `nlmsghdr` + `rtmsg` + `rtattr` (linux/netlink.h, linux/rtnetlink.h).
#[cfg(any(target_os = "linux", test))]
mod netlink {
    use std::net::Ipv4Addr;

    use super::AF_INET;
    use super::bytes::{i32_at, ipv4_at, u16_at, u32_at};
    use crate::discover::Route;

    /// `sizeof(struct nlmsghdr)`.
    pub(crate) const NLMSG_HDRLEN: usize = 16;
    /// `sizeof(struct rtmsg)`.
    pub(crate) const RTMSG_LEN: usize = 12;
    pub(crate) const NLMSG_ERROR: u16 = 2;
    pub(crate) const NLMSG_DONE: u16 = 3;
    pub(crate) const RTM_NEWROUTE: u16 = 24;
    pub(crate) const RTM_GETROUTE: u16 = 26;
    pub(crate) const NLM_F_REQUEST: u16 = 0x1;
    pub(crate) const NLM_F_DUMP: u16 = 0x300;
    pub(crate) const RTA_DST: u16 = 1;
    pub(crate) const RTA_OIF: u16 = 4;
    pub(crate) const RTA_GATEWAY: u16 = 5;
    pub(crate) const RTA_PRIORITY: u16 = 6;
    pub(crate) const RTA_TABLE: u16 = 15;
    pub(crate) const RTN_UNICAST: u8 = 1;
    pub(crate) const RTN_LOCAL: u8 = 2;
    pub(crate) const RTN_BLACKHOLE: u8 = 6;
    pub(crate) const RTN_UNREACHABLE: u8 = 7;
    pub(crate) const RTN_PROHIBIT: u8 = 8;
    pub(crate) const RT_TABLE_MAIN: u32 = 254;
    const RTA_HDRLEN: usize = 4;
    /// Биты `NLA_F_NESTED`/`NLA_F_NET_BYTEORDER` в `rta_type`.
    const NLA_TYPE_MASK: u16 = !(0x8000 | 0x4000);

    /// `NLMSG_ALIGN`/`RTA_ALIGN`: до кратного 4.
    fn align4(n: usize) -> usize {
        n.saturating_add(3) & !3
    }

    fn malformed(what: &str) -> NlError {
        NlError::Malformed(what.to_string())
    }

    /// `struct rtmsg` (linux/rtnetlink.h). `libc` его не объявляет, поэтому своя копия `repr(C)`; в запрос и из
    /// ответа она переносится по полям, без приведения указателей.
    #[repr(C)]
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct RtMsg {
        pub family: u8,
        pub dst_len: u8,
        pub src_len: u8,
        pub tos: u8,
        pub table: u8,
        pub protocol: u8,
        pub scope: u8,
        /// `rtm_type` (`RTN_*`).
        pub kind: u8,
        pub flags: u32,
    }

    const _: () = assert!(std::mem::size_of::<RtMsg>() == RTMSG_LEN);

    impl RtMsg {
        fn to_bytes(self) -> [u8; RTMSG_LEN] {
            let mut b = [0u8; RTMSG_LEN];
            b[..8].copy_from_slice(&[
                self.family,
                self.dst_len,
                self.src_len,
                self.tos,
                self.table,
                self.protocol,
                self.scope,
                self.kind,
            ]);
            b[8..].copy_from_slice(&self.flags.to_ne_bytes());
            b
        }

        fn from_bytes(b: &[u8]) -> Option<RtMsg> {
            let h = b.get(..8)?;
            Some(RtMsg {
                family: h[0],
                dst_len: h[1],
                src_len: h[2],
                tos: h[3],
                table: h[4],
                protocol: h[5],
                scope: h[6],
                kind: h[7],
                flags: u32_at(b, 8)?,
            })
        }
    }

    /// Маршрут из `RTM_NEWROUTE` (только `AF_INET`).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct NlRoute {
        /// `rtm_type` (`RTN_*`).
        pub kind: u8,
        pub dst_len: u8,
        /// `RTA_TABLE`, иначе `rtm_table`.
        pub table: u32,
        pub oif: Option<u32>,
        pub gateway: Option<Ipv4Addr>,
        /// `RTA_PRIORITY` (метрика), 0 без атрибута.
        pub priority: u32,
    }

    /// Отказ разбора: `NLMSG_ERROR` ядра (положительный errno) или искажённый ответ.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum NlError {
        Kernel(i32),
        Malformed(String),
    }

    impl std::fmt::Display for NlError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                NlError::Kernel(e) => {
                    write!(f, "netlink: {}", std::io::Error::from_raw_os_error(*e))
                }
                NlError::Malformed(m) => write!(f, "netlink: malformed reply: {m}"),
            }
        }
    }

    /// Запрос `RTM_GETROUTE`: с `dst` это lookup одного адреса (`NLM_F_REQUEST`, `dst_len` 32, `RTA_DST`), без него
    /// dump всех маршрутов IPv4 (`NLM_F_REQUEST | NLM_F_DUMP`).
    pub(crate) fn netlink_route_request(seq: u32, dst: Option<Ipv4Addr>) -> Vec<u8> {
        let attr_len = if dst.is_some() { RTA_HDRLEN + 4 } else { 0 };
        let len = NLMSG_HDRLEN + RTMSG_LEN + attr_len;
        let flags = match dst {
            Some(_) => NLM_F_REQUEST,
            None => NLM_F_REQUEST | NLM_F_DUMP,
        };
        let mut b = Vec::with_capacity(len);
        b.extend((len as u32).to_ne_bytes());
        b.extend(RTM_GETROUTE.to_ne_bytes());
        b.extend(flags.to_ne_bytes());
        b.extend(seq.to_ne_bytes());
        b.extend(0u32.to_ne_bytes()); // nlmsg_pid: заполняет ядро
        let rt = RtMsg {
            family: AF_INET,
            dst_len: if dst.is_some() { 32 } else { 0 },
            ..RtMsg::default()
        };
        b.extend(rt.to_bytes());
        if let Some(d) = dst {
            b.extend(((RTA_HDRLEN + 4) as u16).to_ne_bytes());
            b.extend(RTA_DST.to_ne_bytes());
            b.extend(d.octets());
        }
        b
    }

    /// Сообщения датаграммы: `(nlmsg_type, тело)`; длины проверены.
    fn split_messages(buf: &[u8]) -> Result<Vec<(u16, &[u8])>, NlError> {
        let mut out = Vec::new();
        let mut off = 0;
        while off < buf.len() {
            let rest = &buf[off..];
            let (Some(len), Some(ty)) = (u32_at(rest, 0), u16_at(rest, 4)) else {
                return Err(malformed("truncated nlmsghdr"));
            };
            let len = len as usize;
            if len < NLMSG_HDRLEN || len > rest.len() {
                return Err(malformed("nlmsg_len out of bounds"));
            }
            out.push((ty, &rest[NLMSG_HDRLEN..len]));
            off += align4(len).min(rest.len());
        }
        Ok(out)
    }

    /// Тело `RTM_NEWROUTE`: `rtmsg` и атрибуты; `None` для семейства не `AF_INET`.
    fn parse_route(body: &[u8]) -> Result<Option<NlRoute>, NlError> {
        let rt = RtMsg::from_bytes(body).ok_or_else(|| malformed("short rtmsg"))?;
        if rt.family != AF_INET {
            return Ok(None);
        }
        let mut r = NlRoute {
            kind: rt.kind,
            dst_len: rt.dst_len,
            table: u32::from(rt.table),
            oif: None,
            gateway: None,
            priority: 0,
        };
        let mut off = RTMSG_LEN;
        while off < body.len() {
            let rest = &body[off..];
            let (Some(len), Some(ty)) = (u16_at(rest, 0), u16_at(rest, 2)) else {
                return Err(malformed("truncated rtattr"));
            };
            let len = usize::from(len);
            if len < RTA_HDRLEN || len > rest.len() {
                return Err(malformed("rta_len out of bounds"));
            }
            let p = &rest[RTA_HDRLEN..len];
            let short = || malformed("short route attribute");
            match ty & NLA_TYPE_MASK {
                RTA_OIF => r.oif = Some(u32_at(p, 0).ok_or_else(short)?),
                RTA_GATEWAY => r.gateway = Some(ipv4_at(p, 0).ok_or_else(short)?),
                RTA_PRIORITY => r.priority = u32_at(p, 0).ok_or_else(short)?,
                RTA_TABLE => r.table = u32_at(p, 0).ok_or_else(short)?,
                _ => {}
            }
            off += align4(len).min(rest.len());
        }
        Ok(Some(r))
    }

    /// Все `RTM_NEWROUTE` (`AF_INET`) одной датаграммы; `NLMSG_DONE` завершает разбор, `NLMSG_ERROR` с ненулевым кодом
    /// это `Err(Kernel(errno))`, нулевой (ACK) пропускается; длины проверяются до каждого чтения.
    pub(crate) fn parse_netlink_routes(buf: &[u8]) -> Result<Vec<NlRoute>, NlError> {
        let mut out = Vec::new();
        for (ty, body) in split_messages(buf)? {
            match ty {
                NLMSG_DONE => break,
                NLMSG_ERROR => {
                    let code = i32_at(body, 0).ok_or_else(|| malformed("short nlmsgerr"))?;
                    if code != 0 {
                        return Err(NlError::Kernel(code.saturating_neg()));
                    }
                }
                RTM_NEWROUTE => out.extend(parse_route(body)?),
                _ => {}
            }
        }
        Ok(out)
    }

    /// Датаграмма завершает ответ (`NLMSG_DONE` или `NLMSG_ERROR`, или она искажена).
    pub(crate) fn netlink_done(buf: &[u8]) -> bool {
        split_messages(buf).map_or(true, |m| {
            m.iter()
                .any(|(ty, _)| *ty == NLMSG_DONE || *ty == NLMSG_ERROR)
        })
    }

    /// Маршруты по умолчанию из dump: `RTN_UNICAST`, `dst_len` 0, таблица main, с `RTA_OIF`; по `priority`.
    pub(crate) fn netlink_defaults(routes: Vec<NlRoute>) -> Vec<NlRoute> {
        let mut d: Vec<NlRoute> = routes
            .into_iter()
            .filter(|r| {
                r.kind == RTN_UNICAST
                    && r.dst_len == 0
                    && r.table == RT_TABLE_MAIN
                    && r.oif.is_some()
            })
            .collect();
        d.sort_by_key(|r| r.priority);
        d
    }

    /// Ответ lookup → [`Route`]: `RTN_LOCAL` это адрес хоста; `RTN_UNREACHABLE`/`BLACKHOLE`/`PROHIBIT` или без
    /// `RTA_OIF` это «нет маршрута».
    pub(crate) fn route_from_nl(r: &NlRoute, ifname: impl FnOnce(u32) -> String) -> Option<Route> {
        if matches!(r.kind, RTN_UNREACHABLE | RTN_BLACKHOLE | RTN_PROHIBIT) {
            return None;
        }
        let oif = r.oif?;
        let local = r.kind == RTN_LOCAL;
        Some(Route {
            ifindex: oif,
            ifname: ifname(oif),
            gateway: if local { None } else { r.gateway },
            local,
        })
    }
}

/// Darwin route socket: `rt_msghdr` + массив `sockaddr`, каждый выровнен `ROUNDUP(sa_len)` до 4 байт
/// (C `rawsock-getroute.c:21–22`, XNU `ROUNDUP32`).
#[cfg(any(target_os = "macos", test))]
mod rtsock {
    use std::net::Ipv4Addr;

    use super::AF_INET;
    use super::bytes::{i32_at, ipv4_at, u16_at};
    use crate::discover::Route;

    /// `sizeof(struct rt_msghdr)` Darwin: 9 полей по 2/4 байта и `rt_metrics` (14 × u32).
    pub(crate) const RT_MSGHDR_LEN: usize = 92;
    pub(crate) const RTM_VERSION: u8 = 5;
    pub(crate) const RTM_GET: u8 = 4;
    pub(crate) const RTA_DST_BIT: i32 = 0x1;
    pub(crate) const RTA_IFP_BIT: i32 = 0x10;
    pub(crate) const RTF_UP: i32 = 0x1;
    pub(crate) const RTF_GATEWAY: i32 = 0x2;
    pub(crate) const RTF_REJECT: i32 = 0x8;
    /// Маршрут хоста с записью канального уровня (ARP); XNU ставит ему `RTF_REJECT` на `arpt_down` после неудачного ARP.
    pub(crate) const RTF_LLINFO: i32 = 0x400;
    pub(crate) const RTF_BLACKHOLE: i32 = 0x1000;
    pub(crate) const RTF_LOCAL: i32 = 0x20_0000;
    pub(crate) const AF_LINK: u8 = 18;
    /// Смещения полей `rt_msghdr`.
    pub(crate) const OFF_MSGLEN: usize = 0;
    pub(crate) const OFF_VERSION: usize = 2;
    pub(crate) const OFF_TYPE: usize = 3;
    pub(crate) const OFF_INDEX: usize = 4;
    pub(crate) const OFF_FLAGS: usize = 8;
    pub(crate) const OFF_ADDRS: usize = 12;
    pub(crate) const OFF_PID: usize = 16;
    pub(crate) const OFF_SEQ: usize = 20;
    pub(crate) const OFF_ERRNO: usize = 24;
    /// Общий заголовок сообщений route socket: `msglen` (u16), `version`, `type`.
    const COMMON_HDR_LEN: usize = 4;
    const RTAX_GATEWAY: usize = 1;
    const RTAX_IFP: usize = 4;
    const RTAX_MAX: usize = 8;
    /// `offsetof(struct sockaddr_dl, sdl_data)`.
    const SDL_DATA: usize = 8;

    /// Ответ `RTM_GET` своего запроса.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct RtReply {
        pub flags: i32,
        /// Имя из `RTAX_IFP` (`sockaddr_dl`).
        pub ifp: Option<String>,
        /// `sdl_index` из `RTAX_IFP`, иначе `rtm_index`.
        pub ifindex: u32,
        /// `RTAX_GATEWAY` как `sockaddr_in`.
        pub gateway_in: Option<Ipv4Addr>,
        /// `RTAX_GATEWAY` как `sockaddr_dl`: on-link.
        pub gateway_is_link: bool,
    }

    /// `ROUNDUP(sa_len)` Darwin: до кратного 4, нулевая длина занимает 4 байта.
    pub(crate) fn sa_roundup(len: usize) -> usize {
        if len == 0 { 4 } else { (len + 3) & !3 }
    }

    /// `RTM_GET` для `dst` с `RTA_DST | RTA_IFP` (как C `rawsock-getroute.c:158–175`): 92 + 16 байт.
    pub(crate) fn rt_get_request(seq: i32, pid: i32, dst: Ipv4Addr) -> Vec<u8> {
        const SIN_LEN: usize = 16;
        let mut b = vec![0u8; RT_MSGHDR_LEN + SIN_LEN];
        let len = b.len() as u16;
        b[OFF_MSGLEN..OFF_MSGLEN + 2].copy_from_slice(&len.to_ne_bytes());
        b[OFF_VERSION] = RTM_VERSION;
        b[OFF_TYPE] = RTM_GET;
        b[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&RTF_UP.to_ne_bytes());
        b[OFF_ADDRS..OFF_ADDRS + 4].copy_from_slice(&(RTA_DST_BIT | RTA_IFP_BIT).to_ne_bytes());
        b[OFF_PID..OFF_PID + 4].copy_from_slice(&pid.to_ne_bytes());
        b[OFF_SEQ..OFF_SEQ + 4].copy_from_slice(&seq.to_ne_bytes());
        let sin = &mut b[RT_MSGHDR_LEN..];
        sin[0] = SIN_LEN as u8;
        sin[1] = AF_INET;
        sin[4..8].copy_from_slice(&dst.octets());
        b
    }

    /// Одно сообщение route socket. Чужие тип (в том числе короче `rt_msghdr`), `rtm_seq` или `rtm_pid` → `Ok(None)`
    /// (сокет видит сообщения всей системы); своё с `rtm_errno`, `RTM_GET` короче `rt_msghdr` или искажённое → `Err`.
    pub(crate) fn parse_rt_reply(
        buf: &[u8],
        seq: i32,
        pid: i32,
    ) -> Result<Option<RtReply>, String> {
        let field = |at: usize| i32_at(buf, at).ok_or("short rt_msghdr");
        // Общий заголовок всех сообщений route socket (`msglen`, `version`, `type`): по нему чужие типы короче
        // `rt_msghdr` (`ifa_msghdr` 20 байт, `ifma_msghdr` 16 байт) пропускаются, а не считаются искажёнными.
        if buf.len() < COMMON_HDR_LEN {
            return Err(format!("short route message ({} bytes)", buf.len()));
        }
        let msglen = usize::from(u16_at(buf, OFF_MSGLEN).ok_or("short route message")?);
        if msglen < COMMON_HDR_LEN || msglen > buf.len() {
            return Err(format!(
                "rtm_msglen {msglen} out of bounds ({} read)",
                buf.len()
            ));
        }
        if buf[OFF_VERSION] != RTM_VERSION {
            return Err(format!(
                "rtm_version {} (expected {RTM_VERSION})",
                buf[OFF_VERSION]
            ));
        }
        if buf[OFF_TYPE] != RTM_GET {
            return Ok(None);
        }
        if msglen < RT_MSGHDR_LEN {
            return Err(format!("short rt_msghdr ({msglen} bytes)"));
        }
        if field(OFF_SEQ)? != seq || field(OFF_PID)? != pid {
            return Ok(None);
        }
        let errno = field(OFF_ERRNO)?;
        if errno != 0 {
            return Err(format!(
                "RTM_GET: {}",
                std::io::Error::from_raw_os_error(errno)
            ));
        }
        let addrs = field(OFF_ADDRS)?;
        let msg = &buf[..msglen];
        let mut reply = RtReply {
            flags: field(OFF_FLAGS)?,
            ifp: None,
            ifindex: u32::from(u16_at(buf, OFF_INDEX).ok_or("short rt_msghdr")?),
            gateway_in: None,
            gateway_is_link: false,
        };
        let mut off = RT_MSGHDR_LEN;
        for i in 0..RTAX_MAX {
            if addrs & (1 << i) == 0 {
                continue;
            }
            let Some(&sa_len) = msg.get(off) else {
                return Err(format!("sockaddr {i} starts past rtm_msglen"));
            };
            let sa = msg
                .get(off..off + usize::from(sa_len))
                .ok_or_else(|| format!("sockaddr {i} overruns rtm_msglen"))?;
            let family = sa.get(1).copied();
            match (i, family) {
                (RTAX_GATEWAY, Some(AF_INET)) => reply.gateway_in = ipv4_at(sa, 4),
                (RTAX_GATEWAY, Some(AF_LINK)) => reply.gateway_is_link = true,
                (RTAX_IFP, Some(AF_LINK)) if sa.len() >= SDL_DATA => {
                    let index = u16_at(sa, 2).unwrap_or(0);
                    if index != 0 {
                        reply.ifindex = u32::from(index);
                    }
                    let nlen = usize::from(sa[5]);
                    let name = sa
                        .get(SDL_DATA..SDL_DATA + nlen)
                        .ok_or_else(|| "sockaddr_dl name overruns sdl_len".to_string())?;
                    reply.ifp = Some(String::from_utf8_lossy(name).into_owned());
                }
                _ => {}
            }
            off += sa_roundup(usize::from(sa_len));
        }
        Ok(Some(reply))
    }

    /// Ответ → [`Route`]: `RTF_LOCAL` или `lo0` это адрес хоста; шлюз только `sockaddr_in` при `RTF_GATEWAY`
    /// (`sockaddr_dl` это on-link); `RTF_REJECT`/`RTF_BLACKHOLE` без `RTF_LLINFO` это «нет маршрута».
    pub(crate) fn route_from_rt(r: &RtReply) -> Option<Route> {
        // llinfo-маршрут хоста с RTF_REJECT это сосед, чей ARP только что не удался (XNU `arpt_down`): он остаётся
        // on-link, иначе следующий скан той же цели получил бы «нет маршрута».
        if r.flags & (RTF_REJECT | RTF_BLACKHOLE) != 0 && r.flags & RTF_LLINFO == 0 {
            return None;
        }
        let ifname = r.ifp.clone().unwrap_or_default();
        let local = r.flags & RTF_LOCAL != 0 || ifname == "lo0";
        let via_gateway = r.flags & RTF_GATEWAY != 0 && !r.gateway_is_link;
        Some(Route {
            ifindex: r.ifindex,
            ifname,
            gateway: if local || !via_gateway {
                None
            } else {
                r.gateway_in
            },
            local,
        })
    }
}

/// Windows IP Helper: строки `MIB_IPFORWARD_ROW2` и адаптеры `IP_ADAPTER_ADDRESSES_LH`, уже скопированные `windows::sys`.
#[cfg(any(windows, test))]
mod iphlp {
    use std::net::Ipv4Addr;

    use crate::discover::{Iface, Route};

    pub(crate) const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
    pub(crate) const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    pub(crate) const IF_TYPE_IEEE80211: u32 = 71;

    /// Строка таблицы маршрутов IPv4.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Fwd {
        pub ifindex: u32,
        pub prefix_len: u8,
        /// `0.0.0.0` это on-link.
        pub next_hop: Ipv4Addr,
        pub metric: u32,
        /// Флаг `Loopback` строки или IfType 24 её интерфейса ([`mark_loopback`]).
        pub loopback: bool,
    }

    /// Адаптер `GetAdaptersAddresses(AF_INET)`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct WinAdapter {
        pub if_index: u32,
        pub if_type: u32,
        /// `OperStatus == IfOperStatusUp`.
        pub oper_up: bool,
        /// `AdapterName` (`{GUID}`).
        pub adapter_name: String,
        pub friendly_name: Option<String>,
        /// `PhysicalAddress` при длине 6.
        pub mac: Option<[u8; 6]>,
        /// `FirstUnicastAddress` по порядку.
        pub ipv4: Vec<Ipv4Addr>,
    }

    /// Ethernet-кадры: IfType 6 и 71 (Wi-Fi; Npcap отдаёт DLT_EN10MB, как C `rawsock-getif.c`).
    pub(crate) fn if_type_is_ethernet(if_type: u32) -> bool {
        if_type == IF_TYPE_ETHERNET_CSMACD || if_type == IF_TYPE_IEEE80211
    }

    /// Адаптер → [`Iface`]: имя и описание это FriendlyName, `device_id` это `\Device\NPF_` + AdapterName.
    pub(crate) fn iface_from_adapter(a: &WinAdapter) -> Iface {
        Iface {
            name: a
                .friendly_name
                .clone()
                .unwrap_or_else(|| a.adapter_name.clone()),
            index: a.if_index,
            device_id: format!("\\Device\\NPF_{}", a.adapter_name),
            description: a.friendly_name.clone(),
            mac: a.mac,
            mac_masked: false,
            ethernet: if_type_is_ethernet(a.if_type),
            up: a.oper_up,
            ipv4: a.ipv4.clone(),
        }
    }

    fn name_of(ifindex: u32, ifaces: &[Iface]) -> String {
        ifaces
            .iter()
            .find(|i| i.index == ifindex)
            .map_or_else(|| format!("ifindex {ifindex}"), |i| i.name.clone())
    }

    /// Строки через интерфейс IfType 24 (software loopback) получают `loopback`.
    pub(crate) fn mark_loopback(rows: &mut [Fwd], adapters: &[WinAdapter]) {
        for row in rows {
            if adapters
                .iter()
                .any(|a| a.if_index == row.ifindex && a.if_type == IF_TYPE_SOFTWARE_LOOPBACK)
            {
                row.loopback = true;
            }
        }
    }

    /// `GetBestRoute2` → [`Route`] (правило `Route::local`: флаг loopback строки или `dst` равен unicast-адресу адаптера).
    pub(crate) fn route_from_best(row: &Fwd, dst: Ipv4Addr, ifaces: &[Iface]) -> Route {
        let local = row.loopback || ifaces.iter().any(|i| i.ipv4.contains(&dst));
        Route {
            ifindex: row.ifindex,
            ifname: name_of(row.ifindex, ifaces),
            gateway: (!local && !row.next_hop.is_unspecified()).then_some(row.next_hop),
            local,
        }
    }

    /// Маршруты по умолчанию: префикс 0, не loopback, по `metric` (порядок равных сохраняется).
    pub(crate) fn defaults_from_table(rows: &[Fwd], ifaces: &[Iface]) -> Vec<Route> {
        let mut d: Vec<&Fwd> = rows
            .iter()
            .filter(|r| r.prefix_len == 0 && !r.loopback)
            .collect();
        d.sort_by_key(|r| r.metric);
        d.into_iter()
            .map(|r| Route {
                ifindex: r.ifindex,
                ifname: name_of(r.ifindex, ifaces),
                gateway: (!r.next_hop.is_unspecified()).then_some(r.next_hop),
                local: false,
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "route_parse_tests.rs"]
mod route_parse_tests;
