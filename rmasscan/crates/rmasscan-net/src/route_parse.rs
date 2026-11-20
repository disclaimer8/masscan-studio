//! Разбор ответов ядра о маршрутах и интерфейсах (AGPL-3.0): Linux rtnetlink, Darwin route socket, Windows IP Helper.
//!
//! Модуль безопасный и переносимый: ни системных вызовов, ни `unsafe`, ни типов `libc`/`windows-sys`. FFI-модули
//! (`linux::route`, `macos::route`, `windows::sys`) только отправляют собранные здесь байты запросов и отдают сюда
//! байты ответов или поля, уже скопированные в безопасные типы; тесты идут на любой ОС. Поля заголовков в родном
//! порядке байт (как их пишет ядро), адреса IPv4 и IPv6 в сетевом. Разбор IPv6 (`*6`) живёт рядом с IPv4 в тех же
//! подмодулях и не меняет ни одной функции IPv4.

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
        u32_at(b, at).map(u32::cast_signed)
    }

    /// Адрес IPv4 в сетевом порядке байт.
    pub(super) fn ipv4_at(b: &[u8], at: usize) -> Option<Ipv4Addr> {
        let o: [u8; 4] = b.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(Ipv4Addr::from(o))
    }

    /// Адрес IPv6 в сетевом порядке байт.
    pub(super) fn ipv6_at(b: &[u8], at: usize) -> Option<std::net::Ipv6Addr> {
        let o: [u8; 16] = b.get(at..at.checked_add(16)?)?.try_into().ok()?;
        Some(std::net::Ipv6Addr::from(o))
    }
}

/// Linux rtnetlink: `nlmsghdr` + `rtmsg` + `rtattr` (linux/netlink.h, linux/rtnetlink.h).
#[cfg(any(target_os = "linux", test))]
mod netlink {
    use std::collections::BTreeMap;
    use std::ffi::CStr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::AF_INET;
    use super::bytes::{i32_at, ipv4_at, ipv6_at, u16_at, u32_at};
    use crate::NetError;
    use crate::adapter_common::errno_msg;
    use crate::discover::{Iface, Route, RouteV6};
    use crate::network_plan::{InterfaceObservation, Ipv4Prefix};

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
    pub(crate) const RT_TABLE_MAIN: u32 = 254;
    pub(crate) const RTA_HDRLEN: usize = 4;
    /// Биты `NLA_F_NESTED`/`NLA_F_NET_BYTEORDER` в `rta_type`.
    const NLA_TYPE_MASK: u16 = !(0x8000 | 0x4000);

    /// `rtm_type` (`RTN_*`): вид маршрута.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct RouteKind(pub u8);

    pub(crate) const RTN_UNICAST: RouteKind = RouteKind(1);
    pub(crate) const RTN_LOCAL: RouteKind = RouteKind(2);
    pub(crate) const RTN_BLACKHOLE: RouteKind = RouteKind(6);
    pub(crate) const RTN_UNREACHABLE: RouteKind = RouteKind(7);
    pub(crate) const RTN_PROHIBIT: RouteKind = RouteKind(8);

    /// Флаги адреса (`IFA_F_*`): `IFA_FLAGS` или 8-битный `ifa_flags`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct IfaFlags(pub u32);

    impl IfaFlags {
        /// Все биты `other` выставлены.
        pub(crate) const fn contains(self, other: IfaFlags) -> bool {
            self.0 & other.0 == other.0
        }
    }

    pub(crate) const IFA_F_DADFAILED: IfaFlags = IfaFlags(0x08);
    pub(crate) const IFA_F_DEPRECATED: IfaFlags = IfaFlags(0x20);
    pub(crate) const IFA_F_TENTATIVE: IfaFlags = IfaFlags(0x40);

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

    /// Семейство маршрутов: что отличает IPv4 от IPv6 в разборе (`rtm_family`, адрес в атрибутах, `RTA_PREFSRC`,
    /// порядок проверки атрибутов).
    pub(crate) trait RouteFamily {
        /// `rtm_family`.
        const AF: u8;
        type Addr: Copy;
        /// Адрес из значения атрибута (сетевой порядок байт); `None`, если значение короче адреса.
        fn addr_at(p: &[u8]) -> Option<Self::Addr>;
        /// Читается ли `RTA_PREFSRC`; только это и значит константа.
        const PREFSRC: bool;
        /// Порядок ошибок как на базе. `true` (IPv6): сначала проверяются границы всех атрибутов и лишь потом их
        /// значения. `false` (IPv4): значения проверяются по ходу, и короткое значение раньше испорченного `rta_len`
        /// побеждает.
        const ATTRS_CHECKED_FIRST: bool;
    }

    /// Маркер `AF_INET`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct V4;
    /// Маркер `AF_INET6`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct V6;

    impl RouteFamily for V4 {
        const AF: u8 = AF_INET;
        type Addr = Ipv4Addr;
        fn addr_at(p: &[u8]) -> Option<Ipv4Addr> {
            ipv4_at(p, 0)
        }
        const PREFSRC: bool = false;
        const ATTRS_CHECKED_FIRST: bool = false;
    }

    impl RouteFamily for V6 {
        const AF: u8 = AF_INET6_LINUX;
        type Addr = Ipv6Addr;
        fn addr_at(p: &[u8]) -> Option<Ipv6Addr> {
            ipv6_at(p, 0)
        }
        const PREFSRC: bool = true;
        const ATTRS_CHECKED_FIRST: bool = true;
    }

    /// Маршрут из `RTM_NEWROUTE` одного семейства.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct NlRouteOf<F: RouteFamily> {
        pub kind: RouteKind,
        pub dst_len: u8,
        /// `RTA_TABLE`, иначе `rtm_table`.
        pub table: u32,
        pub oif: Option<u32>,
        pub gateway: Option<F::Addr>,
        /// `RTA_PREFSRC`: в ответе на lookup это источник, который выбрало ядро (`rt6_fill_node`,
        /// `ip6_route_get_saddr`). Только у IPv6, у IPv4 всегда `None`.
        pub prefsrc: Option<F::Addr>,
        /// `RTA_PRIORITY` (метрика), 0 без атрибута.
        pub priority: u32,
    }

    /// Маршрут `AF_INET`.
    pub(crate) type NlRoute = NlRouteOf<V4>;
    /// Маршрут `AF_INET6`.
    pub(crate) type NlRoute6 = NlRouteOf<V6>;

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

    /// Сообщение netlink: заголовок `nlmsghdr` (16 байт, `nlmsg_pid` 0: заполняет ядро) и полезная нагрузка.
    pub(crate) fn nl_message(ty: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let len = NLMSG_HDRLEN + payload.len();
        let mut b = Vec::with_capacity(len);
        // Младшие 32 бита, бит в бит как прежний `as u32`; запросы здесь короче сотни байт, маска ничего не отрезает.
        b.extend(
            u32::try_from(len & 0xFFFF_FFFF)
                .unwrap_or(u32::MAX)
                .to_ne_bytes(),
        );
        b.extend(ty.to_ne_bytes());
        b.extend(flags.to_ne_bytes());
        b.extend(seq.to_ne_bytes());
        b.extend(0u32.to_ne_bytes());
        b.extend(payload);
        b
    }

    /// Запрос `RTM_GETROUTE`: с `dst` (сетевой порядок байт) это lookup одного адреса (`NLM_F_REQUEST`, `dst_len` =
    /// 8 × длина адреса, `RTA_DST`), без него dump всех маршрутов семейства (`NLM_F_REQUEST | NLM_F_DUMP`).
    pub(crate) fn route_request(family: u8, seq: u32, dst: Option<&[u8]>) -> Vec<u8> {
        debug_assert!(dst.is_none_or(|d| matches!(d.len(), 4 | 16)));
        let rt = RtMsg {
            family,
            // Младшие 8 и 16 бит, бит в бит как прежние `as u8`/`as u16`: адрес 4 или 16 байт (`debug_assert` выше), маски
            // ничего не отрезают.
            dst_len: dst.map_or(0, |d| u8::try_from((d.len() * 8) & 0xFF).unwrap_or(u8::MAX)),
            ..RtMsg::default()
        };
        let mut payload = Vec::with_capacity(RTMSG_LEN + dst.map_or(0, |d| RTA_HDRLEN + d.len()));
        payload.extend(rt.to_bytes());
        if let Some(d) = dst {
            payload.extend(
                u16::try_from((RTA_HDRLEN + d.len()) & 0xFFFF)
                    .unwrap_or(u16::MAX)
                    .to_ne_bytes(),
            );
            payload.extend(RTA_DST.to_ne_bytes());
            payload.extend(d);
        }
        let flags = match dst {
            Some(_) => NLM_F_REQUEST,
            None => NLM_F_REQUEST | NLM_F_DUMP,
        };
        nl_message(RTM_GETROUTE, flags, seq, &payload)
    }

    /// Запрос `RTM_GETROUTE` `AF_INET`: lookup `dst` или dump всех маршрутов IPv4.
    pub(crate) fn netlink_route_request(seq: u32, dst: Option<Ipv4Addr>) -> Vec<u8> {
        let o = dst.map(|d| d.octets());
        route_request(AF_INET, seq, o.as_ref().map(|a| a.as_slice()))
    }

    /// Запрос `RTM_GETROUTE` `AF_INET6`: lookup `dst` или dump всех маршрутов IPv6.
    pub(crate) fn netlink_route_request6(seq: u32, dst: Option<Ipv6Addr>) -> Vec<u8> {
        let o = dst.map(|d| d.octets());
        route_request(AF_INET6_LINUX, seq, o.as_ref().map(|a| a.as_slice()))
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
            let len = usize::try_from(len).unwrap_or(usize::MAX);
            if len < NLMSG_HDRLEN || len > rest.len() {
                return Err(malformed("nlmsg_len out of bounds"));
            }
            out.push((ty, &rest[NLMSG_HDRLEN..len]));
            off += align4(len).min(rest.len());
        }
        Ok(out)
    }

    /// Тела сообщений типа `want` одной датаграммы, по порядку: `NLMSG_DONE` завершает разбор, `NLMSG_ERROR` с
    /// ненулевым кодом это `Err(Kernel(errno))`, нулевой (ACK) пропускается, прочие типы пропускаются. Длины всех
    /// заголовков проверяются до первого тела, а тело разбирается до перехода к следующему сообщению: от этого порядка
    /// зависит, какая из двух ошибок побеждает (искажённое тело перед `NLMSG_ERROR` даёт `Malformed`, после него
    /// `Kernel`).
    fn for_each_payload(
        buf: &[u8],
        want: u16,
        mut f: impl FnMut(&[u8]) -> Result<(), NlError>,
    ) -> Result<(), NlError> {
        for (ty, body) in split_messages(buf)? {
            match ty {
                NLMSG_DONE => break,
                NLMSG_ERROR => {
                    let code = i32_at(body, 0).ok_or_else(|| malformed("short nlmsgerr"))?;
                    if code != 0 {
                        return Err(NlError::Kernel(code.saturating_neg()));
                    }
                }
                t if t == want => f(body)?,
                _ => {}
            }
        }
        Ok(())
    }

    /// Атрибуты `rtattr` тела после заголовка длиной `hdr`: `(тип без флагов NLA, полезная нагрузка)`; длины
    /// проверяются до каждого чтения. После первой ошибки итератор пуст.
    pub(crate) struct NlAttrs<'a> {
        body: &'a [u8],
        off: usize,
    }

    impl<'a> NlAttrs<'a> {
        pub(crate) fn new(body: &'a [u8], hdr: usize) -> Self {
            NlAttrs { body, off: hdr }
        }
    }

    impl<'a> Iterator for NlAttrs<'a> {
        type Item = Result<(u16, &'a [u8]), NlError>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.off >= self.body.len() {
                return None;
            }
            let rest = &self.body[self.off..];
            let (Some(len), Some(ty)) = (u16_at(rest, 0), u16_at(rest, 2)) else {
                self.off = self.body.len();
                return Some(Err(malformed("truncated rtattr")));
            };
            let len = usize::from(len);
            if len < RTA_HDRLEN || len > rest.len() {
                self.off = self.body.len();
                return Some(Err(malformed("rta_len out of bounds")));
            }
            self.off += align4(len).min(rest.len());
            Some(Ok((ty & NLA_TYPE_MASK, &rest[RTA_HDRLEN..len])))
        }
    }

    /// Тело `RTM_NEWROUTE`: `rtmsg` и атрибуты; `None` для другого семейства.
    fn parse_route<F: RouteFamily>(body: &[u8]) -> Result<Option<NlRouteOf<F>>, NlError> {
        let rt = RtMsg::from_bytes(body).ok_or_else(|| malformed("short rtmsg"))?;
        if rt.family != F::AF {
            return Ok(None);
        }
        let mut r = NlRouteOf::<F> {
            kind: RouteKind(rt.kind),
            dst_len: rt.dst_len,
            table: u32::from(rt.table),
            oif: None,
            gateway: None,
            prefsrc: None,
            priority: 0,
        };
        let short = || malformed("short route attribute");
        let mut apply = |ty: u16, p: &[u8]| -> Result<(), NlError> {
            match ty {
                RTA_OIF => r.oif = Some(u32_at(p, 0).ok_or_else(short)?),
                RTA_GATEWAY => r.gateway = Some(F::addr_at(p).ok_or_else(short)?),
                RTA_PREFSRC if F::PREFSRC => r.prefsrc = Some(F::addr_at(p).ok_or_else(short)?),
                RTA_PRIORITY => r.priority = u32_at(p, 0).ok_or_else(short)?,
                RTA_TABLE => r.table = u32_at(p, 0).ok_or_else(short)?,
                _ => {}
            }
            Ok(())
        };
        let attrs = NlAttrs::new(body, RTMSG_LEN);
        if F::ATTRS_CHECKED_FIRST {
            for (ty, p) in attrs.collect::<Result<Vec<_>, _>>()? {
                apply(ty, p)?;
            }
        } else {
            for a in attrs {
                let (ty, p) = a?;
                apply(ty, p)?;
            }
        }
        Ok(Some(r))
    }

    /// Все `RTM_NEWROUTE` семейства `F` одной датаграммы (правила [`for_each_payload`]).
    fn parse_routes<F: RouteFamily>(buf: &[u8]) -> Result<Vec<NlRouteOf<F>>, NlError> {
        let mut out = Vec::new();
        for_each_payload(buf, RTM_NEWROUTE, |body| {
            out.extend(parse_route::<F>(body)?);
            Ok(())
        })?;
        Ok(out)
    }

    /// Все `RTM_NEWROUTE` (`AF_INET`) одной датаграммы; `NLMSG_DONE` завершает разбор, `NLMSG_ERROR` с ненулевым кодом
    /// это `Err(Kernel(errno))`, нулевой (ACK) пропускается; длины проверяются до каждого чтения.
    pub(crate) fn parse_netlink_routes(buf: &[u8]) -> Result<Vec<NlRoute>, NlError> {
        parse_routes::<V4>(buf)
    }

    /// Все `RTM_NEWROUTE` `AF_INET6` датаграммы (правила [`parse_netlink_routes`]).
    pub(crate) fn parse_netlink_routes6(buf: &[u8]) -> Result<Vec<NlRoute6>, NlError> {
        parse_routes::<V6>(buf)
    }

    /// Датаграмма завершает ответ (`NLMSG_DONE` или `NLMSG_ERROR`, или она искажена).
    pub(crate) fn netlink_done(buf: &[u8]) -> bool {
        split_messages(buf).map_or(true, |m| {
            m.iter()
                .any(|(ty, _)| *ty == NLMSG_DONE || *ty == NLMSG_ERROR)
        })
    }

    /// Маршруты по умолчанию из dump: `RTN_UNICAST`, `dst_len` 0, таблица main, с `RTA_OIF` (маршрут IPv6 с
    /// `RTA_MULTIPATH` без `RTA_OIF` не берётся); по `priority`.
    pub(crate) fn netlink_defaults<F: RouteFamily>(routes: Vec<NlRouteOf<F>>) -> Vec<NlRouteOf<F>> {
        let mut d: Vec<NlRouteOf<F>> = routes
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

    /// Общая часть ответа lookup: `(ifindex, ifname, gateway, local)`. `RTN_LOCAL` это адрес хоста (шлюза нет);
    /// `RTN_UNREACHABLE`/`BLACKHOLE`/`PROHIBIT` или без `RTA_OIF` это «нет маршрута».
    #[allow(clippy::type_complexity)]
    fn route_target<F: RouteFamily>(
        r: &NlRouteOf<F>,
        ifname: impl FnOnce(u32) -> String,
    ) -> Option<(u32, String, Option<F::Addr>, bool)> {
        if matches!(r.kind, RTN_UNREACHABLE | RTN_BLACKHOLE | RTN_PROHIBIT) {
            return None;
        }
        let oif = r.oif?;
        let local = r.kind == RTN_LOCAL;
        Some((
            oif,
            ifname(oif),
            if local { None } else { r.gateway },
            local,
        ))
    }

    /// Ответ lookup → [`Route`] (правила [`route_target`]).
    pub(crate) fn route_from_nl(r: &NlRoute, ifname: impl FnOnce(u32) -> String) -> Option<Route> {
        route_target(r, ifname).map(|(ifindex, ifname, gateway, local)| Route {
            ifindex,
            ifname,
            gateway,
            local,
        })
    }

    // ------------------------------------------------------------------------------------------------ IPv6

    /// `AF_INET6` Linux.
    pub(crate) const AF_INET6_LINUX: u8 = 10;
    pub(crate) const RTA_PREFSRC: u16 = 7;
    pub(crate) const RTM_NEWADDR: u16 = 20;
    pub(crate) const RTM_GETADDR: u16 = 22;
    pub(crate) const IFA_ADDRESS: u16 = 1;
    pub(crate) const IFA_LOCAL: u16 = 2;
    pub(crate) const IFA_FLAGS: u16 = 8;
    /// `sizeof(struct ifaddrmsg)`.
    pub(crate) const IFADDRMSG_LEN: usize = 8;

    /// Ответ lookup IPv6 → [`RouteV6`] (правила [`route_target`]); `RTA_PREFSRC` становится `source`.
    pub(crate) fn route6_from_nl(
        r: &NlRoute6,
        ifname: impl FnOnce(u32) -> String,
    ) -> Option<RouteV6> {
        route_target(r, ifname).map(|(ifindex, ifname, gateway, local)| RouteV6 {
            ifindex,
            ifname,
            gateway,
            source: r.prefsrc,
            local,
        })
    }

    /// Адрес IPv6 интерфейса из `RTM_NEWADDR`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct NlAddr6 {
        pub index: u32,
        pub addr: Ipv6Addr,
        /// `IFA_FLAGS`, иначе 8-битный `ifa_flags`.
        pub flags: IfaFlags,
    }

    /// Dump `RTM_GETADDR` всех адресов `AF_INET6`.
    pub(crate) fn netlink_addr_request6(seq: u32) -> Vec<u8> {
        // `struct ifaddrmsg`: семейство и нули (`ifa_prefixlen`, `ifa_flags`, `ifa_scope`, `ifa_index`).
        let mut payload = [0u8; IFADDRMSG_LEN];
        payload[0] = AF_INET6_LINUX;
        nl_message(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, seq, &payload)
    }

    /// Все `RTM_NEWADDR` `AF_INET6` датаграммы: `IFA_LOCAL`, иначе `IFA_ADDRESS` (у IPv6 обычно только он).
    pub(crate) fn parse_netlink_addrs6(buf: &[u8]) -> Result<Vec<NlAddr6>, NlError> {
        let mut out = Vec::new();
        for_each_payload(buf, RTM_NEWADDR, |body| {
            let hdr = body
                .get(..IFADDRMSG_LEN)
                .ok_or_else(|| malformed("short ifaddrmsg"))?;
            if hdr[0] != AF_INET6_LINUX {
                return Ok(());
            }
            let index = u32_at(hdr, 4).ok_or_else(|| malformed("short ifaddrmsg"))?;
            let mut flags = IfaFlags(u32::from(hdr[2]));
            let (mut address, mut local) = (None, None);
            let short = || malformed("short address attribute");
            for (ty, p) in NlAttrs::new(body, IFADDRMSG_LEN).collect::<Result<Vec<_>, _>>()? {
                match ty {
                    IFA_ADDRESS => address = Some(ipv6_at(p, 0).ok_or_else(short)?),
                    IFA_LOCAL => local = Some(ipv6_at(p, 0).ok_or_else(short)?),
                    IFA_FLAGS => flags = IfaFlags(u32_at(p, 0).ok_or_else(short)?),
                    _ => {}
                }
            }
            if let Some(addr) = local.or(address) {
                out.push(NlAddr6 { index, addr, flags });
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Пригодные адреса интерфейса `index` в порядке ядра: без tentative (DAD ещё идёт) и dadfailed; deprecated после
    /// остальных.
    pub(crate) fn usable_addrs6(addrs: &[NlAddr6], index: u32) -> Vec<Ipv6Addr> {
        let mut v: Vec<&NlAddr6> = addrs
            .iter()
            .filter(|a| {
                a.index == index
                    && !a.flags.contains(IFA_F_TENTATIVE)
                    && !a.flags.contains(IFA_F_DADFAILED)
            })
            .collect();
        v.sort_by_key(|a| a.flags.contains(IFA_F_DEPRECATED));
        v.into_iter().map(|a| a.addr).collect()
    }

    // ------------------------------------------------------------------------------------- наблюдение (`observation_*`)
    //
    // Разбор неблокирующего наблюдения интерфейсов и маршрута (`linux::route::observation`; повторы, дедлайн, сокет и
    // предел ответа остаются там). Обходчики сообщений и атрибутов свои, не `split_messages`/`NlAttrs`: у них другие
    // тексты ошибок (`netlink observation: malformed …`). Общие с разбором маршрутов модуль, константы и чтения полей
    // (`bytes::*`).

    pub(crate) const RTM_NEWLINK: u16 = 16;
    pub(crate) const RTM_GETLINK: u16 = 18;
    /// `nlmsg_flags`: dump прерван изменением таблицы ядра.
    pub(crate) const NLM_F_DUMP_INTR: u16 = 0x10;
    /// `ifi_type` Ethernet.
    pub(crate) const ARPHRD_ETHER: u16 = 1;
    /// `ifi_flags`: интерфейс поднят.
    pub(crate) const IFF_UP: u32 = 1;
    /// `AF_UNSPEC` как байт семейства `ifinfomsg`.
    pub(crate) const AF_UNSPEC: u8 = 0;
    pub(crate) const IFLA_ADDRESS: u16 = 1;
    pub(crate) const IFLA_IFNAME: u16 = 3;
    /// Смещения полей `struct nlmsghdr`.
    pub(crate) const OFF_NLMSG_LEN: usize = 0;
    pub(crate) const OFF_NLMSG_TYPE: usize = 4;
    pub(crate) const OFF_NLMSG_FLAGS: usize = 6;
    pub(crate) const OFF_NLMSG_SEQ: usize = 8;
    /// `sizeof(struct ifinfomsg)` и смещения его полей.
    pub(crate) const IFINFOMSG_LEN: usize = 16;
    pub(crate) const OFF_IFI_FAMILY: usize = 0;
    pub(crate) const OFF_IFI_TYPE: usize = 2;
    pub(crate) const OFF_IFI_INDEX: usize = 4;
    pub(crate) const OFF_IFI_FLAGS: usize = 8;
    /// Смещения полей `struct ifaddrmsg` (длина [`IFADDRMSG_LEN`]).
    pub(crate) const OFF_IFA_FAMILY: usize = 0;
    pub(crate) const OFF_IFA_PREFIXLEN: usize = 1;
    pub(crate) const OFF_IFA_INDEX: usize = 4;

    /// `netlink observation: malformed {message}`.
    pub(crate) fn observation_malformed(message: &str) -> NetError {
        NetError::System(format!("netlink observation: malformed {message}"))
    }

    fn observation_u16(bytes: &[u8], at: usize) -> Result<u16, NetError> {
        u16_at(bytes, at).ok_or_else(|| observation_malformed("u16"))
    }

    fn observation_u32(bytes: &[u8], at: usize) -> Result<u32, NetError> {
        u32_at(bytes, at).ok_or_else(|| observation_malformed("u32"))
    }

    /// Ошибка ядра `e` (положительный errno) операции `op`: текст errno по таблице ОС.
    fn observation_sys(op: &str, e: i32) -> NetError {
        NetError::System(errno_msg(op, e))
    }

    /// Dump `RTM_GETLINK` (`ifinfomsg`, `AF_UNSPEC`) или `RTM_GETADDR` (`ifaddrmsg`, `AF_INET`) с флагами
    /// `NLM_F_REQUEST | NLM_F_DUMP`.
    pub(crate) fn observation_dump_request(kind: u16, seq: u32) -> Vec<u8> {
        // ifinfomsg is 16 bytes, ifaddrmsg 8 bytes; family is the first field of both.
        let (payload_len, family_at) = if kind == RTM_GETLINK {
            (IFINFOMSG_LEN, OFF_IFI_FAMILY)
        } else {
            (IFADDRMSG_LEN, OFF_IFA_FAMILY)
        };
        let mut payload = vec![0; payload_len];
        payload[family_at] = if kind == RTM_GETADDR {
            AF_INET
        } else {
            AF_UNSPEC
        };
        nl_message(kind, NLM_F_REQUEST | NLM_F_DUMP, seq, &payload)
    }

    /// Messages for this request only, validated before any are consumed. A fresh
    /// socket is also used for each query, but sequence matching remains mandatory.
    pub(crate) fn observation_messages(bytes: &[u8], seq: u32) -> Result<Vec<&[u8]>, NetError> {
        let mut out = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let rest = &bytes[offset..];
            if rest.len() < NLMSG_HDRLEN {
                return Err(observation_malformed("netlink header"));
            }
            let len = usize::try_from(observation_u32(rest, OFF_NLMSG_LEN)?).unwrap_or(usize::MAX);
            if len < NLMSG_HDRLEN || len > rest.len() {
                return Err(observation_malformed("netlink length"));
            }
            if observation_u32(rest, OFF_NLMSG_SEQ)? == seq {
                out.push(&rest[..len]);
            }
            // A final message need not carry padding beyond its declared length.
            offset += align4(len).min(rest.len());
        }
        Ok(out)
    }

    /// Завершает ли сообщение ответа (одно из [`observation_messages`]) запрос: `NLMSG_DONE` (ненулевой код в нём это
    /// ошибка `netlink dump`), `NLMSG_ERROR` с ненулевым кодом, у не-dump первое сообщение данных. Прерванный dump это
    /// ошибка.
    pub(crate) fn observation_message_ends(message: &[u8], dump: bool) -> Result<bool, NetError> {
        if observation_u16(message, OFF_NLMSG_FLAGS)? & NLM_F_DUMP_INTR != 0 {
            return Err(NetError::System(
                "netlink observation: interrupted dump".into(),
            ));
        }
        let kind = observation_u16(message, OFF_NLMSG_TYPE)?;
        let mut complete = false;
        if kind == NLMSG_DONE {
            if message.len() > NLMSG_HDRLEN {
                let error = observation_u32(message, NLMSG_HDRLEN)?.cast_signed();
                if error != 0 {
                    return Err(observation_sys("netlink dump", error.saturating_neg()));
                }
            }
            complete = true;
        }
        if kind == NLMSG_ERROR {
            // An ACK (zero) does not finish a dump or a route lookup.
            complete |= observation_u32(message, NLMSG_HDRLEN)? != 0;
        } else if kind >= RTM_NEWLINK && !dump {
            complete = true;
        }
        Ok(complete)
    }

    fn observation_attributes(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, NetError> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let len = usize::from(observation_u16(bytes, 0)?);
            if len < RTA_HDRLEN || len > bytes.len() {
                return Err(observation_malformed("attribute length"));
            }
            out.push((
                observation_u16(bytes, 2)? & NLA_TYPE_MASK,
                &bytes[RTA_HDRLEN..len],
            ));
            bytes = &bytes[align4(len).min(bytes.len())..];
        }
        Ok(out)
    }

    fn check_kernel_error(message: &[u8]) -> Result<(), NetError> {
        if observation_u16(message, OFF_NLMSG_TYPE)? == NLMSG_ERROR {
            let error = observation_u32(message, NLMSG_HDRLEN)?.cast_signed();
            if error != 0 {
                return Err(observation_sys(
                    "netlink interface dump",
                    error.saturating_neg(),
                ));
            }
        }
        Ok(())
    }

    /// Интерфейсы из ответов dump `RTM_GETLINK` (`links`, запрос `link_seq`) и `RTM_GETADDR` (`addrs`, `addr_seq`): по
    /// индексу, с префиксами IPv4 всех адресов (`IFA_LOCAL`, иначе `IFA_ADDRESS`).
    pub(crate) fn observations(
        links: &[u8],
        link_seq: u32,
        addrs: &[u8],
        addr_seq: u32,
    ) -> Result<Vec<InterfaceObservation>, NetError> {
        let mut interfaces = BTreeMap::new();
        for message in observation_messages(links, link_seq)? {
            check_kernel_error(message)?;
            if observation_u16(message, OFF_NLMSG_TYPE)? != RTM_NEWLINK {
                continue;
            }
            let body = &message[NLMSG_HDRLEN..];
            if body.len() < IFINFOMSG_LEN {
                return Err(observation_malformed("ifinfomsg"));
            }
            let index = observation_u32(body, OFF_IFI_INDEX)?;
            if index == 0 || index > i32::MAX.cast_unsigned() {
                return Err(observation_malformed("interface index"));
            }
            let ethernet = observation_u16(body, OFF_IFI_TYPE)? == ARPHRD_ETHER;
            let mut name = None;
            let mut mac = None;
            for (kind, value) in observation_attributes(&body[IFINFOMSG_LEN..])? {
                match kind {
                    IFLA_ADDRESS if ethernet && value.len() == 6 => mac = value.try_into().ok(),
                    IFLA_IFNAME => {
                        let value = CStr::from_bytes_with_nul(value)
                            .map_err(|_| observation_malformed("interface name"))?;
                        if value.to_bytes().is_empty() {
                            return Err(observation_malformed("empty interface name"));
                        }
                        name = Some(value.to_string_lossy().into_owned());
                    }
                    _ => {}
                }
            }
            let name = name.ok_or_else(|| observation_malformed("missing interface name"))?;
            interfaces.insert(
                index,
                InterfaceObservation {
                    iface: Iface {
                        device_id: name.clone(),
                        name,
                        index,
                        description: None,
                        mac,
                        mac_masked: false,
                        ethernet,
                        up: observation_u32(body, OFF_IFI_FLAGS)? & IFF_UP != 0,
                        ipv4: Vec::new(),
                    },
                    ipv4_prefixes: Vec::new(),
                },
            );
        }
        for message in observation_messages(addrs, addr_seq)? {
            check_kernel_error(message)?;
            if observation_u16(message, OFF_NLMSG_TYPE)? != RTM_NEWADDR {
                continue;
            }
            let body = &message[NLMSG_HDRLEN..];
            if body.len() < IFADDRMSG_LEN {
                return Err(observation_malformed("ifaddrmsg"));
            }
            if body[OFF_IFA_FAMILY] != AF_INET {
                continue;
            }
            let length = body[OFF_IFA_PREFIXLEN];
            if length > 32 {
                return Err(observation_malformed("IPv4 prefix length"));
            }
            let index = observation_u32(body, OFF_IFA_INDEX)?;
            let mut address = None;
            let mut local = None;
            for (kind, value) in observation_attributes(&body[IFADDRMSG_LEN..])? {
                if matches!(kind, IFA_ADDRESS | IFA_LOCAL) {
                    let bytes: [u8; 4] = value
                        .try_into()
                        .map_err(|_| observation_malformed("IPv4 address"))?;
                    if kind == IFA_LOCAL {
                        local = Some(Ipv4Addr::from(bytes));
                    } else {
                        address = Some(Ipv4Addr::from(bytes));
                    }
                }
            }
            // IFA_ADDRESS is the peer on point-to-point interfaces; IFA_LOCAL is ours.
            if let Some(address) = local.or(address) {
                let interface = interfaces.get_mut(&index).ok_or_else(|| {
                    NetError::System("interfaces changed during network observation".into())
                })?;
                interface.iface.ipv4.push(address);
                interface.ipv4_prefixes.push(Ipv4Prefix { address, length });
            }
        }
        for interface in interfaces.values_mut() {
            interface.iface.ipv4.sort_unstable();
            interface.iface.ipv4.dedup();
            interface.ipv4_prefixes.sort_unstable();
            interface.ipv4_prefixes.dedup();
        }
        Ok(interfaces.into_values().collect())
    }

    /// Ответ lookup наблюдения: `NLMSG_ERROR`, который `no_route` признаёт отсутствием маршрута, это `None`; маршрут
    /// принимается только `RTN_UNICAST` или `RTN_LOCAL` (правила [`route_from_nl`]), прочие виды это `None`.
    pub(crate) fn observation_route_reply(
        bytes: &[u8],
        no_route: impl Fn(i32) -> bool,
        ifname: impl FnOnce(u32) -> String,
    ) -> Result<Option<Route>, NetError> {
        let routes = match parse_netlink_routes(bytes) {
            Ok(routes) => routes,
            Err(NlError::Kernel(e)) if no_route(e) => return Ok(None),
            Err(e) => return Err(NetError::System(e.to_string())),
        };
        let route = routes
            .first()
            .ok_or_else(|| observation_malformed("route reply with no route"))?;
        // Prefix endpoints do not identify custom broadcasts or other kernel route
        // kinds. Physical preparation admits only unicast or a recognised own address.
        if !matches!(route.kind, RTN_UNICAST | RTN_LOCAL) {
            return Ok(None);
        }
        Ok(route_from_nl(route, ifname))
    }
}

/// Darwin route socket: `rt_msghdr` + массив `sockaddr`, каждый выровнен `ROUNDUP(sa_len)` до 4 байт
/// (C `rawsock-getroute.c:21–22`, XNU `ROUNDUP32`).
#[cfg(any(target_os = "macos", test))]
mod rtsock {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::AF_INET;
    use super::bytes::{i32_at, ipv4_at, ipv6_at, u16_at};
    use crate::discover::{Iface, Route, RouteV6};

    /// Loopback Darwin: через него ядро доставляет пакеты на собственные адреса хоста.
    pub(crate) const LO0: &str = "lo0";
    /// `sizeof(struct rt_msghdr)` Darwin: 9 полей по 2/4 байта и `rt_metrics` (14 × u32).
    pub(crate) const RT_MSGHDR_LEN: usize = 92;
    pub(crate) const RTM_VERSION: u8 = 5;
    pub(crate) const RTM_GET: u8 = 4;
    pub(crate) const RTA_DST_BIT: i32 = 0x1;
    pub(crate) const RTA_IFP_BIT: i32 = 0x10;

    /// `rtm_flags` (`RTF_*`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct RtFlags(pub i32);

    impl RtFlags {
        /// Все биты `other` выставлены.
        pub(crate) const fn contains(self, other: RtFlags) -> bool {
            self.0 & other.0 == other.0
        }
    }

    impl std::ops::BitOr for RtFlags {
        type Output = RtFlags;
        fn bitor(self, rhs: RtFlags) -> RtFlags {
            RtFlags(self.0 | rhs.0)
        }
    }

    pub(crate) const RTF_UP: RtFlags = RtFlags(0x1);
    pub(crate) const RTF_GATEWAY: RtFlags = RtFlags(0x2);
    pub(crate) const RTF_REJECT: RtFlags = RtFlags(0x8);
    /// Маршрут хоста с записью канального уровня (ARP); XNU ставит ему `RTF_REJECT` на `arpt_down` после неудачного ARP.
    pub(crate) const RTF_LLINFO: RtFlags = RtFlags(0x400);
    pub(crate) const RTF_BLACKHOLE: RtFlags = RtFlags(0x1000);
    pub(crate) const RTF_LOCAL: RtFlags = RtFlags(0x20_0000);
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
    /// `sizeof(struct sockaddr_in)`.
    const SIN_LEN: usize = 16;
    const RTAX_GATEWAY: usize = 1;
    const RTAX_IFP: usize = 4;
    const RTAX_MAX: usize = 8;
    /// `offsetof(struct sockaddr_dl, sdl_data)`.
    pub(crate) const SDL_DATA: usize = 8;

    /// Ответ `RTM_GET` своего запроса.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct RtReply {
        pub flags: RtFlags,
        /// Имя из `RTAX_IFP` (`sockaddr_dl`).
        pub ifp: Option<String>,
        /// `sdl_index` из `RTAX_IFP`, иначе `rtm_index`.
        pub ifindex: u32,
        /// `RTAX_GATEWAY` как `sockaddr_in`.
        pub gateway_in: Option<Ipv4Addr>,
        /// `RTAX_GATEWAY` как `sockaddr_in6` (зона KAME очищена, [`in6_from_sockaddr`]).
        pub gateway_in6: Option<Ipv6Addr>,
        /// `RTAX_GATEWAY` как `sockaddr_dl`: on-link.
        pub gateway_is_link: bool,
    }

    /// `ROUNDUP(sa_len)` Darwin: до кратного 4, нулевая длина занимает 4 байта.
    pub(crate) fn sa_roundup(len: usize) -> usize {
        if len == 0 { 4 } else { (len + 3) & !3 }
    }

    /// `RTM_GET` для `dst` (сетевой порядок байт: 4 байта IPv4 или 16 байт IPv6) с `RTA_DST | RTA_IFP` (как C
    /// `rawsock-getroute.c:158–175`): 92 байта заголовка и `sockaddr_in` (16) или `sockaddr_in6` (28, scope id 0).
    pub(crate) fn rt_request(seq: i32, pid: i32, dst: &[u8]) -> Vec<u8> {
        debug_assert!(matches!(dst.len(), 4 | 16));
        let (sa_len, family, addr_at) = if dst.len() == 4 {
            (SIN_LEN, AF_INET, 4)
        } else {
            (SIN6_LEN, AF_INET6_DARWIN, SIN6_ADDR)
        };
        let mut b = vec![0u8; RT_MSGHDR_LEN + sa_len];
        // `sa_len` это `SIN_LEN` или `SIN6_LEN` (выбор выше): обе длины и оба сообщения помещаются в `u8` и `u16`.
        const { assert!(SIN_LEN <= SIN6_LEN && SIN6_LEN <= 0xFF && RT_MSGHDR_LEN + SIN6_LEN <= 0xFFFF) };
        let len = u16::try_from(b.len()).unwrap_or(u16::MAX);
        b[OFF_MSGLEN..OFF_MSGLEN + 2].copy_from_slice(&len.to_ne_bytes());
        b[OFF_VERSION] = RTM_VERSION;
        b[OFF_TYPE] = RTM_GET;
        b[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&RTF_UP.0.to_ne_bytes());
        b[OFF_ADDRS..OFF_ADDRS + 4].copy_from_slice(&(RTA_DST_BIT | RTA_IFP_BIT).to_ne_bytes());
        b[OFF_PID..OFF_PID + 4].copy_from_slice(&pid.to_ne_bytes());
        b[OFF_SEQ..OFF_SEQ + 4].copy_from_slice(&seq.to_ne_bytes());
        let sa = &mut b[RT_MSGHDR_LEN..];
        sa[0] = u8::try_from(sa_len).unwrap_or(u8::MAX);
        sa[1] = family;
        sa[addr_at..addr_at + dst.len()].copy_from_slice(dst);
        b
    }

    /// `RTM_GET` IPv4 (92 + 16 байт).
    pub(crate) fn rt_get_request(seq: i32, pid: i32, dst: Ipv4Addr) -> Vec<u8> {
        rt_request(seq, pid, &dst.octets())
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
            flags: RtFlags(field(OFF_FLAGS)?),
            ifp: None,
            ifindex: u32::from(u16_at(buf, OFF_INDEX).ok_or("short rt_msghdr")?),
            gateway_in: None,
            gateway_in6: None,
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
                (RTAX_GATEWAY, Some(AF_INET6_DARWIN)) => reply.gateway_in6 = in6_from_sockaddr(sa),
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

    /// Общая часть ответа обоих семейств ([`rt_route_parts`]).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct RtParts {
        pub ifindex: u32,
        pub ifname: String,
        /// `RTF_LOCAL` или `lo0`: адрес хоста.
        pub local: bool,
        /// `RTF_GATEWAY` и шлюз не `sockaddr_dl`.
        via_gateway: bool,
    }

    impl RtParts {
        /// Шлюз маршрута: байты `RTAX_GATEWAY` нужного семейства (`gateway_in`/`gateway_in6` ответа) только для
        /// не локального маршрута через шлюз.
        pub(crate) fn gateway<T>(&self, gateway: Option<T>) -> Option<T> {
            if self.local || !self.via_gateway {
                None
            } else {
                gateway
            }
        }
    }

    /// Ответ → общие поля маршрута: `RTF_LOCAL` или `lo0` это адрес хоста; шлюз только при `RTF_GATEWAY`
    /// (`sockaddr_dl` это on-link); `RTF_REJECT`/`RTF_BLACKHOLE` без `RTF_LLINFO` это «нет маршрута».
    pub(crate) fn rt_route_parts(r: &RtReply) -> Option<RtParts> {
        // llinfo-маршрут хоста с RTF_REJECT это сосед, чей ARP только что не удался (XNU `arpt_down`): он остаётся
        // on-link, иначе следующий скан той же цели получил бы «нет маршрута».
        if (r.flags.contains(RTF_REJECT) || r.flags.contains(RTF_BLACKHOLE))
            && !r.flags.contains(RTF_LLINFO)
        {
            return None;
        }
        let ifname = r.ifp.clone().unwrap_or_default();
        let local = r.flags.contains(RTF_LOCAL) || ifname == LO0;
        let via_gateway = r.flags.contains(RTF_GATEWAY) && !r.gateway_is_link;
        Some(RtParts {
            ifindex: r.ifindex,
            ifname,
            local,
            via_gateway,
        })
    }

    /// Ответ → [`Route`] ([`rt_route_parts`]; шлюз только `sockaddr_in`). Адреса интерфейсов, о которых ответ может не
    /// знать, добавляет [`lookup_from_rt`].
    pub(crate) fn route_from_rt(r: &RtReply) -> Option<Route> {
        let p = rt_route_parts(r)?;
        Some(Route {
            gateway: p.gateway(r.gateway_in),
            ifindex: p.ifindex,
            ifname: p.ifname,
            local: p.local,
        })
    }

    /// `RouteTable::lookup` Darwin: ответ `RTM_GET` к `dst` (`None`: маршрута нет) и интерфейсы `getifaddrs` →
    /// [`Route`]. Через неё идут `macos::route::OsRoutes` и герметичная таблица стенда m1 в тестах.
    ///
    /// `dst`, равный IPv4-адресу любого интерфейса, это адрес хоста через `lo0`, что бы ни ответил `RTM_GET` (так Darwin
    /// доставляет на свои адреса). Маршрут хоста `dst … lo0` с `RTF_LOCAL` Darwin клонирует из маршрута подсети только
    /// после того, как хост сам отправит на этот адрес; до того `RTM_GET` отвечает маршрутом подсети через интерфейс
    /// адреса (`<UP,DONE,CLONING>`), и без этой проверки ответ зависел бы от истории кеша маршрутов. Индекс такого
    /// маршрута это индекс `lo0` в списке (0, если `lo0` там нет). Иначе [`route_from_rt`]: `RTF_LOCAL` или `lo0`
    /// ответа тоже адрес хоста.
    pub(crate) fn lookup_from_rt(
        reply: Option<&RtReply>,
        dst: Ipv4Addr,
        ifaces: &[Iface],
    ) -> Option<Route> {
        if ifaces.iter().any(|i| i.ipv4.contains(&dst)) {
            return Some(Route {
                ifindex: ifaces.iter().find(|i| i.name == LO0).map_or(0, |i| i.index),
                ifname: LO0.into(),
                gateway: None,
                local: true,
            });
        }
        reply.and_then(route_from_rt)
    }

    /// `RouteTable::default_routes` Darwin: ответ `RTM_GET 0.0.0.0` (C `rawsock-getif.c`) → один маршрут или пусто
    /// (маршрута нет или он локальный).
    pub(crate) fn defaults_from_rt(reply: Option<&RtReply>) -> Vec<Route> {
        reply
            .and_then(route_from_rt)
            .filter(|r| !r.local)
            .into_iter()
            .collect()
    }

    // ------------------------------------------------------------------------------------------------ IPv6

    /// `AF_INET6` Darwin.
    pub(crate) const AF_INET6_DARWIN: u8 = 30;
    /// `sizeof(struct sockaddr_in6)`.
    pub(crate) const SIN6_LEN: usize = 28;
    /// `offsetof(struct sockaddr_in6, sin6_addr)`.
    pub(crate) const SIN6_ADDR: usize = 8;

    /// Адрес `sockaddr_in6` Darwin (`sin6_len`, `sin6_family` 30, порт, flowinfo, адрес, scope id). Ядро KAME хранит
    /// индекс зоны адресов link-local (`fe80::/10`) и multicast с зоной интерфейса или канала (`ff01::/16`,
    /// `ff02::/16`) прямо в `s6_addr[2..4]` и так отдаёт их в route socket (измерено на macOS 27: шлюз по умолчанию
    /// `fe80:e::…`); здесь эти два байта обнуляются, иначе зона ушла бы в NDP-кадр и в `[+]`. `None`: не
    /// `sockaddr_in6` или запись короче адреса.
    pub(crate) fn in6_from_sockaddr(sa: &[u8]) -> Option<Ipv6Addr> {
        if sa.get(1) != Some(&AF_INET6_DARWIN) {
            return None;
        }
        let mut b = ipv6_at(sa, SIN6_ADDR)?.octets();
        let link_local = b[0] == 0xfe && b[1] & 0xc0 == 0x80;
        let scoped_multicast = b[0] == 0xff && matches!(b[1] & 0x0f, 1 | 2);
        if link_local || scoped_multicast {
            b[2] = 0;
            b[3] = 0;
        }
        Some(Ipv6Addr::from(b))
    }

    /// `RTM_GET` IPv6 (92 + 28 байт).
    pub(crate) fn rt_get_request6(seq: i32, pid: i32, dst: Ipv6Addr) -> Vec<u8> {
        rt_request(seq, pid, &dst.octets())
    }

    /// Ответ IPv6 → [`RouteV6`] (правила [`rt_route_parts`]); шлюз только `sockaddr_in6`.
    pub(crate) fn route6_from_rt(r: &RtReply) -> Option<RouteV6> {
        let p = rt_route_parts(r)?;
        Some(RouteV6 {
            gateway: p.gateway(r.gateway_in6),
            ifindex: p.ifindex,
            ifname: p.ifname,
            source: None,
            local: p.local,
        })
    }

    /// `RouteTable::lookup_v6` Darwin: `dst`, равный IPv6-адресу любого интерфейса (`own`), это адрес хоста через
    /// `lo0` (индекс `lo0_index`), как у [`lookup_from_rt`]; иначе [`route6_from_rt`].
    pub(crate) fn lookup6_from_rt(
        reply: Option<&RtReply>,
        dst: Ipv6Addr,
        own: &[Ipv6Addr],
        lo0_index: u32,
    ) -> Option<RouteV6> {
        if own.contains(&dst) {
            return Some(RouteV6 {
                ifindex: lo0_index,
                ifname: LO0.into(),
                gateway: None,
                source: None,
                local: true,
            });
        }
        reply.and_then(route6_from_rt)
    }

    /// `RouteTable::default_routes_v6` Darwin: ответ `RTM_GET ::` → один маршрут или пусто.
    pub(crate) fn defaults6_from_rt(reply: Option<&RtReply>) -> Vec<RouteV6> {
        reply
            .and_then(route6_from_rt)
            .filter(|r| !r.local)
            .into_iter()
            .collect()
    }
}

/// Windows IP Helper: строки `MIB_IPFORWARD_ROW2` и адаптеры `IP_ADAPTER_ADDRESSES_LH`, уже скопированные `windows::sys`.
#[cfg(any(windows, test))]
mod iphlp {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::discover::{Iface, Route, RouteV6};

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
        /// Флаг `Loopback` строки `MIB_IPFORWARD_ROW2` как есть. Windows ставит его и строкам, которые не адрес хоста
        /// (/32 широковещательного адреса подсети), поэтому он только исключает строку из маршрутов по умолчанию
        /// ([`defaults_from_table`]), но не делает назначение локальным ([`route_from_best`]).
        pub mib_loopback: bool,
        /// Интерфейс строки это software loopback, IfType 24 ([`mark_loopback`]).
        pub loopback_if: bool,
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

    /// Строка таблицы маршрутов `GetIpForwardTable2`/`GetBestRoute2` любого семейства: общие поля и пометка
    /// loopback, остальное (шлюз) знает только само семейство.
    pub(crate) trait FwdRow {
        fn ifindex(&self) -> u32;
        fn metric(&self) -> u32;
        fn prefix_len(&self) -> u8;
        /// Флаг `Loopback` строки `MIB_IPFORWARD_ROW2` как есть.
        fn mib_loopback(&self) -> bool;
        /// Интерфейс строки это software loopback ([`mark_loopback`]).
        fn loopback_if(&self) -> bool;
        fn set_loopback_if(&mut self, on: bool);
    }

    impl FwdRow for Fwd {
        fn ifindex(&self) -> u32 {
            self.ifindex
        }
        fn metric(&self) -> u32 {
            self.metric
        }
        fn prefix_len(&self) -> u8 {
            self.prefix_len
        }
        fn mib_loopback(&self) -> bool {
            self.mib_loopback
        }
        fn loopback_if(&self) -> bool {
            self.loopback_if
        }
        fn set_loopback_if(&mut self, on: bool) {
            self.loopback_if = on;
        }
    }

    /// Имя интерфейса: FriendlyName, иначе AdapterName.
    fn adapter_display_name(a: &WinAdapter) -> String {
        a.friendly_name
            .clone()
            .unwrap_or_else(|| a.adapter_name.clone())
    }

    /// Адаптер → [`Iface`]: имя и описание это FriendlyName, `device_id` это `\Device\NPF_` + AdapterName.
    pub(crate) fn iface_from_adapter(a: &WinAdapter) -> Iface {
        Iface {
            name: adapter_display_name(a),
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

    /// Имя интерфейса по ifindex: первый адаптер с этим индексом, иначе `ifindex N`.
    fn name_of(ifindex: u32, adapters: &[WinAdapter]) -> String {
        adapters
            .iter()
            .find(|a| a.if_index == ifindex)
            .map_or_else(|| format!("ifindex {ifindex}"), adapter_display_name)
    }

    /// Строки через интерфейс IfType 24 (software loopback) получают `loopback_if`.
    pub(crate) fn mark_loopback<R: FwdRow>(rows: &mut [R], adapters: &[WinAdapter]) {
        for row in rows {
            if adapters
                .iter()
                .any(|a| a.if_index == row.ifindex() && a.if_type == IF_TYPE_SOFTWARE_LOOPBACK)
            {
                row.set_loopback_if(true);
            }
        }
    }

    /// Строки маршрутов по умолчанию: префикс 0, без флага MIB `Loopback` и не через IfType 24, по `metric` (порядок
    /// равных сохраняется).
    fn default_rows<R: FwdRow>(rows: &[R]) -> Vec<&R> {
        let mut d: Vec<&R> = rows
            .iter()
            .filter(|r| r.prefix_len() == 0 && !r.mib_loopback() && !r.loopback_if())
            .collect();
        d.sort_by_key(|r| r.metric());
        d
    }

    /// `RouteTable::lookup` Windows: строка `GetBestRoute2` к `dst` и адаптеры `GetAdaptersAddresses` → [`Route`]
    /// ([`mark_loopback`], затем [`route_from_best`]). Через неё идут `windows::os::OsRoutes` и герметичная таблица
    /// гостя в тестах.
    pub(crate) fn lookup_from_best(row: Fwd, dst: Ipv4Addr, adapters: &[WinAdapter]) -> Route {
        let mut rows = [row];
        mark_loopback(&mut rows, adapters);
        route_from_best(&rows[0], dst, adapters)
    }

    /// `RouteTable::default_routes` Windows: строки `GetIpForwardTable2` и адаптеры → маршруты по умолчанию
    /// ([`mark_loopback`], затем [`defaults_from_table`]).
    pub(crate) fn defaults_from_rows(mut rows: Vec<Fwd>, adapters: &[WinAdapter]) -> Vec<Route> {
        mark_loopback(&mut rows, adapters);
        defaults_from_table(&rows, adapters)
    }

    /// `GetBestRoute2` → [`Route`]. Правило `Route::local`: `dst` равен unicast-адресу адаптера или лучший маршрут идёт
    /// через software loopback (IfType 24). Флаг MIB `Loopback` строки сам по себе назначение локальным не делает:
    /// Windows ставит его и строке /32 широковещательного адреса подсети, а такая строка это on-link маршрут своего
    /// интерфейса (шлюз это `next_hop`, если он задан), как `RTN_BROADCAST` на Linux и маршрут без `RTF_LOCAL` на macOS.
    pub(crate) fn route_from_best(row: &Fwd, dst: Ipv4Addr, adapters: &[WinAdapter]) -> Route {
        let local = row.loopback_if || adapters.iter().any(|a| a.ipv4.contains(&dst));
        Route {
            ifindex: row.ifindex,
            ifname: name_of(row.ifindex, adapters),
            gateway: (!local && !row.next_hop.is_unspecified()).then_some(row.next_hop),
            local,
        }
    }

    /// Маршруты по умолчанию ([`default_rows`]).
    pub(crate) fn defaults_from_table(rows: &[Fwd], adapters: &[WinAdapter]) -> Vec<Route> {
        default_rows(rows)
            .into_iter()
            .map(|r| Route {
                ifindex: r.ifindex,
                ifname: name_of(r.ifindex, adapters),
                gateway: (!r.next_hop.is_unspecified()).then_some(r.next_hop),
                local: false,
            })
            .collect()
    }

    // ------------------------------------------------------------------------------------------------ IPv6

    /// `NL_DAD_STATE` (`nldef.h`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct DadState(pub i32);

    /// Адрес ещё проверяется (tentative), дубликат, устаревший, предпочтительный.
    pub(crate) const WIN_DAD_TENTATIVE: DadState = DadState(1);
    pub(crate) const WIN_DAD_DUPLICATE: DadState = DadState(2);
    pub(crate) const WIN_DAD_DEPRECATED: DadState = DadState(3);
    pub(crate) const WIN_DAD_PREFERRED: DadState = DadState(4);

    /// Строка таблицы маршрутов IPv6 (поля как у [`Fwd`]).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Fwd6 {
        pub ifindex: u32,
        pub prefix_len: u8,
        /// `::` это on-link.
        pub next_hop: Ipv6Addr,
        pub metric: u32,
        pub mib_loopback: bool,
        pub loopback_if: bool,
    }

    impl FwdRow for Fwd6 {
        fn ifindex(&self) -> u32 {
            self.ifindex
        }
        fn metric(&self) -> u32 {
            self.metric
        }
        fn prefix_len(&self) -> u8 {
            self.prefix_len
        }
        fn mib_loopback(&self) -> bool {
            self.mib_loopback
        }
        fn loopback_if(&self) -> bool {
            self.loopback_if
        }
        fn set_loopback_if(&mut self, on: bool) {
            self.loopback_if = on;
        }
    }

    /// `GetBestRoute2` `AF_INET6` → [`RouteV6`]: `local`, если `dst` это адрес хоста (`own`) или маршрут через
    /// software loopback; шлюз `next_hop`, если он не `::`; `source` это `BestSourceAddress`.
    pub(crate) fn route6_from_best(
        row: &Fwd6,
        source: Option<Ipv6Addr>,
        dst: Ipv6Addr,
        own: &[Ipv6Addr],
        adapters: &[WinAdapter],
    ) -> RouteV6 {
        let local = row.loopback_if || own.contains(&dst);
        RouteV6 {
            ifindex: row.ifindex,
            ifname: name_of(row.ifindex, adapters),
            gateway: (!local && !row.next_hop.is_unspecified()).then_some(row.next_hop),
            source,
            local,
        }
    }

    /// `RouteTable::lookup_v6` Windows: [`mark_loopback`], затем [`route6_from_best`].
    pub(crate) fn lookup6_from_best(
        row: Fwd6,
        source: Option<Ipv6Addr>,
        dst: Ipv6Addr,
        own: &[Ipv6Addr],
        adapters: &[WinAdapter],
    ) -> RouteV6 {
        let mut rows = [row];
        mark_loopback(&mut rows, adapters);
        route6_from_best(&rows[0], source, dst, own, adapters)
    }

    /// Маршруты IPv6 по умолчанию ([`default_rows`]).
    pub(crate) fn defaults6_from_table(rows: &[Fwd6], adapters: &[WinAdapter]) -> Vec<RouteV6> {
        default_rows(rows)
            .into_iter()
            .map(|r| RouteV6 {
                ifindex: r.ifindex,
                ifname: name_of(r.ifindex, adapters),
                gateway: (!r.next_hop.is_unspecified()).then_some(r.next_hop),
                source: None,
                local: false,
            })
            .collect()
    }

    /// `RouteTable::default_routes_v6` Windows: [`mark_loopback`], затем [`defaults6_from_table`].
    pub(crate) fn defaults6_from_rows(
        mut rows: Vec<Fwd6>,
        adapters: &[WinAdapter],
    ) -> Vec<RouteV6> {
        mark_loopback(&mut rows, adapters);
        defaults6_from_table(&rows, adapters)
    }

    /// Адреса `GetAdaptersAddresses(AF_INET6)` одного адаптера `(адрес, DadState)` → пригодные в порядке ОС:
    /// preferred, затем deprecated; tentative, duplicate и invalid отбрасываются.
    pub(crate) fn usable_win_addrs6(entries: &[(Ipv6Addr, i32)]) -> Vec<Ipv6Addr> {
        let usable = |state: i32| match DadState(state) {
            WIN_DAD_PREFERRED | WIN_DAD_DEPRECATED => true,
            // DAD ещё идёт или адрес занят другим узлом: источником быть не может.
            WIN_DAD_TENTATIVE | WIN_DAD_DUPLICATE => false,
            // `IpDadStateInvalid` (0) и неизвестные значения.
            _ => false,
        };
        let mut v: Vec<&(Ipv6Addr, i32)> = entries.iter().filter(|(_, s)| usable(*s)).collect();
        v.sort_by_key(|(_, s)| DadState(*s) == WIN_DAD_DEPRECATED);
        v.into_iter().map(|(a, _)| *a).collect()
    }
}

#[cfg(test)]
#[path = "route_parse_tests.rs"]
mod route_parse_tests;

#[cfg(test)]
#[path = "route_parse6_tests.rs"]
mod route_parse6_tests;
