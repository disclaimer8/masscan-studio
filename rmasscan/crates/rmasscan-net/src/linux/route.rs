//! Linux: маршруты через rtnetlink (`RTM_GETROUTE`) и интерфейсы через `if_nameindex` + ioctl (`SIOCGIFFLAGS`,
//! `SIOCGIFHWADDR`, `SIOCGIFADDR`), в процессе и без привилегий; никаких процессов и никаких записей в ядро (только
//! запросы). `unsafe` только здесь и только вокруг вызовов libc: байты запросов собирает и ответы разбирает
//! безопасный `route_parse`.
//!
//! * lookup цели: `RTM_GETROUTE` с `RTA_DST` (`NLM_F_REQUEST`, одна датаграмма ответа); `NLMSG_ERROR` «нет маршрута»
//!   (`ENETUNREACH`; `EHOSTUNREACH`, `EINVAL`, `EACCES` это типы unreachable, blackhole, prohibit в `fib_props`
//!   ядра) это `None`;
//! * маршруты по умолчанию: dump (`NLM_F_DUMP`) до `NLMSG_DONE`, таблица main, `dst_len` 0, по `priority`; не-dump
//!   lookup `0.0.0.0` отвечает `local … lo` и не используется;
//! * IPv6 (только обнаружение IPv6): те же lookup и dump с `AF_INET6` (ответ lookup несёт `RTA_PREFSRC`, источник,
//!   который выбрало ядро) и dump адресов `RTM_GETADDR` `AF_INET6` с флагами DAD. Путь IPv4 их не вызывает.
//!
//! Каждый fd живёт в `OwnedFd`; буферы это срезы Rust с явной длиной; ответы принимаются только от ядра (`nl_pid` 0).
//! `socket` и адрес ядра `sockaddr_nl` берутся из общих примитивов `crate::unix_sys`.

use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use super::socket::ifreq_for;
use crate::NetError;
use crate::adapter_common::{Errno, errno_msg};
use crate::discover::{Iface, Interfaces, Route, RouteTable, RouteV6};
use crate::network_plan::InterfaceObservation;
use crate::route_parse::{
    NlError, NlRoute, NlRoute6, netlink_addr_request6, netlink_defaults, netlink_done,
    netlink_route_request, netlink_route_request6, parse_netlink_addrs6, parse_netlink_routes,
    parse_netlink_routes6, route_from_nl, route6_from_nl, usable_addrs6,
};
use crate::unix_sys::{last_errno, mac_from_c_chars, nl_kernel_addr, socket, socklen_of};

/// Буфер приёма: больше любой датаграммы dump ядра (`NLMSG_GOODSIZE` ≤ 8 КиБ, на новых ядрах до 32 КиБ).
const RECV_BUF: usize = 64 * 1024;
/// Предел датаграмм одного dump (против бесконечного цикла на искажённом ответе).
const MAX_DATAGRAMS: usize = 4096;
/// Ответ ядра ждём не дольше.
const RECV_TIMEOUT_SECS: libc::time_t = 1;

static SEQ: AtomicU32 = AtomicU32::new(1);

#[path = "route_observation.rs"]
mod observation;

fn sys(op: &str, e: i32) -> NetError {
    NetError::System(errno_msg(op, e))
}

/// Отказ обмена: ошибка сокета или ответ ядра (`NLMSG_ERROR`, искажённые байты).
enum Failure {
    Io(NetError),
    Netlink(NlError),
}

impl From<Failure> for NetError {
    fn from(f: Failure) -> NetError {
        match f {
            Failure::Io(e) => e,
            Failure::Netlink(e) => NetError::System(e.to_string()),
        }
    }
}

/// Сокет `NETLINK_ROUTE` на один запрос, общий у старого блокирующего обмена и неблокирующего наблюдения. Сокет только
/// передаёт байты ядру и обратно: повторы `EINTR`, предикат отправителя и тексты ошибок остаются у каждой политики
/// (старая: [`BlockingNl`], [`exchange_on`]; наблюдение: `observation::DatagramIo`).
struct NlSocket(OwnedFd);

impl NlSocket {
    /// `label` это операция в тексте отказа `socket` (`socket(NETLINK_ROUTE)`, `socket(NETLINK_ROUTE observation)`).
    /// Блокирующий сокет получает `SO_RCVTIMEO` [`RECV_TIMEOUT_SECS`]; неблокирующий открывается с `SOCK_NONBLOCK` и
    /// без таймаута.
    fn open(label: &str, nonblocking: bool) -> Result<NlSocket, NetError> {
        let nonblock = if nonblocking { libc::SOCK_NONBLOCK } else { 0 };
        let fd = socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | nonblock,
            libc::NETLINK_ROUTE,
        )
        .map_err(|e| sys(label, e))?;
        if !nonblocking {
            let tv = libc::timeval {
                tv_sec: RECV_TIMEOUT_SECS,
                tv_usec: 0,
            };
            // SAFETY: указатель и длина описывают живой `tv`; fd валиден (владеет OwnedFd).
            let rc = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&raw const tv).cast::<libc::c_void>(),
                    socklen_of::<libc::timeval>(),
                )
            };
            if rc < 0 {
                return Err(sys("setsockopt(SO_RCVTIMEO)", last_errno()));
            }
        }
        Ok(NlSocket(fd))
    }

    /// Один `sendto` ядру (`nl_pid` 0): число отправленных байт или errno.
    fn send_to_kernel(&self, req: &[u8]) -> Result<usize, Errno> {
        let kernel = nl_kernel_addr();
        // SAFETY: указатель и длина берутся из одного живого среза; адрес назначения это живой `kernel` с его точным
        // размером; fd валиден (владеет OwnedFd).
        let n = unsafe {
            libc::sendto(
                self.0.as_raw_fd(),
                req.as_ptr().cast::<libc::c_void>(),
                req.len(),
                0,
                (&raw const kernel).cast::<libc::sockaddr>(),
                socklen_of::<libc::sockaddr_nl>(),
            )
        };
        usize::try_from(n).map_err(|_| last_errno())
    }

    /// Один `recvfrom` с `MSG_TRUNC`: `(ИСТИННАЯ длина датаграммы, адрес отправителя, длина адреса)` или errno; длина
    /// может превышать `buf`. Адрес до вызова это `nl_kernel_addr()` (`nl_pid` 0, как у прежнего нулевого образа): при
    /// нулевой длине адреса ядро в него ничего не пишет, и каждая политика сама решает, верить ли ему.
    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, libc::sockaddr_nl, libc::socklen_t), Errno> {
        let mut from = nl_kernel_addr();
        let mut flen = socklen_of::<libc::sockaddr_nl>();
        // SAFETY: буфер описан срезом (ядро пишет не более len байт); `from` и `flen` живые локальные объекты, `flen`
        // равен размеру `from`; fd валиден (владеет OwnedFd).
        let n = unsafe {
            libc::recvfrom(
                self.0.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                libc::MSG_TRUNC,
                (&raw mut from).cast::<libc::sockaddr>(),
                &raw mut flen,
            )
        };
        let n = usize::try_from(n).map_err(|_| last_errno())?;
        Ok((n, from, flen))
    }
}

/// Шов старого (блокирующего) обмена, как `DatagramIo` у наблюдения: тесты подставляют свои отправки и датаграммы.
trait BlockingNl {
    /// Один `sendto` ядру: число отправленных байт или errno.
    fn send(&mut self, req: &[u8]) -> Result<usize, Errno>;
    /// Одна датаграмма: `(ИСТИННАЯ длина, nl_pid отправителя)` или errno; длина может превышать `buf`.
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, u32), Errno>;
}

impl BlockingNl for NlSocket {
    fn send(&mut self, req: &[u8]) -> Result<usize, Errno> {
        self.send_to_kernel(req)
    }

    /// Читается только `nl_pid`: он 0 и тогда, когда ядро ответило само, и тогда, когда адрес не записан (нулевая
    /// длина адреса), поэтому длина адреса здесь не проверяется.
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, u32), Errno> {
        self.recv_from(buf).map(|(n, from, _)| (n, from.nl_pid))
    }
}

/// Отправка запроса старым обменом: `EINTR` повторяется, короткая отправка это ошибка.
fn send_request(nl: &mut impl BlockingNl, req: &[u8]) -> Result<(), NetError> {
    loop {
        match nl.send(req) {
            Ok(sent) if sent == req.len() => return Ok(()),
            Ok(_) => return Err(NetError::System("netlink: short send".into())),
            Err(libc::EINTR) => {}
            Err(e) => return Err(sys("sendto(NETLINK_ROUTE)", e)),
        }
    }
}

/// Одна датаграмма от ядра в `buf` (старый обмен); возвращает длину. `EINTR` повторяется, `EAGAIN` по `SO_RCVTIMEO`
/// это «нет ответа»; усечённая датаграмма это ошибка (проверка раньше отправителя), датаграммы других отправителей
/// (`nl_pid` не 0) пропускаются.
fn recv_reply(nl: &mut impl BlockingNl, buf: &mut [u8]) -> Result<usize, NetError> {
    loop {
        let (n, pid) = match nl.recv(buf) {
            Ok(r) => r,
            Err(libc::EINTR) => continue,
            Err(libc::EAGAIN) => {
                return Err(NetError::System(format!(
                    "netlink: no reply within {RECV_TIMEOUT_SECS} s"
                )));
            }
            Err(e) => return Err(sys("recvfrom(NETLINK_ROUTE)", e)),
        };
        if n > buf.len() {
            return Err(NetError::System(format!(
                "netlink: reply of {n} bytes truncated"
            )));
        }
        if pid != 0 {
            continue;
        }
        return Ok(n);
    }
}

/// Запрос `req` и все датаграммы ответа: одна у lookup (`dump == false`), до `NLMSG_DONE` у dump; каждая разбирается
/// `parse`.
fn exchange_with<T>(
    req: &[u8],
    dump: bool,
    parse: impl Fn(&[u8]) -> Result<Vec<T>, NlError>,
) -> Result<Vec<T>, Failure> {
    let mut nl = NlSocket::open("socket(NETLINK_ROUTE)", false).map_err(Failure::Io)?;
    exchange_on(&mut nl, req, dump, parse)
}

/// [`exchange_with`] по шву [`BlockingNl`]: отправка, затем не больше [`MAX_DATAGRAMS`] датаграмм ответа.
fn exchange_on<T>(
    nl: &mut impl BlockingNl,
    req: &[u8],
    dump: bool,
    parse: impl Fn(&[u8]) -> Result<Vec<T>, NlError>,
) -> Result<Vec<T>, Failure> {
    send_request(nl, req).map_err(Failure::Io)?;
    let mut buf = vec![0u8; RECV_BUF];
    let mut out = Vec::new();
    for _ in 0..MAX_DATAGRAMS {
        let n = recv_reply(nl, &mut buf).map_err(Failure::Io)?;
        let dgram = &buf[..n];
        out.extend(parse(dgram).map_err(Failure::Netlink)?);
        if !dump || netlink_done(dgram) {
            return Ok(out);
        }
    }
    Err(Failure::Io(NetError::System(format!(
        "netlink: dump did not end within {MAX_DATAGRAMS} datagrams"
    ))))
}

/// Запрос `RTM_GETROUTE` и все датаграммы ответа (dump до `NLMSG_DONE`).
fn exchange(dst: Option<Ipv4Addr>) -> Result<Vec<NlRoute>, Failure> {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    exchange_with(
        &netlink_route_request(seq, dst),
        dst.is_none(),
        parse_netlink_routes,
    )
}

/// `RTM_GETROUTE` `AF_INET6`: lookup `dst` или dump всех маршрутов IPv6.
fn exchange6(dst: Option<Ipv6Addr>) -> Result<Vec<NlRoute6>, Failure> {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    exchange_with(
        &netlink_route_request6(seq, dst),
        dst.is_none(),
        parse_netlink_routes6,
    )
}

/// `NLMSG_ERROR` lookup, означающий «нет маршрута» (`fib_props` ядра и отсутствие совпадения).
fn is_no_route(errno: i32) -> bool {
    matches!(
        errno,
        libc::ENETUNREACH | libc::EHOSTUNREACH | libc::EINVAL | libc::EACCES
    )
}

/// Имя интерфейса по индексу (`if_indextoname`); исчезнувший интерфейс называется индексом.
fn ifname_of(index: u32) -> String {
    let mut buf: [libc::c_char; libc::IF_NAMESIZE] = [0; libc::IF_NAMESIZE];
    // SAFETY: буфер на IF_NAMESIZE символов, как требует if_indextoname; функция пишет в него не больше.
    let p = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if p.is_null() {
        return format!("ifindex {index}");
    }
    let bytes = buf.map(|c| u8::from_ne_bytes(c.to_ne_bytes()));
    CStr::from_bytes_until_nul(&bytes).map_or_else(
        |_| format!("ifindex {index}"),
        |c| c.to_string_lossy().into_owned(),
    )
}

/// Таблица маршрутов ядра (rtnetlink).
pub(crate) struct OsRoutes;

impl RouteTable for OsRoutes {
    fn lookup_until(
        &self,
        dst: Ipv4Addr,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<Route>, NetError> {
        observation::lookup(dst, deadline, cancelled)
    }

    fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, NetError> {
        let routes = match exchange(Some(dst)) {
            Ok(r) => r,
            Err(Failure::Netlink(NlError::Kernel(e))) if is_no_route(e) => return Ok(None),
            Err(f) => return Err(f.into()),
        };
        let r = routes.first().ok_or_else(|| {
            NetError::System("netlink: RTM_GETROUTE reply carries no route".into())
        })?;
        Ok(route_from_nl(r, ifname_of))
    }

    fn default_routes(&self) -> Result<Vec<Route>, NetError> {
        let routes = exchange(None)?;
        Ok(netlink_defaults(routes)
            .iter()
            .filter_map(|r| route_from_nl(r, ifname_of))
            .collect())
    }

    /// Lookup IPv6 (`RTA_PREFSRC` ответа это источник, который выбрало ядро); «нет маршрута» по тем же errno.
    fn lookup_v6(&self, dst: Ipv6Addr) -> Result<Option<RouteV6>, NetError> {
        let routes = match exchange6(Some(dst)) {
            Ok(r) => r,
            Err(Failure::Netlink(NlError::Kernel(e))) if is_no_route(e) => return Ok(None),
            Err(f) => return Err(f.into()),
        };
        let r = routes.first().ok_or_else(|| {
            NetError::System("netlink: RTM_GETROUTE (AF_INET6) reply carries no route".into())
        })?;
        Ok(route6_from_nl(r, ifname_of))
    }

    fn default_routes_v6(&self) -> Result<Vec<RouteV6>, NetError> {
        let routes = exchange6(None)?;
        Ok(netlink_defaults(routes)
            .iter()
            .filter_map(|r| route6_from_nl(r, ifname_of))
            .collect())
    }
}

/// Владеющий массив `if_nameindex`: `if_freenameindex` ровно один раз в `Drop`.
struct NameIndex(*mut libc::if_nameindex);

impl Drop for NameIndex {
    fn drop(&mut self) {
        // SAFETY: указатель получен из успешного if_nameindex (не null), наружу не копируется и освобождается
        // ровно один раз.
        unsafe { libc::if_freenameindex(self.0) };
    }
}

/// `(индекс, имя)` всех интерфейсов в порядке ядра.
fn name_index() -> Result<Vec<(u32, String)>, NetError> {
    // SAFETY: аргументов нет; при успехе вызывающий владеет массивом (освобождает `NameIndex`).
    let p = unsafe { libc::if_nameindex() };
    if p.is_null() {
        return Err(sys("if_nameindex", last_errno()));
    }
    let list = NameIndex(p);
    let mut out = Vec::new();
    for i in 0.. {
        // SAFETY: массив завершается элементом {0, NULL}; цикл останавливается на нём, поэтому `p + i` лежит внутри
        // массива, который живёт до конца `list`.
        let e = unsafe { &*list.0.add(i) };
        if e.if_index == 0 || e.if_name.is_null() {
            break;
        }
        // SAFETY: `if_name` не null и указывает на NUL-terminated строку внутри массива; копируется сразу.
        let name = unsafe { CStr::from_ptr(e.if_name) }
            .to_string_lossy()
            .into_owned();
        out.push((e.if_index, name));
    }
    Ok(out)
}

/// Датаграммный сокет AF_INET только для ioctl запросов об интерфейсах.
struct IfSock(OwnedFd);

impl IfSock {
    fn open() -> Result<IfSock, NetError> {
        socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)
            .map(IfSock)
            .map_err(|e| sys("socket(AF_INET)", e))
    }

    /// ioctl запроса `req` (`SIOCGIF*`) для интерфейса `name`; `Err(errno)`.
    fn get(&self, name: &str, req: libc::c_ulong) -> Result<libc::ifreq, i32> {
        let mut ifr = ifreq_for(name)?;
        // SAFETY: `ifr` живой ifreq с NUL-terminated именем; для SIOCGIF* ядро читает имя и пишет результат в тот же
        // объект; fd валиден.
        let rc = unsafe { libc::ioctl(self.0.as_raw_fd(), req, &raw mut ifr) };
        if rc < 0 { Err(last_errno()) } else { Ok(ifr) }
    }

    fn iface(&self, index: u32, name: &str) -> Result<Iface, i32> {
        let flags = self.get(name, libc::SIOCGIFFLAGS)?;
        // SAFETY: после успешного SIOCGIFFLAGS активен вариант ifru_flags (целое).
        let flags = i32::from(unsafe { flags.ifr_ifru.ifru_flags });
        let hw = self.get(name, libc::SIOCGIFHWADDR)?;
        // SAFETY: после успешного SIOCGIFHWADDR активен вариант ifru_hwaddr (sockaddr из целых).
        let hw = unsafe { hw.ifr_ifru.ifru_hwaddr };
        let ipv4 = match self.get(name, libc::SIOCGIFADDR) {
            Ok(a) => {
                // SAFETY: после успешного SIOCGIFADDR активен вариант ifru_addr (sockaddr из целых).
                let sa = unsafe { a.ifr_ifru.ifru_addr };
                // sockaddr_in: sa_data[0..2] порт, sa_data[2..6] адрес в сетевом порядке.
                (i32::from(sa.sa_family) == libc::AF_INET)
                    .then(|| {
                        let b = sa.sa_data.map(|c| u8::from_ne_bytes(c.to_ne_bytes()));
                        Ipv4Addr::new(b[2], b[3], b[4], b[5])
                    })
                    .into_iter()
                    .collect()
            }
            Err(libc::EADDRNOTAVAIL) => Vec::new(),
            Err(e) => return Err(e),
        };
        let ethernet = hw.sa_family == libc::ARPHRD_ETHER;
        let mac = mac_from_c_chars(&hw.sa_data);
        Ok(Iface {
            name: name.to_string(),
            index,
            device_id: name.to_string(),
            description: None,
            mac: ethernet.then_some(mac),
            mac_masked: false,
            ethernet,
            up: flags & libc::IFF_UP != 0,
            ipv4,
        })
    }
}

/// Интерфейсы ядра: `if_nameindex`, затем `SIOCGIFFLAGS`/`SIOCGIFHWADDR`/`SIOCGIFADDR` (первый IPv4, как C
/// `rawsock_get_adapter_ip`).
pub(crate) struct OsIfaces;

impl Interfaces for OsIfaces {
    fn observe(
        &self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<InterfaceObservation>, NetError> {
        observation::interfaces(deadline, cancelled)
    }

    fn list(&self) -> Result<Vec<Iface>, NetError> {
        let sock = IfSock::open()?;
        let mut out = Vec::new();
        for (index, name) in name_index()? {
            match sock.iface(index, &name) {
                Ok(i) => out.push(i),
                // Интерфейс исчез между if_nameindex и ioctl.
                Err(libc::ENODEV | libc::ENXIO) => {}
                Err(e) => return Err(sys(&format!("ioctl SIOCGIF* ({name:?})"), e)),
            }
        }
        Ok(out)
    }

    /// Dump `RTM_GETADDR` `AF_INET6`: адреса интерфейса без tentative и dadfailed, deprecated в конце.
    fn ipv6_addrs(&self, iface: &Iface) -> Result<Vec<Ipv6Addr>, NetError> {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let addrs = exchange_with(&netlink_addr_request6(seq), true, parse_netlink_addrs6)?;
        Ok(usable_addrs6(&addrs, iface.index))
    }
}

#[cfg(test)]
#[path = "route_tests.rs"]
mod tests;
