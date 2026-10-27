//! Linux: маршруты через rtnetlink (`RTM_GETROUTE`) и интерфейсы через `if_nameindex` + ioctl (`SIOCGIFFLAGS`,
//! `SIOCGIFHWADDR`, `SIOCGIFADDR`), в процессе и без привилегий; никаких процессов и никаких записей в ядро (только
//! запросы). `unsafe` только здесь и только вокруг вызовов libc: байты запросов собирает и ответы разбирает
//! безопасный `route_parse`.
//!
//! * lookup цели: `RTM_GETROUTE` с `RTA_DST` (`NLM_F_REQUEST`, одна датаграмма ответа); `NLMSG_ERROR` «нет маршрута»
//!   (`ENETUNREACH`; `EHOSTUNREACH`, `EINVAL`, `EACCES` это типы unreachable, blackhole, prohibit в `fib_props`
//!   ядра) это `None`;
//! * маршруты по умолчанию: dump (`NLM_F_DUMP`) до `NLMSG_DONE`, таблица main, `dst_len` 0, по `priority`; не-dump
//!   lookup `0.0.0.0` отвечает `local … lo` и не используется.
//!
//! Каждый fd живёт в `OwnedFd`; буферы это срезы Rust с явной длиной; ответы принимаются только от ядра (`nl_pid` 0).

use std::ffi::CStr;
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};

use super::socket::ifreq_for;
use crate::NetError;
use crate::discover::{Iface, Interfaces, Route, RouteTable};
use crate::route_parse::{
    NlError, NlRoute, netlink_defaults, netlink_done, netlink_route_request, parse_netlink_routes,
    route_from_nl,
};

/// Буфер приёма: больше любой датаграммы dump ядра (`NLMSG_GOODSIZE` ≤ 8 КиБ, на новых ядрах до 32 КиБ).
const RECV_BUF: usize = 64 * 1024;
/// Предел датаграмм одного dump (против бесконечного цикла на искажённом ответе).
const MAX_DATAGRAMS: usize = 4096;
/// Ответ ядра ждём не дольше.
const RECV_TIMEOUT_SECS: libc::time_t = 1;

static SEQ: AtomicU32 = AtomicU32::new(1);

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn sys(op: &str, e: i32) -> NetError {
    NetError::System(format!("{op}: {}", std::io::Error::from_raw_os_error(e)))
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

/// Сокет `NETLINK_ROUTE` на один запрос.
struct Netlink {
    fd: OwnedFd,
}

impl Netlink {
    fn open() -> Result<Netlink, NetError> {
        // SAFETY: socket() принимает только целые аргументы; результат проверяется ниже.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(sys("socket(NETLINK_ROUTE)", last_errno()));
        }
        // SAFETY: `raw` только что вернул socket(), он >= 0 и больше нигде не хранится.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
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
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(sys("setsockopt(SO_RCVTIMEO)", last_errno()));
        }
        Ok(Netlink { fd })
    }

    fn send(&self, req: &[u8]) -> Result<(), NetError> {
        // SAFETY: sockaddr_nl состоит из целых полей; нулевой образ корректен (nl_pid 0 это ядро).
        let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        loop {
            // SAFETY: указатель и длина берутся из одного живого среза; адрес назначения это живой `kernel` с его
            // точным размером; fd валиден.
            let n = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    req.as_ptr().cast::<libc::c_void>(),
                    req.len(),
                    0,
                    (&raw const kernel).cast::<libc::sockaddr>(),
                    mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            match usize::try_from(n) {
                Ok(sent) if sent == req.len() => return Ok(()),
                Ok(_) => return Err(NetError::System("netlink: short send".into())),
                Err(_) if last_errno() == libc::EINTR => {}
                Err(_) => return Err(sys("sendto(NETLINK_ROUTE)", last_errno())),
            }
        }
    }

    /// Одна датаграмма от ядра в `buf`; датаграммы других отправителей пропускаются. Возвращает длину.
    fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        loop {
            // SAFETY: sockaddr_nl из целых полей; нулевой образ корректен.
            let mut from: libc::sockaddr_nl = unsafe { mem::zeroed() };
            let mut flen = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            // SAFETY: буфер описан срезом (ядро пишет не более len байт); `from` и `flen` живые локальные объекты,
            // `flen` равен их размеру. MSG_TRUNC возвращает ИСТИННУЮ длину датаграммы.
            let n = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    libc::MSG_TRUNC,
                    (&raw mut from).cast::<libc::sockaddr>(),
                    &raw mut flen,
                )
            };
            let Ok(n) = usize::try_from(n) else {
                match last_errno() {
                    libc::EINTR => continue,
                    libc::EAGAIN => {
                        return Err(NetError::System(format!(
                            "netlink: no reply within {RECV_TIMEOUT_SECS} s"
                        )));
                    }
                    e => return Err(sys("recvfrom(NETLINK_ROUTE)", e)),
                }
            };
            if n > buf.len() {
                return Err(NetError::System(format!(
                    "netlink: reply of {n} bytes truncated"
                )));
            }
            if from.nl_pid != 0 {
                continue;
            }
            return Ok(n);
        }
    }
}

/// Запрос `RTM_GETROUTE` и все датаграммы ответа (dump до `NLMSG_DONE`).
fn exchange(dst: Option<Ipv4Addr>) -> Result<Vec<NlRoute>, Failure> {
    let nl = Netlink::open().map_err(Failure::Io)?;
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    nl.send(&netlink_route_request(seq, dst))
        .map_err(Failure::Io)?;
    let mut buf = vec![0u8; RECV_BUF];
    let mut routes = Vec::new();
    for _ in 0..MAX_DATAGRAMS {
        let n = nl.recv(&mut buf).map_err(Failure::Io)?;
        let dgram = &buf[..n];
        routes.extend(parse_netlink_routes(dgram).map_err(Failure::Netlink)?);
        if dst.is_some() || netlink_done(dgram) {
            return Ok(routes);
        }
    }
    Err(Failure::Io(NetError::System(format!(
        "netlink: dump did not end within {MAX_DATAGRAMS} datagrams"
    ))))
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
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: буфер на IF_NAMESIZE символов, как требует if_indextoname; функция пишет в него не больше.
    let p = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if p.is_null() {
        return format!("ifindex {index}");
    }
    let bytes = buf.map(|c| c as u8);
    CStr::from_bytes_until_nul(&bytes).map_or_else(
        |_| format!("ifindex {index}"),
        |c| c.to_string_lossy().into_owned(),
    )
}

/// Таблица маршрутов ядра (rtnetlink).
pub(crate) struct OsRoutes;

impl RouteTable for OsRoutes {
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
        // SAFETY: socket() только с целыми аргументами; результат проверяется.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(sys("socket(AF_INET)", last_errno()));
        }
        // SAFETY: `raw` свежий fd >= 0, единственный владелец теперь OwnedFd.
        Ok(IfSock(unsafe { OwnedFd::from_raw_fd(raw) }))
    }

    /// ioctl запроса `req` (`SIOCGIF*`) для интерфейса `name`; `Err(errno)`.
    fn get(&self, name: &str, req: libc::c_ulong) -> Result<libc::ifreq, i32> {
        let mut ifr = ifreq_for(name)?;
        // SAFETY: `ifr` живой ifreq с NUL-terminated именем; для SIOCGIF* ядро читает имя и пишет результат в тот же
        // объект; fd валиден.
        let rc = unsafe { libc::ioctl(self.0.as_raw_fd(), req as _, &raw mut ifr) };
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
                        Ipv4Addr::new(
                            sa.sa_data[2] as u8,
                            sa.sa_data[3] as u8,
                            sa.sa_data[4] as u8,
                            sa.sa_data[5] as u8,
                        )
                    })
                    .into_iter()
                    .collect()
            }
            Err(libc::EADDRNOTAVAIL) => Vec::new(),
            Err(e) => return Err(e),
        };
        let ethernet = hw.sa_family == libc::ARPHRD_ETHER;
        let mut mac = [0u8; 6];
        for (d, s) in mac.iter_mut().zip(hw.sa_data.iter()) {
            *d = *s as u8;
        }
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
}
