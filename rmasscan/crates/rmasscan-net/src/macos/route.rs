//! Darwin: маршруты через route socket (`PF_ROUTE`, `RTM_GET`) и интерфейсы через `getifaddrs` (`ifinfo`), в процессе
//! и без привилегий; никаких процессов (`route`/`netstat` на macOS 27 отфильтрованы для ad-hoc-подписанных вызывающих)
//! и никаких изменений таблицы: `RTM_GET` только читает. `unsafe` только здесь и только вокруг вызовов libc: байты
//! запроса собирает и ответ разбирает безопасный `route_parse`.
//!
//! Каждый `PF_ROUTE`-сокет видит сообщения всей системы, поэтому ответ отбирается по `rtm_seq` и `rtm_pid` (C
//! `rawsock-getroute.c:183–196`); чтение ограничено таймаутом сокета и числом чужих сообщений.

use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};

use super::ifinfo;
use crate::NetError;
use crate::discover::{Iface, Interfaces, Route, RouteTable};
use crate::route_parse::{RtReply, parse_rt_reply, route_from_rt, rt_get_request};

/// Таймаут чтения и записи сокета (как C: `SO_RCVTIMEO`/`SO_SNDTIMEO` 1 с).
const IO_TIMEOUT_SECS: libc::time_t = 1;
/// Сколько чужих сообщений пропустить, прежде чем отказать.
const MAX_FOREIGN: usize = 256;
/// Больше любого сообщения route socket (92 + 8 sockaddr по ≤ 255 байт).
const BUF_LEN: usize = 4096;

static SEQ: AtomicI32 = AtomicI32::new(1);

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn sys(op: &str, e: i32) -> NetError {
    NetError::System(format!("{op}: {}", std::io::Error::from_raw_os_error(e)))
}

fn route_socket() -> Result<OwnedFd, NetError> {
    // SAFETY: socket() принимает только целые аргументы; результат проверяется ниже.
    let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_INET) };
    if raw < 0 {
        return Err(sys("socket(PF_ROUTE)", last_errno()));
    }
    // SAFETY: `raw` только что вернул socket(), он >= 0 и больше нигде не хранится.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let tv = libc::timeval {
        tv_sec: IO_TIMEOUT_SECS,
        tv_usec: 0,
    };
    for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: указатель и длина описывают живой `tv`; fd валиден (владеет OwnedFd).
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                opt,
                (&raw const tv).cast::<libc::c_void>(),
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(sys("setsockopt(SO_RCVTIMEO/SO_SNDTIMEO)", last_errno()));
        }
    }
    Ok(fd)
}

/// `RTM_GET` для `dst`; `None`, если маршрута нет (`ESRCH`/`ENETUNREACH` из `write`).
fn rt_get(dst: Ipv4Addr) -> Result<Option<RtReply>, NetError> {
    let fd = route_socket()?;
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id() as i32;
    let req = rt_get_request(seq, pid, dst);
    loop {
        // SAFETY: указатель и длина берутся из одного живого среза; fd валиден.
        let n = unsafe {
            libc::write(
                fd.as_raw_fd(),
                req.as_ptr().cast::<libc::c_void>(),
                req.len(),
            )
        };
        match usize::try_from(n) {
            Ok(w) if w == req.len() => break,
            Ok(_) => return Err(NetError::System("route socket: short write".into())),
            Err(_) => match last_errno() {
                libc::EINTR => {}
                libc::ESRCH | libc::ENETUNREACH => return Ok(None),
                e => return Err(sys("write(RTM_GET)", e)),
            },
        }
    }
    let mut buf = vec![0u8; BUF_LEN];
    for _ in 0..MAX_FOREIGN {
        // SAFETY: буфер описан срезом (ядро пишет не более len байт); fd валиден.
        let n = unsafe {
            libc::read(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        let n = match usize::try_from(n) {
            Ok(0) => return Err(NetError::System("route socket closed".into())),
            Ok(n) => n,
            Err(_) => match last_errno() {
                libc::EINTR => continue,
                libc::EAGAIN => {
                    return Err(NetError::System(format!(
                        "route socket: no RTM_GET reply within {IO_TIMEOUT_SECS} s"
                    )));
                }
                e => return Err(sys("read(PF_ROUTE)", e)),
            },
        };
        match parse_rt_reply(&buf[..n], seq, pid)
            .map_err(|e| NetError::System(format!("route socket: {e}")))?
        {
            Some(r) => return Ok(Some(r)),
            None => continue,
        }
    }
    Err(NetError::System(format!(
        "route socket: no RTM_GET reply among {MAX_FOREIGN} messages"
    )))
}

/// Таблица маршрутов ядра (route socket).
pub(crate) struct OsRoutes;

impl RouteTable for OsRoutes {
    fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, NetError> {
        Ok(rt_get(dst)?.as_ref().and_then(route_from_rt))
    }

    /// Darwin отдаёт один маршрут по умолчанию: `RTM_GET 0.0.0.0` (C `rawsock-getif.c`); нет его → пусто.
    fn default_routes(&self) -> Result<Vec<Route>, NetError> {
        Ok(rt_get(Ipv4Addr::UNSPECIFIED)?
            .as_ref()
            .and_then(route_from_rt)
            .filter(|r| !r.local)
            .into_iter()
            .collect())
    }
}

/// Интерфейсы `getifaddrs`; скрытый ОС MAC это `mac_masked` (`ifinfo::MASKED_MAC`).
pub(crate) struct OsIfaces;

impl Interfaces for OsIfaces {
    fn list(&self) -> Result<Vec<Iface>, NetError> {
        ifinfo::iface_list().map_err(|e| sys("getifaddrs", e))
    }
}
