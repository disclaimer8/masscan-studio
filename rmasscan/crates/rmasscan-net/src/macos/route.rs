//! Darwin read-only routing observations. PF_ROUTE handles are nonblocking;
//! one absolute <=1s deadline covers writes, readiness, EINTR and foreign replies.
use super::ifinfo;
use crate::network_plan::{InterfaceObservation, check_observation};
use crate::route_parse::{RtReply, parse_rt_reply, route_from_rt, rt_get_request};
use crate::{
    NetError,
    discover::{Iface, Interfaces, Route, RouteTable},
};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
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
    // SAFETY: scalar socket arguments; the result is checked before ownership transfer.
    let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_INET) };
    if raw < 0 {
        return Err(sys("socket(PF_ROUTE)", last_errno()));
    }
    // SAFETY: raw is a newly acquired descriptor owned solely by this object.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: valid owned descriptor; F_GETFL has no pointer argument.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(sys("fcntl(F_GETFL)", last_errno()));
    }
    // SAFETY: valid owned descriptor; setting O_NONBLOCK preserves its other flags.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(sys("fcntl(O_NONBLOCK)", last_errno()));
    }
    Ok(fd)
}
fn ready(fd: &OwnedFd, event: libc::c_short, wait: Duration) -> Result<bool, NetError> {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: event,
        revents: 0,
    };
    // Floor to milliseconds; a sub-ms residual becomes a nonblocking poll.
    let millis = wait.as_millis().min(50) as libc::c_int;
    // SAFETY: p is one writable pollfd, fd is owned and millis is bounded.
    let n = unsafe { libc::poll(&mut p, 1, millis) };
    if n < 0 {
        return match last_errno() {
            libc::EINTR => Ok(false),
            e => Err(sys("poll(PF_ROUTE)", e)),
        };
    }
    if p.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(NetError::System("route socket readiness error".into()));
    }
    Ok(n > 0 && p.revents & event != 0)
}
fn retry_until<T>(
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
    now: impl Fn() -> Instant,
    mut step: impl FnMut(Duration) -> Result<Option<T>, NetError>,
) -> Result<T, NetError> {
    let check = || {
        if cancelled() {
            return Err(NetError::System("network observation cancelled".into()));
        }
        let n = now();
        if n >= deadline {
            return Err(NetError::System(
                "route observation deadline expired".into(),
            ));
        }
        Ok(n)
    };
    loop {
        let n = check()?;
        let result = step((deadline - n).min(Duration::from_millis(50)))?;
        check()?;
        if let Some(value) = result {
            return Ok(value);
        }
    }
}
fn rt_get(
    dst: Ipv4Addr,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Option<RtReply>, NetError> {
    let deadline = deadline.min(Instant::now() + Duration::from_secs(1));
    check_observation(deadline, cancelled)?;
    let fd = route_socket()?;
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id() as i32;
    let req = rt_get_request(seq, pid, dst);
    let sent = retry_until(deadline, cancelled, Instant::now, |wait| {
        if !ready(&fd, libc::POLLOUT, wait)? {
            return Ok(None);
        }
        check_observation(deadline, cancelled)?;
        // SAFETY: request pointer and length refer to one live slice, fd is owned/nonblocking.
        let n = unsafe { libc::write(fd.as_raw_fd(), req.as_ptr().cast(), req.len()) };
        match usize::try_from(n) {
            Ok(n) if n == req.len() => Ok(Some(true)),
            Ok(_) => Err(NetError::System("route socket short write".into())),
            Err(_) => match last_errno() {
                libc::EINTR | libc::EAGAIN => Ok(None),
                libc::ESRCH | libc::ENETUNREACH => Ok(Some(false)),
                e => Err(sys("write(RTM_GET)", e)),
            },
        }
    })?;
    if !sent {
        return Ok(None);
    }
    let mut buf = [0u8; BUF_LEN];
    retry_until(deadline, cancelled, Instant::now, |wait| {
        if !ready(&fd, libc::POLLIN, wait)? {
            return Ok(None);
        }
        check_observation(deadline, cancelled)?;
        // SAFETY: writable live buffer, capacity matches length, fd is owned/nonblocking.
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        let n = match usize::try_from(n) {
            Ok(0) => return Err(NetError::System("route socket closed".into())),
            Ok(n) => n,
            Err(_) => {
                return match last_errno() {
                    libc::EINTR | libc::EAGAIN => Ok(None),
                    e => Err(sys("read(PF_ROUTE)", e)),
                };
            }
        };
        parse_rt_reply(&buf[..n], seq, pid)
            .map_err(|e| NetError::System(format!("route socket: {e}")))
    })
    .map(Some)
}
pub(crate) struct OsRoutes;
impl RouteTable for OsRoutes {
    fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, NetError> {
        self.lookup_until(dst, Instant::now() + Duration::from_secs(1), &|| false)
    }
    fn lookup_until(
        &self,
        dst: Ipv4Addr,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<Route>, NetError> {
        Ok(rt_get(dst, deadline, cancelled)?
            .as_ref()
            .and_then(route_from_rt))
    }
    fn default_routes(&self) -> Result<Vec<Route>, NetError> {
        Ok(rt_get(
            Ipv4Addr::UNSPECIFIED,
            Instant::now() + Duration::from_secs(1),
            &|| false,
        )?
        .as_ref()
        .and_then(route_from_rt)
        .filter(|r| !r.local)
        .into_iter()
        .collect())
    }
}
pub(crate) struct OsIfaces;
impl Interfaces for OsIfaces {
    fn list(&self) -> Result<Vec<Iface>, NetError> {
        ifinfo::iface_list().map_err(|e| sys("getifaddrs", e))
    }
    fn observe(
        &self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<InterfaceObservation>, NetError> {
        ifinfo::observe(deadline, cancelled)
    }
}
#[cfg(test)]
mod bounded_tests {
    use super::*;
    use std::{
        cell::Cell,
        time::{Duration, Instant},
    };
    #[test]
    fn network_plan_foreign_replies_and_eintr_keep_original_deadline() {
        let start = Instant::now();
        let time = Cell::new(start);
        let calls = Cell::new(0);
        let r = retry_until::<()>(
            start + Duration::from_secs(1),
            &|| false,
            || time.get(),
            |slice| {
                assert!(slice <= Duration::from_millis(50));
                calls.set(calls.get() + 1);
                time.set(time.get() + slice);
                Ok(None)
            },
        );
        assert!(r.unwrap_err().to_string().contains("deadline"));
        assert_eq!(calls.get(), 20);
        assert_eq!(time.get() - start, Duration::from_secs(1));
    }
    #[test]
    fn network_plan_cancel_during_blocked_route_lookup_is_seen_after_one_slice() {
        let start = Instant::now();
        let time = Cell::new(start);
        let cancelled = Cell::new(false);
        let calls = Cell::new(0);
        let r = retry_until::<()>(
            start + Duration::from_secs(10),
            &|| cancelled.get(),
            || time.get(),
            |slice| {
                calls.set(calls.get() + 1);
                time.set(time.get() + slice);
                cancelled.set(true);
                Ok(None)
            },
        );
        assert!(r.unwrap_err().to_string().contains("cancelled"));
        assert_eq!(calls.get(), 1);
        assert_eq!(time.get() - start, Duration::from_millis(50));
    }
    #[test]
    fn network_plan_late_success_or_cancelled_success_is_not_accepted() {
        for cancel in [false, true] {
            let start = Instant::now();
            let time = Cell::new(start);
            let c = Cell::new(false);
            let r = retry_until(
                start + Duration::from_millis(5),
                &|| c.get(),
                || time.get(),
                |_| {
                    time.set(start + Duration::from_millis(5));
                    c.set(cancel);
                    Ok(Some(42))
                },
            );
            assert!(r.is_err());
        }
    }
}
