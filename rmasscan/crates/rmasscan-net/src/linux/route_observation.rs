//! Bounded read-only NETLINK_ROUTE queries. No AF_PACKET handles are opened.
//! Separate from legacy CLI enumeration so its interface/address selection stays unchanged.
//! Policy only (deadline, retries, kernel-sender check, reply limit): the bytes are built and decoded by
//! `route_parse::observation_*`, the socket is the shared `NlSocket`.
use super::*;
use crate::network_plan::check_observation;
use crate::route_parse::{
    RTM_GETADDR, RTM_GETLINK, observation_dump_request, observation_malformed,
    observation_message_ends, observation_messages, observation_route_reply, observations,
};
use crate::unix_sys::{poll_one, socklen_of};
use std::os::fd::AsFd;
use std::time::Duration;

const MAX_REPLY_BYTES: usize = 8 * 1024 * 1024;
const MAX_ATTEMPTS: usize = 4096;
const SLICE: Duration = Duration::from_millis(50);

/// The syscall seam only concerns NETLINK_ROUTE, never a packet adapter.
trait DatagramIo {
    fn ready(&mut self, write: bool, wait: Duration) -> Result<bool, i32>;
    fn send(&mut self, request: &[u8]) -> Result<usize, i32>;
    /// `(true length, kernel sender)`; the length may exceed the supplied buffer.
    fn recv(&mut self, buffer: &mut [u8]) -> Result<(usize, bool), i32>;
}

impl DatagramIo for NlSocket {
    fn ready(&mut self, write: bool, wait: Duration) -> Result<bool, i32> {
        let event = if write { libc::POLLOUT } else { libc::POLLIN };
        // Floor rather than round up: a residual shorter than 1ms is nonblocking.
        let millis = libc::c_int::try_from(wait.min(SLICE).as_millis()).unwrap_or(libc::c_int::MAX);
        let (n, revents) = poll_one(self.0.as_fd(), event, millis)?;
        if revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(libc::EIO);
        }
        Ok(n > 0 && revents & event != 0)
    }

    /// The socket is opened nonblocking (`query`), so a write cannot extend our deadline.
    fn send(&mut self, request: &[u8]) -> Result<usize, i32> {
        self.send_to_kernel(request)
    }

    /// The sender address starts as `nl_pid` 0 (as the zeroed value was). With a zero-length address the kernel writes
    /// nothing, so correctness comes from the length check (`len` must cover the whole address) rather than from the
    /// kernel overwriting `from`.
    fn recv(&mut self, buffer: &mut [u8]) -> Result<(usize, bool), i32> {
        let (n, from, len) = self.recv_from(buffer)?;
        Ok((
            n,
            len >= socklen_of::<libc::sockaddr_nl>()
                && i32::from(from.nl_family) == libc::AF_NETLINK
                && from.nl_pid == 0,
        ))
    }
}

fn retry_until<T>(
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
    now: impl Fn() -> Instant,
    mut step: impl FnMut(Duration) -> Result<Option<T>, NetError>,
) -> Result<T, NetError> {
    let check = || {
        if cancelled() {
            return Err(NetError::System("network preparation cancelled".into()));
        }
        let n = now();
        if n >= deadline {
            return Err(NetError::System(
                "network observation deadline expired".into(),
            ));
        }
        Ok(n)
    };
    for _ in 0..MAX_ATTEMPTS {
        let n = check()?;
        let result = step((deadline - n).min(SLICE))?;
        check()?; // Do not accept even a successful reply after cancellation/deadline.
        if let Some(value) = result {
            return Ok(value);
        }
    }
    Err(NetError::System(
        "netlink observation retry limit exceeded".into(),
    ))
}

fn retryable(e: i32) -> bool {
    matches!(e, libc::EINTR | libc::EAGAIN)
}

fn exchange_until(
    io: &mut impl DatagramIo,
    request: &[u8],
    seq: u32,
    dump: bool,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, NetError> {
    retry_until(deadline, cancelled, Instant::now, |wait| {
        match io.ready(true, wait) {
            Ok(false) => return Ok(None),
            Err(e) if retryable(e) => return Ok(None),
            Err(e) => return Err(sys("poll(NETLINK_ROUTE write)", e)),
            Ok(true) => {}
        }
        check_observation(deadline, cancelled)?;
        match io.send(request) {
            Ok(n) if n == request.len() => Ok(Some(())),
            Ok(_) => Err(NetError::System("netlink observation: short send".into())),
            Err(e) if retryable(e) => Ok(None),
            Err(e) => Err(sys("sendto(NETLINK_ROUTE observation)", e)),
        }
    })?;
    let mut buffer = vec![0u8; RECV_BUF];
    let mut output = Vec::new();
    retry_until(deadline, cancelled, Instant::now, |wait| {
        match io.ready(false, wait) {
            Ok(false) => return Ok(None),
            Err(e) if retryable(e) => return Ok(None),
            Err(e) => return Err(sys("poll(NETLINK_ROUTE read)", e)),
            Ok(true) => {}
        }
        check_observation(deadline, cancelled)?;
        let (n, kernel) = match io.recv(&mut buffer) {
            Ok(value) => value,
            Err(e) if retryable(e) => return Ok(None),
            Err(e) => return Err(sys("recvfrom(NETLINK_ROUTE observation)", e)),
        };
        if !kernel {
            return Ok(None);
        }
        if n == 0 || n > buffer.len() {
            return Err(observation_malformed("empty or truncated datagram"));
        }
        let mut complete = false;
        for message in observation_messages(&buffer[..n], seq)? {
            complete |= observation_message_ends(message, dump)?;
            if output.len() + message.len() > MAX_REPLY_BYTES {
                return Err(NetError::System(
                    "netlink observation reply limit exceeded".into(),
                ));
            }
            output.extend_from_slice(message);
            output.resize((output.len() + 3) & !3, 0);
        }
        Ok(complete.then_some(()))
    })?;
    Ok(output)
}

fn query(
    request: &[u8],
    seq: u32,
    dump: bool,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, NetError> {
    check_observation(deadline, cancelled)?;
    let mut socket = NlSocket::open("socket(NETLINK_ROUTE observation)", true)?;
    exchange_until(&mut socket, request, seq, dump, deadline, cancelled)
}

pub(super) fn lookup(
    dst: Ipv4Addr,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Option<Route>, NetError> {
    let deadline = deadline.min(Instant::now() + Duration::from_secs(1));
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let bytes = query(
        &netlink_route_request(seq, Some(dst)),
        seq,
        false,
        deadline,
        cancelled,
    )?;
    let result = observation_route_reply(&bytes, is_no_route, ifname_of)?;
    check_observation(deadline, cancelled)?;
    Ok(result)
}

pub(super) fn interfaces(
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<InterfaceObservation>, NetError> {
    let deadline = deadline.min(Instant::now() + Duration::from_secs(1));
    let link_seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let links = query(
        &observation_dump_request(RTM_GETLINK, link_seq),
        link_seq,
        true,
        deadline,
        cancelled,
    )?;
    let addr_seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let addrs = query(
        &observation_dump_request(RTM_GETADDR, addr_seq),
        addr_seq,
        true,
        deadline,
        cancelled,
    )?;
    let result = observations(&links, link_seq, &addrs, addr_seq)?;
    check_observation(deadline, cancelled)?;
    Ok(result)
}

#[cfg(test)]
#[path = "route_observation_tests.rs"]
mod tests;
