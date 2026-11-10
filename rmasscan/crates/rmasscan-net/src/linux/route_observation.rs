//! Bounded read-only NETLINK_ROUTE queries. No AF_PACKET handles are opened.
//! Separate from legacy CLI enumeration so its interface/address selection stays unchanged.
use super::*;
use crate::network_plan::{Ipv4Prefix, check_observation};
use crate::route_parse::{RTN_LOCAL, RTN_UNICAST};
use std::collections::BTreeMap;
use std::time::Duration;

const HEADER_LEN: usize = 16;
const MAX_REPLY_BYTES: usize = 8 * 1024 * 1024;
const MAX_ATTEMPTS: usize = 4096;
const SLICE: Duration = Duration::from_millis(50);
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_DUMP_INTR: u16 = 0x10;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;

fn malformed(message: &str) -> NetError {
    NetError::System(format!("netlink observation: malformed {message}"))
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, NetError> {
    Ok(u16::from_ne_bytes(
        bytes
            .get(at..at + 2)
            .ok_or_else(|| malformed("u16"))?
            .try_into()
            .unwrap(),
    ))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, NetError> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(at..at + 4)
            .ok_or_else(|| malformed("u32"))?
            .try_into()
            .unwrap(),
    ))
}

/// The syscall seam only concerns NETLINK_ROUTE, never a packet adapter.
trait DatagramIo {
    fn ready(&mut self, write: bool, wait: Duration) -> Result<bool, i32>;
    fn send(&mut self, request: &[u8]) -> Result<usize, i32>;
    /// `(true length, kernel sender)`; the length may exceed the supplied buffer.
    fn recv(&mut self, buffer: &mut [u8]) -> Result<(usize, bool), i32>;
}

struct Socket(OwnedFd);

impl Socket {
    fn open() -> Result<Self, NetError> {
        // SAFETY: scalar arguments; nonnegative return is transferred to one OwnedFd.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(sys("socket(NETLINK_ROUTE observation)", last_errno()));
        }
        // SAFETY: raw is a newly created descriptor; no other object owns it.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(raw) }))
    }
}

impl DatagramIo for Socket {
    fn ready(&mut self, write: bool, wait: Duration) -> Result<bool, i32> {
        let event = if write { libc::POLLOUT } else { libc::POLLIN };
        let mut p = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: event,
            revents: 0,
        };
        // Floor rather than round up: a residual shorter than 1ms is nonblocking.
        let millis = wait.min(SLICE).as_millis() as libc::c_int;
        // SAFETY: p is one live writable pollfd; the timeout is bounded to 50ms.
        let n = unsafe { libc::poll(&raw mut p, 1, millis) };
        if n < 0 {
            return Err(last_errno());
        }
        if p.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(libc::EIO);
        }
        Ok(n > 0 && p.revents & event != 0)
    }

    fn send(&mut self, request: &[u8]) -> Result<usize, i32> {
        // SAFETY: sockaddr_nl is integer fields and zero is a valid kernel destination.
        let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: request and address are live and exactly described by their lengths;
        // the owned nonblocking fd prevents a write from extending our deadline.
        let n = unsafe {
            libc::sendto(
                self.0.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&raw const kernel).cast(),
                mem::size_of_val(&kernel) as libc::socklen_t,
            )
        };
        usize::try_from(n).map_err(|_| last_errno())
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<(usize, bool), i32> {
        // SAFETY: sockaddr_nl has integer fields, so its zero representation is valid.
        let mut from: libc::sockaddr_nl = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&from) as libc::socklen_t;
        // SAFETY: both output buffers have their true writable lengths. MSG_TRUNC
        // reports the datagram's true size, which the caller checks before slicing.
        let n = unsafe {
            libc::recvfrom(
                self.0.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
                (&raw mut from).cast(),
                &raw mut len,
            )
        };
        let n = usize::try_from(n).map_err(|_| last_errno())?;
        Ok((
            n,
            len as usize >= mem::size_of_val(&from)
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

/// Messages for this request only, validated before any are consumed. A fresh
/// socket is also used for each query, but sequence matching remains mandatory.
fn messages(bytes: &[u8], seq: u32) -> Result<Vec<&[u8]>, NetError> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let rest = &bytes[offset..];
        if rest.len() < HEADER_LEN {
            return Err(malformed("netlink header"));
        }
        let len = u32_at(rest, 0)? as usize;
        if len < HEADER_LEN || len > rest.len() {
            return Err(malformed("netlink length"));
        }
        if u32_at(rest, 8)? == seq {
            out.push(&rest[..len]);
        }
        let aligned = (len + 3) & !3;
        // A final message need not carry padding beyond its declared length.
        offset += aligned.min(rest.len());
    }
    Ok(out)
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
            return Err(malformed("empty or truncated datagram"));
        }
        let mut complete = false;
        for message in messages(&buffer[..n], seq)? {
            if u16_at(message, 6)? & NLM_F_DUMP_INTR != 0 {
                return Err(NetError::System(
                    "netlink observation: interrupted dump".into(),
                ));
            }
            let kind = u16_at(message, 4)?;
            if kind == NLMSG_DONE {
                if message.len() > HEADER_LEN {
                    let error = u32_at(message, HEADER_LEN)? as i32;
                    if error != 0 {
                        return Err(sys("netlink dump", error.saturating_neg()));
                    }
                }
                complete = true;
            }
            if kind == NLMSG_ERROR {
                // An ACK (zero) does not finish a dump or a route lookup.
                complete |= u32_at(message, HEADER_LEN)? != 0;
            } else if kind >= RTM_NEWLINK && !dump {
                complete = true;
            }
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
    let mut socket = Socket::open()?;
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
    let result = route_reply(&bytes, ifname_of)?;
    check_observation(deadline, cancelled)?;
    Ok(result)
}

fn route_reply(
    bytes: &[u8],
    ifname: impl FnOnce(u32) -> String,
) -> Result<Option<Route>, NetError> {
    let routes = match parse_netlink_routes(bytes) {
        Ok(routes) => routes,
        Err(NlError::Kernel(e)) if is_no_route(e) => return Ok(None),
        Err(e) => return Err(NetError::System(e.to_string())),
    };
    let route = routes
        .first()
        .ok_or_else(|| malformed("route reply with no route"))?;
    // Prefix endpoints do not identify custom broadcasts or other kernel route
    // kinds. Physical preparation admits only unicast or a recognised own address.
    if !matches!(route.kind, RTN_UNICAST | RTN_LOCAL) {
        return Ok(None);
    }
    Ok(route_from_nl(route, ifname))
}

fn dump_request(kind: u16, seq: u32) -> Vec<u8> {
    // ifinfomsg is 16 bytes, ifaddrmsg 8 bytes; family is the first field of both.
    let payload_len = if kind == RTM_GETLINK { 16 } else { 8 };
    let mut request = vec![0; HEADER_LEN + payload_len];
    request[..4].copy_from_slice(&((HEADER_LEN + payload_len) as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&kind.to_ne_bytes());
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes()); // REQUEST | DUMP
    request[8..12].copy_from_slice(&seq.to_ne_bytes());
    request[HEADER_LEN] = if kind == RTM_GETADDR {
        libc::AF_INET as u8
    } else {
        libc::AF_UNSPEC as u8
    };
    request
}

fn attributes(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, NetError> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let len = usize::from(u16_at(bytes, 0)?);
        if len < 4 || len > bytes.len() {
            return Err(malformed("attribute length"));
        }
        out.push((u16_at(bytes, 2)? & 0x3fff, &bytes[4..len]));
        let aligned = (len + 3) & !3;
        bytes = &bytes[aligned.min(bytes.len())..];
    }
    Ok(out)
}

fn check_kernel_error(message: &[u8]) -> Result<(), NetError> {
    if u16_at(message, 4)? == NLMSG_ERROR {
        let error = u32_at(message, HEADER_LEN)? as i32;
        if error != 0 {
            return Err(sys("netlink interface dump", error.saturating_neg()));
        }
    }
    Ok(())
}

fn observations(
    links: &[u8],
    link_seq: u32,
    addrs: &[u8],
    addr_seq: u32,
) -> Result<Vec<InterfaceObservation>, NetError> {
    let mut interfaces = BTreeMap::new();
    for message in messages(links, link_seq)? {
        check_kernel_error(message)?;
        if u16_at(message, 4)? != RTM_NEWLINK {
            continue;
        }
        let body = &message[HEADER_LEN..];
        if body.len() < 16 {
            return Err(malformed("ifinfomsg"));
        }
        let index = u32_at(body, 4)?;
        if index == 0 || index > i32::MAX as u32 {
            return Err(malformed("interface index"));
        }
        let ethernet = u16_at(body, 2)? == libc::ARPHRD_ETHER;
        let mut name = None;
        let mut mac = None;
        for (kind, value) in attributes(&body[16..])? {
            match kind {
                1 if ethernet && value.len() == 6 => mac = Some(value.try_into().unwrap()),
                3 => {
                    let value = CStr::from_bytes_with_nul(value)
                        .map_err(|_| malformed("interface name"))?;
                    if value.to_bytes().is_empty() {
                        return Err(malformed("empty interface name"));
                    }
                    name = Some(value.to_string_lossy().into_owned());
                }
                _ => {}
            }
        }
        let name = name.ok_or_else(|| malformed("missing interface name"))?;
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
                    up: u32_at(body, 8)? & libc::IFF_UP as u32 != 0,
                    ipv4: Vec::new(),
                },
                ipv4_prefixes: Vec::new(),
            },
        );
    }
    for message in messages(addrs, addr_seq)? {
        check_kernel_error(message)?;
        if u16_at(message, 4)? != RTM_NEWADDR {
            continue;
        }
        let body = &message[HEADER_LEN..];
        if body.len() < 8 {
            return Err(malformed("ifaddrmsg"));
        }
        if body[0] != libc::AF_INET as u8 {
            continue;
        }
        let length = body[1];
        if length > 32 {
            return Err(malformed("IPv4 prefix length"));
        }
        let index = u32_at(body, 4)?;
        let mut address = None;
        let mut local = None;
        for (kind, value) in attributes(&body[8..])? {
            if matches!(kind, 1 | 2) {
                let bytes: [u8; 4] = value.try_into().map_err(|_| malformed("IPv4 address"))?;
                if kind == 2 {
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

pub(super) fn interfaces(
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<InterfaceObservation>, NetError> {
    let deadline = deadline.min(Instant::now() + Duration::from_secs(1));
    let link_seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let links = query(
        &dump_request(RTM_GETLINK, link_seq),
        link_seq,
        true,
        deadline,
        cancelled,
    )?;
    let addr_seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let addrs = query(
        &dump_request(RTM_GETADDR, addr_seq),
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
