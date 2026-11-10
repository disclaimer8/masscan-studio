use super::*;
use std::cell::Cell;
use std::collections::VecDeque;

fn message(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(((16 + body.len()) as u32).to_ne_bytes());
    out.extend(kind.to_ne_bytes());
    out.extend(flags.to_ne_bytes());
    out.extend(seq.to_ne_bytes());
    out.extend(0u32.to_ne_bytes());
    out.extend(body);
    out.resize((out.len() + 3) & !3, 0);
    out
}

fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(((4 + value.len()) as u16).to_ne_bytes());
    out.extend(kind.to_ne_bytes());
    out.extend(value);
    out.resize((out.len() + 3) & !3, 0);
    out
}

fn link(index: u32, name: &str, kind: u16, flags: u32) -> Vec<u8> {
    let mut body = vec![0; 16];
    body[2..4].copy_from_slice(&kind.to_ne_bytes());
    body[4..8].copy_from_slice(&index.to_ne_bytes());
    body[8..12].copy_from_slice(&flags.to_ne_bytes());
    body.extend(attr(3, format!("{name}\0").as_bytes()));
    body.extend(attr(1, &[2, 1, 2, 3, 4, 5]));
    message(16, 0, 41, &body)
}

fn address(index: u32, address: [u8; 4], prefix: u8, local: Option<[u8; 4]>) -> Vec<u8> {
    let mut body = vec![2, prefix, 0, 0];
    body.extend(index.to_ne_bytes());
    body.extend(attr(1, &address));
    if let Some(local) = local {
        body.extend(attr(2, &local));
    }
    // A legacy alias label must not cause a separate or missing interface.
    body.extend(attr(3, b"eth0:office\0"));
    message(20, 0, 42, &body)
}

#[test]
fn network_plan_keeps_all_alias_prefixes_and_uses_local_point_to_point_address() {
    let links = [
        link(2, "eth0", 1, 1),
        link(7, "ppp0", 512, 1),
        link(8, "down0", 1, 0),
    ]
    .concat();
    let addrs = [
        address(2, [192, 168, 5, 20], 24, None),
        address(2, [10, 9, 0, 5], 16, Some([10, 9, 0, 5])),
        address(2, [10, 9, 0, 5], 16, None),
        address(7, [10, 0, 0, 2], 32, Some([10, 0, 0, 1])),
    ]
    .concat();
    let result = observations(&links, 41, &addrs, 42).unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(result[0].iface.name, "eth0");
    assert_eq!(
        result[0].iface.ipv4,
        vec![Ipv4Addr::new(10, 9, 0, 5), Ipv4Addr::new(192, 168, 5, 20)]
    );
    assert_eq!(
        result[0].ipv4_prefixes,
        vec![
            Ipv4Prefix {
                address: Ipv4Addr::new(10, 9, 0, 5),
                length: 16
            },
            Ipv4Prefix {
                address: Ipv4Addr::new(192, 168, 5, 20),
                length: 24
            },
        ]
    );
    assert_eq!(result[0].iface.mac, Some([2, 1, 2, 3, 4, 5]));
    assert!(result[0].iface.ethernet && result[0].iface.up);
    assert_eq!(result[1].iface.ipv4, vec![Ipv4Addr::new(10, 0, 0, 1)]);
    assert_eq!(result[1].ipv4_prefixes[0].length, 32);
    assert!(!result[1].iface.ethernet);
    assert_eq!(result[1].iface.mac, None);
    assert!(!result[2].iface.up);
    assert!(result[2].ipv4_prefixes.is_empty());
}

#[test]
fn network_plan_prefix_extremes_are_not_guessed_or_truncated() {
    let links = link(2, "eth0", 1, 1);
    for prefix in [0, 31, 32] {
        let result =
            observations(&links, 41, &address(2, [10, 0, 0, 1], prefix, None), 42).unwrap();
        assert_eq!(result[0].ipv4_prefixes[0].length, prefix);
    }
    assert!(observations(&links, 41, &address(2, [10, 0, 0, 1], 33, None), 42).is_err());
    assert!(observations(&links, 41, &address(99, [10, 0, 0, 1], 24, None), 42).is_err());
}

#[test]
fn network_plan_rejects_truncated_link_and_address_attributes() {
    let links = link(2, "eth0", 1, 1);
    for body in [vec![], vec![0; 7]] {
        assert!(observations(&links, 41, &message(20, 0, 42, &body), 42).is_err());
    }
    let mut body = vec![2, 24, 0, 0, 2, 0, 0, 0];
    body.extend(attr(1, &[10, 0, 1]));
    assert!(observations(&links, 41, &message(20, 0, 42, &body), 42).is_err());
    assert!(observations(&message(16, 0, 41, &[0; 15]), 41, &[], 42).is_err());
}

#[test]
fn network_plan_retry_keeps_absolute_deadline_despite_foreign_replies_or_eintr() {
    let start = Instant::now();
    let now = Cell::new(start);
    let calls = Cell::new(0);
    let result = retry_until::<()>(
        start + Duration::from_millis(125),
        &|| false,
        || now.get(),
        |wait| {
            assert!(wait <= Duration::from_millis(50));
            calls.set(calls.get() + 1);
            now.set(now.get() + wait);
            Ok(None)
        },
    );
    assert!(result.unwrap_err().to_string().contains("deadline"));
    assert_eq!(calls.get(), 3);
    assert_eq!(now.get() - start, Duration::from_millis(125));
}

#[test]
fn network_plan_cancel_or_late_success_is_rejected_after_one_slice() {
    for cancel in [true, false] {
        let start = Instant::now();
        let now = Cell::new(start);
        let cancelled = Cell::new(false);
        let calls = Cell::new(0);
        let result = retry_until(
            start + Duration::from_millis(50),
            &|| cancelled.get(),
            || now.get(),
            |wait| {
                calls.set(calls.get() + 1);
                if cancel {
                    cancelled.set(true);
                } else {
                    now.set(now.get() + wait);
                }
                Ok(Some(42))
            },
        );
        assert!(result.unwrap_err().to_string().contains(if cancel {
            "cancelled"
        } else {
            "deadline"
        }));
        assert_eq!(calls.get(), 1);
    }
}

#[test]
fn network_plan_no_progress_has_a_finite_attempt_budget() {
    let now = Instant::now();
    let calls = Cell::new(0);
    let result = retry_until::<()>(
        now + Duration::from_secs(1),
        &|| false,
        || now,
        |_| {
            calls.set(calls.get() + 1);
            Ok(None)
        },
    );
    assert!(result.unwrap_err().to_string().contains("retry limit"));
    assert_eq!(calls.get(), 4096);
}

struct Fake {
    sends: VecDeque<Result<usize, i32>>,
    datagrams: VecDeque<Result<(Vec<u8>, bool), i32>>,
    readiness: VecDeque<Result<bool, i32>>,
}

impl Fake {
    fn replies(datagrams: Vec<(Vec<u8>, bool)>) -> Self {
        Self {
            sends: VecDeque::new(),
            datagrams: datagrams.into_iter().map(Ok).collect(),
            readiness: VecDeque::new(),
        }
    }
}

impl DatagramIo for Fake {
    fn ready(&mut self, _: bool, wait: Duration) -> Result<bool, i32> {
        assert!(wait <= Duration::from_millis(50));
        self.readiness.pop_front().unwrap_or(Ok(true))
    }
    fn send(&mut self, request: &[u8]) -> Result<usize, i32> {
        assert_eq!(request, b"request");
        self.sends.pop_front().unwrap_or(Ok(request.len()))
    }
    fn recv(&mut self, buffer: &mut [u8]) -> Result<(usize, bool), i32> {
        let (bytes, kernel) = self.datagrams.pop_front().expect("unexpected receive")?;
        let copy = buffer.len().min(bytes.len());
        buffer[..copy].copy_from_slice(&bytes[..copy]);
        Ok((bytes.len(), kernel))
    }
}

fn exchange(io: &mut Fake, dump: bool) -> Result<Vec<u8>, NetError> {
    exchange_until(
        io,
        b"request",
        41,
        dump,
        Instant::now() + Duration::from_secs(1),
        &|| false,
    )
}

#[test]
fn network_plan_exchange_retries_eintr_eagain_and_ignores_foreign_senders_and_sequences() {
    let expected = message(24, 0, 41, &[0; 12]);
    let mut io = Fake::replies(vec![
        (message(24, 0, 41, &[0; 12]), false),
        (message(2, 0, 99, &(-libc::EACCES).to_ne_bytes()), true),
        (expected.clone(), true),
    ]);
    io.sends = [Err(libc::EINTR), Err(libc::EAGAIN), Ok(7)].into();
    io.datagrams.push_front(Err(libc::EAGAIN));
    io.datagrams.push_front(Err(libc::EINTR));
    io.readiness = [Err(libc::EINTR), Ok(false)].into();
    assert_eq!(exchange(&mut io, false).unwrap(), expected);
    assert!(io.datagrams.is_empty());
}

#[test]
fn network_plan_dump_ends_only_on_matching_done_and_keeps_multiple_datagrams() {
    let first = link(2, "eth0", 1, 1);
    let second = link(3, "eth1", 1, 1);
    let done = message(3, 0, 41, &0i32.to_ne_bytes());
    let mut io = Fake::replies(vec![
        (first.clone(), true),
        (message(3, 0, 99, &[]), true),
        (second.clone(), true),
        (done.clone(), true),
    ]);
    assert_eq!(
        exchange(&mut io, true).unwrap(),
        [first, second, done].concat()
    );
}

#[test]
fn network_plan_truncation_interrupted_dump_and_done_error_are_failures() {
    for bytes in [
        vec![0; RECV_BUF + 1],
        vec![],
        message(3, 0x10, 41, &[]),
        message(3, 0, 41, &(-libc::EINTR).to_ne_bytes()),
        message(3, 0, 41, &[1]),
        vec![0; 16],
    ] {
        assert!(exchange(&mut Fake::replies(vec![(bytes, true)]), true).is_err());
    }
}

#[test]
fn network_plan_kernel_no_route_reply_is_preserved_for_route_parser() {
    let bytes = message(2, 0, 41, &(-libc::ENETUNREACH).to_ne_bytes());
    let result = exchange(&mut Fake::replies(vec![(bytes, true)]), false).unwrap();
    assert_eq!(
        parse_netlink_routes(&result),
        Err(NlError::Kernel(libc::ENETUNREACH))
    );
}

#[test]
fn network_plan_short_send_and_socket_failure_are_not_retried() {
    for send in [Ok(2), Err(libc::EBADF)] {
        let mut io = Fake::replies(vec![]);
        io.sends.push_back(send);
        assert!(exchange(&mut io, false).is_err());
    }
}

fn route_response(kind: u8) -> Vec<u8> {
    // RTM_NEWROUTE: AF_INET, /32 destination, main table, static protocol,
    // link scope, specified kernel route kind, no rtm_flags.
    let mut body = vec![2, 32, 0, 0, 254, 4, 253, kind, 0, 0, 0, 0];
    body.extend(attr(1, &[192, 0, 2, 42])); // RTA_DST
    body.extend(attr(4, &2u32.to_ne_bytes())); // RTA_OIF
    body.extend(attr(5, &[192, 0, 2, 1])); // RTA_GATEWAY
    message(24, 0, 41, &body)
}

#[test]
fn network_plan_kernel_custom_broadcast_route_is_not_an_ordinary_destination() {
    // 192.0.2.42 is neither endpoint of 192.0.2.0/24, but Linux may assign
    // it as that interface's custom broadcast. The kernel route kind wins.
    let result = route_reply(&route_response(3), |_| "eth0".into()).unwrap();
    assert_eq!(result, None);
}

#[test]
fn network_plan_kernel_anycast_multicast_and_unknown_route_kinds_are_refused() {
    for kind in (0..=u8::MAX).filter(|kind| !matches!(kind, 1 | 2 | 3)) {
        let result = route_reply(&route_response(kind), |_| "eth0".into()).unwrap();
        assert_eq!(result, None, "unsupported route kind {kind}");
    }
}

#[test]
fn network_plan_kernel_unicast_and_local_route_kinds_retain_their_meaning() {
    for (kind, local, gateway) in [
        (1, false, Some(Ipv4Addr::new(192, 0, 2, 1))),
        (2, true, None),
    ] {
        assert_eq!(
            route_reply(&route_response(kind), |_| "eth0".into()).unwrap(),
            Some(Route {
                ifindex: 2,
                ifname: "eth0".into(),
                gateway,
                local
            })
        );
    }
}
