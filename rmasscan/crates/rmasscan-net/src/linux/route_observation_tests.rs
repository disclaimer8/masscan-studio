use super::*;
use crate::route_parse::{NLMSG_HDRLEN, RTM_NEWLINK};
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

#[test]
fn observation_socket_keeps_its_flags() {
    use std::os::fd::AsFd;
    let socket = NlSocket::open("socket(NETLINK_ROUTE observation)", true).unwrap();
    let (status, cloexec) = crate::unix_fd_tests::fd_flags(socket.0.as_fd());
    assert!(cloexec, "the observation socket sets FD_CLOEXEC");
    assert_ne!(
        status & libc::O_NONBLOCK,
        0,
        "the observation socket sets O_NONBLOCK"
    );
}

/// The text of errno `e` in the table of the host OS, as `sys` prints it.
fn os(e: i32) -> String {
    std::io::Error::from_raw_os_error(e).to_string()
}

#[test]
fn error_texts_are_byte_identical() {
    let text = |io: &mut Fake, dump: bool| exchange(io, dump).unwrap_err().to_string();
    let mut io = Fake::replies(vec![]);
    io.sends.push_back(Ok(2));
    assert_eq!(
        text(&mut io, false),
        "system error: netlink observation: short send"
    );
    let mut io = Fake::replies(vec![(vec![], true)]);
    assert_eq!(
        text(&mut io, true),
        "system error: netlink observation: malformed empty or truncated datagram"
    );
    let mut io = Fake::replies(vec![(message(3, 0x10, 41, &[]), true)]);
    assert_eq!(
        text(&mut io, true),
        "system error: netlink observation: interrupted dump"
    );
    // 129 full datagrams of one link message each pass the 8 MiB reply limit.
    let full = message(RTM_NEWLINK, 0, 41, &vec![0; RECV_BUF - NLMSG_HDRLEN]);
    assert_eq!(full.len(), RECV_BUF);
    let mut io = Fake::replies(vec![(full, true); MAX_REPLY_BYTES / RECV_BUF + 1]);
    assert_eq!(
        text(&mut io, true),
        "system error: netlink observation reply limit exceeded"
    );
    let mut io = Fake::replies(vec![]);
    io.sends.push_back(Err(libc::EBADF));
    assert_eq!(
        text(&mut io, false),
        format!(
            "system error: sendto(NETLINK_ROUTE observation): {}",
            os(libc::EBADF)
        )
    );
    let mut io = Fake::replies(vec![]);
    io.datagrams.push_back(Err(libc::EBADF));
    assert_eq!(
        text(&mut io, false),
        format!(
            "system error: recvfrom(NETLINK_ROUTE observation): {}",
            os(libc::EBADF)
        )
    );
    let mut io = Fake::replies(vec![]);
    io.readiness = [Err(libc::EBADF)].into();
    assert_eq!(
        text(&mut io, false),
        format!(
            "system error: poll(NETLINK_ROUTE write): {}",
            os(libc::EBADF)
        )
    );
    let mut io = Fake::replies(vec![]);
    io.readiness = [Ok(true), Err(libc::EBADF)].into();
    assert_eq!(
        text(&mut io, false),
        format!(
            "system error: poll(NETLINK_ROUTE read): {}",
            os(libc::EBADF)
        )
    );

    // retry_until on a virtual clock: cancellation, deadline, attempt budget.
    let now = Instant::now();
    let retry = |deadline: Instant, cancelled: bool| {
        retry_until::<()>(deadline, &|| cancelled, || now, |_| Ok(None))
            .unwrap_err()
            .to_string()
    };
    assert_eq!(
        retry(now + Duration::from_secs(1), true),
        "system error: network preparation cancelled"
    );
    assert_eq!(
        retry(now, false),
        "system error: network observation deadline expired"
    );
    assert_eq!(
        retry(now + Duration::from_secs(1), false),
        "system error: netlink observation retry limit exceeded"
    );
}
