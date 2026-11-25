//! Route/interface observations only: no packet adapters and no network mutation.
use super::*;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[test]
fn network_plan_route_rejects_cancelled_or_expired_observation() {
    for cancelled in [true, false] {
        let result = OsRoutes.lookup_until(
            Ipv4Addr::LOCALHOST,
            if cancelled {
                Instant::now() + Duration::from_secs(1)
            } else {
                Instant::now()
            },
            &|| cancelled,
        );
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains(if cancelled { "cancelled" } else { "deadline" }),
            "{error}"
        );
    }
}

#[test]
fn network_plan_interfaces_reject_cancelled_or_expired_observation() {
    for cancelled in [true, false] {
        let result = OsIfaces.observe(
            if cancelled {
                Instant::now() + Duration::from_secs(1)
            } else {
                Instant::now()
            },
            &|| cancelled,
        );
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains(if cancelled { "cancelled" } else { "deadline" }),
            "{error}"
        );
    }
}

#[test]
fn network_plan_read_only_kernel_loopback_observations() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let route = OsRoutes
        .lookup_until(Ipv4Addr::LOCALHOST, deadline, &|| false)
        .unwrap()
        .expect("Linux always has the loopback route");
    assert!(route.local);
    let interfaces = OsIfaces.observe(deadline, &|| false).unwrap();
    let loopback = interfaces
        .iter()
        .find(|i| i.iface.index == route.ifindex)
        .unwrap();
    assert!(loopback.iface.ipv4.contains(&Ipv4Addr::LOCALHOST));
    assert!(
        loopback
            .ipv4_prefixes
            .contains(&crate::network_plan::Ipv4Prefix {
                address: Ipv4Addr::LOCALHOST,
                length: 8,
            })
    );
    assert!(!loopback.iface.ethernet);
}

#[test]
fn netlink_sockets_keep_their_flags() {
    use std::os::fd::AsFd;
    let netlink = NlSocket::open("socket(NETLINK_ROUTE)", false).unwrap();
    let (status, cloexec) = crate::unix_fd_tests::fd_flags(netlink.0.as_fd());
    assert!(cloexec, "the blocking NlSocket::open must set FD_CLOEXEC");
    assert_eq!(
        status & libc::O_NONBLOCK,
        0,
        "the blocking NlSocket::open must block"
    );
    let ioctl = IfSock::open().unwrap();
    let (status, cloexec) = crate::unix_fd_tests::fd_flags(ioctl.0.as_fd());
    assert!(cloexec, "IfSock::open must set FD_CLOEXEC");
    assert_eq!(status & libc::O_NONBLOCK, 0, "IfSock::open must block");
}

/// `SO_RCVTIMEO` сокета: 1 с у блокирующего (старый обмен), нет у неблокирующего (наблюдение).
#[test]
fn netlink_receive_timeout_is_one_second_only_when_blocking() {
    let timeout = |nonblocking: bool| {
        let socket = NlSocket::open("socket(NETLINK_ROUTE)", nonblocking).unwrap();
        let mut tv = libc::timeval {
            tv_sec: -1,
            tv_usec: -1,
        };
        let mut len = socklen_of::<libc::timeval>();
        // SAFETY: указатель и длина описывают живой локальный `tv`; fd принадлежит живому `socket`.
        let rc = unsafe {
            libc::getsockopt(
                socket.0.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw mut tv).cast::<libc::c_void>(),
                &raw mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt(SO_RCVTIMEO)");
        (tv.tv_sec, tv.tv_usec)
    };
    assert_eq!(timeout(false), (1, 0));
    assert_eq!(timeout(true), (0, 0));
}

/// Синтетический обмен старой политики: отправки и датаграммы по очереди; отправка без очереди проходит целиком.
struct FakeNl {
    sends: VecDeque<Result<usize, Errno>>,
    replies: VecDeque<Result<(Vec<u8>, u32), Errno>>,
}

impl FakeNl {
    fn new(replies: Vec<Result<(Vec<u8>, u32), Errno>>) -> Self {
        Self {
            sends: VecDeque::new(),
            replies: replies.into(),
        }
    }
}

impl BlockingNl for FakeNl {
    fn send(&mut self, req: &[u8]) -> Result<usize, Errno> {
        self.sends.pop_front().unwrap_or(Ok(req.len()))
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, u32), Errno> {
        let (bytes, pid) = self.replies.pop_front().expect("unexpected receive")?;
        let copy = buf.len().min(bytes.len());
        buf[..copy].copy_from_slice(&bytes[..copy]);
        Ok((bytes.len(), pid))
    }
}

/// Текст errno `e` таблицей ОС хоста, как его печатает `sys`.
fn os(e: i32) -> String {
    std::io::Error::from_raw_os_error(e).to_string()
}

/// Тексты, предикат отправителя и повтор `EINTR` старого (блокирующего) обмена; литералы с базы (`linux/route.rs`
/// `Netlink::send`/`Netlink::recv`/`exchange_with`, `bace6944`), не из нового кода.
#[test]
fn legacy_netlink_texts_are_byte_identical() {
    let lookup = |nl: &mut FakeNl| exchange_on(nl, b"request", false, parse_netlink_routes);
    let dump = |nl: &mut FakeNl| exchange_on(nl, b"request", true, parse_netlink_routes);
    let text = |r: Result<Vec<NlRoute>, Failure>| match r {
        Ok(v) => panic!("expected a failure, got {v:?}"),
        Err(f) => NetError::from(f).to_string(),
    };

    let mut nl = FakeNl::new(vec![]);
    nl.sends.push_back(Ok(2));
    assert_eq!(text(lookup(&mut nl)), "system error: netlink: short send");
    let mut nl = FakeNl::new(vec![]);
    nl.sends.push_back(Err(libc::EBADF));
    assert_eq!(
        text(lookup(&mut nl)),
        format!("system error: sendto(NETLINK_ROUTE): {}", os(libc::EBADF))
    );
    // EAGAIN после SO_RCVTIMEO это «нет ответа за 1 с».
    let mut nl = FakeNl::new(vec![Err(libc::EAGAIN)]);
    assert_eq!(
        text(lookup(&mut nl)),
        "system error: netlink: no reply within 1 s"
    );
    let mut nl = FakeNl::new(vec![Err(libc::EBADF)]);
    assert_eq!(
        text(lookup(&mut nl)),
        format!("system error: recvfrom(NETLINK_ROUTE): {}", os(libc::EBADF))
    );
    // Усечение проверяется раньше отправителя: усечённая датаграмма чужого отправителя тоже ошибка.
    for pid in [0, 4242] {
        let mut nl = FakeNl::new(vec![Ok((vec![0; RECV_BUF + 1], pid))]);
        assert_eq!(
            text(lookup(&mut nl)),
            "system error: netlink: reply of 65537 bytes truncated"
        );
    }
    // Dump без NLMSG_DONE: ровно 4096 датаграмм, затем отказ.
    let mut nl = FakeNl::new(vec![Ok((Vec::new(), 0)); 4096]);
    assert_eq!(
        text(dump(&mut nl)),
        "system error: netlink: dump did not end within 4096 datagrams"
    );
    assert!(nl.replies.is_empty());

    // Чужой отправитель (`nl_pid` ≠ 0) пропускается, EINTR повторяется и у отправки, и у приёма.
    let route = crate::route_parse::nl_message(
        crate::route_parse::RTM_NEWROUTE,
        0,
        1,
        &[2, 32, 0, 0, 254, 4, 253, 1, 0, 0, 0, 0],
    );
    assert_eq!(parse_netlink_routes(&route).map(|r| r.len()), Ok(1));
    let mut nl = FakeNl::new(vec![
        Err(libc::EINTR),
        Ok((route.clone(), 4242)),
        Ok((Vec::new(), 0)),
    ]);
    nl.sends = [Err(libc::EINTR), Ok(7)].into();
    assert!(lookup(&mut nl).is_ok_and(|r| r.is_empty()));
    assert!(nl.replies.is_empty() && nl.sends.is_empty());
    let mut nl = FakeNl::new(vec![Ok((route, 0))]);
    assert!(lookup(&mut nl).is_ok_and(|r| r.len() == 1));
}
