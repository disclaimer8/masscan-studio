//! Системные тесты Linux AF_PACKET.
//!
//! Первая группа не создаёт AF_PACKET сокетов (ошибки открытия до сокета) и
//! идёт в обычном `cargo test` на Linux. Вторая группа `#[ignore]`: она
//! открывает НАСТОЯЩИЕ raw-сокеты и запускается только внутри замкнутого
//! стенда (veth между двумя namespace, без uplink), с привилегиями
//! CAP_NET_RAW и параметрами из окружения:
//!
//!   RMASSCAN_LAB_IFACE, RMASSCAN_LAB_IP (a.b.c.d), RMASSCAN_LAB_MAC
//!   (aa:bb:cc:dd:ee:ff), RMASSCAN_LAB_PEER_MAC
//!
//! Если окружение не задано, тест ПАДАЕТ с «NOT RUN», а не проходит молча:
//! пропуск никогда не считается PASS.
#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;
use rmasscan_engine::SendStatus;
use rmasscan_net::{NetError, open_explicit};

fn binding(name: &str) -> AdapterBinding {
    AdapterBinding {
        interface_id: name.into(),
        link_type: LinkType::Ethernet,
        source_ipv4: 0x0A00_0001,
        source_mac: [2, 0, 0, 0, 0, 1],
        next_hop_mac: [2, 0, 0, 0, 0, 2],
        source_ports: (40000, 40000),
    }
}

#[test]
fn missing_interface_is_an_interface_mismatch() {
    let r = open_explicit(&binding("no-such-if0"));
    assert!(
        matches!(r, Err(NetError::InterfaceMismatch(_))),
        "{:?}",
        r.err()
    );
}

#[test]
fn shell_metacharacters_in_the_name_are_rejected_not_executed() {
    let r = open_explicit(&binding("lo;touch /tmp/pwned"));
    assert!(
        matches!(r, Err(NetError::InterfaceMismatch(_))),
        "{:?}",
        r.err()
    );
}

#[test]
fn non_ethernet_binding_is_refused_before_any_socket() {
    for lt in [LinkType::Null, LinkType::Raw] {
        let mut b = binding("lo");
        b.link_type = lt;
        assert!(matches!(
            open_explicit(&b),
            Err(NetError::UnsupportedLink(_))
        ));
    }
}

#[test]
fn loopback_is_not_ethernet() {
    // `lo` существует в любом namespace и имеет ARPHRD_LOOPBACK.
    let r = open_explicit(&binding("lo"));
    assert!(
        matches!(r, Err(NetError::UnsupportedLink(_))),
        "{:?}",
        r.err()
    );
}

// ------------------------------------------------------------ лаборатория

struct Lab {
    iface: String,
    ip: u32,
    mac: [u8; 6],
    peer_mac: [u8; 6],
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        panic!("NOT RUN: {key} is not set; this test only runs inside the sealed lab")
    })
}

fn mac(s: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    let parts: Vec<&str> = s.split(':').collect();
    assert_eq!(parts.len(), 6, "bad MAC {s}");
    for (o, p) in out.iter_mut().zip(parts) {
        *o = u8::from_str_radix(p, 16).expect("hex");
    }
    out
}

fn lab() -> Lab {
    Lab {
        iface: env("RMASSCAN_LAB_IFACE"),
        ip: u32::from(
            env("RMASSCAN_LAB_IP")
                .parse::<std::net::Ipv4Addr>()
                .expect("ip"),
        ),
        mac: mac(&env("RMASSCAN_LAB_MAC")),
        peer_mac: mac(&env("RMASSCAN_LAB_PEER_MAC")),
    }
}

fn lab_binding(l: &Lab) -> AdapterBinding {
    AdapterBinding {
        interface_id: l.iface.clone(),
        link_type: LinkType::Ethernet,
        source_ipv4: l.ip,
        source_mac: l.mac,
        next_hop_mac: l.peer_mac,
        source_ports: (40000, 40000),
    }
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").expect("/proc").count()
}

fn euid() -> u32 {
    let st = std::fs::read_to_string("/proc/self/status").expect("status");
    let line = st
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .expect("Uid line");
    line.split_whitespace()
        .nth(2)
        .expect("euid")
        .parse()
        .expect("num")
}

#[test]
#[ignore = "opens real AF_PACKET sockets: sealed lab only"]
fn lab_empty_rx_times_out_within_the_bound() {
    let l = lab();
    let mut a = open_explicit(&lab_binding(&l)).expect("open");
    let mut buf = [0u8; 2048];
    // Любой фоновый кадр допустим, но каждый вызов обязан уложиться в 50 мс.
    for _ in 0..10 {
        let t0 = Instant::now();
        let r =
            a.io.rx
                .recv(&mut buf, Duration::from_millis(50))
                .expect("recv");
        let e = t0.elapsed();
        assert!(e < Duration::from_millis(100), "recv took {e:?}");
        if r.is_none() {
            assert!(e >= Duration::from_millis(45), "returned early: {e:?}");
            let s = a.stats.snapshot();
            assert!(
                s.kernel_drops.is_some(),
                "PACKET_STATISTICS must be readable"
            );
            return;
        }
    }
    panic!("the quiet lab link never produced an empty timeout");
}

#[test]
#[ignore = "opens real AF_PACKET sockets: sealed lab only"]
fn lab_send_is_confirmed_and_own_frame_never_reaches_rx() {
    let l = lab();
    let mut a = open_explicit(&lab_binding(&l)).expect("open");
    // 60 байт, локальный экспериментальный ethertype 0x88b5: стенд замкнут.
    let mut frame = vec![0u8; 60];
    frame[0..6].copy_from_slice(&l.peer_mac);
    frame[6..12].copy_from_slice(&l.mac);
    frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    let st =
        a.io.tx
            .send(&frame, Duration::from_millis(50))
            .expect("send");
    assert_eq!(st, SendStatus::Sent);
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_millis(300);
    let mut own_frames = 0u32;
    while Instant::now() < deadline {
        if let Some(n) =
            a.io.rx
                .recv(&mut buf, Duration::from_millis(50))
                .expect("recv")
        {
            // Допустим только чужой кадр, но не наш собственный.
            if n == 60 && buf[12..14] == [0x88, 0xb5] && buf[6..12] == l.mac {
                own_frames += 1;
            }
        }
    }
    // Ядро с PACKET_IGNORE_OUTGOING (socket.rs включает его на RX fd) вообще не
    // доставляет наш кадр, поэтому userspace-счётчик rx_outgoing тут не
    // требуется: он 0. Путь userspace-fallback (счётчик += 1) проверяет
    // offline-тест шва `rx_drops_outgoing_frames`.
    assert_eq!(own_frames, 0, "our own outgoing frame reached RX output");
    let s = a.stats.snapshot();
    assert_eq!(s.tx_sent, 1, "send must be confirmed: {s:?}");
    assert_eq!(s.tx_uncertain, 0, "{s:?}");
    assert_eq!(s.tx_errors, 0, "{s:?}");
}

#[test]
#[ignore = "opens real AF_PACKET sockets: sealed lab only"]
fn lab_drop_closes_every_fd_and_stats_outlive_them() {
    let l = lab();
    let before = open_fds();
    let mut handles = Vec::new();
    for _ in 0..25 {
        let a = open_explicit(&lab_binding(&l)).expect("open");
        assert_eq!(open_fds(), before + 2, "one TX and one RX fd while open");
        handles.push(a.stats.clone());
        drop(a);
    }
    assert_eq!(open_fds(), before, "fd leak after drop");
    // Handle не владеет fd и читается после закрытия.
    let _ = handles[0].snapshot();
}

#[test]
#[ignore = "needs an UNPRIVILEGED uid inside the sealed lab"]
fn lab_open_without_privilege_is_permission_denied() {
    assert_ne!(
        euid(),
        0,
        "NOT RUN: this test must run as a non-root user without CAP_NET_RAW"
    );
    let l = lab();
    let r = open_explicit(&lab_binding(&l));
    assert!(
        matches!(r, Err(NetError::PermissionDenied(_))),
        "{:?}",
        r.err()
    );
}

#[test]
#[ignore = "opens real AF_PACKET sockets: sealed lab only"]
fn lab_unassigned_source_ip_and_custom_mac_open_and_send() {
    let l = lab();
    // Как --adapter-ip/--adapter-mac: адрес не назначен интерфейсу, MAC чужой.
    let mut b = lab_binding(&l);
    b.source_ipv4 = u32::from(std::net::Ipv4Addr::new(10, 200, 0, 100));
    b.source_mac = [2, 0xaa, 0, 0, 0, 0x77];
    let mut a = open_explicit(&b).expect("unassigned source IP must open");
    let mut frame = vec![0u8; 60];
    frame[0..6].copy_from_slice(&l.peer_mac);
    frame[6..12].copy_from_slice(&b.source_mac);
    frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    assert_eq!(
        a.io.tx
            .send(&frame, Duration::from_millis(50))
            .expect("send"),
        SendStatus::Sent
    );
    assert_eq!(a.stats.snapshot().tx_sent, 1);
}

#[test]
#[ignore = "opens real AF_PACKET sockets: sealed lab only"]
fn lab_missing_interface_still_mismatches_with_privileges() {
    let l = lab();
    let mut b = lab_binding(&l);
    b.interface_id = "no-such-if0".into();
    assert!(matches!(
        open_explicit(&b),
        Err(NetError::InterfaceMismatch(_))
    ));
}

/// Descriptors of this process that are sockets (`/proc/self/fd/<n>` -> `socket:[inode]`).
fn socket_fds() -> std::collections::BTreeSet<u32> {
    std::fs::read_dir("/proc/self/fd")
        .expect("/proc")
        .filter_map(|e| {
            let e = e.ok()?;
            let fd = e.file_name().to_str()?.parse().ok()?;
            let target = std::fs::read_link(e.path()).ok()?;
            target.to_str()?.starts_with("socket:").then_some(fd)
        })
        .collect()
}

/// The `flags:` field of `/proc/self/fdinfo/<fd>`: octal, with `O_CLOEXEC` when close-on-exec is set.
fn fdinfo_flags(fd: u32) -> i32 {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).expect("fdinfo");
    let flags = info
        .lines()
        .find_map(|l| l.strip_prefix("flags:"))
        .expect("flags line");
    i32::from_str_radix(flags.trim(), 8).expect("octal flags")
}

/// The TX and RX AF_PACKET sockets are nonblocking and close-on-exec. Runs only in the adapter smoke run
/// (`--test-threads=1`), so no other test opens sockets between the two snapshots of `/proc/self/fd`.
#[test]
#[ignore = "opens real AF_PACKET sockets: sealed lab only"]
fn lab_packet_sockets_are_nonblocking_and_cloexec() {
    let l = lab();
    let before = socket_fds();
    let a = open_explicit(&lab_binding(&l)).expect("open");
    let new: Vec<u32> = socket_fds().difference(&before).copied().collect();
    assert!(new.len() >= 2, "the TX and RX sockets: {new:?}");
    for fd in new {
        let flags = fdinfo_flags(fd);
        assert_ne!(flags & libc::O_NONBLOCK, 0, "fd {fd}: flags {flags:o}");
        assert_ne!(flags & libc::O_CLOEXEC, 0, "fd {fd}: flags {flags:o}");
    }
    drop(a);
}

/// One `c_int` socket option of descriptor `fd` of this process (`getsockopt`).
fn int_sockopt(fd: u32, level: libc::c_int, name: libc::c_int) -> libc::c_int {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `value` and `len` are live locals and `len` holds the size of `value`, so the kernel writes at most that
    // many bytes; `fd` belongs to the adapter the caller holds open.
    let rc = unsafe {
        libc::getsockopt(
            fd as libc::c_int,
            level,
            name,
            (&raw mut value).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    assert_eq!(
        rc,
        0,
        "getsockopt(fd {fd}): {}",
        std::io::Error::last_os_error()
    );
    value
}

/// `sll_protocol` (host order) of the bound AF_PACKET socket `fd` (`getsockname`); `None` for another family.
fn packet_protocol(fd: u32) -> Option<u16> {
    // SAFETY: sockaddr_ll consists of integers and a byte array; the all-zero image is valid.
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
    // SAFETY: `sll` and `len` are live locals and `len` holds the size of `sll`, so the kernel writes at most that many
    // bytes; `fd` belongs to the adapter the caller holds open.
    let rc = unsafe {
        libc::getsockname(
            fd as libc::c_int,
            (&raw mut sll).cast::<libc::sockaddr>(),
            &raw mut len,
        )
    };
    assert_eq!(
        rc,
        0,
        "getsockname(fd {fd}): {}",
        std::io::Error::last_os_error()
    );
    (sll.sll_family == libc::AF_PACKET as u16).then(|| u16::from_be(sll.sll_protocol))
}

/// Opens the lab adapter and finds its two new AF_PACKET descriptors: RX (bound to ETH_P_ALL) and TX (bound to
/// protocol 0), each exactly once. Finding them by a `/proc/self/fd` diff needs the adapter smoke run
/// (`--test-threads=1`): no other test opens sockets between the two snapshots.
fn open_and_find_rx_tx(l: &Lab) -> (rmasscan_net::OpenedAdapter, u32, u32) {
    let before = socket_fds();
    let a = open_explicit(&lab_binding(l)).expect("open");
    let new: Vec<(u32, Option<u16>)> = socket_fds()
        .difference(&before)
        .map(|&fd| (fd, packet_protocol(fd)))
        .collect();
    let only = |protocol: u16| {
        let fds: Vec<u32> = new
            .iter()
            .filter(|(_, p)| *p == Some(protocol))
            .map(|(fd, _)| *fd)
            .collect();
        assert_eq!(
            fds.len(),
            1,
            "AF_PACKET sockets of protocol {protocol:#06x}: {new:?}"
        );
        fds[0]
    };
    let (rx, tx) = (only(libc::ETH_P_ALL as u16), only(0));
    (a, rx, tx)
}

/// A `net.core` sysctl of the host as an integer.
fn net_core(name: &str) -> i64 {
    std::fs::read_to_string(format!("/proc/sys/net/core/{name}"))
        .unwrap_or_else(|e| panic!("{name}: {e}"))
        .trim()
        .parse()
        .expect("number")
}

/// P3 (user decision): the TX socket asks for a 4 MiB send buffer with plain `SO_SNDBUF`, so the kernel clamps the
/// request to `net.core.wmem_max` and stores double the clamped value; the RX socket keeps `net.core.wmem_default`.
/// The expectation is computed from this host's `wmem_max`, never hard-coded.
#[test]
#[ignore = "opens real AF_PACKET sockets: sealed lab only"]
fn lab_tx_socket_send_buffer_is_raised() {
    let l = lab();
    let (a, rx, tx) = open_and_find_rx_tx(&l);
    let tx_buf = i64::from(int_sockopt(tx, libc::SOL_SOCKET, libc::SO_SNDBUF));
    let rx_buf = i64::from(int_sockopt(rx, libc::SOL_SOCKET, libc::SO_SNDBUF));
    let (max, default) = (net_core("wmem_max"), net_core("wmem_default"));
    let granted = 2 * max.min(4 << 20);
    eprintln!(
        "TX SO_SNDBUF {tx_buf}, RX SO_SNDBUF {rx_buf}, wmem_max {max}, wmem_default {default}"
    );
    assert!(
        tx_buf >= granted,
        "TX SO_SNDBUF {tx_buf} is below what a 4 MiB request gets here ({granted})"
    );
    assert_eq!(rx_buf, default, "the RX socket keeps wmem_default");
    drop(a);
}

/// P3 (user decision): the TX socket sends past the interface qdisc (`PACKET_QDISC_BYPASS` reads back 1); the RX
/// socket, which never sends, keeps the default (0).
#[test]
#[ignore = "opens real AF_PACKET sockets: sealed lab only"]
fn lab_tx_socket_bypasses_the_qdisc() {
    let l = lab();
    let (a, rx, tx) = open_and_find_rx_tx(&l);
    let tx_bypass = int_sockopt(tx, libc::SOL_PACKET, libc::PACKET_QDISC_BYPASS);
    let rx_bypass = int_sockopt(rx, libc::SOL_PACKET, libc::PACKET_QDISC_BYPASS);
    eprintln!("TX PACKET_QDISC_BYPASS {tx_bypass}, RX PACKET_QDISC_BYPASS {rx_bypass}");
    assert_eq!(tx_bypass, 1, "the TX socket bypasses the qdisc");
    assert_eq!(rx_bypass, 0, "the RX socket keeps the qdisc path");
    drop(a);
}

/// P5: the RX socket (bound to ETH_P_ALL) asks for a 4 MiB receive buffer (`SO_RCVBUFFORCE`, without CAP_NET_ADMIN
/// `SO_RCVBUF`), and the kernel reports double what it stored; the TX socket (bound to protocol 0) keeps
/// `net.core.rmem_default`. The two sockets are found as in `lab_packet_sockets_are_nonblocking_and_cloexec`, so this
/// test too runs only in the adapter smoke run (`--test-threads=1`).
#[test]
#[ignore = "opens real AF_PACKET sockets: sealed lab only"]
fn lab_rx_socket_buffer_is_raised() {
    let l = lab();
    let (a, rx, tx) = open_and_find_rx_tx(&l);
    let rx_buf = int_sockopt(rx, libc::SOL_SOCKET, libc::SO_RCVBUF);
    let tx_buf = int_sockopt(tx, libc::SOL_SOCKET, libc::SO_RCVBUF);
    let default: libc::c_int = std::fs::read_to_string("/proc/sys/net/core/rmem_default")
        .expect("rmem_default")
        .trim()
        .parse()
        .expect("number");
    eprintln!("RX SO_RCVBUF {rx_buf}, TX SO_RCVBUF {tx_buf}, rmem_default {default}");
    assert!(rx_buf >= 4 << 20, "RX SO_RCVBUF {rx_buf} is below 4 MiB");
    assert_eq!(tx_buf, default, "the TX socket keeps rmem_default");
    drop(a);
}
