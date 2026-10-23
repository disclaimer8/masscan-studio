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
fn lab_send_is_sent_and_own_frame_is_dropped_as_outgoing() {
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
    while Instant::now() < deadline {
        if let Some(n) =
            a.io.rx
                .recv(&mut buf, Duration::from_millis(50))
                .expect("recv")
        {
            // Допустим только чужой кадр, но не наш собственный.
            assert!(!(n == 60 && buf[12..14] == [0x88, 0xb5] && buf[6..12] == l.mac));
        }
    }
    let s = a.stats.snapshot();
    assert_eq!(s.tx_sent, 1);
    assert!(
        s.rx_outgoing >= 1,
        "PACKET_OUTGOING copy must be counted and dropped: {s:?}"
    );
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
