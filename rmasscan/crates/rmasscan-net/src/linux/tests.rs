//! Поведение через syscall-шов: никаких реальных сокетов.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::NetStats;

const IFINDEX: u32 = 7;

type ScriptedFrame = Result<(Vec<u8>, u8, i32), Errno>;

#[derive(Default)]
struct Script {
    sends: VecDeque<Result<usize, Errno>>,
    /// Если очередь пуста: повторять эту ошибку вечно.
    send_forever: Option<Errno>,
    recvs: VecDeque<ScriptedFrame>,
    recv_forever: Option<Errno>,
    polls: VecDeque<Result<Readiness, Errno>>,
    /// Если очередь пуста: спать запрошенный таймаут и вернуть Timeout.
    stats: VecDeque<Result<KernelStats, Errno>>,
    poll_ms: Vec<i32>,
    send_calls: usize,
    recv_calls: usize,
    poll_calls: usize,
    /// Каждая запрошенная пауза после EINTR.
    backoffs: Vec<Duration>,
}

struct Fake {
    s: Arc<Mutex<Script>>,
    dropped: Arc<AtomicBool>,
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

fn fake(script: Script) -> (Fake, Arc<Mutex<Script>>, Arc<AtomicBool>) {
    let s = Arc::new(Mutex::new(script));
    let dropped = Arc::new(AtomicBool::new(false));
    (
        Fake {
            s: Arc::clone(&s),
            dropped: Arc::clone(&dropped),
        },
        s,
        dropped,
    )
}

impl PacketIo for Fake {
    fn send(&mut self, frame: &[u8]) -> Result<usize, Errno> {
        let mut s = self.s.lock().unwrap();
        s.send_calls += 1;
        let _ = frame;
        match s.sends.pop_front() {
            Some(r) => r,
            None => Err(s.send_forever.expect("unexpected send syscall")),
        }
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<RecvMeta, Errno> {
        let mut s = self.s.lock().unwrap();
        s.recv_calls += 1;
        match s.recvs.pop_front() {
            Some(Ok((data, pkttype, ifindex))) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                // MSG_TRUNC: истинная длина.
                Ok(RecvMeta {
                    len: data.len(),
                    pkttype,
                    ifindex,
                })
            }
            Some(Err(e)) => Err(e),
            None => Err(s.recv_forever.unwrap_or(EAGAIN)),
        }
    }
    fn poll(&mut self, _write: bool, timeout_ms: i32) -> Result<Readiness, Errno> {
        let next = {
            let mut s = self.s.lock().unwrap();
            s.poll_ms.push(timeout_ms);
            s.poll_calls += 1;
            s.polls.pop_front()
        };
        match next {
            Some(r) => r,
            None => {
                std::thread::sleep(Duration::from_millis(timeout_ms as u64));
                Ok(Readiness::Timeout)
            }
        }
    }
    fn backoff(&mut self, wait: Duration) {
        self.s.lock().unwrap().backoffs.push(wait);
        // Часы Deadline реальные: пауза должна двигать время, иначе поток
        // EINTR никогда не дойдёт до дедлайна.
        std::thread::sleep(wait);
    }
    fn packet_stats(&mut self) -> Result<KernelStats, Errno> {
        self.s
            .lock()
            .unwrap()
            .stats
            .pop_front()
            .unwrap_or(Err(libc::ENOPROTOOPT))
    }
}

fn counters() -> Arc<Counters> {
    Arc::new(Counters::default())
}

fn snap(c: &Arc<Counters>) -> NetStats {
    NetStatsHandle::new(Arc::clone(c)).snapshot()
}

fn tx(
    script: Script,
) -> (
    TxHalf<Fake>,
    Arc<Mutex<Script>>,
    Arc<AtomicBool>,
    Arc<Counters>,
) {
    let (f, s, d) = fake(script);
    let c = counters();
    (TxHalf::new(f, Arc::clone(&c)), s, d, c)
}

fn rx(
    script: Script,
) -> (
    RxHalf<Fake>,
    Arc<Mutex<Script>>,
    Arc<AtomicBool>,
    Arc<Counters>,
) {
    let (f, s, d) = fake(script);
    let c = counters();
    (RxHalf::new(f, IFINDEX, Arc::clone(&c)), s, d, c)
}

const FRAME: [u8; 58] = [0xAB; 58];
const MS50: Duration = Duration::from_millis(50);
const SLACK: Duration = Duration::from_millis(40);

// ---------------------------------------------------------------- TX

#[test]
fn tx_full_send_is_sent() {
    let (mut t, _, _, c) = tx(Script {
        sends: [Ok(58)].into(),
        ..Default::default()
    });
    assert_eq!(t.send(&FRAME, MS50), Ok(SendStatus::Sent));
    assert_eq!(snap(&c).tx_sent, 1);
}

#[test]
fn tx_eagain_then_writable_then_sent() {
    let (mut t, s, _, _) = tx(Script {
        sends: [Err(EAGAIN), Ok(58)].into(),
        polls: [Ok(Readiness::Ready)].into(),
        ..Default::default()
    });
    assert_eq!(t.send(&FRAME, MS50), Ok(SendStatus::Sent));
    assert_eq!(s.lock().unwrap().send_calls, 2);
}

#[test]
fn tx_confirmed_eagain_until_deadline_is_would_block_unsent() {
    let (mut t, _, _, c) = tx(Script {
        send_forever: Some(EAGAIN),
        ..Default::default()
    });
    let t0 = Instant::now();
    assert_eq!(
        t.send(&FRAME, Duration::from_millis(20)),
        Ok(SendStatus::WouldBlockUnsent)
    );
    let e = t0.elapsed();
    assert!(
        e >= Duration::from_millis(19) && e < Duration::from_millis(20) + SLACK,
        "{e:?}"
    );
    assert_eq!(snap(&c).tx_would_block, 1);
}

#[test]
fn tx_timeout_is_capped_at_50ms() {
    let (mut t, s, _, _) = tx(Script {
        send_forever: Some(EAGAIN),
        ..Default::default()
    });
    let t0 = Instant::now();
    assert_eq!(
        t.send(&FRAME, Duration::from_secs(10)),
        Ok(SendStatus::WouldBlockUnsent)
    );
    assert!(t0.elapsed() < MS50 + SLACK, "{:?}", t0.elapsed());
    assert!(
        s.lock()
            .unwrap()
            .poll_ms
            .iter()
            .all(|&m| (1..=50).contains(&m))
    );
}

#[test]
fn tx_eintr_flood_does_not_extend_the_deadline() {
    let (mut t, s, _, _) = tx(Script {
        send_forever: Some(EINTR),
        ..Default::default()
    });
    let t0 = Instant::now();
    assert_eq!(
        t.send(&FRAME, Duration::from_millis(15)),
        Ok(SendStatus::WouldBlockUnsent)
    );
    assert!(
        t0.elapsed() < Duration::from_millis(15) + SLACK,
        "{:?}",
        t0.elapsed()
    );
    assert!(s.lock().unwrap().send_calls > 1, "EINTR must be retried");
}

#[test]
fn tx_poll_eintr_flood_does_not_restart_the_deadline() {
    let (mut t, _, _, _) = tx(Script {
        send_forever: Some(EAGAIN),
        polls: std::iter::repeat_n(Err(EINTR), 100_000).collect(),
        ..Default::default()
    });
    let t0 = Instant::now();
    assert_eq!(
        t.send(&FRAME, Duration::from_millis(15)),
        Ok(SendStatus::WouldBlockUnsent)
    );
    assert!(
        t0.elapsed() < Duration::from_millis(15) + SLACK,
        "{:?}",
        t0.elapsed()
    );
}

/// Общие утверждения о бэкоффе: счёт попыток и пауз через шов, не CPU и не
/// верхняя граница wall time. `sleep` не бывает короче запрошенного, поэтому
/// сумма пауз <= таймаут даёт детерминированную верхнюю границу числа повторов.
fn assert_bounded_backoff(s: &Script, attempts: usize, timeout: Duration) {
    assert!(!s.backoffs.is_empty(), "EINTR retries must back off");
    assert!(
        s.backoffs.iter().all(|w| *w <= EINTR_BACKOFF_MAX),
        "{:?}",
        s.backoffs
    );
    let total: Duration = s.backoffs.iter().sum();
    assert!(
        total <= timeout,
        "waits {total:?} exceed deadline {timeout:?}"
    );
    // По одной паузе на повтор: попыток не больше пауз + 1.
    assert!(
        attempts <= s.backoffs.len() + 1,
        "{attempts} vs {}",
        s.backoffs.len()
    );
    // Не менее ~ timeout/1ms пауз нужно для достижения дедлайна, не более
    // timeout/(1 мс) + 1 попыток: busy-spin дал бы миллионы.
    let cap = (timeout.as_millis() as usize) + 2;
    assert!(attempts <= cap, "{attempts} attempts > {cap}");
}

#[test]
fn tx_send_eintr_backs_off_bounded_and_keeps_deadline() {
    let (mut t, s, _, _) = tx(Script {
        send_forever: Some(EINTR),
        ..Default::default()
    });
    let timeout = Duration::from_millis(20);
    assert_eq!(t.send(&FRAME, timeout), Ok(SendStatus::WouldBlockUnsent));
    let s = s.lock().unwrap();
    eprintln!(
        "tx send EINTR: attempts={} waits={}",
        s.send_calls,
        s.backoffs.len()
    );
    assert_bounded_backoff(&s, s.send_calls, timeout);
}

#[test]
fn tx_poll_eintr_backs_off_bounded_and_keeps_deadline() {
    let (mut t, s, _, _) = tx(Script {
        send_forever: Some(EAGAIN),
        polls: std::iter::repeat_n(Err(EINTR), 100_000).collect(),
        ..Default::default()
    });
    let timeout = Duration::from_millis(20);
    assert_eq!(t.send(&FRAME, timeout), Ok(SendStatus::WouldBlockUnsent));
    let s = s.lock().unwrap();
    eprintln!(
        "tx poll EINTR: polls={} waits={}",
        s.poll_calls,
        s.backoffs.len()
    );
    assert_bounded_backoff(&s, s.poll_calls, timeout);
}

#[test]
fn backoff_is_capped_by_the_remaining_deadline() {
    let (mut t, s, _, _) = tx(Script {
        send_forever: Some(EINTR),
        ..Default::default()
    });
    let timeout = Duration::from_micros(300);
    assert_eq!(t.send(&FRAME, timeout), Ok(SendStatus::WouldBlockUnsent));
    let s = s.lock().unwrap();
    let total: Duration = s.backoffs.iter().sum();
    assert!(
        total <= timeout,
        "{total:?} > {timeout:?}: {:?}",
        s.backoffs
    );
    assert!(s.backoffs.iter().all(|w| *w <= timeout));
}

#[test]
fn tx_partial_send_is_uncertain_and_keeps_fd_open() {
    let (mut t, _, dropped, c) = tx(Script {
        sends: [Ok(30), Ok(58)].into(),
        ..Default::default()
    });
    assert_eq!(t.send(&FRAME, MS50), Ok(SendStatus::Uncertain));
    assert_eq!(snap(&c).tx_uncertain, 1);
    assert!(!dropped.load(Ordering::SeqCst));
}

#[test]
fn tx_fatal_error_closes_the_fd_and_later_calls_fail_without_syscalls() {
    let (mut t, s, dropped, c) = tx(Script {
        sends: [Err(libc::ENETDOWN)].into(),
        ..Default::default()
    });
    let e = t.send(&FRAME, MS50).unwrap_err();
    assert!(e.message.contains("send"), "{e}");
    assert!(
        dropped.load(Ordering::SeqCst),
        "fd must be closed after the error"
    );
    assert_eq!(snap(&c).tx_errors, 1);
    let calls = s.lock().unwrap().send_calls;
    assert!(t.send(&FRAME, MS50).is_err());
    assert_eq!(
        s.lock().unwrap().send_calls,
        calls,
        "no syscall after close"
    );
}

#[test]
fn tx_poll_failure_is_fatal() {
    let (mut t, _, dropped, _) = tx(Script {
        sends: [Err(EAGAIN)].into(),
        polls: [Ok(Readiness::Failed)].into(),
        ..Default::default()
    });
    assert!(t.send(&FRAME, MS50).is_err());
    assert!(dropped.load(Ordering::SeqCst));
}

// ---------------------------------------------------------------- RX

fn frame(data: &[u8]) -> ScriptedFrame {
    Ok((data.to_vec(), 0, IFINDEX as i32))
}

#[test]
fn rx_returns_frame_and_counts_it() {
    let (mut r, _, _, c) = rx(Script {
        recvs: [frame(&[1, 2, 3])].into(),
        ..Default::default()
    });
    let mut buf = [0u8; 16];
    assert_eq!(r.recv(&mut buf, MS50), Ok(Some(3)));
    assert_eq!(&buf[..3], &[1, 2, 3]);
    assert_eq!(snap(&c).rx_packets, 1);
}

#[test]
fn rx_empty_times_out_within_the_deadline() {
    let (mut r, s, _, _) = rx(Script::default());
    let mut buf = [0u8; 16];
    let t0 = Instant::now();
    assert_eq!(r.recv(&mut buf, Duration::from_millis(20)), Ok(None));
    let e = t0.elapsed();
    assert!(
        e >= Duration::from_millis(19) && e < Duration::from_millis(20) + SLACK,
        "{e:?}"
    );
    assert!(
        s.lock().unwrap().recv_calls < 50,
        "must sleep in poll, not spin"
    );
}

#[test]
fn rx_timeout_is_capped_at_50ms() {
    let (mut r, _, _, _) = rx(Script::default());
    let mut buf = [0u8; 16];
    let t0 = Instant::now();
    assert_eq!(r.recv(&mut buf, Duration::from_secs(10)), Ok(None));
    assert!(t0.elapsed() < MS50 + SLACK, "{:?}", t0.elapsed());
}

#[test]
fn rx_readiness_without_packet_keeps_waiting_until_deadline() {
    let (mut r, s, _, _) = rx(Script {
        polls: [Ok(Readiness::Ready), Ok(Readiness::Ready)].into(),
        ..Default::default()
    });
    let mut buf = [0u8; 16];
    let t0 = Instant::now();
    assert_eq!(r.recv(&mut buf, Duration::from_millis(20)), Ok(None));
    assert!(t0.elapsed() >= Duration::from_millis(19));
    assert!(s.lock().unwrap().recv_calls >= 3);
}

#[test]
fn rx_readiness_then_packet_is_delivered() {
    let (mut r, _, _, _) = rx(Script {
        recvs: [Err(EAGAIN), frame(&[9])].into(),
        polls: [Ok(Readiness::Ready)].into(),
        ..Default::default()
    });
    let mut buf = [0u8; 4];
    assert_eq!(r.recv(&mut buf, MS50), Ok(Some(1)));
}

#[test]
fn rx_eintr_flood_does_not_restart_the_deadline() {
    let (mut r, _, _, _) = rx(Script {
        recv_forever: Some(EINTR),
        ..Default::default()
    });
    let mut buf = [0u8; 4];
    let t0 = Instant::now();
    assert_eq!(r.recv(&mut buf, Duration::from_millis(15)), Ok(None));
    assert!(
        t0.elapsed() < Duration::from_millis(15) + SLACK,
        "{:?}",
        t0.elapsed()
    );
}

#[test]
fn rx_poll_eintr_flood_does_not_restart_the_deadline() {
    let (mut r, _, _, _) = rx(Script {
        polls: std::iter::repeat_n(Err(EINTR), 100_000).collect(),
        ..Default::default()
    });
    let mut buf = [0u8; 4];
    let t0 = Instant::now();
    assert_eq!(r.recv(&mut buf, Duration::from_millis(15)), Ok(None));
    assert!(
        t0.elapsed() < Duration::from_millis(15) + SLACK,
        "{:?}",
        t0.elapsed()
    );
}

#[test]
fn rx_recv_eintr_backs_off_bounded_and_keeps_deadline() {
    let (mut r, s, _, _) = rx(Script {
        recv_forever: Some(EINTR),
        ..Default::default()
    });
    let timeout = Duration::from_millis(20);
    let mut buf = [0u8; 4];
    assert_eq!(r.recv(&mut buf, timeout), Ok(None));
    let s = s.lock().unwrap();
    eprintln!(
        "rx recv EINTR: attempts={} waits={}",
        s.recv_calls,
        s.backoffs.len()
    );
    assert_bounded_backoff(&s, s.recv_calls, timeout);
}

#[test]
fn rx_poll_eintr_backs_off_bounded_and_keeps_deadline() {
    let (mut r, s, _, _) = rx(Script {
        polls: std::iter::repeat_n(Err(EINTR), 100_000).collect(),
        ..Default::default()
    });
    let timeout = Duration::from_millis(20);
    let mut buf = [0u8; 4];
    assert_eq!(r.recv(&mut buf, timeout), Ok(None));
    let s = s.lock().unwrap();
    eprintln!(
        "rx poll EINTR: polls={} waits={}",
        s.poll_calls,
        s.backoffs.len()
    );
    assert_bounded_backoff(&s, s.poll_calls, timeout);
}

/// Userspace-fallback (ядро без PACKET_IGNORE_OUTGOING): rx_outgoing += 1.
#[test]
fn rx_drops_outgoing_frames() {
    let (mut r, _, _, c) = rx(Script {
        recvs: [
            Ok((vec![1; 10], PACKET_OUTGOING, IFINDEX as i32)),
            frame(&[2, 2]),
        ]
        .into(),
        ..Default::default()
    });
    let mut buf = [0u8; 16];
    assert_eq!(r.recv(&mut buf, MS50), Ok(Some(2)));
    assert_eq!(&buf[..2], &[2, 2]);
    let s = snap(&c);
    assert_eq!((s.rx_outgoing, s.rx_packets), (1, 1));
}

#[test]
fn rx_drops_truncated_frames_and_never_exceeds_the_buffer() {
    let (mut r, _, _, c) = rx(Script {
        recvs: [frame(&[7; 100]), frame(&[1, 2, 3, 4])].into(),
        ..Default::default()
    });
    let mut buf = [0u8; 4];
    // Ровно по размеру буфера это НЕ усечение.
    assert_eq!(r.recv(&mut buf, MS50), Ok(Some(4)));
    assert_eq!(snap(&c).rx_truncated, 1);
    assert_eq!(buf, [1, 2, 3, 4]);
}

#[test]
fn rx_only_truncated_frame_yields_none_not_a_length() {
    let (mut r, _, _, c) = rx(Script {
        recvs: [frame(&[7; 100])].into(),
        ..Default::default()
    });
    let mut buf = [0u8; 8];
    assert_eq!(r.recv(&mut buf, Duration::from_millis(10)), Ok(None));
    assert_eq!(snap(&c).rx_truncated, 1);
}

#[test]
fn rx_drops_frames_of_another_interface() {
    let (mut r, _, _, c) = rx(Script {
        recvs: [Ok((vec![1; 5], 0, IFINDEX as i32 + 1)), frame(&[3])].into(),
        ..Default::default()
    });
    let mut buf = [0u8; 8];
    assert_eq!(r.recv(&mut buf, MS50), Ok(Some(1)));
    assert_eq!(snap(&c).rx_wrong_interface, 1);
}

#[test]
fn rx_flood_of_dropped_frames_cannot_extend_the_deadline() {
    let (mut r, _, _, _) = rx(Script {
        recvs: std::iter::repeat_n(Ok((vec![0; 8], PACKET_OUTGOING, IFINDEX as i32)), 50_000)
            .collect(),
        ..Default::default()
    });
    let mut buf = [0u8; 8];
    let t0 = Instant::now();
    assert!(r.recv(&mut buf, Duration::from_millis(5)).is_ok());
    assert!(t0.elapsed() < Duration::from_millis(5) + SLACK);
}

#[test]
fn rx_fatal_error_closes_fd_and_later_calls_fail() {
    let (mut r, s, dropped, c) = rx(Script {
        recvs: [Err(libc::ENETDOWN)].into(),
        ..Default::default()
    });
    let mut buf = [0u8; 8];
    assert!(r.recv(&mut buf, MS50).is_err());
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(snap(&c).rx_errors, 1);
    let calls = s.lock().unwrap().recv_calls;
    assert!(r.recv(&mut buf, MS50).is_err());
    assert_eq!(s.lock().unwrap().recv_calls, calls);
}

#[test]
fn kernel_drops_accumulate_and_reading_does_not_reset() {
    let (mut r, _, _, c) = rx(Script {
        stats: [
            Ok(KernelStats {
                packets: 5,
                drops: 3,
            }),
            Ok(KernelStats {
                packets: 2,
                drops: 4,
            }),
        ]
        .into(),
        ..Default::default()
    });
    let h = NetStatsHandle::new(Arc::clone(&c));
    assert_eq!(
        h.snapshot().kernel_drops,
        None,
        "unknown before the first read"
    );
    let mut buf = [0u8; 8];
    assert_eq!(r.recv(&mut buf, Duration::from_millis(2)), Ok(None));
    assert_eq!(h.snapshot().kernel_drops, Some(3));
    assert_eq!(
        h.snapshot().kernel_drops,
        Some(3),
        "snapshot must not reset"
    );
    assert_eq!(r.recv(&mut buf, Duration::from_millis(2)), Ok(None));
    assert_eq!(h.snapshot().kernel_drops, Some(7));
}

#[test]
fn kernel_drops_stay_none_when_statistics_are_unavailable() {
    let (mut r, _, _, c) = rx(Script::default());
    let mut buf = [0u8; 8];
    assert_eq!(r.recv(&mut buf, Duration::from_millis(2)), Ok(None));
    assert_eq!(snap(&c).kernel_drops, None);
}

#[test]
fn stats_handle_survives_the_close_and_final_drops_are_collected() {
    let (r, _, dropped, c) = rx(Script {
        stats: [Ok(KernelStats {
            packets: 1,
            drops: 9,
        })]
        .into(),
        ..Default::default()
    });
    let h = NetStatsHandle::new(Arc::clone(&c));
    drop(r);
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(h.snapshot().kernel_drops, Some(9));
    assert_eq!(h.clone().snapshot(), h.snapshot());
}

// ---------------------------------------------------------------- binding

struct FakeIface {
    index: Option<u32>,
    hw: (u16, [u8; 6]),
    queried: Mutex<Vec<&'static str>>,
}

impl FakeIface {
    fn ok() -> Self {
        FakeIface {
            index: Some(IFINDEX),
            hw: (ARPHRD_ETHER, MAC),
            queried: Mutex::new(Vec::new()),
        }
    }
}

impl IfaceInfo for FakeIface {
    fn ifindex(&self, _: &str) -> Result<Option<u32>, Errno> {
        self.queried.lock().unwrap().push("ifindex");
        Ok(self.index)
    }
    fn hw_addr(&self, _: &str) -> Result<(u16, [u8; 6]), Errno> {
        self.queried.lock().unwrap().push("hw");
        Ok(self.hw)
    }
}

const MAC: [u8; 6] = [2, 0xaa, 0, 0, 0, 1];
const IP: u32 = 0x0AC8_0064;

fn binding() -> AdapterBinding {
    AdapterBinding {
        interface_id: "veth-a".into(),
        link_type: LinkType::Ethernet,
        source_ipv4: IP,
        source_mac: MAC,
        next_hop_mac: [2, 0xaa, 0, 0, 0, 2],
        source_ports: (40000, 40000),
    }
}

#[test]
fn binding_matching_the_os_yields_the_ifindex() {
    assert_eq!(verify_binding(&FakeIface::ok(), &binding()), Ok(IFINDEX));
}

#[test]
fn non_ethernet_link_type_is_rejected_before_any_os_query() {
    for lt in [LinkType::Null, LinkType::Raw] {
        let q = FakeIface::ok();
        let mut b = binding();
        b.link_type = lt;
        assert!(matches!(
            verify_binding(&q, &b),
            Err(NetError::UnsupportedLink(_))
        ));
        assert!(q.queried.lock().unwrap().is_empty());
    }
}

#[test]
fn wrong_interface_link_type_is_unsupported_link() {
    let mut q = FakeIface::ok();
    q.hw = (772 /* ARPHRD_LOOPBACK */, [0; 6]);
    assert!(matches!(
        verify_binding(&q, &binding()),
        Err(NetError::UnsupportedLink(_))
    ));
}

#[test]
fn missing_interface_is_a_mismatch() {
    let mut q = FakeIface::ok();
    q.index = None;
    assert!(matches!(
        verify_binding(&q, &binding()),
        Err(NetError::InterfaceMismatch(_))
    ));
}

#[test]
fn source_ip_and_mac_are_not_validated_against_the_os() {
    let q = FakeIface::ok();
    let mut b = binding();
    b.source_ipv4 = 0x0AC8_0064 ^ 0xff;
    b.source_mac = [2, 0xee, 0, 0, 0, 9];
    assert_eq!(verify_binding(&q, &b), Ok(IFINDEX));
}

#[test]
fn hostile_interface_names_never_reach_the_os() {
    for name in [
        "",
        "a b",
        "a/b",
        "..",
        "x\0y",
        "0123456789abcdef",
        "ve;rm -rf",
    ] {
        let q = FakeIface::ok();
        let mut b = binding();
        b.interface_id = name.into();
        let r = verify_binding(&q, &b);
        assert!(matches!(r, Err(NetError::InterfaceMismatch(_))), "{name:?}");
        assert!(q.queried.lock().unwrap().is_empty(), "{name:?}");
    }
}
