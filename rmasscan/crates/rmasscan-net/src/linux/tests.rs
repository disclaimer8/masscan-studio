//! Поведение через syscall-шов: никаких реальных сокетов (кроме проверки флагов сокета ioctl, она только на Linux).
//! Тесты идут на любой ОС: errno это номера Linux из `abi`, ожидаемый текст errno строится той же функцией хоста
//! (`os`), а нижние границы времени проверяются только на Linux.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::abi::errno::{EACCES, EBADF, EIO, ENETDOWN, ENODEV, ENOPROTOOPT, ENXIO, EPERM, EPROTO};
use super::*;
use crate::NetStats;

const IFINDEX: u32 = 7;

/// Запись очереди сокета: кадр `(данные, pkttype, ifindex)` или errno. `Err(EPROTO)` — запись с адресом короче
/// `SLL_MIN_LEN`: настоящий сокет отдаёт её прямым `recv` как `Err(EPROTO)`, а внутри пачки `recv_batch` — как слот
/// `Err(EPROTO)`, пачку она не прерывает. Любой другой errno — ошибка вызова.
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
    /// Все вызовы приёма: прямые `recv` и пачки `recv_batch`.
    recv_calls: usize,
    /// Из них пачки `recv_batch`.
    batch_calls: usize,
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
    /// Пачка: подряд записи очереди (кадры и записи с коротким адресом) до первой ошибки или `batch_len`; ошибка в
    /// голове очереди — `Err`, как у `recvmmsg`, который отдаёт принятый префикс, а ошибку — следующим вызовом.
    fn recv_batch(
        &mut self,
        slots: &mut [[u8; RX_SLOT]],
        metas: &mut [SlotMeta],
    ) -> Result<usize, Errno> {
        let n = batch_len(slots.len(), metas.len())?;
        let mut s = self.s.lock().unwrap();
        s.recv_calls += 1;
        s.batch_calls += 1;
        let mut got = 0;
        while got < n {
            let meta = match s.recvs.front() {
                Some(Ok((data, pkttype, ifindex))) => {
                    // Слот держит не больше RX_SLOT байт; MSG_TRUNC: истинная длина.
                    let k = data.len().min(RX_SLOT);
                    slots[got][..k].copy_from_slice(&data[..k]);
                    Ok(RecvMeta {
                        len: data.len(),
                        pkttype: *pkttype,
                        ifindex: *ifindex,
                    })
                }
                Some(Err(EPROTO)) => Err(EPROTO),
                _ => break,
            };
            s.recvs.pop_front();
            metas[got] = meta;
            got += 1;
        }
        if got > 0 {
            return Ok(got);
        }
        match s.recvs.pop_front() {
            Some(Err(e)) => Err(e),
            Some(Ok(_)) => unreachable!("frames are taken into the batch above"),
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
            .unwrap_or(Err(ENOPROTOOPT))
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
    // Нижняя граница времени проверяется только на Linux, верхняя на любой ОС.
    #[cfg(target_os = "linux")]
    assert!(e >= Duration::from_millis(19), "{e:?}");
    assert!(e < Duration::from_millis(20) + SLACK, "{e:?}");
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
        sends: [Err(ENETDOWN)].into(),
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
    #[cfg(target_os = "linux")]
    assert!(e >= Duration::from_millis(19), "{e:?}");
    assert!(e < Duration::from_millis(20) + SLACK, "{e:?}");
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
    #[cfg(target_os = "linux")]
    let t0 = Instant::now();
    assert_eq!(r.recv(&mut buf, Duration::from_millis(20)), Ok(None));
    #[cfg(target_os = "linux")]
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
        recvs: [Err(ENETDOWN)].into(),
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
        stats: [Ok(KernelStats { drops: 3 }), Ok(KernelStats { drops: 4 })].into(),
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
        stats: [Ok(KernelStats { drops: 9 })].into(),
        ..Default::default()
    });
    let h = NetStatsHandle::new(Arc::clone(&c));
    drop(r);
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(h.snapshot().kernel_drops, Some(9));
    assert_eq!(h.clone().snapshot(), h.snapshot());
}

// ------------------------------------------------------------ rx health

fn ks(drops: u32) -> Result<KernelStats, Errno> {
    Ok(KernelStats { drops })
}

#[test]
fn health_reports_cumulative_drops_from_resetting_deltas() {
    let (mut r, _, _, c) = rx(Script {
        stats: [ks(2), ks(0), ks(3)].into(),
        ..Default::default()
    });
    let t = Instant::now();
    assert_eq!(r.health(MS50).unwrap().kernel_drops, Some(2));
    assert_eq!(r.health(MS50).unwrap().kernel_drops, Some(2));
    assert_eq!(r.health(MS50).unwrap().kernel_drops, Some(5));
    assert!(t.elapsed() < MS50, "health must respect the call limit");
    assert_eq!(snap(&c).kernel_drops, Some(5));
}

#[test]
fn health_error_never_returns_a_cached_zero() {
    let (mut r, _, _, c) = rx(Script {
        stats: [ks(0), Err(ENOPROTOOPT)].into(),
        ..Default::default()
    });
    assert_eq!(r.health(MS50).unwrap().kernel_drops, Some(0));
    let e = r
        .health(MS50)
        .expect_err("last read failed: no cached Some(0)");
    assert!(e.message.contains("PACKET_STATISTICS"), "{}", e.message);
    // Неудачное чтение ядро не сбрасывает: накопленное не потеряно.
    assert_eq!(snap(&c).kernel_drops, Some(0));
}

#[test]
fn health_error_after_a_good_periodic_flush_is_still_an_error() {
    let (mut r, _, _, _) = rx(Script {
        stats: [ks(4), Err(EIO)].into(),
        ..Default::default()
    });
    let mut buf = [0u8; 8];
    assert_eq!(r.recv(&mut buf, Duration::from_millis(2)), Ok(None)); // flush: 4
    assert!(r.health(MS50).is_err());
}

#[test]
fn periodic_flush_health_and_drop_have_one_owner_without_double_counting() {
    let (mut r, _, _, c) = rx(Script {
        stats: [ks(3), ks(0), ks(0)].into(),
        ..Default::default()
    });
    let mut buf = [0u8; 8];
    assert_eq!(r.recv(&mut buf, Duration::from_millis(2)), Ok(None)); // +3
    assert_eq!(r.health(MS50).unwrap().kernel_drops, Some(3), "not 6");
    drop(r); // Drop читает ещё раз: delta 0, итог не меняется
    assert_eq!(snap(&c).kernel_drops, Some(3));
}

#[test]
fn drop_after_health_with_failing_read_keeps_the_total() {
    let (mut r, _, _, c) = rx(Script {
        stats: [ks(4)].into(),
        ..Default::default()
    });
    assert_eq!(r.health(MS50).unwrap().kernel_drops, Some(4));
    drop(r); // чтение в Drop падает (очередь пуста): ничего не стирается
    assert_eq!(snap(&c).kernel_drops, Some(4));
}

#[test]
fn health_after_fatal_error_reports_the_closed_adapter() {
    let (mut r, _, _, _) = rx(Script {
        recv_forever: Some(EIO),
        stats: [ks(1)].into(),
        ..Default::default()
    });
    let mut buf = [0u8; 8];
    assert!(r.recv(&mut buf, MS50).is_err());
    assert!(r.health(MS50).is_err(), "closed fd cannot prove integrity");
}

// ---------------------------------------------------------------- RX batch (recvmmsg)

#[test]
fn batch_len_never_asks_for_more_slots_than_fit() {
    assert_eq!((RX_BATCH, RX_SLOT), (32, 2048));
    assert_eq!(batch_len(0, RX_BATCH), Err(EINVAL));
    assert_eq!(batch_len(RX_BATCH, 0), Err(EINVAL));
    assert_eq!(batch_len(0, 0), Err(EINVAL));
    assert_eq!(batch_len(1, 1), Ok(1));
    assert_eq!(batch_len(3, 10), Ok(3));
    assert_eq!(batch_len(10, 3), Ok(3));
    assert_eq!(batch_len(RX_BATCH, RX_BATCH), Ok(RX_BATCH));
    assert_eq!(batch_len(RX_BATCH + 1, 100), Ok(RX_BATCH));
    assert_eq!(batch_len(usize::MAX, usize::MAX), Ok(RX_BATCH));
    // The seam refuses an empty batch before it receives anything.
    let (mut f, s, _) = fake(Script {
        recvs: [frame(&[1])].into(),
        ..Default::default()
    });
    let mut slots = [[0u8; RX_SLOT]; 2];
    let mut metas = [Err(EAGAIN); RX_BATCH];
    assert_eq!(f.recv_batch(&mut [], &mut metas), Err(EINVAL));
    assert_eq!(f.recv_batch(&mut slots, &mut []), Err(EINVAL));
    let s = s.lock().unwrap();
    assert_eq!((s.recv_calls, s.recvs.len()), (0, 1), "nothing received");
}

#[test]
fn rx_batch_delivers_buffered_frames_without_a_syscall() {
    let (mut r, s, _, c) = rx(Script {
        recvs: [frame(&[1]), frame(&[2, 2]), frame(&[3, 3, 3])].into(),
        ..Default::default()
    });
    let mut buf = [0u8; RX_SLOT];
    assert_eq!(r.recv(&mut buf, MS50), Ok(Some(1)));
    assert_eq!(buf[0], 1);
    {
        let s = s.lock().unwrap();
        assert_eq!((s.recv_calls, s.batch_calls, s.poll_calls), (1, 1, 0));
        assert!(s.recvs.is_empty(), "one batch took the whole burst");
    }
    assert_eq!(r.recv(&mut buf, MS50), Ok(Some(2)));
    assert_eq!(&buf[..2], &[2, 2]);
    assert_eq!(r.recv(&mut buf, MS50), Ok(Some(3)));
    assert_eq!(&buf[..3], &[3, 3, 3]);
    {
        let s = s.lock().unwrap();
        assert_eq!(
            (s.recv_calls, s.batch_calls, s.poll_calls),
            (1, 1, 0),
            "buffered frames need no syscall"
        );
    }
    assert_eq!(snap(&c).rx_packets, 3);
}

/// `rx_packets`, `rx_outgoing`, `rx_wrong_interface`, `rx_truncated`, `rx_errors`.
fn rx_counts(c: &Arc<Counters>) -> [u64; 5] {
    let s = snap(c);
    [
        s.rx_packets,
        s.rx_outgoing,
        s.rx_wrong_interface,
        s.rx_truncated,
        s.rx_errors,
    ]
}

/// Review Focus 1. Each scenario puts records of every kind into one batch: our own outgoing frame (a kernel without
/// `PACKET_IGNORE_OUTGOING`), a frame of another ifindex, a frame longer than the caller's buffer, ordinary frames, a
/// record with a short address (`EPROTO`), and a non-EAGAIN error after the received prefix.
///
/// The expectations below (frames in order, the five counters after each call, the `recvfrom: …` error on its call)
/// were taken from the SAME scenarios on the base `5b0e9712`, where `RxHalf` called the per-frame `recv` of this fake
/// once per record: a temporary probe test printed each call's result and counters and was then removed (its diff
/// and log are with the task-13 evidence). Only the number of receive calls differs, by design, and is asserted
/// separately: the base made one call per record.
#[test]
fn rx_batch_mixed_records_match_the_per_frame_path() {
    let outgoing = |b: u8| Ok((vec![b; 10], PACKET_OUTGOING, IFINDEX as i32));
    let foreign = |b: u8| Ok((vec![b; 10], 0, IFINDEX as i32 + 1));
    let long = |b: u8| Ok((vec![b; 100], 0, IFINDEX as i32));
    let closed = || Err(CLOSED.to_string());
    let proto = || Err(format!("recvfrom: {}", os(EPROTO)));
    // (script, per call: frame or error text and the counters after it, batch calls, records left unread)
    type Calls = Vec<(Result<Vec<u8>, String>, [u64; 5])>;
    let cases: Vec<(&str, Vec<ScriptedFrame>, Calls, usize, usize)> = vec![
        (
            // The short-address record is fatal on its own call; the frame behind it and the error are never
            // delivered (they were in the batch or behind it, as they were in the socket queue on the base).
            "short address",
            vec![
                outgoing(1),
                foreign(2),
                long(3),
                frame(&[4, 4, 4]),
                Err(EPROTO),
                frame(&[5, 5]),
                Err(ENETDOWN),
            ],
            vec![
                (Ok(vec![4, 4, 4]), [1, 1, 1, 1, 0]),
                (proto(), [1, 1, 1, 1, 1]),
                (closed(), [1, 1, 1, 1, 1]),
                (closed(), [1, 1, 1, 1, 1]),
            ],
            1,
            1,
        ),
        (
            // recvmmsg returns the prefix; the error comes with the next call, after the prefix is delivered.
            "error after the prefix",
            vec![
                frame(&[1]),
                outgoing(2),
                foreign(3),
                long(4),
                frame(&[5, 5]),
                Err(ENETDOWN),
                frame(&[6]),
            ],
            vec![
                (Ok(vec![1]), [1, 0, 0, 0, 0]),
                (Ok(vec![5, 5]), [2, 1, 1, 1, 0]),
                (Err(format!("recvfrom: {}", os(ENETDOWN))), [2, 1, 1, 1, 1]),
                (closed(), [2, 1, 1, 1, 1]),
            ],
            2,
            1,
        ),
        (
            "short address at the head",
            vec![Err(EPROTO), frame(&[1])],
            vec![
                (proto(), [0, 0, 0, 0, 1]),
                (closed(), [0, 0, 0, 0, 1]),
                (closed(), [0, 0, 0, 0, 1]),
                (closed(), [0, 0, 0, 0, 1]),
            ],
            1,
            0,
        ),
    ];
    for (name, recvs, calls, batches, left) in cases {
        let (mut r, s, _, c) = rx(Script {
            recvs: recvs.into(),
            ..Default::default()
        });
        for (i, (want, counts)) in calls.into_iter().enumerate() {
            let mut buf = [0u8; 16];
            let got = match r.recv(&mut buf, MS50) {
                Ok(Some(n)) => Ok(buf[..n].to_vec()),
                Ok(None) => Ok(Vec::new()),
                Err(e) => Err(e.message),
            };
            assert_eq!(got, want, "{name}: call {}", i + 1);
            assert_eq!(
                rx_counts(&c),
                counts,
                "{name}: counters after call {}",
                i + 1
            );
        }
        let s = s.lock().unwrap();
        assert_eq!(
            (s.recv_calls, s.batch_calls, s.recvs.len()),
            (batches, batches, left),
            "{name}: receive calls"
        );
    }
}

#[test]
fn rx_ring_is_drained_before_the_direct_path() {
    let (mut r, s, _, c) = rx(Script {
        recvs: [
            frame(&[1]),
            frame(&[7; RX_SLOT + 100]),
            frame(&[2, 2]),
            Err(EAGAIN),
            frame(&[9; RX_SLOT + 100]),
        ]
        .into(),
        polls: [Ok(Readiness::Ready)].into(),
        ..Default::default()
    });
    let mut small = [0u8; 64];
    let mut big = vec![0u8; 2 * RX_SLOT];
    // A buffer no longer than a slot: one batch takes the three records before EAGAIN.
    assert_eq!(r.recv(&mut small, MS50), Ok(Some(1)));
    // A buffer longer than a slot while the ring holds records: the ring goes first, without a syscall. The record
    // longer than a slot was cut to RX_SLOT bytes by the kernel, so it cannot be delivered whole: truncated.
    assert_eq!(r.recv(&mut big, MS50), Ok(Some(2)));
    assert_eq!(&big[..2], &[2, 2]);
    {
        let s = s.lock().unwrap();
        assert_eq!((s.recv_calls, s.batch_calls), (1, 1));
    }
    assert_eq!(rx_counts(&c), [2, 0, 0, 1, 0]);
    // The ring is empty: the direct path, which delivers a frame longer than a slot whole.
    assert_eq!(r.recv(&mut big, MS50), Ok(Some(RX_SLOT + 100)));
    assert!(big[..RX_SLOT + 100].iter().all(|&b| b == 9));
    let s = s.lock().unwrap();
    assert_eq!(
        (s.recv_calls, s.batch_calls),
        (3, 1),
        "EAGAIN, then the frame"
    );
    assert_eq!(rx_counts(&c), [3, 0, 0, 1, 0]);
}

#[test]
fn rx_caller_buffer_larger_than_a_slot_uses_the_direct_path() {
    let (mut r, s, _, c) = rx(Script {
        recvs: [
            frame(&[7; RX_SLOT + 1]),
            frame(&[8; 3 * RX_SLOT]),
            frame(&[4; 10]),
            frame(&[3; RX_SLOT]),
        ]
        .into(),
        ..Default::default()
    });
    let mut big = vec![0u8; RX_SLOT + 1];
    // Long-frame semantics as before, one receive per record: whole when it fits the caller's buffer, truncated
    // when it does not.
    assert_eq!(r.recv(&mut big, MS50), Ok(Some(RX_SLOT + 1)));
    assert!(big.iter().all(|&b| b == 7));
    assert_eq!(r.recv(&mut big, MS50), Ok(Some(10)));
    assert_eq!(&big[..10], &[4; 10]);
    {
        let s = s.lock().unwrap();
        assert_eq!((s.recv_calls, s.batch_calls), (3, 0));
    }
    assert_eq!(rx_counts(&c), [2, 0, 0, 1, 0]);
    // A buffer of exactly one slot takes the batch path.
    let mut slot = vec![0u8; RX_SLOT];
    assert_eq!(r.recv(&mut slot, MS50), Ok(Some(RX_SLOT)));
    assert!(slot.iter().all(|&b| b == 3));
    let s = s.lock().unwrap();
    assert_eq!((s.recv_calls, s.batch_calls), (4, 1));
    assert_eq!(rx_counts(&c), [3, 0, 0, 1, 0]);
}

#[test]
fn rx_batch_partial_fill_then_eagain_waits_until_the_deadline() {
    let (mut r, s, _, c) = rx(Script {
        recvs: [frame(&[1]), frame(&[2])].into(),
        ..Default::default()
    });
    let mut buf = [0u8; 16];
    assert_eq!(r.recv(&mut buf, MS50), Ok(Some(1)));
    assert_eq!(r.recv(&mut buf, MS50), Ok(Some(1)));
    assert_eq!(buf[0], 2);
    assert_eq!(s.lock().unwrap().recv_calls, 1, "a partial batch of two");
    let t0 = Instant::now();
    assert_eq!(r.recv(&mut buf, Duration::from_millis(20)), Ok(None));
    let e = t0.elapsed();
    #[cfg(target_os = "linux")]
    assert!(e >= Duration::from_millis(19), "{e:?}");
    assert!(e < Duration::from_millis(20) + SLACK, "{e:?}");
    let s = s.lock().unwrap();
    assert_eq!(
        s.recv_calls, s.batch_calls,
        "a slot-sized buffer never takes the direct path"
    );
    assert!(s.poll_calls >= 1, "EAGAIN waits in poll");
    assert!(s.recv_calls < 50, "must sleep in poll, not spin");
    assert_eq!(snap(&c).rx_packets, 2);
}

/// Review Focus 5: `health` between batches makes a fresh `PACKET_STATISTICS` read, and the frames waiting in the
/// ring come out after it, none lost and none counted twice.
#[test]
fn health_between_batches_reads_fresh_drops_and_keeps_buffered_frames() {
    let (mut r, s, _, c) = rx(Script {
        recvs: [frame(&[1]), frame(&[2]), frame(&[3])].into(),
        stats: [ks(5), ks(2)].into(),
        ..Default::default()
    });
    let mut buf = [0u8; 16];
    assert_eq!(r.recv(&mut buf, MS50), Ok(Some(1)));
    assert_eq!(r.health(MS50).unwrap().kernel_drops, Some(5));
    assert_eq!(s.lock().unwrap().stats.len(), 1, "one fresh read");
    assert_eq!(r.recv(&mut buf, MS50), Ok(Some(1)));
    assert_eq!(buf[0], 2);
    assert_eq!(r.recv(&mut buf, MS50), Ok(Some(1)));
    assert_eq!(buf[0], 3);
    assert_eq!(r.health(MS50).unwrap().kernel_drops, Some(7));
    let st = snap(&c);
    assert_eq!((st.rx_packets, st.kernel_drops), (3, Some(7)));
    let s = s.lock().unwrap();
    assert_eq!(
        (s.recv_calls, s.batch_calls),
        (1, 1),
        "the buffered frames came without a new receive"
    );
    assert!(s.stats.is_empty(), "each health read the kernel once");
}

// ---------------------------------------------------------------- binding

struct FakeIface {
    index: Option<u32>,
    /// `sa_family` of the link address (`SIOCGIFHWADDR`).
    family: u16,
    /// `if_nametoindex` fails with this errno.
    index_err: Option<Errno>,
    /// `SIOCGIFHWADDR` fails with this errno.
    hw_err: Option<Errno>,
    queried: Mutex<Vec<&'static str>>,
}

impl FakeIface {
    fn ok() -> Self {
        FakeIface {
            index: Some(IFINDEX),
            family: ARPHRD_ETHER,
            index_err: None,
            hw_err: None,
            queried: Mutex::new(Vec::new()),
        }
    }
}

impl IfaceInfo for FakeIface {
    fn ifindex(&self, _: &str) -> Result<Option<u32>, Errno> {
        self.queried.lock().unwrap().push("ifindex");
        self.index_err.map_or(Ok(self.index), Err)
    }
    fn link_family(&self, _: &str) -> Result<u16, Errno> {
        self.queried.lock().unwrap().push("hw");
        self.hw_err.map_or(Ok(self.family), Err)
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
    q.family = 772 /* ARPHRD_LOOPBACK */;
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

// ---------------------------------------------------------------- socket flags

/// Настоящий сокет и `fcntl`: только на Linux.
#[cfg(target_os = "linux")]
#[test]
fn hw_addr_ioctl_socket_keeps_its_flags() {
    use std::os::fd::AsFd;
    let fd = socket::ioctl_socket().unwrap();
    let (status, cloexec) = crate::unix_fd_tests::fd_flags(fd.as_fd());
    assert!(cloexec, "the SIOCGIFHWADDR socket sets FD_CLOEXEC");
    assert_eq!(
        status & libc::O_NONBLOCK,
        0,
        "the SIOCGIFHWADDR socket blocks"
    );
}

// ---------------------------------------------------------------- exact texts

/// The text of errno `e` in the table of the host OS, as `errno_msg` prints it.
fn os(e: Errno) -> String {
    std::io::Error::from_raw_os_error(e).to_string()
}

const CLOSED: &str = "adapter closed after an earlier fatal error";

#[test]
fn error_texts_are_byte_identical() {
    let text = |q: &FakeIface, b: &AdapterBinding| verify_binding(q, b).unwrap_err().to_string();
    // verify_binding
    let mut b = binding();
    b.link_type = LinkType::Null;
    assert_eq!(
        text(&FakeIface::ok(), &b),
        "unsupported link type: Null (Linux AF_PACKET supports Ethernet only)"
    );
    let mut b = binding();
    b.interface_id = "a b".into();
    assert_eq!(
        text(&FakeIface::ok(), &b),
        "interface does not match the binding: invalid interface name \"a b\""
    );
    let mut q = FakeIface::ok();
    q.index = None;
    assert_eq!(
        text(&q, &binding()),
        "interface does not match the binding: no such interface \"veth-a\""
    );
    let mut q = FakeIface::ok();
    q.hw_err = Some(ENODEV);
    assert_eq!(
        text(&q, &binding()),
        "interface does not match the binding: interface \"veth-a\" disappeared"
    );
    let mut q = FakeIface::ok();
    q.index_err = Some(EIO);
    assert_eq!(
        text(&q, &binding()),
        format!("system error: if_nametoindex: {}", os(EIO))
    );
    let mut q = FakeIface::ok();
    q.hw_err = Some(EIO);
    assert_eq!(
        text(&q, &binding()),
        format!("system error: SIOCGIFHWADDR: {}", os(EIO))
    );
    let mut q = FakeIface::ok();
    q.family = 772;
    assert_eq!(
        text(&q, &binding()),
        "unsupported link type: interface \"veth-a\" has ARPHRD type 772, not Ethernet"
    );
    // map_open_error: the kind of each errno and the text of each kind.
    for (e, kind) in [
        (
            EPERM,
            "permission denied (raw packet access needs elevated privileges)",
        ),
        (
            EACCES,
            "permission denied (raw packet access needs elevated privileges)",
        ),
        (ENODEV, "interface does not match the binding"),
        (ENXIO, "interface does not match the binding"),
        (EIO, "system error"),
    ] {
        assert_eq!(
            map_open_error("rx socket", e).to_string(),
            format!("{kind}: rx socket: {}", os(e)),
            "errno {e}"
        );
    }

    // TX
    let (mut t, _, _, _) = tx(Script {
        sends: [Err(ENETDOWN)].into(),
        ..Default::default()
    });
    assert_eq!(
        t.send(&FRAME, MS50).unwrap_err().message,
        format!("send: {}", os(ENETDOWN))
    );
    assert_eq!(t.send(&FRAME, MS50).unwrap_err().message, CLOSED);
    let (mut t, _, _, _) = tx(Script {
        sends: [Err(EAGAIN)].into(),
        polls: [Ok(Readiness::Failed)].into(),
        ..Default::default()
    });
    assert_eq!(
        t.send(&FRAME, MS50).unwrap_err().message,
        "poll(POLLOUT): socket error"
    );
    let (mut t, _, _, _) = tx(Script {
        sends: [Err(EAGAIN)].into(),
        polls: [Err(EBADF)].into(),
        ..Default::default()
    });
    assert_eq!(
        t.send(&FRAME, MS50).unwrap_err().message,
        format!("poll(POLLOUT): {}", os(EBADF))
    );

    // RX
    let mut buf = [0u8; 16];
    let (mut r, _, _, _) = rx(Script {
        recvs: [Err(ENETDOWN)].into(),
        ..Default::default()
    });
    assert_eq!(
        r.recv(&mut buf, MS50).unwrap_err().message,
        format!("recvfrom: {}", os(ENETDOWN))
    );
    assert_eq!(r.recv(&mut buf, MS50).unwrap_err().message, CLOSED);
    assert_eq!(r.health(MS50).unwrap_err().message, CLOSED);
    let (mut r, _, _, _) = rx(Script {
        polls: [Ok(Readiness::Failed)].into(),
        ..Default::default()
    });
    assert_eq!(
        r.recv(&mut buf, MS50).unwrap_err().message,
        "poll(POLLIN): socket error"
    );
    let (mut r, _, _, _) = rx(Script {
        polls: [Err(EBADF)].into(),
        ..Default::default()
    });
    assert_eq!(
        r.recv(&mut buf, MS50).unwrap_err().message,
        format!("poll(POLLIN): {}", os(EBADF))
    );
    let (mut r, _, _, _) = rx(Script {
        stats: [Err(ENOPROTOOPT)].into(),
        ..Default::default()
    });
    assert_eq!(
        r.health(MS50).unwrap_err().message,
        format!("getsockopt(PACKET_STATISTICS): {}", os(ENOPROTOOPT))
    );
}

// ---------------------------------------------------------------- concurrent counters

/// Frames each thread moves in the concurrent counters test.
const CONCURRENT_FRAMES: usize = 20_000;

/// Every field of `cur` is at least the same field of `prev` (`kernel_drops`: unknown < known, then by value).
fn assert_monotonic(prev: &NetStats, cur: &NetStats) {
    let pairs = [
        ("tx_sent", prev.tx_sent, cur.tx_sent),
        ("tx_would_block", prev.tx_would_block, cur.tx_would_block),
        ("tx_uncertain", prev.tx_uncertain, cur.tx_uncertain),
        ("tx_errors", prev.tx_errors, cur.tx_errors),
        ("rx_packets", prev.rx_packets, cur.rx_packets),
        ("rx_truncated", prev.rx_truncated, cur.rx_truncated),
        ("rx_outgoing", prev.rx_outgoing, cur.rx_outgoing),
        (
            "rx_wrong_interface",
            prev.rx_wrong_interface,
            cur.rx_wrong_interface,
        ),
        ("rx_errors", prev.rx_errors, cur.rx_errors),
        ("tx_batches", prev.tx_batches, cur.tx_batches),
        ("tx_batch_max", prev.tx_batch_max, cur.tx_batch_max),
        ("tx_over_budget", prev.tx_over_budget, cur.tx_over_budget),
    ];
    for (name, p, c) in pairs {
        assert!(c >= p, "{name} went back: {prev:?} -> {cur:?}");
    }
    assert!(
        cur.kernel_drops >= prev.kernel_drops,
        "kernel_drops went back: {prev:?} -> {cur:?}"
    );
}

#[test]
fn stats_snapshot_is_monotonic_and_exact_under_concurrent_tx_and_rx() {
    let frame60 = [0x5a_u8; 60];
    let (tx_io, _, _) = fake(Script {
        sends: std::iter::repeat_n(Ok(60), CONCURRENT_FRAMES).collect(),
        ..Default::default()
    });
    let (rx_io, _, _) = fake(Script {
        recvs: std::iter::repeat_n(frame(&frame60), CONCURRENT_FRAMES).collect(),
        stats: std::iter::repeat_n(ks(0), 64).collect(),
        ..Default::default()
    });
    let c = counters();
    let mut t = TxHalf::new(tx_io, Arc::clone(&c));
    let mut r = RxHalf::new(rx_io, IFINDEX, Arc::clone(&c));
    let handle = NetStatsHandle::new(Arc::clone(&c));
    let tx_done = &AtomicBool::new(false);
    let rx_done = &AtomicBool::new(false);
    let last = std::thread::scope(|s| {
        s.spawn(|| {
            for _ in 0..CONCURRENT_FRAMES {
                assert_eq!(t.send(&frame60, MS50), Ok(SendStatus::Sent));
            }
            tx_done.store(true, Ordering::Release);
        });
        s.spawn(move || {
            let mut buf = [0u8; 2048];
            let mut got = 0;
            while got < CONCURRENT_FRAMES {
                if r.recv(&mut buf, MS50).unwrap().is_some() {
                    got += 1;
                }
            }
            drop(r);
            rx_done.store(true, Ordering::Release);
        });
        let observer = s.spawn(|| {
            let mut prev = handle.snapshot();
            loop {
                let done = tx_done.load(Ordering::Acquire) && rx_done.load(Ordering::Acquire);
                let cur = handle.snapshot();
                assert_monotonic(&prev, &cur);
                prev = cur;
                if done {
                    return prev;
                }
            }
        });
        observer.join().unwrap()
    });
    let end = handle.snapshot();
    assert_monotonic(&last, &end);
    // `tx_over_budget` counts driver calls slower than 50 ms: timing-dependent, so only its monotonicity (checked
    // above on every snapshot) is pinned. Every other field is exact.
    assert_eq!(
        NetStats {
            tx_over_budget: 0,
            ..end
        },
        NetStats {
            tx_sent: CONCURRENT_FRAMES as u64,
            rx_packets: CONCURRENT_FRAMES as u64,
            kernel_drops: Some(0),
            ..NetStats::default()
        }
    );
}

// ---------------------------------------------------------------- microbenchmark

/// Lock-free seam for the microbenchmark: `send` accepts everything, `recv` copies one prepared frame.
struct BenchIo {
    frame: [u8; 60],
}

impl PacketIo for BenchIo {
    fn send(&mut self, frame: &[u8]) -> Result<usize, Errno> {
        Ok(frame.len())
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<RecvMeta, Errno> {
        let n = self.frame.len().min(buf.len());
        buf[..n].copy_from_slice(&self.frame[..n]);
        Ok(RecvMeta {
            len: self.frame.len(),
            pkttype: 0,
            ifindex: IFINDEX as i32,
        })
    }
    fn recv_batch(
        &mut self,
        slots: &mut [[u8; RX_SLOT]],
        metas: &mut [SlotMeta],
    ) -> Result<usize, Errno> {
        let n = batch_len(slots.len(), metas.len())?;
        for (slot, meta) in slots.iter_mut().zip(metas.iter_mut()).take(n) {
            slot[..self.frame.len()].copy_from_slice(&self.frame);
            *meta = Ok(RecvMeta {
                len: self.frame.len(),
                pkttype: 0,
                ifindex: IFINDEX as i32,
            });
        }
        Ok(n)
    }
    fn poll(&mut self, _write: bool, _timeout_ms: i32) -> Result<Readiness, Errno> {
        Ok(Readiness::Ready)
    }
    fn packet_stats(&mut self) -> Result<KernelStats, Errno> {
        Ok(KernelStats { drops: 0 })
    }
    fn backoff(&mut self, _wait: Duration) {}
}

/// Calls per thread in the microbenchmark.
const BENCH_CALLS: u32 = 1_000_000;

#[test]
#[ignore = "microbenchmark: cargo test --release -p rmasscan-net adapter_hot_path -- --ignored --nocapture"]
fn adapter_hot_path_two_threads() {
    let frame60 = [0x5a_u8; 60];
    let c = counters();
    let mut t = TxHalf::new(BenchIo { frame: frame60 }, Arc::clone(&c));
    let mut r = RxHalf::new(BenchIo { frame: frame60 }, IFINDEX, Arc::clone(&c));
    let start = std::sync::Barrier::new(2);
    let (tx_time, rx_time) = std::thread::scope(|s| {
        let tx_thread = s.spawn(|| {
            start.wait();
            let t0 = Instant::now();
            for _ in 0..BENCH_CALLS {
                std::hint::black_box(t.send(std::hint::black_box(&frame60), MS50)).unwrap();
            }
            t0.elapsed()
        });
        let rx_thread = s.spawn(|| {
            let mut buf = [0u8; 2048];
            start.wait();
            let t0 = Instant::now();
            for _ in 0..BENCH_CALLS {
                std::hint::black_box(r.recv(&mut buf, MS50)).unwrap();
            }
            t0.elapsed()
        });
        (tx_thread.join().unwrap(), rx_thread.join().unwrap())
    });
    let per = |d: Duration| d.as_nanos() as f64 / f64::from(BENCH_CALLS);
    println!(
        "adapter_hot_path linux: tx {:.1} ns/frame, rx {:.1} ns/frame ({BENCH_CALLS} calls per thread)",
        per(tx_time),
        per(rx_time)
    );
    let s = snap(&c);
    assert_eq!(
        (s.tx_sent, s.rx_packets),
        (u64::from(BENCH_CALLS), u64::from(BENCH_CALLS))
    );
}

/// Таймаут `poll` не больше `MAX_IO_TIMEOUT`, даже когда остаток дедлайна в мс не помещается в `i32`; прошедший
/// дедлайн даёт 0.
#[test]
fn poll_ms_is_capped_by_the_io_bound() {
    let far = Deadline(Instant::now() + Duration::from_secs(30 * 86_400));
    assert_eq!(
        far.poll_ms(),
        i32::try_from(MAX_IO_TIMEOUT.as_millis()).unwrap()
    );
    assert_eq!(Deadline(Instant::now()).poll_ms(), 0);
}
