//! Тесты половин адаптера через подставной шов BPF (`fake`): настоящие
//! `TxHalf`/`RxHalf`/`open_with`, настоящий движок. Собираются на всех
//! платформах. Время не используется как утверждение о точности сна: границы
//! выводятся из записанных запросов шва (паузы, `poll`-таймауты).

use std::sync::Arc;
use std::time::Duration;

use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{AdapterBinding, ProbeCursor, ReadyPlan};
use rmasscan_core::receive::{PortStatus, parse_reply};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_engine::fake::reply_to_syn;
use rmasscan_engine::{
    AdapterPair, Engine, EngineOptions, Event, FailReason, IoError, Reason, SendStatus, Tx,
};

use super::fake::*;
use crate::NetError;
use crate::macos::abi::errno::{
    EACCES, EAGAIN, EBUSY, EINTR, EMSGSIZE, ENOBUFS, ENODEV, ENXIO, EPERM,
};
use crate::macos::abi::{BpfInsn, BpfStat, SIZEOF_BPF_HDR};
use crate::macos::adapter::{
    BACKOFF_MAX, IO_BUDGET, MAX_TX_FRAME, MIN_TX_FRAME, Readiness, Record, check_binding,
    drop_all_filter, open_with, own_mac_filter, parse_record,
};

const OUR_MAC: [u8; 6] = [0x02, 0xac, 0x00, 0x00, 0x00, 0x01];
const PEER_MAC: [u8; 6] = [0x02, 0xac, 0x00, 0x00, 0x00, 0x02];
const IFNAME: &str = "feth4201";
const PROBES: u64 = 16;
const MS50: Duration = Duration::from_millis(50);
/// `ENETDOWN` на macOS: произвольная фатальная ошибка записи.
const ENETDOWN: i32 = 50;

fn binding() -> AdapterBinding {
    AdapterBinding {
        interface_id: IFNAME.into(),
        link_type: LinkType::Ethernet,
        source_ipv4: 0xc612_0001,
        source_mac: OUR_MAC,
        next_hop_mac: PEER_MAC,
        source_ports: (40000, 40015),
    }
}

fn plan(rate: f64, wait: u32) -> ReadyPlan {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), "198.18.0.0/29").unwrap();
    parse_ports(m.ports_mut(), "80,443").unwrap();
    let cfg = ScanConfig {
        targets: m,
        seed: 0x1234_5678_9abc,
        max_rate: rate,
        wait_secs: wait,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).unwrap();
    ReadyPlan::new(eff, binding()).unwrap()
}

/// Настоящий SYN-кадр плана (с индексом `i`).
fn syn_frame(plan: &ReadyPlan, i: usize) -> Vec<u8> {
    let mut c = ProbeCursor::new(plan, 0).unwrap();
    for _ in 0..i {
        c.advance_sent();
    }
    c.current().unwrap().frame.clone()
}

fn open_pair(w: &Shared) -> crate::OpenedAdapter {
    open_with(&mut FakeOpener { w: Arc::clone(w) }, &binding()).expect("open_with")
}

fn open_err(w: &Shared) -> NetError {
    open_with(&mut FakeOpener { w: Arc::clone(w) }, &binding())
        .err()
        .expect("open must fail")
}

fn buf() -> Vec<u8> {
    vec![0u8; 2048]
}

/// Кадр с нашим source MAC (так выглядит наш же TX).
fn own_frame(len: usize) -> Vec<u8> {
    let mut f = vec![0u8; len];
    f[0..6].copy_from_slice(&PEER_MAC);
    f[6..12].copy_from_slice(&OUR_MAC);
    f[12..14].copy_from_slice(&[0x08, 0x00]);
    f
}

/// Кадр от пира (его source MAC).
fn peer_frame(len: usize) -> Vec<u8> {
    let mut f = own_frame(len);
    f[0..6].copy_from_slice(&OUR_MAC);
    f[6..12].copy_from_slice(&PEER_MAC);
    f
}

fn push_batch(w: &Shared, batch: Vec<u8>) {
    lock(w).reads.push_back(Ok(batch));
}

fn recv(a: &mut crate::OpenedAdapter, b: &mut [u8]) -> Result<Option<usize>, IoError> {
    a.io.rx.recv(b, MS50)
}

/// Утверждения о бэкоффе через шов (не по стенным часам): каждая пауза не
/// длиннее `BACKOFF_MAX`, сумма пауз не больше таймаута (сон не бывает короче
/// запрошенного), попыток не больше пауз + 1 и не больше `timeout_ms + 2`.
fn assert_bounded_backoff(w: &Shared, attempts: usize, timeout: Duration) {
    let s = lock(w);
    assert!(!s.backoffs.is_empty(), "retries must back off");
    assert!(
        s.backoffs.iter().all(|x| *x <= BACKOFF_MAX),
        "{:?}",
        s.backoffs
    );
    let total: Duration = s.backoffs.iter().sum();
    assert!(total <= timeout, "waits {total:?} exceed {timeout:?}");
    assert!(attempts <= s.backoffs.len() + 1, "{attempts} attempts");
    let cap = timeout.as_millis() as usize + 2;
    assert!(attempts <= cap, "{attempts} attempts > {cap}");
}

// ---------------------------------------------------------------- TX

#[test]
fn tx_full_write_is_sent() {
    let w = world();
    let mut a = open_pair(&w);
    let f = own_frame(60);
    assert_eq!(a.io.tx.send(&f, MS50), Ok(SendStatus::Sent));
    let s = a.stats.snapshot();
    assert_eq!(
        (s.tx_sent, s.tx_would_block, s.tx_uncertain, s.tx_errors),
        (1, 0, 0, 0)
    );
    assert_eq!(lock(&w).written, vec![f]);
    assert_eq!(calls(&w, "write:2"), 1, "writes go to the TX descriptor");
    assert_eq!(calls(&w, "write:1"), 0, "never to the RX descriptor");
}

#[test]
fn tx_enobufs_until_deadline_is_would_block_unsent() {
    let w = world();
    let mut a = open_pair(&w);
    lock(&w).write_forever = Some(ENOBUFS);
    let timeout = Duration::from_millis(20);
    assert_eq!(
        a.io.tx.send(&own_frame(60), timeout),
        Ok(SendStatus::WouldBlockUnsent)
    );
    let s = a.stats.snapshot();
    assert_eq!((s.tx_would_block, s.tx_sent, s.tx_errors), (1, 0, 0));
    let n = lock(&w).write_calls;
    assert!(n > 1, "ENOBUFS is retried until the deadline");
    assert_bounded_backoff(&w, n, timeout);
    assert!(lock(&w).written.is_empty());
}

#[test]
fn tx_eagain_is_treated_like_enobufs() {
    let w = world();
    let mut a = open_pair(&w);
    lock(&w).writes.extend([Err(EAGAIN), Ok(60)]);
    assert_eq!(a.io.tx.send(&own_frame(60), MS50), Ok(SendStatus::Sent));
}

#[test]
fn tx_enobufs_then_success_is_sent_once() {
    let w = world();
    let mut a = open_pair(&w);
    lock(&w).writes.extend([Err(ENOBUFS), Err(ENOBUFS), Ok(60)]);
    let f = own_frame(60);
    assert_eq!(a.io.tx.send(&f, MS50), Ok(SendStatus::Sent));
    assert_eq!(lock(&w).write_calls, 3);
    assert_eq!(lock(&w).written, vec![f], "the frame left exactly once");
    let s = a.stats.snapshot();
    assert_eq!((s.tx_sent, s.tx_would_block), (1, 0));
}

#[test]
fn tx_partial_write_is_uncertain_and_keeps_fd_open() {
    let w = world();
    let mut a = open_pair(&w);
    lock(&w).writes.extend([Ok(30)]);
    assert_eq!(
        a.io.tx.send(&own_frame(60), MS50),
        Ok(SendStatus::Uncertain)
    );
    assert_eq!(a.stats.snapshot().tx_uncertain, 1);
    assert_eq!(count(&w, "2:close"), 0, "the descriptor stays open");
    assert_eq!(lock(&w).write_calls, 1, "no retry of an uncertain frame");
    // Дескриптор рабочий: следующий кадр уходит.
    assert_eq!(a.io.tx.send(&own_frame(60), MS50), Ok(SendStatus::Sent));
}

#[test]
fn tx_eintr_flood_does_not_extend_the_deadline() {
    let w = world();
    let mut a = open_pair(&w);
    lock(&w).write_forever = Some(EINTR);
    let timeout = Duration::from_millis(15);
    assert_eq!(
        a.io.tx.send(&own_frame(60), timeout),
        Ok(SendStatus::WouldBlockUnsent)
    );
    let n = lock(&w).write_calls;
    assert!(n > 1, "EINTR must be retried");
    assert_bounded_backoff(&w, n, timeout);
}

#[test]
fn tx_emsgsize_is_an_io_error_and_the_fd_stays_open() {
    let w = world();
    let mut a = open_pair(&w);
    lock(&w).writes.extend([Err(EMSGSIZE)]);
    let e = a.io.tx.send(&own_frame(60), MS50).unwrap_err();
    assert!(e.message.contains("nothing was sent"), "{e}");
    assert_eq!(a.stats.snapshot().tx_errors, 1);
    assert_eq!(count(&w, "2:close"), 0);
    assert_eq!(a.io.tx.send(&own_frame(60), MS50), Ok(SendStatus::Sent));
}

#[test]
fn tx_fatal_errno_closes_the_fd_and_later_calls_fail() {
    let w = world();
    let mut a = open_pair(&w);
    lock(&w).writes.extend([Err(ENETDOWN)]);
    let e = a.io.tx.send(&own_frame(60), MS50).unwrap_err();
    assert!(e.message.contains("write"), "{e}");
    assert_eq!(count(&w, "2:close"), 1, "fd closed after the error");
    assert_eq!(a.stats.snapshot().tx_errors, 1);
    let n = lock(&w).write_calls;
    let e = a.io.tx.send(&own_frame(60), MS50).unwrap_err();
    assert!(
        e.message.contains("closed after an earlier fatal error"),
        "{e}"
    );
    assert_eq!(lock(&w).write_calls, n, "no write after close");
}

#[test]
fn tx_timeout_is_capped_at_the_budget() {
    let w = world();
    let mut a = open_pair(&w);
    lock(&w).write_forever = Some(ENOBUFS);
    assert_eq!(
        a.io.tx.send(&own_frame(60), Duration::from_secs(10)),
        Ok(SendStatus::WouldBlockUnsent)
    );
    // Сон не бывает короче запрошенного, а каждая пауза не больше остатка
    // дедлайна: сумма пауз выше бюджета означала бы дедлайн больше бюджета.
    let total: Duration = lock(&w).backoffs.iter().sum();
    assert!(total <= IO_BUDGET, "{total:?} > {IO_BUDGET:?}");
    assert!(IO_BUDGET <= Duration::from_millis(50));
}

#[test]
fn tx_frame_length_is_checked_before_any_write() {
    let w = world();
    let mut a = open_pair(&w);
    for len in [0, MIN_TX_FRAME - 1, MAX_TX_FRAME + 1, 9000] {
        let e = a.io.tx.send(&vec![0u8; len], MS50).unwrap_err();
        assert!(e.message.contains("nothing was sent"), "{len}: {e}");
    }
    assert_eq!(lock(&w).write_calls, 0);
    assert_eq!(a.stats.snapshot().tx_errors, 4);
    assert_eq!(count(&w, "2:close"), 0);
    for len in [MIN_TX_FRAME, MAX_TX_FRAME] {
        assert_eq!(a.io.tx.send(&vec![0u8; len], MS50), Ok(SendStatus::Sent));
    }
}

// ---------------------------------------------------------------- RX

#[test]
fn rx_one_read_with_three_records_yields_three_frames() {
    let w = world();
    let mut a = open_pair(&w);
    let frames = [peer_frame(60), peer_frame(74), peer_frame(54)];
    let batch: Vec<u8> = frames
        .iter()
        .flat_map(|f| record(SIZEOF_BPF_HDR, f))
        .collect();
    push_batch(&w, batch);
    let mut b = buf();
    for f in &frames {
        let n = recv(&mut a, &mut b).unwrap().expect("a frame");
        assert_eq!(&b[..n], f.as_slice());
    }
    assert_eq!(lock(&w).read_calls, 1, "three frames from one read");
    assert_eq!(a.stats.snapshot().rx_packets, 3);
    assert_eq!(recv(&mut a, &mut b).unwrap(), None);
}

#[test]
fn rx_record_walk_uses_bh_hdrlen_and_wordalign() {
    let w = world();
    let mut a = open_pair(&w);
    // Разные bh_hdrlen и длины, не кратные 4: шаг только wordalign(hdrlen+caplen).
    let mut frames = Vec::new();
    let mut batch = Vec::new();
    for (i, (hdrlen, len)) in [(18, 61), (20, 60), (24, 55), (18, 59), (64, 77), (32, 14)]
        .into_iter()
        .enumerate()
    {
        let mut f = peer_frame(len);
        for (j, byte) in f.iter_mut().enumerate().skip(14) {
            *byte = (i * 31 + j) as u8;
        }
        batch.extend(record(hdrlen, &f));
        frames.push(f);
    }
    push_batch(&w, batch);
    let mut b = buf();
    for f in &frames {
        let n = recv(&mut a, &mut b).unwrap().expect("a frame");
        assert_eq!(&b[..n], f.as_slice());
    }
    assert_eq!(a.stats.snapshot().rx_errors, 0);
    assert_eq!(a.stats.snapshot().rx_packets, frames.len() as u64);
}

#[test]
fn parse_record_advances_by_wordalign_and_tolerates_a_missing_final_pad() {
    // Последняя запись без хвостового выравнивания: шаг не выходит за конец.
    let f = peer_frame(61);
    let mut data = record(SIZEOF_BPF_HDR, &f);
    data.truncate(SIZEOF_BPF_HDR + 61);
    let mut off = 0;
    let r = parse_record(&data, &mut off, data.len()).unwrap();
    assert_eq!(
        r,
        Record::Frame {
            start: SIZEOF_BPF_HDR,
            end: SIZEOF_BPF_HDR + 61
        }
    );
    assert_eq!(off, data.len());
}

#[test]
fn rx_caplen_shorter_than_datalen_is_truncated_not_returned() {
    let w = world();
    let mut a = open_pair(&w);
    let cut = peer_frame(40);
    let good = peer_frame(60);
    let mut batch = raw_record(SIZEOF_BPF_HDR, 40, 90, &cut);
    batch.extend(record(SIZEOF_BPF_HDR, &good));
    push_batch(&w, batch);
    let mut b = buf();
    let n = recv(&mut a, &mut b).unwrap().expect("the good frame");
    assert_eq!(
        &b[..n],
        good.as_slice(),
        "the truncated frame is never returned"
    );
    let s = a.stats.snapshot();
    assert_eq!((s.rx_truncated, s.rx_packets, s.rx_errors), (1, 1, 0));
}

#[test]
fn rx_malformed_header_is_fatal_and_closes_the_fd() {
    let good = peer_frame(60);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("hdrlen 17", raw_record(17, 60, 60, &good)),
        ("hdrlen 0", raw_record(0, 60, 60, &good)),
        ("hdrlen 65", raw_record(65, 60, 60, &good)),
        (
            "caplen past the buffer",
            raw_record(SIZEOF_BPF_HDR, 9000, 9000, &good),
        ),
        (
            "caplen near u32::MAX",
            raw_record(SIZEOF_BPF_HDR, u32::MAX, u32::MAX, &good),
        ),
        ("header cut short", vec![0u8; 10]),
        ("second record cut short", {
            let mut b = record(SIZEOF_BPF_HDR, &good);
            b.extend([0u8; 6]);
            b
        }),
    ];
    for (label, batch) in cases {
        let w = world();
        let mut a = open_pair(&w);
        push_batch(&w, batch);
        let mut b = buf();
        let r = recv(&mut a, &mut b);
        // Первая запись «cut short» читается как кадр, ошибка на второй.
        let r = if label == "second record cut short" {
            assert!(r.unwrap().is_some());
            recv(&mut a, &mut b)
        } else {
            r
        };
        let e = r.unwrap_err();
        assert!(e.message.contains("BPF"), "{label}: {e}");
        assert_eq!(count(&w, "1:close"), 1, "{label}: RX fd closed");
        assert_eq!(a.stats.snapshot().rx_errors, 1, "{label}");
        let reads = lock(&w).read_calls;
        let e = recv(&mut a, &mut b).unwrap_err();
        assert!(
            e.message.contains("closed after an earlier fatal error"),
            "{label}: {e}"
        );
        assert_eq!(lock(&w).read_calls, reads, "{label}: no read after close");
        assert!(a.io.rx.health(MS50).is_err(), "{label}");
    }
}

#[test]
fn rx_own_mac_frames_are_dropped_before_the_caller_sees_them() {
    let w = world();
    let mut a = open_pair(&w);
    let peer = peer_frame(60);
    let mut batch = Vec::new();
    batch.extend(record(SIZEOF_BPF_HDR, &own_frame(60)));
    batch.extend(record(SIZEOF_BPF_HDR, &own_frame(54)));
    batch.extend(record(SIZEOF_BPF_HDR, &peer));
    push_batch(&w, batch);
    let mut b = buf();
    let n = recv(&mut a, &mut b).unwrap().expect("the peer frame");
    assert_eq!(&b[..n], peer.as_slice());
    let s = a.stats.snapshot();
    assert_eq!((s.rx_outgoing, s.rx_packets), (2, 1));
}

#[test]
fn rx_peer_syn_ack_and_rst_are_never_filtered_and_parse_as_replies() {
    let w = world();
    let mut a = open_pair(&w);
    let p = plan(1e6, 1);
    let syn = syn_frame(&p, 0);
    let synack = reply_to_syn(&syn, 0x12).unwrap();
    let rst = reply_to_syn(&syn, 0x04).unwrap();
    let mut batch = record(SIZEOF_BPF_HDR, &synack);
    batch.extend(record(SIZEOF_BPF_HDR, &rst));
    push_batch(&w, batch);
    let mut b = buf();
    let mut got = Vec::new();
    for _ in 0..2 {
        let n = recv(&mut a, &mut b).unwrap().expect("a reply");
        got.push(b[..n].to_vec());
    }
    assert_eq!(got, vec![synack, rst]);
    let r1 = parse_reply(&got[0], LinkType::Ethernet, &p)
        .unwrap()
        .unwrap();
    let r2 = parse_reply(&got[1], LinkType::Ethernet, &p)
        .unwrap()
        .unwrap();
    assert_eq!(r1.status, PortStatus::Open);
    assert_eq!(r2.status, PortStatus::Closed);
    assert_eq!(
        a.stats.snapshot().rx_outgoing,
        0,
        "the peer MAC is never ours"
    );
    // Фильтр ядра режет только наш source MAC и не содержит MAC пира.
    let f = lock(&w).filters.clone();
    let rx_prog = &f.iter().find(|(d, _)| *d == 1).unwrap().1;
    assert_eq!(run_filter(rx_prog, &got[0]), 0xffff_ffff);
    assert_eq!(run_filter(rx_prog, &got[1]), 0xffff_ffff);
}

#[test]
fn rx_frame_larger_than_callers_buffer_is_dropped_and_counted() {
    let w = world();
    let mut a = open_pair(&w);
    let big = peer_frame(200);
    let small = peer_frame(60);
    let mut batch = record(SIZEOF_BPF_HDR, &big);
    batch.extend(record(SIZEOF_BPF_HDR, &small));
    push_batch(&w, batch);
    let mut b = [0u8; 100];
    let n =
        a.io.rx
            .recv(&mut b, MS50)
            .unwrap()
            .expect("the small frame");
    assert_eq!(&b[..n], small.as_slice());
    let s = a.stats.snapshot();
    assert_eq!((s.rx_truncated, s.rx_packets), (1, 1));
}

#[test]
fn rx_empty_poll_times_out_within_the_deadline() {
    let w = world();
    let mut a = open_pair(&w);
    let mut b = buf();
    assert_eq!(
        a.io.rx.recv(&mut b, Duration::from_millis(20)).unwrap(),
        None
    );
    let s = lock(&w);
    assert!(s.poll_calls >= 1, "waits in poll, not by spinning");
    assert!(
        s.poll_ms.iter().all(|&m| (1..=20).contains(&m)),
        "poll timeouts stay inside the caller's timeout: {:?}",
        s.poll_ms
    );
    assert!(s.read_calls < 50, "must sleep in poll, not spin");
    drop(s);
    // Таймаут больше бюджета обрезается.
    a.io.rx.recv(&mut b, Duration::from_secs(10)).unwrap();
    assert!(
        lock(&w)
            .poll_ms
            .iter()
            .all(|&m| (1..=IO_BUDGET.as_millis() as i32).contains(&m))
    );
}

#[test]
fn rx_readiness_without_records_keeps_waiting_until_the_deadline() {
    let w = world();
    let mut a = open_pair(&w);
    lock(&w)
        .polls
        .extend(std::iter::repeat_n(Ok(Readiness::Ready), 3));
    let mut b = buf();
    assert_eq!(
        a.io.rx.recv(&mut b, Duration::from_millis(15)).unwrap(),
        None
    );
    assert!(lock(&w).read_calls >= 4, "each Ready is followed by a read");
}

#[test]
fn rx_poll_failure_is_fatal() {
    let w = world();
    let mut a = open_pair(&w);
    lock(&w).polls.extend([Ok(Readiness::Failed)]);
    let mut b = buf();
    let e = recv(&mut a, &mut b).unwrap_err();
    assert!(e.message.contains("poll"), "{e}");
    assert_eq!(count(&w, "1:close"), 1);
    assert_eq!(a.stats.snapshot().rx_errors, 1);
}

#[test]
fn rx_fatal_read_errno_closes_the_fd() {
    let w = world();
    let mut a = open_pair(&w);
    lock(&w).reads.push_back(Err(ENETDOWN));
    let mut b = buf();
    let e = recv(&mut a, &mut b).unwrap_err();
    assert!(e.message.contains("read"), "{e}");
    assert_eq!(count(&w, "1:close"), 1);
}

#[test]
fn rx_garbage_stream_cannot_extend_the_deadline() {
    let w = world();
    let mut a = open_pair(&w);
    // Конечный, но огромный поток пачек с нашими же кадрами: все отбрасываются.
    let junk: Vec<u8> = (0..8)
        .flat_map(|_| record(SIZEOF_BPF_HDR, &own_frame(60)))
        .collect();
    const JUNK_READS: usize = 5_000_000;
    lock(&w).junk = Some((JUNK_READS, junk));
    let mut b = buf();
    assert_eq!(
        a.io.rx.recv(&mut b, Duration::from_millis(15)).unwrap(),
        None
    );
    let left = lock(&w).junk.as_ref().unwrap().0;
    assert!(
        left > 0,
        "the call returned at its deadline, not at the end of the garbage"
    );
    assert!(a.stats.snapshot().rx_outgoing > 0);
    assert_eq!(a.stats.snapshot().rx_packets, 0);
}

#[test]
fn rx_eintr_backs_off_bounded_and_keeps_deadline() {
    let w = world();
    let mut a = open_pair(&w);
    lock(&w).read_forever = Some(EINTR);
    let mut b = buf();
    let timeout = Duration::from_millis(20);
    assert_eq!(a.io.rx.recv(&mut b, timeout).unwrap(), None);
    let n = lock(&w).read_calls;
    assert_bounded_backoff(&w, n, timeout);
}

#[test]
fn rx_poll_eintr_backs_off_bounded_and_keeps_deadline() {
    let w = world();
    let mut a = open_pair(&w);
    lock(&w)
        .polls
        .extend(std::iter::repeat_n(Err(EINTR), 100_000));
    let mut b = buf();
    let timeout = Duration::from_millis(20);
    assert_eq!(a.io.rx.recv(&mut b, timeout).unwrap(), None);
    let n = lock(&w).poll_calls;
    assert_bounded_backoff(&w, n, timeout);
}

// ---------------------------------------------------------------- health

#[test]
fn health_reports_cumulative_drops_from_the_open_baseline() {
    let w = world();
    lock(&w).stats_drop = 1000; // дескриптор уже видел 1000
    let mut a = open_pair(&w);
    let h = |a: &mut crate::OpenedAdapter| a.io.rx.health(MS50).unwrap().kernel_drops;
    assert_eq!(h(&mut a), Some(0));
    lock(&w).stats_drop = 1007;
    assert_eq!(h(&mut a), Some(7));
    assert_eq!(h(&mut a), Some(7), "reading does not reset");
    lock(&w).stats_drop = 1010;
    assert_eq!(h(&mut a), Some(10));
    assert_eq!(a.stats.snapshot().kernel_drops, Some(10));
    assert_eq!(
        calls(&w, "stats:2"),
        0,
        "stats are read only from the RX descriptor"
    );
}

#[test]
fn health_survives_the_u32_wrap() {
    let w = world();
    lock(&w).stats_drop = u32::MAX - 2;
    let mut a = open_pair(&w);
    lock(&w).stats_drop = u32::MAX;
    assert_eq!(a.io.rx.health(MS50).unwrap().kernel_drops, Some(2));
    lock(&w).stats_drop = 1;
    assert_eq!(a.io.rx.health(MS50).unwrap().kernel_drops, Some(4));
}

#[test]
fn a_stats_error_is_an_error_never_a_false_zero_or_a_cached_value() {
    let w = world();
    let mut a = open_pair(&w);
    // Ни одного успешного измерения health ещё не было: и сразу ошибка.
    lock(&w).stats.push_back(Err(EBUSY));
    let e = a.io.rx.health(MS50).unwrap_err();
    assert!(e.message.contains("BIOCGSTATS"), "{e:?}");
    assert_eq!(
        a.stats.snapshot().kernel_drops,
        None,
        "unknown stays unknown"
    );
    // После успеха и новой ошибки прежнее значение не подставляется.
    lock(&w).stats_drop = 5;
    assert_eq!(a.io.rx.health(MS50).unwrap().kernel_drops, Some(5));
    lock(&w).stats.push_back(Err(EBUSY));
    assert!(a.io.rx.health(MS50).is_err());
    assert_eq!(a.io.rx.health(MS50).unwrap().kernel_drops, Some(5));
}

#[test]
fn net_stats_final_totals_survive_closing_the_handles() {
    let w = world();
    let a = open_pair(&w);
    let stats = a.stats.clone();
    assert_eq!(stats.snapshot().kernel_drops, None, "nothing measured yet");
    lock(&w).stats_drop = 9;
    let crate::OpenedAdapter { io, stats: _ } = a;
    drop(io);
    assert_eq!(count(&w, "1:close") + count(&w, "2:close"), 2);
    assert_eq!(
        stats.snapshot().kernel_drops,
        Some(9),
        "final read on close"
    );
}

#[test]
fn a_failed_final_read_keeps_the_last_known_value_or_none() {
    let w = world();
    let a = open_pair(&w);
    let stats = a.stats.clone();
    lock(&w).stats.push_back(Err(EBUSY));
    drop(a);
    assert_eq!(stats.snapshot().kernel_drops, None);

    let w = world();
    let mut a = open_pair(&w);
    let stats = a.stats.clone();
    lock(&w).stats_drop = 4;
    a.io.rx.health(MS50).unwrap();
    lock(&w).stats.push_back(Err(EBUSY));
    drop(a);
    assert_eq!(stats.snapshot().kernel_drops, Some(4));
}

// ---------------------------------------------------------------- фильтры

#[test]
fn own_mac_filter_program_bytes_are_exact() {
    let p = own_mac_filter(OUR_MAC);
    let t: Vec<(u16, u8, u8, u32)> = p.iter().map(|i| (i.code, i.jt, i.jf, i.k)).collect();
    assert_eq!(
        t,
        vec![
            (0x20, 0, 0, 6),
            (0x15, 0, 3, 0x02ac_0000),
            (0x28, 0, 0, 10),
            (0x15, 0, 1, 0x0001),
            (0x06, 0, 0, 0),
            (0x06, 0, 0, 0xffff_ffff),
        ]
    );
    let d = drop_all_filter();
    assert_eq!(
        d.iter()
            .map(|i| (i.code, i.jt, i.jf, i.k))
            .collect::<Vec<_>>(),
        vec![(0x06, 0, 0, 0)]
    );
}

/// Мини-интерпретатор классического BPF: `ld [k]`, `ldh [k]`, `jeq #k`, `ret #k`.
/// Выход за пакет возвращает 0, как ядро.
fn run_filter(prog: &[BpfInsn], pkt: &[u8]) -> u32 {
    let mut a = 0u32;
    let mut pc = 0usize;
    loop {
        let i = prog[pc];
        match i.code {
            0x20 => {
                let k = i.k as usize;
                let Some(b) = pkt.get(k..k + 4) else { return 0 };
                a = u32::from_be_bytes(b.try_into().unwrap());
                pc += 1;
            }
            0x28 => {
                let k = i.k as usize;
                let Some(b) = pkt.get(k..k + 2) else { return 0 };
                a = u32::from(u16::from_be_bytes(b.try_into().unwrap()));
                pc += 1;
            }
            0x15 => pc += 1 + usize::from(if a == i.k { i.jt } else { i.jf }),
            0x06 => return i.k,
            c => panic!("opcode {c:#x} is not in the filter"),
        }
    }
}

#[test]
fn own_mac_filter_interpreted_drops_own_and_accepts_peer() {
    let p = own_mac_filter(OUR_MAC);
    assert_eq!(run_filter(&p, &own_frame(60)), 0, "own frame dropped");
    assert_eq!(
        run_filter(&p, &peer_frame(60)),
        0xffff_ffff,
        "peer frame accepted whole"
    );
    // Совпадение только первых 4 или только последних 2 байт MAC не отбрасывает.
    let mut near = own_frame(60);
    near[11] ^= 0x01;
    assert_eq!(run_filter(&p, &near), 0xffff_ffff);
    let mut near = own_frame(60);
    near[6] ^= 0x01;
    assert_eq!(run_filter(&p, &near), 0xffff_ffff);
    // Broadcast ARP от пира тоже проходит; слишком короткий кадр отбрасывается ядром.
    assert_eq!(run_filter(&p, &[0xff; 12]), 0xffff_ffff);
    assert_eq!(run_filter(&p, &[0xff; 8]), 0);
    // Любой другой MAC проходит.
    for last in 0..=255u8 {
        let mut f = own_frame(60);
        f[6 + 5] = last;
        let want = if last == OUR_MAC[5] { 0 } else { 0xffff_ffff };
        assert_eq!(run_filter(&p, &f), want, "last byte {last}");
    }
    assert_eq!(run_filter(&drop_all_filter(), &peer_frame(60)), 0);
}

// ---------------------------------------------------------------- открытие

#[test]
fn open_configures_rx_then_tx_exactly_as_documented() {
    let w = world();
    let a = open_pair(&w);
    let want: Vec<String> = [
        "open:0",
        "1:BIOCSBLEN:524288",
        "1:BIOCSETIF:feth4201",
        "1:BIOCGDLT",
        "1:BIOCIMMEDIATE:1",
        "1:BIOCSSEESENT:0",
        "1:BIOCSETF:6",
        "1:BIOCGBLEN",
        "1:BIOCGSTATS",
        "open:0:err16", // узел RX занят: TX его пропускает
        "open:1",
        "2:BIOCSBLEN:4096",
        "2:BIOCSETIF:feth4201",
        "2:BIOCGDLT",
        "2:BIOCSHDRCMPLT:1",
        "2:BIOCSSEESENT:0",
        "2:BIOCSETF:1",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(lock(&w).log, want, "promiscuous mode is never requested");
    {
        let s = lock(&w);
        assert_eq!(s.filters.len(), 2);
        assert_eq!(s.filters[0].0, 1);
        assert_eq!(s.filters[0].1, own_mac_filter(OUR_MAC).to_vec());
        assert_eq!(s.filters[1].0, 2);
        assert_eq!(s.filters[1].1, drop_all_filter().to_vec());
    }
    drop(a);
    assert_eq!(count(&w, "1:close"), 1);
    assert_eq!(count(&w, "2:close"), 1);
}

#[test]
fn rx_reads_use_the_buffer_length_the_kernel_reported() {
    // Ядро урезало запрос: пользовательский буфер обязан быть длины BIOCGBLEN
    // (само `FakeDev::read` проверяет равенство).
    let w = world();
    lock(&w).blen = 65_536;
    let mut a = open_pair(&w);
    push_batch(&w, record(SIZEOF_BPF_HDR, &peer_frame(60)));
    let mut b = buf();
    assert!(recv(&mut a, &mut b).unwrap().is_some());
}

#[test]
fn a_kernel_buffer_too_small_for_one_frame_is_refused_and_closed() {
    let w = world();
    lock(&w).blen = 512;
    let e = open_err(&w);
    assert!(matches!(e, NetError::System(_)), "{e:?}");
    assert_eq!(count(&w, "1:close"), 1);
}

#[test]
fn every_open_failure_after_the_first_fd_closes_both() {
    // (подпись, ошибка устройства или узла, число успешных открытий).
    type Setup = fn(&mut World);
    let cases: Vec<(&str, Setup, usize)> = vec![
        (
            "RX BIOCSBLEN",
            |s| s.setup_fail.push((1, "BIOCSBLEN", EBUSY)),
            1,
        ),
        (
            "RX BIOCSETIF",
            |s| s.setup_fail.push((1, "BIOCSETIF", EBUSY)),
            1,
        ),
        (
            "RX BIOCGDLT",
            |s| s.setup_fail.push((1, "BIOCGDLT", EBUSY)),
            1,
        ),
        (
            "RX BIOCIMMEDIATE",
            |s| s.setup_fail.push((1, "BIOCIMMEDIATE", EBUSY)),
            1,
        ),
        (
            "RX BIOCSSEESENT",
            |s| s.setup_fail.push((1, "BIOCSSEESENT", EBUSY)),
            1,
        ),
        (
            "RX BIOCSETF",
            |s| s.setup_fail.push((1, "BIOCSETF", EBUSY)),
            1,
        ),
        (
            "RX BIOCGBLEN",
            |s| s.setup_fail.push((1, "BIOCGBLEN", EBUSY)),
            1,
        ),
        ("RX baseline stats", |s| s.stats.push_back(Err(EBUSY)), 1),
        (
            "TX open",
            |s| {
                s.open_errors.insert(1, EBUSY);
                s.node_count = 2
            },
            1,
        ),
        (
            "TX BIOCSBLEN",
            |s| s.setup_fail.push((2, "BIOCSBLEN", EBUSY)),
            2,
        ),
        (
            "TX BIOCSETIF",
            |s| s.setup_fail.push((2, "BIOCSETIF", EBUSY)),
            2,
        ),
        (
            "TX BIOCGDLT",
            |s| s.setup_fail.push((2, "BIOCGDLT", EBUSY)),
            2,
        ),
        (
            "TX BIOCSHDRCMPLT",
            |s| s.setup_fail.push((2, "BIOCSHDRCMPLT", EBUSY)),
            2,
        ),
        (
            "TX BIOCSSEESENT",
            |s| s.setup_fail.push((2, "BIOCSSEESENT", EBUSY)),
            2,
        ),
        (
            "TX BIOCSETF",
            |s| s.setup_fail.push((2, "BIOCSETF", EBUSY)),
            2,
        ),
    ];
    for (label, tweak, opened) in cases {
        let w = world();
        tweak(&mut lock(&w));
        let e = open_err(&w);
        assert!(
            !matches!(e, NetError::UnsupportedPlatform),
            "{label}: {e:?}"
        );
        let closes = (1..=2)
            .map(|d| count(&w, &format!("{d}:close")))
            .sum::<usize>();
        assert_eq!(closes, opened, "{label}: {:?}", lock(&w).log);
        for d in 1..=opened {
            assert_eq!(count(&w, &format!("{d}:close")), 1, "{label}: device {d}");
        }
    }
}

#[test]
fn setup_errors_map_to_the_documented_kinds() {
    for (e, kind) in [
        (ENXIO, "mismatch"),
        (ENODEV, "mismatch"),
        (EPERM, "permission"),
        (EACCES, "permission"),
        (EBUSY, "system"),
    ] {
        let w = world();
        lock(&w).setup_fail.push((1, "BIOCSETIF", e));
        let got = open_err(&w);
        let ok = matches!(
            (&got, kind),
            (NetError::InterfaceMismatch(_), "mismatch")
                | (NetError::PermissionDenied(_), "permission")
                | (NetError::System(_), "system")
        );
        assert!(ok, "errno {e}: {got:?}");
    }
}

#[test]
fn non_ethernet_dlt_is_unsupported_link_and_closes() {
    for dlt in [0, 12, 105, 127, 0xffff_ffff] {
        let w = world();
        lock(&w).dlt = dlt;
        let e = open_err(&w);
        assert!(
            matches!(e, NetError::UnsupportedLink(_)),
            "dlt {dlt}: {e:?}"
        );
        assert_eq!(count(&w, "1:close"), 1, "dlt {dlt}");
        assert_eq!(count(&w, "2:close"), 0, "TX was never opened");
        assert!(
            !lock(&w).log.iter().any(|l| l.contains("BIOCIMMEDIATE")),
            "no setup after a wrong DLT"
        );
    }
}

#[test]
fn eacces_on_every_device_is_permission_denied_with_the_grant_hint() {
    let w = world();
    {
        let mut s = lock(&w);
        s.node_count = 16;
        for n in 0..16 {
            s.open_errors.insert(n, EACCES);
        }
    }
    let e = open_err(&w);
    match e {
        NetError::PermissionDenied(m) => {
            assert!(m.contains("0600 root:wheel"), "{m}");
            assert!(m.contains("macos-lab bpf-access --grant"), "{m}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        lock(&w).log.len(),
        16,
        "every node was tried once, then ENOENT"
    );
}

#[test]
fn ebusy_devices_are_skipped() {
    let w = world();
    {
        let mut s = lock(&w);
        for n in 0..3 {
            s.open_errors.insert(n, EBUSY);
        }
    }
    let a = open_pair(&w);
    let opens: Vec<String> = lock(&w)
        .log
        .iter()
        .filter(|l| l.starts_with("open:"))
        .cloned()
        .collect();
    assert_eq!(
        opens,
        [
            "open:0:err16",
            "open:1:err16",
            "open:2:err16",
            "open:3",
            "open:0:err16",
            "open:1:err16",
            "open:2:err16",
            "open:3:err16",
            "open:4"
        ]
    );
    drop(a);

    // Все заняты и ни одного EACCES: это System, а не PermissionDenied.
    let w = world();
    {
        let mut s = lock(&w);
        s.node_count = 4;
        for n in 0..4 {
            s.open_errors.insert(n, EBUSY);
        }
    }
    assert!(matches!(open_err(&w), NetError::System(_)));
    // Один EACCES среди занятых: PermissionDenied.
    let w = world();
    {
        let mut s = lock(&w);
        s.node_count = 3;
        s.open_errors.insert(0, EBUSY);
        s.open_errors.insert(1, EACCES);
        s.open_errors.insert(2, EBUSY);
    }
    assert!(matches!(open_err(&w), NetError::PermissionDenied(_)));
}

#[test]
fn no_nodes_at_all_is_a_system_error() {
    let w = world();
    lock(&w).node_count = 0;
    assert!(matches!(open_err(&w), NetError::System(_)));
}

#[test]
fn bad_bindings_are_refused_before_any_descriptor_is_opened() {
    let mut cases = Vec::new();
    let mut b = binding();
    b.link_type = LinkType::Raw;
    cases.push(("raw link", b, "unsupported"));
    let mut b = binding();
    b.source_mac = [0; 6];
    cases.push(("zero mac", b, "mismatch"));
    let mut b = binding();
    b.source_mac = [0x01, 0, 0x5e, 0, 0, 1];
    cases.push(("multicast mac", b, "mismatch"));
    let mut b = binding();
    b.next_hop_mac = b.source_mac;
    cases.push(("source == next hop", b, "mismatch"));
    for (label, b, want) in cases {
        let w = world();
        let e = open_with(&mut FakeOpener { w: Arc::clone(&w) }, &b)
            .err()
            .unwrap_or_else(|| panic!("{label}"));
        match (&e, want) {
            (NetError::UnsupportedLink(_), "unsupported") => {}
            (NetError::InterfaceMismatch(_), "mismatch") => {}
            _ => panic!("{label}: {e:?}"),
        }
        assert!(check_binding(&b).is_err(), "{label}");
        assert!(lock(&w).log.is_empty(), "{label}: nothing was opened");
    }
}

// ---------------------------------------------------------------- общий runtime

fn engine_pair(a: crate::OpenedAdapter) -> (AdapterPair, crate::NetStatsHandle) {
    (a.io, a.stats)
}

fn start(p: &ReadyPlan, io: AdapterPair, attempt: u8) -> rmasscan_engine::EngineHandle {
    Engine::start(p.clone(), io, EngineOptions::new([1; 16], [attempt; 16])).unwrap()
}

fn finish(h: rmasscan_engine::EngineHandle) -> (rmasscan_engine::Outcome, Vec<Event>) {
    h.join_drain().unwrap()
}

fn replies(events: &[Event]) -> Vec<rmasscan_core::receive::Reply> {
    events
        .iter()
        .flat_map(|e| match e {
            Event::Results { replies } => replies.clone(),
            _ => vec![],
        })
        .collect()
}

fn syn_ack_responder(w: &Shared) {
    let mut s = lock(w);
    s.responder = Some(Arc::new(|f: &[u8]| {
        reply_to_syn(f, 0x12).into_iter().collect()
    }));
    s.echo_tx = true;
}

#[test]
fn a_full_scan_through_the_engine_completes_with_exactly_one_advance_per_sent() {
    let w = world();
    syn_ack_responder(&w);
    let p = plan(1e6, 1);
    let (io, stats) = engine_pair(open_pair(&w));
    let (out, events) = finish(start(&p, io, 2));
    assert_eq!(out.reason, Reason::Completed, "{out:?}");
    assert_eq!(out.progress.sent, PROBES);
    assert_eq!(out.progress.next_index, PROBES);
    assert_eq!(out.rx_health.kernel_drops, Some(0));
    assert_eq!(replies(&events).len() as u64, PROBES);
    let s = stats.snapshot();
    assert_eq!((s.tx_sent, s.tx_uncertain, s.tx_errors), (PROBES, 0, 0));
    assert_eq!(
        s.rx_outgoing, PROBES,
        "our own echoed SYNs were dropped before parsing"
    );
    assert_eq!(s.rx_packets, PROBES);
    assert_eq!(s.kernel_drops, Some(0));
    let st = lock(&w);
    assert_eq!(st.write_calls as u64, PROBES);
    // Каждый кадр плана ушёл ровно один раз и по порядку.
    for (i, f) in st.written.iter().enumerate() {
        assert_eq!(*f, syn_frame(&p, i));
    }
}

#[test]
fn an_uncertain_send_fails_the_run_without_checkpoint_retry_or_more_sends() {
    let w = world();
    let p = plan(1e6, 1);
    let full = syn_frame(&p, 0).len();
    lock(&w).writes.extend([Ok(full), Ok(full), Ok(10)]);
    syn_ack_responder(&w);
    let (io, _stats) = engine_pair(open_pair(&w));
    let (out, events) = finish(start(&p, io, 2));
    assert_eq!(out.reason, Reason::Failed(FailReason::TxUncertain));
    assert_eq!(out.progress.sent, 2);
    assert_eq!(out.progress.next_index, 2);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::CheckpointReady { .. }))
    );
    assert_eq!(
        lock(&w).write_calls,
        3,
        "no retry, nothing after the outcome"
    );
    assert_eq!(
        count(&w, "1:close") + count(&w, "2:close"),
        2,
        "both fds closed"
    );
}

#[test]
fn stop_ends_the_run_quickly_and_nothing_is_sent_afterwards() {
    let w = world();
    syn_ack_responder(&w);
    let p = plan(10.0, 3); // медленный TX, длинное ожидание ответов
    let (io, stats) = engine_pair(open_pair(&w));
    let h = start(&p, io, 2);
    while h.progress().sent < 2 {
        std::thread::sleep(Duration::from_millis(5));
    }
    let t = std::time::Instant::now();
    h.stop();
    let (out, _) = finish(h);
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert_eq!(out.reason, Reason::Stopped, "{out:?}");
    // join вернулся: потоков движка больше нет, записи не растут.
    let at_join = lock(&w).write_calls;
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(lock(&w).write_calls, at_join, "a worker wrote after Stop");
    assert_eq!(stats.snapshot().tx_sent as usize, at_join);
    assert_eq!(count(&w, "1:close") + count(&w, "2:close"), 2);
}

#[test]
fn pause_stops_tx_then_resume_continues_without_gaps_or_duplicates() {
    let w = world();
    syn_ack_responder(&w);
    let p = plan(40.0, 1);
    let (io, _stats) = engine_pair(open_pair(&w));
    let h = start(&p, io, 2);
    while h.progress().sent < 3 {
        std::thread::sleep(Duration::from_millis(5));
    }
    let t = std::time::Instant::now();
    h.pause();
    while h.outcome().is_none() {
        assert!(t.elapsed() < Duration::from_secs(4), "pause did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
    let cp = h.checkpoint().expect("a paused run carries a checkpoint");
    let (out, _) = finish(h);
    assert_eq!(out.reason, Reason::Paused, "{out:?}");
    assert_eq!(cp.next_index, out.progress.sent);
    assert_eq!(lock(&w).written.len() as u64, cp.next_index);

    // Новая попытка: свои дескрипторы и новый attempt_id.
    let (io2, _) = engine_pair(open_pair(&w));
    let h2 = Engine::resume(
        p.clone(),
        cp.clone(),
        io2,
        EngineOptions::new([1; 16], [3; 16]),
    )
    .unwrap();
    let (out2, _) = finish(h2);
    assert_eq!(out2.reason, Reason::Completed, "{out2:?}");
    let all = lock(&w).written.clone();
    assert_eq!(
        all.len() as u64,
        PROBES,
        "exactly one write per probe across both legs"
    );
    for (i, f) in all.iter().enumerate() {
        assert_eq!(*f, syn_frame(&p, i), "probe {i}");
    }
}

#[test]
fn rx_loss_and_stats_errors_fail_the_run_and_keep_the_results() {
    let w = world();
    syn_ack_responder(&w);
    let p = plan(1e6, 1);
    let (io, _) = engine_pair(open_pair(&w));
    lock(&w).stats_drop = 3; // потери буфера BPF
    let (out, events) = finish(start(&p, io, 2));
    assert!(
        matches!(
            out.reason,
            Reason::Failed(FailReason::RxLoss { kernel_drops: 3 })
        ),
        "{out:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::CheckpointReady { .. }))
    );

    let w = world();
    syn_ack_responder(&w);
    let (io, _) = engine_pair(open_pair(&w));
    // После первого успешного чтения каждое следующее падает (и итоговое тоже).
    {
        let mut s = lock(&w);
        s.stats.push_back(Ok(BpfStat::default()));
        s.stats.extend(std::iter::repeat_n(Err(EBUSY), 50));
    }
    let (out, _) = finish(start(&p, io, 2));
    assert!(
        matches!(out.reason, Reason::Failed(FailReason::RxError(ref m)) if m.contains("BIOCGSTATS")),
        "{out:?}"
    );
    assert_eq!(out.rx_health.kernel_drops, None, "never a cached zero");
}

struct PanicTx {
    inner: Box<dyn Tx>,
    at: usize,
    n: usize,
}
impl Tx for PanicTx {
    fn send(&mut self, frame: &[u8], t: Duration) -> Result<SendStatus, IoError> {
        if self.n == self.at {
            panic!("injected tx panic");
        }
        self.n += 1;
        self.inner.send(frame, t)
    }
}

#[test]
fn a_worker_panic_ends_the_run_and_closes_every_descriptor() {
    let w = world();
    syn_ack_responder(&w);
    let p = plan(1e6, 1);
    let (io, stats) = engine_pair(open_pair(&w));
    let io = AdapterPair {
        tx: Box::new(PanicTx {
            inner: io.tx,
            at: 2,
            n: 0,
        }),
        rx: io.rx,
    };
    let (out, events) = finish(start(&p, io, 2));
    assert_eq!(
        out.reason,
        Reason::Failed(FailReason::WorkerPanicked),
        "{out:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::CheckpointReady { .. }))
    );
    assert_eq!(lock(&w).write_calls, 2);
    assert_eq!(count(&w, "1:close"), 1, "RX closed normally");
    assert_eq!(
        count(&w, "2:close"),
        1,
        "unwinding closed the TX descriptor"
    );
    assert_eq!(stats.snapshot().tx_sent, 2);
}

// ---------------------------------------------------------------- маршрутизация

#[test]
fn rx_and_stats_hit_only_the_rx_descriptor_writes_only_the_tx_descriptor_and_each_closes_once() {
    let w = world();
    push_batch(&w, record(SIZEOF_BPF_HDR, &peer_frame(60)));
    let mut a = open_pair(&w);
    let mut b = buf();
    assert!(recv(&mut a, &mut b).unwrap().is_some());
    a.io.rx.health(MS50).unwrap();
    let f = own_frame(60);
    a.io.tx.send(&f, MS50).unwrap();
    a.io.tx.send(&f, MS50).unwrap();

    assert!(calls(&w, "read:1") >= 1, "RX reads the RX descriptor");
    assert_eq!(calls(&w, "read:2"), 0, "RX never reads the TX descriptor");
    assert!(
        calls(&w, "stats:1") >= 2,
        "baseline plus health on the RX descriptor"
    );
    assert_eq!(calls(&w, "stats:2"), 0);
    assert_eq!(calls(&w, "write:2"), 2, "writes go to the TX descriptor");
    assert_eq!(calls(&w, "write:1"), 0);
    drop(a);
    assert_eq!(count(&w, "1:close"), 1);
    assert_eq!(count(&w, "2:close"), 1);
}

#[test]
fn rx_record_shorter_than_an_ethernet_header_is_dropped_as_truncated() {
    let w = world();
    let mut a = open_pair(&w);
    let good = peer_frame(60);
    let mut batch = record(SIZEOF_BPF_HDR, &[]);
    batch.extend(record(SIZEOF_BPF_HDR, &[0xab; 13]));
    batch.extend(record(SIZEOF_BPF_HDR, &good));
    push_batch(&w, batch);
    let mut b = buf();
    let n = recv(&mut a, &mut b).unwrap().expect("the good frame");
    assert_eq!(&b[..n], good.as_slice(), "never Some(0) and never a runt");
    let s = a.stats.snapshot();
    assert_eq!((s.rx_truncated, s.rx_packets, s.rx_errors), (2, 1, 0));
}

#[test]
fn io_budget_leaves_margin_below_the_50ms_contract() {
    // Один вызов (poll округляется вверх, таймеры опаздывают) обязан уложиться в 50 мс:
    // бюджет + худшее измеренное спайком превышение (14,3 мс) + 2 мс запаса <= 50 мс.
    let worst_overshoot = Duration::from_micros(14_300);
    let margin = Duration::from_millis(2);
    assert!(
        IO_BUDGET + worst_overshoot + margin <= Duration::from_millis(50),
        "{IO_BUDGET:?}"
    );
}
