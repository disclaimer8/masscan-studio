//! Жизненный цикл runtime: complete, stop, pause, отказы TX/RX, Drop, враждебный
//! приём, dedup, coalescing. Офлайн, на фиктивном адаптере. Реальное время
//! тратят только тесты, которым нужен настоящий throttle на rate=1 (< 1 с).

mod common;

use std::time::{Duration, Instant};

use common::*;
use rmasscan_core::receive::{PortStatus, Reply};
use rmasscan_engine::fake::{ManualClock, RxStep, TxStep, reply_to_syn};
use rmasscan_engine::{DedupCache, Event, FailReason, MAX_DEDUP_ENTRIES, Reason, StartError};

fn failed(o: &rmasscan_engine::Outcome) -> &FailReason {
    match &o.reason {
        Reason::Failed(f) => f,
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn complete_scan_delivers_all_results_then_one_finished() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    synack_responder(&fake);
    let h = start_manual(&p, &fake, &clock, opts());

    let events = drain_to_finished(&h);
    assert!(matches!(events.first(), Some(Event::Started { range }) if *range == PROBES));
    let fin: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, Event::Finished { .. }))
        .collect();
    assert_eq!(fin.len(), 1, "exactly one terminal event");
    assert!(matches!(
        events.last(),
        Some(Event::Finished {
            reason: Reason::Completed
        })
    ));
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::CheckpointReady { .. }))
    );
    let replies = all_replies(&events);
    assert_eq!(replies.len() as u64, PROBES);
    assert!(replies.iter().all(|r| r.status == PortStatus::Open));

    let o = h.join().unwrap();
    assert_eq!(o.reason, Reason::Completed);
    assert_eq!(o.progress.sent, PROBES);
    assert_eq!(o.progress.next_index, PROBES);
    // Отправлены ровно эталонные кадры по порядку.
    assert_eq!(fake.sent_frames(), reference_frames(&p, PROBES as usize));
    // Оба handle освобождены (потоки закончили).
    assert_eq!(fake.alive_handles(), 0);
}

#[test]
fn no_sends_after_terminal_outcome() {
    let p = plan(1_000_000.0, 1);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    let h = start_manual(&p, &fake, &clock, opts());
    wait_for("outcome", || h.outcome().is_some());
    let calls = fake.send_calls();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(fake.send_calls(), calls);
    h.join().unwrap();
}

#[test]
fn stop_immediately_finishes_stopped_quickly() {
    let p = plan(1.0, 3);
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    let h = start_real(&p, &fake);
    h.stop();
    let o = join_within(h, Duration::from_secs(1));
    assert_eq!(o.reason, Reason::Stopped);
    assert_eq!(fake.alive_handles(), 0);
}

#[test]
fn stop_at_rate_1_interrupts_real_throttle_wait() {
    // Настоящие часы: после первой отправки следующий кадр ждёт ~1 с.
    let p = plan(1.0, 3);
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    let h = start_real(&p, &fake);
    wait_for("first send", || fake.sent_count() == 1);
    std::thread::sleep(Duration::from_millis(120)); // TX уже внутри throttle
    let t = Instant::now();
    h.stop();
    let o = h.join().unwrap();
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert_eq!(o.reason, Reason::Stopped);
    assert_eq!(o.progress.sent, 1);
    assert_eq!(fake.sent_count(), 1);
}

#[test]
fn stop_during_deterministic_throttle_wait() {
    // Часы в режиме hold: сон не продвигает время, TX застрял в throttle.
    let p = plan(1.0, 3);
    let clock = ManualClock::new();
    clock.set_hold(true);
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    let h = start_manual(&p, &fake, &clock, opts());
    wait_for("tx inside throttle sleep", || {
        fake.sent_count() == 1 && clock.sleep_calls() > 2
    });
    let t = Instant::now();
    h.stop();
    let o = h.join().unwrap();
    assert!(t.elapsed() < Duration::from_secs(1));
    assert_eq!(o.reason, Reason::Stopped);
    assert_eq!(fake.sent_count(), 1);
    assert_eq!(fake.alive_handles(), 0);
}

#[test]
fn stop_during_drain_does_not_wait_for_wait() {
    // Фейк без часов: время в drain не движется, wait=3600 никогда не истечёт.
    let p = plan(1_000_000.0, 3600);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    let h = start_manual(&p, &fake, &clock, opts());
    wait_for("all sent", || fake.sent_count() as u64 == PROBES);
    std::thread::sleep(Duration::from_millis(30));
    assert!(h.outcome().is_none(), "still draining");
    h.stop();
    let o = join_within(h, Duration::from_secs(1));
    assert_eq!(o.reason, Reason::Stopped);
    assert_eq!(o.progress.sent, PROBES);
}

#[test]
fn stop_with_empty_rx_and_idle_consumer() {
    let p = plan(1.0, 3);
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    let h = start_real(&p, &fake);
    // Потребитель ничего не читает; RX пуст.
    wait_for("first send", || fake.sent_count() >= 1);
    h.stop();
    let o = join_within(h, Duration::from_secs(1));
    assert_eq!(o.reason, Reason::Stopped);
}

#[test]
fn pause_at_rate_1_stops_tx_then_collects_final_replies_for_wait() {
    let p = plan(1.0, 3);
    let clock = ManualClock::new();
    clock.set_hold(true);
    let fake = rmasscan_engine::fake::FakeAdapter::new(); // без часов: время двигает тест
    let h = start_manual(&p, &fake, &clock, opts());
    wait_for("tx inside throttle sleep", || {
        fake.sent_count() == 1 && clock.sleep_calls() > 2
    });

    let t = Instant::now();
    h.pause();
    // TX прекращён быстро: после паузы новых отправок нет.
    std::thread::sleep(Duration::from_millis(100));
    assert!(t.elapsed() < Duration::from_secs(1));
    let calls = fake.send_calls();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(fake.send_calls(), calls);
    // wait ещё не истёк: итога нет, RX принимает.
    assert!(h.outcome().is_none());
    let sent0 = fake.sent_frames()[0].clone();
    fake.push_frame(reply_to_syn(&sent0, 0x12).unwrap());
    clock.advance(Duration::from_secs(1));
    std::thread::sleep(Duration::from_millis(50));
    assert!(h.outcome().is_none(), "wait=3s not elapsed after 1s");
    clock.advance(Duration::from_secs(3));

    let events = drain_to_finished(&h);
    assert!(matches!(
        events.last(),
        Some(Event::Finished {
            reason: Reason::Paused
        })
    ));
    assert!(
        events.contains(&Event::CheckpointReady { next_index: 1 }),
        "{events:?}"
    );
    assert_eq!(all_replies(&events).len(), 1);
    let o = h.join().unwrap();
    assert_eq!(o.progress.next_index, 1);
    assert_eq!(o.progress.sent, 1);
    assert_eq!(fake.alive_handles(), 0);
}

#[test]
fn cancellation_is_checked_before_every_send_inside_a_batch() {
    // Большой план и быстрые виртуальные часы: batch растёт выше 1. Stop,
    // поданный изнутри отправки #5000, обязан остановить TX до #5001, а не
    // в конце пачки.
    let p = plan_with("10.0.0.0/16", 1_000_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    let h = start_manual_paused_hook(&p, &fake, &clock);
    let o = join_within(h, Duration::from_secs(5));
    assert_eq!(o.reason, Reason::Stopped);
    assert_eq!(fake.send_calls(), 5000);
    assert_eq!(o.progress.sent, 5000);
}

fn start_manual_paused_hook(
    p: &rmasscan_core::probe::ReadyPlan,
    fake: &rmasscan_engine::fake::FakeAdapter,
    clock: &std::sync::Arc<ManualClock>,
) -> rmasscan_engine::EngineHandle {
    // Хук должен знать CancelHandle, а он есть только после старта: передаём
    // через OnceLock; отправки #1..#4999 хук пропускает.
    let cell: std::sync::Arc<std::sync::OnceLock<rmasscan_engine::CancelHandle>> =
        std::sync::Arc::default();
    let c2 = cell.clone();
    fake.set_send_hook(move |n| {
        if n == 5000 {
            let c = loop {
                if let Some(c) = c2.get() {
                    break c;
                }
                std::thread::yield_now();
            };
            c.stop();
        }
    });
    let h = start_manual(p, fake, clock, opts());
    cell.set(h.cancel_handle()).ok();
    h
}

#[test]
fn stop_after_pause_overrides_it_and_skips_checkpoint() {
    let p = plan(1.0, 3600);
    let clock = ManualClock::new();
    clock.set_hold(true);
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    let h = start_manual(&p, &fake, &clock, opts());
    wait_for("first send", || fake.sent_count() == 1);
    h.pause();
    std::thread::sleep(Duration::from_millis(50));
    h.stop();
    let events = drain_to_finished(&h);
    assert!(matches!(
        events.last(),
        Some(Event::Finished {
            reason: Reason::Stopped
        })
    ));
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::CheckpointReady { .. }))
    );
}

#[test]
fn partial_send_failure_does_not_skip_unacknowledged_frames() {
    let p = plan(1_000_000.0, 1);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    fake.script_tx([TxStep::Sent, TxStep::Sent, TxStep::Fail("boom".into())]);
    let h = start_manual(&p, &fake, &clock, opts());
    let o = join_within(h, Duration::from_secs(5));
    assert!(matches!(failed(&o), FailReason::TxError(m) if m == "boom"));
    assert_eq!(o.progress.sent, 2);
    // Индекс стоит на первом неподтверждённом кадре.
    assert_eq!(o.progress.next_index, 2);
    assert_eq!(fake.sent_frames(), reference_frames(&p, 2));
    // Нет безопасного checkpoint у Failed.
    assert_ne!(o.reason, Reason::Paused);
}

#[test]
fn would_block_unsent_retries_same_frame_without_advancing() {
    let p = plan(1_000_000.0, 1);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    fake.script_tx([
        TxStep::Sent,
        TxStep::WouldBlockUnsent,
        TxStep::WouldBlockUnsent,
        TxStep::Sent,
    ]);
    let h = start_manual(&p, &fake, &clock, opts());
    let o = join_within(h, Duration::from_secs(5));
    assert_eq!(o.reason, Reason::Completed);
    assert_eq!(o.progress.sent, PROBES);
    assert_eq!(fake.would_block_count(), 2);
    assert_eq!(fake.send_calls(), PROBES + 2);
    // Ни один кадр не пропущен и не продублирован.
    assert_eq!(fake.sent_frames(), reference_frames(&p, PROBES as usize));
}

/// Часы-обёртка: считает сны ровно по 1 мс (backoff после WouldBlockUnsent).
struct BackoffClock {
    inner: std::sync::Arc<ManualClock>,
    backoffs: std::sync::atomic::AtomicU64,
}

impl rmasscan_core::throttle::Clock for BackoffClock {
    fn now_micros(&self) -> u64 {
        self.inner.now_micros()
    }
    fn sleep_micros(&self, us: u64) {
        if us == 1_000 {
            self.backoffs
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        self.inner.sleep_micros(us);
    }
}

#[test]
fn would_block_unsent_backs_off_1ms_on_the_injected_clock() {
    // This checks TX backoff, not RX draining. Let only the injected TX clock
    // advance time: a concurrently idle fake RX otherwise jumps that clock by
    // its entire timeout on every poll and can spuriously trip the stall limit.
    let p = plan(1_000_000.0, 0);
    let manual = ManualClock::new();
    let clock = std::sync::Arc::new(BackoffClock {
        inner: manual.clone(),
        backoffs: Default::default(),
    });
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    fake.script_tx(std::iter::repeat_n(TxStep::WouldBlockUnsent, 30));
    let c: std::sync::Arc<dyn rmasscan_core::throttle::Clock + Send + Sync> = clock.clone();
    let h = rmasscan_engine::Engine::start_with_clock(p.clone(), fake.pair(), opts(), c).unwrap();
    let o = join_within(h, Duration::from_secs(5));
    assert_eq!(o.reason, Reason::Completed);
    assert_eq!(fake.would_block_count(), 30);
    // Каждый отказ сопровождается ожиданием 1 мс по ИНЖЕКТИРОВАННЫМ часам.
    assert!(
        clock.backoffs.load(std::sync::atomic::Ordering::Acquire) >= 30,
        "no backoff after WouldBlockUnsent"
    );
    assert_eq!(fake.sent_frames(), reference_frames(&p, PROBES as usize));
}

fn persistent_would_block() -> (
    rmasscan_core::probe::ReadyPlan,
    rmasscan_engine::fake::FakeAdapter,
    rmasscan_engine::EngineHandle,
) {
    let p = plan(1_000_000.0, 1);
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    fake.script_tx(std::iter::repeat_n(TxStep::WouldBlockUnsent, 100_000));
    let h = start_real(&p, &fake);
    wait_for("tx retrying", || fake.would_block_count() >= 3);
    std::thread::sleep(Duration::from_millis(150));
    // Ограниченное ожидание: без backoff 100_000 попыток кончились бы
    // за миллисекунды (CPU spin) и пошли бы отправки.
    assert!(
        fake.would_block_count() < 2_000,
        "busy retry loop: {} attempts in ~150ms",
        fake.would_block_count()
    );
    assert_eq!(fake.sent_count(), 0, "cursor must not advance");
    (p, fake, h)
}

#[test]
fn persistent_would_block_waits_between_attempts_and_pause_completes() {
    let (_p, fake, h) = persistent_would_block();
    let t = Instant::now();
    h.pause();
    wait_for("tx quiet after pause", || {
        let c = fake.send_calls();
        std::thread::sleep(Duration::from_millis(20));
        c == fake.send_calls()
    });
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    let o = join_within(h, Duration::from_secs(5));
    assert_eq!(o.reason, Reason::Paused);
    assert_eq!(o.progress.sent, 0);
    assert_eq!(o.progress.next_index, 0);
    assert_eq!(fake.sent_count(), 0);
}

#[test]
fn persistent_would_block_waits_between_attempts_and_stop_completes() {
    let (_p, fake, h) = persistent_would_block();
    let t = Instant::now();
    h.stop();
    let o = h.join().unwrap();
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert_eq!(o.reason, Reason::Stopped);
    assert_eq!(o.progress.next_index, 0);
    assert_eq!(fake.sent_count(), 0);
    assert_eq!(fake.alive_handles(), 0);
}

#[test]
fn uncertain_send_fails_without_checkpoint_or_retry() {
    let p = plan(1_000_000.0, 1);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    fake.script_tx([TxStep::Sent, TxStep::Uncertain]);
    let h = start_manual(&p, &fake, &clock, opts());
    let events = drain_to_finished(&h);
    let o = h.join().unwrap();
    assert_eq!(*failed(&o), FailReason::TxUncertain);
    assert_eq!(o.progress.sent, 1, "Uncertain is not counted as sent");
    assert_eq!(o.progress.next_index, 1);
    assert_eq!(fake.send_calls(), 2, "no hidden retry after Uncertain");
    assert_eq!(
        fake.uncertain_frames(),
        reference_frames(&p, 2)[1..].to_vec()
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::CheckpointReady { .. }))
    );
    // Pause после этого не превращает отказ в паузу.
    assert!(matches!(
        events.last(),
        Some(Event::Finished {
            reason: Reason::Failed(FailReason::TxUncertain)
        })
    ));
}

#[test]
fn rx_error_fails_the_scan_and_stops_tx() {
    let p = plan(1.0, 3);
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    fake.push_rx(RxStep::Fail("link down".into()));
    let h = start_real(&p, &fake);
    let o = join_within(h, Duration::from_secs(1));
    assert!(matches!(failed(&o), FailReason::RxError(m) if m == "link down"));
    let calls = fake.send_calls();
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(fake.send_calls(), calls, "TX stopped after the failure");
    assert_eq!(fake.alive_handles(), 0);
}

#[test]
fn dropping_the_handle_stops_and_joins_both_workers() {
    let p = plan(1.0, 3600);
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    let h = start_real(&p, &fake);
    wait_for("first send", || fake.sent_count() == 1);
    let t = Instant::now();
    drop(h);
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    // Потоки joined: оба handle адаптера уничтожены, отправок больше нет.
    assert_eq!(fake.alive_handles(), 0);
    let calls = fake.send_calls();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(fake.send_calls(), calls);
}

#[test]
fn dropping_the_handle_while_draining_joins_workers() {
    let p = plan(1_000_000.0, 3600);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    synack_responder(&fake);
    let h = start_manual(&p, &fake, &clock, opts());
    wait_for("all sent", || fake.sent_count() as u64 == PROBES);
    drop(h);
    assert_eq!(fake.alive_handles(), 0);
}

fn good_synack(p: &rmasscan_core::probe::ReadyPlan) -> Vec<u8> {
    reply_to_syn(&reference_frames(p, 1)[0], 0x12).unwrap()
}

#[test]
fn malformed_frames_are_dropped_and_scan_keeps_running() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    let good = good_synack(&p);

    let mut bad: Vec<Vec<u8>> = vec![
        vec![],              // пустой
        vec![0xff; 5],       // обрезанный Ethernet
        good[..30].to_vec(), // обрезанный IPv4
        good[..40].to_vec(), // обрезанный TCP
        vec![0x5a; 1600],    // длиннее 1514
    ];
    let mut vlan = good.clone();
    vlan[12..14].copy_from_slice(&[0x81, 0x00]);
    bad.push(vlan);
    let mut frag = good.clone();
    frag[14 + 6] = 0x20; // MF
    bad.push(frag);
    let mut ver = good.clone();
    ver[14] = 0x65;
    bad.push(ver);
    let mut ihl = good.clone();
    ihl[14] = 0x44;
    bad.push(ihl);
    let mut total = good.clone();
    total[14 + 2..14 + 4].copy_from_slice(&0xffffu16.to_be_bytes());
    bad.push(total);
    let mut doff = good.clone();
    doff[14 + 20 + 12] = 0x10;
    bad.push(doff);
    let mut badsum = good.clone();
    badsum[14 + 20 + 16] ^= 0xff;
    bad.push(badsum);
    for (i, b) in bad.iter().enumerate() {
        fake.push_frame(b.clone());
        // чужой cookie (правильная форма, неверный ack)
        let mut foreign = good.clone();
        foreign[14 + 20 + 8] ^= i as u8 | 1;
        fake.push_frame(foreign);
    }
    let nbad = bad.len() as u64 * 2;
    synack_responder(&fake); // настоящие ответы приходят ПОСЛЕ мусора
    let h = start_manual(&p, &fake, &clock, opts());
    let events = drain_to_finished(&h);
    let o = h.join().unwrap();
    assert_eq!(
        o.reason,
        Reason::Completed,
        "garbage must not fail the scan"
    );
    assert_eq!(all_replies(&events).len() as u64, PROBES);
    assert!(o.progress.discarded >= nbad, "{:?}", o.progress);
}

#[test]
fn duplicate_replies_are_collapsed_and_counted() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    fake.push_frame_n(&good_synack(&p), 5);
    let h = start_manual(&p, &fake, &clock, opts());
    let events = drain_to_finished(&h);
    let o = h.join().unwrap();
    assert_eq!(all_replies(&events).len(), 1);
    assert_eq!(o.progress.duplicates, 4);
}

/// Вставляет 802.1Q-тег (VID 1) между MAC-адресами и EtherType.
fn vlan_tag(frame: &[u8]) -> Vec<u8> {
    let mut v = frame[..12].to_vec();
    v.extend_from_slice(&[0x81, 0x00, 0x00, 0x01]);
    v.extend_from_slice(&frame[12..]);
    v
}

/// VLAN остаётся явно неподдержанным: корректный по содержимому ответ в
/// 802.1Q-теге не становится результатом, считается отброшенным, скан не
/// падает. Контроль: те же ответы без тега доставляются.
#[test]
fn vlan_tagged_replies_are_unsupported_discarded_and_never_delivered() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    fake.set_responder(|f| {
        reply_to_syn(f, 0x12)
            .map(|r| vlan_tag(&r))
            .into_iter()
            .collect()
    });
    let h = start_manual(&p, &fake, &clock, opts());
    let events = drain_to_finished(&h);
    let o = h.join().unwrap();
    assert_eq!(
        o.reason,
        Reason::Completed,
        "VLAN input must not fail the scan"
    );
    assert!(
        all_replies(&events).is_empty(),
        "tagged replies were delivered"
    );
    assert_eq!(o.progress.received, 0);
    assert_eq!(o.progress.discarded, PROBES, "{:?}", o.progress);

    // Контроль: без тега те же ответы доставляются.
    let clock2 = ManualClock::new();
    let fake2 = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock2.clone());
    synack_responder(&fake2);
    let h2 = start_manual(&p, &fake2, &clock2, opts());
    let events2 = drain_to_finished(&h2);
    h2.join().unwrap();
    assert_eq!(all_replies(&events2).len() as u64, PROBES);
}

/// Bounded FIFO dedup на уровне engine: при ёмкости 2 повтор не обновляет
/// порядок, поэтому после вытеснения тот же ответ доставляется снова, а
/// повтор до вытеснения подавляется. Строгая C-семантика не обещается.
#[test]
fn engine_dedup_is_bounded_fifo_and_redelivers_after_eviction() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    let probes = reference_frames(&p, 3);
    let [a, b, c] = [0, 1, 2].map(|i| reply_to_syn(&probes[i], 0x12).unwrap());
    // A, B, A (повтор подавлен, порядок не обновлён), C (вытесняет A, а не B:
    // FIFO, не LRU), A снова (доставлен повторно).
    for f in [&a, &b, &a, &c, &a] {
        fake.push_frame(f.clone());
    }
    let mut o = opts();
    o.dedup_capacity = 2;
    let h = start_manual(&p, &fake, &clock, o);
    let events = drain_to_finished(&h);
    let out = h.join().unwrap();
    assert_eq!(out.reason, Reason::Completed);
    let replies = all_replies(&events);
    let key = |r: &Reply| (r.remote_ip, r.remote_port);
    let ra = reply_key(&a, &p);
    assert_eq!(replies.len(), 4, "A, B, C and A again: {replies:?}");
    assert_eq!(replies.iter().filter(|r| key(r) == ra).count(), 2);
    assert_eq!(out.progress.duplicates, 1, "{:?}", out.progress);
    assert_eq!(out.progress.received, 4);
}

fn reply_key(frame: &[u8], p: &rmasscan_core::probe::ReadyPlan) -> (u32, u16) {
    let r =
        rmasscan_core::receive::parse_reply(frame, rmasscan_core::packet::LinkType::Ethernet, p)
            .unwrap()
            .unwrap();
    (r.remote_ip, r.remote_port)
}

#[test]
fn progress_events_coalesce_while_consumer_is_idle() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    synack_responder(&fake);
    let mut o = opts();
    o.progress_interval = Duration::from_micros(1);
    let h = start_manual(&p, &fake, &clock, o);
    wait_for("outcome", || h.outcome().is_some());
    let (out, events) = h.join_drain().unwrap();
    let progress: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::Progress(p) => Some(*p),
            _ => None,
        })
        .collect();
    assert!(progress.len() <= 1, "coalesced: {progress:?}");
    assert_eq!(progress.last().copied(), Some(out.progress));
}

#[test]
fn observing_the_outcome_does_not_drop_received_events() {
    let p = plan(1_000_000.0, 1);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    synack_responder(&fake);
    let h = start_manual(&p, &fake, &clock, opts());
    wait_for("outcome", || h.outcome().is_some());
    assert_eq!(h.outcome().unwrap().reason, Reason::Completed);
    let events = drain_to_finished(&h);
    assert_eq!(all_replies(&events).len() as u64, PROBES);
    assert!(matches!(events.last(), Some(Event::Finished { .. })));
    assert_eq!(
        h.try_event(),
        Err(std::sync::mpsc::TryRecvError::Disconnected)
    );
    h.join().unwrap();
}

#[test]
fn result_batches_respect_event_batch_limit() {
    let p = plan(1_000_000.0, 1);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    synack_responder(&fake);
    let mut o = opts();
    o.event_batch_limit = 5;
    let h = start_manual(&p, &fake, &clock, o);
    wait_for("outcome", || h.outcome().is_some());
    let events = drain_to_finished(&h);
    let sizes: Vec<usize> = events
        .iter()
        .filter_map(|e| match e {
            Event::Results { replies } => Some(replies.len()),
            _ => None,
        })
        .collect();
    assert_eq!(sizes.iter().sum::<usize>() as u64, PROBES);
    assert!(sizes.iter().all(|&n| (1..=5).contains(&n)), "{sizes:?}");
    h.join().unwrap();
}

#[test]
fn invalid_options_are_rejected() {
    let p = plan(100.0, 1);
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    let mut o = opts();
    o.result_capacity = 0;
    let e = rmasscan_engine::Engine::start(p.clone(), fake.pair(), o).err();
    assert!(matches!(e, Some(StartError::InvalidOptions(_))));
}

// ---- dedup ----

fn reply(ip: u32, port: u16) -> Reply {
    Reply {
        remote_ip: ip,
        remote_port: port,
        local_ip: IP_ME,
        local_port: 40000,
        status: PortStatus::Open,
        tcp_flags: 0x12,
        ttl: 64,
    }
}

#[test]
fn dedup_is_fifo_bounded_and_allows_repeat_after_eviction() {
    let mut d = DedupCache::new(3);
    let (a, b, c, e) = (reply(1, 80), reply(2, 80), reply(3, 80), reply(4, 80));
    assert!(d.insert(&a) && d.insert(&b) && d.insert(&c));
    assert!(!d.insert(&a), "known tuple is a repeat");
    assert!(d.insert(&e), "evicts the oldest (a)");
    assert_eq!(d.len(), 3);
    // Повтор не обновляет порядок (FIFO, не LRU): a вытеснена первой.
    assert!(d.insert(&a), "repeat after eviction is allowed");
    assert!(!d.insert(&c) || d.len() == 3);
    assert_eq!(d.len(), 3);
}

#[test]
fn dedup_never_exceeds_100k_entries() {
    assert_eq!(DedupCache::new(10_000_000).capacity(), MAX_DEDUP_ENTRIES);
    assert_eq!(DedupCache::new(0).capacity(), 1);
    let mut d = DedupCache::new(usize::MAX);
    for i in 0..(MAX_DEDUP_ENTRIES as u32 + 5_000) {
        assert!(d.insert(&reply(i, 80)));
    }
    assert_eq!(d.len(), MAX_DEDUP_ENTRIES);
    assert!(d.insert(&reply(0, 80)), "oldest was evicted");
}

// ------------------------------------------------- worker panic (2B-2) ---

/// Rx-обёртка: второй вызов `recv` ждёт барьер (тест уже убедился, что первый
/// кадр принят) и паникует.
struct PanicRx {
    inner: Box<dyn rmasscan_engine::Rx>,
    calls: usize,
    gate: std::sync::Arc<std::sync::Barrier>,
}

impl rmasscan_engine::Rx for PanicRx {
    fn recv(
        &mut self,
        buffer: &mut [u8],
        timeout: Duration,
    ) -> Result<Option<usize>, rmasscan_engine::IoError> {
        self.calls += 1;
        if self.calls == 2 {
            self.gate.wait();
            panic!("injected rx panic");
        }
        self.inner.recv(buffer, timeout)
    }
    fn health(
        &mut self,
        timeout: Duration,
    ) -> Result<rmasscan_engine::RxHealth, rmasscan_engine::IoError> {
        self.inner.health(timeout)
    }
}

/// Tx-обёртка: вторая отправка ждёт барьер (тест уже убедился, что первый кадр
/// подтверждён и его ответ принят) и паникует до передачи кадра.
struct PanicTx {
    inner: Box<dyn rmasscan_engine::Tx>,
    calls: usize,
    gate: std::sync::Arc<std::sync::Barrier>,
}

impl rmasscan_engine::Tx for PanicTx {
    fn send(
        &mut self,
        frame: &[u8],
        timeout: Duration,
    ) -> Result<rmasscan_engine::SendStatus, rmasscan_engine::IoError> {
        self.calls += 1;
        if self.calls == 2 {
            self.gate.wait();
            panic!("injected tx panic");
        }
        self.inner.send(frame, timeout)
    }
}

fn replies_in(events: &[Event]) -> usize {
    all_replies(events).len()
}

#[test]
fn rx_panic_preserves_accepted_results_on_join_drain() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    fake.push_frame(good_synack(&p));
    let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
    let rmasscan_engine::AdapterPair { tx, rx } = fake.pair();
    let rx = Box::new(PanicRx {
        inner: rx,
        calls: 0,
        gate: gate.clone(),
    });
    let c: std::sync::Arc<dyn rmasscan_core::throttle::Clock + Send + Sync> = clock.clone();
    let h = rmasscan_engine::Engine::start_with_clock(
        p.clone(),
        rmasscan_engine::AdapterPair { tx, rx },
        opts(),
        c,
    )
    .unwrap();

    // Первый кадр принят раньше, чем RX дойдёт до барьера и упадёт.
    wait_for("reply accepted", || h.progress().received == 1);
    gate.wait();
    wait_for("outcome", || h.outcome().is_some());
    assert!(h.checkpoint().is_none(), "a panic yields no checkpoint");

    let (o, events) = h.join_drain().expect("outcome exists: Ok, not Err");
    assert_eq!(o.reason, Reason::Failed(FailReason::WorkerPanicked));
    assert_eq!(o.progress.received, 1);
    assert_eq!(replies_in(&events), 1, "exactly one accepted reply");
    assert!(!events.iter().any(|e| matches!(e, Event::Finished { .. })));
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::CheckpointReady { .. }))
    );
    assert_eq!(fake.alive_handles(), 0, "both handles released");
}

#[test]
fn tx_panic_after_confirmed_send_preserves_results_on_join_drain() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    synack_responder(&fake);
    let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
    let rmasscan_engine::AdapterPair { tx, rx } = fake.pair();
    let tx = Box::new(PanicTx {
        inner: tx,
        calls: 0,
        gate: gate.clone(),
    });
    let c: std::sync::Arc<dyn rmasscan_core::throttle::Clock + Send + Sync> = clock.clone();
    let h = rmasscan_engine::Engine::start_with_clock(
        p.clone(),
        rmasscan_engine::AdapterPair { tx, rx },
        opts(),
        c,
    )
    .unwrap();

    // Первая отправка подтверждена и её ответ принят RX до паники TX.
    wait_for("first reply accepted", || {
        h.progress().sent == 1 && h.progress().received == 1
    });
    gate.wait();
    wait_for("outcome", || h.outcome().is_some());
    assert!(h.checkpoint().is_none(), "a panic yields no checkpoint");

    let (o, events) = h.join_drain().expect("outcome exists: Ok, not Err");
    assert_eq!(o.reason, Reason::Failed(FailReason::WorkerPanicked));
    assert_eq!(o.progress.sent, 1);
    assert_eq!(o.progress.received, 1);
    assert_eq!(replies_in(&events), 1, "exactly one accepted reply");
    assert_eq!(fake.sent_count(), 1, "the panicking send never went out");
    assert_eq!(fake.alive_handles(), 0, "both handles released");
}

#[test]
fn panic_does_not_duplicate_events_already_read() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone());
    fake.push_frame(good_synack(&p));
    let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
    let rmasscan_engine::AdapterPair { tx, rx } = fake.pair();
    let rx = Box::new(PanicRx {
        inner: rx,
        calls: 0,
        gate: gate.clone(),
    });
    let c: std::sync::Arc<dyn rmasscan_core::throttle::Clock + Send + Sync> = clock.clone();
    let h = rmasscan_engine::Engine::start_with_clock(
        p.clone(),
        rmasscan_engine::AdapterPair { tx, rx },
        opts(),
        c,
    )
    .unwrap();
    wait_for("reply accepted", || h.progress().received == 1);
    // Потребитель уже прочитал результат до паники.
    let mut read = Vec::new();
    while replies_in(&read) == 0 {
        read.push(h.recv_event_timeout(Duration::from_secs(5)).unwrap());
    }
    gate.wait();
    wait_for("outcome", || h.outcome().is_some());
    let (o, rest) = h.join_drain().unwrap();
    assert_eq!(o.reason, Reason::Failed(FailReason::WorkerPanicked));
    assert_eq!(replies_in(&read), 1);
    assert_eq!(replies_in(&rest), 0, "already-read events are not repeated");
}
