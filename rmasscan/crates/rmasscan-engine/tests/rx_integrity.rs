//! RX integrity: исход скана зависит от измеренной достоверности приёма.
//! Потеря, отсутствие статистики или ошибка её чтения никогда не дают
//! Completed/Paused/CheckpointReady, а принятые ранее результаты остаются.

mod common;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use common::*;
use rmasscan_engine::fake::{FakeAdapter, HealthStep, ManualClock};
use rmasscan_engine::io::{AdapterPair, IoError, Rx, RxHealth};
use rmasscan_engine::{Engine, EngineHandle, Event, FailReason, MAX_IO_TIMEOUT, Outcome, Reason};

struct Run {
    outcome: Outcome,
    events: Vec<Event>,
    checkpoint: bool,
}

fn finish(h: EngineHandle) -> Run {
    let events = drain_to_finished(&h);
    let checkpoint = h.checkpoint().is_some();
    let outcome = h.join().unwrap();
    Run {
        outcome,
        events,
        checkpoint,
    }
}

fn has_checkpoint_event(r: &Run) -> bool {
    r.events
        .iter()
        .any(|e| matches!(e, Event::CheckpointReady { .. }))
}

/// Часы заморожены (фейк без часов), wait=0: ни одной периодической проверки,
/// только финальная.
fn frozen_run(fake: &FakeAdapter, wait: u32) -> (EngineHandle, Arc<ManualClock>) {
    let clock = ManualClock::new();
    synack_responder(fake);
    let h = start_manual(&plan(1_000_000.0, wait), fake, &clock, opts());
    (h, clock)
}

fn assert_failed_without_checkpoint(r: &Run, reason: FailReason) {
    assert_eq!(r.outcome.reason, Reason::Failed(reason));
    assert!(!r.checkpoint, "checkpoint() must be None");
    assert!(!has_checkpoint_event(r), "no CheckpointReady on failure");
    // Принятые до отказа результаты выданы до Finished.
    assert_eq!(
        all_replies(&r.events).len() as u64,
        r.outcome.progress.received
    );
}

#[test]
fn verified_zero_drops_completes() {
    let fake = FakeAdapter::new();
    let (h, _c) = frozen_run(&fake, 0);
    let r = finish(h);
    assert_eq!(r.outcome.reason, Reason::Completed);
    assert_eq!(r.outcome.rx_health.kernel_drops, Some(0));
    assert!(fake.health_calls() >= 1, "final health is mandatory");
    assert_eq!(fake.alive_handles(), 0);
}

#[test]
fn drops_fail_with_rx_loss() {
    let fake = FakeAdapter::new();
    fake.set_health(HealthStep::Drops(1));
    let (h, _c) = frozen_run(&fake, 0);
    let r = finish(h);
    assert_failed_without_checkpoint(&r, FailReason::RxLoss { kernel_drops: 1 });
    assert_eq!(r.outcome.rx_health.kernel_drops, Some(1));
}

#[test]
fn unavailable_statistics_fail_and_are_not_zero() {
    let fake = FakeAdapter::new();
    fake.set_health(HealthStep::Unavailable);
    let (h, _c) = frozen_run(&fake, 0);
    let r = finish(h);
    assert_failed_without_checkpoint(&r, FailReason::RxStatsUnavailable);
    assert_eq!(r.outcome.rx_health.kernel_drops, None);
}

#[test]
fn health_error_fails_and_earlier_zero_does_not_mask_it() {
    let fake = FakeAdapter::new();
    // Первая проверка чистая, последняя падает: ошибка не подменяется нулём.
    fake.script_health([HealthStep::Drops(0)]);
    fake.set_health(HealthStep::Fail("stats read failed".into()));
    let clock = ManualClock::new();
    synack_responder(&fake);
    let h = start_manual(&plan(1_000_000.0, 3600), &fake, &clock, opts());
    wait_for("tx done", || h.progress().sent == PROBES);
    clock.advance(Duration::from_millis(250)); // периодическая: Some(0)
    wait_for("first health", || fake.health_calls() >= 1);
    clock.advance(Duration::from_millis(250)); // периодическая: ошибка
    wait_for("outcome", || h.outcome().is_some());
    let r = finish(h);
    assert_failed_without_checkpoint(&r, FailReason::RxError("stats read failed".into()));
    assert_eq!(r.outcome.rx_health.kernel_drops, None);
}

#[test]
fn drops_seen_only_by_the_final_health_still_fail() {
    let fake = FakeAdapter::new();
    fake.set_health(HealthStep::Drops(1));
    let (h, _c) = frozen_run(&fake, 0);
    let r = finish(h);
    assert_eq!(fake.health_calls(), 1, "frozen clock: only the final check");
    assert_failed_without_checkpoint(&r, FailReason::RxLoss { kernel_drops: 1 });
}

#[test]
fn health_runs_periodically_without_incoming_frames() {
    let fake = FakeAdapter::new();
    let (h, clock) = frozen_run(&fake, 3600);
    wait_for("tx done", || h.progress().sent == PROBES);
    std::thread::sleep(Duration::from_millis(30));
    let before = fake.health_calls();
    assert_eq!(before, 0, "frozen clock: no check before the interval");
    clock.advance(Duration::from_millis(250));
    wait_for("periodic health", || fake.health_calls() > before);
    assert!(h.outcome().is_none());
    // Потеря между проверками находится периодической проверкой, не ожидая wait.
    fake.set_health(HealthStep::Drops(2));
    clock.advance(Duration::from_millis(250));
    wait_for("outcome", || h.outcome().is_some());
    let r = finish(h);
    assert_failed_without_checkpoint(&r, FailReason::RxLoss { kernel_drops: 2 });
}

#[test]
fn drops_at_final_health_fail_pause_and_withhold_checkpoint() {
    for (drops, expect_pause) in [(0u64, true), (4, false)] {
        let fake = FakeAdapter::new();
        fake.set_health(HealthStep::Drops(drops));
        synack_responder(&fake);
        let clock = ManualClock::new();
        let cell: Arc<OnceLock<rmasscan_engine::CancelHandle>> = Arc::default();
        let AdapterPair { tx, rx } = fake.pair();
        let tx = Box::new(PauseTx {
            inner: tx,
            at: 4,
            block_calls: 1,
            sent: 0,
            blocked: 0,
            cancel: cell.clone(),
        });
        let c: Arc<dyn rmasscan_core::throttle::Clock + Send + Sync> = clock.clone();
        let h = Engine::start_with_clock(plan(1_000_000.0, 0), AdapterPair { tx, rx }, opts(), c)
            .unwrap();
        cell.set(h.cancel_handle()).ok();
        let r = finish(h);
        if expect_pause {
            assert_eq!(r.outcome.reason, Reason::Paused, "control: clean pause");
            assert!(r.checkpoint && has_checkpoint_event(&r));
        } else {
            assert_failed_without_checkpoint(
                &r,
                FailReason::RxLoss {
                    kernel_drops: drops,
                },
            );
        }
    }
}

#[test]
fn drops_at_final_health_fail_stop() {
    let fake = FakeAdapter::new();
    fake.set_health(HealthStep::Drops(3));
    let (h, _c) = frozen_run(&fake, 3600);
    wait_for("tx done", || h.progress().sent == PROBES);
    h.stop();
    let r = finish(h);
    assert_failed_without_checkpoint(&r, FailReason::RxLoss { kernel_drops: 3 });
}

#[test]
fn earlier_consumer_overflow_is_kept_but_last_statistics_are_recorded() {
    let fake = FakeAdapter::new();
    fake.set_health(HealthStep::Drops(5));
    let clock = ManualClock::new();
    synack_responder(&fake);
    let mut o = opts();
    o.result_capacity = 1;
    let h = start_manual(&plan(1_000_000.0, 3600), &fake, &clock, o);
    // The consumer reads nothing until the outcome, so the one-slot queue overflows
    // deterministically. A concurrent reader could keep it from overflowing, and the full
    // 3600-probe scan then outran the 10 s drain on Windows, where each idle RX sleep of the
    // fake lasts a timer tick instead of 100 us.
    wait_for("outcome", || h.outcome().is_some());
    let r = finish(h);
    assert_eq!(
        r.outcome.reason,
        Reason::Failed(FailReason::ConsumerTooSlow),
        "first failure wins"
    );
    assert_eq!(r.outcome.rx_health.kernel_drops, Some(5));
    assert!(!r.checkpoint && !has_checkpoint_event(&r));
    // Потребитель мог читать параллельно, поэтому число принятых не фиксируем:
    // важно, что принятое не потеряно.
    assert!(!all_replies(&r.events).is_empty());
    assert_eq!(
        all_replies(&r.events).len() as u64,
        r.outcome.progress.received
    );
}

/// Обёртка, записывающая timeout health и (опционально) паникующая.
struct SpyRx {
    inner: Box<dyn Rx>,
    seen: Arc<Mutex<Vec<Duration>>>,
    panic_in_health: bool,
}

impl Rx for SpyRx {
    fn recv(&mut self, b: &mut [u8], t: Duration) -> Result<Option<usize>, IoError> {
        self.inner.recv(b, t)
    }
    fn health(&mut self, t: Duration) -> Result<RxHealth, IoError> {
        self.seen.lock().unwrap().push(t);
        if self.panic_in_health {
            panic!("injected health panic");
        }
        self.inner.health(t)
    }
}

fn spy_run(panic_in_health: bool) -> (Run, Arc<Mutex<Vec<Duration>>>) {
    let fake = FakeAdapter::new();
    synack_responder(&fake);
    let clock = ManualClock::new();
    let seen: Arc<Mutex<Vec<Duration>>> = Arc::default();
    let AdapterPair { tx, rx } = fake.pair();
    let rx = Box::new(SpyRx {
        inner: rx,
        seen: seen.clone(),
        panic_in_health,
    });
    let c: Arc<dyn rmasscan_core::throttle::Clock + Send + Sync> = clock;
    let h =
        Engine::start_with_clock(plan(1_000_000.0, 0), AdapterPair { tx, rx }, opts(), c).unwrap();
    (finish(h), seen)
}

#[test]
fn health_is_called_within_the_adapter_call_limit() {
    let (r, seen) = spy_run(false);
    assert_eq!(r.outcome.reason, Reason::Completed);
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|t| *t <= MAX_IO_TIMEOUT && !t.is_zero()));
}

#[test]
fn panic_in_health_is_worker_panicked_without_checkpoint() {
    let (r, _) = spy_run(true);
    assert_failed_without_checkpoint(&r, FailReason::WorkerPanicked);
}
