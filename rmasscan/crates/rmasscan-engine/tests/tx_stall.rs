//! Watchdog постоянного `WouldBlockUnsent`: окно от первой неудачной попытки
//! кадра, сброс только после `Sent`, throttle-сон не считается, Stop/Pause
//! остаются быстрыми. Офлайн, детерминированные часы.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use rmasscan_core::throttle::Clock;
use rmasscan_engine::fake::{FakeAdapter, ManualClock, TxStep};
use rmasscan_engine::io::{AdapterPair, IoError, SendStatus, Tx};
use rmasscan_engine::{Engine, Event, FailReason, Reason, StartError};

fn no_checkpoint(events: &[Event]) -> bool {
    !events
        .iter()
        .any(|e| matches!(e, Event::CheckpointReady { .. }))
}

/// Ждёт итог; после `sent == PROBES` двигает часы, чтобы отработал `wait`
/// (адаптер без часов: окно watchdog двигает только сон TX).
fn finish_with_wait(h: &rmasscan_engine::EngineHandle, clock: &Arc<ManualClock>) {
    wait_for("outcome", || {
        if h.progress().sent >= PROBES {
            clock.advance(Duration::from_millis(500));
        }
        h.outcome().is_some()
    });
}

#[test]
fn persistent_would_block_fails_with_tx_stalled_after_ten_seconds() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    // Без часов в адаптере: RX-простой не двигает общее время, окно двигает
    // только сон TX.
    let fake = FakeAdapter::new();
    synack_responder(&fake);
    fake.script_tx([TxStep::Sent, TxStep::Sent]);
    fake.set_would_block_forever(true);
    // Шлюз: 10 с окна по ManualClock проходят за миллисекунды реального
    // времени, и отказ (halt = FAIL) не ждёт RX. Если RX не успел вызвать
    // recv, он законно выходит, не читая адаптер: ответы НЕ приняты, и
    // проверять было бы нечего. Поэтому TX держится внутри второй отправки
    // (часы стоят, окно ещё не открыто), пока движок не примет оба ответа.
    // Отпускает тест; если тест упал раньше, `release` уничтожается при
    // раскрутке стека и TX не зависает.
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = Mutex::new(released);
    fake.set_send_hook(move |n| {
        if n == 2 {
            let _ = released
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10));
        }
    });
    let h = start_manual(&p, &fake, &clock, opts());
    wait_for("both replies accepted", || h.progress().received == 2);
    release.send(()).unwrap();
    wait_for("outcome", || h.outcome().is_some());
    let cp = h.checkpoint();
    let (out, events) = h.join_drain().unwrap();
    let Reason::Failed(FailReason::TxStalled { idle_millis }) = out.reason else {
        panic!("expected TxStalled, got {:?}", out.reason);
    };
    assert!(
        (10_000..=10_010).contains(&idle_millis),
        "idle_millis={idle_millis}"
    );
    assert_eq!(out.progress.sent, 2);
    assert_eq!(out.progress.next_index, 2);
    assert_eq!(fake.sent_count(), 2);
    // 10 с / 1 мс backoff: ровно 10_000 неудачных попыток. Новая попытка на
    // границе дедлайна не начинается (проверка перед send в engine.rs).
    assert_eq!(fake.would_block_count(), 10_000);
    assert!(cp.is_none());
    assert!(no_checkpoint(&events));
    // Принятые до отказа результаты доступны.
    assert_eq!(out.progress.received, 2);
    assert_eq!(all_replies(&events).len(), 2);
    assert_eq!(fake.alive_handles(), 0);
}

#[test]
fn transient_would_block_resets_window_after_each_sent() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new();
    synack_responder(&fake);
    let mut steps = vec![TxStep::WouldBlockUnsent; 40];
    steps.push(TxStep::Sent);
    steps.extend(vec![TxStep::WouldBlockUnsent; 40]);
    steps.push(TxStep::Sent);
    fake.script_tx(steps);
    let mut o = opts();
    // Каждое окно ~40 мс < 50 мс; суммарно 80 мс > 50 мс.
    o.tx_stall_timeout = Duration::from_millis(50);
    let h = start_manual(&p, &fake, &clock, o);
    finish_with_wait(&h, &clock);
    let (out, _events) = h.join_drain().unwrap();
    assert_eq!(out.reason, Reason::Completed);
    assert_eq!(fake.would_block_count(), 80);
    // Каждый кадр ушёл ровно один раз и по порядку.
    assert_eq!(fake.sent_frames(), reference_frames(&p, PROBES as usize));
    assert_eq!(out.progress.sent, PROBES);
    assert_eq!(out.progress.next_index, PROBES);
}

#[test]
fn throttle_sleep_at_rate_one_does_not_trip_watchdog() {
    let p = plan(1.0, 3);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new();
    // Короткий backpressure внутри допустимого окна на втором кадре.
    let mut steps = vec![TxStep::Sent];
    steps.extend(vec![TxStep::WouldBlockUnsent; 10]);
    fake.script_tx(steps);
    let mut o = opts();
    o.tx_stall_timeout = Duration::from_millis(100);
    let h = start_manual(&p, &fake, &clock, o);
    // Между кадрами throttle спит ~1 с по часам: во много раз больше окна.
    wait_for("3 frames", || h.progress().sent >= 3);
    h.stop();
    let out = join_within(h, Duration::from_secs(1));
    assert_eq!(out.reason, Reason::Stopped);
    assert!(clock.sleep_calls() > 0);
    let sent = fake.sent_frames();
    assert_eq!(sent, reference_frames(&p, sent.len()));
}

#[test]
fn zero_stall_timeout_is_rejected_before_threads_start() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new();
    let mut o = opts();
    o.tx_stall_timeout = Duration::ZERO;
    let c: Arc<dyn Clock + Send + Sync> = clock.clone();
    match Engine::start_with_clock(p.clone(), fake.pair(), o, c) {
        Err(StartError::InvalidOptions(m)) => assert!(m.contains("tx_stall_timeout"), "{m}"),
        Err(e) => panic!("wrong error: {e:?}"),
        Ok(_) => panic!("zero timeout accepted"),
    }
    assert_eq!(fake.send_calls(), 0);
    assert_eq!(fake.alive_handles(), 0);
}

#[test]
fn stop_inside_long_would_block_is_fast() {
    let p = plan(1_000_000.0, 3600);
    let clock = ManualClock::new();
    clock.set_hold(true); // время не идёт: watchdog не сработает, ждём Stop
    let fake = FakeAdapter::new();
    fake.set_would_block_forever(true);
    let h = start_manual(&p, &fake, &clock, opts());
    wait_for("blocking", || fake.would_block_count() > 5);
    let t = Instant::now();
    h.stop();
    let out = join_within(h, Duration::from_secs(1));
    assert!(t.elapsed() < Duration::from_secs(1));
    assert_eq!(out.reason, Reason::Stopped);
    assert_eq!(out.progress.sent, 0);
}

#[test]
fn pause_inside_long_would_block_is_fast_and_checkpoints() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    clock.set_hold(true);
    let fake = FakeAdapter::new();
    fake.script_tx([TxStep::Sent, TxStep::Sent, TxStep::Sent]);
    fake.set_would_block_forever(true);
    let h = start_manual(&p, &fake, &clock, opts());
    wait_for("blocking", || fake.would_block_count() > 5);
    let t = Instant::now();
    h.pause();
    clock.set_hold(false);
    wait_for("paused", || {
        clock.advance(Duration::from_millis(500));
        h.outcome().is_some()
    });
    let events = drain_to_finished(&h);
    let cp = h.checkpoint().expect("checkpoint after clean pause");
    let out = join_within(h, Duration::from_secs(1));
    assert!(t.elapsed() < Duration::from_secs(1));
    assert_eq!(out.reason, Reason::Paused);
    assert_eq!(cp.next_index, 3);
    assert!(!no_checkpoint(&events));
}

/// Tx-обёртка: на вызове с номером `at_call` двигает часы на `jump` и отдаёт
/// `then`; прочие вызовы идут во внутренний адаптер.
struct JumpTx {
    inner: Box<dyn Tx>,
    clock: Arc<ManualClock>,
    calls: usize,
    at_call: usize,
    jump: Duration,
    then: Option<SendStatus>,
}

impl Tx for JumpTx {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError> {
        self.calls += 1;
        if self.calls == self.at_call {
            self.clock.advance(self.jump);
            if let Some(s) = self.then {
                if s == SendStatus::Sent {
                    // Реально отправляем во внутренний адаптер.
                    return self.inner.send(frame, timeout);
                }
                return Ok(s);
            }
        }
        if self.calls < self.at_call {
            return Ok(SendStatus::WouldBlockUnsent);
        }
        self.inner.send(frame, timeout)
    }
}

fn jump_pair(
    fake: &FakeAdapter,
    clock: &Arc<ManualClock>,
    at_call: usize,
    jump: Duration,
    then: SendStatus,
) -> AdapterPair {
    let AdapterPair { tx, rx } = fake.pair();
    AdapterPair {
        tx: Box::new(JumpTx {
            inner: tx,
            clock: clock.clone(),
            calls: 0,
            at_call,
            jump,
            then: Some(then),
        }),
        rx,
    }
}

#[test]
fn sent_from_call_that_crosses_deadline_is_counted() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new();
    let mut o = opts();
    o.tx_stall_timeout = Duration::from_millis(50);
    // Вызов 1: WouldBlock (окно открыто). Вызов 2: часы уходят за границу
    // внутри вызова, он возвращает Sent: кадр засчитан, скан продолжается.
    let pair = jump_pair(
        &fake,
        &clock,
        2,
        Duration::from_millis(100),
        SendStatus::Sent,
    );
    let c: Arc<dyn Clock + Send + Sync> = clock.clone();
    let h = Engine::start_with_clock(p.clone(), pair, o, c).unwrap();
    finish_with_wait(&h, &clock);
    let (out, _) = h.join_drain().unwrap();
    assert_eq!(out.reason, Reason::Completed);
    assert_eq!(fake.sent_frames(), reference_frames(&p, PROBES as usize));
    assert_eq!(out.progress.sent, PROBES);
}

#[test]
fn no_new_send_starts_after_deadline() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new();
    let mut o = opts();
    o.tx_stall_timeout = Duration::from_millis(50);
    // Вызов 1 уходит за границу окна и отвечает WouldBlock: второй send
    // начинаться не должен.
    let pair = jump_pair(
        &fake,
        &clock,
        1,
        Duration::from_millis(60),
        SendStatus::WouldBlockUnsent,
    );
    let c: Arc<dyn Clock + Send + Sync> = clock.clone();
    let h = Engine::start_with_clock(p.clone(), pair, o, c).unwrap();
    wait_for("outcome", || h.outcome().is_some());
    let (out, _) = h.join_drain().unwrap();
    let Reason::Failed(FailReason::TxStalled { idle_millis }) = out.reason else {
        panic!("expected TxStalled, got {:?}", out.reason);
    };
    assert!(idle_millis >= 60, "idle_millis={idle_millis}");
    assert_eq!(fake.send_calls(), 0, "inner adapter must not be reached");
    assert_eq!(out.progress.sent, 0);
}

#[test]
fn uncertain_and_tx_error_keep_priority_over_stall() {
    for (steps, want) in [
        (
            vec![
                TxStep::WouldBlockUnsent,
                TxStep::WouldBlockUnsent,
                TxStep::Uncertain,
            ],
            FailReason::TxUncertain,
        ),
        (
            vec![TxStep::WouldBlockUnsent, TxStep::Fail("boom".into())],
            FailReason::TxError("boom".into()),
        ),
    ] {
        let p = plan(1_000_000.0, 3);
        let clock = ManualClock::new();
        let fake = FakeAdapter::new();
        fake.script_tx(steps);
        let h = start_manual(&p, &fake, &clock, opts());
        wait_for("outcome", || h.outcome().is_some());
        let (out, events) = h.join_drain().unwrap();
        assert_eq!(out.reason, Reason::Failed(want));
        assert!(no_checkpoint(&events));
        assert_eq!(out.progress.next_index, 0);
    }
}
