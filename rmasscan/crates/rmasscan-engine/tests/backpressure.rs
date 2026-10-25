//! Ограниченная очередь результатов: переполнение, Stop/Pause при полной
//! очереди, независимость отмены от потребителя.

mod common;

use std::time::{Duration, Instant};

use common::*;
use rmasscan_engine::fake::{FakeAdapter, ManualClock};
use rmasscan_engine::{Event, FailReason, Reason};

#[test]
fn overflow_fails_with_consumer_too_slow_and_keeps_received_results() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    synack_responder(&fake);
    let mut o = opts();
    o.result_capacity = 4;
    let h = start_manual(&p, &fake, &clock, o);
    // Потребитель не читает вообще.
    wait_for("outcome", || h.outcome().is_some());
    let (out, events) = h.join_drain().unwrap();
    assert_eq!(out.reason, Reason::Failed(FailReason::ConsumerTooSlow));
    assert_ne!(out.reason, Reason::Completed);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::CheckpointReady { .. })),
        "overflow is not a valid pause"
    );
    // Уже принятые результаты сохранены для drain.
    assert_eq!(all_replies(&events).len(), 4);
    assert_eq!(out.progress.received, 4);
    assert_eq!(fake.alive_handles(), 0);
}

#[test]
fn overflow_stops_tx_without_further_sends() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    synack_responder(&fake);
    let mut o = opts();
    o.result_capacity = 1;
    let h = start_manual(&p, &fake, &clock, o);
    wait_for("outcome", || h.outcome().is_some());
    let calls = fake.send_calls();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(fake.send_calls(), calls);
    drop(h);
}

/// Очередь заполнена ровно до ёмкости (не переполнена); wait не истекает.
fn run_with_full_queue(
    wait_secs: u32,
) -> (
    rmasscan_engine::EngineHandle,
    FakeAdapter,
    std::sync::Arc<ManualClock>,
) {
    let p = plan(1_000_000.0, wait_secs);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new(); // без часов: время в drain двигает тест
    synack_responder(&fake);
    let mut o = opts();
    o.result_capacity = PROBES as usize;
    let h = start_manual(&p, &fake, &clock, o);
    wait_for("queue full", || {
        h.progress().received == PROBES && h.progress().sent == PROBES
    });
    (h, fake, clock)
}

#[test]
fn stop_with_full_queue_is_fast_and_keeps_results() {
    let (h, fake, _clock) = run_with_full_queue(3600);
    assert!(h.outcome().is_none());
    let t = Instant::now();
    h.stop();
    let (out, events) = h.join_drain().unwrap();
    assert!(t.elapsed() < Duration::from_secs(1));
    assert_eq!(out.reason, Reason::Stopped);
    assert_eq!(all_replies(&events).len() as u64, PROBES);
    assert_eq!(fake.alive_handles(), 0);
}

#[test]
fn pause_with_full_queue_still_completes_the_pause() {
    // Пауза после того, как TX закончил, ничего не меняет: Completed.
    // Здесь проверяем именно независимость от потребителя.
    let (h, _fake, clock) = run_with_full_queue(3);
    h.pause();
    advance_until(&clock, Duration::from_secs(10), "outcome", || {
        h.outcome().is_some()
    });
    let events = drain_to_finished(&h);
    assert_eq!(all_replies(&events).len() as u64, PROBES);
    assert!(matches!(
        events.last(),
        Some(Event::Finished {
            reason: Reason::Completed
        })
    ));
    h.join().unwrap();
}

#[test]
fn pause_at_rate_1_with_full_queue_is_not_blocked_by_consumer() {
    let p = plan(1.0, 3);
    let clock = ManualClock::new();
    clock.set_hold(true);
    let fake = FakeAdapter::new();
    synack_responder(&fake);
    let mut o = opts();
    o.result_capacity = 1;
    let h = start_manual(&p, &fake, &clock, o);
    wait_for("first send + reply queued", || {
        fake.sent_count() == 1 && h.progress().received == 1
    });
    // Очередь (ёмкость 1) полна, потребитель молчит.
    h.pause();
    // RX фиксирует срок wait, увидев конец TX; время двигается, пока не будет итога.
    advance_until(&clock, Duration::from_secs(5), "outcome", || {
        h.outcome().is_some()
    });
    let (out, events) = h.join_drain().unwrap();
    assert_eq!(out.reason, Reason::Paused);
    assert!(events.contains(&Event::CheckpointReady { next_index: 1 }));
    assert_eq!(all_replies(&events).len(), 1);
}

#[test]
fn drop_with_full_queue_joins_workers() {
    let (h, fake, _clock) = run_with_full_queue(3600);
    drop(h);
    assert_eq!(fake.alive_handles(), 0);
}
