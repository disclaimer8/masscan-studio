//! Pause и Resume той же последовательности: байтовое совпадение трассы,
//! границы (до первой отправки, последний probe, WouldBlock, завершение во
//! время паузы), отсутствие CheckpointReady на не-паузах. Офлайн.

mod common;

use std::time::Duration;

use common::*;
use rmasscan_core::receive::PortStatus;
use rmasscan_engine::fake::{FakeAdapter, ManualClock, TxStep};
use rmasscan_engine::{Checkpoint, Event, FailReason, Reason};

fn has_checkpoint_event(events: &[Event]) -> bool {
    events
        .iter()
        .any(|e| matches!(e, Event::CheckpointReady { .. }))
}

#[test]
fn pause_at_every_index_then_resume_is_byte_identical() {
    let p = plan(1_000_000.0, 3);
    let reference = reference_frames(&p, PROBES as usize);
    for k in 0..PROBES as usize {
        let a = first_leg(&p, k, 1, 10);
        assert_eq!(a.outcome.reason, Reason::Paused, "k={k}");
        assert!(
            a.events.contains(&Event::CheckpointReady {
                next_index: k as u64
            }),
            "k={k}: {:?}",
            a.events
        );
        let cp = a.checkpoint.clone().expect("checkpoint after clean pause");
        assert_eq!(cp.next_index, k as u64);
        assert_eq!(a.frames.len(), k, "prefix length");

        let b = resume_leg(&p, &cp, usize::MAX, 11);
        assert_eq!(b.outcome.reason, Reason::Completed, "k={k}");
        assert!(!has_checkpoint_event(&b.events));

        let mut joined = a.frames.clone();
        joined.extend(b.frames.clone());
        assert_eq!(joined, reference, "k={k}: prefix + suffix != uninterrupted");
        // Каждый probe получил ровно один ответ (ответы на префикс успели
        // прийти в wait паузы).
        let n = a.replies.len() + b.replies.len();
        assert!(
            a.replies
                .iter()
                .chain(&b.replies)
                .all(|r| r.status == PortStatus::Open)
        );
        assert_eq!(n as u64, PROBES, "k={k}: every probe answered exactly once");
    }
}

#[test]
fn pause_before_first_send_sends_nothing_and_resumes_from_zero() {
    let p = plan(1_000_000.0, 3);
    let a = first_leg(&p, 0, 1, 10);
    assert_eq!(a.outcome.reason, Reason::Paused);
    assert!(a.frames.is_empty());
    assert_eq!(a.outcome.progress.sent, 0);
    let cp = a.checkpoint.unwrap();
    assert_eq!(cp.next_index, 0);
    let b = resume_leg(&p, &cp, usize::MAX, 11);
    assert_eq!(b.frames, reference_frames(&p, PROBES as usize));
}

#[test]
fn pause_on_last_pending_probe_resumes_with_exactly_that_probe() {
    let p = plan(1_000_000.0, 3);
    let last = PROBES as usize - 1;
    let a = first_leg(&p, last, 1, 10);
    assert_eq!(a.outcome.reason, Reason::Paused);
    let cp = a.checkpoint.unwrap();
    assert_eq!(cp.next_index, PROBES - 1);
    let b = resume_leg(&p, &cp, usize::MAX, 11);
    assert_eq!(
        b.frames,
        reference_frames(&p, PROBES as usize)[last..].to_vec()
    );
    assert_eq!(b.outcome.reason, Reason::Completed);
    assert_eq!(b.outcome.progress.next_index, PROBES);
}

#[test]
fn pause_during_would_block_loses_and_duplicates_nothing() {
    let p = plan(1_000_000.0, 3);
    let reference = reference_frames(&p, PROBES as usize);
    for k in [0usize, 1, 7, 15] {
        // Пауза приходит лишь на 6-й подряд WouldBlock на индексе k.
        let a = first_leg(&p, k, 6, 10);
        assert_eq!(a.outcome.reason, Reason::Paused, "k={k}");
        let cp = a.checkpoint.clone().unwrap();
        assert_eq!(cp.next_index, k as u64);
        let b = resume_leg(&p, &cp, usize::MAX, 11);
        let mut joined = a.frames;
        joined.extend(b.frames);
        assert_eq!(joined, reference, "k={k}");
    }
}

#[test]
fn chained_pause_resume_pause_resume_is_byte_identical() {
    let p = plan(1_000_000.0, 3);
    let a = first_leg(&p, 5, 1, 10);
    let cp1 = a.checkpoint.clone().unwrap();
    let b = resume_leg(&p, &cp1, 6, 11);
    assert_eq!(b.outcome.reason, Reason::Paused);
    let cp2 = b.checkpoint.clone().unwrap();
    assert_eq!(cp2.next_index, 11);
    // Происхождение: checkpoint второго отрезка создан попыткой 11.
    assert_eq!(cp2.attempt_id, [11; 16]);
    assert_eq!(cp2.scan_id, cp1.scan_id);
    let c = resume_leg(&p, &cp2, usize::MAX, 12);
    assert_eq!(c.outcome.reason, Reason::Completed);
    let mut joined = a.frames;
    joined.extend(b.frames);
    joined.extend(c.frames);
    assert_eq!(joined, reference_frames(&p, PROBES as usize));
}

#[test]
fn pause_commanded_while_last_probe_is_sent_is_completion_not_checkpoint() {
    // Пауза подана изнутри отправки последнего probe: next_index == range.
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    let cell: std::sync::Arc<std::sync::OnceLock<rmasscan_engine::CancelHandle>> =
        std::sync::Arc::default();
    let c2 = cell.clone();
    fake.set_send_hook(move |n| {
        if n == PROBES as usize {
            let c = loop {
                if let Some(c) = c2.get() {
                    break c;
                }
                std::thread::yield_now();
            };
            c.pause();
        }
    });
    let h = start_manual(&p, &fake, &clock, opts());
    cell.set(h.cancel_handle()).ok();
    let events = drain_to_finished(&h);
    assert!(matches!(
        events.last(),
        Some(Event::Finished {
            reason: Reason::Completed
        })
    ));
    assert!(!has_checkpoint_event(&events));
    assert!(h.checkpoint().is_none());
    assert_eq!(fake.sent_frames(), reference_frames(&p, PROBES as usize));
    h.join().unwrap();
}

#[test]
fn natural_completion_while_paused_stays_completed() {
    // TX уже отправил всё и ждёт wait; Pause после этого ничего не меняет.
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new(); // время двигает тест
    let h = start_manual(&p, &fake, &clock, opts());
    wait_for("all sent", || fake.sent_count() as u64 == PROBES);
    std::thread::sleep(Duration::from_millis(30));
    assert!(h.outcome().is_none(), "still inside wait");
    h.pause();
    advance_until(&clock, Duration::from_secs(10), "outcome", || {
        h.outcome().is_some()
    });
    let events = drain_to_finished(&h);
    assert!(matches!(
        events.last(),
        Some(Event::Finished {
            reason: Reason::Completed
        })
    ));
    assert!(!has_checkpoint_event(&events));
    assert!(h.checkpoint().is_none());
    h.join().unwrap();
}

#[test]
fn only_a_clean_pause_yields_a_checkpoint() {
    let p = plan(1_000_000.0, 1);

    // Uncertain -> Failed, без CheckpointReady и без checkpoint.
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    fake.script_tx([TxStep::Sent, TxStep::Sent, TxStep::Uncertain]);
    let h = start_manual(&p, &fake, &clock, opts());
    let events = drain_to_finished(&h);
    assert!(matches!(
        events.last(),
        Some(Event::Finished {
            reason: Reason::Failed(FailReason::TxUncertain)
        })
    ));
    assert!(!has_checkpoint_event(&events));
    assert!(h.checkpoint().is_none());
    h.join().unwrap();

    // Ошибка TX.
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    fake.script_tx([TxStep::Sent, TxStep::Fail("boom".into())]);
    let h = start_manual(&p, &fake, &clock, opts());
    let events = drain_to_finished(&h);
    assert!(matches!(
        events.last(),
        Some(Event::Finished {
            reason: Reason::Failed(FailReason::TxError(_))
        })
    ));
    assert!(!has_checkpoint_event(&events));
    assert!(h.checkpoint().is_none());
    h.join().unwrap();

    // Stop.
    let slow = plan(1.0, 3);
    let fake = FakeAdapter::new();
    let h = start_real(&slow, &fake);
    wait_for("first send", || fake.sent_count() >= 1);
    h.stop();
    let events = drain_to_finished(&h);
    assert!(matches!(
        events.last(),
        Some(Event::Finished {
            reason: Reason::Stopped
        })
    ));
    assert!(!has_checkpoint_event(&events));
    assert!(h.checkpoint().is_none());
    h.join().unwrap();

    // Stop одновременно с Pause побеждает.
    let fake = FakeAdapter::new();
    let h = start_real(&slow, &fake);
    wait_for("first send", || fake.sent_count() >= 1);
    h.pause();
    h.stop();
    let events = drain_to_finished(&h);
    assert!(matches!(
        events.last(),
        Some(Event::Finished {
            reason: Reason::Stopped
        })
    ));
    assert!(!has_checkpoint_event(&events));
    assert!(h.checkpoint().is_none());
    h.join().unwrap();
}

#[test]
fn full_result_queue_fails_and_never_offers_a_checkpoint() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    synack_responder(&fake);
    let mut o = opts();
    o.result_capacity = 2;
    let h = start_manual(&p, &fake, &clock, o);
    // Потребитель намеренно НЕ вычитывает результаты: RX наполняет очередь из 2
    // ответов и на следующем пуше детерминированно падает Failed(ConsumerTooSlow).
    // Раньше тест вычитывал события конкурентно (`drain_to_finished`) и зависел
    // от того, успеет ли RX опередить потребителя, — на части раннеров (ubuntu,
    // windows) потребитель успевал опустошать очередь, скан завершался Completed,
    // и тест флапал. Итог выставляется независимо от чтения событий.
    wait_for("overflow -> ConsumerTooSlow", || {
        matches!(
            h.outcome().map(|o| o.reason),
            Some(Reason::Failed(FailReason::ConsumerTooSlow))
        )
    });
    // На провале checkpoint не предлагается.
    assert!(h.checkpoint().is_none());
    // Принятые до переполнения результаты сохраняются (ровно 2, capacity=2);
    // Finished сюда не входит.
    let (outcome, events) = h.join_drain().unwrap();
    assert!(matches!(
        outcome.reason,
        Reason::Failed(FailReason::ConsumerTooSlow)
    ));
    assert_eq!(all_replies(&events).len(), 2);
    assert!(!has_checkpoint_event(&events));
}

#[test]
fn checkpoint_carries_scan_attempt_and_versions() {
    let p = plan(1_000_000.0, 3);
    let a = first_leg(&p, 4, 1, 10);
    let cp: Checkpoint = a.checkpoint.unwrap();
    assert_eq!(cp.scan_id, [1; 16]);
    assert_eq!(cp.attempt_id, [10; 16]);
    assert_eq!(
        cp.format_version,
        rmasscan_engine::CHECKPOINT_FORMAT_VERSION
    );
    assert_eq!(cp.engine_version, rmasscan_engine::ENGINE_ALGORITHM_VERSION);
    assert_eq!(cp.job_digest, rmasscan_engine::job_digest(&p));
    assert_eq!(Checkpoint::from_bytes(&cp.to_bytes()).unwrap(), cp);
}
