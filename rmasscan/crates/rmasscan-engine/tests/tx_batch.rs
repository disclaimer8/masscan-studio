//! Пачечный контракт `Tx`: точный учёт префикса, окно stall, Stop/Pause на
//! границе пачки, resume без дыр и дублей. Офлайн, `FakeAdapter` и
//! `ManualClock`; адаптер без часов, поэтому время двигает только сон TX и
//! последовательность пачек детерминирована (размер пачки задаёт throttle, а
//! не время).

mod common;

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use common::*;
use rmasscan_core::probe::ReadyPlan;
use rmasscan_core::throttle::Clock;
use rmasscan_engine::fake::{BatchStep, FakeAdapter, ManualClock};
use rmasscan_engine::io::{AdapterPair, SendStatus};
use rmasscan_engine::{
    CancelHandle, Checkpoint, Engine, EngineHandle, Event, FailReason, MAX_TX_BATCH, Outcome,
    Reason,
};

/// 1024 адреса x 2 порта: достаточно, чтобы throttle выдал пачки больше 1
/// (его размер растёт на 0.5% за вызов, с единицы).
const BIG: &str = "10.0.0.0/22";
const BIG_PROBES: usize = 2048;
const CAP: usize = 12;

fn big_plan() -> ReadyPlan {
    plan_with(BIG, 1_000_000.0, 1)
}

fn quiet_fake(max_batch: usize) -> FakeAdapter {
    let fake = FakeAdapter::new();
    synack_responder(&fake);
    fake.set_max_batch(max_batch);
    fake
}

/// Ждёт итог; после последнего кадра двигает часы, чтобы отработал `wait`.
fn finish(h: EngineHandle, clock: &Arc<ManualClock>) -> (Outcome, Vec<Event>) {
    wait_for("outcome", || {
        if h.progress().sent >= BIG_PROBES as u64 {
            clock.advance(Duration::from_millis(500));
        }
        h.outcome().is_some()
    });
    h.join_drain().unwrap()
}

fn run_big(fake: &FakeAdapter) -> (Outcome, Vec<Event>) {
    let clock = ManualClock::new();
    let h = start_manual(&big_plan(), fake, &clock, opts());
    finish(h, &clock)
}

/// Размеры вызовов `send_batch` чистого прогона.
fn dry_sizes(max_batch: usize) -> Vec<usize> {
    let fake = quiet_fake(max_batch);
    let (out, _) = run_big(&fake);
    assert_eq!(out.reason, Reason::Completed);
    let sizes = fake.batch_sizes();
    assert_eq!(sizes.iter().sum::<usize>(), BIG_PROBES);
    sizes
}

/// Индекс первого вызова размером не меньше `min` и его размер.
fn first_batch_at_least(min: usize) -> (usize, usize) {
    let sizes = dry_sizes(CAP);
    let j = sizes
        .iter()
        .position(|&s| s >= min)
        .unwrap_or_else(|| panic!("no batch of {min}+ frames in {sizes:?}"));
    (j, sizes[j])
}

/// `j` полных пачек, затем `tail`; дальше пачка идёт по кадрам через `send`.
fn script_after(fake: &FakeAdapter, j: usize, tail: impl IntoIterator<Item = BatchStep>) {
    let mut steps = vec![BatchStep::All; j];
    steps.extend(tail);
    fake.script_batch(steps);
}

fn no_checkpoint(events: &[Event]) -> bool {
    !events
        .iter()
        .any(|e| matches!(e, Event::CheckpointReady { .. }))
}

#[test]
fn max_batch_one_sends_the_same_frames_in_the_same_order() {
    let p = plan(1_000_000.0, 3);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    synack_responder(&fake);
    let h = start_manual(&p, &fake, &clock, opts());
    let events = drain_to_finished(&h);
    let o = h.join().unwrap();
    assert_eq!(o.reason, Reason::Completed);
    assert!(no_checkpoint(&events));
    // Тот же эталон и те же вызовы `send`, что у теста lifecycle до пачек.
    assert_eq!(fake.sent_frames(), reference_frames(&p, PROBES as usize));
    assert_eq!(fake.send_calls(), PROBES);
    assert_eq!(fake.batch_sizes(), vec![1; PROBES as usize]);
    assert_eq!(o.progress.sent, PROBES);
    assert_eq!(o.progress.next_index, PROBES);
}

#[test]
fn batches_never_exceed_max_batch_or_the_throttle_batch() {
    let capped = dry_sizes(5);
    assert!(capped.iter().all(|&s| (1..=5).contains(&s)), "{capped:?}");
    assert!(capped.iter().any(|&s| s > 1), "{capped:?}");

    // Выше предела throttle `max_batch` ничего не меняет: пачку ограничивает
    // throttle, а скрепа `MAX_TX_BATCH` над любым адаптером.
    let wide = dry_sizes(64);
    assert_eq!(dry_sizes(usize::MAX), wide);
    assert!(wide.iter().all(|&s| (1..=MAX_TX_BATCH).contains(&s)));
    assert!(wide.iter().any(|&s| s > 5), "{wide:?}");

    // `max_batch() == 1` это одиночный путь.
    let fake = quiet_fake(1);
    let (out, _) = run_big(&fake);
    assert_eq!(out.reason, Reason::Completed);
    assert!(fake.batch_sizes().iter().all(|&s| s == 1));
    assert_eq!(fake.batch_calls() as usize, BIG_PROBES);
}

#[test]
fn a_full_batch_advances_the_cursor_by_its_size_once() {
    let (j, n) = first_batch_at_least(2);
    let fake = quiet_fake(CAP);
    script_after(&fake, j + 1, [BatchStep::Fail("stop here".into())]);
    let (out, events) = run_big(&fake);
    assert_eq!(
        out.reason,
        Reason::Failed(FailReason::TxError("stop here".into()))
    );
    // j одиночных пачек и одна из `n` кадров.
    assert_eq!(out.progress.sent, (j + n) as u64);
    assert_eq!(out.progress.next_index, (j + n) as u64);
    assert_eq!(fake.sent_count(), j + n);
    assert_eq!(fake.sent_frames(), reference_frames(&big_plan(), j + n));
    assert!(no_checkpoint(&events));
}

#[test]
fn a_prefix_result_advances_only_the_prefix_and_fails_uncertain_without_checkpoint() {
    let (j, n) = first_batch_at_least(2);
    let reference = reference_frames(&big_plan(), BIG_PROBES);
    for keep in [0, 1, n - 1] {
        let fake = quiet_fake(CAP);
        script_after(
            &fake,
            j,
            [BatchStep::Prefix {
                sent: keep,
                rest: SendStatus::Uncertain,
            }],
        );
        let (out, events) = run_big(&fake);
        assert_eq!(
            out.reason,
            Reason::Failed(FailReason::TxUncertain),
            "keep {keep}"
        );
        let done = j + keep;
        assert_eq!(out.progress.sent, done as u64, "keep {keep}");
        assert_eq!(out.progress.next_index, done as u64, "keep {keep}");
        assert_eq!(
            fake.sent_frames(),
            reference[..done].to_vec(),
            "keep {keep}"
        );
        // Остаток неизвестен: ровно первый непринятый кадр.
        assert_eq!(fake.uncertain_frames(), vec![reference[done].clone()]);
        assert!(no_checkpoint(&events), "keep {keep}");
        // Повтора остатка нет, после отказа вызовов нет.
        assert_eq!(fake.batch_calls() as usize, j + 1, "keep {keep}");
        assert_eq!(fake.alive_handles(), 0);
    }
}

#[test]
fn an_inconsistent_batch_result_fails_uncertain_without_advancing() {
    let (j, n) = first_batch_at_least(2);
    for bad in [
        // весь префикс, но остаток не Sent
        BatchStep::Prefix {
            sent: n,
            rest: SendStatus::WouldBlockUnsent,
        },
        // не весь префикс, но остаток Sent
        BatchStep::Prefix {
            sent: n - 1,
            rest: SendStatus::Sent,
        },
        // принято больше, чем предложено
        BatchStep::Prefix {
            sent: n + 1,
            rest: SendStatus::Sent,
        },
    ] {
        let fake = quiet_fake(CAP);
        script_after(&fake, j, [bad.clone()]);
        let (out, events) = run_big(&fake);
        assert_eq!(
            out.reason,
            Reason::Failed(FailReason::TxUncertain),
            "{bad:?}"
        );
        assert_eq!(out.progress.next_index, j as u64, "{bad:?}");
        assert!(no_checkpoint(&events));
    }
}

#[test]
fn a_prefix_then_would_block_retries_the_first_unsent_frame_and_opens_the_stall_window() {
    let (j, _) = first_batch_at_least(2);
    let reference = reference_frames(&big_plan(), BIG_PROBES);

    // Короткий backpressure: первый непринятый кадр предложен снова, дыр и
    // дублей нет.
    let fake = quiet_fake(CAP);
    script_after(
        &fake,
        j,
        [BatchStep::Prefix {
            sent: 1,
            rest: SendStatus::WouldBlockUnsent,
        }],
    );
    let (out, _) = run_big(&fake);
    assert_eq!(out.reason, Reason::Completed);
    assert_eq!(fake.sent_frames(), reference);
    assert_eq!(fake.would_block_count(), 1);
    assert_eq!(out.progress.next_index, BIG_PROBES as u64);

    // Вечный backpressure: окно открыто попыткой, которая принесла префикс.
    let fake = quiet_fake(CAP);
    script_after(
        &fake,
        j,
        [BatchStep::Prefix {
            sent: 1,
            rest: SendStatus::WouldBlockUnsent,
        }],
    );
    fake.set_would_block_forever(true);
    let (out, events) = run_big(&fake);
    let Reason::Failed(FailReason::TxStalled { idle_millis }) = out.reason else {
        panic!("expected TxStalled, got {:?}", out.reason);
    };
    assert!(
        (10_000..=10_010).contains(&idle_millis),
        "idle_millis={idle_millis}"
    );
    assert_eq!(out.progress.sent, (j + 1) as u64);
    assert_eq!(out.progress.next_index, (j + 1) as u64);
    assert_eq!(fake.sent_frames(), reference[..j + 1].to_vec());
    assert!(no_checkpoint(&events));
}

#[test]
fn stall_window_resets_after_any_sent_prefix() {
    let (j, _) = first_batch_at_least(3);
    let reference = reference_frames(&big_plan(), BIG_PROBES);
    let fake = quiet_fake(CAP);
    // Две пачки подряд с принятым префиксом и backpressure, затем остаток.
    script_after(
        &fake,
        j,
        [
            BatchStep::Prefix {
                sent: 1,
                rest: SendStatus::WouldBlockUnsent,
            },
            BatchStep::Prefix {
                sent: 1,
                rest: SendStatus::WouldBlockUnsent,
            },
        ],
    );
    let mut o = opts();
    // Один сон backoff это 1 мс: без сброса после префикса второй
    // WouldBlock уже превысил бы 1.5 мс окна.
    o.tx_stall_timeout = Duration::from_micros(1_500);
    let clock = ManualClock::new();
    let h = start_manual(&big_plan(), &fake, &clock, o);
    let (out, _) = finish(h, &clock);
    assert_eq!(out.reason, Reason::Completed);
    assert_eq!(fake.would_block_count(), 2);
    assert_eq!(fake.sent_frames(), reference);
}

/// Запуск, в котором хук адаптера подаёт команду, когда принято `at` кадров.
fn run_with_command_at(
    at: usize,
    command: impl Fn(&CancelHandle) + Send + Sync + 'static,
) -> (FakeAdapter, Outcome, Vec<Event>, Option<Checkpoint>) {
    let fake = quiet_fake(CAP);
    let cell: Arc<OnceLock<CancelHandle>> = Arc::default();
    let hook_cell = cell.clone();
    fake.set_send_hook(move |n| {
        if n == at {
            let c = loop {
                if let Some(c) = hook_cell.get() {
                    break c;
                }
                std::thread::yield_now();
            };
            command(c);
        }
    });
    let clock = ManualClock::new();
    let c: Arc<dyn Clock + Send + Sync> = clock.clone();
    let h = Engine::start_with_clock(big_plan(), fake.pair(), opts(), c).unwrap();
    cell.set(h.cancel_handle()).ok();
    wait_for("outcome", || {
        if h.outcome().is_some() {
            return true;
        }
        // Часы для `wait` только после команды: раньше они сбросили бы throttle.
        if fake.sent_count() >= at {
            clock.advance(Duration::from_millis(500));
        }
        false
    });
    let cp = h.checkpoint();
    let (out, events) = h.join_drain().unwrap();
    (fake, out, events, cp)
}

#[test]
fn stop_between_batches_sends_nothing_afterwards() {
    let (j, _) = first_batch_at_least(2);
    // Команда приходит из середины пачки: пачка заканчивается, следующей нет.
    let at = j + 2;
    let (fake, out, events, cp) = run_with_command_at(at, |c| c.stop());
    assert_eq!(out.reason, Reason::Stopped);
    let sent = fake.sent_count();
    assert!(sent >= at && sent < BIG_PROBES, "sent {sent}");
    assert_eq!(out.progress.sent, sent as u64);
    assert_eq!(out.progress.next_index, sent as u64);
    assert_eq!(fake.sent_frames(), reference_frames(&big_plan(), sent));
    let calls = fake.batch_calls();
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(fake.batch_calls(), calls, "send after the terminal outcome");
    assert_eq!(fake.sent_count(), sent);
    assert!(cp.is_none());
    assert!(no_checkpoint(&events));
}

#[test]
fn pause_lands_on_a_batch_boundary_and_the_checkpoint_equals_position() {
    let (j, _) = first_batch_at_least(3);
    let at = j + 2;
    let (fake, out, events, cp) = run_with_command_at(at, |c| c.pause());
    assert_eq!(out.reason, Reason::Paused);
    let sent = fake.sent_count();
    assert!(sent >= at && sent < BIG_PROBES, "sent {sent}");
    // Позиция и checkpoint это ровно принятые кадры, а не предложенные.
    assert_eq!(out.progress.sent, sent as u64);
    assert_eq!(out.progress.next_index, sent as u64);
    assert_eq!(
        cp.expect("checkpoint after a clean pause").next_index,
        sent as u64
    );
    assert!(events.contains(&Event::CheckpointReady {
        next_index: sent as u64
    }));
    assert_eq!(fake.sent_frames(), reference_frames(&big_plan(), sent));
    // Подтверждённая пачка не оборвана посередине: последний вызов целиком.
    let sizes = fake.batch_sizes();
    assert_eq!(sizes.iter().sum::<usize>(), sent);
}

fn leg(
    fake: &FakeAdapter,
    resume: Option<&Checkpoint>,
    at: usize,
    attempt: u8,
) -> (Outcome, Option<Checkpoint>) {
    let start = resume.map_or(0, |cp| cp.next_index as usize);
    let clock = ManualClock::new();
    let cell: Arc<OnceLock<CancelHandle>> = Arc::default();
    let AdapterPair { tx, rx } = fake.pair();
    let tx = Box::new(PauseTx {
        inner: tx,
        at,
        block_calls: 1,
        sent: 0,
        blocked: 0,
        cancel: cell.clone(),
    });
    let pair = AdapterPair { tx, rx };
    let c: Arc<dyn Clock + Send + Sync> = clock.clone();
    let h = match resume {
        None => Engine::start_with_clock(big_plan(), pair, options_for(attempt), c),
        Some(cp) => {
            Engine::resume_with_clock(big_plan(), cp.clone(), pair, options_for(attempt), c)
        }
    }
    .unwrap();
    cell.set(h.cancel_handle()).ok();
    wait_for("outcome", || {
        if h.outcome().is_some() {
            return true;
        }
        if fake.sent_count() >= at.min(BIG_PROBES - start) {
            clock.advance(Duration::from_millis(500));
        }
        false
    });
    let cp = h.checkpoint();
    (h.join().unwrap(), cp)
}

#[test]
fn resume_from_a_batched_pause_continues_without_gap_or_duplicate() {
    let reference = reference_frames(&big_plan(), BIG_PROBES);
    // Непрерывный прогон при max_batch 1 и 8 даёт тот же ряд кадров.
    for max_batch in [1, 8] {
        let fake = quiet_fake(max_batch);
        let (out, _) = run_big(&fake);
        assert_eq!(out.reason, Reason::Completed);
        assert_eq!(
            fake.sent_frames(),
            reference,
            "continuous, max_batch {max_batch}"
        );
    }
    let (j, _) = first_batch_at_least(2);
    for max_batch in [1, 8] {
        // Пауза посередине области, где пачки уже больше одного кадра.
        for at in [0, 1, j + 3, 1000, BIG_PROBES - 1] {
            let fake = quiet_fake(max_batch);
            let (a, cp) = leg(&fake, None, at, 10);
            assert_eq!(a.reason, Reason::Paused, "max_batch {max_batch} at {at}");
            assert_eq!(a.progress.next_index, at as u64);
            let cp = cp.expect("checkpoint");
            assert_eq!(cp.next_index, at as u64);
            assert_eq!(fake.sent_count(), at, "pause cuts the batch exactly");

            let fake_b = quiet_fake(max_batch);
            let (b, _) = leg(&fake_b, Some(&cp), usize::MAX, 11);
            assert_eq!(b.reason, Reason::Completed);
            let mut joined = fake.sent_frames();
            joined.extend(fake_b.sent_frames());
            assert_eq!(joined, reference, "max_batch {max_batch} at {at}");
        }
    }
}

#[test]
fn a_batch_error_fails_tx_error_and_sends_nothing_more() {
    let (j, _) = first_batch_at_least(2);
    let fake = quiet_fake(CAP);
    script_after(&fake, j, [BatchStep::Fail("boom".into())]);
    let (out, events) = run_big(&fake);
    assert_eq!(
        out.reason,
        Reason::Failed(FailReason::TxError("boom".into()))
    );
    // Ошибка вызова не засчитывает ничего из этой пачки.
    assert_eq!(out.progress.sent, j as u64);
    assert_eq!(out.progress.next_index, j as u64);
    assert_eq!(fake.sent_count(), j);
    assert_eq!(fake.batch_calls() as usize, j + 1);
    assert!(no_checkpoint(&events));
    assert_eq!(fake.alive_handles(), 0);
}

#[test]
fn progress_sent_equals_cursor_position() {
    let (j, n) = first_batch_at_least(2);
    let scripts: Vec<Vec<BatchStep>> = vec![
        vec![],
        vec![BatchStep::Prefix {
            sent: n - 1,
            rest: SendStatus::Uncertain,
        }],
        vec![
            BatchStep::Prefix {
                sent: 1,
                rest: SendStatus::WouldBlockUnsent,
            },
            BatchStep::All,
        ],
        vec![BatchStep::Fail("x".into())],
    ];
    for tail in scripts {
        let fake = quiet_fake(CAP);
        script_after(&fake, j, tail.clone());
        let (out, _) = run_big(&fake);
        assert_eq!(
            out.progress.sent, out.progress.next_index,
            "script {tail:?}: {out:?}"
        );
        assert_eq!(
            out.progress.sent,
            fake.sent_count() as u64,
            "script {tail:?}"
        );
    }
}
