//! Общие помощники интеграционных тестов (AGPL-3.0). Только офлайн.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{AdapterBinding, ProbeCursor, ReadyPlan};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_core::throttle::Clock;
use rmasscan_engine::fake::{FakeAdapter, ManualClock, reply_to_syn};
use rmasscan_engine::{Engine, EngineHandle, EngineOptions, Event, Outcome};
use std::sync::mpsc::TryRecvError;

pub const IP_ME: u32 = 0x0aff_0001;
pub const SEED: u64 = 0x1234_5678_9abc;
/// 8 адресов x 2 порта.
pub const PROBES: u64 = 16;

pub fn plan(rate: f64, wait_secs: u32) -> ReadyPlan {
    plan_with("10.0.0.0/29", rate, wait_secs)
}

pub fn plan_with(targets: &str, rate: f64, wait_secs: u32) -> ReadyPlan {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), targets).unwrap();
    parse_ports(m.ports_mut(), "80,443").unwrap();
    let cfg = ScanConfig {
        targets: m,
        seed: SEED,
        max_rate: rate,
        wait_secs,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).unwrap();
    ReadyPlan::new(
        eff,
        AdapterBinding {
            interface_id: "fake0".into(),
            link_type: LinkType::Ethernet,
            source_ipv4: IP_ME,
            source_mac: [0, 0x11, 0x22, 0x33, 0x44, 0x55],
            next_hop_mac: [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            source_ports: (40000, 40015),
        },
    )
    .unwrap()
}

pub fn opts() -> EngineOptions {
    EngineOptions::new([1; 16], [2; 16])
}

/// Эталонные кадры плана, по порядку (независимый ProbeCursor).
pub fn reference_frames(plan: &ReadyPlan, n: usize) -> Vec<Vec<u8>> {
    let mut c = ProbeCursor::new(plan, 0).unwrap();
    let mut out = Vec::new();
    while out.len() < n {
        let Some(p) = c.current() else { break };
        out.push(p.frame.clone());
        c.advance_sent();
    }
    out
}

/// Ответчик: SYN-ACK на каждый отправленный SYN.
pub fn synack_responder(fake: &FakeAdapter) {
    fake.set_responder(|f| reply_to_syn(f, 0x12).into_iter().collect());
}

pub fn start_manual(
    plan: &ReadyPlan,
    fake: &FakeAdapter,
    clock: &Arc<ManualClock>,
    options: EngineOptions,
) -> EngineHandle {
    let c: Arc<dyn Clock + Send + Sync> = clock.clone();
    Engine::start_with_clock(plan.clone(), fake.pair(), options, c).unwrap()
}

pub fn start_real(plan: &ReadyPlan, fake: &FakeAdapter) -> EngineHandle {
    Engine::start(plan.clone(), fake.pair(), opts()).unwrap()
}

pub fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let t = Instant::now();
    while !cond() {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "timeout waiting: {what}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Двигает ручные часы шагами `step`, пока условие не выполнится.
/// Поток RX читает часы в своём цикле: на медленной машине он может
/// прочитать их уже ПОСЛЕ одиночного `advance` (старт RX, срок wait), и тогда
/// одиночный сдвиг ничего не запускает. Повтор шага убирает эту гонку.
pub fn advance_until(
    clock: &ManualClock,
    step: Duration,
    what: &str,
    mut cond: impl FnMut() -> bool,
) {
    wait_for(what, || {
        if cond() {
            return true;
        }
        clock.advance(step);
        cond()
    });
}

/// Читает события до `Finished` (включительно).
pub fn drain_to_finished(h: &EngineHandle) -> Vec<Event> {
    let mut v = Vec::new();
    let t = Instant::now();
    loop {
        match h.recv_event_timeout(Duration::from_millis(50)) {
            Ok(e) => {
                let fin = matches!(e, Event::Finished { .. });
                v.push(e);
                if fin {
                    return v;
                }
            }
            Err(TryRecvError::Empty) => {
                assert!(t.elapsed() < Duration::from_secs(10), "no Finished: {v:?}");
            }
            Err(TryRecvError::Disconnected) => return v,
        }
    }
}

pub fn all_replies(events: &[Event]) -> Vec<rmasscan_core::receive::Reply> {
    events
        .iter()
        .flat_map(|e| match e {
            Event::Results { replies } => replies.clone(),
            _ => vec![],
        })
        .collect()
}

pub fn join_within(h: EngineHandle, limit: Duration) -> Outcome {
    let t = Instant::now();
    let o = h.join().unwrap();
    assert!(t.elapsed() < limit, "join took {:?}", t.elapsed());
    o
}

// ------------------------------------------------- pause/resume helpers ---

use rmasscan_core::receive::Reply;
use rmasscan_engine::fake::RxStep;
use rmasscan_engine::io::{AdapterPair, IoError, SendStatus, Tx, TxBatch};
use rmasscan_engine::{CancelHandle, Checkpoint, StartError};
use std::sync::OnceLock;

/// Tx-обёртка: после `at` подтверждённых отправок отвечает `WouldBlockUnsent`
/// и на `block_calls`-й такой ответ подаёт Pause (кадр НЕ уходит). Так пауза
/// детерминированно приходится на индекс `at`, в том числе до первой отправки
/// (`at = 0`) и посреди WouldBlock (`block_calls > 1`).
pub struct PauseTx {
    pub inner: Box<dyn Tx>,
    pub at: usize,
    pub block_calls: usize,
    pub sent: usize,
    pub blocked: usize,
    pub cancel: Arc<OnceLock<CancelHandle>>,
}

impl PauseTx {
    /// Одна попытка кадра на границе паузы: считаем WouldBlock и на
    /// `block_calls`-м подаём Pause.
    fn block(&mut self) -> SendStatus {
        self.blocked += 1;
        if self.blocked >= self.block_calls {
            let c = loop {
                if let Some(c) = self.cancel.get() {
                    break c;
                }
                std::thread::yield_now();
            };
            c.pause();
        }
        SendStatus::WouldBlockUnsent
    }
}

impl Tx for PauseTx {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError> {
        if self.sent == self.at {
            return Ok(self.block());
        }
        let r = self.inner.send(frame, timeout)?;
        if r == SendStatus::Sent {
            self.sent += 1;
        }
        Ok(r)
    }

    fn max_batch(&self) -> usize {
        self.inner.max_batch()
    }

    /// Режет пачку ровно на границе `at`: префикс уходит во внутренний адаптер,
    /// следующий кадр это та самая попытка, которую одиночный путь отвечает
    /// `WouldBlockUnsent` (и считает для паузы).
    fn send_batch(&mut self, frames: &[&[u8]], timeout: Duration) -> Result<TxBatch, IoError> {
        let room = self.at.saturating_sub(self.sent);
        if room == 0 {
            return Ok(TxBatch {
                sent: 0,
                rest: self.block(),
            });
        }
        let take = frames.len().min(room);
        let r = self.inner.send_batch(&frames[..take], timeout)?;
        self.sent += r.sent;
        if r.rest == SendStatus::Sent && take < frames.len() {
            return Ok(TxBatch {
                sent: r.sent,
                rest: self.block(),
            });
        }
        Ok(r)
    }
}

pub fn options_for(attempt: u8) -> EngineOptions {
    EngineOptions::new([1; 16], [attempt; 16])
}

/// Результат одного отрезка запуска.
pub struct Leg {
    pub frames: Vec<Vec<u8>>,
    pub events: Vec<Event>,
    pub outcome: Outcome,
    pub checkpoint: Option<Checkpoint>,
    pub replies: Vec<Reply>,
}

fn finish_leg(h: EngineHandle, fake: &FakeAdapter) -> Leg {
    let events = drain_to_finished(&h);
    let checkpoint = h.checkpoint();
    let outcome = h.join().unwrap();
    Leg {
        frames: fake.sent_frames(),
        replies: all_replies(&events),
        events,
        outcome,
        checkpoint,
    }
}

fn leg_fake() -> (FakeAdapter, Arc<ManualClock>) {
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    synack_responder(&fake);
    (fake, clock)
}

fn wrapped_pair(
    fake: &FakeAdapter,
    at: usize,
    block_calls: usize,
) -> (AdapterPair, Arc<OnceLock<CancelHandle>>) {
    let cell: Arc<OnceLock<CancelHandle>> = Arc::default();
    let AdapterPair { tx, rx } = fake.pair();
    let tx = Box::new(PauseTx {
        inner: tx,
        at,
        block_calls,
        sent: 0,
        blocked: 0,
        cancel: cell.clone(),
    });
    (AdapterPair { tx, rx }, cell)
}

/// Новый скан, пауза после `at` кадров (на `block_calls`-м WouldBlock).
pub fn first_leg(plan: &ReadyPlan, at: usize, block_calls: usize, attempt: u8) -> Leg {
    let (fake, clock) = leg_fake();
    let (pair, cell) = wrapped_pair(&fake, at, block_calls);
    let c: Arc<dyn Clock + Send + Sync> = clock.clone();
    let h = Engine::start_with_clock(plan.clone(), pair, options_for(attempt), c).unwrap();
    cell.set(h.cancel_handle()).ok();
    finish_leg(h, &fake)
}

/// Resume с checkpoint; пауза после ещё `at` кадров этого отрезка
/// (`at = usize::MAX`: без паузы, до конца).
pub fn resume_leg(plan: &ReadyPlan, cp: &Checkpoint, at: usize, attempt: u8) -> Leg {
    let (fake, clock) = leg_fake();
    let (pair, cell) = wrapped_pair(&fake, at, 1);
    let c: Arc<dyn Clock + Send + Sync> = clock.clone();
    let h =
        Engine::resume_with_clock(plan.clone(), cp.clone(), pair, options_for(attempt), c).unwrap();
    cell.set(h.cancel_handle()).ok();
    finish_leg(h, &fake)
}

/// Resume, который обязан быть отвергнут до первой отправки.
pub fn resume_rejected(plan: &ReadyPlan, cp: &Checkpoint, attempt: u8) -> StartError {
    let (fake, clock) = leg_fake();
    let c: Arc<dyn Clock + Send + Sync> = clock.clone();
    let err = Engine::resume_with_clock(
        plan.clone(),
        cp.clone(),
        fake.pair(),
        options_for(attempt),
        c,
    )
    .map(|_| ())
    .expect_err("resume must be rejected");
    assert_eq!(fake.send_calls(), 0, "rejected resume sent something");
    assert_eq!(fake.sent_count(), 0);
    assert_eq!(fake.alive_handles(), 0, "adapter handles leaked");
    err
}

pub fn rx_idle() -> RxStep {
    RxStep::Idle(1)
}
