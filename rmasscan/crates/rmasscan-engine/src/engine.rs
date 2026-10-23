//! Запуск, потоки TX/RX, ограниченные очереди и завершение.
//!
//! # Завершение (shutdown handshake)
//! - `halt: AtomicU8` монотонно растёт (`fetch_max`): `RUN < PAUSE < STOP < FAIL`.
//!   Команды и внутренние отказы пишут только в него; первый отказ сохраняется
//!   в `fail`.
//! - TX выходит при любом `halt != RUN`, проверяя его перед каждой отправкой
//!   и внутри каждого повтора/сна throttle (отрезки сна <= 50 мс).
//! - RX выходит при `halt >= STOP`. При `PAUSE` и при естественном конце TX
//!   он отрабатывает `wait` (по инжектированным часам) и выходит.
//! - Каждый поток владеет своим handle адаптера и освобождает его до
//!   публикации выхода. Поток, вышедший вторым, вычисляет единственный
//!   [`Outcome`] и кладёт его в очередь отдельно от результатов; `Finished`
//!   выдаётся только когда принятые результаты уже вычитаны.
//! - `Drop` handle = Stop + join обоих потоков.
//! - Ничто в рабочих потоках не блокируется на потребителе: очередь
//!   результатов ограничена и при переполнении даёт `Failed(ConsumerTooSlow)`.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{PlanError, ProbeCursor, ReadyPlan};
use rmasscan_core::receive::{Reply, parse_reply};
use rmasscan_core::throttle::{Clock, SystemClock, Throttler};

use crate::checkpoint::{CHECKPOINT_FORMAT_VERSION, Checkpoint, CheckpointError};
use crate::events::{Event, FailReason, Outcome, Progress, Reason};
use crate::identity::{ENGINE_ALGORITHM_VERSION, job_digest};
use crate::io::{AdapterPair, Rx, SendStatus, Tx};

/// Верхняя граница таймаута одного вызова адаптера.
pub const MAX_IO_TIMEOUT: Duration = Duration::from_millis(50);
/// Верхняя граница dedup-кэша.
pub const MAX_DEDUP_ENTRIES: usize = 100_000;
/// 1514 + запас: кадр длиннее отбрасывается RX-слоем сети (MSG_TRUNC), в парсер сверхдлинным не попадает.
const RX_BUFFER_LEN: usize = 2048;

const RUN: u8 = 0;
const PAUSE: u8 = 1;
const STOP: u8 = 2;
const FAIL: u8 = 3;

const END_RUNNING: u8 = 0;
/// TX: probe кончились. RX: `wait` отработан.
const END_NATURAL: u8 = 1;
const END_HALTED: u8 = 2;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Параметры запуска. `wait` берётся из плана.
#[derive(Debug, Clone)]
pub struct EngineOptions {
    pub scan_id: [u8; 16],
    pub attempt_id: [u8; 16],
    /// Сколько принятых ответов может ждать потребителя.
    pub result_capacity: usize,
    /// Максимум ответов в одном `Event::Results`.
    pub event_batch_limit: usize,
    pub progress_interval: Duration,
    /// Таймаут вызова адаптера; обрезается до [`MAX_IO_TIMEOUT`].
    pub io_timeout: Duration,
    /// Размер dedup-кэша; обрезается до [`MAX_DEDUP_ENTRIES`].
    pub dedup_capacity: usize,
}

impl EngineOptions {
    pub fn new(scan_id: [u8; 16], attempt_id: [u8; 16]) -> Self {
        Self {
            scan_id,
            attempt_id,
            result_capacity: 4096,
            event_batch_limit: 1000,
            progress_interval: Duration::from_millis(250),
            io_timeout: MAX_IO_TIMEOUT,
            dedup_capacity: MAX_DEDUP_ENTRIES,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("invalid engine option: {0}")]
    InvalidOptions(&'static str),
    #[error(transparent)]
    Plan(#[from] PlanError),
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
    #[error("cannot spawn worker thread: {0}")]
    Spawn(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    /// Больше не возвращается из `join`/`join_drain`: паника отражается в
    /// итоге как `Failed(WorkerPanicked)`. Вариант оставлен для совместимости.
    #[error("a worker thread panicked")]
    WorkerPanicked,
    #[error("engine finished without an outcome")]
    NoOutcome,
}

// ---------------------------------------------------------------- dedup ---

type DedupKey = (u32, u16, u32, u16);

/// Ограниченный dedup по кортежу (remote ip/port, local ip/port).
///
/// Политика вытеснения: FIFO по порядку первой вставки. При заполнении
/// вытесняется самая старая запись; повторное попадание уже известного ключа
/// порядок НЕ обновляет. Ответ после вытеснения пройдёт повторно: устойчивую
/// уникальность результатов обеспечивает Studio. Память ограничена
/// `MAX_DEDUP_ENTRIES`, никакого набора на все адреса /0.
#[derive(Debug)]
pub struct DedupCache {
    cap: usize,
    set: HashSet<DedupKey>,
    order: VecDeque<DedupKey>,
}

impl DedupCache {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.clamp(1, MAX_DEDUP_ENTRIES);
        Self {
            cap,
            set: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// `true`, если кортеж новый (и теперь запомнен); `false` для повтора.
    pub fn insert(&mut self, r: &Reply) -> bool {
        let key = (r.remote_ip, r.remote_port, r.local_ip, r.local_port);
        if self.set.contains(&key) {
            return false;
        }
        if self.order.len() >= self.cap
            && let Some(old) = self.order.pop_front()
        {
            self.set.remove(&old);
        }
        self.set.insert(key);
        self.order.push_back(key);
        true
    }
}

// ---------------------------------------------------------------- queue ---

#[derive(Default)]
struct QState {
    started: Option<u64>,
    results: VecDeque<Reply>,
    progress: Option<Progress>,
    outcome: Option<Outcome>,
    checkpoint: Option<u64>,
    checkpoint_taken: bool,
    finished_taken: bool,
    closed: bool,
}

struct Queue {
    st: Mutex<QState>,
    cv: Condvar,
    capacity: usize,
    batch_limit: usize,
}

impl Queue {
    fn new(capacity: usize, batch_limit: usize) -> Self {
        Self {
            st: Mutex::new(QState::default()),
            cv: Condvar::new(),
            capacity,
            batch_limit,
        }
    }

    /// Не блокирует. `false` = очередь переполнена, ответ НЕ принят.
    fn push_result(&self, r: Reply) -> bool {
        let mut st = lock(&self.st);
        if st.closed {
            return true; // потребителя нет: молча не храним
        }
        if st.results.len() >= self.capacity {
            return false;
        }
        st.results.push_back(r);
        drop(st);
        self.cv.notify_all();
        true
    }

    fn set_progress(&self, p: Progress) {
        let mut st = lock(&self.st);
        if !st.closed {
            st.progress = Some(p); // coalescing: старый слепок заменяется
        }
        drop(st);
        self.cv.notify_all();
    }

    fn finish(&self, outcome: Outcome, checkpoint: Option<u64>) {
        let mut st = lock(&self.st);
        st.progress = Some(outcome.progress);
        st.checkpoint = checkpoint;
        st.outcome = Some(outcome);
        drop(st);
        self.cv.notify_all();
    }

    fn close(&self) {
        let mut st = lock(&self.st);
        st.closed = true;
        st.results.clear();
        st.progress = None;
    }

    fn pop_locked(&self, st: &mut QState) -> Result<Event, TryRecvError> {
        if let Some(range) = st.started.take() {
            return Ok(Event::Started { range });
        }
        if !st.results.is_empty() {
            let n = st.results.len().min(self.batch_limit);
            let replies: Vec<Reply> = st.results.drain(..n).collect();
            return Ok(Event::Results { replies });
        }
        if let Some(p) = st.progress.take() {
            return Ok(Event::Progress(p));
        }
        let Some(outcome) = st.outcome.as_ref() else {
            return Err(TryRecvError::Empty);
        };
        if let Some(next_index) = st.checkpoint
            && !st.checkpoint_taken
        {
            st.checkpoint_taken = true;
            return Ok(Event::CheckpointReady { next_index });
        }
        if st.finished_taken {
            return Err(TryRecvError::Disconnected);
        }
        st.finished_taken = true;
        Ok(Event::Finished {
            reason: outcome.reason.clone(),
        })
    }

    fn try_pop(&self) -> Result<Event, TryRecvError> {
        let mut st = lock(&self.st);
        self.pop_locked(&mut st)
    }

    fn pop_timeout(&self, timeout: Duration) -> Result<Event, TryRecvError> {
        let deadline = std::time::Instant::now() + timeout;
        let mut st = lock(&self.st);
        loop {
            match self.pop_locked(&mut st) {
                Err(TryRecvError::Empty) => {}
                other => return other,
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(TryRecvError::Empty);
            }
            st = self
                .cv
                .wait_timeout(st, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

// --------------------------------------------------------------- shared ---

struct Shared {
    halt: AtomicU8,
    fail: Mutex<Option<FailReason>>,
    sent: AtomicU64,
    position: AtomicU64,
    received: AtomicU64,
    discarded: AtomicU64,
    duplicates: AtomicU64,
    /// `f64::to_bits()` текущей скорости throttle.
    rate_bits: AtomicU64,
    tx_end: AtomicU8,
    rx_end: AtomicU8,
    exited: AtomicU8,
    queue: Queue,
    clock: Arc<dyn Clock + Send + Sync>,
    io_timeout: Duration,
    wait_micros: u64,
    progress_micros: u64,
}

impl Shared {
    fn halted(&self) -> u8 {
        self.halt.load(Ordering::Acquire)
    }

    fn command(&self, level: u8) {
        self.halt.fetch_max(level, Ordering::AcqRel);
    }

    fn fail(&self, reason: FailReason) {
        {
            let mut f = lock(&self.fail);
            if f.is_none() {
                *f = Some(reason);
            }
        }
        self.command(FAIL);
    }

    fn snapshot(&self) -> Progress {
        let rate = f64::from_bits(self.rate_bits.load(Ordering::Relaxed));
        Progress {
            sent: self.sent.load(Ordering::Acquire),
            next_index: self.position.load(Ordering::Acquire),
            received: self.received.load(Ordering::Relaxed),
            discarded: self.discarded.load(Ordering::Relaxed),
            duplicates: self.duplicates.load(Ordering::Relaxed),
            rate: if rate.is_finite() { rate } else { 0.0 },
        }
    }

    /// Вызывается ровно один раз: потоком, вышедшим вторым.
    fn finalize(&self) {
        let fail = lock(&self.fail).clone();
        let tx_end = self.tx_end.load(Ordering::Acquire);
        let rx_end = self.rx_end.load(Ordering::Acquire);
        let halt = self.halted();
        let reason = if let Some(f) = fail {
            Reason::Failed(f)
        } else if tx_end == END_NATURAL && rx_end == END_NATURAL {
            Reason::Completed
        } else if halt >= STOP {
            Reason::Stopped
        } else if halt == PAUSE && rx_end == END_NATURAL {
            Reason::Paused
        } else {
            Reason::Failed(FailReason::Internal)
        };
        let progress = self.snapshot();
        let checkpoint = (reason == Reason::Paused).then_some(progress.next_index);
        self.queue.finish(Outcome { reason, progress }, checkpoint);
    }
}

/// Объявляет выход потока. Объявляется РАНЬШЕ handle адаптера, поэтому
/// уничтожается позже него: к моменту `Finished` handle уже освобождён.
struct ExitGuard {
    shared: Arc<Shared>,
    end: fn(&Shared) -> &AtomicU8,
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        let end = (self.end)(&self.shared);
        if std::thread::panicking() {
            self.shared.fail(FailReason::WorkerPanicked);
        }
        // Если поток не выставил конец сам (отказ, паника): остановлен.
        let _ = end.compare_exchange(END_RUNNING, END_HALTED, Ordering::AcqRel, Ordering::Acquire);
        if self.shared.exited.fetch_add(1, Ordering::AcqRel) == 1 {
            self.shared.finalize();
        }
    }
}

// ------------------------------------------------------------------ tx ----

/// Ожидание после `WouldBlockUnsent` перед повтором того же кадра.
///
/// 1 мс это НОВОЕ РЕШЕНИЕ плана 2B-Linux, а не результат измерения
/// производительности: оно лишь убирает busy-spin и укладывается в контракт
/// "Stop/Pause <= 1 с" (один сон короче любого лимита отмены). Значение можно
/// пересмотреть после замеров на реальном адаптере.
const WOULD_BLOCK_BACKOFF_MICROS: u64 = 1_000;

fn run_tx(shared: Arc<Shared>, tx: Box<dyn Tx>, mut cursor: ProbeCursor, rate: f64) {
    let _guard = ExitGuard {
        shared: shared.clone(),
        end: |s| &s.tx_end,
    };
    let mut tx = tx;
    let clock = &*shared.clock;
    let halted = || shared.halted() != RUN;
    // Один Throttler на TX-поток, плановая скорость, те же часы для start и
    // next_batch.
    let mut throttler = Throttler::start(rate, clock);

    let end = 'run: loop {
        // Конец последовательности сильнее паузы: next_index == range это
        // завершение, а не checkpoint с пустым остатком.
        if cursor.current().is_none() {
            break END_NATURAL;
        }
        if halted() {
            break END_HALTED;
        }
        let batch = match throttler.next_batch_interruptible(
            shared.sent.load(Ordering::Acquire),
            clock,
            halted,
        ) {
            Ok(b) => b,
            Err(_) => break END_HALTED,
        };
        shared
            .rate_bits
            .store(throttler.current_rate().to_bits(), Ordering::Relaxed);
        // batch == 0 означает "вызвать снова".
        let mut left = batch;
        while left > 0 {
            if cursor.current().is_none() {
                break 'run END_NATURAL;
            }
            // Отмена перед КАЖДОЙ отправкой.
            if halted() {
                break 'run END_HALTED;
            }
            let Some(probe) = cursor.current() else {
                break 'run END_NATURAL;
            };
            match tx.send(&probe.frame, shared.io_timeout) {
                Ok(SendStatus::Sent) => {
                    cursor.advance_sent();
                    shared.sent.fetch_add(1, Ordering::AcqRel);
                    shared.position.store(cursor.position(), Ordering::Release);
                    left -= 1;
                }
                // Кадр точно не ушёл: курсор стоит, предложим тот же кадр.
                Ok(SendStatus::WouldBlockUnsent) => {
                    // Не крутимся вхолостую: короткое ожидание по тем же
                    // инжектируемым часам, отмена проверяется до и после.
                    if halted() {
                        break 'run END_HALTED;
                    }
                    clock.sleep_micros(WOULD_BLOCK_BACKOFF_MICROS);
                    if halted() {
                        break 'run END_HALTED;
                    }
                }
                Ok(SendStatus::Uncertain) => {
                    shared.fail(FailReason::TxUncertain);
                    break 'run END_HALTED;
                }
                Err(e) => {
                    shared.fail(FailReason::TxError(e.message));
                    break 'run END_HALTED;
                }
            }
        }
    };
    shared.tx_end.store(end, Ordering::Release);
}

// ------------------------------------------------------------------ rx ----

/// Приём.
///
/// # Контракт недоверенного входа
/// ЛЮБАЯ ошибка [`parse_reply`] (слишком длинный кадр, VLAN, обрезанные
/// заголовки, фрагмент, плохие длины и версии, плохие суммы) означает "кадр
/// чужой или битый: выбросить и продолжать приём" (C `main.c:773 continue`).
/// Это враждебный/посторонний ввод, а не отказ скана: он никогда не ведёт к
/// `Failed`. Падением считается только ошибка самого адаптера (`Rx::recv`).
fn run_rx(shared: Arc<Shared>, rx: Box<dyn Rx>, plan: ReadyPlan, dedup_capacity: usize) {
    let _guard = ExitGuard {
        shared: shared.clone(),
        end: |s| &s.rx_end,
    };
    let mut rx = rx;
    let clock = &*shared.clock;
    let link: LinkType = plan.binding().link_type;
    let mut dedup = DedupCache::new(dedup_capacity);
    let mut buf = vec![0u8; RX_BUFFER_LEN];
    let mut deadline: Option<u64> = None;
    let mut last_progress = clock.now_micros();

    let end = loop {
        if shared.halted() >= STOP {
            break END_HALTED;
        }
        match rx.recv(&mut buf, shared.io_timeout) {
            Err(e) => {
                shared.fail(FailReason::RxError(e.message));
                break END_HALTED;
            }
            Ok(None) => {}
            Ok(Some(n)) => {
                // n > buf.len() это нарушение контракта адаптера; безвредно
                // обрезаем, парсер отбросит такой кадр.
                let frame = &buf[..n.min(buf.len())];
                match parse_reply(frame, link, &plan) {
                    Ok(Some(reply)) => {
                        if !dedup.insert(&reply) {
                            shared.duplicates.fetch_add(1, Ordering::Relaxed);
                        } else if shared.queue.push_result(reply) {
                            shared.received.fetch_add(1, Ordering::Relaxed);
                        } else {
                            // Ответ потерян, молча не теряем: останавливаем TX
                            // и завершаемся Failed; принятое остаётся в очереди.
                            shared.fail(FailReason::ConsumerTooSlow);
                            break END_HALTED;
                        }
                    }
                    // Не наш пакет, либо ЛЮБАЯ ошибка разбора: выбросить и
                    // продолжать (см. контракт выше).
                    Ok(None) | Err(_) => {
                        shared.discarded.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        let now = clock.now_micros();
        if now.wrapping_sub(last_progress) >= shared.progress_micros {
            last_progress = now;
            shared.queue.set_progress(shared.snapshot());
        }
        if shared.tx_end.load(Ordering::Acquire) != END_RUNNING {
            let d = *deadline.get_or_insert(now.saturating_add(shared.wait_micros));
            if now >= d {
                break END_NATURAL;
            }
        }
    };
    shared.rx_end.store(end, Ordering::Release);
}

// --------------------------------------------------------------- engine ---

/// Точка входа.
pub struct Engine;

impl Engine {
    /// Запускает новый скан с боевыми часами.
    pub fn start(
        plan: ReadyPlan,
        io: AdapterPair,
        options: EngineOptions,
    ) -> Result<EngineHandle, StartError> {
        Self::start_with_clock(plan, io, options, Arc::new(SystemClock::new()))
    }

    /// То же с внедрёнными часами/сном (внутренний test runtime). Не часть
    /// стабильного API.
    #[doc(hidden)]
    pub fn start_with_clock(
        plan: ReadyPlan,
        io: AdapterPair,
        options: EngineOptions,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Result<EngineHandle, StartError> {
        Self::launch(plan, io, options, clock, 0)
    }

    /// Продолжает ту же последовательность с `checkpoint.next_index`.
    ///
    /// Всё проверяется ДО запуска потоков и первой отправки: версия формата и
    /// алгоритма, идентичность задания (цели/порты/исключения/seed/rate/
    /// retries/shard/rounds/wait/binding), `scan_id` (сохраняется) и свежий
    /// `attempt_id` (отличается от checkpoint). `next_index == range` это
    /// завершённый скан ([`CheckpointError::AlreadyCompleted`]).
    pub fn resume(
        plan: ReadyPlan,
        checkpoint: Checkpoint,
        io: AdapterPair,
        options: EngineOptions,
    ) -> Result<EngineHandle, StartError> {
        Self::resume_with_clock(plan, checkpoint, io, options, Arc::new(SystemClock::new()))
    }

    /// [`Self::resume`] с внедрёнными часами (внутренний test runtime).
    #[doc(hidden)]
    pub fn resume_with_clock(
        plan: ReadyPlan,
        checkpoint: Checkpoint,
        io: AdapterPair,
        options: EngineOptions,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Result<EngineHandle, StartError> {
        if checkpoint.format_version != CHECKPOINT_FORMAT_VERSION {
            return Err(CheckpointError::UnsupportedFormat(checkpoint.format_version).into());
        }
        if checkpoint.engine_version != ENGINE_ALGORITHM_VERSION {
            return Err(CheckpointError::EngineVersionMismatch(
                checkpoint.engine_version,
                ENGINE_ALGORITHM_VERSION,
            )
            .into());
        }
        if checkpoint.job_digest != job_digest(&plan) {
            return Err(CheckpointError::JobMismatch.into());
        }
        if checkpoint.scan_id != options.scan_id {
            return Err(CheckpointError::ScanIdMismatch.into());
        }
        if checkpoint.attempt_id == options.attempt_id {
            return Err(CheckpointError::AttemptIdReused.into());
        }
        if checkpoint.next_index == plan.range() {
            return Err(CheckpointError::AlreadyCompleted(checkpoint.next_index).into());
        }
        // next_index > range отвергает ProbeCursor::new (NextIndexBeyondRange).
        let mut h = Self::launch(plan, io, options, clock, checkpoint.next_index)?;
        h.resumed_from = Some(checkpoint.attempt_id);
        Ok(h)
    }

    /// Общий запуск; `start_index` приходит только из проверенного checkpoint.
    pub(crate) fn launch(
        plan: ReadyPlan,
        io: AdapterPair,
        options: EngineOptions,
        clock: Arc<dyn Clock + Send + Sync>,
        start_index: u64,
    ) -> Result<EngineHandle, StartError> {
        if options.result_capacity == 0 {
            return Err(StartError::InvalidOptions("result_capacity must be > 0"));
        }
        if options.event_batch_limit == 0 {
            return Err(StartError::InvalidOptions("event_batch_limit must be > 0"));
        }
        if options.io_timeout.is_zero() {
            return Err(StartError::InvalidOptions("io_timeout must be > 0"));
        }
        let cursor = ProbeCursor::new(&plan, start_index)?;
        let rate = plan.effective().max_rate();
        let io_timeout = options.io_timeout.min(MAX_IO_TIMEOUT);

        let queue = Queue::new(options.result_capacity, options.event_batch_limit);
        lock(&queue.st).started = Some(plan.range());
        let shared = Arc::new(Shared {
            halt: AtomicU8::new(RUN),
            fail: Mutex::new(None),
            sent: AtomicU64::new(0),
            position: AtomicU64::new(cursor.position()),
            received: AtomicU64::new(0),
            discarded: AtomicU64::new(0),
            duplicates: AtomicU64::new(0),
            rate_bits: AtomicU64::new(0f64.to_bits()),
            tx_end: AtomicU8::new(END_RUNNING),
            rx_end: AtomicU8::new(END_RUNNING),
            exited: AtomicU8::new(0),
            queue,
            clock,
            io_timeout,
            wait_micros: u64::from(plan.effective().wait_secs()) * 1_000_000,
            progress_micros: u64::try_from(options.progress_interval.as_micros())
                .unwrap_or(u64::MAX),
        });

        let AdapterPair { tx, rx } = io;
        // RX первым: к моменту первой отправки приёмник уже слушает.
        let rx_thread = {
            let s = shared.clone();
            let plan = plan.clone();
            let cap = options.dedup_capacity;
            std::thread::Builder::new()
                .name("rmasscan-rx".into())
                .spawn(move || run_rx(s, rx, plan, cap))
                .map_err(|e| StartError::Spawn(e.to_string()))?
        };
        let tx_thread = {
            let s = shared.clone();
            std::thread::Builder::new()
                .name("rmasscan-tx".into())
                .spawn(move || run_tx(s, tx, cursor, rate))
        };
        let tx_thread = match tx_thread {
            Ok(t) => t,
            Err(e) => {
                shared.command(STOP);
                let _ = rx_thread.join();
                return Err(StartError::Spawn(e.to_string()));
            }
        };
        let digest = job_digest(&plan);
        Ok(EngineHandle {
            shared,
            options,
            digest,
            resumed_from: None,
            tx_thread: Some(tx_thread),
            rx_thread: Some(rx_thread),
        })
    }
}

/// Владелец запуска. `Drop` останавливает и дожидается оба потока.
pub struct EngineHandle {
    shared: Arc<Shared>,
    options: EngineOptions,
    digest: [u8; 32],
    resumed_from: Option<[u8; 16]>,
    tx_thread: Option<JoinHandle<()>>,
    rx_thread: Option<JoinHandle<()>>,
}

/// Клон права на Pause/Stop для другого потока (например, кнопка UI или
/// обработчик сигнала). Не владеет потоками и ничего не join-ит.
#[derive(Clone)]
pub struct CancelHandle {
    shared: Arc<Shared>,
}

impl CancelHandle {
    pub fn pause(&self) {
        self.shared.command(PAUSE);
    }

    pub fn stop(&self) {
        self.shared.command(STOP);
    }
}

impl EngineHandle {
    pub fn cancel_handle(&self) -> CancelHandle {
        CancelHandle {
            shared: self.shared.clone(),
        }
    }

    pub fn scan_id(&self) -> [u8; 16] {
        self.options.scan_id
    }

    pub fn attempt_id(&self) -> [u8; 16] {
        self.options.attempt_id
    }

    /// attempt_id checkpoint, из которого запущен этот прогон (происхождение).
    /// `None` для нового скана. Это не текущая попытка: она в [`Self::attempt_id`].
    pub fn resumed_from_attempt(&self) -> Option<[u8; 16]> {
        self.resumed_from
    }

    /// Checkpoint чистой паузы: `Some` только если итог `Paused`. Его
    /// `attempt_id` это текущая попытка (она создала checkpoint). Не
    /// сохранённая пауза: durable Paused подтверждает Studio.
    pub fn checkpoint(&self) -> Option<Checkpoint> {
        let o = self.outcome()?;
        (o.reason == Reason::Paused).then_some(Checkpoint {
            format_version: CHECKPOINT_FORMAT_VERSION,
            engine_version: ENGINE_ALGORITHM_VERSION,
            scan_id: self.options.scan_id,
            attempt_id: self.options.attempt_id,
            job_digest: self.digest,
            next_index: o.progress.next_index,
        })
    }

    /// Остановить TX на границе подтверждённой отправки; RX примет финальные
    /// ответы в течение `wait`. Не действует, если TX уже закончил.
    pub fn pause(&self) {
        self.shared.command(PAUSE);
    }

    /// Остановить оба потока без ожидания `wait`.
    pub fn stop(&self) {
        self.shared.command(STOP);
    }

    pub fn try_event(&self) -> Result<Event, TryRecvError> {
        self.shared.queue.try_pop()
    }

    /// Ждёт событие не дольше `timeout`; `Err(Empty)` по таймауту.
    pub fn recv_event_timeout(&self, timeout: Duration) -> Result<Event, TryRecvError> {
        self.shared.queue.pop_timeout(timeout)
    }

    /// Терминальный итог, если оба потока уже остановились. Не расходует
    /// события и не мешает их чтению.
    pub fn outcome(&self) -> Option<Outcome> {
        lock(&self.shared.queue.st).outcome.clone()
    }

    pub fn progress(&self) -> Progress {
        self.shared.snapshot()
    }

    /// Блокируется до завершения запуска (вызовите `stop`/`pause`, если не
    /// хотите ждать), joins оба потока.
    ///
    /// Паника рабочего потока НЕ даёт `Err`: если итог существует, возвращается
    /// `Ok(Outcome { reason: Failed(WorkerPanicked), .. })` (checkpoint нет).
    /// `Err(NoOutcome)` только когда итога нет совсем. Непрочитанные события
    /// `join` отбрасывает; чтобы их сохранить, используйте
    /// [`Self::join_drain`].
    pub fn join(self) -> Result<Outcome, EngineError> {
        self.join_drain().map(|(o, _)| o)
    }

    /// Как [`Self::join`], но возвращает ещё не прочитанные события (без
    /// `Finished`): итог не отбрасывает принятые результаты. Уже прочитанные
    /// через `try_event`/`recv_event_timeout` события не повторяются.
    ///
    /// При панике рабочего потока принятые до неё результаты сохраняются, а
    /// итог это `Ok(Failed(WorkerPanicked))` с последним слепком счётчиков.
    pub fn join_drain(mut self) -> Result<(Outcome, Vec<Event>), EngineError> {
        self.join_threads();
        let mut events = Vec::new();
        while let Ok(ev) = self.shared.queue.try_pop() {
            if !matches!(ev, Event::Finished { .. }) {
                events.push(ev);
            }
        }
        // Паника уже отражена в итоге (`ExitGuard` -> `Failed(WorkerPanicked)`),
        // поэтому при наличии итога возвращаем его вместе с событиями.
        match self.outcome() {
            Some(outcome) => Ok((outcome, events)),
            // Итога нет совсем (не должно случаться: второй выходящий поток
            // всегда финализирует).
            None => Err(EngineError::NoOutcome),
        }
    }

    fn join_threads(&mut self) {
        for t in [self.tx_thread.take(), self.rx_thread.take()]
            .into_iter()
            .flatten()
        {
            // Паника потока уже учтена в итоге через `ExitGuard`; здесь важен
            // сам join (handles освобождены).
            let _ = t.join();
        }
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        if self.tx_thread.is_none() && self.rx_thread.is_none() {
            return;
        }
        // Потребитель потерян: остановить, закрыть очередь, дождаться потоков.
        self.shared.command(STOP);
        self.shared.queue.close();
        self.join_threads();
    }
}
