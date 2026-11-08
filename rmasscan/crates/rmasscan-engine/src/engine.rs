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

use std::cell::Cell;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{NicBinding, PlanError, ProbeCursor, ReadyPlan};
use rmasscan_core::receive::{Reply, parse_reply};
use rmasscan_core::throttle::{Clock, SystemClock, Throttler};

use crate::checkpoint::{CHECKPOINT_FORMAT_VERSION, Checkpoint, CheckpointError};
use crate::events::{Event, FailReason, Outcome, Progress, Reason};
use crate::identity::{ENGINE_ALGORITHM_VERSION, job_digest};
use crate::io::{AdapterPair, Rx, RxHealth, SendStatus, Tx};

/// Верхняя граница таймаута одного вызова адаптера.
pub const MAX_IO_TIMEOUT: Duration = Duration::from_millis(50);
/// Окно TX-stall по умолчанию (решение плана ремедиации, задача 3).
pub const DEFAULT_TX_STALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Верхняя граница dedup-кэша.
pub const MAX_DEDUP_ENTRIES: usize = 100_000;
/// Верхняя скрепа над `Tx::max_batch()` любого адаптера: пачка живёт в памяти
/// TX-потока и режет окно отмены.
pub const MAX_TX_BATCH: usize = 4096;
/// Как часто RX-поток (по часам engine) проверяет достоверность приёма.
const RX_HEALTH_INTERVAL_MICROS: u64 = 250_000;
/// 1514 + запас: кадр длиннее отбрасывается RX-слоем сети (MSG_TRUNC), в парсер сверхдлинным не попадает.
const RX_BUFFER_LEN: usize = 2048;
/// `main.c:943`: в захват идут кадры не длиннее 1514 байт.
const PCAP_MAX_FRAME: usize = 1514;

/// Приёмник входящих кадров для `--pcap`: кадр и время приёма в микросекундах
/// часов engine. Вызывается из RX-потоков, поэтому обязан быть потокобезопасным.
pub type PcapSink = Arc<dyn Fn(&[u8], u64) + Send + Sync>;

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
    /// Максимум непрерывного `WouldBlockUnsent` для одного кадра по часам
    /// engine (по умолчанию 10 с, ноль запрещён). Политика времени выполнения:
    /// не влияет на порядок probe, checkpoint и job digest.
    pub tx_stall_timeout: Duration,
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
            tx_stall_timeout: DEFAULT_TX_STALL_TIMEOUT,
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
    /// Последнее успешно измеренное состояние приёма по одному на RX-поток
    /// (пишет только свой RX-поток).
    rx_health: Mutex<Vec<RxHealth>>,
    sent: AtomicU64,
    /// Внешний индекс следующего неподтверждённого probe, по одному на адаптер
    /// (`main.c:431` `parms->my_index`).
    positions: Vec<AtomicU64>,
    /// `ReadyPlan::nic_offset(k)`: смещение shard/NIC в базе `resume.index`.
    offsets: Vec<u64>,
    received: AtomicU64,
    discarded: AtomicU64,
    duplicates: AtomicU64,
    /// `f64::to_bits()` текущей скорости throttle каждого TX-потока.
    rate_bits: Vec<AtomicU64>,
    /// Итог каждого TX- и RX-потока; сводка в [`Shared::tx_end`] / [`Shared::rx_end`].
    tx_ends: Vec<AtomicU8>,
    rx_ends: Vec<AtomicU8>,
    exited: AtomicUsize,
    /// Число рабочих потоков (TX + RX).
    threads: usize,
    queue: Queue,
    clock: Arc<dyn Clock + Send + Sync>,
    io_timeout: Duration,
    wait_micros: u64,
    progress_micros: u64,
}

/// Сводка итогов потоков: "идёт", если хоть один идёт; "естественный конец",
/// только если все закончились естественно; иначе "остановлен".
fn fold_ends(ends: &[AtomicU8]) -> u8 {
    let mut all_natural = true;
    for e in ends {
        match e.load(Ordering::Acquire) {
            END_RUNNING => return END_RUNNING,
            END_NATURAL => {}
            _ => all_natural = false,
        }
    }
    if all_natural { END_NATURAL } else { END_HALTED }
}

/// Сумма потерь по RX-потокам; одно неизвестное делает неизвестной сумму.
fn fold_health(v: &[RxHealth]) -> RxHealth {
    let mut sum = 0u64;
    for h in v {
        match h.kernel_drops {
            Some(n) => sum = sum.saturating_add(n),
            None => return RxHealth { kernel_drops: None },
        }
    }
    RxHealth {
        kernel_drops: Some(sum),
    }
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

    /// Измеряет достоверность приёма и применяет итог. Вызывает только RX-поток
    /// (ему принадлежит handle). Первый отказ сохраняется (`fail` не
    /// перезаписывает); в `rx_health` попадает только УСПЕШНОЕ измерение,
    /// иначе неизвестное значение (`None`): ранее увиденный ноль не подменяет
    /// ошибку. Возвращает `false`, если исход уже нельзя считать чистым.
    fn check_rx_health(&self, idx: usize, rx: &mut dyn Rx) -> bool {
        match rx.health(self.io_timeout) {
            Ok(h) => {
                lock(&self.rx_health)[idx] = h;
                match h.kernel_drops {
                    Some(0) => true,
                    Some(n) => {
                        self.fail(FailReason::RxLoss { kernel_drops: n });
                        false
                    }
                    None => {
                        self.fail(FailReason::RxStatsUnavailable);
                        false
                    }
                }
            }
            Err(e) => {
                lock(&self.rx_health)[idx] = RxHealth { kernel_drops: None };
                self.fail(FailReason::RxError(e.message));
                false
            }
        }
    }

    /// Сводка итогов TX-потоков.
    fn tx_end(&self) -> u8 {
        fold_ends(&self.tx_ends)
    }

    /// Сводка итогов RX-потоков.
    fn rx_end(&self) -> u8 {
        fold_ends(&self.rx_ends)
    }

    /// Сырой `min_k my_index[k]` (`main.c:1408-1414`): для строки статуса.
    fn min_position(&self) -> u64 {
        self.positions
            .iter()
            .map(|p| p.load(Ordering::Acquire))
            .min()
            .unwrap_or(0)
    }

    /// Нормализованная база возобновления `min_k(my_index[k] - nic_offset(k))`
    /// (то же, что `ProbeCursor::resume_base`): `cursor_for_nic` прибавит
    /// смещение shard/NIC заново ровно один раз.
    fn resume_base(&self) -> u64 {
        self.positions
            .iter()
            .zip(&self.offsets)
            .map(|(p, off)| p.load(Ordering::Acquire).saturating_sub(*off))
            .min()
            .unwrap_or(0)
    }

    fn snapshot(&self) -> Progress {
        let rate: f64 = self
            .rate_bits
            .iter()
            .map(|b| f64::from_bits(b.load(Ordering::Relaxed)))
            .sum();
        Progress {
            sent: self.sent.load(Ordering::Acquire),
            next_index: self.min_position(),
            received: self.received.load(Ordering::Relaxed),
            discarded: self.discarded.load(Ordering::Relaxed),
            duplicates: self.duplicates.load(Ordering::Relaxed),
            rate: if rate.is_finite() { rate } else { 0.0 },
        }
    }

    /// Вызывается ровно один раз: потоком, вышедшим последним.
    fn finalize(&self) {
        let fail = lock(&self.fail).clone();
        let tx_end = self.tx_end();
        let rx_end = self.rx_end();
        let halt = self.halted();
        let health = fold_health(&lock(&self.rx_health));
        let reason = if let Some(f) = fail {
            Reason::Failed(f)
        } else if health.kernel_drops != Some(0) {
            // Страховка: успешный исход (Completed/Stopped/Paused) без
            // подтверждённого нуля потерь недопустим, как бы ни завершился RX.
            Reason::Failed(match health.kernel_drops {
                Some(n) => FailReason::RxLoss { kernel_drops: n },
                None => FailReason::RxStatsUnavailable,
            })
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
        let checkpoint = (reason == Reason::Paused).then(|| self.resume_base());
        let rx_health = health;
        self.queue.finish(
            Outcome {
                reason,
                progress,
                rx_health,
            },
            checkpoint,
        );
    }
}

/// Роль рабочего потока.
#[derive(Clone, Copy)]
enum Role {
    Tx,
    Rx,
}

/// Объявляет выход потока. Объявляется РАНЬШЕ handle адаптера, поэтому
/// уничтожается позже него: к моменту `Finished` handle уже освобождён.
struct ExitGuard {
    shared: Arc<Shared>,
    role: Role,
    idx: usize,
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        let end = match self.role {
            Role::Tx => &self.shared.tx_ends[self.idx],
            Role::Rx => &self.shared.rx_ends[self.idx],
        };
        if std::thread::panicking() {
            self.shared.fail(FailReason::WorkerPanicked);
        }
        // Если поток не выставил конец сам (отказ, паника): остановлен.
        let _ = end.compare_exchange(END_RUNNING, END_HALTED, Ordering::AcqRel, Ordering::Acquire);
        if self.shared.exited.fetch_add(1, Ordering::AcqRel) + 1 == self.shared.threads {
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

fn run_tx(
    shared: Arc<Shared>,
    idx: usize,
    tx: Box<dyn Tx>,
    mut cursor: ProbeCursor,
    rate: f64,
    stall_micros: u64,
) {
    let _guard = ExitGuard {
        shared: shared.clone(),
        role: Role::Tx,
        idx,
    };
    let mut tx = tx;
    let clock = &*shared.clock;
    // Подтверждено ли уже начало пачки повторов текущего внешнего индекса `i`
    // (`main.c:421-431`: `retries + 1` кадров на один `i`). Пауза не рвёт пачку:
    // `resume-index` хранит только внешний `i`, и возобновление с середины
    // пачки послало бы уже отправленные копии второй раз. Стоп и отказ рвут
    // пачку сразу. Для `retries == 0` пачка из одного кадра, поведение прежнее.
    let mid_burst = Cell::new(false);
    let halted = || {
        let h = shared.halted();
        h >= STOP || (h == PAUSE && !mid_burst.get())
    };
    // Счёт отправленного для throttle этого потока (общий `shared.sent`
    // суммирует все адаптеры, а скорость делится между ними, `main.c:249`).
    let mut my_sent = 0u64;
    // Один Throttler на TX-поток, плановая скорость, те же часы для start и
    // next_batch.
    let mut throttler = Throttler::start(rate, clock);
    // Окно TX-stall: начало первой неудачной попытки текущего кадра (по тем же
    // часам, что и throttle). Сбрасывается только после `Sent`; сон throttle
    // между кадрами в него не входит, потому что к нему окно уже закрыто.
    let mut stall_since: Option<u64> = None;

    let end = 'run: loop {
        // Конец последовательности сильнее паузы: next_index == range это
        // завершение, а не checkpoint с пустым остатком.
        if cursor.current().is_none() {
            break END_NATURAL;
        }
        if halted() {
            break END_HALTED;
        }
        let batch = match throttler.next_batch_interruptible(my_sent, clock, halted) {
            Ok(b) => b,
            Err(_) => break END_HALTED,
        };
        shared.rate_bits[idx].store(throttler.current_rate().to_bits(), Ordering::Relaxed);
        // batch == 0 означает "вызвать снова".
        let mut left = batch;
        while left > 0 {
            // Не больше, чем осталось в окне throttle, `max_batch()` адаптера и
            // общей скрепы. Загрузка не продвигает курсор.
            let want = left
                .min(tx.max_batch().max(1) as u64)
                .min(MAX_TX_BATCH as u64) as usize;
            let probes = cursor.preload(want);
            if probes.is_empty() {
                break 'run END_NATURAL;
            }
            // Пауза в середине пачки: досылаем только остаток этой пачки.
            let n = if shared.halted() == PAUSE && mid_burst.get() {
                let first = probes[0].index;
                probes.iter().take_while(|p| p.index == first).count()
            } else {
                probes.len()
            };
            let probes = &probes[..n];
            // Отмена перед КАЖДОЙ пачкой (при `max_batch() == 1` это перед
            // каждой отправкой, как раньше).
            if halted() {
                break 'run END_HALTED;
            }
            // Граница окна: новая попытка после дедлайна не начинается.
            let attempt_start = clock.now_micros();
            if let Some(since) = stall_since
                && attempt_start.saturating_sub(since) >= stall_micros
            {
                stall_fail(&shared, attempt_start.saturating_sub(since));
                break 'run END_HALTED;
            }
            let result = if n == 1 {
                let one: &[u8] = &probes[0].frame;
                tx.send_batch(std::slice::from_ref(&one), shared.io_timeout)
            } else {
                let frames: Vec<&[u8]> = probes.iter().map(|p| p.frame.as_slice()).collect();
                tx.send_batch(&frames, shared.io_timeout)
            };
            match result {
                // Нарушение инварианта `TxBatch`: что именно ушло, неизвестно.
                Ok(r) if r.sent > n || (r.sent == n) != (r.rest == SendStatus::Sent) => {
                    shared.fail(FailReason::TxUncertain);
                    break 'run END_HALTED;
                }
                Ok(r) => {
                    if r.sent > 0 {
                        // Sent из уже начатого вызова засчитывается даже после
                        // границы окна; курсор идёт ровно на принятый префикс.
                        stall_since = None;
                        let last = probes[r.sent - 1].index;
                        cursor.advance_sent_n(r.sent);
                        // Следующий кадр с тем же `i` означает середину пачки.
                        mid_burst.set(cursor.position() == last);
                        my_sent += r.sent as u64;
                        shared.sent.fetch_add(r.sent as u64, Ordering::AcqRel);
                        shared.positions[idx].store(cursor.position(), Ordering::Release);
                        left -= r.sent as u64;
                    }
                    match r.rest {
                        SendStatus::Sent => {}
                        // Первый неотправленный кадр точно не ушёл: курсор
                        // стоит, предложим тот же кадр.
                        SendStatus::WouldBlockUnsent => {
                            let since = *stall_since.get_or_insert(attempt_start);
                            let idle = clock.now_micros().saturating_sub(since);
                            if idle >= stall_micros {
                                if halted() {
                                    break 'run END_HALTED;
                                }
                                stall_fail(&shared, idle);
                                break 'run END_HALTED;
                            }
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
                        SendStatus::Uncertain => {
                            shared.fail(FailReason::TxUncertain);
                            break 'run END_HALTED;
                        }
                    }
                }
                Err(e) => {
                    shared.fail(FailReason::TxError(e.message));
                    break 'run END_HALTED;
                }
            }
        }
    };
    shared.tx_ends[idx].store(end, Ordering::Release);
}

fn stall_fail(shared: &Shared, idle_micros: u64) {
    shared.fail(FailReason::TxStalled {
        idle_millis: idle_micros / 1_000,
    });
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
fn run_rx(
    shared: Arc<Shared>,
    idx: usize,
    rx: Box<dyn Rx>,
    plan: ReadyPlan,
    dedup: Arc<Mutex<DedupCache>>,
    pcap_sink: Option<PcapSink>,
) {
    let _guard = ExitGuard {
        shared: shared.clone(),
        role: Role::Rx,
        idx,
    };
    let mut rx = rx;
    let clock = &*shared.clock;
    let link: LinkType = plan.binding().link_type;
    let mut buf = vec![0u8; RX_BUFFER_LEN];
    let mut deadline: Option<u64> = None;
    let mut last_progress = clock.now_micros();
    let mut last_health = last_progress;

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
                // `--pcap` (main.c:943-951): кадр уходит в файл захвата до
                // проверки cookie и дедупликации. Фильтр "наш адрес и порт"
                // принадлежит писателю захвата (Задача 7).
                if let Some(sink) = &pcap_sink
                    && frame.len() <= PCAP_MAX_FRAME
                {
                    sink(frame, clock.now_micros());
                }
                match parse_reply(frame, link, &plan) {
                    Ok(Some(reply)) => {
                        let fresh = lock(&dedup).insert(&reply);
                        if !fresh {
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
        // Проверка достоверности по часам engine, а не по числу кадров.
        if now.wrapping_sub(last_health) >= RX_HEALTH_INTERVAL_MICROS {
            last_health = now;
            if !shared.check_rx_health(idx, &mut *rx) {
                break END_HALTED;
            }
        }
        if shared.tx_end() != END_RUNNING {
            let d = *deadline.get_or_insert(now.saturating_add(shared.wait_micros));
            if now >= d {
                break END_NATURAL;
            }
        }
    };
    // Обязательная финальная проверка: её снимок закрывает окно наблюдения и
    // делается ДО публикации rx_end (а значит, до терминального исхода). Handle
    // закрывается позже, в ExitGuard, то есть до Finished.
    let clean = shared.check_rx_health(idx, &mut *rx);
    let end = if clean || end == END_HALTED {
        end
    } else {
        END_HALTED
    };
    shared.rx_ends[idx].store(end, Ordering::Release);
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

    /// Запуск CLI: по паре потоков TX/RX на каждый адаптер плана
    /// (`main.c:1257-1390`, `transmit_thread` на `nic[k]`, `main.c:269-273`).
    /// Начало потока каждого адаптера берётся из `resume_index` плана
    /// (`ReadyPlan::cursor_for_nic(k, None)`), общий dedup и общая очередь
    /// результатов. Скорость делится на число адаптеров (`main.c:249`).
    ///
    /// Чистая пауза пишет `resume-index = min_k ProbeCursor::resume_base()`
    /// (нормализованная база), а не сырой `min_k my_index[k]` из
    /// `main.c:1408-1414`: `cursor_for_nic` на возобновлении заново прибавит
    /// смещение shard/NIC, и сырое значение задвоило бы его. Скан завершён,
    /// когда каждый адаптер дошёл до своего `effective_end` (его курсор пуст),
    /// а не когда нормализованная база достигла `range` (`main.c:1425` ждёт
    /// именно этого и зависает при усечённом `resume-count`).
    ///
    /// `ios.len()` обязан равняться `plan.nics().len()`. `pcap_sink` получает
    /// входящие кадры до разбора. Для одного адаптера ведёт себя как
    /// [`Self::start_with_clock`] (кроме плана `new_cli`, который тот не
    /// отвергает).
    #[doc(hidden)]
    pub fn start_cli_with_clock(
        plan: ReadyPlan,
        ios: Vec<AdapterPair>,
        options: EngineOptions,
        clock: Arc<dyn Clock + Send + Sync>,
        pcap_sink: Option<PcapSink>,
    ) -> Result<EngineHandle, StartError> {
        let cursors = (0..plan.nics().len() as u32)
            .map(|k| plan.cursor_for_nic(k, None))
            .collect::<Result<Vec<_>, _>>()?;
        Self::launch_n(plan, ios, cursors, options, clock, pcap_sink)
    }

    /// Общий запуск одного адаптера; `start_index` приходит только из
    /// проверенного checkpoint.
    pub(crate) fn launch(
        plan: ReadyPlan,
        io: AdapterPair,
        options: EngineOptions,
        clock: Arc<dyn Clock + Send + Sync>,
        start_index: u64,
    ) -> Result<EngineHandle, StartError> {
        let cursor = ProbeCursor::new(&plan, start_index)?;
        Self::launch_n(plan, vec![io], vec![cursor], options, clock, None)
    }

    fn launch_n(
        plan: ReadyPlan,
        ios: Vec<AdapterPair>,
        cursors: Vec<ProbeCursor>,
        options: EngineOptions,
        clock: Arc<dyn Clock + Send + Sync>,
        pcap_sink: Option<PcapSink>,
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
        if options.tx_stall_timeout.is_zero() {
            return Err(StartError::InvalidOptions("tx_stall_timeout must be > 0"));
        }
        let count = plan.nics().len();
        if ios.len() != count || cursors.len() != count {
            return Err(StartError::InvalidOptions(
                "the number of adapter pairs must equal the number of plan adapters",
            ));
        }
        let stall_micros = u64::try_from(options.tx_stall_timeout.as_micros()).unwrap_or(u64::MAX);
        let rate = plan.effective().max_rate() / count as f64;
        let io_timeout = options.io_timeout.min(MAX_IO_TIMEOUT);

        let queue = Queue::new(options.result_capacity, options.event_batch_limit);
        lock(&queue.st).started = Some(plan.range());
        let shared = Arc::new(Shared {
            halt: AtomicU8::new(RUN),
            fail: Mutex::new(None),
            rx_health: Mutex::new(vec![RxHealth { kernel_drops: None }; count]),
            sent: AtomicU64::new(0),
            positions: cursors
                .iter()
                .map(|c| AtomicU64::new(c.position()))
                .collect(),
            offsets: (0..count as u32).map(|k| plan.nic_offset(k)).collect(),
            received: AtomicU64::new(0),
            discarded: AtomicU64::new(0),
            duplicates: AtomicU64::new(0),
            rate_bits: (0..count).map(|_| AtomicU64::new(0f64.to_bits())).collect(),
            tx_ends: (0..count).map(|_| AtomicU8::new(END_RUNNING)).collect(),
            rx_ends: (0..count).map(|_| AtomicU8::new(END_RUNNING)).collect(),
            exited: AtomicUsize::new(0),
            threads: 2 * count,
            queue,
            clock,
            io_timeout,
            wait_micros: u64::from(plan.effective().wait_secs()) * 1_000_000,
            progress_micros: u64::try_from(options.progress_interval.as_micros())
                .unwrap_or(u64::MAX),
        });

        let dedup = Arc::new(Mutex::new(DedupCache::new(options.dedup_capacity)));
        let mut txs = Vec::with_capacity(count);
        let mut rxs = Vec::with_capacity(count);
        for io in ios {
            let AdapterPair { tx, rx } = io;
            txs.push(tx);
            rxs.push(rx);
        }
        // Остановить уже запущенные потоки и вернуть отказ запуска.
        let abort = |shared: &Shared, threads: Vec<JoinHandle<()>>, e: std::io::Error| {
            shared.command(STOP);
            for t in threads {
                let _ = t.join();
            }
            StartError::Spawn(e.to_string())
        };
        // Планы RX строятся до первого потока: отказ не оставляет живых потоков.
        let rx_plans = (0..count)
            .map(|k| rx_plan(&plan, k))
            .collect::<Result<Vec<_>, _>>()?;
        let mut rx_threads = Vec::with_capacity(count);
        // RX первым: к моменту первой отправки приёмник уже слушает.
        for (k, (rx, plan)) in rxs.into_iter().zip(rx_plans).enumerate() {
            let s = shared.clone();
            let dedup = dedup.clone();
            let sink = pcap_sink.clone();
            let name = if k == 0 {
                "rmasscan-rx".to_string()
            } else {
                format!("rmasscan-rx{k}")
            };
            match std::thread::Builder::new()
                .name(name)
                .spawn(move || run_rx(s, k, rx, plan, dedup, sink))
            {
                Ok(t) => rx_threads.push(t),
                Err(e) => return Err(abort(&shared, rx_threads, e)),
            }
        }
        let mut tx_threads = Vec::with_capacity(count);
        for (k, (tx, cursor)) in txs.into_iter().zip(cursors).enumerate() {
            let s = shared.clone();
            let name = if k == 0 {
                "rmasscan-tx".to_string()
            } else {
                format!("rmasscan-tx{k}")
            };
            match std::thread::Builder::new()
                .name(name)
                .spawn(move || run_tx(s, k, tx, cursor, rate, stall_micros))
            {
                Ok(t) => tx_threads.push(t),
                Err(e) => {
                    let all = rx_threads.into_iter().chain(tx_threads).collect();
                    return Err(abort(&shared, all, e));
                }
            }
        }
        let digest = job_digest(&plan);
        Ok(EngineHandle {
            shared,
            options,
            digest,
            resumed_from: None,
            tx_threads,
            rx_threads,
        })
    }
}

/// План для RX-потока адаптера `k`: `parse_reply` сверяет адрес и порты
/// источника с `plan.binding()` (то есть с `nic[0]`), поэтому для `k > 0`
/// адаптер `k` ставится первым.
fn rx_plan(plan: &ReadyPlan, k: usize) -> Result<ReadyPlan, PlanError> {
    if k == 0 {
        return Ok(plan.clone());
    }
    let mut nics: Vec<NicBinding> = plan.nics().to_vec();
    nics.swap(0, k);
    ReadyPlan::new_cli(plan.effective().clone(), nics)
}

/// Владелец запуска. `Drop` останавливает и дожидается оба потока.
pub struct EngineHandle {
    shared: Arc<Shared>,
    options: EngineOptions,
    digest: [u8; 32],
    resumed_from: Option<[u8; 16]>,
    tx_threads: Vec<JoinHandle<()>>,
    rx_threads: Vec<JoinHandle<()>>,
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
        if o.reason != Reason::Paused {
            return None;
        }
        // Нормализованная база возобновления (`min_k resume_base`), а не
        // сырой индекс прогресса: для плана Studio (shard 1/1, один адаптер)
        // это одно и то же число.
        let next_index = lock(&self.shared.queue.st).checkpoint?;
        Some(Checkpoint {
            format_version: CHECKPOINT_FORMAT_VERSION,
            engine_version: ENGINE_ALGORITHM_VERSION,
            scan_id: self.options.scan_id,
            attempt_id: self.options.attempt_id,
            job_digest: self.digest,
            next_index,
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
        let threads = std::mem::take(&mut self.tx_threads)
            .into_iter()
            .chain(std::mem::take(&mut self.rx_threads));
        for t in threads {
            // Паника потока уже учтена в итоге через `ExitGuard`; здесь важен
            // сам join (handles освобождены).
            let _ = t.join();
        }
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        if self.tx_threads.is_empty() && self.rx_threads.is_empty() {
            return;
        }
        // Потребитель потерян: остановить, закрыть очередь, дождаться потоков.
        self.shared.command(STOP);
        self.shared.queue.close();
        self.join_threads();
    }
}

#[cfg(test)]
mod tests {
    //! Возобновление `--resume` через `start_cli_with_clock` (Задача 3):
    //! пауза посреди пачки повторов и усечённый `resume-count` с повторами.
    //! Только `FakeAdapter` и `ManualClock`.

    use super::*;
    use crate::fake::{FakeAdapter, ManualClock};
    use rmasscan_core::config::{Operation, ScanConfig, validate};
    use rmasscan_core::massip::MassIp;
    use rmasscan_core::probe::{AdapterBinding, NicBinding};
    use rmasscan_core::scan::{Shard, transmit_index_stream};
    use rmasscan_core::targets::{add_target_string, parse_ports};
    use std::sync::OnceLock;
    use std::time::Instant;

    const SEED: u64 = 0x1234_5678_9abc;

    struct Spec {
        targets: &'static str,
        ports: &'static str,
        retries: u32,
        shard: Shard,
        resume_index: u64,
        resume_count: Option<u64>,
    }

    fn cli_plan(spec: &Spec) -> ReadyPlan {
        let mut m = MassIp::new();
        add_target_string(m.ipv4_mut(), spec.targets).unwrap();
        parse_ports(m.ports_mut(), spec.ports).unwrap();
        let cfg = ScanConfig {
            targets: m,
            seed: SEED,
            max_rate: 1_000_000.0,
            wait_secs: 0,
            retries: spec.retries,
            shard: spec.shard,
            resume_index: spec.resume_index,
            resume_count: spec.resume_count,
            ..ScanConfig::default()
        };
        let eff = validate(&cfg, Operation::Scan).unwrap();
        let nic = NicBinding::from(AdapterBinding {
            interface_id: "fake0".into(),
            link_type: LinkType::Ethernet,
            source_ipv4: 0x0aff_0001,
            source_mac: [0, 0x11, 0x22, 0x33, 0x44, 0x55],
            next_hop_mac: [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            source_ports: (40000, 40015),
        });
        ReadyPlan::new_cli(eff, vec![nic]).unwrap()
    }

    /// range = 4 адреса x 3 порта = 12.
    fn plan12(retries: u32, shard: Shard, resume_index: u64) -> ReadyPlan {
        cli_plan(&Spec {
            targets: "10.0.0.0/30",
            ports: "80,443,8080",
            retries,
            shard,
            resume_index,
            resume_count: None,
        })
    }

    struct Leg {
        frames: Vec<Vec<u8>>,
        outcome: Outcome,
        events: Vec<Event>,
    }

    /// Один прогон; `pause_after = Some(n)` подаёт Pause изнутри n-й отправки.
    fn run_leg(plan: &ReadyPlan, pause_after: Option<usize>) -> Leg {
        let clock = ManualClock::new();
        let fake = FakeAdapter::new().with_clock(clock.clone());
        let cell: Arc<OnceLock<CancelHandle>> = Arc::default();
        if let Some(n) = pause_after {
            let c2 = cell.clone();
            fake.set_send_hook(move |sent| {
                if sent == n {
                    let c = loop {
                        if let Some(c) = c2.get() {
                            break c;
                        }
                        std::thread::yield_now();
                    };
                    c.pause();
                }
            });
        }
        let c: Arc<dyn Clock + Send + Sync> = clock;
        let h = Engine::start_cli_with_clock(
            plan.clone(),
            vec![fake.pair()],
            EngineOptions::new([1; 16], [2; 16]),
            c,
            None,
        )
        .unwrap();
        cell.set(h.cancel_handle()).ok();
        let mut events = Vec::new();
        let t = Instant::now();
        loop {
            match h.recv_event_timeout(Duration::from_millis(50)) {
                Ok(e) => {
                    let fin = matches!(e, Event::Finished { .. });
                    events.push(e);
                    if fin {
                        break;
                    }
                }
                Err(TryRecvError::Empty) => {
                    assert!(
                        t.elapsed() < Duration::from_secs(10),
                        "no Finished: {events:?}"
                    );
                }
                Err(TryRecvError::Disconnected) => break,
            }
        }
        let outcome = h.join().unwrap();
        Leg {
            frames: fake.sent_frames(),
            outcome,
            events,
        }
    }

    fn sorted(mut v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        v.sort();
        v
    }

    /// Review Focus 1 (`main.c:421-431`, `:1408-1414`): пауза посреди пачки
    /// из `retries + 1` кадров одного внешнего `i` при `shard.of > 1`. Два
    /// отрезка вместе равны непрерывному прогону как мультимножество кадров:
    /// без пропуска и без лишней копии. Для shard 2/2 смещение потока равно 1,
    /// поэтому дополнительно проверяется нормализованная база возобновления.
    #[test]
    fn resume_mid_retry_burst_completes_exact_multiset() {
        for one in [1, 2] {
            let shard = Shard { one, of: 2 };
            let whole = run_leg(&plan12(1, shard, 0), None);
            assert_eq!(whole.outcome.reason, Reason::Completed, "shard {one}/2");
            // retries 1: пачка из 2 кадров на каждый из 12 внешних `i` потока.
            assert_eq!(whole.frames.len(), 24, "shard {one}/2");

            let first = run_leg(&plan12(1, shard, 0), Some(5));
            assert_eq!(first.outcome.reason, Reason::Paused, "shard {one}/2");
            let next_index = first
                .events
                .iter()
                .find_map(|e| match e {
                    Event::CheckpointReady { next_index } => Some(*next_index),
                    _ => None,
                })
                .expect("CheckpointReady after a clean pause");
            assert!(
                (5..whole.frames.len()).contains(&first.frames.len()),
                "pause landed outside the run: {}",
                first.frames.len()
            );
            // Пауза не рвёт пачку: отправлено целое число пачек по 2 кадра.
            assert_eq!(first.frames.len() % 2, 0, "paused mid burst");
            // Сырой индекс прогресса = база + смещение shard (nic_offset).
            let offset = u64::from(one - 1);
            assert_eq!(first.outcome.progress.next_index, next_index + offset);

            let second = run_leg(&plan12(1, shard, next_index), None);
            assert_eq!(second.outcome.reason, Reason::Completed, "shard {one}/2");

            let mut joined = first.frames.clone();
            joined.extend(second.frames.clone());
            assert_eq!(
                sorted(joined),
                sorted(whole.frames.clone()),
                "shard {one}/2: pause + resume != uninterrupted"
            );
        }
    }

    /// Review Focus 4 (`main.c:269-273`, `:1425`): при `resume-count < range`
    /// и `retries > 0` C ждёт `min_index >= range` и зависает. Здесь каждый
    /// адаптер завершается по своему `effective_end`.
    #[test]
    fn resume_count_with_retries_terminates_cleanly() {
        let plan = cli_plan(&Spec {
            targets: "10.0.0.0-10.0.0.49",
            ports: "80,443",
            retries: 1,
            shard: Shard::default(),
            resume_index: 10,
            resume_count: Some(8),
        });
        assert_eq!(plan.range(), 100);
        let leg = run_leg(&plan, None);
        assert_eq!(leg.outcome.reason, Reason::Completed);

        let expected =
            transmit_index_stream(100, Shard::default(), 1, 0, 10, Some(8), 1, 1e6).count();
        assert!(expected > 0 && expected < 100 * 4, "expected {expected}");
        assert_eq!(leg.frames.len(), expected);
        let mut cursor = plan.cursor_for_nic(0, None).unwrap();
        let mut reference = Vec::new();
        while let Some(p) = cursor.current() {
            reference.push(p.frame.clone());
            cursor.advance_sent();
        }
        assert_eq!(leg.frames, reference);
        assert_eq!(leg.outcome.progress.next_index, plan.effective_end(0));
    }
}
