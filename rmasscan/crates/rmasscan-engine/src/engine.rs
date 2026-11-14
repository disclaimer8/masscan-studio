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
//! - Во время скана ничто в рабочих потоках не блокируется на потребителе: очередь
//!   результатов ограничена и при переполнении даёт `Failed(ConsumerTooSlow)`.
//!   Единственное ожидание потребителя это сброс таблицы стека TCP в конце RX
//!   (`EngineOptions::tcp_stack`, справка 4b A9): наборы баннеров соединений ждут
//!   места в очереди, перепроверяя Stop не реже раза в 50 мс; Stop, `Drop` handle и
//!   `join`/`join_drain` его прерывают, естественный конец он в `Failed` не превращает.
//!
//! # Блокировки стека TCP
//! Таблица соединений принадлежит своему RX-потоку и вызывается без единой
//! блокировки. Блокировка очереди результатов берётся только внутри методов
//! `Queue` (ни один вызов стека и ни один `keep_going` под ней не идёт), блокировка
//! очереди кадров стека адаптера (`stack_out`) только на перекладывание готовых
//! кадров; две эти блокировки никогда не держатся вместе.

use std::cell::Cell;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use rmasscan_core::banner::BannerRecord;
use rmasscan_core::ndp::NDP_FRAME_LEN;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{NicBinding, PlanError, ProbeCursor, ReadyPlan};
use rmasscan_core::receive::{PortStatus, Reply, ndp_reply_for, parse_reply};
use rmasscan_core::stack::{StackOutput, StackStats, TableParams, TcpStack};
use rmasscan_core::tcp_frame::{TcpFrameBuilder, tcp_segment};
use rmasscan_core::throttle::{Clock, SystemClock, Throttler};

use crate::banners::{BannerOptions, Output, StackSummary, TcpStackOptions, udp_reply_banners};
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

/// Потолок очереди кадров стека TCP на адаптер (RX кладёт, TX отправляет): `BUFFER_COUNT - 1` буферов пула C
/// (`src/stack-queue.c:105-124`, справка A8). RX на полной очереди не ждёт (Р7, у C ждёт, E1.12): кадр выбрасывается
/// и считается в [`StackSummary::frames_dropped`].
pub const STACK_OUT_CAP: usize = 16_383;

/// Сколько соединений уничтожает один вызов `TcpStack::finish` в сбросе таблицы в конце RX: между порциями RX
/// отдаёт их баннеры в очередь (с ожиданием места), и таблица не выдаёт сразу все баннеры скана.
const FLUSH_CONNECTIONS: usize = 64;

/// Шаг ожидания места в очереди при сбросе в конце: не реже этого RX перепроверяет Stop.
const ROOM_RECHECK: Duration = Duration::from_millis(50);

/// Бюджет очереди результатов в байтах нагрузки баннеров по умолчанию (64 МиБ).
pub const DEFAULT_RESULT_BYTE_CAPACITY: usize = 64 * 1024 * 1024;

/// Параметры запуска. `wait` берётся из плана.
#[derive(Debug, Clone)]
pub struct EngineOptions {
    pub scan_id: [u8; 16],
    pub attempt_id: [u8; 16],
    /// Сколько элементов (принятых ответов и, с [`Self::banners`], их баннеров) может ждать потребителя. Ответ
    /// принимается, пока очередь не полна, и встаёт вместе со своими баннерами.
    pub result_capacity: usize,
    /// Сколько байт нагрузки баннеров может ждать потребителя (по умолчанию [`DEFAULT_RESULT_BYTE_CAPACITY`], ноль
    /// запрещён). Один порог на любой набор баннеров: набор встаёт целиком или не встаёт, пустая очередь принимает
    /// любой набор. Ответы без баннеров на байты не смотрят.
    pub result_byte_capacity: usize,
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
    /// Баннеры UDP-ответов (`--banners`, `--rawudp`). `None` (по умолчанию, так у Studio): ни одна датаграмма не
    /// разбирается, кадры, события и [`EngineHandle::recv_event_timeout`] побайтно прежние, а
    /// [`EngineHandle::recv_output_timeout`] не выдаёт [`Output::Banner`].
    pub banners: Option<BannerOptions>,
    /// Пользовательский стек TCP (`--banners`, подэтап 4b). `None` (по умолчанию, так у Studio): ни тиков, ни
    /// разбора сегментов, ни [`Output::ConnectionBanner`], путь приёма побайтно прежний. С `Some` каждый RX-поток
    /// ведёт свою таблицу ([`TcpStackOptions`]): таймеры на каждой итерации приёма, сегменты до статуса и дедупа
    /// (справка A1), сброс живых соединений в конце RX ([`EngineHandle::stack_stats`] даёт счётчики).
    pub tcp_stack: Option<TcpStackOptions>,
}

impl EngineOptions {
    pub fn new(scan_id: [u8; 16], attempt_id: [u8; 16]) -> Self {
        Self {
            scan_id,
            attempt_id,
            result_capacity: 4096,
            result_byte_capacity: DEFAULT_RESULT_BYTE_CAPACITY,
            event_batch_limit: 1000,
            progress_interval: Duration::from_millis(250),
            io_timeout: MAX_IO_TIMEOUT,
            dedup_capacity: MAX_DEDUP_ENTRIES,
            tx_stall_timeout: DEFAULT_TX_STALL_TIMEOUT,
            banners: None,
            tcp_stack: None,
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

/// `(remote ip, remote port, local ip, local port, ip_proto, status_bucket, ipv6 remote+local)`. Последний элемент
/// `None` у каждого IPv4-ответа, поэтому ключи IPv4 различаются ровно так же, как раньше; у IPv6-ответа
/// (`remote_ip = local_ip = 0`) он несёт оба адреса целиком (`dedup_is_duplicate` в C принимает `ipaddress`,
/// main.c:1067, и сравнивает версию и все 128 бит).
type DedupKey = (u32, u16, u32, u16, u8, u8, Option<(u128, u128)>);

/// Ограниченный dedup по кортежу (remote ip/port, local ip/port, протокол, корзина статуса). Протокол в ключе нужен,
/// чтобы `80/tcp` и `80/udp` одного хоста не глушили друг друга. Корзина статуса разделяет для не-TCP ответ-датаграмму
/// (`Open`) и ICMP Port Unreachable (`Closed`) на тот же порт. У TCP она 0 для SYN-ACK и RST: RST вслед за SYN-ACK на тот
/// же кортеж остаётся повтором, как в C (`dedup_is_duplicate`, main.c:1067–1068, статус не различает). Closed TCP от ICMP
/// 3/3 (флагов нет) идёт в корзину 1. C такие ответы не дедуплицирует вовсе (`handle_icmp` сообщает каждый,
/// proto-icmp.c:182); rmasscan пропускает их через этот же кэш, отдельная корзина нужна, чтобы они не глушили SYN-ACK.
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
        let bucket = match (r.ip_proto, r.status) {
            // Closed без флагов TCP приходит только из ICMP 3/3 (RST всегда несёт 0x04): у него своя корзина, иначе он
            // глушил бы настоящий SYN-ACK (C не пропускает ICMP через dedup, main.c:917-919).
            (6, PortStatus::Closed) if r.tcp_flags == 0 => 1,
            (6, _) | (_, PortStatus::Open) => 0,
            (_, PortStatus::Closed) => 1,
            (_, PortStatus::Arp) => 2,
        };
        let key = (
            r.remote_ip,
            r.remote_port,
            r.local_ip,
            r.local_port,
            r.ip_proto,
            bucket,
            r.ip6.map(|a| (a.remote, a.local)),
        );
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

/// Элемент очереди результатов: принятый ответ, баннер ответа, стоящего перед ним, или баннер соединения TCP. Одна
/// очередь на все RX-потоки: ответ и его баннеры кладутся под одной блокировкой ([`Queue::push_result`]), набор
/// соединения тоже ([`Queue::push_conn_banners`]), поэтому между записями одного набора ничего не встаёт.
enum Entry {
    Reply(Reply),
    Banner(Box<BannerRecord>),
    ConnBanner(Box<BannerRecord>),
}

#[derive(Default)]
struct QState {
    started: Option<u64>,
    results: VecDeque<Entry>,
    /// Сумма нагрузки баннеров в `results` (бюджет `result_byte_capacity`).
    banner_bytes: usize,
    progress: Option<Progress>,
    outcome: Option<Outcome>,
    checkpoint: Option<u64>,
    checkpoint_taken: bool,
    finished_taken: bool,
    closed: bool,
    /// Потребитель ждёт потоки в `join`/`join_drain` и больше ничего не прочтёт: сброс в конце не ждёт места.
    joining: bool,
    /// Сколько производителей ждут места в `room` ([`Queue::push_conn_banners_waiting`]); без них выдача никого не
    /// будит (путь Studio без стека не меняется).
    room_waiters: usize,
}

impl QState {
    /// Снимает баннер (ответа или соединения) с головы очереди и возвращает его байты бюджету. `None`, если во главе
    /// ответ или очередь пуста (ответ остаётся на месте).
    fn pop_banner(&mut self) -> Option<Output> {
        let len = match self.results.front()? {
            Entry::Reply(_) => return None,
            Entry::Banner(b) | Entry::ConnBanner(b) => b.payload.len(),
        };
        let out = match self.results.pop_front()? {
            Entry::Banner(b) => Output::Banner(*b),
            Entry::ConnBanner(b) => Output::ConnectionBanner(*b),
            Entry::Reply(r) => {
                self.results.push_front(Entry::Reply(r));
                return None;
            }
        };
        debug_assert!(self.banner_bytes >= len);
        self.banner_bytes = self.banner_bytes.saturating_sub(len);
        Some(out)
    }
}

/// Сумма нагрузки набора баннеров (насыщающая).
fn payload_bytes(set: &[BannerRecord]) -> usize {
    set.iter()
        .fold(0usize, |a, b| a.saturating_add(b.payload.len()))
}

struct Queue {
    st: Mutex<QState>,
    /// Новые элементы для потребителя.
    cv: Condvar,
    /// Освободилось место: будит сброс в конце ([`Self::push_conn_banners_waiting`]). Та же блокировка `st`.
    room: Condvar,
    capacity: usize,
    byte_capacity: usize,
    batch_limit: usize,
}

impl Queue {
    fn new(capacity: usize, byte_capacity: usize, batch_limit: usize) -> Self {
        Self {
            st: Mutex::new(QState::default()),
            cv: Condvar::new(),
            room: Condvar::new(),
            capacity,
            byte_capacity,
            batch_limit,
        }
    }

    /// Правило приёма для любого набора (ответ с баннерами, позже набор соединения): очередь пуста, либо записей
    /// меньше `capacity` и байты с набором не больше `byte_capacity`. Набор встаёт целиком или не встаёт; пустая
    /// очередь принимает любой, иначе набор больше бюджета остановил бы скан навсегда.
    fn fits(&self, st: &QState, new_bytes: usize) -> bool {
        st.results.is_empty()
            || (st.results.len() < self.capacity
                && st.banner_bytes.saturating_add(new_bytes) <= self.byte_capacity)
    }

    /// Не блокирует. `false` = очередь переполнена, ответ НЕ принят (и его баннеры тоже). Ёмкость считается по
    /// элементам очереди, ответам и баннерам, и по байтам нагрузки баннеров ([`Self::fits`]): ответ встаёт под той
    /// же блокировкой вместе со своими баннерами (очередь превышает ёмкость не больше чем на баннеры одного ответа).
    /// Без баннеров проверка по записям прежняя.
    fn push_result(&self, r: Reply, banners: Vec<BannerRecord>) -> bool {
        let mut st = lock(&self.st);
        if st.closed {
            return true; // потребителя нет: молча не храним
        }
        let new_bytes = payload_bytes(&banners);
        if !self.fits(&st, new_bytes) {
            return false;
        }
        st.results.push_back(Entry::Reply(r));
        st.results
            .extend(banners.into_iter().map(|b| Entry::Banner(Box::new(b))));
        st.banner_bytes = st.banner_bytes.saturating_add(new_bytes);
        drop(st);
        self.cv.notify_all();
        true
    }

    /// Кладёт набор соединения (записи одного `banner_flush`, `src/stack-tcp-core.c:800-830`) под той же
    /// блокировкой: правило [`Self::fits`], набор целиком или ничего, каждая запись отдельный элемент. Пустой набор
    /// ничего не делает. Не блокирует; `false`: не встал (RX даёт `Failed(ConsumerTooSlow)`, как для ответа).
    fn push_conn_banners(&self, set: Vec<BannerRecord>) -> bool {
        if set.is_empty() {
            return true;
        }
        let new_bytes = payload_bytes(&set);
        let mut st = lock(&self.st);
        if st.closed {
            return true; // потребителя нет: молча не храним
        }
        if !self.fits(&st, new_bytes) {
            return false;
        }
        Self::append_conn(&mut st, set, new_bytes);
        drop(st);
        self.cv.notify_all();
        true
    }

    /// [`Self::push_conn_banners`] для сброса таблицы в конце RX (справка A9): ждёт, пока набор поместится
    /// (потребитель дочитывает очередь, выдача будит `room`), и перепроверяет `keep_going` не реже раза в
    /// [`ROOM_RECHECK`]. `keep_going` вызывается без блокировки очереди. `false` только когда `keep_going` сказал
    /// стоп, а набор так и не поместился. Набор отбрасывается с `true`, если потребителя нет (`close`) или он ждёт
    /// потоки в `join` и непрочитанные баннеры всё равно отбросит.
    fn push_conn_banners_waiting(
        &self,
        set: Vec<BannerRecord>,
        keep_going: &dyn Fn() -> bool,
    ) -> bool {
        if set.is_empty() {
            return true;
        }
        let new_bytes = payload_bytes(&set);
        let mut st = lock(&self.st);
        loop {
            if st.closed || st.joining {
                return true;
            }
            if self.fits(&st, new_bytes) {
                Self::append_conn(&mut st, set, new_bytes);
                drop(st);
                self.cv.notify_all();
                return true;
            }
            drop(st);
            if !keep_going() {
                return false;
            }
            st = lock(&self.st);
            // Место могло освободиться, пока блокировка была отпущена: перепроверить до ожидания.
            if st.closed || st.joining || self.fits(&st, new_bytes) {
                continue;
            }
            st.room_waiters += 1;
            st = self
                .room
                .wait_timeout(st, ROOM_RECHECK)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
            st.room_waiters -= 1;
        }
    }

    fn append_conn(st: &mut QState, set: Vec<BannerRecord>, new_bytes: usize) {
        st.results
            .extend(set.into_iter().map(|b| Entry::ConnBanner(Box::new(b))));
        st.banner_bytes = st.banner_bytes.saturating_add(new_bytes);
    }

    /// Потребитель ушёл в `join`: ожидающий сброс в конце больше не ждёт места.
    fn begin_join(&self) {
        let mut st = lock(&self.st);
        st.joining = true;
        drop(st);
        self.room.notify_all();
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
        st.banner_bytes = 0;
        st.progress = None;
        drop(st);
        self.room.notify_all();
    }

    /// Следующий элемент. [`Want::Events`] (прежний API) выбрасывает баннеры обоих видов, поэтому без баннеров и для
    /// потребителя событий порядок и пачки прежние; [`Want::Outputs`] отдаёт баннер отдельным элементом и обрывает на
    /// нём пачку ответов (гарантия порядка [`Output`]). Снятый элемент будит ожидающий сброс в конце (`room`).
    fn pop_locked(&self, st: &mut QState, want: Want) -> Result<Output, TryRecvError> {
        if let Some(range) = st.started.take() {
            return Ok(Output::Event(Event::Started { range }));
        }
        let before = st.results.len();
        let entry = self.pop_entry(st, want);
        // Место освободилось: разбудить сброс в конце, если он ждёт (без ожидающих никого не будим).
        if st.results.len() < before && st.room_waiters > 0 {
            self.room.notify_all();
        }
        if let Some(o) = entry {
            return Ok(o);
        }
        if let Some(p) = st.progress.take() {
            return Ok(Output::Event(Event::Progress(p)));
        }
        let Some(outcome) = st.outcome.as_ref() else {
            return Err(TryRecvError::Empty);
        };
        if let Some(next_index) = st.checkpoint
            && !st.checkpoint_taken
        {
            st.checkpoint_taken = true;
            return Ok(Output::Event(Event::CheckpointReady { next_index }));
        }
        if st.finished_taken {
            return Err(TryRecvError::Disconnected);
        }
        st.finished_taken = true;
        Ok(Output::Event(Event::Finished {
            reason: outcome.reason.clone(),
        }))
    }

    /// Элемент из `results`: баннер во главе (для [`Want::Outputs`]; [`Want::Events`] пропускает их с возвратом байт)
    /// или пачка ответов до `batch_limit`, которую баннер любого вида обрывает (для [`Want::Events`] пропускается).
    fn pop_entry(&self, st: &mut QState, want: Want) -> Option<Output> {
        while let Some(b) = st.pop_banner() {
            if want == Want::Outputs {
                return Some(b);
            }
        }
        if st.results.is_empty() {
            return None;
        }
        let mut replies = Vec::with_capacity(st.results.len().min(self.batch_limit));
        while replies.len() < self.batch_limit {
            match st.results.front() {
                Some(Entry::Reply(_)) => {
                    if let Some(Entry::Reply(r)) = st.results.pop_front() {
                        replies.push(r);
                    }
                }
                Some(Entry::Banner(_) | Entry::ConnBanner(_)) if want == Want::Events => {
                    st.pop_banner();
                }
                _ => break,
            }
        }
        Some(Output::Event(Event::Results { replies }))
    }

    /// Только события: [`Want::Events`] баннер не возвращает, повтор лишь страховка тотальности.
    fn pop_event_locked(&self, st: &mut QState) -> Result<Event, TryRecvError> {
        loop {
            if let Output::Event(e) = self.pop_locked(st, Want::Events)? {
                return Ok(e);
            }
        }
    }

    fn try_pop(&self) -> Result<Event, TryRecvError> {
        let mut st = lock(&self.st);
        self.pop_event_locked(&mut st)
    }

    fn pop_timeout(&self, timeout: Duration) -> Result<Event, TryRecvError> {
        match self.wait_pop(timeout, Want::Events)? {
            Output::Event(e) => Ok(e),
            Output::Banner(_) | Output::ConnectionBanner(_) => Err(TryRecvError::Empty),
        }
    }

    fn pop_output_timeout(&self, timeout: Duration) -> Result<Output, TryRecvError> {
        self.wait_pop(timeout, Want::Outputs)
    }

    fn wait_pop(&self, timeout: Duration, want: Want) -> Result<Output, TryRecvError> {
        let deadline = std::time::Instant::now() + timeout;
        let mut st = lock(&self.st);
        loop {
            let got = match want {
                Want::Events => self.pop_event_locked(&mut st).map(Output::Event),
                Want::Outputs => self.pop_locked(&mut st, want),
            };
            match got {
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

/// Что читает потребитель: только события ([`EngineHandle::recv_event_timeout`], [`EngineHandle::try_event`]) или
/// события и баннеры ([`EngineHandle::recv_output_timeout`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Want {
    Events,
    Outputs,
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
    /// `effective_end(k)` каждого адаптера: позиция исчерпанного курсора равна `end`.
    ends: Vec<u64>,
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
    /// Кадры Neighbor Advertisement от RX к TX своего адаптера (`stack_transmit_packetbuffer`, stack-queue.h:36:
    /// RX форматирует ответ, отправляет TX). Пишет RX-поток адаптера, читает его TX-поток. Пусто и не читается у
    /// адаптера без `source_ipv6`, поэтому путь IPv4 не меняется.
    ndp_out: Vec<Mutex<VecDeque<[u8; NDP_FRAME_LEN]>>>,
    /// `plan.nics()[k].source_ipv6.is_some()`: отвечает ли адаптер `k` на Neighbor Solicitation.
    ndp_enabled: Vec<bool>,
    clock: Arc<dyn Clock + Send + Sync>,
    io_timeout: Duration,
    wait_micros: u64,
    progress_micros: u64,
    /// [`EngineOptions::banners`]: RX разбирает датаграмму ответа, прошедшего дедуп.
    banners: Option<BannerOptions>,
    /// Кадры стека TCP от RX к TX своего адаптера (`stack_transmit_packetbuffer`, `src/stack-queue.c:105-124`): пишет
    /// RX-поток адаптера (не больше [`STACK_OUT_CAP`], лишнее выбрасывается со счётом), отправляет TX. Без
    /// [`EngineOptions::tcp_stack`] очереди есть (по одной на адаптер), но всегда пусты.
    stack_out: Vec<Mutex<VecDeque<Vec<u8>>>>,
    /// Последний слепок счётчиков таблицы каждого RX-потока (пишет свой RX: на шаге прогресса и при выходе).
    stack_stats: Vec<Mutex<StackStats>>,
    /// Кадры стека, которые отправил TX (все адаптеры).
    stack_frames_sent: AtomicU64,
    /// Кадры стека, которые не встали в `stack_out` или не построились ([`StackSummary::frames_dropped`]).
    stack_frames_dropped: AtomicU64,
    /// Живые соединения, брошенные несбросленными, когда `finish` ответил «ещё есть» без продвижения
    /// ([`StackSummary::flush_abandoned`]).
    stack_flush_abandoned: AtomicU64,
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
    ///
    /// Исчерпанный адаптер (`position >= effective_end`) в минимум не входит: его позиция равна `end`, а
    /// `end - nic_offset` лежит вне класса вычетов потока и при `nic_count >= 3` увёл бы `resume-index` в
    /// индексы чужого шарда. Если исчерпаны все, результат не меньше `effective_end` (T4: `paused.conf` не нужен).
    fn resume_base(&self) -> u64 {
        let live = self
            .positions
            .iter()
            .zip(&self.offsets)
            .zip(&self.ends)
            .filter_map(|((p, off), end)| {
                let pos = p.load(Ordering::Acquire);
                (pos < *end).then(|| pos.saturating_sub(*off))
            })
            .min();
        live.unwrap_or_else(|| self.ends.iter().copied().max().unwrap_or(0))
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
/// "Stop/Pause <= 1 с" (один сон короче любого лимита отмены). Пауза в середине
/// пачки повторов шлёт остаток пачки сразу, мимо throttle, поэтому остаётся
/// такой же быстрой; исключение одно: адаптер, застрявший на `WouldBlockUnsent`
/// во время этой досылки, даёт `TxStalled` по окну `tx_stall_timeout` (решение
/// be022ac). Значение можно пересмотреть после замеров на реальном адаптере.
const WOULD_BLOCK_BACKOFF_MICROS: u64 = 1_000;

/// Потолок очереди Neighbor Advertisement на адаптер: сосед, заваливший нас NS, не растит память без предела
/// (лишний ответ отбрасывается, сосед переспросит).
const NDP_OUT_CAP: usize = 64;

/// Отправляет накопленные Neighbor Advertisement своего адаптера. Ответ необязательный: сосед переспросит, поэтому
/// `WouldBlockUnsent`, `Uncertain` и ошибка адаптера скан не валят (ошибку отправки увидит следующий кадр
/// скана) и кадр не повторяется.
///
/// Работа ограничена: вызов берёт снимок очереди один раз (RX, который кладёт дальше, не удерживает TX) и перед
/// каждой отправкой спрашивает `keep_going`. Иначе заполненная очередь (`NDP_OUT_CAP`) на блокирующемся адаптере
/// (до `timeout` на кадр) держала бы TX-поток секунды и нарушала контракт Stop/Pause <= 1 с и окно `TxStalled`.
/// Остаток снимка при остановке отбрасывается. C ограничивает это пачкой throttle (main.c:478-486).
fn flush_ndp(
    queue: &Mutex<VecDeque<[u8; NDP_FRAME_LEN]>>,
    keep_going: &dyn Fn() -> bool,
    tx: &mut dyn Tx,
    timeout: Duration,
) {
    let batch = std::mem::take(&mut *lock(queue));
    for frame in batch {
        if !keep_going() {
            return;
        }
        let _ = tx.send(&frame, timeout);
    }
}

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
    // пачку сразу. Остаток пачки при паузе уходит одним неограниченным по скорости проходом (ниже), поэтому
    // задержка Pause ограничена числом повторов, а не throttle. Для `retries == 0` пачка из одного кадра,
    // поведение прежнее.
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

    // Только адаптер с адресом IPv6 отвечает на NS; у остальных (весь IPv4) путь не меняется.
    let ndp = shared.ndp_enabled[idx];
    let end = 'run: loop {
        if ndp {
            flush_ndp(
                &shared.ndp_out[idx],
                &|| shared.halted() == RUN,
                &mut *tx,
                shared.io_timeout,
            );
        }
        // Конец последовательности сильнее паузы: next_index == range это
        // завершение, а не checkpoint с пустым остатком.
        // `--infinite` (`main.c:445-449`): конец прохода запускает следующий, пока не придёт команда остановки.
        if cursor.current().is_none() && !cursor.advance_pass() {
            // Probe, который не построился, это отказ, а не естественный конец скана.
            if let Some(e) = cursor.build_error() {
                shared.fail(FailReason::ProbeBuild(e.to_string()));
                break END_HALTED;
            }
            break END_NATURAL;
        }
        if halted() {
            break END_HALTED;
        }
        // Пауза посреди пачки: остаток пачки уходит сразу, мимо throttle (не более `retries` кадров), иначе при
        // малой скорости Pause ждал бы до `retries / rate` секунд. Любая команда прерывает сон throttle.
        let pausing = || shared.halted() == PAUSE && mid_burst.get();
        let batch = if pausing() {
            u64::MAX
        } else {
            match throttler.next_batch_interruptible(my_sent, clock, || shared.halted() != RUN) {
                Ok(b) => b,
                Err(_) if pausing() => u64::MAX,
                Err(_) => break END_HALTED,
            }
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
                // `--infinite`: проход кончился посреди окна throttle, продолжаем со следующего прохода.
                if cursor.advance_pass() {
                    continue;
                }
                if let Some(e) = cursor.build_error() {
                    shared.fail(FailReason::ProbeBuild(e.to_string()));
                    break 'run END_HALTED;
                }
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
    // Окно ожидания ответов после конца передачи: RX ещё принимает, и NS соседа, пришедший теперь, тоже должен
    // получить NA (иначе роутер не вернёт нам ответы на последние зонды). TX живёт, пока RX не закончил.
    if ndp {
        loop {
            let done = shared.rx_end() != END_RUNNING || shared.halted() >= STOP;
            flush_ndp(
                &shared.ndp_out[idx],
                // Linger шлёт NA и после Pause: RX принимает до конца окна ожидания (main.c:470-493 сбрасывает
                // очередь до `is_rx_done`); не шлёт только после Stop/Fail.
                &|| shared.halted() < STOP,
                &mut *tx,
                shared.io_timeout,
            );
            if done {
                break;
            }
            clock.sleep_micros(WOULD_BLOCK_BACKOFF_MICROS);
        }
    }
}

fn stall_fail(shared: &Shared, idle_micros: u64) {
    shared.fail(FailReason::TxStalled {
        idle_millis: idle_micros / 1_000,
    });
}

// ------------------------------------------------------------------ rx ----

/// Биты SYN и ACK (`TCP_IS_SYNACK`, `src/stack-tcp-core.h:15-21`: `(flags & 0x12) == 0x12`).
const TCP_SYNACK: u8 = 0x12;

/// Стек TCP приёмного потока: своя таблица, построитель кадров своего адаптера (`nic[0]` плана RX, тот же адаптер,
/// что у `parse_reply`) и буфер выдачи, который каждый вызов оставляет пустым.
struct RxStack {
    table: Box<dyn TcpStack>,
    frames: TcpFrameBuilder,
    out: StackOutput,
}

impl RxStack {
    fn new(table: Box<dyn TcpStack>, plan: &ReadyPlan) -> Self {
        RxStack {
            table,
            frames: TcpFrameBuilder::from_plan(plan),
            out: StackOutput::default(),
        }
    }

    /// Сегмент кадра стеку (справка A1 шаг 6, A2). Кадр с битами SYN и ACK стек видит, только если `parse_reply` его
    /// принял (`reply_ok`: cookie верен; `Open`, а при SYN|ACK|RST `Closed`): C проверяет cookie в стековом блоке и
    /// на плохом делает `continue` (`src/main.c:969-975`), не трогая TCB, даже живой, и не доходя до статуса, а с
    /// верным создаёт TCB (`:976-986`), в том числе для SYN|ACK|RST (`TCP_IS_SYNACK` смотрит только биты 0x12).
    /// Остальные сегменты идут в стек без cookie (`:987-1041`). Отличие от C: стек видит только то, что принял
    /// `parse_reply` (`rmasscan-core/src/receive.rs:35-39`), а он проверяет и принадлежность адреса и порта ответчика
    /// эффективному набору целей; поэтому SYN-ACK с верным cookie извне набора TCB не получает, а C его создаёт (до
    /// стека C проверяет набор целей только для ARP, `src/main.c:891`). Практически ничтожно: cookie покрывает адрес
    /// и порт ответчика. `true`: стек взял сегмент.
    fn segment(
        &mut self,
        now: u64,
        frame: &[u8],
        link: LinkType,
        plan: &ReadyPlan,
        reply_ok: bool,
    ) -> bool {
        let Some(seg) = tcp_segment(frame, link, plan) else {
            return false;
        };
        if seg.flags & TCP_SYNACK == TCP_SYNACK && !reply_ok {
            return false;
        }
        self.table.on_segment(now, &seg, &mut self.out)
    }

    /// Выдача стека за вызов: кадры в `stack_out` своего адаптера без ожидания (полная очередь или кадр, который
    /// построитель не строит, это выброс со счётом, Р7), наборы баннеров в очередь результатов без ожидания. Кадры
    /// строятся без блокировок, под блокировкой `stack_out` только перекладываются. `false`: набор не встал
    /// (`ConsumerTooSlow`).
    fn deliver(&mut self, shared: &Shared, idx: usize) -> bool {
        if !self.out.segments.is_empty() {
            let frames: Vec<Vec<u8>> = self
                .out
                .segments
                .drain(..)
                .map(|s| self.frames.build(&s))
                .collect();
            let mut dropped = 0u64;
            {
                let mut q = lock(&shared.stack_out[idx]);
                for f in frames {
                    if f.is_empty() || q.len() >= STACK_OUT_CAP {
                        dropped += 1;
                    } else {
                        q.push_back(f);
                    }
                }
            }
            if dropped > 0 {
                shared
                    .stack_frames_dropped
                    .fetch_add(dropped, Ordering::Relaxed);
            }
        }
        for set in self.out.banners.drain(..) {
            if !shared.queue.push_conn_banners(set) {
                return false;
            }
        }
        true
    }

    /// Сброс таблицы в конце RX (`tcpcon_destroy_table`, `src/main.c:1111-1113`, `src/stack-tcp-core.c:933-961`):
    /// порциями по [`FLUSH_CONNECTIONS`], наборы баннеров ждут места в очереди, пока не пришёл Stop. Кадров сброс не
    /// шлёт: сегменты, если таблица их всё же выдала, считаются выброшенными. `false`: Stop прервал сброс и часть
    /// баннеров не доставлена.
    fn flush(&mut self, shared: &Shared) -> bool {
        let keep_going = || shared.halted() < STOP;
        loop {
            let live = self.table.stats().tcbs_live;
            let more = self.table.finish(FLUSH_CONNECTIONS, &mut self.out);
            let stray = self.out.segments.len() as u64;
            self.out.segments.clear();
            if stray > 0 {
                shared
                    .stack_frames_dropped
                    .fetch_add(stray, Ordering::Relaxed);
            }
            let produced = !self.out.banners.is_empty();
            for set in self.out.banners.drain(..) {
                if !shared.queue.push_conn_banners_waiting(set, &keep_going) {
                    return false;
                }
            }
            // Страховка тотальности: таблица, которая отвечает «ещё есть», но ничего не выдала и не уничтожила ни
            // одного соединения, нарушила контракт `finish`; цикл без продвижения не крутится.
            if !more {
                return true;
            }
            let left = self.table.stats().tcbs_live;
            if !produced && left >= live {
                // Баннеры не теряются молча: оставшиеся соединения считаются в `StackSummary::flush_abandoned`,
                // итог остаётся `Completed` (нарушение контракта таблицы, а не отказ скана).
                shared
                    .stack_flush_abandoned
                    .fetch_add(left, Ordering::Relaxed);
                return true;
            }
        }
    }
}

/// Приём.
///
/// # Контракт недоверенного входа
/// ЛЮБАЯ ошибка [`parse_reply`] (слишком длинный кадр, VLAN, обрезанные
/// заголовки, фрагмент, плохие длины и версии, плохие суммы) означает "кадр
/// чужой или битый: выбросить и продолжать приём" (C `main.c:773 continue`).
/// Это враждебный/посторонний ввод, а не отказ скана: он никогда не ведёт к
/// `Failed`. Падением считается только ошибка самого адаптера (`Rx::recv`).
///
/// # Стек TCP (`table: Some`, [`EngineOptions::tcp_stack`])
/// Порядок итерации справки A1: таймеры таблицы по часам движка (и без кадра), затем для кадра `parse_reply`
/// (чистая), `tcp_segment` и стек, затем прежний путь статуса и дедупа. Сегмент, который взял стек, в
/// `Progress.discarded` не идёт. После цикла (естественный конец, пауза, Stop; не отказ) живые соединения
/// сбрасываются с ожиданием места в очереди, до публикации `rx_end`.
fn run_rx(
    shared: Arc<Shared>,
    idx: usize,
    rx: Box<dyn Rx>,
    plan: ReadyPlan,
    dedup: Arc<Mutex<DedupCache>>,
    pcap_sink: Option<PcapSink>,
    table: Option<Box<dyn TcpStack>>,
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
    let mut stack = table.map(|t| RxStack::new(t, &plan));

    let end = loop {
        if shared.halted() >= STOP {
            break END_HALTED;
        }
        let got = match rx.recv(&mut buf, shared.io_timeout) {
            Err(e) => {
                shared.fail(FailReason::RxError(e.message));
                break END_HALTED;
            }
            Ok(got) => got,
        };
        // Таймеры стека на каждой итерации, с кадром и без, раньше любого фильтра кадра (справка A1 шаги 1-2,
        // `tcpcon_timeouts`, `src/main.c:777-797`), по часам движка; это же время получает сегмент кадра. Без стека
        // часы здесь не читаются.
        let at = match stack.as_mut() {
            Some(s) => {
                let at = clock.now_micros();
                s.table.on_tick(at, &mut s.out);
                if !s.deliver(&shared, idx) {
                    shared.fail(FailReason::ConsumerTooSlow);
                    break END_HALTED;
                }
                at
            }
            None => 0,
        };
        match got {
            None => {}
            Some(n) => {
                // n > buf.len() это нарушение контракта адаптера; безвредно
                // обрезаем, парсер отбросит такой кадр.
                let frame = &buf[..n.min(buf.len())];
                // `--pcap` (main.c:943-951): кадр уходит в файл захвата до
                // проверки cookie и дедупликации. Фильтр "наш адрес и порт"
                // принадлежит писателю захвата (`rmasscan-cli::pcap_writer`).
                if let Some(sink) = &pcap_sink
                    && frame.len() <= PCAP_MAX_FRAME
                {
                    sink(frame, clock.now_micros());
                }
                // Neighbor Solicitation для нашего `source_ipv6` (main.c:829-840, :859): ответ идёт в TX, кадр не
                // зонд и дальше не разбирается.
                let na = if shared.ndp_enabled[idx] {
                    ndp_reply_for(frame, link, &plan)
                } else {
                    None
                };
                if let Some(na) = na {
                    let mut q = lock(&shared.ndp_out[idx]);
                    if q.len() < NDP_OUT_CAP {
                        q.push_back(na);
                    }
                } else {
                    let parsed = parse_reply(frame, link, &plan);
                    // Стек раньше статуса и дедупа (справка A1 шаг 6, `src/main.c:962-1043` до `:1048-1092`): повтор
                    // SYN-ACK стек видит, запись статуса остаётся одна.
                    let taken = match stack.as_mut() {
                        Some(s) => {
                            let taken =
                                s.segment(at, frame, link, &plan, matches!(parsed, Ok(Some(_))));
                            if !s.deliver(&shared, idx) {
                                shared.fail(FailReason::ConsumerTooSlow);
                                break END_HALTED;
                            }
                            taken
                        }
                        None => false,
                    };
                    match parsed {
                        Ok(Some(reply)) => {
                            let fresh = lock(&dedup).insert(&reply);
                            // `handle_udp` (`src/main.c:909-916`, `src/proto-udp.c:54-132`) только за ответом,
                            // прошедшим дедуп: повтор датаграммы не даёт ни записи статуса, ни баннеров (у C даёт
                            // оба, справка C1.3). Баннеры встают в очередь сразу за своим ответом.
                            let banners = match (&shared.banners, fresh) {
                                (Some(o), true) => udp_reply_banners(
                                    o,
                                    frame,
                                    link,
                                    &reply,
                                    plan.effective().seed(),
                                ),
                                _ => Vec::new(),
                            };
                            if !fresh {
                                shared.duplicates.fetch_add(1, Ordering::Relaxed);
                            } else if shared.queue.push_result(reply, banners) {
                                shared.received.fetch_add(1, Ordering::Relaxed);
                            } else {
                                // Ответ потерян, молча не теряем: останавливаем TX
                                // и завершаемся Failed; принятое остаётся в очереди.
                                shared.fail(FailReason::ConsumerTooSlow);
                                break END_HALTED;
                            }
                        }
                        // Не наш пакет, либо ЛЮБАЯ ошибка разбора: выбросить и
                        // продолжать (см. контракт выше). Сегмент, который взял стек, не выброшен.
                        Ok(None) | Err(_) => {
                            if !taken {
                                shared.discarded.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        }
        let now = clock.now_micros();
        if now.wrapping_sub(last_progress) >= shared.progress_micros {
            last_progress = now;
            if let Some(s) = &stack {
                *lock(&shared.stack_stats[idx]) = s.table.stats();
            }
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
    let mut end = if clean || end == END_HALTED {
        end
    } else {
        END_HALTED
    };
    if let Some(s) = stack.as_mut() {
        // Сброс живых соединений после естественного конца, паузы и Stop, но не после отказа (решение 21 плана 4b).
        // Он идёт после финальной проверки приёма: окно наблюдения уже закрыто, и сброс, который ждёт медленного
        // потребителя, поздними потерями ядра естественный конец в `Failed` не превращает. Прерванный Stop сброс
        // доставил не всё: итог `Stopped`, а не `Completed`.
        if shared.halted() < FAIL && !s.flush(&shared) {
            end = END_HALTED;
        }
        *lock(&shared.stack_stats[idx]) = s.table.stats();
    }
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
        if options.result_byte_capacity == 0 {
            return Err(StartError::InvalidOptions(
                "result_byte_capacity must be > 0",
            ));
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

        let queue = Queue::new(
            options.result_capacity,
            options.result_byte_capacity,
            options.event_batch_limit,
        );
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
            ends: (0..count as u32).map(|k| plan.effective_end(k)).collect(),
            received: AtomicU64::new(0),
            discarded: AtomicU64::new(0),
            duplicates: AtomicU64::new(0),
            rate_bits: (0..count).map(|_| AtomicU64::new(0f64.to_bits())).collect(),
            tx_ends: (0..count).map(|_| AtomicU8::new(END_RUNNING)).collect(),
            rx_ends: (0..count).map(|_| AtomicU8::new(END_RUNNING)).collect(),
            exited: AtomicUsize::new(0),
            threads: 2 * count,
            queue,
            ndp_out: (0..count).map(|_| Mutex::new(VecDeque::new())).collect(),
            ndp_enabled: plan
                .nics()
                .iter()
                .map(|n| n.source_ipv6.is_some())
                .collect(),
            clock,
            io_timeout,
            wait_micros: u64::from(plan.effective().wait_secs()) * 1_000_000,
            progress_micros: u64::try_from(options.progress_interval.as_micros())
                .unwrap_or(u64::MAX),
            banners: options.banners,
            stack_out: (0..count).map(|_| Mutex::new(VecDeque::new())).collect(),
            stack_stats: (0..count)
                .map(|_| Mutex::new(StackStats::default()))
                .collect(),
            stack_frames_sent: AtomicU64::new(0),
            stack_frames_dropped: AtomicU64::new(0),
            stack_flush_abandoned: AtomicU64::new(0),
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
        // Своя таблица стека у каждого RX-потока (`tcpcon_create_table` в `receive_thread`, `src/main.c:612`): ёмкость
        // и бюджет скана делятся между адаптерами, ёмкость не меньше 1024.
        let tables: Vec<Option<Box<dyn TcpStack>>> = (0..count)
            .map(|_| {
                options.tcp_stack.as_ref().map(|o| {
                    o.factory.new_table(TableParams {
                        seed: plan.effective().seed(),
                        capacity: (o.table_capacity / count).max(1024),
                        banner_byte_budget: o.banner_byte_budget / count,
                    })
                })
            })
            .collect();
        let mut rx_threads = Vec::with_capacity(count);
        // RX первым: к моменту первой отправки приёмник уже слушает.
        for (k, ((rx, plan), table)) in rxs.into_iter().zip(rx_plans).zip(tables).enumerate() {
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
                .spawn(move || run_rx(s, k, rx, plan, dedup, sink, table))
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
    ReadyPlan::new_cli_with_payloads(plan.effective().clone(), nics, plan.payloads().clone())
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

    /// Нормализованная база возобновления (`min_k resume_base`) сразу после того, как пауза остановила все TX-потоки,
    /// ещё до конца `wait`: `main.c:1447-1456` пишет `paused.conf` до ожидания, а `CheckpointReady` приходит только
    /// вместе с итогом, то есть после `wait`. `None`, пока TX идёт, после Stop/отказа и если передача закончилась
    /// сама (конец последовательности сильнее паузы). Значение то же, что в итоговом `CheckpointReady`: позиции
    /// TX после выхода потоков не меняются.
    pub fn pause_resume_base(&self) -> Option<u64> {
        (self.shared.halted() == PAUSE && self.shared.tx_end() == END_HALTED)
            .then(|| self.shared.resume_base())
    }

    /// Следующее событие без ожидания. С `banners: Some` или `tcp_stack: Some` баннер, стоящий в очереди на пути события,
    /// этот вызов ОТБРАСЫВАЕТ: он не возвращается и нигде не учитывается. Баннеры читает только
    /// [`Self::recv_output_timeout`].
    pub fn try_event(&self) -> Result<Event, TryRecvError> {
        self.shared.queue.try_pop()
    }

    /// Ждёт событие не дольше `timeout`; `Err(Empty)` по таймауту. С `banners: Some` ([`EngineOptions::banners`]) или
    /// `tcp_stack: Some` ([`EngineOptions::tcp_stack`]) баннеры, встреченные по пути, этот вызов ОТБРАСЫВАЕТ: они не
    /// возвращаются и нигде не учитываются, а их место в очереди освобождается. Потребитель баннеров читает очередь
    /// только [`Self::recv_output_timeout`].
    pub fn recv_event_timeout(&self, timeout: Duration) -> Result<Event, TryRecvError> {
        self.shared.queue.pop_timeout(timeout)
    }

    /// Как [`Self::recv_event_timeout`], но отдаёт и баннеры, по порядку очереди: баннеры ответа идут сразу после
    /// пачки [`Event::Results`], которая этим ответом кончается, и раньше записи любого более позднего ответа. При
    /// `banners: None` выдаёт ровно те же события, что [`Self::recv_event_timeout`], и ни одного [`Output::Banner`].
    /// Время записи баннера (`BannerRecord::timestamp`) движок не знает и ставит 0: у [`rmasscan_core::receive::Reply`]
    /// времени нет, потребитель ставит баннеру время записи статуса его ответа. С `tcp_stack: Some` выдаёт и
    /// [`Output::ConnectionBanner`] (время 0, потребитель ставит время обработки); при `tcp_stack: None` ни одного.
    pub fn recv_output_timeout(&self, timeout: Duration) -> Result<Output, TryRecvError> {
        self.shared.queue.pop_output_timeout(timeout)
    }

    /// Терминальный итог, если оба потока уже остановились. Не расходует
    /// события и не мешает их чтению.
    pub fn outcome(&self) -> Option<Outcome> {
        lock(&self.shared.queue.st).outcome.clone()
    }

    pub fn progress(&self) -> Progress {
        self.shared.snapshot()
    }

    /// Счётчики стека TCP ([`EngineOptions::tcp_stack`]): сумма таблиц RX-потоков и кадры стека. Таблица отдаёт
    /// счётчики на шаге прогресса и при выходе RX-потока, поэтому окончательные они после `Finished` (CLI читает их
    /// после конца цикла событий и до `join`). Без стека нули.
    pub fn stack_stats(&self) -> StackSummary {
        let mut s = StackSummary {
            frames_sent: self.shared.stack_frames_sent.load(Ordering::Relaxed),
            frames_dropped: self.shared.stack_frames_dropped.load(Ordering::Relaxed),
            flush_abandoned: self.shared.stack_flush_abandoned.load(Ordering::Relaxed),
            ..StackSummary::default()
        };
        for t in &self.shared.stack_stats {
            s.add_table(&lock(t));
        }
        s
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
    /// через `try_event`/`recv_event_timeout` события не повторяются. Непрочитанные
    /// баннеры (`banners: Some`, `tcp_stack: Some`) ОТБРАСЫВАЮТСЯ и нигде не учитываются:
    /// сброс таблицы стека в конце RX после вызова места в очереди не ждёт.
    ///
    /// При панике рабочего потока принятые до неё результаты сохраняются, а
    /// итог это `Ok(Failed(WorkerPanicked))` с последним слепком счётчиков.
    pub fn join_drain(mut self) -> Result<(Outcome, Vec<Event>), EngineError> {
        // Сброс стека в конце ждёт потребителя; этот потребитель ждёт потоки и баннеров не прочтёт.
        self.shared.queue.begin_join();
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
    use rmasscan_core::scan::Shard;
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
        rate: f64,
    }

    fn cli_plan(spec: &Spec) -> ReadyPlan {
        let mut m = MassIp::new();
        add_target_string(m.ipv4_mut(), spec.targets).unwrap();
        parse_ports(m.ports_mut(), spec.ports).unwrap();
        let cfg = ScanConfig {
            targets: m,
            seed: SEED,
            max_rate: spec.rate,
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
            source_ipv4: 0xc612_0063,
            source_mac: [0, 0x11, 0x22, 0x33, 0x44, 0x55],
            next_hop_mac: [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            source_ports: (40000, 40015),
        });
        ReadyPlan::new_cli(eff, vec![nic]).unwrap()
    }

    /// range = 4 адреса x 3 порта = 12.
    fn plan12(retries: u32, shard: Shard, resume_index: u64) -> ReadyPlan {
        cli_plan(&Spec {
            targets: "198.18.0.0/30",
            ports: "80,443,8080",
            retries,
            shard,
            resume_index,
            resume_count: None,
            rate: 1_000_000.0,
        })
    }

    struct Leg {
        frames: Vec<Vec<u8>>,
        outcome: Outcome,
        events: Vec<Event>,
        /// Время часов `ManualClock` от старта до `Finished`.
        elapsed_micros: u64,
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
        let t0 = clock.now_micros();
        let c: Arc<dyn Clock + Send + Sync> = clock.clone();
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
            elapsed_micros: clock.now_micros() - t0,
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

    /// Пауза посреди пачки при малой скорости: остаток пачки уходит мимо throttle, `CheckpointReady` приходит
    /// без долгого ожидания (по часам engine), пачка при этом доведена до конца.
    #[test]
    fn pause_mid_burst_at_a_low_rate_finishes_the_burst_unthrottled() {
        let plan = cli_plan(&Spec {
            targets: "198.18.0.0/30",
            ports: "80,443,8080",
            retries: 99,
            shard: Shard::default(),
            resume_index: 0,
            resume_count: None,
            rate: 1.0,
        });
        let leg = run_leg(&plan, Some(1));
        assert_eq!(leg.outcome.reason, Reason::Paused);
        // Пачка из `retries + 1` кадров одного `i` доведена до конца, дальше пауза.
        assert_eq!(leg.frames.len(), 100);
        assert!(
            leg.events
                .iter()
                .any(|e| matches!(e, Event::CheckpointReady { next_index: 1 }))
        );
        // 99 кадров по 1 кадру/с заняли бы ~99 с; без throttle часы почти не движутся.
        assert!(
            leg.elapsed_micros < 5_000_000,
            "burst was throttled: {} us",
            leg.elapsed_micros
        );
    }

    /// Review Focus 4 (`main.c:269-273`, `:1425`): при `resume-count < range`
    /// и `retries > 0` C ждёт `min_index >= range` и зависает. Здесь каждый
    /// адаптер завершается по своему `effective_end`.
    #[test]
    fn resume_count_with_retries_terminates_cleanly() {
        let plan = cli_plan(&Spec {
            targets: "198.18.0.0-198.18.0.49",
            ports: "80,443",
            retries: 1,
            shard: Shard::default(),
            resume_index: 10,
            resume_count: Some(8),
            rate: 1_000_000.0,
        });
        assert_eq!(plan.range(), 100);
        let leg = run_leg(&plan, None);
        assert_eq!(leg.outcome.reason, Reason::Completed);

        // (min(100, 10 + 8) + 1 * 100 - 10) внешних `i` x (retries + 1) = 108 x 2 (main.c:269-273, 421-431).
        assert_eq!(leg.frames.len(), 216);
        let mut cursor = plan.cursor_for_nic(0, None).unwrap();
        let mut reference = Vec::new();
        while let Some(p) = cursor.current() {
            reference.push(p.frame.clone());
            cursor.advance_sent();
        }
        assert_eq!(leg.frames, reference);
        assert_eq!(leg.outcome.progress.next_index, plan.effective_end(0));
    }

    /// Два адаптера: A `198.18.0.99` с портами `40000..=40015`, B `198.18.0.100` с портами `41000..=41003`.
    fn plan_two_nics() -> ReadyPlan {
        let mut m = MassIp::new();
        add_target_string(m.ipv4_mut(), "198.18.1.0/30").unwrap();
        parse_ports(m.ports_mut(), "80").unwrap();
        let cfg = ScanConfig {
            targets: m,
            seed: SEED,
            max_rate: 1_000_000.0,
            wait_secs: 1, // при 0 RX выходит в той же итерации, где увидел конец TX, и ответы теряются
            ..ScanConfig::default()
        };
        let eff = validate(&cfg, Operation::Scan).unwrap();
        let nic = |ip: u32, mac: u8, ports: (u16, u16)| {
            NicBinding::from(AdapterBinding {
                interface_id: format!("fake{mac}"),
                link_type: LinkType::Ethernet,
                source_ipv4: ip,
                source_mac: [0, 0x11, 0x22, 0x33, 0x44, mac],
                next_hop_mac: [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
                source_ports: ports,
            })
        };
        ReadyPlan::new_cli(
            eff,
            vec![
                nic(0xc612_0063, 0x55, (40000, 40015)),
                nic(0xc612_0064, 0x56, (41000, 41003)),
            ],
        )
        .unwrap()
    }

    /// T3 M-8 (первый тест с n > 1) и T6, замечание 4: два адаптера делят поток внешних индексов по чётности
    /// (`start = nic_index`, `increment = nic_count`, `main.c:269`) и пишут ответы в одну очередь; RX-поток адаптера
    /// `k` проверяет диапазон адресов и портов именно своего адаптера (`rx_plan`), так что ответ, валидный для
    /// адаптера B, адаптером A не принимается, и наоборот.
    #[test]
    fn two_adapters_split_even_odd_and_each_accepts_only_its_own_range() {
        let plan = plan_two_nics();
        let clock = ManualClock::new();
        let fakes = [
            FakeAdapter::new().with_clock(clock.clone()),
            FakeAdapter::new().with_clock(clock.clone()),
        ];
        for f in &fakes {
            f.set_responder(|syn| crate::fake::reply_to_syn(syn, 0x12).into_iter().collect());
        }
        let c: Arc<dyn Clock + Send + Sync> = clock.clone();
        let h = Engine::start_cli_with_clock(
            plan.clone(),
            fakes.iter().map(FakeAdapter::pair).collect(),
            EngineOptions::new([1; 16], [2; 16]),
            c,
            None,
        )
        .unwrap();
        let (_, events) = h.join_drain().unwrap();
        let replies: Vec<Reply> = events
            .into_iter()
            .filter_map(|e| match e {
                Event::Results { replies } => Some(replies),
                _ => None,
            })
            .flatten()
            .collect();

        // range = 4: адаптер A шлёт внешние индексы 0 и 2, адаптер B 1 и 3.
        let sent = |k: usize| fakes[k].sent_frames();
        assert_eq!((sent(0).len(), sent(1).len()), (2, 2));
        let mut want = [Vec::new(), Vec::new()];
        for (k, w) in want.iter_mut().enumerate() {
            let mut cursor = plan.cursor_for_nic(k as u32, None).unwrap();
            while let Some(p) = cursor.current() {
                w.push(p.frame.clone());
                cursor.advance_sent();
            }
        }
        assert_eq!(sent(0), want[0]);
        assert_eq!(sent(1), want[1]);
        // Источники кадров разные: каждый адаптер шлёт со своего адреса и порта.
        for (k, ip) in [[198, 18, 0, 99], [198, 18, 0, 100]]
            .into_iter()
            .enumerate()
        {
            assert!(sent(k).iter().all(|f| f[26..30] == ip), "adapter {k}");
        }
        // Все четыре ответа дошли до общей очереди, по два на адаптер.
        assert_eq!(replies.len(), 4);
        for ip in [0xc612_0063u32, 0xc612_0064] {
            assert_eq!(replies.iter().filter(|r| r.local_ip == ip).count(), 2);
        }

        // Ответ на SYN адаптера B валиден только для RX адаптера B.
        let link = LinkType::Ethernet;
        let (rx_a, rx_b) = (rx_plan(&plan, 0).unwrap(), rx_plan(&plan, 1).unwrap());
        for k in 0..2 {
            for syn in sent(k) {
                let reply = crate::fake::reply_to_syn(&syn, 0x12).unwrap();
                let accepted = |p: &ReadyPlan| matches!(parse_reply(&reply, link, p), Ok(Some(_)));
                assert_eq!(accepted(&rx_a), k == 0, "RX A, reply to adapter {k}");
                assert_eq!(accepted(&rx_b), k == 1, "RX B, reply to adapter {k}");
            }
        }
    }

    /// T5: R7 снят на всех входах, в том числе в плане RX адаптера `k > 0` (`rx_plan` перестраивает план через
    /// `new_cli_with_payloads`). Два адаптера сканируют цели IPv6: каждый шлёт свои зонды IPv6 со своего источника,
    /// и ответ на SYN адаптера B принимает только RX адаптера B.
    #[test]
    fn ipv6_targets_scan_on_every_adapter_including_rx_plans_for_k_above_zero() {
        const ME: [u128; 2] = [
            0xfd00_0000_0000_0000_0000_0000_0000_0063,
            0xfd00_0000_0000_0000_0000_0000_0000_0064,
        ];
        let mut m = MassIp::new();
        m.add_target_string("2001:db8::1-2001:db8::2").unwrap();
        parse_ports(m.ports_mut(), "80,443").unwrap();
        let cfg = ScanConfig {
            targets: m,
            seed: SEED,
            max_rate: 1_000_000.0,
            wait_secs: 1,
            ..ScanConfig::default()
        };
        let eff = validate(&cfg, Operation::Scan).unwrap();
        let nic = |k: usize| {
            let mut n = NicBinding::from(AdapterBinding {
                interface_id: format!("fake{k}"),
                link_type: LinkType::Ethernet,
                source_ipv4: 0,
                source_mac: [0x02, 0, 0, 0, 0, 0x10 + k as u8],
                next_hop_mac: [0; 6],
                source_ports: (40000 + k as u16, 40000 + k as u16),
            });
            n.source_ipv6 = Some(ME[k]);
            n.next_hop_mac_ipv6 = Some([0x02, 0, 0, 0, 0, 0x20]);
            n
        };
        let plan = ReadyPlan::new_cli(eff, vec![nic(0), nic(1)]).unwrap();
        let (rx_a, rx_b) = (rx_plan(&plan, 0).unwrap(), rx_plan(&plan, 1).unwrap());
        let clock = ManualClock::new();
        let fakes: Vec<FakeAdapter> = (0..2)
            .map(|_| {
                let f = FakeAdapter::new().with_clock(clock.clone());
                f.set_responder(|syn| crate::fake::reply_to_syn6(syn, 0x12).into_iter().collect());
                f
            })
            .collect();
        let c: Arc<dyn Clock + Send + Sync> = clock.clone();
        let h = Engine::start_cli_with_clock(
            plan.clone(),
            fakes.iter().map(FakeAdapter::pair).collect(),
            EngineOptions::new([1; 16], [2; 16]),
            c,
            None,
        )
        .unwrap();
        let mut replies = Vec::new();
        let t = Instant::now();
        loop {
            match h.recv_event_timeout(Duration::from_millis(50)) {
                Ok(Event::Results { replies: r }) => replies.extend(r),
                Ok(Event::Finished { .. }) | Err(TryRecvError::Disconnected) => break,
                Ok(_) => {}
                Err(TryRecvError::Empty) => assert!(t.elapsed() < Duration::from_secs(10)),
            }
        }
        h.join().unwrap();
        let sent = |k: usize| fakes[k].sent_frames();
        assert_eq!((sent(0).len(), sent(1).len()), (2, 2));
        for (k, me) in ME.iter().enumerate() {
            for f in sent(k) {
                assert_eq!(&f[12..14], &[0x86, 0xdd], "adapter {k} sends IPv6");
                assert_eq!(u128::from_be_bytes(f[22..38].try_into().unwrap()), *me);
            }
        }
        assert_eq!(replies.len(), 4);
        for (k, me) in ME.iter().enumerate() {
            assert_eq!(
                replies
                    .iter()
                    .filter(|r| r.ip6.map(|i| i.local) == Some(*me))
                    .count(),
                2,
                "adapter {k}"
            );
        }
        let link = LinkType::Ethernet;
        for k in 0..2 {
            for syn in sent(k) {
                let reply = crate::fake::reply_to_syn6(&syn, 0x12).unwrap();
                let accepted = |p: &ReadyPlan| matches!(parse_reply(&reply, link, p), Ok(Some(_)));
                assert_eq!(accepted(&rx_a), k == 0, "RX A, reply to adapter {k}");
                assert_eq!(accepted(&rx_b), k == 1, "RX B, reply to adapter {k}");
            }
        }
    }

    /// T7 I-2: исчерпанный адаптер не тянет `resume-index` вниз. `--shard 1/2`, 3 адаптера, range 13: поток шарда 1
    /// это индексы {0,1,2,6,7,8,12}; адаптеры 1 ({1,7}) и 2 ({2,8}) заканчивают, адаптер 0 ({0,6,12}) встаёт после
    /// отправки 0 и 6. Сырой минимум дал бы `resume-index = 11` (индекс шарда 2), правильная база 12.
    #[test]
    fn exhausted_adapter_does_not_drag_the_resume_base_into_another_shard() {
        let mut m = MassIp::new();
        add_target_string(m.ipv4_mut(), "198.18.1.0-198.18.1.12").unwrap();
        parse_ports(m.ports_mut(), "80").unwrap();
        let cfg = ScanConfig {
            targets: m,
            seed: SEED,
            max_rate: 1_000_000.0,
            wait_secs: 0,
            shard: Shard { one: 1, of: 2 },
            ..ScanConfig::default()
        };
        let eff = validate(&cfg, Operation::Scan).unwrap();
        let nic = |ip: u32, mac: u8| {
            NicBinding::from(AdapterBinding {
                interface_id: format!("fake{mac}"),
                link_type: LinkType::Ethernet,
                source_ipv4: ip,
                source_mac: [0, 0x11, 0x22, 0x33, 0x44, mac],
                next_hop_mac: [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
                source_ports: (40000, 40015),
            })
        };
        let plan = ReadyPlan::new_cli(
            eff,
            vec![
                nic(0xc612_0063, 1),
                nic(0xc612_0064, 2),
                nic(0xc612_0065, 3),
            ],
        )
        .unwrap();
        assert_eq!(plan.range(), 13);

        let clock = ManualClock::new();
        let fakes: Vec<FakeAdapter> = (0..3)
            .map(|_| FakeAdapter::new().with_clock(clock.clone()))
            .collect();
        // Адаптер 0 встаёт на внешнем индексе 12 (две отправки: 0 и 6), пока 1 и 2 ещё не закончили, затем ждёт.
        let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cell: Arc<OnceLock<CancelHandle>> = Arc::default();
        {
            let (c2, d2) = (cell.clone(), done.clone());
            fakes[0].set_send_hook(move |sent| {
                if sent == 2 {
                    // Ждём, пока адаптеры 1 и 2 отправят свои потоки целиком.
                    let t = Instant::now();
                    while d2.load(Ordering::SeqCst) < 4 && t.elapsed() < Duration::from_secs(10) {
                        std::thread::yield_now();
                    }
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
        for f in &fakes[1..] {
            let d3 = done.clone();
            f.set_send_hook(move |_| {
                d3.fetch_add(1, Ordering::SeqCst);
            });
        }
        let c: Arc<dyn Clock + Send + Sync> = clock.clone();
        let h = Engine::start_cli_with_clock(
            plan.clone(),
            fakes.iter().map(FakeAdapter::pair).collect(),
            EngineOptions::new([1; 16], [2; 16]),
            c,
            None,
        )
        .unwrap();
        cell.set(h.cancel_handle()).ok();
        let (outcome, events) = h.join_drain().unwrap();
        assert_eq!(outcome.reason, Reason::Paused);
        let next = events.iter().find_map(|e| match e {
            Event::CheckpointReady { next_index } => Some(*next_index),
            _ => None,
        });
        assert_eq!(next, Some(12), "exhausted adapters must not lower the base");
        let sent0 = fakes[0].sent_count();
        assert_eq!(sent0, 2, "adapter 0 paused after indices 0 and 6");

        // Возобновление с базы 12: во всех адаптерах отправляется ровно индекс 12.
        let mut resumed_cfg = cfg.clone();
        resumed_cfg.resume_index = 12;
        let eff = validate(&resumed_cfg, Operation::Scan).unwrap();
        let plan2 = ReadyPlan::new_cli(eff, plan.nics().to_vec()).unwrap();
        let mut all = Vec::new();
        for k in 0..3 {
            let mut cursor = plan2.cursor_for_nic(k, None).unwrap();
            while let Some(p) = cursor.current() {
                all.push(p.frame.clone());
                cursor.advance_sent();
            }
        }
        assert_eq!(all.len(), 1, "exactly one probe left (index 12)");
        let mut c0 = plan.cursor_for_nic(0, None).unwrap();
        let mut stream0 = Vec::new();
        while let Some(p) = c0.current() {
            stream0.push(p.frame.clone());
            c0.advance_sent();
        }
        assert_eq!(stream0.len(), 3);
        assert_eq!(all[0], stream0[2], "the leftover probe is nic 0's index 12");
    }

    // ---- NDP: ответчик на входящий Neighbor Solicitation (IPv6, задача 4) ----

    const NDP_ME: u128 = 0xfd00_0000_0000_0000_0000_0000_0000_0002;
    const NDP_ME_MAC: [u8; 6] = [0, 0x11, 0x22, 0x33, 0x44, 0x55];
    const NDP_ROUTER_MAC: [u8; 6] = [0x0a, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
    const NDP_ROUTER_IP: u128 = 0xfe80_0000_0000_0000_0000_0000_0000_abcd;

    /// Скан IPv4 (порядок кадров замороженный) с `source_ipv6` адаптера: приёмник и ответчик NS от целей не
    /// зависят (CLI ставит `source_ipv6` только при целях IPv6; здесь он задан нарочно).
    fn ndp_plan(source_ipv6: Option<u128>) -> ReadyPlan {
        let plan = plan12(0, Shard { one: 1, of: 1 }, 0);
        let mut nic = plan.nics()[0].clone();
        nic.source_ipv6 = source_ipv6;
        ReadyPlan::new_cli(plan.effective().clone(), vec![nic]).unwrap()
    }

    fn run_with_rx(plan: &ReadyPlan, rx: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let clock = ManualClock::new();
        let fake = FakeAdapter::new().with_clock(clock.clone());
        for f in rx {
            fake.push_frame(f);
        }
        let c: Arc<dyn Clock + Send + Sync> = clock.clone();
        let h = Engine::start_cli_with_clock(
            plan.clone(),
            vec![fake.pair()],
            EngineOptions::new([1; 16], [2; 16]),
            c,
            None,
        )
        .unwrap();
        let t = Instant::now();
        loop {
            match h.recv_event_timeout(Duration::from_millis(50)) {
                Ok(Event::Finished { .. }) | Err(TryRecvError::Disconnected) => break,
                Ok(_) => {}
                Err(TryRecvError::Empty) => assert!(t.elapsed() < Duration::from_secs(10)),
            }
        }
        h.join().unwrap();
        fake.sent_frames()
    }

    /// `stack-ndpv6.c:95-182`, `main.c:829-840`: NS на наш `source_ipv6` во время скана порождает NA 86 байт с
    /// `payload_length` 32 (адаптерный TX, не результат скана); SYN IPv4 идут как прежде.
    #[test]
    fn incoming_ns_during_scan_replies_with_32_byte_na() {
        use rmasscan_core::ndp::{
            decode_neighbor_advertisement, encode_neighbor_advertisement,
            encode_neighbor_solicitation,
        };
        let ns = encode_neighbor_solicitation(NDP_ROUTER_MAC, NDP_ROUTER_IP, NDP_ME);
        let sent = run_with_rx(&ndp_plan(Some(NDP_ME)), vec![ns.to_vec()]);
        let nas: Vec<&Vec<u8>> = sent.iter().filter(|f| f.len() == 86).collect();
        assert_eq!(nas.len(), 1, "{} frames", sent.len());
        let na = nas[0];
        assert_eq!(
            *na,
            encode_neighbor_advertisement(NDP_ME_MAC, NDP_ME, NDP_ROUTER_MAC, NDP_ROUTER_IP)
                .to_vec()
        );
        assert_eq!(&na[18..20], &[0, 32]);
        let p = decode_neighbor_advertisement(na).unwrap();
        assert_eq!((p.target, p.target_lla), (NDP_ME, NDP_ME_MAC));
        // 12 SYN IPv4 остались как были.
        assert_eq!(sent.len(), 13);
        assert_eq!(sent.iter().filter(|f| f.len() == 58).count(), 12);
    }

    /// Ответчик отвечает только на NS своего адреса и только у плана с `source_ipv6`: план IPv4 (в том числе
    /// Студия) не шлёт ни одного лишнего кадра.
    #[test]
    fn ns_for_other_address_or_on_ipv4_plan_sends_nothing() {
        use rmasscan_core::ndp::encode_neighbor_solicitation;
        let other = encode_neighbor_solicitation(NDP_ROUTER_MAC, NDP_ROUTER_IP, NDP_ME + 1);
        let mine = encode_neighbor_solicitation(NDP_ROUTER_MAC, NDP_ROUTER_IP, NDP_ME);
        let sent = run_with_rx(&ndp_plan(Some(NDP_ME)), vec![other.to_vec()]);
        assert_eq!(sent.len(), 12);
        let sent = run_with_rx(&ndp_plan(None), vec![mine.to_vec()]);
        assert_eq!(sent.len(), 12);
    }

    // ---- NDP: ограниченность и остановка (fix round 1) ----

    fn na_frames(n: usize) -> VecDeque<[u8; NDP_FRAME_LEN]> {
        (0..n).map(|i| [i as u8; NDP_FRAME_LEN]).collect()
    }

    /// Один вызов `flush_ndp` берёт снимок очереди и не гонится за RX, который продолжает класть кадры: поздний
    /// кадр ждёт следующего вызова (C ограничивает это окном throttle, main.c:478-486).
    #[test]
    fn flush_ndp_sends_only_the_snapshot_it_took() {
        let clock = ManualClock::new();
        let fake = FakeAdapter::new().with_clock(clock);
        let q = Arc::new(Mutex::new(na_frames(5)));
        let q2 = q.clone();
        fake.set_send_hook(move |_| lock(&q2).push_back([0xee; NDP_FRAME_LEN]));
        let mut io = fake.pair();
        flush_ndp(&q, &|| true, &mut *io.tx, Duration::from_millis(50));
        assert_eq!(fake.sent_count(), 5);
        assert_eq!(
            lock(&q).len(),
            5,
            "frames pushed during the flush stay queued"
        );
    }

    /// Блокирующийся адаптер (каждая отправка 50 мс по часам) и полная очередь (64): после Stop уходит не больше
    /// одного кадра, а не 64 x 50 мс = 3,2 с (контракт Stop <= 1 с, engine.rs: комментарий у `WOULD_BLOCK_BACKOFF`).
    #[test]
    fn flush_ndp_stops_promptly_on_halt_with_a_blocked_adapter() {
        let clock = ManualClock::new();
        let fake = FakeAdapter::new().with_clock(clock.clone());
        fake.script_tx((0..64).map(|_| crate::fake::TxStep::DelayThenSent(50_000)));
        let q = Arc::new(Mutex::new(na_frames(NDP_OUT_CAP)));
        let mut io = fake.pair();
        let f2 = fake.clone();
        let t0 = clock.now_micros();
        // Stop приходит после второго кадра.
        flush_ndp(
            &q,
            &|| f2.sent_count() < 2,
            &mut *io.tx,
            Duration::from_millis(50),
        );
        assert_eq!(fake.sent_count(), 2);
        assert!(
            clock.now_micros() - t0 <= 100_000,
            "{}",
            clock.now_micros() - t0
        );
        assert!(
            lock(&q).is_empty(),
            "the unsent snapshot is dropped, not retried"
        );
    }

    /// Пауза с включённым NDP заканчивается чисто и приводит к `Paused`.
    #[test]
    fn pause_with_ndp_enabled_ends_cleanly() {
        let leg = run_leg(&ndp_plan(Some(NDP_ME)), Some(5));
        assert_eq!(leg.outcome.reason, Reason::Paused);
    }

    /// Прогон с NS, который приходит после `idles` пустых приёмов RX (по 50 мс часов fake) внутри окна ожидания
    /// `wait_secs`. Часы стоят, пока TX ждёт в linger, и идут только от пустых приёмов RX. `pause_after = Some(n)`
    /// подаёт Pause изнутри n-й отправки.
    fn run_late_ns(
        idles: u32,
        wait_secs: u32,
        pause_after: Option<usize>,
    ) -> (Vec<Vec<u8>>, Outcome) {
        use rmasscan_core::ndp::encode_neighbor_solicitation;
        let mut m = MassIp::new();
        add_target_string(m.ipv4_mut(), "198.18.0.0/30").unwrap();
        parse_ports(m.ports_mut(), "80,443,8080").unwrap();
        let cfg = ScanConfig {
            targets: m,
            seed: SEED,
            max_rate: 1_000_000.0,
            wait_secs,
            ..ScanConfig::default()
        };
        let eff = validate(&cfg, Operation::Scan).unwrap();
        let mut nic = ndp_plan(Some(NDP_ME)).nics()[0].clone();
        nic.source_ipv6 = Some(NDP_ME);
        let plan = ReadyPlan::new_cli(eff, vec![nic]).unwrap();
        let clock = ManualClock::new();
        clock.set_hold(true);
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
        fake.push_rx(crate::fake::RxStep::Idle(idles));
        fake.push_frame(
            encode_neighbor_solicitation(NDP_ROUTER_MAC, NDP_ROUTER_IP, NDP_ME).to_vec(),
        );
        let c: Arc<dyn Clock + Send + Sync> = clock.clone();
        let h = Engine::start_cli_with_clock(
            plan,
            vec![fake.pair()],
            EngineOptions::new([1; 16], [2; 16]),
            c,
            None,
        )
        .unwrap();
        cell.set(h.cancel_handle()).ok();
        let t = Instant::now();
        loop {
            match h.recv_event_timeout(Duration::from_millis(50)) {
                Ok(Event::Finished { .. }) | Err(TryRecvError::Disconnected) => break,
                Ok(_) => {}
                Err(TryRecvError::Empty) => assert!(t.elapsed() < Duration::from_secs(60)),
            }
        }
        let outcome = h.join().unwrap();
        (fake.sent_frames(), outcome)
    }

    /// Цель linger: NS, пришедший ПОСЛЕ конца передачи, в окне ожидания, тоже получает NA. 12 SYN уходят до NS
    /// (2000 пустых приёмов = 100 с часов из окна в 1000 с, то есть сотни мс настоящего времени: голодный TX-поток
    /// на загруженном раннере не успеет вклинить NA между SYN), NA идёт последним кадром.
    #[test]
    fn ns_arriving_after_tx_finished_still_gets_its_na() {
        use rmasscan_core::ndp::encode_neighbor_advertisement;
        let (sent, outcome) = run_late_ns(2000, 1000, None);
        assert_eq!(outcome.reason, Reason::Completed);
        assert_eq!(sent.len(), 13);
        assert!(sent[..12].iter().all(|f| f.len() == 58), "SYNs first");
        assert_eq!(
            sent[12],
            encode_neighbor_advertisement(NDP_ME_MAC, NDP_ME, NDP_ROUTER_MAC, NDP_ROUTER_IP)
                .to_vec()
        );
    }

    /// После Pause RX принимает до конца окна ожидания, и NS в этом окне тоже получает NA (в C очередь
    /// сбрасывается до `is_rx_done`, main.c:470-493); linger заканчивается вместе с RX (скан завершается
    /// `Paused`, а не зависает).
    #[test]
    fn ns_arriving_during_a_pause_wait_window_still_gets_its_na() {
        use rmasscan_core::ndp::encode_neighbor_advertisement;
        let (sent, outcome) = run_late_ns(2000, 1000, Some(5));
        assert_eq!(outcome.reason, Reason::Paused);
        assert_eq!(sent.len(), 6, "5 SYN before the pause, then the NA");
        assert!(sent[..5].iter().all(|f| f.len() == 58));
        assert_eq!(
            sent[5],
            encode_neighbor_advertisement(NDP_ME_MAC, NDP_ME, NDP_ROUTER_MAC, NDP_ROUTER_IP)
                .to_vec()
        );
    }
}

#[cfg(test)]
mod byte_budget_tests {
    //! Бюджет очереди в байтах нагрузки баннеров (И7): правило приёма и возврат байт при выдаче и пропуске.

    use super::*;
    use rmasscan_core::receive::PortStatus;
    use std::net::{IpAddr, Ipv4Addr};

    fn reply(n: u32) -> Reply {
        Reply {
            remote_ip: 0x0a00_0000 + n,
            remote_port: 53,
            local_ip: 0x0a00_00fe,
            local_port: 40000,
            status: PortStatus::Open,
            tcp_flags: 0,
            ttl: 64,
            ip_proto: 17,
            mac: None,
            ip6: None,
        }
    }

    fn banner(len: usize) -> BannerRecord {
        BannerRecord {
            timestamp: 0,
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ip_proto: 17,
            port: 53,
            app: 0,
            ttl: 64,
            payload: vec![0x41; len],
        }
    }

    const KIB64: usize = 64 * 1024;

    #[test]
    fn replies_only_queue_unchanged_by_byte_budget() {
        let q = Queue::new(4096, 1, 1000);
        for n in 0..4096 {
            assert!(q.push_result(reply(n), Vec::new()), "reply {n}");
        }
        assert!(!q.push_result(reply(4096), Vec::new()), "4097th");
    }

    #[test]
    fn empty_queue_accepts_any_banner_set() {
        let q = Queue::new(4096, 1, 1000);
        assert!(q.push_result(reply(0), vec![banner(KIB64), banner(KIB64)]));
        assert!(
            !q.push_result(reply(1), vec![banner(1)]),
            "now it is not empty"
        );
    }

    #[test]
    fn byte_budget_frees_on_pop() {
        let q = Queue::new(4096, 100 * 1024, 1000);
        assert!(q.push_result(reply(0), vec![banner(KIB64)]));
        assert!(!q.push_result(reply(1), vec![banner(KIB64)]));
        let mut st = lock(&q.st);
        assert_eq!(st.banner_bytes, KIB64);
        let _ = q.pop_locked(&mut st, Want::Outputs); // Results{reply 0}
        assert_eq!(st.banner_bytes, KIB64, "the banner is still queued");
        assert!(matches!(
            q.pop_locked(&mut st, Want::Outputs),
            Ok(Output::Banner(_))
        ));
        assert_eq!(st.banner_bytes, 0);
        drop(st);
        assert!(q.push_result(reply(1), vec![banner(KIB64)]));
        assert!(
            q.push_result(reply(2), Vec::new()),
            "no banners: bytes do not matter"
        );
    }

    #[test]
    fn events_consumer_skipping_banners_releases_bytes() {
        let q = Queue::new(4096, 100 * 1024, 1000);
        assert!(q.push_result(reply(0), vec![banner(KIB64)]));
        assert!(!q.push_result(reply(1), vec![banner(KIB64)]));
        let mut st = lock(&q.st);
        match q.pop_locked(&mut st, Want::Events) {
            Ok(Output::Event(Event::Results { replies })) => assert_eq!(replies.len(), 1),
            _ => panic!("expected Results"),
        }
        assert!(
            st.results.is_empty(),
            "the banner is skipped with the batch"
        );
        assert_eq!(st.banner_bytes, 0);
        drop(st);
        assert!(q.push_result(reply(1), vec![banner(KIB64)]));
        // close обнуляет счётчик вместе с очередью
        q.close();
        assert!(lock(&q.st).results.is_empty());
        assert_eq!(lock(&q.st).banner_bytes, 0);
    }

    /// Ответ с баннером ровно на последней позиции полной пачки (`event_batch_limit` = 3): пачка режется по лимиту,
    /// баннер остаётся во главе очереди.
    fn batch_cut_queue() -> Queue {
        let q = Queue::new(4096, DEFAULT_RESULT_BYTE_CAPACITY, 3);
        assert!(q.push_result(reply(0), Vec::new()));
        assert!(q.push_result(reply(1), Vec::new()));
        assert!(q.push_result(reply(2), vec![banner(5)]));
        assert!(q.push_result(reply(3), Vec::new()));
        q
    }

    #[test]
    fn batch_cut_at_event_batch_limit_with_banners() {
        let q = batch_cut_queue();
        let mut st = lock(&q.st);
        assert_eq!(st.banner_bytes, 5);
        let mut got = Vec::new();
        while let Ok(o) = q.pop_locked(&mut st, Want::Outputs) {
            got.push(match o {
                Output::Event(Event::Results { replies }) => format!("R{}", replies.len()),
                Output::Banner(_) => "B".to_string(),
                Output::ConnectionBanner(_) => "C".to_string(),
                Output::Event(e) => format!("{e:?}"),
            });
        }
        assert_eq!(got, ["R3", "B", "R1"]);
        assert_eq!(st.banner_bytes, 0);
    }

    #[test]
    fn batch_cut_at_event_batch_limit_events_consumer_releases_bytes() {
        let q = batch_cut_queue();
        let mut st = lock(&q.st);
        assert!(matches!(
            q.pop_locked(&mut st, Want::Events),
            Ok(Output::Event(Event::Results { replies })) if replies.len() == 3
        ));
        assert_eq!(st.banner_bytes, 5, "the banner waits at the head");
        assert!(matches!(
            q.pop_locked(&mut st, Want::Events),
            Ok(Output::Event(Event::Results { replies })) if replies.len() == 1
        ));
        assert_eq!(st.banner_bytes, 0);
    }
}

#[cfg(test)]
mod conn_banner_tests {
    //! Баннеры соединений TCP в очереди результатов (подэтап 4b, задача 4): правило `fits` для набора соединения,
    //! байты бюджета, порядок относительно ответов и их баннеров, ожидание места при сбросе в конце.

    use super::*;
    use rmasscan_core::receive::PortStatus;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    fn reply(n: u32) -> Reply {
        Reply {
            remote_ip: 0x0a00_0000 + n,
            remote_port: 80,
            local_ip: 0x0a00_00fe,
            local_port: 40000,
            status: PortStatus::Open,
            tcp_flags: 0x12,
            ttl: 64,
            ip_proto: 6,
            mac: None,
            ip6: None,
        }
    }

    fn conn(len: usize) -> BannerRecord {
        BannerRecord {
            timestamp: 0,
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ip_proto: 6,
            port: 80,
            app: 4,
            ttl: 64,
            payload: vec![0x42; len],
        }
    }

    fn kinds(q: &Queue, want: Want) -> Vec<String> {
        let mut st = lock(&q.st);
        let mut got = Vec::new();
        while let Ok(o) = q.pop_locked(&mut st, want) {
            got.push(match o {
                Output::Event(Event::Results { replies }) => format!("R{}", replies.len()),
                Output::Banner(b) => format!("B{}", b.payload.len()),
                Output::ConnectionBanner(b) => format!("C{}", b.payload.len()),
                Output::Event(e) => format!("{e:?}"),
            });
        }
        got
    }

    /// Набор соединения встаёт целиком или не встаёт (правило `fits` задачи 0): не вместился по байтам, и очередь та
    /// же; вместился, и все записи стоят подряд, каждая отдельным элементом.
    #[test]
    fn conn_banner_set_is_all_or_nothing() {
        let q = Queue::new(4096, 1000, 1000);
        assert!(q.push_result(reply(0), vec![conn(600)]));
        assert!(!q.push_conn_banners(vec![conn(300), conn(300)]));
        {
            let st = lock(&q.st);
            assert_eq!((st.results.len(), st.banner_bytes), (2, 600));
        }
        assert!(q.push_conn_banners(vec![conn(200), conn(200)]));
        {
            let st = lock(&q.st);
            assert_eq!((st.results.len(), st.banner_bytes), (4, 1000));
        }
        assert_eq!(kinds(&q, Want::Outputs), ["R1", "B600", "C200", "C200"]);
        assert_eq!(lock(&q.st).banner_bytes, 0);
    }

    /// Байты набора соединения идут в бюджет и возвращаются при выдаче и при пропуске потребителем событий; пустая
    /// очередь принимает любой набор; `close` обнуляет счётчик.
    #[test]
    fn conn_banners_count_in_byte_budget() {
        const KIB64: usize = 64 * 1024;
        let q = Queue::new(4096, 100 * 1024, 1000);
        assert!(q.push_conn_banners(vec![conn(KIB64)]));
        assert_eq!(lock(&q.st).banner_bytes, KIB64);
        assert!(!q.push_conn_banners(vec![conn(KIB64)]));
        assert_eq!(kinds(&q, Want::Outputs), [format!("C{KIB64}")]);
        assert_eq!(lock(&q.st).banner_bytes, 0);
        assert!(q.push_conn_banners(vec![conn(KIB64)]));
        assert!(q.push_result(reply(1), Vec::new()));
        assert_eq!(kinds(&q, Want::Events), ["R1"]);
        assert_eq!(
            lock(&q.st).banner_bytes,
            0,
            "skipped by the events consumer"
        );
        let tiny = Queue::new(4096, 1, 1000);
        assert!(tiny.push_conn_banners(vec![conn(KIB64), conn(KIB64)]));
        tiny.close();
        assert_eq!(lock(&tiny.st).banner_bytes, 0);
        assert!(
            tiny.push_conn_banners(vec![conn(1)]),
            "closed: nobody reads"
        );
        assert!(lock(&tiny.st).results.is_empty());
        assert!(q.push_conn_banners(Vec::new()), "an empty set is a no-op");
    }

    /// Набор соединения не встаёт между ответом и его баннерами (одна блокировка на ответ с баннерами), обрывает
    /// пачку ответов для [`Want::Outputs`] и пропускается для [`Want::Events`].
    #[test]
    fn conn_banners_keep_reply_banner_adjacency() {
        let fill = |q: &Queue| {
            assert!(q.push_result(reply(0), vec![conn(5)]));
            assert!(q.push_conn_banners(vec![conn(7)]));
            assert!(q.push_result(reply(1), Vec::new()));
            assert!(q.push_result(reply(2), vec![conn(5)]));
        };
        let q = Queue::new(4096, DEFAULT_RESULT_BYTE_CAPACITY, 1000);
        fill(&q);
        assert_eq!(kinds(&q, Want::Outputs), ["R1", "B5", "C7", "R2", "B5"]);
        fill(&q);
        assert_eq!(kinds(&q, Want::Events), ["R3"]);
        assert_eq!(lock(&q.st).banner_bytes, 0);
    }

    fn full_queue() -> Arc<Queue> {
        let q = Arc::new(Queue::new(2, DEFAULT_RESULT_BYTE_CAPACITY, 1000));
        assert!(q.push_result(reply(0), Vec::new()));
        assert!(q.push_result(reply(1), Vec::new()));
        assert!(!q.push_conn_banners(vec![conn(1)]), "the queue is full");
        q
    }

    fn wait_until(what: &str, cond: impl Fn() -> bool) {
        let t = Instant::now();
        while !cond() {
            assert!(t.elapsed() < Duration::from_secs(10), "timeout: {what}");
            std::thread::yield_now();
        }
    }

    /// Ожидающий набор встаёт, как только потребитель освобождает место (`room`), и не раньше.
    #[test]
    fn waiting_push_waits_for_room() {
        let q = full_queue();
        let q2 = q.clone();
        let t = std::thread::spawn(move || q2.push_conn_banners_waiting(vec![conn(3)], &|| true));
        wait_until("the producer waits", || lock(&q.st).room_waiters > 0);
        assert_eq!(lock(&q.st).results.len(), 2, "nothing pushed while full");
        assert_eq!(kinds(&q, Want::Outputs), ["R2"]);
        assert!(t.join().unwrap());
        assert_eq!(kinds(&q, Want::Outputs), ["C3"]);
    }

    /// `keep_going` (`!Stop`) прерывает ожидание не позже чем через один шаг ожидания: набор не встаёт, `false`.
    #[test]
    fn waiting_push_returns_false_when_told_to_stop() {
        let q = full_queue();
        let go = Arc::new(AtomicBool::new(true));
        let (q2, g2) = (q.clone(), go.clone());
        let t = std::thread::spawn(move || {
            q2.push_conn_banners_waiting(vec![conn(3)], &|| g2.load(Ordering::SeqCst))
        });
        wait_until("the producer waits", || lock(&q.st).room_waiters > 0);
        let stopped = Instant::now();
        go.store(false, Ordering::SeqCst);
        assert!(!t.join().unwrap());
        assert!(stopped.elapsed() < Duration::from_secs(5));
        assert_eq!(lock(&q.st).results.len(), 2);
        assert_eq!(lock(&q.st).room_waiters, 0);
    }

    /// Потребителя больше нет (`close`) или он ждёт потоки в `join`: ожидающий набор отбрасывается, `true`.
    #[test]
    fn waiting_push_gives_up_on_close_and_join() {
        for close in [true, false] {
            let q = full_queue();
            let q2 = q.clone();
            let t =
                std::thread::spawn(move || q2.push_conn_banners_waiting(vec![conn(3)], &|| true));
            wait_until("the producer waits", || lock(&q.st).room_waiters > 0);
            if close {
                q.close();
            } else {
                q.begin_join();
            }
            assert!(t.join().unwrap(), "close {close}");
            assert!(
                !lock(&q.st)
                    .results
                    .iter()
                    .any(|e| matches!(e, Entry::ConnBanner(_))),
                "close {close}"
            );
        }
    }

    /// Ожидающий набор встаёт и в пустую очередь, если он больше всего бюджета.
    #[test]
    fn waiting_push_of_a_set_larger_than_the_budget_lands_in_an_empty_queue() {
        let q = Arc::new(Queue::new(4096, 10, 1000));
        assert!(q.push_conn_banners(vec![conn(8)]));
        let q2 = q.clone();
        let t = std::thread::spawn(move || {
            q2.push_conn_banners_waiting(vec![conn(50), conn(50)], &|| true)
        });
        wait_until("the producer waits", || lock(&q.st).room_waiters > 0);
        assert_eq!(kinds(&q, Want::Outputs), ["C8"]);
        assert!(t.join().unwrap());
        assert_eq!(kinds(&q, Want::Outputs), ["C50", "C50"]);
    }
}
