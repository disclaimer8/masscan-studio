//! Linux AF_PACKET: отдельные TX/RX сокеты, неблокирующий ввод-вывод и poll
//! до АБСОЛЮТНОГО дедлайна (не более 50 мс). Логика здесь безопасная и
//! общая для всех реализаций [`PacketIo`]; настоящие syscalls лежат в
//! private-модуле `socket`, а тесты подставляют синтетический `PacketIo`.
//! Таблица маршрутов (rtnetlink) и интерфейсы (`if_nameindex` + ioctl) для
//! обнаружения: модуль `route`.
//!
//! Только Linux: `socket`, `route` и `open`. Остальное не зависит от `libc` (номера Linux в `abi`) и собирается в
//! тестах на любой ОС, поэтому тесты адаптера идут и на Mac, и на Windows.
//!
//! Приём идёт пачками: один `recvmmsg` забирает до [`RX_BATCH`] кадров во внутреннее кольцо `RxHalf`, а `recv`
//! выдаёт их по одному, с теми же фильтрами, счётчиками и проверкой дедлайна, что у покадрового пути.
//!
//! Передача (P1) тоже идёт пачками: `send_batch` отдаёт до [`TX_BATCH_FRAMES`] кадров одним `sendmmsg` и даёт каждому
//! кадру ровно исход одиночного `send` (тексты, счётчики, повторы EAGAIN/EINTR/`ENOBUFS`), с одним дедлайном на весь
//! вызов. TX-сокет обходит qdisc интерфейса (`PACKET_QDISC_BYPASS`, P3).

use std::sync::Arc;
use std::time::{Duration, Instant};

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;
#[cfg(target_os = "linux")]
use rmasscan_engine::AdapterPair;
use rmasscan_engine::{IoError, MAX_IO_TIMEOUT, Rx, RxHealth, SendStatus, Tx, TxBatch};

#[cfg(target_os = "linux")]
use crate::OpenedAdapter;
use crate::adapter_common::{
    Errno, Readiness, closed_error, errno_msg, map_setup_errno, valid_ifname,
};
use crate::{Counters, NetError, NetStatsHandle};

// Номера Linux без `libc`: errno, `ARPHRD_ETHER`, `PACKET_OUTGOING`.
mod abi;
use abi::errno::{EAGAIN, EBADF, EINTR, EINVAL, EIO, ENOBUFS, ENODEV, EWOULDBLOCK};
use abi::{ARPHRD_ETHER, PACKET_OUTGOING};

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod socket;

// Обнаружение в процессе: rtnetlink (маршруты) и ioctl интерфейсов; `unsafe` только вокруг вызовов libc.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub(crate) mod route;

/// Метаданные принятого кадра. `len` это ИСТИННАЯ длина (MSG_TRUNC), она
/// может превышать буфер.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecvMeta {
    pub len: usize,
    pub pkttype: u8,
    pub ifindex: i32,
}

/// PACKET_STATISTICS: читаются только потери (`tp_drops`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelStats {
    pub drops: u32,
}

/// Сообщений в одной пачке приёма (`recvmmsg`) и слотов во внутреннем кольце `RxHalf`.
pub(crate) const RX_BATCH: usize = 32;
/// Байт в слоте кольца. Кадр длиннее слота ядро усекает до `RX_SLOT`, а его [`RecvMeta::len`] остаётся истинной
/// длиной (MSG_TRUNC).
pub(crate) const RX_SLOT: usize = 2048;

/// Метаданные одного сообщения пачки. `Err(EPROTO)`: ядро отдало адрес короче `SLL_MIN_LEN` (без `sll_pkttype` свой
/// исходящий кадр не отличить), как прямой `recv`.
pub(crate) type SlotMeta = Result<RecvMeta, Errno>;

/// Сколько сообщений просить у ядра в одной пачке: `min(slots, metas, RX_BATCH)`, то есть не больше, чем есть слотов и
/// мест для метаданных. Ноль — `Err(EINVAL)` до любого системного вызова.
pub(crate) fn batch_len(slots: usize, metas: usize) -> Result<usize, Errno> {
    match slots.min(metas).min(RX_BATCH) {
        0 => Err(EINVAL),
        n => Ok(n),
    }
}

/// Кадров в одной пачке передачи: `max_batch()` TX Linux и длина массивов одного `sendmmsg`.
pub(crate) const TX_BATCH_FRAMES: usize = 64;

/// Сколько сообщений отдать ядру одним `sendmmsg`: `min(frames, lens, TX_BATCH_FRAMES)`, то есть не больше, чем есть
/// кадров и мест для длин. Ноль — `Err(EINVAL)` до любого системного вызова.
fn send_count(frames: usize, lens: usize) -> Result<usize, Errno> {
    match frames.min(lens).min(TX_BATCH_FRAMES) {
        0 => Err(EINVAL),
        n => Ok(n),
    }
}

/// Шов syscalls одного сокета. Все методы НЕБЛОКИРУЮЩИЕ.
pub(crate) trait PacketIo: Send {
    fn send(&mut self, frame: &[u8]) -> Result<usize, Errno>;
    /// Пачка: первые [`send_count`] кадров `frames` одним `sendmmsg`. `Ok(k)` — ядро приняло сообщения `0..k`,
    /// `lens[j]` — байты сообщения j; ошибка первого сообщения — `Err`. Ошибку после принятого префикса ядро теряет
    /// (возвращает `k`), повтор с кадра `k` возвращает её. Ноль сообщений — `Err(EINVAL)` без системного вызова.
    fn send_many(&mut self, frames: &[&[u8]], lens: &mut [usize]) -> Result<usize, Errno>;
    /// Один кадр в буфер вызывающего (прямой путь `RxHalf`: буфер длиннее [`RX_SLOT`]). Адрес короче
    /// `SLL_MIN_LEN` — `Err(EPROTO)`.
    fn recv(&mut self, buf: &mut [u8]) -> Result<RecvMeta, Errno>;
    /// Пачка: до [`batch_len`] сообщений, сообщение `i` в `slots[i]` (не больше [`RX_SLOT`] байт), его метаданные в
    /// `metas[i]`. `Ok(n)` с n ≥ 1, пусто — `Err(EAGAIN)`. Ошибка не-EAGAIN после принятого префикса: ядро отдаёт
    /// префикс, а ошибку — следующим вызовом; исход тот же, что у покадрового пути, на вызов позже.
    fn recv_batch(
        &mut self,
        slots: &mut [[u8; RX_SLOT]],
        metas: &mut [SlotMeta],
    ) -> Result<usize, Errno>;
    fn poll(&mut self, write: bool, timeout_ms: i32) -> Result<Readiness, Errno>;
    /// PACKET_STATISTICS: ядро сбрасывает счётчики при чтении.
    fn packet_stats(&mut self) -> Result<KernelStats, Errno>;
    /// Пауза между повторами после EINTR или `ENOBUFS` передачи. `wait` уже ограничена остатком
    /// дедлайна и [`EINTR_BACKOFF_MAX`]. Реализация обязана реально ждать
    /// (иначе цикл крутится); тесты считают вызовы и сумму `wait`.
    fn backoff(&mut self, wait: Duration);
}

/// Шов запросов к ОС об интерфейсе.
pub(crate) trait IfaceInfo {
    /// `Ok(None)`: такого интерфейса нет.
    fn ifindex(&self, name: &str) -> Result<Option<u32>, Errno>;
    /// `sa_family` адреса канального уровня (`SIOCGIFHWADDR`): тип ARPHRD.
    fn link_family(&self, name: &str) -> Result<u16, Errno>;
}

/// Максимальная пауза между повторами после EINTR и `ENOBUFS` передачи (против busy-spin).
pub(crate) const EINTR_BACKOFF_MAX: Duration = Duration::from_millis(1);
/// Раз в столько принятых кадров забираем статистику ядра.
const STATS_EVERY: u64 = 4096;

fn is_again(e: Errno) -> bool {
    e == EAGAIN || e == EWOULDBLOCK
}

/// Абсолютный дедлайн. Фиксируется один раз на вызов; повторы после EINTR и
/// ложных пробуждений его не продлевают.
struct Deadline(Instant);

impl Deadline {
    fn new(timeout: Duration) -> Self {
        Deadline(Instant::now() + timeout.min(MAX_IO_TIMEOUT))
    }
    fn expired(&self) -> bool {
        Instant::now() >= self.0
    }
    /// Пауза перед повтором после EINTR: не более [`EINTR_BACKOFF_MAX`] и не
    /// более остатка; исходный дедлайн не продлевается.
    fn eintr_wait(&self) -> Duration {
        self.0
            .saturating_duration_since(Instant::now())
            .min(EINTR_BACKOFF_MAX)
    }
    /// Остаток в мс для poll, округление ВВЕРХ (иначе poll(0) крутится).
    fn poll_ms(&self) -> i32 {
        let left = self.0.saturating_duration_since(Instant::now());
        let ms = left.as_micros().div_ceil(1000);
        i32::try_from(ms.min(MAX_IO_TIMEOUT.as_millis())).unwrap_or(i32::MAX)
    }
}

/// TX-половина. После фатальной ошибки fd закрывается (`io = None`).
///
/// Пачка (`send_batch`, P1): до [`TX_BATCH_FRAMES`] кадров одним `sendmmsg`, с одним дедлайном на весь вызов; каждый
/// кадр получает ровно исход одиночного `send` на том же кадре (тексты, счётчики, повторы EAGAIN/EINTR/`ENOBUFS`).
/// Фатальная ошибка после принятого префикса закрывает fd, префикс засчитывается (`TxBatch { sent: i, rest:
/// WouldBlockUnsent }`), а её текст ждёт в `deferred`: следующий вызов (`send` или `send_batch`) сразу возвращает его
/// как `Err`, без системного вызова и без нового счёта, как вернул бы одиночный путь на этом кадре; после него —
/// «adapter closed…».
///
/// `ENOBUFS` (P3): кадр не принят и не ушёл; пауза до [`EINTR_BACKOFF_MAX`] и повтор до дедлайна вызова, затем
/// `WouldBlockUnsent`, fd открыт. TX-сокет обходит qdisc (`PACKET_QDISC_BYPASS`), поэтому отбросов qdisc нет, и
/// `ENOBUFS` приходит от драйвера: занята его очередь передачи (у veth — переполнена очередь приёма пира) или ядру не
/// хватило памяти на кадр. Если обход не включился, `ENOBUFS` отбросившей кадр qdisc обрабатывается так же.
///
/// Известное ограничение (исправление — фаза 2, движок): если Pause или Stop приходит в ту 1 мс, что движок спит после
/// `WouldBlockUnsent`, следующим вызовом оказывается `send` из linger или стека (`flush_replies`, `send_stack_frames`),
/// а движок игнорирует его `Err`: запуск кончается `Paused`/`Stopped` вместо `Failed(TxError)`, текст теряется.
/// Checkpoint при этом верен: принят ровно префикс.
pub(crate) struct TxHalf<I: PacketIo> {
    io: Option<I>,
    counters: Arc<Counters>,
    /// Текст фатальной ошибки, случившейся в пачке после принятого префикса: отдаётся следующим вызовом.
    deferred: Option<String>,
}

enum TxStep {
    Done(SendStatus),
    Fatal(String),
}

/// Что делать после ошибки отправки кадра: повторить его, сдаться без отправки (`WouldBlockUnsent`) или фатальная
/// ошибка со своим текстом.
enum Retry {
    Again,
    Unsent,
    Fatal(String),
}

impl<I: PacketIo> TxHalf<I> {
    pub(crate) fn new(io: I, counters: Arc<Counters>) -> Self {
        Self {
            io: Some(io),
            counters,
            deferred: None,
        }
    }

    /// Ошибка `send`/`sendmmsg` на кадре, одна для одиночного пути и пачки. EAGAIN/EINTR/`ENOBUFS`: ядро не приняло
    /// кадр; EAGAIN ждёт `poll(POLLOUT)` до дедлайна вызова, EINTR и `ENOBUFS` — паузу не больше [`EINTR_BACKOFF_MAX`].
    /// По истечении дедлайна — `WouldBlockUnsent`.
    fn on_send_error(io: &mut I, e: Errno, deadline: &Deadline) -> Retry {
        if is_again(e) {
            if deadline.expired() {
                return Retry::Unsent;
            }
            return match io.poll(true, deadline.poll_ms()) {
                Ok(Readiness::Ready) => Retry::Again,
                Ok(Readiness::Timeout) => Retry::Unsent,
                Ok(Readiness::Failed) => Retry::Fatal("poll(POLLOUT): socket error".into()),
                Err(EINTR) => {
                    io.backoff(deadline.eintr_wait());
                    Retry::Again
                }
                Err(e) => Retry::Fatal(errno_msg("poll(POLLOUT)", e)),
            };
        }
        // EINTR — POSIX: send(), прерванный до передачи первого байта, ничего не отправил. ENOBUFS (P3) — qdisc
        // интерфейса или драйвер отбросили кадр (или ядру не хватило памяти на него): кадр не ушёл. В обоих случаях
        // WouldBlockUnsent (не Uncertain) безопасен. ENOBUFS ждёт паузу, а не `poll(POLLOUT)`: тот сообщает о месте в
        // буфере сокета, а не в очереди qdisc, и вернулся бы сразу.
        if e == EINTR || e == ENOBUFS {
            if deadline.expired() {
                return Retry::Unsent;
            }
            io.backoff(deadline.eintr_wait());
            return Retry::Again;
        }
        Retry::Fatal(errno_msg("send", e))
    }

    fn step(io: &mut I, frame: &[u8], deadline: &Deadline) -> TxStep {
        loop {
            let e = match io.send(frame) {
                Ok(n) if n == frame.len() => return TxStep::Done(SendStatus::Sent),
                // Короткая запись: часть могла уйти.
                Ok(_) => return TxStep::Done(SendStatus::Uncertain),
                Err(e) => e,
            };
            match Self::on_send_error(io, e, deadline) {
                Retry::Again => {}
                Retry::Unsent => return TxStep::Done(SendStatus::WouldBlockUnsent),
                Retry::Fatal(msg) => return TxStep::Fatal(msg),
            }
        }
    }

    /// Пачка из `frames` (2..=[`TX_BATCH_FRAMES`]) под одним дедлайном: число принятых кадров и исход первого
    /// непринятого (`Done(Sent)` — приняты все). Каждый вызов `send_many` начинается с первого непринятого кадра.
    fn step_batch(io: &mut I, frames: &[&[u8]], deadline: &Deadline) -> (usize, TxStep) {
        let mut lens = [0usize; TX_BATCH_FRAMES];
        let mut i = 0;
        loop {
            let rest = frames.get(i..).unwrap_or_default();
            let e = match io.send_many(rest, &mut lens) {
                // Ядро при vlen ≥ 1 не возвращает 0; ноль без errno — фатальная EIO, а не повтор без конца.
                Ok(0) => return (i, TxStep::Fatal(errno_msg("send", EIO))),
                Ok(k) => {
                    let k = k.min(rest.len());
                    // Короткое сообщение — как короткая запись одиночного пути: Uncertain на этом кадре.
                    if let Some(j) = rest
                        .iter()
                        .zip(&lens)
                        .take(k)
                        .position(|(frame, &len)| len != frame.len())
                    {
                        return (i + j, TxStep::Done(SendStatus::Uncertain));
                    }
                    i += k;
                    if i >= frames.len() {
                        return (frames.len(), TxStep::Done(SendStatus::Sent));
                    }
                    // Ошибку после принятого префикса ядро теряет: повтор с кадра i вернёт настоящую.
                    continue;
                }
                Err(e) => e,
            };
            match Self::on_send_error(io, e, deadline) {
                Retry::Again => {}
                Retry::Unsent => return (i, TxStep::Done(SendStatus::WouldBlockUnsent)),
                Retry::Fatal(msg) => return (i, TxStep::Fatal(msg)),
            }
        }
    }
}

impl<I: PacketIo> Tx for TxHalf<I> {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError> {
        if let Some(msg) = self.deferred.take() {
            return Err(IoError::new(msg));
        }
        let deadline = Deadline::new(timeout);
        let Some(io) = self.io.as_mut() else {
            return Err(closed_error());
        };
        match Self::step(io, frame, &deadline) {
            TxStep::Done(status) => {
                let c = match status {
                    SendStatus::Sent => &self.counters.tx_sent,
                    SendStatus::WouldBlockUnsent => &self.counters.tx_would_block,
                    SendStatus::Uncertain => &self.counters.tx_uncertain,
                };
                Counters::bump(c);
                Ok(status)
            }
            TxStep::Fatal(msg) => {
                Counters::bump(&self.counters.tx_errors);
                self.io = None; // закрывает fd
                Err(IoError::new(msg))
            }
        }
    }

    fn max_batch(&self) -> usize {
        TX_BATCH_FRAMES
    }

    fn send_batch(&mut self, frames: &[&[u8]], timeout: Duration) -> Result<TxBatch, IoError> {
        use std::sync::atomic::Ordering::Relaxed;
        if let Some(msg) = self.deferred.take() {
            return Err(IoError::new(msg));
        }
        // Тексты Windows (`windows::adapter`): движок таких пачек не предлагает.
        if frames.is_empty() {
            return Err(IoError::new(
                "send_batch called with no frames; nothing was sent",
            ));
        }
        if frames.len() > TX_BATCH_FRAMES {
            return Err(IoError::new(format!(
                "send_batch called with {} frames, more than {TX_BATCH_FRAMES}; nothing was sent",
                frames.len()
            )));
        }
        if let [one] = frames {
            // Один кадр: прежний одиночный путь, без пачки и без её счёта.
            let rest = self.send(one, timeout)?;
            return Ok(TxBatch {
                sent: usize::from(rest == SendStatus::Sent),
                rest,
            });
        }
        // Один дедлайн на весь вызов: контракт движка для `max_batch() > 1`.
        let deadline = Deadline::new(timeout);
        let Some(io) = self.io.as_mut() else {
            return Err(closed_error());
        };
        let (sent, step) = Self::step_batch(io, frames, &deadline);
        let c = &self.counters;
        // Вызов дошёл до ядра: `step_batch` всегда выполняет хотя бы один `sendmmsg`.
        Counters::bump(&c.tx_batches);
        c.tx_batch_max
            .fetch_max(u64::try_from(frames.len()).unwrap_or(u64::MAX), Relaxed);
        c.tx_sent
            .fetch_add(u64::try_from(sent).unwrap_or(u64::MAX), Relaxed);
        match step {
            TxStep::Done(rest) => {
                match rest {
                    SendStatus::Sent => {}
                    SendStatus::WouldBlockUnsent => Counters::bump(&c.tx_would_block),
                    SendStatus::Uncertain => Counters::bump(&c.tx_uncertain),
                }
                Ok(TxBatch { sent, rest })
            }
            TxStep::Fatal(msg) => {
                Counters::bump(&c.tx_errors);
                self.io = None; // закрывает fd
                if sent == 0 {
                    return Err(IoError::new(msg));
                }
                // Префикс принят: движок засчитает ровно его и предложит кадр `sent` снова, а следующий вызов
                // получит эту ошибку (`TxError`), как одиночный путь на этом кадре.
                self.deferred = Some(msg);
                Ok(TxBatch {
                    sent,
                    rest: SendStatus::WouldBlockUnsent,
                })
            }
        }
    }
}

/// RX-половина. Внутреннее кольцо из [`RX_BATCH`] слотов по [`RX_SLOT`] байт: пачку `recv_batch` `recv` выдаёт по
/// одной записи, и пока в кольце есть записи, никакого нового приёма нет; прямой путь (буфер вызывающего длиннее
/// слота) идёт только при пустом кольце. Кадры в кольце при закрытии теряются (раньше они так же лежали в очереди
/// сокета и уходили вместе с fd). Кадр длиннее [`RX_SLOT`], ждущий в кольце, когда вызывающий тем временем увеличил
/// буфер, считается `rx_truncated` (база выдала бы его целиком): ядро уже усекло его до слота; так не делает ни один
/// вызывающий в workspace (у каждого приёмника буфер одного размера).
pub(crate) struct RxHalf<I: PacketIo> {
    io: Option<I>,
    ifindex: i32,
    counters: Arc<Counters>,
    since_stats: u64,
    ring: RxRing,
}

enum RxStep {
    Frame(usize),
    Idle,
    Fatal(String),
}

/// Принятая пачка, ещё не выданная вызывающему: записи `head..len` в порядке ядра.
struct RxRing {
    slots: Box<[[u8; RX_SLOT]]>,
    metas: [SlotMeta; RX_BATCH],
    head: usize,
    len: usize,
}

impl RxRing {
    fn new() -> Self {
        Self {
            slots: vec![[0; RX_SLOT]; RX_BATCH].into_boxed_slice(),
            metas: [Err(EAGAIN); RX_BATCH],
            head: 0,
            len: 0,
        }
    }

    /// Следующая невыданная запись: слот и метаданные.
    fn pop(&mut self) -> Option<(&[u8; RX_SLOT], SlotMeta)> {
        if self.head >= self.len {
            return None;
        }
        let i = self.head;
        self.head += 1;
        Some((self.slots.get(i)?, *self.metas.get(i)?))
    }

    /// Новая пачка в пустое кольцо.
    fn fill<I: PacketIo>(&mut self, io: &mut I) -> Result<(), Errno> {
        let n = io.recv_batch(&mut self.slots, &mut self.metas)?;
        self.head = 0;
        self.len = n.min(RX_BATCH);
        Ok(())
    }

    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }
}

impl<I: PacketIo> RxHalf<I> {
    pub(crate) fn new(io: I, ifindex: u32, counters: Arc<Counters>) -> Self {
        Self {
            io: Some(io),
            ifindex: ifindex.cast_signed(),
            counters,
            since_stats: 0,
            ring: RxRing::new(),
        }
    }

    /// ЕДИНСТВЕННОЕ место, читающее PACKET_STATISTICS. Чтение сбрасывает
    /// счётчик ядра, поэтому дельта сразу прибавляется к накопленному итогу
    /// (`Counters::kernel_drops`) и больше нигде не учитывается: периодический
    /// сброс в `recv`, `health` и `Drop` лишь разные вызывающие одной функции.
    /// Неудачное чтение ядро не сбрасывает, значит при ошибке ничего не теряется.
    /// Возвращает накопленный итог.
    fn collect_kernel_stats(&mut self) -> Result<u64, Errno> {
        use std::sync::atomic::Ordering::{Relaxed, Release};
        self.since_stats = 0;
        let Some(io) = self.io.as_mut() else {
            return Err(EBADF);
        };
        let s = io.packet_stats()?;
        let delta = u64::from(s.drops);
        let total = self.counters.kernel_drops.fetch_add(delta, Relaxed) + delta;
        self.counters.kernel_drops_known.store(true, Release);
        Ok(total)
    }

    /// Фоновая сборка для актуальности снимка. Ошибку не скрывает навсегда:
    /// достоверность проверяет `health`, который делает свежее чтение и
    /// возвращает ошибку вызывающему.
    fn flush_kernel_stats(&mut self) {
        let _ = self.collect_kernel_stats();
    }

    /// Фильтры одной записи в прежнем порядке: свой исходящий кадр, чужой ifindex, кадр длиннее буфера вызывающего
    /// (`cap`), каждый в свой счётчик. `true` — кадр проходит, `rx_packets` считает вызывающий.
    fn admit(meta: &RecvMeta, ifindex: i32, cap: usize, counters: &Counters) -> bool {
        let dropped = if meta.pkttype == PACKET_OUTGOING {
            &counters.rx_outgoing
        } else if meta.ifindex != ifindex {
            &counters.rx_wrong_interface
        } else if meta.len > cap {
            &counters.rx_truncated
        } else {
            return true;
        };
        Counters::bump(dropped);
        false
    }

    fn step(
        io: &mut I,
        ring: &mut RxRing,
        ifindex: i32,
        counters: &Counters,
        buffer: &mut [u8],
        deadline: &Deadline,
    ) -> RxStep {
        loop {
            // Записи кольца раньше любого нового приёма, по одной, в порядке ядра.
            if let Some((slot, meta)) = ring.pop() {
                let meta = match meta {
                    Ok(meta) => meta,
                    // Тот же текст, что у покадрового `recvfrom`, на той же записи.
                    Err(e) => return RxStep::Fatal(errno_msg("recvfrom", e)),
                };
                if Self::admit(&meta, ifindex, buffer.len(), counters) {
                    // `len <= buffer.len()` проверил фильтр; слот держит не больше RX_SLOT байт кадра.
                    match (slot.get(..meta.len), buffer.get_mut(..meta.len)) {
                        (Some(frame), Some(dst)) => {
                            dst.copy_from_slice(frame);
                            Counters::bump(&counters.rx_packets);
                            return RxStep::Frame(meta.len);
                        }
                        // Кадр длиннее слота при буфере длиннее слота (буфер вырос, пока кадр ждал в кольце): ядро
                        // усекло его до RX_SLOT, целиком его не выдать.
                        _ => Counters::bump(&counters.rx_truncated),
                    }
                }
                // Отброшенный кадр не продлевает вызов.
                if deadline.expired() {
                    return RxStep::Idle;
                }
                continue;
            }
            // Кольцо пусто: буфер длиннее слота читает кадр прямо (длинные кадры как прежде), иначе пачка в кольцо.
            let got = if buffer.len() > RX_SLOT {
                io.recv(buffer).map(Some)
            } else {
                ring.fill(io).map(|()| None)
            };
            match got {
                Ok(Some(meta)) => {
                    if Self::admit(&meta, ifindex, buffer.len(), counters) {
                        Counters::bump(&counters.rx_packets);
                        return RxStep::Frame(meta.len);
                    }
                    // Отброшенный кадр не продлевает вызов.
                    if deadline.expired() {
                        return RxStep::Idle;
                    }
                }
                // Пачка в кольце: её записи разбирает начало цикла.
                Ok(None) => {}
                Err(e) if is_again(e) => {
                    if deadline.expired() {
                        return RxStep::Idle;
                    }
                    match io.poll(false, deadline.poll_ms()) {
                        // Готовность без пакета: возвращаемся к приёму.
                        Ok(Readiness::Ready) => {}
                        Err(EINTR) => io.backoff(deadline.eintr_wait()),
                        Ok(Readiness::Timeout) => return RxStep::Idle,
                        Ok(Readiness::Failed) => {
                            return RxStep::Fatal("poll(POLLIN): socket error".into());
                        }
                        Err(e) => return RxStep::Fatal(errno_msg("poll(POLLIN)", e)),
                    }
                }
                Err(EINTR) => {
                    if deadline.expired() {
                        return RxStep::Idle;
                    }
                    io.backoff(deadline.eintr_wait());
                }
                // Текст `recvfrom` прежний (тексты не меняются), хотя вызов теперь `recvmmsg`.
                Err(e) => return RxStep::Fatal(errno_msg("recvfrom", e)),
            }
        }
    }
}

impl<I: PacketIo> Rx for RxHalf<I> {
    fn recv(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<Option<usize>, IoError> {
        let deadline = Deadline::new(timeout);
        let Some(io) = self.io.as_mut() else {
            return Err(closed_error());
        };
        match Self::step(
            io,
            &mut self.ring,
            self.ifindex,
            &self.counters,
            buffer,
            &deadline,
        ) {
            RxStep::Frame(n) => {
                self.since_stats += 1;
                if self.since_stats >= STATS_EVERY {
                    self.flush_kernel_stats();
                }
                Ok(Some(n))
            }
            RxStep::Idle => {
                self.flush_kernel_stats();
                Ok(None)
            }
            RxStep::Fatal(msg) => {
                Counters::bump(&self.counters.rx_errors);
                self.flush_kernel_stats();
                self.io = None;
                self.ring.clear();
                Err(IoError::new(msg))
            }
        }
    }

    fn health(&mut self, _timeout: Duration) -> Result<RxHealth, IoError> {
        if self.io.is_none() {
            return Err(closed_error());
        }
        // Свежее чтение: ошибка отдаётся вызывающему, кэшированный итог не
        // подменяет её.
        match self.collect_kernel_stats() {
            Ok(total) => Ok(RxHealth {
                kernel_drops: Some(total),
            }),
            Err(e) => Err(IoError::new(errno_msg("getsockopt(PACKET_STATISTICS)", e))),
        }
    }
}

impl<I: PacketIo> Drop for RxHalf<I> {
    fn drop(&mut self) {
        self.flush_kernel_stats();
    }
}

/// Проверяет binding через ОС и возвращает ifindex. Не создаёт AF_PACKET
/// сокетов и не требует привилегий.
pub(crate) fn verify_binding(q: &dyn IfaceInfo, binding: &AdapterBinding) -> Result<u32, NetError> {
    if binding.link_type != LinkType::Ethernet {
        return Err(NetError::UnsupportedLink(format!(
            "{:?} (Linux AF_PACKET supports Ethernet only)",
            binding.link_type
        )));
    }
    let name = binding.interface_id.as_str();
    if !valid_ifname(name) {
        return Err(NetError::InterfaceMismatch(format!(
            "invalid interface name {name:?}"
        )));
    }
    let sys = |op: &str, e: Errno| NetError::System(errno_msg(op, e));
    let ifindex = q
        .ifindex(name)
        .map_err(|e| sys("if_nametoindex", e))?
        .ok_or_else(|| NetError::InterfaceMismatch(format!("no such interface {name:?}")))?;
    let family = match q.link_family(name) {
        Ok(f) => f,
        Err(ENODEV) => {
            return Err(NetError::InterfaceMismatch(format!(
                "interface {name:?} disappeared"
            )));
        }
        Err(e) => return Err(sys("SIOCGIFHWADDR", e)),
    };
    if family != ARPHRD_ETHER {
        return Err(NetError::UnsupportedLink(format!(
            "interface {name:?} has ARPHRD type {family}, not Ethernet"
        )));
    }
    // source_ipv4 и source_mac это явные значения источника сканирования
    // (как --adapter-ip/--adapter-mac): используются в кадрах как есть и с ОС
    // не сверяются. InterfaceMismatch охраняет только разрешение имени.
    Ok(ifindex)
}

fn map_open_error(op: &str, e: Errno) -> NetError {
    map_setup_errno(op, e)
}

#[cfg(target_os = "linux")]
pub(crate) fn open(binding: &AdapterBinding) -> Result<OpenedAdapter, NetError> {
    let ifindex = verify_binding(&socket::OsIface, binding)?;
    // TX не принимает ничего (protocol 0), RX слушает ETH_P_ALL только после
    // bind на ifindex, поэтому кадры других интерфейсов не попадают в очередь.
    let tx = socket::PacketFd::open(ifindex, 0).map_err(|e| map_open_error("tx socket", e))?;
    let rx = socket::PacketFd::open(ifindex, socket::ETH_P_ALL_BE)
        .map_err(|e| map_open_error("rx socket", e))?;
    let counters = Arc::new(Counters::default());
    Ok(OpenedAdapter {
        io: AdapterPair {
            tx: Box::new(TxHalf::new(tx, Arc::clone(&counters))),
            rx: Box::new(RxHalf::new(rx, ifindex, Arc::clone(&counters))),
        },
        stats: NetStatsHandle::new(counters),
        tx_mode: crate::TxMode::SendQueue {
            max_batch: TX_BATCH_FRAMES,
        },
    })
}

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "linux"))]
mod layout_tests;
