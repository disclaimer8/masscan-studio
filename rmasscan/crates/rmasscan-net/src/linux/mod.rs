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

use std::sync::Arc;
use std::time::{Duration, Instant};

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;
#[cfg(target_os = "linux")]
use rmasscan_engine::AdapterPair;
use rmasscan_engine::{IoError, MAX_IO_TIMEOUT, Rx, RxHealth, SendStatus, Tx};

#[cfg(target_os = "linux")]
use crate::OpenedAdapter;
use crate::adapter_common::{
    Errno, Readiness, closed_error, errno_msg, map_setup_errno, valid_ifname,
};
use crate::{Counters, NetError, NetStatsHandle};

// Номера Linux без `libc`: errno, `ARPHRD_ETHER`, `PACKET_OUTGOING`.
mod abi;
use abi::errno::{EAGAIN, EBADF, EINTR, EINVAL, ENODEV, EWOULDBLOCK};
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

/// Шов syscalls одного сокета. Все методы НЕБЛОКИРУЮЩИЕ.
pub(crate) trait PacketIo: Send {
    fn send(&mut self, frame: &[u8]) -> Result<usize, Errno>;
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
    /// Пауза между повторами после EINTR. `wait` уже ограничена остатком
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

/// Максимальная пауза между повторами после EINTR (против busy-spin).
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
pub(crate) struct TxHalf<I: PacketIo> {
    io: Option<I>,
    counters: Arc<Counters>,
}

enum TxStep {
    Done(SendStatus),
    Fatal(String),
}

impl<I: PacketIo> TxHalf<I> {
    pub(crate) fn new(io: I, counters: Arc<Counters>) -> Self {
        Self {
            io: Some(io),
            counters,
        }
    }

    fn step(io: &mut I, frame: &[u8], deadline: &Deadline) -> TxStep {
        loop {
            match io.send(frame) {
                Ok(n) if n == frame.len() => return TxStep::Done(SendStatus::Sent),
                // Короткая запись: часть могла уйти.
                Ok(_) => return TxStep::Done(SendStatus::Uncertain),
                // EAGAIN/EINTR от send(): ядро не приняло ни байта.
                Err(e) if is_again(e) => {
                    if deadline.expired() {
                        return TxStep::Done(SendStatus::WouldBlockUnsent);
                    }
                    match io.poll(true, deadline.poll_ms()) {
                        Ok(Readiness::Ready) => {}
                        Ok(Readiness::Timeout) => {
                            return TxStep::Done(SendStatus::WouldBlockUnsent);
                        }
                        Ok(Readiness::Failed) => {
                            return TxStep::Fatal("poll(POLLOUT): socket error".into());
                        }
                        Err(EINTR) => io.backoff(deadline.eintr_wait()),
                        Err(e) => return TxStep::Fatal(errno_msg("poll(POLLOUT)", e)),
                    }
                }
                Err(EINTR) => {
                    // POSIX: send(), прерванный до передачи первого байта, ничего не
                    // отправил, поэтому WouldBlockUnsent (не Uncertain) безопасен.
                    if deadline.expired() {
                        return TxStep::Done(SendStatus::WouldBlockUnsent);
                    }
                    io.backoff(deadline.eintr_wait());
                }
                Err(e) => return TxStep::Fatal(errno_msg("send", e)),
            }
        }
    }
}

impl<I: PacketIo> Tx for TxHalf<I> {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError> {
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
}

/// RX-половина. Внутреннее кольцо из [`RX_BATCH`] слотов по [`RX_SLOT`] байт: пачку `recv_batch` `recv` выдаёт по
/// одной записи, и пока в кольце есть записи, никакого нового приёма нет; прямой путь (буфер вызывающего длиннее
/// слота) идёт только при пустом кольце. Кадры в кольце при закрытии теряются (раньше они так же лежали в очереди
/// сокета и уходили вместе с fd).
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
        tx_mode: crate::TxMode::Single,
    })
}

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "linux"))]
mod layout_tests;
