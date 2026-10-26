//! macOS BPF: TX/RX половины адаптера поверх шва [`BpfIo`]. Весь код здесь
//! безопасный; настоящие `open`/`ioctl`/`read`/`write`/`poll` лежат в
//! `macos::sys`, а тесты подставляют синтетический шов.
//!
//! # Контракт
//! * Два НЕЗАВИСИМЫХ дескриптора `/dev/bpfN` на один интерфейс: TX (только
//!   `write`) и RX (только чтение). Каждый принадлежит одному потоку движка.
//! * Оба дескриптора `O_NONBLOCK`. Блокирующий `read` не используется вообще,
//!   `BIOCSRTIMEOUT` не используется. RX ждёт `poll(POLLIN)` с остатком
//!   АБСОЛЮТНОГО дедлайна `min(timeout, MAX_IO_TIMEOUT, IO_BUDGET)`; выбор
//!   `poll`/`kevent` скрыт за [`BpfIo::poll_in`].
//! * RX читает пачку записей `bpf_hdr` в собственный буфер ровно длины
//!   `BIOCGBLEN` и выдаёт кадры по одному. Шаг по буферу только
//!   `bpf_wordalign(bh_hdrlen + bh_caplen)`; `bh_hdrlen` проверяется в
//!   `18..=64`. Поля заголовка читаются из проверенного по границам среза.
//!   Нарушение раскладки это фатальная ошибка (дескриптор закрывается).
//! * Свои TX-кадры отсекаются тремя линиями: `BIOCSSEESENT 0`, фильтр ядра
//!   `not ether src <source_mac>` и программная проверка MAC источника.
//!   Поэтому `source_mac` обязан отличаться от `next_hop_mac`.
//! * TX не копит захват: фильтр `ret #0`. Режим promiscuous НЕ включается:
//!   ответы приходят на MAC самого интерфейса.
//! * TX: дескриптор открыт с `O_NONBLOCK`, но `write` НЕ доказанно неблокирующий:
//!   `bpfwrite` в XNU игнорирует флаги ввода-вывода и выделяет mbuf с `MBUF_WAITOK`,
//!   поэтому при нехватке mbuf он может заблокироваться на любом интерфейсе (на `feth`
//!   не наблюдалось, верхней границы нет; ОТКРЫТЫЙ риск). Полная запись это `Sent`; частичная это
//!   `Uncertain` (повтора нет); `ENOBUFS`/`EAGAIN` значит «ядро не приняло
//!   ни байта», поэтому до дедлайна кадр повторяется, после него это
//!   `WouldBlockUnsent`. Статус выводится только из errno, не из текста.
//! * Health: `bs_drop` RX дескриптора (кумулятивно, чтение не сбрасывает, `u32`
//!   оборачивается) через `DropCounter`; ошибка `BIOCGSTATS` это `Err`, а не
//!   `Some(0)`. Область: потери в буфере BPF (нижняя граница; потери в `feth`
//!   и драйвере NIC не видны).
//! * `rx_wrong_interface` всегда 0: структурно неприменимо, дескриптор
//!   привязан к одному интерфейсу (`BIOCSETIF`), сравнивать нечего.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;
use rmasscan_engine::{AdapterPair, IoError, MAX_IO_TIMEOUT, Rx, RxHealth, SendStatus, Tx};

use super::abi::errno::{
    EACCES, EAGAIN, EBUSY, EINTR, EMSGSIZE, ENOBUFS, ENODEV, ENOENT, ENXIO, EPERM,
};
use super::abi::{
    BpfInsn, BpfStat, DLT_EN10MB, DLT_NULL, MAX_HDRLEN, SIZEOF_BPF_HDR, bpf_wordalign,
    read_record_header,
};
use super::{Errno, errno_msg};
use crate::drop_counter::DropCounter;
use crate::{Counters, NetError, NetStatsHandle, OpenedAdapter};

/// Внутренний бюджет одного вызова адаптера: 33 мс. `poll` округляется вверх, таймеры
/// XNU опаздывают, а контракт 50 мс относится ко всему вызову. Живой спайк (задача 3,
/// `docs/experiments/2026-10-25-rmasscan-macos-bpf-spike.md`) измерил худшее превышение
/// `poll` 14,3 мс (под нагрузкой сборки; 9,1 мс на тихом Mac): 50 − (14,3 + 2) = 33.
pub(crate) const IO_BUDGET: Duration = Duration::from_millis(33);
/// Ethernet-заголовок без полезной нагрузки.
pub(crate) const MIN_TX_FRAME: usize = 14;
/// Максимум кадра на отправку: MTU 1500 + заголовок 14, VLAN не принимается.
pub(crate) const MAX_TX_FRAME: usize = 1514;
/// Максимальная пауза между повторами (EINTR, ENOBUFS) против busy-spin.
pub(crate) const BACKOFF_MAX: Duration = Duration::from_millis(1);
/// Буфер TX дескриптора (захват отключён фильтром, нужен минимум).
const TX_BUFFER_BYTES: u32 = 4096;
/// Перебор узлов `/dev/bpfN` заканчивается здесь, если `ENOENT` не встретился.
const MAX_NODES: u32 = 256;

const GRANT_HINT: &str =
    "/dev/bpf* is 0600 root:wheel; run `rmasscan-lab macos-lab bpf-access --grant`";

/// Результат ожидания готовности чтения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Readiness {
    Timeout,
    Ready,
    /// POLLERR/POLLHUP/POLLNVAL без POLLIN.
    Failed,
}

/// Шов ввода-вывода одного дескриптора BPF. Все методы НЕБЛОКИРУЮЩИЕ, кроме
/// `poll_in` (ждёт не дольше `timeout_ms`) и `backoff`.
pub(crate) trait BpfIo: Send {
    /// `write(2)` одного кадра.
    fn write(&mut self, frame: &[u8]) -> Result<usize, Errno>;
    /// `read(2)`: пачка записей `bpf_hdr`. `buf` обязан иметь длину `buffer_len()`.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Errno>;
    fn poll_in(&mut self, timeout_ms: i32) -> Result<Readiness, Errno>;
    /// `BIOCGSTATS`: ядро не сбрасывает счётчики при чтении.
    fn stats(&mut self) -> Result<BpfStat, Errno>;
    /// Пауза между повторами. `wait` уже ограничена остатком дедлайна и
    /// [`BACKOFF_MAX`]. Реализация обязана реально ждать, иначе цикл крутится.
    fn backoff(&mut self, wait: Duration);
    /// `BIOCGBLEN` после настройки.
    fn buffer_len(&self) -> usize;
}

/// Ioctl настройки дескриптора (выполняются один раз при открытии).
pub(crate) trait BpfSetup: BpfIo {
    /// `BIOCSBLEN` (до `BIOCSETIF`).
    fn set_buffer_len(&mut self, requested: u32) -> Result<(), Errno>;
    /// `BIOCSETIF`.
    fn bind_interface(&mut self, name: &str) -> Result<(), Errno>;
    /// `BIOCGDLT`.
    fn data_link(&mut self) -> Result<u32, Errno>;
    /// `BIOCIMMEDIATE`.
    fn set_immediate(&mut self, on: bool) -> Result<(), Errno>;
    /// `BIOCSSEESENT`.
    fn set_see_sent(&mut self, on: bool) -> Result<(), Errno>;
    /// `BIOCSHDRCMPLT`.
    fn set_hdr_complete(&mut self, on: bool) -> Result<(), Errno>;
    /// `BIOCSETF`.
    fn set_filter(&mut self, prog: &[BpfInsn]) -> Result<(), Errno>;
    /// `BIOCGBLEN`: запоминает фактическую длину буфера для `buffer_len()`.
    fn refresh_buffer_len(&mut self) -> Result<(), Errno>;
}

/// Шов открытия узлов `/dev/bpfN`.
pub(crate) trait BpfOpener {
    type Dev: BpfSetup + 'static;
    /// `min(4 MiB, debug.bpf_maxbufsize)`.
    fn max_buffer(&self) -> u32;
    fn open_node(&mut self, index: u32) -> Result<Self::Dev, Errno>;
}

/// Фильтр RX: отбросить кадры с нашим source MAC, остальное принять целиком.
pub(crate) fn own_mac_filter(mac: [u8; 6]) -> [BpfInsn; 6] {
    let hi = u32::from_be_bytes([mac[0], mac[1], mac[2], mac[3]]);
    let lo = u32::from(u16::from_be_bytes([mac[4], mac[5]]));
    let insn = |code, jt, jf, k| BpfInsn { code, jt, jf, k };
    [
        insn(0x20, 0, 0, 6),           // ld  [6:4]
        insn(0x15, 0, 3, hi),          // jeq mac[0..4] ? next : accept
        insn(0x28, 0, 0, 10),          // ldh [10]
        insn(0x15, 0, 1, lo),          // jeq mac[4..6] ? drop : accept
        insn(0x06, 0, 0, 0),           // ret #0 (свой кадр)
        insn(0x06, 0, 0, 0xffff_ffff), // ret #-1 (принять целиком)
    ]
}

/// Фильтр TX: ничего не захватывать.
pub(crate) fn drop_all_filter() -> [BpfInsn; 1] {
    [BpfInsn {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0,
    }]
}

fn closed_error() -> IoError {
    IoError::new("adapter closed after an earlier fatal error")
}

fn is_again(e: Errno) -> bool {
    e == EAGAIN
}

fn publish_drops(counters: &Counters, total: u64) {
    use std::sync::atomic::Ordering::{Relaxed, Release};
    counters.kernel_drops.store(total, Relaxed);
    counters.kernel_drops_known.store(true, Release);
}

/// Абсолютный дедлайн вызова. Фиксируется один раз; повторы не продлевают.
struct Deadline(Instant);

impl Deadline {
    fn new(timeout: Duration) -> Self {
        Deadline(Instant::now() + timeout.min(MAX_IO_TIMEOUT).min(IO_BUDGET))
    }
    fn expired(&self) -> bool {
        Instant::now() >= self.0
    }
    /// Пауза перед повтором: не более [`BACKOFF_MAX`] и не более остатка.
    fn backoff_wait(&self) -> Duration {
        self.0
            .saturating_duration_since(Instant::now())
            .min(BACKOFF_MAX)
    }
    /// Остаток в мс для poll, округление ВВЕРХ (иначе poll(0) крутится).
    fn poll_ms(&self) -> i32 {
        let left = self.0.saturating_duration_since(Instant::now());
        let ms = left.as_nanos().div_ceil(1_000_000);
        ms.min(IO_BUDGET.as_millis()) as i32
    }
}

// ---------------------------------------------------------------- TX

/// TX-половина. После фатальной ошибки дескриптор закрывается (`io = None`).
pub(crate) struct TxHalf<I: BpfIo> {
    io: Option<I>,
    counters: Arc<Counters>,
}

enum TxStep {
    Done(SendStatus),
    /// Кадр не ушёл, дескриптор исправен.
    Rejected(String),
    Fatal(String),
}

impl<I: BpfIo> TxHalf<I> {
    pub(crate) fn new(io: I, counters: Arc<Counters>) -> Self {
        Self {
            io: Some(io),
            counters,
        }
    }

    fn step(io: &mut I, frame: &[u8], deadline: &Deadline) -> TxStep {
        loop {
            match io.write(frame) {
                Ok(n) if n == frame.len() => return TxStep::Done(SendStatus::Sent),
                // Частичная (или нулевая) запись: часть могла уйти.
                Ok(_) => return TxStep::Done(SendStatus::Uncertain),
                // ENOBUFS/EAGAIN: ядро не приняло ни байта, кадр точно не ушёл.
                Err(e) if e == ENOBUFS || is_again(e) => {
                    if deadline.expired() {
                        return TxStep::Done(SendStatus::WouldBlockUnsent);
                    }
                    io.backoff(deadline.backoff_wait());
                }
                // POSIX: write(), прерванный до первого байта, ничего не отправил.
                Err(EINTR) => {
                    if deadline.expired() {
                        return TxStep::Done(SendStatus::WouldBlockUnsent);
                    }
                    io.backoff(deadline.backoff_wait());
                }
                Err(EMSGSIZE) => {
                    return TxStep::Rejected(errno_msg("write", EMSGSIZE) + "; nothing was sent");
                }
                Err(e) => return TxStep::Fatal(errno_msg("write", e)),
            }
        }
    }
}

impl<I: BpfIo> Tx for TxHalf<I> {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError> {
        let deadline = Deadline::new(timeout);
        let Some(io) = self.io.as_mut() else {
            return Err(closed_error());
        };
        // Проверка ДО записи: кадр не уходит, исход известен.
        if !(MIN_TX_FRAME..=MAX_TX_FRAME).contains(&frame.len()) {
            Counters::bump(&self.counters.tx_errors);
            return Err(IoError::new(format!(
                "frame length {} is outside {MIN_TX_FRAME}..={MAX_TX_FRAME}; nothing was sent",
                frame.len()
            )));
        }
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
            TxStep::Rejected(msg) => {
                Counters::bump(&self.counters.tx_errors);
                Err(IoError::new(msg))
            }
            TxStep::Fatal(msg) => {
                Counters::bump(&self.counters.tx_errors);
                self.io = None; // закрывает fd
                Err(IoError::new(msg))
            }
        }
    }
}

// ---------------------------------------------------------------- RX

/// Результат разбора одной записи буфера.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Record {
    /// Кадр целиком (`caplen == datalen`) лежит в `buf[start..end]`.
    Frame { start: usize, end: usize },
    /// Кадр усечён ядром (`caplen != datalen`): не выдаётся.
    Truncated,
}

/// Разбирает запись по смещению `*off` внутри `buf[..end]` и продвигает `*off`
/// на `bpf_wordalign(bh_hdrlen + bh_caplen)`. `Err` значит, что раскладка
/// нарушена и дальнейшему содержимому доверять нельзя.
pub(crate) fn parse_record(
    buf: &[u8],
    off: &mut usize,
    end: usize,
) -> Result<Record, &'static str> {
    let rest = buf
        .get(*off..end)
        .ok_or("BPF record offset is outside the read buffer")?;
    let hdr = read_record_header(rest).ok_or("BPF record header is shorter than 18 bytes")?;
    let hdrlen = usize::from(hdr.hdrlen);
    if !(SIZEOF_BPF_HDR..=MAX_HDRLEN).contains(&hdrlen) {
        return Err("BPF bh_hdrlen is outside 18..=64");
    }
    let caplen = usize::try_from(hdr.caplen).map_err(|_| "BPF bh_caplen does not fit usize")?;
    let total = hdrlen
        .checked_add(caplen)
        .filter(|t| *t <= rest.len())
        .ok_or("BPF record extends past the read buffer")?;
    let start = *off + hdrlen;
    let frame_end = *off + total;
    // Последняя запись может не содержать завершающего выравнивания.
    *off = (*off + bpf_wordalign(total)).min(end);
    if hdr.caplen != hdr.datalen {
        return Ok(Record::Truncated);
    }
    Ok(Record::Frame {
        start,
        end: frame_end,
    })
}

/// RX-половина.
pub(crate) struct RxHalf<I: BpfIo> {
    io: Option<I>,
    own_mac: [u8; 6],
    counters: Arc<Counters>,
    drops: DropCounter,
    /// Последняя прочитанная пачка: `rbuf[off..end]` ещё не разобрано.
    rbuf: Vec<u8>,
    off: usize,
    end: usize,
}

enum RxStep {
    Frame(usize),
    Idle,
    Fatal(String),
}

impl<I: BpfIo> RxHalf<I> {
    pub(crate) fn new(
        io: I,
        own_mac: [u8; 6],
        counters: Arc<Counters>,
        baseline_drop: u32,
    ) -> Self {
        let rbuf = vec![0u8; io.buffer_len()];
        Self {
            io: Some(io),
            own_mac,
            counters,
            drops: DropCounter::new(baseline_drop),
            rbuf,
            off: 0,
            end: 0,
        }
    }

    /// Фоновое обновление итога потерь; ошибку не скрывает навсегда
    /// (достоверность проверяет `health`).
    fn flush_drops(&mut self) {
        if let Some(io) = self.io.as_mut()
            && let Ok(st) = io.stats()
        {
            publish_drops(&self.counters, self.drops.update(st.bs_drop));
        }
    }

    /// Фатальная ошибка: итог потерь фиксируется, дескриптор закрывается.
    fn fatal(&mut self, msg: String) -> RxStep {
        Counters::bump(&self.counters.rx_errors);
        self.flush_drops();
        self.io = None;
        RxStep::Fatal(msg)
    }

    fn step(&mut self, buffer: &mut [u8], deadline: &Deadline) -> RxStep {
        loop {
            // 1. Уже прочитанные записи.
            if self.off < self.end {
                match parse_record(&self.rbuf, &mut self.off, self.end) {
                    Err(why) => {
                        // Остаток буфера недостоверен.
                        self.off = self.end;
                        return self.fatal(why.to_string());
                    }
                    Ok(Record::Truncated) => Counters::bump(&self.counters.rx_truncated),
                    Ok(Record::Frame { start, end }) => {
                        let frame = &self.rbuf[start..end];
                        if frame.len() < MIN_TX_FRAME {
                            // Короче Ethernet-заголовка: не кадр, никогда не `Some(0)`.
                            Counters::bump(&self.counters.rx_truncated);
                        } else if frame[6..12] == self.own_mac {
                            Counters::bump(&self.counters.rx_outgoing);
                        } else if frame.len() > buffer.len() {
                            Counters::bump(&self.counters.rx_truncated);
                        } else {
                            buffer[..frame.len()].copy_from_slice(frame);
                            Counters::bump(&self.counters.rx_packets);
                            return RxStep::Frame(frame.len());
                        }
                    }
                }
                // Отброшенная запись не продлевает вызов.
                if deadline.expired() {
                    return RxStep::Idle;
                }
                continue;
            }
            // 2. Новая пачка.
            let Some(io) = self.io.as_mut() else {
                return RxStep::Fatal(closed_error().message);
            };
            match io.read(&mut self.rbuf) {
                Ok(n) if n > 0 && n <= self.rbuf.len() => {
                    self.off = 0;
                    self.end = n;
                }
                Ok(n) if n > self.rbuf.len() => {
                    return self.fatal(format!(
                        "read returned {n} bytes into a {} byte buffer",
                        self.rbuf.len()
                    ));
                }
                // Пустое чтение ведёт себя как EAGAIN.
                Ok(_) => match Self::wait_readable(io, deadline) {
                    Wait::Retry => {}
                    Wait::Idle => return RxStep::Idle,
                    Wait::Fatal(m) => return self.fatal(m),
                },
                Err(e) if is_again(e) => match Self::wait_readable(io, deadline) {
                    Wait::Retry => {}
                    Wait::Idle => return RxStep::Idle,
                    Wait::Fatal(m) => return self.fatal(m),
                },
                Err(EINTR) => {
                    if deadline.expired() {
                        return RxStep::Idle;
                    }
                    io.backoff(deadline.backoff_wait());
                }
                Err(e) => return self.fatal(errno_msg("read", e)),
            }
        }
    }

    fn wait_readable(io: &mut I, deadline: &Deadline) -> Wait {
        if deadline.expired() {
            return Wait::Idle;
        }
        match io.poll_in(deadline.poll_ms()) {
            // Готовность без записей: вернуться к read (дедлайн проверится).
            Ok(Readiness::Ready) => Wait::Retry,
            Ok(Readiness::Timeout) => Wait::Idle,
            Ok(Readiness::Failed) => Wait::Fatal("poll(POLLIN): descriptor error".into()),
            Err(EINTR) => {
                io.backoff(deadline.backoff_wait());
                Wait::Retry
            }
            Err(e) => Wait::Fatal(errno_msg("poll(POLLIN)", e)),
        }
    }
}

enum Wait {
    Retry,
    Idle,
    Fatal(String),
}

impl<I: BpfIo> Rx for RxHalf<I> {
    fn recv(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<Option<usize>, IoError> {
        if self.io.is_none() {
            return Err(closed_error());
        }
        let deadline = Deadline::new(timeout);
        match self.step(buffer, &deadline) {
            RxStep::Frame(n) => Ok(Some(n)),
            RxStep::Idle => Ok(None),
            RxStep::Fatal(msg) => Err(IoError::new(msg)),
        }
    }

    fn health(&mut self, _timeout: Duration) -> Result<RxHealth, IoError> {
        let Some(io) = self.io.as_mut() else {
            return Err(closed_error());
        };
        // Свежее чтение: ошибка отдаётся вызывающему, кэшированный итог не
        // подменяет её.
        match io.stats() {
            Ok(st) => {
                let total = self.drops.update(st.bs_drop);
                publish_drops(&self.counters, total);
                Ok(RxHealth {
                    kernel_drops: Some(total),
                })
            }
            Err(e) => Err(IoError::new(errno_msg("ioctl(BIOCGSTATS)", e))),
        }
    }
}

impl<I: BpfIo> Drop for RxHalf<I> {
    fn drop(&mut self) {
        // Итог остаётся в общих счётчиках после закрытия дескриптора.
        self.flush_drops();
    }
}

// ---------------------------------------------------------------- открытие

pub(crate) fn mac_text(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Проверка binding без обращения к ОС.
pub(crate) fn check_binding(binding: &AdapterBinding) -> Result<(), NetError> {
    if binding.link_type != LinkType::Ethernet {
        return Err(NetError::UnsupportedLink(format!(
            "{:?} (macOS BPF adapter supports Ethernet only)",
            binding.link_type
        )));
    }
    let mac = binding.source_mac;
    if mac == [0; 6] || mac[0] & 1 == 1 {
        return Err(NetError::InterfaceMismatch(format!(
            "source MAC {} is not a unicast address",
            mac_text(&mac)
        )));
    }
    if mac == binding.next_hop_mac {
        return Err(NetError::InterfaceMismatch(
            "source MAC equals the next-hop MAC: own transmitted frames could not be told \
             from replies"
                .into(),
        ));
    }
    Ok(())
}

fn map_setup_error(op: &str, e: Errno) -> NetError {
    match e {
        EPERM | EACCES => NetError::PermissionDenied(errno_msg(op, e)),
        ENXIO | ENODEV => NetError::InterfaceMismatch(errno_msg(op, e)),
        _ => NetError::System(errno_msg(op, e)),
    }
}

/// Перебор `/dev/bpf0..`: занятый узел пропускается, `EACCES` запоминается,
/// `ENOENT` конец списка.
fn open_device<O: BpfOpener>(opener: &mut O) -> Result<O::Dev, NetError> {
    let mut denied = false;
    let mut busy = 0u32;
    for n in 0..MAX_NODES {
        match opener.open_node(n) {
            Ok(d) => return Ok(d),
            Err(EBUSY) => busy += 1,
            Err(EACCES | EPERM) => denied = true,
            Err(ENOENT) => break,
            Err(e) => return Err(NetError::System(errno_msg(&format!("open /dev/bpf{n}"), e))),
        }
    }
    if denied {
        Err(NetError::PermissionDenied(GRANT_HINT.into()))
    } else {
        Err(NetError::System(format!(
            "no free /dev/bpf* device ({busy} busy)"
        )))
    }
}

fn check_dlt<D: BpfSetup>(dev: &mut D, name: &str) -> Result<(), NetError> {
    match dev
        .data_link()
        .map_err(|e| map_setup_error("BIOCGDLT", e))?
    {
        DLT_EN10MB => Ok(()),
        DLT_NULL => Err(NetError::UnsupportedLink(format!(
            "interface {name:?}: loopback (DLT_NULL) is not Ethernet"
        ))),
        other => Err(NetError::UnsupportedLink(format!(
            "interface {name:?}: DLT {other} is not Ethernet"
        ))),
    }
}

/// RX: `BIOCSBLEN` → `BIOCSETIF` → `BIOCGDLT` → `BIOCIMMEDIATE 1` →
/// `BIOCSSEESENT 0` → `BIOCSETF(own_mac_filter)` → `BIOCGBLEN` → `BIOCGSTATS`.
/// Возвращает базовое значение `bs_drop`.
fn configure_rx<D: BpfSetup>(
    dev: &mut D,
    name: &str,
    mac: [u8; 6],
    max_buffer: u32,
) -> Result<u32, NetError> {
    let s = map_setup_error;
    dev.set_buffer_len(max_buffer)
        .map_err(|e| s("BIOCSBLEN", e))?;
    dev.bind_interface(name).map_err(|e| s("BIOCSETIF", e))?;
    check_dlt(dev, name)?;
    dev.set_immediate(true).map_err(|e| s("BIOCIMMEDIATE", e))?;
    dev.set_see_sent(false).map_err(|e| s("BIOCSSEESENT", e))?;
    dev.set_filter(&own_mac_filter(mac))
        .map_err(|e| s("BIOCSETF", e))?;
    dev.refresh_buffer_len().map_err(|e| s("BIOCGBLEN", e))?;
    if dev.buffer_len() < SIZEOF_BPF_HDR + MAX_TX_FRAME {
        return Err(NetError::System(format!(
            "BPF buffer of {} bytes is too small",
            dev.buffer_len()
        )));
    }
    let base = dev.stats().map_err(|e| s("BIOCGSTATS", e))?;
    Ok(base.bs_drop)
}

/// TX: `BIOCSBLEN 4096` → `BIOCSETIF` → `BIOCGDLT` → `BIOCSHDRCMPLT 1` →
/// `BIOCSSEESENT 0` → `BIOCSETF(drop_all_filter)`.
fn configure_tx<D: BpfSetup>(dev: &mut D, name: &str) -> Result<(), NetError> {
    let s = map_setup_error;
    dev.set_buffer_len(TX_BUFFER_BYTES)
        .map_err(|e| s("BIOCSBLEN", e))?;
    dev.bind_interface(name).map_err(|e| s("BIOCSETIF", e))?;
    check_dlt(dev, name)?;
    dev.set_hdr_complete(true)
        .map_err(|e| s("BIOCSHDRCMPLT", e))?;
    dev.set_see_sent(false).map_err(|e| s("BIOCSSEESENT", e))?;
    dev.set_filter(&drop_all_filter())
        .map_err(|e| s("BIOCSETF", e))?;
    Ok(())
}

/// Открывает пару RX/TX на `opener`. Любая ошибка после первого открытия
/// закрывает уже открытые дескрипторы (Drop).
pub(crate) fn open_with<O: BpfOpener>(
    opener: &mut O,
    binding: &AdapterBinding,
) -> Result<OpenedAdapter, NetError> {
    check_binding(binding)?;
    let name = binding.interface_id.as_str();
    let max_buffer = opener.max_buffer();

    let mut rx = open_device(opener)?;
    let baseline = configure_rx(&mut rx, name, binding.source_mac, max_buffer)?;
    let mut tx = open_device(opener)?;
    configure_tx(&mut tx, name)?;

    let counters = Arc::new(Counters::default());
    Ok(OpenedAdapter {
        io: AdapterPair {
            tx: Box::new(TxHalf::new(tx, Arc::clone(&counters))),
            rx: Box::new(RxHalf::new(
                rx,
                binding.source_mac,
                Arc::clone(&counters),
                baseline,
            )),
        },
        stats: NetStatsHandle::new(counters),
        tx_mode: crate::TxMode::Single,
    })
}

/// Открывает адаптер на настоящих `/dev/bpfN`.
#[cfg(target_os = "macos")]
pub(crate) fn open(binding: &AdapterBinding) -> Result<OpenedAdapter, NetError> {
    check_binding(binding)?;
    super::ifinfo::verify_binding(&super::ifinfo::OsIface, binding)?;
    open_with(&mut super::sys::SysOpener, binding)
}
