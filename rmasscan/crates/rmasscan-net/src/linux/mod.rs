//! Linux AF_PACKET: отдельные TX/RX сокеты, неблокирующий ввод-вывод и poll
//! до АБСОЛЮТНОГО дедлайна (не более 50 мс). Логика здесь безопасная и
//! общая для всех реализаций [`PacketIo`]; настоящие syscalls лежат в
//! private-модуле `socket`, а тесты подставляют синтетический `PacketIo`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;
use rmasscan_engine::{AdapterPair, IoError, MAX_IO_TIMEOUT, Rx, SendStatus, Tx};

use crate::{Counters, NetError, NetStatsHandle, OpenedAdapter};

#[allow(unsafe_code)]
mod socket;

/// Сырой errno.
pub(crate) type Errno = i32;

/// Результат poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Readiness {
    Timeout,
    Ready,
    /// POLLERR/POLLHUP/POLLNVAL без запрошенного события.
    Failed,
}

/// Метаданные принятого кадра. `len` это ИСТИННАЯ длина (MSG_TRUNC), она
/// может превышать буфер.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecvMeta {
    pub len: usize,
    pub pkttype: u8,
    pub ifindex: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelStats {
    pub packets: u32,
    pub drops: u32,
}

/// Шов syscalls одного сокета. Все методы НЕБЛОКИРУЮЩИЕ.
pub(crate) trait PacketIo: Send {
    fn send(&mut self, frame: &[u8]) -> Result<usize, Errno>;
    fn recv(&mut self, buf: &mut [u8]) -> Result<RecvMeta, Errno>;
    fn poll(&mut self, write: bool, timeout_ms: i32) -> Result<Readiness, Errno>;
    /// PACKET_STATISTICS: ядро сбрасывает счётчики при чтении.
    fn packet_stats(&mut self) -> Result<KernelStats, Errno>;
}

/// Шов запросов к ОС об интерфейсе.
pub(crate) trait IfaceInfo {
    /// `Ok(None)`: такого интерфейса нет.
    fn ifindex(&self, name: &str) -> Result<Option<u32>, Errno>;
    /// (sa_family, MAC).
    fn hw_addr(&self, name: &str) -> Result<(u16, [u8; 6]), Errno>;
}

const EAGAIN: Errno = libc::EAGAIN;
const EWOULDBLOCK: Errno = libc::EWOULDBLOCK;
const EINTR: Errno = libc::EINTR;
const ARPHRD_ETHER: u16 = libc::ARPHRD_ETHER;
const PACKET_OUTGOING: u8 = libc::PACKET_OUTGOING;
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
    /// Остаток в мс для poll, округление ВВЕРХ (иначе poll(0) крутится).
    fn poll_ms(&self) -> i32 {
        let left = self.0.saturating_duration_since(Instant::now());
        let ms = left.as_micros().div_ceil(1000);
        ms.min(MAX_IO_TIMEOUT.as_millis()) as i32
    }
}

fn closed_error() -> IoError {
    IoError::new("adapter closed after an earlier fatal error")
}

fn errno_msg(op: &str, e: Errno) -> String {
    format!("{op}: {}", std::io::Error::from_raw_os_error(e))
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
                        Err(EINTR) => {}
                        Err(e) => return TxStep::Fatal(errno_msg("poll(POLLOUT)", e)),
                    }
                }
                Err(EINTR) => {
                    // POSIX: send(), прерванный до передачи первого байта, ничего не
                    // отправил, поэтому WouldBlockUnsent (не Uncertain) безопасен.
                    if deadline.expired() {
                        return TxStep::Done(SendStatus::WouldBlockUnsent);
                    }
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

/// RX-половина.
pub(crate) struct RxHalf<I: PacketIo> {
    io: Option<I>,
    ifindex: i32,
    counters: Arc<Counters>,
    since_stats: u64,
}

enum RxStep {
    Frame(usize),
    Idle,
    Fatal(String),
}

impl<I: PacketIo> RxHalf<I> {
    pub(crate) fn new(io: I, ifindex: u32, counters: Arc<Counters>) -> Self {
        Self {
            io: Some(io),
            ifindex: ifindex as i32,
            counters,
            since_stats: 0,
        }
    }

    /// Забирает счётчики ядра (чтение сбрасывает их в ядре) и накапливает.
    fn flush_kernel_stats(&mut self) {
        use std::sync::atomic::Ordering::{Relaxed, Release};
        if let Some(io) = self.io.as_mut()
            && let Ok(s) = io.packet_stats()
        {
            self.counters
                .kernel_drops
                .fetch_add(u64::from(s.drops), Relaxed);
            self.counters.kernel_drops_known.store(true, Release);
        }
        self.since_stats = 0;
    }

    fn step(
        io: &mut I,
        ifindex: i32,
        counters: &Counters,
        buffer: &mut [u8],
        deadline: &Deadline,
    ) -> RxStep {
        loop {
            match io.recv(buffer) {
                Ok(meta) => {
                    if meta.pkttype == PACKET_OUTGOING {
                        Counters::bump(&counters.rx_outgoing);
                    } else if meta.ifindex != ifindex {
                        Counters::bump(&counters.rx_wrong_interface);
                    } else if meta.len > buffer.len() {
                        Counters::bump(&counters.rx_truncated);
                    } else {
                        Counters::bump(&counters.rx_packets);
                        return RxStep::Frame(meta.len);
                    }
                    // Отброшенный кадр не продлевает вызов.
                    if deadline.expired() {
                        return RxStep::Idle;
                    }
                }
                Err(e) if is_again(e) => {
                    if deadline.expired() {
                        return RxStep::Idle;
                    }
                    match io.poll(false, deadline.poll_ms()) {
                        // Готовность без пакета: возвращаемся к recv.
                        Ok(Readiness::Ready) | Err(EINTR) => {}
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
                }
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
        match Self::step(io, self.ifindex, &self.counters, buffer, &deadline) {
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
                Err(IoError::new(msg))
            }
        }
    }
}

impl<I: PacketIo> Drop for RxHalf<I> {
    fn drop(&mut self) {
        self.flush_kernel_stats();
    }
}

/// Имя интерфейса, допустимое для IFNAMSIZ и пригодное как аргумент ОС.
fn valid_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() < libc::IFNAMSIZ
        && name != "."
        && name != ".."
        && !name
            .bytes()
            .any(|b| b == 0 || b == b'/' || b.is_ascii_whitespace())
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
    let (family, _nic_mac) = match q.hw_addr(name) {
        Ok(v) => v,
        Err(libc::ENODEV) => {
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
    match e {
        libc::EPERM | libc::EACCES => NetError::PermissionDenied(errno_msg(op, e)),
        libc::ENODEV | libc::ENXIO => NetError::InterfaceMismatch(errno_msg(op, e)),
        _ => NetError::System(errno_msg(op, e)),
    }
}

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
    })
}

#[cfg(test)]
mod tests;
