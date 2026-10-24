//! Сетевые адаптеры (AGPL-3.0). Этап 2B-Linux: AF_PACKET с ограниченным по
//! времени вводом-выводом. Это единственный crate, где допускается `unsafe`:
//! весь FFI находится в private-модуле `linux::socket`, остальной код
//! безопасный и тестируется через синтетический syscall-шов
//! (`linux::PacketIo`, `linux::IfaceInfo`).
//!
//! Контракт: каждый вызов `send`/`recv` возвращается не позже
//! `min(timeout, 50 мс)` (абсолютный дедлайн; повтор после EINTR его не
//! продлевает). Другие платформы и типы канала дают явную ошибку ДО любой
//! отправки.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use rmasscan_core::probe::AdapterBinding;
use rmasscan_engine::AdapterPair;

#[cfg(target_os = "linux")]
mod linux;

// Windows/Npcap: на Windows это рабочий backend; в тестах других платформ
// собираются портабельные части (ABI, подставной загрузчик).
#[cfg(any(windows, test))]
#[allow(unsafe_code, dead_code)]
mod windows;

/// Ошибка открытия адаптера.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    #[error("raw packet I/O is not implemented on this platform")]
    UnsupportedPlatform,
    #[error("unsupported link type: {0}")]
    UnsupportedLink(String),
    #[error("permission denied (raw packet access needs elevated privileges): {0}")]
    PermissionDenied(String),
    #[error("interface does not match the binding: {0}")]
    InterfaceMismatch(String),
    #[error("packet driver unavailable: {0}")]
    DriverUnavailable(String),
    #[error("required packet driver capability is missing: {0}")]
    MissingCapability(String),
    #[error("packet driver ABI mismatch: {0}")]
    AbiMismatch(String),
    #[error("system error: {0}")]
    System(String),
}

/// Накопленные счётчики. `kernel_drops == None` значит «недоступно».
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetStats {
    pub tx_sent: u64,
    pub tx_would_block: u64,
    pub tx_uncertain: u64,
    pub tx_errors: u64,
    pub rx_packets: u64,
    /// Кадры, не поместившиеся в буфер вызывающего (отброшены).
    pub rx_truncated: u64,
    /// Кадры с PACKET_OUTGOING (наши собственные; отброшены).
    pub rx_outgoing: u64,
    /// Кадры с чужим ifindex (отброшены).
    pub rx_wrong_interface: u64,
    pub rx_errors: u64,
    pub kernel_drops: Option<u64>,
}

#[derive(Default)]
pub(crate) struct Counters {
    pub tx_sent: AtomicU64,
    pub tx_would_block: AtomicU64,
    pub tx_uncertain: AtomicU64,
    pub tx_errors: AtomicU64,
    pub rx_packets: AtomicU64,
    pub rx_truncated: AtomicU64,
    pub rx_outgoing: AtomicU64,
    pub rx_wrong_interface: AtomicU64,
    pub rx_errors: AtomicU64,
    pub kernel_drops: AtomicU64,
    pub kernel_drops_known: AtomicBool,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl Counters {
    pub(crate) fn bump(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }
}

/// Дескриптор статистики. Не владеет fd; счётчики живут в общем `Arc`,
/// поэтому handle переживает закрытие сокетов. Чтение ничего не сбрасывает.
#[derive(Clone)]
pub struct NetStatsHandle {
    counters: Arc<Counters>,
}

impl NetStatsHandle {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn new(counters: Arc<Counters>) -> Self {
        Self { counters }
    }

    pub fn snapshot(&self) -> NetStats {
        let c = &self.counters;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        NetStats {
            tx_sent: get(&c.tx_sent),
            tx_would_block: get(&c.tx_would_block),
            tx_uncertain: get(&c.tx_uncertain),
            tx_errors: get(&c.tx_errors),
            rx_packets: get(&c.rx_packets),
            rx_truncated: get(&c.rx_truncated),
            rx_outgoing: get(&c.rx_outgoing),
            rx_wrong_interface: get(&c.rx_wrong_interface),
            rx_errors: get(&c.rx_errors),
            kernel_drops: c
                .kernel_drops_known
                .load(Ordering::Acquire)
                .then(|| get(&c.kernel_drops)),
        }
    }
}

impl std::fmt::Debug for NetStatsHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("NetStatsHandle")
            .field(&self.snapshot())
            .finish()
    }
}

/// Открытый адаптер: пара TX/RX для движка и независимый handle статистики.
pub struct OpenedAdapter {
    pub io: AdapterPair,
    pub stats: NetStatsHandle,
}

/// Открывает адаптер по явному binding (имя интерфейса проверяется ОС;
/// никогда не передаётся в shell).
#[cfg(target_os = "linux")]
pub fn open_explicit(binding: &AdapterBinding) -> Result<OpenedAdapter, NetError> {
    linux::open(binding)
}

/// Остальные платформы: явная ошибка до любой отправки.
#[cfg(not(target_os = "linux"))]
pub fn open_explicit(_binding: &AdapterBinding) -> Result<OpenedAdapter, NetError> {
    Err(NetError::UnsupportedPlatform)
}
