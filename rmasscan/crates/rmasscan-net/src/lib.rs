//! Сетевые адаптеры (AGPL-3.0). Linux: AF_PACKET; macOS: BPF (`/dev/bpfN`); Windows: Npcap. Это
//! единственный crate, где допускается `unsafe`: весь FFI находится в
//! private-модулях (`linux::socket`; `macos::{sys, ifinfo, process}` (BPF ABI, sysctl, getifaddrs, метрики процесса); `windows::{ffi, handle, loader, process, sys}`; `process` это лабораторная
//! телеметрия процесса (Toolhelp, токен, счётчики памяти), в продуктовой сборке она
//! тоже присутствует) и,
//! только с feature `lab` (включает один rmasscan-lab), в `lab_io::imp`
//! (sigaction-флаг остановки и listener с backlog 0); остальной код безопасный и тестируется через синтетические швы
//! (`linux::PacketIo`, `linux::IfaceInfo`; `macos::adapter::BpfIo`; подставная таблица функций wpcap).
//!
//! Контракт: каждый вызов `recv`/`health` возвращается не позже
//! `min(timeout, 50 мс)` (абсолютный дедлайн; на Windows внутренний бюджет
//! 42 мс). `send` на Linux и macOS ограничен тем же дедлайном (на macOS бюджет 50 мс, предварительный до спайка); на Windows
//! `pcap_sendpacket` синхронный и не отменяемый (граница измерена, см.
//! `windows::adapter`). Другие платформы и типы канала дают явную ошибку ДО
//! любой отправки.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use rmasscan_core::probe::AdapterBinding;
use rmasscan_engine::AdapterPair;

#[cfg(target_os = "linux")]
mod linux;

// macOS: BPF (`/dev/bpf*`). `unsafe` только в `macos::{sys, ifinfo, process}`. Переносимые
// части (`abi`, `adapter`) собираются и в тестах других платформ (seam-тесты).
#[cfg(any(target_os = "macos", test))]
mod macos;

// Общий счётчик потерь 32-битного драйверного счётчика (Npcap, BPF).
#[cfg(any(windows, target_os = "macos", test))]
mod drop_counter;

// Windows/Npcap: на Windows это рабочий backend; в тестах других платформ
// собираются портабельные части (ABI, подставная таблица функций). `unsafe`
// разрешён только в FFI-подмодулях (см. `windows/mod.rs`).
#[cfg(any(windows, test))]
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

/// Идентификатор ABI-слоя Npcap, попадающий в идентичность каждого JSON:
/// динамическая загрузка `wpcap.dll` по полному пути, собственные объявления
/// (без Npcap SDK и import-библиотек), x86_64.
pub const NPCAP_ABI_ID: &str =
    "wpcap.dll dynamic load by full path; own ffi declarations v1; x86_64";

/// Загруженная и проверенная DLL Npcap (путь, версия, хэш содержимого).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DllReport {
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub version: Option<String>,
}

/// Устройство из перечня Npcap. `mac` это MAC того же адаптера в ОС
/// (`None`, если не определён).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceReport {
    pub name: String,
    pub description: Option<String>,
    pub loopback: bool,
    pub mac: Option<[u8; 6]>,
}

/// Результат `--inventory`: что установлено и какие адаптеры видны. Получается
/// без открытия адаптера и без единой отправки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// Строка `pcap_lib_version`.
    pub lib_version: String,
    pub utf8_text: bool,
    pub dlls: Vec<DllReport>,
    /// Версия драйвера `npcap.sys`, если файл найден.
    pub driver_version: Option<String>,
    pub devices: Vec<DeviceReport>,
}

/// Идентификатор ABI-слоя BPF macOS, попадающий в идентичность каждого JSON:
/// `/dev/bpf*` через ioctl, собственные объявления поверх `libc`, aarch64.
pub const BPF_ABI_ID: &str = "/dev/bpf* ioctl via libc; own declarations v1; aarch64";

/// Узел `/dev/bpfN` (только `stat`, без открытия).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfDevice {
    pub path: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Интерфейс из `getifaddrs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceReport {
    pub name: String,
    pub index: u32,
    pub mac: Option<[u8; 6]>,
    /// ОС скрыла MAC от процесса (macOS 27 отдаёт `02:00:00:00:00:00` без прав):
    /// `mac` тогда `None`, а не плейсхолдер.
    pub mac_masked: bool,
    pub ethernet: bool,
    pub up: bool,
    pub ipv4: Vec<std::net::Ipv4Addr>,
}

/// Результат инвентаря macOS: получается без привилегий, без открытия BPF и
/// без единой отправки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfInventory {
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub bpf_maxbufsize: Option<u32>,
    pub bpf_maxdevices: Option<u32>,
    pub devices: Vec<BpfDevice>,
    pub interfaces: Vec<IfaceReport>,
    pub instant_clock: &'static str,
}

/// macOS: инвентарь BPF (sysctl, `stat` узлов, `getifaddrs`).
#[cfg(target_os = "macos")]
pub fn inventory_bpf() -> Result<BpfInventory, NetError> {
    macos::inventory()
}

#[cfg(not(target_os = "macos"))]
pub fn inventory_bpf() -> Result<BpfInventory, NetError> {
    Err(NetError::UnsupportedPlatform)
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
    /// Собственные кадры, отброшенные до движка. Linux: кадры с PACKET_OUTGOING.
    /// Windows: кадры с нашим source MAC (у Npcap нет признака направления).
    /// macOS: кадры с нашим source MAC (вторая линия после фильтра ядра).
    pub rx_outgoing: u64,
    /// Кадры с чужим ifindex (отброшены). Linux: считается. Windows и macOS: всегда 0 и
    /// НЕ измерено, а структурно неприменимо: handle привязан к одному
    /// устройству, сравнивать ifindex нечего. Нуль здесь не свидетельство.
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

/// Windows: Npcap (`wpcap.dll` из `System32\Npcap`, загрузка по полному пути).
#[cfg(windows)]
pub fn open_explicit(binding: &AdapterBinding) -> Result<OpenedAdapter, NetError> {
    windows::open(binding)
}

/// macOS: BPF (`/dev/bpfN`, два независимых дескриптора).
#[cfg(target_os = "macos")]
pub fn open_explicit(binding: &AdapterBinding) -> Result<OpenedAdapter, NetError> {
    macos::open(binding)
}

/// Остальные платформы: явная ошибка до любой отправки.
#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
pub fn open_explicit(_binding: &AdapterBinding) -> Result<OpenedAdapter, NetError> {
    Err(NetError::UnsupportedPlatform)
}

/// Перечень Npcap и адаптеров БЕЗ открытия адаптера и без отправки. Загружает
/// `wpcap.dll` (только чтение), поэтому отсутствие Npcap это `DriverUnavailable`.
#[cfg(windows)]
pub fn inventory() -> Result<Inventory, NetError> {
    windows::inventory::collect()
}

#[cfg(not(windows))]
pub fn inventory() -> Result<Inventory, NetError> {
    Err(NetError::UnsupportedPlatform)
}

/// MAC адаптера ОС по имени Npcap `\Device\NPF_{GUID}`. `None`, если
/// определить нельзя (в том числе вне Windows).
#[cfg(windows)]
pub fn nic_mac(interface_id: &str) -> Option<[u8; 6]> {
    windows::inventory::nic_mac(interface_id)
}

/// macOS: MAC интерфейса по имени (`getifaddrs`/AF_LINK). `None`, если интерфейса нет
/// или ОС скрыла MAC плейсхолдером `02:00:00:00:00:00` (см. `nic_mac_masked`).
#[cfg(target_os = "macos")]
pub fn nic_mac(interface_id: &str) -> Option<[u8; 6]> {
    macos::ifinfo::nic_mac(interface_id)
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn nic_mac(_interface_id: &str) -> Option<[u8; 6]> {
    None
}

/// macOS: `Some(true/false)` существует ли интерфейс (`if_nametoindex`, не зависит от MAC);
/// `None`, если ОС не ответила или платформа не macOS.
#[doc(hidden)]
#[cfg(target_os = "macos")]
pub fn iface_exists(interface_id: &str) -> Option<bool> {
    macos::ifinfo::iface_exists(interface_id)
}

#[doc(hidden)]
#[cfg(not(target_os = "macos"))]
pub fn iface_exists(_interface_id: &str) -> Option<bool> {
    None
}

/// macOS: ОС вернула плейсхолдер вместо MAC интерфейса (`nic_mac` тогда `None`).
#[doc(hidden)]
#[cfg(target_os = "macos")]
pub fn nic_mac_masked(interface_id: &str) -> bool {
    macos::ifinfo::nic_mac_masked(interface_id)
}

#[doc(hidden)]
#[cfg(not(target_os = "macos"))]
pub fn nic_mac_masked(_interface_id: &str) -> bool {
    false
}

/// Версия ОС (`RtlGetVersion`, ревизия из kernel32.dll при совпадении сборки)
/// для привязки доказательств к сборке Windows; `None` вне Windows.
#[cfg(windows)]
pub fn os_version() -> Option<String> {
    windows::inventory::os_version()
}

/// macOS: `kern.osproductversion (kern.osversion)`, например `27.0.1 (26A434)`.
#[cfg(target_os = "macos")]
pub fn os_version() -> Option<String> {
    macos::os_version()
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn os_version() -> Option<String> {
    None
}

/// Снимок собственного процесса для harness. `None` значит «не измерено».
/// Служебный API лабораторного harness (не часть продуктового контракта).
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessSample {
    pub handles: Option<u64>,
    pub threads: Option<u64>,
    pub working_set_bytes: Option<u64>,
    pub peak_working_set_bytes: Option<u64>,
    pub cpu_user_ms: Option<u64>,
    pub cpu_kernel_ms: Option<u64>,
}

/// Флаги токена процесса (только Windows).
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokenFlags {
    pub elevated: Option<bool>,
    pub restricted: Option<bool>,
}

/// Измерения процесса: Windows (поддерживаемые API) и macOS (`getrusage`, `proc_pidinfo`);
/// на других ОС пусто (Linux harness читает `/proc` сам).
#[doc(hidden)]
#[cfg(windows)]
pub fn process_sample() -> ProcessSample {
    windows::process::process_sample()
}

#[doc(hidden)]
#[cfg(target_os = "macos")]
pub fn process_sample() -> ProcessSample {
    macos::process::process_sample()
}

#[doc(hidden)]
#[cfg(not(any(windows, target_os = "macos")))]
pub fn process_sample() -> ProcessSample {
    ProcessSample::default()
}

#[doc(hidden)]
#[cfg(windows)]
pub fn token_flags() -> TokenFlags {
    windows::process::token_flags()
}

#[doc(hidden)]
#[cfg(not(windows))]
pub fn token_flags() -> TokenFlags {
    TokenFlags::default()
}

/// Идентификатор текущего потока ОС (служебный API harness: проверка потоков движка после join).
#[doc(hidden)]
#[cfg(windows)]
pub fn lab_current_thread_id() -> Option<u64> {
    windows::process::current_thread_id()
}

/// Linux: `/proc/thread-self` указывает на `<pid>/task/<tid>`.
#[doc(hidden)]
#[cfg(target_os = "linux")]
pub fn lab_current_thread_id() -> Option<u64> {
    std::fs::read_link("/proc/thread-self")
        .ok()?
        .file_name()?
        .to_str()?
        .parse()
        .ok()
}

#[doc(hidden)]
#[cfg(target_os = "macos")]
pub fn lab_current_thread_id() -> Option<u64> {
    macos::process::current_thread_id()
}

#[doc(hidden)]
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn lab_current_thread_id() -> Option<u64> {
    None
}

/// Идентификаторы всех потоков процесса (`None`, если ОС их не даёт).
#[doc(hidden)]
#[cfg(windows)]
pub fn lab_thread_ids() -> Option<Vec<u64>> {
    windows::process::thread_ids()
}

#[doc(hidden)]
#[cfg(target_os = "linux")]
pub fn lab_thread_ids() -> Option<Vec<u64>> {
    let ids: Vec<u64> = std::fs::read_dir("/proc/self/task")
        .ok()?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    (!ids.is_empty()).then_some(ids)
}

#[doc(hidden)]
#[cfg(target_os = "macos")]
pub fn lab_thread_ids() -> Option<Vec<u64>> {
    macos::process::thread_ids()
}

#[doc(hidden)]
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn lab_thread_ids() -> Option<Vec<u64>> {
    None
}

/// Laboratory process primitives (stop-flag signal handler, backlog-0 listener): feature `lab`,
/// enabled only by `rmasscan-lab`, never by a product consumer.
#[cfg(feature = "lab")]
pub mod lab_io;
