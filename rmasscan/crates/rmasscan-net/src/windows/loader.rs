//! Безопасная загрузка Npcap: шов загрузчика, владение библиотекой и
//! диагностика загруженных DLL.
//!
//! Правила:
//! - только полный путь `<GetSystemDirectoryW>\Npcap\wpcap.dll`; cwd, PATH и
//!   каталог EXE не участвуют (флаги поиска задаёт `sys`);
//! - библиотека живёт в `Arc<NpcapApi>`; каждый [`super::handle::PcapHandle`]
//!   держит свой `Arc`, поэтому `FreeLibrary` выполняется после `pcap_close`
//!   последнего handle;
//! - Npcap не скачивается и не устанавливается: отсутствие DLL это ошибка
//!   `DriverUnavailable` с текстом, а не действие.
//!
//! Send/Sync. `PcapFns` это набор `fn`-указателей без состояния, а
//! [`Module`] требует `Send + Sync`, значит `NpcapApi` автоматически
//! `Send + Sync` без единого `unsafe impl`. Эта неизменяемая таблица
//! безопасна для общего доступа, потому что сами функции libpcap
//! потокобезопасны только для РАЗНЫХ `pcap_t`; единственный изменяемый
//! объект, `pcap_t`, принадлежит одному владельцу (см. `handle`).

use std::ffi::{CStr, c_void};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::ffi::{PcapFns, REQUIRED_SYMBOLS};
use crate::NetError;

/// Причина неудачной загрузки DLL (классифицирует `sys`/фейк).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LoadFailure {
    /// Файла (или его зависимости) нет.
    NotFound(String),
    /// Неверный формат образа: другая архитектура (ERROR_BAD_EXE_FORMAT).
    BadImage(String),
    /// Любая другая ошибка ОС.
    Other(String),
}

/// Загруженный модуль. `Drop` обязан выгрузить библиотеку (`FreeLibrary`).
///
/// # Safety
/// Реализация гарантирует: `symbol` возвращает `Some(p)` только для реального
/// экспорта загруженной библиотеки под этим именем, с сигнатурой, объявленной в
/// `ffi` для такого имени, и `p` остаётся действительным, пока жив модуль.
/// Нулевой адрес допустим (трактуется как отсутствие), мусорный нет.
pub(crate) unsafe trait Module: Send + Sync {
    /// Адрес экспорта или `None`.
    fn symbol(&self, name: &CStr) -> Option<*const c_void>;
    /// Пути, версии и хэши реально загруженных wpcap/Packet DLL.
    fn describe(&self) -> Result<Vec<DllInfo>, NetError>;
}

/// Шов загрузчика: настоящий (`sys::OsLoader`) или подставной.
pub(crate) trait Loader {
    /// Загружает DLL по ПОЛНОМУ пути.
    fn load(&self, full_path: &str) -> Result<Box<dyn Module>, LoadFailure>;
}

/// Диагностика одной загруженной DLL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DllInfo {
    pub name: String,
    /// Путь, который ОС сообщает для загруженного модуля.
    pub path: String,
    pub sha256: String,
    /// `major.minor.build.revision` из VS_FIXEDFILEINFO, если есть.
    pub version: Option<String>,
}

/// Владелец загруженной библиотеки и таблицы функций.
pub(crate) struct NpcapApi {
    pub(crate) fns: PcapFns,
    version: String,
    diagnostics: Vec<DllInfo>,
    // Последним: выгрузка библиотеки после всего остального.
    _module: Box<dyn Module>,
}

impl std::fmt::Debug for NpcapApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NpcapApi")
            .field("version", &self.version)
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

/// Каталог Npcap относительно системного: `<sys>\Npcap\wpcap.dll`. Системный
/// каталог обязан быть абсолютным (`X:\...` или `\\server\...`); иначе это
/// не ответ WinAPI и грузить по нему нельзя.
pub(crate) fn npcap_dll_path(system_dir: &str) -> Result<String, NetError> {
    let b = system_dir.as_bytes();
    let drive = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    let unc = system_dir.starts_with("\\\\") && b.len() > 2;
    if !(drive || unc) || system_dir.contains('\0') {
        return Err(NetError::DriverUnavailable(format!(
            "system directory is not an absolute path: {system_dir:?}"
        )));
    }
    let base = system_dir.trim_end_matches('\\');
    Ok(format!("{base}\\Npcap\\wpcap.dll"))
}

/// Требует, чтобы реально загруженный wpcap.dll лежал по запрошенному полному
/// пути, а Packet.dll был загружен из того же каталога. Отсутствие любой из
/// двух DLL или иной путь это отказ (подмена/неполная установка).
pub(crate) fn verify_diagnostics(requested: &str, infos: &[DllInfo]) -> Result<(), NetError> {
    let wpcap = infos
        .iter()
        .find(|d| d.name == "wpcap.dll")
        .ok_or_else(|| {
            NetError::DriverUnavailable("wpcap.dll missing from loaded module diagnostics".into())
        })?;
    if !wpcap.path.eq_ignore_ascii_case(requested) {
        return Err(NetError::DriverUnavailable(format!(
            "wpcap.dll was loaded from {}, requested {requested}",
            wpcap.path
        )));
    }
    let dir = wpcap
        .path
        .rsplit_once('\\')
        .map(|(d, _)| d)
        .unwrap_or_default();
    let expected = format!("{dir}\\Packet.dll");
    let packet = infos.iter().find(|d| d.name == "Packet.dll").ok_or_else(|| {
        NetError::DriverUnavailable(format!(
            "Packet.dll is not loaded (expected {expected}); the Npcap installation is incomplete or Packet.dll would be resolved lazily"
        ))
    })?;
    if !packet.path.eq_ignore_ascii_case(&expected) {
        return Err(NetError::DriverUnavailable(format!(
            "Packet.dll was loaded from {}, expected {expected}",
            packet.path
        )));
    }
    Ok(())
}

/// SHA-256 в нижнем регистре hex.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for byte in digest.iter() {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

impl NpcapApi {
    /// Загружает `full_path` через `loader`, разрешает ВСЕ символы и проверяет
    /// `pcap_lib_version`. При любой ошибке модуль выгружается (Drop).
    pub(crate) fn load_with(
        loader: &dyn Loader,
        full_path: &str,
    ) -> Result<Arc<NpcapApi>, NetError> {
        let module = loader.load(full_path).map_err(|f| match f {
            LoadFailure::NotFound(m) => NetError::DriverUnavailable(format!(
                "Npcap is not installed or incomplete ({full_path}): {m}. \
                 Install Npcap from https://npcap.com manually; rmasscan never installs it"
            )),
            LoadFailure::BadImage(m) => NetError::AbiMismatch(format!(
                "{full_path} has the wrong architecture for this x86_64 build: {m}"
            )),
            LoadFailure::Other(m) => {
                NetError::DriverUnavailable(format!("cannot load {full_path}: {m}"))
            }
        })?;
        let mut lookup = |name: &str| -> Option<*const c_void> {
            let c = std::ffi::CString::new(name).ok()?;
            module.symbol(&c).filter(|p| !p.is_null())
        };
        let fns = PcapFns::resolve(&mut lookup).map_err(|missing| {
            NetError::MissingCapability(format!(
                "wpcap.dll lacks required exports: {} (of {} required)",
                missing.join(", "),
                REQUIRED_SYMBOLS.len()
            ))
        })?;
        // SAFETY: lib_version разрешён из wpcap.dll, не принимает аргументов и
        // возвращает указатель на статическую строку библиотеки или NULL.
        let p = unsafe { (fns.lib_version)() };
        if p.is_null() {
            return Err(NetError::DriverUnavailable(
                "pcap_lib_version returned NULL: Npcap did not initialize".into(),
            ));
        }
        // SAFETY: p не NULL и указывает на NUL-терминированную статическую
        // строку внутри загруженной DLL, которая жива (module владеет ею).
        let version = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        let diagnostics = module.describe()?;
        verify_diagnostics(full_path, &diagnostics)?;
        Ok(Arc::new(NpcapApi {
            fns,
            version,
            diagnostics,
            _module: module,
        }))
    }

    /// Строка `pcap_lib_version` (например «Npcap version 1.90, based on libpcap 1.10.7»).
    pub(crate) fn lib_version(&self) -> &str {
        &self.version
    }

    pub(crate) fn diagnostics(&self) -> &[DllInfo] {
        &self.diagnostics
    }
}
