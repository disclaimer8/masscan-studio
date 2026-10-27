//! Настоящий загрузчик на WinAPI: `LoadLibraryExW`/`GetProcAddress`/
//! `FreeLibrary` без libloading, а также чтение адаптеров и маршрутов IP Helper
//! для обнаружения (`adapters`, `best_route`, `forward_table`; только запросы).
//! Компилируется только на Windows.
//!
//! Безопасность загрузки:
//! - системный каталог берётся из `GetSystemDirectoryW`, а не из переменных
//!   окружения (`SystemRoot`, `PATH` игнорируются);
//! - грузится полный путь `<System32>\Npcap\wpcap.dll` с флагами
//!   `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`:
//!   зависимости (Packet.dll) ищутся только в каталоге самой wpcap.dll и в
//!   System32, но не в cwd, PATH или каталоге EXE;
//! - после загрузки проверяем, что Packet.dll пришёл именно из каталога
//!   wpcap.dll, и сохраняем пути, версии и SHA-256 обеих DLL.

use std::ffi::{CStr, c_void};
use std::net::Ipv4Addr;
use std::os::windows::ffi::OsStrExt;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    ERROR_BAD_EXE_FORMAT, ERROR_FILE_NOT_FOUND, ERROR_MOD_NOT_FOUND, ERROR_PATH_NOT_FOUND,
    FreeLibrary, GetLastError,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleW, GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

use super::loader::{
    ApiSlot, DllInfo, LoadFailure, Loader, Module, NpcapApi, npcap_dll_path, sha256_hex,
};
use crate::NetError;
use crate::route_parse::{Fwd, WinAdapter};

const SEARCH_FLAGS: u32 = LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32;

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

fn from_wide(buf: &[u16]) -> String {
    String::from_utf16_lossy(buf)
}

/// Системный каталог из WinAPI.
pub(crate) fn system_directory() -> Result<String, NetError> {
    let mut buf = [0u16; 512];
    // SAFETY: buf валиден на 512 элементов, длина передана верно.
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        // SAFETY: GetLastError без предусловий.
        let e = unsafe { GetLastError() };
        return Err(NetError::System(format!(
            "GetSystemDirectoryW failed (len {n}, error {e})"
        )));
    }
    Ok(from_wide(&buf[..n]))
}

/// Загруженный модуль. `HMODULE` хранится числом: сам по себе он не даёт
/// доступа к данным, а `Module` обязан быть `Send + Sync`.
struct OsModule {
    handle: usize,
}

// SAFETY: symbol() отдаёт только результат GetProcAddress живого HMODULE
// (реальный экспорт; выгрузка лишь в Drop), нулевой результат это None.
unsafe impl Module for OsModule {
    fn symbol(&self, name: &CStr) -> Option<*const c_void> {
        // SAFETY: handle это живой HMODULE (выгрузка только в Drop), name
        // NUL-терминирован.
        let p = unsafe { GetProcAddress(self.handle as *mut c_void, name.as_ptr().cast()) };
        p.map(|f| f as *const c_void)
    }

    fn describe(&self) -> Result<Vec<DllInfo>, NetError> {
        let wpcap_path = module_path(self.handle as *mut c_void)?;
        let mut out = vec![dll_info("wpcap.dll", &wpcap_path)?];
        let name = wide("Packet.dll");
        // SAFETY: name NUL-терминирована. GetModuleHandleW не увеличивает
        // счётчик ссылок и не загружает библиотеку.
        let h = unsafe { GetModuleHandleW(name.as_ptr()) };
        // Packet.dll может отсутствовать: тогда load_with (verify_diagnostics)
        // отказывает; здесь только сообщаем фактическое состояние.
        if !h.is_null() {
            out.push(dll_info("Packet.dll", &module_path(h)?)?);
        }
        Ok(out)
    }
}

impl Drop for OsModule {
    fn drop(&mut self) {
        // SAFETY: handle получен из LoadLibraryExW и освобождается ровно один раз.
        unsafe { FreeLibrary(self.handle as *mut c_void) };
    }
}

fn module_path(h: *mut c_void) -> Result<String, NetError> {
    let mut buf = vec![0u16; 1024];
    // SAFETY: buf валиден на 1024 элемента; h это живой модуль.
    let n = unsafe { GetModuleFileNameW(h, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return Err(NetError::System("GetModuleFileNameW failed".into()));
    }
    Ok(from_wide(&buf[..n]))
}

fn dll_info(name: &str, path: &str) -> Result<DllInfo, NetError> {
    let bytes = std::fs::read(path)
        .map_err(|e| NetError::System(format!("cannot read {path} for hashing: {e}")))?;
    Ok(DllInfo {
        name: name.into(),
        path: path.into(),
        sha256: sha256_hex(&bytes),
        version: file_version(path),
    })
}

pub(crate) fn file_version(path: &str) -> Option<String> {
    let w = wide(path);
    let mut dummy = 0u32;
    // SAFETY: w NUL-терминирована, dummy валидный выходной параметр.
    let size = unsafe { GetFileVersionInfoSizeW(w.as_ptr(), &mut dummy) };
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    // SAFETY: buf имеет ровно size байт.
    if unsafe { GetFileVersionInfoW(w.as_ptr(), 0, size, buf.as_mut_ptr().cast()) } == 0 {
        return None;
    }
    let mut p: *mut c_void = std::ptr::null_mut();
    let mut len = 0u32;
    let root = wide("\\");
    // SAFETY: buf это ресурс версии, root NUL-терминирован, p/len выходные.
    let ok = unsafe { VerQueryValueW(buf.as_ptr().cast(), root.as_ptr(), &mut p, &mut len) };
    if ok == 0 || p.is_null() || (len as usize) < std::mem::size_of::<VS_FIXEDFILEINFO>() {
        return None;
    }
    // SAFETY: p указывает внутрь buf, длина проверена; чтение без
    // предположений о выравнивании.
    let info = unsafe { std::ptr::read_unaligned(p.cast::<VS_FIXEDFILEINFO>()) };
    Some(format!(
        "{}.{}.{}.{}",
        info.dwFileVersionMS >> 16,
        info.dwFileVersionMS & 0xffff,
        info.dwFileVersionLS >> 16,
        info.dwFileVersionLS & 0xffff
    ))
}

/// Флаги `GetAdaptersAddresses`: адреса anycast/multicast и DNS не нужны.
const GAA_FLAGS: u32 = windows_sys::Win32::NetworkManagement::IpHelper::GAA_FLAG_SKIP_ANYCAST
    | windows_sys::Win32::NetworkManagement::IpHelper::GAA_FLAG_SKIP_MULTICAST
    | windows_sys::Win32::NetworkManagement::IpHelper::GAA_FLAG_SKIP_DNS_SERVER;

/// Буфер `GetAdaptersAddresses(family)`: выровнен по 8 (как требует `IP_ADAPTER_ADDRESSES_LH`), растёт по
/// `ERROR_BUFFER_OVERFLOW` до 4 попыток. `Ok(None)`: адаптеров нет (`ERROR_NO_DATA`); `Err(код)` иначе.
fn adapters_buffer(family: u32) -> Result<Option<Vec<u64>>, u32> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA};
    use windows_sys::Win32::NetworkManagement::IpHelper::GetAdaptersAddresses;

    let mut size: u32 = 32 * 1024;
    let mut buf: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
    for _ in 0..4 {
        // SAFETY: buf имеет не менее `size` байт и выровнен по 8; size это
        // входной/выходной параметр API; reserved обязан быть NULL.
        let rc = unsafe {
            GetAdaptersAddresses(
                family,
                GAA_FLAGS,
                std::ptr::null(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        match rc {
            0 => return Ok(Some(buf)),
            ERROR_BUFFER_OVERFLOW => buf = vec![0; (size as usize).div_ceil(8)],
            ERROR_NO_DATA => return Ok(None),
            e => return Err(e),
        }
    }
    Err(ERROR_BUFFER_OVERFLOW)
}

/// Узлы списка адаптеров внутри `buf`, заполненного [`adapters_buffer`].
fn adapter_nodes(
    buf: &[u64],
) -> Vec<&windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH> {
    use windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;

    let mut out = Vec::new();
    let mut p = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !p.is_null() {
        // SAFETY: p указывает на узел списка внутри buf (заполнен API, buf жив
        // дольше возвращаемых ссылок); Next ведёт в тот же буфер или NULL. В
        // узле только целые, массивы, объединения целых и указатели.
        let a = unsafe { &*p };
        out.push(a);
        p = a.Next;
    }
    out
}

/// NUL-терминированная строка ANSI внутри буфера адаптеров.
fn ansi_string(p: windows_sys::core::PSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: p не null и указывает на NUL-терминированную строку внутри буфера
    // адаптеров, который жив на время вызова; строка сразу копируется.
    Some(
        unsafe { CStr::from_ptr(p.cast()) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// NUL-терминированная строка UTF-16 внутри буфера адаптеров (не длиннее 1024 единиц).
fn wide_string(p: windows_sys::core::PWSTR) -> Option<String> {
    const MAX_UNITS: usize = 1024;
    if p.is_null() {
        return None;
    }
    let mut units = Vec::new();
    while units.len() < MAX_UNITS {
        // SAFETY: p указывает на NUL-терминированную строку UTF-16 внутри живого
        // буфера адаптеров; чтение останавливается на NUL, поэтому `p + len` не
        // выходит за строку.
        let c = unsafe { p.add(units.len()).read() };
        if c == 0 {
            break;
        }
        units.push(c);
    }
    Some(String::from_utf16_lossy(&units))
}

/// IPv4-адреса списка `FirstUnicastAddress` по порядку.
fn unicast_v4(
    mut p: *mut windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH,
) -> Vec<Ipv4Addr> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    let mut out = Vec::new();
    while !p.is_null() {
        // SAFETY: p это узел списка unicast внутри живого буфера адаптеров; Next
        // ведёт в тот же буфер или NULL; в узле только целые, объединения целых и указатели.
        let u = unsafe { &*p };
        let sa = u.Address.lpSockaddr;
        if !sa.is_null() && u.Address.iSockaddrLength as usize >= std::mem::size_of::<SOCKADDR_IN>()
        {
            // SAFETY: sa не null и указывает на iSockaddrLength >= sizeof(SOCKADDR_IN)
            // байт внутри буфера; read_unaligned не предполагает выравнивания.
            let sin = unsafe { sa.cast::<SOCKADDR_IN>().read_unaligned() };
            if sin.sin_family == AF_INET {
                // SAFETY: IN_ADDR это объединение целых представлений одного u32.
                let raw = unsafe { sin.sin_addr.S_un.S_addr };
                out.push(Ipv4Addr::from(raw.to_ne_bytes()));
            }
        }
        p = u.Next;
    }
    out
}

/// MAC адаптера ОС по GUID `{...}` (`GetAdaptersAddresses`); `None`, если
/// адаптера нет или вызов не удался. Только чтение системного состояния.
pub(crate) fn adapter_mac_by_guid(guid: &str) -> Option<[u8; 6]> {
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    let buf = adapters_buffer(u32::from(AF_UNSPEC)).ok()??;
    adapter_nodes(&buf).into_iter().find_map(|a| {
        let name = ansi_string(a.AdapterName)?;
        (name.eq_ignore_ascii_case(guid) && a.PhysicalAddressLength == 6).then(|| {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&a.PhysicalAddress[..6]);
            mac
        })
    })
}

/// Адаптеры IPv4 (`GetAdaptersAddresses(AF_INET)`), скопированные в безопасные типы. Только чтение.
pub(crate) fn adapters() -> Result<Vec<WinAdapter>, NetError> {
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let Some(buf) = adapters_buffer(u32::from(AF_INET))
        .map_err(|e| NetError::System(format!("GetAdaptersAddresses error {e}")))?
    else {
        return Ok(Vec::new());
    };
    Ok(adapter_nodes(&buf)
        .into_iter()
        .map(|a| {
            // SAFETY: оба варианта объединения это целые (`Alignment: u64` или
            // `{Length, IfIndex}`), любой образ битов допустим.
            let if_index = unsafe { a.Anonymous1.Anonymous.IfIndex };
            WinAdapter {
                if_index,
                if_type: a.IfType,
                oper_up: a.OperStatus == IfOperStatusUp,
                adapter_name: ansi_string(a.AdapterName).unwrap_or_default(),
                friendly_name: wide_string(a.FriendlyName).filter(|n| !n.is_empty()),
                mac: (a.PhysicalAddressLength == 6).then(|| {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&a.PhysicalAddress[..6]);
                    mac
                }),
                ipv4: unicast_v4(a.FirstUnicastAddress),
            }
        })
        .collect())
}

/// Строка `MIB_IPFORWARD_ROW2` → [`Fwd`]; `loopback` здесь только флаг строки (IfType 24 добавляет
/// `route_parse::mark_loopback`).
///
/// # Safety
/// `p` указывает на строку, заполненную IP Helper и живую на время вызова.
unsafe fn fwd_from_row(
    p: *const windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2,
) -> Fwd {
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    // SAFETY: по контракту функции p валиден. Поля читаются по месту, без копии
    // всей строки: целые как есть; объединение NextHop сначала по общему полю
    // si_family, затем как IPv4 (целые); BOOLEAN Loopback читается как u8, так что
    // значение, отличное от 0/1, никогда не читается как bool.
    unsafe {
        let next_hop = &raw const (*p).NextHop;
        let gateway = if (*next_hop).si_family == AF_INET {
            Ipv4Addr::from((*next_hop).Ipv4.sin_addr.S_un.S_addr.to_ne_bytes())
        } else {
            Ipv4Addr::UNSPECIFIED
        };
        Fwd {
            ifindex: (*p).InterfaceIndex,
            prefix_len: (*p).DestinationPrefix.PrefixLength,
            next_hop: gateway,
            metric: (*p).Metric,
            loopback: (&raw const (*p).Loopback).cast::<u8>().read() != 0,
        }
    }
}

/// Лучший маршрут к `dst` (`GetBestRoute2`); `None`, если маршрута нет
/// (`ERROR_NOT_FOUND`/`ERROR_NETWORK_UNREACHABLE`/`ERROR_HOST_UNREACHABLE`). Только чтение.
pub(crate) fn best_route(dst: Ipv4Addr) -> Result<Option<Fwd>, NetError> {
    use windows_sys::Win32::Foundation::{
        ERROR_HOST_UNREACHABLE, ERROR_NETWORK_UNREACHABLE, ERROR_NOT_FOUND, NO_ERROR,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, IN_ADDR, IN_ADDR_0, SOCKADDR_IN, SOCKADDR_INET,
    };

    let mut to = SOCKADDR_INET::default();
    to.Ipv4 = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(dst.octets()),
            },
        },
        sin_zero: [0; 8],
    };
    let mut row = std::mem::MaybeUninit::<MIB_IPFORWARD_ROW2>::zeroed();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: `to` и `source` живые локальные объекты; `row` это обнулённый
    // буфер ровно этого типа; NULL InterfaceLuid и SourceAddress (индекс 0)
    // документированы как необязательные.
    let rc = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &to,
            0,
            row.as_mut_ptr(),
            &mut source,
        )
    };
    match rc {
        NO_ERROR => {}
        ERROR_NOT_FOUND | ERROR_NETWORK_UNREACHABLE | ERROR_HOST_UNREACHABLE => return Ok(None),
        e => return Err(NetError::System(format!("GetBestRoute2 error {e}"))),
    }
    // SAFETY: при NO_ERROR API заполнил `row`, который жив до конца функции.
    Ok(Some(unsafe { fwd_from_row(row.as_ptr()) }))
}

/// Таблица IP Helper, освобождаемая `FreeMibTable` ровно один раз.
struct MibTable(*mut windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_TABLE2);

impl Drop for MibTable {
    fn drop(&mut self) {
        // SAFETY: указатель получен из успешного GetIpForwardTable2 (не null),
        // наружу не копируется и освобождается ровно один раз.
        unsafe { windows_sys::Win32::NetworkManagement::IpHelper::FreeMibTable(self.0.cast()) };
    }
}

/// Все маршруты IPv4 (`GetIpForwardTable2(AF_INET)`). Только чтение.
pub(crate) fn forward_table() -> Result<Vec<Fwd>, NetError> {
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetIpForwardTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let mut t: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: выходной указатель на живой локальный объект; при успехе API
    // выделяет таблицу, которую освобождает `MibTable`.
    let rc = unsafe { GetIpForwardTable2(AF_INET, &mut t) };
    match rc {
        NO_ERROR => {}
        ERROR_NOT_FOUND => return Ok(Vec::new()),
        e => return Err(NetError::System(format!("GetIpForwardTable2 error {e}"))),
    }
    if t.is_null() {
        return Ok(Vec::new());
    }
    let table = MibTable(t);
    // SAFETY: table.0 это таблица, выделенная API и живая до конца `table`;
    // NumEntries строк лежат подряд с `Table[0]` в том же выделении.
    let (n, base) = unsafe {
        (
            (*table.0).NumEntries as usize,
            (&raw const (*table.0).Table).cast::<MIB_IPFORWARD_ROW2>(),
        )
    };
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        // SAFETY: i < NumEntries, строка лежит внутри живого выделения таблицы.
        out.push(unsafe { fwd_from_row(base.add(i)) });
    }
    Ok(out)
}

/// Версия ОС `major.minor.build[.revision]`. `RtlGetVersion` не подвержена
/// «обману» совместимости (GetFileVersionInfo у процесса без манифеста отдаёт
/// 6.2); ревизия (UBR) берётся из версии kernel32.dll, если номер сборки
/// совпал.
pub(crate) fn os_version() -> Option<String> {
    use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
    use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;

    // SAFETY: структура из нулей допустима для OSVERSIONINFOW (целые и массив u16).
    let mut v: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
    v.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
    // SAFETY: v это валидная структура с заполненным размером.
    if unsafe { RtlGetVersion(&mut v) } != 0 {
        return None;
    }
    let base = format!(
        "{}.{}.{}",
        v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber
    );
    let rev = system_directory()
        .ok()
        .and_then(|d| file_version(&format!("{d}\\kernel32.dll")))
        .and_then(|f| {
            let p: Vec<&str> = f.split('.').collect();
            (p.len() == 4 && p[2] == v.dwBuildNumber.to_string()).then(|| p[3].to_string())
        });
    Some(rev.map_or(base.clone(), |r| format!("{base}.{r}")))
}

/// Настоящий загрузчик.
pub(crate) struct OsLoader;

impl Loader for OsLoader {
    fn load(&self, full_path: &str) -> Result<Box<dyn Module>, LoadFailure> {
        if full_path.contains('\0') {
            return Err(LoadFailure::Other("path contains NUL".into()));
        }
        let w = wide(full_path);
        // SAFETY: w NUL-терминирована; hfile обязан быть NULL.
        let h = unsafe { LoadLibraryExW(w.as_ptr(), std::ptr::null_mut(), SEARCH_FLAGS) };
        if h.is_null() {
            // SAFETY: GetLastError без предусловий, вызывается сразу после сбоя.
            let e = unsafe { GetLastError() };
            let msg = format!("LoadLibraryExW error {e}");
            return Err(match e {
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_MOD_NOT_FOUND => {
                    LoadFailure::NotFound(msg)
                }
                ERROR_BAD_EXE_FORMAT => LoadFailure::BadImage(msg),
                _ => LoadFailure::Other(msg),
            });
        }
        Ok(Box::new(OsModule { handle: h as usize }))
    }
}

static API: ApiSlot = ApiSlot::new();

impl NpcapApi {
    /// Загружает `<System32>\Npcap\wpcap.dll` один раз на процесс (пока жив
    /// хотя бы один владелец), без гонки на общем кэше версии.
    pub(crate) fn load() -> Result<Arc<NpcapApi>, NetError> {
        API.get_or_load(|| {
            let path = npcap_dll_path(&system_directory()?)?;
            NpcapApi::load_with(&OsLoader, &path)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonexistent_full_path_is_driver_unavailable() {
        let e = NpcapApi::load_with(&OsLoader, "C:\\rmasscan-no-such-dir\\Npcap\\wpcap.dll")
            .unwrap_err();
        assert!(matches!(e, NetError::DriverUnavailable(_)), "{e:?}");
    }

    #[test]
    fn system_directory_is_absolute_and_ends_in_system32() {
        let d = system_directory().unwrap();
        assert!(d.to_ascii_lowercase().ends_with("system32"), "{d}");
        assert!(npcap_dll_path(&d).unwrap().ends_with("\\Npcap\\wpcap.dll"));
    }

    #[test]
    fn load_without_or_with_npcap_never_panics_and_errors_are_expected() {
        match NpcapApi::load() {
            Ok(api) => assert!(!api.lib_version().is_empty()),
            Err(e) => assert!(
                matches!(
                    e,
                    NetError::DriverUnavailable(_) | NetError::MissingCapability(_)
                ),
                "{e:?}"
            ),
        }
    }

    /// Opt-in: реальный Npcap установлен. Пакеты не отправляются.
    /// `cargo test -p rmasscan-net -- --ignored live_npcap --nocapture`
    #[test]
    #[ignore = "needs Npcap installed"]
    fn live_npcap_loads_resolves_and_enumerates() {
        let api = NpcapApi::load().expect("Npcap must be installed");
        println!("version: {}", api.lib_version());
        for d in api.diagnostics() {
            println!("{d:#?}");
        }
        assert!(api.lib_version().contains("Npcap"));
        assert!(api.diagnostics().iter().any(|d| d.name == "wpcap.dll"));
        let devs = super::super::handle::list_devices(&api).unwrap();
        for d in &devs {
            println!("{d:?}");
        }
        assert!(!devs.is_empty());
        assert!(devs.iter().all(|d| d.name.starts_with("\\Device\\NPF_")));
        let first = &devs[0].name;
        let c = super::super::handle::resolve_device(&api, first).unwrap();
        assert_eq!(c.to_str().unwrap(), first);
    }
}
