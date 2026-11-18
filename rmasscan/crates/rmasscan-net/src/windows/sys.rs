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
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    ERROR_BAD_EXE_FORMAT, ERROR_FILE_NOT_FOUND, ERROR_HOST_UNREACHABLE, ERROR_MOD_NOT_FOUND,
    ERROR_NETWORK_UNREACHABLE, ERROR_NOT_FOUND, ERROR_PATH_NOT_FOUND, FreeLibrary, GetLastError,
    NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
use windows_sys::Win32::Networking::WinSock::{ADDRESS_FAMILY, SOCKADDR_INET};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleW, GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

use super::ffi::WaitFn;
use super::loader::{
    ApiSlot, DllInfo, LoadFailure, Loader, Module, NpcapApi, npcap_dll_path, sha256_hex,
};
use crate::NetError;
use crate::route_parse::{Fwd, Fwd6, WinAdapter};

/// Переписывает на месте четыре байта BOOLEAN строки `MIB_IPFORWARD_ROW2` по сырому указателю `$row` в 0/1
/// (`u8::from(байт != 0)`): `windows-sys` объявляет `Loopback`, `AutoconfigureAddress`, `Publish` и `Immortal` как
/// `bool`, а IP Helper не обещает 0/1. Ни ссылки на строку, ни `bool` не создаётся. Только внутри `unsafe`: `$row`
/// указывает на строку в записываемой памяти, на которую нет живых ссылок.
macro_rules! canonical_booleans {
    ($row:expr) => {{
        let row: *mut windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2 = $row;
        for byte in [
            (&raw mut (*row).Loopback).cast::<u8>(),
            (&raw mut (*row).AutoconfigureAddress).cast::<u8>(),
            (&raw mut (*row).Publish).cast::<u8>(),
            (&raw mut (*row).Immortal).cast::<u8>(),
        ] {
            byte.write(u8::from(byte.read() != 0));
        }
    }};
}

mod observation;
pub(crate) use observation::{adapters_until, interfaces_until};
mod route_table;
use route_table::{MibTable, TableMemory, walk_table};

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
    // Длина массива 512 (тип) помещается в `u32`.
    let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    // SAFETY: buf валиден на 512 элементов, длина передана верно.
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), cap) };
    let n = usize::try_from(n).unwrap_or(usize::MAX);
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

impl OsModule {
    /// `HMODULE` из числа: обратный перевод `expose_provenance` в `OsLoader::load`, равносилен прежнему `as`.
    fn hmodule(&self) -> *mut c_void {
        std::ptr::with_exposed_provenance_mut(self.handle)
    }
}

// SAFETY: symbol() отдаёт только результат GetProcAddress живого HMODULE
// (реальный экспорт; выгрузка лишь в Drop), нулевой результат это None.
// wait_object() отдаёт сам `WaitForSingleObject` из kernel32: контракт трейта и есть его контракт.
unsafe impl Module for OsModule {
    fn symbol(&self, name: &CStr) -> Option<*const c_void> {
        // SAFETY: handle это живой HMODULE (выгрузка только в Drop), name
        // NUL-терминирован.
        let p = unsafe { GetProcAddress(self.hmodule(), name.as_ptr().cast()) };
        // Указатель на функцию в указатель данных переводится только `as` (иначе `transmute`); адрес тот же.
        p.map(|f| f as *const c_void)
    }

    fn describe(&self) -> Result<Vec<DllInfo>, NetError> {
        let wpcap_path = module_path(self.hmodule())?;
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

    fn wait_object(&self) -> WaitFn {
        WaitForSingleObject
    }
}

impl Drop for OsModule {
    fn drop(&mut self) {
        // SAFETY: handle получен из LoadLibraryExW и освобождается ровно один раз.
        unsafe { FreeLibrary(self.hmodule()) };
    }
}

fn module_path(h: *mut c_void) -> Result<String, NetError> {
    let mut buf = vec![0u16; 1024];
    // Длина 1024 (строка выше) помещается в `u32`.
    let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    // SAFETY: buf валиден на 1024 элемента; h это живой модуль.
    let n = unsafe { GetModuleFileNameW(h, buf.as_mut_ptr(), cap) };
    let n = usize::try_from(n).unwrap_or(usize::MAX);
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
    let mut buf = vec![0u8; usize::try_from(size).ok()?];
    // SAFETY: buf имеет ровно size байт.
    if unsafe { GetFileVersionInfoW(w.as_ptr(), 0, size, buf.as_mut_ptr().cast()) } == 0 {
        return None;
    }
    let mut p: *mut c_void = std::ptr::null_mut();
    let mut len = 0u32;
    let root = wide("\\");
    // SAFETY: buf это ресурс версии, root NUL-терминирован, p/len выходные.
    let ok = unsafe { VerQueryValueW(buf.as_ptr().cast(), root.as_ptr(), &mut p, &mut len) };
    if ok == 0
        || p.is_null()
        || usize::try_from(len).unwrap_or(usize::MAX) < std::mem::size_of::<VS_FIXEDFILEINFO>()
    {
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
        // `iSockaddrLength` это i32: отрицательная длина не годится (`as usize` дал бы огромное значение).
        if !sa.is_null()
            && usize::try_from(u.Address.iSockaddrLength)
                .is_ok_and(|len| len >= std::mem::size_of::<SOCKADDR_IN>())
        {
            // SAFETY: sa не null и указывает на iSockaddrLength >= sizeof(SOCKADDR_IN)
            // байт (длина неотрицательна) внутри буфера; read_unaligned не предполагает выравнивания.
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

/// Метки вызовов IP Helper в тексте [`iphlp_error`], по одной на место вызова.
const FWD4_LABEL: &str = "GetIpForwardTable2";
const FWD6_LABEL: &str = "GetIpForwardTable2(AF_INET6)";
const BEST4_LABEL: &str = "GetBestRoute2";
const BEST6_LABEL: &str = "GetBestRoute2(AF_INET6)";

/// Ошибка вызова IP Helper `label` с кодом `e`: единственное место текста `{label} error {e}`.
fn iphlp_error(label: &str, e: u32) -> NetError {
    NetError::System(format!("{label} error {e}"))
}

/// Строка `MIB_IPFORWARD_ROW2` → [`Fwd`]; `mib_loopback` это флаг `Loopback` строки, `loopback_if` здесь всегда
/// `false` (IfType 24 отмечает `route_parse::mark_loopback`).
fn fwd_from_row(row: &MIB_IPFORWARD_ROW2) -> Fwd {
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    // SAFETY: SOCKADDR_INET это объединение с общим полем si_family; вариант Ipv4 читается только при AF_INET, его
    // адрес это целое (объединение целых представлений одного u32).
    let next_hop = unsafe {
        if row.NextHop.si_family == AF_INET {
            Ipv4Addr::from(row.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes())
        } else {
            Ipv4Addr::UNSPECIFIED
        }
    };
    Fwd {
        ifindex: row.InterfaceIndex,
        prefix_len: row.DestinationPrefix.PrefixLength,
        next_hop,
        metric: row.Metric,
        mib_loopback: row.Loopback,
        loopback_if: false,
    }
}

/// Один `GetBestRoute2` к `to`: строка маршрута и `BestSourceAddress`; `None`, если маршрута нет
/// (`ERROR_NOT_FOUND`/`ERROR_NETWORK_UNREACHABLE`/`ERROR_HOST_UNREACHABLE`), иначе текст с меткой `label`. Только чтение.
fn best_route_raw(
    to: &SOCKADDR_INET,
    label: &str,
) -> Result<Option<(MIB_IPFORWARD_ROW2, SOCKADDR_INET)>, NetError> {
    let mut row = std::mem::MaybeUninit::<MIB_IPFORWARD_ROW2>::zeroed();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: `to` и `source` живые объекты своих типов, `row` это обнулённый буфер ровно этого типа; NULL
    // InterfaceLuid и SourceAddress (индекс 0) документированы как необязательные.
    let rc = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            to,
            0,
            row.as_mut_ptr(),
            &mut source,
        )
    };
    match rc {
        NO_ERROR => {}
        ERROR_NOT_FOUND | ERROR_NETWORK_UNREACHABLE | ERROR_HOST_UNREACHABLE => return Ok(None),
        e => return Err(iphlp_error(label, e)),
    }
    // SAFETY: все байты `row` инициализированы (обнулены, затем записаны API), на `row` нет ссылок; четыре байта
    // BOOLEAN переписаны в 0/1 через сырой указатель до любого типизированного чтения, остальные поля это целые и
    // объединения целых, так что строка допустима как `MIB_IPFORWARD_ROW2`.
    let row = unsafe {
        canonical_booleans!(row.as_mut_ptr());
        row.assume_init()
    };
    Ok(Some((row, source)))
}

/// Лучший маршрут к `dst` (`GetBestRoute2`); `None`, если маршрута нет
/// (`ERROR_NOT_FOUND`/`ERROR_NETWORK_UNREACHABLE`/`ERROR_HOST_UNREACHABLE`). Только чтение.
pub(crate) fn best_route(dst: Ipv4Addr) -> Result<Option<Fwd>, NetError> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, IN_ADDR, IN_ADDR_0, SOCKADDR_IN};

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
    Ok(best_route_raw(&to, BEST4_LABEL)?.map(|(row, _)| fwd_from_row(&row)))
}

/// Synchronous IP Helper route query. The absolute deadline and cancellation
/// are checked before and after WinAPI; the OS call itself cannot be interrupted.
pub(crate) fn best_route_until(
    dst: Ipv4Addr,
    deadline: std::time::Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Option<Fwd>, NetError> {
    crate::network_plan::check_observation(deadline, cancelled)?;
    let result = best_route(dst);
    crate::network_plan::check_observation(deadline, cancelled)?;
    result
}

/// Адреса IPv6 списка `FirstUnicastAddress` по порядку с их `DadState` (`NL_DAD_STATE`).
fn unicast_v6(
    mut p: *mut windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH,
) -> Vec<(Ipv6Addr, i32)> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6};

    let mut out = Vec::new();
    while !p.is_null() {
        // SAFETY: p это узел списка unicast внутри живого буфера адаптеров; Next ведёт в тот же буфер или NULL; в
        // узле только целые, объединения целых и указатели.
        let u = unsafe { &*p };
        let sa = u.Address.lpSockaddr;
        if !sa.is_null()
            && usize::try_from(u.Address.iSockaddrLength)
                .is_ok_and(|len| len >= std::mem::size_of::<SOCKADDR_IN6>())
        {
            // SAFETY: sa не null и указывает на iSockaddrLength >= sizeof(SOCKADDR_IN6) байт (длина неотрицательна)
            // внутри буфера; read_unaligned не предполагает выравнивания.
            let sin6 = unsafe { sa.cast::<SOCKADDR_IN6>().read_unaligned() };
            if sin6.sin6_family == AF_INET6 {
                // SAFETY: IN6_ADDR это объединение целых представлений одних 16 байт.
                let bytes = unsafe { sin6.sin6_addr.u.Byte };
                out.push((Ipv6Addr::from(bytes), u.DadState));
            }
        }
        p = u.Next;
    }
    out
}

/// Адаптер `GetAdaptersAddresses(AF_INET6)`: `AdapterName` (`{GUID}`) и его адреса IPv6 с `DadState` по порядку.
pub(crate) struct Adapter6 {
    pub name: String,
    pub addrs: Vec<(Ipv6Addr, i32)>,
}

/// Адреса IPv6 адаптеров (`GetAdaptersAddresses(AF_INET6)`, как C `rawsock-getip6.c:114-119`). Только чтение;
/// адаптеров без IPv6 нет в списке.
pub(crate) fn adapters6() -> Result<Vec<Adapter6>, NetError> {
    use windows_sys::Win32::Networking::WinSock::AF_INET6;

    let Some(buf) = adapters_buffer(u32::from(AF_INET6))
        .map_err(|e| NetError::System(format!("GetAdaptersAddresses(AF_INET6) error {e}")))?
    else {
        return Ok(Vec::new());
    };
    Ok(adapter_nodes(&buf)
        .into_iter()
        .map(|a| Adapter6 {
            name: ansi_string(a.AdapterName).unwrap_or_default(),
            addrs: unicast_v6(a.FirstUnicastAddress),
        })
        .collect())
}

/// Строка `MIB_IPFORWARD_ROW2` IPv6 → [`Fwd6`] (как [`fwd_from_row`]).
fn fwd6_from_row(row: &MIB_IPFORWARD_ROW2) -> Fwd6 {
    use windows_sys::Win32::Networking::WinSock::AF_INET6;

    // SAFETY: SOCKADDR_INET это объединение с общим полем si_family; вариант Ipv6 читается только при AF_INET6, его
    // адрес это 16 байт целых.
    let next_hop = unsafe {
        if row.NextHop.si_family == AF_INET6 {
            Ipv6Addr::from(row.NextHop.Ipv6.sin6_addr.u.Byte)
        } else {
            Ipv6Addr::UNSPECIFIED
        }
    };
    Fwd6 {
        ifindex: row.InterfaceIndex,
        prefix_len: row.DestinationPrefix.PrefixLength,
        next_hop,
        metric: row.Metric,
        mib_loopback: row.Loopback,
        loopback_if: false,
    }
}

/// Лучший маршрут IPv6 к `dst` (`GetBestRoute2` `AF_INET6`) и `BestSourceAddress`; `None`, если маршрута нет. Только
/// чтение.
pub(crate) fn best_route6(dst: Ipv6Addr) -> Result<Option<(Fwd6, Option<Ipv6Addr>)>, NetError> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6};

    let sin6 = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 { Byte: dst.octets() },
        },
        ..Default::default()
    };
    // Как у `best_route` (IPv4): объединение пишется полем, остальные байты нулевые.
    let mut to = SOCKADDR_INET::default();
    to.Ipv6 = sin6;
    let Some((row, source)) = best_route_raw(&to, BEST6_LABEL)? else {
        return Ok(None);
    };
    // SAFETY: SOCKADDR_INET это объединение с общим полем si_family; вариант Ipv6 читается только при AF_INET6, его
    // адрес это 16 байт целых.
    let best_source = unsafe {
        if source.si_family == AF_INET6 {
            Some(Ipv6Addr::from(source.Ipv6.sin6_addr.u.Byte))
        } else {
            None
        }
    };
    Ok(Some((fwd6_from_row(&row), best_source)))
}

/// Все строки `GetIpForwardTable2(family)` через `decode` по порядку таблицы; `ERROR_NOT_FOUND` и пустой указатель
/// это пустой список, иначе текст с меткой `label`. Байты BOOLEAN строк приводятся к 0/1 до чистого обхода
/// ([`TableMemory::table`]). Только чтение ОС.
fn forward_rows<T>(
    family: ADDRESS_FAMILY,
    label: &str,
    decode: fn(&MIB_IPFORWARD_ROW2) -> T,
) -> Result<Vec<T>, NetError> {
    let Some(mut table) = MibTable::get(family).map_err(|e| iphlp_error(label, e))? else {
        return Ok(Vec::new());
    };
    Ok(walk_table(table.table(), decode))
}

/// Все маршруты IPv4 (`GetIpForwardTable2(AF_INET)`). Только чтение.
pub(crate) fn forward_table() -> Result<Vec<Fwd>, NetError> {
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    forward_rows(AF_INET, FWD4_LABEL, fwd_from_row)
}

/// Все маршруты IPv6 (`GetIpForwardTable2(AF_INET6)`). Только чтение.
pub(crate) fn forward_table6() -> Result<Vec<Fwd6>, NetError> {
    use windows_sys::Win32::Networking::WinSock::AF_INET6;

    forward_rows(AF_INET6, FWD6_LABEL, fwd6_from_row)
}

/// Версия ОС `major.minor.build[.revision]`. `RtlGetVersion` не подвержена
/// «обману» совместимости (GetFileVersionInfo у процесса без манифеста отдаёт
/// 6.2); ревизия (UBR) берётся из версии kernel32.dll, если номер сборки
/// совпал.
pub(crate) fn os_version() -> Option<String> {
    use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
    use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;

    /// `dwOSVersionInfoSize`: размер структуры как `DWORD`.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the assert proves that the size fits u32"
    )]
    const OSVERSIONINFOW_SIZE: u32 = {
        assert!(std::mem::size_of::<OSVERSIONINFOW>() <= 0xFFFF_FFFF);
        std::mem::size_of::<OSVERSIONINFOW>() as u32
    };
    // SAFETY: структура из нулей допустима для OSVERSIONINFOW (целые и массив u16).
    let mut v: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
    v.dwOSVersionInfoSize = OSVERSIONINFOW_SIZE;
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
    Some(match rev {
        Some(r) => format!("{base}.{r}"),
        None => base,
    })
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
        Ok(Box::new(OsModule {
            handle: h.expose_provenance(),
        }))
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
    use super::route_table::{RawTable, SyntheticTable, synthetic};
    use super::*;

    #[test]
    fn nonexistent_full_path_is_driver_unavailable() {
        let e = NpcapApi::load_with(&OsLoader, "C:\\rmasscan-no-such-dir\\Npcap\\wpcap.dll")
            .unwrap_err();
        assert!(matches!(e, NetError::DriverUnavailable(_)), "{e:?}");
    }

    /// Узел unicast с отрицательной или короткой `iSockaddrLength` пропускается, адрес не читается.
    #[test]
    fn unicast_with_negative_or_short_sockaddr_length_is_skipped() {
        use windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH;
        use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR, SOCKADDR_IN};

        let mut sin = SOCKADDR_IN {
            sin_family: AF_INET,
            ..Default::default()
        };
        sin.sin_addr.S_un.S_addr = u32::from_ne_bytes([198, 18, 0, 1]);
        let full = i32::try_from(std::mem::size_of::<SOCKADDR_IN>()).unwrap();
        let mut node = IP_ADAPTER_UNICAST_ADDRESS_LH::default();
        node.Address.lpSockaddr = (&raw mut sin).cast::<SOCKADDR>();
        node.Address.iSockaddrLength = full;
        assert_eq!(
            unicast_v4(&raw mut node),
            vec![Ipv4Addr::new(198, 18, 0, 1)]
        );
        for len in [-1, i32::MIN, 0, full - 1] {
            node.Address.iSockaddrLength = len;
            assert!(
                unicast_v4(&raw mut node).is_empty(),
                "iSockaddrLength {len}"
            );
        }
    }

    /// The four IP Helper call labels and their error texts are the base texts byte for byte.
    #[test]
    fn iphlp_labels_are_byte_identical() {
        assert_eq!(
            [FWD4_LABEL, FWD6_LABEL, BEST4_LABEL, BEST6_LABEL],
            [
                "GetIpForwardTable2",
                "GetIpForwardTable2(AF_INET6)",
                "GetBestRoute2",
                "GetBestRoute2(AF_INET6)"
            ]
        );
        for (label, text) in [
            (FWD4_LABEL, "system error: GetIpForwardTable2 error 5"),
            (
                FWD6_LABEL,
                "system error: GetIpForwardTable2(AF_INET6) error 5",
            ),
            (BEST4_LABEL, "system error: GetBestRoute2 error 5"),
            (BEST6_LABEL, "system error: GetBestRoute2(AF_INET6) error 5"),
        ] {
            assert_eq!(iphlp_error(label, 5).to_string(), text, "{label}");
        }
    }

    /// The pure walk behind `forward_rows` reads `NumEntries` rows from `Table[0]` (a third row past the header's
    /// count is never decoded) and decodes each family: the gateway only when `NextHop` has the row's family,
    /// `Loopback` as is, `loopback_if` always false.
    #[test]
    fn forward_rows_decode_a_synthetic_table_for_both_families() {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            IP_ADDRESS_PREFIX, MIB_IPFORWARD_ROW2,
        };
        use windows_sys::Win32::Networking::WinSock::{
            AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
        };

        let row = |ifindex: u32, prefix_len: u8, metric: u32, loopback: bool| MIB_IPFORWARD_ROW2 {
            InterfaceIndex: ifindex,
            DestinationPrefix: IP_ADDRESS_PREFIX {
                PrefixLength: prefix_len,
                ..Default::default()
            },
            Metric: metric,
            Loopback: loopback,
            ..Default::default()
        };
        let via4 = |r: &mut MIB_IPFORWARD_ROW2, gw: Ipv4Addr| {
            r.NextHop.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(gw.octets()),
                    },
                },
                ..Default::default()
            };
        };
        let via6 = |r: &mut MIB_IPFORWARD_ROW2, gw: Ipv6Addr| {
            r.NextHop.Ipv6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: gw.octets() },
                },
                ..Default::default()
            };
        };

        // IPv4: a default route via a gateway, an on-link /32 with `Loopback` (NextHop of no family), and a third row
        // past NumEntries.
        let mut r0 = row(7, 0, 25, false);
        via4(&mut r0, Ipv4Addr::new(198, 51, 100, 1));
        let r1 = row(1, 32, 256, true);
        let mut r2 = row(99, 8, 1, false);
        via4(&mut r2, Ipv4Addr::new(203, 0, 113, 9));
        let v4 = SyntheticTable {
            num_entries: 2,
            rows: [r0, r1, r2],
        };
        assert_eq!(
            walk_table(synthetic(&v4), fwd_from_row),
            vec![
                Fwd {
                    ifindex: 7,
                    prefix_len: 0,
                    next_hop: Ipv4Addr::new(198, 51, 100, 1),
                    metric: 25,
                    mib_loopback: false,
                    loopback_if: false,
                },
                Fwd {
                    ifindex: 1,
                    prefix_len: 32,
                    next_hop: Ipv4Addr::UNSPECIFIED,
                    metric: 256,
                    mib_loopback: true,
                    loopback_if: false,
                },
            ]
        );

        // IPv6: a default route via a gateway, a /128 with `Loopback` whose NextHop is IPv4 (not the row's family), and
        // a third row past NumEntries.
        let mut r0 = row(12, 0, 10, false);
        via6(&mut r0, "2001:db8::1".parse().unwrap());
        let mut r1 = row(1, 128, 256, true);
        via4(&mut r1, Ipv4Addr::new(198, 51, 100, 2));
        let mut r2 = row(99, 64, 1, false);
        via6(&mut r2, "2001:db8::9".parse().unwrap());
        let v6 = SyntheticTable {
            num_entries: 2,
            rows: [r0, r1, r2],
        };
        assert_eq!(
            walk_table(synthetic(&v6), fwd6_from_row),
            vec![
                Fwd6 {
                    ifindex: 12,
                    prefix_len: 0,
                    next_hop: "2001:db8::1".parse().unwrap(),
                    metric: 10,
                    mib_loopback: false,
                    loopback_if: false,
                },
                Fwd6 {
                    ifindex: 1,
                    prefix_len: 128,
                    next_hop: Ipv6Addr::UNSPECIFIED,
                    metric: 256,
                    mib_loopback: true,
                    loopback_if: false,
                },
            ]
        );

        // An empty table decodes to nothing.
        let empty = SyntheticTable {
            num_entries: 0,
            rows: [row(5, 0, 1, false)],
        };
        assert!(walk_table(synthetic(&empty), fwd_from_row).is_empty());
    }

    /// BOOLEAN bytes other than 0/1 (2, 0xFF and others) are rewritten to 0/1 in place before any typed row exists, so
    /// `Loopback` decodes as `byte != 0`, as the base read it; all four BOOLEAN fields of every row are normalised. The
    /// rows are composed from raw bytes: no `bool` ever holds an invalid value.
    #[test]
    fn route_rows_with_non_canonical_boolean_bytes_decode_loopback_as_true() {
        use std::mem::offset_of;
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            MIB_IPFORWARD_ROW2 as Row, MIB_IPFORWARD_TABLE2,
        };

        let head = offset_of!(MIB_IPFORWARD_TABLE2, Table);
        let size = size_of::<Row>();
        let at = |row: usize, field: usize| head + row * size + field;
        let booleans = [
            offset_of!(Row, Loopback),
            offset_of!(Row, AutoconfigureAddress),
            offset_of!(Row, Publish),
            offset_of!(Row, Immortal),
        ];
        // Per row: InterfaceIndex, Metric and the four BOOLEAN bytes (Loopback first).
        let rows: [(u32, u32, [u8; 4]); 4] = [
            (10, 5, [2, 0x80, 1, 0]),
            (11, 6, [0xFF, 0, 0xFE, 7]),
            (12, 7, [0, 3, 0, 0x40]),
            (13, 8, [1, 1, 0xFF, 1]),
        ];
        let mut bytes = vec![0u8; head + rows.len() * size];
        bytes[..4].copy_from_slice(&u32::try_from(rows.len()).unwrap().to_ne_bytes());
        for (i, (ifindex, metric, flags)) in rows.iter().enumerate() {
            bytes[at(i, offset_of!(Row, InterfaceIndex))..][..4]
                .copy_from_slice(&ifindex.to_ne_bytes());
            bytes[at(i, offset_of!(Row, Metric))..][..4].copy_from_slice(&metric.to_ne_bytes());
            for (field, flag) in booleans.iter().zip(flags) {
                bytes[at(i, *field)] = *flag;
            }
        }

        let mut raw = RawTable::new(&bytes);
        let decoded = walk_table(raw.table(), fwd_from_row);
        let want: Vec<Fwd> = rows
            .iter()
            .map(|(ifindex, metric, flags)| Fwd {
                ifindex: *ifindex,
                prefix_len: 0,
                next_hop: Ipv4Addr::UNSPECIFIED,
                metric: *metric,
                mib_loopback: flags[0] != 0,
                loopback_if: false,
            })
            .collect();
        assert_eq!(decoded, want);
        assert_eq!(
            decoded.iter().map(|f| f.mib_loopback).collect::<Vec<_>>(),
            [true, true, false, true]
        );

        // In place: every BOOLEAN byte is now exactly `u8::from(byte != 0)`; nothing else changed.
        let after = raw.bytes();
        let mut expected = bytes.clone();
        for (i, (_, _, flags)) in rows.iter().enumerate() {
            for (field, flag) in booleans.iter().zip(flags) {
                expected[at(i, *field)] = u8::from(*flag != 0);
            }
        }
        assert_eq!(after[..expected.len()], expected[..]);
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
