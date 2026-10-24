//! Настоящий загрузчик на WinAPI: `LoadLibraryExW`/`GetProcAddress`/
//! `FreeLibrary` без libloading. Компилируется только на Windows.
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

/// MAC адаптера ОС по GUID `{...}` (`GetAdaptersAddresses`); `None`, если
/// адаптера нет или вызов не удался. Только чтение системного состояния.
pub(crate) fn adapter_mac_by_guid(guid: &str) -> Option<[u8; 6]> {
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 32 * 1024;
    // u64: выравнивание 8, как требует IP_ADAPTER_ADDRESSES_LH.
    let mut buf: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
    for _ in 0..4 {
        // SAFETY: buf имеет не менее `size` байт и выровнен по 8; size это
        // входной/выходной параметр API; reserved обязан быть NULL.
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                std::ptr::null(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if rc == ERROR_BUFFER_OVERFLOW {
            buf = vec![0; (size as usize).div_ceil(8)];
            continue;
        }
        if rc != 0 {
            return None;
        }
        let mut p = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !p.is_null() {
            // SAFETY: p указывает на узел списка внутри buf (заполнен API,
            // buf жив); Next ведёт в тот же буфер или NULL.
            let a = unsafe { &*p };
            if !a.AdapterName.is_null() {
                // SAFETY: AdapterName это NUL-терминированная строка внутри buf.
                let name = unsafe { std::ffi::CStr::from_ptr(a.AdapterName.cast()) };
                if name.to_string_lossy().eq_ignore_ascii_case(guid) && a.PhysicalAddressLength == 6
                {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&a.PhysicalAddress[..6]);
                    return Some(mac);
                }
            }
            p = a.Next;
        }
        return None;
    }
    None
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
