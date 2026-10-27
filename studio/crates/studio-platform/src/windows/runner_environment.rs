//! Process-global policy for the dedicated elevated runner only; never call in UI.
use super::{Result, error};
use std::{
    ffi::OsString,
    os::windows::ffi::{OsStrExt, OsStringExt},
};
use windows_sys::Win32::System::{
    LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories},
    SystemInformation::{GetSystemDirectoryW, GetSystemWindowsDirectoryW},
};

pub(crate) fn directory(system: bool) -> Result<OsString> {
    let mut buffer = [0u16; 32768];
    // SAFETY: fixed-size writable UTF-16 buffer; both OS APIs return the required
    // size on overflow. These lookups do not trust caller environment variables.
    let n = unsafe {
        if system {
            GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32)
        } else {
            GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32)
        }
    } as usize;
    if n == 0 || n >= buffer.len() {
        return Err(format!("Cannot resolve system directory: {}", error()));
    }
    Ok(OsString::from_wide(&buffer[..n]))
}
pub fn initialize() -> Result<()> {
    let windows = directory(false)?;
    let system = directory(true)?;
    // SAFETY: process-global Windows loader policy; called in the dedicated
    // runner before serving IPC or loading adapters, never in the UI process.
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
        return Err(error());
    }
    let inherited: Vec<_> = std::env::vars_os().map(|(key, _)| key).collect();
    for key in inherited {
        if key.is_empty() || key.encode_wide().any(|c| c == 0 || c == b'=' as u16) {
            return Err("Invalid inherited runner environment key".into());
        }
        // SAFETY: Windows env mutation is thread-safe per Rust's platform
        // contract; this module is Windows-only and belongs to the runner.
        unsafe {
            std::env::remove_var(key);
        }
    }
    for (key, value) in [
        ("SYSTEMROOT", &windows),
        ("WINDIR", &windows),
        ("PATH", &system),
    ] {
        // SAFETY: Windows-only, fixed valid names and OS-produced directory values.
        unsafe {
            std::env::set_var(key, value);
        }
    }
    // Every successful elevated bootstrap proves the actual process allowlist,
    // regardless of which environment ShellExecuteEx chose to supply.
    if std::env::vars_os().count() != 3
        || std::env::var_os("SYSTEMROOT") != Some(windows.clone())
        || std::env::var_os("WINDIR") != Some(windows)
        || std::env::var_os("PATH") != Some(system)
    {
        return Err("Runner environment allowlist verification failed".into());
    }
    Ok(())
}
