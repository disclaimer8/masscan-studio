#![cfg(windows)]
use std::{path::PathBuf, process::Command};
use windows_sys::Win32::{
    Foundation::FreeLibrary,
    System::{LibraryLoader::*, SystemInformation::*},
};

fn system_directory() -> PathBuf {
    let mut path = [0u16; 32768];
    // SAFETY: sized writable UTF-16 buffer; native system location ignores env.
    let n = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) };
    assert!(n > 0 && n < path.len() as u32);
    PathBuf::from(String::from_utf16(&path[..n as usize]).unwrap())
}
#[test]
fn runner_allowlist_removes_inherited_markers_and_cwd_dll_search() {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "studio-env-{}",
        nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    std::fs::create_dir(&dir).unwrap();
    // A benign copy of an actual OS DLL is a search-path witness, not custom code.
    std::fs::copy(system_directory().join("winmm.dll"), dir.join("winmm.dll")).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "environment_child", "--nocapture"])
        .current_dir(&dir)
        .env("STUDIO_UAC_ENV_MARKER", "must-be-removed")
        .env("PATH", &dir)
        .output()
        .unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
#[ignore = "isolated process-global environment fixture"]
fn environment_child() {
    assert_eq!(
        std::env::var("STUDIO_UAC_ENV_MARKER").unwrap(),
        "must-be-removed"
    );
    studio_platform::windows::runner_environment::initialize().unwrap();
    assert!(
        std::env::var_os("STUDIO_UAC_ENV_MARKER").is_none(),
        "inherited marker survived runner policy"
    );
    let mut keys: Vec<_> = std::env::vars_os()
        .map(|(k, _)| k.to_string_lossy().to_uppercase())
        .collect();
    keys.sort();
    assert_eq!(keys, ["PATH", "SYSTEMROOT", "WINDIR"]);
    assert_eq!(
        PathBuf::from(std::env::var_os("PATH").unwrap()),
        system_directory()
    );
    let name: Vec<u16> = "winmm.dll".encode_utf16().chain(Some(0)).collect();
    // SAFETY: constant DLL name; the initialized policy must search only System32.
    let module = unsafe { LoadLibraryW(name.as_ptr()) };
    assert!(!module.is_null(), "{}", std::io::Error::last_os_error());
    let mut path = [0u16; 32768];
    // SAFETY: retained module and sized writable UTF-16 output.
    let n = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) };
    // SAFETY: unique LoadLibrary reference after querying its path.
    unsafe {
        FreeLibrary(module);
    }
    assert!(n > 0 && n < path.len() as u32);
    let loaded = PathBuf::from(String::from_utf16(&path[..n as usize]).unwrap());
    assert_eq!(
        std::fs::canonicalize(loaded).unwrap(),
        std::fs::canonicalize(system_directory().join("winmm.dll")).unwrap()
    );
}
