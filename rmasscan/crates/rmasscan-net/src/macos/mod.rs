//! macOS BPF: ABI-объявления, сведения об интерфейсе, инвентарь без
//! привилегий и адаптер (`open`, TX/RX поверх шва `BpfIo`). `unsafe` только в
//! `sys`, `ifinfo` и `process`.
//!
//! `abi` и `adapter` переносимы и собираются в тестах на любой ОС (seam-тесты
//! адаптера идут и на Linux, и на Windows); остальное только на macOS.

#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;

#[cfg(target_os = "macos")]
use crate::{BpfDevice, BpfInventory, NetError};

pub(crate) mod abi;
pub(crate) mod adapter;

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(crate) mod sys;

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(crate) mod ifinfo;

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(crate) mod process;

#[cfg(test)]
mod tests;

#[cfg(all(target_os = "macos", test))]
#[allow(unsafe_code)]
mod spike;

#[cfg(target_os = "macos")]
pub(crate) use adapter::open;

/// Сырой errno.
pub(crate) type Errno = i32;

pub(crate) fn errno_msg(op: &str, e: Errno) -> String {
    format!("{op}: {}", std::io::Error::from_raw_os_error(e))
}

#[cfg(target_os = "macos")]
const INSTANT_CLOCK: &str = "CLOCK_UPTIME_RAW (std::time::Instant; stops during sleep)";

/// Версия ОС в виде `27.0.1 (26A434)`.
#[cfg(target_os = "macos")]
pub(crate) fn os_version() -> Option<String> {
    let v = sys::sysctl_string("kern.osproductversion").ok()?;
    match sys::sysctl_string("kern.osversion") {
        Ok(b) => Some(format!("{v} ({b})")),
        Err(_) => Some(v),
    }
}

/// Узлы `/dev/bpf0..`: только `stat`, пока файл существует (`NotFound` это конец
/// списка, любая другая ошибка это `Err`, а не молчаливое усечение) и пока номер
/// меньше `maxdevices`. Узлы никогда не открываются.
#[cfg(target_os = "macos")]
fn stat_devices(max: Option<u32>) -> Result<Vec<BpfDevice>, NetError> {
    let limit = max.unwrap_or(256).min(256);
    let mut out = Vec::new();
    for n in 0..limit {
        let path = format!("/dev/bpf{n}");
        match std::fs::metadata(&path) {
            Ok(m) => out.push(BpfDevice {
                path,
                mode: m.mode() & 0o7777,
                uid: m.uid(),
                gid: m.gid(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(NetError::System(format!("stat {path}: {e}"))),
        }
    }
    Ok(out)
}

#[cfg(target_os = "macos")]
pub(crate) fn inventory() -> Result<BpfInventory, NetError> {
    let maxdev = sys::sysctl_u32("debug.bpf_maxdevices").ok();
    let interfaces = ifinfo::interfaces().map_err(|e| {
        NetError::System(format!(
            "getifaddrs: {}",
            std::io::Error::from_raw_os_error(e)
        ))
    })?;
    Ok(BpfInventory {
        os_version: os_version(),
        kernel_version: sys::sysctl_string("kern.version").ok(),
        bpf_maxbufsize: sys::sysctl_u32("debug.bpf_maxbufsize").ok(),
        bpf_maxdevices: maxdev,
        devices: stat_devices(maxdev)?,
        interfaces,
        instant_clock: INSTANT_CLOCK,
    })
}
