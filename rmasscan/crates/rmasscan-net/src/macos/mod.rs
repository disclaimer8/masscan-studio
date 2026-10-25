//! macOS BPF: ABI-объявления, сведения об интерфейсе и инвентарь без
//! привилегий. Адаптер (open/TX/RX) появится в задаче 4. `unsafe` только в
//! `sys` и `ifinfo`.

use std::os::unix::fs::MetadataExt;

use crate::{BpfDevice, BpfInventory, NetError};

#[allow(unsafe_code, dead_code)]
pub(crate) mod sys;

#[allow(unsafe_code, dead_code)]
pub(crate) mod ifinfo;

#[cfg(test)]
mod tests;

/// Сырой errno.
pub(crate) type Errno = i32;

const INSTANT_CLOCK: &str = "CLOCK_UPTIME_RAW (std::time::Instant; stops during sleep)";

/// Версия ОС в виде `27.0.1 (26A434)`.
pub(crate) fn os_version() -> Option<String> {
    let v = sys::sysctl_string("kern.osproductversion").ok()?;
    match sys::sysctl_string("kern.osversion") {
        Ok(b) => Some(format!("{v} ({b})")),
        Err(_) => Some(v),
    }
}

/// Узлы `/dev/bpf0..`: только `stat`, пока файл существует и пока номер меньше
/// `maxdevices`. Узлы никогда не открываются.
fn stat_devices(max: Option<u32>) -> Vec<BpfDevice> {
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
            Err(_) => break,
        }
    }
    out
}

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
        devices: stat_devices(maxdev),
        interfaces,
        instant_clock: INSTANT_CLOCK,
    })
}
