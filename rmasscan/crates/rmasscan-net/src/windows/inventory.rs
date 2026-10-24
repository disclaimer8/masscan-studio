//! Перечень Npcap для `--inventory`: безопасная сборка отчёта из уже
//! загруженной библиотеки. Адаптер НЕ открывается (ни `pcap_create`, ни
//! `pcap_sendpacket`): только `pcap_findalldevs` и чтение версий файлов.

use super::handle::list_devices;
use super::loader::NpcapApi;
use crate::{DeviceReport, DllReport, Inventory, NetError};

const NPF_PREFIX: &str = "\\Device\\NPF_";

/// GUID `{...}` из имени `\Device\NPF_{GUID}`; иначе `None`.
pub(crate) fn npf_guid(name: &str) -> Option<&str> {
    let g = name.strip_prefix(NPF_PREFIX)?;
    (g.starts_with('{') && g.ends_with('}') && g.len() > 2).then_some(g)
}

/// Собирает отчёт. `mac_of` и `driver_version` подставляются вызывающим
/// (настоящие на Windows, подставные в тестах).
pub(crate) fn build(
    api: &NpcapApi,
    mac_of: &dyn Fn(&str) -> Option<[u8; 6]>,
    driver_version: Option<String>,
) -> Result<Inventory, NetError> {
    let devices = list_devices(api)?
        .into_iter()
        .map(|d| DeviceReport {
            loopback: d.flags & super::ffi::PCAP_IF_LOOPBACK != 0,
            mac: mac_of(&d.name),
            name: d.name,
            description: d.description,
        })
        .collect();
    Ok(Inventory {
        lib_version: api.lib_version().to_string(),
        utf8_text: api.utf8_text(),
        dlls: api
            .diagnostics()
            .iter()
            .map(|d| DllReport {
                name: d.name.clone(),
                path: d.path.clone(),
                sha256: d.sha256.clone(),
                version: d.version.clone(),
            })
            .collect(),
        driver_version,
        devices,
    })
}

#[cfg(windows)]
pub(crate) fn collect() -> Result<Inventory, NetError> {
    let api = NpcapApi::load()?;
    let driver = super::sys::system_directory()
        .ok()
        .and_then(|s| super::sys::file_version(&format!("{s}\\drivers\\npcap.sys")));
    build(&api, &|n| nic_mac(n), driver)
}

#[cfg(windows)]
pub(crate) fn nic_mac(interface_id: &str) -> Option<[u8; 6]> {
    super::sys::adapter_mac_by_guid(npf_guid(interface_id)?)
}

#[cfg(windows)]
pub(crate) fn os_version() -> Option<String> {
    super::sys::os_version()
}
