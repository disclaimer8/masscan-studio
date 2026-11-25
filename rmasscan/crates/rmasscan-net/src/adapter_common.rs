//! Помощники трёх адаптеров (Linux AF_PACKET, macOS BPF, Windows Npcap), которые раньше повторялись в каждом:
//! текст errno, ошибка закрытого адаптера, текст MAC, проверка binding, допустимость имени интерфейса и отображение
//! errno настройки в `NetError`. Тексты ошибок не менялись: один источник вместо двух-трёх копий.
//!
//! Здесь нет `unsafe`. Не объединяется то, что на ОС различается: `Deadline` (округление и бюджеты), `is_again`
//! (`EAGAIN` 11 на Linux, 35 на macOS) и правило коротких кадров.

#[cfg(any(target_os = "macos", windows, test))]
use rmasscan_core::packet::LinkType;
#[cfg(any(target_os = "macos", windows, test))]
use rmasscan_core::probe::AdapterBinding;
use rmasscan_engine::IoError;

use crate::NetError;

/// Сырой errno.
#[cfg(any(unix, test))]
pub(crate) type Errno = i32;

/// Результат ожидания готовности (`poll`).
#[cfg(any(unix, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Readiness {
    Timeout,
    Ready,
    /// POLLERR/POLLHUP/POLLNVAL без запрошенного события.
    Failed,
}

/// Номера errno, по которым настройка адаптера выбирает вид ошибки. На Linux и macOS они совпадают; свои константы
/// нужны, потому что `libc` недоступна в сборке тестов на Windows (равенство `libc` и `macos::abi::errno` проверяет
/// `adapter_common_errnos_match_every_os`).
#[cfg(any(unix, test))]
pub(crate) mod errno {
    pub(crate) const EPERM: i32 = 1;
    pub(crate) const ENXIO: i32 = 6;
    pub(crate) const EACCES: i32 = 13;
    pub(crate) const ENODEV: i32 = 19;
}

/// Ошибка вызова после фатального отказа этого же адаптера.
pub(crate) fn closed_error() -> IoError {
    IoError::new("adapter closed after an earlier fatal error")
}

/// `op: <текст errno по таблице ОС>`.
#[cfg(any(unix, test))]
pub(crate) fn errno_msg(op: &str, e: Errno) -> String {
    format!("{op}: {}", std::io::Error::from_raw_os_error(e))
}

/// MAC в виде `aa:bb:cc:dd:ee:ff` (строчные).
#[cfg(any(target_os = "macos", windows, test))]
pub(crate) fn mac_text(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Проверка binding без обращения к ОС. `adapter` это имя адаптера в тексте отказа по типу канала: «macOS BPF
/// adapter», «Windows Npcap adapter».
#[cfg(any(target_os = "macos", windows, test))]
pub(crate) fn check_binding(binding: &AdapterBinding, adapter: &str) -> Result<(), NetError> {
    if binding.link_type != LinkType::Ethernet {
        return Err(NetError::UnsupportedLink(format!(
            "{:?} ({adapter} supports Ethernet only)",
            binding.link_type
        )));
    }
    let mac = binding.source_mac;
    if mac == [0; 6] || mac[0] & 1 == 1 {
        return Err(NetError::InterfaceMismatch(format!(
            "source MAC {} is not a unicast address",
            mac_text(&mac)
        )));
    }
    if mac == binding.next_hop_mac {
        return Err(NetError::InterfaceMismatch(
            "source MAC equals the next-hop MAC: own transmitted frames could not be told \
             from replies"
                .into(),
        ));
    }
    Ok(())
}

/// `IFNAMSIZ` Linux и macOS (с завершающим NUL).
#[cfg(any(unix, test))]
pub(crate) const IFNAMSIZ: usize = 16;

/// Имя интерфейса, допустимое для IFNAMSIZ и пригодное как аргумент ОС.
#[cfg(any(unix, test))]
pub(crate) fn valid_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() < IFNAMSIZ
        && name != "."
        && name != ".."
        && !name
            .bytes()
            .any(|b| b == 0 || b == b'/' || b.is_ascii_whitespace())
}

/// Вид ошибки настройки по errno: нет прав, нет такого интерфейса или прочее. Текст: `op: <текст errno>`.
#[cfg(any(unix, test))]
pub(crate) fn map_setup_errno(op: &str, e: Errno) -> NetError {
    match e {
        errno::EPERM | errno::EACCES => NetError::PermissionDenied(errno_msg(op, e)),
        errno::ENODEV | errno::ENXIO => NetError::InterfaceMismatch(errno_msg(op, e)),
        _ => NetError::System(errno_msg(op, e)),
    }
}

#[cfg(test)]
#[path = "adapter_common_tests.rs"]
mod tests;
