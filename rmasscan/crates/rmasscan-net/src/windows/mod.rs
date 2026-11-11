//! Windows: Npcap (`wpcap.dll`), загружаемый динамически по полному пути.
//!
//! Модуль собирается на Windows и в тестах любой платформы: ABI-объявления,
//! таблица функций, владение handle, перечисление устройств и сами половины
//! адаптера не зависят от WinAPI и проверяются подставным загрузчиком
//! ([`loader::Loader`]) и подставной таблицей функций. Настоящий
//! `LoadLibraryExW` живёт только в `sys` (`cfg(windows)`).
//!
//! `unsafe` разрешён только в FFI-модулях `ffi`, `handle`, `loader`, `process`,
//! `sys` (и в тестовой подставной таблице); `process` (Toolhelp, токен, память
//! процесса) нужен лабораторному harness, но собирается и в продуктовой сборке.
//! Чтение адаптеров и маршрутов для обнаружения тоже живёт в `sys`; безопасная
//! обёртка `os` реализует над ним `RouteTable`/`Interfaces`.
//! `adapter` (логика TX/RX, фильтрация, счётчики, health) полностью безопасный и работает через `PcapHandle`.

pub(crate) mod adapter;
#[allow(unsafe_code)]
pub(crate) mod ffi;
#[allow(unsafe_code)]
pub(crate) mod handle;
pub(crate) mod inventory;
#[allow(unsafe_code)]
pub(crate) mod loader;
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) mod process;
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) mod sys;

#[cfg(windows)]
pub(crate) use adapter::open;

#[cfg(windows)]
pub(crate) use os::{OsIfaces, OsRoutes};

/// Обнаружение над IP Helper: безопасная обёртка над `sys::{adapters, best_route, forward_table}`; правила
/// (IfType 6/71 это Ethernet, 24 это loopback, `Route::local`, порядок по Metric) и сама склейка строк с адаптерами
/// (`lookup_from_best`, `defaults_from_rows`) в переносимом `route_parse`, где их проверяют тесты любой ОС.
#[cfg(windows)]
mod os {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::sys;
    use crate::NetError;
    use crate::discover::{Iface, Interfaces, Route, RouteTable, RouteV6};
    use crate::route_parse::{
        defaults_from_rows, defaults6_from_rows, iface_from_adapter, lookup_from_best,
        lookup6_from_best, usable_win_addrs6,
    };

    /// Все пригодные адреса IPv6 хоста: назначение среди них это адрес самого хоста.
    fn own_ipv6() -> Result<Vec<Ipv6Addr>, NetError> {
        Ok(sys::adapters6()?
            .iter()
            .flat_map(|(_, entries)| usable_win_addrs6(entries))
            .collect())
    }

    /// Таблица маршрутов IP Helper (`GetBestRoute2`, `GetIpForwardTable2`).
    pub(crate) struct OsRoutes;

    impl RouteTable for OsRoutes {
        fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, NetError> {
            let Some(row) = sys::best_route(dst)? else {
                return Ok(None);
            };
            Ok(Some(lookup_from_best(row, dst, &sys::adapters()?)))
        }

        fn default_routes(&self) -> Result<Vec<Route>, NetError> {
            let rows = sys::forward_table()?;
            Ok(defaults_from_rows(rows, &sys::adapters()?))
        }

        /// `GetBestRoute2` `AF_INET6`: строка, `BestSourceAddress` и адреса хоста (свой адрес это local).
        fn lookup_v6(&self, dst: Ipv6Addr) -> Result<Option<RouteV6>, NetError> {
            let Some((row, source)) = sys::best_route6(dst)? else {
                return Ok(None);
            };
            Ok(Some(lookup6_from_best(
                row,
                source,
                dst,
                &own_ipv6()?,
                &sys::adapters()?,
            )))
        }

        fn default_routes_v6(&self) -> Result<Vec<RouteV6>, NetError> {
            let rows = sys::forward_table6()?;
            Ok(defaults6_from_rows(rows, &sys::adapters()?))
        }
    }

    /// Адаптеры IPv4 (`GetAdaptersAddresses(AF_INET)`).
    pub(crate) struct OsIfaces;

    impl Interfaces for OsIfaces {
        fn list(&self) -> Result<Vec<Iface>, NetError> {
            Ok(sys::adapters()?.iter().map(iface_from_adapter).collect())
        }

        /// Адреса IPv6 адаптера по его GUID (`device_id` это `\Device\NPF_` + `AdapterName`).
        fn ipv6_addrs(&self, iface: &Iface) -> Result<Vec<Ipv6Addr>, NetError> {
            let guid = iface
                .device_id
                .strip_prefix("\\Device\\NPF_")
                .unwrap_or(&iface.device_id);
            Ok(sys::adapters6()?
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(guid))
                .map(|(_, entries)| usable_win_addrs6(entries))
                .unwrap_or_default())
        }
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests;
// Opt-in живые испытания (все `#[ignore]`, пакеты уходят только при явном env).
#[cfg(all(windows, test))]
#[allow(unsafe_code)]
mod live;
