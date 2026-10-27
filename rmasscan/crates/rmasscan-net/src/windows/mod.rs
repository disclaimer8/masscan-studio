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
/// (IfType 6/71 это Ethernet, 24 это loopback, `Route::local`, порядок по Metric) в переносимом `route_parse`.
#[cfg(windows)]
mod os {
    use std::net::Ipv4Addr;

    use super::sys;
    use crate::NetError;
    use crate::discover::{Iface, Interfaces, Route, RouteTable};
    use crate::route_parse::{
        defaults_from_table, iface_from_adapter, mark_loopback, route_from_best,
    };

    /// Таблица маршрутов IP Helper (`GetBestRoute2`, `GetIpForwardTable2`).
    pub(crate) struct OsRoutes;

    impl RouteTable for OsRoutes {
        fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, NetError> {
            let Some(row) = sys::best_route(dst)? else {
                return Ok(None);
            };
            let adapters = sys::adapters()?;
            let mut rows = [row];
            mark_loopback(&mut rows, &adapters);
            let ifaces: Vec<Iface> = adapters.iter().map(iface_from_adapter).collect();
            Ok(Some(route_from_best(&rows[0], dst, &ifaces)))
        }

        fn default_routes(&self) -> Result<Vec<Route>, NetError> {
            let mut rows = sys::forward_table()?;
            let adapters = sys::adapters()?;
            mark_loopback(&mut rows, &adapters);
            let ifaces: Vec<Iface> = adapters.iter().map(iface_from_adapter).collect();
            Ok(defaults_from_table(&rows, &ifaces))
        }
    }

    /// Адаптеры IPv4 (`GetAdaptersAddresses(AF_INET)`).
    pub(crate) struct OsIfaces;

    impl Interfaces for OsIfaces {
        fn list(&self) -> Result<Vec<Iface>, NetError> {
            Ok(sys::adapters()?.iter().map(iface_from_adapter).collect())
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
