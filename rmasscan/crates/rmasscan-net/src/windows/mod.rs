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
    use std::net::Ipv4Addr;

    use super::sys;
    use crate::NetError;
    use crate::discover::{Iface, Interfaces, Route, RouteTable};
    use crate::route_parse::{defaults_from_rows, iface_from_adapter, lookup_from_best};

    /// Таблица маршрутов IP Helper (`GetBestRoute2`, `GetIpForwardTable2`).
    pub(crate) struct OsRoutes;

    impl RouteTable for OsRoutes {
        fn lookup_until(
            &self,
            dst: Ipv4Addr,
            deadline: std::time::Instant,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<Option<Route>, NetError> {
            let Some(row) = sys::best_route_until(dst, deadline, cancelled)? else {
                return Ok(None);
            };
            let adapters = sys::adapters_until(deadline, cancelled)?;
            let route = lookup_from_best(row, dst, &adapters);
            crate::network_plan::check_observation(deadline, cancelled)?;
            Ok(Some(route))
        }

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
    }

    /// Адаптеры IPv4 (`GetAdaptersAddresses(AF_INET)`).
    pub(crate) struct OsIfaces;

    impl Interfaces for OsIfaces {
        fn observe(
            &self,
            deadline: std::time::Instant,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<Vec<crate::network_plan::InterfaceObservation>, NetError> {
            sys::interfaces_until(deadline, cancelled)
        }

        fn list(&self) -> Result<Vec<Iface>, NetError> {
            Ok(sys::adapters()?.iter().map(iface_from_adapter).collect())
        }
    }

    #[cfg(test)]
    mod observation_tests {
        use super::*;
        use std::time::{Duration, Instant};

        /// Explicit native acceptance: IP Helper only; no Npcap adapter is opened.
        #[test]
        #[ignore = "reads live IP Helper state; no packets or adapter handles"]
        fn read_only_ip_helper_snapshot_preserves_prefixes_and_own_route() {
            let deadline = Instant::now() + Duration::from_secs(10);
            let observed = OsIfaces.observe(deadline, &|| false).unwrap();
            let iface = observed
                .iter()
                .find(|o| o.iface.up && !o.iface.ipv4.is_empty())
                .expect("Windows has an active IPv4 interface, including loopback");
            for observation in &observed {
                assert_eq!(
                    observation.iface.ipv4.len(),
                    observation.ipv4_prefixes.len()
                );
                assert!(
                    observation
                        .ipv4_prefixes
                        .iter()
                        .all(|prefix| prefix.length <= 32)
                );
                println!(
                    "interface {}: {:?}",
                    observation.iface.index, observation.ipv4_prefixes
                );
            }
            let route = OsRoutes
                .lookup_until(iface.iface.ipv4[0], deadline, &|| false)
                .unwrap()
                .expect("an address assigned to this host has a route");
            assert!(route.local, "{route:?}");

            // Cancellation becomes visible only after the synchronous route call.
            let checks = std::cell::Cell::new(0);
            let cancelled = || {
                checks.set(checks.get() + 1);
                checks.get() > 1
            };
            let late = OsRoutes.lookup_until(iface.iface.ipv4[0], deadline, &cancelled);
            assert!(late.unwrap_err().to_string().contains("cancelled"));
        }

        #[test]
        fn cancelled_observation_and_route_never_succeed() {
            let deadline = Instant::now() + Duration::from_secs(1);
            let interfaces = OsIfaces.observe(deadline, &|| true).unwrap_err();
            assert!(interfaces.to_string().contains("cancelled"), "{interfaces}");
            let route = OsRoutes
                .lookup_until(Ipv4Addr::new(198, 18, 0, 2), deadline, &|| true)
                .unwrap_err();
            assert!(route.to_string().contains("cancelled"), "{route}");
        }

        #[test]
        fn expired_observation_and_route_never_succeed() {
            let deadline = Instant::now();
            let interfaces = OsIfaces.observe(deadline, &|| false).unwrap_err();
            assert!(interfaces.to_string().contains("deadline"), "{interfaces}");
            let route = OsRoutes
                .lookup_until(Ipv4Addr::new(198, 18, 0, 2), deadline, &|| false)
                .unwrap_err();
            assert!(route.to_string().contains("deadline"), "{route}");
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
