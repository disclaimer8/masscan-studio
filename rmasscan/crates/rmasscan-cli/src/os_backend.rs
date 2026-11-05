//! Настоящая реализация шва `Backend` (AGPL-3.0). Включается только в бинарник вне `cfg(test)` и является
//! единственным местом, где CLI открывает адаптер (`rmasscan_net::open_explicit`). Таблицы маршрутов и интерфейсов
//! читаются в процессе и без привилегий; энтропия из `getrandom`; часы `SystemClock`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rmasscan_cli::live::Backend;
use rmasscan_core::probe::AdapterBinding;
use rmasscan_core::throttle::{Clock, SystemClock};
use rmasscan_engine::AdapterPair;
use rmasscan_net::arp_resolve::ArpPolicy;
use rmasscan_net::{Interfaces, NetError, RouteTable};

pub struct OsBackend;

impl Backend for OsBackend {
    fn routes(&self) -> Result<Box<dyn RouteTable>, NetError> {
        rmasscan_net::os_route_table()
    }

    fn interfaces(&self) -> Result<Box<dyn Interfaces>, NetError> {
        rmasscan_net::os_interfaces()
    }

    fn open(&self, binding: &AdapterBinding) -> Result<AdapterPair, NetError> {
        rmasscan_net::open_explicit(binding).map(|a| a.io)
    }

    fn entropy64(&self) -> u64 {
        // Контракт шва: не 0 (seed 0 в C значит «взять энтропию»).
        loop {
            let v = getrandom::u64().expect("operating system entropy is unavailable");
            if v != 0 {
                return v;
            }
        }
    }

    fn unix_time(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn arp_policy(&self) -> ArpPolicy {
        ArpPolicy::default()
    }

    fn clock(&self) -> Arc<dyn Clock + Send + Sync> {
        Arc::new(SystemClock::new())
    }
}
