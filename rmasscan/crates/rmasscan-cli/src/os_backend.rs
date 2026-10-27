//! Настоящая реализация шва `Backend` (AGPL-3.0). Включается только в бинарник
//! вне `cfg(test)`. В этой задаче: энтропия ОС и системные часы.

use std::time::{SystemTime, UNIX_EPOCH};

use rmasscan_cli::live::Backend;

pub struct OsBackend;

impl Backend for OsBackend {
    fn entropy64(&self) -> u64 {
        getrandom::u64().expect("operating system entropy is unavailable")
    }

    fn unix_time(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}
