//! Запись баннера (то, что `output_report_banner` отдаёт форматам вывода, `src/output.c:885-890`).
//!
//! Тип живёт в ядре, а не в `rmasscan-proto`, потому что его выдаёт движок (`rmasscan-engine`, `Output::Banner`), а
//! движок не зависит от `rmasscan-proto`: новая обычная зависимость движка изменила бы `Cargo.lock` Studio, которая
//! собирается с `--locked` и не меняется (Р11). `rmasscan-proto` реэкспортирует оба имени.

use std::net::IpAddr;

/// Предел полезной нагрузки баннера в байтах (Р5): при нём вывод любого формата совпадает с C (текст усекается на
/// 8192, JSON на 65 536 экранированных символах, `-oB` выбрасывает записи от 16 370 байт).
pub const MAX_BANNER_BYTES: usize = 65_536;

/// Один баннер: поля как у `output_report_banner` (`src/output.c`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BannerRecord {
    pub timestamp: u64,
    pub ip: IpAddr,
    pub ip_proto: u8,
    pub port: u16,
    pub app: u16,
    pub ttl: u8,
    pub payload: Vec<u8>,
}
