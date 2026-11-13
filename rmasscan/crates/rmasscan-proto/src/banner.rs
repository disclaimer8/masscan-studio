//! Запись баннера (то, что `output_report_banner` отдаёт форматам вывода).

use std::net::IpAddr;

/// Предел полезной нагрузки баннера в байтах (Р5).
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
