//! Запись баннера (то, что `output_report_banner` отдаёт форматам вывода). Тип и предел живут в
//! `rmasscan_core::banner`: их выдаёт и движок, который от этого крейта не зависит.

pub use rmasscan_core::banner::{BannerRecord, MAX_BANNER_BYTES};
