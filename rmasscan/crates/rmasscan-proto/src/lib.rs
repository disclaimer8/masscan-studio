//! Протокольный слой баннеров: таблица приложений masscan, нормализаторы строк
//! и запись баннера. Без внешних зависимостей, без `unsafe`.
#![forbid(unsafe_code)]

pub mod app;
pub mod banner;
pub mod normalize;

pub use app::{app_from_name, app_id, app_name};
pub use banner::{BannerRecord, MAX_BANNER_BYTES};
pub use normalize::{normalize_json_string, normalize_string};
