//! Протокольный слой баннеров: таблица приложений masscan, нормализаторы строк,
//! запись баннера и UDP-парсеры баннеров. Без внешних зависимостей, без `unsafe`.
#![forbid(unsafe_code)]

pub mod app;
pub mod banner;
mod memcached_text;
pub mod normalize;
pub mod udp;

pub use app::{app_from_name, app_id, app_name};
pub use banner::{BannerRecord, MAX_BANNER_BYTES};
pub use normalize::{normalize_json_string, normalize_string};
pub use udp::{UdpContext, handle_udp, udp_banner_parser};
