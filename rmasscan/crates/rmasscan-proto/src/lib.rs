//! Протокольный слой баннеров: таблица приложений masscan, нормализаторы строк,
//! запись баннера и UDP-парсеры баннеров. Без внешних зависимостей, без `unsafe`.
#![forbid(unsafe_code)]

pub mod app;
pub mod banner;
mod memcached_text;
pub mod normalize;
// Автомат соединения ведёт таблица соединений (задача 7 подэтапа 4b); до неё в обычной сборке его зовут только тесты.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "автомат соединения ведёт таблица соединений задачи 7"
    )
)]
mod tcp;
pub mod udp;

pub use app::{app_from_name, app_id, app_name};
pub use banner::{BannerRecord, MAX_BANNER_BYTES};
pub use normalize::{normalize_json_string, normalize_string};
pub use udp::{UdpContext, handle_udp, udp_banner_parser};
