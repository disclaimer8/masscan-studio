//! Протокольный слой баннеров: таблица приложений masscan, нормализаторы строк,
//! запись баннера и UDP-парсеры баннеров. Без внешних зависимостей, без `unsafe`.
#![forbid(unsafe_code)]

pub mod app;
pub mod banner;
mod memcached_text;
pub mod normalize;
// Таблицу строит `new_stack` с сессиями баннеров (`Sessions`); их реализацию и фабрику таблицы даёт задача 8
// подэтапа 4b, до неё в обычной сборке стек строят только тесты.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "сессии баннеров и фабрику таблицы даёт задача 8")
)]
mod tcp;
pub mod udp;

pub use app::{app_from_name, app_id, app_name};
pub use banner::{BannerRecord, MAX_BANNER_BYTES};
pub use normalize::{normalize_json_string, normalize_string};
pub use tcp::TcpBannerStack;
#[doc(hidden)]
pub use tcp::connection_memory_floor;
pub use udp::{UdpContext, handle_udp, udp_banner_parser};
