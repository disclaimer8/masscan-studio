//! Windows: Npcap (`wpcap.dll`), загружаемый динамически по полному пути.
//!
//! Модуль собирается на Windows и в тестах любой платформы: ABI-объявления,
//! таблица функций, владение handle, перечисление устройств и сами половины
//! адаптера не зависят от WinAPI и проверяются подставным загрузчиком
//! ([`loader::Loader`]) и подставной таблицей функций. Настоящий
//! `LoadLibraryExW` живёт только в `sys` (`cfg(windows)`).
//!
//! `unsafe` разрешён только в FFI-модулях `ffi`, `handle`, `loader`, `sys`
//! (и в тестовой подставной таблице); `adapter` (логика TX/RX, фильтрация,
//! счётчики, health) полностью безопасный и работает через `PcapHandle`.

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
pub(crate) mod sys;

#[cfg(windows)]
pub(crate) use adapter::open;

#[cfg(test)]
#[allow(unsafe_code)]
mod tests;
// Opt-in живые испытания (все `#[ignore]`, пакеты уходят только при явном env).
#[cfg(all(windows, test))]
#[allow(unsafe_code)]
mod live;
