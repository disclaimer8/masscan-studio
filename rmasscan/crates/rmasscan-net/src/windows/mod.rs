//! Windows: Npcap (`wpcap.dll`), загружаемый динамически по полному пути.
//!
//! Модуль собирается на Windows и в тестах любой платформы: ABI-объявления,
//! таблица функций, владение handle и перечисление устройств не зависят от
//! WinAPI и проверяются подставным загрузчиком ([`loader::Loader`]). Настоящий
//! `LoadLibraryExW` живёт только в `sys` (`cfg(windows)`).
//!
//! Задача 1 этапа 2B-Windows: загрузка, владение и ABI. Отправки и приёма
//! кадров здесь нет (их добавляет `adapter` в следующих задачах).

pub(crate) mod ffi;
pub(crate) mod handle;
pub(crate) mod loader;
#[cfg(windows)]
pub(crate) mod sys;

#[cfg(test)]
mod tests;
