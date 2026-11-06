//! Имена сервисов для `-oG` и `-oU` (AGPL-3.0). В этой задаче заглушка; Задача 2 наполняет её разбором файла
//! services хоста. Имя типа и путь модуля не меняются.

/// Таблица имён портов. Пока пустая.
#[derive(Clone, Debug, Default)]
pub struct ServiceNames;

/// Пустая таблица (все порты `unknown`).
pub fn empty() -> ServiceNames {
    ServiceNames
}
