//! Контракт адаптера. Каждый handle принадлежит ровно одному потоку.
//! Реализации обязаны возвращаться из вызова не позже `timeout` (с запасом на
//! планировщик): на этом держатся критерии остановки runtime.

use std::time::Duration;

/// Ошибка ввода-вывода адаптера.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("adapter I/O error: {message}")]
pub struct IoError {
    pub message: String,
}

impl IoError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Результат попытки отправки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendStatus {
    /// Кадр передан адаптеру; только после этого движется курсор и счётчик sent.
    Sent,
    /// Кадр точно НЕ отправлен (очередь устройства полна): курсор не
    /// продвигается, тот же кадр будет предложен снова.
    WouldBlockUnsent,
    /// Неизвестно, ушёл ли кадр (частичная запись, сбой после записи). Запуск
    /// завершается `Failed`, безопасного checkpoint нет, повторов нет.
    Uncertain,
}

/// Передающая сторона.
pub trait Tx: Send {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError>;
}

/// Достоверность локального приёма на момент вызова [`Rx::health`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxHealth {
    /// Кумулятивное с начала этой попытки (не delta) число кадров, потерянных
    /// ниже движка (например, переполнение очереди ядра). `Some(0)` допустимо
    /// ТОЛЬКО при успешном измерении; `None` значит «измерить нельзя».
    /// Неизвестное никогда не превращается в ноль.
    pub kernel_drops: Option<u64>,
}

/// Принимающая сторона. `Ok(None)` это истёкший таймаут.
pub trait Rx: Send {
    fn recv(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<Option<usize>, IoError>;

    /// Измеряет потери приёма. Обязательный метод: адаптер, который не умеет
    /// измерять, обязан сказать это явно (`kernel_drops: None`) или вернуть
    /// ошибку, а не молчаливый ноль. Возвращается не позже `timeout`.
    fn health(&mut self, timeout: Duration) -> Result<RxHealth, IoError>;
}

/// Пара handle для одного запуска.
pub struct AdapterPair {
    pub tx: Box<dyn Tx>,
    pub rx: Box<dyn Rx>,
}
