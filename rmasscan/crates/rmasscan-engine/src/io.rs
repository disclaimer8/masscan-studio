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

/// Исход пачки: первые `sent` кадров приняты (как `Sent` по одному), остаток
/// описан `rest`. Инвариант: `sent == frames.len()` тогда и только тогда, когда
/// `rest == SendStatus::Sent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxBatch {
    pub sent: usize,
    pub rest: SendStatus,
}

/// Передающая сторона.
pub trait Tx: Send {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError>;

    /// Сколько кадров адаптер принимает одним `send_batch` (не меньше 1).
    /// По умолчанию 1.
    fn max_batch(&self) -> usize {
        1
    }

    /// Один вызов адаптера на префикс `frames` (не больше `max_batch()`, не
    /// меньше 1). Очередь не переживает вызов: принятые кадры это ровно первые
    /// `sent`. `Err` означает, что из этого вызова ничего не принято; сбой после
    /// принятого префикса сообщается как `TxBatch { sent: i, rest: Uncertain }`.
    ///
    /// Реализация по умолчанию это цикл `send` до первого исхода, отличного от
    /// `Sent`, и верна только для `max_batch() == 1`: каждый кадр получает
    /// полный `timeout`. Адаптер с `max_batch() > 1` обязан переопределить
    /// `send_batch` и уложить весь вызов в `timeout`.
    fn send_batch(&mut self, frames: &[&[u8]], timeout: Duration) -> Result<TxBatch, IoError> {
        for (i, frame) in frames.iter().enumerate() {
            let status = match self.send(frame, timeout) {
                Ok(status) => status,
                // Префикс уже принят: ошибка не должна его терять.
                Err(_) if i > 0 => {
                    return Ok(TxBatch {
                        sent: i,
                        rest: SendStatus::Uncertain,
                    });
                }
                Err(e) => return Err(e),
            };
            if status != SendStatus::Sent {
                return Ok(TxBatch {
                    sent: i,
                    rest: status,
                });
            }
        }
        Ok(TxBatch {
            sent: frames.len(),
            rest: SendStatus::Sent,
        })
    }
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
