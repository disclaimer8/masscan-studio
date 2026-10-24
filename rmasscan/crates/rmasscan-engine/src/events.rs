//! События и терминальный итог.

use rmasscan_core::receive::Reply;

use crate::io::RxHealth;

/// Причина отказа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailReason {
    /// Очередь результатов переполнена: часть ответов не принята. Уже принятые
    /// результаты остаются доступными для чтения.
    ConsumerTooSlow,
    /// Адаптер не знает, ушёл ли кадр. Checkpoint небезопасен.
    TxUncertain,
    TxError(String),
    RxError(String),
    /// Адаптер сообщил потерю приёма (`kernel_drops` > 0): полнота локального
    /// приёма не доказана. Это не доказательство потери именно ответа цели
    /// (счётчик может включать посторонние кадры). Принятые результаты остаются.
    RxLoss {
        kernel_drops: u64,
    },
    /// Достоверной статистики приёма нет: неизвестное не считается нулём.
    RxStatsUnavailable,
    /// Паника рабочего потока.
    WorkerPanicked,
    /// Нарушение внутреннего инварианта (не должно случаться).
    Internal,
}

/// Причина завершения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// Все probe отправлены, `wait` отработан.
    Completed,
    /// Stop: потоки остановлены без ожидания `wait`.
    Stopped,
    /// Pause: TX остановлен на границе подтверждённой отправки, финальные
    /// ответы приняты. Это НЕ сохранённая пауза: её подтверждает Studio после
    /// durable commit.
    Paused,
    Failed(FailReason),
}

/// Слепок прогресса; новые события заменяют ещё не прочитанные (coalescing).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Progress {
    pub sent: u64,
    /// Следующий неподтверждённый индекс probe.
    pub next_index: u64,
    pub received: u64,
    /// Кадры, отброшенные без ошибки: чужие, битые, не прошедшие cookie.
    pub discarded: u64,
    /// Повторы, отсеянные ограниченным dedup-кэшем.
    pub duplicates: u64,
    pub rate: f64,
}

/// Терминальный итог запуска. Ровно один на запуск.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub reason: Reason,
    pub progress: Progress,
    /// Последнее УСПЕШНО измеренное состояние приёма; `kernel_drops: None`,
    /// если измерить не удалось (ошибка, нет статистики, измерения не было).
    pub rx_health: RxHealth,
}

/// События для потребителя.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Started {
        range: u64,
    },
    Progress(Progress),
    Results {
        replies: Vec<Reply>,
    },
    /// Только после чистой паузы. Детали (формат checkpoint) это задача 5.
    CheckpointReady {
        next_index: u64,
    },
    /// Последнее событие; приходит после всех принятых результатов.
    Finished {
        reason: Reason,
    },
}
