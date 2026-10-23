#![forbid(unsafe_code)]
//! Runtime движка сканирования (AGPL-3.0). Порт потоков `transmit_thread` /
//! `receive_thread` из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0) с отменяемым
//! завершением и ограниченными очередями.
//!
//! Этап 2A: только офлайн. Здесь нет сокетов и сетевого API; адаптер это
//! пара трейтов [`io::Tx`] / [`io::Rx`], а в тестах их роль играет
//! [`fake::FakeAdapter`].
//!
//! # Модель потоков и завершения
//! Ровно один TX-поток и один RX-поток, у каждого свой handle адаптера.
//! Команды (Pause/Stop) и внутренние отказы это монотонный атомарный флаг
//! `halt`; TX проверяет его перед каждой отправкой и внутри ожиданий throttle,
//! RX на каждой итерации (цикл приёма не дольше 50 мс). Очередь результатов
//! никогда не блокирует производителя, поэтому отмена не зависит от того,
//! читает ли потребитель события. Единственный терминальный [`Outcome`]
//! вычисляется тем из двух потоков, который завершается вторым, то есть уже
//! после остановки обоих; он хранится отдельно от очереди результатов.

pub mod engine;
pub mod events;
pub mod fake;
pub mod io;

pub use engine::{
    CancelHandle, DedupCache, Engine, EngineError, EngineHandle, EngineOptions, MAX_DEDUP_ENTRIES,
    MAX_IO_TIMEOUT, StartError,
};
pub use events::{Event, FailReason, Outcome, Progress, Reason};
pub use io::{AdapterPair, IoError, Rx, SendStatus, Tx};
