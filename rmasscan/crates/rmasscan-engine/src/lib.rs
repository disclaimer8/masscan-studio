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
//! По одной паре потоков TX и RX на адаптер плана (для `Engine::start` и Studio ровно одна), у каждого свой
//! handle адаптера; `Engine::start_cli_with_clock` запускает пару на каждый `nic[k]`.
//! Команды (Pause/Stop) и внутренние отказы это монотонный атомарный флаг
//! `halt`; TX проверяет его перед каждой отправкой и внутри ожиданий throttle,
//! RX на каждой итерации (цикл приёма не дольше 50 мс). Очередь результатов
//! никогда не блокирует производителя, поэтому отмена не зависит от того,
//! читает ли потребитель события. Единственный терминальный [`Outcome`]
//! вычисляется тем из `2n` рабочих потоков, который завершается последним
//! (`ExitGuard`), то есть уже после остановки всех; он хранится отдельно от очереди результатов.

pub mod banners;
pub mod checkpoint;
pub mod engine;
pub mod events;
pub mod fake;
pub mod identity;
pub mod io;

pub use banners::{BannerOptions, Output, UdpBannerParser, udp_reply_banners};
pub use checkpoint::{CHECKPOINT_FORMAT_VERSION, Checkpoint, CheckpointError};
pub use engine::{
    CancelHandle, DEFAULT_TX_STALL_TIMEOUT, DedupCache, Engine, EngineError, EngineHandle,
    EngineOptions, MAX_DEDUP_ENTRIES, MAX_IO_TIMEOUT, MAX_TX_BATCH, PcapSink, StartError,
};
pub use events::{Event, FailReason, Outcome, Progress, Reason};
pub use identity::{ENGINE_ALGORITHM_VERSION, job_digest};
pub use io::{AdapterPair, IoError, Rx, RxHealth, SendStatus, Tx, TxBatch};
