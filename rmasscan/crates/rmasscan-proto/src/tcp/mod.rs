//! Пользовательский стек TCP для баннеров (подэтап 4b), порт `src/stack-tcp-core.c`, `src/stack-tcp-app.c` и
//! `src/misc-rstfilter.c` masscan © Robert David Graham (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0),
//! AGPL-3.0.
//!
//! [`tcb`] это одно соединение: автомат `stack_incoming_tcp` (`src/stack-tcp-core.c:1910-2313`) с очередью отправки,
//! подтверждением и приёмом (справка `2026-11-13-rmasscan-banners-c-reference-tcp.md`, A3-A5). [`table`] ведёт автомат
//! снаружи: соединения, таймеры (`tcpcon_*`, `tcpcon_timeouts`) и сброс баннеров после [`tcb::TcbResult::Destroyed`];
//! [`app`] это `application_event` между автоматом и сессией баннера (B5); [`rstfilter`] глушит RST на FIN без
//! соединения (A7); [`stack`] собирает их в `TcpStack` ядра по стековому блоку приёмного потока (A2).

pub(crate) mod app;
pub(crate) mod rstfilter;
pub(crate) mod stack;
pub(crate) mod table;
pub(crate) mod tcb;

pub use stack::{TcpBannerStack, connection_memory_floor};
