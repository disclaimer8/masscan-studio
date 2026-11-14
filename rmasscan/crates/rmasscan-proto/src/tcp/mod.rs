//! Пользовательский стек TCP для баннеров (подэтап 4b), порт `src/stack-tcp-core.c` masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0), AGPL-3.0.
//!
//! [`tcb`] это одно соединение: автомат `stack_incoming_tcp` (`src/stack-tcp-core.c:1910-2313`) с очередью отправки,
//! подтверждением и приёмом (справка `2026-11-13-rmasscan-banners-c-reference-tcp.md`, A3-A5). Таблица соединений и
//! таймеры (`tcpcon_*`, `tcpcon_timeouts`) ведут автомат снаружи: они решают, какие события и с какими номерами ему
//! отдать, и что делать с соединением после [`tcb::TcbResult::Destroyed`].

pub(crate) mod tcb;
