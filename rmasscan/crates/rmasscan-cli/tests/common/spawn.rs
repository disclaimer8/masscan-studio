//! Единственный путь тестов к бинарнику `rmasscan` (N3). Бинарник содержит
//! настоящий `OsBackend`; полные тесты идут на хосте с реальной сетью, поэтому
//! запуск без операции, которая гарантированно ничего не передаёт, паникует.
//! Собственные тесты защиты живут в `tests/spawn_guard.rs`, а не здесь: модуль
//! включается в несколько тестовых crate.

// Каждый включающий crate берёт свою часть помощников (differential оба, detect_readonly и spawn_guard часть).
#![allow(dead_code)]

use std::process::{Command, Output};

/// Аргументы, при наличии любого из которых бинарник не открывает адаптер.
const READONLY_MARKERS: [&str; 8] = [
    "--iflist",
    "--offline",
    "-sL",
    "--list",
    "--echo",
    "--echo-all",
    "--help",
    "-V",
];

/// `Command` для бинарника с аргументами; паникует, если argv не содержит ни
/// одного из [`READONLY_MARKERS`]. Для тестов, которым нужен свой `stdio`.
pub fn readonly_command(argv: &[&str]) -> Command {
    assert!(
        argv.iter().any(|a| READONLY_MARKERS.contains(a)),
        "refusing to spawn rmasscan with argv that could transmit: {argv:?} \
         (needs one of {READONLY_MARKERS:?})"
    );
    let mut c = Command::new(env!("CARGO_BIN_EXE_rmasscan"));
    c.args(argv);
    c
}

/// Запускает бинарник через [`readonly_command`] (та же защита) и ждёт вывод.
pub fn spawn_readonly(argv: &[&str]) -> Output {
    readonly_command(argv).output().expect("spawn rmasscan")
}
