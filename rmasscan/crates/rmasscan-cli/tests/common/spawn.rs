//! Единственный путь тестов к бинарнику `rmasscan` (N3). Бинарник содержит
//! настоящий `OsBackend`; полные тесты идут на хосте с реальной сетью, поэтому
//! запуск без операции, которая гарантированно ничего не передаёт, паникует.

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

pub fn spawn_readonly(argv: &[&str]) -> Output {
    readonly_command(argv).output().expect("spawn rmasscan")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "could transmit")]
    fn spawn_helper_refuses_argv_that_could_transmit() {
        spawn_readonly(&["10.0.0.0/24", "-p80"]);
    }

    #[test]
    fn spawn_helper_runs_argv_with_a_readonly_marker() {
        let out = spawn_readonly(&["--offline", "--nonsense", "10.0.0.0/30"]);
        assert_ne!(out.status.code(), Some(0));
        assert!(out.stdout.is_empty());
        assert!(!out.stderr.is_empty());
    }
}
