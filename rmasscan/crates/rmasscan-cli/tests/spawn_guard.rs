//! Тесты защиты единственного пути к бинарнику (`tests/common/spawn.rs`, N3, AGPL-3.0): argv без операции только
//! для чтения не запускается ни через `spawn_readonly`, ни через `readonly_command`. Живут отдельно, чтобы не
//! повторяться в каждом crate, включающем общий модуль.

#[path = "common/spawn.rs"]
mod spawn;

use spawn::{readonly_command, spawn_readonly};

#[test]
#[should_panic(expected = "could transmit")]
fn spawn_helper_refuses_argv_that_could_transmit() {
    spawn_readonly(&["10.0.0.0/24", "-p80"]);
}

#[test]
#[should_panic(expected = "could transmit")]
fn readonly_command_refuses_argv_that_could_transmit() {
    let _ = readonly_command(&["10.0.0.0/30", "-p80", "--router-mac", "02-00-00-00-00-01"]);
}

#[test]
fn spawn_helper_runs_argv_with_a_readonly_marker() {
    let out = spawn_readonly(&["--offline", "--nonsense", "10.0.0.0/30"]);
    assert_ne!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}
