//! Счётчик Ctrl-C на настоящем сигнале (AGPL-3.0, Р18): `install()` ставит обработчик SIGINT, `raise(SIGINT)`
//! только увеличивает счётчик, процесс жив. Отдельный тестовый бинарник: в этом процессе сигнал поднимает один
//! тест. Второе нажатие (`_exit(1)`) проверяет дочерний процесс того же бинарника.
#![cfg(unix)]

use std::time::{Duration, Instant};

use rmasscan_net::interrupt::{install, presses};

#[test]
fn first_sigint_is_counted_not_fatal() {
    assert_eq!(presses(), 0, "no press before the signal");
    install().unwrap();
    install().expect("install is idempotent");
    assert_eq!(presses(), 0, "installing is not a press");
    // SAFETY: `raise` не принимает указателей; SIGINT обработан установленным выше обработчиком (только счётчик).
    assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
    // Сигнал, направленный своему потоку, доставляется до возврата `raise`; ожидание лишь страхует от планировщика.
    let deadline = Instant::now() + Duration::from_secs(2);
    while presses() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(presses(), 1, "the first SIGINT is counted once");
    // Процесс жив: тест дошёл до этой строки.
}

const CHILD_ENV: &str = "RMASSCAN_SECOND_SIGINT_CHILD";

/// Работает только в дочернем процессе `second_sigint_exits_immediately_with_code_one`: два `raise(SIGINT)`;
/// второе обязано завершить процесс кодом 1 (`_exit(1)`), до строки `unreachable` дойти нельзя.
#[test]
fn second_sigint_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    install().unwrap();
    // SAFETY: `raise` не принимает указателей; SIGINT обработан установленным выше обработчиком.
    assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
    assert_eq!(presses(), 1, "the first press is only counted");
    println!("first-press-survived");
    // SAFETY: как выше; на втором нажатии обработчик зовёт `_exit(1)` и `raise` не возвращается.
    unsafe { libc::raise(libc::SIGINT) };
    println!("unreachable");
}

/// Р18, `main.c:1131-1154`: второе нажатие выходит сразу с кодом 1 (не 0 и не по сигналу).
#[test]
fn second_sigint_exits_immediately_with_code_one() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "second_sigint_child", "--nocapture"])
        .env(CHILD_ENV, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("first-press-survived"), "{stdout}");
    assert!(!stdout.contains("unreachable"), "{stdout}");
}
