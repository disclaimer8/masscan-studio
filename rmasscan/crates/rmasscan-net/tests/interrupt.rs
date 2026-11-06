//! Счётчик Ctrl-C на настоящем сигнале (AGPL-3.0, Р18): `install()` ставит обработчик SIGINT, `raise(SIGINT)`
//! только увеличивает счётчик, процесс жив. Отдельный тестовый бинарник с единственным тестом: сигнал не может
//! задеть другие тесты, и второго `raise` нет (оно завершило бы процесс с кодом 1, `_exit(1)`).
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
