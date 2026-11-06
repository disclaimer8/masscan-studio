//! Счётчик Ctrl-C живого скана (AGPL-3.0): порт `control_c_handler` (`main.c:1131–1155`, установка `main.c:1338`)
//! masscan © Robert David Graham (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0) в форме решения Р18.
//! Обработчик только увеличивает атомарный счётчик (async-signal-safe); строку C `waiting several seconds to
//! exit...` печатает и engine останавливает цикл событий `rmasscan_cli::live::run_live`, который читает
//! [`presses`]. Нажатие при уже ненулевом счётчике завершает процесс сразу с кодом 1 (`_exit(1)`, `ExitProcess(1)`):
//! фазы ожидания поздних ответов C здесь нет.
//!
//! Unix: `sigaction(SIGINT)` без `SA_RESETHAND` (обработчик остаётся на второе нажатие) и с `SA_RESTART`; адаптеры
//! и так повторяют вызовы после `EINTR`. Windows: `SetConsoleCtrlHandler` для `CTRL_C_EVENT` и `CTRL_BREAK_EVENT`
//! (система зовёт обработчик в своём потоке); прочие события консоли (закрытие окна, выход из системы) уходят
//! следующему обработчику, по умолчанию это завершение процесса.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::NetError;

/// Нажатия с начала процесса. `AtomicU32` lock-free на всех целевых платформах.
static PRESSES: AtomicU32 = AtomicU32::new(0);

/// Итог единственной установки.
static INSTALLED: OnceLock<Result<(), NetError>> = OnceLock::new();

/// Ставит обработчик Ctrl-C. Идемпотентно: обработчик ставится один раз за процесс, повторные вызовы возвращают
/// итог первого.
pub fn install() -> Result<(), NetError> {
    INSTALLED.get_or_init(imp::install).clone()
}

/// Сколько раз нажат Ctrl-C (без [`install`] всегда 0).
pub fn presses() -> u32 {
    PRESSES.load(Ordering::SeqCst)
}

/// Тело обработчика: одно атомарное `fetch_add`. `true` значит «счётчик уже был ненулевым», то есть выйти сразу.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
fn press() -> bool {
    PRESSES.fetch_add(1, Ordering::SeqCst) >= 1
}

#[cfg(unix)]
mod imp {
    use super::press;
    use crate::NetError;

    /// Обработчик SIGINT: только атомарный счётчик и, на втором нажатии, `_exit` (оба async-signal-safe).
    extern "C" fn on_sigint(_: libc::c_int) {
        if press() {
            // SAFETY: `_exit` async-signal-safe (POSIX) и не принимает указателей; atexit и деструкторы не идут.
            unsafe { libc::_exit(1) }
        }
    }

    pub(super) fn install() -> Result<(), NetError> {
        // SAFETY: нулевая `sigaction` допустима как начальное значение; `sa_mask` затем инициализирует
        // `sigemptyset` на той же живой локальной переменной; `on_sigint` это `extern "C"` функция, которая трогает
        // только статический атомарный счётчик; указатель на новое действие ссылается на живую, полностью
        // инициализированную локальную переменную, указатель на старое нулевой, что `sigaction` допускает.
        let rc = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_sigint as extern "C" fn(libc::c_int) as libc::sighandler_t;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut())
        };
        if rc != 0 {
            return Err(NetError::System(format!(
                "sigaction(SIGINT): {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use super::press;
    use crate::NetError;
    use windows_sys::Win32::Foundation::{FALSE, TRUE};
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler,
    };
    use windows_sys::Win32::System::Threading::ExitProcess;
    use windows_sys::core::BOOL;

    /// `PHANDLER_ROUTINE` (безопасная функция приводится к указателю `unsafe extern "system" fn`): Ctrl-C и
    /// Ctrl-Break считаются (`TRUE`, событие обработано), второе нажатие завершает процесс; остальное `FALSE`,
    /// следующему обработчику.
    pub(super) extern "system" fn on_ctrl(ctrl_type: u32) -> BOOL {
        match ctrl_type {
            CTRL_C_EVENT | CTRL_BREAK_EVENT => {
                if press() {
                    // SAFETY: `ExitProcess` не принимает указателей и завершает процесс со всеми потоками.
                    unsafe { ExitProcess(1) }
                }
                TRUE
            }
            _ => FALSE,
        }
    }

    pub(super) fn install() -> Result<(), NetError> {
        // SAFETY: `on_ctrl` имеет сигнатуру `PHANDLER_ROUTINE` и живёт всё время процесса; `TRUE` добавляет его в
        // список обработчиков процесса.
        if unsafe { SetConsoleCtrlHandler(Some(on_ctrl), TRUE) } == FALSE {
            return Err(NetError::System(format!(
                "SetConsoleCtrlHandler: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use crate::NetError;

    pub(super) fn install() -> Result<(), NetError> {
        Err(NetError::UnsupportedPlatform)
    }
}

/// Обработчик вызывается напрямую, без `GenerateConsoleCtrlEvent`: тот разослал бы событие всем процессам консоли,
/// включая запускатель тестов. Второго вызова с `CTRL_C_EVENT` нет: он завершил бы процесс.
#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::{FALSE, TRUE};
    use windows_sys::Win32::System::Console::{CTRL_C_EVENT, CTRL_CLOSE_EVENT};

    #[test]
    fn ctrl_c_handler_counts_the_first_press() {
        assert_eq!(presses(), 0);
        // Закрытие консоли обработчик не обрабатывает и не считает.
        assert_eq!(imp::on_ctrl(CTRL_CLOSE_EVENT), FALSE);
        assert_eq!(presses(), 0);
        assert_eq!(imp::on_ctrl(CTRL_C_EVENT), TRUE);
        assert_eq!(presses(), 1);
    }
}
