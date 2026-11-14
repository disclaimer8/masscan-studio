//! Бинарник `rmasscan` (AGPL-3.0): разбор argv и вызов [`rmasscan_cli::run`] с
//! настоящим `OsBackend`. Весь код и все unit-тесты живут в библиотеке; модуль
//! `os_backend` и `fn main` существуют только вне `cfg(test)` (cargo собирает
//! bin-таргет и под `cfg(test)`), поэтому ни один тест не может дойти до ОС.
//! Ctrl-C перехватывает только живой скан (`OsBackend::interrupts`, Р18); остальные операции оставляют поведение ОС
//! по умолчанию. `paused.conf` не пишется.

#![forbid(unsafe_code)]

#[cfg(not(test))]
mod os_backend;

#[cfg(not(test))]
fn main() -> std::process::ExitCode {
    use std::io::Write;

    use rmasscan_cli::args::{Cli, ParseError, clap_exit_code};

    let cli = match Cli::try_parse_masscan(std::env::args()) {
        Ok(c) => c,
        // Не `e.exit()`: он выходит с кодом 2. Ошибки clap это код 1, как `exit(1)` C на неизвестное имя
        // (`src/main-conf.c:3036`); справка и версия печатаются в stdout с кодом 0. Мёртвый поток не роняет выход.
        Err(ParseError::Clap(e)) => {
            let _ = e.print();
            return std::process::ExitCode::from(clap_exit_code(e.kind()));
        }
        // Тексты masscan (`missing output filename`, `nmap(-oA): …`, `FAIL: …`) как есть, exit 1.
        Err(ParseError::Masscan(text)) => {
            let _ = writeln!(std::io::stderr(), "{text}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut log = std::io::stderr();
    match rmasscan_cli::run(&cli, &os_backend::OsBackend, &mut out, &mut log) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(msg) => {
            let _ = out.flush();
            let text = rmasscan_cli::error_text(&msg);
            // Мёртвый stderr (EPIPE) не превращает exit 1 в панику `eprintln!` (101).
            if !text.is_empty() {
                let _ = writeln!(std::io::stderr(), "{text}");
            }
            std::process::ExitCode::FAILURE
        }
    }
}
