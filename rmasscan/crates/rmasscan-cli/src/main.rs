//! Бинарник `rmasscan` (AGPL-3.0): разбор argv и вызов [`rmasscan_cli::run`] с
//! настоящим `OsBackend`. Весь код и все unit-тесты живут в библиотеке; модуль
//! `os_backend` и `fn main` существуют только вне `cfg(test)` (cargo собирает
//! bin-таргет и под `cfg(test)`), поэтому ни один тест не может дойти до ОС.
//! Ctrl-C не перехватывается: поведение ОС по умолчанию, `paused.conf` не пишется.

#![forbid(unsafe_code)]

#[cfg(not(test))]
mod os_backend;

#[cfg(not(test))]
fn main() -> std::process::ExitCode {
    use std::io::Write;

    let cli = match rmasscan_cli::args::Cli::try_parse_masscan(std::env::args()) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut log = std::io::stderr();
    match rmasscan_cli::run(&cli, &os_backend::OsBackend, &mut out, &mut log) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(msg) => {
            let _ = out.flush();
            eprintln!("{}", rmasscan_cli::error_text(&msg));
            std::process::ExitCode::FAILURE
        }
    }
}
