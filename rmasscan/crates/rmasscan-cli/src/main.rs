//! Заглушка CLI порта masscan. Реальные опции появятся на этапе 1.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version") => {
            println!(
                "rmasscan {} (порт masscan {})",
                env!("CARGO_PKG_VERSION"),
                rmasscan_core::ORACLE_MASSCAN_VERSION
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: rmasscan --version");
            ExitCode::FAILURE
        }
    }
}
