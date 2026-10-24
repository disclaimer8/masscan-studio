//! Приёмка Windows на проводе (этап 2B-Windows, задача 4A): проверка артефактов.
//!
//! Вердикт выносит офлайн-проверяльщик `scripts/windows_wire_verify.py` (stdlib Python, без Npcap, VM и
//! стенда; повторно использует сравнение SYN-потоков `verify-wire.py`). Он читает manifest, run.json,
//! pcap и метаданные захвата, и работает на Mac/Linux/Windows. Отсутствие manifest/pcap (NOT RUN), неполный
//! или недоказанный захват (INVALID) и расхождение поведения (FAIL) никогда не дают PASS.
//!
//! * `offline_verifier_*` обычные тесты: самопроверка проверяльщика и чистых частей оркестратора на
//!   синтетических артефактах (каждый негативный случай ломает ровно одно условие).
//! * `lab_*` помечены `#[ignore]`: нужен каталог сырых данных стенда
//!   (`RMASSCAN_WINWIRE_RESULTS=<…/functional>`). Если он не задан, тест ПАДАЕТ с «NOT RUN»,
//!   а не проходит молча.
//!
//! Сам прогон на стенде: `scripts/windows-wire-suite.py` (оркестратор), `scripts/windows-oracle-fixtures.py`
//! (эталоны C для того же binding). Python берётся как `python3` (на Windows-VM его нет: офлайн-тест там
//! не собирается, артефакты проверяются на Mac/Linux).
#![cfg(not(windows))]

use std::path::PathBuf;
use std::process::Command;

fn scripts() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts")
}

fn python(args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::new("python3")
        .arg("-I")
        .args(args)
        .output()
        .expect("NOT RUN: python3 is required for the offline Windows wire verifier")
}

#[test]
fn offline_verifier_self_tests_pass() {
    let t = scripts().join("tests/test_windows_wire.py");
    let out = python(&[t.as_os_str()]);
    assert!(
        out.status.success(),
        "verifier self-tests failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn offline_verifier_never_passes_an_empty_or_missing_directory() {
    let v = scripts().join("windows_wire_verify.py");
    let missing = std::env::temp_dir().join(format!("winwire_missing_{}", std::process::id()));
    let out = python(&[v.as_os_str(), "--dir".as_ref(), missing.as_os_str()]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success(),
        "a missing directory must not pass: {text}"
    );
    assert!(text.contains("NOT RUN"), "{text}");
    assert!(!text.contains("overall: PASS"), "{text}");
}

#[test]
#[ignore = "stand artifacts: set RMASSCAN_WINWIRE_RESULTS (see module docs)"]
fn lab_functional_and_pause_resume_artifacts_verify() {
    let dir = std::env::var("RMASSCAN_WINWIRE_RESULTS")
        .expect("NOT RUN: set RMASSCAN_WINWIRE_RESULTS to the functional evidence directory");
    let v = scripts().join("windows_wire_verify.py");
    let out = python(&[v.as_os_str(), "--dir".as_ref(), dir.as_ref()]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stand artifacts did not verify:\n{text}"
    );
    assert!(text.contains("overall: PASS"), "{text}");
}
