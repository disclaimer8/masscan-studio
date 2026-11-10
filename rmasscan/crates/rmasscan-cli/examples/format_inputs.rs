//! Входы эталонов форматов вывода (AGPL-3.0): детерминированные файлы `-oB`, записанные писателем binary rmasscan
//! (порт `out-binary.c` masscan © Robert David Graham) напрямую через форматтер: так пишутся и заголовок с подвалом
//! без записей (`empty`), чего конвейер с ленивым заголовком не делает (`output.c:867–870`).
//!
//! `cargo run -p rmasscan-cli --example format_inputs -- OUTDIR` пишет четыре файла; `tests/golden/formats/inputs/`
//! хранит три маленьких, `many` (1 МиБ) не коммитится. Тот же модуль подключает `tests/formats_golden.rs`: тест
//! сверяет закоммиченные входы и sha256 из манифеста с [`inputs`] и строит `many` на лету.
//!
//! Имена `*.scan.bin`, а не `*.scan` C: расширение `.scan` не входит в список данных языкового сторожа репозитория
//! (`scripts/language-guard.sh`, `allowed_name`).

#![forbid(unsafe_code)]

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;

use rmasscan_cli::output::{
    Counts, FileCtx, Format, Proto, Record, ServiceNames, Status, formatter,
};

/// Время записей `basic`, `many` и `s:` пустого файла.
pub const BASE: u64 = 1_700_000_000;
/// Время записей `edge`: `BASE + 1_388_800` = пятница 2023-12-01 00:00:00 UTC. Однозначный день месяца проверяет
/// пробел `%e` в `%c` C-локали (`# Masscan … scan initiated Fri Dec  1 …` в `-oG`), полночь нули `%H:%M:%S`.
pub const EDGE_BASE: u64 = BASE + 1_388_800;
/// Записей в `many`: больше 65 536, чтобы C и rmasscan напечатали строку прогресса `[+] FILE:    65536\r`.
pub const MANY_RECORDS: u32 = 70_000;

fn rec(ip: [u8; 4], port: u16, status: Status, reason: u8, ttl: u8, timestamp: u64) -> Record {
    Record {
        timestamp,
        ip: Ipv4Addr::from(ip),
        port,
        proto: Proto::Tcp,
        status,
        reason,
        ttl,
        mac: None,
    }
}

/// Восемь записей: open и closed на четырёх адресах, порты 80/443/8080/22.
fn basic() -> Vec<Record> {
    use Status::{Closed, Open};
    vec![
        rec([10, 0, 0, 1], 80, Open, 0x12, 64, BASE),
        rec([10, 0, 0, 1], 443, Closed, 0x14, 64, BASE),
        rec([10, 0, 0, 2], 8080, Open, 0x12, 57, BASE + 1),
        rec([10, 0, 0, 2], 22, Closed, 0x04, 57, BASE + 1),
        rec([10, 0, 0, 3], 22, Open, 0x12, 128, BASE + 2),
        rec([10, 0, 0, 3], 80, Closed, 0x14, 128, BASE + 2),
        rec([192, 0, 2, 7], 443, Open, 0x12, 255, BASE + 3),
        rec([192, 0, 2, 7], 8080, Closed, 0x14, 1, BASE + 3),
    ]
}

/// Границы: порты 0, 65535 и 47001 (нет в services), TTL 0 и 255, флаги 0, 0x04, 0x12, 0x14 и 0xFF, адреса
/// `0.0.0.1` и `255.255.255.255`, время на границах суток.
fn edge() -> Vec<Record> {
    use Status::{Closed, Open};
    vec![
        rec([0, 0, 0, 1], 0, Open, 0x12, 0, EDGE_BASE),
        rec([255, 255, 255, 255], 65535, Closed, 0x14, 255, EDGE_BASE),
        rec([192, 0, 2, 1], 47001, Open, 0x00, 64, EDGE_BASE + 1),
        rec([192, 0, 2, 2], 65535, Open, 0xFF, 255, EDGE_BASE + 1),
        rec([192, 0, 2, 3], 0, Closed, 0x04, 0, EDGE_BASE + 59),
        rec([0, 0, 0, 1], 47001, Closed, 0xFF, 1, EDGE_BASE + 3600),
        rec([255, 255, 255, 255], 0, Open, 0x04, 128, EDGE_BASE + 86_399),
    ]
}

/// [`MANY_RECORDS`] записей с адресов подряд от `10.1.0.0`, порты по кругу 22/80/443/8080, каждая третья closed,
/// по тысяче записей на секунду.
fn many() -> Vec<Record> {
    const PORTS: [u16; 4] = [22, 80, 443, 8080];
    (0..MANY_RECORDS)
        .map(|i| {
            let closed = i % 3 == 2;
            Record {
                timestamp: BASE + u64::from(i / 1000),
                ip: Ipv4Addr::from(0x0A01_0000 + i),
                port: PORTS[i as usize % PORTS.len()],
                proto: Proto::Tcp,
                status: if closed { Status::Closed } else { Status::Open },
                reason: if closed { 0x14 } else { 0x12 },
                ttl: 32 + (i % 200) as u8,
                mac: None,
            }
        })
        .collect()
}

/// Файл `-oB`: заголовок 99 байт с `s:` = время первой записи (как пишет C `--readscan`, `in-binary.c` и
/// `out-binary.c:11–29`; без записей `BASE`), записи по 15 байт, подвал 99 байт.
fn scan_file(records: &[Record]) -> Vec<u8> {
    let started = records.first().map_or(BASE, |r| r.timestamp);
    let services = ServiceNames::empty();
    let cx = FileCtx {
        now: started,
        utc_offset_secs: 0,
        scan_started: started,
        file_opened: started,
        counts: Counts::default(),
        stylesheet: None,
        ports: &[],
        services: &services,
    };
    let mut fm = formatter(Format::Binary).expect("-oB has a formatter");
    let mut out = Vec::new();
    fm.header(&mut out, &cx).expect("write to Vec");
    for r in records {
        fm.record(&mut out, &cx, r).expect("write to Vec");
    }
    fm.footer(&mut out, &cx).expect("write to Vec");
    out
}

/// Имя файла и содержимое каждого входа.
pub fn inputs() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("basic.scan.bin", scan_file(&basic())),
        ("edge.scan.bin", scan_file(&edge())),
        ("many.scan.bin", scan_file(&many())),
        ("empty.scan.bin", scan_file(&[])),
    ]
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [dir] = args.as_slice() else {
        eprintln!("usage: format_inputs OUTDIR");
        return ExitCode::from(2);
    };
    let dir = PathBuf::from(dir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("{}: {e}", dir.display());
        return ExitCode::FAILURE;
    }
    for (name, bytes) in inputs() {
        let path = dir.join(name);
        if let Err(e) = std::fs::write(&path, &bytes) {
            eprintln!("{}: {e}", path.display());
            return ExitCode::FAILURE;
        }
        println!("{} {} bytes", path.display(), bytes.len());
    }
    ExitCode::SUCCESS
}
