//! Входы эталонов форматов вывода (AGPL-3.0): детерминированные файлы `-oB`, записанные писателем binary rmasscan
//! (порт `out-binary.c` masscan © Robert David Graham) напрямую через форматтер: так пишутся и заголовок с подвалом
//! без записей (`empty`), чего конвейер с ленивым заголовком не делает (`output.c:867–870`).
//!
//! `cargo run -p rmasscan-cli --example format_inputs -- OUTDIR` пишет шесть файлов; `tests/golden/formats/inputs/`
//! хранит пять маленьких, `many` (1 МиБ) не коммитится. Тот же модуль подключает `tests/formats_golden.rs`: тест
//! сверяет закоммиченные входы и sha256 из манифеста с [`inputs`] и строит `many` на лету.
//!
//! Имена `*.scan.bin`, а не `*.scan` C: расширение `.scan` не входит в список данных языкового сторожа репозитория
//! (`scripts/language-guard.sh`, `allowed_name`).

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
        ip: Ipv4Addr::from(ip).into(),
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

/// Время записей `protocols`: `BASE + 7_200`, через два часа после `basic`.
pub const PROTOCOLS_BASE: u64 = BASE + 7_200;

/// Запись протокола `proto` (UDP, SCTP, ICMP или TCP): типы `6`/`7` `-oB` с `ip_proto` 1/6/17/132, которые C
/// умеет и писать, и читать (`out-binary.c:154–211`, `in-binary.c:100–150`). ARP (тип `8`) C не читает, его
/// покрывают юнит-тесты `readscan`.
fn proto_rec(
    proto: Proto,
    ip: [u8; 4],
    port: u16,
    status: Status,
    reason: u8,
    ttl: u8,
    at: u64,
) -> Record {
    Record {
        proto,
        ..rec(ip, port, status, reason, ttl, PROTOCOLS_BASE + at)
    }
}

/// Не-TCP записи, как их пишет живой скан, вперемешку с TCP: UDP open (порт из services и порт без записи), UDP
/// closed из ICMP 3/3 (reason 0, TTL внешнего заголовка), SCTP open (INIT-ACK) и closed (ABORT), ICMP Echo open
/// (порт 0), TCP open/closed по флагам и TCP closed из ICMP 3/3 (reason 0). Адреса из TEST-NET-1/2/3 (RFC 5737).
fn protocols() -> Vec<Record> {
    use Proto::{Icmp, Sctp, Tcp, Udp};
    use Status::{Closed, Open};
    vec![
        proto_rec(Tcp, [192, 0, 2, 10], 80, Open, 0x12, 64, 0),
        proto_rec(Udp, [192, 0, 2, 10], 53, Open, 0x00, 64, 0),
        proto_rec(Udp, [192, 0, 2, 11], 59999, Open, 0x00, 63, 1),
        proto_rec(Udp, [192, 0, 2, 11], 161, Closed, 0x00, 63, 1),
        proto_rec(Udp, [192, 0, 2, 12], 500, Closed, 0x00, 62, 2),
        proto_rec(Tcp, [192, 0, 2, 12], 443, Closed, 0x14, 62, 2),
        proto_rec(Tcp, [192, 0, 2, 12], 8080, Closed, 0x00, 62, 3),
        proto_rec(Sctp, [198, 51, 100, 5], 2905, Open, 0x00, 64, 3),
        proto_rec(Sctp, [198, 51, 100, 5], 2906, Closed, 0x00, 64, 4),
        proto_rec(Icmp, [198, 51, 100, 6], 0, Open, 0x00, 128, 4),
        proto_rec(Icmp, [203, 0, 113, 9], 0, Open, 0x00, 255, 5),
        proto_rec(Udp, [203, 0, 113, 9], 123, Open, 0x00, 255, 5),
    ]
}

/// Время записей `ipv6`: `BASE + 14_400`, через четыре часа после `basic`.
pub const IPV6_BASE: u64 = BASE + 14_400;

/// Запись IPv6 (тип 10/11 `-oB`, 28 байт, `out-binary.c:103-149`) протокола `proto`.
fn rec6(proto: Proto, ip: &str, port: u16, status: Status, reason: u8, ttl: u8, at: u64) -> Record {
    Record {
        timestamp: IPV6_BASE + at,
        ip: IpAddr::V6(ip.parse::<Ipv6Addr>().expect("IPv6 literal")),
        port,
        proto,
        status,
        reason,
        ttl,
        mac: None,
    }
}

/// Записи IPv6 вперемешку с IPv4 (порядок файла сохраняется): адреса RFC 3849 с каждым случаем `ipv6address_fmt`
/// (`massip-addr.c:33-109`: сжимается первая серия нулей, а не самая длинная, у `Ipv6Addr::Display` наоборот:
/// `2001:db8:0:1::1` у него, `2001:db8::1:0:0:0:1` у C), `::`, `::1`, `fe80::1`, `ffff:…:ffff`, отображённый IPv4 и
/// старшая половина без младшей; TCP open и closed, UDP, SCTP и ICMP, порты 0 и 65535, TTL 0 и 255.
fn ipv6() -> Vec<Record> {
    use Proto::{Icmp, Sctp, Tcp, Udp};
    use Status::{Closed, Open};
    vec![
        rec6(Tcp, "2001:db8::1", 80, Open, 0x12, 64, 0),
        rec([192, 0, 2, 1], 80, Open, 0x12, 64, IPV6_BASE),
        rec6(Tcp, "2001:db8:0:1:0:0:0:1", 443, Closed, 0x14, 57, 0),
        rec6(Tcp, "2001:db8:0:0:1:0:0:1", 22, Open, 0x12, 128, 1),
        rec6(Tcp, "::", 0, Open, 0x12, 0, 1),
        rec6(Tcp, "::1", 65535, Closed, 0x04, 255, 2),
        rec([192, 0, 2, 2], 443, Closed, 0x14, 64, IPV6_BASE + 2),
        rec6(Tcp, "fe80::1", 8080, Open, 0x00, 64, 3),
        rec6(
            Tcp,
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            47001,
            Open,
            0xFF,
            1,
            3,
        ),
        rec6(Tcp, "::ffff:192.0.2.1", 25, Closed, 0x14, 62, 4),
        rec6(Tcp, "2001:db8::", 53, Open, 0x12, 60, 4),
        rec6(Udp, "2001:db8::53", 53, Open, 0x00, 64, 5),
        rec6(Udp, "2001:db8:1::1", 161, Closed, 0x00, 63, 5),
        rec6(Sctp, "2001:db8:2::2905", 2905, Open, 0x00, 64, 6),
        rec6(Icmp, "2001:db8:3::1", 0, Open, 0x00, 128, 7),
        rec([192, 0, 2, 3], 22, Open, 0x12, 57, IPV6_BASE + 7),
        rec6(Tcp, "2a03:9060:0:400::2", 443, Open, 0x12, 57, 8),
        rec6(Tcp, "2a03:9060:0:400::2", 22, Closed, 0x14, 57, 8),
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
                ip: Ipv4Addr::from(0x0A01_0000 + i).into(),
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
/// `out-binary.c:11–29`; без записей `BASE`), записи по 15 байт (IPv4) и по 28 (IPv6), подвал 99 байт.
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
        ("protocols.scan.bin", scan_file(&protocols())),
        ("ipv6.scan.bin", scan_file(&ipv6())),
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
