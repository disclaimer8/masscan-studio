//! Входы эталонов форматов вывода (AGPL-3.0): детерминированные файлы `-oB`, записанные писателем binary rmasscan
//! (порт `out-binary.c` masscan © Robert David Graham) напрямую через форматтер: так пишутся и заголовок с подвалом
//! без записей (`empty`), чего конвейер с ленивым заголовком не делает (`output.c:867–870`).
//!
//! `cargo run -p rmasscan-cli --example format_inputs -- OUTDIR` пишет восемь файлов; `tests/golden/formats/inputs/`
//! хранит семь маленьких, `many` (1 МиБ) не коммитится. Тот же модуль подключает `tests/formats_golden.rs`: тест
//! сверяет закоммиченные входы и sha256 из манифеста с [`inputs`] и строит `many` на лету. Входы с баннерами
//! (`banners`, `banners-legacy`) пишет тот же форматтер (`Formatter::banner`), устаревшие типы 3/4/5 это готовые
//! байты.
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
use rmasscan_proto::BannerRecord;

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

/// Время записей `banners`: `BASE + 21_600`, через шесть часов после `basic`.
pub const BANNERS_BASE: u64 = BASE + 21_600;
/// Время записей `banners-legacy`: `BASE + 28_800`.
pub const LEGACY_BASE: u64 = BASE + 28_800;

/// Запись входа с баннерами: статус и баннер пишет писатель `-oB` rmasscan (типы 6/7/10/11 и 9/13,
/// `out-binary.c:103-355`), `Raw` это готовые байты записи (устаревшие типы 3/4/5, которых не пишет ни C, ни rmasscan).
enum Item {
    Status(Record),
    Banner(BannerRecord),
    Raw(Vec<u8>),
}

fn banner(ip: &str, ip_proto: u8, port: u16, app: u16, ttl: u8, at: u64, px: &[u8]) -> Item {
    Item::Banner(BannerRecord {
        timestamp: BANNERS_BASE + at,
        ip: ip.parse::<IpAddr>().expect("address literal"),
        ip_proto,
        port,
        app,
        ttl,
        payload: px.to_vec(),
    })
}

fn status(proto: Proto, ip: &str, port: u16, status: Status, reason: u8, ttl: u8, at: u64) -> Item {
    Item::Status(Record {
        timestamp: BANNERS_BASE + at,
        ip: ip.parse::<IpAddr>().expect("address literal"),
        port,
        proto,
        status,
        reason,
        ttl,
        mac: None,
    })
}

/// Баннеры IPv4 и IPv6 вперемешку со статусом (справка C2): номера приложений 0..=36, 37 и 65535 (`(N)`),
/// `ip_proto` 0, 1, 6, 17, 132 и 99 (`arp`, `icmp`, …, `err`), все 256 байтов в полезной нагрузке (оба нормализатора),
/// экранируемые `< > & " ' \`, `cert:` длиной 5 и больше (снятие у certs), пустые баннеры, длина `-oB` в один и два
/// байта (113/114 у IPv4, 100/101 у IPv6), 16 369 байт (самая длинная запись IPv4: усечение текста до 8190 с «дырами»
/// и JSON за буфером 65 536), app 6 у не-UDP (XML `syn-ack`), TTL 0 и 255. Порты 80 и 443 только у TCP: фильтр `-p`
/// здесь значит одно и то же у C (несдвинутый порт) и у rmasscan (Р5), адреса из RFC 5737 и RFC 3849.
fn banners() -> Vec<Item> {
    use Proto::{Tcp, Udp};
    use Status::{Closed, Open};
    let all: Vec<u8> = (0..=255u8).collect();
    let text = |n: usize| -> Vec<u8> { (0..n).map(|i| b'a' + (i % 26) as u8).collect() };
    let cyc: Vec<u8> = (0..16_369u32).map(|i| i as u8).collect();
    let mut v = vec![
        status(Tcp, "192.0.2.20", 80, Open, 0x12, 64, 0),
        banner(
            "192.0.2.20",
            6,
            80,
            4,
            64,
            1,
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        ),
        status(Udp, "192.0.2.21", 53, Open, 0x00, 57, 1),
        banner("192.0.2.21", 17, 53, 6, 57, 1, b"9.18.24"),
        status(Tcp, "2001:db8::20", 443, Open, 0x12, 60, 2),
        banner("2001:db8::20", 6, 443, 9, 60, 2, &all),
        banner("192.0.2.22", 6, 8080, 4, 128, 3, &all),
        status(Tcp, "192.0.2.22", 443, Closed, 0x14, 128, 3),
    ];
    const PROTOS: [u8; 6] = [6, 17, 132, 1, 0, 99];
    let apps: Vec<u16> = (0..=37).chain([65535]).collect();
    for (i, &app) in apps.iter().enumerate() {
        let px: Vec<u8> = match app {
            15 => b"cert:MIIBszCCAVmgAwIBAgIJ".to_vec(),
            16 => b"cert:".to_vec(),
            17 => b"<title>A & B \"q\" 'x' \\ </title>".to_vec(),
            _ => format!("banner-{app}").into_bytes(),
        };
        let ip = format!("198.51.100.{}", i + 1);
        let ttl = if app == 65535 { 255 } else { i as u8 };
        v.push(banner(
            &ip,
            PROTOS[i % PROTOS.len()],
            1000 + i as u16,
            app,
            ttl,
            4 + i as u64 / 8,
            &px,
        ));
    }
    for (i, app) in [2u16, 3, 23, 33, 36, 37].into_iter().enumerate() {
        let ip = format!("2001:db8:1::{}", i + 1);
        let px = format!("v6-{app}");
        v.push(banner(
            &ip,
            PROTOS[i],
            2000 + i as u16,
            app,
            64,
            10,
            px.as_bytes(),
        ));
    }
    v.extend([
        banner("192.0.2.23", 17, 123, 19, 64, 11, b""),
        banner("2001:db8::53", 17, 53, 6, 64, 11, b""),
        banner("192.0.2.24", 6, 8081, 31, 64, 12, &text(113)),
        banner("192.0.2.24", 6, 8081, 31, 64, 12, &text(114)),
        banner("2001:db8::24", 6, 8081, 31, 0, 12, &text(100)),
        banner("2001:db8::24", 6, 8081, 31, 0, 12, &text(101)),
        banner("192.0.2.25", 6, 8443, 18, 64, 13, &cyc),
        status(Tcp, "2001:db8::25", 8443, Open, 0x12, 64, 13),
    ]);
    v
}

/// Семибитный varint длины записи (`in-binary.c:557-570`).
fn varint(mut n: usize) -> Vec<u8> {
    let mut v = vec![(n & 0x7F) as u8];
    n >>= 7;
    while n > 0 {
        v.insert(0, (n & 0x7F) as u8 | 0x80);
        n >>= 7;
    }
    v
}

/// Устаревшая запись 3, 4 или 5 (`in-binary.c:339-409`). Тело типа 3: время, адрес, порт, app, баннер; 4 и 5:
/// время, адрес, протокол, порт, app, баннер. У типа 4 длина на единицу меньше тела: последний байт C дочитывает
/// отдельно (`:595-602`), при теле из 13 байт это младший байт app.
fn legacy(ty: u8, ip: [u8; 4], proto: u8, port: u16, app: u16, at: u64, px: &[u8]) -> Item {
    let mut body = ((LEGACY_BASE + at) as u32).to_be_bytes().to_vec();
    body.extend_from_slice(&ip);
    if ty != 3 {
        body.push(proto);
    }
    body.extend_from_slice(&port.to_be_bytes());
    body.extend_from_slice(&app.to_be_bytes());
    body.extend_from_slice(px);
    let mut v = vec![ty];
    v.extend(varint(body.len() - usize::from(ty == 4)));
    v.extend(body);
    Item::Raw(v)
}

/// Устаревшие баннеры 3, 4 и 5 с корректными телами (C читает их, но не пишет: `-oB` переписывает их типом 9) и, для
/// фильтров, по одной записи статуса (6) и баннера (9): у 3/4/5 фильтров нет (`in-binary.c:592-603`).
fn banners_legacy() -> Vec<Item> {
    let at = |s: u64| LEGACY_BASE + s;
    vec![
        legacy(3, [10, 3, 0, 1], 0, 22, 2, 0, b"SSH-2.0-OpenSSH_9.6"),
        legacy(3, [10, 3, 0, 2], 0, 80, 4, 1, b""),
        legacy(4, [10, 4, 0, 1], 17, 53, 6, 2, b"9.18.24"),
        legacy(4, [10, 4, 0, 2], 6, 443, 9, 3, b""),
        legacy(5, [10, 5, 0, 1], 17, 161, 7, 4, b"sysDescr:Linux"),
        legacy(5, [10, 5, 0, 2], 99, 7, 37, 5, b"x"),
        legacy(5, [10, 5, 0, 3], 132, 2905, 65535, 6, &[b'z'; 120]),
        Item::Status(Record {
            timestamp: at(7),
            ip: Ipv4Addr::new(192, 0, 2, 40).into(),
            port: 80,
            proto: Proto::Tcp,
            status: Status::Open,
            reason: 0x12,
            ttl: 64,
            mac: None,
        }),
        Item::Banner(BannerRecord {
            timestamp: at(7),
            ip: Ipv4Addr::new(192, 0, 2, 40).into(),
            ip_proto: 6,
            port: 80,
            app: 4,
            ttl: 64,
            payload: b"HTTP/1.0 200".to_vec(),
        }),
        legacy(3, [10, 3, 0, 3], 0, 443, 15, 8, b"cert:MIIB"),
    ]
}

/// Время записи входа с баннерами (у `Raw` из байтов тела).
fn item_time(it: &Item) -> u64 {
    match it {
        Item::Status(r) => r.timestamp,
        Item::Banner(b) => b.timestamp,
        Item::Raw(v) => {
            let skip = 1 + v[1..].iter().take_while(|&&b| b & 0x80 != 0).count() + 1;
            u64::from(u32::from_be_bytes([
                v[skip],
                v[skip + 1],
                v[skip + 2],
                v[skip + 3],
            ]))
        }
    }
}

/// Файл `-oB` из записей статуса, баннеров и готовых байтов (см. [`scan_file`]).
fn mixed_file(items: &[Item]) -> Vec<u8> {
    let started = items.first().map_or(BASE, item_time);
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
    for it in items {
        match it {
            Item::Status(r) => fm.record(&mut out, &cx, r).expect("write to Vec"),
            Item::Banner(b) => fm.banner(&mut out, &cx, b).expect("write to Vec"),
            Item::Raw(v) => out.extend_from_slice(v),
        }
    }
    fm.footer(&mut out, &cx).expect("write to Vec");
    out
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
        ("banners.scan.bin", mixed_file(&banners())),
        ("banners-legacy.scan.bin", mixed_file(&banners_legacy())),
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
