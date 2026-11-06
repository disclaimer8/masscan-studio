//! Чтение `-oB` и операция `--readscan` (AGPL-3.0). Порт `in-binary.c` (`_binaryfile_parse` :470–640,
//! `parse_status2` :100–150, `readscan_binary_scanfile` :650–691) masscan © Robert David Graham. Читается только
//! то, что пишет `-oB` этой версии: записи типа 6/7 (TCP IPv4) и подвал `'m'`. Остальные типы C (баннеры, IPv6,
//! ARP, устаревшие 1/2) дают ошибку `Unsupported` (Р13), а не молчаливый пропуск.
//!
//! Записи уходят в [`Pipeline::report_record`] со своим исходным временем (никогда не штампуются заново).
//! Начало скана `s:` берётся из первой записи, как `when_scan_started` C (`in-binary.c:65`).

use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::Ipv4Addr;

use rmasscan_core::config::ScanConfig;
use rmasscan_core::massip::MassIp;

use crate::output::{Pipeline, Record, Sink, Status, io_fail};

/// `BUF_MAX` C: наибольшая длина тела записи.
const BUF_MAX: u64 = 1024 * 1024;
/// `'a' + 2`: размер заголовка и подвала.
const BLOCK: usize = 99;
const MAGIC: &[u8] = b"masscan/1.1";

#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    /// Нет префикса `masscan/1.1`.
    NotMasscan,
    /// Пустая строка значит просто `file corrupt`; иначе уточнение (`unknown type N`).
    Corrupt(String),
    /// Тип записи, которого этот читатель не умеет (баннеры, IPv6, ARP, v1).
    Unsupported(u64),
    /// Запись типа 6/7 с протоколом не TCP.
    UnsupportedProtocol(u8),
}

impl fmt::Display for ReadError {
    /// Текст без `[-] ` и без имени файла: их добавляет [`run_readscan`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Io(e) => write!(f, "{e}"),
            ReadError::NotMasscan => f.write_str("unknown file format (expected \"masscan/1.1\")"),
            ReadError::Corrupt(s) if s.is_empty() => f.write_str("file corrupt"),
            ReadError::Corrupt(s) => write!(f, "file corrupt: {s}"),
            ReadError::Unsupported(t) => write!(f, "unsupported record type {t}"),
            ReadError::UnsupportedProtocol(p) => write!(f, "unsupported record protocol {p}"),
        }
    }
}

impl ReadError {
    /// Строка stderr в форме C: у `file corrupt` имени файла нет, у остальных есть.
    fn log_line(&self, file: &str) -> String {
        match self {
            ReadError::Corrupt(_) => format!("[-] {self}\n"),
            _ => format!("[-] {file}: {self}\n"),
        }
    }
}

fn corrupt() -> ReadError {
    ReadError::Corrupt(String::new())
}

/// Читает до `buf.len()` байт; меньше только на конце файла.
fn read_up_to(r: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Семибитный varint C: бит 7 значит «есть следующий байт». `Ok(None)` только если файл кончился до первого
/// байта; конец посреди числа это `Corrupt`.
fn read_varint(r: &mut dyn Read) -> Result<Option<u64>, ReadError> {
    let mut value = 0u64;
    for i in 0..9 {
        let mut b = [0u8; 1];
        if read_up_to(r, &mut b).map_err(ReadError::Io)? == 0 {
            return if i == 0 { Ok(None) } else { Err(corrupt()) };
        }
        value = (value << 7) | u64::from(b[0] & 0x7F);
        if b[0] & 0x80 == 0 {
            return Ok(Some(value));
        }
    }
    Err(corrupt())
}

/// Читает записи типа 6/7 из файла `-oB`. `f` получает каждую; его ошибка прерывает чтение.
pub fn read_records(
    r: &mut dyn Read,
    f: &mut dyn FnMut(Record) -> Result<(), String>,
) -> Result<(), ReadError> {
    read_records_counted(r, f, &mut |_| {})
}

/// То же, с обратным вызовом после каждой записи (в том числе `'m'`) с общим числом: для строки прогресса.
fn read_records_counted(
    r: &mut dyn Read,
    f: &mut dyn FnMut(Record) -> Result<(), String>,
    progress: &mut dyn FnMut(u64),
) -> Result<(), ReadError> {
    let mut head = [0u8; BLOCK];
    let n = read_up_to(r, &mut head).map_err(ReadError::Io)?;
    let cmp = n.min(MAGIC.len());
    if n == 0 || head[..cmp] != MAGIC[..cmp] {
        return Err(ReadError::NotMasscan);
    }
    if n < BLOCK {
        return Err(corrupt());
    }
    let mut total = 0u64;
    while let Some(ty) = read_varint(r)? {
        let len = read_varint(r)?.ok_or_else(corrupt)?;
        if len > BUF_MAX {
            return Err(corrupt());
        }
        let mut body = vec![0u8; len as usize];
        if read_up_to(r, &mut body).map_err(ReadError::Io)? < body.len() {
            return Err(corrupt());
        }
        match ty {
            6 | 7 => {
                // `parse_status2`: тело короче 13 байт молча пропускается.
                if body.len() >= 13 {
                    if body[8] != 6 {
                        return Err(ReadError::UnsupportedProtocol(body[8]));
                    }
                    f(Record {
                        timestamp: u64::from(u32::from_be_bytes([
                            body[0], body[1], body[2], body[3],
                        ])),
                        ip: Ipv4Addr::new(body[4], body[5], body[6], body[7]),
                        port: u16::from_be_bytes([body[9], body[10]]),
                        status: if ty == 6 {
                            Status::Open
                        } else {
                            Status::Closed
                        },
                        reason: body[11],
                        ttl: body[12],
                    })
                    .map_err(|e| ReadError::Io(io::Error::other(e)))?;
                }
            }
            // `case 'm'`: подвал.
            0x6D => {}
            1..=5 | 8..=13 => return Err(ReadError::Unsupported(ty)),
            _ => return Err(ReadError::Corrupt(format!("unknown type {ty}"))),
        }
        total += 1;
        progress(total);
    }
    Ok(())
}

/// Фильтр целей `--readscan` (`filter->count_ipv4s`, `count_ports` в `parse_status2`).
pub struct ReadFilter {
    pub targets: MassIp,
    pub by_ip: bool,
    pub by_port: bool,
}

impl ReadFilter {
    /// Копия целей за вычетом исключений. `optimize` нужен только для `count_*`: `has_ip`/`has_port` ищут линейно
    /// и порядка не требуют.
    pub fn from_config(cfg: &ScanConfig) -> ReadFilter {
        let mut excludes = cfg.excludes.clone();
        let mut targets = cfg.targets.clone();
        targets.apply_excludes(&mut excludes);
        targets.optimize();
        ReadFilter {
            by_ip: targets.count_ipv4s() > 0,
            by_port: targets.count_ports() > 0,
            targets,
        }
    }

    pub fn keeps(&self, r: &Record) -> bool {
        (!self.by_ip || self.targets.has_ip(u32::from(r.ip)))
            && (!self.by_port || self.targets.has_port(u32::from(r.port)))
    }
}

/// `readscan_binary_scanfile`: файлы по порядку в один вывод. На первой ошибке пишет текст C в `log`, всё равно
/// закрывает вывод (`sink.finish()` даёт подвал) и возвращает `Err`.
pub fn run_readscan(
    files: &[String],
    filter: &ReadFilter,
    sink: &mut Pipeline,
    log: &mut dyn Write,
) -> Result<(), String> {
    sink.open()?;
    let mut failure: Option<String> = None;
    for name in files {
        if let Err(msg) = read_one(name, filter, sink, log) {
            failure = Some(msg);
            break;
        }
    }
    let closed = sink.finish();
    match failure {
        Some(msg) => Err(msg),
        None => closed,
    }
}

fn read_one(
    name: &str,
    filter: &ReadFilter,
    sink: &mut Pipeline,
    log: &mut dyn Write,
) -> Result<(), String> {
    log.write_all(format!("[+] --readscan {name}\n").as_bytes())
        .map_err(io_fail)?;
    let file = match File::open(name) {
        Ok(f) => f,
        Err(e) => {
            log.write_all(format!("[-] FAIL: --readscan\n[-] {name}: {e}\n").as_bytes())
                .map_err(io_fail)?;
            return Err(format!("{name}: {e}"));
        }
    };
    let mut reader = BufReader::new(file);
    let mut sink_failure: Option<String> = None;
    let mut log_failure: Option<io::Error> = None;
    let res = read_records_counted(
        &mut reader,
        &mut |rec: Record| {
            sink.set_scan_started_if_unset(rec.timestamp);
            if filter.keeps(&rec) {
                sink.report_record(&rec).inspect_err(|e| {
                    sink_failure = Some(e.clone());
                })?;
            }
            Ok(())
        },
        &mut |n| {
            if n & 0xFFFF == 0
                && let Err(e) = log.write_all(format!("[+] {name}: {n:8}\r").as_bytes())
            {
                log_failure.get_or_insert(e);
            }
        },
    );
    if let Some(msg) = sink_failure {
        return Err(msg);
    }
    if let Some(e) = log_failure {
        return Err(io_fail(e));
    }
    if let Err(e) = res {
        log.write_all(e.log_line(name).as_bytes())
            .map_err(io_fail)?;
        return Err(format!("{name}: {e}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{Format, OutputEnv, OutputOptions, Wall, services};
    use rmasscan_core::targets::{add_target_string, parse_ports};
    use std::path::PathBuf;

    struct FakeWall(u64);
    impl Wall for FakeWall {
        fn unix_time(&self) -> u64 {
            self.0
        }
        fn utc_offset_secs(&self, _: u64) -> i32 {
            0
        }
    }

    fn rec(ts: u64, ip: [u8; 4], port: u16, status: Status) -> Record {
        Record {
            timestamp: ts,
            ip: Ipv4Addr::from(ip),
            port,
            status,
            reason: if status == Status::Open { 0x12 } else { 0x14 },
            ttl: 57,
        }
    }

    fn recs3() -> Vec<Record> {
        vec![
            rec(1_700_000_001, [10, 0, 0, 1], 80, Status::Open),
            rec(1_700_000_002, [10, 0, 0, 2], 443, Status::Closed),
            rec(1_700_000_003, [192, 168, 1, 1], 22, Status::Open),
        ]
    }

    fn opts(format: Format) -> OutputOptions {
        OutputOptions {
            format,
            filename: Some("-".into()),
            show_closed: true,
            ..OutputOptions::default()
        }
    }

    /// Файл `-oB`, собранный настоящим писателем конвейера.
    fn make_bin(recs: &[Record]) -> Vec<u8> {
        let wall = FakeWall(1_800_000_000);
        let mut out = Vec::new();
        {
            let env = OutputEnv {
                wall: &wall,
                services: services::empty(),
                tcp_ports: Vec::new(),
                scan_started: None,
            };
            let mut p = Pipeline::new(opts(Format::Binary), &mut out, env);
            p.open().unwrap();
            for r in recs {
                p.report_record(r).unwrap();
            }
            p.finish().unwrap();
        }
        out
    }

    fn read_all(bytes: &[u8]) -> (Vec<Record>, Result<(), ReadError>) {
        let mut got = Vec::new();
        let res = read_records(&mut &bytes[..], &mut |r| {
            got.push(r);
            Ok(())
        });
        (got, res)
    }

    fn tmp_file(name: &str, bytes: &[u8]) -> String {
        let p: PathBuf =
            std::env::temp_dir().join(format!("rmasscan-readscan-{}-{name}", std::process::id()));
        std::fs::write(&p, bytes).unwrap();
        p.to_string_lossy().into_owned()
    }

    fn no_filter() -> ReadFilter {
        ReadFilter::from_config(&ScanConfig::default())
    }

    /// Прогоняет `--readscan` в выбранный формат; возвращает (stdout, stderr, результат).
    fn convert(
        files: &[String],
        format: Format,
        filter: &ReadFilter,
    ) -> (Vec<u8>, String, Result<(), String>) {
        let wall = FakeWall(1_800_000_000);
        let mut out = Vec::new();
        let mut log = Vec::new();
        let res;
        {
            let env = OutputEnv {
                wall: &wall,
                services: services::empty(),
                tcp_ports: Vec::new(),
                scan_started: Some(0),
            };
            let mut p = Pipeline::new(opts(format), &mut out, env);
            res = run_readscan(files, filter, &mut p, &mut log);
        }
        (out, String::from_utf8(log).unwrap(), res)
    }

    fn record_bytes(ty: u8, len: u8, proto: u8) -> Vec<u8> {
        let mut b = vec![ty, len, 0x65, 0, 0, 1, 1, 2, 3, 4, proto, 0, 80, 0x12, 57];
        b.truncate(2 + len as usize);
        b
    }

    fn with_header(tail: &[u8]) -> Vec<u8> {
        let mut v = b"masscan/1.1\ns:1\n".to_vec();
        v.resize(BLOCK, 0);
        v.extend_from_slice(tail);
        v
    }

    #[test]
    fn roundtrip_status_records() {
        let (got, res) = read_all(&make_bin(&recs3()));
        res.unwrap();
        assert_eq!(got, recs3());
    }

    #[test]
    fn footer_is_skipped_as_m_record() {
        let bin = make_bin(&recs3()[..1]);
        // Заголовок 99 + запись 15 + подвал 99; подвал это запись 'm' (0x6D) длиной 'a' (0x61).
        assert_eq!(bin.len(), BLOCK + 15 + BLOCK);
        let mut foot = b"masscan/1.1".to_vec();
        foot.resize(BLOCK, 0);
        assert_eq!(bin[BLOCK + 15..], foot[..]);
        assert_eq!(foot[..2], [b'm', b'a']);
        let (got, res) = read_all(&bin);
        res.unwrap();
        assert_eq!(got.len(), 1);
        // Файл из одного заголовка и подвала: записей нет, ошибки нет.
        let mut f = with_header(&[]);
        f.extend_from_slice(&foot);
        let (got, res) = read_all(&f);
        res.unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn header_must_be_masscan_1_1() {
        let mut bad = b"nmap scan output".to_vec();
        bad.resize(BLOCK, 0);
        assert!(matches!(read_all(&bad).1, Err(ReadError::NotMasscan)));
        assert!(matches!(read_all(b"nmap").1, Err(ReadError::NotMasscan)));
        assert!(matches!(read_all(b"").1, Err(ReadError::NotMasscan)));
        // Правильный префикс, но файл короче 99 байт.
        assert!(matches!(
            read_all(b"masscan/1.1\n").1,
            Err(ReadError::Corrupt(_))
        ));
    }

    #[test]
    fn unsupported_types_are_errors() {
        for t in [1u8, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13] {
            let f = with_header(&[t, 0]);
            match read_all(&f).1 {
                Err(ReadError::Unsupported(n)) => assert_eq!(n, u64::from(t)),
                other => panic!("type {t}: {other:?}"),
            }
        }
        let f = with_header(&record_bytes(6, 13, 17));
        match read_all(&f).1 {
            Err(e @ ReadError::UnsupportedProtocol(17)) => {
                assert_eq!(e.to_string(), "unsupported record protocol 17")
            }
            other => panic!("{other:?}"),
        }
        let f = with_header(&record_bytes(7, 13, 132));
        assert!(matches!(
            read_all(&f).1,
            Err(ReadError::UnsupportedProtocol(132))
        ));
    }

    #[test]
    fn short_status_body_is_skipped_like_c() {
        let mut tail = vec![6, 2, 0, 0];
        tail.extend_from_slice(&record_bytes(6, 13, 6));
        let (got, res) = read_all(&with_header(&tail));
        res.unwrap();
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn varint_type_and_length_use_seven_bit_groups() {
        // Тип 6 и длина 13, каждое в двух байтах: 0x80 (ноль, продолжение) и значение.
        let mut tail = vec![0x80, 6, 0x80, 13];
        tail.extend_from_slice(&record_bytes(6, 13, 6)[2..]);
        let (got, res) = read_all(&with_header(&tail));
        res.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].port, 80);
    }

    #[test]
    fn corrupt_inputs_finish_output_and_fail() {
        let good = make_bin(&recs3()[..1]);
        // Заголовок и одна запись, без подвала.
        let ok_prefix = good[..BLOCK + 15].to_vec();
        let mut cases: Vec<(&str, Vec<u8>, &str)> = Vec::new();
        cases.push(("short", good[..50].to_vec(), "[-] file corrupt\n"));
        let mut trunc = ok_prefix.clone();
        trunc.extend_from_slice(&record_bytes(6, 13, 6)[..9]);
        cases.push(("trunc", trunc, "[-] file corrupt\n"));
        // Длина 0xC0 0x80 0x01 = (0x40 << 14) | 1 = 1 MiB + 1.
        let mut big = ok_prefix.clone();
        big.extend_from_slice(&[6, 0xC0, 0x80, 0x01]);
        cases.push(("big", big, "[-] file corrupt\n"));
        let mut unk = ok_prefix.clone();
        unk.extend_from_slice(&[0x7E, 0]);
        cases.push(("unk", unk, "[-] file corrupt: unknown type 126\n"));
        let mut uns = ok_prefix.clone();
        uns.extend_from_slice(&[9, 0]);
        cases.push(("uns", uns, ": unsupported record type 9\n"));
        for (name, bytes, expect) in cases {
            let path = tmp_file(name, &bytes);
            let (out, log, res) = convert(std::slice::from_ref(&path), Format::Json, &no_filter());
            assert!(res.is_err(), "{name}");
            assert!(log.contains(expect), "{name}: {log:?}");
            if name == "short" {
                // Заголовок прочитан не был: записей нет, подвала нет.
                assert!(out.is_empty(), "{name}");
            } else {
                let s = String::from_utf8(out).unwrap();
                assert!(
                    s.starts_with("[\n") && s.ends_with("}\n]\n"),
                    "{name}: {s:?}"
                );
            }
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn unknown_format_message_names_the_file() {
        let mut bad = b"nmap".to_vec();
        bad.resize(BLOCK, 0);
        let path = tmp_file("nmap", &bad);
        let (_, log, res) = convert(std::slice::from_ref(&path), Format::Json, &no_filter());
        assert!(res.is_err());
        assert!(log.contains(&format!(
            "[-] {path}: unknown file format (expected \"masscan/1.1\")\n"
        )));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn missing_file_reports_fail_and_errors() {
        let path = format!("{}/rmasscan-no-such-file", std::env::temp_dir().display());
        let (_, log, res) = convert(std::slice::from_ref(&path), Format::Json, &no_filter());
        assert!(res.is_err());
        assert!(
            log.contains(&format!("[-] FAIL: --readscan\n[-] {path}: ")),
            "{log:?}"
        );
    }

    #[test]
    fn scan_started_comes_from_the_first_record() {
        let path = tmp_file("started", &make_bin(&recs3()));
        let (out, _, res) = convert(std::slice::from_ref(&path), Format::Binary, &no_filter());
        res.unwrap();
        let mut head = b"masscan/1.1\ns:1700000001\n".to_vec();
        head.resize(BLOCK, 0);
        assert_eq!(out[..BLOCK], head[..]);
        // Записи сохраняют свои времена, а не время стенки (1_800_000_000).
        let (got, res) = read_all(&out);
        res.unwrap();
        assert_eq!(got, recs3());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn filters_apply_like_c() {
        let all = vec![
            rec(1, [10, 0, 0, 1], 80, Status::Open),
            rec(2, [10, 0, 0, 3], 443, Status::Open),
            rec(3, [10, 0, 0, 9], 80, Status::Open),
            rec(4, [11, 0, 0, 1], 80, Status::Open),
        ];
        let path = tmp_file("filter", &make_bin(&all));
        let files = std::slice::from_ref(&path);
        let mut cfg = ScanConfig::default();
        add_target_string(cfg.targets.ipv4_mut(), "10.0.0.0/30").unwrap();
        parse_ports(cfg.targets.ports_mut(), "80").unwrap();
        let f = ReadFilter::from_config(&cfg);
        assert!(f.by_ip && f.by_port);
        let (out, _, res) = convert(files, Format::Binary, &f);
        res.unwrap();
        assert_eq!(read_all(&out).0, vec![all[0]]);
        // Только порты.
        let mut cfg = ScanConfig::default();
        parse_ports(cfg.targets.ports_mut(), "443").unwrap();
        let f = ReadFilter::from_config(&cfg);
        assert!(!f.by_ip && f.by_port);
        let (out, _, _) = convert(files, Format::Binary, &f);
        assert_eq!(read_all(&out).0, vec![all[1]]);
        // Исключения вычитаются из целей.
        let mut cfg = ScanConfig::default();
        add_target_string(cfg.targets.ipv4_mut(), "10.0.0.0/24").unwrap();
        add_target_string(cfg.excludes.ipv4_mut(), "10.0.0.3").unwrap();
        let f = ReadFilter::from_config(&cfg);
        let (out, _, _) = convert(files, Format::Binary, &f);
        assert_eq!(read_all(&out).0, vec![all[0], all[2]]);
        // Без целей и портов пропускается всё.
        let (out, _, _) = convert(files, Format::Binary, &no_filter());
        assert_eq!(read_all(&out).0, all);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stderr_names_each_file() {
        let a = tmp_file("a", &make_bin(&recs3()[..1]));
        let b = tmp_file("b", &make_bin(&recs3()[1..]));
        let (_, log, res) = convert(&[a.clone(), b.clone()], Format::Ndjson, &no_filter());
        res.unwrap();
        assert_eq!(log, format!("[+] --readscan {a}\n[+] --readscan {b}\n"));
        let _ = std::fs::remove_file(a);
        let _ = std::fs::remove_file(b);
    }

    #[test]
    fn progress_every_65536_records() {
        // 65536 записей 'm' (по 2 байта: тип, длина 0).
        let tail: Vec<u8> = [0x6D, 0].repeat(65_536);
        let path = tmp_file("progress", &with_header(&tail));
        let (_, log, res) = convert(std::slice::from_ref(&path), Format::Ndjson, &no_filter());
        res.unwrap();
        assert!(log.ends_with(&format!("[+] {path}:    65536\r")), "{log:?}");
        let _ = std::fs::remove_file(path);
    }
}
