//! Чтение `-oB` и операция `--readscan` (AGPL-3.0). Порт `in-binary.c` (`_binaryfile_parse` :470–640,
//! `parse_status2` :100–150, `readscan_binary_scanfile` :650–691) masscan © Robert David Graham. Читается только
//! то, что пишет `-oB` этой версии: записи типа 6/7 (IPv4: TCP, UDP, SCTP, ICMP), 8 (ARP), 10/11 (IPv6, 28 байт,
//! `parse_status6` :228–276) и подвал `'m'`. Остальные типы C (баннеры, устаревшие 1/2, 12 `Out_Arp6`) дают ошибку
//! `Unsupported` (Р13), а не молчаливый пропуск.
//! Отличия от C (Р5, лучше C): тип 8 читается (в `in-binary.c:583–634` нет `case Out_Arp2`, это «unknown type 8»),
//! а фильтр `-p` сравнивает пару (протокол, порт) со сдвинутыми диапазонами (`in-filter.c:14–17` сравнивает
//! несдвинутый порт).
//!
//! Записи уходят в [`Pipeline::report_record`] со своим исходным временем (никогда не штампуются заново).
//! Начало скана `s:` берётся из заголовка `masscan/1.1.N` (N >= 2, `in-binary.c:518-534`), иначе из первой записи
//! до фильтра, как `when_scan_started` C (`in-binary.c:128-129`).

use std::cell::RefCell;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rmasscan_core::config::ScanConfig;
use rmasscan_core::massip::MassIp;
use rmasscan_core::targets::{TEMPL_ARP, TEMPL_ICMP_ECHO, TEMPL_SCTP, TEMPL_UDP};

use crate::LOGGED;
use crate::output::{Pipeline, Proto, Record, Sink, Status};

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
    /// Тип записи, которого этот читатель не умеет (баннеры, `Out_Arp6`, v1).
    Unsupported(u64),
    /// Запись типа 6/7/8/10/11 с номером протокола, который этот порт не выводит (не 1/6/17/132, у типа 8 не 0).
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

/// `strtoul(s, 0, 0)` C: пробелы и знак, затем `0x` (16-ричное), `0` (восьмеричное) или десятичное; остановка на
/// первом неподходящем байте или `\0`; переполнение даёт `ULONG_MAX`, минус отрицает по модулю 2^64.
fn strtoul(s: &[u8]) -> u64 {
    let mut i = 0;
    while s.get(i).is_some_and(|b| matches!(b, b' ' | b'\t'..=b'\r')) {
        i += 1;
    }
    let neg = match s.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let mut base = 10u32;
    if s.get(i) == Some(&b'0') {
        if matches!(s.get(i + 1), Some(b'x' | b'X'))
            && s.get(i + 2).is_some_and(|b| b.is_ascii_hexdigit())
        {
            base = 16;
            i += 2;
        } else {
            base = 8;
        }
    }
    let mut v = 0u64;
    let mut overflow = false;
    while let Some(d) = s.get(i).and_then(|&b| char::from(b).to_digit(base)) {
        match v
            .checked_mul(u64::from(base))
            .and_then(|x| x.checked_add(u64::from(d)))
        {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    if overflow {
        return u64::MAX;
    }
    if neg { v.wrapping_neg() } else { v }
}

/// Читает записи типа 6/7/8/10/11 из файла `-oB`. `f` получает каждую; его ошибка прерывает чтение.
pub fn read_records(
    r: &mut dyn Read,
    f: &mut dyn FnMut(Record) -> Result<(), String>,
) -> Result<(), ReadError> {
    read_records_counted(r, f, &mut |_| {}, &mut |_| {}, &mut || {})
}

/// То же, с обратным вызовом после каждой записи (в том числе `'m'`) с общим числом: для строки прогресса.
fn read_records_counted(
    r: &mut dyn Read,
    f: &mut dyn FnMut(Record) -> Result<(), String>,
    progress: &mut dyn FnMut(u64),
    scan_start: &mut dyn FnMut(u64),
    corrupt_record: &mut dyn FnMut(),
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
    // `in-binary.c:518-534`: у `masscan/1.1.<N>`, `N >= 2`, начало скана записано в заголовке как `s:<время>`.
    if head[11] == b'.' && strtoul(&head[12..]) >= 2 {
        // Поле после первой строки; `'a'` (97) и `buf[i]` за пределами заголовка читаются как конец строки.
        let mut i = head[..97]
            .iter()
            .position(|&b| b == 0 || b == b'\n')
            .unwrap_or(97);
        i += 1;
        if head.get(i) == Some(&b's') {
            i += 1;
        }
        if head.get(i) == Some(&b':') {
            i += 1;
        }
        if i < 97 {
            scan_start(strtoul(&head[i..]));
        }
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
            6..=8 => {
                // `parse_status2`: тело короче 13 байт молча пропускается.
                if body.len() >= 13 {
                    // Тип 6/7: IPv4 с протоколом 1/6/17/132 (`out-binary.c:154–211`); тип 8 (`Out_Arp2`): 0.
                    let proto = match (ty, Proto::from_ip_proto(body[8])) {
                        (8, Some(Proto::Arp)) => Proto::Arp,
                        (6 | 7, Some(p)) if p != Proto::Arp => p,
                        _ => return Err(ReadError::UnsupportedProtocol(body[8])),
                    };
                    let ip = Ipv4Addr::new(body[4], body[5], body[6], body[7]);
                    // `parse_status2`: MAC читается, если адрес 0.0.0.0 и в теле есть ещё 6 байт; иначе нули.
                    // `-oB` MAC не пишет, так что у файлов этого порта и C он нулевой.
                    let mac = (proto == Proto::Arp).then(|| {
                        let mut m = [0u8; 6];
                        if ip.is_unspecified() && body.len() >= 13 + 6 {
                            m.copy_from_slice(&body[13..19]);
                        }
                        m
                    });
                    f(Record {
                        timestamp: u64::from(u32::from_be_bytes([
                            body[0], body[1], body[2], body[3],
                        ])),
                        ip: IpAddr::V4(ip),
                        port: u16::from_be_bytes([body[9], body[10]]),
                        proto,
                        status: match ty {
                            6 => Status::Open,
                            7 => Status::Closed,
                            _ => Status::Arp,
                        },
                        reason: body[11],
                        ttl: body[12],
                        mac,
                    })
                    .map_err(|e| ReadError::Io(io::Error::other(e)))?;
                }
            }
            10 | 11 => {
                // `parse_status6` (`in-binary.c:228-276`): поля читаются `_get_*` (за концом тела 0xFF…), версия не 6
                // это `[-] corrupt record` в stderr и запись пропущена, чтение идёт дальше.
                let get = |off: usize, n: usize| -> Option<u128> {
                    body.get(off..off + n)
                        .map(|b| b.iter().fold(0u128, |v, &x| (v << 8) | u128::from(x)))
                };
                if get(9, 1) != Some(6) {
                    corrupt_record();
                } else {
                    let ip_proto = body[4];
                    let proto = match Proto::from_ip_proto(ip_proto) {
                        Some(p) if p != Proto::Arp => p,
                        _ => return Err(ReadError::UnsupportedProtocol(ip_proto)),
                    };
                    // `_get_long` (`in-binary.c:200-218`): половина адреса, которой не хватает целиком, это 2^64-1.
                    let half = |off: usize| get(off, 8).unwrap_or(u128::from(u64::MAX));
                    let ip = Ipv6Addr::from(half(10) << 64 | half(18));
                    f(Record {
                        timestamp: get(0, 4).unwrap_or(0xFFFF_FFFF) as u64,
                        ip: IpAddr::V6(ip),
                        port: get(5, 2).unwrap_or(0xFFFF) as u16,
                        proto,
                        status: if ty == 10 {
                            Status::Open
                        } else {
                            Status::Closed
                        },
                        reason: get(7, 1).unwrap_or(0xFF) as u8,
                        ttl: get(8, 1).unwrap_or(0xFF) as u8,
                        mac: None,
                    })
                    .map_err(|e| ReadError::Io(io::Error::other(e)))?;
                }
            }
            // `case 'm'`: подвал.
            0x6D => {}
            1..=5 | 9 | 12 | 13 => return Err(ReadError::Unsupported(ty)),
            _ => return Err(ReadError::Corrupt(format!("unknown type {ty}"))),
        }
        total += 1;
        progress(total);
    }
    Ok(())
}

/// Индекс порта записи в списке портов цели со сдвигом протокола (`massip-port.h:11–25`): TCP +0, UDP +65536,
/// SCTP +131072, ICMP Echo 196608, ARP 196610. C сравнивает тут несдвинутый порт (`in-filter.c:14–17`), из-за
/// чего `-p U:53` не пропускал ни одной записи.
fn port_index(r: &Record) -> u32 {
    match r.proto {
        Proto::Tcp => u32::from(r.port),
        Proto::Udp => TEMPL_UDP + u32::from(r.port),
        Proto::Sctp => TEMPL_SCTP + u32::from(r.port),
        Proto::Icmp => TEMPL_ICMP_ECHO + u32::from(r.port),
        Proto::Arp => TEMPL_ARP,
    }
}

/// Фильтр целей `--readscan` (`filter->count_ipv4s`, `count_ports` в `parse_status2` и `parse_status6`).
///
/// C включает проверку адреса только при непустом списке IPv4 (`in-binary.c:132,254`, `in-filter.c:10`): фильтр из
/// одних диапазонов IPv6 у него ничего не фильтрует (снято с оракула `8e6b3b0`: все записи проходят). R14, названное
/// отличие от C (как Р5): такой фильтр работает, остаются записи внутри его диапазонов IPv6, записи IPv4 вне набора
/// целей отбрасываются. Смешанный фильтр и фильтр из одного IPv4 ведут себя как у C (`massip_has_ip`, `massip.c:45-51`).
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
            // `count_ipv6s` is the low 64 bits of the count (0 for a /64), so ask for the ranges themselves.
            by_ip: targets.count_ipv4s() > 0 || targets.has_ipv6_targets(),
            by_port: targets.count_ports() > 0,
            targets,
        }
    }

    pub fn keeps(&self, r: &Record) -> bool {
        (!self.by_ip
            || match r.ip {
                IpAddr::V4(a) => self.targets.has_ip(u32::from(a)),
                IpAddr::V6(a) => self.targets.has_ip6(u128::from(a)),
            })
            && (!self.by_port || self.targets.has_port(port_index(r)))
    }
}

/// `readscan_binary_scanfile`: файлы по порядку в один вывод. На первой ошибке чтения пишет текст C в `log`, всё
/// равно закрывает вывод (`sink.finish()` даёт подвал) и возвращает `Err(LOGGED)`: текст уже напечатан. Ошибки
/// открытия и записи вывода возвращаются своим текстом (их печатает вызывающий).
pub fn run_readscan(
    files: &[String],
    filter: &ReadFilter,
    sink: &mut Pipeline,
    log: &mut dyn Write,
) -> Result<(), String> {
    // stderr best-effort (in-binary.c:488-637 не проверяет `fprintf`/`fflush`, util-logger.c:25-31).
    let mut best_effort = crate::live::BestEffort::new(log);
    let log: &mut dyn Write = &mut best_effort;
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
    // `in-binary.c:486-493`: `fopen` раньше строки `[+] --readscan`, на отсутствующем файле её нет.
    // `log` best-effort (`BestEffort` в `run_readscan`): запись в него не возвращает ошибок.
    let file = match File::open(name) {
        Ok(f) => f,
        Err(e) => {
            let _ = log.write_all(format!("[-] FAIL: --readscan\n[-] {name}: {e}\n").as_bytes());
            return Err(LOGGED.into());
        }
    };
    let _ = log.write_all(format!("[+] --readscan {name}\n").as_bytes());
    let log = RefCell::new(log);
    let mut reader = BufReader::new(file);
    let sink = RefCell::new(sink);
    let mut sink_failure: Option<String> = None;
    let res = read_records_counted(
        &mut reader,
        &mut |rec: Record| {
            let mut sink = sink.borrow_mut();
            sink.set_scan_started_if_unset(rec.timestamp);
            if filter.keeps(&rec) {
                sink.report_record(&rec).inspect_err(|e| {
                    sink_failure = Some(e.clone());
                })?;
            }
            Ok(())
        },
        &mut |n| {
            if n & 0xFFFF == 0 {
                let _ = log
                    .borrow_mut()
                    .write_all(format!("[+] {name}: {n:8}\r").as_bytes());
            }
        },
        // `in-binary.c:518-534`: `s:` заголовка перекрывает начало скана (C присваивает без проверки на ноль).
        &mut |ts| sink.borrow_mut().set_scan_started(ts),
        // `parse_status6`: `fprintf(stderr, "[-] corrupt record\n")` без имени файла (`in-binary.c:244-247`).
        &mut || {
            let _ = log.borrow_mut().write_all(b"[-] corrupt record\n");
        },
    );
    if let Some(msg) = sink_failure {
        return Err(msg);
    }
    if let Err(e) = res {
        let _ = log.borrow_mut().write_all(e.log_line(name).as_bytes());
        return Err(LOGGED.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{Format, OutputEnv, OutputOptions, Wall, services};
    use crate::scratch::Scratch;
    use rmasscan_core::targets::{add_target_string, parse_ports};
    use std::net::IpAddr;

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
            ip: Ipv4Addr::from(ip).into(),
            port,
            proto: Proto::Tcp,
            status,
            reason: if status == Status::Open { 0x12 } else { 0x14 },
            ttl: 57,
            mac: None,
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
                ports: Vec::new(),
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

    fn tmp_file(scratch: &Scratch, name: &str, bytes: &[u8]) -> String {
        scratch.write(name, bytes).to_string_lossy().into_owned()
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
                ports: Vec::new(),
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
        for t in [1u8, 2, 3, 4, 5, 9, 12, 13] {
            let f = with_header(&[t, 0]);
            match read_all(&f).1 {
                Err(ReadError::Unsupported(n)) => assert_eq!(n, u64::from(t)),
                other => panic!("type {t}: {other:?}"),
            }
        }
        // Незнакомый номер протокола: C печатает `err`, этот порт отказывает (47 = GRE).
        let f = with_header(&record_bytes(6, 13, 47));
        match read_all(&f).1 {
            Err(e @ ReadError::UnsupportedProtocol(47)) => {
                assert_eq!(e.to_string(), "unsupported record protocol 47")
            }
            other => panic!("{other:?}"),
        }
        // ARP живёт только в типе 8, а тип 8 только с протоколом 0.
        for (ty, proto) in [(6, 0), (7, 0), (8, 6), (8, 17)] {
            let f = with_header(&record_bytes(ty, 13, proto));
            assert!(
                matches!(read_all(&f).1, Err(ReadError::UnsupportedProtocol(p)) if p == proto),
                "type {ty} proto {proto}"
            );
        }
    }

    /// Review Focus 4: записи UDP/ICMP (тип 6, 7), SCTP (тип 6) и ARP (тип 8) разбираются; фильтр `-p U:53`
    /// сопоставляет (протокол, порт) со сдвинутым списком (у C `-p U:53` не пропускает ничего, `in-filter.c:14–17`).
    #[test]
    fn readscan_handles_non_tcp_and_arp_type_8() {
        let mk = |ty: u8, ip: [u8; 4], proto: u8, port: u16, ttl: u8| {
            let mut b = vec![ty, 13, 0x65, 0, 0, 1];
            b.extend_from_slice(&ip);
            b.push(proto);
            b.extend_from_slice(&port.to_be_bytes());
            b.extend_from_slice(&[0, ttl]);
            b
        };
        let mut tail = Vec::new();
        tail.extend(mk(6, [192, 0, 2, 1], 17, 53, 64));
        tail.extend(mk(7, [192, 0, 2, 2], 17, 5353, 64));
        tail.extend(mk(6, [192, 0, 2, 3], 132, 2905, 57));
        tail.extend(mk(6, [192, 0, 2, 4], 1, 0, 60));
        tail.extend(mk(8, [192, 0, 2, 9], 0, 0, 0));
        tail.extend(mk(6, [192, 0, 2, 5], 6, 80, 57));
        let bytes = with_header(&tail);
        let (got, res) = read_all(&bytes);
        res.unwrap();
        let seen: Vec<(Proto, Status, u16, Option<[u8; 6]>)> = got
            .iter()
            .map(|r| (r.proto, r.status, r.port, r.mac))
            .collect();
        assert_eq!(
            seen,
            vec![
                (Proto::Udp, Status::Open, 53, None),
                (Proto::Udp, Status::Closed, 5353, None),
                (Proto::Sctp, Status::Open, 2905, None),
                (Proto::Icmp, Status::Open, 0, None),
                // `-oB` MAC не хранит: `parse_status2` даёт нули (`in-binary.c:116–119`).
                (Proto::Arp, Status::Arp, 0, Some([0; 6])),
                (Proto::Tcp, Status::Open, 80, None),
            ]
        );
        // Запись, пройденная через писатель `-oB`, читается обратно тем же.
        let (again, res) = read_all(&make_bin(&got));
        res.unwrap();
        assert_eq!(again, got);

        let scratch = Scratch::new();
        let path = tmp_file(&scratch, "nontcp", &bytes);
        let files = std::slice::from_ref(&path);
        let ports = |spec: &str| {
            let mut cfg = ScanConfig::default();
            parse_ports(cfg.targets.ports_mut(), spec).unwrap();
            ReadFilter::from_config(&cfg)
        };
        let kept = |f: &ReadFilter| {
            let (out, _, res) = convert(files, Format::Binary, f);
            res.unwrap();
            read_all(&out)
                .0
                .iter()
                .map(|r| (r.proto, r.port))
                .collect::<Vec<_>>()
        };
        assert_eq!(kept(&ports("U:53")), vec![(Proto::Udp, 53)]);
        // `-p 53` это TCP 53: UDP 53 не проходит (у C проходил: сравнивался несдвинутый порт).
        assert_eq!(kept(&ports("53")), vec![]);
        assert_eq!(
            kept(&ports("80,S:2905")),
            vec![(Proto::Sctp, 2905), (Proto::Tcp, 80)]
        );
        assert_eq!(kept(&ports("I:0")), vec![(Proto::Icmp, 0)]);
        // ARP это `I:2` (`Templ_ARP`).
        assert_eq!(kept(&ports("I:2")), vec![(Proto::Arp, 0)]);
        assert_eq!(kept(&no_filter()).len(), 6);
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
        let scratch = Scratch::new();
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
            let path = tmp_file(&scratch, name, &bytes);
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
        }
    }

    #[test]
    fn unknown_format_message_names_the_file() {
        let scratch = Scratch::new();
        let mut bad = b"nmap".to_vec();
        bad.resize(BLOCK, 0);
        let path = tmp_file(&scratch, "nmap", &bad);
        let (_, log, res) = convert(std::slice::from_ref(&path), Format::Json, &no_filter());
        assert!(res.is_err());
        assert!(log.contains(&format!(
            "[-] {path}: unknown file format (expected \"masscan/1.1\")\n"
        )));
    }

    #[test]
    fn missing_file_reports_fail_and_errors() {
        let scratch = Scratch::new();
        let path = scratch.path("no-such-file").to_string_lossy().into_owned();
        let (_, log, res) = convert(std::slice::from_ref(&path), Format::Json, &no_filter());
        assert!(res.is_err());
        // `in-binary.c:486-493`: `fopen` раньше `[+] --readscan`, на отсутствующем файле строки `[+]` нет.
        assert!(
            log.starts_with(&format!("[-] FAIL: --readscan\n[-] {path}: ")),
            "{log:?}"
        );
        assert!(!log.contains("[+]"), "{log:?}");
        assert_eq!(log.lines().count(), 2, "{log:?}");
    }

    /// Файл с заголовком `head` (дополняется нулями до 99 байт) и записями `recs` настоящего писателя.
    fn file_with_header(scratch: &Scratch, name: &str, head: &[u8], recs: &[Record]) -> String {
        let bin = make_bin(recs);
        let mut v = head.to_vec();
        v.resize(BLOCK, 0);
        v.extend_from_slice(&bin[BLOCK..BLOCK + 15 * recs.len()]);
        tmp_file(scratch, name, &v)
    }

    /// Первые 99 байт вывода `-oB` после `--readscan`.
    fn started_of(path: &str, filter: &ReadFilter) -> Vec<u8> {
        let (out, _, res) = convert(&[path.to_string()], Format::Binary, filter);
        res.unwrap();
        out[..BLOCK].to_vec()
    }

    fn header_for(ts: u64) -> Vec<u8> {
        let mut h = format!("masscan/1.1\ns:{ts}\n").into_bytes();
        h.resize(BLOCK, 0);
        h
    }

    /// `in-binary.c:518-534`: у `masscan/1.1.N`, `N >= 2`, начало скана берётся из `s:<время>` заголовка, а не из
    /// первой записи.
    #[test]
    fn header_s_timestamp_is_the_scan_start_for_version_2() {
        let scratch = Scratch::new();
        let path = file_with_header(&scratch, "hdr2", b"masscan/1.1.2\ns:1234567890\n", &recs3());
        assert_eq!(started_of(&path, &no_filter()), header_for(1_234_567_890));
        // Десятичное без ведущего нуля, 16-ричное с `0x` и восьмеричное с `0`: `strtoul(.., 0, 0)`.
        for (h, want) in [
            (&b"masscan/1.1.10\ns:0x10\n"[..], 16u64),
            (&b"masscan/1.1.2\ns:010\n"[..], 8),
        ] {
            let p = file_with_header(&scratch, "hdr2b", h, &recs3());
            assert_eq!(started_of(&p, &no_filter()), header_for(want));
        }
    }

    /// `N < 2` и версия без точки (`masscan/1.1`, как пишет `-oB`) заголовок `s:` не читают: начало скана это
    /// время первой записи.
    #[test]
    fn header_s_timestamp_is_ignored_below_version_2() {
        let scratch = Scratch::new();
        for (name, h) in [
            ("hdr1", &b"masscan/1.1.1\ns:1234567890\n"[..]),
            ("hdr0", &b"masscan/1.1\ns:1234567890\n"[..]),
        ] {
            let path = file_with_header(&scratch, name, h, &recs3());
            assert_eq!(started_of(&path, &no_filter()), header_for(1_700_000_001));
        }
    }

    /// `in-binary.c:128-129`: время первой записи берётся до фильтра по IP/порту, поэтому отфильтрованная первая
    /// запись всё равно задаёт начало скана (и для `masscan/1.1`, и когда `s:` в заголовке не читается).
    #[test]
    fn filtered_first_record_still_sets_the_scan_start() {
        let recs = vec![
            rec(1_700_000_001, [11, 0, 0, 1], 80, Status::Open),
            rec(1_700_000_005, [10, 0, 0, 1], 80, Status::Open),
        ];
        let by_ip = {
            let mut cfg = ScanConfig::default();
            add_target_string(cfg.targets.ipv4_mut(), "10.0.0.0/24").unwrap();
            ReadFilter::from_config(&cfg)
        };
        let by_port = {
            let mut cfg = ScanConfig::default();
            parse_ports(cfg.targets.ports_mut(), "443").unwrap();
            ReadFilter::from_config(&cfg)
        };
        let scratch = Scratch::new();
        let path = file_with_header(&scratch, "filt1", b"masscan/1.1\ns:1234567890\n", &recs);
        assert_eq!(started_of(&path, &by_ip), header_for(1_700_000_001));
        // Порт 443 есть только у второй записи: первая (порт 80) отфильтрована, начало скана всё равно из неё.
        let mut recs443 = recs.clone();
        recs443[0].ip = Ipv4Addr::new(10, 0, 0, 1).into();
        recs443[1].port = 443;
        let p443 = file_with_header(&scratch, "filt3", b"masscan/1.1\ns:1234567890\n", &recs443);
        assert_eq!(started_of(&p443, &by_port), header_for(1_700_000_001));
        // С `masscan/1.1.2` приоритет у заголовка даже при отфильтрованной первой записи.
        let p2 = file_with_header(&scratch, "filt2", b"masscan/1.1.2\ns:1234567890\n", &recs);
        assert_eq!(started_of(&p2, &by_ip), header_for(1_234_567_890));
    }

    #[test]
    fn scan_started_comes_from_the_first_record() {
        let scratch = Scratch::new();
        let path = tmp_file(&scratch, "started", &make_bin(&recs3()));
        let (out, _, res) = convert(std::slice::from_ref(&path), Format::Binary, &no_filter());
        res.unwrap();
        let mut head = b"masscan/1.1\ns:1700000001\n".to_vec();
        head.resize(BLOCK, 0);
        assert_eq!(out[..BLOCK], head[..]);
        // Записи сохраняют свои времена, а не время стенки (1_800_000_000).
        let (got, res) = read_all(&out);
        res.unwrap();
        assert_eq!(got, recs3());
    }

    #[test]
    fn filters_apply_like_c() {
        let scratch = Scratch::new();
        let all = vec![
            rec(1, [10, 0, 0, 1], 80, Status::Open),
            rec(2, [10, 0, 0, 3], 443, Status::Open),
            rec(3, [10, 0, 0, 9], 80, Status::Open),
            rec(4, [11, 0, 0, 1], 80, Status::Open),
        ];
        let path = tmp_file(&scratch, "filter", &make_bin(&all));
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
    }

    fn v6(ts: u64, ip: &str, port: u16, status: Status) -> Record {
        Record {
            ip: IpAddr::V6(ip.parse().unwrap()),
            ..rec(ts, [0; 4], port, status)
        }
    }

    /// One 28-byte type 10/11 record as `binary_out_status_ipv6` writes it (`out-binary.c:103-149`), with the
    /// version byte and the body length overridable.
    fn raw6(ty: u8, ip: &str, port: u16, proto: u8, version: u8, len: usize) -> Vec<u8> {
        let n = u128::from(ip.parse::<std::net::Ipv6Addr>().unwrap());
        let mut b = vec![0x65, 0, 0, 1, proto];
        b.extend_from_slice(&port.to_be_bytes());
        b.extend_from_slice(&[0x12, 57, version]);
        b.extend_from_slice(&n.to_be_bytes());
        b.truncate(len);
        let mut v = vec![ty, len as u8];
        v.extend_from_slice(&b);
        v
    }

    /// Mutated and truncated type 10/11 records never panic the reader (it may return an error). The cli crate has no
    /// proptest dependency, so a fixed xorshift sequence drives the mutations; the run is deterministic.
    #[test]
    fn readscan_v6_records_survive_random_mutation_and_truncation() {
        let base = make_bin(&[
            v6(1_700_000_000, "2a03:9060:0:400::2", 443, Status::Open),
            rec(1_700_000_001, [10, 0, 0, 1], 80, Status::Open),
            v6(1_700_000_002, "2001:db8::5", 22, Status::Closed),
        ]);
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..3000 {
            let mut b = base.clone();
            for _ in 0..(next() % 6) {
                let i = (next() as usize) % b.len();
                b[i] = next() as u8;
            }
            let cut = (next() as usize) % 40;
            b.truncate(b.len().saturating_sub(cut));
            let _ = read_all(&b);
        }
    }

    /// Review Focus 5. Types 10/11 (`in-binary.c:228-276`, `parse_status6`) are read back exactly as written and
    /// mixed with IPv4 records in file order. Mixed and IPv4-only filters are C's (`massip_has_ip` picks the list by
    /// the record's version, `massip.c:45-51`); the IPv6-only filter is R14, see below.
    #[test]
    fn readscan_v6_types_10_11_and_filter_match_c() {
        let all = vec![
            v6(1_700_000_000, "2a03:9060:0:400::2", 443, Status::Open),
            rec(1_700_000_001, [10, 0, 0, 1], 80, Status::Open),
            v6(1_700_000_002, "2001:db8::5", 22, Status::Closed),
            v6(1_700_000_003, "2001:db8:1::5", 8080, Status::Open),
        ];
        let bin = make_bin(&all);
        let (got, res) = read_all(&bin);
        res.unwrap();
        assert_eq!(got, all);
        // type 10 for Open, 11 for Closed, 28 bytes each.
        assert_eq!(bin[BLOCK..BLOCK + 2], [10, 26]);
        assert_eq!(bin[BLOCK + 28 + 15..BLOCK + 28 + 17], [11, 26]);

        let scratch = Scratch::new();
        let path = tmp_file(&scratch, "v6", &bin);
        let files = std::slice::from_ref(&path);
        let filter = |targets: &[&str], ports: Option<&str>| {
            let mut cfg = ScanConfig::default();
            for t in targets {
                cfg.targets.add_target_string(t).unwrap();
            }
            if let Some(p) = ports {
                parse_ports(cfg.targets.ports_mut(), p).unwrap();
            }
            ReadFilter::from_config(&cfg)
        };
        let kept = |f: &ReadFilter| {
            let (out, _, res) = convert(files, Format::Binary, f);
            res.unwrap();
            read_all(&out).0
        };
        // R14 (named difference from C). IPv6 ranges only: C runs the address test only when `count_ipv4s` is
        // non-zero (`in-binary.c:254`, `in-filter.c:10`), so the oracle passes every record, IPv4 and IPv6 alike
        // (measured on 8e6b3b0). rmasscan filters: only records inside the IPv6 ranges stay, IPv4 records are
        // outside the target set.
        assert_eq!(kept(&filter(&["2a03:9060:0:400::/64"], None)), vec![all[0]]);
        assert_eq!(kept(&filter(&["2001:db8::/48"], None)), vec![all[2]]);
        assert_eq!(
            kept(&filter(&["2001:db8::/32"], None)),
            vec![all[2], all[3]]
        );
        // `2a03:9060::/64` is the block before `...:400::`, not the record's /64.
        assert_eq!(
            kept(&filter(&["2a03:9060::/64", "10.0.0.0/24"], None)),
            vec![all[1]]
        );
        // IPv4 range only: every IPv6 record is outside the (empty) IPv6 list.
        assert_eq!(kept(&filter(&["10.0.0.0/24"], None)), vec![all[1]]);
        // Both: IPv6 records are matched against the IPv6 ranges.
        assert_eq!(
            kept(&filter(&["2a03:9060:0:400::/64", "10.0.0.0/24"], None)),
            vec![all[0], all[1]]
        );
        assert_eq!(
            kept(&filter(&["2001:db8::/48", "10.0.0.0/24"], None)),
            vec![all[1], all[2]]
        );
        // Ports apply to IPv6 records (`in-binary.c:258`).
        assert_eq!(kept(&filter(&[], Some("22,8080"))), vec![all[2], all[3]]);
        assert_eq!(kept(&no_filter()), all);

        // `parse_status6`: version != 6 or a body too short for the version byte is `[-] corrupt record` on
        // stderr (no file name) and the record is skipped; the read goes on. A body cut inside the address reads
        // the missing 8-byte halves as all ones (`_get_long`).
        let mut tail = raw6(10, "2001:db8::2", 1, 6, 4, 26);
        tail.extend(raw6(10, "2001:db8::2", 2, 6, 6, 5));
        tail.extend(raw6(10, "2001:db8::2", 3, 6, 6, 11));
        tail.extend(raw6(11, "2001:db8::1", 443, 6, 6, 26));
        let path = tmp_file(&scratch, "corrupt", &with_header(&tail));
        let (out, log, res) = convert(std::slice::from_ref(&path), Format::List, &no_filter());
        res.unwrap();
        assert_eq!(
            log,
            format!("[+] --readscan {path}\n[-] corrupt record\n[-] corrupt record\n")
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "#masscan\nopen tcp 3 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 1694498817\n\
             closed tcp 443 2001:db8::1 1694498817\n# end\n"
        );
        // An unknown ip_proto is refused like in types 6/7 (design decision Р13), not printed as `err`.
        let f = with_header(&raw6(10, "2001:db8::2", 9, 47, 6, 26));
        assert!(matches!(
            read_all(&f).1,
            Err(ReadError::UnsupportedProtocol(47))
        ));
    }

    #[test]
    fn stderr_names_each_file() {
        let scratch = Scratch::new();
        let a = tmp_file(&scratch, "a", &make_bin(&recs3()[..1]));
        let b = tmp_file(&scratch, "b", &make_bin(&recs3()[1..]));
        let (_, log, res) = convert(&[a.clone(), b.clone()], Format::Ndjson, &no_filter());
        res.unwrap();
        assert_eq!(log, format!("[+] --readscan {a}\n[+] --readscan {b}\n"));
    }

    #[test]
    fn progress_every_65536_records() {
        let scratch = Scratch::new();
        // 65536 записей 'm' (по 2 байта: тип, длина 0).
        let tail: Vec<u8> = [0x6D, 0].repeat(65_536);
        let path = tmp_file(&scratch, "progress", &with_header(&tail));
        let (_, log, res) = convert(std::slice::from_ref(&path), Format::Ndjson, &no_filter());
        res.unwrap();
        assert!(log.ends_with(&format!("[+] {path}:    65536\r")), "{log:?}");
    }
}
