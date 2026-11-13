//! Чтение `-oB` и операция `--readscan` (AGPL-3.0). Порт `in-binary.c` (`_binaryfile_parse` :470–640,
//! `parse_status2` :100–150, `readscan_binary_scanfile` :650–691) masscan © Robert David Graham. Читается то, что
//! пишет `-oB`: записи статуса типа 6/7 (IPv4: TCP, UDP, SCTP, ICMP), 8 (ARP), 10/11 (IPv6, 28 байт,
//! `parse_status6` :228–276), баннеры типа 9 (IPv4, `parse_banner9` :414–467) и 13 (IPv6, `parse_banner6`
//! :280–330), устаревшие баннеры 3, 4, 5 (`parse_banner3` :339–369, `parse_banner4` :375–409) и подвал `'m'`.
//! Устаревшие записи статуса 1/2 и тип 12 (`Out_Arp6`) дают ошибку `Unsupported` (Р13), а не молчаливый пропуск.
//! Отличия от C (Р5, лучше C): тип 8 читается (в `in-binary.c:583–634` нет `case Out_Arp2`, это «unknown type 8»),
//! а фильтр `-p` сравнивает пару (протокол, порт) со сдвинутыми диапазонами (`in-filter.c:14–17` сравнивает
//! несдвинутый порт). Тип 3 с телом короче 12 байт это `file corrupt` (Р2: у C `buf_length-12` переполняется, и
//! `output_report_banner` читает ~4 ГиБ, `in-binary.c:363`).
//!
//! Записи уходят в [`Pipeline::report_record`] и [`Pipeline::report_banner`] со своим исходным временем (никогда не
//! штампуются заново). Начало скана `s:` берётся из заголовка `masscan/1.1.N` (N >= 2, `in-binary.c:518-534`), иначе
//! из первой записи, дошедшей до функции разбора, до фильтра, как `when_scan_started` C (`in-binary.c:128-129`,
//! :304–305, :353–354, :393–394, :437–438).

use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rmasscan_core::config::ScanConfig;
use rmasscan_core::massip::MassIp;
use rmasscan_core::targets::{TEMPL_ARP, TEMPL_ICMP_ECHO, TEMPL_SCTP, TEMPL_UDP};
use rmasscan_proto::BannerRecord;

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
    /// Тип записи, которого этот читатель не умеет (устаревший статус 1/2, `Out_Arp6`).
    Unsupported(u64),
    /// Запись типа 6/7/8/10/11 с номером протокола, который этот порт не выводит (не 1/6/17/132, у типа 8 не 0).
    UnsupportedProtocol(u8),
    /// Тип 4: лишний байт после тела не прочитан (`in-binary.c:595-600`): `LOG(0, "[-] read() error\n"); exit(1);`.
    /// C выходит, не закрывая вывод: подвала нет ([`run_readscan`] делает так же).
    ExtraByte,
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
            ReadError::ExtraByte => f.write_str("read() error"),
        }
    }
}

impl ReadError {
    /// Строка stderr в форме C: у `file corrupt` и `read() error` имени файла нет, у остальных есть.
    fn log_line(&self, file: &str) -> String {
        match self {
            ReadError::Corrupt(_) | ReadError::ExtraByte => format!("[-] {self}\n"),
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

/// Запись файла `-oB`, которую читатель отдаёт дальше.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    /// Типы 6/7/8/10/11.
    Status(Record),
    /// Типы 9 и 13: проходят фильтр адреса, порта и `--banner-types` (`readscan_filter_pass`, `in-binary.c:450-452`,
    /// :311–313).
    Banner(BannerRecord),
    /// Устаревшие типы 3, 4 и 5: только IPv4, TTL 0, у типа 3 протокол всегда TCP; фильтров нет никаких
    /// (`in-binary.c:592-603`).
    LegacyBanner(BannerRecord),
}

/// Что читатель сообщает о файле, в порядке `_binaryfile_parse` C.
pub trait ReadEvents {
    /// `s:` заголовка `masscan/1.1.N`, N >= 2 (`in-binary.c:518-534`): начало скана без проверки на ноль.
    fn header_start(&mut self, _ts: u64) {}
    /// Время записи, дошедшей до функции разбора, до фильтров: `if (out->when_scan_started == 0)
    /// out->when_scan_started = record.timestamp;`.
    fn record_time(&mut self, _ts: u64) {}
    /// Разобранная запись; ошибка прерывает чтение.
    fn item(&mut self, it: Item) -> Result<(), String>;
    /// `fprintf(stderr, "[-] corrupt record\n")` типов 10, 11 и 13 с версией не 6 (`in-binary.c:244-247`, :297–300).
    fn corrupt_record(&mut self) {}
    /// Общее число записей после каждой, в том числе `'m'` и пропущенных (`in-binary.c:635-637`).
    fn progress(&mut self, _total: u64) {}
}

/// Читает файл `-oB`. `skip_status`: `--banner-types` не пуст, записи статуса (типы 1, 2, 6, 7, 10, 11; у этого порта
/// ещё 8) пропускаются не разобранными (`if (!btypes->count)`, `in-binary.c:584-623`): ни времени начала скана, ни
/// `[-] corrupt record`, ни отказа по протоколу.
pub fn read_items(
    r: &mut dyn Read,
    skip_status: bool,
    ev: &mut dyn ReadEvents,
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
            ev.header_start(strtoul(&head[i..]));
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
            // `if (!btypes->count)` (`in-binary.c:584-623`): с `--banner-types` статус не разбирается вовсе.
            1 | 2 | 6..=8 | 10 | 11 if skip_status => {}
            3 => {
                // `parse_banner3` (`in-binary.c:339-369`): время, адрес, порт, app, баннер с 12-го байта; протокол
                // всегда TCP, TTL 0. Длину C не проверяет (Р2, см. начало модуля): короткое тело это битая запись.
                if body.len() < 12 {
                    return Err(corrupt());
                }
                let timestamp = u64::from(be32(&body[..4]));
                ev.record_time(timestamp);
                ev.item(Item::LegacyBanner(BannerRecord {
                    timestamp,
                    ip: IpAddr::V4(Ipv4Addr::new(body[4], body[5], body[6], body[7])),
                    ip_proto: 6,
                    port: u16::from_be_bytes([body[8], body[9]]),
                    app: u16::from_be_bytes([body[10], body[11]]),
                    ttl: 0,
                    payload: body[12..].to_vec(),
                }))
                .map_err(item_failed)?;
            }
            4 | 5 => {
                if ty == 4 {
                    // `in-binary.c:595-602`: ещё один байт из файла становится последним байтом тела. У C при длине
                    // ровно `BUF_MAX` это запись за буфером (класс а); здесь тело просто растёт.
                    let mut extra = [0u8; 1];
                    if read_up_to(r, &mut extra).map_err(ReadError::Io)? != 1 {
                        return Err(ReadError::ExtraByte);
                    }
                    body.push(extra[0]);
                }
                // `parse_banner4` (`in-binary.c:375-409`): тело короче 13 байт молча пропускается; TTL 0.
                if body.len() >= 13 {
                    let timestamp = u64::from(be32(&body[..4]));
                    ev.record_time(timestamp);
                    ev.item(Item::LegacyBanner(BannerRecord {
                        timestamp,
                        ip: IpAddr::V4(Ipv4Addr::new(body[4], body[5], body[6], body[7])),
                        ip_proto: body[8],
                        port: u16::from_be_bytes([body[9], body[10]]),
                        app: u16::from_be_bytes([body[11], body[12]]),
                        ttl: 0,
                        payload: body[13..].to_vec(),
                    }))
                    .map_err(item_failed)?;
                }
            }
            9 => {
                // `parse_banner9` (`in-binary.c:414-467`): тело короче 14 байт молча пропускается (до начала скана).
                if body.len() >= 14 {
                    let timestamp = u64::from(be32(&body[..4]));
                    ev.record_time(timestamp);
                    ev.item(Item::Banner(BannerRecord {
                        timestamp,
                        ip: IpAddr::V4(Ipv4Addr::new(body[4], body[5], body[6], body[7])),
                        ip_proto: body[8],
                        port: u16::from_be_bytes([body[9], body[10]]),
                        app: u16::from_be_bytes([body[11], body[12]]),
                        ttl: body[13],
                        payload: body[14..].to_vec(),
                    }))
                    .map_err(item_failed)?;
                }
            }
            13 => {
                // `parse_banner6` (`in-binary.c:280-330`): поля через `_get_*`; версия не 6 (и тело без байта версии)
                // это `[-] corrupt record`, чтение идёт дальше. С версией 6 время уже начало скана (:304–305), а тело
                // короче 27 байт после фильтра молча не выводится (`if (offset > length) return;`, :318–319).
                let get = |off: usize, n: usize| get_be(&body, off, n);
                if get(10, 1) != Some(6) {
                    ev.corrupt_record();
                } else {
                    // Байт версии на месте, значит тело не короче 11 байт и поля до него целы.
                    let timestamp = u64::from(be32(&body[..4]));
                    ev.record_time(timestamp);
                    if body.len() >= 27 {
                        let ip = Ipv6Addr::from(get(11, 16).unwrap_or(u128::MAX));
                        ev.item(Item::Banner(BannerRecord {
                            timestamp,
                            ip: IpAddr::V6(ip),
                            ip_proto: body[4],
                            port: u16::from_be_bytes([body[5], body[6]]),
                            app: u16::from_be_bytes([body[7], body[8]]),
                            ttl: body[9],
                            payload: body[27..].to_vec(),
                        }))
                        .map_err(item_failed)?;
                    }
                }
            }
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
                    let timestamp = u64::from(be32(&body[..4]));
                    ev.record_time(timestamp);
                    ev.item(Item::Status(Record {
                        timestamp,
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
                    }))
                    .map_err(item_failed)?;
                }
            }
            10 | 11 => {
                // `parse_status6` (`in-binary.c:228-276`): поля читаются `_get_*` (за концом тела 0xFF…), версия не 6
                // это `[-] corrupt record` в stderr и запись пропущена, чтение идёт дальше.
                let get = |off: usize, n: usize| get_be(&body, off, n);
                if get(9, 1) != Some(6) {
                    ev.corrupt_record();
                } else {
                    let ip_proto = body[4];
                    let proto = match Proto::from_ip_proto(ip_proto) {
                        Some(p) if p != Proto::Arp => p,
                        _ => return Err(ReadError::UnsupportedProtocol(ip_proto)),
                    };
                    // `_get_long` (`in-binary.c:200-218`): половина адреса, которой не хватает целиком, это 2^64-1.
                    let half = |off: usize| get(off, 8).unwrap_or(u128::from(u64::MAX));
                    let ip = Ipv6Addr::from(half(10) << 64 | half(18));
                    let timestamp = get(0, 4).unwrap_or(0xFFFF_FFFF) as u64;
                    ev.record_time(timestamp);
                    ev.item(Item::Status(Record {
                        timestamp,
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
                    }))
                    .map_err(item_failed)?;
                }
            }
            // `case 'm'`: подвал.
            0x6D => {}
            1 | 2 | 12 => return Err(ReadError::Unsupported(ty)),
            _ => return Err(ReadError::Corrupt(format!("unknown type {ty}"))),
        }
        total += 1;
        ev.progress(total);
    }
    Ok(())
}

/// Ошибка приёмника записи прерывает чтение; текст уже сохранил вызывающий.
fn item_failed(e: String) -> ReadError {
    ReadError::Io(io::Error::other(e))
}

/// Число big-endian из `b[..4]`.
fn be32(b: &[u8]) -> u32 {
    b.iter().take(4).fold(0, |v, &x| (v << 8) | u32::from(x))
}

/// `_get_byte`/`_get_short`/`_get_integer`/`_get_long` (`in-binary.c:156-223`): `n` байт big-endian с `off`, `None`,
/// если тело кончилось раньше (C тогда даёт значение из одних единиц).
fn get_be(body: &[u8], off: usize, n: usize) -> Option<u128> {
    body.get(off..off.checked_add(n)?)
        .map(|b| b.iter().fold(0u128, |v, &x| (v << 8) | u128::from(x)))
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
    /// `--banner-types` (`masscan->banner_types`, `src/main-conf.c:2683-2697`): если не пуст, баннеры типов 9 и 13
    /// проходят только с этими номерами приложения, а записи статуса не читаются вовсе (`in-binary.c:584-623`).
    pub banner_types: BTreeSet<u16>,
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
            banner_types: cfg.banner_types.clone(),
        }
    }

    /// Записи статуса не разбираются (`if (!btypes->count)`, `in-binary.c:584-623`).
    pub fn drops_status(&self) -> bool {
        !self.banner_types.is_empty()
    }

    fn keeps_ip(&self, ip: IpAddr) -> bool {
        !self.by_ip
            || match ip {
                IpAddr::V4(a) => self.targets.has_ip(u32::from(a)),
                IpAddr::V6(a) => self.targets.has_ip6(u128::from(a)),
            }
    }

    pub fn keeps(&self, r: &Record) -> bool {
        self.keeps_ip(r.ip) && (!self.by_port || self.targets.has_port(port_index(r)))
    }

    /// `readscan_filter_pass` (`src/in-filter.c:5-24`) для типов 9 и 13: адрес и порт как у записи статуса (R14 и
    /// Р5: порт со сдвигом протокола; у протокола без своего пространства портов, не 1/6/17/132, фильтр `-p` не
    /// пропускает ничего), затем номер приложения в `--banner-types`.
    pub fn keeps_banner(&self, b: &BannerRecord) -> bool {
        self.keeps_ip(b.ip)
            && (!self.by_port
                || banner_port_index(b.ip_proto, b.port).is_some_and(|i| self.targets.has_port(i)))
            && (self.banner_types.is_empty() || self.banner_types.contains(&b.app))
    }
}

/// Индекс порта записи баннера в сдвинутом списке портов (см. [`port_index`]); `None` для протоколов, у которых
/// нет своего пространства портов.
fn banner_port_index(ip_proto: u8, port: u16) -> Option<u32> {
    let p = u32::from(port);
    match ip_proto {
        6 => Some(p),
        17 => Some(TEMPL_UDP + p),
        132 => Some(TEMPL_SCTP + p),
        1 => Some(TEMPL_ICMP_ECHO + p),
        _ => None,
    }
}

/// Чем кончилось чтение одного файла.
enum Stop {
    /// Ошибка с закрытием вывода (`goto end` C, затем `output_destroy`: подвал пишется).
    Close(String),
    /// `exit(1)` посреди чтения (`in-binary.c:597-600`): вывод не закрывается, подвала нет.
    Exit(String),
}

/// `readscan_binary_scanfile`: файлы по порядку в один вывод. На первой ошибке чтения пишет текст C в `log`, всё
/// равно закрывает вывод (`sink.finish()` даёт подвал) и возвращает `Err(LOGGED)`: текст уже напечатан. Ошибки
/// открытия и записи вывода возвращаются своим текстом (их печатает вызывающий). Обрыв типа 4 на лишнем байте
/// выходит как `exit(1)` C: буферы сбрасываются, подвала нет ([`Pipeline::abandon`]).
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
        match read_one(name, filter, sink, log) {
            Ok(()) => {}
            Err(Stop::Close(msg)) => {
                failure = Some(msg);
                break;
            }
            Err(Stop::Exit(msg)) => {
                sink.abandon()?;
                return Err(msg);
            }
        }
    }
    let closed = sink.finish();
    match failure {
        Some(msg) => Err(msg),
        None => closed,
    }
}

/// Приёмник событий чтения одного файла: фильтр, конвейер и stderr.
struct OneFile<'f, 'p, 'a, 'l> {
    name: &'f str,
    filter: &'f ReadFilter,
    sink: &'p mut Pipeline<'a>,
    log: &'l mut dyn Write,
    /// Ошибка конвейера: её текст важнее текста читателя.
    sink_failure: Option<String>,
}

impl ReadEvents for OneFile<'_, '_, '_, '_> {
    /// `in-binary.c:518-534`: `s:` заголовка перекрывает начало скана (C присваивает без проверки на ноль).
    fn header_start(&mut self, ts: u64) {
        self.sink.set_scan_started(ts);
    }
    fn record_time(&mut self, ts: u64) {
        self.sink.set_scan_started_if_unset(ts);
    }
    fn item(&mut self, it: Item) -> Result<(), String> {
        let res = match it {
            Item::Status(r) if self.filter.keeps(&r) => self.sink.report_record(&r),
            // `--readscan` включает баннеры (`is_banners`, `src/main-conf.c:3266-3272`): проверки `is_banner` нет.
            Item::Banner(b) if self.filter.keeps_banner(&b) => self.sink.report_banner(&b),
            Item::LegacyBanner(b) => self.sink.report_banner(&b),
            Item::Status(_) | Item::Banner(_) => Ok(()),
        };
        res.inspect_err(|e| self.sink_failure = Some(e.clone()))
    }
    /// `fprintf(stderr, "[-] corrupt record\n")` без имени файла (`in-binary.c:244-247`, :297–300).
    fn corrupt_record(&mut self) {
        let _ = self.log.write_all(b"[-] corrupt record\n");
    }
    fn progress(&mut self, n: u64) {
        if n & 0xFFFF == 0 {
            let _ = self
                .log
                .write_all(format!("[+] {}: {n:8}\r", self.name).as_bytes());
        }
    }
}

fn read_one(
    name: &str,
    filter: &ReadFilter,
    sink: &mut Pipeline,
    log: &mut dyn Write,
) -> Result<(), Stop> {
    // `in-binary.c:486-493`: `fopen` раньше строки `[+] --readscan`, на отсутствующем файле её нет.
    // `log` best-effort (`BestEffort` в `run_readscan`): запись в него не возвращает ошибок.
    let file = match File::open(name) {
        Ok(f) => f,
        Err(e) => {
            let _ = log.write_all(format!("[-] FAIL: --readscan\n[-] {name}: {e}\n").as_bytes());
            return Err(Stop::Close(LOGGED.into()));
        }
    };
    let _ = log.write_all(format!("[+] --readscan {name}\n").as_bytes());
    let mut reader = BufReader::new(file);
    let mut ev = OneFile {
        name,
        filter,
        sink,
        log,
        sink_failure: None,
    };
    let res = read_items(&mut reader, filter.drops_status(), &mut ev);
    if let Some(msg) = ev.sink_failure {
        return Err(Stop::Close(msg));
    }
    match res {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = ev.log.write_all(e.log_line(name).as_bytes());
            Err(match e {
                ReadError::ExtraByte => Stop::Exit(LOGGED.into()),
                _ => Stop::Close(LOGGED.into()),
            })
        }
    }
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

    /// Всё, что читатель сообщил о файле.
    #[derive(Default)]
    struct Collect {
        items: Vec<Item>,
        times: Vec<u64>,
        corrupt: usize,
    }

    impl ReadEvents for Collect {
        fn record_time(&mut self, ts: u64) {
            self.times.push(ts);
        }
        fn item(&mut self, it: Item) -> Result<(), String> {
            self.items.push(it);
            Ok(())
        }
        fn corrupt_record(&mut self) {
            self.corrupt += 1;
        }
    }

    fn read_items_all(bytes: &[u8], skip_status: bool) -> (Collect, Result<(), ReadError>) {
        let mut c = Collect::default();
        let res = read_items(&mut &bytes[..], skip_status, &mut c);
        (c, res)
    }

    /// Только записи статуса; запись баннера здесь ошибка теста.
    fn read_all(bytes: &[u8]) -> (Vec<Record>, Result<(), ReadError>) {
        let (c, res) = read_items_all(bytes, false);
        let recs = c
            .items
            .into_iter()
            .map(|it| match it {
                Item::Status(r) => r,
                other => panic!("not a status record: {other:?}"),
            })
            .collect();
        (recs, res)
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

    /// Устаревший статус 1/2 (`parse_status`, порт угадывает протокол, `in-binary.c:41-98`) и тип 12 `Out_Arp6` (у C
    /// «unknown type 12») не читаются (Р13). Баннеры 3, 4, 5, 9 и 13 читаются (`readscan_banner_*`).
    #[test]
    fn unsupported_types_are_errors() {
        for t in [1u8, 2, 12] {
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
        uns.extend_from_slice(&[12, 0]);
        cases.push(("uns", uns, ": unsupported record type 12\n"));
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
            let _ = read_items_all(&b, false);
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

    fn banner(
        ts: u64,
        ip: &str,
        ip_proto: u8,
        port: u16,
        app: u16,
        ttl: u8,
        payload: &[u8],
    ) -> BannerRecord {
        BannerRecord {
            timestamp: ts,
            ip: ip.parse().unwrap(),
            ip_proto,
            port,
            app,
            ttl,
            payload: payload.to_vec(),
        }
    }

    /// Файл `-oB` из записей статуса и баннеров, собранный настоящим писателем конвейера (типы 6/7/10/11, 9/13).
    fn make_bin_items(items: &[Item]) -> Vec<u8> {
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
            for it in items {
                match it {
                    Item::Status(r) => p.report_record(r).unwrap(),
                    Item::Banner(b) | Item::LegacyBanner(b) => p.report_banner(b).unwrap(),
                }
            }
            p.finish().unwrap();
        }
        out
    }

    /// Семибитный varint C (`in-binary.c:546-570`): старшие группы с битом продолжения.
    fn varint(mut n: usize) -> Vec<u8> {
        let mut v = vec![(n & 0x7F) as u8];
        n >>= 7;
        while n > 0 {
            v.insert(0, (n & 0x7F) as u8 | 0x80);
            n >>= 7;
        }
        v
    }

    /// Устаревшая запись 3, 4 или 5. Тело типа 3: время, адрес, порт, app, баннер (`in-binary.c:339-369`); 4 и 5:
    /// время, адрес, протокол, порт, app, баннер (`:375-409`). У типа 4 длина на один байт меньше тела: последний
    /// байт C дочитывает отдельно (`:595-602`).
    fn legacy(ty: u8, ts: u32, ip: [u8; 4], proto: u8, port: u16, app: u16, px: &[u8]) -> Vec<u8> {
        let mut body = ts.to_be_bytes().to_vec();
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
        v
    }

    /// Запись типа 13 как `binary_out_banner_ipv6` (`out-binary.c:216-289`) с подменяемой версией и длиной тела.
    #[allow(clippy::too_many_arguments)]
    fn raw13(
        ts: u32,
        proto: u8,
        port: u16,
        app: u16,
        version: u8,
        ip: &str,
        px: &[u8],
        len: usize,
    ) -> Vec<u8> {
        let mut b = ts.to_be_bytes().to_vec();
        b.push(proto);
        b.extend_from_slice(&port.to_be_bytes());
        b.extend_from_slice(&app.to_be_bytes());
        b.extend_from_slice(&[57, version]);
        b.extend_from_slice(&u128::from(ip.parse::<Ipv6Addr>().unwrap()).to_be_bytes());
        b.extend_from_slice(px);
        b.truncate(len);
        let mut v = vec![13];
        v.extend(varint(b.len()));
        v.extend(b);
        v
    }

    fn list_of(path: &str, filter: &ReadFilter) -> (String, String, Result<(), String>) {
        let (out, log, res) = convert(&[path.to_string()], Format::List, filter);
        (String::from_utf8(out).unwrap(), log, res)
    }

    /// Типы 9 и 13 читаются ровно такими, какими их пишет `-oB` (`out-binary.c:216-355`), в порядке файла
    /// вперемешку со статусом: длина в один байт и в два (113/114 байт у IPv4, 100/101 у IPv6), 16 369 байт (самая
    /// длинная запись `-oB` IPv4), пустой баннер, любой `ip_proto` и любой номер приложения.
    #[test]
    fn readscan_banner_types_9_and_13_roundtrip() {
        let cyc: Vec<u8> = (0..16_369u32).map(|i| i as u8).collect();
        let items = vec![
            Item::Status(rec(1_700_000_001, [192, 0, 2, 1], 80, Status::Open)),
            Item::Banner(banner(
                1_700_000_002,
                "192.0.2.1",
                17,
                53,
                6,
                57,
                b"9.18.24",
            )),
            Item::Banner(banner(
                1_700_000_003,
                "2001:db8::1",
                6,
                443,
                9,
                64,
                &cyc[..256],
            )),
            Item::Status(v6(1_700_000_004, "2001:db8::1", 443, Status::Closed)),
            Item::Banner(banner(
                1_700_000_005,
                "192.0.2.2",
                6,
                80,
                4,
                0,
                &[b'a'; 113],
            )),
            Item::Banner(banner(
                1_700_000_005,
                "192.0.2.2",
                6,
                80,
                4,
                0,
                &[b'b'; 114],
            )),
            Item::Banner(banner(
                1_700_000_006,
                "2001:db8::2",
                132,
                1,
                37,
                255,
                &[b'c'; 100],
            )),
            Item::Banner(banner(
                1_700_000_006,
                "2001:db8::2",
                99,
                2,
                65535,
                1,
                &[b'd'; 101],
            )),
            Item::Banner(banner(1_700_000_007, "192.0.2.3", 0, 0, 0, 1, b"")),
            Item::Banner(banner(1_700_000_007, "::", 1, 0, 36, 2, b"")),
            Item::Banner(banner(1_700_000_008, "192.0.2.4", 6, 443, 15, 64, &cyc)),
        ];
        let bin = make_bin_items(&items);
        let (c, res) = read_items_all(&bin, false);
        res.unwrap();
        assert_eq!(c.items, items);
        assert_eq!(c.corrupt, 0);
        assert_eq!(c.times.len(), items.len());
        // Тот же файл ещё раз через `-oB` даёт те же байты, кроме `s:` заголовка (начало скана из первой записи).
        let scratch = Scratch::new();
        let path = tmp_file(&scratch, "b", &bin);
        let (out, log, res) = convert(std::slice::from_ref(&path), Format::Binary, &no_filter());
        res.unwrap();
        assert_eq!(log, format!("[+] --readscan {path}\n"));
        assert_eq!(out[BLOCK..], bin[BLOCK..]);
        assert_eq!(out[..BLOCK], header_for(1_700_000_001)[..]);
    }

    /// `parse_banner3` (`in-binary.c:339-369`) длину не проверяет: тело короче 12 байт даёт `(unsigned)buf_length-12`
    /// около 4 ГиБ, и `output_report_banner` читает за буфером. Здесь (Р2) это битая запись, как прочие: `[-] file
    /// corrupt` без имени файла, вывод закрыт с подвалом, код 1. Тело ровно 12 байт это пустой баннер TCP с TTL 0.
    #[test]
    fn readscan_type3_short_body_is_corrupt_not_crash() {
        let ok = legacy(3, 1_700_000_000, [10, 3, 0, 1], 0, 22, 2, b"");
        let (c, res) = read_items_all(&with_header(&ok), false);
        res.unwrap();
        assert_eq!(
            c.items,
            vec![Item::LegacyBanner(banner(
                1_700_000_000,
                "10.3.0.1",
                6,
                22,
                2,
                0,
                b""
            ))]
        );
        for short in 0..12usize {
            let mut tail = ok.clone();
            tail.extend([3, short as u8]);
            tail.extend(vec![0x41; short]);
            let (c, res) = read_items_all(&with_header(&tail), false);
            assert!(
                matches!(&res, Err(ReadError::Corrupt(s)) if s.is_empty()),
                "{short}: {res:?}"
            );
            assert_eq!(c.items.len(), 1, "{short}");
        }
        let mut tail = ok.clone();
        tail.extend([3, 11]);
        tail.extend([0x41; 11]);
        let scratch = Scratch::new();
        let path = tmp_file(&scratch, "t3", &with_header(&tail));
        let (out, log, res) = list_of(&path, &no_filter());
        assert_eq!(res.unwrap_err(), LOGGED);
        assert_eq!(log, format!("[+] --readscan {path}\n[-] file corrupt\n"));
        assert_eq!(
            out,
            "#masscan\nbanner tcp 22 10.3.0.1 1700000000 ssh \n# end\n"
        );
    }

    /// Тип 4 (`in-binary.c:595-602`): после тела длины L C читает из файла ещё один байт, и он становится последним
    /// байтом тела (при L = 12 это младший байт номера приложения); следующая запись начинается после него. Если
    /// байта нет, `[-] read() error` и `exit(1)`: вывод не закрывается, подвала нет. Тип 5 тот же разбор без
    /// лишнего байта; у обоих TTL 0, протокол из записи.
    #[test]
    fn readscan_type4_reads_extra_byte() {
        let mut tail = legacy(4, 1_700_000_000, [192, 0, 2, 4], 17, 53, 6, b"hello!");
        assert_eq!(
            tail[1],
            13 + 5,
            "length counts the body without the extra byte"
        );
        // L = 12: лишний байт это младший байт app (6, dns-ver), баннер пуст.
        tail.extend(legacy(4, 1_700_000_001, [192, 0, 2, 5], 6, 80, 6, b""));
        assert_eq!(&tail[tail.len() - 15..tail.len() - 13], [4, 12]);
        tail.extend(legacy(
            5,
            1_700_000_002,
            [192, 0, 2, 6],
            132,
            2905,
            37,
            b"x",
        ));
        let after = banner(1_700_000_003, "192.0.2.7", 6, 22, 3, 64, b"SSH-2.0-x");
        tail.extend(&make_bin_items(&[Item::Banner(after.clone())])[BLOCK..]);
        let (c, res) = read_items_all(&with_header(&tail), false);
        res.unwrap();
        assert_eq!(
            c.items,
            vec![
                Item::LegacyBanner(banner(1_700_000_000, "192.0.2.4", 17, 53, 6, 0, b"hello!")),
                Item::LegacyBanner(banner(1_700_000_001, "192.0.2.5", 6, 80, 6, 0, b"")),
                Item::LegacyBanner(banner(1_700_000_002, "192.0.2.6", 132, 2905, 37, 0, b"x")),
                Item::Banner(after),
            ]
        );

        // Файл кончается на теле типа 4: лишнего байта нет.
        let mut cut = legacy(5, 1_700_000_000, [192, 0, 2, 6], 6, 80, 4, b"ok");
        let t4 = legacy(4, 1_700_000_001, [192, 0, 2, 4], 17, 53, 6, b"hello!");
        cut.extend_from_slice(&t4[..t4.len() - 1]);
        assert!(matches!(
            read_items_all(&with_header(&cut), false).1,
            Err(ReadError::ExtraByte)
        ));
        let scratch = Scratch::new();
        let path = tmp_file(&scratch, "t4", &with_header(&cut));
        let (out, log, res) = list_of(&path, &no_filter());
        assert_eq!(res.unwrap_err(), LOGGED);
        assert_eq!(log, format!("[+] --readscan {path}\n[-] read() error\n"));
        assert_eq!(
            out,
            "#masscan\nbanner tcp 80 192.0.2.6 1700000000 http ok\n"
        );
    }

    /// `parse_banner4` пропускает тело короче 13 байт, `parse_banner9` короче 14 (`in-binary.c:384-385`, :423–424),
    /// молча и до `when_scan_started`: время такой записи не начало скана.
    #[test]
    fn readscan_type5_and_9_short_skipped() {
        let mut tail = vec![5, 12];
        tail.extend([0x11; 12]);
        tail.extend([9, 13]);
        tail.extend([0x22; 13]);
        tail.extend([4, 11]);
        tail.extend([0x33; 12]);
        tail.extend([9, 0, 5, 0]);
        let ok = banner(1_700_000_009, "192.0.2.9", 6, 80, 4, 64, b"x");
        tail.extend(&make_bin_items(&[Item::Banner(ok.clone())])[BLOCK..]);
        let (c, res) = read_items_all(&with_header(&tail), false);
        res.unwrap();
        assert_eq!(c.items, vec![Item::Banner(ok)]);
        assert_eq!(c.times, vec![1_700_000_009]);
        let scratch = Scratch::new();
        let path = file_with_header_bytes(&scratch, "short", b"masscan/1.1\ns:5\n", &tail);
        assert_eq!(started_of(&path, &no_filter()), header_for(1_700_000_009));
    }

    /// `parse_banner6` (`in-binary.c:280-330`): версия не 6 (и тело короче 11 байт, где версии нет) это
    /// `[-] corrupt record` без имени файла, запись пропущена, чтение идёт дальше. С версией 6, но телом короче 27
    /// байт запись молча не выводится (`offset > length`, :318–319), а её время уже стало началом скана (:304–305).
    #[test]
    fn readscan_type13_bad_version_prints_corrupt_record() {
        let ip = "2001:db8::13";
        let mut tail = raw13(1_700_000_100, 6, 443, 9, 4, ip, b"v4?", 30);
        tail.extend(raw13(1_700_000_101, 6, 443, 9, 6, ip, b"", 10));
        tail.extend(raw13(1_700_000_102, 6, 443, 9, 6, ip, b"", 11));
        tail.extend(raw13(1_700_000_103, 6, 443, 9, 6, ip, b"", 26));
        tail.extend(raw13(1_700_000_104, 17, 53, 6, 6, ip, b"ok", 29));
        let (c, res) = read_items_all(&with_header(&tail), false);
        res.unwrap();
        assert_eq!(c.corrupt, 2);
        assert_eq!(c.times, vec![1_700_000_102, 1_700_000_103, 1_700_000_104]);
        let want = banner(1_700_000_104, ip, 17, 53, 6, 57, b"ok");
        assert_eq!(c.items, vec![Item::Banner(want)]);
        let scratch = Scratch::new();
        let path = tmp_file(&scratch, "t13", &with_header(&tail));
        let (out, log, res) = list_of(&path, &no_filter());
        res.unwrap();
        assert_eq!(
            log,
            format!("[+] --readscan {path}\n[-] corrupt record\n[-] corrupt record\n")
        );
        assert_eq!(
            out,
            "#masscan\nbanner udp 53 2001:db8::13 1700000104 dns-ver ok\n# end\n"
        );
        // Начало скана из записи, которая не вывелась.
        let p2 = file_with_header_bytes(&scratch, "t13s", b"masscan/1.1\n", &tail);
        assert_eq!(started_of(&p2, &no_filter()), header_for(1_700_000_102));
    }

    fn types(names: &[u16]) -> ReadFilter {
        let mut cfg = ScanConfig::default();
        cfg.banner_types.extend(names);
        ReadFilter::from_config(&cfg)
    }

    /// `--banner-types` не пуст: записи статуса (типы 1, 2, 6, 7, 10, 11, у этого порта и 8) пропускаются не
    /// разобранными (`if (!btypes->count)`, `in-binary.c:584-623`): нет вывода, нет начала скана, нет `[-] corrupt
    /// record` и отказа по протоколу; баннеры 9 и 13 фильтруются по номеру приложения, 3/4/5 проходят все.
    #[test]
    fn banner_types_drop_all_status_records() {
        let mut tail = make_bin_items(&[
            Item::Status(rec(1_700_000_000, [192, 0, 2, 1], 80, Status::Open)),
            Item::Banner(banner(
                1_700_000_001,
                "192.0.2.1",
                6,
                80,
                4,
                64,
                b"HTTP/1.1",
            )),
            Item::Status(v6(1_700_000_002, "2001:db8::1", 443, Status::Closed)),
            Item::Banner(banner(1_700_000_003, "2001:db8::1", 17, 53, 6, 64, b"9.18")),
        ])[BLOCK..]
            .to_vec();
        tail.truncate(tail.len() - BLOCK);
        tail.extend(raw6(10, "2001:db8::2", 7, 6, 4, 26));
        tail.extend(record_bytes(6, 13, 47));
        tail.extend([1, 12]);
        tail.extend([0; 12]);
        tail.extend([2, 12]);
        tail.extend([0; 12]);
        tail.extend(record_bytes(8, 13, 0));
        tail.extend(legacy(5, 1_700_000_004, [10, 5, 0, 1], 17, 161, 7, b"sys"));
        let bytes = with_header(&tail);
        // Без `--banner-types` первая же устаревшая запись статуса это отказ: файл читается дальше только с ним.
        assert!(matches!(
            read_items_all(&bytes, false).1,
            Err(ReadError::UnsupportedProtocol(47))
        ));
        let (c, res) = read_items_all(&bytes, true);
        res.unwrap();
        assert_eq!(c.corrupt, 0);
        assert_eq!(c.times, vec![1_700_000_001, 1_700_000_003, 1_700_000_004]);
        assert_eq!(c.items.len(), 3);
        assert!(c.items.iter().all(|i| !matches!(i, Item::Status(_))));

        let scratch = Scratch::new();
        let path = tmp_file(&scratch, "bt", &bytes);
        let (out, log, res) = list_of(&path, &types(&[6]));
        res.unwrap();
        assert_eq!(log, format!("[+] --readscan {path}\n"));
        assert_eq!(
            out,
            "#masscan\nbanner udp 53 2001:db8::1 1700000003 dns-ver 9.18\n\
             banner udp 161 10.5.0.1 1700000004 snmp sys\n# end\n"
        );
        let (out, _, res) = list_of(&path, &types(&[4, 6]));
        res.unwrap();
        assert_eq!(out.lines().count(), 5, "{out}");
        // Начало скана из первого баннера: запись статуса до него не разобрана.
        assert_eq!(started_of(&path, &types(&[9])), header_for(1_700_000_001));
    }

    /// Устаревшие баннеры 3, 4, 5 не проходят ни фильтр адреса и порта, ни `--banner-types` (`in-binary.c:592-603`,
    /// у них нет вызова `readscan_filter_pass`); тип 9 и статус фильтруются.
    #[test]
    fn types_3_4_5_bypass_filters() {
        let mut tail = legacy(3, 1_700_000_000, [10, 3, 0, 1], 0, 22, 2, b"SSH-2.0");
        tail.extend(legacy(4, 1_700_000_001, [10, 4, 0, 1], 17, 53, 6, b"9.18"));
        tail.extend(legacy(5, 1_700_000_002, [10, 5, 0, 1], 99, 7, 65535, b""));
        let v9 = make_bin_items(&[
            Item::Banner(banner(1_700_000_003, "10.9.0.1", 6, 80, 4, 64, b"drop")),
            Item::Banner(banner(1_700_000_004, "192.0.2.5", 6, 443, 9, 64, b"keep")),
            Item::Status(rec(1_700_000_005, [192, 0, 2, 5], 443, Status::Open)),
            Item::Banner(banner(1_700_000_006, "192.0.2.5", 17, 443, 9, 64, b"udp")),
        ]);
        tail.extend(&v9[BLOCK..v9.len() - BLOCK]);
        let scratch = Scratch::new();
        let path = tmp_file(&scratch, "legacy", &with_header(&tail));
        let mut cfg = ScanConfig::default();
        add_target_string(cfg.targets.ipv4_mut(), "192.0.2.0/24").unwrap();
        parse_ports(cfg.targets.ports_mut(), "443").unwrap();
        cfg.banner_types.insert(9);
        let (out, _, res) = list_of(&path, &ReadFilter::from_config(&cfg));
        res.unwrap();
        assert_eq!(
            out,
            "#masscan\nbanner tcp 22 10.3.0.1 1700000000 ssh SSH-2.0\n\
             banner udp 53 10.4.0.1 1700000001 dns-ver 9.18\n\
             banner err 7 10.5.0.1 1700000002 (65535) \n\
             banner tcp 443 192.0.2.5 1700000004 ssl keep\n# end\n"
        );
        // Без `--banner-types` тот же фильтр пропускает статус; UDP 443 не проходит `-p443` (Р5: порт со сдвигом).
        cfg.banner_types.clear();
        let (out, _, res) = list_of(&path, &ReadFilter::from_config(&cfg));
        res.unwrap();
        assert!(out.contains("open tcp 443 192.0.2.5 1700000005\n"), "{out}");
        assert!(!out.contains(" drop\n") && !out.contains(" udp\n"), "{out}");
        assert_eq!(out.lines().count(), 7, "{out}");
    }

    /// `-oB` пишет устаревшие баннеры типом 9 (`binary_out_banner`, `out-binary.c:293-355`): они только IPv4, TTL 0, у
    /// типа 3 протокол TCP.
    #[test]
    fn binary_rewrites_3_4_5_as_9() {
        let mut tail = legacy(3, 1_700_000_000, [10, 3, 0, 1], 0, 22, 2, b"SSH-2.0");
        tail.extend(legacy(4, 1_700_000_001, [10, 4, 0, 1], 17, 53, 6, b"9.18"));
        tail.extend(legacy(
            5,
            1_700_000_002,
            [10, 5, 0, 1],
            132,
            2905,
            37,
            &[b'z'; 120],
        ));
        let scratch = Scratch::new();
        let path = tmp_file(&scratch, "rw", &with_header(&tail));
        let (out, _, res) = convert(std::slice::from_ref(&path), Format::Binary, &no_filter());
        res.unwrap();
        let mut want = vec![9, 14 + 7];
        want.extend(1_700_000_000u32.to_be_bytes());
        want.extend([10, 3, 0, 1, 6, 0, 22, 0, 2, 0]);
        want.extend(b"SSH-2.0");
        assert_eq!(out[BLOCK..BLOCK + want.len()], want[..]);
        let (c, res) = read_items_all(&out, false);
        res.unwrap();
        assert_eq!(
            c.items,
            vec![
                Item::Banner(banner(1_700_000_000, "10.3.0.1", 6, 22, 2, 0, b"SSH-2.0")),
                Item::Banner(banner(1_700_000_001, "10.4.0.1", 17, 53, 6, 0, b"9.18")),
                Item::Banner(banner(
                    1_700_000_002,
                    "10.5.0.1",
                    132,
                    2905,
                    37,
                    0,
                    &[b'z'; 120]
                )),
            ]
        );
        // 120 байт: длина `-oB` в два байта, `((120+14)>>7)|0x80` и `(120+14)&0x7F`.
        let start = out.len() - BLOCK - (3 + 14 + 120);
        assert_eq!(out[start..start + 3], [9, 0x81, 6]);
    }

    /// Изменённые и обрезанные записи баннеров (3, 4, 5, 9, 13) не роняют читатель ни с `--banner-types`, ни без.
    #[test]
    fn readscan_banner_records_survive_random_mutation_and_truncation() {
        let mut tail = make_bin_items(&[
            Item::Banner(banner(1, "192.0.2.1", 17, 53, 6, 57, b"9.18.24")),
            Item::Banner(banner(2, "2001:db8::1", 6, 443, 9, 64, &[0xAB; 130])),
            Item::Status(rec(3, [10, 0, 0, 1], 80, Status::Open)),
        ]);
        tail.truncate(tail.len() - BLOCK);
        tail.extend(legacy(3, 4, [10, 3, 0, 1], 0, 22, 2, b"SSH"));
        tail.extend(legacy(4, 5, [10, 4, 0, 1], 17, 53, 6, b"x"));
        tail.extend(legacy(5, 6, [10, 5, 0, 1], 6, 80, 4, b"y"));
        let base = tail;
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for i in 0..4000 {
            let mut b = base.clone();
            for _ in 0..(next() % 6) {
                let k = BLOCK + (next() as usize) % (b.len() - BLOCK);
                b[k] = next() as u8;
            }
            let cut = (next() as usize) % 60;
            b.truncate(b.len().saturating_sub(cut));
            let _ = read_items_all(&b, i % 2 == 0);
        }
    }

    /// Файл с заголовком `head` (дополняется нулями до 99 байт) и хвостом `tail` как есть.
    fn file_with_header_bytes(scratch: &Scratch, name: &str, head: &[u8], tail: &[u8]) -> String {
        let mut v = head.to_vec();
        v.resize(BLOCK, 0);
        v.extend_from_slice(tail);
        tmp_file(scratch, name, &v)
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
