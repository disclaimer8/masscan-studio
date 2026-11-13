//! Входы эталонов UDP-баннеров (`tests/golden/udp-banners`, AGPL-3.0): датаграммы ответов, по которым C-оракул
//! `udp-oracle` (обвязка вокруг `handle_udp` masscan © Robert David Graham, вне репозитория, Р14) записал эталоны.
//! Ответы собраны по справке UDP-парсеров (`docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-output-udp.md`
//! B0–B4): успех, каждый ранний выход, неверный cookie, `--rawudp`, обрезки; плюс вектор selftest C
//! (`src/proto-snmp.c:630-644`).
//!
//! `cargo run -p rmasscan-proto --example udp_golden_inputs -- DIR` пишет `DIR/cases/<имя>.bin` и `DIR/cases.tsv`
//! (имя, порт, cookie, rawudp, режим, описание) для `run-goldens.sh` оракула. Тот же модуль подключает
//! `tests/udp_golden.rs`: тест сверяет закоммиченные `cases/*.bin` с [`cases`] и разворачивает разделы
//! ([`Case::sections`]) так же, как оракул.

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

/// `(unsigned)syn_cookie(...)` большинства кейсов: DNS/NBNS видят `0x1234`, SNMP `0x5EED1234`.
pub const COOKIE: u32 = 0x5EED_1234;
/// Тот же cookie с другим младшим словом: id DNS/NBNS и request-id SNMP не совпадают.
pub const WRONG_COOKIE: u32 = 0x5EED_1235;

/// Как оракул разворачивает датаграмму в разделы (`udp_oracle.c`, аргумент MODE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Один раздел: вся датаграмма.
    Whole,
    /// Раздел на каждую длину префикса `0..=n` (обрезки).
    Prefixes,
    /// 256 разделов: байт по смещению принимает значения `0..=255`.
    Sweep(usize),
}

impl Mode {
    pub fn arg(&self) -> String {
        match self {
            Mode::Whole => "whole".to_string(),
            Mode::Prefixes => "prefixes".to_string(),
            Mode::Sweep(off) => format!("sweep:{off}"),
        }
    }
}

/// Один кейс эталона.
pub struct Case {
    pub name: &'static str,
    /// Порт источника ответа (`port_them`), по нему `handle_udp` выбирает парсер (`src/proto-udp.c:76-113`).
    pub port: u16,
    pub cookie: u32,
    pub rawudp: bool,
    pub mode: Mode,
    pub payload: Vec<u8>,
    /// Что кейс проверяет.
    pub about: &'static str,
}

impl Case {
    /// Разделы как у оракула: подпись (`len=N`, у развёртки `len=N byte[OFF]=K`) и датаграмма.
    pub fn sections(&self) -> Vec<(String, Vec<u8>)> {
        let n = self.payload.len();
        match self.mode {
            Mode::Whole => vec![(format!("len={n}"), self.payload.clone())],
            Mode::Prefixes => (0..=n)
                .map(|k| (format!("len={k}"), self.payload[..k].to_vec()))
                .collect(),
            Mode::Sweep(off) => (0..=255u8)
                .map(|k| {
                    let mut p = self.payload.clone();
                    p[off] = k;
                    (format!("len={n} byte[{off}]={k}"), p)
                })
                .collect(),
        }
    }
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

fn find(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len())
        .position(|w| w == needle)
        .expect("needle in the generated payload")
}

// ---- DNS (B1) и NBNS (B3): заголовок и записи RFC 1035 ----

const DNS_ID: u16 = (COOKIE & 0xFFFF) as u16;
/// QR=1, AA=1, RCODE=0.
const FLAGS_REPLY: u16 = 0x8400;

fn dns_header(id: u16, flags: u16, qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
    cat(&[
        &be16(id),
        &be16(flags),
        &be16(qd),
        &be16(an),
        &be16(ns),
        &be16(ar),
    ])
}

fn dns_name(labels: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for l in labels {
        v.push(u8::try_from(l.len()).expect("label length"));
        v.extend_from_slice(l);
    }
    v.push(0);
    v
}

fn version_bind() -> Vec<u8> {
    dns_name(&[b"version", b"bind"])
}

fn question(name: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
    cat(&[name, &be16(qtype), &be16(qclass)])
}

/// RR с явным RDLENGTH (может не совпадать с длиной `rdata`).
fn rr_len(name: &[u8], rtype: u16, class: u16, rdlength: u16, rdata: &[u8]) -> Vec<u8> {
    cat(&[
        name,
        &be16(rtype),
        &be16(class),
        &[0, 0, 0, 0],
        &be16(rdlength),
        rdata,
    ])
}

fn rr(name: &[u8], rtype: u16, class: u16, rdata: &[u8]) -> Vec<u8> {
    rr_len(
        name,
        rtype,
        class,
        u16::try_from(rdata.len()).expect("rdata"),
        rdata,
    )
}

fn txt(strings: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for s in strings {
        v.push(u8::try_from(s.len()).expect("string length"));
        v.extend_from_slice(s);
    }
    v
}

/// EDNS0 OPT (RFC 6891): имя `.`, тип 41, класс = размер UDP, TTL = расширенный RCODE, версия, флаги.
fn opt_rr(udp_size: u16, ext_rcode: u8) -> Vec<u8> {
    cat(&[
        &[0],
        &be16(41),
        &be16(udp_size),
        &[ext_rcode, 0, 0, 0],
        &be16(0),
    ])
}

const PTR_QNAME: [u8; 2] = [0xC0, 0x0C];
const TYPE_TXT: u16 = 0x10;
const CLASS_CH: u16 = 3;
const CLASS_IN: u16 = 1;

/// Ответ на зонд `version.bind` TXT CHAOS (`src/templ-payloads.c:76-86`) с данными ответа `answers` (уже
/// закодированные RR, `an` штук) и дополнительными RR `additional`.
fn chaos_reply(id: u16, flags: u16, answers: &[Vec<u8>], additional: &[Vec<u8>]) -> Vec<u8> {
    let mut v = dns_header(
        id,
        flags,
        1,
        u16::try_from(answers.len()).expect("an"),
        0,
        u16::try_from(additional.len()).expect("ar"),
    );
    v.extend(question(&version_bind(), TYPE_TXT, CLASS_CH));
    for a in answers.iter().chain(additional) {
        v.extend_from_slice(a);
    }
    v
}

fn chaos_answer(rdata: &[u8]) -> Vec<u8> {
    rr(&PTR_QNAME, TYPE_TXT, CLASS_CH, rdata)
}

fn version_txt() -> Vec<u8> {
    txt(&[b"9.18.24"])
}

fn chaos_ok() -> Vec<u8> {
    chaos_reply(DNS_ID, FLAGS_REPLY, &[chaos_answer(&version_txt())], &[])
}

fn dns_cases() -> Vec<Case> {
    let ok = chaos_ok();
    let with = |name, cookie, rawudp, mode, payload, about| Case {
        name,
        port: 53,
        cookie,
        rawudp,
        mode,
        payload,
        about,
    };
    let reply = |answers: &[Vec<u8>], additional: &[Vec<u8>], flags: u16| {
        chaos_reply(DNS_ID, flags, answers, additional)
    };
    // Цепочка указателей в хвосте сообщения: ответ -> хвост -> ... -> имя вопроса.
    let chain = |pointers: usize| {
        let mut v = dns_header(DNS_ID, FLAGS_REPLY, 1, 1, 0, 0);
        v.extend(question(&version_bind(), TYPE_TXT, CLASS_CH));
        let answer_at = v.len();
        let tail = answer_at + 2 + 10 + version_txt().len();
        let first = u16::try_from(tail).expect("tail") | 0xC000;
        v.extend(rr(&be16(first), TYPE_TXT, CLASS_CH, &version_txt()));
        for i in 1..pointers {
            let next = if i + 1 == pointers {
                0x0C
            } else {
                tail + 2 * i
            };
            v.extend(be16(u16::try_from(next).expect("ptr") | 0xC000));
        }
        v
    };
    let long_name = |last: usize| {
        let a = [b'a'; 63];
        let b = vec![b'b'; last];
        dns_name(&[&a, &a, &a, &b])
    };
    vec![
        with(
            "dns-chaos-txt",
            COOKIE,
            false,
            Mode::Prefixes,
            ok.clone(),
            "ответ на зонд version.bind: только dns-ver (handle_dns вернул 1); все обрезки, в том числе усечение txtlen по концу датаграммы (src/proto-dns.c:433-434)",
        ),
        with(
            "dns-chaos-txt-rawudp",
            COOKIE,
            true,
            Mode::Whole,
            ok.clone(),
            "--rawudp добавляет сырой баннер и после return 1 (src/proto-udp.c:120)",
        ),
        with(
            "dns-chaos-txt-wrong-cookie",
            WRONG_COOKIE,
            false,
            Mode::Whole,
            ok.clone(),
            "id != cookie & 0xFFFF: ничего (src/proto-dns.c:373-374)",
        ),
        with(
            "dns-chaos-txt-wrong-cookie-rawudp",
            WRONG_COOKIE,
            true,
            Mode::Whole,
            ok.clone(),
            "неверный cookie с --rawudp: только сырой баннер",
        ),
        with(
            "dns-chaos-txt-cookie-high-bits",
            0xA5A5_1234,
            false,
            Mode::Whole,
            ok.clone(),
            "сравниваются только младшие 16 бит cookie",
        ),
        with(
            "dns-flags-hi-sweep",
            COOKIE,
            false,
            Mode::Sweep(2),
            ok.clone(),
            "все значения байта QR/opcode/AA/TC/RD: QR=0 даёт сырой баннер (src/proto-dns.c:381-382)",
        ),
        with(
            "dns-flags-lo-sweep",
            COOKIE,
            false,
            Mode::Sweep(3),
            ok.clone(),
            "все значения байта RA/Z/RCODE: строки RCODE 1-9 (src/proto-dns.c:388-409), 0 и 10-15 идут в разбор TXT",
        ),
        with(
            "dns-rcode-3-rawudp",
            COOKIE,
            true,
            Mode::Whole,
            reply(&[chaos_answer(&version_txt())], &[], FLAGS_REPLY | 3),
            "RCODE 3 с --rawudp: один сырой баннер (status 0)",
        ),
        with(
            "dns-txt-two-strings",
            COOKIE,
            false,
            Mode::Whole,
            reply(&[chaos_answer(&txt(&[b"abc", b"def"]))], &[], FLAGS_REPLY),
            "только первая строка TXT (src/proto-dns.c:428)",
        ),
        with(
            "dns-txt-uncompressed-name",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[rr(&version_bind(), TYPE_TXT, CLASS_CH, &version_txt())],
                &[],
                FLAGS_REPLY,
            ),
            "имя ответа без сжатия",
        ),
        with(
            "dns-txt-empty-string",
            COOKIE,
            false,
            Mode::Whole,
            reply(&[chaos_answer(&[0])], &[], FLAGS_REPLY),
            "TXT из пустой строки: пустой баннер dns-ver",
        ),
        with(
            "dns-txt-rdlength-0",
            COOKIE,
            false,
            Mode::Whole,
            cat(&[
                &reply(&[rr(&PTR_QNAME, TYPE_TXT, CLASS_CH, &[])], &[], FLAGS_REPLY),
                &[5],
            ]),
            "RDLENGTH 0 (и байт после записи): сырой баннер (src/proto-dns.c:436)",
        ),
        with(
            "dns-txt-len-over-rdlength",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[rr_len(&PTR_QNAME, TYPE_TXT, CLASS_CH, 4, &version_txt())],
                &[],
                FLAGS_REPLY,
            ),
            "длина строки больше RDLENGTH-1: сырой баннер",
        ),
        with(
            "dns-txt-rdlength-past-end",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[rr_len(&PTR_QNAME, TYPE_TXT, CLASS_CH, 200, &version_txt())],
                &[],
                FLAGS_REPLY,
            ),
            "RDLENGTH за концом датаграммы: разбор RR обрывается, но rr_offset[1] записан, текст печатается",
        ),
        with(
            "dns-txt-len-clamped",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[rr_len(
                    &PTR_QNAME,
                    TYPE_TXT,
                    CLASS_CH,
                    200,
                    &cat(&[&[100], b"9.18.24"]),
                )],
                &[],
                FLAGS_REPLY,
            ),
            "длина строки 100 при 7 оставшихся байтах: усечение по концу датаграммы",
        ),
        with(
            "dns-answer-type-a",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[rr(&PTR_QNAME, 1, CLASS_IN, &[192, 0, 2, 53])],
                &[],
                FLAGS_REPLY,
            ),
            "ответ не TXT: сырой баннер (src/proto-dns.c:438-439)",
        ),
        with(
            "dns-answer-txt-class-in",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[rr(&PTR_QNAME, TYPE_TXT, CLASS_IN, &version_txt())],
                &[],
                FLAGS_REPLY,
            ),
            "TXT класса IN: сырой баннер",
        ),
        with(
            "dns-edns-ext-rcode",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[chaos_answer(&version_txt())],
                &[opt_rr(4096, 1)],
                FLAGS_REPLY,
            ),
            "EDNS0: RCODE |= ext << 4 = 16, строки нет, разбор TXT (src/proto-dns.c:298-305)",
        ),
        with(
            "dns-edns-ext-rcode-nxdomain",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[chaos_answer(&version_txt())],
                &[opt_rr(4096, 1)],
                FLAGS_REPLY | 3,
            ),
            "RCODE 3 с ext 1 = 19: строки нет, разбор TXT",
        ),
        with(
            "dns-edns-small-udp-size",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[chaos_answer(&version_txt())],
                &[opt_rr(256, 1)],
                FLAGS_REPLY | 3,
            ),
            "OPT с размером UDP < 512: разбор останавливается до ext, RCODE остаётся 3",
        ),
        with(
            "dns-qd0-two-answers",
            COOKIE,
            false,
            Mode::Whole,
            cat(&[
                &dns_header(DNS_ID, FLAGS_REPLY, 0, 2, 0, 0),
                &rr(&version_bind(), 1, CLASS_IN, &[192, 0, 2, 53]),
                &rr(&version_bind(), TYPE_TXT, CLASS_CH, &txt(&[b"second"])),
            ]),
            "без вопроса rr_offset[1] это второй ответ (src/proto-dns.c:419)",
        ),
        with(
            "dns-qd0-one-answer",
            COOKIE,
            false,
            Mode::Whole,
            cat(&[
                &dns_header(DNS_ID, FLAGS_REPLY, 0, 1, 0, 0),
                &rr(&version_bind(), TYPE_TXT, CLASS_CH, &version_txt()),
            ]),
            "одна запись: rr_offset[1] у C не инициализирован (C1.16); у нас сырой баннер",
        ),
        with(
            "dns-qd2",
            COOKIE,
            false,
            Mode::Whole,
            cat(&[
                &dns_header(DNS_ID, FLAGS_REPLY, 2, 1, 0, 0),
                &question(&version_bind(), TYPE_TXT, CLASS_CH),
                &question(&version_bind(), TYPE_TXT, CLASS_CH),
                &chaos_answer(&version_txt()),
            ]),
            "два вопроса: rr_offset[1] это второй вопрос, C читает его как RR",
        ),
        with(
            "dns-header-only",
            COOKIE,
            false,
            Mode::Whole,
            dns_header(DNS_ID, FLAGS_REPLY, 0, 0, 0, 0),
            "только заголовок: rr_offset[1] не инициализирован у C; у нас сырой баннер",
        ),
        with(
            "dns-formerr-header-only",
            COOKIE,
            false,
            Mode::Whole,
            dns_header(DNS_ID, FLAGS_REPLY | 1, 0, 0, 0, 0),
            "FORMERR без записей: строка 1:FORMERR и сырой; у C dns_extract_name читает неинициализированный rr_offset[0] (src/proto-dns.c:318)",
        ),
        with(
            "dns-question-only",
            COOKIE,
            false,
            Mode::Whole,
            cat(&[
                &dns_header(DNS_ID, FLAGS_REPLY, 1, 0, 0, 0),
                &question(&version_bind(), TYPE_TXT, CLASS_CH),
            ]),
            "только вопрос: rr_offset[1] не инициализирован у C; у нас сырой баннер",
        ),
        with(
            "dns-question-bad-class",
            COOKIE,
            false,
            Mode::Whole,
            cat(&[
                &dns_header(DNS_ID, FLAGS_REPLY, 1, 1, 0, 0),
                &question(&version_bind(), TYPE_TXT, 2),
                &chaos_answer(&version_txt()),
            ]),
            "класс вопроса 2: разбор стоит на вопросе (src/proto-dns.c:249-250), rr_offset[1] не инициализирован у C",
        ),
        with(
            "dns-short-11",
            COOKIE,
            false,
            Mode::Whole,
            ok[..11].to_vec(),
            "датаграмма < 12 байт: id у C не инициализирован (C1.16); у нас несовпадение, ничего",
        ),
        with(
            "dns-short-11-rawudp",
            COOKIE,
            true,
            Mode::Whole,
            ok[..11].to_vec(),
            "то же с --rawudp: только сырой баннер",
        ),
        with(
            "dns-empty",
            COOKIE,
            false,
            Mode::Whole,
            Vec::new(),
            "пустая датаграмма",
        ),
        with(
            "dns-pointer-to-id",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[rr(&[0xC0, 0x00], TYPE_TXT, CLASS_CH, &version_txt())],
                &[],
                FLAGS_REPLY,
            ),
            "указатель сжатия на смещение 0: у C смещение в кадре (заголовок Ethernet), у нас в датаграмме",
        ),
        with(
            "dns-pointer-loop",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[rr(&[0xC0, 30], TYPE_TXT, CLASS_CH, &version_txt())],
                &[],
                FLAGS_REPLY,
            ),
            "указатель на самого себя: больше 4 переходов, имя неверно (src/proto-dns.c:71-73)",
        ),
        with(
            "dns-pointer-chain-4",
            COOKIE,
            false,
            Mode::Whole,
            chain(4),
            "четыре указателя подряд: имя верно",
        ),
        with(
            "dns-pointer-chain-5",
            COOKIE,
            false,
            Mode::Whole,
            chain(5),
            "пять указателей подряд: имя неверно",
        ),
        with(
            "dns-label-0x40",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[rr(&[0x41, b'x', 0], TYPE_TXT, CLASS_CH, &version_txt())],
                &[],
                FLAGS_REPLY,
            ),
            "метка типа 01 (EDNS): имя неверно (src/proto-dns.c:126-132)",
        ),
        with(
            "dns-label-0x80",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[rr(&[0x81, b'x', 0], TYPE_TXT, CLASS_CH, &version_txt())],
                &[],
                FLAGS_REPLY,
            ),
            "метка типа 10: имя неверно",
        ),
        with(
            "dns-name-254",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[rr(&long_name(61), TYPE_TXT, CLASS_CH, &version_txt())],
                &[],
                FLAGS_REPLY,
            ),
            "имя длины 254: верно (src/proto-dns.c:106-107)",
        ),
        with(
            "dns-name-255",
            COOKIE,
            false,
            Mode::Whole,
            reply(
                &[rr(&long_name(62), TYPE_TXT, CLASS_CH, &version_txt())],
                &[],
                FLAGS_REPLY,
            ),
            "имя длины 255: неверно",
        ),
        with(
            "dns-many-questions",
            COOKIE,
            false,
            Mode::Whole,
            {
                let mut v = dns_header(DNS_ID, FLAGS_REPLY, 1100, 0, 0, 0);
                for _ in 0..1100 {
                    v.extend(question(&[0], TYPE_TXT, CLASS_CH));
                }
                v
            },
            "1100 вопросов: предел 1024 записи rr_offset (src/proto-dns.c:241-242), rr_offset[1] это второй вопрос",
        ),
        with(
            "dns-many-answers",
            COOKIE,
            false,
            Mode::Whole,
            {
                let answers: Vec<Vec<u8>> =
                    (0..1030).map(|_| chaos_answer(&version_txt())).collect();
                reply(&answers, &[], FLAGS_REPLY)
            },
            "1030 ответов: предел 1024 записи, текст из первого",
        ),
    ]
}

// ---- NTP (B2) ----

/// Ответ режима 7 (`ntp_priv`): байт 0 (response, more, версия 2, режим 7), реализация, код запроса, затем
/// `ntp_modlist_parse` (ошибка и количество, размер записи) и `data` байт записей.
fn ntp7(
    b0: u8,
    implementation: u8,
    code: u8,
    err_count: [u8; 2],
    size: u16,
    data: usize,
) -> Vec<u8> {
    let mut v = vec![b0, 0x00, implementation, code, err_count[0], err_count[1]];
    v.extend(be16(size));
    v.extend(std::iter::repeat_n(0u8, data));
    v
}

/// response=1, more=0, версия 2, режим 7.
const NTP_B0: u8 = 0x97;
const XNTPD: u8 = 3;
const MON_GETLIST_1: u8 = 42;

fn ntp_cases() -> Vec<Case> {
    let with = |name, rawudp, mode, payload, about| Case {
        name,
        port: 123,
        cookie: COOKIE,
        rawudp,
        mode,
        payload,
        about,
    };
    let monlist1 = ntp7(NTP_B0, XNTPD, MON_GETLIST_1, [0x00, 0x01], 72, 72);
    let compact = ntp7(NTP_B0, XNTPD, MON_GETLIST_1, [0x00, 0x01], 8, 8);
    let err = |e: u8| ntp7(NTP_B0, XNTPD, MON_GETLIST_1, [e << 4, 0], 0, 4);
    vec![
        with(
            "ntp-monlist-1",
            false,
            Mode::Prefixes,
            monlist1.clone(),
            "MON_GETLIST_1, одна запись 72 байта: ntp и сырой (src/proto-ntp.c:270-281); обрезки до < 4 и <= 8 байт",
        ),
        with(
            "ntp-monlist-6x72",
            false,
            Mode::Whole,
            ntp7(NTP_B0, XNTPD, MON_GETLIST_1, [0x00, 0x06], 72, 432),
            "пример справки B2: response-size=432-bytes more=false",
        ),
        with(
            "ntp-monlist-more",
            false,
            Mode::Whole,
            ntp7(0xD7, XNTPD, MON_GETLIST_1, [0x00, 0x01], 72, 72),
            "бит more (бит 6 байта 0): more=true",
        ),
        with(
            "ntp-monlist-err-4",
            false,
            Mode::Prefixes,
            err(4),
            "пример справки B2: ошибка 4 без разделителя перед Response (C1.12); при длине 8 текста ошибки нет",
        ),
        with("ntp-err-1", false, Mode::Whole, err(1), "код ошибки 1"),
        with("ntp-err-2", false, Mode::Whole, err(2), "код ошибки 2"),
        with("ntp-err-3", false, Mode::Whole, err(3), "код ошибки 3"),
        with(
            "ntp-err-5",
            false,
            Mode::Whole,
            err(5),
            "код ошибки 5: Bogus Error Code",
        ),
        with("ntp-err-7", false, Mode::Whole, err(7), "код ошибки 7"),
        with(
            "ntp-err-15",
            false,
            Mode::Whole,
            err(15),
            "код ошибки 15: Bogus Error Code",
        ),
        with(
            "ntp-byte0-sweep",
            false,
            Mode::Sweep(0),
            compact.clone(),
            "все значения байта 0: версия не 2 даёт только сырой (src/proto-ntp.c:251-262), без бита ответа и не режим 7 пустой ntp",
        ),
        with(
            "ntp-impl-sweep",
            false,
            Mode::Sweep(2),
            compact.clone(),
            "все реализации: UNIV, XNTPD-OLD, XNTPD, остальные пусто (src/proto-ntp.c:167-173)",
        ),
        with(
            "ntp-code-sweep",
            false,
            Mode::Sweep(3),
            compact.clone(),
            "все коды запроса XNTPD (src/proto-ntp.c:34-73), разбор списка только у 42",
        ),
        with(
            "ntp-err-count-sweep",
            false,
            Mode::Sweep(4),
            compact.clone(),
            "все значения байта ошибки и старших бит количества (src/proto-ntp.c:116-141)",
        ),
        with(
            "ntp-too-big-length",
            false,
            Mode::Whole,
            ntp7(NTP_B0, XNTPD, MON_GETLIST_1, [0x00, 0x02], 72, 72),
            "4 + count*size > длины: response-too-big",
        ),
        with(
            "ntp-too-big-500",
            false,
            Mode::Whole,
            ntp7(NTP_B0, XNTPD, MON_GETLIST_1, [0x00, 0x01], 501, 501),
            "count*size = 501 > 500: response-too-big",
        ),
        with(
            "ntp-size-500",
            false,
            Mode::Whole,
            ntp7(NTP_B0, XNTPD, MON_GETLIST_1, [0x00, 0x01], 500, 500),
            "count*size = 500: ещё печатается",
        ),
        with(
            "ntp-v4-server",
            false,
            Mode::Whole,
            {
                let mut v = vec![0x24, 0x02, 0x06, 0xE9];
                v.extend(std::iter::repeat_n(0x11u8, 44));
                v
            },
            "обычный ответ сервера NTPv4: версия 4, только сырой баннер",
        ),
        with(
            "ntp-short-3",
            false,
            Mode::Whole,
            vec![NTP_B0, 0x00, XNTPD],
            "меньше 4 байт: только сырой",
        ),
        with(
            "ntp-monlist-1-rawudp",
            true,
            Mode::Whole,
            monlist1,
            "--rawudp: сырой один раз (status 0)",
        ),
    ]
}

// ---- NetBIOS name service (B3) ----

const NBSTAT: u16 = 0x21;

/// Запись имени NBSTAT: 15 байт имени (дополнено пробелами), суффикс, два байта флагов.
fn nb_entry(name: &[u8], suffix: u8, flags: u16) -> Vec<u8> {
    let mut v = name.to_vec();
    v.resize(15, b' ');
    v.push(suffix);
    v.extend(be16(flags));
    v
}

const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

fn nbstat_rdata(count: u8, entries: &[Vec<u8>], tail: &[u8]) -> Vec<u8> {
    let mut v = vec![count];
    for e in entries {
        v.extend_from_slice(e);
    }
    v.extend_from_slice(tail);
    v
}

/// Имя ответа: закодированное `*` из зонда (`src/templ-payloads.c:109-118`).
fn nb_wildcard_name() -> Vec<u8> {
    dns_name(&[b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"])
}

fn nbns_reply(flags: u16, qd: &[Vec<u8>], answers: &[Vec<u8>], additional: &[Vec<u8>]) -> Vec<u8> {
    let mut v = dns_header(
        DNS_ID,
        flags,
        u16::try_from(qd.len()).expect("qd"),
        u16::try_from(answers.len()).expect("an"),
        0,
        u16::try_from(additional.len()).expect("ar"),
    );
    for p in qd.iter().chain(answers).chain(additional) {
        v.extend_from_slice(p);
    }
    v
}

fn nbns_cases() -> Vec<Case> {
    let with = |name, cookie, rawudp, mode, payload, about| Case {
        name,
        port: 137,
        cookie,
        rawudp,
        mode,
        payload,
        about,
    };
    let two = [
        nb_entry(b"HOST1", 0x00, 0x0400),
        nb_entry(b"WORKGROUP", 0x00, 0x8400),
    ];
    let stats = cat(&[&MAC, &[0u8; 40]]);
    let rdata = nbstat_rdata(2, &two, &stats);
    let answer = rr(&nb_wildcard_name(), NBSTAT, CLASS_IN, &rdata);
    let ok = nbns_reply(FLAGS_REPLY, &[], std::slice::from_ref(&answer), &[]);
    // Короткий ответ для развёрток: имя ответа из одной метки, одно имя NBSTAT и MAC.
    let compact_rdata = nbstat_rdata(1, &[nb_entry(b"HOST1", 0x20, 0x0400)], &MAC);
    let compact = nbns_reply(
        FLAGS_REPLY,
        &[],
        &[rr(&dns_name(&[b"A"]), NBSTAT, CLASS_IN, &compact_rdata)],
        &[],
    );
    let name_char = find(&compact, b"HOST1");
    let probe_question = question(&nb_wildcard_name(), NBSTAT, CLASS_IN);
    let answer_with = |rtype: u16, class: u16, rd: &[u8]| rr(&nb_wildcard_name(), rtype, class, rd);
    vec![
        with(
            "nbns-nbstat",
            COOKIE,
            false,
            Mode::Prefixes,
            ok.clone(),
            "ответ NBSTAT с двумя именами: nbtstat и сырой; MAC печатает первый байт шесть раз (src/proto-netbios.c:87, C1.11); все обрезки",
        ),
        with(
            "nbns-nbstat-rawudp",
            COOKIE,
            true,
            Mode::Whole,
            ok.clone(),
            "--rawudp: сырой один раз (status 0)",
        ),
        with(
            "nbns-nbstat-wrong-cookie",
            WRONG_COOKIE,
            false,
            Mode::Whole,
            ok.clone(),
            "id != cookie & 0xFFFF: ничего (src/proto-netbios.c:129-130)",
        ),
        with(
            "nbns-nbstat-wrong-cookie-rawudp",
            WRONG_COOKIE,
            true,
            Mode::Whole,
            ok.clone(),
            "неверный cookie с --rawudp: только сырой",
        ),
        with(
            "nbns-nbstat-with-question",
            COOKIE,
            false,
            Mode::Whole,
            nbns_reply(
                FLAGS_REPLY,
                std::slice::from_ref(&probe_question),
                &[rr(&PTR_QNAME, NBSTAT, CLASS_IN, &rdata)],
                &[],
            ),
            "ответ с вопросом зонда и сжатым именем: rr_offset[qdcount] = rr_offset[1]",
        ),
        with(
            "nbns-flags-hi-sweep",
            COOKIE,
            false,
            Mode::Sweep(2),
            compact.clone(),
            "все значения байта QR/opcode: QR=0 даёт сырой (src/proto-netbios.c:132-133)",
        ),
        with(
            "nbns-flags-lo-sweep",
            COOKIE,
            false,
            Mode::Sweep(3),
            compact.clone(),
            "все значения байта RA/Z/RCODE: RCODE != 0 даёт сырой (src/proto-netbios.c:134-135)",
        ),
        with(
            "nbns-name-char-sweep",
            COOKIE,
            false,
            Mode::Sweep(name_char),
            compact.clone(),
            "все 256 байт в имени: пробел и NUL как пробел, isalnum||ispunct как есть, иначе <XX> (src/proto-netbios.c:28-55)",
        ),
        with(
            "nbns-qd2",
            COOKIE,
            false,
            Mode::Whole,
            nbns_reply(
                FLAGS_REPLY,
                &[probe_question.clone(), probe_question.clone()],
                std::slice::from_ref(&answer),
                &[],
            ),
            "qdcount 2: сырой (src/proto-netbios.c:136-137)",
        ),
        with(
            "nbns-an0",
            COOKIE,
            false,
            Mode::Whole,
            nbns_reply(FLAGS_REPLY, std::slice::from_ref(&probe_question), &[], &[]),
            "ancount 0: сырой",
        ),
        with(
            "nbns-type-nb",
            COOKIE,
            false,
            Mode::Whole,
            nbns_reply(
                FLAGS_REPLY,
                &[],
                &[answer_with(0x20, CLASS_IN, &rdata)],
                &[],
            ),
            "тип NB (0x20), не NBSTAT: сырой (src/proto-netbios.c:157-158)",
        ),
        with(
            "nbns-class-2",
            COOKIE,
            false,
            Mode::Whole,
            nbns_reply(FLAGS_REPLY, &[], &[answer_with(NBSTAT, 2, &rdata)], &[]),
            "класс 2: сырой",
        ),
        with(
            "nbns-rdlength-0",
            COOKIE,
            false,
            Mode::Whole,
            cat(&[
                &nbns_reply(FLAGS_REPLY, &[], &[answer_with(NBSTAT, CLASS_IN, &[])], &[]),
                &rdata,
            ]),
            "RDLENGTH 0: сырой (src/proto-netbios.c:155-156)",
        ),
        with(
            "nbns-count-over-rdlength",
            COOKIE,
            false,
            Mode::Whole,
            nbns_reply(
                FLAGS_REPLY,
                &[],
                &[rr_len(&nb_wildcard_name(), NBSTAT, CLASS_IN, 2, &rdata)],
                &[],
            ),
            "число имён 2 > RDLENGTH-1 = 1: сырой",
        ),
        with(
            "nbns-question-bad-class",
            COOKIE,
            false,
            Mode::Whole,
            nbns_reply(
                FLAGS_REPLY,
                &[question(&nb_wildcard_name(), NBSTAT, 2)],
                std::slice::from_ref(&answer),
                &[],
            ),
            "класс вопроса 2: разбор стоит на вопросе, rr_offset[1] у C не инициализирован (C1.16); у нас сырой",
        ),
        with(
            "nbns-zero-names",
            COOKIE,
            false,
            Mode::Whole,
            nbns_reply(
                FLAGS_REPLY,
                &[],
                &[answer_with(NBSTAT, CLASS_IN, &nbstat_rdata(0, &[], &stats))],
                &[],
            ),
            "ноль имён: только MAC",
        ),
        with(
            "nbns-count-past-entries",
            COOKIE,
            false,
            Mode::Whole,
            nbns_reply(
                FLAGS_REPLY,
                &[],
                &[answer_with(
                    NBSTAT,
                    CLASS_IN,
                    &nbstat_rdata(5, &two, &stats),
                )],
                &[],
            ),
            "число имён 5 при двух записях: статистика читается как имена, пока помещается 18 байт",
        ),
        with(
            "nbns-mac-3-bytes",
            COOKIE,
            false,
            Mode::Whole,
            nbns_reply(
                FLAGS_REPLY,
                &[],
                &[answer_with(
                    NBSTAT,
                    CLASS_IN,
                    &nbstat_rdata(2, &two, &MAC[..3]),
                )],
                &[],
            ),
            "три байта после имён: три пары с дефисами (src/proto-netbios.c:85-93)",
        ),
        with(
            "nbns-mac-none",
            COOKIE,
            false,
            Mode::Whole,
            nbns_reply(
                FLAGS_REPLY,
                &[],
                &[answer_with(NBSTAT, CLASS_IN, &nbstat_rdata(2, &two, &[]))],
                &[],
            ),
            "после имён ничего: без MAC",
        ),
        with(
            "nbns-edns-ext-rcode",
            COOKIE,
            false,
            Mode::Whole,
            nbns_reply(
                FLAGS_REPLY,
                &[],
                std::slice::from_ref(&answer),
                &[opt_rr(4096, 1)],
            ),
            "EDNS0 ext rcode 1: RCODE 16 != 0, сырой",
        ),
        with(
            "nbns-short-11",
            COOKIE,
            false,
            Mode::Whole,
            ok[..11].to_vec(),
            "датаграмма < 12 байт: id у C не инициализирован; у нас несовпадение, ничего",
        ),
        with(
            "nbns-empty",
            COOKIE,
            false,
            Mode::Whole,
            Vec::new(),
            "пустая датаграмма",
        ),
        with(
            "nbns-header-only",
            COOKIE,
            false,
            Mode::Whole,
            dns_header(DNS_ID, FLAGS_REPLY, 0, 0, 0, 0),
            "только заголовок: ancount 0, сырой; у C dns_extract_name читает неинициализированный rr_offset[0]",
        ),
        with(
            "nbns-255-names",
            COOKIE,
            false,
            Mode::Whole,
            {
                let entries: Vec<Vec<u8>> = (0..255u32)
                    .map(|i| {
                        nb_entry(
                            format!("NAME{i}").as_bytes(),
                            u8::try_from(i % 256).expect("suffix"),
                            0,
                        )
                    })
                    .collect();
                nbns_reply(
                    FLAGS_REPLY,
                    &[],
                    &[answer_with(
                        NBSTAT,
                        CLASS_IN,
                        &nbstat_rdata(255, &entries, &MAC),
                    )],
                    &[],
                )
            },
            "255 имён: длинный баннер",
        ),
    ]
}

// ---- SNMP (B4) ----

fn ber_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![u8::try_from(n).expect("short")]
    } else if n < 0x100 {
        vec![0x81, u8::try_from(n).expect("one")]
    } else {
        let b = u16::try_from(n).expect("two").to_be_bytes();
        vec![0x82, b[0], b[1]]
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    cat(&[&[tag], &ber_len(value.len()), value])
}

/// TLV с длинной формой длины из `len_bytes` байт (`0x80 | len_bytes`).
fn tlv_long(tag: u8, value: &[u8], len_bytes: usize) -> Vec<u8> {
    let be = u64::try_from(value.len()).expect("len").to_be_bytes();
    let lol = 0x80 | u8::try_from(len_bytes).expect("len_bytes");
    cat(&[&[tag, lol], &be[8 - len_bytes..], value])
}

fn varbind(oid: &[u8], tag: u8, value: &[u8]) -> Vec<u8> {
    tlv(0x30, &cat(&[&tlv(6, oid), &tlv(tag, value)]))
}

/// SNMP: версия (содержимое INTEGER), community, тег PDU, request-id (содержимое INTEGER), error-status,
/// error-index, связки.
fn snmp_msg(
    version: &[u8],
    pdu_tag: u8,
    reqid: &[u8],
    err: u8,
    idx: u8,
    varbinds: &[Vec<u8>],
) -> Vec<u8> {
    let vbl = tlv(0x30, &varbinds.concat());
    let pdu = tlv(
        pdu_tag,
        &cat(&[&tlv(2, reqid), &tlv(2, &[err]), &tlv(2, &[idx]), &vbl]),
    );
    tlv(0x30, &cat(&[&tlv(2, version), &tlv(4, b"public"), &pdu]))
}

const REQID: [u8; 4] = COOKIE.to_be_bytes();
const GET_RESPONSE: u8 = 0xA2;
const SYSDESCR_0: [u8; 8] = [0x2B, 6, 1, 2, 1, 1, 1, 0];
const SYSNAME_0: [u8; 8] = [0x2B, 6, 1, 2, 1, 1, 5, 0];

fn get_response(varbinds: &[Vec<u8>]) -> Vec<u8> {
    snmp_msg(&[0], GET_RESPONSE, &REQID, 0, 0, varbinds)
}

/// Вектор `snmp_selftest_banner` (`src/proto-snmp.c:630-644`), request-id 0x26.
const SNMP_SELFTEST: [u8; 59] = [
    0x30, 0x39, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0xA2, 0x2C, 0x02,
    0x01, 0x26, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x21, 0x30, 0x1F, 0x06, 0x09, 0x2B, 0x06,
    0x01, 0x80, 0x02, 0x01, 0x01, 0x02, 0x00, 0x06, 0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x8F, 0x51,
    0x01, 0x01, 0x01, 0x82, 0x29, 0x5D, 0x01, 0x1B, 0x02, 0x02, 0x01,
];

fn snmp_cases() -> Vec<Case> {
    let with = |name, cookie, rawudp, mode, payload, about| Case {
        name,
        port: 161,
        cookie,
        rawudp,
        mode,
        payload,
        about,
    };
    let s = |v: &str| v.as_bytes().to_vec();
    let descr_name = get_response(&[
        varbind(&SYSDESCR_0, 4, b"Linux router 6.1.0"),
        varbind(&SYSNAME_0, 4, b"router1"),
    ]);
    let compact = get_response(&[varbind(&SYSNAME_0, 4, b"r1")]);
    let pdu_tag_at = find(&compact, &[GET_RESPONSE]);
    let value_tag_at = find(&compact, &SYSNAME_0) + SYSNAME_0.len();
    // OID 1.3.6.1.2.1.1.X.0: развёртка X.
    let oid_x_at = find(&compact, &SYSNAME_0) + 6;
    let oid_first_at = find(&compact, &SYSNAME_0);
    let names: Vec<(&[u8], &str)> = vec![
        (&[0x2B], "iso.org"),
        (&[0x2B, 6], "dod"),
        (&[0x2B, 6, 1], "inet"),
        (&[0x2B, 6, 1, 2], "mgmt"),
        (
            &[0x2B, 6, 1, 2, 1],
            "mib2 и sys: на конце OID побеждает sys",
        ),
        (&[0x2B, 6, 1, 2, 1, 2, 2], "mib2.2.2"),
        (&[0x2B, 6, 1, 2, 1, 1], "mib2.1"),
        (&[0x2B, 6, 1, 2, 1, 1, 1], "sysDescr без .0"),
        (&[0x2B, 6, 1, 2, 1, 1, 2, 0], "sysObjectID"),
        (&[0x2B, 6, 1, 2, 1, 1, 3, 0], "sysUpTime"),
        (&[0x2B, 6, 1, 2, 1, 1, 4, 0], "sysContact"),
        (&[0x2B, 6, 1, 2, 1, 1, 5, 0], "sysName"),
        (&[0x2B, 6, 1, 2, 1, 1, 6, 0], "sysLocation"),
        (&[0x2B, 6, 1, 2, 1, 1, 7, 0], "sysServices"),
        (&[0x2B, 6, 1, 2, 1, 1, 8, 0], "mib2.1.8"),
        (&[0x2B, 6, 1, 2, 1, 1, 1, 1], "sysDescr.1"),
        (
            &[0x2B, 6, 1, 2, 1, 1, 1, 0, 0x80, 5],
            "sysDescr.0.5: 0x80 в остатке это пустая цифра base-128",
        ),
        (
            &[0x2B, 6, 1, 2, 1, 1, 5, 0x81],
            "оборванное продолжение в конце",
        ),
        (&[0x2B, 6, 1, 2, 1, 1, 1, 0x80], "0x80 после листа: тупик"),
        (&[0x2B, 6, 1, 4], "priv"),
        (&[0x2B, 6, 1, 4, 1], "enterprise"),
        (&[0x2B, 6, 1, 4, 1, 0x8F, 0x51], "okidata"),
        (&[0x2B, 6, 1, 4, 1, 0x8F, 0x51, 1, 0], "okidata.1"),
        (
            &[0x2B, 6, 1, 4, 1, 0x8F],
            "enterprise с оборванным продолжением",
        ),
        (&[0x2B, 0x87, 0x6E, 0x33, 0x94, 0xEA, 0x54], "selftest"),
        (&[0x2B, 0x87, 0x6E], "iso.org.1006"),
        (
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D],
            "без имени: .42.840.113549",
        ),
        (&[0x80, 0x2B, 6], "0x80 в корне: dod"),
        (
            &[0x2B, 0x80, 0x80, 6, 1, 0x80, 4],
            "0x80 внутри шаблонов: priv",
        ),
        (&[], "пустой OID"),
        (&[0], "OID 0: ничего"),
        (&[0, 0, 0], "OID 0.0.0: .0.0"),
        (&[0x7F, 0x80], "последний 0 после продолжения"),
    ];
    let names_msg = get_response(
        &names
            .iter()
            .enumerate()
            .map(|(i, (oid, _))| varbind(oid, 4, format!("v{i}").as_bytes()))
            .collect::<Vec<_>>(),
    );
    let huge_subid: Vec<u8> = cat(&[&[0x2B, 6, 1, 4, 1], &[0xFF; 20], &[0x7F]]);
    // Тело `descr_name` после внешнего `30 LEN` (короткая форма).
    assert_eq!(usize::from(descr_name[1]), descr_name.len() - 2);
    let descr_body = descr_name[2..].to_vec();
    vec![
        with(
            "snmp-selftest",
            0x26,
            false,
            Mode::Prefixes,
            SNMP_SELFTEST.to_vec(),
            "вектор selftest C: sysObjectID:okidata.1.1.1.297.93.1.27.2.2.1 (src/proto-snmp.c:663); все обрезки",
        ),
        with(
            "snmp-selftest-wrong-cookie",
            0x27,
            false,
            Mode::Whole,
            SNMP_SELFTEST.to_vec(),
            "request-id != cookie & 0x7FFFFFFF: ничего (src/proto-snmp.c:567-569)",
        ),
        with(
            "snmp-sysdescr-sysname",
            COOKIE,
            false,
            Mode::Prefixes,
            descr_name.clone(),
            "ответ на зонд: sysDescr:...\\nsysName:... (справка B4); все обрезки",
        ),
        with(
            "snmp-sysdescr-sysname-rawudp",
            COOKIE,
            true,
            Mode::Whole,
            descr_name.clone(),
            "--rawudp: сырой один раз (status 0)",
        ),
        with(
            "snmp-probe-oids",
            COOKIE,
            false,
            Mode::Whole,
            get_response(&[
                varbind(&[0x2B, 6, 1, 0x80, 2, 1, 1, 1, 0], 4, b"descr"),
                varbind(&[0x2B, 6, 1, 0x80, 2, 1, 1, 5, 0], 4, b"name"),
            ]),
            "OID зонда с байтом 0x80 (src/templ-payloads.c:154-158): SMACK_SNMP_HACK пропускает его",
        ),
        with(
            "snmp-cookie-top-bit",
            0xDEED_1234,
            false,
            Mode::Whole,
            descr_name.clone(),
            "старший бит cookie отбрасывается маской 0x7FFFFFFF",
        ),
        with(
            "snmp-v2c",
            COOKIE,
            false,
            Mode::Whole,
            snmp_msg(
                &[1],
                GET_RESPONSE,
                &REQID,
                0,
                0,
                &[varbind(&SYSNAME_0, 4, b"r1")],
            ),
            "SNMPv2c: request-id не читается, ничего (C1.13)",
        ),
        with(
            "snmp-v2c-cookie-zero",
            0x8000_0000,
            false,
            Mode::Whole,
            snmp_msg(
                &[1],
                GET_RESPONSE,
                &REQID,
                0,
                0,
                &[varbind(&SYSNAME_0, 4, b"r1")],
            ),
            "SNMPv2c при cookie & 0x7FFFFFFF = 0: request-id 0 совпадает, пустой snmp и сырой",
        ),
        with(
            "snmp-not-ber-cookie-zero",
            0,
            false,
            Mode::Whole,
            s("hello"),
            "не BER при cookie 0: пустой snmp и сырой",
        ),
        with(
            "snmp-pdu-tag-sweep",
            COOKIE,
            false,
            Mode::Sweep(pdu_tag_at),
            compact.clone(),
            "все теги PDU: 0xA0-0xA5 разбираются (src/proto-snmp.c:334-336)",
        ),
        with(
            "snmp-value-tag-sweep",
            COOKIE,
            false,
            Mode::Sweep(value_tag_at),
            compact.clone(),
            "все теги значения: 2 число, 5 пропуск, 6 OID, прочие сырые байты (src/proto-snmp.c:271-291, 392-393)",
        ),
        with(
            "snmp-oid-byte-sweep",
            COOKIE,
            false,
            Mode::Sweep(oid_x_at),
            compact.clone(),
            "все значения байта X в 1.3.6.1.2.1.1.X.0",
        ),
        with(
            "snmp-oid-first-byte-sweep",
            COOKIE,
            false,
            Mode::Sweep(oid_first_at),
            compact.clone(),
            "все значения первого байта OID: 0x2B и 0x80 (петля SMACK_SNMP_HACK в корне)",
        ),
        with(
            "snmp-reqid-5-bytes",
            COOKIE,
            false,
            Mode::Whole,
            snmp_msg(
                &[0],
                GET_RESPONSE,
                &cat(&[&[0], &REQID]),
                0,
                0,
                &[varbind(&SYSNAME_0, 4, b"r1")],
            ),
            "request-id из 5 байт с ведущим 0",
        ),
        with(
            "snmp-reqid-9-bytes",
            COOKIE,
            false,
            Mode::Whole,
            snmp_msg(
                &[0],
                GET_RESPONSE,
                &cat(&[&[1, 2, 3, 4, 5], &REQID]),
                0,
                0,
                &[varbind(&SYSNAME_0, 4, b"r1")],
            ),
            "request-id из 9 байт: u64 переполняется, (unsigned) оставляет младшие 32 бита",
        ),
        with(
            "snmp-reqid-20-bytes",
            COOKIE,
            false,
            Mode::Whole,
            snmp_msg(
                &[0],
                GET_RESPONSE,
                &cat(&[&[0xAA; 16], &REQID]),
                0,
                0,
                &[varbind(&SYSNAME_0, 4, b"r1")],
            ),
            "request-id из 20 байт: ещё читается (src/proto-snmp.c:165)",
        ),
        with(
            "snmp-reqid-21-bytes",
            COOKIE,
            false,
            Mode::Whole,
            snmp_msg(
                &[0],
                GET_RESPONSE,
                &cat(&[&[0xAA; 17], &REQID]),
                0,
                0,
                &[varbind(&SYSNAME_0, 4, b"r1")],
            ),
            "request-id из 21 байта: ошибка 0xFFFFFFFF, ничего",
        ),
        with(
            "snmp-reqid-empty",
            COOKIE,
            false,
            Mode::Whole,
            snmp_msg(
                &[0],
                GET_RESPONSE,
                &[],
                0,
                0,
                &[varbind(&SYSNAME_0, 4, b"r1")],
            ),
            "пустой request-id = 0: несовпадение",
        ),
        with(
            "snmp-integer-values",
            COOKIE,
            false,
            Mode::Whole,
            get_response(&[
                varbind(&SYSNAME_0, 2, &[]),
                varbind(&SYSNAME_0, 2, &[7]),
                varbind(&SYSNAME_0, 2, &[0xFF, 0xFE]),
                varbind(&SYSNAME_0, 2, &[0xFF; 8]),
                varbind(&SYSNAME_0, 2, &[1, 2, 3, 4, 5, 6, 7, 8, 9]),
                varbind(&SYSNAME_0, 2, &[0x5A; 20]),
            ]),
            "INTEGER: беззнаково, %llu, больше 8 байт остаются младшие 64 бита (src/proto-snmp.c:272-280)",
        ),
        with(
            "snmp-oid-value",
            COOKIE,
            false,
            Mode::Whole,
            get_response(&[
                varbind(
                    &[0x2B, 6, 1, 2, 1, 1, 2, 0],
                    6,
                    &[0x2B, 6, 1, 4, 1, 0x8F, 0x51, 1, 2],
                ),
                varbind(&[0x2B, 6, 1, 2, 1, 1, 2, 0], 6, &[0x2A, 3]),
            ]),
            "значение OBJECT IDENTIFIER печатается как OID",
        ),
        with(
            "snmp-other-value-tags",
            COOKIE,
            false,
            Mode::Whole,
            get_response(&[
                varbind(&SYSNAME_0, 0x40, &[192, 0, 2, 1]),
                varbind(&SYSNAME_0, 0x41, &[0, 0, 1, 0]),
                varbind(&SYSNAME_0, 0x42, &[0xFF]),
                varbind(&SYSNAME_0, 0x43, &[0x01, 0x02, 0x03]),
                varbind(&SYSNAME_0, 0x44, b"op"),
                varbind(&SYSNAME_0, 0x46, &[1, 2, 3, 4, 5, 6, 7, 8]),
                varbind(&SYSNAME_0, 0x80, &[]),
                varbind(&SYSNAME_0, 4, &[]),
            ]),
            "IpAddress, Counter32, Gauge, TimeTicks, Opaque, Counter64, noSuchObject, пустая строка: сырые байты (C1.13)",
        ),
        with(
            "snmp-null-first",
            COOKIE,
            false,
            Mode::Whole,
            get_response(&[
                varbind(&SYSDESCR_0, 5, &[]),
                varbind(&SYSNAME_0, 4, b"router1"),
            ]),
            "NULL пропускается, перевода строки перед следующей связкой нет",
        ),
        with(
            "snmp-oid-names",
            COOKIE,
            false,
            Mode::Whole,
            names_msg,
            "имена MIB по самому длинному префиксу с SMACK_SNMP_HACK, хвост .N, последний .0 отброшен (src/proto-snmp.c:206-251)",
        ),
        with(
            "snmp-huge-subid",
            COOKIE,
            false,
            Mode::Whole,
            get_response(&[varbind(&huge_subid, 4, b"x")]),
            "sub-id из 21 байта base-128: u64 сдвигается с потерей старших бит, как у C",
        ),
        with(
            "snmp-long-lengths",
            COOKIE,
            false,
            Mode::Whole,
            {
                let vb = tlv_long(
                    0x30,
                    &cat(&[&tlv_long(6, &SYSNAME_0, 1), &tlv_long(4, b"r1", 2)]),
                    1,
                );
                let vbl = tlv_long(0x30, &vb, 2);
                let pdu = tlv_long(
                    GET_RESPONSE,
                    &cat(&[&tlv_long(2, &REQID, 1), &tlv(2, &[0]), &tlv(2, &[0]), &vbl]),
                    1,
                );
                tlv_long(
                    0x30,
                    &cat(&[&tlv(2, &[0]), &tlv_long(4, b"public", 4), &pdu]),
                    2,
                )
            },
            "длинная форма длин 0x81, 0x82 и 0x84 (src/proto-snmp.c:122-137)",
        ),
        with(
            "snmp-length-0x10000",
            COOKIE,
            false,
            Mode::Whole,
            cat(&[&[0x30, 0x83, 0x01, 0x00, 0x00], &descr_body]),
            "внешняя длина 0x10000 допустима и больше датаграммы: без усечения",
        ),
        with(
            "snmp-length-over-0x10000",
            COOKIE,
            false,
            Mode::Whole,
            cat(&[&[0x30, 0x83, 0x01, 0x00, 0x01], &descr_body]),
            "внешняя длина 0x10001: ошибка длины, версия читается на конце датаграммы",
        ),
        with(
            "snmp-length-indefinite",
            COOKIE,
            false,
            Mode::Whole,
            cat(&[&[0x30, 0x80], &descr_body]),
            "длина 0x80 (длина длины 0): ошибка",
        ),
        with(
            "snmp-outer-length-short",
            COOKIE,
            false,
            Mode::Whole,
            {
                let mut v = descr_name.clone();
                v[1] = u8::try_from(v.len() - 2 - 9).expect("len");
                v
            },
            "внешняя длина короче датаграммы: разбор усечён по ней (src/proto-snmp.c:318-319)",
        ),
        with(
            "snmp-varbind-not-seq",
            COOKIE,
            false,
            Mode::Whole,
            get_response(&[
                varbind(&SYSDESCR_0, 4, b"d"),
                tlv(0x31, &cat(&[&tlv(6, &SYSNAME_0), &tlv(4, b"n")])),
            ]),
            "связка не SEQUENCE: стоп, напечатанное остаётся (src/proto-snmp.c:359-361)",
        ),
        with(
            "snmp-varbind-past-end",
            COOKIE,
            false,
            Mode::Whole,
            {
                let mut v =
                    get_response(&[varbind(&SYSDESCR_0, 4, b"d"), varbind(&SYSNAME_0, 4, b"n")]);
                let at = find(&v, &cat(&[&[0x30, 0x0D, 0x06, 0x08], &SYSNAME_0]));
                v[at + 1] = 0x40;
                v
            },
            "конец связки за концом списка: return (src/proto-snmp.c:366-368)",
        ),
        with(
            "snmp-oid-tag-not-6",
            COOKIE,
            false,
            Mode::Whole,
            get_response(&[
                varbind(&SYSDESCR_0, 4, b"d"),
                tlv(0x30, &cat(&[&tlv(7, &SYSNAME_0), &tlv(4, b"n")])),
            ]),
            "в связке не OID: return",
        ),
        with(
            "snmp-value-spans-varbinds",
            COOKIE,
            false,
            Mode::Whole,
            {
                let mut v = get_response(&[
                    varbind(&SYSDESCR_0, 4, b"descr"),
                    varbind(&SYSNAME_0, 4, b"name"),
                ]);
                let at = find(&v, b"descr") - 1;
                v[at] = 9;
                v
            },
            "значение длиннее связки: varbind_end не ограничивает значение (src/proto-snmp.c:365-391)",
        ),
        with(
            "snmp-many-varbinds",
            COOKIE,
            false,
            Mode::Whole,
            get_response(
                &(0..60)
                    .map(|i| varbind(&SYSNAME_0, 4, format!("name-{i}").as_bytes()))
                    .collect::<Vec<_>>(),
            ),
            "60 связок через перевод строки",
        ),
        with(
            "snmp-error-status",
            COOKIE,
            false,
            Mode::Whole,
            snmp_msg(
                &[0],
                GET_RESPONSE,
                &REQID,
                2,
                1,
                &[varbind(&SYSDESCR_0, 5, &[]), varbind(&SYSNAME_0, 4, b"r1")],
            ),
            "error-status 2 не мешает печати",
        ),
    ]
}

// ---- Порты без парсера (B0: default_udp_parse и сырой баннер) ----

fn default_cases() -> Vec<Case> {
    let with = |name, port, rawudp, mode, payload, about| Case {
        name,
        port,
        cookie: COOKIE,
        rawudp,
        mode,
        payload,
        about,
    };
    let chargen: Vec<u8> = (0..100u8).map(|i| b'!' + i % 94).collect();
    vec![
        with(
            "default-echo",
            7,
            false,
            Mode::Whole,
            b"masscan-test 0x00000000".to_vec(),
            "эхо: первые 64 байта (def64) и сырой (src/proto-udp.c:27-50, 108-112)",
        ),
        with(
            "default-chargen",
            19,
            false,
            Mode::Prefixes,
            chargen.clone(),
            "chargen 100 байт: def64 усечён до 64, сырой целиком; все обрезки",
        ),
        with(
            "default-chargen-rawudp",
            19,
            true,
            Mode::Whole,
            chargen,
            "--rawudp: сырой один раз (status 0)",
        ),
        with(
            "default-port-0",
            0,
            false,
            Mode::Whole,
            b"zero!".to_vec(),
            "порт 0: ветка default",
        ),
        with(
            "default-port-65535",
            65535,
            false,
            Mode::Whole,
            b"abc".to_vec(),
            "порт 65535: ветка default",
        ),
        with(
            "default-empty",
            9999,
            false,
            Mode::Whole,
            Vec::new(),
            "пустая датаграмма: def64 и сырой пустые",
        ),
    ]
}

/// Все кейсы, в порядке манифеста.
pub fn cases() -> Vec<Case> {
    let mut v = dns_cases();
    v.extend(ntp_cases());
    v.extend(nbns_cases());
    v.extend(snmp_cases());
    v.extend(default_cases());
    v
}

/// Строка `cases.tsv` для `run-goldens.sh`.
pub fn tsv_line(c: &Case) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{}\t{}\t0x{:08x}\t{}\t{}\t{}",
        c.name,
        c.port,
        c.cookie,
        u8::from(c.rawudp),
        c.mode.arg(),
        c.about
    );
    s
}

#[allow(dead_code)]
fn main() -> ExitCode {
    let Some(dir) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: udp_golden_inputs DIR");
        return ExitCode::from(2);
    };
    let cases_dir = dir.join("cases");
    if let Err(e) = std::fs::create_dir_all(&cases_dir) {
        eprintln!("{}: {e}", cases_dir.display());
        return ExitCode::FAILURE;
    }
    let mut tsv = String::new();
    for c in cases() {
        let path = cases_dir.join(format!("{}.bin", c.name));
        if let Err(e) = std::fs::write(&path, &c.payload) {
            eprintln!("{}: {e}", path.display());
            return ExitCode::FAILURE;
        }
        tsv.push_str(&tsv_line(&c));
    }
    let path = dir.join("cases.tsv");
    if let Err(e) = std::fs::write(&path, tsv) {
        eprintln!("{}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
