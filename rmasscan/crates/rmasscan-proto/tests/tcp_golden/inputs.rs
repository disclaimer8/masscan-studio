//! Кейсы эталонов `tests/golden/tcp-banners` (подэтап 4b, задачи 8 и 9): поток сервера одного соединения, порт и
//! `--capture html`, вид ожидания. Потоки синтетические: имена только `*.test` и `lab`, адресов нет. Входы оракула
//! `cases/<кейс>.in.txt` пишет [`Case::input`]; задачи 9-12 добавляют свои кейсы в [`cases`].

use std::fmt::Write as _;

/// Вид ожидания кейса (поле `expect` манифеста).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// Записи (в порядке C, каждая не длиннее 65 536 байт, Р5), действия и `app_proto` равны выводу C на целом
    /// потоке.
    Records,
    /// Сравнивается только `app_proto` с выбором C: парсер этого приложения в задаче 8 ещё заглушка.
    Classification,
    /// Ожидание по правилу 4b (названо строкой); вывод C хранится как свидетельство, `app_proto` равен выбору C.
    Declared(&'static str),
}

/// Правило 4b: приложение не перенесено (SMB, справка B6), весь поток одной записью `unknown` (app 1).
pub const UNKNOWN_STREAM: &str = "unknown-stream";

/// Правило 4b: согласие сервера на STARTTLS (FTP 234, SMTP 220, POP3 `+OK`; справка B6). Первый сегмент кейса
/// кончается строкой согласия. До неё как C на этом сегменте (записи парсера и действия), hello TLS не шлётся, а каждый
/// байт после неё (следующий сегмент, если он есть) это одна запись `unknown`; `app_proto` C (9).
pub const STARTTLS_UNKNOWN: &str = "starttls-unknown";

impl Expect {
    pub fn name(self) -> &'static str {
        match self {
            Expect::Records => "records",
            Expect::Classification => "classification",
            Expect::Declared(_) => "declared-4b",
        }
    }

    pub fn declared(self) -> &'static str {
        match self {
            Expect::Declared(rule) => rule,
            _ => "-",
        }
    }
}

/// Сегмент потока: байты или повтор образца до длины.
#[derive(Clone, Debug)]
pub enum Seg {
    Bytes(Vec<u8>),
    Repeat(usize, Vec<u8>),
}

impl Seg {
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Seg::Bytes(b) => b.clone(),
            Seg::Repeat(n, unit) => unit.iter().copied().cycle().take(*n).collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Case {
    pub name: String,
    pub expect: Expect,
    pub about: &'static str,
    pub port: u16,
    pub capture_html: bool,
    pub segments: Vec<Seg>,
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

impl Case {
    /// Вход оракула (`tcp-banner-input v1`, README эталонов).
    pub fn input(&self) -> String {
        let mut s = String::from("tcp-banner-input v1\n");
        let _ = writeln!(s, "port {}", self.port);
        let _ = writeln!(
            s,
            "capture {}",
            if self.capture_html { "html" } else { "none" }
        );
        for seg in &self.segments {
            match seg {
                Seg::Bytes(b) => {
                    let _ = writeln!(s, "segment {}", hex(b));
                }
                Seg::Repeat(n, unit) => {
                    let _ = writeln!(s, "segment repeat={n}:{}", hex(unit));
                }
            }
        }
        s
    }

    pub fn segment_bytes(&self) -> Vec<Vec<u8>> {
        self.segments.iter().map(Seg::bytes).collect()
    }

    pub fn stream(&self) -> Vec<u8> {
        self.segment_bytes().concat()
    }
}

fn case(name: &str, expect: Expect, about: &'static str, port: u16, segs: &[&[u8]]) -> Case {
    Case {
        name: name.to_owned(),
        expect,
        about,
        port,
        capture_html: false,
        segments: segs.iter().map(|s| Seg::Bytes(s.to_vec())).collect(),
    }
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// Все кейсы задачи 8: классификатор (каждый шаблон `patterns[]`, регистр, лишний ведущий байт, `*` SMB с 0x7B и
/// 0xFF, совпадение во втором сегменте, SSL3 первым и затем `{"` или IAC, SMB) и потоки без совпадения, в том числе
/// 70 000 байт.
pub fn cases() -> Vec<Case> {
    use Expect::{Classification, Declared, Records};
    let unk = Declared(UNKNOWN_STREAM);
    let mut v = vec![
        // --- без совпадения: весь поток в HEUR (`src/proto-banner1.c:184`) ---
        case(
            "no-match-text",
            Records,
            "текст без шаблона: h начинает HTTP/1. и обрывается, весь поток unknown",
            9999,
            &[b"hello world\r\n"],
        ),
        case(
            "no-match-binary",
            Records,
            "двоичный поток без шаблона: 0x22 не после 0x7B, нет 0xFF",
            9999,
            &[b"\x00\x01\x02\x03\x7a\x7c\x21\x22\xfe\xfd\x80\x81\x0a\x0d\x20\x2a"],
        ),
        Case {
            name: "no-match-70000".to_owned(),
            expect: Records,
            about: "70 000 байт без шаблона: у C запись 70 000 байт, у rmasscan первые 65 536 (Р5)",
            port: 7000,
            capture_html: false,
            segments: vec![Seg::Repeat(
                70_000,
                b"lorem ipsum dolor sit amet, ".to_vec(),
            )],
        },
        case(
            "leading-space-ssh",
            Records,
            "лишний ведущий байт: пробел перед SSH-2. гасит все якорные шаблоны",
            22,
            &[b" SSH-2.0-OpenSSH_9.6\r\n"],
        ),
        case(
            "leading-crlf-http",
            Records,
            "CRLF перед HTTP/1. гасит якорь",
            80,
            &[b"\r\nHTTP/1.1 200 OK\r\n\r\n"],
        ),
        case(
            "leading-byte-ftp",
            Records,
            "x перед 220 гасит якорь",
            21,
            &[b"x220 ready\r\n"],
        ),
        // --- `*` шаблонов SMB (`smack_fixup_wildcards`, `src/smack1.c:1106-1150`): любой байт, кроме первого байта
        //     безъякорного шаблона ---
        case(
            "smb-star-7b-first",
            Records,
            "первая * SMB с 0x7B: переход в безъякорный {, SMB не совпал",
            445,
            &[b"\x00\x00\x7b\x41\xffSMBr\x00"],
        ),
        case(
            "smb-star-7b-second",
            Records,
            "вторая * SMB с 0x7B: SMB не совпал",
            445,
            &[b"\x00\x00\x41\x7b\xffSMBr\x00"],
        ),
        case(
            "smb-star-ff-first",
            Records,
            "первая * SMB с 0xFF: переход в безъякорный IAC, SMB не совпал",
            445,
            &[b"\x00\x00\xff\x41\xffSMBr\x00"],
        ),
        case(
            "smb-star-ff-second",
            Records,
            "вторая * SMB с 0xFF: SMB не совпал",
            445,
            &[b"\x00\x00\x41\xff\xffSMBr\x00"],
        ),
        case(
            "smb-star-7b-then-quote",
            Classification,
            "00 00 7b 22: * не съедает 0x7B, совпадает безъякорный Minecraft (7b 22)",
            445,
            &[b"\x00\x00\x7b\x22a\x22:1}"],
        ),
    ];

    // --- SSL3 без hello отвергнут (`src/proto-banner1.c:137-138`, справка B1.2): поток unknown ---
    for (name, first) in [
        ("ssl3-16-0300", b"\x16\x03\x00"),
        ("ssl3-16-0301", b"\x16\x03\x01"),
        ("ssl3-16-0302", b"\x16\x03\x02"),
        ("ssl3-16-0303", b"\x16\x03\x03"),
        ("ssl3-15-0300", b"\x15\x03\x00"),
        ("ssl3-15-0301", b"\x15\x03\x01"),
        ("ssl3-15-0302", b"\x15\x03\x02"),
        ("ssl3-15-0303", b"\x15\x03\x03"),
    ] {
        v.push(case(
            name,
            Records,
            "запись TLS первой: SSL3 отвергнут без hello, весь поток unknown",
            443,
            &[&cat(&[first, b"\x00\x02\x02\x28"])],
        ));
    }
    v.push(case(
        "ssl3-then-mc",
        Records,
        "SSL3 первым, затем 7b 22 во втором сегменте: у C по сегментам MC (E2.2), целиком unknown",
        443,
        &[b"\x16\x03\x01\x00\x05hello", b"{\"text\":\"lab\"}"],
    ));
    v.push(case(
        "ssl3-then-iac",
        Records,
        "SSL3 первым, затем IAC во втором сегменте: у C по сегментам Telnet (E2.2), целиком unknown",
        443,
        &[b"\x15\x03\x03\x00\x02\x02\x28", b"\xff\xfb\x01\xff\xfb\x03"],
    ));

    // --- классификация (парсеры задач 9-12) ---
    v.push(case(
        "mc-json-at-start",
        Classification,
        "7b 22 (Minecraft) в начале потока",
        9999,
        &[b"{\"text\":\"synthetic\"}"],
    ));
    v.push(case(
        "mc-status-reply",
        Classification,
        "7b 22 после длины и номера пакета (безъякорный шаблон)",
        25565,
        &[b"\x2b\x00\x29{\"description\":{\"text\":\"lab\"},\"players\":{}}"],
    ));
    v.push(case(
        "ssh1",
        Classification,
        "SSH-1. (app 2)",
        22,
        &[b"SSH-1.99-OpenSSH_3.9p1\r\n"],
    ));
    v.push(case(
        "ssh2",
        Classification,
        "SSH-2. (app 3)",
        22,
        &[b"SSH-2.0-OpenSSH_9.6\r\n"],
    ));
    v.push(case(
        "ssh2-lowercase",
        Classification,
        "ssh-2. строчными: регистр A-Z не важен",
        2222,
        &[b"ssh-2.0-dropbear\r\n"],
    ));
    v.push(case(
        "http-status",
        Classification,
        "HTTP/1.",
        80,
        &[b"HTTP/1.1 200 OK\r\nServer: lab\r\n\r\n"],
    ));
    v.push(case(
        "http-mixed-case",
        Classification,
        "hTtP/1. вперемешку",
        8080,
        &[b"hTtP/1.0 404 Not Found\r\n\r\n"],
    ));
    v.push(case(
        "ftp-220-dash-21",
        Records,
        "220- на 21: FTP",
        21,
        &[b"220-Welcome\r\n220 ready\r\n"],
    ));
    v.push(case(
        "ftp-220-space-21",
        Records,
        "220 на 21: FTP",
        21,
        &[b"220 FTP ready\r\n"],
    ));
    v.push(case(
        "smtp-220-space-25",
        Records,
        "220 на 25: SMTP (src/proto-banner1.c:147-153)",
        25,
        &[b"220 mail.example.test ESMTP\r\n"],
    ));
    v.push(case(
        "smtp-220-space-587",
        Records,
        "220 на 587: SMTP",
        587,
        &[b"220 mail.example.test ESMTP\r\n"],
    ));
    v.push(case(
        "ftp-220-space-2525",
        Records,
        "220 на 2525: FTP (E3.3)",
        2525,
        &[b"220 mail.example.test ESMTP\r\n"],
    ));
    v.push(case(
        "ftp-220-dash-25",
        Records,
        "220- на 25: FTP (E3.3)",
        25,
        &[b"220-mail.example.test ESMTP\r\n220 ok\r\n"],
    ));
    v.push(case("pop3", Records, "+OK", 110, &[b"+OK POP3 ready\r\n"]));
    v.push(case(
        "pop3-lowercase",
        Records,
        "+ok строчными",
        110,
        &[b"+ok pop3\r\n"],
    ));
    v.push(case(
        "imap4",
        Records,
        "* OK",
        143,
        &[b"* OK IMAP4rev1 ready\r\n"],
    ));
    v.push(case(
        "imap4-lowercase",
        Records,
        "* ok строчными",
        143,
        &[b"* ok imap\r\n"],
    ));
    v.push(case(
        "smtp-521",
        Records,
        "521 : SMTP на любом порту",
        25,
        &[b"521 no mail here\r\n"],
    ));
    for (name, line) in [
        ("vnc-000-000", &b"RFB 000.000\n"[..]),
        ("vnc-003-003", b"RFB 003.003\n"),
        ("vnc-003-005", b"RFB 003.005\n"),
        ("vnc-003-006", b"RFB 003.006\n"),
        ("vnc-003-007", b"RFB 003.007\n"),
        ("vnc-003-008", b"RFB 003.008\n"),
        ("vnc-003-889", b"RFB 003.889\n"),
        ("vnc-003-009", b"RFB 003.009\n"),
        ("vnc-004-000", b"RFB 004.000\n"),
        ("vnc-004-001", b"RFB 004.001\n"),
        ("vnc-004-002", b"RFB 004.002\n"),
        ("vnc-lowercase", b"rfb 003.008\n"),
    ] {
        v.push(case(
            name,
            Classification,
            "строка версии RFB (app 33, версия = extra шаблона)",
            5900,
            &[line],
        ));
    }
    v.push(case(
        "memcached-stat",
        Classification,
        "STAT pid",
        11211,
        &[b"STAT pid 1234\r\nSTAT uptime 5\r\nEND\r\n"],
    ));
    // 15 безъякорных IAC (`src/proto-banner1.c:78-92`), включая шаблон с ошибкой экранирования ff fb 25 25 78:
    // нечётные с ведущими байтами, чётные с начала.
    for (i, seq) in [
        &b"\xff\xfb\x01\xff\xf0"[..],
        b"\xff\xfb\x01\xff\xfb",
        b"\xff\xfb\x01\xff\xfc",
        b"\xff\xfb\x01\xff\xfd",
        b"\xff\xfb\x01\xff\xfe",
        b"\xff\xfb\x01\x0a\x0d",
        b"\xff\xfb\x01\x0d\x0a",
        b"\xff\xfb\x01\x0d\x0d",
        b"\xff\xfb\x01\x0a\x0a",
        b"\xff\xfb\x25\x25\x78",
        b"\xff\xfb\x26\xff\xfd",
        b"\xff\xfd\x18\xff\xfd",
        b"\xff\xfd\x20\xff\xfd",
        b"\xff\xfd\x23\xff\xfd",
        b"\xff\xfd\x27\xff\xfd",
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("telnet-iac-{:02}", i + 37);
        let stream = if i % 2 == 1 {
            cat(&[b"xx", seq, b"\x03"])
        } else {
            cat(&[seq, b"\x03"])
        };
        v.push(Case {
            name,
            expect: Classification,
            about: "безъякорная последовательность IAC (app 29)",
            port: 23,
            capture_html: false,
            segments: vec![Seg::Bytes(stream)],
        });
    }
    for (name, stream) in [
        ("telnet-anchored-esc", &b"\xff\xfb\x01\x1b[2J"[..]),
        ("telnet-anchored-input", b"\xff\xfb\x01Input: "),
        ("telnet-anchored-spaces", b"\xff\xfb\x01   x"),
        ("telnet-anchored-login-iac", b"\xff\xfb\x01login: "),
        ("telnet-login", b"login: "),
        ("telnet-password", b"password: "),
        ("telnet-login-uppercase", b"LOGIN: "),
        ("telnet-password-capital", b"Password: "),
    ] {
        v.push(case(
            name,
            Classification,
            "якорный шаблон Telnet",
            23,
            &[stream],
        ));
    }
    v.push(case(
        "rdp-beef",
        Classification,
        "12 байт ответа RDP с cookie beef",
        3389,
        &[b"\x03\x00\x00\x13\x0e\xd0\xbe\xef\x12\x34\x00\x02\x0f\x08\x00\x00\x00\x00\x00"],
    ));
    v.push(case(
        "rdp-zero",
        Classification,
        "12 байт ответа RDP с нулевым cookie",
        3389,
        &[b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f\x08\x00\x08\x00\x00\x00"],
    ));
    v.push(case(
        "http-split-after-2",
        Classification,
        "HTTP/1. разрезан после HT: совпадение во втором сегменте (E2.1, у C по сегментам лишняя запись unknown)",
        80,
        &[b"HT", b"TP/1.0 200 OK\r\n\r\n"],
    ));
    v.push(case(
        "telnet-split-in-pattern",
        Classification,
        "безъякорный IAC через границу сегментов (состояние smack между сегментами)",
        23,
        &[b"xx\xff\xfb", b"\x01\xff\xfd\x03"],
    ));

    // --- SMB (справка B6): в 4b весь поток unknown, app_proto 10 как у C ---
    v.push(case(
        "smb1-negotiate",
        unk,
        "00 00 * * ff SMB: ответ SMB1 в сессии NetBIOS",
        445,
        &[b"\x00\x00\x00\x27\xffSMBr\x00\x00\x00\x00\x98\x01\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00"],
    ));
    v.push(case(
        "smb2-negotiate",
        unk,
        "00 00 * * fe SMB: ответ SMB2",
        445,
        &[b"\x00\x00\x00\x48\xfeSMB\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"],
    ));
    v.push(case(
        "smb-star-literal",
        unk,
        "00 00 * * ff SMB с байтами 2a 2a",
        445,
        &[b"\x00\x00\x2a\x2a\xffSMBr\x00\x00\x00\x00"],
    ));
    v.push(case(
        "smb-star-letters",
        unk,
        "00 00 A B fe SMB: * любые байты",
        445,
        &[b"\x00\x00AB\xfeSMB\x40\x00"],
    ));
    v.push(case(
        "smb-82",
        unk,
        "82 00 00 00: положительный ответ сессии NetBIOS",
        139,
        &[b"\x82\x00\x00\x00"],
    ));
    for (name, last) in [
        ("smb-83-80", 0x80u8),
        ("smb-83-81", 0x81),
        ("smb-83-82", 0x82),
        ("smb-83-83", 0x83),
        ("smb-83-8f", 0x8f),
    ] {
        v.push(case(
            name,
            unk,
            "83 00 00 01 и код отказа сессии NetBIOS",
            139,
            &[&[0x83, 0x00, 0x00, 0x01, last]],
        ));
    }
    v.push(case(
        "smb-split",
        unk,
        "SMB1, разрезан после 00 00: совпадение во втором сегменте",
        445,
        &[b"\x00\x00", b"\x00\x27\xffSMBr\x00\x00\x00\x00"],
    ));
    v.extend(text_cases());
    v
}

/// Кейсы задачи 9: FTP, SMTP, POP3 и IMAP4 (справка D2-D5, B6, E3.3, E3.4; `src/proto-ftp.c`, `src/proto-smtp.c`,
/// `src/proto-pop3.c`, `src/proto-imap4.c`). Согласие на STARTTLS это правило 4b [`STARTTLS_UNKNOWN`]: у кейса с
/// хвостом второй сегмент начинается сразу за строкой согласия.
fn text_cases() -> Vec<Case> {
    use Expect::{Declared, Records};
    let tls = Declared(STARTTLS_UNKNOWN);
    let mut v = Vec::new();
    // --- FTP: строки приветствия, ответ на AUTH TLS (`src/proto-ftp.c:29-121`) ---
    for (name, about, port, stream) in [
        (
            "ftp-auth-530",
            "приветствие одной строкой, AUTH TLS, ответ 530 без последнего перевода строки, закрытие",
            21u16,
            &b"220 lab FTP server ready\r\n530 Please login with USER and PASS\r\n"[..],
        ),
        (
            "ftp-multiline-greeting-500",
            "три строки приветствия с кодом, AUTH TLS после последней, ответ 500",
            21,
            b"220-Welcome to ftp.example.test\r\n220-Second line\r\n220 Ready\r\n500 AUTH not understood\r\n",
        ),
        (
            "ftp-line-without-code",
            "строка продолжения без кода: не цифра, закрытие, AUTH TLS не шлётся",
            21,
            b"220-Welcome\r\n  free-form continuation\r\n220 ok\r\n",
        ),
        (
            "ftp-tab-in-greeting",
            "TAB в тексте приветствия: не isprint, закрытие без записи байта",
            21,
            b"220 lab\tFTP ready\r\n",
        ),
        (
            "ftp-nonprint-in-greeting",
            "байт 0xE9 в тексте: не isprint в локали C, закрытие",
            21,
            b"220 lab caf\xe9 ready\r\n",
        ),
        (
            "ftp-nul-in-greeting",
            "NUL в тексте приветствия: закрытие",
            21,
            b"220 lab\x00ready\r\n",
        ),
        (
            "ftp-bad-separator",
            "вторая строка 220x: разделитель не пробел и не минус, закрытие",
            21,
            b"220-first\r\n220xsecond\r\n",
        ),
        (
            "ftp-short-code",
            "вторая строка с кодом из двух цифр: пробел вместо третьей цифры, закрытие",
            21,
            b"220-first\r\n22 second\r\n",
        ),
        (
            "ftp-cr-inside-text",
            "CR внутри текста строк пропускается, в записи его нет",
            21,
            b"220 a\rb\r\r\n530 c\rd\r\n",
        ),
        (
            "ftp-bare-lf",
            "строки с одним LF",
            21,
            b"220 lab\n530 no\n",
        ),
        (
            "ftp-auth-reply-multiline",
            "ответ 530- из двух строк: читается только первая, на её LF закрытие",
            21,
            b"220 ok\r\n530-first line\r\n530 second line\r\n",
        ),
        (
            "ftp-auth-reply-tab",
            "TAB в ответе на AUTH TLS: закрытие",
            21,
            b"220 ok\r\n530 a\tb\r\n",
        ),
        (
            "ftp-auth-reply-without-newline",
            "ответ на AUTH TLS без перевода строки: записан, закрытия нет",
            21,
            b"220 ok\r\n530 not logged in",
        ),
        (
            "ftp-auth-234-without-newline",
            "234 без перевода строки: передачи STARTTLS нет, app_proto 5",
            21,
            b"220 ok\r\n234 AUTH TLS ok",
        ),
        (
            "ftp-auth-reply-not-a-code",
            "ответ на AUTH TLS без кода: закрытие, байт не записан",
            21,
            b"220 ok\r\nhello\r\n",
        ),
        (
            "ftp-auth-code-four-digits",
            "ответ 2345: четвёртая цифра на месте разделителя, закрытие, записано 234",
            21,
            b"220 ok\r\n2345 x\r\n",
        ),
        (
            "ftp-cr-before-code",
            "пустая строка CRLF между строками приветствия: CR на месте цифры, закрытие",
            21,
            b"220-a\r\n\r\n220 b\r\n",
        ),
        (
            "ftp-code-234-in-greeting",
            "строка 234 в приветствии это последняя строка приветствия, не согласие: AUTH TLS, затем 530",
            21,
            b"220-x\r\n234 not a reply\r\n530 no\r\n",
        ),
        (
            "ftp-220-dash-25-auth",
            "220- на 25 это FTP (E3.3): AUTH TLS почтовому серверу, ответ 502",
            25,
            b"220-mail.example.test ESMTP\r\n220 ok\r\n502 5.5.2 Error: command not recognized\r\n",
        ),
        (
            "ftp-220-space-2525-auth",
            "220 на 2525 это FTP (E3.3): AUTH TLS, ответ 502",
            2525,
            b"220 mail.example.test ESMTP\r\n502 5.5.2 Error: command not recognized\r\n",
        ),
    ] {
        v.push(case(name, Records, about, port, &[stream]));
    }
    v.push(case(
        "ftp-split-crlf-and-code",
        Records,
        "заданные сегменты режут CRLF и код ответа",
        21,
        &[b"220-a\r", b"\n220 b\r\n5", b"30 no\r\n"],
    ));
    v.push(Case {
        name: "ftp-greeting-70000".to_owned(),
        expect: Records,
        about: "строка приветствия 70 004 байта с LF: у C запись 70 011 байт, у rmasscan первые 65 536 (Р5), AUTH TLS и закрытие как у C",
        port: 21,
        capture_html: false,
        segments: vec![
            Seg::Bytes(b"220 ".to_vec()),
            Seg::Repeat(70_000, b"lab ".to_vec()),
            Seg::Bytes(b"\n530 no\n".to_vec()),
        ],
    });

    // --- SMTP: приветствие, EHLO, STARTTLS при любом ответе на EHLO (`src/proto-smtp.c:50-166`) ---
    for (name, about, port, stream) in [
        (
            "smtp-ehlo-starttls-454",
            "EHLO со STARTTLS в списке, STARTTLS, ответ 454: закрытие",
            25u16,
            &b"220 mail.example.test ESMTP\r\n250-mail.example.test\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n454 4.7.0 TLS not available due to temporary reason\r\n"[..],
        ),
        (
            "smtp-ehlo-without-starttls",
            "EHLO без STARTTLS в списке: STARTTLS шлётся всё равно, ответ 502",
            25,
            b"220 mail.example.test ESMTP\r\n250-mail.example.test\r\n250 8BITMIME\r\n502 5.5.1 STARTTLS not supported\r\n",
        ),
        (
            "smtp-ehlo-rejected-587",
            "на 587 EHLO отвергнут кодом 500: STARTTLS шлётся всё равно, ответ 503",
            587,
            b"220 mail.example.test ESMTP\r\n500 5.5.1 command unrecognized\r\n503 5.5.1 bad sequence\r\n",
        ),
        (
            "smtp-521-ehlo-reply",
            "521 на любом порту это SMTP: EHLO, ответ 221, STARTTLS",
            2525,
            b"521 no mail here\r\n221 bye\r\n",
        ),
        (
            "smtp-tab-in-ehlo",
            "TAB в строке ответа на EHLO: закрытие",
            25,
            b"220 x\r\n250-mail\texample\r\n",
        ),
        (
            "smtp-nonprint-in-starttls-reply",
            "байт 0x7F в ответе на STARTTLS: закрытие",
            25,
            b"220 x\r\n250 ok\r\n454 \x7f\r\n",
        ),
        (
            "smtp-starttls-reply-without-newline",
            "ответ на STARTTLS без перевода строки: записан, закрытия нет",
            25,
            b"220 x\r\n250 ok\r\n454 later",
        ),
        (
            "smtp-ehlo-line-without-code",
            "строка без кода в ответе на EHLO: закрытие, STARTTLS не шлётся",
            25,
            b"220 x\r\n250-ok\r\n  continued\r\n",
        ),
        (
            "smtp-starttls-reply-multiline",
            "ответ 454- из двух строк: читается первая, закрытие на её LF",
            25,
            b"220 x\r\n250 ok\r\n454-first\r\n454 second\r\n",
        ),
        (
            "smtp-ehlo-bad-separator",
            "ответ на EHLO 250+: разделитель не пробел и не минус, закрытие",
            25,
            b"220 x\r\n250+ok\r\n",
        ),
        (
            "smtp-starttls-reply-221",
            "221 на STARTTLS: передача только на 220, закрытие",
            25,
            b"220 x\r\n250 ok\r\n221 2.0.0 bye\r\n",
        ),
    ] {
        v.push(case(name, Records, about, port, &[stream]));
    }

    // --- POP3: CAPA, STLS (`src/proto-pop3.c:35-150`) ---
    for (name, about, stream) in [
        (
            "pop3-capa-err",
            "-ERR на CAPA: строка записана, закрытие, STLS не шлётся",
            &b"+OK POP3 server ready\r\n-ERR unknown command\r\n"[..],
        ),
        (
            "pop3-capa-stls-err",
            "список CAPA со STLS до точки, STLS, ответ -ERR: закрытие",
            b"+OK lab POP3 ready\r\n+OK Capability list follows\r\nTOP\r\nUSER\r\nSTLS\r\n.\r\n-ERR command not permitted\r\n",
        ),
        (
            "pop3-capa-without-stls",
            "список CAPA без STLS: STLS шлётся всё равно",
            b"+OK ready\r\n+OK\r\nUSER\r\nUIDL\r\n.\r\n-ERR unknown command\r\n",
        ),
        (
            "pop3-capa-bad-reply",
            "ответ на CAPA без + и -: байт записан, закрытие",
            b"+OK ready\r\nhello\r\n",
        ),
        (
            "pop3-capa-plus-no",
            "ответ +NO на CAPA: N не O, закрытие",
            b"+OK ready\r\n+NO\r\n",
        ),
        (
            "pop3-dot-lines",
            "строки с точкой в начале и пустые строки в списке CAPA, конец только на строке из точки",
            b"+OK ready\r\n+OK\r\n.hidden\r\n\r\n\r\nX\r\n.\r\n-ERR no\r\n",
        ),
        (
            "pop3-nonprint-kept",
            "TAB, 0x01, 0x80 и 0xFF в приветствии записаны: проверки isprint у POP3 нет",
            b"+OK lab\t\x01\x80\xff ready\r\n-ERR\r\n",
        ),
        (
            "pop3-greeting-without-newline",
            "приветствие без перевода строки: CAPA не шлётся",
            b"+OK ready",
        ),
        (
            "pop3-bare-lf",
            "строки с одним LF до ответа -ERR на STLS",
            b"+OK ready\n+OK\nTOP\n.\n-ERR no\n",
        ),
        (
            "pop3-stls-reply-bad",
            "ответ +ON на STLS: N не K, закрытие",
            b"+OK x\r\n+OK\r\n.\r\n+ON\r\n",
        ),
        (
            "pop3-empty-line-before-dot",
            "пустая строка перед строкой из точки: начало строки остаётся, точка кончает список CAPA",
            b"+OK ready\r\n+OK\r\nA\r\n\r\n.\r\n-ERR no\r\n",
        ),
    ] {
        v.push(case(name, Records, about, 110, &[stream]));
    }

    // --- IMAP4: всегда `* OK` и закрытие (`src/proto-imap4.c:49-66`, E3.4); без шаблона `* OK ` поток unknown ---
    for (name, about, segs) in [
        (
            "imap4-capability-banner",
            "приветствие с CAPABILITY и STARTTLS: запись * OK, два закрытия",
            vec![&b"* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] lab ready\r\n"[..]],
        ),
        (
            "imap4-starttls-dialogue",
            "полный диалог STARTTLS: CAPABILITY не шлётся, запись * OK, два закрытия",
            vec![&b"* OK ready\r\n* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK done\r\n* OK go\r\na002 OK Begin TLS\r\n"[..]],
        ),
        (
            "imap4-two-spaces",
            "два пробела после звезды: шаблона * OK нет, поток unknown",
            vec![&b"*  OK ready\r\n"[..]],
        ),
        (
            "imap4-bye",
            "* BYE: шаблона нет, поток unknown",
            vec![&b"* BYE server shutting down\r\n"[..]],
        ),
        (
            "imap4-ok-without-space",
            "* OK и сразу CRLF: шаблону нужен пробел, поток unknown",
            vec![&b"* OK\r\n"[..]],
        ),
        (
            "imap4-split-after-star",
            "звезда отдельным сегментом: совпадение во втором сегменте, повтор HEUR",
            vec![&b"*"[..], b" OK ready\r\n"],
        ),
    ] {
        v.push(case(name, Records, about, 143, &segs));
    }

    // --- согласие на STARTTLS (справка B6): дальше unknown, hello TLS не шлётся ---
    v.push(case(
        "ftp-auth-234",
        tls,
        "234 на AUTH TLS: передача TLS",
        21,
        &[b"220 lab FTP server ready\r\n234 AUTH TLS successful\r\n"],
    ));
    v.push(case(
        "ftp-auth-234-dash-25-tail",
        tls,
        "220- на 25 это FTP, 234- передаёт на первом LF; хвост с цифр у C целиком снова приветствие FTP со вторым AUTH TLS, по сегментам TLS",
        25,
        &[
            b"220-mail.example.test\r\n220 ok\r\n234-go ahead\r\n",
            b"234 TLS next\r\n",
        ],
    ));
    v.push(case(
        "smtp-starttls-220",
        tls,
        "EHLO со STARTTLS, 220 на STARTTLS: передача TLS",
        25,
        &[b"220 mail.example.test ESMTP\r\n250-mail.example.test\r\n250-PIPELINING\r\n250 STARTTLS\r\n220 2.0.0 Ready to start TLS\r\n"],
    ));
    v.push(case(
        "smtp-starttls-220-587",
        tls,
        "на 587 EHLO без STARTTLS в списке, 220 на STARTTLS: передача TLS",
        587,
        &[b"220 mail.example.test ESMTP\r\n250 mail.example.test\r\n220 go ahead\r\n"],
    ));
    v.push(case(
        "smtp-starttls-220-tail",
        tls,
        "220- на STARTTLS передаёт на первом LF; хвост у C целиком снова приветствие SMTP со вторым EHLO, по сегментам TLS",
        25,
        &[b"220 x ESMTP\r\n250 ok\r\n220-go\r\n", b"220 Ready\r\nextra\r\n"],
    ));
    v.push(case(
        "pop3-stls-ok",
        tls,
        "список CAPA со STLS, +OK на STLS: передача TLS, строка +OK записана с LF",
        110,
        &[b"+OK lab POP3 ready\r\n+OK Capability list follows\r\nUSER\r\nSTLS\r\n.\r\n+OK Begin TLS negotiation\r\n"],
    ));
    v.push(case(
        "pop3-stls-ok-tail",
        tls,
        "+OK на STLS; хвост +OK у C целиком снова приветствие POP3 со вторым CAPA, по сегментам TLS",
        110,
        &[b"+OK ready\r\n+OK\r\n.\r\n+OK go\r\n", b"+OK again\r\n"],
    ));
    v
}
