//! Кейсы эталонов `tests/golden/tcp-banners` (подэтап 4b, задача 8): поток сервера одного соединения, порт и
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
        Classification,
        "220- на 21: FTP",
        21,
        &[b"220-Welcome\r\n220 ready\r\n"],
    ));
    v.push(case(
        "ftp-220-space-21",
        Classification,
        "220 на 21: FTP",
        21,
        &[b"220 FTP ready\r\n"],
    ));
    v.push(case(
        "smtp-220-space-25",
        Classification,
        "220 на 25: SMTP (src/proto-banner1.c:147-153)",
        25,
        &[b"220 mail.example.test ESMTP\r\n"],
    ));
    v.push(case(
        "smtp-220-space-587",
        Classification,
        "220 на 587: SMTP",
        587,
        &[b"220 mail.example.test ESMTP\r\n"],
    ));
    v.push(case(
        "ftp-220-space-2525",
        Classification,
        "220 на 2525: FTP (E3.3)",
        2525,
        &[b"220 mail.example.test ESMTP\r\n"],
    ));
    v.push(case(
        "ftp-220-dash-25",
        Classification,
        "220- на 25: FTP (E3.3)",
        25,
        &[b"220-mail.example.test ESMTP\r\n220 ok\r\n"],
    ));
    v.push(case(
        "pop3",
        Classification,
        "+OK",
        110,
        &[b"+OK POP3 ready\r\n"],
    ));
    v.push(case(
        "pop3-lowercase",
        Classification,
        "+ok строчными",
        110,
        &[b"+ok pop3\r\n"],
    ));
    v.push(case(
        "imap4",
        Classification,
        "* OK",
        143,
        &[b"* OK IMAP4rev1 ready\r\n"],
    ));
    v.push(case(
        "imap4-lowercase",
        Classification,
        "* ok строчными",
        143,
        &[b"* ok imap\r\n"],
    ));
    v.push(case(
        "smtp-521",
        Classification,
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
    v
}
