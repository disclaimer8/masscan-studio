//! Парсер TLS-записей: ServerHello, сертификаты с X.509, alert, heartbeat и проверки heartbleed, ticketbleed,
//! poodle (справка 4c §B по `src/proto-ssl.c`). Возобновляемый автомат без пересборки фрагментов: состояние
//! переживает границы сегментов, а под-парсеры получают куски не длиннее остатка записи, как у C.
//!
//! Сброс под-парсера рукопожатий в начале содержимого каждой записи (§B1) воспроизведён безусловно: у C
//! результат на рукопожатии, разрезанном на две записи, зависит от нарезки на вызовы, и эталон Р13 — целый
//! поток, где сброс срабатывает.

use crate::app::app_id;

use super::session::{ParseCx, Parser};
use super::x509::X509;

/// Флаги `Banner1` для TLS, как их копирует `tcpcon_set_banner_flags` и ставят режимы
/// (`src/proto-banner1.h:31-38`, справка §E1-§E2). По умолчанию включён только захват сертификатов
/// (`src/main.c:1610`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TlsFlags {
    pub capture_cert: bool,
    pub capture_heartbleed: bool,
    pub capture_ticketbleed: bool,
    pub heartbleed: bool,
    pub ticketbleed: bool,
    pub poodle_sslv3: bool,
}

impl Default for TlsFlags {
    fn default() -> Self {
        TlsFlags {
            capture_cert: true,
            capture_heartbleed: false,
            capture_ticketbleed: false,
            heartbleed: false,
            ticketbleed: false,
            poodle_sslv3: false,
        }
    }
}

/// Зонд heartbleed: alert и heartbeat-запрос одной отправкой (`src/proto-ssl.c:584-587`).
const HEARTBLEED_PROBE: &[u8] = b"\x15\x03\x02\x00\x02\x01\x80\x18\x03\x02\x00\x03\x01\x40\x00";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum RecStep {
    #[default]
    Start,
    VersionMajor,
    VersionMinor,
    Len0,
    Len1,
    Contents,
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum HsStep {
    #[default]
    Start,
    Len0,
    Len1,
    Len2,
    Contents,
    Unknown,
}

/// Состояние ServerHello (`SSL_SERVER_HELLO`): только наблюдаемое; метка времени C не хранится (не выводится).
#[derive(Clone, Debug, Default)]
struct Hello {
    state: u8,
    remaining: u32,
    version_major: u8,
    version_minor: u8,
    cipher: u16,
    ext_tag: u16,
    ext_remaining: u32,
}

/// Состояние списка сертификатов (`SSL_SERVER_CERT`).
#[derive(Debug, Default)]
struct Certs {
    state: u8,
    remaining: u32,
    cert_remaining: u32,
    count: u8,
    x509: X509,
    /// Тело рукопожатия Certificate в пределах текущей TLS-записи: захват и имена обрабатываются на границе
    /// записи, как у C на целом потоке. Без этого порядок записей `ssl`/`X509` зависел бы от нарезки на
    /// сегменты (у C зависит от нарезки на вызовы; эталон Р13 — целый поток, справка §F E2.10). Не больше
    /// одной записи: поле длины u16.
    record_buf: Vec<u8>,
}

/// Парсер TLS одного соединения (`ssl_parse_record` и под-парсеры).
#[derive(Debug, Default)]
pub(crate) struct Tls {
    step: RecStep,
    rec_type: u8,
    rec_remaining: u32,
    hs_step: HsStep,
    hs_type: u8,
    hs_remaining: u32,
    hello: Hello,
    certs: Certs,
    alert_level: u8,
}

impl Parser for Tls {
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        self.record(cx, px);
    }
}

impl Tls {
    /// `ssl_parse_record` (`src/proto-ssl.c:892-1053`).
    fn record(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        let mut i = 0usize;
        while i < px.len() {
            let b = px[i];
            i += 1;
            match self.step {
                RecStep::Start => {
                    if b & 0x80 != 0 {
                        self.step = RecStep::Unknown;
                    } else {
                        if self.rec_type != b {
                            self.rec_type = b;
                            self.hs_step = HsStep::Start;
                        }
                        self.step = RecStep::VersionMajor;
                    }
                }
                RecStep::VersionMajor => {
                    self.step = if b == 3 {
                        RecStep::VersionMinor
                    } else {
                        RecStep::Unknown
                    };
                }
                RecStep::VersionMinor => self.step = RecStep::Len0,
                RecStep::Len0 => {
                    self.rec_remaining = u32::from(b) << 8;
                    self.step = RecStep::Len1;
                }
                RecStep::Len1 => {
                    self.rec_remaining |= u32::from(b);
                    // Сброс под-парсера на входе в содержимое записи (§B1).
                    self.hs_step = HsStep::Start;
                    self.step = RecStep::Contents;
                }
                RecStep::Contents => {
                    let avail = px.len() - i + 1;
                    let len = avail.min(self.rec_remaining as usize);
                    let chunk = &px[i - 1..i - 1 + len];
                    match self.rec_type {
                        21 => self.alert(cx, chunk),
                        22 => self.handshake(cx, chunk),
                        24 => self.heartbeat(cx, chunk),
                        _ => {}
                    }
                    self.rec_remaining -= len as u32;
                    i = i.wrapping_add(len).wrapping_sub(1);
                    if self.rec_remaining == 0 {
                        self.cert_record_end(cx);
                        self.step = RecStep::Start;
                    }
                }
                RecStep::Unknown => return,
            }
        }
    }

    /// `parse_handshake` (`:522-652`): тип и трёхбайтная длина; разбираются только ServerHello (2) и
    /// Certificate (11), остальное пропускается по длине.
    fn handshake(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        let mut i = 0usize;
        while i < px.len() {
            let b = px[i];
            i += 1;
            match self.hs_step {
                HsStep::Start => {
                    if b & 0x80 != 0 {
                        self.hs_step = HsStep::Unknown;
                    } else {
                        self.hs_type = b;
                        self.hello.state = 0;
                        self.certs.state = 0;
                        self.hs_step = HsStep::Len0;
                    }
                }
                HsStep::Len0 => {
                    self.hs_remaining = u32::from(b);
                    self.hs_step = HsStep::Len1;
                }
                HsStep::Len1 => {
                    self.hs_remaining = (self.hs_remaining << 8) | u32::from(b);
                    self.hs_step = HsStep::Len2;
                }
                HsStep::Len2 => {
                    self.hs_remaining = (self.hs_remaining << 8) | u32::from(b);
                    if self.hs_type == 2 && cx.tls_flags.heartbleed {
                        cx.send(HEARTBLEED_PROBE);
                    }
                    self.hs_step = HsStep::Contents;
                }
                HsStep::Contents => {
                    let avail = px.len() - i + 1;
                    let len = avail.min(self.hs_remaining as usize);
                    let chunk = &px[i - 1..i - 1 + len];
                    match self.hs_type {
                        2 => self.server_hello(cx, chunk),
                        11 => self.certs.record_buf.extend_from_slice(chunk),
                        _ => {}
                    }
                    self.hs_remaining -= len as u32;
                    i = i.wrapping_add(len).wrapping_sub(1);
                    if self.hs_remaining == 0 {
                        self.hs_step = HsStep::Start;
                    }
                }
                HsStep::Unknown => return,
            }
        }
    }

    /// `parse_server_hello` (`:127-339`): версия и шифр в `ssl`, heartbeat-расширение и эвристики режимов в
    /// `vuln`. Порядок эмиссии — §B3 справки.
    fn server_hello(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        // Состояния C по порядку enum.
        const VERSION_MAJOR: u8 = 0;
        const VERSION_MINOR: u8 = 1;
        const TIME0: u8 = 2;
        const RANDOM: u8 = 6;
        const SESSION_LENGTH: u8 = 7;
        const SESSION_ID: u8 = 8;
        const CIPHER0: u8 = 9;
        const CIPHER1: u8 = 10;
        const COMPRESSION: u8 = 11;
        const LENGTH0: u8 = 12;
        const LENGTH1: u8 = 13;
        const EXT_TAG0: u8 = 14;
        const EXT_TAG1: u8 = 15;
        const EXT_LEN0: u8 = 16;
        const EXT_LEN1: u8 = 17;
        const EXT_DATA: u8 = 18;
        const EXT_DATA_HEARTBEAT: u8 = 19;
        const UNKNOWN: u8 = 20;

        let flags = cx.tls_flags;
        let mut i = 0usize;
        while i < px.len() {
            let b = px[i];
            i += 1;
            let h = &mut self.hello;
            match h.state {
                VERSION_MAJOR => {
                    h.version_major = b;
                    h.state = VERSION_MINOR;
                }
                VERSION_MINOR => {
                    h.version_minor = b;
                    banner_version(cx, h.version_major, h.version_minor);
                    if flags.poodle_sslv3 {
                        cx.append(app_id::VULN, b" POODLE ");
                    }
                    if h.version_major > 3 || h.version_minor > 4 {
                        h.state = UNKNOWN;
                    } else {
                        h.state = TIME0;
                    }
                }
                TIME0..=5 => {
                    if h.state == 5 {
                        h.remaining = 28;
                    }
                    h.state += 1;
                }
                RANDOM | SESSION_ID => {
                    let avail = px.len() - i + 1;
                    let len = avail.min(h.remaining as usize);
                    h.remaining -= len as u32;
                    i = i.wrapping_add(len).wrapping_sub(1);
                    if h.remaining == 0 {
                        if h.state == SESSION_ID {
                            h.cipher = 0;
                        }
                        h.state += 1;
                    }
                }
                SESSION_LENGTH => {
                    h.remaining = u32::from(b);
                    if flags.ticketbleed && h.remaining > 16 {
                        cx.append(app_id::VULN, b"SSL[ticketbleed] ");
                    }
                    h.state = SESSION_ID;
                }
                CIPHER0 => {
                    h.cipher = u16::from(b) << 8;
                    h.state = CIPHER1;
                }
                CIPHER1 => {
                    h.cipher |= u16::from(b);
                    let mut buf = [0u8; 16];
                    let text = fmt_cipher(&mut buf, h.cipher);
                    cx.append(app_id::SSL3, text);
                    h.state = COMPRESSION;
                }
                COMPRESSION => h.state = LENGTH0,
                LENGTH0 => {
                    h.remaining = u32::from(b);
                    h.state = LENGTH1;
                }
                LENGTH1 => {
                    h.remaining = (h.remaining << 8) | u32::from(b);
                    h.state = EXT_TAG0;
                }
                EXT_TAG0 => {
                    if h.remaining < 4 {
                        h.state = UNKNOWN;
                    } else {
                        h.ext_tag = u16::from(b) << 8;
                        h.remaining -= 1;
                        h.state = EXT_TAG1;
                    }
                }
                EXT_TAG1 => {
                    h.ext_tag |= u16::from(b);
                    h.remaining = h.remaining.saturating_sub(1);
                    h.state = EXT_LEN0;
                }
                EXT_LEN0 => {
                    h.ext_remaining = u32::from(b) << 8;
                    h.remaining = h.remaining.saturating_sub(1);
                    h.state = EXT_LEN1;
                }
                EXT_LEN1 => {
                    h.ext_remaining |= u32::from(b);
                    h.remaining = h.remaining.saturating_sub(1);
                    h.state = if h.ext_tag == 0x000f {
                        EXT_DATA_HEARTBEAT
                    } else {
                        EXT_DATA
                    };
                }
                EXT_DATA => {
                    if h.ext_remaining == 0 {
                        h.state = EXT_TAG0;
                        i -= 1;
                    } else if h.remaining == 0 {
                        h.state = UNKNOWN;
                    } else {
                        h.remaining -= 1;
                        h.ext_remaining -= 1;
                    }
                }
                EXT_DATA_HEARTBEAT => {
                    if h.ext_remaining == 0 {
                        h.state = EXT_TAG0;
                        i -= 1;
                    } else if h.remaining == 0 {
                        h.state = UNKNOWN;
                    } else {
                        h.remaining -= 1;
                        h.ext_remaining -= 1;
                        if b != 0 {
                            cx.append(app_id::VULN, b"SSL[heartbeat] ");
                        }
                        h.state = EXT_DATA;
                    }
                }
                _ => return,
            }
        }
    }

    /// Граница TLS-записи: накопленное тело Certificate разбирается одним куском (см. `record_buf`).
    fn cert_record_end(&mut self, cx: &mut ParseCx<'_>) {
        if self.certs.record_buf.is_empty() {
            return;
        }
        let buf = std::mem::take(&mut self.certs.record_buf);
        self.server_cert(cx, &buf);
        self.certs.record_buf = buf;
        self.certs.record_buf.clear();
    }

    /// `parse_server_cert` (`:370-495`): трёхбайтные длины; первый сертификат в `X509`, остальные в
    /// `X509CA`; захват — потоковый base64 с финализацией и `banout_end` на каждом сертификате.
    fn server_cert(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        const LEN0: u8 = 0;
        const LEN1: u8 = 1;
        const LEN2: u8 = 2;
        const CLEN0: u8 = 3;
        const CERT: u8 = 6;
        const CACERT: u8 = 10;
        const UNKNOWN: u8 = 11;

        let mut i = 0usize;
        while i < px.len() {
            let b = px[i];
            i += 1;
            let c = &mut self.certs;
            match c.state {
                LEN0 => {
                    c.remaining = u32::from(b);
                    c.state = LEN1;
                }
                LEN1 => {
                    c.remaining = c.remaining * 256 + u32::from(b);
                    c.state = LEN2;
                }
                LEN2 => {
                    c.remaining = c.remaining * 256 + u32::from(b);
                    c.state = CLEN0;
                }
                3 | 7 => {
                    // CLEN0 / CALEN0
                    if c.remaining < 3 {
                        c.state = UNKNOWN;
                    } else {
                        c.cert_remaining = u32::from(b);
                        c.remaining -= 1;
                        c.state += 1;
                    }
                }
                4 | 8 => {
                    c.cert_remaining = c.cert_remaining * 256 + u32::from(b);
                    c.remaining -= 1;
                    c.state += 1;
                }
                5 | 9 => {
                    c.cert_remaining = c.cert_remaining * 256 + u32::from(b);
                    c.remaining -= 1;
                    if cx.tls_flags.capture_cert {
                        cx.init_base64();
                    }
                    c.count = c.count.wrapping_add(1);
                    let len = c.cert_remaining as usize;
                    c.x509.init(len, u32::from(c.count));
                    c.state += 1;
                }
                CERT | CACERT => {
                    let proto = if c.state == CERT {
                        app_id::X509_CERT
                    } else {
                        app_id::X509_CACERT
                    };
                    let avail = px.len() - i + 1;
                    let len = avail
                        .min(c.remaining as usize)
                        .min(c.cert_remaining as usize);
                    let start = i - 1;
                    // Заём `c` отпущен выше по скоупу arm: захват и X.509 делят banout через cx.
                    if cx.tls_flags.capture_cert {
                        cx.append_base64(proto, &px[start..start + len]);
                    }
                    self.certs.x509.feed(cx, &px[start..start + len]);
                    let c = &mut self.certs;
                    c.remaining -= len as u32;
                    c.cert_remaining -= len as u32;
                    // len == 0 (пустой сертификат или исчерпанный список): тот же байт читается заново в
                    // следующем состоянии, как `i += len-1` у C.
                    i = i.wrapping_add(len).wrapping_sub(1);
                    if c.cert_remaining == 0 {
                        if cx.tls_flags.capture_cert {
                            cx.finalize_base64(proto);
                            cx.end_banner(proto);
                        }
                        c.state = 7; // CALEN0
                    }
                }
                _ => return,
            }
        }
    }

    /// `parse_alert` (`:788-867`): два байта, дальше UNKNOWN внутри записи.
    fn alert(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        // Состояние делит переменные с рукопожатием у C; здесь оно выводится из hs_step: Start=START,
        // Len0=DESCRIPTION, Unknown=UNKNOWN (сброс на каждой записи в B1 даёт Start).
        for &b in px {
            match self.hs_step {
                HsStep::Start => {
                    self.alert_level = b;
                    self.hs_step = HsStep::Len0;
                }
                HsStep::Len0 => {
                    let desc = b;
                    if cx.tls_flags.poodle_sslv3 && self.alert_level == 2 {
                        match desc {
                            86 => {
                                if !banner_contains(cx, app_id::SAFE, b"TLS_FALLBACK_SCSV") {
                                    cx.append(app_id::SAFE, b"poodle[TLS_FALLBACK_SCSV] ");
                                }
                            }
                            40 => {
                                if !banner_contains(cx, app_id::SAFE, b"TLS_FALLBACK_SCSV") {
                                    cx.append(app_id::SAFE, b"poodle[no-SSLv3] ");
                                }
                            }
                            _ => {
                                cx.append(app_id::SAFE, b"poodle[no-SSLv3] ");
                                let mut buf = [0u8; 16];
                                cx.append(
                                    app_id::SSL3,
                                    fmt_alert(&mut buf, self.alert_level, desc),
                                );
                            }
                        }
                    } else {
                        let mut buf = [0u8; 16];
                        cx.append(app_id::SSL3, fmt_alert(&mut buf, self.alert_level, desc));
                    }
                    self.hs_step = HsStep::Unknown;
                }
                _ => return,
            }
        }
    }

    /// `parse_heartbeat` (`:668-775`): `vuln` по объявленной длине; захват без финализации (справка §B6).
    fn heartbeat(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        let mut i = 0usize;
        while i < px.len() {
            let b = px[i];
            i += 1;
            match self.hs_step {
                HsStep::Start => {
                    if !(1..=2).contains(&b) {
                        self.hs_step = HsStep::Unknown;
                    } else {
                        self.hs_type = b;
                        self.hs_step = HsStep::Len0;
                    }
                }
                HsStep::Len0 => {
                    self.hs_remaining = u32::from(b) << 8;
                    self.hs_step = HsStep::Len1;
                }
                HsStep::Len1 => {
                    self.hs_remaining |= u32::from(b);
                    if self.hs_type == 2 {
                        if self.hs_remaining >= 16 {
                            cx.append(app_id::VULN, b"SSL[HEARTBLEED] ");
                        }
                        if cx.tls_flags.capture_heartbleed {
                            cx.init_base64();
                            cx.append(app_id::HEARTBLEED, &[]);
                        }
                    }
                    self.hs_step = HsStep::Contents;
                }
                HsStep::Contents => {
                    let avail = px.len() - i + 1;
                    let len = avail.min(self.hs_remaining as usize);
                    if self.hs_type == 2 && cx.tls_flags.capture_heartbleed && len > 0 {
                        cx.append_base64(app_id::HEARTBLEED, &px[i - 1..i - 1 + len]);
                    }
                    self.hs_remaining -= len as u32;
                    i = i.wrapping_add(len).wrapping_sub(1);
                    if self.hs_remaining == 0 {
                        self.hs_step = HsStep::Unknown;
                    }
                }
                _ => return,
            }
        }
    }
}

/// `BANNER_VERSION` (`src/proto-ssl.c:90-118`), включая `vuln "SSL[v3] "` для 0x0300 в любом режиме.
fn banner_version(cx: &mut ParseCx<'_>, major: u8, minor: u8) {
    match (major, minor) {
        (3, 0) => {
            cx.append(app_id::SSL3, b"SSLv3 ");
            cx.append(app_id::VULN, b"SSL[v3] ");
        }
        (3, 1) => cx.append(app_id::SSL3, b"TLS/1.0 "),
        (3, 2) => cx.append(app_id::SSL3, b"TLS/1.1 "),
        (3, 3) => cx.append(app_id::SSL3, b"TLS/1.2 "),
        (3, 4) => cx.append(app_id::SSL3, b"TLS/1.3 "),
        _ => {
            let mut buf = [0u8; 20];
            cx.append(app_id::SSL3, fmt_version(&mut buf, major, minor));
        }
    }
}

/// Содержит ли открытая запись приложения подстроку (`banout_is_contains` по сохранённым байтам; у C поиск по
/// всей записи, у нас запись может быть урезана пределом Р5 — расхождение только у предела, как у всех
/// записей). Здесь — по записи `safe` через banout: помощник на cx (см. `ParseCx::banner_contains`).
fn banner_contains(cx: &mut ParseCx<'_>, app: u16, needle: &[u8]) -> bool {
    cx.banner_contains(app, needle)
}

fn fmt_cipher(buf: &mut [u8; 16], cipher: u16) -> &[u8] {
    // "cipher:0x%x" без хвостового пробела.
    let mut n = 0;
    for &c in b"cipher:0x" {
        buf[n] = c;
        n += 1;
    }
    n += write_hex(&mut buf[n..], u32::from(cipher), 0);
    &buf[..n]
}

fn fmt_alert(buf: &mut [u8; 16], level: u8, desc: u8) -> &[u8] {
    // " ALERT(0x%02x%02x) "
    let mut n = 0;
    for &c in b" ALERT(0x" {
        buf[n] = c;
        n += 1;
    }
    n += write_hex(&mut buf[n..], u32::from(level), 2);
    n += write_hex(&mut buf[n..], u32::from(desc), 2);
    buf[n] = b')';
    buf[n + 1] = b' ';
    &buf[..n + 2]
}

fn fmt_version(buf: &mut [u8; 20], major: u8, minor: u8) -> &[u8] {
    // "SSLver[%u,%u] "
    let mut n = 0;
    for &c in b"SSLver[" {
        buf[n] = c;
        n += 1;
    }
    n += write_dec(&mut buf[n..], major);
    buf[n] = b',';
    n += 1;
    n += write_dec(&mut buf[n..], minor);
    buf[n] = b']';
    buf[n + 1] = b' ';
    &buf[..n + 2]
}

/// Нижний регистр hex без ведущих нулей, но не короче `min` цифр; возвращает число цифр.
fn write_hex(out: &mut [u8], v: u32, min: usize) -> usize {
    let mut digits = [0u8; 8];
    let mut n = 0;
    let mut v = v;
    loop {
        digits[n] = b"0123456789abcdef"[(v & 0xF) as usize];
        n += 1;
        v >>= 4;
        if v == 0 && n >= min.max(1) {
            break;
        }
    }
    for i in 0..n {
        out[i] = digits[n - 1 - i];
    }
    n
}

fn write_dec(out: &mut [u8], v: u8) -> usize {
    let mut digits = [0u8; 3];
    let mut n = 0;
    let mut v = v;
    loop {
        digits[n] = b'0' + v % 10;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..n {
        out[i] = digits[n - 1 - i];
    }
    n
}
