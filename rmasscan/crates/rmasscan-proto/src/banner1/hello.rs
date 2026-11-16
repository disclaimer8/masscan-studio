//! Hello по порту: `banner1->payloads.tcp[port]` после `banner1_create` (`src/proto-banner1.c:518-610`, `mc_init`
//! `src/proto-mc.c:95-104`), опций `--hello` (`src/stack-tcp-core.c:501-524`, порядок smbv1, http, ssl,
//! `src/main.c:643-648`) и `--hello-string` (`src/stack-tcp-core.c:595-616`, `src/main.c:727-734`), справка B4, C2.
//!
//! Шлются строки «sent» таблицы B4 и ClientHello TLS на 23 портах (справка 4c §A1); SMB (139, 445) это 4d: до
//! него поток NULL, как у порта без hello. Hello NPSL (`src/proto-banner1.c:327-489`: 15 потоков на 66 портах,
//! `:548-610`) не переносятся никогда (Р3): их байтов здесь нет.

use std::collections::HashMap;
use std::sync::Arc;

use crate::tcp::app::StreamDesc;

use super::tls::TlsFlags;
use super::tls_hello::{TlsHelloKind, tls_hello};

/// `--hello <ssl|smbv1|http>` (`src/main-conf.c:1181-1210`): какие значения заданы.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HelloSet {
    pub http: bool,
    pub ssl: bool,
    pub smbv1: bool,
}

/// Настройки TLS одного скана: пять построенных ClientHello (по одному разу на скан, как один
/// `banner_ssl.hello` у C), флаги захвата и режимы проверок. Режимы — независимые биты, как у C
/// (`src/masscan.h:201-203`, справка §E2): hello на проводе выбирает последний по порядку применения в
/// `src/main.c:645-654` (poodle после ticketbleed после heartbleed), а флаги парсера накапливаются.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsSettings {
    /// Построенные hello в порядке [`TlsHelloKind`]: Default, Tls13, Heartbeat, Ticketbleed, Sslv3Poodle.
    pub hellos: [Arc<[u8]>; 5],
    /// `--capture cert`, по умолчанию включён (`src/main.c:1610`).
    pub capture_cert: bool,
    pub capture_heartbleed: bool,
    pub capture_ticketbleed: bool,
    pub heartbleed: bool,
    pub ticketbleed: bool,
    pub poodle_sslv3: bool,
}

impl TlsSettings {
    /// Строит пять hello на момент `now_secs` (`time(0)` в `ssl_hello`); флаги по умолчанию как у C без опций.
    pub fn new(now_secs: u64) -> TlsSettings {
        let hello = |kind| Arc::<[u8]>::from(tls_hello(kind, now_secs).as_slice());
        TlsSettings {
            hellos: [
                hello(TlsHelloKind::Default),
                hello(TlsHelloKind::Tls13),
                hello(TlsHelloKind::Heartbeat),
                hello(TlsHelloKind::Ticketbleed),
                hello(TlsHelloKind::Sslv3Poodle),
            ],
            capture_cert: true,
            capture_heartbleed: false,
            capture_ticketbleed: false,
            heartbleed: false,
            ticketbleed: false,
            poodle_sslv3: false,
        }
    }

    /// Hello вида `kind`, построенное на старте скана.
    pub fn hello(&self, kind: TlsHelloKind) -> &Arc<[u8]> {
        &self.hellos[kind as usize]
    }

    /// Какой hello шлёт первый поток TLS: последний режим по порядку `src/main.c:645-654`.
    pub fn hello_kind(&self) -> TlsHelloKind {
        if self.poodle_sslv3 {
            TlsHelloKind::Sslv3Poodle
        } else if self.ticketbleed {
            TlsHelloKind::Ticketbleed
        } else if self.heartbleed {
            TlsHelloKind::Heartbeat
        } else {
            TlsHelloKind::Default
        }
    }

    /// Любой режим проверки задан: режимы, как `--hello ssl`, ставят поток TLS на все порты (справка §A1).
    pub fn any_mode(&self) -> bool {
        self.heartbleed || self.ticketbleed || self.poodle_sslv3
    }

    /// Флаги для парсера TLS.
    pub(crate) fn flags(&self) -> TlsFlags {
        TlsFlags {
            capture_cert: self.capture_cert,
            capture_heartbleed: self.capture_heartbleed,
            capture_ticketbleed: self.capture_ticketbleed,
            heartbleed: self.heartbleed,
            ticketbleed: self.ticketbleed,
            poodle_sslv3: self.poodle_sslv3,
        }
    }
}

impl Default for TlsSettings {
    fn default() -> TlsSettings {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        TlsSettings::new(now)
    }
}

/// Неизменяемые опции баннеров TCP одного скана.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpBannerSettings {
    pub hello: HelloSet,
    /// `--hello-string[PORT]`, уже раскодированные и в порядке «первый заданный выигрывает» (справка C2): для
    /// порта берётся первая пара с ним.
    pub hello_strings: Vec<(u16, Vec<u8>)>,
    /// Готовый запрос HTTP (`banner_http.hello` после `--http-*`, справка C3); по умолчанию запрос C.
    pub http_request: Vec<u8>,
    /// `--capture html` (`banner1->is_capture_html`).
    pub capture_html: bool,
    /// TLS: hello, захват и режимы проверок.
    pub tls: TlsSettings,
}

impl Default for TcpBannerSettings {
    fn default() -> TcpBannerSettings {
        TcpBannerSettings {
            hello: HelloSet::default(),
            hello_strings: Vec::new(),
            http_request: HTTP_DEFAULT_REQUEST.to_vec(),
            capture_html: false,
            tls: TlsSettings::default(),
        }
    }
}

/// Запрос HTTP по умолчанию, `http_hello` (`src/proto-http.c:386-396`, без `IVRE_BUILD`): 99 байт, без `Host:`.
pub(crate) const HTTP_DEFAULT_REQUEST: &[u8] = b"GET / HTTP/1.0\r\n\
User-Agent: ivre-masscan/1.3 https://github.com/robertdavidgraham/\r\n\
Accept: */*\r\n\
\r\n";

/// `banner_telnet.hello` (`src/proto-tcp-telnet.c:351-356`): IAC AYT.
const TELNET_HELLO: &[u8] = b"\xff\xf6";

/// `rdp_hello` (`src/proto-tcp-rdp.c:366-370`): TPKT + запрос соединения COTP с `Cookie: mstshash=masscan\r\n`,
/// 45 байт.
const RDP_HELLO: &[u8] = b"\x03\x00\x00\x2d\
\x28\xe0\x00\x00\x00\x00\x00\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\
\x73\x74\x73\x68\x61\x73\x68\x3dmasscan\x0d\x0a\x01\x00\
\x08\x00\x03\x00\x00\x00";

/// `banner_memcached.hello` (`src/proto-memcached.c:429-434`).
const MEMCACHED_HELLO: &[u8] = b"stats\r\n";

/// `hand_shake(25565, "localhost", 9)` (`src/proto-mc.c:13-29`, `:97-102`): длина 16, номер пакета 0, версия
/// протокола 0x05f7 как varint `f7 05`, адрес, порт, следующее состояние 1, затем запрос статуса `01 00`; 19 байт.
const MC_HELLO: &[u8] = b"\x10\x00\xf7\x05\x09localhost\x63\xdd\x01\x01\x00";

/// Порты потока `banner_ssl` из `banner1_create` (`src/proto-banner1.c:527-595`, справка 4c §A1): ровно 23.
const TLS_PORTS: [u16; 23] = [
    322, 443, 465, 636, 637, 990, 991, 992, 993, 994, 995, 2083, 2087, 2096, 2376, 3269, 5061,
    8140, 8443, 8531, 9050, 11712, 49955,
];

/// Потоки портов скана: таблица B4, затем `--hello http`, `--hello ssl` и режимы проверок на портах
/// 0..=65534 (порт 65535 цикл C пропускает, `for (i=0; i<65535; i++)`, E3.6), затем `--hello-string`
/// (копия потока порта с другим hello, справка §A1).
#[derive(Debug)]
pub(crate) struct HelloTable {
    http: Arc<[u8]>,
    telnet: Arc<[u8]>,
    rdp: Arc<[u8]>,
    memcached: Arc<[u8]>,
    mc: Arc<[u8]>,
    tls_first: Arc<[u8]>,
    tls_next: Arc<[u8]>,
    tls_small_window: bool,
    all_http: bool,
    all_tls: bool,
    strings: HashMap<u16, Arc<[u8]>>,
}

impl HelloTable {
    pub(crate) fn new(s: &TcpBannerSettings) -> HelloTable {
        let mut strings = HashMap::new();
        for (port, hello) in &s.hello_strings {
            // Первая заданная выигрывает: C ставит их в начало списка и применяет от новой к старой
            // (`src/main-conf.c:1281-1284`, `src/main.c:727-734`).
            strings
                .entry(*port)
                .or_insert_with(|| Arc::<[u8]>::from(hello.as_slice()));
        }
        HelloTable {
            http: Arc::from(s.http_request.as_slice()),
            telnet: Arc::from(TELNET_HELLO),
            rdp: Arc::from(RDP_HELLO),
            memcached: Arc::from(MEMCACHED_HELLO),
            mc: Arc::from(MC_HELLO),
            tls_first: Arc::clone(s.tls.hello(s.tls.hello_kind())),
            tls_next: Arc::clone(s.tls.hello(TlsHelloKind::Tls13)),
            tls_small_window: s.tls.heartbleed,
            all_http: s.hello.http,
            // `--hello ssl` и каждый режим ставят поток TLS после `http` и побеждают его
            // (`src/main.c:645-654`). `--hello smbv1` меняет только hello SMB, а его до 4d нет.
            all_tls: s.hello.ssl || s.tls.any_mode(),
            strings,
        }
    }

    /// Поток `banner_ssl` как зарегистрирован (`src/proto-ssl.c:1442-1451`): FIN за hello, второе
    /// соединение с hello TLS 1.3.
    fn tls_desc(&self) -> StreamDesc {
        StreamDesc {
            hello: Some(Arc::clone(&self.tls_first)),
            close_after_hello: true,
            next: Some(Arc::clone(&self.tls_next)),
            small_window: self.tls_small_window,
            is_tls: true,
        }
    }

    /// Поток порта без `--hello-string`.
    fn base_stream(&self, port: u16) -> StreamDesc {
        if port < u16::MAX {
            if self.all_tls {
                return self.tls_desc();
            }
            if self.all_http {
                return StreamDesc::plain(Some(Arc::clone(&self.http)));
            }
        }
        // `banner1_create` (`src/proto-banner1.c:518-610`) и `mc_init`: строки «sent» таблицы B4 и TLS.
        if TLS_PORTS.contains(&port) {
            return self.tls_desc();
        }
        StreamDesc::plain(match port {
            80 | 8080 | 8530 => Some(Arc::clone(&self.http)),
            23 => Some(Arc::clone(&self.telnet)),
            3389 => Some(Arc::clone(&self.rdp)),
            11211 => Some(Arc::clone(&self.memcached)),
            25565 => Some(Arc::clone(&self.mc)),
            _ => None,
        })
    }

    /// Поток порта: `--hello-string` заменяет в потоке порта только hello и его длину, флаги и `next`
    /// остаются от потока (`src/stack-tcp-core.c:595-616`, E3.5 справки TCP).
    pub(crate) fn stream(&self, port: u16) -> StreamDesc {
        let mut desc = self.base_stream(port);
        if let Some(h) = self.strings.get(&port) {
            desc.hello = Some(Arc::clone(h));
        }
        desc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const GOLDEN: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/tcp-banners"
    );

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// Потоки `payloads.tcp[]` C после `banner1_create` (`hellos.out`): порт -> (имя, флаги, next, длина,
    /// байты hello, если оракул их печатает).
    type CStream = (String, u32, bool, usize, Option<Vec<u8>>);
    fn c_streams() -> BTreeMap<u16, CStream> {
        let text = std::fs::read_to_string(format!("{GOLDEN}/hellos.out")).expect("hellos.out");
        let mut lines = text.lines();
        let head = lines.next().expect("header");
        let mut out = BTreeMap::new();
        for line in lines {
            let w: Vec<&str> = line.split(' ').collect();
            assert_eq!(w[0], "hello");
            let port: u16 = w[1]
                .strip_prefix("port=")
                .expect("port")
                .parse()
                .expect("port");
            let name = w[2].strip_prefix("name=").expect("name").to_owned();
            let flags = u32::from_str_radix(w[3].strip_prefix("flags=0x").expect("flags"), 16)
                .expect("flags");
            let next = w[4].strip_prefix("next=").expect("next") == "1";
            let len: usize = w[5]
                .strip_prefix("len=")
                .expect("len")
                .parse()
                .expect("len");
            let bytes = (w[6] != "withheld").then(|| unhex(w[6]));
            if let Some(b) = &bytes {
                assert_eq!(b.len(), len, "port {port}");
            }
            out.insert(port, (name, flags, next, len, bytes));
        }
        assert_eq!(head, format!("tcp-oracle hellos streams={}", out.len()));
        out
    }

    fn table(s: &TcpBannerSettings) -> HelloTable {
        HelloTable::new(s)
    }

    fn get(t: &HelloTable, port: u16) -> Option<Vec<u8>> {
        t.stream(port).hello.map(|h| h.to_vec())
    }

    /// Таблица потоков в 4c: hello потоков B4 байт в байт как у C (`hellos.out`), на 23 TLS-портах — поток
    /// `banner_ssl` (hello по умолчанию, `SF__close` и `next` как в дампе C, длина как у C); SMB и NPSL у C
    /// есть, у нас поток NULL; порт без потока у C и у нас NULL.
    #[test]
    fn stream_table_4c() {
        let t = table(&TcpBannerSettings::default());
        let c = c_streams();
        assert_eq!(c.len(), 98);
        let mut sent = 0;
        for port in 0..=u16::MAX {
            let desc = t.stream(port);
            if TLS_PORTS.contains(&port) {
                sent += 1;
                let (_, flags, next, len, _) = c.get(&port).expect("C stream");
                assert!(desc.is_tls, "port {port}");
                assert_eq!(desc.close_after_hello, flags & 1 != 0, "port {port}");
                assert_eq!(desc.next.is_some(), *next, "port {port}");
                assert_eq!(
                    desc.hello.as_ref().map(|h| h.len()),
                    Some(*len),
                    "port {port}"
                );
                assert_eq!(
                    desc.hello.as_deref(),
                    Some(crate::banner1::tls_hello::tls_hello(TlsHelloKind::Default, 0).as_slice()),
                    "port {port}"
                );
                assert_eq!(
                    desc.next.as_ref().map(|h| h.len()),
                    Some(287),
                    "port {port}"
                );
                continue;
            }
            let want = c.get(&port).and_then(|(_, _, _, _, b)| b.clone());
            sent += usize::from(want.is_some());
            assert_eq!(desc.hello.as_deref(), want.as_deref(), "port {port}");
            assert!(
                !desc.is_tls && !desc.close_after_hello && desc.next.is_none(),
                "port {port}"
            );
        }
        assert_eq!(sent, 7 + 23);
        assert_eq!(get(&t, 80).map(|h| h.len()), Some(99));
        for port in [80, 8080, 8530] {
            assert_eq!(
                get(&t, port).as_deref(),
                Some(HTTP_DEFAULT_REQUEST),
                "{port}"
            );
        }
        assert_eq!(get(&t, 23).as_deref(), Some(&b"\xff\xf6"[..]));
        assert_eq!(get(&t, 3389).map(|h| h.len()), Some(45));
        assert_eq!(get(&t, 11211).as_deref(), Some(&b"stats\r\n"[..]));
        assert_eq!(get(&t, 25565).map(|h| h.len()), Some(19));
        for port in [139, 445, 53, 88, 1099, 6000, 6019, 27017, 548] {
            assert!(c.contains_key(&port), "C has a stream on {port}");
            assert_eq!(get(&t, port), None, "{port}");
        }
        assert_eq!(c.get(&443).map(|s| s.0.as_str()), Some("ssl"));
        assert_eq!(c.get(&445).map(|s| s.0.as_str()), Some("smb"));
    }

    /// `--hello http`: запрос HTTP на портах 0..=65534, порт 65535 цикл C пропускает (E3.6) и он остаётся NULL;
    /// `--hello ssl` побеждает `http` потоком TLS; `--hello smbv1` ничего не меняет до 4d.
    #[test]
    fn hello_http_every_port_but_65535() {
        let req = b"GET /x HTTP/1.1\r\n\r\n".to_vec();
        let mut s = TcpBannerSettings {
            http_request: req.clone(),
            ..TcpBannerSettings::default()
        };
        s.hello.http = true;
        let t = table(&s);
        for port in 0..u16::MAX {
            assert_eq!(get(&t, port).as_ref(), Some(&req), "port {port}");
        }
        assert_eq!(get(&t, u16::MAX), None);

        s.hello.ssl = true;
        let t = table(&s);
        let want_tls = crate::banner1::tls_hello::tls_hello(TlsHelloKind::Default, 0);
        for port in [0, 23, 80, 443, 3389, 11211, 25565, 65534] {
            let desc = t.stream(port);
            assert!(desc.is_tls, "port {port}");
            assert_eq!(
                desc.hello.as_deref(),
                Some(want_tls.as_slice()),
                "port {port}"
            );
        }
        assert_eq!(get(&t, u16::MAX), None);

        let base = table(&TcpBannerSettings::default());
        let smb = table(&TcpBannerSettings {
            hello: HelloSet {
                smbv1: true,
                ..HelloSet::default()
            },
            ..TcpBannerSettings::default()
        });
        for port in 0..=u16::MAX {
            assert_eq!(get(&smb, port), get(&base, port), "port {port}");
        }
        // Запрос HTTP опций доходит и до портов B4.
        let custom = table(&TcpBannerSettings {
            http_request: req.clone(),
            ..TcpBannerSettings::default()
        });
        assert_eq!(get(&custom, 8530), Some(req));
    }

    /// `--hello-string`: для порта выигрывает первая заданная (справка C2), поверх таблицы и `--hello http|ssl`;
    /// пустая строка это пустой hello (`Some(&[])`), не NULL; порт 65535 тоже.
    #[test]
    fn hello_string_first_given_wins() {
        let mut s = TcpBannerSettings {
            hello_strings: vec![
                (80, b"first".to_vec()),
                (9999, Vec::new()),
                (80, b"second".to_vec()),
                (443, b"tls-port".to_vec()),
                (u16::MAX, b"last-port".to_vec()),
            ],
            ..TcpBannerSettings::default()
        };
        s.hello.http = true;
        s.hello.ssl = true;
        let t = table(&s);
        assert_eq!(get(&t, 80), Some(b"first".to_vec()));
        assert_eq!(get(&t, 9999), Some(Vec::new()));
        assert_eq!(get(&t, 443), Some(b"tls-port".to_vec()));
        assert_eq!(get(&t, u16::MAX), Some(b"last-port".to_vec()));
        assert!(t.stream(8080).is_tls, "ssl wins over http elsewhere");
    }

    /// E3.5: `--hello-string` на TLS-порту копирует поток `banner_ssl` — свой hello, но `SF__close` и `next`
    /// потока остаются (`src/stack-tcp-core.c:595-616`).
    #[test]
    fn hello_string_on_tls_port_keeps_stream_flags() {
        let t = table(&TcpBannerSettings {
            hello_strings: vec![(443, b"mine".to_vec())],
            ..TcpBannerSettings::default()
        });
        let desc = t.stream(443);
        assert_eq!(desc.hello.as_deref(), Some(&b"mine"[..]));
        assert!(desc.is_tls && desc.close_after_hello);
        assert_eq!(
            desc.next.as_deref(),
            Some(crate::banner1::tls_hello::tls_hello(TlsHelloKind::Tls13, 0).as_slice())
        );
    }

    /// Режим heartbleed: поток TLS на всех портах с hello режима и малым окном; второе соединение — статичный
    /// hello TLS 1.3 (`banner_ssl_12.hello` режим не заменяет, справка §A2).
    #[test]
    fn heartbleed_mode_stream() {
        let mut tls = TlsSettings::new(1_700_000_000);
        tls.heartbleed = true;
        let t = table(&TcpBannerSettings {
            tls,
            ..TcpBannerSettings::default()
        });
        let desc = t.stream(80);
        assert!(desc.is_tls && desc.small_window && desc.close_after_hello);
        assert_eq!(
            desc.hello.as_deref(),
            Some(
                crate::banner1::tls_hello::tls_hello(TlsHelloKind::Heartbeat, 1_700_000_000)
                    .as_slice()
            )
        );
        assert_eq!(
            desc.next.as_deref(),
            Some(crate::banner1::tls_hello::tls_hello(TlsHelloKind::Tls13, 0).as_slice())
        );
        assert_eq!(get(&t, u16::MAX), None);
    }
}
