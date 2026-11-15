//! Hello по порту: `banner1->payloads.tcp[port]` после `banner1_create` (`src/proto-banner1.c:518-610`, `mc_init`
//! `src/proto-mc.c:95-104`), опций `--hello` (`src/stack-tcp-core.c:501-524`, порядок smbv1, http, ssl,
//! `src/main.c:643-648`) и `--hello-string` (`src/stack-tcp-core.c:595-616`, `src/main.c:727-734`), справка B4, C2.
//!
//! В 4b шлются только строки «sent» таблицы B4: запрос HTTP на 80, 8080, 8530, IAC AYT на 23, запрос RDP на 3389,
//! `stats\r\n` на 11211 и рукопожатие Minecraft на 25565. ClientHello TLS (443 и ещё 22 порта) это 4c, SMB (139,
//! 445) это 4d: до них поток NULL, как у порта без hello (справка B6). Hello NPSL (`src/proto-banner1.c:327-489`:
//! 15 потоков на 66 портах, `:548-610`) не переносятся никогда (Р3): их байтов здесь нет.

use std::collections::HashMap;
use std::sync::Arc;

/// `--hello <ssl|smbv1|http>` (`src/main-conf.c:1181-1210`): какие значения заданы.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HelloSet {
    pub http: bool,
    pub ssl: bool,
    pub smbv1: bool,
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
}

impl Default for TcpBannerSettings {
    fn default() -> TcpBannerSettings {
        TcpBannerSettings {
            hello: HelloSet::default(),
            hello_strings: Vec::new(),
            http_request: HTTP_DEFAULT_REQUEST.to_vec(),
            capture_html: false,
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

/// Hello портов скана: таблица B4, затем `--hello http`/`--hello ssl` на портах 0..=65534 (порт 65535 цикл C
/// пропускает, `for (i=0; i<65535; i++)`, E3.6), затем `--hello-string`.
#[derive(Debug)]
pub(crate) struct HelloTable {
    http: Arc<[u8]>,
    telnet: Arc<[u8]>,
    rdp: Arc<[u8]>,
    memcached: Arc<[u8]>,
    mc: Arc<[u8]>,
    all_http: bool,
    all_ssl: bool,
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
            all_http: s.hello.http,
            // `--hello ssl` ставит поток TLS после `http` и побеждает его; в 4b это поток без hello (справка B6).
            // `--hello smbv1` меняет только hello SMB (`smb_set_hello_v1`), а его в 4b нет.
            all_ssl: s.hello.ssl,
            strings,
        }
    }

    /// Hello порта: `None` это поток NULL (hello не шлётся), `Some(&[])` пустой `--hello-string` (справка B5).
    pub(crate) fn hello(&self, port: u16) -> Option<&Arc<[u8]>> {
        if let Some(h) = self.strings.get(&port) {
            return Some(h);
        }
        if port < u16::MAX {
            if self.all_ssl {
                return None;
            }
            if self.all_http {
                return Some(&self.http);
            }
        }
        // `banner1_create` (`src/proto-banner1.c:518-610`) и `mc_init`: только строки «sent» таблицы B4.
        match port {
            80 | 8080 | 8530 => Some(&self.http),
            23 => Some(&self.telnet),
            3389 => Some(&self.rdp),
            11211 => Some(&self.memcached),
            25565 => Some(&self.mc),
            _ => None,
        }
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

    /// Потоки `payloads.tcp[]` C после `banner1_create` (`hellos.out`): порт -> (имя, байты hello, если 4b его шлёт).
    fn c_streams() -> BTreeMap<u16, (String, Option<Vec<u8>>)> {
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
            let len: usize = w[5]
                .strip_prefix("len=")
                .expect("len")
                .parse()
                .expect("len");
            let bytes = (w[6] != "withheld").then(|| unhex(w[6]));
            if let Some(b) = &bytes {
                assert_eq!(b.len(), len, "port {port}");
            }
            out.insert(port, (name, bytes));
        }
        assert_eq!(head, format!("tcp-oracle hellos streams={}", out.len()));
        out
    }

    fn table(s: &TcpBannerSettings) -> HelloTable {
        HelloTable::new(s)
    }

    fn get(t: &HelloTable, port: u16) -> Option<Vec<u8>> {
        t.hello(port).map(|h| h.to_vec())
    }

    /// Таблица B4 в 4b: hello только у потоков, которые 4b шлёт, и байт в байт как у C (`hellos.out`); TLS, SMB и
    /// NPSL у C есть, у нас поток NULL; порт без потока у C и у нас NULL.
    #[test]
    fn hello_table_4b() {
        let t = table(&TcpBannerSettings::default());
        let c = c_streams();
        assert_eq!(c.len(), 98);
        let mut sent = 0;
        for port in 0..=u16::MAX {
            let want = c.get(&port).and_then(|(_, b)| b.clone());
            sent += usize::from(want.is_some());
            assert_eq!(get(&t, port), want, "port {port}");
        }
        assert_eq!(sent, 7);
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
        for port in [
            443, 465, 993, 8443, 139, 445, 53, 88, 1099, 6000, 6019, 27017, 548,
        ] {
            assert!(c.contains_key(&port), "C has a stream on {port}");
            assert_eq!(get(&t, port), None, "{port}");
        }
        assert_eq!(c.get(&443).map(|s| s.0.as_str()), Some("ssl"));
        assert_eq!(c.get(&445).map(|s| s.0.as_str()), Some("smb"));
    }

    /// `--hello http`: запрос HTTP на портах 0..=65534, порт 65535 цикл C пропускает (E3.6) и он остаётся NULL;
    /// `--hello ssl` (поток TLS без hello в 4b) побеждает `http`; `--hello smbv1` в 4b ничего не меняет.
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
        for port in [0, 23, 80, 443, 3389, 11211, 25565, 65534] {
            assert_eq!(get(&t, port), None, "port {port}");
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
        assert_eq!(get(&t, 8080), None, "ssl wins over http elsewhere");
    }
}
