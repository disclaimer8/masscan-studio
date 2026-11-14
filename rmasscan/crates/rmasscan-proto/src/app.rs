//! Таблица приложений: `src/masscan-app.h:8-49`, `src/masscan-app.c`.

use std::borrow::Cow;

/// Идентификаторы `enum ApplicationProtocol` (`src/masscan-app.h:8-49`). Значения
/// хранятся в файлах `-oB`, менять их нельзя.
pub mod app_id {
    pub const NONE: u16 = 0;
    pub const HEUR: u16 = 1;
    pub const SSH1: u16 = 2;
    pub const SSH2: u16 = 3;
    pub const HTTP: u16 = 4;
    pub const FTP: u16 = 5;
    pub const DNS_VERSIONBIND: u16 = 6;
    pub const SNMP: u16 = 7;
    pub const NBTSTAT: u16 = 8;
    pub const SSL3: u16 = 9;
    pub const SMB: u16 = 10;
    pub const SMTP: u16 = 11;
    pub const POP3: u16 = 12;
    pub const IMAP4: u16 = 13;
    pub const ZEROACCESS: u16 = 14;
    pub const X509_CERT: u16 = 15;
    pub const X509_CACERT: u16 = 16;
    pub const HTML_TITLE: u16 = 17;
    pub const HTML_FULL: u16 = 18;
    pub const NTP: u16 = 19;
    pub const VULN: u16 = 20;
    pub const HEARTBLEED: u16 = 21;
    pub const TICKETBLEED: u16 = 22;
    pub const VNC_OLD: u16 = 23;
    pub const SAFE: u16 = 24;
    pub const MEMCACHED: u16 = 25;
    pub const SCRIPTING: u16 = 26;
    pub const VERSIONING: u16 = 27;
    pub const COAP: u16 = 28;
    pub const TELNET: u16 = 29;
    pub const RDP: u16 = 30;
    pub const HTTP_SERVER: u16 = 31;
    pub const MC: u16 = 32;
    pub const VNC_RFB: u16 = 33;
    pub const VNC_INFO: u16 = 34;
    pub const ISAKMP: u16 = 35;
    pub const ERROR: u16 = 36;
}

/// Имена по индексу id, `masscan_app_to_string` (`src/masscan-app.c:12-57`).
const NAMES: [&str; 37] = [
    "unknown",
    "unknown",
    "ssh",
    "ssh",
    "http",
    "ftp",
    "dns-ver",
    "snmp",
    "nbtstat",
    "ssl",
    "smb",
    "smtp",
    "pop",
    "imap",
    "zeroaccess",
    "X509",
    "X509CA",
    "title",
    "html",
    "ntp",
    "vuln",
    "heartbleed",
    "ticketbleed",
    "vnc",
    "safe",
    "memcached",
    "scripting",
    "versioning",
    "coap",
    "telnet",
    "rdp",
    "http.server",
    "minecraft",
    "vnc",
    "vnc-info",
    "isakmp",
    "error",
];

/// Имя приложения; неизвестный id печатается как `(N)` (`src/masscan-app.c:55-56`).
pub fn app_name(app: u16) -> Cow<'static, str> {
    match NAMES.get(usize::from(app)) {
        Some(n) => Cow::Borrowed(n),
        None => Cow::Owned(format!("({app})")),
    }
}

/// `masscan_string_to_app` (`src/masscan-app.c:62-112`): `strcmp`, регистр важен.
/// У C неизвестное имя даёт 0; здесь `None`. Id 0, 1 и 36 выбрать нельзя.
pub fn app_from_name(name: &str) -> Option<u16> {
    use app_id::*;
    Some(match name {
        "ssh1" => SSH1,
        "ssh2" | "ssh" => SSH2,
        "http" => HTTP,
        "ftp" => FTP,
        "dns-ver" => DNS_VERSIONBIND,
        "snmp" => SNMP,
        "nbtstat" => NBTSTAT,
        "ssl" => SSL3,
        "smtp" => SMTP,
        "smb" => SMB,
        "pop" => POP3,
        "imap" => IMAP4,
        "x509" => X509_CERT,
        "x509ca" => X509_CACERT,
        "zeroaccess" => ZEROACCESS,
        "title" => HTML_TITLE,
        "html" => HTML_FULL,
        "ntp" => NTP,
        "vuln" => VULN,
        "heartbleed" => HEARTBLEED,
        "ticketbleed" => TICKETBLEED,
        "vnc-old" => VNC_OLD,
        "safe" => SAFE,
        "memcached" => MEMCACHED,
        "scripting" => SCRIPTING,
        "versioning" => VERSIONING,
        "coap" => COAP,
        "telnet" => TELNET,
        "rdp" => RDP,
        "http.server" => HTTP_SERVER,
        "minecraft" => MC,
        "vnc" => VNC_RFB,
        "vnc-info" => VNC_INFO,
        "isakmp" => ISAKMP,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_names_match_c_table() {
        let want = [
            "unknown",
            "unknown",
            "ssh",
            "ssh",
            "http",
            "ftp",
            "dns-ver",
            "snmp",
            "nbtstat",
            "ssl",
            "smb",
            "smtp",
            "pop",
            "imap",
            "zeroaccess",
            "X509",
            "X509CA",
            "title",
            "html",
            "ntp",
            "vuln",
            "heartbleed",
            "ticketbleed",
            "vnc",
            "safe",
            "memcached",
            "scripting",
            "versioning",
            "coap",
            "telnet",
            "rdp",
            "http.server",
            "minecraft",
            "vnc",
            "vnc-info",
            "isakmp",
            "error",
        ];
        for (i, w) in want.iter().enumerate() {
            assert_eq!(app_name(i as u16), *w, "id {i}");
        }
        assert_eq!(app_name(37), "(37)");
        assert_eq!(app_name(65535), "(65535)");
        assert_eq!(app_name(2), app_name(3));
        assert_eq!(app_name(23), "vnc");
        assert_eq!(app_name(33), "vnc");
        assert_eq!(app_id::ISAKMP, 35);
        assert_eq!(app_id::ERROR, 36);
    }

    #[test]
    fn app_from_name_matches_c() {
        assert_eq!(app_from_name("ssh1"), Some(2));
        assert_eq!(app_from_name("ssh"), Some(3));
        assert_eq!(app_from_name("x509"), Some(15));
        assert_eq!(app_from_name("vnc-old"), Some(23));
        assert_eq!(app_from_name("vnc"), Some(33));
        assert_eq!(app_from_name("unknown"), None);
        assert_eq!(app_from_name("error"), None);
        assert_eq!(app_from_name("HTTP"), None);
    }

    /// Все 37 `app_id::*` против `enum ApplicationProtocol` (`src/masscan-app.h:8-49`), `app_name` по
    /// `masscan_app_to_string` (`src/masscan-app.c:12-57`) и `app_from_name` для каждого ключа
    /// `masscan_string_to_app` (`src/masscan-app.c:61-112`), включая TCP-имена.
    #[test]
    fn app_ids_and_names_pinned() {
        // (id у rmasscan, значение у C по порядку enum, имя `masscan_app_to_string`).
        let ids: [(u16, u16, &str); 37] = [
            (app_id::NONE, 0, "unknown"),
            (app_id::HEUR, 1, "unknown"),
            (app_id::SSH1, 2, "ssh"),
            (app_id::SSH2, 3, "ssh"),
            (app_id::HTTP, 4, "http"),
            (app_id::FTP, 5, "ftp"),
            (app_id::DNS_VERSIONBIND, 6, "dns-ver"),
            (app_id::SNMP, 7, "snmp"),
            (app_id::NBTSTAT, 8, "nbtstat"),
            (app_id::SSL3, 9, "ssl"),
            (app_id::SMB, 10, "smb"),
            (app_id::SMTP, 11, "smtp"),
            (app_id::POP3, 12, "pop"),
            (app_id::IMAP4, 13, "imap"),
            (app_id::ZEROACCESS, 14, "zeroaccess"),
            (app_id::X509_CERT, 15, "X509"),
            (app_id::X509_CACERT, 16, "X509CA"),
            (app_id::HTML_TITLE, 17, "title"),
            (app_id::HTML_FULL, 18, "html"),
            (app_id::NTP, 19, "ntp"),
            (app_id::VULN, 20, "vuln"),
            (app_id::HEARTBLEED, 21, "heartbleed"),
            (app_id::TICKETBLEED, 22, "ticketbleed"),
            (app_id::VNC_OLD, 23, "vnc"),
            (app_id::SAFE, 24, "safe"),
            (app_id::MEMCACHED, 25, "memcached"),
            (app_id::SCRIPTING, 26, "scripting"),
            (app_id::VERSIONING, 27, "versioning"),
            (app_id::COAP, 28, "coap"),
            (app_id::TELNET, 29, "telnet"),
            (app_id::RDP, 30, "rdp"),
            (app_id::HTTP_SERVER, 31, "http.server"),
            (app_id::MC, 32, "minecraft"),
            (app_id::VNC_RFB, 33, "vnc"),
            (app_id::VNC_INFO, 34, "vnc-info"),
            (app_id::ISAKMP, 35, "isakmp"),
            (app_id::ERROR, 36, "error"),
        ];
        for (got, want, name) in ids {
            assert_eq!(got, want, "app_id for C value {want}");
            assert_eq!(app_name(want), name, "app_name({want})");
        }
        assert_eq!(app_name(37), "(37)");
        // Ключи `masscan_string_to_app` (`src/masscan-app.c:68-103`) по порядку списка C.
        let keys: [(&str, u16); 35] = [
            ("ssh1", 2),
            ("ssh2", 3),
            ("ssh", 3),
            ("http", 4),
            ("ftp", 5),
            ("dns-ver", 6),
            ("snmp", 7),
            ("nbtstat", 8),
            ("ssl", 9),
            ("smtp", 11),
            ("smb", 10),
            ("pop", 12),
            ("imap", 13),
            ("x509", 15),
            ("x509ca", 16),
            ("zeroaccess", 14),
            ("title", 17),
            ("html", 18),
            ("ntp", 19),
            ("vuln", 20),
            ("heartbleed", 21),
            ("ticketbleed", 22),
            ("vnc-old", 23),
            ("safe", 24),
            ("memcached", 25),
            ("scripting", 26),
            ("versioning", 27),
            ("coap", 28),
            ("telnet", 29),
            ("rdp", 30),
            ("http.server", 31),
            ("minecraft", 32),
            ("vnc", 33),
            ("vnc-info", 34),
            ("isakmp", 35),
        ];
        for (key, want) in keys {
            assert_eq!(app_from_name(key), Some(want), "app_from_name({key})");
        }
        // Не ключи: ни имя из `masscan_app_to_string` без ключа, ни другой регистр (`strcmp`).
        for bad in [
            "", "unknown", "error", "X509", "X509CA", "HTTP", "Http", "vnc-rfb",
        ] {
            assert_eq!(app_from_name(bad), None, "app_from_name({bad:?})");
        }
    }
}
