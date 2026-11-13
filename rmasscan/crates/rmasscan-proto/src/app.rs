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
}
