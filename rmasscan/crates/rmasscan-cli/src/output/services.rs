//! Имена сервисов для `-oG` и `-oU` (AGPL-3.0). Порт `out-tcp-services.c` masscan © Robert David Graham:
//! C спрашивает `getservbyport(port, "tcp"|"udp")` (:34–99), то есть файл services хоста, а для прочих протоколов
//! `getprotobynumber` (:101–118), то есть файл protocols хоста, и отвечает `unknown`, если записи нет. Здесь те же
//! файлы читаются один раз и разбираются сами, без FFI (`#![forbid(unsafe_code)]`).

use std::collections::HashMap;

/// Таблицы имён портов TCP и UDP и номеров IP-протоколов.
#[derive(Clone, Debug, Default)]
pub struct ServiceNames {
    tcp: HashMap<u16, String>,
    udp: HashMap<u16, String>,
    protocols: HashMap<u8, String>,
}

/// Пустая таблица (все порты `unknown`).
pub fn empty() -> ServiceNames {
    ServiceNames::empty()
}

impl ServiceNames {
    pub fn empty() -> ServiceNames {
        ServiceNames::default()
    }

    /// Разбор формата `имя порт/протокол [алиасы] [# комментарий]`. Для порта побеждает первая запись tcp, как у
    /// `getservbyport`; комментарии, пустые и битые строки пропускаются.
    pub fn parse(text: &str) -> ServiceNames {
        let mut tcp = HashMap::new();
        let mut udp = HashMap::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let mut it = line.split_whitespace();
            let (Some(name), Some(spec)) = (it.next(), it.next()) else {
                continue;
            };
            let Some((port, proto)) = spec.split_once('/') else {
                continue;
            };
            let table = match proto {
                "tcp" => &mut tcp,
                "udp" => &mut udp,
                _ => continue,
            };
            if let Ok(port) = port.parse::<u16>() {
                table.entry(port).or_insert_with(|| name.to_string());
            }
        }
        ServiceNames {
            tcp,
            udp,
            protocols: HashMap::new(),
        }
    }

    /// Дополняет таблицу файлом protocols (`имя номер [алиасы] [# комментарий]`): `getprotobynumber` отдаёт
    /// первое имя строки; для номера побеждает первая запись.
    pub fn with_protocols(mut self, text: &str) -> ServiceNames {
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let mut it = line.split_whitespace();
            let (Some(name), Some(num)) = (it.next(), it.next()) else {
                continue;
            };
            if let Ok(num) = num.parse::<u8>() {
                self.protocols
                    .entry(num)
                    .or_insert_with(|| name.to_string());
            }
        }
        self
    }

    /// Файл services хоста: `/etc/services`, на Windows `%SystemRoot%\System32\drivers\etc\services`
    /// (без переменной `C:\Windows`). Нечитаемый файл даёт пустую таблицу.
    pub fn host() -> ServiceNames {
        let services = match std::fs::read(services_path()) {
            Ok(bytes) => ServiceNames::parse(&String::from_utf8_lossy(&bytes)),
            Err(_) => ServiceNames::empty(),
        };
        match std::fs::read(protocols_path()) {
            Ok(bytes) => services.with_protocols(&String::from_utf8_lossy(&bytes)),
            Err(_) => services,
        }
    }

    /// `tcp_service_name`: имя или `unknown`.
    pub fn tcp(&self, port: u16) -> &str {
        self.tcp.get(&port).map_or("unknown", String::as_str)
    }

    /// `udp_service_name` (`out-tcp-services.c:70–99`): имя или `unknown`.
    pub fn udp(&self, port: u16) -> &str {
        self.udp.get(&port).map_or("unknown", String::as_str)
    }

    /// `oproto_service_name` (`out-tcp-services.c:101–118`): имя из protocols хоста (`getprotobynumber`);
    /// нет файла или записи значит `unknown`, как в C.
    pub fn oproto(&self, ip_proto: u8) -> &str {
        self.protocols
            .get(&ip_proto)
            .map_or("unknown", String::as_str)
    }
}

/// Файл protocols хоста: `/etc/protocols`, на Windows `%SystemRoot%\System32\drivers\etc\protocol`.
fn protocols_path() -> std::path::PathBuf {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        std::path::Path::new(&root).join(r"System32\drivers\etc\protocol")
    } else {
        "/etc/protocols".into()
    }
}

fn services_path() -> std::path::PathBuf {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        std::path::Path::new(&root).join(r"System32\drivers\etc\services")
    } else {
        "/etc/services".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_first_tcp_entry_wins() {
        let s = ServiceNames::parse(
            "http 80/tcp www # web\nhttp-alt 80/tcp\nfoo 80/udp\n# x 81/tcp\nbar\t81/tcp\n",
        );
        assert_eq!(s.tcp(80), "http");
        assert_eq!(s.tcp(81), "bar");
        assert_eq!(s.tcp(82), "unknown");
    }

    #[test]
    fn services_skip_broken_lines() {
        let s = ServiceNames::parse(
            "\n   \nlonely\nbad 99999/tcp\nbad2 x/tcp\nnoslash 5\nok 22/tcp\r\n",
        );
        assert_eq!(s.tcp(22), "ok");
        assert_eq!(s.tcp(5), "unknown");
        assert_eq!(ServiceNames::empty().tcp(80), "unknown");
    }

    #[test]
    fn services_udp_and_protocols() {
        let s = ServiceNames::parse("domain 53/udp\ndomain 53/tcp\nonlytcp 81/tcp\n")
            .with_protocols("# c\nip\t0\tIP\nicmp 1 ICMP # x\nbad x\nbig 999 BIG\n");
        assert_eq!(s.udp(53), "domain");
        assert_eq!(s.tcp(53), "domain");
        assert_eq!(s.udp(81), "unknown");
        assert_eq!(s.oproto(0), "ip");
        assert_eq!(s.oproto(1), "icmp");
        // нет записи в файле (или файла): `unknown`, как `getprotobynumber` == NULL в C
        assert_eq!(s.oproto(132), "unknown");
        assert_eq!(s.oproto(47), "unknown");
        assert_eq!(ServiceNames::empty().oproto(1), "unknown");
        assert_eq!(ServiceNames::empty().oproto(0), "unknown");
    }
}
