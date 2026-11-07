//! Имена сервисов для `-oG` и `-oU` (AGPL-3.0). Порт `out-tcp-services.c` masscan © Robert David Graham:
//! C спрашивает `getservbyport(port, "tcp")`, то есть файл services хоста, и отвечает `unknown`, если записи нет.
//! Здесь тот же файл читается один раз и разбирается сам, без FFI (`#![forbid(unsafe_code)]`).

use std::collections::HashMap;

/// Таблица имён TCP-портов.
#[derive(Clone, Debug, Default)]
pub struct ServiceNames {
    tcp: HashMap<u16, String>,
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
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let mut it = line.split_whitespace();
            let (Some(name), Some(spec)) = (it.next(), it.next()) else {
                continue;
            };
            let Some((port, proto)) = spec.split_once('/') else {
                continue;
            };
            if proto != "tcp" {
                continue;
            }
            if let Ok(port) = port.parse::<u16>() {
                tcp.entry(port).or_insert_with(|| name.to_string());
            }
        }
        ServiceNames { tcp }
    }

    /// Файл services хоста: `/etc/services`, на Windows `%SystemRoot%\System32\drivers\etc\services`
    /// (без переменной `C:\Windows`). Нечитаемый файл даёт пустую таблицу.
    pub fn host() -> ServiceNames {
        match std::fs::read(services_path()) {
            Ok(bytes) => ServiceNames::parse(&String::from_utf8_lossy(&bytes)),
            Err(_) => ServiceNames::empty(),
        }
    }

    /// `tcp_service_name`: имя или `unknown`.
    pub fn tcp(&self, port: u16) -> &str {
        self.tcp.get(&port).map_or("unknown", String::as_str)
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
}
