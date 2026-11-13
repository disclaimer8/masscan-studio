//! Запись о порте и общие помощники форматов (AGPL-3.0). Порт `output.c:71–136` (`name_from_ip_proto`,
//! `status_string`, `reason_string`) masscan © Robert David Graham. Запись это то, что `output_report_status`
//! получает от приёма: время, адрес, порт, протокол, статус, флаги TCP (`reason`), TTL и (у ARP) MAC.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

use rmasscan_core::ranges6::format_ipv6_c;
use rmasscan_core::receive::{PortStatus, Reply};

/// `masscan-version.h:3`.
pub const MASSCAN_VERSION: &str = "1.3.9-integration";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Open,
    Closed,
    /// `PortStatus_Arp`: сосед ARP (`output.c:109–116`, строка `up`).
    Arp,
}

/// Протокол записи; значение это номер IP-протокола, как `ip_proto` в `output_report_status` и в байте 10
/// записи `-oB` (`output.c:75–86`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Proto {
    Tcp = 6,
    Udp = 17,
    Sctp = 132,
    Icmp = 1,
    Arp = 0,
}

impl Proto {
    /// `None` для номеров, которых этот порт не выводит (C печатает для них `err`, `output.c:84`).
    pub fn from_ip_proto(n: u8) -> Option<Proto> {
        match n {
            6 => Some(Proto::Tcp),
            17 => Some(Proto::Udp),
            132 => Some(Proto::Sctp),
            1 => Some(Proto::Icmp),
            0 => Some(Proto::Arp),
            _ => None,
        }
    }
}

/// `name_from_ip_proto` (`output.c:75–86`).
pub fn proto_str(p: Proto) -> &'static str {
    match p {
        Proto::Arp => "arp",
        Proto::Icmp => "icmp",
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
        Proto::Sctp => "sctp",
    }
}

/// `name_from_ip_proto` (`src/output.c:71-82`) над любым байтом: у записи баннера `ip_proto` может быть любым
/// (`--readscan` хранит его как есть), всё, кроме 0/1/6/17/132, печатается `err`. Для записи статуса это то же, что
/// [`proto_str`].
pub fn ip_proto_name(n: u8) -> &'static str {
    match Proto::from_ip_proto(n) {
        Some(p) => proto_str(p),
        None => "err",
    }
}

/// Адрес в тексте C: `ipaddress_fmt` (`massip-addr.c:191-216`). IPv4 это `a.b.c.d`; IPv6 это `ipv6address_fmt`
/// (`massip-addr.c:33-109`, сжимается ПЕРВАЯ серия нулевых слов, `2a03:9060::400:0:0:0:2`, а не `Ipv6Addr::Display`)
/// без скобок: ни один формат вывода C их не ставит.
#[derive(Clone, Copy, Debug)]
pub struct CIp(pub IpAddr);

impl fmt::Display for CIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            IpAddr::V4(a) => write!(f, "{a}"),
            IpAddr::V6(a) => f.write_str(&format_ipv6_c(u128::from(a))),
        }
    }
}

/// Одна запись о порте. `timestamp` хранится целиком; форматы режут его так же, как C (`%u`, `(int)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub timestamp: u64,
    /// Адрес цели: IPv4 или IPv6 (`ipaddress` C, `massip-addr.h`). Текст всегда через [`CIp`].
    pub ip: IpAddr,
    pub port: u16,
    pub proto: Proto,
    pub status: Status,
    /// Байт флагов TCP (`px[transport_offset + 13]`); у остальных протоколов 0.
    pub reason: u8,
    pub ttl: u8,
    /// MAC соседа: только у записей `arp`; в `-oB` не пишется (`out-binary.c:154–211`), виден лишь в
    /// интерактивной строке (`output.c:770–778`).
    pub mac: Option<[u8; 6]>,
}

impl Record {
    pub fn from_reply(r: &Reply, timestamp: u64) -> Record {
        debug_assert!(
            Proto::from_ip_proto(r.ip_proto).is_some(),
            "unknown ip_proto {}",
            r.ip_proto
        );
        Record {
            timestamp,
            // `Reply.remote_ip` остаётся `u32` (контракт Studio, 0 у IPv6); адрес IPv6 лежит в `Reply.ip6`.
            ip: match r.ip6 {
                Some(v6) => IpAddr::V6(Ipv6Addr::from(v6.remote)),
                None => IpAddr::V4(r.remote_ip.into()),
            },
            port: r.remote_port,
            // Приём других протоколов ставит только 0/1/6/17/132 (`output.c:75–86`); незнакомый номер был бы
            // `err` в C, здесь его не бывает.
            proto: Proto::from_ip_proto(r.ip_proto).unwrap_or(Proto::Tcp),
            status: match r.status {
                PortStatus::Open => Status::Open,
                PortStatus::Closed => Status::Closed,
                PortStatus::Arp => Status::Arp,
            },
            reason: r.tcp_flags,
            ttl: r.ttl,
            mac: r.mac,
        }
    }
}

/// `output.c:103–112`.
pub fn status_str(s: Status) -> &'static str {
    match s {
        Status::Open => "open",
        Status::Closed => "closed",
        Status::Arp => "up",
    }
}

/// `output.c:118–136`: имена флагов в порядке fin, syn, rst, psh, ack, urg, ece, cwr через `-`; `none` без флагов.
pub fn reason_string(flags: u8) -> String {
    const NAMES: [&str; 8] = ["fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"];
    let parts: Vec<&str> = NAMES
        .iter()
        .enumerate()
        .filter(|(i, _)| flags & (1 << i) != 0)
        .map(|(_, n)| *n)
        .collect();
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join("-")
    }
}

/// Unix-секунды в григорианскую дату и время (чистая арифметика, `civil_from_days` Говарда Хиннанта):
/// `(год, месяц 1–12, день 1–31, час, минута, секунда, день недели 0 = воскресенье)`.
pub(crate) fn civil(unix_secs: i64) -> (i64, u32, u32, u32, u32, u32, u32) {
    let days = unix_secs.div_euclid(86_400);
    let rem = unix_secs.rem_euclid(86_400) as u32;
    let weekday = (days + 4).rem_euclid(7) as u32;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d, rem / 3600, rem / 60 % 60, rem % 60, weekday)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_strings_follow_c() {
        assert_eq!(reason_string(0), "none");
        assert_eq!(reason_string(0x12), "syn-ack");
        assert_eq!(reason_string(0x04), "rst");
        assert_eq!(reason_string(0x14), "rst-ack");
        assert_eq!(reason_string(0xFF), "fin-syn-rst-psh-ack-urg-ece-cwr");
    }

    #[test]
    fn civil_matches_known_dates() {
        assert_eq!(civil(0), (1970, 1, 1, 0, 0, 0, 4));
        assert_eq!(civil(1_700_000_000), (2023, 11, 14, 22, 13, 20, 2));
        assert_eq!(civil(1_390_335_802), (2014, 1, 21, 20, 23, 22, 2));
        assert_eq!(civil(951_782_400), (2000, 2, 29, 0, 0, 0, 2));
        assert_eq!(civil(-1), (1969, 12, 31, 23, 59, 59, 3));
    }
}
