//! Запись о порте и общие помощники форматов (AGPL-3.0). Порт `output.c:71–136` (`status_string`,
//! `reason_string`) masscan © Robert David Graham. Запись это то, что `output_report_status` получает от приёма:
//! время, адрес, порт, статус, флаги TCP (`reason`) и TTL.

use std::net::Ipv4Addr;

use rmasscan_core::receive::{PortStatus, Reply};

/// `masscan-version.h:3`.
pub const MASSCAN_VERSION: &str = "1.3.9-integration";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Open,
    Closed,
}

/// Одна запись о TCP-порте. `timestamp` хранится целиком; форматы режут его так же, как C (`%u`, `(int)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub timestamp: u64,
    pub ip: Ipv4Addr,
    pub port: u16,
    pub status: Status,
    /// Байт флагов TCP (`px[transport_offset + 13]`).
    pub reason: u8,
    pub ttl: u8,
}

impl Record {
    pub fn from_reply(r: &Reply, timestamp: u64) -> Record {
        Record {
            timestamp,
            ip: Ipv4Addr::from(r.remote_ip),
            port: r.remote_port,
            status: match r.status {
                PortStatus::Open => Status::Open,
                PortStatus::Closed => Status::Closed,
            },
            reason: r.tcp_flags,
            ttl: r.ttl,
        }
    }
}

/// `output.c:103–112`.
pub fn status_str(s: Status) -> &'static str {
    match s {
        Status::Open => "open",
        Status::Closed => "closed",
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
