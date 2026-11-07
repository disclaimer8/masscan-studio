//! `-oG` и `-oU` (AGPL-3.0). Порт `out-grepable.c` и `out-unicornscan.c` masscan © Robert David Graham.
//! Время в заголовке и подвале `-oG` всегда GMT в формате `%c` C-локали (masscan не вызывает `setlocale`).

use std::io::{self, Write};

use super::formats::{FileCtx, Formatter};
use super::record::{MASSCAN_VERSION, Record, civil, status_str};

/// `strftime("%c")` C-локали над GMT: `%a %b %e %H:%M:%S %Y`, день месяца дополнен пробелом до двух знаков.
pub fn c_locale_ctime(unix: u64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (y, mo, d, h, mi, s, wd) = civil(unix as i64);
    format!(
        "{} {} {d:2} {h:02}:{mi:02}:{s:02} {y}",
        DAYS[wd as usize],
        MONTHS[mo as usize - 1]
    )
}

/// `-oG`, `out-grepable.c`.
pub(super) struct Grepable;

impl Formatter for Grepable {
    fn header(&mut self, w: &mut dyn Write, cx: &FileCtx) -> io::Result<()> {
        writeln!(
            w,
            "# Masscan {MASSCAN_VERSION} scan initiated {}",
            c_locale_ctime(cx.scan_started)
        )?;
        // Только TCP: UDP, SCTP и PROTOCOLS всегда пусты. В C разделитель после диапазона зависит от индекса в
        // списке всех портов, и при поздних не-TCP диапазонах остаётся «хвостовая запятая» (`out-grepable.c:42–62`);
        // здесь таких диапазонов нет.
        let count: u64 = cx
            .tcp_ports
            .iter()
            .map(|&(a, b)| u64::from(b) - u64::from(a) + 1)
            .sum();
        write!(w, "# Ports scanned: TCP({count};")?;
        for (i, (a, b)) in cx.tcp_ports.iter().enumerate() {
            let sep = if i + 1 < cx.tcp_ports.len() { "," } else { "" };
            write!(w, "{a}-{b}{sep}")?;
        }
        w.write_all(b") UDP(0;) SCTP(0;) PROTOCOLS(0;)\n")
    }

    fn record(&mut self, w: &mut dyn Write, cx: &FileCtx, r: &Record) -> io::Result<()> {
        writeln!(
            w,
            "Timestamp: {}\tHost: {} ()\tPorts: {}/{}/tcp//{}//",
            r.timestamp,
            r.ip,
            r.port,
            status_str(r.status),
            cx.services.tcp(r.port)
        )
    }

    fn footer(&mut self, w: &mut dyn Write, cx: &FileCtx) -> io::Result<()> {
        writeln!(w, "# Masscan done at {}", c_locale_ctime(cx.now))
    }
}

/// `-oU`, `out-unicornscan.c`.
pub(super) struct Unicornscan;

impl Formatter for Unicornscan {
    fn header(&mut self, w: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        w.write_all(b"#masscan\n")
    }

    fn record(&mut self, w: &mut dyn Write, cx: &FileCtx, r: &Record) -> io::Result<()> {
        writeln!(
            w,
            "TCP {}\t{:>16}[{:>5}]\t\tfrom {}  ttl {:<3}",
            status_str(r.status),
            cx.services.tcp(r.port),
            r.port,
            r.ip,
            r.ttl
        )
    }

    fn footer(&mut self, w: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        w.write_all(b"# end\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::formats::{Counts, Format, formatter};
    use crate::output::record::Status;
    use crate::output::services::ServiceNames;
    use std::net::Ipv4Addr;

    fn rec(port: u16, ttl: u8) -> Record {
        Record {
            timestamp: 1_700_000_000,
            ip: Ipv4Addr::new(1, 2, 3, 4),
            port,
            status: Status::Open,
            reason: 0x12,
            ttl,
        }
    }

    fn ctx<'a>(sv: &'a ServiceNames, ports: &'a [(u16, u16)]) -> FileCtx<'a> {
        FileCtx {
            now: 1_388_620_800,
            utc_offset_secs: 0,
            scan_started: 1_390_335_802,
            file_opened: 0,
            counts: Counts::default(),
            stylesheet: None,
            tcp_ports: ports,
            services: sv,
        }
    }

    fn one(f: Format, cx: &FileCtx, part: u8, r: &Record) -> String {
        let mut fm = formatter(f).expect("formatter");
        let mut out = Vec::new();
        match part {
            0 => fm.header(&mut out, cx).unwrap(),
            1 => fm.record(&mut out, cx, r).unwrap(),
            _ => fm.footer(&mut out, cx).unwrap(),
        }
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn ctime_matches_c_locale() {
        assert_eq!(c_locale_ctime(1_390_335_802), "Tue Jan 21 20:23:22 2014");
        assert_eq!(c_locale_ctime(1_388_620_800), "Thu Jan  2 00:00:00 2014");
    }

    #[test]
    fn grepable_header_record_footer() {
        let sv = ServiceNames::parse("http 80/tcp\n");
        let ports = [(80, 80), (443, 443)];
        let c = ctx(&sv, &ports);
        let r = rec(80, 57);
        assert_eq!(
            one(Format::Grepable, &c, 0, &r),
            "# Masscan 1.3.9-integration scan initiated Tue Jan 21 20:23:22 2014\n\
             # Ports scanned: TCP(2;80-80,443-443) UDP(0;) SCTP(0;) PROTOCOLS(0;)\n"
        );
        assert_eq!(
            one(Format::Grepable, &c, 1, &r),
            "Timestamp: 1700000000\tHost: 1.2.3.4 ()\tPorts: 80/open/tcp//http//\n"
        );
        assert_eq!(
            one(Format::Grepable, &c, 2, &r),
            "# Masscan done at Thu Jan  2 00:00:00 2014\n"
        );
        let c = ctx(&sv, &[]);
        assert!(
            one(Format::Grepable, &c, 0, &r)
                .ends_with("# Ports scanned: TCP(0;) UDP(0;) SCTP(0;) PROTOCOLS(0;)\n")
        );
        let wide = [(1, 1024), (8080, 8081)];
        let c = ctx(&sv, &wide);
        assert!(one(Format::Grepable, &c, 0, &r).contains("TCP(1026;1-1024,8080-8081)"));
    }

    #[test]
    fn unicornscan_widths() {
        let sv = ServiceNames::parse("http 80/tcp\n");
        let c = ctx(&sv, &[]);
        let r = rec(80, 57);
        assert_eq!(one(Format::Unicornscan, &c, 0, &r), "#masscan\n");
        assert_eq!(
            one(Format::Unicornscan, &c, 1, &r),
            "TCP open\t            http[   80]\t\tfrom 1.2.3.4  ttl 57 \n"
        );
        assert_eq!(one(Format::Unicornscan, &c, 2, &r), "# end\n");
    }

    #[test]
    fn edge_values_render_like_c() {
        let sv = ServiceNames::parse("averyveryverylongservicename 1/tcp\n");
        let c = ctx(&sv, &[]);
        assert_eq!(
            one(Format::Unicornscan, &c, 1, &rec(65535, 255)),
            "TCP open\t         unknown[65535]\t\tfrom 1.2.3.4  ttl 255\n"
        );
        assert_eq!(
            one(Format::Unicornscan, &c, 1, &rec(65535, 0)),
            "TCP open\t         unknown[65535]\t\tfrom 1.2.3.4  ttl 0  \n"
        );
        assert_eq!(
            one(Format::Unicornscan, &c, 1, &rec(1, 9)),
            "TCP open\taveryveryverylongservicename[    1]\t\tfrom 1.2.3.4  ttl 9  \n"
        );
        assert_eq!(
            one(Format::Grepable, &c, 1, &rec(65535, 255)),
            "Timestamp: 1700000000\tHost: 1.2.3.4 ()\tPorts: 65535/open/tcp//unknown//\n"
        );
    }
}
