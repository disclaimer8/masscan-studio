//! `-oG` и `-oU` (AGPL-3.0). Порт `out-grepable.c` и `out-unicornscan.c` masscan © Robert David Graham, записи
//! статуса и баннеров.
//! Время в заголовке и подвале `-oG` всегда GMT в формате `%c` C-локали (masscan не вызывает `setlocale`).

use std::io::{self, Write};

use super::formats::{FileCtx, Formatter};
use super::record::{CIp, MASSCAN_VERSION, Proto, Record, civil, proto_str, status_str};
use rmasscan_core::targets::{
    TEMPL_OPROTO_FIRST, TEMPL_OPROTO_LAST, TEMPL_SCTP, TEMPL_SCTP_LAST, TEMPL_TCP, TEMPL_TCP_LAST,
    TEMPL_UDP, TEMPL_UDP_LAST,
};
use rmasscan_proto::{BannerRecord, app_name, normalize_string};

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

/// `count_type` (`out-grepable.c:14–37`): сколько портов списка попадает в `[min, max]`.
fn count_type(ports: &[(u32, u32)], min: u32, max: u32) -> u32 {
    let mut result = 0u32;
    for &(begin, end) in ports {
        if begin > max || end < min {
            continue;
        }
        result = result.wrapping_add(end.min(max).wrapping_sub(begin.max(min)).wrapping_add(1));
    }
    result
}

/// `print_port_list` (`out-grepable.c:42–62`). Печатаются значения со сдвигом протокола (C не вычитает смещение),
/// а запятая ставится по месту диапазона в ОБЩЕМ списке, а не в группе: после диапазона, за которым в списке
/// есть что-то ещё (в том числе чужой группы), остаётся «хвостовая запятая». Это причуды C, сохранённые для
/// паритета `--readscan -oG`.
fn print_port_list(w: &mut dyn Write, ports: &[(u32, u32)], min: u32, max: u32) -> io::Result<()> {
    for (i, &(begin, end)) in ports.iter().enumerate() {
        if begin > max || end < min {
            continue;
        }
        let sep = if i + 1 < ports.len() { "," } else { "" };
        write!(w, "{}-{}{sep}", begin.max(min), end.min(max))?;
    }
    Ok(())
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
        // `out-grepable.c:84–106`: четыре группы подряд, у каждой своё число и список.
        for (open, min, max) in [
            ("# Ports scanned: TCP(", TEMPL_TCP, TEMPL_TCP_LAST),
            (") UDP(", TEMPL_UDP, TEMPL_UDP_LAST),
            (") SCTP(", TEMPL_SCTP, TEMPL_SCTP_LAST),
            (") PROTOCOLS(", TEMPL_OPROTO_FIRST, TEMPL_OPROTO_LAST),
        ] {
            let count = count_type(cx.ports, min, max);
            write!(w, "{open}{count};")?;
            if count != 0 {
                print_port_list(w, cx.ports, min, max)?;
            }
        }
        w.write_all(b")\n")
    }

    fn record(&mut self, w: &mut dyn Write, cx: &FileCtx, r: &Record) -> io::Result<()> {
        // `out-grepable.c:150–155`: сервис TCP и UDP по порту, остальные протоколы по номеру IP-протокола.
        let service = match r.proto {
            Proto::Tcp => cx.services.tcp(r.port),
            Proto::Udp => cx.services.udp(r.port),
            p => cx.services.oproto(p as u8),
        };
        writeln!(
            w,
            "Timestamp: {}\tHost: {} ()\tPorts: {}/{}/{}//{}//",
            r.timestamp,
            CIp(r.ip),
            r.port,
            status_str(r.status),
            proto_str(r.proto),
            service
        )
    }

    /// `grepable_out_banner` (`src/out-grepable.c:178-202`): без `Timestamp:`, протокола и TTL, сервис это имя
    /// приложения (а не поиск в services).
    fn banner(&mut self, w: &mut dyn Write, _: &FileCtx, b: &BannerRecord) -> io::Result<()> {
        writeln!(
            w,
            "Host: {} ()\tPort: {}\tService: {}\tBanner: {}",
            CIp(b.ip),
            b.port,
            app_name(b.app),
            normalize_string(&b.payload)
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
        if r.proto != Proto::Tcp {
            // `out-unicornscan.c:42–54`: unicornscan знает только TCP, остальное в форме grepable без сервиса.
            return writeln!(
                w,
                "Host: {} ()\tPorts: {}/{}/{}////",
                CIp(r.ip),
                r.port,
                status_str(r.status),
                proto_str(r.proto)
            );
        }
        writeln!(
            w,
            "TCP {}\t{:>16}[{:>5}]\t\tfrom {}  ttl {:<3}",
            status_str(r.status),
            cx.services.tcp(r.port),
            r.port,
            CIp(r.ip),
            r.ttl
        )
    }

    /// `unicornscan_out_banner` (`src/out-unicornscan.c:61-79`): пусто («SYN only - no banner»); заголовок и подвал
    /// файла из одних баннеров всё равно пишутся (конвейер).
    fn banner(&mut self, _: &mut dyn Write, _: &FileCtx, _: &BannerRecord) -> io::Result<()> {
        Ok(())
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
            ip: Ipv4Addr::new(1, 2, 3, 4).into(),
            port,
            proto: Proto::Tcp,
            status: Status::Open,
            reason: 0x12,
            ttl,
            mac: None,
        }
    }

    fn ctx<'a>(sv: &'a ServiceNames, ports: &'a [(u32, u32)]) -> FileCtx<'a> {
        FileCtx {
            now: 1_388_620_800,
            utc_offset_secs: 0,
            scan_started: 1_390_335_802,
            file_opened: 0,
            counts: Counts::default(),
            stylesheet: None,
            ports,
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
