//! Форматы вывода (AGPL-3.0). Порт `out-text.c`, `out-json.c`, `out-ndjson.c`, `out-hostonly.c`, `out-xml.c` и
//! `out-binary.c` masscan © Robert David Graham. Байты сверены с C: пробелы в JSON, `\r\n` в XML, 99-байтовые
//! заголовок и подвал бинарного файла. Форматтер ничего не знает о файлах: он пишет в `&mut dyn Write`, а заголовок,
//! подвал и счётчики ведёт конвейер ([`super::pipeline`]).

use std::io::{self, Write};

use super::grepable::{Grepable, Unicornscan};
use super::record::{Record, Status, civil, proto_str, reason_string, status_str};
use super::services::ServiceNames;

/// `--output-format` и `-o?` (`masscan.h:50–65`, нужное подмножество).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Default,
    Interactive,
    List,
    Json,
    Ndjson,
    Grepable,
    Xml,
    Binary,
    Hostonly,
    Unicornscan,
    None,
}

/// Счётчики записей TCP за файл (`out->counts.tcp`): `<hosts up=…>` `-oX` считает только их (`out-xml.c:55–58`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub open: u64,
    pub closed: u64,
}

/// Контекст заголовка, записи и подвала.
pub struct FileCtx<'a> {
    /// Секунды Unix в момент вызова (`time(0)` C).
    pub now: u64,
    pub utc_offset_secs: i32,
    pub scan_started: u64,
    pub file_opened: u64,
    pub counts: Counts,
    pub stylesheet: Option<&'a str>,
    /// Все диапазоны портов цели со сдвигами протоколов (`masscan->targets.ports`, `massip-port.h:11–25`): строка
    /// `# Ports scanned` заголовка `-oG` режет их по протоколам.
    pub ports: &'a [(u32, u32)],
    pub services: &'a ServiceNames,
}

pub trait Formatter {
    fn header(&mut self, w: &mut dyn Write, cx: &FileCtx) -> io::Result<()>;
    fn record(&mut self, w: &mut dyn Write, cx: &FileCtx, r: &Record) -> io::Result<()>;
    fn footer(&mut self, w: &mut dyn Write, cx: &FileCtx) -> io::Result<()>;
}

/// `None` для `Default`/`Interactive`/`None` (это `null_output` C).
pub fn formatter(f: Format) -> Option<Box<dyn Formatter>> {
    match f {
        Format::List => Some(Box::new(List)),
        Format::Json => Some(Box::new(Json::default())),
        Format::Ndjson => Some(Box::new(Ndjson)),
        Format::Xml => Some(Box::new(Xml)),
        Format::Binary => Some(Box::new(Binary)),
        Format::Hostonly => Some(Box::new(Hostonly)),
        Format::Grepable => Some(Box::new(Grepable)),
        Format::Unicornscan => Some(Box::new(Unicornscan)),
        Format::Default | Format::Interactive | Format::None => None,
    }
}

/// `%u` над `(unsigned)timestamp`.
fn ts_u32(r: &Record) -> u32 {
    r.timestamp as u32
}

/// `%d` над `(int)timestamp`.
fn ts_i32(r: &Record) -> i32 {
    r.timestamp as u32 as i32
}

/// `-oL`, `out-text.c`.
struct List;

impl Formatter for List {
    fn header(&mut self, w: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        w.write_all(b"#masscan\n")
    }
    fn record(&mut self, w: &mut dyn Write, _: &FileCtx, r: &Record) -> io::Result<()> {
        writeln!(
            w,
            "{} {} {} {} {}",
            status_str(r.status),
            proto_str(r.proto),
            r.port,
            r.ip,
            ts_u32(r)
        )
    }
    fn footer(&mut self, w: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        w.write_all(b"# end\n")
    }
}

/// `-oJ`, `out-json.c`: запятая ставится перед каждой записью, кроме первой.
#[derive(Default)]
struct Json {
    seen: bool,
}

impl Formatter for Json {
    fn header(&mut self, w: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        w.write_all(b"[\n")
    }
    fn record(&mut self, w: &mut dyn Write, _: &FileCtx, r: &Record) -> io::Result<()> {
        if self.seen {
            w.write_all(b",\n")?;
        }
        self.seen = true;
        writeln!(
            w,
            "{{   \"ip\": \"{}\",   \"timestamp\": \"{}\", \"ports\": [ {{\"port\": {}, \"proto\": \"{}\", \
             \"status\": \"{}\", \"reason\": \"{}\", \"ttl\": {}}} ] }}",
            r.ip,
            ts_i32(r),
            r.port,
            proto_str(r.proto),
            status_str(r.status),
            reason_string(r.reason),
            r.ttl
        )
    }
    fn footer(&mut self, w: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        w.write_all(b"]\n")
    }
}

/// `-oD`, `out-ndjson.c`: без заголовка и подвала.
struct Ndjson;

impl Formatter for Ndjson {
    fn header(&mut self, _: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        Ok(())
    }
    fn record(&mut self, w: &mut dyn Write, _: &FileCtx, r: &Record) -> io::Result<()> {
        writeln!(
            w,
            "{{\"ip\":\"{}\",\"timestamp\":\"{}\",\"port\":{},\"proto\":\"{}\",\"rec_type\":\"status\",\
             \"data\":{{\"status\":\"{}\",\"reason\":\"{}\",\"ttl\":{}}}}}",
            r.ip,
            ts_i32(r),
            r.port,
            proto_str(r.proto),
            status_str(r.status),
            reason_string(r.reason),
            r.ttl
        )
    }
    fn footer(&mut self, _: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        Ok(())
    }
}

/// `-oH`, `out-hostonly.c`: адрес на каждую запись.
struct Hostonly;

impl Formatter for Hostonly {
    fn header(&mut self, _: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        Ok(())
    }
    fn record(&mut self, w: &mut dyn Write, _: &FileCtx, r: &Record) -> io::Result<()> {
        writeln!(w, "{}", r.ip)
    }
    fn footer(&mut self, _: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        Ok(())
    }
}

/// `-oX`, `out-xml.c`: все концы строк `\r\n`, на любой ОС.
struct Xml;

impl Formatter for Xml {
    fn header(&mut self, w: &mut dyn Write, cx: &FileCtx) -> io::Result<()> {
        w.write_all(b"<?xml version=\"1.0\"?>\r\n<!-- masscan v1.0 scan -->\r\n")?;
        if let Some(s) = cx.stylesheet.filter(|s| !s.is_empty()) {
            write!(w, "<?xml-stylesheet href=\"{s}\" type=\"text/xsl\"?>\r\n")?;
        }
        write!(
            w,
            "<nmaprun scanner=\"masscan\" start=\"{}\" version=\"1.0-BETA\"  xmloutputversion=\"1.03\">\r\n\
             <scaninfo type=\"syn\" protocol=\"tcp\" />\r\n",
            cx.now as u32
        )
    }
    fn record(&mut self, w: &mut dyn Write, _: &FileCtx, r: &Record) -> io::Result<()> {
        write!(
            w,
            "<host endtime=\"{}\"><address addr=\"{}\" addrtype=\"ipv4\"/><ports>\
             <port protocol=\"{}\" portid=\"{}\"><state state=\"{}\" reason=\"{}\" reason_ttl=\"{}\"/>\
             </port></ports></host>\r\n",
            ts_u32(r),
            r.ip,
            proto_str(r.proto),
            r.port,
            status_str(r.status),
            reason_string(r.reason),
            r.ttl
        )
    }
    fn footer(&mut self, w: &mut dyn Write, cx: &FileCtx) -> io::Result<()> {
        let local = cx.now as i64 + i64::from(cx.utc_offset_secs);
        let (y, mo, d, h, mi, s, _) = civil(local);
        write!(
            w,
            "<runstats>\r\n<finished time=\"{}\" timestr=\"{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}\" \
             elapsed=\"{}\" />\r\n<hosts up=\"{}\" down=\"{}\" total=\"{}\" />\r\n</runstats>\r\n</nmaprun>\r\n",
            cx.now as u32,
            cx.now.saturating_sub(cx.file_opened) as u32,
            cx.counts.open,
            cx.counts.closed,
            cx.counts.open + cx.counts.closed
        )
    }
}

/// Длина заголовка и подвала бинарного файла (`2 + 'a'`).
const BINARY_BLOCK: usize = 99;

/// `-oB`, `out-binary.c`: всё в сетевом порядке байт.
struct Binary;

impl Formatter for Binary {
    fn header(&mut self, w: &mut dyn Write, cx: &FileCtx) -> io::Result<()> {
        let mut buf = [0u8; BINARY_BLOCK];
        let text = format!("masscan/1.1\ns:{}\n", cx.scan_started as u32);
        buf[..text.len()].copy_from_slice(text.as_bytes());
        w.write_all(&buf)
    }
    fn record(&mut self, w: &mut dyn Write, _: &FileCtx, r: &Record) -> io::Result<()> {
        let mut b = [0u8; 15];
        // `out-binary.c:154–211`: `Out_Open2` 6, `Out_Closed2` 7, `Out_Arp2` 8 (`out-record.h:8–10`); MAC не пишется.
        b[0] = match r.status {
            Status::Open => 6,
            Status::Closed => 7,
            Status::Arp => 8,
        };
        b[1] = 13;
        b[2..6].copy_from_slice(&ts_u32(r).to_be_bytes());
        b[6..10].copy_from_slice(&r.ip.octets());
        b[10] = r.proto as u8;
        b[11..13].copy_from_slice(&r.port.to_be_bytes());
        b[13] = r.reason;
        b[14] = r.ttl;
        w.write_all(&b)
    }
    fn footer(&mut self, w: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        let mut buf = [0u8; BINARY_BLOCK];
        buf[..11].copy_from_slice(b"masscan/1.1");
        w.write_all(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::record::Proto;
    use crate::output::services;
    use std::net::Ipv4Addr;

    fn open_rec() -> Record {
        Record {
            timestamp: 1_700_000_000,
            ip: Ipv4Addr::new(1, 2, 3, 4),
            port: 80,
            proto: Proto::Tcp,
            status: Status::Open,
            reason: 0x12,
            ttl: 57,
            mac: None,
        }
    }

    fn closed_rec() -> Record {
        Record {
            timestamp: 1_700_000_000,
            ip: Ipv4Addr::new(10, 0, 0, 255),
            port: 443,
            proto: Proto::Tcp,
            status: Status::Closed,
            reason: 0x14,
            ttl: 64,
            mac: None,
        }
    }

    fn cx<'a>(services: &'a ServiceNames) -> FileCtx<'a> {
        FileCtx {
            now: 1_700_000_005,
            utc_offset_secs: 0,
            scan_started: 1_700_000_000,
            file_opened: 1_700_000_000,
            counts: Counts::default(),
            stylesheet: None,
            ports: &[],
            services,
        }
    }

    /// Заголовок, записи, подвал одним куском.
    fn render(f: Format, cx: &FileCtx, recs: &[Record]) -> Vec<u8> {
        let mut fm = formatter(f).expect("formatter");
        let mut out = Vec::new();
        fm.header(&mut out, cx).unwrap();
        for r in recs {
            fm.record(&mut out, cx, r).unwrap();
        }
        fm.footer(&mut out, cx).unwrap();
        out
    }

    fn s(b: &[u8]) -> String {
        String::from_utf8(b.to_vec()).unwrap()
    }

    #[test]
    fn list_bytes_match_c() {
        let sv = services::empty();
        let out = render(Format::List, &cx(&sv), &[open_rec(), closed_rec()]);
        assert_eq!(
            s(&out),
            "#masscan\nopen tcp 80 1.2.3.4 1700000000\nclosed tcp 443 10.0.0.255 1700000000\n# end\n"
        );
    }

    #[test]
    fn json_prepends_comma_from_the_second_record() {
        let sv = services::empty();
        let out = render(Format::Json, &cx(&sv), &[open_rec(), closed_rec()]);
        let expect = concat!(
            "[\n",
            "{   \"ip\": \"1.2.3.4\",   \"timestamp\": \"1700000000\", \"ports\": [ {\"port\": 80, \"proto\": \"tcp\", \"status\": \"open\", \"reason\": \"syn-ack\", \"ttl\": 57} ] }\n",
            ",\n",
            "{   \"ip\": \"10.0.0.255\",   \"timestamp\": \"1700000000\", \"ports\": [ {\"port\": 443, \"proto\": \"tcp\", \"status\": \"closed\", \"reason\": \"rst-ack\", \"ttl\": 64} ] }\n",
            "]\n"
        );
        assert_eq!(s(&out), expect);
    }

    #[test]
    fn ndjson_is_compact_without_header() {
        let sv = services::empty();
        let out = render(Format::Ndjson, &cx(&sv), &[open_rec()]);
        assert_eq!(
            s(&out),
            "{\"ip\":\"1.2.3.4\",\"timestamp\":\"1700000000\",\"port\":80,\"proto\":\"tcp\",\"rec_type\":\"status\",\"data\":{\"status\":\"open\",\"reason\":\"syn-ack\",\"ttl\":57}}\n"
        );
    }

    #[test]
    fn hostonly_prints_ip_per_record() {
        let sv = services::empty();
        let out = render(Format::Hostonly, &cx(&sv), &[open_rec(), closed_rec()]);
        assert_eq!(s(&out), "1.2.3.4\n10.0.0.255\n");
    }

    #[test]
    fn xml_uses_crlf_and_c_header() {
        let sv = services::empty();
        let mut c = cx(&sv);
        let mut fm = formatter(Format::Xml).unwrap();
        let mut out = Vec::new();
        fm.header(&mut out, &c).unwrap();
        assert_eq!(
            s(&out),
            "<?xml version=\"1.0\"?>\r\n<!-- masscan v1.0 scan -->\r\n\
             <nmaprun scanner=\"masscan\" start=\"1700000005\" version=\"1.0-BETA\"  xmloutputversion=\"1.03\">\r\n\
             <scaninfo type=\"syn\" protocol=\"tcp\" />\r\n"
        );
        c.stylesheet = Some("http://nmap.org/svn/docs/nmap.xsl");
        let mut styled = Vec::new();
        fm.header(&mut styled, &c).unwrap();
        assert!(s(&styled).contains(
            "<!-- masscan v1.0 scan -->\r\n<?xml-stylesheet href=\"http://nmap.org/svn/docs/nmap.xsl\" type=\"text/xsl\"?>\r\n<nmaprun"
        ));
        let mut rec = Vec::new();
        fm.record(&mut rec, &c, &open_rec()).unwrap();
        assert_eq!(
            s(&rec),
            "<host endtime=\"1700000000\"><address addr=\"1.2.3.4\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\" reason=\"syn-ack\" reason_ttl=\"57\"/></port></ports></host>\r\n"
        );
        c.now = 1_700_000_100;
        c.utc_offset_secs = 3600;
        c.counts = Counts { open: 1, closed: 1 };
        let mut foot = Vec::new();
        fm.footer(&mut foot, &c).unwrap();
        assert_eq!(
            s(&foot),
            "<runstats>\r\n<finished time=\"1700000100\" timestr=\"2023-11-14 23:15:00\" elapsed=\"100\" />\r\n\
             <hosts up=\"1\" down=\"1\" total=\"2\" />\r\n</runstats>\r\n</nmaprun>\r\n"
        );
    }

    #[test]
    fn binary_header_record_footer() {
        let sv = services::empty();
        let c = cx(&sv);
        let out = render(Format::Binary, &c, &[open_rec(), closed_rec()]);
        assert_eq!(out.len(), 99 + 15 + 15 + 99);
        let mut head = b"masscan/1.1\ns:1700000000\n".to_vec();
        head.resize(99, 0);
        assert_eq!(out[..99], head[..]);
        let ts = 1_700_000_000u32.to_be_bytes();
        let mut rec = vec![6, 13];
        rec.extend_from_slice(&ts);
        rec.extend_from_slice(&[1, 2, 3, 4, 6, 0, 80, 0x12, 57]);
        assert_eq!(out[99..114], rec[..]);
        let mut closed = vec![7, 13];
        closed.extend_from_slice(&ts);
        closed.extend_from_slice(&[10, 0, 0, 255, 6, 0x01, 0xBB, 0x14, 64]);
        assert_eq!(out[114..129], closed[..]);
        let mut foot = b"masscan/1.1".to_vec();
        foot.resize(99, 0);
        assert_eq!(out[129..], foot[..]);
    }

    /// Записи не-TCP; ожидаемые строки сняты с C `masscan 8e6b3b0 --readscan` на файле `-oB` с такими же записями
    /// (UDP, SCTP, ICMP: типы 6/7). Для ARP C `--readscan` не читает тип 8, поэтому его строки взяты из исходников
    /// (`output.c:109–116` `status_string` = `up`, `output.c:75–86` `name_from_ip_proto(0)` = `arp`).
    fn non_tcp_recs() -> Vec<Record> {
        let t: u64 = 1_700_000_000;
        let mk = |dt: u64, ip: u8, port: u16, proto, status, ttl: u8| Record {
            timestamp: t + dt,
            ip: Ipv4Addr::new(192, 0, 2, ip),
            port,
            proto,
            status,
            reason: 0,
            ttl,
            mac: None,
        };
        vec![
            mk(0, 1, 53, Proto::Udp, Status::Open, 64),
            mk(1, 2, 5353, Proto::Udp, Status::Closed, 64),
            mk(2, 3, 2905, Proto::Sctp, Status::Open, 57),
            mk(3, 4, 0, Proto::Icmp, Status::Open, 60),
            Record {
                mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                ..mk(4, 9, 0, Proto::Arp, Status::Arp, 0)
            },
        ]
    }

    fn non_tcp_services() -> ServiceNames {
        ServiceNames::parse("domain 53/udp\nmdns 5354/udp\n")
            .with_protocols("ip\t0\tIP\nicmp\t1\tICMP\nsctp\t132\tSCTP\n")
    }

    #[test]
    fn non_tcp_records_render_in_all_formats_like_c() {
        let sv = non_tcp_services();
        let c = cx(&sv);
        let recs = non_tcp_recs();
        assert_eq!(
            s(&render(Format::List, &c, &recs)),
            "#masscan\n\
             open udp 53 192.0.2.1 1700000000\n\
             closed udp 5353 192.0.2.2 1700000001\n\
             open sctp 2905 192.0.2.3 1700000002\n\
             open icmp 0 192.0.2.4 1700000003\n\
             up arp 0 192.0.2.9 1700000004\n\
             # end\n"
        );
        assert_eq!(
            s(&render(Format::Json, &c, &recs)),
            concat!(
                "[\n",
                "{   \"ip\": \"192.0.2.1\",   \"timestamp\": \"1700000000\", \"ports\": [ {\"port\": 53, \"proto\": \"udp\", \"status\": \"open\", \"reason\": \"none\", \"ttl\": 64} ] }\n",
                ",\n",
                "{   \"ip\": \"192.0.2.2\",   \"timestamp\": \"1700000001\", \"ports\": [ {\"port\": 5353, \"proto\": \"udp\", \"status\": \"closed\", \"reason\": \"none\", \"ttl\": 64} ] }\n",
                ",\n",
                "{   \"ip\": \"192.0.2.3\",   \"timestamp\": \"1700000002\", \"ports\": [ {\"port\": 2905, \"proto\": \"sctp\", \"status\": \"open\", \"reason\": \"none\", \"ttl\": 57} ] }\n",
                ",\n",
                "{   \"ip\": \"192.0.2.4\",   \"timestamp\": \"1700000003\", \"ports\": [ {\"port\": 0, \"proto\": \"icmp\", \"status\": \"open\", \"reason\": \"none\", \"ttl\": 60} ] }\n",
                ",\n",
                "{   \"ip\": \"192.0.2.9\",   \"timestamp\": \"1700000004\", \"ports\": [ {\"port\": 0, \"proto\": \"arp\", \"status\": \"up\", \"reason\": \"none\", \"ttl\": 0} ] }\n",
                "]\n"
            )
        );
        assert_eq!(
            s(&render(Format::Ndjson, &c, &recs)),
            concat!(
                "{\"ip\":\"192.0.2.1\",\"timestamp\":\"1700000000\",\"port\":53,\"proto\":\"udp\",\"rec_type\":\"status\",\"data\":{\"status\":\"open\",\"reason\":\"none\",\"ttl\":64}}\n",
                "{\"ip\":\"192.0.2.2\",\"timestamp\":\"1700000001\",\"port\":5353,\"proto\":\"udp\",\"rec_type\":\"status\",\"data\":{\"status\":\"closed\",\"reason\":\"none\",\"ttl\":64}}\n",
                "{\"ip\":\"192.0.2.3\",\"timestamp\":\"1700000002\",\"port\":2905,\"proto\":\"sctp\",\"rec_type\":\"status\",\"data\":{\"status\":\"open\",\"reason\":\"none\",\"ttl\":57}}\n",
                "{\"ip\":\"192.0.2.4\",\"timestamp\":\"1700000003\",\"port\":0,\"proto\":\"icmp\",\"rec_type\":\"status\",\"data\":{\"status\":\"open\",\"reason\":\"none\",\"ttl\":60}}\n",
                "{\"ip\":\"192.0.2.9\",\"timestamp\":\"1700000004\",\"port\":0,\"proto\":\"arp\",\"rec_type\":\"status\",\"data\":{\"status\":\"up\",\"reason\":\"none\",\"ttl\":0}}\n"
            )
        );
        let xml = s(&render(Format::Xml, &c, &recs));
        for expect in [
            "<host endtime=\"1700000000\"><address addr=\"192.0.2.1\" addrtype=\"ipv4\"/><ports><port protocol=\"udp\" portid=\"53\"><state state=\"open\" reason=\"none\" reason_ttl=\"64\"/></port></ports></host>\r\n",
            "<host endtime=\"1700000001\"><address addr=\"192.0.2.2\" addrtype=\"ipv4\"/><ports><port protocol=\"udp\" portid=\"5353\"><state state=\"closed\" reason=\"none\" reason_ttl=\"64\"/></port></ports></host>\r\n",
            "<host endtime=\"1700000002\"><address addr=\"192.0.2.3\" addrtype=\"ipv4\"/><ports><port protocol=\"sctp\" portid=\"2905\"><state state=\"open\" reason=\"none\" reason_ttl=\"57\"/></port></ports></host>\r\n",
            "<host endtime=\"1700000003\"><address addr=\"192.0.2.4\" addrtype=\"ipv4\"/><ports><port protocol=\"icmp\" portid=\"0\"><state state=\"open\" reason=\"none\" reason_ttl=\"60\"/></port></ports></host>\r\n",
            "<host endtime=\"1700000004\"><address addr=\"192.0.2.9\" addrtype=\"ipv4\"/><ports><port protocol=\"arp\" portid=\"0\"><state state=\"up\" reason=\"none\" reason_ttl=\"0\"/></port></ports></host>\r\n",
        ] {
            assert!(xml.contains(expect), "{expect}\n{xml}");
        }
        // `<scaninfo type="syn" protocol="tcp" />` остаётся как в C (`out-xml.c:26–27`), даже для не-TCP файла.
        assert!(xml.contains("<scaninfo type=\"syn\" protocol=\"tcp\" />\r\n"));
        assert_eq!(
            s(&render(Format::Hostonly, &c, &recs)),
            "192.0.2.1\n192.0.2.2\n192.0.2.3\n192.0.2.4\n192.0.2.9\n"
        );
        // `-oG`: сервис UDP из services, остальное из protocols (`out-grepable.c:150–155`).
        let g = s(&render(Format::Grepable, &c, &recs));
        for expect in [
            "Timestamp: 1700000000\tHost: 192.0.2.1 ()\tPorts: 53/open/udp//domain//\n",
            "Timestamp: 1700000001\tHost: 192.0.2.2 ()\tPorts: 5353/closed/udp//unknown//\n",
            "Timestamp: 1700000002\tHost: 192.0.2.3 ()\tPorts: 2905/open/sctp//sctp//\n",
            "Timestamp: 1700000003\tHost: 192.0.2.4 ()\tPorts: 0/open/icmp//icmp//\n",
            "Timestamp: 1700000004\tHost: 192.0.2.9 ()\tPorts: 0/up/arp//ip//\n",
        ] {
            assert!(g.contains(expect), "{expect}\n{g}");
        }
        // `-oU`: не-TCP в формате grepable без сервиса (`out-unicornscan.c:42–54`).
        assert_eq!(
            s(&render(Format::Unicornscan, &c, &recs)),
            "#masscan\n\
             Host: 192.0.2.1 ()\tPorts: 53/open/udp////\n\
             Host: 192.0.2.2 ()\tPorts: 5353/closed/udp////\n\
             Host: 192.0.2.3 ()\tPorts: 2905/open/sctp////\n\
             Host: 192.0.2.4 ()\tPorts: 0/open/icmp////\n\
             Host: 192.0.2.9 ()\tPorts: 0/up/arp////\n\
             # end\n"
        );
        // `-oB`: тип 6 открыт, 7 закрыт, 8 ARP; байт протокола `ip_proto` (`out-binary.c:154–211`); MAC в запись
        // не попадает, длина 15.
        let bin = render(Format::Binary, &c, &recs);
        assert_eq!(bin.len(), 99 + 5 * 15 + 99);
        let body = |i: usize| &bin[99 + 15 * i..99 + 15 * (i + 1)];
        let ts = |dt: u32| (1_700_000_000u32 + dt).to_be_bytes();
        let mk = |ty: u8, dt: u32, ip: u8, proto: u8, port: u16, ttl: u8| {
            let mut v = vec![ty, 13];
            v.extend_from_slice(&ts(dt));
            v.extend_from_slice(&[192, 0, 2, ip, proto]);
            v.extend_from_slice(&port.to_be_bytes());
            v.extend_from_slice(&[0, ttl]);
            v
        };
        assert_eq!(body(0), &mk(6, 0, 1, 17, 53, 64)[..]);
        assert_eq!(body(1), &mk(7, 1, 2, 17, 5353, 64)[..]);
        assert_eq!(body(2), &mk(6, 2, 3, 132, 2905, 57)[..]);
        assert_eq!(body(3), &mk(6, 3, 4, 1, 0, 60)[..]);
        assert_eq!(body(4), &mk(8, 4, 9, 0, 0, 0)[..]);
    }

    #[test]
    fn grepable_header_lists_every_protocol_with_c_quirks() {
        // Снято с C: `-p T:80,U:53,S:2905,U:1000-1002,O:47,I:0` (`out-grepable.c:41–62`): диапазоны печатаются
        // со сдвигом (65589, 133977, 196911), запятая зависит от индекса в общем списке (I:0 = 196608 стоит
        // между SCTP и PROTOCOLS и не печатается нигде, но оставляет «хвостовую запятую» после SCTP).
        let sv = services::empty();
        let ports = [
            (80, 80),
            (65589, 65589),
            (66536, 66538),
            (133977, 133977),
            (196608, 196608),
            (196911, 196911),
        ];
        let mut c = cx(&sv);
        c.ports = &ports;
        let head = s(&{
            let mut out = Vec::new();
            formatter(Format::Grepable)
                .unwrap()
                .header(&mut out, &c)
                .unwrap();
            out
        });
        assert!(
            head.ends_with(
                "# Ports scanned: TCP(1;80-80,) UDP(4;65589-65589,66536-66538,) SCTP(1;133977-133977,) PROTOCOLS(1;196911-196911)\n"
            ),
            "{head}"
        );
        // `-p 80,U:53`: после UDP больше ничего нет, запятой нет.
        let ports = [(80, 80), (65589, 65589)];
        c.ports = &ports;
        let mut out = Vec::new();
        formatter(Format::Grepable)
            .unwrap()
            .header(&mut out, &c)
            .unwrap();
        assert!(s(&out).ends_with(
            "# Ports scanned: TCP(1;80-80,) UDP(1;65589-65589) SCTP(0;) PROTOCOLS(0;)\n"
        ));
    }

    #[test]
    fn proto_names_match_name_from_ip_proto() {
        for (p, name, num) in [
            (Proto::Arp, "arp", 0u8),
            (Proto::Icmp, "icmp", 1),
            (Proto::Tcp, "tcp", 6),
            (Proto::Udp, "udp", 17),
            (Proto::Sctp, "sctp", 132),
        ] {
            assert_eq!(proto_str(p), name);
            assert_eq!(p as u8, num);
            assert_eq!(Proto::from_ip_proto(num), Some(p));
        }
        assert_eq!(Proto::from_ip_proto(47), None);
    }

    #[test]
    fn null_formats_have_no_formatter() {
        for f in [Format::Default, Format::Interactive, Format::None] {
            assert!(formatter(f).is_none());
        }
    }

    #[test]
    fn edge_values_render_like_c() {
        let sv = services::empty();
        let c = cx(&sv);
        let lo = Record {
            timestamp: 4_294_967_296 + 5,
            ip: Ipv4Addr::new(0, 0, 0, 0),
            port: 0,
            proto: Proto::Tcp,
            status: Status::Open,
            reason: 0,
            ttl: 0,
            mac: None,
        };
        let hi = Record {
            timestamp: 4_294_967_296 + 5,
            ip: Ipv4Addr::new(255, 255, 255, 255),
            port: 65535,
            proto: Proto::Tcp,
            status: Status::Closed,
            reason: 0xFF,
            ttl: 255,
            mac: None,
        };
        let list = s(&render(Format::List, &c, &[lo, hi]));
        assert!(list.contains("open tcp 0 0.0.0.0 5\n"));
        assert!(list.contains("closed tcp 65535 255.255.255.255 5\n"));
        let json = s(&render(Format::Json, &c, &[lo, hi]));
        assert!(json.contains("\"timestamp\": \"5\", \"ports\": [ {\"port\": 0, \"proto\": \"tcp\", \"status\": \"open\", \"reason\": \"none\", \"ttl\": 0}"));
        assert!(json.contains("\"port\": 65535, \"proto\": \"tcp\", \"status\": \"closed\", \"reason\": \"fin-syn-rst-psh-ack-urg-ece-cwr\", \"ttl\": 255}"));
        let xml = s(&render(Format::Xml, &c, &[lo, hi]));
        assert!(xml.contains("<host endtime=\"5\">"));
        assert!(
            xml.contains("portid=\"0\"><state state=\"open\" reason=\"none\" reason_ttl=\"0\"/>")
        );
        assert!(xml.contains("portid=\"65535\"><state state=\"closed\" reason=\"fin-syn-rst-psh-ack-urg-ece-cwr\" reason_ttl=\"255\"/>"));
        let bin = render(Format::Binary, &c, &[lo, hi]);
        assert_eq!(bin[99 + 2..99 + 6], 5u32.to_be_bytes());
        assert_eq!(bin[99 + 11..99 + 15], [0, 0, 0, 0]);
        assert_eq!(bin[114 + 11..114 + 15], [0xFF, 0xFF, 0xFF, 255]);
    }
}
