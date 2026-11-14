//! Форматы вывода (AGPL-3.0). Порт `out-text.c`, `out-json.c`, `out-ndjson.c`, `out-hostonly.c`, `out-xml.c`,
//! `out-binary.c` и `out-certs.c` masscan © Robert David Graham. Байты сверены с C: пробелы в JSON, `\r\n` в XML,
//! 99-байтовые заголовок и подвал бинарного файла. Форматтер ничего не знает о файлах: он пишет в `&mut dyn Write`, а
//! заголовок, подвал и счётчики ведёт конвейер ([`super::pipeline`]). У каждого формата две записи: статуса
//! ([`Formatter::record`], `*_out_status`) и баннера ([`Formatter::banner`], `*_out_banner`).

use std::io::{self, Write};
use std::net::IpAddr;

use super::grepable::{Grepable, Unicornscan};
use super::record::{
    CIp, Record, Status, civil, ip_proto_name, proto_str, reason_string, status_str,
};
use super::services::ServiceNames;
use rmasscan_proto::{BannerRecord, app_name, normalize_json_string, normalize_string};

/// `--output-format` и `-o?` (`masscan.h:50–65`, нужное подмножество; у `Certs` буквы `-o` нет, `main-conf.c:1701`).
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
    Certs,
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
    /// Запись баннера (`out->funcs->banner`, `src/output.c:952`). Время берётся из записи, а не из `cx.now`.
    fn banner(&mut self, w: &mut dyn Write, cx: &FileCtx, b: &BannerRecord) -> io::Result<()>;
    fn footer(&mut self, w: &mut dyn Write, cx: &FileCtx) -> io::Result<()>;
    /// `true`, если запись баннера идёт в stdout процесса, а не в файл формата: так только у `certs`, который
    /// печатает PEM через `printf` (`src/out-certs.c:72-79`). Заголовок, подвал и flush остаются у файла.
    fn banner_to_stdout(&self) -> bool {
        false
    }
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
        Format::Certs => Some(Box::new(Certs)),
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

/// `name_from_ip_version` (`output.c:89-96`).
fn addrtype(ip: IpAddr) -> &'static str {
    if ip.is_ipv6() { "ipv6" } else { "ipv4" }
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
            CIp(r.ip),
            ts_u32(r)
        )
    }
    /// `text_out_banner` (`src/out-text.c:51-73`): `"%s %s %u %s %u %s %s\n"`, TTL не печатается.
    fn banner(&mut self, w: &mut dyn Write, _: &FileCtx, b: &BannerRecord) -> io::Result<()> {
        writeln!(
            w,
            "banner {} {} {} {} {} {}",
            ip_proto_name(b.ip_proto),
            b.port,
            CIp(b.ip),
            b.timestamp as u32,
            app_name(b.app),
            normalize_string(&b.payload)
        )
    }
    fn footer(&mut self, w: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        w.write_all(b"# end\n")
    }
}

/// `-oJ`, `out-json.c`: запятая ставится перед каждой записью, кроме первой, статуса или баннера.
#[derive(Default)]
struct Json {
    seen: bool,
}

impl Json {
    /// `is_first_record_seen` (`src/out-json.c:42-45`, `:116-119`): `,\n` перед каждой записью, кроме первой.
    fn separate(&mut self, w: &mut dyn Write) -> io::Result<()> {
        if self.seen {
            w.write_all(b",\n")?;
        }
        self.seen = true;
        Ok(())
    }
}

impl Formatter for Json {
    fn header(&mut self, w: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        w.write_all(b"[\n")
    }
    fn record(&mut self, w: &mut dyn Write, _: &FileCtx, r: &Record) -> io::Result<()> {
        self.separate(w)?;
        writeln!(
            w,
            "{{   \"ip\": \"{}\",   \"timestamp\": \"{}\", \"ports\": [ {{\"port\": {}, \"proto\": \"{}\", \
             \"status\": \"{}\", \"reason\": \"{}\", \"ttl\": {}}} ] }}",
            CIp(r.ip),
            ts_i32(r),
            r.port,
            proto_str(r.proto),
            status_str(r.status),
            reason_string(r.reason),
            r.ttl
        )
    }
    /// `json_out_banner` (`src/out-json.c:101-134`): флаг первой записи общий с записью статуса, после `service`
    /// стоит `} } ]` (у статуса `} ]`), TTL не печатается.
    fn banner(&mut self, w: &mut dyn Write, _: &FileCtx, b: &BannerRecord) -> io::Result<()> {
        self.separate(w)?;
        writeln!(
            w,
            "{{   \"ip\": \"{}\",   \"timestamp\": \"{}\", \"ports\": [ {{\"port\": {}, \"proto\": \"{}\", \
             \"service\": {{\"name\": \"{}\", \"banner\": \"{}\"}} }} ] }}",
            CIp(b.ip),
            b.timestamp as u32 as i32,
            b.port,
            ip_proto_name(b.ip_proto),
            app_name(b.app),
            normalize_json_string(&b.payload)
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
            CIp(r.ip),
            ts_i32(r),
            r.port,
            proto_str(r.proto),
            status_str(r.status),
            reason_string(r.reason),
            r.ttl
        )
    }
    /// `ndjson_out_banner` (`src/out-ndjson.c:97-153`): `normalize_ndjson_string` (`:64-93`) побайтово равен
    /// `normalize_json_string`, TTL не печатается.
    fn banner(&mut self, w: &mut dyn Write, _: &FileCtx, b: &BannerRecord) -> io::Result<()> {
        writeln!(
            w,
            "{{\"ip\":\"{}\",\"timestamp\":\"{}\",\"port\":{},\"proto\":\"{}\",\"rec_type\":\"banner\",\
             \"data\":{{\"service_name\":\"{}\",\"banner\":\"{}\"}}}}",
            CIp(b.ip),
            b.timestamp as u32 as i32,
            b.port,
            ip_proto_name(b.ip_proto),
            app_name(b.app),
            normalize_json_string(&b.payload)
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
        writeln!(w, "{}", CIp(r.ip))
    }
    /// `hostonly_out_banner` (`src/out-hostonly.c:45-65`): ещё одна строка адреса.
    fn banner(&mut self, w: &mut dyn Write, _: &FileCtx, b: &BannerRecord) -> io::Result<()> {
        writeln!(w, "{}", CIp(b.ip))
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
            "<host endtime=\"{}\"><address addr=\"{}\" addrtype=\"{}\"/><ports>\
             <port protocol=\"{}\" portid=\"{}\"><state state=\"{}\" reason=\"{}\" reason_ttl=\"{}\"/>\
             </port></ports></host>\r\n",
            ts_u32(r),
            CIp(r.ip),
            addrtype(r.ip),
            proto_str(r.proto),
            r.port,
            status_str(r.status),
            reason_string(r.reason),
            r.ttl
        )
    }
    /// `xml_out_banner` (`src/out-xml.c:95-132`): `reason` выбирается `switch (proto)` по номеру ПРИЛОЖЕНИЯ
    /// (`:106-109`; в C, видимо, имелся в виду `ip_proto`): app 6 (`dns-ver`) даёт `syn-ack`, всё остальное, в том
    /// числе любой TCP-баннер, `response`. У `<state … />` пробел перед `/>` (у записи статуса его нет).
    fn banner(&mut self, w: &mut dyn Write, _: &FileCtx, b: &BannerRecord) -> io::Result<()> {
        let reason = if b.app == 6 { "syn-ack" } else { "response" };
        write!(
            w,
            "<host endtime=\"{}\"><address addr=\"{}\" addrtype=\"{}\"/><ports>\
             <port protocol=\"{}\" portid=\"{}\"><state state=\"open\" reason=\"{}\" reason_ttl=\"{}\" />\
             <service name=\"{}\" banner=\"{}\"></service></port></ports></host>\r\n",
            b.timestamp as u32,
            CIp(b.ip),
            addrtype(b.ip),
            ip_proto_name(b.ip_proto),
            b.port,
            reason,
            b.ttl,
            app_name(b.app),
            normalize_string(&b.payload)
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
        let a = match r.ip {
            IpAddr::V4(a) => a,
            IpAddr::V6(a) => {
                // `binary_out_status_ipv6` (`out-binary.c:103-149`): `Out_Open6` 10, `Out_Closed6` 11, `Out_Arp6` 12
                // (`out-record.h:13-15`), длина 26, затем время, протокол, порт, reason, TTL, версия 6, `hi` и `lo`.
                let mut b = [0u8; 28];
                b[0] = match r.status {
                    Status::Open => 10,
                    Status::Closed => 11,
                    Status::Arp => 12,
                };
                b[1] = 26;
                b[2..6].copy_from_slice(&ts_u32(r).to_be_bytes());
                b[6] = r.proto as u8;
                b[7..9].copy_from_slice(&r.port.to_be_bytes());
                b[9] = r.reason;
                b[10] = r.ttl;
                b[11] = 6;
                b[12..28].copy_from_slice(&a.octets());
                return w.write_all(&b);
            }
        };
        let mut b = [0u8; 15];
        // `out-binary.c:154–211`: `Out_Open2` 6, `Out_Closed2` 7, `Out_Arp2` 8 (`out-record.h:8–10`); MAC не пишется.
        b[0] = match r.status {
            Status::Open => 6,
            Status::Closed => 7,
            Status::Arp => 8,
        };
        b[1] = 13;
        b[2..6].copy_from_slice(&ts_u32(r).to_be_bytes());
        b[6..10].copy_from_slice(&a.octets());
        b[10] = r.proto as u8;
        b[11..13].copy_from_slice(&r.port.to_be_bytes());
        b[13] = r.reason;
        b[14] = r.ttl;
        w.write_all(&b)
    }
    /// `binary_out_banner` (`src/out-binary.c:293-355`, тип 9 `Out_Banner9`) и `binary_out_banner_ipv6` (`:216-289`,
    /// тип 13 `Out_Banner6`, `src/out-record.h`). Длина записи `n + 14` (IPv6 `n + 27`): один байт, пока
    /// `n < 128 - заголовок`, иначе два, `((n+h)>>7)|0x80` и `(n+h)&0x7F`; от `n >= 128*128 - заголовок` запись молча
    /// не пишется (`:232-233`, `:313-314`), хотя ленивый заголовок файла уже записан. Время это младшие 32 бита,
    /// полезная нагрузка сырая.
    fn banner(&mut self, w: &mut dyn Write, _: &FileCtx, b: &BannerRecord) -> io::Result<()> {
        let (ty, head) = match b.ip {
            IpAddr::V4(_) => (9u8, 14usize),
            IpAddr::V6(_) => (13, 14 + 13),
        };
        let n = b.payload.len();
        if n >= 128 * 128 - head {
            return Ok(());
        }
        let len = n + head;
        let mut rec = Vec::with_capacity(3 + len);
        rec.push(ty);
        if n < 128 - head {
            rec.push(len as u8);
        } else {
            rec.push((len >> 7) as u8 | 0x80);
            rec.push((len & 0x7F) as u8);
        }
        rec.extend_from_slice(&(b.timestamp as u32).to_be_bytes());
        match b.ip {
            IpAddr::V4(a) => {
                // `:324-346`: время, адрес, протокол, порт, app, TTL.
                rec.extend_from_slice(&a.octets());
                rec.push(b.ip_proto);
                rec.extend_from_slice(&b.port.to_be_bytes());
                rec.extend_from_slice(&b.app.to_be_bytes());
                rec.push(b.ttl);
            }
            IpAddr::V6(a) => {
                // `:243-280`: время, протокол, порт, app, TTL, версия 6, `hi`, `lo`.
                rec.push(b.ip_proto);
                rec.extend_from_slice(&b.port.to_be_bytes());
                rec.extend_from_slice(&b.app.to_be_bytes());
                rec.push(b.ttl);
                rec.push(6);
                rec.extend_from_slice(&a.octets());
            }
        }
        rec.extend_from_slice(&b.payload);
        w.write_all(&rec)
    }
    fn footer(&mut self, w: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        let mut buf = [0u8; BINARY_BLOCK];
        buf[..11].copy_from_slice(b"masscan/1.1");
        w.write_all(&buf)
    }
}

/// `--output-format certs`, `src/out-certs.c`: заголовок и запись статуса пусты (`:10-15`, `:29-44`), подвал
/// `{finished: 1}\n` (`:21-25`), то есть файл, которого коснулась хоть одна запись, содержит только эту строку.
struct Certs;

impl Formatter for Certs {
    fn header(&mut self, _: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        Ok(())
    }
    fn record(&mut self, _: &mut dyn Write, _: &FileCtx, _: &Record) -> io::Result<()> {
        Ok(())
    }
    /// `cert_out_banner` (`src/out-certs.c:49-80`): все поля, кроме полезной нагрузки, не используются, проверки
    /// app нет. `cert:` в начале снимается только при длине больше 5; затем PEM-обёртка и строки по 72 байта через
    /// `printf("%.*s\n")`, который останавливается на первом NUL строки.
    fn banner(&mut self, w: &mut dyn Write, _: &FileCtx, b: &BannerRecord) -> io::Result<()> {
        let mut px = b.payload.as_slice();
        if px.len() > 5
            && let Some(rest) = px.strip_prefix(b"cert:")
        {
            px = rest;
        }
        w.write_all(b"-----BEGIN CERTIFICATE-----\n")?;
        for line in px.chunks(72) {
            let text = line.split(|&c| c == 0).next().unwrap_or_default();
            w.write_all(text)?;
            w.write_all(b"\n")?;
        }
        w.write_all(b"-----END CERTIFICATE-----\n")
    }
    fn footer(&mut self, w: &mut dyn Write, _: &FileCtx) -> io::Result<()> {
        w.write_all(b"{finished: 1}\n")
    }
    fn banner_to_stdout(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::record::Proto;
    use crate::output::services;
    use std::net::{IpAddr, Ipv4Addr};

    fn open_rec() -> Record {
        Record {
            timestamp: 1_700_000_000,
            ip: Ipv4Addr::new(1, 2, 3, 4).into(),
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
            ip: Ipv4Addr::new(10, 0, 0, 255).into(),
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
            ip: Ipv4Addr::new(192, 0, 2, ip).into(),
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

    fn v6_rec(status: Status) -> Record {
        Record {
            timestamp: 1_700_000_000,
            ip: IpAddr::V6("2a03:9060:0:400::2".parse().unwrap()),
            port: 443,
            proto: Proto::Tcp,
            status,
            reason: if status == Status::Open { 0x12 } else { 0x14 },
            ttl: 57,
            mac: None,
        }
    }

    /// `out-binary.c:103-149` (`binary_out_status_ipv6`): type 10 (`Out_Open6`) / 11 (`Out_Closed6`), length 26 and
    /// `[ts BE4, ip_proto, port BE2, reason, ttl, version 6, hi BE8, lo BE8]` (`out-record.h:13-14`); the text
    /// formats print `ipv6address_fmt` (`massip-addr.c:33-109`: first zero run compressed, `::400:0:0:0:2`, which
    /// `Ipv6Addr::Display` does not give), no brackets (`out-text.c:42`, `out-json.c:49`, `out-ndjson.c:40`,
    /// `out-hostonly.c:39`, `out-grepable.c:160`, `out-unicornscan.c:41`) and `addrtype="ipv6"`
    /// (`out-xml.c:75-83`, `output.c:89-96`).
    #[test]
    fn binary_records_10_11_layout_is_exact_28_bytes() {
        let sv = services::empty();
        let c = cx(&sv);
        for (status, ty) in [(Status::Open, 10u8), (Status::Closed, 11)] {
            let bin = render(Format::Binary, &c, &[v6_rec(status)]);
            assert_eq!(bin.len(), 99 + 28 + 99);
            let mut want = vec![ty, 26];
            want.extend_from_slice(&1_700_000_000u32.to_be_bytes());
            want.push(6);
            want.extend_from_slice(&443u16.to_be_bytes());
            want.push(if status == Status::Open { 0x12 } else { 0x14 });
            want.push(57);
            want.push(6);
            want.extend_from_slice(&0x2a03_9060_0000_0400u64.to_be_bytes());
            want.extend_from_slice(&2u64.to_be_bytes());
            assert_eq!(want.len(), 28);
            assert_eq!(bin[99..99 + 28], want[..]);
            assert_eq!(bin[99 + 11], 6, "byte 11 is the IP version");
        }
        // The v4 record next to it is still 15 bytes (type 6/7, length 13).
        let mixed = render(
            Format::Binary,
            &c,
            &[open_rec(), v6_rec(Status::Open), closed_rec()],
        );
        assert_eq!(mixed.len(), 99 + 15 + 28 + 15 + 99);
        assert_eq!(mixed[99..101], [6, 13]);
        assert_eq!(mixed[114..116], [10, 26]);
        assert_eq!(mixed[142..144], [7, 13]);

        let addr = "2a03:9060::400:0:0:0:2";
        let r = [v6_rec(Status::Open)];
        assert_ne!(addr, "2a03:9060:0:400::2");
        let list = s(&render(Format::List, &c, &r));
        assert_eq!(
            list,
            format!("#masscan\nopen tcp 443 {addr} 1700000000\n# end\n")
        );
        let json = s(&render(Format::Json, &c, &r));
        assert!(
            json.contains(&format!("\"ip\": \"{addr}\",   \"timestamp\"")),
            "{json}"
        );
        let nd = s(&render(Format::Ndjson, &c, &r));
        assert!(
            nd.starts_with(&format!("{{\"ip\":\"{addr}\",\"timestamp\"")),
            "{nd}"
        );
        assert_eq!(s(&render(Format::Hostonly, &c, &r)), format!("{addr}\n"));
        let g = s(&render(Format::Grepable, &c, &r));
        assert!(
            g.contains(&format!("\tHost: {addr} ()\tPorts: 443/open/tcp//")),
            "{g}"
        );
        let u = s(&render(Format::Unicornscan, &c, &r));
        assert!(u.contains(&format!("\t\tfrom {addr}  ttl 57 \n")), "{u}");
        let x = s(&render(Format::Xml, &c, &r));
        assert!(
            x.contains(&format!("<address addr=\"{addr}\" addrtype=\"ipv6\"/>")),
            "{x}"
        );
        // A v4 record keeps addrtype="ipv4".
        let x4 = s(&render(Format::Xml, &c, &[open_rec()]));
        assert!(x4.contains("<address addr=\"1.2.3.4\" addrtype=\"ipv4\"/>"));
    }

    #[test]
    fn edge_values_render_like_c() {
        let sv = services::empty();
        let c = cx(&sv);
        let lo = Record {
            timestamp: 4_294_967_296 + 5,
            ip: Ipv4Addr::new(0, 0, 0, 0).into(),
            port: 0,
            proto: Proto::Tcp,
            status: Status::Open,
            reason: 0,
            ttl: 0,
            mac: None,
        };
        let hi = Record {
            timestamp: 4_294_967_296 + 5,
            ip: Ipv4Addr::new(255, 255, 255, 255).into(),
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

/// Записи баннеров (справка A4 `docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-output-udp.md`): байты
/// сверены с `out-*.c` masscan `8e6b3b0`.
#[cfg(test)]
mod banner_tests {
    use super::*;
    use crate::output::record::Proto;
    use crate::output::services;
    use rmasscan_proto::{BannerRecord, app_id};
    use std::net::{IpAddr, Ipv4Addr};

    /// Пример справки A4: IPv4 udp/53, TTL 57, app 6 (`dns-ver`), время 0x6553F100, `9.18.24`.
    fn dns() -> BannerRecord {
        BannerRecord {
            timestamp: 0x6553_F100,
            ip: Ipv4Addr::new(192, 0, 2, 1).into(),
            ip_proto: 17,
            port: 53,
            app: app_id::DNS_VERSIONBIND,
            ttl: 57,
            payload: b"9.18.24".to_vec(),
        }
    }

    fn v6(payload: &[u8]) -> BannerRecord {
        BannerRecord {
            ip: IpAddr::V6("2001:db8::1".parse().unwrap()),
            payload: payload.to_vec(),
            ..dns()
        }
    }

    fn open_rec() -> Record {
        Record {
            timestamp: 1_700_000_000,
            ip: Ipv4Addr::new(1, 2, 3, 4).into(),
            port: 80,
            proto: Proto::Tcp,
            status: Status::Open,
            reason: 0x12,
            ttl: 57,
            mac: None,
        }
    }

    fn cx(services: &ServiceNames) -> FileCtx<'_> {
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

    enum Item<'r> {
        S(&'r Record),
        B(&'r BannerRecord),
    }

    /// Заголовок, записи статуса и баннеров в порядке прихода, подвал.
    fn render(f: Format, items: &[Item]) -> Vec<u8> {
        let sv = services::empty();
        let c = cx(&sv);
        let mut fm = formatter(f).expect("formatter");
        let mut out = Vec::new();
        fm.header(&mut out, &c).unwrap();
        for i in items {
            match i {
                Item::S(r) => fm.record(&mut out, &c, r).unwrap(),
                Item::B(b) => fm.banner(&mut out, &c, b).unwrap(),
            }
        }
        fm.footer(&mut out, &c).unwrap();
        out
    }

    /// Только байты одной записи баннера (без заголовка и подвала).
    fn one(f: Format, b: &BannerRecord) -> Vec<u8> {
        let sv = services::empty();
        let c = cx(&sv);
        let mut out = Vec::new();
        formatter(f)
            .expect("formatter")
            .banner(&mut out, &c, b)
            .unwrap();
        out
    }

    fn s(b: &[u8]) -> String {
        String::from_utf8(b.to_vec()).unwrap()
    }

    /// `text_out_banner` (`src/out-text.c:51-73`): `"%s %s %u %s %u %s %s\n"`, TTL не печатается; пустой баннер
    /// оставляет пробел-разделитель; незнакомый `ip_proto` это `err` (`src/output.c:71-82`), незнакомый app `(N)`.
    #[test]
    fn list_banner_bytes() {
        let b = BannerRecord {
            timestamp: 1_700_000_000,
            ..dns()
        };
        assert_eq!(
            s(&one(Format::List, &b)),
            "banner udp 53 192.0.2.1 1700000000 dns-ver 9.18.24\n"
        );
        let ntp = BannerRecord {
            port: 123,
            app: app_id::NTP,
            payload: Vec::new(),
            ..b.clone()
        };
        assert_eq!(
            s(&one(Format::List, &ntp)),
            "banner udp 123 192.0.2.1 1700000000 ntp \n"
        );
        let odd = BannerRecord {
            timestamp: 4_294_967_296 + 5,
            ip_proto: 99,
            app: 37,
            payload: b"a\r\n<\"'&\\>\x7f\xff z".to_vec(),
            ..b.clone()
        };
        assert_eq!(
            s(&one(Format::List, &odd)),
            "banner err 53 192.0.2.1 5 (37) a\\x0d\\x0a\\x3c\\x22\\x27\\x26\\x5c\\x3e\\x7f\\xff z\n"
        );
        for (p, name) in [
            (0u8, "arp"),
            (1, "icmp"),
            (6, "tcp"),
            (17, "udp"),
            (132, "sctp"),
            (255, "err"),
        ] {
            let r = BannerRecord {
                ip_proto: p,
                ..b.clone()
            };
            assert!(
                s(&one(Format::List, &r)).starts_with(&format!("banner {name} 53 ")),
                "{p}"
            );
        }
        // Адрес IPv6 в форме `ipv6address_fmt` C, без скобок.
        assert_eq!(
            s(&one(Format::List, &v6(b"x"))),
            "banner udp 53 2001:db8::1 1700000000 dns-ver x\n"
        );
    }

    /// `json_out_banner` (`src/out-json.c:101-134`): общий с записью статуса флаг первой записи (`,\n` перед каждой,
    /// кроме первой), `} } ]` в конце, `\u00XX` строчными, `%d` над `(int)timestamp`, TTL не печатается.
    #[test]
    fn json_banner_bytes_and_shared_comma() {
        let b = dns();
        let status = open_rec();
        let out = s(&render(Format::Json, &[Item::S(&status), Item::B(&b)]));
        let expect = concat!(
            "[\n",
            "{   \"ip\": \"1.2.3.4\",   \"timestamp\": \"1700000000\", \"ports\": [ {\"port\": 80, \"proto\": \"tcp\", \"status\": \"open\", \"reason\": \"syn-ack\", \"ttl\": 57} ] }\n",
            ",\n",
            "{   \"ip\": \"192.0.2.1\",   \"timestamp\": \"1700000000\", \"ports\": [ {\"port\": 53, \"proto\": \"udp\", \"service\": {\"name\": \"dns-ver\", \"banner\": \"9.18.24\"} } ] }\n",
            "]\n"
        );
        assert_eq!(out, expect);
        // Баннер первым: запятая уходит к следующей записи статуса.
        let out = s(&render(
            Format::Json,
            &[Item::B(&b), Item::S(&status), Item::B(&b)],
        ));
        assert_eq!(out.matches(",\n").count(), 2, "{out}");
        assert!(out.starts_with("[\n{   \"ip\": \"192.0.2.1\""), "{out}");
        let odd = BannerRecord {
            timestamp: 0x8000_0000,
            payload: b"a\"b\n\xc3\xa9".to_vec(),
            ..dns()
        };
        assert_eq!(
            s(&one(Format::Json, &odd)),
            "{   \"ip\": \"192.0.2.1\",   \"timestamp\": \"-2147483648\", \"ports\": [ {\"port\": 53, \"proto\": \"udp\", \"service\": {\"name\": \"dns-ver\", \"banner\": \"a\\u0022b\\u000a\\u00c3\\u00a9\"} } ] }\n"
        );
    }

    /// `ndjson_out_banner` (`src/out-ndjson.c:97-153`): одна строка, `rec_type` `banner`, нормализатор как у JSON.
    #[test]
    fn ndjson_banner_bytes() {
        assert_eq!(
            s(&one(Format::Ndjson, &dns())),
            "{\"ip\":\"192.0.2.1\",\"timestamp\":\"1700000000\",\"port\":53,\"proto\":\"udp\",\"rec_type\":\"banner\",\"data\":{\"service_name\":\"dns-ver\",\"banner\":\"9.18.24\"}}\n"
        );
        let odd = BannerRecord {
            app: 65535,
            payload: b"<\x00>".to_vec(),
            ..v6(b"")
        };
        assert_eq!(
            s(&one(Format::Ndjson, &odd)),
            "{\"ip\":\"2001:db8::1\",\"timestamp\":\"1700000000\",\"port\":53,\"proto\":\"udp\",\"rec_type\":\"banner\",\"data\":{\"service_name\":\"(65535)\",\"banner\":\"\\u003c\\u0000\\u003e\"}}\n"
        );
        // Без заголовка и подвала, как у записи статуса.
        assert_eq!(
            render(Format::Ndjson, &[Item::B(&dns())]),
            one(Format::Ndjson, &dns())
        );
    }

    /// `xml_out_banner` (`src/out-xml.c:95-132`): `reason` выбирается по номеру ПРИЛОЖЕНИЯ (`case 6`, баг C: имелся
    /// в виду `ip_proto`), поэтому `dns-ver` даёт `syn-ack`, а HTTP по TCP `response`; ` />` с пробелом.
    #[test]
    fn xml_banner_reason_by_app_id() {
        assert_eq!(
            s(&one(Format::Xml, &dns())),
            "<host endtime=\"1700000000\"><address addr=\"192.0.2.1\" addrtype=\"ipv4\"/><ports><port protocol=\"udp\" portid=\"53\"><state state=\"open\" reason=\"syn-ack\" reason_ttl=\"57\" /><service name=\"dns-ver\" banner=\"9.18.24\"></service></port></ports></host>\r\n"
        );
        let http = BannerRecord {
            ip_proto: 6,
            port: 80,
            app: app_id::HTTP,
            ttl: 64,
            payload: b"HTTP/1.1 200 OK\r\nServer: <x>".to_vec(),
            ..dns()
        };
        assert_eq!(
            s(&one(Format::Xml, &http)),
            "<host endtime=\"1700000000\"><address addr=\"192.0.2.1\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\" reason=\"response\" reason_ttl=\"64\" /><service name=\"http\" banner=\"HTTP/1.1 200 OK\\x0d\\x0aServer: \\x3cx\\x3e\"></service></port></ports></host>\r\n"
        );
        let x6 = s(&one(Format::Xml, &v6(b"v")));
        assert!(
            x6.starts_with(
                "<host endtime=\"1700000000\"><address addr=\"2001:db8::1\" addrtype=\"ipv6\"/>"
            ),
            "{x6}"
        );
        // Запись статуса рядом остаётся без пробела перед `/>`.
        let mixed = s(&render(
            Format::Xml,
            &[Item::S(&open_rec()), Item::B(&dns())],
        ));
        assert!(mixed.contains("reason_ttl=\"57\"/></port>"), "{mixed}");
        assert!(mixed.contains("reason_ttl=\"57\" /><service"), "{mixed}");
    }

    /// `grepable_out_banner` (`src/out-grepable.c:178-202`): без `Timestamp:`, без протокола и без поиска сервиса.
    #[test]
    fn grepable_banner_bytes() {
        assert_eq!(
            s(&one(Format::Grepable, &dns())),
            "Host: 192.0.2.1 ()\tPort: 53\tService: dns-ver\tBanner: 9.18.24\n"
        );
        let sv = ServiceNames::parse("domain 53/udp\n");
        let c = cx(&sv);
        let mut out = Vec::new();
        formatter(Format::Grepable)
            .unwrap()
            .banner(&mut out, &c, &v6(b"\t"))
            .unwrap();
        assert_eq!(
            s(&out),
            "Host: 2001:db8::1 ()\tPort: 53\tService: dns-ver\tBanner: \\x09\n"
        );
    }

    /// `binary_out_banner` (`src/out-binary.c:293-355`): тип 9, длина `7 + 14`, всё в сетевом порядке байт.
    #[test]
    fn binary_banner_type9_example() {
        assert_eq!(
            one(Format::Binary, &dns()),
            [
                0x09, 0x15, 0x65, 0x53, 0xF1, 0x00, 0xC0, 0x00, 0x02, 0x01, 0x11, 0x00, 0x35, 0x00,
                0x06, 0x39, 0x39, 0x2E, 0x31, 0x38, 0x2E, 0x32, 0x34
            ]
        );
        // Время режется до младших 32 бит; полезная нагрузка сырая, без экранирования.
        let raw = BannerRecord {
            timestamp: 0x1_0000_0002,
            app: 0x1234,
            payload: vec![0x00, 0xFF, b'<'],
            ..dns()
        };
        assert_eq!(
            one(Format::Binary, &raw),
            [
                9, 17, 0, 0, 0, 2, 192, 0, 2, 1, 17, 0, 53, 0x12, 0x34, 57, 0x00, 0xFF, b'<'
            ]
        );
    }

    /// `binary_out_banner_ipv6` (`src/out-binary.c:216-289`): тип 13, длина `n + 27`; время, протокол, порт, app,
    /// TTL, версия 6, `hi`, `lo`, полезная нагрузка (адрес после TTL, а не в начале, как у типа 9).
    #[test]
    fn binary_banner_type13_layout() {
        let b = BannerRecord {
            ip: IpAddr::V6("2a03:9060:0:400::2".parse().unwrap()),
            ..dns()
        };
        let mut want = vec![13u8, 7 + 27];
        want.extend_from_slice(&0x6553_F100u32.to_be_bytes());
        want.push(17);
        want.extend_from_slice(&53u16.to_be_bytes());
        want.extend_from_slice(&6u16.to_be_bytes());
        want.push(57);
        want.push(6);
        want.extend_from_slice(&0x2a03_9060_0000_0400u64.to_be_bytes());
        want.extend_from_slice(&2u64.to_be_bytes());
        want.extend_from_slice(b"9.18.24");
        assert_eq!(one(Format::Binary, &b), want);
        // Тип 9 и тип 13 в одном файле между записями статуса.
        let bin = render(
            Format::Binary,
            &[Item::S(&open_rec()), Item::B(&b), Item::B(&dns())],
        );
        assert_eq!(bin.len(), 99 + 15 + want.len() + 23 + 99);
        assert_eq!(bin[114..114 + want.len()], want[..]);
        assert_eq!(bin[114 + want.len()], 9);
    }

    /// Граница длины `-oB` (Review Focus 1): однобайтовая длина до `128 - header` (113 у IPv4, 100 у IPv6),
    /// затем `((n+h)>>7)|0x80, (n+h)&0x7F`; от `128*128 - header` байт (16 370 / 16 357) запись молча не пишется
    /// (`src/out-binary.c:232-241`, `:313-322`).
    #[test]
    fn binary_banner_length_boundaries() {
        let v4 = |n: usize| BannerRecord {
            payload: vec![b'A'; n],
            ..dns()
        };
        let v6n = |n: usize| v6(&vec![b'B'; n]);
        for (b, head, total) in [
            (v4(113), vec![9u8, 127], 2 + 14 + 113),
            (v4(114), vec![9, 0x81, 0x00], 3 + 14 + 114),
            (v4(16_369), vec![9, 0xFF, 0x7F], 3 + 14 + 16_369),
            (v6n(100), vec![13, 127], 2 + 27 + 100),
            (v6n(101), vec![13, 0x81, 0x00], 3 + 27 + 101),
            (v6n(16_356), vec![13, 0xFF, 0x7F], 3 + 27 + 16_356),
        ] {
            let out = one(Format::Binary, &b);
            assert_eq!(out.len(), total, "{}", b.payload.len());
            assert_eq!(out[..head.len()], head[..], "{}", b.payload.len());
            assert!(out.ends_with(&b.payload), "{}", b.payload.len());
        }
        // Слишком длинные записи выбрасываются целиком, без ошибки.
        for b in [v4(16_370), v4(65_536), v6n(16_357)] {
            assert!(one(Format::Binary, &b).is_empty(), "{}", b.payload.len());
        }
        // Длина 0 пишется: только заголовок записи.
        assert_eq!(one(Format::Binary, &v4(0))[..2], [9, 14]);
        assert_eq!(one(Format::Binary, &v6n(0))[..2], [13, 27]);
    }

    /// `hostonly_out_banner` (`src/out-hostonly.c:45-65`): ещё одна строка адреса на каждую запись баннера.
    #[test]
    fn hostonly_banner_adds_ip_line() {
        let out = s(&render(
            Format::Hostonly,
            &[Item::S(&open_rec()), Item::B(&dns()), Item::B(&v6(b""))],
        ));
        assert_eq!(out, "1.2.3.4\n192.0.2.1\n2001:db8::1\n");
    }

    /// `unicornscan_out_banner` (`src/out-unicornscan.c:61-79`): пустая; заголовок и подвал ведёт конвейер.
    #[test]
    fn unicornscan_banner_writes_nothing() {
        assert!(one(Format::Unicornscan, &dns()).is_empty());
        assert_eq!(
            s(&render(Format::Unicornscan, &[Item::B(&dns())])),
            "#masscan\n# end\n"
        );
    }

    /// `src/out-certs.c`: заголовок и запись статуса пусты, подвал `{finished: 1}\n`; баннер это PEM (байты
    /// [`Formatter::banner`] конвейер отдаёт в stdout, [`Formatter::banner_to_stdout`]).
    #[test]
    fn certs_banner_is_pem_in_72_byte_lines() {
        let mut fm = formatter(Format::Certs).expect("certs formatter");
        assert!(fm.banner_to_stdout());
        let sv = services::empty();
        let c = cx(&sv);
        let mut out = Vec::new();
        fm.header(&mut out, &c).unwrap();
        fm.record(&mut out, &c, &open_rec()).unwrap();
        assert!(out.is_empty());
        fm.footer(&mut out, &c).unwrap();
        assert_eq!(s(&out), "{finished: 1}\n");
        let pem = |payload: &[u8]| {
            let b = BannerRecord {
                payload: payload.to_vec(),
                ..dns()
            };
            let mut out = Vec::new();
            formatter(Format::Certs)
                .unwrap()
                .banner(&mut out, &c, &b)
                .unwrap();
            out
        };
        let body: Vec<u8> = (0..150u32).map(|i| b'A' + (i % 26) as u8).collect();
        let mut with_prefix = b"cert:".to_vec();
        with_prefix.extend_from_slice(&body);
        let mut want = b"-----BEGIN CERTIFICATE-----\n".to_vec();
        for chunk in body.chunks(72) {
            want.extend_from_slice(chunk);
            want.push(b'\n');
        }
        want.extend_from_slice(b"-----END CERTIFICATE-----\n");
        assert_eq!(pem(&with_prefix), want);
        assert_eq!(pem(&body), want, "без `cert:` печатается как есть");
        // `length > 5`: ровно `cert:` не снимается; `cert:X` снимается.
        assert_eq!(
            s(&pem(b"cert:")),
            "-----BEGIN CERTIFICATE-----\ncert:\n-----END CERTIFICATE-----\n"
        );
        assert_eq!(
            s(&pem(b"cert:X")),
            "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n"
        );
        assert_eq!(
            s(&pem(b"")),
            "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"
        );
        // `printf("%.*s\n")` останавливается на NUL внутри строки из 72 байт.
        let mut nul = vec![b'a'; 10];
        nul.push(0);
        nul.extend_from_slice(&[b'b'; 70]);
        assert_eq!(
            s(&pem(&nul)),
            "-----BEGIN CERTIFICATE-----\naaaaaaaaaa\nbbbbbbbbb\n-----END CERTIFICATE-----\n"
        );
    }
}
