//! Конвейер вывода (AGPL-3.0). Порт `output_create`/`output_report_status`/`close_rotate` (`output.c:389–515`,
//! `:746–880`, `:247–269`) masscan © Robert David Graham: фильтр show, интерактивная строка, счётчики, ленивый
//! заголовок при первой записи, запись, flush; подвал только если была хотя бы одна запись (Р7). Время записи это
//! Unix-секунды в момент обработки пачки (Р9). Перевод строки никогда не превращается в `\r\n`: байты одинаковы
//! на всех ОС. Записи баннеров идут своим путём (`output_report_banner`, `output.c:886-956`,
//! [`Pipeline::report_banner`]).

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};

use rmasscan_core::receive::Reply;
use rmasscan_proto::BannerRecord;

use super::formats::{Counts, FileCtx, Format, Formatter, formatter};
use super::record::{Proto, Record, Status};
use super::services::ServiceNames;
use super::{Sink, WriteTarget, banner_line, interactive_line, io_fail, write_failed};

/// Начало отказа открытия файла (`output.c:180–239`, `open_rotate`); `crate::error_text` печатает его как есть.
pub const OPEN_FAILURE_PREFIX: &str = "out: could not open file for ";

/// Часы стенки: Unix-время и смещение местного времени от UTC. Все `Backend` их реализуют.
pub trait Wall {
    fn unix_time(&self) -> u64;
    /// Секунды к UTC для местного времени в момент `unix` (подвал XML печатает местное время, как C).
    fn utc_offset_secs(&self, unix: u64) -> i32;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputOptions {
    pub format: Format,
    /// `-` значит stdout.
    pub filename: Option<String>,
    pub append: bool,
    pub flush: bool,
    pub show_open: bool,
    pub show_closed: bool,
    pub show_host: bool,
    pub interactive: bool,
    pub stylesheet: Option<String>,
}

impl Default for OutputOptions {
    /// Умолчания C (`main.c:1596`): показывать open, остальное выключено.
    fn default() -> Self {
        OutputOptions {
            format: Format::Default,
            filename: None,
            append: false,
            flush: false,
            show_open: true,
            show_closed: false,
            show_host: false,
            interactive: false,
            stylesheet: None,
        }
    }
}

impl OutputOptions {
    /// Формат пишется в stdout (`-o… -`): `open_rotate` берёт `stdout` для имени `-` (`output.c:215–216`), а файл
    /// открывается только для формата с файлом (`output.c:479`).
    pub fn format_to_stdout(&self) -> bool {
        self.filename.as_deref() == Some("-") && formatter(self.format).is_some()
    }
}

pub struct OutputEnv<'a> {
    pub wall: &'a dyn Wall,
    pub services: ServiceNames,
    /// Диапазоны портов цели со сдвигами протоколов (`masscan->targets.ports`), для заголовка `-oG`.
    pub ports: Vec<(u32, u32)>,
    /// Начало скана; `None` значит «момент `open()`», `Some(0)` значит «из первой записи» (`--readscan`).
    pub scan_started: Option<u64>,
}

enum Target {
    /// Файл не открыт (или не нужен).
    Closed,
    Stdout,
    File(BufWriter<File>),
}

/// Писатель файла формата: stdout для имени `-` или открытый файл; `None`, если файла нет (`out->fp == NULL`).
fn file_writer<'b>(
    target: &'b mut Target,
    stdout: &'b mut dyn Write,
) -> Option<(&'b mut dyn Write, WriteTarget)> {
    match target {
        Target::Closed => None,
        Target::Stdout => Some((stdout, WriteTarget::Stdout)),
        Target::File(f) => Some((f, WriteTarget::File)),
    }
}

pub struct Pipeline<'a> {
    opts: OutputOptions,
    stdout: &'a mut dyn Write,
    env: OutputEnv<'a>,
    formatter: Option<Box<dyn Formatter>>,
    target: Target,
    virgin: bool,
    counts: Counts,
    scan_started: u64,
    file_opened: u64,
}

impl<'a> Pipeline<'a> {
    pub fn new(opts: OutputOptions, stdout: &'a mut dyn Write, env: OutputEnv<'a>) -> Pipeline<'a> {
        Pipeline {
            formatter: formatter(opts.format),
            scan_started: env.scan_started.unwrap_or(0),
            opts,
            stdout,
            env,
            target: Target::Closed,
            virgin: true,
            counts: Counts::default(),
            file_opened: 0,
        }
    }

    /// `out->when_scan_started = strtoul(..)` из заголовка `masscan/1.1.N` (`in-binary.c:531-532`): без проверки на ноль.
    pub fn set_scan_started(&mut self, ts: u64) {
        self.scan_started = ts;
    }

    /// `if (out->when_scan_started == 0) out->when_scan_started = record.timestamp` (`in-binary.c`).
    pub fn set_scan_started_if_unset(&mut self, ts: u64) {
        if self.scan_started == 0 {
            self.scan_started = ts;
        }
    }

    /// `exit(1)` C посреди вывода (`--readscan`, тип 4 без лишнего байта, `in-binary.c:597-600`): `output_destroy` не
    /// зовётся, подвала нет, а буферы stdio сбрасываются при выходе. Файл закрывается без подвала.
    pub fn abandon(&mut self) -> Result<(), String> {
        if let Target::File(mut f) = std::mem::replace(&mut self.target, Target::Closed) {
            f.flush().map_err(|e| write_failed(WriteTarget::File, e))?;
        }
        self.stdout.flush().map_err(io_fail)
    }

    fn interactive_line(&self) -> bool {
        self.opts.interactive || matches!(self.opts.format, Format::Default | Format::Interactive)
    }

    /// `output_report_banner` (`output.c:886-956`, справка A1) для одной записи баннера. Флаг `is_banner`
    /// (`:898-899`) проверяет вызывающий: конвейер получает только баннеры, которые надо вывести. Отличия от записи
    /// статуса: нет фильтра show и счётчиков (`<hosts up=…>` `-oX` баннеры не считает), без файла запись молча
    /// теряется, без строк `no output file` (`:926-927`). Ротации у rmasscan нет (`:934-938`).
    pub fn report_banner(&mut self, b: &BannerRecord) -> Result<(), String> {
        if self.interactive_line() {
            // `:903-923`. C не делает здесь `fflush(stdout)`, но его stdout у терминала построчный, а наш stdout это
            // `BufWriter`: flush даёт тот же момент появления строки, байты те же.
            self.stdout
                .write_all(banner_line(b).as_bytes())
                .map_err(io_fail)?;
            self.stdout.flush().map_err(io_fail)?;
        }
        let Some(fm) = self.formatter.as_mut() else {
            return Ok(());
        };
        let now = self.env.wall.unix_time();
        let cx = FileCtx {
            now,
            utc_offset_secs: self.env.wall.utc_offset_secs(now),
            scan_started: self.scan_started,
            file_opened: self.file_opened,
            counts: self.counts,
            stylesheet: self.opts.stylesheet.as_deref(),
            ports: &self.env.ports,
            services: &self.env.services,
        };
        let Some((w, to)) = file_writer(&mut self.target, &mut *self.stdout) else {
            return Ok(());
        };
        // `:943-946`: баннер тоже может записать ленивый заголовок, и после него подвал будет при закрытии.
        if self.virgin {
            fm.header(w, &cx).map_err(|e| write_failed(to, e))?;
            self.virgin = false;
        }
        if fm.banner_to_stdout() {
            // `certs`: PEM через `printf` в stdout (`src/out-certs.c:72-79`), файл остаётся для подвала.
            fm.banner(&mut *self.stdout, &cx, b).map_err(io_fail)?;
            self.stdout.flush().map_err(io_fail)?;
        } else {
            fm.banner(w, &cx, b).map_err(|e| write_failed(to, e))?;
        }
        // `:954-955`: `if (out->is_output_flush) fflush(fp);`.
        if self.opts.flush
            && let Some((w, to)) = file_writer(&mut self.target, &mut *self.stdout)
        {
            w.flush().map_err(|e| write_failed(to, e))?;
        }
        Ok(())
    }

    /// `output.c:746–880` (справка §2) для одной записи.
    pub fn report_record(&mut self, r: &Record) -> Result<(), String> {
        // `output.c:766–771`: фильтр только у open и closed, `up` (ARP) проходит всегда.
        let show = match r.status {
            Status::Open => self.opts.show_open,
            Status::Closed => self.opts.show_closed,
            Status::Arp => true,
        };
        if !show {
            return Ok(());
        }
        if self.interactive_line() {
            let line = interactive_line(r);
            self.stdout.write_all(line.as_bytes()).map_err(io_fail)?;
            self.stdout.flush().map_err(io_fail)?;
        }
        let Some(fm) = self.formatter.as_mut() else {
            return Ok(());
        };
        if matches!(self.target, Target::Closed) {
            // Реальный формат без файла: C молча теряет запись (`output.c:799–803`). Из `crate::run` сюда не дойти:
            // он отклоняет такие опции до скана и до чтения `--readscan`.
            return Ok(());
        }
        // `output.c:818–858`: счётчик TCP идёт в `<hosts up=…>` `-oX`; UDP, SCTP, ICMP и ARP считаются отдельно
        // и в XML не попадают (`out-xml.c:55–58`).
        if r.proto == Proto::Tcp {
            match r.status {
                Status::Open => self.counts.open += 1,
                Status::Closed => self.counts.closed += 1,
                Status::Arp => {}
            }
        }
        let now = self.env.wall.unix_time();
        let cx = FileCtx {
            now,
            utc_offset_secs: self.env.wall.utc_offset_secs(now),
            scan_started: self.scan_started,
            file_opened: self.file_opened,
            counts: self.counts,
            stylesheet: self.opts.stylesheet.as_deref(),
            ports: &self.env.ports,
            services: &self.env.services,
        };
        let (w, to): (&mut dyn Write, WriteTarget) = match &mut self.target {
            Target::Stdout => (&mut *self.stdout, WriteTarget::Stdout),
            Target::File(f) => (f, WriteTarget::File),
            Target::Closed => return Ok(()),
        };
        let fail = |e: io::Error| write_failed(to, e);
        if self.virgin {
            fm.header(w, &cx).map_err(fail)?;
            self.virgin = false;
        }
        fm.record(w, &cx, r).map_err(fail)?;
        if self.opts.flush {
            w.flush().map_err(fail)?;
        }
        Ok(())
    }
}

impl Sink for Pipeline<'_> {
    fn open(&mut self) -> Result<(), String> {
        let now = self.env.wall.unix_time();
        if self.env.scan_started.is_none() {
            self.scan_started = now;
        }
        self.file_opened = now;
        let Some(name) = self.opts.filename.as_deref() else {
            return Ok(());
        };
        // `output.c:479`: для null_output файл не открывается.
        if self.formatter.is_none() {
            return Ok(());
        }
        self.target = if name == "-" {
            Target::Stdout
        } else {
            let mut o = OpenOptions::new();
            if self.opts.append {
                o.append(true).create(true);
            } else {
                o.write(true).create(true).truncate(true);
            }
            match o.open(name) {
                Ok(f) => Target::File(BufWriter::new(f)),
                Err(e) => {
                    let how = if self.opts.append {
                        "appending"
                    } else {
                        "writing"
                    };
                    return Err(format!("{OPEN_FAILURE_PREFIX}{how}\n{name}: {e}"));
                }
            }
        };
        self.virgin = true;
        Ok(())
    }

    fn report(&mut self, reply: &Reply) -> Result<(), String> {
        let r = Record::from_reply(reply, self.env.wall.unix_time());
        self.report_record(&r)
    }

    fn report_banner(&mut self, b: &BannerRecord) -> Result<(), String> {
        Pipeline::report_banner(self, b)
    }

    /// `close_rotate` (`output.c:247–269`): подвал только если файл не пуст, затем flush и закрытие.
    fn finish(&mut self) -> Result<(), String> {
        let now = self.env.wall.unix_time();
        let cx = FileCtx {
            now,
            utc_offset_secs: self.env.wall.utc_offset_secs(now),
            scan_started: self.scan_started,
            file_opened: self.file_opened,
            counts: self.counts,
            stylesheet: self.opts.stylesheet.as_deref(),
            ports: &self.env.ports,
            services: &self.env.services,
        };
        let virgin = std::mem::replace(&mut self.virgin, true);
        self.counts = Counts::default();
        match std::mem::replace(&mut self.target, Target::Closed) {
            Target::Closed => {}
            Target::Stdout => {
                if let (false, Some(fm)) = (virgin, self.formatter.as_mut()) {
                    fm.footer(&mut *self.stdout, &cx).map_err(io_fail)?;
                }
            }
            Target::File(mut f) => {
                let fail = |e: io::Error| write_failed(WriteTarget::File, e);
                if let (false, Some(fm)) = (virgin, self.formatter.as_mut()) {
                    fm.footer(&mut f, &cx).map_err(fail)?;
                }
                f.flush().map_err(fail)?;
            }
        }
        self.stdout.flush().map_err(io_fail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::discovered_line;
    use crate::output::services;
    use crate::scratch::Scratch;
    use std::io;
    use std::net::Ipv4Addr;
    // Used only by the #[cfg(unix)] dead-FIFO child test below; unused on Windows.
    #[cfg(unix)]
    use std::path::PathBuf;

    struct FakeWall(u64);
    impl Wall for FakeWall {
        fn unix_time(&self) -> u64 {
            self.0
        }
        fn utc_offset_secs(&self, _: u64) -> i32 {
            3600
        }
    }

    fn env(wall: &FakeWall) -> OutputEnv<'_> {
        OutputEnv {
            wall,
            services: services::empty(),
            ports: Vec::new(),
            scan_started: None,
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

    /// `open`, записи, `finish`; возвращает stdout.
    fn run(opts: OutputOptions, recs: &[Record]) -> Vec<u8> {
        let wall = FakeWall(1_700_000_100);
        let mut out = Vec::new();
        {
            let mut p = Pipeline::new(opts, &mut out, env(&wall));
            p.open().unwrap();
            for r in recs {
                p.report_record(r).unwrap();
            }
            p.finish().unwrap();
        }
        out
    }

    fn opts(format: Format, filename: Option<&str>) -> OutputOptions {
        OutputOptions {
            format,
            filename: filename.map(str::to_string),
            ..OutputOptions::default()
        }
    }

    #[test]
    fn default_format_prints_discovered_only() {
        let out = run(OutputOptions::default(), &[open_rec(), closed_rec()]);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            discovered_line(Ipv4Addr::new(1, 2, 3, 4), 80)
        );
    }

    fn non_tcp(proto: Proto, status: Status, port: u16, ip: u8) -> Record {
        Record {
            timestamp: 1_700_000_000,
            ip: Ipv4Addr::new(192, 0, 2, ip).into(),
            port,
            proto,
            status,
            reason: 0,
            ttl: 0,
            mac: None,
        }
    }

    /// Интерактивные строки: UDP, SCTP, ICMP как у C `--readscan` (снято с `masscan 8e6b3b0`); ARP по
    /// `output.c:770–778`: адрес, MAC строчными через двоеточие, пробел, производитель, дополнение до 79.
    #[test]
    fn interactive_lines_cover_every_protocol_like_c() {
        let pad = |head: &str| format!("{head:<79}\n");
        let recs = [
            non_tcp(Proto::Udp, Status::Open, 53, 1),
            non_tcp(Proto::Sctp, Status::Open, 2905, 3),
            non_tcp(Proto::Icmp, Status::Open, 0, 4),
            Record {
                mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                ..non_tcp(Proto::Arp, Status::Arp, 0, 9)
            },
            Record {
                mac: Some([0xb8, 0x27, 0xeb, 0x01, 0x02, 0x03]),
                ..non_tcp(Proto::Arp, Status::Arp, 0, 10)
            },
            non_tcp(Proto::Arp, Status::Arp, 0, 11),
        ];
        let out = String::from_utf8(run(OutputOptions::default(), &recs)).unwrap();
        let expect = [
            pad("Discovered open port 53/udp on 192.0.2.1"),
            pad("Discovered open port 2905/sctp on 192.0.2.3"),
            pad("Discovered open port 0/icmp on 192.0.2.4"),
            // OUI 00:11:22 в таблице C нет: после MAC остаётся пробел.
            pad("Discovered up port 0/arp on 192.0.2.9 (00:11:22:33:44:55) "),
            pad("Discovered up port 0/arp on 192.0.2.10 (b8:27:eb:01:02:03) RPi 12-03"),
            pad("Discovered up port 0/arp on 192.0.2.11 (00:00:00:00:00:00) "),
        ]
        .concat();
        assert_eq!(out, expect);
        assert!(out.lines().all(|l| l.len() == 79));
        // Закрытый UDP скрыт без `--show closed` и виден с ним; ARP (`up`) фильтром show не режется.
        let closed = non_tcp(Proto::Udp, Status::Closed, 5353, 2);
        assert!(run(OutputOptions::default(), &[closed]).is_empty());
        let o = OutputOptions {
            show_open: false,
            show_closed: true,
            ..OutputOptions::default()
        };
        let out =
            String::from_utf8(run(o, &[closed, non_tcp(Proto::Arp, Status::Arp, 0, 9)])).unwrap();
        assert_eq!(
            out,
            [
                pad("Discovered closed port 5353/udp on 192.0.2.2"),
                pad("Discovered up port 0/arp on 192.0.2.9 (00:00:00:00:00:00) ")
            ]
            .concat()
        );
    }

    /// `<hosts up=…>` `-oX` считает только TCP (`out-xml.c:55–58`, `output.c:818–858`); снято с C: файл из
    /// четырёх не-TCP и одной TCP open записей даёт `up="1" down="0" total="1"`.
    #[test]
    fn xml_hosts_count_only_tcp() {
        let o = OutputOptions {
            show_closed: true,
            ..opts(Format::Xml, Some("-"))
        };
        let recs = [
            non_tcp(Proto::Udp, Status::Open, 53, 1),
            non_tcp(Proto::Udp, Status::Closed, 5353, 2),
            non_tcp(Proto::Sctp, Status::Open, 2905, 3),
            non_tcp(Proto::Icmp, Status::Open, 0, 4),
            non_tcp(Proto::Arp, Status::Arp, 0, 9),
            open_rec(),
            closed_rec(),
        ];
        let out = String::from_utf8(run(o, &recs)).unwrap();
        assert!(
            out.contains("<hosts up=\"1\" down=\"1\" total=\"2\" />\r\n"),
            "{out}"
        );
        assert_eq!(out.matches("<host endtime=").count(), 7);
    }

    #[test]
    fn default_format_opens_no_file() {
        let scratch = Scratch::new();
        let path = scratch.path("default-nofile");
        let o = opts(Format::Default, path.to_str());
        run(o, &[open_rec()]);
        assert!(!path.exists());
    }

    #[test]
    fn closed_line_when_shown() {
        let o = OutputOptions {
            show_closed: true,
            ..OutputOptions::default()
        };
        let out = String::from_utf8(run(o, &[closed_rec()])).unwrap();
        let head = "Discovered closed port 443/tcp on 10.0.0.255";
        assert_eq!(out, format!("{head}{}\n", " ".repeat(79 - head.len())));
    }

    #[test]
    fn file_format_keeps_stdout_silent() {
        let scratch = Scratch::new();
        let path = scratch.path("silent.list");
        let o = opts(Format::List, path.to_str());
        assert!(run(o, &[open_rec()]).is_empty());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "#masscan\nopen tcp 80 1.2.3.4 1700000000\n# end\n"
        );
        let mut o = opts(Format::List, path.to_str());
        o.interactive = true;
        let out = run(o, &[open_rec()]);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            discovered_line(Ipv4Addr::new(1, 2, 3, 4), 80)
        );
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("open tcp 80")
        );
    }

    #[test]
    fn grepable_and_unicornscan_create_their_files() {
        for (f, name, head) in [
            (
                Format::Grepable,
                "g.gnmap",
                "# Masscan 1.3.9-integration scan initiated",
            ),
            (Format::Unicornscan, "u.txt", "#masscan\n"),
        ] {
            let scratch = Scratch::new();
            let path = scratch.path(name);
            std::fs::write(&path, "stale").unwrap();
            let o = opts(f, path.to_str());
            assert!(run(o, &[open_rec()]).is_empty());
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(text.starts_with(head), "{text}");
            assert!(!text.contains("stale"));
        }
    }

    #[test]
    fn stdout_dash_writes_the_format_to_stdout() {
        let out = run(opts(Format::List, Some("-")), &[open_rec()]);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "#masscan\nopen tcp 80 1.2.3.4 1700000000\n# end\n"
        );
    }

    #[test]
    fn header_is_lazy_and_footer_needs_a_record() {
        let scratch = Scratch::new();
        let path = scratch.path("lazy.json");
        run(opts(Format::Json, path.to_str()), &[]);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        run(opts(Format::Json, path.to_str()), &[open_rec()]);
        let t = std::fs::read_to_string(&path).unwrap();
        assert!(t.starts_with("[\n{   \"ip\": \"1.2.3.4\""));
        assert!(t.ends_with("} ] }\n]\n"));
        assert!(run(opts(Format::Json, Some("-")), &[]).is_empty());
    }

    #[test]
    fn show_filters_before_counting() {
        let mut o = opts(Format::Xml, Some("-"));
        o.show_open = false;
        o.show_closed = true;
        let out = String::from_utf8(run(o, &[open_rec(), closed_rec()])).unwrap();
        assert!(
            out.contains("<hosts up=\"0\" down=\"1\" total=\"1\" />"),
            "{out}"
        );
        assert!(!out.contains("portid=\"80\""));
        // now = 1_700_000_100, смещение 3600, file_opened = now.
        assert!(
            out.contains("timestr=\"2023-11-14 23:15:00\" elapsed=\"0\""),
            "{out}"
        );
    }

    struct Counting {
        bytes: Vec<u8>,
        flushes: usize,
    }
    impl Write for Counting {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn flush_option_flushes_each_record() {
        let wall = FakeWall(1_700_000_100);
        for (flush, expect) in [(true, 3), (false, 0)] {
            let mut w = Counting {
                bytes: Vec::new(),
                flushes: 0,
            };
            let mut o = opts(Format::Hostonly, Some("-"));
            o.flush = flush;
            let mut p = Pipeline::new(o, &mut w, env(&wall));
            p.open().unwrap();
            for _ in 0..3 {
                p.report_record(&open_rec()).unwrap();
            }
            drop(p);
            assert_eq!(w.flushes, expect);
            assert_eq!(w.bytes, b"1.2.3.4\n1.2.3.4\n1.2.3.4\n");
        }
    }

    #[test]
    fn append_reopens_and_writes_header_again() {
        let scratch = Scratch::new();
        let path = scratch.path("append.list");
        let mut o = opts(Format::List, path.to_str());
        o.append = true;
        run(o.clone(), &[open_rec()]);
        run(o, &[open_rec()]);
        let one = "#masscan\nopen tcp 80 1.2.3.4 1700000000\n# end\n";
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{one}{one}")
        );
        // Без append файл усекается.
        run(opts(Format::List, path.to_str()), &[open_rec()]);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), one);
    }

    #[test]
    fn open_failure_message_matches_c() {
        let scratch = Scratch::new();
        let dir = scratch.dir();
        let wall = FakeWall(1);
        for (append, word) in [(false, "writing"), (true, "appending")] {
            let mut out = Vec::new();
            let mut o = opts(Format::List, dir.to_str());
            o.append = append;
            let mut p = Pipeline::new(o, &mut out, env(&wall));
            let e = p.open().unwrap_err();
            let mut lines = e.lines();
            assert_eq!(
                lines.next(),
                Some(format!("out: could not open file for {word}").as_str())
            );
            assert!(lines.next().unwrap().starts_with(dir.to_str().unwrap()));
        }
    }

    #[cfg(unix)]
    const FIFO_CHILD_ENV: &str = "RMASSCAN_DEAD_FIFO_CHILD";

    /// Работает только в дочернем процессе `a_dead_fifo_reader_is_a_write_error`: файл вывода это FIFO, читатель
    /// которого ушёл до первой записи. Запись и заголовок лежат в буфере, `finish` пишет подвал и flush получает
    /// EPIPE. Итог `finish` печатается в stdout; тихий `exit(0)` внутри не напечатает ничего.
    #[cfg(unix)]
    #[test]
    fn dead_fifo_reader_child() {
        let Some(path) = std::env::var_os(FIFO_CHILD_ENV) else {
            return;
        };
        let path = PathBuf::from(path);
        let reader = {
            let path = path.clone();
            // Открытие FIFO на чтение ждёт писателя; читатель сразу закрывает свой конец.
            std::thread::spawn(move || drop(File::open(path).unwrap()))
        };
        let wall = FakeWall(1_700_000_100);
        let mut out = Vec::new();
        let mut p = Pipeline::new(opts(Format::List, path.to_str()), &mut out, env(&wall));
        p.open().unwrap();
        reader.join().unwrap();
        p.report_record(&open_rec()).unwrap();
        let r = p.finish();
        println!("finish: {r:?}");
    }

    /// FIFO (или `/dev/fd/N`), читатель которого ушёл, это обычная ошибка записи (`write failed: …`, скан
    /// останавливается, код 1), а не тихий выход с 0, как у закрытого stdout.
    #[cfg(unix)]
    #[test]
    fn a_dead_fifo_reader_is_a_write_error() {
        let scratch = Scratch::new();
        let path = scratch.path("dead-reader.fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(made.success(), "mkfifo {}", path.display());
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "output::pipeline::tests::dead_fifo_reader_child",
                "--nocapture",
            ])
            .env(FIFO_CHILD_ENV, &path)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("finish: Err(\"write failed: Broken pipe"),
            "{stdout}"
        );
    }

    #[test]
    fn sink_report_uses_wall_time_and_reply_fields() {
        let wall = FakeWall(1_700_000_042);
        let mut out = Vec::new();
        {
            let mut p = Pipeline::new(opts(Format::List, Some("-")), &mut out, env(&wall));
            p.open().unwrap();
            p.report(&Reply {
                remote_ip: u32::from(Ipv4Addr::new(1, 2, 3, 4)),
                remote_port: 80,
                local_ip: 0,
                local_port: 0,
                status: rmasscan_core::receive::PortStatus::Open,
                tcp_flags: 0x12,
                ttl: 57,
                ip_proto: 6,
                mac: None,
                ip6: None,
            })
            .unwrap();
            p.finish().unwrap();
        }
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "#masscan\nopen tcp 80 1.2.3.4 1700000042\n# end\n"
        );
    }

    // ---- Записи баннеров: путь `output_report_banner` (`src/output.c:886-956`, справка A1). ----

    use rmasscan_proto::{BannerRecord, app_id};

    fn dns_banner() -> BannerRecord {
        BannerRecord {
            timestamp: 1_700_000_000,
            ip: Ipv4Addr::new(192, 0, 2, 1).into(),
            ip_proto: 17,
            port: 53,
            app: app_id::DNS_VERSIONBIND,
            ttl: 57,
            payload: b"9.18.24".to_vec(),
        }
    }

    fn http_banner() -> BannerRecord {
        BannerRecord {
            ip: Ipv4Addr::new(1, 2, 3, 4).into(),
            ip_proto: 6,
            port: 80,
            app: app_id::HTTP,
            payload: b"HTTP/1.0 200 OK".to_vec(),
            ..dns_banner()
        }
    }

    enum Item {
        S(Record),
        B(BannerRecord),
    }

    /// `open`, записи статуса и баннеров в порядке прихода, `finish`; возвращает stdout.
    fn run_items(opts: OutputOptions, items: &[Item]) -> String {
        let wall = FakeWall(1_700_000_100);
        let mut out = Vec::new();
        {
            let mut p = Pipeline::new(opts, &mut out, env(&wall));
            p.open().unwrap();
            for i in items {
                match i {
                    Item::S(r) => p.report_record(r).unwrap(),
                    Item::B(b) => p.report_banner(b).unwrap(),
                }
            }
            p.finish().unwrap();
        }
        String::from_utf8(out).unwrap()
    }

    fn pad79(head: &str) -> String {
        format!("{head:<79}\n")
    }

    /// `src/output.c:903-923`: `Banner on port %u/%s on %s: [%s] %s`, пробелы до 79 символов, если строка короче 80,
    /// затем `\n`. Условие то же, что у статуса: формат по умолчанию, `interactive` или `--interactive`.
    #[test]
    fn console_banner_line_padded_to_79() {
        let head = "Banner on port 53/udp on 192.0.2.1: [dns-ver] 9.18.24";
        let out = run_items(OutputOptions::default(), &[Item::B(dns_banner())]);
        assert_eq!(out, format!("{head}{}\n", " ".repeat(79 - head.len())));
        assert_eq!(out.len(), 80);
        // Строка ровно в 79 и в 80 символов не дополняется; экранирование `normalize_string`.
        let base = "Banner on port 53/udp on 192.0.2.1: [dns-ver] ".len();
        for n in [79 - base, 80 - base, 200] {
            let b = BannerRecord {
                payload: vec![b'x'; n],
                ..dns_banner()
            };
            let out = run_items(OutputOptions::default(), &[Item::B(b)]);
            assert_eq!(out.len(), base + n + 1, "{n}");
            assert!(out.ends_with("x\n"), "{n}");
        }
        let odd = BannerRecord {
            ip: std::net::IpAddr::V6("2001:db8::1".parse().unwrap()),
            ip_proto: 99,
            app: 40,
            payload: b"\r\n".to_vec(),
            ..dns_banner()
        };
        assert_eq!(
            run_items(OutputOptions::default(), &[Item::B(odd)]),
            pad79("Banner on port 53/err on 2001:db8::1: [(40)] \\x0d\\x0a")
        );
        // `--output-format interactive` печатает, `none` нет; формат файла печатает только с `--interactive`.
        assert_eq!(
            run_items(opts(Format::Interactive, None), &[Item::B(dns_banner())]),
            pad79(head)
        );
        assert!(run_items(opts(Format::None, None), &[Item::B(dns_banner())]).is_empty());
        let scratch = Scratch::new();
        let path = scratch.path("console.list");
        assert!(run_items(opts(Format::List, path.to_str()), &[Item::B(dns_banner())]).is_empty());
        let mut o = opts(Format::List, path.to_str());
        o.interactive = true;
        assert_eq!(run_items(o, &[Item::B(dns_banner())]), pad79(head));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "#masscan\nbanner udp 53 192.0.2.1 1700000000 dns-ver 9.18.24\n# end\n"
        );
        // Статус и баннер вперемешку в порядке прихода.
        let out = run_items(
            OutputOptions::default(),
            &[Item::S(open_rec()), Item::B(http_banner())],
        );
        assert_eq!(
            out,
            [
                discovered_line(Ipv4Addr::new(1, 2, 3, 4), 80),
                pad79("Banner on port 80/tcp on 1.2.3.4: [http] HTTP/1.0 200 OK"),
            ]
            .concat()
        );
    }

    /// Справка A1.3-4: у баннера нет фильтра show (`--noshow open` его не прячет) и нет счётчиков (`<hosts up=…>`
    /// `-oX` баннеры не считает, даже TCP).
    #[test]
    fn banner_ignores_show_filter_and_counts() {
        let noshow = |o: OutputOptions| OutputOptions {
            show_open: false,
            ..o
        };
        let out = run_items(
            noshow(OutputOptions::default()),
            &[Item::S(open_rec()), Item::B(dns_banner())],
        );
        assert_eq!(
            out,
            pad79("Banner on port 53/udp on 192.0.2.1: [dns-ver] 9.18.24")
        );
        let out = run_items(
            noshow(opts(Format::Xml, Some("-"))),
            &[
                Item::S(open_rec()),
                Item::B(dns_banner()),
                Item::B(http_banner()),
            ],
        );
        assert_eq!(out.matches("<host endtime=").count(), 2, "{out}");
        assert!(!out.contains("reason_ttl=\"57\"/>"), "{out}");
        assert!(
            out.contains("<hosts up=\"0\" down=\"0\" total=\"0\" />"),
            "{out}"
        );
        let out = run_items(
            opts(Format::Xml, Some("-")),
            &[
                Item::S(open_rec()),
                Item::B(http_banner()),
                Item::B(http_banner()),
            ],
        );
        assert_eq!(out.matches("<host endtime=").count(), 3, "{out}");
        assert!(
            out.contains("<hosts up=\"1\" down=\"0\" total=\"1\" />"),
            "{out}"
        );
    }

    /// Справка A1.7: без файла баннер молча теряется (`if (fp == NULL) return;`), без строк `no output file`.
    #[test]
    fn banner_without_file_is_silent() {
        assert!(run_items(opts(Format::List, None), &[Item::B(dns_banner())]).is_empty());
        assert!(run_items(opts(Format::Binary, None), &[Item::B(dns_banner())]).is_empty());
        // Формат без файла (`null_output`) файл не открывает: только строка консоли.
        let scratch = Scratch::new();
        let path = scratch.path("default-banner");
        assert_eq!(
            run_items(
                opts(Format::Default, path.to_str()),
                &[Item::B(dns_banner())]
            ),
            pad79("Banner on port 53/udp on 192.0.2.1: [dns-ver] 9.18.24")
        );
        assert!(run_items(opts(Format::None, path.to_str()), &[Item::B(dns_banner())]).is_empty());
        assert!(!path.exists());
    }

    /// Справка A1.9: баннер может открыть файл (ленивый заголовок) и делает его «не девственным», поэтому подвал
    /// пишется, даже когда запись формата пуста или выброшена (`-oB` от 16 370 байт).
    #[test]
    fn banner_triggers_lazy_header() {
        let scratch = Scratch::new();
        let path = scratch.path("banner.list");
        assert!(run_items(opts(Format::List, path.to_str()), &[Item::B(dns_banner())]).is_empty());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "#masscan\nbanner udp 53 192.0.2.1 1700000000 dns-ver 9.18.24\n# end\n"
        );
        assert_eq!(
            run_items(opts(Format::Json, Some("-")), &[Item::B(dns_banner())]),
            "[\n{   \"ip\": \"192.0.2.1\",   \"timestamp\": \"1700000000\", \"ports\": [ {\"port\": 53, \"proto\": \"udp\", \"service\": {\"name\": \"dns-ver\", \"banner\": \"9.18.24\"} } ] }\n]\n"
        );
        let xml = run_items(opts(Format::Xml, Some("-")), &[Item::B(dns_banner())]);
        assert!(xml.starts_with("<?xml version=\"1.0\"?>\r\n"), "{xml}");
        assert!(
            xml.contains("reason=\"syn-ack\" reason_ttl=\"57\" />"),
            "{xml}"
        );
        assert!(
            xml.ends_with(
                "<hosts up=\"0\" down=\"0\" total=\"0\" />\r\n</runstats>\r\n</nmaprun>\r\n"
            ),
            "{xml}"
        );
        let bin_path = scratch.path("dropped.bin");
        let huge = BannerRecord {
            payload: vec![b'A'; 16_370],
            ..dns_banner()
        };
        run_items(opts(Format::Binary, bin_path.to_str()), &[Item::B(huge)]);
        let bin = std::fs::read(&bin_path).unwrap();
        let mut want = b"masscan/1.1\ns:1700000100\n".to_vec();
        want.resize(99, 0);
        let mut foot = b"masscan/1.1".to_vec();
        foot.resize(99, 0);
        want.extend_from_slice(&foot);
        assert_eq!(bin, want);
    }

    /// `src/out-unicornscan.c:61-79`: запись баннера пуста, но файл из одних баннеров получает заголовок и подвал.
    #[test]
    fn unicornscan_banner_only_file_is_header_footer() {
        let scratch = Scratch::new();
        let path = scratch.path("u.txt");
        assert!(
            run_items(
                opts(Format::Unicornscan, path.to_str()),
                &[Item::B(dns_banner()), Item::B(http_banner())]
            )
            .is_empty()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "#masscan\n# end\n");
    }

    fn pem(body: &[u8]) -> String {
        let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
        for c in body.chunks(72) {
            s.push_str(std::str::from_utf8(c).unwrap());
            s.push('\n');
        }
        s + "-----END CERTIFICATE-----\n"
    }

    /// `src/out-certs.c`: PEM каждого баннера (любого app) идёт в stdout, файл получает только `{finished: 1}\n` при
    /// закрытии, если его коснулась хоть одна запись; статус ничего не пишет.
    #[test]
    fn certs_prints_pem_to_stdout_and_finished_to_file() {
        let scratch = Scratch::new();
        let path = scratch.path("certs.out");
        let body: Vec<u8> = (0..100u32).map(|i| b'a' + (i % 26) as u8).collect();
        let mut payload = b"cert:".to_vec();
        payload.extend_from_slice(&body);
        let cert = BannerRecord {
            ip_proto: 6,
            port: 443,
            app: app_id::X509_CERT,
            payload,
            ..dns_banner()
        };
        let o = opts(Format::Certs, path.to_str());
        let out = run_items(
            o.clone(),
            &[
                Item::S(open_rec()),
                Item::B(cert.clone()),
                Item::B(dns_banner()),
            ],
        );
        assert_eq!(out, pem(&body) + &pem(b"9.18.24"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{finished: 1}\n");
        // Только статус: stdout пуст (формат не консольный), файл тронут, подвал есть.
        assert!(run_items(o.clone(), &[Item::S(open_rec())]).is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{finished: 1}\n");
        // Ни одной записи: файл пуст.
        assert!(run_items(o.clone(), &[]).is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        // `--interactive`: строка консоли раньше PEM (`src/output.c:903-952`).
        let mut oi = o;
        oi.interactive = true;
        assert_eq!(
            run_items(oi, &[Item::B(dns_banner())]),
            pad79("Banner on port 53/udp on 192.0.2.1: [dns-ver] 9.18.24") + &pem(b"9.18.24")
        );
        // Файл `-` это тот же stdout: PEM, затем подвал.
        assert_eq!(
            run_items(opts(Format::Certs, Some("-")), &[Item::B(cert)]),
            pem(&body) + "{finished: 1}\n"
        );
    }

    /// `if (out->is_output_flush) fflush(fp);` (`src/output.c:954-955`): flush файла после каждой записи баннера.
    #[test]
    fn banner_flushes_file_with_output_flush() {
        let wall = FakeWall(1_700_000_100);
        for (flush, expect) in [(true, 2), (false, 0)] {
            let mut w = Counting {
                bytes: Vec::new(),
                flushes: 0,
            };
            let mut o = opts(Format::Hostonly, Some("-"));
            o.flush = flush;
            let mut p = Pipeline::new(o, &mut w, env(&wall));
            p.open().unwrap();
            p.report_banner(&dns_banner()).unwrap();
            Sink::report_banner(&mut p, &http_banner()).unwrap();
            drop(p);
            assert_eq!(w.flushes, expect);
            assert_eq!(w.bytes, b"192.0.2.1\n1.2.3.4\n");
        }
    }
}
