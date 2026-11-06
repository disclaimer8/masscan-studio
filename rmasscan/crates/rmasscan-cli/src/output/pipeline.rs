//! Конвейер вывода (AGPL-3.0). Порт `output_create`/`output_report_status`/`close_rotate` (`output.c:389–515`,
//! `:746–880`, `:247–269`) masscan © Robert David Graham: фильтр show, интерактивная строка, счётчики, ленивый
//! заголовок при первой записи, запись, flush; подвал только если была хотя бы одна запись (Р7). Время записи это
//! Unix-секунды в момент обработки пачки (Р9). Перевод строки никогда не превращается в `\r\n`: байты одинаковы
//! на всех ОС.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};

use rmasscan_core::receive::Reply;

use super::formats::{Counts, FileCtx, Format, Formatter, formatter};
use super::record::{Record, Status, status_str};
use super::services::ServiceNames;
use super::{Sink, io_fail};

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

pub struct OutputEnv<'a> {
    pub wall: &'a dyn Wall,
    pub services: ServiceNames,
    pub tcp_ports: Vec<(u16, u16)>,
    /// Начало скана; `None` значит «момент `open()`», `Some(0)` значит «из первой записи» (`--readscan`).
    pub scan_started: Option<u64>,
}

enum Target {
    /// Файл не открыт (или не нужен).
    Closed,
    Stdout,
    File(BufWriter<File>),
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

    /// `if (out->when_scan_started == 0) out->when_scan_started = record.timestamp` (`in-binary.c`).
    pub fn set_scan_started_if_unset(&mut self, ts: u64) {
        if self.scan_started == 0 {
            self.scan_started = ts;
        }
    }

    fn interactive_line(&self) -> bool {
        self.opts.interactive || matches!(self.opts.format, Format::Default | Format::Interactive)
    }

    /// `output.c:746–880` (справка §2) для одной записи.
    pub fn report_record(&mut self, r: &Record) -> Result<(), String> {
        let show = match r.status {
            Status::Open => self.opts.show_open,
            Status::Closed => self.opts.show_closed,
        };
        if !show {
            return Ok(());
        }
        if self.interactive_line() {
            let head = format!(
                "Discovered {} port {}/tcp on {}",
                status_str(r.status),
                r.port,
                r.ip
            );
            let line = format!("{head:<79}\n");
            self.stdout.write_all(line.as_bytes()).map_err(io_fail)?;
            self.stdout.flush().map_err(io_fail)?;
        }
        let Some(fm) = self.formatter.as_mut() else {
            return Ok(());
        };
        if matches!(self.target, Target::Closed) {
            // C: нет файла и формат не интерактивный; запись теряется (Задача 4 сообщает об этом заранее).
            return Ok(());
        }
        match r.status {
            Status::Open => self.counts.open += 1,
            Status::Closed => self.counts.closed += 1,
        }
        let now = self.env.wall.unix_time();
        let cx = FileCtx {
            now,
            utc_offset_secs: self.env.wall.utc_offset_secs(now),
            scan_started: self.scan_started,
            file_opened: self.file_opened,
            counts: self.counts,
            stylesheet: self.opts.stylesheet.as_deref(),
            tcp_ports: &self.env.tcp_ports,
            services: &self.env.services,
        };
        let w: &mut dyn Write = match &mut self.target {
            Target::Stdout => &mut *self.stdout,
            Target::File(f) => f,
            Target::Closed => return Ok(()),
        };
        if self.virgin {
            fm.header(w, &cx).map_err(io_fail)?;
            self.virgin = false;
        }
        fm.record(w, &cx, r).map_err(io_fail)?;
        if self.opts.flush {
            w.flush().map_err(io_fail)?;
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
                    return Err(format!("out: could not open file for {how}\n{name}: {e}"));
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
            tcp_ports: &self.env.tcp_ports,
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
                if let (false, Some(fm)) = (virgin, self.formatter.as_mut()) {
                    fm.footer(&mut f, &cx).map_err(io_fail)?;
                }
                f.flush().map_err(io_fail)?;
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
    use std::io;
    use std::net::Ipv4Addr;
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
            tcp_ports: Vec::new(),
            scan_started: None,
        }
    }

    fn open_rec() -> Record {
        Record {
            timestamp: 1_700_000_000,
            ip: Ipv4Addr::new(1, 2, 3, 4),
            port: 80,
            status: Status::Open,
            reason: 0x12,
            ttl: 57,
        }
    }

    fn closed_rec() -> Record {
        Record {
            timestamp: 1_700_000_000,
            ip: Ipv4Addr::new(10, 0, 0, 255),
            port: 443,
            status: Status::Closed,
            reason: 0x14,
            ttl: 64,
        }
    }

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("rmasscan-pipeline-{}-{name}", std::process::id()))
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

    #[test]
    fn default_format_opens_no_file() {
        let path = tmp("default-nofile");
        let _ = std::fs::remove_file(&path);
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
        let path = tmp("silent.list");
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
        let _ = std::fs::remove_file(&path);
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
        let path = tmp("lazy.json");
        run(opts(Format::Json, path.to_str()), &[]);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        run(opts(Format::Json, path.to_str()), &[open_rec()]);
        let t = std::fs::read_to_string(&path).unwrap();
        assert!(t.starts_with("[\n{   \"ip\": \"1.2.3.4\""));
        assert!(t.ends_with("} ] }\n]\n"));
        let _ = std::fs::remove_file(&path);
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
        let path = tmp("append.list");
        let _ = std::fs::remove_file(&path);
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
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_failure_message_matches_c() {
        let dir = std::env::temp_dir();
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
            })
            .unwrap();
            p.finish().unwrap();
        }
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "#masscan\nopen tcp 80 1.2.3.4 1700000042\n# end\n"
        );
    }
}
