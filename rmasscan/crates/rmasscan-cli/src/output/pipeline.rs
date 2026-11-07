//! Конвейер вывода (AGPL-3.0). Порт `output_create`/`output_report_status`/`close_rotate` (`output.c:389–515`,
//! `:746–880`, `:247–269`) masscan © Robert David Graham: фильтр show, интерактивная строка, счётчики, ленивый
//! заголовок при первой записи, запись, flush; подвал только если была хотя бы одна запись (Р7). Время записи это
//! Unix-секунды в момент обработки пачки (Р9). Перевод строки никогда не превращается в `\r\n`: байты одинаковы
//! на всех ОС.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};

use rmasscan_core::receive::Reply;

use super::formats::{Counts, FileCtx, Format, Formatter, formatter};
use super::record::{Record, Status, status_str};
use super::services::ServiceNames;
use super::{Sink, WriteTarget, io_fail, write_failed};

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
            // Реальный формат без файла: C молча теряет запись (`output.c:799–803`). Из `crate::run` сюда не дойти:
            // он отклоняет такие опции до скана и до чтения `--readscan`.
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
    fn grepable_and_unicornscan_create_their_files() {
        for (f, name, head) in [
            (
                Format::Grepable,
                "g.gnmap",
                "# Masscan 1.3.9-integration scan initiated",
            ),
            (Format::Unicornscan, "u.txt", "#masscan\n"),
        ] {
            let path = tmp(name);
            std::fs::write(&path, "stale").unwrap();
            let o = opts(f, path.to_str());
            assert!(run(o, &[open_rec()]).is_empty());
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(text.starts_with(head), "{text}");
            assert!(!text.contains("stale"));
            let _ = std::fs::remove_file(&path);
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
        let path = tmp("dead-reader.fifo");
        let _ = std::fs::remove_file(&path);
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
        let _ = std::fs::remove_file(&path);
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
