//! Приёмник результатов скана (AGPL-3.0). Порт `output.c:781-795` masscan ©
//! Robert David Graham: строка `Discovered open port N/tcp on IP`,
//! дополненная пробелами до 79 символов, `\n`, flush на каждую строку.
//! Closed не печатается (`is_show_closed = 0`).
//!
//! Модуль объединяет приёмник [`Sink`], записи ([`record`]), форматы ([`formats`]), имена сервисов ([`services`])
//! и конвейер вывода [`pipeline`] (порт `output.c`).

pub mod formats;
pub mod grepable;
pub mod oui;
pub mod pipeline;
pub mod record;
pub mod services;

use std::io::{self, Write};
use std::net::Ipv4Addr;

use rmasscan_core::receive::{PortStatus, Reply};

pub use formats::{Counts, FileCtx, Format, Formatter, formatter};
pub use pipeline::{OPEN_FAILURE_PREFIX, OutputEnv, OutputOptions, Pipeline, Wall};
pub use record::{MASSCAN_VERSION, Proto, Record, Status, proto_str, reason_string, status_str};
pub use services::ServiceNames;

/// Куда идут результаты. Приёмник этапа 2 реализует тот же трейт.
pub trait Sink {
    /// Открывает выходной файл до ARP и engine (Р8); ошибка значит «ни одного кадра».
    fn open(&mut self) -> Result<(), String>;
    fn report(&mut self, reply: &Reply) -> Result<(), String>;
    fn finish(&mut self) -> Result<(), String>;
}

/// Куда шла запись, которая не удалась.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteTarget {
    /// stdout процесса, в том числе файл вывода `-`.
    Stdout,
    /// Файл `-o…` по имени, в том числе FIFO и `/dev/fd/N`.
    File,
}

/// Чем кончается ошибка записи.
#[derive(Debug, PartialEq, Eq)]
pub enum WriteFailure {
    /// Читатель stdout ушёл (`| head`): C убивает SIGPIPE, rmasscan выходит сразу, тихо и с кодом 0.
    ExitQuietly,
    /// Ошибка приёмника: скан останавливается, `[+] finished` печатается, код 1.
    Error(String),
}

/// Решение по ошибке записи без побочных эффектов: тихий выход только для закрытого stdout. EPIPE файла (FIFO или
/// `/dev/fd/N`, читатель которого умер) это обычная ошибка записи.
pub fn write_failure(target: WriteTarget, e: &io::Error) -> WriteFailure {
    if target == WriteTarget::Stdout && e.kind() == io::ErrorKind::BrokenPipe {
        WriteFailure::ExitQuietly
    } else {
        WriteFailure::Error(format!("write failed: {e}"))
    }
}

/// Текст ошибки записи в `target` по [`write_failure`]; закрытый stdout завершает процесс с кодом 0, не доделывая
/// работу.
pub fn write_failed(target: WriteTarget, e: io::Error) -> String {
    match write_failure(target, &e) {
        WriteFailure::ExitQuietly => std::process::exit(0),
        WriteFailure::Error(msg) => msg,
    }
}

/// Ошибка записи в поток процесса (stdout, у `--readscan` ещё и журнал stderr): [`write_failed`] для
/// [`WriteTarget::Stdout`].
pub fn io_fail(e: io::Error) -> String {
    write_failed(WriteTarget::Stdout, e)
}

/// `Discovered open port {port}/tcp on {ip}`, пробелы до 79 символов, `\n`.
pub fn discovered_line(ip: Ipv4Addr, port: u16) -> String {
    format!(
        "{:<79}\n",
        format!("Discovered open port {port}/tcp on {ip}")
    )
}

/// Интерактивная строка записи (`output.c:766–790`). У ARP после адреса идут MAC строчными шестнадцатеричными
/// через двоеточие, пробел и строка производителя ([`oui::oui_from_mac`]; пробел остаётся и при пустой строке).
/// Строка короче 80 байт дополняется пробелами до 79 символов, длиннее не трогается; затем `\n`.
pub fn interactive_line(r: &Record) -> String {
    let head = match r.proto {
        Proto::Arp => {
            let m = r.mac.unwrap_or([0; 6]);
            format!(
                "Discovered {} port {}/{} on {} ({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}) {}",
                status_str(r.status),
                r.port,
                proto_str(r.proto),
                r.ip,
                m[0],
                m[1],
                m[2],
                m[3],
                m[4],
                m[5],
                oui::oui_from_mac(&m)
            )
        }
        _ => format!(
            "Discovered {} port {}/{} on {}",
            status_str(r.status),
            r.port,
            proto_str(r.proto),
            r.ip
        ),
    };
    format!("{head:<79}\n")
}

/// Интерактивный вывод masscan: только open, flush на строку.
pub struct Interactive<W: Write> {
    out: W,
}

impl<W: Write> Interactive<W> {
    pub fn new(out: W) -> Self {
        Interactive { out }
    }
}

impl<W: Write> Sink for Interactive<W> {
    fn open(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn report(&mut self, reply: &Reply) -> Result<(), String> {
        // Closed не печатается (`is_show_closed = 0`); open и ARP печатаются своей строкой.
        if reply.status == PortStatus::Closed {
            return Ok(());
        }
        let line = interactive_line(&Record::from_reply(reply, 0));
        self.out.write_all(line.as_bytes()).map_err(io_fail)?;
        self.out.flush().map_err(io_fail)
    }

    fn finish(&mut self) -> Result<(), String> {
        self.out.flush().map_err(io_fail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmasscan_core::receive::{PortStatus, Reply};
    use std::io::{self, Write};
    use std::net::Ipv4Addr;

    fn reply(ip: Ipv4Addr, port: u16, status: PortStatus) -> Reply {
        Reply {
            remote_ip: ip.into(),
            remote_port: port,
            local_ip: 0x0a00_0002,
            local_port: 40000,
            status,
            tcp_flags: 0x12,
            ttl: 64,
            ip_proto: 6,
            mac: None,
        }
    }

    #[test]
    fn discovered_line_matches_masscan_byte_for_byte() {
        let l = discovered_line(Ipv4Addr::new(10, 0, 0, 1), 80);
        let expect = format!(
            "Discovered open port 80/tcp on 10.0.0.1{}\n",
            " ".repeat(40)
        );
        assert_eq!(l, expect);
        assert_eq!(l.len(), 80);
        let l = discovered_line(Ipv4Addr::new(198, 18, 0, 2), 443);
        let head = "Discovered open port 443/tcp on 198.18.0.2";
        assert_eq!(head.len(), 42);
        assert_eq!(l, format!("{head}{}\n", " ".repeat(37)));
    }

    #[test]
    fn closed_replies_are_not_printed() {
        let mut buf = Vec::new();
        {
            let mut s = Interactive::new(&mut buf);
            s.report(&reply(Ipv4Addr::new(10, 0, 0, 1), 80, PortStatus::Closed))
                .unwrap();
            s.finish().unwrap();
        }
        assert!(buf.is_empty());
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
    fn each_line_is_flushed() {
        let mut w = Counting {
            bytes: Vec::new(),
            flushes: 0,
        };
        {
            let mut s = Interactive::new(&mut w);
            for p in [80u16, 81, 82] {
                s.report(&reply(Ipv4Addr::new(10, 0, 0, 1), p, PortStatus::Open))
                    .unwrap();
            }
        }
        assert_eq!(w.flushes, 3);
        assert_eq!(w.bytes.len(), 3 * 80);
    }

    /// Тихий выход только для закрытого stdout (`| head`); EPIPE файла (FIFO, `/dev/fd/N`) и любая другая ошибка
    /// на любой цели это текст ошибки приёмника.
    #[test]
    fn only_a_broken_stdout_exits_quietly() {
        let pipe = || io::Error::new(io::ErrorKind::BrokenPipe, "Broken pipe");
        assert_eq!(
            write_failure(WriteTarget::Stdout, &pipe()),
            WriteFailure::ExitQuietly
        );
        assert_eq!(
            write_failure(WriteTarget::File, &pipe()),
            WriteFailure::Error("write failed: Broken pipe".into())
        );
        for target in [WriteTarget::Stdout, WriteTarget::File] {
            let full = io::Error::other("No space left on device");
            assert_eq!(
                write_failure(target, &full),
                WriteFailure::Error("write failed: No space left on device".into()),
                "{target:?}"
            );
            assert_eq!(
                write_failed(target, full),
                "write failed: No space left on device"
            );
        }
        assert_eq!(
            write_failed(WriteTarget::File, pipe()),
            "write failed: Broken pipe"
        );
    }

    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    const CHILD_ENV: &str = "RMASSCAN_BROKEN_PIPE_CHILD";

    /// Работает только в дочернем процессе родительского теста: закрытый канал
    /// обязан завершить процесс кодом 0 (как `io_fail` в `-sL`), а не вернуть
    /// ошибку. Если `report` вернулся, паника даёт код 101.
    #[test]
    fn broken_pipe_child() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        let mut s = Interactive::new(Broken);
        let r = s.report(&reply(Ipv4Addr::new(10, 0, 0, 1), 80, PortStatus::Open));
        panic!("broken pipe did not exit: {r:?}");
    }

    #[test]
    fn broken_pipe_exits_zero() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "output::tests::broken_pipe_child", "--nocapture"])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
