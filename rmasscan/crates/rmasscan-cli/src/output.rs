//! Приёмник результатов скана (AGPL-3.0). Порт `output.c:781-795` masscan ©
//! Robert David Graham: строка `Discovered open port N/tcp on IP`,
//! дополненная пробелами до 79 символов, `\n`, flush на каждую строку.
//! Closed не печатается (`is_show_closed = 0`).

use std::io::{self, Write};
use std::net::Ipv4Addr;

use rmasscan_core::receive::{PortStatus, Reply};

/// Куда идут результаты. Приёмник этапа 2 реализует тот же трейт.
pub trait Sink {
    fn report(&mut self, reply: &Reply) -> Result<(), String>;
    fn finish(&mut self) -> Result<(), String>;
}

/// Ошибка записи в stdout. Закрытый канал (`| head`) в C убивает SIGPIPE, поэтому
/// выходим сразу и тихо, не доделывая работу.
pub fn io_fail(e: io::Error) -> String {
    if e.kind() == io::ErrorKind::BrokenPipe {
        std::process::exit(0);
    }
    format!("write failed: {e}")
}

/// `Discovered open port {port}/tcp on {ip}`, пробелы до 79 символов, `\n`.
pub fn discovered_line(ip: Ipv4Addr, port: u16) -> String {
    format!(
        "{:<79}\n",
        format!("Discovered open port {port}/tcp on {ip}")
    )
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
    fn report(&mut self, reply: &Reply) -> Result<(), String> {
        if reply.status != PortStatus::Open {
            return Ok(());
        }
        let line = discovered_line(Ipv4Addr::from(reply.remote_ip), reply.remote_port);
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
