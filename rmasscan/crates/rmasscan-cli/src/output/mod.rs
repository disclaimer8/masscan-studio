//! Приёмник результатов скана (AGPL-3.0). Порт `output.c:781-795` masscan ©
//! Robert David Graham: строка `Discovered open port N/tcp on IP`,
//! дополненная пробелами до 79 символов, `\n`, flush на каждую строку.
//! Closed не печатается (`is_show_closed = 0`). Записи баннеров печатаются строкой `Banner on port …`
//! (`src/output.c:903-923`, [`banner_line`]).
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
use rmasscan_proto::BannerRecord;

pub use formats::{Counts, FileCtx, Format, Formatter, formatter};
pub use pipeline::{OPEN_FAILURE_PREFIX, OutputEnv, OutputOptions, Pipeline, Wall};
pub use record::{
    CIp, MASSCAN_VERSION, Proto, Record, Status, ip_proto_name, proto_str, reason_string,
    status_str,
};
pub use services::ServiceNames;

/// Куда идут результаты. Приёмник этапа 2 реализует тот же трейт.
pub trait Sink {
    /// Открывает выходной файл до ARP и engine (Р8); ошибка значит «ни одного кадра».
    fn open(&mut self) -> Result<(), String>;
    fn report(&mut self, reply: &Reply) -> Result<(), String>;
    /// Запись баннера (`output_report_banner`, `src/output.c:886-956`): без фильтра show и без счётчиков.
    fn report_banner(&mut self, b: &BannerRecord) -> Result<(), String>;
    /// Баннер ответа, который последним прошёл через [`Sink::report`] (живой скан: движок выдаёт баннеры ответа сразу
    /// за ним, `rmasscan_engine::Output`).
    ///
    /// Контракт: `b.timestamp` от движка всегда 0 (у `Reply` времени нет). Приёмник, который пишет время, обязан
    /// поставить баннеру время записи статуса этого ответа: у C оба получают `secs` одного кадра (`src/main.c:915`,
    /// справка A0), у rmasscan время статуса это момент обработки (Р9 этапа вывода). Метод обязательный, чтобы новый
    /// приёмник не унаследовал молча время 0 (1970 год в выводе).
    fn report_reply_banner(&mut self, b: BannerRecord) -> Result<(), String>;
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
                CIp(r.ip),
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
            CIp(r.ip)
        ),
    };
    format!("{head:<79}\n")
}

/// Строка консоли записи баннера (`src/output.c:903-923`): `Banner on port %u/%s on %s: [%s] %s`, баннер через
/// `normalize_string` (только ASCII, поэтому символы равны байтам `fprintf`), пробелы до 79 символов, если строка
/// короче 80 байт, затем `\n`.
pub fn banner_line(b: &BannerRecord) -> String {
    let head = format!(
        "Banner on port {}/{} on {}: [{}] {}",
        b.port,
        ip_proto_name(b.ip_proto),
        CIp(b.ip),
        rmasscan_proto::app_name(b.app),
        rmasscan_proto::normalize_string(&b.payload)
    );
    format!("{head:<79}\n")
}

/// Интерактивный вывод masscan: строки open и ARP (`up`) по [`interactive_line`], closed не печатается
/// (`is_show_closed = 0`), flush на строку.
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

    fn report_banner(&mut self, b: &BannerRecord) -> Result<(), String> {
        // Фильтра show у баннера нет (`src/output.c:886-956`). C не делает здесь `fflush(stdout)`, но его stdout у
        // терминала построчный; flush даёт тот же момент вывода, байты те же.
        self.out
            .write_all(banner_line(b).as_bytes())
            .map_err(io_fail)?;
        self.out.flush().map_err(io_fail)
    }

    /// Строка `Banner on port …` времени не печатает (`src/output.c:903-923`): метку ставить некуда.
    fn report_reply_banner(&mut self, b: BannerRecord) -> Result<(), String> {
        self.report_banner(&b)
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
            ip6: None,
        }
    }

    /// R10: an IPv6 reply (`remote_ip == 0`, address in `Reply.ip6`) must never print `0.0.0.0`; the interactive
    /// line is `Discovered open port 443/tcp on <ipv6address_fmt>` (`output.c:781-786`).
    #[test]
    fn ipv6_reply_prints_its_ipv6_address_not_0_0_0_0() {
        use rmasscan_core::receive::ReplyIpv6;
        let remote: u128 = "2a03:9060:0:400::2"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .into();
        let mut r = reply(Ipv4Addr::UNSPECIFIED, 443, PortStatus::Open);
        r.ip6 = Some(ReplyIpv6 { remote, local: 1 });
        let rec = Record::from_reply(&r, 1_700_000_000);
        assert_eq!(rec.ip, std::net::IpAddr::V6(remote.into()));
        let line = interactive_line(&rec);
        assert_eq!(
            line,
            format!(
                "{:<79}\n",
                "Discovered open port 443/tcp on 2a03:9060::400:0:0:0:2"
            )
        );
        assert!(!line.contains("0.0.0.0"));
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

    /// Консольный приёмник печатает и баннеры: строка `src/output.c:903-923`, пробелы до 79, `\n`.
    #[test]
    fn interactive_sink_prints_banner_lines() {
        let b = rmasscan_proto::BannerRecord {
            timestamp: 1_700_000_000,
            ip: Ipv4Addr::new(192, 0, 2, 1).into(),
            ip_proto: 17,
            port: 53,
            app: rmasscan_proto::app_id::DNS_VERSIONBIND,
            ttl: 57,
            payload: b"9.18.24".to_vec(),
        };
        let head = "Banner on port 53/udp on 192.0.2.1: [dns-ver] 9.18.24";
        assert_eq!(banner_line(&b), format!("{head:<79}\n"));
        let mut buf = Vec::new();
        {
            let mut s = Interactive::new(&mut buf);
            s.report_banner(&b).unwrap();
            s.finish().unwrap();
        }
        assert_eq!(String::from_utf8(buf).unwrap(), format!("{head:<79}\n"));
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
