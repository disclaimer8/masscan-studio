//! CLI порта masscan (AGPL-3.0): `-sL`, `--echo`/`--echo-all` и
//! `--offline --packet-trace` поверх `rmasscan-core`. Порт `src/main.c`
//! (`main` :1595-1805, `transmit_thread` :203-448), `src/main-listscan.c` и
//! `src/main-ptrace.c` из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).

#![forbid(unsafe_code)]

mod args;

use std::io::{self, BufWriter, Write};
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::Instant;

use args::Cli;
use rmasscan_core::config::{EffectiveConfig, Operation, echo, validate};
use rmasscan_core::cookie::syn_cookie_ipv4;
use rmasscan_core::packet::{LinkType, TcpSynTemplate};
use rmasscan_core::scan::{format_list_line, list_scan, transmit_scan};

/// Одна отправка SYN в режиме `--offline` (main.c:371-402).
#[cfg_attr(not(test), allow(dead_code))] // поля читают только тесты
struct Probe<'a> {
    ip_them: u32,
    port_them: u16,
    ip_me: u32,
    port_me: u16,
    seqno: u32,
    frame: &'a [u8],
}

/// Поток кадров `transmit_thread` без сети: те же индексы, что в C
/// (`transmit_scan`), SYN-cookie и порт источника как main.c:373-393.
///
/// Требует `--adapter-ip`, `--adapter-mac`, `--router-mac` и `--source-port`:
/// в этапе 1 нет обнаружения адаптера, а C без `--source-port` берёт
/// `40000 + time(0) % 20000` (main.c:1316-1321), что недетерминированно.
fn for_each_probe(
    eff: &EffectiveConfig,
    mut f: impl FnMut(&Probe) -> Result<(), String>,
) -> Result<(), String> {
    let missing =
        |o: &str| format!("--offline --packet-trace needs {o} (stage 1 has no adapter discovery)");
    let ip_me0 = eff.adapter_ip().ok_or_else(|| missing("--adapter-ip"))?;
    let adapter_mac = eff.adapter_mac().ok_or_else(|| missing("--adapter-mac"))?;
    let router_mac = eff.router_mac().ok_or_else(|| missing("--router-mac"))?;
    let (first, last) = eff.source_port().ok_or_else(|| {
        "--offline --packet-trace needs --source-port (C picks 40000 + time(0) % 20000, \
         which is not deterministic)"
            .to_string()
    })?;
    // main.c:183-186: port_mask = last - first; ipv4_mask = 0, потому что
    // --adapter-ip принимает один адрес.
    let port_mask = u32::from(last - first);
    let ipv4_mask = 0u32;
    let tmpl = TcpSynTemplate::new(adapter_mac, router_mac, LinkType::Ethernet);
    let entropy = eff.seed();
    let mut frame = Vec::new();
    let mut err: Option<String> = None;
    transmit_scan(
        eff.massip(),
        eff.seed(),
        eff.blackrock_rounds(),
        eff.shard(),
        1,
        0,
        eff.resume_index(),
        eff.resume_count(),
        eff.retries(),
        eff.max_rate(),
        |i, repeats, xxx, ip_them, port_them| {
            if err.is_some() {
                return;
            }
            let (ip_me, port_me) = if ipv4_mask != 0 || port_mask != 0 {
                let n = i.wrapping_add(repeats);
                // main.c:379-384.
                let ck = syn_cookie_ipv4(
                    n as u32,
                    (n >> 32) as u32,
                    xxx as u32,
                    (xxx >> 32) as u32,
                    entropy,
                );
                (
                    ip_me0.wrapping_add(((ck >> 16) as u32) & ipv4_mask),
                    u32::from(first).wrapping_add(ck as u32 & port_mask),
                )
            } else {
                (ip_me0, u32::from(first))
            };
            let (Ok(port_them16), Ok(port_me16)) =
                (u16::try_from(port_them), u16::try_from(port_me))
            else {
                err = Some(format!(
                    "port {port_them}/{port_me} does not fit TCP (v1 is TCP only)"
                ));
                return;
            };
            // main.c:389/:402: seqno = (unsigned)cookie.
            let seqno = syn_cookie_ipv4(ip_them, port_them, ip_me, port_me, entropy) as u32;
            tmpl.build_syn(ip_them, port_them16, ip_me, port_me16, seqno, &mut frame);
            if let Err(e) = f(&Probe {
                ip_them,
                port_them: port_them16,
                ip_me,
                port_me: port_me16,
                seqno,
                frame: &frame,
            }) {
                err = Some(e);
            }
        },
    )
    .map_err(|e| e.to_string())?;
    err.map_or(Ok(()), Err)
}

/// main-ptrace.c:97: `SENT (%5.4f) TCP  %-21s > %-21s %s`. Адреса и флаги
/// разбираются из самого кадра, как `preprocess_frame` в C.
fn trace_line(secs: f64, frame: &[u8]) -> String {
    let (ip, tcp) = (14, 34);
    let src = Ipv4Addr::new(
        frame[ip + 12],
        frame[ip + 13],
        frame[ip + 14],
        frame[ip + 15],
    );
    let dst = Ipv4Addr::new(
        frame[ip + 16],
        frame[ip + 17],
        frame[ip + 18],
        frame[ip + 19],
    );
    let sport = u16::from_be_bytes([frame[tcp], frame[tcp + 1]]);
    let dport = u16::from_be_bytes([frame[tcp + 2], frame[tcp + 3]]);
    let flags = match frame[tcp + 13] {
        0x02 => "SYN".to_string(),
        other => format!("flags-{other:#04x}"),
    };
    format!(
        "SENT ({secs:5.4}) TCP  {:<21} > {:<21} {flags}\n",
        format!("[{src}]:{sport}"),
        format!("[{dst}]:{dport}")
    )
}

/// Ошибка записи в stdout. Закрытый канал (`| head`) в C убивает SIGPIPE, поэтому
/// выходим сразу и тихо, не доделывая работу.
fn io_fail(e: io::Error) -> String {
    if e.kind() == io::ErrorKind::BrokenPipe {
        std::process::exit(0);
    }
    format!("write failed: {e}")
}

fn write_out(out: &mut dyn Write, s: &str) -> Result<(), String> {
    out.write_all(s.as_bytes()).map_err(io_fail)
}

/// Явный flush на успешном пути: ошибка последнего блока не теряется в drop.
fn finish(out: &mut dyn Write) -> Result<(), String> {
    out.flush().map_err(io_fail)
}

fn run(cli: &Cli, out: &mut dyn Write) -> Result<(), String> {
    let cfg = cli.to_config()?;
    if cli.echo || cli.echo_all {
        // main.c:1799-1805: оба режима зовут masscan_echo(.., 0).
        validate(&cfg, Operation::Echo).map_err(|e| e.to_string())?;
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        write_out(out, &s)?;
        return finish(out);
    }
    if cli.list {
        let eff = validate(&cfg, Operation::List).map_err(|e| e.to_string())?;
        let single_port = eff.massip().count_ports() == 1;
        let mut res = Ok(());
        list_scan(
            eff.massip(),
            eff.seed(),
            eff.blackrock_rounds(),
            eff.shard(),
            eff.resume_index(),
            eff.resume_count(),
            eff.retries(),
            eff.max_rate(),
            |ip, port| {
                if res.is_ok() {
                    let mut line = format_list_line(ip, port, single_port);
                    line.push('\n');
                    res = write_out(out, &line);
                }
            },
        )
        .map_err(|e| e.to_string())?;
        res?;
        return finish(out);
    }
    if cli.offline && cli.packet_trace {
        let eff = validate(&cfg, Operation::Scan).map_err(|e| e.to_string())?;
        let start = Instant::now();
        for_each_probe(&eff, |p| {
            write_out(out, &trace_line(start.elapsed().as_secs_f64(), p.frame))
        })?;
        return finish(out);
    }
    Err("stage 1 supports only -sL, --echo/--echo-all and --offline --packet-trace".into())
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse_masscan(std::env::args()) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    match run(&cli, &mut out) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            let _ = out.flush();
            eprintln!("rmasscan: error: {msg}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_args(args: &[&str]) -> Result<String, String> {
        let cli = Cli::try_parse_masscan(args.iter().copied()).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        run(&cli, &mut out)?;
        Ok(String::from_utf8(out).unwrap())
    }

    #[test]
    fn unsupported_option_errors() {
        assert!(Cli::try_parse_masscan(["rmasscan", "--banners", "10.0.0.0/24", "-p80"]).is_err());
        assert!(Cli::try_parse_masscan(["rmasscan", "--nonsense"]).is_err());
        assert!(Cli::try_parse_masscan(["rmasscan", "-oX", "x.xml"]).is_err());
    }

    #[test]
    fn list_scan_single_port_prints_ip_only() {
        let out = run_args(&["rmasscan", "-sL", "10.0.0.0/30", "-p80", "--seed", "1"]).unwrap();
        assert!(out.lines().all(|l| !l.contains(':')));
        assert_eq!(out.lines().count(), 4);
    }

    #[test]
    fn list_scan_with_non_terminating_retries_is_an_error_not_a_hang() {
        let e = run_args(&[
            "rmasscan",
            "-sL",
            "10.0.0.0/30",
            "-p80",
            "--seed",
            "1",
            "--retries",
            "1",
        ])
        .unwrap_err();
        assert!(
            e.contains("never terminate") && e.contains("--retries"),
            "{e}"
        );
        // Golden-backed retries cases keep working (456 lines, see differential.rs).
        let out = run_args(&[
            "rmasscan",
            "-sL",
            "10.0.0.0/24",
            "-p80",
            "--seed",
            "1",
            "--retries",
            "2",
        ])
        .unwrap();
        assert_eq!(out.lines().count(), 456);
    }

    #[test]
    fn list_scan_two_ports_prints_ip_port() {
        let out = run_args(&["rmasscan", "-sL", "10.0.0.0/30", "-p80,443", "--seed", "1"]).unwrap();
        assert_eq!(out.lines().count(), 8);
        assert!(
            out.lines()
                .all(|l| l.ends_with(":80") || l.ends_with(":443"))
        );
    }

    #[test]
    fn list_scan_without_ports_adds_port_80() {
        // ListScan semantics (main.c:1674-1675): no -p means port 80, IP only.
        let with = run_args(&["rmasscan", "-sL", "10.0.0.0/30", "--seed", "1"]).unwrap();
        let expl = run_args(&["rmasscan", "-sL", "10.0.0.0/30", "-p80", "--seed", "1"]).unwrap();
        assert_eq!(with, expl);
        assert_eq!(with.lines().count(), 4);
    }

    #[test]
    fn echo_without_ports_adds_no_port_80() {
        // Operation::Echo: no port 80 is added (main.c:1799 path).
        let out = run_args(&["rmasscan", "--echo", "10.0.0.0/30", "--seed", "1"]).unwrap();
        assert!(out.lines().any(|l| l == "ports = "), "{out}");
        assert!(!out.contains("ports = 80"), "{out}");
        let with = run_args(&["rmasscan", "--echo", "10.0.0.0/30", "-p80", "--seed", "1"]).unwrap();
        assert!(with.contains("ports = 80"), "{with}");
    }

    #[test]
    fn echo_and_echo_all_are_identical() {
        let a = run_args(&["rmasscan", "--echo", "10.0.0.0/30", "-p80", "--seed", "1"]).unwrap();
        let b = run_args(&[
            "rmasscan",
            "--echo-all",
            "10.0.0.0/30",
            "-p80",
            "--seed",
            "1",
        ])
        .unwrap();
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn bad_inputs_are_fatal() {
        for args in [
            &["rmasscan", "-sL", "not-an-ip", "-p80", "--seed", "1"][..],
            &[
                "rmasscan",
                "-sL",
                "--range",
                "10.0.0.256",
                "-p80",
                "--seed",
                "1",
            ][..],
            &["rmasscan", "-sL", "10.0.0.0/30", "-p80x", "--seed", "1"][..],
            &["rmasscan", "-sL", "10.0.0.0/30", "-pU:53", "--seed", "1"][..],
            &[
                "rmasscan",
                "-sL",
                "10.0.0.0/30",
                "-p80",
                "--seed",
                "1",
                "--rate",
                "fast",
            ][..],
            &["rmasscan", "-sL", "10.0.0.0/30", "-p80"][..],
            &["rmasscan", "-sL", "2001:db8::/126", "-p80", "--seed", "1"][..],
            &["rmasscan", "10.0.0.0/30", "-p80", "--seed", "1"][..],
        ] {
            assert!(run_args(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn excludefile_applies() {
        let dir = std::env::temp_dir().join(format!("rmasscan-ex-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("ex.txt");
        std::fs::write(&f, "# comment\n10.0.0.0/31 # first two\n\n10.0.0.3\n").unwrap();
        let out = run_args(&[
            "rmasscan",
            "-sL",
            "10.0.0.0/30",
            "-p80",
            "--seed",
            "1",
            "--excludefile",
            f.to_str().unwrap(),
        ])
        .unwrap();
        assert_eq!(out, "10.0.0.2\n");
        std::fs::remove_dir_all(dir).unwrap();
    }

    const TRACE: [&str; 14] = [
        "rmasscan",
        "--offline",
        "--packet-trace",
        "10.0.0.0/30",
        "-p80,443",
        "--seed",
        "5",
        "--adapter-ip",
        "10.255.0.1",
        "--adapter-mac",
        "00-11-22-33-44-55",
        "--router-mac",
        "66-55-44-33-22-11",
        "--source-port=40000-40003",
    ];

    fn trace_args<'a>(extra: &[&'a str]) -> Vec<&'a str> {
        let mut v = TRACE.to_vec();
        v.extend_from_slice(extra);
        v
    }

    #[test]
    fn packet_trace_count_is_range_times_retries_plus_one_squared() {
        // range 4 ips * 2 ports = 8; transmit sends (retries+1)^2 per target.
        for (retries, expect) in [(0u32, 8usize), (1, 32), (2, 72)] {
            let r = retries.to_string();
            let out = run_args(&trace_args(&["--retries", &r])).unwrap();
            assert_eq!(out.lines().count(), expect, "retries {retries}");
        }
    }

    #[test]
    fn packet_trace_line_format() {
        let out = run_args(&trace_args(&[])).unwrap();
        for l in out.lines() {
            // SENT (t) TCP  [src]:port > [dst]:port SYN (main-ptrace.c:97)
            assert!(l.starts_with("SENT ("), "{l}");
            let (_, rest) = l.split_once(") TCP  [10.255.0.1]:").unwrap();
            let sport: u16 = rest.split_once(' ').unwrap().0.parse().unwrap();
            assert!((40000..=40003).contains(&sport), "{l}");
            assert!(l.ends_with(" SYN"), "{l}");
            assert!(l.contains(" > [10.0.0."), "{l}");
            // "[ip]:port" is left-justified in a 21-wide field.
            assert_eq!(
                l.split(" > ").next().unwrap().len(),
                "SENT (0.0000) TCP  ".len() + 21,
                "{l}"
            );
        }
    }

    fn effective(args: &[&str]) -> Result<EffectiveConfig, String> {
        let cfg = Cli::try_parse_masscan(args.iter().copied())
            .map_err(|e| e.to_string())?
            .to_config()?;
        validate(&cfg, Operation::Scan).map_err(|e| e.to_string())
    }

    #[test]
    fn packet_trace_seqno_and_source_port_match_cookie_formula() {
        let eff = effective(&trace_args(&["--retries", "1"])).unwrap();
        // Independent recomputation of main.c:373-393 from transmit_scan's own indices.
        let mut expected = Vec::new();
        transmit_scan(
            eff.massip(),
            eff.seed(),
            eff.blackrock_rounds(),
            eff.shard(),
            1,
            0,
            eff.resume_index(),
            eff.resume_count(),
            eff.retries(),
            eff.max_rate(),
            |i, repeats, xxx, ip, port| {
                let n = i.wrapping_add(repeats);
                let ck = syn_cookie_ipv4(
                    n as u32,
                    (n >> 32) as u32,
                    xxx as u32,
                    (xxx >> 32) as u32,
                    5,
                );
                let port_me = 40000 + (ck as u32 & 3);
                let seq = syn_cookie_ipv4(ip, port, 0x0aff_0001, port_me, 5) as u32;
                expected.push((ip, port, port_me, seq));
            },
        )
        .unwrap();
        let mut got = Vec::new();
        for_each_probe(&eff, |p| {
            // Frame carries the same values (TCP header at 34, seqno at +4).
            assert_eq!(p.ip_me, 0x0aff_0001);
            assert_eq!(&p.frame[26..30], &p.ip_me.to_be_bytes());
            assert_eq!(&p.frame[30..34], &p.ip_them.to_be_bytes());
            assert_eq!(&p.frame[34..36], &p.port_me.to_be_bytes());
            assert_eq!(&p.frame[36..38], &p.port_them.to_be_bytes());
            assert_eq!(&p.frame[38..42], &p.seqno.to_be_bytes());
            got.push((
                p.ip_them,
                u32::from(p.port_them),
                u32::from(p.port_me),
                p.seqno,
            ));
            Ok(())
        })
        .unwrap();
        assert_eq!(got.len(), 32);
        assert_eq!(got, expected);
        // The range actually exercises more than one source port.
        assert!(
            got.iter()
                .map(|g| g.2)
                .collect::<std::collections::HashSet<_>>()
                .len()
                > 1
        );
    }

    #[test]
    fn packet_trace_single_source_port_uses_plain_cookie() {
        let mut a = trace_args(&[]);
        a.pop();
        a.extend(["--source-port", "40000"]);
        let eff = effective(&a).unwrap();
        let mut n = 0;
        for_each_probe(&eff, |p| {
            assert_eq!(p.port_me, 40000);
            assert_eq!(
                p.seqno,
                syn_cookie_ipv4(p.ip_them, u32::from(p.port_them), p.ip_me, 40000, 5) as u32
            );
            n += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 8);
    }

    #[test]
    fn packet_trace_requires_adapter_options() {
        let without = |opt: &str| -> Vec<&'static str> {
            let mut v = TRACE.to_vec();
            let i = v.iter().position(|a| a.starts_with(opt)).unwrap();
            if v[i].contains('=') {
                v.remove(i);
            } else {
                v.drain(i..i + 2);
            }
            v
        };
        for opt in [
            "--source-port",
            "--adapter-ip",
            "--adapter-mac",
            "--router-mac",
        ] {
            let e = run_args(&without(opt)).unwrap_err();
            assert!(e.contains(opt), "{opt}: {e}");
        }
    }

    #[test]
    fn scan_without_offline_trace_is_rejected() {
        assert!(
            run_args(&[
                "rmasscan",
                "10.0.0.0/30",
                "-p80",
                "--seed",
                "1",
                "--offline"
            ])
            .is_err()
        );
        assert!(Cli::try_parse_masscan(["rmasscan", "10.0.0.0/30", "--packet-trace"]).is_err());
        assert!(Cli::try_parse_masscan(["rmasscan", "-sL", "--echo", "10.0.0.0/30"]).is_err());
    }
}
