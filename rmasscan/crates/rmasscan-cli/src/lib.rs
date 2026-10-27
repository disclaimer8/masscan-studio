//! CLI порта masscan (AGPL-3.0): живой скан с обнаружением адаптера и шлюза, `--offline` (с `--packet-trace`),
//! `-sL`, `--echo`/`--echo-all` и `--iflist` поверх `rmasscan-core`, `rmasscan-engine` и `rmasscan-net`. Порт
//! `src/main.c` (`main` :1595-1805, `main_scan`), `src/main-initadapter.c`, `src/main-listscan.c` и
//! `src/main-ptrace.c` из masscan © Robert David Graham (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Библиотека: бинарник `rmasscan` тонкий и зовёт [`run`] с настоящим `Backend`; все тесты идут через fake (ни один
//! не достигает ОС). Настоящая реализация шва библиотеке недоступна:
//!
//! ```compile_fail
//! use rmasscan_cli::os_backend::OsBackend;
//! ```

#![forbid(unsafe_code)]

pub mod args;
pub mod live;
pub mod output;

use std::io::Write;

use args::{Cli, SeedPolicy, seed_policy};
use output::{Interactive, io_fail};
use rmasscan_core::config::{Operation, echo, validate};
use rmasscan_core::scan::{format_list_line, list_scan};

fn write_out(out: &mut dyn Write, s: &str) -> Result<(), String> {
    out.write_all(s.as_bytes()).map_err(io_fail)
}

/// Явный flush на успешном пути: ошибка последнего блока не теряется в drop.
fn finish(out: &mut dyn Write) -> Result<(), String> {
    out.flush().map_err(io_fail)
}

/// Текст stderr для ошибки [`run`]: отказы обнаружения и ARP (`[-] FAIL: …` и подсказки C) как есть, прочие ошибки
/// с обёрткой `rmasscan: error:`. Любая ошибка даёт exit 1.
pub fn error_text(msg: &str) -> String {
    if msg.starts_with(live::REFUSAL_PREFIX) {
        msg.to_string()
    } else {
        format!("rmasscan: error: {msg}")
    }
}

/// Выполняет разобранную командную строку. `backend` - единственный шов к ОС; `out` получает stdout (строки
/// `Discovered`, трассу, `-sL`, `--echo`, `--iflist`), `log` строки `[+]`. `Ok` значит exit 0.
pub fn run(
    cli: &Cli,
    backend: &dyn live::Backend,
    out: &mut dyn Write,
    log: &mut dyn Write,
) -> Result<(), String> {
    let cfg = cli.to_config()?;
    if cli.iflist {
        live::iflist(backend, out)?;
        return finish(out);
    }
    // Решение по операции до validate: --echo без seed не печатает `seed = 0`.
    if seed_policy(cli) == SeedPolicy::Required && cli.seed.is_none() {
        return Err(
            "--seed is required and must be non-zero for -sL, --echo and --offline \
             (the entropy-based default applies only to live scans)"
                .into(),
        );
    }
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
    if cli.offline {
        live::run_offline(&cfg, backend, cli.packet_trace, out, log)?;
        return finish(out);
    }
    live::run_live(&cfg, backend, &mut Interactive::new(&mut *out), log)?;
    finish(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use args::SeedPolicy;
    use rmasscan_core::cookie::syn_cookie_ipv4;
    use rmasscan_core::probe::AdapterBinding;
    use rmasscan_core::scan::transmit_scan;
    use rmasscan_core::throttle::Clock;
    use rmasscan_engine::AdapterPair;
    use rmasscan_engine::fake::ManualClock;
    use rmasscan_net::arp_resolve::ArpPolicy;
    use rmasscan_net::{Iface, Interfaces, NetError, Route, RouteTable};

    const ETH0_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 5);

    /// Одна сеть: `eth0` (Ethernet, `02:aa:00:00:00:01`, адреса `ipv4`), всё через шлюз `192.0.2.1`. `open`
    /// паникует: unit-тесты библиотеки никогда не открывают адаптер.
    struct FakeBackend {
        ipv4: Vec<Ipv4Addr>,
    }

    impl Default for FakeBackend {
        fn default() -> Self {
            FakeBackend {
                ipv4: vec![ETH0_IP],
            }
        }
    }

    struct Routes;
    fn eth0_route() -> Route {
        Route {
            ifindex: 2,
            ifname: "eth0".into(),
            gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
            local: false,
        }
    }
    impl RouteTable for Routes {
        fn lookup(&self, _: Ipv4Addr) -> Result<Option<Route>, NetError> {
            Ok(Some(eth0_route()))
        }
        fn default_routes(&self) -> Result<Vec<Route>, NetError> {
            Ok(vec![eth0_route()])
        }
    }

    struct Ifaces(Vec<Ipv4Addr>);
    impl Interfaces for Ifaces {
        fn list(&self) -> Result<Vec<Iface>, NetError> {
            Ok(vec![Iface {
                name: "eth0".into(),
                index: 2,
                device_id: "eth0".into(),
                description: None,
                mac: Some([0x02, 0xaa, 0, 0, 0, 1]),
                mac_masked: false,
                ethernet: true,
                up: true,
                ipv4: self.0.clone(),
            }])
        }
    }

    impl live::Backend for FakeBackend {
        fn routes(&self) -> Result<Box<dyn RouteTable>, NetError> {
            Ok(Box::new(Routes))
        }
        fn interfaces(&self) -> Result<Box<dyn Interfaces>, NetError> {
            Ok(Box::new(Ifaces(self.ipv4.clone())))
        }
        fn open(&self, _: &AdapterBinding) -> Result<AdapterPair, NetError> {
            panic!("library unit tests never open an adapter")
        }
        fn entropy64(&self) -> u64 {
            0x1234_5678_9abc_def1
        }
        fn unix_time(&self) -> u64 {
            1_800_000_000
        }
        fn arp_policy(&self) -> ArpPolicy {
            ArpPolicy::default()
        }
        fn clock(&self) -> Arc<dyn Clock + Send + Sync> {
            ManualClock::new()
        }
    }

    fn run_with(b: &FakeBackend, args: &[&str]) -> Result<String, String> {
        let cli = Cli::try_parse_masscan(args.iter().copied()).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        run(&cli, b, &mut out, &mut Vec::new())?;
        Ok(String::from_utf8(out).unwrap())
    }

    fn run_args(args: &[&str]) -> Result<String, String> {
        run_with(&FakeBackend::default(), args)
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

    /// `TRACE` без опции `opt` (и её значения).
    fn trace_without(opts: &[&str]) -> Vec<&'static str> {
        let mut v = TRACE.to_vec();
        for opt in opts {
            let i = v.iter().position(|a| a.starts_with(opt)).unwrap();
            if v[i].contains('=') {
                v.remove(i);
            } else {
                v.drain(i..i + 2);
            }
        }
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

    fn prepared(args: &[&str]) -> live::Prepared {
        let cfg = Cli::try_parse_masscan(args.iter().copied())
            .unwrap()
            .to_config()
            .unwrap();
        live::prepare(&cfg, SeedPolicy::Required, &FakeBackend::default(), true).unwrap()
    }

    #[test]
    fn packet_trace_seqno_and_source_port_match_cookie_formula() {
        let p = prepared(&trace_args(&["--retries", "1"]));
        let eff = &p.eff;
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
        live::for_each_probe(eff, &p.binding, |pr| {
            // Frame carries the same values (TCP header at 34, seqno at +4).
            assert_eq!(pr.ip_me, 0x0aff_0001);
            assert_eq!(&pr.frame[26..30], &pr.ip_me.to_be_bytes());
            assert_eq!(&pr.frame[30..34], &pr.ip_them.to_be_bytes());
            assert_eq!(&pr.frame[34..36], &pr.port_me.to_be_bytes());
            assert_eq!(&pr.frame[36..38], &pr.port_them.to_be_bytes());
            assert_eq!(&pr.frame[38..42], &pr.seqno.to_be_bytes());
            got.push((
                pr.ip_them,
                u32::from(pr.port_them),
                u32::from(pr.port_me),
                pr.seqno,
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
        let p = prepared(&a);
        let mut n = 0;
        live::for_each_probe(&p.eff, &p.binding, |pr| {
            assert_eq!(pr.port_me, 40000);
            assert_eq!(
                pr.seqno,
                syn_cookie_ipv4(pr.ip_them, u32::from(pr.port_them), pr.ip_me, 40000, 5) as u32
            );
            n += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 8);
    }

    /// Прежде `--offline --packet-trace` требовал четыре опции адаптера; теперь недостающие значения даёт
    /// обнаружение (fake-бэкенд), MAC шлюза в offline всегда фиктивный, порт по формуле времени.
    #[test]
    fn packet_trace_fills_missing_values_from_the_backend() {
        for (opts, src) in [
            (&["--adapter-ip"][..], "[192.0.2.5]:4000"),
            (&["--adapter-mac"][..], "[10.255.0.1]:4000"),
            (&["--router-mac"][..], "[10.255.0.1]:4000"),
            // 40000 + 1_800_000_000 % 20000 = 40000, один порт.
            (&["--source-port"][..], "[10.255.0.1]:40000 "),
            (
                &[
                    "--adapter-ip",
                    "--adapter-mac",
                    "--router-mac",
                    "--source-port",
                ][..],
                "[192.0.2.5]:40000 ",
            ),
        ] {
            let out = run_args(&trace_without(opts)).unwrap();
            assert_eq!(out.lines().count(), 8, "{opts:?}");
            assert!(out.lines().all(|l| l.contains(src)), "{opts:?}: {out}");
        }
        let p = prepared(&trace_without(&["--adapter-mac", "--router-mac"]));
        assert_eq!(p.binding.source_mac, [0x02, 0xaa, 0, 0, 0, 1]);
        assert_eq!(p.binding.next_hop_mac, [0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
        assert_eq!(p.binding.interface_id, "eth0");
    }

    #[test]
    fn packet_trace_without_adapter_ip_on_an_interface_without_ipv4_names_the_source_ip_hint() {
        let b = FakeBackend { ipv4: vec![] };
        let e = run_with(&b, &trace_without(&["--adapter-ip"])).unwrap_err();
        assert_eq!(
            e,
            "[-] FAIL: failed to detect IP of interface \"eth0\"\n    \
             [hint] did you spell the name correctly?\n    \
             [hint] if it has no IP address, manually set with something like \"--source-ip 198.51.100.17\""
        );
        assert_eq!(
            error_text(&e),
            e,
            "C form without the rmasscan: error: wrapper"
        );
        assert_eq!(error_text("x"), "rmasscan: error: x");
    }

    /// Заполнитель Darwin и групповой MAC не становятся source MAC и в герметичном `--offline` (ОС не опрашивается).
    #[test]
    fn offline_with_an_unusable_explicit_mac_is_refused() {
        for mac in ["02-00-00-00-00-00", "01-00-5e-00-00-01"] {
            let e = run_args(&[
                "rmasscan",
                "--offline",
                "10.0.0.1",
                "-p80",
                "--seed",
                "1",
                "--adapter-ip",
                "10.255.0.1",
                "--adapter-mac",
                mac,
            ])
            .unwrap_err();
            assert_eq!(
                e,
                "[-] FAIL: failed to detect MAC address of interface: \"offline\"\n \
                 [hint] try something like \"--source-mac 00-11-22-33-44-55\"",
                "{mac}"
            );
        }
    }

    #[test]
    fn packet_trace_without_offline_and_list_with_echo_are_rejected() {
        assert!(Cli::try_parse_masscan(["rmasscan", "10.0.0.0/30", "--packet-trace"]).is_err());
        assert!(Cli::try_parse_masscan(["rmasscan", "-sL", "--echo", "10.0.0.0/30"]).is_err());
    }

    #[test]
    fn echo_without_seed_errors_before_printing() {
        let cli = Cli::try_parse_masscan(["rmasscan", "--echo", "10.0.0.0/30", "-p80"]).unwrap();
        let mut out = Vec::new();
        let e = run(&cli, &FakeBackend::default(), &mut out, &mut Vec::new()).unwrap_err();
        assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
        assert!(e.contains("--seed"), "{e}");
    }

    #[test]
    fn list_without_seed_errors() {
        let e = run_args(&["rmasscan", "-sL", "10.0.0.0/30", "-p80"]).unwrap_err();
        assert!(e.contains("--seed"), "{e}");
    }

    #[test]
    fn offline_without_seed_errors() {
        let e = run_args(&["rmasscan", "--offline", "10.0.0.0/30", "-p80"]).unwrap_err();
        assert!(e.contains("--seed"), "{e}");
    }
}
