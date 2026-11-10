//! CLI порта masscan (AGPL-3.0): живой скан с обнаружением адаптера и шлюза и форматами вывода masscan,
//! `--readscan`, `--offline` (с `--packet-trace`), `-sL`, `--echo`/`--echo-all` и `--iflist` поверх `rmasscan-core`,
//! `rmasscan-engine` и `rmasscan-net`. Порт `src/main.c` (`main` :1595-1805, `main_scan`), `src/main-initadapter.c`,
//! `src/main-listscan.c`, `src/main-ptrace.c` и `src/in-binary.c` из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Библиотека: бинарник `rmasscan` тонкий и зовёт [`run`] с настоящим `Backend`; все тесты идут через fake (ни один
//! не достигает ОС). Настоящая реализация шва библиотеке недоступна:
//!
//! ```compile_fail
//! use rmasscan_cli::os_backend::OsBackend;
//! ```

#![forbid(unsafe_code)]

pub mod args;
pub mod conf;
pub mod live;
pub mod output;
pub mod pcap_writer;
pub mod readscan;
pub mod status;

/// Общий RAII-каталог тестов; тот же файл включают интеграционные тесты.
#[cfg(test)]
#[path = "../tests/common/scratch.rs"]
mod scratch;

use std::io::Write;

use args::{Cli, SeedPolicy, seed_policy};
use output::{
    Format, OPEN_FAILURE_PREFIX, OutputEnv, OutputOptions, Pipeline, ServiceNames, io_fail,
};
use rmasscan_core::config::{EchoExtras, Operation, ScanConfig, echo_with, validate};
use rmasscan_core::scan::{format_list_line, list_scan};

/// Ошибка [`run`], строки которой уже записаны в `log` (`[-] FAIL: --readscan`, `[-] <файл>: …`, `[-] file
/// corrupt`, `in-binary.c`): exit 1 без второй копии. [`error_text`] даёт для неё пустую строку.
pub const LOGGED: &str = "(the error lines are already in the log)";

/// Р19.
const OUTPUT_OUTSIDE_SCAN: &str = "output options apply only to a scan or --readscan";

/// Две строки `ERRMSG` C (`output.c:799–803`) для реального формата без файла: C на этом молча теряет каждую
/// запись, здесь это отказ до любого кадра и любого чтения (решение 2 контроллера).
const NO_OUTPUT_FILE: &str = "[-] ERR: no output file, use `--output-filename <filename>` to set one\n\
                              [-] ERR: for `stdout`, use `--output-filename -`";

fn write_out(out: &mut dyn Write, s: &str) -> Result<(), String> {
    out.write_all(s.as_bytes()).map_err(io_fail)
}

/// Явный flush на успешном пути: ошибка последнего блока не теряется в drop.
fn finish(out: &mut dyn Write) -> Result<(), String> {
    out.flush().map_err(io_fail)
}

/// Текст stderr для ошибки [`run`]: отказы обнаружения и ARP (`[-] FAIL: …` и подсказки C) и отказ открытия файла
/// вывода (`out: could not open file for …`) как есть, [`LOGGED`] пусто (уже в `log`), прочие ошибки с обёрткой
/// `rmasscan: error:`. Любая ошибка даёт exit 1.
pub fn error_text(msg: &str) -> String {
    if msg == LOGGED {
        String::new()
    } else if msg.starts_with(live::REFUSAL_PREFIX) || msg.starts_with(OPEN_FAILURE_PREFIX) {
        msg.to_string()
    } else {
        format!("rmasscan: error: {msg}")
    }
}

/// Опции вывода скана и `--readscan`: реальный формат требует файл (`-` это stdout).
fn checked_output_options(cli: &Cli) -> Result<OutputOptions, String> {
    let o = cli.resolved_output_options()?;
    let needs_file = !matches!(
        o.format,
        Format::Default | Format::Interactive | Format::None
    );
    if needs_file && o.filename.is_none() {
        return Err(NO_OUTPUT_FILE.into());
    }
    Ok(o)
}

/// Опции вывода скана в виде ключей `paused.conf` (`output-filename`, `output-format`, `output-append`, `output-flush`,
/// `stylesheet`, `main-conf.c:2402-2422`).
fn output_patch(o: &OutputOptions) -> conf::OutputConfPatch {
    conf::OutputConfPatch {
        format: Some(o.format),
        filename: o.filename.clone(),
        append: Some(o.append),
        flush: Some(o.flush),
        stylesheet: o.stylesheet.clone(),
        show_open: Some(o.show_open),
        show_closed: Some(o.show_closed),
        show_host: Some(o.show_host),
    }
}

/// Порты TCP целей за вычетом исключений, отсортированные и слитые: `masscan->targets.ports` после
/// `massip_apply_excludes` и `massip_optimize` (main.c:1672–1684), строка `# Ports scanned` заголовка `-oG`.
fn tcp_ports(cfg: &ScanConfig) -> Vec<(u16, u16)> {
    let mut targets = cfg.targets.clone();
    targets.apply_excludes(&mut cfg.excludes.clone());
    targets.optimize();
    targets
        .ports()
        .as_slice()
        .iter()
        .filter(|r| r.begin <= 0xFFFF)
        .map(|r| (r.begin as u16, r.end.min(0xFFFF) as u16))
        .collect()
}

/// Окружение конвейера: часы бэкенда; файл services читается только для `-oG` и `-oU`.
fn output_env<'a>(
    backend: &'a dyn live::Backend,
    opts: &OutputOptions,
    cfg: &ScanConfig,
    scan_started: Option<u64>,
) -> OutputEnv<'a> {
    let services = if matches!(opts.format, Format::Grepable | Format::Unicornscan) {
        backend.services()
    } else {
        ServiceNames::empty()
    };
    OutputEnv {
        wall: backend,
        services,
        tcp_ports: tcp_ports(cfg),
        scan_started,
    }
}

/// `--readscan` (main.c:1764, `readscan_binary_scanfile`): файлы `-oB` через конвейер вывода. Адаптер не
/// открывается, маршруты не читаются, `--seed` и права не нужны; начало скана берётся из `s:` заголовка
/// `masscan/1.1.N` (N >= 2, `in-binary.c:518-534`), иначе из первой записи до фильтра (`when_scan_started = 0`,
/// `in-binary.c:128-129`).
fn readscan(
    cli: &Cli,
    cfg: &ScanConfig,
    backend: &dyn live::Backend,
    out: &mut dyn Write,
    log: &mut dyn Write,
) -> Result<(), String> {
    let opts = checked_output_options(cli)?;
    let filter = readscan::ReadFilter::from_config(cfg);
    let env = output_env(backend, &opts, cfg, Some(0));
    readscan::run_readscan(
        &cli.readscan,
        &filter,
        &mut Pipeline::new(opts, &mut *out, env),
        log,
    )?;
    finish(out)
}

/// Выполняет разобранную командную строку. `backend` - единственный шов к ОС; `out` получает stdout (строки
/// `Discovered`, вывод `-o… -`, трассу, `-sL`, `--echo`, `--iflist`), `log` строки `[+]` и `[-]`. `Ok` значит
/// exit 0.
pub fn run(
    cli: &Cli,
    backend: &dyn live::Backend,
    out: &mut dyn Write,
    log: &mut dyn Write,
) -> Result<(), String> {
    let other_op = cli.list || cli.echo || cli.echo_all || cli.offline || cli.iflist;
    if cli.output_flags_given() && other_op {
        return Err(OUTPUT_OUTSIDE_SCAN.into());
    }
    let cfg = cli.to_config()?;
    let full = cli.resolve()?;
    // Р8: захват только для живого скана; `--echo` лишь печатает ключ `pcap-filename`.
    if full.pcap_filename.as_deref().is_some_and(|f| !f.is_empty())
        && (cli.list || cli.offline || cfg.offline || cli.iflist || !cli.readscan.is_empty())
    {
        return Err(
            "--pcap applies only to a live scan (not to --offline, -sL, --iflist or --readscan)"
                .into(),
        );
    }
    if !cli.readscan.is_empty() {
        return readscan(cli, &cfg, backend, out, log);
    }
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
        let extras = EchoExtras {
            pcap_filename: full.pcap_filename.as_deref(),
            ..EchoExtras::default()
        };
        echo_with(&cfg, false, &extras, &mut s);
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
    // main.c:1720-1742: пустые цели и порты отклоняются до `main_scan` (main.c:1743) и до `output_create`
    // (output.c:799-803), поэтому раньше отказа «нет файла вывода». seed 0 (энтропия) проверяет `prepare`.
    {
        let mut probe = cfg.clone();
        if probe.seed == 0 {
            probe.seed = 1;
        }
        validate(&probe, Operation::Scan).map_err(|e| e.to_string())?;
    }
    // Опции проверяются до обнаружения: отказ не стоит ни строки `[+]`, ни кадра. Начало скана - момент `open`.
    let opts = checked_output_options(cli)?;
    // Файл `-` это stdout C (`output.c:216`), и `close_rotate` закрывает его (`output.c:268`) до `printf` времени
    // скана (`main.c:1551`): в stdout C остаётся только формат.
    let elapsed_to_stdout = !opts.format_to_stdout();
    let env = output_env(backend, &opts, &cfg, None);
    let mode = cli.status_mode();
    // `paused.conf` (первое Ctrl-C) повторяет разобранную конфигурацию: вывод по позиции `--resume`, `-oX`, режим статуса.
    let mut full = full;
    full.output = output_patch(&opts);
    full.ndjson_status = mode == status::StatusMode::Ndjson;
    let (_, scan_millis) = live::run_live_conf(
        &full,
        backend,
        &mut Pipeline::new(opts, &mut *out, env),
        log,
        mode,
    )?;
    if mode == status::StatusMode::Off && elapsed_to_stdout {
        // main.c:1548-1552: без строки статуса C пишет в stdout время скана.
        write_out(out, &format!("{scan_millis} milliseconds elapsed\n"))?;
    }
    finish(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use crate::scratch::Scratch;
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
    /// паникует: unit-тесты библиотеки никогда не открывают адаптер. Таблица сервисов знает только `http 80/tcp`;
    /// `services_calls` считает её чтения.
    struct FakeBackend {
        ipv4: Vec<Ipv4Addr>,
        services_calls: std::cell::Cell<usize>,
    }

    impl Default for FakeBackend {
        fn default() -> Self {
            FakeBackend {
                ipv4: vec![ETH0_IP],
                services_calls: std::cell::Cell::new(0),
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

    impl output::Wall for FakeBackend {
        fn unix_time(&self) -> u64 {
            1_800_000_000
        }
        fn utc_offset_secs(&self, _: u64) -> i32 {
            0
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
        fn arp_policy(&self) -> ArpPolicy {
            ArpPolicy::default()
        }
        fn clock(&self) -> Arc<dyn Clock + Send + Sync> {
            ManualClock::new()
        }
        fn services(&self) -> output::ServiceNames {
            self.services_calls.set(self.services_calls.get() + 1);
            output::ServiceNames::parse("http 80/tcp\n")
        }
        fn interrupts(&self) -> u32 {
            panic!("library unit tests never trap Ctrl-C")
        }
        fn write_paused_conf(&self, _: &str) -> Result<(), String> {
            panic!("library unit tests never write paused.conf")
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

    /// P8: каталог `Scratch` уникален на экземпляр и исчезает вместе с файлами и при панике теста.
    #[test]
    fn scratch_dir_is_unique_and_removed_even_on_panic() {
        let (a, b) = (Scratch::new(), Scratch::new());
        assert_ne!(a.dir(), b.dir());
        let seen = std::sync::Mutex::new(None);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let s = Scratch::new();
            s.write("left-behind.txt", b"x");
            *seen.lock().unwrap() = Some(s.dir().to_path_buf());
            panic!("test body panics while the scratch dir is alive");
        }));
        assert!(r.is_err());
        let dir = seen.lock().unwrap().take().unwrap();
        assert!(!dir.exists(), "{} survived the panic", dir.display());
        let kept = a.dir().to_path_buf();
        drop(a);
        assert!(!kept.exists());
        assert!(b.dir().exists());
    }

    #[test]
    fn unsupported_option_errors() {
        assert!(Cli::try_parse_masscan(["rmasscan", "--banners", "10.0.0.0/24", "-p80"]).is_err());
        assert!(Cli::try_parse_masscan(["rmasscan", "--nonsense"]).is_err());
        // `-oX FILE` разбирается; без целей `run` отказывает раньше, чем тронет файл.
        let scratch = Scratch::new();
        let path = scratch.path("no-targets.xml");
        let e = run_args(&["rmasscan", "-oX", path.to_str().unwrap()]).unwrap_err();
        assert!(e.contains("target IP address list empty"), "{e}");
        assert!(!path.exists());
    }

    /// Р19: флаги вывода и статуса вне живого скана и `--readscan` отклоняются до любого вывода и любого файла.
    #[test]
    fn output_flags_refused_outside_scan_and_readscan() {
        let scratch = Scratch::new();
        let path = scratch.path("r19.txt");
        let file = path.to_str().unwrap();
        for op in [
            &["-sL", "10.0.0.0/30", "-p80", "--seed", "1"][..],
            &["--echo", "10.0.0.0/30", "-p80", "--seed", "1"][..],
            &["--echo-all", "10.0.0.0/30", "-p80", "--seed", "1"][..],
            &["--offline", "10.0.0.1", "-p80", "--seed", "1"][..],
            &[
                "--offline",
                "--packet-trace",
                "10.0.0.1",
                "-p80",
                "--seed",
                "1",
            ][..],
            &["--iflist"][..],
        ] {
            for flags in [
                &["-oL", file][..],
                &["--nostatus"][..],
                &["--show", "closed"][..],
                &["--interactive"][..],
            ] {
                let mut argv = vec!["rmasscan"];
                argv.extend_from_slice(op);
                argv.extend_from_slice(flags);
                let cli = Cli::try_parse_masscan(argv.iter().copied()).unwrap();
                let (mut out, mut log) = (Vec::new(), Vec::new());
                let e = run(&cli, &FakeBackend::default(), &mut out, &mut log).unwrap_err();
                assert_eq!(
                    e, "output options apply only to a scan or --readscan",
                    "{argv:?}"
                );
                assert!(out.is_empty() && log.is_empty(), "{argv:?}");
                assert!(!path.exists(), "{argv:?}");
            }
        }
    }

    fn open_rec() -> output::Record {
        output::Record {
            timestamp: 1_700_000_000,
            ip: Ipv4Addr::new(1, 2, 3, 4),
            port: 80,
            status: output::Status::Open,
            reason: 0x12,
            ttl: 57,
        }
    }

    fn closed_rec() -> output::Record {
        output::Record {
            timestamp: 1_700_000_000,
            ip: Ipv4Addr::new(10, 0, 0, 255),
            port: 443,
            status: output::Status::Closed,
            reason: 0x14,
            ttl: 64,
        }
    }

    /// Файл `-oB` с записями `recs`, собранный писателем конвейера (часы 1_600_000_000, не время записей).
    fn scan_file(scratch: &Scratch, name: &str, recs: &[output::Record]) -> std::path::PathBuf {
        struct W;
        impl output::Wall for W {
            fn unix_time(&self) -> u64 {
                1_600_000_000
            }
            fn utc_offset_secs(&self, _: u64) -> i32 {
                0
            }
        }
        let path = scratch.path(name);
        let mut sink_out = Vec::new();
        let env = OutputEnv {
            wall: &W,
            services: output::ServiceNames::empty(),
            tcp_ports: Vec::new(),
            scan_started: None,
        };
        let o = OutputOptions {
            format: output::Format::Binary,
            filename: Some(path.to_string_lossy().into_owned()),
            show_closed: true,
            ..OutputOptions::default()
        };
        let mut p = Pipeline::new(o, &mut sink_out, env);
        output::Sink::open(&mut p).unwrap();
        for r in recs {
            p.report_record(r).unwrap();
        }
        output::Sink::finish(&mut p).unwrap();
        path
    }

    /// `run` с `--readscan`: (итог, stdout, stderr).
    fn readscan_run(b: &FakeBackend, args: &[&str]) -> (Result<(), String>, Vec<u8>, String) {
        let mut argv = vec!["rmasscan"];
        argv.extend_from_slice(args);
        let cli = Cli::try_parse_masscan(argv).unwrap();
        let (mut out, mut log) = (Vec::new(), Vec::new());
        let r = run(&cli, b, &mut out, &mut log);
        (r, out, String::from_utf8(log).unwrap())
    }

    /// `--readscan` через `run`: записи сохраняют своё время, начало скана из первой записи (1_700_000_000), часы
    /// fake-бэкенда (1_800_000_000, смещение 0) дают только время открытия, заголовка XML и подвалов; имена сервисов
    /// читаются только для `-oG` и `-oU`. Ожидания выписаны по байтам юнит-тестов форматов.
    #[test]
    fn readscan_converts_to_every_format() {
        let scratch = Scratch::new();
        let input = scan_file(&scratch, "every.scan", &[open_rec(), closed_rec()]);
        let input = input.to_str().unwrap();
        let cases: [(&str, &[u8]); 8] = [
            (
                "-oL",
                b"#masscan\nopen tcp 80 1.2.3.4 1700000000\nclosed tcp 443 10.0.0.255 1700000000\n# end\n",
            ),
            (
                "-oJ",
                concat!(
                    "[\n",
                    "{   \"ip\": \"1.2.3.4\",   \"timestamp\": \"1700000000\", \"ports\": [ {\"port\": 80, \"proto\": \"tcp\", \"status\": \"open\", \"reason\": \"syn-ack\", \"ttl\": 57} ] }\n",
                    ",\n",
                    "{   \"ip\": \"10.0.0.255\",   \"timestamp\": \"1700000000\", \"ports\": [ {\"port\": 443, \"proto\": \"tcp\", \"status\": \"closed\", \"reason\": \"rst-ack\", \"ttl\": 64} ] }\n",
                    "]\n"
                )
                .as_bytes(),
            ),
            (
                "-oD",
                concat!(
                    "{\"ip\":\"1.2.3.4\",\"timestamp\":\"1700000000\",\"port\":80,\"proto\":\"tcp\",\"rec_type\":\"status\",\"data\":{\"status\":\"open\",\"reason\":\"syn-ack\",\"ttl\":57}}\n",
                    "{\"ip\":\"10.0.0.255\",\"timestamp\":\"1700000000\",\"port\":443,\"proto\":\"tcp\",\"rec_type\":\"status\",\"data\":{\"status\":\"closed\",\"reason\":\"rst-ack\",\"ttl\":64}}\n"
                )
                .as_bytes(),
            ),
            ("-oH", b"1.2.3.4\n10.0.0.255\n"),
            (
                "-oX",
                concat!(
                    "<?xml version=\"1.0\"?>\r\n<!-- masscan v1.0 scan -->\r\n",
                    "<nmaprun scanner=\"masscan\" start=\"1800000000\" version=\"1.0-BETA\"  xmloutputversion=\"1.03\">\r\n",
                    "<scaninfo type=\"syn\" protocol=\"tcp\" />\r\n",
                    "<host endtime=\"1700000000\"><address addr=\"1.2.3.4\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\" reason=\"syn-ack\" reason_ttl=\"57\"/></port></ports></host>\r\n",
                    "<host endtime=\"1700000000\"><address addr=\"10.0.0.255\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"443\"><state state=\"closed\" reason=\"rst-ack\" reason_ttl=\"64\"/></port></ports></host>\r\n",
                    "<runstats>\r\n<finished time=\"1800000000\" timestr=\"2027-01-15 08:00:00\" elapsed=\"0\" />\r\n",
                    "<hosts up=\"1\" down=\"1\" total=\"2\" />\r\n</runstats>\r\n</nmaprun>\r\n"
                )
                .as_bytes(),
            ),
            (
                "-oG",
                concat!(
                    "# Masscan 1.3.9-integration scan initiated Tue Nov 14 22:13:20 2023\n",
                    "# Ports scanned: TCP(0;) UDP(0;) SCTP(0;) PROTOCOLS(0;)\n",
                    "Timestamp: 1700000000\tHost: 1.2.3.4 ()\tPorts: 80/open/tcp//http//\n",
                    "Timestamp: 1700000000\tHost: 10.0.0.255 ()\tPorts: 443/closed/tcp//unknown//\n",
                    "# Masscan done at Fri Jan 15 08:00:00 2027\n"
                )
                .as_bytes(),
            ),
            (
                "-oU",
                concat!(
                    "#masscan\n",
                    "TCP open\t            http[   80]\t\tfrom 1.2.3.4  ttl 57 \n",
                    "TCP closed\t         unknown[  443]\t\tfrom 10.0.0.255  ttl 64 \n",
                    "# end\n"
                )
                .as_bytes(),
            ),
            ("-oB", &[]),
        ];
        for (flag, want) in cases {
            let b = FakeBackend::default();
            let (r, out, log) = readscan_run(
                &b,
                &["--readscan", input, "--show", "open,closed", flag, "-"],
            );
            r.unwrap();
            assert_eq!(log, format!("[+] --readscan {input}\n"), "{flag}");
            let services = usize::from(matches!(flag, "-oG" | "-oU"));
            assert_eq!(
                b.services_calls.get(),
                services,
                "{flag}: services read only for -oG/-oU"
            );
            if flag == "-oB" {
                let mut head = b"masscan/1.1\ns:1700000000\n".to_vec();
                head.resize(99, 0);
                let mut foot = b"masscan/1.1".to_vec();
                foot.resize(99, 0);
                let ts = 1_700_000_000u32.to_be_bytes();
                let mut want = head;
                want.extend_from_slice(&[6, 13]);
                want.extend_from_slice(&ts);
                want.extend_from_slice(&[1, 2, 3, 4, 6, 0, 80, 0x12, 57]);
                want.extend_from_slice(&[7, 13]);
                want.extend_from_slice(&ts);
                want.extend_from_slice(&[10, 0, 0, 255, 6, 0x01, 0xBB, 0x14, 64]);
                want.extend_from_slice(&foot);
                assert_eq!(out, want, "{flag}");
            } else {
                assert_eq!(
                    String::from_utf8_lossy(&out),
                    String::from_utf8_lossy(want),
                    "{flag}"
                );
            }
        }
        // Без `-o…` и `--show` это интерактивная строка C, только open.
        let (r, out, _) = readscan_run(&FakeBackend::default(), &["--readscan", input]);
        r.unwrap();
        assert_eq!(
            out,
            output::discovered_line(Ipv4Addr::new(1, 2, 3, 4), 80).into_bytes()
        );
    }

    /// Цели и порты перед `--readscan` фильтруют записи (`parse_status2`), порты попадают в заголовок `-oG`;
    /// `--seed` не нужен, адаптер не открывается (`open` fake-бэкенда паникует).
    #[test]
    fn readscan_filters_by_the_targets_given_before_it() {
        let scratch = Scratch::new();
        let input = scan_file(&scratch, "filter.scan", &[open_rec(), closed_rec()]);
        let input = input.to_str().unwrap();
        let (r, out, _) = readscan_run(
            &FakeBackend::default(),
            &[
                "-p80",
                "--readscan",
                input,
                "--show",
                "open,closed",
                "-oG",
                "-",
            ],
        );
        r.unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            concat!(
                "# Masscan 1.3.9-integration scan initiated Tue Nov 14 22:13:20 2023\n",
                "# Ports scanned: TCP(1;80-80) UDP(0;) SCTP(0;) PROTOCOLS(0;)\n",
                "Timestamp: 1700000000\tHost: 1.2.3.4 ()\tPorts: 80/open/tcp//http//\n",
                "# Masscan done at Fri Jan 15 08:00:00 2027\n"
            )
        );
        let (r, out, _) = readscan_run(
            &FakeBackend::default(),
            &[
                "10.0.0.0/24",
                "-p443,80",
                "--readscan",
                input,
                "--show",
                "closed",
                "-oL",
                "-",
            ],
        );
        r.unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "#masscan\nclosed tcp 443 10.0.0.255 1700000000\n# end\n"
        );
    }

    /// Ошибка чтения `--readscan` уже записана в `log` строками C; [`error_text`] для неё пуст, поэтому `main`
    /// печатает её ровно один раз.
    #[test]
    fn readscan_error_is_reported_once() {
        let scratch = Scratch::new();
        let missing = scratch.path("missing.scan");
        let missing = missing.to_str().unwrap();
        let (r, out, log) = readscan_run(
            &FakeBackend::default(),
            &["--readscan", missing, "-oL", "-"],
        );
        let e = r.unwrap_err();
        assert!(out.is_empty());
        assert_eq!(error_text(&e), "");
        let line = format!("[-] {missing}: ");
        assert_eq!(log.matches(&line).count(), 1, "{log}");
        assert_eq!(log.matches("[-] FAIL: --readscan\n").count(), 1, "{log}");
        // `in-binary.c:486-493`: `fopen` раньше `[+] --readscan`.
        assert!(!log.contains("[+]"), "{log}");
        // Неполный файл: `[-] file corrupt` один раз, подвал уже записанного вывода на месте.
        let full = std::fs::read(scan_file(&scratch, "full.scan", &[open_rec()])).unwrap();
        let corrupt = scratch.path("corrupt.scan");
        std::fs::write(&corrupt, &full[..99 + 9]).unwrap();
        let corrupt = corrupt.to_str().unwrap();
        let (r, out, log) = readscan_run(
            &FakeBackend::default(),
            &["--readscan", corrupt, "-oL", "-"],
        );
        assert_eq!(error_text(&r.unwrap_err()), "");
        assert_eq!(log.matches("[-] file corrupt").count(), 1, "{log}");
        assert!(out.is_empty(), "no record was read");
    }

    /// Решение 2 контроллера: реальный формат без имени файла (C молча теряет записи, `output.c:799–803`)
    /// отклоняется двумя строками C до чтения входа и до любого кадра.
    #[test]
    fn file_format_without_a_filename_is_refused() {
        let want = "[-] ERR: no output file, use `--output-filename <filename>` to set one\n\
                    [-] ERR: for `stdout`, use `--output-filename -`";
        for f in [
            "list",
            "json",
            "ndjson",
            "grepable",
            "xml",
            "binary",
            "hostonly",
            "unicornscan",
        ] {
            let (r, out, log) = readscan_run(
                &FakeBackend::default(),
                &["--readscan", "x.scan", "--output-format", f],
            );
            let e = r.unwrap_err();
            assert_eq!(e, want, "{f}");
            assert_eq!(error_text(&e), e, "C form, no wrapper");
            assert!(out.is_empty() && log.is_empty(), "{f}: {log}");
        }
        let (r, _, _) = readscan_run(
            &FakeBackend::default(),
            &[
                "--readscan",
                "x.scan",
                "--output-format",
                "json",
                "--interactive",
            ],
        );
        assert_eq!(r.unwrap_err(), want);
        // none, interactive и умолчание файла не требуют.
        let scratch = Scratch::new();
        let input = scan_file(&scratch, "nofile.scan", &[open_rec()]);
        let input = input.to_str().unwrap();
        for (f, stdout) in [("none", false), ("interactive", true)] {
            let (r, out, _) = readscan_run(
                &FakeBackend::default(),
                &["--readscan", input, "--output-format", f],
            );
            r.unwrap();
            assert_eq!(!out.is_empty(), stdout, "{f}");
        }
    }

    #[test]
    fn error_text_keeps_c_forms_unwrapped() {
        let open = "out: could not open file for writing\n/x: Is a directory (os error 21)";
        assert_eq!(error_text(open), open);
        assert_eq!(error_text("[-] FAIL: x"), "[-] FAIL: x");
        assert_eq!(error_text(LOGGED), "");
        assert_eq!(error_text("x"), "rmasscan: error: x");
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
        let scratch = Scratch::new();
        let f = scratch.write(
            "ex.txt",
            b"# comment\n10.0.0.0/31 # first two\n\n10.0.0.3\n",
        );
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
        let b = FakeBackend {
            ipv4: vec![],
            ..FakeBackend::default()
        };
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

    /// Заполнитель Darwin и групповой MAC не становятся source MAC ни в герметичном `--offline` (IP, MAC и порт заданы,
    /// ОС не опрашивается), ни в `--offline` с обнаружением (порт не задан: интерфейс найден по маршруту).
    #[test]
    fn offline_with_an_unusable_explicit_mac_is_refused() {
        for mac in ["02-00-00-00-00-00", "01-00-5e-00-00-01"] {
            for (port, iface) in [
                (&["--source-port", "40000"][..], "offline"),
                (&[][..], "eth0"),
            ] {
                let mut args = vec![
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
                ];
                args.extend_from_slice(port);
                let e = run_args(&args).unwrap_err();
                assert_eq!(
                    e,
                    format!(
                        "[-] FAIL: failed to detect MAC address of interface: \"{iface}\"\n \
                         [hint] try something like \"--source-mac 00-11-22-33-44-55\""
                    ),
                    "{mac} {port:?}"
                );
            }
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
