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
use rmasscan_core::config::{ConfigError, EchoExtras, Operation, ScanConfig, echo_with, validate};
use rmasscan_core::scan::{format_list_line_v46, list_scan_v46};
use rmasscan_core::targets::TEMPL_TCP_LAST;

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

/// Отказ `main_scan` C (`main.c:1224-1229`): порт скана вместе с `--arp`. Текст как есть, без `[-]` и обёртки.
const ARP_PORTSCAN_REFUSAL: &str = "FAIL: cannot arpscan and portscan at the same time";

/// Проверка `main.c:1224-1229` (после проверок пустых целей и портов): ARP только единственным портом.
fn refuse_arp_with_ports(cfg: &ScanConfig) -> Result<(), String> {
    let ports = cfg.targets.ports();
    if rmasscan_core::probe::is_arp_scan_ports(ports) && ports.count() != 1 {
        return Err(ARP_PORTSCAN_REFUSAL.into());
    }
    Ok(())
}

/// Подэтап 4a: баннеры только UDP. TCP-баннерам нужен собственный стек TCP (`src/stack-tcp-core.c`), он появится в
/// подэтапе 4b; без него скан `--banners -p80` молча дал бы меньше записей, чем C.
const TCP_BANNERS_REFUSAL: &str = "--banners with TCP ports is not supported yet: TCP banners need the \
     user-mode TCP stack, which arrives in the next sub-stage (4b); UDP ports (-pU:53) are supported now";

/// Отказ 4a: `--banners` (или `--rawudp`, который его включает) вместе с портом TCP в скане (живом и `--offline`),
/// до обнаружения адаптера и до первого кадра. `-sL`, `--echo` и `--readscan` ничего не сканируют и не отказывают.
fn refuse_tcp_banners(cfg: &ScanConfig) -> Result<(), String> {
    let tcp = cfg
        .targets
        .ports()
        .as_slice()
        .iter()
        .any(|r| r.begin <= TEMPL_TCP_LAST);
    if cfg.banners && tcp {
        return Err(TCP_BANNERS_REFUSAL.into());
    }
    Ok(())
}

/// `FAIL: <значение>: unknown capture type` и `… nocapture type` (`src/main-conf.c:1159`, `:1174`): строка C.
fn is_capture_refusal(msg: &str) -> bool {
    msg.starts_with("FAIL: ")
        && (msg.ends_with(": unknown capture type") || msg.ends_with(": unknown nocapture type"))
}

/// R3: поверх IPv6 только TCP SYN. Живой скан и `--offline --packet-trace` с целью IPv6 и портом не TCP (`U:`, `S:`,
/// `I:`, `O:`, `--arp`) отказывают до обнаружения адаптера и до кадра (C шлёт их и по IPv6; здесь отложено). `-sL`,
/// `--echo`/`--echo-all`, `--iflist`, `--readscan` и `--offline` без трассировки ничего не строят и принимают любые
/// порты. TCP поверх IPv6 идёт живым путём и трассировкой (R7 снят в T5); план CLI повторяет эту проверку
/// (`PlanError::Ipv6PortNotTcp`).
fn refuse_ipv6_non_tcp(cli: &Cli, cfg: &ScanConfig) -> Result<(), String> {
    if !cfg.targets.has_ipv6_targets() {
        return Ok(());
    }
    let listing = cli.list || cli.echo || cli.echo_all || cli.iflist;
    if listing || (cli.offline && !cli.packet_trace) || !cli.readscan.is_empty() {
        return Ok(());
    }
    let non_tcp = cfg
        .targets
        .ports()
        .as_slice()
        .iter()
        .any(|r| r.end > u32::from(u16::MAX));
    if non_tcp {
        return Err(
            "IPv6 targets support only TCP ports: U:, S:, I:, O: and --arp ports cannot be \
             scanned over IPv6 yet (they are accepted with IPv6 targets only for -sL, --echo and \
             --offline without --packet-trace)"
                .into(),
        );
    }
    Ok(())
}

/// Три строки `LOG(0, ...)` отказа `ExcludeRequired`, `src/main.c:1236-1238` дословно (подсказки с одним пробелом
/// впереди, без префикса `[-]`). Ядро держит однострочный `Display` (его печатает и Studio).
pub const EXCLUDE_REQUIRED_TEXT: &str = "FAIL: range too big, need confirmation\n [hint] to prevent accidents, at least one --exclude must be specified\n [hint] use \"--exclude 255.255.255.255\" as a simple confirmation";

/// Текст stderr для ошибки [`run`]: отказы обнаружения и ARP (`[-] FAIL: …` и подсказки C), отказ `ExcludeRequired`
/// (три строки `main.c:1236-1238`), плохое имя `banner-types` файла конфигурации (`FAIL: bad banner app: …` и `err`,
/// `src/main-conf.c:2694-2695`), неизвестное значение `--capture`/`--nocapture` (`FAIL: …: unknown capture type`,
/// `src/main-conf.c:1159`, `:1174`) и отказ открытия файла вывода (`out: could not open file for …`) как есть, [`LOGGED`] пусто (уже в `log`), прочие ошибки с обёрткой
/// `rmasscan: error:`. Любая ошибка даёт exit 1.
pub fn error_text(msg: &str) -> String {
    if msg == LOGGED {
        String::new()
    } else if msg.starts_with(live::REFUSAL_PREFIX)
        || msg.starts_with(OPEN_FAILURE_PREFIX)
        || msg.starts_with(conf::BAD_BANNER_APP)
        || is_capture_refusal(msg)
        || msg == ARP_PORTSCAN_REFUSAL
    {
        msg.to_string()
    } else if msg == ConfigError::ExcludeRequired.to_string() {
        EXCLUDE_REQUIRED_TEXT.to_string()
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
        ..conf::OutputConfPatch::default()
    }
}

/// Все порты целей за вычетом исключений со сдвигами протоколов, отсортированные и слитые:
/// `masscan->targets.ports` после `massip_apply_excludes` и `massip_optimize` (main.c:1672–1684), строка
/// `# Ports scanned` заголовка `-oG`.
fn target_ports(cfg: &ScanConfig) -> Vec<(u32, u32)> {
    let mut targets = cfg.targets.clone();
    targets.apply_excludes(&mut cfg.excludes.clone());
    targets.optimize();
    targets
        .ports()
        .as_slice()
        .iter()
        .map(|r| (r.begin, r.end))
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
        ports: target_ports(cfg),
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
    // `main.c:1698-1704`: the 63-bit check runs before every operation, `--readscan` included (an IPv6 filter
    // such as `/64` with a port is 65 bits there). IPv4 targets never reach it.
    filter.targets.try_range().map_err(|e| e.to_string())?;
    let env = output_env(backend, &opts, cfg, Some(0));
    readscan::run_readscan(
        &cli.readscan,
        &filter,
        &mut Pipeline::new(opts, &mut *out, env),
        log,
    )?;
    finish(out)
}

/// Строка C (`main-conf.c:3625-3627`), байт в байт.
const SHARD_SEED_WARNING: &str =
    "[-] WARNING: --seed <num> is not specified\n    HINT: all shards must share the same seed\n";

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
    refuse_ipv6_non_tcp(cli, &cfg)?;
    // Р2, main-conf.c:3625-3627: в конце разбора командной строки, для любой операции, `--shard` с `OF > 1` и seed 0
    // (не задан ни в argv, ни в файле) печатает предупреждение: каждый процесс шарда взял бы свою энтропию.
    if cfg.shard.of > 1 && cfg.seed == 0 {
        let _ = log.write_all(SHARD_SEED_WARNING.as_bytes());
        let _ = log.flush();
    }
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
        list_scan_v46(
            eff.massip(),
            eff.seed(),
            eff.blackrock_rounds(),
            eff.shard(),
            eff.resume_index(),
            eff.resume_count(),
            eff.retries(),
            eff.max_rate(),
            |target, port| {
                if res.is_ok() {
                    let mut line = format_list_line_v46(target, port, single_port);
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
        // `--offline` это тот же `main_scan`: отказ ARP и портов виден и без трассировки.
        let mut probe = cfg.clone();
        probe.seed = probe.seed.max(1);
        if validate(&probe, Operation::Scan).is_ok() {
            refuse_arp_with_ports(&cfg)?;
        }
        refuse_tcp_banners(&cfg)?;
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
    // main.c:1224-1229: сразу после проверок пустых целей и портов, до вывода и адаптера.
    refuse_arp_with_ports(&cfg)?;
    refuse_tcp_banners(&cfg)?;
    // Опции проверяются до обнаружения: отказ не стоит ни строки `[+]`, ни кадра. Начало скана - момент `open`.
    let opts = checked_output_options(cli)?;
    // Файл `-` это stdout C (`output.c:216`), и `close_rotate` закрывает его (`output.c:268`) до `printf` времени
    // скана (`main.c:1551`): в stdout C остаётся только формат.
    let elapsed_to_stdout = !opts.format_to_stdout();
    let env = output_env(backend, &opts, &cfg, None);
    // Режим статуса учитывает и `ndjson-status` файлов `-c`/`--resume` (T2 M-5).
    let mode = cli.status_mode();
    // `paused.conf` (первое Ctrl-C) повторяет разобранную конфигурацию: вывод по позиции `--resume`, `-oX`, а
    // `ndjson-status` уже в `full` по позиции argv (C пишет его по `is_status_ndjson` и при `--nostatus`,
    // main-conf.c:1512-1513).
    let mut full = full;
    full.output = output_patch(&opts);
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

    /// Core держит однострочный `Display` (его печатает Studio), CLI подменяет его тремя строками C
    /// (`src/main.c:1236-1238`).
    #[test]
    fn exclude_required_prints_three_c_lines_in_cli() {
        let msg = ConfigError::ExcludeRequired.to_string();
        assert_eq!(error_text(&msg), EXCLUDE_REQUIRED_TEXT);
        assert_eq!(
            EXCLUDE_REQUIRED_TEXT,
            "FAIL: range too big, need confirmation\n\
             \x20[hint] to prevent accidents, at least one --exclude must be specified\n\
             \x20[hint] use \"--exclude 255.255.255.255\" as a simple confirmation"
        );
    }
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

    /// T5 New-3: `infinite = true` из файла `-c` обходит `conflicts_with` clap; `-sL` с ним отказывает, а не печатает
    /// список один раз молча.
    #[test]
    fn conf_infinite_with_list_is_refused() {
        let scratch = Scratch::new();
        let conf = scratch.write("inf.conf", b"infinite = true\n");
        let c = conf.to_str().unwrap();
        let e = run_args(&[
            "rmasscan",
            "-c",
            c,
            "-sL",
            "198.18.0.0/30",
            "-p80",
            "--seed",
            "1",
        ])
        .unwrap_err();
        assert!(e.contains("--infinite"), "{e}");
        // Без `-sL` файл по-прежнему разрешён (`--echo` его печатает).
        assert!(
            run_args(&[
                "rmasscan",
                "-c",
                c,
                "--echo",
                "198.18.0.0/30",
                "-p80",
                "--seed",
                "1"
            ])
            .is_ok()
        );
    }

    #[test]
    fn unsupported_option_errors() {
        assert!(
            Cli::try_parse_masscan(["rmasscan", "--heartbleed", "10.0.0.0/24", "-p80"]).is_err()
        );
        assert!(Cli::try_parse_masscan(["rmasscan", "--nonsense"]).is_err());
        // `-oX FILE` разбирается; без целей `run` отказывает раньше, чем тронет файл.
        let scratch = Scratch::new();
        let path = scratch.path("no-targets.xml");
        let e = run_args(&["rmasscan", "-oX", path.to_str().unwrap()]).unwrap_err();
        assert!(e.contains("target IP address list empty"), "{e}");
        assert!(!path.exists());
    }

    fn echo_of(extra: &[&str]) -> String {
        let base = ["rmasscan", "--echo", "10.0.0.0/30", "-p80", "--seed", "1"];
        run_args(&[&base[..], extra].concat()).unwrap()
    }

    fn scan_config(extra: &[&str]) -> ScanConfig {
        let base = ["rmasscan", "10.0.0.0/30", "-pU:53"];
        Cli::try_parse_masscan([&base[..], extra].concat())
            .unwrap()
            .to_config()
            .unwrap()
    }

    /// Задача 6, шаг 2: в 4a `--banners` (и `--rawudp`, который его включает) с портом TCP отказывает с кодом 1 до
    /// обнаружения и любого кадра (живой скан и `--offline`): TCP-баннерам нужен стек TCP, он придёт в 4b. `-pU:53`
    /// проходит; `--nobanners` правее снимает отказ; `-sL` и `--echo` ничего не сканируют и принимают любые порты.
    #[test]
    fn banners_with_tcp_ports_is_refused_in_4a() {
        for extra in [
            &["-p80", "--banners"][..],
            &["-p80,U:53", "--rawudp"],
            &["--banners", "-pU:53,T:443"],
            &["-pU:53", "--top-ports", "5", "--banner"],
        ] {
            // `FakeBackend::open` и `interrupts` паникуют: отказ раньше обнаружения и Ctrl-C.
            for op in [&["rmasscan"][..], &["rmasscan", "--offline", "--seed", "1"]] {
                let e = run_args(&[op, &["198.51.100.1"], extra].concat()).unwrap_err();
                assert!(
                    e.contains("TCP banners") && e.contains("next sub-stage"),
                    "{extra:?}: {e}"
                );
                assert_eq!(error_text(&e), format!("rmasscan: error: {e}"));
            }
        }
        for ok in [
            &[
                "--offline",
                "198.51.100.1",
                "-pU:53",
                "--banners",
                "--seed",
                "1",
            ][..],
            &[
                "--offline",
                "198.51.100.1",
                "-pU:53,S:2905,I:0",
                "--rawudp",
                "--seed",
                "1",
            ],
            &[
                "--offline",
                "198.51.100.1",
                "-p80",
                "--banners",
                "--nobanners",
                "--seed",
                "1",
            ],
            &["--echo", "198.51.100.1", "-p80", "--banners", "--seed", "1"],
            &["-sL", "198.51.100.1", "-p80", "--rawudp", "--seed", "1"],
        ] {
            run_args(&[&["rmasscan"][..], ok].concat()).unwrap();
        }
    }

    /// `--banners`/`--banner` (`src/main-conf.c:1106-1116`) и `--rawudp` (`:1118-1130`, ставит и `banners`) в `--echo`
    /// как у C: после `shard` (таблица `:2377-2378`), только когда включены; `--hello-timeout N` (`:1288-1298`, после
    /// `pcap-payloads`, `:2390`) только когда не 0. `F_BOOL`: голый флаг это `true`, следующее слово не забирается.
    #[test]
    fn banners_echo_like_c() {
        let plain = echo_of(&[]);
        let with =
            |lines: &str| plain.replacen("shard = 1/1\n", &format!("shard = 1/1\n{lines}"), 1);
        assert_eq!(echo_of(&["--banners"]), with("banners = true\n"));
        assert_eq!(echo_of(&["--banner"]), with("banners = true\n"));
        assert_eq!(echo_of(&["--banners=yes"]), with("banners = true\n"));
        assert_eq!(
            echo_of(&["--rawudp"]),
            with("banners = true\nrawudp = true\n")
        );
        assert_eq!(echo_of(&["--banners=false"]), plain);
        assert_eq!(echo_of(&["--rawudp=0"]), plain);
        // Флаг перед целью не забирает её как значение.
        let e = run_args(&[
            "rmasscan",
            "--echo",
            "--banners",
            "10.0.0.0/30",
            "-p80",
            "--seed",
            "1",
        ]);
        assert_eq!(e.unwrap(), with("banners = true\n"));
        assert_eq!(
            echo_of(&["--hello-timeout", "7"]),
            plain.replacen(
                "nocapture = servername\n",
                "hello-timeout = 7\nnocapture = servername\n",
                1
            )
        );
        assert_eq!(echo_of(&["--hello-timeout=0"]), plain);
        assert!(
            run_args(&[
                "rmasscan",
                "--echo",
                "10.0.0.0/30",
                "-p80",
                "--seed",
                "1",
                "--hello-timeout",
                "x"
            ])
            .is_err()
        );
        // `--echo-all` у C тот же `masscan_echo(.., 0)`.
        let all = run_args(&[
            "rmasscan",
            "--echo-all",
            "10.0.0.0/30",
            "-p80",
            "--seed",
            "1",
            "--rawudp",
        ]);
        assert_eq!(all.unwrap(), with("banners = true\nrawudp = true\n"));
        // `paused.conf` пишет те же ключи и читает их обратно.
        let scratch = Scratch::new();
        let conf = scratch.write(
            "b.conf",
            echo_of(&["--rawudp", "--hello-timeout", "3"]).as_bytes(),
        );
        let c = scan_config(&["-c", conf.to_str().unwrap()]);
        assert_eq!((c.banners, c.rawudp, c.hello_timeout), (true, true, 3));
    }

    /// `--nobanners`/`--nobanner` (`src/main-conf.c:1546-1554`: `is_banners = !parseBoolean(value)`) и прочие ключи
    /// баннеров применяются в порядке argv, вместе с файлами `-c`: побеждает правый. `--rawudp --nobanners` оставляет
    /// `rawudp`, но без баннеров; в эхо тогда только `rawudp = true`.
    #[test]
    fn nobanners_after_banners() {
        let flags = |extra: &[&str]| {
            let c = scan_config(extra);
            (c.banners, c.rawudp)
        };
        assert_eq!(flags(&[]), (false, false));
        assert_eq!(flags(&["--banners", "--nobanners"]), (false, false));
        assert_eq!(flags(&["--nobanners", "--banners"]), (true, false));
        assert_eq!(flags(&["--rawudp", "--nobanners"]), (false, true));
        assert_eq!(flags(&["--nobanners", "--rawudp"]), (true, true));
        assert_eq!(flags(&["--banners", "--nobanner=false"]), (true, false));
        assert_eq!(flags(&["--rawudp", "--rawudp=false"]), (true, false));
        // Р17: имена по `EQUALS` C (`src/main-conf.c:833-849`): регистр и `-`, `.`, `_` не важны, `:` как `=`.
        assert_eq!(flags(&["--BANNERS", "--No-Banners"]), (false, false));
        assert_eq!(flags(&["--No_Banner:false", "--raw.udp"]), (true, true));
        assert_eq!(flags(&["--Raw_UDP=0", "--Banner"]), (true, false));
        let scratch = Scratch::new();
        let f = scratch.write("on.conf", b"banners = true\nrawudp = 1\n");
        let f = f.to_str().unwrap();
        assert_eq!(flags(&["-c", f, "--nobanners"]), (false, true));
        assert_eq!(flags(&["--nobanners", "-c", f]), (true, true));
        let off = scratch.write("off.conf", b"nobanners = true\n");
        let off = off.to_str().unwrap();
        assert_eq!(flags(&["--banners", "-c", off]), (false, false));
        assert_eq!(flags(&["-c", off, "--banner"]), (true, false));
        let plain = echo_of(&[]);
        assert_eq!(
            echo_of(&["--rawudp", "--nobanners"]),
            plain.replacen("shard = 1/1\n", "shard = 1/1\nrawudp = true\n", 1)
        );
        assert_eq!(echo_of(&["--banners", "--nobanners"]), plain);
    }

    /// `--capture`/`--nocapture`/`--no-capture` (`src/main-conf.c:1132-1180`): значение по `EQUALS` (регистр и `-._`
    /// не важны), в порядке argv и файлов. В 4a только разбор и `--echo`: блок печатается дважды (ключи `capture` и
    /// `nocapture` таблицы, `:2402-2403`), cert и servername когда выключены, остальные когда включены.
    #[test]
    fn capture_values_parse_and_echo() {
        let plain = echo_of(&[]);
        let twice = "nocapture = servername\nnocapture = servername\n";
        assert!(plain.contains(twice), "{plain}");
        let block = |lines: &str| plain.replacen(twice, &lines.repeat(2), 1);
        assert_eq!(echo_of(&["--capture", "servername"]), block(""));
        assert_eq!(
            echo_of(&["--nocapture", "cert"]),
            block("nocapture = cert\nnocapture = servername\n")
        );
        assert_eq!(
            echo_of(&[
                "--capture",
                "HTML",
                "--capture=heart_bleed",
                "--no-capture",
                "html",
                "--capture",
                "Ticket-Bleed",
            ]),
            block("nocapture = servername\ncapture = heartbleed\ncapture = ticketbleed\n")
        );
        let c = scan_config(&["--capture", "html", "--nocapture=cert"]).capture;
        assert_eq!(
            (c.cert, c.servername, c.html, c.heartbleed, c.ticketbleed),
            (false, false, true, false, false)
        );
        let scratch = Scratch::new();
        let f = scratch.write("cap.conf", b"capture = html\nno-capture = cert\n");
        let f = f.to_str().unwrap();
        assert_eq!(
            echo_of(&["-c", f]),
            block("nocapture = cert\nnocapture = servername\ncapture = html\n")
        );
        assert_eq!(
            echo_of(&["-c", f, "--capture", "cert", "--nocapture", "html"]),
            plain
        );
        // Имена опций по `EQUALS`, значение после `:`.
        assert_eq!(
            echo_of(&["--Capture:html", "--NO_CAPTURE", "cert"]),
            block("nocapture = cert\nnocapture = servername\ncapture = html\n")
        );
        assert_eq!(
            echo_of(&["--Hello.Timeout", "9"]),
            plain.replacen("nocapture", "hello-timeout = 9\nnocapture", 1)
        );
    }

    /// Неизвестное значение `--capture`/`--nocapture`: строка C (`src/main-conf.c:1159`, `:1174`) как есть и код 1
    /// (Р17; у C разбор идёт дальше); так же из файла `-c`. Без значения это ошибка разбора.
    #[test]
    fn capture_bad_value_fails() {
        let e = run_args(&[
            "rmasscan",
            "--echo",
            "10.0.0.0/30",
            "-p80",
            "--seed",
            "1",
            "--capture",
            "bogus",
        ])
        .unwrap_err();
        assert_eq!(e, "FAIL: bogus: unknown capture type");
        assert_eq!(error_text(&e), e);
        let e = run_args(&[
            "rmasscan",
            "--echo",
            "10.0.0.0/30",
            "-p80",
            "--seed",
            "1",
            "--nocapture=x",
        ])
        .unwrap_err();
        assert_eq!(e, "FAIL: x: unknown nocapture type");
        let scratch = Scratch::new();
        let f = scratch.write("bad.conf", b"capture = everything\n");
        let e = run_args(&[
            "rmasscan",
            "--echo",
            "10.0.0.0/30",
            "-p80",
            "--seed",
            "1",
            "-c",
            f.to_str().unwrap(),
        ])
        .unwrap_err();
        assert_eq!(e, "FAIL: everything: unknown capture type");
        assert!(Cli::try_parse_masscan(["rmasscan", "10.0.0.0/30", "-p80", "--capture"]).is_err());
    }

    /// Справка `--help` называет формат `certs` (баннеры X.509 PEM в stdout, `src/out-certs.c`).
    #[test]
    fn help_names_the_certs_format() {
        use clap::CommandFactory;
        let help = Cli::command()
            .get_after_help()
            .map(ToString::to_string)
            .unwrap_or_default();
        assert!(help.contains("--output-format certs"), "{help}");
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
            ip: Ipv4Addr::new(1, 2, 3, 4).into(),
            port: 80,
            proto: output::Proto::Tcp,
            status: output::Status::Open,
            reason: 0x12,
            ttl: 57,
            mac: None,
        }
    }

    fn closed_rec() -> output::Record {
        output::Record {
            timestamp: 1_700_000_000,
            ip: Ipv4Addr::new(10, 0, 0, 255).into(),
            port: 443,
            proto: output::Proto::Tcp,
            status: output::Status::Closed,
            reason: 0x14,
            ttl: 64,
            mac: None,
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
            ports: Vec::new(),
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

    /// `--banner-types` и синонимы `--banner-type`, `--banner-apps`, `--banner-app` (`src/main-conf.c:2683-2697`):
    /// одно имя `masscan_string_to_app` на опцию, регистр важен, запятая не разделяет (`ssl,http` это одно неизвестное
    /// имя), `unknown` и `error` не выбираются. Плохое имя: `LOG(0, "FAIL: bad banner app: %s\n")` и `err` в stderr,
    /// код 1, до чтения входа; то же у ключа файла конфигурации.
    #[test]
    fn banner_types_bad_name_fails() {
        for (opt, v) in [
            ("--banner-types", "X"),
            ("--banner-type", "HTTP"),
            ("--banner-apps", "ssl,http"),
            ("--banner-app", "unknown"),
            ("--banner-types", "error"),
        ] {
            match Cli::try_parse_masscan(["rmasscan", opt, v, "--readscan", "f"]) {
                Err(args::ParseError::Masscan(t)) => {
                    assert_eq!(t, format!("FAIL: bad banner app: {v}\nerr"), "{opt} {v}")
                }
                other => panic!("{opt} {v}: {other:?}"),
            }
        }
        let scratch = Scratch::new();
        let conf = scratch.write("bt.conf", b"banner-types = x509ca\nbanner-app = bogus\n");
        let e =
            run_args(&["rmasscan", "-c", conf.to_str().unwrap(), "--readscan", "f"]).unwrap_err();
        assert_eq!(error_text(&e), "FAIL: bad banner app: bogus\nerr");
        // Хорошие имена копятся из всех синонимов, командной строки и файла.
        let conf = scratch.write("ok.conf", b"banner-apps = x509\nbannerapp = vnc-old\n");
        let cli = Cli::try_parse_masscan([
            "rmasscan",
            "--banner-types",
            "ssl",
            "--banner-app",
            "http",
            "--banner-type=dns-ver",
            "-c",
            conf.to_str().unwrap(),
            "--banner-apps",
            "ssh1",
            "--readscan",
            "f",
        ])
        .unwrap();
        assert_eq!(
            cli.to_config()
                .unwrap()
                .banner_types
                .into_iter()
                .collect::<Vec<_>>(),
            vec![2, 4, 6, 9, 15, 23]
        );
    }

    /// `--readscan` с `--banner-types` через `run`: записи статуса не выводятся, баннеры типов 9/13 только своих
    /// приложений; два имени это две опции (`--banner-types ssl --banner-types http`).
    #[test]
    fn readscan_banner_types_select_apps() {
        let scratch = Scratch::new();
        let path = scratch.path("bt.scan");
        {
            let wall = FakeBackend::default();
            let mut sink_out = Vec::new();
            let env = OutputEnv {
                wall: &wall,
                services: output::ServiceNames::empty(),
                ports: Vec::new(),
                scan_started: None,
            };
            let o = OutputOptions {
                format: output::Format::Binary,
                filename: Some(path.to_string_lossy().into_owned()),
                ..OutputOptions::default()
            };
            let mut p = Pipeline::new(o, &mut sink_out, env);
            output::Sink::open(&mut p).unwrap();
            p.report_record(&open_rec()).unwrap();
            for (app, text) in [(4u16, "HTTP/1.1"), (9, "TLS"), (6, "9.18")] {
                p.report_banner(&rmasscan_proto::BannerRecord {
                    timestamp: 1_700_000_000 + u64::from(app),
                    ip: Ipv4Addr::new(192, 0, 2, 1).into(),
                    ip_proto: 6,
                    port: 80,
                    app,
                    ttl: 64,
                    payload: text.as_bytes().to_vec(),
                })
                .unwrap();
            }
            output::Sink::finish(&mut p).unwrap();
        }
        let input = path.to_str().unwrap();
        let (r, out, _) = readscan_run(
            &FakeBackend::default(),
            &["--banner-types", "dns-ver", "--readscan", input, "-oL", "-"],
        );
        r.unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "#masscan\nbanner tcp 80 192.0.2.1 1700000006 dns-ver 9.18\n# end\n"
        );
        let (r, out, _) = readscan_run(
            &FakeBackend::default(),
            &[
                "--banner-types",
                "ssl",
                "--banner-types",
                "http",
                "--readscan",
                input,
                "-oL",
                "-",
            ],
        );
        r.unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "#masscan\nbanner tcp 80 192.0.2.1 1700000004 http HTTP/1.1\n\
             banner tcp 80 192.0.2.1 1700000009 ssl TLS\n# end\n"
        );
        // Р17: `banner-types` и три синонима сравниваются по `EQUALS` C (`src/main-conf.c:2683-2697`), значение
        // следующим словом, как у `--capture`.
        for spelling in [
            "--Banner-Types",
            "--banner_type",
            "--BANNER.APPS",
            "--banner-app",
        ] {
            let (r, out, _) = readscan_run(
                &FakeBackend::default(),
                &[spelling, "dns-ver", "--readscan", input, "-oL", "-"],
            );
            r.unwrap();
            assert_eq!(
                String::from_utf8(out).unwrap(),
                "#masscan\nbanner tcp 80 192.0.2.1 1700000006 dns-ver 9.18\n# end\n",
                "{spelling}"
            );
        }
        // Без `--banner-types` и без `-o`: строки `Discovered` и `Banner on port` в stdout (`output.c:903-923`).
        let (r, out, _) = readscan_run(&FakeBackend::default(), &["--readscan", input]);
        r.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(out.lines().count(), 4, "{out}");
        assert!(
            out.contains("Banner on port 80/tcp on 192.0.2.1: [dns-ver] 9.18"),
            "{out}"
        );
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
            &["rmasscan", "-sL", "10.0.0.0/30", "-pU:65536", "--seed", "1"][..],
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
            // IPv6 is accepted since the IPv6 stage (Task 2), malformed IPv6 is not
            &["rmasscan", "-sL", "2001:db8::zz", "-p80", "--seed", "1"][..],
            &["rmasscan", "-sL", "2001:db8::/129", "-p80", "--seed", "1"][..],
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

    #[test]
    fn packet_trace_refuses_oproto_and_icmp_but_echo_and_list_accept_all_prefixes() {
        // Р1: трассировка (как и живой скан) отказывает на O:* и I:1+, текст называет порт
        let e = run_args(&trace_args(&["-pO:47"])).unwrap_err();
        assert!(e.contains("O:47"), "{e}");
        let e = run_args(&trace_args(&["-pI:1"])).unwrap_err();
        assert!(e.contains("I:1"), "{e}");
        // SCTP построен (Задача 5): `S:` проходит, UNK-строки проверяет `packet_trace_prints_the_c_unk_line_for_sctp`.
        let out = run_args(&trace_args(&["-pS:2905"])).unwrap();
        assert_eq!(out.lines().count(), 12, "{out}");
        // I:0 строит ICMP Echo: к 8 SYN (TRACE шлёт на 80 и 443) добавляется по строке ICMP на каждый из 4 адресов
        let out = run_args(&trace_args(&["-pI:0"])).unwrap();
        assert_eq!(out.lines().count(), 12, "{out}");
        let icmp = out
            .lines()
            .filter(|l| l.contains(") ICMP [10.255.0.1]:8 "))
            .count();
        assert_eq!(icmp, 4, "{out}");
        // ARP-индекс вместе с TCP-портами трассировки: отказ смеси текстом C (main.c:1224-1229)
        let (res, out, log) = run_capture(&trace_args(&["-pI:2"]));
        assert_eq!(
            res.unwrap_err(),
            "FAIL: cannot arpscan and portscan at the same time"
        );
        assert!(out.is_empty() && log.is_empty());
        assert_eq!(
            run_args(&trace_args(&[])).unwrap().lines().count(),
            8,
            "pure TCP trace still runs"
        );
        // --echo и -sL принимают все пять префиксов и печатают их как C (O:47 как I:303)
        let echo = run_args(&[
            "rmasscan",
            "--echo",
            "10.0.0.1",
            "-pU:53,T:80-81,s:2905,I:0,o:47",
            "--seed",
            "1",
        ])
        .unwrap();
        assert!(
            echo.contains("ports = 80-81,U:53,S:2905,I:0,I:303\n"),
            "{echo}"
        );
        run_args(&["rmasscan", "-sL", "10.0.0.1", "-pO:47,U:53", "--seed", "1"]).unwrap();
        // без трассировки --offline ничего не строит и не отказывает
        run_args(&["rmasscan", "--offline", "10.0.0.1", "-pO:47", "--seed", "1"]).unwrap();
    }

    /// C `main-ptrace.c` не знает `FOUND_SCTP` и печатает ветку `default`: `SENT (%5.4f) UNK  %-21s > %-21s [%u]\n` с
    /// номером `FOUND_SCTP` = 7 (образец снят с C 8e6b3b0 `packet_trace()` на кадре SCTP INIT).
    #[test]
    fn packet_trace_prints_the_c_unk_line_for_sctp() {
        let out = run_args(&trace_args(&["-pS:2905"])).unwrap();
        let unk: Vec<&str> = out
            .split_inclusive('\n')
            .filter(|l| l.contains(") UNK  "))
            .collect();
        assert_eq!(unk.len(), 4, "{out}");
        let p = prepared(&trace_args(&["-pS:2905"]));
        let mut want = Vec::new();
        live::for_each_probe(&p.eff, &p.binding, |pr| {
            if pr.frame[23] == 132 {
                want.push((
                    format!("[{}]:{}", Ipv4Addr::from(pr.ip_me), pr.port_me),
                    format!("[{}]:{}", Ipv4Addr::from(pr.ip_them), pr.port_them),
                ));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(want.len(), 4);
        for (line, (from, to)) in unk.iter().zip(&want) {
            let tail = format!("UNK  {from:<21} > {to:<21} [7]\n");
            assert!(line.starts_with("SENT ("), "{line:?}");
            assert!(line.ends_with(&tail), "{line:?} vs {tail:?}");
        }
        // SCTP не печатает ни TCP, ни UDP
        assert_eq!(out.lines().count(), 12, "8 SYN и 4 INIT: {out}");
    }

    /// `main-ptrace.c` `FOUND_UDP`/`FOUND_DNS`: `SENT (%5.4f) UDP  %-21s > %-21s \n` (после второго адреса остаётся пробел).
    #[test]
    fn packet_trace_prints_the_c_udp_sent_line() {
        let out = run_args(&trace_args(&["-pU:53,U:59999"])).unwrap();
        // 8 SYN на 80 и 443, по 4 строки UDP на 53 и на 59999
        assert_eq!(out.lines().count(), 16, "{out}");
        let udp: Vec<&str> = out
            .split_inclusive('\n')
            .filter(|l| l.contains(") UDP  "))
            .collect();
        assert_eq!(udp.len(), 8, "{out}");
        let p = prepared(&trace_args(&["-pU:53,U:59999"]));
        let mut want = Vec::new();
        live::for_each_probe(&p.eff, &p.binding, |pr| {
            if pr.frame[23] == 17 {
                want.push((
                    format!("[{}]:{}", Ipv4Addr::from(pr.ip_me), pr.port_me),
                    format!("[{}]:{}", Ipv4Addr::from(pr.ip_them), pr.port_them),
                ));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(want.len(), 8);
        for (line, (from, to)) in udp.iter().zip(&want) {
            // SENT (0.0000) UDP  [10.255.0.1]:4000N         > [10.0.0.N]:53        <пробел>\n
            let tail = format!("UDP  {from:<21} > {to:<21} \n");
            assert!(line.starts_with("SENT ("), "{line:?}");
            assert!(line.ends_with(&tail), "{line:?} vs {tail:?}");
            let secs = line["SENT (".len()..].split_once(')').unwrap().0;
            assert_eq!(secs.len(), "0.0000".len(), "{line:?}");
        }
        assert!(udp[0].contains(") UDP  [10.255.0.1]:4000"), "{}", udp[0]);
        assert!(udp.iter().any(|l| l.contains("> [10.0.0.0]:59999 ")));
        // у UDP нет флагов TCP и числа байт нагрузки (в C `%u-bytes` только у TCP с `app_length`)
        assert!(
            udp.iter()
                .all(|l| !l.contains("SYN") && !l.contains("-bytes"))
        );
    }

    /// `--nmap-payloads` и `--pcap-payloads`: порядок в `--echo` снят с C (`masscan --echo 10.0.0.0/30 -p80 --seed 1
    /// --nmap-payloads /tmp/x.txt --pcap-payloads /tmp/y.pcap --noreset --offline --pcap /tmp/z.pcap --ndjson-status
    /// --retries 2`, config_parameters[], main-conf.c:2380-2399; `--ndjson-status` с `--echo` здесь отказывает); синонимы в единственном числе и файл `-c`.
    #[test]
    fn payload_options_are_positional_and_echoed_in_c_order() {
        let head = |extra: &[&str]| {
            let mut args = vec![
                "rmasscan",
                "--echo",
                "10.0.0.0/30",
                "-p80",
                "--seed",
                "1",
                "--nmap-payloads",
                "/tmp/x.txt",
                "--pcap-payloads",
                "/tmp/y.pcap",
                "--noreset",
                "--retries",
                "2",
            ];
            args.extend_from_slice(extra);
            run_args(&args)
                .unwrap()
                .lines()
                .take_while(|l| !l.starts_with("nocapture"))
                .map(|l| format!("{l}\n"))
                .collect::<String>()
        };
        let top = "seed = 1\nrate = 100       \nshard = 1/1\nretries = 2\nnoreset = true\nnmap-payloads = /tmp/x.txt\n";
        // `--offline` стоит между двумя ключами; `--pcap` (только живой скан) между `offline` и `pcap-payloads`
        assert_eq!(
            head(&["--offline"]),
            format!("{top}offline = true\npcap-payloads = /tmp/y.pcap\n")
        );
        assert_eq!(
            head(&["--pcap", "/tmp/z.pcap"]),
            format!("{top}pcap-filename = /tmp/z.pcap\npcap-payloads = /tmp/y.pcap\n")
        );
        // единственное число, как синонимы C (`nmap-payload`, `pcap-payload`)
        let cfg = Cli::try_parse_masscan([
            "rmasscan",
            "10.0.0.1",
            "--nmap-payload",
            "a.txt",
            "--pcap-payload",
            "b.pcap",
        ])
        .unwrap()
        .to_config()
        .unwrap();
        assert_eq!(cfg.nmap_payloads.as_deref(), Some("a.txt"));
        assert_eq!(cfg.pcap_payloads.as_deref(), Some("b.pcap"));
        // ключ файла и позиция в argv: правее файла побеждает аргумент, левее победит файл
        let scratch = Scratch::new();
        let conf = scratch.write(
            "p.conf",
            b"nmap-payloads = from-file.txt\npcap-payloads = from-file.pcap\n",
        );
        let c = conf.to_str().unwrap();
        let cfg = |args: &[&str]| {
            Cli::try_parse_masscan(args.iter().copied())
                .unwrap()
                .to_config()
                .unwrap()
        };
        let right = cfg(&[
            "rmasscan",
            "10.0.0.1",
            "-c",
            c,
            "--nmap-payloads",
            "arg.txt",
        ]);
        assert_eq!(right.nmap_payloads.as_deref(), Some("arg.txt"));
        assert_eq!(right.pcap_payloads.as_deref(), Some("from-file.pcap"));
        let left = cfg(&[
            "rmasscan",
            "10.0.0.1",
            "--nmap-payloads",
            "arg.txt",
            "-c",
            c,
        ]);
        assert_eq!(left.nmap_payloads.as_deref(), Some("from-file.txt"));
        // без опций ключей в `--echo` нет
        let plain = run_args(&["rmasscan", "--echo", "10.0.0.1", "-p80", "--seed", "1"]).unwrap();
        assert!(!plain.contains("payloads"), "{plain}");
    }

    /// Файл `-c`/`--resume` C разбирает на его месте в `argv` (`masscan_set_parameter` по ходу разбора), поэтому
    /// префикс по умолчанию его строки `ports =` задают `-sU`/`-sZ`/`--udp-ports` левее файла, а правее нет
    /// (main-conf.c:2663–2674: UDP важнее SCTP; `--udp-ports` ставит `scan_type.udp`, :2642–2648). Ожидания сняты с
    /// C 8e6b3b0 (`masscan 10.0.0.1 <argv> --echo`, файл `f` это `ports = 53`, `g` это `ports = 53,U:161`, `nest`
    /// это `conf = f`); строка `ports = …` вывода C:
    /// - `-sU -c f` → `ports = U:53`; `-c f -sU` → `ports = 53`;
    /// - `-sZ -c f` → `ports = S:53`; `-c f -sZ` → `ports = 53`; `-c f` → `ports = 53`;
    /// - `-sU -sZ -c f` и `-sZ -sU -c f` → `ports = U:53`; `-sS -sU -c f` → `ports = U:53`;
    /// - `--udp-ports 7 -c f` → `ports = U:7,U:53`; `-sU -c g` → `ports = U:53,U:161`;
    /// - `-sU -c nest` → `ports = U:53`; `-sU --resume f` → `ports = U:53`; `-c f -sU -p 80` → `ports = 53,U:80`.
    #[test]
    fn scan_type_left_of_a_conf_file_prefixes_its_ports_as_in_c() {
        let scratch = Scratch::new();
        let f = scratch.write("f", b"ports = 53\n");
        let g = scratch.write("g", b"ports = 53,U:161\n");
        let nest = scratch.write("nest", format!("conf = {}\n", f.display()).as_bytes());
        let (f, g, nest) = (
            f.to_str().unwrap(),
            g.to_str().unwrap(),
            nest.to_str().unwrap(),
        );
        let ports = |argv: &[&str]| {
            let mut a = vec!["rmasscan", "10.0.0.1"];
            a.extend_from_slice(argv);
            a.extend_from_slice(&["--seed", "1", "--echo"]);
            let out = run_args(&a).unwrap();
            out.lines()
                .find(|l| l.starts_with("ports = "))
                .unwrap_or_else(|| panic!("{argv:?}: no ports line in {out}"))
                .to_string()
        };
        for (argv, c) in [
            (&["-sU", "-c", f][..], "ports = U:53"),
            (&["-c", f, "-sU"][..], "ports = 53"),
            (&["-sZ", "-c", f][..], "ports = S:53"),
            (&["-c", f, "-sZ"][..], "ports = 53"),
            (&["-c", f][..], "ports = 53"),
            (&["-sU", "-sZ", "-c", f][..], "ports = U:53"),
            (&["-sZ", "-sU", "-c", f][..], "ports = U:53"),
            (&["-sS", "-sU", "-c", f][..], "ports = U:53"),
            (&["--udp-ports", "7", "-c", f][..], "ports = U:7,U:53"),
            (&["-sU", "-c", g][..], "ports = U:53,U:161"),
            (&["-sU", "-c", nest][..], "ports = U:53"),
            (&["-sU", "--resume", f][..], "ports = U:53"),
            (&["-c", f, "-sU", "-p", "80"][..], "ports = 53,U:80"),
        ] {
            assert_eq!(ports(argv), c, "{argv:?}");
        }
    }

    /// `--top-ports` C строит в конце разбора по итоговым типам скана, и TCP по умолчанию только если нет ни UDP, ни
    /// SCTP, ни ping, ни ARP, ни oproto (main-conf.c:3609–3619); `scan_type.arp` ставит `SET_arpscan` (`--arp`,
    /// `--arpscan`, ключ файла `arpscan =`, main-conf.c:1088–1102), а `-pI:2` его не ставит. Ожидания сняты с C 8e6b3b0
    /// (`masscan 10.0.0.1 <argv> --echo`, файл `a` это `arpscan = true`); строка `ports = …` вывода C:
    /// - `--arp --top-ports 5` и `--top-ports 5 --arp` → `ports = I:2`; `--arpscan --top-ports 3` → `ports = I:2`;
    /// - `--arp --top-ports 5 -sS` → `ports = 21,80,443,990,8080,I:2`;
    /// - `--arp --top-ports 5 -sU` → `ports = U:135,U:137-138,U:161,U:500,I:2`;
    /// - `--arp --top-ports 5 --ping` → `ports = I:0,I:2`;
    /// - `-pI:2 --top-ports 5` → `ports = 21,80,443,990,8080,I:2`;
    /// - `-c a --top-ports 5` и `--top-ports 5 -c a` → `ports = I:2`.
    ///
    /// oproto: у rmasscan нет ни `-sO`, ни ключа `oprotos` (C main-conf.c:2649–2655, :3524), а `-pO:47` у C
    /// `scan_type.oproto` не ставит, поэтому эту часть условия у rmasscan ничто не задаёт.
    #[test]
    fn arp_scan_drops_the_tcp_default_of_top_ports_as_in_c() {
        let scratch = Scratch::new();
        let a = scratch.write("a", b"arpscan = true\n");
        let a = a.to_str().unwrap();
        let ports = |argv: &[&str]| {
            let mut v = vec!["rmasscan", "10.0.0.1"];
            v.extend_from_slice(argv);
            v.extend_from_slice(&["--seed", "1", "--echo"]);
            let out = run_args(&v).unwrap();
            out.lines()
                .find(|l| l.starts_with("ports = "))
                .unwrap_or_else(|| panic!("{argv:?}: no ports line in {out}"))
                .to_string()
        };
        for (argv, c) in [
            (&["--arp", "--top-ports", "5"][..], "ports = I:2"),
            (&["--top-ports", "5", "--arp"][..], "ports = I:2"),
            (&["--arpscan", "--top-ports", "3"][..], "ports = I:2"),
            (
                &["--arp", "--top-ports", "5", "-sS"][..],
                "ports = 21,80,443,990,8080,I:2",
            ),
            (
                &["--arp", "--top-ports", "5", "-sU"][..],
                "ports = U:135,U:137-138,U:161,U:500,I:2",
            ),
            (
                &["--arp", "--top-ports", "5", "--ping"][..],
                "ports = I:0,I:2",
            ),
            (
                &["-pI:2", "--top-ports", "5"][..],
                "ports = 21,80,443,990,8080,I:2",
            ),
            (&["-c", a, "--top-ports", "5"][..], "ports = I:2"),
            (&["--top-ports", "5", "-c", a][..], "ports = I:2"),
        ] {
            assert_eq!(ports(argv), c, "{argv:?}");
        }
    }

    /// Файлы нагрузок доходят до кадров: сначала pcap, потом nmap (main-conf.c:3163-3183), оба заменяют встроенные.
    #[test]
    fn payload_files_reach_the_probe_frames() {
        let scratch = Scratch::new();
        let nmap = scratch.write(
            "payloads.txt",
            b"udp 59999\n\"from-nmap\"\nudp 161\n\"x\"\n",
        );
        // pcap с одним пакетом UDP на порт 161 (Ethernet/IPv4, документационные адреса) и одним на 59999
        let udp = |dport: u16, payload: &[u8]| {
            let mut f = vec![
                0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 8, 0,
            ];
            f.extend_from_slice(&[0x45, 0]);
            f.extend_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
            f.extend_from_slice(&[
                0, 0, 0, 0, 64, 17, 0, 0, 198, 18, 0, 1, 198, 18, 0, 2, 0x30, 0x39,
            ]);
            f.extend_from_slice(&dport.to_be_bytes());
            f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            f.extend_from_slice(&[0, 0]);
            f.extend_from_slice(payload);
            f
        };
        let mut pcap = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ];
        for (port, body) in [(161u16, &b"from-pcap"[..]), (59999, b"pcap-loses")] {
            let f = udp(port, body);
            for v in [1u32, 2, f.len() as u32, f.len() as u32] {
                pcap.extend_from_slice(&v.to_le_bytes());
            }
            pcap.extend_from_slice(&f);
        }
        let pcap = scratch.write("payloads.pcap", &pcap);
        let frames = |extra: &[&str]| {
            let p = prepared(&trace_args(
                &[&["-pU:161,U:59999,U:53"][..], extra].concat(),
            ));
            let mut v = Vec::new();
            live::for_each_probe_with(&p.eff, &p.binding, &p.payloads, |pr| {
                if pr.frame[23] == 17 {
                    v.push((pr.port_them, pr.frame[42..].to_vec()));
                }
                Ok(())
            })
            .unwrap();
            v
        };
        let find =
            |v: &[(u16, Vec<u8>)], port: u16| v.iter().find(|f| f.0 == port).unwrap().1.clone();
        let builtin = frames(&[]);
        assert_eq!(builtin.len(), 12);
        assert_eq!(find(&builtin, 161).len(), 59, "built-in SNMP probe");
        assert_eq!(find(&builtin, 59999), b"", "no entry: empty payload");
        assert_eq!(find(&builtin, 53).len(), 31);
        let with_pcap = frames(&["--pcap-payloads", pcap.to_str().unwrap()]);
        assert_eq!(find(&with_pcap, 161), b"from-pcap");
        assert_eq!(find(&with_pcap, 59999), b"pcap-loses");
        assert_eq!(find(&with_pcap, 53).len(), 31, "other built-ins stay");
        let both = frames(&[
            "--pcap-payloads",
            pcap.to_str().unwrap(),
            "--nmap-payloads",
            nmap.to_str().unwrap(),
        ]);
        assert_eq!(find(&both, 161), b"x", "nmap file wins over pcap");
        assert_eq!(find(&both, 59999), b"from-nmap");
        // порядок опций в argv на победителя не влияет (C грузит pcap, затем nmap)
        let swapped = frames(&[
            "--nmap-payloads",
            nmap.to_str().unwrap(),
            "--pcap-payloads",
            pcap.to_str().unwrap(),
        ]);
        assert_eq!(swapped, both);
    }

    #[test]
    fn payload_file_errors_refuse_before_any_output() {
        let scratch = Scratch::new();
        let bad = scratch.write("bad.txt", b"# header\ntcp 80\n\"x\"\n");
        let notpcap = scratch.write("not.pcap", &[0u8; 40]);
        let missing = scratch.dir().join("missing");
        for (opt, file, want) in [
            (
                "--nmap-payloads",
                missing.to_str().unwrap(),
                "--nmap-payloads",
            ),
            (
                "--pcap-payloads",
                missing.to_str().unwrap(),
                "--pcap-payloads",
            ),
            (
                "--nmap-payloads",
                bad.to_str().unwrap(),
                "line 2: expected \"udp\"",
            ),
            (
                "--pcap-payloads",
                notpcap.to_str().unwrap(),
                "unknown byte order",
            ),
        ] {
            let (res, out, log) = run_capture(&trace_args(&["-pU:53", opt, file]));
            let e = res.unwrap_err();
            assert!(e.contains(want), "{opt}: {e}");
            assert!(
                out.is_empty() && log.is_empty(),
                "{opt}: output before the refusal: {out}{log}"
            );
        }
        // `--echo` и `-sL` файлов не читают (в них нет кадров)
        run_args(&[
            "rmasscan",
            "--echo",
            "10.0.0.1",
            "-p80",
            "--seed",
            "1",
            "--nmap-payloads",
            "/nonexistent",
        ])
        .unwrap();
    }

    /// Итог запуска вместе со stdout и stderr (то, что напечатано до отказа).
    fn run_capture(args: &[&str]) -> (Result<(), String>, String, String) {
        let cli = Cli::try_parse_masscan(args.iter().copied()).unwrap();
        let (mut out, mut log) = (Vec::new(), Vec::new());
        let res = run(&cli, &FakeBackend::default(), &mut out, &mut log);
        (
            res,
            String::from_utf8(out).unwrap(),
            String::from_utf8(log).unwrap(),
        )
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

    // ---- IPv6 stage, Task 2 (R7, R3) -------------------------------------------------------------

    /// C binary 8e6b3b0: `masscan -sL --seed 42 2001:db8::/126 192.0.2.0/30 -p80,443`
    /// (main-listscan.c:53-62, `massip_pick` order).
    #[test]
    fn list_scan_accepts_ipv6_and_matches_c_binary() {
        let out = run_args(&[
            "rmasscan",
            "-sL",
            "--seed",
            "42",
            "2001:db8::/126",
            "192.0.2.0/30",
            "-p80,443",
        ])
        .unwrap();
        assert_eq!(
            out,
            "[2001:db8::1]:443\n[2001:db8::2]:80\n192.0.2.2:80\n[2001:db8::3]:80\n192.0.2.1:80\n\
             [2001:db8::1]:80\n[2001:db8::]:443\n192.0.2.3:443\n192.0.2.0:443\n[2001:db8::2]:443\n\
             192.0.2.2:443\n[2001:db8::3]:443\n192.0.2.3:80\n192.0.2.1:443\n[2001:db8::]:80\n\
             192.0.2.0:80\n"
        );
        // one port: addresses only
        let out = run_args(&[
            "rmasscan",
            "-sL",
            "--seed",
            "42",
            "--range",
            "2001:db8::/126",
            "--range",
            "192.0.2.0/30",
            "-p80",
        ])
        .unwrap();
        assert_eq!(
            out,
            "192.0.2.0\n192.0.2.3\n192.0.2.2\n2001:db8::\n2001:db8::3\n192.0.2.1\n2001:db8::1\n\
             2001:db8::2\n"
        );
        // an IPv6 --exclude applies (and the excludefile reads IPv6 too)
        let out = run_args(&[
            "rmasscan",
            "-sL",
            "--seed",
            "42",
            "2001:db8::/126",
            "--exclude",
            "2001:db8::/127",
            "-p80",
        ])
        .unwrap();
        let mut lines: Vec<_> = out.lines().collect();
        lines.sort_unstable();
        assert_eq!(lines, ["2001:db8::2", "2001:db8::3"]);
    }

    /// C binary: `-sL --seed 42 2001:db8::/64 -p80` exits 1 with the 63-bit message.
    #[test]
    fn list_scan_refuses_ipv6_slash_64_with_the_c_message() {
        let e =
            run_args(&["rmasscan", "-sL", "--seed", "42", "2001:db8::/64", "-p80"]).unwrap_err();
        assert!(
            e.contains("scan range too large, max is 63-bits, requested is 65 bits")
                && e.contains("/66"),
            "{e}"
        );
        let e = run_args(&["rmasscan", "--echo", "--seed", "42", "::/0", "-p80"]).unwrap_err();
        assert!(e.contains("requested is 128 bits"), "{e}");
    }

    /// C binary: `--echo --seed 42 2001:db8::/126 2001:db8::5-2001:db8::9 ::1 192.0.2.0/30 -p80,U:53
    /// --exclude 2001:db8::2`.
    #[test]
    fn echo_accepts_ipv6_targets_and_excludes() {
        for flag in ["--echo", "--echo-all"] {
            let out = run_args(&[
                "rmasscan",
                flag,
                "--seed",
                "42",
                "2001:db8::/126",
                "2001:db8::5-2001:db8::9",
                "--range",
                "::1",
                "192.0.2.0/30",
                "-p80,U:53",
                "--exclude",
                "2001:db8::2",
            ])
            .unwrap();
            assert!(
                out.ends_with(
                    "ports = 80,U:53\nrange = 192.0.2.0/30\nrange = ::1\nrange = 2001:db8::/127\n\
                     range = 2001:db8::3\nrange = 2001:db8::5-2001:db8::9\n"
                ),
                "{flag}: {out}"
            );
        }
    }

    fn ipv6_refusal(args: &[&str]) -> String {
        run_args(args).expect_err(&format!("{args:?} must be refused"))
    }

    /// T5 (R7 lifted): a live scan with IPv6 targets goes to IPv6 detection. The library fake has no IPv6 route,
    /// so it ends in the C-form refusal of a missing interface (exit 1), never in the old R7 text, and before any
    /// adapter is opened (the fake backend panics on `open`). A mixed scan detects IPv4 first, then IPv6.
    #[test]
    fn live_scan_with_ipv6_targets_reaches_ipv6_detection() {
        for targets in [&["2001:db8::10"][..], &["10.0.0.0/30", "2001:db8::10"][..]] {
            let mut a = vec!["rmasscan"];
            a.extend_from_slice(targets);
            a.extend_from_slice(&["-p80", "--seed", "1"]);
            let e = ipv6_refusal(&a);
            assert!(
                e.starts_with("[-] FAIL: could not determine default interface"),
                "{targets:?}: {e}"
            );
            assert!(!e.contains("cannot be scanned yet"), "{e}");
        }
        let e = ipv6_refusal(&["rmasscan", "2001:db8::10", "-p80"]);
        assert!(
            e.starts_with("[-] FAIL: could not determine default interface"),
            "{e}"
        );
    }

    /// The trace of an IPv6 SYN: `main-ptrace.c:37-41, 97` formats `[ipv6address_fmt]:port` (C's first-zero-run
    /// compression) in the same 21-wide field.
    const TRACE6: [&str; 13] = [
        "rmasscan",
        "--offline",
        "--packet-trace",
        "2001:db8::/126",
        "-p80,443",
        "--seed",
        "5",
        "--adapter-ip",
        "fd00:0:0:5::1",
        "--adapter-mac",
        "00-11-22-33-44-55",
        "--source-port=40000-40003",
        "--rate=1000000",
    ];

    /// T5: `--offline --packet-trace` traces IPv6 targets (R7 lifted): hermetic with `--adapter-ip <IPv6>`,
    /// `--adapter-mac` and `--source-port`, one SYN per target and port, from the first source port only (main.c:346),
    /// in transmit order; a mixed scan traces both families (IPv6 on the low indices of `range`).
    #[test]
    fn packet_trace_traces_ipv6_targets() {
        let out = run_args(&TRACE6).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 8, "{out}");
        let mut dsts = Vec::new();
        for l in &lines {
            assert!(l.starts_with("SENT ("), "{l}");
            let (_, rest) = l
                .split_once(") TCP  [fd00::5:0:0:0:1]:40000 ")
                .unwrap_or_else(|| panic!("{l}"));
            assert!(rest.starts_with("> [2001:db8::"), "{l}");
            assert!(l.ends_with(" SYN"), "{l}");
            dsts.push(rest.split(' ').nth(1).unwrap().to_string());
        }
        dsts.sort();
        assert_eq!(
            dsts,
            [
                "[2001:db8::1]:443",
                "[2001:db8::1]:80",
                "[2001:db8::2]:443",
                "[2001:db8::2]:80",
                "[2001:db8::3]:443",
                "[2001:db8::3]:80",
                "[2001:db8::]:443",
                "[2001:db8::]:80",
            ]
        );
        // Mixed: `--adapter-ip` for IPv4 and `--adapter-ip[0]` for IPv6 (or a config file), both families traced.
        let mut a = trace_args(&["--adapter-ip[0]=fd00:0:0:5::1"]);
        a.insert(3, "2001:db8::/127");
        let out = run_args(&a).unwrap();
        let v6 = out
            .lines()
            .filter(|l| l.contains("TCP  [fd00::5:0:0:0:1]"))
            .count();
        let v4 = out
            .lines()
            .filter(|l| l.contains("TCP  [10.255.0.1]"))
            .count();
        assert_eq!((v6, v4, out.lines().count()), (4, 8, 12), "{out}");
    }

    /// Task 2 minor: an IPv6-only `--offline` with autodetection takes the IPv6 path (no IPv4 "no unicast target"
    /// error); the library fake knows no IPv6 route.
    #[test]
    fn offline_ipv6_only_detects_through_the_ipv6_path() {
        let e = ipv6_refusal(&[
            "rmasscan",
            "--offline",
            "2001:db8::10",
            "-p80",
            "--seed",
            "1",
        ]);
        assert!(
            e.starts_with("[-] FAIL: could not determine default interface"),
            "{e}"
        );
        let e = ipv6_refusal(&["rmasscan", "--offline", "ff02::1", "-p80", "--seed", "1"]);
        assert!(
            e.starts_with("[-] FAIL: no unicast IPv6 target addresses to route to"),
            "{e}"
        );
    }

    /// R3: a non-TCP port with an IPv6 target gets its own message on live and `--packet-trace`.
    #[test]
    fn non_tcp_ports_with_ipv6_target_are_refused_with_a_specific_message() {
        for ports in ["-pU:53", "-pS:80", "-pI:0", "-p80,U:53", "-pO:47"] {
            let e = ipv6_refusal(&["rmasscan", "2001:db8::10", ports, "--seed", "1"]);
            assert!(
                e.contains("IPv6 targets support only TCP ports"),
                "{ports}: {e}"
            );
            let mut a = trace_args(&[ports]);
            a[3] = "2001:db8::10";
            let e = ipv6_refusal(&a);
            assert!(
                e.contains("IPv6 targets support only TCP ports"),
                "{ports}: {e}"
            );
        }
        let e = ipv6_refusal(&["rmasscan", "2001:db8::10", "--arp", "--seed", "1"]);
        assert!(e.contains("IPv6 targets support only TCP ports"), "{e}");
        let e = ipv6_refusal(&["rmasscan", "2001:db8::10", "--ping", "--seed", "1"]);
        assert!(e.contains("IPv6 targets support only TCP ports"), "{e}");
        // -sL and --echo keep working with such ports (they transmit nothing)
        assert!(run_args(&["rmasscan", "-sL", "2001:db8::10", "-pU:53", "--seed", "1"]).is_ok());
        assert!(
            run_args(&[
                "rmasscan",
                "--echo",
                "2001:db8::10",
                "-pU:53",
                "--seed",
                "1"
            ])
            .is_ok()
        );
    }

    /// `--offline` without `--packet-trace` builds nothing, so IPv6 targets are accepted there.
    #[test]
    fn offline_without_packet_trace_accepts_ipv6_targets() {
        // Hermetic for IPv6 needs the IPv6 source too (`--adapter-ip[0]`), as the IPv4 half needs `--adapter-ip`.
        let mut a = trace_without(&[]);
        a.retain(|x| *x != "--packet-trace");
        let t = a.iter().position(|x| *x == "10.0.0.0/30").unwrap();
        a[t] = "2001:db8::10";
        a.push("--adapter-ip[0]=fd00::1");
        assert_eq!(run_args(&a).unwrap(), "");
    }

    /// Task 6: `--readscan` reads types 10/11 and takes IPv6 target filters (`in-binary.c:228-276`). `--range` with
    /// IPv6 ranges and an IPv4 range keeps the IPv6 records of the IPv6 ranges (C: the address test runs when
    /// `count_ipv4s` is non-zero, `in-binary.c:254`).
    #[test]
    fn readscan_accepts_an_ipv6_filter() {
        let scratch = Scratch::new();
        let v6 = |ip: &str, port| output::Record {
            ip: ip.parse::<std::net::IpAddr>().unwrap(),
            port,
            ..open_rec()
        };
        let input = scan_file(
            &scratch,
            "v6.scan",
            &[
                v6("2a03:9060:0:400::2", 443),
                v6("2001:db8::5", 22),
                open_rec(),
            ],
        );
        let input = input.to_str().unwrap();
        let (r, out, log) = readscan_run(
            &FakeBackend::default(),
            &[
                "--range",
                "2a03:9060:0:400::/64,1.2.3.0/24",
                "--readscan",
                input,
                "-oL",
                "-",
            ],
        );
        r.unwrap();
        assert_eq!(log, format!("[+] --readscan {input}\n"));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "#masscan\nopen tcp 443 2a03:9060::400:0:0:0:2 1700000000\nopen tcp 80 1.2.3.4 1700000000\n# end\n"
        );
        // C checks the 63-bit limit before `--readscan` too (`main.c:1698-1704`): /64 times one port is 65 bits.
        let (r, _, log) = readscan_run(
            &FakeBackend::default(),
            &[
                "--range",
                "2001:db8::/64",
                "-p22",
                "--readscan",
                input,
                "-oL",
                "-",
            ],
        );
        let e = r.unwrap_err();
        assert!(
            e.contains("scan range too large, max is 63-bits, requested is 65 bits"),
            "{e}"
        );
        assert_eq!(log, "");
        // A live scan of the same targets now goes to IPv6 detection (R7 lifted); the 63-bit limit refuses it first.
        let e = ipv6_refusal(&["rmasscan", "2001:db8::/32", "-p80", "--seed", "1"]);
        assert!(e.contains("scan range too large"), "{e}");
    }

    /// `-iL` still takes IPv4 only (its own grammar, main-conf.c:2825-2836): an IPv6 entry is
    /// an error, not a skipped line.
    #[test]
    fn includefile_with_ipv6_is_still_an_error() {
        let scratch = Scratch::new();
        let f = scratch.write("inc.txt", b"2001:db8::1\n");
        let e = run_args(&[
            "rmasscan",
            "-sL",
            "-iL",
            f.to_str().unwrap(),
            "-p80",
            "--seed",
            "1",
        ])
        .unwrap_err();
        // main-conf.c:2825-2836: `-iL` keeps its IPv4-only grammar; the error names the file, line and column.
        assert!(
            e.ends_with("inc.txt:1:4: invalid IP address on line #1"),
            "{e}"
        );
    }
}
