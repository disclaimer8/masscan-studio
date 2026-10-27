//! Разбор командной строки (AGPL-3.0). Порт подмножества опций masscan
//! `src/main-conf.c` (`masscan_command_line` :3211, `masscan_set_parameter`
//! :2434) из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Любая опция вне подмножества v1 (например `--banners`) - ошибка clap,
//! а не молчаливый пропуск (Review Focus №5).

use std::net::Ipv4Addr;

use clap::Parser;
use rmasscan_core::config::{ScanConfig, parse_mac, parse_rate, parse_shard, parse_source_port};
use rmasscan_core::targets::{add_target_string, parse_ports};

// Опции v1. Значения, у которых в C своя грамматика (`--rate`, `--shard`,
// MAC, `--source-port`), хранятся строками и разбираются функциями ядра.
#[derive(Parser, Debug, Clone, Default)]
#[command(
    name = "rmasscan",
    version,
    about = "Rust port of masscan: -sL, --echo, --offline --packet-trace and --iflist",
    disable_help_subcommand = true,
    after_help = "Examples:\n  rmasscan -sL 10.0.0.0/24 -p80,443 --seed 1\n  rmasscan --echo 10.0.0.0/24 -p80 --seed 1\n  rmasscan --offline --packet-trace 10.0.0.0/30 -p80 --seed 1 \\\n    --adapter-ip 10.255.0.1 --adapter-mac 00-11-22-33-44-55 \\\n    --router-mac 66-55-44-33-22-11 --source-port 40000-40003\n\nOperations: -sL, --echo, --echo-all, --offline --packet-trace, --iflist (mutually exclusive).\n--seed is required (and must be non-zero) for -sL, --echo and --offline. Any other masscan option is an error."
)]
pub struct Cli {
    // Цели: IP, CIDR, `a.b.c.d-e.f.g.h`, списки через запятую.
    #[arg(
        value_name = "TARGET",
        help = "Targets: IPv4 address, CIDR, a.b.c.d-e.f.g.h, or comma-separated list"
    )]
    pub targets: Vec<String>,
    // `--range` (main-conf.c:2729): то же, что позиционная цель.
    #[arg(
        long = "range",
        value_name = "RANGE",
        help = "Target range (same as a positional target)"
    )]
    pub range: Vec<String>,
    // `-p80,443`, `-p0-65535`, `--ports 22,80`.
    #[arg(
        short = 'p',
        long = "ports",
        value_name = "PORTS",
        help = "Ports to scan, e.g. -p80,443 or -p0-65535 (TCP only)"
    )]
    pub ports: Vec<String>,
    #[arg(
        long,
        value_name = "RANGE",
        help = "Address range to exclude (repeatable)"
    )]
    pub exclude: Vec<String>,
    #[arg(
        long,
        value_name = "FILE",
        help = "File with ranges to exclude, one per line, # starts a comment"
    )]
    pub excludefile: Vec<String>,
    #[arg(
        long,
        value_name = "N",
        help = "Randomization seed, non-zero (required for -sL, --echo and --offline)"
    )]
    pub seed: Option<u64>,
    #[arg(long, value_name = "PPS", help = "Packets per second (default 100)")]
    pub rate: Option<String>,
    #[arg(
        long,
        value_name = "SECONDS",
        help = "Seconds to wait after the scan (default 10)"
    )]
    pub wait: Option<u32>,
    #[arg(
        long,
        value_name = "N",
        help = "Number of retries (default 0, below 1000)"
    )]
    pub retries: Option<u32>,
    #[arg(
        long,
        value_name = "ONE/OF",
        help = "Scan only shard ONE of OF, e.g. 2/3"
    )]
    pub shard: Option<String>,
    #[arg(
        long = "blackrock-rounds",
        value_name = "N",
        help = "Blackrock shuffle rounds (default 14)"
    )]
    pub blackrock_rounds: Option<u32>,
    #[arg(
        long = "resume-index",
        value_name = "N",
        help = "Start at this index of the shuffled order"
    )]
    pub resume_index: Option<u64>,
    #[arg(
        long = "resume-count",
        value_name = "N",
        help = "Stop after this many indexes"
    )]
    pub resume_count: Option<u64>,
    // main-conf.c:2486: `source-ip` - синоним `adapter-ip`.
    #[arg(
        long = "adapter-ip",
        alias = "source-ip",
        value_name = "IP",
        help = "Source IPv4 address (single address; alias: --source-ip)"
    )]
    pub adapter_ip: Option<String>,
    // main-conf.c:2556: `source-mac` - синоним `adapter-mac`.
    #[arg(
        long = "adapter-mac",
        alias = "source-mac",
        value_name = "MAC",
        help = "Source MAC address (alias: --source-mac)"
    )]
    pub adapter_mac: Option<String>,
    // main-conf.c:2626-2641: ровно один IPv4.
    #[arg(
        long = "router-ip",
        value_name = "IP",
        help = "Router (next hop) IPv4 address (single address)"
    )]
    pub router_ip: Option<String>,
    #[arg(long = "router-mac", value_name = "MAC", help = "Router MAC address")]
    pub router_mac: Option<String>,
    // Одиночный порт или диапазон степени двойки (main-conf.c:2523).
    #[arg(
        long = "source-port",
        alias = "adapter-port",
        value_name = "PORT",
        help = "Source port, or a range whose size is a power of two"
    )]
    pub source_port: Option<String>,
    #[arg(
        short = 'e',
        long = "interface",
        alias = "adapter",
        value_name = "IFACE",
        help = "Network interface name (recorded only; no adapter is opened in stage 1)"
    )]
    pub interface: Option<String>,
    #[arg(
        long,
        help = "Do not transmit (stage 1 supports only --offline --packet-trace)"
    )]
    pub offline: bool,
    #[arg(
        long = "packet-trace",
        requires = "offline",
        help = "With --offline: print one SENT line per SYN. Needs --adapter-ip, --adapter-mac, --router-mac and --source-port"
    )]
    pub packet_trace: bool,
    // `-sL` (см. [`preprocess_args`]).
    #[arg(
        long = "list",
        conflicts_with_all = ["echo", "echo_all", "packet_trace"],
        help = "List the targets in scan order (alias: -sL)"
    )]
    pub list: bool,
    #[arg(
        long = "iflist",
        conflicts_with_all = ["targets", "range", "list", "echo", "echo_all", "packet_trace", "offline"],
        help = "List network interfaces and exit"
    )]
    pub iflist: bool,
    #[arg(long, conflicts_with_all = ["echo_all", "packet_trace"], help = "Print the configuration and exit")]
    pub echo: bool,
    #[arg(
        long = "echo-all",
        conflicts_with = "packet_trace",
        help = "Same as --echo (C prints the same for both)"
    )]
    pub echo_all: bool,
}

// Причуды masscan, которые clap не выражает.
//
// 1. `-sL` (nmap-стиль) - это один флаг, а
//    clap прочёл бы его как `-s L`. Заменяется на `--list`.
//
// Остальное clap обрабатывает как C: `-p80`, `-p0-65535` (короткая опция с
// приклеенным значением), `-e lo`, `--opt=value`.
pub fn preprocess_args<I, S>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    args.into_iter()
        .map(Into::into)
        .map(|a: String| if a == "-sL" { "--list".to_string() } else { a })
        .collect()
}

impl Cli {
    // `try_parse_from` с предобработкой [`preprocess_args`].
    pub fn try_parse_masscan<I, S>(args: I) -> Result<Cli, clap::Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Cli::try_parse_from(preprocess_args(args))
    }

    // Строит `ScanConfig`. В отличие от C (main-conf.c:2736-2741, ошибка
    // `--range` не фатальна) любая ошибка цели, порта или значения фатальна.
    pub fn to_config(&self) -> Result<ScanConfig, String> {
        let mut cfg = ScanConfig::default();
        for t in self.targets.iter().chain(&self.range) {
            add_target_string(cfg.targets.ipv4_mut(), t)
                .map_err(|e| format!("bad target {t:?}: {e}"))?;
        }
        for p in &self.ports {
            parse_ports(cfg.targets.ports_mut(), p).map_err(|e| format!("bad ports {p:?}: {e}"))?;
        }
        for x in &self.exclude {
            add_target_string(cfg.excludes.ipv4_mut(), x)
                .map_err(|e| format!("bad --exclude {x:?}: {e}"))?;
        }
        for f in &self.excludefile {
            read_exclude_file(&mut cfg, f)?;
        }
        // seed == 0 в C значит "взять энтропию" (main.c:1640-1641). Явный 0
        // отклоняется; отсутствие --seed решает `run` по операции (см.
        // [`seed_policy`]), здесь это seed 0.
        cfg.seed = match self.seed {
            Some(0) => {
                return Err(
                    "--seed must be non-zero (omit it for a live scan to use entropy)".into(),
                );
            }
            Some(s) => s,
            None => 0,
        };
        if let Some(r) = &self.rate {
            cfg.max_rate = parse_rate(r).map_err(|e| e.to_string())?;
        }
        if let Some(w) = self.wait {
            cfg.wait_secs = w;
        }
        if let Some(r) = self.retries {
            cfg.retries = r;
        }
        if let Some(s) = &self.shard {
            cfg.shard = parse_shard(s).map_err(|e| e.to_string())?;
        }
        if let Some(r) = self.blackrock_rounds {
            cfg.blackrock_rounds = r;
        }
        if let Some(i) = self.resume_index {
            cfg.resume_index = i;
        }
        cfg.resume_count = self.resume_count;
        if let Some(ip) = &self.adapter_ip {
            let ip: Ipv4Addr = ip
                .parse()
                .map_err(|_| format!("bad --adapter-ip {ip:?}: expected one IPv4 address"))?;
            cfg.adapter_ip = Some(ip.into());
        }
        if let Some(m) = &self.adapter_mac {
            cfg.adapter_mac = Some(parse_mac(m).map_err(|e| e.to_string())?);
        }
        if let Some(ip) = &self.router_ip {
            let ip: Ipv4Addr = ip
                .parse()
                .map_err(|_| format!("bad --router-ip {ip:?}: expected one IPv4 address"))?;
            cfg.router_ip = Some(ip.into());
        }
        if let Some(m) = &self.router_mac {
            cfg.router_mac = Some(parse_mac(m).map_err(|e| e.to_string())?);
        }
        if let Some(p) = &self.source_port {
            cfg.source_port = Some(parse_source_port(p).map_err(|e| e.to_string())?);
        }
        cfg.adapter_name = self.interface.clone();
        cfg.offline = self.offline;
        Ok(cfg)
    }
}

/// Откуда берётся seed (решение 6 плана): по операции, до `validate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedPolicy {
    /// `-sL`, `--echo`/`--echo-all`, `--offline`: нужен явный ненулевой `--seed`.
    Required,
    /// Живой скан (и `--iflist`, где seed не используется): без `--seed` берётся энтропия.
    Entropy,
}

pub fn seed_policy(cli: &Cli) -> SeedPolicy {
    if cli.list || cli.echo || cli.echo_all || cli.offline {
        SeedPolicy::Required
    } else {
        SeedPolicy::Entropy
    }
}

// `--excludefile` (main-conf.c:2791, `massip_parse_file`): по одной записи
// на строку, `#` начинает комментарий. Порт построчный, а не побайтовый
// автомат C; ошибка в строке фатальна (в C тоже `exit(1)`).
fn read_exclude_file(cfg: &mut ScanConfig, path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        add_target_string(cfg.excludes.ipv4_mut(), line)
            .map_err(|e| format!("{path}:{}: invalid IP address: {e}", n + 1))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(a: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_masscan(std::iter::once("rmasscan").chain(a.iter().copied()))
    }

    #[test]
    fn router_ip_accepts_one_address_and_rejects_ranges() {
        let cfg = parse(&["--router-ip", "198.18.0.2"])
            .unwrap()
            .to_config()
            .unwrap();
        assert_eq!(cfg.router_ip, Some(0xc612_0002));
        for bad in ["198.18.0.0/24", "198.18.0.2-198.18.0.3", "x", "", "::1"] {
            let cli = parse(&["--router-ip", bad]).unwrap();
            let e = cli.to_config().unwrap_err();
            assert!(e.contains("--router-ip"), "{bad}: {e}");
        }
        assert_eq!(parse(&[]).unwrap().to_config().unwrap().router_ip, None);
    }

    #[test]
    fn iflist_conflicts_with_operations_and_targets() {
        assert!(parse(&["--iflist"]).unwrap().iflist);
        for other in [
            &["10.0.0.1"][..],
            &["--range", "10.0.0.1"][..],
            &["-sL"][..],
            &["--list"][..],
            &["--echo"][..],
            &["--echo-all"][..],
            &["--offline"][..],
            &["--offline", "--packet-trace"][..],
        ] {
            let mut a = vec!["--iflist"];
            a.extend_from_slice(other);
            assert!(parse(&a).is_err(), "{a:?}");
        }
        assert!(parse(&["--iflist", "-p80"]).is_ok());
    }

    #[test]
    fn source_ip_and_source_mac_aliases_set_the_adapter_fields() {
        let cfg = parse(&[
            "--source-ip",
            "10.255.0.1",
            "--source-mac",
            "00-11-22-33-44-55",
        ])
        .unwrap()
        .to_config()
        .unwrap();
        assert_eq!(cfg.adapter_ip, Some(0x0aff_0001));
        assert_eq!(cfg.adapter_mac, Some([0, 0x11, 0x22, 0x33, 0x44, 0x55]));
    }

    #[test]
    fn seed_policy_by_operation() {
        use SeedPolicy::{Entropy, Required};
        for (args, want) in [
            (&["-sL", "10.0.0.1"][..], Required),
            (&["--list", "10.0.0.1"][..], Required),
            (&["--echo", "10.0.0.1"][..], Required),
            (&["--echo-all", "10.0.0.1"][..], Required),
            (&["--offline", "10.0.0.1"][..], Required),
            (&["--offline", "--packet-trace", "10.0.0.1"][..], Required),
            (&["10.0.0.1", "-p80"][..], Entropy),
            (&["--iflist"][..], Entropy),
        ] {
            assert_eq!(seed_policy(&parse(args).unwrap()), want, "{args:?}");
        }
    }

    #[test]
    fn to_config_seed_none_is_zero_and_explicit_zero_is_an_error() {
        assert_eq!(parse(&[]).unwrap().to_config().unwrap().seed, 0);
        assert_eq!(
            parse(&["--seed", "7"]).unwrap().to_config().unwrap().seed,
            7
        );
        let e = parse(&["--seed", "0"]).unwrap().to_config().unwrap_err();
        assert!(e.contains("--seed"), "{e}");
    }
}
