//! Разбор командной строки (AGPL-3.0). Порт подмножества опций masscan
//! `src/main-conf.c` (`masscan_command_line` :2840, `masscan_set_parameter`
//! :2400) из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Любая опция вне подмножества v1 (например `--banners`) - ошибка clap,
//! а не молчаливый пропуск (Review Focus №5).

use std::net::Ipv4Addr;

use clap::Parser;
use rmasscan_core::config::{ScanConfig, parse_mac, parse_rate, parse_shard, parse_source_port};
use rmasscan_core::targets::{add_target_string, parse_ports};

/// Опции v1. Значения, у которых в C своя грамматика (`--rate`, `--shard`,
/// MAC, `--source-port`), хранятся строками и разбираются функциями ядра.
#[derive(Parser, Debug, Clone, Default)]
#[command(
    name = "rmasscan",
    version,
    about = "Rust port of masscan: -sL, --echo and --offline --packet-trace (stage 1)",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Цели: IP, CIDR, `a.b.c.d-e.f.g.h`, списки через запятую.
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,
    /// `--range` (main-conf.c:2729): то же, что позиционная цель.
    #[arg(long = "range", value_name = "RANGE")]
    pub range: Vec<String>,
    /// `-p80,443`, `-p0-65535`, `--ports 22,80`.
    #[arg(short = 'p', long = "ports", value_name = "PORTS")]
    pub ports: Vec<String>,
    #[arg(long, value_name = "RANGE")]
    pub exclude: Vec<String>,
    #[arg(long, value_name = "FILE")]
    pub excludefile: Vec<String>,
    #[arg(long, value_name = "N")]
    pub seed: Option<u64>,
    #[arg(long, value_name = "PPS")]
    pub rate: Option<String>,
    #[arg(long, value_name = "SECONDS")]
    pub wait: Option<u32>,
    #[arg(long, value_name = "N")]
    pub retries: Option<u32>,
    #[arg(long, value_name = "ONE/OF")]
    pub shard: Option<String>,
    #[arg(long = "blackrock-rounds", value_name = "N")]
    pub blackrock_rounds: Option<u32>,
    #[arg(long = "resume-index", value_name = "N")]
    pub resume_index: Option<u64>,
    #[arg(long = "resume-count", value_name = "N")]
    pub resume_count: Option<u64>,
    #[arg(long = "adapter-ip", value_name = "IP")]
    pub adapter_ip: Option<String>,
    #[arg(long = "adapter-mac", value_name = "MAC")]
    pub adapter_mac: Option<String>,
    #[arg(long = "router-mac", value_name = "MAC")]
    pub router_mac: Option<String>,
    /// Одиночный порт или диапазон степени двойки (main-conf.c:2523).
    #[arg(long = "source-port", alias = "adapter-port", value_name = "PORT")]
    pub source_port: Option<String>,
    #[arg(
        short = 'e',
        long = "interface",
        alias = "adapter",
        value_name = "IFACE"
    )]
    pub interface: Option<String>,
    #[arg(long)]
    pub offline: bool,
    #[arg(long = "packet-trace", requires = "offline")]
    pub packet_trace: bool,
    /// `-sL` (см. [`preprocess_args`]).
    #[arg(
        long = "list",
        conflicts_with_all = ["echo", "echo_all", "packet_trace"]
    )]
    pub list: bool,
    #[arg(long, conflicts_with_all = ["echo_all", "packet_trace"])]
    pub echo: bool,
    #[arg(long = "echo-all", conflicts_with = "packet_trace")]
    pub echo_all: bool,
}

/// Причуды masscan, которые clap не выражает.
///
/// 1. `-sL` (nmap-стиль) - это один флаг, а
///    clap прочёл бы его как `-s L`. Заменяется на `--list`.
///
/// Остальное clap обрабатывает как C: `-p80`, `-p0-65535` (короткая опция с
/// приклеенным значением), `-e lo`, `--opt=value`.
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
    /// `try_parse_from` с предобработкой [`preprocess_args`].
    pub fn try_parse_masscan<I, S>(args: I) -> Result<Cli, clap::Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Cli::try_parse_from(preprocess_args(args))
    }

    /// Строит `ScanConfig`. В отличие от C (main-conf.c:2736-2741, ошибка
    /// `--range` не фатальна) любая ошибка цели, порта или значения фатальна.
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
        // seed == 0 в C значит "взять энтропию" (main.c:1658); порт этого не делает.
        cfg.seed = self
            .seed
            .ok_or("--seed is required (the entropy-based default is not ported)")?;
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

/// `--excludefile` (main-conf.c:2791, `massip_parse_file`): по одной записи
/// на строку, `#` начинает комментарий. Порт построчный, а не побайтовый
/// автомат C; ошибка в строке фатальна (в C тоже `exit(1)`).
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
