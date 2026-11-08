//! Разбор командной строки (AGPL-3.0). Порт подмножества опций masscan
//! `src/main-conf.c` (`masscan_command_line` :3211, `masscan_set_parameter`
//! :2434) из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Любая опция вне подмножества v1 (например `--banners`) - ошибка clap,
//! а не молчаливый пропуск (Review Focus №5).
//!
//! Опции вывода (`SET_output_*`, main-conf.c:1616–1806, `-o<буква>` :3401–3459) разбираются с семантикой C:
//! `-o<буква> FILE` переводится в длинные опции до clap, повтор опции вывода побеждает последним (Р17), `--show`,
//! `--noshow` и `--open` применяются в порядке командной строки. Отклонения от C: неизвестный `--output-format` -
//! ошибка (Р6); redis, certs и ротация отклоняются с причиной (Р1).

use std::collections::HashSet;
use std::fmt;
use std::net::Ipv4Addr;
use std::path::Path;

use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser};
use rmasscan_core::config::{
    NicConfig, ScanConfig, parse_mac, parse_rate, parse_shard, parse_source_port,
};
use rmasscan_core::targets::{add_target_string, parse_ports};

use crate::conf::{FullConf, OutputConfPatch, apply_conf_key};
use crate::output::{Format, OutputOptions};
use crate::status::StatusMode;

/// `--webxml` (main-conf.c:3033–3034).
const NMAP_XSL: &str = "http://nmap.org/svn/docs/nmap.xsl";

/// Допустимые значения `--output-format` в тексте отказа (Р6).
const FORMAT_NAMES: &str =
    "list, json, ndjson, grepable, xml, binary, hostonly, unicornscan, interactive, none";

/// Отказы Р1 с причиной.
const REDIS_REFUSAL: &str =
    "--output-format redis is not supported (rmasscan writes results only to a file or stdout)";
const CERTS_REFUSAL: &str =
    "--output-format certs is not supported (it needs --banners, which rmasscan does not grab)";

// Опции v1. Значения, у которых в C своя грамматика (`--rate`, `--shard`,
// MAC, `--source-port`), хранятся строками и разбираются функциями ядра.
#[derive(Parser, Debug, Clone, Default)]
#[command(
    name = "rmasscan",
    version,
    about = "Rust port of masscan: TCP SYN scan with adapter and gateway auto-detection, masscan output formats, --readscan, --offline, -sL, --echo and --iflist",
    disable_help_subcommand = true,
    after_help = "Examples:\n  sudo rmasscan 198.51.100.0/24 -p80,443\n  rmasscan --offline 198.51.100.0/24 -p80 --seed 1\n  rmasscan --iflist\n  rmasscan -sL 10.0.0.0/24 -p80,443 --seed 1\n  rmasscan --echo 10.0.0.0/24 -p80 --seed 1\n  rmasscan --offline --packet-trace 10.0.0.0/30 -p80 --seed 1 \\\n    --adapter-ip 10.255.0.1 --adapter-mac 00-11-22-33-44-55 --source-port 40000-40003\n  sudo rmasscan 198.51.100.0/24 -p80 -oB scan.bin\n  rmasscan -p80 --readscan scan.bin -oJ scan.json\n\nOutput (scan and --readscan only): -oL list, -oJ json, -oD ndjson, -oG grepable, -oX xml, -oB binary,\n-oH hostonly, -oU unicornscan, each followed by FILE (- is stdout). With a file format stdout is silent\nunless --interactive is given.\n\nWithout an operation flag rmasscan scans: it picks the interface that routes to the targets, its first IPv4\naddress and MAC, resolves the next hop with ARP (unless --router-mac is given) and needs root/Administrator\nonly to open the adapter. Detection, --offline and --iflist only read the OS and never transmit.\nOperations: -sL, --echo, --echo-all, --offline [--packet-trace], --iflist, --readscan (mutually exclusive).\n--seed is required (and must be non-zero) for -sL, --echo and --offline; a live scan without --seed uses\nOS entropy and prints it. [+] lines go to stderr. Any other masscan option is an error."
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
        help = "Randomization seed, non-zero (required for -sL, --echo and --offline; a live scan defaults to OS entropy)"
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
    // main-conf.c:2926-2928: `resume = <file>` читает файл в этой позиции argv.
    #[arg(
        long = "resume",
        value_name = "FILE",
        help = "Resume a scan from a paused.conf file (options to the right of it override the file; output is appended)"
    )]
    pub resume: Vec<String>,
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
        help = "Router (next hop) IPv4 address to resolve with ARP (single address; default: route gateway)"
    )]
    pub router_ip: Option<String>,
    #[arg(
        long = "router-mac",
        value_name = "MAC",
        help = "Router (next hop) MAC address: skips ARP (ignored by --offline, which uses 66-55-44-33-22-11)"
    )]
    pub router_mac: Option<String>,
    // Одиночный порт или диапазон степени двойки (main-conf.c:2523).
    #[arg(
        long = "source-port",
        alias = "adapter-port",
        value_name = "PORT",
        help = "Source port, or a range whose size is a power of two (default: one port 40000 + time % 20000)"
    )]
    pub source_port: Option<String>,
    #[arg(
        short = 'e',
        long = "interface",
        alias = "adapter",
        value_name = "IFACE",
        help = "Network interface (alias: --adapter): its name; on Windows \\Device\\NPF_{GUID} or the adapter name (default: the interface of the route to the targets)"
    )]
    pub interface: Option<String>,
    #[arg(
        long,
        help = "Do not transmit: detect read-only and print the [+] lines (fake router MAC 66-55-44-33-22-11)"
    )]
    pub offline: bool,
    #[arg(
        long = "packet-trace",
        requires = "offline",
        help = "With --offline: print one SENT line per SYN (values not given are detected read-only)"
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
        help = "List network interfaces and default routes (read-only, no privileges) and exit"
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
    // `--readscan f1 f2 …` (main-conf.c:3266–3278): все следующие аргументы без `-` это файлы; цели и порты
    // фильтра идут раньше.
    #[arg(
        long,
        value_name = "FILE",
        num_args = 1..,
        conflicts_with_all = ["list", "echo", "echo_all", "offline", "iflist", "packet_trace"],
        help = "Read masscan -oB files (TCP status records) and write them with the output options; targets and ports given before it filter the records"
    )]
    pub readscan: Vec<String>,
    // Каждое вхождение проверяется (Р6), побеждает последнее (Р17).
    #[arg(
        long = "output-format",
        value_name = "FORMAT",
        value_parser = output_format_value,
        overrides_with = "output_format",
        help = "list, json, ndjson, grepable, xml, binary, hostonly, unicornscan, interactive or none"
    )]
    pub output_format: Option<String>,
    // main-conf.c:1643–1657: без формата значит XML.
    #[arg(
        long = "output-filename",
        alias = "output-file",
        value_name = "FILE",
        overrides_with = "output_filename",
        help = "Output file, - is stdout (without --output-format: XML; alias: --output-file)"
    )]
    pub output_filename: Option<String>,
    // `F_BOOL`-опции C (main-conf.c:2409-2411, `parseBoolean` :657-698): без значения - истина, `=<val>` - по
    // `parseBoolean`; побеждает последнее вхождение (`SET_output_append` :1616, `SET_output_flush` :1631).
    #[arg(
        long = "append-output",
        alias = "output-append",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        value_name = "BOOL",
        help = "Append to the output file instead of truncating it (alias: --output-append; =false undoes it)"
    )]
    pub append_output: Vec<String>,
    #[arg(
        long = "output-flush",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        value_name = "BOOL",
        help = "Flush the output file after every record (=false undoes it)"
    )]
    pub output_flush: Vec<String>,
    // `SET_output_show_open` (main-conf.c:1794-1806) игнорирует значение: любое вхождение, даже `=false`, сбрасывает
    // show в `open`.
    #[arg(
        long = "output-show-open",
        aliases = ["open", "open-only"],
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        value_name = "BOOL",
        help = "Report only open ports (the default; resets --show; aliases: --open, --open-only)"
    )]
    pub open: Vec<String>,
    #[arg(
        long,
        aliases = ["output-show", "output-status"],
        value_name = "LIST",
        help = "Also report: comma list of open, closed, host, all"
    )]
    pub show: Vec<String>,
    #[arg(
        long,
        alias = "output-noshow",
        value_name = "LIST",
        help = "Do not report: comma list of open, closed, host, all"
    )]
    pub noshow: Vec<String>,
    #[arg(
        long,
        overrides_with_all = ["interactive", "nointeractive"],
        help = "Print the Discovered lines on stdout also with a file format"
    )]
    pub interactive: bool,
    #[arg(
        long,
        overrides_with_all = ["interactive", "nointeractive"],
        help = "Undo --interactive"
    )]
    pub nointeractive: bool,
    // `--stylesheet`, `--webxml` и `--no-stylesheet` применяются в порядке командной строки (main-conf.c:2092-2105,
    // :2983-2984, :3033-3034): последний побеждает; `fold_stylesheet` заполняет [`Cli::try_parse_masscan`].
    #[arg(
        long,
        value_name = "URL",
        action = clap::ArgAction::Append,
        help = "XML stylesheet reference (without --output-format: XML)"
    )]
    pub stylesheet: Vec<String>,
    #[arg(
        long,
        action = clap::ArgAction::Count,
        help = "Same as --stylesheet http://nmap.org/svn/docs/nmap.xsl"
    )]
    pub webxml: u8,
    #[arg(
        long = "no-stylesheet",
        action = clap::ArgAction::Count,
        help = "Drop the stylesheet set earlier (does not change the output format)"
    )]
    pub no_stylesheet: u8,
    #[arg(
        long,
        overrides_with_all = ["status", "nostatus"],
        help = "Show the status line on stderr (the default)"
    )]
    pub status: bool,
    #[arg(
        long,
        overrides_with_all = ["status", "nostatus"],
        help = "Do not show the status line"
    )]
    pub nostatus: bool,
    // `F_BOOL` (main-conf.c:3091): `=<val>` по `parseBoolean`, `is_status_ndjson` не зависит от `--status`.
    #[arg(
        long = "ndjson-status",
        alias = "status-ndjson",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        value_name = "BOOL",
        help = "Print the status as NDJSON (alias: --status-ndjson; =false undoes it)"
    )]
    pub ndjson_status: Vec<String>,
    // Ротация (Р1): принимается, чтобы отказать с причиной, а не ошибкой «неизвестная опция».
    #[arg(long, aliases = ["output-rotate", "rotate-output", "rotate-time"], hide = true)]
    pub rotate: Option<String>,
    #[arg(long = "rotate-dir", aliases = ["output-rotate-dir", "rotate-directory"], hide = true)]
    pub rotate_dir: Option<String>,
    #[arg(long = "rotate-offset", alias = "output-rotate-offset", hide = true)]
    pub rotate_offset: Option<String>,
    #[arg(long = "rotate-size", aliases = ["output-rotate-filesize", "rotate-filesize"], hide = true)]
    pub rotate_size: Option<String>,
    /// `--show`, `--noshow` и `--open` в порядке командной строки; заполняет [`Cli::try_parse_masscan`].
    #[arg(skip)]
    show_steps: Vec<ShowStep>,
    /// Итог `--stylesheet`/`--webxml`/`--no-stylesheet`; `None` - таблицы стилей нет.
    #[arg(skip)]
    style: Option<String>,
    /// Был ли хоть один `--stylesheet` или `--webxml` (`SET_output_stylesheet` задаёт XML, если формата нет).
    #[arg(skip)]
    style_sets_xml: bool,
    /// Ключи конфигурации, чьё последнее появление в argv стоит правее `--resume` (они переопределяют файл).
    #[arg(skip)]
    after_resume: HashSet<&'static str>,
    /// Группы опций вывода (`format`, `filename`, `append`, `flush`, `style`, `show`), чьё последнее появление в
    /// argv стоит правее `--resume`.
    #[arg(skip)]
    after_output: HashSet<&'static str>,
    /// Разобранная конфигурация с `--resume`: файл читается один раз на `Cli`.
    #[arg(skip)]
    resolved: std::sync::OnceLock<Result<FullConf, String>>,
}

/// Идентификаторы clap опций, которые кладутся в `ScanConfig` позиционно (ключи правее `--resume` переопределяют
/// файл, ключи левее переопределяются им, `masscan_set_parameter` вызывается в порядке argv).
const POSITIONAL_KEYS: [&str; 14] = [
    "seed",
    "rate",
    "wait",
    "retries",
    "shard",
    "blackrock_rounds",
    "resume_index",
    "resume_count",
    "adapter_ip",
    "adapter_mac",
    "router_ip",
    "router_mac",
    "source_port",
    "interface",
];

/// Один шаг `SET_output_show` (`on`), `SET_output_noshow` (`!on`) или `SET_output_show_open`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ShowStep {
    List { on: bool, list: String },
    OpenOnly,
}

/// `--json-status` и `--status-json` (`SET_status_json`, main-conf.c:1519-1531, :2400): C печатает две строки в
/// stderr (имя как набрано, до `=` или `:`); `masscan_set_parameter` отбрасывает `CONF_ERR`, но rmasscan отказывает
/// при разборе (exit 1), потому что скан с опцией, которую C назвал неподдерживаемой, не нужен.
fn refuse_json_status(argv: &[String]) -> Result<(), ParseError> {
    for a in argv.iter().skip(1) {
        let Some(rest) = a.strip_prefix("--") else {
            continue;
        };
        let name = rest.split(['=', ':']).next().unwrap_or(rest);
        if name.eq_ignore_ascii_case("json-status") || name.eq_ignore_ascii_case("status-json") {
            return Err(ParseError::Masscan(format!(
                "[-] FAIL: {name} not supported, use --status-ndjson\n    hint: new-line delimited JSON status is what we use"
            )));
        }
    }
    Ok(())
}

/// Ошибка разбора: clap печатает свою (`e.exit()`, код clap), текст masscan печатается в stderr как есть, exit 1.
#[derive(Debug)]
pub enum ParseError {
    Clap(clap::Error),
    Masscan(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Clap(e) => write!(f, "{e}"),
            ParseError::Masscan(t) => f.write_str(t),
        }
    }
}

/// Отказ значения `--output-format` из value parser clap; [`Cli::try_parse_masscan`] отдаёт его текст как
/// [`ParseError::Masscan`].
#[derive(Debug)]
struct FormatRefusal(String);

impl fmt::Display for FormatRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FormatRefusal {}

fn output_format_value(name: &str) -> Result<String, FormatRefusal> {
    parse_format(name)
        .map(|_| name.to_string())
        .map_err(FormatRefusal)
}

/// Ошибка clap, кроме отказа [`FormatRefusal`]: тот становится текстом masscan (exit 1, а не код clap).
fn from_clap(e: clap::Error) -> ParseError {
    match std::error::Error::source(&e).and_then(|s| s.downcast_ref::<FormatRefusal>()) {
        Some(r) => ParseError::Masscan(r.0.clone()),
        None => ParseError::Clap(e),
    }
}

/// `-o<буква>` (main-conf.c:3401–3452): формат по третьему символу аргумента.
fn dash_o_format(arg: &str) -> Result<&'static str, String> {
    match arg.as_bytes().get(2) {
        Some(b'L') => Ok("list"),
        Some(b'J') => Ok("json"),
        Some(b'D') => Ok("ndjson"),
        Some(b'G') => Ok("grepable"),
        Some(b'X') => Ok("xml"),
        Some(b'B') => Ok("binary"),
        Some(b'H') => Ok("hostonly"),
        Some(b'U') => Ok("unicornscan"),
        // `-oR` это redis (Р1).
        Some(b'A' | b'N' | b'S' | b'R') => Err(format!("nmap({arg}): unsupported output format")),
        _ => Err(format!("nmap({arg}): unknown output format")),
    }
}

// Причуды masscan, которые clap не выражает.
//
// 1. `-sL` (nmap-стиль) - это один флаг, а
//    clap прочёл бы его как `-s L`. Заменяется на `--list`.
// 2. `-o<буква> FILE` (main-conf.c:3401–3459): буква слитно с `-o`, файл следующим argv (`-` значит stdout, иное
//    начало с `-` или конец argv это `missing output filename`). Заменяется на `--output-format=<имя>
//    --output-filename=<FILE>`; неподдерживаемая или неизвестная буква сообщается раньше проверки файла, как в C.
//
// Остальное clap обрабатывает как C: `-p80`, `-p0-65535` (короткая опция с
// приклеенным значением), `-e lo`, `--opt=value`. Первый элемент (имя программы) не трогается.
pub fn preprocess_args<I, S>(args: I) -> Result<Vec<String>, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut it = args.into_iter().map(Into::into);
    let mut out: Vec<String> = it.next().into_iter().collect();
    while let Some(a) = it.next() {
        if a == "-sL" {
            out.push("--list".into());
        } else if a.starts_with("-o") {
            let format = dash_o_format(&a)?;
            let file = it
                .next()
                .filter(|f| !(f.starts_with('-') && f.len() > 1))
                .ok_or_else(|| "missing output filename".to_string())?;
            out.push(format!("--output-format={format}"));
            out.push(format!("--output-filename={file}"));
        } else {
            out.push(a);
        }
    }
    Ok(out)
}

/// Порядок `--show`, `--noshow` и `--open` по индексам clap. Из нескольких `--open` значим только последний (он
/// сбрасывает всё до него), а его индекс clap и хранит.
/// `parseBoolean` (main-conf.c:657-698): пустое значение и неизвестная буква - истина, цифра - `strtoul(…, 0, 0) != 0`.
fn parse_boolean(v: &str) -> bool {
    let b = v.as_bytes();
    let Some(&c) = b.first() else { return true };
    if c.is_ascii_digit() {
        // strtoul с основанием 0: `0x…` - шестнадцатеричное, `0…` - восьмеричное, иначе десятичное; ненулевое значение
        // есть тогда и только тогда, когда в разобранной серии цифр есть не `0` (переполнение тоже ненулевое).
        let hex = matches!(b, [b'0', b'x' | b'X', d, ..] if d.is_ascii_hexdigit());
        let digits: Vec<u8> = if hex {
            b[2..]
                .iter()
                .copied()
                .take_while(u8::is_ascii_hexdigit)
                .collect()
        } else if c == b'0' {
            b.iter()
                .copied()
                .take_while(|d| (b'0'..=b'7').contains(d))
                .collect()
        } else {
            b.iter().copied().take_while(u8::is_ascii_digit).collect()
        };
        return digits.iter().any(|&d| d != b'0');
    }
    match c.to_ascii_lowercase() {
        b'd' | b'f' | b'n' => false,
        b'o' => !matches!(b.get(1), Some(b'f' | b'F')),
        _ => true,
    }
}

/// Итог `--stylesheet`/`--webxml`/`--no-stylesheet` по индексам clap: последний побеждает. Возвращает таблицу стилей
/// (пустая строка C - её нет) и был ли `--stylesheet`/`--webxml` (main-conf.c:2092-2105, :2983-2984, :3033-3034).
fn fold_stylesheet(m: &ArgMatches) -> (Option<String>, bool) {
    let mut steps: Vec<(usize, Option<String>)> = Vec::new();
    if let (Some(values), Some(indices)) = (
        m.get_many::<String>("stylesheet"),
        m.indices_of("stylesheet"),
    ) {
        steps.extend(indices.zip(values).map(|(i, v)| (i, Some(v.clone()))));
    }
    // `Count` без вхождений всё равно хранит значение по умолчанию, поэтому сначала счётчик.
    if m.get_count("webxml") > 0
        && let Some(indices) = m.indices_of("webxml")
    {
        steps.extend(indices.map(|i| (i, Some(NMAP_XSL.to_string()))));
    }
    let sets_xml = !steps.is_empty();
    if m.get_count("no_stylesheet") > 0
        && let Some(indices) = m.indices_of("no_stylesheet")
    {
        steps.extend(indices.map(|i| (i, None)));
    }
    steps.sort_by_key(|(i, _)| *i);
    let style = steps.pop().and_then(|(_, s)| s).filter(|s| !s.is_empty());
    (style, sets_xml)
}

fn show_steps(m: &ArgMatches) -> Vec<ShowStep> {
    let mut steps: Vec<(usize, ShowStep)> = Vec::new();
    for (id, on) in [("show", true), ("noshow", false)] {
        if let (Some(lists), Some(indices)) = (m.get_many::<String>(id), m.indices_of(id)) {
            let list = |l: &String| ShowStep::List {
                on,
                list: l.clone(),
            };
            steps.extend(indices.zip(lists.map(list)));
        }
    }
    if let Some(i) = m.indices_of("open").and_then(Iterator::max) {
        steps.push((i, ShowStep::OpenOnly));
    }
    steps.sort_by_key(|(i, _)| *i);
    steps.into_iter().map(|(_, s)| s).collect()
}

/// `--output-format` (`SET_output_format`, main-conf.c:1659–1711), кроме причуды C продолжать с прежним форматом.
fn parse_format(name: &str) -> Result<Format, String> {
    Ok(match name {
        "interactive" => Format::Interactive,
        "list" => Format::List,
        "unicornscan" => Format::Unicornscan,
        "xml" => Format::Xml,
        "binary" => Format::Binary,
        "grepable" | "greppable" => Format::Grepable,
        "json" => Format::Json,
        "ndjson" => Format::Ndjson,
        "none" => Format::None,
        "hostonly" => Format::Hostonly,
        "redis" => return Err(REDIS_REFUSAL.into()),
        "certs" => return Err(CERTS_REFUSAL.into()),
        other => {
            return Err(format!(
                "FAIL: unknown output-format: {other}\n  hint: {FORMAT_NAMES}"
            ));
        }
    })
}

/// Цикл `SET_output_show`/`SET_output_noshow` (main-conf.c:1712–1790): элементы через запятую до первого пустого
/// (`INDEX_OF`), повторные запятые пропускаются; неизвестный элемент - `FAIL` C (там `exit(1)`).
fn apply_show(o: &mut OutputOptions, list: &str, on: bool) -> Result<(), String> {
    let mut rest = list;
    loop {
        let len = rest.find(',').unwrap_or(rest.len());
        if len == 0 {
            return Ok(());
        }
        match &rest[..len] {
            "open" => o.show_open = on,
            "closed" | "close" => o.show_closed = on,
            "host" => o.show_host = on,
            "all" => (o.show_open, o.show_closed, o.show_host) = (on, on, on),
            bad => {
                let which = if on { "show" } else { "noshow" };
                return Err(format!("FAIL: unknown '{which}' spec: {bad}"));
            }
        }
        rest = rest[len..].trim_start_matches(',');
    }
}

impl Cli {
    /// Разбор argv в духе masscan: [`preprocess_args`], clap, порядок `--show`/`--noshow`/`--open` и проверка опций
    /// вывода, которые C отклоняет при разборе (`FAIL: unknown 'show' spec`) или которых здесь нет (Р1, Р6).
    pub fn try_parse_masscan<I, S>(args: I) -> Result<Cli, ParseError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let argv = preprocess_args(args).map_err(ParseError::Masscan)?;
        refuse_json_status(&argv)?;
        let m = Cli::command()
            .try_get_matches_from(argv)
            .map_err(from_clap)?;
        let mut cli = Cli::from_arg_matches(&m).map_err(ParseError::Clap)?;
        cli.show_steps = show_steps(&m);
        (cli.style, cli.style_sets_xml) = fold_stylesheet(&m);
        if cli.resume.len() > 1 {
            return Err(ParseError::Masscan(
                "--resume may be given only once".to_string(),
            ));
        }
        if let Some(at) = m.indices_of("resume").and_then(Iterator::max) {
            cli.after_resume = POSITIONAL_KEYS
                .iter()
                .copied()
                .filter(|id| {
                    m.indices_of(id)
                        .and_then(Iterator::max)
                        .is_some_and(|i| i > at)
                })
                .collect();
            // `Count` без вхождений хранит значение по умолчанию, поэтому сначала счётчик (см. `fold_stylesheet`).
            let counted =
                |id: &str| !matches!(id, "webxml" | "no_stylesheet") || m.get_count(id) > 0;
            let right = |ids: &[&str]| {
                ids.iter().any(|id| {
                    counted(id)
                        && m.indices_of(id)
                            .and_then(Iterator::max)
                            .is_some_and(|i| i > at)
                })
            };
            for (group, ids) in [
                (
                    "format",
                    &[
                        "output_format",
                        "output_filename",
                        "stylesheet",
                        "webxml",
                        "no_stylesheet",
                    ][..],
                ),
                ("filename", &["output_filename"][..]),
                ("append", &["append_output"][..]),
                ("flush", &["output_flush"][..]),
                ("style", &["stylesheet", "webxml", "no_stylesheet"][..]),
                ("show", &["show", "noshow", "open"][..]),
            ] {
                if right(ids) {
                    cli.after_output.insert(group);
                }
            }
        }
        cli.output_options().map_err(ParseError::Masscan)?;
        Ok(cli)
    }

    /// Задана ли хоть одна опция вывода или статуса (Р19: они допустимы только со сканом и `--readscan`).
    pub fn output_flags_given(&self) -> bool {
        self.output_format.is_some()
            || self.output_filename.is_some()
            || !self.append_output.is_empty()
            || !self.output_flush.is_empty()
            || !self.open.is_empty()
            || !self.show.is_empty()
            || !self.noshow.is_empty()
            || self.interactive
            || self.nointeractive
            || !self.stylesheet.is_empty()
            || self.webxml > 0
            || self.no_stylesheet > 0
            || self.status
            || self.nostatus
            || !self.ndjson_status.is_empty()
            || self.rotate.is_some()
            || self.rotate_dir.is_some()
            || self.rotate_offset.is_some()
            || self.rotate_size.is_some()
    }

    /// Режим строки статуса: `is_status_updates` (по умолчанию 1; `--status`/`--nostatus`) и `is_status_ndjson`
    /// (по умолчанию 0; `--ndjson-status[=<val>]`) независимы, как в C (`main.c:1399, 1434-1437, 1499-1503`,
    /// `main-conf.c:2842-2845`, `:1507-1517`): выключено, если нет обновлений, иначе NDJSON, если он включён.
    pub fn status_mode(&self) -> StatusMode {
        if self.nostatus {
            StatusMode::Off
        } else if self.ndjson_status.last().is_some_and(|v| parse_boolean(v)) {
            StatusMode::Ndjson
        } else {
            StatusMode::Text
        }
    }

    /// Опции конвейера вывода с умолчаниями C (`main.c:1596`). Формат не задан, а файл или таблица стилей заданы -
    /// значит XML (`SET_output_filename`, `SET_output_stylesheet`; от порядка это не зависит, потому что явный
    /// формат всегда ненулевой). Реальный формат без файла здесь допустим: его отклоняет `run`.
    pub fn output_options(&self) -> Result<OutputOptions, String> {
        let rotation = [
            (self.rotate.is_some(), "--rotate"),
            (self.rotate_dir.is_some(), "--rotate-dir"),
            (self.rotate_offset.is_some(), "--rotate-offset"),
            (self.rotate_size.is_some(), "--rotate-size"),
        ];
        if let Some((_, name)) = rotation.iter().find(|(given, _)| *given) {
            return Err(format!(
                "{name} is not supported (output files are not rotated)"
            ));
        }
        let stylesheet = self.style.clone();
        let format = match &self.output_format {
            Some(f) => parse_format(f)?,
            None if self.output_filename.is_some() || self.style_sets_xml => Format::Xml,
            None => Format::Default,
        };
        let mut o = OutputOptions {
            format,
            filename: self.output_filename.clone(),
            append: self.append_output.last().is_some_and(|v| parse_boolean(v)),
            flush: self.output_flush.last().is_some_and(|v| parse_boolean(v)),
            interactive: self.interactive,
            stylesheet,
            ..OutputOptions::default()
        };
        for step in &self.show_steps {
            match step {
                ShowStep::List { on, list } => apply_show(&mut o, list, *on)?,
                ShowStep::OpenOnly => {
                    (o.show_open, o.show_closed, o.show_host) = (true, false, false);
                }
            }
        }
        Ok(o)
    }

    // Строит `ScanConfig`. В отличие от C (main-conf.c:2736-2741, ошибка
    // `--range` не фатальна) любая ошибка цели, порта или значения фатальна.
    // С `--resume <file>` читает файл в его позиции argv.
    pub fn to_config(&self) -> Result<ScanConfig, String> {
        self.resolve().map(|full| full.scan)
    }

    /// Конфигурация с учётом `--resume <file>` (`resume = <file>`, main-conf.c:2926-2928): ключи левее файла
    /// применяются первыми, затем файл (с его выводом, `pcap-filename` и `ndjson-status`), затем ключи правее
    /// (они переопределяют файл). Без `--resume` это обычный `to_config` с пустым [`FullConf::output`].
    pub fn resolve(&self) -> Result<FullConf, String> {
        self.resolved
            .get_or_init(|| self.resolve_uncached())
            .clone()
    }

    fn resolve_uncached(&self) -> Result<FullConf, String> {
        let mut cfg = ScanConfig::default();
        self.apply_scan_fields(&mut cfg, false)?;
        let mut full = FullConf {
            scan: cfg,
            ..FullConf::default()
        };
        if let Some(file) = self.resume.first() {
            let mut loader = |p: &Path| std::fs::read_to_string(p).map_err(|e| e.to_string());
            apply_conf_key("resume", file, &mut full, &mut loader, 0)?;
            self.apply_scan_fields(&mut full.scan, true)?;
        }
        Ok(full)
    }

    /// Применяет поля командной строки к `cfg`. `after` = `false`: цели, исключения и ключи, стоящие левее
    /// `--resume` (или все, если его нет); `true`: ключи правее `--resume`. Ключи адаптера идут и в
    /// одиночные поля, и в `nics[0]`, если файл уже создал массив адаптеров (`apply_core_kv` держит их равными).
    fn apply_scan_fields(&self, cfg: &mut ScanConfig, after: bool) -> Result<(), String> {
        let take = |id: &'static str| self.after_resume.contains(id) == after;
        if !after {
            for t in self.targets.iter().chain(&self.range) {
                add_target_string(cfg.targets.ipv4_mut(), t)
                    .map_err(|e| format!("bad target {t:?}: {e}"))?;
            }
            for p in &self.ports {
                parse_ports(cfg.targets.ports_mut(), p)
                    .map_err(|e| format!("bad ports {p:?}: {e}"))?;
            }
            for x in &self.exclude {
                add_target_string(cfg.excludes.ipv4_mut(), x)
                    .map_err(|e| format!("bad --exclude {x:?}: {e}"))?;
            }
            for f in &self.excludefile {
                read_exclude_file(cfg, f)?;
            }
            cfg.offline |= self.offline;
        }
        // seed == 0 в C значит "взять энтропию" (main.c:1640-1641). Явный 0
        // отклоняется; отсутствие --seed решает `run` по операции (см.
        // [`seed_policy`]), здесь это seed 0.
        if take("seed") {
            match self.seed {
                Some(0) => {
                    return Err(
                        "--seed must be non-zero (omit it for a live scan to use entropy)".into(),
                    );
                }
                Some(s) => cfg.seed = s,
                None => {}
            }
        }
        if take("rate")
            && let Some(r) = &self.rate
        {
            cfg.max_rate = parse_rate(r).map_err(|e| e.to_string())?;
        }
        if take("wait")
            && let Some(w) = self.wait
        {
            cfg.wait_secs = w;
        }
        if take("retries")
            && let Some(r) = self.retries
        {
            cfg.retries = r;
        }
        if take("shard")
            && let Some(s) = &self.shard
        {
            cfg.shard = parse_shard(s).map_err(|e| e.to_string())?;
        }
        if take("blackrock_rounds")
            && let Some(r) = self.blackrock_rounds
        {
            cfg.blackrock_rounds = r;
        }
        if take("resume_index")
            && let Some(i) = self.resume_index
        {
            cfg.resume_index = i;
        }
        if take("resume_count")
            && let Some(c) = self.resume_count
        {
            cfg.resume_count = Some(c);
        }
        if take("adapter_ip")
            && let Some(ip) = &self.adapter_ip
        {
            let ip: Ipv4Addr = ip
                .parse()
                .map_err(|_| format!("bad --adapter-ip {ip:?}: expected one IPv4 address"))?;
            let ip = u32::from(ip);
            cfg.adapter_ip = Some(ip);
            set_nic0(cfg, |n| n.adapter_ip = Some((ip, ip)));
        }
        if take("adapter_mac")
            && let Some(m) = &self.adapter_mac
        {
            let mac = parse_mac(m).map_err(|e| e.to_string())?;
            cfg.adapter_mac = Some(mac);
            set_nic0(cfg, |n| n.adapter_mac = Some(mac));
        }
        if take("router_ip")
            && let Some(ip) = &self.router_ip
        {
            let ip: Ipv4Addr = ip
                .parse()
                .map_err(|_| format!("bad --router-ip {ip:?}: expected one IPv4 address"))?;
            let ip = u32::from(ip);
            cfg.router_ip = Some(ip);
            set_nic0(cfg, |n| n.router_ip = Some(ip));
        }
        if take("router_mac")
            && let Some(m) = &self.router_mac
        {
            let mac = parse_mac(m).map_err(|e| e.to_string())?;
            cfg.router_mac = Some(mac);
            set_nic0(cfg, |n| {
                (n.router_mac_ipv4, n.router_mac_ipv6) = (Some(mac), Some(mac));
            });
        }
        if take("source_port")
            && let Some(p) = &self.source_port
        {
            let ports = parse_source_port(p).map_err(|e| e.to_string())?;
            cfg.source_port = Some(ports);
            // Явный диапазон степени двойки снимает причуду C в 17 портов, пришедшую из файла.
            cfg.legacy_c_17_port_mask = false;
            set_nic0(cfg, |n| n.source_port = Some(ports));
        }
        if take("interface")
            && let Some(name) = &self.interface
        {
            cfg.adapter_name = Some(name.clone());
            set_nic0(cfg, |n| n.adapter_name = Some(name.clone()));
        }
        Ok(())
    }

    /// Опции вывода с учётом `--resume`: поля файла (`output-filename`, `output-format`, ...) служат базой, а
    /// опции вывода правее `--resume` их переопределяют, левее переопределяются файлом; `output-append` после `--resume`
    /// принудительно истина (main-conf.c:2926-2928). Без `--resume` совпадает с [`Cli::output_options`].
    pub fn resolved_output_options(&self) -> Result<OutputOptions, String> {
        let mut o = self.output_options()?;
        if self.resume.is_empty() {
            return Ok(o);
        }
        let file = self.resolve()?.output;
        merge_file_output(&mut o, &file, self);
        Ok(o)
    }
}

/// `nics[0]`, если массив адаптеров уже создан (файлом): CLI-ключ адаптера обязан попасть и в него, иначе
/// одиночное поле и `nics[0]` разойдутся и `echo`/`paused.conf` напишут значение файла.
fn set_nic0(cfg: &mut ScanConfig, f: impl FnOnce(&mut NicConfig)) {
    if let Some(n) = cfg.nics.first_mut() {
        f(n);
    }
}

/// Опции вывода по позиции относительно `--resume` (main-conf.c:3401-3457, 2926-2928: и `-o…`, и ключи файла
/// применяются в порядке argv): опция правее файла побеждает файл, опция левее переопределяется файлом, если
/// файл задаёт этот ключ; `output-append` после файла всегда истина, пока правее нет явного `--append-output`.
fn merge_file_output(o: &mut OutputOptions, file: &OutputConfPatch, cli: &Cli) {
    let right = |g: &str| cli.after_output.contains(g);
    if !right("format")
        && let Some(f) = file.format
    {
        o.format = f;
    }
    if !right("filename") && file.filename.is_some() {
        o.filename.clone_from(&file.filename);
    }
    o.append = if right("append") {
        cli.append_output.last().is_some_and(|v| parse_boolean(v))
    } else {
        true
    };
    if !right("flush")
        && let Some(v) = file.flush
    {
        o.flush = v;
    }
    if !right("style") && file.stylesheet.is_some() {
        o.stylesheet.clone_from(&file.stylesheet);
    }
    if !right("show") {
        if let Some(v) = file.show_open {
            o.show_open = v;
        }
        if let Some(v) = file.show_closed {
            o.show_closed = v;
        }
        if let Some(v) = file.show_host {
            o.show_host = v;
        }
    }
    // SET_output_filename (main-conf.c:1643): имя файла без формата значит XML.
    if o.format == Format::Default && o.filename.is_some() {
        o.format = Format::Xml;
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
    use crate::output::{Format, OutputOptions};

    fn parse(a: &[&str]) -> Result<Cli, ParseError> {
        Cli::try_parse_masscan(std::iter::once("rmasscan").chain(a.iter().copied()))
    }

    fn opts(a: &[&str]) -> OutputOptions {
        parse(a).unwrap().output_options().unwrap()
    }

    /// Отказ разбора с текстом masscan (печатается как есть, exit 1).
    fn masscan_err(a: &[&str]) -> String {
        match parse(a) {
            Err(ParseError::Masscan(t)) => t,
            other => panic!("{a:?}: {other:?}"),
        }
    }

    #[test]
    fn dash_o_letters_map_to_formats() {
        for (letter, format) in [
            ('L', Format::List),
            ('J', Format::Json),
            ('D', Format::Ndjson),
            ('G', Format::Grepable),
            ('X', Format::Xml),
            ('B', Format::Binary),
            ('H', Format::Hostonly),
            ('U', Format::Unicornscan),
        ] {
            let flag = format!("-o{letter}");
            for file in ["out file.txt", "-"] {
                let o = opts(&[&flag, file]);
                assert_eq!(o.format, format, "{flag} {file}");
                assert_eq!(o.filename.as_deref(), Some(file), "{flag} {file}");
            }
        }
        // Остальная командная строка не трогается.
        let cli = parse(&["10.0.0.0/30", "-oL", "x.txt", "-p80", "-sL"]).unwrap();
        assert_eq!(cli.targets, ["10.0.0.0/30"]);
        assert_eq!(cli.ports, ["80"]);
        assert!(cli.list);
        assert_eq!(
            preprocess_args(["rmasscan", "-oX", "-", "-sL"]).unwrap(),
            [
                "rmasscan",
                "--output-format=xml",
                "--output-filename=-",
                "--list"
            ]
        );
    }

    #[test]
    fn dash_o_errors_match_c() {
        for a in [
            &["-oX"][..],
            &["-oX", "-p80"][..],
            &["-oL", "--seed"][..],
            &["-oJ", "-oL", "x"][..],
        ] {
            assert_eq!(masscan_err(a), "missing output filename", "{a:?}");
        }
        // Неподдерживаемая или неизвестная буква сообщается до проверки имени файла (main-conf.c:3401–3452).
        for f in ["-oA", "-oN", "-oS", "-oR"] {
            let want = format!("nmap({f}): unsupported output format");
            assert_eq!(masscan_err(&[f]), want);
            assert_eq!(masscan_err(&[f, "x"]), want);
        }
        assert_eq!(
            masscan_err(&["-oZ", "x"]),
            "nmap(-oZ): unknown output format"
        );
        assert_eq!(masscan_err(&["-oZ"]), "nmap(-oZ): unknown output format");
        assert_eq!(masscan_err(&["-o"]), "nmap(-o): unknown output format");
        // Как в C, решает третий символ, а argv печатается целиком.
        assert_eq!(
            masscan_err(&["-oAx"]),
            "nmap(-oAx): unsupported output format"
        );
        let o = opts(&["-oXyz", "f.xml"]);
        assert_eq!(
            (o.format, o.filename.as_deref()),
            (Format::Xml, Some("f.xml"))
        );
    }

    #[test]
    fn output_filename_alone_means_xml() {
        assert_eq!(opts(&[]), OutputOptions::default());
        for a in [
            &["--output-filename", "x"][..],
            &["--output-file", "x"][..],
            &["--output-filename=x"][..],
        ] {
            let o = opts(a);
            assert_eq!(
                (o.format, o.filename.as_deref()),
                (Format::Xml, Some("x")),
                "{a:?}"
            );
        }
        for a in [
            &["--output-filename", "x", "--output-format", "json"][..],
            &["--output-format", "json", "--output-filename", "x"][..],
        ] {
            assert_eq!(opts(a).format, Format::Json, "{a:?}");
        }
        assert_eq!(
            opts(&["--output-filename", "-"]).filename.as_deref(),
            Some("-")
        );
    }

    #[test]
    fn unknown_output_format_is_an_error() {
        for (name, f) in [
            ("list", Format::List),
            ("json", Format::Json),
            ("ndjson", Format::Ndjson),
            ("grepable", Format::Grepable),
            ("greppable", Format::Grepable),
            ("xml", Format::Xml),
            ("binary", Format::Binary),
            ("hostonly", Format::Hostonly),
            ("unicornscan", Format::Unicornscan),
            ("interactive", Format::Interactive),
            ("none", Format::None),
        ] {
            assert_eq!(opts(&["--output-format", name]).format, f, "{name}");
        }
        let want = "FAIL: unknown output-format: nmap\n  hint: list, json, ndjson, grepable, xml, binary, \
                    hostonly, unicornscan, interactive, none";
        assert_eq!(masscan_err(&["--output-format", "nmap"]), want);
        // Каждое вхождение проверяется, даже перекрытое последним (Р6 при Р17).
        assert_eq!(masscan_err(&["--output-format", "nmap", "-oL", "x"]), want);
        assert_eq!(masscan_err(&["-oL", "x", "--output-format=nmap"]), want);
        assert_eq!(parse_format("nmap").unwrap_err(), want);
    }

    #[test]
    fn redis_certs_rotate_are_refused() {
        for (a, name) in [
            (&["--output-format", "redis"][..], "--output-format redis"),
            (&["--output-format", "certs"][..], "--output-format certs"),
            (&["--rotate", "3600"][..], "--rotate"),
            (&["--output-rotate", "hourly"][..], "--rotate"),
            (&["--rotate-dir", "x"][..], "--rotate-dir"),
            (&["--rotate-size", "1m"][..], "--rotate-size"),
            (&["--rotate-offset", "60"][..], "--rotate-offset"),
        ] {
            let e = masscan_err(a);
            assert!(
                e.starts_with(&format!("{name} is not supported (")),
                "{a:?}: {e}"
            );
        }
        assert!(masscan_err(&["--output-format", "certs"]).contains("--banners"));
        assert!(masscan_err(&["--rotate", "3600"]).contains("rotat"));
    }

    #[test]
    fn show_and_noshow_tokens() {
        let d = opts(&[]);
        assert_eq!(
            (d.show_open, d.show_closed, d.show_host),
            (true, false, false)
        );
        let flags = |a: &[&str]| {
            let o = opts(a);
            (o.show_open, o.show_closed, o.show_host)
        };
        assert_eq!(flags(&["--show", "open,closed"]), (true, true, false));
        assert_eq!(flags(&["--show", "close"]), (true, true, false));
        assert_eq!(flags(&["--show", "all"]), (true, true, true));
        assert_eq!(flags(&["--show", "host"]), (true, false, true));
        assert_eq!(flags(&["--output-show", "closed"]), (true, true, false));
        assert_eq!(flags(&["--output-status=closed"]), (true, true, false));
        assert_eq!(flags(&["--noshow", "open"]), (false, false, false));
        assert_eq!(flags(&["--output-noshow", "open"]), (false, false, false));
        assert_eq!(
            flags(&["--show", "all", "--noshow", "all"]),
            (false, false, false)
        );
        // `INDEX_OF` C: пустой элемент обрывает список, повторные запятые пропускаются.
        assert_eq!(flags(&["--show", ",closed"]), (true, false, false));
        assert_eq!(flags(&["--show", "open,,closed,"]), (true, true, false));
        assert_eq!(flags(&["--show", ""]), (true, false, false));
        assert_eq!(
            masscan_err(&["--show", "open,bogus"]),
            "FAIL: unknown 'show' spec: bogus"
        );
        assert_eq!(
            masscan_err(&["--noshow", "x,open"]),
            "FAIL: unknown 'noshow' spec: x"
        );
        // Порядок командной строки, как в C: побеждает последнее.
        assert_eq!(
            flags(&["--show", "closed", "--noshow", "closed"]),
            (true, false, false)
        );
        assert_eq!(
            flags(&["--noshow", "closed", "--show", "closed"]),
            (true, true, false)
        );
        // `--open` возвращает умолчание C.
        assert_eq!(flags(&["--show", "all", "--open"]), (true, false, false));
        assert_eq!(
            flags(&["--noshow", "open", "--open-only"]),
            (true, false, false)
        );
        assert_eq!(flags(&["--open", "--show", "closed"]), (true, true, false));
        assert_eq!(
            flags(&["--open", "--show", "closed", "--open"]),
            (true, false, false)
        );
    }

    #[test]
    fn stylesheet_webxml_interactive_append_flush() {
        let o = opts(&["--webxml"]);
        assert_eq!(o.format, Format::Xml);
        assert_eq!(
            o.stylesheet.as_deref(),
            Some("http://nmap.org/svn/docs/nmap.xsl")
        );
        let o = opts(&["--stylesheet", "s.xsl"]);
        assert_eq!(
            (o.format, o.stylesheet.as_deref()),
            (Format::Xml, Some("s.xsl"))
        );
        let o = opts(&["--stylesheet", "s.xsl", "-oJ", "x"]);
        assert_eq!(o.format, Format::Json);
        assert!(opts(&["--interactive"]).interactive);
        assert!(!opts(&["--interactive", "--nointeractive"]).interactive);
        assert!(opts(&["--nointeractive", "--interactive"]).interactive);
        let o = opts(&["--append-output", "--output-flush", "-oL", "x"]);
        assert!(o.append && o.flush);
        assert!(opts(&["--output-append"]).append);
        assert!(!opts(&["-oL", "x"]).append);
        // Флаги C можно повторять.
        assert!(opts(&["--open", "--open", "--output-flush", "--output-flush"]).flush);
    }

    #[test]
    fn last_output_option_wins() {
        let o = opts(&["-oX", "a", "-oJ", "b"]);
        assert_eq!((o.format, o.filename.as_deref()), (Format::Json, Some("b")));
        let o = opts(&["--output-format", "xml", "--output-format", "list"]);
        assert_eq!(o.format, Format::List);
        let o = opts(&["--output-filename", "a", "--output-file", "b"]);
        assert_eq!(o.filename.as_deref(), Some("b"));
        let o = opts(&["--stylesheet", "a", "--stylesheet", "b"]);
        assert_eq!(o.stylesheet.as_deref(), Some("b"));
    }

    #[test]
    fn stylesheet_webxml_no_stylesheet_in_argv_order() {
        const XSL: &str = "http://nmap.org/svn/docs/nmap.xsl";
        let sty = |a: &[&str]| {
            let o = opts(a);
            (o.format, o.stylesheet)
        };
        let some = |s: &str| Some(s.to_string());
        // main-conf.c:2092-2105: любой --stylesheet/--webxml задаёт XML, если формата нет.
        assert_eq!(
            sty(&["--stylesheet", "a", "--webxml"]),
            (Format::Xml, some(XSL))
        );
        assert_eq!(
            sty(&["--webxml", "--stylesheet", "a"]),
            (Format::Xml, some("a"))
        );
        assert_eq!(
            sty(&["--stylesheet", "a", "--webxml", "--stylesheet", "b"]),
            (Format::Xml, some("b"))
        );
        // main-conf.c:2983-2984: --no-stylesheet только стирает таблицу.
        assert_eq!(sty(&["--no-stylesheet"]), (Format::Default, None));
        assert_eq!(
            sty(&["--stylesheet", "a", "--no-stylesheet"]),
            (Format::Xml, None)
        );
        assert_eq!(sty(&["--webxml", "--no-stylesheet"]), (Format::Xml, None));
        assert_eq!(
            sty(&["--no-stylesheet", "--webxml"]),
            (Format::Xml, some(XSL))
        );
        assert_eq!(sty(&["--webxml", "-oJ", "x"]), (Format::Json, some(XSL)));
        assert!(parse(&["--no-stylesheet"]).unwrap().output_flags_given());
    }

    #[test]
    fn parse_boolean_matches_c() {
        for t in [
            "", "1", "7", "0x1", "01", "true", "TRUE", "t", "yes", "Y", "on", "ON", "enable",
            "enabled", "E", "x",
        ] {
            assert!(parse_boolean(t), "{t:?}");
        }
        for f in [
            "0", "00", "0x0", "08", "08x1", "false", "F", "no", "N", "off", "OFF", "oF", "disable",
            "disabled", "d",
        ] {
            assert!(!parse_boolean(f), "{f:?}");
        }
    }

    #[test]
    fn bool_flags_take_values_and_last_wins() {
        assert!(opts(&["--output-append"]).append);
        assert!(!opts(&["--append-output", "--output-append=false"]).append);
        assert!(opts(&["--output-append=off", "--append-output"]).append);
        assert!(opts(&["--output-append=0", "--output-append=yes"]).append);
        assert!(opts(&["--output-flush"]).flush);
        assert!(!opts(&["--output-flush", "--output-flush=0"]).flush);
        assert!(opts(&["--output-flush=no", "--output-flush=1"]).flush);
        // Значение --open/--output-show-open C игнорирует (main-conf.c:1794-1806).
        for n in ["--output-show-open", "--open", "--open-only"] {
            let o = opts(&["--show", "closed", &format!("{n}=false")]);
            assert_eq!(
                (o.show_open, o.show_closed, o.show_host),
                (true, false, false),
                "{n}"
            );
            assert!(parse(&[n]).unwrap().output_flags_given(), "{n}");
            assert!(
                parse(&[&format!("{n}=false")])
                    .unwrap()
                    .output_flags_given(),
                "{n}=false"
            );
        }
        let o = opts(&["--output-show-open", "--show", "closed"]);
        assert_eq!((o.show_open, o.show_closed), (true, true));
        for a in [
            &["--output-append=false"][..],
            &["--output-flush=false"][..],
            &["--ndjson-status=false"][..],
            &["--status-ndjson=0"][..],
        ] {
            assert!(parse(a).unwrap().output_flags_given(), "{a:?}");
        }
    }

    #[test]
    fn status_mode_follows_c_flags() {
        use crate::status::StatusMode::{Ndjson, Off, Text};
        let m = |a: &[&str]| parse(a).unwrap().status_mode();
        assert_eq!(m(&[]), Text);
        assert_eq!(m(&["--status"]), Text);
        assert_eq!(m(&["--nostatus"]), Off);
        assert_eq!(m(&["--ndjson-status"]), Ndjson);
        assert_eq!(m(&["--status-ndjson"]), Ndjson);
        assert_eq!(m(&["--nostatus", "--ndjson-status"]), Off);
        assert_eq!(m(&["--ndjson-status", "--nostatus"]), Off);
        assert_eq!(m(&["--nostatus", "--ndjson-status", "--status"]), Ndjson);
        assert_eq!(m(&["--ndjson-status", "--status"]), Ndjson);
        assert_eq!(m(&["--ndjson-status", "--ndjson-status=false"]), Text);
        assert_eq!(m(&["--ndjson-status=false", "--ndjson-status"]), Ndjson);
        for (v, want) in [
            ("1", Ndjson),
            ("0", Text),
            ("true", Ndjson),
            ("no", Text),
            ("on", Ndjson),
            ("off", Text),
            ("enabled", Ndjson),
            ("disabled", Text),
            ("", Ndjson),
            ("x", Ndjson),
        ] {
            assert_eq!(m(&[&format!("--ndjson-status={v}")]), want, "{v:?}");
        }
    }

    #[test]
    fn json_status_is_refused_like_c() {
        for n in [
            "--json-status",
            "--status-json",
            "--json-status=1",
            "--status-json:x",
        ] {
            let bare = n.trim_start_matches("--").split(['=', ':']).next().unwrap();
            assert_eq!(
                masscan_err(&[n]),
                format!(
                    "[-] FAIL: {bare} not supported, use --status-ndjson\n    hint: new-line delimited JSON status is what we use"
                )
            );
        }
        // В порядке командной строки раньше следующих ошибок разбора не стоит, но после -o: отказ -o идёт первым.
        assert_eq!(masscan_err(&["-oJ"]), "missing output filename");
    }

    #[test]
    fn status_flags_are_stored() {
        let c = parse(&["--nostatus"]).unwrap();
        assert!(c.nostatus && !c.status && c.ndjson_status.is_empty());
        let c = parse(&["--status", "--nostatus"]).unwrap();
        assert!(!c.status && c.nostatus);
        let c = parse(&["--nostatus", "--status"]).unwrap();
        assert!(c.status && !c.nostatus);
        assert!(
            !parse(&["--ndjson-status"])
                .unwrap()
                .ndjson_status
                .is_empty()
        );
        assert!(
            !parse(&["--status-ndjson"])
                .unwrap()
                .ndjson_status
                .is_empty()
        );
    }

    #[test]
    fn output_flags_given_counts_every_output_and_status_flag() {
        assert!(
            !parse(&["10.0.0.1", "-p80", "--seed", "1"])
                .unwrap()
                .output_flags_given()
        );
        for a in [
            &["-oL", "x"][..],
            &["--output-format", "none"][..],
            &["--output-filename", "x"][..],
            &["--append-output"][..],
            &["--output-flush"][..],
            &["--open"][..],
            &["--open-only"][..],
            &["--show", "closed"][..],
            &["--noshow", "open"][..],
            &["--interactive"][..],
            &["--nointeractive"][..],
            &["--stylesheet", "s"][..],
            &["--webxml"][..],
            &["--status"][..],
            &["--nostatus"][..],
            &["--ndjson-status"][..],
        ] {
            assert!(parse(a).unwrap().output_flags_given(), "{a:?}");
        }
    }

    #[test]
    fn readscan_takes_every_following_non_dash_argument() {
        let c = parse(&["-p80", "10.0.0.0/8", "--readscan", "a", "b", "-oL", "-"]).unwrap();
        assert_eq!(c.readscan, ["a", "b"]);
        assert_eq!(c.targets, ["10.0.0.0/8"]);
        assert_eq!(c.ports, ["80"]);
        // C глотает и то, что выглядит целью (main-conf.c:3266–3278).
        let c = parse(&["--readscan", "a", "10.0.0.1"]).unwrap();
        assert_eq!(c.readscan, ["a", "10.0.0.1"]);
        assert!(c.targets.is_empty());
        assert!(parse(&["--readscan"]).is_err());
        for other in [
            &["-sL"][..],
            &["--echo"][..],
            &["--echo-all"][..],
            &["--offline"][..],
            &["--iflist"][..],
            &["--offline", "--packet-trace"][..],
        ] {
            let mut a = vec!["--readscan", "f"];
            a.extend_from_slice(other);
            assert!(matches!(parse(&a), Err(ParseError::Clap(_))), "{a:?}");
        }
        assert_eq!(
            seed_policy(&parse(&["--readscan", "f"]).unwrap()),
            SeedPolicy::Entropy
        );
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

    /// `paused.conf` для тестов `--resume`: адаптер, порт источника, скорость, повторы, вывод.
    const RESUME_FILE: &str = "\n# resume information\nresume-index = 4\nseed = 9\nrate = 250.000000\n\
retries = 2\nshard = 2/3\n\noutput-filename = a.json\noutput-format = json\n\n\
adapter = eth0\nadapter-ip = 198.18.0.2\nadapter-mac = 02-00-00-00-00-01\n\
router-mac-ipv4 = 02-00-00-00-00-02\nrouter-mac-ipv6 = 02-00-00-00-00-02\n\
adapter-port = 41234\n# TARGET SELECTION (IP, PORTS, EXCLUDES)\nports = 80\nrange = 198.18.0.0/28\n";

    /// Т2 M-2 (Р1): `--resume <file>` разбирается в своей позиции argv. Ключи правее файла (`--rate`,
    /// `--adapter-ip`, `--source-port`, `--router-mac`, `--interface`) переопределяют его и попадают и в
    /// одиночные поля, и в `nics[0]`; ключ левее файла файл переопределяет.
    #[test]
    fn resume_file_then_cli_flags_override_it_at_argv_level() {
        let dir = crate::scratch::Scratch::new();
        let file = dir.write("paused.conf", RESUME_FILE.as_bytes());
        let f = file.to_str().unwrap();

        let plain = parse(&["--resume", f]).unwrap().to_config().unwrap();
        assert_eq!(plain.max_rate, 250.0);
        assert_eq!(plain.seed, 9);
        assert_eq!(plain.resume_index, 4);
        assert_eq!(plain.retries, 2);
        assert_eq!(plain.adapter_ip, Some(0xc612_0002));
        assert_eq!(plain.source_port, Some((41234, 41234)));

        let over = parse(&[
            "--resume",
            f,
            "--rate",
            "500",
            "--adapter-ip",
            "198.18.0.9",
            "--source-port",
            "5000-5003",
            "--router-mac",
            "02-00-00-00-00-77",
            "--interface",
            "eth9",
            "--resume-index",
            "1",
        ])
        .unwrap()
        .to_config()
        .unwrap();
        assert_eq!(over.max_rate, 500.0);
        assert_eq!(over.resume_index, 1);
        assert_eq!(over.seed, 9, "keys the CLI did not give stay from the file");
        assert_eq!(over.adapter_ip, Some(0xc612_0009));
        assert_eq!(over.source_port, Some((5000, 5003)));
        assert_eq!(over.router_mac, Some([2, 0, 0, 0, 0, 0x77]));
        assert_eq!(over.adapter_name.as_deref(), Some("eth9"));
        assert_eq!(over.adapter_mac, Some([2, 0, 0, 0, 0, 1]));
        // Одиночные поля и `nics[0]` не расходятся (иначе `paused.conf` напишет значение файла).
        let nic = &over.nics[0];
        assert_eq!(nic.adapter_ip, Some((0xc612_0009, 0xc612_0009)));
        assert_eq!(nic.source_port, Some((5000, 5003)));
        assert_eq!(nic.router_mac_ipv4, Some([2, 0, 0, 0, 0, 0x77]));
        assert_eq!(nic.router_mac_ipv6, Some([2, 0, 0, 0, 0, 0x77]));
        assert_eq!(nic.adapter_name.as_deref(), Some("eth9"));
        assert!(!over.legacy_c_17_port_mask);

        // Ключ левее `--resume` файл переопределяет: файл говорит rate 250.
        let left = parse(&["--rate", "500", "--resume", f])
            .unwrap()
            .to_config()
            .unwrap();
        assert_eq!(left.max_rate, 250.0);
    }

    /// `--resume` принудительно включает `output-append` (main-conf.c:2926-2928); явные опции вывода правее
    /// файла его переопределяют; имя файла без формата значит XML (M-8).
    #[test]
    fn resume_forces_append_and_cli_output_flags_override_the_file() {
        let dir = crate::scratch::Scratch::new();
        let file = dir.write("paused.conf", RESUME_FILE.as_bytes());
        let f = file.to_str().unwrap();

        let o = parse(&["--resume", f])
            .unwrap()
            .resolved_output_options()
            .unwrap();
        assert!(o.append);
        assert_eq!(o.filename.as_deref(), Some("a.json"));
        assert_eq!(o.format, Format::Json);

        // Левее файла: файл переопределяет (-oX left.xml слева, файл говорит json a.json).
        let o = parse(&["-oX", "left.xml", "--resume", f])
            .unwrap()
            .resolved_output_options()
            .unwrap();
        assert_eq!(
            (o.format, o.filename.as_deref()),
            (Format::Json, Some("a.json"))
        );
        let o = parse(&["--append-output=false", "--resume", f])
            .unwrap()
            .resolved_output_options()
            .unwrap();
        assert!(o.append, "the file's forced append wins over a left flag");
        let o = parse(&["--resume", f, "--append-output=false"])
            .unwrap()
            .resolved_output_options()
            .unwrap();
        assert!(!o.append);
        let o = parse(&["--resume", f, "-oX", "b.xml"])
            .unwrap()
            .resolved_output_options()
            .unwrap();
        assert!(o.append);
        assert_eq!(o.filename.as_deref(), Some("b.xml"));
        assert_eq!(o.format, Format::Xml);

        // Без формата в файле имя файла даёт XML, а не `Default` (SET_output_filename, main-conf.c:1643).
        let bare = dir.write(
            "bare.conf",
            b"output-filename = c.out\nports = 80\nrange = 198.18.0.1\n",
        );
        let o = parse(&["--resume", bare.to_str().unwrap()])
            .unwrap()
            .resolved_output_options()
            .unwrap();
        assert_eq!(
            (o.format, o.filename.as_deref()),
            (Format::Xml, Some("c.out"))
        );

        // Без `--resume` ничего не меняется.
        assert!(
            !parse(&["-p80"])
                .unwrap()
                .resolved_output_options()
                .unwrap()
                .append
        );
        // Нечитаемый файл `--resume` это ошибка (отличие от C, Р1), а не молчаливое продолжение.
        let e = parse(&["--resume", "/nonexistent/paused.conf"])
            .unwrap()
            .to_config()
            .unwrap_err();
        assert!(e.contains("paused.conf"), "{e}");
        assert!(parse(&["--resume", "a", "--resume", "b"]).is_err());
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
