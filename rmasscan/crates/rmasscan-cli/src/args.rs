//! Разбор командной строки (AGPL-3.0). Порт подмножества опций masscan
//! `src/main-conf.c` (`masscan_command_line` :3211, `masscan_set_parameter`
//! :2434) из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Любая опция вне подмножества (например `--heartbleed` или `--script`) - ошибка clap,
//! а не молчаливый пропуск (Review Focus №5).
//!
//! Опции вывода (`SET_output_*`, main-conf.c:1616–1806, `-o<буква>` :3401–3459) разбираются с семантикой C:
//! `-o<буква> FILE` переводится в длинные опции до clap, повтор опции вывода побеждает последним (Р17), `--show`,
//! `--noshow` и `--open` применяются в порядке командной строки. Отклонения от C: неизвестный `--output-format` -
//! ошибка (Р6); redis и ротация отклоняются с причиной (Р1).

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::path::Path;

use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser};
use rmasscan_core::config::{
    NicConfig, ScanConfig, apply_core_kv, is_boolean, is_integer, normalize_key, parse_mac,
    parse_rate, parse_shard, parse_source_port,
};
use rmasscan_core::targets::{
    TEMPL_ICMP_ECHO, TEMPL_SCTP, TEMPL_UDP, add_top_ports, parse_ports_with, range_parse_ipv4,
};

use crate::conf::{FullConf, OutputConfPatch, apply_conf_key, banner_app, check_c_index};
use crate::output::{Format, OutputOptions};
use crate::status::StatusMode;

/// `--webxml` (main-conf.c:3033–3034).
const NMAP_XSL: &str = "http://nmap.org/svn/docs/nmap.xsl";

/// Допустимые значения `--output-format` в тексте отказа (Р6).
const FORMAT_NAMES: &str =
    "list, json, ndjson, grepable, xml, binary, hostonly, unicornscan, certs, interactive, none";

/// Отказы Р1 с причиной.
const REDIS_REFUSAL: &str =
    "--output-format redis is not supported (rmasscan writes results only to a file or stdout)";

// Опции v1. Значения, у которых в C своя грамматика (`--rate`, `--shard`,
// MAC, `--source-port`), хранятся строками и разбираются функциями ядра.
#[derive(Parser, Debug, Clone, Default)]
#[command(
    name = "rmasscan",
    version,
    about = "Rust port of masscan: TCP SYN scan with adapter and gateway auto-detection, masscan output formats, --readscan, --offline, -sL, --echo and --iflist",
    disable_help_subcommand = true,
    after_help = "Examples:\n  sudo rmasscan 198.51.100.0/24 -p80,443\n  rmasscan --offline 198.51.100.0/24 -p80 --seed 1\n  rmasscan --iflist\n  rmasscan -sL 10.0.0.0/24 -p80,443 --seed 1\n  rmasscan --echo 10.0.0.0/24 -p80 --seed 1\n  rmasscan --offline --packet-trace 10.0.0.0/30 -p80 --seed 1 \\\n    --adapter-ip 10.255.0.1 --adapter-mac 00-11-22-33-44-55 --source-port 40000-40003\n  sudo rmasscan 198.51.100.0/24 -p80 -oB scan.bin\n  rmasscan -p80 --readscan scan.bin -oJ scan.json\n  sudo rmasscan 198.51.100.0/24 --banners -p80 -oB tcp.bin\n  sudo rmasscan 198.51.100.0/24 -pU:53,123,161 --banners -oB udp.bin\n\nOutput (scan and --readscan only): -oL list, -oJ json, -oD ndjson, -oG grepable, -oX xml, -oB binary,\n-oH hostonly, -oU unicornscan, each followed by FILE (- is stdout); --output-format certs\n--output-filename FILE prints banners as PEM certificates on stdout. With a file format stdout is silent\nunless --interactive is given. --banners adds banner records: UDP replies, and TCP connections through a\nuser-mode TCP stack (give --adapter-ip an address the OS does not own, or the kernel resets them).\n\nWithout an operation flag rmasscan scans: it picks the interface that routes to the targets, its first IPv4\naddress and MAC, resolves the next hop with ARP (unless --router-mac is given) and needs root/Administrator\nonly to open the adapter. IPv6 targets (TCP only) take the source address and next hop of the IPv6 route,\nresolved with an NDP neighbor solicitation (unless --router-mac-ipv6 is given). Detection, --offline and\n--iflist only read the OS and never transmit.\nOperations: -sL, --echo, --echo-all, --offline [--packet-trace], --iflist, --readscan (mutually exclusive).\n--seed is required (and must be non-zero) for -sL, --echo and --offline; a live scan without --seed uses\nOS entropy and prints it. [+] lines go to stderr. Any other masscan option is an error."
)]
pub struct Cli {
    // Цели: IP, CIDR, `a.b.c.d-e.f.g.h`, списки через запятую.
    #[arg(
        value_name = "TARGET",
        help = "Targets: IPv4 or IPv6 address, CIDR, a.b.c.d-e.f.g.h, or comma-separated list"
    )]
    pub targets: Vec<String>,
    // `--range` (main-conf.c:2730-2734, синонимы C `ranges`, `ip`, `ipv4`, `dst-ip`, `dest-ip`, `destination-ip`,
    // `target-ip`): то же, что позиционная цель.
    #[arg(
        long = "range",
        aliases = ["ranges", "ip", "ipv4", "dst-ip", "dest-ip", "destination-ip", "target-ip"],
        value_name = "RANGE",
        help = "Target range (same as a positional target)"
    )]
    pub range: Vec<String>,
    // `pcap-filename` и синоним `pcap` (main-conf.c:2385): файл захвата входящих кадров (Р8).
    #[arg(
        long = "pcap",
        alias = "pcap-filename",
        value_name = "FILE",
        help = "Save the inbound frames addressed to the scanner to a .pcap file (live scan only; alias: --pcap-filename)"
    )]
    pub pcap: Option<String>,
    // `nmap-payloads` и синоним `nmap-payload` (main-conf.c:2382): нагрузки UDP в синтаксисе `nmap-payloads`.
    #[arg(
        long = "nmap-payloads",
        alias = "nmap-payload",
        value_name = "FILE",
        help = "Read UDP probe payloads from FILE in the nmap-payloads syntax (replaces the built-in payload of a port)"
    )]
    pub nmap_payloads: Option<String>,
    // `pcap-payloads` и синоним `pcap-payload` (main-conf.c:2386): нагрузки UDP из захвата pcap.
    #[arg(
        long = "pcap-payloads",
        alias = "pcap-payload",
        value_name = "FILE",
        help = "Read UDP probe payloads from the packets of a .pcap capture (read before --nmap-payloads)"
    )]
    pub pcap_payloads: Option<String>,
    // `-p80,443`, `-p0-65535`, `--ports 22,80` (main-conf.c:2663-2666, синонимы C `port`, `dst-port`, `dest-port`,
    // `destination-port`, `target-port`).
    #[arg(
        short = 'p',
        long = "ports",
        aliases = ["port", "dst-port", "dest-port", "destination-port", "target-port"],
        value_name = "PORTS",
        help = "Ports to scan, e.g. -p80,443 or -p0-65535; prefixes T: U: S: I: O: stay in effect until the next one, e.g. -pU:53,161,T:80,I:0"
    )]
    pub ports: Vec<String>,
    // `--udp-ports` (main-conf.c:2642-2648): порты UDP и сам по себе включает UDP-скан.
    #[arg(
        long = "udp-ports",
        alias = "udp-port",
        value_name = "PORTS",
        help = "UDP ports to scan (same as -pU:PORTS)"
    )]
    pub udp_ports: Vec<String>,
    // `-sS`, `-sU`, `-sZ` (main-conf.c:3524-3549) приходят из [`preprocess_args`] как `--rmasscan-scan=S|U|Z`.
    #[arg(long = "rmasscan-scan", value_name = "S|U|Z", hide = true)]
    pub scan_types: Vec<String>,
    // `--ping`, `--ping-sweep` (main-conf.c:2721-2729): добавляет `I:0`.
    #[arg(
        long,
        alias = "ping-sweep",
        help = "Add an ICMP echo probe (same as -pI:0, alias: --ping-sweep)"
    )]
    pub ping: bool,
    // `--arp`, `--arpscan` (main-conf.c:1088-1102, :2373): порт `I:2`, `router-mac = ff-ff-ff-ff-ff-ff`, `arpscan = true`.
    #[arg(
        long,
        alias = "arpscan",
        help = "ARP scan of the local segment (same as -pI:2; the gateway is not resolved; cannot be combined with other ports; alias: --arpscan)"
    )]
    pub arp: bool,
    // `F_NUMABLE` (main-conf.c:2423): `--top-ports [N]`; значение берётся из следующего слова, если оно целое или
    // логическое (см. [`preprocess_args`]); `--top-port` синоним.
    #[arg(
        long = "top-ports",
        alias = "top-port",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        value_name = "N",
        help = "Also scan the N most common ports (default 20); with -sU the UDP table, with -sS -sU both"
    )]
    pub top_ports: Vec<String>,
    // main-conf.c:2744-2750: синонимы C `exclude-range`, `exclude-ranges`, `exclude-ip`, `exclude-ipv4`.
    #[arg(
        long,
        aliases = ["exclude-range", "exclude-ranges", "exclude-ip", "exclude-ipv4"],
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
    // main-conf.c:2375: синоним C `max-rate`.
    #[arg(
        long,
        alias = "max-rate",
        value_name = "PPS",
        help = "Packets per second (default 100)"
    )]
    pub rate: Option<String>,
    // Р4, main-conf.c:3028-3032: число секунд или `forever` (`INT_MAX`); разбирает ключ ядра `wait`, как в файле.
    #[arg(
        long,
        value_name = "SECONDS|forever",
        help = "Seconds to wait for replies after the scan, or forever (default 10)"
    )]
    pub wait: Option<String>,
    // main-conf.c:2380: синонимы C `retry`, `max-retries`, `max-retry`.
    #[arg(
        long,
        aliases = ["retry", "max-retries", "max-retry"],
        value_name = "N",
        help = "Number of retries (default 0, below 1000)"
    )]
    pub retries: Option<u32>,
    // main-conf.c:2376: синоним C `shards`.
    #[arg(
        long,
        alias = "shards",
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
    // main-conf.c:2472-2473, 3332-3338, 3868-3924: `-c FILE`, `--conf FILE`, `--config FILE` читают файл в своей позиции argv.
    #[arg(
        short = 'c',
        long = "conf",
        alias = "config",
        value_name = "FILE",
        action = clap::ArgAction::Append,
        help = "Read a configuration file (key = value lines) at this position; options to the right override it, repeatable (aliases: --config, -cFILE)"
    )]
    pub conf: Vec<String>,
    // Ключи массива адаптеров `--adapter[i]`, `--adapter-ip[i]`, ... (main-conf.c:882-890, 2437-2641): [`preprocess_args`]
    // переписывает их в `--rmasscan-nic=имя[i]=значение`, чтобы clap дал позицию в `argv`.
    #[arg(long = "rmasscan-nic", hide = true, action = clap::ArgAction::Append)]
    nic_kv: Vec<String>,
    // main-conf.c:2825-2836, 3375-3377: `-iL FILE` / `--includefile FILE`, файл целей (`massip_parse_file`).
    #[arg(
        long = "includefile",
        value_name = "FILE",
        action = clap::ArgAction::Append,
        help = "File of targets: addresses, CIDRs and ranges separated by whitespace or commas, # starts a comment (alias: -iL)"
    )]
    pub includefile: Vec<String>,
    // main-conf.c:2486-2550: `source-ip`, `source-address`, `spoof-ip`, `spoof-address`, `src-ip` - синонимы
    // `adapter-ip`; диапазон `A-B` степени двойки (Р6); адрес IPv6 (main-conf.c:2508-2512) идёт в
    // `nics[0].adapter_ipv6`. Одно значение на командную строку: второе семейство задаёт `--adapter-ip[0]` или файл `-c`.
    #[arg(
        long = "adapter-ip",
        aliases = ["source-ip", "source-address", "spoof-ip", "spoof-address", "src-ip"],
        value_name = "IP",
        help = "Source IPv4 address, or a range A-B / CIDR of 1, 2, 4, 8, ... addresses, or the source IPv6 address (alias: --source-ip; the other family: --adapter-ip[0])"
    )]
    pub adapter_ip: Option<String>,
    // Р9: `--ttl` (main-conf.c:3003-3009), 1..=255; 0 и >= 256 отклоняются.
    #[arg(
        long,
        value_name = "N",
        help = "IP time-to-live of the probes, 1-255 (default 255)"
    )]
    pub ttl: Option<String>,
    // Р9: `badsum` - singleton (main-conf.c:2758, :3074).
    #[arg(
        long,
        help = "Send SYNs with a wrong TCP checksum (the IPv4 header checksum stays valid)"
    )]
    pub badsum: bool,
    // Р9: `F_BOOL` (main-conf.c:2381), singleton (:3083): значение только `--noreset=<bool>`, следующее слово не берётся.
    // Снимает RST без состояния (Р8 этапа баннеров, `src/main.c:1094-1100`); RST стека `--banners` идут и с ним.
    #[arg(
        long,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        value_name = "BOOL",
        help = "Send no RST to a SYN-ACK or RST reply (without --banners every fresh reply gets one, like masscan)"
    )]
    pub noreset: Vec<String>,
    // Р9: `F_NUMABLE` (main-conf.c:2419): `--tcp-mss [N|BOOL]`; значение берётся из следующего слова, если оно
    // целое или логическое (см. [`preprocess_args`]); синоним C `--tcpmss` даёт тот же ключ `EQUALS`, что `tcp-mss`.
    #[arg(
        long = "tcp-mss",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        value_name = "N|BOOL",
        help = "TCP MSS option: number (default 1460) or disable"
    )]
    pub tcp_mss: Vec<String>,
    #[arg(
        long = "tcp-sackok",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        value_name = "BOOL",
        help = "Add the TCP SACK-permitted option (=false disables; never takes the next word)"
    )]
    pub tcp_sackok: Vec<String>,
    #[arg(
        long = "tcp-wscale",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        value_name = "N|BOOL",
        help = "Add the TCP window-scale option: number 0-254 (default 3)"
    )]
    pub tcp_wscale: Vec<String>,
    #[arg(
        long = "tcp-tsecho",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        value_name = "N|BOOL",
        help = "Add the TCP timestamp option with this 32-bit value (default 0x12345678)"
    )]
    pub tcp_tsecho: Vec<String>,
    // main-conf.c:2556-2557: `spoof-mac`, `source-mac`, `src-mac` - синонимы `adapter-mac`.
    #[arg(
        long = "adapter-mac",
        aliases = ["spoof-mac", "source-mac", "src-mac"],
        value_name = "MAC",
        help = "Source MAC address (alias: --source-mac)"
    )]
    pub adapter_mac: Option<String>,
    // main-conf.c:2626-2641: ровно один IPv4. Адрес IPv6 (у C ключа нет) это следующий хоп IPv6 для NDP (R11).
    #[arg(
        long = "router-ip",
        value_name = "IP",
        help = "Router (next hop) IPv4 address to resolve with ARP, or IPv6 address to resolve with NDP (single address; default: route gateway)"
    )]
    pub router_ip: Option<String>,
    // main-conf.c:2587-2600: `--router-mac` (синонимы C `router`, `dest-mac`, `destination-mac`, `dst-mac`,
    // `target-mac`) ставит MAC шлюза и IPv4, и IPv6.
    #[arg(
        long = "router-mac",
        aliases = ["router", "dest-mac", "destination-mac", "dst-mac", "target-mac"],
        value_name = "MAC",
        help = "Router (next hop) MAC address for IPv4 and IPv6: skips ARP and NDP (ignored by --offline, which uses 66-55-44-33-22-11)"
    )]
    pub router_mac: Option<String>,
    // main-conf.c:2602-2612: `router-mac-ipv4` / `router-ipv4` (синоним C, тоже MAC): только MAC шлюза IPv4, как ключ
    // файла и `--router-mac-ipv4[i]`.
    #[arg(
        long = "router-mac-ipv4",
        alias = "router-ipv4",
        value_name = "MAC",
        help = "Router (next hop) MAC address for IPv4 only: skips ARP (alias: --router-ipv4)"
    )]
    pub router_mac_ipv4: Option<String>,
    // main-conf.c:2614-2624: `router-mac-ipv6` / `router-ipv6` (синоним C, тоже MAC): только MAC шлюза IPv6.
    #[arg(
        long = "router-mac-ipv6",
        alias = "router-ipv6",
        value_name = "MAC",
        help = "Router (next hop) MAC address for IPv6 only: skips NDP (alias: --router-ipv6)"
    )]
    pub router_mac_ipv6: Option<String>,
    // Одиночный порт или диапазон степени двойки (main-conf.c:2523-2524, синонимы C `adapter-port`, `src-port`;
    // `sourceport` с :2979 даёт тот же ключ `EQUALS`, что `source-port`).
    #[arg(
        long = "source-port",
        aliases = ["adapter-port", "src-port"],
        value_name = "PORT",
        help = "Source port, or a range whose size is a power of two (default: one port 40000 + time % 20000)"
    )]
    pub source_port: Option<String>,
    // main-conf.c:2474: синонимы C `adapter`, `if`.
    #[arg(
        short = 'e',
        long = "interface",
        aliases = ["adapter", "if"],
        value_name = "IFACE",
        help = "Network interface (alias: --adapter): its name; on Windows \\Device\\NPF_{GUID} or the adapter name (default: the interface of the route to the targets)"
    )]
    pub interface: Option<String>,
    // main-conf.c:2384: синонимы C `notransmit`, `nosend`, `dry-run`.
    #[arg(
        long,
        aliases = ["notransmit", "nosend", "dry-run"],
        help = "Do not transmit: detect read-only and print the [+] lines (fake router MAC 66-55-44-33-22-11)"
    )]
    pub offline: bool,
    // `SET_infinite` (main-conf.c:2836): без конца, проходы заново с `seed + 1`, пока не придёт Ctrl-C.
    #[arg(
        long,
        conflicts_with = "list",
        help = "Scan the range again and again (seed + 1 each pass) until Ctrl-C; no paused.conf is written"
    )]
    pub infinite: bool,
    // main-conf.c:2876: синоним C `trace-packet`.
    #[arg(
        long = "packet-trace",
        alias = "trace-packet",
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
        help = "Read masscan -oB files (status and banner records) and write them with the output options; targets and ports given before it filter the records"
    )]
    pub readscan: Vec<String>,
    // `--banner-types` и синонимы `--banner-type`, `--banner-apps`, `--banner-app` (`src/main-conf.c:2683-2697`): одно
    // имя `masscan_string_to_app` на опцию, набор копится; его потребитель только `--readscan` (`src/in-binary.c:684`).
    // Имена проверяет [`Cli::try_parse_masscan`].
    #[arg(
        long = "banner-types",
        aliases = ["banner-type", "banner-apps", "banner-app"],
        value_name = "APP",
        action = clap::ArgAction::Append,
        help = "With --readscan: keep only banner records of this application (http, ssl, dns-ver, ...; repeatable, one name each) and drop every status record"
    )]
    pub banner_types: Vec<String>,
    // `banners` и синоним `banner` (`F_BOOL`, `src/main-conf.c:1106-1116`, таблица :2377): голый флаг это `true`,
    // `=<bool>` по `parseBoolean`; следующее слово не забирается (`is_singleton`, :3083-3094). `--nobanners`,
    // `--rawudp`, `--capture`, `--nocapture`, `--hello-timeout` и файлы `-c` применяются вместе в порядке argv
    // ([`Cli::banner_steps`]).
    #[arg(
        long = "banners",
        alias = "banner",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        value_name = "BOOL",
        help = "Report banners: UDP replies (dns-ver, ntp, nbtstat, snmp, isakmp, coap, memcached, zeroaccess and raw) and TCP connections through a user-mode TCP stack (http, ftp, smtp, pop3, imap4, ssh, telnet, vnc, rdp, memcached, minecraft; alias: --banner)"
    )]
    pub banners: Vec<String>,
    // `nobanners`/`nobanner` (`F_BOOL`, `src/main-conf.c:1546-1554`, :2379): `is_banners = !parseBoolean(value)`.
    #[arg(
        long = "nobanners",
        alias = "nobanner",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        value_name = "BOOL",
        help = "Undo --banners (alias: --nobanner)"
    )]
    pub nobanners: Vec<String>,
    // `rawudp` (`F_BOOL`, `src/main-conf.c:1118-1130`, :2378): включает и `banners`.
    #[arg(
        long = "rawudp",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        value_name = "BOOL",
        help = "Also report every UDP reply as a raw banner (the whole datagram); implies --banners"
    )]
    pub rawudp: Vec<String>,
    // `capture` и `nocapture`/`no-capture` (`src/main-conf.c:1132-1180`, :2402-2403): значение следующим словом или
    // после `=`. В 4b действует только `html` (`banner1->is_capture_html`); остальные читают баннеры TLS (4c).
    #[arg(
        long = "capture",
        value_name = "TYPE",
        action = clap::ArgAction::Append,
        help = "TCP banner capture: cert (default on), servername, html, heartbleed or ticketbleed; html adds the whole page to HTTP banners, the others act with TLS banners (not in this version)"
    )]
    pub capture: Vec<String>,
    #[arg(
        long = "nocapture",
        alias = "no-capture",
        value_name = "TYPE",
        action = clap::ArgAction::Append,
        help = "Undo --capture TYPE (alias: --no-capture)"
    )]
    pub nocapture: Vec<String>,
    // `hello-timeout` (`src/main-conf.c:1288-1298`): принимается и, как у C, ни на что не влияет (Р1, Р17).
    #[arg(
        long = "hello-timeout",
        value_name = "SECONDS",
        action = clap::ArgAction::Append,
        help = "Accepted for masscan compatibility; like masscan it has no effect"
    )]
    pub hello_timeout: Vec<String>,
    // `hello` (`src/main-conf.c:1181-1210`, таблица :2387): каждое вхождение ставит свой флаг, неизвестное
    // значение отказывает с текстом C на разборе конфигурации.
    #[arg(
        long = "hello",
        value_name = "TYPE",
        action = clap::ArgAction::Append,
        help = "Send this hello on every TCP port (except 65535): ssl, smbv1 or http; repeatable"
    )]
    pub hello: Vec<String>,
    // `hello-string[PORT]`, `hello-file[PORT]` (`hello-filename`) и любое написание `http-header`/`http-field`
    // (`src/main-conf.c:1207-1286`, `:1335-1408`): [`preprocess_args`] переписывает их до `EQUALS` в скрытые
    // опции `--rmasscan-…=набранное-имя=значение`, потому что индекс и форма заголовка читаются из набранного
    // имени (справка C2, C3), а clap такого имени не выражает.
    #[arg(long = "rmasscan-hello-string", hide = true, action = clap::ArgAction::Append)]
    hello_string_kv: Vec<String>,
    #[arg(long = "rmasscan-hello-file", hide = true, action = clap::ArgAction::Append)]
    hello_file_kv: Vec<String>,
    #[arg(long = "rmasscan-http-header", hide = true, action = clap::ArgAction::Append)]
    http_header_kv: Vec<String>,
    // `connection-timeout` и синоним `tcp-timeout` старого стиля (`src/main-conf.c:2765-2767`): жизнь
    // соединения баннеров в секундах, 0 это умолчание C 30; в paused.conf не пишется.
    #[arg(
        long = "connection-timeout",
        alias = "tcp-timeout",
        value_name = "SECONDS",
        action = clap::ArgAction::Append,
        help = "Lifetime of a TCP banner connection in seconds (default 30; alias: --tcp-timeout)"
    )]
    pub connection_timeout: Vec<String>,
    // `http-*` (`src/main-conf.c:1300-1505`, таблица :2391-2398): одиночные держат последнее значение, cookie
    // копятся (не больше 16). Синоним C `http-useragent` даёт тот же ключ `EQUALS`, что `http-user-agent`,
    // поэтому синонимом clap не объявлен.
    #[arg(
        long = "http-method",
        value_name = "METHOD",
        action = clap::ArgAction::Append,
        help = "Method of the HTTP banner request (default GET)"
    )]
    pub http_method: Vec<String>,
    #[arg(
        long = "http-url",
        alias = "http-uri",
        value_name = "URL",
        action = clap::ArgAction::Append,
        help = "URL of the HTTP banner request (default /; alias: --http-uri)"
    )]
    pub http_url: Vec<String>,
    #[arg(
        long = "http-version",
        value_name = "VERSION",
        action = clap::ArgAction::Append,
        help = "Version of the HTTP banner request (default HTTP/1.0)"
    )]
    pub http_version: Vec<String>,
    #[arg(
        long = "http-host",
        value_name = "HOST",
        action = clap::ArgAction::Append,
        help = "Host field of the HTTP banner request (none by default)"
    )]
    pub http_host: Vec<String>,
    #[arg(
        long = "http-user-agent",
        value_name = "AGENT",
        action = clap::ArgAction::Append,
        help = "User-Agent field of the HTTP banner request"
    )]
    pub http_user_agent: Vec<String>,
    #[arg(
        long = "http-payload",
        value_name = "PAYLOAD",
        action = clap::ArgAction::Append,
        help = "Body of the HTTP banner request (also sets Content-Length)"
    )]
    pub http_payload: Vec<String>,
    #[arg(
        long = "http-cookie",
        value_name = "COOKIE",
        action = clap::ArgAction::Append,
        help = "Add a Cookie field to the HTTP banner request (repeatable, at most 16; a header NAME:VALUE or [NAME] is set with --http-header)"
    )]
    pub http_cookie: Vec<String>,
    // Каждое вхождение проверяется (Р6), побеждает последнее (Р17).
    #[arg(
        long = "output-format",
        value_name = "FORMAT",
        value_parser = output_format_value,
        overrides_with = "output_format",
        help = "list, json, ndjson, grepable, xml, binary, hostonly, unicornscan, certs, interactive or none"
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
    /// Файлы конфигурации (`-c`, `--conf`, `--config`, `--resume`) в порядке `argv` и их позиции clap.
    #[arg(skip)]
    markers: Vec<FileMarker>,
    /// Опции портов и типов скана по порядку `argv`: префикс `-p` зависит от `-sU`/`-sZ` левее него.
    #[arg(skip)]
    port_events: Vec<(usize, PortEvent)>,
    /// Позиция clap последнего появления каждого позиционного ключа конфигурации ([`POSITIONAL_KEYS`]).
    #[arg(skip)]
    key_pos: HashMap<&'static str, usize>,
    /// Ключи `имя[i]=значение` массива адаптеров и позиции clap.
    #[arg(skip)]
    nic_pos: Vec<(usize, String)>,
    /// Опции баннеров (`--banners`, `--nobanners`, `--rawudp`, `--capture`, `--nocapture`, `--hello-timeout`,
    /// `--hello*`, `--connection-timeout`, `--http-*`) по порядку argv: позиция clap и шаг. Они меняют одни и те
    /// же флаги и списки (`--rawudp --nobanners`), поэтому применяются одной последовательностью, а не
    /// «последним вхождением» каждой.
    #[arg(skip)]
    banner_steps: Vec<(usize, BannerStep)>,
    /// Позиция clap последнего появления каждой группы опций вывода (`format`, `filename`, `append`, `flush`,
    /// `style`, `show`).
    #[arg(skip)]
    output_pos: HashMap<&'static str, usize>,
    /// Разобранная конфигурация с `--resume`: файл читается один раз на `Cli`.
    #[arg(skip)]
    resolved: std::sync::OnceLock<Result<FullConf, String>>,
}

/// Один шаг опций баннеров в порядке argv: обычный ключ ядра или опция, чей смысл читается из набранного
/// имени (`hello-string[PORT]`, `hello-file[PORT]`, `http-header` с правилом `name += 11`, справка C2, C3).
#[derive(Debug, Clone)]
enum BannerStep {
    Kv(&'static str, String),
    HelloString(String, String),
    HelloFile(String, String),
    HttpHeader(String, String),
}

/// Опция, меняющая порты или тип скана (`masscan_set_parameter` зовётся по ходу `argv`).
#[derive(Debug, Clone)]
enum PortEvent {
    /// `-sS` (`S`), `-sU` (`U`), `-sZ` (`Z`).
    Scan(char),
    Ports(String),
    UdpPorts(String),
}

/// Префикс по умолчанию для портов без префикса (main-conf.c:2670–2674): UDP важнее SCTP, иначе TCP (`0`).
fn port_default(udp: bool, sctp: bool) -> u32 {
    if udp {
        TEMPL_UDP
    } else if sctp {
        TEMPL_SCTP
    } else {
        0
    }
}

/// Идентификаторы clap опций, которые кладутся в `ScanConfig` позиционно (ключи правее `--resume` переопределяют
/// файл, ключи левее переопределяются им, `masscan_set_parameter` вызывается в порядке argv).
const POSITIONAL_KEYS: [&str; 29] = [
    "pcap",
    "nmap_payloads",
    "pcap_payloads",
    "ndjson_status",
    "infinite",
    "offline",
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
    "router_mac_ipv4",
    "router_mac_ipv6",
    "source_port",
    "interface",
    "ttl",
    "badsum",
    "noreset",
    "tcp_mss",
    "tcp_sackok",
    "tcp_wscale",
    "tcp_tsecho",
];

/// Опции баннеров: идентификатор clap и ключ `masscan_set_parameter` (`src/main-conf.c:2377-2403`,
/// `connection-timeout` старого стиля `:2765-2767`).
const BANNER_KEYS: [(&str, &str); 15] = [
    ("banners", "banners"),
    ("nobanners", "nobanners"),
    ("rawudp", "rawudp"),
    ("capture", "capture"),
    ("nocapture", "nocapture"),
    ("hello_timeout", "hello-timeout"),
    ("hello", "hello"),
    ("connection_timeout", "connection-timeout"),
    ("http_method", "http-method"),
    ("http_url", "http-url"),
    ("http_version", "http-version"),
    ("http_host", "http-host"),
    ("http_user_agent", "http-user-agent"),
    ("http_payload", "http-payload"),
    ("http_cookie", "http-cookie"),
];

/// Одиночные опции адаптера, которые идут по порядку `argv` вместе с `--adapter[i]` и т.п.
const NIC_PLAIN: [&str; 8] = [
    "adapter_ip",
    "adapter_mac",
    "router_ip",
    "router_mac",
    "router_mac_ipv4",
    "router_mac_ipv6",
    "source_port",
    "interface",
];

/// Шаг ключа адаптера внутри сегмента.
enum NicStep<'a> {
    Plain(&'static str),
    Indexed(&'a str),
}

/// Файл конфигурации в `argv`: `kind` это ключ C (`conf` или `resume`), `pos` индекс clap его значения.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileMarker {
    pos: usize,
    kind: &'static str,
    path: String,
}

/// Идентификаторы clap опций вывода по группам (`merge_file_output`).
const OUTPUT_GROUPS: [(&str, &[&str]); 6] = [
    // Только `--output-format` ставит формат безусловно; имя файла и таблица стилей лишь подставляют XML
    // при формате 0 (main-conf.c:1643, 2100), `--no-stylesheet` формат не трогает (:2983).
    ("format", &["output_format"]),
    ("filename", &["output_filename"]),
    ("append", &["append_output"]),
    ("flush", &["output_flush"]),
    ("style", &["stylesheet", "webxml", "no_stylesheet"]),
    ("show", &["show", "noshow", "open"]),
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
        // Имя по `EQUALS` (`src/main-conf.c:833-849`), как у опций таблицы clap.
        if matches!(normalize_key(name).as_str(), "jsonstatus" | "statusjson") {
            return Err(ParseError::Masscan(format!(
                "[-] FAIL: {name} not supported, use --status-ndjson\n    hint: new-line delimited JSON status is what we use"
            )));
        }
    }
    Ok(())
}

/// Ошибка разбора: текст clap печатает `clap::Error::print` (справка и версия в stdout) с кодом [`clap_exit_code`], текст
/// masscan печатается в stderr как есть, exit 1.
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
// 0. Имя `--опции` сравнивается как `EQUALS` C ([`equals_option`]) и переписывается в длинное имя clap раньше всех
//    остальных правил, поэтому они видят только каноническое имя. Значения не переписываются: слово, которое правило
//    ниже забирает как значение (`it.next()`), уже не попадает в цикл; значение после `=` или `:` остаётся как есть;
//    отдельное слово, которое начинается с `--`, clap значением не берёт (ни у одной опции нет `allow_hyphen_values`,
//    тест `no_option_takes_hyphen_values`), а другие слова [`equals_option`] не трогает. Голое `--` clap понимает как
//    конец опций: оно и всё правее идут в clap как есть, это цели. Короткие опции не трогаются.
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
    let mut it = args.into_iter().map(Into::into).peekable();
    let mut out: Vec<String> = it.next().into_iter().collect();
    while let Some(raw) = it.next() {
        if raw == "--" {
            out.push(raw);
            out.extend(it.by_ref());
            break;
        }
        // `--hello-string[P]`, `--hello-file[P]` и любое написание `--http-header`/`--http-field` раньше
        // `EQUALS`: индекс и форма заголовка читаются из набранного имени (справка C2, C3).
        if let Some(step) = banner_typed_option(&raw) {
            let step = step?;
            let value = match step.inline {
                Some(v) => v,
                None => it
                    .next()
                    .ok_or_else(|| format!("{}: empty parameter", step.typed))?,
            };
            out.push(format!("--{}={}={value}", step.hidden, step.typed));
            continue;
        }
        let a = equals_option(&raw)?.unwrap_or(raw);
        if let Some((name, inline)) = numable_split(&a) {
            // main-conf.c:3236-3260 (`F_NUMABLE`): `--name=v`, `--name:v` или следующее слово, если оно целое или
            // логическое; иначе `--name` один значит «включить». `--noreset` и `--tcp-sackok` сюда не входят: в C
            // это одиночные `F_BOOL` (main-conf.c:2381, 2422, `is_singleton` :3083–3094), значение только через `=`,
            // следующее слово не забирается.
            let value = match inline {
                Some(v) => v.to_string(),
                None => match it.peek() {
                    Some(n) if is_integer(n) || is_boolean(n) => it.next().unwrap_or_default(),
                    _ => String::new(),
                },
            };
            out.push(format!("--{name}={value}"));
        } else if let Some(nic) = indexed_nic_key(&a) {
            // main-conf.c:3294-3326, 882-890: `--имя[i]` берёт значение из `=`, `:` или следующего слова.
            let (name, inline) = nic?;
            let value = match inline {
                Some(v) => v.to_string(),
                None => it
                    .next()
                    .ok_or_else(|| format!("{name}: empty parameter"))?,
            };
            out.push(format!("--rmasscan-nic={name}={value}"));
        } else if a.starts_with("-6") {
            // main-conf.c:3321-3324 (`case '6'` on `argv[i][1]`): "Silently ignore this: IPv6 features enabled
            // all the time". Тоже для `-6x`: C смотрит только вторую букву.
        } else if a == "-sL" {
            out.push("--list".into());
        } else if let Some(t @ ("S" | "U" | "Z")) = a.strip_prefix("-s") {
            // main-conf.c:3524-3549: `-sS`, `-sU`, `-sZ` (ровно одна буква) выбирают типы скана.
            out.push(format!("--rmasscan-scan={t}"));
        } else if a == "-iL" {
            // main-conf.c:3375-3377: nmap-стиль `-iL FILE` это `includefile`; clap прочёл бы его как `-i L`.
            out.push("--includefile".into());
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

/// Таблица `EQUALS` (`src/main-conf.c:833-849`): ключ [`normalize_key`] каждого длинного имени и синонима clap (вместе
/// с `--help` и `--version`) и длинное имя его опции. Внутренние опции `--rmasscan-…`, которые пишет сам
/// [`preprocess_args`], в неё не входят: скрытая опция, которую пользователь набирать не должен, обязана начинаться с
/// `rmasscan-`. Совпадение двух имён после нормализации одно, `nocapture`/`no-capture`, и это одна опция (как у C,
/// `:2403`); тест `equals_table_has_one_option_per_key` держит это для всей таблицы.
struct EqualsTable(HashMap<String, String>);

impl EqualsTable {
    fn long_of(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
}

/// [`EqualsTable`] из `Cli::command()`, строится один раз на процесс.
fn equals_table() -> &'static EqualsTable {
    static TABLE: std::sync::OnceLock<EqualsTable> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut cmd = Cli::command();
        // `--help` и `--version` clap добавляет при сборке команды (C: `EQUALS("help", …)`, :3225).
        cmd.build();
        let mut by_key = HashMap::new();
        for arg in cmd.get_arguments() {
            let Some(long) = arg.get_long() else { continue };
            if long.starts_with("rmasscan-") {
                continue;
            }
            for name in std::iter::once(long).chain(arg.get_all_aliases().unwrap_or_default()) {
                by_key.insert(normalize_key(name), long.to_string());
            }
        }
        EqualsTable(by_key)
    })
}

/// Имя с индексным смыслом: индекс `[i]` читает его собственный разбор. Сегодня это ключи массива адаптеров
/// ([`NIC_KEYS`], `src/main-conf.c:882-890`).
fn has_index_meaning(key: &str) -> bool {
    NIC_KEYS.contains(&key)
}

/// Р17: имя `--опции` сравнивается как `EQUALS` C (`src/main-conf.c:833-849`: регистр и `-`, `.`, `_` не важны) и
/// переписывается в длинное имя clap. Значение идёт после первого `=`, иначе после первого `:` (`masscan_command_line`,
/// :3279-3289) и остаётся как есть, `:` становится `=`. Закрытый суффикс `[…]` у имени без индексного смысла
/// отбрасывается, как у C (`EQUALS` истинно на `[`, :840-841); имя с индексным смыслом остаётся своему разбору
/// ([`indexed_nic_key`]). Индекс от 65536 это `bad index` C у любого имени ([`check_c_index`], :2437-2441). Незакрытая
/// `[` это ошибка у любого имени (Р17, «непарный индекс»; у C индекс читает `parseInt`, `ARRAY` :881-890). `None`: не
/// `--опция`, ключ адаптера с индексом или имени нет в таблице (тогда его отклонит clap, как C отклоняет неизвестное
/// имя, :3036).
fn equals_option(a: &str) -> Result<Option<String>, String> {
    let Some(rest) = a.strip_prefix("--") else {
        return Ok(None);
    };
    let (name, value) = match rest.find('=').or_else(|| rest.find(':')) {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };
    let key = normalize_key(name);
    if let Some(open) = name.find('[') {
        check_c_index(name)?;
        if !name[open..].contains(']') {
            return Err(format!("--{name}: unclosed '[' in the option name"));
        }
        if has_index_meaning(&key) {
            return Ok(None);
        }
    }
    let Some(long) = equals_table().long_of(&key) else {
        return Ok(None);
    };
    Ok(Some(match value {
        Some(v) => format!("--{long}={v}"),
        None => format!("--{long}"),
    }))
}

/// Код выхода ошибки clap: справка и версия 0, любая ошибка разбора 1, как `exit(1)` C на неизвестное имя
/// (`src/main-conf.c:3036`), а не 2 clap. C печатает справку и версию с кодом 1 (:3225-3227, :3010-3012); здесь
/// `--help` и `--version` это успех.
pub fn clap_exit_code(kind: clap::error::ErrorKind) -> u8 {
    use clap::error::ErrorKind;
    match kind {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
        _ => 1,
    }
}

/// Ключи, которые C хранит в `nic[i]` (`masscan_set_parameter`, main-conf.c:2470-2641), в нормализованном виде.
const NIC_KEYS: [&str; 27] = [
    "adapter",
    "if",
    "interface",
    "adapterip",
    "sourceip",
    "sourceaddress",
    "spoofip",
    "spoofaddress",
    "srcip",
    "adapterport",
    "sourceport",
    "srcport",
    "adaptermac",
    "spoofmac",
    "sourcemac",
    "srcmac",
    "routermac",
    "router",
    "destmac",
    "destinationmac",
    "dstmac",
    "targetmac",
    "routermacipv4",
    "routeripv4",
    "routermacipv6",
    "routeripv6",
    "routerip",
];

/// `--имя[i]`, `--имя[i]=v` или `--имя[i]:v` для ключа массива адаптеров: имя с индексом и встроенное значение.
/// Скобку другого ключа уже отбросил [`equals_option`], незакрытую он отклонил; `None`, если аргумент не такой.
fn indexed_nic_key(a: &str) -> Option<Result<(&str, Option<&str>), String>> {
    let rest = a.strip_prefix("--")?;
    let open = rest.find('[')?;
    if !NIC_KEYS.contains(&normalize_key(&rest[..open]).as_str()) {
        return None;
    }
    // Как в C: сначала `=`, затем `:` (после скобки, чтобы индекс не мешал).
    let close = rest[open..].find(']').map_or(open, |i| open + i);
    let tail = &rest[close..];
    let cut = tail.find('=').or_else(|| tail.find(':')).map(|i| close + i);
    Some(Ok(match cut {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    }))
}

/// `--hello-string`, `--hello-file` (`hello-filename`) и любое написание `--http-header`/`--http-field` по
/// `EQUALS`, до [`equals_option`]: набранное имя целиком (со скобками) и встроенное значение для скрытой опции
/// `--rmasscan-…`. Разделитель значения тот же, что у всякого имени ([`equals_option`]): первое `=`, иначе первое
/// `:` (`masscan_command_line`, :3279-3289), поэтому двоеточие внутри скобок режет набранное имя, как у C.
/// Индекс от 65536 и незакрытая `[` в набранном имени отказывают как у всякого имени ([`check_c_index`], Р17,
/// `bad index` раньше незакрытой). `None`, если аргумент не такой.
/// Результат [`banner_typed_option`]: скрытая опция, набранное имя и встроенное значение.
struct TypedBannerOption {
    hidden: &'static str,
    typed: String,
    inline: Option<String>,
}

fn banner_typed_option(a: &str) -> Option<Result<TypedBannerOption, String>> {
    let rest = a.strip_prefix("--")?;
    let base_end = rest.find(['[', '=', ':']).unwrap_or(rest.len());
    let hidden = match normalize_key(&rest[..base_end]).as_str() {
        "hellostring" => "rmasscan-hello-string",
        "hellofile" | "hellofilename" => "rmasscan-hello-file",
        "httpheader" | "httpfield" => "rmasscan-http-header",
        _ => return None,
    };
    let split = || -> Result<(&str, Option<&str>), String> {
        let (typed, inline) = match rest.find('=').or_else(|| rest.find(':')) {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };
        if let Some(open) = typed.find('[') {
            check_c_index(typed)?;
            if !typed[open..].contains(']') {
                return Err(format!("--{typed}: unclosed '[' in the option name"));
            }
        }
        Ok((typed, inline))
    };
    Some(split().map(|(typed, inline)| TypedBannerOption {
        hidden,
        typed: typed.to_string(),
        inline: inline.map(std::string::ToString::to_string),
    }))
}

/// `SET_topports` (main-conf.c:2107-2139): пусто значит 20, логическое значение включает (`1`, `true`, `on`) или
/// выключает (`0`, `off`) вместо числа, целое это число, остальное ошибка. `isBoolean` стоит раньше `isInteger`,
/// поэтому `--top-ports 1` значит 20.
fn top_ports_count(v: &str) -> Result<u32, String> {
    const DEFAULT: u32 = 20;
    if v.is_empty() {
        Ok(DEFAULT)
    } else if is_boolean(v) {
        Ok(if parse_boolean(v) { DEFAULT } else { 0 })
    } else if is_integer(v) {
        // C: `(unsigned)parseInt(...)`: старшие 32 бита отбрасываются, поэтому число считаем по модулю 2^32.
        Ok(v.bytes().fold(0u32, |n, d| {
            n.wrapping_mul(10).wrapping_add(u32::from(d - b'0'))
        }))
    } else {
        Err(format!("top-ports: bad value: {v}"))
    }
}

/// Опции с необязательным числовым или логическим значением (`F_NUMABLE`, main-conf.c:2419-2421).
const NUMABLE: [&str; 4] = ["tcp-mss", "tcp-wscale", "tcp-tsecho", "top-ports"];

/// `--имя` или `--имя=v` для имён из [`NUMABLE`]: имя и встроенное значение. Имя уже каноническое: синонимы C
/// `tcpmss` (main-conf.c:2419, тот же ключ `normalize_key`, что у `tcp-mss`) и `top-port` (:2423, синоним clap) и любое
/// написание переписал [`equals_option`], `:` тоже.
fn numable_split(a: &str) -> Option<(&'static str, Option<&str>)> {
    let rest = a.strip_prefix("--")?;
    let (name, inline) = match rest.find(['=', ':']) {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };
    NUMABLE.iter().find(|n| **n == name).map(|n| (*n, inline))
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
        // `main-conf.c:1701`: буквы `-o` у certs нет; баннеры печатаются PEM в stdout (`src/out-certs.c`).
        "certs" => Format::Certs,
        "redis" => return Err(REDIS_REFUSAL.into()),
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
        // `src/main-conf.c:2688-2696`: неизвестное имя это выход с кодом 1 прямо при разборе.
        for name in &cli.banner_types {
            banner_app(name).map_err(ParseError::Masscan)?;
        }
        cli.show_steps = show_steps(&m);
        (cli.style, cli.style_sets_xml) = fold_stylesheet(&m);
        if cli.resume.len() > 1 {
            return Err(ParseError::Masscan(
                "--resume may be given only once".to_string(),
            ));
        }
        // Файлы конфигурации: `-c`/`--conf`/`--config` и `--resume` применяются в своей позиции `argv`.
        for (id, kind) in [("conf", "conf"), ("resume", "resume")] {
            if let (Some(values), Some(indices)) = (m.get_many::<String>(id), m.indices_of(id)) {
                cli.markers
                    .extend(indices.zip(values).map(|(pos, path)| FileMarker {
                        pos,
                        kind,
                        path: path.clone(),
                    }));
            }
        }
        cli.markers.sort_by_key(|mk| mk.pos);
        if let (Some(values), Some(indices)) =
            (m.get_many::<String>("nic_kv"), m.indices_of("nic_kv"))
        {
            cli.nic_pos = indices.zip(values.cloned()).collect();
        }
        for (id, make) in [
            (
                "ports",
                (|s: String| PortEvent::Ports(s)) as fn(String) -> PortEvent,
            ),
            ("udp_ports", |s| PortEvent::UdpPorts(s)),
            ("scan_types", |s| {
                PortEvent::Scan(s.chars().next().unwrap_or('S'))
            }),
        ] {
            if let (Some(values), Some(indices)) = (m.get_many::<String>(id), m.indices_of(id)) {
                cli.port_events
                    .extend(indices.zip(values).map(|(pos, v)| (pos, make(v.clone()))));
            }
        }
        cli.port_events.sort_by_key(|(pos, _)| *pos);
        for (id, key) in BANNER_KEYS {
            if let (Some(values), Some(indices)) = (m.get_many::<String>(id), m.indices_of(id)) {
                cli.banner_steps.extend(
                    indices
                        .zip(values)
                        .map(|(pos, v)| (pos, BannerStep::Kv(key, v.clone()))),
                );
            }
        }
        // Скрытые опции с набранным именем (`preprocess_args` пишет `имя=значение` одним словом).
        for (id, make) in [
            (
                "hello_string_kv",
                BannerStep::HelloString as fn(String, String) -> BannerStep,
            ),
            ("hello_file_kv", BannerStep::HelloFile),
            ("http_header_kv", BannerStep::HttpHeader),
        ] {
            if let (Some(values), Some(indices)) = (m.get_many::<String>(id), m.indices_of(id)) {
                cli.banner_steps
                    .extend(indices.zip(values).map(|(pos, kv)| {
                        let (name, value) = kv.split_once('=').unwrap_or((kv, ""));
                        (pos, make(name.to_string(), value.to_string()))
                    }));
            }
        }
        cli.banner_steps.sort_by_key(|(pos, _)| *pos);
        let last = |id: &str| m.indices_of(id).and_then(Iterator::max);
        cli.key_pos = POSITIONAL_KEYS
            .iter()
            .filter_map(|id| last(id).map(|p| (*id, p)))
            .collect();
        // `Count` без вхождений хранит значение по умолчанию, поэтому сначала счётчик (см. `fold_stylesheet`).
        let counted = |id: &str| !matches!(id, "webxml" | "no_stylesheet") || m.get_count(id) > 0;
        cli.output_pos = OUTPUT_GROUPS
            .iter()
            .filter_map(|(group, ids)| {
                ids.iter()
                    .filter(|id| counted(id))
                    .filter_map(|id| last(id))
                    .max()
                    .map(|p| (*group, p))
            })
            .collect();
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

    /// Последнее `--ndjson-status[=<val>]` командной строки (без файлов конфигурации).
    fn ndjson_status_flag(&self) -> bool {
        self.ndjson_status.last().is_some_and(|v| parse_boolean(v))
    }

    /// Режим строки статуса: `is_status_updates` (по умолчанию 1; `--status`/`--nostatus`) и `is_status_ndjson`
    /// (по умолчанию 0; `--ndjson-status[=<val>]` и ключ `ndjson-status` файлов `-c`/`--resume` в порядке argv,
    /// [`FullConf::ndjson_status`]) независимы, как в C (`main.c:1399, 1434-1437, 1499-1503`, `main-conf.c:2842-2845`,
    /// `:1507-1517`): выключено, если нет обновлений, иначе NDJSON, если он включён. Если файл не читается, остаётся
    /// флаг командной строки (`run` к этому времени уже отказал с ошибкой файла).
    pub fn status_mode(&self) -> StatusMode {
        let ndjson = self
            .resolve()
            .map_or_else(|_| self.ndjson_status_flag(), |full| full.ndjson_status);
        if self.nostatus {
            StatusMode::Off
        } else if ndjson {
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

    /// Конфигурация с учётом файлов `-c`/`--conf`/`--config` и `--resume <file>` (`conf = <file>`, `resume = <file>`,
    /// main-conf.c:2472-2473, 2926-2928): ключи применяются в порядке `argv`, то есть ключ правее файла переопределяет
    /// его, левее переопределяется им (`masscan_set_parameter` зовётся по ходу разбора). Файл приносит свой вывод,
    /// `pcap-filename` и `ndjson-status`. Без файлов это обычный `to_config` с пустым [`FullConf::output`].
    pub fn resolve(&self) -> Result<FullConf, String> {
        self.resolved
            .get_or_init(|| self.resolve_uncached())
            .clone()
    }

    fn resolve_uncached(&self) -> Result<FullConf, String> {
        let mut full = FullConf::default();
        let mut loader = |p: &Path| std::fs::read_to_string(p).map_err(|e| e.to_string());
        // Сегмент `s` это ключи между `s`-м и `s+1`-м файлом: ключ входит в сегмент, левее которого лежит ровно
        // `s` файлов.
        for seg in 0..=self.markers.len() {
            self.apply_scan_fields(&mut full.scan, seg)?;
            if self.in_segment("pcap", seg) {
                full.pcap_filename.clone_from(&self.pcap);
            }
            // T2 M-5: `--ndjson-status[=<val>]` тоже ключ по позиции: файл правее флага его переопределяет, флаг правее
            // файла переопределяет файл (`SET_status_ndjson`, main-conf.c:1507-1517, зовётся по ходу разбора).
            if self.in_segment("ndjson_status", seg) {
                full.ndjson_status = self.ndjson_status_flag();
            }
            if let Some(mk) = self.markers.get(seg) {
                full.output.touched.clear();
                full.port_default = self.port_default_at(mk.pos);
                apply_conf_key(mk.kind, &mk.path, &mut full, &mut loader, 0)?;
                for group in std::mem::take(&mut full.output.touched) {
                    full.output.file_pos.insert(group, mk.pos);
                }
            }
        }
        self.apply_top_ports(&mut full.scan)?;
        Ok(full)
    }

    /// Сколько файлов конфигурации стоит левее позиции clap `pos`.
    fn segment_of(&self, pos: usize) -> usize {
        self.markers.iter().filter(|mk| mk.pos < pos).count()
    }

    /// Лежит ли последнее появление ключа `id` в сегменте `seg` (ключа нет: нет).
    fn in_segment(&self, id: &str, seg: usize) -> bool {
        self.key_pos
            .get(id)
            .is_some_and(|&pos| self.segment_of(pos) == seg)
    }

    /// Префикс по умолчанию портов файла конфигурации в позиции clap `pos`: C разбирает файл на его месте в `argv`,
    /// поэтому строка `ports = …` файла берёт тип скана от `-sU`/`-sZ`/`--udp-ports` левее файла (main-conf.c:2663–2674,
    /// `--udp-ports` ставит `scan_type.udp`, :2642–2648).
    fn port_default_at(&self, pos: usize) -> u32 {
        let (mut udp, mut sctp) = (false, false);
        for (_, ev) in self.port_events.iter().take_while(|(p, _)| *p < pos) {
            match ev {
                PortEvent::Scan('U') | PortEvent::UdpPorts(_) => udp = true,
                PortEvent::Scan('S') | PortEvent::Ports(_) => {}
                PortEvent::Scan(_) => sctp = true,
            }
        }
        port_default(udp, sctp)
    }

    /// Порты, `--udp-ports`, `--ping` и `-sS/-sU/-sZ` в порядке `argv`, как `masscan_set_parameter`
    /// (main-conf.c:2642-2681, 2721-2729, 3524-3549): `-p` берёт префикс по умолчанию от `-sU`/`-sZ` левее него.
    /// Таблицы `--top-ports` строит [`Cli::apply_top_ports`] после всех файлов конфигурации.
    fn apply_port_options(&self, cfg: &mut ScanConfig) -> Result<(), String> {
        let (mut udp, mut sctp) = (false, false);
        for (_, ev) in &self.port_events {
            match ev {
                PortEvent::Scan('S') => {}
                PortEvent::Scan('U') => udp = true,
                PortEvent::Scan(_) => sctp = true,
                PortEvent::Ports(p) => {
                    parse_ports_with(cfg.targets.ports_mut(), p, port_default(udp, sctp))
                        .map_err(|e| format!("bad ports {p:?}: {e}"))?;
                }
                PortEvent::UdpPorts(p) => {
                    udp = true;
                    parse_ports_with(cfg.targets.ports_mut(), p, TEMPL_UDP)
                        .map_err(|e| format!("bad --udp-ports {p:?}: {e}"))?;
                }
            }
        }
        // `SET_arpscan` кладёт порт, `router-mac` и флаг через тот же ключ, что `arpscan = ...` в файле (`apply_core_kv`).
        if self.arp {
            apply_core_kv(cfg, "arpscan", "").map_err(|e| e.to_string())?;
        }
        if self.ping {
            cfg.targets
                .ports_mut()
                .add_range(TEMPL_ICMP_ECHO, TEMPL_ICMP_ECHO);
        }
        Ok(())
    }

    /// Таблицы `--top-ports` в конце разбора по итоговым типам скана (main-conf.c:3609-3619), то есть после всех
    /// файлов конфигурации: ARP-скан, заданный файлом (`arpscan =`), тоже снимает TCP по умолчанию.
    fn apply_top_ports(&self, cfg: &mut ScanConfig) -> Result<(), String> {
        let (mut tcp, mut udp, mut sctp) = (false, false, false);
        for (_, ev) in &self.port_events {
            match ev {
                PortEvent::Scan('S') => tcp = true,
                PortEvent::Scan('U') | PortEvent::UdpPorts(_) => udp = true,
                PortEvent::Scan(_) => sctp = true,
                PortEvent::Ports(_) => {}
            }
        }
        // main-conf.c:3609-3612: без UDP, SCTP, ping, ARP и oproto по умолчанию TCP. `scan_type.arp` ставит только
        // `SET_arpscan` (`--arp`, `--arpscan`, `arpscan =` в файле; `cfg.arpscan`), не `-pI:2`. oproto у rmasscan не
        // задаётся ничем: нет ни `-sO`, ни ключа `oprotos` (main-conf.c:2649-2655, :3524), а `-pO:` его у C не ставит.
        if !udp && !sctp && !self.ping && !cfg.arpscan {
            tcp = true;
        }
        if let Some(v) = self.top_ports.last() {
            let n = top_ports_count(v)?;
            if n != 0 {
                add_top_ports(cfg.targets.ports_mut(), n, tcp, udp);
            }
        }
        Ok(())
    }

    /// Применяет поля командной строки сегмента `seg` к `cfg`. Сегмент 0 несёт и цели, исключения и файлы целей
    /// (порядок их добавления значения не имеет). Ключи адаптера идут и в одиночные поля, и в `nics[0]`, если файл
    /// уже создал массив адаптеров (`apply_core_kv` держит их равными).
    fn apply_scan_fields(&self, cfg: &mut ScanConfig, seg: usize) -> Result<(), String> {
        let take = |id: &'static str| self.in_segment(id, seg);
        if seg == 0 {
            for t in self.targets.iter().chain(&self.range) {
                // massip.c:72-100: IPv4 и IPv6.
                cfg.targets
                    .add_target_string(t)
                    .map_err(|e| format!("bad target {t:?}: {e}"))?;
            }
            self.apply_port_options(cfg)?;
            for x in &self.exclude {
                cfg.excludes
                    .add_target_string(x)
                    .map_err(|e| format!("bad --exclude {x:?}: {e}"))?;
            }
            for f in &self.excludefile {
                read_exclude_file(cfg, f)?;
            }
            for f in &self.includefile {
                read_include_file(cfg, f)?;
            }
            // Набор, а не значение: файл левее или правее его только дополняет (`rangelist_add_range`).
            for name in &self.banner_types {
                cfg.banner_types.insert(banner_app(name)?);
            }
        }
        // `--offline`/`--infinite` по порядку `argv`: файл левее/правее включает или отключает их (M-2).
        if take("offline") && self.offline {
            cfg.offline = true;
        }
        if take("infinite") && self.infinite {
            cfg.infinite = true;
        }
        // seed == 0 в C значит "взять энтропию" (main.c:1640-1641). Явный 0
        // отклоняется; отсутствие --seed решает `run` по операции (см.
        // [`seed_policy`]), здесь это seed 0.
        // Файлы нагрузок читает `prepare` (слой живого скана); здесь только имена, правее файла побеждает аргумент.
        if take("nmap_payloads")
            && let Some(f) = &self.nmap_payloads
        {
            cfg.nmap_payloads = Some(f.clone());
        }
        if take("pcap_payloads")
            && let Some(f) = &self.pcap_payloads
        {
            cfg.pcap_payloads = Some(f.clone());
        }
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
        // `masscan_set_parameter` общий у argv и файла: тот же разбор, что у ключа `wait = …` (`forever` включительно).
        if take("wait")
            && let Some(w) = &self.wait
        {
            apply_core_kv(cfg, "wait", w).map_err(|e| e.to_string())?;
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
        // Ключи адаптера: одиночные опции и `--adapter[i]` и т.п. идут по порядку `argv` внутри сегмента (C зовёт
        // `masscan_set_parameter` по ходу разбора). Все они держат одиночные поля и `nics[0]` равными.
        let mut nic_steps: Vec<(usize, NicStep<'_>)> = NIC_PLAIN
            .iter()
            .filter(|id| take(id))
            .filter_map(|id| self.key_pos.get(id).map(|&p| (p, NicStep::Plain(id))))
            .collect();
        nic_steps.extend(
            self.nic_pos
                .iter()
                .filter(|(pos, _)| self.segment_of(*pos) == seg)
                .map(|(pos, kv)| (*pos, NicStep::Indexed(kv))),
        );
        nic_steps.sort_by_key(|(pos, _)| *pos);
        for (_, step) in nic_steps {
            match step {
                NicStep::Plain(id) => self.apply_nic_plain(cfg, id)?,
                NicStep::Indexed(kv) => {
                    let (name, value) = kv.split_once('=').unwrap_or((kv, ""));
                    if !apply_core_kv(cfg, name, value).map_err(|e| format!("{name}: {e}"))? {
                        return Err(format!("unknown adapter option {name:?}"));
                    }
                }
            }
        }
        // Р9: параметры зонда. Ключи ядра сами проверяют значения (`--ttl 0`, `--tcp-mss 70000` отклоняются).
        if take("ttl")
            && let Some(t) = &self.ttl
        {
            apply_core_kv(cfg, "ttl", t).map_err(|e| e.to_string())?;
        }
        if take("badsum") && self.badsum {
            cfg.badsum = true;
        }
        // Опции баннеров (`src/main-conf.c:1106-1505`, :1546-1554, :2765-2767) по порядку argv внутри сегмента.
        for (pos, step) in &self.banner_steps {
            if self.segment_of(*pos) != seg {
                continue;
            }
            match step {
                BannerStep::Kv(key, value) => {
                    apply_core_kv(cfg, key, value).map_err(|e| e.to_string())?;
                }
                BannerStep::HelloString(name, value) | BannerStep::HttpHeader(name, value) => {
                    if !apply_core_kv(cfg, name, value).map_err(|e| e.to_string())? {
                        return Err(format!("unknown banner option {name:?}"));
                    }
                }
                BannerStep::HelloFile(name, file) => {
                    crate::banner_settings::apply_hello_file(cfg, name, file)?;
                }
            }
        }
        for (id, key, values) in [
            ("noreset", "noreset", &self.noreset),
            ("tcp_mss", "tcp-mss", &self.tcp_mss),
            ("tcp_sackok", "tcp-sackok", &self.tcp_sackok),
            ("tcp_wscale", "tcp-wscale", &self.tcp_wscale),
            ("tcp_tsecho", "tcp-tsecho", &self.tcp_tsecho),
        ] {
            if take(id) {
                for v in values {
                    apply_core_kv(cfg, key, v).map_err(|e| e.to_string())?;
                }
            }
        }
        Ok(())
    }

    /// Одиночная опция адаптера `id` в `nic[0]` и одиночные поля (`--adapter-ip`, `--adapter-mac`, `--router-ip`,
    /// `--router-mac`, `--source-port`, `--interface`).
    fn apply_nic_plain(&self, cfg: &mut ScanConfig, id: &str) -> Result<(), String> {
        match id {
            "adapter_ip" => {
                let Some(ip) = &self.adapter_ip else {
                    return Ok(());
                };
                let bad = || {
                    format!(
                        "bad --adapter-ip {ip:?}: expected an IPv4 address or a range A-B of a power-of-two width, or an IPv6 address"
                    )
                };
                if ip.contains(':') {
                    // main-conf.c:2508-2512: адрес IPv6 источника живёт только в `nics[0]` (ключ его заводит).
                    apply_core_kv(cfg, "adapter-ip", ip).map_err(|_| bad())?;
                    return Ok(());
                }
                let r = range_parse_ipv4(ip).map_err(|_| bad())?;
                if r.begin == r.end {
                    cfg.adapter_ip = Some(r.begin);
                    set_nic0(cfg, |n| n.adapter_ip = Some((r.begin, r.begin)));
                } else {
                    // Диапазон хранится только в `nics[0]` (одиночное поле держит первый адрес); ключ
                    // конфигурации проверяет степень двойки (main-conf.c:2483) и заводит `nic[0]`.
                    apply_core_kv(cfg, "adapter-ip", ip).map_err(|_| bad())?;
                }
            }
            "adapter_mac" => {
                let Some(m) = &self.adapter_mac else {
                    return Ok(());
                };
                let mac = parse_mac(m).map_err(|e| e.to_string())?;
                cfg.adapter_mac = Some(mac);
                set_nic0(cfg, |n| n.adapter_mac = Some(mac));
            }
            "router_ip" => {
                let Some(ip) = &self.router_ip else {
                    return Ok(());
                };
                if ip.contains(':') {
                    // Следующий хоп IPv6 для NDP (R11) живёт только в `nics[0]`.
                    apply_core_kv(cfg, "router-ip", ip).map_err(|_| {
                        format!("bad --router-ip {ip:?}: expected one IPv4 or IPv6 address")
                    })?;
                    return Ok(());
                }
                let ip: Ipv4Addr = ip.parse().map_err(|_| {
                    format!("bad --router-ip {ip:?}: expected one IPv4 or IPv6 address")
                })?;
                let ip = u32::from(ip);
                cfg.router_ip = Some(ip);
                set_nic0(cfg, |n| n.router_ip = Some(ip));
            }
            "router_mac" => {
                let Some(m) = &self.router_mac else {
                    return Ok(());
                };
                let mac = parse_mac(m).map_err(|e| e.to_string())?;
                cfg.router_mac = Some(mac);
                set_nic0(cfg, |n| {
                    (n.router_mac_ipv4, n.router_mac_ipv6) = (Some(mac), Some(mac));
                });
            }
            "router_mac_ipv4" => {
                let Some(m) = &self.router_mac_ipv4 else {
                    return Ok(());
                };
                // Ключ C `router-mac-ipv4` (main-conf.c:2602-2612): MAC шлюза IPv4 в `nics[0]`, IPv6 не трогается.
                parse_mac(m).map_err(|e| e.to_string())?;
                apply_core_kv(cfg, "router-mac-ipv4", m).map_err(|e| e.to_string())?;
            }
            "router_mac_ipv6" => {
                let Some(m) = &self.router_mac_ipv6 else {
                    return Ok(());
                };
                // Ключ C `router-mac-ipv6` (main-conf.c:2614-2624): MAC шлюза IPv6 в `nics[0]`, IPv4 не трогается.
                parse_mac(m).map_err(|e| e.to_string())?;
                apply_core_kv(cfg, "router-mac-ipv6", m).map_err(|e| e.to_string())?;
            }
            "source_port" => {
                let Some(p) = &self.source_port else {
                    return Ok(());
                };
                let ports = parse_source_port(p).map_err(|e| e.to_string())?;
                cfg.source_port = Some(ports);
                // Явный диапазон степени двойки снимает причуду C в 17 портов, пришедшую из файла (флаг у адаптера).
                set_nic0(cfg, |n| {
                    n.source_port = Some(ports);
                    n.legacy_c_17_port_mask = false;
                });
            }
            "interface" => {
                let Some(name) = &self.interface else {
                    return Ok(());
                };
                cfg.adapter_name = Some(name.clone());
                set_nic0(cfg, |n| n.adapter_name = Some(name.clone()));
            }
            _ => {}
        }
        Ok(())
    }

    /// Опции вывода с учётом файлов конфигурации: поля файла (`output-filename`, `output-format`, ...) служат базой, а
    /// опции вывода правее файла, который их задал, его переопределяют, левее переопределяются файлом;
    /// `output-append` после `--resume` принудительно истина (main-conf.c:2926-2928). Без файлов совпадает с
    /// [`Cli::output_options`].
    pub fn resolved_output_options(&self) -> Result<OutputOptions, String> {
        let mut o = self.output_options()?;
        if self.markers.is_empty() {
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

/// Опции вывода по позиции относительно файлов конфигурации (main-conf.c:3401-3457, 2926-2928: и `-o…`, и ключи
/// файла применяются в порядке argv): опция правее файла, который задал этот ключ, побеждает файл; опция левее
/// переопределяется файлом. `output-append`, заданный `--resume`, истина, пока правее нет явного `--append-output`.
fn merge_file_output(o: &mut OutputOptions, file: &OutputConfPatch, cli: &Cli) {
    let right = |g: &str| {
        cli.output_pos
            .get(g)
            .is_some_and(|&p| file.file_pos.get(g).is_none_or(|&fp| p > fp))
    };
    if !right("format")
        && let Some(f) = file.format
    {
        o.format = f;
    }
    if !right("filename") && file.filename.is_some() {
        o.filename.clone_from(&file.filename);
    }
    if !right("append")
        && let Some(v) = file.append
    {
        o.append = v;
    }
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
/// `-iL FILE` / `--includefile FILE` (`massip_parse_file`, main-conf.c:2825-2836): грамматика C в
/// [`crate::conf::parse_include_text`].
fn read_include_file(cfg: &mut ScanConfig, path: &str) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    crate::conf::parse_include_text(&bytes, path, cfg.targets.ipv4_mut())
}

fn read_exclude_file(cfg: &mut ScanConfig, path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        cfg.excludes
            .add_target_string(line)
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
                    hostonly, unicornscan, certs, interactive, none";
        assert_eq!(masscan_err(&["--output-format", "nmap"]), want);
        // Каждое вхождение проверяется, даже перекрытое последним (Р6 при Р17).
        assert_eq!(masscan_err(&["--output-format", "nmap", "-oL", "x"]), want);
        assert_eq!(masscan_err(&["-oL", "x", "--output-format=nmap"]), want);
        assert_eq!(parse_format("nmap").unwrap_err(), want);
    }

    /// `--output-format certs` (`main-conf.c:1701`, буквы `-o` нет) принимается: баннеры печатаются PEM в stdout
    /// (`src/out-certs.c`).
    #[test]
    fn certs_format_is_accepted() {
        let o = opts(&["--output-format", "certs", "--output-filename", "c.out"]);
        assert_eq!(
            (o.format, o.filename.as_deref()),
            (Format::Certs, Some("c.out"))
        );
        assert_eq!(parse_format("certs"), Ok(Format::Certs));
        assert!(
            masscan_err(&["--output-format", "nmap"]).contains("unicornscan, certs, interactive")
        );
    }

    #[test]
    fn redis_and_rotate_are_refused() {
        for (a, name) in [
            (&["--output-format", "redis"][..], "--output-format redis"),
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
            // Имя по `EQUALS` (`src/main-conf.c:833-849`), как у прочих опций.
            "--Json_Status",
            "--STATUS.JSON=1",
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

    /// main-conf.c:3321-3324: `-6` (any single-dash word starting `-6`) is
    /// silently ignored, "IPv6 features enabled all the time".
    #[test]
    fn dash_six_is_a_silent_no_op() {
        let plain = parse(&["10.0.0.1", "-p80"]).unwrap();
        for six in ["-6", "-6x"] {
            let c = parse(&[six, "10.0.0.1", "-p80"]).unwrap();
            assert_eq!(c.targets, plain.targets, "{six}");
            assert_eq!(c.ports, plain.ports, "{six}");
            let c = parse(&["10.0.0.1", "-p80", six]).unwrap();
            assert_eq!(c.targets, plain.targets, "{six}");
        }
        assert_eq!(preprocess_args(["rmasscan", "-6"]).unwrap(), ["rmasscan"]);
    }

    #[test]
    fn router_ip_accepts_one_address_and_rejects_ranges() {
        let cfg = parse(&["--router-ip", "198.18.0.2"])
            .unwrap()
            .to_config()
            .unwrap();
        assert_eq!(cfg.router_ip, Some(0xc612_0002));
        for bad in [
            "198.18.0.0/24",
            "198.18.0.2-198.18.0.3",
            "x",
            "",
            "fe80::/64",
            "fe80::1-fe80::2",
        ] {
            let cli = parse(&["--router-ip", bad]).unwrap();
            let e = cli.to_config().unwrap_err();
            assert!(e.contains("--router-ip"), "{bad}: {e}");
        }
        assert_eq!(parse(&[]).unwrap().to_config().unwrap().router_ip, None);
        // T5: one IPv6 address is the IPv6 next hop for NDP, kept in `nics[0]`; the IPv4 field stays unset.
        let cfg = parse(&["--router-ip", "fe80::1"])
            .unwrap()
            .to_config()
            .unwrap();
        assert_eq!(cfg.router_ip, None);
        assert_eq!(cfg.nics[0].router_ipv6, Some(0xfe80 << 112 | 1));
    }

    /// T5: `--router-mac-ipv6` (alias `--router-ipv6`, both MACs as in C main-conf.c:2614-2624) sets only the IPv6
    /// router MAC; `--router-mac` sets both (main-conf.c:2599-2600); `--adapter-ip <IPv6>` is the IPv6 source.
    #[test]
    fn router_mac_ipv6_and_ipv6_adapter_ip_options() {
        for opt in ["--router-mac-ipv6", "--router-ipv6"] {
            let cfg = parse(&[opt, "02-00-00-00-00-06"])
                .unwrap()
                .to_config()
                .unwrap();
            assert_eq!(cfg.router_mac, None, "{opt}");
            assert_eq!(
                cfg.nics[0].router_mac_ipv6,
                Some([2, 0, 0, 0, 0, 6]),
                "{opt}"
            );
            assert_eq!(cfg.nics[0].router_mac_ipv4, None, "{opt}");
        }
        let cfg = parse(&[
            "--router-mac",
            "02-00-00-00-00-04",
            "--router-mac-ipv6",
            "02-00-00-00-00-06",
        ])
        .unwrap()
        .to_config()
        .unwrap();
        assert_eq!(cfg.router_mac, Some([2, 0, 0, 0, 0, 4]));
        assert_eq!(cfg.nics[0].router_mac_ipv6, Some([2, 0, 0, 0, 0, 6]));
        assert!(
            parse(&["--router-mac-ipv6", "nope"])
                .unwrap()
                .to_config()
                .is_err()
        );
        let cfg = parse(&["--adapter-ip", "fd00::1"])
            .unwrap()
            .to_config()
            .unwrap();
        assert_eq!(cfg.adapter_ip, None);
        assert_eq!(
            cfg.nics[0].adapter_ipv6,
            Some((0xfd00 << 112 | 1, 0xfd00 << 112 | 1))
        );
        let e = parse(&["--adapter-ip", "fd00::zz"])
            .unwrap()
            .to_config()
            .unwrap_err();
        assert!(e.contains("--adapter-ip"), "{e}");
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
        assert!(!over.nics[0].legacy_c_17_port_mask);

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
        // Имя файла и таблица стилей формат не ставят: формат файла (json) остаётся (main-conf.c:1643, 2100, 2983).
        let o = parse(&["--resume", f, "--output-filename", "b.out"])
            .unwrap()
            .resolved_output_options()
            .unwrap();
        assert_eq!(
            (o.format, o.filename.as_deref()),
            (Format::Json, Some("b.out"))
        );
        let o = parse(&["--resume", f, "--webxml"])
            .unwrap()
            .resolved_output_options()
            .unwrap();
        assert_eq!(o.format, Format::Json);
        assert_eq!(o.stylesheet.as_deref(), Some(NMAP_XSL));
        let o = parse(&["--resume", f, "--no-stylesheet"])
            .unwrap()
            .resolved_output_options()
            .unwrap();
        assert_eq!(
            (o.format, o.filename.as_deref()),
            (Format::Json, Some("a.json"))
        );
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

    /// Р4, main-conf.c:3028-3032: `--wait` идёт через тот же разбор, что ключ `wait = …` файла (`masscan_set_parameter`
    /// общий у argv и файла): `forever` это `INT_MAX` секунд, иначе число; плохое значение это ошибка ключа `wait`.
    #[test]
    fn wait_forever_on_the_command_line_is_the_conf_key_value() {
        for args in [
            &["--wait", "forever"][..],
            &["--wait=forever"][..],
            &["--wait", "FOREVER"][..],
        ] {
            let cfg = parse(args).unwrap().to_config().unwrap();
            assert_eq!(cfg.wait_secs, i32::MAX as u32, "{args:?}");
        }
        let cfg = parse(&["--wait", "3"]).unwrap().to_config().unwrap();
        assert_eq!(cfg.wait_secs, 3);
        let e = parse(&["--wait", "soon"]).unwrap().to_config().unwrap_err();
        assert!(e.contains("wait") && e.contains("soon"), "{e}");
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("--wait <SECONDS|forever>"), "{help}");
    }

    /// T2 M-5: `ndjson-status` из файла `--resume`/`-c` применяется в позиции файла в argv, как любой ключ
    /// (`masscan_set_parameter` по ходу разбора): флаг правее файла его переопределяет, флаг левее переопределяется им.
    #[test]
    fn ndjson_status_from_a_resume_or_conf_file_is_applied_at_its_argv_position() {
        use crate::status::StatusMode::{Ndjson, Off, Text};
        let dir = crate::scratch::Scratch::new();
        let file = dir.write(
            "paused.conf",
            format!("{RESUME_FILE}ndjson-status = true\n").as_bytes(),
        );
        let f = file.to_str().unwrap();
        let mode = |a: &[&str]| {
            let cli = parse(a).unwrap();
            (cli.status_mode(), cli.resolve().unwrap().ndjson_status)
        };
        assert_eq!(mode(&["--resume", f]), (Ndjson, true));
        assert_eq!(mode(&["-c", f]), (Ndjson, true));
        assert_eq!(
            mode(&["--resume", f, "--ndjson-status=false"]),
            (Text, false)
        );
        assert_eq!(
            mode(&["--ndjson-status=false", "--resume", f]),
            (Ndjson, true)
        );
        // `--nostatus` гасит только строку статуса; `is_status_ndjson` остаётся и попадает в `paused.conf` (C пишет его
        // по `is_status_ndjson`, main-conf.c:1512-1513).
        assert_eq!(mode(&["--resume", f, "--nostatus"]), (Off, true));
        // Без файла всё как раньше.
        assert_eq!(mode(&["--ndjson-status"]), (Ndjson, true));
        assert_eq!(mode(&[]), (Text, false));
        let plain = dir.write("plain.conf", RESUME_FILE.as_bytes());
        let p = plain.to_str().unwrap();
        assert_eq!(mode(&["--resume", p]), (Text, false));
        assert_eq!(mode(&["--ndjson-status", "--resume", p]), (Ndjson, true));
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

    #[test]
    fn adapter_ip_range_is_kept_in_nic0_and_must_be_a_power_of_two_wide() {
        let cfg = parse(&["--adapter-ip", "198.18.0.16-198.18.0.19"])
            .unwrap()
            .to_config()
            .unwrap();
        assert_eq!(cfg.adapter_ip, Some(0xc612_0010), "single field = first");
        assert_eq!(cfg.nics[0].adapter_ip, Some((0xc612_0010, 0xc612_0013)));
        let cidr = parse(&["--source-ip", "198.18.0.16/30"])
            .unwrap()
            .to_config()
            .unwrap();
        assert_eq!(cidr.nics[0].adapter_ip, Some((0xc612_0010, 0xc612_0013)));
        let single = parse(&["--adapter-ip", "198.18.0.16"])
            .unwrap()
            .to_config()
            .unwrap();
        assert!(
            single.nics.is_empty(),
            "a single address keeps the old shape"
        );
        for bad in ["198.18.0.16-198.18.0.18", "198.18.0.19-198.18.0.16", "x"] {
            let e = parse(&["--adapter-ip", bad])
                .unwrap()
                .to_config()
                .unwrap_err();
            assert!(e.contains("--adapter-ip"), "{bad}: {e}");
        }
    }

    #[test]
    fn probe_parameter_flags_reach_the_config() {
        let cfg = parse(&[
            "10.0.0.1",
            "--ttl",
            "64",
            "--badsum",
            "--noreset",
            "--tcp-mss",
            "1400",
            "--tcp-sackok",
            "--tcp-wscale",
            "7",
            "--tcp-tsecho=3735928559",
        ])
        .unwrap()
        .to_config()
        .unwrap();
        assert_eq!(cfg.ttl, Some(64));
        assert!(cfg.badsum && cfg.noreset);
        assert_eq!(
            cfg.tcp_opts,
            rmasscan_core::packet::TcpHeaderOptions {
                mss: Some(1400),
                sackok: true,
                wscale: Some(7),
                tsecho: Some(0xdead_beef),
            }
        );
        // Без значения: включить с умолчанием; логическое значение выключает; цель после опции не съедается.
        let cli = parse(&[
            "--tcp-wscale",
            "--tcp-tsecho",
            "10.0.0.1",
            "--tcp-mss",
            "off",
        ])
        .unwrap();
        assert_eq!(cli.targets, ["10.0.0.1"]);
        let cfg = cli.to_config().unwrap();
        assert_eq!(cfg.tcp_opts.wscale, Some(3));
        assert_eq!(cfg.tcp_opts.tsecho, Some(0x1234_5678));
        assert_eq!(cfg.tcp_opts.mss, None);
        let d = parse(&["10.0.0.1"]).unwrap().to_config().unwrap();
        assert_eq!((d.ttl, d.badsum, d.noreset), (None, false, false));
        assert_eq!(
            d.tcp_opts,
            rmasscan_core::packet::TcpHeaderOptions::default()
        );
    }

    #[test]
    fn bad_probe_parameters_are_refused() {
        for a in [
            &["--ttl", "0"][..],
            &["--ttl", "256"][..],
            &["--ttl", "x"][..],
            &["--tcp-mss", "70000"][..],
            &["--tcp-wscale", "256"][..],
            &["--tcp-tsecho=4294967296"][..],
        ] {
            assert!(parse(a).unwrap().to_config().is_err(), "{a:?}");
        }
    }

    /// Ключи правее `--resume` переопределяют файл, левее файл (Р1): то же для параметров зонда.
    #[test]
    fn probe_parameters_follow_resume_positions() {
        let dir = crate::scratch::Scratch::new();
        let file = dir.write("paused.conf", format!("{RESUME_FILE}ttl = 40\n").as_bytes());
        let f = file.to_str().unwrap();
        let right = parse(&["--resume", f, "--ttl", "99"])
            .unwrap()
            .to_config()
            .unwrap();
        assert_eq!(right.ttl, Some(99));
        let left = parse(&["--ttl", "99", "--resume", f])
            .unwrap()
            .to_config()
            .unwrap();
        assert_eq!(left.ttl, Some(40));
        let bare = parse(&["--resume", f]).unwrap().to_config().unwrap();
        assert_eq!(bare.ttl, Some(40));
    }

    #[test]
    fn noreset_and_sackok_never_swallow_the_next_word() {
        // main-conf.c:2381, :2422 F_BOOL -> is_singleton (:3083): значение только через `=`.
        let cli = parse(&["--noreset", "198.18.0.5", "-p80"]).unwrap();
        assert_eq!(cli.targets, ["198.18.0.5"]);
        assert!(cli.to_config().unwrap().noreset);
        let cfg = parse(&["10.0.0.1", "--tcp-sackok=false"])
            .unwrap()
            .to_config()
            .unwrap();
        assert!(!cfg.tcp_opts.sackok);
        let cli = parse(&["--tcp-sackok", "10.0.0.1"]).unwrap();
        assert_eq!(cli.targets, ["10.0.0.1"]);
        assert!(cli.to_config().unwrap().tcp_opts.sackok);
        let cfg = parse(&["10.0.0.1", "--noreset=false"])
            .unwrap()
            .to_config()
            .unwrap();
        assert!(!cfg.noreset);
        // Синоним C `--tcpmss`.
        let cfg = parse(&["10.0.0.1", "--tcpmss", "1300"])
            .unwrap()
            .to_config()
            .unwrap();
        assert_eq!(cfg.tcp_opts.mss, Some(1300));
    }

    /// Файл конфигурации с адаптером, выводом и целями; `includefile` и `conf` внутри указывают на другие файлы.
    fn write_base(dir: &crate::scratch::Scratch) -> String {
        dir.write(
            "base.conf",
            b"# comment\nrate = 100\nseed = 5\nports = 80\nrange = 198.18.0.0/30\n\
adapter-ip = 198.18.0.9\noutput-filename = base.xml\n",
        )
        .to_str()
        .unwrap()
        .to_string()
    }

    /// Задача 7 (Р7, `main-conf.c:3332-3338, 3375-3377, 3868-3924`): `-c`/`--conf`/`--config` и `-iL`/`--includefile`
    /// разбираются в порядке `argv`. Ключ правее файла его переопределяет, левее переопределяется им (T2 I-1), для
    /// скана, адаптера и вывода; несколько `-c` идут по порядку; рекурсивный `conf = self` обрывается на глубине > 16.
    #[test]
    fn conf_and_includefile_respect_argv_order_and_detect_cycles() {
        let dir = crate::scratch::Scratch::new();
        let base = write_base(&dir);
        let targets = dir
            .write(
                "targets.txt",
                b"# extra targets\n203.0.113.0/30, 203.0.113.8\n",
            )
            .to_str()
            .unwrap()
            .to_string();

        // Правее файла: `--rate 900`, `--adapter-ip`, `-oL` побеждают; цели из `-iL` и файла складываются.
        let c = parse(&[
            "-c",
            &base,
            "--rate",
            "900",
            "-iL",
            &targets,
            "--adapter-ip",
            "198.18.0.50",
            "-oL",
            "x.list",
        ])
        .unwrap();
        let cfg = c.to_config().unwrap();
        assert_eq!(cfg.max_rate, 900.0);
        assert_eq!(cfg.seed, 5);
        assert_eq!(cfg.adapter_ip, Some(0xc612_0032));
        assert_eq!(
            cfg.targets.ipv4().len(),
            3,
            "198.18.0.0/30, 203.0.113.0/30, 203.0.113.8"
        );
        assert_eq!(
            c.resolved_output_options().unwrap().filename.as_deref(),
            Some("x.list")
        );

        // Левее файла: файл побеждает.
        let c = parse(&[
            "--rate",
            "900",
            "--adapter-ip",
            "198.18.0.50",
            "-oL",
            "x.list",
            "--config",
            &base,
        ])
        .unwrap();
        let cfg = c.to_config().unwrap();
        assert_eq!(cfg.max_rate, 100.0);
        assert_eq!(cfg.adapter_ip, Some(0xc612_0009));
        assert_eq!(cfg.nics[0].adapter_ip, Some((0xc612_0009, 0xc612_0009)));
        let o = c.resolved_output_options().unwrap();
        assert_eq!(o.filename.as_deref(), Some("base.xml"));
        assert!(
            !o.append,
            "-c does not force output-append (only --resume does)"
        );

        // Несколько файлов и ключи между ними: файл правее побеждает, а между файлами остаётся ключ, если следующий
        // файл его не задаёт.
        let a = dir
            .write("a.conf", b"rate = 1\nports = 22\n")
            .to_str()
            .unwrap()
            .to_string();
        let b = dir
            .write("b.conf", b"rate = 2\n")
            .to_str()
            .unwrap()
            .to_string();
        let n = dir
            .write("n.conf", b"retries = 1\n")
            .to_str()
            .unwrap()
            .to_string();
        let rate = |a: &[&str]| parse(a).unwrap().to_config().unwrap().max_rate;
        assert_eq!(rate(&["-c", &a, "-c", &b]), 2.0);
        assert_eq!(rate(&["-c", &b, "-c", &a]), 1.0);
        assert_eq!(rate(&["-c", &a, "--rate", "7", "-c", &b]), 2.0);
        assert_eq!(rate(&["-c", &a, "--rate", "7", "-c", &n]), 7.0);
        assert_eq!(rate(&["--rate", "7", "-c", &a, "-c", &n]), 1.0);
        // `-cFILE` слитно, как в C.
        assert_eq!(rate(&[&format!("-c{b}")]), 2.0);

        // `--infinite` и `--offline` тоже по порядку argv: файл правее может их отключить, левее не может.
        let off = dir
            .write("off.conf", b"infinite = false\noffline = false\n")
            .to_str()
            .unwrap()
            .to_string();
        let flags = |a: &[&str]| {
            let c = parse(a).unwrap().to_config().unwrap();
            (c.infinite, c.offline)
        };
        assert_eq!(
            flags(&["-c", &off, "--infinite", "--offline"]),
            (true, true)
        );
        assert_eq!(
            flags(&["--infinite", "--offline", "-c", &off]),
            (false, false)
        );
        assert_eq!(flags(&["--infinite", "-c", &n]), (true, false));

        // Цикл: `conf = self` вкладывается глубже 16 и отказывает; пропавший файл и неизвестный ключ тоже.
        let selfref = dir.path("self.conf");
        std::fs::write(&selfref, format!("conf = {}\n", selfref.display())).unwrap();
        let e = parse(&["-c", selfref.to_str().unwrap()])
            .unwrap()
            .to_config()
            .unwrap_err();
        assert!(e.contains("nested deeper than 16"), "{e}");
        let e = parse(&["-c", "/nonexistent/x.conf"])
            .unwrap()
            .to_config()
            .unwrap_err();
        assert!(e.contains("x.conf"), "{e}");
        let bad = dir
            .write("bad.conf", b"hello-string[80] = x\n")
            .to_str()
            .unwrap()
            .to_string();
        assert!(parse(&["-c", &bad]).unwrap().to_config().is_err());
        let e = parse(&["-iL", "/nonexistent/t.txt"])
            .unwrap()
            .to_config()
            .unwrap_err();
        assert!(e.contains("t.txt"), "{e}");
    }

    /// Задача 7, Review Focus 4 (`main-conf.c:2437-2641`, `nic[8]` переполняет массив): индекс адаптера вне `0..=7`
    /// отказывает (exit 1), а не пишет за массив; `--adapter[i]` и родственные ключи идут по порядку `argv` вместе с
    /// одиночными опциями и держат одиночные поля и `nics[0]` равными (T2 I-1).
    #[test]
    fn adapter_index_out_of_bounds_fails() {
        for bad in [
            &["--adapter[8]", "eth0"][..],
            &["--adapter[-1]", "eth0"][..],
            &["--adapter[x]=eth0"][..],
            &["--adapter-ip[9]", "198.18.0.1"][..],
            &["--router-mac[100]:00-11-22-33-44-55"][..],
        ] {
            let e = parse(bad).unwrap().to_config().unwrap_err();
            assert!(
                e.contains("adapter") || e.contains("router"),
                "{bad:?}: {e}"
            );
        }
        // Файл `adapter[-1] = eth0` тоже отказывает.
        let dir = crate::scratch::Scratch::new();
        let f = dir.write("neg.conf", b"adapter[-1] = eth0\n");
        assert!(
            parse(&["-c", f.to_str().unwrap()])
                .unwrap()
                .to_config()
                .is_err()
        );

        // Допустимые индексы: три формы значения, порядок `argv` с одиночной опцией.
        let cfg = parse(&[
            "--adapter[0]",
            "veth0",
            "--adapter[1]=veth1",
            "--adapter-ip[1]:198.18.0.2",
            "--adapter-mac[1]",
            "02-00-00-00-00-02",
            "--source-port[1]",
            "50000",
        ])
        .unwrap()
        .to_config()
        .unwrap();
        assert_eq!(cfg.nics.len(), 2);
        assert_eq!(cfg.nics[0].adapter_name.as_deref(), Some("veth0"));
        assert_eq!(cfg.adapter_name.as_deref(), Some("veth0"));
        assert_eq!(cfg.nics[1].adapter_name.as_deref(), Some("veth1"));
        assert_eq!(cfg.nics[1].adapter_ip, Some((0xc612_0002, 0xc612_0002)));
        assert_eq!(cfg.nics[1].adapter_mac, Some([2, 0, 0, 0, 0, 2]));
        assert_eq!(cfg.nics[1].source_port, Some((50000, 50000)));
        // Правее побеждает: одиночная опция после `--adapter[0]` и наоборот.
        let name = |a: &[&str]| {
            parse(a).unwrap().to_config().unwrap().nics[0]
                .adapter_name
                .clone()
        };
        assert_eq!(
            name(&["--adapter[0]", "a", "--interface", "b"]).as_deref(),
            Some("b")
        );
        assert_eq!(
            name(&["--interface", "b", "--adapter[0]", "a"]).as_deref(),
            Some("a")
        );
        // Индексированный ключ левее файла переопределяется файлом, правее переопределяет его.
        let conf = dir.write(
            "n.conf",
            b"adapter[1] = from-file\nadapter-ip[1] = 198.18.0.7\n",
        );
        let f = conf.to_str().unwrap();
        let one = |a: &[&str]| {
            parse(a).unwrap().to_config().unwrap().nics[1]
                .adapter_name
                .clone()
        };
        assert_eq!(
            one(&["--adapter[1]", "cli", "-c", f]).as_deref(),
            Some("from-file")
        );
        assert_eq!(
            one(&["-c", f, "--adapter[1]", "cli"]).as_deref(),
            Some("cli")
        );
        // Закрытый `[…]` у ключа не адаптера отбрасывается, как у `EQUALS` C (`src/main-conf.c:840-841`, Р17).
        assert_eq!(
            parse(&["--rate[1]", "5"]).unwrap().rate.as_deref(),
            Some("5")
        );
    }

    /// Порты после разбора `argv`, отсортированные, как их видит `--echo`.
    fn ports_of(a: &[&str]) -> Vec<(u32, u32)> {
        let mut cfg = parse(a).unwrap().to_config().unwrap();
        cfg.targets.ports_mut().sort_and_merge();
        cfg.targets
            .ports()
            .as_slice()
            .iter()
            .map(|r| (r.begin, r.end))
            .collect()
    }

    const U: u32 = 65536;

    #[test]
    fn sticky_port_prefixes_and_oproto_live_refusal() {
        // main-conf.c:2663-2681: `-p` с префиксами разбирается как в ядре
        assert_eq!(
            ports_of(&["-pU:53,161,T:80-81,s:2905,I:0,o:47"]),
            [
                (80, 81),
                (U + 53, U + 53),
                (U + 161, U + 161),
                (2 * U + 2905, 2 * U + 2905),
                (3 * U, 3 * U),
                (3 * U + 303, 3 * U + 303),
            ]
        );
        assert!(parse(&["-p", "O:256"]).unwrap().to_config().is_err());
        assert!(parse(&["-p", "U:65536"]).unwrap().to_config().is_err());
        // порядок argv: `-sU` задаёт префикс только для `-p` правее него
        assert_eq!(ports_of(&["-sU", "-p53"]), [(U + 53, U + 53)]);
        assert_eq!(ports_of(&["-p53", "-sU"]), [(53, 53)]);
        assert_eq!(ports_of(&["-sZ", "-p9"]), [(2 * U + 9, 2 * U + 9)]);
        // явный `T:` перекрывает
        assert_eq!(
            ports_of(&["-sU", "-p53,T:80"]),
            [(80, 80), (U + 53, U + 53)]
        );
        // `--udp-ports` и `--ping`
        assert_eq!(ports_of(&["--udp-ports", "53"]), [(U + 53, U + 53)]);
        assert_eq!(ports_of(&["--ping"]), [(3 * U, 3 * U)]);
        assert_eq!(
            ports_of(&["--ping-sweep", "-p80"]),
            [(80, 80), (3 * U, 3 * U)]
        );
    }

    #[test]
    fn top_ports_follow_scan_types() {
        let tcp5 = [(21, 21), (80, 80), (443, 443), (990, 990), (8080, 8080)];
        let udp5 = [
            (U + 135, U + 135),
            (U + 137, U + 138),
            (U + 161, U + 161),
            (U + 500, U + 500),
        ];
        // main-conf.c:3609-3619: по умолчанию TCP; `-sU` убирает TCP, `-sS -sU` даёт оба
        assert_eq!(ports_of(&["--top-ports", "5"]), tcp5);
        assert_eq!(ports_of(&["--top-ports=5"]), tcp5);
        assert_eq!(ports_of(&["--top-ports", "5", "-sU"]), udp5);
        assert_eq!(
            ports_of(&["--top-ports", "5", "-sS", "-sU"]),
            [&tcp5[..], &udp5[..]].concat()
        );
        // без таблицы для SCTP; ping даёт только I:0
        assert!(ports_of(&["--top-ports", "3", "-sZ"]).is_empty());
        assert_eq!(ports_of(&["--top-ports", "3", "--ping"]), [(3 * U, 3 * U)]);
        // добавляется к `-p`, а `--top-ports 0` ничего не делает
        assert_eq!(ports_of(&["--top-ports", "0", "-p5"]), [(5, 5)]);
        assert_eq!(
            ports_of(&["--top-ports", "2", "-p80", "-sU"]),
            [(80, 80), (U + 135, U + 135), (U + 161, U + 161)]
        );
        // голый `--top-ports` значит 20 (SET_topports, main-conf.c:2107-2123); `1` это булево «включить»
        assert_eq!(
            ports_of(&["--top-ports"])
                .iter()
                .map(|r| r.1 - r.0 + 1)
                .sum::<u32>(),
            20
        );
        assert_eq!(ports_of(&["--top-ports", "1"]), ports_of(&["--top-ports"]));
        assert!(parse(&["--top-ports=abc"]).unwrap().to_config().is_err());
    }

    #[test]
    fn nmap_scan_type_flags_are_accepted_before_clap() {
        assert_eq!(
            preprocess_args(["rmasscan", "-sU", "-sZ", "-sS", "--ping", "-sL"]).unwrap(),
            [
                "rmasscan",
                "--rmasscan-scan=U",
                "--rmasscan-scan=Z",
                "--rmasscan-scan=S",
                "--ping",
                "--list"
            ]
        );
    }

    /// `preprocess_args` с именем программы впереди.
    fn pre(a: &[&str]) -> Vec<String> {
        preprocess_args(std::iter::once("rmasscan").chain(a.iter().copied())).unwrap()
    }

    /// Каждое длинное имя и синоним clap (с `--help` и `--version`, кроме внутренних `--rmasscan-…`) и id его
    /// аргумента, собранные отдельно от [`equals_table`].
    fn clap_long_names() -> Vec<(String, String)> {
        let mut cmd = Cli::command();
        cmd.build();
        let mut names = Vec::new();
        for arg in cmd.get_arguments() {
            let Some(long) = arg.get_long() else { continue };
            if long.starts_with("rmasscan-") {
                // Внутренние опции, которые пишет сам `preprocess_args`, скрыты из справки.
                assert!(arg.is_hide_set(), "{long}");
                continue;
            }
            let id = arg.get_id().as_str().to_string();
            for name in std::iter::once(long).chain(arg.get_all_aliases().unwrap_or_default()) {
                names.push((name.to_string(), id.clone()));
            }
        }
        names
    }

    /// Р17, справка C1: ключ `normalize_key` каждого имени и синонима clap ведёт ровно к одной опции. Совпадают после
    /// нормализации только `nocapture` и его синоним `no-capture` (`src/main-conf.c:2403`), это одна опция.
    #[test]
    fn equals_table_has_one_option_per_key() {
        let names = clap_long_names();
        assert!(names.len() > 100, "{}", names.len());
        let long_to_id: HashMap<String, String> = names.iter().cloned().collect();
        let mut groups: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for (name, id) in &names {
            groups
                .entry(normalize_key(name))
                .or_default()
                .push((name.clone(), id.clone()));
        }
        for (key, group) in &groups {
            let id = &group[0].1;
            assert!(group.iter().all(|(_, i)| i == id), "{key}: {group:?}");
            let long = equals_table().long_of(key);
            assert_eq!(long.map(|l| &long_to_id[l]), Some(id), "{key}");
        }
        assert_eq!(equals_table().0.len(), groups.len());
        let mut pairs: Vec<Vec<&str>> = groups
            .values()
            .filter(|g| g.len() > 1)
            .map(|g| {
                let mut n: Vec<&str> = g.iter().map(|(n, _)| n.as_str()).collect();
                n.sort_unstable();
                n
            })
            .collect();
        pairs.sort();
        assert_eq!(pairs, [["no-capture", "nocapture"]]);
        for name in [
            "help",
            "version",
            "banner-app",
            "top-port",
            "rotate-size",
            "source-ip",
        ] {
            assert!(
                equals_table().long_of(&normalize_key(name)).is_some(),
                "{name}"
            );
        }
        assert_eq!(equals_table().long_of("rmasscannic"), None);
        assert_eq!(equals_table().long_of("rmasscanscan"), None);
    }

    /// Р17 (`EQUALS`, `src/main-conf.c:833-849`): каждое длинное имя и синоним clap, набранные заглавными с `_` вместо
    /// `-`, разбираются как само имя: голым, со значением после `=` и со значением следующим словом. clap узнаёт итог
    /// как ту же опцию (любая ошибка, кроме «неизвестный аргумент», значит, что имя узнано).
    #[test]
    fn equals_rewrites_every_long_option() {
        use clap::error::ErrorKind;
        use clap::parser::ValueSource;
        for (name, id) in clap_long_names() {
            let shout = format!("--{}", name.to_uppercase().replace('-', "_"));
            let plain = format!("--{name}");
            for (typed, canon) in [
                (vec![shout.clone()], vec![plain.clone()]),
                (vec![format!("{shout}=1")], vec![format!("{plain}=1")]),
                (
                    vec![shout.clone(), "1".into()],
                    vec![plain.clone(), "1".into()],
                ),
            ] {
                let typed: Vec<&str> = typed.iter().map(String::as_str).collect();
                let canon: Vec<&str> = canon.iter().map(String::as_str).collect();
                let got = pre(&typed);
                assert_eq!(got, pre(&canon), "{typed:?}");
                match Cli::command().try_get_matches_from(&got) {
                    Ok(m) => assert_eq!(
                        m.value_source(&id),
                        Some(ValueSource::CommandLine),
                        "{typed:?}"
                    ),
                    Err(e) => assert_ne!(e.kind(), ErrorKind::UnknownArgument, "{typed:?}: {e}"),
                }
            }
        }
    }

    /// Значение после первого `=`, иначе после первого `:` (`masscan_command_line`, `src/main-conf.c:3279-3289`); `:` у
    /// любой опции значит `=`, а `:` и `=` внутри значения остаются.
    #[test]
    fn equals_keeps_value_after_eq_and_colon() {
        assert_eq!(pre(&["--Rate=100"]), ["rmasscan", "--rate=100"]);
        assert_eq!(pre(&["--RATE:100"]), ["rmasscan", "--rate=100"]);
        assert_eq!(pre(&["--rate:100"]), ["rmasscan", "--rate=100"]);
        assert_eq!(pre(&["--rate="]), ["rmasscan", "--rate="]);
        assert_eq!(
            pre(&["--Adapter_IP=fe80::1"]),
            ["rmasscan", "--adapter-ip=fe80::1"]
        );
        assert_eq!(
            pre(&["--router.mac:00:11:22:33:44:55"]),
            ["rmasscan", "--router-mac=00:11:22:33:44:55"]
        );
        assert_eq!(
            pre(&["--Stylesheet:http://x/a"]),
            ["rmasscan", "--stylesheet=http://x/a"]
        );
        assert_eq!(
            pre(&["--Stylesheet=http://x/a:b"]),
            ["rmasscan", "--stylesheet=http://x/a:b"]
        );
        // `=` раньше `:`: имя `Exclude:a` неизвестно (у C тоже), clap его отклоняет.
        assert_eq!(pre(&["--Exclude:a=b"]), ["rmasscan", "--Exclude:a=b"]);
        assert!(parse(&["--Exclude:a=b"]).is_err());
        let cli = parse(&["--Rate:250", "--Seed=7", "--Source_IP:fe80::1", "10.0.0.1"]).unwrap();
        assert_eq!(cli.rate.as_deref(), Some("250"));
        assert_eq!(cli.seed, Some(7));
        assert_eq!(cli.adapter_ip.as_deref(), Some("fe80::1"));
        assert_eq!(cli.targets, ["10.0.0.1"]);
    }

    /// Ключ адаптера с индексом (`nic[i]`, `src/main-conf.c:882-890`) `EQUALS` не трогает: индекс разбирает
    /// [`indexed_nic_key`], в любом написании имени. Без индекса это одиночная опция clap.
    #[test]
    fn equals_leaves_array_names_to_indexed_parsers() {
        assert_eq!(
            pre(&["--Adapter-Ip[1]", "10.0.0.1"]),
            ["rmasscan", "--rmasscan-nic=Adapter-Ip[1]=10.0.0.1"]
        );
        assert_eq!(
            pre(&["--SOURCE_IP[1]=10.0.0.1"]),
            ["rmasscan", "--rmasscan-nic=SOURCE_IP[1]=10.0.0.1"]
        );
        assert_eq!(
            pre(&["--Adapter-Ip", "10.0.0.1"]),
            ["rmasscan", "--adapter-ip", "10.0.0.1"]
        );
        let cfg = parse(&["--Adapter-Ip[1]", "198.18.0.2", "--ADAPTER[1]", "veth1"])
            .unwrap()
            .to_config()
            .unwrap();
        assert_eq!(cfg.nics[1].adapter_ip, Some((0xc612_0002, 0xc612_0002)));
        assert_eq!(cfg.nics[1].adapter_name.as_deref(), Some("veth1"));
    }

    /// `EQUALS` C истинно, когда имя таблицы кончилось там, где у набранного имени `[` (`src/main-conf.c:840-841`):
    /// закрытый суффикс `[…]` у опции без индексного смысла отбрасывается, по всей таблице clap.
    #[test]
    fn equals_array_suffix_ignored_like_c() {
        for (name, _) in clap_long_names() {
            if has_index_meaning(&normalize_key(&name)) {
                continue;
            }
            let suffixed = format!("--{name}[0]");
            let plain = format!("--{name}");
            assert_eq!(
                pre(&[&format!("{suffixed}=v")]),
                pre(&[&format!("{plain}=v")]),
                "{name}"
            );
            assert_eq!(pre(&[&suffixed, "v"]), pre(&[&plain, "v"]), "{name}");
            // Что внутри скобок и после них, C не смотрит.
            let shout = format!("--{}[7]x", name.to_uppercase());
            assert_eq!(pre(&[&shout, "v"]), pre(&[&plain, "v"]), "{name}");
        }
        let cli = parse(&["--banner-types[0]", "dns-ver", "--readscan", "f"]).unwrap();
        assert_eq!(cli.banner_types, ["dns-ver"]);
        assert_eq!(
            parse(&["--rate[7]", "100"]).unwrap().rate.as_deref(),
            Some("100")
        );
    }

    /// Р17 («непарный индекс»): незакрытая `[` в имени это код 1 у любой опции, в том числе у ключей адаптера и у
    /// неизвестных имён. C сравнивает имя до `[` и читает индекс `parseInt` (`ARRAY`, `src/main-conf.c:881-890`).
    #[test]
    fn unpaired_index_fails() {
        for (bad, name) in [
            (&["--rate[", "100"][..], "--rate["),
            (&["--Adapter-Ip[1", "10.0.0.1"][..], "--Adapter-Ip[1"),
            (&["--adapter-ip[1=10.0.0.1"][..], "--adapter-ip[1"),
            (&["--banners["][..], "--banners["),
            (&["--bogus[x"][..], "--bogus[x"),
        ] {
            assert_eq!(
                masscan_err(&[bad, &["10.0.0.0/30", "-p80"][..]].concat()),
                format!("{name}: unclosed '[' in the option name"),
                "{bad:?}"
            );
        }
    }

    /// `EQUALS` стоит раньше `F_NUMABLE` (`src/main-conf.c:3228`, `is_numable` :3041-3056 тоже сравнивает по `EQUALS`):
    /// следующее целое или логическое слово забирается при любом написании имени.
    #[test]
    fn equals_then_numable() {
        assert_eq!(pre(&["--TCP-MSS", "1400"]), ["rmasscan", "--tcp-mss=1400"]);
        assert_eq!(pre(&["--TCP-MSS", "1400"]), pre(&["--tcp-mss", "1400"]));
        assert_eq!(pre(&["--TcpMss", "off"]), ["rmasscan", "--tcp-mss=off"]);
        assert_eq!(
            pre(&["--Top_Ports", "100"]),
            ["rmasscan", "--top-ports=100"]
        );
        assert_eq!(pre(&["--TOP-PORT", "5"]), ["rmasscan", "--top-ports=5"]);
        assert_eq!(pre(&["--top-port:5"]), ["rmasscan", "--top-ports=5"]);
        assert_eq!(
            pre(&["--Tcp.WScale", "x"]),
            ["rmasscan", "--tcp-wscale=", "x"]
        );
        let cfg = parse(&["10.0.0.1", "--TCP-MSS", "1400", "-p80"])
            .unwrap()
            .to_config()
            .unwrap();
        assert_eq!(cfg.tcp_opts.mss, Some(1400));
    }

    /// Ошибки clap это код 1, как `exit(1)` C на неизвестное имя (`src/main-conf.c:3036`), а не 2 clap; текст clap.
    /// Справка и версия это 0 (C печатает справку с кодом 1, `:3225-3227`).
    #[test]
    fn clap_errors_exit_1() {
        use clap::error::ErrorKind;
        for (argv, text) in [
            (&["--bogus"][..], "unexpected argument '--bogus'"),
            (
                &["10.0.0.0/30", "--rate"][..],
                "a value is required for '--rate <PPS>'",
            ),
            (&["--seed", "x"][..], "invalid value 'x' for '--seed <N>'"),
        ] {
            match parse(argv) {
                Err(ParseError::Clap(e)) => {
                    assert_eq!(clap_exit_code(e.kind()), 1, "{argv:?}");
                    assert!(e.to_string().contains(text), "{argv:?}: {e}");
                }
                other => panic!("{argv:?}: {other:?}"),
            }
        }
        for (argv, kind) in [
            ("--help", ErrorKind::DisplayHelp),
            ("--HELP", ErrorKind::DisplayHelp),
            ("-h", ErrorKind::DisplayHelp),
            ("--version", ErrorKind::DisplayVersion),
            ("-V", ErrorKind::DisplayVersion),
        ] {
            match parse(&[argv]) {
                Err(ParseError::Clap(e)) => {
                    assert_eq!(e.kind(), kind, "{argv}");
                    assert_eq!(clap_exit_code(e.kind()), 0, "{argv}");
                }
                other => panic!("{argv}: {other:?}"),
            }
        }
    }

    /// `masscan_set_parameter` (`src/main-conf.c:2437-2441`): индекс от 65536 это `"<имя>: bad index"` и код 1 у любого
    /// ключа, раньше сравнения имени, в том числе там, где закрытый суффикс иначе отбрасывается. Индекс читает `ARRAY`
    /// (:881-890): цифры сразу за `[`, по модулю 2^32; без цифр это 0. Так же в файле конфигурации.
    #[test]
    fn bad_index_fails_like_c() {
        for (bad, name) in [
            (&["--rate[70000]", "9"][..], "rate[70000]"),
            (&["--rate[65536]=9"][..], "rate[65536]"),
            (
                &["--Banner-Types[99999]", "dns-ver"][..],
                "Banner-Types[99999]",
            ),
            (
                &["--adapter-ip[70000]", "10.0.0.1"][..],
                "adapter-ip[70000]",
            ),
            (&["--bogus[70000]"][..], "bogus[70000]"),
            // C печатает `bad index` и у незакрытой скобки: проверка индекса идёт первой.
            (&["--rate[70000", "9"][..], "rate[70000"),
        ] {
            assert_eq!(
                masscan_err(&[bad, &["10.0.0.0/30"][..]].concat()),
                format!("{name}: bad index"),
                "{bad:?}"
            );
        }
        for ok in [
            "--rate[65535]",
            "--rate[4294967296]",
            "--rate[x]",
            "--rate[-1]",
        ] {
            assert_eq!(
                parse(&[ok, "9"]).unwrap().rate.as_deref(),
                Some("9"),
                "{ok}"
            );
        }
        let dir = crate::scratch::Scratch::new();
        let f = dir.write("idx.conf", b"rate[70000] = 5\n");
        let e = parse(&["-c", f.to_str().unwrap()])
            .unwrap()
            .to_config()
            .unwrap_err();
        assert_eq!(e, "rate[70000]: bad index");
    }

    /// Голое `--` clap понимает как конец опций, поэтому слова правее него идут в clap как есть: их не переписывает и
    /// не отклоняет ни `EQUALS`, ни другие правила `preprocess_args`. `--`, которое правило забрало значением, концом
    /// опций не считается (C тоже берёт его значением, `src/main-conf.c:3293`).
    #[test]
    fn words_after_double_dash_reach_clap_untouched() {
        assert_eq!(
            pre(&[
                "--Rate",
                "5",
                "--",
                "--Rate",
                "--rate[",
                "-sL",
                "--x[70000]"
            ]),
            [
                "rmasscan",
                "--rate",
                "5",
                "--",
                "--Rate",
                "--rate[",
                "-sL",
                "--x[70000]"
            ]
        );
        assert_eq!(parse(&["--", "--Rate"]).unwrap().targets, ["--Rate"]);
        assert_eq!(
            pre(&["--adapter-ip[1]", "--", "--Rate", "5"]),
            ["rmasscan", "--rmasscan-nic=adapter-ip[1]=--", "--rate", "5"]
        );
    }

    /// Правило 0 `preprocess_args`: значение, которое берёт clap, не переписывается. После `=` или `:` оно идёт как есть,
    /// даже если похоже на опцию с `[`, `=` и `:`; слово, которое забрало правило `preprocess_args`, тоже; отдельное
    /// слово с `--` clap значением не берёт, переписано оно или нет.
    #[test]
    fn clap_bound_values_are_never_rewritten() {
        assert_eq!(
            pre(&["--exclude=--Rate[1]:x=y"]),
            ["rmasscan", "--exclude=--Rate[1]:x=y"]
        );
        assert_eq!(
            parse(&["--exclude=--Rate[1]:x=y"]).unwrap().exclude,
            ["--Rate[1]:x=y"]
        );
        assert_eq!(
            parse(&["--Exclude:--Rate[1"]).unwrap().exclude,
            ["--Rate[1"]
        );
        assert_eq!(
            parse(&["--Stylesheet=--Rate:1["]).unwrap().stylesheet,
            ["--Rate:1["]
        );
        assert_eq!(
            pre(&["--adapter-ip[1]", "--Rate[1"]),
            ["rmasscan", "--rmasscan-nic=adapter-ip[1]=--Rate[1"]
        );
        for argv in [
            &["--exclude", "--Rate", "5"][..],
            &["-p", "--Rate", "5"][..],
        ] {
            match parse(argv) {
                Err(ParseError::Clap(e)) => assert!(
                    e.to_string().contains("a value is required for"),
                    "{argv:?}: {e}"
                ),
                other => panic!("{argv:?}: {other:?}"),
            }
        }
    }

    /// Правило 0 держится на том, что clap не берёт отдельное слово с `--` значением опции. Задача 13
    /// (`--hello-string`, `--http-*`) обязана сохранить это или научить `preprocess_args` пропускать значение опции,
    /// которое переписывать нельзя.
    #[test]
    fn no_option_takes_hyphen_values() {
        let mut cmd = Cli::command();
        cmd.build();
        for arg in cmd.get_arguments() {
            let id = arg.get_id();
            assert!(!arg.is_allow_hyphen_values_set(), "{id}");
            assert!(!arg.is_trailing_var_arg_set(), "{id}");
            assert!(!arg.is_last_set(), "{id}");
        }
    }

    /// Синонимы C (`config_parameters[]`, `src/main-conf.c:2369-2427`, и цепочка `masscan_set_parameter`,
    /// :2470-3037) у опций, которые есть в rmasscan, ведут к той же опции, что у C. Каждое имя ключа адаптера
    /// ([`NIC_KEYS`]) работает и без индекса, как у C (индекс 0).
    #[test]
    fn c_aliases_reach_the_same_option() {
        let long_to_id: HashMap<String, String> = clap_long_names().into_iter().collect();
        let id_of = |name: &str| {
            equals_table()
                .long_of(&normalize_key(name))
                .map(|l| long_to_id[l].clone())
        };
        for (alias, id) in [
            ("max-rate", "rate"),
            ("shards", "shard"),
            ("retry", "retries"),
            ("max-retries", "retries"),
            ("max-retry", "retries"),
            ("notransmit", "offline"),
            ("nosend", "offline"),
            ("dry-run", "offline"),
            ("port", "ports"),
            ("dst-port", "ports"),
            ("dest-port", "ports"),
            ("destination-port", "ports"),
            ("target-port", "ports"),
            ("ranges", "range"),
            ("ip", "range"),
            ("ipv4", "range"),
            ("dst-ip", "range"),
            ("dest-ip", "range"),
            ("destination-ip", "range"),
            ("target-ip", "range"),
            ("exclude-range", "exclude"),
            ("exclude-ranges", "exclude"),
            ("exclude-ip", "exclude"),
            ("exclude-ipv4", "exclude"),
            ("trace-packet", "packet_trace"),
            ("if", "interface"),
            ("source-address", "adapter_ip"),
            ("spoof-ip", "adapter_ip"),
            ("spoof-address", "adapter_ip"),
            ("src-ip", "adapter_ip"),
            ("src-port", "source_port"),
            ("sourceport", "source_port"),
            ("spoof-mac", "adapter_mac"),
            ("src-mac", "adapter_mac"),
            ("router", "router_mac"),
            ("dest-mac", "router_mac"),
            ("destination-mac", "router_mac"),
            ("dst-mac", "router_mac"),
            ("target-mac", "router_mac"),
            ("router-mac-ipv4", "router_mac_ipv4"),
            ("router-ipv4", "router_mac_ipv4"),
            ("tcpmss", "tcp_mss"),
            ("top-port", "top_ports"),
        ] {
            assert_eq!(id_of(alias).as_deref(), Some(id), "{alias}");
        }
        for key in NIC_KEYS {
            assert!(equals_table().long_of(key).is_some(), "{key}");
        }
        let cfg = |a: &[&str]| parse(a).unwrap().to_config().unwrap();
        assert_eq!(
            cfg(&["--spoof-ip", "198.18.0.9"]).adapter_ip,
            Some(0xc612_0009)
        );
        assert_eq!(
            cfg(&["--If", "veth9"]).adapter_name.as_deref(),
            Some("veth9")
        );
        assert_eq!(
            cfg(&["--src-port", "40001"]).source_port,
            Some((40001, 40001))
        );
        assert_eq!(
            cfg(&["--SRC_MAC", "02-00-00-00-00-01"]).adapter_mac,
            Some([2, 0, 0, 0, 0, 1])
        );
        assert_eq!(
            cfg(&["--router", "02-00-00-00-00-04"]).router_mac,
            Some([2, 0, 0, 0, 0, 4])
        );
        // `--router-mac-ipv4` без индекса это то же, что `--router-mac-ipv4[0]`: только MAC шлюза IPv4.
        for argv in [
            &["--router-mac-ipv4", "02-00-00-00-00-05"][..],
            &["--Router-IPv4=02-00-00-00-00-05"][..],
            &["--router-mac-ipv4[0]", "02-00-00-00-00-05"][..],
        ] {
            let c = cfg(argv);
            assert_eq!(c.router_mac, Some([2, 0, 0, 0, 0, 5]), "{argv:?}");
            assert_eq!(
                (c.nics[0].router_mac_ipv4, c.nics[0].router_mac_ipv6),
                (Some([2, 0, 0, 0, 0, 5]), None),
                "{argv:?}"
            );
        }
        assert!(
            parse(&["--router-mac-ipv4", "nope"])
                .unwrap()
                .to_config()
                .is_err()
        );
        let cli = parse(&[
            "--max-rate",
            "50",
            "--Dry-Run",
            "--IP",
            "10.0.0.1",
            "--Max_Retries",
            "2",
        ])
        .unwrap();
        assert_eq!(cli.rate.as_deref(), Some("50"));
        assert!(cli.offline);
        assert_eq!(cli.range, ["10.0.0.1"]);
        assert_eq!(cli.retries, Some(2));
    }

    // Задача 13: `--hello*`, `--connection-timeout`, `--http-*` (справка C1-C4).

    fn banner_cfg(a: &[&str]) -> ScanConfig {
        parse(a).unwrap().to_config().unwrap()
    }

    fn banner_err(a: &[&str]) -> String {
        match parse(a) {
            Err(ParseError::Masscan(t)) => t,
            Ok(cli) => cli.to_config().unwrap_err(),
            Err(e) => panic!("{a:?}: {e:?}"),
        }
    }

    /// `--hello-string` без `[P]` C читает как порт 0 (`ARRAY`, `src/main-conf.c:881-890`); здесь это отказ
    /// (Р17).
    #[test]
    fn hello_string_without_index_fails() {
        for a in [
            &["--hello-string", "QUJD"][..],
            &["--hello-string=QUJD"][..],
            &["--HELLO_STRING:QUJD"][..],
        ] {
            assert!(parse(a).unwrap().to_config().is_err(), "{a:?}");
        }
    }

    /// Незакрытая `[` у `--hello-string`/`--hello-file`/`--http-header`: тот же отказ Р17, что у любой опции.
    #[test]
    fn hello_string_unpaired_index_fails() {
        for (a, name) in [
            (&["--hello-string[80", "QUJD"][..], "--hello-string[80"),
            (&["--hello-string[80=QUJD"][..], "--hello-string[80"),
            (&["--hello-file[80", "f"][..], "--hello-file[80"),
            (&["--http-header[X", "v"][..], "--http-header[X"),
        ] {
            assert_eq!(
                masscan_err(a),
                format!("{name}: unclosed '[' in the option name"),
                "{a:?}"
            );
        }
    }

    /// Индекс не десятичный: C `ARRAY` взял бы ведущие цифры или 0, здесь отказ (Р17).
    #[test]
    fn hello_string_non_decimal_index_fails() {
        for a in [
            &["--hello-string[x]", "QUJD"][..],
            &["--hello-string[8x]", "QUJD"][..],
            &["--hello-string[]", "QUJD"][..],
            &["--hello-string[-1]", "QUJD"][..],
            &["--hello-string[0x50]", "QUJD"][..],
            &["--hello-file[8.0]", "f"][..],
        ] {
            assert!(parse(a).unwrap().to_config().is_err(), "{a:?}");
        }
        // Ведущие нули десятичны, хвост после `]` C не смотрит.
        let cfg = banner_cfg(&["--hello-string[00080]junk", "QUJD"]);
        assert_eq!(cfg.hello_strings, [(80, "QUJD".to_string())]);
    }

    /// Индекс от 65536 это `bad index` C и код 1 (`src/main-conf.c:2437-2441`, `:1276-1278`), ещё на разборе.
    #[test]
    fn hello_string_index_65536_fails() {
        for (a, name) in [
            (
                &["--hello-string[65536]", "QUJD"][..],
                "hello-string[65536]",
            ),
            (&["--hello-string[70000]=QUJD"][..], "hello-string[70000]"),
            (&["--hello-file[65536]", "f"][..], "hello-file[65536]"),
        ] {
            assert_eq!(masscan_err(a), format!("{name}: bad index"), "{a:?}");
        }
        let cfg = banner_cfg(&["--hello-string[65535]", "QUJD"]);
        assert_eq!(cfg.hello_strings, [(65535, "QUJD".to_string())]);
    }

    /// Неверный base64 по определению справки C2 отказывает: пробел, `=` в середине, `QUJD=`, один хвостовой
    /// знак, байт вне алфавита (E1.6: C на части из них зависает).
    #[test]
    fn hello_string_invalid_base64_fails() {
        for bad in ["QU JD", "QU=JD", "QUJD=", "Q", "QUJD*", "QUJD\t"] {
            let a = [format!("--hello-string[80]={bad}")];
            assert!(
                parse(&[a[0].as_str()]).unwrap().to_config().is_err(),
                "{bad:?}"
            );
        }
        for bad in ["", "QQ==", "QUE=", "QUJD", "QUE"] {
            let a = [format!("--hello-string[80]={bad}")];
            assert!(
                parse(&[a[0].as_str()]).unwrap().to_config().is_ok(),
                "{bad:?}"
            );
        }
    }

    /// Эхо `hello-string[%u] = %s` от новой записи к старой (`src/main-conf.c:1264-1268`: список в начало),
    /// хранится порядок argv.
    #[test]
    fn hello_string_echo_newest_first() {
        // Разделитель `:` с набивкой `=` в значении C не разбирает (`strchr('=')` первый), поэтому третье
        // значение отдельным словом.
        let cfg = banner_cfg(&[
            "--hello-string[80]",
            "QUJD",
            "--hello-string[443]=aGVsbG8=",
            "--Hello.String[80]",
            "RA==",
        ]);
        assert_eq!(
            cfg.hello_strings,
            [
                (80, "QUJD".to_string()),
                (443, "aGVsbG8=".to_string()),
                (80, "RA==".to_string()),
            ]
        );
        let mut s = String::new();
        rmasscan_core::config::echo(&cfg, false, &mut s);
        let lines: Vec<&str> = s
            .lines()
            .filter(|l| l.starts_with("hello-string"))
            .collect();
        assert_eq!(
            lines,
            [
                "hello-string[80] = RA==",
                "hello-string[443] = aGVsbG8=",
                "hello-string[80] = QUJD",
            ]
        );
    }

    /// `--hello-file[P]` (`hello-filename`, `src/main-conf.c:1212-1258`): байты файла кодируются и дальше это
    /// `hello-string[P]`; сам ключ в эхо не пишется.
    #[test]
    fn hello_file_becomes_hello_string() {
        let dir = crate::scratch::Scratch::new();
        let f = dir.write("hello.bin", b"\x00hello\xff");
        let name = format!("--hello-filename[8080]={}", f.display());
        let cfg = banner_cfg(&[name.as_str()]);
        assert_eq!(cfg.hello_strings, [(8080, "AGhlbGxv/w==".to_string())]);
        let mut s = String::new();
        rmasscan_core::config::echo(&cfg, false, &mut s);
        assert!(s.contains("hello-string[8080] = AGhlbGxv/w==\n"), "{s}");
        assert!(!s.contains("hello-file"), "{s}");
        assert_eq!(
            crate::banner_settings::tcp_banner_settings(&cfg)
                .unwrap()
                .hello_strings,
            [(8080, b"\x00hello\xff".to_vec())]
        );
        // Отдельное слово и написание `EQUALS` дают то же.
        let cfg = banner_cfg(&["--Hello_File[80]", f.to_str().unwrap()]);
        assert_eq!(cfg.hello_strings, [(80, "AGhlbGxv/w==".to_string())]);
    }

    /// Файл длиннее 12285 байт C молча обрезал бы (`src/main-conf.c:1237-1246`); здесь отказ (E1.14).
    #[test]
    fn hello_file_over_12285_fails() {
        let dir = crate::scratch::Scratch::new();
        let max = dir.write("max.bin", &[b'x'; 12285]);
        let cfg = banner_cfg(&["--hello-file[80]", max.to_str().unwrap()]);
        assert_eq!(cfg.hello_strings.len(), 1);
        let over = dir.write("over.bin", &[b'x'; 12286]);
        assert!(
            parse(&["--hello-file[80]", over.to_str().unwrap()])
                .unwrap()
                .to_config()
                .is_err()
        );
    }

    /// Пустой файл hello: текст C `[FAILED] could not read hello file` (`src/main-conf.c:1240-1244`); каталог у C
    /// открывается, но `fread` даёт 0 байт, поэтому тот же текст, а не ошибка открытия.
    #[test]
    fn hello_file_empty_fails_with_c_text() {
        let dir = crate::scratch::Scratch::new();
        let f = dir.write("empty.bin", b"");
        assert_eq!(
            banner_err(&["--hello-file[80]", f.to_str().unwrap()]),
            "[FAILED] could not read hello file"
        );
        assert_eq!(
            banner_err(&["--hello-file[80]", dir.dir().to_str().unwrap()]),
            "[FAILED] could not read hello file"
        );
    }

    /// Форма `--http-header` выбирается по `name += 11` от набранного имени (`src/main-conf.c:1361`, справка
    /// C3): `HTTP_HEADER[X]` скобочная, `httpheader[X]` (11-й знак не `[`) требует двоеточие в значении.
    #[test]
    fn http_header_form_by_typed_name_like_c() {
        let cfg = banner_cfg(&["--HTTP_HEADER[X]", "v"]);
        assert_eq!(cfg.http.headers, [("X".to_string(), "v".to_string())]);
        let cfg = banner_cfg(&["--httpheader[X]", "a:b"]);
        assert_eq!(cfg.http.headers, [("a".to_string(), "b".to_string())]);
        // Скобочная форма снимает пунктуацию по краям; двоеточная режет пробелы у имени и значения.
        let cfg = banner_cfg(&["--http-header[X-Lab]", " v ", "--http-header", "Y :  w"]);
        assert_eq!(
            cfg.http.headers,
            [
                ("X-Lab".to_string(), " v ".to_string()),
                ("Y".to_string(), "w".to_string()),
            ]
        );
        // Двоеточие разделителя — первое в токене, как у C и у всякого имени: внутри скобок оно режет набранное
        // имя, и остаток это незакрытая `[` (Р17).
        assert!(parse(&["--http-header[A:B]:v"]).is_err());
    }

    /// Набранное имя короче 11 знаков: `name += 11` уходит за NUL (E1.7), здесь отказ.
    #[test]
    fn http_header_short_spelling_fails() {
        for a in [
            &["--http-field", "X:v"][..],
            &["--httpheader", "X:v"][..],
            &["--http.field=X:v"][..],
        ] {
            assert!(parse(a).unwrap().to_config().is_err(), "{a:?}");
        }
    }

    /// Ни скобок, ни двоеточия: две строки C (`src/main-conf.c:1388-1390`).
    #[test]
    fn http_header_neither_form_fails_with_hint() {
        assert_eq!(
            banner_err(&["--http-header", "NoColonHere"]),
            "[-] --http-header needs both a name and value\n    hint: \"--http-header Name:value\""
        );
    }

    /// 17-й заголовок и 17-я cookie отказывают (brief; C лишнее молча отбрасывал, справка C3).
    #[test]
    fn http_header_17th_fails() {
        let mut a: Vec<String> = Vec::new();
        for i in 0..16 {
            a.push(format!("--http-header=X{i}:v"));
        }
        let refs: Vec<&str> = a.iter().map(String::as_str).collect();
        assert_eq!(banner_cfg(&refs).http.headers.len(), 16);
        a.push("--http-header=X16:v".to_string());
        let refs: Vec<&str> = a.iter().map(String::as_str).collect();
        assert!(parse(&refs).unwrap().to_config().is_err());
        let mut a: Vec<String> = (0..17).map(|_| "--http-cookie=a=b".to_string()).collect();
        let refs: Vec<&str> = a.iter().map(String::as_str).collect();
        assert!(parse(&refs).unwrap().to_config().is_err());
        a.truncate(16);
        let refs: Vec<&str> = a.iter().map(String::as_str).collect();
        assert_eq!(banner_cfg(&refs).http.cookies.len(), 16);
    }

    /// Любое другое значение `--http-*`, включая CRLF, как у C (`src/main-conf.c:1300-1505`): хранится как
    /// дано и попадает в запрос задачи 10 без нормализации.
    #[test]
    fn http_values_with_crlf_like_c() {
        let cfg = banner_cfg(&[
            "--http-host=a\r\nX: b",
            "--http-header=Y:c\nd",
            "--http-method=",
            "--http-payload=p\r\nq",
        ]);
        assert_eq!(cfg.http.host.as_deref(), Some("a\r\nX: b"));
        assert_eq!(cfg.http.method.as_deref(), Some(""));
        assert_eq!(cfg.http.payload.as_deref(), Some("p\r\nq"));
        let req = crate::banner_settings::tcp_banner_settings(&cfg)
            .unwrap()
            .http_request;
        assert!(
            req.windows(13).any(|w| w == b"Host: a\r\nX: b"),
            "{:?}",
            String::from_utf8_lossy(&req)
        );
        assert!(req.ends_with(b"p\r\nq"));
    }

    /// Те же случаи через файл `-c`: ключи файла подчиняются тем же правилам, включая набранное имя
    /// `http-header` и файл `--hello-file`.
    #[test]
    fn banner_options_in_config_file() {
        let dir = crate::scratch::Scratch::new();
        let hello = dir.write("hello.bin", b"hi");
        let text = format!(
            "hello = ssl\nhello-string[80] = QUJD\nhello-file[81] = {}\nconnection-timeout = 6\n\
             HTTP_HEADER[X] = v\nhttpheader[Y] = a:b\nhttp-method = POST\nhttp-cookie = a=b\ncapture = html\n",
            hello.display()
        );
        let f = dir.write("banner.conf", text.as_bytes());
        let cfg = banner_cfg(&["-c", f.to_str().unwrap()]);
        assert!(cfg.hello_ssl);
        assert_eq!(
            cfg.hello_strings,
            [(80, "QUJD".to_string()), (81, "aGk=".to_string())]
        );
        assert_eq!(cfg.connection_timeout, 6);
        assert_eq!(
            cfg.http.headers,
            [
                ("X".to_string(), "v".to_string()),
                ("a".to_string(), "b".to_string()),
            ]
        );
        assert_eq!(cfg.http.method.as_deref(), Some("POST"));
        assert_eq!(cfg.http.cookies, ["a=b"]);
        assert!(cfg.capture.html);
        for (name, text) in [
            ("bad-hello.conf", "hello = tls\n"),
            ("bad-b64.conf", "hello-string[80] = Q\n"),
            ("no-index.conf", "hello-string = QUJD\n"),
            ("short.conf", "http-field = X:v\n"),
            ("no-form.conf", "http-header = NoColon\n"),
            ("unclosed.conf", "http-header[X = v\n"),
            ("big-index.conf", "hello-string[65536] = QUJD\n"),
        ] {
            let f = dir.write(name, text.as_bytes());
            assert!(
                parse(&["-c", f.to_str().unwrap()])
                    .unwrap()
                    .to_config()
                    .is_err(),
                "{name}"
            );
        }
    }
}
