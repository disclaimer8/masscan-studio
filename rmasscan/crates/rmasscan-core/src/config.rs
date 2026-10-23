//! Конфигурация скана, валидация и дамп `--echo` (AGPL-3.0).
//! Порт частей `src/main-conf.c` (`masscan_echo` :3636, `masscan_echo_nic`
//! :294, `SET_*`, `masscan_read_config_file` :3883) и подготовки целей из
//! `src/main.c:1595-1733` из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Что здесь НЕ перенесено: IPv6, несколько адаптеров (`nic_count == 1`),
//! `router-ip`, `adapter-ip` как диапазон, все опции вывода/баннеров/
//! `--top-ports` (вне v1). Поэтому `echo` печатает только те ключи
//! `config_parameters[]`, которыми владеет `ScanConfig`.
//!
//! `echo(.., echo_all = true)` печатает все принадлежащие нам ключи
//! безусловно (как `masscan->echo_all` в C), но это не весь `--echo-all` C:
//! десятки ключей вне v1 здесь отсутствуют. Сам C вызывает `masscan_echo`
//! с `is_echo_all = 0` и для `--echo-all` (main.c:1803-1805), поэтому CLI
//! обязан передавать `false` в обоих случаях.

use std::fmt::Write as _;
use std::net::Ipv4Addr;

use crate::massip::{MassIp, RangeOverflow};
use crate::ranges::{RangeList, range_is_cidr};
use crate::scan::Shard;
use crate::targets::{
    self, ParseError, TEMPL_ICMP_ECHO, TEMPL_OPROTO_FIRST, TEMPL_OPROTO_LAST, TEMPL_SCTP, TEMPL_UDP,
};

/// Операция, для которой готовится конфигурация (`masscan->op`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// `-sL` (`Operation_ListScan`, main-listscan.c).
    List,
    /// Обычный скан (`Operation_Scan`, main.c:1715-1735, `main_scan`).
    Scan,
}

/// Ошибки конфигурации.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// Целей нет вообще (main.c:1717-1727: подсказка про `--range`).
    #[error("target IP address list empty (try \"--range 10.0.0.0/8\")")]
    EmptyTargets,
    /// Цели были, но исключения убрали все (main.c:1720-1721).
    #[error("target IP address list empty: all addresses were removed by exclusion ranges")]
    TargetsExcluded,
    /// Портов нет вообще (main.c:1731-1733: подсказка про `-p80`).
    #[error("no ports were specified (try \"-p80,8000-9000\")")]
    EmptyPorts,
    /// Порты были, но исключения убрали все (main.c:1729-1730).
    #[error("all ports were removed by exclusion ranges")]
    PortsExcluded,
    /// Больше 63 бит (main.c:1698-1704).
    #[error(transparent)]
    RangeOverflow(#[from] RangeOverflow),
    /// Больше 1e9 адресов без единого `--exclude` (main.c:1235-1239).
    #[error("range too big, need confirmation: at least one --exclude must be specified")]
    ExcludeRequired,
    /// `blackrock_rounds >= 64`: в C это UB-сдвиг (crypto-blackrock.c),
    /// C такое значение принимает.
    #[error("blackrock rounds must be below 64, got {0}")]
    BadBlackrockRounds(u32),
    /// `shard.of == 0` или `one == 0` или `one > of` (main-conf.c:2077-2086).
    #[error("bad shard {one}/{of}: it goes like 1/4 2/4 3/4 4/4")]
    BadShard { one: u32, of: u32 },
    /// `retries >= 1000` (main-conf.c:1943-1946).
    #[error("retries must be less than 1000, got {0}")]
    TooManyRetries(u32),
    /// Нечисловая или недопустимая скорость (main-conf.c:1880-1897; плюс
    /// отрицательные и нечисловые `f64` в `ScanConfig`).
    #[error("bad rate: {0:?}")]
    BadRate(String),
    #[error("bad MAC address: {0:?}")]
    BadMac(String),
    /// Значение ключа не разобрано.
    #[error("bad value for {key}: {value:?}")]
    BadValue { key: String, value: String },
    /// Ключ, которого нет в v1.
    #[error("unsupported config key {0:?}")]
    UnknownKey(String),
    #[error("{0}")]
    Parse(#[from] ParseError),
}

/// Все параметры скана (masscan.h `struct Masscan`, подмножество v1).
///
/// Сверх списка из задачи добавлены `adapter_name` и `offline`: их пишет и
/// читает `paused.conf` C (`adapter = lo`, `offline = true`).
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: MassIp,
    pub excludes: MassIp,
    /// C: 0 означает "взять энтропию" (main.c:1658); порт этого не делает,
    /// seed всегда задаёт вызывающий.
    pub seed: u64,
    pub max_rate: f64,
    pub retries: u32,
    pub shard: Shard,
    pub resume_index: u64,
    /// `None` и `Some(0)` — без ограничения (C: `resume.count == 0`).
    pub resume_count: Option<u64>,
    pub blackrock_rounds: u32,
    pub wait_secs: u32,
    pub adapter_ip: Option<u32>,
    pub adapter_mac: Option<[u8; 6]>,
    /// Один MAC на ipv4 и ipv6 (`--router-mac` ставит оба).
    pub router_mac: Option<[u8; 6]>,
    /// `(first, last)` включительно.
    pub source_port: Option<(u16, u16)>,
    pub adapter_name: Option<String>,
    pub offline: bool,
}

impl Default for ScanConfig {
    /// Значения main.c:1595-1613 (rounds 14, rate 100, wait 10, shard 1/1).
    fn default() -> Self {
        ScanConfig {
            targets: MassIp::new(),
            excludes: MassIp::new(),
            seed: 0,
            max_rate: 100.0,
            retries: 0,
            shard: Shard::default(),
            resume_index: 0,
            resume_count: None,
            blackrock_rounds: 14,
            wait_secs: 10,
            adapter_ip: None,
            adapter_mac: None,
            router_mac: None,
            source_port: None,
            adapter_name: None,
            offline: false,
        }
    }
}

/// Результат [`validate`]: цели с применёнными исключениями и
/// `optimize`, готовые для `scan::list_scan` / `scan::transmit_scan`.
#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    pub operation: Operation,
    pub massip: MassIp,
    /// Число комбинаций IP/порт, 1..2^63.
    pub range: u64,
    pub seed: u64,
    pub max_rate: f64,
    pub retries: u32,
    pub shard: Shard,
    pub resume_index: u64,
    pub resume_count: Option<u64>,
    pub blackrock_rounds: u32,
    pub wait_secs: u32,
    pub adapter_ip: Option<u32>,
    pub adapter_mac: Option<[u8; 6]>,
    pub router_mac: Option<[u8; 6]>,
    pub source_port: Option<(u16, u16)>,
    pub adapter_name: Option<String>,
    pub offline: bool,
}

// ---------------------------------------------------------------------
// Разбор значений
// ---------------------------------------------------------------------

/// main-conf.c:1863-1906 `SET_rate`, буквально: `rate = rate*10.0 + digit`
/// до `.`, затем `rate += digit/point`, `point *= 10.0`. Результат может
/// отличаться от `str::parse::<f64>` на последний бит (C: `0.29` и `0.33`
/// дают другие числа строк в `-sL --retries 100`), поэтому `parse::<f64>`
/// использовать нельзя. Пустая строка даёт 0.0, как в C.
pub fn parse_rate(value: &str) -> Result<f64, ConfigError> {
    let bad = || ConfigError::BadRate(value.to_string());
    let mut rate = 0.0f64;
    let mut point = 10.0f64;
    let b = value.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i] != b'.' {
        if !b[i].is_ascii_digit() {
            return Err(bad());
        }
        rate = rate * 10.0 + f64::from(b[i] - b'0');
        i += 1;
    }
    if i < b.len() {
        i += 1; // '.'
        while i < b.len() {
            if !b[i].is_ascii_digit() {
                return Err(bad());
            }
            rate += f64::from(b[i] - b'0') / point;
            point *= 10.0;
            i += 1;
        }
    }
    Ok(rate)
}

/// main-conf.c:2059-2092 `SET_shard`: цифры, пропуск пунктуации, цифры.
/// `one`/`of` — `unsigned` с обёрткой, как в C.
pub fn parse_shard(value: &str) -> Result<Shard, ConfigError> {
    let b = value.as_bytes();
    let mut i = 0;
    let (mut one, mut of) = (0u32, 0u32);
    while i < b.len() && b[i].is_ascii_digit() {
        one = one.wrapping_mul(10).wrapping_add(u32::from(b[i] - b'0'));
        i += 1;
    }
    while i < b.len() && b[i].is_ascii_punctuation() {
        i += 1;
    }
    while i < b.len() && b[i].is_ascii_digit() {
        of = of.wrapping_mul(10).wrapping_add(u32::from(b[i] - b'0'));
        i += 1;
    }
    check_shard(Shard { one, of })
}

fn check_shard(s: Shard) -> Result<Shard, ConfigError> {
    if s.one < 1 || s.one > s.of {
        Err(ConfigError::BadShard {
            one: s.one,
            of: s.of,
        })
    } else {
        Ok(s)
    }
}

/// main-conf.c `parse_mac_address`: шесть пар hex-цифр, между парами один
/// знак пунктуации. Как в C, хвост после шестой пары игнорируется.
pub fn parse_mac(value: &str) -> Result<[u8; 6], ConfigError> {
    let bad = || ConfigError::BadMac(value.to_string());
    let b = value.as_bytes();
    let mut i = 0;
    let mut mac = [0u8; 6];
    for byte in &mut mac {
        let hi = b
            .get(i)
            .and_then(|c| (*c as char).to_digit(16))
            .ok_or_else(bad)?;
        let lo = b
            .get(i + 1)
            .and_then(|c| (*c as char).to_digit(16))
            .ok_or_else(bad)?;
        *byte = (hi * 16 + lo) as u8;
        i += 2;
        if b.get(i).is_some_and(u8::is_ascii_punctuation) {
            i += 1;
        }
    }
    Ok(mac)
}

/// `adapter-port` / `--source-port` (main-conf.c:2523-2554): ровно один
/// диапазон, размер — степень двойки.
pub fn parse_source_port(value: &str) -> Result<(u16, u16), ConfigError> {
    let bad = || ConfigError::BadValue {
        key: "adapter-port".into(),
        value: value.into(),
    };
    let mut list = RangeList::new();
    targets::parse_ports(&mut list, value)?;
    if list.len() != 1 {
        return Err(bad());
    }
    let r = list.get(0);
    let (Ok(first), Ok(last)) = (u16::try_from(r.begin), u16::try_from(r.end)) else {
        return Err(bad());
    };
    if !(u32::from(last) - u32::from(first) + 1).is_power_of_two() {
        return Err(bad());
    }
    Ok((first, last))
}

// ---------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------

/// Подготовка конфигурации в порядке main.c:1671-1735 и :1232-1237.
///
/// 1. проверки отдельных значений (шард, раунды, скорость, retries);
/// 2. запоминаем, были ли цели и порты до исключений (main.c:1671-1672);
/// 3. `apply_excludes` (main.c:1673);
/// 4. только для `-sL`: нет портов -> порт 80 (main.c:1674-1675);
/// 5. `optimize` (main.c:1684);
/// 6. диапазон не больше 63 бит (main.c:1698-1704);
/// 7. только для `-sL`: если после исключений портов нет, добавляется 80
///    ещё раз (main-listscan.c:19-20, исключения уже не применяются);
/// 8. пустые списки (main.c:1715-1733; `EmptyPorts` только для скана:
///    у `-sL` порт 80 уже добавлен);
/// 9. только для скана: больше 1e9 адресов требует `--exclude`
///    (main.c:1232-1237, это `main_scan`; `-sL` этого не проверяет).
///
/// Пустая цель при `-sL` в C — деление на ноль в `blackrock_init`
/// (crypto-blackrock.c:117), здесь `EmptyTargets`.
pub fn validate(cfg: &ScanConfig, op: Operation) -> Result<EffectiveConfig, ConfigError> {
    check_shard(cfg.shard)?;
    if cfg.blackrock_rounds >= 64 {
        return Err(ConfigError::BadBlackrockRounds(cfg.blackrock_rounds));
    }
    if cfg.retries >= 1000 {
        return Err(ConfigError::TooManyRetries(cfg.retries));
    }
    if !cfg.max_rate.is_finite() || cfg.max_rate < 0.0 {
        return Err(ConfigError::BadRate(format!("{}", cfg.max_rate)));
    }

    let mut massip = cfg.targets.clone();
    let mut excludes = cfg.excludes.clone();
    let has_addresses = !massip.ipv4().is_empty(); // main.c:1671
    let has_ports = !massip.ports().is_empty(); // main.c:1672
    massip.apply_excludes(&mut excludes);
    if op == Operation::List && !has_ports {
        massip.ports_mut().add_range(80, 80);
    }
    massip.optimize();

    massip.try_range()?;

    if op == Operation::List && massip.ports().is_empty() {
        massip.ports_mut().add_range(80, 80);
        massip.optimize();
    }

    if massip.ipv4().is_empty() {
        return Err(if has_addresses {
            ConfigError::TargetsExcluded
        } else {
            ConfigError::EmptyTargets
        });
    }
    if massip.ports().is_empty() {
        return Err(if has_ports {
            ConfigError::PortsExcluded
        } else {
            ConfigError::EmptyPorts
        });
    }
    if op == Operation::Scan
        && massip.count_ipv4s() > 1_000_000_000
        && cfg.excludes.ipv4().is_empty()
    {
        return Err(ConfigError::ExcludeRequired);
    }

    let range = massip.try_range()?;
    Ok(EffectiveConfig {
        operation: op,
        massip,
        range,
        seed: cfg.seed,
        max_rate: cfg.max_rate,
        retries: cfg.retries,
        shard: cfg.shard,
        resume_index: cfg.resume_index,
        resume_count: cfg.resume_count,
        blackrock_rounds: cfg.blackrock_rounds,
        wait_secs: cfg.wait_secs,
        adapter_ip: cfg.adapter_ip,
        adapter_mac: cfg.adapter_mac,
        router_mac: cfg.router_mac,
        source_port: cfg.source_port,
        adapter_name: cfg.adapter_name.clone(),
        offline: cfg.offline,
    })
}

// ---------------------------------------------------------------------
// echo
// ---------------------------------------------------------------------

/// main-conf.c:1868-1876: ветка "целое" или `%f`.
///
/// C считает `(unsigned)(max_rate * 100000) % 100000`. Для `max_rate`
/// больше ~42949 это UB (результат не помещается в `unsigned`); gcc на
/// x86-64 берёт младшие 32 бита 64-битного преобразования. Мы делаем то же
/// намеренно: `f64 -> u64 -> u32` (усечение). Из-за этого `250000` печатается
/// как `250000.000000` (так в golden `echo/everything.conf`), а `5000` как
/// `5000      ` (`%-10.0f`).
fn format_rate(max_rate: f64) -> String {
    let scaled = (max_rate * 100000.0) as u64 as u32;
    if !scaled.is_multiple_of(100000) {
        format!("rate = {max_rate:.6}\n")
    } else {
        format!("rate = {max_rate:<10.0}\n")
    }
}

fn fmt_mac(mac: [u8; 6]) -> String {
    // massip-addr.c:165 macaddress_fmt: строчный hex через '-'.
    mac.map(|b| format!("{b:02x}")).join("-")
}

/// main-conf.c:3681-3732: порты как `ports = 80,443,8080-8090`, с
/// префиксами `U:`/`S:`/`O:`/`I:` для не-TCP (цикл C перенесён буквально).
fn echo_ports(out: &mut String, ports: &RangeList) {
    out.push_str("ports = ");
    let mut l = false;
    for r in ports.as_slice() {
        let mut range = *r;
        loop {
            let mut rr = range;
            let mut done = false;
            if l {
                out.push(',');
            }
            l = true;
            if rr.begin >= TEMPL_ICMP_ECHO {
                rr.begin = rr.begin.wrapping_sub(TEMPL_ICMP_ECHO);
                rr.end = rr.end.wrapping_sub(TEMPL_ICMP_ECHO);
                out.push_str("I:");
                done = true;
            } else if rr.begin >= TEMPL_SCTP {
                rr.begin -= TEMPL_SCTP;
                rr.end = rr.end.wrapping_sub(TEMPL_SCTP);
                out.push_str("S:");
                range.begin = TEMPL_ICMP_ECHO;
            } else if rr.begin >= TEMPL_UDP {
                rr.begin -= TEMPL_UDP;
                rr.end = rr.end.wrapping_sub(TEMPL_UDP);
                out.push_str("U:");
                range.begin = TEMPL_SCTP;
            } else if (TEMPL_OPROTO_FIRST..=TEMPL_OPROTO_LAST).contains(&rr.begin) {
                // Недостижимо (OPROTO >= ICMP_ECHO), как и в C.
                rr.begin -= TEMPL_OPROTO_FIRST;
                rr.end = rr.end.wrapping_sub(TEMPL_OPROTO_FIRST);
                out.push_str("O:");
                range.begin = TEMPL_OPROTO_FIRST;
            } else {
                range.begin = TEMPL_UDP;
            }
            rr.end = rr.end.min(65535);
            if rr.begin == rr.end {
                let _ = write!(out, "{}", rr.begin);
            } else {
                let _ = write!(out, "{}-{}", rr.begin, rr.end);
            }
            if done || range.begin > range.end {
                break;
            }
        }
    }
    out.push('\n');
}

fn echo_range(out: &mut String, r: crate::ranges::Range) {
    // main-conf.c:3721-3760.
    let a = Ipv4Addr::from(r.begin);
    if r.begin == r.end {
        let _ = writeln!(out, "range = {a}");
    } else if let Some(prefix) = range_is_cidr(r) {
        let _ = writeln!(out, "range = {a}/{prefix}");
    } else {
        let _ = writeln!(out, "range = {a}-{}", Ipv4Addr::from(r.end));
    }
}

/// Дамп конфигурации в формате `paused.conf` (main-conf.c:3636
/// `masscan_echo`): сначала ключи таблицы `config_parameters[]` в её
/// порядке, затем адаптер, `adapter-port`, цели.
///
/// Как в C, цели печатаются после применения исключений (main.c:1673 до
/// `--echo`), порт 80 не добавляется. `--wait` и `--blackrock-rounds` C не
/// печатает (main-conf.c:2763, :3028), поэтому здесь тоже. 63-битную
/// проверку (main.c:1698) делает [`validate`], `echo` её не повторяет.
///
/// `echo_all`: см. документацию модуля.
pub fn echo(cfg: &ScanConfig, echo_all: bool, out: &mut String) {
    // resume-index / resume-count (main-conf.c:1913-1934).
    if cfg.resume_index != 0 || echo_all {
        let _ = write!(
            out,
            "\n# resume information\nresume-index = {}\n",
            cfg.resume_index
        );
    }
    let count = cfg.resume_count.unwrap_or(0);
    if count != 0 || echo_all {
        let _ = writeln!(out, "resume-count = {count}");
    }
    let _ = writeln!(out, "seed = {}", cfg.seed); // :2038, всегда
    out.push_str(&format_rate(cfg.max_rate));
    if cfg.shard.of > 0 || echo_all {
        let _ = writeln!(out, "shard = {}/{}", cfg.shard.one, cfg.shard.of); // :2067
    }
    if cfg.retries != 0 || echo_all {
        let _ = writeln!(out, "retries = {}", cfg.retries); // :1936
    }
    if cfg.offline || echo_all {
        let _ = writeln!(out, "offline = {}", cfg.offline); // :1603
    }
    // SET_capture (main-conf.c:1132) стоит в таблице дважды ("capture" и
    // "nocapture"), поэтому блок печатается дважды. Умолчания C:
    // cert захватывается, остальное нет (main.c:1611).
    for _ in 0..2 {
        if echo_all {
            out.push_str("capture = cert\n");
        }
        out.push_str("nocapture = servername\n");
        if echo_all {
            out.push_str("nocapture = html\nnocapture = heartbleed\nnocapture = ticketbleed\n");
        }
    }
    out.push_str("\n\n"); // две записи SPACE (:2048)

    // masscan_echo_nic (main-conf.c:294-388), nic_count == 1.
    if let Some(name) = cfg.adapter_name.as_deref().filter(|n| !n.is_empty()) {
        let _ = writeln!(out, "adapter = {name}");
    }
    if let Some(ip) = cfg.adapter_ip.filter(|&ip| ip != 0) {
        let _ = writeln!(out, "adapter-ip = {}", Ipv4Addr::from(ip));
    }
    if let Some(mac) = cfg.adapter_mac {
        let _ = writeln!(out, "adapter-mac = {}", fmt_mac(mac));
    }
    if let Some(mac) = cfg.router_mac.filter(|m| *m != [0u8; 6]) {
        let _ = writeln!(out, "router-mac-ipv4 = {}", fmt_mac(mac));
        let _ = writeln!(out, "router-mac-ipv6 = {}", fmt_mac(mac));
    }
    // adapter-port (main-conf.c:3666-3676).
    if let Some((first, last)) = cfg.source_port.filter(|&(f, _)| f != 0) {
        let _ = write!(out, "adapter-port = {first}");
        if first != last {
            let _ = write!(out, "-{last}");
        }
        out.push('\n');
    }

    // Цели после исключений и сортировки (main.c:1673, :1684).
    let mut targets = cfg.targets.clone();
    let mut excludes = cfg.excludes.clone();
    targets.apply_excludes(&mut excludes);
    targets.optimize();
    out.push_str("# TARGET SELECTION (IP, PORTS, EXCLUDES)\n");
    echo_ports(out, targets.ports());
    for r in targets.ipv4().as_slice() {
        echo_range(out, *r);
    }
}

// ---------------------------------------------------------------------
// paused.conf
// ---------------------------------------------------------------------

/// C `isspace` для ASCII.
fn is_c_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

/// main-conf.c:2000 `parseInt`, но строже: нужна хотя бы одна цифра, а
/// переполнение `u64` — ошибка (C молча оборачивает и принимает мусор как 0).
/// Как в C, читаются ведущие цифры; хвост (например ` # comment`) отбрасывается.
fn parse_int(key: &str, value: &str) -> Result<u64, ConfigError> {
    let bad = || ConfigError::BadValue {
        key: key.into(),
        value: value.into(),
    };
    let digits = value.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return Err(bad());
    }
    value[..digits].parse::<u64>().map_err(|_| bad())
}

fn parse_u32(key: &str, value: &str) -> Result<u32, ConfigError> {
    u32::try_from(parse_int(key, value)?).map_err(|_| ConfigError::BadValue {
        key: key.into(),
        value: value.into(),
    })
}

/// main-conf.c:176 `parseBoolean` (по первому символу).
fn parse_bool(value: &str) -> bool {
    match value.bytes().next() {
        None => true,
        Some(c) if c.is_ascii_digit() => value
            .bytes()
            .take_while(u8::is_ascii_digit)
            .any(|d| d != b'0'),
        Some(b'd' | b'D' | b'f' | b'F' | b'n' | b'N') => false,
        Some(b'o' | b'O') => !matches!(value.as_bytes().get(1), Some(b'f' | b'F')),
        Some(_) => true,
    }
}

/// Читает `paused.conf` / вывод [`echo`] (main-conf.c:3883
/// `masscan_read_config_file`): строки `name = value`.
///
/// Как в C: строка обрезается по пробелам, пустые строки и строки,
/// начинающиеся со знака пунктуации (`#...`), пропускаются
/// (:3900-3906); строка без `=` пропускается; имя и значение режутся по
/// первому `=` и обрезаются. Комментарий в конце значения C не вырезает:
/// `seed = 5 # x` даёт значение `5 # x`. Числовые ключи берут ведущие цифры
/// (`5`), а `ports` понимает `#` сам; `range` с таким хвостом даст ошибку
/// разбора.
///
/// Отличия от C: неизвестный ключ — `UnknownKey` (C вызывает exit(1)),
/// нечисловое значение — `BadValue` (C берёт 0). Строки `capture`/`nocapture`
/// проверяются и пропускаются (на скан не влияют), `router-mac-ipv4` и
/// `-ipv6` с разными значениями не представимы одним `router_mac` и дают
/// `BadValue`.
pub fn read_paused_conf(text: &str) -> Result<ScanConfig, ConfigError> {
    let mut cfg = ScanConfig::default();
    let (mut mac4, mut mac6) = (None, None);
    for raw in text.lines() {
        let line = raw.trim_matches(is_c_space);
        if line.is_empty() || line.as_bytes()[0].is_ascii_punctuation() {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim_matches(is_c_space);
        let value = value.trim_matches(is_c_space);
        let bad = || ConfigError::BadValue {
            key: name.into(),
            value: value.into(),
        };
        match name.to_ascii_lowercase().as_str() {
            "resume-index" => cfg.resume_index = parse_int(name, value)?,
            "resume-count" => {
                cfg.resume_count = Some(parse_int(name, value)?).filter(|&c| c != 0);
            }
            "seed" => cfg.seed = parse_int(name, value)?,
            "rate" | "max-rate" => cfg.max_rate = parse_rate(value)?,
            "shard" | "shards" => cfg.shard = parse_shard(value)?,
            "retries" | "retry" | "max-retries" | "max-retry" => {
                let n = parse_u32(name, value)?;
                if n >= 1000 {
                    return Err(ConfigError::TooManyRetries(n));
                }
                cfg.retries = n;
            }
            "offline" | "notransmit" | "nosend" | "dry-run" => cfg.offline = parse_bool(value),
            "blackrock-rounds" => cfg.blackrock_rounds = parse_u32(name, value)?,
            "wait" => cfg.wait_secs = parse_u32(name, value)?,
            "capture" | "nocapture" | "no-capture" => {
                if !["cert", "servername", "html", "heartbleed", "ticketbleed"]
                    .iter()
                    .any(|k| k.eq_ignore_ascii_case(value))
                {
                    return Err(bad());
                }
            }
            "adapter" | "if" | "interface" => cfg.adapter_name = Some(value.to_string()),
            "adapter-ip" | "source-ip" => {
                let ip: Ipv4Addr = value.parse().map_err(|_| bad())?;
                cfg.adapter_ip = Some(ip.into());
            }
            "adapter-mac" | "source-mac" => cfg.adapter_mac = Some(parse_mac(value)?),
            "router-mac" => {
                let m = parse_mac(value)?;
                (mac4, mac6) = (Some(m), Some(m));
            }
            "router-mac-ipv4" => mac4 = Some(parse_mac(value)?),
            "router-mac-ipv6" => mac6 = Some(parse_mac(value)?),
            "adapter-port" | "source-port" => cfg.source_port = Some(parse_source_port(value)?),
            "ports" | "port" => targets::parse_ports(cfg.targets.ports_mut(), value)?,
            "range" => targets::add_target_string(cfg.targets.ipv4_mut(), value)?,
            "exclude" => targets::add_target_string(cfg.excludes.ipv4_mut(), value)?,
            _ => return Err(ConfigError::UnknownKey(name.to_string())),
        }
    }
    if let (Some(a), Some(b)) = (mac4, mac6)
        && a != b
    {
        return Err(ConfigError::BadValue {
            key: "router-mac-ipv6".into(),
            value: fmt_mac(b),
        });
    }
    cfg.router_mac = mac4.or(mac6);
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::list_scan_indices;

    fn cfg_with(targets_s: &str, ports_s: &str) -> ScanConfig {
        let mut cfg = ScanConfig::default();
        if !targets_s.is_empty() {
            targets::add_target_string(cfg.targets.ipv4_mut(), targets_s).unwrap();
        }
        if !ports_s.is_empty() {
            targets::parse_ports(cfg.targets.ports_mut(), ports_s).unwrap();
        }
        cfg
    }

    fn exclude(cfg: &mut ScanConfig, s: &str) {
        targets::add_target_string(cfg.excludes.ipv4_mut(), s).unwrap();
    }

    fn err(cfg: &ScanConfig, op: Operation) -> ConfigError {
        validate(cfg, op).unwrap_err()
    }

    #[test]
    fn defaults_match_c() {
        let c = ScanConfig::default();
        assert_eq!(c.blackrock_rounds, 14);
        assert_eq!(c.max_rate, 100.0);
        assert_eq!(c.wait_secs, 10);
        assert_eq!(c.shard, Shard { one: 1, of: 1 });
        assert_eq!((c.retries, c.resume_index, c.resume_count), (0, 0, None));
        assert_eq!(
            (c.adapter_ip, c.adapter_mac, c.router_mac, c.source_port),
            (None, None, None, None)
        );
    }

    // ---- parse_rate ----

    #[test]
    fn parse_rate_simple_values() {
        assert_eq!(parse_rate("100"), Ok(100.0));
        assert_eq!(parse_rate("250000"), Ok(250000.0));
        assert_eq!(parse_rate("1.5"), Ok(1.5));
        assert_eq!(parse_rate(""), Ok(0.0));
        assert_eq!(parse_rate("."), Ok(0.0));
    }

    #[test]
    fn parse_rate_rejects_non_digits() {
        for s in ["1e3", "-1", "1.2.3", "abc", " 5", "5 "] {
            assert_eq!(parse_rate(s), Err(ConfigError::BadRate(s.into())), "{s}");
        }
    }

    #[test]
    fn parse_rate_differs_from_std_parse_like_c() {
        // C даёт другие double, чем корректно округляющий разбор.
        assert_ne!(parse_rate("0.29").unwrap(), 0.29);
        assert_ne!(parse_rate("0.33").unwrap(), 0.33);
    }

    #[test]
    fn rate_c_semantics_visible_in_list_scan_line_count() {
        // Оракул C: `-sL --retries 100` -> 285 строк для 0.29 и 288 для 0.33
        // (корректное округление дало бы 284 и 289).
        let count = |s: &str| {
            let rate = parse_rate(s).unwrap();
            list_scan_indices(256, Shard::default(), 0, None, 100, rate).count()
        };
        assert_eq!(count("0.29"), 285);
        assert_eq!(count("0.33"), 288);
    }

    // ---- format_rate ----

    #[test]
    fn rate_echo_branches() {
        assert_eq!(format_rate(100.0), "rate = 100       \n");
        assert_eq!(format_rate(5000.0), "rate = 5000      \n");
        assert_eq!(format_rate(0.5), "rate = 0.500000\n");
        assert_eq!(
            format_rate(parse_rate("0.29").unwrap()),
            "rate = 0.290000\n"
        );
        // > 42949: UB в C, gcc/x86-64 берёт младшие 32 бита.
        assert_eq!(format_rate(250000.0), "rate = 250000.000000\n");
        // 42949 * 100000 = 4294900000 < 2^32: ещё целое.
        assert_eq!(format_rate(42949.0), "rate = 42949     \n");
        // 2^32 / 100000 = 42949.67..., 100000.0 * 100000 = 1e10 = 2*2^32 + 1410065408
        // -> 1410065408 % 100000 = 8 != 0.
        assert_eq!(format_rate(100000.0), "rate = 100000.000000\n");
    }

    // ---- shard / mac / source port ----

    #[test]
    fn parse_shard_cases() {
        assert_eq!(parse_shard("2/3"), Ok(Shard { one: 2, of: 3 }));
        assert_eq!(parse_shard("1-1"), Ok(Shard { one: 1, of: 1 }));
        assert_eq!(
            parse_shard("0/3"),
            Err(ConfigError::BadShard { one: 0, of: 3 })
        );
        assert_eq!(
            parse_shard("4/3"),
            Err(ConfigError::BadShard { one: 4, of: 3 })
        );
        assert_eq!(
            parse_shard("1"),
            Err(ConfigError::BadShard { one: 1, of: 0 })
        );
    }

    #[test]
    fn parse_mac_cases() {
        assert_eq!(
            parse_mac("00-11-22-33-44-55"),
            Ok([0, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(
            parse_mac("aa:BB:cc:dd:ee:ff"),
            Ok([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac("00-11-22"),
            Err(ConfigError::BadMac("00-11-22".into()))
        );
        assert_eq!(
            parse_mac("zz-11-22-33-44-55"),
            Err(ConfigError::BadMac("zz-11-22-33-44-55".into()))
        );
    }

    #[test]
    fn parse_source_port_cases() {
        assert_eq!(parse_source_port("40000"), Ok((40000, 40000)));
        assert_eq!(parse_source_port("40000-40003"), Ok((40000, 40003)));
        assert!(matches!(
            parse_source_port("40000-40002"),
            Err(ConfigError::BadValue { .. })
        ));
        assert!(matches!(
            parse_source_port("80,90"),
            Err(ConfigError::BadValue { .. })
        ));
    }

    // ---- validate ----

    #[test]
    fn validate_rejects_empty_ports_for_scan() {
        let cfg = cfg_with("10.0.0.0/24", "");
        assert_eq!(err(&cfg, Operation::Scan), ConfigError::EmptyPorts); // main.c:1733
    }

    #[test]
    fn validate_rejects_empty_targets() {
        let cfg = cfg_with("", "80");
        assert_eq!(err(&cfg, Operation::Scan), ConfigError::EmptyTargets);
        assert_eq!(err(&cfg, Operation::List), ConfigError::EmptyTargets);
    }

    #[test]
    fn validate_distinguishes_everything_excluded() {
        let mut cfg = cfg_with("10.0.0.0/24", "80");
        exclude(&mut cfg, "10.0.0.0/24");
        assert_eq!(err(&cfg, Operation::Scan), ConfigError::TargetsExcluded);

        let mut cfg = cfg_with("10.0.0.0/24", "80");
        targets::parse_ports(cfg.excludes.ports_mut(), "80").unwrap();
        assert_eq!(err(&cfg, Operation::Scan), ConfigError::PortsExcluded);
    }

    #[test]
    fn validate_list_adds_port_80_when_no_ports() {
        let cfg = cfg_with("10.0.0.0/30", "");
        let eff = validate(&cfg, Operation::List).unwrap();
        assert_eq!(eff.range, 4);
        assert_eq!(eff.massip.count_ports(), 1);
        assert!(eff.massip.has_port(80));
        // входная конфигурация не изменилась
        assert!(cfg.targets.ports().is_empty());
    }

    #[test]
    fn validate_list_readds_port_80_when_excludes_removed_all_ports() {
        // main-listscan.c:19-20: порт 80 возвращается, даже если исключён.
        let mut cfg = cfg_with("10.0.0.0/30", "443");
        targets::parse_ports(cfg.excludes.ports_mut(), "443").unwrap();
        let eff = validate(&cfg, Operation::List).unwrap();
        assert!(eff.massip.has_port(80));
        assert_eq!(eff.range, 4);
    }

    #[test]
    fn validate_applies_excludes_before_optimize() {
        let mut cfg = cfg_with("10.0.0.0/30", "80,443");
        exclude(&mut cfg, "10.0.0.1-10.0.0.2");
        let eff = validate(&cfg, Operation::Scan).unwrap();
        assert_eq!(eff.range, 4);
        assert_eq!(eff.massip.pick(1), (0x0a00_0003, 80));
    }

    #[test]
    fn validate_rejects_over_63_bits() {
        // 2^32 адресов * 2^31 портов = 2^63 (main.c:1698-1704).
        let mut cfg = ScanConfig::default();
        cfg.targets.ipv4_mut().add_range(0, u32::MAX);
        cfg.targets.ports_mut().add_range(0, 0x7fff_ffff);
        assert_eq!(
            err(&cfg, Operation::List),
            ConfigError::RangeOverflow(RangeOverflow)
        );
        assert_eq!(
            err(&cfg, Operation::Scan),
            ConfigError::RangeOverflow(RangeOverflow)
        );
    }

    #[test]
    fn validate_accepts_largest_63_bit_range() {
        let mut cfg = ScanConfig::default();
        cfg.targets.ipv4_mut().add_range(0, u32::MAX);
        cfg.targets.ports_mut().add_range(0, 0x7fff_fffe);
        exclude(&mut cfg, "255.255.255.255");
        // minus one address: still under 2^63.
        let eff = validate(&cfg, Operation::Scan).unwrap();
        assert_eq!(eff.range, ((1u64 << 32) - 1) * ((1u64 << 31) - 1));
    }

    #[test]
    fn validate_requires_exclude_over_1e9_addresses_for_scan_only() {
        let cfg = cfg_with("0.0.0.0/1", "80"); // 2^31 > 1e9
        assert_eq!(err(&cfg, Operation::Scan), ConfigError::ExcludeRequired);
        assert!(validate(&cfg, Operation::List).is_ok()); // main_scan only
        let mut cfg = cfg;
        exclude(&mut cfg, "255.255.255.255"); // подтверждение, ничего не вырезает
        assert!(validate(&cfg, Operation::Scan).is_ok());
    }

    #[test]
    fn validate_rejects_bad_rounds_shard_retries_rate() {
        let mut cfg = cfg_with("10.0.0.0/24", "80");
        cfg.blackrock_rounds = 64;
        assert_eq!(
            err(&cfg, Operation::Scan),
            ConfigError::BadBlackrockRounds(64)
        );
        cfg.blackrock_rounds = 63;
        assert!(validate(&cfg, Operation::Scan).is_ok());

        cfg.shard = Shard { one: 1, of: 0 };
        assert_eq!(
            err(&cfg, Operation::List),
            ConfigError::BadShard { one: 1, of: 0 }
        );
        cfg.shard = Shard { one: 3, of: 2 };
        assert_eq!(
            err(&cfg, Operation::List),
            ConfigError::BadShard { one: 3, of: 2 }
        );
        cfg.shard = Shard { one: 0, of: 2 };
        assert_eq!(
            err(&cfg, Operation::List),
            ConfigError::BadShard { one: 0, of: 2 }
        );
        cfg.shard = Shard::default();

        cfg.retries = 1000;
        assert_eq!(
            err(&cfg, Operation::Scan),
            ConfigError::TooManyRetries(1000)
        );
        cfg.retries = 0;

        cfg.max_rate = f64::NAN;
        assert!(matches!(
            err(&cfg, Operation::Scan),
            ConfigError::BadRate(_)
        ));
        cfg.max_rate = -1.0;
        assert!(matches!(
            err(&cfg, Operation::Scan),
            ConfigError::BadRate(_)
        ));
    }

    #[test]
    fn effective_config_feeds_list_scan() {
        let mut cfg = cfg_with("10.0.0.0/30", "80");
        cfg.seed = 1;
        let eff = validate(&cfg, Operation::List).unwrap();
        let mut n = 0;
        crate::scan::list_scan(
            &eff.massip,
            eff.seed,
            eff.blackrock_rounds,
            eff.shard,
            eff.resume_index,
            eff.resume_count,
            eff.retries,
            eff.max_rate,
            |_, _| n += 1,
        )
        .unwrap();
        assert_eq!(n, 4);
    }

    // ---- echo / read ----

    #[test]
    fn echo_roundtrips_through_paused_conf() {
        let mut cfg = cfg_with("10.0.0.0/24", "80,443");
        cfg.seed = 1;
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        let cfg2 = read_paused_conf(&s).unwrap();
        let mut s2 = String::new();
        echo(&cfg2, false, &mut s2);
        assert_eq!(s, s2);
    }

    #[test]
    fn echo_full_roundtrip_all_fields() {
        let mut cfg = cfg_with("10.0.0.0/24,192.168.1.0-192.168.1.20", "22,80,8080-8090");
        cfg.seed = 4294967295;
        cfg.max_rate = 0.29;
        cfg.retries = 3;
        cfg.shard = Shard { one: 2, of: 3 };
        cfg.resume_index = 77;
        cfg.resume_count = Some(5);
        cfg.adapter_ip = Some(0x0aff_0001);
        cfg.adapter_mac = Some([1, 2, 3, 4, 5, 6]);
        cfg.router_mac = Some([6, 5, 4, 3, 2, 1]);
        cfg.source_port = Some((40000, 40003));
        cfg.adapter_name = Some("eth0".into());
        cfg.offline = true;
        for all in [false, true] {
            let mut s = String::new();
            echo(&cfg, all, &mut s);
            let back = read_paused_conf(&s).unwrap();
            assert_eq!(back.seed, cfg.seed);
            assert!((back.max_rate - 0.29).abs() < 1e-6); // печать %f: 6 знаков
            assert_eq!(back.retries, 3);
            assert_eq!(back.shard, cfg.shard);
            assert_eq!(back.resume_index, 77);
            assert_eq!(back.resume_count, Some(5));
            assert_eq!(back.adapter_ip, cfg.adapter_ip);
            assert_eq!(back.adapter_mac, cfg.adapter_mac);
            assert_eq!(back.router_mac, cfg.router_mac);
            assert_eq!(back.source_port, cfg.source_port);
            assert_eq!(back.adapter_name, cfg.adapter_name);
            assert!(back.offline);
            let mut s2 = String::new();
            echo(&back, all, &mut s2);
            assert_eq!(s, s2);
        }
    }

    #[test]
    fn echo_prints_cidr_single_and_dashed_ranges() {
        let cfg = cfg_with("10.0.0.0/24,10.0.2.5,10.0.3.1-10.0.3.5,0.0.0.0/8", "1-3,80");
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        assert!(s.contains("ports = 1-3,80\n"), "{s}");
        assert!(s.contains("range = 0.0.0.0/8\n"));
        assert!(s.contains("range = 10.0.0.0/24\nrange = 10.0.2.5\nrange = 10.0.3.1-10.0.3.5\n"));
    }

    #[test]
    fn echo_applies_excludes_and_does_not_add_port_80() {
        let mut cfg = cfg_with("10.0.0.0/24", "");
        exclude(&mut cfg, "10.0.0.128/25");
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        assert!(s.ends_with("ports = \nrange = 10.0.0.0/25\n"), "{s}");
    }

    #[test]
    fn echo_prints_non_tcp_ports_with_prefixes() {
        let mut cfg = cfg_with("10.0.0.1", "");
        cfg.targets.ports_mut().add_range(80, 80);
        cfg.targets
            .ports_mut()
            .add_range(TEMPL_UDP + 53, TEMPL_UDP + 53);
        cfg.targets
            .ports_mut()
            .add_range(TEMPL_SCTP + 7, TEMPL_SCTP + 9);
        cfg.targets
            .ports_mut()
            .add_range(TEMPL_ICMP_ECHO, TEMPL_ICMP_ECHO);
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        assert!(s.contains("ports = 80,U:53,S:7-9,I:0\n"), "{s}");
    }

    #[test]
    fn echo_all_prints_defaults() {
        let cfg = cfg_with("10.0.0.1", "80");
        let mut s = String::new();
        echo(&cfg, true, &mut s);
        for line in [
            "resume-index = 0\n",
            "resume-count = 0\n",
            "retries = 0\n",
            "offline = false\n",
            "capture = cert\n",
            "nocapture = html\n",
        ] {
            assert!(s.contains(line), "missing {line:?} in {s}");
        }
        let mut plain = String::new();
        echo(&cfg, false, &mut plain);
        assert!(!plain.contains("resume-index"));
        assert!(!plain.contains("retries"));
        assert!(!plain.contains("offline"));
    }

    #[test]
    fn read_skips_comments_blank_and_punct_lines() {
        let text =
            "# comment\n\n  # indented comment\n; semi\nseed = 5\nnoequals\n  ports = 80  \n";
        let cfg = read_paused_conf(text).unwrap();
        assert_eq!(cfg.seed, 5);
        assert_eq!(cfg.targets.ports().as_slice().len(), 1);
    }

    #[test]
    fn read_keeps_trailing_comment_in_value_like_c() {
        // main-conf.c:3906-3920: комментарий остаётся в значении.
        let cfg = read_paused_conf("seed = 5 # note\nports = 80 # web\nrate = 100\n").unwrap();
        assert_eq!(cfg.seed, 5); // parseInt берёт ведущие цифры
        assert_eq!(cfg.targets.ports().get(0).begin, 80); // parse_ports сам останавливается на '#'
        // rate берёт значение целиком, "# " не цифра
        assert!(matches!(
            read_paused_conf("rate = 100 # note\n"),
            Err(ConfigError::BadRate(v)) if v == "100 # note"
        ));
        // range с хвостом разбирается как мусор
        assert!(matches!(
            read_paused_conf("range = 10.0.0.0/24 # note\n"),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn read_errors_have_exact_variants() {
        assert_eq!(
            read_paused_conf("bogus = 1\n").unwrap_err(),
            ConfigError::UnknownKey("bogus".into())
        );
        assert_eq!(
            read_paused_conf("seed = abc\n").unwrap_err(),
            ConfigError::BadValue {
                key: "seed".into(),
                value: "abc".into()
            }
        );
        assert_eq!(
            read_paused_conf("shard = 3/2\n").unwrap_err(),
            ConfigError::BadShard { one: 3, of: 2 }
        );
        assert_eq!(
            read_paused_conf("retries = 1000\n").unwrap_err(),
            ConfigError::TooManyRetries(1000)
        );
        assert_eq!(
            read_paused_conf("adapter-mac = nope\n").unwrap_err(),
            ConfigError::BadMac("nope".into())
        );
        assert_eq!(
            read_paused_conf("ports = U:53\n").unwrap_err(),
            ConfigError::Parse(ParseError::UnsupportedProtoPrefix)
        );
        assert_eq!(
            read_paused_conf("range = ::1\n").unwrap_err(),
            ConfigError::Parse(ParseError::Ipv6NotSupported)
        );
        assert_eq!(
            read_paused_conf(
                "router-mac-ipv4 = 00-00-00-00-00-01\nrouter-mac-ipv6 = 00-00-00-00-00-02\n"
            )
            .unwrap_err(),
            ConfigError::BadValue {
                key: "router-mac-ipv6".into(),
                value: "00-00-00-00-00-02".into()
            }
        );
    }

    #[test]
    fn read_accepts_wait_rounds_exclude_and_booleans() {
        let cfg = read_paused_conf(
            "wait = 3\nblackrock-rounds = 7\nexclude = 10.0.0.0/25\noffline = no\nnocapture = servername\n",
        )
        .unwrap();
        assert_eq!(
            (cfg.wait_secs, cfg.blackrock_rounds, cfg.offline),
            (3, 7, false)
        );
        assert_eq!(cfg.excludes.ipv4().len(), 1);
    }
}
