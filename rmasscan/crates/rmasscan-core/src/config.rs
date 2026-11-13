//! Конфигурация скана, валидация и дамп `--echo` (AGPL-3.0).
//! Порт частей `src/main-conf.c` (`masscan_echo` :3636, `masscan_echo_nic`
//! :294, `SET_*`, `masscan_read_config_file` :3883) и подготовки целей из
//! `src/main.c:1595-1733` из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Что здесь НЕ перенесено: IPv6 и опции баннеров (`--top-ports` разбирает CLI,
//! таблицы лежат в [`crate::top_ports`]). Ключи
//! вывода, `pcap-filename` и `ndjson-status` принадлежат слою CLI и
//! подмешиваются через [`EchoExtras`]; остальные ключи `config_parameters[]`
//! печатает `echo` из `ScanConfig` (адаптеры `nic[0..8)`, `noreset`, `ttl`,
//! `badsum`, опции TCP).
//!
//! `echo(.., echo_all = true)` печатает все принадлежащие нам ключи
//! безусловно (как `masscan->echo_all` в C), но это не весь `--echo-all` C:
//! десятки ключей вне v1 здесь отсутствуют. Сам C вызывает `masscan_echo`
//! с `is_echo_all = 0` и для `--echo-all` (main.c:1803-1805), поэтому CLI
//! обязан передавать `false` в обоих случаях.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::Ipv4Addr;

use crate::massip::{MassIp, RangeOverflow};
use crate::ranges::{RangeList, range_is_cidr};
use crate::ranges6::format_ipv6_c;
use crate::scan::Shard;
use crate::targets::{
    self, ParseError, TEMPL_ICMP_ECHO, TEMPL_OPROTO_FIRST, TEMPL_OPROTO_LAST, TEMPL_SCTP, TEMPL_UDP,
};

/// Операция, для которой готовится конфигурация (`masscan->op`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// `--echo` / `--echo-all`: C доходит до `masscan_echo` только через
    /// `apply_excludes`, `optimize` и 63-битную проверку (main.c:1673-1704,
    /// :1799-1805); пустые цели и порты не ошибка.
    Echo,
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
    /// Больше 1e9 адресов без единого `--exclude` (main.c:1235-1239). Текст это три строки `LOG(0, ...)` из
    /// main.c:1236-1238 дословно (подсказки с одним пробелом впереди, без префикса `[-]`); CLI выводит его как есть.
    #[error(
        "FAIL: range too big, need confirmation\n [hint] to prevent accidents, at least one --exclude must be specified\n [hint] use \"--exclude 255.255.255.255\" as a simple confirmation"
    )]
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
    /// Seed 0 для List/Scan: в C он значит "взять энтропию" (main.c:1658),
    /// порт этого не делает, а runtime требует явный ненулевой seed.
    #[error("seed must be non-zero for -sL and scans (0 would mean entropy in C; not ported)")]
    ZeroSeed,
    #[error("bad rate: {0:?}")]
    BadRate(String),
    #[error("bad MAC address: {0:?}")]
    BadMac(String),
    /// `infinite` с `-sL`: список напечатался бы один раз молча (main.c: `-sL` игнорирует `is_infinite`, а проходы
    /// заново бессмысленны для списка).
    #[error("--infinite cannot be combined with -sL (a list has no repeated passes)")]
    InfiniteWithList,
    /// Значение ключа не разобрано.
    #[error("bad value for {key}: {value:?}")]
    BadValue { key: String, value: String },
    /// Ключ, которого нет в v1.
    #[error("unsupported config key {0:?}")]
    UnknownKey(String),
    #[error("{0}")]
    Parse(#[from] ParseError),
}

/// Максимум адаптеров `nic[0..8)` (masscan.h `nic[8]`). Индекс `>= 8` в C
/// переполняет массив (main-conf.c:2438), здесь это `BadValue`.
pub const MAX_NICS: usize = 8;

pub use crate::packet::{
    DEFAULT_TCP_MSS, DEFAULT_TCP_TSECHO, DEFAULT_TCP_WSCALE, PacketModifiers, TcpHeaderOptions,
};

/// Один адаптер `nic[i]` (masscan.h `struct Masscan::nic`, подмножество
/// IPv4). `adapter_ip` это включительный диапазон `(first, last)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NicConfig {
    pub adapter_name: Option<String>,
    pub adapter_ip: Option<(u32, u32)>,
    /// `adapter-ip` IPv6 (`src.ipv6.first/last`, main-conf.c:2508-2512): C шлёт только с `first` ("TODO: add support
    /// for more than one source"); `::` значит «не задан». Есть только в `nics` (одиночного поля нет).
    pub adapter_ipv6: Option<(u128, u128)>,
    pub adapter_mac: Option<[u8; 6]>,
    pub router_ip: Option<u32>,
    /// `router-ip` IPv6: адрес следующего хопа для NDP (у C `router-ip` только IPv4, main-conf.c:2626-2641; здесь
    /// это адрес Neighbor Solicitation, R11). Есть только в `nics`.
    pub router_ipv6: Option<u128>,
    pub router_mac_ipv4: Option<[u8; 6]>,
    pub router_mac_ipv6: Option<[u8; 6]>,
    pub source_port: Option<(u16, u16)>,
    /// `adapter-port = A-B` шириной 17, как пишет сам C из-за ошибки на единицу (main.c:1318, port_mask 0x10).
    /// Спека Р6: поблажка только для `last - first == 16` и только у этого адаптера, порядок ключей не важен.
    pub legacy_c_17_port_mask: bool,
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
    /// `--router-ip` (main-conf.c:2626-2641): ровно один адрес IPv4.
    pub router_ip: Option<u32>,
    /// MAC шлюза. Пока `nics` пуст (Студия, одиночные поля), это один MAC на ipv4 и ipv6, как `--router-mac`; когда
    /// `nics` заведён, это `nics[0].router_mac_ipv4` (MAC IPv6 живёт в `nics[0].router_mac_ipv6`, main-conf.c:2602-2624).
    pub router_mac: Option<[u8; 6]>,
    /// `(first, last)` включительно.
    pub source_port: Option<(u16, u16)>,
    pub adapter_name: Option<String>,
    pub offline: bool,
    /// Массив адаптеров `nic[0..nic_count)`. Пусто значит «один адаптер,
    /// описанный одиночными полями выше». Когда не пусто, единственный
    /// писатель это [`apply_core_kv`], и он держит одиночные поля равными
    /// `nics[0]` (обратная совместимость со `Studio` и прежними тестами).
    pub nics: Vec<NicConfig>,
    /// `--ttl` (main-conf.c:3003): `None` значит умолчание 255.
    pub ttl: Option<u8>,
    /// `--badsum` (main-conf.c:2758).
    pub badsum: bool,
    /// `--noreset` (main-conf.c:1556).
    pub noreset: bool,
    /// `--infinite` (main-conf.c:2836).
    pub infinite: bool,
    /// `--arp`/`--arpscan` (main-conf.c:1088-1102): порт `I:2` и `router-mac = ff-ff-ff-ff-ff-ff` уже добавлены
    /// ключом [`apply_core_kv`]; флаг нужен только `--echo` (`arpscan = true`). Приём и отправка смотрят на сам порт.
    pub arpscan: bool,
    pub tcp_opts: TcpHeaderOptions,
    /// `--nmap-payloads FILE` (main-conf.c:1568): файл нагрузок UDP в синтаксисе Nmap. Читает слой CLI.
    pub nmap_payloads: Option<String>,
    /// `--pcap-payloads FILE` (main-conf.c:1832): нагрузки UDP из захвата pcap. Читает слой CLI.
    pub pcap_payloads: Option<String>,
    /// `--banner-types` и синонимы `banner-type`, `banner-apps`, `banner-app` (`masscan->banner_types`,
    /// `src/main-conf.c:2683-2697`): номера приложений, которые оставляет `--readscan` (`src/in-binary.c:684`), её
    /// единственный потребитель. Имена разбирает слой CLI (`masscan_string_to_app` живёт в `rmasscan-proto`, ядро от
    /// него не зависит); `--echo` и `paused.conf` C их не пишут.
    pub banner_types: BTreeSet<u16>,
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
            router_ip: None,
            router_mac: None,
            source_port: None,
            adapter_name: None,
            offline: false,
            nics: Vec::new(),
            ttl: None,
            badsum: false,
            noreset: false,
            infinite: false,
            arpscan: false,
            tcp_opts: TcpHeaderOptions::default(),
            nmap_payloads: None,
            pcap_payloads: None,
            banner_types: BTreeSet::new(),
        }
    }
}

/// Результат [`validate`]: цели с применёнными исключениями и
/// `optimize`, готовые для `scan::list_scan` / `scan::transmit_scan`.
#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    operation: Operation,
    massip: MassIp,
    /// Число комбинаций IP/порт, 1..2^63.
    /// Нормализованные (optimize) исходные цели и исключения до
    /// `apply_excludes`: нужны для идентичности скана, в отличие от `massip`.
    source_targets: MassIp,
    source_excludes: MassIp,
    range: u64,
    seed: u64,
    max_rate: f64,
    retries: u32,
    shard: Shard,
    resume_index: u64,
    resume_count: Option<u64>,
    blackrock_rounds: u32,
    wait_secs: u32,
    adapter_ip: Option<u32>,
    adapter_mac: Option<[u8; 6]>,
    router_ip: Option<u32>,
    router_mac: Option<[u8; 6]>,
    source_port: Option<(u16, u16)>,
    adapter_name: Option<String>,
    offline: bool,
    nics: Vec<NicConfig>,
    ttl: Option<u8>,
    badsum: bool,
    noreset: bool,
    infinite: bool,
    tcp_opts: TcpHeaderOptions,
    nmap_payloads: Option<String>,
    pcap_payloads: Option<String>,
}

impl EffectiveConfig {
    pub fn operation(&self) -> Operation {
        self.operation
    }
    pub fn range(&self) -> u64 {
        self.range
    }
    pub fn seed(&self) -> u64 {
        self.seed
    }
    pub fn max_rate(&self) -> f64 {
        self.max_rate
    }
    pub fn retries(&self) -> u32 {
        self.retries
    }
    pub fn shard(&self) -> Shard {
        self.shard
    }
    pub fn resume_index(&self) -> u64 {
        self.resume_index
    }
    pub fn resume_count(&self) -> Option<u64> {
        self.resume_count
    }
    pub fn blackrock_rounds(&self) -> u32 {
        self.blackrock_rounds
    }
    pub fn wait_secs(&self) -> u32 {
        self.wait_secs
    }
    pub fn adapter_ip(&self) -> Option<u32> {
        self.adapter_ip
    }
    pub fn adapter_mac(&self) -> Option<[u8; 6]> {
        self.adapter_mac
    }
    /// `0.0.0.0` значит «не задан» (C `main-initadapter.c:176` тогда ищет шлюз), и в argv, и в `paused.conf`.
    pub fn router_ip(&self) -> Option<u32> {
        self.router_ip.filter(|&ip| ip != 0)
    }
    /// MAC шлюза IPv4 адаптера `nic[0]` (C `router_mac_ipv4`).
    pub fn router_mac(&self) -> Option<[u8; 6]> {
        self.router_mac
    }
    /// MAC шлюза IPv6 адаптера `nic[0]` (C `router_mac_ipv6`): `nics[0].router_mac_ipv6`, а без массива адаптеров
    /// одиночное поле (`--router-mac` ставит оба, main-conf.c:2599-2600). Нулевой MAC значит «не задан».
    pub fn router_mac_ipv6(&self) -> Option<[u8; 6]> {
        match self.nics.first() {
            Some(n) => n.router_mac_ipv6.filter(|m| *m != [0u8; 6]),
            None => self.router_mac,
        }
    }
    /// `adapter-ip` IPv6 адаптера `nic[0]` (первый адрес); `::` значит «не задан» (main-initadapter.c:214).
    pub fn adapter_ipv6(&self) -> Option<u128> {
        self.nics
            .first()
            .and_then(|n| n.adapter_ipv6)
            .map(|(first, _)| first)
            .filter(|&ip| ip != 0)
    }
    /// `router-ip` IPv6 адаптера `nic[0]`; `::` значит «не задан».
    pub fn router_ipv6(&self) -> Option<u128> {
        self.nics
            .first()
            .and_then(|n| n.router_ipv6)
            .filter(|&ip| ip != 0)
    }
    pub fn source_port(&self) -> Option<(u16, u16)> {
        self.source_port
    }
    pub fn offline(&self) -> bool {
        self.offline
    }
    pub fn adapter_name(&self) -> Option<&str> {
        self.adapter_name.as_deref()
    }
    /// Массив адаптеров; пусто значит один адаптер из одиночных полей.
    pub fn nics(&self) -> &[NicConfig] {
        &self.nics
    }
    pub fn ttl(&self) -> Option<u8> {
        self.ttl
    }
    pub fn badsum(&self) -> bool {
        self.badsum
    }
    pub fn noreset(&self) -> bool {
        self.noreset
    }
    pub fn infinite(&self) -> bool {
        self.infinite
    }
    pub fn tcp_opts(&self) -> TcpHeaderOptions {
        self.tcp_opts
    }
    /// `--nmap-payloads`: пустое значение значит "не задан".
    pub fn nmap_payloads(&self) -> Option<&str> {
        self.nmap_payloads.as_deref().filter(|f| !f.is_empty())
    }
    /// `--pcap-payloads`: пустое значение значит "не задан".
    pub fn pcap_payloads(&self) -> Option<&str> {
        self.pcap_payloads.as_deref().filter(|f| !f.is_empty())
    }
    /// `--ttl`, `--badsum` и опции TCP как параметры зонда (templ-pkt.c:1474-1488,
    /// templ-tcp-hdr.c:1066-1119). Умолчание: TTL 255 (`DEFAULT_TCP_TEMPLATE`).
    pub fn packet_modifiers(&self) -> PacketModifiers {
        PacketModifiers {
            ttl: self.ttl.unwrap_or(255),
            badsum: self.badsum,
            tcp: self.tcp_opts,
        }
    }
    /// Итоговый набор (исключения применены, optimize).
    pub fn massip(&self) -> &MassIp {
        &self.massip
    }
    /// Исходные цели, нормализованные, без исключений.
    pub fn source_targets(&self) -> &MassIp {
        &self.source_targets
    }
    /// Исходные исключения, нормализованные.
    pub fn source_excludes(&self) -> &MassIp {
        &self.source_excludes
    }
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
/// `Operation::Echo` выполняет только шаги 1 (без `blackrock_rounds`, их
/// C не проверяет), 3, 5 и 6: `--echo 10.0.0.0/24` (без портов),
/// `--echo -p80` (без целей), `--echo 0.0.0.0/0 -p80` и случай "всё
/// исключено" в C завершаются кодом 0. Возвращаемый `range` может быть 0.
///
/// `seed == 0` отвергается для List и Scan ([`ConfigError::ZeroSeed`], после
/// остальных проверок); Echo его принимает, как раньше.
///
/// Пустая цель при `-sL` в C — бесконечный цикл в `blackrock_init`
/// (crypto-blackrock.c:117-120, :151-152), здесь `EmptyTargets`.
pub fn validate(cfg: &ScanConfig, op: Operation) -> Result<EffectiveConfig, ConfigError> {
    // `infinite` приходит и из файла `-c`/`--resume` (`infinite = true`), поэтому clap `conflicts_with` его не ловит.
    if op == Operation::List && cfg.infinite {
        return Err(ConfigError::InfiniteWithList);
    }
    check_shard(cfg.shard)?;
    if op != Operation::Echo && cfg.blackrock_rounds >= 64 {
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
    let mut source_targets = massip.clone();
    source_targets.optimize();
    let mut source_excludes = excludes.clone();
    source_excludes.optimize();
    // main.c:1671 `massip_has_ipv4_targets || massip_has_ipv6_targets`
    let has_addresses = !massip.ipv4().is_empty() || massip.has_ipv6_targets();
    let has_ports = !massip.ports().is_empty(); // main.c:1672
    massip.apply_excludes(&mut excludes);
    if op == Operation::List && !has_ports {
        massip.ports_mut().add_range(80, 80);
    }
    massip.optimize();

    massip.try_range()?;

    if op == Operation::Echo {
        return Ok(effective(cfg, op, massip, source_targets, source_excludes));
    }

    if op == Operation::List && massip.ports().is_empty() {
        massip.ports_mut().add_range(80, 80);
        massip.optimize();
    }

    // main.c:1717: `rangelist_count(ipv4) == 0 && range6list_count(ipv6) == 0`
    if massip.ipv4().is_empty() && !massip.has_ipv6_targets() {
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
    // main.c:1204, :1235: `count_ips` это IPv4 плюс младшие 64 бита счёта IPv6. C считает подтверждением только
    // `exclude.ipv4`. Исключение IPv6 подтверждает лишь переполнение, которое вызвали цели IPv6 (спека, Р1, R24):
    // если одних целей IPv4 уже больше 1e9, оно не помогает, и чисто IPv4-скан ведёт себя ровно как C.
    if op == Operation::Scan
        && massip.count_ipv4s().wrapping_add(massip.count_ipv6s()) > 1_000_000_000
    {
        let confirmed = !cfg.excludes.ipv4().is_empty()
            || (!cfg.excludes.ipv6().is_empty() && massip.count_ipv4s() <= 1_000_000_000);
        if !confirmed {
            return Err(ConfigError::ExcludeRequired);
        }
    }

    // Только runtime-операции (List, Scan); Echo вернулся выше и seed 0 держит.
    // Проверка после остальных, чтобы порядок прежних ошибок не менялся.
    if cfg.seed == 0 {
        return Err(ConfigError::ZeroSeed);
    }

    Ok(effective(cfg, op, massip, source_targets, source_excludes))
}

fn effective(
    cfg: &ScanConfig,
    op: Operation,
    massip: MassIp,
    source_targets: MassIp,
    source_excludes: MassIp,
) -> EffectiveConfig {
    EffectiveConfig {
        operation: op,
        range: massip.range(),
        source_targets,
        source_excludes,
        massip,
        seed: cfg.seed,
        max_rate: cfg.max_rate,
        retries: cfg.retries,
        shard: cfg.shard,
        resume_index: cfg.resume_index,
        resume_count: cfg.resume_count,
        blackrock_rounds: cfg.blackrock_rounds,
        wait_secs: cfg.wait_secs,
        // main-initadapter.c:122-126: source IP 0 значит «не задан», C берёт адрес интерфейса.
        adapter_ip: cfg.adapter_ip.filter(|&ip| ip != 0),
        // main-conf.c:2552: C никогда не хранит нулевой MAC.
        adapter_mac: cfg.adapter_mac.filter(|m| *m != [0u8; 6]),
        router_ip: cfg.router_ip,
        // main-initadapter.c:170: нулевой MAC шлюза значит «не задан», C ищет шлюз ARP-ом.
        router_mac: cfg.router_mac.filter(|m| *m != [0u8; 6]),
        source_port: cfg.source_port,
        adapter_name: cfg.adapter_name.clone(),
        offline: cfg.offline,
        nics: cfg.nics.clone(),
        ttl: cfg.ttl,
        badsum: cfg.badsum,
        noreset: cfg.noreset,
        infinite: cfg.infinite,
        tcp_opts: cfg.tcp_opts,
        nmap_payloads: cfg.nmap_payloads.clone(),
        pcap_payloads: cfg.pcap_payloads.clone(),
    }
}

// ---------------------------------------------------------------------
// echo
// ---------------------------------------------------------------------

/// main-conf.c:1868-1876: ветка "целое" или `%f`.
///
/// C считает `(unsigned)(max_rate * 100000) % 100000`. Для `max_rate`
/// больше ~42949 это UB (результат не помещается в `unsigned`); gcc на
/// x86-64 делает `cvttsd2si` в 64 бита и берёт младшие 32. Модель:
/// значение вне `i64` даёт "неопределённое целое" 0x8000...0 (младшие 32
/// бита 0), остальное `as i64 as u32` (усечение, не насыщение). Из-за этого
/// `250000` печатается как `250000.000000` (golden `echo/everything.conf`),
/// `5000` как `5000      ` (`%-10.0f`), а `134217728` (произведение кратно
/// 2^32) снова как целое.
fn format_rate(max_rate: f64) -> String {
    let s = max_rate * 100000.0;
    // NaN и значения >= 2^63 попадают в `else` (0x8000...0, младшие 32 бита 0).
    let scaled: u32 = if s < 9_223_372_036_854_775_808.0 {
        s as i64 as u32
    } else {
        0
    };
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
/// `echo_all`: C никогда не вызывает `masscan_echo` с `is_echo_all != 0`
/// (main-conf.c:413 `masscan_save_state`, main.c:1799 и :1804), поэтому эту
/// ветку нельзя сверить с оракулом; она печатает ключи, которыми владеет
/// `ScanConfig`, безусловно (см. документацию модуля).
///
/// Ключи вывода (`output-format = ...`) мы не храним и не печатаем: C пишет
/// их между двумя пустыми строками, поэтому `paused.conf` от студии не
/// совпадает с нашим `echo` байт в байт (читается он нормально).
pub fn echo(cfg: &ScanConfig, echo_all: bool, out: &mut String) {
    echo_with(cfg, echo_all, &EchoExtras::default(), out);
}

/// Дополнения к [`echo`], которыми владеет не `ScanConfig`, а слой CLI
/// (`rmasscan-cli::conf`): ключи `pcap-filename` и `ndjson-status` и секция
/// вывода между двумя записями `SPACE` (main-conf.c:2402-2422).
#[derive(Debug, Clone, Copy, Default)]
pub struct EchoExtras<'a> {
    pub pcap_filename: Option<&'a str>,
    pub ndjson_status: bool,
    /// Готовые строки `output-filename`, `output-format`, ... с `\n` на
    /// конце каждой.
    pub output_section: &'a str,
}

/// [`echo`] с дополнениями. С `EchoExtras::default()` и конфигурацией без
/// новых полей вывод побайтно прежний.
///
/// Порядок как у `config_parameters[]` (main-conf.c:2369-2422): resume,
/// seed, rate, shard, retries, `noreset`, offline, `pcap-filename`,
/// `ndjson-status`, двойной capture, `SPACE`, секция вывода, `SPACE`,
/// затем `ttl`, `badsum` (их C не печатает, это расширение rmasscan, читаемое
/// и C: `masscan_set_parameter` знает оба ключа) и `tcp-mss`, `tcp-wscale`,
/// `tcp-tsecho`, `tcp-sackok` (:2141-2345), после этого адаптеры.
pub fn echo_with(cfg: &ScanConfig, echo_all: bool, extras: &EchoExtras<'_>, out: &mut String) {
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
    // :1092-1094: только при `scan_type.arp`; `echo_all` в этом пути C ключ не печатает (проверено на 8e6b3b0).
    if cfg.arpscan {
        out.push_str("arpscan = true\n");
    }
    out.push_str(&format_rate(cfg.max_rate));
    if cfg.shard.of > 0 || echo_all {
        let _ = writeln!(out, "shard = {}/{}", cfg.shard.one, cfg.shard.of); // :2067
    }
    if cfg.retries != 0 || echo_all {
        let _ = writeln!(out, "retries = {}", cfg.retries); // :1936
    }
    // :1556-1565. Только когда включён: `echo_all` здесь не печатает умолчание,
    // чтобы вывод `--echo-all` старых конфигураций остался прежним.
    if cfg.noreset {
        out.push_str("noreset = true\n");
    }
    if let Some(name) = cfg.nmap_payloads.as_deref().filter(|n| !n.is_empty()) {
        let _ = writeln!(out, "nmap-payloads = {name}"); // :1568-1576
    }
    if cfg.offline || echo_all {
        let _ = writeln!(out, "offline = {}", cfg.offline); // :1603
    }
    if let Some(name) = extras.pcap_filename.filter(|n| !n.is_empty()) {
        let _ = writeln!(out, "pcap-filename = {name}"); // :1814-1822
    }
    if let Some(name) = cfg.pcap_payloads.as_deref().filter(|n| !n.is_empty()) {
        let _ = writeln!(out, "pcap-payloads = {name}"); // :1832-1840
    }
    if extras.ndjson_status {
        out.push_str("ndjson-status = true\n"); // :1507-1514
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
    out.push('\n'); // первая запись SPACE (:2048)
    out.push_str(extras.output_section);
    out.push('\n'); // вторая запись SPACE

    echo_tcp_ip_params(cfg, out);

    // masscan_echo_nic (main-conf.c:294-388).
    let legacy;
    let nics: &[NicConfig] = if cfg.nics.is_empty() {
        legacy = [legacy_nic(cfg)];
        &legacy
    } else {
        &cfg.nics
    };
    for (i, nic) in nics.iter().enumerate() {
        echo_nic(out, nic, (nics.len() > 1).then_some(i));
    }
    // adapter-port (main-conf.c:3666-3676): только nic[0].
    if let Some((first, last)) = nics[0].source_port.filter(|&(f, _)| f != 0) {
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
    // main-conf.c:3762-3781
    for r in targets.ipv6().as_slice() {
        echo_range6(out, *r);
    }
}

/// main-conf.c:245-285 `count_cidr6_bits`: сколько бит префикса у диапазона и точен ли он.
/// Побайтно как C: первый `i`, у которого `begin` кратен блоку; если `end` лежит в том же блоке
/// и заполняет его, префикс точен; если `end` в другом блоке, `exact = false`. Если `end` в
/// том же блоке, но не заполняет его, цикл идёт дальше. После цикла 128 и `exact = false`.
fn count_cidr6_bits(begin: u128, end: u128) -> (u32, bool) {
    for i in 0..128u32 {
        let mask = u128::MAX >> i;
        if begin & mask != 0 {
            continue;
        }
        if begin & !mask == end & !mask {
            if end & mask == mask {
                return (i, true);
            }
        } else {
            return (i, false);
        }
    }
    (128, false)
}

/// main-conf.c:3762-3781: `range = <begin>`, затем `/<bits>`, если префикс точен и не нулевой,
/// иначе `-<end>`. Адреса печатает `ipv6address_fmt`.
fn echo_range6(out: &mut String, r: crate::ranges6::Ipv6Range) {
    let _ = write!(out, "range = {}", format_ipv6_c(r.begin));
    if r.begin != r.end {
        let (bits, exact) = count_cidr6_bits(r.begin, r.end);
        if exact && bits != 0 {
            let _ = write!(out, "/{bits}");
        } else {
            let _ = write!(out, "-{}", format_ipv6_c(r.end));
        }
    }
    out.push('\n');
}

/// Одиночные поля как `nic[0]` (когда `nics` пуст).
fn legacy_nic(cfg: &ScanConfig) -> NicConfig {
    NicConfig {
        adapter_name: cfg.adapter_name.clone(),
        adapter_ip: cfg.adapter_ip.map(|ip| (ip, ip)),
        adapter_ipv6: None,
        adapter_mac: cfg.adapter_mac,
        router_ip: cfg.router_ip,
        router_ipv6: None,
        router_mac_ipv4: cfg.router_mac,
        router_mac_ipv6: cfg.router_mac,
        source_port: cfg.source_port,
        legacy_c_17_port_mask: false,
    }
}

/// `ttl`, `badsum` и опции TCP (изменённые против умолчания).
fn echo_tcp_ip_params(cfg: &ScanConfig, out: &mut String) {
    if let Some(ttl) = cfg.ttl {
        let _ = writeln!(out, "ttl = {ttl}");
    }
    if cfg.badsum {
        out.push_str("badsum = true\n");
    }
    let o = cfg.tcp_opts;
    match o.mss {
        Some(DEFAULT_TCP_MSS) => {}
        Some(v) => {
            let _ = writeln!(out, "tcp-mss = {v}");
        }
        None => out.push_str("tcp-mss = disable\n"),
    }
    match o.wscale {
        Some(DEFAULT_TCP_WSCALE) => out.push_str("tcp-wscale = enable\n"),
        Some(v) => {
            let _ = writeln!(out, "tcp-wscale = {v}");
        }
        None => {}
    }
    match o.tsecho {
        Some(DEFAULT_TCP_TSECHO) => out.push_str("tcp-tsecho = enable\n"),
        Some(v) => {
            let _ = writeln!(out, "tcp-tsecho = {v}");
        }
        None => {}
    }
    if o.sackok {
        out.push_str("tcp-sackok = enable\n");
    }
}

/// main-conf.c:294-389 `masscan_echo_nic`; `idx` это `[i]` при `nic_count > 1`.
fn echo_nic(out: &mut String, nic: &NicConfig, idx: Option<usize>) {
    let sfx = idx.map(|i| format!("[{i}]")).unwrap_or_default();
    if let Some(name) = nic.adapter_name.as_deref().filter(|n| !n.is_empty()) {
        let _ = writeln!(out, "adapter{sfx} = {name}");
    }
    if let Some((first, last)) = nic.adapter_ip.filter(|&(f, l)| f != 0 || l != 0) {
        // :312-358: одиночный адрес, либо диапазон `first-last` (включая два).
        if first == last {
            let _ = writeln!(out, "adapter-ip{sfx} = {}", Ipv4Addr::from(first));
        } else if first < last {
            let _ = writeln!(
                out,
                "adapter-ip{sfx} = {}-{}",
                Ipv4Addr::from(first),
                Ipv4Addr::from(last)
            );
        }
    }
    // main-conf.c:361-369: `adapter-ip` IPv6 после IPv4, `first-last` при `first < last`.
    if let Some((first, last)) = nic.adapter_ipv6 {
        if first < last {
            let _ = writeln!(
                out,
                "adapter-ip{sfx} = {}-{}",
                format_ipv6_c(first),
                format_ipv6_c(last)
            );
        } else {
            let _ = writeln!(out, "adapter-ip{sfx} = {}", format_ipv6_c(first));
        }
    }
    if let Some(mac) = nic.adapter_mac.filter(|m| *m != [0u8; 6]) {
        let _ = writeln!(out, "adapter-mac{sfx} = {}", fmt_mac(mac));
    }
    // main-conf.c:376-378: после adapter-mac, перед router-mac.
    if let Some(ip) = nic.router_ip.filter(|&ip| ip != 0) {
        let _ = writeln!(out, "router-ip{sfx} = {}", Ipv4Addr::from(ip));
    }
    // `router-ip` IPv6 (у C ключа нет): сразу после IPv4, только когда задан.
    if let Some(ip) = nic.router_ipv6 {
        let _ = writeln!(out, "router-ip{sfx} = {}", format_ipv6_c(ip));
    }
    if let Some(mac) = nic.router_mac_ipv4.filter(|m| *m != [0u8; 6]) {
        let _ = writeln!(out, "router-mac-ipv4{sfx} = {}", fmt_mac(mac));
    }
    if let Some(mac) = nic.router_mac_ipv6.filter(|m| *m != [0u8; 6]) {
        let _ = writeln!(out, "router-mac-ipv6{sfx} = {}", fmt_mac(mac));
    }
}

// ---------------------------------------------------------------------
// paused.conf
// ---------------------------------------------------------------------

/// C `isspace` для ASCII.
fn is_c_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

/// main-conf.c:833 `EQUALS`: регистр и символы `-`, `.`, `_` не важны, суффикс
/// `[N]` (массив адаптеров) отбрасывается.
pub fn normalize_key(name: &str) -> String {
    name.split('[')
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !matches!(c, '-' | '.' | '_'))
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// C `strtoul(s, 0, 0)`: `0x..` — hex, ведущий `0` — восьмеричное, иначе
/// десятичное; читается ведущая последовательность цифр, переполнение
/// насыщает. `None`, если цифр нет вовсе (C вернул бы 0).
fn strtoul0(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let (radix, start) = if b.len() > 2
        && b[0] == b'0'
        && (b[1] | 0x20) == b'x'
        && (b[2] as char).is_ascii_hexdigit()
    {
        (16, 2)
    } else if b.first() == Some(&b'0') {
        (8, 0)
    } else {
        (10, 0)
    };
    let mut v: u64 = 0;
    let mut any = false;
    for &c in &b[start..] {
        let Some(d) = (c as char).to_digit(radix) else {
            break;
        };
        v = v
            .saturating_mul(u64::from(radix))
            .saturating_add(u64::from(d));
        any = true;
    }
    any.then_some(v)
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

/// main-conf.c:657 `parseBoolean` (по первому символу).
pub fn parse_bool(value: &str) -> bool {
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
/// проверяются и пропускаются (на скан не влияют). `router-mac-ipv4` и
/// `router-mac-ipv6` хранятся раздельно в `nics` (как в C).
pub fn read_paused_conf(text: &str) -> Result<ScanConfig, ConfigError> {
    let mut cfg = ScanConfig::default();
    for raw in text.lines() {
        let Some((name, value)) = conf_line_kv(raw) else {
            continue;
        };
        if apply_core_kv(&mut cfg, name, value)? {
            continue;
        }
        match normalize_key(name).as_str() {
            // Ключи вывода (pure-output), которые C пишет в paused.conf, если
            // заданы: на порядок и содержимое скана не влияют, значения
            // не проверяются (студия всегда пишет `output-format = interactive`).
            "outputformat"
            | "outputfilename"
            | "outputfile"
            | "outputappend"
            | "appendoutput"
            | "outputshow"
            | "outputstatus"
            | "show"
            | "outputnoshow"
            | "noshow"
            | "outputshowopen"
            | "open"
            | "openonly"
            | "outputflush"
            | "rotate"
            | "outputrotate"
            | "rotateoutput"
            | "rotatetime"
            | "rotatedir"
            | "outputrotatedir"
            | "rotatedirectory"
            | "rotateoffset"
            | "outputrotateoffset"
            | "rotatesize"
            | "outputrotatefilesize"
            | "rotatefilesize"
            | "stylesheet"
            | "ndjsonstatus"
            | "statusndjson"
            | "jsonstatus"
            | "statusjson"
            | "pcapfilename"
            | "pcap" => {}
            _ => return Err(ConfigError::UnknownKey(name.to_string())),
        }
    }
    Ok(cfg)
}

/// Одна строка файла конфигурации (main-conf.c:3900-3920): обрезка по
/// пробелам, пустые строки, строки с пунктуацией первым знаком и строки без
/// `=` дают `None`; иначе `(имя, значение)`, оба обрезаны.
pub fn conf_line_kv(raw: &str) -> Option<(&str, &str)> {
    let line = raw.trim_matches(is_c_space);
    if line.is_empty() || line.as_bytes()[0].is_ascii_punctuation() {
        return None;
    }
    let (name, value) = line.split_once('=')?;
    Some((
        name.trim_matches(is_c_space),
        value.trim_matches(is_c_space),
    ))
}

/// Индекс `[N]` в имени ключа (C `ARRAY`, main-conf.c:2438); без скобок 0.
/// В отличие от C индекс `>= 8` и нечисловой — ошибка, а не переполнение
/// `nic[8]`.
fn nic_index(name: &str, value: &str) -> Result<usize, ConfigError> {
    let bad = || ConfigError::BadValue {
        key: name.into(),
        value: value.into(),
    };
    let Some((_, rest)) = name.split_once('[') else {
        return Ok(0);
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 || digits > 4 {
        return Err(bad());
    }
    let idx: usize = rest[..digits].parse().map_err(|_| bad())?;
    if idx >= MAX_NICS {
        return Err(bad());
    }
    Ok(idx)
}

/// Берёт `nic[idx]`, создавая его (и недостающие до него) при необходимости.
/// Первое создание переносит одиночные поля в `nics[0]`.
fn nic_mut(cfg: &mut ScanConfig, idx: usize) -> &mut NicConfig {
    if cfg.nics.is_empty() {
        let first = legacy_nic(cfg);
        cfg.nics.push(first);
    }
    while cfg.nics.len() <= idx {
        cfg.nics.push(NicConfig::default());
    }
    &mut cfg.nics[idx]
}

/// Одиночные поля := `nics[0]`.
fn sync_legacy_nic(cfg: &mut ScanConfig) {
    let n = cfg.nics[0].clone();
    cfg.adapter_name = n.adapter_name;
    cfg.adapter_ip = n.adapter_ip.map(|(first, _)| first);
    cfg.adapter_mac = n.adapter_mac;
    cfg.router_ip = n.router_ip;
    // MAC шлюза IPv4 и только он: `--router-mac-ipv6` не становится MAC кадров IPv4 (main-conf.c:2614-2624).
    cfg.router_mac = n.router_mac_ipv4;
    cfg.source_port = n.source_port;
}

/// `adapter-port` (main-conf.c:2523-2554) и его ошибка на единицу: `true`,
/// если принят диапазон из 17 портов, какой C пишет сам (main.c:1318).
fn parse_source_port_c(value: &str) -> Result<((u16, u16), bool), ConfigError> {
    match parse_source_port(value) {
        Ok(r) => Ok((r, false)),
        Err(e) => {
            let mut list = RangeList::new();
            if targets::parse_ports(&mut list, value).is_ok() && list.len() == 1 {
                let r = list.get(0);
                if r.end >= r.begin
                    && r.end - r.begin == 16
                    && let (Ok(first), Ok(last)) = (u16::try_from(r.begin), u16::try_from(r.end))
                {
                    return Ok(((first, last), true));
                }
            }
            Err(e)
        }
    }
}

/// main-conf.c:591 `isBoolean`: значение это начало слова из набора или 0/1.
pub fn is_boolean(v: &str) -> bool {
    let Some(&c) = v.as_bytes().first() else {
        return false;
    };
    if c.is_ascii_digit() {
        return matches!(strtoul0(v), None | Some(0 | 1));
    }
    let lower = v.to_ascii_lowercase();
    let words: &[&str] = match c.to_ascii_lowercase() {
        b'e' => &["enable", "enabled"],
        b'd' => &["disable", "disabled"],
        b't' => &["true"],
        b'f' => &["false"],
        b'o' => &["on", "off"],
        b'y' => &["yes"],
        b'n' => &["no"],
        _ => return false,
    };
    words.iter().any(|w| w.starts_with(&lower))
}

/// main-conf.c:1066 `isInteger`.
pub fn is_integer(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())
}

/// Общий разбор `--tcp-mss`/`-wscale`/`-tsecho` (main-conf.c:2141-2345):
/// `Some(None)` выключить, `Some(Some(n))` задать, `Err` плохое значение.
fn parse_tcp_opt(
    key: &str,
    value: &str,
    default: u64,
    limit: u64,
) -> Result<Option<u64>, ConfigError> {
    let bad = || ConfigError::BadValue {
        key: key.into(),
        value: value.into(),
    };
    if value.is_empty() {
        Ok(Some(default))
    } else if is_boolean(value) {
        Ok(parse_bool(value).then_some(default))
    } else if is_integer(value) {
        let n = parse_int(key, value)?;
        if n >= limit {
            return Err(bad());
        }
        Ok(Some(n))
    } else {
        Err(bad())
    }
}

/// Применяет один ключ `name = value` к `ScanConfig` (main-conf.c
/// `masscan_set_parameter` :2429, ключи, которыми владеет `ScanConfig`).
/// `Ok(true)` ключ принят, `Ok(false)` ключ чужой (вывод, `pcap`, `conf`,
/// `resume`, ... - их разбирает слой CLI), `Err` значение плохое.
///
/// Ключи адаптера понимают индекс `name[i]`, `0 <= i < 8` (иначе
/// `BadValue`), и пишут в `nics[i]`, поддерживая одиночные поля равными
/// `nics[0]`. В отличие от C (где только `adapter` растит `nic_count`) любой
/// ключ адаптера создаёт `nic[i]`.
///
/// `adapter-port = A-B` шириной 17 принимается (ставит
/// `NicConfig::legacy_c_17_port_mask` этого адаптера), потому что именно такой диапазон пишет сам C.
/// `wait = forever` это `INT_MAX` (main-conf.c:3028-3032). `ttl` вне `1..=255`
/// отклоняется (в C `0` молча игнорируется).
pub fn apply_core_kv(cfg: &mut ScanConfig, key: &str, val: &str) -> Result<bool, ConfigError> {
    let name = key;
    let value = val;
    let bad = || ConfigError::BadValue {
        key: name.into(),
        value: value.into(),
    };
    match normalize_key(name).as_str() {
        "resumeindex" => cfg.resume_index = parse_int(name, value)?,
        "resumecount" => {
            cfg.resume_count = Some(parse_int(name, value)?).filter(|&c| c != 0);
        }
        "seed" => cfg.seed = parse_int(name, value)?,
        "rate" | "maxrate" => cfg.max_rate = parse_rate(value)?,
        "shard" | "shards" => cfg.shard = parse_shard(value)?,
        "retries" | "retry" | "maxretries" | "maxretry" => {
            // main-conf.c:1943: strtoul(value, 0, 0), затем x >= 1000.
            let n = strtoul0(value).ok_or_else(bad)?;
            if n >= 1000 {
                return Err(ConfigError::TooManyRetries(
                    u32::try_from(n).unwrap_or(u32::MAX),
                ));
            }
            cfg.retries = n as u32;
        }
        "offline" | "notransmit" | "nosend" | "dryrun" => cfg.offline = parse_bool(value),
        "noreset" => cfg.noreset = parse_bool(value),
        // main-conf.c:2382, 2386: файлы читает слой CLI (`masscan_load_database_files`, :3156).
        "nmappayloads" | "nmappayload" => cfg.nmap_payloads = Some(value.to_string()),
        "pcappayloads" | "pcappayload" => cfg.pcap_payloads = Some(value.to_string()),
        // main-conf.c:2758: `badsum` ставит флаг при любом значении.
        "badsum" => cfg.badsum = true,
        // main-conf.c:1088-1102 (`SET_arpscan`, :2373 с псевдонимом `arp`): значение не читается; порт `Templ_ARP`,
        // `router-mac = ff-ff-ff-ff-ff-ff` (как ключ `router-mac` в этой точке) и флаг. Внутри файла и между файлом и
        // командной строкой побеждает то, что правее, как в C. Флаг `--arp` командной строки CLI применяет раньше её
        // ключей адаптера, поэтому явный `--router-mac` командной строки побеждает на любом месте (у C `--arp` правее
        // `--router-mac` его затирает; на проводе разницы нет, README §8).
        "arpscan" | "arp" => {
            cfg.targets
                .ports_mut()
                .add_range(crate::targets::TEMPL_ARP, crate::targets::TEMPL_ARP);
            cfg.arpscan = true;
            apply_core_kv(cfg, "router-mac", "ff-ff-ff-ff-ff-ff")?;
        }
        // Значение читается как логическое (`infinite = false` в файле отменяет `--infinite` левее него); C ставит 1 всегда.
        "infinite" => cfg.infinite = parse_bool(value),
        "ttl" => {
            let n = strtoul0(value).ok_or_else(bad)?;
            cfg.ttl = Some(u8::try_from(n).ok().filter(|&t| t != 0).ok_or_else(bad)?);
        }
        "tcpmss" => {
            cfg.tcp_opts.mss =
                parse_tcp_opt(name, value, u64::from(DEFAULT_TCP_MSS), 0x1_0000)?.map(|n| n as u16);
        }
        "tcpwscale" => {
            cfg.tcp_opts.wscale =
                parse_tcp_opt(name, value, u64::from(DEFAULT_TCP_WSCALE), 255)?.map(|n| n as u8);
        }
        "tcptsecho" => {
            // C ограничивает 255 (main-conf.c:2285); Р9 сохраняет все 32 бита.
            cfg.tcp_opts.tsecho = parse_tcp_opt(
                name,
                value,
                u64::from(DEFAULT_TCP_TSECHO),
                u64::from(u32::MAX) + 1,
            )?
            .map(|n| n as u32);
        }
        "tcpsackok" => {
            // :2305-2340: цифра (не 0/1) тоже включает; пустое значение включает.
            cfg.tcp_opts.sackok = if value.is_empty() {
                true
            } else if is_boolean(value) {
                parse_bool(value)
            } else if is_integer(value) {
                parse_int(name, value)? != 0
            } else {
                return Err(bad());
            };
        }
        "blackrockrounds" => cfg.blackrock_rounds = parse_u32(name, value)?,
        "wait" => {
            cfg.wait_secs = if value.eq_ignore_ascii_case("forever") {
                i32::MAX as u32
            } else {
                parse_u32(name, value)?
            };
        }
        "capture" | "nocapture" => {
            if !["cert", "servername", "html", "heartbleed", "ticketbleed"]
                .iter()
                .any(|k| k.eq_ignore_ascii_case(value))
            {
                return Err(bad());
            }
        }
        "adapter" | "if" | "interface" => {
            let idx = nic_index(name, value)?;
            nic_mut(cfg, idx).adapter_name = Some(value.to_string());
            sync_legacy_nic(cfg);
        }
        "adapterip" | "sourceip" | "sourceaddress" | "spoofip" | "spoofaddress" | "srcip"
            if value.contains(':') =>
        {
            // main-conf.c:2508-2512: адрес или диапазон IPv6, `src.ipv6.first/last`.
            let idx = nic_index(name, value)?;
            let r = crate::ranges6::parse_ipv6_target(value).map_err(|_| bad())?;
            nic_mut(cfg, idx).adapter_ipv6 = Some((r.begin, r.end));
            sync_legacy_nic(cfg);
        }
        "adapterip" | "sourceip" | "sourceaddress" | "spoofip" | "spoofaddress" | "srcip" => {
            let idx = nic_index(name, value)?;
            let r = targets::range_parse_ipv4(value).map_err(|_| bad())?;
            // main-conf.c:2483: ширина диапазона степень двойки.
            if !(u64::from(r.end) - u64::from(r.begin) + 1).is_power_of_two() {
                return Err(bad());
            }
            nic_mut(cfg, idx).adapter_ip = Some((r.begin, r.end));
            sync_legacy_nic(cfg);
        }
        "adaptermac" | "sourcemac" | "spoofmac" | "srcmac" => {
            let idx = nic_index(name, value)?;
            // main-conf.c:2552: нулевой MAC C не хранит.
            nic_mut(cfg, idx).adapter_mac = Some(parse_mac(value)?).filter(|m| *m != [0u8; 6]);
            sync_legacy_nic(cfg);
        }
        "routerip" if value.contains(':') => {
            // Один адрес IPv6 следующего хопа для NDP (у C ключ только IPv4).
            let idx = nic_index(name, value)?;
            let r = crate::ranges6::parse_ipv6_target(value).map_err(|_| bad())?;
            if r.begin != r.end {
                return Err(bad());
            }
            nic_mut(cfg, idx).router_ipv6 = Some(r.begin);
            sync_legacy_nic(cfg);
        }
        "routerip" => {
            let idx = nic_index(name, value)?;
            let r = targets::range_parse_ipv4(value).map_err(|_| bad())?;
            if r.begin != r.end {
                return Err(bad());
            }
            nic_mut(cfg, idx).router_ip = Some(r.begin);
            sync_legacy_nic(cfg);
        }
        "routermac" | "router" | "destmac" | "destinationmac" | "dstmac" | "targetmac" => {
            let idx = nic_index(name, value)?;
            let m = parse_mac(value)?;
            let nic = nic_mut(cfg, idx);
            (nic.router_mac_ipv4, nic.router_mac_ipv6) = (Some(m), Some(m));
            sync_legacy_nic(cfg);
        }
        "routermacipv4" | "routeripv4" | "routermacipv6" | "routeripv6" => {
            let v6 = normalize_key(name).ends_with("v6");
            let idx = nic_index(name, value)?;
            let m = parse_mac(value)?;
            let nic = nic_mut(cfg, idx);
            if v6 {
                nic.router_mac_ipv6 = Some(m);
            } else {
                nic.router_mac_ipv4 = Some(m);
            }
            sync_legacy_nic(cfg);
        }
        "adapterport" | "sourceport" | "srcport" => {
            let idx = nic_index(name, value)?;
            let (range, quirk) = parse_source_port_c(value)?;
            let nic = nic_mut(cfg, idx);
            nic.source_port = Some(range);
            nic.legacy_c_17_port_mask = quirk;
            sync_legacy_nic(cfg);
        }
        // Здесь всегда TCP по умолчанию. Строку `ports =` файла конфигурации CLI разбирает сам, с префиксом типа скана,
        // заданного в `argv` левее файла (rmasscan-cli `conf.rs`, main-conf.c:2663–2674).
        "ports" | "port" => targets::parse_ports(cfg.targets.ports_mut(), value)?,
        // massip.c:72-100: адреса IPv4 и IPv6.
        "range" => cfg.targets.add_target_string(value)?,
        "exclude" => cfg.excludes.add_target_string(value)?,
        _ => return Ok(false),
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::list_scan_indices;

    fn cfg_with(targets_s: &str, ports_s: &str) -> ScanConfig {
        let mut cfg = ScanConfig {
            seed: 1, // List/Scan require a non-zero seed
            ..ScanConfig::default()
        };
        if !targets_s.is_empty() {
            targets::add_target_string(cfg.targets.ipv4_mut(), targets_s).unwrap();
        }
        if !ports_s.is_empty() {
            targets::parse_ports(cfg.targets.ports_mut(), ports_s).unwrap();
        }
        cfg
    }

    #[test]
    fn zero_seed_rejected_for_runtime_ops_but_not_echo() {
        let mut cfg = cfg_with("10.0.0.0/30", "80");
        cfg.seed = 0;
        assert_eq!(err(&cfg, Operation::Scan), ConfigError::ZeroSeed);
        assert_eq!(err(&cfg, Operation::List), ConfigError::ZeroSeed);
        assert!(validate(&cfg, Operation::Echo).is_ok());
        // Earlier errors keep their order over ZeroSeed.
        assert_eq!(
            err(
                &{
                    let mut c = cfg_with("", "80");
                    c.seed = 0;
                    c
                },
                Operation::Scan
            ),
            ConfigError::EmptyTargets
        );
        cfg.seed = 1;
        assert!(validate(&cfg, Operation::Scan).is_ok());
        assert!(validate(&cfg, Operation::List).is_ok());
    }

    #[test]
    fn effective_keeps_normalized_source_ranges_apart_from_final_set() {
        let mut cfg = cfg_with("10.0.0.0/30,10.0.0.2", "80");
        cfg.seed = 1;
        exclude(&mut cfg, "10.0.0.0/31");
        let eff = validate(&cfg, Operation::Scan).unwrap();
        assert_eq!(eff.massip().count_ipv4s(), 2);
        assert_eq!(eff.source_targets().count_ipv4s(), 4);
        assert_eq!(eff.source_targets().ipv4().len(), 1); // optimized: merged
        assert_eq!(eff.source_excludes().count_ipv4s(), 2);
        assert_eq!(eff.range(), 2);
    }

    fn exclude(cfg: &mut ScanConfig, s: &str) {
        targets::add_target_string(cfg.excludes.ipv4_mut(), s).unwrap();
    }

    fn err(cfg: &ScanConfig, op: Operation) -> ConfigError {
        validate(cfg, op).unwrap_err()
    }

    /// T5 New-3: `infinite` (ключ файла `-c`/`--resume` тоже его ставит) несовместим с `-sL`: иначе список
    /// напечатался бы один раз молча.
    #[test]
    fn infinite_with_list_is_refused_but_scan_and_echo_accept_it() {
        let mut cfg = cfg_with("198.18.0.0/30", "80");
        cfg.infinite = true;
        assert_eq!(err(&cfg, Operation::List), ConfigError::InfiniteWithList);
        assert!(validate(&cfg, Operation::Scan).is_ok());
        assert!(validate(&cfg, Operation::Echo).is_ok());
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
        // `masscan->banner_types` пуст: `--readscan` пропускает все баннеры и читает статус (`in-binary.c:584`).
        assert!(c.banner_types.is_empty());
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
        // 1e10 = 2*2^32 + 1410065408; 1410065408 % 100000 = 65408 != 0.
        assert_eq!(format_rate(134217728.0), "rate = 134217728 \n");
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
            ConfigError::RangeOverflow(RangeOverflow { bits: 64 })
        );
        assert_eq!(
            err(&cfg, Operation::Scan),
            ConfigError::RangeOverflow(RangeOverflow { bits: 64 })
        );
    }

    #[test]
    fn validate_accepts_largest_63_bit_range() {
        let mut cfg = ScanConfig {
            seed: 1,
            ..ScanConfig::default()
        };
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
    fn router_ip_round_trips_through_echo_and_paused_conf() {
        let mut cfg = cfg_with("10.0.0.0/30", "80");
        cfg.adapter_mac = Some([1, 2, 3, 4, 5, 6]);
        cfg.router_ip = Some(0xc612_0002);
        cfg.router_mac = Some([6, 5, 4, 3, 2, 1]);
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        // Позиция masscan_echo_nic: adapter-mac, router-ip, router-mac.
        let a = s.find("adapter-mac = ").unwrap();
        let r = s.find("router-ip = 198.18.0.2\n").unwrap();
        let m = s.find("router-mac-ipv4 = ").unwrap();
        assert!(a < r && r < m, "{s}");
        let back = read_paused_conf(&s).unwrap();
        assert_eq!(back.router_ip, Some(0xc612_0002));
        let mut s2 = String::new();
        echo(&back, false, &mut s2);
        assert_eq!(s, s2);
    }

    #[test]
    fn echo_without_router_ip_is_unchanged() {
        let cfg = cfg_with("10.0.0.0/30", "80");
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        assert!(!s.contains("router-ip"), "{s}");
    }

    #[test]
    fn validate_keeps_router_ip() {
        let mut cfg = cfg_with("10.0.0.0/30", "80");
        assert_eq!(validate(&cfg, Operation::Scan).unwrap().router_ip(), None);
        cfg.router_ip = Some(0x0a00_0001);
        assert_eq!(
            validate(&cfg, Operation::Scan).unwrap().router_ip(),
            Some(0x0a00_0001)
        );
    }

    /// C `main-initadapter.c:176`: router_ip 0 значит «не задан» (ищется шлюз).
    #[test]
    fn router_ip_zero_means_not_given() {
        let mut cfg = cfg_with("10.0.0.0/30", "80");
        cfg.router_ip = Some(0);
        assert_eq!(validate(&cfg, Operation::Scan).unwrap().router_ip(), None);
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        assert!(!s.contains("router-ip"), "{s}");
        let back =
            read_paused_conf("seed = 1\nrange = 10.0.0.0/30\nports = 80\nrouter-ip = 0.0.0.0\n")
                .unwrap();
        assert_eq!(
            validate(&back, Operation::Scan).unwrap().router_ip(),
            None,
            "paused.conf router-ip = 0.0.0.0"
        );
    }

    #[test]
    fn echo_prints_cidr_single_and_dashed_ranges() {
        let cfg = cfg_with("10.0.0.0/24,10.0.2.5,10.0.3.1-10.0.3.5,0.0.0.0/8", "1-3,80");
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        assert!(s.contains("ports = 1-3,80\n"), "{s}");
        // begin == 0: поведение gcc x86-64 (оракул), см. ranges::range_is_cidr.
        assert!(s.contains("range = 0.0.0.0-0.255.255.255\n"));
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
        // Р2: U: принимается, границы типа нет
        assert!(read_paused_conf("ports = U:53\n").is_ok());
        assert_eq!(
            read_paused_conf("ports = U:65536\n").unwrap_err(),
            ConfigError::Parse(ParseError::BadPort)
        );
        // IPv6 stage Task 2: `range` takes IPv6 (massip.c:72-100 `massip_add_target_string`)
        let cfg = read_paused_conf("range = ::1\nexclude = 2001:db8::/32\n").unwrap();
        assert_eq!(cfg.targets.ipv6().len(), 1);
        assert_eq!(cfg.excludes.ipv6().len(), 1);
        assert!(matches!(
            read_paused_conf("range = 2001:db8::zz\n").unwrap_err(),
            ConfigError::Parse(_)
        ));
        // T5: MAC шлюза IPv4 и IPv6 хранятся раздельно, как в C (`router_mac_ipv4`/`router_mac_ipv6`,
        // main-conf.c:2602-2624): разные значения больше не отказ.
        let cfg = read_paused_conf(
            "router-mac-ipv4 = 00-00-00-00-00-01\nrouter-mac-ipv6 = 00-00-00-00-00-02\n",
        )
        .unwrap();
        assert_eq!(cfg.nics[0].router_mac_ipv4, Some([0, 0, 0, 0, 0, 1]));
        assert_eq!(cfg.nics[0].router_mac_ipv6, Some([0, 0, 0, 0, 0, 2]));
        assert_eq!(cfg.router_mac, Some([0, 0, 0, 0, 0, 1]));
    }

    fn scan_cfg(text: &str) -> EffectiveConfig {
        let mut cfg = read_paused_conf(text).unwrap();
        cfg.seed = 1;
        if cfg.targets.ipv4().is_empty() && !cfg.targets.has_ipv6_targets() {
            cfg.targets.add_target_string("198.18.0.2").unwrap();
        }
        if cfg.targets.ports().is_empty() {
            crate::targets::parse_ports(cfg.targets.ports_mut(), "80").unwrap();
        }
        validate(&cfg, Operation::Scan).unwrap()
    }

    /// Forward note T4: только `--router-mac-ipv6` не должен становиться MAC шлюза IPv4 (C: `--router-mac` ставит оба,
    /// `--router-mac-ipv6`/`--router-ipv6` только IPv6, main-conf.c:2587-2624). Раньше одиночное поле брало
    /// `ipv4.or(ipv6)`, и кадры IPv4 ушли бы на MAC шлюза IPv6.
    #[test]
    fn router_mac_ipv6_alone_never_becomes_the_ipv4_router_mac() {
        for key in ["router-mac-ipv6", "router-ipv6"] {
            let eff = scan_cfg(&format!("{key} = 02-00-00-00-00-06\n"));
            assert_eq!(eff.router_mac(), None, "{key}");
            assert_eq!(eff.router_mac_ipv6(), Some([2, 0, 0, 0, 0, 6]), "{key}");
        }
        let eff = scan_cfg("router-mac = 02-00-00-00-00-04\n");
        assert_eq!(eff.router_mac(), Some([2, 0, 0, 0, 0, 4]));
        assert_eq!(eff.router_mac_ipv6(), Some([2, 0, 0, 0, 0, 4]));
        let eff = scan_cfg("router-mac-ipv4 = 02-00-00-00-00-04\n");
        assert_eq!(eff.router_mac(), Some([2, 0, 0, 0, 0, 4]));
        assert_eq!(eff.router_mac_ipv6(), None);
        // Одиночное поле Студии (`nics` пуст) это оба MAC, как `--router-mac`.
        let mut cfg = ScanConfig {
            seed: 1,
            router_mac: Some([2, 0, 0, 0, 0, 9]),
            ..ScanConfig::default()
        };
        cfg.targets.add_target_string("198.18.0.2").unwrap();
        crate::targets::parse_ports(cfg.targets.ports_mut(), "80").unwrap();
        let eff = validate(&cfg, Operation::Scan).unwrap();
        assert_eq!(eff.router_mac(), Some([2, 0, 0, 0, 0, 9]));
        assert_eq!(eff.router_mac_ipv6(), Some([2, 0, 0, 0, 0, 9]));
    }

    /// `adapter-ip` принимает IPv6 (C `massip_parse_range` → `src.ipv6.first/last`, main-conf.c:2486-2512), а
    /// `router-ip` IPv6 это адрес для NDP (у C только IPv4, main-conf.c:2626-2641). `echo`/`paused.conf` пишут их
    /// только когда они заданы, в порядке C (`adapter-ip` IPv6 после IPv4, main-conf.c:361-369), и читаются назад
    /// без потерь; чистый IPv4 не меняется ни на байт.
    #[test]
    fn ipv6_adapter_ip_and_router_ip_round_trip_through_echo() {
        let text = "adapter-ip = 198.18.0.1\nadapter-ip = fd00:198:18::1\nrouter-ip = 198.18.0.254\n\
                    router-ip = fe80::1\nrouter-mac-ipv6 = 02-00-00-00-00-06\nrange = fd00:198:18::2\n\
                    ports = 80\nseed = 1\n";
        let cfg = read_paused_conf(text).unwrap();
        let n = &cfg.nics[0];
        assert_eq!(n.adapter_ip, Some((0xc612_0001, 0xc612_0001)));
        assert_eq!(
            n.adapter_ipv6,
            Some((
                0xfd00_0198_0018_0000_0000_0000_0000_0001,
                0xfd00_0198_0018_0000_0000_0000_0000_0001
            ))
        );
        assert_eq!(n.router_ip, Some(0xc612_00fe));
        assert_eq!(
            n.router_ipv6,
            Some(0xfe80_0000_0000_0000_0000_0000_0000_0001)
        );
        let eff = validate(&cfg, Operation::Scan).unwrap();
        assert_eq!(eff.adapter_ip(), Some(0xc612_0001));
        assert_eq!(
            eff.adapter_ipv6(),
            Some(0xfd00_0198_0018_0000_0000_0000_0000_0001)
        );
        assert_eq!(
            eff.router_ipv6(),
            Some(0xfe80_0000_0000_0000_0000_0000_0000_0001)
        );
        let mut out = String::new();
        echo(&cfg, false, &mut out);
        let nic_lines: Vec<&str> = out
            .lines()
            .filter(|l| l.starts_with("adapter-ip") || l.starts_with("router-"))
            .collect();
        assert_eq!(
            nic_lines,
            [
                "adapter-ip = 198.18.0.1",
                "adapter-ip = fd00:198:18::1",
                "router-ip = 198.18.0.254",
                "router-ip = fe80::1",
                "router-mac-ipv6 = 02-00-00-00-00-06",
            ]
        );
        let back = read_paused_conf(&out).unwrap();
        assert_eq!(back.nics, cfg.nics);
        // `adapter-ip` диапазон IPv6: C хранит first/last и шлёт с first (main-conf.c:2510-2512, main.c:188).
        let cfg = read_paused_conf("adapter-ip = [fd00::1]-[fd00::4]\n").unwrap();
        assert_eq!(
            cfg.nics[0].adapter_ipv6,
            Some((0xfd00 << 112 | 1, 0xfd00 << 112 | 4))
        );
        let mut out = String::new();
        echo(&cfg, false, &mut out);
        assert!(out.contains("adapter-ip = fd00::1-fd00::4\n"), "{out}");
        // `router-ip` IPv6 это один адрес; мусор отказ.
        for bad in [
            "router-ip = fe80::1-fe80::2\n",
            "adapter-ip = fd00::zz\n",
            "router-ip = fe80::/64\n",
        ] {
            assert!(read_paused_conf(bad).is_err(), "{bad}");
        }
        // `::` значит «не задан» (C `ipv6address_is_zero`, main-initadapter.c:214): адрес ищет обнаружение.
        let eff = scan_cfg("adapter-ip = ::\nrouter-ip = ::\n");
        assert_eq!((eff.adapter_ipv6(), eff.router_ipv6()), (None, None));
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

    #[test]
    fn echo_zero_based_ranges_like_c_oracle() {
        let dump = |t: &str| {
            let mut s = String::new();
            echo(&cfg_with(t, "80"), false, &mut s);
            s.lines().last().unwrap().to_string()
        };
        assert_eq!(dump("0.0.0.0/8"), "range = 0.0.0.0-0.255.255.255");
        assert_eq!(dump("0.0.0.0/1"), "range = 0.0.0.0-127.255.255.255");
        assert_eq!(dump("0.0.0.0/31"), "range = 0.0.0.0/4294967295");
        assert_eq!(dump("0.0.0.0/0"), "range = 0.0.0.0/0");
        assert_eq!(dump("0.0.0.0"), "range = 0.0.0.0");
    }

    #[test]
    fn validate_echo_accepts_what_c_echo_accepts() {
        // no ports
        let eff = validate(&cfg_with("10.0.0.0/24", ""), Operation::Echo).unwrap();
        assert_eq!(eff.range, 0);
        // no targets
        assert!(validate(&cfg_with("", "80"), Operation::Echo).is_ok());
        // /0 without --exclude (no 1e9 check)
        let eff = validate(&cfg_with("0.0.0.0/0", "80"), Operation::Echo).unwrap();
        assert_eq!(eff.range, 1 << 32);
        // everything excluded
        let mut cfg = cfg_with("10.0.0.0/24", "80");
        exclude(&mut cfg, "10.0.0.0/24");
        assert!(validate(&cfg, Operation::Echo).is_ok());
        // the 63-bit check still applies
        let mut cfg = ScanConfig::default();
        cfg.targets.ipv4_mut().add_range(0, u32::MAX);
        cfg.targets.ports_mut().add_range(0, 0x7fff_ffff);
        assert_eq!(
            err(&cfg, Operation::Echo),
            ConfigError::RangeOverflow(RangeOverflow { bits: 64 })
        );
        // rounds are not checked by --echo
        let mut cfg = cfg_with("10.0.0.0/24", "80");
        cfg.blackrock_rounds = 64;
        assert!(validate(&cfg, Operation::Echo).is_ok());
    }

    #[test]
    fn zero_adapter_mac_is_normalized_to_none() {
        let mut cfg = cfg_with("10.0.0.0/24", "80");
        cfg.adapter_mac = Some([0; 6]);
        assert_eq!(validate(&cfg, Operation::Scan).unwrap().adapter_mac, None);
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        assert!(!s.contains("adapter-mac"));
        let back = read_paused_conf("adapter-mac = 00-00-00-00-00-00\n").unwrap();
        assert_eq!(back.adapter_mac, None);
    }

    /// C `main-initadapter.c:122–126`: source IP 0 значит «определить у интерфейса»; `:170`: нулевой MAC шлюза
    /// значит «искать ARP-ом». Скан и `--echo` (которое их тоже не печатает) согласны.
    #[test]
    fn zero_adapter_ip_and_router_mac_mean_not_given() {
        let mut cfg = cfg_with("10.0.0.0/30", "80");
        cfg.adapter_ip = Some(0);
        cfg.router_mac = Some([0; 6]);
        let eff = validate(&cfg, Operation::Scan).unwrap();
        assert_eq!(eff.adapter_ip(), None);
        assert_eq!(eff.router_mac(), None);
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        assert!(
            !s.contains("adapter-ip") && !s.contains("router-mac"),
            "{s}"
        );
        let back = read_paused_conf(
            "seed = 1\nrange = 10.0.0.0/30\nports = 80\nadapter-ip = 0.0.0.0\n\
             router-mac = 00-00-00-00-00-00\n",
        )
        .unwrap();
        let eff = validate(&back, Operation::Scan).unwrap();
        assert_eq!(eff.adapter_ip(), None, "paused.conf adapter-ip = 0.0.0.0");
        assert_eq!(eff.router_mac(), None, "paused.conf router-mac zero");
        // Ненулевые значения проходят без изменений.
        cfg.adapter_ip = Some(0x0aff_0001);
        cfg.router_mac = Some([6, 5, 4, 3, 2, 1]);
        let eff = validate(&cfg, Operation::Scan).unwrap();
        assert_eq!(eff.adapter_ip(), Some(0x0aff_0001));
        assert_eq!(eff.router_mac(), Some([6, 5, 4, 3, 2, 1]));
    }

    #[test]
    fn read_ignores_display_only_keys_but_not_semantic_ones() {
        let cfg = read_paused_conf(
            "output-format = interactive\nOutput_Filename = x.txt\nndjson-status = true\n\
             rotate = 3600\noutput-show = open\nseed = 8\n",
        )
        .unwrap();
        assert_eq!(cfg.seed, 8);
        for key in ["banners", "min-packet", "top-ports"] {
            assert_eq!(
                read_paused_conf(&format!("{key} = 1\n")).unwrap_err(),
                ConfigError::UnknownKey(key.into())
            );
        }
    }

    #[test]
    fn read_matches_names_like_c_equals() {
        let cfg = read_paused_conf("Resume_Index = 9\nADAPTER.PORT = 40000\nmax-rate = 7\nrouter-mac_ipv4 = 00-00-00-00-00-01\nadapter-ip[0] = 1.2.3.4\n").unwrap();
        assert_eq!(cfg.resume_index, 9);
        assert_eq!(cfg.source_port, Some((40000, 40000)));
        assert_eq!(cfg.max_rate, 7.0);
        assert_eq!(cfg.router_mac, Some([0, 0, 0, 0, 0, 1]));
        assert_eq!(cfg.adapter_ip, Some(0x0102_0304));
    }

    #[test]
    fn read_retries_uses_strtoul_base_0() {
        let r = |v: &str| read_paused_conf(&format!("retries = {v}\n")).map(|c| c.retries);
        assert_eq!(r("010"), Ok(8));
        assert_eq!(r("0x10"), Ok(16));
        assert_eq!(r("7"), Ok(7));
        assert_eq!(r("0"), Ok(0));
        assert_eq!(r("08"), Ok(0)); // strtoul: "0" then stops at '8'
        assert_eq!(r("0x3e8"), Err(ConfigError::TooManyRetries(1000)));
        assert_eq!(
            r("99999999999999999999"),
            Err(ConfigError::TooManyRetries(u32::MAX))
        );
        assert!(matches!(r("x"), Err(ConfigError::BadValue { .. })));
    }

    #[test]
    fn rate_cast_models_cvttsd2si() {
        assert_eq!(format_rate(134217728.0), "rate = 134217728 \n");
        // beyond i64: indefinite integer, low 32 bits zero -> integer branch
        assert_eq!(format_rate(1e300), format!("rate = {:<10.0}\n", 1e300));
    }

    // ---- Задача 2: расширение echo и apply_core_kv ----

    #[test]
    fn apply_core_kv_nic_index_bounds_and_sync() {
        let mut cfg = ScanConfig::default();
        assert!(apply_core_kv(&mut cfg, "adapter[1]", "veth1").unwrap());
        assert!(apply_core_kv(&mut cfg, "adapter-ip[0]", "10.0.0.1").unwrap());
        assert_eq!(cfg.nics.len(), 2);
        assert_eq!(cfg.adapter_ip, Some(0x0a00_0001)); // одиночное поле = nics[0]
        assert_eq!(cfg.nics[1].adapter_name.as_deref(), Some("veth1"));
        for bad in ["adapter[8]", "adapter[-1]", "adapter-ip[x]", "adapter[]"] {
            assert!(
                matches!(
                    apply_core_kv(&mut cfg, bad, "1.2.3.4"),
                    Err(ConfigError::BadValue { .. })
                ),
                "{bad}"
            );
        }
        assert_eq!(cfg.nics.len(), 2);
        // не-степень двойки для adapter-ip (main-conf.c:2483)
        assert!(apply_core_kv(&mut cfg, "adapter-ip", "10.0.0.16-10.0.0.18").is_err());
        assert!(apply_core_kv(&mut cfg, "adapter-ip", "10.0.0.16-10.0.0.19").unwrap());
        assert_eq!(cfg.nics[0].adapter_ip, Some((0x0a00_0010, 0x0a00_0013)));
        assert_eq!(cfg.adapter_ip, Some(0x0a00_0010));
    }

    #[test]
    fn apply_core_kv_probe_params_wait_and_unknown() {
        let mut cfg = ScanConfig::default();
        for (k, v) in [
            ("ttl", "64"),
            ("badsum", ""),
            ("noreset", "true"),
            ("infinite", ""),
            ("tcp-mss", "1400"),
            ("tcp-sackok", "enable"),
            ("tcp-wscale", ""),
            ("tcp-tsecho", "3735928559"),
            ("wait", "forever"),
        ] {
            assert!(apply_core_kv(&mut cfg, k, v).unwrap(), "{k}");
        }
        assert_eq!(cfg.ttl, Some(64));
        assert!(cfg.badsum && cfg.noreset && cfg.infinite);
        assert_eq!(
            cfg.tcp_opts,
            TcpHeaderOptions {
                mss: Some(1400),
                sackok: true,
                wscale: Some(3),
                tsecho: Some(0xdead_beef),
            }
        );
        assert_eq!(cfg.wait_secs, i32::MAX as u32);
        assert!(apply_core_kv(&mut cfg, "tcp-mss", "disable").unwrap());
        assert_eq!(cfg.tcp_opts.mss, None);
        assert!(apply_core_kv(&mut cfg, "ttl", "0").is_err());
        assert!(apply_core_kv(&mut cfg, "ttl", "256").is_err());
        assert!(apply_core_kv(&mut cfg, "tcp-mss", "65536").is_err());
        assert_eq!(apply_core_kv(&mut cfg, "output-filename", "x"), Ok(false));
    }

    #[test]
    fn echo_extension_prints_new_keys_in_c_table_order_and_roundtrips() {
        let mut cfg = cfg_with("10.0.0.0/30", "80");
        cfg.retries = 1;
        for (k, v) in [
            ("noreset", "true"),
            ("ttl", "64"),
            ("badsum", ""),
            ("tcp-mss", "1400"),
            ("tcp-wscale", "7"),
            ("tcp-tsecho", "enable"),
            ("tcp-sackok", ""),
            ("adapter-port", "41234-41250"),
        ] {
            apply_core_kv(&mut cfg, k, v).unwrap();
        }
        assert!(cfg.nics[0].legacy_c_17_port_mask);
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        let pos = |needle: &str| s.find(needle).unwrap_or_else(|| panic!("{needle} in {s}"));
        let order = [
            "retries = 1\n",
            "noreset = true\n",
            "nocapture = servername\n",
            "ttl = 64\n",
            "badsum = true\n",
            "tcp-mss = 1400\n",
            "tcp-wscale = 7\n",
            "tcp-tsecho = enable\n",
            "tcp-sackok = enable\n",
            "adapter-port = 41234-41250\n",
            "# TARGET SELECTION",
        ];
        for w in order.windows(2) {
            assert!(pos(w[0]) < pos(w[1]), "{} before {}: {s}", w[0], w[1]);
        }
        let back = read_paused_conf(&s).unwrap();
        assert_eq!(back.tcp_opts, cfg.tcp_opts);
        assert!(back.nics[0].legacy_c_17_port_mask);
        let mut s2 = String::new();
        echo(&back, false, &mut s2);
        assert_eq!(s, s2);
    }

    /// Порядок ключей `nmap-payloads` и `pcap-payloads` в `--echo` снят с C (`masscan --echo ... --retries 2 --noreset
    /// --nmap-payloads X --pcap-payloads Y --offline --pcap Z --ndjson-status`): `config_parameters[]`, main-conf.c:2380-2399.
    #[test]
    fn echo_prints_payload_file_keys_in_c_order() {
        let mut cfg = cfg_with("10.0.0.0/30", "80");
        cfg.retries = 2;
        cfg.noreset = true;
        cfg.offline = true;
        for (k, v) in [
            ("nmap-payloads", "/tmp/x.txt"),
            ("pcap-payloads", "/tmp/y.pcap"),
        ] {
            assert_eq!(apply_core_kv(&mut cfg, k, v), Ok(true), "{k}");
        }
        // синонимы C: `nmap-payload` и `pcap-payload` (main-conf.c:2382, 2386)
        assert_eq!(
            apply_core_kv(&mut cfg, "nmap-payload", "/tmp/x.txt"),
            Ok(true)
        );
        assert_eq!(
            apply_core_kv(&mut cfg, "pcap-payload", "/tmp/y.pcap"),
            Ok(true)
        );
        assert_eq!(
            validate(&cfg, Operation::Scan).unwrap().nmap_payloads(),
            Some("/tmp/x.txt")
        );
        assert_eq!(
            validate(&cfg, Operation::Scan).unwrap().pcap_payloads(),
            Some("/tmp/y.pcap")
        );
        let mut s = String::new();
        echo_with(
            &cfg,
            false,
            &EchoExtras {
                pcap_filename: Some("/tmp/z.pcap"),
                ndjson_status: true,
                output_section: "",
            },
            &mut s,
        );
        let head: String = s
            .lines()
            .take_while(|l| !l.starts_with("nocapture"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(
            head,
            "seed = 1\nrate = 100       \nshard = 1/1\nretries = 2\nnoreset = true\nnmap-payloads = /tmp/x.txt\n\
             offline = true\npcap-filename = /tmp/z.pcap\npcap-payloads = /tmp/y.pcap\nndjson-status = true\n"
        );
        // paused.conf возвращает те же ключи
        let back = read_paused_conf(&s).unwrap();
        assert_eq!(back.nmap_payloads.as_deref(), Some("/tmp/x.txt"));
        assert_eq!(back.pcap_payloads.as_deref(), Some("/tmp/y.pcap"));
        // без ключей ничего не печатается
        let mut plain = String::new();
        echo(&cfg_with("10.0.0.0/30", "80"), false, &mut plain);
        assert!(!plain.contains("payloads"), "{plain}");
    }

    #[test]
    fn echo_default_probe_params_print_nothing_and_17_wide_cli_port_stays_rejected() {
        let cfg = cfg_with("10.0.0.0/30", "80");
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        for k in [
            "ttl", "badsum", "noreset", "tcp-", "pcap", "ndjson", "output-",
        ] {
            assert!(!s.contains(k), "{k}: {s}");
        }
        assert!(parse_source_port("41234-41250").is_err());
    }
    /// T1 M-2 + T2 M-4: поблажка 17 портов принадлежит адаптеру, а не конфигурации; порядок ключей не важен.
    #[test]
    fn legacy_17_port_flag_is_per_nic_and_independent_of_key_order() {
        let order_a = [
            ("adapter-port[0]", "41234-41250"),
            ("adapter-port[1]", "5000-5003"),
        ];
        let order_b = [
            ("adapter-port[1]", "5000-5003"),
            ("adapter-port[0]", "41234-41250"),
        ];
        for order in [order_a, order_b] {
            let mut cfg = cfg_with("10.0.0.0/30", "80");
            for (k, v) in order {
                apply_core_kv(&mut cfg, k, v).unwrap();
            }
            assert!(cfg.nics[0].legacy_c_17_port_mask, "{order:?}");
            assert!(!cfg.nics[1].legacy_c_17_port_mask, "{order:?}");
            let eff = validate(&cfg, Operation::Scan).unwrap();
            assert!(eff.nics()[0].legacy_c_17_port_mask);
            assert!(!eff.nics()[1].legacy_c_17_port_mask);
        }
        // Явный диапазон степени двойки у того же адаптера снимает флаг; соседний флаг не трогает.
        let mut cfg = cfg_with("10.0.0.0/30", "80");
        apply_core_kv(&mut cfg, "adapter-port[0]", "41234-41250").unwrap();
        apply_core_kv(&mut cfg, "adapter-port[1]", "6000-6016").unwrap();
        apply_core_kv(&mut cfg, "adapter-port[0]", "5000-5003").unwrap();
        assert!(!cfg.nics[0].legacy_c_17_port_mask);
        assert!(cfg.nics[1].legacy_c_17_port_mask);
        // Ширина, отличная от 17 и не степень двойки, не принимается ни с каким флагом.
        for bad in ["5000-5014", "5000-5019", "5000-5002"] {
            assert!(
                apply_core_kv(&mut cfg, "adapter-port[2]", bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn effective_config_exposes_packet_modifiers() {
        let mut cfg = cfg_with("10.0.0.0/30", "80");
        let m = validate(&cfg, Operation::Scan).unwrap().packet_modifiers();
        assert_eq!(m, crate::packet::PacketModifiers::default());
        for (k, v) in [("ttl", "64"), ("badsum", ""), ("tcp-wscale", "7")] {
            apply_core_kv(&mut cfg, k, v).unwrap();
        }
        let m = validate(&cfg, Operation::Scan).unwrap().packet_modifiers();
        assert_eq!((m.ttl, m.badsum, m.tcp.wscale), (64, true, Some(7)));
    }

    #[test]
    fn echo_prints_sticky_prefixed_ports_like_c() {
        // Тот же вход, что в sticky_port_prefixes_and_oproto_live_refusal.
        // C (masscan_echo, main-conf.c:3681-3732) печатает O:47 как `I:303`:
        // ветка `>= Templ_ICMP_echo` стоит раньше ветки Oproto и перехватывает
        // её. Сверено с masscan 8e6b3b0 (`--echo`); `I:303` разбирается обратно
        // в тот же индекс 196911.
        let mut cfg = cfg_with("10.0.0.1", "");
        targets::parse_ports(cfg.targets.ports_mut(), "U:53,161,T:80-81,s:2905,I:0,o:47").unwrap();
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        assert!(
            s.contains("ports = 80-81,U:53,U:161,S:2905,I:0,I:303\n"),
            "{s}"
        );
    }

    // ---- IPv6 stage, Task 2 --------------------------------------------------------------------

    fn cfg_v46(targets_s: &str, ports_s: &str) -> ScanConfig {
        let mut cfg = ScanConfig {
            seed: 1,
            ..ScanConfig::default()
        };
        cfg.targets.add_target_string(targets_s).unwrap();
        targets::parse_ports(cfg.targets.ports_mut(), ports_s).unwrap();
        cfg
    }

    /// Review Focus 1. C binary: `-sL --seed 42 --range 2001:db8::/64 -p80` fails with
    /// "scan range too large, max is 63-bits, requested is 65 bits" (main.c:1698-1704),
    /// `/66 -p80` lists, `/66 -p80,81` fails (2^63 is 64 bits).
    #[test]
    fn ipv6_slash_64_exceeds_63_bits_while_slash_66_succeeds() {
        for op in [Operation::List, Operation::Scan, Operation::Echo] {
            assert_eq!(
                err(&cfg_v46("2001:db8::/64", "80"), op),
                ConfigError::RangeOverflow(RangeOverflow { bits: 65 }),
                "{op:?}"
            );
            assert_eq!(
                err(&cfg_v46("2001:db8::/66", "80,81"), op),
                ConfigError::RangeOverflow(RangeOverflow { bits: 64 }),
                "{op:?}"
            );
        }
        let text = err(&cfg_v46("2001:db8::/64", "80"), Operation::List).to_string();
        assert!(
            text.starts_with("scan range too large, max is 63-bits, requested is 65 bits"),
            "{text}"
        );
        assert!(text.contains("/66"), "{text}");
        // `::/0` (count_u128 == u128::MAX is an overflow marker): 128 bits, never printed as exact
        assert_eq!(
            err(&cfg_v46("::/0", "80"), Operation::List),
            ConfigError::RangeOverflow(RangeOverflow { bits: 128 })
        );
        // /66 with one port is exactly 2^62
        for op in [Operation::List, Operation::Echo] {
            assert_eq!(
                validate(&cfg_v46("2001:db8::/66", "80"), op)
                    .unwrap()
                    .range(),
                1 << 62
            );
        }
    }

    /// main.c:1236-1238: C печатает три строки LOG(0, ...), а не одну. Отказ показывается как есть, без обёртки.
    #[test]
    fn exclude_required_prints_c_second_hint() {
        assert_eq!(
            ConfigError::ExcludeRequired.to_string(),
            "FAIL: range too big, need confirmation\n\
             \x20[hint] to prevent accidents, at least one --exclude must be specified\n\
             \x20[hint] use \"--exclude 255.255.255.255\" as a simple confirmation"
        );
    }

    /// R24, граница main.c:1235 (`count_ips > 1000000000`): ровно 1e9 адресов подтверждения не требует, 1e9 + 1
    /// требует; IPv6-исключение подтверждает только переполнение, вызванное целями IPv6 (R23).
    #[test]
    fn r24_boundary_exactly_1e9() {
        // 0.0.0.0-59.154.201.255 = 0x3B9ACA00 = 1_000_000_000 адресов
        let exactly = || cfg_v46("0.0.0.0-59.154.201.255", "80");
        assert_eq!(
            validate(&exactly(), Operation::Scan).unwrap().range(),
            1_000_000_000
        );
        // 1e9 + 1 за счёт IPv4: нужен IPv4-exclude, IPv6-исключение не помогает
        let over_v4 = || cfg_v46("0.0.0.0-59.154.202.0", "80");
        assert_eq!(
            err(&over_v4(), Operation::Scan),
            ConfigError::ExcludeRequired
        );
        let mut cfg = over_v4();
        cfg.excludes.add_target_string("2001:db8::1").unwrap();
        assert_eq!(err(&cfg, Operation::Scan), ConfigError::ExcludeRequired);
        let mut cfg = over_v4();
        cfg.excludes.add_target_string("255.255.255.255").unwrap();
        assert!(validate(&cfg, Operation::Scan).is_ok());
        // 1e9 IPv4 + один адрес IPv6 = 1e9 + 1: требует подтверждения; IPv6-исключение подтверждает (R23)
        let mut cfg = exactly();
        cfg.targets.add_target_string("2001:db8::1").unwrap();
        assert_eq!(err(&cfg, Operation::Scan), ConfigError::ExcludeRequired);
        cfg.excludes.add_target_string("2001:db8::ff").unwrap();
        assert!(validate(&cfg, Operation::Scan).is_ok());
    }

    /// R24. main.c:1235 confirms an over-1e9 scan only with an IPv4 exclude. rmasscan also accepts an IPv6
    /// exclude, but only when the overflow comes from the IPv6 targets (the IPv4 targets alone are within 1e9).
    #[test]
    fn ipv6_exclude_confirms_only_an_overflow_the_ipv6_targets_cause() {
        let with_exclude = |targets: &str, exclude: &str| {
            let mut cfg = cfg_v46(targets, "80");
            cfg.excludes.add_target_string(exclude).unwrap();
            cfg
        };
        // pure IPv4 over 1e9: an IPv6 exclude must not confirm (as C)
        assert_eq!(
            err(&with_exclude("0.0.0.0/0", "::1"), Operation::Scan),
            ConfigError::ExcludeRequired
        );
        // no exclude at all: refused
        assert_eq!(
            err(&cfg_v46("0.0.0.0/0", "80"), Operation::Scan),
            ConfigError::ExcludeRequired
        );
        assert_eq!(
            err(&cfg_v46("2001:db8::/66", "80"), Operation::Scan),
            ConfigError::ExcludeRequired
        );
        // IPv4 targets alone over 1e9 plus a small IPv6 set: an IPv6-only exclude is still refused
        let mut cfg = with_exclude("0.0.0.0/0", "2001:db8::1");
        cfg.targets.add_target_string("2001:db8::/120").unwrap();
        assert_eq!(err(&cfg, Operation::Scan), ConfigError::ExcludeRequired);
        // an IPv4 exclude confirms everything, as C
        assert!(
            validate(
                &with_exclude("0.0.0.0/0", "255.255.255.255"),
                Operation::Scan
            )
            .is_ok()
        );
        let mut cfg = with_exclude("0.0.0.0/0", "255.255.255.255");
        cfg.targets.add_target_string("2001:db8::/120").unwrap();
        assert!(validate(&cfg, Operation::Scan).is_ok());
        assert_eq!(
            validate(
                &with_exclude("2001:db8::/66", "255.255.255.255"),
                Operation::Scan
            )
            .unwrap()
            .range(),
            1 << 62
        );
        // the overflow comes from the IPv6 targets: an IPv6 exclude confirms
        assert!(
            validate(
                &with_exclude("2001:db8::/66", "2001:db8::1"),
                Operation::Scan
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_counts_ipv6_targets_for_emptiness() {
        // IPv6 only: the list is not empty (main.c:1717)
        let eff = validate(
            &cfg_v46("2001:db8::10-2001:db8::13", "80,443"),
            Operation::Scan,
        )
        .unwrap();
        assert_eq!((eff.range(), eff.massip().range_ipv6()), (8, 8));
        // everything excluded: the "removed by exclusion ranges" error, not "empty"
        let mut cfg = cfg_v46("2001:db8::10", "80");
        cfg.excludes.add_target_string("2001:db8::/64").unwrap();
        assert_eq!(err(&cfg, Operation::Scan), ConfigError::TargetsExcluded);
        assert_eq!(err(&cfg, Operation::List), ConfigError::TargetsExcluded);
        // an IPv4 exclude does not touch IPv6 targets
        let mut cfg = cfg_v46("2001:db8::10", "80");
        exclude(&mut cfg, "10.0.0.0/8");
        assert_eq!(validate(&cfg, Operation::Scan).unwrap().range(), 1);
        // no targets at all
        assert_eq!(
            err(&cfg_v46("", "80"), Operation::Scan),
            ConfigError::EmptyTargets
        );
    }

    /// Output of the C binary 8e6b3b0 for
    /// `--echo --seed 42 2001:db8::/126 2001:db8::5-2001:db8::9 ::1 192.0.2.0/30 -p80,U:53
    /// --exclude 2001:db8::2`: IPv4 `range =` lines first, then IPv6 sorted by
    /// address (main-conf.c:3762-3781).
    #[test]
    fn echo_ipv6_ranges_match_c_binary() {
        let mut cfg = cfg_v46(
            "2001:db8::/126,2001:db8::5-2001:db8::9,::1,192.0.2.0/30",
            "80",
        );
        cfg.targets
            .ports_mut()
            .add_range(TEMPL_UDP + 53, TEMPL_UDP + 53);
        cfg.excludes.add_target_string("2001:db8::2").unwrap();
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        assert!(
            s.ends_with(
                "ports = 80,U:53\nrange = 192.0.2.0/30\nrange = ::1\nrange = 2001:db8::/127\n\
                 range = 2001:db8::3\nrange = 2001:db8::5-2001:db8::9\n"
            ),
            "{s}"
        );
    }

    /// C binary, `--echo --range ...` of many shapes: `count_cidr6_bits` decides between
    /// `/bits` (exact, nonzero) and `-end` (main-conf.c:245-285, :3768-3776).
    #[test]
    fn echo_ipv6_cidr_or_range_matches_c_binary() {
        let mut cfg = cfg_v46(
            "2001:db8::/120,2001:db8:1::1-2001:db8:1::2,2001:db8:2::4-2001:db8:2::7,\
             2001:db8:3::1-2001:db8:3::4,::/66,2001:db8:4::8/125,2001:db8:5::0-2001:db8:5::0,\
             2001:db8:6::10/128,2001:DB8:7::ffff:0:0/96,2001:db8:8::1-2001:db8:8::f",
            "80",
        );
        cfg.seed = 42;
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        let tail = s.split_once("ports = 80\n").unwrap().1;
        assert_eq!(
            tail,
            "range = ::/66\n\
             range = 2001:db8::/120\n\
             range = 2001:db8:1::1-2001:db8:1::2\n\
             range = 2001:db8:2::4/126\n\
             range = 2001:db8:3::1-2001:db8:3::4\n\
             range = 2001:db8:4::8/125\n\
             range = 2001:db8:5::\n\
             range = 2001:db8:6::10\n\
             range = 2001:db8:7::ffff:0:0/96\n\
             range = 2001:db8:8::1-2001:db8:8::f\n"
        );
    }

    /// C binary: `--exclude 2001:db8::1 --range 2001:db8::/126 --exclude 2001:db8::/127`
    /// leaves `range = 2001:db8::2/127`.
    #[test]
    fn echo_ipv6_after_excludes_matches_c_binary() {
        let mut cfg = cfg_v46("2001:db8::/126", "80");
        cfg.excludes.add_target_string("2001:db8::1").unwrap();
        cfg.excludes.add_target_string("2001:db8::/127").unwrap();
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        assert!(s.ends_with("range = 2001:db8::2/127\n"), "{s}");
    }

    /// `count_cidr6_bits` edge cases the C loop has: a range inside one block that does not
    /// fill it keeps looking, a range spanning blocks answers non-exact, `::/0` answers
    /// exact with 0 bits (printed as `-end`).
    #[test]
    fn count_cidr6_bits_follows_c_loop() {
        assert_eq!(count_cidr6_bits(0, u128::MAX), (0, true));
        assert_eq!(count_cidr6_bits(0, 3), (126, true));
        assert_eq!(count_cidr6_bits(0, 2), (127, false));
        assert_eq!(count_cidr6_bits(1, 2), (128, false));
        assert_eq!(count_cidr6_bits(4, 7), (126, true));
        assert_eq!(count_cidr6_bits(1, 4), (128, false));
    }

    /// `paused.conf` written by `--echo` reads back into the same targets.
    #[test]
    fn echo_with_ipv6_reads_back_through_paused_conf() {
        let mut cfg = cfg_v46(
            "2001:db8::/120,2001:db8:1::1-2001:db8:1::2,192.0.2.0/30",
            "80",
        );
        cfg.seed = 9;
        let mut s = String::new();
        echo(&cfg, false, &mut s);
        let back = read_paused_conf(&s).unwrap();
        let (mut a, mut b) = (cfg.targets.clone(), back.targets.clone());
        a.optimize();
        b.optimize();
        assert_eq!(a.ipv6().as_slice(), b.ipv6().as_slice());
        assert_eq!(a.ipv4().as_slice(), b.ipv4().as_slice());
    }
}
