//! Property-тесты (proptest, чистый Rust; cargo-fuzz не используется, спека §12
//! вопрос 3) для инвариантов перестановки и устойчивости парсеров.
//! AGPL-3.0, порт masscan © Robert David Graham. Источники: crypto-blackrock.c,
//! main-listscan.c, main.c:203-448 (transmit), massip.c, massip-parse.c
//! (цели), massip-rangesv4.c (диапазоны), main-conf.c (порты, rate, paused.conf).
//!
//! Failure persistence: регрессии пишутся в
//! `tests/proptest-regressions/proptest_order.txt` (относительно крейта).
//! Решение: файл, если появится, КОММИТИТЬ (рекомендация proptest): он
//! воспроизводит найденные минимизированные входы на каждом прогоне. Сейчас
//! файла нет, потому что ни одно свойство не падало.
//!
//! Парсерные свойства используют структурированные генераторы (иначе они
//! отваливались на первом символе) и в конце проверяют счётчики глубоких
//! состояний. Измеренные доли (2000 прогонов): см. пороги в `assert!` ниже.

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use rmasscan_core::blackrock::BlackRock;
use rmasscan_core::config::{Operation, echo, parse_rate, read_paused_conf, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::ranges::RangeList;
use rmasscan_core::scan::{
    ScanError, Shard, format_list_line, list_scan, list_scan_indices, transmit_index_stream,
    transmit_scan,
};
use rmasscan_core::targets::{add_target_string, parse_ports};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

fn cfg(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "tests/proptest-regressions/proptest_order.txt",
        ))),
        ..ProptestConfig::default()
    }
}

// ---------------------------------------------------------------------
// Структурированные генераторы
// ---------------------------------------------------------------------

fn octet() -> impl Strategy<Value = String> {
    prop_oneof![
        8 => (0u32..=255).prop_map(|n| n.to_string()),
        1 => "[0-9]{0,4}",
        1 => Just("00".to_string()),
    ]
}

fn ipv4() -> impl Strategy<Value = String> {
    prop_oneof![
        9 => (octet(), octet(), octet(), octet()).prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}")),
        1 => prop::collection::vec(octet(), 1..6).prop_map(|v| v.join(".")),
    ]
}

fn target_tok() -> impl Strategy<Value = String> {
    let dash = prop_oneof![
        Just("-"),
        Just("\u{2010}"),
        Just("\u{2013}"),
        Just("\u{2015}"),
        Just("\u{2016}"),
        Just(" - ")
    ];
    prop_oneof![
        4 => ipv4(),
        3 => (ipv4(), "[0-9]{0,3}").prop_map(|(a, n)| format!("{a}/{n}")),
        3 => (ipv4(), dash, ipv4()).prop_map(|(a, d, b)| format!("{a}{d}{b}")),
        1 => "[0-9a-fA-F:\\[\\]]{1,12}",
        1 => "[#;/\\-][^\n]{0,8}\n?",
    ]
}

fn target_str() -> impl Strategy<Value = String> {
    (
        prop::collection::vec(target_tok(), 0..5),
        prop_oneof![Just(","), Just(" "), Just(", "), Just("\t"), Just(",,")],
    )
        .prop_map(|(v, sep)| v.join(sep))
}

fn port_tok() -> impl Strategy<Value = String> {
    let num = prop_oneof![
        6 => (0u32..=70000).prop_map(|n| n.to_string()),
        1 => "0x[0-9a-fA-F]{1,5}",
        1 => "0[0-7]{1,6}",
        1 => Just(String::new()),
    ];
    let pre = prop_oneof![
        6 => Just(""), 2 => Just("T:"), 1 => Just("t:"), 1 => Just("U:"),
        1 => Just("S:"), 1 => Just("I:"), 1 => Just("O:"), 1 => Just("X:"),
    ];
    (pre, num.clone(), prop::option::of(num), " ?").prop_map(|(p, a, b, s)| match b {
        Some(b) => format!("{p}{a}-{b}{s}"),
        None => format!("{p}{a}{s}"),
    })
}

fn port_str() -> impl Strategy<Value = String> {
    (
        prop::collection::vec(port_tok(), 0..5),
        prop_oneof![Just(","), Just(", "), Just(" ,")],
        prop::option::of("#[ -~]{0,5}"),
    )
        .prop_map(|(v, sep, c)| format!("{}{}", v.join(sep), c.unwrap_or_default()))
}

/// Строки paused.conf из структурированных генераторов (+ служебные ключи).
fn conf_line() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => target_str().prop_map(|v| format!("range = {v}")),
        1 => target_str().prop_map(|v| format!("exclude = {v}")),
        3 => port_str().prop_map(|v| format!("ports = {v}")),
        1 => any::<u64>().prop_map(|v| format!("seed = {v}")),
        1 => "[0-9]{1,8}(\\.[0-9]{0,6})?".prop_map(|v| format!("rate = {v}")),
        1 => (0u32..6, 0u32..6).prop_map(|(a, b)| format!("shard = {a}/{b}")),
        1 => (0u32..4).prop_map(|v| format!("retries = {v}")),
        1 => (0u64..2000).prop_map(|v| format!("resume-index = {v}")),
        1 => (0u64..2000).prop_map(|v| format!("resume-count = {v}")),
        1 => (0u32..70).prop_map(|v| format!("blackrock-rounds = {v}")),
        1 => prop_oneof![
            Just("adapter = eth0"),
            Just("adapter-ip = 10.0.0.1"),
            Just("adapter-mac = 00-11-22-33-44-55"),
            Just("router-mac = 0:1:2:3:4:5"),
            Just("adapter-port = 40000-40255"),
            Just("source-port = 61000"),
            Just("adapter-port = 5-4"),
            Just("offline = true"),
            Just("offline = nope"),
            Just("nocapture = html"),
        ].prop_map(String::from),
    ]
}

/// Заведомо корректные строки: без них любая плохая строка обрывает весь разбор
/// и до targets/validate доходит ничтожная доля конфигов.
fn good_conf_line() -> impl Strategy<Value = String> {
    let ip = (0u32..=255, 0u32..=255, 0u32..=255, 0u32..=255)
        .prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}"));
    prop_oneof![
        3 => ip.clone().prop_map(|v| format!("range = {v}")),
        2 => (ip.clone(), 16u32..=32).prop_map(|(v, n)| format!("range = {v}/{n}")),
        1 => (ip.clone(), 0u32..=255).prop_map(|(v, d)| format!("exclude = {v}/{}", 24 + d % 9)),
        3 => (1u32..=65535, 0u32..20).prop_map(|(a, l)| format!("ports = {a}-{}", (a + l).min(65535))),
        1 => (1u32..=65535).prop_map(|a| format!("ports = T:{a}")),
        1 => any::<u64>().prop_map(|v| format!("seed = {v}")),
        1 => (1u32..=50_000).prop_map(|v| format!("rate = {v}.5")),
        1 => (0u32..3).prop_map(|v| format!("retries = {v}")),
        1 => Just("adapter-mac = 00-11-22-33-44-55".to_string()),
        1 => Just("source-port = 40000-40255".to_string()),
    ]
}

static AT_OK: AtomicU64 = AtomicU64::new(0);
static AT_CIDR: AtomicU64 = AtomicU64::new(0);
static AT_DASH: AtomicU64 = AtomicU64::new(0);
static AT_UNI: AtomicU64 = AtomicU64::new(0);
static PP_OK: AtomicU64 = AtomicU64::new(0);
static PP_RANGE: AtomicU64 = AtomicU64::new(0);
static PP_PREFIX: AtomicU64 = AtomicU64::new(0);
static PR_DEC: AtomicU64 = AtomicU64::new(0);
static PR_OK: AtomicU64 = AtomicU64::new(0);
static PC_TARGETS: AtomicU64 = AtomicU64::new(0);
static PC_VALID: AtomicU64 = AtomicU64::new(0);

const PARSER_CASES: u32 = 2000;

/// Измерено (2000 прогонов; paused: 1000): targets ~190-200 непустых, ports ~270,
/// rate ~1800 (дробных ~900), paused ~400 с targets и ~1470 успешных validate.
/// Пороги в 2-4 раза ниже, чтобы свойства не деградировали до отказа на первом символе.
#[test]
fn add_target_string_never_panics_and_reaches_deep_states() {
    proptest!(cfg(PARSER_CASES), |(s in prop_oneof![9 => target_str(), 1 => any::<String>()])| {
        let mut rl = RangeList::new();
        if add_target_string(&mut rl, &s).is_ok() && !rl.is_empty() {
            AT_OK.fetch_add(1, Relaxed);
            if s.contains('/') { AT_CIDR.fetch_add(1, Relaxed); }
            if s.contains('-') { AT_DASH.fetch_add(1, Relaxed); }
            if s.contains(['\u{2010}', '\u{2013}', '\u{2015}']) { AT_UNI.fetch_add(1, Relaxed); }
            for r in rl.as_slice() { prop_assert!(r.begin <= r.end); }
        }
    });
    eprintln!(
        "targets ok_nonempty={} cidr={} dash={} unicode={}",
        AT_OK.load(Relaxed),
        AT_CIDR.load(Relaxed),
        AT_DASH.load(Relaxed),
        AT_UNI.load(Relaxed)
    );
    assert!(
        AT_OK.load(Relaxed) >= PARSER_CASES as u64 / 40,
        "targets accepts degraded"
    );
    assert!(
        AT_CIDR.load(Relaxed) > 0 && AT_DASH.load(Relaxed) > 0,
        "no CIDR/dash accepts"
    );
    assert!(AT_UNI.load(Relaxed) > 0, "no unicode-dash accepts");
}

#[test]
fn parse_ports_never_panics_and_reaches_deep_states() {
    proptest!(cfg(PARSER_CASES), |(s in prop_oneof![9 => port_str(), 1 => any::<String>()])| {
        let mut rl = RangeList::new();
        if parse_ports(&mut rl, &s).is_ok() && !rl.is_empty() {
            PP_OK.fetch_add(1, Relaxed);
            if rl.as_slice().iter().any(|r| r.end > r.begin) { PP_RANGE.fetch_add(1, Relaxed); }
            if s.contains("T:") || s.contains("t:") { PP_PREFIX.fetch_add(1, Relaxed); }
        }
    });
    eprintln!(
        "ports ok_nonempty={} with_range={} T_prefix={}",
        PP_OK.load(Relaxed),
        PP_RANGE.load(Relaxed),
        PP_PREFIX.load(Relaxed)
    );
    assert!(
        PP_OK.load(Relaxed) >= PARSER_CASES as u64 / 40,
        "ports accepts degraded"
    );
    assert!(PP_RANGE.load(Relaxed) > 0, "no a-b range accepted");
    assert!(PP_PREFIX.load(Relaxed) > 0, "no T: prefix accepted");
}

#[test]
fn parse_rate_never_panics_and_reaches_deep_states() {
    proptest!(cfg(PARSER_CASES), |(s in prop_oneof![9 => "[0-9]{0,30}(\\.[0-9]{0,30})?", 1 => any::<String>()])| {
        if let Ok(v) = parse_rate(&s) {
            prop_assert!(v >= 0.0 || v.is_nan());
            PR_OK.fetch_add(1, Relaxed);
            if s.contains('.') && s.len() > 2 { PR_DEC.fetch_add(1, Relaxed); }
        }
    });
    eprintln!(
        "rate ok={} decimals={}",
        PR_OK.load(Relaxed),
        PR_DEC.load(Relaxed)
    );
    assert!(
        PR_OK.load(Relaxed) >= PARSER_CASES as u64 / 2,
        "rate accepts degraded"
    );
    assert!(
        PR_DEC.load(Relaxed) >= PARSER_CASES as u64 / 4,
        "rate decimals degraded"
    );
}

#[test]
fn read_paused_conf_never_panics_and_roundtrips_echo() {
    proptest!(cfg(1000), |(lines in prop_oneof![
            2 => prop::collection::vec(good_conf_line(), 0..8),
            1 => prop::collection::vec(conf_line(), 0..8),
        ], junk in prop::option::weighted(0.1, any::<String>()))| {
        let mut s = lines.join("\n");
        if let Some(j) = junk { s = j; }
        if let Ok(conf) = read_paused_conf(&s) {
            if !conf.targets.ipv4().is_empty() { PC_TARGETS.fetch_add(1, Relaxed); }
            let mut out1 = String::new();
            echo(&conf, false, &mut out1);
            // echo -> read -> echo: неподвижная точка.
            let back = read_paused_conf(&out1);
            prop_assert!(back.is_ok(), "echo not re-readable: {:?} -> {:?}", out1, back.err());
            let mut out2 = String::new();
            echo(&back.unwrap(), false, &mut out2);
            prop_assert_eq!(&out1, &out2);
            for op in [Operation::Scan, Operation::List, Operation::Echo] {
                if validate(&conf, op).is_ok() { PC_VALID.fetch_add(1, Relaxed); }
            }
        }
    });
    eprintln!(
        "paused with_targets={} validate_ok={}",
        PC_TARGETS.load(Relaxed),
        PC_VALID.load(Relaxed)
    );
    assert!(
        PC_TARGETS.load(Relaxed) >= 20,
        "paused confs with targets degraded"
    );
    assert!(
        PC_VALID.load(Relaxed) >= 50,
        "successful validates degraded"
    );
}

// ---------------------------------------------------------------------
// Порядок и перестановки
// ---------------------------------------------------------------------

type Spans = Vec<(u32, u32)>;

/// Диапазоны (begin, len) в узком окне, чтобы исключения реально пересекались.
fn spans(base: u32, window: u32, maxlen: u32, max: usize) -> impl Strategy<Value = Spans> {
    prop::collection::vec((base..base + window, 0..maxlen), 1..=max)
}

fn expand(s: &[(u32, u32)]) -> BTreeSet<u32> {
    s.iter().flat_map(|&(b, l)| b..=b + l).collect()
}

/// MassIp и ожидаемое множество (ip, port) после исключений IP и портов.
fn build(
    ips: &[(u32, u32)],
    ports: &[(u32, u32)],
    ex_ips: &[(u32, u32)],
    ex_ports: &[(u32, u32)],
) -> (MassIp, BTreeSet<(u32, u32)>) {
    let mut t = MassIp::new();
    for &(b, l) in ips {
        t.ipv4_mut().add_range(b, b + l);
    }
    for &(b, l) in ports {
        t.ports_mut().add_range(b, b + l);
    }
    let mut ex = MassIp::new();
    for &(b, l) in ex_ips {
        ex.ipv4_mut().add_range(b, b + l);
    }
    for &(b, l) in ex_ports {
        ex.ports_mut().add_range(b, b + l);
    }
    t.apply_excludes(&mut ex); // main.c:1673 до optimize
    t.optimize(); // main.c:1684
    let (ip_set, port_set) = (expand(ips), expand(ports));
    let (ex_ip, ex_port) = (expand(ex_ips), expand(ex_ports));
    let mut expected = BTreeSet::new();
    for &ip in ip_set.difference(&ex_ip) {
        for &p in port_set.difference(&ex_port) {
            expected.insert((ip, p));
        }
    }
    (t, expected)
}

fn collect_list(t: &MassIp, seed: u64) -> Vec<(u32, u32)> {
    let mut got = Vec::new();
    list_scan(t, seed, 14, Shard::default(), 0, None, 0, 0.0, |ip, p| {
        got.push((ip, p))
    })
    .unwrap();
    got
}

fn rates() -> impl Strategy<Value = u64> {
    // rate <= range: реалистичный режим `while` (main.c:332-333); большие: ветка `%`.
    prop_oneof![0u64..=400, 0u64..1_000_000]
}

proptest! {
    #![proptest_config(cfg(512))]

    // crypto-blackrock.c: shuffle — перестановка 0..range, unshuffle обратна.
    #[test]
    fn blackrock_is_bijective_on_small_ranges(range in 1u64..2000, seed in any::<u64>()) {
        let br = BlackRock::try_new(range, seed, 14).unwrap();
        let mut seen = vec![false; range as usize];
        for i in 0..range {
            let x = br.shuffle(i);
            prop_assert!(x < range);
            prop_assert!(!seen[x as usize], "duplicate output {}", x);
            seen[x as usize] = true;
            prop_assert_eq!(br.unshuffle(x), i);
        }
        prop_assert!(seen.iter().all(|&s| s));
    }
}

proptest! {
    #![proptest_config(cfg(128))]

    #[test]
    fn list_scan_visits_every_target_once(
        ips in spans(0x0A00_0000, 256, 40, 3),
        ports in spans(1, 60, 6, 3),
        ex_ips in prop::option::of(spans(0x0A00_0000, 256, 40, 2)),
        ex_ports in prop::option::of(spans(1, 60, 6, 2)),
        seed in any::<u64>(),
    ) {
        let (t, expected) = build(
            &ips, &ports, ex_ips.as_deref().unwrap_or(&[]), ex_ports.as_deref().unwrap_or(&[]));
        if expected.is_empty() {
            prop_assert_eq!(t.try_range().unwrap(), 0);
            let r = list_scan(&t, seed, 14, Shard::default(), 0, None, 0, 0.0, |_, _| {});
            prop_assert_eq!(r, Err(ScanError::EmptyRange));
            return Ok(());
        }
        prop_assert_eq!(t.range(), expected.len() as u64);
        let got = collect_list(&t, seed);
        prop_assert_eq!(got.len() as u64, t.range());
        let set: BTreeSet<(u32, u32)> = got.iter().copied().collect();
        prop_assert_eq!(set.len(), got.len(), "duplicate pairs");
        prop_assert_eq!(set, expected);
    }

    #[test]
    fn shards_partition_list_indices(range in 1u64..400, of in 1u32..5) {
        let mut all = Vec::new();
        for one in 1..=of {
            all.extend(list_scan_indices(range, Shard { one, of }, 0, None, 0, 0.0));
        }
        let set: BTreeSet<u64> = all.iter().copied().collect();
        prop_assert_eq!(set.len(), all.len(), "shards overlap");
        prop_assert_eq!(set, (0..range).collect::<BTreeSet<u64>>());
    }

    // main-listscan.c:31-34: resume.count ограничивает end = start + count (0 = без лимита).
    #[test]
    fn resume_continues_the_order(
        (range, k) in (1u64..400).prop_flat_map(|r| (Just(r), 1..=r)))
    {
        let full: Vec<u64> = list_scan_indices(range, Shard::default(), 0, None, 0, 0.0).collect();
        let mut parts: Vec<u64> =
            list_scan_indices(range, Shard::default(), 0, Some(k), 0, 0.0).collect();
        parts.extend(list_scan_indices(range, Shard::default(), k, None, 0, 0.0));
        prop_assert_eq!(full, parts);
    }

    // Спека §4.3: transmit при retries 0: xXx = (i + rate) mod range (main.c:328-333).
    #[test]
    fn transmit_retries0_is_list_shifted_by_rate(range in 1u64..400, rate in rates()) {
        let got: Vec<(u64, u64)> = transmit_index_stream(
            range, Shard::default(), 1, 0, 0, None, 0, rate as f64).collect();
        let want: Vec<(u64, u64)> = (0..range).map(|i| (i, (i + rate) % range)).collect();
        prop_assert_eq!(got, want);
    }

    // retries > 0: для каждого i по r = retries+1 .. 1: x = (i + r*rate) mod range
    // (main.c:213, :328, :421-424); end = range + retries*range (:273).
    #[test]
    fn transmit_with_retries_repeats_each_index(
        range in 1u64..60, retries in 1u32..4, rate in rates())
    {
        let got: Vec<(u64, u64)> = transmit_index_stream(
            range, Shard::default(), 1, 0, 0, None, retries, rate as f64).collect();
        let end = range + u64::from(retries) * range;
        let mut want = Vec::new();
        for i in 0..end {
            for r in (1..=u64::from(retries) + 1).rev() {
                want.push((i, (i + r * rate) % range));
            }
        }
        prop_assert_eq!(got, want);
    }

    // main.c:223, :269: шаг shard.of*nic_count, старт (one-1)*nic_count+nic_index.
    #[test]
    fn transmit_shard_nic_partition(range in 1u64..300, of in 1u32..5, nics in 1u32..4) {
        let mut all = Vec::new();
        for one in 1..=of {
            for nic in 0..nics {
                all.extend(
                    transmit_index_stream(range, Shard { one, of }, nics, nic, 0, None, 0, 0.0)
                        .map(|(i, _)| i),
                );
            }
        }
        let set: BTreeSet<u64> = all.iter().copied().collect();
        prop_assert_eq!(set.len(), all.len(), "overlap");
        prop_assert_eq!(set, (0..range).collect::<BTreeSet<u64>>());
    }

    // transmit_scan (retries 0): позиция j == позиция (j + rate) % range в list_scan.
    #[test]
    fn transmit_scan_is_rotated_list_scan(
        ips in spans(0x0A00_0000, 256, 40, 2),
        ports in spans(1, 60, 6, 2),
        seed in any::<u64>(), rate in rates())
    {
        let (t, _) = build(&ips, &ports, &[], &[]);
        let list = collect_list(&t, seed);
        let range = list.len() as u64;
        let mut tx = Vec::new();
        transmit_scan(&t, seed, 14, Shard::default(), 1, 0, 0, None, 0, rate as f64,
            |_, _, _, ip, port| tx.push((ip, port))).unwrap();
        prop_assert_eq!(tx.len(), list.len());
        for (j, pair) in tx.iter().enumerate() {
            prop_assert_eq!(*pair, list[((j as u64 + rate) % range) as usize]);
        }
    }

    // format_list_line (main-listscan.c:53-62) читается обратно нашими парсерами.
    #[test]
    fn list_line_round_trips(ip in any::<u32>(), port in 0u32..=65535, single in any::<bool>()) {
        let line = format_list_line(ip, port, single);
        let (ip_s, port_s) = match line.split_once(':') {
            Some((a, b)) => (a.to_string(), Some(b.to_string())),
            None => (line.clone(), None),
        };
        prop_assert_eq!(port_s.is_some(), !single);
        let mut ips = RangeList::new();
        add_target_string(&mut ips, &ip_s).unwrap();
        prop_assert_eq!((ips.count(), ips.get(0).begin), (1, ip));
        prop_assert_eq!(ip_s.parse::<Ipv4Addr>().unwrap(), Ipv4Addr::from(ip));
        if let Some(p) = port_s {
            let mut ports = RangeList::new();
            parse_ports(&mut ports, &p).unwrap();
            prop_assert_eq!((ports.count(), ports.get(0).begin), (1, port));
        }
    }
}
