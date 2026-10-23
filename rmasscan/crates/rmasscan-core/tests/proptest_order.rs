//! Property-тесты (proptest, чистый Rust; cargo-fuzz не используется, спека §12
//! вопрос 3) для инвариантов перестановки и устойчивости парсеров
//! (AGPL-3.0, порт masscan © Robert David Graham: crypto-blackrock.c,
//! main-listscan.c, main.c:203-448, massip.c).

use proptest::prelude::*;
use rmasscan_core::blackrock::BlackRock;
use rmasscan_core::config::{Operation, ScanConfig, echo, parse_rate, read_paused_conf, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::ranges::RangeList;
use rmasscan_core::scan::{
    Shard, list_scan, list_scan_indices, transmit_index_stream, transmit_scan,
};
use rmasscan_core::targets::{add_target_string, parse_ports};
use std::collections::BTreeSet;

/// Строки, похожие на реальные входы: цифры, точки, слэши, дефисы, запятые, пробелы.
fn plausible() -> impl Strategy<Value = String> {
    "[0-9./,:\\- UTSOIa-f]{0,40}"
}

/// Произвольный текст плюс правдоподобный.
fn any_text() -> impl Strategy<Value = String> {
    prop_oneof![plausible(), ".{0,60}", any::<String>()]
}

/// Построить MassIp и ожидаемое множество (ip, port) после исключений.
fn build(ips: &[(u32, u32)], ports: &[u16], excl: &[(u32, u32)]) -> (MassIp, BTreeSet<(u32, u32)>) {
    let mut expected_ips = BTreeSet::new();
    let mut ex_set = BTreeSet::new();
    let mut t = MassIp::new();
    for &(b, l) in ips {
        t.ipv4_mut().add_range(b, b + l);
        expected_ips.extend(b..=b + l);
    }
    let mut ex = MassIp::new();
    for &(b, l) in excl {
        ex.ipv4_mut().add_range(b, b + l);
        ex_set.extend(b..=b + l);
    }
    let port_set: BTreeSet<u32> = ports.iter().map(|&p| u32::from(p)).collect();
    for &p in &port_set {
        t.ports_mut().add_range(p, p);
    }
    t.apply_excludes(&mut ex); // main.c:1673 до optimize
    t.optimize(); // main.c:1684
    let mut expected = BTreeSet::new();
    for &ip in expected_ips.difference(&ex_set) {
        for &p in &port_set {
            expected.insert((ip, p));
        }
    }
    (t, expected)
}

/// Диапазоны в узком окне, чтобы исключения реально пересекались с целями.
fn small_ranges(max: usize) -> impl Strategy<Value = Vec<(u32, u32)>> {
    prop::collection::vec((0x0A00_0000u32..0x0A00_0100, 0u32..40), 1..=max)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    // crypto-blackrock.c: shuffle — перестановка 0..range, unshuffle обратна.
    #[test]
    fn blackrock_is_bijective_on_small_ranges(range in 9u64..2000, seed in any::<u64>()) {
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

    #[test]
    fn list_scan_visits_every_target_once(
        ips in small_ranges(3),
        ports in prop::collection::vec(1u16..=65535, 1..=8),
        excl in prop::option::of(small_ranges(2)),
        seed in any::<u64>(),
    ) {
        let (t, expected) = build(&ips, &ports, excl.as_deref().unwrap_or(&[]));
        if expected.is_empty() {
            prop_assert_eq!(t.range(), 0);
            return Ok(());
        }
        prop_assert_eq!(t.range(), expected.len() as u64);
        let mut got = Vec::new();
        list_scan(&t, seed, 14, Shard::default(), 0, None, 0, 0.0,
            |ip, port| got.push((ip, port))).unwrap();
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

    // main-listscan.c:31-34: resume.count ограничивает end = start + count.
    #[test]
    fn resume_continues_the_order(range in 1u64..400, k in 1u64..400) {
        let k = k.min(range);
        let full: Vec<u64> = list_scan_indices(range, Shard::default(), 0, None, 0, 0.0).collect();
        let mut parts: Vec<u64> =
            list_scan_indices(range, Shard::default(), 0, Some(k), 0, 0.0).collect();
        parts.extend(list_scan_indices(range, Shard::default(), k, None, 0, 0.0));
        prop_assert_eq!(full, parts);
    }

    // Спека §4.3: transmit при retries 0: xXx = (i + rate) mod range (main.c:328-333).
    #[test]
    fn transmit_retries0_is_list_shifted_by_rate(
        range in 1u64..400, rate in 0u64..1_000_000)
    {
        let xs: Vec<u64> = transmit_index_stream(
            range, Shard::default(), 1, 0, 0, None, 0, rate as f64)
            .map(|(_, x)| x).collect();
        let want: Vec<u64> = (0..range).map(|i| (i + rate) % range).collect();
        prop_assert_eq!(xs, want);
    }

    // То же через transmit_scan: ip/port == pick(shuffle(xXx)), без дубликатов.
    #[test]
    fn transmit_scan_is_permutation(
        ips in small_ranges(2),
        ports in prop::collection::vec(1u16..=65535, 1..=4),
        seed in any::<u64>(), rate in 0u64..100_000)
    {
        let (t, expected) = build(&ips, &ports, &[]);
        let mut got = BTreeSet::new();
        let mut n = 0usize;
        transmit_scan(&t, seed, 14, Shard::default(), 1, 0, 0, None, 0, rate as f64,
            |_, _, _, ip, port| { got.insert((ip, port)); n += 1; }).unwrap();
        prop_assert_eq!(n, got.len());
        prop_assert_eq!(got, expected);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn parse_ports_never_panics(s in any_text()) {
        let _ = parse_ports(&mut RangeList::new(), &s);
    }

    #[test]
    fn add_target_string_never_panics(s in any_text()) {
        let _ = add_target_string(&mut RangeList::new(), &s);
    }

    #[test]
    fn parse_rate_never_panics(s in any_text()) {
        let _ = parse_rate(&s);
    }

    #[test]
    fn read_paused_conf_never_panics(s in prop_oneof![
        any_text(),
        "(((seed|rate|ports|range|shard|retries|exclude|wait|capture|nocapture|resume-index|resume-count) ?= ?[0-9a-z./,:\\- ]{0,20})\n?){0,6}",
    ]) {
        if let Ok(cfg) = read_paused_conf(&s) {
            // Успешный разбор не должен ломать validate/echo.
            let _ = validate(&cfg, Operation::Scan);
            let mut out = String::new();
            echo(&cfg, false, &mut out);
            let _: ScanConfig = cfg;
        }
    }
}
