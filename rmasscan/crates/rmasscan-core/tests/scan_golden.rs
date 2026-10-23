//! Oracle-проверка `-sL` по golden фикстурам через production-код
//! `scan::list_scan` (AGPL-3.0, порт masscan © Robert David Graham,
//! main-listscan.c + main.c:1673-1684).
//!
//! Для каждого IPv4 `-sL` кейса: excludes, optimize, `list_scan`, строки через
//! `format_list_line`. Усечённые кейсы сверяются по первым 2000 строкам,
//! `line_count` и sha256 всего потока (SHA-256 в common, test-only).

mod common;

use common::{GOLDEN_DIR, ListSpec, Sha256, load_manifest, parse_listscan_args};
use rmasscan_core::massip::MassIp;
use rmasscan_core::scan::{Shard, format_list_line, list_scan};
use rmasscan_core::targets::{add_target_string, parse_ports};

fn build(spec: &ListSpec) -> MassIp {
    let mut t = MassIp::new();
    add_target_string(t.ipv4_mut(), &spec.targets).unwrap();
    parse_ports(t.ports_mut(), &spec.ports).unwrap();
    let mut ex = MassIp::new();
    for e in &spec.excludes {
        add_target_string(ex.ipv4_mut(), e).unwrap();
    }
    t.apply_excludes(&mut ex); // main.c:1673
    t.optimize(); // main.c:1684
    t
}

const CHECKED: [&str; 21] = [
    "listscan/exclude_list_seed3.txt",
    "listscan/multirange_ports_seed7.txt",
    "listscan/range3_p80_seed1.txt",
    "listscan/single_ip_p80_seed1.txt",
    "listscan/slash22_p0-1023_seed1.head.txt",
    "listscan/slash24_p80-443_seed1.txt",
    "listscan/slash24_p80_seed1.txt",
    "listscan/slash24_p80_seed1_resume100_count50.txt",
    "listscan/slash24_p80_seed1_retries0.txt",
    "listscan/slash24_p80_seed1_retries2.txt",
    "listscan/slash24_p80_seed1_retries2_rate1000.txt",
    "listscan/slash24_p80_seed1_rounds14.txt",
    "listscan/slash24_p80_seed1_rounds4.txt",
    "listscan/slash24_p80_seed1_shard1of1.txt",
    "listscan/slash24_p80_seed1_shard2of3.txt",
    "listscan/slash24_p80_seed2.txt",
    "listscan/slash24_p80_seed4294967295.txt",
    "listscan/slash30_allports_seed1.head.txt",
    "listscan/slash30_p80_seed1.txt",
    "listscan/slash31_p80_seed1.txt",
    "listscan/slash8_excl_slash9_p80_seed1.head.txt",
];
const SKIPPED: [&str; 2] = [
    "listscan/ipv6_slash126_p80-443_seed1.txt",
    "listscan/ipv6_slash126_p80_seed1.txt",
];

#[test]
fn list_scan_matches_c_oracle_fixtures() {
    let mut checked = Vec::new();
    let mut skipped = Vec::new();
    for case in load_manifest()
        .cases
        .iter()
        .filter(|c| c.mode.as_deref() == Some("-sL"))
    {
        let file = case.file.as_deref().expect("file");
        let spec = parse_listscan_args(case.args.as_deref().expect("args"))
            .unwrap_or_else(|why| panic!("{file}: unparsable case: {why}"));
        if spec.targets.contains(':') || spec.excludes.iter().any(|e| e.contains(':')) {
            println!("SKIP {file}: IPv6 out of scope in v1");
            skipped.push(file.to_string());
            continue;
        }
        let t = build(&spec);
        let single_port = t.count_ports() == 1;
        let truncated = case.truncated.unwrap_or(false);
        let expected = std::fs::read_to_string(format!("{GOLDEN_DIR}/{file}")).unwrap();
        let mut exp = expected.lines();
        let mut sha = Sha256::new();
        let mut n = 0u64;
        list_scan(
            &t,
            spec.seed,
            spec.rounds,
            Shard {
                one: spec.shard_one,
                of: spec.shard_of,
            },
            spec.resume_index,
            spec.resume_count,
            spec.retries,
            spec.max_rate,
            |ip, port| {
                let line = format_list_line(ip, port, single_port);
                if let Some(e) = exp.next() {
                    assert_eq!(line, e, "{file} line {}", n + 1);
                } else {
                    assert!(truncated, "{file}: fixture shorter than output");
                }
                if truncated {
                    sha.update(line.as_bytes());
                    sha.update(b"\n");
                }
                n += 1;
            },
        )
        .unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(Some(n), case.line_count, "{file}: line_count");
        if truncated {
            assert_eq!(expected.lines().count(), 2000, "{file}: head length");
            assert_eq!(
                Some(sha.finish()),
                case.sha256,
                "{file}: sha256 of full stream"
            );
        } else {
            assert!(exp.next().is_none(), "{file}: fixture longer than output");
        }
        checked.push(file.to_string());
    }
    checked.sort();
    skipped.sort();
    assert_eq!(checked, CHECKED, "checked set changed");
    assert_eq!(skipped, SKIPPED, "skipped set changed");
}
