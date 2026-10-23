//! Oracle-проверка MassIp + BlackRock по golden `-sL` фикстурам (AGPL-3.0,
//! порт masscan © Robert David Graham, massip.c + main-listscan.c:15,29-62,
//! main.c:1673-1684).
//!
//! Для каждого IPv4 `-sL` кейса без shard/resume/retries!=0: excludes, optimize,
//! затем строка i = `pick(shuffle(i))`. Усечённые кейсы сверяются по первым
//! 2000 строкам, `line_count` и sha256 всего потока (SHA-256 ниже, test-only).

mod common;

use std::net::Ipv4Addr;

use common::{GOLDEN_DIR, ListSpec, Sha256, load_manifest, parse_listscan_args};
use rmasscan_core::blackrock::BlackRock;
use rmasscan_core::massip::MassIp;
use rmasscan_core::targets::{add_target_string, parse_ports};

#[test]
fn sha256_known_vectors() {
    let mut s = Sha256::new();
    s.update(b"abc");
    assert_eq!(
        s.finish(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        Sha256::new().finish(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

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

const CHECKED: [&str; 19] = [
    "listscan/exclude_list_seed3.txt",
    "listscan/multirange_ports_seed7.txt",
    "listscan/range3_p80_seed1.txt",
    "listscan/single_ip_p80_seed1.txt",
    "listscan/slash22_p0-1023_seed1.head.txt",
    "listscan/slash24_p80-443_seed1.txt",
    "listscan/slash24_p80_seed1.txt",
    "listscan/slash24_p80_seed1_resume100_count50.txt",
    "listscan/slash24_p80_seed1_retries0.txt",
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
const SKIPPED: [&str; 4] = [
    "listscan/ipv6_slash126_p80-443_seed1.txt",
    "listscan/ipv6_slash126_p80_seed1.txt",
    "listscan/slash24_p80_seed1_retries2.txt",
    "listscan/slash24_p80_seed1_retries2_rate1000.txt",
];

#[test]
fn listscan_matches_oracle_for_multi_port_multi_range_exclude() {
    let dir = GOLDEN_DIR;
    let mut checked = Vec::new();
    let mut skipped = Vec::new();
    for case in load_manifest()
        .cases
        .iter()
        .filter(|c| c.mode.as_deref() == Some("-sL"))
    {
        let file = case.file.as_deref().expect("file");
        let spec = match parse_listscan_args(case.args.as_deref().expect("args")) {
            Ok(s) if s.targets.contains(':') || s.excludes.iter().any(|e| e.contains(':')) => {
                println!("SKIP {file}: IPv6 out of scope in v1");
                skipped.push(file.to_string());
                continue;
            }
            Ok(s) => s,
            Err(why) => {
                println!("SKIP {file}: {why}");
                skipped.push(file.to_string());
                continue;
            }
        };
        let t = build(&spec);
        let range = t.range();
        let br = BlackRock::new(range, spec.seed, spec.rounds);
        let single_port = t.count_ports() == 1;
        let truncated = case.truncated.unwrap_or(false);
        let expected = std::fs::read_to_string(format!("{dir}/{file}")).unwrap();
        let mut exp = expected.lines();
        let mut sha = Sha256::new();
        // main-listscan.c:29-35,65: start, end, step.
        let mut end = range;
        if spec.resume_count != 0 && end > spec.start + spec.resume_count {
            end = spec.start + spec.resume_count;
        }
        let (mut i, mut n) = (spec.start, 0u64);
        while i < end {
            let (ip, port) = t.pick(br.shuffle(i));
            let ip = Ipv4Addr::from(ip);
            let line = if single_port {
                ip.to_string()
            } else {
                format!("{ip}:{port}")
            };
            if let Some(e) = exp.next() {
                assert_eq!(line, e, "{file} line {}", n + 1);
            } else {
                assert!(truncated, "{file}: fixture shorter than output");
            }
            if truncated {
                sha.update(line.as_bytes());
                sha.update(b"\n");
            }
            i += spec.step;
            n += 1;
        }
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
