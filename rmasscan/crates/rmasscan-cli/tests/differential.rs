//! Дифференциальные тесты бинарника `rmasscan` против golden-фикстур C
//! (AGPL-3.0, masscan © Robert David Graham): `-sL` (main-listscan.c) и
//! `--echo`/`--echo-all` (main-conf.c:3636). Бинарник запускается с теми
//! же аргументами, что в манифесте; stdout сверяется побайтно.

mod common;

use std::process::Command;

use common::{GOLDEN_DIR, Sha256, load_manifest};

const LIST_CHECKED: [&str; 21] = [
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
const LIST_SKIPPED: [&str; 2] = [
    "listscan/ipv6_slash126_p80-443_seed1.txt",
    "listscan/ipv6_slash126_p80_seed1.txt",
];
const ECHO_CHECKED: [&str; 16] = [
    "echo/adapter_opts.all.conf",
    "echo/adapter_opts.conf",
    "echo/everything.all.conf",
    "echo/everything.conf",
    "echo/minimal_p80.all.conf",
    "echo/minimal_p80.conf",
    "echo/ranges_exclude.all.conf",
    "echo/ranges_exclude.conf",
    "echo/seed_rate_retries.all.conf",
    "echo/seed_rate_retries.conf",
    "echo/shard_rounds.all.conf",
    "echo/shard_rounds.conf",
    "echo/wait_and_ports.all.conf",
    "echo/wait_and_ports.conf",
    "echo/zero_slash31.conf",
    "echo/zero_slash4.conf",
];

fn run_bin(args: &[String]) -> Vec<u8> {
    let out = Command::new(env!("CARGO_BIN_EXE_rmasscan"))
        .args(args)
        .output()
        .expect("spawn rmasscan");
    // C exit code was 0 for all of these cases.
    assert_eq!(
        out.status.code(),
        Some(0),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

#[test]
fn list_scan_binary_matches_c_oracle_fixtures() {
    let (mut checked, mut skipped) = (Vec::new(), Vec::new());
    for case in load_manifest()
        .cases
        .iter()
        .filter(|c| c.mode.as_deref() == Some("-sL"))
    {
        let file = case.file.as_deref().expect("file");
        let args = case.args.as_deref().expect("args");
        if args.iter().any(|a| a.contains(':') && a.contains("::")) {
            println!("SKIP {file}: IPv6 out of scope in v1");
            skipped.push(file.to_string());
            continue;
        }
        let got = run_bin(args);
        let expected = std::fs::read(format!("{GOLDEN_DIR}/{file}")).unwrap();
        if case.truncated.unwrap_or(false) {
            let head_len: usize = got
                .split_inclusive(|&b| b == b'\n')
                .take(2000)
                .map(<[u8]>::len)
                .sum();
            assert_eq!(&got[..head_len], &expected[..], "{file}: first 2000 lines");
            assert_eq!(
                expected.iter().filter(|&&b| b == b'\n').count(),
                2000,
                "{file}"
            );
            let lines = got.iter().filter(|&&b| b == b'\n').count() as u64;
            assert_eq!(Some(lines), case.line_count, "{file}: line_count");
            let mut sha = Sha256::new();
            sha.update(&got);
            assert_eq!(
                Some(sha.finish()),
                case.sha256,
                "{file}: sha256 of full stdout"
            );
        } else {
            assert_eq!(got, expected, "{file}");
            let lines = got.iter().filter(|&&b| b == b'\n').count() as u64;
            assert_eq!(Some(lines), case.line_count, "{file}: line_count");
        }
        checked.push(file.to_string());
    }
    checked.sort();
    skipped.sort();
    assert_eq!(checked, LIST_CHECKED, "checked set changed");
    assert_eq!(skipped, LIST_SKIPPED, "skipped set changed");
}

#[test]
fn echo_binary_matches_c_oracle_fixtures() {
    let mut checked = Vec::new();
    for case in load_manifest()
        .cases
        .iter()
        .filter(|c| matches!(c.mode.as_deref(), Some("--echo") | Some("--echo-all")))
    {
        let file = case.file.as_deref().expect("file");
        let got = run_bin(case.args.as_deref().expect("args"));
        let expected = std::fs::read(format!("{GOLDEN_DIR}/{file}")).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&expected),
            "{file}"
        );
        checked.push(file.to_string());
    }
    checked.sort();
    assert_eq!(checked, ECHO_CHECKED, "checked set changed");
}

#[test]
fn errors_exit_nonzero_with_message_on_stderr() {
    for args in [
        &["-sL", "bogus", "-p80", "--seed", "1"][..],
        &["--banners", "10.0.0.0/24", "-p80"][..],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_rmasscan"))
            .args(args)
            .output()
            .unwrap();
        assert_ne!(out.status.code(), Some(0), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(!out.stderr.is_empty(), "{args:?}");
    }
}
