//! Oracle-проверка `config::echo` и `config::read_paused_conf` по golden
//! фикстурам (AGPL-3.0, порт masscan © Robert David Graham,
//! main-conf.c:3636 `masscan_echo`, :3883 `masscan_read_config_file`).
//!
//! Для каждого `--echo`/`--echo-all` кейса из манифеста `ScanConfig`
//! собирается небольшим тестовым маппером аргументов (только опции этих
//! кейсов), а результат `config::echo` сравнивается с фикстурой как точная
//! строка (байт в байт, включая пробелы после `rate` и пустые строки).

mod common;

use common::{GOLDEN_DIR, load_manifest};
use rmasscan_core::config::{
    ScanConfig, echo, parse_mac, parse_rate, parse_shard, read_paused_conf,
};
use rmasscan_core::scan::Shard;
use rmasscan_core::targets::{add_target_string, parse_ports};

/// Минимальный маппер аргументов masscan -> `ScanConfig` для echo-кейсов.
fn map_args(args: &[String]) -> ScanConfig {
    let mut cfg = ScanConfig::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || {
            it.next()
                .cloned()
                .unwrap_or_else(|| panic!("{a}: no value"))
        };
        match a.as_str() {
            "--echo" | "--echo-all" => {}
            "--range" => add_target_string(cfg.targets.ipv4_mut(), &val()).unwrap(),
            "--ports" => parse_ports(cfg.targets.ports_mut(), &val()).unwrap(),
            "--exclude" => add_target_string(cfg.excludes.ipv4_mut(), &val()).unwrap(),
            "--seed" => cfg.seed = val().parse().unwrap(),
            "--rate" => cfg.max_rate = parse_rate(&val()).unwrap(),
            "--retries" => cfg.retries = val().parse().unwrap(),
            "--shard" => cfg.shard = parse_shard(&val()).unwrap(),
            "--blackrock-rounds" => cfg.blackrock_rounds = val().parse().unwrap(),
            "--wait" => cfg.wait_secs = val().parse().unwrap(),
            "--adapter-ip" => {
                cfg.adapter_ip = Some(val().parse::<std::net::Ipv4Addr>().unwrap().into())
            }
            "--adapter-mac" => cfg.adapter_mac = Some(parse_mac(&val()).unwrap()),
            "--router-mac" => cfg.router_mac = Some(parse_mac(&val()).unwrap()),
            "--source-port" => {
                let p: u16 = val().parse().unwrap();
                cfg.source_port = Some((p, p));
            }
            p if p.starts_with("-p") => parse_ports(cfg.targets.ports_mut(), &p[2..]).unwrap(),
            t if !t.starts_with('-') => add_target_string(cfg.targets.ipv4_mut(), t).unwrap(),
            other => panic!("unsupported option {other}"),
        }
    }
    cfg
}

const CHECKED: [&str; 16] = [
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

#[test]
fn echo_matches_c_oracle_fixtures_exactly() {
    let mut checked = Vec::new();
    for case in load_manifest()
        .cases
        .iter()
        .filter(|c| matches!(c.mode.as_deref(), Some("--echo") | Some("--echo-all")))
    {
        let file = case.file.as_deref().expect("file");
        let cfg = map_args(case.args.as_deref().expect("args"));
        // main.c:1803-1805: `--echo-all` вызывает `masscan_echo(.., 0)`.
        let mut got = String::new();
        echo(&cfg, false, &mut got);
        let expected = std::fs::read_to_string(format!("{GOLDEN_DIR}/{file}")).unwrap();
        assert_eq!(got, expected, "{file}");
        checked.push(file.to_string());
    }
    checked.sort();
    assert_eq!(checked, CHECKED);
}

fn read_fixture(name: &str) -> (String, ScanConfig) {
    let text = std::fs::read_to_string(format!("{GOLDEN_DIR}/paused/{name}")).unwrap();
    let cfg = read_paused_conf(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
    (text, cfg)
}

fn ranges(cfg: &ScanConfig) -> Vec<(u32, u32)> {
    cfg.targets
        .ipv4()
        .as_slice()
        .iter()
        .map(|r| (r.begin, r.end))
        .collect()
}

fn ports(cfg: &ScanConfig) -> Vec<(u32, u32)> {
    cfg.targets
        .ports()
        .as_slice()
        .iter()
        .map(|r| (r.begin, r.end))
        .collect()
}

#[test]
fn reads_c_oracle_paused_conf_fixtures() {
    let common_mac = Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let router = Some([0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);

    let (_, c) = read_fixture("seed1_p80_slash16.conf");
    assert_eq!((c.seed, c.resume_index, c.resume_count), (1, 602, None));
    assert_eq!(
        (c.max_rate, c.retries, c.shard),
        (1000.0, 0, Shard { one: 1, of: 1 })
    );
    assert_eq!(ranges(&c), vec![(0x0A00_0000, 0x0A00_FFFF)]);
    assert_eq!(ports(&c), vec![(80, 80)]);
    assert!(c.offline);
    assert_eq!(c.adapter_name.as_deref(), Some("lo"));
    assert_eq!(c.adapter_ip, Some(0x0AFF_0001));
    assert_eq!((c.adapter_mac, c.router_mac), (common_mac, router));
    assert_eq!(c.source_port, Some((40000, 40000)));

    let (_, c) = read_fixture("seed424242_multi.conf");
    assert_eq!((c.seed, c.resume_index, c.retries), (424242, 200, 2));
    assert_eq!(ranges(&c), vec![(0xC0A8_0000, 0xC0A8_0FFF)]);
    assert_eq!(ports(&c), vec![(22, 22), (80, 80), (443, 443)]);

    let (_, c) = read_fixture("seed9_resume_index.conf");
    assert_eq!((c.seed, c.resume_index, c.retries), (9, 5602, 0));
    assert_eq!(ranges(&c), vec![(0xAC10_0000, 0xAC10_FFFF)]);
    assert_eq!(ports(&c), vec![(0, 9)]);
}

const PAUSED: [&str; 4] = [
    "paused/seed1_p80_slash16.conf",
    "paused/seed424242_multi.conf",
    "paused/seed9_resume_index.conf",
    "paused/studio_flags.conf",
];

#[test]
fn paused_fixtures_are_exactly_the_manifest_paused_records() {
    let mut files: Vec<String> = load_manifest()
        .cases
        .iter()
        .filter(|c| c.mode.as_deref() == Some("paused"))
        .map(|c| c.file.clone().expect("file"))
        .collect();
    files.sort();
    assert_eq!(files, PAUSED);
}

#[test]
fn reads_studio_flags_paused_conf() {
    // Captured with `--interactive --output-format interactive -e lo`: C
    // writes `output-format = interactive`, which the reader must tolerate.
    let (text, c) = read_fixture("studio_flags.conf");
    assert!(text.contains("output-format = interactive"));
    assert_eq!((c.seed, c.resume_index, c.max_rate), (3, 602, 1000.0));
    assert_eq!(ranges(&c), vec![(0xC0A8_0000, 0xC0A8_FFFF)]);
    assert_eq!(ports(&c), vec![(80, 80)]);
    assert!(c.offline);
    assert_eq!(c.adapter_name.as_deref(), Some("lo"));
    assert_eq!(c.source_port, Some((40000, 40000)));
}

#[test]
fn paused_conf_fixtures_round_trip_byte_exact() {
    for case in load_manifest()
        .cases
        .iter()
        .filter(|c| c.mode.as_deref() == Some("paused"))
    {
        let file = case.file.as_deref().expect("file");
        let text = std::fs::read_to_string(format!("{GOLDEN_DIR}/{file}")).unwrap();
        let cfg = read_paused_conf(&text).unwrap_or_else(|e| panic!("{file}: {e}"));
        if text.contains("output-format") {
            // We do not store output keys, so echo cannot reproduce them.
            continue;
        }
        let mut out = String::new();
        echo(&cfg, false, &mut out);
        assert_eq!(out, text, "{file}");
    }
}
