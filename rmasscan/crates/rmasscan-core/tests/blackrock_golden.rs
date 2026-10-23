//! Oracle-проверка BlackRock по golden `-sL` фикстурам (AGPL-3.0, порт masscan
//! © Robert David Graham, crypto-blackrock.c + main-listscan.c:15,29-62).
//!
//! Для одного непрерывного IPv4-диапазона и ровно одного порта строка i
//! вывода `-sL` равна `base + shuffle(i)`.

mod common;

use std::net::Ipv4Addr;

use common::{GOLDEN_DIR, load_manifest, parse_listscan_args};
use rmasscan_core::blackrock::BlackRock;

struct Spec {
    base: u32,
    count: u64,
    seed: u64,
    rounds: u32,
}

fn parse_range(s: &str) -> Result<(u32, u32), String> {
    let ip = |t: &str| {
        t.parse::<Ipv4Addr>()
            .map(u32::from)
            .map_err(|e| format!("{t}: {e}"))
    };
    if let Some((addr, len)) = s.split_once('/') {
        let base = ip(addr)?;
        let len: u32 = len.parse().map_err(|_| format!("bad prefix {s}"))?;
        if len > 32 {
            return Err(format!("bad prefix {s}"));
        }
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        Ok((base & mask, base | !mask))
    } else if let Some((lo, hi)) = s.split_once('-') {
        Ok((ip(lo)?, ip(hi)?))
    } else {
        let v = ip(s)?;
        Ok((v, v))
    }
}

/// `Err(reason)` когда кейс нельзя выразить одним BlackRock.
fn spec_for(args: &[String]) -> Result<Spec, String> {
    let l = parse_listscan_args(args)?;
    if !l.excludes.is_empty()
        || l.resume_index != 0
        || (l.shard_one, l.shard_of) != (1, 1)
        || l.resume_count.is_some()
        || l.retries != 0
    {
        return Err("exclude/shard/resume/retries".into());
    }
    if l.targets.contains(',') || l.targets.contains(':') {
        return Err(format!("not a single IPv4 range: {}", l.targets));
    }
    if l.ports.contains(',') || l.ports.contains('-') {
        return Err(format!("not exactly one port: {}", l.ports));
    }
    l.ports
        .parse::<u16>()
        .map_err(|_| format!("bad port {}", l.ports))?;
    let (lo, hi) = parse_range(&l.targets)?;
    Ok(Spec {
        base: lo,
        count: u64::from(hi) - u64::from(lo) + 1,
        seed: l.seed,
        rounds: l.rounds,
    })
}

#[test]
fn listscan_order_matches_oracle_for_single_range_single_port() {
    let dir = GOLDEN_DIR;
    let manifest = load_manifest();
    let mut checked = Vec::new();
    for case in manifest
        .cases
        .iter()
        .filter(|c| c.mode.as_deref() == Some("-sL"))
    {
        let file = case.file.clone().expect("file");
        let line_count = case.line_count.expect("line_count");
        let spec = match spec_for(case.args.as_deref().expect("args")) {
            Ok(s) => s,
            Err(why) => {
                println!("SKIP {file}: {why}");
                continue;
            }
        };
        if case.truncated.unwrap_or(false) {
            // Усечённый `*.head.txt` хранит только первые 2000 строк, а порядок
            // сверяется по всем строкам; sha256 полного вывода проверяет
            // scan_golden.rs. Однопортовых усечённых кейсов в манифесте нет.
            println!("SKIP {file}: truncated, full output not stored");
            continue;
        }
        let br = BlackRock::new(spec.count, spec.seed, spec.rounds);
        let text = std::fs::read_to_string(format!("{dir}/{}", file)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len() as u64, line_count, "{}", file);
        assert_eq!(spec.count, line_count, "{}", file);
        for (i, line) in lines.iter().enumerate() {
            let ip = Ipv4Addr::from(spec.base.wrapping_add(br.shuffle(i as u64) as u32));
            assert_eq!(*line, ip.to_string(), "{} line {}", file, i + 1);
        }
        checked.push(file.clone());
    }
    println!("CHECKED {checked:?}");
    for must in [
        "single_ip_p80_seed1",
        "slash31_p80_seed1",
        "range3_p80_seed1",
        "slash30_p80_seed1",
        "slash24_p80_seed2",
        "slash24_p80_seed4294967295",
        "slash24_p80_seed1_rounds4",
    ] {
        assert!(
            checked.iter().any(|f| f.contains(must)),
            "{must} not verified"
        );
    }
}
