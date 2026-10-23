//! Oracle-проверка BlackRock по golden `-sL` фикстурам (AGPL-3.0, порт masscan
//! © Robert David Graham, crypto-blackrock.c + main-listscan.c:15,29-62).
//!
//! Для одного непрерывного IPv4-диапазона и ровно одного порта строка i
//! вывода `-sL` равна `base + shuffle(i)`.

use std::net::Ipv4Addr;

use rmasscan_core::blackrock::BlackRock;
use serde::Deserialize;

#[derive(Deserialize)]
struct Manifest {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    file: String,
    mode: String,
    args: Vec<String>,
    line_count: u64,
    truncated: bool,
}

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
    let mut range = None;
    let mut ports = None;
    let mut seed = None;
    let mut rounds = 14u32; // main-conf.c: blackrock_rounds по умолчанию
    let mut it = args.iter().skip(1); // пропустить -sL
    while let Some(a) = it.next() {
        match a.as_str() {
            "--seed" => {
                seed = Some(
                    it.next()
                        .ok_or("missing seed")?
                        .parse::<u64>()
                        .map_err(|e| e.to_string())?,
                )
            }
            "--blackrock-rounds" => {
                rounds = it
                    .next()
                    .ok_or("missing rounds")?
                    .parse()
                    .map_err(|_| "bad rounds")?
            }
            o if o.starts_with("--") => return Err(format!("unsupported option {o}")),
            p if p.starts_with("-p") => {
                if ports.replace(p[2..].to_string()).is_some() {
                    return Err("multiple -p".into());
                }
            }
            t => {
                if range.replace(t.to_string()).is_some() {
                    return Err("multiple targets".into());
                }
            }
        }
    }
    let range = range.ok_or("no target")?;
    if range.contains(',') || range.contains(':') {
        return Err(format!("not a single IPv4 range: {range}"));
    }
    let ports = ports.ok_or("no -p")?;
    if ports.contains(',') || ports.contains('-') {
        return Err(format!("not exactly one port: {ports}"));
    }
    ports
        .parse::<u16>()
        .map_err(|_| format!("bad port {ports}"))?;
    let (lo, hi) = parse_range(&range)?;
    Ok(Spec {
        base: lo,
        count: u64::from(hi) - u64::from(lo) + 1,
        seed: seed.ok_or("no --seed")?,
        rounds,
    })
}

#[test]
fn listscan_order_matches_oracle_for_single_range_single_port() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden");
    let manifest: Manifest =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/manifest.json")).unwrap())
            .unwrap();
    let mut checked = Vec::new();
    for case in manifest.cases.iter().filter(|c| c.mode == "-sL") {
        let spec = match spec_for(&case.args) {
            Ok(s) => s,
            Err(why) => {
                println!("SKIP {}: {why}", case.file);
                continue;
            }
        };
        if case.truncated {
            // sha256 полного вывода требует крейта, которого нет в зависимостях;
            // однопортовых усечённых кейсов в манифесте нет.
            println!("SKIP {}: truncated, sha256 unavailable", case.file);
            continue;
        }
        let br = BlackRock::new(spec.count, spec.seed, spec.rounds);
        let text = std::fs::read_to_string(format!("{dir}/{}", case.file)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len() as u64, case.line_count, "{}", case.file);
        assert_eq!(spec.count, case.line_count, "{}", case.file);
        for (i, line) in lines.iter().enumerate() {
            let ip = Ipv4Addr::from(spec.base.wrapping_add(br.shuffle(i as u64) as u32));
            assert_eq!(*line, ip.to_string(), "{} line {}", case.file, i + 1);
        }
        checked.push(case.file.clone());
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
