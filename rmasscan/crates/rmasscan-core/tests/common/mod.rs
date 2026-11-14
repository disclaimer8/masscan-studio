//! Общая поддержка golden-тестов (AGPL-3.0, masscan © Robert David Graham):
//! манифест, путь к фикстурам, SHA-256 (только для тестов) и разбор
//! аргументов `-sL` (main-listscan.c:15-65, main.c:1595).
#![allow(dead_code)]

use serde::Deserialize;

/// Каталог golden-фикстур; не зависит от cwd.
pub const GOLDEN_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden");

#[derive(Deserialize)]
pub struct Manifest {
    pub cases: Vec<Case>,
    pub offline_gen_pps: Option<f64>,
    pub offline_gen_bench: Option<GenBench>,
}

#[derive(Deserialize)]
pub struct GenBench {
    pub cpu_model: Option<String>,
}

#[derive(Deserialize)]
pub struct Case {
    pub file: Option<String>,
    pub mode: Option<String>,
    pub args: Option<Vec<String>>,
    pub line_count: Option<u64>,
    pub sha256: Option<String>,
    pub truncated: Option<bool>,
}

pub fn load_manifest() -> Manifest {
    let text = std::fs::read_to_string(format!("{GOLDEN_DIR}/manifest.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// Параметры `-sL` кейса (то, что `main_listscan` берёт из Masscan).
pub struct ListSpec {
    pub targets: String,
    pub ports: String,
    pub excludes: Vec<String>,
    pub seed: u64,
    pub rounds: u32,
    /// `shard.one`, `shard.of` (по умолчанию 1/1).
    pub shard_one: u32,
    pub shard_of: u32,
    pub resume_index: u64,
    /// `resume.count`, `None` = не задан (C: 0 = без ограничения).
    pub resume_count: Option<u64>,
    pub retries: u32,
    /// `max_rate` (double); по умолчанию 100 (main.c:1599), задаётся `--rate`.
    pub max_rate: f64,
}

/// `Err(reason)` когда кейс вне области v1 (неизвестные опции).
/// IPv6 определяется вызывающим по `targets`.
pub fn parse_listscan_args(args: &[String]) -> Result<ListSpec, String> {
    let (mut targets, mut ports) = (None, None);
    let mut excludes = Vec::new();
    let (mut seed, mut rounds) = (None, 14u32); // main.c:1595
    let (mut shard_one, mut shard_of) = (1u32, 1u32);
    let (mut resume_index, mut resume_count) = (0u64, None);
    let (mut retries, mut max_rate) = (0u32, 100.0f64); // main.c:1599
    let mut it = args.iter().skip(1); // -sL
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().cloned().ok_or(format!("missing {name} value"));
        let num = |s: String| s.parse::<u64>().map_err(|e| format!("{s}: {e}"));
        match a.as_str() {
            "--seed" => seed = Some(num(val("seed")?)?),
            "--blackrock-rounds" => rounds = num(val("rounds")?)? as u32,
            "--exclude" => excludes.push(val("exclude")?),
            "--retries" => retries = num(val("retries")?)? as u32,
            "--rate" => {
                let v = val("rate")?;
                max_rate = v.parse::<f64>().map_err(|e| format!("{v}: {e}"))?;
            }
            "--shard" => {
                let v = val("shard")?;
                let (o, f) = v.split_once('/').ok_or("bad shard")?;
                (shard_one, shard_of) = (num(o.into())? as u32, num(f.into())? as u32);
                if shard_one == 0 || shard_one > shard_of {
                    return Err("bad shard".into());
                }
            }
            "--resume-index" => resume_index = num(val("resume-index")?)?,
            "--resume-count" => resume_count = Some(num(val("resume-count")?)?),
            o if o.starts_with("--") => return Err(format!("unsupported option {o}")),
            p if p.starts_with("-p") => {
                if ports.replace(p[2..].to_string()).is_some() {
                    return Err("multiple -p".into());
                }
            }
            t => {
                if targets.replace(t.to_string()).is_some() {
                    return Err("multiple targets".into());
                }
            }
        }
    }
    Ok(ListSpec {
        targets: targets.ok_or("no target")?,
        ports: ports.ok_or("no -p")?,
        excludes,
        seed: seed.ok_or("no --seed")?,
        rounds,
        shard_one,
        shard_of,
        resume_index,
        resume_count,
        retries,
        max_rate,
    })
}

// Минимальный SHA-256 вынесен в sha256.rs, чтобы rmasscan-proto подключал его без serde.
mod sha256;
#[allow(unused_imports)]
pub use sha256::Sha256;
