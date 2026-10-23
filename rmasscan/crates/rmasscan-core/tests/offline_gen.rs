//! Порог этапа 1: генерация >= 80% от C (AGPL-3.0, masscan © Robert David
//! Graham). Число C — `offline_gen_pps` в tests/golden/manifest.json.
//!
//! Сравнение имеет смысл только в release на том же железе, что оракул
//! (minipc, Pentium Silver N6005):
//!   cargo test --release -p rmasscan-core --test offline_gen -- --ignored --nocapture

mod common;
#[path = "common/offline_gen.rs"]
mod offline_gen;

use std::time::Instant;

fn oracle_pps() -> f64 {
    let text = std::fs::read_to_string(format!("{}/manifest.json", common::GOLDEN_DIR)).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["offline_gen_pps"]
        .as_f64()
        .expect("offline_gen_pps in manifest")
}

#[test]
fn small_workload_generates_every_target() {
    // Быстрая проверка конвейера (идёт в обычном `cargo test`): /24 x 1 порт.
    let m = offline_gen::build_massip("10.1.2.0/24", "80");
    let (n, _) = offline_gen::generate(&m);
    assert_eq!(n, 256);
}

#[test]
#[ignore = "release-only, minipc: cargo test --release -p rmasscan-core --test offline_gen -- --ignored --nocapture"]
fn offline_generation_meets_80pct_of_oracle() {
    let oracle = oracle_pps();
    let m = offline_gen::build_massip("0.0.0.0/4", "80");
    let start = Instant::now();
    let (n, sink) = offline_gen::generate(&m);
    let secs = start.elapsed().as_secs_f64();
    assert_eq!(n, 1 << 28);
    let ours = n as f64 / secs;
    println!(
        "OFFLINE_GEN packets={n} seconds={secs:.3} pps={ours:.0} oracle={oracle:.0} ratio={:.3} sink={sink}",
        ours / oracle
    );
    assert!(ours >= 0.80 * oracle, "{ours} < 80% of {oracle}");
}
