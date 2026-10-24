//! Offline tests of the Linux suite driver: result schema, capture completeness rules,
//! quiescence and arithmetic helpers. Nothing here needs root, namespaces or packets.
use super::*;

fn scratch(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("rmasscan-wire-suite-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}
fn driver_in(out: &Path) -> Driver {
    Driver {
        c: Config {
            out: out.to_path_buf(),
            work: out.to_path_buf(),
            nsa: "wl-a".into(),
            nsb: "wl-b".into(),
            ifa: "veth-a".into(),
            ifb: "veth-b".into(),
            maca: "02:aa:00:00:00:01".into(),
            macb: "02:aa:00:00:00:02".into(),
            ipa: "10.200.0.100".into(),
            rust: "/tmp/wire_scan".into(),
            oracle: "/tmp/oracle".into(),
            fixtures: PathBuf::new(),
            masked: false,
            empty: String::new(),
            lab: "/tmp/rmasscan-lab".into(),
        },
        checks: vec![],
        extra: json!({"suite":"perf"}),
        responder: OwnedChild(None),
    }
}

/// One VALID perf cell, in the shape `perf_cell` writes.
fn valid_cell(implementation: &str, rate: u64, rep: u64) -> Value {
    let mut c = json!({
        "impl":implementation,"rate":rate,"rep":rep,"rc":0,"valid":true,
        "capture":{"valid":true},"rx_complete":true,
        "transmitted_wire":512,"steady_pps_wire":rate as f64,
        "cpu_user_s":0.1,"cpu_sys_s":0.1,"max_rss_kb":1000,
        "stop":{"stop_to_exit_s":0.01}
    });
    if implementation == "rust" {
        c["net_kernel_drops"] = json!(0);
        c["rx_health_kernel_drops"] = json!(0);
        c["rx_health_ok"] = json!(true);
        c["tx_would_block"] = json!(0);
    }
    c
}
fn full_matrix() -> Vec<Value> {
    let mut cells = vec![];
    for rate in [100, 1000, 10000, 100000] {
        for rep in 1..=5 {
            for i in ["c", "rust"] {
                cells.push(valid_cell(i, rate, rep));
            }
        }
    }
    cells
}

/// The assertions of `rmasscan-net/tests/linux_wire.rs`
/// `lab_perf_matrix_is_complete_and_invalid_cells_are_never_normalised`, on a results file.
fn assert_linux_wire_perf_acceptance(text: &str) {
    let all: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    for rate in [100, 1000, 10000, 100000] {
        assert!(all.contains(&format!("\"rate\":{rate}")), "rate {rate}");
    }
    assert_eq!(all.matches("\"impl\":\"c\"").count(), 20, "C cells");
    assert_eq!(all.matches("\"impl\":\"rust\"").count(), 20, "Rust cells");
    assert!(all.contains("\"perf_summary\""));
    let per_rate = |key: &str, close: char| -> Vec<String> {
        all.split(key)
            .skip(1)
            .map(|t| t.split(close).next().unwrap().to_string())
            .collect()
    };
    let incomplete = per_rate("\"rust_rx_incomplete_runs\":", ',');
    assert_eq!(incomplete.len(), 4, "rust_rx_incomplete_runs per rate");
    assert!(incomplete.iter().all(|v| v == "0"), "{incomplete:?}");
    let drops = per_rate("\"rust_kernel_drops_per_run\":[", ']');
    assert_eq!(drops.len(), 4, "rust_kernel_drops_per_run per rate");
    assert!(drops.iter().all(|d| d.split(',').all(|v| v == "0")));
    let health = per_rate("\"rust_rx_health_drops_per_run\":[", ']');
    assert_eq!(health.len(), 4, "rust_rx_health_drops_per_run per rate");
    assert!(
        health
            .iter()
            .all(|d| d.split(',').count() == 5 && d.split(',').all(|v| v == "0"))
    );
    let bad = per_rate("\"rust_rx_health_bad_runs\":", ',');
    assert_eq!(bad.len(), 4, "rust_rx_health_bad_runs per rate");
    assert!(bad.iter().all(|v| v == "0"));
    assert!(!all.contains("\"valid\":false"));
}

#[test]
fn results_json_schema_is_what_linux_wire_tests_read() {
    let dir = scratch("schema");
    let mut d = driver_in(&dir);
    let cells = full_matrix();
    d.extra["perf_cells"] = json!(cells);
    d.perf_summarize(&cells, &[100, 1000, 10000, 100000]);
    d.save(false).unwrap();
    assert_linux_wire_perf_acceptance(&fs::read_to_string(dir.join("results.json")).unwrap());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn committed_python_perf_results_satisfy_the_same_acceptance() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../../docs/experiments/2026-10-24-rmasscan-linux-acceptance-raw/perf/results.json",
    );
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert_linux_wire_perf_acceptance(&text);
}

#[test]
fn a_missing_summary_field_never_satisfies_any_comparison() {
    let none = json!({});
    let one = json!({"a":1,"b":1,"c":2});
    // absent == absent used to pass (u64::MAX == u64::MAX).
    assert!(n(&none, "a") != n(&none, "b"));
    assert!(n(&none, "a") != n(&one, "a"));
    assert!(n(&none, "a") != 0);
    assert_eq!(n(&none, "a").partial_cmp(&0), None);
    assert_eq!(n(&none, "a").partial_cmp(&n(&one, "c")), None);
    assert_eq!(n(&one, "c").partial_cmp(&n(&none, "a")), None);
    let sum = n(&none, "a").saturating_add(n(&one, "a"));
    assert_eq!(sum.partial_cmp(&100), None);
    // present values still compare as integers, on both sides.
    assert!(n(&one, "a") == n(&one, "b"));
    assert!(n(&one, "a") == 1);
    assert!(1 == n(&one, "a"));
    assert!(n(&one, "a") < n(&one, "c"));
    assert!(n(&one, "a").saturating_add(n(&one, "c")) <= 3);
}
