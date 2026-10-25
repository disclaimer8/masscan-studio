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
            fixtures: None,
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
        "capture":{"valid":true,"kernel_drops":0,"interface_drop_delta":0,"invalid_reasons":[]},"rx_complete":true,
        "transmitted_wire":512,"steady_pps_wire":rate as f64,
        "cpu_user_s":0.1,"cpu_sys_s":0.1,"max_rss_kb":1000,
        "stop":{"stop_to_exit_s":0.01,"valid":true}
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
    // review 7ffa155 P2: `"capture_valid":false` does not contain `"valid":false`.
    assert!(!all.contains("\"capture_valid\":false"));
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
    let path = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join(
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

#[test]
fn the_cli_self_test_is_gone_and_says_where_the_cases_run() {
    let e = run(&["--self-test".to_string()]).unwrap_err();
    assert!(e.contains("cargo test -p rmasscan-lab"), "{e}");
}

// ---- ports of the wire_suite.py --self-test cases that had no Rust equivalent ----

#[test]
fn rx_is_complete_needs_the_exact_reply_sets_python_cases() {
    // (received_open, received_closed, wire_open, wire_closed) -> complete
    assert!(rx_is_complete(Some(8), Some(8), 8, 8), "equal sets");
    assert!(
        !rx_is_complete(Some(7), Some(8), 8, 8),
        "one open reply missing"
    );
    assert!(
        !rx_is_complete(Some(8), Some(7), 8, 8),
        "one RST missing (Rust)"
    );
    assert!(
        rx_is_complete(Some(8), None, 8, 8),
        "C leg: open only, equal"
    );
    assert!(!rx_is_complete(Some(7), None, 8, 8), "C leg: open missing");
    assert!(
        !rx_is_complete(Some(9), Some(8), 8, 8),
        "extra reply beyond the wire"
    );
    assert!(
        !rx_is_complete(None, None, 0, 0),
        "an unreported count is never complete"
    );
}

#[test]
fn rx_health_ok_requires_completed_and_a_measured_zero_all_python_cases() {
    let ok = json!({"reason":"Completed","rx_health":{"kernel_drops":0}});
    assert!(rx_health_ok(&ok), "measured zero");
    for (what, s) in [
        (
            "null is not zero",
            json!({"reason":"Completed","rx_health":{"kernel_drops":null}}),
        ),
        (
            "drops > 0",
            json!({"reason":"Completed","rx_health":{"kernel_drops":3}}),
        ),
        ("field missing", json!({"reason":"Completed"})),
        (
            "Failed with zero drops",
            json!({"reason":"Failed","rx_health":{"kernel_drops":0}}),
        ),
        (
            "boolean is not an integer",
            json!({"reason":"Completed","rx_health":{"kernel_drops":false}}),
        ),
        ("empty summary", json!({})),
        (
            "negative",
            json!({"reason":"Completed","rx_health":{"kernel_drops":-1}}),
        ),
        (
            "float zero",
            json!({"reason":"Completed","rx_health":{"kernel_drops":0.0}}),
        ),
    ] {
        assert!(!rx_health_ok(&s), "{what}");
    }
}

#[test]
fn capture_complete_all_eight_python_cases() {
    let c = capture_complete;
    assert!(
        c(Some(100), Some(100), Some(0), Some(0), 100, 98, 101),
        "exact"
    );
    assert!(
        !c(Some(99), Some(100), Some(0), Some(0), 99, 98, 101),
        "lost tail: received_by_filter > captured"
    );
    assert!(
        !c(Some(100), Some(100), Some(0), Some(0), 99, 98, 101),
        "pcap shorter than captured"
    );
    assert!(
        !c(Some(100), Some(100), Some(1), Some(0), 100, 98, 101),
        "kernel drop"
    );
    assert!(
        !c(Some(100), Some(100), Some(0), Some(1), 100, 98, 101),
        "interface drop"
    );
    assert!(
        !c(Some(100), Some(100), Some(0), Some(0), 100, 101, 105),
        "below the counter window (loss)"
    );
    assert!(
        !c(Some(100), Some(100), Some(0), Some(0), 100, 90, 99),
        "above the counter window"
    );
    assert!(
        !c(None, None, None, None, 0, 0, 0),
        "tcpdump summary missing"
    );
    assert!(
        !c(Some(100), None, Some(0), Some(0), 100, 98, 101),
        "received-by-filter line missing"
    );
    assert!(
        !c(Some(100), Some(100), None, Some(0), 100, 98, 101),
        "kernel-drop line missing is unknown, never zero"
    );
}

/// Virtual time for wait_quiet: the counter value is a step function of time.
struct Fake {
    t: std::cell::Cell<f64>,
    events: Vec<(f64, u64)>,
}
impl Fake {
    fn new(events: &[(f64, u64)]) -> Self {
        Self {
            t: std::cell::Cell::new(0.0),
            events: events.to_vec(),
        }
    }
    fn read(&self) -> Result<u64, String> {
        Ok(self
            .events
            .iter()
            .filter(|(at, _)| self.t.get() >= *at)
            .map(|(_, v)| *v)
            .next_back()
            .unwrap_or(0))
    }
}
impl crate::windows_suite::Clock for Fake {
    fn now(&self) -> f64 {
        self.t.get()
    }
    fn sleep(&self, secs: f64) {
        self.t.set(self.t.get() + secs);
    }
    fn stopped(&self) -> bool {
        false
    }
}

#[test]
fn wait_quiet_waits_past_a_late_retransmit() {
    // A late SYN-ACK retransmit arrives 0.9 s after the previous frame.
    let f = Fake::new(&[(0.0, 10), (0.3, 20), (1.2, 21)]);
    let done = crate::windows_suite::wait_quiet_with(|| f.read(), 1.5, 0.25, 20.0, &f).unwrap();
    assert!(done);
    assert!(f.t.get() >= 1.2 + 1.5, "returned at {}", f.t.get());
}

#[test]
fn wait_quiet_with_a_short_window_would_stop_before_the_late_frame() {
    // Why 1.5 s matters: a 0.5 s quiet window returns before the 1.2 s frame.
    let f = Fake::new(&[(0.0, 10), (0.3, 20), (1.2, 21)]);
    assert!(crate::windows_suite::wait_quiet_with(|| f.read(), 0.5, 0.25, 20.0, &f).unwrap());
    assert!(f.t.get() < 1.2, "returned at {}", f.t.get());
}

#[test]
fn wait_quiet_never_quiet_is_false_after_the_timeout() {
    let events: Vec<(f64, u64)> = (0..400u32)
        .map(|i| (f64::from(i) * 0.1, u64::from(i)))
        .collect();
    let f = Fake::new(&events);
    assert!(!crate::windows_suite::wait_quiet_with(|| f.read(), 1.5, 0.25, 5.0, &f).unwrap());
    assert!(f.t.get() >= 5.0);
}

#[test]
fn wait_quiet_a_constant_counter_is_quiet_from_the_first_sample() {
    let f = Fake::new(&[]);
    assert!(crate::windows_suite::wait_quiet_with(|| f.read(), 1.5, 0.25, 20.0, &f).unwrap());
    assert!(f.t.get() < 3.0, "returned at {}", f.t.get());
}

#[test]
fn wait_quiet_stops_when_the_orchestrator_is_interrupted() {
    struct Interrupted(Fake);
    impl crate::windows_suite::Clock for Interrupted {
        fn now(&self) -> f64 {
            self.0.now()
        }
        fn sleep(&self, s: f64) {
            self.0.sleep(s)
        }
        fn stopped(&self) -> bool {
            true
        }
    }
    let f = Interrupted(Fake::new(&[]));
    let r = crate::windows_suite::wait_quiet_with(|| f.0.read(), 1.5, 0.25, 20.0, &f);
    assert_eq!(r, Err("suite interrupted".into()));
}

#[test]
fn record_hash_records_sha256_size_and_frames_before_the_file_is_deleted() {
    use sha2::{Digest, Sha256};
    let dir = scratch("record");
    let mut d = driver_in(&dir);
    let raw = [
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0,
        1, 0, 0, 0,
    ];
    let p = dir.join("x.pcap");
    fs::write(&p, raw).unwrap();
    let r = d.record_hash("selftest", &p).unwrap();
    let want: String = Sha256::digest(raw)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(r["sha256"], want.as_str());
    assert_eq!(r["size_bytes"], raw.len());
    assert_eq!(r["pcap_frames"], 0);
    fs::remove_file(&p).unwrap();
    let kept = d.extra["pcaps"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(kept["file"], "x.pcap");
    assert_eq!(kept["sha256"], want.as_str());
    // A malformed capture is recorded with its error instead of a frame count.
    let bad = dir.join("bad.pcap");
    fs::write(&bad, &raw[..10]).unwrap();
    let r = d.record_hash("bad", &bad).unwrap();
    assert!(r["pcap_frames"].is_null());
    assert!(r["pcap_error"].is_string());
    let _ = fs::remove_dir_all(dir);
}

// ---- real-fixture negatives: a differing SYN is never normalised ----

fn c03() -> Vec<u8> {
    fs::read(
        Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("../../tests/golden/wire/c03_multi_addr_ports.run1.pcap"),
    )
    .expect("committed golden fixture c03_multi_addr_ports.run1.pcap")
}
fn c03_frames() -> Vec<Vec<u8>> {
    crate::pcap::read_pcap_records(&c03())
        .unwrap()
        .1
        .into_iter()
        .map(|(_, f)| f)
        .collect()
}
fn rebuild(frames: Vec<Vec<u8>>) -> Vec<u8> {
    crate::pcap::encode(
        &frames
            .into_iter()
            .enumerate()
            .map(|(i, f)| (i as f64, f))
            .collect(),
    )
}
fn syn_indexes(frames: &[Vec<u8>]) -> Vec<usize> {
    (0..frames.len())
        .filter(|&i| crate::pcap::is_syn(&frames[i]))
        .collect()
}

#[test]
fn fixture_c03_has_sixteen_syns_and_compares_equal_to_itself() {
    let raw = c03();
    assert_eq!(syn_indexes(&c03_frames()).len(), 16);
    assert_eq!(crate::pcap::compare_bytes(&raw, &[&raw], None, &[]).0, 0);
}

#[test]
fn fixture_c03_one_changed_seq_or_port_byte_swap_or_drop_is_a_fail() {
    let raw = c03();
    let frames = c03_frames();
    let syns = syn_indexes(&frames);
    let compare = |fs: Vec<Vec<u8>>| crate::pcap::compare_bytes(&raw, &[&rebuild(fs)], None, &[]).0;
    // one cookie byte of the sequence number
    let mut f = frames.clone();
    f[syns[5]][14 + 20 + 4 + 3] ^= 1;
    assert_eq!(compare(f), 1, "seq byte");
    // one destination-port byte
    let mut f = frames.clone();
    f[syns[7]][14 + 20 + 2] ^= 1;
    assert_eq!(compare(f), 1, "dst port byte");
    // last SYN dropped
    let mut f = frames.clone();
    f.remove(*syns.last().unwrap());
    assert_eq!(compare(f), 1, "last SYN dropped");
    // two SYNs swapped
    let mut f = frames.clone();
    f.swap(syns[0], syns[1]);
    assert_eq!(compare(f), 1, "two SYNs swapped");
}

#[test]
fn fixture_c03_capture_meta_with_drops_or_a_truncated_pcap_is_invalid() {
    let raw = c03();
    assert_eq!(
        crate::pcap::compare_bytes(&raw, &[&raw], None, &[json!({"drops":1})]).0,
        2
    );
    assert_eq!(
        crate::pcap::compare_bytes(&raw, &[&raw[..raw.len() - 9]], None, &[]).0,
        2
    );
}

#[test]
fn an_empty_fixtures_argument_is_none_never_the_current_directory() {
    // wire-lab.sh always passes --fixtures, empty for the perf suite. PathBuf::from("") joined
    // with "manifest.json" used to read ./manifest.json from the working directory.
    assert_eq!(fixtures_arg(""), None);
    assert_eq!(fixtures_arg("/golden"), Some(PathBuf::from("/golden")));
    let d = driver_in(&scratch("fixtures"));
    assert_eq!(d.c.fixture("manifest.json"), None);
    let mut with = driver_in(&scratch("fixtures2"));
    with.c.fixtures = fixtures_arg("/golden");
    assert_eq!(
        with.c.fixture("manifest.json"),
        Some(PathBuf::from("/golden/manifest.json"))
    );
}

#[test]
fn only_gnu_time_with_verbose_output_satisfies_the_perf_preflight() {
    let gnu = "\tCommand being timed: \"true\"\n\tUser time (seconds): 0.00\n\tSystem time (seconds): 0.00\n\tMaximum resident set size (kbytes): 1920\n\tExit status: 0\n";
    assert!(gnu_time_report_ok(gnu));
    // Missing binary, BSD/busybox time that rejects -v, or an empty report: every perf cell
    // would otherwise be a "driver error" much later.
    for bad in [
        "",
        "time: invalid option -- 'v'\n",
        "real 0.00\nuser 0.00\nsys 0.00\n",
        "\tUser time (seconds): 0.00\n",
    ] {
        assert!(!gnu_time_report_ok(bad), "{bad:?}");
    }
    // The rusage fields the perf cells read must be the ones GNU time prints.
    assert_eq!(
        gnu_time_metric(gnu, "Maximum resident set size (kbytes):"),
        Some(1920.0)
    );
    assert_eq!(gnu_time_metric(gnu, "User time (seconds):"), Some(0.0));
    assert_eq!(gnu_time_metric(gnu, "Elapsed (wall clock) time:"), None);
}

#[test]
fn the_suite_comparison_carries_every_run_capture_meta_into_the_verdict() {
    let dir = scratch("compare");
    let d = driver_in(&dir);
    let golden =
        Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../tests/golden/wire");
    let exp = golden.join("c03_multi_addr_ports.run1.pcap");
    let act = golden.join("c03_multi_addr_ports.run2.pcap");
    let run = |meta: Value, pcap: Option<PathBuf>| Run {
        rc: 0,
        s: json!({}),
        meta,
        pcap,
        wall: 0.0,
    };
    let clean = json!({"valid":true,"kernel_drops":0});
    // A clean capture of an identical stream passes.
    let ok = run(clean.clone(), Some(act.clone()));
    assert_eq!(d.compare(&exp, &[&ok]).unwrap().0, 0);
    // INVALID in the run's meta wins over an identical stream, for any of the legs.
    for bad in [
        json!({"valid":false}),
        json!({"valid":true,"kernel_drops":1}),
        json!({"valid":true,"kernel_drops":null}),
    ] {
        let leg = run(bad.clone(), Some(act.clone()));
        assert_eq!(d.compare(&exp, &[&ok, &leg]).unwrap().0, 2, "{bad}");
        assert_eq!(d.compare(&exp, &[&leg]).unwrap().0, 2, "{bad}");
    }
    // A run without a capture is an error, never a pass.
    let none = run(Value::Null, None);
    assert!(d.compare(&exp, &[&none]).is_err());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rust_suite_captures_stay_in_the_evidence_directory_and_perf_captures_in_scratch() {
    let out = scratch("evidence-out");
    let work = scratch("evidence-work");
    let mut d = driver_in(&out);
    d.c.work = work.clone();
    // The rust suite's pcaps are evidence (hashed into results.json and the manifest); perf pcaps
    // are deleted after each cell and must never land in the evidence tree.
    let (p, m) = d.capture_paths("pr_completed", Evidence::Keep);
    assert_eq!(p, out.join("pr_completed.pcap"));
    assert_eq!(m, out.join("pr_completed.capture.json"));
    let (p, m) = d.capture_paths("perf.rust.100.r1", Evidence::Scratch);
    assert_eq!(p, work.join("perf.rust.100.r1.pcap"));
    assert_eq!(
        m,
        out.join("perf.rust.100.r1.capture.json"),
        "the verdict is always evidence"
    );
    let _ = fs::remove_dir_all(out);
    let _ = fs::remove_dir_all(work);
}

#[cfg(unix)]
#[test]
fn a_witness_that_dies_before_it_is_ready_fails_fast_with_its_own_message() {
    let dir = scratch("early-exit");
    let err = dir.join("w.err");
    let mut child = OwnedChild(Some(
        spawn(
            &strings(&["sh", "-c", "echo 'tcpdump: no permission' >&2; exit 3"]),
            &dir.join("w.out"),
            &err,
        )
        .unwrap(),
    ));
    let started = Instant::now();
    let e = wait_ready(&mut child, &dir.join("never.ready"), 30, &err).unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "waited the full timeout"
    );
    assert!(e.contains("exited") && e.contains("no permission"), "{e}");
    // A witness that becomes ready is reported as ready.
    fs::write(dir.join("ok.ready"), "x").unwrap();
    let mut alive = OwnedChild(Some(
        spawn(
            &strings(&["sleep", "5"]),
            &dir.join("a.out"),
            &dir.join("a.err"),
        )
        .unwrap(),
    ));
    assert!(wait_ready(&mut alive, &dir.join("ok.ready"), 5, &dir.join("a.err")).is_ok());
    alive.stop("TERM").unwrap();
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn perf_rows_record_the_capture_kernel_drops_of_every_cell_and_never_normalise_an_invalid_one() {
    // LR N4: the witness runs tcpdump with -U --immediate-mode; at 100k pps that may drop frames
    // in the kernel and make cells INVALID. The drops must be visible per cell, not hidden.
    let mut cells = full_matrix();
    let at = cells
        .iter()
        .position(|c| c["impl"] == "rust" && c["rate"] == 100000 && c["rep"] == 3)
        .unwrap();
    cells[at]["capture"] = json!({"valid":false,"kernel_drops":7,"interface_drop_delta":0,
        "invalid_reasons":["tcpdump dropped 7 packets by kernel"]});
    cells[at]["valid"] = json!(false);
    let dir = scratch("perf-drops");
    let mut d = driver_in(&dir);
    d.perf_summarize(&cells, &[100, 1000, 10000, 100000]);
    let rows = d.extra["perf_summary"].as_array().unwrap().clone();
    let hot = rows.iter().find(|r| r["rate"] == 100000).unwrap();
    assert_eq!(
        hot["rust_capture_kernel_drops_per_run"],
        json!([0, 0, 7, 0, 0])
    );
    assert_eq!(
        hot["c_capture_kernel_drops_per_run"],
        json!([0, 0, 0, 0, 0])
    );
    assert_eq!(hot["rust_capture_invalid_runs"], 1);
    assert_eq!(hot["rust_valid"], 4);
    assert_eq!(hot["rust_invalid"], 1);
    assert_eq!(
        hot["rust_capture_invalid_reasons"],
        json!(["tcpdump dropped 7 packets by kernel"])
    );
    let cold = rows.iter().find(|r| r["rate"] == 100).unwrap();
    assert_eq!(
        cold["rust_capture_kernel_drops_per_run"],
        json!([0, 0, 0, 0, 0])
    );
    assert_eq!(cold["rust_capture_invalid_runs"], 0);
    // The matrix check fails: an invalid cell is never counted as valid.
    let matrix = d
        .checks
        .iter()
        .find(|c| c["name"] == "matrix complete: every cell VALID")
        .expect("matrix check");
    assert_eq!(matrix["result"], "FAIL");
    let _ = fs::remove_dir_all(dir);
}

// ---- final review M-2: an interrupted perf run is partial, never a complete FAIL matrix ----
#[test]
fn an_interrupted_perf_run_is_partial_and_starts_no_further_cell() {
    let out = scratch("perf-interrupted");
    let mut d = driver_in(&out);
    TEST_STOP.with(|s| s.set(true));
    let r = d.perf(&[100, 1000], 5);
    TEST_STOP.with(|s| s.set(false));
    let e = r.unwrap_err();
    assert!(e.contains("interrupted") && e.contains("partial"), "{e}");
    let v: Value = serde_json::from_slice(&fs::read(out.join("results.json")).unwrap()).unwrap();
    assert_eq!(v["partial"], true);
    assert_eq!(v["interrupted"], true);
    assert_eq!(
        v["perf_cells"],
        json!([]),
        "no cell was started, none recorded as failed"
    );
    assert!(
        v["checks"].as_array().unwrap().is_empty(),
        "no matrix verdict is written for a partial run: {v}"
    );
    let _ = fs::remove_dir_all(&out);
}
// The orchestrator runs on Mac and Linux; this test relies on unix paths or tools.
#[cfg(unix)]
#[test]
fn cleanup_signals_do_not_go_through_command_and_reach_the_process() {
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    signal_process("TERM", child.id());
    let t = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "the signal never arrived"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

// ---- review 7ffa155, P2: an invalid Stop stage is never accepted ----
fn good_stop(implementation: &str) -> Value {
    let mut s = json!({"rc":0,"capture_valid":true,"stopped_early":true,"stop_to_exit_s":0.01});
    if implementation == "rust" {
        s["reason"] = json!("Stopped");
    }
    s
}
#[test]
fn the_stop_stage_verdict_needs_capture_exit_stop_and_the_rust_outcome() {
    for i in ["c", "rust"] {
        assert!(stop_stage_valid(&good_stop(i), i), "{i}");
        for (k, v) in [
            ("capture_valid", json!(false)),
            ("capture_valid", Value::Null),
            ("rc", json!(1)),
            ("stopped_early", json!(false)),
            ("stop_to_exit_s", Value::Null),
        ] {
            let mut s = good_stop(i);
            s[k] = v.clone();
            assert!(!stop_stage_valid(&s, i), "{i} {k}={v}");
        }
    }
    let mut s = good_stop("rust");
    s["reason"] = json!("Completed");
    assert!(!stop_stage_valid(&s, "rust"), "Rust must report Stopped");
    assert!(
        !stop_stage_valid(&json!({}), "c"),
        "absent fields never pass"
    );
}
#[test]
fn an_invalid_stop_stage_is_out_of_the_stop_median_and_the_matrix_check() {
    let dir = scratch("invalid-stop");
    let mut d = driver_in(&dir);
    let mut cells = full_matrix();
    // Three of five invalid with an outlier: without the filter the median would be the outlier.
    for c in cells
        .iter_mut()
        .filter(|c| c["impl"] == "rust" && c["rate"] == 100 && c["rep"].as_u64() <= Some(3))
    {
        c["stop"] = json!({"capture_valid":false,"valid":false,"stop_to_exit_s":99.0});
    }
    d.perf_summarize(&cells, &[100, 1000, 10000, 100000]);
    let row = &d.extra["perf_summary"][0];
    assert_eq!(row["rust_stop_s_median"], json!(0.01), "{row}");
    assert_eq!(row["rust_stop_invalid_runs"], json!(3));
    assert_eq!(row["c_stop_invalid_runs"], json!(0));
    let matrix = d
        .checks
        .iter()
        .find(|c| c["name"].as_str().unwrap().starts_with("matrix complete"))
        .unwrap();
    assert_eq!(matrix["result"], "FAIL", "{matrix}");
    let _ = fs::remove_dir_all(dir);
}
#[test]
fn the_linux_wire_acceptance_rejects_an_invalid_stop_capture_in_a_results_file() {
    let mut cells = full_matrix();
    cells[0]["stop"]["capture_valid"] = json!(false);
    let dir = scratch("invalid-stop-file");
    let mut d = driver_in(&dir);
    d.extra["perf_cells"] = json!(cells);
    d.perf_summarize(&cells, &[100, 1000, 10000, 100000]);
    d.save(false).unwrap();
    let text = fs::read_to_string(dir.join("results.json")).unwrap();
    let r = std::panic::catch_unwind(|| assert_linux_wire_perf_acceptance(&text));
    let _ = fs::remove_dir_all(dir);
    assert!(
        r.is_err(),
        "capture_valid=false in a Stop stage must fail the acceptance"
    );
}
