//! Acceptance mutation tests use copies only; preserved wire evidence is immutable.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn evidence(plan: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw")
        .join(plan);
    if path.is_dir() {
        path
    } else {
        Path::new(file!())
            .parent()
            .unwrap()
            .join("../../../..")
            .join("docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw")
            .join(plan)
    }
}
fn copy_tree(a: &Path, b: &Path) {
    fs::create_dir_all(b).unwrap();
    for e in fs::read_dir(a).unwrap() {
        let e = e.unwrap();
        let dst = b.join(e.file_name());
        if e.path().is_dir() {
            copy_tree(&e.path(), &dst);
        } else {
            fs::copy(e.path(), dst).unwrap();
        }
    }
}
struct Scratch(PathBuf);
impl Scratch {
    fn new(plan: &str, tag: Option<&str>) -> Self {
        let p = std::env::temp_dir().join(format!(
            "rmasscan-verifier-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        if plan == "failure" {
            // Part B evidence was discarded: the plan is synthesised, never read from disk.
            fixture::build_failure(&p, 3);
            return Self(p);
        }
        let src = evidence(plan);
        if let Some(tag) = tag {
            fs::copy(src.join("manifest.json"), p.join("manifest.json")).unwrap();
            copy_tree(&src.join("fixtures"), &p.join("fixtures"));
            copy_tree(&src.join("runs").join(tag), &p.join("runs").join(tag));
        } else {
            copy_tree(&src, &p);
        }
        Self(p)
    }
    fn edit(&self, file: &str, change: impl FnOnce(&mut Value)) {
        let path = self.0.join(file);
        let mut v = read_json(&path).unwrap();
        change(&mut v);
        fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
    }
    /// Edit scanner output and keep the invocation hash proof consistent: a
    /// scanner that really reported it, so only the rule under test reacts.
    fn edit_sealed(&self, file: &str, change: impl FnOnce(&mut Value)) {
        self.edit(file, change);
        fixture::reseal(self.0.join(file).parent().unwrap());
    }
    fn edit_run(&self, tag: &str, path: &str, value: Value) {
        self.edit_sealed(&format!("runs/{tag}/run.json"), |v| {
            *v.pointer_mut(path).expect(path) = value
        });
    }
    fn status(&self, tag: &str) -> (String, bool) {
        run_status(&self.0, tag)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn mutate(plan: &str, tag: &str, file: &str, path: &str, value: Value, want: &str, beh: bool) {
    let d = Scratch::new(plan, Some(tag));
    d.edit_sealed(&format!("runs/{tag}/{file}"), |v| {
        *v.pointer_mut(path).expect(path) = value
    });
    assert_eq!(
        d.status(tag),
        (want.into(), beh),
        "{plan}/{tag}/{file}:{path}"
    );
}
#[test]
fn full_failure_plan_replays_19_pass() {
    let d = Scratch::new("failure", None);
    let v = verify_dir(&d.0);
    assert_eq!(
        v["overall"],
        PASS,
        "{}",
        serde_json::to_string_pretty(&v).unwrap()
    );
    assert_eq!(v["totals"][PASS], 19);
}
#[test]
fn malformed_exported_checkpoints_are_a_behaviour_failure_and_never_rerunnable() {
    for bytes in [vec![], vec![0; 120], vec![1; 60]] {
        let d = Scratch::new("functional", Some("pause_N8"));
        fs::write(d.0.join("runs/pause_N8/checkpoint.bin"), bytes).unwrap();
        let (verdict, behaviour) = d.status("pause_N8");
        assert_eq!((verdict.as_str(), behaviour), (FAIL, true));
        assert!(!crate::windows_suite::may_discard(&verdict, behaviour));
    }
}
#[test]
fn exported_checkpoint_checksum_and_identity_are_verified() {
    for pos in [0, 8, 12, 16, 32, 48, 87, 119] {
        let d = Scratch::new("functional", Some("pause_N8"));
        let p = d.0.join("runs/pause_N8/checkpoint.bin");
        let mut bytes = fs::read(&p).unwrap();
        bytes[pos] ^= 1;
        if pos < 88 {
            let sum = Sha256::digest(&bytes[..88]);
            bytes[88..].copy_from_slice(&sum);
        }
        fs::write(p, bytes).unwrap();
        assert_eq!(d.status("pause_N8"), (FAIL.into(), true), "position {pos}");
    }
}
#[test]
fn all_checkpoint_fields_must_match_report() {
    for (path, value) in [
        ("/checkpoint_hex", json!("")),
        ("/job/job_digest", json!("00".repeat(32))),
    ] {
        mutate(
            "functional",
            "pause_N8",
            "run.json",
            path,
            value,
            FAIL,
            true,
        );
    }
}
#[test]
fn requested_scan_and_attempt_identity_cannot_be_consistently_replaced() {
    for field in ["scan_id", "attempt_id"] {
        let d = Scratch::new("functional", None);
        for tag in ["pause_N8", "resume_N8"] {
            d.edit_run(tag, &format!("/{field}"), json!("cc".repeat(16)));
        }
        assert_eq!(verify_dir(&d.0)["overall"], FAIL);
    }
}
#[test]
fn capture_provenance_mutations_are_invalid() {
    let tag = "c03_multi_ports.run1";
    for (file, path, value) in [
        ("capture.json", "/peer/tcpdump/dropped_kernel", json!(1)),
        ("capture.json", "/peer/tcpdump/dropped_if", json!(1)),
        ("capture.json", "/peer/tcpdump/captured", json!(1)),
        ("capture.json", "/peer/tcpdump/received", Value::Null),
        ("capture.json", "/peer/tcpdump/dropped_kernel", json!(-1)),
        ("capture.json", "/peer/counters/rx_end", json!(999999)),
        ("capture.json", "/quiet/reached", json!(false)),
        ("capture.json", "/peer/listening", json!(false)),
        ("capture.json", "/eno1/filter", json!("tcp port 1")),
        ("capture.json", "/peer/filter", json!("tcp")),
        ("capture.json", "/peer/pcap/sha256", json!("wrong")),
        ("status-pre.json", "/raw_run_allowed", json!(false)),
        ("status-post.json", "/raw_run_allowed", json!(false)),
        ("guest-verify.json", "/ok", json!(false)),
        ("listeners.json", "/ready", json!(false)),
        ("listeners.json", "/silent_proven", json!(false)),
        ("run.json", "/identity/source_commit", json!("wrong")),
        ("run.json", "/identity/binary_sha256", json!("wrong")),
        ("run.json", "/identity/os/family", json!("linux")),
        ("meta.json", "/capture_stopped_utc", json!(0)),
    ] {
        mutate("functional", tag, file, path, value, INVALID, false);
    }
}
#[test]
fn wrong_interface_is_invalid_even_when_filter_and_packet_hashes_match() {
    for who in ["peer", "eno1"] {
        let d = Scratch::new("functional", Some("c03_multi_ports.run1"));
        d.edit("runs/c03_multi_ports.run1/capture.json", |v| {
            let a = v[who]["cmd"].as_array_mut().unwrap();
            let i = a.iter().position(|v| v == "-i").unwrap();
            a[i + 1] = json!("lo");
        });
        assert_eq!(d.status("c03_multi_ports.run1"), (INVALID.into(), false));
    }
}
#[test]
fn missing_artifacts_never_pass() {
    for file in [
        "run.json",
        "meta.json",
        "capture.json",
        "peer.pcap",
        "eno1.pcap",
        "status-post.json",
        "guest-verify.json",
        "listeners.json",
        "argv.json",
    ] {
        let d = Scratch::new("functional", Some("c03_multi_ports.run1"));
        fs::remove_file(d.0.join("runs/c03_multi_ports.run1").join(file)).unwrap();
        assert_eq!(d.status("c03_multi_ports.run1").0, NOT_RUN, "{file}");
    }
}
#[test]
fn packet_truncation_and_hash_changes_are_invalid() {
    for truncate in [true, false] {
        let d = Scratch::new("functional", Some("c03_multi_ports.run1"));
        let p = d.0.join("runs/c03_multi_ports.run1/peer.pcap");
        let mut b = fs::read(&p).unwrap();
        if truncate {
            b.pop();
        } else {
            b[28] ^= 1;
        }
        fs::write(p, b).unwrap();
        assert_eq!(d.status("c03_multi_ports.run1").0, INVALID);
    }
}
#[test]
fn continuous_behaviour_checks_fail_independently_of_capture() {
    let tag = "c03_multi_ports.run1";
    for (path, value) in [
        ("/reason", json!("Failed")),
        ("/sent", json!(1)),
        ("/next_index", json!(1)),
        ("/expected_total", json!(1)),
        ("/range", json!(1)),
        ("/rx_health/kernel_drops", Value::Null),
        ("/rx_health/kernel_drops", json!(1)),
        ("/net/kernel_drops", Value::Null),
        ("/net/tx_sent", json!(1)),
        ("/net/tx_uncertain", json!(1)),
        ("/net/rx_errors", json!(1)),
        ("/replies", json!([])),
        ("/reply_unique", json!(1)),
        ("/job/ports", json!("80")),
    ] {
        mutate("functional", tag, "run.json", path, value, FAIL, true);
    }
}
#[test]
fn argv_error_disables_behaviour_blame() {
    let d = Scratch::new("functional", Some("c03_multi_ports.run1"));
    d.edit("runs/c03_multi_ports.run1/argv.json", |v| {
        v["argv"]
            .as_array_mut()
            .unwrap()
            .push(json!("--unexpected"))
    });
    d.edit_run("c03_multi_ports.run1", "/reason", json!("Failed"));
    assert_eq!(d.status("c03_multi_ports.run1"), (INVALID.into(), false));
}
#[test]
fn bad_capture_cannot_hide_scanner_failure() {
    let d = Scratch::new("functional", None);
    d.edit("runs/c03_multi_ports.run1/capture.json", |v| {
        v["quiet"]["reached"] = json!(false)
    });
    d.edit_run("c03_multi_ports.run1", "/reason", json!("Failed"));
    let v = verify_dir(&d.0);
    assert_eq!(v["overall"], FAIL);
    assert!(array(&v["behaviour_fail"]).contains(&json!("c03_multi_ports.run1")));
}
#[test]
fn stale_run_binding_is_invalid() {
    let d = Scratch::new("functional", Some("c03_multi_ports.run1"));
    d.edit("runs/c03_multi_ports.run1/meta.json", |v| {
        v["run_id"] = json!("new")
    });
    d.edit("runs/c03_multi_ports.run1/run.json", |v| {
        v["run_id"] = json!("old")
    });
    d.edit("runs/c03_multi_ports.run1/guest-verify.json", |v| {
        v["run_id"] = json!("old")
    });
    assert_eq!(d.status("c03_multi_ports.run1").0, INVALID);
}
#[test]
fn stop_latency_worker_and_resource_mutations_fail() {
    for (path, value) in [
        ("/timing/stop_to_outcome_ms", json!(1001)),
        ("/timing/stop_to_outcome_ms", Value::Null),
        ("/timing/join_ms", json!(1001)),
        ("/timing/stop_requested", json!(false)),
        ("/checkpoint", json!(true)),
        ("/reason", json!("Completed")),
        ("/workers/tx_tid", Value::Null),
        ("/workers/rx_alive_after_join", json!(true)),
        ("/resources/fds_after_join", json!(99999)),
        ("/tx_sent_after_observe", json!(999)),
        ("/observe_ms", json!(1)),
        ("/reply_total", json!(1)),
    ] {
        mutate(
            "failure",
            "stop_silent",
            "run.json",
            path,
            value,
            FAIL,
            true,
        );
    }
}
#[test]
fn unrelated_process_worker_count_is_not_engine_leak() {
    let d = Scratch::new("failure", Some("stop_silent"));
    d.edit_sealed("runs/stop_silent/run.json", |v| {
        v["resources"]["threads_before"] = json!(1);
        v["resources"]["threads_after_join"] = json!(999);
    });
    assert_eq!(d.status("stop_silent"), (PASS.into(), false));
}
#[test]
fn failure_plan_each_error_contract_enforced() {
    for (tag, path, value) in [
        ("stop_drain", "/timing/total_s", json!(10.5)),
        ("stop_fullqueue", "/reply_total", json!(1)),
        ("stop_load", "/net/rx_packets", json!(1)),
        ("overflow_queue", "/fail_detail", json!("RxLoss { n: 3 }")),
        ("linkloss", "/fail_detail", json!("TxError")),
        ("ckpt_wrong_seed", "/error", json!("BadChecksum")),
        ("ckpt_empty", "/opened_adapter", json!(true)),
        ("perm_restricted_scan", "/opened_adapter", json!(true)),
        (
            "perm_restricted_inventory",
            "/devices",
            json!([{"name":"NPF_X","loopback":false}]),
        ),
        (
            "rxloss",
            "/fail_detail",
            json!("RxLoss { kernel_drops: 8 }"),
        ),
        ("rxloss", "/checkpoint", json!(true)),
    ] {
        mutate("failure", tag, "run.json", path, value, FAIL, true);
    }
}
#[test]
fn rxloss_unreproduced_or_unknown_is_not_run() {
    for v in [Value::Null, json!(0), json!(-1), json!(true)] {
        mutate(
            "failure",
            "rxloss",
            "run.json",
            "/rx_health/kernel_drops",
            v,
            NOT_RUN,
            false,
        );
    }
}
#[test]
fn rxloss_independent_count_inputs_required() {
    let d = Scratch::new("failure", Some("rxloss"));
    fs::remove_file(d.0.join("runs/rxloss/nic.json")).unwrap();
    assert_eq!(d.status("rxloss").0, NOT_RUN);
}
#[test]
fn failure_plan_harness_evidence_mutations_invalid() {
    for (tag, file, path, value) in [
        ("stop_load", "flood.json", "/sent", json!(1)),
        ("stop_load", "flood.json", "/t_last", json!(0)),
        (
            "linkloss",
            "linkloss.json",
            "/events/0/reply",
            json!({"error":"denied"}),
        ),
        ("linkloss", "linkloss.json", "/events/0/t", json!(0)),
        (
            "perm_restricted_scan",
            "meta.json",
            "/restricted_via",
            json!("plain"),
        ),
    ] {
        mutate("failure", tag, file, path, value, INVALID, false);
    }
}
#[test]
fn failure_checkpoint_file_is_behaviour_fail() {
    for tag in ["linkloss", "rxloss"] {
        mutate(
            "failure",
            tag,
            "meta.json",
            "/checkpoint_file_exists",
            json!(true),
            FAIL,
            true,
        );
    }
}
#[test]
fn foreign_floor_is_a_failure_even_with_bad_capture() {
    let d = Scratch::new("functional", Some("x01_foreign_replies.run1"));
    d.edit_run("x01_foreign_replies.run1", "/discarded", json!(0));
    d.edit("runs/x01_foreign_replies.run1/capture.json", |v| {
        v["quiet"]["reached"] = json!(false)
    });
    assert!(d.status("x01_foreign_replies.run1").1);
}
#[test]
fn incomplete_capture_cannot_blame_unexplained_foreign_discards() {
    let d = Scratch::new("functional", Some("x01_foreign_replies.run1"));
    d.edit_run("x01_foreign_replies.run1", "/discarded", json!(999999));
    d.edit("runs/x01_foreign_replies.run1/capture.json", |v| {
        v["quiet"]["reached"] = json!(false)
    });
    assert_eq!(
        d.status("x01_foreign_replies.run1"),
        (INVALID.into(), false)
    );
}
#[test]
fn fixture_hash_binding_and_path_must_match() {
    for (field, value) in [
        ("/binding/src_mac", json!("00:00:00:00:00:00")),
        ("/oracle/git_tree_clean", json!(false)),
        ("/fixtures/c03_multi_ports.run1/sha256", json!("bad")),
        (
            "/fixtures/c03_multi_ports.run1/file",
            json!("../outside.pcap"),
        ),
    ] {
        let d = Scratch::new("functional", Some("c03_multi_ports.run1"));
        d.edit("fixtures/manifest.json", |v| {
            *v.pointer_mut(field).unwrap() = value
        });
        assert_eq!(d.status("c03_multi_ports.run1").0, INVALID);
    }
}
#[test]
fn discarded_pass_fail_and_unknown_are_not_hidden() {
    for variant in ["pass", "fail", "unknown"] {
        let d = Scratch::new("functional", None);
        let tag = "c03_multi_ports.run1";
        let name = if variant == "unknown" {
            "unknown.123"
        } else {
            "c03_multi_ports.run1.123"
        };
        copy_tree(
            &d.0.join("runs").join(tag),
            &d.0.join("runs_discarded").join(name),
        );
        if variant == "fail" {
            d.edit(&format!("runs_discarded/{name}/run.json"), |v| {
                v["reason"] = json!("Failed")
            });
        }
        assert_eq!(
            verify_dir(&d.0)["overall"],
            if variant == "pass" { INVALID } else { FAIL }
        );
    }
}
fn rewrite_pcap(d: &Scratch, tag: &str, who: &str, change: impl FnOnce(&mut Frames)) {
    let path = d.0.join("runs").join(tag).join(format!("{who}.pcap"));
    let (_, mut frames) = pcap::read_pcap_records(&fs::read(&path).unwrap()).unwrap();
    change(&mut frames);
    let bytes = pcap::encode(&frames);
    fs::write(path, &bytes).unwrap();
    d.edit(&format!("runs/{tag}/capture.json"),|v|{v[who]["pcap"]=json!({"sha256":sha(&bytes),"size":bytes.len(),"frames":frames.len()});v[who]["tcpdump"]["captured"]=json!(frames.len());v[who]["tcpdump"]["received"]=json!(frames.len());if who=="peer"{v[who]["counters"]=json!({"rx_before":0,"tx_before":0,"rx_ready":0,"tx_ready":0,"rx_end":frames.len(),"tx_end":0});}});
}
#[test]
fn syn_bytes_and_order_are_exact() {
    for reorder in [false, true] {
        let d = Scratch::new("functional", Some("c03_multi_ports.run1"));
        rewrite_pcap(&d, "c03_multi_ports.run1", "peer", |fr| {
            let ii: Vec<_> = fr
                .iter()
                .enumerate()
                .filter(|(_, (_, f))| pcap::is_syn(f))
                .map(|(i, _)| i)
                .collect();
            if reorder {
                let a = fr[ii[0]].1.clone();
                fr[ii[0]].1 = fr[ii[1]].1.clone();
                fr[ii[1]].1 = a;
            } else {
                fr[ii[0]].1[41] ^= 1;
            }
        });
        assert_eq!(d.status("c03_multi_ports.run1"), (FAIL.into(), false));
    }
}
#[test]
fn eno1_isolation_failure_is_detected() {
    let d = Scratch::new("functional", Some("c03_multi_ports.run1"));
    let (_, fr) = pcap::read_pcap_records(
        &fs::read(d.0.join("runs/c03_multi_ports.run1/peer.pcap")).unwrap(),
    )
    .unwrap();
    let one = fr.into_iter().find(|(_, f)| pcap::is_syn(f)).unwrap();
    rewrite_pcap(&d, "c03_multi_ports.run1", "eno1", |fr| fr.push(one));
    assert_eq!(d.status("c03_multi_ports.run1").0, FAIL);
}
#[test]
fn missing_readiness_is_invalid() {
    let d = Scratch::new("functional", Some("c03_multi_ports.run1"));
    rewrite_pcap(&d, "c03_multi_ports.run1", "peer", |fr| {
        fr.retain(|(_, f)| !ether(f, [0x88, 0xb5]))
    });
    assert_eq!(d.status("c03_multi_ports.run1").0, INVALID);
}
#[test]
fn schema2_end_marker_tail_and_immediate_mode_required() {
    for variant in ["end", "late", "mode", "downgrade"] {
        let d = Scratch::new("failure", Some("stop_silent"));
        match variant {
            "end" => rewrite_pcap(&d, "stop_silent", "peer", |fr| {
                fr.retain(|(_, f)| f.get(14..25) != Some(b"WIRELAB-END".as_slice()))
            }),
            "late" => rewrite_pcap(&d, "stop_silent", "peer", |fr| {
                let t = fr.last().unwrap().0 + 1.;
                let mut frame = fr[0].1.clone();
                frame[12] = 8;
                frame[13] = 6;
                fr.push((t, frame));
            }),
            "mode" => d.edit("runs/stop_silent/capture.json", |v| {
                v["peer"]["cmd"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|v| v != "--immediate-mode")
            }),
            _ => d.edit("runs/stop_silent/capture.json", |v| {
                v["capture_schema"] = json!(1)
            }),
        }
        assert_eq!(d.status("stop_silent").0, INVALID, "{variant}");
    }
}
#[test]
fn late_tx_is_failure_only_when_capture_complete() {
    for lossy in [false, true] {
        let d = Scratch::new("failure", Some("stop_silent"));
        let j = read_json(d.0.join("runs/stop_silent/run.json")).unwrap();
        let (fr, _) = {
            let data = fs::read(d.0.join("runs/stop_silent/peer.pcap")).unwrap();
            (pcap::read_pcap_records(&data).unwrap().1, data)
        };
        let man = read_json(d.0.join("manifest.json")).unwrap();
        let b = Binding::new(&man["binding"]);
        let sy = syns(&fr, &b, (40000, 40000));
        let end = f(&j["wall"]["outcome_utc_ms"]) / 1000. + sy[0].0
            - f(&j["wall"]["t0_utc_ms"]) / 1000.
            - f(&j["timing"]["first_send_s"]);
        let packet = sy[0].1.clone();
        rewrite_pcap(&d, "stop_silent", "peer", |fr| {
            fr.push((end + 0.3, packet));
            fr.sort_by(|a, b| a.0.total_cmp(&b.0));
        });
        d.edit_sealed("runs/stop_silent/run.json", |v| {
            let count = n(&v["sent"]) + 1;
            for k in [
                "sent",
                "next_index",
                "tx_sent_at_join",
                "tx_sent_after_observe",
            ] {
                v[k] = json!(count);
            }
            v["net"]["tx_sent"] = json!(count);
        });
        if lossy {
            d.edit("runs/stop_silent/capture.json", |v| {
                v["quiet"]["reached"] = json!(false)
            });
        }
        assert_eq!(
            d.status("stop_silent"),
            (if lossy { INVALID } else { FAIL }.into(), !lossy)
        );
    }
}
#[test]
fn fresh_invocation_requires_matching_nonce_and_hash_proof() {
    let d = Scratch::new("functional", Some("c03_multi_ports.run1"));
    let tag = "c03_multi_ports.run1";
    d.edit(&format!("runs/{tag}/meta.json"), |v| {
        v["invocation_nonce"] = json!("new")
    });
    d.edit(&format!("runs/{tag}/guest-verify.json"), |v| {
        v["verification_nonce"] = json!("new")
    });
    let base = d.0.join("runs").join(tag);
    fs::write(base.join("guest-runner.json"), b"{\"exit_code\":0}").unwrap();
    let mut proof = json!({"invocation_nonce":"new","files":{}});
    for name in [
        "run.json",
        "guest-runner.json",
        "argv.json",
        "guest-verify.json",
    ] {
        proof["files"][name] = json!(sha(&fs::read(base.join(name)).unwrap()));
    }
    fs::write(
        base.join("run-artifacts.json"),
        serde_json::to_vec(&proof).unwrap(),
    )
    .unwrap();
    assert_eq!(d.status(tag), (PASS.into(), false));
    d.edit(&format!("runs/{tag}/run-artifacts.json"), |v| {
        v["invocation_nonce"] = json!("old")
    });
    assert_eq!(d.status(tag).0, INVALID);
    d.edit(&format!("runs/{tag}/run-artifacts.json"), |v| {
        v["invocation_nonce"] = json!("new")
    });
    d.edit(&format!("runs/{tag}/guest-runner.json"), |v| {
        v["exit_code"] = json!(2)
    });
    assert_eq!(d.status(tag).0, INVALID);
}
#[test]
fn guest_transport_failure_cannot_reuse_old_success() {
    mutate(
        "functional",
        "c03_multi_ports.run1",
        "meta.json",
        "/guest_ssh_rc",
        json!(255),
        INVALID,
        false,
    );
}
#[test]
fn received_and_duplicate_counters_require_measured_unsigned_values() {
    for field in ["received", "duplicates"] {
        for value in [
            Value::Null,
            json!(-1),
            json!("0"),
            json!(false),
            json!(0.5),
            json!(9_223_372_036_854_775_808u64),
        ] {
            let d = Scratch::new("functional", Some("c01_one_addr_port_synack.run1"));
            d.edit_run("c01_one_addr_port_synack.run1", &format!("/{field}"), value);
            assert_ne!(d.status("c01_one_addr_port_synack.run1").0, PASS, "{field}");
        }
        let d = Scratch::new("functional", Some("c01_one_addr_port_synack.run1"));
        d.edit("runs/c01_one_addr_port_synack.run1/run.json", |v| {
            v.as_object_mut().unwrap().remove(field);
        });
        assert_ne!(
            d.status("c01_one_addr_port_synack.run1").0,
            PASS,
            "missing {field}"
        );
    }
}
#[test]
fn maximum_receive_counters_neither_overflow_nor_pass() {
    for count in [i64::MAX as u64, u64::MAX] {
        let d = Scratch::new("functional", Some("c01_one_addr_port_synack.run1"));
        d.edit("runs/c01_one_addr_port_synack.run1/run.json", |v| {
            v["received"] = json!(count);
            v["duplicates"] = json!(count);
        });
        assert_ne!(d.status("c01_one_addr_port_synack.run1").0, PASS);
    }
}
#[test]
fn maximum_interface_counters_neither_overflow_nor_pass() {
    for count in [i64::MAX as u64, u64::MAX] {
        let d = Scratch::new("functional", Some("c01_one_addr_port_synack.run1"));
        d.edit("runs/c01_one_addr_port_synack.run1/capture.json",|v|v["peer"]["counters"]=json!({"rx_before":0,"tx_before":0,"rx_ready":0,"tx_ready":0,"rx_end":count,"tx_end":count}));
        assert_eq!(d.status("c01_one_addr_port_synack.run1").0, INVALID);
    }
}
#[test]
fn omitted_tcpdump_interface_drops_need_independent_measurement() {
    for delta in [
        None,
        Some(Value::Null),
        Some(json!(-1)),
        Some(json!(1)),
        Some(json!(0)),
    ] {
        let d = Scratch::new("functional", Some("c01_one_addr_port_synack.run1"));
        d.edit("runs/c01_one_addr_port_synack.run1/capture.json", |v| {
            v["peer"]["tcpdump"]["dropped_if"] = Value::Null;
            if let Some(delta) = delta.clone() {
                v["peer"]["interface_drop_delta"] = delta;
            }
        });
        assert_eq!(
            d.status("c01_one_addr_port_synack.run1").0,
            if delta == Some(json!(0)) {
                PASS
            } else {
                INVALID
            }
        );
    }
    let d = Scratch::new("functional", Some("c01_one_addr_port_synack.run1"));
    d.edit("runs/c01_one_addr_port_synack.run1/capture.json", |v| {
        v["peer"]["interface_drop_delta"] = json!(1)
    });
    assert_eq!(d.status("c01_one_addr_port_synack.run1").0, INVALID);
}
#[test]
fn interface_counters_cannot_decrease_and_compensate_each_other() {
    let d = Scratch::new("functional", Some("c01_one_addr_port_synack.run1"));
    d.edit("runs/c01_one_addr_port_synack.run1/capture.json",|v|{let count=v["peer"]["pcap"]["frames"].as_u64().unwrap();v["peer"]["counters"]=json!({"rx_before":1,"tx_before":0,"rx_ready":1,"tx_ready":0,"rx_end":0,"tx_end":count+1});});
    assert_eq!(d.status("c01_one_addr_port_synack.run1").0, INVALID);
}
#[test]
fn independent_nic_unknown_fields_are_not_measured_zero() {
    for value in [Value::Null, json!(-1), json!("0")] {
        let d = Scratch::new("failure", Some("rxloss"));
        d.edit("runs/rxloss/nic.json", |v| {
            v["after"]["stats"]["ReceivedMulticastPackets"] = value
        });
        assert_eq!(d.status("rxloss").0, NOT_RUN);
    }
}
// ---- part B rules, pinned on synthetic evidence (never on discarded runs) ----
#[test]
fn synthetic_failure_plan_has_every_run_passing_individually() {
    let d = Scratch::new("failure", None);
    let v = verify_dir(&d.0);
    assert_eq!(v["totals"][PASS], 19, "manifest plus 18 runs");
    for r in array(&v["runs"]) {
        assert_eq!(r["verdict"], PASS, "{}", r["tag"]);
    }
    assert!(array(&v["behaviour_fail"]).is_empty());
}
#[test]
fn every_checkpoint_refusal_variant_must_name_its_reason_and_open_nothing() {
    for variant in [
        "wrong_ports",
        "wrong_seed",
        "corrupt_next_index",
        "corrupt_checksum",
        "truncated",
        "empty",
        "future_format",
        "future_engine",
    ] {
        let tag = format!("ckpt_{variant}");
        for (file, path, value) in [
            ("run.json", "/error", json!("Unrelated: wrong reason")),
            ("run.json", "/stage", json!("scan")),
            ("run.json", "/tx_sent", json!(1)),
            ("run.json", "/opened_adapter", json!(true)),
            ("meta.json", "/guest_exit", json!(0)),
        ] {
            mutate("failure", &tag, file, path, value, FAIL, true);
        }
    }
}
#[test]
fn a_scanner_syn_in_a_refusal_or_restricted_run_is_a_failure_only_with_a_complete_capture() {
    for tag in [
        "ckpt_wrong_ports",
        "perm_restricted_scan",
        "perm_restricted_inventory",
    ] {
        let d = Scratch::new("failure", Some(tag));
        rewrite_pcap(&d, tag, "peer", |fr| {
            fr.push((1_800_000_004.0, fixture::scanner_syn(80, 40000)))
        });
        assert_eq!(d.status(tag), (FAIL.into(), true), "{tag}");
        d.edit(&format!("runs/{tag}/capture.json"), |v| {
            v["quiet"]["reached"] = json!(false)
        });
        assert_eq!(d.status(tag), (INVALID.into(), false), "{tag} lossy");
    }
}
#[test]
fn restricted_token_rules() {
    mutate(
        "failure",
        "perm_restricted_scan",
        "meta.json",
        "/guest_exit",
        json!(1),
        FAIL,
        true,
    );
    mutate(
        "failure",
        "perm_restricted_inventory",
        "meta.json",
        "/guest_exit",
        json!(0),
        FAIL,
        true,
    );
    mutate(
        "failure",
        "perm_restricted_inventory",
        "run.json",
        "/access_hint",
        json!(""),
        FAIL,
        true,
    );
    mutate(
        "failure",
        "perm_restricted_inventory",
        "run.json",
        "/mode",
        json!("scan"),
        FAIL,
        true,
    );
    for tag in ["perm_restricted_scan", "perm_restricted_inventory"] {
        mutate(
            "failure",
            tag,
            "meta.json",
            "/restricted_via",
            json!(""),
            INVALID,
            false,
        );
    }
}
#[test]
fn overflow_and_linkloss_contracts() {
    for (tag, path, value) in [
        ("overflow_queue", "/sent", json!(6)),
        ("overflow_queue", "/replies", json!(["198.18.0.2:9:open"])),
        ("overflow_queue", "/checkpoint", json!(true)),
        ("linkloss", "/net/tx_uncertain", json!(0)),
        ("linkloss", "/sent", json!(200)),
        ("linkloss", "/checkpoint_hex", json!("00")),
    ] {
        mutate("failure", tag, "run.json", path, value, FAIL, true);
    }
    mutate(
        "failure",
        "overflow_queue",
        "meta.json",
        "/guest_exit",
        json!(0),
        FAIL,
        true,
    );
    mutate(
        "failure",
        "linkloss",
        "meta.json",
        "/guest_exit",
        json!(0),
        FAIL,
        true,
    );
}
#[test]
fn linkloss_harness_events_must_prove_down_then_restore_around_the_failure() {
    for (path, value) in [
        ("/first_syn_seen", json!(false)),
        ("/events/1/reply", json!({"error":"x"})),
        ("/events/1/t", json!(1_800_000_001.0)),
        // Restored after the down event but before the scanner outcome: only the ordering rule objects.
        ("/events/1/t", json!(1_800_000_000.0 + 3.0 + 1.8 - 0.2)),
        ("/events/0/t", json!(1_800_000_000.0 + 3.0 + 1.8 - 3.5)),
        ("/events/0/t", json!(1_800_000_000.0 + 3.0 + 1.8 + 0.5)),
    ] {
        mutate(
            "failure",
            "linkloss",
            "linkloss.json",
            path,
            value,
            INVALID,
            false,
        );
    }
    let d = Scratch::new("failure", Some("linkloss"));
    fs::remove_file(d.0.join("runs/linkloss/linkloss.json")).unwrap();
    assert_eq!(d.status("linkloss").0, NOT_RUN);
}
#[test]
fn uncertain_tx_window_bounds_the_wire_syn_count() {
    // 30 confirmed + 1 uncertain: 31 on the wire is allowed; 32 or 29 is not.
    for extra in [1i64, -2] {
        let d = Scratch::new("failure", Some("linkloss"));
        rewrite_pcap(&d, "linkloss", "peer", |fr| {
            let syn: Vec<_> = fr
                .iter()
                .enumerate()
                .filter(|(_, (_, f))| pcap::is_syn(f))
                .map(|(i, _)| i)
                .collect();
            if extra > 0 {
                let mut again = fr[syn[0]].clone();
                again.0 = fr[*syn.last().unwrap()].0 + 0.01;
                fr.push(again);
            } else {
                for i in syn.iter().rev().take(2) {
                    fr.remove(*i);
                }
            }
        });
        assert_eq!(d.status("linkloss"), (FAIL.into(), true), "{extra}");
    }
}
#[test]
fn syn_after_the_terminal_outcome_fails_on_a_complete_capture() {
    let d = Scratch::new("failure", Some("stop_silent"));
    rewrite_pcap(&d, "stop_silent", "peer", |fr| {
        let mut late = fr.iter().find(|(_, f)| pcap::is_syn(f)).unwrap().clone();
        late.0 = 1_800_000_003.0 + 2.5 + 0.2;
        fr.push(late);
    });
    assert_eq!(d.status("stop_silent"), (FAIL.into(), true));
}
#[test]
fn rx_overflow_independent_bounds_and_flood_accounting() {
    mutate(
        "failure",
        "rxloss",
        "nic.json",
        "/after/stats/ReceivedUnicastPackets",
        json!(1050),
        FAIL,
        true,
    );
    mutate(
        "failure",
        "rxloss",
        "run.json",
        "/net/rx_packets",
        json!(5000),
        FAIL,
        true,
    );
    mutate(
        "failure",
        "rxloss",
        "flood.json",
        "/sent",
        json!(11),
        INVALID,
        false,
    );
    mutate(
        "failure",
        "rxloss",
        "flood.json",
        "/errors",
        json!(1),
        INVALID,
        false,
    );
    let d = Scratch::new("failure", Some("rxloss"));
    fs::remove_file(d.0.join("runs/rxloss/flood.json")).unwrap();
    assert_eq!(d.status("rxloss").0, NOT_RUN);
}
#[test]
fn rx_load_flood_must_overlap_the_stop_and_stay_on_the_wire() {
    for (path, value) in [
        ("/t_first", json!(1_800_000_010.0)),
        ("/t_last", json!(1_800_000_000.0)),
        ("/sent", json!(11)),
    ] {
        mutate(
            "failure",
            "stop_load",
            "flood.json",
            path,
            value,
            INVALID,
            false,
        );
    }
}
#[test]
fn drain_and_fullqueue_stop_contracts() {
    for (tag, path, value) in [
        ("stop_drain", "/sent", json!(1)),
        ("stop_drain", "/replies", json!([])),
        ("stop_fullqueue", "/replies", json!(["198.18.0.2:80:open"])),
        ("stop_fullqueue", "/sent", json!(1)),
        ("stop_silent", "/reply_total", json!(1)),
        ("stop_silent", "/sent", json!(20)),
        ("stop_silent", "/sent", json!(0)),
        ("stop_silent", "/fail_detail", json!("x")),
    ] {
        mutate("failure", tag, "run.json", path, value, FAIL, true);
    }
}
// ---- X4: the recorded capture argv is validated in full ----
fn set_cmd(d: &Scratch, tag: &str, who: &str, change: impl FnOnce(&mut Vec<Value>)) {
    d.edit(&format!("runs/{tag}/capture.json"), |v| {
        change(v[who]["cmd"].as_array_mut().unwrap())
    });
}
#[test]
fn peer_capture_must_run_in_the_manifest_namespace() {
    let tag = "stop_silent";
    type Edit = fn(&mut Vec<Value>);
    let bad: [(&str, Edit); 7] = [
        ("wvp-other", |c| c[3] = json!("wvp-other")),
        ("host namespace", |c| {
            c.drain(0..4);
        }),
        ("lo", |c| c[6] = json!("lo")),
        ("sudo without -n", |c| {
            c.insert(0, json!("sudo"));
        }),
        ("foreign prefix", |c| c.insert(0, json!("env"))),
        ("netns exec with -i eno1", |c| c[6] = json!("eno1")),
        ("extra tail filter", |c| c.push(json!("tcp"))),
    ];
    for (name, change) in bad {
        let d = Scratch::new("failure", Some(tag));
        set_cmd(&d, tag, "peer", change);
        assert_eq!(d.status(tag), (INVALID.into(), false), "{name}");
    }
    // `sudo -n` in front is the one allowed prefix.
    let d = Scratch::new("failure", Some(tag));
    set_cmd(&d, tag, "peer", |c| {
        c.splice(0..0, [json!("sudo"), json!("-n")]);
    });
    assert_eq!(d.status(tag), (PASS.into(), false));
    // The manifest, not the recorded command, decides which namespace is right.
    let d = Scratch::new("failure", Some(tag));
    d.edit("manifest.json", |v| {
        v["stand"]["netns"] = json!("wvp-other")
    });
    assert_eq!(d.status(tag), (INVALID.into(), false));
    d.edit("manifest.json", |v| {
        v["stand"].as_object_mut().unwrap().remove("netns");
    });
    assert_eq!(
        d.status(tag),
        (INVALID.into(), false),
        "no manifest namespace"
    );
}
#[test]
fn eno1_capture_must_run_in_the_host_namespace_with_the_derived_filter() {
    let tag = "stop_silent";
    type Edit = fn(&mut Vec<Value>);
    let bad: [(&str, Edit); 4] = [
        ("inside a namespace", |c| {
            c.splice(0..0, ["ip", "netns", "exec", "wvp-n2"].map(|s| json!(s)));
        }),
        ("foreign prefix", |c| c.insert(0, json!("env"))),
        ("sudo without -n", |c| c.insert(0, json!("sudo"))),
        ("lab0 instead of eno1", |c| c[2] = json!("lab0")),
    ];
    for (name, change) in bad {
        let d = Scratch::new("failure", Some(tag));
        set_cmd(&d, tag, "eno1", change);
        assert_eq!(d.status(tag), (INVALID.into(), false), "{name}");
    }
    let d = Scratch::new("failure", Some(tag));
    set_cmd(&d, tag, "eno1", |c| {
        c.splice(0..0, [json!("sudo"), json!("-n")]);
    });
    assert_eq!(d.status(tag), (PASS.into(), false));
    // A filter that differs from the one derived from the binding is not accepted
    // even when the recorded command and the recorded filter agree with each other.
    let d = Scratch::new("failure", Some(tag));
    d.edit("runs/stop_silent/capture.json", |v| {
        let n = v["eno1"]["cmd"].as_array().unwrap().len();
        let cmd = v["eno1"]["cmd"].as_array_mut().unwrap();
        cmd.truncate(n - 26);
        cmd.push(json!("'tcp"));
        cmd.push(json!("port"));
        cmd.push(json!("1'"));
        v["eno1"]["filter"] = json!("tcp port 1");
    });
    assert_eq!(d.status(tag), (INVALID.into(), false));
}
// ---- X5: refusal cases must have tested the file they claim ----
const CKPT_VARIANTS: [&str; 8] = [
    "wrong_ports",
    "wrong_seed",
    "corrupt_next_index",
    "corrupt_checksum",
    "truncated",
    "empty",
    "future_format",
    "future_engine",
];
#[test]
fn refusal_used_checkpoint_must_be_the_declared_mutation_of_the_forged_one() {
    for variant in CKPT_VARIANTS {
        let tag = format!("ckpt_{variant}");
        let d = Scratch::new("failure", Some(&tag));
        assert_eq!(d.status(&tag), (PASS.into(), false), "{variant} baseline");
        // The suite used the wrong file: any other byte string than the mutation.
        let used = d.0.join("runs").join(&tag).join("checkpoint-used.bin");
        let mut bytes = fs::read(&used).unwrap();
        bytes.push(0);
        fs::write(&used, bytes).unwrap();
        assert_eq!(
            d.status(&tag),
            (FAIL.into(), true),
            "{variant} used differs"
        );
        // The forged source changed after the mutation was derived.
        let d = Scratch::new("failure", Some(&tag));
        let forged = d.0.join("runs").join(&tag).join("checkpoint-forged.bin");
        let mut bytes = fs::read(&forged).unwrap();
        bytes[20] ^= 1;
        fs::write(&forged, bytes).unwrap();
        // `empty` discards every byte, so the flipped source byte cannot matter there.
        let want = if variant == "empty" {
            (PASS.into(), false)
        } else {
            (FAIL.into(), true)
        };
        assert_eq!(d.status(&tag), want, "{variant} forged source changed");
    }
}
#[test]
fn refusal_with_the_wrong_variants_checkpoint_fails() {
    let d = Scratch::new("failure", Some("ckpt_truncated"));
    let runs = d.0.join("runs");
    // Pretend the suite fed the 'empty' mutation to the 'truncated' case.
    fs::write(runs.join("ckpt_truncated/checkpoint-used.bin"), []).unwrap();
    assert_eq!(d.status("ckpt_truncated"), (FAIL.into(), true));
}
#[test]
fn refusal_without_recorded_checkpoints_is_not_run() {
    for file in ["checkpoint-forged.bin", "checkpoint-used.bin"] {
        let d = Scratch::new("failure", Some("ckpt_wrong_seed"));
        fs::remove_file(d.0.join("runs/ckpt_wrong_seed").join(file)).unwrap();
        assert_eq!(d.status("ckpt_wrong_seed").0, NOT_RUN, "{file}");
    }
}
// ---- X1: from capture schema 3 the invocation nonce chain is mandatory ----
const SCHEMA3_TAG: &str = "stop_silent";
fn chain_case(change: impl FnOnce(&Scratch, &Path)) -> (String, bool) {
    let d = Scratch::new("failure", Some(SCHEMA3_TAG));
    let run = d.0.join("runs").join(SCHEMA3_TAG);
    assert_eq!(
        d.status(SCHEMA3_TAG),
        (PASS.into(), false),
        "schema 3 baseline"
    );
    change(&d, &run);
    d.status(SCHEMA3_TAG)
}
#[test]
fn schema3_requires_the_nonce_and_a_matching_guest_verify() {
    let wanted = (INVALID.to_string(), false);
    assert_eq!(
        chain_case(|d, _| d.edit("runs/stop_silent/meta.json", |v| {
            v.as_object_mut().unwrap().remove("invocation_nonce");
        })),
        wanted,
        "nonce removed"
    );
    assert_eq!(
        chain_case(
            |d, _| d.edit("runs/stop_silent/meta.json", |v| v["invocation_nonce"] =
                json!(""))
        ),
        wanted,
        "nonce empty"
    );
    assert_eq!(
        chain_case(
            |d, _| d.edit("runs/stop_silent/meta.json", |v| v["invocation_nonce"] =
                json!("other"))
        ),
        wanted,
        "meta nonce differs from guest Verify and proof"
    );
    assert_eq!(
        chain_case(|d, _| d.edit("runs/stop_silent/guest-verify.json", |v| {
            v.as_object_mut().unwrap().remove("verification_nonce");
        })),
        wanted,
        "guest Verify without nonce"
    );
}
#[test]
fn schema3_requires_the_hash_proof() {
    let (verdict, behaviour) =
        chain_case(|_, run| fs::remove_file(run.join("run-artifacts.json")).unwrap());
    assert_eq!(
        (verdict.as_str(), behaviour),
        (INVALID, false),
        "proof missing"
    );
    let (verdict, _) = chain_case(|d, _| {
        d.edit("runs/stop_silent/run-artifacts.json", |v| {
            v["invocation_nonce"] = json!("old")
        })
    });
    assert_eq!(verdict, INVALID, "proof of another invocation");
    let (verdict, _) = chain_case(|d, _| {
        d.edit("runs/stop_silent/run-artifacts.json", |v| {
            v["files"].as_object_mut().unwrap().remove("argv.json");
        })
    });
    assert_eq!(verdict, INVALID, "proof does not cover argv");
}
#[test]
fn schema3_records_the_guest_verify_exit_code_and_output() {
    let (verdict, _) = chain_case(|d, _| {
        d.edit("runs/stop_silent/meta.json", |v| {
            v["guest_verify_exit"] = json!(1)
        })
    });
    assert_eq!(verdict, INVALID, "failed Verify");
    let (verdict, _) = chain_case(|d, _| {
        d.edit("runs/stop_silent/meta.json", |v| {
            v.as_object_mut().unwrap().remove("guest_verify_exit");
        })
    });
    assert_eq!(verdict, INVALID, "exit code not recorded");
    for file in ["guest-verify-stdout.txt", "guest-verify-stderr.txt"] {
        let (verdict, _) = chain_case(|_, run| fs::remove_file(run.join(file)).unwrap());
        assert_eq!(verdict, INVALID, "{file} missing");
    }
}
#[test]
fn schema_1_and_2_directories_keep_their_exemption_and_say_so() {
    for schema in [2u64, 1] {
        let p =
            std::env::temp_dir().join(format!("rmasscan-schema-{schema}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fixture::build_failure(&p, schema);
        let v = verify_dir(&p);
        fs::remove_dir_all(&p).unwrap();
        // schema 1 has no end marker; the builder's captures still carry one, which is harmless.
        assert_eq!(v["overall"], PASS, "schema {schema}: {v}");
        let run = array(&v["runs"])
            .iter()
            .find(|r| r["tag"] == "stop_silent")
            .unwrap();
        assert!(
            array(&run["checks"]).iter().any(|c| c["name"]
                == format!("historical schema {schema}: invocation nonce chain not required")
                && c["result"] == PASS
                && s(&c["detail"]).contains("schema 3")),
            "exemption must be stated in the verdict: {run}"
        );
    }
}
#[test]
fn guest_verify_nonce_is_checked_even_when_the_hash_proof_is_consistent() {
    // Only the nonce binding can object: the proof is re-sealed over the altered report.
    let d = Scratch::new("failure", Some(SCHEMA3_TAG));
    d.edit_sealed("runs/stop_silent/guest-verify.json", |v| {
        v["verification_nonce"] = json!("another-invocation")
    });
    assert_eq!(d.status(SCHEMA3_TAG), (INVALID.into(), false));
    let d = Scratch::new("failure", Some(SCHEMA3_TAG));
    d.edit_sealed("runs/stop_silent/guest-verify.json", |v| {
        v.as_object_mut().unwrap().remove("verification_nonce");
    });
    assert_eq!(d.status(SCHEMA3_TAG), (INVALID.into(), false));
}

// ---- F2: port of the remaining verifier tests of the retired script harness ----
fn verdict_of(v: &Value, tag: &str) -> String {
    array(&v["runs"])
        .iter()
        .find(|r| r["tag"] == tag)
        .unwrap_or_else(|| panic!("no run {tag}"))["verdict"]
        .as_str()
        .unwrap()
        .to_string()
}
fn group_of(v: &Value, tag: &str) -> String {
    array(&v["groups"])
        .iter()
        .find(|g| g["tag"] == tag)
        .unwrap_or_else(|| panic!("no group {tag}"))["verdict"]
        .as_str()
        .unwrap()
        .to_string()
}
fn first_scanner_syn_time(d: &Scratch, tag: &str) -> f64 {
    let (_, fr) =
        pcap::read_pcap_records(&fs::read(d.0.join("runs").join(tag).join("peer.pcap")).unwrap())
            .unwrap();
    fr.iter().find(|(_, f)| pcap::is_syn(f)).unwrap().0
}
/// An ARP-looking frame (no TCP) between the lab MACs, `from` -> `to`.
fn lab_frame(to: &str, from: &str) -> Vec<u8> {
    let mac = |s: &str| -> Vec<u8> {
        s.split(':')
            .map(|p| u8::from_str_radix(p, 16).unwrap())
            .collect()
    };
    let mut b = mac(to);
    b.extend(mac(from));
    b.extend([8, 6]);
    b.extend([0u8; 28]);
    b
}
const X01: &str = "x01_foreign_replies.run1";
fn add_frame_at(d: &Scratch, tag: &str, offset: f64, frame: Vec<u8>) {
    let at = first_scanner_syn_time(d, tag) + offset;
    rewrite_pcap(d, tag, "peer", |fr| {
        fr.push((at, frame));
        fr.sort_by(|a, b| a.0.total_cmp(&b.0));
    });
}
fn with_discarded(d: &Scratch, tag: &str, delta: i64) {
    d.edit_sealed(&format!("runs/{tag}/run.json"), |v| {
        let now = v["discarded"].as_i64().unwrap();
        v["discarded"] = json!(now + delta);
    });
}
#[test]
fn missing_fixture_manifest_and_planned_runs_are_not_run() {
    let d = Scratch::new("functional", None);
    fs::remove_file(d.0.join("fixtures/manifest.json")).unwrap();
    assert_eq!(verify_dir(&d.0)["overall"], NOT_RUN);

    let d = Scratch::new("functional", None);
    fs::remove_dir_all(d.0.join("runs/pause_N8")).unwrap();
    let v = verify_dir(&d.0);
    assert_eq!(verdict_of(&v, "pause_N8"), NOT_RUN);
    assert_eq!(group_of(&v, "group_pause_resume_N8"), NOT_RUN);
    assert_ne!(v["overall"], PASS);
    // The other groups are not dragged down by the missing leg.
    assert_eq!(group_of(&v, "group_pause_resume_N1"), PASS);
}
#[test]
fn missing_part_b_run_is_not_run() {
    let d = Scratch::new("failure", None);
    fs::remove_dir_all(d.0.join("runs/linkloss")).unwrap();
    let v = verify_dir(&d.0);
    assert_eq!(verdict_of(&v, "linkloss"), NOT_RUN);
    assert_ne!(v["overall"], PASS);
}
#[test]
fn missing_continuous_or_leg_pcap_makes_groups_not_run_without_crashing() {
    let d = Scratch::new("functional", None);
    fs::remove_file(d.0.join("runs/c03_multi_ports.run1/peer.pcap")).unwrap();
    let v = verify_dir(&d.0);
    let verdicts: BTreeSet<_> = array(&v["groups"])
        .iter()
        .map(|g| g["verdict"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(verdicts, BTreeSet::from([NOT_RUN.to_string()]));
    assert_ne!(v["overall"], PASS);

    let d = Scratch::new("functional", None);
    fs::remove_file(d.0.join("runs/pause_N8/peer.pcap")).unwrap();
    let v = verify_dir(&d.0);
    assert_eq!(group_of(&v, "group_pause_resume_N8"), NOT_RUN);
    assert_eq!(group_of(&v, "group_pause_resume_N0"), PASS);
}
#[test]
fn foreign_reply_accepted_as_result_is_fail() {
    let d = Scratch::new("functional", None);
    d.edit_sealed(&format!("runs/{X01}/run.json"), |v| {
        let a = v["replies"].as_array_mut().unwrap();
        a.push(json!("198.18.0.2:8099:open"));
        a.sort_by_key(|x| x.to_string());
    });
    assert_eq!(d.status(X01), (FAIL.into(), true));
}
#[test]
fn foreign_frames_missing_from_the_wire_are_invalid_and_a_missing_injector_log_is_not_run() {
    let d = Scratch::new("functional", None);
    d.edit(&format!("runs/{X01}/injector.json"), |v| {
        v["sent_total"] = json!(v["sent_total"].as_i64().unwrap() + 9)
    });
    assert_eq!(d.status(X01).0, INVALID);

    let d = Scratch::new("functional", None);
    fs::remove_file(d.0.join(format!("runs/{X01}/injector.json"))).unwrap();
    assert_eq!(d.status(X01), (NOT_RUN.into(), false));
}
#[test]
fn foreign_frames_must_each_be_discarded_and_duplicates_are_genuine_retransmits_only() {
    let injected = {
        let d = Scratch::new("functional", None);
        read_json(d.0.join(format!("runs/{X01}/injector.json"))).unwrap()["sent_total"]
            .as_i64()
            .unwrap()
    };
    // Fewer discards than injected frames, more than explained, or an unmeasured
    // count: each is a behaviour failure on this run (its capture is proven).
    for value in [json!(injected - 1), json!(injected + 1), Value::Null] {
        let d = Scratch::new("functional", None);
        d.edit_sealed(&format!("runs/{X01}/run.json"), |v| {
            v["discarded"] = value.clone()
        });
        assert_eq!(d.status(X01), (FAIL.into(), true), "discarded {value}");
    }
    let tag = "x01_foreign_replies.run2";
    let d = Scratch::new("functional", None);
    d.edit_sealed(&format!("runs/{tag}/run.json"), |v| {
        v["duplicates"] = json!(9)
    });
    assert_eq!(d.status(tag).0, FAIL);
}
#[test]
fn pause_resume_group_failures() {
    // A resume that repeats a probe the pause leg already sent.
    let d = Scratch::new("functional", None);
    let (_, fr) =
        pcap::read_pcap_records(&fs::read(d.0.join("runs/resume_N8/peer.pcap")).unwrap()).unwrap();
    let again = fr.iter().find(|(_, f)| pcap::is_syn(f)).unwrap().clone();
    rewrite_pcap(&d, "resume_N8", "peer", |fr| {
        fr.push((again.0 + 0.5, again.1.clone()));
        fr.sort_by(|a, b| a.0.total_cmp(&b.0));
    });
    let v = verify_dir(&d.0);
    assert_ne!(group_of(&v, "group_pause_resume_N8"), PASS);
    // A pause leg that completed instead of pausing.
    let d = Scratch::new("functional", None);
    d.edit_sealed("runs/pause_N15/run.json", |v| {
        v["reason"] = json!("Completed")
    });
    assert_eq!(d.status("pause_N15"), (FAIL.into(), true));
    assert_ne!(group_of(&verify_dir(&d.0), "group_pause_resume_N15"), PASS);
    // Identity rules are separate failures.
    for (field, value) in [
        ("attempt_id", json!("aa".repeat(16))),
        ("scan_id", json!("22".repeat(16))),
    ] {
        let d = Scratch::new("functional", None);
        let was = read_json(d.0.join("runs/pause_N1/run.json")).unwrap()["attempt_id"].clone();
        let value = if field == "attempt_id" { was } else { value };
        d.edit_sealed("runs/resume_N1/run.json", |v| v[field] = value.clone());
        assert_eq!(
            group_of(&verify_dir(&d.0), "group_pause_resume_N1"),
            FAIL,
            "{field}"
        );
    }
}
#[test]
fn a_resumed_completed_job_and_a_syn_during_a_refusal_are_failures() {
    let d = Scratch::new("functional", None);
    d.edit_sealed("runs/refuse_completed/run.json", |v| {
        v["status"] = json!("ok");
        v["opened_adapter"] = json!(true);
    });
    assert_eq!(d.status("refuse_completed"), (FAIL.into(), true));

    let d = Scratch::new("functional", None);
    let (_, fr) = pcap::read_pcap_records(
        &fs::read(d.0.join("runs/c03_multi_ports.run1/peer.pcap")).unwrap(),
    )
    .unwrap();
    let syn = fr.into_iter().find(|(_, f)| pcap::is_syn(f)).unwrap();
    rewrite_pcap(&d, "refuse_completed", "peer", |fr| {
        let t = fr.iter().map(|x| x.0).fold(0., f64::max);
        fr.push((t - 1.0, syn.1));
        fr.sort_by(|a, b| a.0.total_cmp(&b.0));
    });
    assert_eq!(d.status("refuse_completed"), (FAIL.into(), true));
}
#[test]
fn a_schema2_run_in_a_schema1_directory_cannot_skip_the_end_marker() {
    let strip = |d: &Scratch| {
        rewrite_pcap(d, "stop_silent", "peer", |fr| {
            fr.retain(|(_, f)| f.get(14..25) != Some(b"WIRELAB-END".as_slice()))
        })
    };
    // Control: a directory that predates the end marker does not need it.
    let d = Scratch::new("failure", Some("stop_silent"));
    d.edit("manifest.json", |v| {
        v["capture_schema"] = json!(1);
    });
    d.edit("runs/stop_silent/capture.json", |v| {
        v.as_object_mut().unwrap().remove("capture_schema");
    });
    strip(&d);
    d.edit("runs/stop_silent/meta.json", |v| {
        v["end_marker_seen"] = json!(false);
        v.as_object_mut().unwrap().remove("invocation_nonce");
        v.as_object_mut().unwrap().remove("guest_verify_exit");
    });
    assert_eq!(d.status("stop_silent").0, PASS);
    // The attack: the run claims schema 2 but the directory manifest drops its schema.
    d.edit("runs/stop_silent/capture.json", |v| {
        v["capture_schema"] = json!(2)
    });
    assert_eq!(d.status("stop_silent"), (INVALID.into(), false));
    // And a run older than its directory is invalid too.
    let d = Scratch::new("failure", Some("stop_silent"));
    d.edit("runs/stop_silent/capture.json", |v| {
        v.as_object_mut().unwrap().remove("capture_schema");
    });
    assert_eq!(d.status("stop_silent").0, INVALID);
}
#[test]
fn a_discarded_invalid_run_with_an_accepted_foreign_result_is_overall_fail() {
    let d = Scratch::new("functional", None);
    copy_tree(
        &d.0.join("runs").join(X01),
        &d.0.join("runs_discarded/x01_foreign_replies.run1.5"),
    );
    d.edit(
        "runs_discarded/x01_foreign_replies.run1.5/capture.json",
        |v| v["quiet"]["reached"] = json!(false),
    );
    d.edit_sealed("runs_discarded/x01_foreign_replies.run1.5/run.json", |v| {
        v["replies"]
            .as_array_mut()
            .unwrap()
            .push(json!("198.18.0.2:8099:open"))
    });
    let v = verify_dir(&d.0);
    let mine = array(&v["discarded"])
        .iter()
        .find(|r| r["tag"] == "x01_foreign_replies.run1.5")
        .unwrap();
    assert_eq!(mine["verdict"], INVALID);
    assert_eq!(mine["behaviour_fail"], true);
    assert_eq!(v["overall"], FAIL);
}
#[test]
fn pause_after_must_match_n() {
    let d = Scratch::new("functional", None);
    d.edit("runs/pause_N8/argv.json", |v| {
        let a = v["argv"].as_array_mut().unwrap();
        let i = a.iter().position(|x| x == "--pause-after").unwrap();
        a[i + 1] = json!("7");
    });
    assert_eq!(d.status("pause_N8"), (INVALID.into(), false));
}
#[test]
fn strays_in_the_receive_window_are_counted_and_required() {
    let lab = |to: &str, from: &str| lab_frame(to, from);
    let sm = fixture::SM;
    let pm = fixture::PM;
    // Unicast to the guest from the peer inside the window.
    let d = Scratch::new("functional", None);
    add_frame_at(&d, X01, 0.5, lab(sm, pm));
    assert_eq!(d.status(X01), (FAIL.into(), true));
    with_discarded(&d, X01, 1);
    assert_eq!(d.status(X01), (PASS.into(), false));
    let v = verify_dir(&d.0);
    let r = array(&v["runs"]).iter().find(|r| r["tag"] == X01).unwrap();
    let base = Scratch::new("functional", None);
    let injected =
        read_json(base.0.join(format!("runs/{X01}/injector.json"))).unwrap()["sent_total"]
            .as_i64()
            .unwrap();
    assert_eq!(r["notes"]["strays_in_rx_window"], 1);
    assert_eq!(r["notes"]["injected"], injected);
    // A broadcast from the peer counts as well.
    let d = Scratch::new("functional", None);
    add_frame_at(&d, X01, 0.5, lab("ff:ff:ff:ff:ff:ff", pm));
    assert_eq!(d.status(X01), (FAIL.into(), true));
    with_discarded(&d, X01, 1);
    assert_eq!(d.status(X01), (PASS.into(), false));
    // A frame sent by the guest never does.
    let d = Scratch::new("functional", None);
    add_frame_at(&d, X01, 0.5, lab("ff:ff:ff:ff:ff:ff", sm));
    assert_eq!(d.status(X01), (PASS.into(), false));
    // Before the first SYN is outside the receive window.
    let d = Scratch::new("functional", None);
    add_frame_at(&d, X01, -0.5, lab(sm, pm));
    assert_eq!(d.status(X01), (PASS.into(), false));
}
#[test]
fn cases_psv_lists_six_classes_plus_the_foreign_case() {
    let psv = cases_psv();
    let lines: Vec<_> = psv.lines().collect();
    assert_eq!(lines.len(), 7);
    assert!(lines.iter().all(|l| l.split('|').count() == 5), "{psv}");
    let names: Vec<_> = lines.iter().map(|l| l.split('|').next().unwrap()).collect();
    assert_eq!(
        &names[..6],
        [
            "c01_one_addr_port_synack",
            "c02_one_addr_port_rst",
            "c03_multi_ports",
            "c04_exclude",
            "c05_srcport_single",
            "c06_srcport_range"
        ]
    );
    assert!(names[6].starts_with("x01"));
}

// ---- F2: part B tests ----
#[test]
fn the_wire_syn_count_must_equal_tx_sent() {
    let d = Scratch::new("failure", Some("stop_silent"));
    d.edit_sealed("runs/stop_silent/run.json", |v| {
        for k in ["sent", "tx_sent_at_join", "tx_sent_after_observe"] {
            v[k] = json!(5);
        }
        v["net"]["tx_sent"] = json!(5);
    });
    assert_eq!(d.status("stop_silent"), (FAIL.into(), true));
}
#[test]
fn the_clock_offset_is_recorded_from_the_wire_not_assumed() {
    let d = Scratch::new("failure", Some("stop_silent"));
    // Guest clock 50 s behind the peer: both wall stamps shift together.
    d.edit_sealed("runs/stop_silent/run.json", |v| {
        for k in ["t0_utc_ms", "outcome_utc_ms"] {
            v["wall"][k] = json!(v["wall"][k].as_f64().unwrap() - 50_000.);
        }
    });
    let v = verify_dir(&d.0);
    let r = array(&v["runs"])
        .iter()
        .find(|r| r["tag"] == "stop_silent")
        .unwrap();
    let off = r["notes"]["clock_offset_ms"].as_f64().unwrap();
    assert!((off - 50_000.).abs() < 5., "{off}");
    assert_eq!(r["notes"]["syn_after_outcome"], 0);
    assert!(
        r["notes"]["alignment"]
            .as_str()
            .unwrap()
            .contains("peer first SYN")
    );
    assert_eq!(r["verdict"], PASS);
}
#[test]
fn stop_load_needs_the_flood_on_the_wire() {
    let d = Scratch::new("failure", Some("stop_load"));
    fs::remove_file(d.0.join("runs/stop_load/flood.json")).unwrap();
    assert_eq!(d.status("stop_load"), (NOT_RUN.into(), false));
    // The flood log is not enough: its frames must be in the capture.
    let d = Scratch::new("failure", Some("stop_load"));
    rewrite_pcap(&d, "stop_load", "peer", |fr| {
        fr.retain(|(_, f)| !ether(f, [0x88, 0xb6]))
    });
    assert_eq!(d.status("stop_load").0, INVALID);
}
#[test]
fn linkloss_without_events_is_not_run_and_without_proof_is_invalid() {
    let d = Scratch::new("failure", Some("linkloss"));
    fs::remove_file(d.0.join("runs/linkloss/linkloss.json")).unwrap();
    assert_eq!(d.status("linkloss"), (NOT_RUN.into(), false));
    let d = Scratch::new("failure", Some("linkloss"));
    d.edit("runs/linkloss/linkloss.json", |v| {
        v["first_syn_seen"] = json!(false)
    });
    assert_eq!(d.status("linkloss"), (INVALID.into(), false));
    let d = Scratch::new("failure", Some("linkloss"));
    d.edit("runs/linkloss/linkloss.json", |v| v["events"] = json!([]));
    assert_eq!(d.status("linkloss").0, INVALID);
}
#[test]
fn a_checkpoint_refusal_with_a_scanner_syn_on_the_wire_is_a_failure() {
    let d = Scratch::new("failure", Some("ckpt_empty"));
    let stop = Scratch::new("failure", Some("stop_silent"));
    let (_, fr) =
        pcap::read_pcap_records(&fs::read(stop.0.join("runs/stop_silent/peer.pcap")).unwrap())
            .unwrap();
    let syn = fr.into_iter().find(|(_, f)| pcap::is_syn(f)).unwrap();
    rewrite_pcap(&d, "ckpt_empty", "peer", |fr| {
        let t = fr.iter().map(|x| x.0).fold(f64::MAX, f64::min) + 1.0;
        fr.push((t, syn.1));
        fr.sort_by(|a, b| a.0.total_cmp(&b.0));
    });
    assert_eq!(d.status("ckpt_empty"), (FAIL.into(), true));
}
#[test]
fn the_wrong_ports_checkpoint_variant_needs_its_matching_argv() {
    let d = Scratch::new("failure", Some("ckpt_wrong_ports"));
    d.edit("runs/ckpt_wrong_ports/argv.json", |v| {
        let a = v["argv"].as_array_mut().unwrap();
        let i = a.iter().position(|x| x == "--ports").unwrap();
        a[i + 1] = json!("8000-8015");
    });
    assert_eq!(d.status("ckpt_wrong_ports"), (INVALID.into(), false));
}
#[test]
fn restricted_scan_refusals_accepted_are_only_the_documented_ones() {
    let tag = "perm_restricted_scan";
    // InterfaceMismatch is documented for exit code 2 only.
    let d = Scratch::new("failure", Some(tag));
    d.edit_sealed(&format!("runs/{tag}/run.json"), |v| {
        v["error"] = json!("InterfaceMismatch(\"no Npcap device\")")
    });
    assert_eq!(d.status(tag), (FAIL.into(), true));
    d.edit(&format!("runs/{tag}/meta.json"), |v| {
        v["guest_exit"] = json!(2)
    });
    assert_eq!(d.status(tag), (PASS.into(), false));
    // PermissionDenied is documented for exit code 5 only, and nothing else is.
    d.edit_sealed(&format!("runs/{tag}/run.json"), |v| {
        v["error"] = json!("PermissionDenied(\"x\")")
    });
    assert_eq!(d.status(tag), (FAIL.into(), true));
    let d = Scratch::new("failure", Some(tag));
    d.edit_sealed(&format!("runs/{tag}/run.json"), |v| {
        v["error"] = json!("SomethingElse(\"x\")")
    });
    assert_eq!(d.status(tag), (FAIL.into(), true));
}
#[test]
fn the_rxloss_independent_count_is_recorded_and_bounds_the_drops() {
    let d = Scratch::new("failure", None);
    let v = verify_dir(&d.0);
    let r = array(&v["runs"])
        .iter()
        .find(|r| r["tag"] == "rxloss")
        .unwrap();
    let ind = &r["notes"]["independent_count"];
    // The synthetic NIC moved 1000 -> 6000 unicast with 6 constant broadcasts.
    assert_eq!(ind["kernel_drops_n"], 7);
    assert_eq!(ind["nic_rx_delta"], 5000);
    assert_eq!(ind["rx_read_by_handle"], 100);
    assert_eq!(ind["nic_minus_read"], 4900);
    assert_eq!(ind["peer_flood_sent"], 12);
    // Drops beyond what the NIC counted (after drops + reads must fit in the delta).
    let d = Scratch::new("failure", Some("rxloss"));
    d.edit("runs/rxloss/nic.json", |v| {
        v["after"]["stats"]["ReceivedUnicastPackets"] = json!(1050)
    });
    assert_eq!(d.status("rxloss"), (FAIL.into(), true));
    // Drops beyond the peer flood, with the flood log still matching the capture.
    let d = Scratch::new("failure", Some("rxloss"));
    let mut seen = 0;
    rewrite_pcap(&d, "rxloss", "peer", |fr| {
        fr.retain(|(_, f)| {
            if ether(f, [0x88, 0xb6]) {
                seen += 1;
                seen <= 3
            } else {
                true
            }
        })
    });
    d.edit("runs/rxloss/flood.json", |v| v["sent"] = json!(3));
    assert_eq!(d.status("rxloss"), (FAIL.into(), true));
    // Unreadable NIC counters cannot prove anything.
    let d = Scratch::new("failure", Some("rxloss"));
    d.edit("runs/rxloss/nic.json", |v| {
        v["before"] = json!({"error":"Access denied"});
        v["after"] = json!({"error":"Access denied"});
    });
    assert_eq!(d.status("rxloss").0, NOT_RUN);
}
#[test]
fn a_wrong_stop_argument_is_a_harness_error_that_may_be_rerun() {
    let d = Scratch::new("failure", Some("stop_silent"));
    d.edit("runs/stop_silent/argv.json", |v| {
        let a = v["argv"].as_array_mut().unwrap();
        let i = a.iter().position(|x| x == "--stop-after-ms").unwrap();
        a[i + 1] = json!("2000");
    });
    d.edit_sealed("runs/stop_silent/run.json", |v| {
        v["timing"]["stop_to_outcome_ms"] = json!(5000.)
    });
    let (verdict, behaviour) = d.status("stop_silent");
    assert_eq!((verdict.as_str(), behaviour), (INVALID, false));
    assert!(crate::windows_suite::may_discard(&verdict, behaviour));
    // An unexpected extra flag is a harness error as well.
    let d = Scratch::new("failure", Some("rxloss"));
    d.edit("runs/rxloss/argv.json", |v| {
        v["argv"]
            .as_array_mut()
            .unwrap()
            .push(json!("--allow-foreign-source-mac"))
    });
    assert_eq!(d.status("rxloss").0, INVALID);
}

// ---- F5 (WR N3, M1): rules that other checks used to mask ----

/// Names of the checks that did not pass for one run directory.
fn failed_checks(d: &Scratch, tag: &str) -> Vec<String> {
    let man = read_json(d.0.join("manifest.json")).unwrap();
    let it = planned(&man).into_iter().find(|i| i["tag"] == tag).unwrap();
    let fx = read_json(d.0.join("fixtures/manifest.json")).unwrap_or(Value::Null);
    let (r, _) = verify_item(&d.0, &man, &fx, &it, None);
    r.checks
        .iter()
        .filter(|c| c["result"] != PASS)
        .map(|c| c["name"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn the_requested_scan_and_attempt_id_is_checked_in_each_leg_on_its_own() {
    // Replacing one leg's id alone (so no cross-leg or checkpoint comparison can notice) must still
    // trip the rule that compares run.json with the requested argv.
    for tag in ["pause_N8", "resume_N8"] {
        for field in ["scan_id", "attempt_id"] {
            let d = Scratch::new("functional", Some(tag));
            d.edit_run(tag, &format!("/{field}"), json!("cc".repeat(16)));
            let failed = failed_checks(&d, tag);
            let want = format!("{field} matches requested argv");
            assert!(failed.contains(&want), "{tag} {field}: {failed:?}");
        }
    }
}

#[test]
fn linkloss_must_have_at_least_one_uncertain_tx() {
    let d = Scratch::new("failure", Some("linkloss"));
    d.edit_run("linkloss", "/net/tx_uncertain", json!(0));
    let failed = failed_checks(&d, "linkloss");
    assert!(
        failed.contains(&"NIC disconnect fails TxUncertain, partial scan, no checkpoint".into()),
        "{failed:?}"
    );
}

#[test]
fn the_checkpoint_magic_version_and_trailer_are_each_checked_on_their_own() {
    // WR M1: tamper the exported file AND keep run.json's checkpoint_hex in step, so the byte
    // comparison cannot be what reacts; only the format/checksum rule is left to notice.
    for pos in [0usize, 7, 8, 11, 12, 15, 88, 119] {
        let d = Scratch::new("functional", Some("pause_N8"));
        let p = d.0.join("runs/pause_N8/checkpoint.bin");
        let mut bytes = fs::read(&p).unwrap();
        bytes[pos] ^= 1;
        if pos < 88 {
            let sum = Sha256::digest(&bytes[..88]);
            bytes[88..].copy_from_slice(&sum);
        }
        fs::write(&p, &bytes).unwrap();
        d.edit_run("pause_N8", "/checkpoint_hex", json!(hex(&bytes)));
        let failed = failed_checks(&d, "pause_N8");
        assert!(
            failed.contains(&"exported checkpoint format and checksum valid".into()),
            "position {pos}: {failed:?}"
        );
        assert_eq!(d.status("pause_N8"), (FAIL.into(), true), "position {pos}");
    }
}
