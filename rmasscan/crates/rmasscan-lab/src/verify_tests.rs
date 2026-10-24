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
    fn edit_run(&self, tag: &str, path: &str, value: Value) {
        self.edit(&format!("runs/{tag}/run.json"), |v| {
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
    d.edit(&format!("runs/{tag}/{file}"), |v| {
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
    let v = verify_dir(&evidence("failure"));
    assert_eq!(v["overall"], PASS, "{v}");
    assert_eq!(v["totals"][PASS], 19);
}
#[test]
fn malformed_exported_checkpoints_never_pass() {
    for bytes in [vec![], vec![0; 120], vec![1; 60]] {
        let d = Scratch::new("functional", Some("pause_N8"));
        fs::write(d.0.join("runs/pause_N8/checkpoint.bin"), bytes).unwrap();
        assert_eq!(d.status("pause_N8").0, INVALID);
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
        assert_eq!(d.status("pause_N8").0, INVALID, "position {pos}");
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
            INVALID,
            false,
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
    d.edit("runs/stop_silent/run.json", |v| {
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
            json!("RxLoss { kernel_drops: 7 }"),
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
        d.edit("runs/stop_silent/run.json", |v| {
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
