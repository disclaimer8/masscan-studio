use rmasscan_lab::capture::classify;
#[test]
fn a_queued_outgoing_tail_missing_from_the_pcap_does_not_pass_as_complete_capture() {
    // The interface counted 3 frames (window 3..3) but the pcap holds 2 and tcpdump retired 2:
    // the last frame was queued and never written.
    let facts = rmasscan_lab::dump::Facts {
        start_markers: 1,
        end_markers: 3,
        quiesced: true,
        captured: Some(2),
        received: Some(2),
        dropped_kernel: Some(0),
        dropped_if: Some(0),
        interface_drop_delta: Some(0),
        pcap_frames: 2,
        pcap_error: None,
        tcpdump_exited: true,
        window_lo: Some(3),
        window_hi: Some(3),
    };
    assert!(!rmasscan_lab::dump::problems(&facts).is_empty());
}

#[test]
fn isolation_refuses_an_extra_link_or_default_route() {
    use serde_json::json;
    let links = json!([{"ifname":"lo"},{"ifname":"veth-a","linkinfo":{"info_kind":"veth"}}]);
    assert!(rmasscan_lab::capture::check_isolation_snapshot(&links, &json!([]), "0").is_ok());
    assert!(
        rmasscan_lab::capture::check_isolation_snapshot(&links, &json!([{"dst":"default"}]), "0")
            .is_err()
    );
    assert!(rmasscan_lab::capture::check_isolation_snapshot(&links, &json!([]), "1").is_err());
}
#[test]
fn truncated_ipv4_options_are_classified_without_indexing_past_end() {
    let mut frame = vec![0u8; 54];
    frame[12..14].copy_from_slice(&[8, 0]);
    frame[14] = 0x4f;
    frame[23] = 6;
    let result = classify(&[(0., frame)], [1; 6], [2; 6]);
    assert_eq!(result["other"], 1);
}

// ---- re-verification of the committed golden fixtures (no network, no root) ----

use serde_json::{Value, json};
use std::{fs, path::PathBuf};

fn golden() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/wire")
}
fn golden_manifest() -> Value {
    serde_json::from_slice(&fs::read(golden().join("manifest.json")).expect("committed manifest"))
        .unwrap()
}

/// Every case of the committed manifest: run1 vs run2 through the comparator with the capture
/// metas recorded in the manifest gives exactly the recorded verdict string.
#[test]
fn committed_golden_fixtures_reverify_to_the_recorded_verdicts() {
    let m = golden_manifest();
    let cases = m["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let r1 = fs::read(golden().join(format!("{name}.run1.pcap"))).unwrap();
        let r2 = fs::read(golden().join(format!("{name}.run2.pcap"))).unwrap();
        let metas = [
            c["runs"][0]["capture"].clone(),
            c["runs"][1]["capture"].clone(),
        ];
        let (code, detail) =
            rmasscan_lab::pcap::compare_bytes(&r1, &[&r2], Some(&metas[0]), &metas[1..]);
        assert_eq!(code, 0, "{name}: {detail}");
        assert_eq!(c["repeat_compare"]["result"], "PASS");
        assert_eq!(c["repeat_compare"]["detail"], detail, "{name}");
    }
}

/// `capture manifest` rebuilds the committed manifest's cases from the committed inputs.
#[test]
fn capture_manifest_reproduces_the_committed_golden_cases() {
    let m = golden_manifest();
    let dir =
        std::env::temp_dir().join(format!("rmasscan-golden-remanifest-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut tsv = String::new();
    for c in m["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        for f in [
            format!("{name}.echo"),
            format!("{name}.run1.pcap"),
            format!("{name}.run2.pcap"),
        ] {
            fs::copy(golden().join(&f), dir.join(&f)).unwrap();
        }
        for (i, run) in c["runs"].as_array().unwrap().iter().enumerate() {
            fs::write(
                dir.join(format!("{name}.run{}.capture.json", i + 1)),
                serde_json::to_vec(&run["capture"]).unwrap(),
            )
            .unwrap();
        }
        let args: Vec<&str> = c["masscan_args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        tsv += &format!(
            "{name}\t{}\t{}\t{}\t{}\n",
            c["expected"]["syn"],
            c["expected"]["synack"],
            c["expected"]["rst"],
            args.join(" ")
        );
    }
    fs::write(dir.join("cases.tsv"), tsv).unwrap();
    let mut env = json!({});
    for k in [
        "oracle",
        "harness",
        "host",
        "masscan_conf",
        "namespaces",
        "binding",
        "created_utc",
    ] {
        env[k] = m[k].clone();
    }
    fs::write(dir.join("env.json"), serde_json::to_vec(&env).unwrap()).unwrap();
    fs::write(
        dir.join("isolation.json"),
        serde_json::to_vec(&m["isolation"]).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.join("commands.txt"),
        m["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| format!("{}\n", c.as_str().unwrap()))
            .collect::<String>(),
    )
    .unwrap();

    let rc = rmasscan_lab::capture::run(&[
        "manifest".into(),
        "--dir".into(),
        dir.to_string_lossy().into_owned(),
    ])
    .unwrap();
    assert_eq!(rc, 0, "all_valid on the committed inputs");
    let rebuilt: Value =
        serde_json::from_slice(&fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(rebuilt["all_valid"], true);
    assert_eq!(
        rebuilt["cases"], m["cases"],
        "cases: counts, hashes, validity, verdicts"
    );
    for k in ["binding", "isolation", "oracle", "namespaces", "commands"] {
        assert_eq!(rebuilt[k], m[k], "{k}");
    }
    let _ = fs::remove_dir_all(dir);
}

/// A run whose capture meta says INVALID, or whose counts differ from the case table, makes the
/// rebuilt manifest not all_valid (exit 3): INVALID is never normalised into the fixtures.
#[test]
fn a_tampered_capture_meta_or_count_makes_the_manifest_invalid() {
    let m = golden_manifest();
    let c = &m["cases"].as_array().unwrap()[0];
    let name = c["name"].as_str().unwrap();
    for tamper in ["meta", "count"] {
        let dir = std::env::temp_dir().join(format!(
            "rmasscan-golden-tamper-{tamper}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for f in [
            format!("{name}.echo"),
            format!("{name}.run1.pcap"),
            format!("{name}.run2.pcap"),
        ] {
            fs::copy(golden().join(&f), dir.join(&f)).unwrap();
        }
        for (i, run) in c["runs"].as_array().unwrap().iter().enumerate() {
            let mut meta = run["capture"].clone();
            if tamper == "meta" && i == 1 {
                meta["valid"] = json!(false);
            }
            fs::write(
                dir.join(format!("{name}.run{}.capture.json", i + 1)),
                serde_json::to_vec(&meta).unwrap(),
            )
            .unwrap();
        }
        let syn = c["expected"]["syn"].as_u64().unwrap() + u64::from(tamper == "count");
        fs::write(
            dir.join("cases.tsv"),
            format!(
                "{name}\t{syn}\t{}\t{}\t10.200.0.2 -p80\n",
                c["expected"]["synack"], c["expected"]["rst"]
            ),
        )
        .unwrap();
        let mut env = json!({});
        for k in [
            "oracle",
            "harness",
            "host",
            "masscan_conf",
            "namespaces",
            "binding",
            "created_utc",
        ] {
            env[k] = m[k].clone();
        }
        fs::write(dir.join("env.json"), serde_json::to_vec(&env).unwrap()).unwrap();
        fs::write(
            dir.join("isolation.json"),
            serde_json::to_vec(&m["isolation"]).unwrap(),
        )
        .unwrap();
        fs::write(dir.join("commands.txt"), "").unwrap();
        let rc = rmasscan_lab::capture::run(&[
            "manifest".into(),
            "--dir".into(),
            dir.to_string_lossy().into_owned(),
        ])
        .unwrap();
        assert_eq!(rc, 3, "{tamper}");
        let _ = fs::remove_dir_all(dir);
    }
}
