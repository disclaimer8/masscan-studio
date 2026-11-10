use rmasscan_lab::capture::{IsolationMode, Side, classify};
#[test]
fn a_queued_outgoing_tail_missing_from_the_pcap_does_not_pass_as_complete_capture() {
    // The interface counted 3 frames (window 3..3) but the pcap holds 2 and tcpdump retired 2:
    // the last frame was queued and never written.
    let facts = rmasscan_lab::dump::Facts {
        received_is_prefilter: false,
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
    assert!(
        rmasscan_lab::capture::check_isolation_snapshot(
            &links,
            &json!([]),
            "0",
            IsolationMode::Default,
            Side::Scanner
        )
        .is_ok()
    );
    assert!(
        rmasscan_lab::capture::check_isolation_snapshot(
            &links,
            &json!([{"dst":"default"}]),
            "0",
            IsolationMode::Default,
            Side::Scanner
        )
        .is_err()
    );
    assert!(
        rmasscan_lab::capture::check_isolation_snapshot(
            &links,
            &json!([]),
            "1",
            IsolationMode::Default,
            Side::Scanner
        )
        .is_err()
    );
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
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../tests/golden/wire")
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

#[test]
fn legacy_mode_is_byte_identical() {
    use rmasscan_lab::capture::check_isolation_snapshot as check;
    use serde_json::json;
    let veth = json!({"ifname":"veth-a","linkinfo":{"info_kind":"veth"},"master":null});
    let links = json!([{"ifname":"lo"}, veth]);
    let snap = |l: &Value, r: Value, f: &str| {
        format!(
            "{:?}",
            check(l, &r, f, IsolationMode::Default, Side::Scanner)
        )
    };
    let rows = [
        snap(&links, json!([]), "0"),
        snap(
            &links,
            json!([{"dst":"198.18.0.0/24","dev":"veth-a"}]),
            "0\n",
        ),
        snap(&links, json!([{"dst":"default"}]), "0"),
        snap(&links, json!([{"dst":"x","gateway":"198.18.0.2"}]), "0"),
        snap(&links, json!([{"dst":"a"},{"dst":"b"}]), "0"),
        snap(&links, json!([]), "1"),
        snap(&json!([{"ifname":"lo"}]), json!([]), "0"),
        snap(&json!("x"), json!([]), "0"),
        snap(&links, json!("x"), "0"),
        snap(
            &json!([{"ifname":"lo"},{"ifname":"v","linkinfo":{"info_kind":"bridge"}}]),
            json!([]),
            "0",
        ),
        snap(
            &json!([{"ifname":"lo"},{"ifname":"v","linkinfo":{"info_kind":"veth"},"master":"br0"}]),
            json!([]),
            "0",
        ),
    ];
    assert_eq!(
        rows.join("\n"),
        [
            "Ok(())",
            "Ok(())",
            "Err(\"unexpected route or gateway in lab\")",
            "Err(\"unexpected route or gateway in lab\")",
            "Err(\"unexpected route or gateway in lab\")",
            "Err(\"namespace forwarding enabled or unknown\")",
            "Err(\"namespace must contain only lo and its veth\")",
            "Err(\"invalid interface inventory\")",
            "Err(\"invalid route inventory\")",
            "Err(\"foreign link or bridge master in namespace\")",
            "Err(\"foreign link or bridge master in namespace\")",
        ]
        .join("\n")
    );
}

fn ad_links() -> serde_json::Value {
    serde_json::json!([{"ifname":"lo"},{"ifname":"veth-a","linkinfo":{"info_kind":"veth"},"master":null}])
}
fn ad_routes() -> serde_json::Value {
    serde_json::json!([
        {"dst":"default","gateway":"198.18.0.2","dev":"veth-a","flags":[]},
        {"dst":"198.18.0.0/24","dev":"veth-a","protocol":"kernel","scope":"link","prefsrc":"198.18.0.1"}
    ])
}
fn ad_neigh() -> serde_json::Value {
    serde_json::json!(["198.18.0.2", "198.18.0.3", "198.18.0.4", "198.18.0.5"].map(
        |d| serde_json::json!({"dst":d,"dev":"veth-a","lladdr":"02:aa:00:00:00:02","state":["PERMANENT"]})
    ))
}

#[test]
fn autodetect_mode_accepts_the_default_route_via_the_peer_and_the_permanent_neighbours() {
    use rmasscan_lab::capture::{
        check_isolation_neighbours, check_isolation_snapshot, check_route_get,
    };
    assert_eq!(
        check_isolation_snapshot(
            &ad_links(),
            &ad_routes(),
            "0",
            IsolationMode::Autodetect,
            Side::Scanner
        ),
        Ok(())
    );
    assert_eq!(check_isolation_neighbours(&ad_neigh(), "veth-a"), Ok(()));
    assert_eq!(
        check_route_get(
            "8.8.8.8 via 198.18.0.2 dev veth-a src 198.18.0.1 uid 0\n    cache",
            "veth-a"
        ),
        Ok(())
    );
    // the peer namespace keeps the sealed shape
    let peer_links = serde_json::json!([{"ifname":"lo"},{"ifname":"veth-b","linkinfo":{"info_kind":"veth"},"master":null}]);
    assert_eq!(
        check_isolation_snapshot(
            &peer_links,
            &serde_json::json!([{"dst":"198.18.0.0/24","dev":"veth-b"}]),
            "0",
            IsolationMode::Autodetect,
            Side::Peer
        ),
        Ok(())
    );
    // a missing or non-permanent neighbour, or a wrong route get, is refused
    let mut n = ad_neigh();
    n[2]["state"] = serde_json::json!(["REACHABLE"]);
    assert!(check_isolation_neighbours(&n, "veth-a").is_err());
    let mut n = ad_neigh();
    n.as_array_mut().unwrap().pop();
    assert!(check_isolation_neighbours(&n, "veth-a").is_err());
    assert!(check_route_get("8.8.8.8 dev veth-a src 198.18.0.1", "veth-a").is_err());
    assert!(check_route_get("8.8.8.8 via 198.18.0.3 dev veth-a", "veth-a").is_err());
}

#[test]
fn autodetect_mode_refuses_a_default_route_in_the_peer_namespace() {
    use rmasscan_lab::capture::check_isolation_snapshot;
    let peer_links = serde_json::json!([{"ifname":"lo"},{"ifname":"veth-b","linkinfo":{"info_kind":"veth"},"master":null}]);
    for routes in [
        serde_json::json!([{"dst":"default","gateway":"198.18.0.1","dev":"veth-b"}]),
        serde_json::json!([{"dst":"default","dev":"veth-b"}]),
        serde_json::json!([{"dst":"198.18.0.0/24","dev":"veth-b"},{"dst":"default","gateway":"198.18.0.1","dev":"veth-b"}]),
    ] {
        assert!(
            check_isolation_snapshot(
                &peer_links,
                &routes,
                "0",
                IsolationMode::Autodetect,
                Side::Peer
            )
            .is_err(),
            "{routes}"
        );
    }
    // and the scanner side is refused when forwarding is on
    assert!(
        check_isolation_snapshot(
            &ad_links(),
            &ad_routes(),
            "1",
            IsolationMode::Autodetect,
            Side::Scanner
        )
        .is_err()
    );
}

#[test]
fn autodetect_mode_refuses_a_third_route_or_a_host_link() {
    use rmasscan_lab::capture::check_isolation_snapshot;
    let mut third = ad_routes();
    third
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"dst":"10.0.0.0/8","dev":"veth-a"}));
    assert!(
        check_isolation_snapshot(
            &ad_links(),
            &third,
            "0",
            IsolationMode::Autodetect,
            Side::Scanner
        )
        .is_err()
    );
    // only the connected route, only the default route, the wrong gateway, the wrong device
    for routes in [
        serde_json::json!([{"dst":"198.18.0.0/24","dev":"veth-a"}]),
        serde_json::json!([{"dst":"default","gateway":"198.18.0.2","dev":"veth-a"}]),
        serde_json::json!([{"dst":"default","gateway":"198.18.0.3","dev":"veth-a"},{"dst":"198.18.0.0/24","dev":"veth-a"}]),
        serde_json::json!([{"dst":"default","gateway":"198.18.0.2","dev":"eno1"},{"dst":"198.18.0.0/24","dev":"veth-a"}]),
        serde_json::json!([{"dst":"default","gateway":"198.18.0.2","dev":"veth-a"},{"dst":"192.0.2.0/24","dev":"veth-a"}]),
    ] {
        assert!(
            check_isolation_snapshot(
                &ad_links(),
                &routes,
                "0",
                IsolationMode::Autodetect,
                Side::Scanner
            )
            .is_err(),
            "{routes}"
        );
    }
    // a host link inside the namespace
    let hosted = serde_json::json!([{"ifname":"lo"},{"ifname":"veth-a","linkinfo":{"info_kind":"veth"},"master":null},{"ifname":"eno1"}]);
    assert!(
        check_isolation_snapshot(
            &hosted,
            &ad_routes(),
            "0",
            IsolationMode::Autodetect,
            Side::Scanner
        )
        .is_err()
    );
    let bridged = serde_json::json!([{"ifname":"lo"},{"ifname":"veth-a","linkinfo":{"info_kind":"veth"},"master":"br0"}]);
    assert!(
        check_isolation_snapshot(
            &bridged,
            &ad_routes(),
            "0",
            IsolationMode::Autodetect,
            Side::Scanner
        )
        .is_err()
    );
}

#[test]
fn autodetect_mode_records_default_route_truthfully() {
    use rmasscan_lab::capture::{isolation_default_route, isolation_permits};
    let default = isolation_default_route(IsolationMode::Default, "unused");
    assert_eq!(default, serde_json::json!(false));
    let scanner = isolation_default_route(IsolationMode::Autodetect, "veth-a");
    assert_eq!(
        scanner,
        serde_json::json!({"scanner_ns": "via 198.18.0.2 dev veth-a", "peer_ns": false})
    );
    let doc = |d: serde_json::Value| {
        serde_json::json!({
            "uplink":false,"bridge":false,"nat":false,"default_route":d,"ip_forward":0,"ipv6":"disabled",
            "veth_created_inside_scanner_ns_peer_moved_to_peer_ns":true,"host_link_list_unchanged":true
        })
    };
    let truthful = serde_json::json!({"scanner_ns":"via 198.18.0.2 dev veth-a","peer_ns":false});
    assert!(isolation_permits(
        &doc(truthful.clone()),
        IsolationMode::Autodetect
    ));
    // the default mode refuses any recorded default route; autodetect refuses a plain false-less lie
    assert!(!isolation_permits(
        &doc(truthful.clone()),
        IsolationMode::Default
    ));
    assert!(isolation_permits(
        &doc(serde_json::json!(false)),
        IsolationMode::Default
    ));
    assert!(!isolation_permits(
        &doc(serde_json::json!(false)),
        IsolationMode::Autodetect
    ));
    let peer_default = serde_json::json!({"scanner_ns":"via 198.18.0.2 dev veth-a","peer_ns":"via 198.18.0.1 dev veth-b"});
    assert!(!isolation_permits(
        &doc(peer_default),
        IsolationMode::Autodetect
    ));
    let other = serde_json::json!({"scanner_ns":"via 10.0.0.1 dev eno1","peer_ns":false});
    assert!(!isolation_permits(&doc(other), IsolationMode::Autodetect));
}
