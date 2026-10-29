use rmasscan_net::{ExcludedReason, PhysicalRoutePlan};
use std::{collections::BTreeMap, net::Ipv4Addr};
use studio_protocol::*;
fn ip(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(0x0a000000 + n)
}
fn fixture(n: u32) -> (Job, NetworkReport) {
    let mut job = Job::example(Backend::MacNetwork);
    job.targets = format!("{}-{}", ip(1), ip(n));
    job.ports = "1-1024".into();
    let routes = PhysicalRoutePlan {
        interface_name: "en0".into(),
        interface_index: 1,
        source_ipv4: ip(4096),
        source_mac: Some([2, 1, 2, 3, 4, 5]),
        next_hops: (1..=n).map(|i| (ip(i), ip(i))).collect(),
        excluded: BTreeMap::new(),
    };
    let report = NetworkReport {
        job_digest: job.original_digest().unwrap(),
        routes,
        destinations: (1..=n)
            .map(|i| (ip(i), [2, 255, 255, 255, (i >> 8) as u8, i as u8]))
            .collect(),
        unresolved: vec![],
    };
    (job, report)
}
#[test]
fn network_bounds_and_settings_without_binding() {
    let (mut j, r) = fixture(1024);
    assert!(j.validate().is_ok());
    assert!(j.admit_network(&r.routes).is_ok());
    assert_eq!(j.prepare_network(&r).unwrap().range(), 1048576);
    assert!(j.prepare().is_err());
    assert!(!raw_profile_enabled(Backend::MacNetwork));
    j.ports = "1-1025".into();
    assert!(j.admit_network(&r.routes).is_err());
    let (mut j, r) = fixture(1);
    j.ports = "1-65535".into();
    let mut r = r;
    r.job_digest = j.original_digest().unwrap();
    assert_eq!(j.prepare_network(&r).unwrap().range(), 65535);
    j.rate = 1001;
    assert!(j.validate().is_err());
    j.rate = 100;
    j.targets = "0.0.0.0/0".into();
    assert!(j.validate().is_err());
}
#[test]
fn report_roundtrip_and_no_unresolved_limit_discount() {
    let (j, mut r) = fixture(1024);
    r.unresolved = r.destinations.keys().copied().collect();
    r.destinations.clear();
    assert!(r.validate_for(&j).is_ok());
    assert!(j.prepare_network(&r).is_err());
    assert_eq!(NetworkReport::decode(&r.encode().unwrap()).unwrap(), r);
    let mut j = j;
    j.ports = "1-1025".into();
    r.job_digest = j.original_digest().unwrap();
    assert!(r.validate_for(&j).is_err());
}
#[test]
fn report_job_partition_and_executable_identity() {
    let (j, mut r) = fixture(2);
    let original = r.clone();
    r.routes.source_mac = None;
    assert!(j.admit_network(&r.routes).is_ok());
    assert!(r.validate_for(&j).is_err());
    r = original.clone();
    r.destinations.remove(&ip(1));
    assert!(r.validate_for(&j).is_err());
    r = original.clone();
    r.unresolved.push(ip(1));
    assert!(r.validate_for(&j).is_err());
    r = original.clone();
    r.routes.next_hops.remove(&ip(1));
    r.destinations.remove(&ip(1));
    assert!(r.validate_for(&j).is_err());
    let mut changed = j.clone();
    changed.rate = 99;
    assert!(original.validate_for(&changed).is_err());
}
#[test]
fn checkpoint_roundtrip_rejects_corruption_and_substitution() {
    let (j, r) = fixture(2);
    let engine = rmasscan_engine::Checkpoint {
        format_version: rmasscan_engine::CHECKPOINT_FORMAT_VERSION,
        engine_version: ENGINE_VERSION,
        scan_id: [1; 16],
        attempt_id: [2; 16],
        job_digest: rmasscan_engine::job_digest(&j.prepare_network(&r).unwrap()),
        next_index: 1,
    }
    .to_bytes();
    let cp = NetworkCheckpoint {
        report: r.clone(),
        engine,
    };
    let bytes = cp.encode().unwrap();
    validate_checkpoint(&j, [1; 16], [2; 16], &bytes, "1").unwrap();
    assert_eq!(checkpoint_origin(&bytes).unwrap(), [2; 16]);
    assert_eq!(NetworkCheckpoint::decode(&bytes).unwrap(), cp);
    assert!(validate_checkpoint(&j, [1; 16], [3; 16], &bytes, "1").is_err());
    assert!(validate_checkpoint(&j, [9; 16], [2; 16], &bytes, "1").is_err());
    assert!(validate_checkpoint(&j, [1; 16], [2; 16], &bytes, "2").is_err());
    let mut bad = bytes;
    bad[40] ^= 1;
    assert!(NetworkCheckpoint::decode(&bad).is_err());
    let mut substituted = cp;
    substituted
        .report
        .destinations
        .insert(ip(1), [2, 8, 8, 8, 8, 8]);
    assert!(
        validate_checkpoint(&j, [1; 16], [2; 16], &substituted.encode().unwrap(), "1").is_err()
    );
}
#[test]
fn maximum_compact_report_and_outer_json_fit() {
    let (mut j, mut r) = fixture(1024);
    j.targets = format!("{}-{}", ip(1), ip(2048));
    r.routes.excluded = (1025..=2048)
        .map(|i| (ip(i), ExcludedReason::OwnAddress))
        .collect();
    r.job_digest = j.original_digest().unwrap();
    r.routes.interface_name = "e".repeat(63);
    j.admit_network(&r.routes).unwrap();
    let bytes = r.encode().unwrap();
    assert!(bytes.len() < MAX_NETWORK_BLOB);
    assert_eq!(NetworkReport::decode(&bytes).unwrap(), r);
    let engine = rmasscan_engine::Checkpoint {
        format_version: rmasscan_engine::CHECKPOINT_FORMAT_VERSION,
        engine_version: ENGINE_VERSION,
        scan_id: [255; 16],
        attempt_id: [254; 16],
        job_digest: rmasscan_engine::job_digest(&j.prepare_network(&r).unwrap()),
        next_index: 1,
    }
    .to_bytes();
    let checkpoint = NetworkCheckpoint { report: r, engine }.encode().unwrap();
    assert!(checkpoint.len() <= MAX_NETWORK_BLOB);
    validate_checkpoint(&j, [255; 16], [254; 16], &checkpoint, "1").unwrap();
    for payload in [
        Event::NetworkPrepared { bytes },
        Event::Checkpoint {
            bytes: checkpoint,
            next_index: "1".into(),
        },
    ] {
        write_frame(
            &mut vec![],
            &Envelope::new([255; 16], [255; 16], [254; 16], u64::MAX, payload),
        )
        .unwrap();
    }
    for payload in [
        Event::NetworkPrepared {
            bytes: vec![255; MAX_NETWORK_BLOB],
        },
        Event::Checkpoint {
            bytes: vec![255; MAX_NETWORK_BLOB],
            next_index: u64::MAX.to_string(),
        },
    ] {
        let e = Envelope::new([255; 16], [255; 16], [255; 16], u64::MAX, payload);
        assert!(serde_json::to_vec(&e).unwrap().len() <= MAX_FRAME);
        write_frame(&mut vec![], &e).unwrap();
    }
    assert!(NetworkReport::decode(&vec![255; MAX_NETWORK_BLOB + 1]).is_err());
}
#[test]
fn actual_start_frame_rejected_before_observation() {
    let (mut j, _) = fixture(1);
    j.targets = format!("{}{}", " ".repeat(30000), "10.0.0.1");
    j.exclusions = "\n".repeat(65000);
    assert!(j.validate().is_err());
}
#[test]
fn legacy_json_and_checkpoints_still_work() {
    let j:Job=serde_json::from_str(r#"{"targets":"198.18.0.2","ports":"80,443","exclusions":"","seed":"42","rate":100,"backend":"Simulation"}"#).unwrap();
    j.validate().unwrap();
    let cp = rmasscan_engine::Checkpoint {
        format_version: rmasscan_engine::CHECKPOINT_FORMAT_VERSION,
        engine_version: ENGINE_VERSION,
        scan_id: [1; 16],
        attempt_id: [2; 16],
        job_digest: rmasscan_engine::job_digest(&j.prepare().unwrap()),
        next_index: 1,
    }
    .to_bytes();
    validate_checkpoint(&j, [1; 16], [2; 16], &cp, "1").unwrap();
    assert_eq!(checkpoint_origin(&cp).unwrap(), [2; 16]);
}
#[test]
fn admission_preserves_explicit_provenance_and_applies_user_exclusions_first() {
    let (mut j, _) = fixture(1);
    j.targets = "0.0.0.0/0".into();
    j.exclusions = "0.0.0.0-9.255.255.255,10.0.0.3-255.255.255.255".into();
    let targets = j.network_targets().unwrap();
    assert_eq!(targets.addresses().len(), 3);
    j.targets = "10.0.0.0/21".into();
    j.exclusions.clear();
    assert_eq!(j.network_targets().unwrap().addresses().len(), 2048);
    j.targets = "10.0.0.0-10.0.8.0".into();
    assert!(j.validate().is_err());
    let (mut j, mut r) = fixture(2);
    j.targets = "10.0.0.1-10.0.0.2,10.0.0.1".into();
    r.routes.next_hops.remove(&ip(1));
    r.routes.excluded.insert(ip(1), ExcludedReason::OwnAddress);
    assert!(j.admit_network(&r.routes).is_err());
    j.exclusions = "10.0.0.1".into();
    r.routes.excluded.clear();
    assert!(j.admit_network(&r.routes).is_ok());
}
#[test]
fn rejects_bad_ports_and_resume_frames_that_cannot_fit() {
    let (mut j, r) = fixture(1024);
    for ports in ["0", "65536", "T:80", "1-2-3", "-1", "80,"] {
        j.ports = ports.into();
        assert!(j.validate().is_err(), "{ports}");
    }
    j.ports = "1".into();
    j.targets = format!("{}{}", " ".repeat(60000), j.targets);
    assert!(j.validate().is_ok());
    assert!(
        j.admit_network(&r.routes).is_err(),
        "Start fits but future Resume cannot"
    );
}
#[test]
fn malformed_report_codec_rejects_noncanonical_and_truncated_bytes() {
    let (_, r) = fixture(2);
    let bytes = r.encode().unwrap();
    for n in [0, 8, 39, bytes.len() - 1] {
        assert!(NetworkReport::decode(&bytes[..n]).is_err());
    }
    let mut bad = bytes.clone();
    bad[8] ^= 1;
    assert!(NetworkReport::decode(&bad).is_err());
    // Rewrite a reason/count/table byte with a recomputed checksum: structural checks remain necessary.
    let mut bad = bytes.clone();
    bad[8 + 32 + 1 + 3 + 4 + 4 + 6] = 255;
    let end = bad.len() - 32;
    let sum = rmasscan_engine::identity::digest_bytes(&bad[..end]);
    bad[end..].copy_from_slice(&sum);
    assert!(NetworkReport::decode(&bad).is_err());
}
#[test]
fn one_next_hop_cannot_be_both_resolved_and_unresolved() {
    let (j, mut r) = fixture(2);
    r.routes.next_hops.insert(ip(2), ip(1));
    r.destinations.remove(&ip(1));
    r.unresolved.push(ip(1));
    assert!(r.validate_for(&j).is_err());
}
#[test]
fn accepted_singleton_spelling_never_loses_explicit_provenance() {
    let (mut j, mut r) = fixture(2);
    j.targets = "10.0.0.1-10.0.0.2,010.000.000.001".into();
    assert!(
        j.network_targets()
            .unwrap()
            .explicit_singletons()
            .contains(&ip(1))
    );
    r.routes.next_hops.remove(&ip(1));
    r.routes.excluded.insert(ip(1), ExcludedReason::OwnAddress);
    assert!(j.admit_network(&r.routes).is_err());
}
