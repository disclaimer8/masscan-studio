use studio_inspection::*;

fn coverage() -> ExportCoverage {
    ExportCoverage {
        scan_id: "fixture-scan".into(),
        original_job: ExportJob {
            backend: "MacNetwork".into(),
            targets: "10.0.0.0/30".into(),
            ports: "80,443".into(),
            exclusions: "10.0.0.3".into(),
            seed: "18446744073709551615".into(),
            rate: 100,
        },
        requested: CoverageCount {
            targets: 4,
            probes: 8,
        },
        candidate: CoverageCount {
            targets: 3,
            probes: 6,
        },
        effective: CoverageCount {
            targets: 2,
            probes: 4,
        },
        unscanned: CoverageCount {
            targets: 2,
            probes: 4,
        },
        automatically_excluded: CoverageCount {
            targets: 1,
            probes: 2,
        },
        unresolved: ["10.0.0.1", "10.0.0.2"]
            .map(|ip| CoverageAddress {
                ip: ip.into(),
                reason: "no neighbour response".into(),
            })
            .into(),
        excluded: vec![CoverageAddress {
            ip: "10.0.0.0".into(),
            reason: "subnet network address".into(),
        }],
        interface_name: "en0".into(),
        source_ipv4: "10.0.0.254".into(),
        ..Default::default()
    }
}

#[test]
fn all_missing_zero_result_export_retains_whole_scan_coverage_without_fake_ports() {
    let coverage = coverage();
    let json: serde_json::Value =
        serde_json::from_str(&json_with_coverage(&[], Some(&coverage)).unwrap()).unwrap();
    assert_eq!(json["version"], 2);
    assert_eq!(json["rows"], serde_json::json!([]));
    assert_eq!(json["coverage"], serde_json::to_value(&coverage).unwrap());
    assert!(
        json["coverage_scope"]
            .as_str()
            .unwrap()
            .contains("not probes sent")
    );
    let csv = csv_with_coverage(&[], Some(&coverage)).unwrap();
    assert!(csv.starts_with("Record kind,IP,Hostname,Port,Protocol,State,"));
    assert!(csv.contains("\r\nscan_coverage,"));
    assert!(!csv.contains("\r\nresult,"));
    let nonresults: Vec<_> = csv
        .lines()
        .filter(|line| {
            line.starts_with("not_scanned,") || line.starts_with("automatically_excluded,")
        })
        .collect();
    assert_eq!(nonresults.len(), 3);
    for line in nonresults {
        let cells: Vec<_> = line.split(',').collect();
        assert_eq!(cells.len(), 11);
        assert_eq!(
            &cells[3..6],
            ["", "", ""],
            "no port, protocol or open/closed state for non-results"
        );
    }
    assert!(!csv.contains(",0,TCP,closed,"));
}

#[test]
fn physical_exports_preserve_caller_result_order_and_no_hidden_inspection_data() {
    let rows = vec![
        ExportRow {
            ip: "10.0.0.9".into(),
            port: 80,
            open: true,
            hostname: Some("=formula".into()),
            ..Default::default()
        },
        ExportRow {
            ip: "10.0.0.1".into(),
            port: 80,
            open: false,
            ..Default::default()
        },
    ];
    let coverage = coverage();
    let json: serde_json::Value =
        serde_json::from_str(&json_with_coverage(&rows, Some(&coverage)).unwrap()).unwrap();
    assert_eq!(json["rows"], serde_json::to_value(&rows).unwrap());
    assert_eq!(json["rows"][0]["port"], 80);
    assert_eq!(json["coverage"]["original_job"]["ports"], "80,443");
    let csv = csv_with_coverage(&rows, Some(&coverage)).unwrap();
    assert!(csv.contains("result,10.0.0.9,'=formula,80,TCP,open,"));
    assert!(csv.find("result,10.0.0.9,").unwrap() < csv.find("result,10.0.0.1,").unwrap());
    assert_eq!(
        coverage.unscanned.targets, 2,
        "result filtering cannot change scan-wide counts"
    );
}

#[test]
fn optional_coverage_keeps_legacy_format_and_atomic_file_replacement() {
    let rows = [ExportRow {
        ip: "10.0.0.1".into(),
        port: 80,
        open: true,
        source: "rmasscan".into(),
        ..Default::default()
    }];
    let expected = "IP,Hostname,Port,Protocol,State,Service,Device hint,Discovered,Source\r\n10.0.0.1,,80,TCP,open,,,,rmasscan\r\n";
    assert_eq!(csv(&rows).unwrap(), expected);
    assert_eq!(csv_with_coverage(&rows, None).unwrap(), expected);
    let old_json: serde_json::Value =
        serde_json::from_str(&json_with_coverage(&rows, None).unwrap()).unwrap();
    assert_eq!(old_json["version"], 1);
    assert!(old_json.get("coverage").is_none());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.json");
    std::fs::write(&path, "old").unwrap();
    write_export_with_coverage(&path, &[], Some(&coverage()), true).unwrap();
    let before = std::fs::read(&path).unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(saved["coverage"]["unscanned"]["targets"], 2);
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        1,
        "coverage and results use a single file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = dir.path().join("alias.json");
        symlink(&path, &link).unwrap();
        assert!(write_export_with_coverage(&link, &rows, Some(&coverage()), false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    assert!(
        write_export_with_coverage(
            &dir.path().join("missing/report.csv"),
            &[],
            Some(&coverage()),
            false
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
