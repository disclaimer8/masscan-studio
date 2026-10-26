use serde_json::{Value, json};
use studio_protocol::{Backend, Status};
use studio_store::{Store, legacy};

fn session() -> Value {
    json!({"id":"AABBCCDD-0011-2233-4455-66778899AABB","name":"Old scan",
        "date":0.125,"status":"Paused","log":"original log","percent":25.5,
        "config":{"targets":"192.0.2.1","ports":"80,443","exclusions":"","interface":"en0",
            "rate":100,"seed":18446744073709551615u64,"resumeIndex":18446744073709551614u64},
        "results":[{"ip":"192.0.2.1","port":80,"proto":"tcp","discoveredAt":-0.25,
            "hostnameStatus":"pending","deviceHint":"Old device hint","deviceEvidence":"Original evidence"}]})
}
fn profile() -> Value {
    json!({"id":"11223344-0011-2233-4455-66778899AABB","name":"Office","config":session()["config"].clone()})
}
fn bytes(v: Value) -> Vec<u8> {
    serde_json::to_vec(&v).unwrap()
}
fn archive(s: Value, p: Value) -> legacy::Archive {
    legacy::decode(&bytes(s), &bytes(p)).unwrap()
}
fn dir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "studio-import-{}",
        studio_protocol::id_text(studio_protocol::new_id().unwrap())
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}
#[test]
fn swift_dates_u64_and_incompatible_checkpoint_are_preserved() {
    let a = archive(json!([session()]), json!([profile()]));
    let s = &a.sessions[0];
    assert_eq!(s.created_at, "2001-01-01T00:00:00.125Z");
    assert_eq!(s.rows[0].discovered_at, "2000-12-31T23:59:59.750Z");
    assert_eq!(s.job.seed, "18446744073709551615");
    assert_eq!(s.resume_index.as_deref(), Some("18446744073709551614"));
    assert_eq!(s.status, Status::Paused);
    assert_eq!(s.job.backend, Backend::SwiftImport);
    assert!(s.job.prepare().is_err());
    assert_eq!(
        s.hosts[0].dns_state,
        studio_inspection::CheckState::NotChecked
    );
    assert!(s.json.contains("Original evidence"));
}
#[test]
fn invalid_tail_or_profile_rejects_the_whole_archive() {
    let mut broken = session();
    broken["status"] = json!("Success-ish");
    assert!(legacy::decode(&bytes(json!([session(), broken])), b"[]").is_err());
    assert!(legacy::decode(&bytes(json!([session()])), br#"[{"id":"bad"}]"#).is_err());
    for value in [json!(-1), json!(1.5), json!("18446744073709551615")] {
        let mut s = session();
        s["config"]["seed"] = value;
        assert!(legacy::decode(&bytes(json!([s])), b"[]").is_err());
    }
    let invalid = bytes(json!([session()]));
    let invalid = String::from_utf8(invalid)
        .unwrap()
        .replace("18446744073709551615", "18446744073709551616");
    assert!(legacy::decode(invalid.as_bytes(), b"[]").is_err());
}
#[test]
fn active_statuses_recover_and_optional_fields_are_compatible() {
    for status in [
        "Starting",
        "Scanning",
        "Authorizing",
        "Stopping",
        "Interrupted",
    ] {
        let mut s = session();
        s["status"] = json!(status);
        s["config"].as_object_mut().unwrap().remove("resumeIndex");
        let a = archive(json!([s]), json!([]));
        assert_eq!(a.sessions[0].status, Status::Interrupted);
        assert!(a.sessions[0].resume_index.is_none());
    }
}
#[test]
fn duplicate_endpoints_and_unknown_fields_are_reported_and_archived() {
    let mut s = session();
    s["newerField"] = json!({"keep":true});
    let row = s["results"][0].clone();
    s["results"].as_array_mut().unwrap().push(row);
    let a = archive(json!([s]), json!([]));
    assert_eq!(a.sessions[0].rows.len(), 1);
    assert_eq!(a.sessions[0].duplicates, 1);
    assert!(!a.warnings.is_empty());
    assert!(a.sessions[0].json.contains("newerField"));
}
#[test]
fn repeat_import_is_idempotent_and_changed_record_conflicts() {
    let d = dir();
    let mut db = Store::open(&d).unwrap();
    let a = archive(json!([session()]), json!([profile()]));
    let report = db.import_swift(&a).unwrap();
    assert_eq!(
        (report.imported, report.skipped, report.conflicts),
        (2, 0, 0)
    );
    assert_eq!(db.scans().unwrap().len(), 1);
    assert_eq!(db.profiles().unwrap().len(), 1);
    let again = db.import_swift(&a).unwrap();
    assert_eq!((again.imported, again.skipped, again.conflicts), (0, 2, 0));
    let mut changed = session();
    changed["name"] = json!("Changed");
    let conflict = db
        .import_swift(&archive(json!([changed]), json!([])))
        .unwrap();
    assert_eq!(conflict.conflicts, 1);
    assert_eq!(db.scans().unwrap()[0].name.as_deref(), Some("Old scan"));
    let scan = db.scans().unwrap().remove(0);
    assert!(db.begin(scan.scan, [9; 16], &scan.job, true).is_err());
    assert!(scan.checkpoint.is_none());
    drop(db);
    std::fs::remove_dir_all(d).unwrap();
}
#[test]
fn stable_snapshot_keeps_source_files_unchanged_and_rejects_wrong_shapes() {
    let source = dir();
    let destination = dir();
    let sessions = bytes(json!([session()]));
    let profiles = bytes(json!([profile()]));
    std::fs::write(source.join("sessions.json"), &sessions).unwrap();
    std::fs::write(source.join("profiles.json"), &profiles).unwrap();
    let a = legacy::read_directory(&source).unwrap();
    Store::open(&destination).unwrap().import_swift(&a).unwrap();
    assert_eq!(
        std::fs::read(source.join("sessions.json")).unwrap(),
        sessions
    );
    assert_eq!(
        std::fs::read(source.join("profiles.json")).unwrap(),
        profiles
    );
    std::fs::write(source.join("profiles.json"), b"{}").unwrap();
    assert!(legacy::read_directory(&source).is_err());
    std::fs::remove_dir_all(source).unwrap();
    std::fs::remove_dir_all(destination).unwrap();
}

#[test]
fn import_refuses_an_active_scan() {
    let d = dir();
    let mut db = Store::open(&d).unwrap();
    db.begin(
        [1; 16],
        [2; 16],
        &studio_protocol::Job::example(Backend::Simulation),
        false,
    )
    .unwrap();
    assert!(
        db.import_swift(&archive(json!([session()]), json!([])))
            .is_err()
    );
    assert_eq!(db.scans().unwrap().len(), 1);
    drop(db);
    std::fs::remove_dir_all(d).unwrap();
}
#[test]
fn failed_profile_write_rolls_back_sessions_results_and_origin_keys() {
    let d = dir();
    let mut db = Store::open(&d).unwrap();
    let c = rusqlite::Connection::open(d.join("history.sqlite3")).unwrap();
    c.execute_batch("CREATE TRIGGER reject_profile BEFORE INSERT ON legacy_records WHEN NEW.kind='profile' BEGIN SELECT RAISE(ABORT,'injected import failure'); END;").unwrap();
    let a = archive(json!([session()]), json!([profile()]));
    assert!(db.import_swift(&a).is_err());
    assert!(db.scans().unwrap().is_empty());
    let count: i64 = c
        .query_row("SELECT count(*) FROM legacy_records", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    c.execute_batch("DROP TRIGGER reject_profile").unwrap();
    assert_eq!(db.import_swift(&a).unwrap().imported, 2);
    drop(c);
    drop(db);
    std::fs::remove_dir_all(d).unwrap();
}
#[test]
fn migration_keeps_a_consistent_v2_backup() {
    let d = dir();
    let c = rusqlite::Connection::open(d.join("history.sqlite3")).unwrap();
    c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA user_version=2;
        CREATE TABLE scans(id BLOB PRIMARY KEY,attempt BLOB NOT NULL,job TEXT NOT NULL,status TEXT NOT NULL,sequence TEXT NOT NULL DEFAULT '0',checkpoint BLOB,next_index TEXT,detail TEXT NOT NULL DEFAULT '',updated INTEGER NOT NULL);
        CREATE TABLE results(scan BLOB NOT NULL REFERENCES scans(id),ip TEXT NOT NULL,port INTEGER NOT NULL,open INTEGER NOT NULL,discovered_at TEXT,PRIMARY KEY(scan,ip,port));
        CREATE TABLE host_details(scan BLOB NOT NULL REFERENCES scans(id),ip TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(scan,ip));").unwrap();
    c.execute(
        "INSERT INTO scans(id,attempt,job,status,updated) VALUES(?1,?2,?3,'\"Completed\"',1)",
        rusqlite::params![
            [1u8; 16].as_slice(),
            [2u8; 16].as_slice(),
            serde_json::to_string(&studio_protocol::Job::example(Backend::Simulation)).unwrap()
        ],
    )
    .unwrap();
    c.execute(
        "INSERT INTO results VALUES(?1,'192.0.2.1',80,1,NULL)",
        [[1u8; 16].as_slice()],
    )
    .unwrap();
    // Keep the source connection open so backup must include live WAL contents.
    let db = Store::open(&d).unwrap();
    assert_eq!(db.rows([1; 16]).unwrap().len(), 1);
    let backup = std::fs::read_dir(&d)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.extension().is_some_and(|e| e == "sqlite3")
                && p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("before-v3-")
        })
        .unwrap();
    let backup =
        rusqlite::Connection::open_with_flags(backup, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    assert_eq!(
        backup
            .query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        backup
            .query_row("SELECT count(*) FROM results", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        backup
            .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    drop(backup);
    drop(db);
    drop(c);
    std::fs::remove_dir_all(d).unwrap();
}
#[test]
fn inspection_dates_and_original_device_evidence_survive_projection() {
    let mut s = session();
    s["results"][0]["inspection"] = json!({"ip":"192.0.2.1","date":0.25,"ports":[80],
        "services":[{"port":80,"state":"open","name":"http","product":"Example","method":"probed","confidence":"10","deviceType":"router","cpes":["cpe:/a:example"]}]});
    let a = archive(json!([s]), json!([]));
    let host = &a.sessions[0].hosts[0];
    assert_eq!(
        host.inspection.as_ref().unwrap().checked_at,
        "2001-01-01T00:00:00.250Z"
    );
    assert_eq!(host.service(80).unwrap().device_type, "router");
    assert!(host.evidence(80).contains("Original evidence"));
}
#[cfg(unix)]
#[test]
fn symlinked_or_nonregular_sources_are_rejected_without_reading_them() {
    let d = dir();
    let real = d.join("real");
    std::fs::write(&real, b"[]").unwrap();
    std::os::unix::fs::symlink(&real, d.join("sessions.json")).unwrap();
    std::fs::write(d.join("profiles.json"), b"[]").unwrap();
    assert!(legacy::read_directory(&d).is_err());
    std::fs::remove_file(d.join("sessions.json")).unwrap();
    std::fs::create_dir(d.join("sessions.json")).unwrap();
    assert!(legacy::read_directory(&d).is_err());
    std::fs::remove_dir_all(d).unwrap();
}
#[test]
#[ignore = "explicit read-only check of the user's Swift files into a disposable destination"]
fn real_swift_history_in_disposable_destination() {
    let source = std::path::PathBuf::from(
        std::env::var_os("STUDIO_SWIFT_SOURCE").expect("Set STUDIO_SWIFT_SOURCE"),
    );
    let before_s = std::fs::read(source.join("sessions.json")).unwrap();
    let before_p = std::fs::read(source.join("profiles.json")).unwrap();
    let archive = legacy::read_directory(&source).unwrap();
    let d = dir();
    let mut db = Store::open(&d).unwrap();
    let report = db.import_swift(&archive).unwrap();
    assert_eq!(
        report.imported,
        archive.sessions.len() + archive.profiles.len()
    );
    assert_eq!(db.import_swift(&archive).unwrap().skipped, report.imported);
    assert_eq!(
        std::fs::read(source.join("sessions.json")).unwrap(),
        before_s
    );
    assert_eq!(
        std::fs::read(source.join("profiles.json")).unwrap(),
        before_p
    );
    eprintln!(
        "Real Swift check: {} sessions, {} profiles, {} result rows; sources unchanged",
        archive.sessions.len(),
        archive.profiles.len(),
        report.results
    );
    drop(db);
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn unknown_numbers_are_preserved_exactly_and_changes_are_conflicts() {
    let source = serde_json::to_string(&vec![session()]).unwrap();
    let source = source.replacen("{", "{\"futureCounter\":184467440737095516160,", 1);
    let a = legacy::decode(source.as_bytes(), b"[]").unwrap();
    assert!(a.sessions[0].json.contains("184467440737095516160"));
    let changed = source.replace("184467440737095516160", "184467440737095516161");
    let b = legacy::decode(changed.as_bytes(), b"[]").unwrap();
    assert_ne!(a.sessions[0].fingerprint, b.sessions[0].fingerprint);
}
#[test]
fn copied_sources_and_uuid_case_do_not_duplicate_history() {
    let root = dir();
    let first = root.join("first");
    let copy = root.join("copy");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&copy).unwrap();
    let mut s = session();
    s["id"] = json!("abcdefab-cdef-abcd-efab-cdefabcdefab");
    std::fs::write(first.join("sessions.json"), bytes(json!([s.clone()]))).unwrap();
    std::fs::write(first.join("profiles.json"), b"[]").unwrap();
    s["id"] = json!("ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB");
    std::fs::write(
        copy.join("sessions.json"),
        serde_json::to_vec_pretty(&json!([s])).unwrap(),
    )
    .unwrap();
    std::fs::write(copy.join("profiles.json"), b"[]").unwrap();
    let mut db = Store::open(&root.join("data")).unwrap();
    assert_eq!(
        db.import_swift(&legacy::read_directory(&first).unwrap())
            .unwrap()
            .imported,
        1
    );
    assert_eq!(
        db.import_swift(&legacy::read_directory(&copy).unwrap())
            .unwrap()
            .skipped,
        1
    );
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn inspection_order_compares_instants_not_date_strings() {
    let mut s = session();
    let mut second = s["results"][0].clone();
    second["port"] = json!(443);
    let report = |date| json!({"ip":"192.0.2.1","date":date,"ports":[80,443],"services":[]});
    s["results"][0]["inspection"] = report(0.0);
    second["inspection"] = report(0.5);
    s["results"].as_array_mut().unwrap().push(second);
    let a = archive(json!([s]), json!([]));
    assert_eq!(
        a.sessions[0].hosts[0]
            .inspection
            .as_ref()
            .unwrap()
            .checked_at,
        "2001-01-01T00:00:00.500Z"
    );
}

#[test]
fn historical_ptr_names_survive_even_when_not_valid_for_new_urls() {
    let mut s = session();
    s["results"][0]["hostname"] = json!("printer_office.local");
    s["results"][0]["hostnameStatus"] = json!("resolved");
    let a = archive(json!([s]), json!([]));
    assert_eq!(
        a.sessions[0].hosts[0].hostname.as_deref(),
        Some("printer_office.local")
    );
    assert!(a.warnings.iter().any(|w| w.contains("hostname")));
    assert!(studio_inspection::valid_hostname("printer_office.local").is_none());
}

#[test]
fn last_successful_import_report_survives_restart() {
    let root = dir();
    let a = archive(json!([session()]), json!([profile()]));
    let mut db = Store::open(&root).unwrap();
    db.import_swift(&a).unwrap();
    drop(db);
    let db = Store::open(&root).unwrap();
    let report = db.last_import_report().unwrap().unwrap();
    assert_eq!((report.imported, report.results), (2, 1));
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}
