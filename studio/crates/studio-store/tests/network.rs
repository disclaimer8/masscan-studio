use studio_protocol::*;
use studio_store::Store;
fn report(job: &Job) -> NetworkReport {
    // Canonical fixture shared via a protocol-valid report without any adapter access.
    let mut bytes = Vec::new();
    bytes.extend(b"STNETR01");
    bytes.extend(job.original_digest().unwrap());
    bytes.push(3);
    bytes.extend(b"en0");
    bytes.extend(1u32.to_be_bytes());
    bytes.extend([10, 0, 0, 254]);
    bytes.extend([2, 1, 2, 3, 4, 5]);
    for n in [2u16, 0, 2, 0] {
        bytes.extend(n.to_be_bytes());
    }
    bytes.extend([10, 0, 0, 1, 10, 0, 0, 2]);
    for n in 1..=2u8 {
        bytes.extend([10, 0, 0, n]);
        bytes.extend(u16::from(n - 1).to_be_bytes());
        bytes.extend(u16::MAX.to_be_bytes());
    }
    bytes.extend(rmasscan_engine::identity::digest_bytes(&bytes));
    NetworkReport::decode(&bytes).unwrap()
}
fn job() -> Job {
    let mut j = Job::example(Backend::MacNetwork);
    j.targets = "10.0.0.1-10.0.0.2".into();
    j
}
#[test]
fn report_commit_precedes_ack_and_survives_history() {
    let dir = std::env::temp_dir().join(format!("studio-network-{}", id_text(new_id().unwrap())));
    let mut db = Store::open(&dir).unwrap();
    let j = job();
    db.begin([1; 16], [2; 16], &j, false).unwrap();
    let r = report(&j);
    let bytes = r.encode().unwrap();
    let e = Envelope::new(
        [3; 16],
        [1; 16],
        [2; 16],
        1,
        Event::NetworkPrepared {
            bytes: bytes.clone(),
        },
    );
    let sql = rusqlite::Connection::open(dir.join("history.sqlite3")).unwrap();
    sql.execute_batch("CREATE TRIGGER fail_report BEFORE UPDATE OF network_report ON scans BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(db.apply(&e).is_err(), "failed commit cannot authorize ACK");
    assert!(db.scans().unwrap()[0].network_report.is_none());
    sql.execute_batch("DROP TRIGGER fail_report;").unwrap();
    db.apply(&e).unwrap();
    let durable: Vec<u8> = sql
        .query_row("SELECT network_report FROM scans", [], |r| r.get(0))
        .unwrap();
    assert_eq!(durable, bytes);
    drop(sql);
    drop(db);
    let db = Store::open(&dir).unwrap();
    let saved = db.scans().unwrap().remove(0);
    assert_eq!(saved.job, j);
    assert_eq!(saved.network_report, Some(bytes));
    assert_eq!(
        NetworkReport::decode(saved.network_report.as_ref().unwrap())
            .unwrap()
            .unresolved
            .len(),
        2
    );
    assert!(db.rows([1; 16]).unwrap().is_empty());
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn version_four_migration_backs_up_before_altering() {
    let dir = std::env::temp_dir().join(format!(
        "studio-network-migrate-{}",
        id_text(new_id().unwrap())
    ));
    let db = Store::open(&dir).unwrap();
    drop(db);
    let sql = rusqlite::Connection::open(dir.join("history.sqlite3")).unwrap();
    sql.execute_batch("ALTER TABLE scans DROP COLUMN network_report; PRAGMA user_version=4;")
        .unwrap();
    drop(sql);
    let db = Store::open(&dir).unwrap();
    drop(db);
    let backups: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(Result::unwrap)
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            e.file_type().unwrap().is_file()
                && name.starts_with("before-v5-")
                && name.ends_with(".sqlite3")
        })
        .collect();
    assert_eq!(backups.len(), 1);
    let backup = rusqlite::Connection::open(backups[0].path()).unwrap();
    assert_eq!(
        backup
            .query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        4
    );
    assert!(backup.prepare("SELECT network_report FROM scans").is_err());
    assert_eq!(
        backup
            .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    drop(backup);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn physical_started_requires_durable_nonempty_report() {
    let dir = std::env::temp_dir().join(format!(
        "studio-network-start-{}",
        id_text(new_id().unwrap())
    ));
    let mut db = Store::open(&dir).unwrap();
    let j = job();
    db.begin([1; 16], [2; 16], &j, false).unwrap();
    let event = |sequence, payload| Envelope::new([3; 16], [1; 16], [2; 16], sequence, payload);
    assert!(
        db.apply(&event(1, Event::Started { total: "16".into() }))
            .is_err()
    );
    db.apply(&event(
        1,
        Event::NetworkPrepared {
            bytes: report(&j).encode().unwrap(),
        },
    ))
    .unwrap();
    assert!(
        db.apply(&event(2, Event::Started { total: "16".into() }))
            .is_err()
    );
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn substituted_route_checkpoint_rejected_against_committed_report_on_apply_and_load() {
    let dir = std::env::temp_dir().join(format!(
        "studio-network-substitution-{}",
        id_text(new_id().unwrap())
    ));
    let mut db = Store::open(&dir).unwrap();
    let j = job();
    let mut r = report(&j);
    r.destinations = r
        .unresolved
        .iter()
        .map(|ip| (*ip, [2, 8, 8, 8, 8, 8]))
        .collect();
    r.unresolved.clear();
    db.begin([1; 16], [2; 16], &j, false).unwrap();
    db.apply(&Envelope::new(
        [3; 16],
        [1; 16],
        [2; 16],
        1,
        Event::NetworkPrepared {
            bytes: r.encode().unwrap(),
        },
    ))
    .unwrap();
    let engine = rmasscan_engine::Checkpoint {
        format_version: rmasscan_engine::CHECKPOINT_FORMAT_VERSION,
        engine_version: ENGINE_VERSION,
        scan_id: [1; 16],
        attempt_id: [2; 16],
        job_digest: rmasscan_engine::job_digest(&j.prepare_network(&r).unwrap()),
        next_index: 1,
    }
    .to_bytes();
    r.routes
        .next_hops
        .insert("10.0.0.1".parse().unwrap(), "10.0.0.253".parse().unwrap());
    let bytes = NetworkCheckpoint { report: r, engine }.encode().unwrap();
    // Engine digest does not contain route IP metadata. Authenticated frozen report comparison does.
    validate_checkpoint(&j, [1; 16], [2; 16], &bytes, "1").unwrap();
    assert!(
        db.apply(&Envelope::new(
            [3; 16],
            [1; 16],
            [2; 16],
            2,
            Event::Checkpoint {
                bytes: bytes.clone(),
                next_index: "1".into()
            }
        ))
        .is_err()
    );
    let sql = rusqlite::Connection::open(dir.join("history.sqlite3")).unwrap();
    sql.execute(
        "UPDATE scans SET checkpoint=?1,next_index='1',status='\"Paused\"'",
        [bytes],
    )
    .unwrap();
    assert!(
        db.scans().is_err(),
        "History must reject inconsistent frozen provenance"
    );
    assert!(db.begin([1; 16], [4; 16], &j, true).is_err());
    drop(sql);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn network_profiles_and_preparing_recovery_require_no_binding() {
    let dir = std::env::temp_dir().join(format!(
        "studio-network-preparing-{}",
        id_text(new_id().unwrap())
    ));
    let mut db = Store::open(&dir).unwrap();
    let j = job();
    db.save_profile(None, "Network", &j).unwrap();
    db.begin([1; 16], [2; 16], &j, false).unwrap();
    db.apply(&Envelope::new(
        [3; 16],
        [1; 16],
        [2; 16],
        1,
        Event::PreparingNetwork,
    ))
    .unwrap();
    assert_eq!(db.scans().unwrap()[0].status, Status::Preparing);
    assert!(db.delete_scan([1; 16]).is_err());
    assert!(db.rename_scan([1; 16], "Busy").is_err());
    let bytes = report(&j).encode().unwrap();
    assert!(
        db.apply(&Envelope::new(
            [3; 16],
            [1; 16],
            [9; 16],
            2,
            Event::NetworkPrepared {
                bytes: bytes.clone()
            }
        ))
        .is_err()
    );
    let mut other = j.clone();
    other.rate = 99;
    assert!(
        db.apply(&Envelope::new(
            [3; 16],
            [1; 16],
            [2; 16],
            2,
            Event::NetworkPrepared {
                bytes: report(&other).encode().unwrap()
            }
        ))
        .is_err()
    );
    db.apply(&Envelope::new(
        [3; 16],
        [1; 16],
        [2; 16],
        2,
        Event::NetworkPrepared { bytes },
    ))
    .unwrap();
    drop(db);
    let db = Store::open(&dir).unwrap();
    assert_eq!(db.scans().unwrap()[0].status, Status::Interrupted);
    assert_eq!(db.profiles().unwrap()[0].job, j);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}
