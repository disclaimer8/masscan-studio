use studio_protocol::*;
use studio_store::Store;

fn setup() -> (std::path::PathBuf, Store) {
    let dir = std::env::temp_dir().join(format!("studio-history-{}", id_text(new_id().unwrap())));
    let db = Store::open(&dir).unwrap();
    (dir, db)
}
fn saved(db: &mut Store, scan: Id) {
    db.begin(scan, [2; 16], &Job::example(Backend::Simulation), false)
        .unwrap();
    db.apply(&Envelope::new(
        [3; 16],
        scan,
        [2; 16],
        1,
        Event::Results(vec![Row {
            ip: "198.18.0.2".into(),
            port: 80,
            open: true,
        }]),
    ))
    .unwrap();
    db.save_host(scan, &studio_inspection::HostInfo::new("198.18.0.2".into()))
        .unwrap();
    db.apply(&Envelope::new(
        [3; 16],
        scan,
        [2; 16],
        2,
        Event::Finished {
            status: Status::Completed,
            detail: "done".into(),
        },
    ))
    .unwrap();
}

#[test]
fn rename_and_delete_preserve_other_scans_profiles_and_creation_time() {
    let (dir, mut db) = setup();
    saved(&mut db, [1; 16]);
    saved(&mut db, [4; 16]);
    db.save_profile(None, "Office", &Job::example(Backend::Simulation))
        .unwrap();
    let before = db
        .scans()
        .unwrap()
        .into_iter()
        .find(|s| s.scan == [1; 16])
        .unwrap();
    assert!(before.created_at.as_ref().is_some_and(|s| s.ends_with('Z')));
    db.rename_scan([1; 16], "  Office 'scan'  ").unwrap();
    let after = db
        .scans()
        .unwrap()
        .into_iter()
        .find(|s| s.scan == [1; 16])
        .unwrap();
    assert_eq!(after.name.as_deref(), Some("Office 'scan'"));
    assert_eq!(after.created_at, before.created_at);
    assert_eq!(after.job, before.job);
    assert_eq!(after.attempt, before.attempt);
    assert_eq!(after.checkpoint, before.checkpoint);
    db.delete_scan([1; 16]).unwrap();
    assert!(db.rows([1; 16]).unwrap().is_empty());
    assert!(db.hosts([1; 16]).unwrap().is_empty());
    assert_eq!(db.rows([4; 16]).unwrap().len(), 1);
    assert_eq!(db.hosts([4; 16]).unwrap().len(), 1);
    assert_eq!(db.profiles().unwrap().len(), 1);
    drop(db);
    let db = Store::open(&dir).unwrap();
    assert_eq!(db.scans().unwrap().len(), 1);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn active_invalid_and_stale_edits_are_rejected() {
    let (dir, mut db) = setup();
    db.begin([1; 16], [2; 16], &Job::example(Backend::Simulation), false)
        .unwrap();
    assert!(db.delete_scan([1; 16]).is_err());
    assert!(db.rename_scan([1; 16], "Busy").is_err());
    db.interrupt([1; 16], "test").unwrap();
    for name in ["", "  ", "new\nline", &"x".repeat(129)] {
        assert!(db.rename_scan([1; 16], name).is_err());
    }
    assert!(db.delete_scan([9; 16]).is_err());
    assert!(db.rename_scan([9; 16], "Missing").is_err());
    assert!(db.scans().unwrap()[0].name.is_none());
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn failed_delete_rolls_back_results_and_host_details() {
    let (dir, mut db) = setup();
    saved(&mut db, [1; 16]);
    let sql = rusqlite::Connection::open(dir.join("history.sqlite3")).unwrap();
    sql.execute_batch("CREATE TRIGGER reject_delete BEFORE DELETE ON scans BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
    assert!(db.delete_scan([1; 16]).is_err());
    assert_eq!(db.scans().unwrap().len(), 1);
    assert_eq!(db.rows([1; 16]).unwrap().len(), 1);
    assert_eq!(db.hosts([1; 16]).unwrap().len(), 1);
    sql.execute_batch("DROP TRIGGER reject_delete;").unwrap();
    db.delete_scan([1; 16]).unwrap();
    drop(sql);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn paused_checkpoint_survives_rename_and_old_metadata_does_not_block_delete() {
    let (dir, mut db) = setup();
    let job = Job::example(Backend::Simulation);
    let scan = [1; 16];
    let attempt = [2; 16];
    db.begin(scan, attempt, &job, false).unwrap();
    let checkpoint = rmasscan_engine::Checkpoint {
        format_version: rmasscan_engine::CHECKPOINT_FORMAT_VERSION,
        engine_version: ENGINE_VERSION,
        scan_id: scan,
        attempt_id: attempt,
        job_digest: rmasscan_engine::job_digest(&job.prepare().unwrap()),
        next_index: 1,
    }
    .to_bytes();
    db.apply(&Envelope::new(
        [3; 16],
        scan,
        attempt,
        1,
        Event::Checkpoint {
            bytes: checkpoint.clone(),
            next_index: "1".into(),
        },
    ))
    .unwrap();
    // SQLite already holds a durable Paused checkpoint. The controller keeps
    // its separate active guard until the runner acknowledges and finishes.
    db.apply(&Envelope::new(
        [3; 16],
        scan,
        attempt,
        2,
        Event::Finished {
            status: Status::Paused,
            detail: "paused".into(),
        },
    ))
    .unwrap();
    db.rename_scan(scan, "Checkpoint").unwrap();
    let saved = db.scans().unwrap().remove(0);
    assert_eq!(saved.checkpoint, Some(checkpoint));
    assert_eq!(saved.next_index.as_deref(), Some("1"));
    assert_eq!(saved.job, job);
    assert_eq!(saved.status, Status::Paused);
    let sql = rusqlite::Connection::open(dir.join("history.sqlite3")).unwrap();
    sql.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE legacy_records(scan BLOB REFERENCES scans(id), data TEXT);").unwrap();
    sql.execute(
        "INSERT INTO legacy_records VALUES(?1,'old metadata')",
        [scan.as_slice()],
    )
    .unwrap();
    db.delete_scan(scan).unwrap();
    assert_eq!(
        sql.query_row("SELECT count(*) FROM legacy_records", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    drop(sql);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}
