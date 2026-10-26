use studio_protocol::*;
use studio_store::Store;

#[test]
fn restart_preserves_rows_and_marks_inflight_interrupted() {
    let dir = std::env::temp_dir().join(format!("studio-store-{}", id_text(new_id().unwrap())));
    let scan = [3; 16];
    let attempt = [4; 16];
    let job = Job::example(Backend::Simulation);
    {
        let mut db = Store::open(&dir).unwrap();
        assert!(Store::open(&dir).is_err(), "single instance");
        db.begin(scan, attempt, &job, false).unwrap();
        let event = Envelope::new(
            [1; 16],
            scan,
            attempt,
            1,
            Event::Results(vec![Row {
                ip: "198.18.0.2".into(),
                port: 8000,
                open: true,
            }]),
        );
        db.apply(&event).unwrap();
        db.apply(&event).unwrap();
        assert_eq!(db.rows(scan).unwrap().len(), 1, "idempotent replay");
        let wrong = Envelope::new([1; 16], scan, [9; 16], 2, Event::Results(vec![]));
        assert!(db.apply(&wrong).is_err());
    }
    let db = Store::open(&dir).unwrap();
    assert_eq!(db.scans().unwrap()[0].status, Status::Interrupted);
    assert_eq!(db.rows(scan).unwrap().len(), 1);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn corrupted_checkpoint_is_never_resumable() {
    let dir = std::env::temp_dir().join(format!("studio-store-{}", id_text(new_id().unwrap())));
    let mut db = Store::open(&dir).unwrap();
    let scan = [3; 16];
    let attempt = [4; 16];
    db.begin(scan, attempt, &Job::example(Backend::Simulation), false)
        .unwrap();
    let event = Envelope::new(
        [1; 16],
        scan,
        attempt,
        1,
        Event::Checkpoint {
            bytes: vec![0; 120],
            next_index: "2".into(),
        },
    );
    assert!(db.apply(&event).is_err());
    assert!(db.scans().unwrap()[0].checkpoint.is_none());
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn failed_checkpoint_commit_cannot_be_acknowledged_or_resumed() {
    let dir = std::env::temp_dir().join(format!("studio-commit-{}", id_text(new_id().unwrap())));
    let mut db = Store::open(&dir).unwrap();
    let job = Job::example(Backend::Simulation);
    let scan = [3; 16];
    let attempt = [4; 16];
    db.begin(scan, attempt, &job, false).unwrap();
    let checkpoint = rmasscan_engine::Checkpoint {
        format_version: rmasscan_engine::CHECKPOINT_FORMAT_VERSION,
        engine_version: ENGINE_VERSION,
        scan_id: scan,
        attempt_id: attempt,
        job_digest: rmasscan_engine::job_digest(&job.prepare().unwrap()),
        next_index: 1,
    };
    let connection = rusqlite::Connection::open(dir.join("history.sqlite3")).unwrap();
    connection.execute_batch("CREATE TRIGGER reject_checkpoint BEFORE UPDATE OF checkpoint ON scans BEGIN SELECT RAISE(ABORT,'injected write failure'); END;").unwrap();
    let event = Envelope::new(
        [1; 16],
        scan,
        attempt,
        1,
        Event::Checkpoint {
            bytes: checkpoint.to_bytes(),
            next_index: "1".into(),
        },
    );
    assert!(
        db.apply(&event).is_err(),
        "controller must receive failure before ACK"
    );
    assert!(db.scans().unwrap()[0].checkpoint.is_none());
    assert!(db.begin(scan, [5; 16], &job, true).is_err());
    drop(connection);
    drop(db);
    let db = Store::open(&dir).unwrap();
    assert_eq!(db.scans().unwrap()[0].status, Status::Interrupted);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn metadata_and_observation_dates_survive_restart_without_fabricating_legacy_dates() {
    use studio_inspection::{CheckState, HostInfo};
    let dir = std::env::temp_dir().join(format!("studio-migration-{}", id_text(new_id().unwrap())));
    std::fs::create_dir_all(&dir).unwrap();
    let old = rusqlite::Connection::open(dir.join("history.sqlite3")).unwrap();
    old.execute_batch("PRAGMA user_version=1; CREATE TABLE scans(id BLOB PRIMARY KEY,attempt BLOB NOT NULL,job TEXT NOT NULL,status TEXT NOT NULL,sequence TEXT NOT NULL DEFAULT '0',checkpoint BLOB,next_index TEXT,detail TEXT NOT NULL DEFAULT '',updated INTEGER NOT NULL); CREATE TABLE results(scan BLOB NOT NULL REFERENCES scans(id),ip TEXT NOT NULL,port INTEGER NOT NULL,open INTEGER NOT NULL,PRIMARY KEY(scan,ip,port));").unwrap();
    let scan = [3u8; 16];
    let attempt = [4u8; 16];
    old.execute(
        "INSERT INTO scans(id,attempt,job,status,updated) VALUES(?1,?2,?3,'\"Completed\"',0)",
        rusqlite::params![
            scan.as_slice(),
            attempt.as_slice(),
            serde_json::to_string(&Job::example(Backend::Simulation)).unwrap()
        ],
    )
    .unwrap();
    old.execute(
        "INSERT INTO results VALUES(?1,'198.18.0.2',8000,1)",
        [scan.as_slice()],
    )
    .unwrap();
    drop(old);
    let mut db = Store::open(&dir).unwrap();
    assert_eq!(db.observations(scan).unwrap()[0].discovered_at, None);
    let mut info = HostInfo::new("198.18.0.2".into());
    info.hostname = Some("fixture.local".into());
    info.dns_state = CheckState::Complete;
    info.nmap_state = CheckState::Pending;
    db.save_host(scan, &info).unwrap();
    assert!(
        db.save_host(scan, &HostInfo::new("198.18.0.99".into()))
            .is_err()
    );
    let scan2 = [5; 16];
    db.begin(scan2, attempt, &Job::example(Backend::Simulation), false)
        .unwrap();
    let e = Envelope::new(
        [1; 16],
        scan2,
        attempt,
        1,
        Event::Results(vec![Row {
            ip: "198.18.0.2".into(),
            port: 8000,
            open: true,
        }]),
    );
    db.apply(&e).unwrap();
    let timestamp = db.observations(scan2).unwrap()[0].discovered_at.clone();
    assert!(timestamp.is_some());
    db.apply(&e).unwrap();
    assert_eq!(db.observations(scan2).unwrap()[0].discovered_at, timestamp);
    drop(db);
    let db = Store::open(&dir).unwrap();
    let saved = &db.hosts(scan).unwrap()[0];
    assert_eq!(saved.hostname, Some("fixture.local".into()));
    assert_eq!(saved.nmap_state, CheckState::Cancelled);
    assert!(db.hosts(scan2).unwrap().is_empty());
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn committed_batch_returns_saved_dates_without_requerying_each_result() {
    let dir = std::env::temp_dir().join(format!("studio-batch-{}", id_text(new_id().unwrap())));
    let mut db = Store::open(&dir).unwrap();
    let scan = [1; 16];
    let attempt = [2; 16];
    db.begin(scan, attempt, &Job::example(Backend::Simulation), false)
        .unwrap();
    let rows = vec![
        Row {
            ip: "198.18.0.2".into(),
            port: 80,
            open: true,
        },
        Row {
            ip: "198.18.0.2".into(),
            port: 443,
            open: true,
        },
    ];
    let event = Envelope::new([3; 16], scan, attempt, 1, Event::Results(rows.clone()));
    let saved = db.apply(&event).unwrap();
    assert_eq!(saved.len(), 2);
    assert_eq!(saved[0].row, rows[0]);
    assert!(saved[0].discovered_at.is_some());
    let first = saved[0].discovered_at.clone();
    assert!(db.apply(&event).unwrap().is_empty());
    let changed = Row {
        open: false,
        ..rows[0].clone()
    };
    let updated = db
        .apply(&Envelope::new(
            [3; 16],
            scan,
            attempt,
            2,
            Event::Results(vec![changed.clone()]),
        ))
        .unwrap();
    assert_eq!(updated[0].row, changed);
    assert_eq!(updated[0].discovered_at, first);
    assert_eq!(db.observations(scan).unwrap()[0].discovered_at, first);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn failed_result_transaction_exposes_no_uncommitted_rows() {
    let dir =
        std::env::temp_dir().join(format!("studio-batch-fail-{}", id_text(new_id().unwrap())));
    let mut db = Store::open(&dir).unwrap();
    let scan = [1; 16];
    let attempt = [2; 16];
    db.begin(scan, attempt, &Job::example(Backend::Simulation), false)
        .unwrap();
    let sql = rusqlite::Connection::open(dir.join("history.sqlite3")).unwrap();
    sql.execute_batch("CREATE TRIGGER fail_sequence BEFORE UPDATE OF sequence ON scans BEGIN SELECT RAISE(ABORT,'injected commit failure'); END;").unwrap();
    assert!(
        db.apply(&Envelope::new(
            [3; 16],
            scan,
            attempt,
            1,
            Event::Results(vec![Row {
                ip: "198.18.0.2".into(),
                port: 80,
                open: true
            }])
        ))
        .is_err()
    );
    assert!(db.rows(scan).unwrap().is_empty());
    drop(sql);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}
