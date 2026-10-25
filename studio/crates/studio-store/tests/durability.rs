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
