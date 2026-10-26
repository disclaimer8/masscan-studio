use studio_protocol::{Backend, Job};
use studio_store::Store;
fn dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "studio-profiles-{}",
        studio_protocol::id_text(studio_protocol::new_id().unwrap())
    ))
}
#[test]
fn profile_roundtrip_update_delete_keeps_history() {
    let d = dir();
    let mut db = Store::open(&d).unwrap();
    let mut job = Job::example(Backend::Simulation);
    job.seed = u64::MAX.to_string();
    let profile = db.save_profile(None, "  Office  ", &job).unwrap();
    assert_eq!(profile.name, "Office");
    drop(db);
    let mut db = Store::open(&d).unwrap();
    let p = db.profiles().unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].job, job);
    let scan = [1; 16];
    db.begin(scan, [2; 16], &job, false).unwrap();
    job.ports = "80,443".into();
    let updated = db.save_profile(Some(profile.id), "OFFICE", &job).unwrap();
    assert_eq!(updated.id, profile.id);
    assert_eq!(db.profiles().unwrap()[0].job, job);
    db.delete_profile(profile.id).unwrap();
    assert!(db.profiles().unwrap().is_empty());
    assert_eq!(db.scans().unwrap().len(), 1);
    drop(db);
    std::fs::remove_dir_all(d).unwrap();
}
#[test]
fn invalid_conflicting_and_stale_changes_are_atomic() {
    let d = dir();
    let mut db = Store::open(&d).unwrap();
    let job = Job::example(Backend::Simulation);
    let first = db.save_profile(None, "Office", &job).unwrap();
    let second = db.save_profile(None, "Home", &job).unwrap();
    assert!(db.save_profile(None, "office", &job).is_err());
    assert!(db.save_profile(Some(second.id), " OFFICE ", &job).is_err());
    assert!(db.save_profile(Some([99; 16]), "Missing", &job).is_err());
    assert!(db.delete_profile([99; 16]).is_err());
    for name in ["", "  ", "new\nline", &"a".repeat(129)] {
        assert!(db.save_profile(None, name, &job).is_err());
    }
    let mut invalid = job.clone();
    invalid.seed = "18446744073709551616".into();
    assert!(db.save_profile(Some(first.id), "Office", &invalid).is_err());
    let saved = db.profiles().unwrap();
    assert_eq!(saved.len(), 2);
    assert!(
        saved
            .iter()
            .any(|p| p.id == first.id && p.name == "Office" && p.job == job)
    );
    assert!(saved.iter().any(|p| p.id == second.id && p.name == "Home"));
    drop(db);
    std::fs::remove_dir_all(d).unwrap();
}
#[test]
fn profile_limit_does_not_prevent_update_or_delete() {
    let d = dir();
    let mut db = Store::open(&d).unwrap();
    let job = Job::example(Backend::Simulation);
    let mut id = [0; 16];
    for i in 0..100 {
        id = db
            .save_profile(None, &format!("profile {i}"), &job)
            .unwrap()
            .id;
    }
    assert!(db.save_profile(None, "overflow", &job).is_err());
    db.save_profile(Some(id), "renamed", &job).unwrap();
    db.delete_profile(id).unwrap();
    db.save_profile(None, "replacement", &job).unwrap();
    assert_eq!(db.profiles().unwrap().len(), 100);
    drop(db);
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn v3_history_and_archived_metadata_survive_without_an_importer() {
    let d = dir();
    let db = Store::open(&d).unwrap();
    drop(db);
    let c = rusqlite::Connection::open(d.join("history.sqlite3")).unwrap();
    let job = Job::example(Backend::Archived);
    c.execute_batch("DROP TABLE profiles; PRAGMA user_version=3; CREATE TABLE legacy_records(data TEXT NOT NULL); INSERT INTO legacy_records VALUES('retained metadata');").unwrap();
    c.execute("INSERT INTO scans(id,attempt,job,status,updated,name,created_at) VALUES(?1,?2,?3,'\"Paused\"',1,'Archived session','2001-01-01T00:00:00.125Z')", rusqlite::params![[1u8;16].as_slice(),[2u8;16].as_slice(),serde_json::to_string(&job).unwrap()]).unwrap();
    c.execute("INSERT INTO results(scan,ip,port,open,discovered_at) VALUES(?1,'192.0.2.1',80,1,'2001-01-01T00:00:00.250Z')",[[1u8;16].as_slice()]).unwrap();
    let db = Store::open(&d).unwrap();
    let history = db.scans().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].job.backend, Backend::Archived);
    assert!(history[0].job.prepare().is_err());
    assert_eq!(db.rows([1; 16]).unwrap().len(), 1);
    assert_eq!(history[0].name.as_deref(), Some("Archived session"));
    assert!(db.profiles().unwrap().is_empty());
    assert_eq!(
        c.query_row("SELECT data FROM legacy_records", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "retained metadata"
    );
    assert_eq!(
        c.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        4
    );
    let backup = std::fs::read_dir(&d)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.extension().is_some_and(|e| e == "sqlite3")
                && p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("before-v4-")
        })
        .unwrap();
    let b =
        rusqlite::Connection::open_with_flags(backup, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    assert_eq!(
        b.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        b.query_row("SELECT count(*) FROM results", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    drop(b);
    drop(db);
    drop(c);
    std::fs::remove_dir_all(d).unwrap();
}
