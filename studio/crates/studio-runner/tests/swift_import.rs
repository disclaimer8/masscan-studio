use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use studio_app::{Action, Controller, Update};
use studio_protocol::*;
fn directory() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "studio-import-controller-{}",
        id_text(new_id().unwrap())
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}
fn wait(app: &mut Controller, mut predicate: impl FnMut(Update) -> bool) {
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        for update in app.poll() {
            if predicate(update) {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("expected controller update not received");
}
#[cfg(target_os = "macos")]
#[test]
fn manual_import_and_resume_refusal_never_launch_a_runner() {
    let root = directory();
    let source = root.join("source");
    std::fs::create_dir(&source).unwrap();
    let s = serde_json::json!([{"id":"01010101-0101-0101-0101-010101010101","name":"Legacy","date":0.5,"config":{"targets":"192.0.2.1","ports":"80","exclusions":"","interface":"en0","rate":100,"seed":1,"resumeIndex":5},"status":"Paused","results":[{"ip":"192.0.2.1","port":80,"proto":"tcp","discoveredAt":0.25}],"log":"old log","percent":50}]);
    std::fs::write(source.join("sessions.json"), s.to_string()).unwrap();
    std::fs::write(source.join("profiles.json"), "[]").unwrap();
    let data = root.join("data");
    let mut app = Controller::open(data.clone(), root.join("runner-does-not-exist")).unwrap();
    app.send(Action::ImportSwift(source.clone())).unwrap();
    wait(&mut app, |u| match u {
        Update::ImportFinished(r) => {
            assert_eq!(r.unwrap().imported, 1);
            true
        }
        _ => false,
    });
    app.send(Action::Resume).unwrap();
    wait(
        &mut app,
        |u| matches!(u,Update::Notice(s) if s.contains("Imported Swift")),
    );
    app.send(Action::ImportSwift(source)).unwrap();
    wait(&mut app, |u| match u {
        Update::ImportFinished(r) => {
            assert_eq!(r.unwrap().skipped, 1);
            true
        }
        _ => false,
    });
    drop(app);
    // A cached report on reopen must not masquerade as the new command's result.
    let mut app = Controller::open(data.clone(), root.join("runner-does-not-exist")).unwrap();
    app.send(Action::ImportSwift(root.join("missing-source")))
        .unwrap();
    wait(&mut app, |u| match u {
        Update::ImportFinished(result) => {
            assert!(
                result.is_err(),
                "received a stale successful report for a new failing import"
            );
            true
        }
        _ => false,
    });
    drop(app);
    let db = studio_store::Store::open(&data).unwrap();
    let saved = db.scans().unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].status, Status::Paused);
    assert!(saved[0].checkpoint.is_none());
    assert_eq!(db.rows(saved[0].scan).unwrap().len(), 1);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn active_scan_refuses_import_before_reading_source() {
    let root = directory();
    let mut app = Controller::open(
        root.join("data"),
        PathBuf::from(env!("CARGO_BIN_EXE_studio-runner")),
    )
    .unwrap();
    let mut job = Job::example(Backend::Simulation);
    job.ports = "1-1000".into();
    job.rate = 1;
    app.send(Action::Start(job)).unwrap();
    wait(&mut app, |u| {
        matches!(u, Update::State(Status::Scanning, _))
    });
    app.send(Action::ImportSwift(root.join("missing"))).unwrap();
    wait(&mut app, |u| match u {
        Update::ImportFinished(Err(e)) => {
            assert!(e.contains("active scan"), "{e}");
            true
        }
        _ => false,
    });
    app.send(Action::Stop).unwrap();
    wait(&mut app, |u| matches!(u, Update::State(Status::Stopped, _)));
    drop(app);
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(not(target_os = "macos"))]
#[test]
fn manual_import_is_macos_only() {
    let root = directory();
    let mut app = Controller::open(root.join("data"), root.join("missing-runner")).unwrap();
    app.send(Action::ImportSwift(root.join("missing-source")))
        .unwrap();
    wait(&mut app, |u| match u {
        Update::ImportFinished(Err(e)) => {
            assert!(e.contains("macOS"));
            true
        }
        _ => false,
    });
    drop(app);
    std::fs::remove_dir_all(root).unwrap();
}
