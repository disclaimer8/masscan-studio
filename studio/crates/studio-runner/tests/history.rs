use std::time::{Duration, Instant};
use studio_app::{Action, Controller, Update};
use studio_protocol::*;

fn wait(app: &mut Controller, mut done: impl FnMut(&Update) -> bool) -> Vec<Update> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut events = Vec::new();
    while Instant::now() < deadline {
        let batch = app.poll();
        let finished = batch.iter().any(&mut done);
        events.extend(batch);
        if finished {
            return events;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("history result timeout");
}
fn result(app: &mut Controller, success: bool) -> Vec<Update> {
    let events = wait(app, |u| matches!(u, Update::HistoryResult(_)));
    assert!(
        events
            .iter()
            .any(|u| matches!(u, Update::HistoryResult(r) if r.is_ok() == success))
    );
    assert!(!events.iter().any(|u| matches!(
        u,
        Update::Authorization { .. }
            | Update::State(Status::Starting | Status::Scanning | Status::Interrupted, _)
    )));
    events
}

#[test]
fn history_changes_without_runner_refresh_selection_and_clear_last_scan() {
    let root = std::env::temp_dir().join(format!(
        "studio-history-controller-{}",
        id_text(new_id().unwrap())
    ));
    let mut db = studio_store::Store::open(&root).unwrap();
    for scan in [[1; 16], [4; 16]] {
        db.begin(scan, [2; 16], &Job::example(Backend::Simulation), false)
            .unwrap();
        db.apply(&Envelope::new(
            [3; 16],
            scan,
            [2; 16],
            1,
            Event::Finished {
                status: Status::Completed,
                detail: "done".into(),
            },
        ))
        .unwrap();
    }
    drop(db);
    let mut app = Controller::open(root.clone(), "missing-runner".into()).unwrap();
    wait(&mut app, |u| matches!(u, Update::History(_, _)));
    app.send(Action::RenameScan {
        id: [4; 16],
        name: "Office".into(),
    })
    .unwrap();
    let events = result(&mut app, true);
    assert!(events.iter().any(|u| matches!(u, Update::History(h, Some(id)) if *id == [4;16] && h[0].name.as_deref() == Some("Office"))));
    app.send(Action::DeleteScan([4; 16])).unwrap();
    let events = result(&mut app, true);
    assert!(
        events
            .iter()
            .any(|u| matches!(u, Update::History(h, Some(id)) if h.len() == 1 && *id == [1;16]))
    );
    app.send(Action::DeleteScan([4; 16])).unwrap();
    result(&mut app, false);
    app.send(Action::DeleteScan([1; 16])).unwrap();
    let events = result(&mut app, true);
    assert!(
        events
            .iter()
            .any(|u| matches!(u, Update::History(h, None) if h.is_empty()))
    );
    assert!(events.iter().any(|u| matches!(u, Update::Clear)));
    app.send(Action::LookupHosts {
        ips: vec!["198.18.0.2".into()],
        refresh: true,
    })
    .unwrap();
    let events = wait(&mut app, |u| matches!(u, Update::Notice(_)));
    assert!(
        events
            .iter()
            .any(|u| matches!(u, Update::Notice(s) if s.contains("Select a saved scan")))
    );
    drop(app);
    let db = studio_store::Store::open(&root).unwrap();
    assert!(db.scans().unwrap().is_empty());
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn active_controller_refuses_edits_even_to_another_saved_scan() {
    let root = std::env::temp_dir().join(format!(
        "studio-active-history-{}",
        id_text(new_id().unwrap())
    ));
    let mut db = studio_store::Store::open(&root).unwrap();
    db.begin([1; 16], [2; 16], &Job::example(Backend::Simulation), false)
        .unwrap();
    db.interrupt([1; 16], "old run").unwrap();
    drop(db);
    let mut app =
        Controller::open(root.clone(), env!("CARGO_BIN_EXE_studio-runner").into()).unwrap();
    wait(&mut app, |u| matches!(u, Update::History(_, _)));
    let mut job = Job::example(Backend::Simulation);
    job.ports = "1-65535".into();
    job.rate = 1;
    app.send(Action::Start(job)).unwrap();
    wait(&mut app, |u| {
        matches!(u, Update::State(Status::Scanning, _))
    });
    app.send(Action::DeleteScan([1; 16])).unwrap();
    result(&mut app, false);
    app.send(Action::RenameScan {
        id: [1; 16],
        name: "Busy".into(),
    })
    .unwrap();
    result(&mut app, false);
    app.send(Action::Stop).unwrap();
    wait(&mut app, |u| matches!(u, Update::State(Status::Stopped, _)));
    drop(app);
    let db = studio_store::Store::open(&root).unwrap();
    let scans = db.scans().unwrap();
    assert_eq!(scans.len(), 2);
    assert!(
        scans
            .iter()
            .find(|s| s.scan == [1; 16])
            .unwrap()
            .name
            .is_none()
    );
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}
