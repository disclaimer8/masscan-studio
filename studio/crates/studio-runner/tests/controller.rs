use std::time::{Duration, Instant};
use studio_app::{Action, Controller, Update};
use studio_protocol::*;
#[test]
fn controller_persists_pause_before_resume_and_survives_restart() {
    let runner = std::path::PathBuf::from(env!("CARGO_BIN_EXE_studio-runner"));
    let dir = std::env::temp_dir().join(format!("studio-flow-{}", id_text(new_id().unwrap())));
    let mut app = Controller::open(dir.clone(), runner.clone()).unwrap();
    let mut job = Job::example(Backend::Simulation);
    job.ports = "8000-8031".into();
    job.rate = 4;
    app.send(Action::Start(job)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut pause = false;
    let mut got = false;
    while Instant::now() < deadline {
        for u in app.poll() {
            if let Update::State(s, _) = u {
                if s == Status::Scanning && !pause {
                    app.send(Action::Pause).unwrap();
                    pause = true;
                }
                if s == Status::Paused {
                    got = true;
                }
            }
        }
        if got {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(got, "pause was committed and acknowledged");
    drop(app);
    let store = studio_store::Store::open(&dir).unwrap();
    let scans = store.scans().unwrap();
    assert_eq!(scans[0].status, Status::Paused);
    assert!(scans[0].checkpoint.is_some());
    drop(store);
    // A runner may reject Resume before its adapter starts. The previously
    // committed checkpoint must survive that attempt and remain retryable.
    {
        let mut store = studio_store::Store::open(&dir).unwrap();
        let saved = store.scans().unwrap().remove(0);
        let retry = new_id().unwrap();
        store.begin(saved.scan, retry, &saved.job, true).unwrap();
        assert_eq!(store.scans().unwrap()[0].checkpoint, saved.checkpoint);
        store
            .apply(&Envelope::new(
                [1; 16],
                saved.scan,
                retry,
                1,
                Event::Finished {
                    status: Status::Failed,
                    detail: "adapter unavailable".into(),
                },
            ))
            .unwrap();
        let after = store.scans().unwrap().remove(0);
        assert_eq!(after.status, Status::Paused);
        assert_eq!(after.checkpoint, saved.checkpoint);
    }
    let mut app = Controller::open(dir.clone(), runner).unwrap();
    app.send(Action::Resume).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut resumed = false;
    let mut stopped = false;
    while Instant::now() < deadline && !stopped {
        for u in app.poll() {
            if let Update::State(s, detail) = u {
                assert!(
                    !matches!(s, Status::Failed | Status::Interrupted),
                    "{detail}"
                );
                if s == Status::Scanning {
                    resumed = true;
                    app.send(Action::Stop).unwrap();
                }
                stopped |= s == Status::Stopped;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        resumed && stopped,
        "saved checkpoint resumes after application restart"
    );
    drop(app);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn failed_runner_launch_does_not_disable_future_scans() {
    let dir = std::env::temp_dir().join(format!("studio-retry-{}", id_text(new_id().unwrap())));
    std::fs::create_dir_all(&dir).unwrap();
    let runner = dir.join(format!("runner{}", std::env::consts::EXE_SUFFIX));
    let mut app = Controller::open(dir.join("history"), runner.clone()).unwrap();
    let job = Job::example(Backend::Simulation);
    app.send(Action::Start(job.clone())).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut failed = false;
    while Instant::now() < deadline && !failed {
        failed = app
            .poll()
            .iter()
            .any(|u| matches!(u, Update::State(Status::Interrupted, _)));
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(failed);
    std::fs::copy(env!("CARGO_BIN_EXE_studio-runner"), &runner).unwrap();
    app.send(Action::Start(job))
        .expect("controller must survive launch failure");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut completed = false;
    while Instant::now() < deadline && !completed {
        for u in app.poll() {
            if let Update::State(status, detail) = u {
                assert_ne!(status, Status::Interrupted, "{detail}");
                completed |= status == Status::Completed;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(completed);
    drop(app);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn incomplete_raw_integration_refuses_before_opening_an_adapter() {
    let dir = std::env::temp_dir().join(format!("studio-raw-gate-{}", id_text(new_id().unwrap())));
    let mut app =
        Controller::open(dir.clone(), env!("CARGO_BIN_EXE_studio-runner").into()).unwrap();
    app.send(Action::Start(Job::example(Backend::MacFeth)))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut refused = false;
    while Instant::now() < deadline && !refused {
        for u in app.poll() {
            if let Update::State(s, detail) = u {
                assert_ne!(s, Status::Scanning, "must not start the raw adapter");
                if s == Status::Failed {
                    assert!(detail.contains("Raw scanning is not enabled"), "{detail}");
                    refused = true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(refused);
    drop(app);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn hundred_thousand_results_survive_a_display_polled_at_twenty_hz() {
    let dir = std::env::temp_dir().join(format!("studio-volume-{}", id_text(new_id().unwrap())));
    let mut app =
        Controller::open(dir.clone(), env!("CARGO_BIN_EXE_studio-runner").into()).unwrap();
    let mut job = Job::example(Backend::Simulation);
    job.targets = "198.18.0.2-198.18.0.11".into();
    job.ports = "1-10000".into();
    job.rate = 10000;
    app.send(Action::Start(job)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut rows = 0;
    let mut completed = false;
    while Instant::now() < deadline && !completed {
        for u in app.poll() {
            match u {
                Update::Rows(batch) => rows += batch.len(),
                Update::State(s, detail) => {
                    assert!(
                        !matches!(s, Status::Failed | Status::Interrupted),
                        "{detail}"
                    );
                    completed |= s == Status::Completed;
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(completed);
    assert_eq!(rows, 100000);
    drop(app);
    let db = studio_store::Store::open(&dir).unwrap();
    let scan = db.scans().unwrap().remove(0);
    assert_eq!(scan.status, Status::Completed);
    assert_eq!(db.rows(scan.scan).unwrap().len(), 100000);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}
