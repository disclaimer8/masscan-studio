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
    // Allow the runner's 10-second handshake plus cold VM process startup.
    let deadline = Instant::now() + Duration::from_secs(20);
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
    // Closed profile (Windows/Linux): the old build gate text. Open profile
    // (macOS): an unauthorized raw Start fails without a dialog or a runner.
    let expected = if studio_protocol::raw_profile_enabled(Backend::MacFeth) {
        "Authorize the runner before starting a raw scan"
    } else {
        "Raw scanning is not enabled"
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut refused = false;
    while Instant::now() < deadline && !refused {
        for u in app.poll() {
            if let Update::State(s, detail) = u {
                assert_ne!(s, Status::Interrupted, "{detail}");
                assert_ne!(s, Status::Scanning, "must not start the raw adapter");
                if s == Status::Failed {
                    assert!(detail.contains(expected), "{detail}");
                    refused = true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(refused);
    // The controller survives the refusal.
    app.send(Action::Start(Job::example(Backend::Simulation)))
        .expect("controller must survive a refused raw start");
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut completed = false;
    while Instant::now() < deadline && !completed {
        for u in app.poll() {
            if let Update::State(s, detail) = u {
                assert_ne!(s, Status::Interrupted, "{detail}");
                completed |= s == Status::Completed;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(completed, "Simulation still runs after the refusal");
    drop(app);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A parallel test's fork may briefly inherit the history lock descriptor
/// before exec, so a just-released directory can still look busy for a moment.
#[cfg(target_os = "macos")]
fn retry<T, E: std::fmt::Debug>(mut open: impl FnMut() -> Result<T, E>) -> T {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match open() {
            Ok(v) => return v,
            Err(e) if Instant::now() >= deadline || !format!("{e:?}").contains("already using") => {
                panic!("{e:?}")
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn raw_resume_without_authorization_keeps_the_checkpoint() {
    let dir =
        std::env::temp_dir().join(format!("studio-raw-resume-{}", id_text(new_id().unwrap())));
    let job = Job::example(Backend::MacFeth);
    let (scan, attempt) = (new_id().unwrap(), new_id().unwrap());
    let plan = job.prepare().unwrap();
    let bytes = rmasscan_engine::Checkpoint {
        format_version: 1,
        engine_version: ENGINE_VERSION,
        scan_id: scan,
        attempt_id: attempt,
        job_digest: rmasscan_engine::job_digest(&plan),
        next_index: 1,
    }
    .to_bytes();
    let saved = {
        let mut store = retry(|| studio_store::Store::open(&dir));
        store.begin(scan, attempt, &job, false).unwrap();
        for (n, payload) in [
            Event::Checkpoint {
                bytes,
                next_index: "1".into(),
            },
            Event::Finished {
                status: Status::Paused,
                detail: "Checkpoint committed by Studio".into(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            store
                .apply(&Envelope::new(
                    [1; 16],
                    scan,
                    attempt,
                    n as u64 + 1,
                    payload,
                ))
                .unwrap();
        }
        let saved = store.scans().unwrap().remove(0);
        assert_eq!(saved.status, Status::Paused);
        assert!(saved.checkpoint.is_some());
        saved
    };
    let mut app =
        retry(|| Controller::open(dir.clone(), env!("CARGO_BIN_EXE_studio-runner").into()));
    app.send(Action::Resume).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut gated = false;
    while Instant::now() < deadline && !gated {
        for u in app.poll() {
            if let Update::State(s, detail) = u {
                assert_ne!(s, Status::Scanning, "must not open the raw adapter");
                if s == Status::Interrupted {
                    assert!(detail.contains("Raw resume is gated"), "{detail}");
                    gated = true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(gated, "unauthorized raw Resume is refused");
    drop(app);
    let after = retry(|| studio_store::Store::open(&dir))
        .scans()
        .unwrap()
        .remove(0);
    assert_eq!(after.status, Status::Paused);
    assert_eq!(after.checkpoint, saved.checkpoint);
    assert_eq!(after.attempt, saved.attempt);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn failed_authorization_leaves_simulation_and_history_usable() {
    let dir = std::env::temp_dir().join(format!(
        "studio-auth-recover-{}",
        id_text(new_id().unwrap())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let runner = dir.join(format!("runner{}", std::env::consts::EXE_SUFFIX));
    let mut app = Controller::open(dir.join("data"), runner.clone()).unwrap();
    app.send(Action::Authorize).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut refused = false;
    while Instant::now() < deadline && !refused {
        for u in app.poll() {
            if let Update::Authorization {
                busy: false,
                authorized: false,
                detail,
            } = u
            {
                assert!(!detail.is_empty());
                refused = true;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        refused,
        "uninstalled/unsupported authorization must fail without OS prompt"
    );
    std::fs::copy(env!("CARGO_BIN_EXE_studio-runner"), runner).unwrap();
    app.send(Action::Start(Job::example(Backend::Simulation)))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
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
