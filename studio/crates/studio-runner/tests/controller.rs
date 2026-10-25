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
