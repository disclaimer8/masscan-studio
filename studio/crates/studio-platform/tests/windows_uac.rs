#![cfg(windows)]
use std::{
    process::Command,
    time::{Duration, Instant},
};
use studio_platform::windows::{Process, uac::LifetimeJob};

#[test]
fn elevation_is_observed_on_the_retained_process() {
    let process = Process::open(std::process::id()).unwrap();
    let elevation = process.elevation().unwrap();
    println!(
        "Native token: elevated={}, kind={}, logon={:?}",
        elevation.elevated,
        elevation.kind,
        process.identity().logon
    );
    assert!((1..=3).contains(&elevation.kind));
}

#[test]
fn closing_ui_job_kills_an_attached_runner() {
    let job = LifetimeJob::create().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "job_child"])
        .env("STUDIO_TEST_JOB", job.name())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !job.contains(child.id()).unwrap() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "child exited before attach"
        );
        assert!(Instant::now() < deadline, "child did not attach");
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(job);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        assert!(Instant::now() < deadline, "child survived owner job close");
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
#[ignore = "subprocess fixture for job lifetime"]
fn job_child() {
    let name = std::env::var("STUDIO_TEST_JOB").unwrap();
    let me = Process::open(std::process::id()).unwrap();
    LifetimeJob::join(&name, &me.identity().sid).unwrap();
    std::thread::sleep(Duration::from_secs(20));
    panic!("job did not kill child");
}

#[test]
fn abrupt_owner_death_closes_the_only_job_handle() {
    let ready = std::env::temp_dir().join(format!("studio-job-{}.json", std::process::id()));
    let mut owner = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "job_owner"])
        .env("STUDIO_TEST_JOB_READY", &ready)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let record = loop {
        if let Ok(bytes) = std::fs::read(&ready) {
            if let Ok(identity) =
                serde_json::from_slice::<studio_platform::windows::Identity>(&bytes)
            {
                break identity;
            }
        }
        assert!(
            owner.try_wait().unwrap().is_none(),
            "owner exited before readiness"
        );
        assert!(Instant::now() < deadline, "owner did not report readiness");
        std::thread::sleep(Duration::from_millis(10));
    };
    let runner = Process::open(record.pid).unwrap();
    runner.verify(&record).unwrap();
    owner.kill().unwrap();
    owner.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while runner.ensure_alive().is_ok() {
        assert!(Instant::now() < deadline, "runner survived abrupt UI death");
        std::thread::sleep(Duration::from_millis(10));
    }
    std::fs::remove_file(ready).unwrap();
}

#[test]
#[ignore = "subprocess fixture for abrupt UI death"]
fn job_owner() {
    let job = LifetimeJob::create().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "job_child"])
        .env("STUDIO_TEST_JOB", job.name())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !job.contains(child.id()).unwrap() {
        assert!(child.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let runner = Process::open(child.id()).unwrap();
    std::fs::write(
        std::env::var_os("STUDIO_TEST_JOB_READY").unwrap(),
        serde_json::to_vec(runner.identity()).unwrap(),
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(20));
    panic!("parent did not terminate fixture");
}

#[test]
fn malformed_missing_and_wrong_owner_jobs_are_rejected() {
    let sid = Process::open(std::process::id())
        .unwrap()
        .identity()
        .sid
        .clone();
    assert!(LifetimeJob::join("Global\\arbitrary", &sid).is_err());
    assert!(
        LifetimeJob::join(
            "Local\\MasscanStudioJob-00000000000000000000000000000000",
            &sid
        )
        .is_err()
    );
    let job = LifetimeJob::create().unwrap();
    assert!(LifetimeJob::join(job.name(), "S-1-5-18").is_err());
}
