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
