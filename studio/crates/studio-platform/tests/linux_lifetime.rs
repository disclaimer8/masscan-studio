#![cfg(target_os = "linux")]
use std::{
    fs,
    path::Path,
    process::{Child, Command},
    time::{Duration, Instant},
};
use studio_platform::linux::arm_parent_death;

fn wait_file(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(child.try_wait().unwrap().is_none(), "fixture exited early");
        assert!(Instant::now() < deadline, "fixture timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn wrong_parent_is_rejected() {
    assert!(arm_parent_death(0).is_err());
    assert!(arm_parent_death(std::process::id()).is_err());
}
#[test]
fn child_dies_when_spawning_parent_dies() {
    let dir = std::env::temp_dir().join(format!("studio-pdeath-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let ready = dir.join("ready");
    let mut parent = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "fixture"])
        .env("STUDIO_PDEATH_ROLE", "parent")
        .env("STUDIO_PDEATH_READY", &ready)
        .spawn()
        .unwrap();
    wait_file(&ready, &mut parent);
    let pid: u32 = fs::read_to_string(&ready).unwrap().parse().unwrap();
    parent.kill().unwrap();
    parent.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // An unreaped zombie has stopped executing, even if CI's init has not
        // yet reaped it. Never signal this numeric PID (could have been reused).
        match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Ok(stat) if stat.rsplit_once(')').unwrap().1.split_whitespace().next() == Some("Z") => {
                break;
            }
            _ => {}
        }
        assert!(Instant::now() < deadline, "child survived its parent");
        std::thread::sleep(Duration::from_millis(10));
    }
    fs::remove_file(ready).unwrap();
    fs::remove_dir(dir).unwrap();
}
#[test]
#[ignore = "parent/child subprocess fixture"]
fn fixture() {
    let ready = std::env::var_os("STUDIO_PDEATH_READY").expect("fixture ready path");
    if std::env::var("STUDIO_PDEATH_ROLE").unwrap() == "parent" {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "fixture"])
            .env("STUDIO_PDEATH_ROLE", "child")
            .env("STUDIO_PDEATH_PARENT", std::process::id().to_string())
            .spawn()
            .unwrap();
        let _ = child.wait();
    } else {
        arm_parent_death(
            std::env::var("STUDIO_PDEATH_PARENT")
                .unwrap()
                .parse()
                .unwrap(),
        )
        .unwrap();
        fs::write(ready, std::process::id().to_string()).unwrap();
        std::thread::sleep(Duration::from_secs(10));
        panic!("parent-death protection did not fire");
    }
}
