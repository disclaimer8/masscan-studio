use std::{
    path::PathBuf,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
fn fixture() -> &'static PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(||{
        let dir=std::env::temp_dir().join(format!("studio-child-contract-{}",std::process::id()));std::fs::create_dir_all(&dir).unwrap();
        let source=dir.join("child.rs");let binary=dir.join(format!("child{}",std::env::consts::EXE_SUFFIX));
        std::fs::write(&source,r#"use std::io::Write;fn main(){match std::env::args().nth(1).as_deref(){Some("sleep"|"--reverse"|"--unprivileged")=>std::thread::sleep(std::time::Duration::from_secs(20)),Some("flood")=>{let _=std::io::stdout().write_all(&vec![b'x';100000]);},_=>print!("ok")}}"#).unwrap();
        assert!(std::process::Command::new("rustc").arg(&source).arg("-o").arg(&binary).status().unwrap().success());binary
    })
}
#[test]
fn timeout_cancel_and_oversize_are_bounded_and_reaped() {
    let exe = fixture();
    let flag = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    assert!(
        studio_inspection::process::capture(
            exe,
            &["sleep".into()],
            Duration::from_millis(100),
            4096,
            &flag
        )
        .unwrap_err()
        .contains("deadline")
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(
        studio_inspection::process::capture(
            exe,
            &["flood".into()],
            Duration::from_secs(3),
            4096,
            &flag
        )
        .unwrap_err()
        .contains("size")
    );
    let f = flag.clone();
    let trigger = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        f.store(true, Ordering::Release);
    });
    let start = Instant::now();
    assert_eq!(
        studio_inspection::process::capture(
            exe,
            &["sleep".into()],
            Duration::from_secs(20),
            4096,
            &flag
        )
        .unwrap_err(),
        "Cancelled"
    );
    trigger.join().unwrap();
    assert!(start.elapsed() < Duration::from_secs(2));
}
#[test]
fn ptr_rejects_compression_truncation_and_trailing_bytes() {
    assert_eq!(
        studio_inspection::decode_ptr(b"\x04host\x05local\0"),
        Some("host.local".into())
    );
    for bad in [&b"\xc0\x0c"[..], &b"\x04abc"[..], &b"\x01x\0junk"[..]] {
        assert!(studio_inspection::decode_ptr(bad).is_none());
    }
}

#[test]
fn dropping_pool_cancels_active_and_queued_children() {
    use studio_inspection::{
        Request,
        tasks::{Kind, Task, Tasks},
    };
    let exe = fixture();
    let tasks = Tasks::new(exe.clone(), Some(exe.clone()));
    for id in 0..16 {
        tasks
            .submit(
                Kind::Dns,
                Task {
                    id,
                    ip: "127.0.0.1".parse().unwrap(),
                    request: None,
                    cancel: Arc::new(AtomicBool::new(false)),
                },
            )
            .unwrap();
    }
    tasks
        .submit(
            Kind::Nmap,
            Task {
                id: 17,
                ip: "127.0.0.1".parse().unwrap(),
                request: Some(Request::new("127.0.0.1", vec![80]).unwrap()),
                cancel: Arc::new(AtomicBool::new(false)),
            },
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(150));
    let start = Instant::now();
    drop(tasks);
    assert!(start.elapsed() < Duration::from_secs(2));
}
