#![cfg(windows)]
use std::{
    io::{Read, Write},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
use studio_platform::windows::{Endpoint, Identity, Process, Stream};

#[test]
fn authenticated_pipe_roundtrips_and_shutdown_wakes_reader() {
    let owner = Identity::current().unwrap();
    let endpoint = Endpoint::create().unwrap();
    let name = endpoint.name().to_owned();
    let expected = Process::open(std::process::id()).unwrap();
    let child = std::thread::spawn(move || {
        Stream::connect(
            &name,
            &owner,
            Duration::from_secs(3),
            &AtomicBool::new(false),
        )
        .unwrap()
    });
    let mut server = endpoint
        .accept(expected, Duration::from_secs(3), &AtomicBool::new(false))
        .unwrap();
    let mut client = child.join().unwrap();
    server.write_all(b"hello").unwrap();
    let mut bytes = [0; 5];
    client.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"hello");
    client.write_all(b"world").unwrap();
    server.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"world");
    let mut reader = server.clone();
    let waiting = std::thread::spawn(move || reader.read(&mut [0; 1]));
    std::thread::sleep(Duration::from_millis(20));
    let began = Instant::now();
    server.shutdown();
    assert!(waiting.join().unwrap().is_err());
    assert!(began.elapsed() < Duration::from_secs(2));
}

#[test]
fn stale_identity_and_nonlocal_names_are_refused() {
    let process = Process::open(std::process::id()).unwrap();
    let mut expected = Identity::current().unwrap();
    process.verify(&expected).unwrap();
    expected.birth ^= 1;
    assert!(process.verify(&expected).is_err());
    expected = Identity::current().unwrap();
    expected.sid.push_str("-123");
    assert!(process.verify(&expected).is_err());
    for name in [
        r"\\server\pipe\MasscanStudio-123",
        r"\\.\pipe\other",
        "bad\0name",
    ] {
        assert!(Stream::connect(name, &expected, Duration::ZERO, &AtomicBool::new(false)).is_err());
    }
}

#[test]
fn accept_is_bounded_and_cancellable_without_a_client() {
    for cancelled in [false, true] {
        let endpoint = Endpoint::create().unwrap();
        let expected = Process::open(std::process::id()).unwrap();
        let start = Instant::now();
        assert!(
            endpoint
                .accept(
                    expected,
                    Duration::from_millis(30),
                    &AtomicBool::new(cancelled)
                )
                .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
