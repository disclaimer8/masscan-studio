//! Explicit local-only acceptance, never part of offline CI.
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
#[test]
#[ignore = "requires separately installed Nmap; only probes our loopback listener"]
fn real_unprivileged_nmap_inspects_owned_loopback_http_server() {
    let nmap =
        studio_inspection::process::find_nmap().expect("Install Nmap before this explicit test");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let server = std::thread::spawn(move || {
        while !flag.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut s, _)) => {
                    s.set_nonblocking(true).unwrap();
                    let deadline = std::time::Instant::now() + Duration::from_millis(150);
                    loop {
                        match s.read(&mut [0;4096]) {
                            Err(e) if e.kind()==std::io::ErrorKind::WouldBlock && std::time::Instant::now()<deadline => std::thread::sleep(Duration::from_millis(5)),
                            _ => break,
                        }
                    }
                    let _=s.write_all(b"HTTP/1.0 200 OK\r\nServer: StudioFixture/1.0\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("{e}"),
            }
        }
    });
    let request = studio_inspection::Request::new("127.0.0.1", vec![port]).unwrap();
    let result = studio_inspection::process::inspect(&nmap, &request, &AtomicBool::new(false));
    stop.store(true, Ordering::Release);
    server.join().unwrap();
    let result = result.unwrap();
    assert_eq!(result.services.len(), 1);
    assert_eq!(result.services[0].port, port);
    assert_eq!(result.services[0].state, "open");
    assert_eq!(result.services[0].name, "http");
    assert_eq!(result.services[0].method, "probed");
    println!("Loopback Nmap: {}", result.services[0].summary());
}
#[test]
#[ignore = "queries the host system resolver for loopback only"]
fn real_resolver_child_returns_valid_loopback_response() {
    let worker = std::path::Path::new(env!("CARGO_BIN_EXE_studio-inspect"));
    let result = studio_inspection::process::resolve(
        worker,
        "127.0.0.1".parse().unwrap(),
        &AtomicBool::new(false),
    )
    .unwrap();
    if let Some(name) = &result {
        assert!(studio_inspection::valid_hostname(name).is_some());
    }
    println!("Loopback system resolver: {result:?}");
}
