#![cfg(windows)]
use std::{
    io::BufWriter,
    process::{Child, Command, Stdio},
    sync::{atomic::AtomicBool, mpsc},
    time::{Duration, Instant},
};
use studio_platform::windows::{Endpoint, Identity, Process, Stream};
use studio_protocol::*;

struct Runner(Child);
impl Drop for Runner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn launch(endpoint: &Endpoint, ui: &Identity) -> Runner {
    Runner(
        Command::new(env!("CARGO_BIN_EXE_studio-runner"))
            .arg("--connect-pipe")
            .arg(endpoint.name())
            .arg(serde_json::to_string(ui).unwrap())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    )
}
fn wait(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return s;
        }
        if Instant::now() > deadline {
            panic!("runner survived closed pipe");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn event(stream: &Stream) -> Envelope<Event> {
    let mut reader = stream.clone();
    let (tx, rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let _ = tx.send(read_frame::<Event>(&mut reader));
    });
    let result = rx.recv_timeout(Duration::from_secs(3));
    if result.is_err() {
        stream.shutdown();
    }
    thread.join().unwrap();
    result.expect("runner event deadline").unwrap()
}
#[test]
fn runner_authenticates_before_hello_and_exits_on_disconnect() {
    let endpoint = Endpoint::create().unwrap();
    let owner = Identity::current().unwrap();
    let mut child = launch(&endpoint, &owner);
    let peer = Process::open(child.0.id()).unwrap();
    let stream = endpoint
        .accept(peer, Duration::from_secs(3), &AtomicBool::new(false))
        .unwrap();
    let mut writer = BufWriter::new(stream.clone());
    write_frame(
        &mut writer,
        &Envelope::new(
            [1; 16],
            [0; 16],
            [0; 16],
            1,
            studio_protocol::Command::Hello,
        ),
    )
    .unwrap();
    assert!(matches!(
        event(&stream).payload,
        Event::Hello {
            engine: ENGINE_VERSION
        }
    ));
    let mut job = Job::example(Backend::Simulation);
    job.rate = 1;
    write_frame(
        &mut writer,
        &Envelope::new(
            [1; 16],
            [2; 16],
            [3; 16],
            1,
            studio_protocol::Command::Start(job),
        ),
    )
    .unwrap();
    assert!(matches!(event(&stream).payload, Event::Started { .. }));
    stream.shutdown();
    assert!(wait(&mut child.0).success());
}
#[test]
fn stale_ui_identity_is_rejected_before_handshake() {
    let endpoint = Endpoint::create().unwrap();
    let mut owner = Identity::current().unwrap();
    owner.birth ^= 1;
    let mut child = launch(&endpoint, &owner);
    assert!(!wait(&mut child.0).success());
}
