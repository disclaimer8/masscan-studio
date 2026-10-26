#![cfg(any(target_os = "macos", target_os = "linux"))]
use std::{
    io::{BufReader, BufWriter},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use studio_platform::unix::{Endpoint, Identity};
use studio_protocol::*;

fn wait(mut child: Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return s;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("runner survived closed socket");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn authenticated_child_uses_protocol_and_exits_on_disconnect() {
    let endpoint = Endpoint::create().unwrap();
    let ui = Identity::current().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_studio-runner"))
        .arg("--connect")
        .arg(endpoint.path())
        .arg(serde_json::to_string(&ui).unwrap())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let runner = Identity::read(child.id()).unwrap();
    let stream = endpoint.accept(Duration::from_secs(5), &runner).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut output = BufReader::new(stream.try_clone().unwrap());
    let mut input = BufWriter::new(stream);
    write_frame(
        &mut input,
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
        read_frame::<Event>(&mut output).unwrap().payload,
        Event::Hello {
            engine: ENGINE_VERSION
        }
    ));
    write_frame(
        &mut input,
        &Envelope::new(
            [1; 16],
            [0; 16],
            [0; 16],
            2,
            studio_protocol::Command::CheckNetwork,
        ),
    )
    .unwrap();
    let checked = read_frame::<Event>(&mut output).unwrap();
    assert_eq!(checked.sequence, 2);
    assert!(matches!(checked.payload, Event::NetworkChecked { .. }));
    let mut job = Job::example(Backend::Simulation);
    job.rate = 1;
    write_frame(
        &mut input,
        &Envelope::new(
            [1; 16],
            [2; 16],
            [3; 16],
            1,
            studio_protocol::Command::Start(job),
        ),
    )
    .unwrap();
    assert!(matches!(
        read_frame::<Event>(&mut output).unwrap().payload,
        Event::Started { .. }
    ));
    drop(input);
    drop(output);
    assert!(wait(child).success());
}

#[test]
fn stale_owner_identity_never_reaches_hello() {
    let endpoint = Endpoint::create().unwrap();
    let mut ui = Identity::current().unwrap();
    ui.birth[0] ^= 1;
    let child = Command::new(env!("CARGO_BIN_EXE_studio-runner"))
        .arg("--connect")
        .arg(endpoint.path())
        .arg(serde_json::to_string(&ui).unwrap())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    assert!(!wait(child).success());
}
