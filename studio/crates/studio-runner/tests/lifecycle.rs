use std::{
    io::{BufReader, BufWriter},
    process::{Command as Process, Stdio},
};
use studio_protocol::*;
#[test]
fn real_engine_pause_checkpoint_ack_and_resume_on_same_runner() {
    let mut child = Process::new(env!("CARGO_BIN_EXE_studio-runner"))
        .arg("--stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = BufWriter::new(child.stdin.take().unwrap());
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let session = [1; 16];
    let scan = [2; 16];
    let attempt = [3; 16];
    write_frame(
        &mut input,
        &Envelope::new(session, [0; 16], [0; 16], 1, Command::Hello),
    )
    .unwrap();
    assert!(matches!(
        read_frame::<Event>(&mut output).unwrap().payload,
        Event::Hello { .. }
    ));
    let mut job = Job::example(Backend::Simulation);
    job.ports = "8000-8099".into();
    job.rate = 10;
    write_frame(
        &mut input,
        &Envelope::new(session, scan, attempt, 1, Command::Start(job.clone())),
    )
    .unwrap();
    let mut paused = false;
    let mut cp = None;
    loop {
        let e = read_frame::<Event>(&mut output).unwrap();
        match e.payload {
            Event::Started { .. } if !paused => {
                write_frame(
                    &mut input,
                    &Envelope::new(session, scan, attempt, 2, Command::Pause),
                )
                .unwrap();
                paused = true;
            }
            Event::Checkpoint { bytes, .. } => {
                cp = Some(bytes);
                write_frame(
                    &mut input,
                    &Envelope::new(
                        session,
                        scan,
                        attempt,
                        3,
                        Command::AckCheckpoint {
                            through: e.sequence,
                        },
                    ),
                )
                .unwrap();
            }
            Event::Finished { status, .. } => {
                assert_eq!(status, Status::Paused);
                break;
            }
            _ => {}
        }
    }
    write_frame(
        &mut input,
        &Envelope::new(
            session,
            scan,
            [4; 16],
            1,
            Command::Resume {
                job,
                checkpoint: cp.unwrap(),
            },
        ),
    )
    .unwrap();
    write_frame(
        &mut input,
        &Envelope::new(session, scan, [4; 16], 2, Command::Stop),
    )
    .unwrap();
    loop {
        if let Event::Finished { status, .. } = read_frame::<Event>(&mut output).unwrap().payload {
            assert_eq!(status, Status::Stopped);
            break;
        }
    }
    drop(input);
    assert!(child.wait().unwrap().success());
}
