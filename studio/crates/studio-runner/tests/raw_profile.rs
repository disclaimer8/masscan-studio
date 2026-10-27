use std::{
    io::{BufReader, BufWriter},
    process::{ChildStdin, ChildStdout, Command as Process, Stdio},
};
use studio_protocol::*;

struct Runner {
    child: std::process::Child,
    input: BufWriter<ChildStdin>,
    output: BufReader<ChildStdout>,
}
fn spawn() -> Runner {
    let mut child = Process::new(env!("CARGO_BIN_EXE_studio-runner"))
        .arg("--stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = BufWriter::new(child.stdin.take().unwrap());
    let mut output = BufReader::new(child.stdout.take().unwrap());
    write_frame(
        &mut input,
        &Envelope::new([1; 16], [0; 16], [0; 16], 1, Command::Hello),
    )
    .unwrap();
    assert!(matches!(
        read_frame::<Event>(&mut output).unwrap().payload,
        Event::Hello { .. }
    ));
    Runner {
        child,
        input,
        output,
    }
}

#[test]
fn unprivileged_runner_fails_mac_feth_before_any_adapter() {
    let mut r = spawn();
    let (scan, attempt) = ([2; 16], [3; 16]);
    write_frame(
        &mut r.input,
        &Envelope::new(
            [1; 16],
            scan,
            attempt,
            1,
            Command::Start(Job::example(Backend::MacFeth)),
        ),
    )
    .unwrap();
    // The first event of the attempt must be the refusal: no Started, no adapter.
    let first = loop {
        let e = read_frame::<Event>(&mut r.output).unwrap();
        if e.attempt == attempt {
            break e;
        }
    };
    let Event::Finished { status, detail } = first.payload else {
        panic!(
            "first attempt event must be Finished, got {:?}",
            first.payload
        );
    };
    assert_eq!(status, Status::Failed);
    if cfg!(target_os = "macos") {
        // Unique to the root check: the masked-MAC and manifest refusals of the
        // preflight must not satisfy this, or reordering would go unnoticed.
        assert!(detail.contains("Authorize first"), "{detail}");
        assert!(
            !detail.contains("os-masked") && !detail.contains("stand manifest"),
            "{detail}"
        );
    } else {
        // Off macOS the gate itself must refuse; `check_feth` must not be what stops it.
        assert!(detail.contains("not enabled for this profile"), "{detail}");
    }
    // The runner stays alive after the refusal and accepts CloseSession.
    write_frame(
        &mut r.input,
        &Envelope::new([1; 16], scan, attempt, 2, Command::CloseSession),
    )
    .unwrap();
    drop(r.input);
    assert!(r.child.wait().unwrap().success());
}

#[test]
fn check_network_without_root_refuses_and_names_masking_or_manifest() {
    let mut r = spawn();
    write_frame(
        &mut r.input,
        &Envelope::new([1; 16], [0; 16], [0; 16], 2, Command::CheckNetwork),
    )
    .unwrap();
    let (ready, detail) = loop {
        let e = read_frame::<Event>(&mut r.output).unwrap();
        if let Event::NetworkChecked { ready, detail } = e.payload {
            break (ready, detail);
        }
    };
    assert!(!ready, "{detail}");
    if cfg!(target_os = "macos") {
        assert!(
            detail.contains("stand manifest") || detail.contains("os-masked"),
            "{detail}"
        );
    } else {
        assert!(
            detail.contains("unavailable") || detail.contains("only available on macOS"),
            "{detail}"
        );
    }
    write_frame(
        &mut r.input,
        &Envelope::new([1; 16], [0; 16], [0; 16], 3, Command::CloseSession),
    )
    .unwrap();
    let _ = r.child.wait();
}
