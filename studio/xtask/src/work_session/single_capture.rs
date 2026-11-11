//! Fixed one-target capture supervision and bounded authenticated evidence export.
use super::*;
use studio_platform::single_target::{CaptureWitness, Store};
struct CaptureReservation(Arc<Shared>);
impl Drop for CaptureReservation {
    fn drop(&mut self) {
        let mut s = self.0.state.lock().unwrap();
        s.capture_busy = false;
        s.active -= 1;
    }
}
fn reserve_capture(shared: &Arc<Shared>) -> Result<CaptureReservation> {
    let mut s = shared.state.lock().unwrap();
    if s.stopping || s.closing || s.exclusive || s.fixture_busy || s.capture_busy {
        return Err("Working session busy; capture refused".into());
    }
    s.capture_busy = true;
    s.active += 1;
    Ok(CaptureReservation(shared.clone()))
}
struct CaptureChild {
    child: ChildOwner,
    input: Option<std::process::ChildStdin>,
    out: File,
    err: File,
}
impl CaptureChild {
    fn spawn(shared: &Shared, mut cmd: Command) -> Result<Self> {
        let (out, a, err, b) = outputs(shared)?;
        let mut child = ChildOwner(
            cmd.stdin(Stdio::piped())
                .stdout(a)
                .stderr(b)
                .spawn()
                .map_err(error)?,
        );
        let input = child.0.stdin.take().ok_or("Capture control pipe missing")?;
        Ok(Self {
            child,
            input: Some(input),
            out: File::open(out).map_err(error)?,
            err: File::open(err).map_err(error)?,
        })
    }
    fn run(
        mut self,
        stream: &mut UnixStream,
        mut witness: impl FnMut(u32) -> Result<Option<CaptureWitness>>,
        limit: Duration,
    ) -> Result<i32> {
        use std::io::Seek;
        stream.set_nonblocking(true).map_err(error)?;
        let started = Instant::now();
        let mut deadline = started + limit;
        let mut ready = false;
        let mut stopped = false;
        let mut connected = true;
        let code = loop {
            if Instant::now() >= deadline {
                return Err("Capture child deadline exceeded; evidence retained".into());
            }
            if self.out.metadata().map_err(error)?.len() > wire::MAX_FRAME as u64
                || self.err.metadata().map_err(error)?.len() > wire::MAX_FRAME as u64
            {
                return Err("Capture child output limit exceeded".into());
            }
            if let Some(status) = self.child.0.try_wait().map_err(error)? {
                break status.code().unwrap_or(1);
            }
            if connected && !ready {
                if let Some(w) = witness(self.child.0.id())? {
                    if w.process.pid != self.child.0.id() {
                        return Err("Capture readiness belongs to a different child".into());
                    }
                    connected = wire::write_until(
                        stream,
                        &Response::CaptureReady {
                            witness: Box::new(w),
                        },
                        deadline.min(Instant::now() + Duration::from_secs(2)),
                    )
                    .is_ok();
                    ready = connected;
                } else if started.elapsed() >= Duration::from_secs(10) {
                    return Err("Capture did not become ready".into());
                }
            }
            if connected {
                let mut byte = [0];
                match stream.read(&mut byte) {
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Ok(1) if ready && !stopped && byte == *b"S" => {
                        self.input
                            .as_mut()
                            .ok_or("Capture control already closed")?
                            .write_all(&byte)
                            .map_err(error)?;
                        stopped = true;
                        drop(self.input.take());
                    }
                    _ => {
                        connected = false;
                    }
                }
            }
            if !connected {
                drop(self.input.take());
                deadline = deadline.min(Instant::now() + Duration::from_secs(4));
            }
            stream_output(&mut self.out, stream, false, &mut connected, deadline)?;
            stream_output(&mut self.err, stream, true, &mut connected, deadline)?;
            std::thread::sleep(WAIT);
        };
        while self.out.stream_position().map_err(error)? < self.out.metadata().map_err(error)?.len()
            || self.err.stream_position().map_err(error)?
                < self.err.metadata().map_err(error)?.len()
        {
            stream_output(&mut self.out, stream, false, &mut connected, deadline)?;
            stream_output(&mut self.err, stream, true, &mut connected, deadline)?;
        }
        if !connected || !ready || !stopped {
            return Err("Capture control lost or no explicit ready stop; evidence retained".into());
        }
        Ok(code)
    }
}
pub(super) fn capture(
    shared: &Arc<Shared>,
    stream: &mut UnixStream,
    generation: &str,
) -> Result<()> {
    let _reservation = reserve_capture(shared)?;
    if shared.state.lock().unwrap().single_target.as_deref() != Some(generation) {
        return Err("Capture differs from this host's permit".into());
    }
    let config = shared.snapshot();
    let tool = protected_tool(&config)?;
    let store = Store::root()?;
    let ctx = studio_protocol::single_target::Context {
        now: studio_platform::sealed_fixture::now()?,
        owner_uid: config.uid,
        tooling_sha256: &config.tool_hash,
        helper_sha256: &config.runner_hash,
    };
    let permit = store.load(&ctx)?;
    if permit.generation != generation {
        return Err("Capture generation changed".into());
    }
    let mut cmd = command(&tool);
    cmd.args([
        "single-target-acceptance",
        "capture",
        &config.uid.to_string(),
        generation,
    ]);
    let child = CaptureChild::spawn(shared, cmd)?;
    let code = child.run(
        stream,
        |_| {
            let ctx = studio_protocol::single_target::Context {
                now: studio_platform::sealed_fixture::now()?,
                ..ctx
            };
            // Missing readiness during bounded startup is expected. The worker owns
            // failure diagnostics; no response grants readiness unless all live checks pass.
            Ok(store.live_capture(&permit, &ctx).ok())
        },
        Duration::from_secs(50),
    )?;
    wire::write(stream, &Response::Done { code })
}
pub(super) fn export(
    shared: &Arc<Shared>,
    stream: &mut UnixStream,
    generation: &str,
) -> Result<()> {
    let _reservation = reserve(shared, false, false, false)?;
    let evidence = Store::root()?.capture_evidence(shared.config.uid, generation)?;
    wire::write(
        stream,
        &Response::CaptureEvidence {
            permit: Box::new(evidence.permit),
            completion: Box::new(evidence.completion),
        },
    )?;
    let deadline = Instant::now() + Duration::from_secs(30);
    for bytes in evidence.pcap.chunks(2048) {
        wire::write_until(
            stream,
            &Response::Output {
                stderr: false,
                bytes: bytes.to_vec(),
            },
            deadline,
        )?;
    }
    wire::write_until(stream, &Response::Done { code: 0 }, deadline)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn witness(pid: u32) -> CaptureWitness {
        CaptureWitness {
            generation: "1".repeat(32),
            nonce: "2".repeat(32),
            permit_sha256: "a".repeat(64),
            created: 1000,
            process: Identity {
                uid: 0,
                pid,
                birth: [1, 2],
                executable: "/root-reviewed-issuer".into(),
            },
            lease_file: [1, 2],
        }
    }
    #[test]
    fn explicit_stop_finishes_owned_child_and_eof_or_bad_control_cannot_succeed() {
        for mode in ["stop", "eof", "bad"] {
            let host = super::super::tests::shared();
            let child = CaptureChild::spawn(&host, command(Path::new("/bin/cat"))).unwrap();
            let pid = child.child.0.id();
            let (mut client, mut server) = UnixStream::pair().unwrap();
            let worker = std::thread::spawn(move || {
                child.run(
                    &mut server,
                    |pid| Ok(Some(witness(pid))),
                    Duration::from_secs(2),
                )
            });
            let ready: Response =
                wire::read(&mut client, Duration::from_secs(2), &AtomicBool::new(false)).unwrap();
            assert!(matches!(ready, Response::CaptureReady { .. }));
            if mode == "stop" {
                client.write_all(b"S").unwrap();
            } else if mode == "bad" {
                client.write_all(b"X").unwrap();
            } else {
                client.shutdown(std::net::Shutdown::Both).unwrap();
            }
            let result = worker.join().unwrap();
            if mode == "stop" {
                assert_eq!(result.unwrap(), 0);
            } else {
                assert!(result.unwrap_err().contains("control"));
            }
            assert!(Identity::read(pid).is_err());
            fs::remove_dir_all(&host.dir).unwrap();
        }
    }
    #[test]
    fn never_ready_and_wrong_child_witness_are_bounded_and_reaped() {
        for wrong in [false, true] {
            let host = super::super::tests::shared();
            let mut cmd = command(Path::new("/bin/sleep"));
            cmd.arg("5");
            let child = CaptureChild::spawn(&host, cmd).unwrap();
            let pid = child.child.0.id();
            let (_client, mut server) = UnixStream::pair().unwrap();
            let start = Instant::now();
            let result = child.run(
                &mut server,
                |pid| Ok(wrong.then(|| witness(pid + 1))),
                Duration::from_millis(120),
            );
            assert!(result.unwrap_err().contains(if wrong {
                "different child"
            } else {
                "deadline"
            }));
            assert!(start.elapsed() < Duration::from_secs(2));
            assert!(Identity::read(pid).is_err());
            fs::remove_dir_all(&host.dir).unwrap();
        }
    }
    #[test]
    fn capture_has_one_separate_slot_and_cannot_starve_revocation() {
        let host = super::super::tests::shared();
        let jobs = (0..wire::MAX_ACTIVE)
            .map(|_| reserve(&host, true, false, false).unwrap())
            .collect::<Vec<_>>();
        let capture = reserve_capture(&host).unwrap();
        assert!(reserve_capture(&host).is_err());
        assert!(reserve_stage(&host).is_err());
        let revoke = reserve_revocation(&host).unwrap();
        assert_eq!(host.state.lock().unwrap().active, wire::MAX_ACTIVE + 2);
        assert!(reserve_revocation(&host).is_err());
        drop(revoke);
        drop(capture);
        drop(jobs);
        assert_eq!(host.state.lock().unwrap().active, 0);
        assert!(!host.state.lock().unwrap().capture_busy);
        fs::remove_dir(&host.dir).unwrap();
    }
    #[test]
    fn stop_then_disconnect_shortens_deadline_even_without_control_pipe() {
        let host = super::super::tests::shared();
        let mut cmd = command(Path::new("/bin/sleep"));
        cmd.arg("20");
        let child = CaptureChild::spawn(&host, cmd).unwrap();
        let pid = child.child.0.id();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            child.run(
                &mut server,
                |pid| Ok(Some(witness(pid))),
                Duration::from_secs(15),
            )
        });
        let ready: Response =
            wire::read(&mut client, Duration::from_secs(2), &AtomicBool::new(false)).unwrap();
        assert!(matches!(ready, Response::CaptureReady { .. }));
        client.write_all(b"S").unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        drop(client);
        assert!(worker.join().unwrap().unwrap_err().contains("deadline"));
        assert!(start.elapsed() < Duration::from_secs(6));
        assert!(Identity::read(pid).is_err());
        fs::remove_dir_all(&host.dir).unwrap();
    }
}
