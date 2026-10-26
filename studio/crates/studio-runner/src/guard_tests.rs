//! In-memory IPC with the actual runner loop and actual engine, without sockets.
use super::*;
use std::{
    io::{self, Cursor},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

struct Reader(mpsc::Receiver<Vec<u8>>, Cursor<Vec<u8>>);
impl Read for Reader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let n = self.1.read(bytes)?;
            if n != 0 {
                return Ok(n);
            }
            match self.0.recv_timeout(Duration::from_secs(10)) {
                Ok(next) => self.1 = Cursor::new(next),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(0),
                Err(_) => return Err(io::ErrorKind::TimedOut.into()),
            }
        }
    }
}
struct Writer(mpsc::Sender<Vec<u8>>);
impl Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .send(bytes.to_vec())
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn pipe() -> (Writer, Reader) {
    let (tx, rx) = mpsc::channel();
    (Writer(tx), Reader(rx, Cursor::new(Vec::new())))
}

#[test]
fn drift_interrupts_runner_retains_results_and_allows_new_attempt() {
    let (mut input, runner_in) = pipe();
    let (runner_out, mut output) = pipe();
    let changed = Arc::new(AtomicBool::new(false));
    let observe = changed.clone();
    let server = std::thread::spawn(move || {
        serve_with_adapter(
            Box::new(runner_in),
            Box::new(runner_out),
            Box::new(|| Ok(())),
            move |job| {
                // Test-only injection; never a privileged argv/environment capability.
                let (pair, _) = raw_adapter(job)?;
                let observe = observe.clone();
                let inspector: guard::Inspector = Box::new(move |cancelled| {
                    // Hold a real background observation until the test changes route.
                    while !observe.load(Ordering::Acquire) && !cancelled() {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    if observe.load(Ordering::Acquire) {
                        Err("route changed".into())
                    } else {
                        Ok(guard::Observation::Cancelled)
                    }
                });
                Ok((pair, Some(inspector)))
            },
        )
    });
    let session = [71; 16];
    let scan = [72; 16];
    let attempt = [73; 16];
    let send_command = |input: &mut Writer, attempt, sequence, command| {
        studio_protocol::write_frame(
            input,
            &Envelope::new(session, scan, attempt, sequence, command),
        )
        .unwrap();
    };
    studio_protocol::write_frame(
        &mut input,
        &Envelope::new(session, [0; 16], [0; 16], 1, Command::Hello),
    )
    .unwrap();
    assert!(matches!(
        read_frame::<Event>(&mut output).unwrap().payload,
        Event::Hello { .. }
    ));
    let mut job = Job::example(Backend::Simulation);
    job.ports = "1-100".into();
    job.rate = 10;
    let directory = std::env::temp_dir().join(format!(
        "studio-guard-{}",
        studio_protocol::id_text(studio_protocol::new_id().unwrap())
    ));
    let mut store = studio_store::Store::open(&directory).unwrap();
    store.begin(scan, attempt, &job, false).unwrap();
    send_command(&mut input, attempt, 1, Command::Start(job.clone()));
    let mut rows = 0;
    let mut previous = 0;
    loop {
        let event = read_frame::<Event>(&mut output).unwrap();
        assert_eq!(event.sequence, previous + 1);
        previous = event.sequence;
        store.apply(&event).unwrap();
        match event.payload {
            Event::Results(r) => {
                rows += r.len();
                changed.store(true, Ordering::Release);
            }
            Event::Checkpoint { .. } => panic!("drift produced a checkpoint"),
            Event::Finished { status, detail } => {
                assert_eq!(status, Status::Interrupted, "{detail}");
                assert!(detail.contains("route changed"));
                break;
            }
            _ => {}
        }
    }
    assert!(rows > 0);
    drop(store);
    let store = studio_store::Store::open(&directory).unwrap();
    let saved = store.scans().unwrap().pop().unwrap();
    assert_eq!(saved.status, Status::Interrupted);
    assert!(saved.checkpoint.is_none());
    assert_eq!(store.rows(scan).unwrap().len(), rows);
    drop(store);
    changed.store(false, Ordering::Release);
    let attempt2 = [74; 16];
    send_command(&mut input, attempt2, 1, Command::Start(job));
    send_command(&mut input, attempt2, 2, Command::Stop);
    loop {
        if let Event::Finished { status, .. } = read_frame::<Event>(&mut output).unwrap().payload {
            assert_eq!(status, Status::Stopped);
            break;
        }
    }
    drop(input);
    server.join().unwrap().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn interruption_wins_over_queued_completion_or_pause_without_losing_rows() {
    for paused in [false, true] {
        let job = Job::example(Backend::Simulation);
        let (pair, _) = raw_adapter(&job).unwrap();
        let engine = Engine::start(
            job.prepare().unwrap(),
            pair,
            EngineOptions::new([1; 16], [2; 16]),
        )
        .unwrap();
        if paused {
            engine.pause();
        }
        let cancel = engine.cancel_handle();
        let deadline = Instant::now() + Duration::from_secs(5);
        while engine.outcome().is_none() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        let checkpoint = engine.checkpoint();
        let (outcome, _) = engine.join_drain().unwrap();
        assert_eq!(
            outcome.reason,
            if paused {
                Reason::Paused
            } else {
                Reason::Completed
            }
        );
        let mut guard =
            guard::Guard::new(cancel, Some(Box::new(|_| Err("route changed".into())))).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while guard.poll().is_none() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut attempt = Attempt {
            scan: [1; 16],
            id: [2; 16],
            order: ReceiveOrder::new([3; 16], [1; 16], [2; 16]),
            sequence: 0,
            engine: None,
            guard: Some(guard),
            pending: None,
            rows: vec![studio_protocol::Row {
                ip: "198.18.0.2".into(),
                port: 80,
                open: true,
            }],
            progress: None,
            flushed: Instant::now(),
        };
        let (tx, rx) = outbox::channel();
        publish_finish(&tx, [3; 16], &mut attempt, outcome.reason, checkpoint).unwrap();
        assert!(attempt.pending.is_none());
        let mut events = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            let mut bytes = Vec::new();
            frame.write(&mut bytes).unwrap();
            events.push(
                read_frame::<Event>(&mut Cursor::new(bytes))
                    .unwrap()
                    .payload,
            );
        }
        assert!(
            matches!(&events[..], [Event::Results(rows), Event::Finished { status: Status::Interrupted, .. }] if rows.len() == 1)
        );
    }
}
