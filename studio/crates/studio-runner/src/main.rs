#![forbid(unsafe_code)]
mod guard;
#[cfg(test)]
mod guard_tests;
mod outbox;
use rmasscan_engine::{Checkpoint, Engine, EngineHandle, EngineOptions, Reason};
use std::{
    io::{BufReader, BufWriter, Read, Write},
    sync::mpsc::{self, TryRecvError},
    time::{Duration, Instant},
};
use studio_protocol::{
    Backend, Command, Envelope, Event, Id, Job, ReceiveOrder, Status, read_frame,
};

struct Attempt {
    scan: Id,
    id: Id,
    order: ReceiveOrder,
    sequence: u64,
    engine: Option<EngineHandle>,
    guard: Option<guard::Guard>,
    pending: Option<CheckpointAck>,
    rows: Vec<studio_protocol::Row>,
    progress: Option<Event>,
    flushed: Instant,
}
struct CheckpointAck {
    sequence: u64,
    queued: Instant,
    receipt: outbox::Receipt,
}
impl CheckpointAck {
    fn timeout(&self, now: Instant, writer_idle: Duration) -> Option<&'static str> {
        let limit = Duration::from_secs(10);
        match self.receipt.delivered() {
            Some(delivered) if now.saturating_duration_since(delivered) > limit => {
                Some("Checkpoint ACK timeout")
            }
            None if now.saturating_duration_since(self.queued) > limit && writer_idle > limit => {
                Some("Checkpoint delivery stalled")
            }
            _ => None,
        }
    }
}
type PreparedAdapter = (rmasscan_engine::AdapterPair, Option<guard::Inspector>);
fn raw_adapter(job: &Job) -> Result<PreparedAdapter, String> {
    let plan = job.prepare()?;
    match job.backend {
        Backend::Archived => Err("Archived history cannot start a scanner".into()),
        Backend::Simulation => {
            let fake = rmasscan_engine::fake::FakeAdapter::new();
            fake.set_responder(|f| {
                rmasscan_engine::fake::reply_to_syn(f, 0x12)
                    .into_iter()
                    .collect()
            });
            Ok((fake.pair(), None))
        }
        Backend::MacFeth => {
            // The scanner's stand checks also validate routes, peer addresses,
            // ARP and forwarding. A manifest alone is insufficient after VPN
            // changes. Keep raw I/O closed until Studio has the complete gate.
            if !studio_protocol::RAW_SCANNING_ENABLED {
                return Err("Raw scanning is not enabled in this Studio build: complete live isolation preflight and authenticated runner bootstrap are still required. Simulation is available.".into());
            }
            let inspector = feth_inspector()?;
            let pair = rmasscan_net::open_explicit(plan.binding()).map(|a|a.io).map_err(|e|format!("BPF access unavailable: {e}. The isolated feth stand and an explicit access grant are required."))?;
            Ok((pair, Some(inspector)))
        }
    }
}
#[cfg(target_os = "macos")]
fn feth_inspector() -> Result<guard::Inspector, String> {
    let manifest = studio_platform::network::inspect_mac_feth()?.manifest;
    Ok(Box::new(move |cancelled| {
        let cancellation_seen = std::cell::Cell::new(false);
        let check_cancel = || {
            let stop = cancelled();
            cancellation_seen.set(cancellation_seen.get() || stop);
            stop
        };
        let observed = match studio_platform::network::inspect_mac_feth_cancellable(&check_cancel) {
            Ok(observed) => observed,
            Err(_) if cancellation_seen.get() => return Ok(guard::Observation::Cancelled),
            Err(error) => return Err(error),
        };
        if observed.manifest != manifest {
            return Err("Stand manifest changed during this attempt".into());
        }
        Ok(guard::Observation::Valid)
    }))
}
#[cfg(not(target_os = "macos"))]
fn feth_inspector() -> Result<guard::Inspector, String> {
    Err("Mac feth observer is only available on macOS".into())
}
#[cfg(not(target_os = "macos"))]
fn check_feth() -> Result<(), String> {
    Err("Mac feth profile is only available on macOS. Use explicit Simulation to test the application.".into())
}

fn send(tx: &outbox::Sender, session: Id, a: &mut Attempt, event: Event) -> Result<(), String> {
    a.sequence += 1;
    tx.try_send(Envelope::new(session, a.scan, a.id, a.sequence, event))
}
fn flush(tx: &outbox::Sender, session: Id, a: &mut Attempt) -> Result<(), String> {
    if !a.rows.is_empty() {
        let rows = std::mem::take(&mut a.rows);
        send(tx, session, a, Event::Results(rows))?;
    }
    if let Some(progress) = a.progress.take() {
        send(tx, session, a, progress)?;
    }
    a.flushed = Instant::now();
    Ok(())
}
fn publish_finish(
    events: &outbox::Sender,
    session: Id,
    a: &mut Attempt,
    reason: Reason,
    cp: Option<Checkpoint>,
) -> Result<(), String> {
    flush(events, session, a)?;
    let interrupted = a.guard.take().and_then(guard::Guard::finish);
    if let Some(detail) = interrupted {
        send(
            events,
            session,
            a,
            Event::Finished {
                status: Status::Interrupted,
                detail,
            },
        )?;
    } else if reason == Reason::Paused {
        let cp = cp.ok_or("Paused engine supplied no checkpoint")?;
        a.sequence += 1;
        let receipt = events.try_send_tracked(Envelope::new(
            session,
            a.scan,
            a.id,
            a.sequence,
            Event::Checkpoint {
                bytes: cp.to_bytes(),
                next_index: cp.next_index.to_string(),
            },
        ))?;
        a.pending = Some(CheckpointAck {
            sequence: a.sequence,
            queued: Instant::now(),
            receipt,
        });
    } else {
        let status = match reason {
            Reason::Completed => Status::Completed,
            Reason::Stopped => Status::Stopped,
            _ => Status::Failed,
        };
        send(
            events,
            session,
            a,
            Event::Finished {
                status,
                detail: format!("{reason:?}"),
            },
        )?;
    }
    Ok(())
}
fn serve(
    input: Box<dyn Read + Send>,
    output_stream: Box<dyn Write + Send>,
    live: Box<dyn Fn() -> Result<(), String>>,
) -> Result<(), String> {
    serve_with_adapter(input, output_stream, live, raw_adapter)
}
fn serve_with_adapter(
    input: Box<dyn Read + Send>,
    output_stream: Box<dyn Write + Send>,
    live: Box<dyn Fn() -> Result<(), String>>,
    mut adapter: impl FnMut(&Job) -> Result<PreparedAdapter, String>,
) -> Result<(), String> {
    let (commands, rx) = mpsc::sync_channel(8);
    let disconnected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let closed = disconnected.clone();
    std::thread::spawn(move || {
        let mut input = BufReader::new(input);
        while let Ok(e) = read_frame::<Command>(&mut input) {
            if commands.send(e).is_err() {
                break;
            }
        }
        closed.store(true, std::sync::atomic::Ordering::Release);
    });
    let hello = rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| "Handshake timeout/disconnected")?;
    let session = hello.session;
    let mut session_order = ReceiveOrder::new(session, [0; 16], [0; 16]);
    session_order.accept(&hello)?;
    let mut session_sequence = 1u64;
    if hello.payload != Command::Hello {
        return Err("Hello required".into());
    }
    // Four MiB of actual serialized bytes; sender never waits for a slow writer.
    let (events, output) = outbox::channel();
    let writer = std::thread::spawn(move || {
        let mut out = BufWriter::new(output_stream);
        let trace = std::env::var_os("STUDIO_TRACE_TIMINGS").is_some();
        let start = Instant::now();
        let mut logged = start;
        let mut elapsed = Duration::ZERO;
        let mut rows = 0usize;
        for e in output {
            rows += e.rows;
            let began = Instant::now();
            e.write(&mut out)?;
            elapsed += began.elapsed();
            if trace && logged.elapsed() >= Duration::from_secs(1) {
                eprintln!(
                    "runner writer: rows={rows} write_ms={} age_ms={}",
                    elapsed.as_millis(),
                    start.elapsed().as_millis()
                );
                logged = Instant::now();
            }
        }
        Ok::<_, std::io::Error>(())
    });
    events
        .try_send(Envelope::new(
            session,
            [0; 16],
            [0; 16],
            1,
            Event::Hello {
                engine: rmasscan_engine::ENGINE_ALGORITHM_VERSION,
            },
        ))
        .map_err(|e| e.to_string())?;
    let mut active: Option<Attempt> = None;
    let mut checked = Instant::now();
    loop {
        if let Some(a) = active.as_mut()
            && let Some(guard) = a.guard.as_mut()
        {
            // This is nonblocking, including while inspection is in progress.
            // The guard owns cancellation; keep draining already received rows.
            guard.poll();
        }
        if checked.elapsed() >= Duration::from_millis(250) {
            live()?;
            checked = Instant::now();
        }
        if writer.is_finished() {
            return Err("Application event pipe closed".into());
        }
        match rx.try_recv() {
            Ok(e) => {
                if e.session != session {
                    return Err("Session mismatch".into());
                }
                match &e.payload {
                    Command::CheckNetwork if active.is_none() => {
                        session_order.accept(&e)?;
                        #[cfg(target_os = "macos")]
                        let preflight =
                            studio_platform::network::inspect_mac_feth_cancellable(&|| {
                                disconnected.load(std::sync::atomic::Ordering::Acquire)
                            })
                            .map(|_| ());
                        #[cfg(not(target_os = "macos"))]
                        let preflight = check_feth();
                        let (ready, detail) = match preflight {
                            Ok(()) => (
                                true,
                                "Isolated feth preflight passed; no packets sent".into(),
                            ),
                            Err(e) => (false, e),
                        };
                        session_sequence = session_sequence
                            .checked_add(1)
                            .ok_or("Sequence exhausted")?;
                        events
                            .try_send(Envelope::new(
                                session,
                                [0; 16],
                                [0; 16],
                                session_sequence,
                                Event::NetworkChecked { ready, detail },
                            ))
                            .map_err(|e| e.to_string())?;
                    }
                    Command::CloseSession if active.is_none() => {
                        session_order.accept(&e)?;
                        break;
                    }
                    Command::Start(job) | Command::Resume { job, .. } => {
                        if active
                            .as_ref()
                            .is_some_and(|a| a.engine.is_some() || a.pending.is_some())
                        {
                            return Err("One active attempt only".into());
                        }
                        if active.as_ref().is_some_and(|a| a.id == e.attempt) {
                            return Err("Attempt id must be fresh".into());
                        }
                        let mut a = Attempt {
                            scan: e.scan,
                            id: e.attempt,
                            order: ReceiveOrder::new(session, e.scan, e.attempt),
                            sequence: 0,
                            engine: None,
                            guard: None,
                            pending: None,
                            rows: Vec::new(),
                            progress: None,
                            flushed: Instant::now(),
                        };
                        a.order.accept(&e)?;
                        let run = (|| {
                            let plan = job.prepare()?;
                            let cp = if let Command::Resume { checkpoint, .. } = &e.payload {
                                Some(
                                    Checkpoint::from_bytes(checkpoint)
                                        .map_err(|e| e.to_string())?,
                                )
                            } else {
                                None
                            };
                            // Validate resume identity before opening any packet handle.
                            if let Some(cp) = &cp {
                                studio_protocol::validate_checkpoint(
                                    job,
                                    e.scan,
                                    cp.attempt_id,
                                    &cp.to_bytes(),
                                    &cp.next_index.to_string(),
                                )?;
                                if cp.attempt_id == e.attempt {
                                    return Err("Resume needs a fresh attempt".into());
                                }
                            }
                            let (pair, inspect) = adapter(job)?;
                            let mut opts = EngineOptions::new(e.scan, e.attempt);
                            opts.event_batch_limit = 128;
                            let engine = match cp {
                                Some(cp) => Engine::resume(plan, cp, pair, opts),
                                None => Engine::start(plan, pair, opts),
                            }
                            .map_err(|e| e.to_string())?;
                            let guard = guard::Guard::new(engine.cancel_handle(), inspect)?;
                            Ok::<_, String>((engine, guard))
                        })();
                        match run {
                            Ok((engine, guard)) => {
                                a.engine = Some(engine);
                                a.guard = Some(guard);
                            }
                            Err(error) => send(
                                &events,
                                session,
                                &mut a,
                                Event::Finished {
                                    status: Status::Failed,
                                    detail: error,
                                },
                            )?,
                        }
                        active = Some(a);
                    }
                    _ => {
                        let a = active.as_mut().ok_or("No active attempt")?;
                        a.order.accept(&e)?;
                        match e.payload {
                            Command::Pause => {
                                if let Some(engine) = &a.engine {
                                    engine.pause();
                                }
                            }
                            Command::Stop => {
                                if let Some(engine) = &a.engine {
                                    engine.stop();
                                } else if a.pending.take().is_some() {
                                    send(
                                        &events,
                                        session,
                                        a,
                                        Event::Finished {
                                            status: Status::Stopped,
                                            detail: "Stopped before checkpoint acknowledgement"
                                                .into(),
                                        },
                                    )?;
                                }
                            }
                            Command::AckCheckpoint { through } => {
                                if a.pending.as_ref().map(|p| p.sequence) != Some(through) {
                                    return Err("Checkpoint ACK does not match".into());
                                }
                                a.pending = None;
                                send(
                                    &events,
                                    session,
                                    a,
                                    Event::Finished {
                                        status: Status::Paused,
                                        detail: "Checkpoint committed by Studio".into(),
                                    },
                                )?;
                            }
                            Command::CloseSession => break,
                            _ => return Err("Command invalid in this state".into()),
                        }
                    }
                }
            }
            Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }
        if let Some(a) = active.as_mut() {
            if let Some(error) = a
                .pending
                .as_ref()
                .and_then(|p| p.timeout(Instant::now(), events.idle_for()))
            {
                return Err(error.into());
            }
            if let Some(engine) = &a.engine {
                match engine.recv_event_timeout(Duration::from_millis(2)) {
                    Ok(rmasscan_engine::Event::Started { range }) => send(
                        &events,
                        session,
                        a,
                        Event::Started {
                            total: range.to_string(),
                        },
                    )?,
                    Ok(rmasscan_engine::Event::Results { replies }) => {
                        if a.rows.len() + replies.len() > 1000 {
                            flush(&events, session, a)?;
                        }
                        a.rows
                            .extend(replies.into_iter().map(|r| studio_protocol::Row {
                                ip: std::net::Ipv4Addr::from(r.remote_ip).to_string(),
                                port: r.remote_port,
                                open: r.status == rmasscan_core::receive::PortStatus::Open,
                            }));
                    }
                    Ok(rmasscan_engine::Event::Progress(p)) => {
                        a.progress = Some(Event::Progress {
                            sent: p.sent.to_string(),
                            received: p.received.to_string(),
                        });
                    }
                    Ok(rmasscan_engine::Event::CheckpointReady { .. }) => {}
                    Ok(rmasscan_engine::Event::Finished { reason }) => {
                        let cp = engine.checkpoint();
                        a.engine
                            .take()
                            .ok_or("Engine disappeared")?
                            .join()
                            .map_err(|e| e.to_string())?;
                        publish_finish(&events, session, a, reason, cp)?;
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        return Err("Scanner event stream closed without a terminal result".into());
                    }
                }
                if a.rows.len() >= 1000 || a.flushed.elapsed() >= Duration::from_millis(50) {
                    flush(&events, session, a)?;
                }
            } else {
                std::thread::sleep(Duration::from_millis(2));
            }
        } else {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    // EngineHandle drop requests Stop and joins. This also handles every error/EOF path.
    drop(active);
    drop(events);
    // No join on a potentially blocked pipe writer: exiting the process closes it.
    Ok(())
}
fn main() {
    if let Err(e) = launch() {
        eprintln!("Studio runner: {e}");
        std::process::exit(1);
    }
}

fn launch() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    #[cfg(windows)]
    if studio_platform::windows::Process::open(std::process::id())?
        .elevation()?
        .elevated
        && !(args.len() == 5 && args[0] == "--authorized-pipe")
    {
        return Err("Elevated runner requires an authenticated UAC session".into());
    }
    #[cfg(windows)]
    if args.len() == 5 && args[0] == "--authorized-pipe" {
        use studio_platform::windows::{Identity, uac::RunnerConnection};
        let ui: Identity = serde_json::from_str(&args[2]).map_err(|e| e.to_string())?;
        let connection = RunnerConnection::open(&args[1], &ui, &args[3], &args[4])?;
        let monitor = connection.stream.clone();
        let result = serve(
            Box::new(connection.stream.clone()),
            Box::new(connection.stream.clone()),
            Box::new(move || monitor.ensure_peer_alive()),
        );
        // Keep immutable installation handles alive until the session has ended.
        drop(connection);
        return result;
    }
    #[cfg(windows)]
    if args.len() == 3 && args[0] == "--connect-pipe" {
        use studio_platform::windows::{Identity, Stream};
        let ui: Identity = serde_json::from_str(&args[2]).map_err(|e| e.to_string())?;
        let stream = Stream::connect(
            &args[1],
            &ui,
            Duration::from_secs(10),
            &std::sync::atomic::AtomicBool::new(false),
        )?;
        let writer = stream.clone();
        let monitor = stream.clone();
        return serve(
            Box::new(stream),
            Box::new(writer),
            Box::new(move || monitor.ensure_peer_alive()),
        );
    }
    if args == ["--stdio"] {
        #[cfg(unix)]
        if studio_platform::unix::Identity::current()?.uid == 0 {
            return Err(
                "Root runner requires an authenticated socket; stdio is unprivileged only".into(),
            );
        }
        return serve(
            Box::new(std::io::stdin()),
            Box::new(std::io::stdout()),
            Box::new(|| Ok(())),
        );
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if args.len() == 3 && args[0] == "--connect" {
        use studio_platform::unix::{Endpoint, Identity};
        let ui: Identity = serde_json::from_str(&args[2]).map_err(|e| e.to_string())?;
        if ui.uid == 0 {
            return Err("Studio UI must run without root privileges".into());
        }
        let me = Identity::current()?;
        if me.uid == 0 {
            #[cfg(target_os = "linux")]
            studio_platform::linux::arm_parent_death(ui.pid)?;
            studio_platform::trusted::verify(
                &me.executable,
                &studio_platform::trusted::file_hash(&me.executable)?,
            )?;
        }
        let stream = Endpoint::connect(std::path::Path::new(&args[1]), &ui)?;
        let writer = stream.try_clone().map_err(|e| e.to_string())?;
        let live = Box::new(move || {
            if Identity::read(ui.pid)? != ui {
                return Err("UI process exited or changed identity".into());
            }
            Ok(())
        });
        return serve(Box::new(stream), Box::new(writer), live);
    }
    Err("Runner requires --stdio or an authenticated --connect endpoint".into())
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;
    #[test]
    fn backlog_does_not_consume_the_ack_deadline_but_a_stalled_writer_times_out() {
        let (tx, rx) = outbox::channel();
        let receipt = tx
            .try_send_tracked(Envelope::new(
                [1; 16],
                [2; 16],
                [3; 16],
                1,
                Event::Checkpoint {
                    bytes: vec![],
                    next_index: "1".into(),
                },
            ))
            .unwrap();
        let pending = CheckpointAck {
            sequence: 1,
            queued: Instant::now() - Duration::from_secs(60),
            receipt,
        };
        assert_eq!(
            pending.timeout(Instant::now(), Duration::from_secs(1)),
            None
        );
        assert_eq!(
            pending.timeout(Instant::now(), Duration::from_secs(11)),
            Some("Checkpoint delivery stalled")
        );
        rx.recv().unwrap().write(&mut Vec::new()).unwrap();
        let delivered = pending.receipt.delivered().unwrap();
        assert_eq!(
            pending.timeout(delivered + Duration::from_secs(9), Duration::ZERO),
            None
        );
        assert_eq!(
            pending.timeout(delivered + Duration::from_secs(11), Duration::ZERO),
            Some("Checkpoint ACK timeout")
        );
    }
}
