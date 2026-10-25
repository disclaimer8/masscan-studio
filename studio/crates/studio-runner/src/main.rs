#![forbid(unsafe_code)]
#[cfg(any(target_os = "macos", test))]
mod stand;
use rmasscan_engine::{Checkpoint, Engine, EngineHandle, EngineOptions, Reason};
use std::{
    io::{BufReader, BufWriter},
    sync::mpsc::{self, TryRecvError},
    time::{Duration, Instant},
};
use studio_protocol::{
    Backend, Command, Envelope, Event, Id, Job, ReceiveOrder, Status, read_frame, write_frame,
};

struct Attempt {
    scan: Id,
    id: Id,
    order: ReceiveOrder,
    sequence: u64,
    engine: Option<EngineHandle>,
    pending: Option<(u64, Instant)>,
}
fn raw_adapter(job: &Job) -> Result<rmasscan_engine::AdapterPair, String> {
    let plan = job.prepare()?;
    match job.backend {
        Backend::Simulation => {
            let fake = rmasscan_engine::fake::FakeAdapter::new();
            fake.set_responder(|f| {
                rmasscan_engine::fake::reply_to_syn(f, 0x12)
                    .into_iter()
                    .collect()
            });
            Ok(fake.pair())
        }
        Backend::MacFeth => {
            check_feth()?;
            rmasscan_net::open_explicit(plan.binding()).map(|a|a.io).map_err(|e|format!("BPF access unavailable: {e}. The isolated feth stand and an explicit access grant are required."))
        }
    }
}
#[cfg(target_os = "macos")]
fn check_feth() -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let path = "/var/run/rmasscan-lab/m1.json";
    let parent = std::fs::symlink_metadata("/var/run/rmasscan-lab")
        .map_err(|_| "The isolated feth stand is not installed")?;
    if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
        return Err("Untrusted stand manifest directory".into());
    }
    let md =
        std::fs::symlink_metadata(path).map_err(|_| "The isolated feth stand is not installed")?;
    if !md.is_file() || md.uid() != 0 || md.mode() & 0o022 != 0 {
        return Err("Untrusted stand manifest".into());
    }
    if md.len() > 65536 {
        return Err("Stand manifest is too large".into());
    }
    stand::validate_manifest(&std::fs::read(path).map_err(|e| e.to_string())?)?;
    for (name, peer) in [("feth4201", "feth4202"), ("feth4202", "feth4201")] {
        let out = std::process::Command::new("/sbin/ifconfig")
            .arg(name)
            .env_clear()
            .env("LC_ALL", "C")
            .output()
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&out.stdout);
        if !out.status.success()
            || !text.contains(&format!("peer: {peer}"))
            || !text.contains("status: active")
            || (name == "feth4201" && text.lines().any(|l| l.trim_start().starts_with("inet ")))
        {
            return Err("The isolated feth pair is not active or its topology changed".into());
        }
    }
    let all = std::process::Command::new("/sbin/ifconfig")
        .arg("-a")
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&all.stdout);
    if !all.status.success()
        || text.contains("member: feth4201")
        || text.contains("member: feth4202")
    {
        return Err("The feth pair may not belong to a bridge".into());
    }
    Ok(())
}
#[cfg(not(target_os = "macos"))]
fn check_feth() -> Result<(), String> {
    Err("Mac feth profile is only available on macOS. Use explicit Simulation to test the application.".into())
}

fn send(
    tx: &mpsc::SyncSender<Envelope<Event>>,
    session: Id,
    a: &mut Attempt,
    event: Event,
) -> Result<(), String> {
    a.sequence += 1;
    tx.try_send(Envelope::new(session, a.scan, a.id, a.sequence, event))
        .map_err(|_| "Event pipe exceeded its bounded queue or closed".into())
}
fn serve() -> Result<(), String> {
    if std::env::args().skip(1).collect::<Vec<_>>() != ["--stdio"] {
        return Err("Runner is private to Studio (--stdio); no command-line scan API".into());
    }
    let (commands, rx) = mpsc::sync_channel(8);
    std::thread::spawn(move || {
        let mut input = BufReader::new(std::io::stdin());
        while let Ok(e) = read_frame::<Command>(&mut input) {
            if commands.send(e).is_err() {
                break;
            }
        }
    });
    let hello = rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| "Handshake timeout/disconnected")?;
    let session = hello.session;
    ReceiveOrder::new(session, [0; 16], [0; 16]).accept(&hello)?;
    if hello.payload != Command::Hello {
        return Err("Hello required".into());
    }
    // At most 32 bounded frames = 4 MiB, writer never blocks the control/engine loop.
    let (events, output) = mpsc::sync_channel::<Envelope<Event>>(32);
    let writer = std::thread::spawn(move || {
        let mut out = BufWriter::new(std::io::stdout());
        for e in output {
            write_frame(&mut out, &e)?;
        }
        Ok::<_, std::io::Error>(())
    });
    events
        .send(Envelope::new(
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
    loop {
        if writer.is_finished() {
            return Err("Application event pipe closed".into());
        }
        match rx.try_recv() {
            Ok(e) => {
                if e.session != session {
                    return Err("Session mismatch".into());
                }
                match &e.payload {
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
                            pending: None,
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
                            let pair = raw_adapter(job)?;
                            let mut opts = EngineOptions::new(e.scan, e.attempt);
                            opts.event_batch_limit = 128;
                            let engine = match cp {
                                Some(cp) => Engine::resume(plan, cp, pair, opts),
                                None => Engine::start(plan, pair, opts),
                            }
                            .map_err(|e| e.to_string())?;
                            Ok::<_, String>(engine)
                        })();
                        match run {
                            Ok(engine) => a.engine = Some(engine),
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
                                if a.pending.map(|p| p.0) != Some(through) {
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
            if a.pending
                .is_some_and(|p| p.1.elapsed() > Duration::from_secs(10))
            {
                return Err("Checkpoint ACK timeout".into());
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
                    Ok(rmasscan_engine::Event::Results { replies }) => send(
                        &events,
                        session,
                        a,
                        Event::Results(
                            replies
                                .into_iter()
                                .map(|r| studio_protocol::Row {
                                    ip: std::net::Ipv4Addr::from(r.remote_ip).to_string(),
                                    port: r.remote_port,
                                    open: r.status == rmasscan_core::receive::PortStatus::Open,
                                })
                                .collect(),
                        ),
                    )?,
                    Ok(rmasscan_engine::Event::Progress(p)) => send(
                        &events,
                        session,
                        a,
                        Event::Progress {
                            sent: p.sent.to_string(),
                            received: p.received.to_string(),
                        },
                    )?,
                    Ok(rmasscan_engine::Event::CheckpointReady { .. }) => {}
                    Ok(rmasscan_engine::Event::Finished { reason }) => {
                        let cp = engine.checkpoint();
                        a.engine
                            .take()
                            .ok_or("Engine disappeared")?
                            .join()
                            .map_err(|e| e.to_string())?;
                        if reason == Reason::Paused {
                            let cp = cp.ok_or("Paused engine supplied no checkpoint")?;
                            send(
                                &events,
                                session,
                                a,
                                Event::Checkpoint {
                                    bytes: cp.to_bytes(),
                                    next_index: cp.next_index.to_string(),
                                },
                            )?;
                            a.pending = Some((a.sequence, Instant::now()));
                        } else {
                            let status = match reason {
                                Reason::Completed => Status::Completed,
                                Reason::Stopped => Status::Stopped,
                                _ => Status::Failed,
                            };
                            send(
                                &events,
                                session,
                                a,
                                Event::Finished {
                                    status,
                                    detail: format!("{reason:?}"),
                                },
                            )?;
                        }
                    }
                    Err(_) => {}
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
    if let Err(e) = serve() {
        eprintln!("Studio runner: {e}");
        std::process::exit(1);
    }
}
