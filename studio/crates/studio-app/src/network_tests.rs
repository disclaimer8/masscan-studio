use super::*;

#[derive(Clone, Default)]
struct Wire(Arc<Mutex<Vec<u8>>>);
impl Write for Wire {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Wire {
    fn commands(&self) -> Vec<Envelope<Command>> {
        let bytes = self.0.lock().unwrap().clone();
        let mut input = std::io::Cursor::new(bytes);
        let mut out = Vec::new();
        while input.position() < input.get_ref().len() as u64 {
            out.push(read_frame(&mut input).unwrap());
        }
        out
    }
}
fn fake_client() -> (
    Client,
    mpsc::SyncSender<Result<Envelope<Event>, String>>,
    Wire,
) {
    let wire = Wire::default();
    let mut c = Client::connected(Box::new(wire.clone()), Box::new(std::io::empty())).unwrap();
    let (tx, rx) = mpsc::sync_channel(32);
    c.events = rx;
    tx.send(Ok(Envelope::new(
        c.session,
        [0; 16],
        [0; 16],
        1,
        Event::Hello {
            engine: ENGINE_VERSION,
        },
    )))
    .unwrap();
    c.handshake(None).unwrap();
    (c, tx, wire)
}
#[test]
fn asynchronous_preflight_crosses_start_with_independent_orders() {
    let (mut c, tx, wire) = fake_client();
    let job = Job::example(Backend::MacNetwork);
    c.send(Command::CheckNetworkJob(job.clone())).unwrap();
    c.start([1; 16], [2; 16], Command::Start(job.clone()))
        .unwrap();
    tx.send(Ok(Envelope::new(
        c.session,
        [0; 16],
        [0; 16],
        2,
        Event::NetworkPreflight {
            job_digest: job.original_digest().unwrap(),
            ready: true,
            detail: "routes only".into(),
        },
    )))
    .unwrap();
    assert!(matches!(
        c.poll().unwrap().unwrap().payload,
        Event::NetworkPreflight { .. }
    ));
    tx.send(Ok(Envelope::new(
        c.session,
        [1; 16],
        [2; 16],
        1,
        Event::PreparingNetwork,
    )))
    .unwrap();
    assert!(matches!(
        c.poll().unwrap().unwrap().payload,
        Event::PreparingNetwork
    ));
    c.send(Command::CheckNetwork).unwrap();
    let commands = wire.commands();
    assert_eq!(commands[3].scan, [0; 16]);
    assert_eq!(commands[3].attempt, [0; 16]);
    assert_eq!(commands[3].sequence, 3);
    c.send(Command::Stop).unwrap();
    assert_eq!(wire.commands()[4].sequence, 2);
}

fn fixture() -> (Job, NetworkReport) {
    let mut j = Job::example(Backend::MacNetwork);
    j.targets = "10.0.0.1-10.0.0.2".into();
    let a = "10.0.0.1".parse().unwrap();
    let b = "10.0.0.2".parse().unwrap();
    let report = NetworkReport {
        job_digest: j.original_digest().unwrap(),
        routes: rmasscan_net::PhysicalRoutePlan {
            interface_name: "en0".into(),
            interface_index: 1,
            source_ipv4: "10.0.0.254".parse().unwrap(),
            source_mac: Some([2, 1, 2, 3, 4, 5]),
            next_hops: [(a, a), (b, b)].into(),
            excluded: Default::default(),
        },
        destinations: [(a, [2, 1, 1, 1, 1, 1])].into(),
        unresolved: vec![b],
    };
    (j, report)
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(
            std::env::temp_dir().join(format!("studio-app-network-{}", id_text(new_id().unwrap()))),
        )
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn network_report_is_committed_and_acknowledged_by_controller() {
    let dir = Temp::new();
    let mut db = Store::open(&dir.0).unwrap();
    let (job, report) = fixture();
    let (mut c, tx, wire) = fake_client();
    db.begin([1; 16], [2; 16], &job, false).unwrap();
    c.start([1; 16], [2; 16], Command::Start(job)).unwrap();
    tx.send(Ok(Envelope::new(
        c.session,
        c.scan,
        c.attempt,
        1,
        Event::NetworkPrepared {
            bytes: report.encode().unwrap(),
        },
    )))
    .unwrap();
    let events = c.poll_batch().unwrap();
    let (out, _rx) = mpsc::sync_channel(32);
    commit_scan_events(&mut db, &mut c, events, &out, Some([1; 16]), &|| false).unwrap();
    assert_eq!(
        db.scans().unwrap()[0].network_report,
        Some(report.encode().unwrap())
    );
    assert!(matches!(
        wire.commands().last().unwrap().payload,
        Command::AckNetworkReport { through: 1 }
    ));
}

struct AckWitness {
    wire: Wire,
    path: PathBuf,
    expected: Vec<u8>,
    seen: Arc<AtomicBool>,
}
impl Write for AckWitness {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.wire.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if self
            .wire
            .commands()
            .iter()
            .any(|e| matches!(e.payload, Command::AckNetworkReport { .. }))
        {
            // A separate SQLite connection sees only committed data. This assertion
            // runs inside ACK transmission, not after the controller has returned.
            let sql = rusqlite::Connection::open(&self.path).unwrap();
            let durable: Vec<u8> = sql
                .query_row("SELECT network_report FROM scans", [], |r| r.get(0))
                .unwrap();
            assert_eq!(durable, self.expected);
            self.seen.store(true, Ordering::Release);
        }
        Ok(())
    }
}

#[test]
fn report_ack_wire_observes_committed_transaction_and_preparing_state() {
    let dir = Temp::new();
    let mut db = Store::open(&dir.0).unwrap();
    let (job, report) = fixture();
    let (mut c, tx, wire) = fake_client();
    db.begin([1; 16], [2; 16], &job, false).unwrap();
    c.start([1; 16], [2; 16], Command::Start(job.clone()))
        .unwrap();
    let seen = Arc::new(AtomicBool::new(false));
    c.input = Some(BufWriter::new(Box::new(AckWitness {
        wire: wire.clone(),
        path: dir.0.join("history.sqlite3"),
        expected: report.encode().unwrap(),
        seen: seen.clone(),
    })));
    let (out, rx) = mpsc::sync_channel(32);
    for (seq, payload) in [
        (1, Event::PreparingNetwork),
        (
            2,
            Event::NetworkPrepared {
                bytes: report.encode().unwrap(),
            },
        ),
    ] {
        tx.send(Ok(Envelope::new(
            c.session, c.scan, c.attempt, seq, payload,
        )))
        .unwrap();
        let events = c.poll_batch().unwrap();
        commit_scan_events(&mut db, &mut c, events, &out, Some([1; 16]), &|| false).unwrap();
    }
    assert!(seen.load(Ordering::Acquire));
    let updates: Vec<_> = rx.try_iter().collect();
    assert!(matches!(updates[0], Update::State(Status::Preparing, _)));
    match &updates[1] {
        Update::NetworkCoverage(Some(coverage)) => {
            assert_eq!(coverage.job, job);
            assert_eq!(coverage.eligible_targets, 1);
            assert_eq!(coverage.unresolved_targets, 1);
        }
        _ => panic!("Missing persisted coverage"),
    }
    assert_eq!(db.scans().unwrap()[0].status, Status::Preparing);
    assert!(matches!(
        wire.commands().last().unwrap().payload,
        Command::AckNetworkReport { through: 2 }
    ));
}

#[test]
fn failed_report_transaction_rolls_back_preparation_and_never_acks() {
    let dir = Temp::new();
    let mut db = Store::open(&dir.0).unwrap();
    let (job, report) = fixture();
    let (mut c, _tx, wire) = fake_client();
    db.begin([1; 16], [2; 16], &job, false).unwrap();
    c.start([1; 16], [2; 16], Command::Start(job)).unwrap();
    let sql = rusqlite::Connection::open(dir.0.join("history.sqlite3")).unwrap();
    sql.execute_batch("CREATE TRIGGER fail_report BEFORE UPDATE OF network_report ON scans BEGIN SELECT RAISE(ABORT,'injected report write failure'); END;").unwrap();
    let events = vec![
        Envelope::new(c.session, c.scan, c.attempt, 1, Event::PreparingNetwork),
        Envelope::new(
            c.session,
            c.scan,
            c.attempt,
            2,
            Event::NetworkPrepared {
                bytes: report.encode().unwrap(),
            },
        ),
    ];
    let (out, rx) = mpsc::sync_channel(32);
    assert!(
        commit_scan_events(&mut db, &mut c, events, &out, Some([1; 16]), &|| false)
            .unwrap_err()
            .contains("injected")
    );
    let saved = db.scans().unwrap().remove(0);
    assert_eq!(saved.status, Status::Starting);
    assert!(saved.network_report.is_none());
    assert!(rx.try_recv().is_err());
    assert!(
        !wire
            .commands()
            .iter()
            .any(|e| matches!(e.payload, Command::AckNetworkReport { .. }))
    );
    drop(c);
    assert_eq!(
        wire.commands().len(),
        2,
        "failure/transport close cannot emit a delayed ACK"
    );
}

#[test]
fn stop_close_and_pending_stop_during_commit_preserve_report_without_ack() {
    for cancellation in ["stop", "close", "during_commit"] {
        let dir = Temp::new();
        let mut db = Store::open(&dir.0).unwrap();
        let (job, report) = fixture();
        let (mut c, tx, wire) = fake_client();
        db.begin([1; 16], [2; 16], &job, false).unwrap();
        c.start([1; 16], [2; 16], Command::Start(job)).unwrap();
        tx.send(Ok(Envelope::new(
            c.session,
            c.scan,
            c.attempt,
            1,
            Event::PreparingNetwork,
        )))
        .unwrap();
        let (out, rx) = mpsc::sync_channel(32);
        let events = c.poll_batch().unwrap();
        commit_scan_events(&mut db, &mut c, events, &out, Some([1; 16]), &|| false).unwrap();
        assert!(matches!(
            rx.try_recv().unwrap(),
            Update::State(Status::Preparing, _)
        ));
        if cancellation == "stop" {
            c.send(Command::Stop).unwrap();
        }
        // The cancellation callback is evaluated after the transaction. Model a
        // Drop/queued Stop already known to Controller::send, even before the
        // controller worker has drained that action from its channel.
        let cancelled = || cancellation != "stop";
        tx.send(Ok(Envelope::new(
            c.session,
            c.scan,
            c.attempt,
            2,
            Event::NetworkPrepared {
                bytes: report.encode().unwrap(),
            },
        )))
        .unwrap();
        let events = c.poll_batch().unwrap();
        commit_scan_events(&mut db, &mut c, events, &out, Some([1; 16]), &cancelled).unwrap();
        assert!(db.scans().unwrap()[0].network_report.is_some());
        drop(c);
        assert!(
            !wire
                .commands()
                .iter()
                .any(|e| matches!(e.payload, Command::AckNetworkReport { .. })),
            "{cancellation}"
        );
    }
}

#[test]
fn stale_attempt_or_digest_cannot_persist_or_ack() {
    for wrong_digest in [false, true] {
        let dir = Temp::new();
        let mut db = Store::open(&dir.0).unwrap();
        let (job, mut report) = fixture();
        let (mut c, _tx, wire) = fake_client();
        db.begin([1; 16], [2; 16], &job, false).unwrap();
        c.start([1; 16], [2; 16], Command::Start(job)).unwrap();
        if wrong_digest {
            report.job_digest = [55; 32];
        }
        let attempt = if wrong_digest { c.attempt } else { [8; 16] };
        let events = vec![Envelope::new(
            c.session,
            c.scan,
            attempt,
            1,
            Event::NetworkPrepared {
                bytes: report.encode().unwrap(),
            },
        )];
        let (out, _rx) = mpsc::sync_channel(32);
        assert!(
            commit_scan_events(&mut db, &mut c, events, &out, Some([1; 16]), &|| false).is_err()
        );
        assert!(db.scans().unwrap()[0].network_report.is_none());
        assert!(
            !wire
                .commands()
                .iter()
                .any(|e| matches!(e.payload, Command::AckNetworkReport { .. }))
        );
    }
}

#[test]
fn session_checks_after_finished_remain_zero_scoped_and_replays_fail() {
    let (mut c, tx, wire) = fake_client();
    c.start(
        [1; 16],
        [2; 16],
        Command::Start(Job::example(Backend::Simulation)),
    )
    .unwrap();
    tx.send(Ok(Envelope::new(
        c.session,
        c.scan,
        c.attempt,
        1,
        Event::Finished {
            status: Status::Completed,
            detail: String::new(),
        },
    )))
    .unwrap();
    c.poll().unwrap().unwrap();
    c.send(Command::CheckNetwork).unwrap();
    let e = wire.commands().pop().unwrap();
    assert_eq!((e.scan, e.attempt, e.sequence), ([0; 16], [0; 16], 2));
    let reply = Envelope::new(
        c.session,
        [0; 16],
        [0; 16],
        2,
        Event::NetworkChecked {
            ready: false,
            detail: "fake".into(),
        },
    );
    tx.send(Ok(reply.clone())).unwrap();
    assert!(c.poll().unwrap().is_some());
    tx.send(Ok(reply)).unwrap();
    assert!(c.poll().is_err());
}

#[test]
fn wrongly_scoped_replayed_and_old_attempt_events_are_rejected() {
    for bad in 0..7 {
        let (mut c, tx, _wire) = fake_client();
        c.start(
            [1; 16],
            [2; 16],
            Command::Start(Job::example(Backend::Simulation)),
        )
        .unwrap();
        let mut event = Envelope::new(c.session, c.scan, c.attempt, 1, Event::PreparingNetwork);
        match bad {
            0 => event.session = [99; 16],
            1 => event.scan = [99; 16],
            2 => event.attempt = [99; 16],
            3 => event.sequence = 2,
            4 => {
                event.scan = [0; 16];
                event.attempt = [0; 16];
                event.sequence = 2;
            }
            5 => {
                event.payload = Event::NetworkChecked {
                    ready: true,
                    detail: String::new(),
                }
            }
            _ => {
                event.payload = Event::Hello {
                    engine: ENGINE_VERSION,
                }
            }
        }
        tx.send(Ok(event)).unwrap();
        assert!(c.poll().is_err(), "case {bad}");
    }
    let (mut c, tx, _wire) = fake_client();
    let job = Job::example(Backend::Simulation);
    c.start([1; 16], [2; 16], Command::Start(job.clone()))
        .unwrap();
    c.start([1; 16], [3; 16], Command::Start(job)).unwrap();
    tx.send(Ok(Envelope::new(
        c.session,
        [1; 16],
        [2; 16],
        1,
        Event::Started { total: "8".into() },
    )))
    .unwrap();
    assert!(c.poll().is_err());
}

#[test]
fn readiness_is_digest_bound_and_never_claims_execution_or_neighbours() {
    let (job, _) = fixture();
    let mut changed = job.clone();
    changed.ports = "443".into();
    let mut draft = network::Draft::default();
    let (out, rx) = mpsc::sync_channel(32);
    draft.set(&job, true, &out).unwrap();
    draft.set(&changed, true, &out).unwrap();
    rx.try_iter().for_each(drop);
    draft
        .checked(job.original_digest().unwrap(), true, "old".into(), &out)
        .unwrap();
    draft.checked_legacy(true, "feth".into(), &out).unwrap();
    assert!(rx.try_recv().is_err());
    draft
        .checked(
            changed.original_digest().unwrap(),
            true,
            "routes only".into(),
            &out,
        )
        .unwrap();
    match rx.try_recv().unwrap() {
        Update::NetworkReadiness(Some(state)) => {
            assert!(state.route_ready);
            assert!(!state.checking);
            assert!(!state.execution_enabled);
            assert_eq!(state.backend, Backend::MacNetwork);
        }
        _ => panic!("Missing readiness"),
    }
    draft.invalidate(&out).unwrap();
    rx.try_iter().for_each(drop);
    draft
        .checked(
            changed.original_digest().unwrap(),
            true,
            "late".into(),
            &out,
        )
        .unwrap();
    assert!(rx.try_recv().is_err());
    assert!(matches!(
        network::check_command(job),
        Command::CheckNetworkJob(_)
    ));
    assert!(matches!(
        network::check_command(Job::example(Backend::MacFeth)),
        Command::CheckNetwork
    ));
}

fn wait_updates(c: &mut Controller, predicate: impl Fn(&[Update]) -> bool) -> Vec<Update> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut updates = Vec::new();
    loop {
        updates.extend(c.poll());
        if predicate(&updates) {
            return updates;
        }
        assert!(Instant::now() < deadline, "Controller update timed out");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn all_unresolved_history_reopens_and_switching_scan_or_draft_clears_coverage() {
    let dir = Temp::new();
    let mut db = Store::open(&dir.0).unwrap();
    db.begin([8; 16], [9; 16], &Job::example(Backend::Simulation), false)
        .unwrap();
    db.apply(&Envelope::new(
        [3; 16],
        [8; 16],
        [9; 16],
        1,
        Event::Finished {
            status: Status::Completed,
            detail: "Simulation".into(),
        },
    ))
    .unwrap();
    let (job, mut report) = fixture();
    report.unresolved = report.routes.next_hops.keys().copied().collect();
    report.destinations.clear();
    db.begin([1; 16], [2; 16], &job, false).unwrap();
    let (mut transport, _tx, wire) = fake_client();
    transport
        .start([1; 16], [2; 16], Command::Start(job.clone()))
        .unwrap();
    let (out, updates) = mpsc::sync_channel(32);
    let event = Envelope::new(
        transport.session,
        transport.scan,
        transport.attempt,
        1,
        Event::NetworkPrepared {
            bytes: report.encode().unwrap(),
        },
    );
    commit_scan_events(
        &mut db,
        &mut transport,
        vec![event],
        &out,
        Some([1; 16]),
        &|| false,
    )
    .unwrap();
    assert!(updates.try_iter().any(|u|matches!(u,Update::NetworkCoverage(Some(c)) if c.eligible_targets==0 && c.unresolved_targets==2)));
    assert!(matches!(
        wire.commands().last().unwrap().payload,
        Command::AckNetworkReport { through: 1 }
    ));
    let event = Envelope::new(
        transport.session,
        transport.scan,
        transport.attempt,
        2,
        Event::Finished {
            status: Status::Failed,
            detail: "No neighbour responses; no TCP engine started".into(),
        },
    );
    let (_, finished) = commit_scan_events(
        &mut db,
        &mut transport,
        vec![event],
        &out,
        Some([1; 16]),
        &|| false,
    )
    .unwrap();
    assert!(finished);
    assert!(db.rows([1; 16]).unwrap().is_empty());
    drop(transport);
    drop(db);
    let mut c =
        Controller::open(dir.0.clone(), PathBuf::from("/nonexistent/studio-runner")).unwrap();
    let updates = wait_updates(&mut c, |u| {
        u.iter().any(|v| matches!(v, Update::Profiles(..)))
    });
    let coverage = updates
        .into_iter()
        .find_map(|u| {
            if let Update::NetworkCoverage(Some(c)) = u {
                Some(c)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(coverage.job, job);
    assert_eq!(coverage.unresolved_targets, 2);
    assert_eq!(coverage.eligible_probes, 0);
    c.send(Action::Select([8; 16])).unwrap();
    wait_updates(&mut c, |u| {
        u.iter().any(|v| matches!(v, Update::NetworkCoverage(None)))
    });
    c.send(Action::Select([1; 16])).unwrap();
    wait_updates(&mut c, |u| {
        u.iter()
            .any(|v| matches!(v, Update::NetworkCoverage(Some(_))))
    });
    c.send(Action::SetDraft(Job::example(Backend::Simulation)))
        .unwrap();
    wait_updates(&mut c, |u| {
        u.iter().any(|v| matches!(v, Update::NetworkCoverage(None)))
    });
    c.send(Action::Select([1; 16])).unwrap();
    wait_updates(&mut c, |u| {
        u.iter()
            .any(|v| matches!(v, Update::NetworkCoverage(Some(_))))
    });
    c.send(Action::DeleteScan([1; 16])).unwrap();
    let updates = wait_updates(&mut c, |u| {
        u.iter().any(|v| matches!(v, Update::HistoryResult(Ok(_))))
    });
    assert!(
        updates
            .iter()
            .any(|v| matches!(v, Update::NetworkCoverage(None)))
    );
    c.send(Action::DeleteScan([8; 16])).unwrap();
    let updates = wait_updates(&mut c, |u| {
        u.iter().any(|v| matches!(v, Update::HistoryResult(Ok(_))))
    });
    assert!(updates.iter().any(|v| matches!(v, Update::Clear)));
}

#[test]
fn coverage_counts_use_port_union_and_distinguish_user_and_automatic_exclusions() {
    let dir = Temp::new();
    let mut db = Store::open(&dir.0).unwrap();
    let (mut job, mut report) = fixture();
    job.targets = "10.0.0.0-10.0.0.3".into();
    job.exclusions = "10.0.0.3".into();
    job.ports = "80,90,80".into();
    report.job_digest = job.original_digest().unwrap();
    report.routes.excluded.insert(
        "10.0.0.0".parse().unwrap(),
        rmasscan_net::ExcludedReason::NetworkAddress,
    );
    db.begin([1; 16], [2; 16], &job, false).unwrap();
    db.apply(&Envelope::new(
        [3; 16],
        [1; 16],
        [2; 16],
        1,
        Event::NetworkPrepared {
            bytes: report.encode().unwrap(),
        },
    ))
    .unwrap();
    let coverage = NetworkCoverage::from_saved(&db.scans().unwrap()[0])
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            coverage.requested_inputs,
            coverage.candidate_targets,
            coverage.effective_targets,
            coverage.eligible_targets,
            coverage.unresolved_targets,
            coverage.excluded_targets
        ),
        (1, 3, 2, 1, 1, 1)
    );
    assert_eq!(
        (
            coverage.candidate_probes,
            coverage.effective_probes,
            coverage.eligible_probes,
            coverage.unresolved_probes,
            coverage.excluded_probes
        ),
        (6, 4, 2, 2, 2)
    );
    assert_eq!(coverage.job, job);
}

#[test]
fn network_checkpoint_uses_frozen_report_and_resume_restores_coverage() {
    let dir = Temp::new();
    let mut db = Store::open(&dir.0).unwrap();
    let (job, report) = fixture();
    let (mut c, _tx, wire) = fake_client();
    db.begin([1; 16], [2; 16], &job, false).unwrap();
    c.start([1; 16], [2; 16], Command::Start(job.clone()))
        .unwrap();
    let (out, _rx) = mpsc::sync_channel(32);
    let prepared = Envelope::new(
        c.session,
        c.scan,
        c.attempt,
        1,
        Event::NetworkPrepared {
            bytes: report.encode().unwrap(),
        },
    );
    commit_scan_events(
        &mut db,
        &mut c,
        vec![prepared],
        &out,
        Some([1; 16]),
        &|| false,
    )
    .unwrap();
    let checkpoint = NetworkCheckpoint {
        report: report.clone(),
        engine: rmasscan_engine::Checkpoint {
            format_version: rmasscan_engine::CHECKPOINT_FORMAT_VERSION,
            engine_version: ENGINE_VERSION,
            scan_id: c.scan,
            attempt_id: c.attempt,
            job_digest: rmasscan_engine::job_digest(&job.prepare_network(&report).unwrap()),
            next_index: 1,
        }
        .to_bytes(),
    }
    .encode()
    .unwrap();
    let paused = Envelope::new(
        c.session,
        c.scan,
        c.attempt,
        2,
        Event::Checkpoint {
            bytes: checkpoint.clone(),
            next_index: "1".into(),
        },
    );
    commit_scan_events(&mut db, &mut c, vec![paused], &out, Some([1; 16]), &|| {
        false
    })
    .unwrap();
    assert!(matches!(
        wire.commands().last().unwrap().payload,
        Command::AckCheckpoint { through: 2 }
    ));
    let saved = db.scans().unwrap().remove(0);
    assert_eq!(saved.status, Status::Paused);
    assert_eq!(saved.network_report, Some(report.encode().unwrap()));
    drop(db);
    drop(c);
    let mut controller =
        Controller::open(dir.0.clone(), PathBuf::from("/nonexistent/studio-runner")).unwrap();
    let updates = wait_updates(&mut controller, |u| {
        u.iter().any(|v| matches!(v, Update::Profiles(..)))
    });
    assert!(updates.iter().any(|v|matches!(v,Update::NetworkCoverage(Some(coverage)) if coverage.report==report && coverage.job==job)));
    controller.send(Action::Resume).unwrap();
    let updates = wait_updates(&mut controller, |u| {
        u.iter()
            .any(|v| matches!(v,Update::State(_,detail) if detail.contains("Raw resume is gated")))
    });
    assert!(updates.iter().any(
        |v| matches!(v,Update::NetworkCoverage(Some(coverage)) if coverage.unresolved_targets==1)
    ));
    drop(controller);
    let db = Store::open(&dir.0).unwrap();
    let saved = db.scans().unwrap().remove(0);
    assert_eq!(saved.status, Status::Paused);
    assert_eq!(saved.checkpoint, Some(checkpoint));
    assert_eq!(saved.job, job);
}

#[test]
fn malformed_physical_settings_are_reported_without_starting_or_authorizing() {
    let dir = Temp::new();
    let mut c =
        Controller::open(dir.0.clone(), PathBuf::from("/nonexistent/studio-runner")).unwrap();
    wait_updates(&mut c, |u| {
        u.iter().any(|v| matches!(v, Update::Profiles(..)))
    });
    let mut job = fixture().0;
    job.ports = "0".into();
    for action in [
        Action::SetDraft(job.clone()),
        Action::CheckNetwork(job.clone()),
        Action::AuthorizeFor(job),
    ] {
        c.send(action).unwrap();
        let updates = wait_updates(&mut c, |u| {
            u.iter().any(
                |v| matches!(v,Update::NetworkReadiness(Some(state)) if state.job_digest.is_none()),
            )
        });
        assert!(
            !updates
                .iter()
                .any(|v| matches!(v, Update::Authorization { .. } | Update::State(..)))
        );
    }
    drop(c);
    assert!(Store::open(&dir.0).unwrap().scans().unwrap().is_empty());
}

#[test]
fn queued_start_before_stop_is_cancelled_even_before_worker_reads_actions() {
    let dir = Temp::new();
    let db = Store::open(&dir.0).unwrap();
    let (commands, rx) = mpsc::sync_channel(8);
    let (out, updates) = mpsc::sync_channel(32);
    let stop = Arc::new(AtomicBool::new(false));
    let epoch = Arc::new(AtomicU64::new(0));
    let cancel_auth = Arc::new(AtomicBool::new(false));
    let setup_pending = Arc::new(AtomicBool::new(false));
    let cancel_setup = Arc::new(AtomicBool::new(false));
    let mut c = Controller {
        commands,
        updates,
        stop: stop.clone(),
        cancel_auth: cancel_auth.clone(),
        cancel_epoch: epoch.clone(),
        setup_pending: setup_pending.clone(),
        cancel_setup: cancel_setup.clone(),
        error: Arc::new(Mutex::new(None)),
        worker: None,
    };
    c.send(Action::Start(Job::example(Backend::Simulation)))
        .unwrap();
    c.send(Action::Stop).unwrap();
    c.send(Action::SetDraft(fixture().0)).unwrap();
    c.worker = Some(thread::spawn(move || {
        work(
            db,
            PathBuf::from("/must-not-spawn"),
            rx,
            out,
            (stop, epoch),
            cancel_auth,
            (setup_pending, cancel_setup),
        )
        .unwrap()
    }));
    let updates = wait_updates(&mut c, |u| {
        u.iter()
            .any(|v| matches!(v, Update::NetworkReadiness(Some(_))))
    });
    assert!(!updates.iter().any(|v| matches!(v, Update::State(..))));
    drop(c);
    assert!(Store::open(&dir.0).unwrap().scans().unwrap().is_empty());
}

#[test]
fn original_requested_counts_handle_full_ipv4_union_without_expansion() {
    let dir = Temp::new();
    let mut db = Store::open(&dir.0).unwrap();
    let (mut job, mut report) = fixture();
    job.targets = "0.0.0.0/0,10.0.0.1".into();
    job.exclusions = "0.0.0.0-10.0.0.0,10.0.0.3-255.255.255.255".into();
    job.ports = "1-65535,80,90".into();
    report.job_digest = job.original_digest().unwrap();
    db.begin([1; 16], [2; 16], &job, false).unwrap();
    db.apply(&Envelope::new(
        [3; 16],
        [1; 16],
        [2; 16],
        1,
        Event::NetworkPrepared {
            bytes: report.encode().unwrap(),
        },
    ))
    .unwrap();
    let coverage = NetworkCoverage::from_saved(&db.scans().unwrap()[0])
        .unwrap()
        .unwrap();
    assert_eq!(coverage.requested_inputs, 2);
    assert_eq!(coverage.requested_targets, 1u64 << 32);
    assert_eq!(coverage.requested_probes, (1u64 << 32) * 65535);
    assert_eq!(
        (
            coverage.candidate_targets,
            coverage.effective_targets,
            coverage.eligible_targets
        ),
        (2, 2, 1)
    );
    assert_eq!(
        (
            coverage.candidate_probes,
            coverage.effective_probes,
            coverage.eligible_probes
        ),
        (131070, 131070, 65535)
    );
}
