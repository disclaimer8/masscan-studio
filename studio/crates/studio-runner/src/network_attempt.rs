//! Physical attempt state transitions; only this command-loop owner may launch TCP.
use super::{Attempt, CheckpointAck, guard, network, outbox, send};
use rmasscan_engine::{Engine, EngineOptions};
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use studio_protocol::{Event, Id, Job, NetworkReport, Status};

enum Phase {
    Preparing(network::Worker<network::Prepared>),
    Waiting {
        prepared: Box<network::Prepared>,
        ack: CheckpointAck,
    },
    Launching(network::Worker<network::Launch>),
    // Network handoff is done; a running Engine is owned by Attempt.
    Finished,
}
pub struct State {
    phase: Phase,
    env: Arc<dyn network::Environment>,
    pub report: Option<NetworkReport>,
    stopping: bool,
    report_sequence: Option<u64>,
    clock: guard::Clock,
    interruption: Option<String>,
}
impl State {
    pub fn start(
        env: Arc<dyn network::Environment>,
        job: Job,
        scan: Id,
        attempt: Id,
        checkpoint: Option<Vec<u8>>,
    ) -> Result<Self, String> {
        let worker_env = env.clone();
        let worker = network::Worker::spawn(move |cancel| {
            network::prepare(worker_env.as_ref(), job, scan, attempt, checkpoint, cancel)
        })?;
        Ok(Self {
            phase: Phase::Preparing(worker),
            env,
            report: None,
            stopping: false,
            report_sequence: None,
            clock: guard::Clock::new(),
            interruption: None,
        })
    }
    pub fn active(&self) -> bool {
        !matches!(self.phase, Phase::Finished)
    }
    fn check_gap_at(&mut self, tick: Instant, wall: SystemTime) {
        if self.active()
            && !self.stopping
            && let Some(error) = self.clock.check(tick, wall)
        {
            self.interruption = Some(format!(
                "Attempt interrupted: {error}. Start a new scan after checking the network."
            ));
            self.stop();
        }
    }
    fn cancellation(&self, detail: &str) -> (Status, String) {
        match &self.interruption {
            Some(reason) => (Status::Interrupted, reason.clone()),
            None => (Status::Stopped, detail.into()),
        }
    }
    pub fn stop(&mut self) {
        self.stopping = true;
        match &self.phase {
            Phase::Preparing(w) => w.cancel(),
            Phase::Launching(w) => w.cancel(),
            _ => {}
        }
    }
    pub fn acknowledge(&mut self, through: u64) -> Result<(), String> {
        if self.stopping && self.report_sequence == Some(through) {
            // The app can commit/queue its ACK just before the user requests Stop.
            // Authenticate/order it in the command loop, but never revive cancelled work.
            return Ok(());
        }
        if !matches!(&self.phase,Phase::Waiting{ack,..} if ack.sequence==through) {
            return Err("Network report ACK does not match".into());
        }
        if let Phase::Waiting { prepared, .. } = std::mem::replace(&mut self.phase, Phase::Finished)
        {
            let env = self.env.clone();
            self.phase = Phase::Launching(network::Worker::spawn(move |cancel| {
                network::launch(env, *prepared, cancel)
            })?);
        }
        Ok(())
    }
}
pub fn poll(events: &outbox::Sender, session: Id, a: &mut Attempt) -> Result<(), String> {
    let Some(mut state) = a.network.take() else {
        return Ok(());
    };
    // Check BEFORE publishing a prepared report or consuming a launch result.
    // This shares the running guard policy and prevents TCP startup after wake.
    state.check_gap_at(Instant::now(), SystemTime::now());
    let result = poll_inner(events, session, a, &mut state);
    a.network = Some(state);
    result
}
fn poll_inner(
    events: &outbox::Sender,
    session: Id,
    a: &mut Attempt,
    state: &mut State,
) -> Result<(), String> {
    let finished = match &mut state.phase {
        Phase::Preparing(worker) => {
            let Some(result) = worker.poll() else {
                return Ok(());
            };
            state.phase = Phase::Finished;
            if state.stopping {
                drop(result);
                Some(state.cancellation("Stopped during network preparation"))
            } else {
                match result {
                    Err(error) => Some((Status::Failed, error)),
                    Ok(prepared) => {
                        a.sequence += 1;
                        let receipt = events.try_send_tracked(studio_protocol::Envelope::new(
                            session,
                            a.scan,
                            a.id,
                            a.sequence,
                            Event::NetworkPrepared {
                                bytes: prepared.report.encode()?,
                            },
                        ))?;
                        state.report = Some(prepared.report.clone());
                        state.report_sequence = Some(a.sequence);
                        state.phase = Phase::Waiting {
                            prepared: Box::new(prepared),
                            ack: CheckpointAck {
                                sequence: a.sequence,
                                queued: Instant::now(),
                                receipt,
                            },
                        };
                        None
                    }
                }
            }
        }
        Phase::Waiting { ack, .. } => {
            if state.stopping {
                state.phase = Phase::Finished;
                Some(state.cancellation("Stopped before network report acknowledgement"))
            } else if let Some(error) = ack.timeout(Instant::now(), events.idle_for()) {
                let error = error.replace("Checkpoint", "Network report");
                state.phase = Phase::Finished;
                Some((Status::Failed, error))
            } else {
                None
            }
        }
        Phase::Launching(worker) => {
            let Some(result) = worker.poll() else {
                return Ok(());
            };
            state.phase = Phase::Finished;
            if state.stopping {
                drop(result);
                Some(state.cancellation("Stopped before TCP startup"))
            } else {
                match result.and_then(|ready| {
                    if ready.observed.elapsed() >= Duration::from_secs(3) {
                        return Err(
                            "Final network observation became stale before TCP startup".into()
                        );
                    }
                    let mut options = EngineOptions::new(a.scan, a.id);
                    options.event_batch_limit = 128;
                    let engine = match ready.checkpoint {
                        Some(cp) => Engine::resume(ready.plan, cp, ready.pair, options),
                        None => Engine::start(ready.plan, ready.pair, options),
                    }
                    .map_err(|e| e.to_string())?;
                    let guard = guard::Guard::new(engine.cancel_handle(), Some(ready.inspector))?;
                    Ok((engine, guard))
                }) {
                    Ok((engine, guard)) => {
                        a.engine = Some(engine);
                        a.guard = Some(guard);
                        None
                    }
                    Err(error) => Some((Status::Failed, error)),
                }
            }
        }
        Phase::Finished => None,
    };
    if let Some((status, detail)) = finished {
        send(events, session, a, Event::Finished { status, detail })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use studio_protocol::{Backend, Envelope, ReceiveOrder, read_frame};
    fn attempt(state: State) -> Attempt {
        Attempt {
            scan: [2; 16],
            id: [3; 16],
            order: ReceiveOrder::new([1; 16], [2; 16], [3; 16]),
            sequence: 1,
            engine: None,
            guard: None,
            pending: None,
            network: Some(state),
            rows: vec![],
            progress: None,
            flushed: Instant::now(),
        }
    }
    fn prepared() -> network::Prepared {
        let mut job = Job::example(Backend::MacNetwork);
        job.targets = "10.0.0.1".into();
        let target = "10.0.0.1".parse().unwrap();
        let report = NetworkReport {
            job_digest: job.original_digest().unwrap(),
            routes: rmasscan_net::PhysicalRoutePlan {
                interface_name: "en0".into(),
                interface_index: 1,
                source_ipv4: "10.0.0.99".parse().unwrap(),
                source_mac: Some([2, 1, 2, 3, 4, 5]),
                next_hops: [(target, target)].into(),
                excluded: Default::default(),
            },
            destinations: [(target, [2, 0, 0, 0, 0, 1])].into(),
            unresolved: vec![],
        };
        network::Prepared {
            job,
            report,
            checkpoint: None,
        }
    }
    #[test]
    fn suspension_during_preparation_and_ack_wait_interrupts_without_launching() {
        for preparing in [true, false] {
            for wall_only in [true, false] {
                let (events, output) = outbox::channel();
                let closed = Arc::new(AtomicBool::new(false));
                let done = closed.clone();
                let phase = if preparing {
                    Phase::Preparing(
                        network::Worker::spawn(move |cancel| {
                            while !cancel() {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            done.store(true, Ordering::Release);
                            Ok(prepared())
                        })
                        .unwrap(),
                    )
                } else {
                    let receipt = events
                        .try_send_tracked(Envelope::new(
                            [1; 16],
                            [2; 16],
                            [3; 16],
                            1,
                            Event::NetworkPrepared {
                                bytes: prepared().report.encode().unwrap(),
                            },
                        ))
                        .unwrap();
                    output.recv().unwrap().write(&mut Vec::new()).unwrap();
                    Phase::Waiting {
                        prepared: Box::new(prepared()),
                        ack: CheckpointAck {
                            sequence: 1,
                            queued: Instant::now(),
                            receipt,
                        },
                    }
                };
                let mut state = State {
                    phase,
                    env: Arc::new(network::Native),
                    report: None,
                    stopping: false,
                    report_sequence: (!preparing).then_some(1),
                    clock: guard::Clock::new(),
                    interruption: None,
                };
                state.check_gap_at(
                    Instant::now()
                        + if wall_only {
                            Duration::ZERO
                        } else {
                            Duration::from_secs(6)
                        },
                    SystemTime::now() + Duration::from_secs(6),
                );
                if !preparing {
                    state.acknowledge(1).unwrap();
                }
                let mut a = attempt(state);
                let deadline = Instant::now() + Duration::from_secs(2);
                while a.network.as_ref().unwrap().active() {
                    assert!(Instant::now() < deadline);
                    poll(&events, [1; 16], &mut a).unwrap();
                    std::thread::sleep(Duration::from_millis(1));
                }
                let mut bytes = vec![];
                output.recv().unwrap().write(&mut bytes).unwrap();
                let event = read_frame::<Event>(&mut std::io::Cursor::new(bytes)).unwrap();
                assert!(
                    matches!(event.payload,Event::Finished{status:Status::Interrupted,detail} if detail.contains("suspension"))
                );
                assert!(a.engine.is_none());
                assert!(output.try_recv().is_err());
                if preparing {
                    assert!(closed.load(Ordering::Acquire));
                }
            }
        }
    }
    #[test]
    fn suspension_discards_a_completed_post_ack_launch_and_closes_its_pair() {
        let fake = rmasscan_engine::fake::FakeAdapter::new();
        let pair = fake.pair();
        let p = prepared();
        let worker = network::Worker::spawn(move |_| {
            Ok(network::Launch {
                plan: p.job.prepare_network(&p.report).unwrap(),
                pair,
                checkpoint: None,
                inspector: Box::new(|_| Ok(guard::Observation::Valid)),
                observed: Instant::now(),
            })
        })
        .unwrap();
        let mut state = State {
            phase: Phase::Launching(worker),
            env: Arc::new(network::Native),
            report: None,
            stopping: false,
            report_sequence: Some(1),
            clock: guard::Clock::new(),
            interruption: None,
        };
        state.check_gap_at(Instant::now(), SystemTime::now() + Duration::from_secs(6));
        let mut a = attempt(state);
        let (events, output) = outbox::channel();
        let deadline = Instant::now() + Duration::from_secs(2);
        while a.network.as_ref().unwrap().active() {
            assert!(Instant::now() < deadline);
            poll(&events, [1; 16], &mut a).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut bytes = vec![];
        output.recv().unwrap().write(&mut bytes).unwrap();
        assert!(matches!(
            read_frame::<Event>(&mut std::io::Cursor::new(bytes))
                .unwrap()
                .payload,
            Event::Finished {
                status: Status::Interrupted,
                ..
            }
        ));
        assert!(a.engine.is_none());
        assert_eq!(fake.sent_count(), 0);
        assert_eq!(fake.alive_handles(), 0);
    }
}
