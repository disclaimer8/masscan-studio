use super::*;
use std::collections::BTreeMap;
#[derive(Clone)]
struct Fake {
    data: Arc<Mutex<Data>>,
    io: rmasscan_engine::fake::FakeAdapter,
    clock: Arc<rmasscan_engine::fake::ManualClock>,
}
struct Data {
    permit: Permit,
    plan: PhysicalRoutePlan,
    now: u64,
    uid: u32,
    capture: bool,
    missing: bool,
    claim: Option<Claim>,
    calls: Vec<&'static str>,
    lose_on_open: bool,
    mac: [u8; 6],
    real_resolve: bool,
    cancel_in_plan: Option<Arc<AtomicBool>>,
}
impl Fake {
    fn setup() -> (Self, SingleTarget, Job) {
        let permit = Permit {
            version: 1,
            generation: "1".repeat(32),
            owner_uid: 501,
            created: 1000,
            expires: 1300,
            tooling_sha256: "a".repeat(64),
            helper_sha256: "b".repeat(64),
            target: "45.33.32.156".parse().unwrap(),
            ports: vec![80, 443],
            seed: 42,
            interface: studio_protocol::single_target::InterfaceBinding {
                name: "en0".into(),
                index: 5,
                source_ipv4: "10.0.0.2".parse().unwrap(),
                source_mac: [2, 1, 2, 3, 4, 5],
                next_hop: "10.0.0.1".parse().unwrap(),
            },
        };
        let job = permit.job();
        let clock = rmasscan_engine::fake::ManualClock::new();
        let fake = Self {
            data: Arc::new(Mutex::new(Data {
                plan: permit.plan(),
                permit,
                now: 1002,
                uid: 501,
                capture: true,
                missing: false,
                claim: None,
                calls: vec![],
                lose_on_open: false,
                mac: [2, 6, 7, 8, 9, 10],
                real_resolve: false,
                cancel_in_plan: None,
            })),
            io: rmasscan_engine::fake::FakeAdapter::new().with_clock(clock.clone()),
            clock,
        };
        let env = fake.environment();
        (fake, env, job)
    }
    fn environment(&self) -> SingleTarget {
        SingleTarget {
            host: Box::new(self.clone()),
            state: Mutex::new(State::default()),
            rejected: Arc::new(AtomicBool::new(false)),
        }
    }
}
impl Host for Fake {
    fn transmission(
        &self,
        p: &Permit,
        context: &Context<'_>,
        claim: &Claim,
        attempt: Id,
        witness: &CaptureWitness,
        deadline: Instant,
    ) -> Result<Admission, String> {
        let p = p.clone();
        let claim = claim.clone();
        let expires = p.expires.min(witness.created + 40);
        let data = self.data.clone();
        let mut last = context.now;
        Ok(Box::new(move |io_deadline| {
            let d = data.lock().unwrap();
            if d.missing
                || d.permit != p
                || !d.capture
                || d.uid != p.owner_uid
                || d.now < last
                || d.now >= expires
                || d.claim.as_ref() != Some(&claim)
                || claim.attempt != attempt
                || Instant::now() >= deadline
                || Instant::now() >= io_deadline
            {
                return Err("Packet permission lost".into());
            }
            last = d.now;
            Ok(deadline.min(io_deadline))
        }))
    }
    fn authority(&self) -> Result<Authority, String> {
        let d = self.data.lock().unwrap();
        Ok(Authority {
            now: d.now,
            uid: d.uid,
            tool: "a".repeat(64),
            helper: "b".repeat(64),
        })
    }
    fn permit(&self, _: &Context<'_>) -> Result<Permit, String> {
        let d = self.data.lock().unwrap();
        if d.missing {
            Err("missing permit".into())
        } else {
            Ok(d.permit.clone())
        }
    }
    fn capture(&self, p: &Permit, _: &Context<'_>) -> Result<CaptureWitness, String> {
        let mut d = self.data.lock().unwrap();
        d.calls.push("capture");
        if !d.capture {
            return Err("capture unavailable".into());
        }
        Ok(CaptureWitness {
            generation: p.generation.clone(),
            nonce: "2".repeat(32),
            permit_sha256: "c".repeat(64),
            created: 1001,
            process: studio_platform::unix::Identity {
                uid: 0,
                pid: 123,
                birth: [1, 2],
                executable: studio_platform::macos::installed_path(&p.tooling_sha256).unwrap(),
            },
            lease_file: [1, 2],
        })
    }
    fn claim(&self, p: &Permit, _: &Context<'_>, attempt: Id) -> Result<Claim, String> {
        let mut d = self.data.lock().unwrap();
        d.calls.push("claim");
        if d.claim.is_some() {
            return Err("claim consumed".into());
        }
        let c = Claim {
            generation: p.generation.clone(),
            permit_sha256: "c".repeat(64),
            attempt,
            helper_pid: std::process::id(),
        };
        d.claim = Some(c.clone());
        Ok(c)
    }
    fn verify_claim(
        &self,
        _: &Permit,
        _: &Context<'_>,
        claim: &Claim,
        attempt: Id,
    ) -> Result<(), String> {
        let mut d = self.data.lock().unwrap();
        d.calls.push("verify-claim");
        if d.claim.as_ref() != Some(claim) || claim.attempt != attempt {
            return Err("claim changed".into());
        }
        Ok(())
    }
    fn plan(&self, _: &Job, _: Instant, _: &dyn Fn() -> bool) -> Result<PhysicalRoutePlan, String> {
        let mut d = self.data.lock().unwrap();
        d.calls.push("plan");
        if let Some(flag) = &d.cancel_in_plan {
            flag.store(true, Ordering::Release);
            return Err("route read interrupted".into());
        }
        Ok(d.plan.clone())
    }
    fn open(&self, _: &AdapterBinding) -> Result<AdapterPair, String> {
        let mut d = self.data.lock().unwrap();
        d.calls.push("open");
        if d.lose_on_open {
            d.capture = false;
        }
        Ok(self.io.pair())
    }
    fn resolve(
        &self,
        pair: &mut AdapterPair,
        plan: &PhysicalRoutePlan,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<NeighbourReport, String> {
        if self.data.lock().unwrap().real_resolve {
            return rmasscan_net::resolve_neighbours(pair, plan, self.clock.as_ref(), cancelled)
                .map_err(|e| e.to_string());
        }
        let mut d = self.data.lock().unwrap();
        d.calls.push("arp-send");
        Ok(NeighbourReport {
            destinations: plan
                .next_hops
                .keys()
                .map(|ip| (*ip, d.mac))
                .collect::<BTreeMap<_, _>>(),
            unresolved_on_link: vec![],
            requests_sent: 1,
            elapsed: Duration::from_millis(1),
        })
    }
}
#[test]
fn actual_resolver_stops_after_first_arp_when_capture_permit_or_claim_changes() {
    for kind in 0..4 {
        let (fake, env, job) = Fake::setup();
        fake.data.lock().unwrap().real_resolve = true;
        let data = fake.data.clone();
        fake.io.set_send_hook(move |_| {
            let mut d = data.lock().unwrap();
            match kind {
                0 => d.capture = false,
                1 => d.missing = true,
                2 => d.now = 1400,
                _ => d.claim.as_mut().unwrap().attempt = [9; 16],
            };
        });
        assert!(prepare(&env, job, [1; 16], [2; 16], None, &|| false).is_err());
        assert_eq!(
            fake.io.sent_count(),
            1,
            "ARP must not retry after trusted admission fails"
        );
        assert_eq!(fake.io.alive_handles(), 0);
    }
}
#[test]
fn one_use_claim_precedes_arp_and_tcp_requires_the_frozen_mac() {
    let (fake, env, job) = Fake::setup();
    let prepared = prepare(&env, job, [1; 16], [2; 16], None, &|| false).unwrap();
    assert_eq!(fake.io.alive_handles(), 0);
    let d = fake.data.lock().unwrap();
    assert_eq!(d.claim.as_ref().unwrap().attempt, [2; 16]);
    let pos = |name| d.calls.iter().position(|c| *c == name).unwrap();
    assert!(pos("capture") < pos("claim"));
    assert!(pos("claim") < pos("open"));
    assert!(pos("open") < pos("arp-send"));
    drop(d);
    let env = Arc::new(env);
    let launch = launch(env.clone(), prepared, &|| false).unwrap();
    drop(launch);
    assert_eq!(fake.io.alive_handles(), 0);
    assert!(
        env.begin_attempt(&fake.data.lock().unwrap().permit.job(), [3; 16], false)
            .is_err()
    );
}
#[test]
fn read_only_preflight_does_not_claim_but_attempt_requires_live_capture() {
    let (fake, env, job) = Fake::setup();
    fake.data.lock().unwrap().capture = false;
    preflight(&env, &job, &|| false).unwrap();
    assert!(fake.data.lock().unwrap().claim.is_none());
    assert!(!fake.data.lock().unwrap().calls.contains(&"open"));
    assert!(prepare(&env, job, [1; 16], [2; 16], None, &|| false).is_err());
    assert!(fake.data.lock().unwrap().claim.is_none());
}
#[test]
fn expired_missing_wrong_owner_and_job_fail_before_claim_and_stay_poisoned() {
    for kind in 0..4 {
        let (fake, env, mut job) = Fake::setup();
        {
            let mut d = fake.data.lock().unwrap();
            match kind {
                0 => d.now = 1400,
                1 => d.missing = true,
                2 => d.uid = 502,
                _ => job.rate = 2,
            };
        }
        assert!(prepare(&env, job.clone(), [1; 16], [2; 16], None, &|| false).is_err());
        {
            let mut d = fake.data.lock().unwrap();
            assert!(d.claim.is_none());
            assert!(!d.calls.contains(&"open"));
            d.now = 1002;
            d.uid = 501;
            d.missing = false;
        }
        assert!(prepare(&env, job, [1; 16], [3; 16], None, &|| false).is_err());
    }
}
#[test]
fn capture_loss_during_adapter_open_closes_pair_before_arp() {
    let (fake, env, job) = Fake::setup();
    fake.data.lock().unwrap().lose_on_open = true;
    assert!(prepare(&env, job, [1; 16], [2; 16], None, &|| false).is_err());
    let d = fake.data.lock().unwrap();
    assert!(d.claim.is_some());
    assert!(d.calls.contains(&"open"));
    assert!(!d.calls.contains(&"arp-send"));
    assert_eq!(fake.io.alive_handles(), 0);
}
#[test]
fn route_drift_capture_loss_or_changed_claim_blocks_tcp_after_preparation() {
    for kind in 0..3 {
        let (fake, env, job) = Fake::setup();
        let prepared = prepare(&env, job, [1; 16], [2; 16], None, &|| false).unwrap();
        {
            let mut d = fake.data.lock().unwrap();
            match kind {
                0 => d.plan.interface_index += 1,
                1 => d.capture = false,
                _ => d.claim.as_mut().unwrap().attempt = [9; 16],
            };
        }
        assert!(launch(Arc::new(env), prepared, &|| false).is_err());
        assert_eq!(
            fake.data
                .lock()
                .unwrap()
                .calls
                .iter()
                .filter(|c| **c == "open")
                .count(),
            1
        );
        assert_eq!(fake.io.alive_handles(), 0);
    }
}
#[test]
fn a_new_helper_cannot_reuse_the_durable_claim_and_resume_never_opens() {
    let (fake, env, job) = Fake::setup();
    prepare(&env, job.clone(), [1; 16], [2; 16], None, &|| false).unwrap();
    let retry = fake.environment();
    assert!(prepare(&retry, job.clone(), [1; 16], [3; 16], None, &|| false).is_err());
    assert_eq!(
        fake.data
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| **c == "open")
            .count(),
        1
    );
    let (fake, env, job) = Fake::setup();
    assert!(env.begin_attempt(&job, [2; 16], true).is_err());
    assert!(fake.data.lock().unwrap().claim.is_none());
}
#[test]
fn candidate_selection_never_uses_public_policy_as_a_fixture_failure_fallback() {
    let (_, _, public) = Fake::setup();
    assert!(Candidate::select(&public).unwrap());
    let fixture = studio_protocol::sealed_fixture::topology::job();
    assert!(!Candidate::select(&fixture).unwrap());
    let mut bad = fixture;
    bad.targets = "198.18.42.2".into();
    assert!(Candidate::select(&bad).is_err());
    let mut bad = public;
    bad.targets.push_str("/32");
    assert!(Candidate::select(&bad).is_err());
}
#[test]
fn packet_gate_refuses_delayed_first_syn_after_capture_loss_revocation_or_expiry() {
    for kind in 0..4 {
        let (fake, env, job) = Fake::setup();
        let prepared = prepare(&env, job, [1; 16], [2; 16], None, &|| false).unwrap();
        let mut launched = launch(Arc::new(env), prepared, &|| false).unwrap();
        let mut cursor = rmasscan_core::probe::ProbeCursor::new(&launched.plan, 0).unwrap();
        let frame = cursor.current().unwrap().frame.clone();
        {
            let mut d = fake.data.lock().unwrap();
            match kind {
                0 => d.capture = false,
                1 => d.missing = true,
                2 => d.now = 1041,
                _ => d.claim.as_mut().unwrap().attempt = [9; 16],
            };
        }
        assert!(
            launched
                .pair
                .tx
                .send(&frame, Duration::from_millis(50))
                .is_err()
        );
        assert_eq!(fake.io.send_calls(), 0);
        drop(launched);
        assert_eq!(fake.io.alive_handles(), 0);
    }
}
#[test]
fn every_tcp_send_and_would_block_retry_rechecks_and_failure_cannot_recover() {
    for blocked in [false, true] {
        let (fake, env, job) = Fake::setup();
        let prepared = prepare(&env, job, [1; 16], [2; 16], None, &|| false).unwrap();
        let mut launched = launch(Arc::new(env), prepared, &|| false).unwrap();
        let mut cursor = rmasscan_core::probe::ProbeCursor::new(&launched.plan, 0).unwrap();
        let frame = cursor.current().unwrap().frame.clone();
        if blocked {
            fake.io
                .script_tx([rmasscan_engine::fake::TxStep::WouldBlockUnsent]);
        }
        let first = launched
            .pair
            .tx
            .send(&frame, Duration::from_millis(50))
            .unwrap();
        assert_eq!(
            first,
            if blocked {
                rmasscan_engine::SendStatus::WouldBlockUnsent
            } else {
                rmasscan_engine::SendStatus::Sent
            }
        );
        fake.data.lock().unwrap().capture = false;
        assert!(
            launched
                .pair
                .tx
                .send(&frame, Duration::from_millis(50))
                .is_err()
        );
        fake.data.lock().unwrap().capture = true;
        assert!(
            launched
                .pair
                .tx
                .send(&frame, Duration::from_millis(50))
                .is_err()
        );
        assert_eq!(fake.io.send_calls(), 1);
        assert_eq!(fake.io.sent_count(), usize::from(!blocked));
        assert_eq!(launched.pair.tx.max_batch(), 1);
        drop(launched);
        assert_eq!(fake.io.alive_handles(), 0);
    }
}

#[test]
fn cancelled_idle_preflight_does_not_consume_or_poison_the_attempt() {
    let (_, env, job) = Fake::setup();
    assert!(
        env.observe_preflight(&job, Instant::now() + Duration::from_secs(1), &|| true)
            .is_err()
    );
    assert!(!env.rejected.load(Ordering::Acquire));
    env.begin_attempt(&job, [2; 16], false).unwrap();
    assert!(
        env.observe(&job, Instant::now() + Duration::from_secs(1), &|| true)
            .is_err()
    );
    assert!(env.rejected.load(Ordering::Acquire));
}

#[test]
fn start_waits_for_retiring_preflight_state_without_poisoning() {
    let (_, env, job) = Fake::setup();
    std::thread::scope(|scope| {
        let held = env.state.lock().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let env = &env;
        let job = &job;
        let worker = scope.spawn(move || {
            tx.send(()).unwrap();
            env.begin_attempt(job, [2; 16], false)
        });
        rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(30));
        drop(held);
        worker.join().unwrap().unwrap();
    });
    assert!(!env.rejected.load(Ordering::Acquire));
}

#[test]
fn retiring_route_read_can_cancel_but_trust_failure_is_still_fatal() {
    let (fake, env, job) = Fake::setup();
    let cancelled = Arc::new(AtomicBool::new(false));
    fake.data.lock().unwrap().cancel_in_plan = Some(cancelled.clone());
    assert!(
        env.observe_preflight(&job, Instant::now() + Duration::from_secs(1), &|| cancelled
            .load(Ordering::Acquire))
            .is_err()
    );
    assert!(!env.rejected.load(Ordering::Acquire));
    fake.data.lock().unwrap().cancel_in_plan = None;
    env.begin_attempt(&job, [2; 16], false).unwrap();
    let (fake, env, job) = Fake::setup();
    fake.data.lock().unwrap().missing = true;
    assert!(
        env.observe_preflight(&job, Instant::now() + Duration::from_secs(1), &|| false)
            .is_err()
    );
    fake.data.lock().unwrap().missing = false;
    assert!(env.begin_attempt(&job, [2; 16], false).is_err());
}

#[test]
fn state_contention_respects_preflight_deadline_without_invalidating_holder() {
    let (_, env, job) = Fake::setup();
    let _held = env.state.lock().unwrap();
    let start = Instant::now();
    assert!(
        env.observe_preflight(&job, start + Duration::from_millis(30), &|| false)
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(!env.rejected.load(Ordering::Acquire));
}

#[test]
fn cancelled_old_preflight_arriving_after_start_cannot_poison_new_attempt() {
    let (_, env, job) = Fake::setup();
    env.begin_attempt(&job, [2; 16], false).unwrap();
    assert!(
        env.observe_preflight(&job, Instant::now() + Duration::from_secs(1), &|| true)
            .is_err()
    );
    assert!(!env.rejected.load(Ordering::Acquire));
    env.observe(&job, Instant::now() + Duration::from_secs(1), &|| false)
        .unwrap();
}
