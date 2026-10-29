use super::*;
use policy::{
    ownership::{InterfaceIdentity, OwnedRoute},
    topology::*,
};
use std::sync::atomic::{AtomicUsize, Ordering};
struct Fake {
    state: Mutex<State>,
    routes: Mutex<PhysicalRoutePlan>,
    missing_seal: AtomicBool,
    opens: AtomicUsize,
    resolves: AtomicUsize,
    plans: AtomicUsize,
    cancel_on_plan: AtomicBool,
    replace_on_plan: AtomicBool,
    bad_mac: AtomicBool,
    late_open: AtomicBool,
    cancel: AtomicBool,
    io: rmasscan_engine::fake::FakeAdapter,
}
fn routes() -> PhysicalRoutePlan {
    use rmasscan_net::ExcludedReason::*;
    PhysicalRoutePlan {
        interface_name: SCANNER.into(),
        interface_index: 42,
        source_ipv4: SOURCE,
        source_mac: Some(SOURCE_MAC),
        next_hops: [(A, A), (B, B), (MISSING, MISSING), (ROUTED, GATEWAY)].into(),
        excluded: [
            (std::net::Ipv4Addr::new(198, 18, 42, 0), NetworkAddress),
            (SOURCE, OwnAddress),
            (std::net::Ipv4Addr::new(198, 18, 42, 7), BroadcastAddress),
        ]
        .into(),
    }
}
fn fake() -> Arc<Fake> {
    Arc::new(Fake {
        state: Mutex::new(State {
            version: 1,
            generation: "1".repeat(32),
            created_utc_seconds: 100,
            expires_utc_seconds: 1900,
            tooling_sha256: "2".repeat(64),
            sealed: true,
            scanner: Some(InterfaceIdentity {
                name: SCANNER.into(),
                index: 42,
                mac: SOURCE_MAC,
                peer: Some(PEER.into()),
                ipv4: vec![SOURCE],
                ipv4_prefixes: vec![(SOURCE, 29)],
                bridges: vec![],
                up: true,
            }),
            peer: Some(InterfaceIdentity {
                name: PEER.into(),
                index: 43,
                mac: PEER_MAC,
                peer: Some(SCANNER.into()),
                ipv4: vec![],
                ipv4_prefixes: vec![],
                bridges: vec![],
                up: true,
            }),
            route: Some(OwnedRoute {
                destination: ROUTED.to_string(),
                prefix: 32,
                flags: "UGHS".into(),
                gateway: GATEWAY.to_string(),
                interface: SCANNER.into(),
            }),
        }),
        routes: Mutex::new(routes()),
        missing_seal: AtomicBool::new(false),
        opens: AtomicUsize::new(0),
        resolves: AtomicUsize::new(0),
        plans: AtomicUsize::new(0),
        cancel_on_plan: AtomicBool::new(false),
        replace_on_plan: AtomicBool::new(false),
        bad_mac: AtomicBool::new(false),
        late_open: AtomicBool::new(false),
        cancel: AtomicBool::new(false),
        io: rmasscan_engine::fake::FakeAdapter::new(),
    })
}
impl Host for Arc<Fake> {
    fn authorize(&self) -> Result<(), String> {
        Ok(())
    }
    fn seal(&self, _: Instant, _: &dyn Fn() -> bool) -> Result<(State, u64), String> {
        if self.missing_seal.load(Ordering::Relaxed) {
            return Err("missing seal".into());
        }
        Ok((self.state.lock().unwrap().clone(), 101))
    }
    fn plan(&self, _: &Job, _: Instant, _: &dyn Fn() -> bool) -> Result<PhysicalRoutePlan, String> {
        self.plans.fetch_add(1, Ordering::Relaxed);
        if self.replace_on_plan.load(Ordering::Relaxed) {
            self.state.lock().unwrap().generation = "3".repeat(32);
        }
        if self.cancel_on_plan.load(Ordering::Relaxed) {
            self.cancel.store(true, Ordering::Relaxed);
        }
        Ok(self.routes.lock().unwrap().clone())
    }
    fn open(&self, _: &AdapterBinding) -> Result<AdapterPair, String> {
        self.opens.fetch_add(1, Ordering::Relaxed);
        let pair = self.io.pair();
        if self.late_open.load(Ordering::Relaxed) {
            self.cancel.store(true, Ordering::Relaxed);
        }
        Ok(pair)
    }
    fn resolve(
        &self,
        _: &mut AdapterPair,
        plan: &PhysicalRoutePlan,
        _: &dyn Fn() -> bool,
    ) -> Result<NeighbourReport, String> {
        self.resolves.fetch_add(1, Ordering::Relaxed);
        Ok(NeighbourReport {
            destinations: [
                (A, A_MAC),
                (
                    B,
                    if self.bad_mac.load(Ordering::Relaxed) {
                        A_MAC
                    } else {
                        B_MAC
                    },
                ),
                (ROUTED, GATEWAY_MAC),
            ]
            .into(),
            unresolved_on_link: if plan.next_hops.contains_key(&MISSING) {
                vec![MISSING]
            } else {
                vec![]
            },
            requests_sent: 0,
            elapsed: Duration::ZERO,
        })
    }
}
fn native(host: &Arc<Fake>) -> Native {
    Native {
        host: Box::new(host.clone()),
        pin: Mutex::new(Pin::default()),
    }
}
fn binding() -> AdapterBinding {
    AdapterBinding {
        interface_id: SCANNER.into(),
        link_type: rmasscan_core::packet::LinkType::Ethernet,
        source_ipv4: SOURCE.into(),
        source_mac: SOURCE_MAC,
        next_hop_mac: [0xff; 6],
        source_ports: (40000, 40000),
    }
}
#[test]
fn missing_expired_replaced_seals_refuse_before_plan_adapter_and_arp() {
    for defect in 0..5 {
        let host = fake();
        let env = native(&host);
        if defect >= 2 {
            env.observe(&job(), Instant::now() + Duration::from_secs(1), &|| false)
                .unwrap();
        }
        match defect {
            0 => host.missing_seal.store(true, Ordering::Relaxed),
            1 => host.state.lock().unwrap().expires_utc_seconds = 101,
            2 => host.state.lock().unwrap().generation = "3".repeat(32),
            3 => host.state.lock().unwrap().scanner.as_mut().unwrap().index = 44,
            _ => host.state.lock().unwrap().route = None,
        }
        let plans = host.plans.load(Ordering::Relaxed);
        assert!(env.neighbours(&routes(), &|| false).is_err());
        assert_eq!(host.plans.load(Ordering::Relaxed), plans);
        assert_eq!(host.opens.load(Ordering::Relaxed), 0);
        assert_eq!(host.resolves.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn drift_after_observation_and_bad_bindings_never_open_or_arp() {
    for defect in 0..5 {
        let host = fake();
        let env = native(&host);
        env.observe(&job(), Instant::now() + Duration::from_secs(1), &|| false)
            .unwrap();
        let mut binding = binding();
        match defect {
            0 => host.routes.lock().unwrap().interface_name = "en0".into(),
            1 => {
                host.routes.lock().unwrap().next_hops.insert(ROUTED, SOURCE);
            }
            2 => host.routes.lock().unwrap().source_mac = Some(A_MAC),
            3 => binding.source_ports = (1234, 1234),
            _ => binding.source_ipv4 = u32::from(A),
        }
        assert!(
            env.open(&binding, Instant::now() + Duration::from_secs(1), &|| false)
                .is_err()
        );
        assert_eq!(host.opens.load(Ordering::Relaxed), 0);
        assert_eq!(host.resolves.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn valid_frozen_resume_only_resolves_exact_eligible_subset() {
    let host = fake();
    let env = native(&host);
    let mut eligible = routes();
    eligible.next_hops.remove(&MISSING);
    assert!(
        env.neighbours(&eligible, &|| false)
            .unwrap()
            .unresolved_on_link
            .is_empty()
    );
    assert_eq!(host.opens.load(Ordering::Relaxed), 1);
    assert_eq!(host.resolves.load(Ordering::Relaxed), 1);
    eligible.next_hops.remove(&B);
    assert!(env.neighbours(&eligible, &|| false).is_err());
    assert_eq!(host.opens.load(Ordering::Relaxed), 1);
    assert_eq!(host.io.alive_handles(), 0);
}
#[test]
fn cancellation_deadline_and_late_open_cannot_publish_packet_handles() {
    for defect in 0..4 {
        let host = fake();
        let env = native(&host);
        let deadline = if defect == 0 {
            Instant::now()
        } else {
            Instant::now() + Duration::from_secs(1)
        };
        if defect == 1 {
            host.cancel.store(true, Ordering::Relaxed);
        }
        if defect == 2 {
            host.cancel_on_plan.store(true, Ordering::Relaxed);
        }
        if defect == 3 {
            host.late_open.store(true, Ordering::Relaxed);
        }
        assert!(
            env.open(&binding(), deadline, &|| host
                .cancel
                .load(Ordering::Relaxed))
                .is_err()
        );
        assert_eq!(host.opens.load(Ordering::Relaxed), usize::from(defect == 3));
        assert_eq!(host.io.alive_handles(), 0);
        assert_eq!(host.resolves.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn replacement_during_observation_and_bad_resolved_macs_are_refused() {
    let host = fake();
    let env = native(&host);
    host.replace_on_plan.store(true, Ordering::Relaxed);
    assert!(
        env.observe(&job(), Instant::now() + Duration::from_secs(1), &|| false)
            .unwrap_err()
            .contains("replaced")
    );
    assert_eq!(host.opens.load(Ordering::Relaxed), 0);
    let host = fake();
    let env = native(&host);
    host.bad_mac.store(true, Ordering::Relaxed);
    assert!(
        env.neighbours(&routes(), &|| false)
            .unwrap_err()
            .contains("MACs")
    );
    assert_eq!(host.io.alive_handles(), 0);
}
#[test]
fn real_prepare_resume_preserves_frozen_missing_coverage_and_new_attempt() {
    let host = fake();
    let env = native(&host);
    let initial = prepare(&env, job(), [1; 16], [2; 16], None, &|| false).unwrap();
    let checkpoint = studio_protocol::NetworkCheckpoint {
        report: initial.report.clone(),
        engine: rmasscan_engine::Checkpoint {
            format_version: rmasscan_engine::CHECKPOINT_FORMAT_VERSION,
            engine_version: studio_protocol::ENGINE_VERSION,
            scan_id: [1; 16],
            attempt_id: [2; 16],
            job_digest: rmasscan_engine::job_digest(
                &job().prepare_network(&initial.report).unwrap(),
            ),
            next_index: 4,
        }
        .to_bytes(),
    }
    .encode()
    .unwrap();
    let resumed = prepare(&env, job(), [1; 16], [3; 16], Some(checkpoint), &|| false).unwrap();
    assert_eq!(resumed.report, initial.report);
    assert_eq!(resumed.report.unresolved, vec![MISSING]);
    assert_eq!(resumed.checkpoint.unwrap().next_index, 4);
    assert_eq!(host.resolves.load(Ordering::Relaxed), 2);
    assert_eq!(host.io.alive_handles(), 0);
}
