use super::*;
use std::{collections::BTreeMap, net::Ipv4Addr, sync::Mutex};
fn ip(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, n)
}
struct Fake {
    routes: Mutex<PhysicalRoutePlan>,
    resolved: Mutex<BTreeMap<Ipv4Addr, [u8; 6]>>,
    calls: Mutex<Vec<&'static str>>,
}
impl Fake {
    fn new() -> (Job, Self) {
        let mut job = Job::example(studio_protocol::Backend::MacNetwork);
        job.targets = "10.0.0.1-10.0.0.3".into();
        job.ports = "80".into();
        (
            job,
            Self {
                routes: Mutex::new(PhysicalRoutePlan {
                    interface_name: "en0".into(),
                    interface_index: 1,
                    source_ipv4: ip(99),
                    source_mac: Some([2, 1, 2, 3, 4, 5]),
                    next_hops: [(ip(1), ip(1)), (ip(2), ip(2)), (ip(3), ip(254))].into(),
                    excluded: BTreeMap::new(),
                }),
                resolved: Mutex::new(
                    [(ip(1), [2, 0, 0, 0, 0, 1]), (ip(3), [2, 0, 0, 0, 0, 3])].into(),
                ),
                calls: Mutex::new(vec![]),
            },
        )
    }
}
impl Environment for Fake {
    fn authorize(&self) -> Result<(), String> {
        self.calls.lock().unwrap().push("authorize");
        Ok(())
    }
    fn observe(
        &self,
        _: &Job,
        _: Instant,
        _: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String> {
        self.calls.lock().unwrap().push("observe");
        Ok(self.routes.lock().unwrap().clone())
    }
    fn neighbours(
        &self,
        p: &PhysicalRoutePlan,
        _: &dyn Fn() -> bool,
    ) -> Result<NeighbourReport, String> {
        self.calls.lock().unwrap().push("arp");
        let destinations = self
            .resolved
            .lock()
            .unwrap()
            .iter()
            .filter(|(ip, _)| p.next_hops.contains_key(ip))
            .map(|(ip, mac)| (*ip, *mac))
            .collect::<BTreeMap<_, _>>();
        Ok(NeighbourReport {
            unresolved_on_link: p
                .next_hops
                .keys()
                .filter(|ip| !destinations.contains_key(ip))
                .copied()
                .collect(),
            destinations,
            requests_sent: 0,
            elapsed: Duration::ZERO,
        })
    }
    fn open(
        &self,
        _: &AdapterBinding,
        _: Instant,
        _: &dyn Fn() -> bool,
    ) -> Result<AdapterPair, String> {
        self.calls.lock().unwrap().push("tcp-open");
        Ok(rmasscan_engine::fake::FakeAdapter::new().pair())
    }
}
#[test]
fn preparation_keeps_full_routes_and_truthful_partial_coverage_without_tcp() {
    let (job, env) = Fake::new();
    let p = prepare(&env, job.clone(), [1; 16], [2; 16], None, &|| false).unwrap();
    assert_eq!(p.report.routes.next_hops.len(), 3);
    assert_eq!(p.report.destinations.len(), 2);
    assert_eq!(p.report.unresolved, vec![ip(2)]);
    assert_eq!(job.prepare_network(&p.report).unwrap().range(), 2);
    assert_eq!(
        *env.calls.lock().unwrap(),
        vec!["authorize", "observe", "arp", "observe"]
    );
}
#[test]
fn invalid_job_and_masked_source_fail_before_arp() {
    let (mut job, env) = Fake::new();
    job.rate = 1001;
    assert!(prepare(&env, job, [1; 16], [2; 16], None, &|| false).is_err());
    assert_eq!(*env.calls.lock().unwrap(), vec!["authorize"]);
    let (job, env) = Fake::new();
    env.routes.lock().unwrap().source_mac = None;
    assert!(prepare(&env, job, [1; 16], [2; 16], None, &|| false).is_err());
    assert!(!env.calls.lock().unwrap().contains(&"arp"));
}
#[test]
fn all_unresolved_still_returns_persistable_report() {
    let (mut job, env) = Fake::new();
    job.targets = "10.0.0.1-10.0.0.2".into();
    env.routes.lock().unwrap().next_hops.remove(&ip(3));
    env.resolved.lock().unwrap().clear();
    let p = prepare(&env, job.clone(), [1; 16], [2; 16], None, &|| false).unwrap();
    assert!(p.report.destinations.is_empty());
    assert!(p.report.encode().is_ok());
    assert!(job.prepare_network(&p.report).is_err());
}

fn checkpoint(job: &Job, report: &NetworkReport) -> Vec<u8> {
    studio_protocol::NetworkCheckpoint {
        report: report.clone(),
        engine: Checkpoint {
            format_version: rmasscan_engine::CHECKPOINT_FORMAT_VERSION,
            engine_version: rmasscan_engine::ENGINE_ALGORITHM_VERSION,
            scan_id: [1; 16],
            attempt_id: [2; 16],
            job_digest: rmasscan_engine::job_digest(&job.prepare_network(report).unwrap()),
            next_index: 1,
        }
        .to_bytes(),
    }
    .encode()
    .unwrap()
}
#[test]
fn resume_validates_frozen_provenance_and_fresh_attempt_before_observation_or_arp() {
    let (job, env) = Fake::new();
    let prepared = prepare(&env, job.clone(), [1; 16], [2; 16], None, &|| false).unwrap();
    let bytes = checkpoint(&job, &prepared.report);
    for kind in 0..5 {
        env.calls.lock().unwrap().clear();
        let mut j = job.clone();
        let mut b = bytes.clone();
        let mut scan = [1; 16];
        let mut attempt = [3; 16];
        match kind {
            0 => j.rate = 99,
            1 => scan = [9; 16],
            2 => attempt = [2; 16],
            3 => b[30] ^= 1,
            _ => {
                let mut cp = studio_protocol::NetworkCheckpoint::decode(&b).unwrap();
                let mut engine = Checkpoint::from_bytes(&cp.engine).unwrap();
                engine.next_index = 999;
                cp.engine = engine.to_bytes();
                b = cp.encode().unwrap();
            }
        }
        assert!(prepare(&env, j, scan, attempt, Some(b), &|| false).is_err());
        assert_eq!(*env.calls.lock().unwrap(), vec!["authorize"]);
    }
}
#[test]
fn resume_re_resolves_only_eligible_but_compares_the_complete_original_snapshot() {
    let (job, env) = Fake::new();
    let prepared = prepare(&env, job.clone(), [1; 16], [2; 16], None, &|| false).unwrap();
    let bytes = checkpoint(&job, &prepared.report);
    env.resolved
        .lock()
        .unwrap()
        .insert(ip(2), [2, 0, 0, 0, 0, 2]);
    let resumed = prepare(
        &env,
        job.clone(),
        [1; 16],
        [3; 16],
        Some(bytes.clone()),
        &|| false,
    )
    .unwrap();
    assert_eq!(resumed.report, prepared.report);
    env.calls.lock().unwrap().clear();
    env.routes.lock().unwrap().next_hops.insert(ip(2), ip(254));
    assert!(
        prepare(
            &env,
            job.clone(),
            [1; 16],
            [3; 16],
            Some(bytes.clone()),
            &|| false
        )
        .err()
        .expect("expected refusal")
        .contains("snapshot")
    );
    assert!(!env.calls.lock().unwrap().contains(&"arp"));
    env.routes.lock().unwrap().next_hops.insert(ip(2), ip(2));
    env.resolved
        .lock()
        .unwrap()
        .insert(ip(1), [2, 8, 8, 8, 8, 8]);
    assert!(
        prepare(&env, job, [1; 16], [3; 16], Some(bytes), &|| false)
            .err()
            .expect("expected refusal")
            .contains("MAC map")
    );
}
#[test]
fn physical_guard_compares_source_interface_and_interior_unresolved_route() {
    for change in 0..5 {
        let (job, env) = Fake::new();
        let expected = env.routes.lock().unwrap().clone();
        let env = Arc::new(env);
        let mut guard = inspector(env.clone(), job, expected);
        assert!(matches!(
            guard(&|| false),
            Ok(crate::guard::Observation::Valid)
        ));
        {
            let mut route = env.routes.lock().unwrap();
            match change {
                0 => route.source_mac = Some([2, 8, 8, 8, 8, 8]),
                1 => route.source_ipv4 = ip(98),
                2 => route.interface_name = "en1".into(),
                3 => route.interface_index = 2,
                _ => {
                    route.next_hops.insert(ip(2), ip(254));
                }
            }
        }
        assert!(guard(&|| false).is_err());
    }
}
#[test]
fn worker_drop_cancels_and_joins_and_panic_is_reported() {
    let entered = Arc::new(AtomicBool::new(false));
    let closed = Arc::new(AtomicBool::new(false));
    let start = entered.clone();
    let end = closed.clone();
    let worker = Worker::spawn(move |cancel| {
        start.store(true, Ordering::Release);
        while !cancel() {
            std::thread::sleep(Duration::from_millis(1));
        }
        end.store(true, Ordering::Release);
        Ok(())
    })
    .unwrap();
    while !entered.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    drop(worker);
    assert!(closed.load(Ordering::Acquire));
    let mut worker = Worker::<()>::spawn(|_| panic!("test worker panic")).unwrap();
    let error = loop {
        if let Some(result) = worker.poll() {
            break result.unwrap_err();
        }
        std::thread::yield_now();
    };
    assert!(error.contains("panicked"));
}

#[test]
fn full_effective_probe_admission_precedes_arp_even_when_most_hosts_would_be_unresolved() {
    let (mut job, env) = Fake::new();
    job.targets = "10.0.0.1-10.0.0.17".into();
    job.ports = "1-65535".into();
    env.routes.lock().unwrap().next_hops = (1..=17).map(|n| (ip(n), ip(n))).collect();
    assert!(prepare(&env, job, [1; 16], [2; 16], None, &|| false).is_err());
    assert_eq!(*env.calls.lock().unwrap(), vec!["authorize", "observe"]);
}
#[test]
fn mismatched_route_partition_is_rejected_before_arp_and_native_authorization_remains_required() {
    let (job, env) = Fake::new();
    env.routes.lock().unwrap().next_hops.insert(ip(4), ip(4));
    assert!(prepare(&env, job, [1; 16], [2; 16], None, &|| false).is_err());
    assert!(!env.calls.lock().unwrap().contains(&"arp"));
    if !studio_protocol::raw_profile_enabled(studio_protocol::Backend::MacNetwork) {
        assert!(
            Native::default()
                .authorize()
                .unwrap_err()
                .contains("disabled")
        );
    }
    #[cfg(unix)]
    if cfg!(target_os = "macos") && studio_platform::unix::Identity::current().unwrap().uid != 0 {
        assert!(
            Native::default()
                .authorize()
                .unwrap_err()
                .contains("root helper")
        );
    }
}

#[test]
fn read_only_check_refuses_a_successful_but_suspended_completion_without_retry() {
    let mut check = Check::spawn(|cancel| {
        while !cancel() {
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(studio_protocol::Event::NetworkPreflight {
            job_digest: [7; 32],
            ready: true,
            detail: "stale success".into(),
        })
    })
    .unwrap();
    let tick = Instant::now();
    let wall = SystemTime::now() + Duration::from_secs(6);
    let deadline = Instant::now() + Duration::from_secs(2);
    let result = loop {
        if let Some(result) = check.poll_at(tick, wall) {
            break result.unwrap();
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    };
    assert!(
        matches!(result,studio_protocol::Event::NetworkPreflight{job_digest,ready:false,detail} if job_digest == [7;32] && detail.contains("interrupted"))
    );
}

#[test]
fn read_only_probe_count_normalizes_nonadjacent_duplicate_ports() {
    let (mut job, env) = Fake::new();
    job.ports = "80,90,80".into();
    let detail = preflight(&env, &job, &|| false).unwrap();
    assert!(detail.contains("3 effective hosts / 6 probes"), "{detail}");
}
