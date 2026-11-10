//! Ordinary native network access, separate from the sealed acceptance environments.
use super::*;
use std::sync::Mutex;
use studio_protocol::Backend;

trait Host: Send + Sync {
    fn authorize(&self) -> Result<(), String>;
    fn observe(
        &self,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String>;
    fn open(&self, binding: &AdapterBinding) -> Result<AdapterPair, String>;
}
struct Physical {
    host: Box<dyn Host>,
}
impl Environment for Physical {
    fn authorize(&self) -> Result<(), String> {
        self.host.authorize()
    }
    fn observe(
        &self,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String> {
        bounded(deadline, cancelled)?;
        if !job.backend.is_physical() {
            return Err("Not an ordinary network job".into());
        }
        job.validate()?;
        let plan = self.host.observe(job, deadline, cancelled)?;
        bounded(deadline, cancelled)?;
        job.admit_network(&plan)?;
        Ok(plan)
    }
    fn neighbours(
        &self,
        plan: &PhysicalRoutePlan,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<NeighbourReport, String> {
        self.authorize()?;
        plan.validate_executable().map_err(|e| e.to_string())?;
        let deadline = Instant::now() + rmasscan_net::neighbours::NEIGHBOUR_BUDGET;
        let binding = AdapterBinding {
            interface_id: plan.interface_name.clone(),
            link_type: rmasscan_core::packet::LinkType::Ethernet,
            source_ipv4: plan.source_ipv4.into(),
            source_mac: plan.source_mac.ok_or("Missing source MAC")?,
            next_hop_mac: [255; 6],
            source_ports: (40000, 40000),
        };
        let mut pair = self.open(&binding, deadline, cancelled)?;
        let report = rmasscan_net::resolve_neighbours(
            &mut pair,
            plan,
            &rmasscan_core::throttle::SystemClock::new(),
            cancelled,
        )
        .map_err(|e| e.to_string());
        drop(pair);
        bounded(deadline, cancelled)?;
        report
    }
    fn open(
        &self,
        binding: &AdapterBinding,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<AdapterPair, String> {
        bounded(deadline, cancelled)?;
        self.authorize()?;
        let pair = self.host.open(binding)?;
        // Native open is not preemptible. Discard a late/cancelled pair before any send.
        bounded(deadline, cancelled)?;
        self.authorize()?;
        Ok(pair)
    }
}
fn bounded(deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<(), String> {
    rmasscan_net::network_plan::check_observation(deadline, cancelled).map_err(|e| e.to_string())
}
struct System;
impl Host for System {
    fn authorize(&self) -> Result<(), String> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if Backend::native_physical().is_some_and(studio_protocol::raw_profile_enabled)
            && studio_platform::unix::Identity::current()?.uid == 0
        {
            return Ok(());
        }
        #[cfg(windows)]
        if studio_protocol::raw_profile_enabled(Backend::WindowsPhysical)
            && studio_platform::windows::Process::open(std::process::id())?
                .elevation()?
                .elevated
        {
            return Ok(());
        }
        Err("Network scanning requires the authorized native runner".into())
    }
    fn observe(
        &self,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String> {
        if Some(job.backend) != Backend::native_physical() {
            return Err("This network profile is unavailable on the current OS".into());
        }
        rmasscan_net::plan_physical(
            &job.network_targets()?,
            rmasscan_net::os_route_table()
                .map_err(|e| e.to_string())?
                .as_ref(),
            rmasscan_net::os_interfaces()
                .map_err(|e| e.to_string())?
                .as_ref(),
            deadline,
            cancelled,
        )
        .map_err(|e| e.to_string())
    }
    fn open(&self, binding: &AdapterBinding) -> Result<AdapterPair, String> {
        rmasscan_net::open_explicit(binding)
            .map(|a| a.io)
            .map_err(|e| e.to_string())
    }
}

/// Dispatch is explicit and attempt-bound. A failed fixture never selects Physical.
struct Dispatch {
    fixture: Arc<dyn Environment>,
    physical: Arc<dyn Environment>,
    active: Mutex<Option<Backend>>,
}
impl Dispatch {
    fn for_backend(&self, backend: Backend) -> Result<&dyn Environment, String> {
        match backend {
            Backend::MacPhysical | Backend::LinuxPhysical | Backend::WindowsPhysical => {
                Ok(self.physical.as_ref())
            }
            Backend::MacNetwork => Ok(self.fixture.as_ref()),
            _ => Err("Not a network profile".into()),
        }
    }
    fn active(&self) -> Result<&dyn Environment, String> {
        let backend = self
            .active
            .lock()
            .map_err(|_| "Network mode poisoned")?
            .ok_or("No active network attempt")?;
        self.for_backend(backend)
    }
}
impl Environment for Dispatch {
    fn authorize(&self) -> Result<(), String> {
        self.physical.authorize()
    }
    fn begin_attempt(&self, job: &Job, attempt: Id, resuming: bool) -> Result<(), String> {
        let mut active = self.active.lock().map_err(|_| "Network mode poisoned")?;
        *active = None;
        if attempt == [0; 16] {
            return Err("Invalid network attempt".into());
        }
        self.for_backend(job.backend)?
            .begin_attempt(job, attempt, resuming)?;
        *active = Some(job.backend);
        Ok(())
    }
    fn observe(
        &self,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String> {
        self.for_backend(job.backend)?
            .observe(job, deadline, cancelled)
    }
    fn observe_preflight(
        &self,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String> {
        self.for_backend(job.backend)?
            .observe_preflight(job, deadline, cancelled)
    }
    fn neighbours(
        &self,
        plan: &PhysicalRoutePlan,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<NeighbourReport, String> {
        self.active()?.neighbours(plan, cancelled)
    }
    fn open(
        &self,
        binding: &AdapterBinding,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<AdapterPair, String> {
        self.active()?.open(binding, deadline, cancelled)
    }
}
pub fn environment(owner_uid: Option<u32>) -> Arc<dyn Environment> {
    #[cfg(target_os = "macos")]
    let fixture: Arc<dyn Environment> = match owner_uid {
        Some(uid) => Arc::new(super::Candidate::new(uid)),
        None => Arc::new(super::Native::default()),
    };
    #[cfg(not(target_os = "macos"))]
    let fixture: Arc<dyn Environment> = {
        let _ = owner_uid;
        Arc::new(super::Native::default())
    };
    Arc::new(Dispatch {
        fixture,
        physical: Arc::new(Physical {
            host: Box::new(System),
        }),
        active: Mutex::new(None),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    struct Fake {
        allowed: AtomicBool,
        cancel_on_open: AtomicBool,
        cancelled: AtomicBool,
        opens: AtomicUsize,
        io: rmasscan_engine::fake::FakeAdapter,
    }
    impl Host for Arc<Fake> {
        fn authorize(&self) -> Result<(), String> {
            if self.allowed.load(Ordering::Relaxed) {
                Ok(())
            } else {
                Err("not authorized".into())
            }
        }
        fn observe(
            &self,
            _: &Job,
            _: Instant,
            _: &dyn Fn() -> bool,
        ) -> Result<PhysicalRoutePlan, String> {
            Ok(PhysicalRoutePlan {
                interface_name: "en0".into(),
                interface_index: 4,
                source_ipv4: "192.0.2.10".parse().unwrap(),
                source_mac: Some([2, 1, 2, 3, 4, 5]),
                next_hops: [("192.0.2.1".parse().unwrap(), "192.0.2.1".parse().unwrap())].into(),
                excluded: Default::default(),
            })
        }
        fn open(&self, _: &AdapterBinding) -> Result<AdapterPair, String> {
            self.opens.fetch_add(1, Ordering::Relaxed);
            if self.cancel_on_open.load(Ordering::Relaxed) {
                self.cancelled.store(true, Ordering::Relaxed);
            }
            Ok(self.io.pair())
        }
    }
    fn setup() -> (Arc<Fake>, Physical, Job) {
        let fake = Arc::new(Fake {
            allowed: AtomicBool::new(false),
            cancel_on_open: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            opens: AtomicUsize::new(0),
            io: rmasscan_engine::fake::FakeAdapter::new(),
        });
        let env = Physical {
            host: Box::new(fake.clone()),
        };
        let mut job = Job::example(Backend::MacPhysical);
        job.targets = "192.0.2.1".into();
        job.ports = "22".into();
        (fake, env, job)
    }
    #[test]
    fn read_only_preflight_needs_no_authorization_or_packet_handles() {
        let (fake, env, job) = setup();
        let detail = preflight(&env, &job, &|| false).unwrap();
        assert!(detail.contains("1 effective hosts / 1 probes"));
        assert_eq!(fake.opens.load(Ordering::Relaxed), 0);
        assert!(env.authorize().is_err());
    }
    #[test]
    fn packet_open_requires_authority_and_discards_cancelled_success() {
        let (fake, env, job) = setup();
        let deadline = Instant::now() + Duration::from_secs(1);
        let plan = fake.observe(&job, deadline, &|| false).unwrap();
        let binding = AdapterBinding {
            interface_id: "en0".into(),
            link_type: rmasscan_core::packet::LinkType::Ethernet,
            source_ipv4: plan.source_ipv4.into(),
            source_mac: plan.source_mac.unwrap(),
            next_hop_mac: [2, 9, 9, 9, 9, 9],
            source_ports: (40000, 40000),
        };
        assert!(env.open(&binding, deadline, &|| false).is_err());
        assert_eq!(fake.opens.load(Ordering::Relaxed), 0);
        fake.allowed.store(true, Ordering::Relaxed);
        let pair = env
            .open(&binding, deadline, &|| false)
            .expect("authorized packet adapter");
        drop(pair);
        fake.cancel_on_open.store(true, Ordering::Relaxed);
        assert!(
            env.open(&binding, deadline, &|| fake
                .cancelled
                .load(Ordering::Relaxed))
                .is_err()
        );
        assert_eq!(fake.io.alive_handles(), 0);
        assert_eq!(fake.opens.load(Ordering::Relaxed), 2);
    }
    #[test]
    fn neighbours_use_frozen_source_and_close_the_arp_adapter() {
        let (fake, env, job) = setup();
        fake.allowed.store(true, Ordering::Relaxed);
        fake.io.set_responder(|frame| {
            let p = rmasscan_core::arp::decode(frame).unwrap();
            assert_eq!(p.sender_ip, u32::from_be_bytes([192, 0, 2, 10]));
            assert_eq!(p.sender_mac, [2, 1, 2, 3, 4, 5]);
            vec![
                rmasscan_core::arp::encode_reply(
                    [2, 9, 9, 9, 9, 9],
                    p.target_ip,
                    p.sender_mac,
                    p.sender_ip,
                )
                .to_vec(),
            ]
        });
        let plan = fake
            .observe(&job, Instant::now() + Duration::from_secs(1), &|| false)
            .unwrap();
        let report = env.neighbours(&plan, &|| false).unwrap();
        assert_eq!(
            report.destinations,
            [("192.0.2.1".parse().unwrap(), [2, 9, 9, 9, 9, 9])].into()
        );
        assert!(report.unresolved_on_link.is_empty());
        assert_eq!(fake.io.alive_handles(), 0);
        assert_eq!(fake.opens.load(Ordering::Relaxed), 1);
    }

    struct Refused;
    impl Environment for Refused {
        fn authorize(&self) -> Result<(), String> {
            Err("fixture refused".into())
        }
        fn begin_attempt(&self, _: &Job, _: Id, _: bool) -> Result<(), String> {
            self.authorize()
        }
        fn observe(
            &self,
            _: &Job,
            _: Instant,
            _: &dyn Fn() -> bool,
        ) -> Result<PhysicalRoutePlan, String> {
            Err("fixture refused".into())
        }
        fn neighbours(
            &self,
            _: &PhysicalRoutePlan,
            _: &dyn Fn() -> bool,
        ) -> Result<NeighbourReport, String> {
            Err("fixture refused".into())
        }
        fn open(
            &self,
            _: &AdapterBinding,
            _: Instant,
            _: &dyn Fn() -> bool,
        ) -> Result<AdapterPair, String> {
            Err("fixture refused".into())
        }
    }
    #[test]
    fn fixture_refusal_never_falls_back_to_physical_or_leaves_a_previous_attempt_selected() {
        let (fake, physical, mut job) = setup();
        let dispatch = Dispatch {
            fixture: Arc::new(Refused),
            physical: Arc::new(physical),
            active: Mutex::new(None),
        };
        dispatch.begin_attempt(&job, [1; 16], false).unwrap();
        assert!(dispatch.active().is_ok());
        job.backend = Backend::MacNetwork;
        assert!(
            preflight(&dispatch, &job, &|| false)
                .unwrap_err()
                .contains("fixture refused")
        );
        assert!(dispatch.begin_attempt(&job, [2; 16], false).is_err());
        assert!(dispatch.active().is_err());
        assert_eq!(fake.opens.load(Ordering::Relaxed), 0);
        job.backend = Backend::MacPhysical;
        dispatch.begin_attempt(&job, [3; 16], true).unwrap();
        assert!(preflight(&dispatch, &job, &|| false).is_ok());
    }
}
