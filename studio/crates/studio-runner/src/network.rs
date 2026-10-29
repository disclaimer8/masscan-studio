//! Attempt-owned physical preparation. Workers never start the engine.
use rmasscan_core::probe::{AdapterBinding, ReadyPlan};
use rmasscan_engine::{AdapterPair, Checkpoint};
use rmasscan_net::{NeighbourReport, PhysicalRoutePlan};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime},
};
use studio_protocol::{Id, Job, NetworkReport};

pub trait Environment: Send + Sync {
    fn authorize(&self) -> Result<(), String>;
    fn observe(
        &self,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String>;
    fn neighbours(
        &self,
        plan: &PhysicalRoutePlan,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<NeighbourReport, String>;
    fn open(
        &self,
        binding: &AdapterBinding,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<AdapterPair, String>;
}
pub struct Prepared {
    pub job: Job,
    pub report: NetworkReport,
    pub checkpoint: Option<Checkpoint>,
}
pub struct Launch {
    pub plan: ReadyPlan,
    pub pair: AdapterPair,
    pub checkpoint: Option<Checkpoint>,
    pub inspector: crate::guard::Inspector,
    pub observed: Instant,
}
pub fn prepare(
    env: &dyn Environment,
    job: Job,
    scan: Id,
    attempt: Id,
    checkpoint: Option<Vec<u8>>,
    cancelled: &dyn Fn() -> bool,
) -> Result<Prepared, String> {
    env.authorize()?;
    job.validate()?;
    job.network_targets()?;
    check(cancelled)?;
    // Decode and validate the entire frozen job/engine provenance BEFORE OS or packet access.
    let resume = checkpoint
        .map(|bytes| {
            let frozen = studio_protocol::NetworkCheckpoint::decode(&bytes)?;
            let cp = Checkpoint::from_bytes(&frozen.engine).map_err(|e| e.to_string())?;
            studio_protocol::validate_checkpoint(
                &job,
                scan,
                cp.attempt_id,
                &bytes,
                &cp.next_index.to_string(),
            )?;
            if cp.attempt_id == attempt {
                return Err("Resume needs a fresh attempt".into());
            }
            Ok::<_, String>((frozen.report, cp))
        })
        .transpose()?;
    let routes = snapshot(env, &job, Duration::from_secs(10), cancelled)?;
    job.admit_network(&routes)?;
    routes.validate_executable().map_err(|e| e.to_string())?;
    if resume.as_ref().is_some_and(|(r, _)| r.routes != routes) {
        return Err("Network snapshot changed; start a new scan".into());
    }
    // Re-resolve eligible neighbours only. Still compare the COMPLETE snapshot above/below.
    let mut eligible = routes.clone();
    if let Some((report, _)) = &resume {
        eligible
            .next_hops
            .retain(|ip, _| report.destinations.contains_key(ip));
    }
    check(cancelled)?;
    let neighbours = env.neighbours(&eligible, cancelled)?;
    check(cancelled)?;
    if snapshot(env, &job, Duration::from_secs(10), cancelled)? != routes {
        return Err("Network changed during neighbour preparation".into());
    }
    let (report, checkpoint) = match resume {
        Some((frozen, cp)) => {
            if neighbours.destinations != frozen.destinations
                || !neighbours.unresolved_on_link.is_empty()
            {
                return Err("Resolved destination MAC map changed; start a new scan".into());
            }
            (frozen, Some(cp))
        }
        None => (
            NetworkReport {
                job_digest: job.original_digest()?,
                routes,
                destinations: neighbours.destinations,
                unresolved: neighbours.unresolved_on_link,
            },
            None,
        ),
    };
    report.validate_for(&job)?;
    report.encode()?;
    check(cancelled)?;
    Ok(Prepared {
        job,
        report,
        checkpoint,
    })
}
fn check(cancelled: &dyn Fn() -> bool) -> Result<(), String> {
    if cancelled() {
        Err("Network operation cancelled".into())
    } else {
        Ok(())
    }
}
fn snapshot(
    env: &dyn Environment,
    job: &Job,
    budget: Duration,
    cancelled: &dyn Fn() -> bool,
) -> Result<PhysicalRoutePlan, String> {
    let deadline = Instant::now() + budget;
    check(cancelled)?;
    let routes = env.observe(job, deadline, cancelled)?;
    check(cancelled)?;
    if Instant::now() >= deadline {
        return Err("Network observation timed out".into());
    }
    Ok(routes)
}
/// Called only after the matching durable-report ACK. No worker starts Engine.
pub fn launch(
    env: Arc<dyn Environment>,
    prepared: Prepared,
    cancelled: &dyn Fn() -> bool,
) -> Result<Launch, String> {
    env.authorize()?;
    let plan = prepared.job.prepare_network(&prepared.report)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    check(cancelled)?;
    let routes = env.observe(&prepared.job, deadline, cancelled)?;
    check(cancelled)?;
    if Instant::now() >= deadline {
        return Err("Network observation timed out".into());
    }
    if routes != prepared.report.routes {
        return Err("Network changed before first TCP probe".into());
    }
    routes.validate_executable().map_err(|e| e.to_string())?;
    let observed = Instant::now();
    check(cancelled)?;
    let pair = env.open(plan.binding(), deadline, cancelled)?;
    if Instant::now() >= deadline {
        return Err("Network adapter open timed out".into());
    }
    check(cancelled)?;
    let inspector = inspector(env, prepared.job, prepared.report.routes);
    Ok(Launch {
        plan,
        pair,
        checkpoint: prepared.checkpoint,
        inspector,
        observed,
    })
}
pub fn inspector(
    env: Arc<dyn Environment>,
    job: Job,
    expected: PhysicalRoutePlan,
) -> crate::guard::Inspector {
    Box::new(move |cancelled| {
        let observation = snapshot(env.as_ref(), &job, Duration::from_secs(3), cancelled);
        if cancelled() {
            return Ok(crate::guard::Observation::Cancelled);
        }
        if observation? != expected {
            return Err("Interface, source or route snapshot changed".into());
        }
        Ok(crate::guard::Observation::Valid)
    })
}
pub fn preflight(
    env: &dyn Environment,
    job: &Job,
    cancelled: &dyn Fn() -> bool,
) -> Result<String, String> {
    job.validate()?;
    job.network_targets()?;
    let routes = snapshot(env, job, Duration::from_secs(10), cancelled)?;
    job.admit_network(&routes)?;
    let direct = routes
        .next_hops
        .iter()
        .filter(|(dst, hop)| dst == hop)
        .count();
    let mut ports = rmasscan_core::ranges::RangeList::new();
    rmasscan_core::targets::parse_ports(&mut ports, &job.ports).map_err(|e| e.to_string())?;
    ports.sort_and_merge();
    Ok(format!(
        "Interface {} ({}), source {}; {} effective hosts / {} probes; {} direct, {} routed; exclusions: {:?}. Read-only route check; neighbours and BPF not checked. Physical execution gate: {}.",
        routes.interface_name,
        routes.interface_index,
        routes.source_ipv4,
        routes.next_hops.len(),
        routes.next_hops.len() as u64 * ports.count(),
        direct,
        routes.next_hops.len() - direct,
        routes.excluded,
        if studio_protocol::raw_profile_enabled(job.backend) {
            "enabled"
        } else {
            "closed"
        }
    ))
}

/// Owned cancellation/join: dropping an attempt cannot detach a packet-capable worker.
pub struct Worker<T> {
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<T, String>>>,
}
impl<T: Send + 'static> Worker<T> {
    pub fn spawn(
        work: impl FnOnce(&dyn Fn() -> bool) -> Result<T, String> + Send + 'static,
    ) -> Result<Self, String> {
        let cancel = Arc::new(AtomicBool::new(false));
        let token = cancel.clone();
        let thread = std::thread::Builder::new()
            .name("studio-network-prepare".into())
            .spawn(move || work(&|| token.load(Ordering::Acquire)))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            cancel,
            thread: Some(thread),
        })
    }
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }
    pub fn poll(&mut self) -> Option<Result<T, String>> {
        if !self.thread.as_ref()?.is_finished() {
            return None;
        }
        Some(
            self.thread
                .take()
                .unwrap()
                .join()
                .unwrap_or_else(|_| Err("Network worker panicked".into())),
        )
    }
}
impl<T> Drop for Worker<T> {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Session-only check: report stale completion as a failed check, never retry it.
pub struct Check {
    worker: Worker<studio_protocol::Event>,
    clock: crate::guard::Clock,
    interruption: Option<String>,
}
impl Check {
    pub fn spawn(
        work: impl FnOnce(&dyn Fn() -> bool) -> Result<studio_protocol::Event, String> + Send + 'static,
    ) -> Result<Self, String> {
        Ok(Self {
            worker: Worker::spawn(work)?,
            clock: crate::guard::Clock::new(),
            interruption: None,
        })
    }
    pub fn cancel(&self) {
        self.worker.cancel();
    }
    pub fn poll(&mut self) -> Option<Result<studio_protocol::Event, String>> {
        self.poll_at(Instant::now(), SystemTime::now())
    }
    fn poll_at(
        &mut self,
        tick: Instant,
        wall: SystemTime,
    ) -> Option<Result<studio_protocol::Event, String>> {
        if let Some(error) = self.clock.check(tick, wall) {
            self.interruption.get_or_insert(error);
            self.worker.cancel();
        }
        self.worker.poll().map(|result| {
            result.map(|mut event| {
                if let Some(error) = &self.interruption {
                    match &mut event {
                        studio_protocol::Event::NetworkPreflight { ready, detail, .. }
                        | studio_protocol::Event::NetworkChecked { ready, detail } => {
                            *ready = false;
                            *detail = format!(
                                "Read-only network check interrupted: {error}. Check again."
                            );
                        }
                        _ => {}
                    }
                }
                event
            })
        })
    }
}

mod native;
pub use native::Native;

#[cfg(test)]
mod tests;
