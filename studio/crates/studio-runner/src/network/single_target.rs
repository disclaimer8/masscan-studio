//! Distinct one-use public-target environment; never a fallback from a failed seal.
use super::*;
use std::sync::{Mutex, TryLockError};
use studio_platform::single_target::{CapturePin, CaptureWitness, Claim, Lease};
use studio_protocol::single_target::{Context, Intent, Permit};
mod system;
type Admission = Box<dyn FnMut(Instant) -> Result<Instant, String> + Send>;
struct Authority {
    now: u64,
    uid: u32,
    tool: String,
    helper: String,
}
impl Authority {
    fn context(&self) -> Context<'_> {
        Context {
            now: self.now,
            owner_uid: self.uid,
            tooling_sha256: &self.tool,
            helper_sha256: &self.helper,
        }
    }
}
trait Host: Send + Sync {
    fn transmission(
        &self,
        permit: &Permit,
        context: &Context<'_>,
        claim: &Claim,
        attempt: Id,
        witness: &CaptureWitness,
        deadline: Instant,
    ) -> Result<Admission, String>;
    fn authority(&self) -> Result<Authority, String>;
    fn permit(&self, context: &Context<'_>) -> Result<Permit, String>;
    fn capture(&self, permit: &Permit, context: &Context<'_>) -> Result<CaptureWitness, String>;
    fn claim(&self, permit: &Permit, context: &Context<'_>, attempt: Id) -> Result<Claim, String>;
    fn verify_claim(
        &self,
        permit: &Permit,
        context: &Context<'_>,
        claim: &Claim,
        attempt: Id,
    ) -> Result<(), String>;
    fn plan(
        &self,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String>;
    fn open(&self, binding: &AdapterBinding) -> Result<AdapterPair, String>;
    fn resolve(
        &self,
        pair: &mut AdapterPair,
        plan: &PhysicalRoutePlan,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<NeighbourReport, String>;
}
#[derive(Default)]
struct State {
    lease: Lease,
    capture: CapturePin,
    attempt: Option<Id>,
    claim: Option<Claim>,
    resolved: Option<[u8; 6]>,
}
struct SingleTarget {
    host: Box<dyn Host>,
    state: Mutex<State>,
    rejected: Arc<AtomicBool>,
}
enum ObservationError {
    Interrupted(String),
    Rejected(String),
}
impl From<String> for ObservationError {
    fn from(error: String) -> Self {
        Self::Rejected(error)
    }
}
impl ObservationError {
    fn message(self) -> String {
        match self {
            Self::Interrupted(message) | Self::Rejected(message) => message,
        }
    }
}
impl SingleTarget {
    fn with<T>(&self, f: impl FnOnce(&mut State) -> Result<T, String>) -> Result<T, String> {
        self.operation(
            Instant::now() + Duration::from_secs(10),
            &|| false,
            false,
            |state| f(state).map_err(ObservationError::Rejected),
        )
    }
    fn operation<T>(
        &self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        preflight: bool,
        f: impl FnOnce(&mut State) -> Result<T, ObservationError>,
    ) -> Result<T, String> {
        let result = (|| {
            if self.rejected.load(Ordering::Acquire) {
                return Err(ObservationError::Rejected(
                    "Single-target session invalidated".into(),
                ));
            }
            // Retired preflight workers can still hold state when Start arrives.
            // Wait within the original budget, without renewing it on contention.
            let mut state = loop {
                if preflight {
                    bounded(deadline, cancelled).map_err(ObservationError::Interrupted)?;
                }
                match self.state.try_lock() {
                    Ok(state) => break state,
                    Err(TryLockError::WouldBlock) => {
                        bounded(deadline, cancelled).map_err(ObservationError::Interrupted)?;
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(TryLockError::Poisoned(_)) => {
                        return Err(ObservationError::Rejected(
                            "Single-target state poisoned".into(),
                        ));
                    }
                }
            };
            let result = bounded(deadline, cancelled)
                .map_err(ObservationError::Interrupted)
                .and_then(|()| f(&mut state));
            let fatal = matches!(&result, Err(ObservationError::Rejected(_)))
                || (!preflight && result.is_err());
            if fatal {
                state.lease.invalidate();
                state.capture.invalidate();
                self.rejected.store(true, Ordering::Release);
            }
            if self.rejected.load(Ordering::Acquire) {
                return result.and(Err(ObservationError::Rejected(
                    "Single-target session invalidated".into(),
                )));
            }
            result
        })();
        if matches!(&result, Err(ObservationError::Rejected(_))) {
            self.rejected.store(true, Ordering::Release);
        }
        result.map_err(ObservationError::message)
    }
    fn admit(
        &self,
        state: &mut State,
        job: &Job,
        claim: bool,
    ) -> Result<(Permit, Authority), String> {
        if self.rejected.load(Ordering::Acquire) {
            return Err("Single-target session invalidated".into());
        }
        Intent::from_job(job)?;
        let authority = self.host.authority()?;
        let context = authority.context();
        let permit = self.host.permit(&context)?;
        state.lease.check(&permit, &context)?;
        permit.admit_job(job, &context)?;
        if state.attempt.is_some() {
            let witness = self.host.capture(&permit, &context)?;
            state.capture.check(&witness, context.now)?;
        }
        if claim {
            let attempt = state.attempt.ok_or("No current single-target attempt")?;
            self.host.verify_claim(
                &permit,
                &context,
                state
                    .claim
                    .as_ref()
                    .ok_or("Single-target packet claim missing")?,
                attempt,
            )?;
        }
        Ok((permit, authority))
    }
    fn observe_locked(
        &self,
        state: &mut State,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String> {
        self.observation(state, job, deadline, cancelled)
            .map_err(ObservationError::message)
    }
    fn observation(
        &self,
        state: &mut State,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, ObservationError> {
        bounded(deadline, cancelled).map_err(ObservationError::Interrupted)?;
        let (_, _) = self.admit(state, job, state.claim.is_some())?;
        let plan = self.host.plan(job, deadline, cancelled);
        // Cancellation may interrupt the OS route read. Only this read-only
        // phase is benign for preflight; admission failures always remain fatal.
        bounded(deadline, cancelled).map_err(ObservationError::Interrupted)?;
        let plan = plan?;
        let (permit, authority) = self.admit(state, job, state.claim.is_some())?;
        permit.admit_plan(&plan, &authority.context())?;
        Ok(plan)
    }
    fn open_locked(
        &self,
        state: &mut State,
        binding: &AdapterBinding,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<AdapterPair, String> {
        self.observe_locked(state, job, deadline, cancelled)?;
        let (permit, authority) = self.admit(state, job, true)?;
        permit.admit_binding(binding, state.resolved, &authority.context())?;
        bounded(deadline, cancelled)?;
        let pair = self.host.open(binding)?;
        // BPF open is not preemptible: late or revoked opens close before use.
        bounded(deadline, cancelled)?;
        self.admit(state, job, true)?;
        Ok(pair)
    }
    fn resolve_checked(
        &self,
        state: &mut State,
        pair: &mut AdapterPair,
        plan: &PhysicalRoutePlan,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<NeighbourReport, String> {
        let state = std::cell::RefCell::new(state);
        let failure = std::cell::RefCell::new(None);
        // The native resolver checks this callback before and after every send,
        // retry and receive. It must not outlive the outer ten-second budget.
        let stop = || {
            if failure.borrow().is_some() {
                return true;
            }
            let checked = (|| {
                bounded(deadline, cancelled)?;
                self.admit(&mut state.borrow_mut(), job, true)?;
                bounded(deadline, cancelled)
            })();
            if let Err(error) = checked {
                *failure.borrow_mut() = Some(error);
                self.rejected.store(true, Ordering::Release);
                true
            } else {
                false
            }
        };
        let result = self.host.resolve(pair, plan, &stop);
        if let Some(error) = failure.into_inner() {
            return Err(error);
        }
        result
    }
}
fn bounded(deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<(), String> {
    check(cancelled)?;
    if Instant::now() >= deadline {
        return Err("Single-target observation deadline expired".into());
    }
    Ok(())
}
impl Environment for SingleTarget {
    fn authorize(&self) -> Result<(), String> {
        self.with(|_| self.host.authority().map(|_| ()))
    }
    fn begin_attempt(&self, job: &Job, attempt: Id, resuming: bool) -> Result<(), String> {
        self.with(|state| {
            if resuming || attempt == [0; 16] || state.attempt.is_some() {
                return Err("Single-target permit allows one fresh attempt without resume".into());
            }
            state.attempt = Some(attempt);
            self.admit(state, job, false)?;
            Ok(())
        })
    }
    fn observe(
        &self,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String> {
        self.operation(deadline, cancelled, false, |state| {
            self.observation(state, job, deadline, cancelled)
        })
    }
    fn observe_preflight(
        &self,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String> {
        self.operation(deadline, cancelled, true, |state| {
            self.observation(state, job, deadline, cancelled)
        })
    }
    fn neighbours(
        &self,
        plan: &PhysicalRoutePlan,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<NeighbourReport, String> {
        self.with(|state| {
            let deadline = Instant::now() + Duration::from_secs(10);
            bounded(deadline, cancelled)?;
            let authority = self.host.authority()?;
            let permit = self.host.permit(&authority.context())?;
            let job = permit.job();
            let (permit, authority) = self.admit(state, &job, false)?;
            permit.admit_plan(plan, &authority.context())?;
            if state.claim.is_some() {
                return Err("Single-target neighbour attempt already consumed".into());
            }
            let attempt = state.attempt.ok_or("Single-target attempt not bound")?;
            state.claim = Some(self.host.claim(&permit, &authority.context(), attempt)?);
            let binding = AdapterBinding {
                interface_id: plan.interface_name.clone(),
                link_type: rmasscan_core::packet::LinkType::Ethernet,
                source_ipv4: plan.source_ipv4.into(),
                source_mac: plan.source_mac.ok_or("Missing source MAC")?,
                next_hop_mac: [255; 6],
                source_ports: (40000, 40000),
            };
            let mut pair = self.open_locked(state, &binding, &job, deadline, cancelled)?;
            let neighbours =
                self.resolve_checked(state, &mut pair, plan, &job, deadline, cancelled)?;
            drop(pair);
            bounded(deadline, cancelled)?;
            let (permit, authority) = self.admit(state, &job, true)?;
            permit.admit_report(
                &NetworkReport {
                    job_digest: job.original_digest()?,
                    routes: plan.clone(),
                    destinations: neighbours.destinations.clone(),
                    unresolved: neighbours.unresolved_on_link.clone(),
                },
                &authority.context(),
            )?;
            state.resolved = Some(
                *neighbours
                    .destinations
                    .get(&permit.target)
                    .ok_or("Single-target next hop unresolved")?,
            );
            Ok(neighbours)
        })
    }
    fn open(
        &self,
        binding: &AdapterBinding,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<AdapterPair, String> {
        self.with(|state| {
            let authority = self.host.authority()?;
            let permit = self.host.permit(&authority.context())?;
            if state.resolved.is_none() {
                return Err("Single-target TCP open requires resolved next hop".into());
            }
            let pair = self.open_locked(state, binding, &permit.job(), deadline, cancelled)?;
            let (permit, authority) = self.admit(state, &permit.job(), true)?;
            let (witness, capture_deadline) = state.capture.pinned()?;
            let admit = self.host.transmission(
                &permit,
                &authority.context(),
                state.claim.as_ref().ok_or("Missing packet claim")?,
                state.attempt.ok_or("Missing packet attempt")?,
                witness,
                state.lease.deadline()?.min(capture_deadline),
            )?;
            bounded(deadline, cancelled)?;
            Ok(AdapterPair {
                tx: Box::new(GuardedTx {
                    inner: pair.tx,
                    admit,
                    rejected: self.rejected.clone(),
                }),
                rx: pair.rx,
            })
        })
    }
}
/// Observe selects by exact job shape. Packet methods use only the mode bound
/// by the current attempt; a fixture rejection never retries the public mode.
pub struct Candidate {
    fixture: Native,
    single: SingleTarget,
    mode: Mutex<Option<bool>>,
}
struct GuardedTx {
    inner: Box<dyn rmasscan_engine::Tx>,
    admit: Admission,
    rejected: Arc<AtomicBool>,
}
impl rmasscan_engine::Tx for GuardedTx {
    fn send(
        &mut self,
        frame: &[u8],
        timeout: Duration,
    ) -> Result<rmasscan_engine::SendStatus, rmasscan_engine::IoError> {
        let result = (|| {
            if self.rejected.load(Ordering::Acquire) {
                return Err("Single-target packet session invalidated".into());
            }
            let io_deadline = Instant::now()
                .checked_add(timeout)
                .ok_or("Invalid packet I/O timeout")?;
            let deadline = (self.admit)(io_deadline)?.min(io_deadline);
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || self.rejected.load(Ordering::Acquire) {
                return Err("Packet admission expired before dispatch".into());
            }
            self.inner.send(frame, remaining).map_err(|e| e.message)
        })();
        if result.is_err() {
            self.rejected.store(true, Ordering::Release);
        }
        result.map_err(rmasscan_engine::IoError::new)
    }
    // Keep max_batch=1: every frame and every WouldBlock retry is re-admitted.
}
impl Candidate {
    pub fn new(uid: u32) -> Self {
        Self {
            fixture: Native::default(),
            single: SingleTarget {
                host: Box::new(system::System { uid }),
                state: Mutex::new(State::default()),
                rejected: Arc::new(AtomicBool::new(false)),
            },
            mode: Mutex::new(None),
        }
    }
    fn select(job: &Job) -> Result<bool, String> {
        if Intent::from_job(job).is_ok() {
            return Ok(true);
        }
        studio_protocol::sealed_fixture::validate_job(job)?;
        Ok(false)
    }
    fn selected(&self) -> Result<bool, String> {
        self.mode
            .lock()
            .map_err(|_| "Candidate mode poisoned")?
            .ok_or_else(|| "No current network attempt".to_owned())
    }
}
impl Environment for Candidate {
    fn authorize(&self) -> Result<(), String> {
        self.fixture.authorize()
    }
    fn begin_attempt(&self, job: &Job, attempt: Id, resuming: bool) -> Result<(), String> {
        let single = Self::select(job)?;
        if single {
            self.single.begin_attempt(job, attempt, resuming)?;
        }
        *self.mode.lock().map_err(|_| "Candidate mode poisoned")? = Some(single);
        Ok(())
    }
    fn observe(
        &self,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String> {
        if Self::select(job)? {
            self.single.observe(job, deadline, cancelled)
        } else {
            self.fixture.observe(job, deadline, cancelled)
        }
    }
    fn observe_preflight(
        &self,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String> {
        if Self::select(job)? {
            self.single.observe_preflight(job, deadline, cancelled)
        } else {
            self.fixture.observe_preflight(job, deadline, cancelled)
        }
    }
    fn neighbours(
        &self,
        plan: &PhysicalRoutePlan,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<NeighbourReport, String> {
        if self.selected()? {
            self.single.neighbours(plan, cancelled)
        } else {
            self.fixture.neighbours(plan, cancelled)
        }
    }
    fn open(
        &self,
        binding: &AdapterBinding,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<AdapterPair, String> {
        if self.selected()? {
            self.single.open(binding, deadline, cancelled)
        } else {
            self.fixture.open(binding, deadline, cancelled)
        }
    }
}
#[cfg(test)]
mod tests;
