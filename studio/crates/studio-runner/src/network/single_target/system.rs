use super::*;
use studio_platform::{single_target::Store, unix::Identity};
pub(super) struct System {
    pub uid: u32,
}
impl Host for System {
    fn transmission(
        &self,
        permit: &Permit,
        context: &Context<'_>,
        claim: &Claim,
        attempt: Id,
        witness: &CaptureWitness,
        deadline: Instant,
    ) -> Result<Admission, String> {
        let mut lease = Store::existing_root()?
            .transmission_lease(permit, context, claim, attempt, witness, deadline)?;
        Ok(Box::new(move |io_deadline| lease.check(io_deadline)))
    }
    fn authority(&self) -> Result<Authority, String> {
        if self.uid == 0
            || !studio_protocol::raw_profile_enabled(studio_protocol::Backend::MacNetwork)
        {
            return Err("Single-target candidate disabled or invalid owner".into());
        }
        let me = Identity::current()?;
        if me.uid != 0 {
            return Err("Single-target execution requires root helper".into());
        }
        let config = studio_platform::work_session::host_config(self.uid)?
            .ok_or("Single-target host absent")?;
        let host = Identity::read(config.pid)?;
        let issuer = studio_platform::macos::installed_path(&config.tool_hash)?;
        if host.uid != 0
            || host.executable != issuer
            || me.executable != studio_platform::macos::installed_path(&config.runner_hash)?
        {
            return Err("Single-target host/helper identity differs".into());
        }
        studio_platform::trusted::verify(&issuer, &config.tool_hash)?;
        studio_platform::trusted::verify(&me.executable, &config.runner_hash)?;
        Ok(Authority {
            now: studio_platform::sealed_fixture::now()?,
            uid: self.uid,
            tool: config.tool_hash,
            helper: config.runner_hash,
        })
    }
    fn permit(&self, context: &Context<'_>) -> Result<Permit, String> {
        Store::existing_root()?.load(context)
    }
    fn capture(&self, permit: &Permit, context: &Context<'_>) -> Result<CaptureWitness, String> {
        Store::existing_root()?.live_capture(permit, context)
    }
    fn claim(&self, permit: &Permit, context: &Context<'_>, attempt: Id) -> Result<Claim, String> {
        Store::existing_root()?.claim(permit, context, attempt)
    }
    fn verify_claim(
        &self,
        permit: &Permit,
        context: &Context<'_>,
        claim: &Claim,
        attempt: Id,
    ) -> Result<(), String> {
        Store::existing_root()?.verify_claim(permit, context, claim, attempt)
    }
    fn plan(
        &self,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String> {
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
    fn resolve(
        &self,
        pair: &mut AdapterPair,
        plan: &PhysicalRoutePlan,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<NeighbourReport, String> {
        rmasscan_net::resolve_neighbours(
            pair,
            plan,
            &rmasscan_core::throttle::SystemClock::new(),
            cancelled,
        )
        .map_err(|e| e.to_string())
    }
}
