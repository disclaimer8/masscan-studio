//! Mandatory sealed-lab hooks, shared by all candidate Native execution paths.
use super::*;
use std::sync::Mutex;
use studio_protocol::sealed_fixture::{self as policy, Pin, State, topology};

// The only product constructor uses System. Injection is private to this module;
// tests exercise these same hooks, never a cfg(test) safety exemption.
trait Host: Send + Sync {
    fn authorize(&self) -> Result<(), String>;
    fn seal(&self, deadline: Instant, cancelled: &dyn Fn() -> bool)
    -> Result<(State, u64), String>;
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
pub struct Native {
    host: Box<dyn Host>,
    pin: Mutex<Pin>,
}
impl Default for Native {
    fn default() -> Self {
        Self {
            host: Box::new(System),
            pin: Mutex::new(Pin::default()),
        }
    }
}
fn bounded(deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<(), String> {
    check(cancelled)?;
    if Instant::now() >= deadline {
        return Err("sealed fixture observation timed out".into());
    }
    Ok(())
}
impl Native {
    fn sealed(&self, deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<u32, String> {
        bounded(deadline, cancelled)?;
        let (state, now) = self.host.seal(deadline, cancelled)?;
        bounded(deadline, cancelled)?;
        self.pin
            .lock()
            .map_err(|_| "sealed fixture pin poisoned")?
            .check(&state, now)
    }
}
impl Environment for Native {
    fn authorize(&self) -> Result<(), String> {
        self.host.authorize()
    }
    fn observe(
        &self,
        job: &Job,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PhysicalRoutePlan, String> {
        policy::validate_job(job)?;
        let index = self.sealed(deadline, cancelled)?;
        let plan = self.host.plan(job, deadline, cancelled)?;
        bounded(deadline, cancelled)?;
        policy::validate_pinned_plan(&plan, index)?;
        self.sealed(deadline, cancelled)?;
        Ok(plan)
    }
    fn neighbours(
        &self,
        plan: &PhysicalRoutePlan,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<NeighbourReport, String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let index = self.sealed(deadline, cancelled)?;
        let resume = policy::validate_neighbour_plan(plan, index)?;
        let binding = AdapterBinding {
            interface_id: plan.interface_name.clone(),
            link_type: rmasscan_core::packet::LinkType::Ethernet,
            source_ipv4: plan.source_ipv4.into(),
            source_mac: plan.source_mac.ok_or("Missing source MAC")?,
            next_hop_mac: [0xff; 6],
            source_ports: (40000, 40000),
        };
        let mut pair = self.open(&binding, deadline, cancelled)?;
        bounded(deadline, cancelled)?;
        let neighbours = self.host.resolve(&mut pair, plan, cancelled)?;
        drop(pair);
        check(cancelled)?;
        policy::validate_neighbours(&neighbours, resume)?;
        Ok(neighbours)
    }
    fn open(
        &self,
        binding: &AdapterBinding,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<AdapterPair, String> {
        bounded(deadline, cancelled)?;
        self.authorize()?;
        policy::validate_binding(binding)?;
        // Recheck the complete original route map immediately before BPF, even
        // when the caller resolves only the frozen eligible Resume subset.
        self.observe(&topology::job(), deadline, cancelled)?;
        bounded(deadline, cancelled)?;
        let pair = self.host.open(binding)?;
        // Kernel BPF open itself is not preemptible; a late pair is closed here.
        bounded(deadline, cancelled)?;
        Ok(pair)
    }
}
struct System;
impl Host for System {
    fn authorize(&self) -> Result<(), String> {
        if !cfg!(target_os = "macos")
            || !studio_protocol::raw_profile_enabled(studio_protocol::Backend::MacNetwork)
        {
            return Err("Physical network profile is disabled pending acceptance".into());
        }
        #[cfg(unix)]
        if studio_platform::unix::Identity::current()?.uid != 0 {
            return Err("Authorize the root helper before a physical scan".into());
        }
        Ok(())
    }
    fn seal(
        &self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(State, u64), String> {
        bounded(deadline, cancelled)?;
        #[cfg(target_os = "macos")]
        {
            let state = studio_platform::sealed_fixture::live(deadline, cancelled)?;
            Ok((state, studio_platform::sealed_fixture::now()?))
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err("sealed fixture requires macOS".into())
        }
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

#[cfg(test)]
mod tests;
