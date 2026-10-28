//! Read-only draft readiness and durable, scan-wide coverage for presentation.
use crate::{Update, emit};
use std::sync::mpsc;
use studio_protocol::{Backend, Command, Id, Job, NetworkReport, raw_profile_enabled};
use studio_store::SavedScan;

/// `route_ready` proves only read-only route/admission checks. It says nothing
/// about ARP responses, BPF access, or permission to start the TCP engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkReadiness {
    pub job_digest: Option<[u8; 32]>,
    pub backend: Backend,
    pub checking: bool,
    pub route_ready: bool,
    pub execution_enabled: bool,
    pub detail: String,
}

/// Normalized original input counts, before user/automatic exclusions. Parsing
/// uses range arithmetic, so a broad requested range trimmed by exclusions stays bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestedCounts {
    pub targets: u64,
    pub ports: u64,
    pub probes: u64,
}
pub fn requested_counts(job: &Job) -> Result<RequestedCounts, String> {
    job.validate()?;
    let mut targets = rmasscan_core::ranges::RangeList::new();
    for selector in job
        .targets
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
    {
        rmasscan_core::targets::add_target_string(&mut targets, selector)
            .map_err(|e| e.to_string())?;
    }
    targets.sort_and_merge();
    let mut ports = rmasscan_core::ranges::RangeList::new();
    rmasscan_core::targets::parse_ports(&mut ports, &job.ports).map_err(|e| e.to_string())?;
    ports.sort_and_merge();
    Ok(RequestedCounts {
        targets: targets.count(),
        ports: ports.count(),
        probes: targets.count() * ports.count(),
    })
}

/// Scan-wide metadata, independent of the currently filtered result rows.
/// The original input strings and the complete exclusion/unresolved lists remain
/// available; eligible targets are not a claim that TCP probing completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkCoverage {
    pub scan: Id,
    pub job: Job,
    pub report: NetworkReport,
    /// Number of user-written selectors, not expanded hosts.
    pub requested_inputs: usize,
    /// Deduplicated IPv4 union before user or automatic exclusions.
    pub requested_targets: u64,
    pub requested_probes: u64,
    pub candidate_targets: u64,
    pub candidate_probes: u64,
    pub effective_targets: u64,
    pub effective_probes: u64,
    pub eligible_targets: u64,
    pub eligible_probes: u64,
    pub unresolved_targets: u64,
    pub unresolved_probes: u64,
    pub excluded_targets: u64,
    pub excluded_probes: u64,
}
impl NetworkCoverage {
    pub fn from_saved(saved: &SavedScan) -> Result<Option<Self>, String> {
        let Some(bytes) = &saved.network_report else {
            return Ok(None);
        };
        let report = NetworkReport::decode(bytes)?;
        report.validate_for(&saved.job)?;
        // Count normalized ranges without expanding addresses or ports. An
        // original /0 trimmed by user exclusions must remain bounded work.
        let counts = requested_counts(&saved.job)?;
        let requested_targets = counts.targets;
        let ports = counts.ports;
        let candidate_targets = saved.job.network_targets()?.addresses().len() as u64;
        let effective_targets = report.routes.next_hops.len() as u64;
        let eligible_targets = report.destinations.len() as u64;
        let unresolved_targets = report.unresolved.len() as u64;
        let excluded_targets = report.routes.excluded.len() as u64;
        Ok(Some(Self {
            scan: saved.scan,
            job: saved.job.clone(),
            requested_inputs: saved
                .job
                .targets
                .split(|c: char| c.is_whitespace() || c == ',')
                .filter(|s| !s.is_empty())
                .count(),
            report,
            requested_targets,
            requested_probes: requested_targets * ports,
            candidate_targets,
            candidate_probes: candidate_targets * ports,
            effective_targets,
            effective_probes: effective_targets * ports,
            eligible_targets,
            eligible_probes: eligible_targets * ports,
            unresolved_targets,
            unresolved_probes: unresolved_targets * ports,
            excluded_targets,
            excluded_probes: excluded_targets * ports,
        }))
    }
}

#[derive(Default)]
pub(crate) struct Draft {
    current: Option<NetworkReadiness>,
}
impl Draft {
    pub fn set(
        &mut self,
        job: &Job,
        checking: bool,
        out: &mpsc::SyncSender<Update>,
    ) -> Result<bool, String> {
        let validation = job.validate().and_then(|()| job.original_digest());
        let valid = validation.is_ok();
        let (digest, detail) = match validation {
            Ok(digest) => (
                Some(digest),
                if job.backend == Backend::Simulation {
                    "Simulation needs no network check"
                } else if checking {
                    "Checking routes only; no ARP or TCP packets are sent"
                } else {
                    "Network check required for these settings"
                }
                .into(),
            ),
            Err(detail) => (None, detail),
        };
        self.current = Some(NetworkReadiness {
            job_digest: digest,
            backend: job.backend,
            checking: checking && valid,
            route_ready: false,
            execution_enabled: raw_profile_enabled(job.backend),
            detail,
        });
        emit(out, Update::NetworkReadiness(self.current.clone()))?;
        Ok(valid)
    }
    pub fn invalidate(&mut self, out: &mpsc::SyncSender<Update>) -> Result<(), String> {
        self.current = None;
        emit(out, Update::NetworkReadiness(None))
    }
    pub fn checked_legacy(
        &mut self,
        ready: bool,
        detail: String,
        out: &mpsc::SyncSender<Update>,
    ) -> Result<(), String> {
        if let Some(current) = &self.current
            && current.backend == Backend::MacFeth
            && let Some(digest) = current.job_digest
        {
            self.checked(digest, ready, detail, out)?;
        }
        Ok(())
    }
    pub fn checked(
        &mut self,
        digest: [u8; 32],
        ready: bool,
        detail: String,
        out: &mpsc::SyncSender<Update>,
    ) -> Result<(), String> {
        if let Some(current) = self.current.as_mut()
            && current.checking
            && current.job_digest == Some(digest)
        {
            current.checking = false;
            current.route_ready = ready;
            current.detail = detail;
            emit(out, Update::NetworkReadiness(Some(current.clone())))?;
        }
        Ok(())
    }
}

pub(crate) fn coverage(saved: &SavedScan) -> Result<Update, String> {
    Ok(Update::NetworkCoverage(
        NetworkCoverage::from_saved(saved)?.map(Box::new),
    ))
}

pub(crate) fn check_command(job: Job) -> Command {
    if job.backend == Backend::MacFeth {
        Command::CheckNetwork
    } else {
        Command::CheckNetworkJob(job)
    }
}
