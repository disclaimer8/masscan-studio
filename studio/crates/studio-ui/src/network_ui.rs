//! Projection of typed controller facts into visible text and portable export data.
use super::*;
use rmasscan_net::ExcludedReason;
use studio_app::{NetworkCoverage, NetworkReadiness};
use studio_inspection::{CoverageAddress, CoverageCount, ExportCoverage, ExportJob, ExportRoute};

pub(super) fn backend_index(backend: Backend) -> i32 {
    match backend {
        Backend::Simulation => 1,
        Backend::MacNetwork => 2,
        _ => 0,
    }
}
pub(super) fn backend(index: i32) -> Result<Backend, String> {
    match index {
        0 => Ok(Backend::MacFeth),
        1 => Ok(Backend::Simulation),
        2 => Ok(Backend::MacNetwork),
        _ => Err("Choose a scan profile".into()),
    }
}
pub(super) fn session_action(ui: &MainWindow) -> Result<Action, String> {
    if !ui.get_process_active()
        && ui.get_authorization_available()
        && !ui.get_authorized()
        && !ui.get_authorizing()
    {
        draft(ui).map(Action::AuthorizeFor)
    } else {
        Ok(Action::Lock)
    }
}
pub(super) fn profile_hint(macos: bool, enabled: bool) -> &'static str {
    if !macos {
        "Mac network is available on macOS only."
    } else if !enabled {
        "Physical scanning is disabled in this build pending network acceptance. You can check settings and routes without sending scan packets."
    } else {
        "Only scan targets you are authorized to test. Start prepares neighbours, then sends TCP probes."
    }
}
pub(super) fn preview(job: &Job) -> Result<String, String> {
    job.validate()?;
    if job.backend != Backend::MacNetwork {
        let plan = job.prepare()?;
        return Ok(format!(
            "{} endpoints · wait 3 s · exact seed {}",
            plan.range(),
            job.seed
        ));
    }
    let counts = studio_app::requested_counts(job)?;
    let candidates = job.network_targets()?.addresses().len() as u64;
    Ok(format!(
        "Requested: {} addresses / {} probes · {} unique TCP ports\nCandidates after your exclusions: {candidates} addresses / {} probes\nEffective targets require a route check; eligible targets require neighbour preparation after Start.\nLimits: 2048 candidates, 1024 effective addresses, 1048576 probes, 1000 packets/s.",
        counts.targets,
        counts.probes,
        counts.ports,
        candidates * counts.ports
    ))
}
pub(super) fn readiness(ui: &MainWindow, value: Option<&NetworkReadiness>) {
    let digest = draft(ui)
        .and_then(|job| job.validate().and_then(|()| job.original_digest()))
        .ok();
    // A reply already queued in the UI can arrive after a user edit, before its
    // SetDraft is processed. Never render readiness for different settings.
    let value = value.filter(|v| {
        v.job_digest == digest && backend(ui.get_backend_index()).is_ok_and(|b| b == v.backend)
    });
    ui.set_network_checking(value.is_some_and(|v| v.checking));
    ui.set_network_detail(value.map(|v| {
        if v.backend == Backend::Simulation { return v.detail.clone() }
        if v.backend == Backend::MacFeth { return format!("Isolated stand check: {}", v.detail) }
        format!("{}\n{}\nA route check does not authorize a helper session or confirm neighbour responses or packet access. macOS may hide the source hardware address during this check; that does not prove the adapter can send packets.",
            if v.checking { "Checking routes…" } else if v.route_ready { "Read-only route check passed" } else { "Route check required or unavailable" },
            v.detail.replace("BPF", "packet access").replace("Physical execution gate", "Physical scanning"))
    }).unwrap_or_else(|| "Check routes for the current settings. No ARP or TCP scan packets are sent.".into()).into());
}
fn mac(bytes: [u8; 6]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
pub(super) fn export_coverage(value: &NetworkCoverage) -> ExportCoverage {
    let pair = |targets, probes| CoverageCount { targets, probes };
    let routes = &value.report.routes;
    ExportCoverage {
        scan_id: studio_protocol::id_text(value.scan),
        original_job: ExportJob {
            backend: "MacNetwork".into(),
            targets: value.job.targets.clone(),
            ports: value.job.ports.clone(),
            exclusions: value.job.exclusions.clone(),
            seed: value.job.seed.clone(),
            rate: value.job.rate,
        },
        original_job_digest: value
            .report
            .job_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        requested_inputs: value.requested_inputs,
        requested: pair(value.requested_targets, value.requested_probes),
        candidate: pair(value.candidate_targets, value.candidate_probes),
        effective: pair(value.effective_targets, value.effective_probes),
        eligible: pair(value.eligible_targets, value.eligible_probes),
        unscanned: pair(value.unresolved_targets, value.unresolved_probes),
        automatically_excluded: pair(value.excluded_targets, value.excluded_probes),
        interface_name: routes.interface_name.clone(),
        interface_index: routes.interface_index,
        source_ipv4: routes.source_ipv4.to_string(),
        source_mac: routes.source_mac.map(mac),
        routes: routes
            .next_hops
            .iter()
            .map(|(ip, hop)| ExportRoute {
                destination: ip.to_string(),
                next_hop: hop.to_string(),
                destination_mac: value.report.destinations.get(ip).copied().map(mac),
            })
            .collect(),
        unresolved: value
            .report
            .unresolved
            .iter()
            .map(|ip| CoverageAddress {
                ip: ip.to_string(),
                reason: "no neighbour response".into(),
            })
            .collect(),
        excluded: routes
            .excluded
            .iter()
            .map(|(ip, reason)| {
                let reason = match reason {
                    ExcludedReason::OwnAddress => "this Mac's address",
                    ExcludedReason::NetworkAddress => "subnet network address",
                    ExcludedReason::BroadcastAddress => "subnet broadcast address",
                    ExcludedReason::ForbiddenAddress => "forbidden address",
                };
                CoverageAddress {
                    ip: ip.to_string(),
                    reason: reason.into(),
                }
            })
            .collect(),
    }
}
pub(super) fn coverage(ui: &MainWindow, value: Option<&NetworkCoverage>) -> Option<ExportCoverage> {
    ui.set_has_network_coverage(value.is_some());
    let Some(value) = value else {
        ui.set_coverage_summary("".into());
        ui.set_coverage_details("".into());
        ui.set_coverage_open(false);
        return None;
    };
    let report = export_coverage(value);
    ui.set_coverage_summary(format!("Selected scan · requested {} addresses / {} probes · candidates {} addresses / {} probes · effective {} addresses / {} probes · eligible {} addresses / {} probes\nNot scanned: {} addresses / {} probes (no neighbour response) · automatically excluded {} addresses / {} probes. Eligible is the prepared plan; sent counts are shown separately.", value.requested_targets, value.requested_probes, value.candidate_targets, value.candidate_probes, value.effective_targets, value.effective_probes, value.eligible_targets, value.eligible_probes, value.unresolved_targets, value.unresolved_probes, value.excluded_targets, value.excluded_probes).into());
    let direct = value
        .report
        .routes
        .next_hops
        .iter()
        .filter(|(ip, hop)| ip == hop)
        .count();
    let mut details = format!(
        "Interface {} · source {} · {} direct / {} routed\nOriginal targets ({} selectors): {}\nTCP ports: {} · exclusions: {}\n{}",
        report.interface_name,
        report.source_ipv4,
        direct,
        report.routes.len() - direct,
        report.requested_inputs,
        report.original_job.targets,
        report.original_job.ports,
        report.original_job.exclusions,
        if value.eligible_targets == 0 {
            "No targets were eligible; no TCP engine started."
        } else {
            "Eligibility alone does not establish completed TCP coverage."
        }
    );
    for a in &report.unresolved {
        details.push_str(&format!("\n{} · not scanned: {}", a.ip, a.reason));
    }
    for a in &report.excluded {
        details.push_str(&format!(
            "\n{} · automatically excluded: {}",
            a.ip, a.reason
        ));
    }
    ui.set_coverage_details(details.into());
    Some(report)
}

/// Programmatic fills never call the user-edit callback. Slint TextInput.edited
/// and ComboBox.selected fire for user interaction, not property assignment.
pub(super) fn settings_changed(ui: &MainWindow) {
    ui.set_job_valid(false);
    ui.set_job_preview("".into());
    ui.set_job_feedback("Settings changed. Check again to refresh the preview.".into());
}

/// Shared by the actual user-edit callback and headless History/export regression.
pub(super) fn changed_draft(ui: &MainWindow) -> Action {
    settings_changed(ui);
    // Draft readiness belongs to settings; durable coverage belongs to the
    // selected result table (including a saved selection with zero rows).
    readiness(ui, None);
    match draft(ui) {
        Ok(job) => Action::SetDraft(job),
        Err(e) => {
            let invalid = Job {
                targets: ui.get_job_targets().to_string(),
                ports: ui.get_job_ports().to_string(),
                exclusions: ui.get_job_exclusions().to_string(),
                seed: ui.get_job_seed().to_string(),
                rate: 0,
                backend: backend(ui.get_backend_index()).unwrap_or(Backend::Archived),
            };
            ui.set_job_feedback(e.into());
            Action::SetDraft(invalid)
        }
    }
}
