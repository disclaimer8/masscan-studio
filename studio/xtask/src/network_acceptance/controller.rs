//! Actual Studio Controller -> authenticated installed helper -> durable Store.
//! This driver cannot launch until the separately reviewed candidate interlocks exist.
use super::{
    lifecycle::{Attempt, Sampler, Stamp, Ticket},
    read_bounded,
    supervision::Phase,
    topology::*,
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::{Duration, Instant},
};
use studio_app::{Action, Controller, Update};
use studio_protocol::{Backend, Status};

// Task6b must change this only together with reviewed pre-ARP/pre-ACK constraints.
const SEALED_CANDIDATE_INTERLOCKS_REVIEWED: bool = true;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Complete,
    Pause,
    Resume,
    StopPreparing,
    StopRunning,
    Guard,
}
fn case(text: &str) -> Result<Case, String> {
    match text {
        "complete" => Ok(Case::Complete),
        "pause" => Ok(Case::Pause),
        "resume" => Ok(Case::Resume),
        "stop-preparing" => Ok(Case::StopPreparing),
        "stop-running" => Ok(Case::StopRunning),
        "guard" => Ok(Case::Guard),
        _ => Err("case must be complete|pause|resume|stop-preparing|stop-running|guard".into()),
    }
}
fn admission(interlocks: bool, gate: bool) -> Result<(), String> {
    if !interlocks || !gate {
        return Err("NOT RUN: candidate pre-ARP/pre-ACK fixture interlocks and physical gate have not both been reviewed/enabled".into());
    }
    Ok(())
}

pub fn drive(text: &str, runner: &Path, out: &Path, ticket_path: &Path) -> Result<(), String> {
    // Before even creating a directory or opening any history/Controller.
    admission(
        SEALED_CANDIDATE_INTERLOCKS_REVIEWED,
        studio_protocol::raw_profile_enabled(Backend::MacNetwork),
    )?;
    let case = case(text)?;
    if !runner.is_absolute() || !out.is_absolute() || !runner.is_file() {
        return Err("runner/out must be absolute; runner must exist".into());
    }
    let driver_uid = super::native::command(&["/usr/bin/id", "-u"])?
        .trim()
        .parse::<u32>()
        .map_err(|_| "invalid driver uid")?;
    if driver_uid == 0 {
        return Err(
            "Controller driver must run unprivileged; use normal helper authorization".into(),
        );
    }
    let process_identity = super::native::command(&[
        "/bin/ps",
        "-p",
        &std::process::id().to_string(),
        "-o",
        "lstart=",
        "-o",
        "command=",
    ])?;
    if case == Case::Resume {
        if fs::symlink_metadata(out)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
            || read_bounded(&out.join("fixture-job.json"), 4096)?
                != serde_json::to_vec(&job()).map_err(|e| e.to_string())?
        {
            return Err("resume needs this fixture's marked isolated history".into());
        }
    } else if read_bounded(&out.join(format!("prepared-{text}")), 64)? != b"prepared\n"
        || out.join("history").exists()
    {
        return Err("new case needs prepared empty isolated directory".into());
    }
    let ticket: Ticket =
        serde_json::from_slice(&read_bounded(ticket_path, 65536)?).map_err(|e| e.to_string())?;
    if ticket.case != text
        || ticket.runner_sha256 != studio_platform::trusted::file_hash(runner)?
        || ticket.tooling_sha256
            != studio_platform::trusted::file_hash(
                &std::env::current_exe().map_err(|e| e.to_string())?,
            )?
    {
        return Err("ticket case/candidate binary hashes differ".into());
    }
    let begin = Instant::now();
    let driver_started = Stamp::now(begin)?;
    let sampler = Sampler::start(begin, driver_started.clone());
    let expiry = ticket
        .ready
        .wall_ns
        .checked_add(70_000_000_000)
        .ok_or("ticket time overflow")?;
    if driver_started.low()? <= ticket.ready.high()? || driver_started.high()? >= expiry {
        return Err("ticket not fresh or clock ambiguous".into());
    }
    let budget = Duration::from_nanos(expiry - driver_started.high()?);
    let history = out.join("history");
    let previous = if case == Case::Resume {
        let db = studio_store::Store::open(&history).map_err(|e| e.to_string())?;
        let scans = db.scans().map_err(|e| e.to_string())?;
        if scans.len() != 1
            || scans[0].job != job()
            || scans[0].status != Status::Paused
            || scans[0].checkpoint.is_none()
        {
            return Err("resume needs exactly one paused fixture scan".into());
        }
        Some(scans[0].clone())
    } else {
        None
    };
    let mut log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out.join(format!("{text}-events.ndjson")))
        .map_err(|e| e.to_string())?;
    let mut app = Controller::open(history.clone(), runner.into())?;
    app.send(Action::AuthorizeFor(job()))?;
    let mut start_stamp = None;
    let mut control_stamp = None;
    let mut terminal_stamp = None;
    let mut active = None;
    let mut started = false;
    let mut control = false;
    let mut terminal = None;
    let mut coverage = false;
    let mut sent = 0u64;
    while begin.elapsed() < budget && terminal.is_none() {
        for update in app.poll() {
            match update {
                Update::Authorization {
                    busy: false,
                    authorized,
                    detail,
                } => {
                    writeln!(log,"{}",serde_json::json!({"ms":begin.elapsed().as_millis(),"authorization":authorized,"detail":detail})).map_err(|e|e.to_string())?;
                    if !authorized {
                        return Err("fixture helper authorization failed".into());
                    }
                    if !started {
                        // Packet-free planner check before production Start/Resume. The
                        // candidate helper repeats stronger executable checks before I/O.
                        read_only_check()?;
                        if begin.elapsed() >= budget {
                            return Err("ticket expired before Start".into());
                        }
                        start_stamp = Some(Stamp::now(begin)?);
                        writeln!(
                            log,
                            "{}",
                            serde_json::json!({"event":"start-request","stamp":start_stamp})
                        )
                        .map_err(|e| e.to_string())?;
                        app.send(if case == Case::Resume {
                            Action::Resume
                        } else {
                            Action::Start(job())
                        })?;
                        started = true;
                    }
                }
                Update::NetworkCoverage(Some(c)) => {
                    validate_report(&c.report)?;
                    coverage = true;
                }
                Update::Progress(n, received) => {
                    sent = n.parse().map_err(|_| "invalid progress sent")?;
                    writeln!(log,"{}",serde_json::json!({"ms":begin.elapsed().as_millis(),"sent":n,"received":received})).map_err(|e|e.to_string())?;
                    if !control && sent >= 4 && matches!(case, Case::Pause | Case::StopRunning) {
                        control_stamp = Some(Stamp::now(begin)?);
                        writeln!(log,"{}",serde_json::json!({"event":"control-request","case":text,"stamp":control_stamp})).map_err(|e|e.to_string())?;
                        app.send(if case == Case::Pause {
                            Action::Pause
                        } else {
                            Action::Stop
                        })?;
                        control = true;
                    }
                    if !control
                        && sent >= 4
                        && case == Case::Guard
                        && let Some((scan, attempt)) = active
                    {
                        let observed = Stamp::now(begin)?;
                        control_stamp = Some(observed.clone());
                        let phase = Phase {
                            ticket: ticket.clone(),
                            driver_pid: std::process::id(),
                            driver_started: driver_started.clone(),
                            start: start_stamp.clone().ok_or("missing Start stamp")?,
                            observed,
                            scan,
                            attempt,
                            sent,
                        };
                        atomic_json(out, "guard-phase.json", &phase)?;
                        control = true;
                    }
                }
                Update::State(status, detail) => {
                    writeln!(log,"{}",serde_json::json!({"ms":begin.elapsed().as_millis(),"state":status,"detail":detail})).map_err(|e|e.to_string())?;
                    if status == Status::Preparing && case == Case::StopPreparing && !control {
                        control_stamp = Some(Stamp::now(begin)?);
                        writeln!(log,"{}",serde_json::json!({"event":"stop-preparing-request","stamp":control_stamp})).map_err(|e|e.to_string())?;
                        app.send(Action::Stop)?;
                        control = true;
                    }
                    if started
                        && matches!(
                            status,
                            Status::Completed
                                | Status::Stopped
                                | Status::Paused
                                | Status::Failed
                                | Status::Interrupted
                        )
                    {
                        terminal_stamp = Some(Stamp::now(begin)?);
                        writeln!(log,"{}",serde_json::json!({"event":"terminal-observed","stamp":terminal_stamp,"status":status})).map_err(|e|e.to_string())?;
                        terminal = Some(status);
                    }
                }
                Update::History(scans, selected) => {
                    if let Some(scan) = scans.iter().find(|s| Some(s.scan) == selected) {
                        active = Some((scan.scan, scan.attempt));
                    }
                }
                Update::Notice(detail) => {
                    writeln!(
                        log,
                        "{}",
                        serde_json::json!({"ms":begin.elapsed().as_millis(),"notice":detail})
                    )
                    .map_err(|e| e.to_string())?;
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if terminal.is_none() {
        app.send(Action::Stop)?;
        drop(app);
        return Err(
            "controller acceptance deadline expired; stop requested and resources joined".into(),
        );
    }
    // Keep the real Controller alive through a quiet period: dropping it at the
    // first terminal update could hide an automatic restart. Captures continue
    // for another quiet period after its resources are actually joined.
    let quiet = Instant::now() + Duration::from_nanos(super::lifecycle::QUIET_NS);
    while Instant::now() < quiet {
        for update in app.poll() {
            if let Update::State(status, detail) = update {
                writeln!(log,"{}",serde_json::json!({"event":"post-terminal-state","stamp":Stamp::now(begin)?,"state":status,"detail":detail})).map_err(|e|e.to_string())?;
                if matches!(
                    status,
                    Status::Starting | Status::Preparing | Status::Scanning | Status::Saving
                ) {
                    return Err("Controller restarted after terminal state".into());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(app);
    let (joined, samples) = sampler.finish()?;
    writeln!(
        log,
        "{}",
        serde_json::json!({"event":"controller-joined","stamp":joined})
    )
    .map_err(|e| e.to_string())?;
    log.sync_all().map_err(|e| e.to_string())?;
    let db = studio_store::Store::open(&history).map_err(|e| e.to_string())?;
    let scans = db.scans().map_err(|e| e.to_string())?;
    if scans.len() != 1 || scans[0].job != job() {
        return Err("unexpected persisted acceptance history".into());
    }
    let saved = &scans[0];
    let rows = db.rows(saved.scan).map_err(|e| e.to_string())?;
    let expected = match case {
        Case::Complete | Case::Resume => Status::Completed,
        Case::Pause => Status::Paused,
        Case::StopPreparing | Case::StopRunning => Status::Stopped,
        Case::Guard => Status::Interrupted,
    };
    if terminal.as_ref() != Some(&expected) || saved.status != expected {
        return Err(format!(
            "unexpected terminal/persisted status: {terminal:?}/{:?}",
            saved.status
        ));
    }
    if case == Case::StopPreparing && (!rows.is_empty() || sent != 0) {
        return Err("preparation cancellation produced TCP results/progress".into());
    }
    if case != Case::StopPreparing && !coverage {
        return Err("missing app coverage update".into());
    }
    validate_rows(&rows, matches!(case, Case::Complete | Case::Resume))?;
    if let Some(bytes) = &saved.network_report {
        validate_report(&studio_protocol::NetworkReport::decode(bytes)?)?;
        fs::write(out.join("network-report.bin"), bytes).map_err(|e| e.to_string())?;
    }
    if let Some(previous) = &previous
        && (saved.scan != previous.scan
            || saved.attempt == previous.attempt
            || saved.network_report != previous.network_report)
    {
        return Err("restart Resume changed scan/frozen report or reused attempt".into());
    }
    if case == Case::Pause && saved.checkpoint.is_none() {
        return Err("pause not durable".into());
    }
    fs::write(out.join(format!("{text}-store.json")),serde_json::to_vec_pretty(&serde_json::json!({"scan":studio_protocol::id_text(saved.scan),"attempt":studio_protocol::id_text(saved.attempt),"status":saved.status,"checkpoint":saved.checkpoint,"rows":rows,"packet_witness_required":true})).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    let attempt = Attempt {
        ticket,
        driver_pid: std::process::id(),
        driver_uid,
        process_identity,
        driver_started,
        start: start_stamp.ok_or("missing Start")?,
        control: control_stamp,
        terminal: terminal_stamp.ok_or("missing terminal")?,
        joined,
        samples,
        scan: saved.scan,
        attempt: saved.attempt,
        status: saved.status.clone(),
        report: saved.network_report.clone(),
        checkpoint: saved.checkpoint.clone(),
        next_index: saved.next_index.clone(),
        rows,
    };
    atomic_json(out, &format!("{text}-attempt.json"), &attempt)?;
    println!(
        "Controller/store case {text} finished as {expected:?}; independent capture verification still required"
    );
    Ok(())
}

fn validate_rows(rows: &[studio_protocol::Row], complete: bool) -> Result<(), String> {
    let mut keys = std::collections::BTreeSet::new();
    for row in rows {
        let ip = row
            .ip
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| "invalid result IPv4")?;
        if ![A, B, ROUTED].contains(&ip)
            || !(PORT_FIRST..=PORT_LAST).contains(&row.port)
            || row.open != (row.port % 2 == 0)
            || !keys.insert((ip, row.port))
        {
            return Err("unexpected, duplicate or incorrect fixture port result".into());
        }
    }
    if complete && keys.len() != 96 {
        return Err("completed scan lacks96 expected open/closed results".into());
    }
    Ok(())
}

fn read_only_check() -> Result<(), String> {
    let mut plan = rmasscan_net::plan_physical(
        &job().network_targets()?,
        rmasscan_net::os_route_table()
            .map_err(|e| e.to_string())?
            .as_ref(),
        rmasscan_net::os_interfaces()
            .map_err(|e| e.to_string())?
            .as_ref(),
        Instant::now() + Duration::from_secs(10),
        &|| false,
    )
    .map_err(|e| e.to_string())?;
    if plan.source_mac.is_none() {
        plan.source_mac = Some(SOURCE_MAC);
    }
    // This local substitution only checks remaining read-only facts; the result
    // is discarded. It never creates a binding/report or authorizes BPF.
    validate_plan(&plan)
}

/// Prepare user-owned empty history before root pins its directory descriptor.
pub fn prepare(text: &str, out: &Path) -> Result<(), String> {
    let case = case(text)?;
    if !out.is_absolute() {
        return Err("absolute isolated output directory required".into());
    }
    if case != Case::Resume {
        fs::create_dir(out).map_err(|e| e.to_string())?;
        fs::write(
            out.join("fixture-job.json"),
            serde_json::to_vec(&job()).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    } else if read_bounded(&out.join("fixture-job.json"), 4096)?
        != serde_json::to_vec(&job()).map_err(|e| e.to_string())?
    {
        return Err("Resume requires existing paused fixture directory".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out.join(format!("prepared-{text}")))
        .map_err(|e| e.to_string())?;
    file.write_all(b"prepared\n").map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}
fn atomic_json(out: &Path, name: &str, value: &impl serde::Serialize) -> Result<(), String> {
    let temporary = out.join(format!("{name}.next"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    if out.join(name).exists() {
        return Err("refuse existing attempt/phase evidence".into());
    }
    fs::rename(temporary, out.join(name)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_candidate_gate_alone_can_enable_native_controller_driver() {
        assert!(admission(false, true).is_err());
        assert!(admission(true, false).is_err());
        assert!(admission(false, false).is_err());
        assert!(case("scan-arbitrary").is_err());
        let path = std::env::temp_dir().join(format!(
            "studio-native-refusal-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        assert!(
            drive(
                "complete",
                Path::new("/no-runner"),
                &path,
                Path::new("/no-ticket")
            )
            .unwrap_err()
            .contains("runner/out must be absolute; runner must exist")
        );
        assert!(
            !path.exists(),
            "invalid runner must precede Store/directory access"
        );
    }
    #[test]
    fn completed_history_must_cover_exact_ports_and_exclude_missing_peer() {
        let mut rows = Vec::new();
        for ip in [A, B, ROUTED] {
            for port in PORT_FIRST..=PORT_LAST {
                rows.push(studio_protocol::Row {
                    ip: ip.to_string(),
                    port,
                    open: port % 2 == 0,
                });
            }
        }
        assert!(validate_rows(&rows, true).is_ok());
        rows[0].ip = MISSING.to_string();
        assert!(validate_rows(&rows, true).is_err());
        rows.remove(0);
        assert!(validate_rows(&rows, true).is_err());
        assert!(validate_rows(&rows, false).is_ok());
        rows[0].open = !rows[0].open;
        assert!(validate_rows(&rows, false).is_err());
    }
}
