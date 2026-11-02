//! GUI driver for the same sealed, independently captured fixture as xtask.
use super::*;
use studio_protocol::{acceptance::*, sealed_fixture::topology};

fn check_terminal_view(ui: &MainWindow, rows: usize, complete: bool) -> Result<(), String> {
    let expected = if complete { "Completed" } else { "Stopped" };
    if ui.get_process_status() != expected || rows == 0 || (complete && rows != 96) {
        return Err("Native terminal status or results are missing from the GUI".into());
    }
    Ok(())
}

pub fn case(args: &[String]) -> Result<Option<String>, String> {
    let values: Vec<_> = args
        .iter()
        .filter_map(|a| a.strip_prefix("--smoke-network-case="))
        .collect();
    if values.is_empty() {
        return Ok(None);
    }
    if values.len() != 1
        || args.iter().filter(|a| a.starts_with("--smoke")).count() != 1
        || !["complete", "stop-running"].contains(&values[0])
    {
        return Err("Choose one network GUI case: complete or stop-running".into());
    }
    Ok(Some(values[0].into()))
}

pub struct Driver {
    case: String,
    out: PathBuf,
    ticket: Ticket,
    begin: Instant,
    deadline: Instant,
    driver_started: Stamp,
    sampler: Option<Sampler>,
    identity: String,
    uid: u32,
    phase: u8,
    start: Option<Stamp>,
    control: Option<Stamp>,
    terminal: Option<Stamp>,
    coverage: bool,
    sent: u64,
    error: Option<String>,
    displayed_rows: Option<usize>,
}
impl Driver {
    pub fn prepare(case: String, runner: &std::path::Path) -> Result<Self, String> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (case, runner);
            Err("Native GUI fixture requires macOS".into())
        }
        #[cfg(target_os = "macos")]
        {
            let out = std::env::var_os("STUDIO_SMOKE_OUT")
                .map(PathBuf::from)
                .ok_or("STUDIO_SMOKE_OUT required")?;
            let data = std::env::var_os("STUDIO_DATA_DIR")
                .map(PathBuf::from)
                .ok_or("STUDIO_DATA_DIR required")?;
            let ticket_path = std::env::var_os("STUDIO_NETWORK_TICKET")
                .map(PathBuf::from)
                .ok_or("STUDIO_NETWORK_TICKET required")?;
            if !out.is_absolute()
                || !ticket_path.is_absolute()
                || data != out.join("history")
                || data.exists()
                || std::fs::canonicalize(&out).map_err(|e| e.to_string())? != out
            {
                return Err("Native GUI requires a fresh prepared canonical directory and its history subdirectory".into());
            }
            if std::fs::read(out.join(format!("prepared-{case}"))).map_err(|e| e.to_string())?
                != b"prepared\n"
                || std::fs::read(out.join("fixture-job.json")).map_err(|e| e.to_string())?
                    != serde_json::to_vec(&topology::job()).map_err(|e| e.to_string())?
            {
                return Err("Missing fixed-fixture preparation marker".into());
            }
            if std::fs::metadata(&ticket_path)
                .map_err(|e| e.to_string())?
                .len()
                > 16384
            {
                return Err("Oversized ticket".into());
            }
            let ticket: Ticket =
                serde_json::from_slice(&std::fs::read(ticket_path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let (_, host) = studio_platform::work_session::connect()?
                .ok_or("Retained work session required")?;
            let seal = studio_platform::sealed_fixture::load(
                Instant::now() + Duration::from_secs(3),
                &|| false,
            )?;
            let owner = studio_platform::unix::Identity::current()?;
            let begin = Instant::now();
            let driver_started = Stamp::now(begin)?;
            if owner.uid == 0
                || ticket.case != case
                || ticket.seal_generation != seal.generation
                || ticket.tooling_sha256 != seal.tooling_sha256
                || ticket.tooling_sha256 != host.caller_hash
                || ticket.runner_sha256 != host.runner_hash
                || ticket.runner_sha256 != studio_platform::trusted::file_hash(runner)?
                || driver_started.low()? <= ticket.ready.high()?
                || driver_started.high()?
                    >= ticket
                        .ready
                        .wall_ns
                        .checked_add(70_000_000_000)
                        .ok_or("Ticket overflow")?
            {
                return Err(
                    "GUI ticket, retained session, helper or sealed fixture differs/expired".into(),
                );
            }
            let sampler = Some(Sampler::start(begin, driver_started.clone()));
            let deadline = begin
                + Duration::from_nanos(
                    ticket.ready.wall_ns + 70_000_000_000 - driver_started.high()?,
                );
            Ok(Self {
                case,
                out,
                ticket,
                begin,
                deadline,
                driver_started,
                sampler,
                identity: serde_json::to_string(&owner).map_err(|e| e.to_string())?,
                uid: owner.uid,
                phase: 0,
                start: None,
                control: None,
                terminal: None,
                coverage: false,
                sent: 0,
                error: None,
                displayed_rows: None,
            })
        }
    }
    pub fn observe(&mut self, updates: &[Update]) {
        for update in updates {
            let result = match update {
                Update::Authorization {
                    busy: false,
                    authorized: false,
                    detail,
                } if self.phase != 0 => Err(detail.clone()),
                Update::NetworkCoverage(Some(c)) => {
                    topology::validate_report(&c.report).map(|()| self.coverage = true)
                }
                Update::Progress(sent, _) => sent
                    .parse()
                    .map(|n| self.sent = n)
                    .map_err(|_| "Invalid progress count".into()),
                Update::State(status, detail) => {
                    if self.terminal.is_some() && process_active(status) {
                        Err("GUI restarted after terminal state".into())
                    } else if matches!(
                        status,
                        Status::Failed | Status::Interrupted | Status::Paused
                    ) {
                        Err(detail.clone())
                    } else if matches!(status, Status::Completed | Status::Stopped) {
                        let expected = if self.case == "complete" {
                            Status::Completed
                        } else {
                            Status::Stopped
                        };
                        if status != &expected || self.start.is_none() {
                            Err("Unexpected terminal status".into())
                        } else {
                            Stamp::now(self.begin).map(|s| {
                                self.terminal = Some(s);
                                self.phase = 3;
                            })
                        }
                    } else {
                        Ok(())
                    }
                }
                _ => Ok(()),
            };
            if let Err(e) = result {
                self.error = Some(e);
            }
        }
    }
    pub fn tick(&mut self, ui: &MainWindow, displayed_rows: usize) -> Result<bool, String> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        if Instant::now() >= self.deadline
            || Stamp::now(self.begin)?.high()?
                >= self
                    .ticket
                    .ready
                    .wall_ns
                    .checked_add(70_000_000_000)
                    .ok_or("Ticket overflow")?
        {
            return Err("Native GUI deadline expired".into());
        }
        match self.phase {
            0 => {
                fill_settings(ui, &topology::job());
                ui.invoke_settings_edited();
                ui.invoke_check_settings();
                ui.invoke_lock_session();
                self.phase = 1;
            }
            1 if ui.get_authorized() && !ui.get_authorizing() => {
                if draft(ui)? != topology::job() || !ui.get_can_start() {
                    return Err("Fixed native settings changed or Start unavailable".into());
                }
                self.start = Some(Stamp::now(self.begin)?);
                ui.invoke_run_process_test();
                self.phase = 2;
            }
            2 if self.case == "stop-running" && self.sent >= 4 && self.control.is_none() => {
                if !ui.get_can_stop() {
                    return Err("Stop unavailable during native scan".into());
                }
                self.control = Some(Stamp::now(self.begin)?);
                ui.invoke_stop_scan();
            }
            3 if self.begin.elapsed().as_nanos()
                > u128::from(self.terminal.as_ref().unwrap().mono_ns) + u128::from(QUIET_NS) =>
            {
                if !self.coverage {
                    return Err("Native GUI lacked validated coverage".into());
                }
                check_terminal_view(ui, displayed_rows, self.case == "complete")?;
                self.displayed_rows = Some(displayed_rows);
                let pixels = ui.window().take_snapshot().map_err(|e| e.to_string())?;
                image::save_buffer(
                    self.out.join("terminal.png"),
                    pixels.as_bytes(),
                    pixels.width(),
                    pixels.height(),
                    image::ColorType::Rgba8,
                )
                .map_err(|e| e.to_string())?;
                return Ok(true);
            }
            _ => {}
        }
        Ok(false)
    }
    /// Called only after the GUI and its real Controller have been dropped/joined.
    pub fn finish(mut self) -> Result<(), String> {
        let (joined, samples) = self.sampler.take().ok_or("Missing sampler")?.finish()?;
        let db = studio_store::Store::open(&self.out.join("history")).map_err(|e| e.to_string())?;
        let scans = db.scans().map_err(|e| e.to_string())?;
        let expected = if self.case == "complete" {
            Status::Completed
        } else {
            Status::Stopped
        };
        if scans.len() != 1
            || scans[0].job != topology::job()
            || scans[0].status != expected
            || scans[0].checkpoint.is_some()
            || scans[0].next_index.is_some()
        {
            return Err("Native GUI durable outcome differs".into());
        }
        let saved = &scans[0];
        let rows = db.rows(saved.scan).map_err(|e| e.to_string())?;
        if self.displayed_rows != Some(rows.len()) {
            return Err("Displayed native results differ from durable history".into());
        }
        let mut keys = std::collections::BTreeSet::new();
        for r in &rows {
            let ip = r.ip.parse().map_err(|_| "Invalid result IP")?;
            if ![topology::A, topology::B, topology::ROUTED].contains(&ip)
                || !(8000..=8031).contains(&r.port)
                || r.open != (r.port % 2 == 0)
                || !keys.insert((r.ip.clone(), r.port))
            {
                return Err("Native GUI retained incorrect/duplicate results".into());
            }
        }
        if self.case == "complete" && rows.len() != 96 {
            return Err("Native GUI completion lacks 96 results".into());
        }
        topology::validate_report(&studio_protocol::NetworkReport::decode(
            saved
                .network_report
                .as_deref()
                .ok_or("Missing native report")?,
        )?)?;
        let attempt = Attempt {
            ticket: self.ticket,
            driver_pid: std::process::id(),
            driver_uid: self.uid,
            process_identity: self.identity,
            driver_started: self.driver_started,
            start: self.start.ok_or("Missing Start")?,
            control: self.control,
            terminal: self.terminal.ok_or("Missing terminal")?,
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
        let target = self.out.join(format!("{}-attempt.json", self.case));
        if target.exists() {
            return Err("Refuse replacing native GUI evidence".into());
        }
        let temporary = self.out.join("gui-attempt.next");
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        f.write_all(&serde_json::to_vec_pretty(&attempt).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(temporary, target).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_gui_cannot_pass_when_results_or_terminal_status_are_not_displayed() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.set_process_status("Completed".into());
        assert!(check_terminal_view(&ui, 0, true).is_err());
        assert!(check_terminal_view(&ui, 95, true).is_err());
        assert!(check_terminal_view(&ui, 96, true).is_ok());
        ui.set_process_status("Scanning".into());
        assert!(check_terminal_view(&ui, 96, true).is_err());
        ui.set_process_status("Stopped".into());
        assert!(check_terminal_view(&ui, 0, false).is_err());
        assert!(check_terminal_view(&ui, 4, false).is_ok());
    }
    #[test]
    fn native_gui_rejects_unknown_cases_and_mixed_smokes() {
        for args in [
            vec!["--smoke-network-case=guard"],
            vec!["--smoke-network-case=complete", "--smoke"],
            vec![
                "--smoke-network-case=complete",
                "--smoke-network-case=stop-running",
            ],
        ] {
            assert!(case(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err());
        }
        assert_eq!(
            case(&["--smoke-network-case=complete".into()])
                .unwrap()
                .as_deref(),
            Some("complete")
        );
        assert!(case(&[]).unwrap().is_none());
    }
}
