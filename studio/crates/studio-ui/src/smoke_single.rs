//! One bounded GUI attempt. A ticket never bypasses the helper's root admission.
use super::*;
use studio_protocol::{
    acceptance::{Sampler, Stamp},
    single_target::acceptance::{Attempt, Ticket},
};

pub fn requested(args: &[String]) -> Result<bool, String> {
    let selected = args.iter().any(|a| a == "--smoke-single-target");
    if selected && args.iter().filter(|a| a.starts_with("--smoke")).count() != 1 {
        return Err("Choose exactly one smoke mode".into());
    }
    Ok(selected)
}
pub struct Driver {
    out: PathBuf,
    ticket: Ticket,
    begin: Instant,
    deadline: Instant,
    driver_started: Stamp,
    sampler: Option<Sampler>,
    identity: String,
    ui_sha256: String,
    phase: u8,
    start: Option<Stamp>,
    terminal: Option<Stamp>,
    report: Option<Vec<u8>>,
    sent: u64,
    displayed: Option<Vec<studio_protocol::Row>>,
    failure: Option<String>,
}
fn terminal_view(ui: &MainWindow, sent: u64, ports: usize, rows: usize) -> Result<(), String> {
    if ui.get_process_status() != "Completed" || sent != ports as u64 || rows > ports {
        return Err("Single-target GUI status, sent count or displayed rows differs".into());
    }
    Ok(())
}
fn projection(model: &impl Model<Data = ResultRow>) -> Result<Vec<studio_protocol::Row>, String> {
    if model.row_count() > 4 {
        return Err("Too many visible single-target results".into());
    }
    (0..model.row_count())
        .map(|index| {
            let row = model.row_data(index).ok_or("Visible result missing")?;
            let open = match row.service.as_str() {
                "Open" => true,
                "Closed" => false,
                _ => return Err("Unexpected visible port state".into()),
            };
            if row.protocol != "TCP" || row.device != "TCP response" {
                return Err("Visible result is not an observed TCP state".into());
            }
            Ok(studio_protocol::Row {
                ip: row.ip.to_string(),
                port: row.port.parse().map_err(|_| "Invalid visible port")?,
                open,
            })
        })
        .collect()
}
impl Driver {
    pub fn prepare(runner: &std::path::Path) -> Result<Self, String> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = runner;
            Err("Single-target GUI acceptance requires macOS".into())
        }
        #[cfg(target_os = "macos")]
        {
            use studio_platform::{
                unix::Identity,
                work_session::{self, Request, Response, SingleTarget},
            };
            let out = std::env::var_os("STUDIO_SMOKE_OUT")
                .map(PathBuf::from)
                .ok_or("STUDIO_SMOKE_OUT required")?;
            let data = std::env::var_os("STUDIO_DATA_DIR")
                .map(PathBuf::from)
                .ok_or("STUDIO_DATA_DIR required")?;
            if !out.is_absolute()
                || std::fs::canonicalize(&out).map_err(|e| e.to_string())? != out
                || data != out.join("history")
                || data.exists()
                || out.join("gui-attempt.json").exists()
            {
                return Err("Single-target GUI requires canonical output and fresh history".into());
            }
            use std::io::Read;
            let mut bytes = vec![];
            std::fs::File::open(out.join("single-target-ticket.json"))
                .map_err(|e| e.to_string())?
                .take(16385)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > 16384 {
                return Err("Oversized GUI ticket".into());
            }
            let ticket: Ticket = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            let (mut connection, config) =
                work_session::connect()?.ok_or("Retained host required")?;
            work_session::require_single_target_capture(&mut connection)?;
            drop(connection);
            let (mut connection, checked) =
                work_session::connect()?.ok_or("Retained host disappeared")?;
            if checked != config {
                return Err("Retained host selection changed".into());
            }
            work_session::write(
                &mut connection,
                &Request::SingleTarget {
                    operation: SingleTarget::Inspect {},
                },
            )?;
            match work_session::read(
                &mut connection,
                Duration::from_secs(3),
                &std::sync::atomic::AtomicBool::new(false),
            )? {
                Response::SingleTarget {
                    record: Some(record),
                } if record.permit == ticket.permit && !record.claimed && !record.revoked => {}
                _ => return Err("GUI ticket differs from live unconsumed root permit".into()),
            }
            let me = Identity::current()?;
            let capture = Identity::read(ticket.capture_pid)?;
            let ui_sha256 = studio_platform::trusted::file_hash(&me.executable)?;
            ticket.validate(&studio_protocol::single_target::Context {
                now: studio_platform::sealed_fixture::now()?,
                owner_uid: me.uid,
                tooling_sha256: &config.tool_hash,
                helper_sha256: &config.runner_hash,
            })?;
            if me.uid == 0
                || capture.uid != 0
                || capture.executable != studio_platform::macos::installed_path(&config.tool_hash)?
                || ui_sha256 != config.caller_hash
                || studio_platform::trusted::file_hash(runner)? != config.runner_hash
            {
                return Err("GUI, helper or capture identity differs from selected build".into());
            }
            let begin = Instant::now();
            let driver_started = Stamp::now(begin)?;
            let remaining = ticket
                .capture_created
                .checked_add(35)
                .and_then(|s| s.checked_mul(1_000_000_000))
                .and_then(|end| end.checked_sub(driver_started.high().ok()?))
                .ok_or("GUI capture startup budget expired")?;
            let deadline = begin + Duration::from_nanos(remaining.min(30_000_000_000));
            let sampler = Some(Sampler::start(begin, driver_started.clone()));
            Ok(Self {
                out,
                ticket,
                begin,
                deadline,
                driver_started,
                sampler,
                identity: serde_json::to_string(&me).map_err(|e| e.to_string())?,
                ui_sha256,
                phase: 0,
                start: None,
                terminal: None,
                report: None,
                sent: 0,
                displayed: None,
                failure: None,
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
                Update::NetworkCoverage(Some(coverage)) => {
                    let bytes = coverage.report.encode();
                    bytes.and_then(|bytes| {
                        studio_protocol::single_target::validate_persisted(
                            &self.ticket.permit.job(),
                            Some(&bytes),
                        )?;
                        if self.report.as_ref().is_some_and(|prior| prior != &bytes) {
                            return Err("GUI report changed during attempt".into());
                        }
                        self.report = Some(bytes);
                        Ok(())
                    })
                }
                Update::Progress(sent, _) => sent
                    .parse::<u64>()
                    .map_err(|_| "Invalid sent count".to_owned())
                    .and_then(|sent| {
                        if sent < self.sent || sent > self.ticket.permit.ports.len() as u64 {
                            return Err("GUI sent count outside permit".into());
                        }
                        self.sent = sent;
                        Ok(())
                    }),
                Update::State(Status::Failed | Status::Interrupted, detail) => Err(detail.clone()),
                Update::State(status, _) if status.terminal() => {
                    if status != &Status::Completed
                        || self.start.is_none()
                        || self.terminal.is_some()
                    {
                        Err("Unexpected single-target terminal event".into())
                    } else {
                        Stamp::now(self.begin).map(|stamp| {
                            self.terminal = Some(stamp);
                            self.phase = 3;
                        })
                    }
                }
                Update::State(status, _) if self.terminal.is_some() && process_active(status) => {
                    Err("GUI restarted after completion".into())
                }
                _ => Ok(()),
            };
            if let Err(error) = result {
                self.failure = Some(error);
            }
        }
    }
    pub fn tick(&mut self, ui: &MainWindow, model: &Rows) -> Result<bool, String> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if Instant::now() >= self.deadline {
            return Err("Single-target GUI deadline expired".into());
        }
        match self.phase {
            0 => {
                fill_settings(ui, &self.ticket.permit.job());
                ui.invoke_settings_edited();
                ui.invoke_check_settings();
                ui.invoke_lock_session();
                self.phase = 1;
            }
            1 if ui.get_authorized() && !ui.get_authorizing() => {
                if draft(ui)? != self.ticket.permit.job() || !ui.get_can_start() {
                    return Err("Single-target settings differ or Start unavailable".into());
                }
                self.start = Some(Stamp::now(self.begin)?);
                ui.invoke_run_process_test();
                self.phase = 2;
            }
            3 => {
                if self.report.is_none() {
                    return Err("Single-target GUI lacked durable coverage".into());
                }
                terminal_view(
                    ui,
                    self.sent,
                    self.ticket.permit.ports.len(),
                    model.row_count(),
                )?;
                self.displayed = Some(projection(model)?);
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
    /// The real Controller is dropped and joined before this is called.
    pub fn finish(mut self) -> Result<(), String> {
        let (joined, samples) = self
            .sampler
            .take()
            .ok_or("Missing GUI clock sampler")?
            .finish()?;
        let db = studio_store::Store::open(&self.out.join("history")).map_err(|e| e.to_string())?;
        let scans = db.scans().map_err(|e| e.to_string())?;
        if scans.len() != 1
            || scans[0].job != self.ticket.permit.job()
            || scans[0].status != Status::Completed
            || scans[0].checkpoint.is_some()
            || scans[0].next_index.is_some()
            || scans[0].network_report != self.report
        {
            return Err("Single-target durable outcome differs from GUI".into());
        }
        let saved = &scans[0];
        let rows = db.rows(saved.scan).map_err(|e| e.to_string())?;
        let attempt = Attempt {
            driver_pid: std::process::id(),
            driver_uid: self.ticket.permit.owner_uid,
            ticket: self.ticket,
            process_identity: self.identity,
            ui_sha256: self.ui_sha256,
            driver_started: self.driver_started,
            start: self.start.ok_or("Missing GUI Start")?,
            terminal: self.terminal.ok_or("Missing GUI terminal")?,
            joined,
            samples,
            scan: saved.scan,
            attempt: saved.attempt,
            status: saved.status.clone(),
            report: self.report.ok_or("Missing GUI report")?,
            rows,
            displayed_rows: self
                .displayed
                .as_ref()
                .ok_or("Missing displayed results")?
                .len(),
            displayed_results: self.displayed.ok_or("Missing displayed results")?,
            sent: self.sent,
        };
        attempt.validate()?;
        let bytes = serde_json::to_vec(&attempt).map_err(|e| e.to_string())?;
        if bytes.len() > studio_protocol::single_target::acceptance::MAX_GUI_EVIDENCE {
            return Err("Oversized GUI evidence".into());
        }
        use std::io::Write;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.out.join("gui-attempt.json"))
            .map_err(|e| e.to_string())?;
        output.write_all(&bytes).map_err(|e| e.to_string())?;
        output.sync_all().map_err(|e| e.to_string())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn single_target_completion_can_display_zero_responses_without_inventing_results() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.set_process_status("Completed".into());
        assert!(terminal_view(&ui, 4, 4, 0).is_ok());
        assert!(terminal_view(&ui, 4, 4, 4).is_ok());
        assert!(terminal_view(&ui, 3, 4, 0).is_err());
        assert!(terminal_view(&ui, 4, 4, 5).is_err());
        ui.set_process_status("Scanning".into());
        assert!(terminal_view(&ui, 4, 4, 0).is_err());
    }
    #[test]
    fn visible_projection_reads_actual_rendered_ip_port_and_state() {
        let model = slint::VecModel::from(vec![ResultRow {
            ip: "45.33.32.156".into(),
            port: "443".into(),
            protocol: "TCP".into(),
            service: "Closed".into(),
            device: "TCP response".into(),
            ..Default::default()
        }]);
        assert_eq!(
            projection(&model).unwrap(),
            vec![studio_protocol::Row {
                ip: "45.33.32.156".into(),
                port: 443,
                open: false
            }]
        );
        let mut row = model.row_data(0).unwrap();
        row.service = "Unknown".into();
        model.set_row_data(0, row);
        assert!(projection(&model).is_err());
    }
    #[test]
    fn single_target_driver_cannot_mix_with_other_smoke_modes() {
        assert!(requested(&["--smoke-single-target".into()]).unwrap());
        assert!(!requested(&["--smoke".into()]).unwrap());
        assert!(requested(&["--smoke-single-target".into(), "--smoke".into()]).is_err());
        assert!(
            requested(&[
                "--smoke-single-target".into(),
                "--smoke-single-target".into()
            ])
            .is_err()
        );
    }
}
