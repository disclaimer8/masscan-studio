//! Packet-free GUI acceptance for an already running work session.
use super::*;

pub fn validate(
    args: &[String],
    data: Option<PathBuf>,
    output: Option<PathBuf>,
    mac: bool,
) -> Result<Option<PathBuf>, String> {
    if !args.iter().any(|a| a == "--smoke-work-session") {
        return Ok(None);
    }
    if !mac || data.is_none() || output.is_none() {
        return Err(
            "--smoke-work-session requires macOS, STUDIO_DATA_DIR and STUDIO_SMOKE_OUT".into(),
        );
    }
    if args.iter().filter(|a| a.starts_with("--smoke")).count() != 1 {
        return Err("Choose exactly one smoke mode".into());
    }
    if !data.as_ref().unwrap().is_absolute() || !output.as_ref().unwrap().is_absolute() {
        return Err("Session smoke directories must be absolute".into());
    }
    Ok(output)
}

pub struct Driver {
    phase: u8,
    started: Instant,
    output: PathBuf,
    events: Vec<serde_json::Value>,
    failure: Option<String>,
}
impl Driver {
    pub fn new(output: PathBuf) -> Self {
        Self {
            phase: 0,
            started: Instant::now(),
            output,
            events: vec![],
            failure: None,
        }
    }
    pub fn observe(&mut self, updates: &[Update]) {
        for update in updates {
            match update {
                Update::Authorization {
                    busy,
                    authorized,
                    detail,
                } => {
                    self.events.push(serde_json::json!({"event":"authorization", "busy":busy, "authorized":authorized, "detail":detail}));
                    if matches!(self.phase, 1 | 3) && !busy && !authorized {
                        self.failure = Some(detail.clone());
                    }
                }
                Update::State(status, detail) => {
                    self.events.push(
                        serde_json::json!({"event":"state", "status":status, "detail":detail}),
                    );
                    if matches!(status, Status::Failed | Status::Interrupted) {
                        self.failure = Some(detail.clone());
                    }
                }
                _ => {}
            }
        }
    }
    fn snapshot(&self, ui: &MainWindow, name: &str) -> Result<(), String> {
        let pixels = ui.window().take_snapshot().map_err(|e| e.to_string())?;
        image::save_buffer(
            self.output.join(format!("{name}.png")),
            pixels.as_bytes(),
            pixels.width(),
            pixels.height(),
            image::ColorType::Rgba8,
        )
        .map_err(|e| e.to_string())
    }
    fn record(&mut self, ui: &MainWindow, name: &str, rows: usize) -> Result<(), String> {
        self.events.push(serde_json::json!({"event":name, "rows":rows, "status":ui.get_process_status().as_str(), "authorized":ui.get_authorized(), "elapsed_ms":self.started.elapsed().as_millis()}));
        self.snapshot(ui, name)
    }
    fn start(ui: &MainWindow, slow: bool) -> Result<(), String> {
        let mut job = Job::example(Backend::Simulation);
        if slow {
            job.rate = 4;
            job.ports = "8000-8015".into();
        }
        fill_settings(ui, &job);
        if draft(ui)? != job {
            return Err("Settings did not preserve the simulation job".into());
        }
        ui.invoke_settings_edited();
        ui.invoke_check_settings();
        if !ui.get_can_start() {
            return Err("Start is disabled after checking the simulation settings".into());
        }
        ui.invoke_run_process_test();
        Ok(())
    }
    pub fn tick(
        &mut self,
        ui: &MainWindow,
        rows: usize,
        history: &[studio_store::SavedScan],
    ) -> Result<bool, String> {
        if let Some(e) = &self.failure {
            return Err(e.clone());
        }
        if self.started.elapsed() > Duration::from_secs(90) {
            return Err(format!("Session smoke timed out at phase {}", self.phase));
        }
        match self.phase {
            0 => {
                if !history.is_empty() {
                    return Err("Session smoke requires an empty acceptance history".into());
                }
                fill_settings(ui, &Job::example(Backend::MacFeth));
                require_host()?;
                ui.invoke_lock_session();
                self.phase = 1;
            }
            1 | 3 if ui.get_authorized() && !ui.get_authorizing() => {
                self.record(
                    ui,
                    if self.phase == 1 {
                        "authorized-first"
                    } else {
                        "authorized-again"
                    },
                    rows,
                )?;
                ui.invoke_lock_session();
                self.phase += 1;
            }
            2 if !ui.get_authorized() && !ui.get_authorizing() => {
                require_host()?;
                ui.invoke_lock_session();
                self.phase = 3;
            }
            4 if !ui.get_authorized() && !ui.get_authorizing() => {
                Self::start(ui, false)?;
                self.phase = 5;
            }
            5 if ui.get_process_status() == "Completed" && history.len() == 1 => {
                if rows != 8 {
                    return Err(format!("First simulation retained {rows} rows, expected 8"));
                }
                self.record(ui, "completed-first", rows)?;
                Self::start(ui, true)?;
                self.phase = 6;
            }
            6 if ui.get_process_status() == "Scanning" && rows > 0 => {
                if !ui.get_can_stop() {
                    return Err("Stop is disabled during the simulation".into());
                }
                ui.invoke_stop_scan();
                self.phase = 7;
            }
            7 if ui.get_process_status() == "Stopped" && history.len() == 2 => {
                if rows == 0 {
                    return Err("Stop lost the displayed results".into());
                }
                self.record(ui, "stopped", rows)?;
                // Start again through the unchanged form, as the ordinary Start button does.
                if !ui.get_can_start() {
                    return Err("Start remains disabled after Stop".into());
                }
                ui.invoke_run_process_test();
                self.phase = 8;
            }
            8 if ui.get_process_status() == "Scanning" => self.phase = 9,
            9 if ui.get_process_status() == "Completed" && history.len() == 3 => {
                if rows != 16
                    || history
                        .iter()
                        .filter(|s| s.status == Status::Completed)
                        .count()
                        != 2
                    || history
                        .iter()
                        .filter(|s| s.status == Status::Stopped)
                        .count()
                        != 1
                {
                    return Err("Repeat did not preserve all three scan outcomes".into());
                }
                self.record(ui, "completed-again", rows)?;
                return Ok(true);
            }
            _ => {}
        }
        Ok(false)
    }
    pub fn finish(&self, result: &Result<bool, String>) -> Result<(), String> {
        std::fs::write(self.output.join("session.json"), serde_json::to_vec_pretty(&serde_json::json!({"schema":1,"ok":matches!(result,Ok(true)),"error":result.as_ref().err(),"phase":self.phase,"events":self.events})).map_err(|e|e.to_string())?).map_err(|e| e.to_string())
    }
}

fn require_host() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        studio_platform::work_session::connect()?
            .ok_or("No retained work session; this smoke will not start one")?;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    Err("Work sessions require macOS".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsafe_session_smoke_launches_before_opening_history() {
        let args = vec!["studio-ui".into(), "--smoke-work-session".into()];
        let path = Some(std::env::current_dir().unwrap().join("session-test"));
        assert!(validate(&args, None, path.clone(), true).is_err());
        assert!(validate(&args, path.clone(), None, true).is_err());
        assert!(validate(&args, path.clone(), path.clone(), false).is_err());
        let mut mixed = args.clone();
        mixed.push("--smoke".into());
        assert!(validate(&mixed, path.clone(), path.clone(), true).is_err());
        assert_eq!(
            validate(&args, path.clone(), path.clone(), true).unwrap(),
            path
        );
        assert!(validate(&[], None, None, false).unwrap().is_none());
    }
}
