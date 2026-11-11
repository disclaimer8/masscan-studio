//! Packet-free acceptance of a private copy of saved native results.
use super::*;

fn check_loaded(
    status: &str,
    expected: &Status,
    visible: usize,
    saved: usize,
    coverage_scan: Option<&str>,
    scan: studio_protocol::Id,
) -> Result<(), String> {
    if status != format!("{expected:?}")
        || saved == 0
        || visible != saved
        || coverage_scan != Some(studio_protocol::id_text(scan).as_str())
    {
        return Err(format!(
            "History not restored: status={status}, rows={visible}/{saved}, coverage={coverage_scan:?}"
        ));
    }
    Ok(())
}

pub struct Driver {
    output: PathBuf,
    saved: studio_store::SavedScan,
    observations: Vec<studio_store::SavedRow>,
    phase: u8,
    resets: usize,
    started: Instant,
    events: Vec<serde_json::Value>,
}
impl Driver {
    pub fn prepare(args: &[String]) -> Result<Option<Self>, String> {
        if !args.iter().any(|s| s == "--smoke-history") {
            return Ok(None);
        }
        if args.iter().filter(|s| s.starts_with("--smoke")).count() != 1 {
            return Err("Choose exactly one smoke mode".into());
        }
        let data = std::env::var_os("STUDIO_DATA_DIR")
            .map(PathBuf::from)
            .ok_or("History acceptance requires STUDIO_DATA_DIR pointing to a private copy")?;
        let output = std::env::var_os("STUDIO_SMOKE_OUT")
            .map(PathBuf::from)
            .ok_or("History acceptance requires STUDIO_SMOKE_OUT")?;
        if !data.is_absolute() || !output.is_absolute() || !data.join("history.sqlite3").is_file() {
            return Err(
                "History acceptance requires absolute paths and an existing copied database".into(),
            );
        }
        check_smoke_out(&output)?;
        if std::fs::read_dir(&output)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
        {
            return Err("History acceptance output must be empty".into());
        }
        let db = studio_store::Store::open(&data).map_err(|e| e.to_string())?;
        let scans = db.scans().map_err(|e| e.to_string())?;
        if scans.len() != 1
            || scans[0].job.backend != Backend::MacNetwork
            || !matches!(scans[0].status, Status::Completed | Status::Stopped)
            || scans[0].network_report.is_none()
        {
            return Err("History acceptance requires one completed or stopped Mac network scan with coverage".into());
        }
        let saved = scans.into_iter().next().unwrap();
        let observations = db.observations(saved.scan).map_err(|e| e.to_string())?;
        if observations.is_empty() {
            return Err("History acceptance requires retained results".into());
        }
        Ok(Some(Self {
            output,
            saved,
            observations,
            phase: 0,
            resets: 0,
            started: Instant::now(),
            events: vec![],
        }))
    }
    pub fn observe(&mut self, updates: &[Update]) {
        self.resets += updates
            .iter()
            .filter(|u| matches!(u, Update::Reset(..)))
            .count();
    }
    fn snapshot(&self, ui: &MainWindow, name: &str) -> Result<(), String> {
        let p = ui.window().take_snapshot().map_err(|e| e.to_string())?;
        image::save_buffer(
            self.output.join(format!("{name}.png")),
            p.as_bytes(),
            p.width(),
            p.height(),
            image::ColorType::Rgba8,
        )
        .map_err(|e| e.to_string())
    }
    fn loaded(
        &self,
        ui: &MainWindow,
        rows: &Rows,
        coverage: Option<&studio_inspection::ExportCoverage>,
    ) -> Result<(), String> {
        check_loaded(
            ui.get_process_status().as_str(),
            &self.saved.status,
            rows.row_count(),
            self.observations.len(),
            coverage.map(|v| v.scan_id.as_str()),
            self.saved.scan,
        )?;
        let expected: std::collections::BTreeSet<_> = self
            .observations
            .iter()
            .map(|r| {
                (
                    r.row.ip.clone(),
                    r.row.port,
                    r.row.open,
                    r.discovered_at.clone(),
                )
            })
            .collect();
        let actual: std::collections::BTreeSet<_> = rows
            .export_rows()
            .into_iter()
            .map(|r| (r.ip, r.port, r.open, r.discovered_at))
            .collect();
        if actual != expected {
            return Err("Displayed history differs from durable observations".into());
        }
        Ok(())
    }
    fn export(
        &mut self,
        rows: &Rows,
        coverage: Option<&studio_inspection::ExportCoverage>,
        name: &str,
    ) -> Result<(), String> {
        let coverage = coverage.ok_or("History lost whole-scan coverage")?;
        let snapshot = rows.export_rows();
        // Same visible-row projection and atomic writer as the Export callback.
        // Native save dialogs and async completion are deliberately outside this driver.
        for (extension, json) in [("json", true), ("csv", false)] {
            studio_inspection::write_export_with_coverage(
                &self.output.join(format!("{name}.{extension}")),
                &snapshot,
                Some(coverage),
                json,
            )?;
        }
        self.events
            .push(serde_json::json!({"event":name,"rows":snapshot.len(),"scan":coverage.scan_id}));
        Ok(())
    }
    pub fn tick(
        &mut self,
        ui: &MainWindow,
        rows: &Rows,
        history: &[studio_store::SavedScan],
        coverage: Option<&studio_inspection::ExportCoverage>,
    ) -> Result<bool, String> {
        if self.started.elapsed() > Duration::from_secs(30) {
            return Err(format!(
                "History acceptance timed out at phase {}",
                self.phase
            ));
        }
        if ui.get_process_active() || ui.get_authorized() || ui.get_authorizing() {
            return Err(
                "History acceptance unexpectedly activated a scan or helper session".into(),
            );
        }
        if history.is_empty() {
            return Ok(false);
        }
        if history.len() != 1
            || history[0].scan != self.saved.scan
            || history[0].attempt != self.saved.attempt
            || history[0].job != self.saved.job
            || history[0].status != self.saved.status
        {
            return Err("Read-only history actions changed the saved scan".into());
        }
        match self.phase {
            0 => {
                self.loaded(ui, rows, coverage)?;
                self.export(rows, coverage, "all")?;
                self.snapshot(ui, "restored")?;
                ui.invoke_manage_history();
                if !ui.get_history_open() || !ui.get_history_can_repeat() {
                    return Err("Saved History controls did not open".into());
                }
                self.phase = 1;
            }
            1 => {
                self.snapshot(ui, "history")?;
                // Prove Repeat fills all fields, rather than accepting unchanged settings.
                fill_settings(ui, &Job::example(Backend::Simulation));
                ui.invoke_repeat_history();
                if draft(ui)? != self.saved.job || !ui.get_settings_open() || ui.get_history_open()
                {
                    return Err("Repeat did not restore the exact saved settings".into());
                }
                self.phase = 2;
            }
            2 => {
                self.snapshot(ui, "repeated-settings")?;
                self.events
                    .push(serde_json::json!({"event":"repeat","job":draft(ui)?}));
                ui.set_settings_open(false);
                let ip = &self.observations[0].row.ip;
                ui.invoke_filter(ip.clone().into());
                ui.set_sort_column(2);
                ui.set_sort_descending(true);
                ui.invoke_order(2, true);
                let expected = self.observations.iter().filter(|r| r.row.ip == *ip).count();
                let filtered = rows.export_rows();
                if filtered.len() != expected
                    || filtered.iter().any(|r| r.ip != *ip)
                    || filtered.windows(2).any(|pair| pair[0].port < pair[1].port)
                {
                    return Err("History filter or descending port order is incorrect".into());
                }
                self.export(rows, coverage, "filtered")?;
                self.phase = 3;
            }
            3 => {
                self.snapshot(ui, "filtered")?;
                ui.invoke_filter("no-such-history-result".into());
                if rows.row_count() != 0 {
                    return Err("Empty filter retained results".into());
                }
                self.export(rows, coverage, "empty")?;
                self.resets = 0;
                ui.invoke_select_history(0);
                self.phase = 4;
            }
            4 if self.resets > 0 => {
                self.loaded(ui, rows, coverage)?;
                if !ui.get_filter_query().is_empty()
                    || ui.get_sort_column() != -1
                    || ui.get_sort_descending()
                {
                    return Err("History reload did not clear view filters".into());
                }
                self.export(rows, coverage, "reselected")?;
                self.snapshot(ui, "reselected")?;
                return Ok(true);
            }
            _ => {}
        }
        Ok(false)
    }
    pub fn finish(&self, result: &Result<bool, String>) -> Result<(), String> {
        let report = serde_json::json!({"schema":1,"ok":matches!(result, Ok(true)),
            "error":result.as_ref().err(),"phase":self.phase,"events":self.events,
            "scope":"history callbacks, rendered model, shared visible-row export writer; no scan or native save dialog"});
        std::fs::write(
            self.output.join("history.json"),
            serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_acceptance_rejects_missing_rows_status_and_other_scan_coverage() {
        let scan = [1; 16];
        let id = studio_protocol::id_text(scan);
        assert!(check_loaded("Completed", &Status::Completed, 96, 96, Some(&id), scan).is_ok());
        for (status, visible, coverage) in [
            ("Ready", 96, Some(id.as_str())),
            ("Completed", 0, Some(id.as_str())),
            ("Completed", 95, Some(id.as_str())),
            ("Completed", 96, None),
            ("Completed", 96, Some("02020202020202020202020202020202")),
        ] {
            assert!(check_loaded(status, &Status::Completed, visible, 96, coverage, scan).is_err());
        }
        assert!(check_loaded("Completed", &Status::Completed, 0, 0, Some(&id), scan).is_err());
    }
}
