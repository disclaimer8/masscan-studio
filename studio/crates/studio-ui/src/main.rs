use slint::{ComponentHandle, Model, ModelNotify, ModelRc, ModelTracker};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    path::PathBuf,
    rc::Rc,
    time::{Duration, Instant},
};
use studio_app::{Action, Controller, Update};
use studio_protocol::{Backend, Job, Status};
use studio_table::{Change, Table};
slint::include_modules!();

struct Rows {
    observations: RefCell<HashMap<(String, u16), studio_store::SavedRow>>,
    hosts: RefCell<HashMap<String, studio_inspection::HostInfo>>,
    table: RefCell<Table>,
    keys: RefCell<HashMap<(String, u16), u64>>,
    notify: ModelNotify,
    simulation: Cell<bool>,
    archived: Cell<bool>,
}
impl Model for Rows {
    type Data = ResultRow;
    fn row_count(&self) -> usize {
        self.table.borrow().view.len()
    }
    fn row_data(&self, index: usize) -> Option<ResultRow> {
        let t = self.table.borrow();
        let r = t.row(index)?;
        Some(ResultRow {
            ip: r.cells[0].clone().into(),
            hostname: r.cells[1].clone().into(),
            port: r.cells[2].clone().into(),
            protocol: r.cells[3].clone().into(),
            service: r.cells[4].clone().into(),
            device: r.cells[5].clone().into(),
            discovered: r.cells[6].clone().into(),
            evidence: r.evidence.clone().into(),
            chosen: t.selected.contains(&r.id),
        })
    }
    fn model_tracker(&self) -> &dyn ModelTracker {
        &self.notify
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
impl Rows {
    fn add(&self, rows: Vec<studio_store::SavedRow>) {
        let mut changes = Vec::new();
        let mut keys = self.keys.borrow_mut();
        for saved in rows {
            let r = &saved.row;
            let Ok(ip) = r.ip.parse() else { continue };
            let key = (r.ip.clone(), r.port);
            let exists = keys.get(&key).copied();
            let id = exists.unwrap_or(keys.len() as u64);
            keys.insert(key.clone(), id);
            let mut row =
                studio_table::Row::observation(id, ip, r.port, r.open, self.simulation.get());
            row.cells[6] = saved
                .discovered_at
                .clone()
                .unwrap_or_else(|| "Unknown (older history)".into());
            if let Some(info) = self.hosts.borrow().get(&r.ip) {
                row.cells[1] = if info.dns_state == studio_inspection::CheckState::Pending {
                    "Looking up…".into()
                } else {
                    info.hostname.clone().unwrap_or_else(|| {
                        match info.dns_state {
                            studio_inspection::CheckState::NotFound => "No hostname",
                            studio_inspection::CheckState::Failed => "Lookup failed",
                            _ => "Not resolved",
                        }
                        .into()
                    })
                };
                if let Some(legacy) = info.legacy.get(&r.port) {
                    row.cells[5] = legacy.device_hint.clone();
                }
                if let Some(service) = info.service(r.port) {
                    row.cells[4] = service.summary();
                    row.service = row.cells[4].clone();
                    if let Some(hint) = service.device_hint() {
                        row.cells[5] = hint;
                    }
                }
                row.evidence = format!(
                    "{}\n\n{}",
                    if self.simulation.get() {
                        "Simulation · no network evidence"
                    } else {
                        "Saved scan observation"
                    },
                    info.evidence(r.port)
                );
            }
            row.refresh_search();
            self.observations.borrow_mut().insert(key, saved);
            changes.push(if exists.is_some() {
                Change::Update(row)
            } else {
                Change::Append(row)
            });
        }
        self.table.borrow_mut().apply(changes);
        self.notify.reset();
    }
    fn enrich(&self, values: Vec<studio_inspection::HostInfo>) {
        let ips: std::collections::HashSet<_> = values.iter().map(|h| h.ip.clone()).collect();
        for h in values {
            self.hosts.borrow_mut().insert(h.ip.clone(), h);
        }
        let rows = self
            .observations
            .borrow()
            .values()
            .filter(|s| ips.contains(&s.row.ip))
            .cloned()
            .collect();
        self.add(rows);
    }
    fn export_rows(&self) -> Vec<studio_inspection::ExportRow> {
        let table = self.table.borrow();
        let hosts = self.hosts.borrow();
        let observations = self.observations.borrow();
        table
            .view
            .iter()
            .filter_map(|i| {
                let row = &table.rows[*i];
                let key = (row.cells[0].clone(), row.port);
                let saved = observations.get(&key)?;
                let host = hosts.get(&key.0);
                Some(studio_inspection::ExportRow {
                    ip: key.0.clone(),
                    port: row.port,
                    open: saved.row.open,
                    hostname: host.and_then(|h| h.hostname.clone()),
                    service: row.cells[4].clone(),
                    device_hint: row.cells[5].clone(),
                    discovered_at: saved.discovered_at.clone(),
                    source: if self.simulation.get() {
                        "Simulation"
                    } else if self.archived.get() {
                        "Archived history"
                    } else {
                        "rmasscan"
                    }
                    .into(),
                    inspection: host.and_then(|h| h.service(row.port)).cloned(),
                    inspection_checked_at: host
                        .and_then(|h| h.inspection.as_ref())
                        .map(|i| i.checked_at.clone()),
                })
            })
            .collect()
    }
    fn summary(&self, ui: &MainWindow) {
        let t = self.table.borrow();
        ui.set_summary(format!("{} of {} saved results", t.view.len(), t.rows.len()).into());
        ui.set_selection_count(t.selected.len() as i32);
        ui.set_selection_label(format!("{} selected", t.selected.len()).into());
        let active = t
            .focused
            .and_then(|id| t.view.iter().position(|&i| t.rows[i].id == id));
        ui.set_active_row(active.map(|i| i as i32).unwrap_or(-1));
        drop(t);
        if let Some(i) = active
            && let Some(r) = self.row_data(i)
        {
            ui.set_details(r);
        }
    }
}
fn draft(ui: &MainWindow) -> Result<Job, String> {
    Ok(Job {
        targets: ui.get_job_targets().to_string(),
        ports: ui.get_job_ports().to_string(),
        exclusions: ui.get_job_exclusions().to_string(),
        seed: ui.get_job_seed().to_string(),
        rate: ui
            .get_job_rate()
            .parse()
            .map_err(|_| "Rate must be an integer")?,
        backend: if ui.get_backend_index() == 1 {
            Backend::Simulation
        } else {
            Backend::MacFeth
        },
    })
}
fn data_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("STUDIO_DATA_DIR") {
        return p.into();
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("Library/Application Support/Masscan Studio Rust")
    }
    #[cfg(windows)]
    {
        PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default()).join("Masscan Studio")
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share")
            })
            .join("masscan-studio")
    }
}
fn action(app: &RefCell<Controller>, ui: &MainWindow, a: Action) {
    if let Err(e) = app.borrow().send(a) {
        ui.set_action_notice(e.into());
    }
}
fn process_active(status: &Status) -> bool {
    matches!(status, Status::Starting | Status::Scanning | Status::Saving)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let smoke = std::env::args().any(|s| s == "--smoke");
    let pause_smoke = std::env::args().any(|s| s == "--smoke-pause");
    let stop_smoke = std::env::args().any(|s| s == "--smoke-stop-race");
    if std::env::var_os("SLINT_BACKEND").is_none() {
        slint::BackendSelector::new()
            .backend_name("winit".into())
            .select()?;
    }
    let runner = std::env::current_exe()?
        .with_file_name(format!("studio-runner{}", std::env::consts::EXE_SUFFIX));
    let app = Rc::new(RefCell::new(Controller::open(data_dir(), runner)?));
    let ui = MainWindow::new()?;
    ui.set_authorization_available(cfg!(target_os = "macos"));
    ui.set_process_view(true);
    ui.set_job_seed(
        (u32::from_ne_bytes(studio_protocol::new_id()?[..4].try_into().unwrap()).max(1))
            .to_string()
            .into(),
    );
    let rows = Rc::new(Rows {
        observations: RefCell::new(HashMap::new()),
        hosts: RefCell::new(HashMap::new()),
        table: RefCell::new(Table::new(0)),
        keys: RefCell::new(HashMap::new()),
        notify: ModelNotify::default(),
        simulation: Cell::new(false),
        archived: Cell::new(false),
    });
    let history = Rc::new(RefCell::new(Vec::<studio_store::SavedScan>::new()));
    let profiles = Rc::new(RefCell::new(Vec::<studio_store::SavedProfile>::new()));
    ui.set_rows(ModelRc::from(rows.clone()));
    rows.summary(&ui);
    let w = ui.as_weak();
    ui.on_check_settings(move || {
        if let Some(ui) = w.upgrade() {
            match draft(&ui).and_then(|j| j.prepare()) {
                Ok(p) => {
                    ui.set_job_valid(true);
                    ui.set_job_preview(
                        format!(
                            "{} endpoints · wait 3 s · exact seed {}",
                            p.range(),
                            ui.get_job_seed()
                        )
                        .into(),
                    );
                    ui.set_job_feedback(
                        "Settings validated. Access is checked when the scan starts.".into(),
                    );
                }
                Err(e) => {
                    ui.set_job_valid(false);
                    ui.set_job_feedback(e.into());
                }
            }
        }
    });
    let w = ui.as_weak();
    ui.on_regenerate_seed(move || {
        if let Some(ui) = w.upgrade()
            && let Ok(id) = studio_protocol::new_id()
        {
            ui.set_job_seed(
                u32::from_ne_bytes(id[..4].try_into().unwrap())
                    .max(1)
                    .to_string()
                    .into(),
            );
            ui.invoke_settings_edited();
        }
    });
    let w = ui.as_weak();
    let a = app.clone();
    ui.on_run_process_test(move || {
        if let Some(ui) = w.upgrade() {
            match draft(&ui) {
                Ok(job) => {
                    action(&a, &ui, Action::Start(job));
                    ui.set_settings_open(false);
                }
                Err(e) => ui.set_job_feedback(e.into()),
            }
        }
    });
    let w = ui.as_weak();
    let a = app.clone();
    ui.on_pause_scan(move || {
        if let Some(ui) = w.upgrade() {
            action(&a, &ui, Action::Pause);
        }
    });
    let w = ui.as_weak();
    let a = app.clone();
    ui.on_stop_scan(move || {
        if let Some(ui) = w.upgrade() {
            match a.borrow().send(Action::Stop) {
                Ok(()) => ui.set_process_stopping(true),
                Err(e) => ui.set_action_notice(e.into()),
            }
        }
    });
    let w = ui.as_weak();
    let a = app.clone();
    ui.on_resume_scan(move || {
        if let Some(ui) = w.upgrade() {
            action(&a, &ui, Action::Resume);
        }
    });
    let w = ui.as_weak();
    let a = app.clone();
    ui.on_lock_session(move || {
        if let Some(ui) = w.upgrade() {
            let request = if ui.get_authorization_available()
                && !ui.get_authorized()
                && !ui.get_authorizing()
            {
                Action::Authorize
            } else {
                Action::Lock
            };
            action(&a, &ui, request);
        }
    });
    let w = ui.as_weak();
    let a = app.clone();
    let h = history.clone();
    ui.on_select_history(move |i| {
        if let (Some(ui), Some(s)) = (w.upgrade(), h.borrow().get(i as usize)) {
            action(&a, &ui, Action::Select(s.scan));
        }
    });
    let w = ui.as_weak();
    let p = profiles.clone();
    ui.on_load_profile(move |i| {
        if let (Some(ui), Some(profile)) = (w.upgrade(), p.borrow().get(i as usize)) {
            ui.set_job_targets(profile.job.targets.clone().into());
            ui.set_job_ports(profile.job.ports.clone().into());
            ui.set_job_exclusions(profile.job.exclusions.clone().into());
            ui.set_job_rate(profile.job.rate.to_string().into());
            ui.set_job_seed(profile.job.seed.clone().into());
            ui.set_backend_index(if profile.job.backend == Backend::Simulation {
                1
            } else {
                0
            });
            ui.set_profile_name(profile.name.clone().into());
            ui.set_profile_loaded(true);
            ui.set_confirm_profile_delete(false);
            ui.invoke_settings_edited();
            ui.set_profile_feedback(
                format!("Loaded {}. Check settings before starting.", profile.name).into(),
            );
        }
    });
    let w = ui.as_weak();
    let a = app.clone();
    let p = profiles.clone();
    ui.on_save_profile(move |update| {
        if let Some(ui) = w.upgrade() {
            if ui.get_profile_busy() {
                return;
            }
            let id = if update {
                if !ui.get_profile_loaded() {
                    return;
                }
                let profiles = p.borrow();
                let Some(profile) = profiles.get(ui.get_profile_index() as usize) else {
                    return;
                };
                Some(profile.id)
            } else {
                None
            };
            let result = draft(&ui).and_then(|job| {
                a.borrow().send(Action::SaveProfile {
                    id,
                    name: ui.get_profile_name().to_string(),
                    job,
                })
            });
            match result {
                Ok(()) => ui.set_profile_busy(true),
                Err(e) => ui.set_profile_feedback(e.into()),
            }
        }
    });
    let w = ui.as_weak();
    let a = app.clone();
    let p = profiles.clone();
    ui.on_delete_profile(move || {
        if let Some(ui) = w.upgrade() {
            if ui.get_profile_busy() {
                return;
            }
            if let Some(profile) = p.borrow().get(ui.get_profile_index() as usize) {
                match a.borrow().send(Action::DeleteProfile(profile.id)) {
                    Ok(()) => ui.set_profile_busy(true),
                    Err(e) => ui.set_profile_feedback(e.into()),
                }
            }
        }
    });
    let w = ui.as_weak();
    let m = rows.clone();
    ui.on_filter(move |s| {
        m.table.borrow_mut().filter(&s);
        m.notify.reset();
        if let Some(ui) = w.upgrade() {
            ui.set_filter_query(s);
            m.summary(&ui);
        }
    });
    let w = ui.as_weak();
    let m = rows.clone();
    ui.on_order(move |c, d| {
        m.table.borrow_mut().sort(c as usize, d);
        m.notify.reset();
        if let Some(ui) = w.upgrade() {
            m.summary(&ui);
        }
    });
    let w = ui.as_weak();
    let m = rows.clone();
    ui.on_choose(move |i, e, r| {
        m.table.borrow_mut().select_with_modifiers(i as usize, e, r);
        m.notify.reset();
        if let Some(ui) = w.upgrade() {
            m.summary(&ui);
        }
    });
    let w = ui.as_weak();
    let m = rows.clone();
    ui.on_navigate(move |d, r| {
        let n = m.table.borrow_mut().navigate(d, r);
        m.notify.reset();
        if let Some(ui) = w.upgrade() {
            m.summary(&ui);
        }
        n.map(|n| n as i32).unwrap_or(-1)
    });
    let w = ui.as_weak();
    let m = rows.clone();
    ui.on_select_visible(move || {
        m.table.borrow_mut().select_visible();
        m.notify.reset();
        if let Some(ui) = w.upgrade() {
            m.summary(&ui);
        }
    });
    let w = ui.as_weak();
    let m = rows.clone();
    ui.on_activate(move |i| {
        if let (Some(ui), Some(row)) = (w.upgrade(), m.row_data(i as usize)) {
            ui.set_inspector_details(row);
            ui.set_inspector_open(true);
        }
    });
    let w = ui.as_weak();
    let a = app.clone();
    ui.on_row_action(move |mut row, kind| {
        if let Some(ui) = w.upgrade() {
            match kind.as_str() {
                "dns" => action(
                    &a,
                    &ui,
                    Action::LookupHosts {
                        ips: vec![row.ip.to_string()],
                        refresh: true,
                    },
                ),
                "nmap" => action(&a, &ui, Action::InspectHost(row.ip.to_string())),
                "http" | "https" => {
                    if let (Ok(ip), Ok(port)) = (
                        row.ip.parse::<std::net::Ipv4Addr>(),
                        row.port.parse::<u16>(),
                    ) {
                        row.evidence =
                            format!("{}\n\nAddress: {}://{}:{}/", row.evidence, kind, ip, port)
                                .into();
                    }
                }
                _ => {}
            }
            ui.set_inspector_details(row);
            ui.set_inspector_open(true);
        }
    });
    let w = ui.as_weak();
    let a = app.clone();
    ui.on_cancel_inspection(move || {
        if let Some(ui) = w.upgrade() {
            action(&a, &ui, Action::CancelInspection);
        }
    });
    let w = ui.as_weak();
    let a = app.clone();
    let r = rows.clone();
    ui.on_resolve_names(move || {
        if let Some(ui) = w.upgrade() {
            let t = r.table.borrow();
            let ips: std::collections::BTreeSet<_> = t
                .view
                .iter()
                .map(|i| &t.rows[*i])
                .filter(|row| t.selected.is_empty() || t.selected.contains(&row.id))
                .map(|row| row.cells[0].clone())
                .collect();
            action(
                &a,
                &ui,
                Action::LookupHosts {
                    ips: ips.into_iter().collect(),
                    refresh: false,
                },
            );
        }
    });
    let w = ui.as_weak();
    let r = rows.clone();
    ui.on_export_rows(move |format| {
        if let Some(ui) = w.upgrade() {
            if ui.get_exporting() {
                return;
            }
            let snapshot = r.export_rows();
            if snapshot.is_empty() {
                ui.set_action_notice("No visible rows to export".into());
                return;
            }
            let json = format == "json";
            ui.set_exporting(true);
            let dialog = rfd::AsyncFileDialog::new()
                .set_file_name(if json {
                    "masscan-results.json"
                } else {
                    "masscan-results.csv"
                })
                .add_filter(
                    if json { "JSON" } else { "CSV" },
                    &[if json { "json" } else { "csv" }],
                )
                .save_file();
            let w = w.clone();
            std::thread::spawn(move || {
                let result = if let Some(file) = pollster::block_on(dialog) {
                    studio_inspection::write_export(file.path(), &snapshot, json)
                        .map(|_| format!("Exported {} visible rows", snapshot.len()))
                } else {
                    Ok("Export cancelled".into())
                };
                let _ = w.upgrade_in_event_loop(move |ui| {
                    ui.set_exporting(false);
                    ui.set_action_notice(
                        result
                            .unwrap_or_else(|e| format!("Export failed: {e}"))
                            .into(),
                    );
                });
            });
        }
    });
    let timer = slint::Timer::default();
    let w = ui.as_weak();
    let a = app.clone();
    let m = rows.clone();
    let h = history.clone();
    let p = profiles.clone();
    let started = Instant::now();
    let success = Rc::new(Cell::new(false));
    let ok = success.clone();
    let phase = Rc::new(Cell::new(0));
    let phase2 = phase.clone();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(50),
        move || {
            let Some(ui) = w.upgrade() else { return };
            let updates = a.borrow_mut().poll();
            if stop_smoke
                && phase2.get() == 0
                && updates
                    .iter()
                    .any(|u| matches!(u, Update::State(Status::Scanning, _)))
            {
                // A Stop click concurrent with an already queued Started event.
                phase2.set(1);
                ui.invoke_stop_scan();
            }
            for update in updates {
                match update {
                    Update::ProfileResult(result) => {
                        ui.set_profile_busy(false);
                        ui.set_confirm_profile_delete(false);
                        ui.set_profile_feedback(
                            result
                                .unwrap_or_else(|e| format!("Profile change failed: {e}"))
                                .into(),
                        );
                    }
                    Update::Profiles(values, selected) => {
                        ui.set_profile_labels(ModelRc::new(slint::VecModel::from(
                            values
                                .iter()
                                .map(|p| slint::SharedString::from(p.name.as_str()))
                                .collect::<Vec<_>>(),
                        )));
                        ui.set_profile_index(
                            values
                                .iter()
                                .position(|p| Some(p.id) == selected)
                                .map(|i| i as i32)
                                .unwrap_or(-1),
                        );
                        ui.set_profile_loaded(selected.is_some());
                        *p.borrow_mut() = values;
                    }
                    Update::Reset(data, backend) => {
                        ui.set_inspection_available(backend != Backend::Simulation);
                        m.simulation.set(backend == Backend::Simulation);
                        m.archived.set(backend == Backend::Archived);
                        ui.set_scan_backend_label(
                            if backend == Backend::Simulation {
                                "Simulation · no packets"
                            } else if backend == Backend::Archived {
                                "Archived history"
                            } else {
                                "feth lab · raw packets"
                            }
                            .into(),
                        );
                        *m.table.borrow_mut() = Table::new(0);
                        m.keys.borrow_mut().clear();
                        m.observations.borrow_mut().clear();
                        m.hosts.borrow_mut().clear();
                        m.add(data);
                        ui.set_filter_query("".into());
                        ui.set_sort_column(-1);
                        ui.set_sort_descending(false);
                        ui.set_event_label("".into());
                        ui.set_details(ResultRow::default());
                        ui.set_inspector_details(ResultRow::default());
                        ui.set_inspector_open(false);
                    }
                    Update::Rows(data) => m.add(data),
                    Update::Hosts(values) => {
                        m.enrich(values);
                        if ui.get_inspector_open() {
                            let previous = ui.get_inspector_details();
                            let table = m.table.borrow();
                            if let Some(row) = table.rows.iter().find(|r| {
                                r.cells[0] == previous.ip.as_str()
                                    && r.cells[2] == previous.port.as_str()
                            }) {
                                ui.set_inspector_details(ResultRow {
                                    ip: row.cells[0].clone().into(),
                                    hostname: row.cells[1].clone().into(),
                                    port: row.cells[2].clone().into(),
                                    protocol: row.cells[3].clone().into(),
                                    service: row.cells[4].clone().into(),
                                    device: row.cells[5].clone().into(),
                                    discovered: row.cells[6].clone().into(),
                                    evidence: row.evidence.clone().into(),
                                    chosen: table.selected.contains(&row.id),
                                });
                            }
                        }
                    }
                    Update::Progress(sent, received) => ui.set_event_label(
                        format!(
                            "{} · sent {sent} · received {received} · saved to history",
                            if m.simulation.get() {
                                "Simulation"
                            } else {
                                "feth scan"
                            }
                        )
                        .into(),
                    ),
                    Update::Notice(text) => ui.set_action_notice(text.into()),
                    Update::History(data, selected) => {
                        ui.set_history_labels(ModelRc::new(slint::VecModel::from(
                            data.iter()
                                .map(|s| {
                                    if s.job.backend == Backend::Archived {
                                        return slint::SharedString::from(format!(
                                            "{} · {:?} · {}",
                                            s.name.as_deref().unwrap_or("Archived history"),
                                            s.status,
                                            s.created_at.as_deref().unwrap_or("Unknown date")
                                        ));
                                    }
                                    slint::SharedString::from(format!(
                                        "{} · {:?} · {}",
                                        if s.job.backend == Backend::Simulation {
                                            "Simulation"
                                        } else {
                                            "feth"
                                        },
                                        s.status,
                                        s.job.ports
                                    ))
                                })
                                .collect::<Vec<_>>(),
                        )));
                        ui.set_history_index(
                            data.iter()
                                .position(|s| Some(s.scan) == selected)
                                .map(|i| i as i32)
                                .unwrap_or(-1),
                        );
                        *h.borrow_mut() = data;
                    }
                    Update::Authorization {
                        busy,
                        authorized,
                        detail,
                    } => {
                        ui.set_authorizing(busy);
                        ui.set_authorized(authorized);
                        ui.set_process_active(busy);
                        ui.set_process_stopping(false);
                        ui.set_process_status(if busy { "Authorizing" } else { "Ready" }.into());
                        ui.set_action_notice(detail.into());
                    }
                    Update::State(status, detail) => {
                        eprintln!("Studio: {status:?}: {detail}");
                        ui.set_process_status(format!("{status:?}").into());
                        ui.set_action_notice(detail.into());
                        ui.set_process_active(process_active(&status));
                        ui.set_can_resume(status == Status::Paused && !m.archived.get());
                        if !process_active(&status) {
                            ui.set_process_stopping(false);
                        }
                        if pause_smoke {
                            if status == Status::Scanning && phase2.get() == 0 {
                                phase2.set(1);
                                action(&a, &ui, Action::Pause);
                            } else if status == Status::Paused && phase2.get() == 1 {
                                phase2.set(2);
                                action(&a, &ui, Action::Resume);
                            } else if status == Status::Scanning && phase2.get() == 2 {
                                phase2.set(3);
                                ui.invoke_stop_scan();
                            } else if status == Status::Stopped && phase2.get() == 3 {
                                ok.set(true);
                            }
                        }
                        if smoke && status == Status::Completed {
                            ok.set(true);
                        }
                        if stop_smoke && status == Status::Stopped {
                            ok.set(true);
                        }
                    }
                }
            }
            m.summary(&ui);
            if (smoke || pause_smoke || stop_smoke)
                && (ok.get() || started.elapsed() > Duration::from_secs(25))
            {
                if let Some(p) = std::env::var_os("STUDIO_SCREENSHOT")
                    && let Ok(pixels) = ui.window().take_snapshot()
                {
                    let _ = image::save_buffer(
                        p,
                        pixels.as_bytes(),
                        pixels.width(),
                        pixels.height(),
                        image::ColorType::Rgba8,
                    );
                }
                let _ = slint::quit_event_loop();
            }
        },
    );
    if smoke || pause_smoke || stop_smoke {
        ui.set_backend_index(1);
        let mut job = Job::example(Backend::Simulation);
        if pause_smoke {
            job.rate = 4;
            job.ports = "8000-8031".into();
        }
        app.borrow().send(Action::Start(job))?;
    }
    ui.run()?;
    timer.stop();
    if (smoke || pause_smoke || stop_smoke) && !success.get() {
        return Err("UI smoke did not complete the expected lifecycle".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn archived_ready_history_does_not_lock_the_ui_as_an_active_scan() {
        assert!(!process_active(&Status::Ready));
        for status in [Status::Starting, Status::Scanning, Status::Saving] {
            assert!(process_active(&status));
        }
    }
    #[test]
    fn export_uses_filtered_sorted_view_and_never_leaks_hidden_port_details() {
        let rows = Rows {
            observations: RefCell::new(HashMap::new()),
            hosts: RefCell::new(HashMap::new()),
            table: RefCell::new(Table::new(0)),
            keys: RefCell::new(HashMap::new()),
            notify: ModelNotify::default(),
            simulation: Cell::new(false),
            archived: Cell::new(false),
        };
        rows.add(
            [("198.18.0.2", 80), ("198.18.0.2", 443), ("198.18.0.10", 80)]
                .into_iter()
                .map(|(ip, port)| studio_store::SavedRow {
                    row: studio_protocol::Row {
                        ip: ip.into(),
                        port,
                        open: true,
                    },
                    discovered_at: None,
                })
                .collect(),
        );
        let mut h = studio_inspection::HostInfo::new("198.18.0.2".into());
        h.hostname = Some("fixture.local".into());
        h.inspection = Some(studio_inspection::Inspection {
            ip: h.ip.clone(),
            ports: vec![80, 443],
            checked_at: "2026-10-26T00:00:00Z".into(),
            services: vec![
                studio_inspection::Service {
                    port: 80,
                    name: "http".into(),
                    ..Default::default()
                },
                studio_inspection::Service {
                    port: 443,
                    name: "secret-hidden-port".into(),
                    ..Default::default()
                },
            ],
        });
        rows.enrich(vec![h]);
        rows.table.borrow_mut().filter("80");
        rows.table.borrow_mut().sort(0, true);
        let snapshot = rows.export_rows();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].ip, "198.18.0.10");
        assert_eq!(snapshot[1].hostname, Some("fixture.local".into()));
        let json = studio_inspection::json(&snapshot).unwrap();
        assert!(!json.contains("secret-hidden-port"));
        assert!(!json.contains("443"));
        assert!(snapshot.iter().all(|r| r.discovered_at.is_none()));
    }
}
