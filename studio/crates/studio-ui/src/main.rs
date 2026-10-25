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
    table: RefCell<Table>,
    keys: RefCell<HashMap<(String, u16), u64>>,
    notify: ModelNotify,
    simulation: Cell<bool>,
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
    fn add(&self, rows: Vec<studio_protocol::Row>) {
        let mut changes = Vec::new();
        let mut keys = self.keys.borrow_mut();
        for r in rows {
            let Ok(ip) = r.ip.parse() else { continue };
            let key = (r.ip, r.port);
            let exists = keys.get(&key).copied();
            let id = exists.unwrap_or(keys.len() as u64);
            keys.insert(key, id);
            let row = studio_table::Row::observation(id, ip, r.port, r.open, self.simulation.get());
            changes.push(if exists.is_some() {
                Change::Update(row)
            } else {
                Change::Append(row)
            });
        }
        self.table.borrow_mut().apply(changes);
        self.notify.reset();
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
    ui.set_process_view(true);
    ui.set_job_seed(
        (u32::from_ne_bytes(studio_protocol::new_id()?[..4].try_into().unwrap()).max(1))
            .to_string()
            .into(),
    );
    let rows = Rc::new(Rows {
        table: RefCell::new(Table::new(0)),
        keys: RefCell::new(HashMap::new()),
        notify: ModelNotify::default(),
        simulation: Cell::new(false),
    });
    let history = Rc::new(RefCell::new(Vec::<studio_store::SavedScan>::new()));
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
            action(&a, &ui, Action::Lock);
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
    ui.on_row_action(move|mut row,kind|{if let Some(ui)=w.upgrade(){match kind.as_str(){"dns"|"nmap"=>row.evidence="Hostname and Nmap inspection are not connected yet. No lookup or scan was started.".into(),"http"|"https"=>row.evidence=format!("{}://{}:{}",kind,row.ip,row.port).into(),_=>{}}ui.set_inspector_details(row);ui.set_inspector_open(true);}});
    let timer = slint::Timer::default();
    let w = ui.as_weak();
    let a = app.clone();
    let m = rows.clone();
    let h = history.clone();
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
                    Update::Reset(data, backend) => {
                        m.simulation.set(backend == Backend::Simulation);
                        ui.set_scan_backend_label(
                            if backend == Backend::Simulation {
                                "Simulation · no packets"
                            } else {
                                "feth lab · raw packets"
                            }
                            .into(),
                        );
                        *m.table.borrow_mut() = Table::new(0);
                        m.keys.borrow_mut().clear();
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
                    Update::History(data) => {
                        ui.set_history_labels(ModelRc::new(slint::VecModel::from(
                            data.iter()
                                .map(|s| {
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
                        *h.borrow_mut() = data;
                    }
                    Update::State(status, detail) => {
                        eprintln!("Studio: {status:?}: {detail}");
                        ui.set_process_status(format!("{status:?}").into());
                        ui.set_action_notice(detail.into());
                        ui.set_process_active(!status.terminal());
                        ui.set_can_resume(status == Status::Paused);
                        if status.terminal() {
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
