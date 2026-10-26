//! Application controller.
#![forbid(unsafe_code)]
mod hosts;
mod persistence;
use std::{
    io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
    process::{Child, Command as Process, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};
use studio_protocol::*;
use studio_store::{SavedRow, SavedScan, Store};

pub enum Action {
    LookupHosts { ips: Vec<String>, refresh: bool },
    InspectHost(String),
    CancelInspection,
    Authorize,
    Start(Job),
    Pause,
    Stop,
    Resume,
    Select(Id),
    Lock,
}
pub enum Update {
    Authorization {
        busy: bool,
        authorized: bool,
        detail: String,
    },
    Reset(Vec<SavedRow>, Backend),
    Rows(Vec<SavedRow>),
    Hosts(Vec<studio_inspection::HostInfo>),
    State(Status, String),
    Progress(String, String),
    History(Vec<SavedScan>, Option<Id>),
    Notice(String),
}
pub struct Controller {
    commands: mpsc::SyncSender<Action>,
    updates: mpsc::Receiver<Update>,
    stop: Arc<AtomicBool>,
    cancel_auth: Arc<AtomicBool>,
    error: Arc<Mutex<Option<String>>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Controller {
    pub fn open(dir: PathBuf, runner: PathBuf) -> Result<Self, String> {
        let store = Store::open(&dir).map_err(|e| e.to_string())?;
        let (commands, rx) = mpsc::sync_channel(8);
        let (out, updates) = mpsc::sync_channel(32);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let cancel_auth = Arc::new(AtomicBool::new(false));
        let cancel = cancel_auth.clone();
        let error = Arc::new(Mutex::new(None));
        let errors = error.clone();
        let worker = thread::spawn(move || {
            if let Err(e) = work(store, runner, rx, out, flag, cancel) {
                *errors.lock().unwrap() = Some(e);
            }
        });
        Ok(Self {
            commands,
            updates,
            stop,
            cancel_auth,
            error,
            worker: Some(worker),
        })
    }
    pub fn send(&self, a: Action) -> Result<(), String> {
        if matches!(a, Action::Authorize) {
            self.cancel_auth.store(false, Ordering::Release);
        }
        // Interrupt a pending OS prompt without waiting for the worker queue.
        if matches!(a, Action::Stop | Action::Lock) {
            self.cancel_auth.store(true, Ordering::Release);
        }
        self.commands
            .try_send(a)
            .map_err(|_| "Application command queue is busy or closed".into())
    }
    pub fn poll(&mut self) -> Vec<Update> {
        let mut out: Vec<_> = self.updates.try_iter().collect();
        if let Some(e) = self.error.lock().unwrap().take() {
            out.push(Update::State(Status::Interrupted, e));
        }
        out
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.cancel_auth.store(true, Ordering::Release);
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

struct Client {
    child: Option<Child>,
    #[cfg(target_os = "macos")]
    authorized: Option<studio_platform::macos::Authorized>,
    input: Option<BufWriter<Box<dyn Write + Send>>>,
    events: mpsc::Receiver<Result<Envelope<Event>, String>>,
    session: Id,
    scan: Id,
    attempt: Id,
    sequence: u64,
    order: ReceiveOrder,
    pending: persistence::Pending,
    deferred: Option<Envelope<Event>>,
}
impl Client {
    fn open(path: &PathBuf) -> Result<Self, String> {
        let mut child = Process::new(path)
            .arg("--stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("Cannot start Studio runner: {e}"))?;
        let input = child.stdin.take().ok_or("Runner stdin missing")?;
        let stdout = child.stdout.take().ok_or("Runner stdout missing")?;
        let mut c = Self::connected(Box::new(input), Box::new(stdout))?;
        c.child = Some(child);
        c.handshake(None)?;
        Ok(c)
    }
    #[cfg(target_os = "macos")]
    fn authorize(source: &std::path::Path, cancelled: &AtomicBool) -> Result<Self, String> {
        let hash = studio_platform::trusted::file_hash(source)?;
        let path = studio_platform::macos::installed_path(&hash)?;
        let auth =
            studio_platform::macos::Authorized::open(&path, &hash, cancelled).map_err(|e| {
                format!("{e}. Install this build's runner with cargo xtask prepare-runner first.")
            })?;
        let input = auth.stream.try_clone().map_err(|e| e.to_string())?;
        let output = auth.stream.try_clone().map_err(|e| e.to_string())?;
        let mut c = Self::connected(Box::new(input), Box::new(output))?;
        c.authorized = Some(auth);
        c.handshake(Some(cancelled))?;
        Ok(c)
    }
    #[cfg(not(target_os = "macos"))]
    fn authorize(_: &std::path::Path, _: &AtomicBool) -> Result<Self, String> {
        Err(
            "System authorization is currently implemented only on macOS; simulation is available"
                .into(),
        )
    }
    fn is_authorized(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.authorized.is_some()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }
    fn connected(
        input: Box<dyn Write + Send>,
        stdout: Box<dyn Read + Send>,
    ) -> Result<Self, String> {
        let session = new_id()?;
        let (tx, events) = mpsc::sync_channel(32);
        thread::spawn(move || {
            let mut out = BufReader::new(stdout);
            loop {
                let e = read_frame::<Event>(&mut out)
                    .map_err(|e| format!("Runner connection closed: {e}"));
                let done = e.is_err();
                if tx.send(e).is_err() || done {
                    break;
                }
            }
        });
        Ok(Self {
            child: None,
            #[cfg(target_os = "macos")]
            authorized: None,
            input: Some(BufWriter::new(input)),
            events,
            session,
            scan: [0; 16],
            attempt: [0; 16],
            sequence: 0,
            order: ReceiveOrder::new(session, [0; 16], [0; 16]),
            pending: persistence::Pending::default(),
            deferred: None,
        })
    }
    fn poll_batch(&mut self) -> Result<Vec<Envelope<Event>>, String> {
        while !self.pending.ready(Instant::now()) {
            let event = match self.deferred.take() {
                Some(e) => Some(e),
                None => self.poll()?,
            };
            let Some(event) = event else { break };
            if !self.pending.can_fit(&event) {
                self.deferred = Some(event);
                return Ok(self.pending.take());
            }
            self.pending.push(event, Instant::now());
        }
        Ok(if self.pending.ready(Instant::now()) {
            self.pending.take()
        } else {
            Vec::new()
        })
    }
    fn handshake(&mut self, cancelled: Option<&AtomicBool>) -> Result<(), String> {
        self.send(Command::Hello)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let hello = loop {
            if cancelled.is_some_and(|c| c.load(Ordering::Acquire)) {
                return Err("Authorization cancelled during handshake".into());
            }
            match self.events.recv_timeout(Duration::from_millis(20)) {
                Ok(e) => break e?,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("Runner disconnected during handshake".into());
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if Instant::now() >= deadline {
                return Err("Runner handshake timed out".into());
            }
        };
        self.order.accept(&hello)?;
        if !matches!(
            hello.payload,
            Event::Hello {
                engine: ENGINE_VERSION
            }
        ) {
            return Err("Runner handshake incompatible".into());
        }
        Ok(())
    }
    fn start(&mut self, scan: Id, attempt: Id, command: Command) -> Result<(), String> {
        self.scan = scan;
        self.attempt = attempt;
        self.sequence = 0;
        self.order = ReceiveOrder::new(self.session, scan, attempt);
        self.send(command)
    }
    fn send(&mut self, command: Command) -> Result<(), String> {
        self.sequence += 1;
        write_frame(
            self.input.as_mut().ok_or("Runner closed")?,
            &Envelope::new(
                self.session,
                self.scan,
                self.attempt,
                self.sequence,
                command,
            ),
        )
        .map_err(|e| e.to_string())
    }
    fn poll(&mut self) -> Result<Option<Envelope<Event>>, String> {
        match self.events.try_recv() {
            Ok(e) => {
                let e = e?;
                self.order.accept(&e)?;
                Ok(Some(e))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(_) => Err("Runner exited".into()),
        }
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.input.take();
        #[cfg(target_os = "macos")]
        self.authorized.take();
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let deadline = Instant::now() + Duration::from_millis(700);
        loop {
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
fn emit(out: &mpsc::SyncSender<Update>, u: Update) -> Result<(), String> {
    out.try_send(u).map_err(|_| {
        "Display stopped consuming updates; scan interrupted to prevent data loss".into()
    })
}
fn work(
    mut db: Store,
    path: PathBuf,
    actions: mpsc::Receiver<Action>,
    out: mpsc::SyncSender<Update>,
    stop: Arc<AtomicBool>,
    cancel_auth: Arc<AtomicBool>,
) -> Result<(), String> {
    let mut client: Option<Client> = None;
    let mut hosts = hosts::Hosts::new(
        path.with_file_name(format!("studio-inspect{}", std::env::consts::EXE_SUFFIX)),
    );
    let mut selected: Option<Id> = None;
    let mut active = false;
    let history = db.scans().map_err(|e| e.to_string())?;
    if let Some(s) = history.first() {
        selected = Some(s.scan);
        emit(
            &out,
            Update::Reset(
                db.observations(s.scan).map_err(|e| e.to_string())?,
                s.job.backend,
            ),
        )?;
        emit(
            &out,
            host_selection(&mut hosts, s.scan, s.job.backend, &mut db),
        )?;
        emit(&out, Update::State(s.status.clone(), s.detail.clone()))?;
    }
    emit(&out, Update::History(history, selected))?;
    let result = (|| {
        while !stop.load(Ordering::Acquire) {
            let step = (|| -> Result<(), String> {
                if let Ok(action) = actions.try_recv() {
                    match action {
                        Action::LookupHosts { ips, refresh } => {
                            match hosts.dns(ips, refresh, &mut db) {
                                Ok(info) => emit(&out, Update::Hosts(info))?,
                                Err(e) => emit(&out, Update::Notice(e))?,
                            }
                        }
                        Action::InspectHost(ip) => match hosts.nmap(ip, &mut db) {
                            Ok(info) => emit(&out, Update::Hosts(info))?,
                            Err(e) => emit(&out, Update::Notice(e))?,
                        },
                        Action::CancelInspection => match hosts.cancel(&mut db) {
                            Ok(info) => emit(&out, Update::Hosts(info))?,
                            Err(e) => emit(&out, Update::Notice(e))?,
                        },
                        Action::Authorize if !active => {
                            client.take();
                            emit(
                                &out,
                                Update::Authorization {
                                    busy: true,
                                    authorized: false,
                                    detail: "Waiting for system authorization…".into(),
                                },
                            )?;
                            match Client::authorize(&path, &cancel_auth) {
                                Ok(mut c) => {
                                    emit(&out,Update::Authorization {busy:false,authorized:true,detail:"Runner authorized for this session; checking isolated network…".into()})?;
                                    c.send(Command::CheckNetwork)?;
                                    client = Some(c);
                                }
                                Err(e) => emit(
                                    &out,
                                    Update::Authorization {
                                        busy: false,
                                        authorized: false,
                                        detail: e,
                                    },
                                )?,
                            }
                        }
                        Action::Start(_) | Action::Resume if active => {
                            emit(&out, Update::Notice("A scan is already active".into()))?
                        }
                        Action::Start(job) => {
                            job.prepare()?;
                            if job.backend != Backend::Simulation {
                                if !RAW_SCANNING_ENABLED {
                                    emit(&out,Update::State(Status::Failed,"Raw scanning is not enabled in this build. Authorization can be checked separately without sending packets.".into()))?;
                                    return Ok(());
                                }
                                if !client.as_ref().is_some_and(Client::is_authorized) {
                                    return Err(
                                        "Authorize the runner before starting a raw scan".into()
                                    );
                                }
                            } else if client.as_ref().is_some_and(Client::is_authorized) {
                                client.take();
                                emit(
                                    &out,
                                    Update::Authorization {
                                        busy: false,
                                        authorized: false,
                                        detail: "Simulation uses an unprivileged runner".into(),
                                    },
                                )?;
                            }
                            let scan = new_id()?;
                            let attempt = new_id()?;
                            if client.is_none() {
                                client = Some(Client::open(&path)?);
                            }
                            db.begin(scan, attempt, &job, false)
                                .map_err(|e| e.to_string())?;
                            selected = Some(scan);
                            active = true;
                            let backend = job.backend;
                            client
                                .as_mut()
                                .unwrap()
                                .start(scan, attempt, Command::Start(job))?;
                            emit(&out, Update::Reset(vec![], backend))?;
                            emit(&out, host_selection(&mut hosts, scan, backend, &mut db))?;
                            emit(
                                &out,
                                Update::State(Status::Starting, "Starting scanner".into()),
                            )?;
                        }
                        Action::Resume => {
                            let s = db
                                .scans()
                                .map_err(|e| e.to_string())?
                                .into_iter()
                                .find(|s| Some(s.scan) == selected)
                                .ok_or("Select a paused scan")?;
                            if s.status != Status::Paused {
                                emit(
                                    &out,
                                    Update::Notice("Only a saved paused scan can resume".into()),
                                )?;
                                return Ok(());
                            }
                            let checkpoint = s.checkpoint.ok_or("Checkpoint unavailable")?;
                            if s.job.backend != Backend::Simulation
                                && (!RAW_SCANNING_ENABLED
                                    || !client.as_ref().is_some_and(Client::is_authorized))
                            {
                                return Err(
                                    "Raw resume is gated; saved checkpoint is unchanged".into()
                                );
                            }
                            if s.job.backend == Backend::Simulation
                                && client.as_ref().is_some_and(Client::is_authorized)
                            {
                                client.take();
                                emit(
                                    &out,
                                    Update::Authorization {
                                        busy: false,
                                        authorized: false,
                                        detail: "Simulation uses an unprivileged runner".into(),
                                    },
                                )?;
                            }
                            let attempt = new_id()?;
                            if client.is_none() {
                                client = Some(Client::open(&path)?);
                            }
                            db.begin(s.scan, attempt, &s.job, true)
                                .map_err(|e| e.to_string())?;
                            active = true;
                            client.as_mut().unwrap().start(
                                s.scan,
                                attempt,
                                Command::Resume {
                                    job: s.job,
                                    checkpoint,
                                },
                            )?;
                            emit(
                                &out,
                                Update::State(Status::Starting, "Resuming saved scan".into()),
                            )?;
                        }
                        Action::Pause if active => {
                            client
                                .as_mut()
                                .ok_or("Runner unavailable")?
                                .send(Command::Pause)?;
                            emit(
                                &out,
                                Update::State(
                                    Status::Saving,
                                    "Pausing and draining replies…".into(),
                                ),
                            )?;
                        }
                        Action::Stop if active => {
                            client
                                .as_mut()
                                .ok_or("Runner unavailable")?
                                .send(Command::Stop)?;
                            emit(&out, Update::Notice("Stopping…".into()))?;
                        }
                        Action::Lock if !active => {
                            client.take();
                            emit(
                                &out,
                                Update::Authorization {
                                    busy: false,
                                    authorized: false,
                                    detail: "Runner session closed".into(),
                                },
                            )?;
                            emit(&out, Update::Notice("Runner session closed".into()))?;
                        }
                        Action::Select(id) if !active => {
                            if let Some(s) = db
                                .scans()
                                .map_err(|e| e.to_string())?
                                .into_iter()
                                .find(|s| s.scan == id)
                            {
                                selected = Some(id);
                                emit(
                                    &out,
                                    Update::Reset(
                                        db.observations(id).map_err(|e| e.to_string())?,
                                        s.job.backend,
                                    ),
                                )?;
                                emit(&out, host_selection(&mut hosts, id, s.job.backend, &mut db))?;
                                emit(&out, Update::State(s.status, s.detail))?;
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(c) = client.as_mut() {
                    let events = c.poll_batch()?;
                    let mut durable = Vec::new();
                    for e in events {
                        if let Event::NetworkChecked { ready, detail } = &e.payload {
                            emit(
                                &out,
                                Update::Notice(format!(
                                    "Network preflight {}: {detail}",
                                    if *ready { "passed" } else { "refused" }
                                )),
                            )?;
                            continue;
                        }
                        durable.push(e);
                    }
                    let committed = if durable.is_empty() {
                        Vec::new()
                    } else {
                        db.apply_batch(&durable).map_err(|e| e.to_string())?
                    };
                    for (e, observed) in durable.into_iter().zip(committed) {
                        match e.payload {
                            Event::Started { total } => emit(
                                &out,
                                Update::State(
                                    Status::Scanning,
                                    format!("Scanning {total} endpoints"),
                                ),
                            )?,
                            Event::Results(_) => emit(&out, Update::Rows(observed))?,
                            Event::Progress { sent, received } => {
                                emit(&out, Update::Progress(sent, received))?
                            }
                            Event::Checkpoint { .. } => {
                                emit(
                                    &out,
                                    Update::State(
                                        Status::Saving,
                                        "Checkpoint saved; confirming pause…".into(),
                                    ),
                                )?;
                                c.send(Command::AckCheckpoint {
                                    through: e.sequence,
                                })?;
                            }
                            Event::Finished { detail, .. } => {
                                active = false;
                                let history = db.scans().map_err(|e| e.to_string())?;
                                let status = history
                                    .iter()
                                    .find(|s| s.scan == e.scan)
                                    .ok_or("Saved scan disappeared")?
                                    .status
                                    .clone();
                                emit(&out, Update::State(status, detail))?;
                                emit(&out, Update::History(history, selected))?;
                            }
                            _ => {}
                        }
                    }
                }
                Ok(())
            })();
            if let Err(detail) = step {
                // A broken runner session is recoverable. Close its inherited pipes
                // before accepting another scan; committed history remains intact.
                client.take();
                emit(
                    &out,
                    Update::Authorization {
                        busy: false,
                        authorized: false,
                        detail: "Runner session closed".into(),
                    },
                )?;
                let mut status = Status::Interrupted;
                if active && let Some(scan) = selected {
                    db.interrupt(scan, &detail).map_err(|e| e.to_string())?;
                    let saved = db.scans().map_err(|e| e.to_string())?;
                    if let Some(s) = saved.iter().find(|s| s.scan == scan) {
                        status = s.status.clone();
                    }
                }
                active = false;
                emit(&out, Update::State(status, detail))?;
                emit(
                    &out,
                    Update::History(db.scans().map_err(|e| e.to_string())?, selected),
                )?;
            }
            thread::sleep(Duration::from_millis(5));
            match hosts.poll(&mut db) {
                Ok(info) if !info.is_empty() => emit(&out, Update::Hosts(info))?,
                Err(e) => emit(
                    &out,
                    Update::Notice(format!("Inspection results could not be saved: {e}")),
                )?,
                _ => {}
            }
        }
        Ok(())
    })();
    drop(client);
    let _ = hosts.cancel(&mut db);
    if active && let Some(id) = selected {
        let detail = result
            .as_ref()
            .err()
            .map(String::as_str)
            .unwrap_or("Studio closed during scan");
        let _ = db.interrupt(id, detail);
    }
    result
}

fn host_selection(hosts: &mut hosts::Hosts, scan: Id, backend: Backend, db: &mut Store) -> Update {
    match hosts.select(scan, backend, db) {
        Ok(info) => Update::Hosts(info),
        Err(e) => Update::Notice(format!("Host details unavailable: {e}")),
    }
}
