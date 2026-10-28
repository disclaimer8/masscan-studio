//! Application controller.
#![forbid(unsafe_code)]
mod hosts;
mod network;
mod persistence;
pub use network::{NetworkCoverage, NetworkReadiness, RequestedCounts, requested_counts};
#[cfg(test)]
mod network_tests;
// On macOS, a concurrent child spawn can briefly retain a flock open-file
// description even with CLOEXEC. Coordinate only subprocess/reopen fixtures;
// production Store ownership and locking are unchanged.
#[cfg(test)]
static PROCESS_REOPEN_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
mod setup;
use std::{
    io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
    process::{Child, Command as Process, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use studio_platform::linux as authorization;
#[cfg(target_os = "macos")]
use studio_platform::macos as authorization;
#[cfg(windows)]
use studio_platform::windows::uac as authorization;
use studio_protocol::*;
use studio_store::{SavedRow, SavedScan, Store};

pub enum Action {
    RenameScan {
        id: Id,
        name: String,
    },
    DeleteScan(Id),
    SaveProfile {
        id: Option<Id>,
        name: String,
        job: Job,
    },
    DeleteProfile(Id),
    LookupHosts {
        ips: Vec<String>,
        refresh: bool,
    },
    InspectHost(String),
    CancelInspection,
    CheckSetup,
    InstallRunner,
    CancelSetup,
    Authorize,
    /// Packet-free authorization/check for this job; legacy Authorize checks feth.
    AuthorizeFor(Job),
    /// Packet-free, job-specific route check. Never grants execution readiness.
    CheckNetwork(Job),
    /// Call whenever settings/backend change to invalidate obsolete readiness.
    SetDraft(Job),
    Start(Job),
    Pause,
    Stop,
    Resume,
    Select(Id),
    Lock,
}
pub enum Update {
    NetworkReadiness(Option<NetworkReadiness>),
    NetworkCoverage(Option<Box<NetworkCoverage>>),
    Setup {
        busy: bool,
        ready: bool,
        installable: bool,
        detail: String,
    },
    HistoryResult(Result<String, String>),
    Clear,
    ProfileResult(Result<String, String>),
    Profiles(Vec<studio_store::SavedProfile>, Option<Id>),
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
    commands: mpsc::SyncSender<(Action, u64)>,
    updates: mpsc::Receiver<Update>,
    stop: Arc<AtomicBool>,
    cancel_auth: Arc<AtomicBool>,
    cancel_epoch: Arc<AtomicU64>,
    setup_pending: Arc<AtomicBool>,
    cancel_setup: Arc<AtomicBool>,
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
        let cancel_epoch = Arc::new(AtomicU64::new(0));
        let cancel_attempt = cancel_epoch.clone();
        let error = Arc::new(Mutex::new(None));
        let errors = error.clone();
        let setup_pending = Arc::new(AtomicBool::new(false));
        let cancel_setup = Arc::new(AtomicBool::new(false));
        let setup_state = (setup_pending.clone(), cancel_setup.clone());
        let worker = thread::spawn(move || {
            if let Err(e) = work(
                store,
                runner,
                rx,
                out,
                (flag, cancel_attempt),
                cancel,
                setup_state,
            ) {
                *errors.lock().unwrap() = Some(e);
            }
        });
        Ok(Self {
            commands,
            updates,
            stop,
            cancel_auth,
            cancel_epoch,
            setup_pending,
            cancel_setup,
            error,
            worker: Some(worker),
        })
    }
    pub fn send(&self, a: Action) -> Result<(), String> {
        if matches!(a, Action::CancelSetup) {
            self.cancel_setup.store(true, Ordering::Release);
            return Ok(());
        }
        let setup = matches!(a, Action::CheckSetup | Action::InstallRunner);
        if setup {
            self.setup_pending
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| "Scanner setup is already in progress")?;
            self.cancel_setup.store(false, Ordering::Release);
        } else if self.setup_pending.load(Ordering::Acquire) {
            return Err("Wait for scanner setup to finish, or cancel waiting in Setup".into());
        }
        if matches!(a, Action::Authorize | Action::AuthorizeFor(_)) {
            self.cancel_auth.store(false, Ordering::Release);
        }
        // Invalidate queued starts and suppress report ACKs immediately, including
        // while the worker is committing SQLite or waiting on an OS prompt.
        if matches!(a, Action::Stop | Action::Lock) {
            self.cancel_auth.store(true, Ordering::Release);
            self.cancel_epoch.fetch_add(1, Ordering::AcqRel);
        }
        let epoch = self.cancel_epoch.load(Ordering::Acquire);
        if self.commands.try_send((a, epoch)).is_err() {
            if setup {
                self.setup_pending.store(false, Ordering::Release);
            }
            return Err("Application command queue is busy or closed".into());
        }
        Ok(())
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
        self.cancel_setup.store(true, Ordering::Release);
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

struct Client {
    child: Option<Child>,
    #[cfg(windows)]
    pipe: Option<studio_platform::windows::Stream>,
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    authorized: Option<authorization::Authorized>,
    input: Option<BufWriter<Box<dyn Write + Send>>>,
    events: mpsc::Receiver<Result<Envelope<Event>, String>>,
    session: Id,
    scan: Id,
    attempt: Id,
    sequence: u64,
    order: Option<ReceiveOrder>,
    session_sequence: u64,
    session_order: ReceiveOrder,
    halted: bool,
    preparing: bool,
    pending: persistence::Pending,
    deferred: Option<Envelope<Event>>,
}
impl Client {
    #[cfg(not(windows))]
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
    #[cfg(windows)]
    fn open(path: &PathBuf) -> Result<Self, String> {
        use studio_platform::windows::{Endpoint, Identity, Process as Peer};
        let endpoint = Endpoint::create()?;
        let owner = serde_json::to_string(&Identity::current()?).map_err(|e| e.to_string())?;
        let mut child = Process::new(path)
            .arg("--connect-pipe")
            .arg(endpoint.name())
            .arg(owner)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("Cannot start Studio runner: {e}"))?;
        let connection = (|| {
            let peer = Peer::open(child.id())?;
            let stream = endpoint.accept(peer, Duration::from_secs(10), &AtomicBool::new(false))?;
            match Self::connected(Box::new(stream.clone()), Box::new(stream.clone())) {
                Ok(mut c) => {
                    c.pipe = Some(stream);
                    Ok(c)
                }
                Err(e) => {
                    stream.shutdown();
                    Err(e)
                }
            }
        })();
        let mut c = match connection {
            Ok(c) => c,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        c.child = Some(child);
        c.handshake(None)?;
        Ok(c)
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn authorize(source: &std::path::Path, cancelled: &AtomicBool) -> Result<Self, String> {
        let hash = studio_platform::trusted::file_hash(source)?;
        let path = authorization::installed_path(&hash)?;
        // The installation hint belongs to a missing or unverifiable installed image only; a timeout or a
        // cancelled dialog keeps its own diagnostic.
        let installed = studio_platform::trusted::verify(&path, &hash);
        let auth = authorization::Authorized::open(&path, &hash, cancelled).map_err(|e| {
            if installed.is_err() {
                format!("{e}. Open Scanner setup to install the helper for this build.")
            } else {
                e
            }
        })?;
        let input = auth.stream.try_clone().map_err(|e| e.to_string())?;
        let output = auth.stream.try_clone().map_err(|e| e.to_string())?;
        let mut c = Self::connected(Box::new(input), Box::new(output))?;
        c.authorized = Some(auth);
        c.handshake(Some(cancelled))?;
        Ok(c)
    }
    #[cfg(windows)]
    fn authorize(source: &std::path::Path, cancelled: &AtomicBool) -> Result<Self, String> {
        let hash = studio_platform::trusted::file_hash(source)?;
        let auth = authorization::Authorized::open(&hash, cancelled)?;
        let mut c = Self::connected(Box::new(auth.stream.clone()), Box::new(auth.stream.clone()))?;
        c.authorized = Some(auth);
        c.handshake(Some(cancelled))?;
        Ok(c)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    fn authorize(_: &std::path::Path, _: &AtomicBool) -> Result<Self, String> {
        Err(
            "System authorization is currently implemented on macOS and Linux; simulation is available"
                .into(),
        )
    }
    fn is_authorized(&self) -> bool {
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        {
            self.authorized.is_some()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
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
            let trace = std::env::var_os("STUDIO_TRACE_TIMINGS").is_some();
            let start = Instant::now();
            let mut logged = start;
            let mut blocked = Duration::ZERO;
            let mut rows = 0usize;
            loop {
                let e = read_frame::<Event>(&mut out)
                    .map_err(|e| format!("Runner connection closed: {e}"));
                if let Ok(Envelope {
                    payload: Event::Results(batch),
                    ..
                }) = &e
                {
                    rows += batch.len();
                }
                let done = e.is_err();
                let began = Instant::now();
                if tx.send(e).is_err() || done {
                    break;
                }
                blocked += began.elapsed();
                if trace && logged.elapsed() >= Duration::from_secs(1) {
                    eprintln!(
                        "controller reader: rows={rows} queue_wait_ms={} age_ms={}",
                        blocked.as_millis(),
                        start.elapsed().as_millis()
                    );
                    logged = Instant::now();
                }
            }
        });
        Ok(Self {
            child: None,
            #[cfg(windows)]
            pipe: None,
            #[cfg(any(target_os = "macos", target_os = "linux", windows))]
            authorized: None,
            input: Some(BufWriter::new(input)),
            events,
            session,
            scan: [0; 16],
            attempt: [0; 16],
            sequence: 0,
            order: None,
            session_sequence: 0,
            session_order: ReceiveOrder::new(session, [0; 16], [0; 16]),
            halted: false,
            preparing: false,
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
        self.session_order.accept(&hello)?;
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
        if scan == [0; 16]
            || attempt == [0; 16]
            || !matches!(command, Command::Start(_) | Command::Resume { .. })
        {
            return Err("Invalid scan start identity or command".into());
        }
        self.halted = false;
        self.preparing = match &command {
            Command::Start(job) | Command::Resume { job, .. } => job.backend == Backend::MacNetwork,
            _ => false,
        };
        self.scan = scan;
        self.attempt = attempt;
        self.sequence = 0;
        self.order = Some(ReceiveOrder::new(self.session, scan, attempt));
        self.send(command)
    }
    fn send(&mut self, command: Command) -> Result<(), String> {
        let session_command = matches!(
            command,
            Command::Hello | Command::CheckNetwork | Command::CheckNetworkJob(_)
        );
        let (scan, attempt, sequence) = if session_command {
            self.session_sequence = self
                .session_sequence
                .checked_add(1)
                .ok_or("Sequence exhausted")?;
            ([0; 16], [0; 16], self.session_sequence)
        } else {
            if self.order.is_none() {
                return Err("No scan attempt".into());
            }
            if matches!(command, Command::Stop | Command::CloseSession) {
                self.halted = true;
            }
            self.sequence = self.sequence.checked_add(1).ok_or("Sequence exhausted")?;
            (self.scan, self.attempt, self.sequence)
        };
        write_frame(
            self.input.as_mut().ok_or("Runner closed")?,
            &Envelope::new(self.session, scan, attempt, sequence, command),
        )
        .map_err(|e| e.to_string())
    }
    fn poll(&mut self) -> Result<Option<Envelope<Event>>, String> {
        match self.events.try_recv() {
            Ok(e) => {
                let e = e?;
                match e.payload {
                    Event::NetworkChecked { .. } | Event::NetworkPreflight { .. } => {
                        self.session_order.accept(&e)?
                    }
                    Event::Hello { .. } => return Err("Unexpected repeated handshake".into()),
                    _ => self
                        .order
                        .as_mut()
                        .ok_or("Scan event without an attempt")?
                        .accept(&e)?,
                }
                Ok(Some(e))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(_) => Err("Runner exited".into()),
        }
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some(pipe) = self.pipe.take() {
            pipe.shutdown();
        }
        self.input.take();
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
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
    actions: mpsc::Receiver<(Action, u64)>,
    out: mpsc::SyncSender<Update>,
    cancellation: (Arc<AtomicBool>, Arc<AtomicU64>),
    cancel_auth: Arc<AtomicBool>,
    setup_state: (Arc<AtomicBool>, Arc<AtomicBool>),
) -> Result<(), String> {
    let (stop, cancel_epoch) = cancellation;
    let mut attempt_epoch = 0;
    let (setup_pending, cancel_setup) = setup_state;
    let mut draft = network::Draft::default();
    let mut setup = setup::Setup::default();
    let mut client: Option<Client> = None;
    let mut hosts = hosts::Hosts::new(
        path.with_file_name(format!("studio-inspect{}", std::env::consts::EXE_SUFFIX)),
    );
    let mut selected: Option<Id> = None;
    let mut active = false;
    let trace = std::env::var_os("STUDIO_TRACE_TIMINGS").is_some();
    let started = Instant::now();
    let mut logged = started;
    let mut commits = Duration::ZERO;
    let mut saved_rows = 0usize;
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
        emit(&out, network::coverage(s)?)?;
        emit(&out, Update::State(s.status.clone(), s.detail.clone()))?;
    }
    emit(&out, Update::History(history, selected))?;
    emit(
        &out,
        Update::Profiles(db.profiles().map_err(|e| e.to_string())?, None),
    )?;
    let result = (|| {
        while !stop.load(Ordering::Acquire) {
            let step = (|| -> Result<(), String> {
                if let Ok((action, requested_epoch)) = actions.try_recv() {
                    match action {
                        Action::RenameScan { .. } | Action::DeleteScan(_) if active => {
                            emit(
                                &out,
                                Update::HistoryResult(Err(
                                    "Wait for the active scan to stop before editing history"
                                        .into(),
                                )),
                            )?;
                        }
                        Action::RenameScan { id, name } => {
                            let result = db.rename_scan(id, &name).map_err(|e| e.to_string());
                            if result.is_ok() {
                                emit(
                                    &out,
                                    Update::History(
                                        db.scans().map_err(|e| e.to_string())?,
                                        selected,
                                    ),
                                )?;
                            }
                            emit(
                                &out,
                                Update::HistoryResult(result.map(|_| "Scan renamed".into())),
                            )?;
                        }
                        Action::DeleteScan(id) => {
                            let result = db.delete_scan(id).map_err(|e| e.to_string());
                            if result.is_ok() {
                                let history = db.scans().map_err(|e| e.to_string())?;
                                if selected == Some(id) {
                                    // No completion can be processed between the commit and
                                    // forget: both run on this controller thread.
                                    hosts.forget();
                                    selected = history.first().map(|s| s.scan);
                                    if let Some(s) = history.first() {
                                        draft.invalidate(&out)?;
                                        emit(
                                            &out,
                                            Update::Reset(
                                                db.observations(s.scan)
                                                    .map_err(|e| e.to_string())?,
                                                s.job.backend,
                                            ),
                                        )?;
                                        emit(
                                            &out,
                                            host_selection(
                                                &mut hosts,
                                                s.scan,
                                                s.job.backend,
                                                &mut db,
                                            ),
                                        )?;
                                        emit(&out, network::coverage(s)?)?;
                                        emit(
                                            &out,
                                            Update::State(s.status.clone(), s.detail.clone()),
                                        )?;
                                    } else {
                                        draft.invalidate(&out)?;
                                        emit(&out, Update::NetworkCoverage(None))?;
                                        emit(&out, Update::Clear)?;
                                        emit(
                                            &out,
                                            Update::State(Status::Ready, "No saved scans".into()),
                                        )?;
                                    }
                                }
                                emit(&out, Update::History(history, selected))?;
                            }
                            emit(
                                &out,
                                Update::HistoryResult(
                                    result.map(|_| {
                                        "Scan deleted. Saved profiles are unchanged.".into()
                                    }),
                                ),
                            )?;
                        }
                        Action::SaveProfile { id, name, job } => {
                            let result =
                                db.save_profile(id, &name, &job).map_err(|e| e.to_string());
                            if let Ok(profile) = &result {
                                emit(
                                    &out,
                                    Update::Profiles(
                                        db.profiles().map_err(|e| e.to_string())?,
                                        Some(profile.id),
                                    ),
                                )?;
                            }
                            emit(
                                &out,
                                Update::ProfileResult(result.map(|p| {
                                    format!("Saved profile {}. No scan started.", p.name)
                                })),
                            )?;
                        }
                        Action::DeleteProfile(id) => {
                            let result = db.delete_profile(id).map_err(|e| e.to_string());
                            if result.is_ok() {
                                emit(
                                    &out,
                                    Update::Profiles(
                                        db.profiles().map_err(|e| e.to_string())?,
                                        None,
                                    ),
                                )?;
                            }
                            emit(
                                &out,
                                Update::ProfileResult(
                                    result.map(|_| {
                                        "Profile deleted. Saved scans are unchanged.".into()
                                    }),
                                ),
                            )?;
                        }
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
                        Action::CheckSetup | Action::InstallRunner => {
                            emit(
                                &out,
                                Update::Setup {
                                    busy: true,
                                    ready: false,
                                    installable: false,
                                    detail: if matches!(action, Action::InstallRunner) {
                                        "Waiting for system installation permission…"
                                    } else {
                                        "Checking the bundled scanner helper…"
                                    }
                                    .into(),
                                },
                            )?;
                            let result = setup.perform(
                                matches!(action, Action::InstallRunner),
                                &path,
                                active || client.as_ref().is_some_and(Client::is_authorized),
                                &cancel_setup,
                            );
                            setup_pending.store(false, Ordering::Release);
                            emit(&out, result)?;
                        }
                        Action::SetDraft(job) if !active => {
                            draft.invalidate(&out)?;
                            emit(&out, Update::NetworkCoverage(None))?;
                            draft.set(&job, false, &out)?;
                        }
                        Action::CheckNetwork(job) if !active => {
                            draft.invalidate(&out)?;
                            if !draft.set(&job, job.backend != Backend::Simulation, &out)? {
                                return Ok(());
                            }
                            if job.backend == Backend::Simulation {
                                return Ok(());
                            }
                            if client.is_none() {
                                client = Some(Client::open(&path)?);
                            }
                            client.as_mut().unwrap().send(network::check_command(job))?;
                        }
                        action @ (Action::Authorize | Action::AuthorizeFor(_)) if !active => {
                            let job = match action {
                                Action::AuthorizeFor(job) => Some(job),
                                _ => None,
                            };
                            draft.invalidate(&out)?;
                            if let Some(job) = &job {
                                if !draft.set(job, job.backend != Backend::Simulation, &out)? {
                                    return Ok(());
                                }
                                if job.backend == Backend::Simulation {
                                    emit(
                                        &out,
                                        Update::Notice(
                                            "Simulation needs no privileged network session".into(),
                                        ),
                                    )?;
                                    return Ok(());
                                }
                            }

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
                                    emit(&out, Update::Authorization { busy:false, authorized:true, detail:"Runner authorized for this session; checking network routes…".into() })?;
                                    c.send(match job {
                                        Some(job) => network::check_command(job),
                                        None => Command::CheckNetwork,
                                    })?;
                                    client = Some(c);
                                }
                                Err(e) => {
                                    draft.invalidate(&out)?;
                                    emit(
                                        &out,
                                        Update::Authorization {
                                            busy: false,
                                            authorized: false,
                                            detail: e,
                                        },
                                    )?;
                                }
                            }
                        }
                        Action::Start(_) | Action::Resume if active => {
                            emit(&out, Update::Notice("A scan is already active".into()))?
                        }
                        Action::Start(job) => {
                            job.validate()?;
                            if requested_epoch != cancel_epoch.load(Ordering::Acquire)
                                || stop.load(Ordering::Acquire)
                            {
                                return Ok(());
                            }
                            attempt_epoch = requested_epoch;
                            if job.backend != Backend::Simulation {
                                if !raw_profile_enabled(job.backend) {
                                    emit(&out,Update::State(Status::Failed,"Raw scanning is not enabled in this build. Authorization can be checked separately without sending packets.".into()))?;
                                    return Ok(());
                                }
                                if !client.as_ref().is_some_and(Client::is_authorized) {
                                    emit(
                                        &out,
                                        Update::State(
                                            Status::Failed,
                                            "Authorize the runner before starting a raw scan"
                                                .into(),
                                        ),
                                    )?;
                                    return Ok(());
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
                            let backend = job.backend;
                            if !launch_attempt(
                                &mut db,
                                &mut client,
                                Launch {
                                    scan,
                                    attempt,
                                    command: Command::Start(job),
                                },
                                &|| {
                                    requested_epoch != cancel_epoch.load(Ordering::Acquire)
                                        || stop.load(Ordering::Acquire)
                                },
                                || Client::open(&path),
                                persist_launch,
                            )? {
                                emit(
                                    &out,
                                    Update::History(
                                        db.scans().map_err(|e| e.to_string())?,
                                        selected,
                                    ),
                                )?;
                                emit(
                                    &out,
                                    Update::Notice("Scan launch cancelled before dispatch".into()),
                                )?;
                                return Ok(());
                            }
                            selected = Some(scan);
                            active = true;
                            draft.invalidate(&out)?;
                            emit(&out, Update::Reset(vec![], backend))?;
                            emit(&out, Update::NetworkCoverage(None))?;
                            emit(&out, host_selection(&mut hosts, scan, backend, &mut db))?;
                            emit(
                                &out,
                                Update::State(Status::Starting, "Starting scanner".into()),
                            )?;
                        }
                        Action::Resume => {
                            if requested_epoch != cancel_epoch.load(Ordering::Acquire)
                                || stop.load(Ordering::Acquire)
                            {
                                return Ok(());
                            }
                            attempt_epoch = requested_epoch;
                            let s = db
                                .scans()
                                .map_err(|e| e.to_string())?
                                .into_iter()
                                .find(|s| Some(s.scan) == selected)
                                .ok_or("Select a paused scan")?;
                            if s.job.backend == Backend::Archived {
                                emit(&out, Update::Notice("Archived history is read-only; its checkpoint cannot resume in rmasscan".into()))?;
                                return Ok(());
                            }
                            if s.status != Status::Paused {
                                emit(
                                    &out,
                                    Update::Notice("Only a saved paused scan can resume".into()),
                                )?;
                                return Ok(());
                            }
                            emit(&out, network::coverage(&s)?)?;
                            let checkpoint = s.checkpoint.ok_or("Checkpoint unavailable")?;
                            if s.job.backend != Backend::Simulation
                                && (!raw_profile_enabled(s.job.backend)
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
                            if !launch_attempt(
                                &mut db,
                                &mut client,
                                Launch {
                                    scan: s.scan,
                                    attempt,
                                    command: Command::Resume {
                                        job: s.job,
                                        checkpoint,
                                    },
                                },
                                &|| {
                                    requested_epoch != cancel_epoch.load(Ordering::Acquire)
                                        || stop.load(Ordering::Acquire)
                                },
                                || Client::open(&path),
                                persist_launch,
                            )? {
                                emit(
                                    &out,
                                    Update::History(
                                        db.scans().map_err(|e| e.to_string())?,
                                        selected,
                                    ),
                                )?;
                                emit(
                                    &out,
                                    Update::Notice("Scan launch cancelled before dispatch".into()),
                                )?;
                                return Ok(());
                            }
                            active = true;
                            draft.invalidate(&out)?;
                            emit(
                                &out,
                                Update::State(Status::Starting, "Resuming saved scan".into()),
                            )?;
                        }
                        Action::Pause if active && client.as_ref().is_some_and(|c| c.preparing) => {
                            emit(
                                &out,
                                Update::Notice(
                                    "Network preparation cannot be paused; use Stop to cancel"
                                        .into(),
                                ),
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
                        Action::Lock => {
                            client.take();
                            draft.invalidate(&out)?;
                            if active && let Some(scan) = selected {
                                db.interrupt(scan, "Runner session locked during scan")
                                    .map_err(|e| e.to_string())?;
                                active = false;
                                let saved = db.scans().map_err(|e| e.to_string())?;
                                let scan = saved
                                    .iter()
                                    .find(|s| s.scan == scan)
                                    .ok_or("Saved scan disappeared")?;
                                emit(
                                    &out,
                                    Update::State(scan.status.clone(), scan.detail.clone()),
                                )?;
                                emit(&out, Update::History(saved, selected))?;
                            }
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
                                draft.invalidate(&out)?;
                                emit(
                                    &out,
                                    Update::Reset(
                                        db.observations(id).map_err(|e| e.to_string())?,
                                        s.job.backend,
                                    ),
                                )?;
                                emit(&out, host_selection(&mut hosts, id, s.job.backend, &mut db))?;
                                emit(&out, network::coverage(&s)?)?;
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
                        if let Event::NetworkPreflight {
                            job_digest,
                            ready,
                            detail,
                        } = &e.payload
                        {
                            draft.checked(*job_digest, *ready, detail.clone(), &out)?;
                            continue;
                        }
                        if let Event::NetworkChecked { ready, detail } = &e.payload {
                            draft.checked_legacy(*ready, detail.clone(), &out)?;
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
                    let began = Instant::now();
                    let (rows, finished) =
                        commit_scan_events(&mut db, c, durable, &out, selected, &|| {
                            stop.load(Ordering::Acquire)
                                || attempt_epoch != cancel_epoch.load(Ordering::Acquire)
                        })?;
                    commits += began.elapsed();
                    saved_rows += rows;
                    if finished {
                        active = false;
                    }
                    if trace && logged.elapsed() >= Duration::from_secs(1) {
                        eprintln!(
                            "controller store: rows={saved_rows} commit_ms={} age_ms={}",
                            commits.as_millis(),
                            started.elapsed().as_millis()
                        );
                        logged = Instant::now();
                    }
                }
                Ok(())
            })();
            if let Err(detail) = step {
                // A broken runner session is recoverable. Close its inherited pipes
                // before accepting another scan; committed history remains intact.
                client.take();
                draft.invalidate(&out)?;
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

// This is the controller's durable boundary: no acknowledgement can leave before
// the whole batch commits successfully, and only this client's attempt may commit.
fn commit_scan_events(
    db: &mut Store,
    c: &mut Client,
    durable: Vec<Envelope<Event>>,
    out: &mpsc::SyncSender<Update>,
    selected: Option<Id>,
    cancelled: &dyn Fn() -> bool,
) -> Result<(usize, bool), String> {
    if durable
        .iter()
        .any(|e| e.session != c.session || e.scan != c.scan || e.attempt != c.attempt)
    {
        return Err("Stale controller event identity".into());
    }
    let committed = if durable.is_empty() {
        Vec::new()
    } else {
        db.apply_batch(&durable).map_err(|e| e.to_string())?
    };
    let rows = committed.iter().map(Vec::len).sum();
    let mut finished = false;
    for (e, observed) in durable.into_iter().zip(committed) {
        match e.payload {
            Event::PreparingNetwork => emit(
                out,
                Update::State(
                    Status::Preparing,
                    "Preparing network; Stop or Lock cancels preparation".into(),
                ),
            )?,
            Event::NetworkPrepared { .. } => {
                let saved = db.scans().map_err(|e| e.to_string())?;
                let saved = saved
                    .iter()
                    .find(|s| s.scan == e.scan)
                    .ok_or("Saved scan disappeared")?;
                emit(out, network::coverage(saved)?)?;
                if !c.halted && !cancelled() {
                    c.send(Command::AckNetworkReport {
                        through: e.sequence,
                    })?;
                }
            }
            Event::Started { total } => {
                c.preparing = false;
                emit(
                    out,
                    Update::State(Status::Scanning, format!("Scanning {total} endpoints")),
                )?;
            }
            Event::Results(_) => emit(out, Update::Rows(observed))?,
            Event::Progress { sent, received } => emit(out, Update::Progress(sent, received))?,
            Event::Checkpoint { .. } => {
                emit(
                    out,
                    Update::State(Status::Saving, "Checkpoint saved; confirming pause…".into()),
                )?;
                if !c.halted && !cancelled() {
                    c.send(Command::AckCheckpoint {
                        through: e.sequence,
                    })?;
                }
            }
            Event::Finished { detail, .. } => {
                c.preparing = false;
                finished = true;
                let history = db.scans().map_err(|e| e.to_string())?;
                let status = history
                    .iter()
                    .find(|s| s.scan == e.scan)
                    .ok_or("Saved scan disappeared")?
                    .status
                    .clone();
                emit(out, Update::State(status, detail))?;
                emit(out, Update::History(history, selected))?;
            }
            _ => {}
        }
    }
    Ok((rows, finished))
}

struct Launch {
    scan: Id,
    attempt: Id,
    command: Command,
}
fn persist_launch(db: &mut Store, launch: &Launch) -> Result<(), String> {
    let (job, resume) = match &launch.command {
        Command::Start(job) => (job, false),
        Command::Resume { job, .. } => (job, true),
        _ => return Err("Invalid launch command".into()),
    };
    db.begin(launch.scan, launch.attempt, job, resume)
        .map_err(|e| e.to_string())
}
// Both production Start and Resume use this boundary. The injected operations
// let tests hold setup or persistence while another thread requests cancellation.
fn launch_attempt(
    db: &mut Store,
    client: &mut Option<Client>,
    launch: Launch,
    cancelled: &dyn Fn() -> bool,
    open: impl FnOnce() -> Result<Client, String>,
    persist: impl FnOnce(&mut Store, &Launch) -> Result<(), String>,
) -> Result<bool, String> {
    if cancelled() {
        return Ok(false);
    }
    if client.is_none() {
        *client = Some(open()?);
    }
    // Opening/handshaking can block; do not even create a Starting row if a
    // Stop, Lock, or application close became known during that operation.
    if cancelled() {
        return Ok(false);
    }
    persist(db, &launch)?;
    // SQLite may wait for another writer. Make the final decision immediately
    // before dispatch, and reconcile a committed row if cancellation won.
    if cancelled() {
        db.interrupt(launch.scan, "Scan launch cancelled before dispatch")
            .map_err(|e| e.to_string())?;
        return Ok(false);
    }
    if let Err(detail) = client
        .as_mut()
        .unwrap()
        .start(launch.scan, launch.attempt, launch.command)
    {
        db.interrupt(launch.scan, &detail)
            .map_err(|e| e.to_string())?;
        return Err(detail);
    }
    Ok(true)
}
