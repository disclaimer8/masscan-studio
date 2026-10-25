//! Application controller.
#![forbid(unsafe_code)]
use std::{
    io::{BufReader, BufWriter},
    path::PathBuf,
    process::{Child, ChildStdin, Command as Process, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};
use studio_protocol::*;
use studio_store::{SavedScan, Store};

pub enum Action {
    Start(Job),
    Pause,
    Stop,
    Resume,
    Select(Id),
    Lock,
}
pub enum Update {
    Reset(Vec<Row>, Backend),
    Rows(Vec<Row>),
    State(Status, String),
    Progress(String, String),
    History(Vec<SavedScan>, Option<Id>),
    Notice(String),
}
pub struct Controller {
    commands: mpsc::SyncSender<Action>,
    updates: mpsc::Receiver<Update>,
    stop: Arc<AtomicBool>,
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
        let error = Arc::new(Mutex::new(None));
        let errors = error.clone();
        let worker = thread::spawn(move || {
            if let Err(e) = work(store, runner, rx, out, flag) {
                *errors.lock().unwrap() = Some(e);
            }
        });
        Ok(Self {
            commands,
            updates,
            stop,
            error,
            worker: Some(worker),
        })
    }
    pub fn send(&self, a: Action) -> Result<(), String> {
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
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

struct Client {
    child: Child,
    input: Option<BufWriter<ChildStdin>>,
    events: mpsc::Receiver<Result<Envelope<Event>, String>>,
    session: Id,
    scan: Id,
    attempt: Id,
    sequence: u64,
    order: ReceiveOrder,
}
impl Client {
    fn open(path: &PathBuf) -> Result<Self, String> {
        let session = new_id()?;
        let mut child = Process::new(path)
            .arg("--stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("Cannot start Studio runner: {e}"))?;
        let input = BufWriter::new(child.stdin.take().ok_or("Runner stdin missing")?);
        let stdout = child.stdout.take().ok_or("Runner stdout missing")?;
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
        let mut c = Self {
            child,
            input: Some(input),
            events,
            session,
            scan: [0; 16],
            attempt: [0; 16],
            sequence: 0,
            order: ReceiveOrder::new(session, [0; 16], [0; 16]),
        };
        c.send(Command::Hello)?;
        let hello = c
            .events
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| "Runner handshake timed out")??;
        c.order.accept(&hello)?;
        if !matches!(
            hello.payload,
            Event::Hello {
                engine: ENGINE_VERSION
            }
        ) {
            return Err("Runner handshake incompatible".into());
        }
        Ok(c)
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
        let deadline = Instant::now() + Duration::from_millis(700);
        loop {
            if self.child.try_wait().ok().flatten().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
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
) -> Result<(), String> {
    let mut client: Option<Client> = None;
    let mut selected: Option<Id> = None;
    let mut active = false;
    let history = db.scans().map_err(|e| e.to_string())?;
    if let Some(s) = history.first() {
        selected = Some(s.scan);
        emit(
            &out,
            Update::Reset(db.rows(s.scan).map_err(|e| e.to_string())?, s.job.backend),
        )?;
        emit(&out, Update::State(s.status.clone(), s.detail.clone()))?;
    }
    emit(&out, Update::History(history, selected))?;
    let result = (|| {
        while !stop.load(Ordering::Acquire) {
            let step = (|| -> Result<(), String> {
                if let Ok(action) = actions.try_recv() {
                    match action {
                        Action::Start(_) | Action::Resume if active => {
                            emit(&out, Update::Notice("A scan is already active".into()))?
                        }
                        Action::Start(job) => {
                            job.prepare()?;
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
                                        db.rows(id).map_err(|e| e.to_string())?,
                                        s.job.backend,
                                    ),
                                )?;
                                emit(&out, Update::State(s.status, s.detail))?;
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(c) = client.as_mut() {
                    for _ in 0..32 {
                        let Some(e) = c.poll()? else {
                            break;
                        };
                        db.apply(&e).map_err(|e| e.to_string())?;
                        match e.payload {
                            Event::Started { total } => emit(
                                &out,
                                Update::State(
                                    Status::Scanning,
                                    format!("Scanning {total} endpoints"),
                                ),
                            )?,
                            Event::Results(rows) => emit(&out, Update::Rows(rows))?,
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
        }
        Ok(())
    })();
    drop(client);
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
