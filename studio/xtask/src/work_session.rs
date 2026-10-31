//! Fixed-purpose, explicitly authorized working host. It never accepts a shell command.
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use studio_platform::{
    audit::Peer,
    unix::Identity,
    work_session::{self as wire, Config, Fixture, Request, Response},
};
type Result<T> = std::result::Result<T, String>;
const WAIT: Duration = Duration::from_millis(20);
struct State {
    active: usize,
    helpers: usize,
    fixture_busy: bool,
    exclusive: bool,
    closing: bool,
    generation: Option<String>,
    runs: BTreeSet<String>,
    stopping: bool,
    selected: Option<(String, String)>,
    callers: BTreeSet<String>,
}
impl State {
    fn new() -> Self {
        Self {
            active: 0,
            helpers: 0,
            fixture_busy: false,
            exclusive: false,
            closing: false,
            generation: None,
            runs: BTreeSet::new(),
            stopping: false,
            selected: None,
            callers: BTreeSet::new(),
        }
    }
}
struct Shared {
    config: Config,
    dir: PathBuf,
    state: Mutex<State>,
    sequence: AtomicUsize,
}
impl Shared {
    fn snapshot(&self) -> Config {
        let mut c = self.config.clone();
        if let Some((tool, runner)) = &self.state.lock().unwrap().selected {
            c.caller_hash = tool.clone();
            c.runner_hash = runner.clone();
        }
        c
    }
}
fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn command(path: &Path) -> Command {
    let mut c = Command::new(path);
    c.env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null());
    c
}
fn tool(c: &Config) -> Result<PathBuf> {
    studio_platform::macos::installed_path(&c.tool_hash)
}
fn protected_tool(c: &Config) -> Result<PathBuf> {
    let p = tool(c)?;
    studio_platform::trusted::verify(&p, &c.tool_hash)?;
    Ok(p)
}
fn selected_tool(c: &Config) -> Result<PathBuf> {
    let p = studio_platform::macos::installed_path(&c.caller_hash)?;
    studio_platform::trusted::verify(&p, &c.caller_hash)?;
    Ok(p)
}
struct StageDir(PathBuf);
impl Drop for StageDir {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("studio-runner"));
        let _ = fs::remove_dir(&self.0);
    }
}
fn copy_build(build: &wire::Build, uid: u32, destination: &Path) -> Result<()> {
    let source = wire::open_build(build, uid)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(destination)
        .map_err(error)?;
    let size = std::io::copy(&mut source.take(wire::MAX_BUILD + 1), &mut output).map_err(error)?;
    if size == 0 || size > wire::MAX_BUILD {
        return Err("Staged source exceeded build bound".into());
    }
    output.sync_all().map_err(error)?;
    if studio_platform::trusted::file_hash(destination)? != build.sha256 {
        return Err("Staged source hash changed or differs from requested build".into());
    }
    Ok(())
}
fn install_build(build: &wire::Build, uid: u32) -> Result<()> {
    build.validate()?;
    let destination = studio_platform::macos::installed_path(&build.sha256)?;
    let parent = destination.parent().unwrap().parent().unwrap();
    wire::protected(parent, false)?;
    if destination.try_exists().map_err(error)? {
        return studio_platform::trusted::verify(&destination, &build.sha256);
    }
    let staging_path = parent.join(format!(
        ".work-stage-{}",
        studio_protocol::id_text(studio_protocol::new_id()?)
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging_path)
        .map_err(error)?;
    let stage = StageDir(staging_path);
    let copy = stage.0.join("studio-runner");
    copy_build(build, uid, &copy)?;
    super::runner_setup::validate(&copy).map_err(error)?;
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o755)).map_err(error)?;
    // A root-owned parent and exclusive session reservation prevent user races.
    // create_dir refuses any existing version, including a dangling link.
    let target = destination.parent().unwrap();
    fs::DirBuilder::new()
        .mode(0o755)
        .create(target)
        .map_err(error)?;
    if let Err(e) = fs::rename(&copy, &destination) {
        let _ = fs::remove_dir(target);
        return Err(error(e));
    }
    studio_platform::trusted::verify(&destination, &build.sha256)
}
fn reserve_stage(shared: &Arc<Shared>) -> Result<Reservation> {
    let reservation = reserve(shared, false, true, true)?;
    if shared.state.lock().unwrap().generation.is_some() {
        return Err("Take down the owned fixture before changing builds".into());
    }
    Ok(reservation)
}
fn publish_selection(shared: &Shared, tool: String, runner: String) -> Result<()> {
    let mut config = shared.config.clone();
    config.caller_hash = tool.clone();
    config.runner_hash = runner.clone();
    wire::validate_config(&config)?;
    let path = shared.dir.join(format!(
        "host-{}.json",
        studio_protocol::id_text(studio_protocol::new_id()?)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .open(&path)
            .map_err(error)?;
        file.write_all(&serde_json::to_vec(&config).map_err(error)?)
            .map_err(error)?;
        file.sync_all().map_err(error)?;
        // Keep readers of the selected pair and caller allowlist together.
        let mut state = shared.state.lock().unwrap();
        fs::rename(&path, shared.dir.join("host.json")).map_err(error)?;
        state.callers.insert(tool.clone());
        state.selected = Some((tool, runner));
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}
fn stage(
    shared: &Arc<Shared>,
    stream: &mut UnixStream,
    tool: wire::Build,
    runner: wire::Build,
) -> Result<()> {
    let _reservation = reserve_stage(shared)?;
    install_build(&tool, shared.config.uid)?;
    install_build(&runner, shared.config.uid)?;
    publish_selection(shared, tool.sha256, runner.sha256)?;
    wire::write(stream, &Response::Done { code: 0 })
}
fn fixture_state() -> Result<Option<studio_protocol::sealed_fixture::State>> {
    let p = Path::new(studio_platform::sealed_fixture::STATE);
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(error(e)),
        Ok(m) if m.len() > 65536 => return Err("Oversized fixture state".into()),
        Ok(_) => {}
    }
    studio_platform::sealed_fixture::load(Instant::now() + Duration::from_secs(3), &|| false)
        .map(Some)
}

fn own_fixture(shared: &Shared) -> Result<()> {
    let expected = shared
        .state
        .lock()
        .unwrap()
        .generation
        .clone()
        .ok_or("This work session owns no fixture")?;
    let state = fixture_state()?.ok_or("Owned fixture disappeared")?;
    if state.generation != expected || state.tooling_sha256 != shared.snapshot().caller_hash {
        return Err("Fixture generation/tool differs from this work session".into());
    }
    Ok(())
}
struct ChildOwner(Child);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}
struct Reservation {
    shared: Arc<Shared>,
    helper: bool,
    fixture: bool,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut s = self.shared.state.lock().unwrap();
        s.active -= 1;
        if self.helper {
            s.helpers -= 1;
        }
        if self.fixture {
            s.fixture_busy = false;
            s.exclusive = false;
        }
    }
}
fn reserve(
    shared: &Arc<Shared>,
    helper: bool,
    fixture: bool,
    exclusive: bool,
) -> Result<Reservation> {
    let mut s = shared.state.lock().unwrap();
    if s.stopping
        || s.closing
        || s.exclusive
        || s.active >= wire::MAX_ACTIVE
        || (fixture && s.fixture_busy)
        || (exclusive && s.active != 0)
    {
        return Err("Working session busy; operation refused".into());
    }
    s.active += 1;
    if helper {
        s.helpers += 1;
    }
    if fixture {
        s.fixture_busy = true;
        s.exclusive = exclusive;
    }
    Ok(Reservation {
        shared: shared.clone(),
        helper,
        fixture,
    })
}
fn authenticate(stream: &UnixStream, shared: &Shared) -> Result<Identity> {
    let c = &shared.config;
    let audit = Peer::from_stream(stream)?;
    if audit.uid != c.uid {
        return Err("Different work-session account".into());
    }
    let owner = Identity::read(audit.pid)?;
    if owner.uid != audit.uid || owner.executable != audit.executable {
        return Err("Caller identity changed".into());
    }
    let hash = studio_platform::trusted::file_hash(&audit.executable)?;
    if hash != c.caller_hash && !shared.state.lock().unwrap().callers.contains(&hash) {
        return Err("Caller build is not authorized for this working session".into());
    }
    owner.verify(stream)?;
    audit.verify(stream)?;
    Ok(owner)
}
fn helper(
    shared: &Arc<Shared>,
    stream: &mut UnixStream,
    hash: String,
    endpoint: PathBuf,
    owner: Identity,
) -> Result<()> {
    let _reservation = reserve(shared, true, false, false)?;
    if hash != shared.snapshot().runner_hash {
        return Err("Helper selection changed; retry with the current build".into());
    }
    let path = studio_platform::macos::installed_path(&hash)?;
    studio_platform::trusted::verify(&path, &hash)?;
    let mut child = ChildOwner(
        command(&path)
            .arg("--connect")
            .arg(endpoint)
            .arg(serde_json::to_string(&owner).map_err(error)?)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(error)?,
    );
    wire::write(stream, &Response::HelperStarted)?;
    serve_lease(stream, &mut child, Duration::from_secs(2))
}
fn serve_lease(stream: &mut UnixStream, child: &mut ChildOwner, grace: Duration) -> Result<()> {
    stream.set_nonblocking(true).map_err(error)?;
    loop {
        if child.0.try_wait().map_err(error)?.is_some() {
            break;
        }
        let mut b = [0];
        match stream.read(&mut b) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            _ => break,
        }
        std::thread::sleep(WAIT);
    }
    // Controller closes its direct IPC first. Give the authenticated helper time
    // to join packet workers; a broken/malicious owner cannot retain the child.
    let deadline = Instant::now() + grace;
    while child.0.try_wait().map_err(error)?.is_none() && Instant::now() < deadline {
        std::thread::sleep(WAIT);
    }
    Ok(())
}
fn outputs(shared: &Shared) -> Result<(PathBuf, File, PathBuf, File)> {
    let n = shared.sequence.fetch_add(1, Ordering::Relaxed);
    let dir = shared.dir.join(format!("job-{n}"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(error)?;
    let out = dir.join("stdout");
    let err = dir.join("stderr");
    let a = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&out)
        .map_err(error)?;
    let b = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&err)
        .map_err(error)?;
    Ok((out, a, err, b))
}
fn stream_output(
    file: &mut File,
    stream: &mut UnixStream,
    stderr: bool,
    connected: &mut bool,
    deadline: Instant,
) -> Result<()> {
    let mut bytes = [0; 2048];
    for _ in 0..2 {
        if Instant::now() >= deadline {
            return Err("Work-session output deadline".into());
        }
        let n = file.read(&mut bytes).map_err(error)?;
        if n == 0 {
            return Ok(());
        }
        if *connected
            && wire::write_until(
                stream,
                &Response::Output {
                    stderr,
                    bytes: bytes[..n].to_vec(),
                },
                deadline.min(Instant::now() + Duration::from_secs(2)),
            )
            .is_err()
        {
            *connected = false;
        }
    }
    Ok(())
}

fn run_job(
    shared: &Arc<Shared>,
    stream: &mut UnixStream,
    mut cmd: Command,
    limit: Duration,
    notify: bool,
) -> Result<(i32, PathBuf)> {
    let (out, a, err, b) = outputs(shared)?;
    let mut out_reader = File::open(&out).map_err(error)?;
    let mut err_reader = File::open(&err).map_err(error)?;
    let mut child = ChildOwner(cmd.stdout(a).stderr(b).spawn().map_err(error)?);
    // Root originals stay private. Only authenticated peers receive output.
    // CLI loss does not abort a native supervisor before its bounded cleanup.
    let mut connected = notify && wire::write(stream, &Response::Started {}).is_ok();
    let deadline = Instant::now() + limit;
    let code = loop {
        if out_reader.metadata().map_err(error)?.len() > 64 * 1024 * 1024
            || err_reader.metadata().map_err(error)?.len() > 1024 * 1024
        {
            return Err("Work-session output budget exceeded".into());
        }
        stream_output(&mut out_reader, stream, false, &mut connected, deadline)?;
        stream_output(&mut err_reader, stream, true, &mut connected, deadline)?;
        if let Some(status) = child.0.try_wait().map_err(error)? {
            break status.code().unwrap_or(1);
        }
        if Instant::now() >= deadline {
            return Err("Work-session child deadline exceeded; private output retained".into());
        }
        std::thread::sleep(WAIT);
    };
    use std::io::Seek;
    while out_reader.stream_position().map_err(error)? < out_reader.metadata().map_err(error)?.len()
        || err_reader.stream_position().map_err(error)?
            < err_reader.metadata().map_err(error)?.len()
    {
        if Instant::now() >= deadline {
            return Err("Work-session output delivery deadline".into());
        }
        stream_output(&mut out_reader, stream, false, &mut connected, deadline)?;
        stream_output(&mut err_reader, stream, true, &mut connected, deadline)?;
    }
    Ok((code, out))
}

fn reconcile_up(
    shared: &Shared,
    generation: &str,
    state: Option<studio_protocol::sealed_fixture::State>,
) -> Result<()> {
    if let Some(state) = state {
        if state.generation != generation || state.tooling_sha256 != shared.snapshot().caller_hash {
            return Err("Another operation owns the fixture journal; refusing adoption".into());
        }
        shared.state.lock().unwrap().generation = Some(generation.into());
    }
    Ok(())
}

fn fixture(shared: &Arc<Shared>, stream: &mut UnixStream, op: Fixture) -> Result<()> {
    let exclusive = matches!(op, Fixture::Up {} | Fixture::Down {});
    let _reservation = reserve(shared, false, true, exclusive)?;
    let config = shared.snapshot();
    let mut cmd = command(&selected_tool(&config)?);
    cmd.arg("network-acceptance");
    let mut supervise = false;
    let mut up: Option<String> = None;
    let mut down = false;
    match op {
        Fixture::Up {} => {
            if shared.state.lock().unwrap().generation.is_some() || fixture_state()?.is_some() {
                return Err("Existing fixture is not adopted or replaced".into());
            }
            let generation = studio_protocol::id_text(studio_protocol::new_id()?);
            cmd.args(["up-owned", &generation]);
            up = Some(generation);
        }
        Fixture::Down {} => {
            own_fixture(shared)?;
            cmd.arg("down");
            down = true;
        }
        Fixture::Status {} => {
            own_fixture(shared)?;
            cmd.arg("status");
        }
        Fixture::Supervise {
            case,
            driver,
            prior,
        } => {
            own_fixture(shared)?;
            if prior
                .as_ref()
                .is_some_and(|n| !shared.state.lock().unwrap().runs.contains(n))
            {
                return Err("Pause run belongs to another work session".into());
            }
            cmd.args(["supervise", &case])
                .arg(driver)
                .arg(config.uid.to_string())
                .arg(&config.runner_hash);
            if let Some(n) = prior {
                cmd.arg(n);
            }
            supervise = true;
        }
    }
    let result = run_job(
        shared,
        stream,
        cmd,
        Duration::from_secs(if supervise { 130 } else { 45 }),
        true,
    );
    if let Some(generation) = up {
        // An Up failure can leave a partial native journal. Only the nonce
        // minted before this exact launch may be adopted for later cleanup.
        reconcile_up(shared, &generation, fixture_state()?)?;
    }
    let (code, out) = result?;
    if down && code == 0 {
        shared.state.lock().unwrap().generation = None;
    }
    if supervise {
        // Only this protected child's ticket grants export rights; user-supplied nonces do not.
        let mut data = String::new();
        File::open(out)
            .map_err(error)?
            .take(wire::MAX_FRAME as u64)
            .read_to_string(&mut data)
            .map_err(error)?;
        if let Some(line) = data.lines().next()
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(line)
            && let (Some(n), Some(g)) = (v["nonce"].as_str(), v["seal_generation"].as_str())
        {
            let mut s = shared.state.lock().unwrap();
            if wire::valid_hex(n, 32) && s.generation.as_deref() == Some(g) {
                s.runs.insert(n.into());
            }
        }
    }

    wire::write(stream, &Response::Done { code })
}
fn export(shared: &Arc<Shared>, stream: &mut UnixStream, nonce: String) -> Result<()> {
    let _reservation = reserve(shared, false, true, false)?;
    if !shared.state.lock().unwrap().runs.contains(&nonce) {
        return Err("Evidence does not belong to this work session".into());
    }
    let mut cmd = command(Path::new("/usr/bin/tar"));
    cmd.args([
        "-C",
        studio_platform::sealed_fixture::STATE_DIR,
        "-cf",
        "-",
        &format!("run-{nonce}"),
    ]);
    let (code, _) = run_job(shared, stream, cmd, Duration::from_secs(30), true)?;
    wire::write(stream, &Response::Done { code })
}
struct Closing(Arc<Shared>);
impl Drop for Closing {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        if !state.stopping {
            state.closing = false;
        }
    }
}

fn handle(shared: &Arc<Shared>, mut stream: UnixStream) -> Result<()> {
    let owner = authenticate(&stream, shared)?;
    let request: Request =
        wire::read(&mut stream, Duration::from_secs(3), &AtomicBool::new(false))?;
    wire::validate_request(&request, &shared.snapshot(), &owner)?;
    // Revalidate process incarnation after receiving a possibly slow frame.
    owner.verify(&stream)?;
    match request {
        Request::Status {} => wire::write(
            &mut stream,
            &Response::Status {
                config: shared.snapshot(),
                active: shared.state.lock().unwrap().active,
            },
        ),
        Request::Stop {} => {
            {
                let mut s = shared.state.lock().unwrap();
                if s.active != 0 || s.closing {
                    return Err("Active jobs or helper leases remain; stop refused".into());
                }
                s.closing = true;
            }
            let _closing = Closing(shared.clone());
            if shared.state.lock().unwrap().generation.is_some() {
                if let Err(e) = own_fixture(shared) {
                    shared.state.lock().unwrap().closing = false;
                    return Err(e);
                }
                let mut cmd = command(&selected_tool(&shared.snapshot())?);
                cmd.args(["network-acceptance", "down"]);
                let result = run_job(shared, &mut stream, cmd, Duration::from_secs(45), false);
                match result {
                    Ok((0, _)) => {}
                    Ok(_) => {
                        shared.state.lock().unwrap().closing = false;
                        return Err("Fixture cleanup failed; host retained".into());
                    }
                    Err(e) => {
                        shared.state.lock().unwrap().closing = false;
                        return Err(e);
                    }
                }
            }
            shared.state.lock().unwrap().stopping = true;
            wire::write(&mut stream, &Response::Done { code: 0 })
        }
        Request::Helper {
            hash,
            endpoint,
            owner,
        } => helper(shared, &mut stream, hash, endpoint, owner),
        Request::Fixture { operation } => fixture(shared, &mut stream, operation),
        Request::Export { nonce } => export(shared, &mut stream, nonce),
        Request::Stage { tool, runner } => stage(shared, &mut stream, tool, runner),
    }
}
fn serve(uid: u32, runner_hash: String, caller_hash: String) -> Result<()> {
    if Identity::current()?.uid != 0 {
        return Err("Work-session host requires administrator launch".into());
    }
    let exe = std::env::current_exe().map_err(error)?;
    let hash = studio_platform::trusted::file_hash(&exe)?;
    let config = Config {
        uid,
        pid: std::process::id(),
        tool_hash: hash,
        runner_hash,
        caller_hash,
    };
    wire::validate_config(&config)?;
    if exe != protected_tool(&config)? {
        return Err("Work-session host must be the protected installed tool".into());
    }
    let runner = studio_platform::macos::installed_path(&config.runner_hash)?;
    studio_platform::trusted::verify(&runner, &config.runner_hash)?;
    // Global fixture state is shared across users; only one host may own it.
    let lock_path = Path::new("/Library/PrivilegedHelperTools/MasscanStudio/work-fixture.lock");
    let lock = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(lock_path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            wire::protected(lock_path, false)?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(lock_path)
                .map_err(error)?
        }
        Err(e) => return Err(error(e)),
    };
    lock.try_lock()
        .map_err(|_| "Another work-session host owns the fixture lock")?;
    let dir = wire::directory(uid);
    wire::protected(dir.parent().unwrap(), false)?;
    fs::DirBuilder::new()
        .mode(0o711)
        .create(&dir)
        .map_err(error)?;
    let listener = UnixListener::bind(dir.join("socket")).map_err(error)?;
    fs::set_permissions(dir.join("socket"), fs::Permissions::from_mode(0o666)).map_err(error)?;
    listener.set_nonblocking(true).map_err(error)?;
    let mut meta = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o644)
        .open(dir.join("host.json"))
        .map_err(error)?;
    meta.write_all(&serde_json::to_vec(&config).map_err(error)?)
        .map_err(error)?;
    meta.sync_all().map_err(error)?;
    let shared = Arc::new(Shared {
        config,
        dir,
        state: Mutex::new(State::new()),
        sequence: AtomicUsize::new(0),
    });
    let connections = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    while !shared.state.lock().unwrap().stopping {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Lease slots are separate from connection slots, so status/stop still work.
                if connections.load(Ordering::Acquire) >= 16 {
                    let _ = wire::write(
                        &mut stream,
                        &Response::Error {
                            message: "Too many work-session connections".into(),
                        },
                    );
                    continue;
                }
                connections.fetch_add(1, Ordering::AcqRel);
                let counter = connections.clone();
                let host = shared.clone();
                threads.push(std::thread::spawn(move || {
                    let reply = stream.try_clone();
                    if let Err(message) = handle(&host, stream)
                        && let Ok(mut reply) = reply
                    {
                        let _ = wire::write(&mut reply, &Response::Error { message });
                    }
                    counter.fetch_sub(1, Ordering::AcqRel);
                }));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(WAIT),
            Err(e) => return Err(error(e)),
        }
        let mut i = 0;
        while i < threads.len() {
            if threads[i].is_finished() {
                let t = threads.swap_remove(i);
                let _ = t.join();
            } else {
                i += 1;
            }
        }
    }
    for t in threads {
        let _ = t.join();
    }
    // Keep root-owned job records for inspection; only remove the live endpoint
    // and metadata. Rename the directory so the next explicit start is fresh.
    drop(listener);
    fs::remove_file(shared.dir.join("socket")).map_err(error)?;
    fs::remove_file(shared.dir.join("host.json")).map_err(error)?;
    let archived = shared
        .dir
        .with_file_name(format!("work-{uid}-ended-{}", shared.config.pid));
    fs::rename(&shared.dir, archived).map_err(error)?;
    Ok(())
}
fn request(request: Request) -> Result<()> {
    let (mut stream, _) =
        wire::connect()?.ok_or("No working session; run work-session start RUNNER once")?;
    wire::write(&mut stream, &request)?;
    let deadline = Instant::now() + Duration::from_secs(150);
    loop {
        let timeout = deadline.saturating_duration_since(Instant::now());
        match wire::read(&mut stream, timeout, &AtomicBool::new(false))? {
            Response::Status { config, active } => {
                println!(
                    "{}",
                    serde_json::json!({"state":"ready","active":active,"config":config})
                );
                return Ok(());
            }
            Response::Started {} => {}
            Response::Output { stderr, bytes } => {
                if stderr {
                    std::io::stderr().write_all(&bytes).map_err(error)?;
                    std::io::stderr().flush().map_err(error)?;
                } else {
                    std::io::stdout().write_all(&bytes).map_err(error)?;
                    std::io::stdout().flush().map_err(error)?;
                }
            }
            Response::Done { code } => {
                return if code == 0 {
                    Ok(())
                } else {
                    Err(format!("Work-session operation exited {code}"))
                };
            }
            Response::Error { message } => return Err(message),
            _ => return Err("Unexpected work-session response".into()),
        }
    }
}

fn build(path: &Path) -> Result<wire::Build> {
    let path = fs::canonicalize(path).map_err(error)?;
    let sha256 = studio_platform::trusted::file_hash(&path)?;
    Ok(wire::Build { path, sha256 })
}
fn start(root: &Path, runner: &Path, replace: bool) -> Result<()> {
    let previous = wire::connect()?.map(|(_, config)| config);
    if previous.is_some() && !replace {
        return request(Request::Status {});
    }
    let owner = Identity::current()?;
    let exe = std::env::current_exe().map_err(error)?;
    let hash = studio_platform::trusted::file_hash(&exe)?;
    let runner = fs::canonicalize(runner).map_err(error)?;
    let runner_hash = studio_platform::trusted::file_hash(&runner)?;
    let tool_dir = super::runner_setup::prepare_source(root, &exe).map_err(error)?;
    let mut script = String::from("set -eu\nexport PATH=/usr/bin:/bin:/usr/sbin:/sbin\n");
    let installed = studio_platform::macos::installed_path(&hash)?;
    if installed.exists() {
        studio_platform::trusted::verify(&installed, &hash)?;
    } else {
        script.push_str("(\n");
        script.push_str(&fs::read_to_string(tool_dir.join("install.sh")).map_err(error)?);
        script.push_str("\n)\n");
    }
    let installed_runner = studio_platform::macos::installed_path(&runner_hash)?;
    if installed_runner.exists() {
        studio_platform::trusted::verify(&installed_runner, &runner_hash)?;
    } else {
        let p = super::runner_setup::prepare_source(root, &runner).map_err(error)?;
        script.push_str("(\n");
        script.push_str(&fs::read_to_string(p.join("install.sh")).map_err(error)?);
        script.push_str("\n)\n");
    }
    if let Some(old) = &previous {
        let old_client = selected_tool(old)?;
        let old_dir = wire::directory(old.uid);
        script.push_str(&format!(
            "/usr/bin/sudo -u '#{}' -- {} work-session stop\n\
             n=0\nwhile /bin/kill -0 {} 2>/dev/null || test -e {}; do\n\
             n=$((n+1))\ntest \"$n\" -lt 200 || exit 1\n/bin/sleep 0.1\ndone\n",
            old.uid,
            studio_platform::macos::shell_quote(old_client.to_str().ok_or("non-UTF8 old tool")?)?,
            old.pid,
            studio_platform::macos::shell_quote(old_dir.to_str().ok_or("non-UTF8 old directory")?)?,
        ));
    }
    script.push_str(&format!(
        "exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C {} work-session serve {} {} {}\n",
        studio_platform::macos::shell_quote(installed.to_str().ok_or("non-UTF8 tool")?)?,
        owner.uid,
        runner_hash,
        hash
    ));
    let mut launcher = Command::new("/usr/bin/osascript")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .args(["-e", &studio_platform::macos::applescript(&script)])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(error)?;
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if matches!(wire::connect(), Ok(Some((_, c))) if c.tool_hash == hash && previous.as_ref().is_none_or(|p| p.pid != c.pid))
        {
            // Child::drop does not terminate the launcher. The explicitly started
            // host and its authorization outlive this CLI until work-session stop.
            return request(Request::Status {});
        }
        if launcher.try_wait().map_err(error)?.is_some() {
            let mut output = String::new();
            if let Some(out) = launcher.stdout.take() {
                out.take(32768).read_to_string(&mut output).map_err(error)?;
            }
            if let Some(err) = launcher.stderr.take() {
                err.take(32768).read_to_string(&mut output).map_err(error)?;
            }
            return Err(format!("Working-session launch failed: {output}"));
        }
        if Instant::now() >= deadline {
            let _ = launcher.kill();
            let _ = launcher.wait();
            return Err("Working-session authorization/start timed out".into());
        }
        std::thread::sleep(WAIT);
    }
}

pub fn main_entry(root: &Path) -> Result<()> {
    let args = std::env::args().skip(2).collect::<Vec<_>>();
    let a = args.iter().map(String::as_str).collect::<Vec<_>>();
    match a.as_slice(){
  ["start",runner]=>start(root,Path::new(runner),false),
  ["replace",runner]=>start(root,Path::new(runner),true),
  ["stage",tool,runner]=>request(Request::Stage{tool:build(Path::new(tool))?,runner:build(Path::new(runner))?}),["status"]=>request(Request::Status{}),["stop"]=>request(Request::Stop{}),
  ["probe",runner]=>{
      let(_,config)=wire::connect()?.ok_or("No working session; probe will not request a password")?;
      if studio_platform::trusted::file_hash(Path::new(runner))?!=config.runner_hash{return Err("Probe helper differs from working session".into());}
      super::runner_setup::probe_source(Path::new(runner)).map_err(error)
  },
  ["serve",uid,runner,caller]=>serve(uid.parse().map_err(error)?,(*runner).into(),(*caller).into()),
  ["fixture","up"]=>request(Request::Fixture{operation:Fixture::Up{}}),["fixture","down"]=>request(Request::Fixture{operation:Fixture::Down{}}),["fixture","status"]=>request(Request::Fixture{operation:Fixture::Status{}}),
  ["fixture","supervise",case,driver]=>request(Request::Fixture{operation:Fixture::Supervise{case:(*case).into(),driver:(*driver).into(),prior:None}}),
  ["fixture","supervise",case,driver,prior]=>request(Request::Fixture{operation:Fixture::Supervise{case:(*case).into(),driver:(*driver).into(),prior:Some((*prior).into())}}),
  ["export",nonce]=>request(Request::Export{nonce:(*nonce).into()}),
  _=>Err("Usage: work-session start/replace RUNNER | stage TOOL RUNNER | status | stop | probe RUNNER | fixture up/down/status | fixture supervise CASE DIR [PAUSE_NONCE] | export NONCE".into())
 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    fn shared() -> Arc<Shared> {
        let owner = Identity::current().unwrap();
        let path = std::env::temp_dir().join(format!(
            "studio-work-test-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        fs::create_dir(&path).unwrap();
        Arc::new(Shared {
            config: Config {
                uid: owner.uid,
                pid: owner.pid,
                tool_hash: "a".repeat(64),
                runner_hash: "b".repeat(64),
                caller_hash: studio_platform::trusted::file_hash(&owner.executable).unwrap(),
            },
            dir: path,
            state: Mutex::new(State::new()),
            sequence: AtomicUsize::new(0),
        })
    }
    #[test]
    fn staged_copy_pins_requested_bytes_and_does_not_replace_existing_files() {
        let host = shared();
        let source = host.dir.join("source");
        fs::write(&source, b"first reviewed bytes").unwrap();
        let build = build(&source).unwrap();
        let target = host.dir.join("copy");
        copy_build(&build, host.config.uid, &target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"first reviewed bytes");
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o600);
        assert!(copy_build(&build, host.config.uid, &target).is_err());
        fs::write(&source, b"changed after selection").unwrap();
        assert!(
            copy_build(&build, host.config.uid, &host.dir.join("changed"))
                .unwrap_err()
                .contains("hash changed")
        );
        fs::remove_dir_all(&host.dir).unwrap();
    }
    #[test]
    fn staging_requires_idle_session_without_owned_fixture() {
        let host = shared();
        let helper = reserve(&host, true, false, false).unwrap();
        assert!(reserve_stage(&host).is_err());
        drop(helper);
        host.state.lock().unwrap().generation = Some("1".repeat(32));
        assert!(reserve_stage(&host).is_err());
        assert_eq!(host.state.lock().unwrap().active, 0);
        host.state.lock().unwrap().generation = None;
        let stage = reserve_stage(&host).unwrap();
        assert!(reserve_stage(&host).is_err());
        assert!(reserve(&host, true, false, false).is_err());
        drop(stage);
        fs::remove_dir(&host.dir).unwrap();
    }
    #[test]
    fn selection_keeps_host_identity_and_previous_clients_and_is_atomic_on_failure() {
        let host = shared();
        let original = host.snapshot();
        publish_selection(&host, "c".repeat(64), "d".repeat(64)).unwrap();
        let selected = host.snapshot();
        assert_eq!(selected.tool_hash, original.tool_hash);
        assert_eq!(selected.pid, original.pid);
        assert_eq!(selected.caller_hash, "c".repeat(64));
        assert_eq!(selected.runner_hash, "d".repeat(64));
        assert_eq!(
            serde_json::from_slice::<Config>(&fs::read(host.dir.join("host.json")).unwrap())
                .unwrap(),
            selected
        );
        let (a, _b) = UnixStream::pair().unwrap();
        authenticate(&a, &host).unwrap(); // original client still authorized
        publish_selection(&host, "e".repeat(64), "f".repeat(64)).unwrap();
        assert!(host.state.lock().unwrap().callers.contains(&"c".repeat(64)));
        let before_failure = host.snapshot();
        fs::remove_file(host.dir.join("host.json")).unwrap();
        fs::create_dir(host.dir.join("host.json")).unwrap();
        assert!(publish_selection(&host, "1".repeat(64), "2".repeat(64)).is_err());
        assert_eq!(host.snapshot(), before_failure);
        assert!(!host.state.lock().unwrap().callers.contains(&"1".repeat(64)));
        assert_eq!(fs::read_dir(&host.dir).unwrap().count(), 1);
        fs::remove_dir_all(&host.dir).unwrap();
    }
    #[test]
    fn selected_client_authentication_and_stale_helper_selection() {
        let mut host = shared();
        let current_hash = host.config.caller_hash.clone();
        Arc::get_mut(&mut host).unwrap().config.caller_hash = "a".repeat(64);
        let (mut client, mut server) = UnixStream::pair().unwrap();
        assert!(authenticate(&server, &host).is_err());
        publish_selection(&host, current_hash, "d".repeat(64)).unwrap();
        let owner = authenticate(&server, &host).unwrap();
        assert!(
            helper(
                &host,
                &mut server,
                "b".repeat(64),
                "/tmp/unused".into(),
                owner
            )
            .unwrap_err()
            .contains("selection changed")
        );
        assert_eq!(host.state.lock().unwrap().active, 0);
        wire::write(&mut client, &Request::Status {}).unwrap();
        handle(&host, server).unwrap();
        assert!(matches!(
            wire::read::<Response>(&mut client, Duration::from_secs(1), &AtomicBool::new(false))
                .unwrap(),
            Response::Status { active: 0, .. }
        ));
        fs::remove_dir_all(&host.dir).unwrap();
    }
    #[test]
    fn fixture_conflicts_and_capacity_preserve_status_and_next_client() {
        let host = shared();
        let up = reserve(&host, false, true, true).unwrap();
        assert!(reserve(&host, true, false, false).is_err());
        drop(up);
        let supervisor = reserve(&host, false, true, false).unwrap();
        let helper = reserve(&host, true, false, false).unwrap();
        assert!(reserve(&host, false, true, true).is_err());
        drop(helper);
        drop(supervisor);
        let leases = (0..wire::MAX_ACTIVE)
            .map(|_| reserve(&host, true, false, false).unwrap())
            .collect::<Vec<_>>();
        assert!(reserve(&host, true, false, false).is_err());
        let (mut client, server) = UnixStream::pair().unwrap();
        wire::write(&mut client, &Request::Status {}).unwrap();
        handle(&host, server).unwrap();
        assert!(matches!(
            wire::read::<Response>(&mut client, Duration::from_secs(1), &AtomicBool::new(false))
                .unwrap(),
            Response::Status { active: 8, .. }
        ));
        let (mut client, server) = UnixStream::pair().unwrap();
        wire::write(&mut client, &Request::Stop {}).unwrap();
        assert!(handle(&host, server).unwrap_err().contains("Active jobs"));
        drop(leases);
        let next = reserve(&host, true, false, false).unwrap();
        assert_eq!(host.state.lock().unwrap().active, 1);
        drop(next);
        assert_eq!(host.state.lock().unwrap().active, 0);
        fs::remove_dir(&host.dir).unwrap();
    }
    #[test]
    fn authenticates_kernel_identity_and_refuses_wrong_hash_or_account() {
        let host = shared();
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(
            authenticate(&a, &host).unwrap(),
            Identity::current().unwrap()
        );
        let mut bad = shared();
        Arc::get_mut(&mut bad).unwrap().config.uid += 1;
        assert!(authenticate(&a, &bad).is_err());
        Arc::get_mut(&mut bad).unwrap().config.uid = host.config.uid;
        Arc::get_mut(&mut bad).unwrap().config.caller_hash = "c".repeat(64);
        assert!(authenticate(&a, &bad).is_err());
        fs::remove_dir(&bad.dir).unwrap();
        fs::remove_dir(&host.dir).unwrap();
    }
    #[test]
    fn partial_up_journal_is_owned_for_recovery_but_foreign_generation_is_not_adopted() {
        let host = shared();
        let generation = "1".repeat(32);
        let state = studio_protocol::sealed_fixture::State {
            version: 1,
            generation: generation.clone(),
            created_utc_seconds: 1,
            expires_utc_seconds: 1801,
            tooling_sha256: host.snapshot().caller_hash,
            sealed: false,
            scanner: None,
            peer: None,
            route: None,
        };
        reconcile_up(&host, &generation, Some(state.clone())).unwrap();
        assert_eq!(
            host.state.lock().unwrap().generation.as_deref(),
            Some(generation.as_str())
        );
        // Failed Up reservation releases; cleanup can then reserve exclusively.
        let down = reserve(&host, false, true, true).unwrap();
        drop(down);
        host.state.lock().unwrap().generation = None;
        assert!(reconcile_up(&host, &"2".repeat(32), Some(state)).is_err());
        assert!(host.state.lock().unwrap().generation.is_none());
        fs::remove_dir(&host.dir).unwrap();
    }
    #[test]
    fn repeated_lease_eof_reaps_only_owned_child_and_preserves_host() {
        let host = shared();
        for _ in 0..2 {
            let reservation = reserve(&host, true, false, false).unwrap();
            let (client, mut server) = UnixStream::pair().unwrap();
            let child = ChildOwner(Command::new("/bin/sleep").arg("30").spawn().unwrap());
            let worker = std::thread::spawn(move || {
                let mut child = child;
                serve_lease(&mut server, &mut child, Duration::from_millis(20)).unwrap();
                drop(child);
                drop(reservation);
            });
            drop(client);
            worker.join().unwrap();
            assert_eq!(host.state.lock().unwrap().active, 0);
            assert!(!host.state.lock().unwrap().stopping);
        }
        fs::remove_dir(&host.dir).unwrap();
    }
    #[test]
    fn job_output_is_private_and_streamed_over_authenticated_connection() {
        let host = shared();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let h = host.clone();
        let worker = std::thread::spawn(move || {
            let mut c = command(Path::new("/usr/bin/printf"));
            c.arg("fixture-ticket\n");
            let (code, path) = run_job(&h, &mut server, c, Duration::from_secs(2), true).unwrap();
            wire::write(&mut server, &Response::Done { code }).unwrap();
            path
        });
        let mut got = Vec::new();
        loop {
            match wire::read::<Response>(
                &mut client,
                Duration::from_secs(3),
                &AtomicBool::new(false),
            )
            .unwrap()
            {
                Response::Output {
                    stderr: false,
                    bytes,
                } => got.extend(bytes),
                Response::Started {} => {}
                Response::Done { code: 0 } => break,
                other => panic!("{other:?}"),
            }
        }
        let path = worker.join().unwrap();
        assert_eq!(got, b"fixture-ticket\n");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o077, 0);
        assert_eq!(
            fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o077,
            0
        );
        fs::remove_dir_all(&host.dir).unwrap();
    }
}
