//! Temporary root orchestration; every mutable path/child command is owned here.
use super::{
    lifecycle::{self, Attempt, Stamp, Ticket, Window},
    native, read_bounded,
    topology::*,
    witness,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use studio_platform::{
    sealed_fixture::{self, STATE_DIR, evidence::EvidenceDirectory},
    trusted,
};
const FILTER: &str = "net 198.18.42.0/29 or host 198.19.42.2 or ether host 02:ac:42:00:00:01 or ether host 02:ac:42:00:00:02 or ether host 02:ac:42:00:01:02 or ether host 02:ac:42:00:01:03 or ether host 02:ac:42:00:01:04";
type Result<T> = std::result::Result<T, String>;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase {
    pub ticket: Ticket,
    pub driver_pid: u32,
    pub driver_started: Stamp,
    pub start: Stamp,
    pub observed: Stamp,
    pub scan: studio_protocol::Id,
    pub attempt: studio_protocol::Id,
    pub sent: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChildRecord {
    argv: Vec<String>,
    sha256: String,
    pid: u32,
    started: Stamp,
    process_identity: String,
    ready: Option<Stamp>,
    stop_requested: Option<Stamp>,
    ended: Option<Stamp>,
    exit_code: Option<i32>,
    forced: bool,
}
struct OwnedChild {
    child: Child,
    record: ChildRecord,
    reaped: bool,
}
impl OwnedChild {
    fn spawn(argv: Vec<String>, out: File, err: File, origin: Instant) -> Result<Self> {
        let hash = trusted::file_hash(Path::new(argv.first().ok_or("empty child argv")?))?;
        let started = Stamp::now(origin)?;
        let child = Command::new(&argv[0])
            .args(&argv[1..])
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .spawn()
            .map_err(|e| e.to_string())?;
        let pid = child.id();
        let mut owned = Self {
            child,
            reaped: false,
            record: ChildRecord {
                argv,
                sha256: hash,
                pid,
                started,
                process_identity: String::new(),
                ready: None,
                stop_requested: None,
                ended: None,
                exit_code: None,
                forced: false,
            },
        };
        owned.record.process_identity = native::command(&[
            "/bin/ps",
            "-p",
            &pid.to_string(),
            "-o",
            "lstart=",
            "-o",
            "command=",
        ])?;
        if owned.record.process_identity.trim().is_empty() {
            return Err("owned child process identity missing".into());
        }
        Ok(owned)
    }
    fn poll(&mut self, origin: Instant) -> Result<bool> {
        if self.reaped {
            return Ok(true);
        }
        if let Some(status) = self.child.try_wait().map_err(|e| e.to_string())? {
            self.reaped = true;
            self.record.ended = Some(Stamp::now(origin)?);
            self.record.exit_code = status.code();
            return Ok(true);
        }
        Ok(false)
    }
    fn require_alive(&mut self, origin: Instant) -> Result<()> {
        if self.poll(origin)? {
            Err("owned child exited before requested shutdown".into())
        } else {
            Ok(())
        }
    }
    fn interrupt(&mut self, origin: Instant) -> Result<()> {
        self.require_alive(origin)?;
        self.record.stop_requested = Some(Stamp::now(origin)?);
        // This pid comes only from our still-unreaped Child. If it exits here,
        // its zombie retains the pid until our wait; no supplied pid is used.
        native::command(&["/bin/kill", "-INT", &self.child.id().to_string()])?;
        self.finish(origin, Instant::now() + Duration::from_secs(5))
    }
    fn finish(&mut self, origin: Instant, deadline: Instant) -> Result<()> {
        while !self.poll(origin)? {
            if Instant::now() >= deadline {
                self.force(origin)?;
                return Err("owned child stop deadline expired".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if self.record.exit_code != Some(0) {
            return Err("owned child abnormal exit".into());
        }
        Ok(())
    }
    fn force(&mut self, origin: Instant) -> Result<()> {
        if !self.reaped {
            self.record.forced = true;
            self.child.kill().map_err(|e| e.to_string())?;
            let status = self.child.wait().map_err(|e| e.to_string())?;
            self.reaped = true;
            self.record.exit_code = status.code();
            self.record.ended = Some(Stamp::now(origin)?);
        }
        Ok(())
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    schema: u32,
    window: Window,
    children: Vec<ChildRecord>,
    uplink: String,
    route_observation: String,
    seal: studio_protocol::sealed_fixture::State,
    driver_uid: u32,
    guard: Option<Phase>,
    drift: Option<Stamp>,
    hashes: BTreeMap<String, String>,
    failure: Option<String>,
}
fn create(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())
}
fn json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut f = create(path)?;
    f.write_all(&serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}
fn text(path: &Path) -> Result<String> {
    String::from_utf8(read_bounded(path, 65536)?).map_err(|e| e.to_string())
}
fn lock() -> Result<File> {
    let p = Path::new(STATE_DIR).join("supervisor.lock");
    let f = match create(&p) {
        Ok(f) => f,
        Err(_) => {
            sealed_fixture::trusted(&p, false, Instant::now() + Duration::from_secs(2), &|| {
                false
            })?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(p)
                .map_err(|e| e.to_string())?
        }
    };
    f.try_lock()
        .map_err(|_| "another supervisor owns fixture")?;
    Ok(f)
}
fn ready(
    child: &mut OwnedChild,
    path: &Path,
    needle: &str,
    origin: Instant,
    deadline: Instant,
) -> Result<()> {
    loop {
        child.require_alive(origin)?;
        if text(path)?.lines().any(|l| l.starts_with(needle)) {
            child.record.ready = Some(Stamp::now(origin)?);
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("child readiness deadline expired".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn valid_case(case: &str) -> bool {
    matches!(
        case,
        "complete" | "pause" | "resume" | "stop-preparing" | "stop-running" | "guard"
    )
}

pub fn supervise(
    case: &str,
    driver: &Path,
    uid: u32,
    runner_hash: &str,
    previous: Option<&str>,
) -> Result<()> {
    if !valid_case(case)
        || runner_hash.len() != 64
        || !runner_hash.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err("invalid case/runner SHA256".into());
    }
    let prior = match previous {
        Some(n)
            if case == "resume" && n.len() == 32 && n.bytes().all(|c| c.is_ascii_hexdigit()) =>
        {
            Some(Path::new(STATE_DIR).join(format!("run-{n}")))
        }
        None if case != "resume" => None,
        _ => return Err("Resume requires exactly one prior root-owned pause run nonce".into()),
    };
    // Explicit root invocation only. The executable path and its parents must
    // already be root-owned and immutable to the unprivileged driver.
    if native::command(&["/usr/bin/id", "-u"])?.trim() != "0" {
        return Err("supervise requires explicit reviewed root grant".into());
    }
    let exe = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let exe_hash = trusted::file_hash(&exe)?;
    trusted::verify(&exe, &exe_hash)?;
    let tcpdump = Path::new("/usr/sbin/tcpdump");
    trusted::verify(tcpdump, &trusted::file_hash(tcpdump)?)?;
    let state = native::supervision_state()?;
    if state.tooling_sha256 != exe_hash {
        return Err("supervisor binary differs from sealed tooling".into());
    }
    let _lock = lock()?;
    let reader = EvidenceDirectory::open(driver, uid)?;
    if reader
        .read(
            &format!("prepared-{case}"),
            64,
            Instant::now() + Duration::from_secs(1),
        )?
        .as_deref()
        != Some(b"prepared\n")
    {
        return Err("prepare driver directory before supervisor".into());
    }
    let route = native::command(&["/sbin/route", "-n", "get", "default"])?;
    let names = route
        .lines()
        .filter_map(|l| l.trim().strip_prefix("interface:").map(str::trim))
        .collect::<Vec<_>>();
    if names.len() != 1
        || names[0].is_empty()
        || !names[0].bytes().all(|c| c.is_ascii_alphanumeric())
        || [SCANNER, PEER].contains(&names[0])
    {
        return Err("cannot identify actual default uplink".into());
    }
    let uplink = names[0].to_string();
    let all = sealed_fixture::observations(Instant::now() + Duration::from_secs(3), &|| false)?;
    if !all.iter().any(|o| {
        o.iface.name == uplink && o.iface.up && o.iface.ethernet && !o.iface.ipv4.is_empty()
    }) {
        return Err("observed uplink is not active Ethernet/Wi-Fi".into());
    }
    let nonce = studio_protocol::id_text(studio_protocol::new_id()?);
    let dir = Path::new(STATE_DIR).join(format!("run-{nonce}"));
    fs::create_dir(&dir).map_err(|e| e.to_string())?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let origin = Instant::now();
    let opened = Stamp::now(origin)?;
    let deadline = origin + Duration::from_secs(120);
    let sampler = lifecycle::Sampler::start(origin, opened.clone());
    let mut children = Vec::<OwnedChild>::new();
    let mut ticket = None;
    let mut guard = None;
    let mut drift = None;
    let mut peer_stopped = false;
    let mut attempt = None;
    let outcome = (|| -> Result<()> {
        for (name, iface) in [("peer", PEER), ("uplink", uplink.as_str())] {
            let mut argv = vec![
                "/usr/sbin/tcpdump".into(),
                "-p".into(),
                "-n".into(),
                "-U".into(),
                "-s".into(),
                "0".into(),
                "-i".into(),
                iface.into(),
                "-w".into(),
                dir.join(format!("{name}.pcap")).display().to_string(),
            ];
            if name == "uplink" {
                argv.push(FILTER.into());
            }
            children.push(OwnedChild::spawn(
                argv,
                create(&dir.join(format!("{name}.stdout")))?,
                create(&dir.join(format!("{name}.stderr")))?,
                origin,
            )?);
            ready(
                children.last_mut().ok_or("missing capture")?,
                &dir.join(format!("{name}.stderr")),
                &format!("tcpdump: listening on {iface},"),
                origin,
                Instant::now() + Duration::from_secs(5),
            )?;
        }
        children.push(OwnedChild::spawn(
            vec![
                exe.display().to_string(),
                "network-acceptance".into(),
                "peer".into(),
            ],
            create(&dir.join("raw-peer.stdout"))?,
            create(&dir.join("raw-peer.stderr"))?,
            origin,
        )?);
        ready(
            &mut children[2],
            &dir.join("raw-peer.stdout"),
            "peer ready:",
            origin,
            Instant::now() + Duration::from_secs(10),
        )?;
        native::supervision_check(&state, true)?;
        let t = Ticket {
            nonce: nonce.clone(),
            case: case.into(),
            seal_generation: state.generation.clone(),
            tooling_sha256: exe_hash.clone(),
            runner_sha256: runner_hash.into(),
            ready: Stamp::now(origin)?,
        };
        json(&dir.join("ticket.json"), &t)?;
        println!("{}", serde_json::to_string(&t).map_err(|e| e.to_string())?);
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        ticket = Some(t.clone());
        // Startup can block on BPF/readiness. Never pretend dense samples cover it;
        // only the window after ready is used for timing attestation.

        loop {
            let now = Stamp::now(origin)?;
            for name in [
                "peer.pcap",
                "uplink.pcap",
                "peer.stderr",
                "uplink.stderr",
                "raw-peer.stdout",
                "raw-peer.stderr",
            ] {
                let limit = if name.ends_with("pcap") {
                    witness::MAX_CAPTURE
                } else {
                    65536
                };
                if fs::metadata(dir.join(name))
                    .map_err(|e| e.to_string())?
                    .len()
                    > limit as u64
                {
                    return Err("capture/child output exceeds bounded size".into());
                }
            }
            if Instant::now() >= deadline {
                return Err("supervision120-second deadline expired".into());
            }
            for c in children.iter_mut().take(if peer_stopped { 2 } else { 3 }) {
                c.require_alive(origin)?;
            }
            if case == "guard"
                && guard.is_none()
                && let Some(bytes) = reader.read(
                    "guard-phase.json",
                    65536,
                    Instant::now() + Duration::from_secs(1),
                )?
            {
                let phase: Phase = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                if phase.ticket != t
                    || phase.driver_pid == 0
                    || phase.sent < 4
                    || phase.sent >= 96
                    || phase.scan == [0; 16]
                    || phase.attempt == [0; 16]
                {
                    return Err("guard phase/ticket/attempt invalid".into());
                }
                lifecycle::clocks(&[
                    phase.driver_started.clone(),
                    phase.start.clone(),
                    phase.observed.clone(),
                ])?;
                if phase.observed.high()? >= now.low()? {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                native::stop_peer()?;
                children[2].record.stop_requested = Some(Stamp::now(origin)?);
                children[2].finish(origin, Instant::now() + Duration::from_secs(5))?;
                peer_stopped = true;
                native::guard_down(&state)?;
                drift = Some(Stamp::now(origin)?);
                guard = Some(phase);
            }
            if let Some(bytes) = reader.read(
                &format!("{case}-attempt.json"),
                1_048_576,
                Instant::now() + Duration::from_secs(1),
            )? {
                let a: Attempt = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                if a.ticket != t {
                    return Err("finished attempt ticket differs".into());
                }
                if case == "guard"
                    && guard.as_ref().is_none_or(|g| {
                        g.scan != a.scan
                            || g.attempt != a.attempt
                            || g.driver_pid != a.driver_pid
                            || g.start != a.start
                            || !(4..96).contains(&g.sent)
                    })
                {
                    return Err("guard phase and durable attempt differ".into());
                }
                if now.low()?
                    > a.joined
                        .high()?
                        .max(a.terminal.high()?)
                        .checked_add(lifecycle::QUIET_NS)
                        .ok_or("clock overflow")?
                {
                    json(&dir.join("attempt.json"), &a)?;
                    attempt = Some(a);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        native::supervision_check(&state, case != "guard")?;
        if native::command(&["/sbin/route", "-n", "get", "default"])? != route {
            return Err("actual uplink/default route changed during capture".into());
        }
        Ok(())
    })();
    // Cleanup only children owned by this stack, even when readiness/driver fails.
    let mut failure = outcome.err();
    if children.len() == 3
        && !peer_stopped
        && children[2].record.ready.is_some()
        && !children[2].reaped
    {
        let result = native::stop_peer().and_then(|()| {
            children[2].record.stop_requested = Stamp::now(origin).ok();
            children[2].finish(origin, Instant::now() + Duration::from_secs(5))
        });
        if let Err(e) = result {
            failure.get_or_insert(e);
        }
    }
    for c in children.iter_mut().take(2) {
        if !c.reaped
            && let Err(e) = c.interrupt(origin)
        {
            failure.get_or_insert(e);
        }
    }
    for c in &mut children {
        if !c.reaped {
            let _ = c.force(origin);
            failure.get_or_insert("forced child cleanup".into());
        }
    }
    let (stopped, samples) = sampler.finish()?;
    let health = text(&dir.join("raw-peer.stdout")).ok().and_then(|s| {
        s.lines()
            .last()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
    });
    let peer_drops = health.as_ref().and_then(|v| v["kernel_drops"].as_u64());
    if peer_drops != Some(0) || health.as_ref().is_none_or(|v| v["stop_marker"] != true) {
        failure.get_or_insert("raw peer final health/stop evidence missing".into());
    }
    let fallback = Ticket {
        nonce,
        case: case.into(),
        seal_generation: state.generation.clone(),
        tooling_sha256: exe_hash,
        runner_sha256: runner_hash.into(),
        ready: opened.clone(),
    };
    let mut hashes = BTreeMap::new();
    for name in [
        "peer.pcap",
        "uplink.pcap",
        "peer.stderr",
        "uplink.stderr",
        "raw-peer.stdout",
        "raw-peer.stderr",
        "attempt.json",
        "ticket.json",
    ] {
        if dir.join(name).is_file() {
            hashes.insert(name.into(), trusted::file_hash(&dir.join(name))?);
        }
    }
    let clean = failure.is_none()
        && children.len() == 3
        && children.iter().all(|c| {
            c.reaped
                && !c.record.forced
                && c.record.exit_code == Some(0)
                && c.record.ready.is_some()
                && c.record.stop_requested.is_some()
        });
    let manifest = Manifest {
        schema: 1,
        window: Window {
            ticket: ticket.unwrap_or(fallback),
            opened,
            stopped,
            samples,
            children_clean: clean,
            peer_drops,
        },
        children: children.iter().map(|c| c.record.clone()).collect(),
        uplink,
        route_observation: route,
        seal: state,
        driver_uid: uid,
        guard,
        drift,
        hashes,
        failure,
    };
    json(&dir.join("manifest.json"), &manifest)?;
    eprintln!("Root-owned evidence: {}", dir.display());
    if let Some(e) = manifest.failure {
        return Err(e);
    }
    if attempt.is_none() {
        return Err("no finished attempt evidence".into());
    }
    verify_dir(&dir, prior.as_deref())
}

pub fn verify_dir(dir: &Path, previous: Option<&Path>) -> Result<()> {
    let (a, w, p, ps, u, us) = load(dir)?;
    let old = previous.map(load).transpose()?;
    let checked = old
        .as_ref()
        .map(|(a, w, p, ps, u, us)| {
            lifecycle::verify(
                lifecycle::Input {
                    attempt: a,
                    window: w,
                    peer: p,
                    peer_stats: ps,
                    uplink: u,
                    uplink_stats: us,
                },
                None,
            )
        })
        .transpose()?;
    let result = lifecycle::verify(
        lifecycle::Input {
            attempt: &a,
            window: &w,
            peer: &p,
            peer_stats: &ps,
            uplink: &u,
            uplink_stats: &us,
        },
        old.as_ref()
            .zip(checked.as_ref())
            .map(|((a, ..), c)| (a, c)),
    )?;
    println!(
        "Offline consistency PASS: {} probes, {} correlated replies, cumulative cursor {}. This does not authenticate native capture provenance; review the root-owned originals, reviewed binary hashes and execution record.",
        result.probes.len(),
        result.replies.len(),
        result.cursor
    );
    Ok(())
}
type Loaded = (Attempt, Window, Vec<u8>, String, Vec<u8>, String);
fn load(dir: &Path) -> Result<Loaded> {
    let m: Manifest = serde_json::from_slice(&read_bounded(&dir.join("manifest.json"), 1_048_576)?)
        .map_err(|e| e.to_string())?;
    if m.schema != 1 || m.failure.is_some() || !m.window.children_clean || m.children.len() != 3 {
        return Err("failed/incomplete supervisor manifest".into());
    }
    for name in [
        "peer.pcap",
        "uplink.pcap",
        "peer.stderr",
        "uplink.stderr",
        "raw-peer.stdout",
        "raw-peer.stderr",
        "attempt.json",
        "ticket.json",
    ] {
        if m.hashes.get(name) != Some(&trusted::file_hash(&dir.join(name))?) {
            return Err("evidence artifact hash mismatch".into());
        }
    }
    let a: Attempt = serde_json::from_slice(&read_bounded(&dir.join("attempt.json"), 1_048_576)?)
        .map_err(|e| e.to_string())?;
    validate_manifest(&m, &a)?;
    capture_stats(&text(&dir.join("peer.stderr"))?)?;
    capture_stats(&text(&dir.join("uplink.stderr"))?)?;
    if let Some(drift) = &m.drift {
        let bytes = read_bounded(&dir.join("peer.pcap"), witness::MAX_CAPTURE)?;
        let phase = m.guard.as_ref().ok_or("guard phase missing")?;
        let phase_low = phase.observed.low()?;
        let count = witness::frames(&bytes)?
            .into_iter()
            .filter(|p| {
                p.time_ns + lifecycle::CLOCK_ERROR_NS + 1000
                    < phase_low.min(drift.low().unwrap_or(0))
            })
            .filter(|p| {
                matches!(
                    super::wire::classify(p.frame),
                    Ok(super::wire::Frame::Syn(_))
                )
            })
            .count();
        if count < 4 || count < phase.sent as usize {
            return Err("capture does not prove four probes before guard drift".into());
        }
    }
    Ok((
        a,
        m.window,
        read_bounded(&dir.join("peer.pcap"), witness::MAX_CAPTURE)?,
        text(&dir.join("peer.stderr"))?,
        read_bounded(&dir.join("uplink.pcap"), witness::MAX_CAPTURE)?,
        text(&dir.join("uplink.stderr"))?,
    ))
}
fn validate_manifest(m: &Manifest, a: &Attempt) -> Result<()> {
    if m.window.ticket != a.ticket
        || m.seal.generation != a.ticket.seal_generation
        || m.seal.tooling_sha256 != a.ticket.tooling_sha256
        || m.driver_uid == 0
        || m.driver_uid != a.driver_uid
        || m.children.len() != 3
    {
        return Err("manifest seal/driver identity differs".into());
    }
    studio_protocol::sealed_fixture::validate_state(
        &m.seal,
        m.window.ticket.ready.wall_ns / 1_000_000_000,
    )?;
    if let Some(bytes) = &a.report {
        let report = studio_protocol::NetworkReport::decode(bytes)?;
        if m.seal
            .scanner
            .as_ref()
            .is_none_or(|i| i.index != report.routes.interface_index)
        {
            return Err("frozen report interface differs from supervisor seal".into());
        }
    }
    let mut ids = std::collections::BTreeSet::new();
    for (i, c) in m.children.iter().enumerate() {
        if c.pid == 0
            || !ids.insert(c.pid)
            || c.forced
            || c.exit_code != Some(0)
            || c.process_identity.trim().is_empty()
            || c.sha256.len() != 64
        {
            return Err("child identity/normal exit evidence invalid".into());
        }
        let ready = c.ready.as_ref().ok_or("missing child readiness")?;
        let stop = c.stop_requested.as_ref().ok_or("missing child shutdown")?;
        let ended = c.ended.as_ref().ok_or("missing child reap")?;
        lifecycle::clocks(&[
            c.started.clone(),
            ready.clone(),
            stop.clone(),
            ended.clone(),
        ])?;
        if ready.mono_ns > m.window.ticket.ready.mono_ns || ended.mono_ns > m.window.stopped.mono_ns
        {
            return Err("child window does not cover ticket".into());
        }
        if i < 2 {
            let iface = if i == 0 { PEER } else { &m.uplink };
            let name = if i == 0 { "peer" } else { "uplink" };
            let output = Path::new(STATE_DIR)
                .join(format!("run-{}", a.ticket.nonce))
                .join(format!("{name}.pcap"))
                .display()
                .to_string();
            if c.argv.len() != if i == 0 { 10 } else { 11 }
                || c.argv[..9]
                    != [
                        "/usr/sbin/tcpdump",
                        "-p",
                        "-n",
                        "-U",
                        "-s",
                        "0",
                        "-i",
                        iface,
                        "-w",
                    ]
                || c.argv.get(9) != Some(&output)
                || (i == 1 && c.argv.get(10).map(String::as_str) != Some(FILTER))
                || (i == 1 && c.sha256 != m.children[0].sha256)
                || stop.low()?
                    <= a.joined
                        .high()?
                        .max(a.terminal.high()?)
                        .checked_add(lifecycle::QUIET_NS)
                        .ok_or("clock overflow")?
            {
                return Err("capture argv/shutdown lacks full quiet window".into());
            }
        } else if c.argv.len() != 3
            || c.argv[1..] != ["network-acceptance", "peer"]
            || c.sha256 != a.ticket.tooling_sha256
        {
            return Err("raw peer executable identity/argv differs".into());
        }
    }
    if a.ticket.case == "guard" {
        let g = m.guard.as_ref().ok_or("guard phase missing")?;
        let drift = m.drift.as_ref().ok_or("drift anchor missing")?;
        if g.ticket != a.ticket
            || g.scan != a.scan
            || g.attempt != a.attempt
            || g.driver_pid != a.driver_pid
            || g.start != a.start
            || !(4..96).contains(&g.sent)
            || a.control.as_ref() != Some(&g.observed)
            || g.observed.high()? >= drift.low()?
            || drift.high()? >= a.terminal.low()?
            || m.children[2]
                .ended
                .as_ref()
                .ok_or("peer end missing")?
                .mono_ns
                >= drift.mono_ns
        {
            return Err("guard phase/drift/terminal ordering differs".into());
        }
    } else if m.guard.is_some() || m.drift.is_some() {
        return Err("unexpected guard mutation".into());
    }
    Ok(())
}
fn capture_stats(text: &str) -> Result<()> {
    let captured = witness::stats(text)?;
    let mut received = None;
    let mut interface_drop = None;
    for line in text.lines() {
        let words = line.split_whitespace().collect::<Vec<_>>();
        if words.len() < 3 || !matches!(words[1], "packet" | "packets") {
            continue;
        }
        let n = words[0].parse::<u64>().map_err(|_| "invalid statistics")?;
        match &words[2..] {
            ["captured"] | ["dropped", "by", "kernel"] => {}
            ["received", "by", "filter"] if received.replace(n).is_none() => {}
            ["dropped", "by", "interface"] if interface_drop.replace(n).is_none() && n == 0 => {}
            _ => return Err("unknown/duplicate/nonzero capture statistics".into()),
        }
    }
    if received.is_none_or(|n| n < captured) {
        return Err("missing/inconsistent packets received by filter".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_child_deadline_reaps_only_its_child() {
        let _test_lock = super::super::TEST_PROCESS_LOCK.lock().unwrap();
        let origin = Instant::now();
        let dir = std::env::temp_dir().join(format!(
            "owned-child-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        fs::create_dir(&dir).unwrap();
        let mut survivor = Command::new("/bin/sleep").arg("10").spawn().unwrap();
        let mut c = OwnedChild::spawn(
            vec!["/bin/sleep".into(), "10".into()],
            create(&dir.join("out")).unwrap(),
            create(&dir.join("err")).unwrap(),
            origin,
        )
        .unwrap();
        assert!(
            c.finish(origin, Instant::now())
                .unwrap_err()
                .contains("deadline")
        );
        assert!(c.reaped && c.record.forced);
        assert!(survivor.try_wait().unwrap().is_none());
        survivor.kill().unwrap();
        survivor.wait().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn owned_child_readiness_and_graceful_interrupt_are_measured() {
        let _test_lock = super::super::TEST_PROCESS_LOCK.lock().unwrap();
        let origin = Instant::now();
        let dir = std::env::temp_dir().join(format!(
            "owned-ready-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        fs::create_dir(&dir).unwrap();
        let mut c = OwnedChild::spawn(
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "trap 'exit 0' INT; echo READY; while :; do :; done".into(),
            ],
            create(&dir.join("out")).unwrap(),
            create(&dir.join("err")).unwrap(),
            origin,
        )
        .unwrap();
        ready(
            &mut c,
            &dir.join("out"),
            "READY",
            origin,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        c.interrupt(origin).unwrap();
        assert!(c.reaped && !c.record.forced);
        assert_eq!(c.record.exit_code, Some(0));
        assert!(
            c.record.ready.is_some()
                && c.record.stop_requested.is_some()
                && c.record.ended.is_some()
        );
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn unknown_missing_duplicate_or_dropped_capture_statistics_fail() {
        let good =
            "4 packets captured\n4 packets received by filter\n0 packets dropped by kernel\n";
        assert!(capture_stats(good).is_ok());
        for bad in [
            "4 packets captured\n0 packets dropped by kernel",
            "4 packets captured\n3 packets received by filter\n0 packets dropped by kernel",
            "4 packets captured\n4 packets received by filter\n1 packet dropped by kernel",
        ] {
            assert!(capture_stats(bad).is_err());
        }
        for extra in [
            "1 packet dropped by interface",
            "4 packets received by filter",
            "0 packets unknown",
        ] {
            assert!(capture_stats(&format!("{good}{extra}")).is_err());
        }
    }
    #[test]
    fn readiness_timeout_and_premature_exit_never_become_ready() {
        let _test_lock = super::super::TEST_PROCESS_LOCK.lock().unwrap();
        let origin = Instant::now();
        let dir = std::env::temp_dir().join(format!(
            "owned-not-ready-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        fs::create_dir(&dir).unwrap();
        let mut c = OwnedChild::spawn(
            vec!["/bin/sleep".into(), "10".into()],
            create(&dir.join("out")).unwrap(),
            create(&dir.join("err")).unwrap(),
            origin,
        )
        .unwrap();
        assert!(
            ready(&mut c, &dir.join("out"), "READY", origin, Instant::now())
                .unwrap_err()
                .contains("readiness")
        );
        assert!(c.record.ready.is_none());
        c.force(origin).unwrap();
        let mut c = OwnedChild::spawn(
            vec!["/bin/sleep".into(), "0.05".into()],
            create(&dir.join("out2")).unwrap(),
            create(&dir.join("err2")).unwrap(),
            origin,
        )
        .unwrap();
        assert!(
            ready(
                &mut c,
                &dir.join("out2"),
                "READY",
                origin,
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap_err()
            .contains("before requested")
        );
        assert!(c.reaped && c.record.ready.is_none());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn manifest_requires_exact_owned_children_hashes_windows_seal_and_guard_order() {
        use super::super::ownership::{InterfaceIdentity, OwnedRoute};
        let (a, w) = lifecycle::sample_attempt("guard");
        let stamp = |t: u64| Stamp {
            wall_ns: 100_000_000_000 + t,
            mono_ns: t,
            uncertainty_ns: 0,
        };
        let state = studio_protocol::sealed_fixture::State {
            version: 1,
            generation: a.ticket.seal_generation.clone(),
            created_utc_seconds: 100,
            expires_utc_seconds: 1900,
            tooling_sha256: a.ticket.tooling_sha256.clone(),
            sealed: true,
            scanner: Some(InterfaceIdentity {
                name: SCANNER.into(),
                index: 42,
                mac: SOURCE_MAC,
                peer: Some(PEER.into()),
                ipv4: vec![SOURCE],
                ipv4_prefixes: vec![(SOURCE, 29)],
                bridges: vec![],
                up: true,
            }),
            peer: Some(InterfaceIdentity {
                name: PEER.into(),
                index: 43,
                mac: PEER_MAC,
                peer: Some(SCANNER.into()),
                ipv4: vec![],
                ipv4_prefixes: vec![],
                bridges: vec![],
                up: true,
            }),
            route: Some(OwnedRoute {
                destination: ROUTED.to_string(),
                prefix: 32,
                flags: "UGHS".into(),
                gateway: GATEWAY.to_string(),
                interface: SCANNER.into(),
            }),
        };
        let mut children = Vec::new();
        for (i, name, iface) in [
            (0, "peer", PEER),
            (1, "uplink", "en0"),
            (2, "raw-peer", PEER),
        ] {
            let mut argv = vec![
                "/usr/sbin/tcpdump".into(),
                "-p".into(),
                "-n".into(),
                "-U".into(),
                "-s".into(),
                "0".into(),
                "-i".into(),
                iface.into(),
                "-w".into(),
                Path::new(STATE_DIR)
                    .join(format!("run-{}", a.ticket.nonce))
                    .join(format!("{name}.pcap"))
                    .display()
                    .to_string(),
            ];
            if i == 1 {
                argv.push(FILTER.into());
            }
            if i == 2 {
                argv = vec![
                    "/protected/xtask".into(),
                    "network-acceptance".into(),
                    "peer".into(),
                ];
            }
            children.push(ChildRecord {
                argv,
                sha256: if i < 2 {
                    "f".repeat(64)
                } else {
                    a.ticket.tooling_sha256.clone()
                },
                pid: 100 + i,
                started: stamp(100_000_000),
                process_identity: "synthetic owned process".into(),
                ready: Some(stamp(500_000_000)),
                stop_requested: Some(stamp(if i < 2 {
                    15_100_000_000
                } else {
                    11_100_000_000
                })),
                ended: Some(stamp(if i < 2 {
                    15_200_000_000
                } else {
                    11_200_000_000
                })),
                exit_code: Some(0),
                forced: false,
            });
        }
        let guard = Phase {
            ticket: a.ticket.clone(),
            driver_pid: a.driver_pid,
            driver_started: a.driver_started.clone(),
            start: a.start.clone(),
            observed: a.control.clone().unwrap(),
            scan: a.scan,
            attempt: a.attempt,
            sent: 4,
        };
        let m = Manifest {
            schema: 1,
            window: w,
            children,
            uplink: "en0".into(),
            route_observation: "synthetic default uplink".into(),
            seal: state,
            driver_uid: a.driver_uid,
            guard: Some(guard),
            drift: Some(stamp(11_500_000_000)),
            hashes: BTreeMap::new(),
            failure: None,
        };
        assert!(validate_manifest(&m, &a).is_ok());
        let bytes = serde_json::to_vec(&m).unwrap();
        for change in [
            |m: &mut Manifest| m.children[0].stop_requested = Some(m.window.ticket.ready.clone()),
            |m: &mut Manifest| m.children[1].argv[7] = "foreign0".into(),
            |m: &mut Manifest| m.children[2].sha256 = "e".repeat(64),
            |m: &mut Manifest| m.children[0].forced = true,
            |m: &mut Manifest| m.children[1].exit_code = None,
            |m: &mut Manifest| m.seal.scanner.as_mut().unwrap().index = 99,
            |m: &mut Manifest| m.guard.as_mut().unwrap().attempt = [9; 16],
            |m: &mut Manifest| m.drift = Some(m.window.ticket.ready.clone()),
        ] {
            let mut m: Manifest = serde_json::from_slice(&bytes).unwrap();
            change(&mut m);
            assert!(validate_manifest(&m, &a).is_err());
        }
    }
}
