//! Explicit root fixture operations. No helper installation, firewall change or BPF grant.
use super::{ownership::*, topology::*};
use rmasscan_net::{InterfaceObservation, PhysicalRoutePlan};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const STATE_DIR: &str = "/private/var/run/studio-network-fixture-v1";
const STATE: &str = "/private/var/run/studio-network-fixture-v1/state.json";
type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    generation: String,
    created_utc_seconds: u64,
    expires_utc_seconds: u64,
    tooling_sha256: String,
    sealed: bool,
    scanner: Option<InterfaceIdentity>,
    peer: Option<InterfaceIdentity>,
    route: Option<OwnedRoute>,
}

fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|e| e.to_string())
}

/// Native tools have bounded argv and output, and are killed/reaped at the deadline.
fn command(argv: &[&str]) -> Result<String> {
    let mut child = Command::new(argv[0])
        .args(&argv[1..])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let read = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut b = Vec::new();
            pipe.by_ref().take(65537).read_to_end(&mut b).map(|_| b)
        })
    };
    let out = read(Box::new(child.stdout.take().unwrap()));
    let err = read(Box::new(child.stderr.take().unwrap()));
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            other => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(format!(
                    "native command timed out or failed: {argv:?}: {other:?}"
                ));
            }
        }
    };
    let out = out
        .join()
        .map_err(|_| "native stdout worker panic")?
        .map_err(|e| e.to_string())?;
    let err = err
        .join()
        .map_err(|_| "native stderr worker panic")?
        .map_err(|e| e.to_string())?;
    if out.len() > 65536 || err.len() > 65536 {
        return Err("native command output too large".into());
    }
    if !status?.success() {
        return Err(format!("{argv:?}: {}", String::from_utf8_lossy(&err)));
    }
    String::from_utf8(out).map_err(|e| e.to_string())
}

fn trusted(path: &Path, dir: bool) -> Result<()> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if m.file_type().is_symlink()
        || m.uid() != 0
        || m.mode() & 0o077 != 0
        || (if dir {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1
        })
    {
        return Err(format!("untrusted fixture state {}", path.display()));
    }
    let text = command(&[
        "/bin/ls",
        "-lde",
        "-n",
        path.to_str().ok_or("invalid trusted path")?,
    ])?;
    if text.lines().count() != 1 {
        return Err("extended ACL on fixture state".into());
    }
    Ok(())
}
fn lock(create: bool) -> Result<File> {
    if command(&["/usr/bin/id", "-u"])?.trim() != "0" {
        return Err("fixture mutation/status/peer requires explicit root execution".into());
    }
    let path = Path::new(STATE_DIR);
    if create && !path.try_exists().map_err(|e| e.to_string())? {
        fs::DirBuilder::new()
            .create(path)
            .map_err(|e| e.to_string())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    trusted(path, true)?;
    let path = path.join("lock");
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            trusted(&path, false)?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|e| e.to_string())?
        }
        Err(e) => return Err(e.to_string()),
    };
    file.try_lock()
        .map_err(|_| "another fixture operation owns the lock")?;
    Ok(file)
}
fn save(state: &State) -> Result<()> {
    let temporary = Path::new(STATE_DIR).join("state.next");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec_pretty(state).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    fs::rename(temporary, STATE).map_err(|e| e.to_string())?;
    File::open(STATE_DIR)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}
fn load() -> Result<State> {
    trusted(Path::new(STATE), false)?;
    let state: State = serde_json::from_slice(&super::read_bounded(Path::new(STATE), 8192)?)
        .map_err(|e| e.to_string())?;
    if state.version != 1 {
        return Err("unknown fixture state version".into());
    }
    Ok(state)
}
fn observations() -> Result<Vec<InterfaceObservation>> {
    rmasscan_net::os_interfaces()
        .map_err(|e| e.to_string())?
        .observe(Instant::now() + Duration::from_secs(3), &|| false)
        .map_err(|e| e.to_string())
}
fn identity(name: &str) -> Result<Option<InterfaceIdentity>> {
    let all = observations()?;
    let Some(i) = all.iter().find(|o| o.iface.name == name) else {
        return Ok(None);
    };
    let text = command(&["/sbin/ifconfig", name])?;
    let peer = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("peer: "))
        .filter(|s| *s != "<none>")
        .map(str::to_owned);
    Ok(Some(InterfaceIdentity {
        name: name.into(),
        index: i.iface.index,
        mac: i.iface.mac.ok_or("fixture MAC unavailable")?,
        peer,
        ipv4: {
            let mut addresses = i.iface.ipv4.clone();
            addresses.sort_unstable();
            addresses
        },
        ipv4_prefixes: {
            let mut p: Vec<_> = i
                .ipv4_prefixes
                .iter()
                .map(|p| (p.address, p.length))
                .collect();
            p.sort_unstable();
            p
        },
        bridges: memberships(&command(&["/sbin/ifconfig", "-a"])?, name)?,
        up: i.iface.up,
    }))
}
fn route() -> Result<Option<OwnedRoute>> {
    exact_route(&command(&["/usr/sbin/netstat", "-rn", "-f", "inet"])?)
}

pub fn snapshot() -> Result<PhysicalRoutePlan> {
    let p = rmasscan_net::plan_physical(
        &job().network_targets()?,
        rmasscan_net::os_route_table()
            .map_err(|e| e.to_string())?
            .as_ref(),
        rmasscan_net::os_interfaces()
            .map_err(|e| e.to_string())?
            .as_ref(),
        Instant::now() + Duration::from_secs(10),
        &|| false,
    )
    .map_err(|e| e.to_string())?;
    validate_plan(&p)?;
    let all = observations()?;
    validate_interfaces(&all, true)?;
    let scanner = all
        .iter()
        .find(|o| o.iface.name == SCANNER)
        .ok_or("scanner absent")?;
    let peer = all
        .iter()
        .find(|o| o.iface.name == PEER)
        .ok_or("peer absent")?;
    if scanner.iface.ipv4 != [SOURCE]
        || scanner.ipv4_prefixes
            != [rmasscan_net::Ipv4Prefix {
                address: SOURCE,
                length: 29,
            }]
        || !peer.iface.ipv4.is_empty()
        || !peer.iface.up
        || peer.iface.mac != Some(PEER_MAC)
    {
        return Err("fixture aliases/prefix/peer identity changed".into());
    }
    let text = command(&["/sbin/ifconfig", "-a"])?;
    if text.lines().any(|l| {
        l.split_whitespace().any(|w| w == "member:") && (l.contains(SCANNER) || l.contains(PEER))
    }) {
        return Err("fixture interface is bridged".into());
    }
    for (name, other) in [(SCANNER, PEER), (PEER, SCANNER)] {
        if identity(name)?.and_then(|i| i.peer).as_deref() != Some(other) {
            return Err("fixture peer relation changed".into());
        }
    }
    Ok(p)
}

pub fn status() -> Result<()> {
    let _lock = lock(false)?;
    let state = load()?;
    check_owned(&state)?;
    println!(
        "{}",
        serde_json::json!({"sealed":state.sealed,"plan":format!("{:?}",snapshot()?),"native_execution":"requires separately reviewed candidate interlocks"})
    );
    Ok(())
}
fn check_owned(state: &State) -> Result<()> {
    fresh_lease(state.created_utc_seconds, state.expires_utc_seconds, now()?)?;
    if !state.sealed {
        return Err("fixture setup incomplete; inspect retained state".into());
    }
    for recorded in [&state.scanner, &state.peer] {
        let recorded = recorded.as_ref().ok_or("missing owned interface")?;
        if !can_destroy(recorded, identity(&recorded.name)?.as_ref())? {
            return Err("owned interface disappeared".into());
        }
    }
    delete_route(
        state.route.as_ref().ok_or("missing owned host route")?,
        route()?.as_ref(),
    )?
    .ok_or("owned route disappeared")?;
    Ok(())
}

pub fn up() -> Result<()> {
    let _lock = lock(true)?;
    if Path::new(STATE).exists() {
        return Err("fixture state already exists; inspect/down first".into());
    }
    validate_interfaces(&observations()?, false)?;
    // A pre-existing benchmark route can indicate an active VPN/lab. Never override it.
    super::validate_route_table(&command(&["/usr/sbin/netstat", "-rn", "-f", "inet"])?)?;
    let created = now()?;
    let mut state = State {
        version: 1,
        generation: studio_protocol::id_text(studio_protocol::new_id()?),
        created_utc_seconds: created,
        expires_utc_seconds: created.checked_add(1800).ok_or("fixture time overflow")?,
        tooling_sha256: crate::digest(&std::env::current_exe().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?,
        sealed: false,
        scanner: None,
        peer: None,
        route: None,
    };
    save(&state)?;
    struct Host;
    impl SetupHost for Host {
        fn identity(&mut self, name: &str) -> Result<Option<InterfaceIdentity>> {
            identity(name)
        }
        fn command(&mut self, argv: &[&str]) -> Result<()> {
            command(argv).map(|_| ())
        }
    }
    for index in 0..setup_steps().len() {
        if let Err(e) = setup_step(&mut Host, index, &mut state.scanner, &mut state.peer) {
            return Err(format!(
                "setup step{index} failed; state retained, use reviewed down: {e}"
            ));
        }
        // Record identity after every confirmed operation. If observation fails, retain
        // everything: an unrecorded name cannot authorize later cleanup.
        if index == 7 {
            let created = route()?.ok_or("created host route absent; journal retained")?;
            delete_route(&created, Some(&created))?;
            state.route = Some(created);
        }
        save(&state)?;
    }
    snapshot()?;
    state.sealed = true;
    save(&state)?;
    println!("sealed fixture ready; no Studio scan started");
    Ok(())
}

pub fn down() -> Result<()> {
    let _lock = lock(false)?;
    let mut state = load()?;
    // Check every owned interface before deleting anything: a foreign alias or
    // bridge on either side must preserve the complete stand for inspection.
    for recorded in [&state.scanner, &state.peer].into_iter().flatten() {
        can_destroy(recorded, identity(&recorded.name)?.as_ref())?;
    }
    if let Some(recorded) = &state.route {
        if let Some(argv) = delete_route(recorded, route()?.as_ref())? {
            command(&argv.iter().map(String::as_str).collect::<Vec<_>>())?;
        }
        state.route = None;
        state.sealed = false;
        save(&state)?;
    }
    for scanner in [false, true] {
        let recorded = if scanner {
            state.scanner.as_ref()
        } else {
            state.peer.as_ref()
        };
        if let Some(recorded) = recorded {
            // Destroying the peer changes only the survivor's peer relationship;
            // record that observed identity immediately before continuing.
            if can_destroy(recorded, identity(&recorded.name)?.as_ref())? {
                command(&["/sbin/ifconfig", &recorded.name, "destroy"])?;
            }
            if scanner {
                state.scanner = None;
            } else {
                state.peer = None;
                if let Some(prior) = &state.scanner {
                    let mut expected = prior.clone();
                    expected.peer = None;
                    let observed = identity(SCANNER)?;
                    if !can_destroy(&expected, observed.as_ref())? {
                        return Err("scanner disappeared during cleanup; retained state".into());
                    }
                    state.scanner = observed;
                }
            }
            save(&state)?;
        }
    }
    // Any crash-window resource not recorded remains untouched and blocks reuse.
    if identity(SCANNER)?.is_some() || identity(PEER)?.is_some() {
        return Err("unrecorded fixture resource preserved for operator inspection".into());
    }
    let stop = Path::new(STATE_DIR).join("stop-peer");
    if stop.try_exists().map_err(|e| e.to_string())? {
        trusted(&stop, false)?;
        fs::remove_file(stop).map_err(|e| e.to_string())?;
    }
    fs::remove_file(STATE).map_err(|e| e.to_string())?;
    println!("owned fixture resources removed; stable app/history and other interfaces unchanged");
    Ok(())
}

pub fn peer() -> Result<()> {
    let _lock = lock(false)?;
    let state = load()?;
    check_owned(&state)?;
    let expected = snapshot()?;
    let stop = Path::new(STATE_DIR).join("stop-peer");
    if stop.try_exists().map_err(|e| e.to_string())? {
        return Err("peer stop marker exists; down/up before a new run".into());
    }
    let binding = rmasscan_core::probe::AdapterBinding {
        interface_id: PEER.into(),
        link_type: rmasscan_core::packet::LinkType::Ethernet,
        source_ipv4: 0,
        source_mac: PEER_MAC,
        next_hop_mac: SOURCE_MAC,
        source_ports: (40000, 40000),
    };
    let opened = rmasscan_net::open_explicit(&binding).map_err(|e| e.to_string())?;
    let mut pair = opened.io;
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut observed = Instant::now();
    let mut sent = 0u64;
    let mut buffer = [0; 65536];
    println!("peer ready: fixed allowlist,90-second deadline,non-promiscuous BPF");
    while Instant::now() < deadline && !stop.try_exists().map_err(|e| e.to_string())? {
        fresh_lease(state.created_utc_seconds, state.expires_utc_seconds, now()?)?;
        if observed.elapsed() >= Duration::from_secs(1) {
            check_owned(&state)?;
            if snapshot()? != expected {
                return Err("fixture drift; peer stopped".into());
            }
            if pair
                .rx
                .health(Duration::from_millis(50))
                .map_err(|e| e.to_string())?
                .kernel_drops
                != Some(0)
            {
                return Err("peer receive health unknown or dropped".into());
            }
            observed = Instant::now();
        }
        if let Some(n) = pair
            .rx
            .recv(&mut buffer, Duration::from_millis(50))
            .map_err(|e| e.to_string())?
        {
            if n > buffer.len() {
                return Err("peer returned invalid frame length".into());
            }
            if let Some(reply) = super::wire::reply(&buffer[..n])? {
                if sent >= 2048 {
                    return Err("peer response budget exceeded".into());
                }
                let status = pair
                    .tx
                    .send(&reply, Duration::from_millis(50))
                    .map_err(|e| e.to_string())?;
                if !matches!(status, rmasscan_engine::SendStatus::Sent) {
                    return Err("peer send not confirmed; no retries".into());
                }
                sent += 1;
            }
        }
    }
    if pair
        .rx
        .health(Duration::from_millis(50))
        .map_err(|e| e.to_string())?
        .kernel_drops
        != Some(0)
    {
        return Err("peer final health unknown or dropped".into());
    }
    drop(pair);
    println!(
        "{}",
        serde_json::json!({"responses":sent,"kernel_drops":0,"stop_marker":stop.exists(),"deadline_seconds":90,"packet_witness_required":true})
    );
    Ok(())
}

pub fn stop_peer() -> Result<()> {
    // The peer deliberately holds the exclusive operation lock; this one fixed
    // cancellation marker is the sole operation permitted concurrently.
    if command(&["/usr/bin/id", "-u"])?.trim() != "0" {
        return Err("stop-peer requires root".into());
    }
    trusted(Path::new(STATE_DIR), true)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(Path::new(STATE_DIR).join("stop-peer"))
        .map_err(|e| e.to_string())?
        .sync_all()
        .map_err(|e| e.to_string())
}
