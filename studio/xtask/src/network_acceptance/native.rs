//! Explicit root fixture operations. No helper installation, firewall change or BPF grant.
use super::{ownership::*, topology::*};
use rmasscan_net::{InterfaceObservation, PhysicalRoutePlan};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{Duration, Instant},
};

use studio_platform::sealed_fixture::{STATE, STATE_DIR};
type Result<T> = std::result::Result<T, String>;

use studio_protocol::sealed_fixture::State;

fn now() -> Result<u64> {
    studio_platform::sealed_fixture::now()
}

/// Native tools have bounded argv and output, and are killed/reaped at the deadline.
pub(super) fn command(argv: &[&str]) -> Result<String> {
    studio_platform::sealed_fixture::command(argv, Instant::now() + Duration::from_secs(5), &|| {
        false
    })
}

fn trusted(path: &Path, dir: bool) -> Result<()> {
    studio_platform::sealed_fixture::trusted(
        path,
        dir,
        Instant::now() + Duration::from_secs(5),
        &|| false,
    )
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
    let state =
        studio_platform::sealed_fixture::load(Instant::now() + Duration::from_secs(5), &|| false)?;
    if state.version != 1 {
        return Err("unknown fixture state version".into());
    }
    Ok(state)
}
fn observations() -> Result<Vec<InterfaceObservation>> {
    studio_platform::sealed_fixture::observations(Instant::now() + Duration::from_secs(3), &|| {
        false
    })
}
fn identity(name: &str) -> Result<Option<InterfaceIdentity>> {
    studio_platform::sealed_fixture::identity(
        name,
        Instant::now() + Duration::from_secs(5),
        &|| false,
    )
}
fn route() -> Result<Option<OwnedRoute>> {
    studio_platform::sealed_fixture::route(Instant::now() + Duration::from_secs(5), &|| false)
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
        serde_json::json!({"sealed":state.sealed,"plan":format!("{:?}",snapshot()?),"native_execution":"fixture-only candidate; supervision and native grant still required"})
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
    if !stop.exists() {
        return Err("raw peer deadline expired without supervised stop".into());
    }
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

/// Supervision starts only while no prior peer/setup operation holds the lock.
pub(super) fn supervision_state() -> Result<State> {
    let _lock = lock(false)?;
    let state = load()?;
    check_owned(&state)?;
    snapshot()?;
    // A prior supervised case has ended; preserve seal/index/generation for Resume.
    let marker = Path::new(STATE_DIR).join("stop-peer");
    if marker.try_exists().map_err(|e| e.to_string())? {
        trusted(&marker, false)?;
        fs::remove_file(marker).map_err(|e| e.to_string())?;
    }
    Ok(state)
}
/// The sole supervised drift action. No user path, command or interface is used.
pub(super) fn guard_down(expected: &State) -> Result<()> {
    let _lock = lock(false)?;
    let current = load()?;
    if &current != expected {
        return Err("guard seal replaced".into());
    }
    check_owned(&current)?;
    snapshot()?;
    command(&["/sbin/ifconfig", SCANNER, "down"])?;
    Ok(())
}

pub(super) fn supervision_check(expected: &State, running: bool) -> Result<()> {
    let current = load()?;
    if &current != expected {
        return Err("supervised fixture seal replaced".into());
    }
    check_owned(&current)?;
    if running {
        snapshot()?;
    }
    Ok(())
}
