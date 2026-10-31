//! Read-only root seal and live ownership checks for the unmerged candidate.
//! Never takes the peer's operation lock, creates, repairs or refreshes a seal.
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use studio_protocol::sealed_fixture::{self as policy, State, ownership::*, topology::*};
type Result<T> = std::result::Result<T, String>;
pub const STATE_DIR: &str = "/private/var/run/studio-network-fixture-v1";
pub const STATE: &str = "/private/var/run/studio-network-fixture-v1/state.json";

pub fn check(deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<()> {
    if cancelled() {
        return Err("sealed fixture observation cancelled".into());
    }
    if Instant::now() >= deadline {
        return Err("sealed fixture observation timed out".into());
    }
    Ok(())
}
pub fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|e| e.to_string())
}
/// A single absolute caller budget covers spawn, reads, waits and all commands.
pub fn command(argv: &[&str], deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<String> {
    check(deadline, cancelled)?;
    let mut child = Command::new(argv.first().ok_or("empty fixture command")?)
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
            let mut data = Vec::new();
            pipe.by_ref()
                .take(65537)
                .read_to_end(&mut data)
                .map(|_| data)
        })
    };
    let out = read(Box::new(child.stdout.take().ok_or("missing stdout")?));
    let err = read(Box::new(child.stderr.take().ok_or("missing stderr")?));
    let status = loop {
        if let Err(e) = check(deadline, cancelled) {
            let _ = child.kill();
            let _ = child.wait();
            break Err(e);
        }
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(e.to_string());
            }
        }
    };
    let out = out
        .join()
        .map_err(|_| "fixture stdout worker panic")?
        .map_err(|e| e.to_string())?;
    let err = err
        .join()
        .map_err(|_| "fixture stderr worker panic")?
        .map_err(|e| e.to_string())?;
    let status = status?;
    check(deadline, cancelled)?;
    if out.len() > 65536 || err.len() > 65536 {
        return Err("fixture command output exceeds limit".into());
    }
    if !status.success() {
        return Err(format!(
            "fixture command failed {argv:?}: {}",
            String::from_utf8_lossy(&err)
        ));
    }
    String::from_utf8(out).map_err(|e| e.to_string())
}
fn metadata(m: &fs::Metadata, dir: bool) -> Result<()> {
    if m.file_type().is_symlink()
        || m.uid() != 0
        || m.mode() & 0o077 != 0
        || (if dir {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1
        })
    {
        return Err("untrusted sealed fixture filesystem identity".into());
    }
    Ok(())
}
pub fn trusted(
    path: &Path,
    dir: bool,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    check(deadline, cancelled)?;
    metadata(&fs::symlink_metadata(path).map_err(|e| e.to_string())?, dir)?;
    let text = command(
        &[
            "/bin/ls",
            "-lde",
            "-n",
            path.to_str().ok_or("invalid fixture path")?,
        ],
        deadline,
        cancelled,
    )?;
    if text.lines().count() != 1 {
        return Err("extended ACL on sealed fixture state".into());
    }
    Ok(())
}
pub fn load(deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<State> {
    trusted(Path::new(STATE_DIR), true, deadline, cancelled)?;
    trusted(Path::new(STATE), false, deadline, cancelled)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(STATE)
        .map_err(|e| e.to_string())?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    metadata(&before, false)?;
    let mut bytes = Vec::new();
    (&file)
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let after = fs::symlink_metadata(STATE).map_err(|e| e.to_string())?;
    metadata(&after, false)?;
    if before.dev() != after.dev() || before.ino() != after.ino() || bytes.len() > 8192 {
        return Err("sealed fixture changed during read or exceeds limit".into());
    }
    check(deadline, cancelled)?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}
pub fn observations(
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<rmasscan_net::InterfaceObservation>> {
    check(deadline, cancelled)?;
    let all = rmasscan_net::os_interfaces()
        .map_err(|e| e.to_string())?
        .observe(deadline, cancelled)
        .map_err(|e| e.to_string())?;
    check(deadline, cancelled)?;
    Ok(all)
}
fn identity_from(
    all: &[rmasscan_net::InterfaceObservation],
    text: &str,
    name: &str,
) -> Result<Option<InterfaceIdentity>> {
    let Some(i) = all.iter().find(|o| o.iface.name == name) else {
        return Ok(None);
    };
    let mut in_interface = false;
    let mut peer = None;
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) && !line.is_empty() {
            in_interface = line.split_once(':').is_some_and(|(n, _)| n == name);
        } else if in_interface && let Some(p) = line.trim().strip_prefix("peer: ") {
            peer = (p != "<none>").then(|| p.to_owned());
        }
    }
    let mut ipv4 = i.iface.ipv4.clone();
    ipv4.sort_unstable();
    let mut ipv4_prefixes: Vec<_> = i
        .ipv4_prefixes
        .iter()
        .map(|p| (p.address, p.length))
        .collect();
    ipv4_prefixes.sort_unstable();
    Ok(Some(InterfaceIdentity {
        name: name.into(),
        index: i.iface.index,
        mac: i.iface.mac.ok_or("fixture MAC unavailable")?,
        peer,
        ipv4,
        ipv4_prefixes,
        bridges: memberships(text, name)?,
        up: i.iface.up,
    }))
}
pub fn identity(
    name: &str,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Option<InterfaceIdentity>> {
    identity_from(
        &observations(deadline, cancelled)?,
        &command(&["/sbin/ifconfig", "-a"], deadline, cancelled)?,
        name,
    )
}
pub fn route(deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<Option<OwnedRoute>> {
    exact_route(&command(
        &["/usr/sbin/netstat", "-rn", "-f", "inet"],
        deadline,
        cancelled,
    )?)
}
pub fn live(deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<State> {
    let state = load(deadline, cancelled)?;
    policy::validate_state(&state, now()?)?;
    let all = observations(deadline, cancelled)?;
    validate_interfaces(&all, true)?;
    let text = command(&["/sbin/ifconfig", "-a"], deadline, cancelled)?;
    for recorded in [&state.scanner, &state.peer].into_iter().flatten() {
        if identity_from(&all, &text, &recorded.name)?.as_ref() != Some(recorded) {
            return Err("sealed fixture live interface ownership changed".into());
        }
    }
    if route(deadline, cancelled)? != state.route {
        return Err("sealed fixture exact host route changed or absent".into());
    }
    // Atomic replacement during observation is a failure, never adoption.
    if load(deadline, cancelled)? != state {
        return Err("sealed fixture replaced during observation".into());
    }
    policy::validate_state(&state, now()?)?;
    check(deadline, cancelled)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_parser_keeps_peer_aliases_prefixes_and_bridge_membership() {
        let all = vec![rmasscan_net::InterfaceObservation {
            iface: rmasscan_net::Iface {
                name: SCANNER.into(),
                index: 42,
                device_id: SCANNER.into(),
                description: None,
                mac: Some(SOURCE_MAC),
                mac_masked: false,
                ethernet: true,
                up: true,
                ipv4: vec![SOURCE, A],
            },
            ipv4_prefixes: vec![
                rmasscan_net::Ipv4Prefix {
                    address: SOURCE,
                    length: 29,
                },
                rmasscan_net::Ipv4Prefix {
                    address: A,
                    length: 32,
                },
            ],
        }];
        let text = format!(
            "{SCANNER}: flags=1<UP>\n\tpeer: {PEER}\n{PEER}: flags=1<UP>\n\tpeer: {SCANNER}\nbridge0: flags=1<UP>\n\tmember: {SCANNER} flags=0\n"
        );
        let identity = identity_from(&all, &text, SCANNER).unwrap().unwrap();
        assert_eq!(identity.peer.as_deref(), Some(PEER));
        assert_eq!(identity.ipv4, vec![SOURCE, A]);
        assert_eq!(identity.ipv4_prefixes, vec![(SOURCE, 29), (A, 32)]);
        assert_eq!(identity.bridges, vec!["bridge0"]);
        assert!(identity_from(&all, &text, PEER).unwrap().is_none());
    }
    #[test]
    fn cancelled_and_expired_command_never_spawns() {
        for (deadline, cancel) in [
            (Instant::now() + Duration::from_secs(1), true),
            (Instant::now(), false),
        ] {
            let error = command(&["/definitely-absent-fixture-command"], deadline, &|| {
                cancel
            })
            .unwrap_err();
            assert!(error.contains(if cancel { "cancelled" } else { "timed out" }));
        }
    }
    #[test]
    fn running_owned_child_is_cancelled_and_reaped_with_same_absolute_budget() {
        let start = Instant::now();
        let error = command(
            &["/bin/sleep", "10"],
            start + Duration::from_secs(1),
            &|| start.elapsed() >= Duration::from_millis(20),
        )
        .unwrap_err();
        assert!(error.contains("cancelled"));
        assert!(start.elapsed() < Duration::from_secs(1));
        let start = Instant::now();
        assert!(
            command(
                &["/bin/sleep", "10"],
                start + Duration::from_millis(20),
                &|| false
            )
            .unwrap_err()
            .contains("timed out")
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}

/// Temporary acceptance supervisor's read-only unprivileged evidence boundary.
pub mod evidence;
