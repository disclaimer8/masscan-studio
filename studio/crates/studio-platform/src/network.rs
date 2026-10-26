#![forbid(unsafe_code)]
use std::net::Ipv4Addr;

/// Read-only observations collected immediately before an adapter is opened.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub manifest: serde_json::Value,
    pub scanner: String,
    pub peer: String,
    pub interfaces: String,
    pub default_route: String,
    pub source_route: String,
    pub peer_route: String,
    pub public_route: String,
    pub routes: String,
    pub arp: String,
    pub forwarding: String,
}
type Result<T> = std::result::Result<T, String>;
const BASE: u32 = u32::from_be_bytes([198, 18, 0, 0]);

fn field<'a>(text: &'a str, key: &str) -> Result<Option<&'a str>> {
    let mut values = text
        .lines()
        .filter_map(|l| l.trim().split_once(':'))
        .filter(|(k, _)| *k == key)
        .map(|(_, v)| v.trim());
    let value = values.next();
    if values.next().is_some() {
        return Err(format!("Duplicate {key} field"));
    }
    Ok(value)
}
fn mac(s: &str) -> Option<[u8; 6]> {
    s.split(':')
        .map(|v| u8::from_str_radix(v, 16).ok())
        .collect::<Option<Vec<_>>>()?
        .try_into()
        .ok()
}
fn mask(s: &str) -> Option<u32> {
    let value = if let Some(s) = s.strip_prefix("0x") {
        u32::from_str_radix(s, 16).ok()?
    } else {
        u32::from(s.parse::<Ipv4Addr>().ok()?)
    };
    (value.leading_ones() + value.trailing_zeros() == 32 || value == 0)
        .then_some(value.leading_ones())
}
fn address(s: &str) -> Result<(u32, u32)> {
    let (ip, prefix) = s.split_once('/').map_or((s, None), |(i, p)| (i, Some(p)));
    let parts = ip
        .split('.')
        .map(|s| s.parse::<u8>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| format!("Unreadable route {s}"))?;
    if parts.is_empty() || parts.len() > 4 {
        return Err(format!("Unreadable route {s}"));
    }
    let p = prefix
        .map_or(Ok(parts.len() as u32 * 8), |p| p.parse())
        .map_err(|_| format!("Unreadable prefix {s}"))?;
    if p > 32 {
        return Err(format!("Invalid prefix {s}"));
    }
    let mut bytes = [0; 4];
    bytes[..parts.len()].copy_from_slice(&parts);
    Ok((u32::from_be_bytes(bytes), p))
}
fn overlaps(ip: u32, prefix: u32) -> bool {
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (ip & bits) <= BASE + 3 && (ip | !bits) >= BASE
}
fn iface(
    text: &str,
    name: &str,
    peer: &str,
    expected_mac: [u8; 6],
    addresses: usize,
) -> Result<()> {
    if !text
        .lines()
        .next()
        .is_some_and(|l| l.starts_with(&format!("{name}:")))
        || field(text, "status")? != Some("active")
        || field(text, "peer")? != Some(peer)
    {
        return Err(format!("{name}: link/peer changed"));
    }
    let mut ethers = text.lines().filter_map(|l| l.trim().strip_prefix("ether "));
    if ethers.next().and_then(mac) != Some(expected_mac) || ethers.next().is_some() {
        return Err(format!("{name}: MAC changed or unavailable"));
    }
    let inets = text
        .lines()
        .filter(|l| l.trim_start().starts_with("inet "))
        .collect::<Vec<_>>();
    if inets.len() != addresses {
        return Err(format!("{name}: unexpected IPv4 address count"));
    }
    for l in inets {
        let words = l.split_whitespace().collect::<Vec<_>>();
        let prefix = words
            .iter()
            .position(|s| *s == "netmask")
            .and_then(|n| words.get(n + 1))
            .and_then(|s| mask(s));
        if words.get(1) != Some(&"198.18.0.2") || prefix != Some(30) {
            return Err("Peer address/mask changed".into());
        }
    }
    Ok(())
}

pub fn validate(s: &Snapshot) -> Result<()> {
    for (key, value) in [
        ("state", "sealed"),
        ("scanner_if", "feth4201"),
        ("peer_if", "feth4202"),
        ("scanner_mac", "02:ac:00:00:00:01"),
        ("peer_mac", "02:ac:00:00:00:02"),
        ("source_ip", "198.18.0.1"),
        ("peer_ip", "198.18.0.2"),
    ] {
        if s.manifest[key].as_str() != Some(value) {
            return Err(format!("Unsealed or changed manifest: {key}"));
        }
    }
    iface(&s.scanner, "feth4201", "feth4202", [2, 172, 0, 0, 0, 1], 0)?;
    iface(&s.peer, "feth4202", "feth4201", [2, 172, 0, 0, 0, 2], 1)?;
    let uplink = s.manifest["uplink"]
        .as_str()
        .filter(|s| !s.is_empty() && !s.starts_with("feth"))
        .ok_or("Manifest lacks a valid uplink")?;
    let gateway = s.manifest["gateway"]
        .as_str()
        .filter(|v| v.parse::<Ipv4Addr>().is_ok())
        .ok_or("Manifest lacks an IPv4 gateway")?;
    if field(&s.default_route, "interface")? != Some(uplink)
        || field(&s.default_route, "gateway")? != Some(gateway)
    {
        return Err("Default route changed since sealing".into());
    }
    for (text, permitted) in [
        (&s.source_route, &["feth4202"][..]),
        (&s.peer_route, &["feth4202", "lo0"][..]),
    ] {
        if !field(text, "interface")?.is_some_and(|i| permitted.contains(&i)) {
            return Err("Lab traffic would leave the pair".into());
        }
    }
    if !field(&s.public_route, "interface")?.is_some_and(|i| !i.starts_with("feth")) {
        return Err("Public route points into lab".into());
    }
    let mut column = None;
    for line in s.routes.lines() {
        let words = line.split_whitespace().collect::<Vec<_>>();
        if words.first() == Some(&"Destination") {
            if column.is_some() {
                return Err("Ambiguous route header".into());
            }
            column = Some(
                words
                    .iter()
                    .position(|s| *s == "Netif")
                    .ok_or("Routes have no Netif column")?,
            );
            continue;
        }
        let Some(col) = column else { continue };
        if words.is_empty() {
            continue;
        }
        let nic = words.get(col).ok_or("Truncated route row")?;
        if words[0] == "default" {
            if nic.starts_with("feth") {
                return Err("Default route through lab".into());
            }
            continue;
        }
        let (ip, prefix) = address(words[0])?;
        let in_pair = *nic == "feth4202" && prefix >= 30 && ip & !3 == BASE;
        let local_peer = *nic == "lo0" && prefix == 32 && ip == BASE + 2;
        if (nic.starts_with("feth") && !in_pair)
            || (overlaps(ip, prefix) && !in_pair && !local_peer)
        {
            return Err(format!("Unsafe route {} via {nic}", words[0]));
        }
    }
    if column.is_none() {
        return Err("Missing route table header".into());
    }
    let mut current = "";
    for line in s.interfaces.lines() {
        if !line.starts_with(char::is_whitespace) {
            current = line.split(':').next().unwrap_or("");
        }
        let words = line.split_whitespace().collect::<Vec<_>>();
        if words.first() == Some(&"member:") && words.get(1).is_some_and(|i| i.starts_with("feth"))
        {
            return Err("Feth attached to bridge".into());
        }
        if words.first() == Some(&"inet") {
            let ip = words
                .get(1)
                .ok_or("Missing IPv4 address")?
                .parse::<Ipv4Addr>()
                .map_err(|_| "Bad interface IPv4")?;
            let p = words
                .iter()
                .position(|s| *s == "netmask")
                .and_then(|n| words.get(n + 1))
                .and_then(|s| mask(s))
                .ok_or("Bad interface netmask")?;
            if overlaps(ip.into(), p)
                && !(current == "feth4202" && u32::from(ip) == BASE + 2 && p == 30)
            {
                return Err("Another interface overlaps the lab".into());
            }
        }
    }
    let entries = s
        .arp
        .lines()
        .filter(|l| l.contains("(198.18.0.1)"))
        .collect::<Vec<_>>();
    if entries.len() != 1 {
        return Err("Missing or ambiguous source ARP entry".into());
    }
    let w = entries[0].split_whitespace().collect::<Vec<_>>();
    let after = |key| {
        w.iter()
            .position(|s| *s == key)
            .and_then(|i| w.get(i + 1))
            .copied()
    };
    if after("on") != Some("feth4202")
        || after("at").and_then(mac) != Some([2, 172, 0, 0, 0, 1])
        || !w.contains(&"permanent")
    {
        return Err("Source ARP mapping changed".into());
    }
    if s.forwarding.trim() != "0" {
        return Err("IPv4 forwarding must be off".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn command(exe: &str, args: &[&str], cancelled: &dyn Fn() -> bool) -> Result<String> {
    use std::{
        io::Read,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let mut child = Command::new(exe)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().ok_or("Missing preflight stdout")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(e.to_string());
            }
        }
        if cancelled() || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err(format!("Preflight command cancelled or timed out: {exe}"));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let bytes = reader
        .join()
        .map_err(|_| "Preflight reader failed")?
        .map_err(|e| e.to_string())?;
    if !status.success() || bytes.len() > 2 * 1024 * 1024 {
        return Err(format!("Preflight command failed/overflowed: {exe}"));
    }
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

/// Reads only fixed OS tools and the fixed root-owned stand manifest. No adapter
/// is opened, no route/interface/ARP/firewall setting is modified.
#[cfg(target_os = "macos")]
fn manifest() -> Result<Vec<u8>> {
    use std::{
        fs,
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let path = std::path::Path::new("/private/var/run/rmasscan-lab/m1.json");
    for (i, p) in path.ancestors().enumerate() {
        let m = fs::symlink_metadata(p).map_err(|e| e.to_string())?;
        // macOS ships this fixed system ancestor root:daemon 0775. The
        // dedicated lab directory and manifest still require root-only writes.
        let system_run = p == std::path::Path::new("/private/var/run") && m.gid() == 1;
        if m.uid() != 0
            || m.mode() & if system_run { 0o002 } else { 0o022 } != 0
            || (i == 0 && !m.is_file())
            || (i != 0 && !m.is_dir())
        {
            return Err("Untrusted stand manifest path".into());
        }
        crate::macos::reject_extended_acl(p)?;
    }
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    let m = f.metadata().map_err(|e| e.to_string())?;
    if !m.is_file() || m.len() > 65536 {
        return Err("Invalid stand manifest type/size".into());
    }
    let mut bytes = Vec::new();
    f.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 65536 {
        return Err("Stand manifest overflow".into());
    }
    Ok(bytes)
}
/// Read-only network preflight; never opens a packet adapter.
#[cfg(target_os = "macos")]
pub fn inspect_mac_feth() -> Result<Snapshot> {
    inspect_mac_feth_cancellable(&|| false)
}
#[cfg(target_os = "macos")]
pub fn inspect_mac_feth_cancellable(cancelled: &dyn Fn() -> bool) -> Result<Snapshot> {
    if cancelled() {
        return Err("Preflight cancelled".into());
    }
    let bytes = manifest()?;
    let command = |exe, args: &[&str]| command(exe, args, cancelled);
    let s = Snapshot {
        manifest: serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
        scanner: command("/sbin/ifconfig", &["feth4201"])?,
        peer: command("/sbin/ifconfig", &["feth4202"])?,
        interfaces: command("/sbin/ifconfig", &["-a"])?,
        default_route: command("/sbin/route", &["-n", "get", "default"])?,
        source_route: command("/sbin/route", &["-n", "get", "198.18.0.1"])?,
        peer_route: command("/sbin/route", &["-n", "get", "198.18.0.2"])?,
        public_route: command("/sbin/route", &["-n", "get", "8.8.8.8"])?,
        routes: command("/usr/sbin/netstat", &["-rn", "-f", "inet"])?,
        arp: command("/usr/sbin/arp", &["-an"])?,
        forwarding: command("/usr/sbin/sysctl", &["-n", "net.inet.ip.forwarding"])?,
    };
    if manifest()? != bytes {
        return Err("Stand changed during preflight".into());
    }
    validate(&s)?;
    Ok(s)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    #[test]
    fn cancelled_preflight_reaps_its_command_without_waiting_for_timeout() {
        let start = std::time::Instant::now();
        let result = super::command("/bin/sleep", &["20"], &|| true);
        assert!(result.unwrap_err().contains("cancelled"));
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }
}
