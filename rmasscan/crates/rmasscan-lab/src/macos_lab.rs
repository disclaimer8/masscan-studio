//! The sealed macOS `feth` stand: `rmasscan-lab macos-lab plan|up|status|down|bpf-access|link`.
//!
//! Two `feth` interfaces peered to each other, no uplink, no bridge, no IP on the scanner side.
//! Every OS command goes through [`Host`] as an argument array (no shell), so the tests script
//! the whole system. The crate stays `forbid(unsafe_code)`: root is detected with `id -u`, BPF
//! nodes are created by opening them (std), modes are changed with std `chmod`/`chown`.
//!
//! Exit codes: 0 ok; 2 NOT RUN (arguments, foreign objects, no root); 3 stand not sealed
//! (`status`); 10 partial `up`/`down` (rolled back / manifest kept).
use crate::vm_lab::overlap;
use clap::Parser;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// What Darwin shows an unprivileged process descended from an ad-hoc-signed executable in
/// `ifconfig` and `arp` output instead of an Ethernet MAC. It means "os-masked", never a MAC.
pub const MASKED_MAC: &str = "02:00:00:00:00:00";
pub const SCANNER_IF: &str = "feth4201";
pub const PEER_IF: &str = "feth4202";
pub const SCANNER_MAC: &str = "02:ac:00:00:00:01";
pub const PEER_MAC: &str = "02:ac:00:00:00:02";
pub const PEER_IP: &str = "198.18.0.2";
pub const PEER_NETMASK: &str = "255.255.255.252";
pub const SOURCE_IP: &str = "198.18.0.1";
/// `/dev/bpf0..=BPF_LAST`.
pub const BPF_LAST: u32 = 15;
/// The mode of a granted node and of a revoked one.
const GRANTED_MODE: u32 = 0o660;
const REVOKED_MODE: u32 = 0o600;
/// The uplink capture filter of the lab (everything the lab may emit).
pub const UPLINK_FILTER: &str = "net 198.18.0.0/30 or (arp and (host 198.18.0.1 or host 198.18.0.2)) or ether host 02:ac:00:00:00:01 or ether host 02:ac:00:00:00:02 or ether proto 0x88b5";

/// What the lab needs from the OS. The real host runs commands and touches `/dev/bpf*`;
/// the tests script it.
pub(crate) trait Host {
    /// Run `args[0]` with `args[1..]` (no shell). `Err` on spawn failure or non-zero exit.
    fn sh(&self, args: &[&str]) -> Result<String, String>;
    /// `(mode & 0o7777, gid)` of `/dev/bpfN`; `None` when the node does not exist.
    fn bpf_stat(&self, n: u32) -> Option<(u32, u32)>;
    fn bpf_set(&self, n: u32, mode: u32, gid: u32) -> Result<(), String>;
    /// Make `/dev/bpf0..=last` exist (see [`populate`]).
    fn bpf_populate(&self, last: u32) -> Result<(), String>;
    /// The uid that must own the state directory and its files (root; the test user in tests).
    fn state_owner(&self) -> u32;
    /// The state directory ([`STATE_DIR`]).
    fn state_dir(&self) -> Result<PathBuf, String>;
    /// Whether this process is root (real MACs are visible to it; see [`MASKED_MAC`]).
    fn is_root(&self) -> bool;
}

/// Outcome of trying to open one `/dev/bpfN`.
pub(crate) enum Slot {
    /// Opened; the caller keeps it open until the pass ends.
    Held,
    /// Exists but is in use by someone else.
    Busy,
    Missing,
}

/// macOS creates the next `/dev/bpfN` when the highest existing node is opened. Open every
/// node that exists (the open attempt itself makes the kernel create the next one; keeping the
/// handles open is harmless), and repeat until `bpf0..=last`
/// all exist. A pass that finds no new node is an error: the kernel refused to create more.
pub(crate) fn populate(
    open: &mut dyn FnMut(u32) -> Result<Slot, String>,
    last: u32,
) -> Result<(), String> {
    let mut have = BTreeSet::new();
    loop {
        let before = have.len();
        for n in 0..=last {
            if have.contains(&n) {
                continue;
            }
            match open(n)? {
                Slot::Held | Slot::Busy => {
                    have.insert(n);
                }
                Slot::Missing => {}
            }
        }
        if have.len() as u32 > last {
            return Ok(());
        }
        if have.len() == before {
            return Err(format!(
                "the kernel created no further /dev/bpf node (have {} of {})",
                have.len(),
                last + 1
            ));
        }
    }
}

/// Absolute paths of the system tools the lab runs, so a changed `PATH` (sudo keeps the
/// caller's) can never substitute another binary.
pub(crate) fn system_path(name: &str) -> Option<&'static str> {
    Some(match name {
        "ifconfig" => "/sbin/ifconfig",
        "route" => "/sbin/route",
        "arp" => "/usr/sbin/arp",
        "netstat" => "/usr/sbin/netstat",
        "sysctl" => "/usr/sbin/sysctl",
        "id" => "/usr/bin/id",
        "dscl" => "/usr/bin/dscl",
        _ => return None,
    })
}

struct RealHost;
impl Host for RealHost {
    fn sh(&self, args: &[&str]) -> Result<String, String> {
        let program = system_path(args[0])
            .ok_or_else(|| format!("{}: not a command the lab may run", args[0]))?;
        let r = Command::new(program)
            .args(&args[1..])
            .output()
            .map_err(|e| format!("{}: {e}", args[0]))?;
        if !r.status.success() {
            return Err(format!(
                "{}: {}",
                args.join(" "),
                String::from_utf8_lossy(&r.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&r.stdout).into_owned())
    }
    #[cfg(unix)]
    fn bpf_stat(&self, n: u32) -> Option<(u32, u32)> {
        use std::os::unix::fs::MetadataExt;
        let m = fs::metadata(format!("/dev/bpf{n}")).ok()?;
        Some((m.mode() & 0o7777, m.gid()))
    }
    #[cfg(not(unix))]
    fn bpf_stat(&self, _n: u32) -> Option<(u32, u32)> {
        None
    }
    #[cfg(unix)]
    fn bpf_set(&self, n: u32, mode: u32, gid: u32) -> Result<(), String> {
        use std::os::unix::fs::{PermissionsExt, chown};
        let p = format!("/dev/bpf{n}");
        let chmod = || {
            fs::set_permissions(&p, fs::Permissions::from_mode(mode))
                .map_err(|e| format!("chmod {p}: {e}"))
        };
        let chgrp = || chown(&p, None, Some(gid)).map_err(|e| format!("chown {p}: {e}"));
        // Narrowing: drop the permission bits first, so there is never a moment with the old
        // group and wider bits than the target. Widening: give the group first, then the bits.
        if mode & 0o077 == 0 {
            chmod()?;
            chgrp()
        } else {
            chgrp()?;
            chmod()
        }
    }
    #[cfg(not(unix))]
    fn bpf_set(&self, _n: u32, _mode: u32, _gid: u32) -> Result<(), String> {
        Err("BPF devices need Unix".into())
    }
    fn state_owner(&self) -> u32 {
        0
    }
    fn is_root(&self) -> bool {
        self.sh(&["id", "-u"]).is_ok_and(|o| o.trim() == "0")
    }
    fn state_dir(&self) -> Result<PathBuf, String> {
        Ok(PathBuf::from(STATE_DIR))
    }
    fn bpf_populate(&self, last: u32) -> Result<(), String> {
        let mut held: Vec<fs::File> = vec![];
        let r = populate(
            &mut |n| {
                match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(format!("/dev/bpf{n}"))
                {
                    Ok(f) => {
                        held.push(f);
                        Ok(Slot::Held)
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Slot::Missing),
                    // EBUSY: the node exists and someone else has it open.
                    Err(e) if e.kind() == std::io::ErrorKind::ResourceBusy => Ok(Slot::Busy),
                    Err(e) => Err(format!("/dev/bpf{n}: {e}")),
                }
            },
            last,
        );
        drop(held);
        r
    }
}

// ---------------------------------------------------------------- parsing (pure)

/// `2:ac:0:0:0:1` and `02:AC:00:00:00:01` both become `02:ac:00:00:00:01`.
pub(crate) fn norm_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = vec![];
    for p in parts {
        if p.is_empty() || p.len() > 2 {
            return None;
        }
        out.push(format!("{:02x}", u8::from_str_radix(p, 16).ok()?));
    }
    Some(out.join(":"))
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct IfInfo {
    pub ether: Option<String>,
    /// `(ip, netmask as printed)`
    pub inets: Vec<(String, String)>,
    pub status: Option<String>,
    pub peer: Option<String>,
}

pub(crate) fn parse_ifconfig(text: &str) -> IfInfo {
    let mut i = IfInfo::default();
    for l in text.lines() {
        let t: Vec<&str> = l.split_whitespace().collect();
        match t.as_slice() {
            ["ether", mac, ..] => i.ether = norm_mac(mac),
            ["inet", ip, rest @ ..] => {
                // Every `inet` line counts. A form without a readable netmask is kept with
                // "?" so that the checks refuse it instead of skipping it.
                let mask = rest
                    .iter()
                    .position(|w| *w == "netmask")
                    .and_then(|p| rest.get(p + 1))
                    .copied()
                    .unwrap_or("?");
                i.inets.push(((*ip).into(), mask.into()));
            }
            ["status:", s, ..] => i.status = Some((*s).into()),
            ["peer:", p, ..] => i.peer = Some((*p).into()),
            _ => {}
        }
    }
    i
}

/// `0xfffffffc` or `255.255.255.252` -> prefix length.
pub(crate) fn prefix_of(mask: &str) -> Option<u32> {
    let bits = match mask.strip_prefix("0x") {
        Some(h) => u32::from_str_radix(h, 16).ok()?,
        None => u32::from(mask.parse::<Ipv4Addr>().ok()?),
    };
    (bits.leading_ones() + bits.trailing_zeros() == 32 || bits == 0).then(|| bits.leading_ones())
}

/// `(interface, gateway)` of `route -n get ...`.
pub(crate) fn parse_route_get(text: &str) -> (Option<String>, Option<String>) {
    let mut iface = None;
    let mut gw = None;
    for l in text.lines() {
        if let Some((k, v)) = l.trim().split_once(':') {
            match k {
                "interface" => iface = Some(v.trim().to_owned()),
                "gateway" => gw = Some(v.trim().to_owned()),
                _ => {}
            }
        }
    }
    (iface, gw)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Route {
    pub dest: String,
    pub netif: String,
}

/// Rows of `netstat -rn -f inet`. The `Netif` column is found by its header name, so a layout
/// with extra columns (`Refs Use`) still reads the right one. A missing header, a missing
/// `Netif` column or a row too short to reach it is an error: the caller refuses.
pub(crate) fn parse_routes(text: &str) -> Result<Vec<Route>, String> {
    let mut rows = vec![];
    let mut netif_at = None;
    for l in text.lines() {
        let t: Vec<&str> = l.split_whitespace().collect();
        if t.first() == Some(&"Destination") {
            netif_at = Some(
                t.iter()
                    .position(|h| *h == "Netif")
                    .ok_or("netstat -rn: no Netif column")?,
            );
            continue;
        }
        let Some(at) = netif_at else { continue };
        if t.is_empty() {
            continue;
        }
        let netif = t
            .get(at)
            .ok_or_else(|| format!("netstat -rn: row too short for the Netif column: {l:?}"))?;
        rows.push(Route {
            dest: t[0].into(),
            netif: (*netif).into(),
        });
    }
    if netif_at.is_none() {
        return Err("netstat -rn: no Destination header".into());
    }
    Ok(rows)
}

/// A netstat destination as `(address, prefix)`: `198.18.0/30`, `127`, `169.254`,
/// `192.168.1.1/32`, `192.168.1.5`. `default` and link-level names give `None`.
pub(crate) fn route_dest(dest: &str) -> Option<(Ipv4Addr, u32)> {
    if dest == "default" {
        return None;
    }
    let (addr, explicit) = match dest.split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u32>().ok()?)),
        None => (dest, None),
    };
    let octets: Vec<u8> = addr
        .split('.')
        .map(|o| o.parse::<u8>().ok())
        .collect::<Option<_>>()?;
    if octets.is_empty() || octets.len() > 4 {
        return None;
    }
    let prefix = explicit.unwrap_or(8 * octets.len() as u32);
    let mut full = [0u8; 4];
    full[..octets.len()].copy_from_slice(&octets);
    (prefix <= 32).then(|| (Ipv4Addr::from(full), prefix))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ArpEntry {
    pub ip: String,
    pub mac: Option<String>,
    pub iface: String,
    pub permanent: bool,
}

/// `? (198.18.0.1) at 2:ac:0:0:0:1 on feth4202 ifscope permanent [ethernet]`
pub(crate) fn parse_arp(text: &str) -> Vec<ArpEntry> {
    let mut out = vec![];
    for l in text.lines() {
        let Some(open) = l.find('(') else { continue };
        let Some(close) = l[open..].find(')') else {
            continue;
        };
        let ip = l[open + 1..open + close].to_owned();
        let rest: Vec<&str> = l[open + close + 1..].split_whitespace().collect();
        let after = |key: &str| {
            rest.iter()
                .position(|w| *w == key)
                .and_then(|i| rest.get(i + 1))
                .copied()
        };
        out.push(ArpEntry {
            ip,
            mac: after("at").and_then(norm_mac),
            iface: after("on").unwrap_or("").to_owned(),
            permanent: rest.contains(&"permanent"),
        });
    }
    out
}

// ---------------------------------------------------------------- checks

#[derive(Debug, Clone)]
pub(crate) struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

fn check(name: &'static str, r: Result<String, String>) -> Check {
    match r {
        Ok(detail) => Check {
            name,
            ok: true,
            detail,
        },
        Err(detail) => Check {
            name,
            ok: false,
            detail,
        },
    }
}

fn staff_gid(h: &dyn Host) -> Result<u32, String> {
    let out = h.sh(&["dscl", ".", "-read", "/Groups/staff", "PrimaryGroupID"])?;
    out.split_whitespace()
        .last()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("cannot read the gid of group staff from {out:?}"))
}

fn is_feth(name: &str) -> bool {
    name.starts_with("feth")
}

/// `mask_ok`: the placeholder MAC is accepted for this interface (non-root, against a sealed
/// root-owned manifest). The returned flag says it was the placeholder that was seen.
fn feth_ok(
    h: &dyn Host,
    name: &str,
    mac: &str,
    peer: &str,
    mask_ok: bool,
) -> Result<(IfInfo, bool), String> {
    let info = parse_ifconfig(&h.sh(&["ifconfig", name])?);
    let masked = mask_ok && info.ether.as_deref() == Some(MASKED_MAC);
    if info.ether.as_deref() != Some(mac) && !masked {
        return Err(format!("{name}: MAC {:?}, expected {mac}", info.ether));
    }
    if info.status.as_deref() != Some("active") {
        return Err(format!("{name}: status {:?}, expected active", info.status));
    }
    if info.peer.as_deref() != Some(peer) {
        return Err(format!("{name}: peer {:?}, expected {peer}", info.peer));
    }
    Ok((info, masked))
}

fn default_route(h: &dyn Host) -> Result<(String, Option<String>), String> {
    let (iface, gw) = parse_route_get(&h.sh(&["route", "-n", "get", "default"])?);
    let iface = iface.ok_or("route -n get default: no interface")?;
    Ok((iface, gw))
}

/// A route may be through a `feth` only when it is inside the lab /30 and on the peer side.
fn route_allowed(r: &Route) -> bool {
    if !is_feth(&r.netif) {
        return true;
    }
    r.netif == PEER_IF
        && route_dest(&r.dest).is_some_and(|(ip, prefix)| {
            prefix >= 30 && (u32::from(ip) & !3) == u32::from(Ipv4Addr::new(198, 18, 0, 0))
        })
}

/// Nothing may send lab traffic anywhere but the pair. The peer kernel answers 198.18.0.1 by
/// the route table, and only the ARP entry is `ifscope`d, so a later unscoped route for the
/// /30 (a VPN or fake-IP tool) would carry the replies to the uplink. Checked after `up`:
/// 198.18.0.1 must route via `feth4202`, 198.18.0.2 via `feth4202` or `lo0`, and every route
/// overlapping the /30 must be on `feth4202` inside the /30 (or the local `lo0` host route).
fn lab_routes(h: &dyn Host) -> Result<String, String> {
    for (ip, ok) in [
        (SOURCE_IP, &[PEER_IF][..]),
        (PEER_IP, &[PEER_IF, "lo0"][..]),
    ] {
        let (i, _) = parse_route_get(&h.sh(&["route", "-n", "get", ip])?);
        match i {
            Some(i) if ok.contains(&i.as_str()) => {}
            other => {
                return Err(format!(
                    "route to {ip} goes through {other:?}, not the pair"
                ));
            }
        }
    }
    let mut bad = vec![];
    for r in parse_routes(&h.sh(&["netstat", "-rn", "-f", "inet"])?)? {
        let touches = match route_dest(&r.dest) {
            Some((ip, prefix)) => overlap(&format!("{ip}/{prefix}")),
            None => r.dest != "default" && r.dest.contains("198.18"),
        };
        if !touches {
            continue;
        }
        let local_host = r.netif == "lo0"
            && route_dest(&r.dest) == Some((PEER_IP.parse().unwrap_or(Ipv4Addr::UNSPECIFIED), 32));
        if !(local_host || (r.netif == PEER_IF && route_allowed(&r))) {
            bad.push(format!("{} via {}", r.dest, r.netif));
        }
    }
    if bad.is_empty() {
        Ok("198.18.0.0/30 is routed only by the pair".into())
    } else {
        Err(format!(
            "routes touching 198.18.0.0/30 outside the pair: {bad:?}"
        ))
    }
}

/// Which `/dev/bpf*` modes there are: `granted` (every existing node 0660 gid staff),
/// `denied` (every existing node 0600, or no node at all), otherwise `mixed`.
pub(crate) fn bpf_access(h: &dyn Host) -> (String, Vec<u32>) {
    let staff = staff_gid(h).ok();
    let mut missing = vec![];
    let (mut granted, mut denied, mut seen) = (true, true, 0);
    for n in 0..=BPF_LAST {
        match h.bpf_stat(n) {
            None => missing.push(n),
            Some((mode, gid)) => {
                seen += 1;
                granted &= mode == GRANTED_MODE && Some(gid) == staff;
                denied &= mode == REVOKED_MODE;
            }
        }
    }
    let word = if seen == 0 || denied {
        "denied"
    } else if granted {
        "granted"
    } else {
        "mixed"
    };
    (word.into(), missing)
}

pub(crate) struct Report {
    pub checks: Vec<Check>,
    pub bpf_access: String,
    pub uplink: Option<String>,
    pub gateway: Option<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }
    fn json(&self, extra: Value) -> Value {
        let mut v = json!({
            "raw_run_allowed": self.ok(),
            "checks": self.checks.iter().map(|c| json!({"name":c.name,"ok":c.ok,"detail":c.detail})).collect::<Vec<_>>(),
            "bpf_access": self.bpf_access,
            "uplink": self.uplink,
            "gateway": self.gateway,
        });
        if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
            o.extend(e.clone());
        }
        v
    }
}

/// The printing rules 1..7. `recorded` is `(uplink, gateway)` from the manifest when there is one.
/// `stand` is the sealed, root-owned manifest when there is one. Only with it, and only for a
/// non-root process, is the placeholder MAC accepted (as "os-masked") for the stand's own MACs;
/// root always needs the real ones.
pub(crate) fn run_checks(
    h: &dyn Host,
    recorded: Option<(&str, Option<&str>)>,
    stand: Option<&Value>,
) -> Report {
    let mut checks = vec![];
    let mask_ok = stand.is_some_and(|m| {
        m["state"] == "sealed" && m["scanner_mac"] == SCANNER_MAC && m["peer_mac"] == PEER_MAC
    }) && !h.is_root();
    let masked_note = |what: &str, mac: &str| {
        format!(
            "{what}: MAC os-masked (Darwin hides MACs from ad-hoc-signed processes); root verified {mac} at up"
        )
    };
    let mut notes: Vec<String> = vec![];
    // 1 + 2
    let both = (|| -> Result<(), String> {
        let (s, masked) = feth_ok(h, SCANNER_IF, SCANNER_MAC, PEER_IF, mask_ok)?;
        if masked {
            notes.push(masked_note(SCANNER_IF, SCANNER_MAC));
        }
        if !s.inets.is_empty() {
            return Err(format!("{SCANNER_IF} has an inet address: {:?}", s.inets));
        }
        let (p, masked) = feth_ok(h, PEER_IF, PEER_MAC, SCANNER_IF, mask_ok)?;
        if masked {
            notes.push(masked_note(PEER_IF, PEER_MAC));
        }
        match p.inets.as_slice() {
            [(ip, mask)] if ip == PEER_IP && prefix_of(mask) == Some(30) => Ok(()),
            other => Err(format!(
                "{PEER_IF} must have exactly {PEER_IP}/30, has {other:?}"
            )),
        }
    })();
    checks.push(check(
        "interfaces",
        both.map(|()| {
            let mut d = format!("{SCANNER_IF} <-> {PEER_IF}, {PEER_IP}/30 on the peer only");
            for n in &notes {
                d.push_str("; ");
                d.push_str(n);
            }
            d
        }),
    ));
    // 3
    let now = default_route(h);
    let (uplink, gateway) = match &now {
        Ok((i, g)) => (Some(i.clone()), g.clone()),
        Err(_) => (None, None),
    };
    checks.push(check(
        "default_route",
        now.and_then(|(i, g)| {
            if is_feth(&i) {
                return Err(format!("default route goes through {i}"));
            }
            match recorded {
                Some((ri, rg)) if ri != i || rg != g.as_deref() => Err(format!(
                    "default route changed: recorded {ri} via {rg:?}, now {i} via {g:?}"
                )),
                Some(_) => Ok(format!("{i} via {g:?}, unchanged")),
                None => Err("no recorded default route to compare with".into()),
            }
        }),
    ));
    // 4
    checks.push(check(
        "routes",
        h.sh(&["netstat", "-rn", "-f", "inet"])
            .and_then(|t| {
                let bad: Vec<_> = parse_routes(&t)?
                    .into_iter()
                    .filter(|r| !route_allowed(r))
                    .map(|r| format!("{} via {}", r.dest, r.netif))
                    .collect();
                if bad.is_empty() {
                    Ok(())
                } else {
                    Err(format!("routes through feth outside the lab /30: {bad:?}"))
                }
            })
            .and_then(|()| {
                let (i, _) = parse_route_get(&h.sh(&["route", "-n", "get", "8.8.8.8"])?);
                match i {
                    Some(i) if !is_feth(&i) => Ok(format!("8.8.8.8 via {i}")),
                    other => Err(format!("route to 8.8.8.8 goes through {other:?}")),
                }
            }),
    ));
    // 4b: nothing may send lab traffic anywhere but the pair
    checks.push(check("lab_routes", lab_routes(h)));
    // 5
    checks.push(check(
        "arp",
        h.sh(&["arp", "-an"]).and_then(|t| {
            let e = parse_arp(&t);
            let entry = |mac_ok: &dyn Fn(&str) -> bool| {
                e.iter().any(|a| {
                    a.ip == SOURCE_IP
                        && a.mac.as_deref().is_some_and(mac_ok)
                        && a.iface == PEER_IF
                        && a.permanent
                })
            };
            if entry(&|m| m == SCANNER_MAC) {
                Ok(format!(
                    "{SOURCE_IP} -> {SCANNER_MAC} on {PEER_IF} permanent"
                ))
            } else if mask_ok && entry(&|m| m == MASKED_MAC) {
                Ok(format!(
                    "{SOURCE_IP} on {PEER_IF} permanent; {}",
                    masked_note("arp entry", SCANNER_MAC)
                ))
            } else {
                Err(format!(
                    "no permanent {SOURCE_IP} -> {SCANNER_MAC} entry on {PEER_IF}"
                ))
            }
        }),
    ));
    // 6
    checks.push(check(
        "bridges",
        h.sh(&["ifconfig", "-a"]).and_then(|t| {
            if t.lines()
                .any(|l| l.trim_start().starts_with("member: feth"))
            {
                Err("a feth interface is a bridge member".into())
            } else {
                Ok("no bridge has a feth member".into())
            }
        }),
    ));
    checks.push(check(
        "forwarding",
        h.sh(&["sysctl", "-n", "net.inet.ip.forwarding"])
            .and_then(|v| {
                if v.trim() == "0" {
                    Ok("net.inet.ip.forwarding = 0".into())
                } else {
                    Err(format!("net.inet.ip.forwarding = {}", v.trim()))
                }
            }),
    ));
    // 7
    let (access, missing) = bpf_access(h);
    checks.push(check(
        "bpf_nodes",
        if missing.is_empty() {
            Ok(format!("/dev/bpf0..{BPF_LAST} exist"))
        } else {
            Err(format!("missing /dev/bpf nodes: {missing:?}"))
        },
    ));
    Report {
        checks,
        bpf_access: access,
        uplink,
        gateway,
    }
}

/// Rule 8, before `up`: nothing of the lab exists and nothing overlaps 198.18.0.0/30.
fn preflight(h: &dyn Host) -> Result<(String, Option<String>), String> {
    let mut problems = vec![];
    let names = h.sh(&["ifconfig", "-l"])?;
    for n in [SCANNER_IF, PEER_IF] {
        if names.split_whitespace().any(|x| x == n) {
            problems.push(format!("{n} already exists (not ours to reuse)"));
        }
    }
    let routes = match parse_routes(&h.sh(&["netstat", "-rn", "-f", "inet"])?) {
        Ok(r) => r,
        Err(e) => return Err(format!("refusing to touch this host: {e}")),
    };
    for r in &routes {
        match route_dest(&r.dest) {
            Some((ip, prefix)) if overlap(&format!("{ip}/{prefix}")) => problems.push(format!(
                "route {} via {} overlaps 198.18.0.0/30",
                r.dest, r.netif
            )),
            None if r.dest != "default" && r.dest.contains("198.18") => problems.push(format!(
                "route {} via {} is unreadable and mentions 198.18",
                r.dest, r.netif
            )),
            _ => {}
        }
    }
    let all = h.sh(&["ifconfig", "-a"])?;
    for l in all.lines() {
        let t: Vec<&str> = l.split_whitespace().collect();
        if let ["inet", ip, rest @ ..] = t.as_slice() {
            let mask = rest
                .iter()
                .position(|w| *w == "netmask")
                .and_then(|p| rest.get(p + 1));
            match mask.and_then(|m| prefix_of(m)) {
                Some(p) if overlap(&format!("{ip}/{p}")) => {
                    problems.push(format!("address {ip}/{p} overlaps 198.18.0.0/30"))
                }
                Some(_) => {}
                None => problems.push(format!("cannot read the netmask of inet {ip}")),
            }
        }
        if l.trim_start().starts_with("member: feth") {
            problems.push("a feth interface is already a bridge member".into());
        }
    }
    let fwd = h.sh(&["sysctl", "-n", "net.inet.ip.forwarding"])?;
    if fwd.trim() != "0" {
        problems.push(format!("net.inet.ip.forwarding = {}", fwd.trim()));
    }
    let (iface, gw) = default_route(h)?;
    if is_feth(&iface) {
        problems.push(format!("default route already goes through {iface}"));
    }
    if !problems.is_empty() {
        return Err(format!(
            "refusing to touch this host: {}",
            problems.join("; ")
        ));
    }
    Ok((iface, gw))
}

// ---------------------------------------------------------------- commands

/// The `up` commands, in order. `plan` prints them and `up` runs them.
pub(crate) fn up_steps() -> Vec<Vec<&'static str>> {
    vec![
        vec!["ifconfig", SCANNER_IF, "create"],
        vec!["ifconfig", PEER_IF, "create"],
        vec!["ifconfig", SCANNER_IF, "lladdr", SCANNER_MAC],
        vec!["ifconfig", PEER_IF, "lladdr", PEER_MAC],
        vec!["ifconfig", SCANNER_IF, "peer", PEER_IF],
        vec![
            "ifconfig",
            PEER_IF,
            "inet",
            PEER_IP,
            "netmask",
            PEER_NETMASK,
        ],
        vec!["ifconfig", SCANNER_IF, "up"],
        vec!["ifconfig", PEER_IF, "up"],
        vec!["arp", "-S", SOURCE_IP, SCANNER_MAC, "ifscope", PEER_IF],
    ]
}

fn arp_delete() -> Vec<&'static str> {
    vec!["arp", "-d", SOURCE_IP, "ifscope", PEER_IF]
}

#[derive(Parser)]
struct Cli {
    #[arg(value_parser=["plan","up","status","down","bpf-access","link"])]
    cmd: String,
    #[arg(long)]
    run_id: String,
    /// Optional. The manifest is fixed at `/var/run/rmasscan-lab/<run-id>.json`; if given it
    /// must be exactly that.
    #[arg(long)]
    manifest: Option<PathBuf>,
    #[arg(long)]
    grant: bool,
    #[arg(long)]
    revoke: bool,
    #[arg(long)]
    down: bool,
    #[arg(long)]
    up: bool,
}

/// The parsed command with the manifest path resolved (`manifest` is always the full path).
pub(crate) struct Args {
    cmd: String,
    run_id: String,
    manifest: PathBuf,
    grant: bool,
    revoke: bool,
    down: bool,
    up: bool,
}

fn valid_run_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 8
        && id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn validate(a: &Args) -> Result<(), String> {
    if !valid_run_id(&a.run_id) {
        return Err("run-id must match [a-z0-9]{1,8}".into());
    }
    let flags = (a.grant, a.revoke, a.down, a.up);
    let ok = match a.cmd.as_str() {
        "bpf-access" => matches!(
            flags,
            (true, false, false, false) | (false, true, false, false)
        ),
        "link" => matches!(
            flags,
            (false, false, true, false) | (false, false, false, true)
        ),
        _ => flags == (false, false, false, false),
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "wrong flags for {}: bpf-access takes one of --grant/--revoke, link one of --down/--up, others none",
            a.cmd
        ))
    }
}

fn marker_path(manifest: &Path) -> PathBuf {
    let mut n = manifest.as_os_str().to_os_string();
    n.push(".mark");
    PathBuf::from(n)
}

fn random_token() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| format!("operating system RNG unavailable: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// `YYYY-MM-DDTHH:MM:SSZ` from Unix seconds.
pub(crate) fn utc(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn require_root(h: &dyn Host) -> Result<(), String> {
    let id = h.sh(&["id", "-u"])?;
    if id.trim() == "0" {
        Ok(())
    } else {
        Err("this command needs root (run it with sudo, in your own session)".into())
    }
}

/// The fixed, root-owned directory of the stand's state (manifest, marker, lock). It is under
/// `/var/run` (root-owned, cleared at reboot), never in a user-writable directory: root creates,
/// reads for action, renames and unlinks only inside a directory only root can change.
pub const STATE_DIR: &str = "/var/run/rmasscan-lab";

const READ_CAP: u64 = 1 << 20;

/// Read a state file: it must be a regular file with one link, owned by `owner` (root; in tests
/// the test user), not group/world-writable, and at most 1 MiB. It is checked with
/// `symlink_metadata` first (so a symlink, FIFO or device is never opened) and again on the
/// opened descriptor. `None` when it does not exist.
pub(crate) fn read_trusted(path: &Path, owner: u32) -> Result<Option<Vec<u8>>, String> {
    use std::io::Read;
    let shown = path.display();
    let md = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{shown}: {e}")),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        existing_file_policy(
            md.file_type().is_symlink(),
            md.is_file(),
            md.nlink(),
            md.uid(),
            md.mode(),
            owner,
        )
        .map_err(|e| format!("{shown}: refused: {e}"))?;
        if md.len() > READ_CAP {
            return Err(format!("{shown}: refused: larger than {READ_CAP} bytes"));
        }
        let mut o = OpenOptions::new();
        o.read(true);
        #[cfg(target_os = "macos")]
        o.custom_flags(O_NOFOLLOW | O_NONBLOCK);
        let f = o.open(path).map_err(|e| format!("{shown}: {e}"))?;
        let mine = f.metadata().map_err(|e| e.to_string())?;
        if !mine.is_file() || (md.dev(), md.ino()) != (mine.dev(), mine.ino()) {
            return Err(format!("{shown}: refused: the file was swapped"));
        }
        let mut buf = vec![];
        f.take(READ_CAP + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("{shown}: {e}"))?;
        if buf.len() as u64 > READ_CAP {
            return Err(format!("{shown}: refused: larger than {READ_CAP} bytes"));
        }
        Ok(Some(buf))
    }
    #[cfg(not(unix))]
    {
        let _ = (md, owner);
        fs::read(path)
            .map(Some)
            .map_err(|e| format!("{shown}: {e}"))
    }
}

/// Create a new state file (`create_new`: `O_EXCL`, never follows a symlink), mode 0644. It is
/// owned by whoever runs the command (root); nothing is ever chowned.
pub(crate) fn create_state_file(path: &Path) -> std::io::Result<fs::File> {
    let mut o = OpenOptions::new();
    o.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o644);
    }
    o.open(path)
}

/// Write the manifest atomically inside the state directory: a new temporary file, sync,
/// rename. No ownership change.
pub(crate) fn write_manifest(path: &Path, v: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?;
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let result = create_state_file(&tmp)
        .and_then(|mut f| f.write_all(&bytes).and_then(|()| f.sync_all()))
        .and_then(|()| fs::rename(&tmp, path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(|e| format!("{}: {e}", path.display()))
}

/// The recorded stand of this run: manifest and marker present, tokens equal, run-id equal.
fn load_stand(h: &dyn Host, a: &Args) -> Result<Value, String> {
    let owner = h.state_owner();
    let bytes = read_trusted(&a.manifest, owner)?
        .ok_or_else(|| format!("no stand recorded at {}", a.manifest.display()))?;
    let m: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("manifest unreadable: {e}"))?;
    if m["run_id"] != a.run_id {
        return Err("manifest belongs to another run-id".into());
    }
    let token = m["token"].as_str().filter(|t| !t.is_empty());
    let marker = read_trusted(&marker_path(&a.manifest), owner)?
        .map(|b| String::from_utf8_lossy(&b).trim().to_owned());
    match (token, marker) {
        (Some(t), Some(mk)) if t == mk => Ok(m),
        _ => Err("marker file is missing or does not match the manifest token".into()),
    }
}

/// The manifest of a run is fixed: `<state dir>/<run-id>.json`. `--manifest`, if given, must be
/// exactly that; any other path is refused before any action.
pub(crate) fn expected_manifest(state_dir: &Path, run_id: &str) -> PathBuf {
    state_dir.join(format!("{run_id}.json"))
}

fn check_manifest_arg(h: &dyn Host, a: &Args) -> Result<(), String> {
    if a.cmd == "plan" {
        return Ok(());
    }
    let want = expected_manifest(&h.state_dir()?, &a.run_id);
    if a.manifest != want {
        return Err(format!(
            "--manifest {} refused: the manifest is fixed at {} (omit --manifest)",
            a.manifest.display(),
            want.display()
        ));
    }
    Ok(())
}

fn recorded_route(m: &Value) -> Option<(String, Option<String>)> {
    Some((
        m["uplink"].as_str()?.to_owned(),
        m["gateway"].as_str().map(str::to_owned),
    ))
}

fn plan(out: &mut Vec<String>) {
    out.push(format!(
        "# state (root-owned, cleared at reboot): {STATE_DIR}/<run-id>.json, .json.mark, .json.lock; up makes the directory with one mkdir (0755, root) and every command refuses it if it is a symlink, not owned by root or group/world-writable; nothing is written under $HOME"
    ));
    out.push("# macos-lab up (root), in this order; plan runs nothing".into());
    for s in up_steps() {
        out.push(s.join(" "));
    }
    out.push(format!(
        "open /dev/bpf0..{BPF_LAST} together as root and close them (the kernel creates the missing nodes)"
    ));
    out.push("# macos-lab bpf-access --grant".into());
    out.push(format!(
        "chgrp staff and chmod 0660 on /dev/bpf0..{BPF_LAST} (previous modes go into the manifest)"
    ));
    out.push("# macos-lab bpf-access --revoke".into());
    out.push(format!(
        "chmod 0600 and chgrp wheel on /dev/bpf0..{BPF_LAST}"
    ));
    out.push("# macos-lab down (root)".into());
    out.push(arp_delete().join(" "));
    out.push(format!("ifconfig {SCANNER_IF} destroy"));
    out.push(format!("ifconfig {PEER_IF} destroy"));
    out.push(
        "set /dev/bpf* to 0600 root:wheel (recorded previous modes are only printed), remove the manifest, marker and lock"
            .into(),
    );
}

// ---------------------------------------------------------------- the state directory

/// The state directory is acceptable only when it is a real directory (not a symlink), owned by
/// `expected_owner` (root), and not writable by group or others.
pub(crate) fn dir_policy(
    is_symlink: bool,
    is_dir: bool,
    owner: u32,
    mode: u32,
    expected_owner: u32,
) -> Result<(), String> {
    if is_symlink {
        return Err("the state directory is a symlink".into());
    }
    if !is_dir {
        return Err("the state directory path is not a directory".into());
    }
    if owner != expected_owner {
        return Err(format!(
            "the state directory is owned by uid {owner}, expected uid {expected_owner}"
        ));
    }
    if mode & 0o022 != 0 {
        return Err(format!(
            "the state directory is group- or world-writable (mode {:04o})",
            mode & 0o7777
        ));
    }
    Ok(())
}

/// Make sure the state directory exists and is trustworthy. With `create`, a missing directory
/// is made with a single `mkdir` (no parents, no following), mode 0755, owned by the caller
/// (root). An existing one is only checked, never changed.
#[cfg(unix)]
fn prepare_dir(h: &dyn Host, dir: &Path, create: bool) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let owner = h.state_owner();
    match fs::symlink_metadata(dir) {
        Ok(md) => dir_policy(
            md.file_type().is_symlink(),
            md.is_dir(),
            md.uid(),
            md.mode(),
            owner,
        )
        .map_err(|e| format!("{}: {e}", dir.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
            fs::DirBuilder::new()
                .mode(0o755)
                .create(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
            // The umask may have narrowed it; the mode is what the policy expects.
            fs::set_permissions(dir, fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("{}: {e}", dir.display()))
        }
        Err(e) => Err(format!("{}: {e}", dir.display())),
    }
}
#[cfg(not(unix))]
fn prepare_dir(_h: &dyn Host, dir: &Path, create: bool) -> Result<(), String> {
    if create {
        fs::create_dir(dir).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// An existing state file is acceptable only when it is a regular file with a single link (a
/// hardlink to a system file is refused), owned by `expected_owner` (root), and not writable by
/// group or others. It is never chowned.
pub(crate) fn existing_file_policy(
    is_symlink: bool,
    is_file: bool,
    nlink: u64,
    owner: u32,
    mode: u32,
    expected_owner: u32,
) -> Result<(), String> {
    if is_symlink {
        return Err("it is a symlink".into());
    }
    if !is_file {
        return Err("it is not a regular file".into());
    }
    if nlink != 1 {
        return Err(format!("it has {nlink} hard links"));
    }
    if owner != expected_owner {
        return Err(format!(
            "it is owned by uid {owner}, expected {expected_owner}"
        ));
    }
    if mode & 0o022 != 0 {
        return Err(format!(
            "it is group- or world-writable (mode {:04o})",
            mode & 0o7777
        ));
    }
    Ok(())
}

/// `O_NOFOLLOW` on macOS (`<sys/fcntl.h>`), so no libc is needed.
#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x0100;
/// `O_NONBLOCK` on macOS, so a swapped-in FIFO can never hang a root process.
#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x0004;

/// Open the lock file: created with `create_new` (never follows a symlink); an existing one is
/// only checked ([`existing_file_policy`]) and opened without following a symlink.
pub(crate) fn open_lock_with(path: &Path, owner: u32) -> Result<fs::File, String> {
    let shown = path.display();
    match create_state_file(path) {
        Ok(f) => return Ok(f),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("{shown}: {e}")),
    }
    let md = fs::symlink_metadata(path).map_err(|e| format!("{shown}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        existing_file_policy(
            md.file_type().is_symlink(),
            md.is_file(),
            md.nlink(),
            md.uid(),
            md.mode(),
            owner,
        )
        .map_err(|e| format!("{shown}: existing lock file refused: {e}"))?;
        let mut o = OpenOptions::new();
        o.read(true).write(true);
        #[cfg(target_os = "macos")]
        o.custom_flags(O_NOFOLLOW | O_NONBLOCK);
        let f = o.open(path).map_err(|e| format!("{shown}: {e}"))?;
        let mine = f.metadata().map_err(|e| e.to_string())?;
        if (md.dev(), md.ino()) != (mine.dev(), mine.ino()) || mine.nlink() != 1 {
            return Err(format!("{shown}: the lock file was swapped"));
        }
        Ok(f)
    }
    #[cfg(not(unix))]
    {
        let _ = (md, owner);
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("{shown}: {e}"))
    }
}

fn open_lock(h: &dyn Host, path: &Path) -> Result<fs::File, String> {
    open_lock_with(path, h.state_owner())
}

// ---------------------------------------------------------------- up / rollback / down

fn names_of(m: &Value, key: &str) -> Vec<String> {
    m[key]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// `created` comes from a user-writable manifest and decides what a root `ifconfig destroy`
/// touches, so it may name only the two fixed lab interfaces. Anything else refuses the whole
/// operation before any command runs.
fn lab_names(list: &[String]) -> Result<Vec<String>, String> {
    for n in list {
        if n != SCANNER_IF && n != PEER_IF {
            return Err(format!(
                "the manifest lists {n:?}, which is not a lab interface; nothing was destroyed"
            ));
        }
    }
    Ok(list.to_vec())
}

/// A live check before destroying a lab-named interface: its MAC is the lab MAC, or its peer
/// is the other lab feth, or it is a fresh feth with no peer yet.
fn lab_property(h: &dyn Host, n: &str) -> Result<(), String> {
    let (mac, other) = if n == SCANNER_IF {
        (SCANNER_MAC, PEER_IF)
    } else if n == PEER_IF {
        (PEER_MAC, SCANNER_IF)
    } else {
        return Err(format!("{n} is not a lab interface"));
    };
    let info = parse_ifconfig(&h.sh(&["ifconfig", n])?);
    let no_peer = matches!(info.peer.as_deref(), None | Some("<none>"));
    if info.ether.as_deref() == Some(mac) || info.peer.as_deref() == Some(other) || no_peer {
        Ok(())
    } else {
        Err(format!(
            "{n} has MAC {:?} and peer {:?}: not a lab interface, left alone",
            info.ether, info.peer
        ))
    }
}

/// Remove what a (possibly partial) `up` created: the ARP entry, if it was attempted and is
/// there, and each listed interface that exists. Returns `true` when every step succeeded.
fn cleanup(h: &dyn Host, created: &[String], arp_set: bool, out: &mut Vec<String>) -> bool {
    let mut ok = true;
    let names = match h.sh(&["ifconfig", "-l"]) {
        Ok(n) => n,
        Err(e) => {
            out.push(format!("FAILED: cannot list interfaces: {e}"));
            return false;
        }
    };
    let has = |n: &str| names.split_whitespace().any(|x| x == n);
    if arp_set && created.iter().any(|c| c == PEER_IF) && has(PEER_IF) {
        let present = h.sh(&["arp", "-an"]).map(|t| {
            parse_arp(&t)
                .iter()
                .any(|e| e.ip == SOURCE_IP && e.iface == PEER_IF)
        });
        if present.unwrap_or(true) {
            out.push(format!("+ {}", arp_delete().join(" ")));
            if let Err(e) = h.sh(&arp_delete()) {
                out.push(format!("FAILED: {e}"));
                ok = false;
            }
        }
    }
    for n in created.iter().rev() {
        if has(n) {
            if let Err(e) = lab_property(h, n) {
                out.push(format!("REFUSED: {e}"));
                ok = false;
                continue;
            }
            out.push(format!("+ ifconfig {n} destroy"));
            if let Err(e) = h.sh(&["ifconfig", n, "destroy"]) {
                out.push(format!("FAILED: {e}"));
                ok = false;
            }
        }
    }
    ok
}

fn rollback(h: &dyn Host, a: &Args, m: &mut Value, out: &mut Vec<String>) -> i32 {
    let ok = match lab_names(&names_of(m, "created")) {
        Ok(c) => cleanup(h, &c, m["arp_set"] == true, out),
        Err(e) => {
            out.push(format!("REFUSED: {e}"));
            false
        }
    };
    if ok {
        let _ = fs::remove_file(&a.manifest);
        let _ = fs::remove_file(marker_path(&a.manifest));
        out.push("rolled back: manifest and marker removed".into());
    } else {
        m["state"] = "rollback-incomplete".into();
        let _ = write_manifest(&a.manifest, m);
        out.push(
            "rollback incomplete: the manifest is kept; run macos-lab down to finish it".into(),
        );
    }
    10
}

fn up(h: &dyn Host, a: &Args, out: &mut Vec<String>) -> Result<i32, String> {
    require_root(h)?;
    if a.manifest.exists() || marker_path(&a.manifest).exists() {
        return Err(format!(
            "a stand is already recorded at {} (not reused; run down first)",
            a.manifest.display()
        ));
    }
    let (uplink, gateway) = preflight(h)?;
    let token = random_token()?;
    let mut mark =
        create_state_file(&marker_path(&a.manifest)).map_err(|e| format!("marker: {e}"))?;
    writeln!(mark, "{token}").map_err(|e| e.to_string())?;
    drop(mark);
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut m = json!({
        "run_id": a.run_id,
        "token": token,
        "created_utc": utc(secs),
        "scanner_if": SCANNER_IF, "scanner_mac": SCANNER_MAC,
        "peer_if": PEER_IF, "peer_mac": PEER_MAC, "peer_ip": PEER_IP,
        "source_ip": SOURCE_IP,
        "uplink": uplink, "gateway": gateway,
        "created": [],
        "arp_set": false,
        "bpf_nodes": [],
        "bpf_prev": {},
        "state": "creating",
    });
    if let Err(e) = write_manifest(&a.manifest, &m) {
        let _ = fs::remove_file(marker_path(&a.manifest));
        return Err(e);
    }
    for step in up_steps() {
        // The intent is recorded before the command, so an interrupted `up` (or one whose
        // rollback fails) leaves a manifest that `down` can act on.
        let mut intent = false;
        if step[2] == "create" {
            let mut list = names_of(&m, "created");
            list.push(step[1].to_owned());
            m["created"] = list.into();
            intent = true;
        }
        if step[0] == "arp" {
            m["arp_set"] = true.into();
            intent = true;
        }
        if intent && let Err(e) = write_manifest(&a.manifest, &m) {
            out.push(format!("FAILED: cannot record progress: {e}"));
            return Ok(rollback(h, a, &mut m, out));
        }
        out.push(format!("+ {}", step.join(" ")));
        if let Err(e) = h.sh(&step) {
            out.push(format!("FAILED: {e}"));
            if step[2] == "create" {
                // A failed create makes nothing, and the name may belong to a foreign interface
                // that appeared after the preflight: it must never reach the rollback.
                let mut list = names_of(&m, "created");
                list.retain(|n| n != step[1]);
                m["created"] = list.into();
                let _ = write_manifest(&a.manifest, &m);
            }
            return Ok(rollback(h, a, &mut m, out));
        }
    }
    out.push(format!("+ open /dev/bpf0..{BPF_LAST} together"));
    if let Err(e) = h.bpf_populate(BPF_LAST) {
        out.push(format!("FAILED: {e}"));
        return Ok(rollback(h, a, &mut m, out));
    }
    let rec = recorded_route(&m);
    let report = run_checks(
        h,
        rec.as_ref().map(|(i, g)| (i.as_str(), g.as_deref())),
        None,
    );
    if !report.ok() {
        for c in report.checks.iter().filter(|c| !c.ok) {
            out.push(format!("FAILED check {}: {}", c.name, c.detail));
        }
        return Ok(rollback(h, a, &mut m, out));
    }
    m["bpf_nodes"] = (0..=BPF_LAST)
        .map(|n| format!("/dev/bpf{n}"))
        .collect::<Vec<_>>()
        .into();
    m["state"] = "sealed".into();
    if let Err(e) = write_manifest(&a.manifest, &m) {
        out.push(format!("FAILED: cannot record the sealed state: {e}"));
        return Ok(rollback(h, a, &mut m, out));
    }
    out.push(format!(
        "OK: stand {} is up; next: macos-lab bpf-access --grant",
        a.run_id
    ));
    Ok(0)
}

fn status(h: &dyn Host, a: &Args, out: &mut Vec<String>) -> Result<i32, String> {
    let stand = load_stand(h, a).and_then(|m| match m["state"].as_str() {
        Some("sealed") => Ok(m),
        other => Err(format!("the stand is not sealed (state {other:?})")),
    });
    let recorded = stand.as_ref().ok().and_then(recorded_route);
    let mut report = run_checks(
        h,
        recorded.as_ref().map(|(i, g)| (i.as_str(), g.as_deref())),
        stand.as_ref().ok(),
    );
    report.checks.insert(
        0,
        check(
            "manifest",
            stand
                .as_ref()
                .map(|m| format!("run {} created {}", m["run_id"], m["created_utc"]))
                .map_err(Clone::clone),
        ),
    );
    let v = report.json(json!({"run_id": a.run_id, "manifest": a.manifest}));
    out.push(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?);
    Ok(if report.ok() { 0 } else { 3 })
}

/// The exposure of a grant, printed with it and written in the guide.
pub const GRANT_WARNING: &str = "WARNING: 0660 root:staff lets every process of every local account in group staff (all regular macOS users) read AND inject raw frames on EVERY interface, including en0, without root, until --revoke, down or reboot. Revoke whenever no run is active.";

/// What to run by hand if the lab cannot revoke BPF access itself.
pub const BPF_FALLBACK: &str =
    "manual fallback: sudo chmod 600 /dev/bpf{0..15}; sudo chgrp wheel /dev/bpf{0..15}";

/// Set every existing `/dev/bpf0..15` to `0600 root:wheel`. It needs no manifest and no stand;
/// only nodes that differ are touched, and what changed is reported. `true` when all went well.
fn revoke_all(h: &dyn Host, out: &mut Vec<String>) -> bool {
    let mut changed = vec![];
    let mut ok = true;
    for n in 0..=BPF_LAST {
        match h.bpf_stat(n) {
            Some((m, g)) if (m, g) == (REVOKED_MODE, 0) => {}
            Some(_) => match h.bpf_set(n, REVOKED_MODE, 0) {
                Ok(()) => changed.push(n),
                Err(e) => {
                    out.push(format!("FAILED: revoke /dev/bpf{n}: {e}"));
                    ok = false;
                }
            },
            None => {}
        }
    }
    out.push(if changed.is_empty() {
        "revoke: /dev/bpf* already 0600 root:wheel (nothing changed)".to_string()
    } else {
        format!("revoke: set 0600 root:wheel on /dev/bpf{changed:?}")
    });
    if !ok {
        out.push(BPF_FALLBACK.into());
    }
    ok
}

fn bpf_access_cmd(h: &dyn Host, a: &Args, out: &mut Vec<String>) -> Result<i32, String> {
    require_root(h)?;
    if a.revoke {
        // Taking access away never depends on a stand or a readable manifest.
        return Ok(if revoke_all(h, out) { 0 } else { 10 });
    }
    let mut m = load_stand(h, a)?;
    if m["state"] != "sealed" {
        return Err("the stand is not sealed; run down and up again".into());
    }
    let nodes: Vec<(u32, u32, u32)> = (0..=BPF_LAST)
        .filter_map(|n| h.bpf_stat(n).map(|(mode, gid)| (n, mode, gid)))
        .collect();
    let missing: Vec<u32> = (0..=BPF_LAST)
        .filter(|n| !nodes.iter().any(|(k, _, _)| k == n))
        .collect();
    let note = if missing.is_empty() {
        String::new()
    } else {
        format!(" (not present yet: {missing:?}; `up` creates them)")
    };
    if a.grant {
        let staff = staff_gid(h)?;
        // Previous modes are saved first (the first grant wins), so nothing is changed that the
        // manifest cannot restore.
        for (n, mode, gid) in &nodes {
            if m["bpf_prev"].get(n.to_string()).is_none() {
                m["bpf_prev"][n.to_string()] = json!({"mode": format!("{mode:04o}"), "gid": gid});
            }
        }
        write_manifest(&a.manifest, &m)?;
        let mut changed: Vec<(u32, u32, u32)> = vec![];
        for (n, mode, gid) in &nodes {
            if let Err(e) = h.bpf_set(*n, GRANTED_MODE, staff) {
                out.push(format!("FAILED: /dev/bpf{n}: {e}; reverting this grant"));
                for (k, om, og) in changed
                    .iter()
                    .rev()
                    .chain(std::iter::once(&(*n, *mode, *gid)))
                {
                    if let Err(e) = h.bpf_set(*k, *om, *og) {
                        out.push(format!("FAILED to revert /dev/bpf{k}: {e}"));
                    }
                }
                return Ok(10);
            }
            changed.push((*n, *mode, *gid));
        }
        out.push(format!(
            "granted: /dev/bpf0..{BPF_LAST} -> 0660 gid {staff}{note}"
        ));
        out.push(GRANT_WARNING.into());
        return Ok(0);
    }
    Err("internal: neither --grant nor --revoke".into())
}

fn link_cmd(h: &dyn Host, a: &Args, out: &mut Vec<String>) -> Result<i32, String> {
    require_root(h)?;
    load_stand(h, a)?;
    let info = parse_ifconfig(&h.sh(&["ifconfig", PEER_IF])?);
    if info.ether.as_deref() != Some(PEER_MAC) {
        return Err(format!(
            "{PEER_IF} has MAC {:?}, not the lab's {PEER_MAC}: not ours, left alone",
            info.ether
        ));
    }
    let word = if a.down { "down" } else { "up" };
    out.push(format!("+ ifconfig {PEER_IF} {word}"));
    h.sh(&["ifconfig", PEER_IF, word])?;
    Ok(0)
}

/// Recorded previous modes that differ from the macOS default `0600 root:wheel`, for
/// information only (a ChmodBPF Mac). They are never applied: a user-writable manifest must not
/// drive a root `chmod`/`chown`.
fn differing_prev(m: &Value) -> Vec<String> {
    let Some(prev) = m["bpf_prev"].as_object() else {
        return vec![];
    };
    prev.iter()
        .filter(|(_, v)| v["mode"].as_str() != Some("0600") || v["gid"].as_u64() != Some(0))
        .map(|(k, v)| format!("/dev/bpf{k}: mode {} gid {}", v["mode"], v["gid"]))
        .collect()
}

fn down(h: &dyn Host, a: &Args, out: &mut Vec<String>) -> Result<i32, String> {
    require_root(h)?;
    // Taking BPF access away comes first and does not depend on the manifest or on the
    // interfaces being accepted.
    let revoked = revoke_all(h, out);
    match down_stand(h, a, out) {
        Ok(0) if !revoked => Ok(10),
        Ok(rc) => Ok(rc),
        Err(e) => Err(format!(
            "{e}\n{BPF_FALLBACK} (already applied above if it said so)"
        )),
    }
}

fn down_stand(h: &dyn Host, a: &Args, out: &mut Vec<String>) -> Result<i32, String> {
    if !a.manifest.exists() && !marker_path(&a.manifest).exists() {
        out.push("no stand recorded; nothing to do".into());
        return Ok(0);
    }
    let m = load_stand(h, a)?;
    let sealed = m["state"] == "sealed";
    let mut created = lab_names(&names_of(&m, "created"))?;
    let mut arp_set = m["arp_set"] == true;
    if sealed && created.is_empty() {
        created = vec![SCANNER_IF.into(), PEER_IF.into()];
        arp_set = true;
    }
    let names = h.sh(&["ifconfig", "-l"])?;
    if sealed {
        // A finished stand: a lab-named interface with another MAC is foreign and left alone.
        for (n, mac) in [(SCANNER_IF, SCANNER_MAC), (PEER_IF, PEER_MAC)] {
            if names.split_whitespace().any(|x| x == n) {
                let info = parse_ifconfig(&h.sh(&["ifconfig", n])?);
                if info.ether.as_deref() != Some(mac) {
                    return Err(format!(
                        "{n} exists but its MAC is {:?}, not the lab's {mac}: not ours, left alone",
                        info.ether
                    ));
                }
            }
        }
    }
    let ok = cleanup(h, &created, arp_set, out);
    let differing = differing_prev(&m);
    if !differing.is_empty() {
        out.push(format!(
            "NOTE: before the first grant these nodes were not 0600 root:wheel; down set them to 0600 root:wheel and does not restore them. Restore by hand if you need them: {differing:?}"
        ));
    }
    if !ok {
        out.push("down incomplete: manifest kept so down can be repeated".into());
        return Ok(10);
    }
    let _ = fs::remove_file(&a.manifest);
    let _ = fs::remove_file(marker_path(&a.manifest));
    out.push("OK: stand removed, /dev/bpf* set to 0600 root:wheel, manifest deleted".into());
    Ok(0)
}

pub(crate) fn execute(h: &dyn Host, a: &Args, out: &mut Vec<String>) -> Result<i32, String> {
    validate(a)?;
    check_manifest_arg(h, a)?;
    match a.cmd.as_str() {
        "plan" => {
            plan(out);
            Ok(0)
        }
        "up" => up(h, a, out),
        "status" => status(h, a, out),
        "down" => down(h, a, out),
        "bpf-access" => bpf_access_cmd(h, a, out),
        "link" => link_cmd(h, a, out),
        other => Err(format!("unknown command {other}")),
    }
}

/// Take the exclusive lock, polling until `wait` has passed.
fn try_lock_for(f: fs::File, wait: Duration) -> Result<fs::File, String> {
    let start = Instant::now();
    loop {
        match f.try_lock() {
            Ok(()) => return Ok(f),
            Err(std::fs::TryLockError::WouldBlock) if start.elapsed() < wait => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(e) => return Err(format!("another macos-lab command holds the lock: {e}")),
        }
    }
}

fn lock_path(manifest: &Path) -> PathBuf {
    let mut n = manifest.as_os_str().to_os_string();
    n.push(".lock");
    PathBuf::from(n)
}

/// Every command except `plan` and `status` runs under the manifest's lock file, so two lab
/// commands on one stand never interleave. `down`, `link` and `bpf-access` with no stand
/// recorded touch nothing (no directory, no lock). Root is checked before anything is created.
/// The lock is released when this returns; a successful `down` removes the file too.
fn dispatch(h: &dyn Host, a: &Args, wait: Duration, out: &mut Vec<String>) -> Result<i32, String> {
    validate(a)?;
    check_manifest_arg(h, a)?;
    let mut lock = None;
    let needs_lock = match a.cmd.as_str() {
        "plan" | "status" => false,
        "bpf-access" if a.revoke => false,
        "up" => true,
        _ => a.manifest.exists() || marker_path(&a.manifest).exists(),
    };
    // Revoking never depends on a stand: with a trustworthy state directory it takes the lock,
    // without one (missing, refused) it still runs, because taking access away must not wait.
    if a.cmd == "bpf-access" && a.revoke && !needs_lock {
        require_root(h)?;
        let dir = a
            .manifest
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let lock = prepare_dir(h, &dir, false)
            .and_then(|()| open_lock(h, &lock_path(&a.manifest)))
            .and_then(|f| try_lock_for(f, wait))
            .ok();
        if lock.is_none() {
            out.push("note: no usable state directory or lock; revoking without the lock".into());
        }
        let r = execute(h, a, out);
        drop(lock);
        return r;
    }
    if needs_lock {
        require_root(h)?;
        if let Some(dir) = a.manifest.parent().filter(|d| !d.as_os_str().is_empty()) {
            prepare_dir(h, dir, a.cmd == "up")?;
        }
        let f = open_lock(h, &lock_path(&a.manifest))?;
        lock = Some(try_lock_for(f, wait)?);
    }
    let r = execute(h, a, out);
    if a.cmd == "down" && matches!(r, Ok(0)) && lock.is_some() {
        let _ = fs::remove_file(lock_path(&a.manifest));
    }
    drop(lock);
    r
}

pub fn run(args: &[String]) -> Result<i32, String> {
    let c = Cli::try_parse_from(std::iter::once("macos-lab".into()).chain(args.iter().cloned()))
        .map_err(|e| e.to_string())?;
    let manifest = match c.manifest {
        Some(m) => m,
        None => expected_manifest(Path::new(STATE_DIR), &c.run_id),
    };
    let a = Args {
        cmd: c.cmd,
        run_id: c.run_id,
        manifest,
        grant: c.grant,
        revoke: c.revoke,
        down: c.down,
        up: c.up,
    };
    validate(&a)?;
    let mut out = vec![];
    let r = dispatch(&RealHost, &a, Duration::from_secs(30), &mut out);
    for l in out {
        println!("{l}");
    }
    r
}

#[cfg(test)]
#[path = "macos_lab_tests.rs"]
mod tests;
