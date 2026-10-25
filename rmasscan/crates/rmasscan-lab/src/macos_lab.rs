//! The sealed macOS `feth` stand: `rmasscan-lab macos-lab plan|up|status|down|bpf-access|link`.
//!
//! Two `feth` interfaces peered to each other, no uplink, no bridge, no IP on the scanner side.
//! Every OS command goes through [`Host`] as an argument array (no shell), so the tests script
//! the whole system. The crate stays `forbid(unsafe_code)`: root is detected with `id -u`, BPF
//! nodes are created by opening them (std), modes are changed with std `chmod`/`chown`.
//!
//! Exit codes: 0 ok; 2 NOT RUN (arguments, foreign objects, no root); 3 stand not sealed
//! (`status`); 10 partial `up`/`down` (rolled back / manifest kept).
use crate::vm_lab::{overlap, read_manifest, write_manifest};
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
/// node that exists, keep it open (`open` owns the handles), and repeat until `bpf0..=last`
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

struct RealHost;
impl Host for RealHost {
    fn sh(&self, args: &[&str]) -> Result<String, String> {
        let r = Command::new(args[0])
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
        chown(&p, None, Some(gid)).map_err(|e| format!("chown {p}: {e}"))?;
        fs::set_permissions(&p, fs::Permissions::from_mode(mode))
            .map_err(|e| format!("chmod {p}: {e}"))
    }
    #[cfg(not(unix))]
    fn bpf_set(&self, _n: u32, _mode: u32, _gid: u32) -> Result<(), String> {
        Err("BPF devices need Unix".into())
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
                    Err(e) if e.raw_os_error() == Some(16) => Ok(Slot::Busy),
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
            ["inet", ip, "netmask", mask, ..] => i.inets.push(((*ip).into(), (*mask).into())),
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

/// Rows of `netstat -rn -f inet`: `Destination Gateway Flags Netif [Expire]`.
pub(crate) fn parse_routes(text: &str) -> Vec<Route> {
    let mut rows = vec![];
    let mut in_table = false;
    for l in text.lines() {
        let t: Vec<&str> = l.split_whitespace().collect();
        if t.first() == Some(&"Destination") {
            in_table = true;
            continue;
        }
        if in_table && t.len() >= 4 {
            rows.push(Route {
                dest: t[0].into(),
                netif: t[3].into(),
            });
        }
    }
    rows
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

fn feth_ok(h: &dyn Host, name: &str, mac: &str, peer: &str) -> Result<IfInfo, String> {
    let info = parse_ifconfig(&h.sh(&["ifconfig", name])?);
    if info.ether.as_deref() != Some(mac) {
        return Err(format!("{name}: MAC {:?}, expected {mac}", info.ether));
    }
    if info.status.as_deref() != Some("active") {
        return Err(format!("{name}: status {:?}, expected active", info.status));
    }
    if info.peer.as_deref() != Some(peer) {
        return Err(format!("{name}: peer {:?}, expected {peer}", info.peer));
    }
    Ok(info)
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
pub(crate) fn run_checks(h: &dyn Host, recorded: Option<(&str, Option<&str>)>) -> Report {
    let mut checks = vec![];
    // 1 + 2
    let both = feth_ok(h, SCANNER_IF, SCANNER_MAC, PEER_IF)
        .and_then(|s| {
            if s.inets.is_empty() {
                Ok(())
            } else {
                Err(format!("{SCANNER_IF} has an inet address: {:?}", s.inets))
            }
        })
        .and_then(|()| feth_ok(h, PEER_IF, PEER_MAC, SCANNER_IF))
        .and_then(|p| match p.inets.as_slice() {
            [(ip, mask)] if ip == PEER_IP && prefix_of(mask) == Some(30) => Ok(()),
            other => Err(format!(
                "{PEER_IF} must have exactly {PEER_IP}/30, has {other:?}"
            )),
        });
    checks.push(check(
        "interfaces",
        both.map(|()| format!("{SCANNER_IF} <-> {PEER_IF}, {PEER_IP}/30 on the peer only")),
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
                let bad: Vec<_> = parse_routes(&t)
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
    // 5
    checks.push(check(
        "arp",
        h.sh(&["arp", "-an"]).and_then(|t| {
            let e = parse_arp(&t);
            if e.iter().any(|a| {
                a.ip == SOURCE_IP
                    && a.mac.as_deref() == Some(SCANNER_MAC)
                    && a.iface == PEER_IF
                    && a.permanent
            }) {
                Ok(format!(
                    "{SOURCE_IP} -> {SCANNER_MAC} on {PEER_IF} permanent"
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
    let routes = parse_routes(&h.sh(&["netstat", "-rn", "-f", "inet"])?);
    for r in &routes {
        if let Some((ip, prefix)) = route_dest(&r.dest)
            && overlap(&format!("{ip}/{prefix}"))
        {
            problems.push(format!(
                "route {} via {} overlaps 198.18.0.0/30",
                r.dest, r.netif
            ));
        }
    }
    let all = h.sh(&["ifconfig", "-a"])?;
    for l in all.lines() {
        let t: Vec<&str> = l.split_whitespace().collect();
        if let ["inet", ip, "netmask", mask, ..] = t.as_slice()
            && let Some(p) = prefix_of(mask)
            && overlap(&format!("{ip}/{p}"))
        {
            problems.push(format!("address {ip}/{p} overlaps 198.18.0.0/30"));
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
pub(crate) struct Args {
    #[arg(value_parser=["plan","up","status","down","bpf-access","link"])]
    cmd: String,
    #[arg(long)]
    run_id: String,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    grant: bool,
    #[arg(long)]
    revoke: bool,
    #[arg(long)]
    down: bool,
    #[arg(long)]
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

fn read_marker(manifest: &Path) -> Option<String> {
    fs::read_to_string(marker_path(manifest))
        .ok()
        .map(|s| s.trim().to_owned())
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

/// The recorded stand of this run: manifest and marker present, tokens equal, run-id equal.
fn load_stand(a: &Args) -> Result<Value, String> {
    let m = read_manifest(&a.manifest)?
        .ok_or_else(|| format!("no stand recorded at {}", a.manifest.display()))?;
    if m["run_id"] != a.run_id {
        return Err("manifest belongs to another run-id".into());
    }
    let token = m["token"].as_str().filter(|t| !t.is_empty());
    match (token, read_marker(&a.manifest)) {
        (Some(t), Some(mk)) if t == mk => Ok(m),
        _ => Err("marker file is missing or does not match the manifest token".into()),
    }
}

fn recorded_route(m: &Value) -> Option<(String, Option<String>)> {
    Some((
        m["uplink"].as_str()?.to_owned(),
        m["gateway"].as_str().map(str::to_owned),
    ))
}

fn plan(out: &mut Vec<String>) {
    out.push("# macos-lab up (root), in this order; plan runs nothing".into());
    for s in up_steps() {
        out.push(s.join(" "));
    }
    out.push(format!(
        "open /dev/bpf0..{BPF_LAST} together as root and close them (the kernel creates the missing nodes)"
    ));
    out.push("# macos-lab bpf-access --grant".into());
    out.push(format!(
        "chmod 0660 and chgrp staff on /dev/bpf0..{BPF_LAST}"
    ));
    out.push("# macos-lab down (root)".into());
    out.push(arp_delete().join(" "));
    out.push(format!("ifconfig {SCANNER_IF} destroy"));
    out.push(format!("ifconfig {PEER_IF} destroy"));
    out.push(format!(
        "chmod 0600 and chown root:wheel on /dev/bpf0..{BPF_LAST} (--revoke)"
    ));
    out.push("remove the manifest and its marker".into());
}

fn rollback(
    h: &dyn Host,
    a: &Args,
    created: &[&'static str],
    arp_set: bool,
    out: &mut Vec<String>,
) {
    if arp_set {
        note(out, h.sh(&arp_delete()), "arp -d");
    }
    for n in created.iter().rev() {
        note(out, h.sh(&["ifconfig", n, "destroy"]), "destroy");
    }
    let _ = fs::remove_file(&a.manifest);
    let _ = fs::remove_file(marker_path(&a.manifest));
    out.push("rolled back: manifest and marker removed".into());
}

fn note(out: &mut Vec<String>, r: Result<String, String>, what: &str) {
    if let Err(e) = r {
        out.push(format!("rollback {what} failed: {e}"));
    }
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
    if let Some(dir) = a.manifest.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let mut mark = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker_path(&a.manifest))
        .map_err(|e| format!("marker: {e}"))?;
    writeln!(mark, "{token}").map_err(|e| e.to_string())?;
    drop(mark);
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut manifest = json!({
        "run_id": a.run_id,
        "token": token,
        "created_utc": utc(secs),
        "scanner_if": SCANNER_IF, "scanner_mac": SCANNER_MAC,
        "peer_if": PEER_IF, "peer_mac": PEER_MAC, "peer_ip": PEER_IP,
        "source_ip": SOURCE_IP,
        "uplink": uplink, "gateway": gateway,
        "bpf_nodes": [],
        "bpf_prev": {},
        "state": "creating",
    });
    if let Err(e) = write_manifest(&a.manifest, &manifest) {
        let _ = fs::remove_file(marker_path(&a.manifest));
        return Err(e);
    }
    let mut created: Vec<&'static str> = vec![];
    let mut arp_set = false;
    for step in up_steps() {
        out.push(format!("+ {}", step.join(" ")));
        if let Err(e) = h.sh(&step) {
            out.push(format!("FAILED: {e}"));
            rollback(h, a, &created, arp_set, out);
            return Ok(10);
        }
        if step[2] == "create" {
            created.push(step[1]);
        }
        if step[0] == "arp" {
            arp_set = true;
        }
    }
    out.push(format!("+ open /dev/bpf0..{BPF_LAST} together"));
    if let Err(e) = h.bpf_populate(BPF_LAST) {
        out.push(format!("FAILED: {e}"));
        rollback(h, a, &created, arp_set, out);
        return Ok(10);
    }
    let rec = recorded_route(&manifest);
    let report = run_checks(h, rec.as_ref().map(|(i, g)| (i.as_str(), g.as_deref())));
    if !report.ok() {
        for c in report.checks.iter().filter(|c| !c.ok) {
            out.push(format!("FAILED check {}: {}", c.name, c.detail));
        }
        rollback(h, a, &created, arp_set, out);
        return Ok(10);
    }
    manifest["bpf_nodes"] = (0..=BPF_LAST)
        .map(|n| format!("/dev/bpf{n}"))
        .collect::<Vec<_>>()
        .into();
    manifest["state"] = "sealed".into();
    write_manifest(&a.manifest, &manifest)?;
    out.push(format!(
        "OK: stand {} is up; next: macos-lab bpf-access --grant",
        a.run_id
    ));
    Ok(0)
}

fn status(h: &dyn Host, a: &Args, out: &mut Vec<String>) -> Result<i32, String> {
    let stand = load_stand(a);
    let recorded = stand.as_ref().ok().and_then(recorded_route);
    let mut report = run_checks(
        h,
        recorded.as_ref().map(|(i, g)| (i.as_str(), g.as_deref())),
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

fn bpf_access_cmd(h: &dyn Host, a: &Args, out: &mut Vec<String>) -> Result<i32, String> {
    require_root(h)?;
    let mut m = load_stand(a)?;
    let (mode, gid, label) = if a.grant {
        (GRANTED_MODE, staff_gid(h)?, "granted")
    } else {
        (REVOKED_MODE, 0, "revoked")
    };
    let mut missing = vec![];
    for n in 0..=BPF_LAST {
        let Some((old_mode, old_gid)) = h.bpf_stat(n) else {
            missing.push(n);
            continue;
        };
        if a.grant && m["bpf_prev"].get(n.to_string()).is_none() {
            // The first grant records the mode the node had; later grants keep it.
            m["bpf_prev"][n.to_string()] =
                json!({"mode": format!("{old_mode:04o}"), "gid": old_gid});
        }
        h.bpf_set(n, mode, gid)?;
    }
    write_manifest(&a.manifest, &m)?;
    out.push(format!(
        "{label}: /dev/bpf0..{BPF_LAST} -> {mode:04o} gid {gid}{}",
        if missing.is_empty() {
            String::new()
        } else {
            format!(" (not present yet: {missing:?}; `up` creates them)")
        }
    ));
    Ok(0)
}

fn link_cmd(h: &dyn Host, a: &Args, out: &mut Vec<String>) -> Result<i32, String> {
    require_root(h)?;
    load_stand(a)?;
    let word = if a.down { "down" } else { "up" };
    out.push(format!("+ ifconfig {PEER_IF} {word}"));
    h.sh(&["ifconfig", PEER_IF, word])?;
    Ok(0)
}

fn down(h: &dyn Host, a: &Args, out: &mut Vec<String>) -> Result<i32, String> {
    require_root(h)?;
    if !a.manifest.exists() && !marker_path(&a.manifest).exists() {
        out.push("no stand recorded; nothing to do".into());
        return Ok(0);
    }
    let _m = load_stand(a)?;
    let names = h.sh(&["ifconfig", "-l"])?;
    let present: Vec<(&str, &str)> = [(SCANNER_IF, SCANNER_MAC), (PEER_IF, PEER_MAC)]
        .into_iter()
        .filter(|(n, _)| names.split_whitespace().any(|x| x == *n))
        .collect();
    // Foreign objects are refused before anything is touched.
    for (n, mac) in &present {
        let info = parse_ifconfig(&h.sh(&["ifconfig", n])?);
        if info.ether.as_deref() != Some(mac) {
            return Err(format!(
                "{n} exists but its MAC is {:?}, not the lab's {mac}: not ours, left alone",
                info.ether
            ));
        }
    }
    let mut failed = false;
    let mut run = |args: &[&str], out: &mut Vec<String>| {
        out.push(format!("+ {}", args.join(" ")));
        if let Err(e) = h.sh(args) {
            out.push(format!("FAILED: {e}"));
            failed = true;
        }
    };
    if present.iter().any(|(n, _)| *n == PEER_IF) {
        let arp = h.sh(&["arp", "-an"]).map(|t| {
            parse_arp(&t)
                .iter()
                .any(|e| e.ip == SOURCE_IP && e.iface == PEER_IF)
        });
        if arp.unwrap_or(true) {
            run(&arp_delete(), out);
        }
    }
    for (n, _) in &present {
        run(&["ifconfig", n, "destroy"], out);
    }
    for n in 0..=BPF_LAST {
        if h.bpf_stat(n).is_some()
            && let Err(e) = h.bpf_set(n, REVOKED_MODE, 0)
        {
            out.push(format!("FAILED: revoke /dev/bpf{n}: {e}"));
            failed = true;
        }
    }
    if failed {
        out.push("down incomplete: manifest kept so down can be repeated".into());
        return Ok(10);
    }
    let _ = fs::remove_file(&a.manifest);
    let _ = fs::remove_file(marker_path(&a.manifest));
    out.push("OK: stand removed, BPF access revoked, manifest deleted".into());
    Ok(0)
}

pub(crate) fn execute(h: &dyn Host, a: &Args, out: &mut Vec<String>) -> Result<i32, String> {
    validate(a)?;
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

/// Every command except `plan` and `status` runs under the manifest's lock file, so two lab
/// commands on one stand never interleave. The lock is released when this returns.
fn dispatch(h: &dyn Host, a: &Args, wait: Duration, out: &mut Vec<String>) -> Result<i32, String> {
    let mut lock = None;
    if !matches!(a.cmd.as_str(), "plan" | "status") {
        let mut name = a.manifest.as_os_str().to_os_string();
        name.push(".lock");
        if let Some(dir) = a.manifest.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(PathBuf::from(name))
            .map_err(|e| e.to_string())?;
        let start = Instant::now();
        loop {
            match f.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if start.elapsed() < wait => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(e) => return Err(format!("another macos-lab command holds the lock: {e}")),
            }
        }
        lock = Some(f);
    }
    let r = execute(h, a, out);
    drop(lock);
    r
}

pub fn run(args: &[String]) -> Result<i32, String> {
    let a = Args::try_parse_from(std::iter::once("macos-lab".into()).chain(args.iter().cloned()))
        .map_err(|e| e.to_string())?;
    validate(&a)?;
    if a.cmd != "plan" && !cfg!(target_os = "macos") {
        return Err("macOS only (plan works anywhere)".into());
    }
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
