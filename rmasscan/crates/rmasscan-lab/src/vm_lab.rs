//! Isolated VM laboratory ownership and guest attestation.
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_are_bounded_and_deterministic() {
        assert!(derive("../x").is_err());
        assert!(derive("abcdefghi").is_err());
        assert_eq!(derive("t1").unwrap(), derive("t1").unwrap());
    }
    #[test]
    fn old_guest_json_cannot_be_relabelled_fresh() {
        let m = serde_json::json!({"token":"nonce","names":{"windows_mac":"52:54:00:01:02:03"},"guest":{"guid":"{A}","verify":{"ok":true,"status":"Up","mac":"52:54:00:01:02:03","guid":"{A}","recorded_at":9999999999.0}}});
        assert!(!guest_fresh(&m, &serde_json::json!({"start":1.0})));
    }
    #[test]
    fn overlap_covers_host_routes_and_broad_routes() {
        assert!(overlap("198.18.0.1/32"));
        assert!(overlap("198.0.0.0/8"));
        assert!(!overlap("192.168.0.1/24"));
    }
}
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const MARK_DIR: &str = "/run/rmasscan-wvl";
const MGMT: &str = "52:54:00:12:34:56";
/// A guest Verify report may be at most this far ahead of the home-pc clock (seconds).
pub(crate) const VERIFY_FUTURE_SKEW_S: f64 = 5.0;
/// A guest Verify report older than this on the home-pc clock is stale (seconds).
pub(crate) const VERIFY_MAX_AGE_S: f64 = 60.0;
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Names {
    run_id: String,
    bridge: String,
    tap: String,
    veth_host: String,
    netns: String,
    peer_if: String,
    windows_mac: String,
    peer_mac: String,
    veth_host_mac: String,
}
fn derive(id: &str) -> Result<Names, String> {
    if id.is_empty()
        || id.len() > 8
        || !id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err("run-id must match [a-z0-9]{1,8}".into());
    }
    let h = Sha256::digest(id.as_bytes());
    let n = Names {
        run_id: id.into(),
        bridge: format!("wvb-{id}"),
        tap: format!("wvt-{id}"),
        veth_host: format!("wvh-{id}"),
        netns: format!("wvp-{id}"),
        peer_if: "lab0".into(),
        windows_mac: format!("52:54:00:{:02x}:{:02x}:{:02x}", h[0], h[1], h[2]),
        peer_mac: format!("02:57:4c:{:02x}:{:02x}:{:02x}", h[3], h[4], h[5]),
        veth_host_mac: format!("02:57:4d:{:02x}:{:02x}:{:02x}", h[6], h[7], h[8]),
    };
    if [&n.windows_mac, &n.peer_mac, &n.veth_host_mac].contains(&&MGMT.to_owned()) {
        return Err("derived MAC collision".into());
    }
    Ok(n)
}
fn alias(d: &Names, t: &str) -> String {
    format!("rmasscan-wvl:{}:{t}", d.run_id)
}
fn norm(s: &str) -> String {
    s.to_ascii_lowercase().replace('-', ":")
}
pub(crate) fn overlap(s: &str) -> bool {
    let (ip, prefix) = s.split_once('/').unwrap_or((s, "32"));
    let Ok(ip) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(bits) = prefix.parse::<u32>() else {
        return false;
    };
    if bits > 32 {
        return false;
    }
    let bits = bits.min(30);
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    u32::from(ip) & mask == u32::from(Ipv4Addr::new(198, 18, 0, 0)) & mask
}
#[derive(Default, Clone)]
struct Link {
    master: Option<String>,
    alias: String,
    physical: bool,
    mac: String,
    addrs: Vec<String>,
    noarp: bool,
    lower_up: bool,
    vlan_filtering: bool,
}
trait Host {
    fn sh(&self, args: &[&str], check: bool) -> Result<String, String>;
    fn optional_command(&self, args: &[&str]) -> Result<Option<String>, String> {
        self.sh(args, true).map(Some)
    }
    fn marker(&self, ns: &str) -> Option<String>;
    fn marker_exists(&self, ns: &str) -> bool {
        self.marker(ns).is_some()
    }
    fn mark_write(&self, ns: &str, token: &str) -> Result<(), String>;
    fn mark_remove(&self, ns: &str) -> Result<(), String>;
    fn sysctl(&self, key: &str) -> Option<String>;
    fn links(&self) -> Result<BTreeMap<String, Link>, String> {
        let raw = self.sh(&["ip", "-j", "-d", "addr", "show"], true)?;
        let all: Vec<Value> = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        let mut out = BTreeMap::new();
        for l in all {
            let name = l["ifname"].as_str().ok_or("link lacks name")?.to_owned();
            let flags = l["flags"].as_array().cloned().unwrap_or_default();
            let link = Link {
                master: l["master"].as_str().map(str::to_owned),
                alias: l["ifalias"].as_str().unwrap_or("").into(),
                physical: Path::new(&format!("/sys/class/net/{name}/device")).exists(),
                mac: norm(l["address"].as_str().unwrap_or("")),
                addrs: l["addr_info"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|a| {
                        Some(format!(
                            "{}/{}",
                            a["local"].as_str()?,
                            a["prefixlen"].as_u64()?
                        ))
                    })
                    .collect(),
                noarp: flags.contains(&json!("NOARP")),
                lower_up: flags.contains(&json!("LOWER_UP")),
                vlan_filtering: l["linkinfo"]["info_data"]["vlan_filtering"].as_u64() == Some(1)
                    || l["linkinfo"]["info_data"]["vlan_filtering"] == true,
            };
            out.insert(name, link);
        }
        Ok(out)
    }
    fn namespaces(&self) -> Result<BTreeSet<String>, String> {
        Ok(self
            .sh(&["ip", "netns", "list"], true)?
            .lines()
            .filter_map(|l| l.split_whitespace().next().map(str::to_owned))
            .collect())
    }
    fn settle(&self) {
        let _ = self.sh(&["udevadm", "settle", "--timeout=5"], false);
    }
    fn firewall(&self, names: &[&str]) -> Result<Vec<String>, String> {
        let mut hits = vec![];
        for cmd in [
            &["nft", "list", "ruleset"][..],
            &["iptables-save"][..],
            &["ip6tables-save"][..],
        ] {
            if let Some(s) = self.optional_command(cmd)? {
                for l in s.lines() {
                    if names.iter().any(|n| {
                        l.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
                            .any(|t| t == *n)
                    }) {
                        hits.push(format!("{}: {}", cmd[0], l.trim()));
                    }
                }
            }
        }
        Ok(hits)
    }
    fn vm(&self, d: &Names) -> Value {
        vm_facts(d)
    }
}
struct RealHost;
impl Host for RealHost {
    fn optional_command(&self, args: &[&str]) -> Result<Option<String>, String> {
        optional_command_output(args, Command::new(args[0]).args(&args[1..]).output())
    }
    fn sh(&self, args: &[&str], check: bool) -> Result<String, String> {
        let r = Command::new(args[0])
            .args(&args[1..])
            .output()
            .map_err(|e| format!("{}: {e}", args[0]))?;
        if check && !r.status.success() {
            return Err(format!(
                "{}: {}",
                args.join(" "),
                String::from_utf8_lossy(&r.stderr).trim()
            ));
        }
        Ok(if r.status.success() {
            String::from_utf8_lossy(&r.stdout).into_owned()
        } else {
            String::new()
        })
    }
    fn marker(&self, ns: &str) -> Option<String> {
        fs::read_to_string(Path::new(MARK_DIR).join(ns))
            .ok()
            .map(|s| s.trim().into())
    }
    fn marker_exists(&self, ns: &str) -> bool {
        fs::symlink_metadata(Path::new(MARK_DIR).join(ns)).is_ok()
    }
    fn mark_write(&self, ns: &str, t: &str) -> Result<(), String> {
        fs::create_dir_all(MARK_DIR).map_err(|e| e.to_string())?;
        let p = Path::new(MARK_DIR).join(ns);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
            .map_err(|e| e.to_string())?;
        if let Err(e) = writeln!(f, "{t}").and_then(|_| f.sync_all()) {
            let _ = fs::remove_file(p);
            return Err(e.to_string());
        }
        Ok(())
    }
    fn mark_remove(&self, ns: &str) -> Result<(), String> {
        match fs::remove_file(Path::new(MARK_DIR).join(ns)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
    fn sysctl(&self, k: &str) -> Option<String> {
        fs::read_to_string(format!("/proc/sys/{}", k.replace('.', "/")))
            .ok()
            .map(|s| s.trim().into())
    }
}
fn optional_command_output(
    args: &[&str],
    result: std::io::Result<std::process::Output>,
) -> Result<Option<String>, String> {
    match result {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot inspect firewall backend {}: {e}", args[0])),
        Ok(r) if r.status.success() => Ok(Some(String::from_utf8_lossy(&r.stdout).into_owned())),
        Ok(r) => Err(format!(
            "firewall query {} failed ({}): {}",
            args.join(" "),
            r.status,
            String::from_utf8_lossy(&r.stderr).trim()
        )),
    }
}
fn vm_facts(d: &Names) -> Value {
    let mut out = json!({"pid":null,"cmdline_ok":false,"fd_iff":false,"start":0.0});
    let boot = fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("btime ").and_then(|s| s.parse::<f64>().ok()))
        })
        .unwrap_or(0.0);
    let ticks = Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .filter(|r| r.status.success())
        .and_then(|r| {
            String::from_utf8_lossy(&r.stdout)
                .trim()
                .parse::<f64>()
                .ok()
        })
        .filter(|x| *x > 0.0)
        .unwrap_or(0.0);
    let Ok(dirs) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in dirs.flatten() {
        let pid = entry.file_name().to_string_lossy().into_owned();
        if pid.parse::<u32>().is_err() {
            continue;
        }
        let p = entry.path();
        let Ok(raw) = fs::read(p.join("cmdline")) else {
            continue;
        };
        let text = String::from_utf8_lossy(&raw);
        let argv: Vec<_> = text.split('\0').collect();
        if !argv.first().is_some_and(|s| s.contains("qemu-system")) {
            continue;
        }
        let tap = argv.iter().any(|s| {
            s.starts_with("tap,")
                && s.split(',').any(|x| x == "id=lab0")
                && s.split(',').any(|x| x == format!("ifname={}", d.tap))
        });
        let mac = argv.iter().any(|s| {
            s.starts_with("e1000e,")
                && s.split(',').any(|x| x == "netdev=lab0")
                && s.split(',')
                    .any(|x| norm(x) == format!("mac={}", d.windows_mac))
        });
        if !tap && !mac {
            continue;
        }
        let fd = fs::read_dir(p.join("fd"))
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .any(|e| {
                fs::read_link(e.path()).ok().as_deref() == Some(Path::new("/dev/net/tun"))
                    && fs::read_to_string(p.join("fdinfo").join(e.file_name()))
                        .is_ok_and(|s| s.lines().any(|l| l == format!("iff:\t{}", d.tap)))
            });
        let start = if ticks > 0.0 && boot > 0.0 {
            fs::read_to_string(p.join("stat"))
                .ok()
                .and_then(|s| {
                    s.rsplit_once(')').and_then(|(_, s)| {
                        s.split_whitespace()
                            .nth(19)
                            .and_then(|v| v.parse::<f64>().ok())
                    })
                })
                .map(|v| boot + v / ticks)
                .unwrap_or(0.0)
        } else {
            0.0
        };
        out =
            json!({"pid":pid.parse::<u32>().ok(),"cmdline_ok":tap&&mac,"fd_iff":fd,"start":start});
        break;
    }
    out
}
fn read_manifest(p: &Path) -> Result<Option<Value>, String> {
    match fs::read(p) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| format!("manifest unreadable: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn write_manifest(p: &Path, m: &Value) -> Result<(), String> {
    atomic_write(p, &serde_json::to_vec_pretty(m).map_err(|e| e.to_string())?)
}
/// The owner to give a report back when sudo atomically replaced an unprivileged user's file:
/// only when the file we just created is root-owned (we are root) and SUDO_UID is set. The
/// group falls back to the uid. Invalid ids are an error. Only the unix `restore_sudo_owner` calls
/// it; the logic stays compiled and tested everywhere.
#[cfg_attr(not(unix), allow(dead_code))]
fn sudo_target(
    owner_uid: u32,
    sudo_uid: Option<&str>,
    sudo_gid: Option<&str>,
) -> io::Result<Option<(u32, u32)>> {
    if owner_uid != 0 {
        return Ok(None);
    }
    let Some(uid) = sudo_uid else {
        return Ok(None);
    };
    let parse = |s: &str| -> io::Result<u32> {
        s.parse::<u32>()
            .ok()
            .filter(|id| *id != u32::MAX)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid SUDO_UID/SUDO_GID"))
    };
    let gid = sudo_gid.unwrap_or(uid);
    Ok(Some((parse(uid)?, parse(gid)?)))
}
/// Preserve ownership when sudo replaces an unprivileged user's report. Uses the already-open
/// descriptor (std `fchown`), so a pathname race cannot redirect it.
#[cfg(unix)]
fn restore_sudo_owner(file: &fs::File) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, fchown};
    let uid = std::env::var("SUDO_UID").ok();
    let gid = std::env::var("SUDO_GID").ok();
    if let Some((u, g)) = sudo_target(file.metadata()?.uid(), uid.as_deref(), gid.as_deref())? {
        fchown(file, Some(u), Some(g))?;
    }
    Ok(())
}
#[cfg(not(unix))]
fn restore_sudo_owner(_file: &fs::File) -> io::Result<()> {
    Ok(())
}
fn atomic_write(p: &Path, b: &[u8]) -> Result<(), String> {
    let mut name = p.as_os_str().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(name);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| e.to_string())?;
    let result = f
        .write_all(b)
        .and_then(|_| restore_sudo_owner(&f))
        .and_then(|_| f.sync_all())
        .and_then(|_| fs::rename(&tmp, p));
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result.map_err(|e| e.to_string())
}
fn plan(h: &dyn Host, d: &Names, m: Option<&Value>) -> Result<(Vec<String>, Vec<String>), String> {
    let mut problems = vec![];
    let links = h.links()?;
    let ns = h.namespaces()?;
    for n in [&d.bridge, &d.tap, &d.veth_host] {
        if links.contains_key(n) {
            problems.push(format!("name busy: link {n}"));
        }
    }
    if ns.contains(&d.netns) {
        problems.push(format!("name busy: netns {}", d.netns));
    }
    if h.marker_exists(&d.netns) {
        problems.push(format!("stale or foreign owner marker for {}", d.netns));
    }
    if let Some(m) = m
        && m["state"] != "down"
    {
        problems.push(format!(
            "manifest exists with state={}: run down first",
            m["state"]
        ));
    }
    for (n, l) in &links {
        if [&d.windows_mac, &d.peer_mac, &d.veth_host_mac].contains(&&l.mac) {
            problems.push(format!("MAC {} already used by host link {n}", l.mac));
        }
        for a in &l.addrs {
            if overlap(a) {
                problems.push(format!(
                    "address conflict: {a} on {n} overlaps 198.18.0.0/30"
                ));
            }
        }
    }
    let routes: Vec<Value> = serde_json::from_str(&h.sh(&["ip", "-j", "route", "show"], true)?)
        .map_err(|e| e.to_string())?;
    for r in routes {
        if let Some(s) = r["dst"].as_str()
            && s != "default"
            && overlap(s)
        {
            problems.push(format!("route conflict: {s} overlaps 198.18.0.0/30"));
        }
    }
    if h.sysctl("net.ipv4.ip_forward").as_deref() != Some("0") {
        problems.push("global net.ipv4.ip_forward must be 0".into());
    }
    problems.extend(
        h.firewall(&[&d.bridge, &d.tap, &d.veth_host])?
            .into_iter()
            .map(|s| format!("firewall rule already references lab interfaces: {s}")),
    );
    let actions = vec![
        format!(
            "create bridge {}: L2-only vlan_filtering, self vid 1 removed, NOARP, arp_ignore=8, rp_filter=1, forwarding=0, IPv6 off",
            d.bridge
        ),
        format!("create tap {} and enslave to {}", d.tap, d.bridge),
        format!(
            "create netns {} with ownership marker; veth {} <-> lab0",
            d.netns, d.veth_host
        ),
        "set 198.18.0.2/30 on namespace lab0 only, no gateway/DNS".into(),
        "verify isolation and exclusive bridge ports".into(),
    ];
    Ok((problems, actions))
}
fn isolation(h: &dyn Host, d: &Names) -> Result<Vec<String>, String> {
    h.settle();
    let links = h.links()?;
    let Some(br) = links.get(&d.bridge) else {
        return Ok(vec![format!("bridge {} missing", d.bridge)]);
    };
    let mut v = vec![];
    for (n, l) in &links {
        if l.master.as_deref() == Some(&d.bridge) {
            if l.physical {
                v.push(format!("physical uplink {n} enslaved to bridge"));
            } else if n != &d.tap && n != &d.veth_host {
                v.push(format!("unexpected port {n} on bridge"));
            }
        }
    }
    for n in [&d.bridge, &d.tap, &d.veth_host] {
        let Some(l) = links.get(n) else {
            v.push(format!("{n} missing"));
            continue;
        };
        if !l.addrs.is_empty() {
            v.push(format!("{n} has host IP {:?}", l.addrs));
        }
        if !l.noarp {
            v.push(format!("{n} is not NOARP"));
        }
        for (k, want) in [("arp_ignore", "8"), ("rp_filter", "1"), ("forwarding", "0")] {
            if h.sysctl(&format!("net.ipv4.conf.{n}.{k}")).as_deref() != Some(want) {
                v.push(format!("{n}: {k} must be {want}"));
            }
        }
        if h.sysctl(&format!("net.ipv6.conf.{n}.disable_ipv6"))
            .as_deref()
            != Some("1")
        {
            v.push(format!("{n}: IPv6 not disabled"));
        }
        if n != &d.bridge && l.master.as_deref() != Some(&d.bridge) {
            v.push(format!("{n} not enslaved to bridge"));
        }
    }
    if !br.vlan_filtering {
        v.push("bridge vlan_filtering is off".into());
    }
    match h
        .sh(&["bridge", "-j", "vlan", "show", "dev", &d.bridge], true)
        .and_then(|s| serde_json::from_str::<Vec<Value>>(&s).map_err(|e| e.to_string()))
    {
        Ok(entries) => {
            if entries.iter().any(|e| {
                e["ifname"] == d.bridge && e["vlans"].as_array().is_some_and(|a| !a.is_empty())
            }) {
                v.push("bridge self VLAN present: frames reach host IP stack".into());
            }
        }
        Err(_) => v.push("cannot read bridge self VLANs".into()),
    }
    if h.sysctl("net.ipv4.ip_forward").as_deref() != Some("0") {
        v.push("global ip_forward must be 0".into());
    }
    v.extend(
        h.firewall(&[&d.bridge, &d.tap, &d.veth_host])?
            .into_iter()
            .map(|s| format!("firewall references lab interface: {s}")),
    );
    Ok(v)
}
fn l2only(h: &dyn Host, n: &str) -> Result<(), String> {
    if h.sh(&["nmcli", "-t", "-f", "RUNNING", "general"], false)
        .is_ok_and(|s| s.trim() == "running")
    {
        let _ = h.sh(&["nmcli", "device", "set", n, "managed", "no"], false);
        for _ in 0..30 {
            if h.sh(&["nmcli", "-t", "-f", "DEVICE,STATE", "device"], false)
                .is_ok_and(|s| s.lines().any(|l| l == format!("{n}:unmanaged")))
            {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    h.settle();
    h.sh(&["ip", "link", "set", n, "arp", "off"], true)?;
    for (key, v) in [
        ("net.ipv6.conf", "disable_ipv6=1"),
        ("net.ipv4.conf", "arp_ignore=8"),
        ("net.ipv4.conf", "rp_filter=1"),
        ("net.ipv4.conf", "forwarding=0"),
    ] {
        h.sh(&["sysctl", "-qw", &format!("{key}.{n}.{v}")], true)?;
    }
    Ok(())
}
fn create_link(
    h: &dyn Host,
    n: &str,
    add: &[&str],
    after: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    h.sh(add, true)?;
    if let Err(e) = after() {
        let cleanup = h.sh(&["ip", "link", "del", n], true);
        return Err(match cleanup {
            Ok(_) => e,
            Err(c) => format!("{e}; rollback failed: {c}"),
        });
    }
    Ok(())
}
fn create_namespace(h: &dyn Host, ns: &str, t: &str) -> Result<(), String> {
    if h.marker_exists(ns) {
        return Err("stale or foreign namespace marker".into());
    }
    h.sh(&["ip", "netns", "add", ns], true)?;
    if let Err(e) = h.mark_write(ns, t) {
        let result = h.sh(&["ip", "netns", "del", ns], true);
        return Err(match result {
            Ok(_) => e,
            Err(c) => format!("{e}; namespace rollback failed: {c}"),
        });
    }
    Ok(())
}
fn teardown(h: &dyn Host, d: &Names, t: &str) -> Result<i32, String> {
    let links = h.links()?;
    let ns = h.namespaces()?;
    let mut rc = 0;
    for n in [&d.tap, &d.veth_host, &d.bridge] {
        if let Some(l) = links.get(n) {
            if l.alias != alias(d, t) {
                eprintln!("SKIP {n}: live mark is foreign");
                rc = 5;
            } else {
                h.sh(&["ip", "link", "del", n], true)?;
            }
        }
    }
    if ns.contains(&d.netns) {
        if h.marker(&d.netns).as_deref() == Some(t) {
            h.sh(&["ip", "netns", "del", &d.netns], true)?;
            h.mark_remove(&d.netns)?;
        } else {
            eprintln!("SKIP netns {}: owner marker is foreign", d.netns);
            rc = 5;
        }
    } else if h.marker(&d.netns).as_deref() == Some(t) {
        h.mark_remove(&d.netns)?;
    }
    Ok(rc)
}
fn guest_fresh(m: &Value, vm: &Value) -> bool {
    let g = &m["guest"];
    let v = &g["verify"];
    let verified = v["verified_at"].as_f64().unwrap_or(0.0);
    let start = vm["start"].as_f64().unwrap_or(f64::INFINITY);
    v["ok"] == true
        && v["status"] == "Up"
        && norm(v["mac"].as_str().unwrap_or(""))
            == m["names"]["windows_mac"].as_str().unwrap_or("!")
        && v["guid"].as_str().is_some_and(|s| !s.is_empty())
        && v["guid"] == g["guid"]
        && verified > 0.0
        && start > 0.0
        && verified >= start
        && v["verification_nonce"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
        && v["verification_nonce"] == g["verification_nonce"]
}
#[derive(Parser)]
struct Args {
    #[arg(value_parser=["plan","up","status","down","record-guest"])]
    cmd: String,
    #[arg(long)]
    run_id: String,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    tap_user: Option<String>,
    #[arg(long)]
    lab_env: Option<PathBuf>,
    #[arg(long)]
    guest_json: Option<PathBuf>,
    #[arg(long)]
    verify_json: Option<PathBuf>,
    #[arg(long)]
    nonce: Option<String>,
    #[arg(long)]
    host_only: bool,
}
fn validate_manifest(m: &Value, d: &Names) -> Result<(), String> {
    if m["run_id"] != d.run_id || m["token"].as_str().is_none_or(|s| s.is_empty()) {
        return Err("manifest belongs to another run-id or has no token".into());
    }
    if let Some(names) = m.get("names")
        && names != &serde_json::to_value(d).map_err(|e| e.to_string())?
    {
        return Err("manifest names do not match derived run identity".into());
    }
    Ok(())
}
fn random_token() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| format!("operating system RNG unavailable: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}
fn execute(h: &dyn Host, a: &Args) -> Result<i32, String> {
    execute_with_clock(h, a, now)
}
fn execute_with_clock(h: &dyn Host, a: &Args, clock: impl Fn() -> f64) -> Result<i32, String> {
    let d = derive(&a.run_id)?;
    let mut m = read_manifest(&a.manifest)?;
    match a.cmd.as_str() {
        "plan" => {
            let (p, actions) = plan(h, &d, m.as_ref())?;
            emit(
                json!({"run_id":a.run_id,"names":d,"problems":p,"actions":actions,"net":"198.18.0.0/30","ok":p.is_empty()}).to_string()
            );
            Ok(if p.is_empty() { 0 } else { 3 })
        }
        "up" => {
            let (mut p, _) = plan(h, &d, m.as_ref())?;
            if let Some(env) = &a.lab_env
                && env.exists()
                && !fs::read_to_string(env)
                    .map_err(|e| e.to_string())?
                    .lines()
                    .any(|l| l == format!("LAB_RUN_ID={}", d.run_id))
            {
                p.push("lab.env belongs to another run-id".into());
            }
            if !p.is_empty() {
                return Err(format!(
                    "REFUSED (nothing created or removed): {}",
                    p.join("; ")
                ));
            }
            let token = random_token()?;
            let mark = alias(&d, &token);
            let mut m = json!({"schema":2,"run_id":d.run_id,"token":token,"state":"creating","names":d,"created":[],"lab":{"net":"198.18.0.0/30","windows_ip":"198.18.0.1","peer_ip":"198.18.0.2","prefix":30,"gateway":null,"dns":null},"guest":{"guid":null,"npf":null},"vm":{"attached":false}});
            write_manifest(&a.manifest, &m)?;
            let result = (|| -> Result<(), String> {
                let mut record = |kind: &str, name: &str| -> Result<(), String> {
                    m["created"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"kind":kind,"name":name,"at":now()}));
                    write_manifest(&a.manifest, &m)
                };
                create_link(
                    h,
                    &d.bridge,
                    &[
                        "ip",
                        "link",
                        "add",
                        &d.bridge,
                        "type",
                        "bridge",
                        "stp_state",
                        "0",
                        "vlan_filtering",
                        "1",
                    ],
                    || {
                        h.sh(&["ip", "link", "set", &d.bridge, "alias", &mark], true)?;
                        l2only(h, &d.bridge)?;
                        h.sh(
                            &[
                                "bridge", "vlan", "del", "dev", &d.bridge, "vid", "1", "self",
                            ],
                            true,
                        )?;
                        h.sh(&["ip", "link", "set", &d.bridge, "up"], true)?;
                        Ok(())
                    },
                )?;
                record("link", &d.bridge)?;
                let user = a
                    .tap_user
                    .clone()
                    .or_else(|| std::env::var("SUDO_USER").ok())
                    .unwrap_or("root".into());
                create_link(
                    h,
                    &d.tap,
                    &[
                        "ip", "tuntap", "add", "dev", &d.tap, "mode", "tap", "user", &user,
                    ],
                    || {
                        h.sh(&["ip", "link", "set", &d.tap, "alias", &mark], true)?;
                        l2only(h, &d.tap)
                    },
                )?;
                record("link", &d.tap)?;
                enslave(h, &d.tap, &d.bridge)?;
                create_namespace(h, &d.netns, &token)?;
                record("netns", &d.netns)?;
                create_link(
                    h,
                    &d.veth_host,
                    &[
                        "ip",
                        "link",
                        "add",
                        &d.veth_host,
                        "address",
                        &d.veth_host_mac,
                        "type",
                        "veth",
                        "peer",
                        "name",
                        "lab0",
                        "address",
                        &d.peer_mac,
                        "netns",
                        &d.netns,
                    ],
                    || {
                        h.sh(&["ip", "link", "set", &d.veth_host, "alias", &mark], true)?;
                        l2only(h, &d.veth_host)
                    },
                )?;
                record("link", &d.veth_host)?;
                enslave(h, &d.veth_host, &d.bridge)?;
                h.sh(
                    &[
                        "ip",
                        "netns",
                        "exec",
                        &d.netns,
                        "sysctl",
                        "-qw",
                        "net.ipv6.conf.all.disable_ipv6=1",
                    ],
                    true,
                )?;
                h.sh(&["ip", "-n", &d.netns, "link", "set", "lo", "up"], true)?;
                h.sh(
                    &[
                        "ip",
                        "-n",
                        &d.netns,
                        "addr",
                        "add",
                        "198.18.0.2/30",
                        "dev",
                        "lab0",
                    ],
                    true,
                )?;
                h.sh(&["ip", "-n", &d.netns, "link", "set", "lab0", "up"], true)?;
                let v = isolation(h, &d)?;
                if !v.is_empty() {
                    return Err(format!("isolation check failed: {}", v.join("; ")));
                }
                if let Some(env) = &a.lab_env {
                    atomic_write(
                        env,
                        format!(
                            "LAB_RUN_ID={}\nLAB_TAP={}\nLAB_MAC={}\n",
                            d.run_id, d.tap, d.windows_mac
                        )
                        .as_bytes(),
                    )?;
                    m["lab_env"] = json!(env);
                }
                Ok(())
            })();
            if let Err(e) = result {
                eprintln!("up failed: {e}; rolling back own objects");
                if teardown(h, &d, &token)? == 0 {
                    m["state"] = json!("down");
                    write_manifest(&a.manifest, &m)?;
                }
                return Ok(4);
            }
            m["state"] = json!("up");
            m["vm"] = json!({"attached":false,"note":"restart the VM via ~/winvm/run.sh to bind the new TAP"});
            write_manifest(&a.manifest, &m)?;
            println!("up: {}", a.manifest.display());
            Ok(0)
        }
        "down" => {
            let Some(mut m) = m.take() else {
                println!("down: no manifest (no-op)");
                return Ok(0);
            };
            validate_manifest(&m, &d)?;
            if m["state"] == "down" {
                println!("down: already down (no-op)");
                return Ok(0);
            }
            let token = m["token"].as_str().unwrap();
            let rc = teardown(h, &d, token)?;
            if let Some(env) = m["lab_env"].as_str()
                && fs::read_to_string(env)
                    .is_ok_and(|s| s.lines().any(|l| l == format!("LAB_RUN_ID={}", d.run_id)))
            {
                fs::remove_file(env).map_err(|e| e.to_string())?;
            }
            m["state"] = json!(if rc == 0 { "down" } else { "down-incomplete" });
            m["vm"] = json!({"attached":false});
            write_manifest(&a.manifest, &m)?;
            println!("down: {}", m["state"]);
            Ok(rc)
        }
        "status" => {
            let Some(mut m) = m.take() else {
                println!("{}", json!({"state":"absent"}));
                return Ok(2);
            };
            validate_manifest(&m, &d)?;
            let links = h.links()?;
            let ns = h.namespaces()?;
            let token = m["token"].as_str().unwrap();
            let mut objs = BTreeMap::new();
            for (kind, n) in [
                ("link", &d.bridge),
                ("link", &d.tap),
                ("link", &d.veth_host),
                ("netns", &d.netns),
            ] {
                let present = if kind == "netns" {
                    ns.contains(n)
                } else {
                    links.contains_key(n)
                };
                let owned = if kind == "netns" {
                    h.marker(n).as_deref() == Some(token)
                } else {
                    links.get(n).is_some_and(|l| l.alias == alias(&d, token))
                };
                objs.insert(
                    n.clone(),
                    if present && owned {
                        "present, owned"
                    } else if present {
                        "FOREIGN"
                    } else {
                        "MISSING"
                    },
                );
            }
            let up = m["state"] == "up";
            let violations = if up { isolation(h, &d)? } else { vec![] };
            let host_ok =
                up && objs.values().all(|s| *s == "present, owned") && violations.is_empty();
            let mut vm = if up {
                h.vm(&d)
            } else {
                json!({"pid":null,"cmdline_ok":false,"fd_iff":false,"start":0})
            };
            vm["carrier"] = json!(links.get(&d.tap).is_some_and(|l| l.lower_up));
            vm["attached"] = json!(
                !vm["pid"].is_null()
                    && vm["cmdline_ok"] == true
                    && vm["fd_iff"] == true
                    && vm["carrier"] == true
            );
            let gf = up && guest_fresh(&m, &vm);
            let full = host_ok && vm["attached"] == true && gf;
            let ok = if a.host_only { host_ok } else { full };
            if up && !a.host_only {
                m["vm"] = vm.clone();
                m["status_checked_at"] = json!(now());
                write_manifest(&a.manifest, &m)?;
            }
            emit(
                json!({"state":m["state"],"objects":objs,"isolation_violations":violations,"host_ok":host_ok,"vm":vm,"guest_verify_fresh":gf,"guest_verify_nonce":if a.host_only{Value::Null}else{m["guest"]["verify"]["verification_nonce"].clone()},"raw_run_allowed":full,"ok":ok}).to_string()
            );
            Ok(if ok { 0 } else { 1 })
        }
        "record-guest" => {
            let mut m = m.ok_or("no up manifest for run-id")?;
            validate_manifest(&m, &d)?;
            if m["state"] != "up" {
                return Err("no up manifest for run-id".into());
            }
            if !m["guest"].is_object() {
                m["guest"] = json!({});
            }
            // A failed import must revoke the previously successful attestation.
            // Preserve its nonce separately so replay remains detectable.
            if a.verify_json.is_some() || a.guest_json.is_some() {
                m["guest"]["verify"] = Value::Null;
                write_manifest(&a.manifest, &m)?;
            }
            if let Some(p) = &a.guest_json {
                let g = read_manifest(p)?.ok_or("missing guest JSON")?;
                let ads = g["adapters"]
                    .as_array()
                    .ok_or("malformed guest record: missing adapters")?;
                let hits: Vec<_> = ads
                    .iter()
                    .filter(|ad| {
                        norm(
                            ad["MacAddress"]
                                .as_str()
                                .or_else(|| ad["mac"].as_str())
                                .unwrap_or(""),
                        ) == d.windows_mac
                    })
                    .collect();
                if d.windows_mac == MGMT || hits.len() != 1 {
                    return Err("lab NIC ambiguous/absent or management MAC".into());
                }
                let ad = hits[0];
                let guid = ad["InterfaceGuid"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or("malformed guest record: missing InterfaceGuid")?;
                m["guest"]["guid"] = json!(guid);
                m["guest"]["npf"] = json!(format!("\\Device\\NPF_{guid}"));
                m["guest"]["name"] = ad["Name"].clone();
                m["guest"]["ifindex"] = ad["ifIndex"].clone();
            }
            if let Some(p) = &a.verify_json {
                let v = read_manifest(p)?.ok_or("missing verify JSON")?;
                let nonce = a
                    .nonce
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .ok_or("record-guest --verify-json requires unique --nonce")?;
                let verified = v["verified_at"]
                    .as_f64()
                    .ok_or("malformed guest record: actual verified_at required")?;
                let vm = h.vm(&d);
                let start = vm["start"].as_f64().unwrap_or(0.0);
                // Read once at the decision, after report and VM lookup, so both bounds
                // and the persisted import time use the same clock observation.
                let recorded_at = clock();
                if v["verification_nonce"] != nonce
                    || m["guest"]["verification_nonce"] == nonce
                    || verified > recorded_at + VERIFY_FUTURE_SKEW_S
                    || recorded_at - verified > VERIFY_MAX_AGE_S
                    || start <= 0.0
                    || verified < start
                {
                    return Err("stale, replayed or mismatched guest verification".into());
                }
                let lab = &v["lab"];
                let status = lab["Status"]
                    .as_str()
                    .ok_or("malformed guest record: Status")?;
                let mac = norm(
                    lab["MacAddress"]
                        .as_str()
                        .ok_or("malformed guest record: MacAddress")?,
                );
                let guid = lab["InterfaceGuid"]
                    .as_str()
                    .ok_or("malformed guest record: InterfaceGuid")?;
                let ok = v["ok"].as_bool().ok_or("malformed guest record: ok")?;
                m["guest"]["verification_nonce"] = json!(nonce);
                m["guest"]["verify"] = json!({"ok":ok,"status":status,"mac":mac,"guid":guid,"verified_at":verified,"verification_nonce":nonce,"recorded_at":recorded_at});
            }
            write_manifest(&a.manifest, &m)?;
            println!("{}", m["guest"]);
            Ok(0)
        }
        _ => Err("unknown VM lab command".into()),
    }
}
fn enslave(h: &dyn Host, n: &str, br: &str) -> Result<(), String> {
    h.sh(&["ip", "link", "set", n, "master", br], true)?;
    h.sh(&["ip", "link", "set", n, "up"], true)?;
    Ok(())
}
pub fn run(args: &[String]) -> Result<i32, String> {
    let a = Args::try_parse_from(std::iter::once("vm-lab".into()).chain(args.iter().cloned()))
        .map_err(|e| e.to_string())?;
    derive(&a.run_id)?;
    if !cfg!(target_os = "linux") {
        return Err("Linux only".into());
    }
    let root = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| e.to_string())?;
    if String::from_utf8_lossy(&root.stdout).trim() != "0" {
        return Command::new("sudo")
            .arg("-n")
            .arg(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg("vm-lab")
            .args(args)
            .status()
            .map(|s| s.code().unwrap_or(3))
            .map_err(|e| e.to_string());
    }
    dispatch(&RealHost, &a, Path::new(MARK_DIR), Duration::from_secs(30))
}
/// Every command except `plan` runs under the run-id lock, so two lab commands for the
/// same run-id can never interleave. The lock is released when this returns.
fn dispatch(h: &dyn Host, a: &Args, lock_dir: &Path, wait: Duration) -> Result<i32, String> {
    let mut lock = None;
    if a.cmd != "plan" {
        fs::create_dir_all(lock_dir).map_err(|e| e.to_string())?;
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_dir.join(format!("{}.lock", a.run_id)))
            .map_err(|e| e.to_string())?;
        let start = Instant::now();
        loop {
            match f.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if start.elapsed() < wait => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(e) => return Err(format!("another VM lab command holds run lock: {e}")),
            }
        }
        lock = Some(f);
    }
    let result = execute(h, a);
    drop(lock);
    result
}
#[cfg(test)]
thread_local!(static OUTPUT: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) });
fn emit(line: String) {
    #[cfg(test)]
    OUTPUT.with(|o| o.borrow_mut().push(line));
    #[cfg(not(test))]
    println!("{line}");
}

#[cfg(test)]
mod ownership_tests {
    use super::*;
    use std::cell::RefCell;
    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<Vec<String>>>,
        links: RefCell<BTreeMap<String, Link>>,
        ns: RefCell<BTreeSet<String>>,
        marks: RefCell<BTreeMap<String, String>>,
        fail: RefCell<Option<String>>,
        mark_fail: bool,
        vm_start: std::cell::Cell<Option<f64>>,
        sysctls: RefCell<BTreeMap<String, String>>,
        replies: RefCell<Vec<(String, String)>>,
        vm_facts: RefCell<Option<Value>>,
        rogue: RefCell<Option<String>>,
        lock_probe: RefCell<Option<PathBuf>>,
        lock_was_held: std::cell::Cell<usize>,
        lock_was_free: std::cell::Cell<usize>,
    }
    impl Host for Fake {
        fn sh(&self, a: &[&str], _: bool) -> Result<String, String> {
            self.calls
                .borrow_mut()
                .push(a.iter().map(|s| s.to_string()).collect());
            if let Some(dir) = self.lock_probe.borrow().as_ref() {
                let f = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(dir.join("t1.lock"))
                    .unwrap();
                match f.try_lock() {
                    Err(std::fs::TryLockError::WouldBlock) => {
                        self.lock_was_held.set(self.lock_was_held.get() + 1)
                    }
                    _ => self.lock_was_free.set(self.lock_was_free.get() + 1),
                }
            }
            if self
                .fail
                .borrow()
                .as_deref()
                .is_some_and(|s| a.join(" ").starts_with(s))
            {
                return Err("injected command failure".into());
            }
            if a.starts_with(&["ip", "netns", "add"]) {
                if !self.ns.borrow_mut().insert(a[3].into()) {
                    return Err("namespace already exists".into());
                }
            } else if a.starts_with(&["ip", "netns", "del"]) {
                self.ns.borrow_mut().remove(a[3]);
            } else if a.starts_with(&["ip", "link", "add"]) {
                let mut l = self.links.borrow_mut();
                if l.contains_key(a[3]) {
                    return Err("link already exists".into());
                }
                l.insert(
                    a[3].into(),
                    Link {
                        vlan_filtering: a.contains(&"bridge"),
                        ..Default::default()
                    },
                );
                if a.contains(&"bridge")
                    && let Some(r) = self.rogue.borrow().as_ref()
                    && let Some(x) = l.get_mut(r)
                {
                    x.master = Some(a[3].into());
                }
            } else if a.starts_with(&["ip", "tuntap", "add"]) {
                self.links.borrow_mut().insert(a[4].into(), Link::default());
            } else if a.starts_with(&["ip", "link", "del"]) {
                self.links.borrow_mut().remove(a[3]);
            } else if a.starts_with(&["ip", "link", "set"])
                && let Some(l) = self.links.borrow_mut().get_mut(a[3])
            {
                match a[4] {
                    "alias" => l.alias = a[5].into(),
                    "master" => l.master = Some(a[5].into()),
                    "arp" => l.noarp = a[5] == "off",
                    _ => {}
                }
            }
            let joined = a.join(" ");
            if let Some((_, out)) = self
                .replies
                .borrow()
                .iter()
                .find(|(p, _)| joined.starts_with(p.as_str()))
            {
                return Ok(out.clone());
            }
            if a.starts_with(&["ip", "-j", "route"]) || a.starts_with(&["bridge", "-j"]) {
                return Ok("[]".into());
            }
            Ok(String::new())
        }
        fn marker(&self, n: &str) -> Option<String> {
            self.marks.borrow().get(n).cloned()
        }
        fn mark_write(&self, n: &str, t: &str) -> Result<(), String> {
            if self.mark_fail {
                return Err("marker disk full".into());
            }
            self.marks.borrow_mut().insert(n.into(), t.into());
            Ok(())
        }
        fn mark_remove(&self, n: &str) -> Result<(), String> {
            self.marks.borrow_mut().remove(n);
            Ok(())
        }
        fn links(&self) -> Result<BTreeMap<String, Link>, String> {
            Ok(self.links.borrow().clone())
        }
        fn namespaces(&self) -> Result<BTreeSet<String>, String> {
            Ok(self.ns.borrow().clone())
        }
        fn sysctl(&self, k: &str) -> Option<String> {
            if let Some(v) = self.sysctls.borrow().get(k) {
                return Some(v.clone());
            }
            Some(
                if k.ends_with("arp_ignore") {
                    "8"
                } else if k.ends_with("rp_filter") || k.ends_with("disable_ipv6") {
                    "1"
                } else {
                    "0"
                }
                .into(),
            )
        }
        fn vm(&self, _: &Names) -> Value {
            if let Some(v) = self.vm_facts.borrow().as_ref() {
                return v.clone();
            }
            json!({"pid":42,"cmdline_ok":true,"fd_iff":true,"start":self.vm_start.get().unwrap_or(1.0)})
        }
    }
    fn temp() -> PathBuf {
        // A random suffix, not the time: macOS SystemTime has microsecond resolution, so two
        // parallel tests could get the same name (EEXIST on the macos-14 CI runner).
        let p = std::env::temp_dir().join(format!(
            "rmasscan-vmlab-{}-{}",
            std::process::id(),
            crate::windows_suite::nonce()
        ));
        fs::create_dir(&p).unwrap();
        p
    }
    fn args(p: &Path, cmd: &str) -> Args {
        Args {
            cmd: cmd.into(),
            run_id: "t1".into(),
            manifest: p.join("manifest.json"),
            tap_user: Some("root".into()),
            lab_env: None,
            guest_json: None,
            verify_json: None,
            nonce: None,
            host_only: true,
        }
    }
    #[test]
    fn marker_failure_removes_only_created_namespace() {
        let h = Fake {
            mark_fail: true,
            ..Default::default()
        };
        h.ns.borrow_mut().insert("foreign".into());
        assert!(create_namespace(&h, "wvp-t1", "t").is_err());
        assert_eq!(*h.ns.borrow(), BTreeSet::from(["foreign".into()]));
        assert!(
            h.calls
                .borrow()
                .iter()
                .any(|c| c == &["ip", "netns", "del", "wvp-t1"])
        );
    }
    #[test]
    fn failed_namespace_creation_never_deletes_existing() {
        let h = Fake::default();
        h.ns.borrow_mut().insert("wvp-t1".into());
        assert!(create_namespace(&h, "wvp-t1", "t").is_err());
        assert!(h.ns.borrow().contains("wvp-t1"));
        assert!(!h.calls.borrow().iter().any(|c| c.starts_with(&[
            "ip".into(),
            "netns".into(),
            "del".into()
        ])));
    }
    #[test]
    fn stale_marker_refuses_before_creation() {
        let h = Fake::default();
        h.marks
            .borrow_mut()
            .insert("wvp-t1".into(), "foreign".into());
        assert!(create_namespace(&h, "wvp-t1", "t").is_err());
        assert!(h.calls.borrow().is_empty());
        assert!(
            plan(&h, &derive("t1").unwrap(), None)
                .unwrap()
                .0
                .iter()
                .any(|s| s.contains("marker"))
        );
    }
    #[test]
    fn failed_link_creation_cannot_delete_foreign() {
        let h = Fake::default();
        h.links
            .borrow_mut()
            .insert("wvb-t1".into(), Link::default());
        assert!(create_link(&h, "wvb-t1", &["ip", "link", "add", "wvb-t1"], || Ok(())).is_err());
        assert!(h.links.borrow().contains_key("wvb-t1"));
    }
    #[test]
    fn failure_after_link_creation_rolls_back_that_link() {
        let h = Fake::default();
        assert!(
            create_link(&h, "wvb-t1", &["ip", "link", "add", "wvb-t1"], || Err(
                "post-create failure".into()
            ))
            .is_err()
        );
        assert!(!h.links.borrow().contains_key("wvb-t1"));
    }
    #[test]
    fn lifecycle_preserves_foreign_objects_and_repeated_down() {
        let h = Fake::default();
        h.links.borrow_mut().insert(
            "eno1".into(),
            Link {
                physical: true,
                ..Default::default()
            },
        );
        let p = temp();
        assert_eq!(execute(&h, &args(&p, "up")).unwrap(), 0);
        assert_eq!(execute(&h, &args(&p, "status")).unwrap(), 0);
        assert_eq!(execute(&h, &args(&p, "down")).unwrap(), 0);
        assert_eq!(execute(&h, &args(&p, "down")).unwrap(), 0);
        assert_eq!(
            h.links.borrow().keys().cloned().collect::<Vec<_>>(),
            vec!["eno1"]
        );
        assert!(h.ns.borrow().is_empty());
        assert!(h.marks.borrow().is_empty());
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn teardown_refuses_changed_live_owner() {
        let h = Fake::default();
        let d = derive("t1").unwrap();
        h.links.borrow_mut().insert(
            d.bridge.clone(),
            Link {
                alias: "foreign".into(),
                ..Default::default()
            },
        );
        h.ns.borrow_mut().insert(d.netns.clone());
        h.marks
            .borrow_mut()
            .insert(d.netns.clone(), "foreign".into());
        assert_eq!(teardown(&h, &d, "mine").unwrap(), 5);
        assert!(h.links.borrow().contains_key(&d.bridge));
        assert!(h.ns.borrow().contains(&d.netns));
    }
    #[test]
    fn physical_port_and_host_address_fail_isolation() {
        let h = Fake::default();
        let p = temp();
        assert_eq!(execute(&h, &args(&p, "up")).unwrap(), 0);
        h.links.borrow_mut().insert(
            "eno1".into(),
            Link {
                physical: true,
                master: Some("wvb-t1".into()),
                ..Default::default()
            },
        );
        h.links
            .borrow_mut()
            .get_mut("wvt-t1")
            .unwrap()
            .addrs
            .push("169.254.1.1/16".into());
        let v = isolation(&h, &derive("t1").unwrap()).unwrap();
        assert!(v.iter().any(|s| s.contains("physical uplink")));
        assert!(v.iter().any(|s| s.contains("host IP")));
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn actual_guest_time_and_nonce_bind_vm() {
        let v = json!({"ok":true,"status":"Up","mac":"52:54:00:01:02:03","guid":"{A}","verified_at":100.0,"verification_nonce":"run-a"});
        let mut m = json!({"names":{"windows_mac":"52:54:00:01:02:03"},"guest":{"guid":"{A}","verification_nonce":"run-a","verify":v}});
        assert!(guest_fresh(&m, &json!({"start":99.0})));
        assert!(!guest_fresh(&m, &json!({"start":101.0})));
        m["guest"]["verification_nonce"] = json!("run-b");
        assert!(!guest_fresh(&m, &json!({"start":99.0})));
    }
    #[test]
    fn present_firewall_backend_failure_refuses_preflight_and_status() {
        let h = Fake::default();
        *h.fail.borrow_mut() = Some("nft list ruleset".into());
        assert!(plan(&h, &derive("t1").unwrap(), None).is_err());
        let p = temp();
        *h.fail.borrow_mut() = None;
        execute(&h, &args(&p, "up")).unwrap();
        *h.fail.borrow_mut() = Some("iptables-save".into());
        assert!(execute(&h, &args(&p, "status")).is_err());
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn only_missing_optional_firewall_program_is_ignored() {
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert_eq!(
            optional_command_output(&["nft"], Err(missing)).unwrap(),
            None
        );
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(optional_command_output(&["nft"], Err(denied)).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn nonzero_firewall_query_cannot_masquerade_as_empty_rules() {
        use std::os::unix::process::ExitStatusExt;
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: b"operation not permitted".to_vec(),
        };
        assert!(optional_command_output(&["nft", "list", "ruleset"], Ok(output)).is_err());
    }
    #[test]
    fn secure_tokens_are_available_on_this_platform() {
        let a = random_token().unwrap();
        let b = random_token().unwrap();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
    /// An `up` stand with a recorded guest GUID, and a Verify report written by the guest.
    fn record_setup(h: &Fake, verified_at: f64, report_nonce: &str) -> (PathBuf, Args) {
        let p = temp();
        let a = args(&p, "up");
        execute(h, &a).unwrap();
        attach(h);
        let mut m = read_manifest(&a.manifest).unwrap().unwrap();
        m["guest"]["guid"] = json!("{A}");
        write_manifest(&a.manifest, &m).unwrap();
        let verify = p.join("verify.json");
        write_manifest(&verify, &json!({"ok":true,"verified_at":verified_at,"verification_nonce":report_nonce,"lab":{"Status":"Up","MacAddress":derive("t1").unwrap().windows_mac,"InterfaceGuid":"{A}"}})).unwrap();
        let mut r = args(&p, "record-guest");
        r.verify_json = Some(verify);
        r.nonce = Some("check-1".into());
        (p, r)
    }
    fn fresh_after(h: &Fake, a: &Args) -> bool {
        guest_fresh(
            &read_manifest(&a.manifest).unwrap().unwrap(),
            &h.vm(&derive("t1").unwrap()),
        )
    }
    fn host(start: Option<f64>) -> Fake {
        let h = Fake::default();
        h.vm_start.set(start);
        h
    }
    #[test]
    fn record_guest_refuses_a_report_for_another_nonce() {
        let h = host(None);
        let (p, a) = record_setup(&h, now(), "check-OTHER");
        assert!(execute(&h, &a).unwrap_err().contains("mismatched"));
        assert!(!fresh_after(&h, &a));
        assert!(read_manifest(&a.manifest).unwrap().unwrap()["guest"]["verify"].is_null());
        fs::remove_dir_all(p).unwrap();
        let h = host(None);
        let (p, ok) = record_setup(&h, now(), "check-1");
        assert_eq!(execute(&h, &ok).unwrap(), 0);
        assert!(fresh_after(&h, &ok));
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn record_guest_refuses_reports_outside_the_sixty_second_window() {
        let decision_at = 1_700_000_000.0;
        for (age, accepted) in [
            (30.0, true),
            (59.0, true),
            (60.0, true),
            (60.001, false),
            (61.0, false),
            (3600.0, false),
        ] {
            let h = host(None);
            let verified_at = decision_at - age;
            let (p, a) = record_setup(&h, verified_at, "check-1");
            let clock_reads = std::cell::Cell::new(0);
            assert_eq!(
                execute_with_clock(&h, &a, || {
                    clock_reads.set(clock_reads.get() + 1);
                    decision_at
                })
                .is_ok(),
                accepted,
                "age {age}s"
            );
            assert_eq!(clock_reads.get(), 1);
            assert_eq!(fresh_after(&h, &a), accepted, "age {age}s");
            let m = read_manifest(&a.manifest).unwrap().unwrap();
            if accepted {
                assert_eq!(m["guest"]["verify"]["verified_at"], verified_at);
                assert_eq!(m["guest"]["verify"]["recorded_at"], decision_at);
            } else {
                assert!(m["guest"]["verify"].is_null());
            }
            fs::remove_dir_all(p).unwrap();
        }
    }
    #[test]
    fn record_guest_accepts_only_reports_within_the_future_skew_window() {
        let decision_at = 1_700_000_000.0;
        for (ahead, accepted) in [(5.0, true), (5.001, false), (30.0, false)] {
            let h = host(None);
            let (p, a) = record_setup(&h, decision_at + ahead, "check-1");
            assert_eq!(
                execute_with_clock(&h, &a, || decision_at).is_ok(),
                accepted,
                "ahead {ahead}s"
            );
            assert_eq!(fresh_after(&h, &a), accepted, "ahead {ahead}s");
            let m = read_manifest(&a.manifest).unwrap().unwrap();
            if accepted {
                assert_eq!(m["guest"]["verify"]["recorded_at"], decision_at);
            } else {
                assert!(m["guest"]["verify"].is_null());
            }
            fs::remove_dir_all(p).unwrap();
        }
    }
    #[test]
    fn record_guest_refuses_a_verify_that_predates_the_vm_start() {
        let decision_at = 1_700_000_000.0;
        // Both reports are inside the 60 s window, so only the VM start rule can refuse.
        let h = host(Some(decision_at - 10.0));
        let (p, a) = record_setup(&h, decision_at - 20.0, "check-1");
        assert!(execute_with_clock(&h, &a, || decision_at).is_err());
        assert!(!fresh_after(&h, &a));
        fs::remove_dir_all(p).unwrap();
        let h = host(Some(decision_at - 10.0));
        let (p, a) = record_setup(&h, decision_at - 5.0, "check-1");
        assert_eq!(execute_with_clock(&h, &a, || decision_at).unwrap(), 0);
        assert!(fresh_after(&h, &a));
        fs::remove_dir_all(p).unwrap();
        // An unknown VM start (no VM process) can never validate a report.
        let h = host(Some(0.0));
        let (p, a) = record_setup(&h, decision_at, "check-1");
        assert!(execute_with_clock(&h, &a, || decision_at).is_err());
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn verification_import_rejects_replay_and_revokes_previous_success() {
        let h = Fake::default();
        let p = temp();
        let a = args(&p, "up");
        execute(&h, &a).unwrap();
        let mut m = read_manifest(&a.manifest).unwrap().unwrap();
        m["guest"]["guid"] = json!("{A}");
        write_manifest(&a.manifest, &m).unwrap();
        let verify = p.join("verify.json");
        write_manifest(&verify, &json!({"ok":true,"verified_at":now(),"verification_nonce":"check-1","lab":{"Status":"Up","MacAddress":derive("t1").unwrap().windows_mac,"InterfaceGuid":"{A}"}})).unwrap();
        let mut a = args(&p, "record-guest");
        a.verify_json = Some(verify);
        a.nonce = Some("check-1".into());
        assert_eq!(execute(&h, &a).unwrap(), 0);
        assert!(guest_fresh(
            &read_manifest(&a.manifest).unwrap().unwrap(),
            &h.vm(&derive("t1").unwrap())
        ));
        assert!(execute(&h, &a).is_err());
        assert!(read_manifest(&a.manifest).unwrap().unwrap()["guest"]["verify"].is_null());
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn status_reports_the_nonce_of_the_guest_verify_it_relied_on() {
        // WR I3 residual: status-pre.json must carry the attested nonce so the verifier can bind the
        // gate decision to this invocation.
        let h = host(None);
        let (p, a) = record_setup(&h, now(), "check-1");
        let report = |h: &Fake, p: &Path| {
            out_lines();
            let mut s = args(p, "status");
            s.host_only = false;
            execute(h, &s).unwrap();
            out_lines().pop().unwrap()
        };
        assert!(
            report(&h, &p)["guest_verify_nonce"].is_null(),
            "nothing attested yet"
        );
        assert_eq!(execute(&h, &a).unwrap(), 0);
        let r = report(&h, &p);
        assert_eq!(r["guest_verify_nonce"], "check-1", "{r}");
        // A host-only status makes no claim about the guest.
        out_lines();
        execute(&h, &args(&p, "status")).unwrap();
        assert!(out_lines().pop().unwrap()["guest_verify_nonce"].is_null());
        fs::remove_dir_all(p).unwrap();
    }
    // ---- F2: port of test_windows_vm_lab.py ----
    fn is_cmd(c: &[String], p: &[&str]) -> bool {
        c.len() >= p.len() && c.iter().zip(p).all(|(a, b)| a == b)
    }
    fn out_lines() -> Vec<Value> {
        OUTPUT.with(|o| {
            o.borrow_mut()
                .drain(..)
                .filter_map(|l| serde_json::from_str(&l).ok())
                .collect()
        })
    }
    fn up(h: &Fake) -> (PathBuf, Args) {
        let p = temp();
        let a = args(&p, "up");
        assert_eq!(execute(h, &a).unwrap(), 0);
        (p, a)
    }
    /// Host-only status of an up stand: (exit code, report).
    fn status(h: &Fake, p: &Path) -> (i32, Value) {
        out_lines();
        let rc = execute(h, &args(p, "status")).unwrap();
        (rc, out_lines().pop().unwrap())
    }
    fn full_status(h: &Fake, p: &Path) -> (i32, Value) {
        out_lines();
        let mut a = args(p, "status");
        a.host_only = false;
        let rc = execute(h, &a).unwrap();
        (rc, out_lines().pop().unwrap())
    }
    fn violations(report: &Value) -> String {
        report["isolation_violations"].to_string()
    }
    fn set_sysctl(h: &Fake, k: &str, v: &str) {
        h.sysctls.borrow_mut().insert(k.into(), v.into());
    }
    fn no_mutation(h: &Fake) -> bool {
        h.links.borrow().is_empty()
            && h.ns.borrow().is_empty()
            && !h.calls.borrow().iter().any(|c| {
                c.starts_with(&["ip".into(), "link".into(), "add".into()])
                    || c.starts_with(&["ip".into(), "tuntap".into()])
                    || c.starts_with(&["ip".into(), "netns".into(), "add".into()])
            })
    }
    #[test]
    fn derived_names_fit_ifnamsiz_and_macs_never_collide() {
        let d = derive("abcdefgh").unwrap();
        for n in [&d.bridge, &d.tap, &d.veth_host, &d.peer_if] {
            assert!(n.len() <= 15, "{n}");
        }
        assert_ne!(
            derive("a").unwrap().windows_mac,
            derive("b").unwrap().windows_mac
        );
        // The old derivation collided for these ids.
        for id in ["rg", "yr", "6p", "80", "n2", "t1"] {
            let d = derive(id).unwrap();
            let macs = BTreeSet::from([d.windows_mac, d.peer_mac, d.veth_host_mac]);
            assert_eq!(macs.len(), 3, "{id}");
        }
        assert!(derive("../x").is_err());
    }
    #[test]
    fn busy_names_refuse_up_and_change_nothing() {
        for busy in ["wvb-t1", "wvt-t1", "wvh-t1", "wvp-t1"] {
            let h = Fake::default();
            if busy.starts_with("wvp") {
                h.ns.borrow_mut().insert(busy.into());
            } else {
                h.links.borrow_mut().insert(busy.into(), Link::default());
            }
            let before = (h.links.borrow().clone().len(), h.ns.borrow().clone());
            let p = temp();
            let err = execute(&h, &args(&p, "up")).unwrap_err();
            assert!(err.contains("busy"), "{err}");
            assert!(err.contains("nothing created or removed"));
            assert_eq!((h.links.borrow().len(), h.ns.borrow().clone()), before);
            assert!(
                !h.calls
                    .borrow()
                    .iter()
                    .any(|c| is_cmd(c, &["ip", "link", "del"]))
            );
            assert!(!p.join("manifest.json").exists(), "{busy}");
            fs::remove_dir_all(p).unwrap();
        }
    }
    #[test]
    fn a_foreign_namespace_of_our_name_is_never_deleted_by_a_stale_manifest() {
        let h = Fake::default();
        let d = derive("t1").unwrap();
        h.ns.borrow_mut().insert(d.netns.clone());
        let p = temp();
        write_manifest(
            &p.join("manifest.json"),
            &json!({"run_id":"t1","token":"tok-A","state":"creating","names":d,"created":[{"kind":"netns","name":d.netns}]}),
        )
        .unwrap();
        assert_eq!(execute(&h, &args(&p, "down")).unwrap(), 5);
        assert!(h.ns.borrow().contains(&d.netns));
        assert!(
            !h.calls
                .borrow()
                .iter()
                .any(|c| is_cmd(c, &["ip", "netns", "del"]))
        );
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn another_manifest_for_the_same_run_id_cannot_delete_our_stand() {
        let h = Fake::default();
        let (p, a) = up(&h);
        let d = derive("t1").unwrap();
        let other = p.join("other.json");
        write_manifest(
            &other,
            &json!({"run_id":"t1","token":"other-token","state":"up","names":d,"created":[]}),
        )
        .unwrap();
        let mut o = args(&p, "down");
        o.manifest = other;
        assert_eq!(execute(&h, &o).unwrap(), 5);
        for n in [&d.bridge, &d.tap, &d.veth_host] {
            assert!(h.links.borrow().contains_key(n), "{n}");
        }
        assert_eq!(execute(&h, &args(&p, "down")).unwrap(), 0);
        assert!(h.links.borrow().is_empty() && h.ns.borrow().is_empty());
        let _ = a;
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn a_namespace_with_another_manifests_token_is_not_deleted() {
        let h = Fake::default();
        let (p, _) = up(&h);
        let d = derive("t1").unwrap();
        h.marks
            .borrow_mut()
            .insert(d.netns.clone(), "someone-elses-token".into());
        assert_eq!(execute(&h, &args(&p, "down")).unwrap(), 5);
        assert!(h.ns.borrow().contains(&d.netns));
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn plan_changes_nothing_and_conflicts_block_it() {
        let h = Fake::default();
        let p = temp();
        assert_eq!(execute(&h, &args(&p, "plan")).unwrap(), 0);
        assert!(no_mutation(&h));
        assert!(!p.join("manifest.json").exists());
        // A routed 198.18.0.0/24 conflicts.
        let h = Fake::default();
        h.replies.borrow_mut().push((
            "ip -j route".into(),
            r#"[{"dst":"198.18.0.0/24"},{"dst":"default"}]"#.into(),
        ));
        assert_eq!(execute(&h, &args(&p, "plan")).unwrap(), 3);
        assert!(
            out_lines().pop().unwrap()["problems"]
                .to_string()
                .contains("route conflict")
        );
        // So does a host address inside the lab net.
        let h = Fake::default();
        h.links.borrow_mut().insert(
            "eno1".into(),
            Link {
                addrs: vec!["198.18.0.5/24".into()],
                ..Default::default()
            },
        );
        assert_eq!(execute(&h, &args(&p, "plan")).unwrap(), 3);
        // Global forwarding or a firewall rule naming a lab interface blocks plan and up.
        let h = Fake::default();
        set_sysctl(&h, "net.ipv4.ip_forward", "1");
        assert_eq!(execute(&h, &args(&p, "plan")).unwrap(), 3);
        assert!(execute(&h, &args(&p, "up")).is_err());
        assert!(no_mutation(&h));
        let h = Fake::default();
        h.replies.borrow_mut().push((
            "nft list ruleset".into(),
            "iifname \"wvb-t1\" accept".into(),
        ));
        assert_eq!(execute(&h, &args(&p, "plan")).unwrap(), 3);
        assert!(
            out_lines().pop().unwrap()["problems"]
                .to_string()
                .contains("firewall")
        );
        assert!(execute(&h, &args(&p, "up")).is_err());
        assert!(no_mutation(&h));
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn a_physical_uplink_enslaved_during_up_is_rejected_and_rolled_back() {
        let h = Fake::default();
        h.links.borrow_mut().insert(
            "eno1".into(),
            Link {
                physical: true,
                addrs: vec!["192.168.1.148/24".into()],
                ..Default::default()
            },
        );
        let before = h.links.borrow().get("eno1").unwrap().addrs.clone();
        *h.rogue.borrow_mut() = Some("eno1".into());
        let p = temp();
        assert_eq!(execute(&h, &args(&p, "up")).unwrap(), 4);
        let l = h.links.borrow();
        assert_eq!(l.keys().cloned().collect::<Vec<_>>(), vec!["eno1"]);
        assert_eq!(l["eno1"].addrs, before);
        assert!(
            !h.calls
                .borrow()
                .iter()
                .any(|c| c == &["ip", "link", "del", "eno1"])
        );
        assert!(h.ns.borrow().is_empty() && h.marks.borrow().is_empty());
        let m = read_manifest(&p.join("manifest.json")).unwrap().unwrap();
        assert_eq!(m["state"], "down"); // a re-upable manifest
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn status_flags_a_physical_uplink_enslaved_later() {
        let h = Fake::default();
        let (p, _) = up(&h);
        h.links.borrow_mut().insert(
            "eno1".into(),
            Link {
                physical: true,
                ..Default::default()
            },
        );
        assert_eq!(status(&h, &p).0, 0);
        h.links.borrow_mut().get_mut("eno1").unwrap().master = Some("wvb-t1".into());
        let (rc, r) = status(&h, &p);
        assert_eq!(rc, 1);
        assert!(violations(&r).contains("physical uplink eno1"));
        fs::remove_dir_all(p).unwrap();
    }
    /// Break one isolation fact on an up stand and require status to name it.
    fn break_and_expect(change: impl FnOnce(&Fake), needle: &str) {
        let h = Fake::default();
        let (p, _) = up(&h);
        let (rc, r) = status(&h, &p);
        assert_eq!(rc, 0, "{r}");
        assert_eq!(r["isolation_violations"], json!([]));
        change(&h);
        let (rc, r) = status(&h, &p);
        assert_eq!(rc, 1, "{needle}");
        assert!(violations(&r).contains(needle), "{needle}: {r}");
        assert_eq!(r["raw_run_allowed"], false);
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn an_unexpected_non_physical_port_on_the_bridge_is_named_as_a_violation() {
        // WR N3: a virtual port (not the TAP, not the host-side veth) enslaved to the lab bridge.
        break_and_expect(
            |h| {
                h.links.borrow_mut().insert(
                    "dummy9".into(),
                    Link {
                        master: Some("wvb-t1".into()),
                        noarp: true,
                        ..Default::default()
                    },
                );
            },
            "unexpected port dummy9 on bridge",
        );
    }
    #[test]
    fn bridge_self_vlan_is_a_violation() {
        break_and_expect(
            |h| {
                h.replies.borrow_mut().push((
                    "bridge -j vlan show".into(),
                    r#"[{"ifname":"wvb-t1","vlans":[{"vlan":1}]}]"#.into(),
                ))
            },
            "self VLAN",
        );
    }
    #[test]
    fn an_unreadable_bridge_vlan_table_is_a_violation_not_a_pass() {
        break_and_expect(
            |h| {
                h.replies
                    .borrow_mut()
                    .push(("bridge -j vlan show".into(), "not json".into()))
            },
            "cannot read bridge self VLANs",
        );
    }
    #[test]
    fn vlan_filtering_off_is_a_violation() {
        break_and_expect(
            |h| {
                h.links
                    .borrow_mut()
                    .get_mut("wvb-t1")
                    .unwrap()
                    .vlan_filtering = false
            },
            "vlan_filtering",
        );
    }
    #[test]
    fn arp_on_is_a_violation_on_every_lab_interface() {
        for n in ["wvb-t1", "wvt-t1", "wvh-t1"] {
            break_and_expect(
                |h| h.links.borrow_mut().get_mut(n).unwrap().noarp = false,
                &format!("{n} is not NOARP"),
            );
        }
    }
    #[test]
    fn arp_ignore_rp_filter_forwarding_and_ipv6_violations() {
        for (n, key, bad) in [
            ("wvb-t1", "arp_ignore", "0"),
            ("wvt-t1", "rp_filter", "2"),
            ("wvh-t1", "forwarding", "1"),
        ] {
            break_and_expect(
                |h| set_sysctl(h, &format!("net.ipv4.conf.{n}.{key}"), bad),
                &format!("{n}: {key}"),
            );
        }
        break_and_expect(
            |h| set_sysctl(h, "net.ipv6.conf.wvt-t1.disable_ipv6", "0"),
            "IPv6 not disabled",
        );
    }
    #[test]
    fn global_ip_forward_enabled_later_is_a_violation() {
        break_and_expect(|h| set_sysctl(h, "net.ipv4.ip_forward", "1"), "ip_forward");
    }
    #[test]
    fn a_host_ip_on_bridge_or_tap_is_a_violation() {
        for n in ["wvb-t1", "wvt-t1", "wvh-t1"] {
            break_and_expect(
                |h| {
                    h.links
                        .borrow_mut()
                        .get_mut(n)
                        .unwrap()
                        .addrs
                        .push("198.18.0.9/30".into())
                },
                "host IP",
            );
        }
    }
    #[test]
    fn a_firewall_rule_naming_a_lab_interface_is_a_violation() {
        for cmd in ["nft list ruleset", "iptables-save", "ip6tables-save"] {
            break_and_expect(
                |h| {
                    h.replies
                        .borrow_mut()
                        .push((cmd.into(), "-A FORWARD -i wvb-t1 -j ACCEPT".into()))
                },
                "firewall",
            );
        }
        // A rule that merely contains the name as a substring of another word is not ours.
        let h = Fake::default();
        let (p, _) = up(&h);
        h.replies.borrow_mut().push((
            "nft list ruleset".into(),
            "iifname \"xwvb-t1y\" accept".into(),
        ));
        assert_eq!(status(&h, &p).0, 0);
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn host_only_status_is_ok_but_never_allows_a_raw_run_without_attachment() {
        let h = Fake::default();
        let (p, _) = up(&h);
        let (rc, r) = status(&h, &p);
        assert_eq!(rc, 0);
        assert_eq!(r["host_ok"], true);
        // The TAP has no carrier, so the VM is not attached, and no guest record exists.
        assert_eq!(r["raw_run_allowed"], false);
        assert_eq!(r["vm"]["attached"], false);
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn status_is_not_ok_without_vm_attachment() {
        let h = Fake::default();
        let (p, _) = up(&h);
        let (rc, r) = full_status(&h, &p);
        assert_eq!(rc, 1);
        assert_eq!(r["raw_run_allowed"], false);
        let m = read_manifest(&p.join("manifest.json")).unwrap().unwrap();
        assert_eq!(m["vm"]["attached"], false);
        fs::remove_dir_all(p).unwrap();
    }
    fn attach(h: &Fake) {
        h.links.borrow_mut().get_mut("wvt-t1").unwrap().lower_up = true;
    }
    fn recorded_stand(h: &Fake, status_text: &str, mac: Option<&str>) -> (PathBuf, Args) {
        let p = temp();
        let a = args(&p, "up");
        execute(h, &a).unwrap();
        attach(h);
        let mut m = read_manifest(&a.manifest).unwrap().unwrap();
        m["guest"]["guid"] = json!("{A}");
        write_manifest(&a.manifest, &m).unwrap();
        let verify = p.join("verify.json");
        let mac = mac.map_or(derive("t1").unwrap().windows_mac, str::to_string);
        write_manifest(&verify, &json!({"ok":true,"verified_at":now(),"verification_nonce":"check-1","lab":{"Status":status_text,"MacAddress":mac,"InterfaceGuid":"{A}"}})).unwrap();
        let mut r = args(&p, "record-guest");
        r.verify_json = Some(verify);
        r.nonce = Some("check-1".into());
        assert_eq!(execute(h, &r).unwrap(), 0);
        (p, a)
    }
    #[test]
    fn status_ok_needs_every_attachment_fact_the_carrier_and_a_fresh_guest() {
        let h = Fake::default();
        let (p, _) = recorded_stand(&h, "Up", None);
        let (rc, r) = full_status(&h, &p);
        assert_eq!((rc, r["raw_run_allowed"].clone()), (0, json!(true)), "{r}");
        let m = read_manifest(&p.join("manifest.json")).unwrap().unwrap();
        assert_eq!(m["vm"]["attached"], true);
        let good = json!({"pid":42,"cmdline_ok":true,"fd_iff":true,"start":1.0});
        for (k, bad) in [
            ("cmdline_ok", json!(false)),
            ("fd_iff", json!(false)),
            ("pid", Value::Null),
        ] {
            let mut v = good.clone();
            v[k] = bad;
            *h.vm_facts.borrow_mut() = Some(v);
            let (rc, r) = full_status(&h, &p);
            assert_eq!((rc, r["raw_run_allowed"].clone()), (1, json!(false)), "{k}");
            let m = read_manifest(&p.join("manifest.json")).unwrap().unwrap();
            assert_eq!(m["vm"]["attached"], false, "{k}");
        }
        *h.vm_facts.borrow_mut() = None;
        // A stale or detached TAP has no carrier.
        h.links.borrow_mut().get_mut("wvt-t1").unwrap().lower_up = false;
        assert_eq!(full_status(&h, &p).0, 1);
        attach(&h);
        assert_eq!(full_status(&h, &p).0, 0);
        // The VM restarted after the guest record: the record is stale.
        h.vm_start.set(Some(now() + 1000.0));
        assert_eq!(full_status(&h, &p).0, 1);
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn a_guest_verify_must_be_up_and_report_the_lab_mac() {
        for (status_text, mac) in [("Disconnected", None), ("Up", Some("52-54-00-aa-aa-aa"))] {
            let h = Fake::default();
            let (p, _) = recorded_stand(&h, status_text, mac);
            let (rc, r) = full_status(&h, &p);
            assert_eq!(rc, 1, "{status_text} {mac:?}");
            assert_eq!(r["guest_verify_fresh"], false);
            assert_eq!(r["host_ok"], true);
            fs::remove_dir_all(p).unwrap();
        }
        // ok:false from the guest is not fresh either.
        let h = Fake::default();
        let (p, _) = recorded_stand(&h, "Up", None);
        let mut m = read_manifest(&p.join("manifest.json")).unwrap().unwrap();
        m["guest"]["verify"]["ok"] = json!(false);
        write_manifest(&p.join("manifest.json"), &m).unwrap();
        assert_eq!(full_status(&h, &p).0, 1);
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn record_guest_selects_exactly_one_adapter_by_the_lab_mac() {
        let h = Fake::default();
        let (p, _) = up(&h);
        let mac = derive("t1").unwrap().windows_mac;
        let guest = |ads: Value| {
            let g = p.join("g.json");
            write_manifest(&g, &json!({"adapters": ads})).unwrap();
            let mut a = args(&p, "record-guest");
            a.guest_json = Some(g);
            execute(&h, &a)
        };
        let upper = mac.to_uppercase().replace(':', "-");
        let two = json!([{"MacAddress":upper,"InterfaceGuid":"{1}"},{"MacAddress":mac,"InterfaceGuid":"{2}"}]);
        assert!(guest(two).unwrap_err().contains("ambiguous"));
        assert!(guest(json!([{"MacAddress":"52-54-00-00-00-01","InterfaceGuid":"{1}"}])).is_err());
        // The management NIC is never the lab NIC.
        assert!(
            guest(
                json!([{"MacAddress":MGMT.to_uppercase().replace(':', "-"),"InterfaceGuid":"{M}"}])
            )
            .is_err()
        );
        assert!(
            guest(json!([{"MacAddress":upper,"InterfaceGuid":""}]))
                .unwrap_err()
                .contains("malformed")
        );
        assert_eq!(
            guest(json!([{"MacAddress":upper,"InterfaceGuid":"{1}"}])).unwrap(),
            0
        );
        let m = read_manifest(&p.join("manifest.json")).unwrap().unwrap();
        assert_eq!(m["guest"]["guid"], "{1}");
        assert_eq!(m["guest"]["npf"], "\\Device\\NPF_{1}");
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn a_malformed_guest_record_is_a_clean_error() {
        let h = Fake::default();
        let (p, _) = up(&h);
        let g = p.join("bad.json");
        fs::write(&g, "{}").unwrap();
        let mut a = args(&p, "record-guest");
        a.guest_json = Some(g);
        assert!(execute(&h, &a).unwrap_err().contains("malformed"));
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn a_taken_name_at_create_time_deletes_nothing_it_did_not_create() {
        for (failing, created, may_delete) in [
            ("ip link add wvb-t1", vec![], vec![]),
            ("ip tuntap add", vec!["wvb-t1"], vec!["wvb-t1"]),
            (
                "ip link add wvh-t1",
                vec!["wvb-t1", "wvt-t1"],
                vec!["wvb-t1", "wvt-t1"],
            ),
        ] {
            let h = Fake::default();
            *h.fail.borrow_mut() = Some(failing.into());
            let p = temp();
            assert_eq!(execute(&h, &args(&p, "up")).unwrap(), 4, "{failing}");
            let deleted: Vec<String> = h
                .calls
                .borrow()
                .iter()
                .filter(|c| is_cmd(c, &["ip", "link", "del"]))
                .map(|c| c[3].clone())
                .collect();
            assert!(
                deleted.iter().all(|d| may_delete.contains(&d.as_str())),
                "{failing}: {deleted:?}"
            );
            assert_eq!(deleted.len(), created.len(), "{failing}: {deleted:?}");
            assert!(h.links.borrow().is_empty());
            fs::remove_dir_all(p).unwrap();
        }
    }
    #[test]
    fn every_non_plan_command_runs_under_the_run_id_lock() {
        let locks = temp();
        let h = Fake::default();
        *h.lock_probe.borrow_mut() = Some(locks.clone());
        // The probe opens the lock file, so it must exist before the first command.
        fs::write(locks.join("t1.lock"), "").unwrap();
        let p = temp();
        for cmd in ["up", "status", "down"] {
            let mut a = args(&p, cmd);
            a.manifest = locks.join("manifest.json");
            let held = h.lock_was_held.get();
            dispatch(&h, &a, &locks, Duration::from_secs(1)).unwrap();
            assert!(h.lock_was_held.get() > held, "{cmd}");
            assert_eq!(
                h.lock_was_free.get(),
                0,
                "{cmd}: ran a command outside the lock"
            );
        }
        fs::remove_dir_all(p).unwrap();
        // plan takes no lock.
        let h = Fake::default();
        *h.lock_probe.borrow_mut() = Some(locks.clone());
        let p = temp();
        let mut a = args(&p, "plan");
        a.manifest = locks.join("m2.json");
        dispatch(&h, &a, &locks, Duration::from_secs(1)).unwrap();
        assert!(h.lock_was_held.get() == 0 && h.lock_was_free.get() > 0);
        fs::remove_dir_all(p).unwrap();
        fs::remove_dir_all(locks).unwrap();
    }
    #[test]
    fn the_real_lock_serializes_the_same_run_id_and_releases_afterwards() {
        let dir = temp();
        let lock = |id: &str| {
            let f = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(dir.join(format!("{id}.lock")))
                .unwrap();
            f.try_lock().map(|()| f)
        };
        let held = lock("t1").unwrap();
        assert!(matches!(lock("t1"), Err(std::fs::TryLockError::WouldBlock)));
        // dispatch with a busy lock times out with a clear error and runs nothing.
        let h = Fake::default();
        let p = temp();
        let err = dispatch(&h, &args(&p, "status"), &dir, Duration::from_millis(100)).unwrap_err();
        assert!(err.contains("holds run lock"), "{err}");
        assert!(h.calls.borrow().is_empty());
        // Another run-id is independent.
        let other = lock("t2").unwrap();
        drop(other);
        drop(held);
        // A child that a parallel test forks can share the open file description between fork
        // and exec, so the flock may outlive `drop` by a moment (dispatch retries for the same
        // reason). Released means: free again within a bounded wait.
        let t = Instant::now();
        while lock("t1").is_err() {
            assert!(
                t.elapsed() < Duration::from_secs(5),
                "t1 lock was not released"
            );
            thread::sleep(Duration::from_millis(10));
        }
        fs::remove_dir_all(p).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn network_manager_not_running_is_not_fatal_and_running_marks_the_link_unmanaged() {
        let h = Fake::default();
        l2only(&h, "wvb-t1").unwrap();
        assert!(
            !h.calls
                .borrow()
                .iter()
                .any(|c| is_cmd(c, &["nmcli", "device"]))
        );
        assert!(
            h.calls
                .borrow()
                .iter()
                .any(|c| c == &["ip", "link", "set", "wvb-t1", "arp", "off"])
        );
        let h = Fake::default();
        *h.fail.borrow_mut() = Some("nmcli -t -f RUNNING".into());
        l2only(&h, "wvb-t1").unwrap();
        assert!(
            !h.calls
                .borrow()
                .iter()
                .any(|c| is_cmd(c, &["nmcli", "device"]))
        );
        let h = Fake::default();
        h.replies
            .borrow_mut()
            .push(("nmcli -t -f RUNNING".into(), "running".into()));
        h.replies
            .borrow_mut()
            .push(("nmcli -t -f DEVICE,STATE".into(), "wvb-t1:unmanaged".into()));
        l2only(&h, "wvb-t1").unwrap();
        assert!(
            h.calls
                .borrow()
                .iter()
                .any(|c| c == &["nmcli", "device", "set", "wvb-t1", "managed", "no"])
        );
    }
    #[test]
    fn down_without_a_manifest_is_a_noop_that_leaves_look_alike_objects() {
        let h = Fake::default();
        let d = derive("t1").unwrap();
        h.links.borrow_mut().insert(
            d.bridge.clone(),
            Link {
                alias: alias(&d, "whatever"),
                ..Default::default()
            },
        );
        let p = temp();
        assert_eq!(execute(&h, &args(&p, "down")).unwrap(), 0);
        assert!(h.links.borrow().contains_key(&d.bridge));
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn an_incomplete_up_is_refused_and_down_cleans_only_our_objects() {
        let h = Fake::default();
        let d = derive("t1").unwrap();
        let p = temp();
        write_manifest(
            &p.join("manifest.json"),
            &json!({"run_id":"t1","token":"tok-A","state":"creating","names":d,"created":[{"kind":"link","name":d.bridge}]}),
        )
        .unwrap();
        for n in [&d.bridge, &d.tap] {
            h.links.borrow_mut().insert(
                n.clone(),
                Link {
                    alias: alias(&d, "tok-A"),
                    noarp: true,
                    ..Default::default()
                },
            );
        }
        h.ns.borrow_mut().insert("foreign-ns".into());
        let err = execute(&h, &args(&p, "up")).unwrap_err();
        assert!(err.contains("state=\"creating\""), "{err}");
        assert_eq!(status(&h, &p).0, 1);
        assert_eq!(execute(&h, &args(&p, "down")).unwrap(), 0);
        assert!(h.links.borrow().is_empty());
        assert!(h.ns.borrow().contains("foreign-ns"));
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn up_after_a_clean_down_gets_a_fresh_token_and_a_healthy_stand() {
        let h = Fake::default();
        let (p, a) = up(&h);
        let t1 = read_manifest(&a.manifest).unwrap().unwrap()["token"].clone();
        assert_eq!(execute(&h, &args(&p, "down")).unwrap(), 0);
        assert_eq!(execute(&h, &args(&p, "up")).unwrap(), 0);
        let t2 = read_manifest(&a.manifest).unwrap().unwrap()["token"].clone();
        assert_ne!(t1, t2);
        assert_eq!(status(&h, &p).0, 0);
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn the_lab_env_of_another_run_is_not_overwritten() {
        let h = Fake::default();
        let p = temp();
        let env = p.join("lab.env");
        fs::write(&env, "LAB_RUN_ID=other\nLAB_TAP=wvt-other\n").unwrap();
        let mut a = args(&p, "up");
        a.lab_env = Some(env.clone());
        let err = execute(&h, &a).unwrap_err();
        assert!(err.contains("another run-id"), "{err}");
        assert!(h.links.borrow().is_empty());
        assert!(
            fs::read_to_string(env)
                .unwrap()
                .contains("LAB_RUN_ID=other")
        );
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn up_status_down_roundtrip_records_the_lab_net_and_keeps_the_uplink() {
        let h = Fake::default();
        let eno1 = Link {
            physical: true,
            addrs: vec!["192.168.1.148/24".into()],
            mac: "c8:7f:54:6c:e4:33".into(),
            lower_up: true,
            ..Default::default()
        };
        h.links.borrow_mut().insert("eno1".into(), eno1.clone());
        let (p, a) = up(&h);
        let m = read_manifest(&a.manifest).unwrap().unwrap();
        assert_eq!(m["state"], "up");
        assert_eq!(m["lab"]["windows_ip"], "198.18.0.1");
        assert_eq!(m["lab"]["peer_ip"], "198.18.0.2");
        assert!(m["lab"]["gateway"].is_null() && m["lab"]["dns"].is_null());
        assert_eq!(h.links.borrow()["eno1"].addrs, eno1.addrs);
        assert_eq!(h.links.borrow()["eno1"].master, None);
        assert_eq!(execute(&h, &args(&p, "down")).unwrap(), 0);
        assert_eq!(h.links.borrow()["eno1"].addrs, eno1.addrs);
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn the_guest_script_keeps_its_guards() {
        let ps1 = include_str!("../../../scripts/windows-vm-lab.ps1");
        for needle in [
            "Inventory",
            "Configure",
            "Verify",
            "ambiguous",
            "DefaultGateway",
            "'Up'",
            "52-54-00-12-34-56",
            "VerificationNonce",
        ] {
            assert!(ps1.contains(needle), "{needle}");
        }
    }
}

/// The std-only replacements for the former unsafe `lab_io::{restore_sudo_owner, random_bytes_16}`.
#[cfg(test)]
mod std_helper_tests {
    use super::*;

    #[test]
    fn sudo_target_applies_only_to_root_owned_files_with_valid_ids() {
        // Not root-owned: nothing to restore, whatever the environment says.
        assert_eq!(sudo_target(1000, Some("1000"), Some("1000")).unwrap(), None);
        // Root-owned (we are root, e.g. under sudo) and SUDO_UID set: restore to the caller.
        assert_eq!(
            sudo_target(0, Some("1000"), Some("1001")).unwrap(),
            Some((1000, 1001))
        );
        // SUDO_GID absent: the group falls back to the uid, as before.
        assert_eq!(
            sudo_target(0, Some("1000"), None).unwrap(),
            Some((1000, 1000))
        );
        // Running as real root with no sudo: nothing to restore.
        assert_eq!(sudo_target(0, None, None).unwrap(), None);
        // Invalid ids are an error, never silently ignored.
        for bad in ["", "x", "-1", "4294967295", "1 ", "99999999999"] {
            assert!(sudo_target(0, Some(bad), Some("1")).is_err(), "uid {bad:?}");
            assert!(sudo_target(0, Some("1"), Some(bad)).is_err(), "gid {bad:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn restoring_the_owner_of_a_file_we_own_as_a_normal_user_is_a_no_op() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("rmasscan-owner-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = fs::File::create(dir.join("report.json")).unwrap();
        if f.metadata().unwrap().uid() == 0 {
            // Real root runs this suite only inside the lab; chown would then be live.
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        restore_sudo_owner(&f).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn random_token_is_sixteen_random_bytes_as_hex() {
        let a = random_token().unwrap();
        let b = random_token().unwrap();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
