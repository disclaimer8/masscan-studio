//! Offline tests of the macOS stand. Every OS command goes to a scripted [`Fake`] host that
//! keeps a small model of the system (interfaces, ARP, routes, `/dev/bpf*` modes). No `ifconfig`,
//! `route`, `arp`, `sudo` or `/dev/bpf` is touched; manifests live in a unique scratch directory.
use super::*;
use std::cell::RefCell;
use std::collections::BTreeMap;

#[derive(Clone, Default)]
struct FIf {
    mac: String,
    inet: Option<(String, String)>,
    peer: Option<String>,
    up: bool,
}

struct State {
    root: bool,
    ifaces: BTreeMap<String, FIf>,
    arp: Option<(String, String, String)>,
    default_if: String,
    default_gw: String,
    extra_routes: Vec<String>,
    extra_ifconfig: String,
    bridge_member: bool,
    forwarding: String,
    bpf: BTreeMap<u32, (u32, u32)>,
    log: Vec<String>,
    /// Commands (joined) that fail.
    fail: Vec<String>,
    populate_calls: u32,
    staff: u32,
    route_get: BTreeMap<String, String>,
    state_dir: Option<PathBuf>,
    /// A foreign interface that appears when the next `create` runs (a race after preflight).
    appear_on_create: Option<String>,
}

struct Fake(RefCell<State>);

impl Fake {
    fn new() -> Self {
        Fake(RefCell::new(State {
            root: true,
            ifaces: BTreeMap::new(),
            arp: None,
            default_if: "en0".into(),
            default_gw: "192.168.1.1".into(),
            extra_routes: vec![],
            extra_ifconfig: String::new(),
            bridge_member: false,
            forwarding: "0".into(),
            bpf: (0..4).map(|n| (n, (0o600, 0))).collect(),
            log: vec![],
            fail: vec![],
            populate_calls: 0,
            staff: 20,
            route_get: BTreeMap::new(),
            state_dir: None,
            appear_on_create: None,
        }))
    }
    fn log(&self) -> Vec<String> {
        self.0.borrow().log.clone()
    }
    fn mutating(&self) -> Vec<String> {
        self.log()
            .into_iter()
            .filter(|c| {
                let ifconfig_change = c.starts_with("ifconfig feth")
                    && ["create", "destroy", "lladdr", "peer", "inet", "up", "down"]
                        .iter()
                        .any(|w| c.split(' ').any(|t| t == *w));
                ifconfig_change
                    || c.starts_with("arp -S")
                    || c.starts_with("arp -d")
                    || c.starts_with("bpf_set")
                    || c.starts_with("bpf_populate")
            })
            .collect()
    }
    fn st<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut self.0.borrow_mut())
    }
}

fn mac_str(m: &str) -> String {
    // macOS prints ARP MACs without leading zeros.
    m.split(':')
        .map(|p| format!("{:x}", u8::from_str_radix(p, 16).unwrap()))
        .collect::<Vec<_>>()
        .join(":")
}

fn mask_hex(m: &str) -> String {
    match m.parse::<Ipv4Addr>() {
        Ok(a) => format!("0x{:08x}", u32::from(a)),
        Err(_) => m.into(),
    }
}

impl Host for Fake {
    fn sh(&self, args: &[&str]) -> Result<String, String> {
        let line = args.join(" ");
        let mut s = self.0.borrow_mut();
        s.log.push(line.clone());
        if s.fail.contains(&line) {
            return Err(format!("{line}: scripted failure"));
        }
        let render = |name: &str, f: &FIf| {
            let mut t = format!(
                "{name}: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether {}\n",
                f.mac
            );
            if let Some((ip, m)) = &f.inet {
                t += &format!("\tinet {ip} netmask {} broadcast 198.18.0.3\n", mask_hex(m));
            }
            t += "\tmedia: autoselect\n";
            if f.up && f.peer.is_some() {
                t += "\tstatus: active\n";
            } else {
                t += "\tstatus: inactive\n";
            }
            if let Some(p) = &f.peer {
                t += &format!("\tpeer: {p}\n");
            }
            t
        };
        match args {
            ["id", "-u"] => Ok(if s.root { "0\n" } else { "501\n" }.into()),
            ["dscl", ".", "-read", "/Groups/staff", "PrimaryGroupID"] => {
                Ok(format!("PrimaryGroupID: {}\n", s.staff))
            }
            ["ifconfig", "-l"] => {
                let mut v = vec!["lo0".to_string(), "en0".to_string()];
                v.extend(s.ifaces.keys().cloned());
                Ok(v.join(" ") + "\n")
            }
            ["ifconfig", "-a"] => {
                let mut t =
                    String::from("lo0: flags=8049<UP>\n\tinet 127.0.0.1 netmask 0xff000000\n");
                t += "en0: flags=8863<UP>\n\tinet 192.168.1.157 netmask 0xffffff00 broadcast 192.168.1.255\n";
                t += &s.extra_ifconfig;
                for (n, f) in &s.ifaces {
                    t += &render(n, f);
                }
                t += "bridge0: flags=8863<UP>\n";
                if s.bridge_member {
                    t += "\tmember: feth4201 flags=3<LEARNING,DISCOVER>\n";
                } else {
                    t += "\tmember: en1 flags=3<LEARNING,DISCOVER>\n";
                }
                Ok(t)
            }
            ["ifconfig", n, "create"] => {
                if s.ifaces.contains_key(*n) {
                    return Err(format!("{n} exists"));
                }
                if let Some(x) = s.appear_on_create.take() {
                    s.ifaces.insert(
                        x,
                        FIf {
                            mac: "aa:aa:aa:aa:aa:77".into(),
                            ..FIf::default()
                        },
                    );
                }
                let mac = format!("ee:ee:ee:00:00:{:02x}", s.ifaces.len() + 1);
                s.ifaces.insert(
                    (*n).into(),
                    FIf {
                        mac,
                        ..FIf::default()
                    },
                );
                Ok(String::new())
            }
            ["ifconfig", n, "destroy"] => s
                .ifaces
                .remove(*n)
                .map(|_| String::new())
                .ok_or_else(|| format!("ifconfig: interface {n} does not exist")),
            ["ifconfig", n, "lladdr", m] => {
                s.ifaces.get_mut(*n).ok_or("no such interface")?.mac = (*m).into();
                Ok(String::new())
            }
            ["ifconfig", n, "peer", p] => {
                if !s.ifaces.contains_key(*p) {
                    return Err("no such peer".into());
                }
                s.ifaces.get_mut(*n).ok_or("no such interface")?.peer = Some((*p).into());
                s.ifaces.get_mut(*p).unwrap().peer = Some((*n).into());
                Ok(String::new())
            }
            ["ifconfig", n, "inet", ip, "netmask", m] => {
                s.ifaces.get_mut(*n).ok_or("no such interface")?.inet =
                    Some(((*ip).into(), (*m).into()));
                Ok(String::new())
            }
            ["ifconfig", n, "up"] | ["ifconfig", n, "down"] => {
                let up = args[2] == "up";
                s.ifaces.get_mut(*n).ok_or("no such interface")?.up = up;
                Ok(String::new())
            }
            ["ifconfig", n] => s
                .ifaces
                .get(*n)
                .map(|f| render(n, f))
                .ok_or_else(|| format!("ifconfig: interface {n} does not exist")),
            ["arp", "-S", ip, m, "ifscope", i] => {
                s.arp = Some(((*ip).into(), (*m).into(), (*i).into()));
                Ok(String::new())
            }
            ["arp", "-d", ip, "ifscope", i] => match &s.arp {
                Some((a, _, b)) if a == ip && b == i => {
                    s.arp = None;
                    Ok(String::new())
                }
                _ => Err("arp: delete: no entry".into()),
            },
            ["arp", "-an"] => {
                let mut t = String::from(
                    "? (192.168.1.1) at 84:3c:99:3d:79:ab on en0 ifscope [ethernet]\n",
                );
                if let Some((ip, m, i)) = &s.arp {
                    t += &format!(
                        "? ({ip}) at {} on {i} ifscope permanent [ethernet]\n",
                        mac_str(m)
                    );
                }
                Ok(t)
            }
            ["route", "-n", "get", "default"] => Ok(format!(
                "   route to: default\ndestination: default\n       mask: default\n    gateway: {}\n  interface: {}\n",
                s.default_gw, s.default_if
            )),
            ["route", "-n", "get", ip @ ("198.18.0.1" | "198.18.0.2")] => {
                let paired = s.ifaces.contains_key("feth4202");
                let iface = s
                    .route_get
                    .get(*ip)
                    .cloned()
                    .unwrap_or_else(|| match (paired, *ip) {
                        (false, _) => s.default_if.clone(),
                        (true, "198.18.0.1") => "feth4202".into(),
                        (true, _) => "lo0".into(),
                    });
                Ok(format!("   route to: {ip}\n  interface: {iface}\n"))
            }
            ["route", "-n", "get", "8.8.8.8"] => Ok(format!(
                "   route to: 8.8.8.8\n    gateway: {}\n  interface: {}\n",
                s.default_gw, s.default_if
            )),
            ["netstat", "-rn", "-f", "inet"] => {
                let mut t = format!(
                    "Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\ndefault            {} UGScg {}\n127                127.0.0.1          UCS                   lo0\n192.168.1          link#14            UCS                   en0      !\n",
                    s.default_gw, s.default_if
                );
                for r in &s.extra_routes {
                    t += r;
                    t.push('\n');
                }
                if s.ifaces.get("feth4202").is_some_and(|f| f.inet.is_some()) {
                    t += "198.18.0/30        link#22            UCS                feth4202      !\n";
                }
                if s.ifaces.get("feth4202").is_some_and(|f| f.inet.is_some()) {
                    t += "198.18.0.2/32      link#22            UCS                feth4202      !\n";
                    t += "198.18.0.2        link#22            UHS                   lo0\n";
                    t += "198.18.0.3        ff:ff:ff:ff:ff:ff  UHLSbW            feth4202      !\n";
                }
                if s.arp.is_some() {
                    t += "198.18.0.1        2:ac:0:0:0:1       UHLSW              feth4202\n";
                }
                Ok(t)
            }
            ["sysctl", "-n", "net.inet.ip.forwarding"] => Ok(format!("{}\n", s.forwarding)),
            _ => Err(format!("unscripted command: {line}")),
        }
    }
    fn bpf_stat(&self, n: u32) -> Option<(u32, u32)> {
        self.0.borrow().bpf.get(&n).copied()
    }
    fn bpf_set(&self, n: u32, mode: u32, gid: u32) -> Result<(), String> {
        let mut s = self.0.borrow_mut();
        s.log.push(format!("bpf_set {n} {mode:o} {gid}"));
        if s.fail.contains(&format!("bpf_set {n} {mode:o} {gid}")) {
            return Err(format!("bpf{n}: scripted failure"));
        }
        match s.bpf.get_mut(&n) {
            Some(v) => {
                *v = (mode, gid);
                Ok(())
            }
            None => Err(format!("bpf{n} missing")),
        }
    }
    fn state_owner(&self) -> u32 {
        test_uid()
    }
    fn state_dir(&self) -> Result<PathBuf, String> {
        self.0
            .borrow()
            .state_dir
            .clone()
            .ok_or_else(|| "no lab dir scripted".to_string())
    }
    fn bpf_populate(&self, last: u32) -> Result<(), String> {
        let mut s = self.0.borrow_mut();
        s.populate_calls += 1;
        s.log.push(format!("bpf_populate {last}"));
        if s.fail.contains(&"bpf_populate".to_string()) {
            return Err("scripted populate failure".into());
        }
        for n in 0..=last {
            s.bpf.entry(n).or_insert((0o600, 0));
        }
        Ok(())
    }
}

/// The uid that owns the files of this test process (the test binary), so the directory
/// policy sees the scratch directories as ours.
#[cfg(unix)]
fn test_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(std::env::current_exe().unwrap())
        .unwrap()
        .uid()
}
#[cfg(not(unix))]
fn test_uid() -> u32 {
    0
}

/// A unique scratch directory, removed at the end of the test.
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let d = std::env::temp_dir().join(format!(
            "rmasscan-macoslab-{}",
            crate::windows_suite::nonce()
        ));
        fs::create_dir_all(&d).unwrap();
        Scratch(d)
    }
    fn manifest(&self) -> PathBuf {
        self.0.join("m1.json")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn args(s: &Scratch, cmd: &str) -> Args {
    Args {
        cmd: cmd.into(),
        run_id: "m1".into(),
        manifest: s.manifest(),
        grant: false,
        revoke: false,
        down: false,
        up: false,
    }
}

fn go(h: &Fake, a: &Args) -> (Result<i32, String>, String) {
    h.st(|st| st.state_dir = a.manifest.parent().map(Path::to_path_buf));
    let mut out = vec![];
    let r = execute(h, a, &mut out);
    (r, out.join("\n"))
}

fn up_ok(h: &Fake, s: &Scratch) {
    let (r, out) = go(h, &args(s, "up"));
    assert_eq!(r, Ok(0), "{out}");
}

fn status_json(h: &Fake, s: &Scratch) -> (i32, Value) {
    let (r, out) = go(h, &args(s, "status"));
    (r.unwrap(), serde_json::from_str(&out).unwrap())
}

fn check_ok(v: &Value, name: &str) -> bool {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no check {name}"))["ok"]
        .as_bool()
        .unwrap()
}

#[test]
fn plan_prints_commands_and_runs_nothing() {
    let s = Scratch::new();
    let h = Fake::new();
    let (r, out) = go(&h, &args(&s, "plan"));
    assert_eq!(r, Ok(0));
    assert!(h.log().is_empty(), "plan ran {:?}", h.log());
    assert!(!s.manifest().exists());
    for want in [
        "ifconfig feth4201 create",
        "ifconfig feth4202 create",
        "ifconfig feth4201 lladdr 02:ac:00:00:00:01",
        "ifconfig feth4201 peer feth4202",
        "ifconfig feth4202 inet 198.18.0.2 netmask 255.255.255.252",
        "arp -S 198.18.0.1 02:ac:00:00:00:01 ifscope feth4202",
        "arp -d 198.18.0.1 ifscope feth4202",
        "ifconfig feth4202 destroy",
    ] {
        assert!(out.lines().any(|l| l == want), "missing {want:?} in\n{out}");
    }
}

#[test]
fn up_refuses_existing_feth_names() {
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| {
        st.ifaces.insert("feth4202".into(), FIf::default());
    });
    let (r, _) = go(&h, &args(&s, "up"));
    assert!(r.unwrap_err().contains("feth4202 already exists"));
    assert!(h.mutating().is_empty(), "{:?}", h.log());
    assert!(!s.manifest().exists());
    assert!(
        h.st(|st| st.ifaces.contains_key("feth4202")),
        "foreign interface must stay"
    );
}

#[test]
fn up_refuses_overlapping_198_18_route() {
    for row in [
        "198.18.0/24        link#9             UCS                   en7      !",
        "198.18.0.2/32      link#9             UCS                   en7      !",
        "198.18             link#9             UCS                   en7      !",
    ] {
        let s = Scratch::new();
        let h = Fake::new();
        h.st(|st| st.extra_routes.push(row.into()));
        let (r, _) = go(&h, &args(&s, "up"));
        assert!(r.unwrap_err().contains("overlaps 198.18.0.0/30"), "{row}");
        assert!(h.mutating().is_empty());
    }
    // An interface address counts too.
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| {
        st.extra_ifconfig =
            "en7: flags=8863<UP>\n\tinet 198.18.0.9 netmask 0xffff0000 broadcast 198.18.255.255\n"
                .into()
    });
    assert!(go(&h, &args(&s, "up")).0.unwrap_err().contains("overlaps"));
}

#[test]
fn up_refuses_without_root() {
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| st.root = false);
    let (r, _) = go(&h, &args(&s, "up"));
    assert!(r.unwrap_err().contains("needs root"));
    assert_eq!(h.log(), ["id -u"], "nothing but the root probe may run");
    assert!(!s.manifest().exists());
    for cmd in ["down", "bpf-access", "link"] {
        let mut a = args(&s, cmd);
        a.grant = cmd == "bpf-access";
        a.down = cmd == "link";
        let (r, _) = go(&h, &a);
        assert!(r.unwrap_err().contains("needs root"), "{cmd}");
    }
}

#[test]
fn up_rolls_back_created_interfaces_on_failure() {
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| st.fail.push("ifconfig feth4202 create".into()));
    let (r, out) = go(&h, &args(&s, "up"));
    assert_eq!(r, Ok(10), "{out}");
    let log = h.log();
    assert!(
        log.contains(&"ifconfig feth4201 destroy".to_string()),
        "{log:?}"
    );
    assert!(
        !log.contains(&"ifconfig feth4202 destroy".to_string()),
        "{log:?}"
    );
    assert!(!log.iter().any(|c| c.starts_with("arp")), "{log:?}");
    assert!(h.st(|st| st.ifaces.is_empty()));
    assert!(!s.manifest().exists() && !marker_path(&s.manifest()).exists());
}

#[test]
fn up_rolls_back_arp_and_both_interfaces_when_a_later_step_fails() {
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| st.fail.push("bpf_populate".into()));
    let (r, _) = go(&h, &args(&s, "up"));
    assert_eq!(r, Ok(10));
    assert!(h.st(|st| st.ifaces.is_empty() && st.arp.is_none()));
    assert!(!s.manifest().exists());
}

#[test]
fn up_then_status_is_sealed_and_a_second_up_is_refused() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    assert_eq!(h.st(|st| st.populate_calls), 1);
    let m: Value = serde_json::from_slice(&fs::read(s.manifest()).unwrap()).unwrap();
    assert_eq!(m["state"], "sealed");
    assert_eq!(m["uplink"], "en0");
    assert_eq!(m["gateway"], "192.168.1.1");
    assert_eq!(m["token"].as_str().unwrap().len(), 32);
    assert_eq!(m["bpf_nodes"].as_array().unwrap().len(), 16);
    assert_eq!(m["scanner_mac"], SCANNER_MAC);
    let (rc, v) = status_json(&h, &s);
    assert_eq!(rc, 0, "{v}");
    assert_eq!(v["raw_run_allowed"], true);
    assert_eq!(v["bpf_access"], "denied");
    assert_eq!(v["uplink"], "en0");
    // A second up must not reuse or touch the recorded stand.
    let before = h.log().len();
    let (r, _) = go(&h, &args(&s, "up"));
    assert!(r.unwrap_err().contains("already recorded"));
    assert_eq!(
        h.log()[before..],
        ["id -u"],
        "refused after the root probe, before any change"
    );
}

#[test]
fn status_without_a_stand_is_not_sealed() {
    let s = Scratch::new();
    let h = Fake::new();
    let (rc, v) = status_json(&h, &s);
    assert_eq!(rc, 3);
    assert_eq!(v["raw_run_allowed"], false);
    assert!(!check_ok(&v, "manifest"));
    assert!(!check_ok(&v, "interfaces"));
}

#[test]
fn status_fails_closed_when_default_route_changed() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    h.st(|st| st.default_if = "en1".into());
    let (rc, v) = status_json(&h, &s);
    assert_eq!(rc, 3);
    assert_eq!(v["raw_run_allowed"], false);
    assert!(!check_ok(&v, "default_route"));
    // Same interface, other gateway: also a change.
    h.st(|st| {
        st.default_if = "en0".into();
        st.default_gw = "10.0.0.1".into();
    });
    assert!(!check_ok(&status_json(&h, &s).1, "default_route"));
    // Back to the recorded route: sealed again.
    h.st(|st| st.default_gw = "192.168.1.1".into());
    assert_eq!(status_json(&h, &s).0, 0);
    // A default route through a feth is never fine.
    h.st(|st| st.default_if = "feth4202".into());
    assert!(!check_ok(&status_json(&h, &s).1, "default_route"));
}

#[test]
fn status_fails_closed_when_feth_is_a_bridge_member() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    h.st(|st| st.bridge_member = true);
    let (rc, v) = status_json(&h, &s);
    assert_eq!(rc, 3);
    assert!(!check_ok(&v, "bridges"));
    h.st(|st| {
        st.bridge_member = false;
        st.forwarding = "1".into();
    });
    assert!(!check_ok(&status_json(&h, &s).1, "forwarding"));
}

#[test]
fn status_fails_closed_on_stray_routes_addresses_and_missing_arp() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    h.st(|st| {
        st.extra_routes
            .push("10.9.0/24          link#30            UCS                feth4201      !".into())
    });
    assert!(!check_ok(&status_json(&h, &s).1, "routes"));
    h.st(|st| st.extra_routes.clear());
    h.st(|st| {
        st.ifaces.get_mut("feth4201").unwrap().inet =
            Some(("10.1.1.1".into(), "255.255.255.0".into()))
    });
    assert!(!check_ok(&status_json(&h, &s).1, "interfaces"));
    h.st(|st| st.ifaces.get_mut("feth4201").unwrap().inet = None);
    h.st(|st| st.arp = None);
    assert!(!check_ok(&status_json(&h, &s).1, "arp"));
}

#[test]
fn status_parses_arp_without_leading_zeros() {
    let e = parse_arp(
        "? (198.18.0.1) at 2:ac:0:0:0:1 on feth4202 ifscope permanent [ethernet]\n? (192.168.1.1) at 84:3c:99:3d:79:ab on en0 ifscope [ethernet]\n",
    );
    assert_eq!(
        e[0],
        ArpEntry {
            ip: "198.18.0.1".into(),
            mac: Some("02:ac:00:00:00:01".into()),
            iface: "feth4202".into(),
            permanent: true
        }
    );
    assert!(!e[1].permanent);
    assert_eq!(
        norm_mac("02:AC:00:00:00:01").as_deref(),
        Some("02:ac:00:00:00:01")
    );
    assert_eq!(norm_mac("2:ac:0:0:0"), None);
    assert_eq!(norm_mac("zz:ac:0:0:0:1"), None);
    // The fake prints exactly that form, so `up` + `status` exercises the same path.
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    assert!(
        h.sh(&["arp", "-an"])
            .unwrap()
            .contains("at 2:ac:0:0:0:1 on feth4202")
    );
    assert!(check_ok(&status_json(&h, &s).1, "arp"));
}

#[test]
fn status_reports_bpf_access_from_modes() {
    let h = Fake::new();
    let set = |h: &Fake, f: &dyn Fn(u32) -> (u32, u32)| {
        h.st(|st| {
            st.bpf = (0..16).map(|n| (n, f(n))).collect();
        })
    };
    set(&h, &|_| (0o660, 20));
    assert_eq!(bpf_access(&h), ("granted".into(), vec![]));
    set(&h, &|_| (0o600, 0));
    assert_eq!(bpf_access(&h).0, "denied");
    set(&h, &|n| if n == 7 { (0o600, 0) } else { (0o660, 20) });
    assert_eq!(bpf_access(&h).0, "mixed");
    // 0660 but the wrong group is not a grant.
    set(&h, &|_| (0o660, 0));
    assert_eq!(bpf_access(&h).0, "mixed");
    // Nodes that do not exist yet are reported, not an error, and do not hide the state.
    h.st(|st| st.bpf = (0..4).map(|n| (n, (0o660, 20))).collect());
    let (word, missing) = bpf_access(&h);
    assert_eq!(word, "granted");
    assert_eq!(missing, (4..16).collect::<Vec<u32>>());
    h.st(|st| st.bpf.clear());
    assert_eq!(bpf_access(&h).0, "denied");
}

#[test]
fn status_requires_all_sixteen_bpf_nodes() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    h.st(|st| {
        st.bpf.remove(&9);
    });
    let (rc, v) = status_json(&h, &s);
    assert_eq!(rc, 3);
    assert!(!check_ok(&v, "bpf_nodes"));
}

#[test]
fn bpf_access_records_previous_modes() {
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| {
        st.bpf = (0..4).map(|n| (n, (0o600, 0))).collect();
    });
    up_ok(&h, &s);
    h.st(|st| {
        st.bpf.insert(2, (0o640, 80));
    });
    let mut g = args(&s, "bpf-access");
    g.grant = true;
    let (r, out) = go(&h, &g);
    assert_eq!(r, Ok(0), "{out}");
    let m: Value = serde_json::from_slice(&fs::read(s.manifest()).unwrap()).unwrap();
    assert_eq!(m["bpf_prev"]["2"], json!({"mode":"0640","gid":80}));
    assert_eq!(m["bpf_prev"]["0"], json!({"mode":"0600","gid":0}));
    assert_eq!(m["bpf_prev"].as_object().unwrap().len(), 16);
    assert_eq!(status_json(&h, &s).1["bpf_access"], "granted");
    // revoke, grant again: the first recorded modes survive.
    let mut r = args(&s, "bpf-access");
    r.revoke = true;
    assert_eq!(go(&h, &r).0, Ok(0));
    assert_eq!(status_json(&h, &s).1["bpf_access"], "denied");
    assert_eq!(go(&h, &g).0, Ok(0));
    let m: Value = serde_json::from_slice(&fs::read(s.manifest()).unwrap()).unwrap();
    assert_eq!(m["bpf_prev"]["2"], json!({"mode":"0640","gid":80}));
    assert_eq!(status_json(&h, &s).1["bpf_access"], "granted");
}

#[test]
fn bpf_access_handles_nodes_that_do_not_exist_yet() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    // Pretend the kernel has only bpf0..3 (e.g. after a manual cleanup).
    h.st(|st| st.bpf.retain(|n, _| *n < 4));
    let mut g = args(&s, "bpf-access");
    g.grant = true;
    let (r, out) = go(&h, &g);
    assert_eq!(r, Ok(0), "{out}");
    assert!(out.contains("not present yet"), "{out}");
    assert!(h.st(|st| st.bpf.values().all(|v| *v == (0o660, 20))));
    assert_eq!(
        h.st(|st| st.bpf.len()),
        4,
        "nothing is created by bpf-access"
    );
    // status still reports the gap through bpf_nodes, and raw runs stay refused.
    let (rc, v) = status_json(&h, &s);
    assert_eq!((rc, v["bpf_access"].as_str()), (3, Some("granted")));
}

#[test]
fn bpf_access_needs_a_recorded_stand() {
    let s = Scratch::new();
    let h = Fake::new();
    let mut g = args(&s, "bpf-access");
    g.grant = true;
    assert!(go(&h, &g).0.unwrap_err().contains("no stand recorded"));
    assert!(h.st(|st| st.bpf.values().all(|v| *v == (0o600, 0))));
}

#[test]
fn down_touches_only_manifest_objects_and_revokes_bpf() {
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| {
        st.ifaces.insert(
            "feth9".into(),
            FIf {
                mac: "aa:aa:aa:aa:aa:09".into(),
                ..FIf::default()
            },
        );
    });
    up_ok(&h, &s);
    let mut g = args(&s, "bpf-access");
    g.grant = true;
    assert_eq!(go(&h, &g).0, Ok(0));
    let from = h.log().len();
    let (r, out) = go(&h, &args(&s, "down"));
    assert_eq!(r, Ok(0), "{out}");
    let log = h.log()[from..].to_vec();
    for c in &log {
        assert!(
            !c.contains("feth9"),
            "down touched a foreign interface: {c}"
        );
    }
    assert!(log.contains(&"arp -d 198.18.0.1 ifscope feth4202".to_string()));
    assert!(log.contains(&"ifconfig feth4201 destroy".to_string()));
    assert!(log.contains(&"ifconfig feth4202 destroy".to_string()));
    assert!(h.st(|st| st.ifaces.keys().cloned().collect::<Vec<_>>()) == ["feth9"]);
    assert!(
        h.st(|st| st.bpf.values().all(|v| *v == (0o600, 0))),
        "revoked"
    );
    assert!(!s.manifest().exists() && !marker_path(&s.manifest()).exists());
}

#[test]
fn down_refuses_a_foreign_interface_with_the_lab_name() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    h.st(|st| st.ifaces.get_mut("feth4202").unwrap().mac = "de:ad:be:ef:00:02".into());
    let from = h.log().len();
    let (r, _) = go(&h, &args(&s, "down"));
    assert!(r.unwrap_err().contains("not ours"));
    assert!(
        !h.log()[from..]
            .iter()
            .any(|c| c.contains("destroy") || c.starts_with("arp")),
        "nothing may be destroyed"
    );
    assert!(s.manifest().exists());
}

#[test]
fn second_down_is_safe() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    assert_eq!(go(&h, &args(&s, "down")).0, Ok(0));
    let from = h.log().len();
    let (r, out) = go(&h, &args(&s, "down"));
    assert_eq!(r, Ok(0), "{out}");
    assert!(out.contains("nothing to do"));
    assert_eq!(
        h.log()[from..],
        ["id -u"],
        "the second down runs nothing else"
    );
}

#[test]
fn failed_down_keeps_the_manifest_so_it_can_be_repeated() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    h.st(|st| st.fail.push("ifconfig feth4201 destroy".into()));
    let (r, _) = go(&h, &args(&s, "down"));
    assert_eq!(r, Ok(10));
    assert!(s.manifest().exists());
    h.st(|st| st.fail.clear());
    assert_eq!(go(&h, &args(&s, "down")).0, Ok(0));
    assert!(h.st(|st| st.ifaces.is_empty()));
}

#[test]
fn down_without_a_matching_marker_is_refused() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    fs::write(marker_path(&s.manifest()), "someone-elses-token\n").unwrap();
    let from = h.log().len();
    assert!(go(&h, &args(&s, "down")).0.unwrap_err().contains("marker"));
    assert_eq!(h.log()[from..], ["id -u"]);
}

#[test]
fn link_only_flaps_the_peer_side() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    let mut l = args(&s, "link");
    l.down = true;
    assert_eq!(go(&h, &l).0, Ok(0));
    assert!(!h.st(|st| st.ifaces["feth4202"].up));
    assert!(h.st(|st| st.ifaces["feth4201"].up));
    assert!(!check_ok(&status_json(&h, &s).1, "interfaces"));
    l.down = false;
    l.up = true;
    assert_eq!(go(&h, &l).0, Ok(0));
    assert_eq!(status_json(&h, &s).0, 0);
}

#[test]
fn flags_are_validated_per_command() {
    let s = Scratch::new();
    let h = Fake::new();
    let mut a = args(&s, "bpf-access");
    assert!(go(&h, &a).0.is_err(), "needs one of grant/revoke");
    a.grant = true;
    a.revoke = true;
    assert!(go(&h, &a).0.is_err(), "not both");
    let mut a = args(&s, "up");
    a.grant = true;
    assert!(go(&h, &a).0.is_err());
    let mut a = args(&s, "link");
    assert!(go(&h, &a).0.is_err());
    a.run_id = "BAD/ID".into();
    a.down = true;
    assert!(go(&h, &a).0.is_err());
    assert!(h.log().is_empty());
}

#[test]
fn a_held_lock_is_reported_not_waited_on_forever() {
    let s = Scratch::new();
    let h = Fake::new();
    let mut name = s.manifest().into_os_string();
    name.push(".lock");
    let holder = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(PathBuf::from(name))
        .unwrap();
    holder.lock().unwrap();
    let mut out = vec![];
    let e = dispatch_in(&h, &args(&s, "up"), Duration::ZERO, &mut out).unwrap_err();
    assert!(e.contains("holds the lock"), "{e}");
    assert_eq!(h.log(), ["id -u"], "only the root probe may have run");
    // plan and status never take the lock.
    assert_eq!(
        dispatch_in(&h, &args(&s, "plan"), Duration::ZERO, &mut out),
        Ok(0)
    );
}

#[test]
fn prefix_and_route_destination_parsing() {
    assert_eq!(prefix_of("0xfffffffc"), Some(30));
    assert_eq!(prefix_of("255.255.255.252"), Some(30));
    assert_eq!(prefix_of("0xff00ff00"), None);
    assert_eq!(
        route_dest("198.18.0/30"),
        Some((Ipv4Addr::new(198, 18, 0, 0), 30))
    );
    assert_eq!(route_dest("127"), Some((Ipv4Addr::new(127, 0, 0, 0), 8)));
    assert_eq!(
        route_dest("169.254"),
        Some((Ipv4Addr::new(169, 254, 0, 0), 16))
    );
    assert_eq!(
        route_dest("192.168.1.5"),
        Some((Ipv4Addr::new(192, 168, 1, 5), 32))
    );
    assert_eq!(route_dest("default"), None);
    assert_eq!(route_dest("link#4"), None);
}

#[test]
fn utc_formatting() {
    assert_eq!(utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(utc(1_700_000_000), "2023-11-14T22:13:20Z");
    assert_eq!(utc(951_782_400), "2000-02-29T00:00:00Z");
}

// ---- BPF node creation

/// A kernel that creates `/dev/bpf(N+1)` when the highest existing node is opened.
struct Kernel {
    exist: BTreeSet<u32>,
    held: BTreeSet<u32>,
    cap: u32,
}
impl Kernel {
    fn open(&mut self, n: u32) -> Slot {
        if !self.exist.contains(&n) {
            return Slot::Missing;
        }
        if !self.held.insert(n) {
            return Slot::Busy;
        }
        if Some(&n) == self.exist.iter().max() && n + 1 < self.cap {
            self.exist.insert(n + 1);
        }
        Slot::Held
    }
}

#[test]
fn populate_opens_existing_nodes_in_sequence_until_bpf15_exists() {
    let mut k = Kernel {
        exist: (0..4).collect(),
        held: BTreeSet::new(),
        cap: 256,
    };
    populate(&mut |n| Ok(k.open(n)), BPF_LAST).unwrap();
    assert!((0..=15).all(|n| k.exist.contains(&n)));
    assert!(
        (0..=15).all(|n| k.held.contains(&n)),
        "all held until the end"
    );
}

#[test]
fn populate_counts_busy_nodes_and_stops_when_the_kernel_stops_creating() {
    // Node 2 is held by another process: it exists but cannot be opened.
    let mut k = Kernel {
        exist: (0..4).collect(),
        held: [2].into(),
        cap: 256,
    };
    populate(&mut |n| Ok(k.open(n)), BPF_LAST).unwrap();
    assert!(k.exist.contains(&15));
    // A kernel capped at 8 nodes never reaches 15: an error, not a loop.
    let mut k = Kernel {
        exist: (0..4).collect(),
        held: BTreeSet::new(),
        cap: 8,
    };
    let e = populate(&mut |n| Ok(k.open(n)), BPF_LAST).unwrap_err();
    assert!(e.contains("created no further"), "{e}");
    // An open error (e.g. permission) is returned as is.
    let e = populate(&mut |_| Err("Permission denied".into()), BPF_LAST).unwrap_err();
    assert_eq!(e, "Permission denied");
}

#[test]
fn populate_is_a_no_op_when_everything_exists() {
    let mut opens = 0;
    populate(
        &mut |_| {
            opens += 1;
            Ok(Slot::Held)
        },
        BPF_LAST,
    )
    .unwrap();
    assert_eq!(opens, 16);
}

// ---- fix round 1: persistence, parsers, lab routes, ownership, grant

/// Like `dispatch`, with the lab directory scripted as the manifest's own directory.
fn dispatch_in(h: &Fake, a: &Args, wait: Duration, out: &mut Vec<String>) -> Result<i32, String> {
    h.st(|st| st.state_dir = a.manifest.parent().map(Path::to_path_buf));
    dispatch(h, a, wait, out)
}

fn manifest_of(s: &Scratch) -> Value {
    serde_json::from_slice(&fs::read(s.manifest()).unwrap()).unwrap()
}

#[test]
fn a_failed_rollback_keeps_the_manifest_and_down_finishes_it() {
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| {
        st.fail.push("ifconfig feth4202 create".into());
        st.fail.push("ifconfig feth4201 destroy".into());
    });
    let (r, out) = go(&h, &args(&s, "up"));
    assert_eq!(r, Ok(10), "{out}");
    assert!(out.contains("rollback incomplete"), "{out}");
    let m = manifest_of(&s);
    assert_eq!(m["state"], "rollback-incomplete");
    // The intent of the failed create was recorded before the command ran.
    // The failed create is dropped from the record (N1); the first one stays.
    assert_eq!(m["created"], json!(["feth4201"]));
    assert!(marker_path(&s.manifest()).exists());
    assert!(
        h.st(|st| st.ifaces.contains_key("feth4201")),
        "the orphan is still there"
    );
    // A new up refuses; down acts on the record.
    assert!(
        go(&h, &args(&s, "up"))
            .0
            .unwrap_err()
            .contains("already recorded")
    );
    h.st(|st| st.fail.clear());
    let (r, out) = go(&h, &args(&s, "down"));
    assert_eq!(r, Ok(0), "{out}");
    assert!(h.st(|st| st.ifaces.is_empty()));
    assert!(!s.manifest().exists() && !marker_path(&s.manifest()).exists());
}

#[test]
fn down_destroys_a_half_made_interface_whose_mac_is_not_yet_the_lab_mac() {
    // `up` died (or its rollback failed) after `create` but before `lladdr`.
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| {
        st.fail
            .push("ifconfig feth4201 lladdr 02:ac:00:00:00:01".into());
        st.fail.push("ifconfig feth4201 destroy".into());
    });
    assert_eq!(go(&h, &args(&s, "up")).0, Ok(10));
    assert_ne!(h.st(|st| st.ifaces["feth4201"].mac.clone()), SCANNER_MAC);
    h.st(|st| st.fail.clear());
    assert_eq!(go(&h, &args(&s, "down")).0, Ok(0));
    assert!(h.st(|st| st.ifaces.is_empty()));
}

#[test]
fn a_failed_arp_set_rolls_back_without_deleting_an_arp_entry() {
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| {
        st.fail
            .push("arp -S 198.18.0.1 02:ac:00:00:00:01 ifscope feth4202".into())
    });
    let (r, _) = go(&h, &args(&s, "up"));
    assert_eq!(r, Ok(10));
    assert!(
        !h.log().iter().any(|c| c.starts_with("arp -d")),
        "{:?}",
        h.log()
    );
    assert!(h.st(|st| st.ifaces.is_empty()));
    assert!(!s.manifest().exists());
}

#[test]
fn a_failed_post_check_rolls_everything_back() {
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| {
        st.route_get.insert("198.18.0.1".into(), "en0".into());
    });
    let (r, out) = go(&h, &args(&s, "up"));
    assert_eq!(r, Ok(10), "{out}");
    assert!(out.contains("FAILED check lab_routes"), "{out}");
    assert!(h.st(|st| st.ifaces.is_empty() && st.arp.is_none()));
    assert!(!s.manifest().exists() && !marker_path(&s.manifest()).exists());
}

#[test]
fn up_refuses_a_stray_marker() {
    let s = Scratch::new();
    let h = Fake::new();
    fs::write(marker_path(&s.manifest()), "x\n").unwrap();
    assert!(
        go(&h, &args(&s, "up"))
            .0
            .unwrap_err()
            .contains("already recorded")
    );
    assert!(h.mutating().is_empty());
}

#[test]
fn up_refuses_forwarding_and_unreadable_inet() {
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| st.forwarding = "1".into());
    assert!(
        go(&h, &args(&s, "up"))
            .0
            .unwrap_err()
            .contains("forwarding")
    );
    let h = Fake::new();
    h.st(|st| st.extra_ifconfig = "en7: flags=8863<UP>\n\tinet 10.0.0.1 --> 10.0.0.2\n".into());
    assert!(
        go(&h, &args(&s, "up"))
            .0
            .unwrap_err()
            .contains("cannot read the netmask")
    );
    assert!(h.mutating().is_empty());
}

#[test]
fn routes_are_read_by_header_and_short_rows_are_errors() {
    let refs = "Destination        Gateway            Flags      Refs      Use   Netif Expire\n\
default            192.168.1.1        UGSc         12        0     en0\n\
10.9.0/24          link#30            UCS           1        0  feth4201      !\n";
    let r = parse_routes(refs).unwrap();
    assert_eq!(
        r[1],
        Route {
            dest: "10.9.0/24".into(),
            netif: "feth4201".into()
        }
    );
    assert!(!route_allowed(&r[1]));
    let short = "Destination        Gateway            Flags               Netif Expire\n10.9.0/24          link#30\n";
    assert!(parse_routes(short).unwrap_err().contains("too short"));
    assert!(parse_routes("Destination Gateway Flags\nx y z\n").is_err());
    assert!(parse_routes("no table here\n").is_err());
    assert!(parse_routes("").is_err());
}

#[test]
fn a_short_route_row_makes_status_and_up_refuse() {
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| st.extra_routes.push("10.9.0/24          link#30".into()));
    assert!(go(&h, &args(&s, "up")).0.unwrap_err().contains("too short"));
    let h = Fake::new();
    up_ok(&h, &s);
    h.st(|st| st.extra_routes.push("10.9.0/24          link#30".into()));
    let (rc, v) = status_json(&h, &s);
    assert_eq!(rc, 3);
    assert!(!check_ok(&v, "routes") && !check_ok(&v, "lab_routes"));
}

#[test]
fn status_refuses_routes_that_would_carry_lab_replies_off_the_pair() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    assert_eq!(
        status_json(&h, &s).0,
        0,
        "the realistic side rows are accepted"
    );
    for row in [
        "198.18.0.1/32      link#9             UCS                   en0      !",
        "198.18.0.0/15      198.18.0.1         UGSc                  utun4",
        "198.18.0.0/31      link#9             UCS                  feth4201  !",
    ] {
        h.st(|st| st.extra_routes = vec![row.into()]);
        let (rc, v) = status_json(&h, &s);
        assert_eq!(rc, 3, "{row}");
        assert!(!check_ok(&v, "lab_routes"), "{row}");
    }
    h.st(|st| st.extra_routes.clear());
    h.st(|st| {
        st.route_get.insert("198.18.0.1".into(), "utun4".into());
    });
    assert!(!check_ok(&status_json(&h, &s).1, "lab_routes"));
    h.st(|st| {
        st.route_get.clear();
        st.route_get.insert("198.18.0.2".into(), "en0".into());
    });
    assert!(!check_ok(&status_json(&h, &s).1, "lab_routes"));
    h.st(|st| st.route_get.clear());
    assert_eq!(status_json(&h, &s).0, 0);
}

#[test]
fn status_refuses_a_feth4202_route_outside_the_slash_30() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    for row in [
        "198.18.0/24        link#22            UCS                feth4202      !",
        "10.1.1.1           link#22            UHS                feth4202",
    ] {
        h.st(|st| st.extra_routes = vec![row.into()]);
        assert_eq!(status_json(&h, &s).0, 3, "{row}");
    }
}

#[test]
fn status_refuses_a_non_permanent_arp_entry_and_an_unsealed_manifest() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    let mut m = manifest_of(&s);
    m["state"] = "creating".into();
    write_manifest(&s.manifest(), &m).unwrap();
    let (rc, v) = status_json(&h, &s);
    assert_eq!(rc, 3);
    assert!(!check_ok(&v, "manifest"));
    m["state"] = "sealed".into();
    write_manifest(&s.manifest(), &m).unwrap();
    assert_eq!(status_json(&h, &s).0, 0);
    let e = parse_arp("? (198.18.0.1) at 2:ac:0:0:0:1 on feth4202 ifscope [ethernet]\n");
    assert!(!e[0].permanent);
}

#[test]
fn unreadable_inet_forms_are_kept_and_refused() {
    let i = parse_ifconfig(
        "\tinet 198.18.0.9 --> 198.18.0.10\n\tinet 10.0.0.1 netmask 0xff000000 broadcast 10.255.255.255\n",
    );
    assert_eq!(i.inets[0], ("198.18.0.9".into(), "?".into()));
    assert_eq!(i.inets[1].1, "0xff000000");
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    h.st(|st| st.ifaces.get_mut("feth4201").unwrap().inet = Some(("10.1.1.1".into(), "?".into())));
    assert!(!check_ok(&status_json(&h, &s).1, "interfaces"));
}

#[test]
fn grant_saves_previous_modes_first_and_is_atomic() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    h.st(|st| {
        st.bpf.insert(1, (0o640, 80));
        st.fail.push("bpf_set 5 660 20".into());
    });
    let mut g = args(&s, "bpf-access");
    g.grant = true;
    let (r, out) = go(&h, &g);
    assert_eq!(r, Ok(10), "{out}");
    assert!(out.contains("reverting"), "{out}");
    // Nodes 0..4 were changed and put back; the failing node never changed.
    assert_eq!(h.st(|st| st.bpf[&1]), (0o640, 80));
    assert!(h.st(|st| st.bpf.iter().all(|(n, v)| *n == 1 || *v == (0o600, 0))));
    // The previous modes were persisted before anything was touched.
    assert_eq!(
        manifest_of(&s)["bpf_prev"]["1"],
        json!({"mode":"0640","gid":80})
    );
    h.st(|st| st.fail.clear());
    assert_eq!(go(&h, &g).0, Ok(0));
}

#[test]
fn grant_prints_the_real_exposure() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    let mut g = args(&s, "bpf-access");
    g.grant = true;
    let (_, out) = go(&h, &g);
    for w in [
        "every local account",
        "group staff",
        "inject",
        "en0",
        "Revoke whenever no run is active",
    ] {
        assert!(out.contains(w), "{w} missing from {out}");
    }
}

#[test]
fn the_guide_states_the_grant_exposure_and_commands() {
    let doc = include_str!("../../../docs/macos-feth-lab.md");
    for w in [
        "group staff",
        "inject",
        "en0",
        "/var/run/rmasscan-lab",
        "revoke",
    ] {
        assert!(doc.contains(w), "guide lacks {w:?}");
    }
    assert!(
        !doc.contains("any process of your user"),
        "the old understatement is back"
    );
}

#[test]
fn down_and_revoke_only_ever_set_0600_root_wheel_whatever_the_manifest_says() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    h.st(|st| {
        st.bpf.insert(2, (0o640, 80));
    });
    let mut g = args(&s, "bpf-access");
    g.grant = true;
    assert_eq!(go(&h, &g).0, Ok(0));
    // A tampered manifest asks for the world to read and write.
    let mut m = manifest_of(&s);
    for n in 0..16 {
        m["bpf_prev"][n.to_string()] = json!({"mode":"0666","gid":20});
    }
    write_manifest(&s.manifest(), &m).unwrap();
    let from = h.log().len();
    let mut r = args(&s, "bpf-access");
    r.revoke = true;
    assert_eq!(go(&h, &r).0, Ok(0));
    let (r, out) = go(&h, &args(&s, "down"));
    assert_eq!(r, Ok(0), "{out}");
    let sets: Vec<String> = h.log()[from..]
        .iter()
        .filter(|c| c.starts_with("bpf_set"))
        .cloned()
        .collect();
    assert!(!sets.is_empty());
    for c in &sets {
        assert!(
            c.ends_with(" 600 0"),
            "a value from the manifest reached a chmod: {c}"
        );
    }
    assert!(h.st(|st| st.bpf.values().all(|v| *v == (0o600, 0))));
    assert!(out.contains("Restore by hand"), "{out}");
}

#[test]
fn down_does_not_mention_modes_that_were_the_default() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    let mut g = args(&s, "bpf-access");
    g.grant = true;
    assert_eq!(go(&h, &g).0, Ok(0));
    let (_, out) = go(&h, &args(&s, "down"));
    assert!(!out.contains("Restore by hand"), "{out}");
}

#[test]
fn link_refuses_a_foreign_peer_interface() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    h.st(|st| st.ifaces.get_mut("feth4202").unwrap().mac = "de:ad:be:ef:00:02".into());
    let mut l = args(&s, "link");
    l.down = true;
    assert!(go(&h, &l).0.unwrap_err().contains("not ours"));
    assert!(h.st(|st| st.ifaces["feth4202"].up));
}

#[test]
fn plan_does_not_claim_a_chown_to_root() {
    let s = Scratch::new();
    let (_, out) = go(&Fake::new(), &args(&s, "plan"));
    assert!(!out.contains("chown root"));
    assert!(out.contains("chgrp wheel"));
}

#[test]
fn every_command_the_lab_runs_has_an_absolute_system_path() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    status_json(&h, &s);
    let mut g = args(&s, "bpf-access");
    g.grant = true;
    let _ = go(&h, &g);
    let _ = go(&h, &args(&s, "down"));
    let words: BTreeSet<String> = h
        .log()
        .iter()
        .filter(|c| !c.starts_with("bpf_"))
        .map(|c| c.split(' ').next().unwrap().to_owned())
        .collect();
    assert!(!words.is_empty());
    for w in &words {
        let p = system_path(w).unwrap_or_else(|| panic!("{w} has no absolute path"));
        assert!(p.starts_with('/'), "{p}");
        #[cfg(target_os = "macos")]
        assert!(Path::new(p).exists(), "{p} does not exist on this Mac");
    }
    assert_eq!(system_path("curl"), None);
    assert_eq!(system_path("sh"), None);
}

#[test]
fn dir_policy_table() {
    let ok = dir_policy;
    // Owned by root (0) and not writable by others: fine.
    assert!(ok(false, true, 0, 0o755, 0).is_ok());
    assert!(ok(false, true, 0, 0o700, 0).is_ok());
    assert!(ok(true, true, 0, 0o755, 0).unwrap_err().contains("symlink"));
    assert!(
        ok(false, false, 0, 0o755, 0)
            .unwrap_err()
            .contains("not a directory")
    );
    // A user-owned directory is never a state directory.
    assert!(
        ok(false, true, 501, 0o755, 0)
            .unwrap_err()
            .contains("expected uid 0")
    );
    assert!(
        ok(false, true, 0, 0o775, 0)
            .unwrap_err()
            .contains("writable")
    );
    assert!(
        ok(false, true, 0, 0o757, 0)
            .unwrap_err()
            .contains("writable")
    );
}

#[cfg(unix)]
#[test]
fn dispatch_refuses_a_symlinked_or_group_writable_lab_directory() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let s = Scratch::new();
    let real = s.0.join("real");
    fs::create_dir(&real).unwrap();
    let link = s.0.join("link");
    symlink(&real, &link).unwrap();
    let h = Fake::new();
    let mut a = args(&s, "up");
    a.manifest = link.join("m1.json");
    let mut out = vec![];
    let e = dispatch_in(&h, &a, Duration::ZERO, &mut out).unwrap_err();
    assert!(e.contains("symlink"), "{e}");
    assert!(h.mutating().is_empty());
    fs::set_permissions(&real, fs::Permissions::from_mode(0o775)).unwrap();
    a.manifest = real.join("m1.json");
    let e = dispatch_in(&h, &a, Duration::ZERO, &mut out).unwrap_err();
    assert!(e.contains("writable"), "{e}");
    assert!(
        fs::read_dir(&real).unwrap().next().is_none(),
        "nothing was created in it"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_lock_file_is_refused() {
    use std::os::unix::fs::symlink;
    let s = Scratch::new();
    let target = s.0.join("victim");
    fs::write(&target, "x").unwrap();
    symlink(&target, lock_path(&s.manifest())).unwrap();
    let h = Fake::new();
    let mut out = vec![];
    let e = dispatch_in(&h, &args(&s, "up"), Duration::ZERO, &mut out).unwrap_err();
    assert!(e.contains("symlink"), "{e}");
    assert_eq!(fs::read_to_string(&target).unwrap(), "x");
}

#[test]
fn dispatch_creates_the_directory_for_up_and_removes_the_lock_after_down() {
    let s = Scratch::new();
    let h = Fake::new();
    let mut a = args(&s, "up");
    a.manifest = s.0.join("sub").join("m1.json");
    let mut out = vec![];
    assert_eq!(
        dispatch_in(&h, &a, Duration::ZERO, &mut out),
        Ok(0),
        "{out:?}"
    );
    assert!(lock_path(&a.manifest).exists());
    a.cmd = "down".into();
    assert_eq!(
        dispatch_in(&h, &a, Duration::ZERO, &mut out),
        Ok(0),
        "{out:?}"
    );
    assert!(
        !lock_path(&a.manifest).exists(),
        "the lock is removed with the stand"
    );
    assert!(!a.manifest.exists() && !marker_path(&a.manifest).exists());
}

#[test]
fn commands_without_a_stand_or_without_root_create_nothing() {
    let s = Scratch::new();
    let h = Fake::new();
    let mut a = args(&s, "up");
    a.manifest = s.0.join("sub").join("m1.json");
    h.st(|st| st.root = false);
    let mut out = vec![];
    assert!(
        dispatch_in(&h, &a, Duration::ZERO, &mut out)
            .unwrap_err()
            .contains("needs root")
    );
    assert!(
        !s.0.join("sub").exists(),
        "no directory before the root check"
    );
    h.st(|st| st.root = true);
    for cmd in ["down", "link", "bpf-access"] {
        a.cmd = cmd.into();
        a.down = cmd == "link";
        a.grant = cmd == "bpf-access";
        let r = dispatch_in(&h, &a, Duration::ZERO, &mut out);
        assert!(r == Ok(0) || r.is_err(), "{cmd}");
        assert!(!s.0.join("sub").exists(), "{cmd} created the directory");
        assert!(!lock_path(&a.manifest).exists());
    }
}

// ---- fix round 2: root actions must not be driven by user-writable state

fn write_manifest_with(s: &Scratch, h: &Fake, created: Value, state: &str) {
    up_ok(h, s);
    let mut m = manifest_of(s);
    m["created"] = created;
    m["state"] = state.into();
    write_manifest(&s.manifest(), &m).unwrap();
}

#[test]
fn a_manifest_that_lists_foreign_interfaces_destroys_nothing() {
    for bad in ["en0", "bridge0", "utun3", "lo0", "feth4203", ""] {
        let s = Scratch::new();
        let h = Fake::new();
        h.st(|st| {
            for n in ["bridge0", "utun3", "feth4203"] {
                st.ifaces.insert(n.into(), FIf::default());
            }
        });
        write_manifest_with(&s, &h, json!(["feth4201", bad]), "creating");
        let from = h.log().len();
        let (r, _) = go(&h, &args(&s, "down"));
        assert!(r.unwrap_err().contains("not a lab interface"), "{bad}");
        assert!(
            !h.log()[from..]
                .iter()
                .any(|c| c.contains("destroy") || c.starts_with("arp -d")),
            "{bad}: {:?}",
            h.log()
        );
        assert!(s.manifest().exists());
    }
}

#[test]
fn a_lab_named_interface_that_is_not_ours_is_not_destroyed_even_when_unsealed() {
    let s = Scratch::new();
    let h = Fake::new();
    write_manifest_with(&s, &h, json!(["feth4201", "feth4202"]), "creating");
    h.st(|st| {
        let f = st.ifaces.get_mut("feth4201").unwrap();
        f.mac = "de:ad:be:ef:00:01".into();
        f.peer = Some("feth9".into());
    });
    let (r, out) = go(&h, &args(&s, "down"));
    assert_eq!(r, Ok(10), "{out}");
    assert!(out.contains("REFUSED"), "{out}");
    assert!(
        h.st(|st| st.ifaces.contains_key("feth4201")),
        "the foreign one stays"
    );
    assert!(
        !h.st(|st| st.ifaces.contains_key("feth4202")),
        "the ours one goes"
    );
    assert!(s.manifest().exists());
}

#[test]
fn a_fresh_unpeered_feth_with_a_random_mac_is_destroyed_when_unsealed() {
    let s = Scratch::new();
    let h = Fake::new();
    write_manifest_with(&s, &h, json!(["feth4201"]), "rollback-incomplete");
    h.st(|st| {
        let f = st.ifaces.get_mut("feth4201").unwrap();
        f.mac = "ee:ee:ee:00:00:09".into();
        f.peer = None;
    });
    assert_eq!(go(&h, &args(&s, "down")).0, Ok(0));
    assert!(!h.st(|st| st.ifaces.contains_key("feth4201")));
}

#[cfg(unix)]
mod lock_ownership {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn open(path: &Path, _calls: &mut u32) -> Result<fs::File, String> {
        open_lock_with(path, test_uid())
    }

    #[test]
    fn a_new_lock_is_created_with_create_new_and_reused_when_it_is_ours() {
        let s = Scratch::new();
        let p = s.0.join("x.lock");
        let mut calls = 0;
        open(&p, &mut calls).unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o644
        );
        // An existing lock of the right owner is accepted; nothing is ever chowned.
        open(&p, &mut calls).unwrap();
    }

    #[test]
    fn a_hardlinked_lock_is_refused_and_not_chowned() {
        let s = Scratch::new();
        let victim = s.0.join("sudoers-like");
        fs::write(&victim, "x").unwrap();
        let p = s.0.join("x.lock");
        fs::hard_link(&victim, &p).unwrap();
        let mut calls = 0;
        let e = open(&p, &mut calls).unwrap_err();
        assert!(e.contains("hard links"), "{e}");
        assert_eq!(calls, 0);
    }

    #[test]
    fn a_symlinked_lock_is_refused_and_not_chowned() {
        let s = Scratch::new();
        let victim = s.0.join("victim");
        fs::write(&victim, "x").unwrap();
        let p = s.0.join("x.lock");
        symlink(&victim, &p).unwrap();
        let mut calls = 0;
        let e = open(&p, &mut calls).unwrap_err();
        assert!(e.contains("symlink"), "{e}");
        assert_eq!(calls, 0);
        assert_eq!(fs::read_to_string(&victim).unwrap(), "x");
    }

    #[test]
    fn a_writable_or_non_regular_existing_lock_is_refused() {
        let s = Scratch::new();
        let p = s.0.join("x.lock");
        fs::write(&p, "").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap();
        let mut calls = 0;
        assert!(open(&p, &mut calls).unwrap_err().contains("writable"));
        let d = s.0.join("dir.lock");
        fs::create_dir(&d).unwrap();
        assert!(open(&d, &mut calls).is_err());
        assert_eq!(calls, 0);
    }

    #[test]
    fn existing_file_policy_table() {
        let p = existing_file_policy;
        assert!(p(false, true, 1, 0, 0o644, 0).is_ok());
        assert!(p(false, true, 1, 0, 0o600, 0).is_ok());
        assert!(p(true, true, 1, 0, 0o644, 0).is_err());
        assert!(p(false, false, 1, 0, 0o644, 0).is_err());
        assert!(p(false, true, 2, 0, 0o644, 0).is_err());
        assert!(p(false, true, 1, 501, 0o644, 0).is_err());
        assert!(p(false, true, 1, 0, 0o620, 0).is_err());
    }
}

// ---- fix round 3: user-writable input must not steer root

#[test]
fn a_foreign_interface_that_appears_after_preflight_is_never_destroyed() {
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| st.appear_on_create = Some("feth4202".into()));
    let (r, out) = go(&h, &args(&s, "up"));
    assert_eq!(r, Ok(10), "{out}");
    assert!(
        h.st(|st| st.ifaces.contains_key("feth4202")),
        "the foreign feth4202 must survive"
    );
    assert!(
        !h.st(|st| st.ifaces.contains_key("feth4201")),
        "ours is rolled back"
    );
    assert!(!h.log().contains(&"ifconfig feth4202 destroy".to_string()));
    assert!(!s.manifest().exists());
}

#[test]
fn the_manifest_path_is_fixed_by_the_run_id() {
    assert_eq!(
        expected_manifest(Path::new(STATE_DIR), "m1"),
        Path::new("/var/run/rmasscan-lab/m1.json")
    );
    let h = Fake::new();
    let s = Scratch::new();
    h.st(|st| st.state_dir = Some(s.0.clone()));
    let mut a = args(&s, "status");
    assert!(check_manifest_arg(&h, &a).is_ok());
    for bad in [
        "/etc/sudoers.d/x.json",
        "/var/run/rmasscan-lab/other.json",
        "/var/run/rmasscan-lab/m1.json",
        "/Users/me/.rmasscan-lab/m1.json",
    ] {
        a.manifest = PathBuf::from(bad);
        assert!(check_manifest_arg(&h, &a).is_err(), "{bad}");
    }
    a.manifest = s.0.join("sub").join("..").join("m1.json");
    assert!(check_manifest_arg(&h, &a).is_err());
}

#[test]
fn a_manifest_outside_the_state_directory_is_refused_for_every_command() {
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| st.state_dir = Some(s.0.join("lab")));
    for p in [
        s.0.join("elsewhere.json"),
        s.0.join("lab").join("sub").join("x.json"),
        s.0.join("lab").join("other.json"),
        PathBuf::from("/etc/sudoers.d/rmasscan.json"),
    ] {
        let mut a = args(&s, "up");
        a.manifest = p.clone();
        let mut out = vec![];
        let e = dispatch(&h, &a, Duration::ZERO, &mut out).unwrap_err();
        assert!(e.contains("refused"), "{p:?}: {e}");
        for c in ["status", "down"] {
            a.cmd = c.into();
            assert!(execute(&h, &a, &mut out).is_err(), "{c} {p:?}");
        }
    }
    assert!(h.log().is_empty(), "no command ran: {:?}", h.log());
    assert!(!s.0.join("lab").exists() && !s.0.join("elsewhere.json").exists());
}

#[test]
fn a_missing_parent_is_never_created_only_the_lab_directory_itself() {
    let s = Scratch::new();
    let h = Fake::new();
    // The lab directory's parent does not exist: refused, nothing created.
    let mut a = args(&s, "up");
    a.manifest = s.0.join("no-home").join(".rmasscan-lab").join("m1.json");
    let mut out = vec![];
    assert!(dispatch_in(&h, &a, Duration::ZERO, &mut out).is_err());
    assert!(!s.0.join("no-home").exists());
    // The parent exists: exactly the lab directory is created.
    a.manifest = s.0.join(".rmasscan-lab").join("m1.json");
    assert_eq!(
        dispatch_in(&h, &a, Duration::ZERO, &mut out),
        Ok(0),
        "{out:?}"
    );
    assert!(s.0.join(".rmasscan-lab").is_dir());
}

#[cfg(unix)]
mod trusted_reads {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn symlinks_oversize_hardlinked_and_writable_files_are_not_read() {
        let s = Scratch::new();
        let uid = test_uid();
        let p = s.0.join("m.json");
        assert_eq!(read_trusted(&p, uid), Ok(None));
        fs::write(&p, "{}").unwrap();
        assert_eq!(read_trusted(&p, uid).unwrap().unwrap(), b"{}");
        // A symlink to an endless file is refused, not opened.
        let z = s.0.join("zero.json");
        symlink("/dev/zero", &z).unwrap();
        assert!(read_trusted(&z, uid).unwrap_err().contains("symlink"));
        // Larger than the cap.
        let big = s.0.join("big.json");
        fs::write(&big, vec![b'x'; (1 << 20) + 1]).unwrap();
        assert!(read_trusted(&big, uid).unwrap_err().contains("larger"));
        // A hard link.
        fs::hard_link(&p, s.0.join("m2.json")).unwrap();
        assert!(read_trusted(&p, uid).unwrap_err().contains("hard links"));
        // Group-writable.
        let w = s.0.join("w.json");
        fs::write(&w, "{}").unwrap();
        fs::set_permissions(&w, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(read_trusted(&w, uid).unwrap_err().contains("writable"));
        // A directory is not a file.
        assert!(read_trusted(&s.0, uid).is_err());
    }

    #[test]
    fn status_with_a_symlinked_manifest_is_refused_not_followed() {
        let s = Scratch::new();
        let h = Fake::new();
        symlink("/dev/zero", s.manifest()).unwrap();
        let (rc, v) = status_json(&h, &s);
        assert_eq!(rc, 3);
        assert!(!check_ok(&v, "manifest"));
    }
}

#[test]
fn a_sealed_manifest_cannot_make_down_destroy_a_foreign_interface() {
    let s = Scratch::new();
    let h = Fake::new();
    h.st(|st| {
        st.ifaces.insert("bridge9".into(), FIf::default());
    });
    up_ok(&h, &s);
    let mut m = manifest_of(&s);
    m["created"] = json!(["feth4201", "feth4202", "bridge9"]);
    write_manifest(&s.manifest(), &m).unwrap();
    assert_eq!(m["state"], "sealed");
    let from = h.log().len();
    assert!(
        go(&h, &args(&s, "down"))
            .0
            .unwrap_err()
            .contains("not a lab interface")
    );
    assert!(!h.log()[from..].iter().any(|c| c.contains("destroy")));
    assert!(h.st(|st| st.ifaces.contains_key("bridge9")));
}

#[test]
fn plan_and_guide_describe_the_real_down_and_the_chmodbpf_cost() {
    let s = Scratch::new();
    let (_, out) = go(&Fake::new(), &args(&s, "plan"));
    assert!(out.contains("0600 root:wheel"));
    assert!(!out.contains("restore the recorded"));
    let doc = include_str!("../../../docs/macos-feth-lab.md");
    assert!(doc.contains("ChmodBPF"));
    assert!(doc.contains("until the next reboot") || doc.contains("until reboot"));
    assert!(!doc.contains("restore BPF modes"));
}

// ---- fix round 4: all state lives in a root-owned directory

#[test]
fn status_reads_the_root_owned_state_without_root() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    h.st(|st| st.root = false);
    let from = h.log().len();
    let (rc, v) = status_json(&h, &s);
    assert_eq!(rc, 0, "{v}");
    assert!(
        !h.log()[from..].iter().any(|c| c == "id -u"),
        "status asked for root"
    );
    assert!(check_ok(&v, "manifest"));
}

#[test]
fn a_state_file_not_owned_by_the_state_owner_is_not_trusted() {
    let s = Scratch::new();
    let h = Fake::new();
    up_ok(&h, &s);
    // The files are the test user's; the host now claims root must own them.
    let uid = test_uid();
    assert!(
        read_trusted(&s.manifest(), uid + 1)
            .unwrap_err()
            .contains("owned by uid")
    );
    assert!(read_trusted(&s.manifest(), uid).unwrap().is_some());
}

#[cfg(unix)]
#[test]
fn a_symlinked_or_writable_state_directory_is_refused_by_every_privileged_command() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let s = Scratch::new();
    let real = s.0.join("real");
    fs::create_dir(&real).unwrap();
    let link = s.0.join("link");
    symlink(&real, &link).unwrap();
    for cmd in ["up", "down", "link", "bpf-access"] {
        let h = Fake::new();
        let mut a = args(&s, cmd);
        a.manifest = link.join("m1.json");
        a.down = cmd == "link";
        a.grant = cmd == "bpf-access";
        if cmd != "up" {
            fs::write(real.join("m1.json"), "{}").unwrap();
        }
        let mut out = vec![];
        let e = dispatch_in(&h, &a, Duration::ZERO, &mut out).unwrap_err();
        assert!(e.contains("symlink"), "{cmd}: {e}");
        assert!(h.mutating().is_empty(), "{cmd}");
        let _ = fs::remove_file(real.join("m1.json"));
    }
    fs::set_permissions(&real, fs::Permissions::from_mode(0o777)).unwrap();
    let h = Fake::new();
    let mut a = args(&s, "up");
    a.manifest = real.join("m1.json");
    let mut out = vec![];
    assert!(
        dispatch_in(&h, &a, Duration::ZERO, &mut out)
            .unwrap_err()
            .contains("writable")
    );
    assert!(fs::read_dir(&real).unwrap().next().is_none());
}

#[test]
fn nothing_the_lab_does_reads_the_environment_or_the_home_directory() {
    let src = include_str!("macos_lab.rs");
    for banned in [
        "env::var",
        "restore_sudo_owner",
        "sudo_target",
        "lchown",
        "fchown",
        "chown(",
    ] {
        // `chown` appears only for the /dev/bpf groups (`chown(&p, None, Some(gid))`).
        if banned == "chown(" {
            assert_eq!(
                src.matches("chown(").count(),
                1,
                "a new chown call appeared"
            );
            continue;
        }
        assert!(!src.contains(banned), "{banned} is back in macos_lab.rs");
    }
}

#[test]
fn plan_names_the_root_owned_state_directory() {
    let s = Scratch::new();
    let (_, out) = go(&Fake::new(), &args(&s, "plan"));
    assert!(out.contains("/var/run/rmasscan-lab"), "{out}");
    assert!(out.contains("nothing is written under $HOME"));
}
