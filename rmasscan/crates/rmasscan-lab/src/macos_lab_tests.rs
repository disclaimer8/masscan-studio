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
        }))
    }
    fn log(&self) -> Vec<String> {
        self.0.borrow().log.clone()
    }
    fn mutating(&self) -> Vec<String> {
        self.log()
            .into_iter()
            .filter(|c| {
                c.starts_with("ifconfig feth")
                    && !c.ends_with("feth4201")
                    && !c.ends_with("feth4202")
                    || c.starts_with("arp -S")
                    || c.starts_with("arp -d")
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
    format!("0x{:08x}", u32::from(m.parse::<Ipv4Addr>().unwrap()))
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
        match s.bpf.get_mut(&n) {
            Some(v) => {
                *v = (mode, gid);
                Ok(())
            }
            None => Err(format!("bpf{n} missing")),
        }
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
        self.0.join("macos-m1.json")
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
    let e = dispatch(&h, &args(&s, "up"), Duration::ZERO, &mut out).unwrap_err();
    assert!(e.contains("holds the lock"), "{e}");
    assert!(h.log().is_empty());
    // plan and status never take the lock.
    assert_eq!(
        dispatch(&h, &args(&s, "plan"), Duration::ZERO, &mut out),
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
