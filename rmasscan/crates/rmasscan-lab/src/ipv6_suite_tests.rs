//! The IPv6 suite against a recording host: nothing here opens an interface, runs a process or writes a frame. The
//! scanners' outputs, exits and captures come from the verifier's synthetic generator (`ipv6_verify::tests::Sim`); the
//! suite writes the evidence directory itself and `ipv6-verify` judges it, so the layout the suite writes and the
//! layout the verifier reads are tested against each other.
use super::*;
use crate::{
    autodetect_suite::{Running, SH, UNSHARE, p2s},
    autodetect_verify::{
        self as av,
        tests::{LAB_ID, Sim as AdSim, TEARDOWN},
    },
    ipv6_verify::tests::{Sim, ipv6_isolation},
    pcap,
    scan_control_suite::IN_DIR_SCRIPT,
    scan_control_verify::Who,
    verify::{PASS, array},
    windows_suite::{Output, nonce},
};
use serde_json::Value;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    time::Duration,
};

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-ipv6-suite-{}", nonce()));
    fs::create_dir_all(&d).unwrap();
    d
}
fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}
fn after<'a>(a: &'a [String], k: &str) -> &'a str {
    let i = a
        .iter()
        .position(|x| x == k)
        .unwrap_or_else(|| panic!("{k} not in {a:?}"));
    &a[i + 1]
}
fn slashes(s: &str) -> String {
    s.replace('\\', "/")
}
fn bad(res: &Value) -> Vec<String> {
    array(&res["runs"])
        .iter()
        .flat_map(|r| {
            array(&r["checks"])
                .iter()
                .filter(|c| c["result"] != "PASS")
                .map(move |c| {
                    format!(
                        "{} {}: {} ({})",
                        r["tag"], c["result"], c["name"], c["detail"]
                    )
                })
        })
        .collect()
}

struct FakeRun {
    rc: Option<i32>,
    on_stop: Option<Box<dyn FnOnce() -> i32>>,
    name: String,
    log: Rc<RefCell<Vec<String>>>,
}
impl Running for FakeRun {
    fn try_wait(&mut self) -> Result<Option<i32>, String> {
        Ok(self.rc)
    }
    fn signal(&mut self, sig: &str) {
        self.log
            .borrow_mut()
            .push(format!("signal {}:{sig}", self.name));
        if self.rc.is_none() {
            self.rc = Some(self.on_stop.take().map_or(0, |f| f()));
        }
    }
    fn kill(&mut self) {
        self.log
            .borrow_mut()
            .push(format!("signal {}:KILL", self.name));
        self.rc.get_or_insert(-9);
    }
}

/// `ip -6 -j addr show dev IF` of a side of the stand, the scanner's ULA `tentative` when asked.
fn addr_json(iface: &str, tentative: bool) -> String {
    let (ulas, ll): (Vec<&str>, &str) = if iface == "veth-a" {
        (vec![capture::IPV6_SCANNER], capture::IPV6_SCANNER_LL)
    } else {
        (capture::IPV6_PEERS.to_vec(), capture::IPV6_PEER_LL)
    };
    let mut info: Vec<Value> = ulas
        .iter()
        .map(|a| {
            let mut v =
                json!({"family":"inet6","local":a,"prefixlen":64,"scope":"global","nodad":true});
            if tentative {
                v["tentative"] = json!(true);
            }
            v
        })
        .collect();
    info.push(json!({"family":"inet6","local":ll,"prefixlen":64,"scope":"link"}));
    json!([{"ifindex":2,"ifname":iface,"addr_info":info}]).to_string()
}

/// The netns stand as the suite sees it, played from the generator's cases.
struct FakeV6 {
    sims: BTreeMap<&'static str, Sim>,
    rmasscan: String,
    oracle: String,
    euid: u32,
    current: RefCell<&'static str>,
    spawned: RefCell<Vec<Vec<String>>>,
    execs: RefCell<Vec<Vec<String>>>,
    log: Rc<RefCell<Vec<String>>>,
    /// From the `n`-th read of the stand's addresses on (counting both sides), the scanner's ULA is tentative.
    tentative_from: Cell<Option<usize>>,
    addr_reads: Cell<usize>,
    /// What `cat` of the veth's IPv6 settings prints.
    sysctls: RefCell<String>,
}
impl FakeV6 {
    fn new(tags: &[&'static str], rmasscan: &Path, oracle: &Path) -> Self {
        FakeV6 {
            sims: tags.iter().map(|t| (*t, Sim::new(t))).collect(),
            rmasscan: p2s(rmasscan),
            oracle: p2s(oracle),
            euid: 0,
            current: RefCell::new(""),
            spawned: RefCell::default(),
            execs: RefCell::default(),
            log: Rc::default(),
            tentative_from: Cell::new(None),
            addr_reads: Cell::new(0),
            sysctls: RefCell::new("0\n0\n0\n0\n0\n0\n".into()),
        }
    }
    fn note(&self, argv: &[String], paths: &[&Path]) {
        let all: Vec<String> = argv
            .iter()
            .cloned()
            .chain(paths.iter().map(|p| p2s(p)))
            .map(|a| slashes(&a))
            .collect();
        for tag in self.sims.keys() {
            if all.iter().any(|a| a.contains(&format!("/{tag}."))) {
                *self.current.borrow_mut() = tag;
            }
        }
    }
    fn proc(
        &self,
        name: &str,
        rc: Option<i32>,
        on_stop: Option<Box<dyn FnOnce() -> i32>>,
    ) -> Box<dyn Running> {
        self.log.borrow_mut().push(format!("start {name}"));
        Box::new(FakeRun {
            rc,
            on_stop,
            name: name.into(),
            log: self.log.clone(),
        })
    }
    fn scans(&self, program: &str) -> Vec<Vec<String>> {
        self.spawned
            .borrow()
            .iter()
            .filter(|a| a.iter().any(|x| x == program))
            .cloned()
            .collect()
    }
    fn responders(&self) -> Vec<Vec<String>> {
        self.spawned
            .borrow()
            .iter()
            .filter(|a| a.iter().any(|x| x == "responder"))
            .cloned()
            .collect()
    }
}
impl LinuxHost for FakeV6 {
    fn exec(&self, argv: &[String], _timeout: u64) -> Result<Output, String> {
        self.note(argv, &[]);
        self.execs.borrow_mut().push(argv.to_vec());
        self.log
            .borrow_mut()
            .push(format!("exec {}", argv.join(" ")));
        if argv.iter().any(|a| a == "isolation") {
            fs::write(after(argv, "--out"), ipv6_isolation()).unwrap();
        }
        let stdout = if argv.get(4).map(String::as_str) == Some(CAT) {
            self.sysctls.borrow().clone()
        } else if argv.first().map(String::as_str) == Some(IP) && argv.iter().any(|a| a == "addr") {
            let n = self.addr_reads.get();
            self.addr_reads.set(n + 1);
            let tentative = self.tentative_from.get().is_some_and(|k| n >= k);
            addr_json(
                argv.last().unwrap(),
                tentative && argv.last().unwrap() == "veth-a",
            )
        } else {
            String::new()
        };
        Ok(Output {
            rc: 0,
            stdout,
            stderr: String::new(),
        })
    }
    fn spawn(
        &self,
        argv: &[String],
        stdout: &Path,
        stderr: &Path,
    ) -> Result<Box<dyn Running>, String> {
        self.note(argv, &[stdout]);
        self.spawned.borrow_mut().push(argv.to_vec());
        fs::write(stdout, "").unwrap();
        fs::write(stderr, "").unwrap();
        if argv.iter().any(|a| a == "responder") {
            fs::write(
                after(argv, "--ready"),
                "listening 80,8080 tcp6 fd00:198:18::2\n",
            )
            .unwrap();
            return Ok(self.proc("responder", None, None));
        }
        let sim = &self.sims[*self.current.borrow()];
        let step_of = |p: &Path| -> String {
            p.parent()
                .and_then(Path::file_name)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        };
        if argv.iter().any(|a| a == "dump") {
            fs::write(after(argv, "--ready"), "{\"tcpdump_pid\":1}\n").unwrap();
            fs::write(after(argv, "--ack"), "ack\n").unwrap();
            let pcap_path = PathBuf::from(after(argv, "--pcap"));
            let step = sim
                .steps
                .iter()
                .find(|s| s.spec.name == step_of(&pcap_path))
                .unwrap();
            let frames = step.frames.clone();
            let meta = PathBuf::from(after(argv, "--meta"));
            let stop = move || {
                fs::write(&pcap_path, pcap::encode(&frames)).unwrap();
                fs::write(&meta, AdSim::witness(&frames)).unwrap();
                fs::write(
                    format!("{}.tcpdump.err", pcap_path.display()),
                    format!("{0} packets captured\n", frames.len()),
                )
                .unwrap();
                0
            };
            return Ok(self.proc("witness", None, Some(Box::new(stop))));
        }
        let who = if argv.contains(&self.oracle) {
            Who::Oracle
        } else if argv.contains(&self.rmasscan) {
            Who::Rmasscan
        } else {
            return Ok(self.proc("other", Some(0), None));
        };
        assert_eq!(
            &argv[4..7],
            &strings(&[SH, "-c", IN_DIR_SCRIPT])[..],
            "{argv:?}"
        );
        let cwd = PathBuf::from(&argv[7]);
        let step = sim
            .steps
            .iter()
            .find(|s| s.spec.name == step_of(stdout))
            .unwrap();
        assert_eq!(step.spec.who, who);
        fs::write(stdout, &step.stdout).unwrap();
        fs::write(stderr, &step.stderr).unwrap();
        if let (Some(name), Some(d)) = (step.spec.out.file(), &step.doc) {
            fs::write(cwd.join(name), d).unwrap();
        }
        Ok(self.proc(
            if who == Who::Oracle {
                "oracle"
            } else {
                "scanner"
            },
            Some(step.exit),
            None,
        ))
    }
    fn euid(&self) -> Result<u32, String> {
        Ok(self.euid)
    }
    fn account(&self) -> Option<String> {
        None
    }
    fn pause(&self, _d: Duration) {
        self.log.borrow_mut().push("pause".into());
    }
    fn stopped(&self) -> bool {
        false
    }
}

struct Setup {
    root: PathBuf,
    out: PathBuf,
    lab: PathBuf,
    fake: FakeV6,
    args: Vec<String>,
}
fn setup(tags: &[&'static str]) -> Setup {
    let root = scratch();
    let out = root.join("linux-ipv6-r1");
    let work = out.join(".work");
    fs::create_dir_all(&work).unwrap();
    fs::write(work.join("host-links-before.txt"), "eno1\nlo\n").unwrap();
    fs::write(out.join(iv::ISOLATION_JSON), ipv6_isolation()).unwrap();
    let (lab, rm, oracle) = (
        root.join("rmasscan-lab"),
        root.join("rmasscan"),
        root.join("masscan"),
    );
    for (p, b) in [(&lab, "lab"), (&rm, "rmasscan"), (&oracle, "masscan")] {
        fs::write(p, b).unwrap();
    }
    let mut args = strings(&[
        "--out",
        out.to_str().unwrap(),
        "--work",
        work.to_str().unwrap(),
        "--ns-a",
        "wl-scan-41-42",
        "--ns-b",
        "wl-peer-41-42",
        "--iface-a",
        "veth-a",
        "--iface-b",
        "veth-b",
        "--mac-a",
        "02:aa:00:00:00:01",
        "--mac-b",
        "02:aa:00:00:00:02",
        "--rmasscan",
        rm.to_str().unwrap(),
        "--oracle",
        oracle.to_str().unwrap(),
        "--conf-masked",
        "1",
        "--lab-id",
        LAB_ID,
    ]);
    if tags.len() < iv::planned_tags().len() {
        args.push("--only".into());
        args.extend(tags.iter().map(|t| (*t).to_owned()));
    }
    let fake = FakeV6::new(tags, &rm, &oracle);
    Setup {
        root,
        out,
        lab,
        fake,
        args,
    }
}
fn run_suite(s: &Setup) -> Result<i32, SuiteError> {
    linux_with(&s.args, &s.fake, &s.lab)
}
fn not_run_text(r: Result<i32, SuiteError>) -> String {
    match r {
        Err(SuiteError::NotRun(m)) => m,
        other => panic!("not a NOT RUN: {other:?}"),
    }
}

#[test]
fn the_suite_writes_what_the_verifier_reads_for_every_case() {
    let s = setup(&iv::planned_tags());
    assert_eq!(run_suite(&s).unwrap(), 0);
    fs::write(s.out.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = iv::verify_dir(&s.out);
    assert_eq!(res["overall"], PASS, "{:#?}", bad(&res));
    for tag in iv::planned_tags() {
        let d = s.out.join("runs").join(tag);
        for f in [
            "hashes-before-copy.txt",
            "expect.json",
            "ipv6-stack.json",
            "isolation.json",
            "isolation-post.json",
        ] {
            assert!(d.join(f).is_file(), "{tag} {f}");
        }
        let stack: Ipv6Stack =
            serde_json::from_slice(&fs::read(d.join("ipv6-stack.json")).unwrap()).unwrap();
        assert_eq!(stack, crate::ipv6_verify::tests::stack());
        let iso: Value =
            serde_json::from_slice(&fs::read(d.join("isolation.json")).unwrap()).unwrap();
        assert_eq!(iso["mode"], "ipv6");
    }
    let m = crate::windows_suite::read_json(s.out.join("manifest.json")).unwrap();
    assert_eq!(
        (m["ipv6"].as_str(), m["lab_id"].as_str()),
        (Some("linux"), Some(LAB_ID))
    );
    // the seal of every case is `capture isolation --mode ipv6`, before and after
    let seals: Vec<Vec<String>> = s
        .fake
        .execs
        .borrow()
        .iter()
        .filter(|a| a.iter().any(|x| x == "isolation"))
        .cloned()
        .collect();
    assert_eq!(seals.len(), 2 * iv::planned_tags().len());
    assert!(seals.iter().all(|a| after(a, "--mode") == "ipv6"));
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn every_scanner_runs_the_tables_argv_and_the_oracle_its_two_extras_in_its_own_directory() {
    let s = setup(&iv::planned_tags());
    run_suite(&s).unwrap();
    let rm = s.fake.scans(&s.fake.rmasscan);
    let or = s.fake.scans(&s.fake.oracle);
    let table: Vec<StepSpec> = iv::planned_tags()
        .iter()
        .flat_map(|t| iv::steps(t).unwrap())
        .collect();
    let want_rm: Vec<&StepSpec> = table.iter().filter(|x| x.who == Who::Rmasscan).collect();
    let want_or: Vec<&StepSpec> = table.iter().filter(|x| x.who == Who::Oracle).collect();
    assert_eq!((rm.len(), or.len()), (5, 5));
    for (a, st) in rm.iter().zip(&want_rm) {
        assert_eq!(
            &a[..4],
            &strings(&[IP, "netns", "exec", "wl-scan-41-42"])[..],
            "{a:?}"
        );
        assert!(
            slashes(&a[7]).ends_with(&format!("/cwd-{}", st.name)),
            "{a:?}"
        );
        assert_eq!(a[8], s.fake.rmasscan);
        assert_eq!(&a[9..], &st.argv[..]);
        assert!(
            !a.iter().any(|x| x == "--adapter-ip"),
            "rmasscan detects its source"
        );
    }
    for (a, st) in or.iter().zip(&want_or) {
        assert_eq!(&a[8..12], &strings(&[UNSHARE, "-m", SH, "-c"])[..], "{a:?}");
        let at = a.iter().position(|x| *x == s.fake.oracle).unwrap();
        assert_eq!(&a[at + 1..], &st.argv[..]);
        assert_eq!(after(a, "--adapter-ip"), "fd00:198:18::1");
        assert_eq!(after(a, "--router-mac-ipv6"), "02-aa-00-00-00-02");
    }
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn the_responder_listens_on_ipv6_too_and_the_stands_ipv6_is_read_before_every_case() {
    let s = setup(&iv::planned_tags());
    run_suite(&s).unwrap();
    let resp = s.fake.responders();
    assert_eq!(resp.len(), 10, "one responder per step");
    for a in &resp {
        assert_eq!(
            &a[..4],
            &strings(&[IP, "netns", "exec", "wl-peer-41-42"])[..]
        );
        let mut want = iv::responder_args();
        want.push("--ready".into());
        assert_eq!(&a[7..a.len() - 1], &want[..]);
        assert_eq!(
            after(a, "--tcp6-ips"),
            "fd00:198:18::2,fd00:198:18::3,fd00:198:18::4,fd00:198:18::5"
        );
    }
    // the stand's IPv6: once before anything, then once per case, each a settings read and an address read per side
    let execs = s.fake.execs.borrow();
    let cats: Vec<&Vec<String>> = execs
        .iter()
        .filter(|a| a.get(4).map(String::as_str) == Some(CAT))
        .collect();
    assert_eq!(cats.len(), 2 * (1 + iv::planned_tags().len()));
    for a in &cats {
        assert!(
            a[5..]
                .iter()
                .all(|f| f.starts_with("/proc/sys/net/ipv6/conf/veth-")),
            "{a:?}"
        );
        assert_eq!(a.len(), 5 + capture::IPV6_SYSCTLS.len());
    }
    let addrs: Vec<&Vec<String>> = execs
        .iter()
        .filter(|a| a[0] == IP && a.iter().any(|x| x == "addr"))
        .collect();
    assert_eq!(addrs.len(), 2 * (1 + iv::planned_tags().len()));
    assert!(
        addrs
            .iter()
            .all(|a| a[1..4] == strings(&["-n", a[2].as_str(), "-6"])[..]
                && a.contains(&"-j".to_owned()))
    );
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn a_tentative_address_refuses_the_suite_before_anything_starts() {
    let s = setup(&iv::planned_tags());
    s.fake.tentative_from.set(Some(0));
    let m = not_run_text(run_suite(&s));
    assert!(
        m.contains("fd00:198:18::1 on veth-a is tentative") && m.contains("nothing was started"),
        "{m}"
    );
    assert!(s.fake.spawned.borrow().is_empty(), "nothing was started");
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn a_tentative_address_before_a_later_case_is_not_run_and_the_earlier_case_stands() {
    let s = setup(&iv::planned_tags());
    // reads 0-1: before anything; 2-3: before v01; 4-5: before v02, where the scanner's ULA turns tentative
    s.fake.tentative_from.set(Some(4));
    let m = not_run_text(run_suite(&s));
    assert!(
        m.contains("v02_mixed_v4_v6: the stand's IPv6 is not ready") && m.contains("tentative"),
        "{m}"
    );
    assert!(s.out.join("runs/v01_ndp_and_tcp6_syn").is_dir());
    assert!(!s.out.join("runs/v02_mixed_v4_v6").exists());
    assert_eq!(
        s.fake.scans(&s.fake.rmasscan).len(),
        2,
        "only v01's scanners ran"
    );
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn ipv6_settings_that_are_not_the_stands_refuse_the_suite() {
    let s = setup(&iv::planned_tags());
    *s.fake.sysctls.borrow_mut() = "0\n1\n0\n0\n0\n0\n".into();
    let m = not_run_text(run_suite(&s));
    assert!(m.contains("IPv6 settings"), "{m}");
    assert!(s.fake.spawned.borrow().is_empty());
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn only_root_inside_the_ipv6_stand_may_run_it_and_only_the_tables_cases() {
    let mut s = setup(&iv::planned_tags());
    s.fake.euid = 1000;
    assert!(not_run_text(run_suite(&s)).contains("runs as root"));
    assert!(s.fake.spawned.borrow().is_empty() && s.fake.execs.borrow().is_empty());
    fs::remove_dir_all(&s.root).unwrap();
    let mut s = setup(&iv::planned_tags());
    s.args.extend(strings(&["--only", "v99_nope"]));
    assert!(not_run_text(run_suite(&s)).contains("v99_nope is not an ipv6 case"));
    fs::remove_dir_all(&s.root).unwrap();
    // wire-lab.sh's isolation.json must attest the IPv6 stand: the autodetect stand's record does not
    let s = setup(&["v03_explicit_router_mac_ipv6"]);
    fs::write(s.out.join(iv::ISOLATION_JSON), av::tests::linux_isolation()).unwrap();
    let m = not_run_text(run_suite(&s));
    assert!(m.contains("does not attest the sealed IPv6 stand"), "{m}");
    assert!(s.fake.spawned.borrow().is_empty());
    fs::remove_dir_all(&s.root).unwrap();
    assert_eq!(run(&strings(&["help"])), Ok(0));
    assert!(
        run(&strings(&["macos"]))
            .unwrap_err()
            .contains("the ipv6 suite runs on linux")
    );
    if !cfg!(target_os = "linux") {
        assert!(
            matches!(linux_entry(&[], Path::new("/x")), Err(SuiteError::NotRun(m)) if m.contains("runs on the Linux lab host"))
        );
    }
}

#[test]
fn every_target_must_be_in_the_stands_prefixes() {
    for ok in [
        "[fd00:198:18::2]-[fd00:198:18::5]",
        "fd00:198:18::2-fd00:198:18::5",
        "fd00:198:18::7",
        "--adapter-ip=fd00:198:18::1",
        "fd00:198:18::/64",
        "198.18.0.2-198.18.0.5,[fd00:198:18::2]-[fd00:198:18::5]",
        "02-aa-00-00-00-02",
    ] {
        assert!(ipv6_outside_the_lab(&strings(&[ok])).is_empty(), "{ok}");
    }
    for bad in [
        "2001:db8::1",
        "[fd00:198:18::2]-[fd00:198:19::5]",
        "fd00:198:18::/48",
        "fe80::1",
        "fd00::zz",
    ] {
        assert_eq!(ipv6_outside_the_lab(&strings(&[bad])).len(), 1, "{bad}");
    }
    // and every case's argv is inside
    for tag in iv::planned_tags() {
        for s in iv::steps(tag).unwrap() {
            assert!(
                ipv6_outside_the_lab(&s.argv).is_empty()
                    && addresses_outside_the_lab(&s.argv).is_empty()
            );
        }
    }
}

#[test]
fn wire_lab_raises_ipv6_only_for_the_ipv6_suite_and_only_on_the_lab_veth_pair() {
    let text =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/wire-lab.sh"))
            .unwrap();
    // The older suites' IPv6 lines are untouched and run for every suite, ipv6 included.
    for line in [
        r#"  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 net.ipv4.ip_forward=0"#,
        r#"nsa sysctl -qw "net.ipv6.conf.$IF_A.disable_ipv6=1"; nsb sysctl -qw "net.ipv6.conf.$IF_B.disable_ipv6=1""#,
        r#"  nsa sysctl -qw "net.ipv6.conf.$IF_A2.disable_ipv6=1"; nsb sysctl -qw "net.ipv6.conf.$IF_B2.disable_ipv6=1""#,
        r#"    [ -z "$(ip -n "$ns" -6 route show default)" ] || fail "$ns has an IPv6 default route""#,
    ] {
        assert!(text.lines().any(|l| l == line), "{line}");
    }
    assert!(text.contains(r#"ipv6) [ -n "$RMASSCAN_BIN" ] || { echo "--suite ipv6 needs --rmasscan" >&2; exit 64; } ;;"#));
    assert!(text.contains(r#"[ "$SUITE" != ipv6 ] || STAND_SUITE=1"#));
    assert!(text.contains(r#"[ "$SUITE" != ipv6 ] || ISOLATION_MODE=ipv6"#));
    // Every line that turns IPv6 on, adds an IPv6 address, route or neighbour, sits inside an `if [ "$SUITE" = ipv6 ]`
    // block and names a namespace of this lab.
    let mut in_ipv6 = false;
    let mut enabling = 0;
    for l in text.lines() {
        let t = l.trim_start();
        if t.starts_with("if [ \"$SUITE\" = ipv6 ]") {
            in_ipv6 = true;
        } else if l == "fi" {
            in_ipv6 = false;
        }
        if t.starts_with('#') || t.starts_with("note_cmd") || t.starts_with("IPV6_SETTINGS=") {
            continue;
        }
        let turns_on = t.contains("$IPV6_SETTINGS")
            || t.contains("disable_ipv6=0")
            || t.contains(" -6 addr add")
            || t.contains(" -6 route add")
            || t.contains(" -6 neigh add");
        if turns_on {
            enabling += 1;
            assert!(in_ipv6, "IPv6 raised outside the ipv6 suite: {l}");
            assert!(
                [
                    "nsa ",
                    "nsb ",
                    r#"-n "$NS_A""#,
                    r#"-n "$NS_B""#,
                    r#"exec "$ns""#
                ]
                .iter()
                .any(|n| t.contains(n)),
                "an IPv6 change outside the lab's namespaces: {l}"
            );
        }
    }
    assert_eq!(
        enabling, 7,
        "settings, lo + all.accept_dad, scanner address, peer addresses, route, two neighbour lines"
    );
    // The settings are the Rust stand's, IPv6 itself turned on last.
    let settings = text
        .lines()
        .find_map(|l| l.strip_prefix("IPV6_SETTINGS=\""))
        .and_then(|l| l.strip_suffix('"'))
        .unwrap();
    let mut want: Vec<String> = capture::IPV6_SYSCTLS
        .iter()
        .filter(|(k, _)| *k != "disable_ipv6")
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    want.push("disable_ipv6=0".into());
    assert_eq!(settings, want.join(" "));
    // The stand's addresses are the Rust stand's.
    assert!(text.contains(&format!(
        "IP6_A={}; IP6_PEERS=\"{}\"; IP6_GW={}",
        capture::IPV6_SCANNER,
        capture::IPV6_PEERS.join(" "),
        capture::IPV6_PEER_LL
    )));
    // The suite is started with the lab id and the same flags as the other stand suites.
    let suite = text
        .split("start_suite_group \"$OUT/suite.log\" \"$LAB_BIN\" ipv6-suite linux")
        .nth(1)
        .and_then(|t| t.split("SUITE_PID=").next())
        .expect("the ipv6 suite's start");
    for flag in [
        r#"--lab-id "$LAB_ID""#,
        r#"--rmasscan "$RMASSCAN_BIN""#,
        r#"--oracle "$ORACLE""#,
        r#"--conf-masked "$CONF_MASKED""#,
        r#"--work "$WORK""#,
        r#"--ns-a "$NS_A""#,
        r#"--ns-b "$NS_B""#,
    ] {
        assert!(suite.contains(flag), "{flag}: {suite}");
    }
    // Nothing of the new branch loads a module or touches the host's firewall, routes, bridges or sudo.
    for banned in [
        "modprobe",
        "insmod",
        "iptables",
        "nft ",
        "ip6tables",
        "brctl",
        "sudo ",
        "ip -6 route add default",
        "ip route add",
    ] {
        assert!(
            !text
                .lines()
                .filter(|l| l.contains("ipv6") || l.contains("IP6_") || l.contains("IPV6_"))
                .any(|l| l.contains(banned) && !l.trim_start().starts_with('#')),
            "{banned}"
        );
    }
}
