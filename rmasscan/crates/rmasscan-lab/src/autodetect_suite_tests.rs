//! The autodetect suites against recording hosts: nothing here opens an interface, runs a process or writes a
//! frame. The process outputs (rmasscan's stdout, stderr and exit code, the witnesses' captures and records, the
//! stand's statuses) come from the verifier's synthetic generator (`autodetect_verify::tests::Sim`); the suite
//! writes the run directories itself, and `autodetect-verify` judges them. Scratch names come from
//! `windows_suite::nonce`, never from the clock.
use super::*;
use crate::{
    autodetect_verify::{self as av, tests::Sim},
    pcap,
    windows_suite::nonce,
};
use serde_json::json;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
};

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-autodetect-suite-{}", nonce()));
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
fn file_of(sim: &Sim, name: &str) -> Vec<u8> {
    sim.files()
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, b)| b)
        .unwrap_or_else(|| panic!("the generator has no {name}"))
}
/// Every check of a verdict that did not pass, for the assertion messages.
fn bad(res: &Value) -> Vec<String> {
    res["runs"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|r| {
            r["checks"]
                .as_array()
                .unwrap()
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
const PLANS: [Plan; 4] = [Plan::Linux, Plan::Macos, Plan::MacosRoot, Plan::Windows];
/// A full `--iflist` listing as a host prints it: the stand NIC between interfaces of the host, which must never
/// reach the evidence (the MAC and the names are an inventory).
fn full_iflist(stand_line: &str) -> String {
    format!(
        "lo index=1 mac=none ipv4=127.0.0.1 up other\n{stand_line}\nwlp2s0 index=3 mac=3c-22-fb-11-22-33 ipv4=192.168.1.20 up ethernet\ndefault via 192.168.1.1 dev wlp2s0\n"
    )
}
/// The C oracle's `--iflist` (its own format), with a host interface in it.
const ORACLE_IFLIST: &str = "If list:\n  1  veth-a\n  2  wlp2s0\n  3  lo\n";
/// The host name an mDNS announcement carries: it must never reach the evidence.
const HOST: &[u8] = b"\x09denys-mbp\x05local\x00";
const PEER: [u8; 6] = crate::link::STAND_PEER_MAC;
const SCANNER: [u8; 6] = crate::link::STAND_SCANNER_MAC;

/// An Ethernet frame with an IPv4 (or IPv6) header and a UDP (17) or TCP SYN-ACK (6) header, then `payload`.
fn ip_frame(
    src: [u8; 6],
    dst: [u8; 6],
    v6: bool,
    proto: u8,
    ports: (u16, u16),
    payload: &[u8],
) -> Vec<u8> {
    let mut l4 = Vec::new();
    l4.extend(ports.0.to_be_bytes());
    l4.extend(ports.1.to_be_bytes());
    if proto == 17 {
        l4.extend(((8 + payload.len()) as u16).to_be_bytes());
        l4.extend([0, 0]);
    } else {
        l4.extend([0; 8]);
        l4.extend([0x50, 0x12]);
        l4.extend([0; 6]);
    }
    l4.extend(payload);
    let mut f: Vec<u8> = dst.iter().chain(&src).copied().collect();
    if v6 {
        f.extend([0x86, 0xdd, 0x60, 0, 0, 0]);
        f.extend((l4.len() as u16).to_be_bytes());
        f.extend([proto, 255]);
        f.extend([0xfe, 0x80].iter().chain(&[0u8; 14]));
        f.extend([0xff, 0x02].iter().chain(&[0u8; 13]).chain(&[0xfb]));
    } else {
        f.extend([8, 0, 0x45, 0]);
        f.extend(((20 + l4.len()) as u16).to_be_bytes());
        f.extend([0, 0, 0, 0, 64, proto, 0, 0, 198, 18, 0, 2, 224, 0, 0, 251]);
    }
    f.extend(l4);
    f
}
/// The peer host's own mDNS announcement (multicast, from the peer stand MAC, UDP 5353), naming the host.
fn mdns(v6: bool) -> Vec<u8> {
    ip_frame(
        PEER,
        [0x01, 0x00, 0x5e, 0, 0, 0xfb],
        v6,
        17,
        (5353, 5353),
        HOST,
    )
}
/// `frames` with the peer host's mDNS (IPv4 and IPv6) right after the first frame: what the unfiltered witness saw.
fn with_mdns(frames: &pcap::Frames) -> pcap::Frames {
    let mut v = frames.clone();
    let t = v.first().map_or(1.0, |f| f.0);
    v.insert(1.min(v.len()), (t + 0.000_002, mdns(false)));
    v.insert(2.min(v.len()), (t + 0.000_003, mdns(true)));
    v
}
fn holds(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// ------------------------------------------------------------------ a recording Linux host

/// A scripted process: it exits at once with `rc`, or runs until signalled, then runs `on_stop` (the witness
/// finalising its capture) and exits with what that returns, `linger` polls later.
struct FakeRun {
    rc: Option<i32>,
    on_stop: Option<Box<dyn FnOnce() -> i32>>,
    name: String,
    signals: Rc<RefCell<Vec<String>>>,
    linger: u32,
}
impl Running for FakeRun {
    fn try_wait(&mut self) -> Result<Option<i32>, String> {
        if self.rc.is_some() && self.linger > 0 {
            self.linger -= 1;
            return Ok(None);
        }
        Ok(self.rc)
    }
    fn signal(&mut self, sig: &str) {
        self.signals
            .borrow_mut()
            .push(format!("{}:{sig}", self.name));
        if self.rc.is_none() {
            self.rc = Some(self.on_stop.take().map_or(0, |f| f()));
        }
    }
    fn kill(&mut self) {
        self.signals
            .borrow_mut()
            .push(format!("{}:KILL", self.name));
        self.rc.get_or_insert(-9);
    }
}

/// The netns stand as the suite sees it, played from the generator's runs (one `Sim` per tag).
struct FakeLinux {
    sims: BTreeMap<&'static str, Sim>,
    rmasscan: String,
    oracle: String,
    euid: u32,
    current: RefCell<&'static str>,
    spawned: RefCell<Vec<Vec<String>>>,
    execs: RefCell<Vec<Vec<String>>>,
    signals: Rc<RefCell<Vec<String>>>,
    /// rmasscan runs until it is signalled.
    scanner_hangs: Cell<bool>,
    /// Polls the witness still runs after its stop signal (it finalises its capture).
    witness_linger: Cell<u32>,
    /// The responder never says it is ready.
    responder_silent: Cell<bool>,
    /// The n-th `capture isolation` (1-based) fails; 0: none does.
    isolation_fails_at: Cell<usize>,
    isolation_calls: Cell<usize>,
    /// A file overwritten when rmasscan starts (a binary replaced in the middle of the suite).
    replace_on_scan: RefCell<Option<PathBuf>>,
}
impl FakeLinux {
    fn new(tags: &[&'static str], rmasscan: &Path, oracle: &Path) -> Self {
        FakeLinux {
            sims: tags
                .iter()
                .map(|t| (*t, Sim::new(Plan::Linux, t)))
                .collect(),
            rmasscan: p2s(rmasscan),
            oracle: p2s(oracle),
            euid: 0,
            current: RefCell::new(""),
            spawned: RefCell::default(),
            execs: RefCell::default(),
            signals: Rc::default(),
            scanner_hangs: Cell::new(false),
            witness_linger: Cell::new(0),
            responder_silent: Cell::new(false),
            isolation_fails_at: Cell::new(0),
            isolation_calls: Cell::new(0),
            replace_on_scan: RefCell::default(),
        }
    }
    /// The run a command belongs to, from the work directory its paths name (`<work>/<tag>.<nonce>/...`).
    fn note(&self, argv: &[String], paths: &[&Path]) {
        // Either separator: the hermetic tests also run on the Windows CI runner.
        let all: Vec<String> = argv
            .iter()
            .cloned()
            .chain(paths.iter().map(|p| p2s(p)))
            .map(|a| a.replace('\\', "/"))
            .collect();
        for tag in self.sims.keys() {
            if all.iter().any(|a| a.contains(&format!("/{tag}."))) {
                *self.current.borrow_mut() = tag;
            }
        }
    }
    fn sim(&self) -> &Sim {
        &self.sims[*self.current.borrow()]
    }
    fn runs(&self, program: &str) -> usize {
        self.spawned
            .borrow()
            .iter()
            .chain(self.execs.borrow().iter())
            .filter(|a| a.iter().any(|x| x == program))
            .count()
    }
    fn nothing_started(&self) -> bool {
        self.spawned.borrow().is_empty() && self.execs.borrow().is_empty()
    }
    fn proc(
        &self,
        name: &str,
        rc: Option<i32>,
        on_stop: Option<Box<dyn FnOnce() -> i32>>,
    ) -> Box<dyn Running> {
        Box::new(FakeRun {
            rc,
            on_stop,
            name: name.into(),
            signals: self.signals.clone(),
            linger: if name == "witness" {
                self.witness_linger.get()
            } else {
                0
            },
        })
    }
}
impl LinuxHost for FakeLinux {
    fn exec(&self, argv: &[String], _timeout: u64) -> Result<Output, String> {
        self.note(argv, &[]);
        self.execs.borrow_mut().push(argv.to_vec());
        let ok = |stdout: String| Output {
            rc: 0,
            stdout,
            stderr: String::new(),
        };
        if argv.iter().any(|a| a == "isolation") {
            self.isolation_calls.set(self.isolation_calls.get() + 1);
            if self.isolation_calls.get() == self.isolation_fails_at.get() {
                return Ok(Output {
                    rc: 1,
                    stdout: String::new(),
                    stderr: "host link list changed or baseline does not match".into(),
                });
            }
            fs::write(after(argv, "--out"), file_of(self.sim(), "isolation.json")).unwrap();
        } else if argv.iter().any(|a| a == "--iflist") {
            return Ok(ok(if argv.contains(&self.oracle) {
                ORACLE_IFLIST.to_owned()
            } else {
                full_iflist("veth-a index=2 mac=02-aa-00-00-00-01 ipv4=198.18.0.1 up ethernet")
            }));
        }
        Ok(ok(String::new()))
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
        let sim = self.sim();
        if argv.iter().any(|a| a == "responder") {
            if !self.responder_silent.get() {
                fs::write(after(argv, "--ready"), "listening 80,8080\n").unwrap();
            }
            return Ok(self.proc("responder", None, None));
        }
        if argv.iter().any(|a| a == "dump") {
            fs::write(after(argv, "--ready"), "{\"tcpdump_pid\":1}\n").unwrap();
            fs::write(after(argv, "--ack"), "ack\n").unwrap();
            let pcap_path = PathBuf::from(after(argv, "--pcap"));
            let frames = if pcap_path.ends_with("oracle.pcap") {
                sim.oracle.as_ref().unwrap().pcap.clone()
            } else {
                sim.peer.clone()
            };
            let meta = PathBuf::from(after(argv, "--meta"));
            let stop = move || {
                fs::write(&pcap_path, pcap::encode(&frames)).unwrap();
                fs::write(&meta, Sim::witness(&frames)).unwrap();
                fs::write(
                    format!("{}.tcpdump.err", pcap_path.display()),
                    format!("tcpdump: listening on veth-b, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n{0} packets captured\n{0} packets received by filter\n0 packets dropped by kernel\n", frames.len()),
                )
                .unwrap();
                0
            };
            return Ok(self.proc("witness", None, Some(Box::new(stop))));
        }
        if argv.contains(&self.oracle) {
            let o = sim.oracle.as_ref().unwrap();
            fs::write(stdout, &o.stdout).unwrap();
            fs::write(stderr, &o.stderr).unwrap();
            return Ok(self.proc("oracle", Some(o.exit.trim().parse().unwrap()), None));
        }
        if argv.contains(&self.rmasscan) {
            if let Some(p) = self.replace_on_scan.borrow().as_ref() {
                fs::write(p, "another build").unwrap();
            }
            if self.scanner_hangs.get() {
                return Ok(self.proc("scanner", None, None));
            }
            fs::write(stdout, sim.stdout.clone().unwrap_or_default()).unwrap();
            fs::write(stderr, sim.stderr_text()).unwrap();
            return Ok(self.proc("scanner", Some(sim.exit), None));
        }
        Ok(self.proc("other", Some(0), None))
    }
    fn euid(&self) -> Result<u32, String> {
        Ok(self.euid)
    }
    fn pause(&self, _d: Duration) {}
    fn stopped(&self) -> bool {
        false
    }
}

/// A Linux evidence directory as `wire-lab.sh --suite autodetect` leaves it before the suite starts: the
/// attestation of the sealed stand and the work directory.
struct LinuxSetup {
    root: PathBuf,
    out: PathBuf,
    lab: PathBuf,
    fake: FakeLinux,
    args: Vec<String>,
}
fn linux_setup(tags: &[&'static str]) -> LinuxSetup {
    let root = scratch();
    let out = root.join("linux-r1");
    let work = out.join(".work");
    fs::create_dir_all(&work).unwrap();
    fs::write(work.join("host-links-before.txt"), "eno1\nlo\n").unwrap();
    fs::write(
        out.join("isolation.json"),
        file_of(&Sim::new(Plan::Linux, "l01_auto"), "isolation.json"),
    )
    .unwrap();
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
    ]);
    if tags.len() < av::planned_tags(Plan::Linux).len() {
        args.push("--only".into());
        args.extend(tags.iter().map(|t| (*t).to_owned()));
    }
    let fake = FakeLinux::new(tags, &rm, &oracle);
    LinuxSetup {
        root,
        out,
        lab,
        fake,
        args,
    }
}
fn set_arg(args: &mut [String], k: &str, v: &str) {
    let i = args.iter().position(|x| x == k).unwrap();
    args[i + 1] = v.into();
}

// ------------------------------------------------------------------ the brief's tests

#[test]
fn case_tables_of_the_three_oses_serialize_into_argv_json_and_expect_json() {
    let d = scratch();
    for plan in PLANS {
        for spec in av::cases(plan) {
            let (argv, expect) = case_records(spec);
            assert_eq!(argv.argv, spec.argv(), "{}", spec.tag);
            assert_eq!(expect, spec.expect(), "{}", spec.tag);
            let dir = d.join(spec.tag);
            fs::create_dir_all(&dir).unwrap();
            write_case_records(&dir, spec).unwrap();
            let read: av::ArgvRecord =
                serde_json::from_slice(&fs::read(dir.join(av::ARGV_JSON)).unwrap()).unwrap();
            let want: av::ExpectRecord =
                serde_json::from_slice(&fs::read(dir.join(av::EXPECT_JSON)).unwrap()).unwrap();
            assert_eq!(read.argv, spec.argv(), "{} argv.json", spec.tag);
            assert_eq!(want, spec.expect(), "{} expect.json", spec.tag);
            assert_eq!(want.tag, spec.tag);
            assert_eq!(want.kind, spec.kind);
        }
    }
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn linux_cases_never_name_an_address_outside_198_18_0_0_24() {
    for spec in av::cases(Plan::Linux) {
        assert!(
            addresses_outside_the_lab(&spec.argv()).is_empty(),
            "{} {:?}",
            spec.tag,
            spec.argv()
        );
        assert!(addresses_outside_the_lab(&preflight_argv(spec)).is_empty());
    }
    // The check itself: every address, range, block and option value counts; ports, MACs and names do not.
    for (argv, outside) in [
        (&["198.18.0.2", "-p80,81"][..], false),
        (&["198.18.0.2-198.18.0.5", "-p8000-8007"], false),
        (
            &["198.18.0.0/24", "--adapter-mac", "02-aa-00-00-00-01"],
            false,
        ),
        (
            &[
                "198.18.0.2",
                "--adapter",
                "veth-a",
                "--router-ip",
                "198.18.0.9",
            ],
            false,
        ),
        (&["10.0.0.1", "-p80"], true),
        (&["198.18.0.2,8.8.8.8", "-p80"], true),
        (&["198.18.0.2-198.18.1.5", "-p80"], true),
        (&["198.18.0.0/16", "-p80"], true),
        (&["198.18.0.2", "--router-ip", "192.168.1.1"], true),
        (&["198.18.0.2", "--adapter-ip", "100.64.0.1"], true),
        (&["198.18.0.2", "--exclude", "0.0.0.0/0"], true),
        (&["198.18.0.2", "--router-ip=192.168.1.1"], true),
        (&["--range=198.18.0.2-198.18.0.5", "-p80"], false),
    ] {
        assert_eq!(
            !addresses_outside_the_lab(&strings(argv)).is_empty(),
            outside,
            "{argv:?}"
        );
    }
}

#[test]
fn macos_user_cases_all_carry_adapter_feth4201_or_expect_a_refusal() {
    let adapter = |argv: &[String]| {
        argv.windows(2)
            .any(|w| w[0] == "--adapter" && w[1] == "feth4201")
    };
    for plan in [Plan::Macos, Plan::MacosRoot] {
        for spec in av::cases(plan) {
            let argv = spec.argv();
            match spec.kind {
                // Anything that may put a frame on the wire names the stand NIC itself.
                CaseKind::Scan | CaseKind::ArpTimeout | CaseKind::Parity => {
                    assert!(adapter(&argv), "{} {argv:?}", spec.tag)
                }
                // Without it the case must be refused before any frame (m05) or list only (m07, m11).
                CaseKind::Refusal => {
                    assert!(spec.expect().refusal.is_some_and(|r| r.fail.is_some()))
                }
                CaseKind::Iflist => assert_eq!(argv, ["--iflist"], "{}", spec.tag),
            }
            if !adapter(&argv) {
                assert!(
                    matches!(spec.kind, CaseKind::Refusal | CaseKind::Iflist),
                    "{}",
                    spec.tag
                );
            }
        }
    }
    // The user window is m01-m07, the root case m10-m11, in the brief's order.
    assert_eq!(
        selected_tags(Plan::Macos, &[]).unwrap(),
        [
            "m01_user_masked",
            "m02_user_explicit",
            "m03_user_router_mac",
            "m04_user_arp_timeout",
            "m05_user_no_adapter",
            "m06_user_no_ip",
            "m07_user_iflist"
        ]
    );
}

#[test]
fn root_case_requires_euid_zero_and_user_cases_refuse_root() {
    assert!(euid_rule(Plan::MacosRoot, 0).is_ok());
    assert!(euid_rule(Plan::MacosRoot, 501).is_err());
    assert!(euid_rule(Plan::Macos, 501).is_ok());
    assert!(euid_rule(Plan::Macos, 0).is_err());
    // The Linux suite runs as root inside wire-lab.sh; it never calls sudo itself.
    assert!(euid_rule(Plan::Linux, 0).is_ok());
    assert!(euid_rule(Plan::Linux, 1000).is_err());
    assert_eq!(
        selected_tags(Plan::MacosRoot, &[]).unwrap(),
        ["m10_root_auto_mac", "m11_root_iflist"]
    );
    assert!(selected_tags(Plan::MacosRoot, &strings(&["m02_user_explicit"])).is_err());
    assert!(selected_tags(Plan::Macos, &strings(&["m10_root_auto_mac"])).is_err());
    assert_eq!(
        selected_tags(
            Plan::Macos,
            &strings(&["m07_user_iflist", "m01_user_masked"])
        )
        .unwrap(),
        ["m01_user_masked", "m07_user_iflist"],
        "the brief's order, not the command line's"
    );
    // A Linux suite started without root refuses before any command or file.
    let s = linux_setup(&["l01_auto"]);
    let mut fake = s.fake;
    fake.euid = 1000;
    let e = linux_with(&s.args, &fake, &s.lab).unwrap_err();
    assert!(matches!(e, SuiteError::NotRun(_)), "{e:?}");
    assert!(fake.nothing_started());
    assert!(!s.out.join("manifest.json").exists());
    fs::remove_dir_all(s.root).unwrap();
    #[cfg(target_os = "macos")]
    mac::root_rules_refuse_before_anything_starts();
}

#[cfg(target_os = "macos")]
#[test]
fn leftover_patterns_cover_rmasscan() {
    use crate::macos_suite::lab_leftovers;
    let ps = "  PID  PGID COMMAND\n    1     1 /sbin/launchd\n 5300  5300 /Users/u/bin/rmasscan-lab autodetect-suite macos --out x\n";
    assert!(
        lab_leftovers(ps, 1, "/opt/lab/rmasscan").is_empty(),
        "the suite itself (rmasscan-lab) is not an rmasscan"
    );
    // An `rmasscan` is a leftover by its name, whatever binary the running suite was given (a wire_scan suite
    // too); a renamed binary under test is one by the path the suite runs.
    for (line, scanner) in [
        (
            "6001  6001 /Users/u/bin/rmasscan 198.18.0.2 -p8000-8007 --adapter feth4201",
            "/x/wire_scan",
        ),
        ("6002  6002 ./rmasscan --iflist", "/x/wire_scan"),
        (
            "6003  6003 /tmp/t/rm-under-test 198.18.0.2 -p80",
            "/tmp/t/rm-under-test",
        ),
        (
            "6004  6004 /x/wire_scan --iface feth4201",
            "/opt/lab/rmasscan",
        ),
    ] {
        let found = lab_leftovers(&format!("{ps}{line}\n"), 1, scanner);
        assert_eq!(found.len(), 1, "{line}: {found:?}");
    }
    mac::a_live_rmasscan_refuses_the_run();
}

#[test]
fn privacy_filter_is_applied_to_the_peer_witness_on_macos() {
    use crate::macos_verify::PEER_FILTER;
    // The brief's filter, applied after the capture: exactly the peer host's own mDNS, over IPv4 and IPv6.
    assert_eq!(
        PEER_FILTER,
        "not (ether src 02:ac:00:00:00:02 and udp port 5353)"
    );
    assert!(is_peer_mdns(&mdns(false)) && is_peer_mdns(&mdns(true)));
    for (f, why) in [
        (
            ip_frame(SCANNER, PEER, false, 17, (5353, 5353), HOST),
            "UDP 5353 from the scanner MAC",
        ),
        (
            ip_frame(PEER, SCANNER, false, 17, (53, 40000), b"x"),
            "other UDP from the peer",
        ),
        (
            ip_frame(PEER, SCANNER, false, 6, (5353, 40000), b""),
            "TCP from the peer",
        ),
        (
            mdns(false)[..36].to_vec(),
            "a frame cut before its UDP ports",
        ),
    ] {
        assert!(!is_peer_mdns(&f), "{why}");
    }
    // A later fragment carries no UDP header: never read as one.
    let mut frag = mdns(false);
    frag[20..22].copy_from_slice(&0x0010u16.to_be_bytes());
    assert!(!is_peer_mdns(&frag));
    // `capture dump` takes no filter any more: the witness records every frame of the peer interface.
    assert!(
        !crate::dump::tcpdump_argv_macos("feth4202", "/w/peer.unfiltered", None)
            .iter()
            .any(|a| a.contains("5353"))
    );
    #[cfg(target_os = "macos")]
    mac::the_peer_capture_is_published_without_the_hosts_mdns();
}

#[test]
fn the_peer_capture_drops_only_the_peer_hosts_mdns_and_counts_it() {
    use rmasscan_core::arp::encode_reply;
    let ip = |o: u8| u32::from(Ipv4Addr::new(198, 18, 0, o));
    let lab: pcap::Frames = vec![
        (
            1.0,
            crate::link::marker_frame(SCANNER, PEER, crate::link::START_PAYLOAD),
        ),
        (1.1, encode_reply(PEER, ip(2), SCANNER, ip(1)).to_vec()),
        (1.2, ip_frame(PEER, SCANNER, false, 6, (8000, 40000), b"")),
        (
            1.3,
            ip_frame(SCANNER, PEER, false, 17, (5353, 5353), b"scanner"),
        ),
        (
            1.4,
            ip_frame(PEER, SCANNER, false, 17, (53, 40000), b"other"),
        ),
        (
            1.5,
            crate::link::marker_frame(SCANNER, PEER, crate::link::END_PAYLOAD),
        ),
    ];
    let unfiltered = with_mdns(&lab);
    assert_eq!(unfiltered.len(), lab.len() + 2);
    let raw = pcap::encode(&unfiltered);
    let (kept, dropped) = pcap::keep_records(&raw, |f| !is_peer_mdns(f)).unwrap();
    assert_eq!(dropped, 2);
    // Every lab frame survives, byte for byte and with its timestamp; the host name does not.
    assert_eq!(kept, pcap::encode(&lab));
    let frames = |b: &[u8]| pcap::read_pcap_records(b).unwrap().1;
    assert_eq!(frames(&kept), frames(&pcap::encode(&lab)));
    assert_eq!(frames(&kept).len(), lab.len());
    assert!(holds(&raw, HOST) && !holds(&kept, HOST));
    // capture.json: the witness's verdict on all it captured, describing the published file.
    let witness: Value = serde_json::from_slice(&Sim::witness(&unfiltered)).unwrap();
    let (published, rec) = publish_peer_capture(&raw, witness.clone()).unwrap();
    assert_eq!(published, kept);
    assert_eq!(rec["pcap_sha256"], crate::verify::sha(&kept));
    assert_eq!(rec["pcap_frames"], lab.len());
    assert_eq!(rec["privacy_filter"]["frames_dropped"], 2);
    assert_eq!(rec["unfiltered"]["pcap_frames"], unfiltered.len());
    assert_eq!(rec["unfiltered"]["pcap_sha256"], witness["pcap_sha256"]);
    let w: av::PeerWitness = serde_json::from_value(rec).unwrap();
    assert!(w.valid && w.invalid_reasons.is_empty(), "{w:?}");
    // A file other than the one the witness hashed and counted is not its capture.
    let mut other = raw.clone();
    let last = other.len() - 1;
    other[last] ^= 1;
    let (_, rec) = publish_peer_capture(&other, witness).unwrap();
    assert_eq!(rec["valid"], false, "{rec}");
}

#[test]
fn a_witness_window_with_dropped_mdns_is_still_complete() {
    use crate::dump::{Facts, problems};
    // The peer interface moved 13 frames in the witness's counter window: 11 of the lab and the host's mDNS twice.
    let lab: pcap::Frames = (0..11)
        .map(|k| {
            let payload = if k == 0 {
                crate::link::START_PAYLOAD
            } else {
                crate::link::END_PAYLOAD
            };
            (
                1.0 + f64::from(k),
                crate::link::marker_frame(SCANNER, PEER, payload),
            )
        })
        .collect();
    let all = with_mdns(&lab);
    let n = all.len() as u64;
    assert_eq!(n, 13);
    let unfiltered = Facts {
        start_markers: 1,
        end_markers: 10,
        quiesced: true,
        captured: Some(n),
        received: Some(n + 57),
        dropped_kernel: Some(0),
        interface_drop_delta: Some(0),
        received_is_prefilter: true,
        pcap_frames: n,
        tcpdump_exited: true,
        window_lo: Some(n),
        window_hi: Some(n),
        ..Facts::default()
    };
    assert!(
        problems(&unfiltered).is_empty(),
        "{:?}",
        problems(&unfiltered)
    );
    // Filtered at capture time (round 1) the same window could not be proven: the counters saw both frames.
    let filtered = Facts {
        captured: Some(n - 2),
        pcap_frames: n - 2,
        ..unfiltered.clone()
    };
    assert!(!problems(&filtered).is_empty());
    // Filtered after the capture, the witness's record stays valid and describes the published capture.
    let witness: Value = serde_json::from_slice(&Sim::witness(&all)).unwrap();
    let (_, rec) = publish_peer_capture(&pcap::encode(&all), witness).unwrap();
    let w: av::PeerWitness = serde_json::from_value(rec.clone()).unwrap();
    assert!(w.valid && w.invalid_reasons.is_empty(), "{rec}");
    assert_eq!(w.pcap_frames, 11);
    assert_eq!(rec["privacy_filter"]["frames_dropped"], 2);
}

#[test]
fn iflist_cases_store_only_the_redacted_form() {
    let stand = "veth-a index=2 mac=02-aa-00-00-00-01 ipv4=198.18.0.1 up ethernet";
    let full = full_iflist(stand);
    let r = reduce_iflist(0, &full, Some("veth-a"));
    assert_eq!(r.rc, 0);
    assert_eq!(r.lines, 4);
    assert_eq!(r.sha256, crate::verify::sha(full.as_bytes()));
    assert_eq!(r.stand_line.as_deref(), Some(stand));
    let text = serde_json::to_string(&r).unwrap();
    for host in ["wlp2s0", "3c-22-fb", "192.168.1.20", "lo index"] {
        assert!(!text.contains(host), "{host} in {text}");
    }
    // The oracle's record has no line at all; a listing without the stand NIC has none either.
    assert_eq!(reduce_iflist(0, ORACLE_IFLIST, None).stand_line, None);
    assert_eq!(
        reduce_iflist(0, "lo index=1 mac=none\n", Some("veth-a")).stand_line,
        None
    );
    // The suite: l12 keeps iflist.json and oracle/iflist.json, never a stdout file, and no file names the host.
    let s = linux_setup(&["l12_iflist"]);
    assert_eq!(linux_with(&s.args, &s.fake, &s.lab).unwrap(), 0);
    let run = s.out.join("runs/l12_iflist");
    assert!(run.join(av::IFLIST_JSON).is_file());
    assert!(run.join(av::ORACLE_IFLIST_JSON).is_file());
    assert!(!run.join("stdout.txt").exists() && !run.join("oracle/stdout.txt").exists());
    for f in crate::macos_verify::relative_files(&s.out) {
        let b = fs::read(s.out.join(&f)).unwrap();
        let t = String::from_utf8_lossy(&b);
        assert!(
            !t.contains("wlp2s0") && !t.contains("3c-22-fb"),
            "{f} holds the host listing"
        );
    }
    let rec: av::IflistRecord =
        serde_json::from_slice(&fs::read(run.join(av::ORACLE_IFLIST_JSON)).unwrap()).unwrap();
    assert_eq!((rec.rc, rec.lines, rec.stand_line), (0, 4, None));
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn preflight_expectation_is_the_stand_nic_for_w01_w06_and_local_target_for_m05() {
    use av::ExpectPreflight;
    let local = "198.18.0.2 is an address of this host (route via lo0)";
    for plan in PLANS {
        for spec in av::cases(plan) {
            let want = match spec.tag {
                "w01_auto" | "w06_multi_no_gateway" => {
                    Some(ExpectPreflight::Interface("Ethernet 2".into()))
                }
                "m05_user_no_adapter" => Some(ExpectPreflight::Refusal(local.into())),
                _ => None,
            };
            assert_eq!(av::preflight_expectation(spec.tag), want, "{}", spec.tag);
        }
    }
    let m05 = av::case_spec(Plan::Macos, "m05_user_no_adapter").unwrap();
    let mut argv = m05.argv();
    argv.push("--offline".into());
    assert_eq!(preflight_argv(&m05), argv, "the same targets, read only");
    let refused = preflight_text(
        1,
        &format!(
            "[-] FAIL: {local}\n    [hint] try \"--interface ethX\" and \"--router-ip 192.0.2.1\"\n"
        ),
    );
    assert!(refused.starts_with("rc 1\n[-] FAIL: "));
    assert!(av::preflight_shows(&m05, &refused));
    let detected = preflight_text(
        0,
        "[+] interface = feth4201 (detected: route to 198.18.0.2)\n",
    );
    assert!(!av::preflight_shows(&m05, &detected));
    let w01 = av::case_spec(Plan::Windows, "w01_auto").unwrap();
    for (text, ok) in [
        (
            "[+] interface = Ethernet 2 (detected: route to 198.18.0.2)\n",
            true,
        ),
        ("[+] interface = Ethernet 2 (given)\n", false),
        (
            "[+] interface = Ethernet (detected: route to 198.18.0.2)\n",
            false,
        ),
    ] {
        assert_eq!(
            av::preflight_shows(&w01, &preflight_text(0, text)),
            ok,
            "{text}"
        );
    }
    #[cfg(target_os = "macos")]
    mac::a_preflight_that_does_not_show_the_refusal_is_not_run();
}

// ------------------------------------------------------------------ suite and verifier agree

#[test]
fn a_linux_suite_directory_passes_autodetect_verify() {
    let tags = av::planned_tags(Plan::Linux);
    let s = linux_setup(&tags);
    // wire-lab.sh's env.json names the oracle under a home directory: the suite scrubs it.
    fs::write(
        s.out.join("env.json"),
        json!({"oracle":{"path":"/home/alice/masscan/bin/masscan"}}).to_string(),
    )
    .unwrap();
    assert_eq!(linux_with(&s.args, &s.fake, &s.lab).unwrap(), 0);
    let res = av::verify_dir(&s.out);
    assert_eq!(res["overall"], "PASS", "{:#?}", bad(&res));
    assert_eq!(res["runs"].as_array().unwrap().len(), tags.len() + 1);
    assert_eq!(
        read_json(s.out.join("manifest.json")).unwrap()["autodetect"],
        "linux"
    );
    assert_eq!(
        read_json(s.out.join("env.json")).unwrap()["oracle"]["path"],
        "$HOME/masscan/bin/masscan"
    );
    // Every case ran rmasscan once with the table's argv, inside the scanner namespace, and nothing else.
    let rm = s.fake.rmasscan.clone();
    let scans: Vec<Vec<String>> = s
        .fake
        .spawned
        .borrow()
        .iter()
        .filter(|a| a.contains(&rm))
        .cloned()
        .collect();
    for spec in av::cases(Plan::Linux)
        .iter()
        .filter(|c| c.kind != CaseKind::Iflist)
    {
        let mut want = strings(&[IP, "netns", "exec", "wl-scan-41-42"]);
        want.push(rm.clone());
        want.extend(spec.argv());
        assert_eq!(
            scans.iter().filter(|a| **a == want).count(),
            1,
            "{}",
            spec.tag
        );
    }
    assert_eq!(scans.len(), tags.len() - 1);
    // The oracle runs l11 with the same argv, /etc/masscan masked in a private mount namespace.
    let l11 = av::case_spec(Plan::Linux, "l11_parity").unwrap();
    let oracle: Vec<Vec<String>> = s
        .fake
        .spawned
        .borrow()
        .iter()
        .filter(|a| a.contains(&s.fake.oracle))
        .cloned()
        .collect();
    assert_eq!(oracle.len(), 1);
    assert_eq!(
        &oracle[0][..7],
        &strings(&[IP, "netns", "exec", "wl-scan-41-42", UNSHARE, "-m", SH])[..]
    );
    assert!(oracle[0].ends_with(&l11.argv()));
    // Each run is sealed before and after, and its witness was stopped gracefully.
    assert_eq!(s.fake.runs("isolation"), 2 * tags.len());
    assert!(
        s.fake
            .signals
            .borrow()
            .iter()
            .all(|x| !x.ends_with(":KILL"))
    );
    for tag in &tags {
        let run = s.out.join("runs").join(tag);
        assert!(run.join("isolation-post.json").is_file(), "{tag}");
        assert!(!run.join("peer.pcap.tcpdump.err").exists() && run.join("peer.err").is_file());
    }
    assert!(
        s.out.join(".work").read_dir().unwrap().count() == 1,
        "only wire-lab's own file is left"
    );
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn the_linux_suite_refuses_another_stand_before_anything_starts() {
    for (k, v) in [
        ("--iface-a", "eth0"),
        ("--iface-b", "veth-c"),
        ("--mac-a", "02:aa:00:00:00:09"),
        ("--mac-b", "02:ac:00:00:00:02"),
        ("--ns-b", "wl-scan-41-42"),
        ("--conf-masked", "2"),
        ("--rmasscan", "relative/rmasscan"),
    ] {
        let s = linux_setup(&["l01_auto"]);
        let mut args = s.args.clone();
        set_arg(&mut args, k, v);
        let e = linux_with(&args, &s.fake, &s.lab).unwrap_err();
        assert!(matches!(e, SuiteError::NotRun(_)), "{k} {v}: {e:?}");
        assert!(s.fake.nothing_started(), "{k} {v}");
        assert!(!s.out.join("manifest.json").exists(), "{k} {v}");
        fs::remove_dir_all(s.root).unwrap();
    }
    // A stand attested in the default mode (no route via the peer) is not the autodetect stand.
    let s = linux_setup(&["l01_auto"]);
    let mut v = read_json(s.out.join("isolation.json")).unwrap();
    v["default_route"] = json!(false);
    write_json(s.out.join("isolation.json"), &v).unwrap();
    assert!(matches!(
        linux_with(&s.args, &s.fake, &s.lab),
        Err(SuiteError::NotRun(_))
    ));
    assert!(s.fake.nothing_started());
    fs::remove_dir_all(s.root).unwrap();
    // A case that already has a run is never run again into the same directory, and an unknown tag is refused.
    let s = linux_setup(&["l01_auto"]);
    fs::create_dir_all(s.out.join("runs/l01_auto")).unwrap();
    assert!(matches!(
        linux_with(&s.args, &s.fake, &s.lab),
        Err(SuiteError::NotRun(_))
    ));
    let mut args = s.args.clone();
    set_arg(&mut args, "--only", "l99_bogus");
    assert!(matches!(
        linux_with(&args, &s.fake, &s.lab),
        Err(SuiteError::NotRun(_))
    ));
    assert!(s.fake.nothing_started());
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn a_run_copy_is_hashed_before_the_copy_and_checked_with_the_verifiers_rule() {
    let d = scratch();
    let (work, dest) = (d.join("work"), d.join("runs/x"));
    fs::create_dir_all(work.join("oracle")).unwrap();
    fs::write(work.join("a.txt"), "a").unwrap();
    fs::write(work.join("oracle/exit.txt"), "0\n").unwrap();
    hash_and_copy(&work, &dest).unwrap();
    let h = fs::read_to_string(dest.join(av::HASHES)).unwrap();
    assert!(
        h.contains("  oracle/exit.txt\n") && h.contains("  a.txt\n"),
        "{h}"
    );
    crate::macos_verify::hashes_match_tree(&dest, true).unwrap();
    // An existing destination is never overwritten.
    assert!(hash_and_copy(&work, &dest).is_err());
    fs::remove_dir_all(d).unwrap();
}

/// The directories under `runs_aborted/`.
fn aborted(out: &Path) -> Vec<PathBuf> {
    fs::read_dir(out.join("runs_aborted"))
        .map(|d| d.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default()
}

#[test]
fn a_linux_run_that_fails_after_a_frame_is_kept_under_runs_aborted() {
    let s = linux_setup(&["l01_auto", "l02_auto_multi"]);
    s.fake.scanner_hangs.set(true);
    // Longer than the 40 polls a dropped run grants, well inside the witness's own stop window.
    s.fake.witness_linger.set(500);
    let e = linux_with(&s.args, &s.fake, &s.lab).unwrap_err();
    assert!(
        matches!(e, SuiteError::Abort(_))
            && e.message().contains("ran longer than")
            && e.message().contains("runs_aborted/l01_auto."),
        "{e:?}"
    );
    // The scanner stops first, then the witness, which finishes its capture: nothing is killed.
    let sig = s.fake.signals.borrow().clone();
    let at = |x: &str| {
        sig.iter()
            .position(|y| y == x)
            .unwrap_or_else(|| panic!("{x} not in {sig:?}"))
    };
    assert!(at("scanner:INT") < at("witness:TERM"), "{sig:?}");
    assert!(!sig.iter().any(|x| x.ends_with(":KILL")), "{sig:?}");
    // The run is kept, hashed like a run; the work directory is gone, and the next case never started.
    let kept = aborted(&s.out);
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert!(
        kept[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("l01_auto.")
    );
    crate::macos_verify::hashes_match_tree(&kept[0], true).unwrap();
    for f in ["peer.pcap", "isolation.json", "argv.json", "expect.json"] {
        assert!(kept[0].join(f).is_file(), "{f}");
    }
    assert!(!s.out.join("runs/l01_auto").exists());
    assert_eq!(s.fake.runs(&s.fake.rmasscan.clone()), 1);
    assert_eq!(fs::read_dir(s.out.join(".work")).unwrap().count(), 1);
    // The verifier's safety walk reads the kept capture and finds nothing foreign in it.
    assert_eq!(av::verify_dir(&s.out)["safety_trips"], json!([]));
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn a_linux_failure_before_any_frame_leaves_nothing() {
    let s = linux_setup(&["l01_auto"]);
    s.fake.responder_silent.set(true);
    let e = linux_with(&s.args, &s.fake, &s.lab).unwrap_err();
    assert!(
        matches!(e, SuiteError::NotRun(_)) && e.message().contains("responder"),
        "{e:?}"
    );
    assert!(aborted(&s.out).is_empty() && !s.out.join("runs_aborted").exists());
    assert!(
        !s.fake
            .spawned
            .borrow()
            .iter()
            .any(|a| a.iter().any(|x| x == "dump")),
        "no witness"
    );
    assert_eq!(s.fake.runs(&s.fake.rmasscan.clone()), 0);
    assert_eq!(fs::read_dir(s.out.join(".work")).unwrap().count(), 1);
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn an_isolation_failure_after_the_run_is_an_abort_and_the_run_is_kept() {
    let s = linux_setup(&["l01_auto", "l02_auto_multi"]);
    s.fake.isolation_fails_at.set(2);
    let e = linux_with(&s.args, &s.fake, &s.lab).unwrap_err();
    assert!(
        matches!(e, SuiteError::Abort(_)) && e.message().contains("not sealed after the run"),
        "{e:?}"
    );
    let kept = aborted(&s.out);
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert!(kept[0].join("isolation.json").is_file() && kept[0].join("capture.json").is_file());
    assert!(!kept[0].join("isolation-post.json").exists());
    assert!(!s.out.join("runs/l01_auto").exists());
    assert_eq!(s.fake.runs(&s.fake.rmasscan.clone()), 1, "no further run");
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn another_build_never_extends_a_directory_and_a_replaced_binary_stops_the_next_run() {
    // A binary replaced while the suite runs stops it before the next case.
    let s = linux_setup(&["l01_auto", "l02_auto_multi"]);
    let oracle = PathBuf::from(&s.fake.oracle);
    *s.fake.replace_on_scan.borrow_mut() = Some(oracle.clone());
    let e = linux_with(&s.args, &s.fake, &s.lab).unwrap_err();
    assert!(
        matches!(e, SuiteError::NotRun(_)) && e.message().contains("masscan changed"),
        "{e:?}"
    );
    assert!(s.out.join("runs/l01_auto").is_dir() && !s.out.join("runs/l02_auto_multi").exists());
    assert_eq!(s.fake.runs(&s.fake.rmasscan.clone()), 1);
    // That directory is never extended by another oracle, rmasscan-lab or rmasscan build.
    *s.fake.replace_on_scan.borrow_mut() = None;
    let mut args = s.args.clone();
    set_arg(&mut args, "--only", "l02_auto_multi");
    let before = s.fake.execs.borrow().len() + s.fake.spawned.borrow().len();
    let e = linux_with(&args, &s.fake, &s.lab).unwrap_err();
    assert!(
        matches!(e, SuiteError::NotRun(_)) && e.message().contains("oracle"),
        "{e:?}"
    );
    fs::write(&oracle, "masscan").unwrap();
    fs::write(&s.lab, "another lab build").unwrap();
    let e = linux_with(&args, &s.fake, &s.lab).unwrap_err();
    assert!(
        matches!(e, SuiteError::NotRun(_)) && e.message().contains("lab"),
        "{e:?}"
    );
    assert_eq!(
        s.fake.execs.borrow().len() + s.fake.spawned.borrow().len(),
        before,
        "nothing started"
    );
    // The same builds extend it.
    fs::write(&s.lab, "lab").unwrap();
    assert_eq!(linux_with(&args, &s.fake, &s.lab).unwrap(), 0);
    assert!(s.out.join("runs/l02_auto_multi").is_dir());
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn a_committed_macos_status_file_passes_the_verifiers_privacy_scan() {
    // The status the stand printed in the committed BPF acceptance: the LAN gateway and the stand MACs in it.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../../docs/experiments/2026-10-25-rmasscan-macos-bpf-acceptance-raw/macos-live/status-pre.json",
    );
    let status = fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let text = String::from_utf8_lossy(&status);
    assert!(text.contains("\"gateway\": \"192.168.1.1\"") && text.contains("02:ac:00:00:00:01"));
    // A consistent m02 run whose statuses are that file, written and hashed by the suite's own writer.
    let root = scratch();
    let work = root.join("work");
    for (name, bytes) in Sim::new(Plan::Macos, "m02_user_explicit").files() {
        let to = work.join(&name);
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        let real = matches!(name.as_str(), "status-pre.json" | "status-post.json");
        fs::write(to, if real { status.clone() } else { bytes }).unwrap();
    }
    hash_and_copy(&work, &root.join("runs/m02_user_explicit")).unwrap();
    fs::write(
        root.join("manifest.json"),
        json!({"autodetect": "macos"}).to_string(),
    )
    .unwrap();
    let res = av::verify_dir(&root);
    let run = res["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["tag"] == "m02_user_explicit")
        .unwrap();
    let privacy: Vec<&Value> = run["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["name"].as_str().is_some_and(|n| n.starts_with("privacy")))
        .collect();
    assert_eq!(privacy.len(), 1, "{privacy:#?}");
    assert_eq!(
        privacy[0]["name"],
        "privacy: every text file holds only allowlisted names, addresses and paths"
    );
    assert_eq!(privacy[0]["result"], "PASS", "{privacy:#?}");
    assert_eq!(run["verdict"], "PASS", "{:#?}", bad(&res));
    fs::remove_dir_all(root).unwrap();
}

// ------------------------------------------------------------------ macOS (the seam is macos_suite::Stand)

#[cfg(target_os = "macos")]
#[test]
fn a_macos_suite_directory_passes_autodetect_verify() {
    mac::user_and_root_directories_pass();
}

#[cfg(target_os = "macos")]
#[test]
fn a_lab_frame_on_the_uplink_stops_the_macos_suite_with_13() {
    mac::uplink_frame_is_an_isolation_stop();
}

#[cfg(target_os = "macos")]
#[test]
fn a_second_suite_is_refused_while_macos_suites_lock_is_held() {
    mac::the_lock_keeps_one_suite_on_the_stand();
}

#[cfg(target_os = "macos")]
mod mac {
    use super::*;
    use crate::{
        dump::NetstatCounters,
        macos_suite::{FloodSpec, InjectSpec, LinkState, Proc, Side, Stand, take_lock},
    };

    /// Every scripted process leads this process group; the suite records it in the lock.
    const PGID: u32 = 4242;

    struct FakeProc {
        rc: Option<i32>,
        on_stop: Option<Box<dyn FnOnce() -> i32>>,
    }
    impl Proc for FakeProc {
        fn try_wait(&mut self) -> Result<Option<i32>, String> {
            Ok(self.rc)
        }
        fn pgid(&self) -> Option<u32> {
            Some(PGID)
        }
        fn signal(&mut self, _sig: &str) {
            if self.rc.is_none() {
                self.rc = Some(self.on_stop.take().map_or(0, |f| f()));
            }
        }
        fn kill(&mut self) {
            self.rc.get_or_insert(-9);
        }
    }

    /// The feth stand as the suite sees it, played from the generator's runs of one plan. Its peer witness hears
    /// the host's own mDNS (IPv4 and IPv6) in every run, as the real one would.
    pub(super) struct FakeMac {
        plan: Plan,
        sims: BTreeMap<&'static str, Sim>,
        rmasscan: String,
        pub(super) euid: Cell<u32>,
        current: RefCell<&'static str>,
        pub(super) spawned: RefCell<Vec<Vec<String>>>,
        pub(super) execs: RefCell<Vec<Vec<String>>>,
        /// Frames the uplink tcpdump stores (a lab frame on the user's LAN).
        pub(super) uplink_frames: Cell<usize>,
        /// What the `--offline` preflight prints instead of the generator's text (`rc N` first).
        pub(super) preflight: RefCell<Option<String>>,
        /// Extra `ps` lines (leftover processes).
        pub(super) ps: RefCell<String>,
        /// The lock file, read when rmasscan starts.
        pub(super) lock_file: RefCell<Option<PathBuf>>,
        pub(super) lock_at_scanner: RefCell<String>,
    }
    impl FakeMac {
        pub(super) fn new(plan: Plan, rmasscan: &Path) -> Self {
            FakeMac {
                plan,
                sims: av::planned_tags(plan)
                    .into_iter()
                    .map(|t| (t, Sim::new(plan, t)))
                    .collect(),
                rmasscan: p2s(rmasscan),
                euid: Cell::new(if plan == Plan::MacosRoot { 0 } else { 501 }),
                current: RefCell::new(""),
                spawned: RefCell::default(),
                execs: RefCell::default(),
                uplink_frames: Cell::new(0),
                preflight: RefCell::default(),
                ps: RefCell::default(),
                lock_file: RefCell::default(),
                lock_at_scanner: RefCell::default(),
            }
        }
        fn note(&self, all: &[String]) {
            for tag in self.sims.keys() {
                if all.iter().any(|a| a.contains(&format!("/{tag}."))) {
                    *self.current.borrow_mut() = tag;
                }
            }
        }
        fn sim(&self) -> &Sim {
            &self.sims[*self.current.borrow()]
        }
        pub(super) fn scanner_runs(&self) -> usize {
            self.spawned
                .borrow()
                .iter()
                .chain(self.execs.borrow().iter())
                .filter(|a| a[0] == self.rmasscan && !a.iter().any(|x| x == "--offline"))
                .count()
        }
        pub(super) fn nothing_started(&self) -> bool {
            self.spawned.borrow().is_empty() && self.execs.borrow().is_empty()
        }
    }
    fn out(rc: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            rc,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }
    impl Stand for FakeMac {
        fn exec(&self, argv: &[String], _timeout: u64) -> Result<Output, String> {
            self.note(argv);
            self.execs.borrow_mut().push(argv.to_vec());
            if argv.iter().any(|a| a == "status") {
                let s = Sim::new(Plan::Macos, "m01_user_masked");
                return Ok(out(
                    0,
                    &String::from_utf8(file_of(&s, "status-pre.json")).unwrap(),
                    "",
                ));
            }
            if argv[0].ends_with("socketfilterfw") {
                return Ok(out(0, "Firewall is disabled. (State = 0)\n", ""));
            }
            if argv[0] == "/bin/ps" {
                let me = std::process::id();
                return Ok(out(
                    0,
                    &format!(
                        "  PID  PGID COMMAND\n{me} {me} /x/rmasscan-lab autodetect-suite macos\n{}",
                        self.ps.borrow()
                    ),
                    "",
                ));
            }
            if argv[0] == self.rmasscan && argv.iter().any(|a| a == "--offline") {
                let tag = self
                    .sims
                    .values()
                    .find(|s| {
                        preflight_argv(&av::case_spec(self.plan, s.case.tag).unwrap()) == argv[1..]
                    })
                    .map(|s| s.case.tag)
                    .expect("a preflight of a planned case");
                let text = self
                    .preflight
                    .borrow()
                    .clone()
                    .or_else(|| self.sims[tag].preflight.clone())
                    .unwrap();
                let (rc, rest) = text.split_once('\n').unwrap();
                return Ok(out(rc.trim_start_matches("rc ").parse().unwrap(), "", rest));
            }
            if argv[0] == self.rmasscan && argv.iter().any(|a| a == "--iflist") {
                let mac = if self.plan == Plan::Macos {
                    "masked"
                } else {
                    "02-ac-00-00-00-01"
                };
                return Ok(out(
                    0,
                    &full_iflist(&format!("feth4201 index=17 mac={mac} ipv4=- up ethernet")),
                    "",
                ));
            }
            Ok(out(0, "", ""))
        }
        fn spawn(
            &self,
            argv: &[String],
            stdout: &Path,
            stderr: &Path,
        ) -> Result<Box<dyn Proc>, String> {
            let mut all = argv.to_vec();
            all.push(p2s(stdout));
            self.note(&all);
            self.spawned.borrow_mut().push(argv.to_vec());
            fs::write(stdout, "").unwrap();
            fs::write(stderr, "").unwrap();
            let sim = self.sim();
            let running = |on_stop: Box<dyn FnOnce() -> i32>| -> Box<dyn Proc> {
                Box::new(FakeProc {
                    rc: None,
                    on_stop: Some(on_stop),
                })
            };
            if argv.iter().any(|a| a == "listen") {
                fs::write(
                    after(argv, "--ready"),
                    json!({"open":[8000,8001,8002,8003,8004,8005,8006,8007],"silent":[],"silent_proven":null,"ready":true,"bind":"198.18.0.2"}).to_string(),
                )
                .unwrap();
                return Ok(running(Box::new(|| 0)));
            }
            if argv[0] == "/usr/sbin/tcpdump" {
                fs::write(stderr, "tcpdump: listening on en0, link-type EN10MB (Ethernet), snapshot length 524288 bytes\n").unwrap();
                let (pcap_path, err) = (PathBuf::from(after(argv, "-w")), stderr.to_path_buf());
                let n = self.uplink_frames.get();
                let frames: pcap::Frames = (0..n)
                    .map(|k| (1.0 + k as f64, crate::macos_suite::flood_frame(k as u32)))
                    .collect();
                let text = String::from_utf8(file_of(sim, "uplink.err"))
                    .unwrap()
                    .replace("\n0 packets captured", &format!("\n{n} packets captured"));
                return Ok(running(Box::new(move || {
                    fs::write(&pcap_path, pcap::encode(&frames)).unwrap();
                    fs::write(&err, text).unwrap();
                    0
                })));
            }
            if argv.iter().any(|a| a == "dump") {
                fs::write(after(argv, "--ready"), "{\"tcpdump_pid\":1}\n").unwrap();
                fs::write(after(argv, "--ack"), "ack\n").unwrap();
                let (pcap_path, meta) = (
                    PathBuf::from(after(argv, "--pcap")),
                    PathBuf::from(after(argv, "--meta")),
                );
                // Every frame of the peer interface: the run's and the host's own mDNS announcements.
                let frames = with_mdns(&sim.peer);
                return Ok(running(Box::new(move || {
                    fs::write(&pcap_path, pcap::encode(&frames)).unwrap();
                    fs::write(&meta, Sim::witness(&frames)).unwrap();
                    fs::write(
                        format!("{}.tcpdump.err", pcap_path.display()),
                        format!("tcpdump: listening on feth4202, link-type EN10MB (Ethernet), snapshot length 524288 bytes\n{0} packets captured\n{0} packets received by filter\n0 packets dropped by kernel\n", frames.len()),
                    )
                    .unwrap();
                    0
                })));
            }
            if argv[0] == self.rmasscan {
                if let Some(l) = self.lock_file.borrow().as_ref() {
                    *self.lock_at_scanner.borrow_mut() = fs::read_to_string(l).unwrap_or_default();
                }
                fs::write(stdout, sim.stdout.clone().unwrap_or_default()).unwrap();
                fs::write(stderr, sim.stderr_text()).unwrap();
                return Ok(Box::new(FakeProc {
                    rc: Some(sim.exit),
                    on_stop: None,
                }));
            }
            Ok(Box::new(FakeProc {
                rc: Some(0),
                on_stop: None,
            }))
        }
        fn counters(&self, _iface: &str) -> Result<NetstatCounters, String> {
            Ok(NetstatCounters {
                ipkts: 10,
                opkts: 10,
                ierrs: 0,
                drop: 0,
            })
        }
        fn iface_mac(&self, iface: &str) -> Result<String, String> {
            Ok(if iface == "feth4201" {
                "02:ac:00:00:00:01"
            } else {
                "02:ac:00:00:00:02"
            }
            .into())
        }
        fn send_start_markers(&self) -> Result<(), String> {
            Ok(())
        }
        fn start_injector(&self, _spec: &InjectSpec) -> Result<Box<dyn Side>, String> {
            Err("no injector in the autodetect suite".into())
        }
        fn start_flood(&self, _spec: &FloodSpec) -> Result<Box<dyn Side>, String> {
            Err("no flood in the autodetect suite".into())
        }
        fn flood_burst_frames(&self) -> Result<u64, String> {
            Err("no flood in the autodetect suite".into())
        }
        fn link_state(&self) -> Result<LinkState, String> {
            Err("no link loss in the autodetect suite".into())
        }
        fn euid(&self) -> Result<u32, String> {
            Ok(self.euid.get())
        }
        fn provenance(&self, _repo: &Path) -> Value {
            panic!("the autodetect suite records the binaries' hashes, it runs no git")
        }
        fn pause(&self, _d: Duration) {}
        fn stopped(&self) -> bool {
            false
        }
    }

    pub(super) struct MacSetup {
        pub(super) root: PathBuf,
        pub(super) out: PathBuf,
        pub(super) exe: PathBuf,
        /// macos-suite's lock file of this scratch (its directory does not exist before the suite).
        pub(super) lock: PathBuf,
        pub(super) fake: FakeMac,
        pub(super) args: Vec<String>,
    }
    pub(super) fn setup(plan: Plan, only: &[&str]) -> MacSetup {
        let root = scratch();
        let out = root.join(if plan == Plan::MacosRoot {
            "macos-root-r1"
        } else {
            "macos-r1"
        });
        let (exe, rm) = (root.join("rmasscan-lab"), root.join("rmasscan"));
        fs::write(&exe, "lab").unwrap();
        fs::write(&rm, "rmasscan").unwrap();
        let mut args = strings(&[
            "--out",
            out.to_str().unwrap(),
            "--rmasscan",
            rm.to_str().unwrap(),
            "--lab",
            exe.to_str().unwrap(),
        ]);
        if plan == Plan::MacosRoot {
            args.push("--root-case".into());
        }
        if !only.is_empty() {
            args.push("--only".into());
            args.extend(strings(only));
        }
        let fake = FakeMac::new(plan, &rm);
        MacSetup {
            lock: root.join("lockdir").join("macos-suite.lock"),
            root,
            out,
            exe,
            fake,
            args,
        }
    }
    /// The suite of `s` with `args`, its lock in the scratch.
    pub(super) fn run(
        s: &MacSetup,
        args: &[String],
        sudo: Option<&str>,
    ) -> Result<i32, SuiteError> {
        macos_with(args, &s.fake, &s.exe, sudo, &|| Ok(s.lock.clone()))
    }
    /// No file under `out` keeps the unfiltered capture or the host name.
    fn no_host_data(out: &Path) {
        for f in crate::macos_verify::relative_files(out) {
            assert!(!f.ends_with(".unfiltered"), "{f} left behind");
            assert!(
                !holds(&fs::read(out.join(&f)).unwrap(), HOST),
                "{f} names the host"
            );
        }
    }

    pub(super) fn user_and_root_directories_pass() {
        let s = setup(Plan::Macos, &[]);
        assert_eq!(run(&s, &s.args, None).unwrap(), 0);
        let res = av::verify_dir(&s.out);
        assert_eq!(res["overall"], "PASS", "{:#?}", bad(&res));
        assert_eq!(
            read_json(s.out.join("manifest.json")).unwrap()["autodetect"],
            "macos"
        );
        // m05 ran its preflight first; every case ran rmasscan once (m07 --iflist).
        assert_eq!(s.fake.scanner_runs(), 7);
        assert!(
            s.out
                .join("runs/m05_user_no_adapter/preflight.txt")
                .is_file()
        );
        // Every published peer capture left out the host's two mDNS frames and says so.
        for tag in av::planned_tags(Plan::Macos) {
            let rec = read_json(s.out.join("runs").join(tag).join(CAPTURE_JSON)).unwrap();
            assert_eq!(rec["privacy_filter"]["frames_dropped"], 2, "{tag}");
        }
        no_host_data(&s.out);
        // The user window never hands anything to anyone, and its lock is gone.
        assert!(!s.fake.execs.borrow().iter().any(|a| a[0] == CHOWN));
        assert!(!s.out.join(".work").exists());
        assert!(!s.lock.exists());
        fs::remove_dir_all(&s.root).unwrap();

        let s = setup(Plan::MacosRoot, &[]);
        assert_eq!(run(&s, &s.args, Some("alice")).unwrap(), 0);
        let res = av::verify_dir(&s.out);
        assert_eq!(res["overall"], "PASS", "{:#?}", bad(&res));
        assert_eq!(
            read_json(s.out.join("manifest.json")).unwrap()["autodetect"],
            "macos-root"
        );
        no_host_data(&s.out);
        // At the end the directory goes back to the user who ran sudo, and so does the lock directory this root
        // case created.
        let execs = s.fake.execs.borrow();
        let n = execs.len();
        assert_eq!(
            execs[n - 2],
            strings(&[CHOWN, "-R", "alice", s.out.to_str().unwrap()])
        );
        assert_eq!(
            execs[n - 1],
            strings(&[
                CHOWN,
                "-h",
                "alice",
                s.lock.parent().unwrap().to_str().unwrap()
            ])
        );
        drop(execs);
        fs::remove_dir_all(&s.root).unwrap();
    }

    pub(super) fn root_rules_refuse_before_anything_starts() {
        // User window as root.
        let s = setup(Plan::Macos, &[]);
        s.fake.euid.set(0);
        let e = run(&s, &s.args, Some("alice")).unwrap_err();
        assert!(matches!(e, SuiteError::NotRun(_)), "{e:?}");
        assert!(s.fake.nothing_started());
        assert!(!s.out.exists() && !s.lock.exists());
        fs::remove_dir_all(&s.root).unwrap();
        // Root case as the user, root case without $SUDO_USER (or as root's own), a user case under --root-case.
        for (euid, sudo, only) in [
            (501, Some("alice"), None),
            (0, None, None),
            (0, Some("root"), None),
            (0, Some("alice"), Some("m02_user_explicit")),
        ] {
            let s = setup(Plan::MacosRoot, only.as_slice());
            s.fake.euid.set(euid);
            let e = run(&s, &s.args, sudo).unwrap_err();
            assert!(
                matches!(e, SuiteError::NotRun(_)),
                "{euid} {sudo:?} {only:?}: {e:?}"
            );
            assert!(s.fake.nothing_started(), "{euid} {sudo:?} {only:?}");
            fs::remove_dir_all(&s.root).unwrap();
        }
        // --lab must be the running binary.
        let s = setup(Plan::Macos, &[]);
        let other = s.root.join("other-lab");
        fs::write(&other, "another build").unwrap();
        let mut args = s.args.clone();
        set_arg(&mut args, "--lab", other.to_str().unwrap());
        assert!(matches!(run(&s, &args, None), Err(SuiteError::NotRun(_))));
        assert!(s.fake.nothing_started());
        fs::remove_dir_all(&s.root).unwrap();
    }

    pub(super) fn a_live_rmasscan_refuses_the_run() {
        let s = setup(Plan::Macos, &["m02_user_explicit"]);
        *s.fake.ps.borrow_mut() = "6001  6001 /opt/x/rmasscan 198.18.0.2 -p8000\n".into();
        let e = run(&s, &s.args, None).unwrap_err();
        assert!(
            matches!(e, SuiteError::NotRun(_)) && e.message().contains("still alive"),
            "{e:?}"
        );
        assert!(s.fake.spawned.borrow().is_empty());
        assert_eq!(s.fake.scanner_runs(), 0);
        fs::remove_dir_all(&s.root).unwrap();
    }

    pub(super) fn the_peer_capture_is_published_without_the_hosts_mdns() {
        let s = setup(Plan::Macos, &["m02_user_explicit"]);
        assert_eq!(run(&s, &s.args, None).unwrap(), 0);
        let spawned = s.fake.spawned.borrow();
        // The witness records every frame (no filter) into the private work directory, never the run directory.
        let dumps: Vec<&Vec<String>> = spawned
            .iter()
            .filter(|a| a.iter().any(|x| x == "dump"))
            .collect();
        assert_eq!(dumps.len(), 1);
        assert_eq!(after(dumps[0], "--iface"), "feth4202");
        assert!(
            !dumps[0]
                .iter()
                .any(|a| a == "--filter" || a.contains("5353"))
        );
        let unfiltered = Path::new(after(dumps[0], "--pcap"));
        assert_eq!(unfiltered.file_name().unwrap(), "peer.unfiltered");
        let base = unfiltered.parent().unwrap();
        assert_eq!(
            after(dumps[0], "--meta"),
            p2s(&base.join("peer-witness.json"))
        );
        assert_eq!(
            witness_files(base, &base.join("run")).peer_pcap,
            unfiltered,
            "the suite's own layout"
        );
        // The published capture is the run's frames exactly; the record says what was left out.
        let run_dir = s.out.join("runs/m02_user_explicit");
        let sim = Sim::new(Plan::Macos, "m02_user_explicit");
        assert_eq!(
            fs::read(run_dir.join(PEER_PCAP)).unwrap(),
            pcap::encode(&sim.peer)
        );
        let rec = read_json(run_dir.join(CAPTURE_JSON)).unwrap();
        assert_eq!(rec["privacy_filter"]["frames_dropped"], 2);
        assert_eq!(rec["pcap_frames"], sim.peer.len());
        assert_eq!(rec["unfiltered"]["pcap_frames"], sim.peer.len() + 2);
        no_host_data(&s.out);
        // The listeners open the stand's ports; the uplink witness carries the lab filter, not promiscuous.
        let listen = spawned
            .iter()
            .find(|a| a.iter().any(|x| x == "listen"))
            .unwrap();
        assert_eq!(after(listen, "--open"), open_ports());
        assert_eq!(open_ports(), "8000-8007");
        let up = spawned
            .iter()
            .find(|a| a[0] == "/usr/sbin/tcpdump")
            .unwrap();
        assert_eq!(up.last().unwrap(), crate::macos_lab::UPLINK_FILTER);
        assert_eq!(after(up, "-i"), "en0");
        assert!(up.contains(&"-p".to_owned()));
        drop(spawned);
        fs::remove_dir_all(&s.root).unwrap();
    }

    pub(super) fn a_preflight_that_does_not_show_the_refusal_is_not_run() {
        let s = setup(Plan::Macos, &["m05_user_no_adapter"]);
        *s.fake.preflight.borrow_mut() =
            Some("rc 0\n[+] interface = feth4201 (detected: route to 198.18.0.2)\n".into());
        let e = run(&s, &s.args, None).unwrap_err();
        assert!(matches!(e, SuiteError::NotRun(_)), "{e:?}");
        assert_eq!(s.fake.scanner_runs(), 0, "the live case never started");
        assert!(
            s.fake.spawned.borrow().is_empty(),
            "no listener, witness or scanner"
        );
        assert!(!s.out.join("runs/m05_user_no_adapter").exists());
        fs::remove_dir_all(&s.root).unwrap();
    }

    pub(super) fn uplink_frame_is_an_isolation_stop() {
        let s = setup(Plan::Macos, &["m01_user_masked", "m02_user_explicit"]);
        s.fake.uplink_frames.set(1);
        let e = run(&s, &s.args, None).unwrap_err();
        assert!(matches!(e, SuiteError::Isolation(_)), "{e:?}");
        assert_eq!(e.code(), 13);
        assert_eq!(s.fake.scanner_runs(), 1, "no further run after the breach");
        let aborted: Vec<String> = fs::read_dir(s.out.join("runs_aborted"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            aborted.len() == 1 && aborted[0].starts_with("m01_user_masked."),
            "{aborted:?}"
        );
        assert!(!s.out.join("runs/m01_user_masked").exists());
        // The kept run has its published peer capture; the unfiltered one is gone on this path too.
        assert!(
            s.out
                .join("runs_aborted")
                .join(&aborted[0])
                .join(PEER_PCAP)
                .is_file()
        );
        no_host_data(&s.out);
        // The directory is FAIL for good and cannot be extended.
        assert_eq!(av::verify_dir(&s.out)["overall"], "FAIL");
        let again = setup(Plan::Macos, &["m02_user_explicit"]);
        let mut args = again.args.clone();
        set_arg(&mut args, "--out", s.out.to_str().unwrap());
        assert!(matches!(
            run(&again, &args, None),
            Err(SuiteError::Isolation(_))
        ));
        assert!(again.fake.spawned.borrow().is_empty());
        fs::remove_dir_all(&s.root).unwrap();
        fs::remove_dir_all(&again.root).unwrap();
    }

    pub(super) fn the_lock_keeps_one_suite_on_the_stand() {
        let s = setup(Plan::Macos, &["m01_user_masked"]);
        // Another suite holds macos-suite's lock: nothing starts and nothing is written.
        let held = take_lock(&s.lock).unwrap();
        let e = run(&s, &s.args, None).unwrap_err();
        assert!(
            matches!(e, SuiteError::NotRun(_)) && e.message().contains("one suite at a time"),
            "{e:?}"
        );
        assert!(s.fake.nothing_started() && !s.out.exists());
        drop(held);
        // Free again: the live children's process group is in the lock while rmasscan runs; the lock goes after.
        *s.fake.lock_file.borrow_mut() = Some(s.lock.clone());
        assert_eq!(run(&s, &s.args, None).unwrap(), 0);
        assert!(
            s.fake
                .lock_at_scanner
                .borrow()
                .contains(&format!("children={PGID}")),
            "{}",
            s.fake.lock_at_scanner.borrow()
        );
        assert!(!s.lock.exists());
        // The directory is never extended under another stand run id.
        let mut args = s.args.clone();
        set_arg(&mut args, "--only", "m02_user_explicit");
        args.extend(strings(&["--run-id", "m2"]));
        let before = s.fake.execs.borrow().len() + s.fake.spawned.borrow().len();
        let e = run(&s, &args, None).unwrap_err();
        assert!(
            matches!(e, SuiteError::NotRun(_)) && e.message().contains("run_id"),
            "{e:?}"
        );
        assert_eq!(
            s.fake.execs.borrow().len() + s.fake.spawned.borrow().len(),
            before
        );
        fs::remove_dir_all(&s.root).unwrap();
    }
}
