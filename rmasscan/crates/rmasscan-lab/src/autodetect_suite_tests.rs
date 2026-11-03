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
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

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

// ------------------------------------------------------------------ a recording Linux host

/// A scripted process: it exits at once with `rc`, or runs until signalled, then runs `on_stop` (the witness
/// finalising its capture) and exits with what that returns.
struct FakeRun {
    rc: Option<i32>,
    on_stop: Option<Box<dyn FnOnce() -> i32>>,
    name: String,
    signals: Rc<RefCell<Vec<String>>>,
}
impl Running for FakeRun {
    fn try_wait(&mut self) -> Result<Option<i32>, String> {
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
            fs::write(after(argv, "--ready"), "listening 80,8080\n").unwrap();
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
    use crate::{dump, macos_verify::PEER_FILTER};
    assert_eq!(
        PEER_FILTER,
        "not (ether src 02:ac:00:00:00:02 and udp port 5353)"
    );
    // `capture dump --filter` takes exactly the privacy filter on the macOS peer interface, and nothing else.
    assert!(dump::witness_filter_allowed("feth4202", PEER_FILTER, true));
    for (iface, filter, macos) in [
        ("feth4202", PEER_FILTER, false),
        ("feth4201", PEER_FILTER, true),
        ("veth-b", PEER_FILTER, true),
        ("feth4202", "not arp", true),
        ("feth4202", "", true),
        (
            "feth4202",
            "not (ether src 02:ac:00:00:00:02 and udp port 5353) or tcp",
            true,
        ),
    ] {
        assert!(
            !dump::witness_filter_allowed(iface, filter, macos),
            "{iface} {filter:?} {macos}"
        );
    }
    let argv = dump::tcpdump_argv_macos("feth4202", "/w/peer.pcap", Some(PEER_FILTER));
    assert_eq!(argv.last().map(String::as_str), Some(PEER_FILTER));
    #[cfg(target_os = "macos")]
    mac::the_witness_carries_the_privacy_filter();
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
mod mac {
    use super::*;
    use crate::{
        dump::NetstatCounters,
        macos_suite::{FloodSpec, InjectSpec, LinkState, Proc, Side, Stand},
        macos_verify::PEER_FILTER,
    };
    use std::cell::Cell;

    struct FakeProc {
        rc: Option<i32>,
        on_stop: Option<Box<dyn FnOnce() -> i32>>,
    }
    impl Proc for FakeProc {
        fn try_wait(&mut self) -> Result<Option<i32>, String> {
            Ok(self.rc)
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

    /// The feth stand as the suite sees it, played from the generator's runs of one plan.
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
                let frames = sim.peer.clone();
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
            root,
            out,
            exe,
            fake,
            args,
        }
    }

    pub(super) fn user_and_root_directories_pass() {
        let s = setup(Plan::Macos, &[]);
        assert_eq!(macos_with(&s.args, &s.fake, &s.exe, None).unwrap(), 0);
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
        // The user window never hands the directory to anyone.
        assert!(!s.fake.execs.borrow().iter().any(|a| a[0] == CHOWN));
        assert!(!s.out.join(".work").exists());
        fs::remove_dir_all(&s.root).unwrap();

        let s = setup(Plan::MacosRoot, &[]);
        assert_eq!(
            macos_with(&s.args, &s.fake, &s.exe, Some("alice")).unwrap(),
            0
        );
        let res = av::verify_dir(&s.out);
        assert_eq!(res["overall"], "PASS", "{:#?}", bad(&res));
        assert_eq!(
            read_json(s.out.join("manifest.json")).unwrap()["autodetect"],
            "macos-root"
        );
        // At the end the whole directory goes back to the user who ran sudo.
        let execs = s.fake.execs.borrow();
        let last = execs.last().unwrap();
        assert_eq!(
            *last,
            strings(&[CHOWN, "-R", "alice", s.out.to_str().unwrap()])
        );
        drop(execs);
        fs::remove_dir_all(&s.root).unwrap();
    }

    pub(super) fn root_rules_refuse_before_anything_starts() {
        // User window as root.
        let s = setup(Plan::Macos, &[]);
        s.fake.euid.set(0);
        let e = macos_with(&s.args, &s.fake, &s.exe, Some("alice")).unwrap_err();
        assert!(matches!(e, SuiteError::NotRun(_)), "{e:?}");
        assert!(s.fake.nothing_started());
        assert!(!s.out.exists());
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
            let e = macos_with(&s.args, &s.fake, &s.exe, sudo).unwrap_err();
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
        assert!(matches!(
            macos_with(&args, &s.fake, &s.exe, None),
            Err(SuiteError::NotRun(_))
        ));
        assert!(s.fake.nothing_started());
        fs::remove_dir_all(&s.root).unwrap();
    }

    pub(super) fn a_live_rmasscan_refuses_the_run() {
        let s = setup(Plan::Macos, &["m02_user_explicit"]);
        *s.fake.ps.borrow_mut() = "6001  6001 /opt/x/rmasscan 198.18.0.2 -p8000\n".into();
        let e = macos_with(&s.args, &s.fake, &s.exe, None).unwrap_err();
        assert!(
            matches!(e, SuiteError::NotRun(_)) && e.message().contains("still alive"),
            "{e:?}"
        );
        assert!(s.fake.spawned.borrow().is_empty());
        assert_eq!(s.fake.scanner_runs(), 0);
        fs::remove_dir_all(&s.root).unwrap();
    }

    pub(super) fn the_witness_carries_the_privacy_filter() {
        let w = macos_witness_argv("/x/rmasscan-lab", Path::new("/w/run"), Path::new("/w"));
        assert_eq!(after(&w, "--iface"), "feth4202");
        assert_eq!(after(&w, "--filter"), PEER_FILTER);
        assert_eq!(after(&w, "--pcap"), "/w/run/peer.pcap");
        let s = setup(Plan::Macos, &["m07_user_iflist"]);
        assert_eq!(macos_with(&s.args, &s.fake, &s.exe, None).unwrap(), 0);
        let spawned = s.fake.spawned.borrow();
        let dumps: Vec<&Vec<String>> = spawned
            .iter()
            .filter(|a| a.iter().any(|x| x == "dump"))
            .collect();
        assert_eq!(dumps.len(), 1);
        assert_eq!(after(dumps[0], "--filter"), PEER_FILTER);
        assert_eq!(after(dumps[0], "--iface"), "feth4202");
        // The uplink witness carries the lab filter, on the uplink, not promiscuous.
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
        let e = macos_with(&s.args, &s.fake, &s.exe, None).unwrap_err();
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
        let e = macos_with(&s.args, &s.fake, &s.exe, None).unwrap_err();
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
        // The directory is FAIL for good and cannot be extended.
        assert_eq!(av::verify_dir(&s.out)["overall"], "FAIL");
        let again = setup(Plan::Macos, &["m02_user_explicit"]);
        let mut args = again.args.clone();
        set_arg(&mut args, "--out", s.out.to_str().unwrap());
        assert!(matches!(
            macos_with(&args, &again.fake, &again.exe, None),
            Err(SuiteError::Isolation(_))
        ));
        assert!(again.fake.spawned.borrow().is_empty());
        fs::remove_dir_all(&s.root).unwrap();
        fs::remove_dir_all(&again.root).unwrap();
    }
}
