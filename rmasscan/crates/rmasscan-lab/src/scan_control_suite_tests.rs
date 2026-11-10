//! The scan-control suite against a recording host: nothing here opens an interface, runs a process or writes a frame.
//! The scanners' outputs, exits and captures come from the verifier's synthetic generator
//! (`scan_control_verify::tests::Sim`); the suite writes the evidence directory itself and `scan-control-verify` judges
//! it, so the layout the suite writes and the layout the verifier reads are tested against each other.
use super::*;
use crate::{
    autodetect_suite::{IP, Running, UNSHARE},
    autodetect_verify::{
        self as av,
        tests::{LAB_ID, Sim as AdSim, TEARDOWN},
    },
    pcap,
    scan_control_verify::tests::{Sim, sc_isolation},
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
    let d = std::env::temp_dir().join(format!("rml-sc-suite-{}", nonce()));
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

/// A scripted process: it exits with `rc` at once, or runs until signalled (`on_stop` then gives its exit code;
/// `ignores_int` keeps it running through SIGINT).
struct FakeRun {
    rc: Option<i32>,
    on_stop: Option<Box<dyn FnOnce() -> i32>>,
    ignores_int: bool,
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
        if self.rc.is_none() && !(self.ignores_int && sig == "INT") {
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

/// The netns stand as the suite sees it, played from the generator's cases.
struct FakeSc {
    sims: BTreeMap<&'static str, Sim>,
    rmasscan: String,
    oracle: String,
    euid: u32,
    current: RefCell<&'static str>,
    spawned: RefCell<Vec<Vec<String>>>,
    execs: RefCell<Vec<Vec<String>>>,
    /// Everything the suite did, in order: `exec ...`, `start ...`, `signal ...`.
    log: Rc<RefCell<Vec<String>>>,
    ignores_int: Cell<bool>,
    /// `tc` exits with this.
    tc_rc: Cell<i32>,
    /// The clock of an interrupted step: the generator's moment of the signal, then 0.1 s later per reading.
    clock: Cell<(f64, u32)>,
    /// The files in each scanner's working directory when it started.
    cwd_files: RefCell<Vec<(String, String, Vec<String>)>>,
    stop_after_int: Cell<bool>,
}
impl FakeSc {
    fn new(tags: &[&'static str], rmasscan: &Path, oracle: &Path) -> Self {
        FakeSc {
            sims: tags.iter().map(|t| (*t, Sim::new(t))).collect(),
            rmasscan: p2s(rmasscan),
            oracle: p2s(oracle),
            euid: 0,
            current: RefCell::new(""),
            spawned: RefCell::default(),
            execs: RefCell::default(),
            log: Rc::default(),
            ignores_int: Cell::new(false),
            tc_rc: Cell::new(0),
            clock: Cell::new((0.0, 0)),
            cwd_files: RefCell::default(),
            stop_after_int: Cell::new(false),
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
    fn sim(&self) -> &Sim {
        &self.sims[*self.current.borrow()]
    }
    fn proc(
        &self,
        name: &str,
        rc: Option<i32>,
        on_stop: Option<Box<dyn FnOnce() -> i32>>,
        ignores_int: bool,
    ) -> Box<dyn Running> {
        self.log.borrow_mut().push(format!("start {name}"));
        Box::new(FakeRun {
            rc,
            on_stop,
            ignores_int,
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
}
impl LinuxHost for FakeSc {
    fn exec(&self, argv: &[String], _timeout: u64) -> Result<Output, String> {
        self.note(argv, &[]);
        self.execs.borrow_mut().push(argv.to_vec());
        self.log.borrow_mut().push(format!(
            "exec {}",
            argv.iter().skip(4).cloned().collect::<Vec<_>>().join(" ")
        ));
        if argv.iter().any(|a| a == "isolation") {
            fs::write(after(argv, "--out"), sc_isolation()).unwrap();
        }
        let tc = argv.iter().any(|a| a == TC);
        Ok(Output {
            rc: if tc { self.tc_rc.get() } else { 0 },
            stdout: String::new(),
            stderr: if tc && self.tc_rc.get() != 0 {
                "RTNETLINK answers: Operation not supported".into()
            } else {
                String::new()
            },
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
        let sim = self.sim();
        if argv.iter().any(|a| a == "responder") {
            fs::write(after(argv, "--ready"), "listening 80,8080\n").unwrap();
            return Ok(self.proc("responder", None, None, false));
        }
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
            let link = usize::from(pcap_path.ends_with("peer2.pcap"));
            let frames = step.links[link].clone();
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
            return Ok(self.proc(
                if link == 0 { "witness" } else { "witness2" },
                None,
                Some(Box::new(stop)),
                false,
            ));
        }
        let who = if argv.contains(&self.oracle) {
            Who::Oracle
        } else if argv.contains(&self.rmasscan) {
            Who::Rmasscan
        } else {
            return Ok(self.proc("other", Some(0), None, false));
        };
        // `ip netns exec NS /bin/sh -c SCRIPT DIR program ...`: the scanner's working directory.
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
        let mut names: Vec<String> = fs::read_dir(&cwd)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        self.cwd_files
            .borrow_mut()
            .push((step.spec.name.into(), format!("{who:?}"), names));
        fs::write(stdout, &step.stdout).unwrap();
        fs::write(stderr, &step.stderr).unwrap();
        for (evidence, bytes) in &step.files {
            let name = step
                .spec
                .collect
                .iter()
                .find(|c| c.1 == evidence)
                .map_or(evidence.as_str(), |c| c.0);
            fs::write(cwd.join(name), bytes).unwrap();
        }
        let rc = step.exit;
        if let Some(i) = &step.interrupt
            && who == Who::Rmasscan
        {
            self.clock.set((i.signal_unix.unwrap_or(0.0), 0));
            return Ok(self.proc(
                "scanner",
                None,
                Some(Box::new(move || rc)),
                self.ignores_int.get(),
            ));
        }
        Ok(self.proc(
            if who == Who::Oracle {
                "oracle"
            } else {
                "scanner"
            },
            Some(rc),
            None,
            false,
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
        self.stop_after_int.get() && self.log.borrow().iter().any(|x| x == "signal scanner:INT")
    }
    fn now(&self) -> f64 {
        let (base, n) = self.clock.get();
        self.clock.set((base, n + 1));
        base + 0.1 * f64::from(n)
    }
}

struct Setup {
    root: PathBuf,
    out: PathBuf,
    lab: PathBuf,
    fake: FakeSc,
    args: Vec<String>,
}
fn setup(tags: &[&'static str]) -> Setup {
    let root = scratch();
    let out = root.join("linux-scan-control-r1");
    let work = out.join(".work");
    fs::create_dir_all(&work).unwrap();
    fs::write(work.join("host-links-before.txt"), "eno1\nlo\n").unwrap();
    fs::write(out.join(ISOLATION_JSON), sc_isolation()).unwrap();
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
    if tags.len() < sv::planned_tags().len() {
        args.push("--only".into());
        args.extend(tags.iter().map(|t| (*t).to_owned()));
    }
    let fake = FakeSc::new(tags, &rm, &oracle);
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
/// The directory as `wire-lab.sh` leaves it after a clean teardown.
fn teardown(s: &Setup) {
    fs::write(s.out.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
}
fn not_run_text(r: Result<i32, SuiteError>) -> String {
    match r {
        Err(SuiteError::NotRun(m)) => m,
        other => panic!("not a NOT RUN: {other:?}"),
    }
}

// ------------------------------------------------------------------ the whole pipeline

#[test]
fn the_suite_writes_what_the_verifier_reads_for_every_case() {
    let s = setup(&sv::planned_tags());
    assert_eq!(run_suite(&s).unwrap(), 0);
    teardown(&s);
    let res = sv::verify_dir(&s.out);
    assert_eq!(res["overall"], PASS, "{:#?}", bad(&res));
    for tag in sv::TAGS {
        let d = s.out.join("runs").join(tag);
        assert!(d.join("hashes-before-copy.txt").is_file(), "{tag}");
        for step in sv::steps(tag).unwrap() {
            for f in [
                "argv.json",
                "stdout.txt",
                "stderr.txt",
                "exit.txt",
                "peer.pcap",
                "capture.json",
                "peer.err",
            ] {
                assert!(
                    d.join(step.name).join(f).is_file(),
                    "{tag}/{} {f}",
                    step.name
                );
            }
            assert_eq!(
                d.join(step.name).join("peer2.pcap").is_file(),
                step.links == 2,
                "{tag}/{}",
                step.name
            );
            assert_eq!(
                d.join(step.name).join("interrupt.json").is_file(),
                step.interrupt_after_s.is_some()
            );
            assert_eq!(d.join(step.name).join("netem.json").is_file(), step.netem);
        }
    }
    // the manifest binds the plan and the lab
    let m = crate::windows_suite::read_json(s.out.join(MANIFEST_JSON_NAME)).unwrap();
    assert_eq!(m["scan-control"], "linux");
    assert_eq!(m["lab_id"], LAB_ID);
    // the work directory holds nothing of the cases any more
    let left: Vec<_> = fs::read_dir(s.out.join(".work"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(
        left.iter().all(|n| n == "host-links-before.txt"),
        "{left:?}"
    );
    fs::remove_dir_all(s.root).unwrap();
}
const MANIFEST_JSON_NAME: &str = "manifest.json";

// ------------------------------------------------------------------ argv construction

#[test]
fn every_scanner_runs_the_tables_argv_in_its_groups_directory_inside_the_sealed_namespace() {
    let s = setup(&sv::planned_tags());
    run_suite(&s).unwrap();
    let rm = s.fake.scans(&s.fake.rmasscan);
    let or = s.fake.scans(&s.fake.oracle);
    // rmasscan: ip netns exec NS_A /bin/sh -c SCRIPT CWD rmasscan <argv>
    let want: Vec<(String, Vec<String>)> = sv::TAGS
        .iter()
        .flat_map(|t| sv::steps(t).unwrap())
        .filter(|st| st.who == Who::Rmasscan)
        .map(|st| (st.cwd.to_owned(), st.argv))
        .collect();
    assert_eq!(rm.len(), want.len());
    for (a, (group, argv)) in rm.iter().zip(&want) {
        assert_eq!(
            &a[..4],
            &strings(&[IP, "netns", "exec", "wl-scan-41-42"])[..],
            "{a:?}"
        );
        assert_eq!(&a[4..7], &strings(&[SH, "-c", IN_DIR_SCRIPT])[..]);
        assert!(slashes(&a[7]).ends_with(&format!("/cwd-{group}")), "{a:?}");
        assert_eq!(a[8], s.fake.rmasscan);
        assert_eq!(&a[9..], &argv[..]);
    }
    // the oracle: under the masked /etc/masscan, the same argv, in its own directory
    assert_eq!(or.len(), 2);
    for a in &or {
        assert_eq!(
            &a[..4],
            &strings(&[IP, "netns", "exec", "wl-scan-41-42"])[..]
        );
        assert_eq!(&a[8..12], &strings(&[UNSHARE, "-m", SH, "-c"])[..], "{a:?}");
        assert!(a.contains(&s.fake.oracle));
        assert!(
            a.iter().any(|x| x == "--retries") || a.iter().any(|x| x == "198.18.0.2-198.18.0.5")
        );
        assert!(
            !a.iter().any(|x| x == "--shard"),
            "the oracle runs the whole scan: {a:?}"
        );
    }
    // a resume runs in the directory of the run it resumes, and finds its files there
    let cwd = |step: &str| {
        s.fake
            .cwd_files
            .borrow()
            .iter()
            .find(|c| c.0 == step)
            .cloned()
            .unwrap()
    };
    assert_eq!(cwd("pause").2, Vec::<String>::new());
    assert_eq!(cwd("resume").2, ["output.json", "paused.conf"]);
    assert_eq!(cwd("dual_resume").2, ["output.json", "paused.conf"]);
    // every other step starts in an empty directory
    for step in [
        "shard1",
        "shard2",
        "oracle",
        "retries",
        "mods",
        "badsum",
        "run",
        "dual",
        "dual_pause",
    ] {
        assert_eq!(cwd(step).2, Vec::<String>::new(), "{step}");
    }
    // shard1 and shard2 do not share a directory
    let dirs: Vec<String> = rm
        .iter()
        .filter(|a| a.iter().any(|x| x == "--shard"))
        .map(|a| a[7].clone())
        .collect();
    assert_eq!(dirs.len(), 2);
    assert_ne!(dirs[0], dirs[1]);
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn the_second_link_has_its_own_witness_marker_and_isolation_mode() {
    let s = setup(&["sc06_dual_veth"]);
    run_suite(&s).unwrap();
    let dumps: Vec<Vec<String>> = s
        .fake
        .spawned
        .borrow()
        .iter()
        .filter(|a| a.iter().any(|x| x == "dump"))
        .cloned()
        .collect();
    // one witness per link of each of the three steps
    assert_eq!(dumps.len(), 6);
    for pair in dumps.chunks(2) {
        assert_eq!(after(&pair[0], "--iface"), "veth-b");
        assert_eq!(after(&pair[0], "--end-dst"), "02:aa:00:00:00:01");
        assert!(slashes(after(&pair[0], "--pcap")).ends_with("/peer.pcap"));
        assert_eq!(after(&pair[1], "--iface"), "veth-b2");
        assert_eq!(after(&pair[1], "--end-dst"), "02:aa:00:00:00:03");
        assert!(slashes(after(&pair[1], "--pcap")).ends_with("/peer2.pcap"));
        // both in the peer namespace
        assert_eq!(
            &pair[1][..4],
            &strings(&[IP, "netns", "exec", "wl-peer-41-42"])[..]
        );
    }
    let markers: Vec<Vec<String>> = s
        .fake
        .execs
        .borrow()
        .iter()
        .filter(|a| a.iter().any(|x| x == "marker"))
        .cloned()
        .collect();
    assert_eq!(markers.len(), 6);
    assert_eq!(
        (
            after(&markers[1], "--iface"),
            after(&markers[1], "--src"),
            after(&markers[1], "--dst")
        ),
        ("veth-a2", "02:aa:00:00:00:03", "02:aa:00:00:00:04")
    );
    assert_eq!(
        (
            after(&markers[0], "--iface"),
            after(&markers[0], "--src"),
            after(&markers[0], "--dst")
        ),
        ("veth-a", "02:aa:00:00:00:01", "02:aa:00:00:00:02")
    );
    // the seal is proven in scan-control mode, before and after the case
    let iso: Vec<Vec<String>> = s
        .fake
        .execs
        .borrow()
        .iter()
        .filter(|a| a.iter().any(|x| x == "isolation"))
        .cloned()
        .collect();
    assert_eq!(iso.len(), 2);
    assert!(iso.iter().all(|a| after(a, "--mode") == "scan-control"));
    assert!(slashes(after(&iso[0], "--out")).ends_with("/run/isolation.json"));
    assert!(slashes(after(&iso[1], "--out")).ends_with("/run/isolation-post.json"));
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn the_netem_delay_is_set_before_the_scanner_and_taken_off_after_the_witness_in_the_peer_namespace()
{
    let s = setup(&["sc02_pause_wait_resume"]);
    run_suite(&s).unwrap();
    let tcs: Vec<Vec<String>> = s
        .fake
        .execs
        .borrow()
        .iter()
        .filter(|a| a.iter().any(|x| x == TC))
        .cloned()
        .collect();
    assert_eq!(
        tcs,
        [
            strings(&[
                IP,
                "netns",
                "exec",
                "wl-peer-41-42",
                TC,
                "qdisc",
                "add",
                "dev",
                "veth-b",
                "root",
                "netem",
                "delay",
                "1000ms"
            ]),
            strings(&[
                IP,
                "netns",
                "exec",
                "wl-peer-41-42",
                TC,
                "qdisc",
                "del",
                "dev",
                "veth-b",
                "root"
            ]),
        ],
        "only the pause step, only the peer's own veth"
    );
    let log = s.fake.log.borrow();
    let at = |needle: &str| log.iter().position(|l| l.contains(needle)).unwrap();
    let pause_scanner = log.iter().position(|l| l == "start scanner").unwrap();
    assert!(
        at("qdisc add") < pause_scanner,
        "the delay is on before the scanner starts"
    );
    let del = at("qdisc del");
    let witness_stop = log.iter().position(|l| l == "signal witness:TERM").unwrap();
    assert!(
        witness_stop < del,
        "and off only after the witness finished"
    );
    let rec: Value =
        crate::windows_suite::read_json(s.out.join("runs/sc02_pause_wait_resume/pause/netem.json"))
            .unwrap();
    assert_eq!(
        rec,
        json!({"iface": "veth-b", "delay_ms": 1000, "applied": true, "removed": true})
    );
    fs::remove_dir_all(s.root).unwrap();
}

// ------------------------------------------------------------------ the interrupt

#[test]
fn an_interrupted_step_gets_sigint_to_the_scanner_alone_and_records_the_paused_conf() {
    let s = setup(&["sc02_pause_wait_resume"]);
    run_suite(&s).unwrap();
    let log = s.fake.log.borrow();
    assert_eq!(
        log.iter().filter(|l| *l == "signal scanner:INT").count(),
        1,
        "one SIGINT, to the scanner process only"
    );
    assert!(!log.iter().any(|l| l.contains("KILL")));
    drop(log);
    let rec: ScInterrupt = serde_json::from_slice(
        &fs::read(
            s.out
                .join("runs/sc02_pause_wait_resume/pause/interrupt.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(rec.signal, "INT");
    assert_eq!(
        (rec.after_s, rec.exit_within_s, rec.killed),
        (3.0, 30.0, false)
    );
    let sig = rec.signal_unix.unwrap();
    assert!(
        (rec.paused_seen_unix.unwrap() - sig - 0.1).abs() < 1e-6,
        "{rec:?}"
    );
    assert!(rec.paused_conf_present);
    // the resume step is not interrupted and left no record
    assert!(
        !s.out
            .join("runs/sc02_pause_wait_resume/resume/interrupt.json")
            .exists()
    );
    // paused.conf is in the evidence under its neutral name
    assert!(
        s.out
            .join("runs/sc02_pause_wait_resume/pause/paused.txt")
            .is_file()
    );
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn a_scanner_that_ignores_sigint_is_killed_and_the_record_says_so() {
    let mut s = setup(&["sc05_infinite_interrupt"]);
    s.fake.ignores_int.set(true);
    run_suite(&s).unwrap();
    let rec: ScInterrupt = serde_json::from_slice(
        &fs::read(
            s.out
                .join("runs/sc05_infinite_interrupt/run/interrupt.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(rec.killed);
    assert!(
        s.fake
            .log
            .borrow()
            .iter()
            .any(|l| l == "signal scanner:KILL")
    );
    teardown(&s);
    s.args.clear();
    // the verifier calls that a FAIL of rmasscan
    let res = sv::verify_dir(&s.out);
    let r = array(&res["runs"])
        .iter()
        .find(|r| r["tag"] == "sc05_infinite_interrupt")
        .unwrap()
        .clone();
    assert!(
        array(&r["checks"])
            .iter()
            .any(|c| c["result"] != PASS && c["name"].as_str().unwrap().contains("no SIGKILL"))
    );
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn a_stop_request_after_a_cases_sigint_stops_before_the_next_case_and_leaves_nothing_running() {
    let s = setup(&["sc02_pause_wait_resume", "sc03_retries"]);
    s.fake.stop_after_int.set(true);
    let r = run_suite(&s);
    // the stop comes between the pause and the resume of sc02: the case is kept as an aborted attempt, not as a run,
    // and sc03 never starts
    assert!(
        matches!(&r, Err(SuiteError::Interrupted(m)) if m.contains("stop requested before sc02_pause_wait_resume/resume started its scanner") && m.contains("runs_aborted/sc02_pause_wait_resume.")),
        "{r:?}"
    );
    assert!(
        !s.out.join("runs/sc02_pause_wait_resume").exists()
            && !s.out.join("runs/sc03_retries").exists()
    );
    assert!(s.fake.scans(&s.fake.oracle).is_empty());
    let kept = s.out.join("runs_aborted");
    assert_eq!(fs::read_dir(&kept).unwrap().count(), 1);
    // the verifier treats the attempt as no run of the case
    teardown(&s);
    let res = sv::verify_dir(&s.out);
    let run = array(&res["runs"])
        .iter()
        .find(|r| r["tag"] == "sc02_pause_wait_resume")
        .unwrap()
        .clone();
    assert_ne!(run["verdict"], PASS);
    fs::remove_dir_all(s.root).unwrap();
    // and a stop requested while the scanner exits after SIGINT aborts the run and keeps it under runs_aborted
    let s = setup(&["sc05_infinite_interrupt"]);
    s.fake.stop_after_int.set(true);
    s.fake.ignores_int.set(true);
    let r = run_suite(&s);
    assert!(
        matches!(&r, Err(SuiteError::Interrupted(m)) if m.contains("exiting after SIGINT")),
        "{r:?}"
    );
    assert!(!s.out.join("runs/sc05_infinite_interrupt").exists());
    let kept: Vec<_> = fs::read_dir(s.out.join("runs_aborted"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(kept.len(), 1);
    assert!(kept[0].starts_with("sc05_infinite_interrupt."), "{kept:?}");
    fs::remove_dir_all(s.root).unwrap();
}

// ------------------------------------------------------------------ the guards

#[test]
fn only_root_inside_the_wire_lab_may_run_it() {
    let mut s = setup(&sv::planned_tags());
    s.fake.euid = 1000;
    let m = not_run_text(run_suite(&s));
    assert!(
        m.contains("runs as root") && m.contains("never calls sudo"),
        "{m}"
    );
    assert!(
        s.fake.spawned.borrow().is_empty() && s.fake.execs.borrow().is_empty(),
        "nothing was started"
    );
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn a_case_that_is_not_in_the_table_is_refused_before_anything_starts() {
    let mut s = setup(&sv::planned_tags());
    s.args.extend(strings(&["--only", "sc99_nope"]));
    let m = not_run_text(run_suite(&s));
    assert!(m.contains("sc99_nope is not a scan-control case"), "{m}");
    assert!(s.fake.spawned.borrow().is_empty() && s.fake.execs.borrow().is_empty());
    assert_eq!(selected(&[]).unwrap().len(), 6);
    assert_eq!(
        selected(&strings(&["sc06_dual_veth", "sc01_shards_union"])).unwrap(),
        ["sc01_shards_union", "sc06_dual_veth"]
    );
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn the_stand_must_be_the_wire_labs_scan_control_stand() {
    // the stand's names and MACs are fixed: anything else is refused
    for (k, v) in [
        ("--iface-a", "eth0"),
        ("--iface-b", "veth-b2"),
        ("--mac-a", "02:aa:00:00:00:03"),
        ("--mac-b", "02:aa:00:00:00:04"),
    ] {
        let mut s = setup(&["sc03_retries"]);
        let i = s.args.iter().position(|a| a == k).unwrap();
        s.args[i + 1] = v.into();
        let m = not_run_text(run_suite(&s));
        assert!(m.contains("fixes the stand"), "{k}: {m}");
        assert!(s.fake.spawned.borrow().is_empty() && s.fake.execs.borrow().is_empty());
        fs::remove_dir_all(s.root).unwrap();
    }
    // wire-lab.sh's isolation.json must attest the scan-control stand: not the autodetect one, not one without the
    // second link, not a missing one
    let edits: [fn(&mut Value); 4] = [
        |v| v["mode"] = json!("autodetect"),
        |v| {
            v.as_object_mut().unwrap().remove("second_link");
        },
        |v| v["second_link"]["peer"] = json!("veth-b9"),
        |v| v["uplink"] = json!(true),
    ];
    for edit in edits {
        let s = setup(&["sc03_retries"]);
        let mut v: Value = serde_json::from_slice(&sc_isolation()).unwrap();
        edit(&mut v);
        fs::write(s.out.join(ISOLATION_JSON), serde_json::to_vec(&v).unwrap()).unwrap();
        let m = not_run_text(run_suite(&s));
        assert!(
            m.contains("does not attest the sealed scan-control stand"),
            "{m}"
        );
        assert!(s.fake.spawned.borrow().is_empty() && s.fake.execs.borrow().is_empty());
        fs::remove_dir_all(s.root).unwrap();
    }
    let s = setup(&["sc03_retries"]);
    fs::remove_file(s.out.join(ISOLATION_JSON)).unwrap();
    assert!(not_run_text(run_suite(&s)).contains("isolation.json is missing"));
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn a_changed_binary_or_a_second_run_of_a_case_into_one_out_is_refused() {
    let s = setup(&["sc04_packet_mods_and_pcap"]);
    run_suite(&s).unwrap();
    let again = FakeSc::new(
        &["sc04_packet_mods_and_pcap"],
        Path::new(&s.fake.rmasscan),
        Path::new(&s.fake.oracle),
    );
    let m = not_run_text(linux_with(&s.args, &again, &s.lab));
    assert!(m.contains("already has a run in this directory"), "{m}");
    assert!(again.spawned.borrow().is_empty());
    fs::remove_dir_all(s.root).unwrap();
    // rmasscan replaced after the manifest: nothing starts
    let s = setup(&["sc03_retries"]);
    let suite_args = s.args.clone();
    let rm = PathBuf::from(&s.fake.rmasscan);
    let host = &s.fake;
    let o = options_for("t", &suite_args, ad::LINUX_OPTIONS).unwrap();
    let sc = Scrubber::new(&s.out, Some(&s.out.join(".work")), None);
    let l = ad::linux_driver(
        host,
        &s.lab,
        s.out.clone(),
        s.out.join(".work"),
        ad::linux_args(&o, SUITE).unwrap(),
        &sc,
        &["sc03_retries"],
        ("scan-control", json!("linux"), "scan-control-suite linux"),
        sv::verify_dir,
    )
    .unwrap();
    fs::write(&rm, "a different rmasscan").unwrap();
    let r = l.one_with("sc03_retries", |base, run, t| {
        one(
            &l,
            "sc03_retries",
            &sv::steps("sc03_retries").unwrap(),
            base,
            run,
            t,
        )
    });
    assert!(matches!(r, Err(SuiteError::NotRun(m)) if m.contains("changed since the manifest")));
    assert!(s.fake.spawned.borrow().is_empty());
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn a_stale_paused_conf_or_a_netem_that_cannot_be_set_stops_the_step_before_the_scanner() {
    // netem unavailable on the host: the late-reply window cannot be proven
    let s = setup(&["sc02_pause_wait_resume"]);
    s.fake.tc_rc.set(2);
    let m = not_run_text(run_suite(&s));
    assert!(
        m.contains("netem delay") && m.contains("scanner was not started"),
        "{m}"
    );
    assert!(
        s.fake.scans(&s.fake.rmasscan).is_empty(),
        "the scanner was never started"
    );
    fs::remove_dir_all(s.root).unwrap();
    // a paused.conf already in the directory of an interrupted step
    let s = setup(&["sc05_infinite_interrupt"]);
    let l_work = s.out.join(".work");
    let _ = l_work;
    let o = options_for("t", &s.args, ad::LINUX_OPTIONS).unwrap();
    let sc = Scrubber::new(&s.out, Some(&s.out.join(".work")), None);
    let l = ad::linux_driver(
        &s.fake,
        &s.lab,
        s.out.clone(),
        s.out.join(".work"),
        ad::linux_args(&o, SUITE).unwrap(),
        &sc,
        &["sc05_infinite_interrupt"],
        ("scan-control", json!("linux"), "x"),
        sv::verify_dir,
    )
    .unwrap();
    let base = s.out.join(".work/sc05_infinite_interrupt.1");
    let run = base.join("run");
    fs::create_dir_all(base.join("cwd-run")).unwrap();
    fs::create_dir_all(run.join("run")).unwrap();
    fs::write(base.join("cwd-run").join(PAUSED_CONF), "old").unwrap();
    let spec = sv::steps("sc05_infinite_interrupt").unwrap().remove(0);
    let mut t = LinuxTools::default();
    let r = step(&l, "sc05_infinite_interrupt", &spec, &base, &run, &mut t);
    assert!(matches!(r, Err(SuiteError::NotRun(m)) if m.contains("a paused.conf is already")));
    assert!(s.fake.scans(&s.fake.rmasscan).is_empty());
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn usage_and_unknown_stands_are_refused_without_running_anything() {
    assert_eq!(run(&strings(&["help"])), Ok(0));
    assert!(run(&[]).unwrap_err().contains("which stand?"));
    let e = run(&strings(&["macos"])).unwrap_err();
    assert!(e.contains("the scan-control suite runs on linux"), "{e}");
    let off_linux = linux_entry(&[], Path::new("/x"));
    if cfg!(target_os = "linux") {
        assert!(off_linux.is_err());
    } else {
        assert!(
            matches!(off_linux, Err(SuiteError::NotRun(m)) if m.contains("runs on the Linux lab host"))
        );
    }
    let s = setup(&["sc03_retries"]);
    let mut a = s.args.clone();
    a.push("--help".into());
    assert_eq!(linux_with(&a, &s.fake, &s.lab).unwrap(), 0);
    assert!(s.fake.spawned.borrow().is_empty());
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn the_table_never_names_an_address_outside_the_lab_net() {
    for tag in sv::TAGS {
        for st in sv::steps(tag).unwrap() {
            assert!(
                addresses_outside_the_lab(&st.argv).is_empty(),
                "{tag}/{}",
                st.name
            );
        }
    }
    assert_eq!(
        addresses_outside_the_lab(&strings(&["198.18.1.1", "-p80"])),
        ["198.18.1.1"]
    );
    assert_eq!(
        addresses_outside_the_lab(&strings(&["--adapter-ip[1]=10.0.0.5"])),
        ["10.0.0.5"]
    );
    // the shell script is a constant: no value is spliced into it
    assert_eq!(IN_DIR_SCRIPT, "cd \"$0\" && exec \"$@\"");
}

#[test]
fn wire_lab_raises_the_second_pair_inside_the_same_two_namespaces_and_tears_both_down_in_one_trap()
{
    let text =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/wire-lab.sh"))
            .unwrap();
    // `--suite scan-control` needs --rmasscan, like output, and runs on the same fixed stand, lab id and teardown.
    assert!(text.contains(r#"scan-control) [ -n "$RMASSCAN_BIN" ] || { echo "--suite scan-control needs --rmasscan" >&2; exit 64; } ;;"#));
    assert!(
        text.contains(r#"case "$SUITE" in autodetect|output|scan-control) STAND_SUITE=1 ;; esac"#)
    );
    // The second pair: created inside the scanner namespace with its peer end moved straight into the peer one, like
    // the first; never a link in the host namespace, never a host interface named.
    assert!(
        text.contains(
            r#"ip -n "$NS_A" link add "$IF_A2" type veth peer name "$IF_B2" netns "$NS_B""#
        )
    );
    assert!(text.contains("IF_A2=veth-a2; IF_B2=veth-b2; MAC_A2=02:aa:00:00:00:03; MAC_B2=02:aa:00:00:00:04; IP_ADAPTER2=198.18.0.6"));
    for line in text.lines().filter(|l| {
        l.contains("link add") && !l.trim_start().starts_with('#') && !l.contains("note_cmd")
    }) {
        assert!(
            line.contains(r#"ip -n "$NS_A" link add"#),
            "a link created outside the scanner namespace: {line}"
        );
    }
    // Every command that touches the second pair names a namespace of this lab.
    for line in text.lines().filter(|l| {
        (l.contains("$IF_A2") || l.contains("$IF_B2"))
            && !l.trim_start().starts_with('#')
            && !l.contains("note_cmd")
    }) {
        assert!(
            ["$NS_A", "$NS_B", r#"-n "$ns""#, "nsa ", "nsb ", "want="]
                .iter()
                .any(|n| line.contains(n))
                || line.trim_start().starts_with("IF_A2="),
            "a command on the second pair outside the lab's namespaces: {line}"
        );
    }
    // The seal expects exactly the two pairs, and the peer namespace exactly the one /32 route of the second adapter.
    assert!(text.contains(r#"want="lo $IF_A $IF_A2 ";; *) want="lo $IF_B $IF_B2 ""#));
    assert!(text.contains(r#"ip -n "$NS_B" route add "$IP_ADAPTER2/32" dev "$IF_B2""#));
    assert!(text.contains(
        r#"ISOLATION_MODE=autodetect; [ "$SUITE" != scan-control ] || ISOLATION_MODE=scan-control"#
    ));
    // The same trap deletes both namespaces (and with them both pairs); no second cleanup exists.
    let cleanup = text
        .split("cleanup() {")
        .nth(1)
        .unwrap()
        .split("\ntrap cleanup EXIT")
        .next()
        .unwrap();
    assert!(
        cleanup.contains(r#"ip netns del "$NS_A""#) && cleanup.contains(r#"ip netns del "$NS_B""#)
    );
    assert!(!cleanup.contains("$IF_A2") && !text.contains("trap cleanup EXIT\ntrap cleanup EXIT"));
    assert!(text.contains(r#"trap 'exit 130' INT"#) && text.contains(r#"trap 'exit 143' TERM"#));
    let teardown = cleanup
        .find(r#"[ "$STAND_SUITE" = 0 ] || autodetect_teardown"#)
        .unwrap();
    assert!(
        cleanup.find(r#"ip netns del "$NS_B""#).unwrap() < teardown
            && teardown < cleanup.find("chown -R").unwrap()
    );
    // The suite is started with the lab id and the same flags as the output suite.
    let suite = text
        .split("start_suite_group \"$OUT/suite.log\" \"$LAB_BIN\" scan-control-suite linux")
        .nth(1)
        .and_then(|t| t.split("SUITE_PID=").next())
        .expect("the scan-control suite's start");
    for flag in [
        r#"--lab-id "$LAB_ID""#,
        r#"--rmasscan "$RMASSCAN_BIN""#,
        r#"--conf-masked "$CONF_MASKED""#,
        r#"--work "$WORK""#,
        r#"--ns-a "$NS_A""#,
        r#"--ns-b "$NS_B""#,
    ] {
        assert!(suite.contains(flag), "{flag}: {suite}");
    }
    // Nothing in the new branch calls the host's firewall, routes, bridges or sudo.
    for banned in ["iptables", "nft ", "brctl", "ip route add default", "sudo "] {
        assert!(
            !text
                .lines()
                .filter(|l| l.contains("A2") || l.contains("scan-control"))
                .any(|l| l.contains(banned) && !l.trim_start().starts_with('#')),
            "{banned}"
        );
    }
}
