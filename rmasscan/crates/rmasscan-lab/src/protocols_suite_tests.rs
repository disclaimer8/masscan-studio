//! The protocols suite against a recording host: nothing here opens an interface, runs a process or writes a frame.
//! The scanners' outputs, exits and captures come from the verifier's synthetic generator
//! (`protocols_verify::tests::Sim`); the suite writes the evidence directory itself and `protocols-verify` judges it,
//! so the layout the suite writes and the layout the verifier reads are tested against each other.
use super::*;
use crate::{
    autodetect_suite::{IP, Running, UNSHARE},
    autodetect_verify::{
        self as av,
        tests::{LAB_ID, Sim as AdSim, TEARDOWN, linux_isolation},
    },
    pcap,
    protocols_verify::tests::Sim,
    verify::{PASS, array},
    windows_suite::Output,
};
use serde_json::Value;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    time::Duration,
};

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-proto-suite-{}", nonce()));
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

/// A scripted process: it exits with `rc` at once, or runs until signalled (`on_stop` then gives its exit code).
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

const PROTOCOLS_NO_SCTP: &str = "protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re bi br ha uh gp em\nPACKET    1536      0      -1   NI       0   no   kernel      n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n\nUDP       1152      0       2   NI       0   yes  kernel      y  y  y  n  y  y  y  n  y  y  y  y  y  n  n  y  y  y  n\nTCP       2432      0       1   no     320   yes  kernel      y  y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  y\n";
const PROTOCOLS_SCTP: &str = "SCTP      1376      0      -1   NI       0   yes  sctp        y  y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  y\n";

/// The netns stand as the suite sees it, played from the generator's cases.
struct FakeProto {
    sims: BTreeMap<&'static str, Sim>,
    rmasscan: String,
    oracle: String,
    euid: u32,
    current: RefCell<&'static str>,
    spawned: RefCell<Vec<Vec<String>>>,
    execs: RefCell<Vec<Vec<String>>>,
    /// Everything the suite did, in order: `exec ...`, `start ...`, `signal ...`.
    log: Rc<RefCell<Vec<String>>>,
    /// The peer namespace's `icmp_ratemask` and whether `/proc/net/protocols` lists SCTP.
    ratemask: RefCell<String>,
    sctp: Cell<bool>,
    /// The files in each scanner's working directory when it started.
    cwd_files: RefCell<Vec<(String, Vec<String>)>>,
    /// The `n`-th responder (from 0) dies with exit 2 and [`DEAD`] on its stderr; `true`: after it said ready.
    dead_responder: Cell<Option<(usize, bool)>>,
}
/// What `capture responder` prints when an answerer fails (main: `NOT RUN: <error>`, exit 2).
const DEAD: &str = "NOT RUN: udp responder: Address already in use (os error 98)";
impl FakeProto {
    fn new(tags: &[&'static str], rmasscan: &Path, oracle: &Path) -> Self {
        FakeProto {
            sims: tags.iter().map(|t| (*t, Sim::new(t))).collect(),
            rmasscan: p2s(rmasscan),
            oracle: p2s(oracle),
            euid: 0,
            current: RefCell::new(""),
            spawned: RefCell::default(),
            execs: RefCell::default(),
            log: Rc::default(),
            ratemask: RefCell::new("0".into()),
            sctp: Cell::new(false),
            cwd_files: RefCell::default(),
            dead_responder: Cell::new(None),
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
impl LinuxHost for FakeProto {
    fn exec(&self, argv: &[String], _timeout: u64) -> Result<Output, String> {
        self.note(argv, &[]);
        self.execs.borrow_mut().push(argv.to_vec());
        self.log.borrow_mut().push(format!(
            "exec {}",
            argv.iter().skip(4).cloned().collect::<Vec<_>>().join(" ")
        ));
        if argv.iter().any(|a| a == "isolation") {
            fs::write(after(argv, "--out"), linux_isolation()).unwrap();
        }
        let stdout = match argv.last().map(String::as_str) {
            Some(RATEMASK) => format!("{}\n", self.ratemask.borrow()),
            Some(ECHO_IGNORE) => "0\n".into(),
            Some(PROTOCOLS) if self.sctp.get() => format!("{PROTOCOLS_NO_SCTP}{PROTOCOLS_SCTP}"),
            Some(PROTOCOLS) => PROTOCOLS_NO_SCTP.into(),
            _ => String::new(),
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
            match self.dead_responder.get() {
                Some((n, ready)) if n + 1 == self.responders().len() => {
                    fs::write(stderr, format!("{DEAD}\n")).unwrap();
                    if ready {
                        fs::write(after(argv, "--ready"), "listening 80,8080\n").unwrap();
                    }
                    return Ok(self.proc("responder", Some(2), None));
                }
                _ => {}
            }
            fs::write(
                after(argv, "--ready"),
                "listening 80,8080 udp 53,161 sctp veth-b open 2905\n",
            )
            .unwrap();
            return Ok(self.proc("responder", None, None));
        }
        let sim = self.sim();
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
        assert_eq!(step.spec.who, who);
        let mut names: Vec<String> = fs::read_dir(&cwd)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        self.cwd_files
            .borrow_mut()
            .push((step.spec.name.into(), names));
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
    fake: FakeProto,
    args: Vec<String>,
}
fn setup(tags: &[&'static str]) -> Setup {
    let root = scratch();
    let out = root.join("linux-protocols-r1");
    let work = out.join(".work");
    fs::create_dir_all(&work).unwrap();
    fs::write(work.join("host-links-before.txt"), "eno1\nlo\n").unwrap();
    fs::write(out.join(pv::ISOLATION_JSON), linux_isolation()).unwrap();
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
    if tags.len() < pv::planned_tags().len() {
        args.push("--only".into());
        args.extend(tags.iter().map(|t| (*t).to_owned()));
    }
    let fake = FakeProto::new(tags, &rm, &oracle);
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
    let s = setup(&pv::planned_tags());
    assert_eq!(run_suite(&s).unwrap(), 0);
    teardown(&s);
    let res = pv::verify_dir(&s.out);
    assert_eq!(res["overall"], PASS, "{:#?}", bad(&res));
    for tag in pv::planned_tags() {
        let d = s.out.join("runs").join(tag);
        for f in [
            "hashes-before-copy.txt",
            "expect.json",
            "peer-stack.json",
            "isolation.json",
            "isolation-post.json",
        ] {
            assert!(d.join(f).is_file(), "{tag} {f}");
        }
        for step in pv::steps(tag).unwrap() {
            for f in [
                "argv.json",
                "stdout.txt",
                "stderr.txt",
                "exit.txt",
                "peer.pcap",
                "capture.json",
                "peer.err",
                "responder.json",
            ] {
                assert!(
                    d.join(step.name).join(f).is_file(),
                    "{tag}/{} {f}",
                    step.name
                );
            }
            if let Some(n) = step.out.file() {
                assert!(
                    d.join(step.name).join(n).is_file(),
                    "{tag}/{} {n}",
                    step.name
                );
            }
        }
        // the peer stack the case ran on
        let stack: PeerStack =
            serde_json::from_slice(&fs::read(d.join("peer-stack.json")).unwrap()).unwrap();
        assert_eq!(stack, crate::protocols_verify::tests::stack());
    }
    let m = crate::windows_suite::read_json(s.out.join("manifest.json")).unwrap();
    assert_eq!(m["protocols"], "linux");
    assert_eq!(m["lab_id"], LAB_ID);
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

// ------------------------------------------------------------------ argv construction

#[test]
fn every_scanner_runs_the_tables_argv_in_its_own_directory_inside_the_scanner_namespace() {
    let s = setup(&pv::planned_tags());
    run_suite(&s).unwrap();
    let rm = s.fake.scans(&s.fake.rmasscan);
    let or = s.fake.scans(&s.fake.oracle);
    let table: Vec<StepSpec> = pv::planned_tags()
        .iter()
        .flat_map(|t| pv::steps(t).unwrap())
        .collect();
    let want_rm: Vec<&StepSpec> = table.iter().filter(|x| x.who == Who::Rmasscan).collect();
    let want_or: Vec<&StepSpec> = table.iter().filter(|x| x.who == Who::Oracle).collect();
    assert_eq!((rm.len(), or.len()), (want_rm.len(), want_or.len()));
    for (a, st) in rm.iter().zip(&want_rm) {
        assert_eq!(
            &a[..4],
            &strings(&[IP, "netns", "exec", "wl-scan-41-42"])[..],
            "{a:?}"
        );
        assert_eq!(&a[4..7], &strings(&[SH, "-c", IN_DIR_SCRIPT])[..]);
        assert!(
            slashes(&a[7]).ends_with(&format!("/cwd-{}", st.name)),
            "{a:?}"
        );
        assert_eq!(a[8], s.fake.rmasscan);
        assert_eq!(&a[9..], &st.argv[..]);
    }
    // the oracle: under the masked /etc/masscan, the same argv, in its own directory
    for (a, st) in or.iter().zip(&want_or) {
        assert_eq!(
            &a[..4],
            &strings(&[IP, "netns", "exec", "wl-scan-41-42"])[..]
        );
        assert!(
            slashes(&a[7]).ends_with(&format!("/cwd-{}", st.name)),
            "{a:?}"
        );
        assert_eq!(&a[8..12], &strings(&[UNSHARE, "-m", SH, "-c"])[..], "{a:?}");
        let at = a.iter().position(|x| *x == s.fake.oracle).unwrap();
        assert_eq!(&a[at + 1..], &st.argv[..]);
    }
    // every scanner starts in an empty directory of its own
    for (step, files) in s.fake.cwd_files.borrow().iter() {
        assert!(files.is_empty(), "{step}: {files:?}");
    }
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn the_responder_answers_the_stands_way_from_the_peer_namespace_and_restarts_for_every_step() {
    let s = setup(&pv::planned_tags());
    run_suite(&s).unwrap();
    let resp = s.fake.responders();
    let steps: usize = pv::planned_tags()
        .iter()
        .map(|t| pv::steps(t).unwrap().len())
        .sum();
    assert_eq!(resp.len(), steps, "one responder per step");
    for a in &resp {
        assert_eq!(
            &a[..4],
            &strings(&[IP, "netns", "exec", "wl-peer-41-42"])[..]
        );
        assert_eq!(a[4], p2s(&s.lab));
        assert_eq!(&a[5..7], &strings(&["capture", "responder"])[..]);
        let mut want = pv::responder_args();
        want.push("--ready".into());
        assert_eq!(&a[7..a.len() - 1], &want[..]);
    }
    assert_eq!(
        pv::responder_args(),
        strings(&[
            "--ports",
            "80,8080",
            "--udp-ports",
            "53,161",
            "--udp-ips",
            "198.18.0.2,198.18.0.3,198.18.0.4,198.18.0.5",
            "--sctp-iface",
            "veth-b",
            "--sctp-open",
            "2905"
        ])
    );
    // every responder is stopped before the next one starts
    let log = s.fake.log.borrow();
    let mut running = false;
    for l in log.iter() {
        if l == "start responder" {
            assert!(!running, "two responders at once");
            running = true;
        } else if l == "signal responder:TERM" {
            running = false;
        }
    }
    assert!(!running);
    // the peer stack is read in the peer namespace with absolute paths: before the first case, then once per case
    let reads: Vec<Vec<String>> = s
        .fake
        .execs
        .borrow()
        .iter()
        .filter(|a| a.get(4).map(String::as_str) == Some(CAT))
        .cloned()
        .collect();
    assert_eq!(reads.len(), 3 * (1 + pv::planned_tags().len()));
    for a in &reads {
        assert_eq!(
            &a[..4],
            &strings(&[IP, "netns", "exec", "wl-peer-41-42"])[..]
        );
        assert!([RATEMASK, ECHO_IGNORE, PROTOCOLS].contains(&a[5].as_str()));
    }
    fs::remove_dir_all(s.root).unwrap();
}

// ------------------------------------------------------------------ a responder that dies

#[test]
fn a_responder_that_never_became_ready_is_named_in_the_not_run_reason() {
    let s = setup(&["p02_udp_payloads_and_closed"]);
    s.fake.dead_responder.set(Some((0, false)));
    let m = not_run_text(run_suite(&s));
    assert!(
        m.contains(&format!(
            "the peer responder did not become ready (it exited with 2: {DEAD}); the scanner was not started"
        )),
        "{m}"
    );
    assert!(
        s.fake.scans(&s.fake.rmasscan).is_empty() && s.fake.scans(&s.fake.oracle).is_empty(),
        "no scanner was started"
    );
    assert!(!s.out.join("runs").exists() && !s.out.join("runs_aborted").exists());
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn a_responder_that_died_mid_step_is_recorded_and_named_in_the_verdict() {
    // p02's first step is `json`: its responder said ready, then died before the scanner ended.
    let s = setup(&["p02_udp_payloads_and_closed"]);
    s.fake.dead_responder.set(Some((0, true)));
    assert_eq!(run_suite(&s).unwrap(), 0);
    teardown(&s);
    let d = s.out.join("runs/p02_udp_payloads_and_closed");
    let rec: pv::ResponderRecord =
        serde_json::from_slice(&fs::read(d.join("json").join(pv::RESPONDER_JSON)).unwrap())
            .unwrap();
    assert_eq!(
        rec,
        pv::ResponderRecord {
            exited_with: Some(2),
            stderr: DEAD.into(),
            ..pv::ResponderRecord::default()
        }
    );
    // the other steps' responders ran through their scans
    for step in ["oracle-json", "binary", "oracle-binary"] {
        let rec: pv::ResponderRecord =
            serde_json::from_slice(&fs::read(d.join(step).join(pv::RESPONDER_JSON)).unwrap())
                .unwrap();
        assert_eq!(rec, pv::ResponderRecord::default(), "{step}");
    }
    let res = pv::verify_dir(&s.out);
    let run = array(&res["runs"])
        .iter()
        .find(|r| r["tag"] == "p02_udp_payloads_and_closed")
        .unwrap();
    let b: Vec<String> = bad(&res)
        .into_iter()
        .filter(|x| x.contains("p02_udp_payloads_and_closed"))
        .collect();
    assert_eq!(run["verdict"], "INVALID", "{b:#?}");
    assert_eq!(b.len(), 1, "{b:#?}");
    assert!(
        b[0].contains("json/responder.json: the peer responder ran until the scanner ended")
            && b[0].contains(&format!(
                "not seen running when the scanner ended (it exited with 2): {DEAD}"
            )),
        "{b:#?}"
    );
    fs::remove_dir_all(s.root).unwrap();
}

/// A responder handle whose `try_end` answers what the test says.
struct Fixed(Result<Option<ad::Ended>, String>);
impl Running for Fixed {
    fn try_wait(&mut self) -> Result<Option<i32>, String> {
        unreachable!("responder_end reads try_end")
    }
    fn try_end(&mut self) -> Result<Option<ad::Ended>, String> {
        self.0.clone()
    }
    fn signal(&mut self, _sig: &str) {}
    fn kill(&mut self) {}
}

#[test]
fn the_responders_state_names_an_exit_a_signal_a_missing_handle_and_an_unreadable_state_apart() {
    // Until the final review of the stage all four ended as one `exited_with: -1`.
    let end = |r: Result<Option<ad::Ended>, String>| {
        let mut p: Box<dyn Running> = Box::new(Fixed(r));
        responder_end(Some(&mut p))
    };
    let rec = |exited_with, killed_by_signal, state_unknown: Option<&str>| pv::ResponderRecord {
        exited_with,
        killed_by_signal,
        state_unknown: state_unknown.map(str::to_owned),
        stderr: String::new(),
    };
    assert_eq!(end(Ok(None)), rec(None, None, None), "running");
    assert_eq!(end(Ok(Some(ad::Ended::Code(2)))), rec(Some(2), None, None));
    assert_eq!(
        end(Ok(Some(ad::Ended::Code(-1)))),
        rec(Some(-1), None, None)
    );
    assert_eq!(
        end(Ok(Some(ad::Ended::Signal(9)))),
        rec(None, Some(9), None)
    );
    assert_eq!(
        end(Err("Interrupted system call (os error 4)".into())),
        rec(
            None,
            None,
            Some("try_wait failed: Interrupted system call (os error 4)")
        )
    );
    assert_eq!(
        responder_end(None),
        rec(
            None,
            None,
            Some("the suite held no handle of the responder")
        )
    );
    // every way of not running is a problem the verifier names; running is none
    assert_eq!(pv::responder_problem(&end(Ok(None))), None);
    for r in [
        end(Ok(Some(ad::Ended::Code(2)))),
        end(Ok(Some(ad::Ended::Signal(9)))),
        end(Err("x".into())),
        responder_end(None),
    ] {
        assert!(pv::responder_problem(&r).is_some(), "{r:?}");
    }
}

// ------------------------------------------------------------------ refusals

#[test]
fn a_host_kernel_with_sctp_refuses_the_sctp_cases_before_anything_starts() {
    let s = setup(&pv::planned_tags());
    s.fake.sctp.set(true);
    let m = not_run_text(run_suite(&s));
    assert!(
        m.contains("p03_sctp_init_ack_abort: the host kernel has SCTP")
            && m.contains("p05_mixed_protos: the host kernel has SCTP")
            && !m.contains("p01_ping"),
        "{m}"
    );
    assert!(s.fake.spawned.borrow().is_empty(), "nothing was started");
    fs::remove_dir_all(s.root).unwrap();
    // the cases without SCTP run on that host
    let tags = ["p01_ping", "p02_udp_payloads_and_closed", "p04_arp_scan"];
    let s = setup(&tags);
    s.fake.sctp.set(true);
    assert_eq!(run_suite(&s).unwrap(), 0);
    teardown(&s);
    let res = pv::verify_dir(&s.out);
    for tag in tags {
        let r = array(&res["runs"])
            .iter()
            .find(|r| r["tag"] == tag)
            .unwrap();
        assert_eq!(r["verdict"], PASS, "{tag}: {:#?}", bad(&res));
    }
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn a_peer_namespace_that_rate_limits_icmp_errors_refuses_every_case() {
    let s = setup(&pv::planned_tags());
    *s.fake.ratemask.borrow_mut() = "6168".into();
    let m = not_run_text(run_suite(&s));
    assert!(m.contains("icmp_ratemask is 6168"), "{m}");
    assert!(s.fake.spawned.borrow().is_empty());
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn only_root_inside_the_wire_lab_may_run_it() {
    let mut s = setup(&pv::planned_tags());
    s.fake.euid = 1000;
    let m = not_run_text(run_suite(&s));
    assert!(
        m.contains("runs as root") && m.contains("never calls sudo"),
        "{m}"
    );
    assert!(s.fake.spawned.borrow().is_empty() && s.fake.execs.borrow().is_empty());
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn a_case_that_is_not_in_the_table_or_a_stand_that_is_not_attested_is_refused() {
    let mut s = setup(&pv::planned_tags());
    s.args.extend(strings(&["--only", "p99_nope"]));
    let m = not_run_text(run_suite(&s));
    assert!(m.contains("p99_nope is not a protocols case"), "{m}");
    assert!(s.fake.spawned.borrow().is_empty() && s.fake.execs.borrow().is_empty());
    fs::remove_dir_all(s.root).unwrap();
    assert_eq!(
        selected(&strings(&["p05_mixed_protos", "p01_ping"])).unwrap(),
        ["p01_ping", "p05_mixed_protos"]
    );
    // wire-lab.sh's isolation.json must attest the sealed autodetect stand
    let s = setup(&["p01_ping"]);
    let mut v: Value = serde_json::from_slice(&linux_isolation()).unwrap();
    v["uplink"] = json!(true);
    fs::write(
        s.out.join(pv::ISOLATION_JSON),
        serde_json::to_vec(&v).unwrap(),
    )
    .unwrap();
    let m = not_run_text(run_suite(&s));
    assert!(
        m.contains("does not attest the sealed autodetect stand"),
        "{m}"
    );
    assert!(s.fake.spawned.borrow().is_empty());
    fs::remove_dir_all(s.root).unwrap();
    // the stand's names are fixed
    let mut s = setup(&["p01_ping"]);
    let i = s.args.iter().position(|a| a == "--iface-b").unwrap();
    s.args[i + 1] = "eth0".into();
    assert!(not_run_text(run_suite(&s)).contains("fixes the stand"));
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn usage_and_unknown_stands_are_refused_without_running_anything() {
    assert_eq!(run(&strings(&["help"])), Ok(0));
    assert!(run(&[]).unwrap_err().contains("which stand?"));
    let e = run(&strings(&["macos"])).unwrap_err();
    assert!(e.contains("the protocols suite runs on linux"), "{e}");
    let off_linux = linux_entry(&[], Path::new("/x"));
    if cfg!(target_os = "linux") {
        assert!(off_linux.is_err());
    } else {
        assert!(
            matches!(off_linux, Err(SuiteError::NotRun(m)) if m.contains("runs on the Linux lab host"))
        );
    }
    let s = setup(&["p01_ping"]);
    let mut a = s.args.clone();
    a.push("--help".into());
    assert_eq!(linux_with(&a, &s.fake, &s.lab).unwrap(), 0);
    assert!(s.fake.spawned.borrow().is_empty());
    fs::remove_dir_all(s.root).unwrap();
}

// ------------------------------------------------------------------ wire-lab.sh

#[test]
fn wire_lab_raises_the_protocols_stand_with_every_icmp_error_answered_in_the_peer_namespace_only() {
    let text =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/wire-lab.sh"))
            .unwrap();
    // `--suite protocols` needs --rmasscan and runs on the fixed autodetect stand, lab id and teardown.
    assert!(text.contains(r#"protocols) [ -n "$RMASSCAN_BIN" ] || { echo "--suite protocols needs --rmasscan" >&2; exit 64; } ;;"#));
    assert!(text.contains(
        r#"case "$SUITE" in autodetect|output|scan-control|protocols) STAND_SUITE=1 ;; esac"#
    ));
    // The one stand change of the suite: no ICMP error rate limit, in the peer namespace only (dies with it).
    let changes: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("icmp_ratemask") && !l.trim_start().starts_with('#'))
        .collect();
    assert!(
        changes.iter().any(|l| l
            .contains(r#"[ "$SUITE" != protocols ] || nsb sysctl -qw net.ipv4.icmp_ratemask=0"#)),
        "{changes:?}"
    );
    for l in &changes {
        assert!(
            l.contains("nsb ") || l.contains("note_cmd") || l.contains("$NS_B"),
            "an ICMP setting outside the peer namespace: {l}"
        );
    }
    // the isolation record is the autodetect stand's
    assert!(text.contains(
        r#"ISOLATION_MODE=autodetect; [ "$SUITE" != scan-control ] || ISOLATION_MODE=scan-control"#
    ));
    // The suite is started with the lab id and the same flags as the other stand suites.
    let suite = text
        .split("start_suite_group \"$OUT/suite.log\" \"$LAB_BIN\" protocols-suite linux")
        .nth(1)
        .and_then(|t| t.split("SUITE_PID=").next())
        .expect("the protocols suite's start");
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
        "brctl",
        "ip route add default",
        "sudo ",
    ] {
        assert!(
            !text
                .lines()
                .filter(|l| l.contains("protocols"))
                .any(|l| l.contains(banned) && !l.trim_start().starts_with('#')),
            "{banned}"
        );
    }
}
