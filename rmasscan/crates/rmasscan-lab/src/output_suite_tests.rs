//! The output suite against a recording host: nothing here opens an interface, runs a process or writes a frame.
//! The scanners' outputs, exits and captures come from the verifier's synthetic generator
//! (`output_verify::tests::Sim`); the suite writes the run directories itself and `output-verify` judges them.
use super::*;
use crate::{
    autodetect_suite::{IP, Running, SH, UNSHARE},
    autodetect_verify::{
        self as av, ORACLE_PCAP,
        tests::{LAB_ID, Sim as AdSim, T0, TEARDOWN, linux_isolation},
    },
    output_verify::tests::Sim,
    pcap,
    windows_suite::{Output, nonce, read_json},
};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    time::Duration,
};

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-output-suite-{}", nonce()));
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
fn bad(res: &Value) -> Vec<String> {
    crate::verify::array(&res["runs"])
        .iter()
        .flat_map(|r| {
            crate::verify::array(&r["checks"])
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

/// The netns stand as the suite sees it, played from the generator's runs.
struct FakeOutput {
    sims: BTreeMap<&'static str, Sim>,
    rmasscan: String,
    oracle: String,
    euid: u32,
    current: RefCell<&'static str>,
    spawned: RefCell<Vec<Vec<String>>>,
    log: Rc<RefCell<Vec<String>>>,
    /// rmasscan keeps running through SIGINT.
    ignores_int: Cell<bool>,
    /// The operator asks to stop once the scanner has had its SIGINT.
    stop_after_int: Cell<bool>,
    /// The files each scanner found in its working directory when it started (tag, who, names).
    cwd_files: RefCell<Vec<(String, String, Vec<String>)>>,
}
impl FakeOutput {
    fn new(tags: &[&'static str], rmasscan: &Path, oracle: &Path) -> Self {
        FakeOutput {
            sims: tags.iter().map(|t| (*t, Sim::new(t))).collect(),
            rmasscan: p2s(rmasscan),
            oracle: p2s(oracle),
            euid: 0,
            current: RefCell::new(""),
            spawned: RefCell::default(),
            log: Rc::default(),
            ignores_int: Cell::new(false),
            stop_after_int: Cell::new(false),
            cwd_files: RefCell::default(),
        }
    }
    fn note(&self, argv: &[String], paths: &[&Path]) {
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
            ignores_int: name == "scanner" && self.ignores_int.get(),
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
impl LinuxHost for FakeOutput {
    fn exec(&self, argv: &[String], _timeout: u64) -> Result<Output, String> {
        self.note(argv, &[]);
        if argv.iter().any(|a| a == "isolation") {
            fs::write(after(argv, "--out"), linux_isolation()).unwrap();
        }
        Ok(Output {
            rc: 0,
            stdout: String::new(),
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
        let sim = self.sim();
        if argv.iter().any(|a| a == "responder") {
            fs::write(after(argv, "--ready"), "listening 80,8080\n").unwrap();
            return Ok(self.proc("responder", None, None));
        }
        if argv.iter().any(|a| a == "dump") {
            fs::write(after(argv, "--ready"), "{\"tcpdump_pid\":1}\n").unwrap();
            fs::write(after(argv, "--ack"), "ack\n").unwrap();
            let pcap_path = PathBuf::from(after(argv, "--pcap"));
            let frames = if pcap_path.ends_with(ORACLE_PCAP) {
                sim.oracle.as_ref().unwrap().pcap.clone()
            } else {
                sim.rm.pcap.clone()
            };
            let meta = PathBuf::from(after(argv, "--meta"));
            let stop = move || {
                fs::write(&pcap_path, pcap::encode(&frames)).unwrap();
                fs::write(&meta, AdSim::witness(&frames)).unwrap();
                fs::write(
                    format!("{}.tcpdump.err", pcap_path.display()),
                    format!("tcpdump: listening on veth-b, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n{0} packets captured\n{0} packets received by filter\n0 packets dropped by kernel\n", frames.len()),
                )
                .unwrap();
                0
            };
            return Ok(self.proc("witness", None, Some(Box::new(stop))));
        }
        let (who, side) = if argv.contains(&self.oracle) {
            ("oracle", sim.oracle.clone().unwrap())
        } else if argv.contains(&self.rmasscan) {
            ("rmasscan", sim.rm.clone())
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
        let mut names: Vec<String> = fs::read_dir(&cwd)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        self.cwd_files
            .borrow_mut()
            .push((sim.case.tag.into(), who.into(), names));
        fs::write(stdout, &side.stdout).unwrap();
        fs::write(stderr, &side.stderr).unwrap();
        if let Some((n, b)) = &side.file {
            fs::write(cwd.join(n), b).unwrap();
        }
        if who == "rmasscan" && sim.case.kind == OutputKind::Interrupt {
            let rc = side.exit;
            return Ok(self.proc("scanner", None, Some(Box::new(move || rc))));
        }
        Ok(self.proc(
            if who == "oracle" { "oracle" } else { "scanner" },
            Some(side.exit),
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
        self.stop_after_int.get() && self.log.borrow().iter().any(|x| x == "signal scanner:INT")
    }
    /// The generator's moment of the signal, so that `interrupt.json` matches its capture.
    fn now(&self) -> f64 {
        self.sim()
            .interrupt
            .as_ref()
            .and_then(|i| i.signal_unix)
            .unwrap_or(T0)
    }
}

/// A Linux evidence directory as `wire-lab.sh --suite output` leaves it before the suite starts.
struct Setup {
    root: PathBuf,
    out: PathBuf,
    lab: PathBuf,
    fake: FakeOutput,
    args: Vec<String>,
}
fn setup(tags: &[&'static str]) -> Setup {
    let root = scratch();
    let out = root.join("linux-output-r1");
    let work = out.join(".work");
    fs::create_dir_all(&work).unwrap();
    fs::write(work.join("host-links-before.txt"), "eno1\nlo\n").unwrap();
    fs::write(out.join("isolation.json"), linux_isolation()).unwrap();
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
    if tags.len() < ov::planned_tags().len() {
        args.push("--only".into());
        args.extend(tags.iter().map(|t| (*t).to_owned()));
    }
    let fake = FakeOutput::new(tags, &rm, &oracle);
    Setup {
        root,
        out,
        lab,
        fake,
        args,
    }
}
/// The case and the directory name of a scanner's working directory `<work>/<tag>.<run id>/cwd-<who>`, read by
/// path components (the hermetic tests also run on the Windows CI runner).
fn cwd_of(dir: &str) -> (String, String) {
    let p = Path::new(dir);
    let name = |p: Option<&Path>| {
        p.and_then(Path::file_name)
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    let run = name(p.parent());
    (
        run.split('.').next().unwrap_or_default().to_owned(),
        name(Some(p)),
    )
}
fn set_arg(args: &mut [String], k: &str, v: &str) {
    let i = args.iter().position(|x| x == k).unwrap();
    args[i + 1] = v.into();
}

#[test]
fn an_output_suite_directory_passes_output_verify() {
    let tags = ov::planned_tags();
    let s = setup(&tags);
    assert_eq!(linux_with(&s.args, &s.fake, &s.lab).unwrap(), 0);
    // wire-lab.sh's cleanup then deletes both namespaces and records the undo.
    fs::write(s.out.join(av::TEARDOWN_JSON), TEARDOWN).unwrap();
    let res = ov::verify_dir(&s.out);
    assert_eq!(res["overall"], "PASS", "{:#?}", bad(&res));
    let manifest = read_json(s.out.join("manifest.json")).unwrap();
    assert_eq!(manifest["output"], "linux");
    assert_eq!(manifest["lab_id"], LAB_ID);
    // Every case ran rmasscan once with the table's argv in its own working directory in the scanner namespace.
    let scans = s.fake.scans(&s.fake.rmasscan.clone());
    assert_eq!(scans.len(), tags.len());
    for c in ov::cases() {
        let mine: Vec<&Vec<String>> = scans
            .iter()
            .filter(|a| a.ends_with(&c.argv()) && cwd_of(&a[7]).0 == c.tag)
            .collect();
        assert_eq!(mine.len(), 1, "{}", c.tag);
        let a = mine[0];
        assert_eq!(
            &a[..7],
            &strings(&[
                IP,
                "netns",
                "exec",
                "wl-scan-41-42",
                SH,
                "-c",
                IN_DIR_SCRIPT
            ])[..]
        );
        assert_eq!(cwd_of(&a[7]).1, "cwd-rmasscan", "{a:?}");
        assert_eq!(a[8], s.fake.rmasscan);
    }
    // The oracle runs exactly the oracle cases, the same argv, /etc/masscan masked, in a directory of its own.
    let oracle = s.fake.scans(&s.fake.oracle.clone());
    assert_eq!(
        oracle.len(),
        ov::cases().iter().filter(|c| c.oracle).count()
    );
    for a in &oracle {
        assert_eq!(&a[4..7], &strings(&[SH, "-c", IN_DIR_SCRIPT])[..]);
        assert_eq!(cwd_of(&a[7]).1, "cwd-oracle", "{a:?}");
        assert_eq!(&a[8..11], &strings(&[UNSHARE, "-m", SH])[..]);
        let c = ov::cases()
            .iter()
            .find(|c| cwd_of(&a[7]).0 == c.tag)
            .unwrap();
        assert!(c.oracle && a.ends_with(&c.argv()), "{}", c.tag);
    }
    // The output files are in the evidence under their neutral names, byte for byte what the scanners wrote.
    for c in ov::cases().iter().filter(|c| c.writes_file()) {
        let run = s.out.join("runs").join(c.tag);
        let sim = &s.fake.sims[c.tag];
        assert_eq!(
            fs::read(run.join(c.format.file())).unwrap(),
            sim.rm.file.as_ref().unwrap().1,
            "{}",
            c.tag
        );
        if let Some(o) = &sim.oracle {
            assert_eq!(
                fs::read(run.join("oracle").join(c.format.file())).unwrap(),
                o.file.as_ref().unwrap().1
            );
        }
    }
    // o17 found o06's two outputs in each scanner's directory; nobody else found anything there.
    for (tag, who, names) in s.fake.cwd_files.borrow().iter() {
        let want: Vec<String> = if tag == "o17_readscan" {
            strings(&ov::READSCAN_INPUTS)
        } else {
            Vec::new()
        };
        let mut want = want;
        want.sort();
        assert_eq!(*names, want, "{tag} {who}");
    }
    let o17 = s.out.join("runs/o17_readscan");
    assert_eq!(
        fs::read(o17.join("input-rmasscan.bin")).unwrap(),
        fs::read(s.out.join("runs/o06_binary/output.bin")).unwrap()
    );
    assert_eq!(
        fs::read(o17.join("input-oracle.bin")).unwrap(),
        fs::read(s.out.join("runs/o06_binary/oracle/output.bin")).unwrap()
    );
    // Each run is sealed before and after; nothing was killed.
    for tag in &tags {
        assert!(
            s.out
                .join("runs")
                .join(tag)
                .join("isolation-post.json")
                .is_file(),
            "{tag}"
        );
    }
    assert!(!s.fake.log.borrow().iter().any(|x| x.ends_with(":KILL")));
    assert_eq!(
        fs::read_dir(s.out.join(".work")).unwrap().count(),
        1,
        "only wire-lab's own file is left"
    );
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn an_interrupt_sends_sigint_to_rmasscan_alone_two_seconds_after_its_start() {
    let s = setup(&["o14_interrupt_json"]);
    assert_eq!(linux_with(&s.args, &s.fake, &s.lab).unwrap(), 0);
    let log = s.fake.log.borrow().clone();
    let start = log.iter().position(|x| x == "start scanner").unwrap();
    let int = log.iter().position(|x| x == "signal scanner:INT").unwrap();
    // 40 polls of 50 ms, then the signal; the scanner is the only process that gets an INT.
    assert_eq!(
        log[start + 1..int].iter().filter(|x| *x == "pause").count(),
        40,
        "{log:?}"
    );
    assert_eq!(
        log.iter().filter(|x| x.ends_with(":INT")).count(),
        1,
        "{log:?}"
    );
    let rec: ov::InterruptRecord = serde_json::from_value(
        read_json(
            s.out
                .join("runs/o14_interrupt_json")
                .join(ov::INTERRUPT_JSON),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        rec,
        s.fake.sims["o14_interrupt_json"].interrupt.clone().unwrap()
    );
    assert!(s.fake.scans(&s.fake.oracle.clone()).is_empty());
    fs::write(s.out.join(av::TEARDOWN_JSON), TEARDOWN).unwrap();
    let res = ov::verify_dir(&s.out);
    let run = crate::verify::array(&res["runs"])
        .iter()
        .find(|r| r["tag"] == "o14_interrupt_json")
        .cloned()
        .unwrap();
    assert_eq!(run["verdict"], "PASS", "{:#?}", bad(&res));
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn a_scan_that_ignores_sigint_is_killed_and_the_kill_is_recorded() {
    let s = setup(&["o15_interrupt_xml"]);
    s.fake.ignores_int.set(true);
    assert_eq!(linux_with(&s.args, &s.fake, &s.lab).unwrap(), 0);
    let log = s.fake.log.borrow().clone();
    let int = log.iter().position(|x| x == "signal scanner:INT").unwrap();
    let kill = log.iter().position(|x| x == "signal scanner:KILL").unwrap();
    assert_eq!(
        log[int + 1..kill].iter().filter(|x| *x == "pause").count(),
        600,
        "30 s of polls"
    );
    let run = s.out.join("runs/o15_interrupt_xml");
    let rec = read_json(run.join(ov::INTERRUPT_JSON)).unwrap();
    assert_eq!(rec["killed"], true);
    assert_eq!(fs::read_to_string(run.join("exit.txt")).unwrap(), "-9\n");
    fs::write(s.out.join(av::TEARDOWN_JSON), TEARDOWN).unwrap();
    let res = ov::verify_dir(&s.out);
    let r = crate::verify::array(&res["runs"])
        .iter()
        .find(|r| r["tag"] == "o15_interrupt_xml")
        .cloned()
        .unwrap();
    assert_eq!(r["verdict"], "FAIL", "{:#?}", bad(&res));
    fs::remove_dir_all(s.root).unwrap();
}

/// An operator stop while rmasscan is still exiting after its SIGINT is honoured at the next poll, as before the
/// signal: INTERRUPTED at once (the abort then stops the scanner), not after the 30 s wait and a kill.
#[test]
fn an_operator_stop_after_sigint_is_honoured_at_once() {
    let s = setup(&["o16_interrupt_binary"]);
    s.fake.ignores_int.set(true);
    s.fake.stop_after_int.set(true);
    let e = linux_with(&s.args, &s.fake, &s.lab).unwrap_err();
    assert!(
        matches!(&e, SuiteError::Interrupted(m) if m.contains("o16_interrupt_binary")),
        "{e:?}"
    );
    let log = s.fake.log.borrow().clone();
    let int = log.iter().position(|x| x == "signal scanner:INT").unwrap();
    // No poll after the suite's own SIGINT: the next entry is the abort's stop of the scanner.
    assert_eq!(log[int + 1], "signal scanner:INT", "{log:?}");
    assert!(!s.out.join("runs/o16_interrupt_binary").exists());
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn readscan_needs_o06_in_the_same_out() {
    // Alone in a new --out: o06's outputs do not exist, nothing starts.
    let s = setup(&["o17_readscan"]);
    let e = linux_with(&s.args, &s.fake, &s.lab).unwrap_err();
    assert!(
        matches!(&e, SuiteError::NotRun(m) if m.contains("o06_binary")),
        "{e:?}"
    );
    assert!(s.fake.spawned.borrow().is_empty() && !s.out.join("manifest.json").exists());
    fs::remove_dir_all(s.root).unwrap();
    // After o06 ran into the same --out, a later invocation runs o17 alone.
    let s = setup(&["o06_binary", "o17_readscan"]);
    let mut first = s.args.clone();
    set_arg(&mut first, "--only", "o06_binary");
    first.retain(|a| a != "o17_readscan");
    assert_eq!(linux_with(&first, &s.fake, &s.lab).unwrap(), 0);
    let mut second = s.args.clone();
    set_arg(&mut second, "--only", "o17_readscan");
    second.retain(|a| a != "o06_binary");
    assert_eq!(linux_with(&second, &s.fake, &s.lab).unwrap(), 0);
    assert!(s.out.join("runs/o17_readscan/input-oracle.bin").is_file());
    // --readscan sends nothing: no responder is started for it.
    let responders = s
        .fake
        .spawned
        .borrow()
        .iter()
        .filter(|a| a.iter().any(|x| x == "responder"))
        .count();
    assert_eq!(responders, 2, "o06's two scanners only");
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn the_open_failure_runs_rmasscan_alone_and_keeps_no_output_file() {
    let s = setup(&["o13_open_fail"]);
    assert_eq!(linux_with(&s.args, &s.fake, &s.lab).unwrap(), 0);
    assert!(s.fake.scans(&s.fake.oracle.clone()).is_empty());
    let run = s.out.join("runs/o13_open_fail");
    assert_eq!(fs::read_to_string(run.join("exit.txt")).unwrap(), "1\n");
    assert!(!run.join("output.txt").exists() && !run.join("oracle").exists());
    assert_eq!(
        read_json(run.join("argv.json")).unwrap()["argv"][3],
        ov::UNOPENABLE
    );
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn the_output_suite_refuses_another_stand_before_anything_starts() {
    for (k, v) in [
        ("--iface-a", "eth0"),
        ("--mac-b", "02:ac:00:00:00:02"),
        ("--ns-b", "wl-scan-41-42"),
        ("--conf-masked", "2"),
        ("--rmasscan", "relative/rmasscan"),
        ("--lab-id", "a b"),
        ("--only", "o99_bogus"),
    ] {
        let s = setup(&["o01_list"]);
        let mut args = s.args.clone();
        set_arg(&mut args, k, v);
        let e = linux_with(&args, &s.fake, &s.lab).unwrap_err();
        assert!(matches!(e, SuiteError::NotRun(_)), "{k} {v}: {e:?}");
        assert!(s.fake.spawned.borrow().is_empty(), "{k} {v}");
        assert!(!s.out.join("manifest.json").exists(), "{k} {v}");
        fs::remove_dir_all(s.root).unwrap();
    }
    // Not root, or outside wire-lab.sh (no attestation of the sealed stand): nothing starts.
    let mut s = setup(&["o01_list"]);
    s.fake.euid = 1000;
    assert!(matches!(
        linux_with(&s.args, &s.fake, &s.lab),
        Err(SuiteError::NotRun(_))
    ));
    s.fake.euid = 0;
    fs::remove_file(s.out.join("isolation.json")).unwrap();
    let e = linux_with(&s.args, &s.fake, &s.lab).unwrap_err();
    assert!(
        matches!(&e, SuiteError::NotRun(m) if m.contains("wire-lab.sh --suite output")),
        "{e:?}"
    );
    assert!(s.fake.spawned.borrow().is_empty());
    fs::remove_dir_all(s.root).unwrap();
    // A directory of the autodetect suite is never extended by the output suite.
    let s = setup(&["o01_list"]);
    fs::write(
        s.out.join("manifest.json"),
        json!({"autodetect": "linux", "lab_id": LAB_ID}).to_string(),
    )
    .unwrap();
    let e = linux_with(&s.args, &s.fake, &s.lab).unwrap_err();
    assert!(
        matches!(&e, SuiteError::NotRun(m) if m.contains("output")),
        "{e:?}"
    );
    assert!(s.fake.spawned.borrow().is_empty());
    fs::remove_dir_all(s.root).unwrap();
}

#[test]
fn wire_lab_runs_the_output_suite_on_the_autodetect_stand() {
    let text =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/wire-lab.sh"))
            .unwrap();
    // `--suite output` needs --rmasscan, like autodetect.
    assert!(text.contains(r#"output) [ -n "$RMASSCAN_BIN" ] || { echo "--suite output needs --rmasscan" >&2; exit 64; } ;;"#));
    // The same fixed stand, the same refusal of an earlier lab's --out, the same lab id and teardown record.
    for needle in [
        r#"if [ "$STAND_SUITE" = 1 ]; then
  # Fixed stand"#,
        r#"if [ "$STAND_SUITE" = 1 ]; then
  # An earlier lab's directory"#,
        r#"[ "$STAND_SUITE" = 0 ] || autodetect_teardown"#,
        r#"elif [ "$STAND_SUITE" = 1 ] && [ -e "$WORK/work-kept.txt" ]; then"#,
    ] {
        assert!(text.contains(needle), "{needle}");
    }
    let suite = text
        .split("start_suite_group \"$OUT/suite.log\" \"$LAB_BIN\" output-suite linux")
        .nth(1)
        .and_then(|t| t.split("SUITE_PID=").next())
        .expect("the output suite's start");
    for flag in [
        r#"--lab-id "$LAB_ID""#,
        r#"--rmasscan "$RMASSCAN_BIN""#,
        r#"--conf-masked "$CONF_MASKED""#,
        r#"--work "$WORK""#,
    ] {
        assert!(suite.contains(flag), "{flag}: {suite}");
    }
    let cleanup = text
        .split("cleanup() {")
        .nth(1)
        .unwrap()
        .split("\ntrap cleanup EXIT")
        .next()
        .unwrap();
    let teardown = cleanup
        .find(r#"[ "$STAND_SUITE" = 0 ] || autodetect_teardown"#)
        .unwrap();
    assert!(
        cleanup.find(r#"ip netns del "$NS_B""#).unwrap() < teardown
            && teardown < cleanup.find("chown -R").unwrap()
    );
}
