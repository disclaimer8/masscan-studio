//! The banners suite against a recording host: nothing here opens an interface, runs a process or writes a frame. The
//! scanners' outputs, exits and captures come from the verifier's synthetic generator (`banners_verify::tests::Sim`);
//! the suite writes the evidence directory itself and `banners-verify` judges it, so the layout the suite writes and
//! the layout the verifier reads are tested against each other.
use super::*;
use crate::{
    autodetect_suite::{Running, SH, p2s},
    autodetect_verify::{
        self as av,
        tests::{LAB_ID, Sim as AdSim, TEARDOWN, linux_isolation},
    },
    banners_verify::tests::Sim,
    pcap,
    protocols_suite::{
        ECHO_IGNORE, PROTOCOLS, RATEMASK,
        tests::{FakeRun, after, bad, not_run_text, slashes, strings},
    },
    scan_control_suite::IN_DIR_SCRIPT,
    scan_control_verify::Who,
    verify::PASS,
    windows_suite::{Output, nonce},
};
use std::{cell::RefCell, fs, rc::Rc, time::Duration};

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-banners-suite-{}", nonce()));
    fs::create_dir_all(&d).unwrap();
    d
}

/// The netns stand as the suite sees it, played from the generator's cases.
struct FakeBanners {
    sims: BTreeMap<&'static str, Sim>,
    rmasscan: String,
    oracle: String,
    euid: u32,
    current: RefCell<&'static str>,
    spawned: RefCell<Vec<Vec<String>>>,
    execs: RefCell<Vec<Vec<String>>>,
    log: Rc<RefCell<Vec<String>>>,
    /// What the peer namespace's `icmp_ratemask` reads.
    ratemask: RefCell<String>,
}
impl FakeBanners {
    fn new(tags: &[&'static str], rmasscan: &Path, oracle: &Path) -> Self {
        FakeBanners {
            sims: tags.iter().map(|t| (*t, Sim::new(t))).collect(),
            rmasscan: p2s(rmasscan),
            oracle: p2s(oracle),
            euid: 0,
            current: RefCell::new(""),
            spawned: RefCell::default(),
            execs: RefCell::default(),
            log: Rc::default(),
            ratemask: RefCell::new("0".into()),
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
    fn of(&self, program: &str) -> Vec<Vec<String>> {
        self.spawned
            .borrow()
            .iter()
            .filter(|a| a.iter().any(|x| x == program))
            .cloned()
            .collect()
    }
}
impl LinuxHost for FakeBanners {
    fn exec(&self, argv: &[String], _timeout: u64) -> Result<Output, String> {
        self.note(argv, &[]);
        self.execs.borrow_mut().push(argv.to_vec());
        if argv.iter().any(|a| a == "isolation") {
            fs::write(after(argv, "--out"), linux_isolation()).unwrap();
        }
        let stdout = match argv.last().map(String::as_str) {
            Some(RATEMASK) => format!("{}\n", self.ratemask.borrow()),
            Some(ECHO_IGNORE) => "0\n".into(),
            Some(PROTOCOLS) => "UDP       1152      0       2   NI       0   yes  kernel\n".into(),
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
            fs::write(after(argv, "--ready"), "listening 80,8080 udp 53\n").unwrap();
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
        fs::write(stderr, &step.stderr).unwrap();
        fs::write(cwd.join(step.spec.out.file().unwrap()), step.doc()).unwrap();
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
    fake: FakeBanners,
    args: Vec<String>,
}
fn setup(tags: &[&'static str]) -> Setup {
    let root = scratch();
    let out = root.join("linux-banners-r1");
    let work = out.join(".work");
    fs::create_dir_all(&work).unwrap();
    fs::write(work.join("host-links-before.txt"), "eno1\nlo\n").unwrap();
    fs::write(out.join(bv::ISOLATION_JSON), linux_isolation()).unwrap();
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
    if tags.len() < bv::planned_tags().len() {
        args.push("--only".into());
        args.extend(tags.iter().map(|t| (*t).to_owned()));
    }
    let fake = FakeBanners::new(tags, &rm, &oracle);
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

#[test]
fn the_suite_writes_what_the_verifier_reads_for_every_case() {
    let s = setup(&bv::planned_tags());
    assert_eq!(run_suite(&s).unwrap(), 0);
    fs::write(s.out.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = bv::verify_dir(&s.out);
    assert_eq!(res["overall"], PASS, "{:#?}", bad(&res));
    for tag in bv::planned_tags() {
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
        for step in bv::steps(tag).unwrap() {
            for f in [
                "argv.json",
                "stdout.txt",
                "stderr.txt",
                "exit.txt",
                "peer.pcap",
                "capture.json",
                "peer.err",
                "responder.json",
                step.out.file().unwrap(),
            ] {
                assert!(
                    d.join(step.name).join(f).is_file(),
                    "{tag}/{} {f}",
                    step.name
                );
            }
        }
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(s.out.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["banners"], "linux");
    fs::remove_dir_all(&s.root).unwrap();
}

#[test]
fn every_step_has_its_own_scenario_responder_and_the_tables_argv() {
    let s = setup(&["b01_banners"]);
    assert_eq!(run_suite(&s).unwrap(), 0);
    let responders = s.fake.of("responder");
    assert_eq!(responders.len(), 4, "one responder per step");
    for r in &responders {
        // ip netns exec <peer ns> <lab> capture responder <options> --ready <file>
        assert_eq!(
            &r[..3],
            &strings(&[crate::autodetect_suite::IP, "netns", "exec"])[..]
        );
        assert_eq!(r[3], "wl-peer-41-42");
        let at = r.iter().position(|a| a == "responder").unwrap();
        let ready = r.iter().position(|a| a == "--ready").unwrap();
        assert_eq!(r[at + 1..ready], bv::responder_args()[..]);
    }
    assert_eq!(after(&bv::responder_args(), "--udp-answer"), "banners");
    assert_eq!(
        after(&bv::responder_args(), "--udp-ports"),
        "53,123,137,161,500,1900,5683,11211,16464"
    );
    let steps = bv::steps("b01_banners").unwrap();
    for (who, program) in [
        (Who::Rmasscan, &s.fake.rmasscan),
        (Who::Oracle, &s.fake.oracle),
    ] {
        let runs = s.fake.of(program);
        let want: Vec<&StepSpec> = steps.iter().filter(|x| x.who == who).collect();
        assert_eq!(runs.len(), want.len());
        for (argv, spec) in runs.iter().zip(want) {
            // The scanner namespace, the constant script, its own working directory, then the table's argv.
            assert_eq!(argv[3], "wl-scan-41-42");
            let tail = &argv[argv.len() - spec.argv.len()..];
            assert_eq!(tail, &spec.argv[..], "{}", spec.name);
        }
    }
    fs::remove_dir_all(&s.root).unwrap();
}

#[test]
fn a_peer_that_rate_limits_icmp_errors_refuses_the_suite_before_anything_starts() {
    let s = setup(&bv::planned_tags());
    *s.fake.ratemask.borrow_mut() = "6168".into();
    let m = not_run_text(run_suite(&s));
    assert!(m.contains("icmp_ratemask is 6168"), "{m}");
    assert!(s.fake.spawned.borrow().is_empty(), "nothing was started");
    fs::remove_dir_all(&s.root).unwrap();
}

#[test]
fn only_root_inside_the_banners_stand_may_run_it_and_only_the_tables_cases() {
    let mut s = setup(&bv::planned_tags());
    s.fake.euid = 1000;
    let m = not_run_text(run_suite(&s));
    assert!(
        m.contains("runs as root inside wire-lab.sh --suite banners"),
        "{m}"
    );
    let mut s2 = setup(&bv::planned_tags());
    s2.args
        .extend(strings(&["--only", "p02_udp_payloads_and_closed"]));
    let m = not_run_text(run_suite(&s2));
    assert!(m.contains("is not a banners case"), "{m}");
    // wire-lab.sh's isolation.json must attest the sealed stand.
    let s3 = setup(&bv::planned_tags());
    fs::remove_file(s3.out.join(bv::ISOLATION_JSON)).unwrap();
    let m = not_run_text(run_suite(&s3));
    assert!(m.contains("wire-lab.sh --suite banners"), "{m}");
    for x in [s, s2, s3] {
        fs::remove_dir_all(&x.root).unwrap();
    }
}

#[test]
fn every_target_of_the_table_is_on_the_stand() {
    for tag in bv::planned_tags() {
        for s in bv::steps(tag).unwrap() {
            assert!(
                addresses_outside_the_lab(&s.argv).is_empty(),
                "{tag}/{}",
                s.name
            );
        }
    }
}

// ------------------------------------------------------------------ wire-lab.sh

#[test]
fn wire_lab_raises_the_banners_stand_as_the_protocols_stand_and_starts_the_banners_suite() {
    let text =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/wire-lab.sh"))
            .unwrap();
    assert!(text.contains(
        r#"banners) [ -n "$RMASSCAN_BIN" ] || { echo "--suite banners needs --rmasscan" >&2; exit 64; } ;;"#
    ));
    assert!(text.contains(r#"[ "$SUITE" != banners ] || STAND_SUITE=1"#));
    // The protocols stand's one change, for this suite too: no ICMP error rate limit, in the peer namespace only.
    assert!(
        text.lines()
            .any(|l| l == r#"[ "$SUITE" != banners ] || nsb sysctl -qw net.ipv4.icmp_ratemask=0"#)
    );
    for l in text
        .lines()
        .filter(|l| l.contains("icmp_ratemask") && !l.trim_start().starts_with('#'))
    {
        assert!(
            l.contains("nsb ") || l.contains("note_cmd") || l.contains("$NS_B"),
            "an ICMP setting outside the peer namespace: {l}"
        );
    }
    // The seal is the autodetect stand's (no IPv6, no second link).
    for l in text.lines().filter(|l| l.contains("ISOLATION_MODE=")) {
        assert!(!l.contains("banners"), "{l}");
    }
    let suite = text
        .split("start_suite_group \"$OUT/suite.log\" \"$LAB_BIN\" banners-suite linux")
        .nth(1)
        .and_then(|t| t.split("SUITE_PID=").next())
        .expect("the banners suite's start");
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
                .filter(|l| l.contains("banners"))
                .any(|l| l.contains(banned) && !l.trim_start().starts_with('#')),
            "{banned}"
        );
    }
}
