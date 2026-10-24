//! Gate- and run-level tests of the Windows suite against a recording stand: nothing here
//! reaches ssh, scp, home-pc, the VM or the network. The stand answers each command from a
//! synthetic evidence directory (see verify_fixture.rs) and logs every call.
use super::*;
use crate::verify::fixture::{self, COMMIT, EXE, NPF, PM};
use std::cell::{Cell, RefCell};

#[derive(Default)]
struct Knobs {
    verify_rc: i32,
    report_nonce: Option<String>,
    report_npf: Option<String>,
    status: Option<Value>,
    record_rc: i32,
    eno1_frames: usize,
    fail_runner: bool,
}
struct Stand {
    src: PathBuf,
    log: RefCell<Vec<String>>,
    knobs: RefCell<Knobs>,
    tag: RefCell<String>,
    counter_calls: Cell<usize>,
    nonce: RefCell<String>,
}
fn out(rc: i32, stdout: &str) -> Result<Output, String> {
    Ok(Output {
        rc,
        stdout: stdout.into(),
        stderr: String::new(),
    })
}
impl Stand {
    fn new(src: &Path) -> Self {
        Self {
            src: src.to_path_buf(),
            log: RefCell::default(),
            knobs: RefCell::default(),
            tag: RefCell::default(),
            counter_calls: Cell::new(0),
            nonce: RefCell::default(),
        }
    }
    fn calls(&self) -> Vec<String> {
        self.log.borrow().clone()
    }
    fn count(&self, needle: &str) -> usize {
        self.log
            .borrow()
            .iter()
            .filter(|c| c.contains(needle))
            .count()
    }
    fn run_dir(&self) -> PathBuf {
        self.src.join("runs").join(&*self.tag.borrow())
    }
    fn pcap(&self, who: &str) -> Vec<u8> {
        let mut bytes = fs::read(self.run_dir().join(format!("{who}.pcap"))).unwrap();
        if who == "eno1" {
            let extra = self.knobs.borrow().eno1_frames;
            if extra > 0 {
                let (_, mut frames) = crate::pcap::read_pcap_records(&bytes).unwrap();
                for k in 0..extra {
                    frames.push((fixture::BASE + k as f64, fixture::scanner_syn(80, 40000)));
                }
                bytes = crate::pcap::encode(&frames);
            }
        }
        bytes
    }
    fn frames(&self, who: &str) -> usize {
        crate::pcap::read_pcap_records(&self.pcap(who))
            .unwrap()
            .1
            .len()
    }
    fn home(&self, cmd: &str) -> Result<Output, String> {
        let k = self.knobs.borrow();
        if cmd.contains("printf '%s' \"$HOME\"") {
            return out(0, "/home/a1");
        }
        if cmd.contains("cat /sys/class/net/lab0/address") {
            return out(0, &format!("{PM}\n"));
        }
        if cmd.contains("record-guest") {
            return out(k.record_rc, "{}");
        }
        if cmd.contains("vm-lab status") {
            let v = k
                .status
                .clone()
                .unwrap_or(json!({"raw_run_allowed":true,"isolation_violations":[],"ok":true}));
            return out(0, &v.to_string());
        }
        if cmd.contains("counters --iface lab0") {
            let n = self.counter_calls.get();
            self.counter_calls.set(n + 1);
            let rx = if n < 2 { 0 } else { self.frames("peer") };
            return out(0, &format!("{rx} 0\n"));
        }
        if cmd.contains("rx_dropped") {
            return out(0, "0\n");
        }
        if cmd.contains("sha256sum") {
            let mut s = String::new();
            for who in ["peer", "eno1"] {
                s += &format!("{}  {who}.pcap\n", hex_of(&Sha256::digest(self.pcap(who))));
            }
            for who in ["peer", "eno1"] {
                s += &format!("{who}.pcap {}\n", self.pcap(who).len());
            }
            return out(0, &s);
        }
        if cmd.contains("mkdir --") {
            // scratch_create: the leaf is the run tag.
            let leaf = cmd.rsplit("mkdir -- '").next().unwrap_or("");
            if let Some(tag) = leaf.trim_end_matches('\'').rsplit('/').next() {
                *self.tag.borrow_mut() = tag.into();
            }
            return out(0, "");
        }
        // Everything else the suite issues (waits, markers, background starts, stops,
        // sweeps, removals) succeeds silently.
        out(0, "")
    }
    fn guest(&self, cmd: &str) -> Result<Output, String> {
        let k = self.knobs.borrow();
        if cmd.contains("windows-vm-lab.ps1") {
            let nonce = cmd
                .split("-VerificationNonce \"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .unwrap_or("")
                .to_string();
            *self.nonce.borrow_mut() = nonce;
            return Ok(Output {
                rc: k.verify_rc,
                stdout: "verify stdout".into(),
                stderr: "verify stderr".into(),
            });
        }
        if cmd.contains("windows_wire_hash.ps1") {
            return out(0, &format!("{EXE}\n42\n"));
        }
        if cmd.contains("windows_wire_run.ps1") && k.fail_runner {
            return out(255, "");
        }
        out(0, "")
    }
    fn fetch(&self, remote: &str, local: &Path) -> Result<Output, String> {
        let name = remote.rsplit(['/', '\\']).next().unwrap_or("");
        let dir = self.run_dir();
        let k = self.knobs.borrow();
        let body: Option<Vec<u8>> = if name.ends_with(".verify.json") {
            Some(
                json!({
                    "ok":true,"errors":[],
                    "verification_nonce":k.report_nonce.clone().unwrap_or(self.nonce.borrow().clone()),
                    "verified_at":epoch(),
                    "lab":{"Status":"Up","Npf":NPF},
                    "npf":k.report_npf.clone().unwrap_or(NPF.into()),
                })
                .to_string()
                .into_bytes(),
            )
        } else {
            match name {
                "listener.json" => fs::read(dir.join("listeners.json")).ok(),
                "peer.pcap" => Some(self.pcap("peer")),
                "eno1.pcap" => Some(self.pcap("eno1")),
                "peer.err" | "eno1.err" => {
                    let n = self.frames(&name[..name.len() - 4]);
                    Some(format!("listening on x, link-type EN10MB\n{n} packets captured\n{n} packets received by filter\n0 packets dropped by kernel\n0 packets dropped by interface\n").into_bytes())
                }
                "flood.json" | "injector.json" | "linkloss.json" => fs::read(dir.join(name)).ok(),
                "stdout.txt" => {
                    let run = read_json(dir.join("run.json")).unwrap();
                    Some(format!("banner\n{run}\n").into_bytes())
                }
                "stderr.txt" => Some(Vec::new()),
                "exit.txt" => Some(b"0\n".to_vec()),
                "runner.json" => Some(
                    json!({"exe":"C:\\x\\wire_scan.exe","exe_sha256":EXE,"argc":1,"times":{"started_utc":1.0,"finished_utc":2.0}})
                        .to_string()
                        .into_bytes(),
                ),
                "nic.json" => fs::read(dir.join("nic.json")).ok().or(Some(
                    json!({"nic":"Ethernet 2","before":{"utc":1.0,"stats":{}},"after":{"utc":2.0,"stats":{}}})
                        .to_string()
                        .into_bytes(),
                )),
                _ => None,
            }
        };
        match body {
            Some(b) => {
                fs::write(local, b).map_err(|e| e.to_string())?;
                out(0, "")
            }
            None => out(1, ""),
        }
    }
}
impl Exec for Stand {
    fn exec(&self, argv: &[String], _timeout: u64) -> Result<Output, String> {
        let last = argv.last().cloned().unwrap_or_default();
        match argv[0].as_str() {
            "ssh" => {
                let guest = argv.iter().any(|a| a == "lab@127.0.0.1");
                self.log
                    .borrow_mut()
                    .push(format!("{} {last}", if guest { "guest" } else { "home" }));
                if guest {
                    self.guest(&last)
                } else {
                    self.home(&last)
                }
            }
            "scp" => {
                let src = argv[argv.len() - 2].clone();
                self.log.borrow_mut().push(format!("scp {src} {last}"));
                for prefix in ["home-pc:", "lab@127.0.0.1:"] {
                    if let Some(remote) = src.strip_prefix(prefix) {
                        return self.fetch(remote, Path::new(&last));
                    }
                }
                out(0, "")
            }
            other => Err(format!("unexpected program {other}")),
        }
    }
    fn pause(&self, _: Duration) {}
}
struct World {
    root: PathBuf,
    src: PathBuf,
}
impl World {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "rmasscan-suite-{name}-{}-{}",
            std::process::id(),
            nonce()
        ));
        let (root, src) = (base.join("out"), base.join("src"));
        fs::create_dir_all(&root).unwrap();
        fixture::build_failure(&src, 3);
        // The suite writes its own runs: start from the manifest and fixtures only.
        copy_tree(&src.join("fixtures"), &root.join("fixtures")).unwrap();
        fs::copy(src.join("manifest.json"), root.join("manifest.json")).unwrap();
        Self { root, src }
    }
}
impl Drop for World {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.root.parent().unwrap());
    }
}
fn suite<'a>(stand: &'a Stand, root: &Path) -> Suite<'a> {
    Suite {
        exec: stand,
        out: root.to_path_buf(),
        suite: "failure".into(),
        run_id: "r00112233445566778899aabbccddeeff".into(),
        remote: "/home/a1/rmasscan-lab".into(),
        remote_ev: "/home/a1/winvm/t4-ev".into(),
        qmp: "/home/a1/winvm/qmp.sock".into(),
        manifest: "/home/a1/winvm/lab/n2.json".into(),
        guest_exe: "C:\\x\\wire_scan.exe".into(),
        plan: "failure".into(),
        timeout: 240,
        pm: PM.into(),
    }
}
const TAG: &str = "perm_elevated_control";
fn item(tag: &str) -> Value {
    crate::verify::planned(&json!({"plan":"failure"}))
        .into_iter()
        .find(|i| i["tag"] == tag)
        .unwrap()
}
fn argv_for(tag: &str, w: &World) -> Vec<String> {
    let man = read_json(w.root.join("manifest.json")).unwrap();
    let paths = BTreeMap::from([
        ("--checkpoint-out".to_string(), "C:\\cp\\x.bin".to_string()),
        (
            "--resume-checkpoint".to_string(),
            "C:\\cp\\x.bin".to_string(),
        ),
    ]);
    crate::verify::expected_args(&item(tag), &man, &paths).unwrap()
}
fn scratch(w: &World, stand: &Stand, tag: &str) -> PathBuf {
    *stand.tag.borrow_mut() = tag.into();
    let ev = w.root.join("runs").join(tag);
    fs::create_dir_all(&ev).unwrap();
    ev
}

// ---- run(): validation happens before any remote command ----
fn suite_args(w: &World, extra: &[&str]) -> Vec<String> {
    let mut a = strings(&[
        "--out",
        w.root.to_str().unwrap(),
        "--commit",
        COMMIT,
        "--guest-exe",
        "C:\\x\\wire_scan.exe",
        "--fixtures",
        w.root.join("fixtures").to_str().unwrap(),
        "--remote-lab",
        "/home/a1/rmasscan-lab",
        "--plan",
        "failure",
    ]);
    a.extend(strings(extra));
    a
}
#[test]
fn invalid_suite_ids_and_tags_are_refused_before_any_remote_command() {
    let w = World::new("validate");
    // A fresh output directory: no existing manifest can mask a missing check.
    let fresh = w.root.parent().unwrap().join("fresh-out");
    fs::create_dir_all(&fresh).unwrap();
    let args_for = |extra: &[&str]| {
        let mut a = suite_args(&w, extra);
        a[1] = fresh.to_str().unwrap().into();
        a
    };
    for bad in ["../functional", "a b", "x;rm -rf ~", "", "-x", "a..b"] {
        let stand = Stand::new(&w.src);
        let r = run_with(&args_for(&["--suite", bad]), &stand);
        assert!(
            matches!(r, Err(SuiteError::NotRun(_))),
            "--suite {bad:?}: {r:?}"
        );
        assert!(
            stand.calls().is_empty(),
            "--suite {bad:?} reached a remote command"
        );
    }
    for bad in ["../x", "c01 x", "stop_silent;id", "nonexistent", "-x"] {
        let stand = Stand::new(&w.src);
        let r = run_with(
            &suite_args(&w, &["--suite", "failure", "--only", bad]),
            &stand,
        );
        assert!(
            matches!(r, Err(SuiteError::NotRun(_))),
            "--only {bad:?}: {r:?}"
        );
        assert!(
            stand.calls().is_empty(),
            "--only {bad:?} reached a remote command"
        );
    }
    let stand = Stand::new(&w.src);
    for (flag, value) in [
        ("--guest-exe", "C:\\x&y.exe"),
        ("--guest-exe", "C:\\%PATH%\\x.exe"),
        ("--remote-lab", "relative/lab"),
        ("--commit", "abc"),
    ] {
        let mut a = args_for(&["--suite", "failure"]);
        let at = a.iter().position(|x| x == flag).unwrap();
        a[at + 1] = value.into();
        assert!(
            matches!(run_with(&a, &stand), Err(SuiteError::NotRun(_))),
            "{flag} {value}"
        );
    }
    assert!(stand.calls().is_empty());
}
#[test]
fn old_schema_and_refused_rerun_have_their_own_exit_codes_and_touch_nothing() {
    let w = World::new("codes");
    // A directory written by schema 2 cannot be extended.
    let mut man = read_json(w.root.join("manifest.json")).unwrap();
    man["capture_schema"] = json!(2);
    write_json(w.root.join("manifest.json"), &man).unwrap();
    let stand = Stand::new(&w.src);
    let a = suite_args(&w, &["--suite", "failure"]);
    let e = run_with(&a, &stand).unwrap_err();
    assert!(matches!(e, SuiteError::SchemaTooOld(_)), "{e:?}");
    assert_eq!(e.code(), 12);
    assert!(stand.calls().is_empty());
    // A behaviour failure is never discarded by --rerun.
    man["capture_schema"] = json!(3);
    write_json(w.root.join("manifest.json"), &man).unwrap();
    copy_tree(
        &w.src.join("runs").join("stop_silent"),
        &w.root.join("runs/stop_silent"),
    )
    .unwrap();
    let run = w.root.join("runs/stop_silent/run.json");
    let mut j = read_json(&run).unwrap();
    j["reason"] = json!("Failed");
    write_json(&run, &j).unwrap();
    crate::verify::fixture::reseal(&w.root.join("runs/stop_silent"));
    let a = suite_args(
        &w,
        &["--suite", "failure", "--rerun", "--only", "stop_silent"],
    );
    let e = run_with(&a, &stand).unwrap_err();
    assert!(matches!(e, SuiteError::RerunRefused(_)), "{e:?}");
    assert_eq!(e.code(), 11);
    assert!(stand.calls().is_empty());
    assert!(w.root.join("runs/stop_silent").is_dir(), "nothing moved");
    assert_eq!(
        [
            EXIT_NOT_RUN,
            EXIT_ABORT,
            EXIT_RERUN_REFUSED,
            EXIT_SCHEMA_TOO_OLD
        ],
        [2, 10, 11, 12]
    );
    assert_eq!(SuiteError::Abort(String::new()).code(), 10);
    assert_eq!(SuiteError::NotRun(String::new()).code(), 2);
}

// ---- gate ----
#[test]
fn gate_binds_the_nonce_records_the_verify_and_only_then_reports_status() {
    let w = World::new("gate-ok");
    let stand = Stand::new(&w.src);
    let s = suite(&stand, &w.root);
    let ev = scratch(&w, &stand, TAG);
    let rc = s
        .gate(&ev, "/home/a1/winvm/t4-ev/failure/r/x", TAG)
        .unwrap();
    assert_eq!(rc, 0);
    let calls = stand.calls();
    let nonce = invocation_nonce(&s.run_id, TAG);
    let order: Vec<usize> = [
        "-Action Verify",
        "scp lab@127.0.0.1",
        "scp /",
        "record-guest",
        "vm-lab status",
    ]
    .iter()
    .map(|n| {
        calls
            .iter()
            .position(|c| c.contains(n))
            .unwrap_or_else(|| panic!("{n} missing in {calls:?}"))
    })
    .collect();
    assert!(
        order.windows(2).all(|w| w[0] < w[1]),
        "gate order {order:?}"
    );
    assert!(calls[order[0]].contains(&format!("-VerificationNonce \"{nonce}\"")));
    assert!(calls[order[0]].contains(&format!("failure.{TAG}.{}.verify.json", s.run_id)));
    assert!(
        calls[order[3]].contains(&format!("--nonce '{nonce}'")),
        "{}",
        calls[order[3]]
    );
    assert_eq!(
        fs::read_to_string(ev.join("guest-verify-stdout.txt")).unwrap(),
        "verify stdout"
    );
    assert_eq!(
        fs::read_to_string(ev.join("guest-verify-stderr.txt")).unwrap(),
        "verify stderr"
    );
}
#[test]
fn failed_verify_aborts_before_fetching_recording_or_asking_for_status() {
    let w = World::new("gate-rc");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().verify_rc = 1;
    let s = suite(&stand, &w.root);
    let ev = scratch(&w, &stand, TAG);
    // An old successful report is sitting on the guest: it must never be fetched.
    assert!(s.gate(&ev, "/r", TAG).is_err());
    assert_eq!(stand.count("scp lab@127.0.0.1"), 0, "{:?}", stand.calls());
    assert_eq!(stand.count("record-guest"), 0);
    assert_eq!(stand.count("vm-lab status"), 0);
}
#[test]
fn report_of_another_invocation_aborts_before_record_guest() {
    let w = World::new("gate-nonce");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().report_nonce = Some("someone-elses-nonce".into());
    let s = suite(&stand, &w.root);
    let ev = scratch(&w, &stand, TAG);
    assert!(s.gate(&ev, "/r", TAG).unwrap_err().contains("nonce"));
    assert_eq!(stand.count("record-guest"), 0);
    assert_eq!(stand.count("vm-lab status"), 0);
}
#[test]
fn lab_nic_must_be_the_one_the_scanner_is_told_to_open() {
    let w = World::new("gate-npf");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().report_npf =
        Some("\\Device\\NPF_{00000000-0000-0000-0000-000000000000}".into());
    let s = suite(&stand, &w.root);
    let ev = scratch(&w, &stand, TAG);
    assert!(s.gate(&ev, "/r", TAG).unwrap_err().contains("--iface"));
    assert_eq!(stand.count("record-guest"), 0);
}
#[test]
fn isolation_refusal_or_any_violation_aborts_the_gate() {
    for status in [
        json!({"raw_run_allowed":false,"isolation_violations":[]}),
        json!({"raw_run_allowed":true,"isolation_violations":["bridge has a host address"]}),
        json!({"isolation_violations":[]}),
        json!({"raw_run_allowed":"true","isolation_violations":[]}),
    ] {
        let w = World::new("gate-status");
        let stand = Stand::new(&w.src);
        stand.knobs.borrow_mut().status = Some(status.clone());
        let s = suite(&stand, &w.root);
        let ev = scratch(&w, &stand, TAG);
        assert!(
            s.gate(&ev, "/r", TAG).unwrap_err().contains("isolation"),
            "{status}"
        );
    }
}
#[test]
fn record_guest_refusal_aborts_before_status() {
    let w = World::new("gate-record");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().record_rc = 1;
    let s = suite(&stand, &w.root);
    let ev = scratch(&w, &stand, TAG);
    assert!(s.gate(&ev, "/r", TAG).is_err());
    assert_eq!(stand.count("vm-lab status"), 0);
}

// ---- one(): nothing raw starts unless the gate passed ----
const RAW_STARTERS: [&str; 7] = [
    "listen --open",
    "tcpdump",
    "marker --iface",
    "inject --iface",
    "flood --guest-mac",
    "windows_wire_run.ps1",
    "windows_wire_runas.cmd",
];
#[test]
fn a_refused_gate_starts_no_listener_capture_marker_or_scanner() {
    let w = World::new("one-refused");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().status =
        Some(json!({"raw_run_allowed":false,"isolation_violations":[]}));
    let s = suite(&stand, &w.root);
    let argv = argv_for(TAG, &w);
    assert!(s.one(&item(TAG), argv, None, None).is_err());
    for raw in RAW_STARTERS {
        assert_eq!(stand.count(raw), 0, "{raw} started after a refused gate");
    }
    // Cleanup of whatever could have been recorded still runs, and the scratch is kept and copied home.
    assert!(stand.count("read -r pid born extra") >= 1);
    assert_eq!(
        stand.count("rm -rf"),
        0,
        "failure evidence must stay on the remote"
    );
    assert!(
        stand
            .calls()
            .iter()
            .any(|c| c.starts_with("scp -q -r") || c.contains("home-pc:/home/a1/winvm/t4-ev"))
    );
}
#[test]
fn guest_scanner_failure_keeps_remote_scratch_and_stops_the_remote_tools() {
    let w = World::new("one-runner");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().fail_runner = true;
    let s = suite(&stand, &w.root);
    let argv = argv_for(TAG, &w);
    assert!(s.one(&item(TAG), argv, None, None).is_err());
    assert_eq!(stand.count("rm -rf"), 0);
    assert!(
        stand.count("read -r pid born extra") >= 6,
        "all six pidfiles are stopped"
    );
}
#[test]
fn background_tools_run_under_a_dead_man_timeout() {
    let w = World::new("one-deadman");
    let stand = Stand::new(&w.src);
    let s = suite(&stand, &w.root);
    let argv = argv_for(TAG, &w);
    s.one(&item(TAG), argv, None, None).unwrap();
    let bg: Vec<String> = stand
        .calls()
        .into_iter()
        .filter(|c| c.contains("nohup sudo -n sh -c"))
        .collect();
    assert_eq!(bg.len(), 3, "listener, peer capture, eno1 capture: {bg:?}");
    for c in &bg {
        assert!(
            c.contains("exec timeout -k 10 "),
            "no dead-man timeout: {c}"
        );
    }
    for who in ["listen --open", "-i lab0", "-i eno1"] {
        assert!(
            bg.iter().any(|c| c.contains(who)),
            "{who} not started in the background"
        );
    }
}
#[test]
fn complete_run_writes_schema_3_evidence_that_the_verifier_passes() {
    let w = World::new("one-closed");
    let stand = Stand::new(&w.src);
    let s = suite(&stand, &w.root);
    let argv = argv_for(TAG, &w);
    s.one(&item(TAG), argv, None, None).unwrap();
    let ev = w.root.join("runs").join(TAG);
    let cap = read_json(ev.join("capture.json")).unwrap();
    assert_eq!(cap["capture_schema"], 3);
    let meta = read_json(ev.join("meta.json")).unwrap();
    assert_eq!(meta["invocation_nonce"], invocation_nonce(&s.run_id, TAG));
    assert_eq!(meta["guest_verify_exit"], 0);
    for f in [
        "guest-verify-stdout.txt",
        "guest-verify-stderr.txt",
        "run-artifacts.json",
    ] {
        assert!(ev.join(f).is_file(), "{f}");
    }
    let proof = read_json(ev.join("run-artifacts.json")).unwrap();
    assert!(
        proof["files"]
            .as_object()
            .unwrap()
            .contains_key("guest-verify-stdout.txt")
    );
    // The suite and the verifier agree on the whole contract.
    let verdict = crate::verify::run_status(&w.root, TAG);
    assert_eq!(
        verdict,
        ("PASS".to_string(), false),
        "{}",
        crate::verify::verify_dir(&w.root)["runs"]
    );
    assert_eq!(
        stand.count("rm -rf"),
        1,
        "a successful run removes only its own scratch"
    );
    let rm = stand
        .calls()
        .into_iter()
        .find(|c| c.contains("rm -rf"))
        .unwrap();
    assert!(
        rm.contains(&format!(
            "'/home/a1/winvm/t4-ev/failure/{}/{TAG}'",
            s.run_id
        )),
        "{rm}"
    );
    assert!(rm.contains("readlink -f") && rm.contains("test ! -L"));
}
#[test]
fn eno1_lab_frames_abort_the_suite_before_the_next_raw_run() {
    let w = World::new("interlock");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().eno1_frames = 1;
    let a = suite_args(&w, &["--suite", "failure", "--only", TAG, "rxloss"]);
    let e = run_with(&a, &stand).unwrap_err();
    assert!(
        matches!(&e, SuiteError::Abort(m) if m.contains("eno1 interlock")),
        "{e:?}"
    );
    assert_eq!(e.code(), 10);
    // The first run's evidence is written (so the verifier can blame it); the second never starts.
    assert!(w.root.join("runs").join(TAG).join("capture.json").is_file());
    assert_eq!(stand.count("rxloss"), 0, "{:?}", stand.calls());
    assert_eq!(stand.count("-Action Verify"), 1, "exactly one gate ran");
    assert_eq!(crate::verify::run_status(&w.root, TAG).0, "FAIL");
}
#[test]
fn eno1_interlock_treats_unreadable_captures_as_unproven() {
    assert!(eno1_interlock(&json!({"eno1":{"pcap":{"frames":0}}})).is_ok());
    assert!(eno1_interlock(&json!({"eno1":{"pcap":{"frames":1}}})).is_err());
    assert!(eno1_interlock(&json!({"eno1":{"pcap":{"frames":null}}})).is_err());
    assert!(eno1_interlock(&json!({"eno1":{}})).is_err());
    assert!(eno1_interlock(&json!({})).is_err());
}

// ---- I6: cleanup and the start-of-suite sweep ----
#[test]
fn cleanup_stops_recorded_processes_by_start_time_then_removes_only_the_suite_scratch() {
    let w = World::new("cleanup");
    let stand = Stand::new(&w.src);
    let r = run_with(&strings(&["--cleanup", "--suite", "failure"]), &stand).unwrap();
    assert_eq!(r, 0);
    let calls = stand.calls();
    let term = calls
        .iter()
        .position(|c| c.contains("kill -TERM"))
        .expect("TERM sweep");
    let kill = calls
        .iter()
        .position(|c| c.contains("kill -KILL"))
        .expect("KILL sweep");
    let rm = calls
        .iter()
        .position(|c| c.contains("rm -rf"))
        .expect("scratch removal");
    assert!(term < kill && kill < rm, "{calls:?}");
    for sweep in [&calls[term], &calls[kill]] {
        // pid and start time must both match before any signal.
        assert!(sweep.contains("read -r pid born extra"));
        assert!(
            sweep.find("test \"$actual\" != \"$born\"").unwrap()
                < sweep.find("sudo -n kill").unwrap()
        );
        assert!(
            sweep.contains("/home/a1/winvm/t4-ev'/*/*/*/*.pid"),
            "{sweep}"
        );
    }
    assert!(
        calls[rm].contains("'/home/a1/winvm/t4-ev/failure'"),
        "{}",
        calls[rm]
    );
    assert!(
        calls
            .iter()
            .all(|c| !c.contains("windows-vm-lab") && !c.contains("tcpdump"))
    );
    // An unsafe suite id never reaches rm.
    let stand = Stand::new(&w.src);
    assert!(run_with(&strings(&["--cleanup", "--suite", "../x"]), &stand).is_err());
    assert!(stand.calls().is_empty());
}
#[test]
fn every_suite_start_sweeps_before_it_creates_anything() {
    let w = World::new("start-sweep");
    let stand = Stand::new(&w.src);
    // Run nothing: --only names a tag and the stand refuses the gate.
    stand.knobs.borrow_mut().verify_rc = 1;
    let a = suite_args(&w, &["--suite", "failure", "--only", TAG]);
    assert!(run_with(&a, &stand).is_err());
    let calls = stand.calls();
    let sweep = calls
        .iter()
        .position(|c| c.contains("kill -TERM"))
        .expect("start sweep");
    let first_create = calls
        .iter()
        .position(|c| {
            c.contains("mkdir -p") || c.contains("windows_wire_prepare") || c.contains("mkdir --")
        })
        .unwrap();
    assert!(sweep < first_create, "{calls:?}");
}
#[test]
fn sweep_script_skips_a_reused_pid() {
    let cmd = sweep_command("/home/a1/winvm/t4-ev", "TERM");
    assert!(cmd.starts_with("for pidfile in '/home/a1/winvm/t4-ev'/*/*/*/*.pid; do ( "));
    assert!(cmd.contains("if test \"$actual\" != \"$born\"; then exit 0; fi"));
    assert!(cmd.ends_with("; done; true"));
}
#[test]
fn scratch_removal_is_quoted_and_symlink_checked() {
    let cmd = remove_scratch_command("/home/a1/winvm/t4-ev/s/n/it's");
    assert_eq!(
        cmd.matches("'/home/a1/winvm/t4-ev/s/n/it'\"'\"'s'").count(),
        4,
        "{cmd}"
    );
    assert!(
        cmd.contains("readlink -f --") && cmd.contains("test ! -L") && cmd.contains("rm -rf --")
    );
    assert!(cmd.find("readlink").unwrap() < cmd.find("rm -rf").unwrap());
    let space = remove_scratch_command("/x/a b");
    assert!(!space.contains("rm -rf -- /x/a b"), "{space}");
}

// ---- smaller findings ----
#[test]
fn guest_directories_are_prepared_by_a_script_file() {
    let w = World::new("prepare");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().verify_rc = 1;
    let a = suite_args(&w, &["--suite", "failure", "--only", TAG]);
    let _ = run_with(&a, &stand);
    let guest: Vec<String> = stand
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("guest "))
        .collect();
    assert!(guest.iter().all(|c| !c.contains("-Command")), "{guest:?}");
    assert!(guest.iter().any(|c| c.contains(
        "-File C:\\Users\\lab\\t4\\windows_wire_prepare.ps1 -Suite \"failure\" -RunId \"r"
    )));
    let prep = stand
        .calls()
        .iter()
        .position(|c| c.starts_with("guest ") && c.contains("windows_wire_prepare.ps1"))
        .unwrap();
    let copied = stand
        .calls()
        .iter()
        .position(|c| c.contains("windows_wire_prepare.ps1") && c.starts_with("scp"))
        .unwrap();
    assert!(copied < prep, "the script is copied before it is run");
    let script = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/windows_wire_prepare.ps1"),
    )
    .unwrap();
    assert!(
        script.contains("[Parameter(Mandatory)][string]$Suite")
            && !script.contains("Invoke-Expression")
    );
}
#[test]
fn nonces_come_from_the_os_rng_and_fit_the_powershell_contract() {
    let (a, b) = (nonce(), nonce());
    assert_ne!(a, b);
    for n in [&a, &b] {
        assert_eq!(n.len(), 33, "r + 16 bytes as hex");
        assert!(n.starts_with('r') && n[1..].bytes().all(|c| c.is_ascii_hexdigit()));
    }
    let invocation = invocation_nonce(&a, "pause_N8");
    assert!((16..=128).contains(&invocation.len()));
    assert_ne!(invocation, invocation_nonce(&a, "pause_N0"));
    assert_ne!(invocation, invocation_nonce(&b, "pause_N8"));
}
#[test]
fn schema_age_gate() {
    assert!(schema_too_old(&json!({})));
    assert!(schema_too_old(&json!({"capture_schema":2})));
    assert!(!schema_too_old(&json!({"capture_schema":CAPTURE_SCHEMA})));
    assert_eq!(CAPTURE_SCHEMA, 3);
}
