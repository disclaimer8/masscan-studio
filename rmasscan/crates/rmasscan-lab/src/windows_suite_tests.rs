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
    lab_binary: Vec<u8>,
    guest_clock_offset: f64,
    tamper_script: Option<String>,
    missing_script: Option<String>,
}
struct Stand {
    src: PathBuf,
    log: RefCell<Vec<String>>,
    knobs: RefCell<Knobs>,
    tag: RefCell<String>,
    counter_calls: Cell<usize>,
    nonce: RefCell<String>,
    commit_reads: RefCell<Vec<(String, String)>>,
}
/// The "installed" Linux binary of the fake stand; the default deploy manifest vouches for it.
const LAB_BINARY: &[u8] = b"rmasscan-lab test binary";
const REMOTE_LAB: &str = "/home/a1/rmasscan-lab";
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
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
            knobs: RefCell::new(Knobs {
                lab_binary: LAB_BINARY.to_vec(),
                ..Knobs::default()
            }),
            tag: RefCell::default(),
            counter_calls: Cell::new(0),
            nonce: RefCell::default(),
            commit_reads: RefCell::default(),
        }
    }
    fn script_bytes(&self, name: &str) -> Option<Vec<u8>> {
        crate::deploy::GUEST_SCRIPTS
            .iter()
            .any(|(n, _)| *n == name)
            .then(|| fs::read(repo_root().join("rmasscan/scripts").join(name)).ok())
            .flatten()
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
        if cmd.contains("pwd -P") {
            return out(0, "/home/a1");
        }
        if cmd.contains("cat /sys/class/net/lab0/address") {
            return out(0, &format!("{PM}\n"));
        }
        if cmd == format!("sha256sum -- '{REMOTE_LAB}'") {
            return out(
                0,
                &format!(
                    "{}  {REMOTE_LAB}\n",
                    crate::deploy::sha256_hex(&k.lab_binary)
                ),
            );
        }
        if cmd == "date -u +%s.%N" {
            return out(0, &format!("{:.3}\n", epoch()));
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
        if cmd.contains("windows_wire_clock.ps1") && !cmd.contains("windows_wire_hash.ps1") {
            return out(0, &format!("{:.3}\n", epoch() + k.guest_clock_offset));
        }
        if cmd.contains("windows_wire_hash.ps1") {
            let path = cmd
                .split("-Path \"")
                .nth(1)
                .and_then(|s| s.split('"').next());
            let name = path.and_then(|p| p.rsplit('\\').next()).unwrap_or("");
            if let Some(mut bytes) = self.script_bytes(name) {
                if k.tamper_script.as_deref() == Some(name) {
                    bytes.push(b'x');
                }
                return out(
                    0,
                    &format!("{}\n{}\n", crate::deploy::sha256_hex(&bytes), bytes.len()),
                );
            }
            return out(0, &format!("{EXE}\n42\n"));
        }
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
    fn file_at_commit(&self, _repo: &Path, commit: &str, path: &str) -> Result<Vec<u8>, String> {
        self.commit_reads
            .borrow_mut()
            .push((commit.into(), path.into()));
        if self
            .knobs
            .borrow()
            .missing_script
            .as_deref()
            .is_some_and(|m| path.ends_with(m))
        {
            return Err("path does not exist in the commit".into());
        }
        fs::read(repo_root().join(path)).map_err(|e| e.to_string())
    }
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
    deploy: PathBuf,
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
        let deploy = base.join("deploy.json");
        write_json(
            &deploy,
            &crate::deploy::build_manifest(COMMIT, REMOTE_LAB, LAB_BINARY, "rustc test", 1.0),
        )
        .unwrap();
        Self { root, src, deploy }
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
        "--deploy-manifest",
        w.deploy.to_str().unwrap(),
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
fn an_aborted_run_is_copied_from_its_own_scratch_into_runs_aborted_under_tag_and_run_id() {
    // WR N3: the copy source and destination are pinned exactly, not just "some scp -r".
    let w = World::new("one-aborted-copy");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().fail_runner = true;
    let s = suite(&stand, &w.root);
    let argv = argv_for(TAG, &w);
    assert!(s.one(&item(TAG), argv, None, None).is_err());
    let want = format!(
        "scp home-pc:/home/a1/winvm/t4-ev/failure/{id}/{TAG}/. {out}/runs_aborted/{TAG}.{id}",
        id = s.run_id,
        out = w.root.display()
    );
    let copies: Vec<String> = stand
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("scp home-pc:") && c.contains("/. "))
        .collect();
    assert_eq!(copies, vec![want]);
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
            // the evidence-root bootstrap `mkdir -p -- ev` is the one create allowed before the sweep
            (c.contains("mkdir -p") && !c.ends_with("winvm/t4-ev'"))
                || c.contains("windows_wire_prepare")
                || c.contains("mkdir --")
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
        6,
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

// ---- I8: deployment provenance and preflights ----
fn gate_failing_args(w: &World) -> Vec<String> {
    suite_args(w, &["--suite", "failure", "--only", TAG])
}
fn mutating(call: &str) -> bool {
    // Anything beyond reading $HOME and hashing the binary changes or starts something.
    !(call.contains("pwd -P") || call.contains("sha256sum --"))
}
#[test]
fn a_remote_binary_that_is_not_in_the_manifest_is_refused_before_anything_runs() {
    let w = World::new("binary-hash");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().lab_binary = b"a rebuilt or replaced binary".to_vec();
    let e = run_with(&gate_failing_args(&w), &stand).unwrap_err();
    assert!(
        matches!(&e, SuiteError::NotRun(m) if m.contains("not in the deploy manifest")),
        "{e:?}"
    );
    assert_eq!(e.code(), 2);
    let calls = stand.calls();
    assert!(
        calls.iter().any(|c| c.contains("sha256sum --")),
        "the hash is checked: {calls:?}"
    );
    assert!(
        calls.iter().all(|c| !mutating(c)),
        "nothing ran, swept, copied or started: {calls:?}"
    );
}
#[test]
fn the_vouched_binary_passes_and_its_hash_is_recorded_in_the_evidence() {
    let w = World::new("binary-ok");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().verify_rc = 1; // stop at the first gate: the preflights are done
    let _ = run_with(&gate_failing_args(&w), &stand);
    let pre = fs::read_dir(w.root.join("deploy"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with("preflight-"))
        .expect("preflight record")
        .path();
    let rec = read_json(pre).unwrap();
    assert_eq!(rec["commit"], COMMIT);
    assert_eq!(
        rec["remote_lab"]["sha256"],
        crate::deploy::sha256_hex(LAB_BINARY)
    );
    assert_eq!(rec["remote_lab"]["path"], REMOTE_LAB);
    assert_eq!(
        rec["deploy_manifest_sha256"],
        hash(&w.deploy).unwrap(),
        "the manifest that vouched is the one recorded"
    );
    assert_eq!(
        fs::read(w.root.join("deploy/deploy-manifest.json")).unwrap(),
        fs::read(&w.deploy).unwrap()
    );
}
#[test]
fn a_manifest_for_another_commit_or_binary_path_or_a_missing_one_is_refused_locally() {
    let w = World::new("manifest-refusals");
    for (label, manifest) in [
        (
            "other commit",
            crate::deploy::build_manifest(&"f".repeat(40), REMOTE_LAB, LAB_BINARY, "", 1.0),
        ),
        (
            "other path",
            crate::deploy::build_manifest(COMMIT, "/home/a1/other-lab", LAB_BINARY, "", 1.0),
        ),
        ("not a manifest", json!({"hello": 1})),
    ] {
        write_json(&w.deploy, &manifest).unwrap();
        let stand = Stand::new(&w.src);
        let r = run_with(&gate_failing_args(&w), &stand);
        assert!(matches!(r, Err(SuiteError::NotRun(_))), "{label}: {r:?}");
        assert!(stand.calls().is_empty(), "{label}: {:?}", stand.calls());
    }
    let stand = Stand::new(&w.src);
    let mut a = gate_failing_args(&w);
    let at = a.iter().position(|x| x == "--deploy-manifest").unwrap();
    a.drain(at..at + 2);
    let r = run_with(&a, &stand);
    assert!(
        matches!(&r, Err(SuiteError::NotRun(m)) if m.contains("--deploy-manifest")),
        "{r:?}"
    );
    assert!(stand.calls().is_empty());
}
#[test]
fn guest_scripts_come_from_the_commit_and_their_hashes_are_evidence() {
    let w = World::new("guest-scripts");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().verify_rc = 1;
    let _ = run_with(&gate_failing_args(&w), &stand);
    // Every script was read from the tree of --commit.
    let reads = stand.commit_reads.borrow().clone();
    assert_eq!(reads.len(), crate::deploy::GUEST_SCRIPTS.len());
    assert!(
        reads
            .iter()
            .all(|(c, p)| c == COMMIT && p.starts_with("rmasscan/scripts/"))
    );
    // windows-vm-lab.ps1 is deployed too (the old guest copy made every gate fail), at the
    // path the gate runs it from.
    let calls = stand.calls();
    assert!(
        calls.iter().any(|c| c.starts_with("scp ")
            && c.contains("guest-scripts/windows-vm-lab.ps1")
            && c.ends_with("lab@127.0.0.1:windows-vm-lab.ps1")),
        "{calls:?}"
    );
    // The copies are taken from the evidence staging area, never from the build tree.
    let build_tree = repo_root().join("rmasscan/scripts");
    let build_tree = build_tree.to_string_lossy();
    for c in calls
        .iter()
        .filter(|c| c.starts_with("scp ") && c.contains(" lab@127.0.0.1:"))
    {
        assert!(
            !c.contains(&*build_tree) && c.contains("/deploy/guest-scripts/"),
            "{c}"
        );
    }
    // Hashes in the preflight record equal the bytes of the staged evidence copies and of the
    // committed scripts.
    let pre = fs::read_dir(w.root.join("deploy"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with("preflight-"))
        .unwrap()
        .path();
    let rec = read_json(pre).unwrap();
    for (name, _) in crate::deploy::GUEST_SCRIPTS {
        let staged = w.root.join("deploy/guest-scripts").join(name);
        let committed = fs::read(repo_root().join("rmasscan/scripts").join(name)).unwrap();
        assert_eq!(fs::read(&staged).unwrap(), committed, "{name}");
        assert_eq!(
            rec["guest_scripts"][*name]["sha256"],
            crate::deploy::sha256_hex(&committed),
            "{name}"
        );
    }
    assert_eq!(
        rec["guest_scripts"].as_object().unwrap().len(),
        crate::deploy::GUEST_SCRIPTS.len()
    );
}
#[test]
fn a_script_missing_at_the_commit_is_refused_before_any_remote_command() {
    let w = World::new("script-missing");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().missing_script = Some("windows-vm-lab.ps1".into());
    let e = run_with(&gate_failing_args(&w), &stand).unwrap_err();
    assert!(
        matches!(&e, SuiteError::NotRun(m) if m.contains("windows-vm-lab.ps1")),
        "{e:?}"
    );
    assert!(stand.calls().is_empty(), "{:?}", stand.calls());
}
#[test]
fn a_guest_copy_that_differs_from_the_commit_stops_the_suite_before_the_gate() {
    let w = World::new("guest-tamper");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().tamper_script = Some("windows-vm-lab.ps1".into());
    let e = run_with(&gate_failing_args(&w), &stand).unwrap_err();
    assert!(
        matches!(&e, SuiteError::NotRun(m) if m.contains("windows-vm-lab.ps1") && m.contains("does not match")),
        "{e:?}"
    );
    assert_eq!(stand.count("-Action Verify"), 0);
    assert_eq!(stand.count("windows_wire_prepare.ps1 -Suite"), 0);
}
#[test]
fn clock_skew_beyond_plus_five_or_minus_sixty_seconds_refuses_every_raw_run() {
    for (offset, refused) in [
        (0.0, false),
        (3.0, false),
        (-30.0, false),
        (8.0, true),
        (-90.0, true),
    ] {
        let w = World::new("clock");
        let stand = Stand::new(&w.src);
        {
            let mut k = stand.knobs.borrow_mut();
            k.guest_clock_offset = offset;
            k.verify_rc = 1; // a passing clock reaches the (failing) gate
        }
        let r = run_with(&gate_failing_args(&w), &stand);
        if refused {
            assert!(
                matches!(&r, Err(SuiteError::NotRun(m)) if m.contains("clock")),
                "{offset}: {r:?}"
            );
            assert_eq!(stand.count("-Action Verify"), 0, "{offset}");
            assert_eq!(
                stand.count("windows_wire_prepare.ps1 -Suite"),
                0,
                "{offset}"
            );
        } else {
            assert!(
                !matches!(&r, Err(SuiteError::NotRun(m)) if m.contains("clock")),
                "{offset}: {r:?}"
            );
            assert_eq!(stand.count("-Action Verify"), 1, "{offset}");
        }
    }
}
#[test]
fn the_clock_reading_is_recorded_in_the_preflight_evidence() {
    let w = World::new("clock-record");
    let stand = Stand::new(&w.src);
    {
        let mut k = stand.knobs.borrow_mut();
        k.guest_clock_offset = -12.0;
        k.verify_rc = 1;
    }
    let _ = run_with(&gate_failing_args(&w), &stand);
    let pre = fs::read_dir(w.root.join("deploy"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with("preflight-"))
        .unwrap()
        .path();
    let rec = read_json(pre).unwrap();
    let offset = rec["clock"]["guest_minus_home_s"].as_f64().unwrap();
    assert!((offset + 12.0).abs() < 2.0, "{offset}");
    assert_eq!(rec["clock"]["limits"]["guest_ahead_s"], 5.0);
    assert_eq!(rec["clock"]["limits"]["guest_behind_s"], 60.0);
}
#[test]
fn the_clock_limits_are_the_ones_record_guest_enforces() {
    // One definition: the preflight and record-guest cannot drift apart.
    let source = include_str!("vm_lab.rs");
    assert!(source.contains("verified > now() + VERIFY_FUTURE_SKEW_S"));
    assert!(source.contains("now() - verified > VERIFY_MAX_AGE_S"));
    assert_eq!(crate::vm_lab::VERIFY_FUTURE_SKEW_S, 5.0);
    assert_eq!(crate::vm_lab::VERIFY_MAX_AGE_S, 60.0);
}

// ---- F5: the remote sweep against a real local shell (WR N1, N2) ----
//
// `LocalHome` answers the `ssh home-pc CMD` calls by running CMD in a local `sh` with a private
// HOME and a `sudo` stub that drops `-n` and execs the rest. Nothing leaves this machine.
#[cfg(unix)]
mod local_sweep {
    use super::*;
    use std::process::{Command, Stdio};

    pub(super) struct LocalHome {
        pub home: PathBuf,
        bin: PathBuf,
    }
    impl LocalHome {
        pub(super) fn new(tag: &str) -> Self {
            let base = std::env::temp_dir().join(format!(
                "rmasscan-localhome-{tag}-{}-{}",
                std::process::id(),
                nonce()
            ));
            fs::create_dir_all(&base).unwrap();
            let base = base.canonicalize().unwrap(); // macOS: /var -> /private/var
            let home = base.join("home");
            let bin = base.join("bin");
            fs::create_dir_all(&home).unwrap();
            fs::create_dir_all(&bin).unwrap();
            let sudo = bin.join("sudo");
            fs::write(
                &sudo,
                "#!/bin/sh\nif [ \"$1\" = -n ]; then shift; fi\nexec \"$@\"\n",
            )
            .unwrap();
            let _ = Command::new("chmod").arg("+x").arg(&sudo).status();
            Self { home, bin }
        }
        pub(super) fn base(&self) -> PathBuf {
            self.home.parent().unwrap().to_path_buf()
        }
    }
    impl Drop for LocalHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(self.base());
        }
    }
    impl Exec for LocalHome {
        fn exec(&self, argv: &[String], _timeout: u64) -> Result<Output, String> {
            assert_eq!(argv[0], "ssh", "only home-pc calls are local: {argv:?}");
            let cmd = argv.last().unwrap();
            let path = format!(
                "{}:{}",
                self.bin.display(),
                std::env::var("PATH").unwrap_or_default()
            );
            let o = Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .env("HOME", &self.home)
                .env("PATH", path)
                .stdin(Stdio::null())
                .output()
                .map_err(|e| e.to_string())?;
            Ok(Output {
                rc: o.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
            })
        }
        fn file_at_commit(&self, _: &Path, _: &str, _: &str) -> Result<Vec<u8>, String> {
            Err("not used".into())
        }
        fn pause(&self, d: Duration) {
            thread::sleep(d.min(Duration::from_millis(300)));
        }
    }

    fn sh(cmd: &str) -> i32 {
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .stdin(Stdio::null())
            .status()
            .unwrap()
            .code()
            .unwrap_or(-1)
    }

    #[test]
    fn removing_a_scratch_directory_that_does_not_exist_is_a_clean_no_op() {
        // WR N1: `readlink -f` of a path whose parents are missing prints nothing, which used to
        // fail the check and end every suite start in NOT RUN.
        let h = LocalHome::new("rm-missing");
        let p = h.home.join("winvm/t4-ev/failure");
        assert_eq!(sh(&remove_scratch_command(&p.to_string_lossy())), 0);
        assert!(
            !h.home.join("winvm").exists(),
            "nothing is created by a removal"
        );
        // An existing run directory is still removed...
        fs::create_dir_all(p.join("run/tag")).unwrap();
        assert_eq!(sh(&remove_scratch_command(&p.to_string_lossy())), 0);
        assert!(!p.exists());
        // ...but a symlink in its place, or a symlinked parent, is still refused and kept.
        let target = h.base().join("elsewhere");
        fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &p).unwrap();
        assert_ne!(sh(&remove_scratch_command(&p.to_string_lossy())), 0);
        assert!(target.exists() && p.is_symlink());
        let _ = fs::remove_file(&p);
        let linked = h.base().join("linked");
        std::os::unix::fs::symlink(h.home.join("winvm"), &linked).unwrap();
        fs::create_dir_all(h.home.join("winvm/t4-ev/failure")).unwrap();
        let via = linked.join("t4-ev/failure");
        assert_ne!(sh(&remove_scratch_command(&via.to_string_lossy())), 0);
        assert!(h.home.join("winvm/t4-ev/failure").exists());
    }

    #[test]
    fn the_sweep_creates_the_evidence_root_and_works_on_a_first_ever_start() {
        let h = LocalHome::new("first-start");
        assert!(!h.home.join("winvm").exists());
        sweep_remote(&h, "failure").unwrap();
        assert!(h.home.join("winvm/t4-ev").is_dir());
        // A second call (the --cleanup path) is equally clean.
        sweep_remote(&h, "failure").unwrap();
    }

    #[test]
    fn the_sweep_works_when_home_is_reached_through_a_symlink() {
        // macOS-style: /var -> /private/var. The sweep compares real paths, so it must use one.
        let h = LocalHome::new("symlink-home");
        let link = h.base().join("home-link");
        std::os::unix::fs::symlink(&h.home, &link).unwrap();
        struct Linked<'a>(&'a LocalHome, PathBuf);
        impl Exec for Linked<'_> {
            fn exec(&self, argv: &[String], t: u64) -> Result<Output, String> {
                let mut a = argv.to_vec();
                *a.last_mut().unwrap() = format!(
                    "HOME='{}'; export HOME; {}",
                    self.1.display(),
                    a.last().unwrap()
                );
                self.0.exec(&a, t)
            }
            fn file_at_commit(&self, _: &Path, _: &str, _: &str) -> Result<Vec<u8>, String> {
                Err("unused".into())
            }
            fn pause(&self, d: Duration) {
                self.0.pause(d);
            }
        }
        let l = Linked(&h, link);
        sweep_remote(&l, "failure").unwrap();
        assert!(h.home.join("winvm/t4-ev").is_dir());
    }

    /// A pidfile line as `Suite::bg` writes it, for a TERM-ignoring tool under the dead-man.
    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_kills_a_tool_that_ignores_term_not_only_its_timeout_wrapper() {
        // WR N2: the pidfile pid is the `timeout` wrapper; SIGKILL to it alone orphans the tool.
        let h = LocalHome::new("kill-tool");
        let ev = h.home.join("winvm/t4-ev");
        let dir = ev.join("failure/r1/tag");
        fs::create_dir_all(&dir).unwrap();
        let toolpid = dir.join("tool.pid");
        let w = Suite {
            exec: &h,
            out: h.base(),
            suite: "failure".into(),
            run_id: "r1".into(),
            remote: "/unused".into(),
            remote_ev: ev.to_string_lossy().into_owned(),
            qmp: String::new(),
            manifest: String::new(),
            guest_exe: String::new(),
            plan: "failure".into(),
            timeout: 240,
            pm: PM.into(),
        };
        // The real wrapper of `Suite::bg`, around a TERM-ignoring shell.
        let tool = format!(
            "sh -c 'trap \"\" TERM; echo $$ > {}; while :; do sleep 1; done'",
            quote(&toolpid.to_string_lossy())
        );
        let pidfile = dir.join("x.pid");
        w.bg(
            &tool,
            &pidfile.to_string_lossy(),
            &dir.join("x.err").to_string_lossy(),
            120,
        )
        .unwrap();
        for _ in 0..100 {
            if toolpid.exists() && fs::read_to_string(&toolpid).is_ok_and(|s| !s.trim().is_empty())
            {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let tool_pid: i32 = fs::read_to_string(&toolpid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(alive(tool_pid), "the tool must be running before the sweep");
        sweep_remote(&h, "failure").unwrap();
        for _ in 0..100 {
            if !alive(tool_pid) {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let survived = alive(tool_pid);
        if survived {
            let _ = Command::new("kill")
                .args(["-KILL", &tool_pid.to_string()])
                .status();
        }
        assert!(!survived, "the TERM-ignoring tool survived --cleanup");
    }

    #[cfg(target_os = "linux")]
    fn alive(pid: i32) -> bool {
        // /proc state: a zombie is gone for our purposes.
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .map(|s| !s.rsplit(") ").next().unwrap_or("").starts_with('Z'))
            .unwrap_or(false)
    }
}

// ---- F5 (WR N4): the orchestrator build is recorded with the evidence ----
#[test]
fn a_new_evidence_directory_records_the_orchestrator_build_in_manifest_and_preflight() {
    let w = World::new("orchestrator-build");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().verify_rc = 1; // stop at the first gate: the manifest is already written
    let out = w.root.parent().unwrap().join("fresh-out");
    let a = strings(&[
        "--out",
        out.to_str().unwrap(),
        "--commit",
        COMMIT,
        "--guest-exe",
        "C:\\x\\wire_scan.exe",
        "--fixtures",
        w.src.join("fixtures").to_str().unwrap(),
        "--remote-lab",
        "/home/a1/rmasscan-lab",
        "--deploy-manifest",
        w.deploy.to_str().unwrap(),
        "--plan",
        "failure",
        "--only",
        TAG,
    ]);
    let _ = run_with(&a, &stand);
    let man = read_json(out.join("manifest.json")).expect("a new directory gets a manifest");
    let orch = &man["orchestrator"];
    assert_eq!(crate::provenance::problem(orch), None, "{orch}");
    let exe = fs::read(std::env::current_exe().unwrap()).unwrap();
    assert_eq!(orch["binary_sha256"], crate::deploy::sha256_hex(&exe));
    let pre = fs::read_dir(out.join("deploy"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with("preflight-"))
        .expect("preflight record")
        .path();
    assert_eq!(
        read_json(pre).unwrap()["orchestrator"],
        *orch,
        "every start records the build that ran it"
    );
}
