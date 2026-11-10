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
    status_nonce: Option<String>,
    report_npf: Option<String>,
    status: Option<Value>,
    record_rc: i32,
    eno1_frames: usize,
    fail_runner: bool,
    lab_binary: Vec<u8>,
    guest_clock_offset: f64,
    tamper_script: Option<String>,
    missing_script: Option<String>,
    /// The process has been asked to stop (Ctrl-C): ordinary exec calls die like `command()` does.
    stopped: bool,
    /// Raise `stopped` the moment the guest scanner runner is started (and let it fail).
    stop_at_runner: bool,
    lock_held: bool,
    /// `scp -r remote/. local` copies nothing.
    no_dir_copy: bool,
    /// Every home-pc ssh/scp fails (set by `down_after_runner` once the guest runner was invoked).
    home_down: bool,
    down_after_runner: bool,
    /// The peer start marker command fails.
    fail_marker: bool,
    /// The remote eno1.pcap cannot be read.
    eno1_unreadable: bool,
    /// The scratch holds a sub-directory (the marker-clearing command refuses).
    subdir_present: bool,
    /// Raise `stopped` when the guest Verify (the gate) is invoked.
    stop_at_verify: bool,
    /// Canned orchestrator provenance: the suite then reads no `git` (the autodetect tests start no process at all).
    provenance: Option<Value>,
    /// The sha256 the guest runner reports for the executable it ran (default: `EXE`, what the guest hash reports).
    runner_exe_sha: Option<String>,
    /// What `windows_wire_hash.ps1` reports for the scanner executable (default: `EXE`).
    exe_hash: Option<String>,
    /// The executable the guest runner reports it ran (`runner.json` `exe`; default: the plan's own scanner).
    runner_exe: Option<String>,
    /// The account that started the orchestrator (`Exec::account`; default: none).
    account: Option<String>,
}
struct Stand {
    src: PathBuf,
    log: RefCell<Vec<String>>,
    knobs: RefCell<Knobs>,
    tag: RefCell<String>,
    counter_calls: Cell<usize>,
    nonce: RefCell<String>,
    recorded_nonce: RefCell<String>,
    commit_reads: RefCell<Vec<(String, String)>>,
    pauses: RefCell<Vec<Duration>>,
    locks: Cell<usize>,
    /// The remote keep marker (path) and whether a sweep deleted a scratch directory.
    marker: RefCell<Option<String>>,
    deleted: Cell<bool>,
    created: Cell<bool>,
    /// The local destination of every copy of a guest `stdout.txt` (autodetect stand).
    stdout_fetches: RefCell<Vec<PathBuf>>,
}
/// The "installed" Linux binary of the fake stand; the default deploy manifest vouches for it.
const LAB_BINARY: &[u8] = b"rmasscan-lab test binary";
const REMOTE_LAB: &str = "/home/a1/rmasscan-lab";
fn repo_root() -> PathBuf {
    Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../..")
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
            recorded_nonce: RefCell::default(),
            commit_reads: RefCell::default(),
            pauses: RefCell::default(),
            locks: Cell::new(0),
            marker: RefCell::default(),
            deleted: Cell::new(false),
            created: Cell::new(false),
            stdout_fetches: RefCell::default(),
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
        if k.home_down {
            return Err("ssh: connect to host home-pc: Connection refused".into());
        }
        if cmd.contains("peer marker") && k.fail_marker {
            return Err("ssh: connection reset".into());
        }
        if cmd.starts_with("touch -- ") && cmd.contains(ABORT_MARKER) {
            let p = cmd.trim_start_matches("touch -- ").trim_matches('\'');
            *self.marker.borrow_mut() = Some(p.to_owned());
            self.created.set(true);
            return out(0, "");
        }
        if cmd.contains("rm -f --") && cmd.contains(ABORT_MARKER) {
            if cmd.contains("find .") && k.subdir_present {
                return out(1, "");
            }
            *self.marker.borrow_mut() = None;
            return out(0, "");
        }
        if cmd.starts_with("if test -e") && cmd.contains("rm -rf --") {
            *self.marker.borrow_mut() = None;
            return out(0, "");
        }
        if cmd.contains("kept-uncopied") {
            if let Some(m) = self.marker.borrow().as_ref() {
                let dir = m.trim_end_matches(&format!("/{ABORT_MARKER}"));
                return out(0, &format!("kept-uncopied {dir}\n"));
            }
            if self.created.get() {
                self.deleted.set(true);
            }
            return out(0, "");
        }
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
            let recorded = cmd
                .split("--nonce '")
                .nth(1)
                .and_then(|s| s.split('\'').next())
                .unwrap_or("");
            *self.recorded_nonce.borrow_mut() = recorded.to_string();
            return out(k.record_rc, "{}");
        }
        if cmd.contains("vm-lab status") {
            // The real status reports the nonce of the guest Verify it relied on (host-only: null).
            let v = k.status.clone().unwrap_or(json!({
                "raw_run_allowed":true,"isolation_violations":[],"ok":true,
                "guest_verify_nonce":k.status_nonce.clone().unwrap_or(self.recorded_nonce.borrow().clone())
            }));
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
        if cmd.contains("eno1_size=") {
            let n = self.frames("eno1");
            let size = if k.eno1_unreadable {
                -1
            } else if n == 0 {
                24
            } else {
                24 + 100 * n as i64
            };
            return out(
                0,
                &format!(
                    "eno1_size={size} frames={n}\nlistening on x, link-type EN10MB\n{n} packets captured\n{n} packets received by filter\n0 packets dropped by kernel\n0 packets dropped by interface\n"
                ),
            );
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
            self.counter_calls.set(0);
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
            let exe = k.exe_hash.clone().unwrap_or_else(|| EXE.into());
            return out(0, &format!("{exe}\n42\n"));
        }
        if cmd.contains("windows-vm-lab.ps1") {
            if k.stop_at_verify {
                drop(k);
                self.knobs.borrow_mut().stopped = true;
                return out(255, "");
            }
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
        if cmd.contains("windows_wire_run.ps1")
            && (k.fail_runner || k.stop_at_runner || k.down_after_runner)
        {
            drop(k);
            if self.knobs.borrow().stop_at_runner {
                self.knobs.borrow_mut().stopped = true;
            }
            if self.knobs.borrow().down_after_runner {
                self.knobs.borrow_mut().home_down = true;
            }
            return out(255, "");
        }
        out(0, "")
    }
    fn fetch(&self, remote: &str, local: &Path) -> Result<Output, String> {
        let name = remote.rsplit(['/', '\\']).next().unwrap_or("");
        let dir = self.run_dir();
        let k = self.knobs.borrow();
        if name == "." {
            if k.no_dir_copy {
                return out(1, "");
            }
            fs::create_dir_all(local).map_err(|e| e.to_string())?;
            for who in ["peer", "eno1"] {
                fs::write(local.join(format!("{who}.pcap")), self.pcap(who))
                    .map_err(|e| e.to_string())?;
            }
            // `scp -r DIR/.` copies dot files too: the keep marker comes home with the scratch while it is set.
            if self.marker.borrow().is_some() {
                fs::write(local.join(ABORT_MARKER), "").map_err(|e| e.to_string())?;
            }
            return out(0, "");
        }
        let guest = dir.join("guest");
        let body: Option<Vec<u8>> = if guest.is_dir()
            && matches!(name, "stdout.txt" | "stderr.txt" | "exit.txt")
        {
            // An autodetect stand: what the guest runner wrote for this run (or for its `--offline` preflight).
            if name == "stdout.txt" {
                self.stdout_fetches.borrow_mut().push(local.to_path_buf());
            }
            let file = if remote.contains(".preflight/") {
                format!("preflight-{name}")
            } else {
                name.to_owned()
            };
            fs::read(guest.join(file)).ok()
        } else if guest.join("restricted").exists() && name.ends_with(".runner.rc") {
            // Only windows_wire_restricted.cmd writes these: `echo %errorlevel% > OUT.runner.rc`, the runner's log.
            Some(b"0 \r\n".to_vec())
        } else if guest.join("restricted").exists() && name.ends_with(".runner.log") {
            Some(Vec::new())
        } else if name.ends_with(".verify.json") {
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
                    json!({"exe":k.runner_exe.clone().unwrap_or_else(|| if guest.is_dir() { RMASSCAN_EXE } else { "C:\\x\\wire_scan.exe" }.into()),"exe_sha256":k.runner_exe_sha.clone().unwrap_or_else(|| EXE.into()),"argc":1,"times":{"started_utc":1.0,"finished_utc":2.0}})
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
    fn exec(&self, argv: &[String], timeout: u64) -> Result<Output, String> {
        // The real `command()` kills its child as soon as the stop flag is up.
        if self.knobs.borrow().stopped {
            self.log.borrow_mut().push(format!(
                "killed {}",
                argv.last().cloned().unwrap_or_default()
            ));
            return out(130, "");
        }
        self.exec_uninterruptible(argv, timeout)
    }
    fn exec_uninterruptible(&self, argv: &[String], _timeout: u64) -> Result<Output, String> {
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
                if self.knobs.borrow().home_down {
                    return Err("scp: connect to host home-pc: Connection refused".into());
                }
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
    fn pause(&self, d: Duration) {
        self.pauses.borrow_mut().push(d);
        self.log
            .borrow_mut()
            .push(format!("pause {}s", d.as_secs()));
    }
    fn stopped(&self) -> bool {
        self.knobs.borrow().stopped
    }
    fn account(&self) -> Option<String> {
        self.knobs.borrow().account.clone()
    }
    fn lock_suite(&self) -> Result<LockGuard, String> {
        if self.knobs.borrow().lock_held {
            return Err(LOCK_BUSY.into());
        }
        self.locks.set(self.locks.get() + 1);
        Ok(LockGuard::none())
    }
    fn provenance(&self, repo: &Path) -> Value {
        let canned = self.knobs.borrow().provenance.clone();
        canned.unwrap_or_else(|| crate::provenance::collect(repo))
    }
}
struct World {
    root: PathBuf,
    src: PathBuf,
    deploy: PathBuf,
    /// A tiny throwaway git repository for `--repo`: the suite records the orchestrator build
    /// (commit, dirty flag) from it, and the tests must not depend on the tree they run in
    /// (`git archive` exports have no .git).
    repo: PathBuf,
}
impl World {
    fn new(name: &str) -> Self {
        Self::build(name, |src| fixture::build_failure(src, 3))
    }
    /// A stand whose canned evidence is the named perf cells (all twenty when `only` is empty).
    fn perf(name: &str, only: &[&str]) -> Self {
        Self::build(name, |src| fixture::build_perf_only(src, 3, only, &|_| {}))
    }
    fn build(name: &str, evidence: impl FnOnce(&Path)) -> Self {
        let base = std::env::temp_dir().join(format!(
            "rmasscan-suite-{name}-{}-{}",
            std::process::id(),
            nonce()
        ));
        let (root, src) = (base.join("out"), base.join("src"));
        fs::create_dir_all(&root).unwrap();
        evidence(&src);
        // The suite writes its own runs: start from the manifest and fixtures only.
        copy_tree(&src.join("fixtures"), &root.join("fixtures")).unwrap();
        fs::copy(src.join("manifest.json"), root.join("manifest.json")).unwrap();
        let deploy = base.join("deploy.json");
        write_json(
            &deploy,
            &crate::deploy::build_manifest(COMMIT, REMOTE_LAB, LAB_BINARY, "rustc test", 1.0),
        )
        .unwrap();
        let repo = base.join("repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(repo.join("a.txt"), "x").unwrap();
        for args in [
            vec!["init", "-q"],
            vec!["add", "-A"],
            vec![
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "x",
            ],
        ] {
            let st = std::process::Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .output()
                .unwrap();
            assert!(st.status.success(), "{st:?}");
        }
        Self {
            root,
            src,
            deploy,
            repo,
        }
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
        tx_mode: "sendqueue".into(),
        timeout: 240,
        pm: PM.into(),
        cleanup: Cell::new(false),
        runner_invoked: Cell::new(false),
        lock: None,
        scrub: Default::default(),
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
        "--repo",
        w.repo.to_str().unwrap(),
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
    // No isolation path may share a code with an ordinary rerun refusal.
    assert_eq!(EXIT_ISOLATION, 13);
    assert_eq!(SuiteError::Isolation(String::new()).code(), 13);
    assert_eq!(SuiteError::RerunRefused(String::new()).code(), 11);
    assert_ne!(EXIT_ISOLATION, EXIT_RERUN_REFUSED);
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
// The orchestrator runs on Mac and Linux; this test relies on unix paths or tools.
#[cfg(unix)]
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
// The orchestrator runs on Mac and Linux; this test relies on unix paths or tools.
#[cfg(unix)]
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
        matches!(&e, SuiteError::Isolation(m) if m.contains("eno1 interlock")),
        "{e:?}"
    );
    // A lab frame on eno1 is exit 13 (EXIT_ISOLATION). It was 10 before the final review; 11 is only a refused rerun.
    assert_eq!(e.code(), 13);
    // The first run's evidence is written (so the verifier can blame it); the second never starts.
    assert!(w.root.join("runs").join(TAG).join("capture.json").is_file());
    assert_eq!(stand.count("rxloss"), 0, "{:?}", stand.calls());
    assert_eq!(stand.count("-Action Verify"), 1, "exactly one gate ran");
    assert_eq!(crate::verify::run_status(&w.root, TAG).0, "FAIL");
}
#[test]
fn eno1_interlock_treats_unreadable_captures_as_unproven() {
    let eno = |frames: Value, tcpdump: Value| json!({"eno1":{"pcap":{"frames":frames},"tcpdump":tcpdump}});
    let zero = json!({"captured":0,"received":0,"dropped_kernel":0});
    assert!(eno1_interlock(&eno(json!(0), zero.clone())).is_ok());
    assert!(eno1_interlock(&eno(json!(1), zero.clone())).is_err());
    assert!(eno1_interlock(&eno(json!(null), zero.clone())).is_err());
    // Final review I-2 (e): the tcpdump counters must be measured and zero, not only the frame count.
    for bad in [
        json!({"captured":0,"received":0}),
        json!({"captured":0,"dropped_kernel":0}),
        json!({"captured":0,"received":null,"dropped_kernel":0}),
        json!({}),
    ] {
        let e = eno1_interlock(&eno(json!(0), bad.clone())).unwrap_err();
        assert!(e.contains("not measured"), "{bad}: {e}");
        assert!(!e.contains(LAB_FRAME_MARK));
    }
    let e = eno1_interlock(&eno(
        json!(0),
        json!({"captured":0,"received":2,"dropped_kernel":0}),
    ))
    .unwrap_err();
    assert!(
        e.contains(LAB_FRAME_MARK),
        "a counted but unstored frame is a lab frame: {e}"
    );
    let e = eno1_interlock(&eno(
        json!(0),
        json!({"captured":0,"received":0,"dropped_kernel":4}),
    ))
    .unwrap_err();
    assert!(e.contains("dropped 4") && !e.contains(LAB_FRAME_MARK));
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
        Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("../../scripts/windows_wire_prepare.ps1"),
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
// The orchestrator runs on Mac and Linux; this test relies on unix paths or tools.
#[cfg(unix)]
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
            tx_mode: "sendqueue".into(),
            timeout: 240,
            pm: PM.into(),
            cleanup: Cell::new(false),
            runner_invoked: Cell::new(false),
            lock: None,
            scrub: Default::default(),
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
    #[test]
    fn a_lost_lock_reap_kills_only_this_runs_process_groups_and_spares_a_foreign_lab_tool() {
        let h = LocalHome::new("lost-lock-reap");
        let ev = h.home.join("winvm/t4-ev");
        let own_dir = ev.join("failure/r1/tag");
        let foreign_dir = ev.join("other/r9/tag");
        fs::create_dir_all(&own_dir).unwrap();
        fs::create_dir_all(&foreign_dir).unwrap();
        let lock = LockGuard::new(|| {}, || false);
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
            tx_mode: "sendqueue".into(),
            timeout: 240,
            pm: PM.into(),
            cleanup: Cell::new(true),
            runner_invoked: Cell::new(false),
            lock: Some(&lock),
            scrub: Default::default(),
        };
        // Two TERM-ignoring tools in the real `Suite::bg` wrapper: ours, and one of another orchestrator's run.
        let start = |dir: &Path| -> i32 {
            let toolpid = dir.join("tool.pid");
            let tool = format!(
                "sh -c 'trap \"\" TERM; echo $$ > {}; while :; do sleep 1; done'",
                quote(&toolpid.to_string_lossy())
            );
            w.bg(
                &tool,
                &dir.join("peer.pid").to_string_lossy(),
                &dir.join("peer.err").to_string_lossy(),
                120,
            )
            .unwrap();
            for _ in 0..100 {
                if fs::read_to_string(&toolpid).is_ok_and(|s| !s.trim().is_empty()) {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            fs::read_to_string(&toolpid)
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        };
        let own = start(&own_dir);
        let foreign = start(&foreign_dir);
        let mut unrelated = Command::new("sleep").arg("60").spawn().unwrap();
        let notes = w.reap_own_run(&own_dir.to_string_lossy());
        for _ in 0..100 {
            if !alive(own) {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let (own_alive, foreign_alive, unrelated_alive) = (
            alive(own),
            alive(foreign),
            unrelated.try_wait().unwrap().is_none(),
        );
        // Clean up whatever the assertions below are about to judge.
        let wrapper: String = fs::read_to_string(foreign_dir.join("peer.pid")).unwrap();
        let wrapper = wrapper.split_whitespace().next().unwrap().to_owned();
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{wrapper}")])
            .status();
        let _ = Command::new("kill")
            .args(["-KILL", &wrapper, &own.to_string()])
            .status();
        let _ = unrelated.kill();
        let _ = unrelated.wait();
        assert!(
            !own_alive,
            "the TERM-ignoring tool of this run must be KILLed"
        );
        assert!(
            foreign_alive,
            "a lab tool of another run must be left alone"
        );
        assert!(unrelated_alive, "an unrelated process must be left alone");
        assert!(notes.is_empty(), "{notes:?}");
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
        "--repo",
        w.repo.to_str().unwrap(),
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

#[test]
fn the_gate_refuses_a_status_that_relied_on_another_guest_verify() {
    // WR I3 residual: the status must name the nonce of THIS invocation's Verify, not a stale one.
    let w = World::new("gate-status-nonce");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().status_nonce = Some("a-stale-verify".into());
    let s = suite(&stand, &w.root);
    let ev = w.root.join("runs").join(TAG);
    fs::create_dir_all(&ev).unwrap();
    let e = s.gate(&ev, "/r", TAG).unwrap_err();
    assert!(e.contains("another guest Verify"), "{e}");
}

// ---- F5 (WR N6): dead-man bounds with real slack ----
fn bound_of(call: &str) -> u64 {
    call.split("exec timeout -k 10 ")
        .nth(1)
        .and_then(|t| t.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no timeout bound in {call}"))
}
#[test]
fn every_background_tool_has_at_least_twice_its_expected_run_time_as_dead_man_bound() {
    // A bound that is only slightly above the worst case would make `timeout` stop tcpdump or the
    // link-restoring tool in the middle of a slow but healthy run (WR N6: 420 s against a ~405 s
    // worst-case linkloss timeline). The bound is a safety net for a dead orchestrator, not a limit.
    for (tag, tools) in [
        (
            "linkloss",
            vec![
                ("-i lab0", capture_expected_s(240)),
                ("-i eno1", capture_expected_s(240)),
                ("listen --open", capture_expected_s(240)),
                ("linkloss --guest-mac", LINKLOSS_EXPECTED_S),
            ],
        ),
        (
            "rxloss",
            vec![
                ("-i lab0", capture_expected_s(240)),
                ("flood --guest-mac", FLOOD_EXPECTED_S),
            ],
        ),
    ] {
        let w = World::new(&format!("bound-{}", tag.replace('.', "-")));
        let stand = Stand::new(&w.src);
        let s = suite(&stand, &w.root);
        let argv = argv_for(tag, &w);
        let _ = s.one(&item(tag), argv, None, None);
        let calls: Vec<String> = stand
            .calls()
            .into_iter()
            .filter(|c| c.contains("nohup sudo -n sh -c"))
            .collect();
        for (needle, expected) in tools {
            let c = calls
                .iter()
                .find(|c| c.contains(needle))
                .unwrap_or_else(|| panic!("{tag}: {needle} not started: {calls:?}"));
            let bound = bound_of(c);
            assert!(
                bound >= 2 * expected,
                "{tag} {needle}: bound {bound} s < 2 x expected {expected} s"
            );
        }
    }
}
// Compile-time: a bound below twice the expected time, or an expected time below what the tool's own
// arguments need, does not build.
const _: () = {
    assert!(INJECT_BOUND_S >= 2 * INJECT_EXPECTED_S);
    assert!(FLOOD_BOUND_S >= 2 * FLOOD_EXPECTED_S);
    assert!(LINKLOSS_BOUND_S >= 2 * LINKLOSS_EXPECTED_S);
    assert!(INJECT_EXPECTED_S >= 120 + 2); // wait-first 120 + duration 2
    assert!(FLOOD_EXPECTED_S >= 40); // flood --duration 40
    assert!(LINKLOSS_EXPECTED_S >= 120 + 2 + 40); // wait-first + down-after + hold-max
};

// ---- perf plan (N4c) ----
fn perf_item(rate: u64, rep: u64) -> Value {
    crate::verify::planned(&json!({"plan":"perf"}))
        .into_iter()
        .find(|i| i["tag"] == format!("perf.{rate}.r{rep}"))
        .unwrap()
}
fn with_plan(mut a: Vec<String>, plan: &str) -> Vec<String> {
    let at = a.iter().position(|x| x == "--plan").unwrap();
    a[at + 1] = plan.into();
    a
}
fn perf_args(w: &World, extra: &[&str]) -> Vec<String> {
    let mut a = vec!["--suite", "perf"];
    a.extend(extra);
    with_plan(suite_args(w, &a), "perf")
}
#[test]
fn perf_is_a_known_plan_and_other_names_are_still_refused() {
    let w = World::perf("perf-plan-names", &[]);
    let stand = Stand::new(&w.src);
    assert_eq!(
        run_with(&strings(&["--plan", "perf", "--list"]), &stand).unwrap(),
        0
    );
    for bad in ["perfs", "Perf", "", "functional,perf", "stress"] {
        let r = run_with(&strings(&["--plan", bad, "--list"]), &stand);
        assert!(matches!(r, Err(SuiteError::NotRun(_))), "{bad:?}: {r:?}");
    }
    assert!(stand.calls().is_empty());
}
#[test]
fn a_perf_run_needs_an_explicit_suite_id() {
    // The default suite id is "functional": a perf directory must never be mistaken for it.
    let w = World::perf("perf-needs-suite", &[]);
    let stand = Stand::new(&w.src);
    let mut a = with_plan(suite_args(&w, &[]), "perf");
    let at = a.iter().position(|x| x == "--suite");
    assert!(at.is_none(), "suite_args must not set --suite: {a:?}");
    a.extend(strings(&["--only", "perf.100.r1"]));
    let r = run_with(&a, &stand);
    assert!(
        matches!(&r, Err(SuiteError::NotRun(m)) if m.contains("--suite")),
        "{r:?}"
    );
    assert!(stand.calls().is_empty());
}
#[test]
fn perf_timeouts_scale_with_the_run_and_both_extreme_cells_fit() {
    let c100 = perf_item(100, 1);
    let c100k = perf_item(100000, 1);
    // 500 probes at 100 pps are 5 s plus the 3 s wait; 65535 probes at 100 kpps are 0.66 s (rounded up to 1 s) plus 3 s.
    assert_eq!(perf_nominal_s(&c100), 8);
    assert_eq!(perf_nominal_s(&c100k), 4);
    for item in crate::verify::planned(&json!({"plan":"perf"})) {
        let nominal = perf_nominal_s(&item);
        // The formula alone (no floor) already has twice the nominal time plus the fixed overhead.
        let t = perf_run_timeout(&item, 0);
        assert!(t >= 2 * (nominal + PERF_OVERHEAD_S), "{} {t}", item["tag"]);
        // The capture and listener dead-man bound (2 x capture_expected_s) is above 2 x everything one run does.
        let bound = 2 * capture_expected_s(t);
        assert!(
            bound >= 2 * (nominal + PERF_OVERHEAD_S + 165),
            "{}",
            item["tag"]
        );
        // The default per-run timeout of 240 s is never lowered.
        assert!(perf_run_timeout(&item, 240) >= 240);
    }
    // Concrete values. With the documented command (default --run-timeout 240) every cell keeps 240 s
    // guest timeouts and the 810 s dead-man bound of parts A and B; the formula alone gives 136 s and 128 s.
    for item in crate::verify::planned(&json!({"plan":"perf"})) {
        assert_eq!(perf_run_timeout(&item, 240), 240, "{}", item["tag"]);
    }
    assert_eq!(2 * capture_expected_s(240), 810);
    assert_eq!(perf_run_timeout(&c100, 0), 136);
    assert_eq!(perf_run_timeout(&c100k, 0), 128);
    assert_eq!(2 * capture_expected_s(136), 602);
    assert_eq!(2 * capture_expected_s(128), 586);
    // A stingy --run-timeout cannot cut the 100-pps cell short, and a long one is kept.
    assert!(perf_run_timeout(&c100, 10) >= 2 * (8 + PERF_OVERHEAD_S));
    assert_eq!(perf_run_timeout(&c100, 900), 900);
}
#[test]
fn a_perf_cell_runs_through_the_same_gate_with_its_rate_and_ports_and_scaled_bounds() {
    let tags = ["perf.100.r1", "perf.100000.r1"];
    let w = World::perf("perf-run", &tags);
    let stand = Stand::new(&w.src);
    let a = perf_args(&w, &["--run-timeout", "10", "--only", tags[0], tags[1]]);
    assert_eq!(run_with(&a, &stand).unwrap(), 0, "{:?}", stand.calls());
    // Each cell went through the unchanged per-run gate: guest Verify, record-guest, status.
    assert_eq!(stand.count("-Action Verify"), 2);
    assert_eq!(stand.count("record-guest"), 2);
    let man = read_json(w.root.join("manifest.json")).unwrap();
    assert_eq!(man["plan"], "perf");
    for (tag, rate, last) in [(tags[0], "100", "1-500"), (tags[1], "100000", "1-65535")] {
        let argv = read_json(w.root.join("runs").join(tag).join("argv.json")).unwrap();
        let av: Vec<String> = argv["argv"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        assert_eq!(arg_value(&av, "--rate"), Some(rate));
        assert_eq!(arg_value(&av, "--ports"), Some(last));
        assert_eq!(arg_value(&av, "--targets"), Some("198.18.0.2"));
        assert_eq!(arg_value(&av, "--source-port"), Some("40000"));
        assert_eq!(arg_value(&av, "--wait"), Some("3"));
        assert_eq!(arg_value(&av, "--seed"), Some("1"));
        let v = crate::verify::verify_dir(&w.root);
        let r = v["runs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["tag"] == tag)
            .unwrap();
        let bad: Vec<_> = r["checks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["result"] != "PASS")
            .collect();
        assert_eq!(
            crate::verify::run_status(&w.root, tag).0,
            "PASS",
            "{tag}: {bad:?}"
        );
    }
    // The dead-man bound of the lab0 capture of each cell follows that cell's own timeout.
    let bounds: Vec<u64> = stand
        .calls()
        .iter()
        .filter(|c| c.contains("nohup sudo -n sh -c") && c.contains("-i lab0"))
        .map(|c| bound_of(c))
        .collect();
    assert_eq!(
        bounds,
        vec![
            2 * capture_expected_s(2 * (8 + PERF_OVERHEAD_S)),
            2 * capture_expected_s(2 * (4 + PERF_OVERHEAD_S)),
        ]
    );
    // No pcap is deleted or compressed by the suite: both captures of both cells are on disk, hashed.
    for tag in tags {
        let ev = w.root.join("runs").join(tag);
        assert!(ev.join("peer.pcap").is_file() && ev.join("eno1.pcap").is_file());
        assert!(ev.join("pcap-hashes-on-home-pc.txt").is_file());
        assert!(!ev.join("peer.pcap.gz").exists());
    }
    assert_eq!(stand.count("gzip"), 0);
}

// ---- final review I-1 / I-2 / M-1 / M-3: safety, aborted evidence, Ctrl-C, the suite lock ----
fn aborted_dirs(w: &World) -> Vec<PathBuf> {
    fs::read_dir(w.root.join("runs_aborted"))
        .map(|d| d.filter_map(Result::ok).map(|e| e.path()).collect())
        .unwrap_or_default()
}
fn only_tag(w: &World) -> Vec<String> {
    suite_args(w, &["--suite", "failure", "--only", TAG])
}
#[test]
fn abort_after_send_with_an_eno1_frame_exits_13_and_the_verifier_fails_the_directory() {
    let w = World::new("abort-frame");
    let stand = Stand::new(&w.src);
    {
        let mut k = stand.knobs.borrow_mut();
        k.fail_runner = true;
        k.eno1_frames = 1;
    }
    let e = run_with(&only_tag(&w), &stand).unwrap_err();
    assert!(
        matches!(&e, SuiteError::Isolation(m) if m.contains(LAB_FRAME_MARK) && m.contains("aborted earlier")),
        "{e:?}"
    );
    assert_eq!(e.code(), 13);
    let dirs = aborted_dirs(&w);
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    assert!(dirs[0].join("eno1.pcap").is_file());
    assert!(dirs[0].join("abort-hashes-on-home-pc.txt").is_file());
    let v = crate::verify::verify_dir(&w.root);
    assert_eq!(v["overall"], "FAIL");
    assert_eq!(v["safety_trips"].as_array().unwrap().len(), 1);
    // The directory is now closed: neither a rerun nor a plain start is accepted.
    let stand2 = Stand::new(&w.src);
    let again = run_with(&only_tag(&w), &stand2).unwrap_err();
    assert_eq!(again.code(), 13);
    assert!(again.message().contains("runs_aborted/"), "{again:?}");
    assert!(stand2.calls().is_empty() && stand2.locks.get() == 0);
}
#[test]
fn abort_after_send_with_a_clean_eno1_is_still_not_run_and_discardable() {
    let w = World::new("abort-clean");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().fail_runner = true;
    let e = run_with(&only_tag(&w), &stand).unwrap_err();
    assert!(
        matches!(&e, SuiteError::Abort(m) if m.contains("no lab frame")),
        "{e:?}"
    );
    assert_eq!(e.code(), 10);
    assert_eq!(aborted_dirs(&w).len(), 1);
    assert!(stand.count("eno1_size=") == 1, "{:?}", stand.calls());
    let (verdict, beh) = crate::verify::run_status(&w.root, TAG);
    assert_eq!(verdict, "NOT RUN");
    assert!(may_discard(&verdict, beh));
    let v = crate::verify::verify_dir(&w.root);
    assert_ne!(v["overall"], "FAIL");
    assert_eq!(v["safety_trips"], json!([]));
}
#[test]
fn an_abort_before_the_runner_never_reads_eno1() {
    let w = World::new("abort-early");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().verify_rc = 1;
    let e = run_with(&only_tag(&w), &stand).unwrap_err();
    assert_eq!(e.code(), 10);
    assert_eq!(stand.count("eno1_size="), 0);
}
#[test]
fn the_remote_scratch_stays_marked_until_the_local_copy_matches_the_recorded_hashes() {
    for copies in [true, false] {
        let w = World::new("abort-marker");
        let stand = Stand::new(&w.src);
        {
            let mut k = stand.knobs.borrow_mut();
            k.fail_runner = true;
            k.no_dir_copy = !copies;
        }
        let e = run_with(&only_tag(&w), &stand).unwrap_err();
        assert_eq!(e.code(), 10);
        let calls = stand.calls();
        let at = |needle: &str| calls.iter().position(|c| c.contains(needle));
        let touch = at("touch -- ").expect("the marker is set first");
        let hashes = at("sha256sum -- *").expect("hashes are recorded on home-pc");
        let copy = calls
            .iter()
            .position(|c| c.starts_with("scp home-pc:") && c.contains("/. "))
            .expect("the copy");
        assert!(touch < hashes && hashes < copy, "{calls:?}");
        let cleared = calls
            .iter()
            .position(|c| c.contains("rm -f --") && c.contains(ABORT_MARKER));
        assert_eq!(cleared.is_some(), copies, "{calls:?}");
        if let Some(c) = cleared {
            assert!(copy < c, "the marker goes only after the copy: {calls:?}");
        }
        assert!(
            e.message().contains("hash-matched") == copies
                && e.message().contains("does not match") == !copies,
            "{e:?}"
        );
        assert!(
            !calls[touch..].iter().any(|c| c.contains("rm -rf")),
            "an aborted run's scratch is not removed by its own failure path: {calls:?}"
        );
    }
}
// The orchestrator runs on Mac and Linux; this test relies on unix paths or tools.
#[cfg(unix)]
#[test]
fn the_sweep_keeps_uncopied_abort_evidence_and_removes_the_rest() {
    // Runs the generated script for real on a scratch tree (POSIX sh, GNU or BSD readlink -f).
    let base =
        std::env::temp_dir().join(format!("rmasscan-sweep-{}-{}", std::process::id(), nonce()));
    let base = fs::canonicalize({
        fs::create_dir_all(&base).unwrap();
        base
    })
    .unwrap();
    let suite_dir = base.join("t4-ev/failure");
    for rel in ["r1/kept", "r1/gone", "r2/gone2"] {
        fs::create_dir_all(suite_dir.join(rel)).unwrap();
        fs::write(suite_dir.join(rel).join("peer.pcap"), "x").unwrap();
    }
    fs::write(suite_dir.join("r1/kept").join(ABORT_MARKER), "").unwrap();
    // A tag directory that is a symlink out of the tree must be left alone, with its target.
    let outside = base.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("precious"), "x").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, suite_dir.join("r2/link")).unwrap();
    let cmd = sweep_scratch_command(suite_dir.to_str().unwrap());
    let o = std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{o:?}");
    assert!(
        suite_dir.join("r1/kept/peer.pcap").is_file(),
        "marked evidence survives"
    );
    assert!(!suite_dir.join("r1/gone").exists() && !suite_dir.join("r2/gone2").exists());
    assert!(
        outside.join("precious").is_file(),
        "a symlink is not followed"
    );
    assert!(
        stdout.contains("kept-uncopied") && stdout.contains("r1/kept"),
        "{stdout}"
    );
    // Once the marker is gone the next sweep removes the run and the empty parents.
    fs::remove_file(suite_dir.join("r1/kept").join(ABORT_MARKER)).unwrap();
    std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .unwrap();
    assert!(!suite_dir.join("r1").exists());
    let _ = fs::remove_dir_all(&base);
}
#[test]
fn ctrl_c_during_a_run_stops_the_remote_tools_through_the_uninterruptible_path() {
    let w = World::new("ctrl-c");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().stop_at_runner = true;
    let e = run_with(&only_tag(&w), &stand).unwrap_err();
    assert!(matches!(e, SuiteError::Interrupted(_)), "{e:?}");
    assert_eq!(e.code(), 130);
    let calls = stand.calls();
    // The stop flag kills ordinary calls; nothing of the cleanup may be among them.
    assert!(
        !calls.iter().any(|c| c.starts_with("killed ")),
        "cleanup was self-killed: {calls:?}"
    );
    let at = |needle: &str| calls.iter().rposition(|c| c.contains(needle)).unwrap();
    let (term, kill) = (at("kill -TERM -- \"$pid\""), at("kill -KILL"));
    assert!(calls.iter().filter(|c| c.contains("/*/*/*/*.pid")).count() >= 2);
    assert!(term < kill, "{calls:?}");
    // At least 12 s separate the suite-wide TERM from the KILL (a link-loss tool restores lab0 first).
    let between = &calls[term..kill];
    assert!(
        between
            .iter()
            .any(|c| c == &format!("pause {TERM_GRACE_S}s"))
            && TERM_GRACE_S >= 12,
        "{between:?}"
    );
    assert!(aborted_dirs(&w).len() == 1);
}
#[test]
fn a_stop_request_before_a_run_starts_exits_130_without_a_remote_run() {
    let w = World::new("ctrl-c-early");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().stopped = true;
    let e = run_with(&only_tag(&w), &stand).unwrap_err();
    assert_eq!(e.code(), 130);
    assert_eq!(stand.count("-Action Verify"), 0);
}
#[test]
fn the_suite_lock_is_held_by_every_invocation_and_refuses_a_second_one() {
    let w = World::new("lock");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().lock_held = true;
    for args in [only_tag(&w), strings(&["--cleanup", "--suite", "failure"])] {
        let e = run_with(&args, &stand).unwrap_err();
        assert!(
            matches!(&e, SuiteError::NotRun(m) if m.contains("one suite at a time")),
            "{e:?}"
        );
        assert_eq!(e.code(), 2);
    }
    assert!(
        stand.calls().is_empty(),
        "refused before any remote change: {:?}",
        stand.calls()
    );
    stand.knobs.borrow_mut().lock_held = false;
    assert_eq!(
        run_with(&strings(&["--cleanup", "--suite", "failure"]), &stand).unwrap(),
        0
    );
    assert_eq!(stand.locks.get(), 1, "--cleanup takes the lock too");
    let lock_script = SUITE_LOCK_SCRIPT;
    assert!(lock_script.contains("flock -n 9") && lock_script.contains(".suite.lock"));
    assert!(
        lock_script.contains("cat > /dev/null"),
        "held until the session's stdin closes"
    );
}
#[test]
fn a_safety_finding_in_a_discarded_run_refuses_to_start_a_rerun() {
    let w = World::new("safety-start");
    let disc = w
        .root
        .join("runs_discarded")
        .join(format!("{TAG}.attempt1"));
    fs::create_dir_all(&disc).unwrap();
    fs::write(
        disc.join("eno1.pcap"),
        crate::pcap::encode(&vec![(fixture::BASE, fixture::scanner_syn(80, 40000))]),
    )
    .unwrap();
    let stand = Stand::new(&w.src);
    let a = suite_args(&w, &["--suite", "failure", "--rerun", "--only", TAG]);
    let e = run_with(&a, &stand).unwrap_err();
    assert_eq!(e.code(), 13);
    assert!(
        e.message()
            .contains(&format!("runs_discarded/{TAG}.attempt1")),
        "{e:?}"
    );
    assert!(stand.calls().is_empty());
}

// ---- final review M-5: unknown and repeated options are refused, and the documented commands parse ----
#[test]
fn unknown_and_repeated_options_are_refused_by_name_before_any_remote_command() {
    let w = World::new("options");
    for (extra, named) in [
        (vec!["--pla", "perf"], "--pla"),
        (vec!["--run-timeut", "10"], "--run-timeut"),
        (vec!["--only", "a", "--only", "b"], "--only"),
        (vec!["--rerun", "--rerun"], "--rerun"),
        (vec!["--repo", "x", "--repo", "y"], "--repo"),
    ] {
        let stand = Stand::new(&w.src);
        let e = run_with(&suite_args(&w, &extra), &stand).unwrap_err();
        assert!(
            matches!(&e, SuiteError::NotRun(m) if m.contains(named)),
            "{extra:?}: {e:?}"
        );
        assert_eq!(e.code(), 2);
        assert!(stand.calls().is_empty() && stand.locks.get() == 0);
    }
}
#[test]
fn every_subcommand_refuses_unknown_and_repeated_options() {
    let one = |v: &[&str]| strings(v);
    assert!(
        crate::deploy::run(&one(&["--commit", "x", "--bogus", "1"]))
            .unwrap_err()
            .contains("--bogus")
    );
    assert!(
        crate::deploy::run(&one(&["--out", "a", "--out", "b"]))
            .unwrap_err()
            .contains("--out")
    );
    assert!(
        crate::oracle::run(&one(&["--hots", "x"]))
            .unwrap_err()
            .contains("--hots")
    );
    assert!(
        crate::oracle::run(&one(&["--host", "a", "--host", "b"]))
            .unwrap_err()
            .contains("--host")
    );
    assert!(
        crate::wire_suite::run(&one(&["--rate", "100"]))
            .unwrap_err()
            .contains("--rate")
    );
    assert!(
        crate::wire_suite::run(&one(&["--reps", "1", "--reps", "2"]))
            .unwrap_err()
            .contains("--reps")
    );
    // Every option the help text names is accepted by its own allow-list.
    for k in [
        "out",
        "commit",
        "guest-exe",
        "fixtures",
        "remote-lab",
        "deploy-manifest",
        "repo",
        "suite",
        "plan",
        "only",
        "rerun",
        "list",
        "cleanup",
        "run-timeout",
        "tx-mode",
    ] {
        assert!(WINDOWS_SUITE_OPTIONS.contains(&k), "{k}");
    }
}
/// Split a documented shell command into words (single quotes, double quotes and `\"` quote; `\x` is `x`).
fn shell_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let (mut cur, mut quote, mut any) = (String::new(), None::<char>, false);
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match (c, quote) {
            ('\\', _) => match it.next() {
                Some('"') if quote != Some('\'') => {
                    quote = if quote == Some('"') { None } else { Some('"') };
                    any = true;
                }
                Some(n) => cur.push(n),
                None => {}
            },
            ('\'', None) | ('"', None) => {
                quote = Some(c);
                any = true;
            }
            (q, Some(open)) if q == open => quote = None,
            (c, None) if c.is_whitespace() => {
                if any || !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            (c, _) => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        words.push(cur);
    }
    words
}
/// `(subcommand, argument words)` of every `rmasscan-lab <sub> ...` command in the fenced `sh` blocks.
fn documented_commands(doc: &str) -> Vec<(String, Vec<String>)> {
    let mut found = Vec::new();
    let (mut in_sh, mut joined) = (false, String::new());
    for line in doc.lines() {
        let t = line.trim();
        if t.starts_with("```") {
            in_sh = t == "```sh";
            joined.clear();
            continue;
        }
        if !in_sh {
            continue;
        }
        if let Some(head) = t.strip_suffix('\\') {
            joined.push_str(head);
            joined.push(' ');
            continue;
        }
        joined.push_str(t);
        let mut cmd = std::mem::take(&mut joined);
        if let Some(i) = cmd.find("   #") {
            cmd.truncate(i);
        }
        for sub in [
            "windows-suite",
            "wire-suite",
            "oracle-fixtures",
            "deploy-manifest",
        ] {
            if let Some(i) = cmd.find(&format!("rmasscan-lab {sub}")) {
                let mut rest = cmd[i + "rmasscan-lab ".len() + sub.len()..]
                    .trim()
                    .to_owned();
                if rest.ends_with('"') && !rest.ends_with("\\\"") {
                    rest.pop();
                }
                found.push((sub.to_owned(), shell_words(&rest)));
            }
        }
    }
    found
}
#[test]
fn the_commands_documented_in_rust_lab_md_parse_with_the_option_allow_lists() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let doc = fs::read_to_string(Path::new(&manifest).join("../../docs/rust-lab.md")).unwrap();
    let found = documented_commands(&doc);
    let subs: std::collections::BTreeSet<_> = found.iter().map(|(s, _)| s.as_str()).collect();
    assert!(
        subs.contains("windows-suite") && subs.contains("deploy-manifest"),
        "{subs:?}"
    );
    assert!(found.len() >= 5, "{} commands found", found.len());
    for (sub, args) in &found {
        let allowed: &[&str] = match sub.as_str() {
            "windows-suite" => WINDOWS_SUITE_OPTIONS,
            "deploy-manifest" => &["commit", "binary", "out", "toolchain"],
            "wire-suite" => crate::wire_suite::WIRE_SUITE_OPTIONS,
            _ => &["out", "peer-mac", "remote-lab", "host"],
        };
        options_for(sub, args, allowed)
            .unwrap_or_else(|e| panic!("rust-lab.md: {sub} {args:?}: {e}"));
    }
}

// ---- fix round 2 (re-review N1, N2, N6, N8) ----
#[test]
fn a_dead_orchestrator_or_failed_ssh_after_the_send_leaves_the_run_marked_and_the_next_start_refuses()
 {
    let w = World::new("marker-dies");
    let stand = Stand::new(&w.src);
    {
        let mut k = stand.knobs.borrow_mut();
        k.fail_runner = true;
        k.down_after_runner = true;
    }
    // home-pc is unreachable from the runner on: abort_evidence can do nothing (no copy, no eno1 read).
    let e = run_with(&only_tag(&w), &stand).unwrap_err();
    assert_eq!(e.code(), 10, "{e:?}");
    assert!(
        stand.marker.borrow().is_some(),
        "the marker was written at scratch creation"
    );
    assert!(!stand.deleted.get());
    // Next start: ssh works again, the sweep finds the marked run and deletes nothing.
    {
        let mut k = stand.knobs.borrow_mut();
        k.home_down = false;
        k.down_after_runner = false;
        k.fail_runner = false;
    }
    let again = run_with(&only_tag(&w), &stand).unwrap_err();
    assert!(
        matches!(&again, SuiteError::Abort(m) if m.contains("not yet copied and hash-matched") && m.contains(&stand.marker.borrow().clone().unwrap().replace("/.abort-uncopied", "")) && m.contains("Recovery")),
        "{again:?}"
    );
    assert_eq!(again.code(), 10);
    assert!(!stand.deleted.get(), "nothing may be deleted");
    assert!(stand.marker.borrow().is_some());
    assert_eq!(stand.count("-Action Verify"), 1, "no new run started");
    // The kept eno1 shows a lab frame: that is an isolation breach.
    stand.knobs.borrow_mut().eno1_frames = 1;
    let again = run_with(&only_tag(&w), &stand).unwrap_err();
    assert_eq!(again.code(), 13, "{again:?}");
    assert!(!stand.deleted.get());
    // --cleanup keeps it and says so.
    assert_eq!(
        run_with(&strings(&["--cleanup", "--suite", "failure"]), &stand).unwrap(),
        0
    );
    assert!(!stand.deleted.get() && stand.marker.borrow().is_some());
}
#[test]
fn a_normal_run_sets_the_marker_before_anything_is_sent_and_clears_it_with_the_scratch() {
    let w = World::new("marker-normal");
    let stand = Stand::new(&w.src);
    assert_eq!(run_with(&only_tag(&w), &stand).unwrap(), 0);
    assert!(stand.marker.borrow().is_none());
    let calls = stand.calls();
    let touch = calls
        .iter()
        .position(|c| c.starts_with("home touch -- ") && c.contains(ABORT_MARKER))
        .unwrap();
    let first_raw = calls.iter().position(|c| c.contains("nohup")).unwrap();
    let mk = calls.iter().position(|c| c.contains("mkdir --")).unwrap();
    let rm = calls
        .iter()
        .rposition(|c| c.starts_with("home if test -e") && c.contains("rm -rf --"))
        .unwrap();
    assert!(
        mk < touch && touch < first_raw && first_raw < rm,
        "{calls:?}"
    );
}
#[test]
fn the_marker_is_not_cleared_while_the_scratch_has_a_subdirectory() {
    let w = World::new("marker-subdir");
    let stand = Stand::new(&w.src);
    {
        let mut k = stand.knobs.borrow_mut();
        k.fail_runner = true;
        k.subdir_present = true;
    }
    let e = run_with(&only_tag(&w), &stand).unwrap_err();
    assert!(e.message().contains("keep marker stays"), "{e:?}");
    assert!(stand.marker.borrow().is_some());
}
#[test]
fn an_abort_between_the_captures_and_the_runner_still_reads_remote_eno1() {
    for (frames, code) in [(0, 10), (1, 13)] {
        let w = World::new("early-raw");
        let stand = Stand::new(&w.src);
        {
            let mut k = stand.knobs.borrow_mut();
            k.fail_marker = true;
            k.eno1_frames = frames;
        }
        let e = run_with(&only_tag(&w), &stand).unwrap_err();
        assert_eq!(e.code(), code, "{e:?}");
        assert_eq!(stand.count("eno1_size="), 1, "{:?}", stand.calls());
        assert_eq!(stand.count("-ArgvFile"), 0, "the runner never ran");
    }
}
#[test]
fn an_unproven_eno1_under_a_stop_is_exit_10_never_a_plain_interrupt() {
    let w = World::new("stop-unproven");
    let stand = Stand::new(&w.src);
    {
        let mut k = stand.knobs.borrow_mut();
        k.stop_at_runner = true;
        k.eno1_unreadable = true;
    }
    let e = run_with(&only_tag(&w), &stand).unwrap_err();
    assert_eq!(e.code(), 10, "{e:?}");
    assert!(e.message().contains(UNPROVEN_MARK));
    // The same stop with a readable, clean eno1 stays 130.
    let w = World::new("stop-proven");
    let stand = Stand::new(&w.src);
    stand.knobs.borrow_mut().stop_at_runner = true;
    assert_eq!(run_with(&only_tag(&w), &stand).unwrap_err().code(), 130);
}
#[test]
fn the_lock_session_is_kept_alive_and_a_missing_flock_is_not_busy() {
    let a = lock_ssh_args();
    assert!(a.windows(2).any(|p| p == ["-o", "ServerAliveInterval=15"]));
    assert!(a.windows(2).any(|p| p == ["-o", "ServerAliveCountMax=4"]));
    assert!(
        SUITE_LOCK_SCRIPT.starts_with("command -v flock")
            && SUITE_LOCK_SCRIPT.contains("echo NOFLOCK")
    );
    assert_ne!(LOCK_NOFLOCK, LOCK_BUSY);
    assert_eq!(lock_error(LOCK_NOFLOCK.into()).code(), 10);
    assert!(
        lock_error(LOCK_NOFLOCK.into())
            .message()
            .contains("flock is not installed")
    );
    assert_eq!(lock_error(LOCK_BUSY.into()).code(), 2);
}
#[test]
fn the_text_report_names_aborted_runs_and_every_safety_trip() {
    let res = json!({
        "runs":[{"tag":"c01","safety_trip":true,"checks":[{"safety":true,"result":"FAIL","name":"eno1 saw zero lab packets","detail":"1"}]}],
        "aborted":[{"tag":"c01.r1","safety_trip":true,"checks":[{"safety":true,"result":"FAIL","name":"eno1 tcpdump counted zero frames matching the lab filter","detail":"2"}]}],
        "groups":[],"discarded":[]
    });
    let lines = crate::verify::safety_report_lines(&res);
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("ABORTED") && l.contains("c01.r1"))
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("safety trip: c01 : eno1 saw zero lab packets"))
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("safety trip: c01.r1 : eno1 tcpdump counted"))
    );
}

// ---- fix round 3 (R2-1): nothing could have been sent, so nothing is kept ----
#[test]
fn a_gate_failure_or_ctrl_c_during_the_gate_clears_the_marker_and_the_next_start_proceeds() {
    for stop in [false, true] {
        let w = World::new("marker-gate");
        let stand = Stand::new(&w.src);
        {
            let mut k = stand.knobs.borrow_mut();
            if stop {
                k.stop_at_verify = true;
            } else {
                k.verify_rc = 1;
            }
        }
        let e = run_with(&only_tag(&w), &stand).unwrap_err();
        assert_eq!(e.code(), if stop { 130 } else { 10 }, "{e:?}");
        assert!(
            stand.marker.borrow().is_none(),
            "stop={stop}: no capture ran, so no marker is kept"
        );
        assert_eq!(stand.count("eno1_size="), 0);
        // The next start (a new run in the same --out is a new tag directory) is not blocked.
        {
            let mut k = stand.knobs.borrow_mut();
            k.stopped = false;
            k.stop_at_verify = false;
            k.verify_rc = 0;
        }
        std::fs::remove_dir_all(w.root.join("runs")).unwrap();
        assert_eq!(run_with(&only_tag(&w), &stand).unwrap(), 0, "stop={stop}");
    }
}
#[test]
fn an_abort_after_a_capture_started_still_keeps_the_marker_until_the_copy_matches() {
    let w = World::new("marker-keeps");
    let stand = Stand::new(&w.src);
    {
        let mut k = stand.knobs.borrow_mut();
        k.fail_marker = true;
        k.no_dir_copy = true;
    }
    let e = run_with(&only_tag(&w), &stand).unwrap_err();
    assert_eq!(e.code(), 10);
    assert!(stand.marker.borrow().is_some());
}

// ---- review 7ffa155, P1: losing the lock session must stop the run ----
/// The suite on a stand whose lock session can be killed: `lock_alive` is what the guard reports.
struct LockWatch<'a> {
    stand: &'a Stand,
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The lock session dies when a remote call containing this text goes out (empty: it is dead from the start).
    die_at: &'static str,
    /// The operator's stop request arrives together with the loss (the sweep path of a stopped suite).
    stop_on_loss: bool,
}
impl Exec for LockWatch<'_> {
    fn exec(&self, a: &[String], t: u64) -> Result<Output, String> {
        if !self.die_at.is_empty() && a.iter().any(|v| v.contains(self.die_at)) {
            self.alive.store(false, std::sync::atomic::Ordering::SeqCst);
        }
        self.stand.exec(a, t)
    }
    fn exec_uninterruptible(&self, a: &[String], t: u64) -> Result<Output, String> {
        self.stand.exec_uninterruptible(a, t)
    }
    fn stopped(&self) -> bool {
        self.stand.stopped()
            || (self.stop_on_loss && !self.alive.load(std::sync::atomic::Ordering::SeqCst))
    }
    fn pause(&self, d: Duration) {
        self.stand.pause(d)
    }
    fn file_at_commit(&self, r: &Path, c: &str, p: &str) -> Result<Vec<u8>, String> {
        self.stand.file_at_commit(r, c, p)
    }
    fn lock_suite(&self) -> Result<LockGuard, String> {
        let alive = std::sync::Arc::clone(&self.alive);
        Ok(LockGuard::new(
            || {},
            move || alive.load(std::sync::atomic::Ordering::SeqCst),
        ))
    }
}
#[test]
fn a_lost_lock_session_stops_the_suite_before_any_raw_run() {
    for die_at in ["", "touch -- "] {
        let w = World::new("lost-lock");
        let stand = Stand::new(&w.src);
        let watch = LockWatch {
            stand: &stand,
            alive: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(!die_at.is_empty())),
            die_at,
            stop_on_loss: false,
        };
        let r = run_with(&only_tag(&w), &watch);
        let runners = stand.count("windows_wire_run.ps1 -ArgvFile");
        assert!(
            matches!(&r, Err(SuiteError::Abort(m)) if m.contains("lock")),
            "die_at={die_at:?}: {r:?}"
        );
        assert_eq!(
            runners, 0,
            "die_at={die_at:?}: no raw run after the lock is lost"
        );
    }
}
#[cfg(unix)]
#[test]
fn the_lock_guard_notices_that_its_ssh_session_died() {
    let live = lock_session("sh", &strings(&["-c", "echo LOCKED; cat > /dev/null"])).unwrap();
    assert!(!live.lost());
    let dying = lock_session("sh", &strings(&["-c", "echo LOCKED; sleep 0.1; exit 255"])).unwrap();
    for _ in 0..100 {
        if dying.lost() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(dying.lost(), "an exited lock session is a lost lock");
    let busy = lock_session("sh", &strings(&["-c", "echo BUSY"]));
    assert_eq!(busy.err().as_deref(), Some(LOCK_BUSY));
}

// ---- review 7ffa155, P1: another suite's unfinished evidence blocks a new suite name ----
#[cfg(unix)]
#[test]
fn unfinished_evidence_of_another_suite_is_reported_and_nothing_of_it_is_deleted() {
    let h = local_sweep::LocalHome::new("other-suite-kept");
    let ev = h.home.join("winvm/t4-ev");
    let kept = ev.join("old-suite/run/tag");
    let other_done = ev.join("old-suite/run/done");
    let own_done = ev.join("new-suite/run/done");
    for d in [&kept, &other_done, &own_done] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(kept.join(ABORT_MARKER), "").unwrap();
    let reports = sweep_remote(&h, "new-suite").unwrap();
    assert_eq!(reports, vec![kept.to_string_lossy().into_owned()]);
    assert!(
        kept.join(ABORT_MARKER).exists(),
        "kept evidence is never deleted"
    );
    assert!(
        other_done.exists(),
        "another suite's scratch is not this run's to delete"
    );
    assert!(
        !own_done.exists(),
        "the own suite's unmarked scratch is still swept"
    );
    // The start refuses with the directory named, whatever the suite name.
    let e = refuse_kept_runs(&h, &reports);
    assert!(
        matches!(&e, SuiteError::Abort(m) if m.contains("old-suite/run/tag")),
        "{e:?}"
    );
    // Own kept evidence is reported once, not twice.
    let own = ev.join("new-suite/run/tag");
    fs::create_dir_all(&own).unwrap();
    fs::write(own.join(ABORT_MARKER), "").unwrap();
    assert_eq!(sweep_remote(&h, "new-suite").unwrap().len(), 2);
}

// ---- lost lock: no global sweep; only this run's own tools are stopped ----
const START_SWEEP_CALLS: usize = 2; // TERM and KILL of the start-of-suite sweep, before the loss
#[test]
fn a_lost_lock_with_a_stop_request_runs_no_global_sweep() {
    let w = World::new("lost-lock-no-sweep");
    let stand = Stand::new(&w.src);
    let watch = LockWatch {
        stand: &stand,
        alive: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        die_at: "touch -- ",
        stop_on_loss: true,
    };
    let _ = run_with(&only_tag(&w), &watch);
    assert_eq!(
        stand.count("for pidfile in"),
        START_SWEEP_CALLS,
        "{:?}",
        stand.calls()
    );
    assert_eq!(stand.count("windows_wire_run.ps1 -ArgvFile"), 0);
}
/// Answers every `ssh home-pc` with success, except that the processes of `alive_pids` never exit.
struct Stubborn {
    alive_pids: &'static [&'static str],
    log: RefCell<Vec<String>>,
}
impl Exec for Stubborn {
    fn exec(&self, argv: &[String], _t: u64) -> Result<Output, String> {
        let cmd = argv.last().unwrap().clone();
        self.log.borrow_mut().push(cmd.clone());
        // An exit check is `owned_process_command(.., None)`: it ends in `false` for a process that is still there.
        let probe = cmd.contains("; false; }");
        let alive = probe && self.alive_pids.iter().any(|p| cmd.contains(p));
        out(i32::from(alive), "")
    }
    fn file_at_commit(&self, _: &Path, _: &str, _: &str) -> Result<Vec<u8>, String> {
        Err("unused".into())
    }
    fn pause(&self, d: Duration) {
        thread::sleep(d.min(Duration::from_millis(50)));
    }
}
#[test]
fn a_lost_lock_abort_signals_only_this_runs_pidfiles_escalates_and_names_what_it_could_not_stop() {
    let w = World::new("lost-lock-reap");
    let stand = Stand::new(&w.src);
    let stub = Stubborn {
        alive_pids: &["/peer.pid"],
        log: RefCell::default(),
    };
    let lock = LockGuard::new(|| {}, || false);
    let mut s = suite(&stand, &w.root);
    s.exec = &stub;
    s.lock = Some(&lock);
    s.cleanup.set(true);
    let rev = "/home/a1/winvm/t4-ev/failure/r00112233445566778899aabbccddeeff/tag";
    let note = s.abort_evidence("tag", rev, "boom".into());
    let log = stub.log.borrow().clone();
    assert!(
        !log.iter().any(|c| c.contains("for pidfile in")),
        "no global sweep: {log:?}"
    );
    let kills: Vec<_> = log.iter().filter(|c| c.contains("kill -KILL")).collect();
    assert_eq!(
        kills.len(),
        1,
        "only the stubborn tool is KILLed: {kills:?}"
    );
    assert!(
        kills[0].contains(&format!("{rev}/peer.pid")),
        "{}",
        kills[0]
    );
    assert!(
        log.iter()
            .filter(|c| c.contains("kill -TERM"))
            .all(|c| c.contains(rev)),
        "every signal targets a pidfile of this run"
    );
    assert!(
        note.contains("could not be stopped")
            && note.contains(&format!("{rev}/peer.pid"))
            && note.contains("kill -KILL"),
        "manual advice names the pidfile: {note}"
    );
}

// ---- Task 5: --tx-mode ----
#[test]
fn options_list_includes_tx_mode() {
    assert!(WINDOWS_SUITE_OPTIONS.contains(&"tx-mode"));
    let args = strings(&["--tx-mode", "single"]);
    assert!(options_for("windows-suite", &args, WINDOWS_SUITE_OPTIONS).is_ok());
    let dup = strings(&["--tx-mode", "single", "--tx-mode", "sendqueue"]);
    assert!(
        options_for("windows-suite", &dup, WINDOWS_SUITE_OPTIONS)
            .unwrap_err()
            .contains("--tx-mode")
    );
}
#[test]
fn tx_mode_option_is_validated_and_recorded_in_the_manifest() {
    let w = World::new("tx-mode");
    let fresh = |n: &str| {
        let p = w.root.parent().unwrap().join(n);
        fs::create_dir_all(&p).unwrap();
        p
    };
    let with_out = |out: &Path, extra: &[&str]| {
        let mut a = suite_args(&w, &["--suite", "failure", "--only", TAG]);
        a[1] = out.to_str().unwrap().into();
        a.extend(strings(extra));
        a
    };
    // Anything but sendqueue|single is refused before any remote command.
    for bad in ["", "batch", "SENDQUEUE", "sendqueue,single"] {
        let stand = Stand::new(&w.src);
        let r = run_with(&with_out(&fresh("bad"), &["--tx-mode", bad]), &stand);
        assert!(matches!(r, Err(SuiteError::NotRun(_))), "{bad:?}: {r:?}");
        assert!(stand.calls().is_empty(), "{bad:?} reached a remote command");
    }
    // Recorded as given; sendqueue by default.
    for (name, extra, want) in [
        ("dflt", &[][..], "sendqueue"),
        ("sq", &["--tx-mode", "sendqueue"][..], "sendqueue"),
        ("single", &["--tx-mode", "single"][..], "single"),
    ] {
        let out = fresh(name);
        let stand = Stand::new(&w.src);
        run_with(&with_out(&out, extra), &stand).unwrap();
        let man = read_json(out.join("manifest.json")).unwrap();
        assert_eq!(man["tx_mode_expected"], want, "{name}");
    }
    // A directory keeps the mode it was started with.
    let stand = Stand::new(&w.src);
    let e = run_with(&with_out(&w.root, &["--tx-mode", "single"]), &stand).unwrap_err();
    assert!(
        e.message().contains("existing manifest identity differs"),
        "{e:?}"
    );
    assert!(stand.calls().is_empty(), "refused only after remote calls");
}

// ---- Task 6d: --plan autodetect, the rmasscan CLI cases w01-w08b of the verifier's case table ----
//
// The stand serves, per tag, what the guest runner and the two captures produce for a correct run of the case: the
// verifier's synthetic generator (`autodetect_verify::tests::Sim`). The suite writes the run directories itself and
// `autodetect-verify` judges them. Nothing here starts a process: the provenance is canned and `--repo` is a plain
// directory.
use crate::autodetect_verify::{
    self as av, ArgvRecord, CaseKind, ExpectRecord, IflistRecord, Plan, tests::Sim,
};

const RMASSCAN_EXE: &str = "C:\\Users\\lab\\t4\\rmasscan.exe";
/// The guest's `--iflist` around the stand line: the management NIC, loopback and a miniport, which no evidence file
/// may ever hold (an inventory of the guest).
fn guest_listing(stand_line: &str) -> String {
    format!(
        "Ethernet index=4 mac=52-54-00-12-34-56 ipv4=10.0.2.15 up ethernet id=\\Device\\NPF_{{0B9A3C1D-1111-2222-3333-444455556666}} desc=Intel(R) 82574L Gigabit Network Connection\n{stand_line}\nLoopback Pseudo-Interface 1 index=1 mac=none ipv4=127.0.0.1 up loopback\nWAN Miniport (IP) index=9 mac=none ipv4=- down other\n"
    )
}
const LISTING_ONLY: [&str; 5] = [
    "52-54-00-12-34-56",
    "10.0.2.15",
    "Loopback Pseudo",
    "WAN Miniport",
    "0B9A3C1D",
];
fn canned_provenance() -> Value {
    json!({"git_commit": COMMIT, "git_dirty": false, "build_commit": "unknown",
        "binary_sha256": "c".repeat(64), "binary_name": "rmasscan-lab", "errors": []})
}
fn sim_file(sim: &Sim, name: &str) -> Vec<u8> {
    sim.files()
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, b)| b)
        .unwrap_or_else(|| panic!("the generator has no {name}"))
}
/// The stand's source of one case: both captures, the peer listener's record, and under `guest/` what the guest
/// runner writes (`stdout.txt`, `stderr.txt`, `exit.txt`; `preflight-stderr.txt`, `preflight-exit.txt` for the
/// `--offline` preflight). An `--iflist` case's stdout is the guest's full listing.
fn write_case(src: &Path, sim: &Sim) {
    let d = src.join("runs").join(sim.case.tag);
    let g = d.join("guest");
    fs::create_dir_all(&g).unwrap();
    fs::write(d.join("peer.pcap"), sim_file(sim, "peer.pcap")).unwrap();
    fs::write(d.join("eno1.pcap"), sim_file(sim, "eno1.pcap")).unwrap();
    write_json(
        d.join("listeners.json"),
        &json!({"bind":"198.18.0.2","open":[80,443,8000,8001,8002,8003,8004,8005,8006,8007],"pid":4242,"ready":true,"silent":[8099],"silent_proven":true}),
    )
    .unwrap();
    let stdout = match &sim.stdout {
        Some(s) => s.clone(),
        None => {
            let rec: IflistRecord = serde_json::from_slice(&sim_file(sim, "iflist.json")).unwrap();
            guest_listing(&rec.stand_line.unwrap())
        }
    };
    fs::write(g.join("stdout.txt"), stdout).unwrap();
    fs::write(g.join("stderr.txt"), sim.stderr_text()).unwrap();
    fs::write(g.join("exit.txt"), format!("{}\n", sim.exit)).unwrap();
    if spec_of(sim.case.tag).restricted {
        // The restricted-token runner (windows_wire_restricted.cmd) also leaves `OUT.runner.rc` and `OUT.runner.log`.
        fs::write(g.join("restricted"), "").unwrap();
    }
    if let Some(p) = &sim.preflight {
        let (rc, stderr) = p.split_once('\n').unwrap();
        let rc = rc.strip_prefix("rc ").unwrap();
        fs::write(g.join("preflight-exit.txt"), format!("{rc}\n")).unwrap();
        fs::write(g.join("preflight-stderr.txt"), stderr).unwrap();
    }
}
impl World {
    /// The `n2` stand running the autodetect cases: `--out` starts empty, `--repo` is a plain directory, the deploy
    /// manifest vouches for the stand's binary. `tweak` changes a case's simulated outputs before they are served.
    fn autodetect(name: &str, tweak: impl Fn(&mut Sim)) -> Self {
        let base = std::env::temp_dir().join(format!(
            "rmasscan-suite-ad-{name}-{}-{}",
            std::process::id(),
            nonce()
        ));
        let (root, src, repo) = (base.join("out"), base.join("src"), base.join("repo"));
        for d in [&root, &src, &repo] {
            fs::create_dir_all(d).unwrap();
        }
        for tag in av::planned_tags(Plan::Windows) {
            let mut sim = Sim::new(Plan::Windows, tag);
            tweak(&mut sim);
            write_case(&src, &sim);
        }
        let deploy = base.join("deploy.json");
        write_json(
            &deploy,
            &crate::deploy::build_manifest(COMMIT, REMOTE_LAB, LAB_BINARY, "rustc test", 1.0),
        )
        .unwrap();
        Self {
            root,
            src,
            deploy,
            repo,
        }
    }
}
fn autodetect_stand(w: &World) -> Stand {
    let stand = Stand::new(&w.src);
    {
        let mut k = stand.knobs.borrow_mut();
        k.provenance = Some(canned_provenance());
    }
    stand
}
fn autodetect_args(w: &World, extra: &[&str]) -> Vec<String> {
    let mut a = strings(&[
        "--out",
        w.root.to_str().unwrap(),
        "--commit",
        COMMIT,
        "--guest-exe",
        RMASSCAN_EXE,
        "--remote-lab",
        REMOTE_LAB,
        "--deploy-manifest",
        w.deploy.to_str().unwrap(),
        "--plan",
        "autodetect",
        "--suite",
        "windows-r1",
        "--repo",
        w.repo.to_str().unwrap(),
    ]);
    a.extend(strings(extra));
    a
}
fn spec_of(tag: &str) -> av::CaseSpec {
    av::case_spec(Plan::Windows, tag).unwrap()
}
fn argv_of(v: &Value) -> Vec<String> {
    v["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_owned())
        .collect()
}
/// The non-PASS checks of a verdict, for assertion messages.
fn ad_bad(res: &Value) -> Vec<String> {
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
fn ad_verdict(res: &Value, tag: &str) -> String {
    res["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["tag"] == tag)
        .map(|r| r["verdict"].as_str().unwrap().to_owned())
        .unwrap_or_else(|| panic!("no run {tag}"))
}
/// Every file under `dir` (relative), for the evidence-wide assertions.
fn every_file(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                todo.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}

#[test]
fn plan_autodetect_lists_w01_to_w08b() {
    let tags = av::planned_tags(Plan::Windows);
    assert_eq!(
        tags,
        [
            "w01_auto",
            "w02_adapter_npf",
            "w03_adapter_friendly",
            "w04_router_mac",
            "w05_arp_timeout",
            "w06_multi_no_gateway",
            "w07_iflist",
            "w08a_restricted_iflist",
            "w08b_restricted_scan"
        ]
    );
    // --list names the nine cases, w08a and w08b under the restricted token, and starts nothing.
    let items = autodetect_items();
    assert_eq!(
        items
            .iter()
            .map(|i| i["tag"].as_str().unwrap())
            .collect::<Vec<_>>(),
        tags
    );
    let restricted: Vec<&str> = items
        .iter()
        .filter(|i| i["restricted"] == true)
        .map(|i| i["tag"].as_str().unwrap())
        .collect();
    assert_eq!(
        restricted,
        ["w08a_restricted_iflist", "w08b_restricted_scan"]
    );
    for i in &items {
        let spec = spec_of(i["tag"].as_str().unwrap());
        assert_eq!(i["kind"], json!(spec.kind), "{i}");
        assert_eq!(i["restricted"], spec.restricted, "{i}");
    }
    let stand = Stand::new(Path::new("/nonexistent"));
    assert_eq!(
        run_with(&strings(&["--plan", "autodetect", "--list"]), &stand).unwrap(),
        0
    );
    assert!(stand.calls().is_empty());
    // A full run: w08a (`--iflist`) and w08b (the scan) are two runner invocations under the restricted token, the
    // seven others and the two preflights go through the plain runner.
    let w = World::autodetect("list", |_| {});
    let stand = autodetect_stand(&w);
    assert_eq!(
        run_with(&autodetect_args(&w, &[]), &stand).unwrap(),
        0,
        "{:?}",
        stand.calls()
    );
    let calls = stand.calls();
    let runas: Vec<&String> = calls
        .iter()
        .filter(|c| c.starts_with("guest ") && c.contains("windows_wire_runas.cmd \""))
        .collect();
    assert_eq!(runas.len(), 2, "{runas:?}");
    assert!(
        runas[0].contains(".w08a_restricted_iflist.runner-argv.json"),
        "{}",
        runas[0]
    );
    assert!(
        runas[1].contains(".w08b_restricted_scan.runner-argv.json"),
        "{}",
        runas[1]
    );
    let plain = calls
        .iter()
        .filter(|c| c.starts_with("guest ") && c.contains("windows_wire_run.ps1 -ArgvFile"))
        .count();
    assert_eq!(plain, 7 + 2, "seven scans and the w01/w06 preflights");
    let runner =
        |tag: &str| read_json(w.root.join("runs").join(tag).join("runner-argv.json")).unwrap();
    assert_eq!(argv_of(&runner("w08a_restricted_iflist")), ["--iflist"]);
    assert_eq!(
        argv_of(&runner("w08b_restricted_scan")),
        spec_of("w01_auto").argv(),
        "w08b scans what w01 scans"
    );
    for tag in &tags {
        let d = w.root.join("runs").join(tag);
        let meta = read_json(d.join("meta.json")).unwrap();
        let restricted = spec_of(tag).restricted;
        assert_eq!(
            meta.get("restricted_via").is_some(),
            restricted,
            "{tag}: {meta}"
        );
        // The restricted runner's own exit code is kept under an evidence extension, never as `.rc`.
        assert_eq!(d.join("guest-runner-rc.txt").is_file(), restricted, "{tag}");
        assert_eq!(d.join("guest-runner.log").is_file(), restricted, "{tag}");
        assert!(!d.join("guest-runner.rc").exists(), "{tag}");
    }
}

#[test]
fn autodetect_runs_carry_expect_json() {
    let w = World::autodetect("expect", |_| {});
    let stand = autodetect_stand(&w);
    assert_eq!(run_with(&autodetect_args(&w, &[]), &stand).unwrap(), 0);
    for spec in av::cases(Plan::Windows) {
        let d = w.root.join("runs").join(spec.tag);
        // One schema, one case table: the run's records are the table's, in the verifier's own types.
        let expect: ExpectRecord =
            serde_json::from_slice(&fs::read(d.join(av::EXPECT_JSON)).unwrap()).unwrap();
        assert_eq!(expect, spec.expect(), "{}", spec.tag);
        let argv: ArgvRecord =
            serde_json::from_slice(&fs::read(d.join(av::ARGV_JSON)).unwrap()).unwrap();
        assert_eq!(argv.argv, spec.argv(), "{}", spec.tag);
        assert!(d.join(av::HASHES).is_file(), "{}", spec.tag);
        // The preflight cases carry what their --offline preflight printed.
        assert_eq!(
            d.join(av::PREFLIGHT_TXT).is_file(),
            spec.preflight.is_some(),
            "{}",
            spec.tag
        );
        if spec.kind != CaseKind::Iflist {
            let det: av::DetectedRecord =
                serde_json::from_slice(&fs::read(d.join(av::DETECTED_JSON)).unwrap()).unwrap();
            let stderr = fs::read_to_string(d.join("guest-stderr.txt")).unwrap();
            assert_eq!(det, av::parse_stderr(&stderr).unwrap(), "{}", spec.tag);
        }
    }
}

#[test]
fn options_list_accepts_plan_autodetect() {
    // The documented command parses with the option allow-list, and `--plan autodetect` is a known plan.
    let w = World::autodetect("options", |_| {});
    let documented = autodetect_args(&w, &[]);
    assert!(options_for("windows-suite", &documented, WINDOWS_SUITE_OPTIONS).is_ok());
    let stand = Stand::new(&w.src);
    for plan in ["autodetect", "functional", "failure", "perf"] {
        assert_eq!(
            run_with(&strings(&["--plan", plan, "--list"]), &stand).unwrap(),
            0,
            "{plan}"
        );
    }
    for bad in ["Autodetect", "auto", "autodetect,functional", "windows"] {
        let r = run_with(&strings(&["--plan", bad, "--list"]), &stand);
        assert!(matches!(r, Err(SuiteError::NotRun(_))), "{bad:?}: {r:?}");
    }
    assert!(stand.calls().is_empty());
    // What the plan refuses before any remote command: no --suite (the default would be the functional suite id),
    // --rerun (a case runs once into one --out), --tx-mode (wire_scan's TX path), a scanner other than rmasscan.exe.
    let without_suite: Vec<String> = {
        let mut a = documented.clone();
        let at = a.iter().position(|x| x == "--suite").unwrap();
        a.drain(at..at + 2);
        a
    };
    for (args, named) in [
        (without_suite, "--suite"),
        (
            autodetect_args(&w, &["--rerun", "--only", "w01_auto"]),
            "--rerun",
        ),
        (autodetect_args(&w, &["--tx-mode", "single"]), "--tx-mode"),
        (
            {
                let mut a = documented.clone();
                let at = a.iter().position(|x| x == "--guest-exe").unwrap();
                a[at + 1] = "C:\\Users\\lab\\t4\\wire_scan.exe".into();
                a
            },
            "rmasscan.exe",
        ),
        (
            autodetect_args(&w, &["--only", "c01_one_addr_port_synack.run1"]),
            "c01_one_addr_port_synack.run1",
        ),
    ] {
        let stand = autodetect_stand(&w);
        let e = run_with(&args, &stand).unwrap_err();
        assert!(
            matches!(&e, SuiteError::NotRun(m) if m.contains(named)),
            "{named}: {e:?}"
        );
        assert!(
            stand.calls().is_empty() && stand.locks.get() == 0,
            "{named}: {:?}",
            stand.calls()
        );
        assert!(!w.root.join("manifest.json").exists(), "{named}");
    }
}

#[test]
fn fixtures_are_optional_only_for_plan_autodetect() {
    let w = World::autodetect("fixtures", |_| {});
    // Every wire_scan plan still needs the oracle fixtures, and refuses before any remote command.
    for plan in ["functional", "failure", "perf"] {
        let stand = autodetect_stand(&w);
        let mut a = autodetect_args(&w, &[]);
        let at = a.iter().position(|x| x == "--plan").unwrap();
        a[at + 1] = plan.into();
        let at = a.iter().position(|x| x == "--guest-exe").unwrap();
        a[at + 1] = "C:\\Users\\lab\\t4\\wire_scan.exe".into();
        let e = run_with(&a, &stand).unwrap_err();
        assert!(
            matches!(&e, SuiteError::NotRun(m) if m.contains("--fixtures")),
            "{plan}: {e:?}"
        );
        assert!(stand.calls().is_empty(), "{plan}");
    }
    // The autodetect plan runs without them...
    let stand = autodetect_stand(&w);
    assert_eq!(
        run_with(&autodetect_args(&w, &["--only", "w02_adapter_npf"]), &stand).unwrap(),
        0,
        "{:?}",
        stand.calls()
    );
    // ...and given anyway they are neither read nor copied (the plan has no oracle).
    let stand = autodetect_stand(&w);
    let missing = w.root.parent().unwrap().join("no-such-fixtures");
    assert_eq!(
        run_with(
            &autodetect_args(
                &w,
                &[
                    "--fixtures",
                    missing.to_str().unwrap(),
                    "--only",
                    "w03_adapter_friendly"
                ]
            ),
            &stand
        )
        .unwrap(),
        0
    );
    assert!(!w.root.join("fixtures").exists());
    let man = read_json(w.root.join("manifest.json")).unwrap();
    assert!(man.get("oracle").is_none(), "{man}");
}

#[test]
fn manifest_build_and_binding_follow_the_plan() {
    let w = World::autodetect("manifest", |_| {});
    // A wire_scan plan: the explicit binding of every run, the wire_scan build.
    let fixtures = w.root.parent().unwrap().join("fixtures");
    fs::create_dir_all(&fixtures).unwrap();
    write_json(
        fixtures.join("manifest.json"),
        &json!({"all_valid": true, "oracle": {"git_commit": "8e6b3b0"}}),
    )
    .unwrap();
    let legacy_out = w.root.parent().unwrap().join("legacy-out");
    // The failed gate's copy home reads the run's (empty) captures from the stand.
    let tag_src = w.src.join("runs").join(TAG);
    fs::create_dir_all(&tag_src).unwrap();
    for who in ["peer", "eno1"] {
        fs::write(
            tag_src.join(format!("{who}.pcap")),
            crate::pcap::encode(&Vec::new()),
        )
        .unwrap();
    }
    let stand = autodetect_stand(&w);
    stand.knobs.borrow_mut().verify_rc = 1; // the manifest is written before the first gate
    let mut a = autodetect_args(
        &w,
        &["--fixtures", fixtures.to_str().unwrap(), "--only", TAG],
    );
    for (k, v) in [
        ("--plan", "failure"),
        ("--suite", "failure"),
        ("--guest-exe", "C:\\x\\wire_scan.exe"),
        ("--out", legacy_out.to_str().unwrap()),
    ] {
        let at = a.iter().position(|x| x == k).unwrap();
        a[at + 1] = v.into();
    }
    let _ = run_with(&a, &stand);
    let man = read_json(legacy_out.join("manifest.json")).unwrap();
    assert_eq!(
        man["exe"]["build"],
        "Rust static CRT wire_scan from code_commit"
    );
    assert_eq!(
        man["binding"],
        json!({"iface":IFACE,"src_ip":"198.18.0.1","src_mac":MAC,"router_mac":PM,"peer_ip":"198.18.0.2","seed":1,"rate":100,"wait":3})
    );
    assert!(man.get("autodetect").is_none());
    assert_eq!(man["perm_restricted_refusal"], "PermissionDenied");
    // The autodetect plan: the rmasscan CLI build, the binding of each case from its expect.json, the plan key the
    // verifier reads, and no wire_scan-only field.
    let stand = autodetect_stand(&w);
    assert_eq!(
        run_with(&autodetect_args(&w, &["--only", "w01_auto"]), &stand).unwrap(),
        0
    );
    let man = read_json(w.root.join("manifest.json")).unwrap();
    assert_eq!(
        man["exe"]["build"],
        "Rust static CRT rmasscan CLI from code_commit"
    );
    assert_eq!(man["exe"]["guest_path"], RMASSCAN_EXE);
    assert_eq!(man["autodetect"], "windows");
    assert_eq!(man["plan"], "autodetect");
    let binding = man["binding"].as_object().unwrap();
    assert_eq!(binding.len(), 9);
    for spec in av::cases(Plan::Windows) {
        assert_eq!(
            binding[spec.tag],
            json!(spec.expect().detection),
            "{}",
            spec.tag
        );
    }
    for k in [
        "oracle",
        "pause",
        "tx_mode_expected",
        "perm_restricted_refusal",
    ] {
        assert!(man.get(k).is_none(), "{k}: {man}");
    }
    // Personal paths are scrubbed: the stand manifest lives under the home directory on home-pc.
    assert_eq!(man["stand"]["manifest"], "$HOME/winvm/lab/n2.json");
    let parsed: av::Manifest = serde_json::from_value(man).unwrap();
    assert_eq!(parsed.autodetect, Plan::Windows);
}

#[test]
fn autodetect_plan_skips_the_run_json_line_and_keeps_guest_names() {
    // rmasscan prints no JSON line; a line that merely starts with `{` must not be parsed into run.json (the
    // wire_scan plans would refuse it), and the guest's files keep their guest-* names.
    let w = World::autodetect("guest-names", |sim| {
        if sim.case.tag == "w02_adapter_npf" {
            let out = sim.stdout.take().unwrap();
            sim.stdout = Some(format!("{out}{{not json\n"));
        }
    });
    let stand = autodetect_stand(&w);
    let only = [
        "--only",
        "w02_adapter_npf",
        "w03_adapter_friendly",
        "w07_iflist",
    ];
    assert_eq!(
        run_with(&autodetect_args(&w, &only), &stand).unwrap(),
        0,
        "{:?}",
        stand.calls()
    );
    for tag in ["w02_adapter_npf", "w03_adapter_friendly", "w07_iflist"] {
        let d = w.root.join("runs").join(tag);
        assert!(!d.join("run.json").exists(), "{tag}");
        for n in ["stdout.txt", "stderr.txt", "exit.txt", "guest-runner.rc"] {
            assert!(!d.join(n).exists(), "{tag}: {n}");
        }
        for n in ["guest-stderr.txt", "guest-exit.txt", "guest-runner.json"] {
            assert!(d.join(n).is_file(), "{tag}: {n}");
        }
        assert_eq!(
            d.join("guest-stdout.txt").is_file(),
            tag != "w07_iflist",
            "{tag}"
        );
        let proof = read_json(d.join("run-artifacts.json")).unwrap();
        assert!(proof["files"].get("run.json").is_none(), "{tag}: {proof}");
    }
    // The guest's stdout is copied as it is, and the verifier sees the stray line.
    let w02 = fs::read_to_string(w.root.join("runs/w02_adapter_npf/guest-stdout.txt")).unwrap();
    assert!(w02.ends_with("{not json\n"), "{w02:?}");
    let res = av::verify_dir(&w.root);
    assert_eq!(
        ad_verdict(&res, "w03_adapter_friendly"),
        "PASS",
        "{:#?}",
        ad_bad(&res)
    );
    assert_eq!(
        ad_verdict(&res, "w07_iflist"),
        "PASS",
        "{:#?}",
        ad_bad(&res)
    );
    assert_eq!(ad_verdict(&res, "w02_adapter_npf"), "INVALID");
}

#[test]
fn iflist_runs_reduce_guest_stdout_in_the_work_dir_before_the_run_dir_is_written() {
    let w = World::autodetect("iflist", |_| {});
    let stand = autodetect_stand(&w);
    let tags = ["w07_iflist", "w08a_restricted_iflist"];
    assert_eq!(
        run_with(&autodetect_args(&w, &["--only", tags[0], tags[1]]), &stand).unwrap(),
        0,
        "{:?}",
        stand.calls()
    );
    // The guest's stdout went to the work directory next to the run (`.work/<tag>.<run id>/`), never into the run
    // directory (`.work/<tag>.<run id>/run`), which is what reaches `runs/<tag>`; and it is deleted at once.
    let fetches = stand.stdout_fetches.borrow().clone();
    assert_eq!(fetches.len(), 2, "{fetches:?}");
    for (local, tag) in fetches.iter().zip(tags) {
        let rel = local
            .strip_prefix(w.root.join(".work"))
            .unwrap_or_else(|_| panic!("{} is not in the work directory", local.display()));
        let parts: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        assert_eq!(parts.len(), 2, "{parts:?}");
        assert!(parts[0].starts_with(&format!("{tag}.")), "{parts:?}");
        assert!(!parts.iter().any(|p| p == "run"), "{parts:?}");
        assert!(
            !local.exists(),
            "the copy is deleted at once: {}",
            local.display()
        );
    }
    for tag in tags {
        let d = w.root.join("runs").join(tag);
        assert!(!d.join("guest-stdout.txt").exists(), "{tag}");
        let rec: IflistRecord =
            serde_json::from_slice(&fs::read(d.join(av::IFLIST_JSON)).unwrap()).unwrap();
        let listing =
            fs::read_to_string(w.src.join("runs").join(tag).join("guest/stdout.txt")).unwrap();
        assert_eq!(rec.rc, 0);
        assert_eq!(rec.lines, 4);
        assert_eq!(rec.sha256, crate::verify::sha(listing.as_bytes()));
        let stand_line = rec.stand_line.unwrap();
        assert!(stand_line.starts_with("Ethernet 2 index="), "{stand_line}");
        assert!(listing.lines().any(|l| l == stand_line));
    }
    // No file of the evidence directory holds anything of the listing but the stand line; the work directory is gone.
    for f in every_file(&w.root) {
        let t = String::from_utf8_lossy(&fs::read(&f).unwrap()).into_owned();
        for host in LISTING_ONLY {
            assert!(!t.contains(host), "{}: {host}", f.display());
        }
    }
    assert!(!w.root.join(".work").exists());
    let res = av::verify_dir(&w.root);
    for tag in tags {
        assert_eq!(ad_verdict(&res, tag), "PASS", "{:#?}", ad_bad(&res));
    }
}

#[test]
fn windows_plan_uses_rmasscan_exe_argv_not_wire_scan() {
    let w = World::autodetect("argv", |_| {});
    let stand = autodetect_stand(&w);
    assert_eq!(run_with(&autodetect_args(&w, &[]), &stand).unwrap(), 0);
    let calls = stand.calls();
    for spec in av::cases(Plan::Windows) {
        let d = w.root.join("runs").join(spec.tag);
        // What the guest runner was given: rmasscan.exe and the case's own argv, none of wire_scan's options.
        let input = read_json(d.join("runner-argv.json")).unwrap();
        assert_eq!(input["exe"], RMASSCAN_EXE, "{}", spec.tag);
        let argv = argv_of(&input);
        assert_eq!(argv, spec.argv(), "{}", spec.tag);
        for k in [
            "--iface",
            "--src-ip",
            "--src-mac",
            "--targets",
            "--ports",
            "--checkpoint-out",
            "--resume-checkpoint",
        ] {
            assert!(!argv.iter().any(|a| a == k), "{}: {k}", spec.tag);
        }
        assert!(
            calls.iter().any(|c| c.starts_with("guest ")
                && c.contains(&format!(".{}.runner-argv.json", spec.tag))),
            "{}",
            spec.tag
        );
        // The preflight ran the same executable with the same argv plus --offline, read only.
        if spec.preflight.is_some() {
            let pre = read_json(d.join("runner-preflight-argv.json")).unwrap();
            assert_eq!(pre["exe"], RMASSCAN_EXE);
            let mut want = spec.argv();
            want.push("--offline".into());
            assert_eq!(argv_of(&pre), want, "{}", spec.tag);
        }
        let runner = read_json(d.join("guest-runner.json")).unwrap();
        assert_eq!(runner["exe_sha256"], EXE, "{}", spec.tag);
    }
    // Nothing of the wire_scan plans: no fixtures, no checkpoints, no injector, flood or link loss.
    for needle in [
        "checkpoint",
        "inject --iface",
        "flood --guest-mac",
        "linkloss --guest-mac",
    ] {
        assert_eq!(stand.count(needle), 0, "{needle}");
    }
}

#[test]
fn a_windows_autodetect_directory_written_by_the_suite_passes_autodetect_verify() {
    // The cross-check: the suite writes every run from the guest's and the captures' synthetic outputs, and both
    // autodetect-verify and windows-verify (which hands the directory over) find it PASS.
    let w = World::autodetect("cross", |_| {});
    let stand = autodetect_stand(&w);
    assert_eq!(
        run_with(&autodetect_args(&w, &[]), &stand).unwrap(),
        0,
        "{:?}",
        stand.calls()
    );
    let res = av::verify_dir(&w.root);
    assert_eq!(res["overall"], "PASS", "{:#?}", ad_bad(&res));
    for tag in av::planned_tags(Plan::Windows) {
        assert_eq!(ad_verdict(&res, tag), "PASS", "{tag}");
    }
    assert_eq!(ad_verdict(&res, "manifest"), "PASS");
    assert_eq!(crate::verify::verify_dir(&w.root), res);
    assert_eq!(
        crate::verify::run(&strings(&["--dir", w.root.to_str().unwrap()])).unwrap(),
        0
    );
    // The guest kernel's ARP answers are on the wire and counted as the OS's, never as the scanner's.
    let w01 = res["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["tag"] == "w01_auto")
        .unwrap();
    assert_eq!(w01["notes"]["os_arp"]["replies"], 1);
    // The guest scripts were sent from the work directory (`.ps1`/`.cmd` are no evidence), never from `deploy/`.
    let sent: Vec<String> = stand
        .calls()
        .into_iter()
        .filter(|c| {
            c.starts_with("scp ")
                && c.rsplit(' ').next().is_some_and(|to| {
                    to.starts_with("lab@127.0.0.1:")
                        && (to.ends_with(".ps1") || to.ends_with(".cmd"))
                })
        })
        .collect();
    assert_eq!(sent.len(), crate::deploy::GUEST_SCRIPTS.len(), "{sent:?}");
    let staged = w.root.join(".work").join("guest-scripts");
    for c in &sent {
        assert!(c.contains(&*staged.to_string_lossy()), "{c}");
    }
    // Nothing of the suite's own work is left in the evidence directory, no staged script, no full listing.
    assert!(!w.root.join(".work").exists());
    for f in every_file(&w.root) {
        let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
        assert!(av::EVIDENCE_EXTENSIONS.contains(&ext), "{}", f.display());
    }
}

#[test]
fn a_preflight_other_than_the_expected_detection_is_not_run_and_starts_nothing() {
    let w = World::autodetect("preflight", |sim| {
        if sim.case.tag == "w01_auto" {
            sim.preflight =
                Some("rc 0\n[+] interface = Ethernet (detected: route to 198.18.0.2)\n".into());
        }
    });
    let stand = autodetect_stand(&w);
    let e = run_with(&autodetect_args(&w, &["--only", "w01_auto"]), &stand).unwrap_err();
    assert!(
        matches!(&e, SuiteError::NotRun(m) if m.contains(PREFLIGHT_MARK)),
        "{e:?}"
    );
    assert_eq!(e.code(), 2);
    // Only the read-only preflight ran: no listener, capture, marker or scanner.
    for raw in [
        "listen --open",
        "tcpdump",
        "marker --iface",
        "windows_wire_runas.cmd \"",
    ] {
        assert_eq!(stand.count(raw), 0, "{raw}");
    }
    assert_eq!(stand.count("windows_wire_run.ps1 -ArgvFile"), 1);
    assert_eq!(stand.count("eno1_size="), 0);
    assert!(!w.root.join("runs/w01_auto").exists());
    // Nothing ran and nothing was captured: no failure copy of the remote scratch (it would bring the keep marker
    // home), the scratch and its marker are removed on home-pc, and only the orchestrator's records are kept.
    let copies = stand
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("scp home-pc:") && c.contains("/. "))
        .count();
    assert_eq!(copies, 0, "{:?}", stand.calls());
    assert!(
        stand.marker.borrow().is_none(),
        "the keep marker is cleared"
    );
    assert!(
        stand
            .calls()
            .iter()
            .any(|c| c.starts_with("home if test -e")
                && c.contains("rm -rf --")
                && c.contains("/w01_auto'")),
        "{:?}",
        stand.calls()
    );
    let files = every_file(&w.root);
    assert!(
        !files
            .iter()
            .any(|p| p.ends_with(ABORT_MARKER) || p.ends_with("eno1.pcap")),
        "{files:?}"
    );
    // What it printed is kept with the gate's records; the directory is NOT RUN, exactly, never INVALID or PASS.
    let kept: Vec<&PathBuf> = files
        .iter()
        .filter(|p| p.ends_with(av::PREFLIGHT_TXT))
        .collect();
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert!(
        kept[0].starts_with(w.root.join("runs_aborted")),
        "{}",
        kept[0].display()
    );
    assert!(
        fs::read_to_string(kept[0])
            .unwrap()
            .contains("interface = Ethernet (")
    );
    let res = av::verify_dir(&w.root);
    assert_eq!(ad_verdict(&res, "w01_auto"), "NOT RUN");
    assert_eq!(ad_verdict(&res, "manifest"), "PASS", "{:#?}", ad_bad(&res));
    assert_eq!(res["overall"], "NOT RUN", "{:#?}", ad_bad(&res));
    assert!(!w.root.join(".work").exists());
}

#[test]
fn an_autodetect_run_that_fails_after_the_send_is_kept_under_runs_aborted_and_never_in_runs() {
    let w = World::autodetect("abort", |_| {});
    let stand = autodetect_stand(&w);
    stand.knobs.borrow_mut().fail_runner = true;
    let e = run_with(&autodetect_args(&w, &["--only", "w02_adapter_npf"]), &stand).unwrap_err();
    assert_eq!(e.code(), 10, "{e:?}");
    assert!(!w.root.join("runs/w02_adapter_npf").exists());
    let aborted: Vec<PathBuf> = fs::read_dir(w.root.join("runs_aborted"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(aborted.len(), 1, "{aborted:?}");
    // The remote scratch (captures) and the orchestrator's own part of the run are both kept.
    assert!(aborted[0].join("eno1.pcap").is_file());
    assert!(aborted[0].join("work").join(av::ARGV_JSON).is_file());
    assert!(!w.root.join(".work").exists());
    let res = av::verify_dir(&w.root);
    assert_eq!(ad_verdict(&res, "w02_adapter_npf"), "NOT RUN");
    assert_eq!(res["safety_trips"], json!([]));
    // A scanner whose hash differs from the manifest's is refused: per run, and when a directory is extended.
    let w = World::autodetect("exe-hash", |_| {});
    let stand = autodetect_stand(&w);
    stand.knobs.borrow_mut().runner_exe_sha = Some("d".repeat(64));
    let e = run_with(&autodetect_args(&w, &["--only", "w02_adapter_npf"]), &stand).unwrap_err();
    assert!(e.message().contains("manifest"), "{e:?}");
    assert!(!w.root.join("runs/w02_adapter_npf").exists());
    let w = World::autodetect("exe-extend", |_| {});
    let stand = autodetect_stand(&w);
    assert_eq!(
        run_with(&autodetect_args(&w, &["--only", "w02_adapter_npf"]), &stand).unwrap(),
        0
    );
    let stand = autodetect_stand(&w);
    stand.knobs.borrow_mut().exe_hash = Some("e".repeat(64));
    let e = run_with(
        &autodetect_args(&w, &["--only", "w03_adapter_friendly"]),
        &stand,
    )
    .unwrap_err();
    assert!(
        matches!(&e, SuiteError::NotRun(m) if m.contains("sha256")),
        "{e:?}"
    );
    assert_eq!(stand.count("-Action Verify"), 0);
}

#[test]
fn an_autodetect_directory_never_runs_a_case_twice_or_over_a_work_directory() {
    let w = World::autodetect("twice", |_| {});
    let stand = autodetect_stand(&w);
    assert_eq!(
        run_with(&autodetect_args(&w, &["--only", "w02_adapter_npf"]), &stand).unwrap(),
        0
    );
    // A case that has a run is not run again into the same --out.
    let stand = autodetect_stand(&w);
    let e = run_with(&autodetect_args(&w, &["--only", "w02_adapter_npf"]), &stand).unwrap_err();
    assert!(
        matches!(&e, SuiteError::NotRun(m) if m.contains("w02_adapter_npf")),
        "{e:?}"
    );
    assert!(stand.calls().is_empty() && stand.locks.get() == 0);
    // Something left in the work directory (a crash) stops every start until it is looked at.
    fs::create_dir_all(w.root.join(".work/x")).unwrap();
    fs::write(w.root.join(".work/x/guest-iflist.raw"), "x").unwrap();
    let stand = autodetect_stand(&w);
    let e = run_with(
        &autodetect_args(&w, &["--only", "w03_adapter_friendly"]),
        &stand,
    )
    .unwrap_err();
    assert!(
        matches!(&e, SuiteError::NotRun(m) if m.contains(".work")),
        "{e:?}"
    );
    assert!(stand.calls().is_empty());
}

#[test]
fn an_autodetect_case_with_an_aborted_attempt_is_not_run_and_nothing_is_started() {
    // A preflight NOT RUN of an earlier start kept the orchestrator's records under runs_aborted/<tag>.<run id>/work/.
    // A later `--only <tag>` into the same --out is refused before any remote change, as a case with a run is.
    let w = World::autodetect("aborted-again", |_| {});
    let attempt = w.root.join("runs_aborted/w06_multi_no_gateway.r1/work");
    fs::create_dir_all(&attempt).unwrap();
    fs::write(attempt.join(av::PREFLIGHT_TXT), "rc 0\n").unwrap();
    let stand = autodetect_stand(&w);
    let e = run_with(
        &autodetect_args(&w, &["--only", "w06_multi_no_gateway"]),
        &stand,
    )
    .unwrap_err();
    assert!(
        matches!(&e, SuiteError::NotRun(m) if m.contains("runs_aborted/w06_multi_no_gateway.r1")),
        "{e:?}"
    );
    assert_eq!(e.code(), 2);
    assert!(stand.calls().is_empty() && stand.locks.get() == 0);
    // Another case of the directory still runs; the attempt stays visible and its case NOT RUN.
    let stand = autodetect_stand(&w);
    assert_eq!(
        run_with(&autodetect_args(&w, &["--only", "w01_auto"]), &stand).unwrap(),
        0
    );
    let res = av::verify_dir(&w.root);
    assert_eq!(ad_verdict(&res, "w01_auto"), "PASS", "{:#?}", ad_bad(&res));
    assert_eq!(ad_verdict(&res, "w06_multi_no_gateway"), "NOT RUN");
    assert_eq!(res["aborted"][0]["tag"], "w06_multi_no_gateway.r1");
}

#[test]
fn the_windows_autodetect_records_carry_out_and_account_as_placeholders() {
    // The orchestrator's records (the deploy manifest copy among them) go through the suites' one scrubber: its
    // --out and the account that started it are `$OUT` and `$USER` in the evidence.
    let w = World::autodetect("scrub", |_| {});
    let mut deploy =
        crate::deploy::build_manifest(COMMIT, REMOTE_LAB, LAB_BINARY, "rustc test", 1.0);
    deploy["toolchain"] = json!(format!(
        "rustc test, built by alice for {}",
        w.root.display()
    ));
    write_json(&w.deploy, &deploy).unwrap();
    let stand = autodetect_stand(&w);
    stand.knobs.borrow_mut().account = Some("alice".into());
    assert_eq!(run_with(&autodetect_args(&w, &[]), &stand).unwrap(), 0);
    let copy = read_json(w.root.join("deploy/deploy-manifest.json")).unwrap();
    assert_eq!(copy["toolchain"], "rustc test, built by $USER for $OUT");
    let root = w.root.to_string_lossy().into_owned();
    for f in every_file(&w.root) {
        let b = fs::read(&f).unwrap();
        for needle in [root.as_str(), "alice"] {
            assert!(
                !b.windows(needle.len()).any(|x| x == needle.as_bytes()),
                "{} holds {needle:?}",
                f.display()
            );
        }
    }
    let res = av::verify_dir(&w.root);
    assert_eq!(res["overall"], "PASS", "{:#?}", ad_bad(&res));
}

#[test]
fn the_peer_witness_of_a_windows_run_is_judged_by_the_capture_dump_rule() {
    // A complete capture: start marker, the run, three end markers; tcpdump counted and stored every frame, no drop,
    // the lab0 counters moved by exactly the frames, the wait went quiet, tcpdump exited.
    let sim = Sim::new(Plan::Windows, "w01_auto");
    let pcap = sim_file(&sim, "peer.pcap");
    let n = sim.peer.len() as u64;
    let cap = json!({"quiet":{"reached":true,"quiet_s":1.5},"peer":{
        "exited": true, "interface_drop_delta": 0,
        "tcpdump": {"captured": n, "received": n, "dropped_kernel": 0, "dropped_if": 0},
        "counters": {"rx_before": 10, "tx_before": 20, "rx_ready": 10, "tx_ready": 20, "rx_end": 10 + n, "tx_end": 20}}});
    let w = peer_witness(&cap, &pcap);
    assert_eq!(w["valid"], true, "{w}");
    assert_eq!(w["invalid_reasons"], json!([]));
    assert_eq!(w["pcap_sha256"], crate::verify::sha(&pcap));
    assert_eq!(w["pcap_frames"], n);
    let rec: av::PeerWitness = serde_json::from_value(w).unwrap();
    assert!(rec.valid);
    // Each broken fact alone makes the witness invalid, with its reason.
    let broken = |path: &str, v: Value| {
        let mut c = cap.clone();
        *c.pointer_mut(path).unwrap() = v;
        peer_witness(&c, &pcap)
    };
    for (path, v, why) in [
        (
            "/peer/tcpdump/dropped_kernel",
            json!(1),
            "tcpdump completeness",
        ),
        (
            "/peer/tcpdump/captured",
            json!(n - 1),
            "tcpdump completeness",
        ),
        ("/peer/interface_drop_delta", json!(2), "rx_dropped"),
        ("/peer/interface_drop_delta", Value::Null, "rx_dropped"),
        ("/peer/exited", json!(false), "did not exit"),
        ("/quiet/reached", json!(false), "never went quiet"),
        (
            "/peer/counters/rx_end",
            json!(10 + n - 1),
            "tcpdump completeness",
        ),
        (
            "/peer/counters/rx_end",
            json!(5),
            "decreased or were unreadable",
        ),
    ] {
        let w = broken(path, v.clone());
        assert_eq!(w["valid"], false, "{path} = {v}");
        assert!(
            w["invalid_reasons"].to_string().contains(why),
            "{path} = {v}: {}",
            w["invalid_reasons"]
        );
    }
    // Without its end markers the tail of the capture is not proven; a pcap that does not parse is no capture.
    let cut: Vec<_> = sim
        .peer
        .iter()
        .filter(|(_, f)| {
            !(f.get(12..14) == Some(&[0x88, 0xb5][..]) && f[14..].starts_with(b"WIRELAB-END"))
        })
        .cloned()
        .collect();
    let w = peer_witness(&cap, &crate::pcap::encode(&cut));
    assert_eq!(w["valid"], false);
    assert!(
        w["invalid_reasons"].to_string().contains("end markers"),
        "{w}"
    );
    let w = peer_witness(&cap, b"not a pcap");
    assert_eq!(w["valid"], false);
    assert!(
        w["invalid_reasons"].to_string().contains("pcap unreadable"),
        "{w}"
    );
}

// ---- Task 6d fix round 1 ----
#[test]
fn the_guest_runner_must_have_run_the_executable_it_was_given() {
    // runner.json names what the guest runner really started; the autodetect plan accepts only `--guest-exe`.
    let w = World::autodetect("runner-exe", |_| {});
    let stand = autodetect_stand(&w);
    assert_eq!(
        run_with(&autodetect_args(&w, &["--only", "w02_adapter_npf"]), &stand).unwrap(),
        0
    );
    let runner = read_json(w.root.join("runs/w02_adapter_npf/guest-runner.json")).unwrap();
    assert_eq!(runner["exe"], RMASSCAN_EXE);
    // The same sha256 under another executable (a wire_scan.exe that the runner was pointed at) is refused.
    let w = World::autodetect("runner-exe-other", |_| {});
    let stand = autodetect_stand(&w);
    stand.knobs.borrow_mut().runner_exe = Some("C:\\Users\\lab\\t4\\wire_scan.exe".into());
    let e = run_with(&autodetect_args(&w, &["--only", "w02_adapter_npf"]), &stand).unwrap_err();
    assert!(
        matches!(&e, SuiteError::Abort(m) if m.contains("wire_scan.exe") && m.contains("rmasscan.exe")),
        "{e:?}"
    );
    assert!(!w.root.join("runs/w02_adapter_npf").exists());
}

#[test]
fn the_deploy_record_hashes_the_trust_anchor_and_the_scrubbed_copy_it_keeps() {
    let w = World::autodetect("deploy-hash", |_| {});
    let stand = autodetect_stand(&w);
    assert_eq!(
        run_with(&autodetect_args(&w, &["--only", "w02_adapter_npf"]), &stand).unwrap(),
        0
    );
    let copy = w.root.join("deploy/deploy-manifest.json");
    let text = fs::read_to_string(&copy).unwrap();
    assert!(
        !text.contains("/home/a1") && text.contains("$HOME"),
        "{text}"
    );
    let pre = fs::read_dir(w.root.join("deploy"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with("preflight-"))
        .unwrap()
        .path();
    let rec = read_json(pre).unwrap();
    // The anchor on the orchestrating machine (what vouched for the binary) and the copy in the directory.
    assert_eq!(rec["deploy_manifest_sha256"], hash(&w.deploy).unwrap());
    assert_eq!(
        rec["deploy_manifest_copy"]["path"],
        "deploy/deploy-manifest.json"
    );
    assert_eq!(rec["deploy_manifest_copy"]["sha256"], hash(&copy).unwrap());
    assert_eq!(rec["deploy_manifest_copy"]["scrubbed"], true);
    assert_ne!(hash(&copy).unwrap(), hash(&w.deploy).unwrap());
}

#[test]
fn an_iflist_stand_line_in_the_windows_cli_format_passes_with_the_e1000e_nic() {
    // The n2 guest's NICs are e1000e ("Intel(R) 82574L Gigabit Network Connection", "… #2"). rmasscan --iflist prints
    // `desc=` from the adapter's FriendlyName (route_parse::iface_from_adapter), so the stand line reads
    // `… desc=Ethernet 2`; a line carrying the hardware description must pass as well.
    use rmasscan_net::{Iface, Route, iflist_text};
    use std::net::Ipv4Addr;
    let mac = |b: [u8; 6]| Some(b);
    let iface = |name: &str, index, id: &str, desc: &str, m, ip: Vec<Ipv4Addr>| Iface {
        name: name.into(),
        index,
        device_id: id.into(),
        description: Some(desc.into()),
        mac: m,
        mac_masked: false,
        ethernet: true,
        up: true,
        ipv4: ip,
    };
    let lab_id = IFACE;
    for lab_desc in [
        "Ethernet 2",
        "Intel(R) 82574L Gigabit Network Connection #2",
    ] {
        let listing = iflist_text(
            &[
                iface(
                    "Ethernet",
                    4,
                    "\\Device\\NPF_{0B9A3C1D-1111-2222-3333-444455556666}",
                    "Intel(R) 82574L Gigabit Network Connection",
                    mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]),
                    vec![Ipv4Addr::new(10, 0, 2, 15)],
                ),
                iface(
                    "Ethernet 2",
                    14,
                    lab_id,
                    lab_desc,
                    mac([0x52, 0x54, 0, 0x04, 0x80, 0xa9]),
                    vec![Ipv4Addr::new(198, 18, 0, 1)],
                ),
            ],
            &[Route {
                ifindex: 4,
                ifname: "Ethernet".into(),
                gateway: Some(Ipv4Addr::new(10, 0, 2, 2)),
                local: false,
            }],
        );
        let w = World::autodetect("e1000e", |_| {});
        for tag in ["w07_iflist", "w08a_restricted_iflist"] {
            fs::write(
                w.src.join("runs").join(tag).join("guest/stdout.txt"),
                &listing,
            )
            .unwrap();
        }
        let stand = autodetect_stand(&w);
        assert_eq!(
            run_with(
                &autodetect_args(&w, &["--only", "w07_iflist", "w08a_restricted_iflist"]),
                &stand
            )
            .unwrap(),
            0
        );
        let res = av::verify_dir(&w.root);
        for tag in ["w07_iflist", "w08a_restricted_iflist"] {
            assert_eq!(
                ad_verdict(&res, tag),
                "PASS",
                "{lab_desc}: {:#?}",
                ad_bad(&res)
            );
            let rec: IflistRecord = serde_json::from_slice(
                &fs::read(w.root.join("runs").join(tag).join(av::IFLIST_JSON)).unwrap(),
            )
            .unwrap();
            let line = rec.stand_line.unwrap();
            assert_eq!(
                line,
                format!(
                    "Ethernet 2 index=14 mac=52-54-00-04-80-a9 ipv4=198.18.0.1 up ethernet id={lab_id} desc={lab_desc}"
                )
            );
            assert_eq!(rec.lines, 3);
        }
        for f in every_file(&w.root) {
            let t = String::from_utf8_lossy(&fs::read(&f).unwrap()).into_owned();
            for host in ["10.0.2.15", "52-54-00-12-34-56", "10.0.2.2", "0B9A3C1D"] {
                assert!(!t.contains(host), "{}: {host}", f.display());
            }
        }
    }
}
