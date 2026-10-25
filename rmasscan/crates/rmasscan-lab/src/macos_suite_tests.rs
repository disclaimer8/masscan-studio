//! The suite against a recording stand: nothing opens an interface, runs a process or writes a
//! frame. Scratch names come from `windows_suite::nonce`, never from the clock.
use super::*;
use crate::windows_suite::nonce;
use rmasscan_engine::IoError;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-macos-suite-{}", nonce()));
    fs::create_dir_all(&d).unwrap();
    d
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// Exits at once with this code.
    Exits(i32),
    /// Runs for this many `try_wait` calls, then exits 3 (a scan that ran its course).
    ExitsAfter(u32),
    /// Runs until it is signalled (INT or TERM) or killed.
    Hangs,
    /// The first `try_wait` fails, then it runs until signalled.
    FailsOnceThenHangs,
}
struct FakeProc {
    name: &'static str,
    log: Rc<RefCell<Vec<String>>>,
    mode: Mode,
    done: bool,
    failed: bool,
    polls: u32,
    pgid: u32,
}
impl Proc for FakeProc {
    fn pgid(&self) -> Option<u32> {
        Some(self.pgid)
    }
    fn try_wait(&mut self) -> Result<Option<i32>, String> {
        match self.mode {
            Mode::Exits(rc) => Ok(Some(rc)),
            Mode::ExitsAfter(n) => {
                self.polls += 1;
                Ok((self.polls > n || self.done).then_some(3))
            }
            Mode::FailsOnceThenHangs if !self.failed => {
                self.failed = true;
                Err("try_wait failed".into())
            }
            _ => Ok(self.done.then_some(0)),
        }
    }
    fn signal(&mut self, sig: &str) {
        self.log.borrow_mut().push(format!("{}:{sig}", self.name));
        self.done = true;
    }
    fn kill(&mut self) {
        self.log.borrow_mut().push(format!("{}:KILL", self.name));
        self.done = true;
    }
}
struct FakeSide(Value);
impl Side for FakeSide {
    fn finish(self: Box<Self>) -> Result<Value, String> {
        Ok(self.0)
    }
}

struct Fake {
    allowed: Cell<bool>,
    bpf: RefCell<String>,
    ack: Cell<bool>,
    uplink_frames: Cell<usize>,
    wire: String,
    spawned: RefCell<Vec<Vec<String>>>,
    markers: Cell<u32>,
    stopped: Cell<bool>,
    euid: Cell<u32>,
    alf_enabled: Cell<bool>,
    /// Overrides the socketfilterfw answer (exit code, stdout).
    alf_raw: RefCell<Option<(i32, String)>>,
    scanner: Cell<Mode>,
    log: Rc<RefCell<Vec<String>>>,
    peer_up: Cell<bool>,
    /// `link_state` reports the peer down from this call on (0: never).
    flip_after: Cell<u32>,
    link_calls: Cell<u32>,
    /// What `ps -axo pid,pgid,command` prints.
    ps_text: RefCell<String>,
    /// The lock file path, whose content is read at the moment the scanner is spawned.
    lock_file: RefCell<Option<PathBuf>>,
    lock_at_scanner: RefCell<String>,
}
impl Fake {
    fn new(wire: &str) -> Self {
        Self {
            allowed: Cell::new(true),
            bpf: RefCell::new("granted".into()),
            ack: Cell::new(true),
            uplink_frames: Cell::new(0),
            wire: wire.into(),
            spawned: RefCell::default(),
            markers: Cell::new(0),
            stopped: Cell::new(false),
            euid: Cell::new(501),
            alf_enabled: Cell::new(false),
            alf_raw: RefCell::default(),
            scanner: Cell::new(Mode::Exits(0)),
            log: Rc::default(),
            peer_up: Cell::new(true),
            flip_after: Cell::new(0),
            link_calls: Cell::new(0),
            ps_text: RefCell::default(),
            lock_file: RefCell::default(),
            lock_at_scanner: RefCell::default(),
        }
    }
    fn scanner_runs(&self) -> usize {
        self.spawned
            .borrow()
            .iter()
            .filter(|a| a[0] == self.wire)
            .count()
    }
    fn any_spawned(&self) -> bool {
        !self.spawned.borrow().is_empty()
    }
    fn position(&self, what: &str) -> Option<usize> {
        self.log.borrow().iter().position(|x| x == what)
    }
}
fn after<'a>(a: &'a [String], k: &str) -> &'a str {
    let i = a.iter().position(|x| x == k).unwrap();
    &a[i + 1]
}
fn err_text(frames: usize) -> String {
    err_text3(frames, frames, 0)
}
fn err_text3(captured: usize, received: usize, dropped: usize) -> String {
    format!(
        "tcpdump: listening on x, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n{captured} packets captured\n{received} packets received by filter\n{dropped} packets dropped by kernel\n"
    )
}
fn pcap_of(n: usize) -> Vec<u8> {
    let frames: pcap::Frames = (0..n)
        .map(|k| (1.0 + k as f64, flood_frame(k as u32)))
        .collect();
    pcap::encode(&frames)
}
impl Stand for Fake {
    fn exec(&self, argv: &[String], _timeout: u64) -> Result<Output, String> {
        if argv.iter().any(|a| a == "status") {
            let ok = self.allowed.get();
            return Ok(Output {
                rc: if ok { 0 } else { 3 },
                stdout: json!({"raw_run_allowed":ok,"bpf_access":*self.bpf.borrow(),"uplink":"en0",
                    "gateway":"192.168.1.1","checks":[{"name":"arp","ok":ok}]})
                .to_string(),
                stderr: String::new(),
            });
        }
        if argv[0] == "/usr/sbin/sysctl" {
            return Ok(Output {
                rc: 0,
                stdout: "250\n".into(),
                stderr: String::new(),
            });
        }
        if argv[0] == "/bin/ps" {
            return Ok(Output {
                rc: 0,
                stdout: self.ps_text.borrow().clone(),
                stderr: String::new(),
            });
        }
        if argv[0].ends_with("socketfilterfw") {
            if let Some((rc, out)) = self.alf_raw.borrow().clone() {
                return Ok(Output {
                    rc,
                    stdout: out,
                    stderr: String::new(),
                });
            }
            let on = self.alf_enabled.get();
            return Ok(Output {
                rc: 0,
                stdout: format!(
                    "Firewall is {}. (State = {})\n",
                    if on { "enabled" } else { "disabled" },
                    u8::from(on)
                ),
                stderr: String::new(),
            });
        }
        self.spawned.borrow_mut().push(argv.to_vec());
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
    ) -> Result<Box<dyn Proc>, String> {
        self.spawned.borrow_mut().push(argv.to_vec());
        fs::write(stdout, "").unwrap();
        fs::write(stderr, "").unwrap();
        let mut name = "other";
        let mut mode = Mode::Exits(0);
        if argv.iter().any(|a| a == "listen") {
            name = "listener";
            fs::write(
                after(argv, "--ready"),
                json!({"open":[80],"silent":[8099],"silent_proven":true,"ready":true}).to_string(),
            )
            .unwrap();
        } else if argv[0] == "/usr/sbin/tcpdump" {
            name = "uplink";
            fs::write(after(argv, "-w"), pcap_of(self.uplink_frames.get())).unwrap();
            // macOS: frames the descriptor saw before its filter are counted as received; only
            // what passed the filter is captured.
            fs::write(
                stderr,
                err_text3(self.uplink_frames.get(), self.uplink_frames.get() + 57, 0),
            )
            .unwrap();
        } else if argv.iter().any(|a| a == "dump") {
            name = "witness";
            let p = after(argv, "--pcap");
            fs::write(after(argv, "--ready"), "{}").unwrap();
            if self.ack.get() {
                fs::write(after(argv, "--ack"), "ack\n").unwrap();
            }
            fs::write(p, pcap_of(6)).unwrap();
            fs::write(format!("{p}.tcpdump.err"), err_text(6)).unwrap();
            fs::write(
                after(argv, "--meta"),
                json!({"tcpdump_argv":["tcpdump","-i","feth4202"],"interface_drop_delta":0,
                    "iface_rxtx_delta_lo":3,"iface_rxtx_delta_hi":6,"quiesced_before_stop":true,
                    "valid":true,"invalid_reasons":[]})
                .to_string(),
            )
            .unwrap();
        } else if argv[0] == self.wire {
            name = "scanner";
            if let Some(p) = self.lock_file.borrow().as_ref() {
                *self.lock_at_scanner.borrow_mut() = fs::read_to_string(p).unwrap_or_default();
            }
            mode = self.scanner.get();
            fs::write(
                stdout,
                format!("{}\n", json!({"status":"ok","reason":"Completed","sent":1})),
            )
            .unwrap();
        }
        Ok(Box::new(FakeProc {
            name,
            log: self.log.clone(),
            mode,
            done: false,
            failed: false,
            polls: 0,
            pgid: 9000 + self.spawned.borrow().len() as u32,
        }))
    }
    fn counters(&self, _: &str) -> Result<NetstatCounters, String> {
        Ok(NetstatCounters {
            ipkts: 1,
            opkts: 1,
            ierrs: 0,
            drop: 0,
        })
    }
    fn iface_mac(&self, iface: &str) -> Result<String, String> {
        Ok(if iface == SCANNER_IF {
            SCANNER_MAC
        } else {
            PEER_MAC
        }
        .to_owned())
    }
    fn send_start_markers(&self) -> Result<(), String> {
        self.markers.set(self.markers.get() + 1);
        Ok(())
    }
    fn start_injector(&self, _: &InjectSpec) -> Result<Box<dyn Side>, String> {
        Ok(Box::new(FakeSide(json!({"sent_total":3,"kinds":{}}))))
    }
    fn start_flood(&self, _: &FloodSpec) -> Result<Box<dyn Side>, String> {
        Ok(Box::new(FakeSide(json!({"sent":3,"errors":0}))))
    }
    fn flood_burst_frames(&self) -> Result<u64, String> {
        Ok(10)
    }
    fn link_state(&self) -> Result<LinkState, String> {
        self.link_calls.set(self.link_calls.get() + 1);
        let flipped = self.flip_after.get() != 0 && self.link_calls.get() >= self.flip_after.get();
        Ok(LinkState {
            peer_up: self.peer_up.get() && !flipped,
            scanner_active: true,
        })
    }
    fn euid(&self) -> Result<u32, String> {
        Ok(self.euid.get())
    }
    fn provenance(&self, _: &Path) -> Value {
        json!({"git_commit":COMMIT,"git_dirty":false,"binary_sha256":"ab".repeat(32),"errors":[]})
    }
    fn pause(&self, _: Duration) {}
    fn stopped(&self) -> bool {
        self.stopped.get()
    }
}

struct Rig {
    root: PathBuf,
    out: PathBuf,
    fixtures: PathBuf,
    wire: String,
}
impl Rig {
    fn new() -> Self {
        let root = scratch();
        let wire = root.join("wire_scan");
        fs::write(&wire, b"scanner").unwrap();
        let fixtures = root.join("fixtures");
        fs::create_dir_all(&fixtures).unwrap();
        fs::write(
            fixtures.join("manifest.json"),
            json!({"all_valid":true,"binding":{"src_ip":SOURCE_IP,"src_mac":SCANNER_MAC,"router_mac":PEER_MAC}})
                .to_string(),
        )
        .unwrap();
        Self {
            out: root.join("out"),
            root,
            fixtures,
            wire: wire.to_string_lossy().into_owned(),
        }
    }
    fn args(&self, extra: &[&str]) -> Vec<String> {
        let mut a: Vec<String> = [
            "--out",
            &p2s(&self.out),
            "--commit",
            COMMIT,
            "--wire-scan",
            &self.wire,
            "--fixtures",
            &p2s(&self.fixtures),
            "--repo",
            ".",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        a.extend(extra.iter().map(|s| (*s).to_owned()));
        a
    }
    fn lock(&self) -> Box<dyn Fn() -> Result<Lock, String>> {
        let p = self.root.join("suite.lock");
        Box::new(move || take_lock(&p))
    }
    fn suite<'a>(&self, st: &'a Fake, plan: &str) -> Suite<'a> {
        let man = json!({
            "plan":plan,"macos_capture_schema":1,
            "binding":{"iface":SCANNER_IF,"src_ip":SOURCE_IP,"src_mac":SCANNER_MAC,"router_mac":PEER_MAC,"seed":1,"rate":100,"wait":3},
        });
        fs::create_dir_all(&self.out).unwrap();
        Suite {
            st,
            exe: "/x/rmasscan-lab".into(),
            out: self.out.clone(),
            plan: plan.into(),
            wire_scan: self.wire.clone(),
            wire_sha: hash(&self.wire).unwrap(),
            lab_run_id: "m1".into(),
            lab_manifest: None,
            lock_path: None,
            children: RefCell::default(),
            timeout: 30,
            man,
        }
    }
}
impl Drop for Rig {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn item(plan: &str, tag: &str) -> Value {
    mv::planned(&json!({"plan":plan}))
        .into_iter()
        .find(|i| i["tag"] == tag)
        .unwrap()
}
const C01: &str = "c01_one_addr_port_synack.run1";

#[test]
fn gate_refuses_when_status_pre_not_allowed() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    st.allowed.set(false);
    let s = rig.suite(&st, "functional");
    let e = s.one(&item("functional", C01), 30).unwrap_err();
    assert!(matches!(e, SuiteError::NotRun(_)), "{e:?}");
    assert!(e.message().contains("not sealed"), "{}", e.message());
    assert!(
        !st.any_spawned(),
        "no listener, capture or scanner may start behind a refused gate: {:?}",
        st.spawned.borrow()
    );
    assert_eq!(st.markers.get(), 0);
    assert!(!rig.out.join("runs").exists() && !rig.out.join("runs_aborted").exists());
    // The run directory it made is gone: nothing was started, nothing to keep.
    assert_eq!(fs::read_dir(rig.out.join(".work")).unwrap().count(), 0);
}

#[test]
fn gate_refuses_when_start_marker_missing() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    st.ack.set(false);
    let s = rig.suite(&st, "functional");
    let e = s.one(&item("functional", C01), 30).unwrap_err();
    assert!(matches!(e, SuiteError::NotRun(_)), "{e:?}");
    assert!(e.message().contains("start marker"), "{}", e.message());
    assert_eq!(
        st.scanner_runs(),
        0,
        "the scanner must not start without the marker in the capture"
    );
    assert_eq!(st.markers.get(), 1);
    // Frames may have existed (the marker), so the evidence is kept and hash-checked.
    let kept: Vec<_> = fs::read_dir(rig.out.join("runs_aborted"))
        .unwrap()
        .collect();
    assert_eq!(kept.len(), 1);
    let d = kept[0].as_ref().unwrap().path();
    assert!(d.join("hashes-before-copy.txt").is_file() && d.join("uplink.pcap").is_file());
}

#[test]
fn hashes_are_taken_before_copy_and_checked_after() {
    let root = scratch();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    fs::write(work.join("a.json"), "{}").unwrap();
    fs::write(work.join("b.pcap"), [1, 2, 3]).unwrap();
    let dest = root.join("dest");
    copy_verified(&work, &dest, &|_| {}).unwrap();
    // The list sits in the work directory (written before the copy) and in the copy, identical.
    let before = fs::read_to_string(work.join("hashes-before-copy.txt")).unwrap();
    assert_eq!(
        before,
        fs::read_to_string(dest.join("hashes-before-copy.txt")).unwrap()
    );
    assert!(before.contains(&format!("{}  a.json", hash(work.join("a.json")).unwrap())));
    assert_eq!(before.lines().count(), 2, "the list does not list itself");
    // A copy that changed after the hashes were taken is refused, and the work directory stays.
    let dest2 = root.join("dest2");
    let e = copy_verified(&work, &dest2, &|d| {
        fs::write(d.join("b.pcap"), [9]).unwrap()
    })
    .unwrap_err();
    assert!(
        e.contains("differs after the copy") && e.contains("kept"),
        "{e}"
    );
    assert!(work.join("b.pcap").exists());
    // Only plain files are evidence.
    fs::create_dir(work.join("sub")).unwrap();
    assert!(copy_verified(&work, &root.join("dest3"), &|_| {}).is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn uplink_frame_stops_the_suite_with_exit_13() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    st.uplink_frames.set(1);
    // `--only` takes every tag after it: both runs of c01 are requested, only the first may start.
    let e = run_locked(
        &rig.args(&["--only", C01, "c01_one_addr_port_synack.run2"]),
        &st,
        PathBuf::from("/x/rmasscan-lab"),
        rig.lock().as_ref(),
    )
    .unwrap_err();
    assert!(matches!(e, SuiteError::Isolation(_)), "{e:?}");
    assert_eq!(e.code(), 13);
    assert!(e.message().contains(LAB_FRAME_MARK), "{}", e.message());
    assert_eq!(
        st.scanner_runs(),
        1,
        "no further raw run after a lab frame on the uplink"
    );
    // The evidence is kept under runs_aborted and the directory is FAIL for good.
    assert_eq!(
        fs::read_dir(rig.out.join("runs_aborted")).unwrap().count(),
        1
    );
    assert!(
        !rig.out.join("runs").exists() || fs::read_dir(rig.out.join("runs")).unwrap().count() == 0
    );
    assert_eq!(mv::safety_trips(&rig.out).len(), 1);
    // A new start in that directory is refused with the same exit code, before any process starts.
    let st2 = Fake::new(&rig.wire);
    let again = run_locked(
        &rig.args(&["--only", C01]),
        &st2,
        PathBuf::from("/x/l"),
        rig.lock().as_ref(),
    )
    .unwrap_err();
    assert_eq!(again.code(), 13);
    assert!(!st2.any_spawned());
}

#[test]
fn perm_denied_requires_bpf_access_denied() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    let s = rig.suite(&st, "failure");
    let scratch_dir = s.out.join(".work/g");
    fs::create_dir_all(&scratch_dir).unwrap();
    let perm = item("failure", "perm_denied_scan");
    let inv = item("failure", "perm_inventory_control");
    let normal = item("failure", "stop_silent");
    // granted: the permission runs are refused, the others pass the gate.
    *st.bpf.borrow_mut() = "granted".into();
    for it in [&perm, &inv] {
        let e = s.gate_status(&scratch_dir, it).unwrap_err();
        assert!(
            matches!(e, SuiteError::NotRun(_)) && e.message().contains("needs bpf_access denied"),
            "{e:?}"
        );
    }
    assert!(s.gate_status(&scratch_dir, &normal).is_ok());
    // denied: the reverse.
    *st.bpf.borrow_mut() = "denied".into();
    assert!(s.gate_status(&scratch_dir, &perm).is_ok());
    assert!(s.gate_status(&scratch_dir, &inv).is_ok());
    let e = s.gate_status(&scratch_dir, &normal).unwrap_err();
    assert!(
        e.message().contains("needs bpf_access granted"),
        "{}",
        e.message()
    );
    // mixed is neither.
    *st.bpf.borrow_mut() = "mixed".into();
    assert!(
        s.gate_status(&scratch_dir, &perm).is_err()
            && s.gate_status(&scratch_dir, &normal).is_err()
    );
}

#[test]
fn perm_denied_runs_use_counters_and_no_capture() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    *st.bpf.borrow_mut() = "denied".into();
    let s = rig.suite(&st, "failure");
    // The fake scanner exits 0 with a Completed summary; the point is what the suite starts and records.
    let dest = s.one(&item("failure", "perm_denied_scan"), 30).unwrap();
    let spawned = st.spawned.borrow();
    assert!(
        !spawned
            .iter()
            .any(|a| a[0] == "/usr/sbin/tcpdump" || a.iter().any(|x| x == "dump")),
        "no capture can run while BPF is denied: {spawned:?}"
    );
    assert_eq!(st.markers.get(), 0);
    assert!(dest.join("counters.json").is_file() && dest.join("capture.json").is_file());
    let cap: Value = serde_json::from_slice(&fs::read(dest.join("capture.json")).unwrap()).unwrap();
    assert_eq!(cap["witness"], mv::NO_WITNESS);
}

#[test]
fn only_and_rerun_accept_discardable_runs_only() {
    let root = scratch();
    let mk = |tag: &str| {
        let d = root.join("runs").join(format!("{tag}.{}", nonce()));
        fs::create_dir_all(&d).unwrap();
        d
    };
    let a = mk("a_tag");
    let status =
        |verdict: &'static str, beh: bool| move |_: &Path, _: &str| (verdict.to_owned(), beh);
    // Not a rerun: nothing is moved.
    assert!(
        discard_plan(&root, &[], false, &status(PASS_, false))
            .unwrap()
            .is_empty()
    );
    // A rerun needs explicit tags.
    assert!(matches!(
        discard_plan(&root, &[], true, &status("NOT RUN", false)),
        Err(SuiteError::NotRun(_))
    ));
    let only = vec!["a_tag".to_owned()];
    for (v, b) in [("NOT RUN", false), ("INVALID", false)] {
        assert_eq!(
            discard_plan(&root, &only, true, &status(v, b)).unwrap(),
            vec![a.clone()],
            "{v}"
        );
    }
    for (v, b) in [
        ("INVALID", true),
        ("FAIL", false),
        ("PASS", false),
        ("NOT RUN", true),
    ] {
        let e = discard_plan(&root, &only, true, &status(v, b)).unwrap_err();
        assert!(matches!(e, SuiteError::RerunRefused(_)), "{v} {b}");
        assert_eq!(e.code(), 11);
    }
    // A tag with no run yet is simply run.
    assert!(
        discard_plan(
            &root,
            &["never_run".to_owned()],
            true,
            &status("FAIL", false)
        )
        .unwrap()
        .is_empty()
    );
    // Two directories of one tag are ambiguous and never discarded.
    mk("a_tag");
    assert!(discard_plan(&root, &only, true, &status("NOT RUN", false)).is_err());
    let _ = fs::remove_dir_all(root);
}
const PASS_: &str = "PASS";

#[test]
fn lock_file_refuses_a_second_suite() {
    let root = scratch();
    let p = root.join("sub/macos-suite.lock");
    let first = take_lock(&p).unwrap();
    let text = fs::read_to_string(&p).unwrap();
    assert!(
        text.contains(&format!("pid={}", std::process::id())) && text.contains("start="),
        "{text}"
    );
    let e = take_lock(&p).err().unwrap();
    assert!(
        e.contains("another macos-suite") && e.contains(&format!("pid={}", std::process::id())),
        "{e}"
    );
    // The owner is alive: the lock is not stale, and nothing removes it for us.
    assert!(remove_stale_lock(&p).is_err());
    assert!(p.exists());
    drop(first);
    assert!(!p.exists(), "a normal exit releases the lock");
    // A dead owner leaves a lock that is never taken over automatically, only removed explicitly.
    fs::write(&p, "pid=4294967290\nstart=1\n").unwrap();
    let e = take_lock(&p).err().unwrap();
    assert!(e.contains("--remove-stale-lock"), "{e}");
    assert!(p.exists());
    remove_stale_lock(&p).unwrap();
    assert!(take_lock(&p).is_ok());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_second_suite_does_not_start_anything() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    let held = take_lock(&rig.root.join("suite.lock")).unwrap();
    let e = run_locked(
        &rig.args(&["--only", C01]),
        &st,
        PathBuf::from("/x/l"),
        rig.lock().as_ref(),
    )
    .unwrap_err();
    assert!(
        matches!(e, SuiteError::NotRun(_)) && e.message().contains("another macos-suite"),
        "{e:?}"
    );
    assert!(!st.any_spawned());
    drop(held);
}

#[test]
fn options_are_validated_by_name() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    let go = |extra: &[&str]| {
        run_locked(
            &rig.args(extra),
            &st,
            PathBuf::from("/x/l"),
            rig.lock().as_ref(),
        )
    };
    let msg = |r: Result<i32, SuiteError>| r.unwrap_err().message().to_owned();
    assert!(msg(go(&["--bogus", "1"])).contains("unknown option --bogus"));
    assert!(msg(go(&["--plan", "functional", "--plan", "perf"])).contains("more than once"));
    assert!(msg(go(&["--plan", "nope"])).contains("unknown suite plan"));
    assert!(msg(go(&["--plan", "perf"])).contains("explicit --suite"));
    assert!(msg(go(&["--only", "no_such_tag"])).contains("unknown or unsafe tag"));
    assert!(msg(go(&["--rerun"])).contains("--only"));
    assert!(msg(go(&["--plan", "functional", "--reps", "2"])).contains("perf only"));
    assert!(msg(go(&["--plan", "perf", "--suite", "p", "--rates", "7"])).contains("subset"));
    assert!(msg(go(&["--plan", "perf", "--suite", "p", "--reps", "6"])).contains("--reps"));
    let bad: Vec<String> = [
        "--out",
        "x",
        "--commit",
        "abc",
        "--wire-scan",
        "w",
        "--fixtures",
        "f",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    let e = run_locked(&bad, &st, PathBuf::from("/x/l"), rig.lock().as_ref()).unwrap_err();
    assert!(e.message().contains("full SHA"), "{}", e.message());
    assert!(!st.any_spawned());
    assert!(
        !rig.out.join("manifest.json").exists(),
        "a refused option list changes nothing"
    );
}

#[test]
fn list_prints_the_plan_without_any_action() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    let perf = selected_plan("perf", None, None).unwrap();
    assert_eq!(list_lines(&perf).len(), 20);
    assert_eq!(list_lines(&perf)[0], "perf.100.r1 perf");
    assert_eq!(
        selected_plan("perf", Some(2), Some(&[100, 1000]))
            .unwrap()
            .len(),
        4
    );
    assert_eq!(selected_plan("failure", None, None).unwrap().len(), 17);
    assert_eq!(selected_plan("functional", None, None).unwrap().len(), 24);
    assert_eq!(
        run_locked(
            &rig.args(&["--list", "--plan", "perf"]),
            &st,
            PathBuf::from("/x/l"),
            rig.lock().as_ref()
        )
        .unwrap(),
        0
    );
    assert!(!st.any_spawned());
    assert!(!rig.out.exists() || fs::read_dir(&rig.out).unwrap().count() == 0);
}

#[test]
fn the_lab_writes_only_peer_to_scanner_markers_and_peer_ip_frames() {
    let marker = link::marker_frame(SM, PM, link::START_PAYLOAD);
    assert!(link::injection_allowed(&marker));
    assert!(link::injection_allowed(&flood_frame(7)));
    // The foreign replies: three kinds are inside the guard, the 198.18.0.3 one is not.
    let frames =
        crate::peer::foreign_frames(PEER_MAC, SCANNER_MAC, SOURCE_IP, 40000, 8099).unwrap();
    for (k, f) in &frames {
        assert_eq!(link::injection_allowed(f), k != "other_ip", "{k}");
    }
    let mut bad = marker.clone();
    bad[0] ^= 1;
    assert!(!link::injection_allowed(&bad), "wrong destination MAC");
    let mut bad = marker.clone();
    bad[6] ^= 1;
    assert!(!link::injection_allowed(&bad), "wrong source MAC");
    let mut bad = marker.clone();
    bad[12..14].copy_from_slice(&[0x08, 0x06]);
    assert!(!link::injection_allowed(&bad), "ARP");
    let mut ip = frames["unscanned_port"].clone();
    assert!(link::injection_allowed(&ip));
    ip[30..34].copy_from_slice(&[198, 18, 0, 9]);
    assert!(!link::injection_allowed(&ip), "another destination");
    assert!(!link::injection_allowed(&marker[..13]) && !link::injection_allowed(&[]));
    // The guard in front of the real Tx refuses and counts, and passes the good frame through.
    struct Count(Arc<AtomicU64>);
    impl Tx for Count {
        fn send(&mut self, _: &[u8], _: Duration) -> Result<SendStatus, IoError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(SendStatus::Sent)
        }
    }
    let written = Arc::new(AtomicU64::new(0));
    let refused = Arc::new(AtomicU64::new(0));
    let mut g = link::GuardedTx {
        inner: Box::new(Count(written.clone())),
        refused: refused.clone(),
    };
    assert_eq!(
        g.send(&marker, Duration::from_millis(1)).unwrap(),
        SendStatus::Sent
    );
    assert!(g.send(&bad, Duration::from_millis(1)).is_err());
    assert_eq!(
        (
            written.load(Ordering::Relaxed),
            refused.load(Ordering::Relaxed)
        ),
        (1, 1)
    );
}

#[test]
fn the_flood_frame_is_recognised_by_the_verifier() {
    assert!(crate::verify::is_flood(&flood_frame(1)));
    assert!(!crate::verify::is_flood(&link::marker_frame(
        SM,
        PM,
        link::END_PAYLOAD
    )));
}

#[test]
fn an_uplink_capture_that_cannot_be_read_is_not_isolation_proof() {
    let d = scratch();
    let e = uplink_interlock(&d).unwrap_err();
    assert!(e.contains(UNPROVEN_MARK), "{e}");
    fs::write(d.join("uplink.pcap"), pcap_of(0)).unwrap();
    assert!(uplink_interlock(&d).is_err(), "no counters, no proof");
    fs::write(d.join("uplink.err"), err_text(0)).unwrap();
    assert!(uplink_interlock(&d).is_ok());
    fs::write(d.join("uplink.err"), err_text(2)).unwrap();
    assert!(uplink_interlock(&d).unwrap_err().contains(LAB_FRAME_MARK));
    fs::write(d.join("uplink.pcap"), pcap_of(1)).unwrap();
    assert!(uplink_interlock(&d).unwrap_err().contains(LAB_FRAME_MARK));
    let _ = fs::remove_dir_all(d);
}

#[test]
fn received_by_filter_is_information_only_for_the_uplink_interlock() {
    // macOS: every packet the descriptor saw is "received", whatever the filter did with it.
    assert!(interlock_stats(&err_text3(0, 57, 0)).is_ok());
    let e = interlock_stats(&err_text3(1, 58, 0)).unwrap_err();
    assert!(e.contains(LAB_FRAME_MARK), "{e}");
    let e = interlock_stats(&err_text3(0, 57, 1)).unwrap_err();
    assert!(
        e.contains(UNPROVEN_MARK) && !e.contains(LAB_FRAME_MARK),
        "{e}"
    );
    let e = interlock_stats("tcpdump: listening on x\n").unwrap_err();
    assert!(e.contains(UNPROVEN_MARK), "{e}");
    // Through a directory: an empty pcap with 57 pre-filter packets is clean.
    let d = scratch();
    fs::write(d.join("uplink.pcap"), pcap_of(0)).unwrap();
    fs::write(d.join("uplink.err"), err_text3(0, 57, 0)).unwrap();
    assert!(uplink_interlock(&d).is_ok());
    let _ = fs::remove_dir_all(d);
}

#[test]
fn background_traffic_on_the_uplink_is_not_an_isolation_breach() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire); // the fake uplink reports 57 pre-filter packets and none captured
    let code = run_locked(
        &rig.args(&["--only", C01]),
        &st,
        PathBuf::from("/x/l"),
        rig.lock().as_ref(),
    )
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(fs::read_dir(rig.out.join("runs")).unwrap().count(), 1);
    assert!(mv::safety_trips(&rig.out).is_empty());
    assert!(
        !rig.out.join(".work").exists(),
        "no empty work root is left behind"
    );
}

#[test]
fn a_tag_that_already_has_a_run_is_not_run_again() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    let s = rig.suite(&st, "functional");
    s.one(&item("functional", C01), 30).unwrap();
    let before = st.spawned.borrow().len();
    let e = s.one(&item("functional", C01), 30).unwrap_err();
    assert!(
        matches!(e, SuiteError::NotRun(_)) && e.message().contains("--rerun"),
        "{e:?}"
    );
    assert_eq!(
        st.spawned.borrow().len(),
        before,
        "nothing is started for a repeated tag"
    );
}

#[test]
fn the_suite_refuses_to_run_as_root_before_anything_else() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    st.euid.set(0);
    let e = run_locked(
        &rig.args(&["--only", C01]),
        &st,
        PathBuf::from("/x/l"),
        rig.lock().as_ref(),
    )
    .unwrap_err();
    assert!(matches!(e, SuiteError::NotRun(_)) && e.message().contains("must not run as root"));
    assert!(!st.any_spawned() && !rig.out.exists());
    // --list is refused too: it is the same entry.
    assert!(
        run_locked(
            &rig.args(&["--list"]),
            &st,
            PathBuf::from("/x/l"),
            rig.lock().as_ref()
        )
        .is_err()
    );
    // As a normal user the uid is recorded in the manifest and in the run.
    st.euid.set(501);
    run_locked(
        &rig.args(&["--only", C01]),
        &st,
        PathBuf::from("/x/l"),
        rig.lock().as_ref(),
    )
    .unwrap();
    let man: Value = read_json(rig.out.join("manifest.json")).unwrap();
    assert_eq!(man["euid"], 501);
    let d = mv::run_dirs(&rig.out, "runs", C01).pop().unwrap();
    assert_eq!(read_json(d.join("meta.json")).unwrap()["euid"], 501);
    assert_eq!(
        read_json(d.join("run.json")).unwrap()["invocation_nonce"],
        read_json(d.join("meta.json")).unwrap()["invocation_nonce"]
    );
}

#[test]
fn an_error_while_the_scanner_runs_stops_and_reaps_it_before_the_witnesses() {
    // Path 1: the supervision of the scanner itself fails.
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    st.scanner.set(Mode::FailsOnceThenHangs);
    let s = rig.suite(&st, "functional");
    let e = s.one(&item("functional", C01), 30).unwrap_err();
    assert!(
        matches!(e, SuiteError::Abort(_) | SuiteError::NotRun(_)),
        "{e:?}"
    );
    let log = st.log.borrow().clone();
    let sc = st
        .position("scanner:INT")
        .unwrap_or_else(|| panic!("scanner was never stopped: {log:?}"));
    for w in ["witness:INT", "uplink:INT"] {
        assert!(
            sc < st.position(w).unwrap(),
            "{w} stopped before the scanner: {log:?}"
        );
    }
    // Path 2: the operator stops the suite (Ctrl-C) while the scanner runs.
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    st.scanner.set(Mode::Hangs);
    st.stopped.set(true);
    let s = rig.suite(&st, "functional");
    let e = s.one(&item("functional", C01), 30).unwrap_err();
    assert!(matches!(e, SuiteError::Interrupted(_)), "{e:?}");
    let log = st.log.borrow().clone();
    let sc = st
        .position("scanner:INT")
        .unwrap_or_else(|| panic!("{log:?}"));
    assert!(sc < st.position("witness:INT").unwrap(), "{log:?}");
    assert_eq!(
        st.position("scanner:KILL"),
        None,
        "it exited on INT: no SIGKILL needed"
    );
    // The evidence of the interrupted run is kept, hash-checked.
    assert_eq!(
        fs::read_dir(rig.out.join("runs_aborted")).unwrap().count(),
        1
    );
}

#[test]
fn a_scanner_that_ignores_int_is_killed_before_the_witnesses_stop() {
    struct Stubborn(Rc<RefCell<Vec<String>>>);
    impl Proc for Stubborn {
        fn try_wait(&mut self) -> Result<Option<i32>, String> {
            Ok(None)
        }
        fn signal(&mut self, s: &str) {
            self.0.borrow_mut().push(format!("scanner:{s}"));
        }
        fn kill(&mut self) {
            self.0.borrow_mut().push("scanner:KILL".into());
        }
    }
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    let s = rig.suite(&st, "functional");
    let mut t = Tools {
        scanner: Some(Box::new(Stubborn(st.log.clone()))),
        witness: Some(Box::new(FakeProc {
            name: "witness",
            log: st.log.clone(),
            mode: Mode::Hangs,
            done: false,
            failed: false,
            polls: 0,
            pgid: 1,
        })),
        ..Tools::default()
    };
    s.stop_tools(&mut t);
    let log = st.log.borrow().clone();
    assert_eq!(
        log[..3],
        ["scanner:INT", "scanner:KILL", "witness:INT"],
        "{log:?}"
    );
}

#[test]
fn the_uplink_capture_is_not_promiscuous_and_the_firewall_state_is_recorded() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    let s = rig.suite(&st, "functional");
    let dest = s.one(&item("functional", C01), 30).unwrap();
    let up = st
        .spawned
        .borrow()
        .iter()
        .find(|a| a[0] == "/usr/sbin/tcpdump")
        .unwrap()
        .clone();
    assert_eq!(up[..3], ["/usr/sbin/tcpdump", "-p", "-i"], "{up:?}");
    assert!(dest.join("alf.txt").is_file());
    // An enabled Application Firewall refuses the run before anything starts.
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    st.alf_enabled.set(true);
    let s = rig.suite(&st, "functional");
    let e = s.one(&item("functional", C01), 30).unwrap_err();
    assert!(
        e.message().contains("Application Firewall"),
        "{}",
        e.message()
    );
    assert!(!st.any_spawned());
    assert!(firewall_disabled(0, "Firewall is disabled. (State = 0)\n"));
    for (rc, out) in [
        (0, "Firewall is enabled. (State = 1)"),
        (0, "Firewall is enabled. (State = 2)"),
        (0, ""),
        (0, "something else"),
        (1, "Firewall is disabled. (State = 0)"),
        (0, "Firewall is disabled. (State = 1)"),
    ] {
        assert!(!firewall_disabled(rc, out), "{rc} {out:?}");
    }
    // Fail closed through the gate: each unproven answer refuses the run, with the raw output kept.
    for (rc, out) in [
        (0, ""),
        (0, "garbage"),
        (2, "Firewall is disabled. (State = 0)"),
        (0, "Firewall is enabled. (State = 1)"),
    ] {
        let rig = Rig::new();
        let st = Fake::new(&rig.wire);
        *st.alf_raw.borrow_mut() = Some((rc, out.to_owned()));
        let s = rig.suite(&st, "functional");
        let e = s.one(&item("functional", C01), 30).unwrap_err();
        assert!(
            matches!(e, SuiteError::NotRun(_)) && e.message().contains("not proven disabled"),
            "{rc} {out:?}: {e:?}"
        );
        assert!(!st.any_spawned());
    }
}

#[test]
fn a_rebuilt_scanner_binary_cannot_extend_an_existing_directory() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    run_locked(
        &rig.args(&["--only", C01]),
        &st,
        PathBuf::from("/x/l"),
        rig.lock().as_ref(),
    )
    .unwrap();
    fs::write(&rig.wire, b"a different scanner").unwrap();
    let e = run_locked(
        &rig.args(&["--only", "c01_one_addr_port_synack.run2"]),
        &st,
        PathBuf::from("/x/l"),
        rig.lock().as_ref(),
    )
    .unwrap_err();
    assert!(
        matches!(e, SuiteError::NotRun(_)) && e.message().contains("differs"),
        "{e:?}"
    );
}

#[test]
fn the_uplink_filter_of_the_verifier_is_the_one_of_the_lab() {
    assert_eq!(
        mv::uplink_filter(SCANNER_MAC, PEER_MAC),
        crate::macos_lab::UPLINK_FILTER
    );
}

#[test]
fn a_lock_owned_by_another_user_is_alive_and_media_flags_are_read() {
    assert!(alive_from(true, ""));
    assert!(alive_from(false, "kill: 1: Operation not permitted"));
    assert!(!alive_from(false, "kill: 4294967290: No such process"));
    assert!(flags_up(
        "feth4202: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether 2:ac:0:0:0:2\n"
    ));
    assert!(!flags_up(
        "feth4202: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500\n"
    ));
    assert!(!flags_up("no flags here\n"));
}

#[test]
fn link_loss_is_recorded_on_the_peer_interface_the_user_takes_down() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    st.scanner.set(Mode::ExitsAfter(6));
    st.flip_after.set(3);
    let s = rig.suite(&st, "failure");
    let dest = s.one(&item("failure", "linkloss"), 30).unwrap();
    let ll = read_json(dest.join("linkloss.json")).unwrap();
    let down = ll["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["link"] == "down")
        .unwrap();
    assert_eq!(down["iface"], PEER_IF);
    assert_eq!(down["scanner_if"], SCANNER_IF);
    assert!(down["scanner_active"].is_boolean());
}

#[test]
fn a_changed_binding_in_an_existing_manifest_is_refused_before_the_scanner_is_called() {
    let mutations: [(&str, Value); 6] = [
        ("iface", json!("en0")),
        ("src_ip", json!("192.168.1.10")),
        ("src_mac", json!("02:ac:00:00:00:09")),
        ("router_mac", json!("aa:bb:cc:dd:ee:ff")),
        ("peer_ip", json!("192.168.1.1")),
        ("rate", json!(100000)),
    ];
    for (key, value) in mutations {
        let rig = Rig::new();
        let st = Fake::new(&rig.wire);
        run_locked(
            &rig.args(&["--only", C01]),
            &st,
            PathBuf::from("/x/l"),
            rig.lock().as_ref(),
        )
        .unwrap();
        let scans = st.scanner_runs();
        let path = rig.out.join("manifest.json");
        let mut m = read_json(&path).unwrap();
        m["binding"][key] = value.clone();
        write_json(&path, &m).unwrap();
        let spawned = st.spawned.borrow().len();
        let e = run_locked(
            &rig.args(&["--only", "c01_one_addr_port_synack.run2"]),
            &st,
            PathBuf::from("/x/l"),
            rig.lock().as_ref(),
        )
        .unwrap_err();
        assert!(
            matches!(e, SuiteError::NotRun(_)) && e.message().contains(&format!("binding.{key}")),
            "{key}: {e:?}"
        );
        assert_eq!(
            st.scanner_runs(),
            scans,
            "{key}: the scanner must not be called"
        );
        assert_eq!(
            st.spawned.borrow().len(),
            spawned,
            "{key}: nothing at all may start"
        );
    }
    // An extra network field (a gateway), and another stand interface, are refused too.
    for edit in [
        |m: &mut Value| m["binding"]["gateway"] = json!("192.168.1.1"),
        |m: &mut Value| m["stand"]["peer_if"] = json!("en0"),
        |m: &mut Value| m["binding"] = Value::Null,
    ] {
        let rig = Rig::new();
        let st = Fake::new(&rig.wire);
        run_locked(
            &rig.args(&["--only", C01]),
            &st,
            PathBuf::from("/x/l"),
            rig.lock().as_ref(),
        )
        .unwrap();
        let path = rig.out.join("manifest.json");
        let mut m = read_json(&path).unwrap();
        edit(&mut m);
        write_json(&path, &m).unwrap();
        let scans = st.scanner_runs();
        assert!(
            run_locked(
                &rig.args(&["--only", "c01_one_addr_port_synack.run2"]),
                &st,
                PathBuf::from("/x/l"),
                rig.lock().as_ref(),
            )
            .is_err()
        );
        assert_eq!(st.scanner_runs(), scans);
    }
    // The scanner argv comes from the stand's constants.
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    run_locked(
        &rig.args(&["--only", C01]),
        &st,
        PathBuf::from("/x/l"),
        rig.lock().as_ref(),
    )
    .unwrap();
    let spawned = st.spawned.borrow();
    let argv = spawned.iter().find(|a| a[0] == rig.wire).unwrap();
    assert_eq!(after(argv, "--iface"), SCANNER_IF);
    assert_eq!(after(argv, "--src-ip"), SOURCE_IP);
    assert_eq!(after(argv, "--src-mac"), SCANNER_MAC);
    assert_eq!(after(argv, "--router-mac"), PEER_MAC);
}

#[test]
fn a_forced_stop_kills_the_whole_process_group_and_nothing_else() {
    let rig = Rig::new();
    let pidfile = rig.root.join("child.pid");
    let st = RealStand;
    // sh (the leader, like the witness) starts a child (like its tcpdump) and waits for it.
    let argv = vec![
        "/bin/sh".to_owned(),
        "-c".into(),
        "/bin/sleep 30 & echo $! > \"$1\"; wait".into(),
        "x".into(),
        p2s(&pidfile),
    ];
    // An unrelated process in its own group: it must survive.
    let mut bystander = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let mut p = st
        .spawn(&argv, &rig.root.join("p.out"), &rig.root.join("p.err"))
        .unwrap();
    let t0 = Instant::now();
    while fs::read_to_string(&pidfile).map_or(true, |t| t.trim().is_empty())
        && t0.elapsed() < Duration::from_secs(10)
    {
        thread::sleep(Duration::from_millis(10));
    }
    let child = fs::read_to_string(&pidfile).unwrap().trim().to_owned();
    let alive = |pid: &str| {
        Command::new("/bin/kill")
            .args(["-0", pid])
            .output()
            .is_ok_and(|o| o.status.success())
    };
    // `ps` tells a zombie (waiting to be reaped by launchd) from a live process.
    let running = |pid: &str| {
        let o = Command::new("/bin/ps")
            .args(["-p", pid, "-o", "stat="])
            .output()
            .unwrap();
        let stat = String::from_utf8_lossy(&o.stdout).trim().to_owned();
        !stat.is_empty() && !stat.starts_with('Z')
    };
    assert!(alive(&child));
    p.kill();
    let t1 = Instant::now();
    while running(&child) && t1.elapsed() < Duration::from_secs(10) {
        thread::sleep(Duration::from_millis(20));
    }
    let survived = running(&child);
    if survived {
        let _ = Command::new("/bin/kill").args(["-KILL", &child]).status();
    }
    let by = bystander.try_wait().unwrap().is_none();
    let _ = bystander.kill();
    let _ = bystander.wait();
    assert!(!survived, "the grandchild survived the forced stop");
    assert!(by, "an unrelated process was touched");
}

const PS: &str = "  PID  PGID COMMAND
    1     1 /sbin/launchd
 5001  5001 /bin/zsh -l
 5100  5100 /usr/bin/ssh -N somewhere
 5200  5200 /usr/sbin/tcpdump -i en5 -n port 80
 5300  5300 /Users/u/rmasscan/target/release/rmasscan-lab macos-suite --list
";

#[test]
fn leftover_lab_processes_are_found_in_a_ps_listing() {
    let wire = "/Users/u/rmasscan/target/release/examples/wire_scan";
    assert!(
        lab_leftovers(PS, 1, wire).is_empty(),
        "unrelated processes are not leftovers"
    );
    for (line, what) in [
        (
            "6001  6001 /Users/u/rmasscan/target/release/examples/wire_scan --iface feth4201 --targets 198.18.0.2",
            "wire_scan by path",
        ),
        (
            "6002  6002 ./wire_scan --iface feth4201",
            "wire_scan by name",
        ),
        (
            "6003  6003 tcpdump -i feth4202 -n -U --immediate-mode -s 0 -w /x/peer.pcap",
            "witness tcpdump",
        ),
        (
            "6004  6004 /usr/sbin/tcpdump -p -i en0 -n -U -s 0 -w u.pcap net 198.18.0.0/30 or ether proto 0x88b5",
            "uplink tcpdump with the lab filter",
        ),
        (
            "6005  6005 /x/rmasscan-lab peer listen --open 80 --silent 8099 --ready /w/l.json",
            "peer listen",
        ),
        (
            "6006  6006 /x/rmasscan-lab capture dump --iface feth4202 --end-dst 02:ac:00:00:00:01",
            "capture dump",
        ),
        (
            "6007  6007 /usr/sbin/tcpdump -i feth4201 -w /spike/a.pcap",
            "a spike tcpdump on the pair",
        ),
    ] {
        let found = lab_leftovers(&format!("{PS}{line}\n"), 1, wire);
        assert_eq!(found.len(), 1, "{what}: {found:?}");
        assert_eq!(
            found[0].pid,
            line.split_whitespace()
                .next()
                .unwrap()
                .parse::<u32>()
                .unwrap()
        );
    }
    // The suite itself is not its own leftover.
    assert!(
        lab_leftovers(
            "7000  7000 /x/rmasscan-lab peer listen --open 80\n",
            7000,
            wire
        )
        .is_empty()
    );
    assert!(lab_leftovers("garbage\n\n  x y z\n", 1, wire).is_empty());
}

#[test]
fn a_run_is_refused_while_an_earlier_scanner_or_lab_tcpdump_is_alive() {
    for line in [
        "6001  6001 /x/wire_scan --iface feth4201 --targets 198.18.0.2",
        "6003  6003 tcpdump -i feth4202 -n -U -w /spike/x.pcap",
        "6005  6005 /x/rmasscan-lab peer listen --open 80",
    ] {
        let rig = Rig::new();
        let st = Fake::new(&rig.wire);
        *st.ps_text.borrow_mut() = format!("{PS}{line}\n");
        let s = rig.suite(&st, "functional");
        let e = s.one(&item("functional", C01), 30).unwrap_err();
        assert!(matches!(e, SuiteError::NotRun(_)), "{line}: {e:?}");
        let pid = line.split_whitespace().next().unwrap();
        assert!(
            e.message().contains(pid) && e.message().contains("kill"),
            "{}",
            e.message()
        );
        assert!(
            !st.any_spawned(),
            "{line}: nothing may start behind the gate"
        );
        assert!(!rig.out.join("runs_aborted").exists());
    }
    // Clean process list: the run goes ahead.
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    *st.ps_text.borrow_mut() = PS.to_owned();
    rig.suite(&st, "functional")
        .one(&item("functional", C01), 30)
        .unwrap();
}

#[test]
fn the_children_process_groups_are_recorded_in_the_lock_file() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    let lock = rig.root.join("suite.lock");
    let _held = take_lock(&lock).unwrap();
    *st.lock_file.borrow_mut() = Some(lock.clone());
    let mut s = rig.suite(&st, "functional");
    s.lock_path = Some(lock.clone());
    s.one(&item("functional", C01), 30).unwrap();
    let during = st.lock_at_scanner.borrow().clone();
    let children = during
        .lines()
        .find_map(|l| l.strip_prefix("children="))
        .unwrap_or_else(|| panic!("{during:?}"));
    let pgids: Vec<u32> = children.split(',').map(|x| x.parse().unwrap()).collect();
    // listener, uplink tcpdump, witness: three process groups were alive when the scanner started.
    assert!(pgids.len() >= 3, "{pgids:?}");
    assert!(
        during.contains(&format!("pid={}", std::process::id())),
        "{during}"
    );
    // When the run is over nothing is left to record.
    let after = fs::read_to_string(&lock).unwrap();
    assert!(
        !after
            .lines()
            .any(|l| l.starts_with("children=") && l.len() > "children=".len()),
        "{after}"
    );
}

#[test]
fn a_stale_lock_with_live_children_is_not_removed() {
    let root = scratch();
    let p = root.join("l.lock");
    fs::write(&p, "pid=4294967290\nstart=1\nchildren=7001,7002\n").unwrap();
    let ps = "7001  7001 /x/wire_scan --iface feth4201\n 9 9 /bin/sh\n";
    assert_eq!(alive_pgids(ps, &[7001, 7002]), vec![7001]);
    assert!(remove_stale_lock_with(&p, ps).unwrap_err().contains("7001"));
    assert!(p.exists());
    remove_stale_lock_with(&p, "9 9 /bin/sh\n").unwrap();
    assert!(!p.exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_leader_that_exits_leaves_no_member_of_its_group_behind() {
    // sh (the leader) starts a child in its group and exits at once, like a witness that dies on its own.
    let rig = Rig::new();
    let pidfile = rig.root.join("child.pid");
    let st = RealStand;
    let argv = vec![
        "/bin/sh".to_owned(),
        "-c".into(),
        "/bin/sleep 30 & echo $! > \"$1\"; exit 0".into(),
        "x".into(),
        p2s(&pidfile),
    ];
    let mut bystander = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let mut p = st
        .spawn(&argv, &rig.root.join("p.out"), &rig.root.join("p.err"))
        .unwrap();
    let t0 = Instant::now();
    let rc = loop {
        if let Some(rc) = p.try_wait().unwrap() {
            break rc;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(20),
            "the leader never reported its exit"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(rc, 0);
    let child = fs::read_to_string(&pidfile).unwrap().trim().to_owned();
    let running = |pid: &str| {
        let o = Command::new("/bin/ps")
            .args(["-p", pid, "-o", "stat="])
            .output()
            .unwrap();
        let stat = String::from_utf8_lossy(&o.stdout).trim().to_owned();
        !stat.is_empty() && !stat.starts_with('Z')
    };
    let t1 = Instant::now();
    while running(&child) && t1.elapsed() < Duration::from_secs(10) {
        thread::sleep(Duration::from_millis(20));
    }
    let survived = running(&child);
    if survived {
        let _ = Command::new("/bin/kill").args(["-KILL", &child]).status();
    }
    let by = bystander.try_wait().unwrap().is_none();
    let _ = bystander.kill();
    let _ = bystander.wait();
    assert!(
        !survived,
        "a member of the reaped leader\x27s group survived"
    );
    assert!(by, "an unrelated process was touched");
}

#[test]
fn the_group_state_is_read_from_ps_without_reaping_the_leader() {
    let ps = "  100   100 Ss\n  101   100 S\n  102   100 Z\n  200   200 Ss\n  100000 100000 Z\n";
    assert_eq!(group_state(ps, 100), (false, vec![101]));
    assert_eq!(group_state(ps, 200), (false, vec![]));
    assert_eq!(
        group_state("  100   100 Z\n  101   100 S\n", 100),
        (true, vec![101])
    );
    assert_eq!(group_state("", 100), (false, vec![]));
    assert!(!is_gone("  100   100 Ss\n", 100) && is_gone("  1 1 S\n", 100));
}

#[test]
fn a_work_directory_left_in_out_blocks_the_next_start() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    fs::create_dir_all(
        rig.out
            .join(".work/c01_one_addr_port_synack.run1.rdeadbeef"),
    )
    .unwrap();
    let e = run_locked(
        &rig.args(&["--only", C01]),
        &st,
        PathBuf::from("/x/l"),
        rig.lock().as_ref(),
    )
    .unwrap_err();
    assert!(
        matches!(e, SuiteError::NotRun(_)) && e.message().contains(".work"),
        "{e:?}"
    );
    assert!(!st.any_spawned());
    assert!(rig.out.join(".work").exists(), "nothing is deleted");
}

#[test]
fn the_verifiers_pinned_binding_is_the_suites_plan() {
    assert_eq!(mv::stand_binding(), plan_binding());
    assert_eq!(
        binding_problem(
            &json!({"binding":plan_binding(),"stand":{"scanner_if":SCANNER_IF,"peer_if":PEER_IF}})
        ),
        None
    );
}

#[test]
fn the_peer_listens_on_8000_to_8007_only_and_the_rst_limit_is_recorded() {
    let rig = Rig::new();
    let st = Fake::new(&rig.wire);
    let dest = rig
        .suite(&st, "functional")
        .one(&item("functional", C01), 30)
        .unwrap();
    let spawned = st.spawned.borrow();
    let listen = spawned
        .iter()
        .find(|a| a.iter().any(|x| x == "listen"))
        .unwrap();
    assert_eq!(
        after(listen, "--open"),
        "8000-8007",
        "no root listeners: 80 and 443 stay closed"
    );
    let meta = read_json(dest.join("meta.json")).unwrap();
    assert_eq!(meta["icmplim"], "250");
    assert!(
        fs::read_to_string(dest.join("icmplim.txt"))
            .unwrap()
            .contains("250")
    );
    assert!(
        !spawned.iter().any(|a| a[0] == "/usr/sbin/sysctl"),
        "read through exec, not spawned"
    );
}
