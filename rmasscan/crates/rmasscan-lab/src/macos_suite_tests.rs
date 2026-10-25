//! The suite against a recording stand: nothing opens an interface, runs a process or writes a
//! frame. Scratch names come from `windows_suite::nonce`, never from the clock.
use super::*;
use crate::windows_suite::nonce;
use std::cell::{Cell, RefCell};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-macos-suite-{}", nonce()));
    fs::create_dir_all(&d).unwrap();
    d
}

struct FakeProc(i32);
impl Proc for FakeProc {
    fn try_wait(&mut self) -> Result<Option<i32>, String> {
        Ok(Some(self.0))
    }
    fn signal(&mut self, _: &str) {}
    fn kill(&mut self) {}
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
}
fn after<'a>(a: &'a [String], k: &str) -> &'a str {
    let i = a.iter().position(|x| x == k).unwrap();
    &a[i + 1]
}
fn err_text(frames: usize) -> String {
    format!(
        "tcpdump: listening on x, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n{frames} packets captured\n{frames} packets received by filter\n0 packets dropped by kernel\n"
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
        if argv.iter().any(|a| a == "listen") {
            fs::write(
                after(argv, "--ready"),
                json!({"open":[80],"silent":[8099],"silent_proven":true,"ready":true}).to_string(),
            )
            .unwrap();
        } else if argv[0] == "/usr/sbin/tcpdump" {
            fs::write(after(argv, "-w"), pcap_of(self.uplink_frames.get())).unwrap();
            fs::write(stderr, err_text(self.uplink_frames.get())).unwrap();
        } else if argv.iter().any(|a| a == "dump") {
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
            fs::write(
                stdout,
                format!("{}\n", json!({"status":"ok","reason":"Completed","sent":1})),
            )
            .unwrap();
        }
        Ok(Box::new(FakeProc(0)))
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
    fn link_active(&self) -> Result<bool, String> {
        Ok(true)
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
    assert!(injection_allowed(&marker));
    assert!(injection_allowed(&flood_frame(7)));
    // The foreign replies: three kinds are inside the guard, the 198.18.0.3 one is not.
    let frames =
        crate::peer::foreign_frames(PEER_MAC, SCANNER_MAC, SOURCE_IP, 40000, 8099).unwrap();
    for (k, f) in &frames {
        assert_eq!(injection_allowed(f), k != "other_ip", "{k}");
    }
    let mut bad = marker.clone();
    bad[0] ^= 1;
    assert!(!injection_allowed(&bad), "wrong destination MAC");
    let mut bad = marker.clone();
    bad[6] ^= 1;
    assert!(!injection_allowed(&bad), "wrong source MAC");
    let mut bad = marker.clone();
    bad[12..14].copy_from_slice(&[0x08, 0x06]);
    assert!(!injection_allowed(&bad), "ARP");
    let mut ip = frames["unscanned_port"].clone();
    assert!(injection_allowed(&ip));
    ip[30..34].copy_from_slice(&[198, 18, 0, 9]);
    assert!(!injection_allowed(&ip), "another destination");
    assert!(!injection_allowed(&marker[..13]) && !injection_allowed(&[]));
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
    let mut g = GuardedTx {
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
