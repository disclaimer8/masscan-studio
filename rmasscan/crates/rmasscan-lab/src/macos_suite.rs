//! `macos-suite`: live orchestration of the acceptance runs on the sealed macOS `feth` stand.
//!
//! macOS only, and nothing here runs as root. The stand is already up (`macos-lab up`) and BPF is
//! granted or denied by the user (`macos-lab bpf-access`); the suite only checks that and then, for
//! each planned run, starts the peer listeners, an independent `tcpdump` witness on the peer side
//! (`capture dump`), a `tcpdump` on the uplink with the lab filter, sends the start marker, runs the
//! scanner, and writes one self-contained directory that `macos-verify` judges offline.
//!
//! Every frame the lab itself writes (start and end markers, the foreign replies of x01, the
//! RX-loss and stop-load floods) goes out from the peer side through the safe public adapter API and
//! through [`GuardedTx`]: source MAC the peer's, destination MAC the scanner's, and either the lab
//! marker ethertype or an IPv4 frame from 198.18.0.2 to 198.18.0.1. Nothing else is ever written.
//!
//! A lab frame on the uplink stops the suite with exit 13 and fails the directory for good.
use crate::{
    dump::NetstatCounters,
    link,
    macos_lab::{PEER_IF, PEER_IP, PEER_MAC, SCANNER_IF, SCANNER_MAC, SOURCE_IP},
    macos_verify as mv, pcap,
    windows_suite::{
        LAB_FRAME_MARK, Output, SuiteError, UNPROVEN_MARK, epoch, hash, nonce, opt, options_for,
        parse_tcpdump, read_json, required, safe_id, write_json,
    },
};
use rmasscan_engine::{Rx, SendStatus, Tx};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub(crate) const OPTIONS: &[&str] = &[
    "out",
    "suite",
    "plan",
    "commit",
    "repo",
    "wire-scan",
    "fixtures",
    "manifest",
    "run-id",
    "reps",
    "rates",
    "only",
    "rerun",
    "list",
    "run-timeout",
    "remove-stale-lock",
];
/// The scanner and peer MACs of the stand, as bytes (the frames the lab may write).
use link::{GuardedTx, STAND_PEER_MAC as PM, STAND_SCANNER_MAC as SM};
const KEPT_RECOVERY: &str = "Recovery: inspect the directory (tcpdump -nr uplink.pcap), compare it with hashes-before-copy.txt, then move it by hand.";

// ------------------------------------------------------------------ the frames the lab may write

/// A flood frame: peer to scanner on the lab marker ethertype, sequence number at 14, `RMSP` at 18.
pub(crate) fn flood_frame(seq: u32) -> Vec<u8> {
    let mut f = vec![0u8; 60];
    f[0..6].copy_from_slice(&SM);
    f[6..12].copy_from_slice(&PM);
    f[12..14].copy_from_slice(&[0x88, 0xb5]);
    f[14..18].copy_from_slice(&seq.to_be_bytes());
    f[18..22].copy_from_slice(b"RMSP");
    f
}

// ------------------------------------------------------------------ the seam

pub(crate) trait Proc {
    /// `None` while running.
    fn try_wait(&mut self) -> Result<Option<i32>, String>;
    /// The process group this process leads, when it leads one.
    fn pgid(&self) -> Option<u32> {
        None
    }
    fn signal(&mut self, sig: &str);
    fn kill(&mut self);
}
/// A peer-side task running in a thread of this process (injector, flood).
pub(crate) trait Side {
    /// Stop it and return its record.
    fn finish(self: Box<Self>) -> Result<Value, String>;
}
/// See [`Stand::link_state`].
#[derive(Clone, Copy)]
pub(crate) struct LinkState {
    pub peer_up: bool,
    pub scanner_active: bool,
}
/// `socketfilterfw --getglobalstate` must exit 0 and print exactly "Firewall is disabled. (State = 0)"; anything
/// else (enabled, empty, unrecognised, non-zero exit) is not proof and refuses the run.
pub(crate) fn firewall_disabled(rc: i32, text: &str) -> bool {
    rc == 0 && text.trim() == "Firewall is disabled. (State = 0)"
}
/// `UP` in the `flags=...<...>` list of an `ifconfig` listing (the administrative state).
pub(crate) fn flags_up(text: &str) -> bool {
    text.lines()
        .find_map(|l| l.split_once("<").filter(|_| l.contains("flags=")))
        .and_then(|(_, rest)| rest.split_once('>'))
        .is_some_and(|(list, _)| list.split(',').any(|f| f == "UP"))
}
pub(crate) struct InjectSpec {
    pub sport: u16,
    pub silent: u16,
    pub duration_s: f64,
    pub interval_s: f64,
}
pub(crate) struct FloodSpec {
    /// `None`: as fast as the interface takes frames.
    pub pps: Option<u64>,
    /// Stop after this many frames (`None`: until `finish`).
    pub frames: Option<u64>,
    pub delay_ms: u64,
    pub max_secs: u64,
}
/// Everything the suite does to the outside world, so the gate and the run can be tested with a
/// recording stand and nothing can reach an interface by accident.
pub(crate) trait Stand {
    fn exec(&self, argv: &[String], timeout: u64) -> Result<Output, String>;
    fn spawn(&self, argv: &[String], stdout: &Path, stderr: &Path)
    -> Result<Box<dyn Proc>, String>;
    fn counters(&self, iface: &str) -> Result<NetstatCounters, String>;
    /// The MAC the OS reports for `iface` (read from `ifconfig`; the masked placeholder is an error).
    fn iface_mac(&self, iface: &str) -> Result<String, String>;
    /// Three start markers from the peer side.
    fn send_start_markers(&self) -> Result<(), String>;
    fn start_injector(&self, spec: &InjectSpec) -> Result<Box<dyn Side>, String>;
    fn start_flood(&self, spec: &FloodSpec) -> Result<Box<dyn Side>, String>;
    /// Frames needed to overflow the scanner's BPF buffer.
    fn flood_burst_frames(&self) -> Result<u64, String>;
    /// The administrative state of the peer interface (what `macos-lab link --down` changes) and the media
    /// state of the scanner interface.
    fn link_state(&self) -> Result<LinkState, String>;
    /// The effective uid of this process (the suite must never run as root).
    fn euid(&self) -> Result<u32, String>;
    fn provenance(&self, repo: &Path) -> Value {
        crate::provenance::collect(repo)
    }
    fn pause(&self, d: Duration);
    fn stopped(&self) -> bool;
}

// ------------------------------------------------------------------ the real stand

struct RealProc(std::process::Child);
impl Proc for RealProc {
    fn pgid(&self) -> Option<u32> {
        Some(self.0.id())
    }
    /// The leader's exit is read from `ps` (a zombie row) and not by reaping it, so that the rest of its
    /// group can be swept while its pid, which is the group id, is still ours; only then is it reaped.
    fn try_wait(&mut self) -> Result<Option<i32>, String> {
        let id = self.0.id();
        let snap = ps_listing("pid=,pgid=,stat=");
        if is_gone(&snap, id) {
            return self
                .0
                .try_wait()
                .map(|s| s.map(|s| s.code().unwrap_or(-1)))
                .map_err(|e| e.to_string());
        }
        if !group_state(&snap, id).0 {
            return Ok(None);
        }
        sweep_group(id);
        self.0
            .wait()
            .map(|s| Some(s.code().unwrap_or(-1)))
            .map_err(|e| e.to_string())
    }
    fn signal(&mut self, sig: &str) {
        let _ = Command::new("/bin/kill")
            .args(["-s", sig, &self.0.id().to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    fn kill(&mut self) {
        // The child leads its own process group (`process_group(0)`), so its pgid is its pid and the group
        // holds exactly this run's descendants (the witness's tcpdump included). SIGKILL goes to the whole
        // group first, while the leader is still unreaped (so the pgid cannot have been reused), then the
        // leader is reaped. `/bin/kill` by absolute path: this crate stays `forbid(unsafe_code)`. Graceful
        // signals (`signal`) go to the leader only: its own cleanup stops its children in order.
        let _ = Command::new("/bin/kill")
            .args(["-s", "KILL", "--", &format!("-{}", self.0.id())])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct ThreadSide {
    stop: Arc<AtomicBool>,
    join: thread::JoinHandle<Result<Value, String>>,
}
impl Side for ThreadSide {
    fn finish(self: Box<Self>) -> Result<Value, String> {
        self.stop.store(true, Ordering::Relaxed);
        self.join
            .join()
            .map_err(|_| "a peer-side task panicked".to_string())?
    }
}

/// The guarded TX half, the RX half and the count of refused frames of one peer-side adapter.
type PeerSide = (GuardedTx, Box<dyn Rx>, Arc<AtomicU64>);

pub(crate) struct RealStand;
impl RealStand {
    fn peer_tx(&self) -> Result<PeerSide, String> {
        let link::Link { tx, rx } = link::open(PEER_IF)?;
        let refused = Arc::new(AtomicU64::new(0));
        Ok((
            GuardedTx {
                inner: tx,
                refused: refused.clone(),
            },
            rx,
            refused,
        ))
    }
}
impl Stand for RealStand {
    fn exec(&self, argv: &[String], timeout: u64) -> Result<Output, String> {
        crate::windows_suite::command(argv, timeout, false)
    }
    fn spawn(
        &self,
        argv: &[String],
        stdout: &Path,
        stderr: &Path,
    ) -> Result<Box<dyn Proc>, String> {
        let program = argv.first().ok_or("empty command")?;
        let mut cmd = Command::new(program);
        cmd.args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(fs::File::create(stdout).map_err(|e| format!("{}: {e}", stdout.display()))?)
            .stderr(fs::File::create(stderr).map_err(|e| format!("{}: {e}", stderr.display()))?);
        {
            use std::os::unix::process::CommandExt;
            // A terminal Ctrl-C must reach the suite, which then stops its children in order.
            cmd.process_group(0);
        }
        let child = cmd.spawn().map_err(|e| format!("{program}: {e}"))?;
        Ok(Box::new(RealProc(child)))
    }
    fn counters(&self, iface: &str) -> Result<NetstatCounters, String> {
        crate::dump::netstat_counters(iface)
    }
    fn iface_mac(&self, iface: &str) -> Result<String, String> {
        let m = link::iface_mac(iface)?;
        Ok(m.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"))
    }
    fn send_start_markers(&self) -> Result<(), String> {
        let (mut tx, _rx, _) = self.peer_tx()?;
        let f = link::marker_frame(SM, PM, link::START_PAYLOAD);
        for _ in 0..3 {
            link::send_blocking(&mut tx, &f, link::SEND_PATIENCE, &|| false)?;
            thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }
    fn start_injector(&self, spec: &InjectSpec) -> Result<Box<dyn Side>, String> {
        let (mut tx, mut rx, refused) = self.peer_tx()?;
        let frames: Vec<(String, Vec<u8>)> =
            crate::peer::foreign_frames(PEER_MAC, SCANNER_MAC, SOURCE_IP, spec.sport, spec.silent)?
                .into_iter()
                // The "other IP" reply would come from 198.18.0.3, which the guard forbids the lab to write.
                .filter(|(k, _)| k != "other_ip")
                .collect();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let (duration, interval) = (spec.duration_s, spec.interval_s);
        let join = thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            let waited = Instant::now();
            let mut seen = false;
            while !flag.load(Ordering::Relaxed) && waited.elapsed() < Duration::from_secs(120) {
                if let Some(n) = rx
                    .recv(&mut buf, Duration::from_millis(50))
                    .map_err(|e| e.to_string())?
                    && n >= 54
                    && buf[6..12] == SM
                    && pcap::is_syn(&buf[..n])
                {
                    seen = true;
                    break;
                }
            }
            let mut counts: BTreeMap<String, u64> =
                frames.iter().map(|(k, _)| (k.clone(), 0)).collect();
            let mut first = None;
            let start = Instant::now();
            let patience = &|| flag.load(Ordering::Relaxed);
            while seen && start.elapsed() < Duration::from_secs_f64(duration) && !patience() {
                for (k, f) in &frames {
                    link::send_blocking(&mut tx, f, link::SEND_PATIENCE, patience)?;
                    *counts.get_mut(k).ok_or("kind")? += 1;
                    first.get_or_insert_with(epoch);
                }
                thread::sleep(Duration::from_secs_f64(interval));
            }
            Ok(
                json!({"first_syn_seen":seen,"sent_total":counts.values().sum::<u64>(),
                "kinds":counts,"interval_s":interval,"duration_s":duration,"ipid":0xf0e1,
                "first_sent_at":first,"guard_refused":refused.load(Ordering::Relaxed)}),
            )
        });
        Ok(Box::new(ThreadSide { stop, join }))
    }
    fn start_flood(&self, spec: &FloodSpec) -> Result<Box<dyn Side>, String> {
        let (mut tx, _rx, refused) = self.peer_tx()?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let (pps, frames, delay, max) = (
            spec.pps,
            spec.frames,
            Duration::from_millis(spec.delay_ms),
            Duration::from_secs(spec.max_secs),
        );
        let join = thread::spawn(move || {
            let begin = Instant::now();
            while begin.elapsed() < delay && !flag.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(5));
            }
            let (mut sent, mut errors, mut blocked) = (0u64, 0u64, 0u64);
            let first = epoch();
            let start = Instant::now();
            while start.elapsed() < max
                && !flag.load(Ordering::Relaxed)
                && frames.is_none_or(|n| sent < n)
            {
                match tx.send(&flood_frame(sent as u32), Duration::from_millis(50)) {
                    Ok(SendStatus::Sent) => sent += 1,
                    Ok(SendStatus::WouldBlockUnsent) => {
                        blocked += 1;
                        continue;
                    }
                    Ok(SendStatus::Uncertain) | Err(_) => {
                        errors += 1;
                        if errors > 100 {
                            break;
                        }
                    }
                }
                if let Some(p) = pps
                    && sent > 0
                    && sent % 50 == 0
                {
                    let target = Duration::from_secs_f64(sent as f64 / p as f64);
                    while target > start.elapsed() && !flag.load(Ordering::Relaxed) {
                        thread::sleep(
                            target
                                .saturating_sub(start.elapsed())
                                .min(Duration::from_millis(100)),
                        );
                    }
                }
            }
            let last = epoch();
            Ok(
                json!({"sent":sent,"errors":errors,"blocked":blocked,"t_first":first,"t_last":last,
                "pps_target":pps,"frames_target":frames,"ethertype":0x88b5,"payload_marker":"RMSP",
                "pps_avg":sent as f64/(last-first).max(1e-9),"iface":PEER_IF,
                "guard_refused":refused.load(Ordering::Relaxed)}),
            )
        });
        Ok(Box::new(ThreadSide { stop, join }))
    }
    fn flood_burst_frames(&self) -> Result<u64, String> {
        // The scanner asks for min(4 MiB, debug.bpf_maxbufsize); a record of a 60-byte frame is 80
        // bytes; store plus hold buffer, times 1.5 (the same arithmetic as the live adapter test).
        let inv = rmasscan_net::inventory_bpf().map_err(|e| e.to_string())?;
        let max = u64::from(
            inv.bpf_maxbufsize
                .ok_or("debug.bpf_maxbufsize is unreadable")?,
        );
        Ok((max.min(4 << 20) * 2 * 3 / 2).div_ceil(80))
    }
    fn link_state(&self) -> Result<LinkState, String> {
        let read = |i: &str| -> Result<String, String> {
            let out = Command::new("/sbin/ifconfig")
                .arg(i)
                .output()
                .map_err(|e| e.to_string())?;
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        };
        Ok(LinkState {
            peer_up: flags_up(&read(PEER_IF)?),
            scanner_active: crate::macos_lab::parse_ifconfig(&read(SCANNER_IF)?)
                .status
                .as_deref()
                == Some("active"),
        })
    }
    fn euid(&self) -> Result<u32, String> {
        // `id -u` by absolute path: no unsafe in this crate, and the value is the kernel's.
        let out = Command::new("/usr/bin/id")
            .arg("-u")
            .output()
            .map_err(|e| format!("id: {e}"))?;
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .map_err(|_| "id -u printed no uid".to_string())
    }
    fn pause(&self, d: Duration) {
        thread::sleep(d);
    }
    fn stopped(&self) -> bool {
        rmasscan_net::lab_io::stop_requested()
    }
}

// ------------------------------------------------------------------ small helpers

fn wait_exit(p: &mut dyn Proc, st: &dyn Stand, polls: u32) -> Option<i32> {
    for _ in 0..polls {
        if let Ok(Some(rc)) = p.try_wait() {
            return Some(rc);
        }
        st.pause(Duration::from_millis(50));
    }
    p.try_wait().ok().flatten()
}
fn wait_file(path: &Path, st: &dyn Stand, polls: u32, needle: Option<&str>) -> bool {
    for _ in 0..polls {
        if let Ok(t) = fs::read_to_string(path)
            && !t.is_empty()
            && needle.is_none_or(|n| t.contains(n))
        {
            return true;
        }
        st.pause(Duration::from_millis(100));
    }
    false
}
fn p2s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}
fn io<T>(r: std::io::Result<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e}"))
}

/// Lines `hash  name` of the files of `dir` (not itself), written to `hashes-before-copy.txt` in the
/// work directory before the copy; returns the map. Only plain files are evidence.
pub(crate) fn write_hashes(dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    for e in io(fs::read_dir(dir), "read work directory")? {
        let e = io(e, "read work directory")?;
        let name = e.file_name().to_string_lossy().into_owned();
        if name == "hashes-before-copy.txt" {
            continue;
        }
        if !io(e.file_type(), &name)?.is_file() {
            return Err(format!("{name}: only plain files are evidence"));
        }
        map.insert(name, hash(e.path())?);
    }
    let text: String = map.iter().map(|(n, h)| format!("{h}  {n}\n")).collect();
    io(
        fs::write(dir.join("hashes-before-copy.txt"), text),
        "write hashes",
    )?;
    Ok(map)
}
/// Hash, copy, check: the hashes are taken in `work` before anything is copied, and every copied
/// file is hashed again at `dest`. `after_copy` runs between the two (a test uses it to tamper).
pub(crate) fn copy_verified(
    work: &Path,
    dest: &Path,
    after_copy: &dyn Fn(&Path),
) -> Result<(), String> {
    let before = write_hashes(work)?;
    io(fs::create_dir(dest), &format!("create {}", dest.display()))?;
    for name in before
        .keys()
        .chain(std::iter::once(&"hashes-before-copy.txt".to_owned()))
    {
        io(fs::copy(work.join(name), dest.join(name)), name)?;
    }
    after_copy(dest);
    for (name, h) in &before {
        if hash(dest.join(name))? != *h {
            return Err(format!(
                "{name} differs after the copy from the hash taken before it; the work directory {} is kept",
                work.display()
            ));
        }
    }
    let on_disk: usize = io(fs::read_dir(dest), "read copy")?.count();
    if on_disk != before.len() + 1 {
        return Err("the copy holds files that were never hashed".into());
    }
    Ok(())
}

/// The isolation interlock on the uplink capture of one run directory: no stored frame, no counted
/// frame, no kernel drop, and the counters must have been measured at all.
pub(crate) fn uplink_interlock(dir: &Path) -> Result<(), String> {
    let frames = fs::read(dir.join("uplink.pcap"))
        .ok()
        .and_then(|b| pcap::read_pcap_records(&b).ok())
        .map(|(_, f)| f.len());
    match frames {
        Some(0) => {}
        Some(n) => {
            return Err(format!(
                "uplink interlock: {n} {LAB_FRAME_MARK}; no further raw run"
            ));
        }
        None => {
            return Err(format!(
                "uplink interlock: the uplink capture is unreadable, so {UNPROVEN_MARK}; no further raw run"
            ));
        }
    }
    interlock_stats(&fs::read_to_string(dir.join("uplink.err")).unwrap_or_default())
}

/// The tcpdump statistics of the uplink capture, read the macOS way. `packets received by filter` is the
/// count before the kernel filter on macOS (every packet the descriptor saw), so it is information only and
/// never a lab-frame count. A lab frame is a stored frame, or a frame tcpdump captured (it matched the lab
/// filter) without storing it; a kernel drop is a matched frame lost, so the capture is unproven.
pub(crate) fn interlock_stats(err: &str) -> Result<(), String> {
    let st = parse_tcpdump(err);
    match (st["captured"].as_u64(), st["dropped_kernel"].as_u64()) {
        (Some(0), Some(0)) => Ok(()),
        (Some(c), _) if c > 0 => Err(format!(
            "uplink interlock: tcpdump captured {c} packet(s) that matched the lab filter although the file holds none; treated as {LAB_FRAME_MARK}; no further raw run"
        )),
        (Some(_), Some(d)) => Err(format!(
            "uplink interlock: tcpdump dropped {d} packet(s) in the kernel (on macOS only filter matches are counted), so {UNPROVEN_MARK}; no further raw run"
        )),
        _ => Err(format!(
            "uplink interlock: the uplink tcpdump counters (captured, dropped by kernel) are not measured, so {UNPROVEN_MARK}; no further raw run"
        )),
    }
}

/// The binding of the sealed stand: the only thing a scan may be pointed at.
pub(crate) fn plan_binding() -> Value {
    json!({"iface":SCANNER_IF,"src_ip":SOURCE_IP,"src_mac":SCANNER_MAC,"router_mac":PEER_MAC,
        "peer_ip":PEER_IP,"seed":1,"rate":100,"wait":3})
}
/// Why an existing manifest's binding or stand is not the sealed stand's (`None`: it is). Every key must be
/// present and equal, and no other key may be there (a gateway or next hop of another network).
pub(crate) fn binding_problem(man: &Value) -> Option<String> {
    let want = plan_binding();
    let (Some(have), Some(want)) = (man["binding"].as_object(), want.as_object()) else {
        return Some("no binding".into());
    };
    for (k, w) in want {
        if have.get(k) != Some(w) {
            return Some(format!(
                "binding.{k} is {} not {w}",
                have.get(k).map_or("missing".into(), Value::to_string)
            ));
        }
    }
    if let Some(extra) = have.keys().find(|k| !want.contains_key(*k)) {
        return Some(format!("binding.{extra} is not part of the stand plan"));
    }
    for (k, w) in [("scanner_if", SCANNER_IF), ("peer_if", PEER_IF)] {
        if man["stand"][k] != w {
            return Some(format!("stand.{k} is {} not {w}", man["stand"][k]));
        }
    }
    None
}

/// Removes the work root when the suite ends if nothing is left in it (a kept run stays).
struct WorkRoot(PathBuf);
impl Drop for WorkRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

// ------------------------------------------------------------------ the one-suite lock

/// The lock of one suite at a time: a file created with `create_new`, holding the pid and the start
/// time of its owner. It is removed when the suite ends; a stale one (dead owner) is only ever
/// removed by `--remove-stale-lock`, never automatically.
pub(crate) struct Lock(PathBuf);
impl Lock {
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
/// `kill -0` succeeded, or failed only because the process belongs to someone else (EPERM): alive either way.
pub(crate) fn alive_from(success: bool, stderr: &str) -> bool {
    success || stderr.contains("not permitted")
}
fn pid_alive(pid: u32) -> bool {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .output()
        .is_ok_and(|o| alive_from(o.status.success(), &String::from_utf8_lossy(&o.stderr)))
}
pub(crate) fn take_lock(path: &Path) -> Result<Lock, String> {
    if let Some(dir) = path.parent() {
        io(fs::create_dir_all(dir), "lock directory")?;
    }
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut f) => {
            io(
                writeln!(f, "pid={}\nstart={}", std::process::id(), epoch()),
                "write lock",
            )?;
            Ok(Lock(path.to_path_buf()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let text = fs::read_to_string(path).unwrap_or_default();
            let pid = text
                .lines()
                .find_map(|l| l.strip_prefix("pid="))
                .and_then(|v| v.parse::<u32>().ok());
            Err(format!(
                "another macos-suite holds {} ({}); one suite at a time. {}",
                path.display(),
                text.replace('\n', " "),
                match pid {
                    Some(p) if !pid_alive(p) =>
                        "That process is gone: remove the lock with --remove-stale-lock after checking nothing runs.",
                    _ => "Nothing was changed.",
                }
            ))
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}
/// Remove the lock only when its recorded owner is dead. Never done implicitly.
/// [`remove_stale_lock_with`] against the live process list.
pub(crate) fn remove_stale_lock(path: &Path) -> Result<(), String> {
    remove_stale_lock_with(path, &ps_listing("pid,pgid,command"))
}
/// Remove a lock whose owner is dead, unless a process group it recorded (`children=`) still has a member:
/// those are named, with the commands to stop them, and the lock stays.
pub(crate) fn remove_stale_lock_with(path: &Path, ps: &str) -> Result<(), String> {
    let text = io(fs::read_to_string(path), "read lock")?;
    let pid = text
        .lines()
        .find_map(|l| l.strip_prefix("pid="))
        .and_then(|v| v.parse::<u32>().ok())
        .ok_or("the lock records no pid; remove it by hand if you are sure")?;
    if pid_alive(pid) {
        return Err(format!("process {pid} is alive: the lock is not stale"));
    }
    let recorded: Vec<u32> = text
        .lines()
        .find_map(|l| l.strip_prefix("children="))
        .map(|v| v.split(',').filter_map(|x| x.parse().ok()).collect())
        .unwrap_or_default();
    let alive = alive_pgids(ps, &recorded);
    if !alive.is_empty() {
        return Err(format!(
            "the dead suite left process group(s) {alive:?} running (raw senders and captures); stop them first: {}; the lock stays",
            alive
                .iter()
                .map(|g| format!("kill -INT -- -{g}; kill -KILL -- -{g}"))
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    io(fs::remove_file(path), "remove lock")
}
fn lock_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set")?;
    Ok(PathBuf::from(home).join(".rmasscan-lab/macos-suite.lock"))
}

// ------------------------------------------------------------------ leftover processes and groups

/// A process of an earlier suite (or of the spike) that still holds the stand.
#[derive(Debug)]
pub(crate) struct Leftover {
    pub pid: u32,
    pub pgid: u32,
    pub command: String,
}
fn base(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}
/// The processes of a `ps -axo pid,pgid,command` listing that belong to the lab: a `wire_scan`, a `tcpdump`
/// that names a stand interface or the lab filter, `rmasscan-lab peer listen` and `rmasscan-lab capture dump`.
/// `own` (this suite) is never a leftover.
pub(crate) fn lab_leftovers(ps: &str, own: u32, wire_scan: &str) -> Vec<Leftover> {
    let mut out = vec![];
    for line in ps.lines() {
        let mut it = line.split_whitespace();
        let (Some(pid), Some(pgid)) = (
            it.next().and_then(|v| v.parse::<u32>().ok()),
            it.next().and_then(|v| v.parse::<u32>().ok()),
        ) else {
            continue;
        };
        let tokens: Vec<&str> = it.collect();
        let Some(first) = tokens.first() else {
            continue;
        };
        let joined = tokens.join(" ");
        let has = |w: &str| tokens.contains(&w);
        let lab = base(first) == base(wire_scan)
            || base(first) == "wire_scan"
            || (base(first) == "tcpdump"
                && (has(SCANNER_IF)
                    || has(PEER_IF)
                    || joined.contains("198.18.0.0/30")
                    || joined.contains("ether proto 0x88b5")))
            || (base(first) == "rmasscan-lab"
                && ((has("peer") && has("listen")) || (has("capture") && has("dump"))));
        if lab && pid != own {
            out.push(Leftover {
                pid,
                pgid,
                command: joined,
            });
        }
    }
    out
}
/// Which of `pgids` still have a member in a `ps -axo pid,pgid,command` listing.
pub(crate) fn alive_pgids(ps: &str, pgids: &[u32]) -> Vec<u32> {
    let mut v: Vec<u32> = ps
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            it.next()?.parse::<u32>().ok()?;
            it.next()?.parse::<u32>().ok()
        })
        .filter(|g| pgids.contains(g))
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}
fn ps_listing(columns: &str) -> String {
    Command::new("/bin/ps")
        .args(["-axo", columns])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}
/// From `ps -axo pid=,pgid=,stat=`: is the leader a zombie (exited, not yet reaped), and which live
/// processes other than the leader are in its group?
pub(crate) fn group_state(ps: &str, leader: u32) -> (bool, Vec<u32>) {
    let (mut zombie, mut members) = (false, vec![]);
    for l in ps.lines() {
        let mut it = l.split_whitespace();
        let (Some(pid), Some(pgid), Some(stat)) = (
            it.next().and_then(|v| v.parse::<u32>().ok()),
            it.next().and_then(|v| v.parse::<u32>().ok()),
            it.next(),
        ) else {
            continue;
        };
        if pid == leader {
            zombie = stat.starts_with('Z');
        } else if pgid == leader && !stat.starts_with('Z') {
            members.push(pid);
        }
    }
    (zombie, members)
}
/// The leader has no row at all (already reaped, or `ps` gave nothing).
pub(crate) fn is_gone(ps: &str, leader: u32) -> bool {
    !ps.lines().any(|l| {
        l.split_whitespace()
            .next()
            .and_then(|v| v.parse::<u32>().ok())
            == Some(leader)
    })
}
fn group_signal(sig: &str, pgid: u32) {
    let _ = Command::new("/bin/kill")
        .args(["-s", sig, "--", &format!("-{pgid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
/// Stop the members of a group whose leader has exited but is NOT yet reaped: SIGINT, a bounded grace of
/// one second, then SIGKILL to the group, then another bounded wait.
///
/// Why this never hits a reused pgid: the leader is a zombie, so its pid, which is the group id, is still
/// allocated to it; the kernel cannot give that number to another process or group until the leader is
/// reaped, and it is reaped only after this returns. (Sweeping after the reaping could not promise that.)
fn sweep_group(leader: u32) {
    let members = || group_state(&ps_listing("pid=,pgid=,stat="), leader).1;
    if members().is_empty() {
        return;
    }
    group_signal("INT", leader);
    for _ in 0..20 {
        if members().is_empty() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    group_signal("KILL", leader);
    for _ in 0..20 {
        if members().is_empty() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

// ------------------------------------------------------------------ plan, rerun, list

/// The planned items after `--reps` and `--rates` (perf only).
pub(crate) fn selected_plan(
    plan: &str,
    reps: Option<u64>,
    rates: Option<&[u64]>,
) -> Result<Vec<Value>, String> {
    let items = mv::planned(&json!({"plan":plan}));
    if plan != "perf" {
        if reps.is_some() || rates.is_some() {
            return Err("--reps and --rates apply to --plan perf only".into());
        }
        return Ok(items);
    }
    if let Some(r) = rates
        && r.iter().any(|x| !crate::verify::PERF_RATES.contains(x))
    {
        return Err(format!(
            "--rates must be a subset of {:?}",
            crate::verify::PERF_RATES
        ));
    }
    if reps.is_some_and(|r| r == 0 || r > crate::verify::PERF_REPS) {
        return Err(format!("--reps must be 1..={}", crate::verify::PERF_REPS));
    }
    Ok(items
        .into_iter()
        .filter(|i| {
            reps.is_none_or(|r| i["rep"].as_u64().is_some_and(|k| k <= r))
                && rates.is_none_or(|rs| i["rate"].as_u64().is_some_and(|k| rs.contains(&k)))
        })
        .collect())
}
pub(crate) fn list_lines(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .map(|i| {
            format!(
                "{} {}",
                i["tag"].as_str().unwrap_or(""),
                i["kind"].as_str().unwrap_or("")
            )
        })
        .collect()
}
/// `--only`/`--rerun`: the directories to move to `runs_discarded`. A rerun needs explicit tags,
/// and a run that was judged anything but a discardable INVALID/NOT RUN (or has a behaviour failure)
/// can never be repeated.
pub(crate) fn discard_plan(
    out: &Path,
    only: &[String],
    rerun: bool,
    status: &dyn Fn(&Path, &str) -> (String, bool),
) -> Result<Vec<PathBuf>, SuiteError> {
    if !rerun {
        return Ok(vec![]);
    }
    if only.is_empty() {
        return Err(SuiteError::NotRun(
            "--rerun requires explicit --only tags".into(),
        ));
    }
    let mut moves = vec![];
    for tag in only {
        let dirs = mv::run_dirs(out, "runs", tag);
        if dirs.is_empty() {
            continue;
        }
        let (v, b) = status(out, tag);
        if dirs.len() > 1 || !mv::may_discard(&v, b) {
            return Err(SuiteError::RerunRefused(format!(
                "cannot discard {tag}: {v}, behaviour failure={b}, {} directories",
                dirs.len()
            )));
        }
        moves.extend(dirs);
    }
    Ok(moves)
}

// ------------------------------------------------------------------ the suite

struct Suite<'a> {
    st: &'a dyn Stand,
    exe: String,
    out: PathBuf,
    plan: String,
    wire_scan: String,
    wire_sha: String,
    lab_run_id: String,
    lab_manifest: Option<String>,
    /// The lock file of this suite: the process groups of the live children are recorded in it.
    lock_path: Option<PathBuf>,
    children: RefCell<BTreeSet<u32>>,
    timeout: u64,
    man: Value,
}

/// What one run has started and must stop.
#[derive(Default)]
struct Tools {
    listener: Option<Box<dyn Proc>>,
    scanner: Option<Box<dyn Proc>>,
    witness: Option<Box<dyn Proc>>,
    uplink: Option<Box<dyn Proc>>,
    sides: Vec<(String, Box<dyn Side>)>,
    /// A frame may exist: the first marker is about to be written.
    frames_possible: bool,
}

fn json_line(stdout: &str) -> Option<Value> {
    stdout
        .trim_start_matches('\u{feff}')
        .lines()
        .rev()
        .find(|l| l.starts_with('{'))
        .and_then(|l| serde_json::from_str(l).ok())
}

impl Suite<'_> {
    fn status_argv(&self) -> Vec<String> {
        let mut a = vec![
            self.exe.clone(),
            "macos-lab".into(),
            "status".into(),
            "--run-id".into(),
            self.lab_run_id.clone(),
        ];
        if let Some(m) = &self.lab_manifest {
            a.extend(["--manifest".into(), m.clone()]);
        }
        a
    }
    /// `macos-lab status`, stored under `name` in `work`; the JSON is returned with its exit code.
    fn status(&self, work: &Path, name: &str) -> Result<(i32, Value), String> {
        let o = self.st.exec(&self.status_argv(), 60)?;
        io(fs::write(work.join(name), &o.stdout), name)?;
        let v = serde_json::from_str::<Value>(&o.stdout).map_err(|e| {
            format!(
                "macos-lab status printed no JSON ({e}): {}",
                o.stderr.trim()
            )
        })?;
        Ok((o.rc, v))
    }

    /// The per-run gate. Without it the run is NOT RUN and no adapter is ever opened.
    fn gate_status(&self, work: &Path, item: &Value) -> Result<Value, SuiteError> {
        let (rc, v) = self.status(work, "status-pre.json")?;
        let want = mv::required_bpf_access(item);
        if rc != 0 || v["raw_run_allowed"] != true {
            let failing: Vec<String> = v["checks"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter(|c| c["ok"] == false)
                        .map(|c| c["name"].to_string())
                        .collect()
                })
                .unwrap_or_default();
            return Err(SuiteError::NotRun(format!(
                "the stand is not sealed (macos-lab status rc {rc}; failing checks {failing:?}); nothing was started"
            )));
        }
        if v["bpf_access"] != want {
            return Err(SuiteError::NotRun(format!(
                "{} needs bpf_access {want} but the stand reports {}; the user changes it with macos-lab bpf-access; nothing was started",
                item["tag"], v["bpf_access"]
            )));
        }
        Ok(v)
    }

    /// The macOS Application Firewall can prompt for, or silently block, an unsigned listener; its state is
    /// recorded in `alf.txt` and an enabled firewall refuses the run before anything starts.
    fn application_firewall(&self, work: &Path) -> Result<(), SuiteError> {
        let o = self.st.exec(
            &[
                "/usr/libexec/ApplicationFirewall/socketfilterfw".into(),
                "--getglobalstate".into(),
            ],
            20,
        )?;
        io(
            fs::write(
                work.join("alf.txt"),
                format!("rc {}\nstdout:\n{}\nstderr:\n{}", o.rc, o.stdout, o.stderr),
            ),
            "alf.txt",
        )?;
        // Fail closed: only an exit 0 that says the firewall is disabled lets the run start.
        if !firewall_disabled(o.rc, &o.stdout) {
            return Err(SuiteError::NotRun(format!(
                "the macOS Application Firewall is not proven disabled (socketfilterfw rc {}, output {:?}); it can block or prompt for the peer listeners. Turn it off for the session (System Settings, Network, Firewall) and start again; alf.txt has the raw output; nothing was started",
                o.rc,
                o.stdout.trim()
            )));
        }
        Ok(())
    }

    fn start_proc(
        &self,
        argv: &[String],
        work: &Path,
        name: &str,
    ) -> Result<Box<dyn Proc>, String> {
        let p = self.st.spawn(
            argv,
            &work.join(format!("{name}.out.txt")),
            &work.join(format!("{name}.stderr.txt")),
        )?;
        self.note_child(&*p);
        Ok(p)
    }

    /// Record a child's process group in the lock file, so that the gate and the operator can find it after
    /// a SIGKILL of the suite.
    fn note_child(&self, p: &dyn Proc) {
        if let Some(g) = p.pgid() {
            self.children.borrow_mut().insert(g);
            self.sync_lock();
        }
    }
    fn sync_lock(&self) {
        let Some(path) = &self.lock_path else { return };
        let Ok(text) = fs::read_to_string(path) else {
            return;
        };
        let mut keep: Vec<&str> = text
            .lines()
            .filter(|l| !l.starts_with("children="))
            .collect();
        let children = self
            .children
            .borrow()
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let line = format!("children={children}");
        if !children.is_empty() {
            keep.push(&line);
        }
        let _ = fs::write(path, format!("{}\n", keep.join("\n")));
    }

    /// Refuse while an earlier `wire_scan`, lab `tcpdump`, `peer listen` or `capture dump` is alive: a raw
    /// sender without a witness would poison the next run (same seed, same cookies).
    fn leftover_gate(&self) -> Result<(), SuiteError> {
        let o = self.st.exec(
            &["/bin/ps".into(), "-axo".into(), "pid,pgid,command".into()],
            20,
        )?;
        let left = lab_leftovers(&o.stdout, std::process::id(), &self.wire_scan);
        if left.is_empty() {
            return Ok(());
        }
        let list = left
            .iter()
            .map(|l| {
                format!(
                    "pid {} (group {}): {}",
                    l.pid,
                    l.pgid,
                    l.command.chars().take(100).collect::<String>()
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let stop = left
            .iter()
            .map(|l| format!("kill -INT -- -{g}; sleep 2; kill -KILL -- -{g}", g = l.pgid))
            .collect::<Vec<_>>()
            .join("; ");
        Err(SuiteError::NotRun(format!(
            "a lab process of an earlier suite or the spike is still alive: {list}. Stop them (check first that they are not a run you want): {stop}. Nothing was started"
        )))
    }

    fn stop_tools(&self, t: &mut Tools) {
        // The raw sender goes first: nothing may keep writing frames once its witnesses are gone.
        if let Some(sc) = t.scanner.as_mut() {
            sc.signal("INT");
            if wait_exit(sc.as_mut(), self.st, 100).is_none() {
                sc.kill();
            }
        }
        t.scanner = None;
        if let Some(p) = t.listener.as_mut() {
            p.signal("TERM");
        }
        for (_, s) in std::mem::take(&mut t.sides) {
            let _ = s.finish();
        }
        for (p, sig) in [
            (&mut t.witness, "INT"),
            (&mut t.uplink, "INT"),
            (&mut t.listener, "TERM"),
        ] {
            if let Some(proc_) = p.as_mut() {
                proc_.signal(sig);
                if wait_exit(proc_.as_mut(), self.st, 1200).is_none() {
                    proc_.kill();
                }
            }
            *p = None;
        }
    }

    /// The failure path of one run. It stops the run's tools; once a frame may exist it also reads
    /// the uplink evidence (a lab frame there is the isolation breach, exit 13) and keeps the work
    /// directory under `runs_aborted`, hash-checked. A run that never reached a frame leaves nothing.
    fn abort(&self, work: &Path, name: &str, t: &mut Tools, err: SuiteError) -> SuiteError {
        self.stop_tools(t);
        if !t.frames_possible {
            let _ = fs::remove_dir_all(work);
            return err;
        }
        let breach = uplink_interlock(work).err();
        let dest = self.out.join("runs_aborted").join(name);
        let _ = fs::create_dir_all(self.out.join("runs_aborted"));
        let note = match copy_verified(work, &dest, &|_| {}) {
            Ok(()) => {
                let _ = fs::remove_dir_all(work);
                format!("evidence kept in {}", dest.display())
            }
            Err(e) => format!("{e}; {KEPT_RECOVERY}"),
        };
        match breach {
            Some(m) if m.contains(LAB_FRAME_MARK) => SuiteError::Isolation(format!(
                "{m}; the run had aborted earlier with: {}; {note}",
                err.message()
            )),
            Some(m) => SuiteError::Abort(format!("{m}; {}; {note}", err.message())),
            None => match err {
                SuiteError::NotRun(m) => SuiteError::NotRun(format!("{m}; {note}")),
                SuiteError::Interrupted(m) => SuiteError::Interrupted(format!("{m}; {note}")),
                other => SuiteError::Abort(format!("{}; {note}", other.message())),
            },
        }
    }

    fn paths_for(&self, item: &Value, work: &Path) -> BTreeMap<String, String> {
        let cp = |n: &str| p2s(&work.join(n));
        let mut p = BTreeMap::new();
        match item["kind"].as_str().unwrap_or("") {
            "resume" => {
                p.insert("--resume-checkpoint".into(), cp("checkpoint-in.bin"));
            }
            "refuse_completed" | "ckpt_refuse" => {
                p.insert("--resume-checkpoint".into(), cp("checkpoint-used.bin"));
            }
            _ => {
                p.insert("--checkpoint-out".into(), cp("checkpoint.bin"));
            }
        }
        p
    }

    fn one(&self, item: &Value, run_timeout: u64) -> Result<PathBuf, SuiteError> {
        let tag = item["tag"].as_str().ok_or("planned item has no tag")?;
        let kind = item["kind"].as_str().unwrap_or("");
        if !safe_id(tag) {
            return Err("unsafe tag".to_string().into());
        }
        self.leftover_gate()?;
        let existing = mv::run_dirs(&self.out, "runs", tag);
        if !existing.is_empty() {
            return Err(SuiteError::NotRun(format!(
                "{tag} already has a run in {}; run it again only with --rerun --only {tag} (it is set aside under runs_discarded when its verdict allows)",
                self.out.join("runs").display()
            )));
        }
        let run_nonce = nonce();
        let name = format!("{tag}.{run_nonce}");
        let work = self.out.join(".work").join(&name);
        io(fs::create_dir_all(&work), "work directory")?;
        let mut t = Tools::default();
        let result = match self.one_inner(item, kind, &name, &run_nonce, &work, run_timeout, &mut t)
        {
            Ok(dest) => Ok(dest),
            Err(e) => Err(self.abort(&work, &name, &mut t, e)),
        };
        // Every child is stopped and reaped by now (or the run is an abort that said so).
        self.children.borrow_mut().clear();
        self.sync_lock();
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn one_inner(
        &self,
        item: &Value,
        kind: &str,
        name: &str,
        run_nonce: &str,
        work: &Path,
        run_timeout: u64,
        t: &mut Tools,
    ) -> Result<PathBuf, SuiteError> {
        let tag = item["tag"].as_str().unwrap_or("");
        let denied = kind == "perm_denied";
        // 1. gate: the stand, then the binary the manifest vouches for.
        let pre = self.gate_status(work, item)?;
        self.application_firewall(work)?;
        if hash(&self.wire_scan)? != self.wire_sha {
            return Err(SuiteError::NotRun(
                "the scanner binary changed since the manifest was written; nothing was started"
                    .into(),
            ));
        }
        // Resume needs the checkpoint of its pause leg, found before anything starts.
        if kind == "resume" {
            let n = item["n"].as_u64().ok_or("resume n missing")?;
            let dirs = mv::run_dirs(&self.out, "runs", &format!("pause_N{n}"));
            let [dir] = dirs.as_slice() else {
                return Err(SuiteError::NotRun(format!(
                    "resume_N{n} needs exactly one pause_N{n} run first ({} found)",
                    dirs.len()
                )));
            };
            io(
                fs::copy(dir.join("checkpoint.bin"), work.join("checkpoint-in.bin")),
                "checkpoint of the pause leg",
            )?;
        }
        // 2. listeners, restarted for every run.
        let silent = if self.plan == "failure" {
            "8099,8100-8119"
        } else {
            "8099"
        };
        let ready = work.join("listeners.json");
        t.listener = Some(self.start_proc(
            &[
                self.exe.clone(),
                "peer".into(),
                "listen".into(),
                "--open".into(),
                "80,443,8000-8007".into(),
                "--silent".into(),
                silent.into(),
                "--ready".into(),
                p2s(&ready),
            ],
            work,
            "listener",
        )?);
        if !wait_file(&ready, self.st, 300, None) {
            return Err(SuiteError::NotRun(
                "the peer listeners did not become ready; nothing was started".into(),
            ));
        }
        let lj = read_json(&ready)?;
        if lj["ready"] != true || lj["silent_proven"] != true {
            return Err(SuiteError::NotRun(format!(
                "the peer listeners are not proven (ready {}, silent_proven {}); nothing was started",
                lj["ready"], lj["silent_proven"]
            )));
        }
        let uplink_if = pre["uplink"].as_str().unwrap_or("").to_owned();
        let mut cap = json!({"capture_schema":mv::CAPTURE_SCHEMA});
        let mut meta =
            json!({"tag":tag,"kind":kind,"invocation_nonce":run_nonce,"euid":self.st.euid()?});
        let (mut up0, mut c0) = (None, None);
        if denied {
            // BPF is denied, so no witness can run: the interface counters are the only evidence.
            let read = |i: &str| -> Result<Value, String> {
                let c = self.st.counters(i)?;
                Ok(json!({"ipkts":c.ipkts,"opkts":c.opkts}))
            };
            c0 = Some((
                json!({SCANNER_IF:read(SCANNER_IF)?,PEER_IF:read(PEER_IF)?}),
                epoch(),
            ));
            meta["capture_started_utc"] = json!(c0.as_ref().map(|c| c.1));
        } else {
            if uplink_if.is_empty() || uplink_if.starts_with("feth") {
                return Err(SuiteError::NotRun(format!(
                    "the uplink interface {uplink_if:?} is not a real default-route interface; nothing was started"
                )));
            }
            let want_mac = self.st.iface_mac(SCANNER_IF)?;
            if want_mac != SCANNER_MAC || self.st.iface_mac(PEER_IF)? != PEER_MAC {
                return Err(SuiteError::NotRun(
                    "the OS reports other MACs on the stand than the manifest binding; nothing was started".into(),
                ));
            }
            let cu = self.st.counters(&uplink_if)?;
            up0 = Some(cu.ierrs + cu.drop);
            let filter = mv::uplink_filter(SCANNER_MAC, PEER_MAC);
            let mut argv = crate::dump::tcpdump_argv_macos(
                &uplink_if,
                &p2s(&work.join("uplink.pcap")),
                Some(&filter),
            );
            argv[0] = "/usr/sbin/tcpdump".into();
            // Not promiscuous: the uplink is the user's own NIC, and what is looked for (frames the lab
            // itself emitted) needs no promiscuous mode.
            argv.insert(1, "-p".into());
            // From here on a frame may exist on the wire; an abort reads the uplink evidence.
            t.frames_possible = true;
            meta["capture_started_utc"] = json!(epoch());
            t.uplink = Some(self.st.spawn(
                &argv,
                &work.join("uplink.out.txt"),
                &work.join("uplink.err"),
            )?);
            if let Some(u) = t.uplink.as_deref() {
                self.note_child(u);
            }
            cap["uplink_argv"] = json!(argv);
            let witness = work.join("peer-witness.json");
            t.witness = Some(self.start_proc(
                &[
                    self.exe.clone(),
                    "capture".into(),
                    "dump".into(),
                    "--iface".into(),
                    PEER_IF.into(),
                    "--end-dst".into(),
                    SCANNER_MAC.into(),
                    "--pcap".into(),
                    p2s(&work.join("peer.pcap")),
                    "--ready".into(),
                    p2s(&work.join("peer-ready.json")),
                    "--ack".into(),
                    p2s(&work.join("peer-ack.txt")),
                    "--meta".into(),
                    p2s(&witness),
                ],
                work,
                "witness",
            )?);
            if !wait_file(&work.join("uplink.err"), self.st, 200, Some("listening on")) {
                return Err(SuiteError::NotRun(
                    "the uplink tcpdump never started listening; the scanner was not started"
                        .into(),
                ));
            }
            if !wait_file(&work.join("peer-ready.json"), self.st, 300, None) {
                return Err(SuiteError::NotRun(
                    "the peer witness never became ready; the scanner was not started".into(),
                ));
            }
            self.st.send_start_markers()?;
            if !wait_file(&work.join("peer-ack.txt"), self.st, 200, None) {
                return Err(SuiteError::NotRun(
                    "the start marker is not in the peer capture; the scanner was not started"
                        .into(),
                ));
            }
        }
        // 3. peer-side tasks of the kind.
        match kind {
            "foreign" => {
                t.sides.push((
                    "injector".into(),
                    self.st.start_injector(&InjectSpec {
                        sport: 40000,
                        silent: 8099,
                        duration_s: 2.0,
                        interval_s: 0.1,
                    })?,
                ));
                self.st.pause(Duration::from_millis(500));
            }
            "stop" if item["scenario"] == "load" => {
                t.sides.push((
                    "flood".into(),
                    self.st.start_flood(&FloodSpec {
                        pps: Some(10000),
                        frames: None,
                        delay_ms: 0,
                        max_secs: 40,
                    })?,
                ));
                self.st.pause(Duration::from_millis(1500));
            }
            "rxloss" => {
                t.sides.push((
                    "flood".into(),
                    self.st.start_flood(&FloodSpec {
                        pps: None,
                        frames: Some(self.st.flood_burst_frames()?),
                        delay_ms: 500,
                        max_secs: 40,
                    })?,
                ));
            }
            _ => {}
        }
        // 4. forged checkpoints for the refusal kinds (no network: --forge-checkpoint-next-index).
        if matches!(kind, "refuse_completed" | "ckpt_refuse") {
            let mut forge_item = item.clone();
            forge_item["forge"] = json!(true);
            let mut paths = BTreeMap::new();
            paths.insert(
                "--checkpoint-out".to_owned(),
                p2s(&work.join("checkpoint-forged.bin")),
            );
            let forge = mv::expected_args(&forge_item, &self.man, &paths)?;
            write_json(
                work.join("forge-argv.json"),
                &json!({"exe":self.wire_scan,"argv":forge,"invocation_nonce":run_nonce}),
            )?;
            let mut argv = vec![self.wire_scan.clone()];
            argv.extend(forge);
            let o = self.st.exec(&argv, 60)?;
            io(
                fs::write(work.join("forge-stdout.txt"), &o.stdout),
                "forge stdout",
            )?;
            if o.rc != 0 {
                return Err(SuiteError::Abort(format!(
                    "forging the checkpoint failed rc {}",
                    o.rc
                )));
            }
            let forged = io(
                fs::read(work.join("checkpoint-forged.bin")),
                "forged checkpoint",
            )?;
            let used = if kind == "ckpt_refuse" {
                crate::windows_suite::mutate_checkpoint(
                    item["variant"].as_str().unwrap_or(""),
                    &forged,
                )?
            } else {
                forged
            };
            io(
                fs::write(work.join("checkpoint-used.bin"), used),
                "used checkpoint",
            )?;
        }
        // 5. the scanner.
        let argv_tail = mv::expected_args(item, &self.man, &self.paths_for(item, work))?;
        write_json(
            work.join("argv.json"),
            &json!({"exe":self.wire_scan,"argv":argv_tail,"invocation_nonce":run_nonce}),
        )?;
        let mut argv = vec![self.wire_scan.clone()];
        argv.extend(argv_tail);
        meta["exe_sha256"] = json!(self.wire_sha);
        meta["guest_started_utc"] = json!(epoch());
        t.scanner = Some(self.start_proc(&argv, work, "scanner")?);
        if kind == "linkloss" {
            eprintln!(
                "ACTION REQUIRED NOW (linkloss): in a root shell run\n  rmasscan-lab macos-lab link --run-id {} --down ; sleep 3 ; rmasscan-lab macos-lab link --run-id {} --up\n(that takes {PEER_IF} down and up; the suite watches {PEER_IF}). The scan lasts about 10 s; without it this run is NOT RUN (user action not performed).",
                self.lab_run_id, self.lab_run_id
            );
        }
        let deadline = Instant::now() + Duration::from_secs(run_timeout);
        let mut events: Vec<Value> = vec![];
        let mut peer_was = true;
        let rc = loop {
            // An error here leaves the scanner in `t`: `abort` stops it before any witness.
            let scanner = t.scanner.as_mut().ok_or("scanner missing")?;
            if let Some(rc) = scanner.try_wait()? {
                break rc;
            }
            if self.st.stopped() {
                return Err(SuiteError::Interrupted(format!(
                    "stopped while {tag} was running"
                )));
            }
            if Instant::now() > deadline {
                return Err(SuiteError::Abort(format!(
                    "the scanner exceeded {run_timeout} s"
                )));
            }
            if kind == "linkloss"
                && let Ok(s) = self.st.link_state()
                && s.peer_up != peer_was
            {
                // `macos-lab link --down` takes down the peer side; the scanner side's media state is
                // recorded next to it, the down event itself is the peer's.
                events.push(
                    json!({"link":if s.peer_up {"up"} else {"down"},"iface":PEER_IF,
                    "scanner_if":SCANNER_IF,"scanner_active":s.scanner_active,"t":epoch()}),
                );
                peer_was = s.peer_up;
            }
            self.st.pause(Duration::from_millis(100));
        };
        t.scanner = None;
        meta["guest_finished_utc"] = json!(epoch());
        meta["guest_exit"] = json!(rc);
        if kind == "linkloss" {
            // The scan may end before the user brings the link back; wait for the stand to be sealed.
            write_json(work.join("linkloss.json"), &json!({"events":events}))?;
            let mut restored = false;
            for _ in 0..120 {
                let (rc, v) = self.status(work, "status-link-restored.json")?;
                if rc == 0 && v["raw_run_allowed"] == true {
                    restored = true;
                    break;
                }
                self.st.pause(Duration::from_secs(1));
            }
            if !restored {
                return Err(SuiteError::Abort(
                    "the link did not come back (macos-lab link --up)".into(),
                ));
            }
            let mut ev = events.clone();
            if ev.last().is_some_and(|e| e["link"] == "down")
                && self.st.link_state().is_ok_and(|s| s.peer_up)
            {
                ev.push(json!({"link":"up","iface":PEER_IF,"t":epoch()}));
            }
            write_json(work.join("linkloss.json"), &json!({"events":ev}))?;
        }
        let o_out = fs::read_to_string(work.join("scanner.out.txt")).unwrap_or_default();
        io(
            fs::rename(work.join("scanner.out.txt"), work.join("stdout.txt")),
            "stdout",
        )?;
        io(
            fs::rename(work.join("scanner.stderr.txt"), work.join("stderr.txt")),
            "stderr",
        )?;
        io(fs::write(work.join("exit.txt"), format!("{rc}\n")), "exit")?;
        if let Some(mut run) = json_line(&o_out) {
            // The scanner has no nonce argument; the suite binds its own to the summary it received.
            // stdout.txt keeps the scanner's line byte for byte.
            run["invocation_nonce"] = json!(run_nonce);
            write_json(work.join("run.json"), &run)?;
        }
        if matches!(kind, "linkloss" | "rxloss") {
            meta["checkpoint_file_exists"] = json!(work.join("checkpoint.bin").exists());
        }
        // 6. stop the peer-side tasks.
        for (what, side) in std::mem::take(&mut t.sides) {
            let rec = side.finish()?;
            write_json(
                work.join(match what.as_str() {
                    "injector" => "injector.json",
                    _ => "flood.json",
                }),
                &rec,
            )?;
        }
        if let Some(l) = t.listener.as_mut() {
            l.signal("TERM");
            if wait_exit(l.as_mut(), self.st, 100).is_none() {
                l.kill();
            }
        }
        t.listener = None;
        // 7. the witnesses.
        if denied {
            let read = |i: &str| -> Result<Value, String> {
                let c = self.st.counters(i)?;
                Ok(json!({"ipkts":c.ipkts,"opkts":c.opkts}))
            };
            let after = json!({SCANNER_IF:read(SCANNER_IF)?,PEER_IF:read(PEER_IF)?});
            let after_utc = epoch();
            let (before, before_utc) = c0.take().ok_or("counters before the run are missing")?;
            write_json(
                work.join("counters.json"),
                &json!({"before":before,"before_utc":before_utc,"after":after,"after_utc":after_utc}),
            )?;
            meta["capture_stopped_utc"] = json!(after_utc);
            cap["peer"] = Value::Null;
            cap["uplink"] = Value::Null;
            cap["witness"] = json!(mv::NO_WITNESS);
        } else {
            let (mut w, mut u) = (
                t.witness.take().ok_or("witness missing")?,
                t.uplink.take().ok_or("uplink missing")?,
            );
            w.signal("INT");
            let wrc = wait_exit(w.as_mut(), self.st, 2400);
            if wrc.is_none() {
                w.kill();
            }
            u.signal("INT");
            let urc = wait_exit(u.as_mut(), self.st, 400);
            if urc.is_none() {
                u.kill();
            }
            if urc != Some(0) {
                return Err(SuiteError::Abort(format!(
                    "the uplink tcpdump did not exit cleanly (exit {urc:?}); its statistics are not evidence"
                )));
            }
            meta["capture_stopped_utc"] = json!(epoch());
            if wrc != Some(0) {
                return Err(SuiteError::Abort(format!(
                    "the peer witness did not finish cleanly (exit {wrc:?}); see witness.stderr.txt"
                )));
            }
            let wmeta = read_json(work.join("peer-witness.json"))?;
            io(
                fs::rename(work.join("peer.pcap.tcpdump.err"), work.join("peer.err")),
                "peer.err",
            )?;
            let cu = self.st.counters(&uplink_if)?;
            let up_delta = (cu.ierrs + cu.drop).checked_sub(up0.unwrap_or(u64::MAX));
            let strip = |mut v: Value| {
                if let Some(o) = v.as_object_mut() {
                    o.remove("listening");
                }
                v
            };
            let rec = |file: &str| -> Result<Value, String> {
                let b = io(fs::read(work.join(file)), file)?;
                Ok(json!({"sha256":hex(&b),"size":b.len(),
                    "frames":pcap::read_pcap_records(&b).ok().map(|(_, f)| f.len())}))
            };
            let pe = fs::read_to_string(work.join("peer.err")).unwrap_or_default();
            let ue = fs::read_to_string(work.join("uplink.err")).unwrap_or_default();
            cap["peer"] = json!({"iface":PEER_IF,"cmd":wmeta["tcpdump_argv"],
                "filter":"(none: every frame on the peer interface)","exited":wrc==Some(0),
                "listening":parse_tcpdump(&pe)["listening"],"tcpdump":strip(parse_tcpdump(&pe)),
                "pcap":rec("peer.pcap")?,"interface_drop_delta":wmeta["interface_drop_delta"],
                "witness":wmeta});
            cap["uplink"] = json!({"iface":uplink_if,"cmd":cap["uplink_argv"],
                "filter":mv::uplink_filter(SCANNER_MAC, PEER_MAC),"exited":urc.is_some(),"exit_code":urc,
                "listening":parse_tcpdump(&ue)["listening"],"tcpdump":strip(parse_tcpdump(&ue)),
                "pcap":rec("uplink.pcap")?,"interface_drop_delta":up_delta});
            cap.as_object_mut()
                .ok_or("capture record")?
                .remove("uplink_argv");
            cap["quiet"] = json!({"reached":cap["peer"]["witness"]["quiesced_before_stop"]});
        }
        // 8. status after, then the interlock before a single byte is trusted or copied.
        let (post_rc, post) = self.status(work, "status-post.json")?;
        cap["status_post_raw_run_allowed"] = json!(post_rc == 0 && post["raw_run_allowed"] == true);
        write_json(work.join("capture.json"), &cap)?;
        write_json(work.join("meta.json"), &meta)?;
        if kind == "pause" {
            // already in place: --checkpoint-out wrote it into the work directory
        }
        if !denied {
            uplink_interlock(work).map_err(|m| {
                if m.contains(LAB_FRAME_MARK) {
                    SuiteError::Isolation(m)
                } else {
                    SuiteError::Abort(m)
                }
            })?;
        }
        // 9. hashes in the work directory, copy, hashes again.
        let dest = self.out.join("runs").join(name);
        io(fs::create_dir_all(self.out.join("runs")), "runs directory")?;
        copy_verified(work, &dest, &|_| {}).map_err(SuiteError::Abort)?;
        io(fs::remove_dir_all(work), "remove work directory")?;
        Ok(dest)
    }
}
fn hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

// ------------------------------------------------------------------ entry points

pub fn run(args: &[String]) -> Result<i32, String> {
    rmasscan_net::lab_io::install_signal_handlers()
        .map_err(|e| format!("cannot install the stop-signal handlers: {e}"))?;
    match run_with(
        args,
        &RealStand,
        std::env::current_exe().map_err(|e| e.to_string())?,
    ) {
        Ok(code) => Ok(code),
        Err(SuiteError::NotRun(m)) => Err(m),
        Err(e) => {
            let label = match e {
                SuiteError::Abort(_) => "ABORT",
                SuiteError::RerunRefused(_) => "RERUN REFUSED",
                SuiteError::Isolation(_) => "ISOLATION BREACH",
                SuiteError::Interrupted(_) => "INTERRUPTED",
                _ => "SCHEMA TOO OLD",
            };
            eprintln!("{label}: {}", e.message());
            Ok(e.code())
        }
    }
}

pub(crate) fn run_with(args: &[String], st: &dyn Stand, exe: PathBuf) -> Result<i32, SuiteError> {
    run_locked(args, st, exe, &|| lock_path().and_then(|p| take_lock(&p)))
}

/// `lock` is how the one-suite lock is taken (tests give it a temporary path).
pub(crate) fn run_locked(
    args: &[String],
    st: &dyn Stand,
    exe: PathBuf,
    lock: &dyn Fn() -> Result<Lock, String>,
) -> Result<i32, SuiteError> {
    // Nothing runs as root: a root suite would make the BPF permission runs meaningless.
    let uid = st.euid().map_err(SuiteError::NotRun)?;
    if uid == 0 {
        return Err(SuiteError::NotRun(
            "macos-suite must not run as root (effective uid 0); run it as your own user".into(),
        ));
    }
    let o = options_for("macos-suite", args, OPTIONS)?;
    if o.contains_key("help") {
        println!(
            "macos-suite --out DIR --suite ID --plan functional|failure|perf --commit SHA --repo PATH --wire-scan PATH --fixtures DIR [--run-id m1] [--manifest LAB_MANIFEST] [--reps N] [--rates CSV] [--only TAG ...] [--rerun] [--list] [--run-timeout S] [--remove-stale-lock]"
        );
        return Ok(0);
    }
    let plan = opt(&o, "plan", "functional");
    if !matches!(plan.as_str(), "functional" | "failure" | "perf") {
        return Err("unknown suite plan".to_string().into());
    }
    let reps = o
        .get("reps")
        .and_then(|v| v.first())
        .map(|v| {
            v.parse::<u64>()
                .map_err(|_| "--reps must be a number".to_string())
        })
        .transpose()?;
    let rates = o
        .get("rates")
        .and_then(|v| v.first())
        .map(|v| {
            v.split(',')
                .map(|x| {
                    x.parse::<u64>()
                        .map_err(|_| "--rates must be a CSV of numbers".to_string())
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let items = selected_plan(&plan, reps, rates.as_deref())?;
    if o.contains_key("list") {
        for l in list_lines(&items) {
            println!("{l}");
        }
        return Ok(0);
    }
    if o.contains_key("remove-stale-lock") {
        remove_stale_lock(&lock_path()?)?;
        println!("stale lock removed");
        return Ok(0);
    }
    let suite = opt(&o, "suite", "functional");
    if plan == "perf" && !o.contains_key("suite") {
        return Err(SuiteError::NotRun(
            "--plan perf needs an explicit --suite ID (for example perf-r1)".into(),
        ));
    }
    if !safe_id(&suite) {
        return Err("--suite must be a safe identifier".to_string().into());
    }
    let out = PathBuf::from(required(&o, "out")?);
    let commit = required(&o, "commit")?;
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("--commit requires a full SHA".to_string().into());
    }
    let wire_scan = required(&o, "wire-scan")?;
    let fixtures = PathBuf::from(required(&o, "fixtures")?);
    let lab_run_id = opt(&o, "run-id", "m1");
    if !safe_id(&lab_run_id) {
        return Err("--run-id must be a safe identifier".to_string().into());
    }
    let lab_manifest = o.get("manifest").and_then(|v| v.first()).cloned();
    let timeout: u64 = opt(&o, "run-timeout", "240")
        .parse()
        .map_err(|_| "bad --run-timeout".to_string())?;
    let only = o.get("only").cloned().unwrap_or_default();
    for tag in &only {
        if !safe_id(tag) || !items.iter().any(|i| i["tag"] == *tag) {
            return Err(format!("unknown or unsafe tag {tag}").into());
        }
    }
    let wire_sha = hash(&wire_scan).map_err(|e| format!("--wire-scan: {e}"))?;
    let fx = read_json(fixtures.join("manifest.json"))?;
    if fx["all_valid"] != true {
        return Err("oracle fixtures are not all valid".to_string().into());
    }
    if fx["binding"]["src_mac"] != SCANNER_MAC
        || fx["binding"]["router_mac"] != PEER_MAC
        || fx["binding"]["src_ip"] != SOURCE_IP
    {
        return Err(SuiteError::NotRun(
            "the fixtures were taken for another binding than the stand's; take them again with oracle-fixtures --src-mac".into(),
        ));
    }
    io(fs::create_dir_all(&out), "--out")?;
    let old = read_json(out.join("manifest.json")).ok();
    if old
        .as_ref()
        .is_some_and(|m| m["code_commit"] != commit || m["plan"] != plan || m["suite"] != suite)
    {
        return Err("existing manifest identity differs".to_string().into());
    }
    // A manifest from an earlier start is data, not a plan: its network-affecting fields must be the
    // stand's own before any process starts, and the scanner argv is built from the constants below.
    if let Some(why) = old.as_ref().and_then(binding_problem) {
        return Err(SuiteError::NotRun(format!(
            "the existing manifest does not describe the stand ({why}); nothing was started, use a new --out"
        )));
    }
    let trips = mv::safety_trips(&out);
    if !trips.is_empty() {
        return Err(SuiteError::Isolation(format!(
            "lab-isolation finding in {}: {}; this directory is FAIL and cannot be extended or rerun, use a new --out",
            out.display(),
            trips.join(", ")
        )));
    }
    let moves = discard_plan(&out, &only, o.contains_key("rerun"), &|d, t| {
        mv::run_status(d, t)
    })?;
    let repo = PathBuf::from(opt(&o, "repo", "."));
    let orchestrator = st.provenance(&repo);
    if let Some(why) = crate::provenance::problem(&orchestrator) {
        return Err(SuiteError::NotRun(format!(
            "cannot establish the orchestrator build provenance ({why}); run from the work tree of the commit under test or pass --repo"
        )));
    }
    let _lock = lock().map_err(SuiteError::NotRun)?;
    let mut s = Suite {
        st,
        exe: p2s(&exe),
        out: out.clone(),
        plan: plan.clone(),
        wire_scan: wire_scan.clone(),
        wire_sha: wire_sha.clone(),
        lab_run_id,
        lab_manifest,
        lock_path: Some(_lock.path().to_path_buf()),
        children: RefCell::default(),
        timeout,
        man: Value::Null,
    };
    // The stand must be sealed before anything is written into --out.
    if let Ok(rd) = fs::read_dir(out.join(".work")) {
        let left: Vec<String> = rd
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        if !left.is_empty() {
            return Err(SuiteError::NotRun(format!(
                "{} holds unfinished run directories {left:?} (an abort whose evidence copy failed); inspect them, copy or remove them by hand, then start again. Nothing was deleted or started",
                out.join(".work").display()
            )));
        }
    }
    let probe_dir = out.join(".work");
    io(fs::create_dir_all(&probe_dir), "work root")?;
    let _work_root = WorkRoot(probe_dir.clone());
    let (rc, status0) = s.status(&probe_dir, "status-start.json")?;
    let _ = fs::remove_file(probe_dir.join("status-start.json"));
    if rc != 0 || status0["raw_run_allowed"] != true {
        return Err(SuiteError::NotRun(format!(
            "the stand is not sealed (macos-lab status rc {rc}); start it with macos-lab up. Nothing was started"
        )));
    }
    for (iface, want) in [(SCANNER_IF, SCANNER_MAC), (PEER_IF, PEER_MAC)] {
        let got = st.iface_mac(iface)?;
        if got != want {
            return Err(SuiteError::NotRun(format!(
                "ifconfig reports {got} on {iface}, the stand binding is {want}"
            )));
        }
    }
    if old.as_ref().is_some_and(|m| m["exe"]["sha256"] != wire_sha) {
        return Err(SuiteError::NotRun(
            "the scanner binary differs from the one in the existing manifest; use a new --out"
                .into(),
        ));
    }
    let man = match old {
        Some(m) => m,
        None => {
            let silent: Vec<u32> = if plan == "failure" {
                std::iter::once(8099).chain(8100..8120).collect()
            } else {
                vec![8099]
            };
            let mut m = json!({"schema":1,"macos_capture_schema":mv::CAPTURE_SCHEMA,"suite":suite,
                "plan":plan,"code_commit":commit,
                "exe":{"sha256":wire_sha,"size":fs::metadata(&wire_scan).map(|m| m.len()).unwrap_or(0),
                    "path":wire_scan,"build":"cargo build --locked --release -p rmasscan-net --example wire_scan with RMASSCAN_SOURCE_COMMIT=code_commit"},
                "binding":plan_binding(),
                "stand":{"run_id":s.lab_run_id,"scanner_if":SCANNER_IF,"peer_if":PEER_IF,
                    "uplink":status0["uplink"],"gateway":status0["gateway"]},
                "listeners":{"open":[80,443,8000,8001,8002,8003,8004,8005,8006,8007],"silent":silent},
                "euid":uid,"orchestrator":orchestrator,"created_utc":epoch()});
            if plan == "perf" {
                m["perf"] = json!({"rates":rates.clone().unwrap_or_else(|| crate::verify::PERF_RATES.to_vec()),
                    "reps":reps.unwrap_or(crate::verify::PERF_REPS),"order":"rep-major","target":PEER_IP});
            }
            write_json(out.join("manifest.json"), &m)?;
            copy_fixtures(&fixtures, &out.join("fixtures"))?;
            io(fs::write(out.join("README.md"), readme()), "README.md")?;
            m
        }
    };
    let mut man = man;
    man["binding"] = plan_binding();
    s.man = man;
    for p in moves {
        let dst = out.join("runs_discarded");
        io(fs::create_dir_all(&dst), "runs_discarded")?;
        let leaf = p.file_name().ok_or("run directory name")?.to_owned();
        io(fs::rename(&p, dst.join(leaf)), "discard run")?;
    }
    let base_timeout = s.timeout;
    for item in items {
        let tag = item["tag"].as_str().ok_or("planned tag missing")?;
        if !only.is_empty() && !only.iter().any(|t| t == tag) {
            continue;
        }
        if s.plan == "perf" {
            s.timeout = crate::windows_suite::perf_run_timeout(&item, base_timeout);
        }
        if st.stopped() {
            return Err(SuiteError::Interrupted(format!(
                "stop requested before {tag} started; nothing was left running"
            )));
        }
        let timeout = s.timeout;
        let dest = s.one(&item, timeout)?;
        println!("done {tag} -> {}", dest.display());
    }
    println!(
        "all planned runs executed; verify offline with rmasscan-lab macos-verify --dir {}",
        out.display()
    );
    Ok(0)
}

fn copy_fixtures(src: &Path, dst: &Path) -> Result<(), String> {
    io(fs::create_dir_all(dst), "fixtures")?;
    for e in io(fs::read_dir(src), "fixtures")? {
        let e = io(e, "fixtures")?;
        let to = dst.join(e.file_name());
        if io(e.file_type(), "fixtures")?.is_dir() {
            copy_fixtures(&e.path(), &to)?;
        } else {
            io(fs::copy(e.path(), to), "fixture file")?;
        }
    }
    Ok(())
}
fn readme() -> &'static str {
    "# macOS feth evidence (macos_capture_schema 1)\n\nWritten by `rmasscan-lab macos-suite`; judged offline by `rmasscan-lab macos-verify --dir .`.\n\n- `manifest.json`: suite, plan, commit, scanner binary hash, binding, stand, orchestrator build\n- `fixtures/`: the C oracle's SYN captures for this binding\n- `runs/<tag>.<nonce>/`: one directory per run; `runs_discarded/` and `runs_aborted/` keep what was set aside\n\nFiles of a run: `run.json` (scanner summary), `argv.json`, `meta.json`, `capture.json`, `status-pre.json`,\n`status-post.json`, `listeners.json`, `peer.pcap` + `peer.err` (witness on the peer interface),\n`uplink.pcap` + `uplink.err` (lab filter on the uplink; must hold zero frames), `peer-witness.json`, `peer-ready.json`,\n`peer-ack.txt`, `injector.json`, `flood.json`, `linkloss.json`, `counters.json`, `checkpoint*.bin`, `forge-argv.json`,\n`stdout.txt`, `stderr.txt`, `exit.txt`, `hashes-before-copy.txt` (sha256 of every other file, taken before the copy).\n\nA permission run with BPF denied has no capture; its evidence is the scanner's refusal and `counters.json`.\n"
}

#[cfg(test)]
#[path = "macos_suite_tests.rs"]
mod tests;
