//! `autodetect-suite linux|macos`: the live runs of the rmasscan autodetect acceptance on the sealed Linux netns
//! stand and on the macOS `feth` stand. Every planned case of the verifier's case table becomes one `runs/<tag>/`
//! directory that `autodetect-verify` judges offline:
//! - `argv.json` and `expect.json` straight from [`CaseSpec::argv`] and [`CaseSpec::expect`] (no case is defined
//!   here), rmasscan's `stdout.txt`, `stderr.txt`, `exit.txt` and `detected.json` (its stderr parsed by the
//!   verifier's own parser); an `--iflist` case keeps only `iflist.json`, reduced in memory, never the listing;
//! - the peer witness of `capture dump`: `peer.pcap`, its record `capture.json`, tcpdump's `peer.err`;
//! - the stand's own record: Linux `isolation.json` (and `isolation-post.json`), taken again for every run; macOS
//!   `status-pre.json`, `status-post.json`, `alf.txt`, `listeners.json`, `uplink.pcap` and `uplink.err`;
//! - `preflight.txt` (and `preflight-argv.json`) for `m05`; `l11_parity` the C oracle's `oracle/`, `oracle.pcap`
//!   and `oracle-capture.json`; `l12_iflist` the oracle's `oracle/iflist.json`;
//! - `hashes-before-copy.txt`, taken in the work directory before the copy and checked on the copy with the
//!   verifier's own rule.
//!
//! The suite never calls `sudo`. Linux: `wire-lab.sh --suite autodetect` runs it as root inside the sealed lab,
//! and every scanner, responder and witness runs through `ip netns exec`. macOS: the user's grant window runs it as
//! the user (`m01`-`m07`); `--root-case` (`m10`, `m11`) is started by the user under `sudo`, and the evidence
//! directory goes back to `$SUDO_USER` at the end. Commands are argument arrays with absolute paths. Every process
//! goes through a seam ([`LinuxHost`]; on macOS `macos_suite::Stand`), so the tests run the whole suite against
//! recording hosts and nothing in them can reach an interface.
//!
//! Personal paths and run-specific namespace names are scrubbed from everything the suite writes or prints (on
//! Linux its stdout is `suite.log` in the evidence directory).
// The Linux suite is reachable from `run` only on Linux (elsewhere `autodetect-suite linux` refuses at once), so
// off Linux its code is dead by design; on Linux, where all of it is live, the lint stays on.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use crate::{
    autodetect_verify::{
        self as av, ARGV_JSON, ArgvRecord, CAPTURE_JSON, CaseKind, CaseSpec, DETECTED_JSON,
        EXPECT_JSON, ExpectRecord, HASHES, IFLIST_JSON, IflistRecord, MANIFEST_JSON,
        ORACLE_CAPTURE_JSON, ORACLE_IFLIST_JSON, ORACLE_PCAP, PEER_PCAP, PREFLIGHT_TXT, Plan,
    },
    capture::{self, IsolationMode, isolation_permits, scrub_str},
    macos_verify::{hashes_match_tree, tree},
    windows_suite::{
        Output, SuiteError, epoch, hash, nonce, opt, options_for, read_json, required, safe_id,
        write_json,
    },
};
#[cfg(target_os = "macos")]
use mac::macos_with;
#[cfg(all(target_os = "macos", test))]
use mac::{CHOWN, macos_witness_argv};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};

/// The host tools the Linux suite runs itself, by absolute path (`/sbin`, `/bin` resolve on merged-`/usr`
/// systems too).
pub(crate) const IP: &str = "/sbin/ip";
pub(crate) const UNSHARE: &str = "/usr/bin/unshare";
pub(crate) const SH: &str = "/bin/sh";
const ID: &str = "/usr/bin/id";
/// Masks `/etc/masscan` for the C oracle in a private mount namespace, as `wire-lab.sh` does (`oracle_in`): `$0`
/// is an empty directory, `$@` the oracle and its arguments. A constant script; no value is ever spliced into it.
const MASK_SCRIPT: &str = "/bin/mount --bind \"$0\" /etc/masscan && exec \"$@\"";
/// The peer end of the Linux stand (`wire-lab.sh` `IF_B`).
const LINUX_PEER_IF: &str = "veth-b";
const POLL: Duration = Duration::from_millis(50);
/// The longest case is the ARP timeout (10 s); a scan of the stand takes a few seconds plus `--wait 3`.
const SCAN_POLLS: u32 = 2400;
const READY_POLLS: u32 = 600;
const ACK_POLLS: u32 = 300;
/// `capture dump` stops within 90 s: quiet <= 20 s, end markers <= 15 s, tcpdump stop <= 30 s.
const WITNESS_POLLS: u32 = 1800;
const RESPONDER_POLLS: u32 = 200;
const EXEC_TIMEOUT: u64 = 60;

const USAGE: &str = "autodetect-suite linux --out DIR --work DIR --ns-a NS --ns-b NS --iface-a IF --iface-b IF --mac-a MAC --mac-b MAC --rmasscan PATH --oracle PATH --conf-masked 0|1 [--only TAG ...]   (run by wire-lab.sh --suite autodetect, as root)
autodetect-suite macos --out DIR --rmasscan PATH --lab PATH_TO_SELF [--run-id m1] [--only TAG ...] [--root-case]   (as the user in the grant window; --root-case under sudo)
exit 0 every selected run executed, 2 NOT RUN, 10 ABORT, 13 ISOLATION BREACH, 130 INTERRUPTED; judge the directory with autodetect-verify";
pub(crate) const LINUX_OPTIONS: &[&str] = &[
    "out",
    "work",
    "ns-a",
    "ns-b",
    "iface-a",
    "iface-b",
    "mac-a",
    "mac-b",
    "rmasscan",
    "oracle",
    "conf-masked",
    "only",
];
pub(crate) const MACOS_OPTIONS: &[&str] =
    &["out", "rmasscan", "lab", "run-id", "only", "root-case"];

// ------------------------------------------------------------------ small helpers

pub(crate) fn p2s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}
fn io<T>(r: std::io::Result<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e}"))
}
fn not_run(m: impl Into<String>) -> SuiteError {
    SuiteError::NotRun(m.into())
}
/// One line on stdout, scrubbed (the Linux suite's stdout is `suite.log` in the evidence directory). A broken pipe
/// is ignored: the children must still be stopped in order.
fn say(line: &str) {
    let mut o = std::io::stdout();
    let _ = writeln!(o, "{}", scrub_str(line));
    let _ = o.flush();
}
fn warn(line: &str) {
    let mut o = std::io::stderr();
    let _ = writeln!(o, "{}", scrub_str(line));
    let _ = o.flush();
}
fn colon(m: [u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
/// A record as pretty JSON with a final newline.
fn write_record<T: Serialize>(path: &Path, v: &T) -> Result<(), String> {
    let mut b = serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?;
    b.push(b'\n');
    io(fs::write(path, b), &p2s(path))
}
fn write_exit(dir: &Path, rc: i32) -> Result<(), String> {
    io(
        fs::write(dir.join("exit.txt"), format!("{rc}\n")),
        "exit.txt",
    )
}
/// `--KEY` naming an existing file by its absolute path.
fn absolute_file(o: &BTreeMap<String, Vec<String>>, k: &str) -> Result<String, SuiteError> {
    let v = required(o, k)?;
    let p = Path::new(&v);
    if !p.is_absolute() || !p.is_file() {
        return Err(not_run(format!(
            "--{k} must name an existing file by its absolute path"
        )));
    }
    Ok(v)
}
/// Up to `polls` checks, `pause` apart; `true` as soon as `done` holds.
fn poll(pause: &dyn Fn(Duration), polls: u32, mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..polls {
        if done() {
            return true;
        }
        pause(POLL);
    }
    done()
}
/// Signal `p` and wait up to `polls` for it; SIGKILL when it is still there. The exit code when it exited.
fn stop(p: &mut dyn Running, sig: &str, pause: &dyn Fn(Duration), polls: u32) -> Option<i32> {
    p.signal(sig);
    let mut rc = None;
    if !poll(pause, polls, || {
        rc = p.try_wait().ok().flatten();
        rc.is_some()
    }) {
        p.kill();
    }
    rc
}
/// Wait for a scanner (rmasscan or the C oracle) to exit: INTERRUPTED on a stop request, ABORT after
/// [`SCAN_POLLS`]. Every case ends by itself within seconds; the bound is the suite's own safety net.
fn wait_scanner(
    tag: &str,
    mut try_wait: impl FnMut() -> Result<Option<i32>, String>,
    stopped: &dyn Fn() -> bool,
    pause: &dyn Fn(Duration),
) -> Result<i32, SuiteError> {
    for _ in 0..SCAN_POLLS {
        if let Some(rc) = try_wait()? {
            return Ok(rc);
        }
        if stopped() {
            return Err(SuiteError::Interrupted(format!(
                "stopped while the scanner of {tag} was running"
            )));
        }
        pause(POLL);
    }
    Err(SuiteError::Abort(format!(
        "the scanner of {tag} ran longer than {} s",
        (POLL * SCAN_POLLS).as_secs()
    )))
}

// ------------------------------------------------------------------ plans and cases (no definition of a case here)

/// The euid each plan needs: the Linux suite and `--root-case` run as root (the user or `wire-lab.sh` started them
/// through `sudo`); the user window never runs as root, or BPF and the masked MAC would mean nothing.
pub(crate) fn euid_rule(plan: Plan, euid: u32) -> Result<(), String> {
    match (plan, euid) {
        (Plan::Macos, 0) => Err("the user window (m01-m07) runs as the user, not as root (effective uid 0): start autodetect-suite macos without sudo, or add --root-case for m10-m11".into()),
        (Plan::Macos, _) | (Plan::MacosRoot | Plan::Linux, 0) => Ok(()),
        (Plan::MacosRoot, u) => Err(format!(
            "--root-case needs effective uid 0 (it is {u}); the user starts it with sudo"
        )),
        (Plan::Linux, u) => Err(format!(
            "autodetect-suite linux runs as root inside wire-lab.sh --suite autodetect (effective uid {u}); it never calls sudo itself"
        )),
        (Plan::Windows, _) => Err("the Windows plan runs through windows-suite --plan autodetect".into()),
    }
}

/// The cases to run: every planned tag of `plan` in the brief's order, or the `--only` subset of them.
pub(crate) fn selected_tags(plan: Plan, only: &[String]) -> Result<Vec<&'static str>, String> {
    let all = av::planned_tags(plan);
    if let Some(t) = only.iter().find(|t| !all.contains(&t.as_str())) {
        return Err(format!(
            "{t} is not a case of this plan ({})",
            all.join(" ")
        ));
    }
    Ok(all
        .into_iter()
        .filter(|t| only.is_empty() || only.iter().any(|o| o == t))
        .collect())
}
fn only_of(o: &BTreeMap<String, Vec<String>>) -> Result<&[String], SuiteError> {
    match o.get("only") {
        Some(v) if v.is_empty() => Err(not_run("--only needs at least one tag")),
        Some(v) => Ok(v),
        None => Ok(&[]),
    }
}
fn specs(plan: Plan, tags: &[&str]) -> Vec<CaseSpec> {
    tags.iter().filter_map(|t| av::case_spec(plan, t)).collect()
}

/// `argv.json` and `expect.json` of a case: the table's, as they are.
pub(crate) fn case_records(spec: &CaseSpec) -> (ArgvRecord, ExpectRecord) {
    (ArgvRecord { argv: spec.argv() }, spec.expect())
}
pub(crate) fn write_case_records(dir: &Path, spec: &CaseSpec) -> Result<(), String> {
    let (argv, expect) = case_records(spec);
    write_record(&dir.join(ARGV_JSON), &argv)?;
    write_record(&dir.join(EXPECT_JSON), &expect)
}

/// Every address, `a-b` range or CIDR block an argv names outside `198.18.0.0/24` (targets, `--exclude`,
/// `--adapter-ip`, `--router-ip`, `--opt=value`, comma lists). Ports, MACs and names are not addresses.
pub(crate) fn addresses_outside_the_lab(argv: &[String]) -> Vec<String> {
    let addr = |s: &str| s.parse::<Ipv4Addr>().ok();
    let inside = |a: Ipv4Addr| a.octets()[..3] == [198, 18, 0];
    let mut bad = Vec::new();
    for arg in argv {
        let value = arg.split_once('=').map_or(arg.as_str(), |(_, v)| v);
        for item in value.split(',') {
            let ok = if let Some((a, n)) = item.split_once('/').filter(|(a, _)| addr(a).is_some()) {
                addr(a).is_some_and(inside) && n.parse::<u8>().is_ok_and(|n| (24..=32).contains(&n))
            } else if let Some((a, b)) = item.split_once('-').filter(|(a, _)| addr(a).is_some()) {
                addr(a).is_some_and(inside) && addr(b).is_some_and(inside)
            } else if let Some(a) = addr(item) {
                inside(a)
            } else {
                continue;
            };
            if !ok {
                bad.push(item.to_owned());
            }
        }
    }
    bad
}

/// `--iflist` reduced on the spot: exit code, line count, sha256 of the whole output and the one line of the stand
/// NIC (`None` for the oracle, whose format is its own). The listing itself is an inventory of the host.
pub(crate) fn reduce_iflist(rc: i32, stdout: &str, stand_iface: Option<&str>) -> IflistRecord {
    let lead = stand_iface.map(|n| format!("{n} index="));
    IflistRecord {
        rc,
        lines: stdout.lines().count() as u64,
        sha256: crate::verify::sha(stdout.as_bytes()),
        stand_line: lead.and_then(|lead| {
            stdout
                .lines()
                .find(|l| l.starts_with(&lead))
                .map(|l| l.trim_end_matches('\r').to_owned())
        }),
    }
}
/// `iflist.json`, `stderr.txt` and `exit.txt` of an `--iflist` run; its stdout stays in memory.
fn write_iflist(run: &Path, o: &Output, stand_iface: &str) -> Result<(), String> {
    write_record(
        &run.join(IFLIST_JSON),
        &reduce_iflist(o.rc, &o.stdout, Some(stand_iface)),
    )?;
    io(fs::write(run.join("stderr.txt"), &o.stderr), "stderr.txt")?;
    write_exit(run, o.rc)
}
/// `detected.json`: rmasscan's stderr parsed by the verifier's parser. A stderr that does not parse gets no record
/// (the verifier then cannot pass the run).
fn write_detected(run: &Path) -> Result<(), String> {
    let b = io(fs::read(run.join("stderr.txt")), "stderr.txt")?;
    match av::parse_stderr(&String::from_utf8_lossy(&b)) {
        Ok(d) => write_record(&run.join(DETECTED_JSON), &d),
        Err(e) => {
            warn(&format!(
                "stderr.txt does not parse ({e}); detected.json is not written"
            ));
            Ok(())
        }
    }
}

/// The `--offline` preflight of a case (R1): the same argv, read only.
pub(crate) fn preflight_argv(spec: &CaseSpec) -> Vec<String> {
    let mut a = spec.argv();
    a.push("--offline".into());
    a
}
/// `preflight.txt`: `rc N`, then the preflight's stderr.
pub(crate) fn preflight_text(rc: i32, stderr: &str) -> String {
    format!("rc {rc}\n{stderr}")
}

// ------------------------------------------------------------------ the evidence directory

/// Hash every file of `work` (nested paths joined with `/`) into `hashes-before-copy.txt` before anything is
/// copied, copy the tree to `dest` (which must not exist), then check the copy with the verifier's own rule.
pub(crate) fn hash_and_copy(work: &Path, dest: &Path) -> Result<(), String> {
    if dest.exists() {
        return Err(format!("{} exists already", dest.display()));
    }
    let t = tree(work);
    if !t.links.is_empty() {
        return Err(format!("{:?}: only plain files are evidence", t.links));
    }
    let files: Vec<&String> = t.files.iter().filter(|f| *f != HASHES).collect();
    let mut text = String::new();
    for f in &files {
        text.push_str(&format!("{}  {f}\n", hash(work.join(f))?));
    }
    io(fs::write(work.join(HASHES), text), HASHES)?;
    for f in files.iter().map(|f| f.as_str()).chain([HASHES]) {
        let to = dest.join(f);
        if let Some(d) = to.parent() {
            io(fs::create_dir_all(d), f)?;
        }
        io(fs::copy(work.join(f), &to), f)?;
    }
    hashes_match_tree(dest, true).map_err(|e| {
        format!(
            "the copy {} does not match the hashes taken before it ({e}); the work directory {} is kept",
            dest.display(),
            work.display()
        )
    })
}

/// Before the first run: no lab-isolation finding anywhere in `out` (a breach makes the directory FAIL for good),
/// no run of a selected case yet, and no manifest of another plan or build.
fn check_out(out: &Path, tags: &[&str], identity: &Value) -> Result<(), SuiteError> {
    io(fs::create_dir_all(out), "--out")?;
    let trips = av::verify_dir(out)["safety_trips"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !trips.is_empty() {
        return Err(SuiteError::Isolation(format!(
            "lab-isolation finding in {}: {trips:?}; this directory is FAIL and cannot be extended, use a new --out",
            out.display()
        )));
    }
    if let Some(t) = tags.iter().find(|t| out.join("runs").join(t).exists()) {
        return Err(not_run(format!(
            "{t} already has a run in this directory; run it again into a new --out"
        )));
    }
    let path = out.join(MANIFEST_JSON);
    if path.exists() {
        let m = read_json(&path).map_err(|e| {
            not_run(format!(
                "manifest.json is unreadable ({e}); use a new --out"
            ))
        })?;
        for k in ["autodetect", "rmasscan", "oracle"] {
            if m[k] != identity[k] {
                return Err(not_run(format!(
                    "the existing manifest.json has {k} {} where this suite has {}; use a new --out",
                    m[k], identity[k]
                )));
            }
        }
    }
    Ok(())
}
/// `manifest.json` (key `autodetect` names the plan), written once, scrubbed.
fn write_manifest(out: &Path, identity: &Value) -> Result<(), String> {
    let path = out.join(MANIFEST_JSON);
    if path.exists() {
        return Ok(());
    }
    let mut v = identity.clone();
    v["created_utc"] = json!(epoch());
    capture::scrub(&mut v);
    write_record(&path, &v)
}
fn binary(path: &str) -> Result<Value, String> {
    Ok(json!({"sha256": hash(path)?, "size": fs::metadata(path).map(|m| m.len()).unwrap_or(0)}))
}

// ------------------------------------------------------------------ Linux: the seam

/// A process the Linux suite started.
pub(crate) trait Running {
    /// `None` while it runs.
    fn try_wait(&mut self) -> Result<Option<i32>, String>;
    /// A graceful stop (`INT`, `TERM`).
    fn signal(&mut self, sig: &str);
    fn kill(&mut self);
}
/// Everything the Linux suite does to the host: commands, processes, the uid, time. The tests record it.
pub(crate) trait LinuxHost {
    /// Run a command to its end (stdout and stderr in memory).
    fn exec(&self, argv: &[String], timeout: u64) -> Result<Output, String>;
    fn spawn(
        &self,
        argv: &[String],
        stdout: &Path,
        stderr: &Path,
    ) -> Result<Box<dyn Running>, String>;
    fn euid(&self) -> Result<u32, String>;
    fn pause(&self, d: Duration);
    fn stopped(&self) -> bool;
}

/// The lab host: children of this process. They stay in the suite's process group, which `wire-lab.sh` stops as a
/// whole if the suite dies.
struct RealLinux;
struct RealChild(std::process::Child);
impl Running for RealChild {
    fn try_wait(&mut self) -> Result<Option<i32>, String> {
        self.0
            .try_wait()
            .map(|s| s.map(|s| s.code().unwrap_or(-1)))
            .map_err(|e| e.to_string())
    }
    fn signal(&mut self, sig: &str) {
        crate::wire_suite::signal_process(sig, self.0.id());
    }
    fn kill(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl LinuxHost for RealLinux {
    fn exec(&self, argv: &[String], timeout: u64) -> Result<Output, String> {
        crate::windows_suite::command(argv, timeout, false)
    }
    fn spawn(
        &self,
        argv: &[String],
        stdout: &Path,
        stderr: &Path,
    ) -> Result<Box<dyn Running>, String> {
        Ok(Box::new(RealChild(crate::wire_suite::spawn(
            argv, stdout, stderr,
        )?)))
    }
    fn euid(&self) -> Result<u32, String> {
        let o = self.exec(&[ID.into(), "-u".into()], 10)?;
        o.stdout
            .trim()
            .parse()
            .map_err(|_| format!("{ID} -u printed no uid"))
    }
    fn pause(&self, d: Duration) {
        std::thread::sleep(d);
    }
    fn stopped(&self) -> bool {
        rmasscan_net::lab_io::stop_requested()
    }
}

// ------------------------------------------------------------------ Linux: one run

/// What one Linux run has started. Dropped with anything still running (an error, a panic), it stops the scanner
/// first, then the witness and the responder, each with a short grace and then SIGKILL.
#[derive(Default)]
struct LinuxTools {
    scanner: Option<Box<dyn Running>>,
    witness: Option<Box<dyn Running>>,
    responder: Option<Box<dyn Running>>,
    /// A frame may exist: the start marker is about to be sent.
    frames_possible: bool,
}
impl Drop for LinuxTools {
    fn drop(&mut self) {
        for (p, sig) in [
            (self.scanner.take(), "INT"),
            (self.witness.take(), "TERM"),
            (self.responder.take(), "TERM"),
        ] {
            if let Some(mut p) = p {
                stop(p.as_mut(), sig, &std::thread::sleep, 40);
            }
        }
    }
}
/// One capture's witness: the pcap it writes and the record it leaves.
struct Witness {
    pcap: PathBuf,
    meta: PathBuf,
}

struct Linux<'a> {
    host: &'a dyn LinuxHost,
    out: PathBuf,
    work: PathBuf,
    ns_a: String,
    ns_b: String,
    mac_a: String,
    mac_b: String,
    rmasscan: String,
    rmasscan_sha: String,
    oracle: String,
    masked: bool,
    lab: String,
}

impl Linux<'_> {
    fn pause(&self) -> impl Fn(Duration) + '_ {
        |d| self.host.pause(d)
    }
    fn ns(&self, ns: &str, tail: impl IntoIterator<Item = String>) -> Vec<String> {
        [IP, "netns", "exec", ns]
            .into_iter()
            .map(str::to_owned)
            .chain(tail)
            .collect()
    }
    fn lab(&self, args: &[&str]) -> Vec<String> {
        std::iter::once(self.lab.clone())
            .chain(args.iter().map(|a| (*a).to_owned()))
            .collect()
    }

    /// `capture isolation --mode autodetect` now, into `path` (scrubbed): the seal of the stand, proven again.
    fn isolation(&self, path: &Path) -> Result<(), String> {
        let links = self.work.join("host-links-before.txt");
        let o = self.host.exec(
            &self.lab(&[
                "capture",
                "isolation",
                "--mode",
                "autodetect",
                "--out",
                &p2s(path),
                "--ns-a",
                &self.ns_a,
                "--ns-b",
                &self.ns_b,
                "--host-links-before",
                &p2s(&links),
            ]),
            EXEC_TIMEOUT,
        )?;
        if o.rc != 0 {
            return Err(format!(
                "capture isolation exited {}: {}",
                o.rc,
                o.stderr.trim()
            ));
        }
        let mut v = read_json(path)?;
        if v["mode"] != "autodetect" || !isolation_permits(&v, IsolationMode::Autodetect) {
            return Err(format!(
                "the record does not permit an autodetect run (default_route {})",
                v["default_route"]
            ));
        }
        capture::scrub(&mut v);
        write_record(path, &v)
    }

    /// The peer's listeners (the stand's open ports; every other port is reset), restarted for every capture so
    /// that half-open connections of an earlier scan never answer into the next one.
    fn responder(&self, base: &Path, t: &mut LinuxTools) -> Result<(), SuiteError> {
        if let Some(mut p) = t.responder.take() {
            stop(p.as_mut(), "TERM", &self.pause(), RESPONDER_POLLS);
        }
        let ready = base.join(format!("responder-{}.ready", nonce()));
        let ports = av::stand(Plan::Linux)
            .open_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let argv = self.ns(
            &self.ns_b,
            self.lab(&[
                "capture",
                "responder",
                "--ports",
                &ports,
                "--ready",
                &p2s(&ready),
            ]),
        );
        t.responder = Some(self.host.spawn(
            &argv,
            &base.join("responder.out.txt"),
            &base.join("responder.err.txt"),
        )?);
        if !poll(&self.pause(), RESPONDER_POLLS, || ready.exists()) {
            return Err(not_run(
                "the peer responder did not become ready; the scanner was not started",
            ));
        }
        Ok(())
    }

    /// The witness of one capture on the peer veth (`capture dump`), proven live by a start marker from the
    /// scanner side.
    fn witness(
        &self,
        base: &Path,
        run: &Path,
        pcap_name: &str,
        t: &mut LinuxTools,
    ) -> Result<Witness, SuiteError> {
        let stem = pcap_name.trim_end_matches(".pcap");
        let pcap = run.join(pcap_name);
        let meta = base.join(format!("{stem}-witness.json"));
        let (ready, ack) = (
            base.join(format!("{stem}.ready")),
            base.join(format!("{stem}.ack")),
        );
        let argv = self.ns(
            &self.ns_b,
            self.lab(&[
                "capture",
                "dump",
                "--iface",
                LINUX_PEER_IF,
                "--pcap",
                &p2s(&pcap),
                "--meta",
                &p2s(&meta),
                "--ready",
                &p2s(&ready),
                "--ack",
                &p2s(&ack),
                "--end-dst",
                &self.mac_a,
            ]),
        );
        t.witness = Some(self.host.spawn(
            &argv,
            &base.join(format!("{stem}-witness.out.txt")),
            &base.join(format!("{stem}-witness.err.txt")),
        )?);
        if !poll(&self.pause(), READY_POLLS, || ready.exists()) {
            return Err(not_run(
                "the peer witness never became ready; the scanner was not started",
            ));
        }
        t.frames_possible = true;
        let marker = self.host.exec(
            &self.ns(
                &self.ns_a,
                self.lab(&[
                    "capture",
                    "marker",
                    "--iface",
                    av::stand(Plan::Linux).iface,
                    "--src",
                    &self.mac_a,
                    "--dst",
                    &self.mac_b,
                ]),
            ),
            EXEC_TIMEOUT,
        )?;
        if marker.rc != 0 {
            return Err(not_run(format!(
                "the start marker was not sent (exit {}); the scanner was not started",
                marker.rc
            )));
        }
        if !poll(&self.pause(), ACK_POLLS, || ack.exists()) {
            return Err(not_run(
                "the start marker is not in the peer capture; the scanner was not started",
            ));
        }
        Ok(Witness { pcap, meta })
    }

    /// Stop the witness (quiet, end markers, tcpdump stop) and keep its record, scrubbed, and tcpdump's statistics.
    fn finish_witness(
        &self,
        w: &Witness,
        t: &mut LinuxTools,
        run: &Path,
        record: &str,
        err: &str,
    ) -> Result<(), SuiteError> {
        let mut p = t.witness.take().ok_or("the witness is not running")?;
        let rc = stop(p.as_mut(), "TERM", &self.pause(), WITNESS_POLLS);
        if rc != Some(0) {
            return Err(SuiteError::Abort(format!(
                "the peer witness did not finish cleanly (exit {rc:?})"
            )));
        }
        let mut meta = read_json(&w.meta)?;
        capture::scrub(&mut meta);
        write_record(&run.join(record), &meta)?;
        io(
            fs::rename(format!("{}.tcpdump.err", p2s(&w.pcap)), run.join(err)),
            err,
        )?;
        Ok(())
    }

    fn wait(&self, t: &mut LinuxTools, tag: &str) -> Result<i32, SuiteError> {
        let rc = wait_scanner(
            tag,
            || {
                t.scanner
                    .as_mut()
                    .ok_or("the scanner is not running")?
                    .try_wait()
            },
            &|| self.host.stopped(),
            &self.pause(),
        )?;
        t.scanner = None;
        Ok(rc)
    }

    /// The C oracle's argv in the scanner namespace, `/etc/masscan` masked when the host has a config.
    fn oracle_argv(&self, base: &Path, args: Vec<String>) -> Result<Vec<String>, String> {
        let mut a = Vec::new();
        if self.masked {
            let empty = base.join("empty-etc-masscan");
            io(fs::create_dir_all(&empty), "empty-etc-masscan")?;
            a.extend([UNSHARE, "-m", SH, "-c", MASK_SCRIPT].map(str::to_owned));
            a.push(p2s(&empty));
        }
        a.push(self.oracle.clone());
        a.extend(args);
        Ok(self.ns(&self.ns_a, a))
    }

    /// `--iflist` of rmasscan and of the C oracle in the scanner namespace, reduced in memory.
    fn iflist(&self, base: &Path, run: &Path) -> Result<(), SuiteError> {
        let o = self.host.exec(
            &self.ns(&self.ns_a, [self.rmasscan.clone(), "--iflist".into()]),
            EXEC_TIMEOUT,
        )?;
        write_iflist(run, &o, av::stand(Plan::Linux).iface)?;
        let o = self.host.exec(
            &self.oracle_argv(base, vec!["--iflist".into()])?,
            EXEC_TIMEOUT,
        )?;
        io(fs::create_dir_all(run.join("oracle")), "oracle directory")?;
        write_record(
            &run.join(ORACLE_IFLIST_JSON),
            &reduce_iflist(o.rc, &o.stdout, None),
        )?;
        Ok(())
    }

    fn one(&self, spec: &CaseSpec) -> Result<PathBuf, SuiteError> {
        let name = format!("{}.{}", spec.tag, nonce());
        let base = self.work.join(&name);
        let run = base.join("run");
        io(fs::create_dir_all(&run), "work directory")?;
        let mut t = LinuxTools::default();
        if let Err(e) = self.one_inner(spec, &base, &run, &mut t) {
            return Err(self.abort(&base, &run, &name, t, e));
        }
        drop(t);
        let dest = self.out.join("runs").join(spec.tag);
        io(fs::create_dir_all(self.out.join("runs")), "runs directory")?;
        hash_and_copy(&run, &dest).map_err(SuiteError::Abort)?;
        io(fs::remove_dir_all(&base), "remove the work directory")?;
        Ok(dest)
    }

    fn one_inner(
        &self,
        spec: &CaseSpec,
        base: &Path,
        run: &Path,
        t: &mut LinuxTools,
    ) -> Result<(), SuiteError> {
        let tag = spec.tag;
        if hash(&self.rmasscan)? != self.rmasscan_sha {
            return Err(not_run(
                "rmasscan changed since the manifest was written; nothing was started",
            ));
        }
        // 1. The seal, proven again before anything starts.
        self.isolation(&run.join("isolation.json")).map_err(|e| {
            not_run(format!(
                "{tag}: the sealed autodetect stand is not proven ({e}); nothing was started"
            ))
        })?;
        write_case_records(run, spec)?;
        // 2. The peer's listeners and the witness of rmasscan's capture.
        self.responder(base, t)?;
        let w = self.witness(base, run, PEER_PCAP, t)?;
        if self.host.stopped() {
            return Err(SuiteError::Interrupted(format!(
                "stop requested before {tag} started its scanner"
            )));
        }
        // 3. rmasscan with the table's argv: a scan, or `--iflist` reduced in memory.
        if spec.kind == CaseKind::Iflist {
            self.iflist(base, run)?;
        } else {
            let argv = self.ns(
                &self.ns_a,
                std::iter::once(self.rmasscan.clone()).chain(spec.argv()),
            );
            t.scanner = Some(self.host.spawn(
                &argv,
                &run.join("stdout.txt"),
                &run.join("stderr.txt"),
            )?);
            let rc = self.wait(t, tag)?;
            write_exit(run, rc)?;
            write_detected(run)?;
        }
        self.finish_witness(&w, t, run, CAPTURE_JSON, "peer.err")?;
        // 4. l11: the C oracle on the same stand with the same argv, under its own witness.
        if spec.kind == CaseKind::Parity {
            self.responder(base, t)?;
            let w = self.witness(base, run, ORACLE_PCAP, t)?;
            let dir = run.join("oracle");
            io(fs::create_dir_all(&dir), "oracle directory")?;
            t.scanner = Some(self.host.spawn(
                &self.oracle_argv(base, spec.argv())?,
                &dir.join("stdout.txt"),
                &dir.join("stderr.txt"),
            )?);
            let rc = self.wait(t, tag)?;
            write_exit(&dir, rc)?;
            self.finish_witness(&w, t, run, ORACLE_CAPTURE_JSON, "oracle.err")?;
        }
        if let Some(mut p) = t.responder.take() {
            stop(p.as_mut(), "TERM", &self.pause(), RESPONDER_POLLS);
        }
        // 5. The seal after the run: a stand that changed stops the suite (the run is kept under runs_aborted).
        self.isolation(&run.join("isolation-post.json"))
            .map_err(|e| {
                SuiteError::Abort(format!(
                    "{tag}: the stand is not sealed after the run ({e}); no further run"
                ))
            })
    }

    /// The failure path of one run: the scanner stops first, then the witness (with its full window, so that its
    /// capture is finished). Once a frame may exist the run directory is kept under `runs_aborted/<tag>.<nonce>`,
    /// hashed like a run; before that nothing is left.
    fn abort(
        &self,
        base: &Path,
        run: &Path,
        name: &str,
        mut t: LinuxTools,
        err: SuiteError,
    ) -> SuiteError {
        if let Some(mut p) = t.scanner.take() {
            stop(p.as_mut(), "INT", &self.pause(), 100);
        }
        if let Some(mut p) = t.witness.take() {
            stop(p.as_mut(), "TERM", &self.pause(), WITNESS_POLLS);
        }
        let frames = t.frames_possible;
        drop(t);
        if !frames {
            let _ = fs::remove_dir_all(base);
            return err;
        }
        let dest = self.out.join("runs_aborted").join(name);
        let note = match io(
            fs::create_dir_all(self.out.join("runs_aborted")),
            "runs_aborted",
        )
        .and_then(|()| hash_and_copy(run, &dest))
        {
            Ok(()) => {
                let _ = fs::remove_dir_all(base);
                format!("evidence kept in runs_aborted/{name}")
            }
            Err(e) => format!("{e}; the work directory {} is kept", base.display()),
        };
        match err {
            SuiteError::NotRun(m) => SuiteError::NotRun(format!("{m}; {note}")),
            SuiteError::Interrupted(m) => SuiteError::Interrupted(format!("{m}; {note}")),
            SuiteError::Isolation(m) => SuiteError::Isolation(format!("{m}; {note}")),
            other => SuiteError::Abort(format!("{}; {note}", other.message())),
        }
    }
}

// ------------------------------------------------------------------ Linux: the suite

/// `autodetect-suite linux`, inside the lab `wire-lab.sh --suite autodetect` sealed. `lab` is this binary.
pub(crate) fn linux_with(
    args: &[String],
    host: &dyn LinuxHost,
    lab: &Path,
) -> Result<i32, SuiteError> {
    let o = options_for("autodetect-suite linux", args, LINUX_OPTIONS)?;
    if o.contains_key("help") {
        say(USAGE);
        return Ok(0);
    }
    euid_rule(Plan::Linux, host.euid()?)?;
    // The stand is wire-lab.sh's fixed autodetect stand, nothing else.
    let st = av::stand(Plan::Linux);
    for (k, want) in [
        ("iface-a", st.iface.to_owned()),
        ("iface-b", LINUX_PEER_IF.to_owned()),
        ("mac-a", colon(st.scanner_mac)),
        ("mac-b", colon(st.peer_mac)),
    ] {
        let v = required(&o, k)?;
        if v != want {
            return Err(not_run(format!(
                "--{k} {v} is not the autodetect stand's {want} (wire-lab.sh --suite autodetect fixes the stand)"
            )));
        }
    }
    let (ns_a, ns_b) = (required(&o, "ns-a")?, required(&o, "ns-b")?);
    if !safe_id(&ns_a) || !safe_id(&ns_b) || ns_a == ns_b {
        return Err(not_run(
            "--ns-a and --ns-b must be two different safe namespace names",
        ));
    }
    let masked = match required(&o, "conf-masked")?.as_str() {
        "0" => false,
        "1" => true,
        v => return Err(not_run(format!("--conf-masked must be 0 or 1, not {v}"))),
    };
    let rmasscan = absolute_file(&o, "rmasscan")?;
    let oracle = absolute_file(&o, "oracle")?;
    let (out, work) = (
        PathBuf::from(required(&o, "out")?),
        PathBuf::from(required(&o, "work")?),
    );
    let tags = selected_tags(Plan::Linux, only_of(&o)?)?;
    let cases = specs(Plan::Linux, &tags);
    for spec in &cases {
        let bad = addresses_outside_the_lab(&spec.argv());
        if !bad.is_empty() {
            return Err(not_run(format!(
                "{} names addresses outside 198.18.0.0/24: {bad:?}",
                spec.tag
            )));
        }
    }
    let iso = read_json(out.join("isolation.json")).map_err(|e| {
        not_run(format!(
            "wire-lab.sh's isolation.json is missing ({e}); the suite runs only inside wire-lab.sh --suite autodetect"
        ))
    })?;
    if iso["mode"] != "autodetect" || !isolation_permits(&iso, IsolationMode::Autodetect) {
        return Err(not_run(format!(
            "isolation.json does not attest the sealed autodetect stand (mode {}, default_route {})",
            iso["mode"], iso["default_route"]
        )));
    }
    let rmasscan_sha = hash(&rmasscan)?;
    let identity = json!({"autodetect": Plan::Linux, "schema": 1, "suite": "autodetect-suite linux",
        "rmasscan": binary(&rmasscan)?, "oracle": binary(&oracle)?, "lab": binary(&p2s(lab))?,
        "stand": {"scanner_if": st.iface, "peer_if": LINUX_PEER_IF, "scanner_mac": colon(st.scanner_mac),
            "peer_mac": colon(st.peer_mac), "scanner_ip": st.scanner_ip.to_string(),
            "peer_ips": st.peer_ips.iter().map(Ipv4Addr::to_string).collect::<Vec<_>>(),
            "open_ports": st.open_ports, "default_route": "via 198.18.0.2 dev veth-a (scanner namespace only)"},
        "conf_masked": masked});
    check_out(&out, &tags, &identity)?;
    write_manifest(&out, &identity)?;
    // wire-lab.sh's env.json names the oracle by its path, which may be under a home directory.
    if let Ok(mut env) = read_json(out.join("env.json")) {
        capture::scrub(&mut env);
        write_json(out.join("env.json"), &env)?;
    }
    io(fs::create_dir_all(&work), "--work")?;
    let suite = Linux {
        host,
        out: out.clone(),
        work,
        ns_a,
        ns_b,
        mac_a: colon(st.scanner_mac),
        mac_b: colon(st.peer_mac),
        rmasscan,
        rmasscan_sha,
        oracle,
        masked,
        lab: p2s(lab),
    };
    for spec in &cases {
        if host.stopped() {
            return Err(SuiteError::Interrupted(format!(
                "stop requested before {} started; nothing was left running",
                spec.tag
            )));
        }
        suite.one(spec)?;
        say(&format!("done {0} -> runs/{0}", spec.tag));
    }
    say(&format!(
        "all selected runs executed; verify offline with rmasscan-lab autodetect-verify --dir {}",
        out.display()
    ));
    Ok(0)
}

// ------------------------------------------------------------------ macOS

#[cfg(target_os = "macos")]
mod mac {
    //! The feth stand through `macos_suite::Stand`, with `macos-suite`'s own gates: status before and after each
    //! run, the Application Firewall, leftover lab processes (rmasscan included), a quiet pair, the peer
    //! listeners, the uplink capture with the lab filter and its interlock (exit 13), and the peer witness.
    use super::*;
    use crate::{
        macos_lab::{
            PEER_IF, PEER_IP, PEER_MAC, SCANNER_IF, SCANNER_MAC, SOURCE_IP, UPLINK_FILTER,
        },
        macos_suite::{
            Stand, Tools, abort_run, application_firewall, gate_status, lab_status, leftover_gate,
            pair_quiet_gate, status_argv, uplink_interlock, uplink_tcpdump_argv, wait_exit,
            wait_file,
        },
        macos_verify::PEER_FILTER,
        windows_suite::LAB_FRAME_MARK,
    };

    pub(crate) const CHOWN: &str = "/usr/sbin/chown";

    /// The peer witness: `capture dump` on feth4202 with the privacy filter (the host's own mDNS announcements on
    /// the peer interface name the host; they are the only frames left out).
    pub(crate) fn macos_witness_argv(lab: &str, run: &Path, base: &Path) -> Vec<String> {
        [
            lab,
            "capture",
            "dump",
            "--iface",
            PEER_IF,
            "--end-dst",
            SCANNER_MAC,
            "--pcap",
            &p2s(&run.join(PEER_PCAP)),
            "--ready",
            &p2s(&base.join("peer-ready.json")),
            "--ack",
            &p2s(&base.join("peer-ack.txt")),
            "--meta",
            &p2s(&base.join("peer-witness.json")),
            "--filter",
            PEER_FILTER,
        ]
        .map(str::to_owned)
        .to_vec()
    }

    struct Mac<'a> {
        st: &'a dyn Stand,
        out: PathBuf,
        rmasscan: String,
        rmasscan_sha: String,
        lab: String,
        status: Vec<String>,
    }

    impl Mac<'_> {
        fn stand_macs(&self) -> Result<(), SuiteError> {
            for (iface, want) in [(SCANNER_IF, SCANNER_MAC), (PEER_IF, PEER_MAC)] {
                let got = self.st.iface_mac(iface)?;
                if got != want {
                    return Err(not_run(format!(
                        "ifconfig reports {got} on {iface}, the stand binding is {want}; nothing was started"
                    )));
                }
            }
            Ok(())
        }

        fn one(&self, spec: &CaseSpec) -> Result<PathBuf, SuiteError> {
            leftover_gate(self.st, &self.rmasscan)?;
            pair_quiet_gate(self.st)?;
            let name = format!("{}.{}", spec.tag, nonce());
            let base = self.out.join(".work").join(&name);
            let run = base.join("run");
            io(fs::create_dir_all(&run), "work directory")?;
            let mut t = Tools::default();
            let sealed_after = match self.one_inner(spec, &base, &run, &mut t) {
                Ok(sealed) => sealed,
                Err(e) => {
                    let e = abort_run(self.st, &self.out, &run, &name, &mut t, e);
                    if !run.exists() {
                        let _ = fs::remove_dir_all(&base);
                    }
                    return Err(e);
                }
            };
            drop(t);
            let dest = self.out.join("runs").join(spec.tag);
            io(fs::create_dir_all(self.out.join("runs")), "runs directory")?;
            hash_and_copy(&run, &dest).map_err(SuiteError::Abort)?;
            io(fs::remove_dir_all(&base), "remove the work directory")?;
            if !sealed_after {
                return Err(SuiteError::Abort(format!(
                    "macos-lab status after {} does not allow raw runs; the run is kept in runs/{} for the verifier and no further run starts",
                    spec.tag, spec.tag
                )));
            }
            Ok(dest)
        }

        /// One run; `Ok(sealed)` with the stand's state after it.
        fn one_inner(
            &self,
            spec: &CaseSpec,
            base: &Path,
            run: &Path,
            t: &mut Tools,
        ) -> Result<bool, SuiteError> {
            let tag = spec.tag;
            // 1. The gates, before anything starts: the sealed stand with BPF granted, the firewall, the binary.
            let pre = gate_status(self.st, &self.status, run, &json!(tag), "granted")?;
            application_firewall(self.st, run)?;
            if hash(&self.rmasscan)? != self.rmasscan_sha {
                return Err(not_run(
                    "rmasscan changed since the manifest was written; nothing was started",
                ));
            }
            self.stand_macs()?;
            // 2. The preflight (R1), read only: the live case runs only when it shows the expected detection.
            if spec.preflight.is_some() {
                let argv = preflight_argv(spec);
                let o = self.st.exec(
                    &std::iter::once(self.rmasscan.clone())
                        .chain(argv.iter().cloned())
                        .collect::<Vec<_>>(),
                    EXEC_TIMEOUT,
                )?;
                let text = preflight_text(o.rc, &o.stderr);
                io(fs::write(run.join(PREFLIGHT_TXT), &text), PREFLIGHT_TXT)?;
                write_record(&run.join("preflight-argv.json"), &ArgvRecord { argv })?;
                if !av::preflight_shows(spec, &text) {
                    return Err(not_run(format!(
                        "{tag}: the --offline preflight does not show the expected detection {:?} (it printed: {}); the live case is NOT RUN",
                        spec.expect().preflight,
                        text.trim().replace('\n', " | ")
                    )));
                }
            }
            write_case_records(run, spec)?;
            // 3. The peer listeners.
            let ready = run.join("listeners.json");
            t.listener = Some(self.st.spawn(
                &[
                    self.lab.clone(),
                    "peer".into(),
                    "listen".into(),
                    "--open".into(),
                    "8000-8007".into(),
                    "--ready".into(),
                    p2s(&ready),
                ],
                &base.join("listener.out.txt"),
                &base.join("listener.err.txt"),
            )?);
            if !wait_file(&ready, self.st, 300, None) {
                return Err(not_run(
                    "the peer listeners did not become ready; nothing was started",
                ));
            }
            let lj = read_json(&ready)?;
            if lj["ready"] != true || lj["silent"] != json!([]) {
                return Err(not_run(format!(
                    "the peer listeners are not proven (ready {}, silent {}); nothing was started",
                    lj["ready"], lj["silent"]
                )));
            }
            // 4. The uplink capture with the lab filter, then the peer witness with the privacy filter.
            let uplink_if = pre["uplink"].as_str().unwrap_or("").to_owned();
            if uplink_if.is_empty() || uplink_if.starts_with("feth") {
                return Err(not_run(format!(
                    "the uplink interface {uplink_if:?} is not a real default-route interface; nothing was started"
                )));
            }
            t.frames_possible = true;
            t.uplink = Some(self.st.spawn(
                &uplink_tcpdump_argv(&uplink_if, &run.join("uplink.pcap")),
                &base.join("uplink.out.txt"),
                &run.join("uplink.err"),
            )?);
            if !wait_file(&run.join("uplink.err"), self.st, 200, Some("listening on")) {
                return Err(not_run(
                    "the uplink tcpdump never started listening; the scanner was not started",
                ));
            }
            t.witness = Some(self.st.spawn(
                &macos_witness_argv(&self.lab, run, base),
                &base.join("witness.out.txt"),
                &base.join("witness.err.txt"),
            )?);
            if !wait_file(&base.join("peer-ready.json"), self.st, 300, None) {
                return Err(not_run(
                    "the peer witness never became ready; the scanner was not started",
                ));
            }
            self.st.send_start_markers()?;
            if !wait_file(&base.join("peer-ack.txt"), self.st, 200, None) {
                return Err(not_run(
                    "the start marker is not in the peer capture; the scanner was not started",
                ));
            }
            if self.st.stopped() {
                return Err(SuiteError::Interrupted(format!(
                    "stop requested before {tag} started its scanner"
                )));
            }
            // 5. rmasscan with the table's argv: a scan, or `--iflist` reduced in memory.
            if spec.kind == CaseKind::Iflist {
                let o = self
                    .st
                    .exec(&[self.rmasscan.clone(), "--iflist".into()], EXEC_TIMEOUT)?;
                write_iflist(run, &o, SCANNER_IF)?;
            } else {
                let argv: Vec<String> = std::iter::once(self.rmasscan.clone())
                    .chain(spec.argv())
                    .collect();
                t.scanner = Some(self.st.spawn(
                    &argv,
                    &run.join("stdout.txt"),
                    &run.join("stderr.txt"),
                )?);
                let rc = wait_scanner(
                    tag,
                    || {
                        t.scanner
                            .as_mut()
                            .ok_or("the scanner is not running")?
                            .try_wait()
                    },
                    &|| self.st.stopped(),
                    &|d| self.st.pause(d),
                )?;
                t.scanner = None;
                write_exit(run, rc)?;
                write_detected(run)?;
            }
            // 6. The witnesses: the peer first (quiet, end markers), then the uplink.
            let mut w = t.witness.take().ok_or("the witness is not running")?;
            let mut u = t.uplink.take().ok_or("the uplink capture is not running")?;
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
            if wrc != Some(0) {
                return Err(SuiteError::Abort(format!(
                    "the peer witness did not finish cleanly (exit {wrc:?})"
                )));
            }
            let mut meta = read_json(base.join("peer-witness.json"))?;
            capture::scrub(&mut meta);
            write_record(&run.join(CAPTURE_JSON), &meta)?;
            io(
                fs::rename(run.join("peer.pcap.tcpdump.err"), run.join("peer.err")),
                "peer.err",
            )?;
            // 7. The listeners go after the witness: stopping one resets its embryonic connections.
            if let Some(l) = t.listener.as_mut() {
                l.signal("TERM");
                if wait_exit(l.as_mut(), self.st, 100).is_none() {
                    l.kill();
                }
            }
            t.listener = None;
            // 8. The stand after the run, then the interlock before a byte is trusted or copied.
            let (post_rc, post) = lab_status(self.st, &self.status, run, "status-post.json")?;
            uplink_interlock(run).map_err(|m| {
                if m.contains(LAB_FRAME_MARK) {
                    SuiteError::Isolation(m)
                } else {
                    SuiteError::Abort(m)
                }
            })?;
            Ok(post_rc == 0 && post["raw_run_allowed"] == true)
        }
    }

    /// `autodetect-suite macos [--root-case]`. `exe` is this binary (`--lab` must be it); `sudo_user` is
    /// `$SUDO_USER`, who gets the directory back after a root case.
    pub(crate) fn macos_with(
        args: &[String],
        st: &dyn Stand,
        exe: &Path,
        sudo_user: Option<&str>,
    ) -> Result<i32, SuiteError> {
        let o = options_for("autodetect-suite macos", args, MACOS_OPTIONS)?;
        if o.contains_key("help") {
            say(USAGE);
            return Ok(0);
        }
        if o.get("root-case").is_some_and(|v| !v.is_empty()) {
            return Err(not_run("--root-case takes no value"));
        }
        let plan = if o.contains_key("root-case") {
            Plan::MacosRoot
        } else {
            Plan::Macos
        };
        let euid = st.euid()?;
        euid_rule(plan, euid)?;
        let user = match plan {
            Plan::MacosRoot => Some(
                sudo_user
                    .filter(|u| safe_id(u) && *u != "root")
                    .ok_or_else(|| {
                        not_run("--root-case is started by the user through sudo: $SUDO_USER must name the account that gets the evidence directory back")
                    })?
                    .to_owned(),
            ),
            _ => None,
        };
        let tags = selected_tags(plan, only_of(&o)?)?;
        let rmasscan = absolute_file(&o, "rmasscan")?;
        let lab = absolute_file(&o, "lab")?;
        if hash(&lab)? != hash(exe)? {
            return Err(not_run(
                "--lab is not the running rmasscan-lab: the gates, listeners and witnesses must be this build",
            ));
        }
        let run_id = opt(&o, "run-id", "m1");
        if !safe_id(&run_id) {
            return Err(not_run("--run-id must be a safe identifier"));
        }
        let out = PathBuf::from(required(&o, "out")?);
        let identity = json!({"autodetect": plan, "schema": 1, "suite": "autodetect-suite macos",
            "rmasscan": binary(&rmasscan)?, "lab": binary(&lab)?, "run_id": run_id, "euid": euid,
            "stand": {"scanner_if": SCANNER_IF, "peer_if": PEER_IF, "scanner_mac": SCANNER_MAC, "peer_mac": PEER_MAC,
                "scanner_ip": SOURCE_IP, "peer_ip": PEER_IP, "listeners": "8000-8007"},
            "peer_witness_filter": PEER_FILTER, "uplink_filter": UPLINK_FILTER});
        let suite = Mac {
            st,
            out: out.clone(),
            rmasscan_sha: hash(&rmasscan)?,
            rmasscan,
            status: status_argv(&lab, &run_id, None),
            lab,
        };
        // Nothing is written before this point; from here on the directory exists and a root case gives it back.
        let result = run_cases(&suite, &specs(plan, &tags), &identity);
        let _ = fs::remove_dir(out.join(".work"));
        match user {
            Some(u) if out.exists() => give_back(st, &u, &out, result),
            _ => result,
        }
    }

    fn run_cases(s: &Mac, cases: &[CaseSpec], identity: &Value) -> Result<i32, SuiteError> {
        let tags: Vec<&str> = cases.iter().map(|c| c.tag).collect();
        check_out(&s.out, &tags, identity)?;
        // The stand must be sealed, with BPF granted, before anything is written into --out.
        let probe = s.out.join(".work");
        if fs::read_dir(&probe).is_ok_and(|mut d| d.next().is_some()) {
            return Err(not_run(format!(
                "{} holds unfinished run directories (an abort whose evidence copy failed); inspect them, copy or remove them by hand, then start again. Nothing was deleted or started",
                probe.display()
            )));
        }
        io(fs::create_dir_all(&probe), "work root")?;
        let (rc, s0) = lab_status(s.st, &s.status, &probe, "status-start.json")?;
        let _ = fs::remove_file(probe.join("status-start.json"));
        if rc != 0 || s0["raw_run_allowed"] != true || s0["bpf_access"] != "granted" {
            return Err(not_run(format!(
                "the stand is not sealed with BPF granted (macos-lab status rc {rc}, bpf_access {}); run macos-lab up and bpf-access --grant first. Nothing was started",
                s0["bpf_access"]
            )));
        }
        s.stand_macs()?;
        write_manifest(&s.out, identity)?;
        for spec in cases {
            if s.st.stopped() {
                return Err(SuiteError::Interrupted(format!(
                    "stop requested before {} started; nothing was left running",
                    spec.tag
                )));
            }
            s.one(spec)?;
            say(&format!("done {0} -> runs/{0}", spec.tag));
        }
        say(&format!(
            "all selected runs executed; verify offline with rmasscan-lab autodetect-verify --dir {}",
            s.out.display()
        ));
        Ok(0)
    }

    /// The root case's directory goes back to the user who ran sudo, whatever happened in it.
    fn give_back(
        st: &dyn Stand,
        user: &str,
        out: &Path,
        result: Result<i32, SuiteError>,
    ) -> Result<i32, SuiteError> {
        let failed = match st.exec(&[CHOWN.into(), "-R".into(), user.into(), p2s(out)], 120) {
            Ok(o) if o.rc == 0 => None,
            Ok(o) => Some(format!("exit {}: {}", o.rc, o.stderr.trim())),
            Err(e) => Some(e),
        };
        let Some(why) = failed else { return result };
        let hint = format!(
            "chown -R {user} of the evidence directory failed ({why}); run it by hand: sudo chown -R {user} {}",
            out.display()
        );
        match result {
            Ok(_) => Err(SuiteError::Abort(hint)),
            Err(e) => {
                warn(&hint);
                Err(e)
            }
        }
    }
}

// ------------------------------------------------------------------ entry point

/// The exit code of a suite result (the other suites' convention: NOT RUN through `Err`, printed by `main`).
fn report(r: Result<i32, SuiteError>) -> Result<i32, String> {
    match r {
        Ok(code) => Ok(code),
        Err(SuiteError::NotRun(m)) => Err(scrub_str(&m)),
        Err(e) => {
            let label = match e {
                SuiteError::Abort(_) => "ABORT",
                SuiteError::Isolation(_) => "ISOLATION BREACH",
                SuiteError::Interrupted(_) => "INTERRUPTED",
                SuiteError::RerunRefused(_) => "RERUN REFUSED",
                _ => "SCHEMA TOO OLD",
            };
            warn(&format!("{label}: {}", e.message()));
            Ok(e.code())
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_entry(args: &[String], exe: &Path) -> Result<i32, SuiteError> {
    linux_with(args, &RealLinux, exe)
}
#[cfg(not(target_os = "linux"))]
fn linux_entry(_args: &[String], _exe: &Path) -> Result<i32, SuiteError> {
    Err(not_run(
        "autodetect-suite linux runs on the Linux lab host, inside wire-lab.sh --suite autodetect",
    ))
}
#[cfg(target_os = "macos")]
fn macos_entry(args: &[String], exe: &Path) -> Result<i32, SuiteError> {
    macos_with(
        args,
        &crate::macos_suite::RealStand,
        exe,
        std::env::var("SUDO_USER").ok().as_deref(),
    )
}
#[cfg(not(target_os = "macos"))]
fn macos_entry(_args: &[String], _exe: &Path) -> Result<i32, SuiteError> {
    Err(not_run(
        "autodetect-suite macos runs on the Mac with the feth stand",
    ))
}

/// `autodetect-suite linux|macos ...`: 0 every selected run executed, 2 NOT RUN, 10 ABORT, 13 ISOLATION BREACH,
/// 130 INTERRUPTED. Whether a run passed is `autodetect-verify`'s verdict, never this exit code.
pub fn run(args: &[String]) -> Result<i32, String> {
    let Some((stand, rest)) = args.split_first() else {
        return Err(format!("which stand?\n{USAGE}"));
    };
    if matches!(stand.as_str(), "--help" | "-h" | "help") {
        say(USAGE);
        return Ok(0);
    }
    rmasscan_net::lab_io::install_signal_handlers()
        .map_err(|e| format!("cannot install the stop-signal handlers: {e}"))?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    report(match stand.as_str() {
        "linux" => linux_entry(rest, &exe),
        "macos" => macos_entry(rest, &exe),
        other => Err(not_run(format!(
            "unknown stand {other}; use linux or macos"
        ))),
    })
}

#[cfg(test)]
#[path = "autodetect_suite_tests.rs"]
mod tests;
