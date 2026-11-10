//! `autodetect-suite linux|macos`: the live runs of the rmasscan autodetect acceptance on the sealed Linux netns
//! stand and on the macOS `feth` stand. Every planned case of the verifier's case table becomes one `runs/<tag>/`
//! directory that `autodetect-verify` judges offline:
//! - `argv.json` and `expect.json` straight from [`CaseSpec::argv`] and [`CaseSpec::expect`] (no case is defined
//!   here), rmasscan's `stdout.txt`, `stderr.txt`, `exit.txt` and `detected.json` (its stderr parsed by the
//!   verifier's own parser); an `--iflist` case keeps only `iflist.json`, reduced in memory, never the listing;
//! - the peer witness of `capture dump`: `peer.pcap`, its record `capture.json`, tcpdump's `peer.err`. On macOS the
//!   witness captures every frame of the peer interface into the private work directory and the suite publishes
//!   that capture without the host's own mDNS ([`publish_peer_capture`]);
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
//! Linux its stdout is `suite.log` in the evidence directory). Every record it writes, and on Linux what it prints,
//! also names its `--out` `$OUT`, its private work directory `$WORK` (macOS: `$OUT/.work`) and the account that
//! started it `$USER`, through one [`capture::Scrubber`] the Windows plan shares. A case with a run or an aborted
//! attempt in `--out` is not run again there.
use crate::{
    autodetect_verify::{
        self as av, ARGV_JSON, ArgvRecord, CAPTURE_JSON, CaseKind, CaseSpec, DETECTED_JSON,
        EXPECT_JSON, ExpectRecord, HASHES, IFLIST_JSON, ISOLATION_POST_JSON, IflistRecord,
        MANIFEST_JSON, ORACLE_CAPTURE_JSON, ORACLE_IFLIST_JSON, ORACLE_PCAP, PEER_PCAP, Plan,
    },
    capture::{self, IsolationMode, Scrubber, isolation_permits, scrub_str},
    macos_verify::{hashes_match_tree, tree},
    windows_suite::{
        Output, SuiteError, epoch, hash, nonce, options_for, read_json, required, safe_id,
        write_json,
    },
};
#[cfg(target_os = "macos")]
use mac::macos_with;
#[cfg(all(target_os = "macos", test))]
use mac::{CHOWN, open_ports, witness_files};
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
pub(crate) const LINUX_PEER_IF: &str = "veth-b";
pub(crate) const POLL: Duration = Duration::from_millis(50);
/// The longest case is the ARP timeout (10 s); a scan of the stand takes a few seconds plus `--wait 3`.
const SCAN_POLLS: u32 = 2400;
const READY_POLLS: u32 = 600;
const ACK_POLLS: u32 = 300;
/// `capture dump` stops within 90 s: quiet <= 20 s, end markers <= 15 s, tcpdump stop <= 30 s.
const WITNESS_POLLS: u32 = 1800;
pub(crate) const RESPONDER_POLLS: u32 = 200;
pub(crate) const EXEC_TIMEOUT: u64 = 60;
/// The Linux suite's mark in `--work` that a run could not be copied into the evidence directory and its work
/// directory stays: `wire-lab.sh` then leaves `--work` in place at its cleanup (and refuses that `--out` next time).
pub(crate) const WORK_KEPT: &str = "work-kept.txt";

const USAGE: &str = "autodetect-suite linux --out DIR --work DIR --ns-a NS --ns-b NS --iface-a IF --iface-b IF --mac-a MAC --mac-b MAC --rmasscan PATH --oracle PATH --conf-masked 0|1 --lab-id ID [--only TAG ...]   (run by wire-lab.sh --suite autodetect, as root)
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
    "lab-id",
    "only",
];

// ------------------------------------------------------------------ small helpers

pub(crate) fn p2s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}
pub(crate) fn io<T>(r: std::io::Result<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e}"))
}
pub(crate) fn not_run(m: impl Into<String>) -> SuiteError {
    SuiteError::NotRun(m.into())
}
/// One line on stdout, scrubbed (the Linux suite's stdout is `suite.log` in the evidence directory). A broken pipe
/// is ignored: the children must still be stopped in order.
pub(crate) fn say(line: &str) {
    let mut o = std::io::stdout();
    let _ = writeln!(o, "{}", scrub_str(line));
    let _ = o.flush();
}
pub(crate) fn warn(line: &str) {
    let mut o = std::io::stderr();
    let _ = writeln!(o, "{}", scrub_str(line));
    let _ = o.flush();
}
pub(crate) fn colon(m: [u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
/// A record as pretty JSON with a final newline.
pub(crate) fn write_record<T: Serialize>(path: &Path, v: &T) -> Result<(), String> {
    let mut b = serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?;
    b.push(b'\n');
    io(fs::write(path, b), &p2s(path))
}
pub(crate) fn write_exit(dir: &Path, rc: i32) -> Result<(), String> {
    io(
        fs::write(dir.join("exit.txt"), format!("{rc}\n")),
        "exit.txt",
    )
}
/// `--KEY` naming an existing file by its absolute path.
pub(crate) fn absolute_file(
    o: &BTreeMap<String, Vec<String>>,
    k: &str,
) -> Result<String, SuiteError> {
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
pub(crate) fn poll(pause: &dyn Fn(Duration), polls: u32, mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..polls {
        if done() {
            return true;
        }
        pause(POLL);
    }
    done()
}
/// Signal `p` and wait up to `polls` for it; SIGKILL when it is still there. The exit code when it exited.
pub(crate) fn stop(
    p: &mut dyn Running,
    sig: &str,
    pause: &dyn Fn(Duration),
    polls: u32,
) -> Option<i32> {
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
pub(crate) fn only_of(o: &BTreeMap<String, Vec<String>>) -> Result<&[String], SuiteError> {
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

/// rmasscan's `--iflist` reduced on the spot: exit code, the number of listed (non-blank) lines, sha256 of the whole
/// output and the one line of the stand NIC (`NAME index=…`; `None` when it is not listed or no NIC is asked for).
/// The listing itself is an inventory of the host.
pub(crate) fn reduce_iflist(rc: i32, text: &str, stand_iface: Option<&str>) -> IflistRecord {
    let lead = stand_iface.map(|n| format!("{n} index="));
    reduce(rc, text, |l| {
        lead.as_deref().is_some_and(|lead| l.starts_with(lead))
    })
}
/// The C oracle's `--iflist` (masscan lists on stderr) reduced by the same rule; its stand line is masscan's own
/// ` N  NAME \t(DESC)` line of `stand_iface` ([`av::masscan_iflist_name`]). masscan closes its listing with a blank
/// line and without any adapter prints one error line, so a blank line never counts.
pub(crate) fn reduce_masscan_iflist(rc: i32, text: &str, stand_iface: &str) -> IflistRecord {
    reduce(rc, text, |l| {
        av::masscan_iflist_name(l) == Some(stand_iface)
    })
}
fn reduce(rc: i32, text: &str, is_stand: impl Fn(&str) -> bool) -> IflistRecord {
    IflistRecord {
        rc,
        lines: text.lines().filter(|l| !l.trim().is_empty()).count() as u64,
        sha256: crate::verify::sha(text.as_bytes()),
        stand_line: text
            .lines()
            .find(|l| is_stand(l))
            .map(|l| l.trim_end_matches('\r').to_owned()),
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
/// What the suite prints when rmasscan's stderr (`stderr`, the file it read) does not parse.
pub(crate) fn stderr_parse_warning(stderr: &str, e: &str) -> String {
    format!("{stderr} does not parse ({e}); detected.json is not written")
}
/// `detected.json`: rmasscan's stderr (`stderr`: `stderr.txt`, on Windows `guest-stderr.txt`) parsed by the verifier's
/// parser. A stderr that does not parse gets no record (the verifier then cannot pass the run).
pub(crate) fn write_detected(run: &Path, stderr: &str) -> Result<(), String> {
    let b = io(fs::read(run.join(stderr)), stderr)?;
    match av::parse_stderr(&String::from_utf8_lossy(&b)) {
        Ok(d) => write_record(&run.join(DETECTED_JSON), &d),
        Err(e) => {
            warn(&stderr_parse_warning(stderr, &e));
            Ok(())
        }
    }
}

/// The `--offline` preflight of a case (R1): the same argv, read only (`w01`, `w06` through `windows-suite --plan
/// autodetect`, `m05` here).
pub(crate) fn preflight_argv(spec: &CaseSpec) -> Vec<String> {
    let mut a = spec.argv();
    a.push("--offline".into());
    a
}
/// `preflight.txt`: `rc N`, then the preflight's stderr.
pub(crate) fn preflight_text(rc: i32, stderr: &str) -> String {
    format!("rc {rc}\n{stderr}")
}

// ------------------------------------------------------------------ the macOS peer capture's privacy rule

/// A frame the macOS peer capture must not publish: the host's own mDNS on the peer interface, which names the host.
/// The rule of `macos_verify::PEER_FILTER`, applied after the capture: ether source = the peer stand MAC and UDP port
/// 5353 (source or destination), over IPv4 (a first fragment) or IPv6. Every lab frame fails one of the two: the
/// scanner's frames come from the scanner MAC; the peer's SYN-ACKs, RSTs and ARP replies are not UDP; the markers
/// are not IP.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn is_peer_mdns(f: &[u8]) -> bool {
    if f.get(6..12) != Some(&crate::link::STAND_PEER_MAC[..]) {
        return false;
    }
    let udp = match f.get(12..14) {
        Some([0x08, 0x00]) => {
            let ihl = usize::from(f.get(14).map_or(0, |b| b & 15)) * 4;
            let first = f
                .get(20..22)
                .is_some_and(|x| u16::from_be_bytes([x[0], x[1]]) & 0x1fff == 0);
            (ihl >= 20 && first && f.get(23) == Some(&17)).then_some(14 + ihl)
        }
        Some([0x86, 0xdd]) => (f.get(20) == Some(&17)).then_some(54),
        _ => None,
    };
    udp.and_then(|o| f.get(o..o + 4)).is_some_and(|p| {
        u16::from_be_bytes([p[0], p[1]]) == 5353 || u16::from_be_bytes([p[2], p[3]]) == 5353
    })
}

/// The published peer capture of a macOS run and its `capture.json`: the witness's unfiltered capture without
/// [`is_peer_mdns`] frames, every kept record byte for byte. The witness judged completeness on every frame it
/// captured, kept and dropped alike, against the interface counters, so its verdict stands. The record then describes
/// the published file (`pcap_sha256`, `pcap_frames`, `pcap_size_bytes`) and keeps the unfiltered file's identity
/// (`unfiltered`) and what was left out (`privacy_filter`); `autodetect-verify` reads the fields of a `capture dump`
/// record and ignores the others. An unfiltered file other than the one the witness hashed and counted is not its
/// capture: the record is then invalid.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn publish_peer_capture(
    unfiltered: &[u8],
    mut witness: Value,
) -> Result<(Vec<u8>, Value), String> {
    let (_, frames) = crate::pcap::read_pcap_records(unfiltered)?;
    let (kept, dropped) = crate::pcap::keep_records(unfiltered, |f| !is_peer_mdns(f))?;
    let recorded = (
        witness["pcap_sha256"].clone(),
        witness["pcap_frames"].clone(),
    );
    if recorded.0 != crate::verify::sha(unfiltered) || recorded.1 != json!(frames.len()) {
        witness["valid"] = json!(false);
        let why = json!("the unfiltered capture is not the file the witness hashed and counted");
        match witness["invalid_reasons"].as_array_mut() {
            Some(r) => r.push(why),
            None => witness["invalid_reasons"] = json!([why]),
        }
    }
    witness["unfiltered"] = json!({"pcap_sha256": recorded.0, "pcap_frames": frames.len(),
        "kept": "private work directory only, deleted after publishing"});
    witness["privacy_filter"] = json!({"published": crate::macos_verify::PEER_FILTER,
        "frames_dropped": dropped, "frames_kept": frames.len() - dropped});
    witness["pcap_sha256"] = json!(crate::verify::sha(&kept));
    witness["pcap_frames"] = json!(frames.len() - dropped);
    witness["pcap_size_bytes"] = json!(kept.len());
    Ok((kept, witness))
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

/// Before the first run: no lab-isolation finding anywhere in `out` (a breach makes the directory FAIL for good; `verify`
/// is the plan's verifier), no run and no aborted attempt of a selected case yet, and no manifest of another plan (its
/// key `plan_key`), build (rmasscan, oracle, rmasscan-lab), stand or Linux lab (`lab_id`).
pub(crate) fn check_out_for(
    out: &Path,
    tags: &[&str],
    identity: &Value,
    plan_key: &str,
    verify: fn(&Path) -> Value,
) -> Result<(), SuiteError> {
    io(fs::create_dir_all(out), "--out")?;
    let trips = verify(out)["safety_trips"]
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
    // An earlier attempt counts as a run: a later run of the case would overtake it (the verifier never passes one).
    for t in tags {
        let earlier = av::aborted_attempts(out, t);
        if !earlier.is_empty() {
            return Err(not_run(format!(
                "{t} has an aborted attempt in this directory ({}); a case runs once into one --out, run it again into a new --out",
                earlier.join(", ")
            )));
        }
    }
    let path = out.join(MANIFEST_JSON);
    if path.exists() {
        let m = read_json(&path).map_err(|e| {
            not_run(format!(
                "manifest.json is unreadable ({e}); use a new --out"
            ))
        })?;
        for k in [plan_key, "rmasscan", "oracle", "lab", "run_id", "lab_id"] {
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
pub(crate) fn write_manifest(out: &Path, identity: &Value, sc: &Scrubber) -> Result<(), String> {
    let path = out.join(MANIFEST_JSON);
    if path.exists() {
        return Ok(());
    }
    let mut v = identity.clone();
    v["created_utc"] = json!(epoch());
    sc.value(&mut v);
    write_record(&path, &v)
}
/// The binaries the manifest vouches for (path, sha256) are still the files on disk: checked before every run.
pub(crate) fn binaries_unchanged(binaries: &[(String, String)]) -> Result<(), SuiteError> {
    for (path, sha) in binaries {
        if hash(path)? != *sha {
            let name = Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned());
            return Err(not_run(format!(
                "{} changed since the manifest was written; nothing was started",
                name.unwrap_or_default()
            )));
        }
    }
    Ok(())
}
pub(crate) fn binary(path: &str) -> Result<Value, String> {
    Ok(json!({"sha256": hash(path)?, "size": fs::metadata(path).map(|m| m.len()).unwrap_or(0)}))
}

// ------------------------------------------------------------------ Linux: the seam

/// How a process the Linux suite started ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ended {
    /// It exited with this code.
    Code(i32),
    /// A signal ended it (Unix: no exit code; `ExitStatusExt::signal`).
    Signal(i32),
}
/// A process the Linux suite started.
pub(crate) trait Running {
    /// `None` while it runs. A process without an exit code (a signal ended it) reads as -1.
    fn try_wait(&mut self) -> Result<Option<i32>, String>;
    /// How it ended, `None` while it runs. The default reads [`Running::try_wait`] as an exit code; the real child
    /// tells a signal apart.
    fn try_end(&mut self) -> Result<Option<Ended>, String> {
        self.try_wait().map(|r| r.map(Ended::Code))
    }
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
    /// The account that started the suite ([`capture::account`]), taken once at the start.
    fn account(&self) -> Option<String>;
    fn pause(&self, d: Duration);
    fn stopped(&self) -> bool;
    /// The wall clock, Unix seconds (the output suite records when it interrupts a scan).
    fn now(&self) -> f64 {
        epoch()
    }
}

/// A status without an exit code: the signal that ended the process (Unix), or -1 where there is none to read.
#[cfg(unix)]
fn ended_by_signal(s: &std::process::ExitStatus) -> Ended {
    use std::os::unix::process::ExitStatusExt;
    s.signal().map_or(Ended::Code(-1), Ended::Signal)
}
#[cfg(not(unix))]
fn ended_by_signal(_s: &std::process::ExitStatus) -> Ended {
    Ended::Code(-1)
}

/// The lab host: children of this process. They stay in the suite's process group, which `wire-lab.sh` stops as a
/// whole if the suite dies.
pub(crate) struct RealLinux;
struct RealChild(std::process::Child);
impl Running for RealChild {
    fn try_wait(&mut self) -> Result<Option<i32>, String> {
        self.0
            .try_wait()
            .map(|s| s.map(|s| s.code().unwrap_or(-1)))
            .map_err(|e| e.to_string())
    }
    fn try_end(&mut self) -> Result<Option<Ended>, String> {
        let status = self.0.try_wait().map_err(|e| e.to_string())?;
        Ok(status.map(|s| match s.code() {
            Some(rc) => Ended::Code(rc),
            None => ended_by_signal(&s),
        }))
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
    fn account(&self) -> Option<String> {
        capture::account_from_env()
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
pub(crate) struct LinuxTools {
    pub(crate) scanner: Option<Box<dyn Running>>,
    pub(crate) witness: Option<Box<dyn Running>>,
    /// The witness of the second link (the scan-control stand's `veth-b2`), when that suite runs one.
    pub(crate) witness2: Option<Box<dyn Running>>,
    pub(crate) responder: Option<Box<dyn Running>>,
    /// A frame may exist: the start marker is about to be sent.
    pub(crate) frames_possible: bool,
}
impl Drop for LinuxTools {
    fn drop(&mut self) {
        for (p, sig) in [
            (self.scanner.take(), "INT"),
            (self.witness.take(), "TERM"),
            (self.witness2.take(), "TERM"),
            (self.responder.take(), "TERM"),
        ] {
            if let Some(mut p) = p {
                stop(p.as_mut(), sig, &std::thread::sleep, 40);
            }
        }
    }
}
/// One capture's witness: the pcap it writes and the record it leaves.
pub(crate) struct Witness {
    pub(crate) pcap: PathBuf,
    pub(crate) meta: PathBuf,
}
/// Which link a witness watches: the peer end it records on, and the scanner end that sends its start marker.
pub(crate) struct WitnessLink<'a> {
    pub(crate) peer_if: &'a str,
    pub(crate) scanner_if: &'a str,
    pub(crate) scanner_mac: &'a str,
    pub(crate) peer_mac: &'a str,
}

/// The driver of the Linux netns stand, shared by `autodetect-suite linux` and `output-suite linux`.
pub(crate) struct Linux<'a> {
    pub(crate) host: &'a dyn LinuxHost,
    pub(crate) out: PathBuf,
    pub(crate) work: PathBuf,
    pub(crate) ns_a: String,
    pub(crate) ns_b: String,
    pub(crate) mac_a: String,
    pub(crate) mac_b: String,
    pub(crate) rmasscan: String,
    pub(crate) oracle: String,
    pub(crate) masked: bool,
    pub(crate) lab: String,
    /// rmasscan, the oracle and rmasscan-lab as the manifest vouches for them (path, sha256).
    pub(crate) binaries: Vec<(String, String)>,
    /// `--out`, `--work` and the account as placeholders in every record it writes.
    pub(crate) scrub: Scrubber,
}

impl Linux<'_> {
    pub(crate) fn pause(&self) -> impl Fn(Duration) + '_ {
        |d| self.host.pause(d)
    }
    pub(crate) fn ns(&self, ns: &str, tail: impl IntoIterator<Item = String>) -> Vec<String> {
        [IP, "netns", "exec", ns]
            .into_iter()
            .map(str::to_owned)
            .chain(tail)
            .collect()
    }
    pub(crate) fn lab(&self, args: &[&str]) -> Vec<String> {
        std::iter::once(self.lab.clone())
            .chain(args.iter().map(|a| (*a).to_owned()))
            .collect()
    }

    /// `capture isolation --mode autodetect` now, into `path` (scrubbed): the seal of the stand, proven again.
    pub(crate) fn isolation(&self, path: &Path) -> Result<(), String> {
        self.isolation_mode(path, "autodetect")
    }
    /// [`Self::isolation`] for `mode` `autodetect` or `scan-control` (the autodetect stand plus the second veth pair).
    pub(crate) fn isolation_mode(&self, path: &Path, mode: &str) -> Result<(), String> {
        let links = self.work.join("host-links-before.txt");
        let o = self.host.exec(
            &self.lab(&[
                "capture",
                "isolation",
                "--mode",
                mode,
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
        if v["mode"] != mode || !isolation_permits(&v, IsolationMode::Autodetect) {
            return Err(format!(
                "the record does not permit a {mode} run (default_route {})",
                v["default_route"]
            ));
        }
        self.scrub.value(&mut v);
        write_record(path, &v)
    }

    /// The peer's listeners (the stand's open ports; every other port is reset), restarted for every capture so
    /// that half-open connections of an earlier scan never answer into the next one.
    pub(crate) fn responder(&self, base: &Path, t: &mut LinuxTools) -> Result<(), SuiteError> {
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
    pub(crate) fn witness(
        &self,
        base: &Path,
        run: &Path,
        pcap_name: &str,
        t: &mut LinuxTools,
    ) -> Result<Witness, SuiteError> {
        let link = WitnessLink {
            peer_if: LINUX_PEER_IF,
            scanner_if: av::stand(Plan::Linux).iface,
            scanner_mac: &self.mac_a,
            peer_mac: &self.mac_b,
        };
        self.witness_link(base, run, pcap_name, t, &link, false)
    }

    /// [`Self::witness`] on any link of the stand; `second` keeps the process in `t.witness2`.
    pub(crate) fn witness_link(
        &self,
        base: &Path,
        run: &Path,
        pcap_name: &str,
        t: &mut LinuxTools,
        link: &WitnessLink,
        second: bool,
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
                link.peer_if,
                "--pcap",
                &p2s(&pcap),
                "--meta",
                &p2s(&meta),
                "--ready",
                &p2s(&ready),
                "--ack",
                &p2s(&ack),
                "--end-dst",
                link.scanner_mac,
            ]),
        );
        let process = self.host.spawn(
            &argv,
            &base.join(format!("{stem}-witness.out.txt")),
            &base.join(format!("{stem}-witness.err.txt")),
        )?;
        if second {
            t.witness2 = Some(process);
        } else {
            t.witness = Some(process);
        }
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
                    link.scanner_if,
                    "--src",
                    link.scanner_mac,
                    "--dst",
                    link.peer_mac,
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
    pub(crate) fn finish_witness(
        &self,
        w: &Witness,
        t: &mut LinuxTools,
        run: &Path,
        record: &str,
        err: &str,
    ) -> Result<(), SuiteError> {
        let p = t.witness.take();
        self.finish_witness_process(p, w, run, record, err)
    }
    /// [`Self::finish_witness`] for the process of the second link.
    pub(crate) fn finish_witness2(
        &self,
        w: &Witness,
        t: &mut LinuxTools,
        run: &Path,
        record: &str,
        err: &str,
    ) -> Result<(), SuiteError> {
        let p = t.witness2.take();
        self.finish_witness_process(p, w, run, record, err)
    }
    fn finish_witness_process(
        &self,
        p: Option<Box<dyn Running>>,
        w: &Witness,
        run: &Path,
        record: &str,
        err: &str,
    ) -> Result<(), SuiteError> {
        let mut p = p.ok_or("the witness is not running")?;
        let rc = stop(p.as_mut(), "TERM", &self.pause(), WITNESS_POLLS);
        if rc != Some(0) {
            return Err(SuiteError::Abort(format!(
                "the peer witness did not finish cleanly (exit {rc:?})"
            )));
        }
        let mut meta = read_json(&w.meta)?;
        self.scrub.value(&mut meta);
        write_record(&run.join(record), &meta)?;
        io(
            fs::rename(format!("{}.tcpdump.err", p2s(&w.pcap)), run.join(err)),
            err,
        )?;
        Ok(())
    }

    pub(crate) fn wait(&self, t: &mut LinuxTools, tag: &str) -> Result<i32, SuiteError> {
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
        Ok(self.ns(&self.ns_a, self.oracle_cmd(base, args)?))
    }
    /// [`Self::oracle_argv`] without the namespace: what runs inside it.
    pub(crate) fn oracle_cmd(&self, base: &Path, args: Vec<String>) -> Result<Vec<String>, String> {
        let mut a = Vec::new();
        if self.masked {
            let empty = base.join("empty-etc-masscan");
            io(fs::create_dir_all(&empty), "empty-etc-masscan")?;
            a.extend([UNSHARE, "-m", SH, "-c", MASK_SCRIPT].map(str::to_owned));
            a.push(p2s(&empty));
        }
        a.push(self.oracle.clone());
        a.extend(args);
        Ok(a)
    }

    /// `--iflist` of rmasscan and of the C oracle in the scanner namespace, reduced in memory, each with its line of
    /// the stand NIC. rmasscan lists on stdout; masscan on stderr (`rawsock_list_adapters`), its stdout stays empty.
    /// Neither of the oracle's streams is written anywhere: `oracle/iflist.json` is all that is kept of it.
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
            &reduce_masscan_iflist(o.rc, &o.stderr, av::stand(Plan::Linux).iface),
        )?;
        Ok(())
    }

    fn one(&self, spec: &CaseSpec) -> Result<PathBuf, SuiteError> {
        self.one_with(spec.tag, |base, run, t| self.one_inner(spec, base, run, t))
    }
    /// One run of case `tag`: `body` fills the run directory (`run`, inside the work directory `base`) with the tools
    /// it starts in `t`; the run is then hashed and copied to `runs/<tag>`, or kept under `runs_aborted` on a failure
    /// once a frame may exist ([`Self::abort`]).
    pub(crate) fn one_with(
        &self,
        tag: &str,
        body: impl FnOnce(&Path, &Path, &mut LinuxTools) -> Result<(), SuiteError>,
    ) -> Result<PathBuf, SuiteError> {
        let name = format!("{tag}.{}", nonce());
        let base = self.work.join(&name);
        let run = base.join("run");
        io(fs::create_dir_all(&run), "work directory")?;
        let mut t = LinuxTools::default();
        if let Err(e) = body(&base, &run, &mut t) {
            return Err(self.abort(&base, &run, &name, t, e));
        }
        drop(t);
        let dest = self.out.join("runs").join(tag);
        io(fs::create_dir_all(self.out.join("runs")), "runs directory")
            .and_then(|()| hash_and_copy(&run, &dest))
            .map_err(|e| SuiteError::Abort(self.keep_work(&base, &e)))?;
        io(fs::remove_dir_all(&base), "remove the work directory")?;
        Ok(dest)
    }

    /// A run that could not be copied into the evidence directory: its work directory `base` stays as it is, marked
    /// in `--work` ([`WORK_KEPT`]) so that `wire-lab.sh` leaves `--work` in place at its cleanup. The message tells
    /// what happens to it, also when the mark cannot be written (then the cleanup removes it).
    fn keep_work(&self, base: &Path, e: &str) -> String {
        let mark = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.work.join(WORK_KEPT))
            .and_then(|mut f| writeln!(f, "{}: {}", scrub_str(&p2s(base)), scrub_str(e)));
        match mark {
            Ok(()) => format!(
                "{e}; the work directory {} is kept ({WORK_KEPT} tells wire-lab.sh to leave {} in place)",
                base.display(),
                self.work.display()
            ),
            Err(x) => format!(
                "{e}; the work directory {} could not be marked to be kept ({x}), so wire-lab.sh's cleanup removes it",
                base.display()
            ),
        }
    }

    fn one_inner(
        &self,
        spec: &CaseSpec,
        base: &Path,
        run: &Path,
        t: &mut LinuxTools,
    ) -> Result<(), SuiteError> {
        let tag = spec.tag;
        binaries_unchanged(&self.binaries)?;
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
            write_detected(run, "stderr.txt")?;
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
        self.isolation(&run.join(ISOLATION_POST_JSON)).map_err(|e| {
            SuiteError::Abort(format!(
                "{tag}: the stand is not sealed after the run ({e}); no further run"
            ))
        })
    }

    /// The failure path of one run: the scanner stops first, then the witness (with its full window, so that its
    /// capture is finished). Once a frame may exist the run directory is kept under `runs_aborted/<tag>.<nonce>`,
    /// hashed like a run (when that copy fails, the work directory stays, marked: [`Self::keep_work`]); before that
    /// nothing is left.
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
        if let Some(mut p) = t.witness2.take() {
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
            Err(e) => self.keep_work(base, &e),
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
    let (out, work) = (
        PathBuf::from(required(&o, "out")?),
        PathBuf::from(required(&o, "work")?),
    );
    // The account is taken once, here. The suite's stdout and stderr are `suite.log` in the evidence directory: what
    // it prints names --out, --work and the account by placeholder too.
    let sc = Scrubber::new(&out, Some(&work), host.account().as_deref());
    linux_run(&o, host, lab, out, work, &sc).map_err(|e| e.map_message(|m| sc.str(m)))
}
/// The Linux suite once its `--out`, `--work` and account are known: every record goes through `sc`.
fn linux_run(
    o: &BTreeMap<String, Vec<String>>,
    host: &dyn LinuxHost,
    lab: &Path,
    out: PathBuf,
    work: PathBuf,
    sc: &Scrubber,
) -> Result<i32, SuiteError> {
    const SUITE: &str = "wire-lab.sh --suite autodetect";
    let a = linux_args(o, SUITE)?;
    let tags = selected_tags(Plan::Linux, only_of(o)?)?;
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
    attested_stand(&out, SUITE)?;
    let plan = ("autodetect", json!(Plan::Linux), "autodetect-suite linux");
    let suite = linux_driver(
        host,
        lab,
        out.clone(),
        work,
        a,
        sc,
        &tags,
        plan,
        av::verify_dir,
    )?;
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
    say(&sc.str(&format!(
        "all selected runs executed; verify offline with rmasscan-lab autodetect-verify --dir {}",
        out.display()
    )));
    Ok(0)
}

/// The Linux stand's options as `wire-lab.sh` passes them: its fixed stand (`suite`, the script's mode, names it in
/// the refusal), the two namespaces, the lab id, whether `/etc/masscan` is masked, and the two scanners.
pub(crate) struct LinuxArgs {
    ns_a: String,
    ns_b: String,
    lab_id: String,
    masked: bool,
    rmasscan: String,
    oracle: String,
}
pub(crate) fn linux_args(
    o: &BTreeMap<String, Vec<String>>,
    suite: &str,
) -> Result<LinuxArgs, SuiteError> {
    // The stand is wire-lab.sh's fixed autodetect stand, nothing else.
    let st = av::stand(Plan::Linux);
    for (k, want) in [
        ("iface-a", st.iface.to_owned()),
        ("iface-b", LINUX_PEER_IF.to_owned()),
        ("mac-a", colon(st.scanner_mac)),
        ("mac-b", colon(st.peer_mac)),
    ] {
        let v = required(o, k)?;
        if v != want {
            return Err(not_run(format!(
                "--{k} {v} is not the autodetect stand's {want} ({suite} fixes the stand)"
            )));
        }
    }
    let (ns_a, ns_b) = (required(o, "ns-a")?, required(o, "ns-b")?);
    if !safe_id(&ns_a) || !safe_id(&ns_b) || ns_a == ns_b {
        return Err(not_run(
            "--ns-a and --ns-b must be two different safe namespace names",
        ));
    }
    // wire-lab.sh's id of this lab: kept in manifest.json, and its teardown.json carries the same (the verifier binds
    // the record of the undo to these runs with it).
    let lab_id = required(o, "lab-id")?;
    if !safe_id(&lab_id) {
        return Err(not_run("--lab-id must be a safe identifier"));
    }
    let masked = match required(o, "conf-masked")?.as_str() {
        "0" => false,
        "1" => true,
        v => return Err(not_run(format!("--conf-masked must be 0 or 1, not {v}"))),
    };
    Ok(LinuxArgs {
        ns_a,
        ns_b,
        lab_id,
        masked,
        rmasscan: absolute_file(o, "rmasscan")?,
        oracle: absolute_file(o, "oracle")?,
    })
}
/// `wire-lab.sh`'s own `isolation.json` in `out`: the sealed autodetect stand (`suite` is the script's mode).
pub(crate) fn attested_stand(out: &Path, suite: &str) -> Result<(), SuiteError> {
    let iso = read_json(out.join("isolation.json")).map_err(|e| {
        not_run(format!(
            "wire-lab.sh's isolation.json is missing ({e}); the suite runs only inside {suite}"
        ))
    })?;
    if iso["mode"] != "autodetect" || !isolation_permits(&iso, IsolationMode::Autodetect) {
        return Err(not_run(format!(
            "isolation.json does not attest the sealed autodetect stand (mode {}, default_route {})",
            iso["mode"], iso["default_route"]
        )));
    }
    Ok(())
}
/// The driver of the stand once the cases are chosen: `manifest.json` (the stand, the builds and the lab id; `plan` is
/// its key, value and suite name), the evidence directory's checks ([`check_out_for`] with `verify`), `env.json`
/// scrubbed, and the work directory.
#[allow(clippy::too_many_arguments)]
pub(crate) fn linux_driver<'a>(
    host: &'a dyn LinuxHost,
    lab: &Path,
    out: PathBuf,
    work: PathBuf,
    a: LinuxArgs,
    sc: &Scrubber,
    tags: &[&str],
    plan: (&str, Value, &str),
    verify: fn(&Path) -> Value,
) -> Result<Linux<'a>, SuiteError> {
    let st = av::stand(Plan::Linux);
    let lab = p2s(lab);
    let binaries = [&a.rmasscan, &a.oracle, &lab]
        .into_iter()
        .map(|p| Ok((p.clone(), hash(p)?)))
        .collect::<Result<Vec<_>, String>>()?;
    let mut identity = json!({"schema": 1, "suite": plan.2,
        "rmasscan": binary(&a.rmasscan)?, "oracle": binary(&a.oracle)?, "lab": binary(&lab)?,
        "stand": {"scanner_if": st.iface, "peer_if": LINUX_PEER_IF, "scanner_mac": colon(st.scanner_mac),
            "peer_mac": colon(st.peer_mac), "scanner_ip": st.scanner_ip.to_string(),
            "peer_ips": st.peer_ips.iter().map(Ipv4Addr::to_string).collect::<Vec<_>>(),
            "open_ports": st.open_ports, "default_route": "via 198.18.0.2 dev veth-a (scanner namespace only)"},
        "conf_masked": a.masked, "lab_id": a.lab_id});
    identity[plan.0] = plan.1;
    check_out_for(&out, tags, &identity, plan.0, verify)?;
    write_manifest(&out, &identity, sc)?;
    // wire-lab.sh's env.json names the oracle by its path, which may be under a home directory or name the account.
    if let Ok(mut env) = read_json(out.join("env.json")) {
        sc.value(&mut env);
        write_json(out.join("env.json"), &env)?;
    }
    io(fs::create_dir_all(&work), "--work")?;
    Ok(Linux {
        host,
        out,
        work,
        ns_a: a.ns_a,
        ns_b: a.ns_b,
        mac_a: colon(st.scanner_mac),
        mac_b: colon(st.peer_mac),
        rmasscan: a.rmasscan,
        oracle: a.oracle,
        masked: a.masked,
        lab,
        binaries,
        scrub: sc.clone(),
    })
}

// ------------------------------------------------------------------ macOS

#[cfg(target_os = "macos")]
mod mac {
    //! The feth stand through `macos_suite::Stand`, with `macos-suite`'s own lock and run steps: status before and
    //! after each run, the Application Firewall, leftover lab processes (rmasscan included), a quiet pair, the peer
    //! listeners, the uplink capture with the lab filter and its interlock (exit 13), and the peer witness. The
    //! witness captures every frame of the peer interface into the private work directory; the suite publishes that
    //! capture without the host's own mDNS ([`publish_peer_capture`]) and deletes the unfiltered file.
    use super::*;
    use crate::{
        autodetect_verify::PREFLIGHT_TXT,
        macos_lab::{
            PEER_IF, PEER_IP, PEER_MAC, SCANNER_IF, SCANNER_MAC, SOURCE_IP, UPLINK_FILTER,
        },
        macos_suite::{
            Proc, Stand, Tools, WitnessFiles, abort_run, application_firewall, gate_status,
            interlock, lab_status, leftover_gate, note_child, pair_quiet_gate, start_listeners,
            start_witnesses, status_argv, stop_listener, stop_tools, stop_witnesses, sync_lock,
            take_lock,
        },
        macos_verify::PEER_FILTER,
        pcap::keep_records,
        windows_suite::opt,
    };
    use std::{cell::RefCell, collections::BTreeSet};

    pub(crate) const CHOWN: &str = "/usr/sbin/chown";
    const MACOS_OPTIONS: &[&str] = &["out", "rmasscan", "lab", "run-id", "only", "root-case"];

    /// `peer listen --open` for the stand's open ports: a range when they are contiguous.
    pub(crate) fn open_ports() -> String {
        let p = av::stand(Plan::Macos).open_ports;
        match (p.first(), p.last()) {
            (Some(a), Some(b)) if usize::from(b - a) + 1 == p.len() => format!("{a}-{b}"),
            _ => p.iter().map(u16::to_string).collect::<Vec<_>>().join(","),
        }
    }

    /// A run's witness files: the uplink capture's in the run directory (evidence), the peer witness's in the
    /// private work directory. Its capture there is `peer.unfiltered`, an extension no evidence file may carry, so a
    /// copy a crash left behind makes the evidence directory INVALID instead of publishable.
    pub(crate) fn witness_files(base: &Path, run: &Path) -> WitnessFiles {
        WitnessFiles {
            uplink_pcap: run.join("uplink.pcap"),
            uplink_err: run.join("uplink.err"),
            uplink_out: base.join("uplink.out.txt"),
            peer_pcap: base.join("peer.unfiltered"),
            peer_dir: base.to_path_buf(),
            peer_err: run.join("peer.err"),
        }
    }

    /// Publish the peer capture into `run`: `peer.pcap` without the host's own mDNS and, with the witness's record,
    /// `capture.json`. The unfiltered file is deleted whatever happens.
    fn publish(
        f: &WitnessFiles,
        run: &Path,
        witness: Option<Value>,
        sc: &Scrubber,
    ) -> Result<(), String> {
        let published = (|| -> Result<(), String> {
            let raw = io(fs::read(&f.peer_pcap), "the unfiltered peer capture")?;
            let (kept, record) = match witness {
                Some(w) => {
                    let (kept, mut rec) = publish_peer_capture(&raw, w)?;
                    sc.value(&mut rec);
                    (kept, Some(rec))
                }
                None => (keep_records(&raw, |fr| !is_peer_mdns(fr))?.0, None),
            };
            io(fs::write(run.join(PEER_PCAP), kept), PEER_PCAP)?;
            record.map_or(Ok(()), |r| write_record(&run.join(CAPTURE_JSON), &r))
        })();
        let _ = fs::remove_file(&f.peer_pcap);
        published
    }

    struct Mac<'a> {
        st: &'a dyn Stand,
        out: PathBuf,
        rmasscan: String,
        lab: String,
        /// The binaries the manifest vouches for (path, sha256), checked again before every run.
        binaries: Vec<(String, String)>,
        status: Vec<String>,
        /// macos-suite's lock (one suite on the stand at a time); the live children's process groups go into it.
        lock: Option<PathBuf>,
        children: RefCell<BTreeSet<u32>>,
        /// `--out` and the account as placeholders in every record it writes (its work directory is `$OUT/.work`).
        scrub: Scrubber,
    }

    impl Mac<'_> {
        fn note(&self, p: &dyn Proc) {
            note_child(self.lock.as_deref(), &self.children, p);
        }

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
            let files = witness_files(&base, &run);
            let mut t = Tools::default();
            let result = match self.one_inner(spec, &base, &run, &files, &mut t) {
                Ok(sealed) => self.keep(spec.tag, &base, &run, sealed),
                Err(e) => {
                    // The tools stop first; whatever the witness captured is then published without the host's
                    // mDNS (the unfiltered file never outlives the run) and kept the way macos-suite keeps an abort.
                    stop_tools(self.st, &mut t);
                    if files.peer_pcap.exists() {
                        let w = read_json(base.join("peer-witness.json")).ok();
                        if let Err(x) = publish(&files, &run, w, &self.scrub) {
                            warn(&format!(
                                "the aborted run's peer capture was not published ({x}); it is deleted"
                            ));
                        }
                    }
                    self.scrub_status(&run);
                    let e = abort_run(self.st, &self.out, &run, &name, &mut t, e);
                    if !run.exists() {
                        let _ = fs::remove_dir_all(&base);
                    }
                    Err(e)
                }
            };
            // Every child is stopped and reaped by now (or the run is an abort that said so).
            self.children.borrow_mut().clear();
            sync_lock(self.lock.as_deref(), &self.children.borrow());
            result
        }

        /// `macos-lab status`'s records of a run, as it printed them, rewritten before the run is hashed and copied
        /// (kept or aborted). One that cannot be rewritten stays as it is: the verifier still scans it.
        fn scrub_status(&self, run: &Path) {
            for name in ["status-pre.json", "status-post.json"] {
                let p = run.join(name);
                if p.is_file()
                    && let Err(e) = self.scrub.file(&p)
                {
                    warn(&format!("{name} was not rewritten ({e})"));
                }
            }
        }

        /// A finished run goes to `runs/<tag>`; a stand that is not sealed afterwards stops the suite.
        fn keep(
            &self,
            tag: &str,
            base: &Path,
            run: &Path,
            sealed: bool,
        ) -> Result<PathBuf, SuiteError> {
            let dest = self.out.join("runs").join(tag);
            io(fs::create_dir_all(self.out.join("runs")), "runs directory")?;
            self.scrub_status(run);
            hash_and_copy(run, &dest).map_err(SuiteError::Abort)?;
            io(fs::remove_dir_all(base), "remove the work directory")?;
            if !sealed {
                return Err(SuiteError::Abort(format!(
                    "macos-lab status after {tag} does not allow raw runs; the run is kept in runs/{tag} for the verifier and no further run starts"
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
            files: &WitnessFiles,
            t: &mut Tools,
        ) -> Result<bool, SuiteError> {
            let tag = spec.tag;
            let note = |p: &dyn Proc| self.note(p);
            // 1. The gates, before anything starts: the sealed stand with BPF granted, the firewall, the binaries.
            let pre = gate_status(self.st, &self.status, run, &json!(tag), "granted")?;
            application_firewall(self.st, run)?;
            binaries_unchanged(&self.binaries)?;
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
            // 3. The peer listeners, then the uplink capture and the peer witness (macos-suite's steps).
            start_listeners(
                self.st,
                t,
                &self.lab,
                &open_ports(),
                &run.join("listeners.json"),
                base,
                &note,
            )?;
            let uplink_if = pre["uplink"].as_str().unwrap_or("").to_owned();
            if uplink_if.is_empty() || uplink_if.starts_with("feth") {
                return Err(not_run(format!(
                    "the uplink interface {uplink_if:?} is not a real default-route interface; nothing was started"
                )));
            }
            start_witnesses(self.st, t, &self.lab, &uplink_if, files, &note)?;
            if self.st.stopped() {
                return Err(SuiteError::Interrupted(format!(
                    "stop requested before {tag} started its scanner"
                )));
            }
            // 4. rmasscan with the table's argv: a scan, or `--iflist` reduced in memory.
            if spec.kind == CaseKind::Iflist {
                let o = self
                    .st
                    .exec(&[self.rmasscan.clone(), "--iflist".into()], EXEC_TIMEOUT)?;
                write_iflist(run, &o, SCANNER_IF)?;
            } else {
                let argv: Vec<String> = std::iter::once(self.rmasscan.clone())
                    .chain(spec.argv())
                    .collect();
                let p = self
                    .st
                    .spawn(&argv, &run.join("stdout.txt"), &run.join("stderr.txt"))?;
                note(&*p);
                t.scanner = Some(p);
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
                write_detected(run, "stderr.txt")?;
            }
            // 5. The witnesses stop (peer first); the peer capture is published without the host's own mDNS.
            let (witness, _, _) = stop_witnesses(self.st, t, files)?;
            publish(files, run, Some(witness), &self.scrub)?;
            // 6. The listeners after the witness, the stand after the run, then the interlock before a byte is copied.
            stop_listener(self.st, t);
            let (post_rc, post) = lab_status(self.st, &self.status, run, "status-post.json")?;
            interlock(run)?;
            Ok(post_rc == 0 && post["raw_run_allowed"] == true)
        }
    }

    /// `autodetect-suite macos [--root-case]`. `exe` is this binary (`--lab` must be it); `sudo_user` is `$SUDO_USER`,
    /// who gets the directory back after a root case, and with `login` (`$USER`) names the account the evidence never
    /// names ([`capture::account`]); `lock_path` is macos-suite's one-suite lock.
    pub(crate) fn macos_with(
        args: &[String],
        st: &dyn Stand,
        exe: &Path,
        sudo_user: Option<&str>,
        login: Option<&str>,
        lock_path: &dyn Fn() -> Result<PathBuf, String>,
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
        // The account, taken once: `$SUDO_USER` for the root case, `$USER` for the user window. The work directory is
        // `--out/.work`, so `$OUT/.work` names it.
        let account = capture::account(sudo_user, login);
        let scrub = Scrubber::new(&out, None, account.as_deref());
        let identity = json!({"autodetect": plan, "schema": 1, "suite": "autodetect-suite macos",
            "rmasscan": binary(&rmasscan)?, "lab": binary(&lab)?, "run_id": run_id, "euid": euid,
            "stand": {"scanner_if": SCANNER_IF, "peer_if": PEER_IF, "scanner_mac": SCANNER_MAC, "peer_mac": PEER_MAC,
                "scanner_ip": SOURCE_IP, "peer_ip": PEER_IP, "listeners": open_ports()},
            "peer_capture": {"witness": "capture dump on feth4202, every frame, into the private work directory",
                "published": PEER_FILTER},
            "uplink_filter": UPLINK_FILTER});
        // One suite on the stand at a time: macos-suite's lock, taken before anything is written.
        let path = lock_path().map_err(SuiteError::NotRun)?;
        let lock_dir = path.parent().map(Path::to_path_buf);
        let created = lock_dir.as_ref().is_some_and(|d| !d.exists());
        let lock = take_lock(&path).map_err(SuiteError::NotRun)?;
        let suite = Mac {
            st,
            out: out.clone(),
            binaries: vec![
                (rmasscan.clone(), hash(&rmasscan)?),
                (lab.clone(), hash(&lab)?),
            ],
            rmasscan,
            status: status_argv(&lab, &run_id, None),
            lab,
            lock: Some(lock.path().to_path_buf()),
            children: RefCell::default(),
            scrub,
        };
        let result = run_cases(&suite, &specs(plan, &tags), &identity);
        let _ = fs::remove_dir(out.join(".work"));
        drop(lock);
        match user {
            Some(u) => give_back(
                st,
                &u,
                &out,
                lock_dir.filter(|_| created).as_deref(),
                result,
            ),
            None => result,
        }
    }

    fn run_cases(s: &Mac, cases: &[CaseSpec], identity: &Value) -> Result<i32, SuiteError> {
        let tags: Vec<&str> = cases.iter().map(|c| c.tag).collect();
        check_out_for(&s.out, &tags, identity, "autodetect", av::verify_dir)?;
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
        write_manifest(&s.out, identity, &s.scrub)?;
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

    /// The root case's files go back to the user who ran sudo, whatever happened: the evidence directory, and the
    /// lock directory when this root case created it (the user's later suites must be able to lock in it).
    fn give_back(
        st: &dyn Stand,
        user: &str,
        out: &Path,
        lock_dir: Option<&Path>,
        result: Result<i32, SuiteError>,
    ) -> Result<i32, SuiteError> {
        let mut commands = Vec::new();
        if out.exists() {
            commands.push(vec![
                CHOWN.to_owned(),
                "-R".into(),
                user.to_owned(),
                p2s(out),
            ]);
        }
        if let Some(d) = lock_dir {
            commands.push(vec![CHOWN.to_owned(), "-h".into(), user.to_owned(), p2s(d)]);
        }
        let failed: Vec<String> = commands
            .iter()
            .filter_map(|argv| match st.exec(argv, 120) {
                Ok(o) if o.rc == 0 => None,
                Ok(o) => Some(format!(
                    "{}: exit {}: {}",
                    argv.join(" "),
                    o.rc,
                    o.stderr.trim()
                )),
                Err(e) => Some(format!("{}: {e}", argv.join(" "))),
            })
            .collect();
        if failed.is_empty() {
            return result;
        }
        let hint = format!(
            "handing the files back to {user} failed ({}); run it by hand: sudo chown -R {user} {}",
            failed.join("; "),
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
pub(crate) fn report(r: Result<i32, SuiteError>) -> Result<i32, String> {
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

/// The Linux suite, refused at once off Linux. One code path on every OS: it is compiled and linted everywhere.
fn linux_entry(args: &[String], exe: &Path) -> Result<i32, SuiteError> {
    if !cfg!(target_os = "linux") {
        return Err(not_run(
            "autodetect-suite linux runs on the Linux lab host, inside wire-lab.sh --suite autodetect",
        ));
    }
    linux_with(args, &RealLinux, exe)
}
#[cfg(target_os = "macos")]
fn macos_entry(args: &[String], exe: &Path) -> Result<i32, SuiteError> {
    macos_with(
        args,
        &crate::macos_suite::RealStand,
        exe,
        std::env::var("SUDO_USER").ok().as_deref(),
        std::env::var("USER").ok().as_deref(),
        &crate::macos_suite::lock_path,
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

/// The real child tells a signal apart from an exit code (`try_wait` alone reads both as a code, a signal as -1).
/// These run `/bin/sh` and nothing else: no interface, no frame.
#[cfg(all(test, unix))]
mod real_child_tests {
    use super::{Ended, RealChild, Running};
    use std::{process::Command, thread, time::Duration};

    fn ended(script: &str) -> Ended {
        let mut c = RealChild(
            Command::new("/bin/sh")
                .args(["-c", script])
                .spawn()
                .unwrap(),
        );
        for _ in 0..500 {
            if let Some(e) = c.try_end().unwrap() {
                return e;
            }
            thread::sleep(Duration::from_millis(10));
        }
        c.kill();
        panic!("{script}: still running after 5 s");
    }

    #[test]
    fn a_signal_and_an_exit_code_are_told_apart() {
        assert_eq!(ended("kill -9 $$"), Ended::Signal(9));
        assert_eq!(ended("kill -15 $$"), Ended::Signal(15));
        assert_eq!(ended("exit 3"), Ended::Code(3));
        assert_eq!(ended("exit 0"), Ended::Code(0));
        // try_wait keeps its old reading for the other suites: a signal is -1
        let mut c = RealChild(
            Command::new("/bin/sh")
                .args(["-c", "kill -9 $$"])
                .spawn()
                .unwrap(),
        );
        let rc = loop {
            if let Some(rc) = c.try_wait().unwrap() {
                break rc;
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(rc, -1);
    }
}
