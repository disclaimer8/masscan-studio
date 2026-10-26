//! Offline verifier of a Masscan Studio window on the sealed macOS `feth` stand.
//!
//! Portable on purpose: it reads the files of one window directory, parses the independent `peer.pcap`
//! and `uplink.pcap`, and compares them with what Studio itself recorded (the UI chronicle `smoke.json`
//! and the SQLite dump `history.json`). Nothing here touches the network or starts a process, and no
//! status is ever promoted: an unproven capture is INVALID, a missing file is NOT RUN, a lab frame on
//! the uplink is a FAIL that no rerun discards.
//!
//! The binding of Studio (source `198.18.0.1`, MAC `02:ac:00:00:00:01`, next hop `02:ac:00:00:00:02`,
//! source port 40000, wait 3 s, adapter `feth4201`) and the three jobs of `--smoke-feth` are pinned
//! below on purpose instead of imported from `studio-protocol`: the verifier must not depend on the code
//! it judges. The probe order is rebuilt with the engine's own `ProbeCursor` through `verify::plan_frames`,
//! the function the Windows and macOS verifiers use for the same purpose.
//!
//! The window directory, its file formats and every rule are specified in `rmasscan/docs/macos-feth-lab.md`
//! ("Studio acceptance"), which is the contract of the orchestrator (`cargo xtask feth-acceptance`).
use crate::{
    macos_verify::{CLOCK_TOLERANCE_S, capture_command, has_compressed_capture},
    pcap::{self, Frames},
    verify::{
        self, Binding, FAIL, INVALID, NOT_RUN, PASS, Run, answered_port_open, array, read_json, s,
        sha, tcp,
    },
    windows_suite::parse_tcpdump,
};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

pub const SCANNER_IP: &str = "198.18.0.1";
pub const PEER_IP: &str = "198.18.0.2";
pub const SCANNER_MAC: &str = "02:ac:00:00:00:01";
pub const NEXT_HOP_MAC: &str = "02:ac:00:00:00:02";
pub const ADAPTER: &str = "feth4201";
pub const PEER_IF: &str = "feth4202";
pub const ALF_TEXT: &str = "Firewall is disabled. (State = 0)";
pub const SOURCE_PORT: u16 = 40000;
pub const WAIT_SECS: u32 = 3;
pub const PAUSE_ACK_TEXT: &str = "Checkpoint committed by Studio";
/// The order of the user-level actions of one `--smoke-feth` session.
pub const ACTION_ORDER: [&str; 8] = [
    "Authorize",
    "Start:s1_full",
    "Start:s2_pause",
    "Pause",
    "Resume",
    "Start:s3_stop",
    "Stop",
    "Lock",
];
pub const PAUSE_TO_PAUSED_MAX_MS: i64 = 5000;
pub const STOP_TO_STOPPED_MAX_MS: i64 = 1000;
/// The last SYN of a stopped scan may trail the observed `Stopped` state by the UI poll (50 ms) plus margin.
pub const STOP_SYN_GRACE_S: f64 = 0.25;
const HASHES: &str = "hashes-before-copy.txt";
const VERDICT: &str = "verdict.json";
const LAB_OPEN_PORTS: std::ops::RangeInclusive<u16> = 8000..=8007;
/// A reply that answers a stopped scan within this time before the Stop action need not have reached the results.
const STOP_REPLY_GRACE_S: f64 = 0.25;

/// One planned case of the session. The jobs are the constants of `--smoke-feth`.
pub struct CaseSpec {
    pub tag: &'static str,
    pub ports: &'static str,
    pub seed: &'static str,
    pub rate: u64,
    pub status: &'static str,
}
pub const CASES: [CaseSpec; 3] = [
    CaseSpec {
        tag: "s1_full",
        ports: "80,443,8000-8007,9000-9009",
        seed: "1",
        rate: 100,
        status: "Completed",
    },
    CaseSpec {
        tag: "s2_pause",
        ports: "9000-9031",
        seed: "2",
        rate: 4,
        status: "Completed",
    },
    CaseSpec {
        tag: "s3_stop",
        ports: "1-2000",
        seed: "3",
        rate: 300,
        status: "Stopped",
    },
];
fn spec_job(c: &CaseSpec) -> Value {
    json!({"targets":PEER_IP,"ports":c.ports,"exclusions":"","seed":c.seed,"rate":c.rate,"backend":"MacFeth"})
}

// ------------------------------------------------------------------ utilities

/// The planned frames of a Studio job (an object with `targets ports exclusions seed rate backend`), built as
/// `wire_scan` and the other verifiers build theirs, with the Studio binding pinned in this module.
pub(crate) fn plan_frames_for_job(job: &Value) -> Result<Vec<Vec<u8>>, String> {
    if job["backend"] != "MacFeth" {
        return Err("job backend is not MacFeth".into());
    }
    let text = |k: &str| {
        job[k]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("job.{k} missing"))
    };
    let rate = job["rate"].as_u64().ok_or("job.rate missing")?;
    let mut args: BTreeMap<String, Value> = BTreeMap::new();
    for (k, v) in [
        ("src-ip", SCANNER_IP.to_owned()),
        ("src-mac", SCANNER_MAC.to_owned()),
        ("router-mac", NEXT_HOP_MAC.to_owned()),
        ("source-port", SOURCE_PORT.to_string()),
        ("iface", ADAPTER.to_owned()),
        ("wait", WAIT_SECS.to_string()),
        ("targets", text("targets")?),
        ("ports", text("ports")?),
        ("seed", text("seed")?),
        ("rate", rate.to_string()),
    ] {
        args.insert(format!("--{k}"), json!(v));
    }
    let exclusions = text("exclusions")?;
    if !exclusions.trim().is_empty() {
        args.insert("--exclude".into(), json!(exclusions));
    }
    verify::plan_frames(&args)
}
/// The destination ports of the probes of a job, in the order the scanner sends them.
pub fn plan_ports_for_job(job: &Value) -> Result<Vec<u16>, String> {
    plan_frames_for_job(job)?
        .iter()
        .map(|f| {
            tcp(f)
                .map(|t| t.dp)
                .ok_or_else(|| "plan frame is not TCP".into())
        })
        .collect()
}
/// The time window `[lo, hi)` in which the SYNs of a case may lie: one second before its `Starting` and one
/// second after its terminal state. Where the window of a neighbouring case would overlap, both are cut at the
/// later case's `Starting` minus 250 ms (not before the earlier case finished), so no frame belongs to two cases.
pub fn scan_window(
    starting: f64,
    finished: f64,
    prev_finished: Option<f64>,
    next_starting: Option<f64>,
) -> (f64, f64) {
    let mut lo = starting - 1.0;
    let mut hi = finished + 1.0;
    if let Some(pf) = prev_finished
        && pf + 1.0 > lo
    {
        lo = pf.max(starting - 0.25);
    }
    if let Some(ns) = next_starting
        && ns - 1.0 < hi
    {
        hi = finished.max(ns - 0.25);
    }
    (lo, hi)
}
/// What tcpdump printed on exit. `received` is information only on macOS (it counts before the filter).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TcpdumpStats {
    pub captured: u64,
    pub received: Option<u64>,
    pub dropped_kernel: u64,
}
/// `None` unless both `packets captured` and `packets dropped by kernel` are there: those lines are printed on a
/// clean exit (SIGINT), so their absence means the witness did not end cleanly and is unproven.
pub fn parse_tcpdump_stats(text: &str) -> Option<TcpdumpStats> {
    let v = parse_tcpdump(text);
    Some(TcpdumpStats {
        captured: v["captured"].as_u64()?,
        received: v["received"].as_u64(),
        dropped_kernel: v["dropped_kernel"].as_u64()?,
    })
}
/// `YYYY-MM-DDTHH:MM:SS[.fff]Z` (UTC) as seconds since the epoch.
pub fn parse_utc(t: &str) -> Option<f64> {
    let (date, rest) = t.split_once('T')?;
    let rest = rest.strip_suffix('Z')?;
    let mut d = date.split('-');
    let (y, m, day): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    if d.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    let (hms, frac) = rest.split_once('.').unwrap_or((rest, ""));
    let mut p = hms.split(':');
    let (h, mi, sec): (i64, i64, i64) = (
        p.next()?.parse().ok()?,
        p.next()?.parse().ok()?,
        p.next()?.parse().ok()?,
    );
    if p.next().is_some() || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let frac = if frac.is_empty() {
        0.0
    } else if frac.bytes().all(|b| b.is_ascii_digit()) {
        format!("0.{frac}").parse().ok()?
    } else {
        return None;
    };
    // Days from civil (Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((days * 86_400 + h * 3600 + mi * 60 + sec) as f64 + frac)
}

// ------------------------------------------------------------------ wire model

struct Syn {
    t: f64,
    port: u16,
    seq: u32,
}
struct Reply {
    t: f64,
    port: u16,
    ack: u32,
    open: bool,
}
#[derive(Default)]
struct Wire {
    syns: Vec<Syn>,
    replies: Vec<Reply>,
    /// Unicast IPv4 frames from the scanner (its MAC or its IP) that are not a source-port-40000 SYN to 198.18.0.2.
    rogue: Vec<String>,
}
fn mac_str(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
/// The scanner's SYNs, the peer's replies to the scanner (`198.18.0.2 -> 198.18.0.1`, dport 40000) and every
/// other unicast IPv4 frame the scanner sent (group-addressed frames are exempt, as in `strays_lifetime`).
fn classify(frames: &Frames) -> Wire {
    let mut w = Wire::default();
    for (t, f) in frames {
        let i = tcp(f);
        if f.len() >= 34 && f[12..14] == [8, 0] && f[0] & 1 == 0 {
            let from_scanner = mac_str(&f[6..12]) == SCANNER_MAC || f[26..30] == [198, 18, 0, 1];
            let planned_form = i.as_ref().is_some_and(|i| {
                pcap::is_syn(f)
                    && i.sm == SCANNER_MAC
                    && i.src == SCANNER_IP
                    && i.dst == PEER_IP
                    && i.sp == SOURCE_PORT
            });
            if from_scanner && !planned_form {
                w.rogue.push(format!(
                    "t={t:.3} {} > {} {}",
                    mac_str(&f[6..12]),
                    mac_str(&f[0..6]),
                    i.as_ref().map_or("not TCP".to_owned(), |i| format!(
                        "{}:{} > {}:{} flags {:#04x}",
                        i.src, i.sp, i.dst, i.dp, i.flags
                    ))
                ));
            }
        }
        let Some(i) = i else { continue };
        if pcap::is_syn(f)
            && i.sm == SCANNER_MAC
            && i.src == SCANNER_IP
            && i.dst == PEER_IP
            && i.sp == SOURCE_PORT
        {
            w.syns.push(Syn {
                t: *t,
                port: i.dp,
                seq: i.seq,
            });
        } else if i.sm == NEXT_HOP_MAC
            && i.dm == SCANNER_MAC
            && i.src == PEER_IP
            && i.dst == SCANNER_IP
            && i.dp == SOURCE_PORT
        {
            if i.flags & 0x3f == 0x12 {
                w.replies.push(Reply {
                    t: *t,
                    port: i.sp,
                    ack: i.ack,
                    open: true,
                });
            } else if i.flags & 0x04 != 0 {
                w.replies.push(Reply {
                    t: *t,
                    port: i.sp,
                    ack: i.ack,
                    open: false,
                });
            }
        }
    }
    w
}

#[derive(Clone)]
struct Row {
    ip: String,
    port: u16,
    open: bool,
}
fn rows_of(scan: &Value) -> Result<Vec<Row>, String> {
    array(&scan["rows"])
        .iter()
        .map(|r| {
            Ok(Row {
                ip: r["ip"].as_str().ok_or("row.ip missing")?.to_owned(),
                port: u16::try_from(r["port"].as_u64().ok_or("row.port missing")?)
                    .map_err(|_| "row.port out of range")?,
                open: r["open"].as_bool().ok_or("row.open missing")?,
            })
        })
        .collect()
}
fn scans_of(h: &Value) -> &[Value] {
    if h.is_array() {
        array(h)
    } else {
        array(&h["scans"])
    }
}
/// A `Run` whose behaviour failures count (they are never laundered into INVALID by an unrelated unproven file).
fn run_of(tag: &str) -> Run {
    let mut r = Run::new(tag);
    r.argv_ok = true;
    r
}
fn is_hex(x: &str, n: usize) -> bool {
    x.len() == n && x.bytes().all(|b| b.is_ascii_hexdigit())
}

// ------------------------------------------------------------------ chronicle

struct Ev {
    mono: i64,
    utc: f64,
    kind: String,
    status: String,
    detail: String,
    authorized: Option<bool>,
}
struct Act {
    mono: i64,
    utc: f64,
    name: String,
}
struct Chronicle {
    events: Vec<Ev>,
    actions: Vec<Act>,
    /// The run timed out before the first Start: nothing ran, so nothing is judged.
    aborted_early: bool,
}
const TERMINAL: [&str; 4] = ["Completed", "Stopped", "Failed", "Interrupted"];
fn load_chronicle(r: &mut Run, sm: &Value) -> Option<Chronicle> {
    r.inv(
        "smoke.json schema 1",
        sm["schema"] == 1,
        sm["schema"].to_string(),
    );
    let mut bad = vec![];
    let mut events = vec![];
    for e in array(&sm["events"]) {
        match (e["mono_ms"].as_i64(), parse_utc(s(&e["utc"]))) {
            (Some(mono), Some(utc)) => events.push(Ev {
                mono,
                utc,
                kind: s(&e["kind"]).into(),
                status: s(&e["status"]).into(),
                detail: s(&e["detail"]).into(),
                authorized: e["authorized"].as_bool(),
            }),
            _ => bad.push(e.to_string()),
        }
    }
    let mut actions = vec![];
    for a in array(&sm["actions"]) {
        match (a["mono_ms"].as_i64(), parse_utc(s(&a["utc"]))) {
            (Some(mono), Some(utc)) => actions.push(Act {
                mono,
                utc,
                name: s(&a["action"]).into(),
            }),
            _ => bad.push(a.to_string()),
        }
    }
    r.inv(
        "chronicle times parse (UTC and mono_ms)",
        bad.is_empty(),
        format!("{bad:?}"),
    );
    if !bad.is_empty() {
        return None;
    }
    events.sort_by_key(|e| e.mono);
    actions.sort_by_key(|a| a.mono);
    let has_start = actions.iter().any(|a| a.name.starts_with("Start:"));
    let result = s(&sm["result"]);
    let timeout = result.starts_with("timeout");
    if result == "ok" {
        r.beh("smoke.json result is ok", true, "ok");
    } else if timeout && !has_start {
        // The authorization phase never finished: no scan ran, nothing can be judged.
        r.add("smoke.json result is ok", NOT_RUN, result, false);
    } else {
        // A failed run, or a Studio that hung after a Start: the UI/runner contract was broken.
        r.beh("smoke.json result is ok", false, result);
    }
    Some(Chronicle {
        events,
        actions,
        aborted_early: timeout && !has_start,
    })
}
fn chronicle_checks(r: &mut Run, c: &Chronicle) {
    let names: Vec<&str> = c.actions.iter().map(|a| a.name.as_str()).collect();
    r.beh(
        "actions equal the plan",
        names == ACTION_ORDER,
        names.join(","),
    );
    let granted = c
        .events
        .iter()
        .filter(|e| e.kind == "Authorization" && e.authorized == Some(true))
        .count();
    r.beh("authorization granted exactly once", granted == 1, granted);
    let first_start = c
        .actions
        .iter()
        .find(|a| a.name.starts_with("Start:"))
        .map_or(i64::MAX, |a| a.mono);
    r.beh(
        "network preflight passed before the first Start",
        c.events.iter().any(|e| {
            e.kind == "Notice"
                && e.detail.contains("Network preflight passed")
                && e.mono < first_start
        }),
        "",
    );
    let lock = c
        .actions
        .iter()
        .find(|a| a.name == "Lock")
        .map_or(i64::MAX, |a| a.mono);
    r.beh(
        "runner session closed after Lock",
        c.events.iter().any(|e| {
            e.kind == "Notice" && e.detail.contains("Runner session closed") && e.mono >= lock
        }),
        "",
    );
    // The windows are cut from UTC while the latencies come from the monotonic clock: a wall-clock step in
    // between would silently shift one against the other.
    let drift: Vec<f64> = c
        .events
        .iter()
        .map(|e| (e.utc, e.mono))
        .chain(c.actions.iter().map(|a| (a.utc, a.mono)))
        .map(|(u, m)| u - m as f64 / 1000.0)
        .collect();
    let spread = drift.iter().copied().fold(f64::MIN, f64::max)
        - drift.iter().copied().fold(f64::MAX, f64::min);
    r.inv(
        "chronicle UTC and monotonic clocks agree (no wall-clock step, 100 ms)",
        drift.is_empty() || spread <= 0.1,
        format!("spread {spread:.3} s"),
    );
}
/// The first and last instant the chronicle knows (UTC).
fn chronicle_span(c: &Chronicle) -> Option<(f64, f64)> {
    let all: Vec<f64> = c
        .events
        .iter()
        .map(|e| e.utc)
        .chain(c.actions.iter().map(|a| a.utc))
        .collect();
    Some((
        all.iter().copied().reduce(f64::min)?,
        all.iter().copied().reduce(f64::max)?,
    ))
}
/// The `State` events and actions that belong to one case (from its `Start:<tag>` to the next Start or Lock).
struct CaseTimeline<'a> {
    states: Vec<&'a Ev>,
    actions: Vec<&'a Act>,
}
fn case_timeline<'a>(c: &'a Chronicle, tag: &str) -> Option<CaseTimeline<'a>> {
    let start = c
        .actions
        .iter()
        .find(|a| a.name == format!("Start:{tag}"))?;
    let end = c
        .actions
        .iter()
        .find(|a| a.mono > start.mono && (a.name.starts_with("Start:") || a.name == "Lock"))
        .map_or(i64::MAX, |a| a.mono);
    Some(CaseTimeline {
        states: c
            .events
            .iter()
            .filter(|e| e.kind == "State" && e.mono >= start.mono && e.mono < end)
            .collect(),
        actions: c
            .actions
            .iter()
            .filter(|a| a.mono >= start.mono && a.mono < end)
            .collect(),
    })
}

// ------------------------------------------------------------------ safety

struct Cap {
    ok: bool,
    start: Option<f64>,
    stop: Option<f64>,
    exit: Value,
}
struct Safe {
    peer: Option<Frames>,
    /// The peer pcap parsed, is complete, was recorded by the right command inside its window.
    peer_proven: bool,
    caps: [Cap; 2],
}
fn text_in(dir: &Path, name: &str) -> Option<String> {
    fs::read_to_string(dir.join(name)).ok()
}
/// A file the verifier needs: its text, or a NOT RUN check.
fn need(r: &mut Run, d: &Path, name: &str) -> Option<String> {
    let t = text_in(d, name);
    if t.is_none() {
        r.add(&format!("{name} present"), NOT_RUN, "missing", false);
    }
    t
}
fn hashes_check(r: &mut Run, d: &Path) {
    let Some(text) = text_in(d, HASHES) else {
        r.add(&format!("{HASHES} present"), NOT_RUN, "missing", false);
        return;
    };
    let mut want = BTreeMap::new();
    for l in text.lines().filter(|l| !l.is_empty()) {
        let Some((h, name)) = l.split_once("  ") else {
            r.inv("hashes-before-copy.txt well formed", false, l);
            return;
        };
        if !is_hex(h, 64)
            || Path::new(name).components().count() != 1
            || name == HASHES
            || name == VERDICT
            || want.insert(name.to_owned(), h.to_owned()).is_some()
        {
            r.inv("hashes-before-copy.txt well formed", false, l);
            return;
        }
    }
    let mut have = BTreeSet::new();
    for e in fs::read_dir(d).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let is_data = name == "data" && e.path().is_dir();
        if name != HASHES && name != VERDICT && !is_data {
            have.insert(name);
        }
    }
    let listed: BTreeSet<String> = want.keys().cloned().collect();
    let mut problems = vec![];
    if listed != have {
        problems.push(format!(
            "unlisted {:?}, missing {:?}",
            have.difference(&listed).collect::<Vec<_>>(),
            listed.difference(&have).collect::<Vec<_>>()
        ));
    }
    for (name, h) in &want {
        match fs::read(d.join(name)) {
            Ok(b) if sha(&b) == *h => {}
            Ok(_) => problems.push(format!(
                "{name} differs from its hash taken before the copy"
            )),
            // A listed entry that cannot be read (a directory, a vanished file) is not proven by its hash.
            Err(e) => problems.push(format!("{name} cannot be read: {e}")),
        }
    }
    r.inv(
        "hashes-before-copy.txt matches the files",
        problems.is_empty(),
        problems.join("; "),
    );
}
fn status_checks(r: &mut Run, d: &Path) -> (Value, Value) {
    let mut out = [Value::Null, Value::Null];
    for (i, name) in ["status-pre.json", "status-post.json"].iter().enumerate() {
        let Some(v) = read_json(d.join(name)) else {
            r.add(
                &format!("{name} present"),
                NOT_RUN,
                "missing or not JSON",
                false,
            );
            continue;
        };
        r.inv(
            &format!("{name} raw_run_allowed is true"),
            v["raw_run_allowed"] == true,
            v["raw_run_allowed"].to_string(),
        );
        if i == 0 {
            r.inv(
                "status-pre.json bpf_access is granted",
                v["bpf_access"] == "granted",
                v["bpf_access"].to_string(),
            );
        }
        out[i] = v;
    }
    let [a, b] = out;
    (a, b)
}
fn provenance_checks(r: &mut Run, d: &Path, expect_head: Option<&str>) -> Value {
    let Some(p) = read_json(d.join("provenance.json")) else {
        r.add(
            "provenance.json present",
            NOT_RUN,
            "missing or not JSON",
            false,
        );
        return Value::Null;
    };
    let (head, ui) = (s(&p["git_head"]), s(&p["ui_sha256"]));
    let (run, inst) = (s(&p["runner_sha256"]), s(&p["installed_runner_sha256"]));
    r.inv(
        "git_head is a 40-hex commit",
        is_hex(head, 40),
        format!("{head:?}"),
    );
    r.inv(
        "ui, bundle runner and installed runner hashes are 64-hex",
        is_hex(ui, 64) && is_hex(run, 64) && is_hex(inst, 64),
        format!("ui {ui:?} runner {run:?} installed {inst:?}"),
    );
    r.inv(
        "bundle runner hash equals the installed runner hash",
        is_hex(run, 64) && run == inst,
        format!("bundle {run} installed {inst}"),
    );
    r.inv(
        "working tree was clean (dirty is false)",
        p["dirty"] == false,
        p["dirty"].to_string(),
    );
    if let Some(want) = expect_head {
        r.inv(
            "git_head equals the expected commit",
            head == want,
            format!("expected {want} recorded {head}"),
        );
    }
    p
}
/// The record `<who>.cmd.json` of one witness: its command, timing and exit. The command is judged by the check
/// `macos-verify` uses (interface, exact lab filter on the uplink, no filter on the peer).
fn capture_record(r: &mut Run, d: &Path, who: &str, uplink_if: &str, err: Option<&str>) -> Cap {
    let name = format!("{who}.cmd.json");
    let none = Cap {
        ok: false,
        start: None,
        stop: None,
        exit: Value::Null,
    };
    let Some(c) = read_json(d.join(&name)) else {
        r.inv(
            &format!("{name} present (the witness's command and timing)"),
            false,
            "missing or not JSON",
        );
        return none;
    };
    let b = Binding {
        src: SCANNER_IP.into(),
        sm: SCANNER_MAC.into(),
        pm: NEXT_HOP_MAC.into(),
    };
    let rec = json!({"cmd":c["cmd"],"filter":c["filter"]});
    let man = json!({"stand":{"peer_if":PEER_IF}});
    let mut ok = r.check(
        &format!("{who} capture interface and filter are exact"),
        capture_command(&rec, who, &man, uplink_if, &b),
        c["cmd"].to_string(),
        INVALID,
        false,
    );
    let iface = if who == "peer" { PEER_IF } else { uplink_if };
    ok &= r.check(
        &format!("{who}.err banner names the interface {iface}"),
        !iface.is_empty()
            && err.is_some_and(|t| {
                t.contains(&format!("listening on {iface},"))
                    || t.contains(&format!("listening on {iface}\n"))
            }),
        "",
        INVALID,
        false,
    );
    ok &= r.check(
        &format!("{who} listening before the first action"),
        c["listening"] == true,
        c["listening"].to_string(),
        INVALID,
        false,
    );
    ok &= r.check(
        &format!("{who} tcpdump exited cleanly after the stop (exit code 0)"),
        c["exit_code"].as_i64() == Some(0),
        c["exit_code"].to_string(),
        INVALID,
        false,
    );
    if who == "uplink" {
        ok &= r.check(
            "uplink tcpdump is not promiscuous (the user's own NIC)",
            array(&c["cmd"]).iter().any(|v| v == "-p"),
            c["cmd"].to_string(),
            INVALID,
            false,
        );
    }
    let (start, stop) = (parse_utc(s(&c["start_utc"])), parse_utc(s(&c["stop_utc"])));
    ok &= r.check(
        &format!("{who} start_utc and stop_utc are recorded"),
        matches!((start, stop), (Some(a), Some(b)) if a < b),
        format!("{} .. {}", c["start_utc"], c["stop_utc"]),
        INVALID,
        false,
    );
    Cap {
        ok,
        start,
        stop,
        exit: c["exit_code"].clone(),
    }
}
/// The files the orchestrator writes besides the captures: the window record, the gates before the run, the
/// hash of the store and the isolation interlock.
fn gate_files(r: &mut Run, d: &Path, pre_uplink: &str) {
    if let Some(w) = read_json(d.join("window.json")) {
        let marks = array(&w["invalid_marks"]);
        r.inv(
            "window.json has no INVALID mark",
            w["invalid_marks"].is_array() && marks.is_empty(),
            Value::Array(marks.to_vec()).to_string(),
        );
        r.inv(
            "the UI exited with code 0 (window.json ui_rc)",
            w["ui_rc"].as_i64() == Some(0),
            w["ui_rc"].to_string(),
        );
        r.inv(
            "window.json uplink equals status-pre.json uplink",
            !pre_uplink.is_empty() && s(&w["uplink"]) == pre_uplink,
            format!("{} vs {pre_uplink}", w["uplink"]),
        );
    } else {
        r.add("window.json present", NOT_RUN, "missing or not JSON", false);
    }
    if let Some(t) = need(r, d, "alf.txt") {
        r.inv(
            "the application firewall was disabled",
            t.trim() == ALF_TEXT,
            t.trim(),
        );
    }
    for name in ["leftover-listeners.txt", "leftover-procs.txt"] {
        if let Some(t) = need(r, d, name) {
            r.inv(
                &format!("{name} is empty (nothing left over from an earlier run)"),
                t.trim().is_empty(),
                t.trim(),
            );
        }
    }
    need(r, d, "pair-quiet.txt");
    r.inv(
        "the lab listeners were ready (listeners-ready.txt)",
        d.join("listeners-ready.txt").is_file(),
        "",
    );
    if let Some(t) = need(r, d, "data.sha256") {
        let first = t.split_whitespace().next().unwrap_or("");
        r.inv(
            "data.sha256 holds a 64-hex hash",
            is_hex(first, 64),
            t.trim(),
        );
        if let Ok(b) = fs::read(d.join("data").join("history.sqlite3")) {
            r.inv(
                "data/history.sqlite3 equals data.sha256",
                sha(&b) == first,
                "",
            );
        }
    }
    let journal = ["history.sqlite3-wal", "history.sqlite3-shm"]
        .iter()
        .any(|n| d.join("data").join(n).exists());
    r.inv(
        "the history store was closed cleanly (no -wal or -shm left)",
        !journal,
        "",
    );
    r.safety(
        "no ISOLATION-BREACH.txt: the orchestrator's interlock did not trip",
        !d.join("ISOLATION-BREACH.txt").exists(),
        text_in(d, "ISOLATION-BREACH.txt").unwrap_or_default(),
    );
}
fn safety(d: &Path, expect_head: Option<&str>) -> (Run, Safe, Value) {
    let mut r = run_of("safety");
    r.safety(
        "no compressed capture in the window directory",
        !has_compressed_capture(d),
        "compressed capture is not allowed; store captures uncompressed",
    );
    let load = |r: &mut Run, name: &str| {
        if d.join(name).exists() {
            verify::load_pcap(r, &d.join(name)).map(|x| x.0)
        } else {
            r.add(&format!("{name} present"), NOT_RUN, "missing", false);
            None
        }
    };
    let peer = load(&mut r, "peer.pcap");
    let uplink = load(&mut r, "uplink.pcap");
    let (peer_err, uplink_err) = (text_in(d, "peer.err"), text_in(d, "uplink.err"));
    let stats = |t: &Option<String>| t.as_deref().and_then(parse_tcpdump_stats);
    let (peer_stats, uplink_stats) = (stats(&peer_err), stats(&uplink_err));
    // The lab-frame rule is the Windows/macOS one: stored frames, and frames tcpdump counted as passing its
    // filter. `received by filter` is a pre-filter counter on macOS and is information only.
    let pinned =
        json!({"binding":{"src_ip":SCANNER_IP,"src_mac":SCANNER_MAC,"router_mac":NEXT_HOP_MAC}});
    verify::safety_checks(
        &mut r,
        "uplink",
        &pinned,
        "",
        peer.as_ref(),
        uplink.as_ref(),
        uplink_stats.map(|u| u.captured),
    );
    r.inv(
        "uplink.err has tcpdump's exit statistics (clean exit)",
        uplink_stats.is_some(),
        "",
    );
    r.inv(
        "uplink tcpdump dropped 0 packets by kernel",
        uplink_stats.is_some_and(|u| u.dropped_kernel == 0),
        format!("{:?}", uplink_stats.map(|u| u.dropped_kernel)),
    );
    let mut peer_proven = peer.is_some()
        && r.check(
            "peer.err has tcpdump's exit statistics (clean exit)",
            peer_stats.is_some(),
            "",
            INVALID,
            false,
        );
    if let (Some(p), Some(fr)) = (peer_stats, peer.as_ref()) {
        peer_proven &= r.check(
            "peer capture complete: captured equals the pcap frames, 0 kernel drops",
            p.captured == fr.len() as u64 && p.dropped_kernel == 0,
            format!(
                "captured {} frames {} dropped {}",
                p.captured,
                fr.len(),
                p.dropped_kernel
            ),
            INVALID,
            false,
        );
    }
    let (pre, post) = status_checks(&mut r, d);
    let pre_uplink = s(&pre["uplink"]).to_owned();
    r.inv(
        "status-pre.json names the uplink (default-route interface, not feth)",
        !pre_uplink.is_empty() && !pre_uplink.starts_with("feth"),
        pre_uplink.clone(),
    );
    let pc = capture_record(&mut r, d, "peer", &pre_uplink, peer_err.as_deref());
    let uc = capture_record(&mut r, d, "uplink", &pre_uplink, uplink_err.as_deref());
    // Freshness: every frame lies inside the capture's own window. A hash proves the bytes are the ones copied,
    // not that they were captured now.
    for (who, fr, cap) in [("peer", &peer, &pc), ("uplink", &uplink, &uc)] {
        let (Some(fr), Some(a), Some(b)) = (fr, cap.start, cap.stop) else {
            continue;
        };
        let outside = fr
            .iter()
            .filter(|(t, _)| !(a - CLOCK_TOLERANCE_S..=b + CLOCK_TOLERANCE_S).contains(t))
            .count();
        let ok = r.check(
            &format!("{who} capture packets fall inside the recorded window"),
            outside == 0,
            format!(
                "{outside} of {} packets outside the recorded window",
                fr.len()
            ),
            INVALID,
            false,
        );
        if who == "peer" {
            peer_proven &= ok;
        }
    }
    peer_proven &= pc.ok;
    hashes_check(&mut r, d);
    let prov = provenance_checks(&mut r, d, expect_head);
    gate_files(&mut r, d, &pre_uplink);
    let isolation = json!({
        "uplink_frames": uplink.as_ref().map(Vec::len),
        "uplink_captured": uplink_stats.map(|u| u.captured),
        "uplink_dropped": uplink_stats.map(|u| u.dropped_kernel),
        "uplink_exit_code": uc.exit,
        "peer_exit_code": pc.exit,
        "status_pre": pre,
        "status_post": post,
    });
    (
        r,
        Safe {
            peer,
            peer_proven,
            caps: [pc, uc],
        },
        json!({"provenance":prov,"isolation":isolation}),
    )
}
/// Both witnesses recorded the whole session: they started before its first action and stopped after its last event.
fn coverage_checks(r: &mut Run, caps: &[Cap; 2], c: &Chronicle) -> bool {
    let Some((first, last)) = chronicle_span(c) else {
        return false;
    };
    let mut all = true;
    for (who, cap) in ["peer", "uplink"].iter().zip(caps) {
        let ok = r.check(
            &format!("{who} capture covers the session (first action to last event, 1 s margin)"),
            matches!((cap.start, cap.stop), (Some(a), Some(b)) if a <= first - 1.0 && b >= last + 1.0),
            format!("capture {:?} .. {:?}, session {first:.3} .. {last:.3}", cap.start, cap.stop),
            INVALID,
            false,
        );
        if *who == "peer" {
            all &= ok;
        }
    }
    all
}

// ------------------------------------------------------------------ results (rows against the wire)

struct Recv<'a> {
    syns: &'a [Syn],
    replies: &'a [Reply],
    /// The scanner's receive window ends here (the observed terminal state).
    end: f64,
    /// Replies later than this need no row (a stopped scan).
    exempt_after: Option<f64>,
}
fn key(ip: &str, port: u16, open: bool) -> String {
    format!("{ip}:{port}:{}", if open { "open" } else { "closed" })
}
/// Rows against the replies on the wire. A reply answers a SYN of the case when it comes from that SYN's port with
/// `ack == seq + 1`. Every row must be backed by such a reply with the same open flag. Every such reply inside the
/// receive window must be a row, with the rules of the other verifiers: a SYN with no reply is fine (closed-port
/// RSTs are rate-limited), and an RST that follows a SYN-ACK of the same port is not a second result because
/// Studio keeps one row per port (`answered_port_open`). Replies after the window (listener teardown) are notes.
fn results_checks(
    r: &mut Run,
    rows: &[Row],
    rc: &Recv,
    manual: bool,
    notes: &mut Map<String, Value>,
) {
    let by_key: BTreeSet<(u16, u32)> = rc
        .syns
        .iter()
        .map(|y| (y.port, y.seq.wrapping_add(1)))
        .collect();
    let mine: Vec<&Reply> = rc
        .replies
        .iter()
        .filter(|p| by_key.contains(&(p.port, p.ack)))
        .collect();
    let (inside, after): (Vec<&Reply>, Vec<&Reply>) = if manual {
        (mine, vec![])
    } else {
        mine.into_iter().partition(|p| p.t <= rc.end)
    };
    if !after.is_empty() {
        notes.insert(
            "post_run_replies".into(),
            json!(
                after
                    .iter()
                    .map(|p| json!({"port":p.port,"open":p.open,"after_s":p.t - rc.end}))
                    .collect::<Vec<_>>()
            ),
        );
    }
    let answered: BTreeSet<String> = inside
        .iter()
        .map(|p| key(PEER_IP, p.port, p.open))
        .collect();
    let row_keys: Vec<String> = rows.iter().map(|w| key(&w.ip, w.port, w.open)).collect();
    let unbacked: Vec<&String> = row_keys.iter().filter(|k| !answered.contains(*k)).collect();
    r.beh(
        "every row has a wire reply with the same open flag",
        unbacked.is_empty(),
        format!("row without wire reply: {unbacked:?}"),
    );
    if manual {
        return;
    }
    let have: BTreeSet<&str> = row_keys.iter().map(String::as_str).collect();
    let missing: Vec<String> = inside
        .iter()
        .filter(|p| rc.exempt_after.is_none_or(|x| p.t <= x))
        .map(|p| key(PEER_IP, p.port, p.open))
        .filter(|k| !have.contains(k.as_str()))
        .filter(|k| !(k.ends_with(":closed") && answered_port_open(&answered, &have, k)))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    r.beh(
        "every genuine reply on the wire is a row (a missing RST is tolerated)",
        missing.is_empty(),
        format!("reply without row: {missing:?}"),
    );
}
fn open_ports_from_host(
    d: &Path,
    r: &mut Run,
    notes: &mut Map<String, Value>,
) -> Option<BTreeSet<u16>> {
    // A netstat that did not exit 0 is "not recorded", never "no host listeners".
    let rec = |n: &str| {
        text_in(d, n).filter(|t| {
            t.lines()
                .next()
                .is_none_or(|l| !l.starts_with("rc ") || l.trim() == "rc 0")
        })
    };
    let (Some(b), Some(a)) = (rec("host-listen-before.txt"), rec("host-listen-after.txt")) else {
        r.inv(
            "host listeners recorded before and after (wildcard listeners answer on 198.18.0.2)",
            false,
            "host-listen-before.txt or host-listen-after.txt missing",
        );
        return None;
    };
    let host: BTreeSet<u16> = verify::host_listen_ports(&b)
        .intersection(&verify::host_listen_ports(&a))
        .copied()
        .collect();
    notes.insert("host_listen_ports".into(), json!(host));
    Some(host)
}

// ------------------------------------------------------------------ the verifier

fn status_of(scan: &Value) -> &str {
    s(&scan["status"])
}
fn find_scan<'a>(h: &'a Value, id: &str) -> Option<&'a Value> {
    scans_of(h)
        .iter()
        .find(|x| s(&x["scan_id_hex"]) == id && !id.is_empty())
}
fn history_checks(r: &mut Run, scan: &Value) -> Vec<Row> {
    let rows = match rows_of(scan) {
        Ok(x) => x,
        Err(e) => {
            r.inv("history rows parse", false, e);
            return vec![];
        }
    };
    let mut seen = BTreeSet::new();
    let dup: Vec<_> = rows
        .iter()
        .filter(|w| !seen.insert((w.ip.clone(), w.port)))
        .map(|w| w.port)
        .collect();
    r.beh(
        "history rows have no duplicate (ip, port)",
        dup.is_empty(),
        format!("{dup:?}"),
    );
    let foreign: Vec<_> = rows
        .iter()
        .filter(|w| w.ip != PEER_IP)
        .map(|w| w.ip.clone())
        .collect();
    r.beh(
        "history rows are all 198.18.0.2",
        foreign.is_empty(),
        format!("{foreign:?}"),
    );
    rows
}
fn lab_open(ports: &[u16], host: &BTreeSet<u16>) -> BTreeSet<u16> {
    ports
        .iter()
        .copied()
        .filter(|p| LAB_OPEN_PORTS.contains(p) || host.contains(p))
        .collect()
}

/// Verifies the window directory `d`. `manual` is a window the operator drove by hand: no chronicle, no plan.
pub fn verify_dir(d: &Path, manual: bool) -> Value {
    verify_dir_expect(d, manual, None)
}
/// As `verify_dir`, and `expect_head` (the commit the window must have been taken on) binds `provenance.json`.
pub fn verify_dir_expect(d: &Path, manual: bool, expect_head: Option<&str>) -> Value {
    let (mut sr, safe, extra) = safety(d, expect_head);
    let mut notes = Map::new();
    let history = read_json(d.join("history.json"));
    let wire = safe.peer.as_ref().map_or_else(Wire::default, classify);
    let mut peer_ok = safe.peer_proven;
    let peer_present = d.join("peer.pcap").exists();
    let mut runs: Vec<(Run, Option<String>)> = vec![];
    if manual {
        runs.push((sr, None));
        manual_cases(
            d,
            history.as_ref(),
            &wire,
            peer_ok,
            peer_present,
            &mut runs,
            &mut notes,
        );
    } else {
        let (cr, smoke, chron) = chronicle_run(d);
        if let Some(c) = &chron {
            peer_ok &= coverage_checks(&mut sr, &safe.caps, c);
        } else {
            peer_ok = false;
        }
        runs.push((sr, None));
        runs.push((cr, None));
        planned_cases(
            d,
            history.as_ref(),
            smoke.as_ref(),
            chron.as_ref(),
            &wire,
            (peer_ok, peer_present),
            &mut runs,
            &mut notes,
        );
    }
    finish(runs, extra, notes, manual)
}
fn chronicle_run(d: &Path) -> (Run, Option<Value>, Option<Chronicle>) {
    let mut cr = run_of("chronicle");
    let smoke = read_json(d.join("smoke.json"));
    let Some(sm) = &smoke else {
        cr.add("smoke.json present", NOT_RUN, "missing or not JSON", false);
        return (cr, None, None);
    };
    let chron = load_chronicle(&mut cr, sm);
    if let Some(c) = &chron
        && !c.aborted_early
    {
        chronicle_checks(&mut cr, c);
    }
    (cr, smoke, chron)
}
/// The history of a hand-driven window: every scan settled, rows backed by the scanner's own SYNs and replies.
fn manual_cases(
    d: &Path,
    history: Option<&Value>,
    wire: &Wire,
    peer_ok: bool,
    peer_present: bool,
    runs: &mut Vec<(Run, Option<String>)>,
    notes: &mut Map<String, Value>,
) {
    notes.insert("manual".into(), json!(true));
    let mut r = run_of("history");
    let Some(h) = history else {
        r.add(
            "history.json present",
            NOT_RUN,
            "missing or not JSON",
            false,
        );
        runs.push((r, None));
        return;
    };
    let _ = d;
    for sc in scans_of(h) {
        let id = s(&sc["scan_id_hex"]);
        let mut rr = run_of(&format!("scan-{}", &id[..id.len().min(8)]));
        let st = status_of(sc);
        rr.beh(
            "history status is settled",
            matches!(
                st,
                "Completed" | "Stopped" | "Failed" | "Paused" | "Interrupted"
            ),
            st,
        );
        let rows = history_checks(&mut rr, sc);
        if peer_ok {
            let rc = Recv {
                syns: &wire.syns,
                replies: &wire.replies,
                end: f64::MAX,
                exempt_after: None,
            };
            results_checks(&mut rr, &rows, &rc, true, notes);
        } else {
            unproven(&mut rr, peer_present, "results need a proven peer capture");
        }
        runs.push((rr, Some(id.to_owned())));
    }
    if scans_of(h).is_empty() {
        r.beh("history lists a scan", false, "no scans");
        runs.push((r, None));
    }
    let mut wr = run_of("wire");
    if peer_ok {
        rogue_check(&mut wr, wire);
    } else {
        unproven(
            &mut wr,
            peer_present,
            "scanner frames need a proven peer capture",
        );
    }
    runs.push((wr, None));
}
fn rogue_check(r: &mut Run, wire: &Wire) {
    r.beh(
        "every unicast IPv4 frame from the scanner is a source-port-40000 SYN to 198.18.0.2",
        wire.rogue.is_empty(),
        format!("scanner frame outside the plan: {:?}", wire.rogue),
    );
}
/// A rule that cannot run: INVALID when a capture exists but is unproven, NOT RUN when it is simply missing.
fn unproven(r: &mut Run, captured: bool, name: &str) {
    r.add(name, if captured { INVALID } else { NOT_RUN }, "", false);
}

#[allow(clippy::too_many_arguments)]
fn planned_cases(
    d: &Path,
    history: Option<&Value>,
    smoke: Option<&Value>,
    chron: Option<&Chronicle>,
    wire: &Wire,
    (peer_ok, peer_present): (bool, bool),
    runs: &mut Vec<(Run, Option<String>)>,
    notes: &mut Map<String, Value>,
) {
    let (syns, replies) = (&wire.syns, &wire.replies);
    let host = {
        let mut r = run_of("host-listeners");
        let h = open_ports_from_host(d, &mut r, notes);
        if r.checks.iter().any(|c| c["result"] != PASS) {
            runs.push((r, None));
        }
        h
    };
    let record = |tag: &str| -> Option<&Value> {
        smoke.and_then(|sm| array(&sm["plan"]).iter().find(|p| s(&p["tag"]) == tag))
    };
    // The history holds exactly the planned scans.
    {
        let mut r = run_of("history");
        match history {
            None => r.add(
                "history.json present",
                NOT_RUN,
                "missing or not JSON",
                false,
            ),
            Some(_) if smoke.is_none() => {
                r.add("planned scans need smoke.json", NOT_RUN, "", false)
            }
            Some(h) => {
                let planned: BTreeSet<String> = CASES
                    .iter()
                    .filter_map(|c| record(c.tag))
                    .map(|p| s(&p["scan_id_hex"]).to_owned())
                    .collect();
                let got: Vec<String> = scans_of(h)
                    .iter()
                    .map(|x| s(&x["scan_id_hex"]).to_owned())
                    .collect();
                let got_set: BTreeSet<String> = got.iter().cloned().collect();
                r.beh(
                    "history holds exactly the planned scans (no other scan, none twice)",
                    got_set == planned && got.len() == planned.len(),
                    format!("planned {planned:?} history {got:?}"),
                );
            }
        }
        runs.push((r, None));
    }
    // Case landmarks first: windows need the neighbours.
    struct Marks {
        starting: Option<f64>,
        finished: Option<f64>,
    }
    let marks: Vec<Marks> = CASES
        .iter()
        .map(|c| {
            let tl = chron.and_then(|ch| case_timeline(ch, c.tag));
            let starting = tl
                .as_ref()
                .and_then(|t| t.states.iter().find(|e| e.status == "Starting"))
                .map(|e| e.utc);
            // The receive window ends at the terminal State the UI observed, not at a figure the UI wrote.
            let finished = tl
                .as_ref()
                .and_then(|t| {
                    t.states
                        .iter()
                        .rev()
                        .find(|e| TERMINAL.contains(&e.status.as_str()))
                })
                .map(|e| e.utc);
            Marks { starting, finished }
        })
        .collect();
    let mut claimed = vec![false; syns.len()];
    for (i, spec) in CASES.iter().enumerate() {
        let mut r = run_of(spec.tag);
        let rec = record(spec.tag);
        let id = rec
            .map(|p| s(&p["scan_id_hex"]).to_owned())
            .unwrap_or_default();
        let Some(rec) = rec else {
            r.add("chronicle has the case record", NOT_RUN, spec.tag, false);
            runs.push((r, None));
            continue;
        };
        let Some(tl) = chron.and_then(|ch| case_timeline(ch, spec.tag)) else {
            r.add(
                "the Start action of the case is in the chronicle",
                NOT_RUN,
                spec.tag,
                false,
            );
            runs.push((r, Some(id)));
            continue;
        };
        let m = &marks[i];
        let scan = history.and_then(|h| find_scan(h, &id));
        if history.is_some() {
            r.beh(
                "history has the scan of the case (by scan_id_hex)",
                scan.is_some(),
                &id,
            );
        }
        let job = spec_job(spec);
        r.beh(
            "chronicle job equals the plan",
            rec["job"] == job,
            rec["job"].to_string(),
        );
        let rows = scan.map(|sc| {
            r.beh(
                "history job equals the plan",
                sc["job"] == job,
                sc["job"].to_string(),
            );
            r.beh(
                &format!("history status is {}", spec.status),
                status_of(sc) == spec.status,
                status_of(sc),
            );
            history_checks(&mut r, sc)
        });
        if let Some(rows) = &rows {
            r.beh(
                "rows_seen of the chronicle equals the history rows",
                rec["rows_seen"].as_u64() == Some(rows.len() as u64),
                format!("rows_seen {} rows {}", rec["rows_seen"], rows.len()),
            );
        }
        if let Some(sc) = scan {
            r.beh(
                "chronicle finished_status equals the history status",
                s(&rec["finished_status"]) == status_of(sc),
                s(&rec["finished_status"]),
            );
            if spec.tag == "s2_pause" {
                r.beh(
                    "history detail is not empty",
                    !s(&sc["detail"]).is_empty(),
                    s(&sc["detail"]),
                );
            }
            if matches!(spec.tag, "s2_pause" | "s3_stop") {
                // `checkpoint_len` is the integer 0 (not null) for a cleared checkpoint.
                r.beh(
                    "history checkpoint_len is 0 and next_index is null (Started cleared them)",
                    sc["checkpoint_len"].as_u64() == Some(0) && sc["next_index"].is_null(),
                    format!(
                        "checkpoint_len {} next_index {}",
                        sc["checkpoint_len"], sc["next_index"]
                    ),
                );
            }
        }
        r.beh(
            "the case reached a terminal State (Studio did not hang)",
            m.finished.is_some(),
            "",
        );
        if let Some(f) = m.finished {
            r.inv(
                "chronicle finished_utc equals the terminal State (50 ms)",
                parse_utc(s(&rec["finished_utc"])).is_some_and(|x| (x - f).abs() <= 0.05),
                format!("{} vs state at {f:.3}", rec["finished_utc"]),
            );
        }
        // Wire.
        let (Some(starting), Some(finished)) = (m.starting, m.finished) else {
            r.add(
                "wire checks need the chronicle times of the case",
                NOT_RUN,
                "",
                false,
            );
            runs.push((r, Some(id)));
            continue;
        };
        if !peer_ok {
            unproven(
                &mut r,
                peer_present,
                "wire checks need a proven peer capture",
            );
            runs.push((r, Some(id)));
            continue;
        }
        let (lo, hi) = scan_window(
            starting,
            finished,
            i.checked_sub(1).and_then(|j| marks[j].finished),
            marks.get(i + 1).and_then(|n| n.starting),
        );
        let mut mine = vec![];
        for (k, y) in syns.iter().enumerate() {
            if y.t >= lo && y.t < hi {
                claimed[k] = true;
                mine.push(y);
            }
        }
        mine.sort_by(|a, b| a.t.total_cmp(&b.t));
        let mine_ports: Vec<u16> = mine.iter().map(|y| y.port).collect();
        let plan = match plan_ports_for_job(&job) {
            Ok(p) => p,
            Err(e) => {
                r.inv("plan rebuilt from the job", false, e);
                runs.push((r, Some(id)));
                continue;
            }
        };
        let mut uniq = BTreeSet::new();
        let dup: Vec<u16> = mine_ports
            .iter()
            .copied()
            .filter(|p| !uniq.insert(*p))
            .collect();
        r.beh(
            "exactly once: no port probed twice in the case",
            dup.is_empty(),
            format!("duplicates {dup:?}"),
        );
        if spec.status == "Completed" {
            r.beh(
                "SYN order equals the whole plan",
                mine_ports == plan,
                format!(
                    "plan {} SYN {}; first difference at {:?}",
                    plan.len(),
                    mine_ports.len(),
                    first_diff(&plan, &mine_ports)
                ),
            );
        } else {
            let n = mine_ports.len().min(plan.len());
            r.beh(
                "SYN order equals a prefix of the plan",
                mine_ports.len() <= plan.len() && mine_ports[..] == plan[..n],
                format!(
                    "SYN {} first difference at {:?}",
                    mine_ports.len(),
                    first_diff(&plan, &mine_ports)
                ),
            );
        }
        match spec.tag {
            "s2_pause" => pause_resume(&mut r, Some(rec), &tl, &mine, &plan),
            "s3_stop" => stop_checks(&mut r, Some(rec), &tl, &mine, finished),
            _ => {}
        }
        // Results against the wire, inside the case window.
        let exempt = (spec.status == "Stopped")
            .then(|| {
                tl.actions
                    .iter()
                    .find(|a| a.name == "Stop")
                    .map(|a| a.utc - STOP_REPLY_GRACE_S)
            })
            .flatten();
        let own: Vec<Syn> = mine
            .iter()
            .map(|y| Syn {
                t: y.t,
                port: y.port,
                seq: y.seq,
            })
            .collect();
        let case_replies: Vec<Reply> = replies
            .iter()
            .filter(|p| p.t >= lo)
            .map(|p| Reply {
                t: p.t,
                port: p.port,
                ack: p.ack,
                open: p.open,
            })
            .collect();
        if let Some(rows) = &rows {
            let rc = Recv {
                syns: &own,
                replies: &case_replies,
                end: finished,
                exempt_after: exempt,
            };
            let mut cn = Map::new();
            results_checks(&mut r, rows, &rc, false, &mut cn);
            if let Some(v) = cn.remove("post_run_replies") {
                notes.insert(format!("post_run_replies.{}", spec.tag), v);
            }
            if spec.tag == "s1_full"
                && let Some(host) = &host
            {
                let want = lab_open(&plan, host);
                let got: BTreeSet<u16> = rows.iter().filter(|w| w.open).map(|w| w.port).collect();
                r.beh(
                    "open rows are the lab listeners 8000-8007 plus host wildcard listeners",
                    got == want,
                    format!("want {want:?} got {got:?}"),
                );
            }
        }
        runs.push((r, Some(id)));
    }
    let strays = claimed.iter().filter(|c| !**c).count();
    let mut wr = run_of("wire");
    let all_times = marks
        .iter()
        .all(|m| m.starting.is_some() && m.finished.is_some());
    if !all_times {
        wr.add(
            "SYN outside the case windows needs the chronicle times of every case",
            NOT_RUN,
            "",
            false,
        );
    } else if !peer_ok {
        unproven(
            &mut wr,
            peer_present,
            "scanner frames need a proven peer capture",
        );
    } else {
        wr.beh(
            "no scanner SYN outside the windows of the cases",
            strays == 0,
            format!("{strays} SYN outside every case window"),
        );
        rogue_check(&mut wr, wire);
    }
    runs.push((wr, None));
}
fn first_diff(plan: &[u16], got: &[u16]) -> Option<usize> {
    (0..plan.len().max(got.len())).find(|&i| plan.get(i) != got.get(i))
}
fn pause_resume(r: &mut Run, rec: Option<&Value>, t: &CaseTimeline, mine: &[&Syn], plan: &[u16]) {
    let mut seq: Vec<&str> = vec![];
    for e in &t.states {
        if e.status != "Starting" && seq.last() != Some(&e.status.as_str()) {
            seq.push(&e.status);
        }
    }
    r.beh(
        "chronicle states are Scanning, Saving, Paused, Scanning, Completed",
        seq == ["Scanning", "Saving", "Paused", "Scanning", "Completed"],
        seq.join(" > "),
    );
    let pause = t.actions.iter().find(|a| a.name == "Pause");
    let resume = t.actions.iter().find(|a| a.name == "Resume");
    let paused = t.states.iter().find(|e| e.status == "Paused");
    if let (Some(p), Some(q)) = (pause, paused) {
        let ms = q.mono - p.mono;
        r.beh(
            "pause_to_paused_ms is at most 5000",
            (0..=PAUSE_TO_PAUSED_MAX_MS).contains(&ms),
            format!("{ms} ms from the Pause action to Paused"),
        );
        let recorded = rec.and_then(|x| x["pause_to_paused_ms"].as_i64());
        r.inv(
            "recorded pause_to_paused_ms equals the chronicle",
            recorded.is_some_and(|x| (x - ms).abs() <= 5),
            format!("recorded {recorded:?} chronicle {ms}"),
        );
    } else {
        r.beh(
            "Pause action and Paused state are in the chronicle",
            false,
            "",
        );
    }
    r.beh(
        "Paused carries the runner's checkpoint ACK text",
        paused.is_some_and(|e| e.detail == PAUSE_ACK_TEXT),
        paused.map_or(String::new(), |e| e.detail.clone()),
    );
    let k = rec.and_then(|x| x["paused_next_index"].as_u64());
    r.beh(
        "chronicle carries paused_next_index",
        k.is_some(),
        format!("{k:?}"),
    );
    let (Some(k), Some(resume)) = (k, resume) else {
        r.beh("Resume action is in the chronicle", resume.is_some(), "");
        return;
    };
    let k = k as usize;
    // A pause before the first probe, or after the last, did not exercise the checkpoint: it proves nothing.
    r.inv(
        "the pause split the probe stream (0 < paused_next_index < planned probes)",
        0 < k && k < plan.len(),
        format!("paused_next_index {k} of {} planned probes", plan.len()),
    );
    let first: Vec<u16> = mine
        .iter()
        .filter(|y| y.t < resume.utc)
        .map(|y| y.port)
        .collect();
    let second: Vec<u16> = mine
        .iter()
        .filter(|y| y.t >= resume.utc)
        .map(|y| y.port)
        .collect();
    r.beh(
        "SYN before the second Starting equal paused_next_index",
        first.len() == k,
        format!("first leg {} next_index {k}", first.len()),
    );
    r.beh(
        "first leg is the first k ports of the plan, second leg the rest",
        k <= plan.len() && first[..] == plan[..k] && second[..] == plan[k..],
        format!("legs {} + {} of {}", first.len(), second.len(), plan.len()),
    );
    let mut all: Vec<u16> = first.into_iter().chain(second).collect();
    all.sort_unstable();
    let mut want = plan.to_vec();
    want.sort_unstable();
    r.beh(
        "the two legs together have no gap and no duplicate",
        all == want,
        format!("{} probes for {} planned", all.len(), want.len()),
    );
}
fn stop_checks(r: &mut Run, rec: Option<&Value>, t: &CaseTimeline, mine: &[&Syn], finished: f64) {
    let stop = t.actions.iter().find(|a| a.name == "Stop");
    let stopped = t.states.iter().find(|e| e.status == "Stopped");
    if let (Some(a), Some(e)) = (stop, stopped) {
        let ms = e.mono - a.mono;
        r.beh(
            "stop_to_stopped_ms is at most 1000",
            (0..=STOP_TO_STOPPED_MAX_MS).contains(&ms),
            format!("{ms} ms from the Stop action to Stopped"),
        );
        let recorded = rec.and_then(|x| x["stop_to_stopped_ms"].as_i64());
        r.inv(
            "recorded stop_to_stopped_ms equals the chronicle",
            recorded.is_some_and(|x| (x - ms).abs() <= 5),
            format!("recorded {recorded:?} chronicle {ms}"),
        );
    } else {
        r.beh(
            "Stop action and Stopped state are in the chronicle",
            false,
            "",
        );
    }
    r.beh(
        "a stopped scan sent some, not all, probes (0 < SYN < 2000)",
        !mine.is_empty() && mine.len() < 2000,
        mine.len(),
    );
    let t_stopped = stopped.map_or(finished, |e| e.utc);
    let late: Vec<f64> = mine
        .iter()
        .filter(|y| y.t > t_stopped + STOP_SYN_GRACE_S)
        .map(|y| y.t - t_stopped)
        .collect();
    r.beh(
        "no SYN after Stopped (250 ms for the UI poll)",
        late.is_empty(),
        format!("{} SYN later than Stopped + 250 ms: {late:?}", late.len()),
    );
}

/// The shared precedence (`verify::finish`): a safety trip or a behaviour failure anywhere is FAIL and cannot be
/// downgraded by an unrelated unproven file; otherwise NOT RUN, then INVALID, then PASS only if everything passed.
fn finish(
    runs: Vec<(Run, Option<String>)>,
    extra: Value,
    notes: Map<String, Value>,
    manual: bool,
) -> Value {
    let summaries: Vec<Value> = runs
        .iter()
        .map(|(r, id)| {
            let mut v = r.summary();
            v["scan_id"] = json!(id);
            v
        })
        .collect();
    let res = verify::finish(json!({ "runs": summaries }));
    let cases: Vec<Value> = array(&res["runs"])
        .iter()
        .map(|c| {
            let checks: Vec<Value> = array(&c["checks"])
                .iter()
                .map(|k| {
                    json!({
                        "name": k["name"], "ok": k["result"] == PASS, "result": k["result"],
                        "detail": k["detail"], "behaviour": k["behaviour"] == true,
                        "safety": k["safety"] == true,
                    })
                })
                .collect();
            json!({"tag":c["tag"],"scan_id":c["scan_id"],"status":c["verdict"],"checks":checks})
        })
        .collect();
    let mut notes = notes;
    notes.insert("manual".into(), json!(manual));
    let prov = &extra["provenance"];
    let provenance = json!({
        "verifier_sha256": std::env::current_exe().ok().and_then(|e| fs::read(e).ok()).map(|b| sha(&b)),
        "window_sha": prov["git_head"],
        "ui_sha256": prov["ui_sha256"],
        "runner_sha256": prov["runner_sha256"],
        "installed_runner_sha256": prov["installed_runner_sha256"],
    });
    let t = &res["totals"];
    json!({
        "overall": res["overall"],
        "provenance": provenance,
        "isolation": extra["isolation"],
        "cases": cases,
        "totals": {"pass":t[PASS],"fail":t[FAIL],"invalid":t[INVALID],"not_run":t[NOT_RUN]},
        "behaviour_fail": res["behaviour_fail"],
        "safety_trips": res["safety_trips"],
        "notes": notes,
    })
}
/// 0 PASS, 1 FAIL, 2 INVALID or NOT RUN.
pub fn exit_code(verdict: &Value) -> i32 {
    match s(&verdict["overall"]) {
        PASS => 0,
        FAIL => 1,
        _ => 2,
    }
}

pub fn run(args: &[String]) -> Result<i32, String> {
    let manual = args.iter().any(|a| a == "--manual");
    let rest: Vec<String> = args.iter().filter(|a| *a != "--manual").cloned().collect();
    let o =
        crate::windows_suite::options_for("studio-verify", &rest, &["dir", "out", "expect-head"])?;
    if o.contains_key("help") {
        println!(
            "studio-verify --dir DIR --out FILE [--expect-head SHA] [--manual]  (exit 0 PASS, 1 FAIL, 2 INVALID or NOT RUN)"
        );
        return Ok(0);
    }
    let dir = crate::windows_suite::required(&o, "dir")?;
    let out = crate::windows_suite::required(&o, "out")?;
    if !Path::new(&dir).is_dir() {
        return Err(format!("--dir {dir} is not a directory"));
    }
    let head = o.get("expect-head").and_then(|v| v.first()).cloned();
    let res = verify_dir_expect(Path::new(&dir), manual, head.as_deref());
    fs::write(
        &out,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&res).map_err(|e| e.to_string())?
        ),
    )
    .map_err(|e| e.to_string())?;
    for c in array(&res["cases"]) {
        let bad: Vec<_> = array(&c["checks"])
            .iter()
            .filter(|k| k["result"] != PASS)
            .take(3)
            .map(|k| format!("{}: {}", s(&k["result"]), s(&k["name"])))
            .collect();
        println!("{:<8} {} {}", s(&c["status"]), s(&c["tag"]), bad.join("; "));
    }
    println!("overall: {} {}", s(&res["overall"]), res["totals"]);
    Ok(exit_code(&res))
}

#[cfg(test)]
#[path = "studio_verify_tests.rs"]
mod tests;
