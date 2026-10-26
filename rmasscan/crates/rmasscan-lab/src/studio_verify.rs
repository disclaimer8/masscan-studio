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
//! Window directory (written by `cargo xtask feth-acceptance`, see `rmasscan/docs/macos-feth-lab.md`):
//! `smoke.json history.json provenance.json status-pre.json status-post.json peer.pcap peer.err
//! uplink.pcap uplink.err hashes-before-copy.txt host-listen-before.txt host-listen-after.txt`, any
//! further file (listed in the hashes), and `data/` (SQLite, never hashed or read). `verdict.json` is
//! written by this verifier and is outside the hashes.
use crate::{
    macos_verify::has_compressed_capture,
    pcap::{self, Frames},
    verify::{self, FAIL, INVALID, NOT_RUN, PASS, Run, array, read_json, s, sha, tcp},
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
/// The scanner's SYNs and the peer's replies to the scanner (`198.18.0.2 -> 198.18.0.1`, dport 40000).
fn classify(frames: &Frames) -> (Vec<Syn>, Vec<Reply>) {
    let (mut syns, mut replies) = (vec![], vec![]);
    for (t, f) in frames {
        let Some(i) = tcp(f) else { continue };
        if pcap::is_syn(f)
            && i.sm == SCANNER_MAC
            && i.src == SCANNER_IP
            && i.dst == PEER_IP
            && i.sp == SOURCE_PORT
        {
            syns.push(Syn {
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
                replies.push(Reply {
                    t: *t,
                    port: i.sp,
                    ack: i.ack,
                    open: true,
                });
            } else if i.flags & 0x04 != 0 {
                replies.push(Reply {
                    t: *t,
                    port: i.sp,
                    ack: i.ack,
                    open: false,
                });
            }
        }
    }
    (syns, replies)
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
}
fn load_chronicle(r: &mut Run, sm: &Value) -> Option<Chronicle> {
    r.inv(
        "smoke.json schema 1",
        sm["schema"] == 1,
        sm["schema"].to_string(),
    );
    let result = s(&sm["result"]);
    if result == "ok" {
        r.add("smoke.json result is ok", PASS, "ok", true);
    } else if result.starts_with("timeout") {
        r.add("smoke.json result is ok", INVALID, result, false);
    } else {
        r.beh("smoke.json result is ok", false, result);
    }
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
    Some(Chronicle { events, actions })
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

struct Window {
    peer: Option<Frames>,
    peer_stats: Option<TcpdumpStats>,
}
fn text_in(dir: &Path, name: &str) -> Option<String> {
    fs::read_to_string(dir.join(name)).ok()
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
        if h.len() != 64
            || !h.bytes().all(|b| b.is_ascii_hexdigit())
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
            Err(_) => {}
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
fn provenance_checks(r: &mut Run, d: &Path) -> Value {
    let Some(p) = read_json(d.join("provenance.json")) else {
        r.add(
            "provenance.json present",
            NOT_RUN,
            "missing or not JSON",
            false,
        );
        return Value::Null;
    };
    let (run, inst) = (s(&p["runner_sha256"]), s(&p["installed_runner_sha256"]));
    r.inv(
        "bundle runner hash equals the installed runner hash",
        run.len() == 64 && run == inst,
        format!("bundle {run} installed {inst}"),
    );
    r.inv(
        "working tree was clean (dirty is false)",
        p["dirty"] == false,
        p["dirty"].to_string(),
    );
    p
}
fn safety(d: &Path) -> (Run, Window, Value) {
    let mut r = Run::new("safety");
    r.argv_ok = true;
    r.safety(
        "no compressed capture in the window directory",
        !has_compressed_capture(d),
        "compressed capture is not allowed; store captures uncompressed",
    );
    let peer = d
        .join("peer.pcap")
        .exists()
        .then(|| verify::load_pcap(&mut r, &d.join("peer.pcap")))
        .flatten()
        .map(|x| x.0);
    if peer.is_none() && !d.join("peer.pcap").exists() {
        r.add("peer.pcap present", NOT_RUN, "missing", false);
    }
    let uplink = d
        .join("uplink.pcap")
        .exists()
        .then(|| verify::load_pcap(&mut r, &d.join("uplink.pcap")))
        .flatten()
        .map(|x| x.0);
    if uplink.is_none() && !d.join("uplink.pcap").exists() {
        r.add("uplink.pcap present", NOT_RUN, "missing", false);
    }
    let stats = |name: &str| text_in(d, name).as_deref().and_then(parse_tcpdump_stats);
    let (peer_stats, uplink_stats) = (stats("peer.err"), stats("uplink.err"));
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
    r.inv(
        "peer.err has tcpdump's exit statistics (clean exit)",
        peer_stats.is_some(),
        "",
    );
    if let (Some(p), Some(fr)) = (peer_stats, peer.as_ref()) {
        r.inv(
            "peer capture complete: captured equals the pcap frames, 0 kernel drops",
            p.captured == fr.len() as u64 && p.dropped_kernel == 0,
            format!(
                "captured {} frames {} dropped {}",
                p.captured,
                fr.len(),
                p.dropped_kernel
            ),
        );
    }
    let (pre, post) = status_checks(&mut r, d);
    hashes_check(&mut r, d);
    let prov = provenance_checks(&mut r, d);
    let isolation = json!({
        "uplink_frames": uplink.as_ref().map(Vec::len),
        "uplink_captured": uplink_stats.map(|u| u.captured),
        "uplink_dropped": uplink_stats.map(|u| u.dropped_kernel),
        "status_pre": pre,
        "status_post": post,
    });
    (
        r,
        Window { peer, peer_stats },
        json!({"provenance":prov,"isolation":isolation}),
    )
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
/// Rows against the replies on the wire. A reply answers a SYN of the case when it comes from that SYN's port with
/// `ack == seq + 1`. Every row must be backed by such a reply with the same open flag; every such reply inside the
/// receive window must be a row. A SYN with no reply is fine (closed-port RSTs are rate-limited), a reply with
/// no row is not. Replies after the window (listener teardown) are only noted.
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
    let wire: BTreeSet<(u16, bool)> = inside.iter().map(|p| (p.port, p.open)).collect();
    let unbacked: Vec<String> = rows
        .iter()
        .filter(|w| !wire.contains(&(w.port, w.open)))
        .map(|w| format!("{}:{}", w.port, if w.open { "open" } else { "closed" }))
        .collect();
    r.beh(
        "every row has a wire reply with the same open flag",
        unbacked.is_empty(),
        format!("row without wire reply: {unbacked:?}"),
    );
    if manual {
        return;
    }
    let have: BTreeSet<(u16, bool)> = rows.iter().map(|w| (w.port, w.open)).collect();
    let missing: Vec<String> = inside
        .iter()
        .filter(|p| rc.exempt_after.is_none_or(|x| p.t <= x))
        .filter(|p| !have.contains(&(p.port, p.open)))
        .map(|p| format!("{}:{}", p.port, if p.open { "SYN-ACK" } else { "RST" }))
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
    let (sr, win, extra) = safety(d);
    let mut runs: Vec<(Run, Option<String>)> = vec![(sr, None)];
    let mut notes = Map::new();
    if manual {
        notes.insert("manual".into(), json!(true));
    }
    let history = read_json(d.join("history.json"));
    let (peer_syns, peer_replies) = win.peer.as_ref().map_or((vec![], vec![]), classify);
    let peer_ok = win.peer.is_some() && win.peer_stats.is_some();
    if manual {
        let mut r = Run::new("history");
        r.argv_ok = true;
        match &history {
            None => r.add(
                "history.json present",
                NOT_RUN,
                "missing or not JSON",
                false,
            ),
            Some(h) => {
                for sc in scans_of(h) {
                    let mut rr = Run::new(&format!(
                        "scan-{}",
                        &s(&sc["scan_id_hex"])[..s(&sc["scan_id_hex"]).len().min(8)]
                    ));
                    rr.argv_ok = true;
                    let st = status_of(sc);
                    rr.beh(
                        "history status is settled",
                        matches!(st, "Completed" | "Stopped" | "Failed" | "Paused"),
                        st,
                    );
                    let rows = history_checks(&mut rr, sc);
                    if peer_ok {
                        let rc = Recv {
                            syns: &peer_syns,
                            replies: &peer_replies,
                            end: f64::MAX,
                            exempt_after: None,
                        };
                        results_checks(&mut rr, &rows, &rc, true, &mut notes);
                    } else {
                        unproven(&mut rr, d, "results need a complete peer capture");
                    }
                    runs.push((rr, Some(s(&sc["scan_id_hex"]).to_owned())));
                }
                if scans_of(h).is_empty() {
                    r.beh("history lists a scan", false, "no scans");
                }
            }
        }
        if !r.checks.is_empty() {
            runs.push((r, None));
        }
    } else {
        planned_cases(
            d,
            history.as_ref(),
            &peer_syns,
            &peer_replies,
            peer_ok,
            &mut runs,
            &mut notes,
        );
    }
    finish(runs, extra, notes, manual)
}

#[allow(clippy::too_many_arguments)]
fn planned_cases(
    d: &Path,
    history: Option<&Value>,
    syns: &[Syn],
    replies: &[Reply],
    peer_ok: bool,
    runs: &mut Vec<(Run, Option<String>)>,
    notes: &mut Map<String, Value>,
) {
    let mut cr = Run::new("chronicle");
    cr.argv_ok = true;
    let smoke = read_json(d.join("smoke.json"));
    let chron = match &smoke {
        None => {
            cr.add("smoke.json present", NOT_RUN, "missing or not JSON", false);
            None
        }
        Some(sm) => load_chronicle(&mut cr, sm),
    };
    if let Some(c) = &chron {
        chronicle_checks(&mut cr, c);
    }
    runs.push((cr, None));
    let host = {
        let mut r = Run::new("host-listeners");
        r.argv_ok = true;
        let h = open_ports_from_host(d, &mut r, notes);
        if r.checks.iter().any(|c| c["result"] != PASS) {
            runs.push((r, None));
        }
        h
    };
    // Case landmarks first: windows need the neighbours.
    struct Marks {
        starting: Option<f64>,
        finished: Option<f64>,
    }
    let marks: Vec<Marks> = CASES
        .iter()
        .map(|c| {
            let rec = smoke
                .as_ref()
                .and_then(|sm| array(&sm["plan"]).iter().find(|p| s(&p["tag"]) == c.tag));
            let tl = chron.as_ref().and_then(|ch| case_timeline(ch, c.tag));
            let starting = tl
                .as_ref()
                .and_then(|t| t.states.iter().find(|e| e.status == "Starting"))
                .map(|e| e.utc);
            let finished = rec.and_then(|p| parse_utc(s(&p["finished_utc"])));
            Marks { starting, finished }
        })
        .collect();
    let mut claimed = vec![false; syns.len()];
    for (i, spec) in CASES.iter().enumerate() {
        let mut r = Run::new(spec.tag);
        r.argv_ok = true;
        let rec = smoke
            .as_ref()
            .and_then(|sm| array(&sm["plan"]).iter().find(|p| s(&p["tag"]) == spec.tag));
        let id = rec
            .map(|p| s(&p["scan_id_hex"]).to_owned())
            .unwrap_or_default();
        let tl = chron.as_ref().and_then(|ch| case_timeline(ch, spec.tag));
        let m = &marks[i];
        let scan = history.and_then(|h| find_scan(h, &id));
        r.beh("chronicle has the case record", rec.is_some(), spec.tag);
        r.beh(
            "history has the scan of the case (by scan_id_hex)",
            scan.is_some(),
            &id,
        );
        let job = spec_job(spec);
        if let Some(p) = rec {
            r.beh(
                "chronicle job equals the plan",
                p["job"] == job,
                p["job"].to_string(),
            );
        }
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
        if let (Some(rows), Some(p)) = (&rows, rec) {
            r.beh(
                "rows_seen of the chronicle equals the history rows",
                p["rows_seen"].as_u64() == Some(rows.len() as u64),
                format!("rows_seen {} rows {}", p["rows_seen"], rows.len()),
            );
        }
        if let (Some(p), Some(sc)) = (rec, scan) {
            r.beh(
                "chronicle finished_status equals the history status",
                s(&p["finished_status"]) == status_of(sc),
                s(&p["finished_status"]),
            );
        }
        if let Some(sc) = scan
            && spec.tag == "s2_pause"
        {
            r.beh(
                "history detail is not empty",
                !s(&sc["detail"]).is_empty(),
                s(&sc["detail"]),
            );
        }
        if let Some(sc) = scan
            && matches!(spec.tag, "s2_pause" | "s3_stop")
        {
            r.beh(
                "history checkpoint_len is 0 and next_index is null (Started cleared them)",
                sc["checkpoint_len"] == 0 && sc["next_index"].is_null(),
                format!(
                    "checkpoint_len {} next_index {}",
                    sc["checkpoint_len"], sc["next_index"]
                ),
            );
        }
        // Wire.
        let (Some(starting), Some(finished), true) = (m.starting, m.finished, peer_ok) else {
            unproven(
                &mut r,
                d,
                "wire checks need the chronicle times and a complete peer capture",
            );
            runs.push((r, Some(id)));
            continue;
        };
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
        let plan = plan_ports_for_job(&job);
        let plan = match plan {
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
        match (spec.tag, &tl) {
            ("s2_pause", Some(t)) => pause_resume(&mut r, rec, t, &mine, &plan),
            ("s3_stop", Some(t)) => stop_checks(&mut r, rec, t, &mine, finished),
            _ => {}
        }
        // Results against the wire, inside the case window.
        let exempt = (spec.status == "Stopped")
            .then(|| {
                tl.as_ref()
                    .and_then(|t| t.actions.iter().find(|a| a.name == "Stop"))
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
    let mut wr = Run::new("wire");
    wr.argv_ok = true;
    if peer_ok
        && marks
            .iter()
            .all(|m| m.starting.is_some() && m.finished.is_some())
    {
        wr.beh(
            "no scanner SYN outside the windows of the cases",
            strays == 0,
            format!("{strays} SYN outside every case window"),
        );
    } else {
        unproven(
            &mut wr,
            d,
            "SYN outside the case windows needs chronicle times and a complete peer capture",
        );
    }
    runs.push((wr, None));
}
/// A rule that cannot run: INVALID when a capture exists but is unproven, NOT RUN when something is simply missing.
fn unproven(r: &mut Run, d: &Path, name: &str) {
    let captured = d.join("peer.pcap").exists();
    r.add(name, if captured { INVALID } else { NOT_RUN }, "", false);
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

fn finish(
    runs: Vec<(Run, Option<String>)>,
    extra: Value,
    notes: Map<String, Value>,
    manual: bool,
) -> Value {
    let mut totals = BTreeMap::from([(PASS, 0u32), (FAIL, 0), (INVALID, 0), (NOT_RUN, 0)]);
    let mut overall = PASS;
    let mut safety_trip = false;
    let mut cases = vec![];
    for (r, id) in &runs {
        let v = r.verdict();
        safety_trip |= r.safety_trip();
        *totals.entry(v_static(v)).or_default() += 1;
        // Precedence of the macOS verifier: NOT RUN, then INVALID, then FAIL, then PASS.
        for w in [NOT_RUN, INVALID, FAIL, PASS] {
            if v == w {
                if rank(w) < rank(overall) {
                    overall = w;
                }
                break;
            }
        }
        let checks: Vec<Value> = r
            .checks
            .iter()
            .map(|c| json!({"name":c["name"],"ok":c["result"]==PASS,"result":c["result"],"detail":c["detail"]}))
            .collect();
        cases.push(json!({"tag":r.tag,"scan_id":id,"status":v,"checks":checks}));
    }
    if safety_trip {
        overall = FAIL;
    }
    let mut notes = notes;
    notes.insert("manual".into(), json!(manual));
    let mut provenance = extra["provenance"].clone();
    let p = |k: &str| provenance[k].clone();
    let prov = json!({
        "verifier_sha256": std::env::current_exe().ok().and_then(|e| fs::read(e).ok()).map(|b| sha(&b)),
        "window_sha": if p("git_head").is_null() { p("window_sha") } else { p("git_head") },
        "ui_sha256": p("ui_sha256"),
        "runner_sha256": p("runner_sha256"),
        "installed_runner_sha256": p("installed_runner_sha256"),
    });
    provenance = prov;
    json!({
        "overall": overall,
        "provenance": provenance,
        "isolation": extra["isolation"],
        "cases": cases,
        "totals": {"pass":totals[PASS],"fail":totals[FAIL],"invalid":totals[INVALID],"not_run":totals[NOT_RUN]},
        "notes": notes,
    })
}
fn rank(v: &str) -> u8 {
    match v {
        NOT_RUN => 0,
        INVALID => 1,
        FAIL => 2,
        _ => 3,
    }
}
fn v_static(v: &str) -> &'static str {
    match v {
        PASS => PASS,
        FAIL => FAIL,
        INVALID => INVALID,
        _ => NOT_RUN,
    }
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
    let o = crate::windows_suite::options_for("studio-verify", &rest, &["dir", "out"])?;
    if o.contains_key("help") {
        println!(
            "studio-verify --dir DIR --out FILE [--manual]  (exit 0 PASS, 1 FAIL, 2 INVALID or NOT RUN)"
        );
        return Ok(0);
    }
    let dir = crate::windows_suite::required(&o, "dir")?;
    let out = crate::windows_suite::required(&o, "out")?;
    if !Path::new(&dir).is_dir() {
        return Err(format!("--dir {dir} is not a directory"));
    }
    let res = verify_dir(Path::new(&dir), manual);
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
