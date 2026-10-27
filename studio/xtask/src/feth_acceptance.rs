//! `cargo xtask feth-acceptance`: the orchestrator of one live Studio window on the sealed Mac `feth` stand.
//!
//! It checks the gates, starts the two independent `tcpdump` witnesses and `peer listen`, runs the packaged
//! `studio-ui --smoke-feth` against the installed and authorized runner, dumps the SQLite history through
//! `studio-store` after the UI exited, and writes the files that `rmasscan-lab studio-verify` judges (the contract is
//! "Studio acceptance" in `rmasscan/docs/macos-feth-lab.md`). It sends no frame, reads no pcap and never runs `sudo`:
//! whatever needs root is printed as a command for the user and the run ends as NOT RUN (rc 2).
//!
//! Exit codes: 0 window closed and clean, 2 NOT RUN (nothing ran), 10 abort or an unclean window (directory kept),
//! 13 isolation breach (a lab frame on the uplink).
#![forbid(unsafe_code)]
use super::Result;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use studio_protocol::id_text;
use studio_store::{SavedRow, SavedScan, Store};

pub const RUN_ID: &str = "m1";
pub const PEER_IF: &str = "feth4202";
const SCANNER_IF: &str = "feth4201";
/// The exact filter of `macos_lab::UPLINK_FILTER` (the verifier pins the same text).
pub const UPLINK_FILTER: &str = "net 198.18.0.0/30 or (arp and (host 198.18.0.1 or host 198.18.0.2)) or ether host 02:ac:00:00:00:01 or ether host 02:ac:00:00:00:02 or ether proto 0x88b5";
pub const ALF_TEXT: &str = "Firewall is disabled. (State = 0)";
/// A pcap holding no frame is exactly its global header.
const PCAP_HEADER: u64 = 24;
/// The peer witness drops only the host's own mDNS (it announces the host name on the peer interface).
pub const PEER_FILTER: &str = "not (ether src 02:ac:00:00:00:02 and udp port 5353)";
const TCPDUMP: &str = "/usr/sbin/tcpdump";
/// 420 s smoke deadline of the UI plus a minute.
const UI_SECONDS: u64 = 480;
const MANUAL_SECONDS: u64 = 2 * 60 * 60;
const DRY_SECONDS: u64 = 120;
const POLL_MS: u64 = 250;

// ------------------------------------------------------------------ options

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opts {
    pub out: PathBuf,
    pub app: PathBuf,
    pub lab: PathBuf,
    pub manual: bool,
    pub dry_run: bool,
}

const USAGE: &str = "Usage: cargo xtask feth-acceptance --out DIR --app '/abs/Masscan Studio.app' --lab /abs/rmasscan-lab [--manual] [--dry-run]";

pub fn parse_args(args: &[String]) -> std::result::Result<Opts, String> {
    let (mut out, mut app, mut lab) = (None, None, None);
    let (mut manual, mut dry_run) = (false, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |slot: &mut Option<PathBuf>| match it.next() {
            Some(v) if !v.is_empty() => {
                *slot = Some(PathBuf::from(v));
                Ok(())
            }
            _ => Err(format!("{a} needs a value. {USAGE}")),
        };
        match a.as_str() {
            "--out" => value(&mut out)?,
            "--app" => value(&mut app)?,
            "--lab" => value(&mut lab)?,
            "--manual" => manual = true,
            "--dry-run" => dry_run = true,
            other => return Err(format!("unknown argument {other}. {USAGE}")),
        }
    }
    let (Some(out), Some(app), Some(lab)) = (out, app, lab) else {
        return Err(USAGE.into());
    };
    for (name, p) in [("--out", &out), ("--app", &app), ("--lab", &lab)] {
        if !p.is_absolute() {
            return Err(format!("{name} must be an absolute path. {USAGE}"));
        }
    }
    if manual && dry_run {
        return Err(format!(
            "--manual and --dry-run exclude each other. {USAGE}"
        ));
    }
    Ok(Opts {
        out,
        app,
        lab,
        manual,
        dry_run,
    })
}

// ------------------------------------------------------------------ pure parts

/// Single-quote a word for the Terminal lines printed for the user.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Replaces personal paths in text before it is written, so that the hashes taken afterwards stay valid.
/// `rules` are applied in order (longest path first).
pub fn scrub(text: &str, rules: &[(String, String)]) -> String {
    let mut s = text.to_owned();
    for (from, to) in rules {
        if from.len() > 1 {
            s = s.replace(from.as_str(), to);
        }
    }
    s
}

pub fn utc_text(secs: u64, millis: u32) -> String {
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// What `status-pre.json` says about the stand.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StatusVerdict {
    pub uplink: Option<String>,
    pub reasons: Vec<String>,
    /// `up` is needed (no sealed stand recorded).
    pub stand_missing: bool,
    /// `bpf-access --grant` is needed.
    pub grant_missing: bool,
}

/// `macos-lab status` before the window: rc 0, `raw_run_allowed: true`, `bpf_access: "granted"`, an uplink that is
/// not a `feth*` interface.
pub fn status_pre(rc: i32, text: &str) -> StatusVerdict {
    let mut v = StatusVerdict::default();
    let json = serde_json::from_str::<Value>(text).ok();
    let Some(j) = json.filter(Value::is_object) else {
        v.stand_missing = true;
        v.reasons.push(format!(
            "macos-lab status gave no JSON (rc {rc}): no sealed stand '{RUN_ID}' is recorded"
        ));
        return v;
    };
    // `up` is needed only when no stand is recorded (the manifest check fails); a recorded stand that fails
    // other checks has drifted and `up` would refuse it.
    let manifest_ok = j["checks"]
        .as_array()
        .is_some_and(|c| c.iter().any(|x| x["name"] == "manifest" && x["ok"] == true));
    v.stand_missing = !manifest_ok;
    if rc != 0 {
        v.reasons.push(format!(
            "macos-lab status exited rc {rc} (rc 3: a check failed)"
        ));
    }
    if manifest_ok && j["raw_run_allowed"] != true {
        v.reasons.push(
            "the recorded stand has drifted (a check other than the manifest fails): take it down (user action F) and bring it up again; `up` is not offered for a recorded stand"
                .into(),
        );
    }
    if j["raw_run_allowed"] != true {
        let failed: Vec<String> = j["checks"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["ok"] != true)
            .map(|c| {
                format!(
                    "{}: {}",
                    c["name"].as_str().unwrap_or("?"),
                    c["detail"].as_str().unwrap_or("")
                )
            })
            .collect();
        v.reasons.push(format!(
            "status raw_run_allowed is not true; failed checks: {failed:?}"
        ));
    }
    let bpf = j["bpf_access"].as_str().unwrap_or("");
    if bpf != "granted" {
        v.grant_missing = true;
        v.reasons
            .push(format!("status bpf_access is {bpf:?}, not \"granted\""));
    }
    match j["uplink"].as_str() {
        Some(u) if !u.is_empty() && !u.starts_with("feth") => v.uplink = Some(u.to_owned()),
        other => v.reasons.push(format!(
            "status uplink {other:?} is not a real default-route interface"
        )),
    }
    v
}

pub fn status_post_allowed(text: &str) -> bool {
    serde_json::from_str::<Value>(text).is_ok_and(|j| j["raw_run_allowed"] == true)
}

pub fn firewall_ok(text: &str) -> bool {
    text.trim() == ALF_TEXT
}

/// A process line of `ps` that is left over from an earlier run, or is Studio's own binary.
pub fn is_leftover_proc(line: &str, own: &[u32]) -> bool {
    // Only this orchestrator and its `cargo xtask` parent are exempt; a second orchestrator is a leftover.
    let pid = line
        .split_whitespace()
        .next()
        .and_then(|p| p.parse::<u32>().ok());
    if line.contains("feth-acceptance") && pid.is_some_and(|p| own.contains(&p)) {
        return false;
    }
    line.contains("wire_scan")
        || (line.contains("tcpdump") && (line.contains("feth420") || line.contains("uplink.pcap")))
        || line.contains("peer listen")
        || line.contains("capture dump")
        || line.contains("studio-ui")
        || line.contains("studio-runner")
}

/// The matching lines of `ps -axo pid=,command=` (empty text means nothing is left over).
pub fn leftover_procs(ps: &str, own: &[u32]) -> String {
    let mut out = String::new();
    for l in ps.lines().filter(|l| is_leftover_proc(l, own)) {
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// After a dry run: Studio's binaries, and the command line of an administrator dialog.
pub fn dry_leftover_procs(ps: &str) -> String {
    let mut out = String::new();
    for l in ps.lines().filter(|l| {
        !l.contains("feth-acceptance")
            && (l.contains("studio-ui")
                || l.contains("studio-runner")
                || l.contains("with administrator privileges"))
    }) {
        out.push_str(l);
        out.push('\n');
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
pub struct PairQuiet {
    pub ok: bool,
    pub report: String,
}

/// `samples` are consecutive `netstat -I ... -b -d -n` snapshots of both pair interfaces, 1 s apart. The window
/// between two neighbours is "moved" when the text differs. Refuses only when every window moved (or a sample is
/// unreadable).
pub fn pair_quiet(samples: &[String]) -> PairQuiet {
    let mut report = String::new();
    if samples.len() < 2 || samples.iter().any(|s| s.trim().is_empty()) {
        report.push_str("unreadable counters: a snapshot is empty or fewer than two were taken\n");
        return PairQuiet { ok: false, report };
    }
    let moved: Vec<bool> = samples.windows(2).map(|w| w[0] != w[1]).collect();
    for (i, m) in moved.iter().enumerate() {
        report.push_str(&format!(
            "window {} (1 s): {}\n",
            i + 1,
            if *m { "moved" } else { "quiet" }
        ));
    }
    let ok = moved.iter().any(|m| !m);
    report.push_str(if ok {
        "ok: the pair was quiet in at least one window\n"
    } else {
        "refused: the pair counters moved in every window\n"
    });
    PairQuiet { ok, report }
}

/// `N packet(s) captured` and `N packet(s) dropped by kernel` of tcpdump's exit statistics.
pub fn tcpdump_stats(err: &str) -> Option<(u64, u64)> {
    let find = |tail: &str| {
        err.lines().find_map(|l| {
            let l = l.trim();
            let (n, rest) = l.split_once(' ')?;
            let n = n.parse::<u64>().ok()?;
            let rest = rest
                .strip_prefix("packets ")
                .or_else(|| rest.strip_prefix("packet "))?;
            (rest == tail).then_some(n)
        })
    };
    Some((find("captured")?, find("dropped by kernel")?))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Interlock {
    Clean,
    Breach(String),
    Unproven(String),
}

/// The uplink interlock without reading the pcap: tcpdump's statistics and the size of the file.
pub fn interlock(uplink_err: &str, pcap_len: Option<u64>) -> Interlock {
    let stats = tcpdump_stats(uplink_err);
    let mut why = Vec::new();
    if let Some((captured, dropped)) = stats {
        if captured > 0 {
            why.push(format!("{captured} packets captured on the uplink"));
        }
        if dropped > 0 {
            why.push(format!("{dropped} packets dropped by kernel on the uplink"));
        }
    }
    if pcap_len.is_some_and(|n| n > PCAP_HEADER) {
        why.push(format!(
            "uplink.pcap holds {} bytes, more than the {PCAP_HEADER}-byte header",
            pcap_len.unwrap_or(0)
        ));
    }
    if !why.is_empty() {
        return Interlock::Breach(why.join("; "));
    }
    if stats.is_none() {
        return Interlock::Unproven("uplink.err has no tcpdump exit statistics".into());
    }
    if pcap_len != Some(PCAP_HEADER) {
        return Interlock::Unproven(format!(
            "uplink.pcap is {pcap_len:?} bytes, expected exactly the {PCAP_HEADER}-byte header"
        ));
    }
    Interlock::Clean
}

pub fn capture_argv(iface: &str, pcap: &str, filter: Option<&str>) -> Vec<String> {
    let mut v: Vec<String> = [
        TCPDUMP, "-p", "-n", "-U", "-s", "0", "-i", iface, "-w", pcap,
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    if let Some(f) = filter {
        v.push(f.to_owned());
    }
    v
}

pub fn cmd_record(
    argv: &[String],
    iface: &str,
    filter: &str,
    start: &str,
    stop: &str,
    exit_code: i32,
    listening: bool,
) -> Value {
    json!({"cmd":argv,"interface":iface,"filter":filter,"start_utc":start,"stop_utc":stop,"exit_code":exit_code,"listening":listening})
}

/// The runner of the bundle must be installed, byte for byte, before the UI starts. `installed` is the sha256 of
/// the bytes of the installed file (`None` when it is absent or unreadable).
pub fn check_installed(
    bundle_hash: &str,
    installed: Option<&str>,
) -> std::result::Result<(), String> {
    match installed {
        None => Err(format!(
            "the runner of this exact bundle ({bundle_hash}) is not installed under /Library/PrivilegedHelperTools/MasscanStudio/: install the runner of this exact bundle first"
        )),
        Some(h) if h != bundle_hash => Err(format!(
            "the installed runner bytes ({h}) differ from the bundle's runner ({bundle_hash}): install the runner of this exact bundle first"
        )),
        Some(_) => Ok(()),
    }
}

/// Action B for the user: one Terminal line, only the pieces that are missing.
pub fn user_action_b(
    exe: &str,
    runner_dir: Option<&str>,
    lab: &str,
    up: bool,
    grant: bool,
) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(d) = runner_dir {
        parts.push(format!("{} install-runner {}", sh_quote(exe), sh_quote(d)));
    }
    if up {
        parts.push(format!(
            "sudo {} macos-lab up --run-id {RUN_ID}",
            sh_quote(lab)
        ));
    }
    if grant {
        parts.push(format!(
            "sudo {} macos-lab bpf-access --run-id {RUN_ID} --grant",
            sh_quote(lab)
        ));
    }
    (!parts.is_empty()).then(|| parts.join(" && "))
}

/// Action F: the end of the window (it also takes the BPF grant back).
pub fn user_action_f(lab: &str) -> String {
    format!("sudo {} macos-lab down --run-id {RUN_ID}", sh_quote(lab))
}

/// Apple's SQLite keeps `-wal`/`-shm` after close, which makes a window INVALID.
pub fn links_apple_sqlite(otool: &str) -> bool {
    otool
        .lines()
        .any(|l| l.trim_start().starts_with("/usr/lib/libsqlite3"))
}

const SQLITE_HINT: &str = "rebuild with the Homebrew SQLite: SQLITE3_LIB_DIR=/opt/homebrew/opt/sqlite/lib (the bundle: `cd studio && SQLITE3_LIB_DIR=/opt/homebrew/opt/sqlite/lib cargo xtask build --release`; this orchestrator: run it as `SQLITE3_LIB_DIR=/opt/homebrew/opt/sqlite/lib cargo xtask feth-acceptance ...` after `touch xtask/src/main.rs`, or build xtask with that variable)";

/// The bundle must come from the commit that is recorded as `git_head`. Returns the manifest's dirty flag
/// (information only: the build counts untracked files, the verifier's `dirty` does not).
pub fn check_bundle_manifest(text: Option<&str>, head: &str) -> std::result::Result<bool, String> {
    let Some(text) = text else {
        return Err(
            "manifest.json next to the .app is missing: the bundle cannot be bound to the git HEAD"
                .into(),
        );
    };
    let j: Value = serde_json::from_str(text)
        .map_err(|e| format!("manifest.json next to the .app is not JSON: {e}"))?;
    let Some(commit) = j["source_commit"].as_str() else {
        return Err("manifest.json has no source_commit".into());
    };
    if commit != head {
        return Err(format!(
            "bundle manifest source_commit {commit} differs from the git HEAD {head}: rebuild the bundle from HEAD"
        ));
    }
    Ok(j["dirty"] == true)
}

/// lsof exits 0 or 1; anything else (it could not run) is not "no listeners".
/// lsof run as the user sees only the user's own sockets and can be blinded without any message, so an empty
/// result proves nothing; it is extra information. A listener it does show is a finding.
pub fn lsof_ok(rc: i32) -> bool {
    matches!(rc, 0 | 1)
}

fn lines_text(v: &[String]) -> String {
    v.iter().map(|l| format!("{l}\n")).collect()
}

/// Leftover lab listeners in `lsof -nP -iTCP -sTCP:LISTEN` output: a LISTEN on `198.18.0.2:<port>` or on
/// `*:<port>` for a lab port. Other addresses (127.0.0.1) and other ports are not leftovers.
pub fn lsof_leftovers(lsof: &str) -> Vec<String> {
    lsof.lines()
        .filter(|l| l.contains("(LISTEN)"))
        .filter(|l| {
            let mut t = l.split_whitespace().skip_while(|w| *w != "TCP");
            let Some((addr, port)) = t.nth(1).and_then(|a| a.rsplit_once(':')) else {
                return false;
            };
            match (addr, port.parse::<u16>()) {
                ("198.18.0.2", Ok(_)) => true,
                ("*", Ok(p)) => LAB_LISTEN_PORTS.contains(&p),
                _ => false,
            }
        })
        .map(|l| l.trim().to_owned())
        .collect()
}

/// A netstat that ran cleanly (rc 0, empty stderr) but printed no TCP table: macOS hides the inet pcblist from
/// processes started by ad-hoc-signed tools. Not an error; the verifier judges replies from the wire capture.
pub fn netstat_blind(ns: &Done) -> bool {
    ns.rc == 0
        && ns.stderr.trim().is_empty()
        && !ns
            .stdout
            .lines()
            .any(|l| l.starts_with("Active Internet connections"))
}

/// Lab listener ports of the peer (`peer listen --open 8000-8007`).
const LAB_LISTEN_PORTS: std::ops::RangeInclusive<u16> = 8000..=8007;

/// Leftover listeners found in a `netstat -an -p tcp` record: any LISTEN on `198.18.0.2.<port>`, or on `*.<port>`
/// of a lab port (the wildcard also answers on 198.18.0.2). Other wildcard services of the host are not leftovers.
pub fn leftover_listeners(netstat: &str) -> Vec<String> {
    netstat
        .lines()
        .filter(|l| l.contains("LISTEN"))
        .filter(|l| matches!(l.split_whitespace().next(), Some("tcp4" | "tcp46")))
        .filter_map(|l| {
            let a = l.split_whitespace().nth(3)?;
            let hit = if let Some(p) = a.strip_prefix("198.18.0.2.") {
                p.parse::<u16>().is_ok()
            } else if let Some(p) = a.strip_prefix("*.") {
                p.parse::<u16>()
                    .is_ok_and(|p| LAB_LISTEN_PORTS.contains(&p))
            } else {
                false
            };
            hit.then(|| l.trim().to_owned())
        })
        .collect()
}

const BLIND_NOTE: &str = "# not recorded: macOS hides the TCP table from processes started by ad-hoc-signed tools; replies are judged from the wire capture\n";

/// What `host-listen-*.txt` holds and whether it is a record. A blinded `netstat -an -p tcp` exits 0 with empty
/// stdout and the reason on stderr; that is "not recorded", never "no host listeners". The record needs rc 0, the
/// netstat header and an empty stderr; stderr is kept in the file as `# stderr:` lines.
pub fn netstat_record(ns: &Done) -> (String, bool) {
    let mut text = format!("rc {}\n{}", ns.rc, ns.stdout);
    if !text.ends_with('\n') {
        text.push('\n');
    }
    for l in ns.stderr.lines() {
        text.push_str(&format!("# stderr: {l}\n"));
    }
    if netstat_blind(ns) {
        text.push_str(BLIND_NOTE);
    }
    let ok = ns.rc == 0
        && ns
            .stdout
            .lines()
            .any(|l| l.starts_with("Active Internet connections"))
        && ns.stderr.trim().is_empty();
    (text, ok)
}

pub fn dirty(porcelain: &str) -> bool {
    !porcelain.trim().is_empty()
}

fn sha_bytes(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn sha_file(p: &Path) -> Result<String> {
    Ok(sha_bytes(&fs::read(p)?))
}

/// `sha256sum` lines of every top-level regular file except the list itself and `verdict.json`; the directory
/// `data/` is not listed (the SQLite file stays out of the repository: `history.json` and `data.sha256` stand for it).
pub fn hashes_text(dir: &Path) -> Result<String> {
    let mut names = Vec::new();
    for e in fs::read_dir(dir)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        if name == "hashes-before-copy.txt" || name == "verdict.json" || e.path().is_dir() {
            continue;
        }
        names.push(name);
    }
    names.sort();
    let mut s = String::new();
    for n in names {
        s.push_str(&format!("{}  {n}\n", sha_file(&dir.join(&n))?));
    }
    Ok(s)
}

/// The verdict of a dry run: no runner is installed, so the Authorize step must fail by itself.
pub fn dry_verdict(ui_rc: Option<i32>, smoke: Option<&str>, procs_after: &str) -> Vec<String> {
    let mut p = Vec::new();
    match ui_rc {
        Some(1) => {}
        other => p.push(format!(
            "studio-ui --smoke-feth exited {other:?}, expected rc 1 (a hang means a dialog may be open)"
        )),
    }
    match smoke.and_then(|t| serde_json::from_str::<Value>(t).ok()) {
        None => p.push("smoke.json is missing or not JSON".into()),
        Some(j) => {
            if !j["result"]
                .as_str()
                .is_some_and(|r| r.starts_with("Authorization failed"))
            {
                p.push(format!(
                    "smoke.json result is {}, expected \"Authorization failed...\"",
                    j["result"]
                ));
            }
            if j["events"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|e| e["authorized"] == true)
            {
                p.push("smoke.json records an authorized session".into());
            }
            if j["actions"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|a| a["action"].as_str().is_some_and(|a| a.starts_with("Start")))
            {
                p.push("smoke.json records a Start although nothing was authorized".into());
            }
        }
    }
    if !procs_after.trim().is_empty() {
        p.push(format!(
            "a Studio process or an administrator dialog is left over: {}",
            procs_after.trim()
        ));
    }
    p
}

// ------------------------------------------------------------------ history.json

pub fn scan_json(s: &SavedScan, rows: &[SavedRow]) -> Value {
    let next_index = match s.next_index.as_deref() {
        None => Value::Null,
        Some(n) => n.parse::<u64>().map_or_else(|_| json!(n), |n| json!(n)),
    };
    json!({
        "scan_id_hex": id_text(s.scan),
        "attempt_hex": id_text(s.attempt),
        "job": serde_json::to_value(&s.job).unwrap_or(Value::Null),
        "status": serde_json::to_value(&s.status).unwrap_or(Value::Null),
        "detail": s.detail,
        "next_index": next_index,
        "checkpoint_len": s.checkpoint.as_ref().map_or(0, Vec::len),
        // studio-store exposes no accessor for the sequence column and this task may not change it.
        "sequence": Value::Null,
        "created_at": s.created_at,
        "rows": rows.iter().map(|r| json!({"ip":r.row.ip,"port":r.row.port,"open":r.row.open,"discovered_at":r.discovered_at})).collect::<Vec<_>>(),
    })
}

/// The SQLite history as the verifier reads it: oldest scan first, rows in rowid order.
pub fn history_json(
    store: &Store,
) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let mut scans = store.scans()?;
    scans.reverse();
    let mut out = Vec::new();
    for s in &scans {
        out.push(scan_json(s, &store.observations(s.scan)?));
    }
    Ok(json!({"scans": out}))
}

// ------------------------------------------------------------------ process host

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done {
    pub rc: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone)]
pub struct Spawn {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    pub stdout: PathBuf,
    /// `None`: the same file as stdout.
    pub stderr: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proc {
    pub id: usize,
    pub pid: u32,
}

/// Everything the orchestrator asks of the machine, so that the flow can be tested with a fake.
pub trait Host {
    /// Blocking command with captured output; `argv[0]` is an absolute path.
    fn run(&mut self, argv: &[String]) -> Result<Done>;
    fn spawn(&mut self, s: &Spawn) -> Result<Proc>;
    /// The exit code once the process ended (`-1` when a signal killed it), `None` while it runs after `timeout`.
    fn wait(&mut self, p: Proc, timeout: Duration) -> Option<i32>;
    /// `INT`, `TERM` or `KILL`.
    fn signal(&mut self, p: Proc, sig: &str) -> Result<()>;
    fn sleep(&mut self, d: Duration);
    fn utc(&mut self) -> String;
    /// sha256 of the bytes of the installed runner of `bundle_hash`, read as the user.
    fn installed_runner_sha256(&mut self, bundle_hash: &str) -> Option<String>;
    /// `cargo xtask prepare-runner` for the bundle's runner (copies and validates; changes no system file).
    fn prepare_runner(&mut self, runner: &Path) -> Result<PathBuf>;
}

struct Slot {
    child: Option<std::process::Child>,
    rc: Option<i32>,
}
#[derive(Default)]
pub struct RealHost {
    slots: Vec<Slot>,
}
impl Host for RealHost {
    fn run(&mut self, argv: &[String]) -> Result<Done> {
        let o = Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .output()?;
        Ok(Done {
            rc: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        })
    }
    fn spawn(&mut self, s: &Spawn) -> Result<Proc> {
        let out = fs::File::create(&s.stdout)?;
        let err = match &s.stderr {
            Some(p) => fs::File::create(p)?,
            None => out.try_clone()?,
        };
        let child = Command::new(&s.argv[0])
            .args(&s.argv[1..])
            .envs(s.env.iter().map(|(k, v)| (k, v)))
            .current_dir(&s.cwd)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .spawn()?;
        let pid = child.id();
        self.slots.push(Slot {
            child: Some(child),
            rc: None,
        });
        Ok(Proc {
            id: self.slots.len() - 1,
            pid,
        })
    }
    fn wait(&mut self, p: Proc, timeout: Duration) -> Option<i32> {
        let end = Instant::now() + timeout;
        loop {
            let slot = &mut self.slots[p.id];
            if let Some(rc) = slot.rc {
                return Some(rc);
            }
            if let Some(Ok(Some(st))) = slot.child.as_mut().map(|c| c.try_wait()) {
                let rc = st.code().unwrap_or(-1);
                slot.rc = Some(rc);
                slot.child = None;
                return Some(rc);
            }
            if Instant::now() >= end {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn signal(&mut self, p: Proc, sig: &str) -> Result<()> {
        let st = Command::new("/bin/kill")
            .arg(format!("-{sig}"))
            .arg(p.pid.to_string())
            .stdin(Stdio::null())
            .status()?;
        if !st.success() {
            return Err(format!("kill -{sig} {} failed: {st}", p.pid).into());
        }
        Ok(())
    }
    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
    fn utc(&mut self) -> String {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        utc_text(d.as_secs(), d.subsec_millis())
    }
    fn installed_runner_sha256(&mut self, bundle_hash: &str) -> Option<String> {
        let p = studio_platform::macos::installed_path(bundle_hash).ok()?;
        fs::read(p).ok().map(|b| sha_bytes(&b))
    }
    fn prepare_runner(&mut self, runner: &Path) -> Result<PathBuf> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or("no studio directory")?
            .to_owned();
        super::runner_setup::prepare_source(&root, runner)
    }
}

// ------------------------------------------------------------------ the run

struct Ctx<'a, H: Host> {
    h: &'a mut H,
    o: &'a Opts,
    dir: PathBuf,
    rules: Vec<(String, String)>,
    marks: Vec<String>,
    /// Every spawned child (name, process): the guard of the cleanup path.
    children: Vec<(&'static str, Proc)>,
    started: String,
    uplink: Option<String>,
    breach: Option<String>,
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

impl<H: Host> Ctx<'_, H> {
    fn put(&self, name: &str, text: &str) -> Result<()> {
        Ok(fs::write(self.dir.join(name), scrub(text, &self.rules))?)
    }
    fn put_json(&self, name: &str, v: &Value) -> Result<()> {
        self.put(name, &(serde_json::to_string_pretty(v)? + "\n"))
    }
    /// A command whose failure to start is a result, not an error.
    fn run(&mut self, argv: &[&str]) -> Done {
        let a: Vec<String> = argv.iter().map(|x| (*x).to_owned()).collect();
        self.h.run(&a).unwrap_or_else(|e| Done {
            rc: -1,
            stdout: String::new(),
            stderr: format!("cannot run {}: {e}", argv[0]),
        })
    }
    fn mark(&mut self, text: impl Into<String>) {
        let t = text.into();
        eprintln!("INVALID MARK: {t}");
        if !self.marks.contains(&t) {
            self.marks.push(t);
        }
    }
    /// Rewrites a file written by a child process (stderr, logs) with the paths scrubbed.
    fn scrub_file(&self, name: &str) {
        if let Ok(t) = fs::read(self.dir.join(name)) {
            let _ = fs::write(
                self.dir.join(name),
                scrub(&String::from_utf8_lossy(&t), &self.rules),
            );
        }
    }
    fn spawn(&mut self, name: &'static str, sp: &Spawn) -> Result<Proc> {
        let p = self.h.spawn(sp)?;
        self.children.push((name, p));
        Ok(p)
    }
    /// The uplink saw a lab frame: the file comes before anything else is stopped or written.
    fn record_breach(&mut self, why: &str) {
        let text = format!(
            "ISOLATION BREACH: a lab frame reached the uplink. There is no rerun.\n{why}\n"
        );
        let _ = fs::write(self.dir.join("ISOLATION-BREACH.txt"), &text);
        eprintln!(
            "\n*** ISOLATION BREACH: do not rerun this window; verify it and take the stand down. ***\n{why}"
        );
        self.breach = Some(why.to_owned());
    }
    fn not_run(&self, reasons: &[String], actions: &[String]) -> Result<i32> {
        let mut t = if self.children.is_empty() {
            String::from("NOT RUN: nothing was started by the orchestrator.\n")
        } else {
            format!(
                "NOT RUN: the orchestrator started {} process(es) and stopped them again. The stand is still up with the BPF grant open: user action F is below.\n",
                self.children.len()
            )
        };
        for r in reasons {
            t.push_str(&format!("- {r}\n"));
        }
        for a in actions {
            t.push_str(&format!("\n{a}\n"));
        }
        if !self.children.is_empty() {
            t.push_str(&format!(
                "\nUser action F:\n{}\n",
                user_action_f(&s(&self.o.lab))
            ));
        }
        t.push_str("\nThe orchestrator never runs sudo itself. Use a fresh, empty --out directory for the next attempt.\n");
        eprint!("{t}");
        self.put("NOT-RUN.txt", &t)?;
        Ok(2)
    }
}

/// who, interface, argv, filter, start_utc, process
type Witness = (
    &'static str,
    String,
    Vec<String>,
    Option<&'static str>,
    String,
    Proc,
);

fn own_pids() -> Vec<u32> {
    vec![std::process::id(), std::os::unix::process::parent_id()]
}

fn ps_text<H: Host>(c: &mut Ctx<'_, H>) -> Done {
    c.run(&["/bin/ps", "-axo", "pid=,command="])
}

struct Bundle {
    ui: PathBuf,
    runner: PathBuf,
    ui_sha: String,
    runner_sha: String,
    inspect_sha: String,
}

fn bundle(app: &Path) -> std::result::Result<Bundle, String> {
    let macos = app.join("Contents/MacOS");
    let one = |n: &str| -> std::result::Result<(PathBuf, String), String> {
        let p = macos.join(n);
        let b = fs::read(&p).map_err(|e| format!("bundle file {} unreadable: {e}", p.display()))?;
        Ok((p, sha_bytes(&b)))
    };
    let (ui, ui_sha) = one("studio-ui")?;
    let (runner, runner_sha) = one("studio-runner")?;
    let (_, inspect_sha) = one("studio-inspect")?;
    Ok(Bundle {
        ui,
        runner,
        ui_sha,
        runner_sha,
        inspect_sha,
    })
}

struct Git {
    head: String,
    dirty: bool,
    toplevel: String,
}

fn git<H: Host>(c: &mut Ctx<'_, H>) -> std::result::Result<Git, String> {
    let g = |c: &mut Ctx<'_, H>, a: &[&str]| -> std::result::Result<String, String> {
        let studio = studio_dir();
        let mut argv = vec!["/usr/bin/git", "-C", studio.as_str()];
        argv.extend_from_slice(a);
        let d = c.run(&argv);
        if d.rc != 0 {
            return Err(format!(
                "git {} failed (rc {}): {}",
                a.join(" "),
                d.rc,
                d.stderr.trim()
            ));
        }
        Ok(d.stdout)
    };
    Ok(Git {
        head: g(c, &["rev-parse", "HEAD"])?.trim().to_owned(),
        dirty: dirty(&g(c, &["status", "--porcelain", "--untracked-files=no"])?),
        toplevel: g(c, &["rev-parse", "--show-toplevel"])?.trim().to_owned(),
    })
}

fn exe_path() -> String {
    std::env::current_exe().map(|p| s(&p)).unwrap_or_default()
}

fn studio_dir() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(s)
        .unwrap_or_default()
}

fn uplink_len(dir: &Path) -> Option<u64> {
    fs::metadata(dir.join("uplink.pcap")).ok().map(|m| m.len())
}

fn ui_env(c: &Ctx<'_, impl Host>, smoke: bool) -> Vec<(String, String)> {
    let mut env = vec![("STUDIO_DATA_DIR".to_owned(), s(&c.dir.join("data")))];
    if smoke {
        env.push(("STUDIO_SMOKE_OUT".into(), s(&c.dir)));
    }
    env.push(("STUDIO_SCREENSHOT".into(), s(&c.dir.join("final.png"))));
    env
}

#[derive(Debug, PartialEq, Eq)]
enum UiEnd {
    Exited(i32),
    Timeout,
    Breach,
    WitnessDied(&'static str),
}

fn supervise<H: Host>(
    c: &mut Ctx<'_, H>,
    ui: Proc,
    witnesses: &[(&'static str, Proc)],
    seconds: u64,
) -> UiEnd {
    let polls = seconds * 1000 / POLL_MS;
    for _ in 0..polls {
        if let Some(rc) = c.h.wait(ui, Duration::from_millis(POLL_MS)) {
            return UiEnd::Exited(rc);
        }
        if uplink_len(&c.dir).is_some_and(|n| n > PCAP_HEADER) {
            return UiEnd::Breach;
        }
        for (who, p) in witnesses {
            if c.h.wait(*p, Duration::ZERO).is_some() {
                return UiEnd::WitnessDied(who);
            }
        }
    }
    UiEnd::Timeout
}

/// Stops a process politely, then hard. Returns its exit code (`-1` when it had to be killed).
fn stop<H: Host>(c: &mut Ctx<'_, H>, p: Proc, first: &str) -> i32 {
    if let Some(rc) = c.h.wait(p, Duration::ZERO) {
        return rc;
    }
    let _ = c.h.signal(p, first);
    if let Some(rc) = c.h.wait(p, Duration::from_secs(10)) {
        return rc;
    }
    let _ = c.h.signal(p, "KILL");
    c.h.wait(p, Duration::from_secs(5));
    -1
}

pub fn run<H: Host>(h: &mut H, o: &Opts) -> Result<i32> {
    // The window directory is created empty; anything else is refused.
    if o.out.exists() && fs::read_dir(&o.out)?.next().is_some() {
        eprintln!("NOT RUN: --out {} exists and is not empty", o.out.display());
        return Ok(2);
    }
    fs::create_dir_all(&o.out)?;
    let dir = fs::canonicalize(&o.out)?;
    let mut c = Ctx {
        h,
        o,
        rules: vec![(s(&dir), "$OUT".into())],
        dir,
        marks: Vec::new(),
        children: Vec::new(),
        started: String::new(),
        uplink: None,
        breach: None,
    };
    if let Some(home) = std::env::var_os("HOME").and_then(|h| h.into_string().ok()) {
        c.rules.push((home, "$HOME".into()));
    }
    let mut early = Vec::new();
    if !o.lab.is_file() {
        early.push(format!("--lab {} is not a file", o.lab.display()));
    }
    let b = match bundle(&o.app) {
        Ok(b) => Some(b),
        Err(e) => {
            early.push(e);
            None
        }
    };
    let g = match git(&mut c) {
        Ok(g) => {
            // $REPO goes before $HOME so that a checkout under the home directory reads as $REPO.
            c.rules.insert(1, (g.toplevel.clone(), "$REPO".into()));
            Some(g)
        }
        Err(e) => {
            early.push(e);
            None
        }
    };
    let (Some(b), Some(g)) = (b, g) else {
        return c.not_run(&early, &[]);
    };
    // The SQLite of the orchestrator and of the bundle must not be Apple's.
    let exe = std::env::current_exe().map(|p| s(&p)).unwrap_or_default();
    for (label, path) in [
        ("this orchestrator", exe),
        ("the bundle's studio-ui", s(&b.ui)),
    ] {
        let d = c.run(&["/usr/bin/otool", "-L", &path]);
        if d.rc != 0 {
            early.push(format!("otool -L {label} failed (rc {})", d.rc));
        } else if links_apple_sqlite(&d.stdout) {
            early.push(format!("{label} links Apple's /usr/lib/libsqlite3, which leaves -wal/-shm behind: {SQLITE_HINT}"));
        }
    }
    let manifest = o.app.parent().map(|p| p.join("manifest.json"));
    let manifest_text = manifest.and_then(|m| fs::read_to_string(m).ok());
    if let Err(e) = check_bundle_manifest(manifest_text.as_deref(), &g.head) {
        early.push(e);
    }
    if !early.is_empty() {
        return c.not_run(&early, &[]);
    }
    if o.dry_run {
        dry_run(&mut c, &b, &g)
    } else {
        live(&mut c, &b, &g)
    }
}

fn lab_info<H: Host>(c: &mut Ctx<'_, H>) -> Result<(String, String)> {
    let v = c.run(&[&s(&c.o.lab), "--version"]);
    let version = if v.rc == 0 {
        v.stdout.trim().to_owned()
    } else {
        format!("unavailable (rc {})", v.rc)
    };
    Ok((sha_file(&c.o.lab)?, version))
}

fn provenance<H: Host>(
    c: &mut Ctx<'_, H>,
    b: &Bundle,
    g: &Git,
    installed: Option<&str>,
) -> Result<()> {
    let (lab_sha, lab_version) = lab_info(c)?;
    let manifest = c.o.app.parent().map(|p| p.join("manifest.json"));
    let mut bundle_dirty = Value::Null;
    let manifest_sha = match manifest.filter(|m| m.is_file()) {
        Some(m) => {
            let t = fs::read_to_string(&m)?;
            bundle_dirty = serde_json::from_str::<Value>(&t)
                .map(|j| j["dirty"].clone())
                .unwrap_or(Value::Null);
            c.put("bundle-manifest.json", &t)?;
            Some(sha_bytes(t.as_bytes()))
        }
        None => None,
    };
    c.put_json(
        "provenance.json",
        &json!({
            "git_head": g.head, "dirty": g.dirty,
            "ui_sha256": b.ui_sha, "runner_sha256": b.runner_sha, "installed_runner_sha256": installed,
            "inspect_sha256": b.inspect_sha, "lab_sha256": lab_sha, "lab_version": lab_version,
            "bundle_manifest_sha256": manifest_sha, "bundle_manifest_dirty": bundle_dirty,
        }),
    )
}

/// The common end: the interlock, the history dump, the data hash, `window.json` and the hashes. Returns the exit code.
fn close<H: Host>(
    c: &mut Ctx<'_, H>,
    ended: &str,
    ui_rc: Option<i32>,
    extra: Value,
    aborted: bool,
) -> Result<i32> {
    // Interlock first (live runs only): tcpdump's statistics and the size of the pcap, never a parse of it.
    if c.uplink.is_some() {
        let uerr = fs::read_to_string(c.dir.join("uplink.err")).unwrap_or_default();
        match interlock(&uerr, uplink_len(&c.dir)) {
            Interlock::Breach(w) if c.breach.is_none() => c.record_breach(&w),
            Interlock::Unproven(w) if c.breach.is_none() => {
                c.mark(format!("uplink interlock unproven: {w}"))
            }
            _ => {}
        }
        if let Some(why) = c.breach.clone() {
            c.mark(format!("isolation breach: {why}"));
        }
    }
    let data = c.dir.join("data");
    let journal = |d: &Path| {
        ["history.sqlite3-wal", "history.sqlite3-shm"]
            .iter()
            .any(|n| d.join(n).exists())
    };
    if journal(&data) {
        c.mark("history not closed cleanly");
    }
    let before_dump = fs::read(data.join("history.sqlite3"))
        .ok()
        .map(|b| sha_bytes(&b));
    if data.is_dir() {
        match Store::open(&data).and_then(|st| history_json(&st)) {
            Ok(h) => c.put_json("history.json", &h)?,
            Err(e) => c.mark(format!("history.json not written: {e}")),
        }
        if journal(&data) {
            c.mark("history not closed cleanly");
        }
        if let Ok(b) = fs::read(data.join("history.sqlite3")) {
            c.put(
                "data.sha256",
                &format!("{}  history.sqlite3\n", sha_bytes(&b)),
            )?;
        }
    } else {
        c.mark("the UI left no data directory: history.json not written");
    }
    if let Some(rc) = ui_rc {
        c.put("ui_rc.txt", &format!("{rc}\n"))?;
    }
    let mut w = json!({
        "schema": 1, "started_utc": c.started, "ended_utc": ended, "uplink": c.uplink,
        "ui_rc": ui_rc, "invalid_marks": c.marks,
        "manual": c.o.manual, "dry_run": c.o.dry_run,
        "data_sha256_before_dump": before_dump,
        "thresholds": {"pause_to_paused_ms": 5000, "stop_to_stopped_ms": 1000, "smoke_deadline_s": 420},
    });
    if let (Some(o), Some(e)) = (w.as_object_mut(), extra.as_object()) {
        o.extend(e.clone());
    }
    c.put_json("window.json", &w)?;
    let list = hashes_text(&c.dir)?;
    fs::write(c.dir.join("hashes-before-copy.txt"), list)?;
    Ok(if c.breach.is_some() {
        13
    } else if aborted || !c.marks.is_empty() || ui_rc != Some(0) {
        10
    } else {
        0
    })
}

/// Any error after children started: breach file first when the uplink holds a frame, every child stopped,
/// then a best-effort `window.json` with an INVALID mark naming the failure. rc 13 on a breach, otherwise 10.
fn cleanup_after_error<H: Host>(c: &mut Ctx<'_, H>, err: &str) -> i32 {
    eprintln!("ABORT: {err}");
    if c.breach.is_none() && uplink_len(&c.dir).is_some_and(|n| n > PCAP_HEADER) {
        c.record_breach("uplink.pcap holds a frame (found while aborting)");
    }
    for (name, p) in c.children.clone() {
        stop(c, p, if name == "ui" { "TERM" } else { "INT" });
    }
    c.mark(format!("aborted: {err}"));
    if let Some(why) = c.breach.clone() {
        c.mark(format!("isolation breach: {why}"));
    }
    let ended = c.h.utc();
    for who in ["peer", "uplink"] {
        c.scrub_file(&format!("{who}.err"));
    }
    c.scrub_file("ui.log");
    c.scrub_file("listeners.log");
    let w = json!({
        "schema": 1, "started_utc": c.started, "ended_utc": ended, "uplink": c.uplink,
        "ui_rc": Value::Null, "invalid_marks": c.marks, "manual": c.o.manual, "dry_run": c.o.dry_run,
        "aborted": true,
    });
    let _ = c.put_json("window.json", &w);
    if let Ok(list) = hashes_text(&c.dir) {
        let _ = fs::write(c.dir.join("hashes-before-copy.txt"), list);
    }
    if c.breach.is_some() { 13 } else { 10 }
}

fn dry_run<H: Host>(c: &mut Ctx<'_, H>, b: &Bundle, g: &Git) -> Result<i32> {
    let mut reasons = Vec::new();
    if c.h.installed_runner_sha256(&b.runner_sha).is_some() {
        reasons.push(format!(
            "the runner of this bundle ({}) is installed: a dry run would reach the administrator dialog; a dry run needs NO installed runner",
            b.runner_sha
        ));
    }
    let ps = ps_text(c);
    c.put(
        "leftover-procs.txt",
        &leftover_procs(&ps.stdout, &own_pids()),
    )?;
    if !leftover_procs(&ps.stdout, &own_pids()).trim().is_empty() {
        reasons.push("leftover processes (see leftover-procs.txt)".into());
    }
    if !reasons.is_empty() {
        return c.not_run(&reasons, &[]);
    }
    provenance(c, b, g, None)?;
    let started = c.h.utc();
    let ui = c.h.spawn(&Spawn {
        argv: vec![s(&b.ui), "--smoke-feth".into()],
        env: ui_env(c, true),
        cwd: c.dir.clone(),
        stdout: c.dir.join("ui.log"),
        stderr: None,
    })?;
    let end = supervise(c, ui, &[], DRY_SECONDS);
    let ui_rc = match end {
        UiEnd::Exited(rc) => Some(rc),
        _ => {
            stop(c, ui, "TERM");
            None
        }
    };
    let ended = c.h.utc();
    c.scrub_file("ui.log");
    let ps = ps_text(c);
    let after = dry_leftover_procs(&ps.stdout);
    c.put("procs-after.txt", &after)?;
    let smoke = fs::read_to_string(c.dir.join("smoke.json")).ok();
    let problems = dry_verdict(ui_rc, smoke.as_deref(), &after);
    let mut report = String::from(
        "DRY RUN: no stand, no installed runner, no witness, no frame. The window is NOT RUN.\n",
    );
    if problems.is_empty() {
        report.push_str("PASS: studio-ui --smoke-feth exited rc 1 with \"Authorization failed\", wrote smoke.json, left no Studio process and no administrator dialog.\n");
    } else {
        for p in &problems {
            report.push_str(&format!("FAIL: {p}\n"));
        }
    }
    c.put("dry-run.txt", &report)?;
    eprint!("{report}");
    c.marks
        .push("NOT RUN: dry run, no stand and no installed runner".into());
    // `close` returns 10 for a window that is not clean, which a dry run always is; its verdict decides here.
    c.started = started;
    let _ = close(
        c,
        &ended,
        ui_rc,
        json!({"result":"NOT RUN","dry_run_problems":problems}),
        false,
    )?;
    Ok(if problems.is_empty() { 0 } else { 10 })
}

fn live<H: Host>(c: &mut Ctx<'_, H>, b: &Bundle, g: &Git) -> Result<i32> {
    let lab = s(&c.o.lab);
    let mut reasons: Vec<String> = Vec::new();

    // 1. gates (all are reads)
    let st = c.run(&[&lab, "macos-lab", "status", "--run-id", RUN_ID]);
    c.put("status-pre.json", &st.stdout)?;
    let verdict = status_pre(st.rc, &st.stdout);
    reasons.extend(verdict.reasons.iter().cloned());
    let alf = c.run(&[
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        "--getglobalstate",
    ]);
    c.put("alf.txt", &alf.stdout)?;
    if !firewall_ok(&alf.stdout) {
        reasons.push(format!(
            "application firewall: {:?}, expected {ALF_TEXT:?}",
            alf.stdout.trim()
        ));
    }
    let ls = c.run(&["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]);
    if !lsof_ok(ls.rc) {
        reasons.push(format!("lsof could not run (rc {})", ls.rc));
    }
    let lleft = lsof_leftovers(&ls.stdout);
    // Only the leftover lines are evidence; the full listing is the user's app inventory and is never written.
    c.put("leftover-listeners.txt", &lines_text(&lleft))?;
    if !lleft.is_empty() {
        reasons.push(format!(
            "a listener on 198.18.0.2 or a lab port is left over (lsof): {lleft:?}"
        ));
    }
    let ps = ps_text(c);
    let left = leftover_procs(&ps.stdout, &own_pids());
    c.put("leftover-procs.txt", &left)?;
    if ps.rc != 0 || !left.trim().is_empty() {
        reasons.push("leftover processes (see leftover-procs.txt)".into());
    }
    let mut samples = Vec::new();
    for i in 0..4 {
        if i > 0 {
            c.h.sleep(Duration::from_secs(1));
        }
        let (a, bb) = (
            c.run(&["/usr/sbin/netstat", "-I", SCANNER_IF, "-b", "-d", "-n"]),
            c.run(&["/usr/sbin/netstat", "-I", PEER_IF, "-b", "-d", "-n"]),
        );
        samples.push(if a.rc == 0 && bb.rc == 0 {
            format!("{}{}", a.stdout, bb.stdout)
        } else {
            String::new()
        });
    }
    let quiet = pair_quiet(&samples);
    c.put("pair-quiet.txt", &quiet.report)?;
    if !quiet.ok {
        reasons.push("the feth pair is not quiet (see pair-quiet.txt)".into());
    }
    let ns = c.run(&["/usr/sbin/netstat", "-an", "-p", "tcp"]);
    let (rec, recorded) = netstat_record(&ns);
    c.put("host-listen-before.txt", &rec)?;
    if netstat_blind(&ns) {
        eprintln!(
            "note: netstat shows no TCP table (macOS hides it from ad-hoc-signed tools); replies are judged from the wire capture"
        );
    } else if !recorded {
        reasons.push(
            "host listeners not recorded: netstat -an -p tcp failed or wrote to stderr".into(),
        );
    }
    // A valid record lists every user's sockets; lsof above covers the user's own when netstat is blind.
    let left = leftover_listeners(&ns.stdout);
    if !left.is_empty() {
        c.put(
            "leftover-listeners.txt",
            &lines_text(&[lleft.clone(), left.clone()].concat()),
        )?;
        reasons.push(format!(
            "a listener on 198.18.0.2 or a lab port is left over (netstat): {left:?}"
        ));
    }
    let mut sys = String::new();
    for k in [
        "net.inet.tcp.syncookie",
        "net.inet.tcp.rst_rlc_enable",
        "net.inet.tcp.rst_rlc_bucket_ms",
    ] {
        let d = c.run(&["/usr/sbin/sysctl", k]);
        sys.push_str(&if d.rc == 0 {
            d.stdout
        } else {
            format!("{k}: unavailable (rc {})\n", d.rc)
        });
    }
    c.put("sysctl.txt", &sys)?;
    let sw = c.run(&["/usr/bin/sw_vers"]);
    c.put("sw_vers.txt", &sw.stdout)?;

    // 2. provenance gates: the runner of this bundle must be installed, the tree clean
    let installed = c.h.installed_runner_sha256(&b.runner_sha);
    let mut runner_dir = None;
    let mut need_install = false;
    if let Err(e) = check_installed(&b.runner_sha, installed.as_deref()) {
        reasons.push(e);
        need_install = true;
        match c.h.prepare_runner(&b.runner) {
            Ok(d) => runner_dir = Some(s(&d)),
            Err(e) => reasons.push(format!(
                "could not prepare the bundle's runner for installation: {e} (run `cargo xtask prepare-runner {}` yourself)",
                sh_quote(&s(&b.runner))
            )),
        }
    }
    if g.dirty {
        reasons.push("the working tree has tracked changes (git status --porcelain --untracked-files=no): commit them first".into());
    }
    if !reasons.is_empty() {
        let line = user_action_b(
            &exe_path(),
            runner_dir.as_deref().filter(|_| need_install),
            &lab,
            verdict.stand_missing,
            verdict.grant_missing || verdict.stand_missing,
        );
        let actions: Vec<String> = line
            .map(|l| {
                vec![format!(
                    "User action B (paste this one line into Terminal; it asks for your password, and install-runner shows the administrator dialog once), then rerun with a fresh --out:\n{l}"
                )]
            })
            .unwrap_or_default();
        return c.not_run(&reasons, &actions);
    }
    let uplink = verdict.uplink.clone().unwrap_or_default();
    provenance(c, b, g, installed.as_deref())?;
    c.uplink = Some(uplink.clone());
    c.started = c.h.utc();
    let code = match window(c, b, &lab, &uplink) {
        Ok(code) => code,
        Err(e) => cleanup_after_error(c, &e.to_string()),
    };
    if code == 2 {
        // NOT RUN after children were started and stopped: NOT-RUN.txt holds the reasons and action F.
        return Ok(2);
    }
    if code == 13 {
        println!(
            "*** ISOLATION BREACH (rc 13): a lab frame reached the uplink. Do not rerun this window. See ISOLATION-BREACH.txt. ***"
        );
    }
    println!(
        "feth-acceptance: window {} closed with rc {code} (0 clean, 10 abort or unclean, 13 isolation breach)",
        c.dir.display()
    );
    println!(
        "Next, you: verify the window with `{} studio-verify --dir {} --out {}`.",
        sh_quote(&lab),
        sh_quote(&s(&c.dir)),
        sh_quote(&s(&c.dir.join("verdict.json")))
    );
    println!(
        "User action F (end of the window, takes the BPF grant back):\n{}",
        user_action_f(&lab)
    );
    Ok(code)
}

/// From the peer listeners to the closed window. An `Err` here is handled by `cleanup_after_error`.
fn window<H: Host>(c: &mut Ctx<'_, H>, b: &Bundle, lab: &str, uplink: &str) -> Result<i32> {
    // 3. peer listeners
    let ready = c.dir.join("listeners-ready.txt");
    let listen = c.spawn(
        "peer-listen",
        &Spawn {
            argv: vec![
                lab.to_owned(),
                "peer".into(),
                "listen".into(),
                "--open".into(),
                "8000-8007".into(),
                "--ready".into(),
                s(&ready),
            ],
            env: vec![],
            cwd: c.dir.clone(),
            stdout: c.dir.join("listeners.log"),
            stderr: None,
        },
    )?;
    let mut ready_ok = false;
    for _ in 0..100 {
        if ready.is_file() {
            ready_ok = true;
            break;
        }
        if c.h.wait(listen, Duration::from_millis(100)).is_some() {
            break;
        }
    }
    if !ready_ok {
        stop(c, listen, "INT");
        c.scrub_file("listeners.log");
        return c.not_run(
            &["peer listen was not ready within 10 s (see listeners.log)".into()],
            &[],
        );
    }

    // 4. witnesses
    let mut cmds: Vec<Witness> = Vec::new();
    for (who, iface, filter) in [
        ("peer", PEER_IF.to_owned(), Some(PEER_FILTER)),
        ("uplink", uplink.to_owned(), Some(UPLINK_FILTER)),
    ] {
        let argv = capture_argv(&iface, &format!("{who}.pcap"), filter);
        let start = c.h.utc();
        let sp = Spawn {
            argv: argv.clone(),
            env: vec![],
            cwd: c.dir.clone(),
            stdout: c.dir.join(format!("{who}.log")),
            stderr: Some(c.dir.join(format!("{who}.err"))),
        };
        match c.spawn(who, &sp) {
            Ok(p) => cmds.push((who, iface, argv, filter, start, p)),
            Err(e) => {
                let children = c.children.clone();
                for (_, p) in children {
                    stop(c, p, "INT");
                }
                return c.not_run(&[format!("cannot start the {who} witness: {e}")], &[]);
            }
        }
    }
    c.h.sleep(Duration::from_secs(2));
    let mut listening = Vec::new();
    for (who, iface, _, _, _, p) in &cmds {
        let alive = c.h.wait(*p, Duration::ZERO).is_none();
        let banner = fs::read_to_string(c.dir.join(format!("{who}.err")))
            .is_ok_and(|t| t.contains(&format!("listening on {iface},")));
        listening.push(alive && banner);
    }
    if listening.iter().any(|l| !l) {
        let children = c.children.clone();
        for (_, p) in children {
            stop(c, p, "INT");
        }
        for who in ["peer", "uplink"] {
            c.scrub_file(&format!("{who}.err"));
        }
        return c.not_run(&["a witness is not alive and listening 2 s after its start (see peer.err and uplink.err)".into()], &[]);
    }

    // 5. the UI
    let ui_started = c.h.utc();
    let ui = c.spawn(
        "ui",
        &Spawn {
            argv: if c.o.manual {
                vec![s(&b.ui)]
            } else {
                vec![s(&b.ui), "--smoke-feth".into()]
            },
            env: ui_env(c, !c.o.manual),
            cwd: c.dir.clone(),
            stdout: c.dir.join("ui.log"),
            stderr: None,
        },
    )?;
    let watch: Vec<(&'static str, Proc)> = cmds.iter().map(|(w, _, _, _, _, p)| (*w, *p)).collect();
    let end = supervise(
        c,
        ui,
        &watch,
        if c.o.manual {
            MANUAL_SECONDS
        } else {
            UI_SECONDS
        },
    );
    let mut aborted = false;
    let ui_rc = match end {
        UiEnd::Exited(rc) => Some(rc),
        UiEnd::Breach => {
            // The file comes first, before the UI or anything else is stopped.
            c.record_breach("a frame appeared in uplink.pcap while the UI ran; the UI was stopped");
            stop(c, ui, "TERM");
            None
        }
        UiEnd::Timeout => {
            aborted = true;
            c.mark("the UI did not exit before its deadline; it was stopped");
            stop(c, ui, "TERM");
            None
        }
        UiEnd::WitnessDied(w) => {
            aborted = true;
            c.mark(format!("the {w} witness died while the UI ran"));
            stop(c, ui, "TERM");
            None
        }
    };
    if ui_rc.is_none() {
        // A stopped UI may leave its administrator dialog behind.
        let ps = ps_text(c);
        if ps
            .stdout
            .lines()
            .any(|l| l.contains("with administrator privileges") && !l.contains("feth-acceptance"))
        {
            c.mark("an administrator dialog (osascript) is left over after the UI was stopped");
        }
    }

    // 6. stop: a second of quiet, SIGINT to the witnesses, wait
    c.h.sleep(Duration::from_secs(1));
    let mut records = Vec::new();
    for ((who, iface, argv, filter, start, p), l) in cmds.iter().zip(&listening) {
        let rc = stop(c, *p, "INT");
        let stop_utc = c.h.utc();
        if rc != 0 {
            c.mark(format!("the {who} tcpdump exited with {rc}, not 0"));
        }
        records.push((
            who,
            cmd_record(argv, iface, filter.unwrap_or(""), start, &stop_utc, rc, *l),
        ));
    }
    let lrc = stop(c, listen, "INT");
    if lrc != 0 {
        c.mark(format!("peer listen exited with {lrc}"));
    }
    // Every child is stopped; the writes below may fail without leaving anything running.
    for (who, rec) in &records {
        c.put_json(&format!("{who}.cmd.json"), rec)?;
        c.scrub_file(&format!("{who}.err"));
    }
    let ended = c.h.utc();
    c.scrub_file("ui.log");
    c.scrub_file("listeners.log");
    let ns = c.run(&["/usr/sbin/netstat", "-an", "-p", "tcp"]);
    let (rec, recorded) = netstat_record(&ns);
    c.put("host-listen-after.txt", &rec)?;
    if netstat_blind(&ns) {
        eprintln!(
            "note: netstat shows no TCP table (macOS hides it from ad-hoc-signed tools); replies are judged from the wire capture"
        );
    } else if !recorded {
        c.mark("host listeners not recorded");
    }
    let post = c.run(&[lab, "macos-lab", "status", "--run-id", RUN_ID]);
    c.put("status-post.json", &post.stdout)?;
    if !status_post_allowed(&post.stdout) {
        c.mark("status-post.json: raw_run_allowed is not true");
    }
    if ui_rc != Some(0) && c.breach.is_none() && !aborted {
        c.mark(format!("the UI exited with {ui_rc:?}"));
    }
    let pids: Vec<Value> = std::iter::once(("peer-listen", listen))
        .chain(cmds.iter().map(|(w, _, _, _, _, p)| (*w, *p)))
        .chain(std::iter::once(("ui", ui)))
        .map(|(n, p)| json!({"name": n, "pid": p.pid}))
        .collect();
    let (lab_sha, lab_version) = lab_info(c)?;
    close(
        c,
        &ended,
        ui_rc,
        json!({"pids": pids, "ui_started_utc": ui_started, "lab_sha256": lab_sha, "lab_version": lab_version, "result": "closed"}),
        aborted,
    )
}

/// Entry for `cargo xtask feth-acceptance ...`.
pub fn main_entry() -> Result<i32> {
    let args: Vec<String> = std::env::args().skip(2).collect();
    let o = parse_args(&args)?;
    run(&mut RealHost::default(), &o)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "feth-acc-{tag}-{}",
            id_text(studio_protocol::new_id().unwrap())
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }
    const GOOD: &str = r#"{"raw_run_allowed":true,"bpf_access":"granted","uplink":"en0","gateway":"192.168.1.1","checks":[{"name":"manifest","ok":true,"detail":""}]}"#;

    #[test]
    fn gates_require_granted_sealed_stand_and_a_real_uplink() {
        let ok = status_pre(0, GOOD);
        assert!(ok.reasons.is_empty(), "{:?}", ok.reasons);
        assert_eq!(ok.uplink.as_deref(), Some("en0"));
        let denied = status_pre(0, &GOOD.replace("granted", "denied"));
        assert!(denied.grant_missing && !denied.stand_missing);
        assert!(denied.reasons.iter().any(|r| r.contains("bpf_access")));
        let feth = status_pre(0, &GOOD.replace("en0", "feth4201"));
        assert!(feth.uplink.is_none() && feth.reasons.iter().any(|r| r.contains("uplink")));
        let null = status_pre(0, &GOOD.replace("\"en0\"", "null"));
        assert!(null.uplink.is_none() && !null.reasons.is_empty());
        let unsealed = status_pre(3, &GOOD.replace("true", "false"));
        assert!(unsealed.stand_missing && unsealed.reasons.len() >= 2);
        let nojson = status_pre(3, "");
        assert!(nojson.stand_missing && nojson.uplink.is_none());
        assert!(!status_pre(1, GOOD).reasons.is_empty());
        assert!(status_post_allowed(GOOD));
        assert!(!status_post_allowed(&GOOD.replace("true", "false")));
        assert!(!status_post_allowed("nope"));
    }

    #[test]
    fn firewall_text_must_be_exact() {
        assert!(firewall_ok("Firewall is disabled. (State = 0)\n"));
        for bad in [
            "",
            "Firewall is enabled. (State = 1)",
            "Firewall is disabled. (State = 0) x",
            "firewall is disabled. (State = 0)",
        ] {
            assert!(!firewall_ok(bad), "{bad}");
        }
    }

    #[test]
    fn leftover_patterns_cover_studio_binaries() {
        for l in [
            " 12 /x/wire_scan --a",
            " 12 /usr/sbin/tcpdump -i feth4202 -w p",
            " 12 /x/rmasscan-lab peer listen --open 8000",
            " 12 /x/rmasscan-lab capture dump",
            " 12 /x/Masscan Studio.app/Contents/MacOS/studio-ui --smoke-feth",
            " 12 /Library/PrivilegedHelperTools/MasscanStudio/ab/studio-runner",
            " 12 /usr/sbin/tcpdump -p -n -U -s 0 -i en0 -w uplink.pcap net 198.18.0.0/30",
        ] {
            assert!(is_leftover_proc(l, &[]), "{l}");
        }
        for l in [" 12 /usr/sbin/tcpdump -i en0", " 12 /bin/zsh"] {
            assert!(!is_leftover_proc(l, &[]), "{l}");
        }
        // only the orchestrator itself and its cargo parent are exempt, a second orchestrator is not
        assert!(!is_leftover_proc(
            " 12 /x/xtask feth-acceptance --app studio-ui",
            &[12]
        ));
        assert!(!is_leftover_proc(
            " 7 cargo xtask feth-acceptance --app studio-runner",
            &[12, 7]
        ));
        assert!(is_leftover_proc(
            " 99 /x/xtask feth-acceptance --app studio-ui",
            &[12, 7]
        ));
        assert_eq!(
            leftover_procs(" 1 /bin/zsh\n 2 studio-ui\n", &[]),
            " 2 studio-ui\n"
        );
        assert!(
            dry_leftover_procs(" 3 osascript -e do shell script with administrator privileges")
                .contains("osascript")
        );
        assert!(dry_leftover_procs(" 1 /bin/zsh\n").is_empty());
    }

    #[test]
    fn pair_quiet_refuses_only_when_every_window_moved() {
        let a = |n: u32| format!("feth4201 {n}\nfeth4202 {n}\n");
        assert!(!pair_quiet(&[a(1), a(2), a(3), a(4)]).ok);
        assert!(pair_quiet(&[a(1), a(2), a(2), a(3)]).ok);
        assert!(pair_quiet(&[a(1), a(1), a(1), a(1)]).ok);
        let r = pair_quiet(&[a(1), a(2), a(2), a(3)]);
        assert!(
            r.report.contains("window 2 (1 s): quiet")
                && r.report.contains("window 1 (1 s): moved")
        );
        assert!(!pair_quiet(&[a(1), String::new(), a(1)]).ok);
        assert!(!pair_quiet(&[a(1)]).ok);
    }

    #[test]
    fn interlock_reads_tcpdump_statistics() {
        let err = |c: &str, d: &str| {
            format!(
                "tcpdump: listening on en0, link-type EN10MB\n1 packet received by filter\n{c}\n{d}\n"
            )
        };
        let zero = err("0 packets captured", "0 packets dropped by kernel");
        assert_eq!(interlock(&zero, Some(24)), Interlock::Clean);
        assert!(matches!(
            interlock(
                &err("1 packet captured", "0 packets dropped by kernel"),
                Some(24)
            ),
            Interlock::Breach(_)
        ));
        assert!(matches!(
            interlock(
                &err("1 packets captured", "0 packets dropped by kernel"),
                Some(24)
            ),
            Interlock::Breach(_)
        ));
        assert!(matches!(
            interlock(
                &err("0 packets captured", "1 packet dropped by kernel"),
                Some(24)
            ),
            Interlock::Breach(_)
        ));
        assert!(matches!(interlock(&zero, Some(25)), Interlock::Breach(_)));
        assert!(matches!(interlock("", Some(100)), Interlock::Breach(_)));
        assert!(matches!(
            interlock("tcpdump: listening on en0\n", Some(24)),
            Interlock::Unproven(_)
        ));
        assert!(matches!(
            interlock("0 packets captured\n", Some(24)),
            Interlock::Unproven(_)
        ));
        assert!(matches!(interlock(&zero, None), Interlock::Unproven(_)));
        assert!(matches!(interlock(&zero, Some(0)), Interlock::Unproven(_)));
        assert_eq!(tcpdump_stats(&zero), Some((0, 0)));
    }

    #[test]
    fn paths_are_scrubbed_before_writing() {
        let rules = vec![
            ("/Users/me/out/win".to_owned(), "$OUT".to_owned()),
            ("/Users/me/repo".to_owned(), "$REPO".to_owned()),
            ("/Users/me".to_owned(), "$HOME".to_owned()),
        ];
        assert_eq!(
            scrub(
                "a /Users/me/out/win/x b /Users/me/repo/studio c /Users/me/.cargo",
                &rules
            ),
            "a $OUT/x b $REPO/studio c $HOME/.cargo"
        );
        assert_eq!(scrub("/ root", &[("/".into(), "$X".into())]), "/ root");
        assert_eq!(utc_text(951_868_801, 500), "2000-03-01T00:00:01.500Z");
        assert_eq!(utc_text(0, 0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn runner_of_the_bundle_must_be_installed_before_the_ui_starts() {
        let h = "a".repeat(64);
        assert!(check_installed(&h, Some(&h)).is_ok());
        let missing = check_installed(&h, None).unwrap_err();
        assert!(missing.contains("install the runner of this exact bundle first"));
        let other = check_installed(&h, Some(&"b".repeat(64))).unwrap_err();
        assert!(other.contains("differ"));
    }

    #[test]
    fn user_action_lines_are_one_chain_with_only_what_is_missing() {
        let b = user_action_b(
            "/r/xtask",
            Some("/r/studio/dist/runner-1"),
            "/l/rmasscan-lab",
            true,
            true,
        )
        .unwrap();
        assert_eq!(
            b,
            "'/r/xtask' install-runner '/r/studio/dist/runner-1' && sudo '/l/rmasscan-lab' macos-lab up --run-id m1 && sudo '/l/rmasscan-lab' macos-lab bpf-access --run-id m1 --grant"
        );
        assert_eq!(
            user_action_b("/s", None, "/l", false, true).unwrap(),
            "sudo '/l' macos-lab bpf-access --run-id m1 --grant"
        );
        assert!(user_action_b("/s", None, "/l", false, false).is_none());
        assert_eq!(
            user_action_f("/a b/l"),
            "sudo '/a b/l' macos-lab down --run-id m1"
        );
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn capture_commands_match_the_verifier_contract() {
        assert_eq!(
            capture_argv("en0", "uplink.pcap", Some(UPLINK_FILTER)),
            vec![
                "/usr/sbin/tcpdump",
                "-p",
                "-n",
                "-U",
                "-s",
                "0",
                "-i",
                "en0",
                "-w",
                "uplink.pcap",
                UPLINK_FILTER
            ]
        );
        assert_eq!(
            capture_argv("feth4202", "peer.pcap", Some(PEER_FILTER))
                .last()
                .unwrap(),
            PEER_FILTER
        );
        assert!(
            UPLINK_FILTER
                .starts_with("net 198.18.0.0/30 or (arp and (host 198.18.0.1 or host 198.18.0.2))")
        );
        assert!(UPLINK_FILTER.ends_with("or ether proto 0x88b5"));
        let r = cmd_record(
            &capture_argv("en0", "u.pcap", None),
            "en0",
            "",
            "A",
            "B",
            0,
            true,
        );
        for k in [
            "cmd",
            "interface",
            "filter",
            "start_utc",
            "stop_utc",
            "exit_code",
            "listening",
        ] {
            assert!(r.get(k).is_some(), "{k}");
        }
        assert!(dirty(" M x\n") && !dirty("\n"));
    }

    #[test]
    fn args_are_absolute_and_exclusive() {
        let v = |a: &[&str]| a.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        let o = parse_args(&v(&[
            "--out",
            "/o",
            "--app",
            "/a.app",
            "--lab",
            "/l",
            "--dry-run",
        ]))
        .unwrap();
        assert!(o.dry_run && !o.manual);
        assert!(parse_args(&v(&["--out", "o", "--app", "/a", "--lab", "/l"])).is_err());
        assert!(parse_args(&v(&["--out", "/o", "--app", "/a"])).is_err());
        assert!(
            parse_args(&v(&[
                "--out",
                "/o",
                "--app",
                "/a",
                "--lab",
                "/l",
                "--manual",
                "--dry-run"
            ]))
            .is_err()
        );
        assert!(parse_args(&v(&["--out", "/o", "--app", "/a", "--lab", "/l", "--x"])).is_err());
    }

    #[test]
    fn history_json_lists_rows_in_rowid_order_with_checkpoint_presence() {
        use studio_protocol::{Backend, Envelope, Event, Job, Row, Status};
        let dir = tmp("hist");
        let mut st = Store::open(&dir).unwrap();
        let (scan, attempt) = ([5; 16], [6; 16]);
        let job = Job {
            targets: "198.18.0.2".into(),
            ports: "8000-8002".into(),
            exclusions: String::new(),
            seed: "1".into(),
            rate: 100,
            backend: Backend::MacFeth,
        };
        st.begin(scan, attempt, &job, false).unwrap();
        let ev = |n, p| Envelope::new([1; 16], scan, attempt, n, p);
        let row = |port, open| Row {
            ip: "198.18.0.2".into(),
            port,
            open,
        };
        st.apply(&ev(1, Event::Started { total: "3".into() }))
            .unwrap();
        st.apply(&ev(
            2,
            Event::Results(vec![row(8002, true), row(8000, false)]),
        ))
        .unwrap();
        st.apply(&ev(3, Event::Results(vec![row(8001, true)])))
            .unwrap();
        st.apply(&ev(
            4,
            Event::Finished {
                status: Status::Completed,
                detail: "done".into(),
            },
        ))
        .unwrap();
        let h = history_json(&st).unwrap();
        let sc = &h["scans"][0];
        assert_eq!(sc["scan_id_hex"], id_text(scan));
        assert_eq!(sc["attempt_hex"], id_text(attempt));
        assert_eq!(sc["status"], "Completed");
        assert_eq!(sc["detail"], "done");
        assert_eq!(sc["checkpoint_len"], 0);
        assert!(sc["next_index"].is_null());
        assert_eq!(sc["job"]["seed"], "1");
        assert_eq!(sc["job"]["rate"], 100);
        assert_eq!(sc["job"]["backend"], "MacFeth");
        let ports: Vec<u64> = sc["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["port"].as_u64().unwrap())
            .collect();
        assert_eq!(ports, vec![8002, 8000, 8001]);
        assert_eq!(sc["rows"][0]["open"], true);
        assert!(sc["rows"][0]["discovered_at"].is_string());
        // a saved checkpoint shows as an integer length and an integer next_index
        let mut saved = st.scans().unwrap().remove(0);
        saved.checkpoint = Some(vec![1, 2, 3]);
        saved.next_index = Some("12".into());
        saved.status = Status::Paused;
        let j = scan_json(&saved, &[]);
        assert_eq!(j["checkpoint_len"], 3);
        assert_eq!(j["next_index"], 12);
        assert_eq!(j["status"], "Paused");
        drop(st);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn dry_verdict_accepts_only_an_authorization_failure() {
        let smoke = r#"{"result":"Authorization failed: Runner is not in its versioned installation directory","events":[{"kind":"Authorization","authorized":false}],"actions":[{"action":"Authorize"},{"action":"Lock"}]}"#;
        assert!(dry_verdict(Some(1), Some(smoke), "").is_empty());
        assert!(!dry_verdict(Some(0), Some(smoke), "").is_empty());
        assert!(!dry_verdict(None, Some(smoke), "").is_empty());
        assert!(!dry_verdict(Some(1), None, "").is_empty());
        assert!(
            !dry_verdict(
                Some(1),
                Some(&smoke.replace("Authorization failed", "ok")),
                ""
            )
            .is_empty()
        );
        assert!(!dry_verdict(Some(1), Some(&smoke.replace("false", "true")), "").is_empty());
        assert!(!dry_verdict(Some(1), Some(smoke), " 9 studio-runner").is_empty());
    }

    // ---- the flow with a fake host

    #[derive(Default)]
    struct Fake {
        ui_dead: bool,
        fail_ui_spawn: bool,
        poison_on_term: Option<String>,
        block_name: Option<String>,
        otool_out: Option<String>,
        blind_netstat: bool,
        silent_netstat: bool,
        netstat_rc: i32,
        lsof_out: Option<String>,
        netstat_out: Option<String>,
        log: Vec<String>,
        status: Option<(i32, String)>,
        installed: Option<String>,
        dirty: bool,
        uplink_err: String,
        uplink_pcap_len: usize,
        ui_rc: i32,
        ui_polls: VecDeque<bool>,
        procs: Vec<Spawn>,
        clock: u64,
        smoke: Option<String>,
        dir: PathBuf,
    }
    impl Host for Fake {
        fn run(&mut self, a: &[String]) -> Result<Done> {
            let a: &[String] = &if a.get(1).map(String::as_str) == Some("-C") {
                let mut v = a.to_vec();
                v.drain(1..3);
                v
            } else {
                a.to_vec()
            };
            self.log.push(format!("run {}", a.join(" ")));
            let ok = |o: &str| {
                Ok(Done {
                    rc: 0,
                    stdout: o.into(),
                    stderr: String::new(),
                })
            };
            let tool = a[0].rsplit('/').next().unwrap();
            match (tool, a.get(1).map(String::as_str)) {
                ("git", Some("rev-parse")) if a[2] == "HEAD" => {
                    ok(&format!("{}\n", "c".repeat(40)))
                }
                ("git", Some("rev-parse")) => ok("/work/repo\n"),
                ("git", Some("status")) => ok(if self.dirty { " M f\n" } else { "" }),
                ("rmasscan-lab", Some("macos-lab")) => {
                    let (rc, t) = self.status.clone().unwrap_or((0, GOOD.into()));
                    Ok(Done {
                        rc,
                        stdout: t,
                        stderr: String::new(),
                    })
                }
                ("rmasscan-lab", Some("--version")) => ok("rmasscan-lab 0.0\n"),
                ("socketfilterfw", _) => ok("Firewall is disabled. (State = 0)\n"),
                ("lsof", _) => Ok(Done {
                    rc: i32::from(self.lsof_out.is_none()),
                    stdout: self.lsof_out.clone().unwrap_or_default(),
                    stderr: String::new(),
                }),
                ("ps", _) => ok(" 1 /bin/zsh\n"),
                ("netstat", Some("-I")) => ok(&format!("{} 0\n", a[2])),
                ("netstat", _) if self.silent_netstat => ok(""),
                ("netstat", _) if self.netstat_rc != 0 => Ok(Done {
                    rc: self.netstat_rc,
                    stdout: String::new(),
                    stderr: String::new(),
                }),
                ("netstat", _) if self.blind_netstat => Ok(Done {
                    rc: 0,
                    stdout: String::new(),
                    stderr: "netstat: sysctl: net.inet.tcp.pcblist_n: Operation not permitted\n".into(),
                }),
                ("netstat", _) => ok(self.netstat_out.as_deref().unwrap_or("Active Internet connections (including servers)\ntcp4 0 0 *.22 *.* LISTEN\n")),
                ("sysctl", _) => ok("k: 1\n"),
                ("sw_vers", _) => ok("macOS\n"),
                ("otool", _) => ok(self.otool_out.as_deref().unwrap_or("x:\n\t/opt/homebrew/opt/sqlite/lib/libsqlite3.dylib (compat)\n\t/usr/lib/libSystem.B.dylib\n")),
                _ => Err(format!("unexpected {a:?}").into()),
            }
        }
        fn spawn(&mut self, s: &Spawn) -> Result<Proc> {
            self.log.push(format!("spawn {}", s.argv.join(" ")));
            let name = s.argv[0].rsplit('/').next().unwrap();
            if let Some(n) = self.block_name.take() {
                fs::create_dir_all(self.dir.join(n))?;
            }
            if name == "rmasscan-lab" {
                fs::write(self.dir.join("listeners-ready.txt"), "{}")?;
            } else if name == "tcpdump" {
                let who = if s.argv.contains(&"feth4202".to_owned()) {
                    "peer"
                } else {
                    "uplink"
                };
                let iface = if who == "peer" { "feth4202" } else { "en0" };
                fs::write(
                    self.dir.join(format!("{who}.pcap")),
                    vec![
                        0u8;
                        if who == "uplink" {
                            self.uplink_pcap_len
                        } else {
                            24
                        }
                    ],
                )?;
                let tail = if who == "uplink" {
                    self.uplink_err.clone()
                } else {
                    "0 packets captured\n0 packets dropped by kernel\n".into()
                };
                fs::write(
                    self.dir.join(format!("{who}.err")),
                    format!("tcpdump: listening on {iface}, link-type EN10MB\n{tail}"),
                )?;
            } else if name == "studio-ui" {
                if self.fail_ui_spawn {
                    return Err("cannot spawn studio-ui".into());
                }
                if let Some(t) = &self.smoke {
                    fs::write(self.dir.join("smoke.json"), t)?;
                }
                fs::write(self.dir.join("ui.log"), "ui\n")?;
                let data = self.dir.join("data");
                fs::create_dir_all(&data)?;
                drop(Store::open(&data).unwrap());
            }
            self.procs.push(s.clone());
            Ok(Proc {
                id: self.procs.len() - 1,
                pid: 100 + self.procs.len() as u32,
            })
        }
        fn wait(&mut self, p: Proc, t: Duration) -> Option<i32> {
            let name = self.procs[p.id].argv[0]
                .rsplit('/')
                .next()
                .unwrap()
                .to_owned();
            match name.as_str() {
                "studio-ui" => {
                    if self.ui_dead {
                        return Some(self.ui_rc);
                    }
                    if t.is_zero() {
                        return None;
                    }
                    if self.ui_polls.pop_front().unwrap_or(true) {
                        self.ui_dead = true;
                        Some(self.ui_rc)
                    } else {
                        None
                    }
                }
                // witnesses and listeners run until signalled
                _ => (self
                    .log
                    .iter()
                    .any(|l| l.starts_with(&format!("signal {} ", p.pid))))
                .then_some(0),
            }
        }
        fn signal(&mut self, p: Proc, sig: &str) -> Result<()> {
            self.log.push(format!("signal {} {sig}", p.pid));
            if sig == "TERM" {
                let breach = self.dir.join("ISOLATION-BREACH.txt").exists();
                self.log.push(format!("breach-file-exists={breach}"));
                if let Some(n) = &self.poison_on_term {
                    fs::create_dir_all(self.dir.join(n))?;
                }
            }
            Ok(())
        }
        fn sleep(&mut self, d: Duration) {
            self.log.push(format!("sleep {}", d.as_secs()));
        }
        fn utc(&mut self) -> String {
            self.clock += 1;
            utc_text(1_700_000_000 + self.clock, 0)
        }
        fn installed_runner_sha256(&mut self, _: &str) -> Option<String> {
            self.installed.clone()
        }
        fn prepare_runner(&mut self, _: &Path) -> Result<PathBuf> {
            self.log.push("prepare".into());
            Ok(PathBuf::from("/r/studio/dist/runner-1"))
        }
    }

    fn setup(tag: &str) -> (PathBuf, Opts, Fake, String) {
        let root = tmp(tag);
        let app = root.join("Masscan Studio.app");
        let macos = app.join("Contents/MacOS");
        fs::create_dir_all(&macos).unwrap();
        for n in ["studio-ui", "studio-runner", "studio-inspect"] {
            fs::write(macos.join(n), n).unwrap();
        }
        fs::write(
            root.join("manifest.json"),
            format!(r#"{{"source_commit":"{}","dirty":false}}"#, "c".repeat(40)),
        )
        .unwrap();
        let lab = root.join("rmasscan-lab");
        fs::write(&lab, "lab").unwrap();
        let out = root.join("out");
        let runner = sha_bytes(b"studio-runner");
        let f = Fake {
            installed: Some(runner.clone()),
            ui_rc: 0,
            uplink_err: "0 packets captured\n0 packets dropped by kernel\n".into(),
            uplink_pcap_len: 24,
            dir: fs::canonicalize(&root).unwrap().join("out"),
            ..Default::default()
        };
        (
            root,
            Opts {
                out,
                app,
                lab,
                manual: false,
                dry_run: false,
            },
            f,
            runner,
        )
    }

    fn spawned(f: &Fake) -> Vec<String> {
        f.log
            .iter()
            .filter(|l| l.starts_with("spawn "))
            .cloned()
            .collect()
    }

    #[test]
    fn a_missing_stand_is_not_run_and_prints_action_b_without_starting_anything() {
        let (root, o, mut f, _) = setup("nostand");
        f.status = Some((3, String::new()));
        f.installed = None;
        let rc = run(&mut f, &o).unwrap();
        assert_eq!(rc, 2);
        assert!(spawned(&f).is_empty(), "{:?}", f.log);
        assert!(
            !f.log
                .iter()
                .any(|l| l.contains("sudo") && l.starts_with("run ")),
            "the orchestrator never runs sudo"
        );
        let t = fs::read_to_string(o.out.join("NOT-RUN.txt")).unwrap();
        assert!(
            t.contains("install-runner '/r/studio/dist/runner-1' && sudo")
                && t.contains("macos-lab up --run-id m1 && sudo")
        );
        assert!(t.contains("bpf-access --run-id m1 --grant"));
        assert!(!o.out.join("provenance.json").exists() && !o.out.join("peer.pcap").exists());
        assert!(f.log.contains(&"prepare".to_owned()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dirty_tree_and_unready_gates_refuse_with_reasons_only() {
        let (root, o, mut f, _) = setup("dirty");
        f.dirty = true;
        assert_eq!(run(&mut f, &o).unwrap(), 2);
        let t = fs::read_to_string(o.out.join("NOT-RUN.txt")).unwrap();
        assert!(t.contains("tracked changes") && !t.contains("User action B"));
        assert!(spawned(&f).is_empty());
        // an out directory that is not empty is refused before anything runs
        let mut g = Fake {
            dir: f.dir.clone(),
            ..Default::default()
        };
        assert_eq!(run(&mut g, &o).unwrap(), 2);
        assert!(g.log.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    const NAMES: &[&str] = &[
        "status-pre.json",
        "status-post.json",
        "alf.txt",
        "leftover-listeners.txt",
        "leftover-procs.txt",
        "pair-quiet.txt",
        "sysctl.txt",
        "sw_vers.txt",
        "host-listen-before.txt",
        "host-listen-after.txt",
        "provenance.json",
        "listeners-ready.txt",
        "peer.pcap",
        "peer.err",
        "peer.cmd.json",
        "uplink.pcap",
        "uplink.err",
        "uplink.cmd.json",
        "ui.log",
        "ui_rc.txt",
        "smoke.json",
        "history.json",
        "data.sha256",
        "window.json",
        "hashes-before-copy.txt",
        "bundle-manifest.json",
    ];

    #[test]
    fn a_clean_window_writes_every_file_of_the_contract_in_order() {
        let (root, o, mut f, runner) = setup("clean");
        f.smoke = Some(r#"{"result":"ok"}"#.into());
        let rc = run(&mut f, &o).unwrap();
        assert_eq!(rc, 0, "{:?}", f.log);
        for n in NAMES {
            assert!(o.out.join(n).is_file(), "missing {n}");
        }
        assert!(!o.out.join("ISOLATION-BREACH.txt").exists());
        // order: listeners, peer witness, uplink witness, then the UI; the UI starts after the 2 s liveness wait
        let sp = spawned(&f);
        assert_eq!(sp.len(), 4, "{sp:?}");
        assert!(sp[0].contains("peer listen --open 8000-8007 --ready"));
        assert!(sp[1].contains("-i feth4202 -w peer.pcap") && !sp[1].contains("net 198.18"));
        assert!(sp[2].contains("-i en0 -w uplink.pcap net 198.18.0.0/30"));
        assert!(sp[3].ends_with("studio-ui --smoke-feth"));
        let ui = &f.procs[3];
        assert!(
            ui.env
                .iter()
                .any(|(k, v)| k == "STUDIO_SMOKE_OUT" && v.ends_with("/out"))
        );
        assert!(
            ui.env
                .iter()
                .any(|(k, v)| k == "STUDIO_DATA_DIR" && v.ends_with("/out/data"))
        );
        // witnesses are alive for 2 s before the UI starts and get 1 s of quiet after it exits
        let at = |p: &str| f.log.iter().position(|l| l.contains(p)).unwrap();
        let ui_at = at("studio-ui --smoke-feth");
        let sleeps_between =
            |a: usize, b: usize, s: &str| f.log[a..b].contains(&format!("sleep {s}"));
        assert!(sleeps_between(at("-w uplink.pcap"), ui_at, "2"));
        assert!(sleeps_between(ui_at, at("signal 102 INT"), "1"));
        // the witnesses were interrupted after the UI and the listeners last
        let sig: Vec<&String> = f.log.iter().filter(|l| l.starts_with("signal ")).collect();
        assert_eq!(sig.len(), 3, "{sig:?}");
        assert!(sig[0].ends_with(" INT") && sig[2].ends_with(" INT"));
        // timing contract: witnesses start before the UI and stop after it
        let w: Value =
            serde_json::from_slice(&fs::read(o.out.join("window.json")).unwrap()).unwrap();
        assert_eq!(w["ui_rc"], 0);
        assert_eq!(w["uplink"], "en0");
        assert_eq!(w["invalid_marks"], json!([]));
        let pc: Value =
            serde_json::from_slice(&fs::read(o.out.join("peer.cmd.json")).unwrap()).unwrap();
        let uc: Value =
            serde_json::from_slice(&fs::read(o.out.join("uplink.cmd.json")).unwrap()).unwrap();
        for c in [&pc, &uc] {
            assert_eq!(c["listening"], true);
            assert_eq!(c["exit_code"], 0);
            assert!(c["start_utc"].as_str().unwrap() < c["stop_utc"].as_str().unwrap());
        }
        assert_eq!(uc["filter"], UPLINK_FILTER);
        assert_eq!(pc["filter"], PEER_FILTER);
        assert_eq!(pc["cmd"].as_array().unwrap().last().unwrap(), PEER_FILTER);
        let p: Value =
            serde_json::from_slice(&fs::read(o.out.join("provenance.json")).unwrap()).unwrap();
        assert_eq!(p["installed_runner_sha256"], runner);
        assert_eq!(p["runner_sha256"], runner);
        assert_eq!(p["dirty"], false);
        assert_eq!(p["git_head"], "c".repeat(40));
        // the hash list covers every top-level file but itself and data/, and the SQLite copy has no journal
        let hashes = fs::read_to_string(o.out.join("hashes-before-copy.txt")).unwrap();
        assert!(!hashes.contains("data") || hashes.contains("data.sha256"));
        assert!(!hashes.contains("hashes-before-copy"));
        for n in NAMES.iter().filter(|n| **n != "hashes-before-copy.txt") {
            assert!(hashes.contains(&format!("  {n}\n")), "{n} not hashed");
        }
        let sum = fs::read_to_string(o.out.join("data.sha256")).unwrap();
        let db = fs::read(o.out.join("data/history.sqlite3")).unwrap();
        assert_eq!(sum, format!("{}  history.sqlite3\n", sha_bytes(&db)));
        assert!(
            !o.out.join("data/history.sqlite3-wal").exists()
                && !o.out.join("data/history.sqlite3-shm").exists()
        );
        assert!(
            fs::read_to_string(o.out.join("host-listen-before.txt"))
                .unwrap()
                .starts_with("rc 0\n")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_lab_frame_on_the_uplink_stops_everything_and_exits_13() {
        let (root, o, mut f, _) = setup("breach");
        f.smoke = Some(r#"{"result":"ok"}"#.into());
        f.uplink_pcap_len = 24 + 60;
        f.uplink_err = "1 packet captured\n0 packets dropped by kernel\n".into();
        f.ui_polls = VecDeque::from([false, false, false]);
        let rc = run(&mut f, &o).unwrap();
        assert_eq!(rc, 13);
        let b = fs::read_to_string(o.out.join("ISOLATION-BREACH.txt")).unwrap();
        assert!(b.contains("uplink"));
        assert!(
            f.log.iter().any(|l| l.ends_with(" TERM")),
            "the UI was stopped: {:?}",
            f.log
        );
        assert_eq!(
            f.log
                .iter()
                .filter(|l| l.starts_with("signal ") && l.ends_with(" INT"))
                .count(),
            3
        );
        let w: Value =
            serde_json::from_slice(&fs::read(o.out.join("window.json")).unwrap()).unwrap();
        assert!(
            w["invalid_marks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m.as_str().unwrap().contains("isolation breach"))
        );
        assert!(o.out.join("hashes-before-copy.txt").is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_uplink_statistics_trip_the_interlock_even_if_the_file_is_clean() {
        let (root, o, mut f, _) = setup("stats");
        f.smoke = Some(r#"{"result":"ok"}"#.into());
        f.uplink_err = "0 packets captured\n2 packets dropped by kernel\n".into();
        assert_eq!(run(&mut f, &o).unwrap(), 13);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_failing_ui_or_missing_statistics_is_an_abort_not_a_clean_window() {
        let (root, o, mut f, _) = setup("abort");
        f.smoke = Some(r#"{"result":"x"}"#.into());
        f.ui_rc = 1;
        assert_eq!(run(&mut f, &o).unwrap(), 10);
        fs::remove_dir_all(root).unwrap();
        let (root, o, mut f, _) = setup("nostats");
        f.smoke = Some(r#"{"result":"ok"}"#.into());
        f.uplink_err = String::new();
        assert_eq!(run(&mut f, &o).unwrap(), 10);
        let w: Value =
            serde_json::from_slice(&fs::read(o.out.join("window.json")).unwrap()).unwrap();
        assert!(
            w["invalid_marks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m.as_str().unwrap().contains("unproven"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dry_run_needs_no_runner_and_starts_only_the_ui() {
        let (root, mut o, mut f, _) = setup("dry");
        o.dry_run = true;
        f.installed = None;
        f.ui_rc = 1;
        f.smoke = Some(
            r#"{"result":"Authorization failed: not installed","events":[],"actions":[]}"#.into(),
        );
        let rc = run(&mut f, &o).unwrap();
        assert_eq!(rc, 0, "{:?}", f.log);
        let sp = spawned(&f);
        assert_eq!(sp.len(), 1);
        assert!(sp[0].ends_with("studio-ui --smoke-feth"));
        assert!(
            !f.log
                .iter()
                .any(|l| l.contains("macos-lab") || l.contains("tcpdump"))
        );
        let w: Value =
            serde_json::from_slice(&fs::read(o.out.join("window.json")).unwrap()).unwrap();
        assert_eq!(w["result"], "NOT RUN");
        assert!(
            !w["invalid_marks"].as_array().unwrap().is_empty(),
            "never promoted"
        );
        assert!(
            fs::read_to_string(o.out.join("dry-run.txt"))
                .unwrap()
                .contains("PASS")
        );
        assert!(o.out.join("smoke.json").is_file() && o.out.join("history.json").is_file());
        fs::remove_dir_all(root).unwrap();
        // an installed runner makes a dry run refuse: it would reach the administrator dialog
        let (root, mut o, mut f, _) = setup("dry2");
        o.dry_run = true;
        assert_eq!(run(&mut f, &o).unwrap(), 2);
        assert!(spawned(&f).is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    // ---- fix round 1

    #[test]
    fn pure_gates_of_round_one() {
        // the sqlite preflight
        assert!(links_apple_sqlite(
            "x:\n\t/usr/lib/libsqlite3.dylib (compat)\n"
        ));
        assert!(!links_apple_sqlite(
            "x:\n\t/opt/homebrew/opt/sqlite/lib/libsqlite3.dylib (c)\n\t/usr/lib/libSystem.B.dylib\n"
        ));
        // the bundle is bound to HEAD
        let head = "c".repeat(40);
        let m = |c: &str, d: bool| format!(r#"{{"source_commit":"{c}","dirty":{d}}}"#);
        assert_eq!(
            check_bundle_manifest(Some(&m(&head, false)), &head),
            Ok(false)
        );
        assert_eq!(
            check_bundle_manifest(Some(&m(&head, true)), &head),
            Ok(true)
        );
        assert!(check_bundle_manifest(Some(&m(&"d".repeat(40), false)), &head).is_err());
        assert!(check_bundle_manifest(None, &head).is_err());
        assert!(check_bundle_manifest(Some("{}"), &head).is_err());
        // lsof that could not run is not "no listeners"
        assert!(lsof_ok(0) && lsof_ok(1));
        assert!(!lsof_ok(-1) && !lsof_ok(2));
        let lsof = |l: &str| lsof_leftovers(&format!("rmasscan- 1 u 5u IPv4 0x1 0t0 {l}\n")).len();
        assert_eq!(lsof("TCP *:8003 (LISTEN)"), 1);
        assert_eq!(lsof("TCP 198.18.0.2:9000 (LISTEN)"), 1);
        assert_eq!(lsof("TCP 127.0.0.1:8003 (LISTEN)"), 0);
        assert_eq!(lsof("TCP *:5000 (LISTEN)"), 0);
        // leftover listeners come from the netstat record: 198.18.0.2 or a lab port on the wildcard
        let ns = "Active Internet connections (including servers)\n\
tcp4       0      0  *.5000                 *.*                    LISTEN\n\
tcp46      0      0  *.7000                 *.*                    LISTEN\n\
tcp6       0      0  *.8001                 *.*                    LISTEN\n\
tcp4       0      0  192.168.1.5.8002       *.*                    ESTABLISHED\n";
        assert!(leftover_listeners(ns).is_empty());
        assert_eq!(
            leftover_listeners(&format!("{ns}tcp4 0 0 198.18.0.2.9999 *.* LISTEN\n")).len(),
            1
        );
        assert_eq!(
            leftover_listeners(&format!("{ns}tcp46 0 0 *.8003 *.* LISTEN\n")).len(),
            1
        );
        // a blinded netstat (rc 0, empty stdout, reason on stderr) is not a record; a real one is
        let hdr = "Active Internet connections (including servers)\ntcp4 0 0 *.5000 *.* LISTEN\n";
        let done = |rc: i32, out: &str, err: &str| Done {
            rc,
            stdout: out.into(),
            stderr: err.into(),
        };
        assert!(netstat_record(&done(0, hdr, "")).1);
        assert!(!netstat_record(&done(0, "", "netstat: sysctl: Operation not permitted\n")).1);
        assert!(!netstat_record(&done(0, "", "")).1);
        assert!(!netstat_record(&done(0, "tcp4 0 0 *.22 *.* LISTEN\n", "")).1);
        assert!(!netstat_record(&done(1, hdr, "")).1);
        assert!(!netstat_record(&done(0, hdr, "boom\n")).1);
        let (text, _) = netstat_record(&done(0, "", "netstat: denied\n"));
        assert_eq!(text, "rc 0\n# stderr: netstat: denied\n");
        // a recorded stand that drifted needs no `up`
        let drift = status_pre(
            3,
            &GOOD
                .replace("true", "false")
                .replacen("\"ok\":false", "\"ok\":true", 1),
        );
        assert!(!drift.stand_missing, "{drift:?}");
        assert!(drift.reasons.iter().any(|r| r.contains("drift")));
    }

    #[test]
    fn action_b_uses_the_built_binary() {
        let b = user_action_b("/t/xtask", Some("/r/dist/runner-1"), "/l/lab", true, true).unwrap();
        assert!(b.starts_with(
            "'/t/xtask' install-runner '/r/dist/runner-1' && sudo '/l/lab' macos-lab up"
        ));
        assert!(!b.contains("cargo"));
    }

    #[test]
    fn a_failed_ui_spawn_stops_every_child_and_still_writes_the_window() {
        let (root, o, mut f, _) = setup("uifail");
        f.fail_ui_spawn = true;
        let rc = run(&mut f, &o).unwrap();
        assert_eq!(rc, 10, "{:?}", f.log);
        assert_eq!(f.procs.len(), 3);
        for (i, p) in f.procs.iter().enumerate() {
            let pid = 101 + i;
            assert!(
                f.log
                    .iter()
                    .any(|l| l.starts_with(&format!("signal {pid} INT"))),
                "{} left running",
                p.argv[0]
            );
        }
        let w: Value =
            serde_json::from_slice(&fs::read(o.out.join("window.json")).unwrap()).unwrap();
        assert!(
            w["invalid_marks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m.as_str().unwrap().contains("cannot spawn studio-ui"))
        );
        assert!(o.out.join("hashes-before-copy.txt").is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_failed_write_after_the_children_started_still_cleans_up() {
        let (root, o, mut f, _) = setup("writefail");
        f.smoke = Some(r#"{"result":"ok"}"#.into());
        f.block_name = Some("peer.cmd.json".into());
        let mut g = f;
        let rc = run(&mut g, &o).unwrap();
        assert_eq!(rc, 10, "{:?}", g.log);
        assert!(o.out.join("window.json").is_file());
        assert_eq!(
            g.log
                .iter()
                .filter(|l| l.starts_with("signal ") && l.ends_with(" INT"))
                .count(),
            3
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_breach_file_comes_first_and_rc_13_survives_a_failed_write() {
        let (root, o, mut f, _) = setup("breachfirst");
        f.smoke = Some(r#"{"result":"ok"}"#.into());
        f.uplink_pcap_len = 24 + 60;
        f.uplink_err = "1 packet captured\n0 packets dropped by kernel\n".into();
        f.ui_polls = VecDeque::from([false, false]);
        f.poison_on_term = Some("peer.cmd.json".into());
        let rc = run(&mut f, &o).unwrap();
        assert_eq!(rc, 13);
        let at = f.log.iter().position(|l| l.ends_with(" TERM")).unwrap();
        assert_eq!(f.log[at + 1], "breach-file-exists=true", "{:?}", f.log);
        assert!(o.out.join("ISOLATION-BREACH.txt").is_file());
        assert!(o.out.join("window.json").is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn apple_sqlite_is_not_run_before_anything_starts() {
        let (root, o, mut f, _) = setup("applesql");
        f.otool_out = Some("x:\n\t/usr/lib/libsqlite3.dylib (c)\n".into());
        assert_eq!(run(&mut f, &o).unwrap(), 2);
        assert!(spawned(&f).is_empty());
        let t = fs::read_to_string(o.out.join("NOT-RUN.txt")).unwrap();
        assert!(t.contains("SQLITE3_LIB_DIR=/opt/homebrew/opt/sqlite/lib"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_silent_netstat_proceeds_with_a_note_and_no_invalid_mark() {
        let (root, o, mut f, _) = setup("silentnet");
        f.silent_netstat = true;
        let rc = run(&mut f, &o).unwrap();
        assert!(!o.out.join("NOT-RUN.txt").exists(), "not run");
        assert!(!spawned(&f).is_empty());
        assert_ne!(rc, 2);
        let rec = fs::read_to_string(o.out.join("host-listen-before.txt")).unwrap();
        assert!(
            rec.contains("# not recorded: macOS hides the TCP table"),
            "{rec}"
        );
        let after = fs::read_to_string(o.out.join("host-listen-after.txt")).unwrap();
        assert!(after.contains("# not recorded:"), "{after}");
        if let Ok(w) = fs::read_to_string(o.out.join("INVALID.txt")) {
            assert!(!w.contains("host listeners not recorded"), "{w}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_leftover_file_holds_leftovers_only() {
        let (root, o, mut f, _) = setup("lsofprivacy");
        f.lsof_out = Some(
            "appA 1 u 5u IPv4 0x1 0t0 TCP *:5000 (LISTEN)\nappB 2 u 3u IPv4 0x2 0t0 TCP 127.0.0.1:11434 (LISTEN)\n"
                .into(),
        );
        run(&mut f, &o).unwrap();
        let t = fs::read_to_string(o.out.join("leftover-listeners.txt")).unwrap();
        assert!(t.is_empty(), "{t}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_failing_netstat_is_not_run() {
        let (root, o, mut f, _) = setup("blindnet");
        f.blind_netstat = true;
        assert_eq!(run(&mut f, &o).unwrap(), 2);
        assert!(spawned(&f).is_empty());
        let t = fs::read_to_string(o.out.join("NOT-RUN.txt")).unwrap();
        assert!(t.contains("host listeners not recorded"), "{t}");
        let rec = fs::read_to_string(o.out.join("host-listen-before.txt")).unwrap();
        assert!(
            rec.starts_with("rc 0\n") && rec.contains("# stderr: netstat: sysctl"),
            "{rec}"
        );
        fs::remove_dir_all(root).unwrap();
        let (root, o, mut f, _) = setup("rcnet");
        f.netstat_rc = 70;
        assert_eq!(run(&mut f, &o).unwrap(), 2);
        assert!(spawned(&f).is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_leftover_lab_listener_is_not_run() {
        // seen by lsof, with a blind netstat
        let (root, o, mut f, _) = setup("leftlsof");
        f.silent_netstat = true;
        f.lsof_out = Some("rmasscan- 9 u 5u IPv4 0x1 0t0 TCP *:8003 (LISTEN)\n".into());
        assert_eq!(run(&mut f, &o).unwrap(), 2);
        assert!(spawned(&f).is_empty());
        let t = fs::read_to_string(o.out.join("NOT-RUN.txt")).unwrap();
        assert!(t.contains("left over (lsof)"), "{t}");
        fs::remove_dir_all(root).unwrap();
        // seen in a valid netstat record
        let (root, o, mut f, _) = setup("leftnet");
        f.netstat_out = Some(
            "Active Internet connections (including servers)\ntcp4 0 0 *.8003 *.* LISTEN\n".into(),
        );
        assert_eq!(run(&mut f, &o).unwrap(), 2);
        assert!(spawned(&f).is_empty());
        let t = fs::read_to_string(o.out.join("NOT-RUN.txt")).unwrap();
        assert!(t.contains("left over (netstat)"), "{t}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_bundle_from_another_commit_is_not_run() {
        let (root, o, mut f, _) = setup("oldbundle");
        fs::write(
            root.join("manifest.json"),
            format!(r#"{{"source_commit":"{}","dirty":false}}"#, "d".repeat(40)),
        )
        .unwrap();
        assert_eq!(run(&mut f, &o).unwrap(), 2);
        assert!(spawned(&f).is_empty());
        assert!(
            fs::read_to_string(o.out.join("NOT-RUN.txt"))
                .unwrap()
                .contains("source_commit")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_sealed_but_drifted_stand_does_not_print_up() {
        let (root, o, mut f, _) = setup("drift");
        f.status = Some((
            3,
            GOOD.replace("\"raw_run_allowed\":true", "\"raw_run_allowed\":false"),
        ));
        f.installed = None;
        assert_eq!(run(&mut f, &o).unwrap(), 2);
        let t = fs::read_to_string(o.out.join("NOT-RUN.txt")).unwrap();
        assert!(!t.contains("macos-lab up"), "{t}");
        fs::remove_dir_all(root).unwrap();
    }
}
