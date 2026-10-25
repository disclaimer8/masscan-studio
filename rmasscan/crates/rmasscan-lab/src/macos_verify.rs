//! Offline verifier of the macOS `feth` stand evidence written by `macos-suite`.
//!
//! Portable on purpose: it reads files and compares bytes, nothing here needs macOS. It follows the
//! honesty rules of the Windows verifier (and reuses its checks): an incomplete capture is INVALID,
//! a missing result is NOT RUN, nothing is ever promoted to PASS, and a lab frame on the uplink or a
//! foreign SYN is a safety FAIL that no rerun can discard.
//!
//! Layout of a directory (written by the suite, listed again in its `README.md`):
//! `manifest.json`, `fixtures/manifest.json`, `runs/<tag>.<nonce>/`, `runs_discarded/`,
//! `runs_aborted/`. One run directory holds `run.json argv.json meta.json capture.json
//! status-pre.json status-post.json listeners.json hashes-before-copy.txt` and, depending on the
//! kind, `peer.pcap peer.err uplink.pcap uplink.err injector.json flood.json linkloss.json
//! counters.json checkpoint*.bin forge-argv.json stdout.txt stderr.txt`.
use crate::{
    link::{END_PAYLOAD, START_PAYLOAD, count_markers},
    pcap::Frames,
    verify::{
        self, Binding, Ctx, FAIL, INVALID, NOT_RUN, PASS, Run, array, ether, n, read_json, s, sha,
        tcp, truth,
    },
    windows_suite::parse_tcpdump,
    wire_suite::capture_complete,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

/// Schema of the per-run evidence (`macos_capture_schema` in the manifest, `capture_schema` in each
/// `capture.json`). A run must not be older than its manifest.
pub const CAPTURE_SCHEMA: u64 = 1;
/// Shown in `capture.json` where a witness is impossible because BPF access is denied.
pub const NO_WITNESS: &str = "none: /dev/bpf* is denied, so no capture can run";
const HASHES: &str = "hashes-before-copy.txt";

/// `r` and 32 hex digits, as produced by `windows_suite::nonce`.
pub(crate) fn valid_nonce(s: &str) -> bool {
    s.len() == 33 && s.starts_with('r') && s[1..].bytes().all(|b| b.is_ascii_hexdigit())
}
/// `<tag>.<nonce>` split at its last dot (a tag may contain dots).
pub(crate) fn split_dir_name(name: &str) -> Option<(&str, &str)> {
    let (tag, nonce) = name.rsplit_once('.')?;
    (!tag.is_empty() && valid_nonce(nonce)).then_some((tag, nonce))
}

/// The `src_mac_check` values of `wire_scan` that are evidence on the sealed stand: the explicit `--src-mac`
/// equals the NIC MAC the process could read (`explicit-equal`), or the OS hid the MAC (`os-masked`).
/// `override-foreign` (a MAC that differs from the NIC's was forced) and `unverified` (no reading at all)
/// are emitted too, and are not evidence here.
pub const SRC_MAC_CHECK_ACCEPTED: [&str; 2] = ["explicit-equal", "os-masked"];
/// The binding of the sealed stand, as the verifier pins it (the same values the suite plans with; a macOS test
/// asserts the two lists are equal, since this module must stay portable and cannot import them).
pub fn stand_binding() -> Value {
    json!({"iface":"feth4201","src_ip":"198.18.0.1","src_mac":"02:ac:00:00:00:01","router_mac":"02:ac:00:00:00:02",
        "peer_ip":"198.18.0.2","seed":1,"rate":100,"wait":3})
}
/// Clock tolerance, in seconds, between the tcpdump packet timestamps and the suite's own wall clock
/// (both are this host's clock; the margin covers the order of the two reads and tcpdump buffering).
pub const CLOCK_TOLERANCE_S: f64 = 2.0;

// ------------------------------------------------------------------ plan and arguments

/// The planned runs. Functional and perf are the Windows plans (same tags, cases and rates); the
/// failure plan is the Mac one: the two `perm_denied` runs come first because they need BPF access
/// denied, the rest need it granted.
pub fn planned(man: &Value) -> Vec<Value> {
    if man["plan"] != "failure" {
        return verify::planned(man);
    }
    let mut out = vec![
        json!({"tag":"perm_denied_scan","kind":"perm_denied","variant":"scan"}),
        json!({"tag":"perm_inventory_control","kind":"perm_denied","variant":"inventory"}),
    ];
    for sc in ["silent", "drain", "fullqueue", "load"] {
        out.push(json!({"tag":format!("stop_{sc}"),"kind":"stop","scenario":sc}));
    }
    out.push(json!({"tag":"overflow_queue","kind":"overflow_queue"}));
    out.push(json!({"tag":"rxloss","kind":"rxloss"}));
    for v in [
        "wrong_ports",
        "wrong_seed",
        "corrupt_next_index",
        "corrupt_checksum",
        "truncated",
        "empty",
        "future_format",
        "future_engine",
    ] {
        out.push(json!({"tag":format!("ckpt_{v}"),"kind":"ckpt_refuse","variant":v}));
    }
    out.push(json!({"tag":"linkloss","kind":"linkloss"}));
    out
}
/// The item as the shared (Windows) argument and case tables know it.
fn shared_item(it: &Value) -> Value {
    if it["kind"] == "perm_denied" {
        let mut x = it.clone();
        x["kind"] = json!("perm_restricted");
        x
    } else {
        it.clone()
    }
}
/// The kind name the shared lab-isolation checks use.
pub(crate) fn shared_kind(it: &Value) -> String {
    s(&shared_item(it)["kind"]).to_owned()
}
/// The case of an item. The Mac RX-loss run scans every port at 100000 pps so that the kernel's
/// closed-port RSTs (rate limited by the OS) are not what loads the reader; the load comes from the
/// peer side.
pub(crate) fn case_of(it: &Value) -> Option<Value> {
    let mut c = verify::kind_case(&shared_item(it))?;
    if it["kind"] == "rxloss" {
        c["ports"] = json!("1-65535");
        c["syn"] = json!(65535);
        c["rate"] = json!(100000);
    }
    Some(c)
}
pub(crate) fn arg_map(it: &Value, man: &Value, side: bool) -> BTreeMap<String, Value> {
    let mut a = verify::arg_map(&shared_item(it), man, side);
    if !side && it["kind"] == "rxloss" {
        a.insert("--ports".into(), json!("1-65535"));
        a.insert("--rate".into(), json!("100000"));
        a.insert("--rx-stall-ms".into(), json!("3000"));
    }
    a
}
/// The exact `wire_scan` argv of an item (`<any>` options take their value from `paths`).
pub fn expected_args(
    it: &Value,
    man: &Value,
    paths: &BTreeMap<String, String>,
) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (k, v) in arg_map(it, man, it["forge"] == true) {
        out.push(k.clone());
        if v == true {
            continue;
        }
        out.push(if v == "<any>" {
            paths
                .get(&k)
                .ok_or_else(|| format!("path required for {k}"))?
                .clone()
        } else {
            s(&v).to_owned()
        });
    }
    Ok(out)
}
/// Which `/dev/bpf*` state the gate must report for this item: `denied` for the two permission runs,
/// `granted` for everything else.
pub fn required_bpf_access(it: &Value) -> &'static str {
    if it["kind"] == "perm_denied" {
        "denied"
    } else {
        "granted"
    }
}
/// The uplink capture filter of the lab for a binding (everything the lab may emit).
pub fn uplink_filter(sm: &str, pm: &str) -> String {
    format!(
        "net 198.18.0.0/30 or (arp and (host 198.18.0.1 or host 198.18.0.2)) or ether host {sm} or ether host {pm} or ether proto 0x88b5"
    )
}
/// The same discard rule as the other suites: only unproven runs without a behaviour failure.
pub fn may_discard(verdict: &str, behaviour_fail: bool) -> bool {
    crate::windows_suite::may_discard(verdict, behaviour_fail)
}

// ------------------------------------------------------------------ run directories

/// The run directories of `tag` below `root/sub`.
pub(crate) fn run_dirs(root: &Path, sub: &str, tag: &str) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(root.join(sub)) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .and_then(split_dir_name)
                    .is_some_and(|(t, _)| t == tag)
        })
        .collect();
    v.sort();
    v
}

fn load_if_present(r: &mut Run, p: &Path) -> Option<(Frames, Vec<u8>)> {
    p.exists().then(|| verify::load_pcap(r, p)).flatten()
}

/// One capture of a run directory (`<stem>.pcap` and/or `<stem>.pcap.gz`), each judged on its own. A compressed
/// capture is decompressed in memory; one that cannot be read, or that disagrees with the plain file beside it, is a
/// tripped safety check (isolation is unproven), never a skipped one. The presence of one capture proves nothing
/// about another.
fn load_capture(r: &mut Run, d: &Path, stem: &str) -> Option<(Frames, Vec<u8>)> {
    let plain = load_if_present(r, &d.join(format!("{stem}.pcap")));
    let gz = d.join(format!("{stem}.pcap.gz"));
    if !gz.exists() {
        return plain;
    }
    let name = format!("{stem}.pcap.gz readable and consistent");
    let read = fs::read(&gz)
        .map_err(|e| e.to_string())
        .and_then(|z| crate::gunzip::gunzip(&z))
        .and_then(|b| crate::pcap::read_pcap_records(&b).map(|(_, f)| (f, b)));
    match read {
        Err(e) => {
            r.safety(&name, false, format!("{} is unreadable ({e}); isolation is unproven. Run `gunzip -k` on it in a copy and verify again", gz.display()));
            plain
        }
        Ok((frames, bytes)) => match plain {
            Some(p) if p.1 != bytes => {
                r.safety(&name, false, "the compressed and the plain capture differ");
                Some(p)
            }
            Some(p) => Some(p),
            None => Some((frames, bytes)),
        },
    }
}

/// Packets tcpdump stored or tried to store, from its own statistics. On macOS `packets received by filter` is the
/// count before the kernel filter (xnu `bd_rcount`), so it says nothing about lab frames and is never used for that:
/// only `captured` (what passed the lab filter) is.
fn captured_in(dir: &Path, err: &str) -> Option<u64> {
    let text = fs::read_to_string(dir.join(err)).ok()?;
    parse_tcpdump(&text)["captured"].as_u64()
}

/// Lab-isolation checks that need nothing but the pcaps and the binding: a frame on the uplink
/// (stored, or counted by tcpdump without being stored), a SYN that is not the scanner's, a scanner
/// SYN where none may exist. They cannot be hidden by a missing meta, an incomplete capture or a
/// wrong argv, and a tripped one makes the run FAIL for good.
fn safety(r: &mut Run, man: &Value, it: &Value, d: &Path, peer: Option<&Frames>) {
    let uplink = load_capture(r, d, "uplink");
    let gz_peer;
    let peer = match peer {
        Some(p) => Some(p),
        None if d.join("peer.pcap.gz").exists() => {
            gz_peer = load_capture(r, d, "peer");
            gz_peer.as_ref().map(|p| &p.0)
        }
        None => None,
    };
    // Judged against the stand's own binding, never the manifest's: a hand-edited manifest cannot make a
    // foreign SYN look like the scanner's.
    let mut pinned = man.clone();
    pinned["binding"] = stand_binding();
    verify::safety_checks(
        r,
        "uplink",
        &pinned,
        &shared_kind(it),
        peer,
        uplink.as_ref().map(|u| &u.0),
        captured_in(d, "uplink.err"),
    );
    // Known classification gap, kept on purpose (final review M3): on macOS the descriptor's drop
    // counter (`bd_dcount`) counts only packets that matched the lab filter, so a kernel drop on
    // the uplink capture is a lost LAB frame, while the safety walk above does not trip on it:
    // the capture-completeness check (`capture no drops`, further down) reports it as INVALID
    // (unproven, never PASS), and the live interlock in `macos_suite` refuses further raw runs.
    // That is fail-safe (the run cannot pass and nothing continues). It is practically
    // unreachable, since a drop needs a full store buffer and a full hold buffer of matching
    // frames, which would also be captured. `received by filter` stays informational.
}

// ------------------------------------------------------------------ evidence gate

fn flags_of(cmd: &[&str]) -> Option<(String, Vec<String>)> {
    // `tcpdump` or an absolute path ending in it; options of the witness only; the rest is the filter.
    let (first, av) = cmd.split_first()?;
    if first.rsplit('/').next() != Some("tcpdump") {
        return None;
    }
    let mut iface = None;
    let mut i = 0;
    let mut tail = Vec::new();
    while i < av.len() {
        match av[i] {
            "-i" => {
                if iface.is_some() {
                    return None;
                }
                iface = Some(av.get(i + 1)?.to_string());
                i += 2;
            }
            "-w" | "-s" => {
                av.get(i + 1)?;
                i += 2;
            }
            "-n" | "-U" | "-p" | "--immediate-mode" => i += 1,
            x if x.starts_with('-') => return None,
            _ => {
                tail.extend(av[i..].iter().map(|x| (*x).to_owned()));
                break;
            }
        }
    }
    Some((iface?, tail))
}
/// `who` is `peer` (every frame of the peer interface, no filter) or `uplink` (the default-route
/// interface of the status gate, the lab filter).
fn capture_command(c: &Value, who: &str, man: &Value, uplink: &str, b: &Binding) -> bool {
    let all: Vec<&str> = array(&c["cmd"]).iter().filter_map(Value::as_str).collect();
    let Some((iface, tail)) = flags_of(&all) else {
        return false;
    };
    let filter = s(&c["filter"]);
    if who == "peer" {
        iface == s(&man["stand"]["peer_if"])
            && !iface.is_empty()
            && tail.is_empty()
            && (filter.is_empty() || filter == "(none: every frame on the peer interface)")
    } else {
        let want = uplink_filter(&b.sm, &b.pm);
        !uplink.is_empty()
            && !uplink.starts_with("feth")
            && iface == uplink
            && filter == want
            && tail.join(" ") == want
    }
}

/// `hashes-before-copy.txt`: sha256sum format, every file of the directory but itself, each hash
/// recomputed from the copy.
fn hashes_match(d: &Path) -> Result<(), String> {
    let text = fs::read_to_string(d.join(HASHES)).map_err(|_| format!("{HASHES} missing"))?;
    let mut want = BTreeMap::new();
    for l in text.lines().filter(|l| !l.is_empty()) {
        let (h, name) = l.split_once("  ").ok_or("malformed hash line")?;
        if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("malformed hash for {name}"));
        }
        if Path::new(name).components().count() != 1 || name == HASHES {
            return Err(format!("bad name {name}"));
        }
        if want.insert(name.to_owned(), h.to_owned()).is_some() {
            return Err(format!("{name} listed twice"));
        }
    }
    let mut have = BTreeSet::new();
    for e in fs::read_dir(d).map_err(|e| e.to_string())?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name != HASHES {
            have.insert(name);
        }
    }
    let listed: BTreeSet<String> = want.keys().cloned().collect();
    if listed != have {
        let extra: Vec<_> = have.difference(&listed).collect();
        let gone: Vec<_> = listed.difference(&have).collect();
        return Err(format!("unlisted files {extra:?}, missing files {gone:?}"));
    }
    for (name, h) in &want {
        let bytes = fs::read(d.join(name)).map_err(|e| format!("{name}: {e}"))?;
        if sha(&bytes) != *h {
            return Err(format!(
                "{name} differs from its hash taken before the copy"
            ));
        }
    }
    Ok(())
}

fn witness_stats(r: &mut Run, who: &str, d: &Path, rec: &Value, interface_delta: &Value) {
    let st = fs::read_to_string(d.join(format!("{who}.err"))).map(|t| parse_tcpdump(&t));
    let Ok(st) = st else {
        r.add(&format!("{who}.err present"), NOT_RUN, "missing", false);
        return;
    };
    let recorded = &rec["tcpdump"];
    r.inv(
        &format!("{who} recorded tcpdump statistics equal {who}.err"),
        ["captured", "received", "dropped_kernel", "dropped_if"]
            .iter()
            .all(|k| recorded[k] == st[k]),
        recorded.to_string(),
    );
    let measured = ["captured", "dropped_kernel"]
        .iter()
        .all(|k| st[k].as_u64().is_some())
        && (st["dropped_if"].as_u64().is_some() || interface_delta.as_u64().is_some());
    r.inv(
        &format!("{who} tcpdump statistics measured"),
        measured,
        st.to_string(),
    );
}

#[allow(clippy::too_many_arguments)]
fn gate(
    r: &mut Run,
    man: &Value,
    it: &Value,
    ctx: &Ctx,
    cap: &Value,
    uplink: Option<&(Frames, Vec<u8>)>,
    dir_nonce: &str,
) {
    let b = &ctx.bind;
    let denied = it["kind"] == "perm_denied";
    let schema = cap["capture_schema"].as_u64().unwrap_or(0);
    r.inv(
        "capture schema not older than manifest",
        schema
            >= man["macos_capture_schema"]
                .as_u64()
                .unwrap_or(CAPTURE_SCHEMA)
                .max(1),
        schema,
    );
    let pre = read_json(ctx.d.join("status-pre.json"));
    let want_access = required_bpf_access(it);
    for name in ["status-pre", "status-post"] {
        let Some(v) = read_json(ctx.d.join(format!("{name}.json"))) else {
            r.add(name, NOT_RUN, "missing or invalid JSON", false);
            continue;
        };
        // `macos-lab status` never prints `isolation_violations` (that key is the Windows status's); absent is fine.
        let ok = v["raw_run_allowed"] == true
            && !truth(&v["isolation_violations"])
            && v["bpf_access"] == want_access;
        let label = format!("{name} allows a raw run with bpf_access {want_access}");
        if name == "status-pre" {
            // The gate refused: the evidence cannot show a run on a proven stand, so the run did not
            // happen as far as the verdict goes. Rerunnable.
            r.check(&label, ok, v.to_string(), NOT_RUN, false);
        } else {
            // The scanner ran; a stand that is no longer proven afterwards is INVALID (FAIL for a perf
            // cell, which therefore cannot be discarded and rerun), as on Windows.
            verify::gate_leg(r, man["plan"] == "perf", &label, ok, v.to_string());
        }
    }
    match read_json(ctx.d.join("listeners.json")) {
        None => r.add("listeners", NOT_RUN, "missing or invalid JSON", false),
        Some(v) => {
            let mut op: Vec<_> = array(&v["open"]).iter().filter_map(Value::as_u64).collect();
            op.sort_unstable();
            let mut want: Vec<u64> = verify::open_ports().into_iter().map(u64::from).collect();
            want.sort_unstable();
            // Darwin completes the handshake whatever the listen queue holds (`net.inet.tcp.syncookie`), so a
            // silent port cannot exist on the Mac stand: none is asked for, none is claimed, and the reason and
            // the observed sysctl value are part of the evidence. 8099 and 8100-8119 are ordinary closed ports.
            r.inv(
                "listeners valid before/after run (8000-8007 ready; no silent port on the Mac)",
                op == want
                    && v["ready"] == true
                    && v["silent"] == json!([])
                    && v["silent_proven"].is_null()
                    && v["silent_unavailable"] == "darwin-syncookies"
                    && v["syncookie"]
                        .as_str()
                        .is_some_and(|c| c.trim().parse::<u64>().is_ok()),
                v.to_string(),
            );
        }
    }
    // Nothing runs as root: the recorded effective uid must be there and not 0.
    let euid = ctx.meta["euid"].as_u64();
    let unprivileged = euid.is_some_and(|u| u != 0);
    if denied && euid == Some(0) {
        r.beh(
            "the suite ran unprivileged (recorded effective uid is not 0)",
            false,
            "euid 0",
        );
    } else {
        r.inv(
            "the suite ran unprivileged (recorded effective uid is not 0)",
            unprivileged,
            ctx.meta["euid"].to_string(),
        );
    }
    r.inv(
        "run.json carries this invocation's nonce",
        ctx.rj["invocation_nonce"].as_str() == Some(nonce_of(ctx)),
        ctx.rj["invocation_nonce"].to_string(),
    );
    // The invocation: directory name, argv record and meta name the same nonce, and every file is
    // the one hashed before the copy.
    let nonce = ctx.meta["invocation_nonce"].as_str().unwrap_or("");
    let argv_nonce =
        read_json(ctx.d.join("argv.json")).map(|v| s(&v["invocation_nonce"]).to_owned());
    r.inv(
        "invocation nonce is the directory's, the meta's and the argv record's",
        valid_nonce(nonce) && nonce == dir_nonce && argv_nonce.as_deref() == Some(nonce),
        nonce,
    );
    match hashes_match(&ctx.d) {
        Ok(()) => r.add(
            "every file equals its hash taken before the copy",
            PASS,
            "",
            false,
        ),
        Err(e) => r.add(
            "every file equals its hash taken before the copy",
            INVALID,
            e,
            false,
        ),
    }
    let ts: Vec<_> = [
        "capture_started_utc",
        "guest_started_utc",
        "guest_finished_utc",
        "capture_stopped_utc",
    ]
    .iter()
    .map(|k| verify::f(&ctx.meta[k]))
    .collect();
    let ts_ok = ts.iter().all(|x| x.is_finite()) && ts.windows(2).all(|w| w[0] <= w[1]);
    if denied {
        // No capture can exist while BPF is denied; the witness is the scanner's own refusal plus the
        // interface counters, which are readable without BPF.
        r.inv(
            "no witness claimed while BPF is denied",
            cap["peer"].is_null() && cap["uplink"].is_null(),
            cap["peer"].to_string(),
        );
        // The counters are the only witness of this run: the readings must enclose the scanner.
        let cj = read_json(ctx.d.join("counters.json")).unwrap_or(Value::Null);
        let (b0, a1) = (verify::f(&cj["before_utc"]), verify::f(&cj["after_utc"]));
        r.inv(
            "the counter readings enclose the scanner run (before <= start, end <= after)",
            ts[1].is_finite()
                && ts[2].is_finite()
                && ts[1] <= ts[2]
                && b0.is_finite()
                && a1.is_finite()
                && b0 <= ts[1]
                && ts[2] <= a1,
            format!("before {b0}, scanner {} .. {}, after {a1}", ts[1], ts[2]),
        );
        return;
    }
    r.inv("capture encloses scanner in UTC", ts_ok, format!("{ts:?}"));
    let uplink_if = pre.as_ref().map_or("", |v| s(&v["uplink"]));
    for (who, p) in [("peer", &ctx.peer), ("uplink", &uplink.cloned())] {
        let c = &cap[who];
        r.inv(
            &format!("{who} capture interface and filter are exact"),
            capture_command(c, who, man, uplink_if, b),
            c["cmd"].to_string(),
        );
        let Some((fr, data)) = p else { continue };
        let rec = &c["pcap"];
        r.inv(
            &format!("{who} pcap hash, size and count"),
            rec["sha256"] == sha(data)
                && n(&rec["size"]) == data.len() as i128
                && n(&rec["frames"]) == fr.len() as i128,
            rec.to_string(),
        );
        witness_stats(r, who, &ctx.d, c, &c["interface_drop_delta"]);
        let st = &c["tcpdump"];
        let delta = c["interface_drop_delta"].as_u64();
        let dropped_if = st["dropped_if"].as_u64().or(delta);
        r.inv(
            &format!("{who} capture no drops and all frames accounted"),
            st["dropped_kernel"] == 0
                && dropped_if == Some(0)
                && delta.is_none_or(|d| d == 0)
                && n(&st["captured"]) == fr.len() as i128,
            format!("{st} interface_drop_delta {}", c["interface_drop_delta"]),
        );
        r.inv(
            &format!("{who} listening before the scanner"),
            c["listening"] == true,
            "",
        );
        if who == "uplink" {
            // The suite stops it with SIGINT and treats only exit 0 as clean.
            r.inv(
                "uplink tcpdump exited cleanly after the stop (exit code 0)",
                c["exit_code"].as_i64() == Some(0),
                c["exit_code"].to_string(),
            );
        }
        if who == "uplink" {
            r.inv(
                "uplink tcpdump is not promiscuous (the user's own NIC)",
                array(&c["cmd"]).iter().any(|v| v == "-p"),
                c["cmd"].to_string(),
            );
        }
        r.inv(
            &format!("{who} tcpdump in immediate mode"),
            array(&c["cmd"]).iter().any(|v| v == "--immediate-mode"),
            "",
        );
    }
    if let Some((fr, _)) = &ctx.peer {
        let w = &cap["peer"]["witness"];
        let lo = w["iface_rxtx_delta_lo"].as_u64();
        let hi = w["iface_rxtx_delta_hi"].as_u64();
        let st = &cap["peer"]["tcpdump"];
        r.inv(
            "peer interface counter window encloses the capture",
            matches!((lo, hi), (Some(lo), Some(hi)) if lo <= fr.len() as u64 && fr.len() as u64 <= hi),
            w.to_string(),
        );
        r.inv(
            "peer capture complete (captured, kernel drops, counter window; received-by-filter is information only on macOS)",
            capture_complete(
                st["captured"].as_u64(),
                st["captured"].as_u64(),
                st["dropped_kernel"].as_u64(),
                st["dropped_if"]
                    .as_u64()
                    .or(cap["peer"]["interface_drop_delta"].as_u64()),
                fr.len() as u64,
                lo.unwrap_or(u64::MAX),
                hi.unwrap_or(0),
            ),
            st.to_string(),
        );
        // Freshness: every packet belongs to this run's capture window (start .. stop, with the clock
        // tolerance), and the order is start markers, then scanner traffic, then end markers. A hash proves
        // the bytes are the ones copied, not that they were captured now.
        let (t0, t1) = (ts[0], ts[3]);
        let outside = fr
            .iter()
            .filter(|(t, _)| !(t0 - CLOCK_TOLERANCE_S..=t1 + CLOCK_TOLERANCE_S).contains(t))
            .count();
        r.inv(
            "capture packets fall inside the recorded window",
            t0.is_finite() && t1.is_finite() && outside == 0,
            format!(
                "{outside} of {} packets outside {t0} .. {t1} (+-{CLOCK_TOLERANCE_S} s)",
                fr.len()
            ),
        );
        let marker_times = |payload: &[u8]| -> Vec<f64> {
            fr.iter()
                .filter(|(_, f)| {
                    ether(f, [0x88, 0xb5]) && f.get(14..14 + payload.len()) == Some(payload)
                })
                .map(|(t, _)| *t)
                .collect()
        };
        let (starts, ends) = (marker_times(START_PAYLOAD), marker_times(END_PAYLOAD));
        let scanner: Vec<f64> = fr
            .iter()
            .filter(|(_, f)| tcp(f).is_some_and(|i| i.sm == b.sm && i.dm == b.pm))
            .map(|(t, _)| *t)
            .collect();
        let min = |v: &[f64]| v.iter().copied().fold(f64::INFINITY, f64::min);
        let max = |v: &[f64]| v.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        r.inv(
            "start markers, then scanner traffic, then end markers",
            !starts.is_empty()
                && !ends.is_empty()
                && (scanner.is_empty()
                    || (max(&starts) <= min(&scanner) && max(&scanner) <= min(&ends)))
                && max(&starts) <= min(&ends),
            format!(
                "start .. {}, scanner {} .. {}, end {} ..",
                max(&starts),
                min(&scanner),
                max(&scanner),
                min(&ends)
            ),
        );
        let it_ = || fr.iter().map(|(_, f)| f.as_slice());
        r.inv(
            "start marker captured before the scanner",
            count_markers(it_(), START_PAYLOAD) >= 1,
            "",
        );
        let end = fr
            .iter()
            .filter(|(_, f)| {
                ether(f, [0x88, 0xb5]) && f.get(14..14 + END_PAYLOAD.len()) == Some(END_PAYLOAD)
            })
            .map(|(t, _)| *t)
            .fold(f64::NEG_INFINITY, f64::max);
        // The lab listeners are stopped only after the witness, so a SYN-ACK retransmit of a reply the scanner
        // already had can land after the last end marker. That is a post-run note; any other frame is a tail that
        // was not flushed (INVALID).
        let synacked: BTreeSet<u16> = fr
            .iter()
            .filter(|(t, _)| *t <= end)
            .filter_map(|(_, f)| tcp(f))
            .filter(|i| i.sm == b.pm && i.dm == b.sm && i.dst == b.src && i.flags & 0x12 == 0x12)
            .map(|i| i.sp)
            .collect();
        let (mut late, mut unexplained) = (0usize, 0usize);
        for (t, f) in fr {
            if *t > end && !ether(f, [0x88, 0xb5]) {
                if tcp(f).is_some_and(|i| {
                    i.sm == b.pm
                        && i.dm == b.sm
                        && i.dst == b.src
                        && i.flags & 0x12 == 0x12
                        && synacked.contains(&i.sp)
                }) {
                    late += 1;
                } else {
                    unexplained += 1;
                }
            }
        }
        if late > 0 {
            r.notes.insert(
                "post_run_synack_retransmits".into(),
                json!({"count":late,"kind":"post-run (lab SYN-ACK retransmit after the last end marker)"}),
            );
        }
        r.inv(
            "three end markers and a flushed capture tail",
            count_markers(it_(), END_PAYLOAD) >= 3 && unexplained == 0,
            format!("{unexplained} unexplained frames after the last end marker"),
        );
        r.inv(
            "capture reached quiescence",
            cap["quiet"]["reached"] == true && w["quiesced_before_stop"] == true,
            cap["quiet"].to_string(),
        );
        r.inv(
            "the witness judged its own capture valid",
            w["valid"] == true,
            w["invalid_reasons"].to_string(),
        );
    }
}

fn nonce_of(ctx: &Ctx) -> &str {
    ctx.meta["invocation_nonce"].as_str().unwrap_or("")
}

/// A permission run with BPF denied has no capture, so it is judged on the scanner's refusal and
/// on the interface counters, which are readable without BPF. Counters that moved make the zero
/// frames unprovable (INVALID, rerunnable); they never turn a refusal into a PASS by themselves.
fn permission(r: &mut Run, ctx: &Ctx, it: &Value, man: &Value) {
    let j = &ctx.rj;
    let rc = n(&ctx.meta["guest_exit"]);
    if it["variant"] == "inventory" {
        r.beh(
            "inventory under denied BPF exits zero, opens no adapter, sends nothing",
            rc == 0
                && j["mode"] == "inventory"
                && j["opened_adapter"] == false
                && j["tx_sent"] == 0,
            j["mode"].to_string(),
        );
    } else {
        verify::job(r, j, &verify::case_by_name("pb_perm_scan").unwrap(), man);
        let e = s(&j["error"]).split('(').next().unwrap_or("");
        r.beh(
            "denied scan refuses with PermissionDenied before opening an adapter or sending",
            rc == 5
                && j["status"] == "error"
                && e == "PermissionDenied"
                && j["opened_adapter"] == false
                && j["tx_sent"] == 0,
            j["error"].to_string(),
        );
    }
    match read_json(ctx.d.join("counters.json")) {
        None => r.add("counters.json present", NOT_RUN, "missing", false),
        Some(c) => {
            let d = |side: &str, iface: &str, k: &str| -> Option<i128> {
                Some(
                    i128::from(c[side][iface][k].as_u64()?)
                        - i128::from(c["before"][iface][k].as_u64()?),
                )
            };
            let scanner_out = d("after", s(&man["stand"]["scanner_if"]), "opkts");
            let peer_in = d("after", s(&man["stand"]["peer_if"]), "ipkts");
            r.inv(
                "no frame crossed the pair while BPF was denied (interface counters)",
                scanner_out == Some(0) && peer_in == Some(0),
                format!("scanner opkts delta {scanner_out:?}, peer ipkts delta {peer_in:?}"),
            );
        }
    }
    if let Some((fr, _)) = &ctx.peer {
        r.cap(
            "no scanner SYN while BPF is denied",
            verify::syns(fr, &ctx.bind, (1, 65535)).is_empty(),
            "",
        );
    }
}

/// RX loss, Mac form: the load comes from the peer side (frames on the lab marker ethertype), so
/// the independent upper bound on the drops is the flood plus the genuine replies on the wire.
fn rxloss(r: &mut Run, ctx: &Ctx, c: &Value, man: &Value) {
    let j = &ctx.rj;
    verify::job(r, j, c, man);
    let claimed = j["reason"] == "Failed" && s(&j["fail_detail"]).contains("RxLoss");
    let measured = j["rx_health"]["kernel_drops"].as_u64();
    // An unknown count, or an RxLoss failure that names drops the receive health does not show, is a
    // finding about the scanner. A scan that simply lost nothing is "not reproduced".
    if measured.is_none() || (claimed && measured == Some(0)) {
        r.beh(
            "RX loss is backed by measured kernel drops above zero",
            false,
            format!("rx_health {}, outcome {}", j["rx_health"], j["fail_detail"]),
        );
        return;
    }
    let Some(drops) = measured.filter(|x| *x > 0) else {
        r.add(
            "RX overflow reproduced with measured drops",
            NOT_RUN,
            format!("NOT REPRODUCED: {}", j["rx_health"]),
            false,
        );
        return;
    };
    let exp = verify::replies(c, false);
    verify::rxloss_genuine(r, ctx, drops, &exp);
    r.beh(
        "RX loss has no checkpoint summary, hex or file",
        j["checkpoint"] == false
            && j["checkpoint_hex"].is_null()
            && ctx.meta["checkpoint_file_exists"] == false,
        "",
    );
    r.beh(
        "TX frozen after RX failure",
        verify::frozen(j),
        j["net"].to_string(),
    );
    verify::workers(r, j);
    let fl = read_json(ctx.d.join("flood.json"));
    let replies_on_wire = ctx.peer.as_ref().map(|(fr, _)| {
        fr.iter()
            .filter(|(_, f)| tcp(f).is_some_and(|i| i.sm == ctx.bind.pm && i.dm == ctx.bind.sm))
            .count() as u64
    });
    match (&fl, replies_on_wire) {
        (Some(fl), Some(wire)) => {
            r.beh(
                "drops cannot exceed the peer flood plus the genuine replies on the wire",
                fl["sent"].as_u64().is_some_and(|x| drops <= x + wire),
                format!("drops {drops}, flood {}, replies {wire}", fl["sent"]),
            );
        }
        _ => r.add(
            "independent flood and wire inputs present",
            NOT_RUN,
            "missing",
            false,
        ),
    }
    let end = verify::align(r, ctx, c, false);
    if ctx.peer.is_some() {
        verify::flood(r, ctx, c, end, false);
    }
}

/// Link loss needs the user: the suite only watches the peer interface, the one `macos-lab link --down`
/// takes down (the scanner side's media state is recorded next to each event). No `down` event of the
/// peer interface means the user did not act, which is NOT RUN, never a failure of the scanner.
///
/// PROVISIONAL (until the spike pins the Mac failure class, as Windows pins `TxUncertain`): a down
/// observed during the scan must end in a failure whose detail names a TX or link class. A scan that
/// completed anyway, or failed for another reason (RxLoss, ConsumerTooSlow, ...), is INVALID, not a
/// verdict on the scanner.
fn linkloss(r: &mut Run, ctx: &Ctx, c: &Value, man: &Value) {
    let j = &ctx.rj;
    verify::job(r, j, c, man);
    let ll = read_json(ctx.d.join("linkloss.json"));
    let events = ll
        .as_ref()
        .map(|l| array(&l["events"]).to_vec())
        .unwrap_or_default();
    let peer_if = s(&man["stand"]["peer_if"]);
    let on_peer = |e: &&Value| !peer_if.is_empty() && s(&e["iface"]) == peer_if;
    let down = events.iter().filter(on_peer).find(|v| v["link"] == "down");
    let up = events.iter().filter(on_peer).find(|v| v["link"] == "up");
    let (Some(down), true) = (down, ll.is_some()) else {
        r.add(
            "link-down event of the peer interface observed",
            NOT_RUN,
            "user action not performed",
            false,
        );
        return;
    };
    let detail = s(&j["fail_detail"]);
    let named = detail.contains("Tx") || detail.contains("TX") || detail.contains("Link");
    if j["reason"] != "Failed" || !named {
        r.inv(
            "a link-down during the scan ends in a failure naming a TX or link class (provisional)",
            false,
            format!("reason {}, detail {detail:?}", j["reason"]),
        );
        return;
    }
    r.beh(
        "link loss fails the run, partial scan, no checkpoint",
        ctx.meta["guest_exit"] == 3
            && j["checkpoint"] == false
            && j["checkpoint_hex"].is_null()
            && n(&j["sent"]) > 0
            && n(&j["sent"]) < n(&j["range"])
            && (n(&j["net"]["tx_uncertain"]) >= 1 || n(&j["net"]["tx_errors"]) >= 1),
        detail,
    );
    r.beh(
        "uncertain TX not retried or counted, confirmed TX frozen",
        verify::frozen(j),
        j["net"].to_string(),
    );
    r.beh(
        "no checkpoint file",
        ctx.meta["checkpoint_file_exists"] == false,
        "",
    );
    verify::workers(r, j);
    let end = verify::align(r, ctx, c, true);
    r.inv(
        "link restored after the failure",
        up.is_some_and(|u| verify::f(&u["t"]) > verify::f(&down["t"])),
        ll.map_or(String::new(), |l| l.to_string()),
    );
    if let Some(e) = end {
        let lag = e - verify::f(&down["t"]);
        r.notes
            .insert("down_to_outcome_ms".into(), json!(lag * 1000.));
        r.inv(
            "failure follows the disconnect",
            (-0.5..10.).contains(&lag),
            lag,
        );
    }
}

fn verify_argv(r: &mut Run, it: &Value, man: &Value, d: &Path) {
    let mut ok = true;
    for (side, name) in [(false, "argv.json"), (true, "forge-argv.json")] {
        if side && it["kind"] != "refuse_completed" && it["kind"] != "ckpt_refuse" {
            continue;
        }
        let Some(av) = read_json(d.join(name)) else {
            r.add(name, NOT_RUN, "missing or invalid JSON", false);
            ok = false;
            continue;
        };
        let want = arg_map(it, man, side);
        let good = verify::parse_args(&av).is_ok_and(|got| {
            got.len() == want.len()
                && want.iter().all(|(k, v)| {
                    got.get(k).is_some_and(|g| {
                        g == v || (v == "<any>" && g.as_str().is_some_and(|s| !s.is_empty()))
                    })
                })
        });
        ok = r.check(
            &format!("{name} matches run kind definition"),
            good,
            av.to_string(),
            INVALID,
            false,
        ) && ok;
    }
    r.argv_ok = ok;
}

/// The injected foreign frames and the genuine kernel replies are told apart by content: the injector records the
/// sha256 of each frame it wrote, and every frame on the wire that looks like one (IP id 0xf0e1) must be one of them.
/// What is left is the genuine reply set that the results are judged against.
fn injected_identities(r: &mut Run, ctx: &Ctx) {
    let (Some(inj), Some((fr, _))) = (read_json(ctx.d.join("injector.json")), &ctx.peer) else {
        return;
    };
    let known: BTreeSet<String> = inj["injected"]
        .as_object()
        .map(|m| m.values().map(|v| s(v).to_owned()).collect())
        .unwrap_or_default();
    let unknown = fr
        .iter()
        .filter(|(_, f)| tcp(f).is_some_and(|i| i.id == 0xf0e1))
        .filter(|(_, f)| !known.contains(&sha(f)))
        .count();
    r.inv(
        "every frame marked as injected (IP id 0xf0e1) on the wire is one the injector recorded writing",
        !known.is_empty() && unknown == 0,
        format!("{} recorded, {unknown} unrecorded on the wire", known.len()),
    );
}

/// Everything the lab wrote from the peer side went through the guard: no refused frame, and (injector) no
/// "other IP" reply, which would come from 198.18.0.3 and which the guard forbids on macOS.
fn guard_clean(r: &mut Run, ctx: &Ctx, file: &str, injector: bool) {
    let Some(v) = read_json(ctx.d.join(file)) else {
        return; // a missing record is reported by the check that needs it
    };
    r.inv(
        &format!("{file}: the peer-side guard refused no frame"),
        v["guard_refused"].as_u64() == Some(0),
        v["guard_refused"].to_string(),
    );
    if injector {
        r.inv(
            "injector.json: no other_ip reply was written (the guard forbids 198.18.0.3 on macOS)",
            v["kinds"]
                .get("other_ip")
                .is_none_or(|k| k.as_u64() == Some(0)),
            v["kinds"].to_string(),
        );
    }
}

/// The manifest's binding and stand interfaces are exactly the stand's.
fn binding_is_stand(man: &Value) -> bool {
    man["binding"] == stand_binding()
        && man["stand"]["scanner_if"] == "feth4201"
        && man["stand"]["peer_if"] == "feth4202"
}

/// A scan summary (status ok, a `reason`, a job, the wall clock and the MAC check), as against the other things
/// `wire_scan` prints: the inventory summary (`mode`), a refused start (`status` error) and a forged checkpoint.
fn is_scan_summary(j: &Value) -> bool {
    j["status"] == "ok" && j.get("mode").is_none() && j.get("reason").is_some()
}

/// `run.json` is the scanner's own stdout line plus the suite's nonce, and the scanner's own wall clock (the same
/// host clock) lies inside the window the suite recorded for the scanner, within the clock tolerance.
fn bind_run_json(r: &mut Run, ctx: &Ctx) {
    let line = fs::read_to_string(ctx.d.join("stdout.txt"))
        .ok()
        .and_then(|t| {
            t.trim_start_matches('\u{feff}')
                .lines()
                .rev()
                .find(|l| l.starts_with('{'))
                .and_then(|l| serde_json::from_str::<Value>(l).ok())
        });
    let mut bare = ctx.rj.clone();
    if let Some(o) = bare.as_object_mut() {
        o.remove("invocation_nonce");
    }
    r.inv(
        "run.json is the scanner's stdout line plus the nonce",
        line.as_ref() == Some(&bare),
        "stdout.txt missing, unparseable or different from run.json",
    );
    let wall = &ctx.rj["wall"];
    if wall.is_object() {
        let (t0, t1) = (
            verify::f(&wall["t0_utc_ms"]) / 1000.,
            verify::f(&wall["outcome_utc_ms"]) / 1000.,
        );
        let (g0, g1) = (
            verify::f(&ctx.meta["guest_started_utc"]),
            verify::f(&ctx.meta["guest_finished_utc"]),
        );
        let tol = CLOCK_TOLERANCE_S;
        r.inv(
            "scanner wall clock inside the run window",
            [t0, t1, g0, g1].iter().all(|x| x.is_finite())
                && t0 >= g0 - tol
                && t1 <= g1 + tol
                && t0 <= t1,
            format!("scanner {t0} .. {t1}, suite {g0} .. {g1}"),
        );
    } else if is_scan_summary(&ctx.rj) {
        r.inv(
            "scanner wall clock inside the run window",
            false,
            "no wall clock in the summary",
        );
    }
}

/// Verify one planned item whose directory is `dir` (`None`: it is missing).
pub(crate) fn verify_item(
    root: &Path,
    man: &Value,
    fx: &Value,
    it: &Value,
    dir: Option<PathBuf>,
) -> (Run, Option<Ctx>) {
    let _mac = verify::MacStandGuard::enter();
    let mut r = Run::new(s(&it["tag"]));
    let Some(d) = dir.filter(|d| d.is_dir()) else {
        r.add("run directory present", NOT_RUN, "missing", false);
        return (r, None);
    };
    let dir_nonce = d
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(split_dir_name)
        .map_or(String::new(), |(_, nonce)| nonce.to_owned());
    let rj = read_json(d.join("run.json"));
    let meta = read_json(d.join("meta.json"));
    let cap = read_json(d.join("capture.json"));
    for (name, v) in [
        ("run.json", &rj),
        ("meta.json", &meta),
        ("capture.json", &cap),
    ] {
        if v.is_none() {
            r.add(name, NOT_RUN, "missing or invalid JSON", false);
        }
    }
    let denied = it["kind"] == "perm_denied";
    let peer = if denied {
        load_if_present(&mut r, &d.join("peer.pcap"))
    } else {
        verify::load_pcap(&mut r, &d.join("peer.pcap"))
    };
    safety(&mut r, man, it, &d, peer.as_ref().map(|p| &p.0));
    let (Some(rj), Some(meta), Some(cap)) = (rj, meta, cap) else {
        return (r, None);
    };
    let uplink = if denied {
        None
    } else {
        verify::load_pcap(&mut r, &d.join("uplink.pcap"))
    };
    let ctx = Ctx {
        d: d.clone(),
        rj,
        meta,
        peer,
        bind: Binding::new(&man["binding"]),
    };
    let j = &ctx.rj;
    r.inv(
        "source commit matches manifest",
        truth(&man["code_commit"]) && j["identity"]["source_commit"] == man["code_commit"],
        j["identity"].to_string(),
    );
    r.inv(
        "binary sha256 matches manifest",
        truth(&man["exe"]["sha256"]) && j["identity"]["binary_sha256"] == man["exe"]["sha256"],
        "",
    );
    r.inv(
        "suite hashed the same executable before the run",
        ctx.meta["exe_sha256"] == man["exe"]["sha256"],
        "",
    );
    r.inv(
        "process is macOS",
        j["identity"]["os"]["family"] == "macos",
        "",
    );
    r.inv(
        "manifest binding is the stand's (interfaces, addresses, MACs)",
        binding_is_stand(man),
        man["binding"].to_string(),
    );
    bind_run_json(&mut r, &ctx);
    // The OS hides interface MACs from an unprivileged process; the value the scanner then reports
    // ("os-masked") is accepted, and no OS cross-check is demanded of it. The contract is the one list
    // [`SRC_MAC_CHECK_ACCEPTED`]; a test feeds every literal `wire_scan` can emit through it.
    r.inv(
        "source MAC check is explicit-equal or reported as OS-masked",
        (j.get("src_mac_check").is_none() && !is_scan_summary(j))
            || SRC_MAC_CHECK_ACCEPTED.contains(&s(&j["src_mac_check"])),
        j["src_mac_check"].to_string(),
    );
    gate(&mut r, man, it, &ctx, &cap, uplink.as_ref(), &dir_nonce);
    verify_argv(&mut r, it, man, &ctx.d);
    verify::fixture_binding(&mut r, fx, &ctx.bind);
    let open = fx["binding"]["responder_open_ports"]
        .as_str()
        .map(|t| {
            t.split(',')
                .filter_map(|x| x.trim().parse::<u16>().ok())
                .collect::<Vec<_>>()
        })
        .or_else(|| {
            fx["binding"]["responder_open_ports"].as_array().map(|a| {
                a.iter()
                    .filter_map(|x| x.as_u64().map(|v| v as u16))
                    .collect()
            })
        });
    r.inv(
        "oracle fixtures were taken with the Mac open ports (8000-8007; 80 and 443 closed)",
        open.is_some_and(|mut o| {
            o.sort_unstable();
            o == verify::open_ports()
        }),
        fx["binding"]["responder_open_ports"].to_string(),
    );
    // The OS rate-limits closed-port RSTs (Darwin: `net.inet.tcp.rst_rlc_*`; older records read the Linux-style
    // `net.inet.icmp.icmplim`, which Darwin 27 does not have). Whatever was recorded, an error included, is
    // informational context and never makes a run INVALID.
    {
        let raw = ["rst_rlc.txt", "icmplim.txt"]
            .iter()
            .find_map(|n| fs::read_to_string(ctx.d.join(n)).ok());
        r.notes.insert(
            "rst_rate_limit".into(),
            json!({"informational":true,"raw":raw,"meta":ctx.meta.get("rst_rlc").or(ctx.meta.get("icmplim"))}),
        );
    }
    let wanted = arg_map(it, man, false);
    for (k, field) in [("--scan-id", "scan_id"), ("--attempt-id", "attempt_id")] {
        if let Some(v) = wanted.get(k) {
            if j.get(field).is_some() {
                r.beh(
                    &format!("{field} matches requested argv"),
                    j[field] == *v,
                    j[field].to_string(),
                );
            } else if ["pause", "resume", "complete_nopause"].contains(&s(&it["kind"])) {
                r.beh(&format!("{field} echoed"), false, "missing");
            }
        }
    }
    let c = case_of(it).unwrap_or(Value::Null);
    match s(&it["kind"]) {
        "case" | "foreign" => {
            verify::continuous(&mut r, root, man, fx, &ctx, &c);
            if it["kind"] == "foreign" {
                verify::foreign(
                    &mut r,
                    &ctx,
                    &c,
                    &["unscanned_port", "wrong_cookie", "wrong_dst_port"],
                );
                guard_clean(&mut r, &ctx, "injector.json", true);
                injected_identities(&mut r, &ctx);
            }
        }
        "stop" => {
            verify::stop(&mut r, &ctx, it, &c, man);
            if it["scenario"] == "load" {
                guard_clean(&mut r, &ctx, "flood.json", false);
            }
        }
        "overflow_queue" => verify::overflow(&mut r, &ctx, &c, man),
        "linkloss" => linkloss(&mut r, &ctx, &c, man),
        "rxloss" => {
            rxloss(&mut r, &ctx, &c, man);
            guard_clean(&mut r, &ctx, "flood.json", false);
        }
        "perf" => verify::perf(&mut r, &ctx, it, &c, man),
        "ckpt_refuse" | "refuse_completed" => verify::refusal(&mut r, &ctx, it, &c, man),
        "perm_denied" => permission(&mut r, &ctx, it, man),
        "pause" => {
            verify::job(&mut r, j, &c, man);
            let ni = n(&it["n"]);
            r.beh(
                "pause exits zero, Paused, exact progress and checkpoint summary",
                ctx.meta["guest_exit"] == 0
                    && j["reason"] == "Paused"
                    && n(&j["sent"]) == ni
                    && n(&j["next_index"]) == ni
                    && j["checkpoint"] == true
                    && n(&j["checkpoint_next_index"]) == ni,
                j["reason"].to_string(),
            );
            r.beh(
                "pause health measured zero, exact TX and clean net",
                verify::health(j) && verify::clean(j) && n(&j["net"]["tx_sent"]) == ni,
                j["net"].to_string(),
            );
            verify::checkpoint(&mut r, &ctx, it);
        }
        "resume" => {
            verify::job(&mut r, j, &c, man);
            r.beh(
                "resume completes remaining progress",
                ctx.meta["guest_exit"] == 0
                    && j["reason"] == "Completed"
                    && n(&j["sent"]) == 16 - n(&it["n"])
                    && j["start_index"] == it["n"]
                    && j["next_index"] == 16,
                j["reason"].to_string(),
            );
            r.beh(
                "resume RX measured zero and clean net",
                verify::health(j) && verify::clean(j),
                j["net"].to_string(),
            );
        }
        "complete_nopause" => {
            verify::job(&mut r, j, &c, man);
            r.beh(
                "pause at end completes with no checkpoint",
                ctx.meta["guest_exit"] == 0
                    && j["reason"] == "Completed"
                    && j["checkpoint"] == false
                    && j["sent"] == 16,
                j["reason"].to_string(),
            );
            r.beh(
                "completed RX measured zero",
                verify::health(j),
                j["rx_health"].to_string(),
            );
        }
        _ => r.add("known run kind", INVALID, it.to_string(), false),
    }
    (r, Some(ctx))
}

/// Safety findings of every run of `sub` (kept, discarded or aborted): only the pcaps are read.
fn dir_findings(root: &Path, sub: &str, man: &Value) -> Vec<Value> {
    let Ok(rd) = fs::read_dir(root.join(sub)) else {
        return Vec::new();
    };
    let mut dirs: Vec<_> = rd
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .collect();
    dirs.sort_by_key(|e| e.file_name());
    let items = if man.is_null() {
        Vec::new()
    } else {
        planned(man)
    };
    let mut out = Vec::new();
    for e in dirs {
        let name = e.file_name().to_string_lossy().to_string();
        let d = e.path();
        let has = |f: &str| d.join(f).exists();
        if !(has("uplink.pcap")
            || has("uplink.pcap.gz")
            || has("uplink.err")
            || has("peer.pcap")
            || has("peer.pcap.gz"))
        {
            continue;
        }
        let tag = split_dir_name(&name).map_or(name.as_str(), |(t, _)| t);
        let it = items
            .iter()
            .find(|it| s(&it["tag"]) == tag)
            .cloned()
            .unwrap_or_else(|| json!({"tag":tag,"kind":""}));
        let mut r = Run::new(&name);
        let peer = load_capture(&mut r, &d, "peer");
        safety(&mut r, man, &it, &d, peer.as_ref().map(|p| &p.0));
        out.push(r.summary());
    }
    out
}

/// The pcap-only safety findings of `runs/` and `runs_discarded/`: what a failed manifest gate must not hide.
fn scan_runs(root: &Path, man: &Value) -> Vec<Value> {
    let mut v = dir_findings(root, "runs", man);
    v.extend(dir_findings(root, "runs_discarded", man));
    v.extend(dir_findings(root, ".work", man));
    v
}

/// The safety findings of the directories of `runs/` and `runs_discarded/` that `verify_dir` did not judge itself:
/// unknown tags and names that do not parse as `<tag>.<nonce>`.
fn unplanned_scan(root: &Path, man: &Value) -> Vec<Value> {
    let planned_tags: BTreeSet<String> = planned(man)
        .iter()
        .map(|i| s(&i["tag"]).to_owned())
        .collect();
    let mut v: Vec<Value> = dir_findings(root, "runs", man)
        .into_iter()
        .chain(dir_findings(root, "runs_discarded", man))
        .filter(|r| split_dir_name(s(&r["tag"])).is_none_or(|(t, _)| !planned_tags.contains(t)))
        .collect();
    // A kept work directory is never judged by the plan: all of it is walked.
    v.extend(dir_findings(root, ".work", man));
    v
}

/// A work directory left in `--out` (an abort whose copy failed) is reported, not hidden.
fn work_note(root: &Path) -> Option<String> {
    let names: Vec<String> = fs::read_dir(root.join(".work"))
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    (!names.is_empty()).then(|| format!(".work holds {} unfinished run directory(ies) ({}); its pcaps were walked for lab frames, nothing else was judged", names.len(), names.join(", ")))
}

/// Judge every directory of a tag. One directory is judged as it is. More than one is never a blanket
/// INVALID: each is judged, their findings (a behaviour FAIL, a safety trip) are kept under the directory's
/// name, and the ambiguity is added on top.
pub(crate) fn judge_tag(root: &Path, man: &Value, fx: &Value, it: &Value) -> (Run, Option<Ctx>) {
    let tag = s(&it["tag"]).to_owned();
    let mut dirs = run_dirs(root, "runs", &tag);
    if dirs.len() <= 1 {
        return verify_item(root, man, fx, it, dirs.pop());
    }
    let mut merged = Run::new(&tag);
    merged.argv_ok = true;
    let count = dirs.len();
    for d in dirs {
        let label = d
            .file_name()
            .map_or(String::new(), |n| n.to_string_lossy().into_owned());
        let (sub, _) = verify_item(root, man, fx, it, Some(d));
        for mut c in sub.checks {
            c["name"] = json!(format!("[{label}] {}", s(&c["name"])));
            if !sub.argv_ok {
                // The same demotion `Run::verdict` applies to a run whose argv is wrong.
                c["behaviour"] = json!(false);
                if c["result"] == FAIL && c["safety"] != true {
                    c["result"] = json!(INVALID);
                }
            }
            merged.checks.push(c);
        }
    }
    merged.add(
        "exactly one run directory for the tag",
        INVALID,
        format!("{count} directories"),
        false,
    );
    (merged, None)
}

/// Every run of `root` (kept, discarded or aborted) whose lab-isolation checks tripped. The suite
/// refuses to start or to `--rerun` in a directory where this is not empty.
pub fn safety_trips(root: &Path) -> Vec<String> {
    let man = read_json(root.join("manifest.json")).unwrap_or(Value::Null);
    [".work", "runs", "runs_discarded", "runs_aborted"]
        .iter()
        .flat_map(|sub| {
            dir_findings(root, sub, &man)
                .into_iter()
                .filter(|r| r["safety_trip"] == true)
                .map(move |r| format!("{sub}/{}", s(&r["tag"])))
        })
        .collect()
}

/// The verdict of one tag (`verdict`, `behaviour_fail`), for the rerun rule.
pub fn run_status(root: &Path, tag: &str) -> (String, bool) {
    let _mac = verify::MacStandGuard::enter();
    let Some(man) = read_json(root.join("manifest.json")) else {
        return (NOT_RUN.into(), false);
    };
    let Some(it) = planned(&man).into_iter().find(|it| it["tag"] == tag) else {
        return (NOT_RUN.into(), false);
    };
    let fx = read_json(root.join("fixtures/manifest.json")).unwrap_or(Value::Null);
    let (r, _) = judge_tag(root, &man, &fx, &it);
    (r.verdict().into(), r.behaviour_fail())
}

pub fn verify_dir(root: &Path) -> Value {
    let _mac = verify::MacStandGuard::enter();
    let mut result = json!({"schema":1,"dir":root.file_name().unwrap_or_default().to_string_lossy(),"runs":[],"groups":[],"discarded":[],"aborted":[]});
    let Some(man) = read_json(root.join("manifest.json")) else {
        let mut r = Run::new("manifest");
        r.add("manifest present and valid JSON", NOT_RUN, "missing", false);
        result["runs"] = json!([r.summary()]);
        result["aborted"] = json!(dir_findings(root, "runs_aborted", &Value::Null));
        result["safety_scan"] = json!(scan_runs(root, &Value::Null));
        return verify::finish(result);
    };
    let fx = read_json(root.join("fixtures/manifest.json"));
    let mut r = Run::new("manifest");
    for k in ["code_commit", "exe", "binding", "stand"] {
        r.check(
            &format!("manifest.{k} present"),
            truth(&man[k]),
            "",
            NOT_RUN,
            false,
        );
    }
    r.check(
        "manifest.macos_capture_schema present",
        man["macos_capture_schema"].as_u64().is_some_and(|v| v >= 1),
        man["macos_capture_schema"].to_string(),
        NOT_RUN,
        false,
    );
    r.check(
        "manifest.plan is functional, failure or perf",
        matches!(s(&man["plan"]), "functional" | "failure" | "perf"),
        man["plan"].to_string(),
        NOT_RUN,
        false,
    );
    r.check(
        "manifest binding is the stand's (interfaces, addresses, MACs)",
        binding_is_stand(&man),
        man["binding"].to_string(),
        INVALID,
        false,
    );
    r.check(
        "manifest executable sha256 present",
        truth(&man["exe"]["sha256"]),
        "",
        NOT_RUN,
        false,
    );
    result["notes"] = json!([
        "x01 on macOS exercises three foreign-reply kinds (unscanned port, wrong cookie, wrong destination port); the other_ip kind is not written because the peer-side guard forbids a source other than 198.18.0.2. It is covered by the Linux and Windows runs; the reply filtering is shared core code.",
        "perm_denied runs have no capture: the evidence is that zero frames crossed the pair (scanner refusal plus unchanged pair counters inside a recorded window), not 0 SYN in a capture."
    ]);
    if let (Some(n), Some(a)) = (work_note(root), result["notes"].as_array_mut()) {
        a.push(json!(n));
    }
    result["provenance"] = verify::provenance_report(&man);
    let why = crate::provenance::problem(&man["orchestrator"]);
    r.check(
        "orchestrator build recorded (commit, dirty flag, binary sha256)",
        why.is_none(),
        why.unwrap_or_default(),
        INVALID,
        false,
    );
    r.check(
        "fixtures manifest present",
        fx.is_some(),
        "",
        NOT_RUN,
        false,
    );
    let mut runs = vec![r.summary()];
    if r.verdict() != PASS {
        result["runs"] = json!(runs);
        result["aborted"] = json!(dir_findings(root, "runs_aborted", &man));
        result["safety_scan"] = json!(scan_runs(root, &man));
        return verify::finish(result);
    }
    let fx = fx.unwrap_or(Value::Null);
    let mut rs = BTreeMap::new();
    let mut cs = BTreeMap::new();
    for it in planned(&man) {
        let tag = s(&it["tag"]).to_owned();
        let (r, c) = judge_tag(root, &man, &fx, &it);
        runs.push(r.summary());
        if let Some(c) = c {
            cs.insert(tag.clone(), c);
        }
        rs.insert(tag, r);
    }
    if man["plan"] == "perf" {
        result["perf_summary"] = verify::perf_summary(&runs);
    }
    if man["plan"] == "functional" {
        result["groups"] = json!(verify::groups(root, &man, &fx, &rs, &cs));
    }
    result["runs"] = json!(runs);
    let mut discarded = Vec::new();
    if let Ok(rd) = fs::read_dir(root.join("runs_discarded")) {
        let mut paths: Vec<_> = rd
            .filter_map(Result::ok)
            .filter(|e| e.path().is_dir())
            .collect();
        paths.sort_by_key(|e| e.file_name());
        for e in paths {
            let name = e.file_name().to_string_lossy().to_string();
            let tag = split_dir_name(&name).map_or(name.as_str(), |(t, _)| t);
            let mut r = if let Some(it) = planned(&man).into_iter().find(|it| it["tag"] == tag) {
                verify_item(root, &man, &fx, &it, Some(e.path())).0
            } else {
                let mut r = Run::new(&name);
                r.argv_ok = true;
                r.add("discarded run belongs to planned tag", FAIL, tag, false);
                r
            };
            r.tag = name;
            discarded.push(r.summary());
        }
    }
    result["discarded"] = json!(discarded);
    result["aborted"] = json!(dir_findings(root, "runs_aborted", &man));
    // An independent full walk: a directory under runs/ or runs_discarded/ that the plan does not know (or
    // whose name is malformed) is still evidence of a leak. Planned directories were judged above.
    result["safety_scan"] = json!(unplanned_scan(root, &man));
    verify::finish(result)
}

/// `macos-verify --dir DIR [--out FILE]`: 0 PASS, 1 FAIL, 2 INVALID or NOT RUN.
pub fn run(args: &[String]) -> Result<i32, String> {
    let o = crate::windows_suite::options_for("macos-verify", args, &["dir", "out"])?;
    if o.contains_key("help") {
        println!(
            "macos-verify --dir DIR [--out FILE]  (exit 0 PASS, 1 FAIL, 2 INVALID or NOT RUN)"
        );
        return Ok(0);
    }
    let dir = crate::windows_suite::required(&o, "dir")?;
    let res = verify_dir(Path::new(&dir));
    if let Some(out) = o.get("out").and_then(|v| v.first()) {
        fs::write(
            out,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&res).map_err(|e| e.to_string())?
            ),
        )
        .map_err(|e| e.to_string())?;
    }
    for r in array(&res["runs"])
        .iter()
        .chain(array(&res["groups"]))
        .chain(array(&res["discarded"]))
    {
        let bad: Vec<_> = array(&r["checks"])
            .iter()
            .filter(|c| c["result"] != PASS)
            .take(3)
            .map(|c| format!("{}: {}", s(&c["result"]), s(&c["name"])))
            .collect();
        println!(
            "{:<8} {} {}",
            s(&r["verdict"]),
            s(&r["tag"]),
            bad.join("; ")
        );
    }
    for line in verify::safety_report_lines(&res) {
        println!("{line}");
    }
    for row in array(&res["perf_summary"]["rows"]) {
        println!(
            "perf {:>6} pps: pass {} fail {} invalid {} not run {} rx_loss {}; median wire {} pps; rate gate {}",
            row["rate"],
            row["pass"],
            row["fail"],
            row["invalid"],
            row["not_run"],
            row["rx_loss"],
            row["median"]["steady_pps_wire"]
                .as_f64()
                .map_or("n/a".to_owned(), |w| format!("{w:.1}")),
            s(&row["rate_gate"]),
        );
    }
    println!("overall: {} {}", s(&res["overall"]), res["totals"]);
    Ok(match s(&res["overall"]) {
        PASS => 0,
        FAIL => 1,
        _ => 2,
    })
}

#[cfg(test)]
#[path = "macos_verify_tests.rs"]
mod tests;
