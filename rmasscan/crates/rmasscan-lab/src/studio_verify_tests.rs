//! Synthetic, hermetic Studio windows. Frames come from the engine's own plan (`ProbeCursor` through
//! `plan_frames_for_job`), everything else is invented so that one rule at a time can be broken.
//! Nothing here touches a network, an interface or a real evidence directory.
use super::*;
use crate::windows_suite::nonce;
use std::path::PathBuf;

const T0: f64 = 1_800_000_000.0;
const RUNNER: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

fn mac(s: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    for (i, p) in s.split(':').enumerate() {
        out[i] = u8::from_str_radix(p, 16).unwrap();
    }
    out
}
fn tcp_frame(
    sm: &str,
    dm: &str,
    src: [u8; 4],
    dst: [u8; 4],
    sp: u16,
    dp: u16,
    flags: u8,
) -> Vec<u8> {
    let mut b = vec![0u8; 54];
    b[0..6].copy_from_slice(&mac(dm));
    b[6..12].copy_from_slice(&mac(sm));
    b[12] = 8;
    b[14] = 0x45;
    b[16..18].copy_from_slice(&40u16.to_be_bytes());
    b[22] = 64;
    b[23] = 6;
    b[26..30].copy_from_slice(&src);
    b[30..34].copy_from_slice(&dst);
    b[34..36].copy_from_slice(&sp.to_be_bytes());
    b[36..38].copy_from_slice(&dp.to_be_bytes());
    b[46] = 0x50;
    b[47] = flags;
    b
}
/// The peer's reply to a SYN frame: SYN-ACK or RST, ack = seq + 1.
fn reply_to(syn: &[u8], open: bool) -> Vec<u8> {
    let i = tcp(syn).unwrap();
    let mut f = tcp_frame(
        NEXT_HOP_MAC,
        SCANNER_MAC,
        [198, 18, 0, 2],
        [198, 18, 0, 1],
        i.dp,
        SOURCE_PORT,
        if open { 0x12 } else { 0x14 },
    );
    f[42..46].copy_from_slice(&i.seq.wrapping_add(1).to_be_bytes());
    f
}
fn syn_of(port: u16) -> Vec<u8> {
    tcp_frame(
        SCANNER_MAC,
        NEXT_HOP_MAC,
        [198, 18, 0, 1],
        [198, 18, 0, 2],
        SOURCE_PORT,
        port,
        2,
    )
}
fn utc(t: f64) -> String {
    let ms = ((t - T0) * 1000.0).round() as i64;
    let total = 1_800_000_000 + ms.div_euclid(1000);
    let (days, sec) = (total.div_euclid(86_400), total.rem_euclid(86_400));
    // civil from days (Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        sec / 3600,
        sec % 3600 / 60,
        sec % 60,
        ms.rem_euclid(1000)
    )
}
fn tcpdump_err(captured: usize, received: usize, dropped: usize) -> String {
    tcpdump_err_on("en0", captured, received, dropped)
}
fn tcpdump_err_on(iface: &str, captured: usize, received: usize, dropped: usize) -> String {
    format!(
        "tcpdump: listening on {iface}, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n{captured} packets captured\n{received} packets received by filter\n{dropped} packets dropped by kernel\n"
    )
}
fn pretty(v: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(v).unwrap()
}

#[derive(Clone, Copy)]
struct Knobs {
    pause_wait: f64,
    stop_lat: f64,
}
const KNOBS: Knobs = Knobs {
    pause_wait: 3.1,
    stop_lat: 0.05,
};

/// The whole window as data. `write` puts it on disk with its hashes.
struct Model {
    syns: Vec<Vec<(f64, Vec<u8>)>>,
    replies: Vec<Vec<(f64, Vec<u8>)>>,
    uplink: Frames,
    peer_err: Option<String>,
    uplink_err: String,
    smoke: Option<Value>,
    history: Value,
    prov: Value,
    pre: Value,
    post: Value,
    host_before: String,
    host_after: String,
    extra: BTreeMap<String, Vec<u8>>,
    /// Files left out of the directory (and of the hashes).
    skip: Vec<&'static str>,
}
fn event(t: f64, kind: &str, status: &str, detail: &str) -> Value {
    json!({"utc":utc(T0 + t),"mono_ms":(t * 1000.0).round() as i64,"kind":kind,"status":status,"detail":detail,"rows":0})
}
fn action(t: f64, name: &str) -> Value {
    json!({"utc":utc(T0 + t),"mono_ms":(t * 1000.0).round() as i64,"action":name})
}
impl Model {
    fn consistent() -> Self {
        Self::with(KNOBS)
    }
    fn with(k: Knobs) -> Self {
        let jobs: Vec<Value> = CASES.iter().map(spec_job).collect();
        let plans: Vec<Vec<Vec<u8>>> = jobs
            .iter()
            .map(|j| plan_frames_for_job(j).unwrap())
            .collect();
        // Timeline (seconds after T0).
        let leg1 = 6usize;
        let pause = 11.3;
        let paused = pause + k.pause_wait;
        let resume = paused + 0.1;
        let leg2_start = resume + 0.2;
        let leg2_last = leg2_start + 25.0 * 0.25;
        let s2_done = leg2_last + 3.0;
        let s3_start = s2_done + 0.2;
        let s3_n = 450usize;
        let s3_first = s3_start + 0.2;
        let s3_last = s3_first + (s3_n - 1) as f64 / 300.0;
        let stop = s3_last + 0.01;
        let stopped = stop + k.stop_lat;
        let lock = stopped + 0.25;
        // SYNs per case, with times.
        let mut syns: Vec<Vec<(f64, Vec<u8>)>> = vec![vec![], vec![], vec![]];
        for (i, f) in plans[0].iter().enumerate() {
            syns[0].push((T0 + 6.2 + i as f64 * 0.01, f.clone()));
        }
        for (i, f) in plans[1].iter().enumerate() {
            let t = if i < leg1 {
                9.8 + i as f64 * 0.25
            } else {
                leg2_start + (i - leg1) as f64 * 0.25
            };
            syns[1].push((T0 + t, f.clone()));
        }
        for (i, f) in plans[2].iter().take(s3_n).enumerate() {
            syns[2].push((T0 + s3_first + i as f64 / 300.0, f.clone()));
        }
        let open = |port: u16| LAB_OPEN_PORTS.contains(&port);
        let mut replies = vec![vec![], vec![], vec![]];
        let mut rows: Vec<Vec<Value>> = vec![vec![], vec![], vec![]];
        for c in 0..3 {
            for (t, f) in &syns[c] {
                let port = tcp(f).unwrap().dp;
                replies[c].push((t + 0.0005, reply_to(f, open(port))));
                rows[c].push(
                    json!({"ip":PEER_IP,"port":port,"open":open(port),"discovered_at":utc(*t)}),
                );
            }
        }
        let finished = [9.5, s2_done, stopped];
        let started = [6.0, 9.6, s3_start];
        let scan_ids = [
            "11111111111111111111111111111111",
            "22222222222222222222222222222222",
            "33333333333333333333333333333333",
        ];
        let mut events = vec![
            event(0.1, "Authorization", "Authorized", ""),
            event(
                5.2,
                "Notice",
                "",
                "Network preflight passed: feth4201 sealed stand",
            ),
            event(6.05, "State", "Starting", ""),
            event(6.15, "State", "Scanning", ""),
            event(9.5, "State", "Completed", ""),
            event(9.65, "State", "Starting", ""),
            event(9.75, "State", "Scanning", ""),
            event(pause + 0.05, "State", "Saving", ""),
            event(paused, "State", "Paused", PAUSE_ACK_TEXT),
            event(resume + 0.05, "State", "Starting", ""),
            event(resume + 0.15, "State", "Scanning", ""),
            event(s2_done, "State", "Completed", ""),
            event(s3_start + 0.05, "State", "Starting", ""),
            event(s3_start + 0.15, "State", "Scanning", ""),
            event(stopped, "State", "Stopped", "Stopped"),
            event(lock + 0.1, "Notice", "", "Runner session closed"),
        ];
        events[0]["authorized"] = json!(true);
        events[0]["busy"] = json!(false);
        let actions = vec![
            action(0.0, "Authorize"),
            action(6.0, "Start:s1_full"),
            action(9.6, "Start:s2_pause"),
            action(pause, "Pause"),
            action(resume, "Resume"),
            action(s2_done + 0.1, "Start:s3_stop"),
            action(stop, "Stop"),
            action(lock, "Lock"),
        ];
        // The s3 Start action is 0.1 after s2 finished; Starting is 0.15 after that action.
        let plan_rec: Vec<Value> = (0..3)
            .map(|c| {
                json!({
                    "tag": CASES[c].tag,
                    "job": jobs[c],
                    "scan_id_hex": scan_ids[c],
                    "rows_seen": rows[c].len(),
                    "started_utc": utc(T0 + started[c]),
                    "finished_utc": utc(T0 + finished[c]),
                    "finished_status": CASES[c].status,
                    "paused_next_index": if c == 1 { json!(leg1) } else { Value::Null },
                    "pause_to_paused_ms": if c == 1 { json!((k.pause_wait * 1000.0).round() as i64) } else { Value::Null },
                    "stop_to_stopped_ms": if c == 2 { json!((k.stop_lat * 1000.0).round() as i64) } else { Value::Null },
                })
            })
            .collect();
        let smoke = json!({
            "schema":1,"started_utc":utc(T0),"plan":plan_rec,"events":events,"actions":actions,"result":"ok",
        });
        let history = json!({"scans": (0..3).map(|c| json!({
            "scan_id_hex": scan_ids[c], "attempt_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "job": jobs[c], "status": CASES[c].status,
            "detail": if c == 1 { "Completed after resume" } else { "" },
            "next_index": null, "checkpoint_len": 0, "sequence": 10 + c, "created_at": utc(T0 + started[c]),
            "rows": rows[c],
        })).collect::<Vec<_>>()});
        // Lab listeners are not in this netstat sample; the wildcard host services are not scanned ports.
        let netstat = "rc 0\ntcp4       0      0  *.5000                 *.*                    LISTEN\ntcp46      0      0  *.7000                 *.*                    LISTEN\ntcp4       0      0  198.18.0.2.8000        *.*                    LISTEN\n".to_owned();
        let mut extra = BTreeMap::new();
        extra.insert("ui.log".into(), b"studio-ui log\n".to_vec());
        let cmd = |iface: &str, filter: &str, out: &str, p: bool, start: f64, stop: f64| {
            let mut argv = vec![
                "/usr/sbin/tcpdump",
                if p { "-p" } else { "-n" },
                "-n",
                "-U",
                "-s",
                "0",
                "-i",
                iface,
                "-w",
                out,
            ];
            if !filter.is_empty() {
                argv.push(filter);
            }
            pretty(
                &json!({"cmd":argv,"interface":iface,"filter":filter,"start_utc":utc(T0 + start),"stop_utc":utc(T0 + stop),"exit_code":0,"listening":true}),
            )
        };
        extra.insert(
            "peer.cmd.json".into(),
            cmd("feth4202", "", "peer.pcap", true, -5.0, lock + 5.0),
        );
        extra.insert(
            "uplink.cmd.json".into(),
            cmd(
                "en0",
                &crate::macos_verify::uplink_filter(SCANNER_MAC, NEXT_HOP_MAC),
                "uplink.pcap",
                true,
                -5.0,
                lock + 5.0,
            ),
        );
        extra.insert("window.json".into(), pretty(&json!({"schema":1,"started_utc":utc(T0 - 5.0),"ended_utc":utc(T0 + lock + 5.0),"uplink":"en0","ui_rc":0,"invalid_marks":[]})));
        extra.insert(
            "alf.txt".into(),
            b"Firewall is disabled. (State = 0)\n".to_vec(),
        );
        extra.insert("leftover-listeners.txt".into(), vec![]);
        extra.insert("leftover-procs.txt".into(), vec![]);
        extra.insert("pair-quiet.txt".into(), b"quiet\n".to_vec());
        extra.insert("listeners-ready.txt".into(), b"ready\n".to_vec());
        extra.insert(
            "data.sha256".into(),
            format!("{}  history.sqlite3\n", sha(b"not hashed")).into_bytes(),
        );
        Self {
            syns,
            replies,
            uplink: vec![],
            peer_err: None,
            uplink_err: tcpdump_err(0, 123_456, 0),
            smoke: Some(smoke),
            history,
            prov: json!({
                "git_head":"0123456789abcdef0123456789abcdef01234567","dirty":false,
                "ui_sha256":"ab".repeat(32),"runner_sha256":RUNNER,"installed_runner_sha256":RUNNER,
            }),
            pre: json!({"raw_run_allowed":true,"bpf_access":"granted","uplink":"en0"}),
            post: json!({"raw_run_allowed":true,"bpf_access":"granted","uplink":"en0"}),
            host_before: netstat.clone(),
            host_after: netstat,
            extra,
            skip: vec![],
        }
    }
    fn peer_frames(&self) -> Frames {
        let mut all: Frames = self
            .syns
            .iter()
            .chain(self.replies.iter())
            .flatten()
            .cloned()
            .collect();
        all.sort_by(|a, b| a.0.total_cmp(&b.0));
        all
    }
    fn rows_mut(&mut self, case: usize) -> &mut Vec<Value> {
        self.history["scans"][case]["rows"].as_array_mut().unwrap()
    }
    /// Keeps `rows_seen` equal to the history rows, so only the intended rule is broken.
    fn sync_rows_seen(&mut self) {
        for c in 0..self.history["scans"].as_array().unwrap().len() {
            let n = self.history["scans"][c]["rows"].as_array().unwrap().len();
            if let Some(p) = self.smoke.as_mut().and_then(|sm| sm["plan"].get_mut(c)) {
                p["rows_seen"] = json!(n);
            }
        }
    }
    /// Edits one JSON file of the extra files.
    fn edit(&mut self, name: &str, f: impl FnOnce(&mut Value)) {
        let mut v: Value = serde_json::from_slice(&self.extra[name]).unwrap();
        f(&mut v);
        self.extra.insert(name.into(), pretty(&v));
    }
    fn paused_event(&mut self) -> &mut Value {
        self.smoke.as_mut().unwrap()["events"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["status"] == "Paused")
            .unwrap()
    }
    fn write(&mut self) -> PathBuf {
        self.sync_rows_seen();
        let d = std::env::temp_dir().join(format!("rml-studio-verify-{}", nonce()));
        fs::create_dir_all(d.join("data")).unwrap();
        fs::write(d.join("data").join("history.sqlite3"), b"not hashed").unwrap();
        let peer = self.peer_frames();
        let mut files: BTreeMap<String, Vec<u8>> = self.extra.clone();
        files.insert("peer.pcap".into(), pcap::encode(&peer));
        files.insert(
            "peer.err".into(),
            self.peer_err
                .clone()
                .unwrap_or_else(|| tcpdump_err_on("feth4202", peer.len(), peer.len() + 50, 0))
                .into_bytes(),
        );
        files.insert("uplink.pcap".into(), pcap::encode(&self.uplink));
        files.insert("uplink.err".into(), self.uplink_err.clone().into_bytes());
        if let Some(sm) = &self.smoke {
            files.insert("smoke.json".into(), pretty(sm));
        }
        files.insert("history.json".into(), pretty(&self.history));
        files.insert("provenance.json".into(), pretty(&self.prov));
        files.insert("status-pre.json".into(), pretty(&self.pre));
        files.insert("status-post.json".into(), pretty(&self.post));
        files.insert(
            "host-listen-before.txt".into(),
            self.host_before.clone().into_bytes(),
        );
        files.insert(
            "host-listen-after.txt".into(),
            self.host_after.clone().into_bytes(),
        );
        for k in &self.skip {
            files.remove(*k);
        }
        let mut hashes = String::new();
        for (name, bytes) in &files {
            fs::write(d.join(name), bytes).unwrap();
            hashes.push_str(&format!("{}  {name}\n", sha(bytes)));
        }
        fs::write(d.join(HASHES), hashes).unwrap();
        d
    }
}
fn verdict_of(m: &mut Model) -> Value {
    let d = m.write();
    let v = verify_dir(&d, false);
    fs::remove_dir_all(d).ok();
    v
}
fn overall(v: &Value) -> &str {
    s(&v["overall"])
}
/// Names of the checks that are not PASS, with their case tag.
fn bad(v: &Value) -> Vec<String> {
    array(&v["cases"])
        .iter()
        .flat_map(|c| {
            array(&c["checks"])
                .iter()
                .filter(|k| k["result"] != PASS)
                .map(|k| format!("{}/{}", s(&c["tag"]), s(&k["name"])))
                .collect::<Vec<_>>()
        })
        .collect()
}
fn has_bad(v: &Value, tag: &str, part: &str) -> bool {
    bad(v)
        .iter()
        .any(|b| b.starts_with(&format!("{tag}/")) && b.contains(part))
}

// ------------------------------------------------------------------ utilities

#[test]
fn plan_ports_for_job_follow_the_engine_cursor() {
    for c in &CASES {
        let ports = plan_ports_for_job(&spec_job(c)).unwrap();
        let mut sorted = ports.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ports.len(), "{}: each port once", c.tag);
        assert_eq!(
            plan_ports_for_job(&spec_job(c)).unwrap(),
            ports,
            "deterministic"
        );
    }
    assert_eq!(plan_ports_for_job(&spec_job(&CASES[0])).unwrap().len(), 20);
    assert_eq!(plan_ports_for_job(&spec_job(&CASES[1])).unwrap().len(), 32);
    assert_eq!(
        plan_ports_for_job(&spec_job(&CASES[2])).unwrap().len(),
        2000
    );
    let mut other = spec_job(&CASES[0]);
    other["seed"] = json!("9");
    assert_ne!(
        plan_ports_for_job(&other).unwrap(),
        plan_ports_for_job(&spec_job(&CASES[0])).unwrap(),
        "the seed shapes the order"
    );
    other["backend"] = json!("Simulation");
    assert!(plan_ports_for_job(&other).is_err());
}

#[test]
fn scan_window_table() {
    type Row = (f64, f64, Option<f64>, Option<f64>, (f64, f64));
    let cases: [Row; 5] = [
        (10.0, 20.0, None, None, (9.0, 21.0)),
        // the previous case finished long before: untouched
        (10.0, 20.0, Some(5.0), Some(30.0), (9.0, 21.0)),
        // overlap with the previous case: cut at Starting - 0.25
        (10.0, 20.0, Some(9.5), None, (9.75, 21.0)),
        // overlap with the next case
        (10.0, 20.0, None, Some(20.5), (9.0, 20.25)),
        // the previous case finished after Starting - 0.25: cut at its end
        (10.0, 20.0, Some(9.9), None, (9.9, 21.0)),
    ];
    for (st, fi, pf, ns, want) in cases {
        assert_eq!(scan_window(st, fi, pf, ns), want, "{st} {fi} {pf:?} {ns:?}");
    }
}

#[test]
fn parse_tcpdump_stats_table() {
    let ok = tcpdump_err(7, 70, 0);
    assert_eq!(
        parse_tcpdump_stats(&ok),
        Some(TcpdumpStats {
            captured: 7,
            received: Some(70),
            dropped_kernel: 0
        })
    );
    assert_eq!(
        parse_tcpdump_stats(
            "1 packet captured\n3 packets received by filter\n2 packets dropped by kernel\n"
        ),
        Some(TcpdumpStats {
            captured: 1,
            received: Some(3),
            dropped_kernel: 2
        })
    );
    for text in [
        "",
        "tcpdump: listening on en0\n",
        "0 packets captured\n",
        "5 packets dropped by kernel\n",
        "x packets captured\n0 packets dropped by kernel\n",
    ] {
        assert_eq!(parse_tcpdump_stats(text), None, "{text:?}");
    }
}

#[test]
fn parse_utc_table() {
    assert_eq!(parse_utc("1970-01-01T00:00:00Z"), Some(0.0));
    assert_eq!(parse_utc("2000-03-01T00:00:01.5Z"), Some(951_868_801.5));
    assert_eq!(parse_utc(&utc(T0 + 12.345)), Some(T0 + 12.345));
    for t in [
        "",
        "2026-10-26",
        "2026-10-26T12:00:00",
        "2026-13-26T00:00:00Z",
        "2026-10-26T25:00:00Z",
        "2026-10-26T00:00:00.xZ",
    ] {
        assert_eq!(parse_utc(t), None, "{t}");
    }
}

// ------------------------------------------------------------------ the window

#[test]
fn a_consistent_window_is_pass() {
    let v = verdict_of(&mut Model::consistent());
    assert_eq!(overall(&v), PASS, "{:?}", bad(&v));
    assert_eq!(v["totals"]["fail"], 0);
    assert_eq!(v["isolation"]["uplink_frames"], 0);
    assert_eq!(v["isolation"]["uplink_captured"], 0);
    assert_eq!(v["isolation"]["uplink_dropped"], 0);
    assert_eq!(v["provenance"]["runner_sha256"], RUNNER);
    assert_eq!(v["provenance"]["installed_runner_sha256"], RUNNER);
    assert_eq!(
        v["provenance"]["window_sha"],
        "0123456789abcdef0123456789abcdef01234567"
    );
    let tags: Vec<&str> = array(&v["cases"]).iter().map(|c| s(&c["tag"])).collect();
    assert!(
        [
            "safety",
            "chronicle",
            "s1_full",
            "s2_pause",
            "s3_stop",
            "wire"
        ]
        .iter()
        .all(|t| tags.contains(t)),
        "{tags:?}"
    );
    let s1 = array(&v["cases"])
        .iter()
        .find(|c| c["tag"] == "s1_full")
        .unwrap();
    assert_eq!(s1["scan_id"], "11111111111111111111111111111111");
    assert!(array(&s1["checks"]).iter().all(|c| c["ok"] == true));
}

#[test]
fn a_lab_frame_on_the_uplink_is_fail() {
    let mut m = Model::consistent();
    m.uplink = vec![(T0 + 7.0, syn_of(80))];
    m.uplink_err = tcpdump_err(1, 500, 0);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL);
    assert!(
        has_bad(&v, "safety", "uplink saw zero lab packets"),
        "{:?}",
        bad(&v)
    );
    // tcpdump counting a matching frame without storing it is the same breach
    let mut m = Model::consistent();
    m.uplink_err = tcpdump_err(1, 500, 0);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL);
    assert!(
        has_bad(&v, "safety", "counted zero frames"),
        "{:?}",
        bad(&v)
    );
}

#[test]
fn uplink_kernel_drop_is_invalid() {
    let mut m = Model::consistent();
    m.uplink_err = tcpdump_err(0, 500, 3);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), INVALID, "{:?}", bad(&v));
    assert!(has_bad(&v, "safety", "dropped 0 packets by kernel"));
    // received by filter is pre-filter on macOS: a huge number there is not a breach
    let v = verdict_of(&mut Model::consistent());
    assert_eq!(overall(&v), PASS);
}

#[test]
fn a_gzipped_capture_is_refused() {
    let mut m = Model::consistent();
    m.extra.insert("uplink.pcap.gz".into(), vec![0x1f, 0x8b, 8]);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL);
    assert!(has_bad(&v, "safety", "no compressed capture"));
}

#[test]
fn a_changed_hash_is_invalid() {
    let mut m = Model::consistent();
    let d = m.write();
    fs::write(d.join("ui.log"), b"edited after the hashes were taken\n").unwrap();
    let v = verify_dir(&d, false);
    fs::remove_dir_all(&d).ok();
    assert_eq!(overall(&v), INVALID, "{:?}", bad(&v));
    assert!(has_bad(&v, "safety", "hashes-before-copy.txt matches"));
    // an unlisted file is the same finding; the data directory and verdict.json are outside the hashes
    let mut m = Model::consistent();
    let d = m.write();
    fs::write(d.join("verdict.json"), b"{}").unwrap();
    assert_eq!(overall(&verify_dir(&d, false)), PASS);
    fs::write(d.join("extra.txt"), b"x").unwrap();
    let v = verify_dir(&d, false);
    fs::remove_dir_all(&d).ok();
    assert_eq!(overall(&v), INVALID);
}

#[test]
fn installed_hash_mismatch_is_invalid() {
    let mut m = Model::consistent();
    m.prov["installed_runner_sha256"] = json!("ef".repeat(32));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), INVALID, "{:?}", bad(&v));
    assert!(has_bad(&v, "safety", "installed runner hash"));
    let mut m = Model::consistent();
    m.prov["dirty"] = json!(true);
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
}

#[test]
fn the_gates_are_checked() {
    let mut m = Model::consistent();
    m.post["raw_run_allowed"] = json!(false);
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
    let mut m = Model::consistent();
    m.pre["bpf_access"] = json!("denied");
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
}

#[test]
fn a_duplicate_syn_is_fail() {
    let mut m = Model::consistent();
    let dup = m.syns[0][3].clone();
    m.syns[0].insert(4, (dup.0 + 0.003, dup.1));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(has_bad(&v, "s1_full", "exactly once"));
}

#[test]
fn syn_order_off_the_plan_is_fail() {
    let mut m = Model::consistent();
    let (a, b) = (m.syns[0][2].1.clone(), m.syns[0][3].1.clone());
    m.syns[0][2].1 = b;
    m.syns[0][3].1 = a;
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(has_bad(&v, "s1_full", "SYN order"));
    // a stopped scan must also follow the plan prefix
    let mut m = Model::consistent();
    let (a, b) = (m.syns[2][10].1.clone(), m.syns[2][11].1.clone());
    m.syns[2][10].1 = b;
    m.syns[2][11].1 = a;
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL);
    assert!(has_bad(&v, "s3_stop", "prefix of the plan"));
}

#[test]
fn a_syn_after_stop_is_fail() {
    let mut m = Model::consistent();
    let plan = plan_frames_for_job(&spec_job(&CASES[2])).unwrap();
    let last = m.syns[2].last().unwrap().0;
    let stopped = last + 0.01 + KNOBS.stop_lat;
    m.syns[2].push((stopped + 0.5, plan[450].clone()));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(has_bad(&v, "s3_stop", "no SYN after Stopped"));
    // far later, outside every window
    let mut m = Model::consistent();
    let last = m.syns[2].last().unwrap().0;
    m.syns[2].push((last + 4.0, plan[450].clone()));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL);
    assert!(has_bad(&v, "wire", "outside the windows"));
}

#[test]
fn stop_latency_over_a_second_is_fail() {
    let v = verdict_of(&mut Model::with(Knobs {
        stop_lat: 1.2,
        ..KNOBS
    }));
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(has_bad(&v, "s3_stop", "stop_to_stopped_ms"));
    let v = verdict_of(&mut Model::with(Knobs {
        stop_lat: 0.9,
        ..KNOBS
    }));
    assert_eq!(overall(&v), PASS, "{:?}", bad(&v));
}

#[test]
fn pause_latency_over_five_seconds_is_fail() {
    let v = verdict_of(&mut Model::with(Knobs {
        pause_wait: 5.5,
        ..KNOBS
    }));
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(has_bad(&v, "s2_pause", "pause_to_paused_ms"));
    let v = verdict_of(&mut Model::with(Knobs {
        pause_wait: 4.9,
        ..KNOBS
    }));
    assert_eq!(overall(&v), PASS, "{:?}", bad(&v));
}

#[test]
fn paused_without_the_runner_ack_text_is_fail() {
    let mut m = Model::consistent();
    m.paused_event()["detail"] = json!("Paused");
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL);
    assert!(has_bad(&v, "s2_pause", "checkpoint ACK"));
}

#[test]
fn first_leg_not_equal_next_index_is_fail() {
    let mut m = Model::consistent();
    m.smoke.as_mut().unwrap()["plan"][1]["paused_next_index"] = json!(5);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(has_bad(&v, "s2_pause", "equal paused_next_index"));
    // the history keeps the checkpoint after Resume
    let mut m = Model::consistent();
    m.history["scans"][1]["checkpoint_len"] = json!(64);
    assert_eq!(overall(&verdict_of(&mut m)), FAIL);
    let mut m = Model::consistent();
    m.history["scans"][1]["next_index"] = json!(6);
    assert_eq!(overall(&verdict_of(&mut m)), FAIL);
}

#[test]
fn resume_gap_or_duplicate_is_fail() {
    // a gap: one probe of the second leg is never sent
    let mut m = Model::consistent();
    m.syns[1].remove(10);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(has_bad(&v, "s2_pause", "SYN order"));
    // a duplicate: the first probe of the second leg is repeated from the first leg
    let mut m = Model::consistent();
    let again = m.syns[1][2].1.clone();
    let t = m.syns[1][7].0 + 0.05;
    m.syns[1].insert(8, (t, again));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL);
    assert!(has_bad(&v, "s2_pause", "exactly once"));
}

#[test]
fn a_row_without_a_wire_reply_is_fail() {
    let mut m = Model::consistent();
    m.rows_mut(1)
        .push(json!({"ip":PEER_IP,"port":4000,"open":true,"discovered_at":utc(T0 + 12.0)}));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(has_bad(&v, "s2_pause", "wire reply"));
    // the flag must match: a closed port reported open
    let mut m = Model::consistent();
    let row = m.rows_mut(0).iter_mut().find(|r| r["port"] == 443).unwrap();
    row["open"] = json!(true);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL);
    assert!(has_bad(&v, "s1_full", "wire reply"));
}

#[test]
fn a_synack_without_an_open_row_is_fail() {
    let mut m = Model::consistent();
    m.rows_mut(0).retain(|r| r["port"] != 8003);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(has_bad(&v, "s1_full", "genuine reply"));
    assert!(has_bad(&v, "s1_full", "open rows are the lab listeners"));
}

#[test]
fn missing_rst_is_tolerated() {
    let mut m = Model::consistent();
    // the peer's rate limit swallowed the RST of port 443 and of port 9004: no reply on the wire, no row
    for port in [443u16, 9004] {
        m.replies[0].retain(|(_, f)| tcp(f).unwrap().sp != port);
        m.rows_mut(0).retain(|r| r["port"] != port);
    }
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), PASS, "{:?}", bad(&v));
    // a genuine RST on the wire must be a result
    let mut m = Model::consistent();
    m.rows_mut(0).retain(|r| r["port"] != 9004);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL);
    assert!(has_bad(&v, "s1_full", "genuine reply"));
}

#[test]
fn replies_after_the_scanner_exit_are_only_a_note() {
    let mut m = Model::consistent();
    // listener teardown: an RST for a port of s1 arrives after the scan finished and has no row
    let syn = m.syns[0]
        .iter()
        .find(|(_, f)| tcp(f).unwrap().dp == 9001)
        .unwrap()
        .1
        .clone();
    m.replies[0].retain(|(_, f)| tcp(f).unwrap().sp != 9001);
    m.rows_mut(0).retain(|r| r["port"] != 9001);
    m.replies[0].push((T0 + 9.51, reply_to(&syn, false)));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), PASS, "{:?}", bad(&v));
    assert!(v["notes"]["post_run_replies.s1_full"].is_array());
}

#[test]
fn rows_seen_not_equal_history_rows_is_fail() {
    let mut m = Model::consistent();
    let d = m.write();
    let mut sm: Value = serde_json::from_slice(&fs::read(d.join("smoke.json")).unwrap()).unwrap();
    sm["plan"][0]["rows_seen"] = json!(19);
    let bytes = pretty(&sm);
    fs::write(d.join("smoke.json"), &bytes).unwrap();
    // keep the hashes honest so only the rule under test fails
    let list = fs::read_to_string(d.join(HASHES)).unwrap();
    let old = list
        .lines()
        .find(|l| l.ends_with("  smoke.json"))
        .unwrap()
        .to_owned();
    fs::write(
        d.join(HASHES),
        list.replace(&old, &format!("{}  smoke.json", sha(&bytes))),
    )
    .unwrap();
    let v = verify_dir(&d, false);
    fs::remove_dir_all(&d).ok();
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(has_bad(&v, "s1_full", "rows_seen"));
}

#[test]
fn history_must_match_the_plan_and_have_no_duplicate_rows() {
    let mut m = Model::consistent();
    m.history["scans"][0]["job"]["seed"] = json!("5");
    assert!(has_bad(
        &verdict_of(&mut m),
        "s1_full",
        "history job equals the plan"
    ));
    let mut m = Model::consistent();
    m.history["scans"][2]["status"] = json!("Completed");
    assert!(has_bad(
        &verdict_of(&mut m),
        "s3_stop",
        "history status is Stopped"
    ));
    let mut m = Model::consistent();
    m.history["scans"][1]["detail"] = json!("");
    assert!(has_bad(&verdict_of(&mut m), "s2_pause", "detail"));
    let mut m = Model::consistent();
    let dup = m.rows_mut(0)[0].clone();
    m.rows_mut(0).push(dup);
    assert!(has_bad(&verdict_of(&mut m), "s1_full", "no duplicate"));
    let mut m = Model::consistent();
    m.rows_mut(0)[0]["ip"] = json!("198.18.0.3");
    assert!(has_bad(&verdict_of(&mut m), "s1_full", "198.18.0.2"));
    let mut m = Model::consistent();
    m.history["scans"].as_array_mut().unwrap().remove(1);
    let v = verdict_of(&mut m);
    assert_ne!(overall(&v), PASS);
    assert!(has_bad(&v, "s2_pause", "history has the scan"));
}

#[test]
fn the_chronicle_must_follow_the_plan() {
    let mut m = Model::consistent();
    m.smoke.as_mut().unwrap()["actions"][3]["action"] = json!("Stop");
    assert!(has_bad(
        &verdict_of(&mut m),
        "chronicle",
        "actions equal the plan"
    ));
    let mut m = Model::consistent();
    m.smoke.as_mut().unwrap()["events"][0]["authorized"] = json!(false);
    assert!(has_bad(&verdict_of(&mut m), "chronicle", "exactly once"));
    let mut m = Model::consistent();
    m.smoke.as_mut().unwrap()["events"]
        .as_array_mut()
        .unwrap()
        .remove(1);
    assert!(has_bad(&verdict_of(&mut m), "chronicle", "preflight"));
    let mut m = Model::consistent();
    m.smoke.as_mut().unwrap()["result"] = json!("failed: Network preflight refused");
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL);
    assert!(has_bad(&v, "chronicle", "result is ok"));
    let mut m = Model::consistent();
    m.smoke.as_mut().unwrap()["result"] = json!("timeout in phase Scanning");
    // a Studio that hung after a Start broke the contract: FAIL (fix round 1, I5)
    assert_eq!(overall(&verdict_of(&mut m)), FAIL);
    let mut m = Model::consistent();
    m.smoke.as_mut().unwrap()["schema"] = json!(2);
    assert_ne!(overall(&verdict_of(&mut m)), PASS);
}

#[test]
fn scanner_syn_to_a_foreign_address_is_a_safety_fail() {
    let mut m = Model::consistent();
    let f = tcp_frame(
        SCANNER_MAC,
        NEXT_HOP_MAC,
        [198, 18, 0, 1],
        [198, 18, 0, 9],
        SOURCE_PORT,
        80,
        2,
    );
    m.syns[0].push((T0 + 6.3, f));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL);
    assert!(has_bad(&v, "safety", "no SYN from outside the binding"));
}

#[test]
fn manual_mode_skips_the_plan_but_keeps_safety_and_results() {
    let manual = |m: &mut Model| {
        m.smoke = None;
        let d = m.write();
        let v = verify_dir(&d, true);
        fs::remove_dir_all(d).ok();
        v
    };
    // the plan is broken (a probe never sent, the chronicle absent): no plan check, still PASS
    let mut m = Model::consistent();
    let gone = m.syns[0].remove(5);
    let port = tcp(&gone.1).unwrap().dp;
    m.replies[0].retain(|(_, f)| tcp(f).unwrap().sp != port);
    m.rows_mut(0).retain(|r| r["port"] != port);
    let v = manual(&mut m);
    assert_eq!(overall(&v), PASS, "{:?}", bad(&v));
    assert_eq!(v["notes"]["manual"], true);
    assert!(
        array(&v["cases"])
            .iter()
            .all(|c| c["tag"] != "chronicle" && c["tag"] != "s1_full")
    );
    // safety is kept
    let mut m = Model::consistent();
    m.uplink = vec![(T0 + 7.0, syn_of(80))];
    m.uplink_err = tcpdump_err(1, 500, 0);
    assert_eq!(overall(&manual(&mut m)), FAIL);
    // results are kept: a row without a wire reply
    let mut m = Model::consistent();
    m.rows_mut(2)
        .push(json!({"ip":PEER_IP,"port":4000,"open":true,"discovered_at":utc(T0)}));
    let v = manual(&mut m);
    assert_eq!(overall(&v), FAIL);
    assert!(bad(&v).iter().any(|b| b.contains("wire reply")));
    // a non-terminal status is not accepted
    let mut m = Model::consistent();
    m.history["scans"][0]["status"] = json!("Scanning");
    assert_eq!(overall(&manual(&mut m)), FAIL);
    // and without --manual the same directory is not a planned window
    let mut m = Model::consistent();
    m.smoke = None;
    let d = m.write();
    let v = verify_dir(&d, false);
    fs::remove_dir_all(d).ok();
    assert_eq!(overall(&v), NOT_RUN, "{:?}", bad(&v));
}

#[test]
fn verdict_never_upgrades_invalid_to_pass() {
    // an unclean peer witness (no exit statistics) is unproven, whatever the frames say
    let mut m = Model::consistent();
    m.peer_err = Some("tcpdump: listening on feth4202\n".into());
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), INVALID, "{:?}", bad(&v));
    assert_eq!(exit_code(&v), 2);
    // a truncated pcap is INVALID and the wire rules do not run on it
    let mut m = Model::consistent();
    let d = m.write();
    let mut b = fs::read(d.join("peer.pcap")).unwrap();
    b.truncate(b.len() - 7);
    let bytes = b;
    fs::write(d.join("peer.pcap"), &bytes).unwrap();
    let v = verify_dir(&d, false);
    fs::remove_dir_all(&d).ok();
    assert_ne!(overall(&v), PASS);
    assert!(has_bad(&v, "safety", "peer.pcap complete pcap"));
    // a missing capture is NOT RUN
    let mut m = Model::consistent();
    let d = m.write();
    fs::remove_file(d.join("uplink.err")).unwrap();
    fs::remove_file(d.join("uplink.pcap")).unwrap();
    let v = verify_dir(&d, false);
    fs::remove_dir_all(&d).ok();
    assert_ne!(overall(&v), PASS);
    // an isolation breach beats an unproven capture
    let mut m = Model::consistent();
    m.peer_err = Some(String::new());
    m.uplink = vec![(T0 + 7.0, syn_of(80))];
    m.uplink_err = tcpdump_err(1, 500, 0);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL);
    assert_eq!(exit_code(&v), 1);
    assert_eq!(exit_code(&json!({"overall":PASS})), 0);
    assert_eq!(exit_code(&json!({"overall":NOT_RUN})), 2);
}

#[test]
fn run_writes_the_verdict_and_returns_the_code() {
    let mut m = Model::consistent();
    let d = m.write();
    let out = d.join("verdict.json");
    let args = |extra: &[&str]| -> Vec<String> {
        ["--dir", d.to_str().unwrap(), "--out", out.to_str().unwrap()]
            .iter()
            .chain(extra)
            .map(|x| x.to_string())
            .collect()
    };
    assert_eq!(run(&args(&[])), Ok(0));
    let v: Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(v["overall"], PASS);
    assert!(v["provenance"]["verifier_sha256"].is_string());
    // verdict.json is outside the hashes: a second run over the same directory still passes
    assert_eq!(run(&args(&[])), Ok(0));
    assert!(
        run(&[
            "--dir".into(),
            d.join("nope").to_str().unwrap().into(),
            "--out".into(),
            out.to_str().unwrap().into()
        ])
        .is_err()
    );
    assert!(run(&["--dir".into(), d.to_str().unwrap().into()]).is_err());
    fs::remove_dir_all(d).ok();
}

// ------------------------------------------------------------------ fix round 1 (review of dd4cfe6)

fn write_file(d: &Path, name: &str, bytes: &[u8]) {
    fs::write(d.join(name), bytes).unwrap();
}
/// Re-hashes one file in `hashes-before-copy.txt` after a test edited it, so only the rule under test fails.
fn rehash(d: &Path, name: &str) {
    let list = fs::read_to_string(d.join(HASHES)).unwrap();
    let suffix = format!("  {name}");
    let old = list
        .lines()
        .find(|l| l.ends_with(&suffix))
        .unwrap()
        .to_owned();
    let new = format!("{}{suffix}", sha(&fs::read(d.join(name)).unwrap()));
    fs::write(d.join(HASHES), list.replace(&old, &new)).unwrap();
}
fn plan_of(case: usize) -> Vec<Vec<u8>> {
    plan_frames_for_job(&spec_job(&CASES[case])).unwrap()
}
fn action_time(m: &Model, name: &str) -> f64 {
    let a = m.smoke.as_ref().unwrap()["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["action"] == name)
        .unwrap();
    parse_utc(s(&a["utc"])).unwrap()
}

#[test]
fn an_extra_syn_from_another_source_port_is_fail() {
    let mut m = Model::consistent();
    let port = tcp(&plan_of(0)[3]).unwrap().dp;
    let f = tcp_frame(
        SCANNER_MAC,
        NEXT_HOP_MAC,
        [198, 18, 0, 1],
        [198, 18, 0, 2],
        40001,
        port,
        2,
    );
    m.syns[0].push((T0 + 6.35, f));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(has_bad(&v, "wire", "from the scanner"), "{:?}", bad(&v));
}

#[test]
fn a_non_syn_from_the_scanner_is_fail() {
    let mut m = Model::consistent();
    let f = tcp_frame(
        SCANNER_MAC,
        NEXT_HOP_MAC,
        [198, 18, 0, 1],
        [198, 18, 0, 2],
        SOURCE_PORT,
        8003,
        4,
    );
    m.syns[0].push((T0 + 6.35, f));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(has_bad(&v, "wire", "from the scanner"), "{:?}", bad(&v));
    // the same frame in manual mode
    let mut m = Model::consistent();
    let f = tcp_frame(
        SCANNER_MAC,
        NEXT_HOP_MAC,
        [198, 18, 0, 1],
        [198, 18, 0, 2],
        SOURCE_PORT,
        8003,
        4,
    );
    m.syns[0].push((T0 + 6.35, f));
    m.smoke = None;
    let d = m.write();
    let v = verify_dir(&d, true);
    fs::remove_dir_all(d).ok();
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
}

#[test]
fn the_uplink_witness_must_be_the_default_route_interface_with_the_lab_filter() {
    // another interface (M04c)
    let mut m = Model::consistent();
    m.edit("uplink.cmd.json", |v| {
        v["cmd"][7] = json!("en7");
        v["interface"] = json!("en7");
    });
    m.uplink_err = tcpdump_err_on("en7", 0, 100, 0);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), INVALID, "{:?}", bad(&v));
    assert!(has_bad(&v, "safety", "uplink capture interface and filter"));
    // a narrower filter
    let mut m = Model::consistent();
    m.edit("uplink.cmd.json", |v| {
        v["cmd"][10] = json!("net 198.18.0.0/30");
        v["filter"] = json!("net 198.18.0.0/30");
    });
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
    // promiscuous (no -p)
    let mut m = Model::consistent();
    m.edit("uplink.cmd.json", |v| v["cmd"][1] = json!("-n"));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), INVALID);
    assert!(has_bad(&v, "safety", "not promiscuous"));
    // a feth uplink is the pair, not the user's NIC
    let mut m = Model::consistent();
    m.pre["uplink"] = json!("feth4201");
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
    // the banner of the .err must name the interface too
    let mut m = Model::consistent();
    m.uplink_err = tcpdump_err_on("en5", 0, 100, 0);
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
}

#[test]
fn the_peer_witness_must_be_the_peer_interface_without_a_filter() {
    let mut m = Model::consistent();
    m.edit("peer.cmd.json", |v| v["cmd"][7] = json!("feth4201"));
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
    let mut m = Model::consistent();
    m.edit("peer.cmd.json", |v| {
        v["cmd"]
            .as_array_mut()
            .unwrap()
            .push(json!("tcp port 8000"));
        v["filter"] = json!("tcp port 8000");
    });
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
}

#[test]
fn a_witness_must_cover_the_session_and_exit_cleanly() {
    // stopped before the last scan ended
    let mut m = Model::consistent();
    m.edit("uplink.cmd.json", |v| v["stop_utc"] = json!(utc(T0 + 20.0)));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), INVALID, "{:?}", bad(&v));
    assert!(has_bad(&v, "safety", "covers the session"));
    // started after the first Start
    let mut m = Model::consistent();
    m.edit("uplink.cmd.json", |v| v["start_utc"] = json!(utc(T0 + 6.5)));
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
    // not listening before the first action
    let mut m = Model::consistent();
    m.edit("peer.cmd.json", |v| v["listening"] = json!(false));
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
    // killed, not interrupted
    let mut m = Model::consistent();
    m.edit("uplink.cmd.json", |v| v["exit_code"] = json!(137));
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
    // no capture record at all
    for name in ["uplink.cmd.json", "peer.cmd.json"] {
        let mut m = Model::consistent();
        m.skip.push(if name == "uplink.cmd.json" {
            "uplink.cmd.json"
        } else {
            "peer.cmd.json"
        });
        let v = verdict_of(&mut m);
        assert_eq!(overall(&v), INVALID, "{name}: {:?}", bad(&v));
    }
}

#[test]
fn a_late_peer_witness_is_invalid_not_fail() {
    // M04e: the peer capture started after s1 ran; its frames are missing
    let mut m = Model::consistent();
    m.syns[0].clear();
    m.replies[0].clear();
    m.edit("peer.cmd.json", |v| v["start_utc"] = json!(utc(T0 + 8.0)));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), INVALID, "{:?}", bad(&v));
}

#[test]
fn frames_outside_the_capture_window_make_it_invalid() {
    let mut m = Model::consistent();
    let syn = plan_of(0)[0].clone();
    m.replies[0].push((T0 - 100.0, reply_to(&syn, false)));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), INVALID, "{:?}", bad(&v));
    assert!(has_bad(&v, "safety", "inside the recorded window"));
}

#[test]
fn a_behaviour_fail_is_not_laundered_by_unproven_evidence() {
    // M08a: a SYN after Stop, plus a file nobody hashed
    let mut m = Model::consistent();
    let last = m.syns[2].last().unwrap().0;
    m.syns[2].push((last + 0.01 + KNOBS.stop_lat + 0.5, plan_of(2)[450].clone()));
    let d = m.write();
    write_file(&d, "stray.txt", b"x");
    let v = verify_dir(&d, false);
    fs::remove_dir_all(&d).ok();
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert_eq!(exit_code(&v), 1);
    assert!(array(&v["behaviour_fail"]).iter().any(|t| t == "s3_stop"));
    // M08b: a 5.5 s pause plus a recorded figure that is off by 100 ms
    let mut m = Model::with(Knobs {
        pause_wait: 5.5,
        ..KNOBS
    });
    m.smoke.as_mut().unwrap()["plan"][1]["pause_to_paused_ms"] = json!(5400);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    // an unproven window without a behaviour failure stays INVALID
    let mut m = Model::consistent();
    m.uplink_err = tcpdump_err(0, 500, 3);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), INVALID);
    assert!(array(&v["behaviour_fail"]).is_empty());
}

#[test]
fn provenance_is_bound_to_a_commit_and_to_real_hashes() {
    for key in [
        "git_head",
        "ui_sha256",
        "runner_sha256",
        "installed_runner_sha256",
    ] {
        let mut m = Model::consistent();
        m.prov.as_object_mut().unwrap().remove(key);
        let v = verdict_of(&mut m);
        assert_eq!(overall(&v), INVALID, "{key}: {:?}", bad(&v));
    }
    let mut m = Model::consistent();
    m.prov["runner_sha256"] = json!("z".repeat(64));
    m.prov["installed_runner_sha256"] = json!("z".repeat(64));
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
    let mut m = Model::consistent();
    m.prov["git_head"] = json!("main");
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
}

#[test]
fn a_pause_that_does_not_split_the_probes_is_invalid() {
    for k in [0usize, 32] {
        let mut m = Model::consistent();
        let resume = action_time(&m, "Resume");
        let pause = action_time(&m, "Pause");
        for i in 0..32 {
            // k = 0: every probe after Resume; k = 32: every probe before Pause (a fast first leg)
            let t = if k == 0 {
                resume + 0.2 + i as f64 * 0.25
            } else {
                pause - 1.5 + i as f64 * 0.01
            };
            m.syns[1][i].0 = t;
            m.replies[1][i].0 = t + 0.0005;
        }
        m.smoke.as_mut().unwrap()["plan"][1]["paused_next_index"] = json!(k);
        let v = verdict_of(&mut m);
        assert_eq!(overall(&v), INVALID, "k {k}: {:?}", bad(&v));
        assert!(has_bad(&v, "s2_pause", "split"), "{:?}", bad(&v));
    }
}

#[test]
fn a_missing_history_is_not_run() {
    let mut m = Model::consistent();
    m.skip.push("history.json");
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), NOT_RUN, "{:?}", bad(&v));
    assert_eq!(exit_code(&v), 2);
    let mut m = Model::consistent();
    let d = m.write();
    write_file(&d, "history.json", b"not json");
    rehash(&d, "history.json");
    let v = verify_dir(&d, false);
    fs::remove_dir_all(&d).ok();
    assert_eq!(overall(&v), NOT_RUN, "{:?}", bad(&v));
}

#[test]
fn a_hang_after_the_first_start_is_fail_and_before_it_is_not_run() {
    let mut m = Model::consistent();
    m.smoke.as_mut().unwrap()["result"] = json!("timeout in phase Scanning");
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    // authorization never finished: nothing ran
    let mut m = Model::consistent();
    m.syns = vec![vec![], vec![], vec![]];
    m.replies = vec![vec![], vec![], vec![]];
    m.history = json!({"scans":[]});
    let sm = m.smoke.as_mut().unwrap();
    sm["result"] = json!("timeout in phase Authorization");
    sm["actions"] = json!([action(0.0, "Authorize")]);
    sm["events"] = json!([]);
    sm["plan"] = json!([]);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), NOT_RUN, "{:?}", bad(&v));
}

#[test]
fn a_darwin_synack_then_rst_is_one_result() {
    // Darwin aborts the embryonic connection of an open port with an RST; Studio keeps one row per port
    let mut m = Model::consistent();
    let syn = m.syns[0]
        .iter()
        .find(|(_, f)| tcp(f).unwrap().dp == 8003)
        .unwrap()
        .clone();
    m.replies[0].push((syn.0 + 0.002, reply_to(&syn.1, false)));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), PASS, "{:?}", bad(&v));
}

#[test]
fn an_unplanned_scan_in_the_history_is_fail() {
    let mut m = Model::consistent();
    let mut extra = m.history["scans"][0].clone();
    extra["scan_id_hex"] = json!("44444444444444444444444444444444");
    m.history["scans"].as_array_mut().unwrap().push(extra);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(
        has_bad(&v, "chronicle", "exactly the planned scans")
            || bad(&v)
                .iter()
                .any(|b| b.contains("exactly the planned scans"))
    );
}

#[test]
fn a_listed_entry_that_cannot_be_read_is_invalid() {
    let mut m = Model::consistent();
    let d = m.write();
    fs::create_dir_all(d.join("sub")).unwrap();
    let list = fs::read_to_string(d.join(HASHES)).unwrap();
    fs::write(d.join(HASHES), format!("{list}{}  sub\n", "0".repeat(64))).unwrap();
    let v = verify_dir(&d, false);
    fs::remove_dir_all(&d).ok();
    assert_eq!(overall(&v), INVALID, "{:?}", bad(&v));
}

#[test]
fn chronicle_times_must_agree_with_themselves() {
    // finished_utc of the case record is a second after the terminal State
    let mut m = Model::consistent();
    let t = parse_utc(s(&m.smoke.as_ref().unwrap()["plan"][2]["finished_utc"])).unwrap();
    m.smoke.as_mut().unwrap()["plan"][2]["finished_utc"] = json!(utc(t + 1.0));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), INVALID, "{:?}", bad(&v));
    // the wall clock stepped between two events
    let mut m = Model::consistent();
    let sm = m.smoke.as_mut().unwrap();
    let t = parse_utc(s(&sm["events"][14]["utc"])).unwrap();
    sm["events"][14]["utc"] = json!(utc(t + 0.5));
    let v = verdict_of(&mut m);
    assert_ne!(overall(&v), PASS, "{:?}", bad(&v));
}

#[test]
fn the_files_of_the_orchestrator_are_judged() {
    type Mutation = Box<dyn Fn(&mut Model)>;
    let cases: Vec<(&str, Mutation, &str)> = vec![
        (
            "invalid mark",
            Box::new(|m| {
                m.edit("window.json", |v| {
                    v["invalid_marks"] = json!(["history not closed cleanly"])
                })
            }),
            INVALID,
        ),
        (
            "ui_rc",
            Box::new(|m| m.edit("window.json", |v| v["ui_rc"] = json!(1))),
            INVALID,
        ),
        (
            "window uplink",
            Box::new(|m| m.edit("window.json", |v| v["uplink"] = json!("en9"))),
            INVALID,
        ),
        (
            "no window.json",
            Box::new(|m| m.skip.push("window.json")),
            NOT_RUN,
        ),
        (
            "alf",
            Box::new(|m| {
                m.extra.insert(
                    "alf.txt".into(),
                    b"Firewall is enabled. (State = 1)\n".to_vec(),
                );
            }),
            INVALID,
        ),
        (
            "leftover listeners",
            Box::new(|m| {
                m.extra.insert(
                    "leftover-listeners.txt".into(),
                    b"some-process 123\n".to_vec(),
                );
            }),
            INVALID,
        ),
        (
            "leftover procs",
            Box::new(|m| {
                m.extra.insert(
                    "leftover-procs.txt".into(),
                    b"tcpdump -i feth4202\n".to_vec(),
                );
            }),
            INVALID,
        ),
        (
            "no pair-quiet",
            Box::new(|m| m.skip.push("pair-quiet.txt")),
            NOT_RUN,
        ),
        (
            "listeners not ready",
            Box::new(|m| m.skip.push("listeners-ready.txt")),
            INVALID,
        ),
        (
            "data hash",
            Box::new(|m| {
                m.extra.insert(
                    "data.sha256".into(),
                    format!("{}  history.sqlite3\n", "1".repeat(64)).into_bytes(),
                );
            }),
            INVALID,
        ),
        (
            "no data hash",
            Box::new(|m| m.skip.push("data.sha256")),
            NOT_RUN,
        ),
        (
            "isolation breach",
            Box::new(|m| {
                m.extra
                    .insert("ISOLATION-BREACH.txt".into(), b"frame on en0\n".to_vec());
            }),
            FAIL,
        ),
    ];
    for (name, f, want) in cases {
        let mut m = Model::consistent();
        f(&mut m);
        let v = verdict_of(&mut m);
        assert_eq!(overall(&v), want, "{name}: {:?}", bad(&v));
    }
    // the SQLite store left a journal behind: not closed cleanly
    let mut m = Model::consistent();
    let d = m.write();
    write_file(&d, "data/history.sqlite3-wal", b"x");
    let v = verify_dir(&d, false);
    fs::remove_dir_all(&d).ok();
    assert_eq!(overall(&v), INVALID, "{:?}", bad(&v));
    // and the real file must hash to data.sha256
    let mut m = Model::consistent();
    let d = m.write();
    write_file(&d, "data/history.sqlite3", b"changed");
    let v = verify_dir(&d, false);
    fs::remove_dir_all(&d).ok();
    assert_eq!(overall(&v), INVALID, "{:?}", bad(&v));
}

#[test]
fn late_replies_before_a_stop_need_no_row() {
    // the last replies before the Stop action may not have reached the results
    let mut m = Model::consistent();
    let n = m.syns[2].len();
    let late: Vec<u16> = m.syns[2][n - 5..]
        .iter()
        .map(|(_, f)| tcp(f).unwrap().dp)
        .collect();
    m.rows_mut(2)
        .retain(|r| !late.contains(&(r["port"].as_u64().unwrap() as u16)));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), PASS, "{:?}", bad(&v));
    // but a reply from the middle of the scan without a row is a failure
    let mut m = Model::consistent();
    let mid = tcp(&m.syns[2][100].1).unwrap().dp;
    m.rows_mut(2).retain(|r| r["port"] != mid);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL);
}

#[test]
fn host_wildcard_listeners_make_scanned_ports_open() {
    let open_9003 = |m: &mut Model| {
        let (t, f) = m.syns[0]
            .iter()
            .find(|(_, f)| tcp(f).unwrap().dp == 9003)
            .unwrap()
            .clone();
        m.replies[0].retain(|(_, r)| tcp(r).unwrap().sp != 9003);
        m.replies[0].push((t + 0.0005, reply_to(&f, true)));
        for r in m.rows_mut(0) {
            if r["port"] == 9003 {
                r["open"] = json!(true);
            }
        }
    };
    let listen =
        "rc 0\ntcp4       0      0  *.9003                 *.*                    LISTEN\n";
    let mut m = Model::consistent();
    open_9003(&mut m);
    m.host_before = listen.into();
    m.host_after = listen.into();
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), PASS, "{:?}", bad(&v));
    // not recorded as a listener: the extra open port is not a lab listener
    let mut m = Model::consistent();
    open_9003(&mut m);
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(has_bad(&v, "s1_full", "open rows are the lab listeners"));
    // a netstat that failed is not a record
    let mut m = Model::consistent();
    m.host_before = "rc 1\n".into();
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
}

#[test]
fn the_peer_capture_must_be_complete() {
    let n = Model::consistent().peer_frames().len();
    let mut m = Model::consistent();
    m.peer_err = Some(tcpdump_err_on("feth4202", n - 1, n, 0));
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
    let mut m = Model::consistent();
    m.peer_err = Some(tcpdump_err_on("feth4202", n, n + 5, 2));
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
    // the uplink statistics must be there
    let mut m = Model::consistent();
    m.uplink_err = "tcpdump: listening on en0\n".into();
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), INVALID, "{:?}", bad(&v));
}

#[test]
fn manual_mode_accepts_an_interrupted_scan() {
    let mut m = Model::consistent();
    m.smoke = None;
    m.history["scans"][0]["status"] = json!("Interrupted");
    let d = m.write();
    let v = verify_dir(&d, true);
    fs::remove_dir_all(&d).ok();
    assert_eq!(overall(&v), PASS, "{:?}", bad(&v));
}

#[test]
fn the_verdict_carries_the_facts_the_rerun_rule_needs() {
    let v = verdict_of(&mut Model::consistent());
    assert!(array(&v["behaviour_fail"]).is_empty());
    assert!(array(&v["safety_trips"]).is_empty());
    assert_eq!(v["isolation"]["uplink_exit_code"], 0);
    assert_eq!(v["isolation"]["peer_exit_code"], 0);
    let c = array(&v["cases"])
        .iter()
        .find(|c| c["tag"] == "s3_stop")
        .unwrap();
    assert!(
        array(&c["checks"])
            .iter()
            .all(|k| k["behaviour"].is_boolean())
    );
    assert!(array(&c["checks"]).iter().any(|k| k["behaviour"] == true));
    let sf = array(&v["cases"])
        .iter()
        .find(|c| c["tag"] == "safety")
        .unwrap();
    assert!(array(&sf["checks"]).iter().any(|k| k["safety"] == true));
}

#[test]
fn expect_head_binds_the_window_to_a_commit() {
    let mut m = Model::consistent();
    let d = m.write();
    let out = d.join("verdict.json");
    let head = "0123456789abcdef0123456789abcdef01234567";
    let args = |h: &str| -> Vec<String> {
        [
            "--dir",
            d.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--expect-head",
            h,
        ]
        .iter()
        .map(|x| x.to_string())
        .collect()
    };
    assert_eq!(run(&args(head)), Ok(0));
    assert_eq!(run(&args(&"f".repeat(40))), Ok(2));
    fs::remove_dir_all(d).ok();
}

// ------------------------------------------------------------------ fix round 2

/// A session that ended before any Start, in the shape the committed driver writes: three plan records with null
/// scan ids, `Authorize` (and `Lock`) as the only actions, the reason as the result, no scan in the history.
fn ended_before_start(result: &str, events: Vec<Value>) -> Model {
    let mut m = Model::consistent();
    m.syns = vec![vec![], vec![], vec![]];
    m.replies = vec![vec![], vec![], vec![]];
    m.history = json!({"scans":[]});
    let sm = m.smoke.as_mut().unwrap();
    for p in sm["plan"].as_array_mut().unwrap() {
        p["scan_id_hex"] = Value::Null;
        p["rows_seen"] = json!(0);
        p["finished_utc"] = Value::Null;
        p["finished_status"] = Value::Null;
        p["paused_next_index"] = Value::Null;
        p["pause_to_paused_ms"] = Value::Null;
        p["stop_to_stopped_ms"] = Value::Null;
    }
    sm["result"] = json!(result);
    sm["actions"] = json!([action(0.0, "Authorize"), action(2.0, "Lock")]);
    sm["events"] = json!(events);
    m
}
fn authorization(t: f64, authorized: bool, detail: &str) -> Value {
    let mut e = event(t, "Authorization", "", detail);
    e["authorized"] = json!(authorized);
    e
}

#[test]
fn a_session_that_ends_before_any_start_is_not_run() {
    let cases = [
        (
            "cancelled dialog",
            "Authorization failed: User cancelled",
            vec![authorization(1.0, false, "User cancelled")],
        ),
        (
            "authorization timeout",
            "timeout in phase Authorize after 200 s",
            vec![],
        ),
        (
            "preflight refused",
            "Network preflight refused: stand is down",
            vec![
                authorization(0.5, true, ""),
                event(
                    1.0,
                    "Notice",
                    "",
                    "Network preflight refused: stand is down",
                ),
            ],
        ),
    ];
    for (name, result, events) in cases {
        let mut m = ended_before_start(result, events);
        let v = verdict_of(&mut m);
        assert_eq!(overall(&v), NOT_RUN, "{name}: {:?}", bad(&v));
        assert_eq!(exit_code(&v), 2);
        assert!(array(&v["behaviour_fail"]).is_empty(), "{name}");
        // the reason is the chronicle's own
        let ch = array(&v["cases"])
            .iter()
            .find(|c| c["tag"] == "chronicle")
            .unwrap();
        assert!(
            array(&ch["checks"]).iter().any(|k| k["detail"] == result),
            "{name}"
        );
    }
    // a safety trip still FAILs
    let mut m = ended_before_start("timeout in phase Authorize after 200 s", vec![]);
    m.uplink = vec![(T0 + 1.0, syn_of(80))];
    m.uplink_err = tcpdump_err(1, 500, 0);
    assert_eq!(overall(&verdict_of(&mut m)), FAIL);
}

#[test]
fn the_stop_grace_is_100_ms() {
    let stopped = |m: &Model| {
        let a = m.smoke.as_ref().unwrap()["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["status"] == "Stopped")
            .unwrap();
        parse_utc(s(&a["utc"])).unwrap()
    };
    let mut m = Model::consistent();
    let t = stopped(&m) + 0.05;
    m.syns[2].push((t, plan_of(2)[450].clone()));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), PASS, "{:?}", bad(&v));
    let mut m = Model::consistent();
    let t = stopped(&m) + 0.15;
    m.syns[2].push((t, plan_of(2)[450].clone()));
    let v = verdict_of(&mut m);
    assert_eq!(overall(&v), FAIL, "{:?}", bad(&v));
    assert!(has_bad(&v, "s3_stop", "no SYN after Stopped"));
}

#[test]
fn the_drift_cap_scales_with_the_session() {
    assert_eq!(drift_cap_s(0.0), 0.1);
    assert!((drift_cap_s(420.0) - 0.52).abs() < 1e-9);
    assert_eq!(drift_cap_s(-5.0), 0.1);
    // a 26 s session: 0.12 s of drift is inside the cap (0.126), 0.2 s is not
    let shifted = |dt: f64| {
        let mut m = Model::consistent();
        let sm = m.smoke.as_mut().unwrap();
        let n = sm["events"].as_array().unwrap().len();
        let t = parse_utc(s(&sm["events"][n - 1]["utc"])).unwrap();
        sm["events"][n - 1]["utc"] = json!(utc(t + dt));
        verdict_of(&mut m)
    };
    let v = shifted(0.115);
    assert_eq!(overall(&v), PASS, "{:?}", bad(&v));
    let v = shifted(0.2);
    assert_eq!(overall(&v), INVALID, "{:?}", bad(&v));
    assert!(has_bad(&v, "chronicle", "clocks agree"));
}
