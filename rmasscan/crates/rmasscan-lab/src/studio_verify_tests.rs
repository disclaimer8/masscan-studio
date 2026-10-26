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
    format!(
        "tcpdump: listening on x, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n{captured} packets captured\n{received} packets received by filter\n{dropped} packets dropped by kernel\n"
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
        extra.insert("window.json".into(), pretty(&json!({"ui_rc":0})));
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
            if let Some(sm) = self.smoke.as_mut() {
                sm["plan"][c]["rows_seen"] = json!(n);
            }
        }
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
                .unwrap_or_else(|| tcpdump_err(peer.len(), peer.len() + 50, 0))
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
    m.syns[2].push((last + 30.0, plan[450].clone()));
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
    assert_eq!(overall(&verdict_of(&mut m)), INVALID);
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
    assert_eq!(overall(&v), NOT_RUN);
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
