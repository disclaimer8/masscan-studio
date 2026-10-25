//! Synthetic, hermetic Windows part B evidence for the verifier tests.
//!
//! The directories built here are tiny and invented: frames are generated, not
//! captured, and every number is chosen so one rule at a time can be broken by a
//! test. Nothing reads an untracked or discarded evidence directory.
use super::*;
use crate::windows_suite::{capture_commands, mutate_checkpoint};

pub(crate) const SM: &str = "52:54:00:04:80:a9";
pub(crate) const PM: &str = "02:57:4c:3d:2e:9b";
pub(crate) const NETNS: &str = "wvp-n2";
pub(crate) const NPF: &str = "\\Device\\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}";
pub(crate) const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
pub(crate) const EXE: &str = "abababababababababababababababababababababababababababababababab";
pub(crate) const BASE: f64 = 1_800_000_000.0;
const SRC: [u8; 4] = [198, 18, 0, 1];
const DST: [u8; 4] = [198, 18, 0, 2];

fn mac(s: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    for (i, p) in s.split(':').enumerate() {
        out[i] = u8::from_str_radix(p, 16).unwrap();
    }
    out
}
#[allow(clippy::too_many_arguments)]
fn frame(
    sm: &str,
    dm: &str,
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    flags: u8,
    id: u16,
) -> Vec<u8> {
    let mut b = vec![0u8; 54];
    b[0..6].copy_from_slice(&mac(dm));
    b[6..12].copy_from_slice(&mac(sm));
    b[12] = 8;
    b[14] = 0x45;
    b[16..18].copy_from_slice(&40u16.to_be_bytes());
    b[18..20].copy_from_slice(&id.to_be_bytes());
    b[22] = 64;
    b[23] = 6;
    b[26..30].copy_from_slice(&src);
    b[30..34].copy_from_slice(&dst);
    b[34..36].copy_from_slice(&sport.to_be_bytes());
    b[36..38].copy_from_slice(&dport.to_be_bytes());
    b[46] = 0x50;
    b[47] = flags;
    b
}
pub(crate) fn scanner_syn(port: u16, sport: u16) -> Vec<u8> {
    frame(SM, PM, SRC, DST, sport, port, 2, 1)
}
fn peer_reply(port: u16, sport: u16, open: bool) -> Vec<u8> {
    frame(
        PM,
        SM,
        DST,
        SRC,
        port,
        sport,
        if open { 0x12 } else { 0x14 },
        9,
    )
}
fn ether_frame(ethertype: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 60];
    b[0..6].copy_from_slice(&mac(SM));
    b[6..12].copy_from_slice(&mac(PM));
    b[12..14].copy_from_slice(&ethertype);
    b[14..14 + payload.len()].copy_from_slice(payload);
    b
}
fn marker(payload: &[u8]) -> Vec<u8> {
    ether_frame([0x88, 0xb5], payload)
}
fn flood_frame() -> Vec<u8> {
    ether_frame([0x88, 0xb6], b"flood")
}
fn syn_series(count: usize, first: f64, period: f64, port0: u16, sport: u16) -> Frames {
    (0..count)
        .map(|k| {
            (
                first + k as f64 * period,
                scanner_syn(port0 + k as u16, sport),
            )
        })
        .collect()
}
fn pretty(v: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(v).unwrap()
}
fn put(dir: &Path, name: &str, bytes: impl AsRef<[u8]>) {
    fs::write(dir.join(name), bytes).unwrap();
}
fn manifest(schema: u64) -> Value {
    manifest_for(schema, "failure")
}
fn manifest_for(schema: u64, plan: &str) -> Value {
    let mut silent = vec![8099u32];
    if plan == "failure" {
        silent.extend(8100..8120);
    }
    let mut m = json!({
        "schema":1,"capture_schema":schema,"suite":plan,"plan":plan,
        "code_commit":COMMIT,
        "exe":{"sha256":EXE,"size":1,"guest_path":"C:\\x\\wire_scan.exe","build":"synthetic"},
        "binding":{"iface":NPF,"src_ip":"198.18.0.1","src_mac":SM,"router_mac":PM,"peer_ip":"198.18.0.2","seed":1,"rate":100,"wait":3},
        "stand":{"run_id":"n2","netns":NETNS,"manifest":"$HOME/winvm/lab/n2.json"},
        "listeners":{"open":[80,443,8000,8001,8002,8003,8004,8005,8006,8007],"silent":silent},
        "oracle":{"sha256":"cd","git_commit":"ef","git_tree_clean":true},
        "pause":{"case":"c03_multi_ports","n":[0,1,8,15]}
    });
    if schema >= 3 {
        // What the suite records for the Mac-side build that ran it (provenance.rs).
        m["orchestrator"] = json!({"git_commit":COMMIT,"git_dirty":false,"binary_sha256":"ab".repeat(32),"binary_name":"rmasscan-lab","errors":[]});
    }
    m
}
fn job_echo(c: &Value, man: &Value) -> Value {
    let b = &man["binding"];
    let mut j = json!({"iface":b["iface"],"src_ip":b["src_ip"],"src_mac":b["src_mac"],"router_mac":b["router_mac"],"retries":0,"shard":"1/1","blackrock_rounds":14,"job_digest":"00"});
    for k in [
        "source_port",
        "targets",
        "exclude",
        "ports",
        "seed",
        "rate",
        "wait",
    ] {
        j[k] = c[k].clone();
    }
    j
}
pub(crate) struct Built {
    pub(crate) tag: String,
    pub(crate) frames: Frames,
    pub(crate) run: Value,
    pub(crate) guest_exit: i64,
    pub(crate) outcome: f64,
    pub(crate) files: Vec<(String, Vec<u8>)>,
    pub(crate) meta: Value,
}
fn workers() -> (Value, Value) {
    (
        json!({"tx_tid":11,"rx_tid":12,"tx_alive_after_join":false,"rx_alive_after_join":false}),
        json!({"fds_before_open":10,"fds_open":20,"fds_after_join":10,"threads_before":4,"threads_after_join":4}),
    )
}
/// A run.json shared by all kinds; kind builders override the fields they own.
fn base_run(c: &Value, man: &Value, t0: f64, outcome: f64, tag: &str) -> Value {
    let (w, res) = workers();
    json!({
        "run_id":format!("run-{tag}"),"status":"ok","reason":"Completed","fail_detail":"",
        "identity":{"source_commit":COMMIT,"binary_sha256":EXE,"elevated":true,"restricted_token":false,"os":{"family":"windows"}},
        "job":job_echo(c,man),
        "net":{"kernel_drops":0,"rx_errors":0,"rx_packets":0,"tx_errors":0,"tx_sent":0,"tx_uncertain":0},
        "rx_health":{"kernel_drops":0},
        "sent":0,"next_index":0,"range":n(&c["syn"]),"expected_total":n(&c["syn"]),
        "replies":[],"reply_total":0,"reply_unique":0,"received":0,"duplicates":0,"discarded":0,
        "checkpoint":false,"checkpoint_hex":null,"checkpoint_next_index":null,
        "tx_sent_at_join":0,"tx_sent_after_observe":0,"observe_ms":1500,
        "workers":w,"resources":res,
        "timing":{"first_send_s":0.002,"join_ms":0.3,"stop_requested":false,"stop_to_outcome_ms":null,"total_s":outcome-t0},
        "wall":{"t0_utc_ms":(t0*1000.).round(),"outcome_utc_ms":(outcome*1000.).round()}
    })
}
fn set_sent(run: &mut Value, count: u64) {
    for k in [
        "sent",
        "next_index",
        "tx_sent_at_join",
        "tx_sent_after_observe",
    ] {
        run[k] = json!(count);
    }
    run["net"]["tx_sent"] = json!(count);
}
fn nonempty_checkpoint(scan: &str, attempt: &str, next: u64) -> Vec<u8> {
    let mut b = b"RMSCNCKP".to_vec();
    b.extend(1u32.to_be_bytes());
    b.extend(1u32.to_be_bytes());
    b.extend(hex_decode(scan));
    b.extend(hex_decode(attempt));
    b.extend([0u8; 32]);
    b.extend(next.to_be_bytes());
    let sum = Sha256::digest(&b);
    b.extend(sum);
    b
}
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}
fn build_kind(it: &Value, man: &Value, tag: &str) -> Built {
    let t0 = BASE + 3.0;
    let c = kind_case(it).unwrap_or(Value::Null);
    let exp = if c.is_null() {
        vec![]
    } else if it["kind"] == "perf" {
        perf_expected(&c)
    } else {
        replies(&c, false)
    };
    let mut files = Vec::new();
    let mut meta = json!({});
    let kind = s(&it["kind"]).to_string();
    let mut frames: Frames = Vec::new();
    let mut run: Value;
    let mut guest_exit = 0i64;
    let outcome: f64;
    match kind.as_str() {
        "stop" => {
            let scenario = s(&it["scenario"]).to_string();
            let (count, period) = (
                if matches!(scenario.as_str(), "silent" | "load") {
                    3
                } else {
                    2
                },
                1.0,
            );
            let sport = 40000;
            frames = syn_series(count, t0 + 0.002, period, 8100, sport);
            outcome = if scenario == "drain" || scenario == "fullqueue" {
                t0 + 3.0
            } else {
                t0 + 2.5
            };
            run = base_run(&c, man, t0, outcome, tag);
            run["reason"] = json!("Stopped");
            run["timing"]["stop_requested"] = json!(true);
            run["timing"]["stop_to_outcome_ms"] = json!(25.8);
            set_sent(&mut run, count as u64);
            if scenario == "drain" || scenario == "fullqueue" {
                run["replies"] = json!(exp);
                run["reply_total"] = json!(exp.len());
                run["reply_unique"] = json!(exp.len());
            }
            if scenario == "load" {
                run["net"]["rx_packets"] = json!(5000);
                let flood: Frames = (0..12)
                    .map(|k| (t0 - 1.0 + k as f64 * 0.5, flood_frame()))
                    .collect();
                files.push((
                    "flood.json".into(),
                    pretty(
                        &json!({"sent":12,"errors":0,"t_first":flood[0].0,"t_last":flood[11].0}),
                    ),
                ));
                frames.extend(flood);
            }
        }
        "overflow_queue" => {
            outcome = t0 + 3.2;
            frames = syn_series(3, t0 + 0.002, 1.0, 80, 40000);
            run = base_run(&c, man, t0, outcome, tag);
            run["reason"] = json!("Failed");
            run["status"] = json!("failed");
            run["fail_detail"] = json!("ConsumerTooSlow { capacity: 1 }");
            set_sent(&mut run, 3);
            run["replies"] = json!(&exp[..2]);
            run["reply_total"] = json!(2);
            run["reply_unique"] = json!(2);
            guest_exit = 3;
        }
        "linkloss" => {
            outcome = t0 + 1.8;
            frames = syn_series(31, t0 + 0.002, 0.05, 8200, 40000);
            run = base_run(&c, man, t0, outcome, tag);
            run["reason"] = json!("Failed");
            run["status"] = json!("failed");
            run["fail_detail"] = json!("TxUncertain { sent: 30 }");
            set_sent(&mut run, 30);
            run["net"]["tx_uncertain"] = json!(1);
            guest_exit = 3;
            meta["checkpoint_file_exists"] = json!(false);
            files.push((
                "linkloss.json".into(),
                pretty(&json!({"first_syn_seen":true,"events":[
                    {"set_link":"down","t":outcome-0.4,"reply":{"return":{}}},
                    {"set_link":"up","t":outcome+1.0,"reply":{"return":{}}}]})),
            ));
        }
        "rxloss" => {
            outcome = t0 + 1.0;
            frames = syn_series(16, t0 + 0.002, 0.01, 8000, 40000);
            run = base_run(&c, man, t0, outcome, tag);
            run["reason"] = json!("Failed");
            run["status"] = json!("failed");
            run["fail_detail"] = json!("RxLoss { kernel_drops: 7 }");
            run["rx_health"]["kernel_drops"] = json!(7);
            run["net"]["kernel_drops"] = json!(7);
            run["net"]["rx_packets"] = json!(100);
            set_sent(&mut run, 16);
            run["replies"] = json!(&exp[..4]);
            run["reply_total"] = json!(4);
            run["reply_unique"] = json!(4);
            guest_exit = 3;
            meta["checkpoint_file_exists"] = json!(false);
            let flood: Frames = (0..12)
                .map(|k| (t0 - 1.5 + k as f64 * 0.1, flood_frame()))
                .collect();
            files.push((
                "flood.json".into(),
                pretty(&json!({"sent":12,"errors":0,"t_first":flood[0].0,"t_last":flood[11].0})),
            ));
            frames.extend(flood);
            let stats = |a: u64| json!({"ReceivedUnicastPackets":a,"ReceivedMulticastPackets":0,"ReceivedBroadcastPackets":6});
            files.push((
                "nic.json".into(),
                pretty(&json!({"nic":"Ethernet 2","before":{"utc":t0,"stats":stats(1000)},"after":{"utc":outcome,"stats":stats(6000)}})),
            ));
        }
        "ckpt_refuse" => {
            let want = match s(&it["variant"]) {
                "wrong_ports" | "wrong_seed" => "JobMismatch",
                "corrupt_next_index" | "corrupt_checksum" => "BadChecksum",
                "truncated" | "empty" => "Malformed",
                "future_format" => "UnsupportedFormat",
                _ => "EngineVersionMismatch",
            };
            outcome = t0 + 0.1;
            run = base_run(&c, man, t0, outcome, tag);
            run["status"] = json!("error");
            run["stage"] = json!("resume-preflight");
            run["error"] = json!(format!("{want}: synthetic"));
            run["opened_adapter"] = json!(false);
            run["tx_sent"] = json!(0);
            guest_exit = 4;
            let forged = nonempty_checkpoint(SCAN, A1, 8);
            let used = mutate_checkpoint(s(&it["variant"]), &forged).unwrap();
            files.push(("checkpoint-forged.bin".into(), forged));
            files.push(("checkpoint-used.bin".into(), used));
        }
        "perm_restricted" => {
            outcome = t0 + 0.1;
            meta["restricted_via"] = json!("runas /trustlevel:0x20000 (windows_wire_runas.cmd)");
            if it["variant"] == "inventory" {
                run = base_run(&Value::Null, man, t0, outcome, tag);
                run["job"] = Value::Null;
                run["mode"] = json!("inventory");
                run["devices"] = json!([{"name":"NPF_Loopback","loopback":true}]);
                run["access_hint"] = json!("Npcap is installed for Administrators-only access");
                guest_exit = 5;
            } else {
                run = base_run(&c, man, t0, outcome, tag);
                run["status"] = json!("error");
                run["error"] = json!("PermissionDenied(synthetic)");
                guest_exit = 5;
            }
            run["opened_adapter"] = json!(false);
            run["tx_sent"] = json!(0);
        }
        "perf" => {
            // A clean Completed cell: one SYN per port at exactly the requested pace, one reply per
            // answering port 0.5 ms after its SYN.
            let rate = it["rate"].as_u64().unwrap();
            let probes = n(&c["syn"]) as usize;
            let period = 1.0 / rate as f64;
            let first = t0 + 0.002;
            frames = syn_series(probes, first, period, 1, 40000);
            for p in 1..=probes as u16 {
                if p != 8099 {
                    frames.push((
                        first + f64::from(p - 1) * period + 0.0005,
                        peer_reply(p, 40000, open_ports().contains(&p)),
                    ));
                }
            }
            let last_send = 0.002 + (probes - 1) as f64 * period;
            outcome = t0 + last_send + 3.1;
            run = base_run(&c, man, t0, outcome, tag);
            set_sent(&mut run, probes as u64);
            run["replies"] = json!(exp);
            run["reply_total"] = json!(exp.len());
            run["reply_unique"] = json!(exp.len());
            run["received"] = json!(exp.len());
            run["net"]["rx_packets"] = json!(exp.len());
            run["timing"]["last_send_s"] = json!(last_send);
            run["timing"]["steady_pps"] = json!(rate as f64 * 0.98);
            run["timing"]["join_ms"] = json!(1.5);
            run["resources"]["cpu_user_ms"] = json!(120);
            run["resources"]["cpu_kernel_ms"] = json!(340);
            run["resources"]["peak_working_set_bytes"] = json!(25_000_000);
            run["resources"]["working_set_bytes_after_join"] = json!(18_000_000);
        }
        _ => {
            // perm_elevated_control: a continuous c01 run.
            outcome = t0 + 3.5;
            frames = vec![
                (t0 + 0.002, scanner_syn(80, 40000)),
                (t0 + 0.004, peer_reply(80, 40000, true)),
            ];
            run = base_run(&c, man, t0, outcome, tag);
            set_sent(&mut run, 1);
            run["replies"] = json!(exp);
            run["reply_total"] = json!(1);
            run["reply_unique"] = json!(1);
            run["received"] = json!(1);
        }
    }
    Built {
        tag: tag.to_owned(),
        frames,
        run,
        guest_exit,
        outcome,
        files,
        meta,
    }
}
pub(crate) fn write_capture(
    dir: &Path,
    man: &Value,
    schema: u64,
    mut frames: Frames,
    outcome: f64,
) -> Value {
    let tag = dir.file_name().unwrap().to_string_lossy().to_string();
    frames.push((BASE + 1.0, marker(b"WIRELAB-READY")));
    let end = outcome + 2.5;
    for k in 0..3 {
        frames.push((end + k as f64 * 0.01, marker(b"WIRELAB-END")));
    }
    frames.sort_by(|a, b| a.0.total_cmp(&b.0));
    let bytes = pcap::encode(&frames);
    put(dir, "peer.pcap", &bytes);
    let empty = pcap::encode(&Vec::new());
    put(dir, "eno1.pcap", &empty);
    let rev = format!("$HOME/winvm/t4-ev/failure/n2/{tag}");
    let (peer_cmd, eno_cmd, filter) = capture_commands(s(&man["stand"]["netns"]), &rev, PM);
    let stats = |n: usize| json!({"captured":n,"received":n,"dropped_kernel":0,"dropped_if":0});
    let cap = json!({
        "capture_schema":schema,
        "quiet":{"reached":true,"quiet_s":1.5},
        "status_post_raw_run_allowed":true,
        "peer":{"filter":"(none: every frame on lab0)","cmd":peer_cmd.split_whitespace().collect::<Vec<_>>(),
            "exited":true,"listening":true,"tcpdump":stats(frames.len()),
            "pcap":{"sha256":sha(&bytes),"size":bytes.len(),"frames":frames.len()},
            "counters":{"rx_before":0,"tx_before":0,"rx_ready":0,"tx_ready":0,"rx_end":frames.len(),"tx_end":0},
            "interface_drop_delta":0},
        "eno1":{"filter":filter,"cmd":eno_cmd.split_whitespace().collect::<Vec<_>>(),
            "exited":true,"listening":true,"tcpdump":stats(0),
            "pcap":{"sha256":sha(&empty),"size":empty.len(),"frames":0},
            "interface_drop_delta":0}
    });
    put(dir, "capture.json", pretty(&cap));
    cap
}
/// Write one planned run into `root/runs/<tag>`.
fn write_run(root: &Path, man: &Value, it: &Value, schema: u64) {
    write_run_with(root, man, it, schema, &|_| {});
}
/// `tweak` edits what the synthetic scanner and peer would have produced before it is written.
fn write_run_with(root: &Path, man: &Value, it: &Value, schema: u64, tweak: &dyn Fn(&mut Built)) {
    let tag = s(&it["tag"]);
    let dir = root.join("runs").join(tag);
    fs::create_dir_all(&dir).unwrap();
    let mut b = build_kind(it, man, tag);
    tweak(&mut b);
    let t0 = BASE + 3.0;
    let finished = b.outcome + 0.5;
    let nonce = format!("nonce-{tag}");
    let run_id = format!("run-{tag}");
    let cap_end = finished + 2.5 + 1.0;
    let mut meta = json!({
        "tag":tag,"kind":it["kind"],"argv_file":"argv.json","run_id":run_id,
        "capture_started_utc":BASE,"guest_started_utc":t0-0.5,"guest_finished_utc":finished,
        "capture_stopped_utc":cap_end,"guest_exit":b.guest_exit,"guest_ssh_rc":0,
        "exe_sha256":EXE,"end_marker_seen":true
    });
    for (k, v) in b.meta.as_object().unwrap() {
        meta[k] = v.clone();
    }
    if schema >= 3 {
        meta["invocation_nonce"] = json!(nonce);
        meta["guest_verify_exit"] = json!(0);
    }
    put(&dir, "run.json", pretty(&b.run));
    for (name, bytes) in &b.files {
        put(&dir, name, bytes);
    }
    write_capture(&dir, man, schema, b.frames, b.outcome);
    put(&dir, "meta.json", pretty(&meta));
    let paths = BTreeMap::from([
        ("--checkpoint-out".to_string(), "C:\\cp\\x.bin".to_string()),
        (
            "--resume-checkpoint".to_string(),
            "C:\\cp\\x.bin".to_string(),
        ),
    ]);
    let argv = expected_args(it, man, &paths).unwrap();
    put(
        &dir,
        "argv.json",
        pretty(&json!({"exe":"C:\\x\\wire_scan.exe","argv":argv})),
    );
    if it["kind"] == "ckpt_refuse" {
        let mut f = it.clone();
        f["forge"] = json!(true);
        let argv = expected_args(&f, man, &paths).unwrap();
        put(
            &dir,
            "forge-argv.json",
            pretty(&json!({"exe":"C:\\x\\wire_scan.exe","argv":argv})),
        );
    }
    let status = json!({"raw_run_allowed":true,"isolation_violations":[],"ok":true});
    let mut pre = status.clone();
    if schema >= 3 {
        // vm-lab status reports the nonce of the guest Verify the gate relied on.
        pre["guest_verify_nonce"] = json!(nonce);
    }
    put(&dir, "status-pre.json", pretty(&pre));
    put(&dir, "status-post.json", pretty(&status));
    put(
        &dir,
        "listeners.json",
        pretty(
            &json!({"open":[80,443,8000,8001,8002,8003,8004,8005,8006,8007],
            "silent":man["listeners"]["silent"],"silent_proven":true,"ready":true}),
        ),
    );
    let mut gv = json!({"ok":true,"errors":[],"run_id":run_id,
        "lab":{"Status":"Up","Npf":NPF},"npf":NPF});
    if schema >= 3 {
        gv["verification_nonce"] = json!(nonce);
    }
    put(&dir, "guest-verify.json", pretty(&gv));
    put(
        &dir,
        "guest-runner.json",
        pretty(
            &json!({"exe_sha256":EXE,"times":{"started_utc":t0-0.4,"finished_utc":finished-0.1}}),
        ),
    );
    if schema >= 3 {
        put(&dir, "guest-verify-stdout.txt", b"{}\n");
        put(&dir, "guest-verify-stderr.txt", b"");
        let mut files = serde_json::Map::new();
        for name in [
            "run.json",
            "guest-runner.json",
            "argv.json",
            "guest-verify.json",
        ] {
            files.insert(name.into(), json!(sha(&fs::read(dir.join(name)).unwrap())));
        }
        put(
            &dir,
            "run-artifacts.json",
            pretty(&json!({"invocation_nonce":nonce,"files":files})),
        );
    }
}
/// Build a complete synthetic failure-plan directory (18 runs plus fixtures).
pub(crate) fn build_failure(root: &Path, schema: u64) {
    fs::create_dir_all(root.join("fixtures")).unwrap();
    let man = manifest(schema);
    put(root, "manifest.json", pretty(&man));
    let fixture = pcap::encode(&vec![
        (1.0, scanner_syn(80, 40000)),
        (1.001, peer_reply(80, 40000, true)),
    ]);
    put(
        root,
        "fixtures/c01_one_addr_port_synack.run1.pcap",
        &fixture,
    );
    put(
        root,
        "fixtures/manifest.json",
        pretty(&json!({
            "binding":man["binding"],"all_valid":true,"oracle":man["oracle"],
            "fixtures":{"c01_one_addr_port_synack.run1":{
                "file":"fixtures/c01_one_addr_port_synack.run1.pcap","sha256":sha(&fixture)}}
        })),
    );
    for it in planned(&man) {
        write_run(root, &man, &it, schema);
    }
}
/// Re-hash the files named by `run-artifacts.json`. Tests that mutate the
/// scanner's own output (run.json) call this to model "the scanner really
/// reported that", so only the rule under test reacts and not the hash proof.
pub(crate) fn reseal(run_dir: &Path) {
    let p = run_dir.join("run-artifacts.json");
    let Some(mut proof) = read_json(&p) else {
        return;
    };
    let names: Vec<String> = array(&json!(
        proof["files"]
            .as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>())
    ))
    .iter()
    .map(|v| s(v).to_string())
    .collect();
    for name in names {
        if let Ok(bytes) = fs::read(run_dir.join(&name)) {
            proof["files"][&name] = json!(sha(&bytes));
        }
    }
    fs::write(p, pretty(&proof)).unwrap();
}
fn write_fixtures(root: &Path, man: &Value) {
    fs::create_dir_all(root.join("fixtures")).unwrap();
    put(root, "manifest.json", pretty(man));
    let fixture = pcap::encode(&vec![
        (1.0, scanner_syn(80, 40000)),
        (1.001, peer_reply(80, 40000, true)),
    ]);
    put(
        root,
        "fixtures/c01_one_addr_port_synack.run1.pcap",
        &fixture,
    );
    put(
        root,
        "fixtures/manifest.json",
        pretty(&json!({
            "binding":man["binding"],"all_valid":true,"oracle":man["oracle"],
            "fixtures":{"c01_one_addr_port_synack.run1":{
                "file":"fixtures/c01_one_addr_port_synack.run1.pcap","sha256":sha(&fixture)}}
        })),
    );
}
/// Build a complete synthetic perf-plan directory: 20 clean Completed cells plus fixtures.
pub(crate) fn build_perf(root: &Path, schema: u64) {
    build_perf_only(root, schema, &[], &|_| {});
}
/// Like [`build_perf`] but only the named cells (all when `only` is empty), each edited by `tweak`.
pub(crate) fn build_perf_only(root: &Path, schema: u64, only: &[&str], tweak: &dyn Fn(&mut Built)) {
    let man = manifest_for(schema, "perf");
    write_fixtures(root, &man);
    for it in planned(&man) {
        if only.is_empty() || only.contains(&s(&it["tag"])) {
            write_run_with(root, &man, &it, schema, tweak);
        }
    }
}
