//! Synthetic, hermetic macOS evidence. Frames and numbers are invented so that one rule at a time
//! can be broken. Nothing here touches a network, an interface or a real evidence directory; scratch
//! names come from `windows_suite::nonce`, never from the clock.
use super::*;
use crate::{pcap, windows_suite::nonce};
use sha2::{Digest, Sha256};

const SM: &str = "02:ac:00:00:00:01";
const PM: &str = "02:ac:00:00:00:02";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const EXE: &str = "abababababababababababababababababababababababababababababababab";
const BASE: f64 = 1_800_000_000.0;
const SCAN_ID: &str = "11111111111111111111111111111111";
const ATTEMPT1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ATTEMPT2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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
    b[18..20].copy_from_slice(&1u16.to_be_bytes());
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
fn syn(port: u16) -> Vec<u8> {
    tcp_frame(SM, PM, [198, 18, 0, 1], [198, 18, 0, 2], 40000, port, 2)
}
fn reply(port: u16, open: bool) -> Vec<u8> {
    let mut f = tcp_frame(
        PM,
        SM,
        [198, 18, 0, 2],
        [198, 18, 0, 1],
        port,
        40000,
        if open { 0x12 } else { 0x14 },
    );
    f[18..20].copy_from_slice(&9u16.to_be_bytes());
    f
}
fn marker(payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 60];
    b[0..6].copy_from_slice(&mac(SM));
    b[6..12].copy_from_slice(&mac(PM));
    b[12..14].copy_from_slice(&[0x88, 0xb5]);
    b[14..14 + payload.len()].copy_from_slice(payload);
    b
}
fn is_open(port: u16) -> bool {
    port == 80 || port == 443 || (8000..8008).contains(&port)
}
fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn pretty(v: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(v).unwrap()
}
fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-macos-verify-{}", nonce()));
    fs::create_dir_all(&d).unwrap();
    d
}
fn tcpdump_err(frames: usize) -> String {
    tcpdump_err3(frames, frames, 0)
}
fn tcpdump_err3(captured: usize, received: usize, dropped: usize) -> String {
    format!(
        "tcpdump: listening on x, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n{captured} packets captured\n{received} packets received by filter\n{dropped} packets dropped by kernel\n"
    )
}
fn checkpoint_bytes(scan: &str, attempt: &str, next: u64) -> Vec<u8> {
    let unhex = |s: &str| -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    };
    let mut b = b"RMSCNCKP".to_vec();
    b.extend(1u32.to_be_bytes());
    b.extend(1u32.to_be_bytes());
    b.extend(unhex(scan));
    b.extend(unhex(attempt));
    b.extend([0u8; 32]);
    b.extend(next.to_be_bytes());
    let sum = Sha256::digest(&b);
    b.extend(sum);
    b
}

fn manifest(plan: &str) -> Value {
    let mut silent = vec![8099u32];
    if plan == "failure" {
        silent.extend(8100..8120);
    }
    json!({
        "schema":1,"macos_capture_schema":1,"suite":plan,"plan":plan,"code_commit":COMMIT,
        "exe":{"sha256":EXE,"size":1,"path":"/x/wire_scan","build":"synthetic"},
        "binding":{"iface":"feth4201","src_ip":"198.18.0.1","src_mac":SM,"router_mac":PM,"peer_ip":"198.18.0.2","seed":1,"rate":100,"wait":3},
        "stand":{"run_id":"m1","scanner_if":"feth4201","peer_if":"feth4202"},
        "listeners":{"open":[80,443,8000,8001,8002,8003,8004,8005,8006,8007],"silent":silent},
        "orchestrator":{"git_commit":COMMIT,"git_dirty":false,"binary_sha256":"ab".repeat(32),"errors":[]}
    })
}

/// The directory root with its manifest and the C-oracle fixtures of c01 and c03.
struct Env {
    root: PathBuf,
    man: Value,
    fx: Value,
}
impl Env {
    fn new(plan: &str) -> Self {
        let root = scratch();
        let man = manifest(plan);
        fs::write(root.join("manifest.json"), pretty(&man)).unwrap();
        fs::create_dir_all(root.join("fixtures")).unwrap();
        let mut entries = serde_json::Map::new();
        for (case, ports) in [
            ("c01_one_addr_port_synack", vec![80u16]),
            ("c03_multi_ports", (8000..8016).collect()),
        ] {
            let frames: Frames = ports
                .iter()
                .enumerate()
                .flat_map(|(k, p)| {
                    [
                        (BASE + k as f64 * 0.01, syn(*p)),
                        (BASE + k as f64 * 0.01 + 0.001, reply(*p, is_open(*p))),
                    ]
                })
                .collect();
            let bytes = pcap::encode(&frames);
            let file = format!("fixtures/{case}.run1.pcap");
            fs::write(root.join(&file), &bytes).unwrap();
            entries.insert(
                format!("{case}.run1"),
                json!({"file":file,"sha256":hex_of(&Sha256::digest(&bytes))}),
            );
        }
        let fx = json!({"schema":1,"all_valid":true,
            "oracle":{"sha256":"cd","git_commit":"ef","git_tree_clean":true},
            "binding":{"src_ip":"198.18.0.1","src_mac":SM,"router_mac":PM,"seed":1,"rate":100},
            "fixtures":entries});
        fs::write(root.join("fixtures/manifest.json"), pretty(&fx)).unwrap();
        Self { root, man, fx }
    }
    fn item(&self, tag: &str) -> Value {
        planned(&self.man)
            .into_iter()
            .find(|i| i["tag"] == tag)
            .unwrap_or_else(|| panic!("no planned tag {tag}"))
    }
}
impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// One run directory, still in memory so a test can break one file before it is written.
struct Ev {
    tag: String,
    nonce: String,
    item: Value,
    files: BTreeMap<String, Vec<u8>>,
}
impl Ev {
    fn json(&mut self, name: &str, f: impl FnOnce(&mut Value)) {
        let mut v: Value = serde_json::from_slice(&self.files[name]).unwrap();
        f(&mut v);
        self.files.insert(name.into(), pretty(&v));
    }
    fn remove(&mut self, name: &str) {
        self.files.remove(name).unwrap();
    }
    fn set_frames(&mut self, who: &str, frames: &Frames) {
        let bytes = pcap::encode(frames);
        self.files.insert(format!("{who}.pcap"), bytes);
        self.files
            .insert(format!("{who}.err"), tcpdump_err(frames.len()).into_bytes());
    }
    /// Write the directory with the hashes taken first, like the suite does before its copy.
    fn write(&self, env: &Env) -> PathBuf {
        let d = env
            .root
            .join("runs")
            .join(format!("{}.{}", self.tag, self.nonce));
        fs::create_dir_all(&d).unwrap();
        let mut lines = String::new();
        for (name, bytes) in &self.files {
            fs::write(d.join(name), bytes).unwrap();
            lines.push_str(&format!("{}  {name}\n", hex_of(&Sha256::digest(bytes))));
        }
        fs::write(d.join(HASHES), lines).unwrap();
        d
    }
    fn verify(&self, env: &Env) -> (Run, Option<Ctx>) {
        let d = self.write(env);
        verify_item(&env.root, &env.man, &env.fx, &self.item, Some(d))
    }
    fn verdict(&self, env: &Env) -> String {
        self.verify(env).0.verdict().to_owned()
    }
}

fn job_echo(c: &Value, man: &Value) -> Value {
    let b = &man["binding"];
    let mut j = json!({"iface":b["iface"],"src_ip":b["src_ip"],"src_mac":b["src_mac"],"router_mac":b["router_mac"],"retries":0,"shard":"1/1","blackrock_rounds":14,"job_digest":"00".repeat(32)});
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
fn base_run(c: &Value, man: &Value, tag: &str) -> Value {
    json!({
        "run_id":format!("run-{tag}"),"status":"ok","reason":"Completed","fail_detail":"",
        "identity":{"source_commit":COMMIT,"binary_sha256":EXE,"os":{"family":"macos"}},
        "src_mac_check":"os-masked",
        "job":job_echo(c,man),
        "net":{"kernel_drops":0,"rx_errors":0,"rx_packets":0,"tx_errors":0,"tx_sent":0,"tx_uncertain":0},
        "rx_health":{"kernel_drops":0},
        "sent":0,"next_index":0,"range":c["syn"],"expected_total":c["syn"],
        "replies":[],"reply_total":0,"reply_unique":0,"received":0,"duplicates":0,"discarded":0,
        "checkpoint":false,"checkpoint_hex":null,"checkpoint_next_index":null,
        "tx_sent_at_join":0,"tx_sent_after_observe":0,"observe_ms":1500,
        "workers":{"tx_tid":11,"rx_tid":12,"tx_alive_after_join":false,"rx_alive_after_join":false},
        "resources":{"fds_before_open":10,"fds_open":20,"fds_after_join":10},
        "timing":{"first_send_s":0.002,"join_ms":0.3,"total_s":3.0},
        "wall":{"t0_utc_ms":(BASE*1000.).round(),"outcome_utc_ms":((BASE+3.0)*1000.).round()}
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

/// A complete, valid run of any item the tests need.
fn build(env: &Env, tag: &str) -> Ev {
    let item = env.item(tag);
    let nonce = nonce();
    let man = &env.man;
    let c = case_of(&item).unwrap_or(Value::Null);
    let kind = s(&item["kind"]).to_owned();
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut run = base_run(&c, man, tag);
    let mut guest_exit = 0;
    let mut exit_meta = json!({});
    // The scanner's SYNs and the peer's replies on the wire.
    let mut peer: Frames = vec![];
    let ports: Vec<u16> = match kind.as_str() {
        "case" | "foreign" | "perf" => (0..n(&c["syn"]) as usize)
            .map(|k| {
                let first = verify_ports(&c);
                first[k]
            })
            .collect(),
        "pause" => verify_ports(&c)[..n(&item["n"]) as usize].to_vec(),
        "resume" => verify_ports(&c)[n(&item["n"]) as usize..].to_vec(),
        _ => vec![],
    };
    let denied = kind == "perm_denied";
    match kind.as_str() {
        "case" | "foreign" | "perf" | "pause" | "resume" => {
            for (k, p) in ports.iter().enumerate() {
                peer.push((BASE + 0.002 + k as f64 * 0.01, syn(*p)));
                if *p != 8099 {
                    peer.push((BASE + 0.003 + k as f64 * 0.01, reply(*p, is_open(*p))));
                }
            }
            let mut exp: Vec<String> = ports
                .iter()
                .filter(|p| **p != 8099)
                .map(|p| {
                    format!(
                        "198.18.0.2:{p}:{}",
                        if is_open(*p) { "open" } else { "closed" }
                    )
                })
                .collect();
            exp.sort();
            set_sent(&mut run, ports.len() as u64);
            run["replies"] = json!(exp);
            run["reply_total"] = json!(exp.len());
            run["reply_unique"] = json!(exp.len());
            run["received"] = json!(exp.len());
            if kind == "pause" {
                let ni = n(&item["n"]) as u64;
                let cp = checkpoint_bytes(SCAN_ID, ATTEMPT1, ni);
                run["reason"] = json!("Paused");
                run["range"] = json!(16);
                run["expected_total"] = json!(16);
                run["scan_id"] = json!(SCAN_ID);
                run["attempt_id"] = json!(ATTEMPT1);
                run["checkpoint"] = json!(true);
                run["checkpoint_hex"] = json!(hex_of(&cp));
                run["checkpoint_next_index"] = json!(ni);
                files.insert("checkpoint.bin".into(), cp);
            }
            if kind == "resume" {
                let ni = n(&item["n"]) as u64;
                run["scan_id"] = json!(SCAN_ID);
                run["attempt_id"] = json!(ATTEMPT2);
                run["resumed_from_attempt"] = json!(ATTEMPT1);
                run["start_index"] = json!(ni);
                run["next_index"] = json!(16);
                run["range"] = json!(16);
                run["expected_total"] = json!(16);
            }
        }
        "perm_denied" => {
            run["status"] = json!("error");
            run["opened_adapter"] = json!(false);
            run["tx_sent"] = json!(0);
            if item["variant"] == "inventory" {
                run["mode"] = json!("inventory");
            } else {
                run["error"] = json!("PermissionDenied(/dev/bpf0: grant access)");
                guest_exit = 5;
            }
        }
        "rxloss" => {
            run["reason"] = json!("Failed");
            run["status"] = json!("failed");
            run["fail_detail"] = json!("RxLoss { kernel_drops: 7 }");
            run["rx_health"]["kernel_drops"] = json!(7);
            run["net"]["kernel_drops"] = json!(7);
            run["checkpoint"] = json!(false);
            guest_exit = 3;
            exit_meta["checkpoint_file_exists"] = json!(false);
        }
        other => panic!("test builder does not know {other}"),
    }
    // Argument record
    let mut paths = BTreeMap::new();
    paths.insert("--checkpoint-out".to_owned(), "/work/cp.bin".to_owned());
    paths.insert(
        "--resume-checkpoint".to_owned(),
        "/work/cp-in.bin".to_owned(),
    );
    let argv = expected_args(&item, man, &paths).unwrap();
    files.insert(
        "argv.json".into(),
        pretty(&json!({"exe":"/x/wire_scan","argv":argv,"invocation_nonce":nonce})),
    );
    run["invocation_nonce"] = json!(nonce);
    files.insert("run.json".into(), pretty(&run));
    let mut meta = json!({"tag":tag,"kind":kind,"invocation_nonce":nonce,"guest_exit":guest_exit,"euid":1000,
        "exe_sha256":EXE,"capture_started_utc":BASE-2.0,"guest_started_utc":BASE,
        "guest_finished_utc":BASE+3.0,"capture_stopped_utc":BASE+9.0});
    for (k, v) in exit_meta.as_object().unwrap() {
        meta[k] = v.clone();
    }
    files.insert("meta.json".into(), pretty(&meta));
    let access = required_bpf_access(&item);
    for name in ["status-pre", "status-post"] {
        files.insert(
            format!("{name}.json"),
            pretty(&json!({"raw_run_allowed":true,"bpf_access":access,"uplink":"en0","checks":[]})),
        );
    }
    let silent = if man["plan"] == "failure" {
        json!(
            [8099]
                .iter()
                .copied()
                .chain(8100..8120)
                .collect::<Vec<u32>>()
        )
    } else {
        json!([8099])
    };
    files.insert(
        "listeners.json".into(),
        pretty(&json!({"open":[80,443,8000,8001,8002,8003,8004,8005,8006,8007],"silent":silent,"silent_proven":true,"ready":true,"bind":"198.18.0.2"})),
    );
    let mut ev = Ev {
        tag: tag.into(),
        nonce,
        item: item.clone(),
        files,
    };
    if denied {
        ev.files.insert(
            "capture.json".into(),
            pretty(&json!({"capture_schema":1,"peer":null,"uplink":null,"witness":NO_WITNESS})),
        );
        let c = json!({"feth4201":{"ipkts":5,"opkts":5},"feth4202":{"ipkts":7,"opkts":7}});
        ev.files.insert(
            "counters.json".into(),
            pretty(&json!({"before":c,"after":c,"before_utc":BASE-1.0,"after_utc":BASE+4.0})),
        );
        return ev;
    }
    if kind == "foreign" {
        // Three kinds of foreign reply, as the macOS injector writes them (never "other_ip").
        for k in 0..3u16 {
            let mut f = tcp_frame(
                PM,
                SM,
                [198, 18, 0, 2],
                [198, 18, 0, 1],
                9999 + k,
                40000,
                0x12,
            );
            f[18..20].copy_from_slice(&0xf0e1u16.to_be_bytes());
            peer.push((BASE + 0.5 + f64::from(k) * 0.01, f));
        }
        ev.files.insert(
            "injector.json".into(),
            pretty(&json!({"first_syn_seen":true,"sent_total":3,
                "kinds":{"unscanned_port":1,"wrong_cookie":1,"wrong_dst_port":1},"guard_refused":0})),
        );
    }
    // Peer witness: start markers, the scan, end markers.
    let mut all: Frames = (0..3)
        .map(|k| (BASE - 1.0 + k as f64 * 0.01, marker(b"WIRELAB-READY")))
        .collect();
    all.extend(peer);
    all.extend((0..3).map(|k| (BASE + 8.0 + k as f64 * 0.01, marker(b"WIRELAB-END"))));
    let nframes = all.len();
    ev.set_frames("peer", &all);
    ev.set_frames("uplink", &vec![]);
    let up_filter = uplink_filter(SM, PM);
    let pcap_rec = |who: &str, ev: &Ev| {
        let b = &ev.files[&format!("{who}.pcap")];
        json!({"sha256":hex_of(&Sha256::digest(b)),"size":b.len(),"frames":pcap::read_pcap_records(b).unwrap().1.len()})
    };
    let (peer_rec, up_rec) = (pcap_rec("peer", &ev), pcap_rec("uplink", &ev));
    let cap = json!({"capture_schema":1,
        "peer":{"iface":"feth4202","cmd":["tcpdump","-i","feth4202","-n","-U","--immediate-mode","-s","0","-w","/work/peer.pcap"],
            "filter":"(none: every frame on the peer interface)","exited":true,"listening":true,
            "tcpdump":{"captured":nframes,"received":nframes,"dropped_kernel":0,"dropped_if":null},
            "pcap":peer_rec,"interface_drop_delta":0,
            "witness":{"iface_rxtx_delta_lo":nframes-3,"iface_rxtx_delta_hi":nframes,"quiesced_before_stop":true,"valid":true,"invalid_reasons":[]}},
        "uplink":{"iface":"en0","cmd":["tcpdump","-i","en0","-p","-n","-U","--immediate-mode","-s","0","-w","/work/uplink.pcap",up_filter],
            "filter":up_filter,"exited":true,"exit_code":0,"listening":true,
            "tcpdump":{"captured":0,"received":0,"dropped_kernel":0,"dropped_if":null},
            "pcap":up_rec,"interface_drop_delta":0},
        "quiet":{"reached":true,"quiet_s":1.5}});
    ev.files.insert("capture.json".into(), pretty(&cap));
    ev
}
fn verify_ports(c: &Value) -> Vec<u16> {
    verify::ports(s(&c["ports"]))
}
fn failed(r: &Run, needle: &str) -> bool {
    r.summary()["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["result"] == FAIL && s(&c["name"]).contains(needle))
}
fn result_of(r: &Run, needle: &str) -> String {
    r.summary()["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| s(&c["name"]).contains(needle))
        .map(|c| s(&c["result"]).to_owned())
        .unwrap_or_else(|| panic!("no check named like {needle}"))
}
const C01: &str = "c01_one_addr_port_synack.run1";

#[test]
fn a_complete_synthetic_run_is_pass_and_the_baselines_hold() {
    let env = Env::new("functional");
    let (r, _) = build(&env, C01).verify(&env);
    let bad: Vec<_> = r.summary()["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["result"] != PASS)
        .cloned()
        .collect();
    assert!(bad.is_empty(), "{bad:#?}");
    assert_eq!(r.verdict(), PASS);
    // The OS-masked MAC value is accepted; an unknown value is not evidence.
    let mut ev = build(&env, C01);
    ev.json("run.json", |v| v["src_mac_check"] = json!("mismatch"));
    assert_eq!(ev.verdict(&env), INVALID);
}

#[test]
fn missing_run_json_is_not_run_never_pass() {
    let env = Env::new("functional");
    let mut ev = build(&env, C01);
    ev.remove("run.json");
    assert_eq!(ev.verdict(&env), NOT_RUN);
    let none = verify_item(&env.root, &env.man, &env.fx, &env.item(C01), None);
    assert_eq!(none.0.verdict(), NOT_RUN);
}

#[test]
fn incomplete_capture_is_invalid_not_pass() {
    let env = Env::new("functional");
    // tcpdump counted one frame more than it stored.
    let mut ev = build(&env, C01);
    let stored = pcap::read_pcap_records(&ev.files["peer.pcap"])
        .unwrap()
        .1
        .len();
    ev.files.insert(
        "peer.err".into(),
        tcpdump_err(stored)
            .replace(
                &format!("{stored} packets received"),
                &format!("{} packets received", stored + 1),
            )
            .into_bytes(),
    );
    assert_eq!(ev.verdict(&env), INVALID);
    // The end markers never arrived: the tail is not proven.
    let mut ev = build(&env, C01);
    let mut frames = pcap::read_pcap_records(&ev.files["peer.pcap"]).unwrap().1;
    frames.truncate(frames.len() - 3);
    ev.set_frames("peer", &frames);
    ev.json("capture.json", |v| {
        v["peer"]["pcap"] = json!({"sha256":"x","size":0,"frames":0});
    });
    assert_eq!(ev.verdict(&env), INVALID);
    // Dropped in the kernel.
    let mut ev = build(&env, C01);
    ev.json("capture.json", |v| {
        v["peer"]["tcpdump"]["dropped_kernel"] = json!(1)
    });
    assert_eq!(ev.verdict(&env), INVALID);
}

#[test]
fn a_lab_frame_on_uplink_is_fail_and_a_safety_trip() {
    let env = Env::new("functional");
    let mut ev = build(&env, C01);
    ev.set_frames("uplink", &vec![(BASE, syn(80))]);
    let (r, _) = ev.verify(&env);
    assert!(r.safety_trip());
    assert_eq!(
        r.verdict(),
        FAIL,
        "a safety trip outranks every other finding"
    );
    // Counted by tcpdump but not stored is as bad as stored.
    let mut ev = build(&env, C01);
    ev.files
        .insert("uplink.err".into(), tcpdump_err(1).into_bytes());
    let (r, _) = ev.verify(&env);
    assert!(r.safety_trip());
    // The same finding is found in an aborted copy, and fails the whole directory.
    let env2 = Env::new("functional");
    let mut ab = build(&env2, C01);
    ab.set_frames("uplink", &vec![(BASE, syn(80))]);
    let d = ab.write(&env2);
    let aborted = env2.root.join("runs_aborted").join(d.file_name().unwrap());
    fs::create_dir_all(env2.root.join("runs_aborted")).unwrap();
    fs::rename(&d, &aborted).unwrap();
    assert_eq!(safety_trips(&env2.root).len(), 1);
}

#[test]
fn hash_mismatch_after_copy_is_invalid() {
    let env = Env::new("functional");
    let ev = build(&env, C01);
    let d = ev.write(&env);
    let mut run = fs::read(d.join("run.json")).unwrap();
    run.extend(b"\n");
    fs::write(d.join("run.json"), run).unwrap();
    let (r, _) = verify_item(&env.root, &env.man, &env.fx, &ev.item, Some(d.clone()));
    assert_eq!(r.verdict(), INVALID);
    assert_eq!(result_of(&r, "hash taken before the copy"), INVALID);
    // A file nobody hashed is also not evidence.
    fs::write(d.join("extra.txt"), "x").unwrap();
    let (r, _) = verify_item(&env.root, &env.man, &env.fx, &ev.item, Some(d));
    assert_eq!(result_of(&r, "hash taken before the copy"), INVALID);
}

#[test]
fn status_pre_or_post_not_allowed_is_not_run() {
    let env = Env::new("functional");
    // The brief's name keeps the pre case: a refused gate means the run did not happen.
    let name = "status-pre";
    let mut ev = build(&env, C01);
    ev.json(&format!("{name}.json"), |v| {
        v["raw_run_allowed"] = json!(false)
    });
    assert_eq!(ev.verdict(&env), NOT_RUN, "{name}");
    // A stand whose BPF access is not what the run needs is the same refusal.
    let mut ev = build(&env, "c02_one_addr_port_rst.run1");
    ev.json(&format!("{name}.json"), |v| {
        v["bpf_access"] = json!("denied")
    });
    assert_eq!(ev.verdict(&env), NOT_RUN, "{name} bpf");
}

#[test]
fn status_post_not_allowed_is_invalid_and_a_fail_for_a_perf_cell() {
    // The scanner ran: the stand is no longer proven afterwards. Windows parity.
    let env = Env::new("functional");
    let mut ev = build(&env, C01);
    ev.json("status-post.json", |v| v["raw_run_allowed"] = json!(false));
    assert_eq!(ev.verdict(&env), INVALID);
    let mut ev = build(&env, C01);
    ev.json("status-post.json", |v| v["bpf_access"] = json!("mixed"));
    assert_eq!(ev.verdict(&env), INVALID);
    let env = Env::new("perf");
    let mut ev = build(&env, "perf.100.r1");
    ev.json("status-post.json", |v| v["raw_run_allowed"] = json!(false));
    let (r, _) = ev.verify(&env);
    assert!(
        failed(&r, "status-post allows a raw run"),
        "a perf cell with a failed post gate is a FAIL"
    );
    assert!(!may_discard(r.verdict(), r.behaviour_fail()));
}

#[test]
fn syn_bytes_differ_from_fixture_is_fail() {
    let env = Env::new("functional");
    let mut ev = build(&env, C01);
    // The scanner's SYN differs from the C oracle's in one byte (TTL).
    let mut frames = pcap::read_pcap_records(&ev.files["peer.pcap"]).unwrap().1;
    for (_, f) in &mut frames {
        if pcap::is_syn(f) {
            f[22] = 63;
        }
    }
    ev.set_frames("peer", &frames);
    ev.json("capture.json", |v| {
        let b = &ev_bytes(&frames);
        v["peer"]["pcap"] =
            json!({"sha256":hex_of(&Sha256::digest(b)),"size":b.len(),"frames":frames.len()});
    });
    let (r, _) = ev.verify(&env);
    assert_eq!(result_of(&r, "SYN bytes and order equal C oracle"), FAIL);
    assert_eq!(r.verdict(), FAIL);
}
fn ev_bytes(frames: &Frames) -> Vec<u8> {
    pcap::encode(frames)
}

#[test]
fn pause_resume_legs_must_equal_continuous_and_fixture() {
    let env = Env::new("functional");
    let legs = |env: &Env, mutate: &dyn Fn(&mut Ev)| {
        let mut rs = BTreeMap::new();
        let mut cs = BTreeMap::new();
        for tag in ["pause_N8", "resume_N8", "c03_multi_ports.run1"] {
            let mut ev = build(env, tag);
            if tag == "resume_N8" {
                mutate(&mut ev);
            }
            let (r, c) = ev.verify(env);
            if tag != "c03_multi_ports.run1" {
                assert_eq!(r.verdict(), PASS, "{tag}: {:#?}", r.summary()["checks"]);
            }
            rs.insert(tag.to_owned(), r);
            cs.insert(tag.to_owned(), c.unwrap());
        }
        // `groups` looks the continuous run up under its run1 name.
        let g = verify::groups(&env.root, &env.man, &env.fx, &rs, &cs);
        g.into_iter()
            .find(|g| g["tag"] == "group_pause_resume_N8")
            .unwrap()
    };
    let g = legs(&env, &|_| {});
    assert_eq!(g["verdict"], PASS, "{g:#}");
    // A resume leg that sends the right number of SYNs in the wrong order fails the byte comparison.
    let env = Env::new("functional");
    let g = legs(&env, &|ev| {
        let mut frames = pcap::read_pcap_records(&ev.files["peer.pcap"]).unwrap().1;
        let syns: Vec<usize> = (0..frames.len())
            .filter(|i| pcap::is_syn(&frames[*i].1))
            .collect();
        let (a, b) = (syns[0], syns[1]);
        let fa = frames[a].1.clone();
        frames[a].1 = frames[b].1.clone();
        frames[b].1 = fa;
        ev.set_frames("peer", &frames);
        let bytes = ev_bytes(&frames);
        ev.json("capture.json", |v| {
            v["peer"]["pcap"] = json!({"sha256":hex_of(&Sha256::digest(&bytes)),"size":bytes.len(),"frames":frames.len()});
        });
    });
    assert_eq!(g["verdict"], FAIL, "{g:#}");
    // A directory that never had the legs does not claim a pass.
    let empty = verify::groups(
        &env.root,
        &env.man,
        &env.fx,
        &BTreeMap::new(),
        &BTreeMap::new(),
    );
    assert!(empty.iter().all(|g| g["verdict"] == NOT_RUN));
}

#[test]
fn completed_with_unknown_or_nonzero_drops_is_fail() {
    let env = Env::new("functional");
    for drops in [json!(null), json!(3)] {
        let mut ev = build(&env, C01);
        ev.json("run.json", |v| {
            v["rx_health"]["kernel_drops"] = drops.clone()
        });
        let (r, _) = ev.verify(&env);
        assert!(failed(&r, "RX drops are measured zero"), "{drops}");
        assert_eq!(r.verdict(), FAIL, "{drops}");
    }
}

#[test]
fn rxloss_with_zero_or_unknown_drops_is_fail() {
    let env = Env::new("failure");
    for drops in [json!(null), json!(0)] {
        let mut ev = build(&env, "rxloss");
        ev.json("run.json", |v| {
            v["rx_health"]["kernel_drops"] = drops.clone()
        });
        let (r, _) = ev.verify(&env);
        assert!(failed(&r, "backed by measured kernel drops"), "{drops}");
        assert_eq!(r.verdict(), FAIL, "{drops}");
    }
    // The scan that lost nothing is "not reproduced", not a failure of the scanner.
    let mut ev = build(&env, "rxloss");
    ev.json("run.json", |v| {
        v["rx_health"]["kernel_drops"] = json!(0);
        v["reason"] = json!("Completed");
        v["fail_detail"] = json!("");
    });
    let (r, _) = ev.verify(&env);
    assert!(!failed(&r, "backed by measured kernel drops"));
    assert_eq!(result_of(&r, "RX overflow reproduced"), NOT_RUN);
    // Measured drops make the RxLoss check run (and name the drop count).
    let (r, _) = build(&env, "rxloss").verify(&env);
    assert!(!failed(&r, "backed by measured kernel drops"));
    assert_eq!(
        result_of(&r, "RX loss fails with exactly measured drop count"),
        PASS
    );
    // The rxloss case scans everything at 100000 pps and stalls the reader for 3 s.
    let it = env.item("rxloss");
    let a = arg_map(&it, &env.man, false);
    assert_eq!(a["--ports"], "1-65535");
    assert_eq!(a["--rate"], "100000");
    assert_eq!(a["--rx-stall-ms"], "3000");
}

#[test]
fn perm_denied_run_with_any_syn_is_fail() {
    let env = Env::new("failure");
    let (r, _) = build(&env, "perm_denied_scan").verify(&env);
    let bad: Vec<_> = r.summary()["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["result"] != PASS)
        .cloned()
        .collect();
    assert!(bad.is_empty(), "{bad:#?}");
    assert_eq!(r.verdict(), PASS);
    let mut ev = build(&env, "perm_denied_scan");
    ev.set_frames("peer", &vec![(BASE, syn(80))]);
    let (r, _) = ev.verify(&env);
    assert!(r.safety_trip());
    assert_eq!(r.verdict(), FAIL);
    // The permission runs need BPF denied; a granted stand cannot show the refusal.
    let mut ev = build(&env, "perm_inventory_control");
    ev.json("status-pre.json", |v| v["bpf_access"] = json!("granted"));
    assert_eq!(ev.verdict(&env), NOT_RUN);
    // Frames that crossed the pair while BPF was denied cannot be shown to be none.
    let mut ev = build(&env, "perm_denied_scan");
    ev.json("counters.json", |v| {
        v["after"]["feth4202"]["ipkts"] = json!(9)
    });
    assert_eq!(ev.verdict(&env), INVALID);
    // The scanner must have refused, not merely not been seen.
    let mut ev = build(&env, "perm_denied_scan");
    ev.json("run.json", |v| v["opened_adapter"] = json!(true));
    assert_eq!(ev.verdict(&env), FAIL);
}

#[test]
fn perf_gate_is_open_outside_twenty_percent_and_not_run_under_three_cells() {
    let cell = |rate: u64, rep: u64, pps: f64| {
        json!({"tag":format!("perf.{rate}.r{rep}"),"verdict":PASS,
            "notes":{"perf":{"steady_pps_wire":pps,"rx_loss":false,"cpu_user_ms":1.0}}})
    };
    let row = |runs: &[Value], rate: u64| {
        verify::perf_summary(runs)["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["rate"] == rate)
            .cloned()
            .unwrap()
    };
    let runs: Vec<_> = (1..=5).map(|k| cell(100, k, 119.0)).collect();
    assert_eq!(row(&runs, 100)["rate_gate"], "MET");
    let runs: Vec<_> = (1..=5).map(|k| cell(100, k, 121.0)).collect();
    assert_eq!(row(&runs, 100)["rate_gate"], "OPEN");
    let runs: Vec<_> = (1..=2).map(|k| cell(100, k, 100.0)).collect();
    assert_eq!(row(&runs, 100)["rate_gate"], "NOT RUN");
    // The Mac perf plan is the Windows one: four rates, five repetitions, repetition-major.
    let tags: Vec<_> = planned(&json!({"plan":"perf"}))
        .iter()
        .map(|i| s(&i["tag"]).to_owned())
        .collect();
    assert_eq!(tags.len(), 20);
    assert_eq!(tags[0], "perf.100.r1");
    assert_eq!(tags[19], "perf.100000.r5");
}

#[test]
fn fixture_binding_must_equal_run_binding() {
    for (key, value) in [
        ("src_mac", "2:ac:0:0:0:1"),
        ("router_mac", "02:ac:00:00:00:03"),
        ("src_ip", "198.18.000.1"),
        ("src_ip", "198.18.0.9"),
    ] {
        let mut env = Env::new("functional");
        env.fx["binding"][key] = json!(value);
        let (r, _) = build(&env, C01).verify(&env);
        assert_eq!(
            result_of(&r, "oracle fixture binding identical without normalization"),
            INVALID,
            "{key}={value}"
        );
        assert_ne!(r.verdict(), PASS);
    }
}

#[test]
fn verdict_counts_add_up() {
    let env = Env::new("functional");
    let ev = build(&env, C01);
    ev.write(&env);
    let mut pre =
        serde_json::from_slice::<Value>(&fs::read(env.root.join("manifest.json")).unwrap())
            .unwrap();
    // Everything else of the plan is absent: NOT RUN, counted once each.
    pre["capture_schema_note"] = json!("x");
    let v = verify_dir(&env.root);
    let total = array(&v["runs"]).len() + array(&v["groups"]).len();
    let sum: u64 = [PASS, FAIL, INVALID, NOT_RUN]
        .iter()
        .map(|k| v["totals"][k].as_u64().unwrap())
        .sum();
    assert_eq!(sum as usize, total, "{v:#}");
    assert_eq!(v["overall"], NOT_RUN);
    // 1 manifest row + 24 planned runs + 4 pause groups.
    assert_eq!(total, 1 + 24 + 4);
    let c01 = array(&v["runs"]).iter().find(|r| r["tag"] == C01).unwrap();
    assert_eq!(c01["verdict"], PASS);
}

#[test]
fn an_empty_directory_is_not_run_with_exit_two_and_never_pass() {
    let d = scratch();
    let v = verify_dir(&d);
    assert_eq!(v["overall"], NOT_RUN);
    assert_eq!(
        run(&["--dir".into(), d.to_string_lossy().into_owned()]).unwrap(),
        2
    );
    assert!(
        run(&[
            "--dir".into(),
            d.to_string_lossy().into_owned(),
            "--bogus".into(),
            "x".into()
        ])
        .is_err()
    );
    let _ = fs::remove_dir_all(d);
}

#[test]
fn the_failure_plan_has_the_agreed_tags_and_permission_runs_first() {
    let tags: Vec<String> = planned(&json!({"plan":"failure"}))
        .iter()
        .map(|i| s(&i["tag"]).to_owned())
        .collect();
    assert_eq!(tags.len(), 17);
    assert_eq!(&tags[..2], ["perm_denied_scan", "perm_inventory_control"]);
    for t in [
        "stop_silent",
        "stop_load",
        "stop_drain",
        "stop_fullqueue",
        "overflow_queue",
        "rxloss",
        "linkloss",
        "ckpt_wrong_ports",
        "ckpt_future_engine",
    ] {
        assert!(tags.iter().any(|x| x == t), "{t}");
    }
    for it in planned(&json!({"plan":"failure"})) {
        let want = if s(&it["kind"]) == "perm_denied" {
            "denied"
        } else {
            "granted"
        };
        assert_eq!(required_bpf_access(&it), want);
    }
}

#[test]
fn linkloss_without_a_down_event_is_not_run_user_action_not_performed() {
    let env = Env::new("failure");
    let item = env.item("linkloss");
    let c = case_of(&item).unwrap();
    // A scan that completed because nobody took the link down.
    let mut ev = build(&env, "rxloss");
    ev.tag = "linkloss".into();
    ev.item = item.clone();
    let _ = c;
    ev.files
        .insert("linkloss.json".into(), pretty(&json!({"events":[]})));
    let (r, _) = ev.verify(&env);
    assert_eq!(
        result_of(&r, "link-down event of the peer interface observed"),
        NOT_RUN
    );
    assert_eq!(r.verdict(), NOT_RUN);
}
#[test]
fn run_directories_are_found_by_tag_and_nonce_and_a_second_one_is_ambiguous() {
    assert!(valid_nonce(&nonce()));
    assert!(!valid_nonce("rxyz"));
    let n = format!("r{}", "a".repeat(32));
    assert_eq!(
        split_dir_name(&format!("perf.100.r1.{n}")),
        Some(("perf.100.r1", n.as_str()))
    );
    let env = Env::new("functional");
    let a = build(&env, C01);
    let b = build(&env, C01);
    a.write(&env);
    b.write(&env);
    assert_eq!(run_dirs(&env.root, "runs", C01).len(), 2);
    let v = verify_dir(&env.root);
    let row = array(&v["runs"]).iter().find(|r| r["tag"] == C01).unwrap();
    assert_eq!(row["verdict"], INVALID);
    assert_eq!(run_status(&env.root, C01).0, INVALID);
}

#[test]
fn only_a_discardable_verdict_may_be_rerun() {
    assert!(may_discard(NOT_RUN, false));
    assert!(may_discard(INVALID, false));
    assert!(!may_discard(INVALID, true));
    assert!(!may_discard(FAIL, false));
    assert!(!may_discard(PASS, false));
}

fn has_check(r: &Run, needle: &str) -> bool {
    r.summary()["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| s(&c["name"]).contains(needle))
}
/// Rewrite both the stats file of a witness and the record of it in capture.json.
fn set_stats(ev: &mut Ev, who: &str, captured: usize, received: usize, dropped: usize) {
    ev.files.insert(
        format!("{who}.err"),
        tcpdump_err3(captured, received, dropped).into_bytes(),
    );
    ev.json("capture.json", |v| {
        v[who]["tcpdump"] = json!({"captured":captured,"received":received,"dropped_kernel":dropped,"dropped_if":null});
    });
}

#[test]
fn macos_received_by_filter_counts_everything_the_descriptor_saw_and_is_information_only() {
    let env = Env::new("functional");
    // The uplink saw 57 unrelated packets before its filter and passed none: that is not a lab frame.
    let mut ev = build(&env, C01);
    set_stats(&mut ev, "uplink", 0, 57, 0);
    let (r, _) = ev.verify(&env);
    assert!(!r.safety_trip(), "{:#?}", r.summary()["checks"]);
    assert_eq!(r.verdict(), PASS);
    // The same reading applies to the peer capture: its received count is not a matched-frame count.
    let mut ev = build(&env, C01);
    let stored = pcap::read_pcap_records(&ev.files["peer.pcap"])
        .unwrap()
        .1
        .len();
    set_stats(&mut ev, "peer", stored, stored + 50, 0);
    assert_eq!(ev.verdict(&env), PASS);
    // A kernel drop on the filtered uplink capture is a matched frame lost: unproven (INVALID), not a pass.
    let mut ev = build(&env, C01);
    set_stats(&mut ev, "uplink", 0, 57, 1);
    let (r, _) = ev.verify(&env);
    assert_eq!(r.verdict(), INVALID);
    // A frame that matched the lab filter but was not stored is a lab frame.
    let mut ev = build(&env, C01);
    set_stats(&mut ev, "uplink", 1, 58, 0);
    assert!(ev.verify(&env).0.safety_trip());
}

#[test]
fn a_tag_with_two_directories_is_judged_in_each_and_a_fail_is_never_hidden_as_invalid() {
    let env = Env::new("functional");
    let mut bad = build(&env, C01);
    bad.json("run.json", |v| v["rx_health"]["kernel_drops"] = json!(3));
    bad.write(&env);
    build(&env, C01).write(&env);
    let it = env.item(C01);
    let (r, _) = judge_tag(&env.root, &env.man, &env.fx, &it);
    assert!(has_check(&r, "exactly one run directory"));
    assert!(
        r.behaviour_fail(),
        "the behaviour FAIL of one directory survives"
    );
    assert!(run_status(&env.root, C01).1);
    let v = verify_dir(&env.root);
    assert_eq!(v["overall"], FAIL, "{}", v["totals"]);
    // A safety trip in the second directory fails the directory too.
    let env = Env::new("functional");
    build(&env, C01).write(&env);
    let mut trip = build(&env, C01);
    trip.set_frames("uplink", &vec![(BASE, syn(80))]);
    trip.write(&env);
    let (r, _) = judge_tag(&env.root, &env.man, &env.fx, &env.item(C01));
    assert!(r.safety_trip());
    assert_eq!(verify_dir(&env.root)["overall"], FAIL);
}

#[test]
fn a_failed_manifest_gate_cannot_turn_a_safety_trip_into_not_run() {
    for sub in ["runs", "runs_discarded"] {
        let env = Env::new("functional");
        let mut ev = build(&env, C01);
        ev.set_frames("uplink", &vec![(BASE, syn(80))]);
        let d = ev.write(&env);
        if sub == "runs_discarded" {
            fs::create_dir_all(env.root.join(sub)).unwrap();
            fs::rename(&d, env.root.join(sub).join(d.file_name().unwrap())).unwrap();
        }
        // No fixtures manifest: the manifest gate fails.
        fs::remove_file(env.root.join("fixtures/manifest.json")).unwrap();
        let v = verify_dir(&env.root);
        assert_eq!(v["overall"], FAIL, "{sub}: {v:#}");
        assert_eq!(v["safety_trips"].as_array().unwrap().len(), 1, "{sub}");
        // And with no manifest at all.
        fs::remove_file(env.root.join("manifest.json")).unwrap();
        assert_eq!(
            verify_dir(&env.root)["overall"],
            FAIL,
            "{sub} without manifest"
        );
    }
}

#[test]
fn the_recorded_effective_uid_must_be_there_and_not_root() {
    let env = Env::new("failure");
    for tag in ["perm_denied_scan", "rxloss"] {
        let mut ev = build(&env, tag);
        ev.json("meta.json", |v| {
            v.as_object_mut().unwrap().remove("euid");
        });
        let (r, _) = ev.verify(&env);
        assert_eq!(
            result_of(&r, "ran unprivileged"),
            INVALID,
            "{tag} missing uid"
        );
        let mut ev = build(&env, tag);
        ev.json("meta.json", |v| v["euid"] = json!(0));
        let (r, _) = ev.verify(&env);
        let want = if tag == "rxloss" { INVALID } else { FAIL };
        assert_eq!(result_of(&r, "ran unprivileged"), want, "{tag} root");
    }
    let (r, _) = build(&env, "perm_denied_scan").verify(&env);
    assert_eq!(result_of(&r, "ran unprivileged"), PASS);
}

#[test]
fn the_perm_denied_counter_window_must_enclose_the_scanner_run() {
    let env = Env::new("failure");
    for (key, value) in [
        ("before_utc", BASE + 0.5), // read after the scanner started
        ("after_utc", BASE + 1.0),  // read before the scanner finished
    ] {
        let mut ev = build(&env, "perm_denied_scan");
        ev.json("counters.json", |v| v[key] = json!(value));
        let (r, _) = ev.verify(&env);
        assert_eq!(
            result_of(&r, "counter readings enclose the scanner run"),
            INVALID,
            "{key}"
        );
    }
    let mut ev = build(&env, "perm_denied_scan");
    ev.json("counters.json", |v| {
        v.as_object_mut().unwrap().remove("before_utc");
    });
    assert_eq!(
        result_of(
            &ev.verify(&env).0,
            "counter readings enclose the scanner run"
        ),
        INVALID
    );
    assert_eq!(
        result_of(
            &build(&env, "perm_denied_scan").verify(&env).0,
            "counter readings enclose"
        ),
        PASS
    );
}

#[test]
fn x01_needs_three_kinds_from_a_clean_guard_and_never_other_ip() {
    let env = Env::new("functional");
    let tag = "x01_foreign_replies.run1";
    let (r, _) = build(&env, tag).verify(&env);
    assert_eq!(
        result_of(&r, "all foreign injection kinds reached the wire"),
        PASS
    );
    assert_eq!(result_of(&r, "the peer-side guard refused no frame"), PASS);
    assert_eq!(result_of(&r, "no other_ip reply was written"), PASS);
    let mut ev = build(&env, tag);
    ev.json("injector.json", |v| v["guard_refused"] = json!(2));
    assert_eq!(
        result_of(&ev.verify(&env).0, "the peer-side guard refused no frame"),
        INVALID
    );
    let mut ev = build(&env, tag);
    ev.json("injector.json", |v| v["kinds"]["other_ip"] = json!(1));
    assert_eq!(
        result_of(&ev.verify(&env).0, "no other_ip reply was written"),
        INVALID
    );
    let mut ev = build(&env, tag);
    ev.json("injector.json", |v| v["kinds"]["wrong_cookie"] = json!(0));
    assert_eq!(
        result_of(
            &ev.verify(&env).0,
            "all foreign injection kinds reached the wire"
        ),
        INVALID
    );
    // The verdict says what x01 does not cover on macOS.
    let v = verify_dir(&env.root);
    assert!(v["notes"][0].as_str().unwrap().contains("other_ip"));
}

#[test]
fn link_loss_is_judged_on_the_peer_interface_and_the_failure_class_is_provisional() {
    let env = Env::new("failure");
    let item = env.item("linkloss");
    let mk = |events: Value, reason: &str, detail: &str| {
        let mut ev = build(&env, "rxloss");
        ev.tag = "linkloss".into();
        ev.item = item.clone();
        ev.json("run.json", |v| {
            v["reason"] = json!(reason);
            v["fail_detail"] = json!(detail);
        });
        ev.files
            .insert("linkloss.json".into(), pretty(&json!({"events":events})));
        ev
    };
    let down = |iface: &str| json!([{"link":"down","iface":iface,"t":BASE+1.0},{"link":"up","iface":iface,"t":BASE+5.0}]);
    // A down of the scanner-side interface is not the user\x27s action: nothing observed.
    let (r, _) = mk(down("feth4201"), "Failed", "TxUncertain").verify(&env);
    assert_eq!(
        result_of(&r, "link-down event of the peer interface observed"),
        NOT_RUN
    );
    // A down of the peer side during a scan that completed, or failed for another reason, is INVALID.
    for (reason, detail) in [
        ("Completed", ""),
        ("Failed", "RxLoss { kernel_drops: 7 }"),
        ("Failed", "ConsumerTooSlow"),
    ] {
        let (r, _) = mk(down("feth4202"), reason, detail).verify(&env);
        assert_eq!(
            result_of(&r, "ends in a failure naming a TX or link class"),
            INVALID,
            "{reason} {detail}"
        );
        assert!(
            !r.behaviour_fail(),
            "the lab cannot be held against the scanner here"
        );
    }
    // A TX failure passes the class gate and goes on to the real checks.
    let (r, _) = mk(down("feth4202"), "Failed", "TxUncertain { sent: 30 }").verify(&env);
    assert!(!has_check(
        &r,
        "ends in a failure naming a TX or link class"
    ));
    assert!(has_check(&r, "link loss fails the run"));
}

#[test]
fn a_kept_run_needs_the_uplink_tcpdump_to_have_exited_cleanly() {
    let env = Env::new("functional");
    for bad in [json!(null), json!(1), json!(130)] {
        let mut ev = build(&env, C01);
        ev.json("capture.json", |v| v["uplink"]["exit_code"] = bad.clone());
        let (r, _) = ev.verify(&env);
        assert_eq!(
            result_of(&r, "uplink tcpdump exited cleanly"),
            INVALID,
            "{bad}"
        );
        assert_eq!(r.verdict(), INVALID);
    }
    assert_eq!(
        result_of(
            &build(&env, C01).verify(&env).0,
            "uplink tcpdump exited cleanly"
        ),
        PASS
    );
}

#[test]
fn the_text_report_names_a_run_tripped_while_the_manifest_gate_failed() {
    let env = Env::new("functional");
    let mut ev = build(&env, C01);
    ev.set_frames("uplink", &vec![(BASE, syn(80))]);
    ev.write(&env);
    fs::remove_file(env.root.join("fixtures/manifest.json")).unwrap();
    let v = verify_dir(&env.root);
    let lines = verify::safety_report_lines(&v);
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("safety trip: ") && l.contains(C01)),
        "{lines:?}"
    );
    // Windows-shaped results (no safety_scan key) print exactly what they did.
    assert!(verify::safety_report_lines(&json!({"runs":[],"aborted":[]})).is_empty());
}

fn rebuild_peer(ev: &mut Ev, frames: &Frames) {
    ev.set_frames("peer", frames);
    let b = ev.files["peer.pcap"].clone();
    let n = frames.len();
    ev.json("capture.json", |v| {
        v["peer"]["pcap"] = json!({"sha256":hex_of(&Sha256::digest(&b)),"size":b.len(),"frames":n});
        v["peer"]["tcpdump"]["captured"] = json!(n);
        v["peer"]["tcpdump"]["received"] = json!(n);
        v["peer"]["witness"]["iface_rxtx_delta_hi"] = json!(n);
        v["peer"]["witness"]["iface_rxtx_delta_lo"] = json!(n);
    });
}

#[test]
fn a_capture_from_another_time_window_is_invalid() {
    let env = Env::new("functional");
    // The whole peer capture is an hour old while the metadata window is current.
    let mut ev = build(&env, C01);
    let mut fr = pcap::read_pcap_records(&ev.files["peer.pcap"]).unwrap().1;
    for (t, _) in &mut fr {
        *t -= 3600.0;
    }
    rebuild_peer(&mut ev, &fr);
    let (r, _) = ev.verify(&env);
    assert_eq!(
        result_of(&r, "capture packets fall inside the recorded window"),
        INVALID
    );
    assert_eq!(r.verdict(), INVALID);
    // Within the documented clock tolerance (2 s) it still passes.
    let mut ev = build(&env, C01);
    let mut fr = pcap::read_pcap_records(&ev.files["peer.pcap"]).unwrap().1;
    for (t, _) in &mut fr {
        *t += 1.5; // the end markers at +8.0 stay below capture_stopped +9.0 + 2.0
    }
    rebuild_peer(&mut ev, &fr);
    assert_eq!(ev.verdict(&env), PASS);
    let mut ev = build(&env, C01);
    let mut fr = pcap::read_pcap_records(&ev.files["peer.pcap"]).unwrap().1;
    for (t, _) in &mut fr {
        *t += 5.0;
    }
    rebuild_peer(&mut ev, &fr);
    assert_eq!(
        ev.verdict(&env),
        INVALID,
        "five seconds late is outside the tolerance"
    );
}

#[test]
fn start_markers_after_the_scanner_traffic_are_invalid() {
    let env = Env::new("functional");
    let mut ev = build(&env, C01);
    let mut fr = pcap::read_pcap_records(&ev.files["peer.pcap"]).unwrap().1;
    for (t, f) in &mut fr {
        if f.get(14..14 + START_PAYLOAD.len()) == Some(START_PAYLOAD) {
            *t = BASE + 7.0;
        }
    }
    fr.sort_by(|a, b| a.0.total_cmp(&b.0));
    rebuild_peer(&mut ev, &fr);
    let (r, _) = ev.verify(&env);
    assert_eq!(
        result_of(&r, "start markers, then scanner traffic, then end markers"),
        INVALID
    );
    assert_eq!(r.verdict(), INVALID);
    // End markers before the scanner traffic are the same kind of order violation.
    let mut ev = build(&env, C01);
    let mut fr = pcap::read_pcap_records(&ev.files["peer.pcap"]).unwrap().1;
    for (t, f) in &mut fr {
        if f.get(14..14 + END_PAYLOAD.len()) == Some(END_PAYLOAD) {
            *t = BASE - 0.5;
        }
    }
    fr.sort_by(|a, b| a.0.total_cmp(&b.0));
    rebuild_peer(&mut ev, &fr);
    let (r, _) = ev.verify(&env);
    assert_eq!(r.verdict(), INVALID);
}

#[test]
fn a_leak_in_an_unplanned_directory_is_fail_whatever_else_is_missing() {
    for name in [
        "unplanned",
        "c01_one_addr_port_synack.run1.extra",
        "weird name",
    ] {
        let env = Env::new("functional");
        let mut ev = build(&env, C01);
        ev.set_frames("uplink", &vec![(BASE, syn(80))]);
        let d = ev.write(&env);
        let leaf = if name == "weird name" {
            name.to_owned() // no nonce at all: a malformed name
        } else {
            format!("{name}.{}", nonce())
        };
        fs::rename(&d, env.root.join("runs").join(leaf)).unwrap();
        assert_eq!(safety_trips(&env.root).len(), 1, "{name}");
        let v = verify_dir(&env.root);
        assert_eq!(
            v["safety_trips"].as_array().unwrap().len(),
            1,
            "{name}: {v:#}"
        );
        assert_eq!(v["overall"], FAIL, "{name}");
        assert!(
            verify::safety_report_lines(&v)
                .iter()
                .any(|l| l.starts_with("safety trip: "))
        );
    }
    // The planned runs of a good set are not counted twice.
    let env = Env::new("functional");
    let mut ev = build(&env, C01);
    ev.set_frames("uplink", &vec![(BASE, syn(80))]);
    ev.write(&env);
    let v = verify_dir(&env.root);
    assert_eq!(v["safety_trips"].as_array().unwrap().len(), 1, "{v:#}");
}

#[test]
fn every_counter_of_the_tcpdump_stderr_is_compared_and_a_known_loss_is_invalid() {
    let env = Env::new("functional");
    // stderr reports interface drops, the JSON says zero.
    let mut ev = build(&env, C01);
    let old = String::from_utf8(ev.files["peer.err"].clone()).unwrap();
    ev.files.insert(
        "peer.err".into(),
        format!("{old}3 packets dropped by interface\n").into_bytes(),
    );
    let (r, _) = ev.verify(&env);
    assert_eq!(
        result_of(&r, "recorded tcpdump statistics equal peer.err"),
        INVALID
    );
    assert_eq!(r.verdict(), INVALID);
    // Consistent JSON and stderr, but a known non-zero loss: still INVALID, for both witnesses.
    for who in ["peer", "uplink"] {
        let mut ev = build(&env, C01);
        let old = String::from_utf8(ev.files[&format!("{who}.err")].clone()).unwrap();
        ev.files.insert(
            format!("{who}.err"),
            format!("{old}3 packets dropped by interface\n").into_bytes(),
        );
        ev.json("capture.json", |v| {
            v[who]["tcpdump"]["dropped_if"] = json!(3)
        });
        let (r, _) = ev.verify(&env);
        assert_eq!(r.verdict(), INVALID, "{who}");
        assert_eq!(
            result_of(&r, &format!("{who} capture no drops")),
            INVALID,
            "{who}"
        );
    }
}

#[test]
fn wire_scans_real_src_mac_check_values_have_one_contract() {
    // Every literal wire_scan can emit, read from its source, so the contract cannot drift from it.
    let src = include_str!("../../rmasscan-net/examples/wire_scan.rs");
    let mut emitted: Vec<&str> = src
        .lines()
        .filter(|l| l.contains("(m, \"") && !l.contains("assert"))
        .filter_map(|l| l.split("(m, \"").nth(1)?.split('"').next())
        .collect();
    emitted.sort_unstable();
    emitted.dedup();
    assert!(
        emitted.contains(&"explicit-equal") && emitted.contains(&"os-masked"),
        "{emitted:?}"
    );
    let env = Env::new("functional");
    for value in emitted {
        let mut ev = build(&env, C01);
        ev.json("run.json", |v| v["src_mac_check"] = json!(value));
        let verdict = ev.verify(&env).0.verdict().to_owned();
        let accepted = SRC_MAC_CHECK_ACCEPTED.contains(&value);
        assert_eq!(verdict == PASS, accepted, "{value}: {verdict}");
        if !accepted {
            assert_eq!(verdict, INVALID, "{value}");
        }
    }
    assert_eq!(SRC_MAC_CHECK_ACCEPTED, ["explicit-equal", "os-masked"]);
    // A value nobody emits is not evidence either.
    let mut ev = build(&env, C01);
    ev.json("run.json", |v| v["src_mac_check"] = json!("matched"));
    assert_eq!(ev.verdict(&env), INVALID);
}
