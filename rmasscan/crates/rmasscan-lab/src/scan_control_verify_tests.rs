//! Synthetic, hermetic scan-control evidence. Every frame is built here: SYNs from the scan plan (`ReadyPlan` + its
//! cursors, the product's own plan), peer SYN-ACK/RST by hand, the documents in the byte forms of the C reference
//! (`output_verify::tests::render`), `paused.conf` and the `[+]` lines rendered as text and not with the verifier's
//! parsers. One rule at a time is broken. Nothing touches a network or a real evidence directory.
use super::*;
use crate::{
    autodetect_verify::{
        HASHES,
        tests::{
            LAB_ID, Sim as AdSim, T0, TEARDOWN, interrupt_line, linux_isolation, marker,
            status_fragments, syn_dst, tcp_answer,
        },
    },
    link::{END_PAYLOAD, START_PAYLOAD},
    output_verify::tests::{R, cut_footer, render},
    pcap,
    windows_suite::nonce,
};
use std::path::PathBuf;

const PORT0: u16 = 41234;
const PORT1: u16 = 41235;
const ORACLE_PORT: u16 = 61234;
const ORACLE_STDERR: &str = "Starting masscan 1.3.9-integration (http://bit.ly/14GZzcT) at 2027-01-15 08:01:40 GMT\nInitiating SYN Stealth Scan\nScanning 4 hosts [3 ports/host]\nrate:  0.00-kpps, 100.00% done, waiting 3-secs, found=8       \r[-] Passed the wait window but still running, forcing exit...\n";

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-sc-verify-{}", nonce()));
    fs::create_dir_all(&d).unwrap();
    d
}

// ------------------------------------------------------------------ the generator

/// What one step left, before it is written.
#[derive(Clone)]
pub(crate) struct StepSim {
    pub(crate) spec: StepSpec,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) exit: i32,
    /// The peer capture of each link.
    pub(crate) links: Vec<Frames>,
    /// The output file (name, bytes) and the other collected files.
    pub(crate) files: Vec<(String, Vec<u8>)>,
    pub(crate) interrupt: Option<ScInterrupt>,
    pub(crate) netem: Option<NetemRecord>,
    pub(crate) argv: Vec<String>,
}
pub(crate) struct Sim {
    pub(crate) tag: &'static str,
    pub(crate) steps: Vec<StepSim>,
    pub(crate) expect: ScExpect,
    pub(crate) isolation: Vec<u8>,
    pub(crate) extra: Vec<(String, Vec<u8>)>,
    pub(crate) omit: Vec<String>,
}

fn json_bytes<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec_pretty(v).unwrap()
}
pub(crate) fn sc_isolation() -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(&linux_isolation()).unwrap();
    v["mode"] = json!("scan-control");
    v["second_link"] = json!({"scanner": "veth-a2", "peer": "veth-b2", "adapter_ip": "198.18.0.6"});
    json_bytes(&v)
}
fn ends(fr: &mut Frames, st: &Stand, last: f64) {
    for k in 0..3 {
        fr.push((last + 1.0 + f64::from(k) * 0.05, marker(st, END_PAYLOAD)));
    }
}
/// The peer capture of one link: the start marker, every SYN of `syns` at `t`, `at(i)`, its answer `delay` later
/// (SYN-ACK on an open port, RST otherwise), the end markers. The records the scanner would report, in send order.
fn link_frames(k: usize, t0: f64, syns: &[Vec<u8>], dt: f64, delay: f64) -> (Frames, Vec<R>) {
    link_frames_until(k, t0, syns, dt, delay, 0.0)
}
/// [`link_frames`] with the capture kept open until `t0 + until` (a scan that is paused stays up for its wait).
fn link_frames_until(
    k: usize,
    t0: f64,
    syns: &[Vec<u8>],
    dt: f64,
    delay: f64,
    until: f64,
) -> (Frames, Vec<R>) {
    let st = link_stand(k);
    let mut fr: Frames = vec![(t0, marker(&st, START_PAYLOAD))];
    let mut recs = Vec::new();
    let mut last = t0;
    for (i, s) in syns.iter().enumerate() {
        let t = t0 + 0.6 + i as f64 * dt;
        fr.push((t, s.clone()));
        let (ip, port) = syn_dst(s);
        let open = st.open_ports.contains(&port);
        let reason = if open { 0x12 } else { 0x14 };
        fr.push((t + delay, tcp_answer(s, reason, st.peer_mac, false)));
        last = last.max(t + delay);
        recs.push(R {
            open,
            ip,
            port,
            ts: (t + delay) as u64,
            reason,
            ttl: 64,
        });
    }
    ends(&mut fr, &st, last.max(t0 + until));
    (fr, recs)
}
/// The records a scanner reports for `recs`: the first reply per key (the engine deduplicates).
fn dedup(recs: &[R]) -> Vec<R> {
    let mut seen = BTreeSet::new();
    recs.iter()
        .filter(|r| seen.insert((r.ip, r.port)))
        .cloned()
        .collect()
}

const PLUS_AUTO: &str = "[+] interface = veth-a (detected: route to 198.18.0.2)\n[+] source-mac = 02-aa-00-00-00-01 (detected)\n[+] source-ip = 198.18.0.1 (detected)\n[+] router-ip = 198.18.0.2 (interface default gateway)\n[+] router-mac = 02-aa-00-00-00-02 (arp: 1 requests, 1 ms)\n[+] seed = 1 (given)\n";
fn auto_stderr(port: u16, src: &str) -> String {
    format!("{PLUS_AUTO}[+] source-port = {port} ({src})\n")
}
fn dual_stderr(p0: u16, p1: u16, src: &str) -> String {
    format!(
        "[+] interface = veth-a (given)\n[+] source-mac = 02-aa-00-00-00-01 (detected)\n[+] source-ip = 198.18.0.1 (detected)\n[+] router-mac = 02-aa-00-00-00-02 (given)\n[+] interface[1] = veth-a2 (given)\n[+] source-mac[1] = 02-aa-00-00-00-03 (given)\n[+] source-ip[1] = 198.18.0.6 (given)\n[+] router-mac[1] = 02-aa-00-00-00-04 (given)\n[+] seed = 1 (given)\n[+] source-port = {p0} ({src})\n[+] source-port[1] = {p1} ({src})\n"
    )
}
fn finished(reason: &str, sent: usize, recs: &[R]) -> String {
    let open = recs.iter().filter(|r| r.open).count();
    format!(
        "[+] finished: {reason}, sent {sent}, replies {}, open {open}\n",
        recs.len()
    )
}
fn waiting_tick(n: i64) -> String {
    format!("rate:  0.00-kpps, 100.00% done, waiting {n}-secs, found=8       \r")
}
fn erase() -> String {
    format!("{}\r", " ".repeat(77))
}
const SAVING: &str = "                                                                      \rsaving resume file to: paused.conf\n";
/// A completed scan's stderr: a running tick, then the erase right before `[+] finished`.
fn complete_stderr(plus: &str, sent: usize, recs: &[R]) -> String {
    let f = status_fragments();
    format!(
        "{plus}{}{}{}",
        f[0],
        erase(),
        finished("Completed", sent, recs)
    )
}
/// A paused scan's stderr: running tick, the Ctrl-C line, the saving line, the wait ticks, the erase.
fn paused_stderr(plus: &str, sent: usize, recs: &[R]) -> String {
    let f = status_fragments();
    format!(
        "{plus}{}{}{SAVING}{}{}{}{}",
        f[0],
        interrupt_line(),
        waiting_tick(2),
        waiting_tick(1),
        erase(),
        finished("Paused", sent, recs)
    )
}
fn conf(k: usize, port: u16, extra: &str) -> String {
    format!(
        "seed = 1\nrate = 10       \nshard = 1/1\nresume-index = {k}\nadapter-port = {port}\n{extra}output-filename = output.json\noutput-format = json\n# TARGET SELECTION (IP, PORTS, EXCLUDES)\nports = 76-95\nrange = 198.18.0.2-198.18.0.5\n"
    )
}
fn doc(fmt: Format, recs: &[R], t0: f64) -> Vec<u8> {
    render(fmt, recs, t0 as u64, t0 as u64 + 6)
}

fn spec_of(tag: &str, name: &str) -> StepSpec {
    steps(tag)
        .unwrap()
        .into_iter()
        .find(|s| s.name == name)
        .unwrap()
}
fn plan(spec: &PlanSpec) -> Vec<Vec<Vec<u8>>> {
    plan_streams(spec).unwrap()
}
fn base_step(spec: &StepSpec) -> StepSim {
    StepSim {
        spec: spec.clone(),
        stdout: String::new(),
        stderr: String::new(),
        exit: 0,
        links: Vec::new(),
        files: Vec::new(),
        interrupt: None,
        netem: None,
        argv: spec.argv.clone(),
    }
}
/// A scan that ran to its end on one link: `syns` on the wire, `recs` in the file.
fn one_link_step(
    tag: &str,
    name: &str,
    t0: f64,
    syns: &[Vec<u8>],
    port: u16,
    oracle: bool,
) -> StepSim {
    let spec = spec_of(tag, name);
    let mut s = base_step(&spec);
    let (fr, recs) = link_frames(0, t0, syns, 0.01, 0.0005);
    let out = dedup(&recs);
    let shown: Vec<R> = out.clone();
    let whole = doc(format_of(&spec), &shown, t0);
    s.links = vec![fr];
    if oracle {
        s.stderr = ORACLE_STDERR.to_owned();
        s.files = vec![("output.txt".into(), cut_footer(Format::List, &whole))];
    } else {
        s.stderr = complete_stderr(&auto_stderr(port, "time"), syns.len(), &shown);
        if let Some(n) = spec.output_name() {
            s.files = vec![(n.to_owned(), whole)];
        }
    }
    s
}

impl Sim {
    pub(crate) fn new(tag: &'static str) -> Sim {
        let mut sim = Sim {
            tag,
            steps: Vec::new(),
            expect: expect(tag).unwrap(),
            isolation: sc_isolation(),
            extra: Vec::new(),
            omit: Vec::new(),
        };
        sim.steps = match tag {
            "sc01_shards_union" => sc01_steps(),
            "sc02_pause_wait_resume" => sc02_steps(),
            "sc03_retries" => sc03_steps(),
            "sc04_packet_mods_and_pcap" => sc04_steps(),
            "sc05_infinite_interrupt" => sc05_steps(),
            _ => sc06_steps(),
        };
        sim
    }
    pub(crate) fn step(&mut self, name: &str) -> &mut StepSim {
        self.steps.iter_mut().find(|s| s.spec.name == name).unwrap()
    }
    /// The case directory's files (relative path, bytes) before hashing.
    pub(crate) fn files(&self) -> Vec<(String, Vec<u8>)> {
        let mut f = vec![
            (EXPECT_JSON.to_owned(), json_bytes(&self.expect)),
            (ISOLATION_JSON.to_owned(), self.isolation.clone()),
            (ISOLATION_POST_JSON.to_owned(), self.isolation.clone()),
        ];
        for s in &self.steps {
            let p = |n: &str| format!("{}/{n}", s.spec.name);
            f.push((
                p("argv.json"),
                json_bytes(&ArgvRecord {
                    argv: s.argv.clone(),
                }),
            ));
            f.push((p("stdout.txt"), s.stdout.clone().into_bytes()));
            f.push((p("stderr.txt"), s.stderr.clone().into_bytes()));
            f.push((p("exit.txt"), format!("{}\n", s.exit).into_bytes()));
            for (k, fr) in s.links.iter().enumerate() {
                let st = link_stand(k);
                let [pc, meta, err] = PEER_FILES[k];
                f.push((p(pc), pcap::encode(fr)));
                f.push((p(meta), AdSim::witness(fr)));
                f.push((
                    p(err),
                    format!("tcpdump: listening on {}, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n{1} packets captured\n{1} packets received by filter\n0 packets dropped by kernel\n", if k == 0 { "veth-b" } else { "veth-b2" }, fr.len()).into_bytes(),
                ));
                let _ = st;
            }
            f.extend(s.files.iter().map(|(n, b)| (p(n), b.clone())));
            if let Some(i) = &s.interrupt {
                f.push((p(INTERRUPT_JSON), json_bytes(i)));
            }
            if let Some(n) = &s.netem {
                f.push((p(NETEM_JSON), json_bytes(n)));
            }
        }
        f.retain(|(n, _)| !self.omit.contains(n));
        f.extend(self.extra.iter().cloned());
        f
    }
    /// Writes `root/manifest.json` (if absent) and `root/runs/<tag>/` with its hashes; returns the case directory.
    pub(crate) fn write(&self, root: &Path) -> PathBuf {
        let man = root.join(MANIFEST_JSON);
        if !man.exists() {
            fs::write(
                &man,
                json!({"scan-control": "linux", "lab_id": LAB_ID}).to_string(),
            )
            .unwrap();
        }
        let d = root.join("runs").join(self.tag);
        fs::create_dir_all(&d).unwrap();
        let mut files = self.files();
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let mut hashes = String::new();
        for (n, b) in &files {
            let p = d.join(n);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b).unwrap();
            hashes.push_str(&format!("{}  {n}\n", verify::sha(b)));
        }
        if !self.omit.iter().any(|o| o == HASHES) {
            fs::write(d.join(HASHES), hashes).unwrap();
        }
        d
    }
}

fn sc01_steps() -> Vec<StepSim> {
    let tag = "sc01_shards_union";
    let sh = |one, port| {
        let mut p = PlanSpec::single(PORTS, RATE, port);
        p.shard = (one, 2);
        plan(&p).remove(0)
    };
    let (a, b) = (sh(1, PORT0), sh(2, PORT1));
    let full = plan(&PlanSpec::single(PORTS, RATE, ORACLE_PORT)).remove(0);
    vec![
        one_link_step(tag, "shard1", T0, &a, PORT0, false),
        one_link_step(tag, "shard2", T0 + 100.0, &b, PORT1, false),
        one_link_step(tag, "oracle", T0 + 200.0, &full, ORACLE_PORT, true),
    ]
}
fn sc03_steps() -> Vec<StepSim> {
    let tag = "sc03_retries";
    let mut p = PlanSpec::single(PORTS, RATE, PORT0);
    p.retries = 2;
    let rm = plan(&p).remove(0);
    p.nics[0].port = ORACLE_PORT;
    let or = plan(&p).remove(0);
    vec![
        one_link_step(tag, "retries", T0, &rm, PORT0, false),
        one_link_step(tag, "oracle", T0 + 100.0, &or, ORACLE_PORT, true),
    ]
}
/// The scanner's `--pcap`: the classic header and the frames the peer sent to the scanner's ip:port.
fn scanner_pcap_bytes(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut b = PCAP_HEADER.to_vec();
    for (i, f) in frames.iter().enumerate() {
        b.extend((T0 as u32 + i as u32).to_le_bytes());
        b.extend(0u32.to_le_bytes());
        b.extend((f.len() as u32).to_le_bytes());
        b.extend((f.len() as u32).to_le_bytes());
        b.extend(f);
    }
    b
}
fn sc04_steps() -> Vec<StepSim> {
    let tag = "sc04_packet_mods_and_pcap";
    let mut p = PlanSpec::single(PORTS, RATE, PORT0);
    p.mods = Mods {
        ttl: Some(42),
        sackok: true,
        wscale: Some(7),
        ..Mods::default()
    };
    let mods_syns = plan(&p).remove(0);
    let mut mods = one_link_step(tag, "mods", T0, &mods_syns, PORT0, false);
    let replies: Vec<Vec<u8>> = mods.links[0]
        .iter()
        .filter(|(_, f)| tcp(f).is_some_and(|i| i.sm == "02:aa:00:00:00:02"))
        .map(|(_, f)| f.clone())
        .collect();
    mods.files
        .push((SCANNER_PCAP.into(), scanner_pcap_bytes(&replies)));
    // --badsum: the peer drops every SYN, nothing answers.
    let mut q = PlanSpec::single(PORTS, RATE, PORT1);
    q.mods.badsum = true;
    let bad_syns = plan(&q).remove(0);
    let mut bad = one_link_step(tag, "badsum", T0 + 100.0, &bad_syns, PORT1, false);
    let st = link_stand(0);
    let mut fr: Frames = vec![(T0 + 100.0, marker(&st, START_PAYLOAD))];
    for (i, s) in bad_syns.iter().enumerate() {
        fr.push((T0 + 100.6 + i as f64 * 0.01, s.clone()));
    }
    ends(&mut fr, &st, T0 + 101.0);
    bad.links = vec![fr];
    bad.stderr = complete_stderr(&auto_stderr(PORT1, "time"), 12, &[]);
    bad.files = vec![("output.txt".into(), Vec::new())];
    vec![mods, bad]
}
fn sc05_steps() -> Vec<StepSim> {
    let tag = "sc05_infinite_interrupt";
    let pass0 = plan(&PlanSpec::single(PORTS, RATE, PORT0)).remove(0);
    let mut syns = Vec::new();
    for j in 0..16usize {
        let mut pass = pass0.clone();
        pass.rotate_left(j % 12);
        syns.extend(pass);
    }
    syns.extend(pass0[..5].iter().cloned());
    let spec = spec_of(tag, "run");
    let mut s = base_step(&spec);
    let (fr, recs) = link_frames_until(0, T0, &syns, 0.01, 0.0005, 4.0);
    let out = dedup(&recs);
    let f = status_fragments();
    let infinite = "rate:  0.10-kpps, syn/s=100 ack/s=5 tcb-rate=0, 0-tcbs,         \r";
    s.stderr = format!(
        "{}{infinite}{infinite}{}{infinite}{}{}",
        auto_stderr(PORT0, "time"),
        interrupt_line(),
        erase(),
        finished("Paused", syns.len(), &out)
    );
    let _ = f;
    s.links = vec![fr];
    s.files = vec![("output.txt".into(), doc(Format::List, &out, T0))];
    s.interrupt = Some(ScInterrupt {
        signal: "INT".into(),
        after_s: INFINITE_AFTER_S,
        signal_unix: Some(T0 + 0.6 + syns.len() as f64 * 0.01),
        exit_within_s: EXIT_WITHIN_S,
        killed: false,
        paused_seen_unix: None,
        paused_conf_present: false,
    });
    vec![s]
}
const SENT_BEFORE_PAUSE: usize = 30;
/// A paused scan's capture stays open past its wait: SIGINT at 3.6 s, the wait 2 s.
const HOLD: f64 = 7.0;
fn sc02_steps() -> Vec<StepSim> {
    let tag = "sc02_pause_wait_resume";
    let full = plan(&PlanSpec::single(PAUSE_PORTS, PAUSE_RATE, PORT0)).remove(0);
    let k = SENT_BEFORE_PAUSE;
    let spec = spec_of(tag, "pause");
    let mut pause = base_step(&spec);
    // The peer's replies come a second late (netem): the last ten arrive after SIGINT, inside the wait.
    let (fr, recs) = link_frames_until(0, T0, &full[..k], 0.1, 1.0, HOLD);
    let out1 = dedup(&recs);
    pause.links = vec![fr];
    pause.stderr = paused_stderr(&auto_stderr(PORT0, "time"), k, &out1);
    let signal = T0 + 0.6 + 3.0;
    pause.interrupt = Some(ScInterrupt {
        signal: "INT".into(),
        after_s: PAUSE_AFTER_S,
        signal_unix: Some(signal),
        exit_within_s: EXIT_WITHIN_S,
        killed: false,
        paused_seen_unix: Some(signal + 0.1),
        paused_conf_present: true,
    });
    pause.netem = Some(NetemRecord {
        iface: "veth-b".into(),
        delay_ms: NETEM_DELAY_MS,
        applied: true,
        removed: true,
    });
    let doc1 = doc(Format::Json, &out1, T0);
    pause.files = vec![
        ("output.json".into(), doc1.clone()),
        (PAUSED_EVIDENCE.into(), conf(k, PORT0, "").into_bytes()),
    ];
    let rspec = spec_of(tag, "resume");
    let mut resume = base_step(&rspec);
    let (fr2, recs2) = link_frames(0, T0 + 100.0, &full[k..], 0.01, 0.0005);
    let out2 = dedup(&recs2);
    resume.links = vec![fr2];
    resume.stderr = complete_stderr(&auto_stderr(PORT0, "given"), full.len() - k, &out2);
    let mut both = doc1;
    both.extend(doc(Format::Json, &out2, T0 + 100.0));
    resume.files = vec![("output.json".into(), both)];
    vec![pause, resume]
}
fn sc06_steps() -> Vec<StepSim> {
    let tag = "sc06_dual_veth";
    let two = |ports: &str, rate: &str, resume: u64| {
        let mut p = PlanSpec::single(ports, rate, PORT0);
        p.nics.push(NicPlan {
            link: 1,
            port: PORT1,
        });
        p.resume_index = resume;
        plan(&p)
    };
    let both =
        |tag: &str, name: &str, t0: f64, syns: [&[Vec<u8>]; 2], dt: f64| -> (StepSim, Vec<R>) {
            let mut s = base_step(&spec_of(tag, name));
            let until = if name == "dual_pause" { HOLD } else { 0.0 };
            let (f0, r0) = link_frames_until(0, t0, syns[0], dt, 0.0005, until);
            let (f1, r1) = link_frames_until(1, t0, syns[1], dt, 0.0005, until);
            s.links = vec![f0, f1];
            (s, r0.into_iter().chain(r1).collect())
        };
    let p = two(PORTS, RATE, 0);
    let (mut dual, recs) = both(tag, "dual", T0, [&p[0], &p[1]], 0.01);
    let out = dedup(&recs);
    dual.stderr = complete_stderr(&dual_stderr(PORT0, PORT1, "time"), 12, &out);
    dual.files = vec![("output.txt".into(), doc(Format::List, &out, T0))];
    // The pause: adapter 0 sent 14 probes and adapter 1 17 before SIGINT; the resume starts from the minimum base
    // 2 x 14 = 28, so adapter 1 sends its probes 14..17 a second time (bounded duplicates, not an exact multiset).
    let q = two(PAUSE_PORTS, PAUSE_RATE, 0);
    let (a0, a1) = (14usize, 17usize);
    let (mut pause, recs) = both(
        tag,
        "dual_pause",
        T0 + 100.0,
        [&q[0][..a0], &q[1][..a1]],
        0.1,
    );
    let out1 = dedup(&recs);
    pause.stderr = paused_stderr(&dual_stderr(PORT0, PORT1, "time"), a0 + a1, &out1);
    let signal = T0 + 100.0 + 0.6 + 3.0;
    pause.interrupt = Some(ScInterrupt {
        signal: "INT".into(),
        after_s: PAUSE_AFTER_S,
        signal_unix: Some(signal),
        exit_within_s: EXIT_WITHIN_S,
        killed: false,
        paused_seen_unix: Some(signal + 0.1),
        paused_conf_present: true,
    });
    let doc1 = doc(Format::Json, &out1, T0 + 100.0);
    let extra = "adapter[1] = veth-a2\nadapter-ip[1] = 198.18.0.6\n";
    pause.files = vec![
        ("output.json".into(), doc1.clone()),
        (PAUSED_EVIDENCE.into(), conf(28, PORT0, extra).into_bytes()),
    ];
    let m = 28u64;
    let r = two(PAUSE_PORTS, PAUSE_RATE, m);
    let (mut resume, recs2) = both(tag, "dual_resume", T0 + 200.0, [&r[0], &r[1]], 0.01);
    let out2 = dedup(&recs2);
    resume.stderr = complete_stderr(
        &dual_stderr(PORT0, PORT1, "given"),
        r[0].len() + r[1].len(),
        &out2,
    );
    let mut whole = doc1;
    whole.extend(doc(Format::Json, &out2, T0 + 200.0));
    resume.files = vec![("output.json".into(), whole)];
    vec![dual, pause, resume]
}

// ------------------------------------------------------------------ judging

fn run_of(res: &Value, tag: &str) -> Value {
    array(&res["runs"])
        .iter()
        .find(|r| r["tag"] == tag)
        .cloned()
        .unwrap_or_else(|| panic!("no run {tag}"))
}
fn bad(run: &Value) -> Vec<String> {
    array(&run["checks"])
        .iter()
        .filter(|c| c["result"] != PASS)
        .map(|c| format!("{}: {} ({})", c["result"], c["name"], c["detail"]))
        .collect()
}
#[track_caller]
fn check<'a>(run: &'a Value, needle: &str) -> &'a Value {
    array(&run["checks"])
        .iter()
        .find(|c| c["name"].as_str().is_some_and(|n| n.contains(needle)))
        .unwrap_or_else(|| panic!("no check {needle:?} in {:#}", run["checks"]))
}
fn judge(sim: &Sim) -> Value {
    let root = scratch();
    sim.write(&root);
    let v = run_of(&verify_dir(&root), sim.tag);
    fs::remove_dir_all(root).unwrap();
    v
}
#[track_caller]
fn assert_verdict(run: &Value, want: &str) {
    assert_eq!(run["verdict"], want, "{} {:#?}", run["tag"], bad(run));
}
/// `sim` broken by `f`, judged: it must be `want`, and the check named `needle` must be `result`.
#[track_caller]
fn breaks(tag: &'static str, f: impl FnOnce(&mut Sim), want: &str, needle: &str) -> Value {
    let mut sim = Sim::new(tag);
    f(&mut sim);
    let r = judge(&sim);
    assert_verdict(&r, want);
    assert_eq!(check(&r, needle)["result"], want, "{needle}");
    r
}
fn edit_text(s: &mut StepSim, file: &str, f: impl Fn(&str) -> String) {
    let (_, b) = s.files.iter_mut().find(|(n, _)| n == file).unwrap();
    *b = f(&String::from_utf8(b.clone()).unwrap()).into_bytes();
}
/// The SYNs of link `k` of `s` (time, frame).
fn syn_idx(s: &StepSim, k: usize) -> Vec<usize> {
    s.links[k]
        .iter()
        .enumerate()
        .filter(|(_, (_, f))| pcap::is_syn(f))
        .map(|(i, _)| i)
        .collect()
}
fn mutate_syn(s: &mut StepSim, k: usize, n: usize, f: impl Fn(&mut Vec<u8>)) {
    let i = syn_idx(s, k)[n];
    f(&mut s.links[k][i].1);
}
fn drop_syn(s: &mut StepSim, k: usize, n: usize) {
    let i = syn_idx(s, k)[n];
    s.links[k].remove(i);
    // and its reply, which follows it
    s.links[k].remove(i);
}

// ------------------------------------------------------------------ the brief's tests

#[test]
fn a_consistent_evidence_directory_is_pass() {
    let root = scratch();
    for tag in planned_tags() {
        Sim::new(tag).write(&root);
    }
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = verify_dir(&root);
    for tag in planned_tags() {
        assert_verdict(&run_of(&res, tag), PASS);
    }
    assert_verdict(&run_of(&res, "manifest"), PASS);
    assert_eq!(res["overall"], PASS, "{res:#}");
    assert_eq!(res["safety_trips"], json!([]));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_case_table_holds_the_six_cases_and_their_argv() {
    assert_eq!(
        planned_tags(),
        [
            "sc01_shards_union",
            "sc02_pause_wait_resume",
            "sc03_retries",
            "sc04_packet_mods_and_pcap",
            "sc05_infinite_interrupt",
            "sc06_dual_veth"
        ]
    );
    let a = |tag: &str, name: &str| spec_of(tag, name).argv.join(" ");
    let common = "-p80,443,8080 -oL output.txt --show open,closed --seed 1 --rate 100 --wait 3";
    assert_eq!(
        a("sc01_shards_union", "shard1"),
        format!("198.18.0.2-198.18.0.5 {common} --shard 1/2")
    );
    assert_eq!(
        a("sc01_shards_union", "shard2"),
        format!("198.18.0.2-198.18.0.5 {common} --shard 2/2")
    );
    assert_eq!(
        a("sc01_shards_union", "oracle"),
        format!("198.18.0.2-198.18.0.5 {common}")
    );
    assert_eq!(
        a("sc03_retries", "retries"),
        format!("198.18.0.2-198.18.0.5 {common} --retries 2")
    );
    assert_eq!(a("sc03_retries", "oracle"), a("sc03_retries", "retries"));
    assert_eq!(
        a("sc04_packet_mods_and_pcap", "mods"),
        format!(
            "198.18.0.2-198.18.0.5 {common} --ttl 42 --tcp-sackok --tcp-wscale 7 --pcap scanner.pcap"
        )
    );
    assert_eq!(
        a("sc04_packet_mods_and_pcap", "badsum"),
        format!("198.18.0.2-198.18.0.5 {common} --badsum")
    );
    assert_eq!(
        a("sc05_infinite_interrupt", "run"),
        format!("198.18.0.2-198.18.0.5 {common} --infinite")
    );
    assert_eq!(
        a("sc02_pause_wait_resume", "pause"),
        "198.18.0.2-198.18.0.5 -p76-95 -oJ output.json --show open,closed --seed 1 --rate 10 --wait 2"
    );
    assert_eq!(
        a("sc02_pause_wait_resume", "resume"),
        "--resume paused.conf --show open,closed --wait 3"
    );
    assert!(a("sc06_dual_veth", "dual").ends_with("--adapter[0] veth-a --adapter[1] veth-a2 --adapter-ip[1] 198.18.0.6 --adapter-mac[1] 02-aa-00-00-00-03 --router-mac[0] 02-aa-00-00-00-02 --router-mac[1] 02-aa-00-00-00-04"));
    assert_eq!(
        spec_of("sc06_dual_veth", "dual_resume").argv,
        spec_of("sc02_pause_wait_resume", "resume").argv
    );
    // Which cases have the oracle: only sc01 and sc03; the others say why not.
    for tag in TAGS {
        let has_oracle = steps(tag).unwrap().iter().any(|s| s.who == Who::Oracle);
        assert_eq!(
            has_oracle,
            matches!(tag, "sc01_shards_union" | "sc03_retries"),
            "{tag}"
        );
        assert!(
            oracle_note(tag).is_some_and(|n| n.contains("oracle") || n.contains("rmasscan-only")),
            "{tag}"
        );
        if !has_oracle {
            assert!(
                oracle_note(tag).unwrap().starts_with("rmasscan-only"),
                "{tag}"
            );
        }
    }
    // The interrupted steps and the one with the netem delay.
    let interrupted: Vec<&str> = TAGS
        .iter()
        .flat_map(|t| steps(t).unwrap())
        .filter(|s| s.interrupt_after_s.is_some())
        .map(|s| s.name)
        .collect();
    assert_eq!(interrupted, ["pause", "run", "dual_pause"]);
    assert!(
        spec_of("sc02_pause_wait_resume", "pause").netem
            && !spec_of("sc06_dual_veth", "dual_pause").netem
    );
    assert!(steps("nope").is_none() && expect("nope").is_none());
}

#[test]
fn every_target_of_every_step_is_inside_the_lab_net() {
    use crate::autodetect_suite::addresses_outside_the_lab;
    for tag in TAGS {
        for s in steps(tag).unwrap() {
            assert_eq!(
                addresses_outside_the_lab(&s.argv),
                Vec::<String>::new(),
                "{tag} {}",
                s.name
            );
        }
    }
    assert_eq!(
        addresses_outside_the_lab(&argv(&["8.8.8.8", "-p80"])),
        ["8.8.8.8"]
    );
}

// ---- evidence gate, seal, privacy, safety

#[test]
fn a_seal_without_the_second_link_or_of_the_wrong_mode_is_invalid() {
    for edit in [
        |v: &mut Value| v["mode"] = json!("autodetect"),
        |v: &mut Value| {
            v["second_link"] =
                json!({"scanner": "veth-a2", "peer": "veth-b2", "adapter_ip": "198.18.0.7"})
        },
        |v: &mut Value| {
            v.as_object_mut().unwrap().remove("second_link");
        },
        |v: &mut Value| v["uplink"] = json!(true),
    ] {
        let r = breaks(
            "sc03_retries",
            |sim| {
                let mut v: Value = serde_json::from_slice(&sim.isolation).unwrap();
                edit(&mut v);
                sim.isolation = json_bytes(&v);
            },
            INVALID,
            "isolation.json: the sealed scan-control stand",
        );
        assert_eq!(check(&r, "isolation-post.json")["result"], INVALID);
    }
}

#[test]
fn a_hash_mismatch_a_wrong_argv_or_a_wrong_expect_is_invalid() {
    let root = scratch();
    let d = Sim::new("sc04_packet_mods_and_pcap").write(&root);
    fs::write(d.join("mods/stdout.txt"), "x").unwrap();
    let r = run_of(&verify_dir(&root), "sc04_packet_mods_and_pcap");
    assert_verdict(&r, INVALID);
    assert_eq!(check(&r, "hashes-before-copy.txt")["result"], INVALID);
    fs::remove_dir_all(root).unwrap();
    breaks(
        "sc04_packet_mods_and_pcap",
        |s| s.step("mods").argv.push("--ttl".into()),
        INVALID,
        "mods/argv.json is the step's argv",
    );
    breaks(
        "sc01_shards_union",
        |s| s.expect.steps[0].links = 2,
        INVALID,
        "expect.json equals",
    );
}

#[test]
fn private_names_in_any_text_file_are_invalid() {
    for (file, text) in [
        ("stderr.txt", "[+] interface = eth0 (detected)\n"),
        ("stderr.txt", "see /Users/alice/x\n"),
        ("stdout.txt", "host 192.168.1.20\n"),
        ("paused.txt", "adapter = wlp3s0 02:11:22:33:44:55\n"),
    ] {
        let mut sim = Sim::new("sc02_pause_wait_resume");
        let s = sim.step("pause");
        match file {
            "stderr.txt" => s.stderr.push_str(text),
            "stdout.txt" => s.stdout.push_str(text),
            _ => edit_text(s, PAUSED_EVIDENCE, |t| format!("{t}{text}")),
        }
        let r = judge(&sim);
        assert_eq!(r["verdict"], INVALID, "{file} {text}: {:#?}", bad(&r));
        assert!(
            check(&r, "privacy")["result"] == INVALID
                || check(&r, "privacy: pause/")["result"] == INVALID
        );
    }
}

#[test]
fn a_frame_from_a_foreign_mac_or_a_syn_off_the_stand_on_either_link_is_a_safety_fail() {
    for (tag, step, link) in [
        ("sc03_retries", "retries", 0),
        ("sc06_dual_veth", "dual", 1),
        ("sc06_dual_veth", "dual", 0),
    ] {
        let mut sim = Sim::new(tag);
        let s = sim.step(step);
        // a SYN from the second link's address on the first link (and the reverse) is not the stand's binding
        let mut syn = s.links[link][syn_idx(s, link)[0]].1.clone();
        syn[6..12].copy_from_slice(&[2, 0xbb, 0, 0, 0, 9]);
        s.links[link].insert(2, (T0 + 0.01, syn));
        let r = judge(&sim);
        assert_eq!(r["verdict"], FAIL, "{tag} {link}");
        assert_eq!(r["safety_trip"], true);
    }
    let mut sim = Sim::new("sc06_dual_veth");
    let s = sim.step("dual");
    let syn = s.links[0][syn_idx(s, 0)[0]].1.clone();
    // the first adapter's SYN on the second link: wrong source address and MAC for that link
    s.links[1].insert(2, (T0 + 0.01, syn));
    assert_eq!(judge(&sim)["safety_trip"], true);
}

// ---- stderr grammar

#[test]
fn the_stderr_parser_reads_the_status_forms_and_the_saving_line() {
    let s = parse_stderr(&paused_stderr(&auto_stderr(PORT0, "time"), 30, &[]));
    assert_eq!(s.stray, Vec::<String>::new());
    assert_eq!(
        (
            s.count(Ev::Interrupt),
            s.count(Ev::Saving),
            s.count(Ev::Waiting),
            s.count(Ev::Erase)
        ),
        (1, 1, 2, 1)
    );
    assert!(s.at(Ev::Interrupt) < s.at(Ev::Saving) && s.at(Ev::Saving) < s.at(Ev::Waiting));
    assert_eq!(s.wait_secs, [2, 1]);
    assert_eq!(s.fin.as_ref().unwrap().reason, "Paused");
    assert_eq!(s.number("source-port"), Some(u64::from(PORT0)));
    let inf = parse_stderr("rate:  0.10-kpps, syn/s=100 ack/s=5 tcb-rate=0, 0-tcbs,         \r\n");
    assert_eq!(inf.events, [Ev::Infinite]);
    for bad_form in [
        "rate:  0.10-kpps, syn/s=x ack/s=5 tcb-rate=0, 0-tcbs,         \r\n",
        "rate:  0.10-kpps, syn/s=100 ack/s=5 tcb-rate=0, 0-tcbs,\r\n",
        "something else\n",
        "[+] finished: Paused, sent x\n",
        "                                                                      \r\n",
    ] {
        assert!(!parse_stderr(bad_form).stray.is_empty(), "{bad_form:?}");
    }
}

// ---- frames

#[test]
fn syn_info_reads_ttl_checksums_and_options_of_the_products_frames() {
    let mut p = PlanSpec::single(PORTS, RATE, PORT0);
    p.mods = Mods {
        ttl: Some(42),
        sackok: true,
        wscale: Some(7),
        ..Mods::default()
    };
    let f = &plan(&p)[0][0];
    let i = syn_info(f).unwrap();
    assert_eq!(
        (i.ttl, i.ip_header_ok, i.tcp_checksum_ok, i.length_ok),
        (42, true, true, true)
    );
    assert_eq!(
        i.options,
        Ok(vec![TcpOpt::Mss(1460), TcpOpt::SackOk, TcpOpt::WScale(7)])
    );
    assert_eq!(f.len(), 14 + 20 + 20 + 12);
    p.mods = Mods {
        badsum: true,
        ..Mods::default()
    };
    let b = syn_info(&plan(&p)[0][0]).unwrap();
    assert_eq!(
        (b.ttl, b.ip_header_ok, b.tcp_checksum_ok),
        (255, true, false)
    );
    assert_eq!(
        tcp_options(&[2, 4, 5, 0xb4, 1, 0, 0, 0]),
        Ok(vec![TcpOpt::Mss(1460), TcpOpt::Other(1)])
    );
    assert!(tcp_options(&[2, 4, 5, 0xb4, 0, 0, 9, 0]).is_err());
    assert!(tcp_options(&[2, 9]).is_err());
}

// ------------------------------------------------------------------ sc01

#[test]
fn sc01_passes_and_its_oracle_has_no_footer_after_the_forced_exit() {
    let sim = Sim::new("sc01_shards_union");
    let r = judge(&sim);
    assert_verdict(&r, PASS);
    assert_eq!(r["notes"]["oracle_forced_exit"], true);
    // a footer the oracle did write is fine too
    let mut sim = Sim::new("sc01_shards_union");
    let o = sim.step("oracle");
    let recs: Vec<R> = Vec::new();
    let _ = recs;
    o.files[0].1.extend(b"# end\n");
    o.stderr = o.stderr.replace(FORCED_EXIT, "");
    assert_verdict(&judge(&sim), PASS);
}

#[test]
fn sc01_an_oracle_without_footer_and_without_the_forced_exit_line_is_invalid() {
    breaks(
        "sc01_shards_union",
        |s| {
            let o = s.step("oracle");
            o.stderr = o.stderr.replace(FORCED_EXIT, "");
        },
        INVALID,
        "its file lacks the footer only after masscan's forced exit",
    );
}

#[test]
fn sc01_shards_that_overlap_or_leave_a_probe_out_fail() {
    // shard 2/2 sends shard 1/2's probes again: they overlap and half the scan is missing
    let r = breaks(
        "sc01_shards_union",
        |s| {
            let a = s.step("shard1").links[0].clone();
            let st = s.step("shard2");
            st.links = vec![a];
        },
        FAIL,
        "share none",
    );
    assert_eq!(check(&r, "all 12 probes")["result"], FAIL);
    // shard 2/2 loses a probe
    let r = breaks(
        "sc01_shards_union",
        |s| drop_syn(s.step("shard2"), 0, 5),
        FAIL,
        "all 12 probes",
    );
    assert_eq!(check(&r, "shard2: the shard sends half")["result"], FAIL);
    // the plan of a shard is exact: two SYNs swapped
    breaks(
        "sc01_shards_union",
        |s| {
            let st = s.step("shard1");
            let (a, b) = (syn_idx(st, 0)[0], syn_idx(st, 0)[1]);
            let (fa, fb) = (st.links[0][a].1.clone(), st.links[0][b].1.clone());
            st.links[0][a].1 = fb;
            st.links[0][b].1 = fa;
        },
        FAIL,
        "equal the plan of --shard 1/2",
    );
}

#[test]
fn sc01_findings_must_be_the_oracles_and_the_oracles_order_the_shards_interleaved() {
    // the oracle finds one record less than the shards together
    let r = breaks(
        "sc01_shards_union",
        |s| {
            let o = s.step("oracle");
            edit_text(o, "output.txt", |t| {
                let first = t.lines().position(|l| l.starts_with("open ")).unwrap();
                let mut lines: Vec<&str> = t.lines().collect();
                lines.remove(first);
                format!("{}\n", lines.join("\n"))
            });
        },
        FAIL,
        "together are the oracle's findings",
    );
    assert_eq!(
        check(&r, "together are the stand's replies")["result"],
        PASS
    );
    // the shards miss a finding
    breaks(
        "sc01_shards_union",
        |s| {
            let st = s.step("shard1");
            edit_text(st, "output.txt", |t| {
                let mut lines: Vec<&str> = t.lines().collect();
                lines.remove(1);
                format!("{}\n", lines.join("\n"))
            });
        },
        FAIL,
        "together are the stand's replies",
    );
    // the oracle's probes in another order than the shards interleaved
    breaks(
        "sc01_shards_union",
        |s| {
            let o = s.step("oracle");
            let (a, b) = (syn_idx(o, 0)[0], syn_idx(o, 0)[1]);
            let (fa, fb) = (o.links[0][a].1.clone(), o.links[0][b].1.clone());
            o.links[0][a].1 = fb;
            o.links[0][b].1 = fa;
        },
        FAIL,
        "interleaved",
    );
}

// ------------------------------------------------------------------ sc02

#[test]
fn sc02_passes_with_a_late_reply_a_paused_conf_and_an_exact_resume() {
    let r = judge(&Sim::new("sc02_pause_wait_resume"));
    assert_verdict(&r, PASS);
    for n in [
        "a reply that came on the wire after SIGINT",
        "--resume sends exactly the rest of the plan",
        "the SYNs of both runs are the multiset of the continuous scan",
        "output-append",
        "paused.conf is saved after the Ctrl-C line and before the first",
        "paused.conf was on disk within 1 s of SIGINT",
    ] {
        assert_eq!(check(&r, n)["result"], PASS, "{n}");
    }
}

#[test]
fn sc02_a_wait_phase_that_catches_no_late_reply_fails() {
    // no netem: the peer answers at once, nothing arrives after SIGINT
    let r = breaks(
        "sc02_pause_wait_resume",
        |s| {
            let full = plan(&PlanSpec::single(PAUSE_PORTS, PAUSE_RATE, PORT0)).remove(0);
            let st = s.step("pause");
            let (fr, _) = link_frames_until(0, T0, &full[..SENT_BEFORE_PAUSE], 0.1, 0.0005, HOLD);
            st.links = vec![fr];
        },
        FAIL,
        "a reply that came on the wire after SIGINT",
    );
    assert!(
        check(&r, "a reply that came on the wire after SIGINT")["detail"]
            .as_str()
            .unwrap()
            .contains("0 late")
    );
    // a late reply the scanner did not record (the wait dropped it)
    breaks(
        "sc02_pause_wait_resume",
        |s| {
            let st = s.step("pause");
            edit_text(st, "output.json", |t| {
                let at = t.rfind(",\n").unwrap();
                format!("{}]\n", &t[..at])
            });
            let (_, b) = st
                .files
                .iter_mut()
                .find(|(n, _)| n == "output.json")
                .unwrap();
            let _ = b;
        },
        FAIL,
        "holds every reply to the SYNs sent before the pause",
    );
}

#[test]
fn sc02_paused_conf_must_be_saved_before_the_wait_and_exist_within_a_second() {
    // the saving line after the first wait tick
    breaks(
        "sc02_pause_wait_resume",
        |s| {
            let st = s.step("pause");
            st.stderr = st
                .stderr
                .replace(SAVING, "")
                .replace(&erase(), &format!("{SAVING}{}", erase()));
        },
        FAIL,
        "saved after the Ctrl-C line and before the first",
    );
    // no saving line at all
    breaks(
        "sc02_pause_wait_resume",
        |s| {
            let st = s.step("pause");
            st.stderr = st.stderr.replace(SAVING, "");
        },
        FAIL,
        "`saving resume file to: paused.conf` once",
    );
    // the file appeared only after the wait ended
    breaks(
        "sc02_pause_wait_resume",
        |s| {
            let st = s.step("pause");
            let i = st.interrupt.as_mut().unwrap();
            i.paused_seen_unix = i.signal_unix.map(|t| t + 2.5);
        },
        FAIL,
        "paused.conf was on disk within 1 s",
    );
    // no wait phase: no waiting tick
    breaks(
        "sc02_pause_wait_resume",
        |s| {
            let st = s.step("pause");
            st.stderr = st
                .stderr
                .replace(&waiting_tick(2), "")
                .replace(&waiting_tick(1), "");
        },
        FAIL,
        "the wait phase ran",
    );
    // an exit code other than 0, SIGKILL, a missing Ctrl-C line, a footer that is not closed
    breaks(
        "sc02_pause_wait_resume",
        |s| s.step("pause").exit = 1,
        FAIL,
        "exit.txt is 0",
    );
    breaks(
        "sc02_pause_wait_resume",
        |s| s.step("pause").interrupt.as_mut().unwrap().killed = true,
        FAIL,
        "no SIGKILL",
    );
    breaks(
        "sc02_pause_wait_resume",
        |s| {
            let st = s.step("pause");
            st.stderr = st.stderr.replace(&interrupt_line(), "");
        },
        FAIL,
        "Ctrl-C line once",
    );
    breaks(
        "sc02_pause_wait_resume",
        |s| {
            edit_text(s.step("pause"), "output.json", |t| {
                t.trim_end_matches("]\n").to_owned()
            });
            let st = s.step("resume");
            edit_text(st, "output.json", |t| t.replacen("]\n[\n", "\n[\n", 1));
        },
        FAIL,
        "complete after the pause",
    );
}

#[test]
fn sc02_a_resume_that_resends_or_skips_a_probe_or_truncates_the_file_fails() {
    // resends the last probe of the first run
    let r = breaks(
        "sc02_pause_wait_resume",
        |s| {
            let full = plan(&PlanSpec::single(PAUSE_PORTS, PAUSE_RATE, PORT0)).remove(0);
            let st = s.step("resume");
            let (fr, _) = link_frames(0, T0 + 100.0, &full[SENT_BEFORE_PAUSE - 1..], 0.01, 0.0005);
            st.links = vec![fr];
        },
        FAIL,
        "--resume sends exactly the rest of the plan",
    );
    assert_eq!(check(&r, "multiset of the continuous scan")["result"], FAIL);
    // skips the first probe of the rest
    breaks(
        "sc02_pause_wait_resume",
        |s| drop_syn(s.step("resume"), 0, 0),
        FAIL,
        "multiset of the continuous scan",
    );
    // restarts from the beginning
    breaks(
        "sc02_pause_wait_resume",
        |s| {
            let full = plan(&PlanSpec::single(PAUSE_PORTS, PAUSE_RATE, PORT0)).remove(0);
            let st = s.step("resume");
            let (fr, _) = link_frames(0, T0 + 100.0, &full, 0.01, 0.0005);
            st.links = vec![fr];
        },
        FAIL,
        "--resume sends exactly the rest of the plan",
    );
    // the output file is truncated and rewritten, not appended
    let r = breaks(
        "sc02_pause_wait_resume",
        |s| {
            let st = s.step("resume");
            let (_, b) = st
                .files
                .iter_mut()
                .find(|(n, _)| n == "output.json")
                .unwrap();
            let at = b.windows(4).position(|w| w == b"]\n[\n").unwrap() + 2;
            b.drain(..at);
        },
        FAIL,
        "output-append",
    );
    assert_eq!(
        check(&r, "the appended part is one well-formed")["result"],
        FAIL
    );
}

#[test]
fn sc02_paused_conf_must_hold_the_stop_point_the_seed_and_the_port() {
    breaks(
        "sc02_pause_wait_resume",
        |s| {
            edit_text(s.step("pause"), PAUSED_EVIDENCE, |t| {
                t.replace("resume-index = 30", "resume-index = 31")
            });
        },
        FAIL,
        "resume-index equals the SYNs sent",
    );
    breaks(
        "sc02_pause_wait_resume",
        |s| {
            edit_text(s.step("pause"), PAUSED_EVIDENCE, |t| {
                t.replace("resume-index = 30", "resume-index = 0")
            });
        },
        FAIL,
        "resume-index is where the scan stopped",
    );
    breaks(
        "sc02_pause_wait_resume",
        |s| {
            edit_text(s.step("pause"), PAUSED_EVIDENCE, |t| {
                t.replace("seed = 1", "seed = 2")
            });
        },
        FAIL,
        "seed, rate and the source port",
    );
    breaks(
        "sc02_pause_wait_resume",
        |s| {
            edit_text(s.step("pause"), PAUSED_EVIDENCE, |t| {
                t.replace("output-format = json", "output-format = list")
            });
        },
        FAIL,
        "carries the output file and format",
    );
    // no paused.conf at all: unproven
    let mut sim = Sim::new("sc02_pause_wait_resume");
    sim.omit.push(format!("pause/{PAUSED_EVIDENCE}"));
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
}

#[test]
fn sc02_the_netem_record_must_show_a_delay_that_fits_the_wait() {
    for edit in [
        |n: &mut NetemRecord| n.delay_ms = 2500,
        |n: &mut NetemRecord| n.removed = false,
        |n: &mut NetemRecord| n.iface = "veth-a".into(),
    ] {
        breaks(
            "sc02_pause_wait_resume",
            |s| edit(s.step("pause").netem.as_mut().unwrap()),
            INVALID,
            "netem.json",
        );
    }
}

// ------------------------------------------------------------------ sc03

#[test]
fn sc03_passes_with_nine_sends_per_probe_and_the_oracles_multiset() {
    let r = judge(&Sim::new("sc03_retries"));
    assert_verdict(&r, PASS);
    assert_eq!(r["notes"]["oracle_forced_exit"], true);
    assert_eq!(
        check(&r, "multiset of probes on the wire equals the oracle's")["result"],
        PASS
    );
}

#[test]
fn sc03_a_scan_with_other_retries_or_an_uneven_count_fails() {
    for keep in [2usize, 4] {
        let r = breaks(
            "sc03_retries",
            |s| {
                let mut p = PlanSpec::single(PORTS, RATE, PORT0);
                p.retries = keep as u32 - 1;
                let syns = plan(&p).remove(0);
                let st = s.step("retries");
                let (fr, _) = link_frames(0, T0, &syns, 0.01, 0.0005);
                st.links = vec![fr];
            },
            FAIL,
            "retries: --retries 2 puts every probe on the wire (2+1)^2 = 9 times",
        );
        assert_eq!(check(&r, "[+] finished reports sent")["result"], FAIL);
    }
    // one probe missing one send
    breaks(
        "sc03_retries",
        |s| drop_syn(s.step("retries"), 0, 7),
        FAIL,
        "retries: --retries 2 puts every probe on the wire (2+1)^2 = 9 times",
    );
    // the oracle sends another multiset: a broken oracle is a broken stand
    breaks(
        "sc03_retries",
        |s| drop_syn(s.step("oracle"), 0, 3),
        INVALID,
        "oracle: --retries 2 puts every probe on the wire (2+1)^2 = 9 times",
    );
}

#[test]
fn sc03_a_record_reported_twice_or_a_different_finding_fails() {
    breaks(
        "sc03_retries",
        |s| {
            edit_text(s.step("retries"), "output.txt", |t| {
                let line = t.lines().nth(1).unwrap().to_owned();
                t.replacen(&format!("{line}\n"), &format!("{line}\n{line}\n"), 1)
            });
        },
        FAIL,
        "holds no record twice",
    );
    breaks(
        "sc03_retries",
        |s| {
            edit_text(s.step("retries"), "output.txt", |t| {
                t.replacen(" tcp 443 ", " tcp 444 ", 1)
            });
        },
        FAIL,
        "findings equal the oracle's",
    );
}

// ------------------------------------------------------------------ sc04

#[test]
fn sc04_passes_ttl_options_checksums_badsum_and_the_scanners_pcap() {
    let r = judge(&Sim::new("sc04_packet_mods_and_pcap"));
    assert_verdict(&r, PASS);
    for n in [
        "every SYN has TTL 42",
        "MSS 1460, SACK-permitted and window scale 7",
        "TCP checksum is invalid while its IPv4 header checksum is valid",
        "is a classic pcap",
        "holds only frames to the scanner's ip:port",
        "every frame of scanner.pcap is a frame the peer sent",
    ] {
        assert_eq!(check(&r, n)["result"], PASS, "{n}");
    }
}

#[test]
fn sc04_a_wrong_ttl_or_missing_option_or_bad_checksum_on_the_modified_run_fails() {
    breaks(
        "sc04_packet_mods_and_pcap",
        |s| mutate_syn(s.step("mods"), 0, 4, |f| f[22] = 64),
        FAIL,
        "every SYN has TTL 42",
    );
    // the default template, none of the options
    breaks(
        "sc04_packet_mods_and_pcap",
        |s| {
            let plain = plan(&PlanSpec::single(PORTS, RATE, PORT0)).remove(0);
            let st = s.step("mods");
            let (fr, _) = link_frames(0, T0, &plain, 0.01, 0.0005);
            st.links = vec![fr];
        },
        FAIL,
        "MSS 1460, SACK-permitted and window scale 7",
    );
    // window scale 6 instead of 7
    breaks(
        "sc04_packet_mods_and_pcap",
        |s| {
            mutate_syn(s.step("mods"), 0, 0, |f| {
                let n = f.len();
                f[n - 4] = 6;
            });
        },
        FAIL,
        "MSS 1460, SACK-permitted and window scale 7",
    );
    // a corrupted TCP checksum on a SYN of the modified run
    breaks(
        "sc04_packet_mods_and_pcap",
        |s| {
            mutate_syn(s.step("mods"), 0, 2, |f| {
                let n = f.len();
                f[n - 1] ^= 0xff;
            });
        },
        FAIL,
        "IPv4 header checksum, TCP checksum and total length are valid",
    );
}

#[test]
fn sc04_badsum_must_break_only_the_l4_checksum_and_draw_no_reply() {
    // the run sent valid SYNs (the flag did nothing)
    let r = breaks(
        "sc04_packet_mods_and_pcap",
        |s| {
            let ok = plan(&PlanSpec::single(PORTS, RATE, PORT1)).remove(0);
            let st = s.step("badsum");
            let (fr, _) = link_frames(0, T0 + 100.0, &ok, 0.01, 0.0005);
            st.links = vec![fr];
        },
        FAIL,
        "TCP checksum is invalid while its IPv4 header checksum is valid",
    );
    assert_eq!(check(&r, "the peer answered none")["result"], FAIL);
    // the IPv4 header checksum broken too
    breaks(
        "sc04_packet_mods_and_pcap",
        |s| mutate_syn(s.step("badsum"), 0, 1, |f| f[24] ^= 0xff),
        FAIL,
        "TCP checksum is invalid while its IPv4 header checksum is valid",
    );
    // a TTL of 42 leaks into the badsum run
    breaks(
        "sc04_packet_mods_and_pcap",
        |s| mutate_syn(s.step("badsum"), 0, 1, |f| f[22] = 42),
        FAIL,
        "default TTL 255",
    );
    // the scan found records although its probes were dropped
    breaks(
        "sc04_packet_mods_and_pcap",
        |s| {
            s.step("badsum").files = vec![(
                "output.txt".into(),
                b"#masscan\nopen tcp 80 198.18.0.2 1\n# end\n".to_vec(),
            )];
        },
        FAIL,
        "the output holds no record",
    );
}

#[test]
fn sc04_the_scanners_pcap_has_a_format_and_a_filter() {
    let pcap_file = |s: &mut Sim, f: &dyn Fn(Vec<u8>) -> Vec<u8>| {
        let st = s.step("mods");
        let (_, b) = st
            .files
            .iter_mut()
            .find(|(n, _)| n == SCANNER_PCAP)
            .unwrap();
        *b = f(std::mem::take(b));
    };
    // big-endian header, a record with different lengths, a cut record, a trailing byte
    breaks(
        "sc04_packet_mods_and_pcap",
        |s| {
            pcap_file(s, &|mut b| {
                b[..4].copy_from_slice(&[0xa1, 0xb2, 0xc3, 0xd4]);
                b
            })
        },
        FAIL,
        "is a classic pcap",
    );
    breaks(
        "sc04_packet_mods_and_pcap",
        |s| {
            pcap_file(s, &|mut b| {
                b[24 + 12] ^= 1;
                b
            })
        },
        FAIL,
        "is a classic pcap",
    );
    breaks(
        "sc04_packet_mods_and_pcap",
        |s| {
            pcap_file(s, &|mut b| {
                b.pop();
                b
            })
        },
        FAIL,
        "is a classic pcap",
    );
    breaks(
        "sc04_packet_mods_and_pcap",
        |s| {
            pcap_file(s, &|mut b| {
                b.push(0);
                b
            })
        },
        FAIL,
        "is a classic pcap",
    );
    // the filter: an outgoing SYN, an ARP request, a frame to another port
    for extra in [
        syn_for_pcap(),
        crate::autodetect_verify::tests::arp_request(&link_stand(0), link_stand(0).peer_ips[0]),
        reply_to_other_port(),
    ] {
        let r = breaks(
            "sc04_packet_mods_and_pcap",
            |s| {
                let st = s.step("mods");
                let mut frames = scanner_pcap_frames(
                    &st.files.iter().find(|(n, _)| n == SCANNER_PCAP).unwrap().1,
                )
                .unwrap();
                frames.push(extra.clone());
                st.files
                    .iter_mut()
                    .find(|(n, _)| n == SCANNER_PCAP)
                    .unwrap()
                    .1 = scanner_pcap_bytes(&frames);
            },
            FAIL,
            "holds only frames to the scanner's ip:port",
        );
        assert_eq!(check(&r, "is a classic pcap")["result"], PASS);
    }
    // a frame no peer sent, and a reply the file lacks
    breaks(
        "sc04_packet_mods_and_pcap",
        |s| {
            let st = s.step("mods");
            let mut frames =
                scanner_pcap_frames(&st.files.iter().find(|(n, _)| n == SCANNER_PCAP).unwrap().1)
                    .unwrap();
            frames[0][50] ^= 1;
            st.files
                .iter_mut()
                .find(|(n, _)| n == SCANNER_PCAP)
                .unwrap()
                .1 = scanner_pcap_bytes(&frames);
        },
        FAIL,
        "every frame of scanner.pcap is a frame the peer sent",
    );
    breaks(
        "sc04_packet_mods_and_pcap",
        |s| {
            let st = s.step("mods");
            let frames: Vec<Vec<u8>> =
                scanner_pcap_frames(&st.files.iter().find(|(n, _)| n == SCANNER_PCAP).unwrap().1)
                    .unwrap()
                    .into_iter()
                    .filter(|f| tcp(f).unwrap().flags & 0x12 != 0x12)
                    .collect();
            st.files
                .iter_mut()
                .find(|(n, _)| n == SCANNER_PCAP)
                .unwrap()
                .1 = scanner_pcap_bytes(&frames);
        },
        FAIL,
        "holds a SYN-ACK or RST from every peer address and port that answered",
    );
    // no pcap file at all
    let mut sim = Sim::new("sc04_packet_mods_and_pcap");
    sim.step("mods").files.retain(|(n, _)| n != SCANNER_PCAP);
    assert_verdict(&judge(&sim), NOT_RUN);
}
fn syn_for_pcap() -> Vec<u8> {
    plan(&PlanSpec::single(PORTS, RATE, PORT0))
        .remove(0)
        .remove(0)
}
fn reply_to_other_port() -> Vec<u8> {
    let st = link_stand(0);
    let mut f = tcp_answer(&syn_for_pcap(), 0x12, st.peer_mac, false);
    f[36] ^= 1;
    f
}
#[test]
fn sc04_scanner_pcap_parse_is_strict() {
    let f = vec![0u8; 60];
    let b = scanner_pcap_bytes(&[f.clone(), f.clone()]);
    assert_eq!(scanner_pcap_frames(&b).unwrap().len(), 2);
    assert_eq!(scanner_pcap_frames(&PCAP_HEADER).unwrap().len(), 0);
    assert!(scanner_pcap_frames(&[]).is_err());
    let big = scanner_pcap_bytes(&[vec![0u8; 1515]]);
    assert!(scanner_pcap_frames(&big).is_err());
    let ok = scanner_pcap_bytes(&[vec![0u8; 1514]]);
    assert!(scanner_pcap_frames(&ok).is_ok());
}

// ------------------------------------------------------------------ sc05

#[test]
fn sc05_passes_with_many_passes_an_infinite_status_and_no_paused_conf() {
    let r = judge(&Sim::new("sc05_infinite_interrupt"));
    assert_verdict(&r, PASS);
    assert_eq!(check(&r, "more than one full pass")["result"], PASS);
    // `Stopped` is as good as `Paused` for an infinite scan
    let mut sim = Sim::new("sc05_infinite_interrupt");
    let st = sim.step("run");
    st.stderr = st.stderr.replace("Paused", "Stopped");
    assert_verdict(&judge(&sim), PASS);
}

#[test]
fn sc05_one_pass_a_leftover_paused_conf_or_a_percentage_status_fails() {
    // only one pass
    let r = breaks(
        "sc05_infinite_interrupt",
        |s| {
            let one = plan(&PlanSpec::single(PORTS, RATE, PORT0)).remove(0);
            let st = s.step("run");
            let (fr, recs) = link_frames_until(0, T0, &one, 0.01, 0.0005, 4.0);
            st.links = vec![fr];
            st.interrupt.as_mut().unwrap().signal_unix = Some(T0 + 1.0);
            st.stderr = st.stderr.replace(
                &finished("Paused", 197, &dedup(&recs)),
                &finished("Paused", 12, &dedup(&recs)),
            );
        },
        FAIL,
        "more than one full pass",
    );
    let _ = r;
    // a paused.conf was written
    breaks(
        "sc05_infinite_interrupt",
        |s| {
            let st = s.step("run");
            st.interrupt.as_mut().unwrap().paused_conf_present = true;
            st.files
                .push((PAUSED_EVIDENCE.into(), conf(3, PORT0, "").into_bytes()));
        },
        FAIL,
        "no paused.conf was left",
    );
    // the status line is the percentage form
    breaks(
        "sc05_infinite_interrupt",
        |s| {
            let st = s.step("run");
            let f = status_fragments();
            st.stderr = st.stderr.replace(
                "rate:  0.10-kpps, syn/s=100 ack/s=5 tcb-rate=0, 0-tcbs,         \r",
                &f[0],
            );
        },
        FAIL,
        "the status line is the infinite form",
    );
    // a pass that repeats a probe and misses another
    breaks(
        "sc05_infinite_interrupt",
        |s| {
            let st = s.step("run");
            let a = syn_idx(st, 0)[14];
            let b = syn_idx(st, 0)[15];
            let copy = st.links[0][a].1.clone();
            st.links[0][b].1 = copy;
        },
        FAIL,
        "every full pass of the SYN stream is a permutation",
    );
    // the first pass is not the plan
    breaks(
        "sc05_infinite_interrupt",
        |s| {
            let st = s.step("run");
            let (a, b) = (syn_idx(st, 0)[0], syn_idx(st, 0)[1]);
            let fa = st.links[0][a].1.clone();
            st.links[0][a].1 = st.links[0][b].1.clone();
            st.links[0][b].1 = fa;
        },
        FAIL,
        "the first pass is the plan's",
    );
    // a scan that does not exit on SIGINT, a non-zero exit
    breaks(
        "sc05_infinite_interrupt",
        |s| s.step("run").interrupt.as_mut().unwrap().killed = true,
        FAIL,
        "no SIGKILL",
    );
    breaks(
        "sc05_infinite_interrupt",
        |s| s.step("run").exit = 1,
        FAIL,
        "exit.txt is 0",
    );
    // the interrupt came after the scan had ended: the scan did not run
    breaks(
        "sc05_infinite_interrupt",
        |s| s.step("run").interrupt.as_mut().unwrap().signal_unix = None,
        FAIL,
        "still scanning when SIGINT came",
    );
}

// ------------------------------------------------------------------ sc06

#[test]
fn sc06_passes_with_a_partition_over_two_links_and_bounded_duplicates_on_resume() {
    let r = judge(&Sim::new("sc06_dual_veth"));
    assert_verdict(&r, PASS);
    assert_eq!(
        check(&r, "bounded duplicates: no probe was sent more than twice")["result"],
        PASS
    );
    // the pause is deliberately uneven: adapter 1 resends 3 probes, so the multiset is NOT exact and still passes
    assert_eq!(r["notes"]["resent_probes"], 3);
}

#[test]
fn sc06_an_exact_multiset_resume_passes_too_and_needs_no_duplicate() {
    // adapter 0 and 1 stopped at the same base: nothing is resent
    let mut sim = Sim::new("sc06_dual_veth");
    let q = {
        let mut p = PlanSpec::single(PAUSE_PORTS, PAUSE_RATE, PORT0);
        p.nics.push(NicPlan {
            link: 1,
            port: PORT1,
        });
        plan(&p)
    };
    let (a0, a1) = (15usize, 15usize);
    let st = sim.step("dual_pause");
    let (f0, r0) = link_frames_until(0, T0 + 100.0, &q[0][..a0], 0.1, 0.0005, HOLD);
    let (f1, r1) = link_frames_until(1, T0 + 100.0, &q[1][..a1], 0.1, 0.0005, HOLD);
    st.links = vec![f0, f1];
    let out1 = dedup(&r0.into_iter().chain(r1).collect::<Vec<_>>());
    st.stderr = paused_stderr(&dual_stderr(PORT0, PORT1, "time"), a0 + a1, &out1);
    let doc1 = doc(Format::Json, &out1, T0 + 100.0);
    st.files = vec![
        ("output.json".into(), doc1.clone()),
        (
            PAUSED_EVIDENCE.into(),
            conf(
                30,
                PORT0,
                "adapter[1] = veth-a2\nadapter-ip[1] = 198.18.0.6\n",
            )
            .into_bytes(),
        ),
    ];
    let mut p = PlanSpec::single(PAUSE_PORTS, PAUSE_RATE, PORT0);
    p.nics.push(NicPlan {
        link: 1,
        port: PORT1,
    });
    p.resume_index = 30;
    let r = plan(&p);
    let rs = sim.step("dual_resume");
    let (g0, s0) = link_frames(0, T0 + 200.0, &r[0], 0.01, 0.0005);
    let (g1, s1) = link_frames(1, T0 + 200.0, &r[1], 0.01, 0.0005);
    rs.links = vec![g0, g1];
    let out2 = dedup(&s0.into_iter().chain(s1).collect::<Vec<_>>());
    rs.stderr = complete_stderr(
        &dual_stderr(PORT0, PORT1, "given"),
        r[0].len() + r[1].len(),
        &out2,
    );
    let mut whole = doc1;
    whole.extend(doc(Format::Json, &out2, T0 + 200.0));
    rs.files = vec![("output.json".into(), whole)];
    let res = judge(&sim);
    assert_verdict(&res, PASS);
    assert_eq!(res["notes"]["resent_probes"], 0);
}

#[test]
fn sc06_one_link_idle_or_a_wrong_partition_fails() {
    // adapter 1 carried nothing
    let r = breaks(
        "sc06_dual_veth",
        |s| {
            let st = s.step("dual");
            let (fr, _) = link_frames(1, T0, &[], 0.01, 0.0005);
            st.links[1] = fr;
        },
        FAIL,
        "both adapters carried probes",
    );
    assert_eq!(check(&r, "all 12 probes exactly once")["result"], FAIL);
    // the adapters swapped their probes: no longer the even/odd split of the plan
    breaks(
        "sc06_dual_veth",
        |s| {
            let st = s.step("dual");
            let (a, b) = (syn_idx(st, 0)[0], syn_idx(st, 0)[1]);
            let (fa, fb) = (st.links[0][a].1.clone(), st.links[0][b].1.clone());
            st.links[0][a].1 = fb;
            st.links[0][b].1 = fa;
        },
        FAIL,
        "link 0: the scanner SYNs equal the plan of --adapter[0]",
    );
    // a probe on both links
    breaks(
        "sc06_dual_veth",
        |s| {
            let st = s.step("dual");
            let a = syn_idx(st, 0)[0];
            let b = syn_idx(st, 1)[0];
            st.links[1][b].1 = st.links[0][a].1.clone();
        },
        FAIL,
        "all 12 probes exactly once",
    );
    // the answers of the second link did not come back on it
    breaks(
        "sc06_dual_veth",
        |s| {
            let st = s.step("dual");
            let keep: Vec<usize> = syn_idx(st, 1);
            for i in keep.into_iter().rev() {
                st.links[1].remove(i + 1);
            }
        },
        FAIL,
        "replies to the second adapter's SYNs came back on the second link",
    );
}

#[test]
fn sc06_a_resume_that_loses_a_probe_or_sends_one_three_times_fails() {
    // adapter 0's resume stream loses its first probe
    let r = breaks(
        "sc06_dual_veth",
        |s| drop_syn(s.step("dual_resume"), 0, 0),
        FAIL,
        "no loss: every probe of the scan was sent",
    );
    assert_eq!(
        check(&r, "link 0: the scanner SYNs equal the plan of the resume")["result"],
        FAIL
    );
    // a probe sent a third time: the first run's probe resent twice more by the second run
    breaks(
        "sc06_dual_veth",
        |s| {
            let mut p = PlanSpec::single(PAUSE_PORTS, PAUSE_RATE, PORT0);
            p.nics.push(NicPlan {
                link: 1,
                port: PORT1,
            });
            let full = plan(&p);
            // the resume restarts adapter 1 at its very beginning; and resumes the pause's probes of adapter 0 twice
            let st = s.step("dual_resume");
            let mut again = full[1].clone();
            again.extend(full[1][..4].iter().cloned());
            let (fr, _) = link_frames(1, T0 + 200.0, &again, 0.01, 0.0005);
            st.links[1] = fr;
        },
        FAIL,
        "bounded duplicates: no probe was sent more than twice",
    );
    // resume-index is not the minimum of the adapters' bases
    breaks(
        "sc06_dual_veth",
        |s| {
            edit_text(s.step("dual_pause"), PAUSED_EVIDENCE, |t| {
                t.replace("resume-index = 28", "resume-index = 34")
            });
        },
        FAIL,
        "resume-index is the minimum of the adapters' bases",
    );
    // the conf forgets the second adapter
    breaks(
        "sc06_dual_veth",
        |s| {
            edit_text(s.step("dual_pause"), PAUSED_EVIDENCE, |t| {
                t.replace("adapter[1] = veth-a2\n", "")
            });
        },
        FAIL,
        "paused.conf names both adapters",
    );
}

#[test]
fn sc06_findings_lost_across_the_two_documents_fail_but_resent_ones_may_repeat() {
    breaks(
        "sc06_dual_veth",
        |s| {
            edit_text(s.step("dual_resume"), "output.json", |t| {
                // drop the last record of the appended document
                let at = t.rfind(",\n").unwrap();
                format!("{}]\n", &t[..at])
            });
        },
        FAIL,
        "no loss: the two documents together hold",
    );
    breaks(
        "sc06_dual_veth",
        |s| {
            let st = s.step("dual_resume");
            let (_, b) = st
                .files
                .iter_mut()
                .find(|(n, _)| n == "output.json")
                .unwrap();
            let at = b.windows(4).position(|w| w == b"]\n[\n").unwrap() + 2;
            b.drain(..at);
        },
        FAIL,
        "output-append",
    );
    // a record three times across the documents
    breaks(
        "sc06_dual_veth",
        |s| {
            let st = s.step("dual_resume");
            edit_text(st, "output.json", |t| {
                let parts: Vec<&str> = t.splitn(2, "]\n[\n").collect();
                let rec = parts[0].lines().nth(1).unwrap().to_owned();
                format!("{}]\n[\n{rec}\n,\n{rec}\n,\n{}", parts[0], parts[1])
            });
        },
        FAIL,
        "no record is in the two documents more than twice",
    );
}

#[test]
fn sc06_the_detection_lines_must_name_both_adapters() {
    for (from, to) in [
        (
            "[+] interface[1] = veth-a2 (given)\n",
            "[+] interface[1] = veth-a (given)\n",
        ),
        (
            "[+] source-ip[1] = 198.18.0.6 (given)\n",
            "[+] source-ip[1] = 198.18.0.7 (given)\n",
        ),
        ("[+] router-mac[1] = 02-aa-00-00-00-04 (given)\n", ""),
    ] {
        let r = judge(&{
            let mut sim = Sim::new("sc06_dual_veth");
            let st = sim.step("dual");
            st.stderr = st.stderr.replace(from, to);
            sim
        });
        assert!(
            r["verdict"] == FAIL || r["verdict"] == INVALID,
            "{from}: {:#?}",
            bad(&r)
        );
        assert!(
            array(&r["checks"]).iter().any(|c| c["result"] != PASS
                && c["name"]
                    .as_str()
                    .unwrap()
                    .contains("[+] lines are the stand's")),
            "{from}"
        );
    }
}

// ------------------------------------------------------------------ the directory

#[test]
fn a_manifest_of_another_plan_or_a_missing_case_is_not_run() {
    let root = scratch();
    Sim::new("sc03_retries").write(&root);
    fs::write(
        root.join(MANIFEST_JSON),
        json!({"output": "linux"}).to_string(),
    )
    .unwrap();
    let res = verify_dir(&root);
    assert_ne!(res["overall"], PASS);
    assert_eq!(run_of(&res, "manifest")["verdict"], NOT_RUN);
    fs::write(
        root.join(MANIFEST_JSON),
        json!({"scan-control": "linux", "lab_id": LAB_ID}).to_string(),
    )
    .unwrap();
    let res = verify_dir(&root);
    assert_eq!(run_of(&res, "sc01_shards_union")["verdict"], NOT_RUN);
    assert_eq!(run_of(&res, "sc03_retries")["verdict"], PASS);
    assert_ne!(res["overall"], PASS);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_aborted_attempt_or_a_foreign_directory_makes_the_case_invalid() {
    let root = scratch();
    for tag in planned_tags() {
        Sim::new(tag).write(&root);
    }
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    fs::create_dir_all(root.join("runs_aborted/sc03_retries.42")).unwrap();
    fs::write(root.join("runs_aborted/sc03_retries.42/stderr.txt"), "x").unwrap();
    fs::create_dir_all(root.join("runs/sc99_other")).unwrap();
    let res = verify_dir(&root);
    assert_ne!(res["overall"], PASS);
    let r = run_of(&res, "sc03_retries");
    assert_eq!(
        check(&r, "no aborted attempt of this case")["result"],
        INVALID
    );
    assert_eq!(
        check(
            &run_of(&res, "manifest"),
            "runs/ holds only the planned case directories"
        )["result"],
        INVALID
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_stray_second_link_capture_outside_the_cases_is_judged_against_the_second_stand() {
    let root = scratch();
    for tag in planned_tags() {
        Sim::new(tag).write(&root);
    }
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    // an aborted attempt holds a second-link capture with a SYN from the first link's address
    let d = root.join("runs_aborted/sc06_dual_veth.7/dual");
    fs::create_dir_all(&d).unwrap();
    let mut s = Sim::new("sc06_dual_veth");
    let st = s.step("dual");
    let syn = st.links[0][syn_idx(st, 0)[0]].1.clone();
    st.links[1].insert(2, (T0 + 0.01, syn));
    fs::write(d.join("peer2.pcap"), pcap::encode(&st.links[1])).unwrap();
    let res = verify_dir(&root);
    assert_eq!(res["overall"], FAIL, "{res:#}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_runner_command_reports_the_exit_codes() {
    let root = scratch();
    for tag in planned_tags() {
        Sim::new(tag).write(&root);
    }
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let dir = root.to_str().unwrap().to_owned();
    let go = |extra: &[&str]| {
        let mut a = argv(&["--dir", &dir]);
        a.extend(argv(extra));
        run(&a)
    };
    assert_eq!(go(&[]), Ok(0));
    let out = root.join("verdict-out.json");
    assert_eq!(go(&["--out", out.to_str().unwrap()]), Ok(0));
    assert!(out.is_file());
    // unproven evidence (a file that no longer matches its hash) is INVALID: exit 2
    fs::write(root.join("runs/sc03_retries/retries/peer.err"), "x").unwrap();
    assert_eq!(go(&[]), Ok(2));
    Sim::new("sc03_retries").write(&root);
    assert_eq!(go(&[]), Ok(0));
    // a proven misbehaviour is FAIL: exit 1
    let mut sim = Sim::new("sc04_packet_mods_and_pcap");
    mutate_syn(sim.step("mods"), 0, 2, |f| f[22] = 9);
    sim.write(&root);
    assert_eq!(go(&[]), Ok(1));
    assert_eq!(run(&argv(&["--help"])), Ok(0));
    assert!(run(&argv(&[])).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_split_of_the_conf_and_ports_helpers() {
    let c = conf_lines("a = 1\n# x\nb=2\nresume-index = 7\n");
    assert_eq!(conf_value(&c, "resume-index"), Some("7"));
    assert_eq!(conf_value(&c, "b"), None);
    assert_eq!(port_list("80,443,8080"), [80, 443, 8080]);
    assert_eq!(port_list("76-78"), [76, 77, 78]);
    assert_eq!(stand_keys(&port_list(PORTS)).len(), 12);
    assert_eq!(probe_pairs(&port_list(PAUSE_PORTS)).len(), 80);
    assert_eq!(link_stand(1).scanner_ip.to_string(), "198.18.0.6");
    assert_eq!(link_stand(0).scanner_ip.to_string(), "198.18.0.1");
}

#[test]
fn sc06_a_second_adapter_that_keeps_sending_after_sigint_fails() {
    // adapter 1 sends one more SYN 2.5 s after SIGINT (3.6 s after the start of the step)
    let r = breaks(
        "sc06_dual_veth",
        |s| {
            let st = s.step("dual_pause");
            let at = syn_idx(st, 1)[0];
            let syn = st.links[1][at].1.clone();
            let sig = st.interrupt.as_ref().unwrap().signal_unix.unwrap();
            st.links[1].insert(at + 1, (sig + 2.5, syn));
        },
        FAIL,
        "link 1: no SYN later than 1 s after SIGINT",
    );
    assert_eq!(
        check(&r, "no SYN later than 1 s after SIGINT")["result"],
        PASS
    );
    // the signal outside the second capture's window is unproven evidence
    breaks(
        "sc06_dual_veth",
        |s| {
            let st = s.step("dual_pause");
            st.interrupt.as_mut().unwrap().signal_unix = Some(T0 + 100.0 + 50.0);
        },
        INVALID,
        "link 1: SIGINT is inside the capture window",
    );
}

#[test]
fn a_frame_padded_past_its_ip_total_length_is_read_by_the_ip_length() {
    let mut p = PlanSpec::single(PORTS, RATE, PORT0);
    p.mods = Mods {
        ttl: Some(42),
        sackok: true,
        wscale: Some(7),
        ..Mods::default()
    };
    let mut f = plan(&p)[0][0].clone();
    f.extend([0u8; 6]);
    let i = syn_info(&f).unwrap();
    assert!(i.tcp_checksum_ok && i.ip_header_ok && i.length_ok, "{i:?}");
    // padding that is not zero, or a total length past the frame, is a finding
    let mut g = f.clone();
    *g.last_mut().unwrap() = 1;
    assert!(!syn_info(&g).unwrap().length_ok);
    f.truncate(f.len() - 6);
    f[17] = f[17].wrapping_add(4);
    assert!(!syn_info(&f).unwrap().length_ok);
}

#[test]
fn sc06_a_resent_probe_must_come_from_its_own_adapter_at_its_own_index() {
    // adapter 1's first probe of the resume is one that adapter 0 sent in the pause run: it is on the wrong link
    breaks(
        "sc06_dual_veth",
        |s| {
            let a = syn_idx(s.step("dual_pause"), 0)[0];
            let foreign = s.step("dual_pause").links[0][a].1.clone();
            let st = s.step("dual_resume");
            let b = syn_idx(st, 1)[0];
            st.links[1][b].1 = foreign;
        },
        FAIL,
        "a resent probe comes from the adapter's own stream",
    );
}
