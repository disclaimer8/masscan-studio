//! Synthetic, hermetic output-format evidence. The documents of every format are rendered here from records, in the
//! byte forms of the C reference (§1), not with the verifier's parsers; SYNs come from the scan plan (`ReadyPlan` +
//! `ProbeCursor`, the autodetect generator), peer answers and the stand's records from the autodetect tests. One rule
//! at a time is broken. Nothing touches a network or a real evidence directory.
use super::*;
use crate::{
    autodetect_verify::{
        self as av, HASHES, Stand,
        tests::{
            LAB_ID, Sim as AdSim, T0, TEARDOWN, arp_request, interrupt_line, linux_isolation,
            marker, plan_syns_at, status_fragments, syn_dst, tcp_answer,
        },
    },
    link::{END_PAYLOAD, START_PAYLOAD},
    windows_suite::nonce,
};
use rmasscan_core::arp::encode_reply;
use std::path::PathBuf;

/// rmasscan's source port (`(time)`) and the oracle's on the synthetic stand.
const RM_PORT: &str = "41234";
const ORACLE_PORT: &str = "61234";
/// The oracle runs 100 s after rmasscan (its own capture).
const ORACLE_AT: f64 = 100.0;
/// SYNs an interrupted scan sends before SIGINT (2 s at 20 pps).
const INTERRUPT_SYNS: usize = 40;

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-output-verify-{}", nonce()));
    fs::create_dir_all(&d).unwrap();
    d
}

/// One record as a scanner reports it.
#[derive(Clone, Debug)]
pub(crate) struct R {
    pub(crate) open: bool,
    pub(crate) ip: Ipv4Addr,
    pub(crate) port: u16,
    pub(crate) ts: u64,
    pub(crate) reason: u8,
    pub(crate) ttl: u8,
}
impl R {
    fn status(&self) -> &'static str {
        if self.open { "open" } else { "closed" }
    }
    fn reason_text(&self) -> &'static str {
        match self.reason {
            0x12 => "syn-ack",
            0x14 => "rst-ack",
            _ => "none",
        }
    }
    fn service(&self) -> &'static str {
        match self.port {
            80 => "http",
            443 => "https",
            8080 => "http-alt",
            _ => "unknown",
        }
    }
}

/// The C forms of `--readscan`'s and the scan's documents (reference §1), `start`/`end` the clock of header and
/// footer. No record: an empty file (the header is written lazily).
pub(crate) fn render(fmt: Format, recs: &[R], start: u64, end: u64) -> Vec<u8> {
    if recs.is_empty() {
        return Vec::new();
    }
    let mut o = String::new();
    let lines = |f: &dyn Fn(&R) -> String| recs.iter().map(f).collect::<Vec<_>>();
    match fmt {
        Format::List => {
            o.push_str("#masscan\n");
            for r in recs {
                o.push_str(&format!(
                    "{} tcp {} {} {}\n",
                    r.status(),
                    r.port,
                    r.ip,
                    r.ts
                ));
            }
            o.push_str("# end\n");
        }
        Format::Json => {
            o.push_str("[\n");
            o.push_str(&lines(&|r| format!("{{   \"ip\": \"{}\",   \"timestamp\": \"{}\", \"ports\": [ {{\"port\": {}, \"proto\": \"tcp\", \"status\": \"{}\", \"reason\": \"{}\", \"ttl\": {}}} ] }}\n", r.ip, r.ts, r.port, r.status(), r.reason_text(), r.ttl)).join(",\n"));
            o.push_str("]\n");
        }
        Format::Ndjson => {
            for r in recs {
                o.push_str(&format!("{{\"ip\":\"{}\",\"timestamp\":\"{}\",\"port\":{},\"proto\":\"tcp\",\"rec_type\":\"status\",\"data\":{{\"status\":\"{}\",\"reason\":\"{}\",\"ttl\":{}}}}}\n", r.ip, r.ts, r.port, r.status(), r.reason_text(), r.ttl));
            }
        }
        Format::Grepable => {
            o.push_str(&format!("# Masscan 1.3.9-integration scan initiated {}\n# Ports scanned: TCP(3;80-80,443-443,8080-8080) UDP(0;) SCTP(0;) PROTOCOLS(0;)\n", ctime(start)));
            for r in recs {
                o.push_str(&format!(
                    "Timestamp: {}\tHost: {} ()\tPorts: {}/{}/tcp//{}//\n",
                    r.ts,
                    r.ip,
                    r.port,
                    r.status(),
                    r.service()
                ));
            }
            o.push_str(&format!("# Masscan done at {}\n", ctime(end)));
        }
        Format::Xml => {
            o.push_str(&format!("<?xml version=\"1.0\"?>\r\n<!-- masscan v1.0 scan -->\r\n<nmaprun scanner=\"masscan\" start=\"{start}\" version=\"1.0-BETA\"  xmloutputversion=\"1.03\">\r\n<scaninfo type=\"syn\" protocol=\"tcp\" />\r\n"));
            for r in recs {
                o.push_str(&format!("<host endtime=\"{}\"><address addr=\"{}\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"{}\"><state state=\"{}\" reason=\"{}\" reason_ttl=\"{}\"/></port></ports></host>\r\n", r.ts, r.ip, r.port, r.status(), r.reason_text(), r.ttl));
            }
            let up = recs.iter().filter(|r| r.open).count();
            o.push_str(&format!("<runstats>\r\n<finished time=\"{end}\" timestr=\"2027-01-15 10:00:05\" elapsed=\"{}\" />\r\n<hosts up=\"{up}\" down=\"{}\" total=\"{}\" />\r\n</runstats>\r\n</nmaprun>\r\n", end - start, recs.len() - up, recs.len()));
        }
        Format::Binary => {
            let mut b = vec![0u8; 99];
            let head = format!("masscan/1.1\ns:{start}\n");
            b[..head.len()].copy_from_slice(head.as_bytes());
            for r in recs {
                b.extend([if r.open { 6 } else { 7 }, 13]);
                b.extend((r.ts as u32).to_be_bytes());
                b.extend(r.ip.octets());
                b.push(6);
                b.extend(r.port.to_be_bytes());
                b.extend([r.reason, r.ttl]);
            }
            let mut foot = vec![0u8; 99];
            foot[..11].copy_from_slice(b"masscan/1.1");
            b.extend(foot);
            return b;
        }
        Format::Hostonly => {
            for r in recs {
                o.push_str(&format!("{}\n", r.ip));
            }
        }
        Format::Unicornscan => {
            o.push_str("#masscan\n");
            for r in recs {
                o.push_str(&format!(
                    "TCP {}\t{:>16}[{:>5}]\t\tfrom {}  ttl {:<3}\n",
                    r.status(),
                    r.service(),
                    r.port,
                    r.ip,
                    r.ttl
                ));
            }
            o.push_str("# end\n");
        }
    }
    o.into_bytes()
}
/// `%c` of the C locale in GMT for the two clocks the generator uses (checked with `date -u -r`).
fn ctime(t: u64) -> String {
    let s = t - 1_800_000_000;
    format!(
        "Fri Jan 15 {:02}:{:02}:{:02} 2027",
        8 + s / 3600,
        s / 60 % 60,
        s % 60
    )
}

/// One scanner's side of a run: what it printed, its exit code, the output file it left, and the capture.
#[derive(Clone)]
pub(crate) struct Side {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: String,
    pub(crate) exit: i32,
    /// The file the scanner left in its working directory (name, bytes).
    pub(crate) file: Option<(String, Vec<u8>)>,
    pub(crate) pcap: Frames,
    /// The records of its document, in file order.
    pub(crate) recs: Vec<R>,
}

/// One simulated run directory; tests change fields before `write`. The suite's tests play its sides.
pub(crate) struct Sim {
    pub(crate) case: OutputCase,
    pub(crate) rm: Side,
    pub(crate) oracle: Option<Side>,
    pub(crate) interrupt: Option<InterruptRecord>,
    /// `o17_readscan`'s inputs (name, bytes).
    pub(crate) inputs: Vec<(String, Vec<u8>)>,
    pub(crate) extra: Vec<(String, Vec<u8>)>,
    pub(crate) omit: Vec<&'static str>,
}

fn st() -> Stand {
    av::stand(Plan::Linux)
}
fn ends(fr: &mut Frames, last: f64) {
    for k in 0..3 {
        fr.push((last + 1.0 + f64::from(k) * 0.05, marker(&st(), END_PAYLOAD)));
    }
}
/// The detection lines rmasscan prints on the stand before the output file opens (rmasscan-cli `live.rs`).
const DETECTION: &str = "[+] interface = veth-a (detected: route to 198.18.0.2)\n[+] source-mac = 02-aa-00-00-00-01 (detected)\n[+] source-ip = 198.18.0.1 (detected)\n[+] router-ip = 198.18.0.2 (interface default gateway)\n";
/// masscan's stderr of a scan: banner, status lines rewritten after `\r`, the erase.
const ORACLE_STDERR: &str = "Starting masscan 1.3.9-integration (http://bit.ly/14GZzcT) at 2027-01-15 08:01:40 GMT\nInitiating SYN Stealth Scan\nScanning 4 hosts [3 ports/host]\nrate:  0.00-kpps, 100.00% done, waiting 3-secs, found=8       \r                                                                             \r\n";

/// A scan of the stand from `t0` on: ARP, SYNs of the plan, the peer's answers (SYN-ACK on 80 and 8080, RST
/// otherwise) and the scanner kernel's RST, the records and what the scanner prints.
fn live_side(c: &OutputCase, t0: f64, sp: &str, oracle: bool) -> Side {
    let st = st();
    let mut fr: Frames = vec![(t0, marker(&st, START_PAYLOAD))];
    let router = st.peer_ips[0];
    fr.push((t0 + 0.5, arp_request(&st, router)));
    fr.push((
        t0 + 0.501,
        encode_reply(
            st.peer_mac,
            u32::from(router),
            st.scanner_mac,
            u32::from(st.scanner_ip),
        )
        .to_vec(),
    ));
    let mut syns = plan_syns_at(&st, TARGETS, c.ports(), sp, st.peer_mac, c.rate());
    let step = if c.kind == OutputKind::Interrupt {
        syns.truncate(INTERRUPT_SYNS);
        0.05
    } else {
        0.01
    };
    let start = t0 + 0.6;
    let mut all = Vec::new();
    for (i, s) in syns.iter().enumerate() {
        let t = start + i as f64 * step;
        fr.push((t, s.clone()));
        let (ip, port) = syn_dst(s);
        let open = st.open_ports.contains(&port);
        let reason = if open { 0x12 } else { 0x14 };
        fr.push((t + 0.0005, tcp_answer(s, reason, st.peer_mac, false)));
        if open {
            fr.push((t + 0.0007, tcp_answer(s, 0x04, st.peer_mac, true)));
        }
        all.push(R {
            open,
            ip,
            port,
            ts: (t + 0.0005) as u64,
            reason,
            ttl: 64,
        });
    }
    let last = start + (syns.len() - 1) as f64 * step + 0.001;
    ends(&mut fr, last);
    let recs: Vec<R> = all
        .iter()
        .filter(|r| r.open || c.show_closed)
        .cloned()
        .collect();
    let doc = render(c.format, &recs, t0 as u64, (last + 0.5) as u64);
    let open = all.iter().filter(|r| r.open).count();
    let stdout = match c.stdout() {
        StdoutForm::Silent => Vec::new(),
        StdoutForm::Document => doc.clone(),
        StdoutForm::Discovered => recs
            .iter()
            .filter(|r| r.open)
            .map(|r| av::discovered_line(r.ip, r.port))
            .collect::<String>()
            .into_bytes(),
        StdoutForm::Elapsed => b"3612 milliseconds elapsed\n".to_vec(),
    };
    let stderr = if oracle {
        ORACLE_STDERR.to_owned()
    } else {
        let mut e = format!(
            "{DETECTION}[+] router-mac = 02-aa-00-00-00-02 (arp: 1 requests, 1 ms)\n[+] seed = 1 (given)\n[+] source-port = {sp} (time)\n"
        );
        let frags = status_fragments();
        let stopped = c.kind == OutputKind::Interrupt;
        if c.status() == StatusForm::Text {
            e.push_str(&frags[0]);
            if stopped {
                e.push_str(&interrupt_line());
            }
            e.push_str(&frags[1..].concat());
        } else if stopped {
            e.push_str(&interrupt_line());
        }
        e.push_str(&format!(
            "[+] finished: {}, sent {}, replies {}, open {open}\n",
            if stopped { "Stopped" } else { "Completed" },
            syns.len(),
            all.len()
        ));
        e
    };
    Side {
        stdout,
        stderr,
        exit: 0,
        file: c.writes_file().then(|| (c.format.file().to_owned(), doc)),
        pcap: fr,
        recs,
    }
}
/// A side that sends nothing: markers only.
fn quiet(t0: f64) -> Frames {
    let mut fr: Frames = vec![(t0, marker(&st(), START_PAYLOAD))];
    ends(&mut fr, t0 + 0.3);
    fr
}

impl Sim {
    pub(crate) fn new(tag: &str) -> Sim {
        let c = case(tag).unwrap_or_else(|| panic!("{tag} is not an output case"));
        let mut inputs = Vec::new();
        let mut interrupt = None;
        let (rm, oracle) = match c.kind {
            OutputKind::Scan | OutputKind::Interrupt => {
                let rm = live_side(&c, T0, RM_PORT, false);
                if c.kind == OutputKind::Interrupt {
                    interrupt = Some(InterruptRecord {
                        signal: "INT".into(),
                        after_s: INTERRUPT_AFTER_S,
                        signal_unix: Some(T0 + 0.6 + INTERRUPT_SYNS as f64 * 0.05),
                        exit_within_s: INTERRUPT_EXIT_S,
                        killed: false,
                    });
                }
                let oracle = c
                    .oracle
                    .then(|| live_side(&c, T0 + ORACLE_AT, ORACLE_PORT, true));
                (rm, oracle)
            }
            OutputKind::OpenFailure => (
                Side {
                    stdout: Vec::new(),
                    stderr: format!(
                        "{DETECTION}{OPEN_FAILURE}\n{UNOPENABLE}: No such file or directory (os error 2)\n"
                    ),
                    exit: 1,
                    file: None,
                    pcap: quiet(T0),
                    recs: Vec::new(),
                },
                None,
            ),
            OutputKind::Readscan => {
                let b = Sim::new(BINARY_TAG);
                let o = b.oracle.unwrap();
                let recs: Vec<R> = b.rm.recs.iter().chain(&o.recs).cloned().collect();
                inputs = vec![
                    (READSCAN_INPUTS[0].to_owned(), b.rm.file.unwrap().1),
                    (READSCAN_INPUTS[1].to_owned(), o.file.unwrap().1),
                ];
                let side = |t0: f64| Side {
                    stdout: Vec::new(),
                    stderr: READSCAN_INPUTS
                        .iter()
                        .map(|n| format!("[+] --readscan {n}\n"))
                        .collect(),
                    exit: 0,
                    file: Some(("output.txt".into(), render(Format::List, &recs, 0, 0))),
                    pcap: quiet(t0),
                    recs: recs.clone(),
                };
                (side(T0), Some(side(T0 + ORACLE_AT)))
            }
        };
        Sim {
            case: c,
            rm,
            oracle,
            interrupt,
            inputs,
            extra: Vec::new(),
            omit: Vec::new(),
        }
    }

    fn side_files(
        s: &Side,
        dir: &str,
        pcap_name: &str,
        meta: &str,
        err: &str,
    ) -> Vec<(String, Vec<u8>)> {
        let p = |n: &str| format!("{dir}{n}");
        let mut f = vec![
            (p("stdout.txt"), s.stdout.clone()),
            (p("stderr.txt"), s.stderr.clone().into_bytes()),
            (p("exit.txt"), format!("{}\n", s.exit).into_bytes()),
            (pcap_name.into(), pcap::encode(&s.pcap)),
            (meta.into(), AdSim::witness(&s.pcap)),
            (
                err.into(),
                format!("tcpdump: listening on veth-b, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n{0} packets captured\n{0} packets received by filter\n0 packets dropped by kernel\n", s.pcap.len()).into_bytes(),
            ),
        ];
        if let Some((n, b)) = &s.file {
            f.push((p(n), b.clone()));
        }
        f
    }

    /// The run directory's files (relative path, bytes) before hashing.
    pub(crate) fn files(&self) -> Vec<(String, Vec<u8>)> {
        let c = &self.case;
        let mut f = vec![
            ("argv.json".to_owned(), json(&ArgvRecord { argv: c.argv() })),
            ("expect.json".to_owned(), json(&c.expect())),
            ("isolation.json".to_owned(), linux_isolation()),
            ("isolation-post.json".to_owned(), linux_isolation()),
        ];
        f.extend(Sim::side_files(
            &self.rm,
            "",
            PEER_PCAP,
            CAPTURE_JSON,
            "peer.err",
        ));
        if let Some(o) = &self.oracle {
            f.extend(Sim::side_files(
                o,
                "oracle/",
                ORACLE_PCAP,
                ORACLE_CAPTURE_JSON,
                "oracle.err",
            ));
        }
        if let Some(i) = &self.interrupt {
            f.push((INTERRUPT_JSON.into(), json(i)));
        }
        f.extend(self.inputs.iter().cloned());
        f.retain(|(n, _)| !self.omit.contains(&n.as_str()));
        f.extend(self.extra.iter().cloned());
        f
    }

    /// Writes `root/manifest.json` (if absent) and `root/runs/<tag>/` with its hashes; returns the run directory.
    pub(crate) fn write(&self, root: &Path) -> PathBuf {
        let man = root.join(MANIFEST_JSON);
        if !man.exists() {
            fs::write(
                &man,
                json!({"output": "linux", "lab_id": LAB_ID}).to_string(),
            )
            .unwrap();
        }
        let d = root.join("runs").join(self.case.tag);
        fs::create_dir_all(&d).unwrap();
        let mut files = self.files();
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let mut hashes = String::new();
        for (n, b) in &files {
            let p = d.join(n);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b).unwrap();
            hashes.push_str(&format!("{}  {n}\n", sha(b)));
        }
        if !self.omit.contains(&HASHES) {
            fs::write(d.join(HASHES), hashes).unwrap();
        }
        d
    }
}

/// A record of the run as the suite writes it (pretty JSON).
fn json<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec_pretty(v).unwrap()
}

/// Every planned run and the root's teardown record: a whole evidence directory.
pub(crate) fn write_plan(root: &Path) {
    for tag in planned_tags() {
        Sim::new(tag).write(root);
    }
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
}
fn run_of(res: &Value, tag: &str) -> Value {
    array(&res["runs"])
        .iter()
        .find(|r| r["tag"] == tag)
        .cloned()
        .unwrap_or_else(|| panic!("no run {tag} in {res}"))
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
/// The run summary of `sim` judged alone (the other planned tags are simply missing).
fn judge(sim: &Sim) -> Value {
    let root = scratch();
    sim.write(&root);
    if sim.case.kind == OutputKind::Readscan {
        // o17 reads o06's outputs: they are evidence of the directory.
        Sim::new(BINARY_TAG).write(&root);
    }
    let v = run_of(&verify_dir(&root), sim.case.tag);
    fs::remove_dir_all(root).unwrap();
    v
}
#[track_caller]
fn assert_verdict(run: &Value, want: &str) {
    assert_eq!(run["verdict"], want, "{} {:#?}", run["tag"], bad(run));
}
/// `sim`'s rmasscan document with `f` applied to its text.
fn edit_doc(sim: &mut Sim, f: impl Fn(&str) -> String) {
    let (_, b) = sim.rm.file.as_mut().unwrap();
    *b = f(&String::from_utf8(b.clone()).unwrap()).into_bytes();
}

// ------------------------------------------------------------------ the brief's tests

#[test]
fn a_consistent_run_is_pass() {
    let root = scratch();
    write_plan(&root);
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
fn record_mismatch_is_fail() {
    // rmasscan's JSON loses its last record: no longer the oracle's records, the stand's or the wire's.
    let mut sim = Sim::new("o02_json");
    edit_doc(&mut sim, |t| {
        let cut = t[..t.len() - 3].rfind(",\n").unwrap();
        format!("{}]\n", &t[..cut])
    });
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(
        check(&r, "equal the oracle's after masking")["result"],
        FAIL
    );
    assert_eq!(check(&r, "the stand's replies")["result"], FAIL);
    // A port changed in one list record is a mismatch too, while the document stays well formed.
    let mut sim = Sim::new("o01_list");
    edit_doc(&mut sim, |t| t.replacen(" tcp 443 ", " tcp 444 ", 1));
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "is a well-formed list document")["result"], PASS);
    assert_eq!(
        check(&r, "equal the oracle's after masking")["result"],
        FAIL
    );
    // Two scanners that agree only once their times are masked still pass: the times are not compared.
    let mut sim = Sim::new("o08_unicornscan");
    let o = sim.oracle.as_mut().unwrap();
    o.recs.reverse();
    let doc = render(Format::Unicornscan, &o.recs, 0, 0);
    o.file = Some(("output.txt".into(), doc));
    assert_verdict(&judge(&sim), PASS);
}

#[test]
fn missing_footer_after_interrupt_is_fail() {
    for (tag, cut) in [
        ("o14_interrupt_json", "]\n".len()),
        ("o15_interrupt_xml", "</nmaprun>\r\n".len()),
        ("o16_interrupt_binary", 99),
    ] {
        let good = Sim::new(tag);
        assert_verdict(&judge(&good), PASS);
        let mut sim = Sim::new(tag);
        let (_, b) = sim.rm.file.as_mut().unwrap();
        b.truncate(b.len() - cut);
        let r = judge(&sim);
        assert_verdict(&r, FAIL);
        assert_eq!(
            check(&r, "complete after the interrupt")["result"],
            FAIL,
            "{tag}"
        );
    }
}

#[test]
fn frames_on_open_failure_is_fail() {
    assert_verdict(&judge(&Sim::new("o13_open_fail")), PASS);
    // An ARP request, then a SYN: the output file was opened after the first frame, or not at all.
    let st = st();
    for frame in [
        arp_request(&st, st.peer_ips[0]),
        plan_syns_at(&st, TARGETS, PORTS, RM_PORT, st.peer_mac, RATE).remove(0),
    ] {
        let mut sim = Sim::new("o13_open_fail");
        sim.rm.pcap.insert(1, (T0 + 0.1, frame));
        let r = judge(&sim);
        assert_verdict(&r, FAIL);
        assert_eq!(check(&r, "no scanner frame")["result"], FAIL);
    }
    // The refusal must be the C text and exit 1.
    let mut sim = Sim::new("o13_open_fail");
    sim.rm.exit = 0;
    assert_verdict(&judge(&sim), FAIL);
    let mut sim = Sim::new("o13_open_fail");
    // The CLI's other mode (`--append-output`) is not this case's.
    sim.rm.stderr = sim
        .rm
        .stderr
        .replace(OPEN_FAILURE, "out: could not open file for appending");
    assert_verdict(&judge(&sim), FAIL);
}

#[test]
fn private_token_is_fail() {
    // A private token never passes: as in autodetect, evidence that cannot be published proves nothing (INVALID), in
    // the scanner's output files as well as its streams; a binary document is read record by record.
    let leak = |sim: &mut Sim| {
        edit_doc(sim, |t| {
            t.replacen("<scaninfo", "<!-- printer.lan --><scaninfo", 1)
        })
    };
    let mut sim = Sim::new("o05_xml");
    leak(&mut sim);
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(
        check(&r, "privacy: output.txt holds only")["result"],
        INVALID
    );
    let mut sim = Sim::new("o06_binary");
    let (_, b) = sim.rm.file.as_mut().unwrap();
    b[99 + 6..99 + 10].copy_from_slice(&[192, 168, 1, 20]);
    let r = judge(&sim);
    assert_ne!(r["verdict"], PASS);
    assert_eq!(
        check(&r, "privacy: output.bin holds only")["result"],
        INVALID
    );
    let mut sim = Sim::new("o01_list");
    sim.rm.stderr.push_str("[+] note = /home/alice/x (given)\n");
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(
        check(&r, "privacy: stderr.txt holds only")["result"],
        INVALID
    );
    let mut sim = Sim::new("o17_readscan");
    let o = sim.oracle.as_mut().unwrap();
    o.stderr.push_str("Owner-MacBook-Pro.local\n");
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(
        check(&r, "privacy: oracle/stderr.txt holds only")["result"],
        INVALID
    );
}

// ------------------------------------------------------------------ the other rules

#[test]
fn the_case_table_holds_the_briefs_cases() {
    let tags = planned_tags();
    assert_eq!(tags.len(), 17);
    assert_eq!(
        case("o01_list").unwrap().argv(),
        strs(&[
            "198.18.0.2-198.18.0.5",
            "-p80,443,8080",
            "-oL",
            "output.txt",
            "--show",
            "open,closed",
            "--seed",
            "1",
            "--rate",
            "100",
            "--wait",
            "3"
        ])
    );
    for (tag, letter) in [
        ("o01_list", 'L'),
        ("o02_json", 'J'),
        ("o03_ndjson", 'D'),
        ("o04_grepable", 'G'),
        ("o05_xml", 'X'),
        ("o06_binary", 'B'),
        ("o07_hostonly", 'H'),
        ("o08_unicornscan", 'U'),
    ] {
        let c = case(tag).unwrap();
        assert_eq!(c.format.letter(), letter);
        assert!(
            c.oracle && c.show_closed && c.kind == OutputKind::Scan,
            "{tag}"
        );
    }
    let flags = |tag: &str| case(tag).unwrap().argv()[2..].join(" ");
    assert_eq!(
        flags("o09_json_default_show"),
        "-oJ output.txt --seed 1 --rate 100 --wait 3"
    );
    assert_eq!(
        flags("o10_list_stdout"),
        "-oL - --seed 1 --rate 100 --wait 3"
    );
    assert_eq!(
        flags("o11_interactive"),
        "-oL output.txt --interactive --seed 1 --rate 100 --wait 3"
    );
    assert_eq!(
        flags("o12_nostatus"),
        "-oJ output.txt --nostatus --seed 1 --rate 100 --wait 3"
    );
    assert_eq!(
        flags("o13_open_fail"),
        "-oL /nonexistent-rmasscan-dir/x --seed 1 --rate 100 --wait 3"
    );
    for tag in [
        "o14_interrupt_json",
        "o15_interrupt_xml",
        "o16_interrupt_binary",
    ] {
        let c = case(tag).unwrap();
        assert_eq!(c.argv()[1], "-p1-1000");
        assert!(
            c.argv()
                .join(" ")
                .ends_with("--show open,closed --seed 1 --rate 20 --wait 3")
        );
        assert!(!c.oracle && c.kind == OutputKind::Interrupt);
    }
    assert_eq!(
        case("o17_readscan").unwrap().argv(),
        strs(&[
            "--readscan",
            "input-rmasscan.bin",
            "input-oracle.bin",
            "-oL",
            "output.txt",
            "--show",
            "open,closed"
        ])
    );
    assert!(case("o17_readscan").unwrap().oracle);
    for tag in ["o12_nostatus", "o13_open_fail"] {
        assert!(!case(tag).unwrap().oracle, "{tag}");
    }
    // Every address of every argv is the stand's.
    for c in cases() {
        assert!(
            crate::autodetect_suite::addresses_outside_the_lab(&c.argv()).is_empty(),
            "{}",
            c.tag
        );
    }
}
fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

#[test]
fn every_document_parses_back_into_its_records() {
    // The generator's documents of every format, as both scanners write them, round-trip through the parser; one
    // malformed byte in each is refused.
    for tag in planned_tags() {
        let sim = Sim::new(tag);
        let (fmt, Some((_, doc))) = (sim.case.format, sim.rm.file.clone()) else {
            continue;
        };
        let d = parse_doc(fmt, &doc).unwrap_or_else(|e| panic!("{tag}: {e}"));
        assert_eq!(d.records.len(), sim.rm.recs.len(), "{tag}");
        assert!(d.complete, "{tag}");
        for (got, r) in d.records.iter().zip(&sim.rm.recs) {
            assert_eq!(got.ip, r.ip, "{tag}");
            if fmt != Format::Hostonly {
                assert_eq!(got.port, Some(r.port), "{tag}");
                assert_eq!(
                    got.status,
                    Some(if r.open { Status::Open } else { Status::Closed })
                );
            }
            if !matches!(fmt, Format::Hostonly | Format::Unicornscan) {
                assert_eq!(got.ts, Some(r.ts), "{tag}");
            }
        }
    }
    let list = render(Format::List, &Sim::new("o01_list").rm.recs, 0, 0);
    let text = String::from_utf8(list).unwrap();
    for bad in [
        text.replacen("open tcp", "open  tcp", 1),
        text.replacen("#masscan\n", "", 1),
        text.replacen(" 1800000000\n", " 01800000000\n", 1),
        text.replacen("198.18.0.", "198.018.0.", 1),
        text.trim_end_matches('\n').to_owned(),
    ] {
        assert!(parse_doc(Format::List, bad.as_bytes()).is_err(), "{bad:?}");
    }
    let json =
        String::from_utf8(render(Format::Json, &Sim::new("o02_json").rm.recs, 0, 0)).unwrap();
    for bad in [
        json.replacen("\n,\n", "\n", 1),
        json.replacen("\"reason\": \"syn-ack\"", "\"reason\": \"ack-syn\"", 1),
        json.replacen("{   \"ip\"", "{  \"ip\"", 1),
    ] {
        assert!(parse_doc(Format::Json, bad.as_bytes()).is_err(), "{bad:?}");
    }
    // An unterminated JSON parses, but is not complete.
    let open = parse_doc(Format::Json, json.trim_end_matches("]\n").as_bytes()).unwrap();
    assert!(!open.complete);
    // The binary layout: 99 + 15 n + 99 bytes, the footer `masscan/1.1` and zeros.
    let bin = render(
        Format::Binary,
        &Sim::new("o06_binary").rm.recs,
        1_800_000_000,
        0,
    );
    assert_eq!(bin.len(), 99 + 15 * 12 + 99);
    let mut odd = bin.clone();
    odd.insert(99, 0);
    assert!(parse_doc(Format::Binary, &odd).is_err());
    // The C locale's `%c` pads a one-digit day with a space.
    assert_eq!(c_time("Sat Nov  7 08:00:00 2026"), Some(1_794_038_400));
    assert_eq!(c_time("Sat Nov 07 08:00:00 2026"), None);
    assert_eq!(c_time("Fri Nov  7 08:00:00 2026"), None);
}

#[test]
fn status_lines_follow_the_case() {
    // Text mode: the erase must stand right before `[+] finished`.
    let mut sim = Sim::new("o01_list");
    sim.rm.stderr = sim.rm.stderr.replace(&format!("{}\r", " ".repeat(77)), "");
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "77-space erase")["result"], FAIL);
    // `--nostatus`: no status fragment at all.
    let mut sim = Sim::new("o12_nostatus");
    sim.rm.stderr = sim.rm.stderr.replace(
        "[+] finished",
        &format!("{}[+] finished", status_fragments().concat()),
    );
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "no status line")["result"], FAIL);
    // A fragment the CLI never prints breaks the grammar.
    let mut sim = Sim::new("o03_ndjson");
    sim.rm.stderr = sim.rm.stderr.replace("found=0       \r", "found=0 \r");
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "status line grammar")["result"], FAIL);
}

#[test]
fn stdout_follows_the_case() {
    // A file format silences stdout.
    let mut sim = Sim::new("o04_grepable");
    sim.rm.stdout = av::discovered_line(Ipv4Addr::new(198, 18, 0, 2), 80).into_bytes();
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "stdout.txt is empty")["result"], FAIL);
    // `-oL -` writes the list, never a Discovered line.
    let mut sim = Sim::new("o10_list_stdout");
    sim.rm
        .stdout
        .extend(av::discovered_line(Ipv4Addr::new(198, 18, 0, 2), 80).into_bytes());
    assert_verdict(&judge(&sim), FAIL);
    // `--interactive` prints a Discovered line per open record.
    let mut sim = Sim::new("o11_interactive");
    let half = sim.rm.stdout.len() / 2;
    sim.rm.stdout.truncate(half - half % 80);
    assert_verdict(&judge(&sim), FAIL);
    // `--nostatus` prints the elapsed time.
    let mut sim = Sim::new("o12_nostatus");
    sim.rm.stdout = b"3612 ms\n".to_vec();
    assert_verdict(&judge(&sim), FAIL);
}

#[test]
fn sent_must_equal_the_syns_on_the_wire() {
    let mut sim = Sim::new("o07_hostonly");
    sim.rm.stderr = sim.rm.stderr.replace("sent 12,", "sent 13,");
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "sent equal to the scanner SYNs")["result"], FAIL);
}

#[test]
fn an_interrupt_must_stop_the_scan() {
    // Killed after the timeout: rmasscan did not stop on SIGINT.
    let mut sim = Sim::new("o14_interrupt_json");
    sim.interrupt.as_mut().unwrap().killed = true;
    assert_verdict(&judge(&sim), FAIL);
    // Finished as completed, or without the Ctrl-C line.
    let mut sim = Sim::new("o15_interrupt_xml");
    sim.rm.stderr = sim
        .rm
        .stderr
        .replace("finished: Stopped", "finished: Completed");
    assert_verdict(&judge(&sim), FAIL);
    let mut sim = Sim::new("o16_interrupt_binary");
    sim.rm.stderr = sim.rm.stderr.replace(&interrupt_line(), "");
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "the Ctrl-C line once")["result"], FAIL);
    // A SYN long after the signal: the scan went on.
    let mut sim = Sim::new("o14_interrupt_json");
    let st = st();
    let late = plan_syns_at(
        &st,
        TARGETS,
        INTERRUPT_PORTS,
        RM_PORT,
        st.peer_mac,
        INTERRUPT_RATE,
    )[INTERRUPT_SYNS]
        .clone();
    let at = sim.interrupt.as_ref().unwrap().signal_unix.unwrap() + 1.5;
    // Inside the capture window: its end markers come after the late SYN.
    sim.rm.pcap.retain(|(_, f)| !av::is_marker(f, END_PAYLOAD));
    sim.rm.pcap.push((at, late));
    ends(&mut sim.rm.pcap, at);
    sim.rm.pcap.sort_by(|a, b| a.0.total_cmp(&b.0));
    sim.rm.stderr = sim.rm.stderr.replace("sent 40,", "sent 41,");
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "no SYN later than")["result"], FAIL);
    // No interrupt record: the signal is unproven.
    let mut sim = Sim::new("o14_interrupt_json");
    sim.interrupt = None;
    assert_verdict(&judge(&sim), NOT_RUN);
}

#[test]
fn readscan_reads_o06s_outputs_and_both_scanners_agree() {
    assert_verdict(&judge(&Sim::new("o17_readscan")), PASS);
    // Inputs that are not o06's outputs prove nothing.
    let mut sim = Sim::new("o17_readscan");
    let first = sim.inputs[0].1.clone();
    sim.inputs[0].1 = sim.inputs[1].1.clone();
    sim.inputs[1].1 = first;
    assert_verdict(&judge(&sim), INVALID);
    // rmasscan's list differs from the oracle's (and from the inputs) by one record.
    let mut sim = Sim::new("o17_readscan");
    edit_doc(&mut sim, |t| {
        t.replacen("closed tcp 443", "open tcp 443", 1)
    });
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "byte for byte the oracle's")["result"], FAIL);
    // Without o06 in the directory the inputs are unproven.
    let root = scratch();
    Sim::new("o17_readscan").write(&root);
    let r = run_of(&verify_dir(&root), "o17_readscan");
    assert_verdict(&r, INVALID);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_record_times_lie_in_the_capture_window() {
    let mut sim = Sim::new("o03_ndjson");
    edit_doc(&mut sim, |t| {
        t.replacen(
            "\"timestamp\":\"1800000000\"",
            "\"timestamp\":\"1700000000\"",
            1,
        )
    });
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "times lie in the capture window")["result"], FAIL);
}

#[test]
fn verdict_never_upgrades() {
    // A missing case keeps the directory NOT RUN; a missing hash file is INVALID, never PASS.
    let root = scratch();
    write_plan(&root);
    fs::remove_dir_all(root.join("runs/o09_json_default_show")).unwrap();
    let res = verify_dir(&root);
    assert_eq!(res["overall"], NOT_RUN);
    fs::remove_dir_all(root).unwrap();
    let mut sim = Sim::new("o01_list");
    sim.omit.push(HASHES);
    assert_verdict(&judge(&sim), INVALID);
    // The table, not the run's own expect.json, decides.
    let mut sim = Sim::new("o01_list");
    let mut x = sim.case.expect();
    x.show_closed = false;
    sim.extra
        .push(("expect.json".into(), serde_json::to_vec_pretty(&x).unwrap()));
    sim.omit.push("expect.json");
    assert_verdict(&judge(&sim), INVALID);
}
