//! Synthetic, hermetic banners evidence. The probes come from the scan plan (`ReadyPlan` + its cursor, the product's
//! own plan); the stand's answers are the table's scenario replies ([`scenario_reply`]); the documents are built here
//! by hand in the byte forms of the C reference (status records, `-oB` type 9 banner records with their one- or
//! two-byte length, `-oL` `banner` lines), never with the verifier's parsers. The banner payloads are what the
//! product's UDP parsers make of each reply (`rmasscan_proto::handle_udp`); C's raw banner on the ports where it reads
//! past the datagram is other bytes of the same length, as on the wire. One rule at a time is broken. Nothing touches a
//! network or a real evidence directory.
use super::*;
use crate::{
    autodetect_verify::{
        HASHES, MANIFEST_JSON, TEARDOWN_JSON,
        tests::{LAB_ID, Sim as AdSim, T0, TEARDOWN, marker, status_fragments},
    },
    ipv6_verify::tests::ipv6_isolation,
    link::{END_PAYLOAD, START_PAYLOAD},
    pcap,
    protocols_verify::{
        ResponderRecord,
        tests::{bad, erased, has, ip_frame, run_of},
    },
    verify::{FAIL, INVALID, PASS},
    windows_suite::nonce,
};
use rmasscan_proto::{UdpContext, handle_udp, normalize_string};
use serde_json::json;
use std::{fs, path::PathBuf};

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-banners-verify-{}", nonce()));
    fs::create_dir_all(&d).unwrap();
    d
}

// ------------------------------------------------------------------ frames by hand

const SCANNER_MAC: [u8; 6] = [2, 0xaa, 0, 0, 0, 1];
const PEER_MAC: [u8; 6] = [2, 0xaa, 0, 0, 0, 2];
const SCANNER_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const TTL: u8 = 64;

fn probe_peer(p: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(p[30], p[31], p[32], p[33])
}
fn probe_ports(p: &[u8]) -> (u16, u16) {
    (
        u16::from_be_bytes([p[34], p[35]]),
        u16::from_be_bytes([p[36], p[37]]),
    )
}
fn probe_payload(p: &[u8]) -> &[u8] {
    &p[42..]
}
/// The peer's UDP datagram carrying `payload` back to the probe's source.
fn udp_back(p: &[u8], payload: &[u8]) -> Vec<u8> {
    let (sp, dp) = probe_ports(p);
    let mut u = Vec::new();
    u.extend(dp.to_be_bytes());
    u.extend(sp.to_be_bytes());
    u.extend(((8 + payload.len()) as u16).to_be_bytes());
    u.extend([0, 0]);
    u.extend(payload);
    ip_frame(SCANNER_MAC, PEER_MAC, probe_peer(p), SCANNER_IP, 17, u)
}
/// The scanner kernel's ICMP 3/3 for a reply (no socket on the scanner's port).
fn port_unreachable(reply: &[u8]) -> Vec<u8> {
    let mut l4 = vec![3, 3, 0, 0, 0, 0, 0, 0];
    l4.extend(&reply[14..14 + 28]);
    let v = crate::protocols_verify::tests::sum16(&l4, 0);
    l4[2..4].copy_from_slice(&v.to_be_bytes());
    let to = Ipv4Addr::new(reply[26], reply[27], reply[28], reply[29]);
    ip_frame(PEER_MAC, SCANNER_MAC, SCANNER_IP, to, 1, l4)
}
fn next_hop_request() -> Vec<u8> {
    let mut f = crate::autodetect_verify::tests::arp_request(&stand(), pv::GATEWAY);
    f.resize(60, 0);
    f
}
fn next_hop_reply() -> Vec<u8> {
    let mut f = Vec::new();
    f.extend(SCANNER_MAC);
    f.extend(PEER_MAC);
    f.extend([8, 6, 0, 1, 8, 0, 6, 4, 0, 2]);
    f.extend(PEER_MAC);
    f.extend(pv::GATEWAY.octets());
    f.extend(SCANNER_MAC);
    f.extend(SCANNER_IP.octets());
    f
}

// ------------------------------------------------------------------ records and documents by hand

/// One record as the generator renders it: a status, or a banner with its application number and payload (UDP, 4a);
/// the same over TCP, either family, with the reply's flags and ttl (4b).
#[derive(Clone, Debug)]
pub(crate) enum SimRec {
    Status {
        ip: Ipv4Addr,
        port: u16,
        ts: u32,
    },
    Banner {
        ip: Ipv4Addr,
        port: u16,
        ts: u32,
        app: u16,
        payload: Vec<u8>,
    },
    TcpStatus {
        ip: IpAddr,
        port: u16,
        ts: u32,
        ttl: u8,
    },
    TcpBanner {
        ip: IpAddr,
        port: u16,
        ts: u32,
        app: u16,
        ttl: u8,
        payload: Vec<u8>,
    },
}
impl SimRec {
    fn ts(&self) -> u32 {
        match self {
            SimRec::Status { ts, .. }
            | SimRec::Banner { ts, .. }
            | SimRec::TcpStatus { ts, .. }
            | SimRec::TcpBanner { ts, .. } => *ts,
        }
    }
}
/// The `-oB` length of a record body: one byte up to 127, else two (out-binary.c:315-322).
fn put_len(b: &mut Vec<u8>, len: usize) {
    if len <= 127 {
        b.push(len as u8);
    } else {
        b.extend([((len >> 7) as u8) | 0x80, (len & 0x7f) as u8]);
    }
}
/// The application names of the banners, by number (`src/masscan-app.c:8-57`).
fn name(app: u16) -> &'static str {
    match app {
        0 | 1 => "unknown",
        2 | 3 => "ssh",
        4 => "http",
        5 => "ftp",
        11 => "smtp",
        12 => "pop",
        13 => "imap",
        17 => "title",
        29 => "telnet",
        30 => "rdp",
        31 => "http.server",
        32 => "minecraft",
        33 => "vnc",
        34 => "vnc-info",
        6 => "dns-ver",
        7 => "snmp",
        8 => "nbtstat",
        14 => "zeroaccess",
        19 => "ntp",
        25 => "memcached",
        28 => "coap",
        35 => "isakmp",
        _ => panic!("app {app}"),
    }
}
fn render(out: Out, recs: &[SimRec], complete: bool) -> Vec<u8> {
    let mut b = Vec::new();
    match out {
        Out::List => {
            b.extend(b"#masscan\n");
            for r in recs {
                match r {
                    SimRec::Status { ip, port, ts } => {
                        b.extend(format!("open udp {port} {ip} {ts}\n").bytes());
                    }
                    SimRec::Banner {
                        ip,
                        port,
                        ts,
                        app,
                        payload,
                    } => b.extend(
                        format!(
                            "banner udp {port} {ip} {ts} {} {}\n",
                            name(*app),
                            normalize_string(payload)
                        )
                        .bytes(),
                    ),
                    SimRec::TcpStatus { ip, port, ts, .. } => {
                        b.extend(format!("open tcp {port} {ip} {ts}\n").bytes());
                    }
                    SimRec::TcpBanner {
                        ip,
                        port,
                        ts,
                        app,
                        payload,
                        ..
                    } => b.extend(
                        format!(
                            "banner tcp {port} {ip} {ts} {} {}\n",
                            name(*app),
                            normalize_string(payload)
                        )
                        .bytes(),
                    ),
                }
            }
            if complete {
                b.extend(b"# end\n");
            }
        }
        Out::Binary => {
            let first = recs[0].ts();
            let mut head = format!("masscan/1.1\ns:{first}\n").into_bytes();
            head.resize(99, 0);
            b.extend(head);
            for r in recs {
                match r {
                    SimRec::Status { ip, port, ts } => {
                        b.extend([6, 13]);
                        b.extend(ts.to_be_bytes());
                        b.extend(ip.octets());
                        b.push(17);
                        b.extend(port.to_be_bytes());
                        b.extend([0, TTL]);
                    }
                    SimRec::Banner {
                        ip,
                        port,
                        ts,
                        app,
                        payload,
                    } => {
                        // out-binary.c:315-322: one length byte up to 113 payload bytes, else two.
                        b.push(9);
                        let len = payload.len() + 14;
                        if payload.len() <= 113 {
                            b.push(len as u8);
                        } else {
                            b.extend([((len >> 7) as u8) | 0x80, (len & 0x7f) as u8]);
                        }
                        b.extend(ts.to_be_bytes());
                        b.extend(ip.octets());
                        b.push(17);
                        b.extend(port.to_be_bytes());
                        b.extend(app.to_be_bytes());
                        b.push(TTL);
                        b.extend(payload);
                    }
                    SimRec::TcpStatus { ip, port, ts, ttl } => match ip {
                        IpAddr::V4(a) => {
                            b.extend([6, 13]);
                            b.extend(ts.to_be_bytes());
                            b.extend(a.octets());
                            b.push(6);
                            b.extend(port.to_be_bytes());
                            b.extend([0x12, *ttl]);
                        }
                        IpAddr::V6(a) => {
                            b.extend([10, 26]);
                            b.extend(ts.to_be_bytes());
                            b.push(6);
                            b.extend(port.to_be_bytes());
                            b.extend([0x12, *ttl, 6]);
                            b.extend(a.octets());
                        }
                    },
                    SimRec::TcpBanner {
                        ip,
                        port,
                        ts,
                        app,
                        ttl,
                        payload,
                    } => match ip {
                        IpAddr::V4(a) => {
                            b.push(9);
                            put_len(&mut b, payload.len() + 14);
                            b.extend(ts.to_be_bytes());
                            b.extend(a.octets());
                            b.push(6);
                            b.extend(port.to_be_bytes());
                            b.extend(app.to_be_bytes());
                            b.push(*ttl);
                            b.extend(payload);
                        }
                        IpAddr::V6(a) => {
                            b.push(13);
                            put_len(&mut b, payload.len() + 27);
                            b.extend(ts.to_be_bytes());
                            b.push(6);
                            b.extend(port.to_be_bytes());
                            b.extend(app.to_be_bytes());
                            b.extend([*ttl, 6]);
                            b.extend(a.octets());
                            b.extend(payload);
                        }
                    },
                }
            }
            if complete {
                let mut foot = b"masscan/1.1".to_vec();
                foot.resize(99, 0);
                b.extend(foot);
            }
        }
        _ => panic!("the banners window writes -oB and -oL"),
    }
    b
}

const PLUS: &str = "[+] interface = veth-a (detected: route to 198.18.0.2)\n[+] source-mac = 02-aa-00-00-00-01 (detected)\n[+] source-ip = 198.18.0.1 (detected)\n[+] router-ip = 198.18.0.2 (interface default gateway)\n[+] router-mac = 02-aa-00-00-00-02 (arp: 1 requests, 1 ms)\n[+] seed = 1 (given)\n[+] source-port = 40000 (given)\n";
const ORACLE_STDERR: &str = "Starting masscan 1.3.9-integration (http://bit.ly/14GZzcT) at 2027-01-15 08:01:40 GMT\nInitiating SYN Stealth Scan\nScanning 4 hosts [9 ports/host]\nrate:  0.00-kpps, 100.00% done, waiting 3-secs, found=36       \r[-] Passed the wait window but still running, forcing exit...\n";
fn rm_stderr(sent: usize, replies: usize) -> String {
    format!(
        "{PLUS}{}{}\r[+] finished: Completed, sent {sent}, replies {replies}, open {replies}\n",
        status_fragments()[0],
        " ".repeat(77)
    )
}

// ------------------------------------------------------------------ the generator

#[derive(Clone)]
pub(crate) struct StepSim {
    pub(crate) spec: StepSpec,
    pub(crate) stderr: String,
    pub(crate) exit: i32,
    pub(crate) frames: Frames,
    pub(crate) recs: Vec<SimRec>,
    pub(crate) complete: bool,
    pub(crate) argv: Vec<String>,
    pub(crate) responder: ResponderRecord,
    /// The document, rendered from `recs` unless a test set its bytes.
    pub(crate) doc: Option<Vec<u8>>,
}
impl StepSim {
    pub(crate) fn doc(&self) -> Vec<u8> {
        self.doc
            .clone()
            .unwrap_or_else(|| render(self.spec.out, &self.recs, self.complete))
    }
}
pub(crate) struct Sim {
    pub(crate) tag: &'static str,
    pub(crate) steps: Vec<StepSim>,
    pub(crate) expect: BannerExpect,
    pub(crate) stack: PeerStack,
    pub(crate) extra: Vec<(String, Vec<u8>)>,
}
pub(crate) fn stack() -> PeerStack {
    PeerStack {
        icmp_ratemask: "0".into(),
        icmp_echo_ignore_all: "0".into(),
        sctp_in_kernel: false,
        responder: responder_args(),
    }
}

/// The reply payload to each probe of the plan, built by `answer` (the stand's scenario reply unless a test changes
/// it).
type Answer = fn(u16, Ipv4Addr, &[u8]) -> Option<Vec<u8>>;

/// The peer capture of one step and the records each scanner writes for it: the start marker, the next-hop ARP, each
/// probe 10 ms apart with its reply 1 ms later and the scanner kernel's ICMP 3/3 on it, the end markers. C reads its
/// raw banner on 11211 and 1900 past the datagram: other bytes of the same length.
fn wire(
    c: &CaseSpec,
    who: Who,
    t0: f64,
    probes: &[Vec<u8>],
    answer: Answer,
) -> (Frames, Vec<SimRec>) {
    let st = stand();
    let mut fr: Frames = vec![(t0, marker(&st, START_PAYLOAD))];
    fr.push((t0 + 0.2, next_hop_request()));
    fr.push((t0 + 0.201, next_hop_reply()));
    let mut recs = Vec::new();
    let mut last = t0;
    for (i, p) in probes.iter().enumerate() {
        let t = t0 + 0.6 + i as f64 * 0.01;
        fr.push((t, p.clone()));
        let a = t + 0.001;
        let (ip, port) = (probe_peer(p), probe_ports(p).1);
        let Some(payload) = answer(port, ip, probe_payload(p)) else {
            continue;
        };
        let r = udp_back(p, &payload);
        fr.push((a, r.clone()));
        fr.push((a + 0.0005, port_unreachable(&r)));
        let ts = a as u32;
        recs.push(SimRec::Status { ip, port, ts });
        let cx = UdpContext {
            port_them: port,
            cookie: probe_cookie(port, probe_payload(p)),
            rawudp: c.rawudp,
        };
        let banners = handle_udp(&cx, &payload);
        let n = banners.len();
        for (k, (app, mut bytes)) in banners.into_iter().enumerate() {
            if who == Who::Oracle
                && k + 1 == n
                && app == 0
                && RAW_PAST_DATAGRAM_PORTS.contains(&port)
            {
                bytes = vec![0xee; bytes.len()];
            }
            recs.push(SimRec::Banner {
                ip,
                port,
                ts,
                app,
                payload: bytes,
            });
        }
        last = a;
    }
    for k in 0..3 {
        fr.push((last + 1.0 + f64::from(k) * 0.05, marker(&st, END_PAYLOAD)));
    }
    (fr, recs)
}

impl Sim {
    pub(crate) fn new(tag: &'static str) -> Sim {
        match any_case(tag) {
            Some(Case::Tcp(c)) => Sim::tcp(&c),
            _ => Sim::with_answer(tag, scenario_reply),
        }
    }
    fn with_answer(tag: &'static str, answer: Answer) -> Sim {
        let c = case(tag).unwrap();
        let probes = plan_stream(&c).unwrap();
        let mut steps_ = Vec::new();
        for (i, spec) in steps(tag).unwrap().into_iter().enumerate() {
            let t0 = T0 + 100.0 * i as f64;
            let (frames, recs) = wire(&c, spec.who, t0, &probes, answer);
            let oracle = spec.who == Who::Oracle;
            let replies = recs
                .iter()
                .filter(|r| matches!(r, SimRec::Status { .. }))
                .count();
            steps_.push(StepSim {
                argv: spec.argv.clone(),
                stderr: if oracle {
                    ORACLE_STDERR.into()
                } else {
                    rm_stderr(probes.len(), replies)
                },
                spec,
                exit: 0,
                frames,
                recs,
                complete: !oracle,
                responder: ResponderRecord::default(),
                doc: None,
            });
        }
        Sim {
            tag,
            steps: steps_,
            expect: expect(tag).unwrap(),
            stack: stack(),
            extra: Vec::new(),
        }
    }
    pub(crate) fn step_mut(&mut self, name: &str) -> &mut StepSim {
        self.steps.iter_mut().find(|s| s.spec.name == name).unwrap()
    }
    fn files(&self) -> Vec<(String, Vec<u8>)> {
        let json_ = |v: &dyn erased::Ser| v.bytes();
        let mut f: Vec<(String, Vec<u8>)> = vec![
            (EXPECT_JSON.into(), json_(&self.expect)),
            (ISOLATION_JSON.into(), ipv6_isolation()),
            (ISOLATION_POST_JSON.into(), ipv6_isolation()),
            (PEER_STACK_JSON.into(), json_(&self.stack)),
        ];
        for s in &self.steps {
            let n = s.spec.name;
            f.push((
                format!("{n}/argv.json"),
                json_(&crate::autodetect_verify::ArgvRecord {
                    argv: s.argv.clone(),
                }),
            ));
            f.push((format!("{n}/stdout.txt"), Vec::new()));
            f.push((format!("{n}/stderr.txt"), s.stderr.clone().into_bytes()));
            f.push((
                format!("{n}/exit.txt"),
                format!("{}\n", s.exit).into_bytes(),
            ));
            f.push((format!("{n}/peer.pcap"), pcap::encode(&s.frames)));
            f.push((format!("{n}/capture.json"), AdSim::witness(&s.frames)));
            f.push((
                format!("{n}/peer.err"),
                format!("{} packets captured\n", s.frames.len()).into_bytes(),
            ));
            f.push((format!("{n}/{RESPONDER_JSON}"), json_(&s.responder)));
            f.push((format!("{n}/{}", s.spec.out.file().unwrap()), s.doc()));
        }
        if let Some(Case::Tcp(_)) = any_case(self.tag) {
            f.push((
                PEER_TCP_JSON.into(),
                json_(&PeerTcp {
                    tcp_max_tw_buckets: "0".into(),
                }),
            ));
        }
        f.extend(self.extra.iter().cloned());
        f
    }
    /// The case directory under `root/runs/<tag>`, with `manifest.json` at the root if none is there yet.
    pub(crate) fn write(&self, root: &Path) -> PathBuf {
        let man = root.join(MANIFEST_JSON);
        if !man.exists() {
            fs::write(
                &man,
                json!({"banners": "linux", "lab_id": LAB_ID}).to_string(),
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
        fs::write(d.join(HASHES), hashes).unwrap();
        d
    }
}

// ------------------------------------------------------------------ TCP: the generator

/// A TCP segment of the peer's kernel from `peer` to the scanner's `src`, plain 20-byte header, valid sums, ttl 64.
fn peer_seg(
    peer: IpAddr,
    src: IpAddr,
    ports: (u16, u16),
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend(ports.0.to_be_bytes());
    t.extend(ports.1.to_be_bytes());
    t.extend(seq.to_be_bytes());
    t.extend(ack.to_be_bytes());
    t.extend([0x50, flags]);
    t.extend(64240u16.to_be_bytes());
    t.extend([0, 0, 0, 0]);
    t.extend(payload);
    match (peer, src) {
        (IpAddr::V4(p), IpAddr::V4(s)) => ip_frame(SCANNER_MAC, PEER_MAC, p, s, 6, t),
        (IpAddr::V6(p), IpAddr::V6(s)) => v6_frame(SCANNER_MAC, PEER_MAC, p, s, 6, TTL, t),
        _ => panic!("mixed families"),
    }
}
/// An Ethernet + IPv6 frame around `l4` with its TCP (16) or ICMPv6 (2) checksum set.
fn v6_frame(
    dmac: [u8; 6],
    smac: [u8; 6],
    s: Ipv6Addr,
    d: Ipv6Addr,
    next: u8,
    hop: u8,
    mut l4: Vec<u8>,
) -> Vec<u8> {
    let at = if next == 6 { 16 } else { 2 };
    l4[at..at + 2].fill(0);
    let mut all = Vec::new();
    all.extend(s.octets());
    all.extend(d.octets());
    all.extend((l4.len() as u32).to_be_bytes());
    all.extend([0, 0, 0, next]);
    all.extend(&l4);
    let v = crate::protocols_verify::tests::sum16(&all, 0);
    l4[at..at + 2].copy_from_slice(&v.to_be_bytes());
    let mut f = Vec::new();
    f.extend(dmac);
    f.extend(smac);
    f.extend([0x86, 0xdd, 0x60, 0, 0, 0]);
    f.extend((l4.len() as u16).to_be_bytes());
    f.extend([next, hop]);
    f.extend(s.octets());
    f.extend(d.octets());
    f.extend(l4);
    f
}
/// The peer's request for the scanner's `src` (Linux: a 42-byte ARP who-has, or an NS to the solicited-node group
/// with the source link-layer option) and the scanner's answer in C's form.
fn resolution(src: IpAddr) -> (Vec<u8>, Vec<u8>) {
    match src {
        IpAddr::V4(s) => {
            let peer = Ipv4Addr::new(198, 18, 0, 2);
            let mut q = vec![0xff; 6];
            q.extend(PEER_MAC);
            q.extend([8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
            q.extend(PEER_MAC);
            q.extend(peer.octets());
            q.extend([0; 6]);
            q.extend(s.octets());
            let mut a = Vec::new();
            a.extend(PEER_MAC);
            a.extend(SCANNER_MAC);
            a.extend([8, 6, 0, 1, 8, 0, 6, 4, 0, 2]);
            a.extend(SCANNER_MAC);
            a.extend(s.octets());
            a.extend(PEER_MAC);
            a.extend(peer.octets());
            a.resize(60, 0);
            (q, a)
        }
        IpAddr::V6(s) => {
            let peer: Ipv6Addr = "fd00:198:18::2".parse().unwrap();
            let o = s.octets();
            let group = Ipv6Addr::new(
                0xff02,
                0,
                0,
                0,
                0,
                1,
                0xff00 | u16::from(o[13]),
                u16::from_be_bytes([o[14], o[15]]),
            );
            let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
            ns.extend(o);
            ns.extend([1, 1]);
            ns.extend(PEER_MAC);
            let q = v6_frame(
                [0x33, 0x33, 0xff, o[13], o[14], o[15]],
                PEER_MAC,
                peer,
                group,
                58,
                255,
                ns,
            );
            let mut na = vec![136, 0, 0, 0, 0x60, 0, 0, 0];
            na.extend(o);
            na.extend([2, 1]);
            na.extend(SCANNER_MAC);
            let a = v6_frame(PEER_MAC, SCANNER_MAC, s, peer, 58, 255, na);
            (q, a)
        }
    }
}
/// The peer of one connection: its kernel (sequence numbers, ACKs, FIN) and its scenario script (`run_script`).
struct PeerConn {
    ip: IpAddr,
    port: u16,
    sport: u16,
    syn_seq: u32,
    sc: Option<&'static TcpScenario>,
    snd_nxt: u32,
    rcv_nxt: u32,
    established: bool,
    pc: usize,
    ready_at: f64,
    unread: usize,
    eof: bool,
    done: bool,
    dead: bool,
    end_at: Option<f64>,
    reply_t: f64,
}
/// One TCP step on a simulated stand: the plan's SYNs 10 ms apart, the peer kernel and the scenario responder of the
/// table, the product's own stack (`rmasscan_proto::tcp_stack_factory`) with `--banners` or the stateless RST without
/// it (src/main.c:1094-1100), the frames from `TcpFrameBuilder::from_plan`, the heartbeat, the records each scanner
/// writes (C's IPv6 ttl stale). Time advances in 1 ms ticks; the stack is ticked every 10 ms.
fn tcp_wire(c: &TcpCase, who: Who, t0: f64) -> (Frames, Vec<SimRec>, (usize, usize, usize)) {
    use rmasscan_core::{
        stack::{ConnAddrs, ConnKey, SegmentIn, SegmentOut, StackOutput, TableParams},
        tcp_frame::TcpFrameBuilder,
    };
    let st = stand();
    let plan = tcp_ready_plan(c).unwrap();
    let builder = TcpFrameBuilder::from_plan(&plan);
    let probes = tcp_plan_stream(c).unwrap();
    let src = c.source();
    let mut stack = c.banners.then(|| {
        rmasscan_proto::tcp_stack_factory(
            rmasscan_proto::TcpBannerSettings::default(),
            c.connection_timeout.unwrap_or(0),
        )
        .new_table(TableParams {
            seed: 1,
            capacity: 4096,
            banner_byte_budget: 1 << 29,
        })
    });
    let isn0: u32 = if who == Who::Oracle {
        0x7000_0000
    } else {
        0x1000_0000
    };
    let addr = |a: IpAddr| match a {
        IpAddr::V4(x) => (Some(u32::from(x)), None),
        IpAddr::V6(x) => (None, Some(u128::from(x))),
    };
    let key_of = |peer: IpAddr, port: u16, sport: u16| ConnKey {
        addrs: match (addr(src), addr(peer)) {
            ((Some(l), _), (Some(r), _)) => ConnAddrs::V4 {
                local: l,
                remote: r,
            },
            ((_, Some(l)), (_, Some(r))) => ConnAddrs::V6 {
                local: l,
                remote: r,
            },
            _ => panic!("mixed families"),
        },
        local_port: sport,
        remote_port: port,
    };
    let mut fr: Frames = vec![(t0, marker(&st, START_PAYLOAD))];
    let mut recs: Vec<SimRec> = Vec::new();
    let mut conns: Vec<PeerConn> = probes
        .iter()
        .map(|p| {
            let h = tcp_head(p).unwrap();
            PeerConn {
                ip: h.dst,
                port: h.dp,
                sport: h.sp,
                syn_seq: h.seq,
                sc: tcp_scenario(h.dp, h.dst),
                snd_nxt: 0,
                rcv_nxt: h.seq.wrapping_add(1),
                established: false,
                pc: 0,
                ready_at: 0.0,
                unread: 0,
                eof: false,
                done: false,
                dead: false,
                end_at: None,
                reply_t: 0.0,
            }
        })
        .collect();
    // Frames of the peer waiting for their time: (time, connection, frame).
    let mut pending: Vec<(f64, usize, Vec<u8>)> = Vec::new();
    let first = t0 + 0.6;
    let last_probe = first + (probes.len() - 1) as f64 * 0.01;
    let scan_end = last_probe + f64::from(c.wait);
    let mut resolved = !c.resolve;
    let ttl_of = |ip: IpAddr| {
        if who == Who::Oracle && ip.is_ipv6() {
            0
        } else {
            TTL
        }
    };
    let mut beat = t0 + 0.3;
    let mut tick = 0u64;
    let (mut replies, mut open) = (0, 0);
    // What the scanner sent on a connection, as the peer kernel takes it.
    fn to_peer(
        pc: &mut PeerConn,
        seg: &SegmentOut,
        at: f64,
        pending: &mut Vec<(f64, usize, Vec<u8>)>,
        i: usize,
        src: IpAddr,
    ) {
        if seg.flags & 0x04 != 0 {
            pc.dead = true;
            return;
        }
        if !pc.established && seg.flags & 0x10 != 0 && seg.ack == pc.snd_nxt {
            pc.established = true;
            pc.ready_at = at;
        }
        let mut ack = false;
        if !seg.payload.is_empty() && seg.seq == pc.rcv_nxt {
            pc.rcv_nxt = pc.rcv_nxt.wrapping_add(seg.payload.len() as u32);
            pc.unread += seg.payload.len();
            ack = true;
        }
        if seg.flags & 0x01 != 0 && seg.seq.wrapping_add(seg.payload.len() as u32) == pc.rcv_nxt {
            pc.rcv_nxt = pc.rcv_nxt.wrapping_add(1);
            pc.eof = true;
            ack = true;
        }
        if ack && !pc.dead {
            pending.push((
                at + 0.0005,
                i,
                peer_seg(
                    pc.ip,
                    src,
                    (pc.port, pc.sport),
                    pc.snd_nxt,
                    pc.rcv_nxt,
                    0x10,
                    &[],
                ),
            ));
        }
    }
    let mut t = first;
    while t <= scan_end + 1e-9 {
        let now = ((t - t0) * 1e6) as u64;
        let mut out = StackOutput::default();
        while beat <= t && beat <= scan_end + 0.6 {
            fr.push((
                beat,
                crate::link::marker_frame(SCANNER_MAC, PEER_MAC, HEARTBEAT_PAYLOAD),
            ));
            beat += 0.2;
        }
        // The SYNs due now, and the peer kernel's answers.
        for (i, p) in probes.iter().enumerate() {
            let at = first + i as f64 * 0.01;
            if (at - t).abs() > 0.0004 {
                continue;
            }
            fr.push((at, p.clone()));
            if !resolved {
                let (q, a) = resolution(src);
                fr.push((at + 0.0003, q));
                fr.push((at + 0.0006, a));
                resolved = true;
            }
            let pc = &mut conns[i];
            let isn = isn0.wrapping_add((i as u32) << 20);
            pc.snd_nxt = isn.wrapping_add(1);
            pc.reply_t = at + 0.001;
            let (flags, seq) = if pc.sc.is_some() {
                (0x12, isn)
            } else {
                (0x14, 0)
            };
            pending.push((
                at + 0.001,
                i,
                peer_seg(
                    pc.ip,
                    src,
                    (pc.port, pc.sport),
                    seq,
                    pc.syn_seq.wrapping_add(1),
                    flags,
                    &[],
                ),
            ));
            // t06: the peer kernel repeats a SYN-ACK nobody acknowledges (tcp_synack_retries).
            if c.noreset && !c.banners && pc.sc.is_some() {
                for k in [1.0, 3.0] {
                    if at + k < scan_end + 0.5 {
                        pending.push((
                            at + 0.001 + k,
                            i,
                            peer_seg(
                                pc.ip,
                                src,
                                (pc.port, pc.sport),
                                isn,
                                pc.syn_seq.wrapping_add(1),
                                0x12,
                                &[],
                            ),
                        ));
                    }
                }
            }
        }
        // The peer's scripts.
        for (i, pc) in conns.iter_mut().enumerate() {
            let Some(sc) = pc.sc else { continue };
            if !pc.established || pc.done || pc.dead || t < pc.ready_at {
                continue;
            }
            let send = |pc: &mut PeerConn,
                        flags: u8,
                        payload: &[u8],
                        pending: &mut Vec<(f64, usize, Vec<u8>)>| {
                pending.push((
                    t + 0.0007,
                    i,
                    peer_seg(
                        pc.ip,
                        src,
                        (pc.port, pc.sport),
                        pc.snd_nxt,
                        pc.rcv_nxt,
                        flags,
                        payload,
                    ),
                ));
                pc.snd_nxt = pc
                    .snd_nxt
                    .wrapping_add(payload.len() as u32 + u32::from(flags & 0x01));
            };
            loop {
                match sc.steps.get(pc.pc) {
                    Some(TcpStep::Write(b)) => {
                        send(pc, 0x18, b, &mut pending);
                        pc.pc += 1;
                        pc.ready_at = t + 0.2;
                        break;
                    }
                    Some(TcpStep::Recv | TcpStep::Peek) if pc.unread > 0 => {
                        if sc.steps[pc.pc] == TcpStep::Recv {
                            pc.unread = 0;
                        }
                        pc.pc += 1;
                    }
                    Some(TcpStep::Recv | TcpStep::Peek) if pc.eof => {
                        send(pc, 0x11, &[], &mut pending);
                        pc.done = true;
                        break;
                    }
                    // Held: closed with the hello unread, the kernel resets (run_script's hold).
                    Some(TcpStep::Hold) if pc.eof => {
                        send(
                            pc,
                            if pc.unread > 0 { 0x14 } else { 0x11 },
                            &[],
                            &mut pending,
                        );
                        pc.done = true;
                        break;
                    }
                    Some(TcpStep::Reset) => {
                        send(pc, 0x14, &[], &mut pending);
                        pc.dead = true;
                        break;
                    }
                    Some(_) => break,
                    None => {
                        let end = *pc.end_at.get_or_insert(t + 1.0);
                        if pc.eof || t >= end {
                            send(pc, 0x11, &[], &mut pending);
                            pc.done = true;
                        }
                        break;
                    }
                }
            }
        }
        // The peer's frames due now, to the scanner.
        pending.sort_by(|a, b| a.0.total_cmp(&b.0));
        let due: Vec<(f64, usize, Vec<u8>)> = {
            let n = pending.iter().take_while(|x| x.0 <= t + 0.0009).count();
            pending.drain(..n).collect()
        };
        let mut sent: Vec<(f64, SegmentOut)> = Vec::new();
        for (at, i, f) in due {
            fr.push((at, f.clone()));
            let h = tcp_head(&f).unwrap();
            let pc = &conns[i];
            let first_reply =
                h.flags & 0x12 == 0x12 && h.seq.wrapping_add(1) == pc.snd_nxt && !pc.established
                    || h.flags == 0x14 && h.seq == 0;
            if first_reply && !recs.iter().any(|r| matches!(r, SimRec::TcpStatus { ip, port, .. } if *ip == pc.ip && *port == pc.port))
                && (h.flags & 0x12 == 0x12)
            {
                recs.push(SimRec::TcpStatus { ip: pc.ip, port: pc.port, ts: at as u32, ttl: ttl_of(pc.ip) });
            }
            let fresh = (h.flags & 0x12 == 0x12 && (at - pc.reply_t).abs() < 1e-6)
                || (h.flags == 0x14 && h.seq == 0);
            if fresh {
                replies += 1;
                open += usize::from(h.flags & 0x12 == 0x12);
            }
            match &mut stack {
                Some(stk) => {
                    let seg = SegmentIn {
                        key: key_of(pc.ip, pc.port, pc.sport),
                        seq: h.seq,
                        ack: h.ack,
                        flags: h.flags,
                        ttl: TTL,
                        payload: &h.payload,
                    };
                    let mut o = StackOutput::default();
                    stk.on_segment(((at - t0) * 1e6) as u64, &seg, &mut o);
                    sent.extend(o.segments.into_iter().map(|g| (at + 0.0002, g)));
                    out.banners.extend(o.banners);
                }
                None if fresh && !c.noreset => sent.push((
                    at + 0.0002,
                    SegmentOut {
                        key: key_of(pc.ip, pc.port, pc.sport),
                        seq: h.ack,
                        ack: 0,
                        flags: 0x04,
                        payload: Vec::new(),
                        window: None,
                    },
                )),
                None => {}
            }
        }
        if tick.is_multiple_of(10)
            && let Some(stk) = &mut stack
        {
            let mut o = StackOutput::default();
            stk.on_tick(now, &mut o);
            sent.extend(o.segments.into_iter().map(|g| (t + 0.0002, g)));
            out.banners.extend(o.banners);
        }
        for (at, g) in sent {
            fr.push((at, builder.build(&g)));
            let i = conns
                .iter()
                .position(|pc| key_of(pc.ip, pc.port, pc.sport) == g.key)
                .unwrap();
            to_peer(&mut conns[i], &g, at, &mut pending, i, src);
        }
        for flush in out.banners {
            for b in flush {
                recs.push(SimRec::TcpBanner {
                    ip: b.ip,
                    port: b.port,
                    ts: t as u32,
                    app: b.app,
                    ttl: ttl_of(b.ip),
                    payload: b.payload,
                });
            }
        }
        t += 0.001;
        tick += 1;
    }
    // The end of the scan: the table is flushed without a frame (tcpcon_destroy_table).
    if let Some(stk) = &mut stack {
        let mut o = StackOutput::default();
        while stk.finish(usize::MAX, &mut o) {}
        for b in o.banners.into_iter().flatten() {
            recs.push(SimRec::TcpBanner {
                ip: b.ip,
                port: b.port,
                ts: scan_end as u32,
                app: b.app,
                ttl: ttl_of(b.ip),
                payload: b.payload,
            });
        }
    }
    while beat <= scan_end + 0.6 {
        fr.push((
            beat,
            crate::link::marker_frame(SCANNER_MAC, PEER_MAC, HEARTBEAT_PAYLOAD),
        ));
        beat += 0.2;
    }
    fr.sort_by(|a, b| a.0.total_cmp(&b.0));
    let end = fr.last().map_or(t0, |x| x.0) + 1.0;
    for k in 0..3 {
        fr.push((end + f64::from(k) * 0.05, marker(&st, END_PAYLOAD)));
    }
    (fr, recs, (probes.len(), replies, open))
}
const ORACLE_TCP_STDERR: &str = "Starting masscan 1.3.9-integration (http://bit.ly/14GZzcT) at 2027-01-15 08:01:40 GMT\nInitiating SYN Stealth Scan\nScanning 4 hosts [11 ports/host]\n";
fn tcp_rm_stderr(c: &TcpCase, counts: (usize, usize, usize)) -> String {
    let plus: String = tcp_plus_for_tests(c)
        .iter()
        .map(|(k, v)| format!("[+] {k} = {v}\n"))
        .collect();
    format!(
        "{plus}{}{}\r[+] finished: Completed, sent {}, replies {}, open {}\n",
        status_fragments()[0],
        " ".repeat(77),
        counts.0,
        counts.1,
        counts.2
    )
}
/// The `[+]` lines of a TCP case as rmasscan prints them (live.rs: the interface by the route to the first target,
/// the given source and next hop), written here by hand.
fn tcp_plus_for_tests(c: &TcpCase) -> Vec<(&'static str, String)> {
    let first = c.targets.split('-').next().unwrap();
    let src = match c.source() {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => format!("[{a}]"),
    };
    vec![
        ("interface", format!("veth-a (detected: route to {first})")),
        ("source-mac", "02-aa-00-00-00-01 (detected)".into()),
        ("source-ip", format!("{src} (given)")),
        (
            if c.v6 {
                "router-mac-ipv6"
            } else {
                "router-mac"
            },
            "02-aa-00-00-00-02 (given)".into(),
        ),
        ("seed", "1 (given)".into()),
        ("source-port", "40000 (given)".into()),
    ]
}
impl Sim {
    /// A TCP case: each step from [`tcp_wire`]; the oracle's document complete (the heartbeat lets C end its scan).
    pub(crate) fn tcp(c: &TcpCase) -> Sim {
        let mut steps_ = Vec::new();
        for (i, spec) in steps(c.tag).unwrap().into_iter().enumerate() {
            let t0 = T0 + 100.0 * i as f64;
            let (frames, recs, counts) = tcp_wire(c, spec.who, t0);
            let oracle = spec.who == Who::Oracle;
            steps_.push(StepSim {
                argv: spec.argv.clone(),
                stderr: if oracle {
                    ORACLE_TCP_STDERR.into()
                } else {
                    tcp_rm_stderr(c, counts)
                },
                spec,
                exit: 0,
                frames,
                recs,
                complete: true,
                responder: ResponderRecord::default(),
                doc: None,
            });
        }
        Sim {
            tag: c.tag,
            steps: steps_,
            expect: expect(c.tag).unwrap(),
            stack: PeerStack {
                responder: tcp_responder_args(c),
                ..stack()
            },
            extra: Vec::new(),
        }
    }
}

/// The verdict of one case written alone (with its manifest and teardown), and its failing checks.
fn judge_one(sim: &Sim) -> (String, Vec<String>) {
    let root = scratch();
    sim.write(&root);
    fs::write(root.join(TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = verify_dir(&root);
    let run = run_of(&res, sim.tag).clone();
    fs::remove_dir_all(&root).unwrap();
    (s(&run["verdict"]).to_owned(), bad(&run))
}
/// The index of the first banner record of `(ip, port)` with application `app` in a step's records.
fn banner_at(recs: &[SimRec], ip: u8, port: u16, app: u16) -> usize {
    recs.iter()
        .position(|r| {
            matches!(r, SimRec::Banner { ip: i, port: p, app: a, .. }
                if i.octets()[3] == ip && *p == port && *a == app)
        })
        .unwrap_or_else(|| panic!("no banner {app} of .{ip}:{port}"))
}

// ------------------------------------------------------------------ the scenarios

#[test]
fn every_probe_gets_its_scenario_reply_and_the_replies_make_the_declared_banners() {
    for c in CASES {
        let probes = plan_stream(&c).unwrap();
        assert_eq!(probes.len(), 4 * PORTS.len(), "4 peers x 9 ports");
        for p in &probes {
            let (ip, port) = (probe_peer(p), probe_ports(p).1);
            let probe = probe_payload(p);
            assert!(!probe.is_empty(), "port {port} has a built-in payload");
            let reply = scenario_reply(port, ip, probe).expect("every probe is answered");
            let sc = scenario(port, role_of(ip).unwrap()).unwrap();
            let cx = UdpContext {
                port_them: port,
                cookie: probe_cookie(port, probe),
                rawudp: c.rawudp,
            };
            let apps: Vec<&str> = handle_udp(&cx, &reply)
                .iter()
                .map(|(a, _)| name(*a))
                .collect();
            assert_eq!(
                apps,
                sc.apps(c.rawudp),
                "{ip}:{port} {:?} ({}), rawudp {}",
                sc.role,
                sc.about,
                c.rawudp
            );
        }
    }
}

#[test]
fn the_replies_are_the_c_goldens_with_the_probes_cookie_or_a_spoiled_one() {
    let probes = plan_stream(&case("b01_banners").unwrap()).unwrap();
    let probe = |o: u8, port: u16| {
        probes
            .iter()
            .find(|p| probe_peer(p).octets()[3] == o && probe_ports(p).1 == port)
            .map(|p| probe_payload(p).to_vec())
            .unwrap()
    };
    let ip = |o| Ipv4Addr::new(198, 18, 0, o);
    // DNS: the golden CHAOS TXT reply with the probe's id; the wrong-cookie peer's id has its low byte inverted.
    let q = probe(2, 53);
    let r = scenario_reply(53, ip(2), &q).unwrap();
    assert_eq!(&r[..2], &q[..2]);
    assert_eq!(&r[2..], &DNS_CHAOS_TXT[2..]);
    let q3 = probe(3, 53);
    let r3 = scenario_reply(53, ip(3), &q3).unwrap();
    assert_eq!((r3[0], r3[1]), (q3[0], q3[1] ^ 0xff));
    // SNMP: the request id at 17..21 is the probe's (snmp_set_cookie case 4).
    let q = probe(2, 161);
    assert_eq!(&q[15..17], &[2, 4]);
    let r = scenario_reply(161, ip(2), &q).unwrap();
    assert_eq!(&r[17..21], &q[17..21]);
    // ISAKMP: the initiator cookie, 00 00 00 00 and the 32-bit cookie, is the probe's.
    let q = probe(2, 500);
    let r = scenario_reply(500, ip(2), &q).unwrap();
    assert_eq!(&r[..8], &q[..8]);
    assert_eq!(&q[..4], &[0, 0, 0, 0]);
    // CoAP's message id and memcached's request id.
    let q = probe(2, 5683);
    assert_eq!(&scenario_reply(5683, ip(2), &q).unwrap()[2..4], &q[2..4]);
    let q = probe(2, 11211);
    assert_eq!(&scenario_reply(11211, ip(2), &q).unwrap()[..2], &q[..2]);
    // No answer off the stand's four addresses, or to a probe too short to carry the cookie.
    assert_eq!(scenario_reply(53, ip(9), &probe(2, 53)), None);
    assert_eq!(scenario_reply(161, ip(2), &[0x30]), None);
    assert_eq!(scenario_reply(9, ip(2), b"x"), None);
}

#[test]
fn zeroaccess_replies_are_sealed_the_way_c_opens_them() {
    let cx = UdpContext {
        port_them: 16464,
        cookie: 0,
        rawudp: false,
    };
    let retl = zeroaccess_retl(&stand().peer_ips[..3]);
    assert_eq!(
        handle_udp(&cx, &retl)[0],
        (14, b"ZeroAccess:198.18.0.2 198.18.0.3 198.18.0.4 ".to_vec())
    );
    // The golden retL of the C self-test round-trips: opening and sealing again gives the same bytes.
    let golden = include_bytes!("../../../tests/golden/udp-banners/cases/zeroaccess-retl.bin");
    assert_eq!(zeroaccess_seal(&zeroaccess_open(golden)), golden.to_vec());
}

#[test]
fn the_parsers_read_cs_own_banner_documents() {
    // The C oracle's --readscan outputs of the banners golden input (tests/golden/formats), not a rendering here:
    // `--banner-types dns-ver` keeps three dns-ver banners (udp IPv4, tcp IPv4, udp IPv6, the last one empty).
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/formats/outputs"
    );
    let read = |n: &str| fs::read(format!("{dir}/{n}")).unwrap();
    let list = parse_doc(Out::List, &read("banner-types.dns-ver.list.out")).unwrap();
    let bin = parse_doc(Out::Binary, &read("banner-types.dns-ver.binary.out")).unwrap();
    assert!(list.complete && bin.complete);
    assert_eq!(list.records.len(), 3);
    assert_eq!(bin.records.len(), 3);
    for (l, b) in list.records.iter().zip(&bin.records) {
        assert_eq!(
            (l.ip, l.port, &l.proto, l.ts),
            (b.ip, b.port, &b.proto, b.ts)
        );
        assert_eq!(l.app_name(), Some("dns-ver".to_owned()));
        assert_eq!(b.app_name(), Some("dns-ver".to_owned()));
        // -oL holds normalize_string of what -oB holds raw.
        let (
            Body::Banner {
                data: Data::Text(t),
                ..
            },
            Body::Banner {
                data: Data::Raw(r), ..
            },
        ) = (&l.body, &b.body)
        else {
            panic!("{l:?} {b:?}");
        };
        assert_eq!(*t, normalize_string(r));
    }
    assert_eq!(
        bin.records[0].show(),
        "banner 192.0.2.21 53/udp dns-ver ttl 57 7 bytes \"9.18.24\""
    );
    // Status and banner records of every kind the banners golden input has: tcp, udp, IPv4, IPv6, -oB lengths of one
    // and two bytes.
    let list = parse_doc(Out::List, &read("banners.open-closed.list.out")).unwrap();
    let bin = parse_doc(Out::Binary, &read("banners.open-closed.binary.out")).unwrap();
    assert_eq!(list.records.len(), bin.records.len());
    assert!(
        bin.records
            .iter()
            .any(|r| matches!(&r.body, Body::Banner { data: Data::Raw(b), .. } if b.len() > 113))
    );
    assert!(list.records.iter().any(|r| r.ip.is_ipv6()));
}

#[test]
fn a_document_that_is_not_the_c_form_is_refused() {
    let ok = render(
        Out::List,
        &[SimRec::Status {
            ip: Ipv4Addr::new(198, 18, 0, 2),
            port: 53,
            ts: 1,
        }],
        true,
    );
    assert!(parse_doc(Out::List, &ok).is_ok());
    // A banner line without the space after the application, a record type the window never writes, a short footer.
    assert!(
        parse_doc(
            Out::List,
            b"#masscan\nbanner udp 53 198.18.0.2 1 dns-ver\n# end\n"
        )
        .is_err()
    );
    let mut b = render(
        Out::Binary,
        &[SimRec::Status {
            ip: Ipv4Addr::new(198, 18, 0, 2),
            port: 53,
            ts: 1,
        }],
        false,
    );
    assert_eq!(parse_doc(Out::Binary, &b).map(|d| d.complete), Ok(false));
    b.push(42);
    b.push(1);
    b.push(0);
    assert!(parse_doc(Out::Binary, &b).unwrap_err().contains("type 42"));
    b.truncate(b.len() - 3);
    b.extend(b"masscan/1.1");
    assert!(parse_doc(Out::Binary, &b).is_err());
    assert!(parse_doc(Out::Json, b"[\n]\n").is_err());
}

#[test]
fn only_cs_raw_banner_on_11211_and_1900_is_masked_and_by_length_in_binary() {
    let ip = Ipv4Addr::new(198, 18, 0, 2);
    let rec = |port: u16, app: AppId, data: Data| Rec {
        ip: IpAddr::V4(ip),
        port,
        proto: "udp".into(),
        body: Body::Banner {
            app,
            ttl: Some(64),
            data,
        },
        ts: Some(1),
    };
    let recs = vec![
        rec(11211, AppId::Id(25), Data::Raw(b"uptime=1 ".to_vec())),
        rec(11211, AppId::Id(0), Data::Raw(vec![1, 2, 3])),
        rec(1900, AppId::Id(0), Data::Raw(vec![9; 64])),
        rec(1900, AppId::Id(0), Data::Raw(vec![9; 80])),
        rec(53, AppId::Id(0), Data::Raw(vec![4; 5])),
        rec(
            1900,
            AppId::Name("unknown".into()),
            Data::Text("abc".into()),
        ),
    ];
    let (m, n) = mask_raw_past_datagram(&recs);
    assert_eq!(
        n, 2,
        "the last unknown banner of 11211 and of 1900 per address and port"
    );
    assert_eq!(m[0], recs[0]);
    assert!(matches!(
        &m[1].body,
        Body::Banner {
            data: Data::PastDatagram(Some(3)),
            ..
        }
    ));
    assert_eq!(m[2], recs[2], "def64 stays");
    assert!(
        matches!(
            &m[5].body,
            Body::Banner {
                data: Data::PastDatagram(None),
                ..
            }
        ),
        "-oL text: presence only"
    );
    assert_eq!(
        m[3], recs[3],
        "only the last unknown banner of an address and port"
    );
    assert_eq!(m[4], recs[4], "port 53 is never masked");
}

// ------------------------------------------------------------------ whole cases

#[test]
fn the_whole_directory_passes() {
    let root = scratch();
    for tag in planned_tags() {
        Sim::new(tag).write(&root);
    }
    fs::write(root.join(TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = verify_dir(&root);
    let failing: Vec<String> = array(&res["runs"]).iter().flat_map(bad).collect();
    assert_eq!(res["overall"], PASS, "{failing:#?}");
    let b01 = run_of(&res, "b01_banners");
    // The notes say how many of C's raw banners were masked, and what each case's scenarios are.
    let dev = array(&b01["notes"]["deviations"]);
    assert!(
        dev.iter().any(|d| d["name"] == "udp-raw-past-datagram"
            && s(&d["observed"]).starts_with("16 raw banners of C past the datagram masked")),
        "{dev:?}"
    );
    assert_eq!(array(&b01["notes"]["scenarios"]).len(), 36);
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn an_extra_banner_of_rmasscan_fails_against_c() {
    for out in ["binary", "list"] {
        let mut sim = Sim::new("b01_banners");
        let st = sim.step_mut(out);
        let i = banner_at(&st.recs, 2, 53, 6);
        let mut extra = st.recs[i].clone();
        if let SimRec::Banner { app, .. } = &mut extra {
            *app = 0;
        }
        st.recs.insert(i + 1, extra);
        let (v, b) = judge_one(&sim);
        assert_eq!(v, FAIL, "{out}: {b:#?}");
        assert!(
            has(
                &b,
                FAIL,
                &format!("{out}: the records equal the C oracle's")
            ),
            "{b:#?}"
        );
        assert!(has(&b, FAIL, "banners the scenario declares"), "{b:#?}");
    }
}

#[test]
fn a_lost_banner_of_rmasscan_fails_against_c() {
    let mut sim = Sim::new("b01_banners");
    let st = sim.step_mut("binary");
    let i = banner_at(&st.recs, 2, 5683, 28);
    st.recs.remove(i);
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "binary: the records equal the C oracle's"),
        "{b:#?}"
    );
    assert!(has(&b, FAIL, "banners the scenario declares"), "{b:#?}");
}

#[test]
fn a_banner_under_another_application_fails_against_c() {
    let mut sim = Sim::new("b02_rawudp");
    let st = sim.step_mut("binary");
    let i = banner_at(&st.recs, 2, 161, 7);
    if let SimRec::Banner { app, .. } = &mut st.recs[i] {
        *app = 8;
    }
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "binary: the records equal the C oracle's"),
        "{b:#?}"
    );
}

#[test]
fn a_banner_for_a_reply_with_the_wrong_cookie_fails_against_c() {
    // rmasscan prints the DNS answer of the peer whose reply carries a wrong id (C drops it, proto-dns.c:373).
    let mut sim = Sim::new("b01_banners");
    let st = sim.step_mut("list");
    let at = st
        .recs
        .iter()
        .position(|r| matches!(r, SimRec::Status { ip, port: 53, .. } if ip.octets()[3] == 3))
        .unwrap();
    let ts = st.recs[at].ts();
    st.recs.insert(
        at + 1,
        SimRec::Banner {
            ip: Ipv4Addr::new(198, 18, 0, 3),
            port: 53,
            ts,
            app: 6,
            payload: b"9.18.24".to_vec(),
        },
    );
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "list: the records equal the C oracle's"),
        "{b:#?}"
    );
    assert!(has(&b, FAIL, "banners the scenario declares"), "{b:#?}");
}

#[test]
fn a_stand_that_does_not_echo_the_cookie_is_invalid_not_a_fail() {
    // The peer of the success scenario answers DNS with a wrong id: both scanners drop it, and the stand is wrong.
    fn spoiled(port: u16, ip: Ipv4Addr, probe: &[u8]) -> Option<Vec<u8>> {
        let mut r = scenario_reply(port, ip, probe)?;
        if port == 53 && ip.octets()[3] == 2 {
            r[1] ^= 0xff;
        }
        Some(r)
    }
    let sim = Sim::with_answer("b01_banners", spoiled);
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(
            &b,
            INVALID,
            "the stand answered every probe exactly once with its scenario reply"
        ),
        "{b:#?}"
    );
    assert!(!b.iter().any(|x| x.starts_with(FAIL)), "{b:#?}");
}

#[test]
fn cs_raw_banner_past_the_datagram_needs_only_its_length_and_rmasscans_must_be_the_datagram() {
    // C's raw banner on 11211 with another length than the datagram: the documents differ, and the declared
    // difference no longer explains C (INVALID, which outranks the FAIL).
    let mut sim = Sim::new("b01_banners");
    let st = sim.step_mut("oracle-binary");
    let i = st
        .recs
        .iter()
        .rposition(
            |r| matches!(r, SimRec::Banner { ip, port: 11211, app: 0, .. } if ip.octets()[3] == 2),
        )
        .unwrap();
    if let SimRec::Banner { payload, .. } = &mut st.recs[i] {
        payload.push(0xee);
    }
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(&b, FAIL, "binary: the records equal the C oracle's"),
        "{b:#?}"
    );
    assert!(
        has(&b, INVALID, "deviation udp-raw-past-datagram"),
        "{b:#?}"
    );
    // rmasscan's raw banner on 1900 that is not the datagram (same length): masked against C, but its own rule fails.
    let mut sim = Sim::new("b01_banners");
    let st = sim.step_mut("binary");
    let i = st
        .recs
        .iter()
        .rposition(
            |r| matches!(r, SimRec::Banner { ip, port: 1900, app: 0, .. } if ip.octets()[3] == 5),
        )
        .unwrap();
    if let SimRec::Banner { payload, .. } = &mut st.recs[i] {
        payload[0] ^= 1;
    }
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "rmasscan's raw banner is the reply's datagram"),
        "{b:#?}"
    );
    assert!(!has(&b, FAIL, "the records equal the C oracle's"), "{b:#?}");
}

#[test]
fn a_banner_must_follow_its_own_status_record_with_the_same_time() {
    let mut sim = Sim::new("b01_banners");
    let st = sim.step_mut("binary");
    let i = banner_at(&st.recs, 2, 123, 19);
    if let SimRec::Banner { ts, .. } = &mut st.recs[i] {
        *ts += 1;
    }
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "every banner record follows the status record of its reply"
        ),
        "{b:#?}"
    );
    // A banner moved in front of its status record.
    let mut sim = Sim::new("b01_banners");
    let st = sim.step_mut("list");
    let i = banner_at(&st.recs, 2, 123, 19);
    let r = st.recs.remove(i);
    st.recs.insert(0, r);
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "every banner record follows the status record of its reply"
        ),
        "{b:#?}"
    );
}

#[test]
fn other_probes_than_cs_fail() {
    let mut sim = Sim::new("b01_banners");
    let st = sim.step_mut("binary");
    let k = st
        .frames
        .iter()
        .position(|(_, f)| f.get(6..12) == Some(&SCANNER_MAC[..]) && f.get(23) == Some(&17))
        .unwrap();
    // One payload byte of rmasscan's first probe changed, its checksum fixed: still a well-formed datagram.
    let f = &mut st.frames[k].1;
    let last = f.len() - 1;
    f[last] ^= 0x20;
    let mut l4 = f[34..].to_vec();
    l4[6..8].fill(0);
    let p = ip_frame(
        PEER_MAC,
        SCANNER_MAC,
        SCANNER_IP,
        Ipv4Addr::new(f[30], f[31], f[32], f[33]),
        17,
        l4,
    );
    *f = p;
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "binary: the probes equal the C oracle's"),
        "{b:#?}"
    );
}

#[test]
fn the_case_table_is_the_window_of_the_plan() {
    assert_eq!(
        planned_tags(),
        [
            "b01_banners",
            "b02_rawudp",
            "t01_tcp4",
            "t02_tcp6",
            "t03_teardown",
            "t04_banners_noreset",
            "t05_stateless_rst",
            "t06_noreset",
            "t07_resolve_arp",
            "t08_resolve_ndp"
        ]
    );
    let s = steps("b01_banners").unwrap();
    assert_eq!(
        s.iter().map(|x| x.name).collect::<Vec<_>>(),
        ["binary", "oracle-binary", "list", "oracle-list"]
    );
    assert_eq!(
        s[0].argv,
        [
            "198.18.0.2-198.18.0.5",
            "-sU",
            "-p53,123,137,161,500,1900,5683,11211,16464",
            "--banners",
            "-oB",
            "output.bin",
            "--seed",
            "1",
            "--rate",
            "100",
            "--wait",
            "3",
            "--source-port",
            "40000",
            "--retries",
            "0"
        ]
    );
    assert_eq!(s[0].argv, s[1].argv, "the oracle runs the same argv");
    assert!(
        steps("b02_rawudp").unwrap()[0]
            .argv
            .contains(&"--rawudp".to_owned())
    );
    // Every scenario of the table is one port and one peer; 9 ports x 4 peers.
    assert_eq!(SCENARIOS.len(), 36);
    for port in PORTS {
        for (o, role) in ROLES {
            let sc = scenario(port, role).unwrap();
            assert_eq!(role_of(Ipv4Addr::new(198, 18, 0, o)), Some(role));
            assert!(!sc.about.is_empty());
        }
    }
}

// ------------------------------------------------------------------ the TCP window (4b)

/// The IPv4 stand address 198.18.0.`o`.
fn ip4(o: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 18, 0, o))
}
/// The indices of a step's frames of the scanner on its connection to `.o:port` (the SYN aside).
fn scanner_frames_of(st: &StepSim, o: u8, port: u16) -> Vec<usize> {
    st.frames
        .iter()
        .enumerate()
        .filter(|(_, (_, f))| {
            f.get(6..12) == Some(&SCANNER_MAC[..])
                && tcp_head(f).is_some_and(|h| {
                    peer_of(h.dst) == Some(o) && h.dp == port && h.flags & 0x3f != 0x02
                })
        })
        .map(|(i, _)| i)
        .collect()
}
/// An IPv4 TCP frame of the scanner rebuilt with `payload` (its header kept, the sums set again).
fn with_payload(f: &[u8], payload: &[u8]) -> Vec<u8> {
    let h = tcp_head(f).unwrap();
    let (IpAddr::V4(s), IpAddr::V4(d)) = (h.src, h.dst) else {
        panic!("IPv4 only")
    };
    let off = usize::from(f[34 + 12] >> 4) * 4;
    let mut l4 = f[34..34 + off].to_vec();
    l4.extend(payload);
    ip_frame(PEER_MAC, SCANNER_MAC, s, d, 6, l4)
}
/// A segment of the scanner from `src` to `.o:port` (source port 40000), plain header, valid sums.
fn scanner_seg(src: Ipv4Addr, o: u8, port: u16, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend(SOURCE_PORT.to_be_bytes());
    t.extend(port.to_be_bytes());
    t.extend(seq.to_be_bytes());
    t.extend(ack.to_be_bytes());
    t.extend([0x50, flags, 0x04, 0xb0, 0, 0, 0, 0]);
    ip_frame(
        PEER_MAC,
        SCANNER_MAC,
        src,
        Ipv4Addr::new(198, 18, 0, o),
        6,
        t,
    )
}

#[test]
fn tcp_scenarios_make_the_declared_banners_and_their_scripts_follow_the_parsers() {
    use rmasscan_proto::{StreamAction, TcpBannerSettings, banner_stream};
    let settings = TcpBannerSettings::default();
    for sc in &TCP_SCENARIOS {
        // The product's parsers on the server's whole stream, in the script's segments (C's flush order, B3).
        let r = banner_stream(&settings, sc.port, None, &sc.sends());
        let apps: Vec<&str> = r.records.iter().map(|(a, _)| name(*a)).collect();
        assert_eq!(apps, sc.apps, "{}:{} {}", sc.port, sc.peer, sc.about);
        // Every Recv or Peek waits for one segment of the scanner: a hello (B4, when the server waits) or a send of
        // its parser (FTP AUTH TLS, SMTP EHLO and STARTTLS, POP3 CAPA and STLS, SSH, telnet, VNC).
        let sends = r
            .actions
            .iter()
            .filter(|a| matches!(a, StreamAction::Send(_)))
            .count();
        let hello = usize::from(TCP_HELLO_PORTS.contains(&sc.port) && !sc.server_first());
        let waits = sc
            .steps
            .iter()
            .filter(|s| matches!(s, TcpStep::Recv | TcpStep::Peek))
            .count();
        assert_eq!(waits, sends + hello, "{}:{} {}", sc.port, sc.peer, sc.about);
        assert!(!sc.about.is_empty() && (2..=5).contains(&sc.peer));
        // A split scenario writes more than once before its parser answers.
        if sc.split {
            assert!(sc.sends().len() >= 2, "{}:{}", sc.port, sc.peer);
        }
    }
    // Each of the 11 parsers at least once, and the scenarios the plan names.
    let all: BTreeSet<&str> = TCP_SCENARIOS
        .iter()
        .flat_map(|x| x.apps.iter().copied())
        .collect();
    for app in [
        "http",
        "ftp",
        "smtp",
        "pop",
        "imap",
        "ssh",
        "vnc",
        "telnet",
        "rdp",
        "memcached",
        "minecraft",
    ] {
        assert!(all.contains(app), "{app}");
    }
    let about = |port: u16, peer: u8| tcp_scenario(port, ip4(peer)).unwrap().about;
    assert!(about(3389, 5).contains("silent"));
    assert!(about(21, 5).contains("unknown protocol speaking first"));
    assert!(about(80, 4).contains("HTTP/1.1 without close"));
    assert!(about(80, 5).contains("RST in the middle"));
    assert!(about(25, 2).contains("454") && about(21, 2).contains("530"));
    assert!(about(25, 5).contains("\"220-\" on 25"));
    assert!(TCP_SCENARIOS.iter().filter(|x| x.split).count() >= 4);
    // Every scenario is found at its IPv4 and its IPv6 peer.
    for sc in &TCP_SCENARIOS {
        let v6 = IpAddr::V6(Ipv6Addr::new(
            0xfd00,
            0x198,
            0x18,
            0,
            0,
            0,
            0,
            u16::from(sc.peer),
        ));
        assert_eq!(tcp_scenario(sc.port, v6), Some(sc));
        assert_eq!(tcp_scenario(sc.port, ip4(sc.peer)), Some(sc));
    }
    assert_eq!(tcp_scenario(80, ip4(9)), None);
    // A held connection never has its hello read (Peek, then Hold): its close resets, no socket stays on the 4-tuple.
    for sc in TCP_SCENARIOS.iter().filter(|x| x.held()) {
        assert_eq!(
            sc.steps.first(),
            Some(&TcpStep::Peek),
            "{}:{}",
            sc.port,
            sc.peer
        );
        assert!(
            !sc.steps.contains(&TcpStep::Recv),
            "{}:{}",
            sc.port,
            sc.peer
        );
        assert!(
            TCP_HELLO_PORTS.contains(&sc.port),
            "{}:{}",
            sc.port,
            sc.peer
        );
    }
}

#[test]
fn the_tcp_cases_scan_from_their_own_source_with_one_argv_for_both_scanners() {
    let s = steps("t01_tcp4").unwrap();
    assert_eq!(
        s.iter().map(|x| x.name).collect::<Vec<_>>(),
        ["binary", "oracle-binary", "list", "oracle-list"]
    );
    assert_eq!(
        s[0].argv,
        [
            "198.18.0.2-198.18.0.5",
            "-p21,22,23,25,80,110,143,3389,5900,11211,25565",
            "--banners",
            "--connection-timeout",
            "8",
            "--adapter-ip",
            "198.18.0.9",
            "--router-mac",
            "02-aa-00-00-00-02",
            "-oB",
            "output.bin",
            "--seed",
            "1",
            "--rate",
            "100",
            "--wait",
            "14",
            "--source-port",
            "40000",
            "--retries",
            "0"
        ]
    );
    for tag in planned_tags() {
        let s = steps(tag).unwrap();
        for pair in s.chunks(2) {
            assert_eq!(
                pair[0].argv, pair[1].argv,
                "{tag}: the oracle runs rmasscan's argv"
            );
        }
    }
    let v6 = steps("t02_tcp6").unwrap();
    assert!(
        v6[0]
            .argv
            .starts_with(&["[fd00:198:18::2]-[fd00:198:18::5]".to_owned()])
    );
    for w in [
        ["--adapter-ip", "fd00:198:18::9"],
        ["--router-mac-ipv6", PEER_MAC_ARG],
    ] {
        assert!(v6[0].argv.windows(2).any(|x| x == w), "{w:?}");
    }
    assert!(
        steps("t07_resolve_arp").unwrap()[0]
            .argv
            .contains(&"198.18.0.10".to_owned())
    );
    assert!(
        steps("t08_resolve_ndp").unwrap()[0]
            .argv
            .contains(&"fd00:198:18::a".to_owned())
    );
    let no_banners = steps("t05_stateless_rst").unwrap();
    assert!(!no_banners[0].argv.contains(&"--banners".to_owned()));
    assert!(
        steps("t06_noreset").unwrap()[0]
            .argv
            .contains(&"--noreset".to_owned())
    );
    let t04 = &steps("t04_banners_noreset").unwrap()[0].argv;
    assert!(t04.contains(&"--banners".to_owned()) && t04.contains(&"--noreset".to_owned()));
    // The responder of a TCP case: the scenario sockets on both families and the heartbeat for the wait and 8 s.
    let r = tcp_responder_args(&tcp_case("t01_tcp4").unwrap());
    let after = |k: &str| r[r.iter().position(|x| x == k).unwrap() + 1].clone();
    assert_eq!(after("--tcp-answer"), "banners");
    assert!(after("--tcp-ips").ends_with("fd00:198:18::5"));
    assert_eq!(
        after("--tcp-ports"),
        "21,22,23,25,80,110,143,3389,5900,11211,25565"
    );
    assert_eq!(after("--heartbeat-iface"), "veth-b");
    assert_eq!(after("--heartbeat-dst"), "02:aa:00:00:00:01");
    assert_eq!(after("--heartbeat-secs"), "22");
    // expect.json of a TCP case names its source; a UDP case's is 4a's (no `tcp` key).
    let e = expect("t07_resolve_arp").unwrap();
    assert_eq!(
        e.tcp
            .as_ref()
            .map(|x| (x.source.as_str(), x.neighbour_entry)),
        Some(("198.18.0.10", false))
    );
    assert!(
        !serde_json::to_string(&expect("b01_banners").unwrap())
            .unwrap()
            .contains("tcp")
    );
}

/// A TCP case judged alone; `edit` changes the generated evidence first.
fn judge_tcp(tag: &'static str, edit: impl FnOnce(&mut Sim)) -> (String, Vec<String>) {
    let mut sim = Sim::new(tag);
    edit(&mut sim);
    judge_one(&sim)
}

#[test]
fn every_tcp_case_passes_on_the_products_own_stack() {
    for c in TCP_CASES {
        let (v, b) = judge_tcp(c.tag, |_| {});
        assert_eq!(v, PASS, "{}: {b:#?}", c.tag);
    }
}

#[test]
fn a_lost_tcp_banner_of_rmasscan_fails_against_c_and_its_scenario() {
    let (v, b) = judge_tcp("t01_tcp4", |sim| {
        let st = sim.step_mut("list");
        let i = st
            .recs
            .iter()
            .position(
                |r| matches!(r, SimRec::TcpBanner { ip, port: 80, app: 17, .. } if *ip == ip4(2)),
            )
            .unwrap();
        st.recs.remove(i);
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "list: the records equal the C oracle's"),
        "{b:#?}"
    );
    assert!(
        has(&b, FAIL, "applications its scenario declares"),
        "{b:#?}"
    );
}

#[test]
fn an_extra_unknown_tcp_banner_of_rmasscan_fails() {
    let (v, b) = judge_tcp("t01_tcp4", |sim| {
        let st = sim.step_mut("binary");
        let i = st
            .recs
            .iter()
            .position(|r| matches!(r, SimRec::TcpBanner { ip, port: 21, .. } if *ip == ip4(2)))
            .unwrap();
        let SimRec::TcpBanner { ts, ttl, .. } = st.recs[i].clone() else {
            unreachable!()
        };
        st.recs.insert(
            i + 1,
            SimRec::TcpBanner {
                ip: ip4(2),
                port: 21,
                ts,
                app: 1,
                ttl,
                payload: b"530 Please login".to_vec(),
            },
        );
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "binary: the records equal the C oracle's"),
        "{b:#?}"
    );
    assert!(
        has(&b, FAIL, "applications its scenario declares"),
        "{b:#?}"
    );
}

#[test]
fn another_hello_than_cs_fails_and_so_does_a_late_one() {
    // The hello to 198.18.0.2:80 with another method: the connection's segments are no longer C's.
    let (v, b) = judge_tcp("t01_tcp4", |sim| {
        let st = sim.step_mut("binary");
        let i = scanner_frames_of(st, 2, 80)
            .into_iter()
            .find(|i| !tcp_head(&st.frames[*i].1).unwrap().payload.is_empty())
            .unwrap();
        let mut p = tcp_head(&st.frames[i].1).unwrap().payload;
        p[..3].copy_from_slice(b"PUT");
        st.frames[i].1 = with_payload(&st.frames[i].1, &p);
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "binary: every connection's scanner segments equal the C oracle's"
        ),
        "{b:#?}"
    );
    // The same hello 2 s later than the window allows.
    let (v, b) = judge_tcp("t01_tcp4", |sim| {
        let st = sim.step_mut("list");
        let i = scanner_frames_of(st, 3, 80)
            .into_iter()
            .find(|i| !tcp_head(&st.frames[*i].1).unwrap().payload.is_empty())
            .unwrap();
        st.frames[i].0 += 2.0;
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "list: the hello leaves 1-3.5 s after the SYN-ACK"),
        "{b:#?}"
    );
}

#[test]
fn a_frame_of_a_connection_after_its_lifetime_rst_fails() {
    let (v, b) = judge_tcp("t01_tcp4", |sim| {
        let st = sim.step_mut("list");
        let mine = scanner_frames_of(st, 4, 80);
        let rst = *mine
            .iter()
            .find(|i| tcp_head(&st.frames[**i].1).unwrap().flags == 0x04)
            .unwrap();
        let ack = st.frames[mine[0]].1.clone();
        let t = st.frames[rst].0 + 0.1;
        st.frames.insert(rst + 1, (t, ack));
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "list: no frame of a connection after the connection was destroyed"
        ),
        "{b:#?}"
    );
}

#[test]
fn rmasscan_without_its_stateless_rst_fails() {
    let (v, b) = judge_tcp("t05_stateless_rst", |sim| {
        let st = sim.step_mut("list");
        st.frames.retain(|(_, f)| {
            !(f.get(6..12) == Some(&SCANNER_MAC[..])
                && tcp_head(f).is_some_and(|h| h.flags == 0x04))
        });
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "list: exactly one stateless RST per connection"),
        "{b:#?}"
    );
    assert!(
        has(
            &b,
            FAIL,
            "list: every connection's scanner segments equal the C oracle's"
        ),
        "{b:#?}"
    );
}

#[test]
fn a_rst_of_rmasscan_under_noreset_fails() {
    let (v, b) = judge_tcp("t06_noreset", |sim| {
        let st = sim.step_mut("list");
        let (t, syn) = st
            .frames
            .iter()
            .find(|(_, f)| {
                f.get(6..12) == Some(&SCANNER_MAC[..])
                    && tcp_head(f)
                        .is_some_and(|h| h.flags == 0x02 && h.dp == 80 && peer_of(h.dst) == Some(2))
            })
            .map(|(t, f)| (*t, tcp_head(f).unwrap()))
            .unwrap();
        st.frames.push((
            t + 0.002,
            scanner_seg(TCP_SOURCE, 2, 80, syn.seq.wrapping_add(1), 0, 0x04),
        ));
        st.frames.sort_by(|a, b| a.0.total_cmp(&b.0));
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "list: --noreset: no RST of the scanner"),
        "{b:#?}"
    );
}

#[test]
fn banners_with_noreset_still_need_the_lifetime_rst() {
    let (v, b) = judge_tcp("t04_banners_noreset", |sim| {
        let st = sim.step_mut("list");
        st.frames.retain(|(_, f)| {
            !(f.get(6..12) == Some(&SCANNER_MAC[..])
                && tcp_head(f).is_some_and(|h| h.flags & 0x04 != 0))
        });
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "list: the lifetime RST leaves 8-12 s after the SYN-ACK"
        ),
        "{b:#?}"
    );
    assert!(has(&b, FAIL, "held open and 0 RSTs"), "{b:#?}");
}

#[test]
fn a_udp_banner_apart_from_its_reply_fails_m1() {
    let mut sim = Sim::new("b01_banners");
    let st = sim.step_mut("binary");
    let i = banner_at(&st.recs, 2, 123, 19);
    let next_status = (i + 1..st.recs.len())
        .find(|k| matches!(st.recs[*k], SimRec::Status { .. }))
        .unwrap();
    let r = st.recs.remove(i);
    st.recs.insert(next_status, r);
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "binary: every UDP banner record comes right after"
        ),
        "{b:#?}"
    );
    assert!(!has(&b, FAIL, "the records equal the C oracle's"), "{b:#?}");
}

#[test]
fn a_wrong_list_text_of_rmasscans_raw_banner_fails_m2() {
    let mut sim = Sim::new("b01_banners");
    let st = sim.step_mut("list");
    let i = st
        .recs
        .iter()
        .rposition(
            |r| matches!(r, SimRec::Banner { ip, port: 1900, app: 0, .. } if ip.octets()[3] == 2),
        )
        .unwrap();
    if let SimRec::Banner { payload, .. } = &mut st.recs[i] {
        payload[0] ^= 0x20;
    }
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "list: rmasscan's -oL text of the raw banner on 1900 and 11211"
        ),
        "{b:#?}"
    );
    // udp-raw-past-datagram keeps it out of the comparison with C: only M2 sees it.
    assert!(!has(&b, FAIL, "the records equal the C oracle's"), "{b:#?}");
}

#[test]
fn a_resolve_case_needs_one_answer_in_cs_form_per_request_of_the_peer() {
    let arp_reply =
        |f: &[u8]| f.get(12..14) == Some(&[8, 6][..]) && f.get(20..22) == Some(&[0, 2][..]);
    let (v, b) = judge_tcp("t07_resolve_arp", |sim| {
        sim.step_mut("list").frames.retain(|(_, f)| !arp_reply(f));
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "list: the scanner answers every request of the peer for its source"
        ),
        "{b:#?}"
    );
    assert!(
        has(
            &b,
            FAIL,
            "the ARP replies for the source equal the C oracle's"
        ),
        "{b:#?}"
    );
    // An answer that is not C's form: the reply with another sender address.
    let (v, b) = judge_tcp("t08_resolve_ndp", |sim| {
        let st = sim.step_mut("list");
        let i = st
            .frames
            .iter()
            .position(|(_, f)| {
                iv::pkt(f).is_some_and(|p| p.proto == 58 && p.l4.first() == Some(&136))
            })
            .unwrap();
        st.frames[i].1[54 + 4] = 0x20;
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "Neighbor Advertisement not in C's form"),
        "{b:#?}"
    );
    // A peer that never asked (its entry was not flushed): the stand did not run the case.
    let request = |f: &[u8]| {
        (f.get(12..14) == Some(&[8, 6][..]) && f.get(20..22) == Some(&[0, 1][..]))
            || iv::pkt(f).is_some_and(|p| p.proto == 58 && p.l4.first() == Some(&135))
    };
    let (v, b) = judge_tcp("t07_resolve_arp", |sim| {
        for st in &mut sim.steps {
            st.frames.retain(|(_, f)| !request(f) && !arp_reply(f));
        }
    });
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(&b, INVALID, "the peer resolved the source at least once"),
        "{b:#?}"
    );
}

#[test]
fn cs_scrubbed_tcb_segment_is_its_named_deviation_and_rmasscans_a_fail() {
    let scrubbed = || {
        let mut t = Vec::new();
        t.extend(0xffffu16.to_be_bytes());
        t.extend(0xffffu16.to_be_bytes());
        t.extend([0, 0, 0, 1, 0, 0, 0, 2, 0x50, 0x10, 0x04, 0xb0, 0, 0, 0, 0]);
        ip_frame(
            PEER_MAC,
            SCANNER_MAC,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::BROADCAST,
            6,
            t,
        )
    };
    let add = |st: &mut StepSim| {
        let t = st.frames[st.frames.len() / 2].0;
        st.frames.push((t, scrubbed()));
        st.frames.sort_by(|a, b| a.0.total_cmp(&b.0));
    };
    let mut sim = Sim::new("t01_tcp4");
    add(sim.step_mut("oracle-list"));
    let root = scratch();
    sim.write(&root);
    fs::write(root.join(TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = verify_dir(&root);
    let run = run_of(&res, "t01_tcp4").clone();
    fs::remove_dir_all(&root).unwrap();
    assert_eq!(run["verdict"], PASS, "{:#?}", bad(&run));
    let dev = array(&run["notes"]["deviations"]);
    assert!(
        dev.iter()
            .any(|d| d["name"] == "no-frame-from-destroyed-tcb"
                && s(&d["observed"]).starts_with("1 segments of C")),
        "{dev:?}"
    );
    let (v, b) = judge_tcp("t01_tcp4", |sim| add(sim.step_mut("list")));
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "list: no segment of a scrubbed TCB"),
        "{b:#?}"
    );
}

#[test]
fn a_heartbeat_gap_or_a_tcp_frame_from_another_source_is_never_a_pass() {
    // C's receive loop turns only on frames: a stand whose heartbeat stopped is INVALID.
    let (v, b) = judge_tcp("t05_stateless_rst", |sim| {
        let st = sim.step_mut("oracle-list");
        let first = st
            .frames
            .iter()
            .find(|(_, f)| f.get(6..12) == Some(&SCANNER_MAC[..]) && tcp_head(f).is_some())
            .unwrap()
            .0;
        st.frames.retain(|(t, f)| {
            !(f.get(14..)
                .is_some_and(|x| x.starts_with(HEARTBEAT_PAYLOAD))
                && *t > first + 0.5
                && *t < first + 2.5)
        });
    });
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(
            &b,
            INVALID,
            "oracle-list: the peer heartbeat covered the scan"
        ),
        "{b:#?}"
    );
    // A segment of the scanner from an address that is no source of the window: a safety finding.
    let (v, b) = judge_tcp("t03_teardown", |sim| {
        let st = sim.step_mut("binary");
        let t = st.frames[st.frames.len() / 2].0;
        st.frames.push((
            t,
            scanner_seg(Ipv4Addr::new(198, 18, 0, 7), 4, 80, 1, 1, 0x10),
        ));
        st.frames.sort_by(|a, b| a.0.total_cmp(&b.0));
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "no frame of the scanner on the binary capture to an address off the stand"
        ),
        "{b:#?}"
    );
}

#[test]
fn cs_forced_exit_with_connections_alive_leaves_no_reference_for_their_banners() {
    // t03: C killed by its own forced exit never flushed the held connections: INVALID, not a FAIL of rmasscan.
    let (v, b) = judge_tcp("t03_teardown", |sim| {
        let st = sim.step_mut("oracle-binary");
        st.stderr
            .push_str("[-] Passed the wait window but still running, forcing exit...\n");
        st.complete = false;
        st.recs
            .retain(|r| !matches!(r, SimRec::TcpBanner { ip, port: 80, .. } if *ip == ip4(4)));
    });
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(
            &b,
            INVALID,
            "oracle-binary: C flushed its connections alive at the end of the scan"
        ),
        "{b:#?}"
    );
    // A forced exit after every connection ended changes nothing.
    let (v, b) = judge_tcp("t01_tcp4", |sim| {
        let st = sim.step_mut("oracle-list");
        st.stderr
            .push_str("[-] Passed the wait window but still running, forcing exit...\n");
        st.complete = false;
    });
    assert_eq!(v, PASS, "{b:#?}");
}

#[test]
fn a_peer_that_keeps_time_wait_sockets_is_no_tcp_stand() {
    let (v, b) = judge_tcp("t05_stateless_rst", |sim| {
        sim.extra.push((
            PEER_TCP_JSON.into(),
            serde_json::to_vec(&PeerTcp {
                tcp_max_tw_buckets: "262144".into(),
            })
            .unwrap(),
        ));
    });
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(
            &b,
            INVALID,
            "peer-tcp.json: the peer namespace keeps no TIME_WAIT socket"
        ),
        "{b:#?}"
    );
}

#[test]
fn ipv6_kernel_noise_on_a_udp_step_is_the_stands_not_the_scanners() {
    // The banners stand raises IPv6 on its veth pair: an MLD report of the scanner namespace kernel inside a UDP step
    // is the stand's noise (INVALID), never a frame of rmasscan (FAIL).
    let mut sim = Sim::new("b01_banners");
    let st = sim.step_mut("binary");
    let t = st.frames[st.frames.len() / 2].0;
    let ll: Ipv6Addr = capture::IPV6_SCANNER_LL.parse().unwrap();
    let mld = v6_frame(
        [0x33, 0x33, 0, 0, 0, 0x16],
        SCANNER_MAC,
        ll,
        "ff02::16".parse().unwrap(),
        58,
        1,
        vec![143, 0, 0, 0, 0, 0, 0, 0],
    );
    st.frames.push((t, mld));
    st.frames.sort_by(|a, b| a.0.total_cmp(&b.0));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(
            &b,
            INVALID,
            "binary: no IPv6 kernel noise of the scanner namespace"
        ),
        "{b:#?}"
    );
    assert!(!b.iter().any(|x| x.starts_with(FAIL)), "{b:#?}");
}
