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
        tests::{
            LAB_ID, Sim as AdSim, T0, TEARDOWN, marker, peer_who_has, responder_reply,
            status_fragments,
        },
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
/// The peer namespace as the suite names it (`wire-lab.sh`: `wl-peer-<run id>`).
const PEER_NS: &str = "wl-peer-41-42";

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
    /// `neigh-flush.json` of a step of a resolve case.
    pub(crate) flush: Option<NeighFlush>,
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
                flush: None,
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
            if let Some(x) = &s.flush {
                f.push((format!("{n}/{NEIGH_FLUSH_JSON}"), json_(x)));
            }
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
    // The quiet control has no heartbeat: its first beat lies past the end.
    let mut beat = if c.quiet { f64::INFINITY } else { t0 + 0.3 };
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
                flush: c.resolve.then(|| NeighFlush {
                    argv: neigh_flush_argv(PEER_NS, c.source()),
                    rc: 0,
                }),
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
/// One case judged in a whole directory (every other planned case as the generator makes it, so PASS), with what the
/// directory makes of it.
struct Judged {
    verdict: String,
    bad: Vec<String>,
    behaviour_fail: bool,
    overall: String,
}
fn judge_full(sim: &Sim) -> Judged {
    let root = scratch();
    sim.write(&root);
    for tag in planned_tags().into_iter().filter(|t| *t != sim.tag) {
        Sim::new(tag).write(&root);
    }
    fs::write(root.join(TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = verify_dir(&root);
    let run = run_of(&res, sim.tag).clone();
    fs::remove_dir_all(&root).unwrap();
    Judged {
        verdict: s(&run["verdict"]).to_owned(),
        bad: bad(&run),
        behaviour_fail: run["behaviour_fail"] == true,
        overall: s(&res["overall"]).to_owned(),
    }
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
fn the_udp_cases_judge_the_scanners_arp_replies_like_the_protocols_window() {
    // The UDP cases take the scanner-side classes of the protocols window, its own-frame checks included: a C-form ARP
    // reply of the scanner answering a who-has of the peer passes, the same reply without a request fails rmasscan's
    // step and makes the oracle's INVALID (no stateless RST here: --banners, and no TCP).
    let st = stand();
    let req = peer_who_has(&st);
    let ans = responder_reply(&st, &req);
    for (step, want) in [("binary", FAIL), ("oracle-binary", INVALID)] {
        let mut sim = Sim::new("b01_banners");
        let s = sim.step_mut(step);
        let t = s.frames[2].0 + 0.0001;
        s.frames
            .extend([(t, req.clone()), (t + 0.00005, ans.clone())]);
        s.frames.sort_by(|a, b| a.0.total_cmp(&b.0));
        let (v, b) = judge_one(&sim);
        assert_eq!(v, PASS, "{step}: {b:#?}");
        let mut sim = Sim::new("b01_banners");
        let s = sim.step_mut(step);
        let t = s.frames[2].0 + 0.0001;
        s.frames.push((t, ans.clone()));
        s.frames.sort_by(|a, b| a.0.total_cmp(&b.0));
        let (v, b) = judge_one(&sim);
        assert_eq!(v, want, "{step}: {b:#?}");
        assert!(
            b.iter()
                .any(|x| x.contains("arp_reply_for_scanner 1 of at most 0"))
                && b.iter().any(|x| {
                    x.contains("the scanner answers the peer's who-has for its address")
                        && x.contains("before any who-has")
                }),
            "{step}: {b:#?}"
        );
    }
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
    // difference no longer explains C. Its condition is judged before the comparison (I2): the comparison is INVALID,
    // never a FAIL of rmasscan, and the directory is INVALID.
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
    let j = judge_full(&sim);
    assert_eq!(j.verdict, INVALID, "{:#?}", j.bad);
    assert!(
        has(&j.bad, INVALID, "binary: the records equal the C oracle's"),
        "{:#?}",
        j.bad
    );
    assert!(
        has(&j.bad, INVALID, "deviation udp-raw-past-datagram"),
        "{:#?}",
        j.bad
    );
    assert!(!j.behaviour_fail, "{:#?}", j.bad);
    assert_eq!(j.overall, INVALID);
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
            "t08_resolve_ndp",
            "t09_quiet_timers"
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
        if tcp_case(tag).is_some_and(|c| c.quiet) {
            // The quiet control (M3): rmasscan alone, without the heartbeat.
            assert_eq!(s.len(), 1, "{tag}");
            assert_eq!(s[0].who, Who::Rmasscan, "{tag}");
            continue;
        }
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
    // t03: C killed by its own forced exit never flushed the held connections: INVALID, not a FAIL of rmasscan. The
    // rule is judged before the comparisons with C (I2): the comparison of the records is INVALID too, the run carries
    // no behaviour FAIL, and the directory is INVALID.
    let mut sim = Sim::new("t03_teardown");
    let st = sim.step_mut("oracle-binary");
    st.stderr
        .push_str("[-] Passed the wait window but still running, forcing exit...\n");
    st.complete = false;
    st.recs
        .retain(|r| !matches!(r, SimRec::TcpBanner { ip, port: 80, .. } if *ip == ip4(4)));
    let j = judge_full(&sim);
    let b = &j.bad;
    assert_eq!(j.verdict, INVALID, "{b:#?}");
    assert!(
        has(
            b,
            INVALID,
            "oracle-binary: C flushed its connections alive at the end of the scan"
        ),
        "{b:#?}"
    );
    assert!(
        has(b, INVALID, "binary: the records equal the C oracle's"),
        "{b:#?}"
    );
    assert!(!j.behaviour_fail, "{b:#?}");
    assert_eq!(j.overall, INVALID, "{b:#?}");
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

// ------------------------------------------------------------------ TCP: one rule at a time (review I1-I3, M1-M8)

/// The IPv6 stand address fd00:198:18::`g`.
fn ip6(g: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0x198, 0x18, 0, 0, 0, 0, g))
}
/// A step's capture as the verifier takes it apart.
fn view_of(c: &TcpCase, st: &StepSim) -> TcpView {
    tcp_view(c, &st.frames, &stand())
}
fn resort(st: &mut StepSim) {
    st.frames.sort_by(|a, b| a.0.total_cmp(&b.0));
}
/// The indices of a step's TCP frames on the connection to `peer:port`: the scanner's (its SYN aside) or the peer's.
fn conn_frames(st: &StepSim, peer: IpAddr, port: u16, scanner: bool) -> Vec<usize> {
    let mac = if scanner { SCANNER_MAC } else { PEER_MAC };
    st.frames
        .iter()
        .enumerate()
        .filter(|(_, (_, f))| {
            f.get(6..12) == Some(&mac[..])
                && tcp_head(f).is_some_and(|h| {
                    if scanner {
                        h.dst == peer && h.dp == port && h.flags & 0x3f != 0x02
                    } else {
                        h.src == peer && h.sp == port
                    }
                })
        })
        .map(|(i, _)| i)
        .collect()
}
/// The end of a frame's IP packet (an Ethernet trailer left out) and the start of its upper layer.
fn ip_bounds(g: &[u8]) -> (usize, usize) {
    if g[12..14] == [0x86, 0xdd] {
        (54 + usize::from(u16::from_be_bytes([g[18], g[19]])), 54)
    } else {
        (
            14 + usize::from(u16::from_be_bytes([g[16], g[17]])),
            14 + usize::from(g[14] & 0x0f) * 4,
        )
    }
}
/// Sets the IPv4 header checksum (IPv4) and the TCP or ICMPv6 checksum of a frame again, by hand.
fn set_sums(g: &mut [u8]) {
    let sum16 = crate::protocols_verify::tests::sum16;
    let (end, l4) = ip_bounds(g);
    let v6 = g[12..14] == [0x86, 0xdd];
    let mut pseudo = if v6 {
        let mut p = g[22..54].to_vec();
        p.extend(((end - l4) as u32).to_be_bytes());
        p.extend([0, 0, 0, g[20]]);
        p
    } else {
        g[24..26].fill(0);
        let h = sum16(&g[14..l4], 0);
        g[24..26].copy_from_slice(&h.to_be_bytes());
        let mut p = g[26..34].to_vec();
        p.extend([0, g[23]]);
        p.extend(((end - l4) as u16).to_be_bytes());
        p
    };
    let proto = if v6 { g[20] } else { g[23] };
    let at = l4 + if proto == 6 { 16 } else { 2 };
    g[at..at + 2].fill(0);
    pseudo.extend(&g[l4..end]);
    let v = sum16(&pseudo, 0);
    g[at..at + 2].copy_from_slice(&v.to_be_bytes());
}
/// A TCP frame (either family) with some fields changed, its lengths and sums set again, the rest of it kept.
fn tcp_rebuilt(
    f: &[u8],
    seq: Option<u32>,
    ack: Option<u32>,
    flags: Option<u8>,
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let (end, l4) = ip_bounds(f);
    let off = usize::from(f[l4 + 12] >> 4) * 4;
    let mut g = f[..l4 + off].to_vec();
    if let Some(x) = seq {
        g[l4 + 4..l4 + 8].copy_from_slice(&x.to_be_bytes());
    }
    if let Some(x) = ack {
        g[l4 + 8..l4 + 12].copy_from_slice(&x.to_be_bytes());
    }
    if let Some(x) = flags {
        g[l4 + 13] = x;
    }
    g.extend(payload.unwrap_or(&f[l4 + off..end]));
    let n = g.len();
    if g[12..14] == [0x86, 0xdd] {
        g[18..20].copy_from_slice(&((n - 54) as u16).to_be_bytes());
    } else {
        g[16..18].copy_from_slice(&((n - 14) as u16).to_be_bytes());
    }
    set_sums(&mut g);
    g
}
/// A data segment of the peer cut in two at `at` (the second one `at` bytes on), both at its time.
fn split_peer_segment(st: &mut StepSim, i: usize, at: usize) {
    let (t, f) = st.frames[i].clone();
    let h = tcp_head(&f).unwrap();
    st.frames[i].1 = tcp_rebuilt(&f, None, None, None, Some(&h.payload[..at]));
    let second = tcp_rebuilt(
        &f,
        Some(h.seq.wrapping_add(at as u32)),
        None,
        None,
        Some(&h.payload[at..]),
    );
    st.frames.insert(i + 1, (t, second));
}
fn is_request(f: &[u8]) -> bool {
    (f.get(12..14) == Some(&[8, 6][..]) && f.get(20..22) == Some(&[0, 1][..]))
        || iv::pkt(f).is_some_and(|p| p.proto == 58 && p.l4.first() == Some(&135))
}
fn is_answer(f: &[u8]) -> bool {
    (f.get(12..14) == Some(&[8, 6][..]) && f.get(20..22) == Some(&[0, 2][..]))
        || iv::pkt(f).is_some_and(|p| p.proto == 58 && p.l4.first() == Some(&136))
}
/// A resolve step as a live run leaves it when the peer never took the scanner's answer: the peer asks three times,
/// one second apart (each followed by `answer` applied to the scanner's answer, or by nothing), never sends its
/// SYN-ACK (it has no MAC for the source), and the scanner writes nothing.
fn starved(st: &mut StepSim, answer: Option<fn(&mut Vec<u8>)>) {
    let (t, q) = st
        .frames
        .iter()
        .find(|(_, f)| is_request(f))
        .cloned()
        .unwrap();
    let a = st
        .frames
        .iter()
        .find(|(_, f)| is_answer(f))
        .cloned()
        .unwrap()
        .1;
    st.frames.retain(|(_, f)| {
        !is_request(f) && !is_answer(f) && tcp_head(f).is_none_or(|h| h.flags & 0x3f == 0x02)
    });
    for k in 0..3 {
        let at = t + f64::from(k);
        st.frames.push((at, q.clone()));
        if let Some(edit) = answer {
            let mut x = a.clone();
            edit(&mut x);
            st.frames.push((at + 0.0003, x));
        }
    }
    resort(st);
    st.doc = Some(Vec::new());
    st.recs.clear();
}
fn no(b: &[String], result: &str) -> bool {
    !b.iter().any(|x| x.starts_with(result))
}

#[test]
fn a_request_rmasscan_leaves_unanswered_is_its_behaviour_fail_never_the_stands() {
    // I1, t07 as a live run leaves it: rmasscan never answers the who-has, the peer asks three times and never sends
    // its SYN-ACK. The unanswered SYN is the scanner's doing: a FAIL with behaviour, no INVALID anywhere.
    let c = tcp_case("t07_resolve_arp").unwrap();
    let mut sim = Sim::new(c.tag);
    let st = sim.step_mut("list");
    starved(st, None);
    st.stderr = tcp_rm_stderr(&c, (1, 0, 0));
    let j = judge_full(&sim);
    let b = &j.bad;
    assert_eq!(j.verdict, FAIL, "{b:#?}");
    assert!(
        has(
            b,
            FAIL,
            "list: the scanner answers every request of the peer for its source"
        ),
        "{b:#?}"
    );
    assert!(has(b, FAIL, "0 answers to request 0"), "{b:#?}");
    assert!(no(b, INVALID), "{b:#?}");
    assert!(j.behaviour_fail && j.overall == FAIL, "{b:#?}");
    // The same next to a stand fault of the step's own (a heartbeat gap): the scanner's check comes before the
    // stand's, so its FAIL keeps its behaviour and the directory FAILs although the run is INVALID.
    let mut sim = Sim::new(c.tag);
    let st = sim.step_mut("list");
    starved(st, None);
    st.stderr = tcp_rm_stderr(&c, (1, 0, 0));
    let first = st
        .frames
        .iter()
        .find(|(_, f)| tcp_head(f).is_some())
        .unwrap()
        .0;
    st.frames.retain(|(t, f)| {
        !(f.get(14..)
            .is_some_and(|x| x.starts_with(HEARTBEAT_PAYLOAD))
            && *t > first + 0.5
            && *t < first + 3.5)
    });
    let j = judge_full(&sim);
    let b = &j.bad;
    assert_eq!(j.verdict, INVALID, "{b:#?}");
    assert!(
        has(b, INVALID, "list: the peer heartbeat covered the scan"),
        "{b:#?}"
    );
    assert!(
        has(
            b,
            FAIL,
            "list: the scanner answers every request of the peer for its source"
        ),
        "{b:#?}"
    );
    assert!(j.behaviour_fail && j.overall == FAIL, "{b:#?}");
}

#[test]
fn an_answer_the_peer_drops_is_rmasscans_fail_and_cs_silence_its_own_invalid() {
    let c = tcp_case("t08_resolve_ndp").unwrap();
    let hop64: fn(&mut Vec<u8>) = |f| f[21] = 64;
    // I1: rmasscan's NA with hop limit 64 (RFC 4861 §7.1.2: the Linux peer drops it), as a live run leaves it.
    let mut sim = Sim::new(c.tag);
    let st = sim.step_mut("list");
    starved(st, Some(hop64));
    st.stderr = tcp_rm_stderr(&c, (1, 0, 0));
    let j = judge_full(&sim);
    let b = &j.bad;
    assert_eq!(j.verdict, FAIL, "{b:#?}");
    assert!(has(b, FAIL, "hop limit 255"), "{b:#?}");
    assert!(has(b, FAIL, "the peer asked 3 times"), "{b:#?}");
    assert!(no(b, INVALID), "{b:#?}");
    assert!(j.behaviour_fail && j.overall == FAIL, "{b:#?}");
    // C that never answers the solicitation (the accepted concern: its responder answers by a stale opcode) and a
    // correct rmasscan: C's step is INVALID, nothing of rmasscan's FAILs, the directory is INVALID.
    let mut sim = Sim::new(c.tag);
    starved(sim.step_mut("oracle-list"), None);
    let j = judge_full(&sim);
    let b = &j.bad;
    assert_eq!(j.verdict, INVALID, "{b:#?}");
    assert!(
        has(
            b,
            INVALID,
            "oracle-list: the scanner answers every request of the peer for its source"
        ),
        "{b:#?}"
    );
    assert!(no(b, FAIL), "{b:#?}");
    assert!(!j.behaviour_fail && j.overall == INVALID, "{b:#?}");
    // Both: rmasscan's FAIL keeps its behaviour whatever C did (its step comes first): the directory FAILs.
    let mut sim = Sim::new(c.tag);
    let st = sim.step_mut("list");
    starved(st, Some(hop64));
    st.stderr = tcp_rm_stderr(&c, (1, 0, 0));
    starved(sim.step_mut("oracle-list"), None);
    let j = judge_full(&sim);
    let b = &j.bad;
    assert!(
        has(b, FAIL, "list: the scanner answers every request"),
        "{b:#?}"
    );
    assert!(j.behaviour_fail && j.overall == FAIL, "{b:#?}");
    // C silent and rmasscan's document without the scenario's last banner: rmasscan's own banner checks come in its
    // step, before C's INVALID, so the FAIL keeps its behaviour.
    let mut sim = Sim::new(c.tag);
    let st = sim.step_mut("list");
    let last = st
        .recs
        .iter()
        .rposition(|r| matches!(r, SimRec::TcpBanner { .. }))
        .unwrap();
    st.recs.remove(last);
    starved(sim.step_mut("oracle-list"), None);
    let j = judge_full(&sim);
    let b = &j.bad;
    assert!(
        has(b, FAIL, "list: each connection's banners carry"),
        "{b:#?}"
    );
    assert!(j.behaviour_fail && j.overall == FAIL, "{b:#?}");
}

#[test]
fn a_second_request_after_an_answer_in_form_is_the_scanners() {
    // t07: the peer asks again one second after rmasscan's answer, which was in C's form: the peer did not take it.
    let (v, b) = judge_tcp("t07_resolve_arp", |sim| {
        let st = sim.step_mut("list");
        let (t, q) = st
            .frames
            .iter()
            .find(|(_, f)| is_request(f))
            .cloned()
            .unwrap();
        let (ta, a) = st
            .frames
            .iter()
            .find(|(_, f)| is_answer(f))
            .cloned()
            .unwrap();
        st.frames.push((t + 1.0, q));
        st.frames.push((ta + 1.0, a));
        resort(st);
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(b.as_slice(), FAIL, "the peer asked 2 times"), "{b:#?}");
}

#[test]
fn every_field_of_the_answer_to_the_peers_request_is_judged() {
    type Edit = fn(&mut Vec<u8>);
    let cases: [(&str, &str, Edit); 9] = [
        ("t08_resolve_ndp", "hop limit 255", |f| f[21] = 64),
        ("t08_resolve_ndp", "a right checksum", |f| f[56] ^= 1),
        ("t08_resolve_ndp", "code 0", |f| {
            f[55] = 0x55;
            set_sums(f);
        }),
        (
            "t08_resolve_ndp",
            "the scanner MAC as target link-layer address",
            |f| {
                f[85] ^= 1;
                set_sums(f);
            },
        ),
        ("t08_resolve_ndp", "ICMPv6 length 32", |f| {
            f.extend([0u8; 8]);
            let n = (f.len() - 54) as u16;
            f[18..20].copy_from_slice(&n.to_be_bytes());
            set_sums(f);
        }),
        ("t08_resolve_ndp", "to the requester's MAC", |f| f[4] ^= 1),
        ("t07_resolve_arp", "length 60", |f| f.truncate(42)),
        ("t07_resolve_arp", "zero padding", |f| f[59] = 1),
        ("t07_resolve_arp", "to the requester's MAC", |f| f[4] ^= 1),
    ];
    for (tag, field, edit) in cases {
        let (v, b) = judge_tcp(tag, |sim| {
            let st = sim.step_mut("list");
            let i = st.frames.iter().position(|(_, f)| is_answer(f)).unwrap();
            edit(&mut st.frames[i].1);
        });
        assert_eq!(v, FAIL, "{tag} {field}: {b:#?}");
        assert!(
            has(
                &b,
                FAIL,
                "list: the scanner answers every request of the peer for its source"
            ) && has(&b, FAIL, field),
            "{tag} {field}: {b:#?}"
        );
    }
}

#[test]
fn after_the_resolution_the_connection_must_carry_its_stream() {
    // t07: the answer is right but the connection never carried the scenario's data (nor banners).
    let (v, b) = judge_tcp("t07_resolve_arp", |sim| {
        let st = sim.step_mut("list");
        st.frames.retain(|(_, f)| {
            !(f.get(6..12) == Some(&PEER_MAC[..])
                && tcp_head(f).is_some_and(|h| !h.payload.is_empty()))
        });
        st.recs.retain(|r| !matches!(r, SimRec::TcpBanner { .. }));
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "list: after the resolution the connection opens and carries its scenario's stream"
        ),
        "{b:#?}"
    );
}

#[test]
fn a_stray_frame_is_put_to_the_side_that_began_it() {
    let src = IpAddr::V4(TCP_SOURCE);
    // rmasscan sends an ACK to 198.18.0.2:8080, which it never opened, and the peer kernel answers with a RST: the
    // scanner's FAIL, and the RST no fault of the stand (I1).
    let (v, b) = judge_tcp("t01_tcp4", |sim| {
        let st = sim.step_mut("binary");
        let t = st.frames[st.frames.len() / 2].0;
        st.frames
            .push((t, scanner_seg(TCP_SOURCE, 2, 8080, 7, 9, 0x10)));
        st.frames.push((
            t + 0.0005,
            peer_seg(ip4(2), src, (8080, SOURCE_PORT), 9, 0, 0x04, &[]),
        ));
        resort(st);
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "binary: every frame of the scanner MAC is a SYN of the scan"
        ) && has(&b, FAIL, "of no connection the stand opened"),
        "{b:#?}"
    );
    assert!(no(&b, INVALID), "{b:#?}");
    // The other way round: the peer sends a FIN on a 4-tuple without a connection and the scanner's stack answers it
    // with its RST (src/main.c:1019-1041): the stand's INVALID, and the RST is no unexplained frame.
    let (v, b) = judge_tcp("t01_tcp4", |sim| {
        let st = sim.step_mut("binary");
        let t = st.frames[st.frames.len() / 2].0;
        st.frames.push((
            t,
            peer_seg(ip4(2), src, (8080, SOURCE_PORT), 9, 7, 0x11, &[]),
        ));
        st.frames
            .push((t + 0.0005, scanner_seg(TCP_SOURCE, 2, 8080, 7, 10, 0x04)));
        resort(st);
    });
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(
            &b,
            INVALID,
            "binary: nothing on the peer side answers anything the scan did not send"
        ),
        "{b:#?}"
    );
    assert!(no(&b, FAIL), "{b:#?}");
    // A segment of rmasscan from another source of the window (198.18.0.10: no safety finding) on the 4-tuple of a
    // connection, and the peer's who-has for that address: the scanner's FAIL, the who-has no fault of the stand.
    let (v, b) = judge_tcp("t01_tcp4", |sim| {
        let st = sim.step_mut("binary");
        let i = conn_frames(st, ip4(2), 21, true)[0];
        let (t, mut f) = st.frames[i].clone();
        f[26..30].copy_from_slice(&RESOLVE_SOURCE.octets());
        set_sums(&mut f);
        st.frames.push((t + 0.001, f));
        st.frames
            .push((t + 0.002, resolution(IpAddr::V4(RESOLVE_SOURCE)).0));
        resort(st);
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "binary: every frame of the scanner MAC is a SYN of the scan"
        ),
        "{b:#?}"
    );
    assert!(no(&b, INVALID), "{b:#?}");
    assert!(
        !b.iter()
            .any(|x| x.starts_with(FAIL) && x.contains("safety")),
        "{b:#?}"
    );
}

#[test]
fn a_repeated_syn_of_rmasscan_is_its_fail_never_the_stands() {
    let (v, b) = judge_tcp("t05_stateless_rst", |sim| {
        let st = sim.step_mut("list");
        let (t, syn) = st
            .frames
            .iter()
            .find(|(_, f)| {
                f.get(6..12) == Some(&SCANNER_MAC[..])
                    && tcp_head(f).is_some_and(|h| h.flags == 0x02)
            })
            .cloned()
            .unwrap();
        st.frames.push((t + 0.005, syn));
        resort(st);
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "list: the scan put its SYNs on the wire, each once"
        ),
        "{b:#?}"
    );
    assert!(
        has(&b, FAIL, "list: the probes on the wire equal the plan"),
        "{b:#?}"
    );
    assert!(no(&b, INVALID), "{b:#?}");
}

#[test]
fn every_field_of_a_connections_segments_is_compared_with_cs() {
    // 198.18.0.2:21 (FTP: no hello, no lifetime RST): each edit changes one field of one of rmasscan's segments, and
    // only the comparison with C sees it.
    type Edit = fn(&mut StepSim, &[usize]);
    let data = |st: &StepSim, k: &[usize]| {
        *k.iter()
            .find(|i| !tcp_head(&st.frames[**i].1).unwrap().payload.is_empty())
            .unwrap()
    };
    let _ = data;
    let edits: [(&str, Edit); 4] = [
        ("seq", |st, k| {
            let i = *k
                .iter()
                .find(|i| !tcp_head(&st.frames[**i].1).unwrap().payload.is_empty())
                .unwrap();
            let h = tcp_head(&st.frames[i].1).unwrap();
            st.frames[i].1 = tcp_rebuilt(
                &st.frames[i].1,
                Some(h.seq.wrapping_add(1)),
                None,
                None,
                None,
            );
        }),
        ("ack", |st, k| {
            let h = tcp_head(&st.frames[k[0]].1).unwrap();
            st.frames[k[0]].1 = tcp_rebuilt(
                &st.frames[k[0]].1,
                None,
                Some(h.ack.wrapping_add(1)),
                None,
                None,
            );
        }),
        ("flags", |st, k| {
            let i = *k
                .iter()
                .find(|i| !tcp_head(&st.frames[**i].1).unwrap().payload.is_empty())
                .unwrap();
            st.frames[i].1 = tcp_rebuilt(&st.frames[i].1, None, None, Some(0x10), None);
        }),
        ("order", |st, k| {
            let (a, b) = (st.frames[k[1]].1.clone(), st.frames[k[2]].1.clone());
            assert_ne!(tcp_head(&a), tcp_head(&b));
            st.frames[k[1]].1 = b;
            st.frames[k[2]].1 = a;
        }),
    ];
    for (what, edit) in edits {
        let (v, b) = judge_tcp("t01_tcp4", |sim| {
            let st = sim.step_mut("binary");
            let k = conn_frames(st, ip4(2), 21, true);
            edit(st, &k);
        });
        assert_eq!(v, FAIL, "{what}: {b:#?}");
        assert!(
            has(
                &b,
                FAIL,
                "binary: every connection's scanner segments equal the C oracle's"
            ),
            "{what}: {b:#?}"
        );
        assert_eq!(
            b.iter().filter(|x| x.starts_with(FAIL)).count(),
            1,
            "{what}: only the comparison sees it: {b:#?}"
        );
    }
}

#[test]
fn a_tcp_connections_banners_come_in_one_run_after_its_open_m1() {
    let at = |recs: &[SimRec], o: u8, port: u16, banner: bool| {
        recs.iter()
            .position(|r| match r {
                SimRec::TcpBanner { ip, port: p, .. } => banner && *ip == ip4(o) && *p == port,
                SimRec::TcpStatus { ip, port: p, .. } => !banner && *ip == ip4(o) && *p == port,
                _ => false,
            })
            .unwrap()
    };
    // A banner of 198.18.0.2:21 between two banners of 198.18.0.2:80: only M1 sees it (the records against C are a
    // multiset, the own wire holds the status records only).
    let (v, b) = judge_tcp("t01_tcp4", |sim| {
        let st = sim.step_mut("binary");
        let r = st.recs.remove(at(&st.recs, 2, 21, true));
        let http = at(&st.recs, 2, 80, true);
        st.recs.insert(http + 1, r);
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "binary: the banners of one TCP connection come in one run, after its open record (M1)"
        ) && has(&b, FAIL, "198.18.0.2:80: its banners are not in one run"),
        "{b:#?}"
    );
    assert!(!has(&b, FAIL, "the records equal the C oracle's"), "{b:#?}");
    // The banner of 198.18.0.2:21 just before its own open record.
    let (v, b) = judge_tcp("t01_tcp4", |sim| {
        let st = sim.step_mut("binary");
        let r = st.recs.remove(at(&st.recs, 2, 21, true));
        let open = at(&st.recs, 2, 21, false);
        st.recs.insert(open, r);
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "198.18.0.2:21: a banner before its open"),
        "{b:#?}"
    );
    assert!(!has(&b, FAIL, "the records equal the C oracle's"), "{b:#?}");
}

#[test]
fn rmasscans_stack_frames_need_right_ipv4_header_and_tcp_sums() {
    for (what, at) in [("TCP", 34 + 16), ("IPv4 header", 24)] {
        let (v, b) = judge_tcp("t01_tcp4", |sim| {
            let st = sim.step_mut("list");
            let i = conn_frames(st, ip4(2), 21, true)[1];
            st.frames[i].1[at] ^= 0x01;
        });
        assert_eq!(v, FAIL, "{what}: {b:#?}");
        assert!(
            has(
                &b,
                FAIL,
                "list: every stack frame of rmasscan carries right IPv4 header and TCP sums"
            ),
            "{what}: {b:#?}"
        );
    }
}

#[test]
fn a_frame_after_the_peers_ack_of_its_fin_in_last_ack_fails() {
    // 198.18.0.2:80 ends in the peer's LAST_ACK (its FIN, the scanner's FIN, its ACK of that FIN), no RST anywhere.
    let c = tcp_case("t01_tcp4").unwrap();
    let (v, b) = judge_tcp(c.tag, |sim| {
        let st = sim.step_mut("list");
        let v = view_of(&c, st);
        let x = v
            .conns
            .iter()
            .find(|x| x.ip == ip4(2) && x.port == 80)
            .unwrap();
        assert!(x.scanner.iter().chain(&x.peer).all(|g| g.flags & 0x04 == 0));
        let end = x.destroyed_at().unwrap();
        let last = *conn_frames(st, ip4(2), 80, true).last().unwrap();
        let f = st.frames[last].1.clone();
        st.frames.push((end + 0.1, f));
        resort(st);
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
fn a_rst_of_the_scanner_outside_the_lifetime_window_fails_and_a_teardown_has_none() {
    // 198.18.0.2:21 closes by FIN, no lifetime ends it: a RST 5 s after its SYN-ACK is no lifetime RST.
    let c = tcp_case("t01_tcp4").unwrap();
    let (v, b) = judge_tcp(c.tag, |sim| {
        let st = sim.step_mut("list");
        let v = view_of(&c, st);
        let x = v
            .conns
            .iter()
            .find(|x| x.ip == ip4(2) && x.port == 21)
            .unwrap();
        let next = x.scanner.last().unwrap().seq;
        st.frames.push((
            x.reply_t + 5.0,
            scanner_seg(TCP_SOURCE, 2, 21, next, 0, 0x04),
        ));
        resort(st);
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "list: the lifetime RST leaves 8-12 s after the SYN-ACK"
        ) && has(&b, FAIL, "198.18.0.2:21 RST after 5.000 s"),
        "{b:#?}"
    );
    // t03: no lifetime ends inside the scan, so any RST of the scanner fails.
    let t3 = tcp_case("t03_teardown").unwrap();
    let (v, b) = judge_tcp(t3.tag, |sim| {
        let st = sim.step_mut("binary");
        let v = view_of(&t3, st);
        let x = v
            .conns
            .iter()
            .find(|x| x.ip == ip4(4) && x.port == 80)
            .unwrap();
        let next = x.scanner.last().unwrap().seq;
        st.frames.push((
            x.reply_t + 4.0,
            scanner_seg(TCP_SOURCE, 4, 80, next, 0, 0x04),
        ));
        resort(st);
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "binary: no RST of the scanner: the connections alive at the end of the scan are flushed without a frame"
        ),
        "{b:#?}"
    );
}

#[test]
fn rmasscans_rst_to_a_fin_after_the_connections_end_is_r8s_not_a_lifetime_rst_m4() {
    // 198.18.0.2:80 after its end: the peer repeats its FIN, the stack answers with its RST to a FIN without a
    // connection (src/main.c:1019-1041: seq the FIN's ack). Both scanners do it: PASS, the lifetime rule included.
    let c = tcp_case("t01_tcp4").unwrap();
    let late_fin = |st: &mut StepSim, good: bool| {
        let v = view_of(&c, st);
        let x = v
            .conns
            .iter()
            .find(|x| x.ip == ip4(2) && x.port == 80)
            .unwrap();
        let fin = x.peer.iter().find(|g| g.flags & 0x01 != 0).unwrap();
        let at = x.destroyed_at().unwrap() + 0.5;
        let (fseq, fack) = (fin.seq, fin.ack);
        st.frames.push((
            at,
            peer_seg(
                ip4(2),
                IpAddr::V4(TCP_SOURCE),
                (80, SOURCE_PORT),
                fseq,
                fack,
                0x11,
                &[],
            ),
        ));
        let seq = if good { fack } else { fack.wrapping_add(1) };
        st.frames.push((
            at + 0.0002,
            scanner_seg(TCP_SOURCE, 2, 80, seq, fseq.wrapping_add(1), 0x04),
        ));
        resort(st);
    };
    let (v, b) = judge_tcp(c.tag, |sim| {
        late_fin(sim.step_mut("list"), true);
        late_fin(sim.step_mut("oracle-list"), true);
    });
    assert_eq!(v, PASS, "{b:#?}");
    // Another seq than the FIN's ack: no answer to that FIN, a frame after the connection's end and a RST outside
    // the lifetime window.
    let (v, b) = judge_tcp(c.tag, |sim| late_fin(sim.step_mut("list"), false));
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "list: no frame of a connection after the connection was destroyed"
        ) && has(&b, FAIL, "list: the lifetime RST leaves 8-12 s"),
        "{b:#?}"
    );
}

#[test]
fn the_hello_window_holds_on_every_hello_port() {
    // 198.18.0.2:3389 (RDP) over IPv4 and [fd00:198:18::2]:11211 (memcached) over IPv6: the hello 2 s late.
    for (tag, step, ip, port) in [
        ("t01_tcp4", "list", ip4(2), 3389),
        ("t02_tcp6", "binary", ip6(2), 11211),
    ] {
        let (v, b) = judge_tcp(tag, |sim| {
            let st = sim.step_mut(step);
            let i = conn_frames(st, ip, port, true)
                .into_iter()
                .find(|i| !tcp_head(&st.frames[*i].1).unwrap().payload.is_empty())
                .unwrap();
            st.frames[i].0 += 2.0;
            resort(st);
        });
        assert_eq!(v, FAIL, "{tag}: {b:#?}");
        assert!(
            has(
                &b,
                FAIL,
                &format!("{step}: the hello leaves 1-3.5 s after the SYN-ACK")
            ) && has(&b, FAIL, &format!(":{port} after 4.")),
            "{tag}: {b:#?}"
        );
    }
}

#[test]
fn the_plus_lines_of_a_tcp_step_are_the_stands() {
    let (v, b) = judge_tcp("t05_stateless_rst", |sim| {
        let st = sim.step_mut("list");
        assert!(st.stderr.contains("source-ip = 198.18.0.9 (given)"));
        st.stderr = st.stderr.replace(
            "source-ip = 198.18.0.9 (given)",
            "source-ip = 198.18.0.1 (detected)",
        );
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(&b, FAIL, "list: [+] lines are the stand's"), "{b:#?}");
}

#[test]
fn the_stateless_rst_has_cs_form_and_answers_every_reset_too() {
    let rst = |st: &StepSim, o: u8, port: u16| {
        st.frames
            .iter()
            .position(|(_, f)| {
                f.get(6..12) == Some(&SCANNER_MAC[..])
                    && tcp_head(f).is_some_and(|h| {
                        h.flags == 0x04 && peer_of(h.dst) == Some(o) && h.dp == port
                    })
            })
            .unwrap()
    };
    type Edit = fn(&mut StepSim, usize);
    let edits: [(&str, u16, Edit); 3] = [
        // Its seq one past the reply's ack.
        ("seq", 80, |st, i| {
            let h = tcp_head(&st.frames[i].1).unwrap();
            st.frames[i].1 = tcp_rebuilt(
                &st.frames[i].1,
                Some(h.seq.wrapping_add(1)),
                None,
                None,
                None,
            );
        }),
        // Its ack not 0.
        ("ack", 80, |st, i| {
            st.frames[i].1 = tcp_rebuilt(&st.frames[i].1, None, Some(1), None, None);
        }),
        // None to the reset of 198.18.0.2:81 (a closed port: the peer's RST is a reply too).
        ("reset", 81, |st, i| {
            st.frames.remove(i);
        }),
    ];
    for (what, port, edit) in edits {
        let (v, b) = judge_tcp("t05_stateless_rst", |sim| {
            let st = sim.step_mut("list");
            let i = rst(st, 2, port);
            edit(st, i);
        });
        assert_eq!(v, FAIL, "{what}: {b:#?}");
        assert!(
            has(&b, FAIL, "list: exactly one stateless RST per connection"),
            "{what}: {b:#?}"
        );
    }
}

#[test]
fn every_stand_check_of_a_tcp_step_is_invalid_and_never_a_fail() {
    let src = IpAddr::V4(TCP_SOURCE);
    // 198.18.0.3:22 without an answer, or reset although the table has its scenario.
    let unanswered = move |st: &mut StepSim, reset: bool| {
        let (t, syn) = st
            .frames
            .iter()
            .find(|(_, f)| {
                f.get(6..12) == Some(&SCANNER_MAC[..])
                    && tcp_head(f).is_some_and(|h| h.flags == 0x02 && h.dst == ip4(3) && h.dp == 22)
            })
            .map(|(t, f)| (*t, tcp_head(f).unwrap()))
            .unwrap();
        st.frames.retain(|(_, f)| {
            !tcp_head(f).is_some_and(|h| {
                (h.dst == ip4(3) && h.dp == 22 && h.flags != 0x02)
                    || (h.src == ip4(3) && h.sp == 22)
            })
        });
        if reset {
            st.frames.push((
                t + 0.001,
                peer_seg(
                    ip4(3),
                    src,
                    (22, SOURCE_PORT),
                    0,
                    syn.seq.wrapping_add(1),
                    0x14,
                    &[],
                ),
            ));
        }
        resort(st);
    };
    type Edit = Box<dyn Fn(&mut Sim)>;
    let cases: Vec<(&str, &str, &str, Edit)> = vec![
        (
            "t01_tcp4",
            "binary: the stand answered every SYN exactly once",
            "unanswered",
            Box::new(move |sim| unanswered(sim.step_mut("binary"), false)),
        ),
        (
            "t01_tcp4",
            "binary: the stand answered every SYN exactly once",
            "reset",
            Box::new(move |sim| unanswered(sim.step_mut("binary"), true)),
        ),
        (
            "t01_tcp4",
            "binary: the peer's stream of every connection is its scenario's writes",
            "a byte of the SSH ident changed",
            Box::new(|sim| {
                let st = sim.step_mut("binary");
                let i = conn_frames(st, ip4(2), 22, false)
                    .into_iter()
                    .find(|i| !tcp_head(&st.frames[*i].1).unwrap().payload.is_empty())
                    .unwrap();
                let mut p = tcp_head(&st.frames[i].1).unwrap().payload;
                p[0] ^= 0x20;
                st.frames[i].1 = tcp_rebuilt(&st.frames[i].1, None, None, None, Some(&p));
            }),
        ),
        (
            "t01_tcp4",
            "binary: every split scenario came in more than one data segment",
            "the split SSH ident in one segment",
            Box::new(|sim| merge_split(sim.step_mut("binary"), false)),
        ),
        (
            "t01_tcp4",
            "binary: every split scenario came in more than one data segment",
            "the split SSH ident in one segment, sent twice",
            Box::new(|sim| merge_split(sim.step_mut("binary"), true)),
        ),
        (
            "t01_tcp4",
            "binary: nothing on the peer side answers anything the scan did not send",
            "a peer segment of no connection",
            Box::new(move |sim| {
                let st = sim.step_mut("binary");
                let t = st.frames[st.frames.len() / 2].0;
                st.frames.push((
                    t,
                    peer_seg(ip4(2), src, (9999, SOURCE_PORT), 5, 6, 0x10, &[]),
                ));
                resort(st);
            }),
        ),
        (
            "t02_tcp6",
            "binary: no IPv6 kernel noise on the wire",
            "an MLD report of the scanner namespace",
            Box::new(|sim| {
                let st = sim.step_mut("binary");
                let t = st.frames[st.frames.len() / 2].0;
                let ll: Ipv6Addr = capture::IPV6_SCANNER_LL.parse().unwrap();
                st.frames.push((
                    t,
                    v6_frame(
                        [0x33, 0x33, 0, 0, 0, 0x16],
                        SCANNER_MAC,
                        ll,
                        "ff02::16".parse().unwrap(),
                        58,
                        1,
                        vec![143, 0, 0, 0, 0, 0, 0, 0],
                    ),
                ));
                resort(st);
            }),
        ),
        (
            "t05_stateless_rst",
            "list: every SYN and reply lies inside the witness window",
            "a SYN before the start marker",
            Box::new(|sim| {
                let st = sim.step_mut("list");
                let start = st.frames[0].0;
                let i = st
                    .frames
                    .iter()
                    .position(|(_, f)| tcp_head(f).is_some_and(|h| h.flags == 0x02))
                    .unwrap();
                st.frames[i].0 = start - 0.05;
                resort(st);
            }),
        ),
        (
            "t01_tcp4",
            "list: the peer resolved the source never",
            "a who-has for the source with a permanent entry",
            Box::new(|sim| {
                let st = sim.step_mut("list");
                let t = st.frames[st.frames.len() / 2].0;
                st.frames.push((t, resolution(IpAddr::V4(TCP_SOURCE)).0));
                resort(st);
            }),
        ),
        (
            "t09_quiet_timers",
            "list: no peer heartbeat on the wire",
            "a heartbeat on the quiet control",
            Box::new(|sim| {
                let st = sim.step_mut("list");
                let t = st.frames[st.frames.len() / 2].0;
                st.frames.push((
                    t,
                    crate::link::marker_frame(SCANNER_MAC, PEER_MAC, HEARTBEAT_PAYLOAD),
                ));
                resort(st);
            }),
        ),
    ];
    for (tag, check, what, edit) in cases {
        let (v, b) = judge_tcp(tag, |sim| edit(sim));
        assert_eq!(v, INVALID, "{what}: {b:#?}");
        assert!(has(&b, INVALID, check), "{what}: {b:#?}");
        assert!(no(&b, FAIL), "{what}: {b:#?}");
    }
}
/// 198.18.0.3:22, whose SSH ident the scenario writes in two segments, in one (and, `twice`, that segment repeated).
fn merge_split(st: &mut StepSim, twice: bool) {
    let k: Vec<usize> = conn_frames(st, ip4(3), 22, false)
        .into_iter()
        .filter(|i| !tcp_head(&st.frames[*i].1).unwrap().payload.is_empty())
        .collect();
    let (a, b) = (
        tcp_head(&st.frames[k[0]].1).unwrap(),
        tcp_head(&st.frames[k[1]].1).unwrap(),
    );
    assert_eq!(b.seq, a.seq.wrapping_add(a.payload.len() as u32));
    let mut whole = a.payload.clone();
    whole.extend(&b.payload);
    let merged = tcp_rebuilt(&st.frames[k[0]].1, None, None, None, Some(&whole));
    let t = st.frames[k[0]].0;
    st.frames[k[0]].1 = merged.clone();
    st.frames.remove(k[1]);
    if twice {
        st.frames.push((t + 0.1, merged));
    }
    resort(st);
}

#[test]
fn every_deviation_condition_is_judged_on_the_wire() {
    type Edit = fn(&mut Sim);
    let cases: [(&str, &str, Edit); 6] = [
        // rmasscan's -oB IPv6 banner with another ttl than its SYN-ACK's hop limit.
        ("t02_tcp6", "deviation ipv6-ttl", |sim| {
            let st = sim.step_mut("binary");
            let r = st
                .recs
                .iter_mut()
                .find(|r| matches!(r, SimRec::TcpBanner { .. }))
                .unwrap();
            if let SimRec::TcpBanner { ttl, .. } = r {
                *ttl = 1;
            }
        }),
        // The memcached reply of 198.18.0.2 cut before its LF.
        ("t01_tcp4", "deviation memcached-tcp-past-segment", |sim| {
            let st = sim.step_mut("list");
            let i = conn_frames(st, ip4(2), 11211, false)
                .into_iter()
                .find(|i| !tcp_head(&st.frames[*i].1).unwrap().payload.is_empty())
                .unwrap();
            split_peer_segment(st, i, 10);
        }),
        // A stack frame of C with a wrong IPv4 header checksum.
        ("t01_tcp4", "deviation ipv4-stack-checksum", |sim| {
            let st = sim.step_mut("oracle-list");
            let i = conn_frames(st, ip4(2), 21, true)[1];
            st.frames[i].1[24] ^= 0x01;
        }),
        // A data segment of the peer with a wrong TCP checksum.
        ("t01_tcp4", "deviation rx-checksum-verify", |sim| {
            let st = sim.step_mut("list");
            let i = conn_frames(st, ip4(2), 22, false)
                .into_iter()
                .find(|i| !tcp_head(&st.frames[*i].1).unwrap().payload.is_empty())
                .unwrap();
            st.frames[i].1[34 + 16] ^= 0x01;
        }),
        // The peer's SYN-ACK with a wrong IPv4 header checksum.
        ("t01_tcp4", "deviation rx-checksum-verify", |sim| {
            let st = sim.step_mut("oracle-binary");
            let i = conn_frames(st, ip4(2), 22, false)[0];
            assert_eq!(tcp_head(&st.frames[i].1).unwrap().flags, 0x12);
            st.frames[i].1[24] ^= 0x01;
        }),
        // The Minecraft reply of 198.18.0.2 in two segments on C's wire.
        ("t01_tcp4", "deviation minecraft-unsplit", |sim| {
            let st = sim.step_mut("oracle-list");
            let i = conn_frames(st, ip4(2), 25565, false)
                .into_iter()
                .find(|i| !tcp_head(&st.frames[*i].1).unwrap().payload.is_empty())
                .unwrap();
            split_peer_segment(st, i, 50);
        }),
    ];
    for (tag, check, edit) in cases {
        let (v, b) = judge_tcp(tag, edit);
        assert_eq!(v, INVALID, "{check}: {b:#?}");
        assert!(has(&b, INVALID, check), "{check}: {b:#?}");
        assert!(no(&b, FAIL), "{check}: {b:#?}");
    }
}

#[test]
fn an_unmet_deviation_condition_makes_the_comparison_invalid_not_a_fail_i2() {
    // C's Minecraft reply split by the peer kernel, and C's parser losing bytes of it (src/proto-mc.c:68-89): the
    // records differ, but the condition is judged first, so the comparison is INVALID, the run has no behaviour FAIL
    // and the directory is INVALID.
    let mut sim = Sim::new("t01_tcp4");
    let st = sim.step_mut("oracle-list");
    let i = conn_frames(st, ip4(2), 25565, false)
        .into_iter()
        .find(|i| !tcp_head(&st.frames[*i].1).unwrap().payload.is_empty())
        .unwrap();
    split_peer_segment(st, i, 50);
    let r = st
        .recs
        .iter_mut()
        .find(|r| matches!(r, SimRec::TcpBanner { port: 25565, .. }))
        .unwrap();
    if let SimRec::TcpBanner { payload, .. } = r {
        payload[60..].fill(0);
    }
    let j = judge_full(&sim);
    let b = &j.bad;
    assert_eq!(j.verdict, INVALID, "{b:#?}");
    assert!(has(b, INVALID, "deviation minecraft-unsplit"), "{b:#?}");
    assert!(
        has(b, INVALID, "list: the records equal the C oracle's"),
        "{b:#?}"
    );
    assert!(no(b, FAIL) && !j.behaviour_fail, "{b:#?}");
    assert_eq!(j.overall, INVALID, "{b:#?}");
}

#[test]
fn the_verifiers_own_c_escaper_gives_cs_list_text() {
    // src/output.c:144-170, written by hand: printable but < > & \ " ' stays, the rest is \xNN in lowercase.
    assert_eq!(
        c_normalize_string(b"A<b>&\\\"' ~\x00\x1f\x7f\x80\xff"),
        "A\\x3cb\\x3e\\x26\\x5c\\x22\\x27 ~\\x00\\x1f\\x7f\\x80\\xff"
    );
    // The 8192-byte buffer: an escape fits while offset + 5 < 8192, a byte while offset + 2 < 8192.
    let mut px = vec![0u8; 3000];
    px.extend(b"abc");
    let want = format!("{}ab", "\\x00".repeat(2047));
    assert_eq!(c_normalize_string(&px), want);
    // Three bytes first: the 2047th escape would start at offset 8187, where 8187 + 5 is no longer below 8192.
    let mut edge = b"abc".to_vec();
    edge.extend([0u8; 3000]);
    edge.extend(b"defg");
    assert_eq!(
        c_normalize_string(&edge),
        format!("abc{}def", "\\x00".repeat(2046))
    );
    assert_eq!(c_normalize_string(&edge), normalize_string(&edge));
    // The product's escaper agrees (a cross-check; the expectation above is the anchor).
    for px in [&px[..], b"\x01\x02 <a href='x'>\r\n"] {
        assert_eq!(c_normalize_string(px), normalize_string(px));
    }
}

#[test]
fn a_wrong_list_text_of_rmasscans_raw_banner_on_11211_fails_m2() {
    let mut sim = Sim::new("b01_banners");
    let st = sim.step_mut("list");
    let i = st
        .recs
        .iter()
        .rposition(
            |r| matches!(r, SimRec::Banner { ip, port: 11211, app: 0, .. } if ip.octets()[3] == 2),
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
        ) && has(&b, FAIL, "11211"),
        "{b:#?}"
    );
}

#[test]
fn a_syn_of_the_scanner_mac_from_no_source_of_the_window_is_a_safety_finding() {
    let (v, b) = judge_tcp("t01_tcp4", |sim| {
        let st = sim.step_mut("binary");
        let t = st.frames[st.frames.len() / 2].0;
        st.frames.push((
            t,
            scanner_seg(Ipv4Addr::new(198, 18, 0, 7), 2, 80, 1, 0, 0x02),
        ));
        resort(st);
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "no SYN on the binary capture from outside the stand binding or to an address off the stand"
        ),
        "{b:#?}"
    );
}

#[test]
fn a_resolve_step_records_the_flush_of_the_peers_entry_m8() {
    let c = tcp_case("t07_resolve_arp").unwrap();
    assert_eq!(
        neigh_flush_argv("wl-peer-1-2", c.source()),
        [
            crate::autodetect_suite::IP,
            "-n",
            "wl-peer-1-2",
            "neigh",
            "flush",
            "to",
            "198.18.0.10",
            "dev",
            "veth-b"
        ]
    );
    assert!(
        neigh_flush_argv("wl-peer-1-2", tcp_case("t08_resolve_ndp").unwrap().source())
            .windows(2)
            .any(|w| w == ["wl-peer-1-2", "-6"])
    );
    let (v, b) = judge_tcp(c.tag, |sim| sim.step_mut("list").flush = None);
    assert_eq!(v, NOT_RUN, "{b:#?}");
    assert!(has(&b, NOT_RUN, "neigh-flush.json"), "{b:#?}");
    let (v, b) = judge_tcp(c.tag, |sim| {
        if let Some(f) = &mut sim.step_mut("oracle-list").flush {
            f.rc = 1;
        }
    });
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(
            &b,
            INVALID,
            "oracle-list/neigh-flush.json: the peer's neighbour entry for the source was flushed"
        ) && has(&b, INVALID, "exited 1"),
        "{b:#?}"
    );
    let (v, b) = judge_tcp(c.tag, |sim| {
        sim.step_mut("list").flush = Some(NeighFlush {
            argv: neigh_flush_argv(PEER_NS, IpAddr::V4(TCP_SOURCE)),
            rc: 0,
        });
    });
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(has(&b, INVALID, "list/neigh-flush.json"), "{b:#?}");
}

#[test]
fn the_quiet_control_judges_rmasscans_timers_on_a_quiet_link_m3() {
    let c = tcp_case("t09_quiet_timers").unwrap();
    assert!(c.quiet && c.banners && c.connection_timeout == Some(8));
    assert_eq!(
        steps(c.tag)
            .unwrap()
            .iter()
            .map(|s| (s.name, s.who))
            .collect::<Vec<_>>(),
        [("list", Who::Rmasscan)]
    );
    let r = tcp_responder_args(&c);
    assert!(!r.iter().any(|a| a.starts_with("--heartbeat")), "{r:?}");
    assert!(!expect(c.tag).unwrap().tcp.unwrap().heartbeat);
    assert!(expect("t01_tcp4").unwrap().tcp.unwrap().heartbeat);
    // The generated control: rmasscan alone, no heartbeat, PASS.
    let sim = Sim::new(c.tag);
    assert!(sim.steps[0].frames.iter().all(|(_, f)| {
        !f.get(14..)
            .is_some_and(|x| x.starts_with(HEARTBEAT_PAYLOAD))
    }));
    // No hello on 198.18.0.4:80, and no lifetime RST on 198.18.0.5:3389: each timer is judged.
    let (v, b) = judge_tcp(c.tag, |sim| {
        let st = sim.step_mut("list");
        let i = conn_frames(st, ip4(4), 80, true)
            .into_iter()
            .find(|i| !tcp_head(&st.frames[*i].1).unwrap().payload.is_empty())
            .unwrap();
        st.frames.remove(i);
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "list: the hello leaves 1-3.5 s") && has(&b, FAIL, "198.18.0.4:80 never"),
        "{b:#?}"
    );
    let (v, b) = judge_tcp(c.tag, |sim| {
        let st = sim.step_mut("list");
        let i = conn_frames(st, ip4(5), 3389, true)
            .into_iter()
            .find(|i| tcp_head(&st.frames[*i].1).unwrap().flags & 0x04 != 0)
            .unwrap();
        st.frames.remove(i);
    });
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "198.18.0.5:3389 held open and 0 RSTs"),
        "{b:#?}"
    );
}
