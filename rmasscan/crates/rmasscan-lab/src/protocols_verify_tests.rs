//! Synthetic, hermetic protocols evidence. The probes come from the scan plan (`ReadyPlan` + its cursor, the product's
//! own plan); every answer of the peer, the kernel noise of both hosts, the documents in the byte forms of the C
//! reference and the `[+]` lines are built here by hand, never with the verifier's parsers. One rule at a time is
//! broken. Nothing touches a network or a real evidence directory.
use super::*;
use crate::{
    autodetect_verify::{
        HASHES,
        tests::{LAB_ID, Sim as AdSim, T0, TEARDOWN, linux_isolation, marker, status_fragments},
    },
    link::{END_PAYLOAD, START_PAYLOAD},
    pcap,
    windows_suite::nonce,
};
use std::path::PathBuf;

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-proto-verify-{}", nonce()));
    fs::create_dir_all(&d).unwrap();
    d
}

// ------------------------------------------------------------------ frames by hand

const SCANNER_MAC: [u8; 6] = [2, 0xaa, 0, 0, 0, 1];
const PEER_MAC: [u8; 6] = [2, 0xaa, 0, 0, 0, 2];
const SCANNER_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const TTL: u8 = 64;

fn sum16(b: &[u8], init: u32) -> u16 {
    let mut s = init;
    for c in b.chunks(2) {
        s += (u32::from(c[0]) << 8) | u32::from(*c.get(1).unwrap_or(&0));
    }
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}
/// An Ethernet + IPv4 frame around `l4`, its IPv4 header checksum and (TCP, UDP) its transport checksum set.
fn ip_frame(
    dmac: [u8; 6],
    smac: [u8; 6],
    s: Ipv4Addr,
    d: Ipv4Addr,
    proto: u8,
    mut l4: Vec<u8>,
) -> Vec<u8> {
    let at = match proto {
        6 => Some(16),
        17 => Some(6),
        _ => None,
    };
    if let Some(at) = at {
        l4[at..at + 2].fill(0);
        let mut pseudo = Vec::new();
        pseudo.extend(s.octets());
        pseudo.extend(d.octets());
        pseudo.extend([0, proto]);
        pseudo.extend((l4.len() as u16).to_be_bytes());
        let mut init = 0u32;
        for c in pseudo.chunks(2) {
            init += (u32::from(c[0]) << 8) | u32::from(c[1]);
        }
        let v = sum16(&l4, init);
        l4[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }
    let mut f = Vec::new();
    f.extend(dmac);
    f.extend(smac);
    f.extend([8, 0]);
    let mut ip = vec![0x45, 0];
    ip.extend(((20 + l4.len()) as u16).to_be_bytes());
    ip.extend([0x12, 0x34, 0x40, 0, TTL, proto, 0, 0]);
    ip.extend(s.octets());
    ip.extend(d.octets());
    let v = sum16(&ip, 0);
    ip[10..12].copy_from_slice(&v.to_be_bytes());
    f.extend(ip);
    f.extend(l4);
    f
}
fn icmp(t: u8, code: u8, rest: &[u8], data: &[u8]) -> Vec<u8> {
    let mut b = vec![t, code, 0, 0];
    b.extend(rest);
    b.extend(data);
    let v = sum16(&b, 0);
    b[2..4].copy_from_slice(&v.to_be_bytes());
    b
}
fn peer_ip(p: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(p[30], p[31], p[32], p[33])
}
fn ports(p: &[u8]) -> (u16, u16) {
    (be16(p, 34), be16(p, 36))
}
/// The peer's frame to the scanner from the probe's destination.
fn back(p: &[u8], proto: u8, l4: Vec<u8>) -> Vec<u8> {
    ip_frame(SCANNER_MAC, PEER_MAC, peer_ip(p), SCANNER_IP, proto, l4)
}
/// An ICMP error quoting `p`'s IPv4 header and first 8 transport bytes, `from` the peer or (`scanner`) the scanner.
fn icmp_error(p: &[u8], code: u8, scanner: bool) -> Vec<u8> {
    let l4 = icmp(3, code, &[0; 4], &p[14..14 + 28]);
    if scanner {
        ip_frame(
            PEER_MAC,
            SCANNER_MAC,
            SCANNER_IP,
            Ipv4Addr::new(p[26], p[27], p[28], p[29]),
            1,
            l4,
        )
    } else {
        back(p, 1, l4)
    }
}
fn tcp_reply(p: &[u8], flags: u8) -> Vec<u8> {
    let (sp, dp) = ports(p);
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&dp.to_be_bytes());
    t[2..4].copy_from_slice(&sp.to_be_bytes());
    t[4..8].copy_from_slice(&0x5000_0000_u32.to_be_bytes());
    t[8..12].copy_from_slice(&be32(p, 38).wrapping_add(1).to_be_bytes());
    t[12] = 0x50;
    t[13] = flags;
    t[14..16].copy_from_slice(&64240_u16.to_be_bytes());
    back(p, 6, t)
}
fn scanner_rst(reply: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&reply[36..38]);
    t[2..4].copy_from_slice(&reply[34..36]);
    t[4..8].copy_from_slice(&reply[42..46]);
    t[12] = 0x50;
    t[13] = 0x04;
    ip_frame(PEER_MAC, SCANNER_MAC, SCANNER_IP, src(reply), 6, t)
}
fn udp_reply(p: &[u8]) -> Vec<u8> {
    let (sp, dp) = ports(p);
    let mut u = Vec::new();
    u.extend(dp.to_be_bytes());
    u.extend(sp.to_be_bytes());
    u.extend(((8 + UDP_REPLY.len()) as u16).to_be_bytes());
    u.extend([0, 0]);
    u.extend(UDP_REPLY);
    back(p, 17, u)
}
fn echo_reply(p: &[u8], code: u8) -> Vec<u8> {
    let total = 14 + usize::from(be16(p, 16));
    back(p, 1, icmp(0, code, &p[38..42], &p[42..total]))
}
fn arp_reply(p: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend(SCANNER_MAC);
    f.extend(PEER_MAC);
    f.extend([8, 6, 0, 1, 8, 0, 6, 4, 0, 2]);
    f.extend(PEER_MAC);
    f.extend(&p[38..42]);
    f.extend(SCANNER_MAC);
    f.extend(SCANNER_IP.octets());
    f
}
/// The next-hop resolution's who-has for the gateway: 60 bytes, zero padded (the resolver's form).
fn next_hop_request() -> Vec<u8> {
    let mut f = crate::autodetect_verify::tests::arp_request(&stand(), GATEWAY);
    f.resize(60, 0);
    f
}
fn next_hop_reply() -> Vec<u8> {
    let mut f = Vec::new();
    f.extend(SCANNER_MAC);
    f.extend(PEER_MAC);
    f.extend([8, 6, 0, 1, 8, 0, 6, 4, 0, 2]);
    f.extend(PEER_MAC);
    f.extend(GATEWAY.octets());
    f.extend(SCANNER_MAC);
    f.extend(SCANNER_IP.octets());
    f
}

// ------------------------------------------------------------------ records and documents by hand

/// What the stand answers a probe with, as a record (time aside).
fn stand_rec(p: &[u8], arp: bool) -> Rec {
    let ip = if arp {
        Ipv4Addr::new(p[38], p[39], p[40], p[41])
    } else {
        peer_ip(p)
    };
    let (proto, port, open) = if arp {
        (Proto::Arp, 0, true)
    } else {
        match p[23] {
            6 => (Proto::Tcp, ports(p).1, TCP_OPEN.contains(&ports(p).1)),
            17 => (Proto::Udp, ports(p).1, UDP_OPEN.contains(&ports(p).1)),
            132 => (Proto::Sctp, ports(p).1, SCTP_OPEN.contains(&ports(p).1)),
            _ => (Proto::Icmp, 0, true),
        }
    };
    let st = match (arp, open) {
        (true, _) => St::Up,
        (false, true) => St::Open,
        (false, false) => St::Closed,
    };
    let reason = match (proto, open) {
        (Proto::Tcp, true) => "syn-ack",
        (Proto::Tcp, false) => "rst-ack",
        _ => "none",
    };
    Rec {
        st,
        proto,
        ip,
        port,
        reason: Some(reason.into()),
        ttl: Some(if arp { 0 } else { TTL }),
        mac: arp.then_some(PEER_MAC),
        ts: None,
    }
}
fn render(out: Out, recs: &[Rec], complete: bool) -> Vec<u8> {
    let mut b = Vec::new();
    match out {
        Out::List => {
            b.extend(b"#masscan\n");
            for r in recs {
                b.extend(
                    format!(
                        "{} {} {} {} {}\n",
                        r.st.name(),
                        r.proto.name(),
                        r.port,
                        r.ip,
                        r.ts.unwrap()
                    )
                    .bytes(),
                );
            }
            if complete {
                b.extend(b"# end\n");
            }
        }
        Out::Json => {
            b.extend(b"[\n");
            for (i, r) in recs.iter().enumerate() {
                if i > 0 {
                    b.extend(b",\n");
                }
                b.extend(format!("{{   \"ip\": \"{}\",   \"timestamp\": \"{}\", \"ports\": [ {{\"port\": {}, \"proto\": \"{}\", \"status\": \"{}\", \"reason\": \"{}\", \"ttl\": {}}} ] }}\n",
                    r.ip, r.ts.unwrap(), r.port, r.proto.name(), r.st.name(), r.reason.as_deref().unwrap(), r.ttl.unwrap()).bytes());
            }
            if complete {
                b.extend(b"]\n");
            }
        }
        Out::Binary => {
            let mut head = format!("masscan/1.1\ns:{}\n", recs[0].ts.unwrap()).into_bytes();
            head.resize(99, 0);
            b.extend(head);
            for r in recs {
                b.push(match r.st {
                    St::Open => 6,
                    St::Closed => 7,
                    St::Up => 8,
                });
                b.push(13);
                b.extend((r.ts.unwrap() as u32).to_be_bytes());
                b.extend(r.ip.octets());
                b.push(r.proto.number());
                b.extend(r.port.to_be_bytes());
                b.push(match r.reason.as_deref() {
                    Some("syn-ack") => 0x12,
                    Some("rst-ack") => 0x14,
                    _ => 0,
                });
                b.push(r.ttl.unwrap());
            }
            if complete {
                let mut foot = b"masscan/1.1".to_vec();
                foot.resize(99, 0);
                b.extend(foot);
            }
        }
        Out::Stdout => {
            for r in recs.iter().filter(|r| r.st != St::Closed) {
                let mut line = format!(
                    "Discovered {} port {}/{} on {}",
                    r.st.name(),
                    r.port,
                    r.proto.name(),
                    r.ip
                );
                if let Some(m) = r.mac {
                    line.push_str(&format!(
                        " ({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}) ",
                        m[0], m[1], m[2], m[3], m[4], m[5]
                    ));
                }
                b.extend(format!("{line:<79}\n").bytes());
            }
        }
    }
    b
}

const PLUS: &str = "[+] interface = veth-a (detected: route to 198.18.0.2)\n[+] source-mac = 02-aa-00-00-00-01 (detected)\n[+] source-ip = 198.18.0.1 (detected)\n[+] router-ip = 198.18.0.2 (interface default gateway)\n[+] router-mac = 02-aa-00-00-00-02 (arp: 1 requests, 1 ms)\n[+] seed = 1 (given)\n[+] source-port = 40000 (given)\n";
const PLUS_ARP: &str = "[+] interface = veth-a (detected: route to 198.18.0.2)\n[+] source-mac = 02-aa-00-00-00-01 (detected)\n[+] source-ip = 198.18.0.1 (detected)\n[+] router-mac = ff-ff-ff-ff-ff-ff (given)\n[+] seed = 1 (given)\n[+] source-port = 40000 (given)\n";
const ORACLE_STDERR: &str = "Starting masscan 1.3.9-integration (http://bit.ly/14GZzcT) at 2027-01-15 08:01:40 GMT\nInitiating SYN Stealth Scan\nScanning 4 hosts [4 ports/host]\nrate:  0.00-kpps, 100.00% done, waiting 3-secs, found=8       \r[-] Passed the wait window but still running, forcing exit...\n";
fn rm_stderr(arp: bool, sent: usize, recs: &[Rec]) -> String {
    let open = recs.iter().filter(|r| r.st == St::Open).count();
    format!(
        "{}{}{}\r[+] finished: Completed, sent {sent}, replies {}, open {open}\n",
        if arp { PLUS_ARP } else { PLUS },
        status_fragments()[0],
        " ".repeat(77),
        recs.len()
    )
}

// ------------------------------------------------------------------ the generator

/// What one step left, before it is written.
#[derive(Clone)]
pub(crate) struct StepSim {
    pub(crate) spec: StepSpec,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: String,
    pub(crate) exit: i32,
    pub(crate) frames: Frames,
    /// The document file, when the step writes one.
    pub(crate) doc: Option<Vec<u8>>,
    pub(crate) argv: Vec<String>,
    /// The probes it sent and the records it reported, in order (for the tests that break one).
    pub(crate) probes: Vec<Vec<u8>>,
    pub(crate) recs: Vec<Rec>,
}
pub(crate) struct Sim {
    pub(crate) tag: &'static str,
    pub(crate) steps: Vec<StepSim>,
    pub(crate) expect: ProtoExpect,
    pub(crate) stack: PeerStack,
    pub(crate) extra: Vec<(String, Vec<u8>)>,
    pub(crate) omit: Vec<String>,
}

pub(crate) fn stack() -> PeerStack {
    PeerStack {
        icmp_ratemask: "0".into(),
        icmp_echo_ignore_all: "0".into(),
        sctp_in_kernel: false,
        responder: responder_args(),
    }
}

/// The peer capture of one step and the records the stand's answers give: the start marker, the next-hop ARP (a scan
/// that is no ARP scan), each probe 10 ms apart with its answer 1 ms later (and the kernel noise both hosts add), the
/// end markers.
fn wire(c: &CaseSpec, t0: f64, probes: &[Vec<u8>]) -> (Frames, Vec<Rec>) {
    let st = stand();
    let mut fr: Frames = vec![(t0, marker(&st, START_PAYLOAD))];
    if !c.arp {
        fr.push((t0 + 0.2, next_hop_request()));
        fr.push((t0 + 0.201, next_hop_reply()));
    }
    let mut recs = Vec::new();
    let mut last = t0;
    for (i, p) in probes.iter().enumerate() {
        let t = t0 + 0.6 + i as f64 * 0.01;
        fr.push((t, p.clone()));
        let a = t + 0.001;
        let mut rec = stand_rec(p, c.arp);
        rec.ts = Some(a as u64);
        if c.arp {
            fr.push((a, arp_reply(p)));
        } else {
            match (rec.proto, rec.st) {
                (Proto::Tcp, St::Open) => {
                    let r = tcp_reply(p, 0x12);
                    fr.push((a, r.clone()));
                    fr.push((a + 0.0005, scanner_rst(&r)));
                }
                (Proto::Tcp, _) => fr.push((a, tcp_reply(p, 0x14))),
                (Proto::Udp, St::Open) => {
                    let r = udp_reply(p);
                    fr.push((a, r.clone()));
                    // The scanner host's kernel has no socket on the scanner's port: its ICMP 3/3 back.
                    fr.push((a + 0.0005, icmp_error(&r, 3, true)));
                }
                (Proto::Udp, _) => fr.push((a, icmp_error(p, 3, false))),
                (Proto::Icmp, _) => fr.push((a, echo_reply(p, 0))),
                (Proto::Sctp, _) => {
                    let r = sctp_reply(p, PEER_MAC, &SCTP_OPEN).unwrap();
                    fr.push((a, r.clone()));
                    // The peer kernel without SCTP, and the scanner kernel without SCTP: protocol unreachable.
                    fr.push((a + 0.0002, icmp_error(p, 2, false)));
                    fr.push((a + 0.0005, icmp_error(&r, 2, true)));
                }
                (Proto::Arp, _) => {}
            }
        }
        recs.push(rec);
        last = a;
    }
    for k in 0..3 {
        fr.push((last + 1.0 + f64::from(k) * 0.05, marker(&st, END_PAYLOAD)));
    }
    (fr, recs)
}

impl Sim {
    pub(crate) fn new(tag: &'static str) -> Sim {
        let c = case(tag).unwrap();
        let probes = plan_stream(&c).unwrap();
        let mut steps_ = Vec::new();
        for (i, spec) in steps(tag).unwrap().into_iter().enumerate() {
            let t0 = T0 + 100.0 * i as f64;
            let (frames, recs) = wire(&c, t0, &probes);
            let shown: Vec<Rec> = recs
                .iter()
                .filter(|r| c.show_closed || r.st != St::Closed)
                .cloned()
                .collect();
            let oracle = spec.who == Who::Oracle;
            let doc = spec.out.file().map(|_| render(spec.out, &shown, !oracle));
            let stdout = if spec.out == Out::Stdout {
                render(Out::Stdout, &shown, true)
            } else {
                Vec::new()
            };
            steps_.push(StepSim {
                argv: spec.argv.clone(),
                stderr: if oracle {
                    ORACLE_STDERR.into()
                } else {
                    rm_stderr(c.arp, probes.len(), &recs)
                },
                spec,
                stdout,
                exit: 0,
                frames,
                doc,
                probes: probes.clone(),
                recs: shown,
            });
        }
        Sim {
            tag,
            steps: steps_,
            expect: expect(tag).unwrap(),
            stack: stack(),
            extra: Vec::new(),
            omit: Vec::new(),
        }
    }
    pub(crate) fn step_mut(&mut self, name: &str) -> &mut StepSim {
        self.steps.iter_mut().find(|s| s.spec.name == name).unwrap()
    }
    fn files(&self) -> Vec<(String, Vec<u8>)> {
        let json = |v: &dyn erased::Ser| v.bytes();
        let mut f: Vec<(String, Vec<u8>)> = vec![
            (EXPECT_JSON.into(), json(&self.expect)),
            (ISOLATION_JSON.into(), linux_isolation()),
            (ISOLATION_POST_JSON.into(), linux_isolation()),
            (PEER_STACK_JSON.into(), json(&self.stack)),
        ];
        for s in &self.steps {
            let n = s.spec.name;
            f.push((
                format!("{n}/argv.json"),
                json(&ArgvRecord {
                    argv: s.argv.clone(),
                }),
            ));
            f.push((format!("{n}/stdout.txt"), s.stdout.clone()));
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
            if let (Some(name), Some(d)) = (s.spec.out.file(), &s.doc) {
                f.push((format!("{n}/{name}"), d.clone()));
            }
        }
        f.extend(self.extra.iter().cloned());
        f.retain(|(n, _)| !self.omit.contains(n));
        f
    }
    /// The case directory under `root/runs/<tag>`, with `manifest.json` at the root if none is there yet.
    pub(crate) fn write(&self, root: &Path) -> PathBuf {
        let man = root.join(MANIFEST_JSON);
        if !man.exists() {
            fs::write(
                &man,
                json!({"protocols": "linux", "lab_id": LAB_ID}).to_string(),
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
/// `serde_json::to_vec_pretty` behind one object-safe call (the generator's records are of several types).
mod erased {
    pub(crate) trait Ser {
        fn bytes(&self) -> Vec<u8>;
    }
    impl<T: serde::Serialize> Ser for T {
        fn bytes(&self) -> Vec<u8> {
            serde_json::to_vec_pretty(self).unwrap()
        }
    }
}

/// The whole evidence directory: every case of the table and the root's teardown record.
fn all_cases(root: &Path) {
    for tag in planned_tags() {
        Sim::new(tag).write(root);
    }
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
}
fn run_of<'a>(res: &'a Value, tag: &str) -> &'a Value {
    array(&res["runs"])
        .iter()
        .find(|r| r["tag"] == tag)
        .unwrap_or_else(|| panic!("no run {tag}"))
}
fn bad(run: &Value) -> Vec<String> {
    array(&run["checks"])
        .iter()
        .filter(|c| c["result"] != PASS)
        .map(|c| format!("{} {}: {}", s(&c["result"]), s(&c["name"]), s(&c["detail"])))
        .collect()
}
/// The verdict of one case written alone (with its manifest and teardown), and its failing checks.
fn judge_one(sim: &Sim) -> (String, Vec<String>) {
    let root = scratch();
    sim.write(&root);
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = verify_dir(&root);
    let run = run_of(&res, sim.tag).clone();
    fs::remove_dir_all(&root).unwrap();
    (s(&run["verdict"]).to_owned(), bad(&run))
}
fn has(bad: &[String], result: &str, needle: &str) -> bool {
    bad.iter()
        .any(|b| b.starts_with(result) && b.contains(needle))
}

// ------------------------------------------------------------------ the pure pieces

#[test]
fn crc32c_matches_c_sctp_selftest() {
    // proto-sctp.c:195-208: the 32 bytes of the selftest; bytes 8..12 hold the CRC as it goes on the wire.
    let t: [u8; 32] = [
        0xd1, 0x60, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x58, 0xe4, 0x5d, 0x36, 0x01, 0x00, 0x00,
        0x14, 0x9e, 0x8d, 0x52, 0x25, 0x00, 0x00, 0x80, 0x00, 0x00, 0x0a, 0x08, 0x00, 0x46, 0x1a,
        0xdf, 0x3d,
    ];
    assert_eq!(crc32c_wire(&t), [0x58, 0xe4, 0x5d, 0x36]);
}

#[test]
fn sctp_reply_answers_init_with_init_ack_or_abort_like_linux() {
    let c = case("p03_sctp_init_ack_abort").unwrap();
    let plan = plan_stream(&c).unwrap();
    assert_eq!(plan.len(), 8, "4 peers x 2 ports");
    for p in &plan {
        let r = sctp_reply(p, PEER_MAC, &SCTP_OPEN).expect("an INIT is answered");
        let seg = &r[34..];
        // Ethernet and IPv4 back to the scanner, from the INIT's destination, TTL 64, a right header checksum.
        assert_eq!(&r[0..6], &p[6..12]);
        assert_eq!(&r[6..12], &PEER_MAC);
        assert_eq!((src(&r), dst(&r)), (dst(p), src(p)));
        assert_eq!((r[22], r[23]), (64, 132));
        assert!(sums_ok(&r), "IPv4 sum and CRC-32C");
        // Ports swapped, the INIT's initiate tag as the verification tag.
        assert_eq!((be16(seg, 0), be16(seg, 2)), (be16(p, 36), be16(p, 34)));
        assert_eq!(&seg[4..8], &p[50..54]);
        if be16(p, 36) == 2905 {
            assert_eq!(&seg[12..16], &[2, 0, 0, 32], "INIT-ACK");
            assert_eq!(be32(seg, 16), PEER_INIT_TAG);
            assert_eq!(&seg[32..36], &[0, 7, 0, 12], "a state cookie parameter");
        } else {
            assert_eq!(&seg[12..], &[6, 0, 0, 4], "ABORT, T bit 0, no cause");
        }
    }
    // Nothing else is answered: another MAC, a wrong CRC, a chunk that is no INIT, a fragment.
    let p = &plan[0];
    assert!(sctp_reply(p, SCANNER_MAC, &SCTP_OPEN).is_none());
    let mut bad_crc = p.clone();
    bad_crc[42] ^= 1;
    assert!(sctp_reply(&bad_crc, PEER_MAC, &SCTP_OPEN).is_none());
    let mut not_init = p.clone();
    not_init[46] = 2;
    let crc = crc32c_wire(&not_init[34..]);
    not_init[42..46].copy_from_slice(&crc);
    assert!(sctp_reply(&not_init, PEER_MAC, &SCTP_OPEN).is_none());
    let mut frag = p.clone();
    frag[20] |= 0x20;
    assert!(sctp_reply(&frag, PEER_MAC, &SCTP_OPEN).is_none());
}

#[test]
fn r12_equates_only_a_udp_checksum_of_ffff_against_0000() {
    let p = plan_stream(&case("p02_udp_payloads_and_closed").unwrap()).unwrap()[0].clone();
    assert_eq!(same_probe(&p, &p), Some(false));
    let (mut rm, mut c) = (p.clone(), p.clone());
    rm[40..42].copy_from_slice(&[0xff, 0xff]);
    c[40..42].copy_from_slice(&[0, 0]);
    assert_eq!(same_probe(&rm, &c), Some(true), "R12");
    assert_eq!(same_probe(&c, &rm), None, "rmasscan never sends 0x0000");
    let mut other = c.clone();
    other[45] ^= 1;
    assert_eq!(same_probe(&rm, &other), None, "any other byte");
    // The same two bytes in a TCP SYN are no checksum rule.
    let syn = plan_stream(&case("p05_mixed_protos").unwrap())
        .unwrap()
        .into_iter()
        .find(|f| f[23] == 6)
        .unwrap();
    let (mut a, mut b) = (syn.clone(), syn);
    a[40..42].copy_from_slice(&[0xff, 0xff]);
    b[40..42].copy_from_slice(&[0, 0]);
    assert_eq!(same_probe(&a, &b), None);
}

#[test]
fn the_parsers_read_cs_own_documents_of_every_protocol() {
    // The C oracle's --readscan outputs of the protocols golden input (tests/golden/formats), not a rendering here.
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/formats/outputs"
    );
    let read = |n: &str| fs::read(format!("{dir}/{n}")).unwrap();
    let list = parse_doc(Out::List, &read("protocols.open-closed.list.out")).unwrap();
    let json_ = parse_doc(Out::Json, &read("protocols.open-closed.json.out")).unwrap();
    let bin = parse_doc(Out::Binary, &read("protocols.open-closed.binary.out")).unwrap();
    assert!(list.complete && json_.complete && bin.complete);
    assert_eq!(list.records.len(), 12);
    let protos: BTreeSet<Proto> = list.records.iter().map(|r| r.proto).collect();
    assert_eq!(
        protos,
        BTreeSet::from([Proto::Icmp, Proto::Tcp, Proto::Udp, Proto::Sctp])
    );
    // The three formats carry the same records; JSON and -oB also reason and TTL.
    for ((l, j), b) in list.records.iter().zip(&json_.records).zip(&bin.records) {
        assert_eq!(
            (l.st, l.proto, l.ip, l.port, l.ts),
            (j.st, j.proto, j.ip, j.port, j.ts)
        );
        assert_eq!(j, b, "JSON and -oB agree field for field");
    }
    assert_eq!(
        json_.records[0].show(),
        "open 192.0.2.10 80/tcp reason syn-ack ttl 64"
    );
    assert_eq!(
        json_.records[3].show(),
        "closed 192.0.2.11 161/udp reason none ttl 63"
    );
    // A file cut after a record (the oracle's forced exit) is a document that is not complete.
    let raw = read("protocols.open-closed.list.out");
    let cut = parse_doc(Out::List, &raw[..raw.len() - "# end\n".len()]).unwrap();
    assert!(!cut.complete && cut.records.len() == 12);
    let raw = read("protocols.open-closed.binary.out");
    let cut = parse_doc(Out::Binary, &raw[..raw.len() - 99]).unwrap();
    assert!(!cut.complete && cut.records.len() == 12);
    assert!(parse_doc(Out::Binary, &raw[..raw.len() - 98]).is_err());
}

#[test]
fn the_interactive_line_is_cs_form_and_padding() {
    let line = |s: &str| format!("{s:<79}\n");
    let d = parse_doc(
        Out::Stdout,
        line("Discovered up port 0/arp on 198.18.0.3 (02:aa:00:00:00:02) ").as_bytes(),
    )
    .unwrap();
    assert_eq!(
        d.records[0].show(),
        "up 198.18.0.3 0/arp mac 02:aa:00:00:00:02"
    );
    assert!(
        parse_doc(
            Out::Stdout,
            b"Discovered up port 0/arp on 198.18.0.3 (02:aa:00:00:00:02)\n"
        )
        .is_err()
    );
    assert!(
        parse_doc(
            Out::Stdout,
            line("Discovered open port 0/arp on 198.18.0.3").as_bytes()
        )
        .is_err()
    );
    assert!(
        parse_doc(
            Out::Stdout,
            line("Discovered open port 53/udp on 198.18.0.3").as_bytes()
        )
        .is_ok()
    );
}

#[test]
fn reason_names_follow_c() {
    assert_eq!(reason_string(0), "none");
    assert_eq!(reason_string(0x12), "syn-ack");
    assert_eq!(reason_string(0x14), "rst-ack");
    assert_eq!(reason_string(0xff), "fin-syn-rst-psh-ack-urg-ece-cwr");
}

#[test]
fn the_peer_stack_rules() {
    let p01 = case("p01_ping").unwrap();
    let p03 = case("p03_sctp_init_ack_abort").unwrap();
    assert_eq!(peer_stack_problem(&stack(), &p03), None);
    let sctp = PeerStack {
        sctp_in_kernel: true,
        ..stack()
    };
    assert!(peer_stack_problem(&sctp, &p03).unwrap().contains("SCTP"));
    assert_eq!(peer_stack_problem(&sctp, &p01), None, "a case without SCTP");
    let limited = PeerStack {
        icmp_ratemask: "6168".into(),
        ..stack()
    };
    assert!(
        peer_stack_problem(&limited, &p01)
            .unwrap()
            .contains("icmp_ratemask")
    );
    let other = PeerStack {
        responder: vec!["--ports".into(), "80,8080".into()],
        ..stack()
    };
    assert!(peer_stack_problem(&other, &p01).is_some());
    // /proc/net/protocols: the SCTP rows of a kernel that has it, none without.
    let head = "protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re bi br ha uh gp em\n";
    assert!(!lists_sctp(&format!(
        "{head}UDP       1152      3       2   NI       0   yes  kernel      y  y  y  n  y  y  y  n  y  y  y  y  y  n  n  y  y  y  n\n"
    )));
    assert!(lists_sctp(&format!(
        "{head}SCTPv6    1536      0      -1   NI       0   yes  sctp        y  y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  y\nSCTP      1376      0      -1   NI       0   yes  sctp        y  y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  y\n"
    )));
}

#[test]
fn c_prints_every_non_tcp_reply_and_rmasscan_collapses_repeats() {
    // A second, identical ICMP 3/3 for one closed UDP probe: C prints two records, rmasscan one (non-tcp-dedup).
    let c = case("p02_udp_payloads_and_closed").unwrap();
    let probes = plan_stream(&c).unwrap();
    let (mut fr, _) = wire(&c, T0, &probes);
    let closed = probes.iter().find(|p| ports(p).1 == 500).unwrap();
    let at = fr.len() - 3;
    fr.insert(at, (T0 + 0.9, icmp_error(closed, 3, false)));
    let v = view(&fr, &stand(), false);
    let rm = wire_records(&v, Who::Rmasscan, Out::Json, true);
    let or = wire_records(&v, Who::Oracle, Out::Json, true);
    assert_eq!(rm.len(), probes.len());
    assert_eq!(or.len(), probes.len() + 1);
    let (collapsed, n) = collapse(&or);
    assert_eq!((collapsed, n), (rm, 1));
}

// ------------------------------------------------------------------ whole directories

#[test]
fn the_generator_passes_every_case_and_the_verdict_rederives_byte_for_byte() {
    let root = scratch();
    all_cases(&root);
    let res = verify_dir(&root);
    for tag in planned_tags() {
        let run = run_of(&res, tag);
        assert_eq!(run["verdict"], PASS, "{tag}: {:#?}", bad(run));
        // Every named deviation of the case is in its notes and has its check.
        let notes = array(&run["notes"]["deviations"]);
        assert_eq!(notes.len(), case(tag).unwrap().deviations.len(), "{tag}");
    }
    assert_eq!(res["overall"], PASS, "{}", res["totals"]);
    assert!(array(&res["safety_trips"]).is_empty());
    let again = verify_dir(&root);
    assert_eq!(
        serde_json::to_string_pretty(&res).unwrap(),
        serde_json::to_string_pretty(&again).unwrap()
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_probe_byte_that_differs_from_the_oracle_or_the_plan_fails() {
    // The oracle's Echo Request differs in one data byte: rmasscan no longer equals C.
    let mut sim = Sim::new("p01_ping");
    let s = sim.step_mut("oracle-list");
    let at = s
        .frames
        .iter()
        .position(|(_, f)| f.get(23) == Some(&1) && f.get(34) == Some(&8))
        .unwrap();
    s.frames[at].1[60] ^= 0x01;
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(&b, FAIL, "the probes equal the C oracle's"), "{b:#?}");
    // rmasscan sends a probe the plan does not have (one Echo Request dropped).
    let mut sim = Sim::new("p01_ping");
    let s = sim.step_mut("list");
    let at = s
        .frames
        .iter()
        .position(|(_, f)| f.get(23) == Some(&1) && f.get(34) == Some(&8))
        .unwrap();
    s.frames.remove(at);
    s.frames.remove(at);
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "the probes on the wire equal the plan"),
        "{b:#?}"
    );
}

#[test]
fn a_document_that_differs_from_the_wire_or_from_c_fails() {
    // rmasscan's JSON lacks a record.
    let mut sim = Sim::new("p02_udp_payloads_and_closed");
    let s = sim.step_mut("json");
    let recs: Vec<Rec> = s.recs[1..].to_vec();
    s.doc = Some(render(Out::Json, &recs, true));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(
        &b,
        FAIL,
        "json: the document holds the records of the replies on its wire"
    ));
    assert!(has(&b, FAIL, "json: the records equal the C oracle's"));
    // rmasscan's -oB has a wrong TTL on one record.
    let mut sim = Sim::new("p03_sctp_init_ack_abort");
    let s = sim.step_mut("binary");
    let mut recs = s.recs.clone();
    recs[2].ttl = Some(63);
    s.doc = Some(render(Out::Binary, &recs, true));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(&b, FAIL, "binary: the document holds the records"));
    // rmasscan's -oL holds the right records in another order than C's.
    let mut sim = Sim::new("p03_sctp_init_ack_abort");
    let s = sim.step_mut("list");
    let mut recs = s.recs.clone();
    recs.swap(0, 1);
    s.doc = Some(render(Out::List, &recs, true));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "list: the records equal the C oracle's (oracle-list) in order"
        ),
        "{b:#?}"
    );
}

#[test]
fn rmasscans_stderr_and_exit_are_judged() {
    // `[+] finished` counts one reply too many.
    let mut sim = Sim::new("p05_mixed_protos");
    let s = sim.step_mut("json");
    s.stderr = s.stderr.replace("replies 16,", "replies 17,");
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "[+] finished reports sent, replies and open"),
        "{b:#?}"
    );
    // The source port is the scanner's own choice instead of the given 40000.
    let mut sim = Sim::new("p01_ping");
    let s = sim.step_mut("list");
    s.stderr = s.stderr.replace("40000 (given)", "61000 (time)");
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(&b, FAIL, "[+] lines are the stand's"));
    // A stray line, and exit 1.
    let mut sim = Sim::new("p01_ping");
    let s = sim.step_mut("list");
    s.stderr.push_str("warning: something\n");
    s.exit = 1;
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(&b, FAIL, "stderr.txt holds only"));
    assert!(has(&b, FAIL, "exit.txt is 0"));
}

#[test]
fn a_stand_that_answers_otherwise_is_invalid_never_a_fail() {
    // The peer kernel rate-limited one ICMP 3/3: a closed UDP probe without its answer (both documents agree).
    let mut sim = Sim::new("p02_udp_payloads_and_closed");
    for name in ["binary", "oracle-binary"] {
        let s = sim.step_mut(name);
        let at = s
            .frames
            .iter()
            .position(|(_, f)| f.get(6..12) == Some(&PEER_MAC[..]) && f.get(34) == Some(&3))
            .unwrap();
        s.frames.remove(at);
    }
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(&b, INVALID, "the stand answered every probe exactly once"),
        "{b:#?}"
    );
    // A frame of the peer that answers nothing.
    let mut sim = Sim::new("p01_ping");
    let s = sim.step_mut("oracle-list");
    let junk = ip_frame(
        SCANNER_MAC,
        PEER_MAC,
        Ipv4Addr::new(198, 18, 0, 3),
        SCANNER_IP,
        17,
        vec![0; 12],
    );
    let n = s.frames.len();
    s.frames.insert(n - 3, (T0 + 100.9, junk));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(has(
        &b,
        INVALID,
        "nothing on the peer side answers anything the scan did not send"
    ));
}

#[test]
fn every_named_deviation_has_its_wire_condition() {
    // icmp-echo-code-0: an Echo Reply with code 1 (C would take it, rmasscan not).
    let mut sim = Sim::new("p01_ping");
    for name in ["list", "oracle-list"] {
        let s = sim.step_mut(name);
        let probes = s.probes.clone();
        for (_, f) in s
            .frames
            .iter_mut()
            .filter(|(_, f)| f.get(6..12) == Some(&PEER_MAC[..]))
        {
            if f.get(12..14) == Some(&[8, 0][..]) && f.get(23) == Some(&1) && f.get(34) == Some(&0)
            {
                let p = probes.iter().find(|p| dst(p) == src(f)).unwrap();
                *f = echo_reply(p, 1);
            }
        }
    }
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(has(&b, INVALID, "deviation icmp-echo-code-0"), "{b:#?}");
    // rx-checksum-verify: an open UDP reply with a wrong UDP checksum.
    let mut sim = Sim::new("p02_udp_payloads_and_closed");
    let s = sim.step_mut("oracle-json");
    let (_, f) = s
        .frames
        .iter_mut()
        .find(|(_, f)| f.get(6..12) == Some(&PEER_MAC[..]) && f.get(23) == Some(&17))
        .unwrap();
    f[40] ^= 0x55;
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(has(&b, INVALID, "deviation rx-checksum-verify"), "{b:#?}");
    // sctp-tcp-fallthrough: an ABORT whose chunk flags read as RST to C.
    let mut sim = Sim::new("p03_sctp_init_ack_abort");
    let s = sim.step_mut("oracle-list");
    let (_, f) = s
        .frames
        .iter_mut()
        .find(|(_, f)| {
            f.get(6..12) == Some(&PEER_MAC[..]) && f.get(23) == Some(&132) && f.get(46) == Some(&6)
        })
        .unwrap();
    f[47] = 0x04;
    let crc = crc32c_wire(&f[34..]);
    f[42..46].copy_from_slice(&crc);
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(has(&b, INVALID, "deviation sctp-tcp-fallthrough"), "{b:#?}");
    // arp-mac-ethernet-source: an ARP reply whose sender hardware address is another MAC.
    let mut sim = Sim::new("p04_arp_scan");
    let s = sim.step_mut("oracle-binary");
    let (_, f) = s
        .frames
        .iter_mut()
        .find(|(_, f)| f.get(12..14) == Some(&[8, 6][..]) && f.get(21) == Some(&2))
        .unwrap();
    f[27] = 0x99;
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(&b, INVALID, "deviation arp-mac-ethernet-source"),
        "{b:#?}"
    );
}

/// `f` inserted into a step's capture just before its end markers (inside the witness window).
fn with_frame(fr: &Frames, f: Vec<u8>) -> Frames {
    let mut fr = fr.clone();
    let at = fr.len() - 3;
    let t = fr[at - 1].0 + 0.001;
    fr.insert(at, (t, f));
    fr
}
fn tcp_from_scanner(to: Ipv4Addr, dport: u16, flags: u8) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&40000_u16.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[12] = 0x50;
    t[13] = flags;
    ip_frame(PEER_MAC, SCANNER_MAC, SCANNER_IP, to, 6, t)
}
fn class_counts(v: &WireView) -> Vec<usize> {
    SCANNER_CLASSES
        .iter()
        .map(|(k, _)| v.scanner_named.get(k).copied().unwrap_or(0))
        .collect()
}

#[test]
fn the_scanner_sides_frames_of_the_stand_are_named_and_counted_in_the_notes() {
    // p05 on four peers: T:80 open (a reset per SYN-ACK), U:53 open (an ICMP 3/3 per UDP reply), S:2905 open (an
    // ICMP 3/2 per INIT-ACK), the next-hop who-has once; nothing else from the scanner MAC.
    let c = case("p05_mixed_protos").unwrap();
    let (fr, _) = wire(&c, T0, &plan_stream(&c).unwrap());
    let v = view(&fr, &stand(), false);
    assert_eq!(class_counts(&v), [1, 4, 4, 4]);
    assert!(
        v.scanner_unexplained.is_empty(),
        "{:?}",
        v.scanner_unexplained
    );
    // an ARP scan: no class at all
    let c = case("p04_arp_scan").unwrap();
    let (fr, _) = wire(&c, T0, &plan_stream(&c).unwrap());
    let v = view(&fr, &stand(), true);
    assert_eq!(class_counts(&v), [0, 0, 0, 0]);
    assert!(v.scanner_unexplained.is_empty());
    // the notes carry each step's counts and what each class is
    let root = scratch();
    Sim::new("p05_mixed_protos").write(&root);
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = verify_dir(&root);
    let run = run_of(&res, "p05_mixed_protos");
    assert_eq!(run["verdict"], PASS, "{:#?}", bad(run));
    for step in ["json", "oracle-json"] {
        assert_eq!(
            run["notes"]["scanner_frames"][step],
            json!({"next_hop_who_has": 1, "rst_to_syn_ack": 4, "port_unreachable_to_udp_reply": 4,
                   "protocol_unreachable_to_sctp_reply": 4, "unexplained": 0}),
            "{step}"
        );
    }
    let classes = run["notes"]["scanner_frame_classes"].as_object().unwrap();
    assert_eq!(classes.len(), SCANNER_CLASSES.len());
    assert!(s(&classes["rst_to_syn_ack"]).contains("main.c:1095"));
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_scanner_frame_of_no_named_class_is_left_unexplained() {
    let c = case("p05_mixed_protos").unwrap();
    let probes = plan_stream(&c).unwrap();
    let (fr, _) = wire(&c, T0, &probes);
    let st = stand();
    let base = class_counts(&view(&fr, &st, false));
    let peer = Ipv4Addr::new(198, 18, 0, 2);
    let from_peer = |proto: u8, flags: Option<u8>| {
        fr.iter()
            .map(|(_, f)| f.clone())
            .find(|f| {
                f[6..12] == PEER_MAC
                    && f.get(23) == Some(&proto)
                    && flags.is_none_or(|x| f.get(47) == Some(&x))
            })
            .unwrap()
    };
    let (syn_ack, udp, sctp) = (
        from_peer(6, Some(0x12)),
        from_peer(17, None),
        from_peer(132, None),
    );
    let udp_probe = probes.iter().find(|p| p[23] == 17).unwrap();
    let mut wrong_seq = scanner_rst(&syn_ack);
    wrong_seq[38] ^= 1;
    let mut rst_ack = scanner_rst(&syn_ack);
    rst_ack[47] = 0x14;
    let mut cookie_echo = vec![0x9c, 0x40, 0x0b, 0x59, 0, 0, 0, 1, 0, 0, 0, 0];
    cookie_echo.extend([10, 0, 0, 4]);
    let mut arp_reply = Vec::new();
    arp_reply.extend(PEER_MAC);
    arp_reply.extend(SCANNER_MAC);
    arp_reply.extend([8, 6, 0, 1, 8, 0, 6, 4, 0, 2]);
    arp_reply.extend(SCANNER_MAC);
    arp_reply.extend(SCANNER_IP.octets());
    arp_reply.extend(PEER_MAC);
    arp_reply.extend(peer.octets());
    let extra: Vec<(&str, Vec<u8>)> = vec![
        ("a TCP ACK", tcp_from_scanner(peer, 80, 0x10)),
        ("a TCP SYN-ACK", tcp_from_scanner(peer, 80, 0x12)),
        ("a reset of no SYN-ACK", wrong_seq),
        ("RST-ACK", rst_ack),
        (
            "an SCTP COOKIE ECHO",
            ip_frame(PEER_MAC, SCANNER_MAC, SCANNER_IP, peer, 132, cookie_echo),
        ),
        ("an ARP reply", arp_reply),
        (
            "an ICMP 3/3 quoting a probe",
            ip_frame(
                PEER_MAC,
                SCANNER_MAC,
                SCANNER_IP,
                peer,
                1,
                icmp(3, 3, &[0; 4], &udp_probe[14..42]),
            ),
        ),
        ("an ICMP 3/2 quoting a UDP reply", icmp_error(&udp, 2, true)),
        (
            "an ICMP 3/3 quoting an SCTP reply",
            icmp_error(&sctp, 3, true),
        ),
        (
            "an Echo Reply",
            ip_frame(
                PEER_MAC,
                SCANNER_MAC,
                SCANNER_IP,
                peer,
                1,
                icmp(0, 0, &[0, 1, 0, 1], &[]),
            ),
        ),
        ("a 42-byte who-has for the gateway", {
            let mut f = next_hop_request();
            f.truncate(42);
            f
        }),
    ];
    for (what, f) in extra {
        let v = view(&with_frame(&fr, f), &st, false);
        assert_eq!(
            v.scanner_unexplained.len(),
            1,
            "{what}: {:?}",
            v.scanner_unexplained
        );
        assert_eq!(class_counts(&v), base, "{what}");
    }
    // In an ARP scan the router MAC is given: the next-hop who-has is no class there.
    let c = case("p04_arp_scan").unwrap();
    let (fr, _) = wire(&c, T0, &plan_stream(&c).unwrap());
    let v = view(&with_frame(&fr, next_hop_request()), &st, true);
    assert_eq!(
        v.scanner_unexplained.len(),
        1,
        "{:?}",
        v.scanner_unexplained
    );
}

#[test]
fn an_extra_frame_of_the_scanner_fails_rmasscan_and_invalidates_the_oracle() {
    const CHECK: &str = "every frame of the scanner MAC is a probe of the scan or of a named class";
    let extra = tcp_from_scanner(Ipv4Addr::new(198, 18, 0, 2), 80, 0x10);
    let mut sim = Sim::new("p05_mixed_protos");
    let s = sim.step_mut("json");
    s.frames = with_frame(&s.frames, extra.clone());
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(&b, FAIL, &format!("json: {CHECK}")), "{b:#?}");
    assert_eq!(b.len(), 1, "{b:#?}");
    // the same frame on the oracle's step: the oracle (or the stand) misbehaved, not rmasscan
    let mut sim = Sim::new("p05_mixed_protos");
    let s = sim.step_mut("oracle-json");
    s.frames = with_frame(&s.frames, extra);
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(has(&b, INVALID, &format!("oracle-json: {CHECK}")), "{b:#?}");
    assert_eq!(b.len(), 1, "{b:#?}");
}

#[test]
fn an_arp_scan_that_asks_the_gateway_fails() {
    let mut sim = Sim::new("p04_arp_scan");
    let s = sim.step_mut("stdout");
    s.frames.insert(1, (T0 + 0.2, next_hop_request()));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "no ARP request to the default gateway"),
        "{b:#?}"
    );
    // and the interactive lines must carry the neighbours' MAC (here the scanner's own, an allowlisted name)
    let mut sim = Sim::new("p04_arp_scan");
    let s = sim.step_mut("stdout");
    s.stdout = String::from_utf8(s.stdout.clone())
        .unwrap()
        .replace("02:aa:00:00:00:02", "02:aa:00:00:00:01")
        .into_bytes();
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(&b, FAIL, "--arp finds every neighbour"), "{b:#?}");
}

#[test]
fn a_probe_off_the_stand_is_a_safety_fail() {
    let mut sim = Sim::new("p02_udp_payloads_and_closed");
    let s = sim.step_mut("json");
    let off = ip_frame(
        PEER_MAC,
        SCANNER_MAC,
        SCANNER_IP,
        Ipv4Addr::new(10, 9, 8, 7),
        17,
        vec![0x9c, 0x40, 0, 53, 0, 8, 0, 0],
    );
    s.frames.insert(2, (T0 + 0.5, off));
    let root = scratch();
    sim.write(&root);
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = verify_dir(&root);
    assert_eq!(res["overall"], FAIL);
    assert!(
        !array(&res["safety_trips"]).is_empty(),
        "{:#?}",
        res["safety_trips"]
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn the_oracles_document_without_footer_needs_its_forced_exit() {
    let mut sim = Sim::new("p03_sctp_init_ack_abort");
    let s = sim.step_mut("oracle-binary");
    s.stderr = s.stderr.replace(sv::FORCED_EXIT, "");
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(has(
        &b,
        INVALID,
        "oracle-binary: its file lacks the footer only after masscan's forced exit"
    ));
    // rmasscan's document without the footer is a FAIL.
    let mut sim = Sim::new("p03_sctp_init_ack_abort");
    let s = sim.step_mut("binary");
    let recs = s.recs.clone();
    s.doc = Some(render(Out::Binary, &recs, false));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(&b, FAIL, "binary: its file lacks the footer"));
}

#[test]
fn the_case_records_must_be_the_tables() {
    // peer-stack.json of an SCTP case on a host whose kernel has SCTP.
    let mut sim = Sim::new("p05_mixed_protos");
    sim.stack.sctp_in_kernel = true;
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(has(&b, INVALID, "peer-stack.json"));
    // an argv that is not the table's: the run cannot FAIL, only be INVALID
    let mut sim = Sim::new("p01_ping");
    sim.step_mut("list").argv.push("--ttl".into());
    sim.step_mut("list").exit = 1;
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(has(&b, INVALID, "list/argv.json is the step's argv"));
    // a case without its peer-stack.json is not run as far as the evidence shows
    let mut sim = Sim::new("p01_ping");
    sim.omit.push(PEER_STACK_JSON.into());
    let (v, b) = judge_one(&sim);
    assert_eq!(v, NOT_RUN, "{b:#?}");
    assert!(has(&b, NOT_RUN, "peer-stack.json present"), "{b:#?}");
}

#[test]
fn the_table_names_only_the_lab_and_every_case_has_its_documents() {
    for c in CASES {
        let st = steps(c.tag).unwrap();
        assert_eq!(st.len(), 2 * c.outs.len());
        for s in &st {
            assert!(
                crate::autodetect_suite::addresses_outside_the_lab(&s.argv).is_empty(),
                "{}",
                c.tag
            );
            assert!(s.argv.windows(2).any(|w| w == ["--source-port", "40000"]));
            assert!(s.argv.windows(2).any(|w| w == ["--seed", "1"]));
        }
        // The plan of every case builds, one probe per (peer, port).
        let n = plan_stream(&c).unwrap().len();
        let ports = c.plan_ports.split(',').count();
        assert_eq!(n, 4 * ports, "{}", c.tag);
    }
    assert_eq!(
        steps("p02_udp_payloads_and_closed").unwrap()[0].argv,
        [
            "198.18.0.2-198.18.0.5",
            "-sU",
            "-p53,161,500,59999",
            "-oJ",
            "output.json",
            "--show",
            "open,closed",
            "--seed",
            "1",
            "--rate",
            "100",
            "--wait",
            "3",
            "--source-port",
            "40000"
        ]
    );
}
