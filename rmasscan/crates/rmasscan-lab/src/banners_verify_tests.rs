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
        tests::{LAB_ID, Sim as AdSim, T0, TEARDOWN, linux_isolation, marker, status_fragments},
    },
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

/// One record as the generator renders it: a status, or a banner with its application number and payload.
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
}
/// The application names of the UDP banners, by number (`src/masscan-app.c:8-57`).
fn name(app: u16) -> &'static str {
    match app {
        0 => "unknown",
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
                }
            }
            if complete {
                b.extend(b"# end\n");
            }
        }
        Out::Binary => {
            let first = match &recs[0] {
                SimRec::Status { ts, .. } | SimRec::Banner { ts, .. } => *ts,
            };
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
        Sim::with_answer(tag, scenario_reply)
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
            (ISOLATION_JSON.into(), linux_isolation()),
            (ISOLATION_POST_JSON.into(), linux_isolation()),
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
    let ts = match st.recs[at] {
        SimRec::Status { ts, .. } => ts,
        SimRec::Banner { .. } => unreachable!(),
    };
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
    assert_eq!(planned_tags(), ["b01_banners", "b02_rawudp"]);
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
