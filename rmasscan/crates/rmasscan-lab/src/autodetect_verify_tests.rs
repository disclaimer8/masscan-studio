//! Synthetic, hermetic autodetect evidence. Every frame is built here: ARP from `rmasscan_core::arp`, SYNs from the
//! scan plan (`ReadyPlan` + `ProbeCursor`, independent of the verifier's `plan_args_from`), peer SYN-ACK/RST and the
//! scanner kernel's RST by hand. The `[+]` lines are rendered from the case's detection record (not with the
//! verifier's parser), so the parser is checked against an independent writer. One rule at a time is broken.
//! Nothing touches a network or a real evidence directory; scratch names come from `windows_suite::nonce`.
use super::*;
use crate::{
    capture::{IsolationMode, isolation_default_route},
    link::{END_PAYLOAD, START_PAYLOAD, marker_frame},
    pcap::{self, Frames},
    windows_suite::nonce,
};
use rmasscan_core::{
    arp::{encode_reply, encode_request},
    config::{Operation, ScanConfig, parse_rate, parse_source_port, validate},
    massip::MassIp,
    packet::LinkType,
    probe::{AdapterBinding, ProbeCursor, ReadyPlan},
    targets::{add_target_string, parse_ports},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

const T0: f64 = 1_800_000_000.0;
const TIME_PORT: &str = "41234";
const ROUTER_HINTS: [&str; 3] = [
    "    [hint] try \"--router-ip 192.0.2.1\" to specify different router",
    "    [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP",
    "    [hint] try \"--interface eth0\" to change interface",
];

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-autodetect-verify-{}", nonce()));
    fs::create_dir_all(&d).unwrap();
    d
}
fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn sha_of(b: &[u8]) -> String {
    hexs(&Sha256::digest(b))
}
fn dash(m: [u8; 6]) -> String {
    m.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join("-")
}
fn ip4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}
fn sourced(v: &str, s: &str) -> Sourced {
    Sourced {
        value: v.into(),
        source: s.into(),
    }
}
fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

/// The case kinds as the brief's case tables give them (the generator's own copy, not the verifier's).
fn kind_of(tag: &str) -> CaseKind {
    match tag {
        "l09_arp_timeout" | "m04_user_arp_timeout" | "w05_arp_timeout" => CaseKind::ArpTimeout,
        "l10_no_such_adapter"
        | "m01_user_masked"
        | "m05_user_no_adapter"
        | "m06_user_no_ip"
        | "w06_multi_no_gateway"
        | "w08b_restricted_scan" => CaseKind::Refusal,
        "l12_iflist"
        | "m07_user_iflist"
        | "m11_root_iflist"
        | "w07_iflist"
        | "w08a_restricted_iflist" => CaseKind::Iflist,
        "l11_parity" => CaseKind::Parity,
        _ => CaseKind::Scan,
    }
}
fn tags_of(plan: Plan) -> Vec<&'static str> {
    match plan {
        Plan::Linux => vec![
            "l01_auto",
            "l02_auto_multi",
            "l03_adapter",
            "l04_adapter_ip",
            "l05_adapter_mac",
            "l06_router_ip",
            "l07_router_mac",
            "l08_source_port",
            "l09_arp_timeout",
            "l10_no_such_adapter",
            "l11_parity",
            "l12_iflist",
        ],
        Plan::Macos => vec![
            "m01_user_masked",
            "m02_user_explicit",
            "m03_user_router_mac",
            "m04_user_arp_timeout",
            "m05_user_no_adapter",
            "m06_user_no_ip",
            "m07_user_iflist",
        ],
        Plan::MacosRoot => vec!["m10_root_auto_mac", "m11_root_iflist"],
        Plan::Windows => vec![
            "w01_auto",
            "w02_adapter_npf",
            "w03_adapter_friendly",
            "w04_router_mac",
            "w05_arp_timeout",
            "w06_multi_no_gateway",
            "w07_iflist",
            "w08a_restricted_iflist",
            "w08b_restricted_scan",
        ],
    }
}

/// One case as a suite would define it.
#[derive(Clone)]
struct Case {
    plan: Plan,
    tag: &'static str,
    kind: CaseKind,
    argv: Vec<String>,
    targets: &'static str,
    ports: &'static str,
    /// The `[+]` lines up to `router-ip`/`router-mac (given)` (ARP, seed, source port and finished are added by the run).
    printed: DetectedRecord,
    expect: ExpectRecord,
    /// The address the scanner resolves with ARP (none: `--router-mac`, a refusal or `--iflist`).
    arp_target: Option<Ipv4Addr>,
}

fn case(plan: Plan, tag: &'static str) -> Case {
    let st = stand(plan);
    let (mac, pmac, iface) = (dash(st.scanner_mac), dash(st.peer_mac), st.iface);
    let (targets, ports) = match (plan, tag) {
        (Plan::Linux, "l02_auto_multi") => ("198.18.0.2-198.18.0.5", "80,81,8080"),
        (Plan::Linux, "l11_parity") => ("198.18.0.2-198.18.0.5", "80,8080"),
        (Plan::Linux, _) => ("198.18.0.2", "80,81,8080"),
        (Plan::Windows, "w06_multi_no_gateway") => {
            ("198.18.0.2-198.18.0.3", "80,443,8000-8007,8099")
        }
        (Plan::Windows, _) => ("198.18.0.2", "80,443,8000-8007,8099"),
        _ => ("198.18.0.2", "8000-8007,9000-9003"),
    };
    let npf = crate::windows_suite::IFACE;
    let extra: Vec<&str> = match tag {
        "l03_adapter" => vec!["--adapter", "veth-a"],
        "l04_adapter_ip" => vec!["--adapter-ip", "198.18.0.1"],
        "l05_adapter_mac" => vec!["--adapter-mac", "02-aa-00-00-00-01"],
        "l06_router_ip" => vec!["--router-ip", "198.18.0.3"],
        "l07_router_mac" => vec!["--router-mac", "02-aa-00-00-00-02"],
        "l08_source_port" => vec!["--source-port", "50000-50015"],
        "l09_arp_timeout" => vec!["--router-ip", "198.18.0.9"],
        "l10_no_such_adapter" => vec!["--adapter", "nosuch0"],
        "l11_parity" => vec!["--source-port", "40000"],
        "m01_user_masked" | "m10_root_auto_mac" => vec![
            "--adapter",
            "feth4201",
            "--adapter-ip",
            "198.18.0.1",
            "--router-ip",
            "198.18.0.2",
        ],
        "m02_user_explicit" => vec![
            "--adapter",
            "feth4201",
            "--adapter-ip",
            "198.18.0.1",
            "--adapter-mac",
            "02-ac-00-00-00-01",
            "--router-ip",
            "198.18.0.2",
        ],
        "m03_user_router_mac" => vec![
            "--adapter",
            "feth4201",
            "--adapter-ip",
            "198.18.0.1",
            "--adapter-mac",
            "02-ac-00-00-00-01",
            "--router-ip",
            "198.18.0.2",
            "--router-mac",
            "02-ac-00-00-00-02",
        ],
        "m04_user_arp_timeout" => vec![
            "--adapter",
            "feth4201",
            "--adapter-ip",
            "198.18.0.1",
            "--adapter-mac",
            "02-ac-00-00-00-01",
            "--router-ip",
            "198.18.0.3",
        ],
        "m06_user_no_ip" => vec![
            "--adapter",
            "feth4201",
            "--adapter-mac",
            "02-ac-00-00-00-01",
            "--router-ip",
            "198.18.0.2",
        ],
        "w02_adapter_npf" => vec!["--adapter", npf],
        "w03_adapter_friendly" => vec!["--adapter", "Ethernet 2"],
        "w04_router_mac" => vec!["--router-mac", "02-57-4c-3d-2e-9b"],
        "w05_arp_timeout" => vec!["--router-ip", "198.18.0.3"],
        _ => vec![],
    };
    let kind = kind_of(tag);
    let argv = if kind == CaseKind::Iflist {
        strings(&["--iflist"])
    } else {
        let mut a = strings(&[targets, &format!("-p{ports}")]);
        a.extend(strings(&extra));
        a.extend(strings(&["--seed", "1", "--rate", "100", "--wait", "3"]));
        a
    };
    let value_of = |k: &str| {
        extra
            .iter()
            .position(|x| *x == k)
            .map(|i| extra[i + 1].to_owned())
    };
    let multi = targets.contains('-');
    let first = targets.split('-').next().unwrap();
    let detection = ExpectDetection {
        interface: if value_of("--adapter").is_some() {
            sourced(iface, "given")
        } else {
            sourced(iface, &format!("detected: route to {first}"))
        },
        source_mac: sourced(
            &mac,
            if value_of("--adapter-mac").is_some() {
                "given"
            } else {
                "detected"
            },
        ),
        source_ip: sourced(
            "198.18.0.1",
            if value_of("--adapter-ip").is_some() {
                "given"
            } else {
                "detected"
            },
        ),
        router_ip: match (value_of("--router-ip"), value_of("--router-mac")) {
            (Some(ip), _) => Some(sourced(&ip, "given")),
            (None, Some(_)) => None,
            (None, None) if multi => Some(sourced("198.18.0.2", "interface default gateway")),
            (None, None) => Some(sourced("198.18.0.2", "on-link target")),
        },
        router_mac: Some(sourced(
            &pmac,
            if value_of("--router-mac").is_some() {
                "given"
            } else {
                "arp"
            },
        )),
    };
    let router_given = value_of("--router-mac").is_some();
    let printed_of = |x: &ExpectDetection, with_router_mac: bool| DetectedRecord {
        interface: Some(x.interface.clone()),
        source_mac: Some(x.source_mac.clone()),
        source_ip: Some(x.source_ip.clone()),
        router_ip: x.router_ip.clone(),
        router_mac: x
            .router_mac
            .as_ref()
            .filter(|_| with_router_mac)
            .map(|m| RouterMac {
                value: m.value.clone(),
                source: m.source.clone(),
                arp: None,
            }),
        ..DetectedRecord::default()
    };
    let refusal = |fail: &str, hints: &[&str]| ExpectRefusal {
        fail: Some(fail.to_owned()),
        hints: strings(hints),
    };
    let mut expect = ExpectRecord {
        tag: tag.to_owned(),
        kind,
        detection: None,
        refusal: None,
        iflist: None,
        preflight: match tag {
            "w01_auto" | "w06_multi_no_gateway" => {
                Some(ExpectPreflight::Interface("Ethernet 2".into()))
            }
            "m05_user_no_adapter" => Some(ExpectPreflight::Refusal(
                "198.18.0.2 is an address of this host (route via lo0)".into(),
            )),
            _ => None,
        },
    };
    let mut printed = DetectedRecord::default();
    let mut arp_target = None;
    match kind {
        CaseKind::Scan | CaseKind::Parity => {
            printed = printed_of(&detection, router_given);
            if !router_given {
                arp_target = detection.router_ip.as_ref().map(|r| ip4(&r.value));
            }
            expect.detection = Some(detection);
        }
        CaseKind::ArpTimeout => {
            let mut d = detection;
            d.router_mac = None;
            printed = printed_of(&d, false);
            arp_target = d.router_ip.as_ref().map(|r| ip4(&r.value));
            let target = d.router_ip.as_ref().unwrap().value.clone();
            expect.refusal = Some(refusal(
                &format!("ARP timed-out resolving MAC address for router {iface}: \"{target}\""),
                &ROUTER_HINTS,
            ));
            expect.detection = Some(d);
        }
        CaseKind::Refusal => {
            expect.refusal = Some(match tag {
                "l10_no_such_adapter" => refusal(
                    "no such interface \"nosuch0\"",
                    &["    [hint] did you spell the name correctly?"],
                ),
                "m01_user_masked" => refusal(
                    "MAC of interface \"feth4201\" is os-masked (Darwin hides MACs from unprivileged processes)",
                    &[
                        "    [hint] run as root, or try something like \"--source-mac 00-11-22-33-44-55\"",
                    ],
                ),
                "m05_user_no_adapter" => refusal(
                    "198.18.0.2 is an address of this host (route via lo0)",
                    &["    [hint] try \"--interface ethX\" and \"--router-ip 192.0.2.1\""],
                ),
                "m06_user_no_ip" => refusal(
                    "failed to detect IP of interface \"feth4201\"",
                    &[
                        "    [hint] did you spell the name correctly?",
                        "    [hint] if it has no IP address, manually set with something like \"--source-ip 198.51.100.17\"",
                    ],
                ),
                "w06_multi_no_gateway" => refusal(
                    "no default gateway on interface \"Ethernet 2\" for several on-link targets",
                    &ROUTER_HINTS,
                ),
                _ => {
                    // w08b: a restricted token; detection works, opening the adapter is refused. Any refusal kind.
                    let mut d = detection;
                    d.router_mac = None;
                    printed = printed_of(&d, false);
                    printed.error = Some("cannot open adapter \"Ethernet 2\": permission denied (raw packet access needs elevated privileges): PacketOpenAdapter failed".into());
                    printed.hints = strings(&[
                        "    [hint] run as Administrator; Npcap must be installed (Admin-only mode needs an elevated prompt)",
                    ]);
                    ExpectRefusal {
                        fail: None,
                        hints: vec![],
                    }
                }
            });
        }
        CaseKind::Iflist => {
            expect.iflist = Some(ExpectIflist {
                name: iface.into(),
                mac: if tag == "m07_user_iflist" {
                    "masked".into()
                } else {
                    mac.clone()
                },
            });
        }
    }
    Case {
        plan,
        tag,
        kind,
        argv,
        targets,
        ports,
        printed,
        expect,
        arp_target,
    }
}

/// The SYNs of the plan, straight from `ReadyPlan` + `ProbeCursor`.
fn plan_syns(
    st: &Stand,
    targets: &str,
    ports: &str,
    sp: &str,
    router_mac: [u8; 6],
) -> Vec<Vec<u8>> {
    let mut ips = MassIp::new();
    add_target_string(ips.ipv4_mut(), targets).unwrap();
    parse_ports(ips.ports_mut(), ports).unwrap();
    let sp = parse_source_port(sp).unwrap();
    let cfg = ScanConfig {
        targets: ips,
        seed: 1,
        max_rate: parse_rate("100").unwrap(),
        wait_secs: 3,
        adapter_ip: Some(u32::from(st.scanner_ip)),
        adapter_mac: Some(st.scanner_mac),
        router_mac: Some(router_mac),
        source_port: Some(sp),
        adapter_name: Some(st.iface.into()),
        ..ScanConfig::default()
    };
    let plan = ReadyPlan::new(
        validate(&cfg, Operation::Scan).unwrap(),
        AdapterBinding {
            interface_id: st.iface.into(),
            link_type: LinkType::Ethernet,
            source_ipv4: u32::from(st.scanner_ip),
            source_mac: st.scanner_mac,
            next_hop_mac: router_mac,
            source_ports: sp,
        },
    )
    .unwrap();
    let mut c = ProbeCursor::new(&plan, 0).unwrap();
    let mut out = Vec::new();
    loop {
        let b: Vec<Vec<u8>> = c.preload(64).iter().map(|p| p.frame.clone()).collect();
        if b.is_empty() {
            return out;
        }
        c.advance_sent_n(b.len());
        out.extend(b);
    }
}

/// A TCP frame answering `syn` (peer to scanner, or the scanner kernel back to the peer with `back`).
fn tcp_answer(syn: &[u8], flags: u8, peer_mac: [u8; 6], back: bool) -> Vec<u8> {
    let o = 14 + usize::from(syn[14] & 15) * 4;
    let seq = u32::from_be_bytes(syn[o + 4..o + 8].try_into().unwrap());
    let mut b = vec![0u8; 54];
    if back {
        b[0..6].copy_from_slice(&peer_mac);
        b[6..12].copy_from_slice(&syn[6..12]);
        b[26..30].copy_from_slice(&syn[26..30]);
        b[30..34].copy_from_slice(&syn[30..34]);
        b[34..36].copy_from_slice(&syn[o..o + 2]);
        b[36..38].copy_from_slice(&syn[o + 2..o + 4]);
        b[38..42].copy_from_slice(&0x5000_0001u32.to_be_bytes());
    } else {
        b[0..6].copy_from_slice(&syn[6..12]);
        b[6..12].copy_from_slice(&peer_mac);
        b[26..30].copy_from_slice(&syn[30..34]);
        b[30..34].copy_from_slice(&syn[26..30]);
        b[34..36].copy_from_slice(&syn[o + 2..o + 4]);
        b[36..38].copy_from_slice(&syn[o..o + 2]);
        b[38..42].copy_from_slice(&0x5000_0000u32.to_be_bytes());
        b[42..46].copy_from_slice(&seq.wrapping_add(1).to_be_bytes());
    }
    b[12] = 8;
    b[14] = 0x45;
    b[16..18].copy_from_slice(&40u16.to_be_bytes());
    b[22] = 64;
    b[23] = 6;
    b[46] = 0x50;
    b[47] = flags;
    b
}
fn syn_dst(syn: &[u8]) -> (Ipv4Addr, u16) {
    let o = 14 + usize::from(syn[14] & 15) * 4;
    (
        Ipv4Addr::new(syn[30], syn[31], syn[32], syn[33]),
        u16::from_be_bytes([syn[o + 2], syn[o + 3]]),
    )
}

struct OracleSim {
    stdout: String,
    stderr: String,
    exit: i32,
    pcap: Frames,
}

/// One simulated run directory. Fields are mutated by the tests before `write`.
struct Sim {
    case: Case,
    st: Stand,
    det: DetectedRecord,
    extra_stderr: Vec<String>,
    stdout: Option<String>,
    exit: i32,
    peer: Frames,
    uplink: Frames,
    oracle: Option<OracleSim>,
    iflist: Option<IflistRecord>,
    oracle_iflist: Option<IflistRecord>,
    preflight: Option<String>,
    extra: Vec<(String, Vec<u8>)>,
    omit: Vec<&'static str>,
    plain_names: bool,
    syns: Vec<Vec<u8>>,
}

fn marker(st: &Stand, payload: &[u8]) -> Vec<u8> {
    marker_frame(st.scanner_mac, st.peer_mac, payload)
}
fn arp_request(st: &Stand, target: Ipv4Addr) -> Vec<u8> {
    encode_request(st.scanner_mac, u32::from(st.scanner_ip), u32::from(target)).to_vec()
}

impl Sim {
    fn new(plan: Plan, tag: &'static str) -> Sim {
        Sim::build(plan, tag, None)
    }
    /// `arp`: how many scanner ARP requests (default 1 for a scan, 10 for a timeout).
    fn build(plan: Plan, tag: &'static str, arp: Option<u32>) -> Sim {
        let c = case(plan, tag);
        let st = stand(plan);
        let windows = plan == Plan::Windows;
        let mac_stand = matches!(plan, Plan::Macos | Plan::MacosRoot);
        let mut det = c.printed.clone();
        let mut fr: Frames = vec![(T0, marker(&st, START_PAYLOAD))];
        if windows {
            // The peer kernel asks who has 198.18.0.1; the guest kernel answers (42 bytes): OS ARP.
            let peer_ip = st.peer_ips[0];
            let mut ask =
                encode_request(st.peer_mac, u32::from(peer_ip), u32::from(st.scanner_ip)).to_vec();
            ask.truncate(42);
            let mut answer = encode_reply(
                st.scanner_mac,
                u32::from(st.scanner_ip),
                st.peer_mac,
                u32::from(peer_ip),
            )
            .to_vec();
            answer.truncate(42);
            fr.push((T0 + 0.2, ask));
            fr.push((T0 + 0.2001, answer));
        }
        let mut lines = Vec::new();
        let mut syns = Vec::new();
        let mut exit = 0;
        let mut iflist = None;
        let mut oracle_iflist = None;
        let mut oracle = None;
        let mut last = T0 + 0.3;
        match c.kind {
            CaseKind::Scan | CaseKind::Parity => {
                let n = arp.unwrap_or(1);
                let router_mac = st.peer_mac;
                let mut start = T0 + 0.5;
                if let Some(target) = c.arp_target {
                    for i in 0..n {
                        fr.push((T0 + 0.5 + f64::from(i), arp_request(&st, target)));
                    }
                    let tr = T0 + 0.5 + f64::from(n - 1) + 0.001;
                    fr.push((
                        tr,
                        encode_reply(
                            st.peer_mac,
                            u32::from(target),
                            st.scanner_mac,
                            u32::from(st.scanner_ip),
                        )
                        .to_vec(),
                    ));
                    if let Some(m) = det.router_mac.as_mut() {
                        m.arp = Some(ArpCount {
                            requests: n,
                            ms: u64::from(n - 1) * 1000 + 1,
                        });
                    } else {
                        det.router_mac = Some(RouterMac {
                            value: dash(router_mac),
                            source: "arp".into(),
                            arp: Some(ArpCount {
                                requests: n,
                                ms: u64::from(n - 1) * 1000 + 1,
                            }),
                        });
                    }
                    start = tr + 0.1;
                }
                let sp = c
                    .argv
                    .iter()
                    .position(|x| x == "--source-port")
                    .map(|i| c.argv[i + 1].clone());
                det.seed = Some(sourced("1", "given"));
                det.source_port = Some(match &sp {
                    Some(v) => sourced(v, "given"),
                    None => sourced(TIME_PORT, "time"),
                });
                let sp = sp.unwrap_or_else(|| TIME_PORT.into());
                syns = plan_syns(&st, c.targets, c.ports, &sp, router_mac);
                for (i, s) in syns.iter().enumerate() {
                    let t = start + i as f64 * 0.01;
                    fr.push((t, s.clone()));
                    let (ip, port) = syn_dst(s);
                    let open = st.open_ports.contains(&port);
                    fr.push((
                        t + 0.0005,
                        tcp_answer(s, if open { 0x12 } else { 0x14 }, st.peer_mac, false),
                    ));
                    if open {
                        lines.push(discovered_line(ip, port));
                        if !mac_stand {
                            // The scanner's own kernel resets the half-open connection (counted, allowed).
                            fr.push((t + 0.0007, tcp_answer(s, 0x04, st.peer_mac, true)));
                        }
                    }
                    last = t + 0.001;
                }
                det.finished = Some(Finished {
                    reason: "Completed".into(),
                    sent: syns.len() as u64,
                    replies: syns.len() as u64,
                    open: lines.len() as u64,
                });
                if c.kind == CaseKind::Parity {
                    let mut ofr: Frames = vec![(T0 + 100.0, marker(&st, START_PAYLOAD))];
                    for (t, f) in &fr {
                        if f.get(12..14) != Some(&[0x88, 0xb5][..]) {
                            ofr.push((t + 100.5, f.clone()));
                        }
                    }
                    let ol = ofr.last().unwrap().0;
                    for k in 0..3 {
                        ofr.push((ol + 1.0 + f64::from(k) * 0.05, marker(&st, END_PAYLOAD)));
                    }
                    oracle = Some(OracleSim {
                        stdout: lines.concat(),
                        stderr: "Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2026-11-03 10:00:00 GMT\nInitiating SYN Stealth Scan\nScanning 4 hosts [2 ports/host]\n".into(),
                        exit: 0,
                        pcap: ofr,
                    });
                }
            }
            CaseKind::ArpTimeout => {
                let n = arp.unwrap_or(10);
                let target = c.arp_target.unwrap();
                for i in 0..n {
                    fr.push((T0 + 0.5 + f64::from(i), arp_request(&st, target)));
                    last = T0 + 0.5 + f64::from(i);
                }
                let r = c.expect.refusal.clone().unwrap();
                det.fail = r.fail;
                det.hints = r.hints;
                exit = 1;
            }
            CaseKind::Refusal => {
                let r = c.expect.refusal.clone().unwrap();
                if r.fail.is_some() {
                    det.fail = r.fail;
                    det.hints = r.hints;
                }
                exit = 1;
            }
            CaseKind::Iflist => {
                let x = c.expect.iflist.clone().unwrap();
                let line = match plan {
                    Plan::Windows => format!(
                        "{} index=5 mac={} ipv4=198.18.0.1 up ethernet id={} desc=Red Hat VirtIO Ethernet Adapter #2",
                        x.name,
                        x.mac,
                        crate::windows_suite::IFACE
                    ),
                    Plan::Linux => format!(
                        "{} index=2 mac={} ipv4=198.18.0.1 up ethernet",
                        x.name, x.mac
                    ),
                    _ => format!("{} index=17 mac={} ipv4=- up ethernet", x.name, x.mac),
                };
                iflist = Some(IflistRecord {
                    rc: 0,
                    lines: 4,
                    sha256: sha_of(b"the full --iflist output, reduced on the spot"),
                    stand_line: Some(line),
                });
                if c.tag == "l12_iflist" {
                    oracle_iflist = Some(IflistRecord {
                        rc: 0,
                        lines: 3,
                        sha256: sha_of(b"the oracle's --iflist output"),
                        stand_line: None,
                    });
                }
            }
        }
        for k in 0..3 {
            fr.push((last + 1.0 + f64::from(k) * 0.05, marker(&st, END_PAYLOAD)));
        }
        fr.sort_by(|a, b| a.0.total_cmp(&b.0));
        let stdout = (c.kind != CaseKind::Iflist).then(|| {
            if lines.is_empty() && windows {
                "\n".to_owned()
            } else {
                lines.concat()
            }
        });
        let preflight = match c.tag {
            "w01_auto" | "w06_multi_no_gateway" => Some(format!(
                "rc 0\n[+] interface = Ethernet 2 (detected: route to 198.18.0.2)\n[+] source-mac = {} (detected)\n[+] source-ip = 198.18.0.1 (detected)\n[+] router-ip = none (offline)\n[+] router-mac = 66-55-44-33-22-11 (offline)\n[+] seed = 1 (given)\n[+] source-port = {TIME_PORT} (time)\n",
                dash(st.scanner_mac)
            )),
            "m05_user_no_adapter" => Some(
                "rc 1\n[-] FAIL: 198.18.0.2 is an address of this host (route via lo0)\n    [hint] try \"--interface ethX\" and \"--router-ip 192.0.2.1\"\n".into(),
            ),
            _ => None,
        };
        Sim {
            case: c,
            st,
            det,
            extra_stderr: vec![],
            stdout,
            exit,
            peer: fr,
            uplink: vec![],
            oracle,
            iflist,
            oracle_iflist,
            preflight,
            extra: vec![],
            omit: vec![],
            plain_names: false,
            syns,
        }
    }

    fn tag(&self) -> &'static str {
        self.case.tag
    }
    fn insert(&mut self, t: f64, f: Vec<u8>) {
        self.peer.push((t, f));
        self.peer.sort_by(|a, b| a.0.total_cmp(&b.0));
    }
    /// Index of the `n`th scanner SYN in `peer`.
    fn syn_index(&self, n: usize) -> usize {
        self.peer
            .iter()
            .enumerate()
            .filter(|(_, (_, f))| pcap::is_syn(f) && f[6..12] == self.st.scanner_mac)
            .nth(n)
            .unwrap()
            .0
    }
    fn first_syn_time(&self) -> f64 {
        self.peer[self.syn_index(0)].0
    }

    /// stderr rendered from the detection record in the CLI's own forms (live.rs), then any extra lines.
    fn stderr_text(&self) -> String {
        let d = &self.det;
        let mut out = String::new();
        let mut put = |s: String| {
            out.push_str(&s);
            out.push('\n');
        };
        if let Some(x) = &d.interface {
            put(format!("[+] interface = {} ({})", x.value, x.source));
        }
        if let Some(x) = &d.source_mac {
            put(format!("[+] source-mac = {} ({})", x.value, x.source));
        }
        if let Some(x) = &d.source_ip {
            put(format!("[+] source-ip = {} ({})", x.value, x.source));
        }
        if let Some(x) = &d.router_ip {
            put(format!("[+] router-ip = {} ({})", x.value, x.source));
        }
        if let Some(x) = &d.router_mac {
            match &x.arp {
                Some(a) => put(format!(
                    "[+] router-mac = {} (arp: {} requests, {} ms)",
                    x.value, a.requests, a.ms
                )),
                None => put(format!("[+] router-mac = {} ({})", x.value, x.source)),
            }
        }
        if let Some(x) = &d.seed {
            put(format!("[+] seed = {} ({})", x.value, x.source));
        }
        if let Some(x) = &d.source_port {
            put(format!("[+] source-port = {} ({})", x.value, x.source));
        }
        if let Some(x) = &d.finished {
            put(format!(
                "[+] finished: {}, sent {}, replies {}, open {}",
                x.reason, x.sent, x.replies, x.open
            ));
        }
        if let Some(x) = &d.fail {
            put(format!("[-] FAIL: {x}"));
        }
        if let Some(x) = &d.error {
            put(format!("rmasscan: error: {x}"));
        }
        for h in &d.hints {
            put(h.clone());
        }
        for l in &self.extra_stderr {
            put(l.clone());
        }
        out
    }

    fn witness(fr: &Frames) -> Vec<u8> {
        let data = pcap::encode(fr);
        serde_json::to_vec_pretty(&json!({
            "tcpdump_captured": fr.len(), "received_by_filter": fr.len(), "kernel_drops": 0, "interface_drops": 0,
            "interface_drop_delta": 0, "pcap_frames": fr.len(), "start_marker_frames": 1, "end_marker_frames": 3,
            "iface_rxtx_delta_lo": fr.len(), "iface_rxtx_delta_hi": fr.len(), "quiesced_before_stop": true,
            "tcpdump_argv": ["tcpdump", "-i", "veth-b", "-n", "-U", "--immediate-mode", "-s", "0", "-w", "$SCRATCH/peer.pcap"],
            "pcap_sha256": sha_of(&data), "pcap_size_bytes": data.len(), "invalid_reasons": [], "valid": true
        }))
        .unwrap()
    }

    /// The run directory's files (relative path, bytes) before hashing.
    fn files(&self) -> Vec<(String, Vec<u8>)> {
        let c = &self.case;
        let guest = c.plan == Plan::Windows && !self.plain_names;
        let name = |n: &str| {
            if guest {
                format!("guest-{n}")
            } else {
                n.to_owned()
            }
        };
        let mut f: Vec<(String, Vec<u8>)> = vec![
            (
                "argv.json".into(),
                json(&ArgvRecord {
                    argv: c.argv.clone(),
                }),
            ),
            ("expect.json".into(), json(&c.expect)),
            (name("stderr.txt"), self.stderr_text().into_bytes()),
            (name("exit.txt"), format!("{}\n", self.exit).into_bytes()),
            ("peer.pcap".into(), pcap::encode(&self.peer)),
            ("capture.json".into(), Sim::witness(&self.peer)),
        ];
        if c.kind != CaseKind::Iflist {
            f.push(("detected.json".into(), json(&self.det)));
        }
        if let Some(o) = &self.stdout {
            f.push((name("stdout.txt"), o.clone().into_bytes()));
        }
        match c.plan {
            Plan::Linux => {
                let mut v = json!({"uplink":false,"bridge":false,"nat":false,"ip_forward":0,"ipv6":"disabled",
                    "veth_created_inside_scanner_ns_peer_moved_to_peer_ns":true,"host_link_list_unchanged":true,
                    "verified_by":"Rust capture isolation: live namespace links, routes, forwarding, IPv6 and host link baseline; plus wire-lab lifecycle assertions",
                    "scanner_route_get_8_8_8_8":"8.8.8.8 via 198.18.0.2 dev veth-a src 198.18.0.1 uid 0",
                    "peer_route_get_8_8_8_8":"RTNETLINK answers: Network is unreachable",
                    "scanner_routes":["default via 198.18.0.2 dev veth-a","198.18.0.0/24 dev veth-a proto kernel scope link src 198.18.0.1"],
                    "scanner_links":["1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00",
                        "2: veth-a@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\\    link/ether 02:aa:00:00:00:01 brd ff:ff:ff:ff:ff:ff link-netns wl-peer-4242"],
                    "peer_routes":["198.18.0.0/24 dev veth-b proto kernel scope link src 198.18.0.2"],
                    "mode":"autodetect"});
                v["default_route"] = isolation_default_route(IsolationMode::Autodetect, "veth-a");
                f.push((
                    "isolation.json".into(),
                    serde_json::to_vec_pretty(&v).unwrap(),
                ));
            }
            Plan::Macos | Plan::MacosRoot => {
                f.push(("uplink.pcap".into(), pcap::encode(&self.uplink)));
                f.push((
                    "uplink.err".into(),
                    format!("tcpdump: listening on en0, link-type EN10MB (Ethernet), snapshot length 524288 bytes\n{} packets captured\n731 packets received by filter\n0 packets dropped by kernel\n", self.uplink.len()).into_bytes(),
                ));
                let st = json!({"bpf_access":"granted","raw_run_allowed":true,"uplink":"en0","gateway":"192.168.1.1","run_id":"m1",
                    "manifest":"/var/run/rmasscan-lab/m1.json",
                    "checks":[{"name":"routes","detail":"8.8.8.8 via en0","ok":true},{"name":"default_route","detail":"en0 via Some(\"192.168.1.1\"), unchanged","ok":true}]});
                for n in ["status-pre.json", "status-post.json"] {
                    f.push((n.into(), serde_json::to_vec_pretty(&st).unwrap()));
                }
            }
            Plan::Windows => {
                f.push(("eno1.pcap".into(), pcap::encode(&self.uplink)));
                f.push((
                    "eno1.err".into(),
                    format!("tcpdump: listening on eno1, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n{0} packets captured\n{0} packets received by filter\n0 packets dropped by kernel\n", self.uplink.len()).into_bytes(),
                ));
                let st = json!({"guest_verify_fresh":true,"host_ok":true,"isolation_violations":[],"ok":true,"raw_run_allowed":true,"state":"up"});
                for n in ["status-pre.json", "status-post.json"] {
                    f.push((n.into(), serde_json::to_vec_pretty(&st).unwrap()));
                }
            }
        }
        if let Some(p) = &self.preflight {
            f.push(("preflight.txt".into(), p.clone().into_bytes()));
        }
        if let Some(i) = &self.iflist {
            f.push(("iflist.json".into(), json(i)));
        }
        if let Some(i) = &self.oracle_iflist {
            f.push(("oracle/iflist.json".into(), json(i)));
        }
        if let Some(o) = &self.oracle {
            f.push(("oracle/stdout.txt".into(), o.stdout.clone().into_bytes()));
            f.push(("oracle/stderr.txt".into(), o.stderr.clone().into_bytes()));
            f.push((
                "oracle/exit.txt".into(),
                format!("{}\n", o.exit).into_bytes(),
            ));
            f.push(("oracle.pcap".into(), pcap::encode(&o.pcap)));
            f.push(("oracle-capture.json".into(), Sim::witness(&o.pcap)));
        }
        f.extend(self.extra.iter().cloned());
        f.retain(|(n, _)| !self.omit.contains(&n.as_str()));
        f
    }

    /// Writes `root/manifest.json` (if absent) and `root/runs/<tag>/` with its hashes; returns the run directory.
    fn write(&self, root: &Path) -> PathBuf {
        let man = root.join("manifest.json");
        if !man.exists() {
            fs::write(&man, json!({"autodetect": self.case.plan}).to_string()).unwrap();
        }
        let d = root.join("runs").join(self.tag());
        fs::create_dir_all(&d).unwrap();
        let mut files = self.files();
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let mut hashes = String::new();
        for (n, b) in &files {
            let p = d.join(n);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b).unwrap();
            hashes.push_str(&format!("{}  {n}\n", sha_of(b)));
        }
        if !self.omit.contains(&"hashes-before-copy.txt") {
            fs::write(d.join("hashes-before-copy.txt"), hashes).unwrap();
        }
        d
    }
}

fn json<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec_pretty(v).unwrap()
}

fn write_plan(root: &Path, plan: Plan) {
    for tag in tags_of(plan) {
        Sim::new(plan, tag).write(root);
    }
}
fn run_of(res: &Value, tag: &str) -> Value {
    res["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["tag"] == tag)
        .cloned()
        .unwrap_or_else(|| panic!("no run {tag} in {res}"))
}
fn verdict(run: &Value) -> String {
    run["verdict"].as_str().unwrap_or("").to_owned()
}
fn bad(run: &Value) -> Vec<String> {
    run["checks"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|c| c["result"] != "PASS")
                .map(|c| format!("{}: {} ({})", c["result"], c["name"], c["detail"]))
                .collect()
        })
        .unwrap_or_default()
}
fn check<'a>(run: &'a Value, needle: &str) -> &'a Value {
    run["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"].as_str().is_some_and(|n| n.contains(needle)))
        .unwrap_or_else(|| panic!("no check {needle:?} in {:#}", run["checks"]))
}
/// The run summary of `sim` judged alone (the other planned tags are simply missing).
fn judge(sim: &Sim) -> Value {
    let root = scratch();
    sim.write(&root);
    let v = run_of(&verify_dir(&root), sim.tag());
    fs::remove_dir_all(root).unwrap();
    v
}
#[track_caller]
fn assert_verdict(run: &Value, want: &str) {
    assert_eq!(verdict(run), want, "{} {:#?}", run["tag"], bad(run));
}

// ------------------------------------------------------------------ consistent runs

#[test]
fn a_consistent_linux_run_is_pass() {
    let root = scratch();
    write_plan(&root, Plan::Linux);
    let res = verify_dir(&root);
    for tag in tags_of(Plan::Linux) {
        assert_verdict(&run_of(&res, tag), PASS);
    }
    assert_eq!(res["overall"], PASS, "{res:#}");
    let l01 = run_of(&res, "l01_auto");
    assert_eq!(l01["notes"]["os_arp"], json!({"requests":0,"replies":0}));
    assert!(l01["notes"]["rst_from_scanner"].as_u64().unwrap() > 0);
    assert_eq!(
        run(&strings(&["--dir", root.to_str().unwrap()])).unwrap(),
        0
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_consistent_macos_run_is_pass() {
    let user = scratch();
    write_plan(&user, Plan::Macos);
    let res = verify_dir(&user);
    for tag in tags_of(Plan::Macos) {
        assert_verdict(&run_of(&res, tag), PASS);
    }
    assert_eq!(res["overall"], PASS, "{res:#}");
    let root_case = scratch();
    write_plan(&root_case, Plan::MacosRoot);
    let res = verify_dir(&root_case);
    for tag in tags_of(Plan::MacosRoot) {
        assert_verdict(&run_of(&res, tag), PASS);
    }
    assert_eq!(res["overall"], PASS, "{res:#}");
    // The status of the stand names the user's uplink and its private gateway: neither is a privacy finding.
    assert_eq!(
        check(&run_of(&res, "m10_root_auto_mac"), "privacy")["result"],
        PASS
    );
    fs::remove_dir_all(user).unwrap();
    fs::remove_dir_all(root_case).unwrap();
}

#[test]
fn a_consistent_windows_run_with_guest_kernel_arp_reply_is_pass() {
    let root = scratch();
    write_plan(&root, Plan::Windows);
    let res = verify_dir(&root);
    for tag in tags_of(Plan::Windows) {
        assert_verdict(&run_of(&res, tag), PASS);
    }
    assert_eq!(res["overall"], PASS, "{res:#}");
    let w01 = run_of(&res, "w01_auto");
    assert_eq!(w01["notes"]["os_arp"]["replies"], 1);
    assert_eq!(w01["notes"]["scanner_arp_requests"], 1);
    fs::remove_dir_all(root).unwrap();
}

// ------------------------------------------------------------------ arp

#[test]
fn an_arp_request_to_another_ip_is_fail() {
    let mut sim = Sim::new(Plan::Macos, "m02_user_explicit");
    let i = sim
        .peer
        .iter()
        .position(|(_, f)| f.len() == 60 && f[12..14] == [8, 6] && f[6..12] == sim.st.scanner_mac)
        .unwrap();
    sim.peer[i].1 = arp_request(&sim.st, ip4("198.18.0.3"));
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "every scanner ARP request")["result"], FAIL);
}

#[test]
fn a_60_byte_scanner_request_to_another_ip_is_fail() {
    // A 60-byte, zero-padded request from the scanner MAC is the scanner's, whatever its target: FAIL, not OS ARP.
    let mut sim = Sim::new(Plan::Linux, "l01_auto");
    let t = sim.first_syn_time() - 0.05;
    let req = arp_request(&sim.st, ip4("198.18.0.9"));
    assert_eq!(req.len(), 60);
    sim.insert(t, req);
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "every scanner ARP request")["result"], FAIL);
    assert_eq!(r["notes"]["os_arp"]["requests"], 0);
    // A 60-byte request whose padding is not zero is neither the scanner's nor a 42-byte OS request: INVALID.
    let mut sim = Sim::new(Plan::Linux, "l01_auto");
    let mut odd = arp_request(&sim.st, ip4("198.18.0.2"));
    odd[59] = 0x5a;
    sim.insert(sim.first_syn_time() - 0.05, odd);
    assert_verdict(&judge(&sim), INVALID);
}

#[test]
fn a_42_byte_kernel_arp_request_is_os_arp_not_scanner_arp_and_invalid_on_linux() {
    let mut sim = Sim::new(Plan::Linux, "l01_auto");
    let mut short = arp_request(&sim.st, ip4("198.18.0.9"));
    short.truncate(42);
    sim.insert(sim.first_syn_time() - 0.05, short.clone());
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(r["notes"]["os_arp"]["requests"], 1);
    assert_eq!(r["notes"]["scanner_arp_requests"], 1);
    assert_eq!(check(&r, "every scanner ARP request")["result"], PASS);
    assert_eq!(check(&r, "OS ARP")["result"], INVALID);
    // The same kernel request on the Windows stand is OS ARP and allowed.
    let mut sim = Sim::new(Plan::Windows, "w01_auto");
    let mut short = arp_request(&sim.st, ip4("198.18.0.2"));
    short.truncate(42);
    sim.insert(sim.first_syn_time() + 0.002, short);
    let r = judge(&sim);
    assert_verdict(&r, PASS);
    assert_eq!(r["notes"]["os_arp"]["requests"], 1);
}

#[test]
fn a_guest_arp_reply_under_router_mac_is_os_arp_and_pass() {
    let sim = Sim::new(Plan::Windows, "w04_router_mac");
    assert!(
        sim.peer
            .iter()
            .any(|(_, f)| f.len() == 42 && f[6..12] == sim.st.scanner_mac && f[21] == 2)
    );
    let r = judge(&sim);
    assert_verdict(&r, PASS);
    assert_eq!(r["notes"]["os_arp"]["replies"], 1);
    assert_eq!(r["notes"]["scanner_arp_requests"], 0);
}

#[test]
fn two_scanner_requests_before_a_reply_is_noted_not_fail() {
    let sim = Sim::build(Plan::Linux, "l01_auto", Some(2));
    let r = judge(&sim);
    assert_verdict(&r, PASS);
    assert_eq!(r["notes"]["scanner_arp_requests"], 2);
    assert!(r["notes"]["arp_reply_lost"].is_object(), "{r:#}");
    // Eleven requests before a reply is beyond the resolver's ten: FAIL.
    assert_verdict(&judge(&Sim::build(Plan::Linux, "l01_auto", Some(11))), FAIL);
}

#[test]
fn a_syn_before_the_arp_reply_is_fail() {
    let mut sim = Sim::new(Plan::Linux, "l01_auto");
    let i = sim
        .peer
        .iter()
        .position(|(_, f)| f[12..14] == [8, 6] && f[21] == 2)
        .unwrap();
    let (_, reply) = sim.peer.remove(i);
    let t = sim.peer[sim.syn_index(1)].0 + 0.0001;
    sim.insert(t, reply);
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "before the first SYN")["result"], FAIL);
}

#[test]
fn a_syn_to_the_wrong_mac_is_fail() {
    let mut sim = Sim::new(Plan::Linux, "l01_auto");
    let i = sim.syn_index(2);
    sim.peer[i].1[0..6].copy_from_slice(&[2, 0xaa, 0, 0, 0, 9]);
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "goes to the router-mac")["result"], FAIL);
}

#[test]
fn router_mac_override_with_a_scanner_arp_is_fail() {
    let mut sim = Sim::new(Plan::Linux, "l07_router_mac");
    let req = arp_request(&sim.st, ip4("198.18.0.2"));
    sim.insert(sim.first_syn_time() - 0.05, req);
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "no scanner ARP request")["result"], FAIL);
}

#[test]
fn timeout_case_with_nine_or_eleven_requests_is_fail() {
    assert_verdict(&judge(&Sim::new(Plan::Linux, "l09_arp_timeout")), PASS);
    for n in [9, 11] {
        let r = judge(&Sim::build(Plan::Linux, "l09_arp_timeout", Some(n)));
        assert_verdict(&r, FAIL);
        assert_eq!(check(&r, "exactly 10 scanner ARP requests")["result"], FAIL);
    }
    // Ten requests, but one step of 1.5 s: FAIL.
    let mut sim = Sim::new(Plan::Linux, "l09_arp_timeout");
    for (t, f) in sim.peer.iter_mut() {
        if f[12..14] == [8, 6] && *t > T0 + 5.0 {
            *t += 0.5;
        }
    }
    assert_verdict(&judge(&sim), FAIL);
}

#[test]
fn timeout_case_with_a_router_reply_is_fail() {
    // The router answered, yet the scanner timed out: the resolver ignored a valid reply.
    let mut sim = Sim::new(Plan::Linux, "l09_arp_timeout");
    let reply = encode_reply(
        sim.st.peer_mac,
        u32::from(ip4("198.18.0.9")),
        sim.st.scanner_mac,
        u32::from(sim.st.scanner_ip),
    )
    .to_vec();
    sim.insert(T0 + 0.501, reply);
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "no ARP reply from the router-ip")["result"], FAIL);
}

#[test]
fn timeout_case_with_a_syn_is_fail() {
    let mut sim = Sim::new(Plan::Windows, "w05_arp_timeout");
    let syn = plan_syns(&sim.st, "198.18.0.2", "80", TIME_PORT, sim.st.peer_mac).remove(0);
    sim.insert(T0 + 10.0, syn);
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "no scanner SYN")["result"], FAIL);
}

#[test]
fn refusal_case_with_any_scanner_frame_is_fail() {
    let sim = Sim::new(Plan::Linux, "l10_no_such_adapter");
    assert_verdict(&judge(&sim), PASS);
    let mut with_arp = Sim::new(Plan::Linux, "l10_no_such_adapter");
    with_arp.insert(T0 + 0.5, arp_request(&with_arp.st, ip4("198.18.0.2")));
    let r = judge(&with_arp);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "no scanner frame")["result"], FAIL);
    let mut with_syn = Sim::new(Plan::Macos, "m06_user_no_ip");
    let syn = plan_syns(
        &with_syn.st,
        "198.18.0.2",
        "8000",
        TIME_PORT,
        with_syn.st.peer_mac,
    )
    .remove(0);
    with_syn.insert(T0 + 0.5, syn);
    assert_verdict(&judge(&with_syn), FAIL);
}

// ------------------------------------------------------------------ wire and results

#[test]
fn sent_count_not_equal_syn_is_fail() {
    let mut sim = Sim::new(Plan::Linux, "l02_auto_multi");
    sim.det.finished.as_mut().unwrap().sent += 1;
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "reports sent")["result"], FAIL);
}

#[test]
fn a_discovered_line_without_a_synack_is_fail() {
    let mut sim = Sim::new(Plan::Linux, "l01_auto");
    sim.stdout
        .as_mut()
        .unwrap()
        .push_str(&discovered_line(ip4("198.18.0.2"), 81));
    sim.det.finished.as_mut().unwrap().open += 1;
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "SYN-ACK")["result"], FAIL);
}

#[test]
fn a_synack_without_a_discovered_line_is_fail() {
    let mut sim = Sim::new(Plan::Linux, "l02_auto_multi");
    let out = sim.stdout.take().unwrap();
    sim.stdout = Some(out.split_inclusive('\n').skip(1).collect());
    sim.det.finished.as_mut().unwrap().open -= 1;
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "SYN-ACK")["result"], FAIL);
}

#[test]
fn a_line_not_80_bytes_is_fail() {
    let mut sim = Sim::new(Plan::Windows, "w03_adapter_friendly");
    let out = sim.stdout.take().unwrap();
    let mut lines: Vec<String> = out.split_inclusive('\n').map(str::to_owned).collect();
    lines[0] = format!("{}\n", lines[0].trim_end());
    sim.stdout = Some(lines.concat());
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "80 bytes")["result"], FAIL);
}

#[test]
fn guest_newline_only_stdout_is_empty() {
    let sim = Sim::new(Plan::Windows, "w06_multi_no_gateway");
    assert_eq!(sim.stdout.as_deref(), Some("\n"));
    assert_verdict(&judge(&sim), PASS);
    let mut sim = Sim::new(Plan::Linux, "l10_no_such_adapter");
    sim.stdout = Some("\n".into());
    assert_verdict(&judge(&sim), PASS);
    // Two newlines are a line that is not a result.
    let mut sim = Sim::new(Plan::Windows, "w06_multi_no_gateway");
    sim.stdout = Some("\n\n".into());
    assert_ne!(verdict(&judge(&sim)), PASS);
}

// ------------------------------------------------------------------ parity

#[test]
fn parity_arp_bytes_differ_is_fail() {
    let mut sim = Sim::new(Plan::Linux, "l11_parity");
    let st = sim.st.clone();
    let o = sim.oracle.as_mut().unwrap();
    let i = o
        .pcap
        .iter()
        .position(|(_, f)| f.len() == 60 && f[12..14] == [8, 6] && f[21] == 1)
        .unwrap();
    o.pcap[i].1 = arp_request(&st, ip4("198.18.0.3"));
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "oracle's ARP request")["result"], FAIL);
}

#[test]
fn parity_syn_order_differs_is_fail() {
    let mut sim = Sim::new(Plan::Linux, "l11_parity");
    let o = sim.oracle.as_mut().unwrap();
    let idx: Vec<usize> = o
        .pcap
        .iter()
        .enumerate()
        .filter(|(_, (_, f))| pcap::is_syn(f))
        .map(|(i, _)| i)
        .collect();
    let (a, b) = (o.pcap[idx[0]].1.clone(), o.pcap[idx[1]].1.clone());
    o.pcap[idx[0]].1 = b;
    o.pcap[idx[1]].1 = a;
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "oracle's SYNs")["result"], FAIL);
}

// ------------------------------------------------------------------ safety and evidence

#[test]
fn a_lab_frame_on_the_uplink_is_fail() {
    let mut sim = Sim::new(Plan::Macos, "m02_user_explicit");
    let syn = sim.syns[0].clone();
    sim.uplink.push((T0 + 1.0, syn));
    let root = scratch();
    sim.write(&root);
    let res = verify_dir(&root);
    let r = run_of(&res, "m02_user_explicit");
    assert_verdict(&r, FAIL);
    assert_eq!(r["safety_trip"], true);
    assert_eq!(res["overall"], FAIL);
    // Windows: eno1.
    let mut sim = Sim::new(Plan::Windows, "w07_iflist");
    sim.uplink
        .push((T0 + 1.0, arp_request(&sim.st, ip4("198.18.0.2"))));
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(r["safety_trip"], true);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_gzipped_capture_is_refused() {
    let mut sim = Sim::new(Plan::Linux, "l01_auto");
    sim.extra
        .push(("peer.pcap.gz".into(), vec![0x1f, 0x8b, 8, 0]));
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(r["safety_trip"], true);
    // Anywhere in the evidence directory, not only inside a run.
    let root = scratch();
    Sim::new(Plan::Linux, "l01_auto").write(&root);
    fs::write(root.join("uplink.pcap.gz"), [0x1f, 0x8b]).unwrap();
    assert_eq!(verify_dir(&root)["overall"], FAIL);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_changed_hash_is_invalid() {
    let root = scratch();
    let d = Sim::new(Plan::Linux, "l03_adapter").write(&root);
    let mut iso = fs::read(d.join("isolation.json")).unwrap();
    iso.push(b'\n');
    fs::write(d.join("isolation.json"), iso).unwrap();
    let r = run_of(&verify_dir(&root), "l03_adapter");
    assert_verdict(&r, INVALID);
    let c = check(&r, "hashes-before-copy");
    assert_eq!(c["result"], INVALID);
    assert!(
        c["detail"].as_str().unwrap().contains("isolation.json"),
        "{c}"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_hostname_in_stderr_is_invalid() {
    let mut sim = Sim::new(Plan::Macos, "m04_user_arp_timeout");
    sim.extra_stderr
        .push("rmasscan: error: Denys-MacBook-Pro.local is unreachable".into());
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    let c = check(&r, "privacy: stderr.txt");
    assert_eq!(c["result"], INVALID);
    assert!(
        c["detail"]
            .as_str()
            .unwrap()
            .contains("Denys-MacBook-Pro.local"),
        "{c}"
    );
    // An interface name that is not the stand's, in a [+] line.
    let mut sim = Sim::new(Plan::Linux, "l01_auto");
    sim.det.interface = Some(sourced("wlp3s0", "detected: route to 198.18.0.2"));
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(check(&r, "privacy: stderr.txt")["result"], INVALID);
    // A home path in a JSON file.
    let mut sim = Sim::new(Plan::Windows, "w03_adapter_friendly");
    sim.extra.push((
        "guest-runner.json".into(),
        br#"{"exe":"C:\\Users\\HiMaxym\\t4\\rmasscan.exe"}"#.to_vec(),
    ));
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(check(&r, "privacy: guest-runner.json")["result"], INVALID);
}

#[test]
fn a_full_iflist_dump_in_the_run_is_invalid() {
    let dump = "lo index=1 mac=00-00-00-00-00-00 ipv4=127.0.0.1 up other\nveth-a index=2 mac=02-aa-00-00-00-01 ipv4=198.18.0.1 up ethernet\ndefault via 198.18.0.2 dev veth-a\n";
    let mut sim = Sim::new(Plan::Linux, "l12_iflist");
    sim.extra
        .push(("stdout.txt".into(), dump.as_bytes().to_vec()));
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(check(&r, "stdout.txt absent")["result"], INVALID);
    let mut sim = Sim::new(Plan::Windows, "w07_iflist");
    sim.extra.push(("guest-stdout.txt".into(), b"\n".to_vec()));
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(check(&r, "guest-stdout.txt absent")["result"], INVALID);
    // A dump hidden in another file is found as well.
    let mut sim = Sim::new(Plan::Linux, "l01_auto");
    sim.extra
        .push(("notes.txt".into(), dump.as_bytes().to_vec()));
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(check(&r, "privacy: notes.txt")["result"], INVALID);
}

#[test]
fn iflist_json_without_the_stand_line_is_fail() {
    let mut sim = Sim::new(Plan::Linux, "l12_iflist");
    sim.iflist.as_mut().unwrap().stand_line = None;
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "stand line")["result"], FAIL);
    // The stand NIC listed, but masked where the MAC must be readable (m11 runs as root).
    let mut sim = Sim::new(Plan::MacosRoot, "m11_root_iflist");
    let line = sim.iflist.as_ref().unwrap().stand_line.clone().unwrap();
    sim.iflist.as_mut().unwrap().stand_line =
        Some(line.replace("mac=02-ac-00-00-00-01", "mac=masked"));
    assert_verdict(&judge(&sim), FAIL);
}

#[test]
fn missing_preflight_is_not_run() {
    for (plan, tag) in [
        (Plan::Windows, "w01_auto"),
        (Plan::Macos, "m05_user_no_adapter"),
    ] {
        let mut sim = Sim::new(plan, tag);
        sim.preflight = None;
        let r = judge(&sim);
        assert_verdict(&r, NOT_RUN);
        assert_eq!(check(&r, "preflight.txt")["result"], NOT_RUN);
    }
}

#[test]
fn preflight_not_equal_to_the_expected_detection_is_not_run() {
    let mut sim = Sim::new(Plan::Windows, "w01_auto");
    sim.preflight = Some(sim.preflight.take().unwrap().replace(
        "interface = Ethernet 2 (detected",
        "interface = Ethernet (detected",
    ));
    let r = judge(&sim);
    assert_verdict(&r, NOT_RUN);
    assert_eq!(check(&r, "preflight equals")["result"], NOT_RUN);
    let mut sim = Sim::new(Plan::Macos, "m05_user_no_adapter");
    sim.preflight = Some(
        "rc 0\n[+] interface = feth4201 (detected: route to 198.18.0.2)\n[+] source-mac = 02-ac-00-00-00-01 (detected)\n[+] source-ip = 198.18.0.1 (detected)\n[+] router-ip = none (offline)\n[+] router-mac = 66-55-44-33-22-11 (offline)\n[+] seed = 1 (given)\n[+] source-port = 41234 (time)\n".into(),
    );
    let r = judge(&sim);
    assert_verdict(&r, NOT_RUN);
    assert_eq!(check(&r, "preflight equals")["result"], NOT_RUN);
}

#[test]
fn windows_run_reads_guest_named_files() {
    let sim = Sim::new(Plan::Windows, "w02_adapter_npf");
    let r = judge(&sim);
    assert_verdict(&r, PASS);
    assert_eq!(check(&r, "guest-stderr.txt")["result"], PASS);
    // Linux/macOS names in a Windows run: the guest files are missing and the plain names are refused.
    let mut sim = Sim::new(Plan::Windows, "w02_adapter_npf");
    sim.plain_names = true;
    let r = judge(&sim);
    assert_verdict(&r, NOT_RUN);
    assert_eq!(check(&r, "guest-stderr.txt present")["result"], NOT_RUN);
    assert_eq!(check(&r, "guest file names")["result"], INVALID);
    // A file that is missing is not judged as the scanner's behaviour: never a FAIL of the directory.
    assert_eq!(r["behaviour_fail"], false, "{:#?}", bad(&r));
    let root = scratch();
    sim.write(&root);
    assert_eq!(verify_dir(&root)["overall"], NOT_RUN);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_root_case_is_not_run_never_pass() {
    let root = scratch();
    fs::write(root.join("manifest.json"), r#"{"autodetect":"macos-root"}"#).unwrap();
    let res = verify_dir(&root);
    assert_eq!(res["overall"], NOT_RUN);
    for tag in ["m10_root_auto_mac", "m11_root_iflist"] {
        assert_verdict(&run_of(&res, tag), NOT_RUN);
    }
    Sim::new(Plan::MacosRoot, "m11_root_iflist").write(&root);
    let res = verify_dir(&root);
    assert_verdict(&run_of(&res, "m11_root_iflist"), PASS);
    assert_verdict(&run_of(&res, "m10_root_auto_mac"), NOT_RUN);
    assert_eq!(res["overall"], NOT_RUN);
    assert_eq!(
        run(&strings(&["--dir", root.to_str().unwrap()])).unwrap(),
        2
    );
    // A root-case run whose MAC was given, not detected, is not the root case.
    let mut sim = Sim::new(Plan::MacosRoot, "m10_root_auto_mac");
    sim.case
        .expect
        .detection
        .as_mut()
        .unwrap()
        .source_mac
        .source = "given".into();
    sim.det.source_mac.as_mut().unwrap().source = "given".into();
    assert_ne!(verdict(&judge(&sim)), PASS);
    // The user window's directory cannot stand in for the root case.
    let user = scratch();
    write_plan(&user, Plan::Macos);
    let res = verify_dir(&user);
    assert!(
        !res["runs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["tag"] == "m10_root_auto_mac")
    );
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(user).unwrap();
}

#[test]
fn verdict_never_upgrades() {
    let root = scratch();
    write_plan(&root, Plan::Linux);
    // INVALID (a file changed after hashing) although every behaviour check of the run passes.
    let d = root.join("runs/l03_adapter");
    let mut iso = fs::read(d.join("isolation.json")).unwrap();
    iso.push(b' ');
    fs::write(d.join("isolation.json"), iso).unwrap();
    let res = verify_dir(&root);
    let l03 = run_of(&res, "l03_adapter");
    assert_verdict(&l03, INVALID);
    assert!(
        l03["checks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["behaviour"] == true)
            .all(|c| c["result"] == PASS)
    );
    assert_eq!(res["overall"], INVALID);
    assert_eq!(
        run(&strings(&["--dir", root.to_str().unwrap()])).unwrap(),
        2
    );
    // NOT RUN (the witness of another run is gone) outranks it; a stale verdict.json claiming PASS changes nothing.
    fs::remove_file(root.join("runs/l04_adapter_ip/capture.json")).unwrap();
    fs::write(root.join("verdict.json"), r#"{"overall":"PASS"}"#).unwrap();
    let res = verify_dir(&root);
    assert_verdict(&run_of(&res, "l04_adapter_ip"), NOT_RUN);
    assert_eq!(res["overall"], NOT_RUN);
    // A behaviour FAIL in one run and a safety trip in another: FAIL overall, never PASS, whatever else passed.
    let root2 = scratch();
    write_plan(&root2, Plan::Linux);
    let mut sim = Sim::new(Plan::Linux, "l01_auto");
    sim.det.finished.as_mut().unwrap().sent += 1;
    fs::remove_dir_all(root2.join("runs/l01_auto")).unwrap();
    sim.write(&root2);
    let res = verify_dir(&root2);
    assert_eq!(res["overall"], FAIL);
    assert_eq!(
        run(&strings(&["--dir", root2.to_str().unwrap()])).unwrap(),
        1
    );
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(root2).unwrap();
}

// ------------------------------------------------------------------ plan arguments and parsing

#[test]
fn plan_args_from_argv_and_detected_matches_wire_scan_keys() {
    for (plan, tag) in [
        (Plan::Linux, "l02_auto_multi"),
        (Plan::Linux, "l08_source_port"),
        (Plan::Macos, "m02_user_explicit"),
        (Plan::Windows, "w02_adapter_npf"),
    ] {
        let sim = Sim::new(plan, tag);
        let argv = ArgvRecord {
            argv: sim.case.argv.clone(),
        };
        let a = plan_args_from(&argv, &sim.det).unwrap();
        let keys: Vec<&str> = a.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "--iface",
                "--ports",
                "--rate",
                "--router-mac",
                "--seed",
                "--source-port",
                "--src-ip",
                "--src-mac",
                "--targets",
                "--wait"
            ],
            "{tag}"
        );
        assert_eq!(a["--targets"], sim.case.targets);
        assert_eq!(a["--ports"], sim.case.ports);
        assert_eq!(a["--seed"], "1");
        assert_eq!(a["--src-ip"], "198.18.0.1");
        assert_eq!(
            a["--source-port"],
            sim.det.source_port.as_ref().unwrap().value
        );
        assert_eq!(crate::verify::plan_frames(&a).unwrap(), sim.syns, "{tag}");
    }
    // --exclude is passed through; the rate and wait defaults are the CLI's.
    let sim = Sim::new(Plan::Linux, "l02_auto_multi");
    let argv = ArgvRecord {
        argv: strings(&[
            "198.18.0.2-198.18.0.5",
            "--ports",
            "80",
            "--exclude",
            "198.18.0.4",
        ]),
    };
    let a = plan_args_from(&argv, &sim.det).unwrap();
    assert_eq!(a["--exclude"], "198.18.0.4");
    assert_eq!(a["--rate"], "100");
    assert_eq!(a["--wait"], "10");
    assert_eq!(crate::verify::plan_frames(&a).unwrap().len(), 3);
    // An option the verifier does not model, or no target, is refused rather than guessed.
    for bad in [
        strings(&["198.18.0.2", "-p80", "--banners"]),
        strings(&["198.18.0.2", "-p80", "--seed", "1", "--seed", "2"]),
        strings(&["--iflist"]),
    ] {
        assert!(
            plan_args_from(&ArgvRecord { argv: bad.clone() }, &sim.det).is_err(),
            "{bad:?}"
        );
    }
    // A detection without the next hop's MAC has no plan.
    let mut det = sim.det.clone();
    det.router_mac = None;
    assert!(
        plan_args_from(
            &ArgvRecord {
                argv: sim.case.argv.clone()
            },
            &det
        )
        .is_err()
    );
}

#[test]
fn parse_stderr_reads_every_cli_line_form() {
    // Lines exactly as rmasscan-cli prints them (tests/live_fake.rs, src/live.rs, rmasscan-net refusals).
    let text = "[+] interface = eth0 (detected: route to 198.51.100.1)\n[+] source-mac = 02-aa-00-00-00-01 (detected)\n[+] source-ip = 192.0.2.5 (detected)\n[+] router-ip = 192.0.2.1 (route gateway)\n[+] router-mac = 02-aa-00-00-00-02 (arp: 1 requests, 0 ms)\n[+] seed = 7 (entropy)\n[+] source-port = 50000-50015 (given)\n[+] finished: Failed(TxUncertain { sent: 3, at: 2 }), sent 3, replies 1, open 1\n";
    let d = parse_stderr(text).unwrap();
    assert_eq!(
        d.interface,
        Some(sourced("eth0", "detected: route to 198.51.100.1"))
    );
    assert_eq!(
        d.router_mac,
        Some(RouterMac {
            value: "02-aa-00-00-00-02".into(),
            source: "arp".into(),
            arp: Some(ArpCount { requests: 1, ms: 0 })
        })
    );
    assert_eq!(d.seed, Some(sourced("7", "entropy")));
    assert_eq!(d.source_port, Some(sourced("50000-50015", "given")));
    assert_eq!(
        d.finished,
        Some(Finished {
            reason: "Failed(TxUncertain { sent: 3, at: 2 })".into(),
            sent: 3,
            replies: 1,
            open: 1
        })
    );
    let off = parse_stderr("[+] interface = none (offline)\n[+] source-mac = 00-11-22-33-44-55 (given)\n[+] source-ip = 10.255.0.1 (given)\n[+] router-ip = none (offline)\n[+] router-mac = 66-55-44-33-22-11 (offline)\n[+] seed = 5 (given)\n[+] source-port = 40000-40003 (given)\n").unwrap();
    assert_eq!(off.router_ip, Some(sourced("none", "offline")));
    assert_eq!(off.interface, Some(sourced("none", "offline")));
    let fail = parse_stderr("[+] interface = Ethernet 2 (given)\n[+] source-mac = 52-54-00-04-80-a9 (detected)\n[+] source-ip = 198.18.0.1 (detected)\n[+] router-ip = 198.18.0.3 (given)\n[-] FAIL: ARP timed-out resolving MAC address for router Ethernet 2: \"198.18.0.3\"\r\n    [hint] try \"--router-ip 192.0.2.1\" to specify different router\r\n").unwrap();
    assert_eq!(fail.interface, Some(sourced("Ethernet 2", "given")));
    assert_eq!(
        fail.fail.as_deref(),
        Some("ARP timed-out resolving MAC address for router Ethernet 2: \"198.18.0.3\"")
    );
    assert_eq!(fail.hints.len(), 1);
    let masked = parse_stderr("[-] FAIL: failed to detect MAC address of interface: \"x\"\n [hint] try something like \"--source-mac 00-11-22-33-44-55\"\n").unwrap();
    assert_eq!(
        masked.hints,
        strings(&[" [hint] try something like \"--source-mac 00-11-22-33-44-55\""])
    );
    for bad in [
        "[+] interface = veth-a\n", // no source
        "[+] source-ip = 198.18.0.1 (detected)\n[+] interface = veth-a (given)\n", // out of order
        "[+] seed = 1 (given)\n[+] seed = 1 (given)\n", // twice
        "[+] source-mac = 02:aa:00:00:00:01 (detected)\n", // not the CLI's MAC form
        "[+] router-ip = 198.18.0.2 (because)\n", // unknown reason
        "    [hint] alone\n",       // a hint with no refusal
        "Starting masscan\n",       // not a line of rmasscan
        "[-] FAIL: x\n[+] seed = 1 (given)\n", // [+] after the refusal
    ] {
        assert!(parse_stderr(bad).is_err(), "{bad:?}");
    }
    assert_eq!(parse_stderr("").unwrap(), DetectedRecord::default());
}

#[test]
fn stand_matches_the_other_lab_modules() {
    let w = stand(Plan::Windows);
    assert_eq!(
        rmasscan_core::config::parse_mac(crate::windows_suite::MAC).unwrap(),
        w.scanner_mac
    );
    let m = stand(Plan::Macos);
    let b = crate::macos_verify::stand_binding();
    assert_eq!(b["iface"], m.iface);
    assert_eq!(b["src_mac"], dash(m.scanner_mac).replace('-', ":"));
    assert_eq!(b["router_mac"], dash(m.peer_mac).replace('-', ":"));
    assert_eq!(stand(Plan::MacosRoot), m);
    for plan in [Plan::Linux, Plan::Macos, Plan::MacosRoot, Plan::Windows] {
        assert_eq!(planned_tags(plan), tags_of(plan).as_slice());
        for tag in tags_of(plan) {
            assert_eq!(case_kind(tag), Some(kind_of(tag)), "{tag}");
            assert_eq!(
                preflight_expectation(tag),
                case(plan, tag).expect.preflight,
                "{tag}"
            );
        }
    }
}

#[test]
fn privacy_tokens_allow_the_stand_and_anonymous_values_only() {
    let flagged = |text: &str, scanner: bool| !token_problems(text, scanner).is_empty();
    // The scanner's own text: the stand's /24 and the CLI's fixed hint addresses only.
    for ok in [
        "198.18.0.9",
        "try \"--router-ip 192.0.2.1\"",
        "0.0.0.0/8, 127.0.0.0/8 and 224.0.0.0/3",
        "02-aa-00-00-00-01 66-55-44-33-22-11",
    ] {
        assert!(!flagged(ok, true), "{ok}");
    }
    for bad in [
        "192.168.1.1",
        "93.184.216.34",
        "a4-83-e7-12-34-56",
        "Denys-MacBook-Pro.local",
    ] {
        assert!(flagged(bad, true), "{bad}");
    }
    // The stand's own records: private and shared gateways, the route probe; never a public address or a real MAC.
    for ok in [
        "en0 via Some(\"192.168.1.1\")",
        "gateway 100.64.0.1",
        "8.8.8.8 via 198.18.0.2 dev veth-a",
        "link/ether 02:aa:00:00:00:01 brd ff:ff:ff:ff:ff:ff",
        "C:\\\\Users\\\\lab\\\\t4\\\\rmasscan.exe",
        "$HOME/winvm/build",
        "2026-11-03T10:00:00Z nonce r4ba81a67df548977f2dc32a8e4249c77-8e47e8ff447a6c1d",
    ] {
        assert!(!flagged(ok, false), "{ok}");
    }
    for bad in [
        "93.184.216.34",
        "ether a4:83:e7:12:34:56",
        "_airplay._tcp.local",
        "printer.lan",
        "/Users/denys/masscan",
        "/home/a1/winvm",
        "C:\\\\Users\\\\HiMaxym\\\\t4",
        "a index=1 mac=x\nb index=2 mac=y",
    ] {
        assert!(flagged(bad, false), "{bad}");
    }
}
