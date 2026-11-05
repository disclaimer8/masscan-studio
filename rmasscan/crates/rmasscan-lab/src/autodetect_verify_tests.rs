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

/// One case as the suites define it: the verifier's case table, plus what the simulated run prints.
#[derive(Clone)]
pub(crate) struct Case {
    pub(crate) plan: Plan,
    pub(crate) tag: &'static str,
    pub(crate) kind: CaseKind,
    pub(crate) argv: Vec<String>,
    targets: &'static str,
    ports: &'static str,
    /// The `[+]` lines up to `router-ip`/`router-mac (given)` (ARP, seed, source port and finished are added by the run).
    printed: DetectedRecord,
    pub(crate) expect: ExpectRecord,
    /// The address the scanner resolves with ARP (none: `--router-mac`, a refusal or `--iflist`).
    arp_target: Option<Ipv4Addr>,
}

/// The case of the table (`case_spec`), with the `[+]` lines a correct run prints for it.
fn case(plan: Plan, tag: &'static str) -> Case {
    let spec = case_spec(plan, tag).unwrap_or_else(|| panic!("{tag} is not a case of {plan:?}"));
    let expect = spec.expect();
    let printed_of = |x: &ExpectDetection| DetectedRecord {
        interface: Some(x.interface.clone()),
        source_mac: Some(x.source_mac.clone()),
        source_ip: Some(x.source_ip.clone()),
        router_ip: x.router_ip.clone(),
        // `(given)` is printed by detection; `(arp: …)` only after the resolver, which the run adds.
        router_mac: x
            .router_mac
            .as_ref()
            .filter(|m| m.source == "given")
            .map(|m| RouterMac {
                value: m.value.clone(),
                source: m.source.clone(),
                arp: None,
            }),
        ..DetectedRecord::default()
    };
    let mut printed = expect
        .detection
        .as_ref()
        .map(printed_of)
        .unwrap_or_default();
    let arp_target = expect
        .detection
        .as_ref()
        .filter(|d| {
            spec.kind == CaseKind::ArpTimeout
                || d.router_mac.as_ref().is_some_and(|m| m.source == "arp")
        })
        .and_then(|d| d.router_ip.as_ref())
        .map(|r| ip4(&r.value));
    if tag == "w08b_restricted_scan" {
        // A restricted token: detection works, opening the ARP adapter is refused (the table accepts any refusal),
        // with the product's own text: Admin-only Npcap shows the token only loopback (rmasscan-net
        // `windows/handle.rs`, format string copied verbatim, the device name through `{:?}`), wrapped by the CLI's
        // `open` (`rmasscan-cli/src/live.rs`) with its privilege hint.
        let st = stand(plan);
        let denied = rmasscan_net::NetError::PermissionDenied(format!(
            "no Npcap device named {:?}: only loopback is visible: Npcap may be installed in Administrators-only mode and this process lacks rights ({} devices enumerated)",
            crate::windows_suite::IFACE,
            1
        ));
        printed = DetectedRecord {
            interface: Some(sourced(st.iface, "detected: route to 198.18.0.2")),
            source_mac: Some(sourced(&dash(st.scanner_mac), "detected")),
            source_ip: Some(sourced("198.18.0.1", "detected")),
            router_ip: Some(sourced("198.18.0.2", "on-link target")),
            error: Some(format!("cannot open adapter \"{}\": {denied}", st.iface)),
            hints: strings(&[
                "    [hint] run as Administrator; Npcap must be installed (Admin-only mode needs an elevated prompt)",
            ]),
            ..DetectedRecord::default()
        };
    }
    Case {
        plan,
        tag,
        kind: spec.kind,
        argv: spec.argv(),
        targets: spec.targets,
        ports: spec.ports,
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

pub(crate) struct OracleSim {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    /// The text of `oracle/exit.txt`.
    pub(crate) exit: String,
    pub(crate) pcap: Frames,
}

/// One simulated run directory. Fields are mutated by the tests before `write`. The suite's tests read its
/// process outputs (stderr, stdout, exit, captures, preflight) and let the suite write the directory itself.
pub(crate) struct Sim {
    pub(crate) case: Case,
    st: Stand,
    det: DetectedRecord,
    extra_stderr: Vec<String>,
    pub(crate) stdout: Option<String>,
    pub(crate) exit: i32,
    pub(crate) peer: Frames,
    pub(crate) uplink: Frames,
    pub(crate) oracle: Option<OracleSim>,
    iflist: Option<IflistRecord>,
    oracle_iflist: Option<IflistRecord>,
    pub(crate) preflight: Option<String>,
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
    pub(crate) fn new(plan: Plan, tag: &'static str) -> Sim {
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
                        // The forms every committed oracle run shows: banner, status lines rewritten after `\r`, forced exit.
                        stderr: "Starting masscan 1.3.2-integration (http://bit.ly/14GZzcT) at 2026-11-03 10:00:00 GMT\nInitiating SYN Stealth Scan\nScanning 4 hosts [2 ports/host]\nrate:  0.00-kpps,  0.00% done,   0:00:00 remaining, found=0       \rrate:  0.00-kpps, 100.00% done, waiting 3-secs, found=8       \rrate:  0.00-kpps, 100.00% done, waiting -1-secs, found=8       \r\n[-] Passed the wait window but still running, forcing exit...\n".into(),
                        exit: "0\n".into(),
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
                    // masscan's own line of the stand NIC (`rawsock_list_adapters`).
                    oracle_iflist = Some(IflistRecord {
                        rc: 0,
                        lines: 3,
                        sha256: sha_of(b"the oracle's --iflist output"),
                        stand_line: Some(" 1  veth-a \t(No description available)".into()),
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
        // What the `--offline` preflight prints when it shows what the case expects.
        let preflight = match &c.expect.preflight {
            Some(ExpectPreflight::Interface(name)) => Some(format!(
                "rc 0\n[+] interface = {name} (detected: route to 198.18.0.2)\n[+] source-mac = {} (detected)\n[+] source-ip = 198.18.0.1 (detected)\n[+] router-ip = none (offline)\n[+] router-mac = 66-55-44-33-22-11 (offline)\n[+] seed = 1 (given)\n[+] source-port = {TIME_PORT} (time)\n",
                dash(st.scanner_mac)
            )),
            Some(ExpectPreflight::Refusal(text)) => Some(format!(
                "rc 1\n[-] FAIL: {text}\n{}\n",
                c.expect.refusal.as_ref().unwrap().hints.join("\n")
            )),
            None => None,
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
    pub(crate) fn stderr_text(&self) -> String {
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

    pub(crate) fn witness(fr: &Frames) -> Vec<u8> {
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

    /// A macOS `capture.json`: the witness record of the published capture `fr`, which the host's mDNS (two frames
    /// here) was left out of, with what was left out (the fields `autodetect_suite::publish_peer_capture` adds).
    pub(crate) fn published_witness(fr: &Frames) -> Vec<u8> {
        let mut v: Value = serde_json::from_slice(&Sim::witness(fr)).unwrap();
        v["unfiltered"] = json!({"pcap_sha256": sha_of(b"the witness's capture with the host's mDNS"),
            "pcap_frames": fr.len() + 2, "kept": "private work directory only, deleted after publishing"});
        v["privacy_filter"] = json!({"published": crate::macos_verify::PEER_FILTER, "frames_dropped": 2,
            "frames_kept": fr.len()});
        serde_json::to_vec_pretty(&v).unwrap()
    }

    /// The run directory's files (relative path, bytes) before hashing.
    pub(crate) fn files(&self) -> Vec<(String, Vec<u8>)> {
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
            (
                "capture.json".into(),
                if matches!(c.plan, Plan::Macos | Plan::MacosRoot) {
                    Sim::published_witness(&self.peer)
                } else {
                    Sim::witness(&self.peer)
                },
            ),
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
                // The seal before the run and after it (the suite takes `capture isolation` again).
                for n in ["isolation.json", "isolation-post.json"] {
                    f.push((n.into(), serde_json::to_vec_pretty(&v).unwrap()));
                }
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
            f.push(("oracle/exit.txt".into(), o.exit.clone().into_bytes()));
            f.push(("oracle.pcap".into(), pcap::encode(&o.pcap)));
            f.push(("oracle-capture.json".into(), Sim::witness(&o.pcap)));
        }
        // An extra file may stand in for an omitted one.
        f.retain(|(n, _)| !self.omit.contains(&n.as_str()));
        f.extend(self.extra.iter().cloned());
        f
    }

    /// Writes `root/manifest.json` (if absent) and `root/runs/<tag>/` with its hashes; returns the run directory.
    pub(crate) fn write(&self, root: &Path) -> PathBuf {
        let man = root.join("manifest.json");
        if !man.exists() {
            let mut m = json!({"autodetect": self.case.plan});
            if self.case.plan == Plan::Linux {
                // The lab id wire-lab.sh gave the suite (and writes into teardown.json).
                m["lab_id"] = json!(LAB_ID);
            }
            fs::write(&man, m.to_string()).unwrap();
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

/// `teardown.json` as `wire-lab.sh --suite autodetect` writes it after a clean teardown (namespace names scrubbed).
/// The id of one Linux lab: `wire-lab.sh` passes it to the suite (`--lab-id`, kept in `manifest.json`) and writes it
/// into `teardown.json`.
pub(crate) const LAB_ID: &str = "3f2c9e1a-7b4d-4c3e-9a51-0d6e2b8f4c17";
/// `teardown.json` as `wire-lab.sh --suite autodetect` writes it after a clean teardown of lab [`LAB_ID`].
pub(crate) const TEARDOWN: &str = r#"{"lab_id":"3f2c9e1a-7b4d-4c3e-9a51-0d6e2b8f4c17","namespaces_deleted":["wl-scan-RUNID","wl-peer-RUNID"],"namespaces_left":0}"#;

/// Every planned run of `plan` and, on Linux, the root's teardown record: a whole evidence directory.
fn write_plan(root: &Path, plan: Plan) {
    for tag in planned_tags(plan) {
        Sim::new(plan, tag).write(root);
    }
    if plan == Plan::Linux {
        fs::write(root.join("teardown.json"), format!("{TEARDOWN}\n")).unwrap();
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
    for tag in planned_tags(Plan::Linux) {
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
    for tag in planned_tags(Plan::Macos) {
        assert_verdict(&run_of(&res, tag), PASS);
    }
    assert_eq!(res["overall"], PASS, "{res:#}");
    let root_case = scratch();
    write_plan(&root_case, Plan::MacosRoot);
    let res = verify_dir(&root_case);
    for tag in planned_tags(Plan::MacosRoot) {
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
    for tag in planned_tags(Plan::Windows) {
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
    let mut trip = Sim::new(Plan::Linux, "l02_auto_multi");
    let mut foreign = trip.syns[0].clone();
    foreign[6..12].copy_from_slice(&[2, 0xaa, 0, 0, 0, 0x77]);
    trip.insert(trip.first_syn_time() + 0.003, foreign);
    fs::remove_dir_all(root2.join("runs/l02_auto_multi")).unwrap();
    trip.write(&root2);
    let res = verify_dir(&root2);
    assert_eq!(res["overall"], FAIL);
    assert_eq!(res["behaviour_fail"], json!(["l01_auto"]));
    assert_eq!(res["safety_trips"], json!(["l02_auto_multi"]));
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
        for spec in cases(plan) {
            assert_eq!(spec.plan, plan, "{}", spec.tag);
            assert_eq!(case_kind(spec.tag), Some(spec.kind));
            assert_eq!(preflight_expectation(spec.tag), spec.expect().preflight);
            assert_eq!(case_spec(plan, spec.tag), Some(*spec));
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

// ------------------------------------------------------------------ fix round 1

#[test]
fn case_table_holds_the_briefs_cases() {
    // The brief's case lists, kinds and defining arguments (constants table), literally.
    use CaseKind::*;
    let c = "--seed 1 --rate 100 --wait 3";
    let npf = crate::windows_suite::IFACE;
    let m_up = "--adapter feth4201 --adapter-ip 198.18.0.1";
    let want: Vec<(Plan, &str, CaseKind, String)> = vec![
        (
            Plan::Linux,
            "l01_auto",
            Scan,
            format!("198.18.0.2 -p80,81,8080 {c}"),
        ),
        (
            Plan::Linux,
            "l02_auto_multi",
            Scan,
            format!("198.18.0.2-198.18.0.5 -p80,81,8080 {c}"),
        ),
        (
            Plan::Linux,
            "l03_adapter",
            Scan,
            format!("198.18.0.2 -p80,81,8080 --adapter veth-a {c}"),
        ),
        (
            Plan::Linux,
            "l04_adapter_ip",
            Scan,
            format!("198.18.0.2 -p80,81,8080 --adapter-ip 198.18.0.1 {c}"),
        ),
        (
            Plan::Linux,
            "l05_adapter_mac",
            Scan,
            format!("198.18.0.2 -p80,81,8080 --adapter-mac 02-aa-00-00-00-01 {c}"),
        ),
        (
            Plan::Linux,
            "l06_router_ip",
            Scan,
            format!("198.18.0.2 -p80,81,8080 --router-ip 198.18.0.3 {c}"),
        ),
        (
            Plan::Linux,
            "l07_router_mac",
            Scan,
            format!("198.18.0.2 -p80,81,8080 --router-mac 02-aa-00-00-00-02 {c}"),
        ),
        (
            Plan::Linux,
            "l08_source_port",
            Scan,
            format!("198.18.0.2 -p80,81,8080 --source-port 50000-50015 {c}"),
        ),
        (
            Plan::Linux,
            "l09_arp_timeout",
            ArpTimeout,
            format!("198.18.0.2 -p80,81,8080 --router-ip 198.18.0.9 {c}"),
        ),
        (
            Plan::Linux,
            "l10_no_such_adapter",
            Refusal,
            format!("198.18.0.2 -p80,81,8080 --adapter nosuch0 {c}"),
        ),
        (
            Plan::Linux,
            "l11_parity",
            Parity,
            format!("198.18.0.2-198.18.0.5 -p80,8080 --source-port 40000 {c}"),
        ),
        (Plan::Linux, "l12_iflist", Iflist, "--iflist".into()),
        (
            Plan::Macos,
            "m01_user_masked",
            Refusal,
            format!("198.18.0.2 -p8000-8007,9000-9003 {m_up} --router-ip 198.18.0.2 {c}"),
        ),
        (
            Plan::Macos,
            "m02_user_explicit",
            Scan,
            format!(
                "198.18.0.2 -p8000-8007,9000-9003 {m_up} --adapter-mac 02-ac-00-00-00-01 --router-ip 198.18.0.2 {c}"
            ),
        ),
        (
            Plan::Macos,
            "m03_user_router_mac",
            Scan,
            format!(
                "198.18.0.2 -p8000-8007,9000-9003 {m_up} --adapter-mac 02-ac-00-00-00-01 --router-ip 198.18.0.2 --router-mac 02-ac-00-00-00-02 {c}"
            ),
        ),
        (
            Plan::Macos,
            "m04_user_arp_timeout",
            ArpTimeout,
            format!(
                "198.18.0.2 -p8000-8007,9000-9003 {m_up} --adapter-mac 02-ac-00-00-00-01 --router-ip 198.18.0.3 {c}"
            ),
        ),
        (
            Plan::Macos,
            "m05_user_no_adapter",
            Refusal,
            format!("198.18.0.2 -p8000-8007,9000-9003 {c}"),
        ),
        (
            Plan::Macos,
            "m06_user_no_ip",
            Refusal,
            format!(
                "198.18.0.2 -p8000-8007,9000-9003 --adapter feth4201 --adapter-mac 02-ac-00-00-00-01 --router-ip 198.18.0.2 {c}"
            ),
        ),
        (Plan::Macos, "m07_user_iflist", Iflist, "--iflist".into()),
        (
            Plan::MacosRoot,
            "m10_root_auto_mac",
            Scan,
            format!("198.18.0.2 -p8000-8007,9000-9003 {m_up} --router-ip 198.18.0.2 {c}"),
        ),
        (
            Plan::MacosRoot,
            "m11_root_iflist",
            Iflist,
            "--iflist".into(),
        ),
        (
            Plan::Windows,
            "w01_auto",
            Scan,
            format!("198.18.0.2 -p80,443,8000-8007,8099 {c}"),
        ),
        (
            Plan::Windows,
            "w02_adapter_npf",
            Scan,
            format!("198.18.0.2 -p80,443,8000-8007,8099 --adapter {npf} {c}"),
        ),
        (
            Plan::Windows,
            "w03_adapter_friendly",
            Scan,
            format!("198.18.0.2 -p80,443,8000-8007,8099 --adapter Ethernet 2 {c}"),
        ),
        (
            Plan::Windows,
            "w04_router_mac",
            Scan,
            format!("198.18.0.2 -p80,443,8000-8007,8099 --router-mac 02-57-4c-3d-2e-9b {c}"),
        ),
        (
            Plan::Windows,
            "w05_arp_timeout",
            ArpTimeout,
            format!("198.18.0.2 -p80,443,8000-8007,8099 --router-ip 198.18.0.3 {c}"),
        ),
        (
            Plan::Windows,
            "w06_multi_no_gateway",
            Refusal,
            format!("198.18.0.2-198.18.0.3 -p80,443,8000-8007,8099 {c}"),
        ),
        (Plan::Windows, "w07_iflist", Iflist, "--iflist".into()),
        (
            Plan::Windows,
            "w08a_restricted_iflist",
            Iflist,
            "--iflist".into(),
        ),
        (
            Plan::Windows,
            "w08b_restricted_scan",
            Refusal,
            format!("198.18.0.2 -p80,443,8000-8007,8099 {c}"),
        ),
    ];
    let all: Vec<CaseSpec> = [Plan::Linux, Plan::Macos, Plan::MacosRoot, Plan::Windows]
        .into_iter()
        .flat_map(|p| cases(p).iter().copied())
        .collect();
    assert_eq!(all.len(), want.len());
    for (spec, (plan, tag, kind, argv)) in all.iter().zip(&want) {
        assert_eq!((spec.plan, spec.tag, spec.kind), (*plan, *tag, *kind));
        assert_eq!(spec.argv().join(" "), *argv, "{tag}");
    }
    // What each case proves: route-based detection without adapter flags, the given value where one is given.
    let src = |tag: &str| case_spec(Plan::Linux, tag).unwrap().detection;
    assert_eq!(src("l01_auto"), Some([Src::Detected; 3]));
    assert_eq!(
        src("l03_adapter"),
        Some([Src::Given, Src::Detected, Src::Detected])
    );
    assert_eq!(
        case_spec(Plan::Linux, "l02_auto_multi").unwrap().router_ip,
        Some(("198.18.0.2", "interface default gateway"))
    );
    assert_eq!(
        case_spec(Plan::MacosRoot, "m10_root_auto_mac")
            .unwrap()
            .detection,
        Some([Src::Given, Src::Detected, Src::Given])
    );
    let m01 = case_spec(Plan::Macos, "m01_user_masked").unwrap().expect();
    assert!(m01.refusal.unwrap().fail.unwrap().contains("os-masked"));
    assert_eq!(
        case_spec(Plan::Windows, "w08b_restricted_scan")
            .unwrap()
            .fail,
        None
    );
    // w08 is two runs under the restricted token (`--iflist`, then w01's scan); every other case runs elevated.
    let restricted: Vec<&str> = all.iter().filter(|c| c.restricted).map(|c| c.tag).collect();
    assert_eq!(
        restricted,
        ["w08a_restricted_iflist", "w08b_restricted_scan"]
    );
}

#[test]
fn l01_with_the_adapter_given_is_not_pass() {
    // A self-consistent wrong directory: argv, expect.json and stderr all say the interface was given.
    let mut sim = Sim::new(Plan::Linux, "l01_auto");
    sim.case
        .argv
        .splice(2..2, strings(&["--adapter", "veth-a"]));
    sim.case.expect.detection.as_mut().unwrap().interface = sourced("veth-a", "given");
    sim.det.interface = Some(sourced("veth-a", "given"));
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(check(&r, "argv.json is the case's argv")["result"], INVALID);
    assert_eq!(
        check(&r, "expect.json equals the case table")["result"],
        INVALID
    );
    // The right argv and expect.json, but rmasscan printed the interface as given: its behaviour, FAIL.
    let mut sim = Sim::new(Plan::Linux, "l01_auto");
    sim.det.interface = Some(sourced("veth-a", "given"));
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "[+] detection lines equal")["result"], FAIL);
}

#[test]
fn m01_with_a_refusal_other_than_the_masked_mac_is_fail() {
    let mut sim = Sim::new(Plan::Macos, "m01_user_masked");
    sim.det.fail = Some("failed to detect IP of interface \"feth4201\"".into());
    sim.det.hints = strings(&[
        "    [hint] did you spell the name correctly?",
        "    [hint] if it has no IP address, manually set with something like \"--source-ip 198.51.100.17\"",
    ]);
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(check(&r, "carries the expected refusal")["result"], FAIL);
    // The run's own expect.json naming that refusal changes nothing: it disagrees with the table.
    sim.case.expect.refusal = Some(ExpectRefusal {
        fail: sim.det.fail.clone(),
        hints: sim.det.hints.clone(),
    });
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(
        check(&r, "expect.json equals the case table")["result"],
        INVALID
    );
}

#[test]
fn expect_json_that_disagrees_with_the_case_table_is_invalid() {
    let mut sim = Sim::new(Plan::Linux, "l02_auto_multi");
    sim.case.expect.detection.as_mut().unwrap().router_ip =
        Some(sourced("198.18.0.2", "route gateway"));
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(
        check(&r, "expect.json equals the case table")["result"],
        INVALID
    );
    assert_eq!(r["behaviour_fail"], false);
    // Any field: the preflight of a case that needs none.
    let mut sim = Sim::new(Plan::Windows, "w02_adapter_npf");
    sim.case.expect.preflight = Some(ExpectPreflight::Interface("Ethernet 2".into()));
    assert_verdict(&judge(&sim), INVALID);
}

#[test]
fn a_preflight_with_a_given_interface_is_not_run() {
    // The NIC must come from the route to the case's first target, not from the command line.
    let mut sim = Sim::new(Plan::Windows, "w06_multi_no_gateway");
    sim.preflight = Some(sim.preflight.take().unwrap().replace(
        "interface = Ethernet 2 (detected: route to 198.18.0.2)",
        "interface = Ethernet 2 (given)",
    ));
    let r = judge(&sim);
    assert_verdict(&r, NOT_RUN);
    assert_eq!(check(&r, "preflight equals")["result"], NOT_RUN);
}

#[test]
fn an_oracle_that_did_not_exit_zero_is_invalid() {
    for (text, name) in [
        ("abc\n", "oracle/exit.txt holds an exit code"),
        ("", "oracle/exit.txt holds an exit code"),
        ("1\n", "the oracle exited 0"),
    ] {
        let mut sim = Sim::new(Plan::Linux, "l11_parity");
        sim.oracle.as_mut().unwrap().exit = text.into();
        let root = scratch();
        sim.write(&root);
        let r = run_of(&verify_dir(&root), "l11_parity");
        assert_eq!(check(&r, "hashes-before-copy")["result"], PASS);
        assert_verdict(&r, INVALID);
        assert_eq!(check(&r, name)["result"], INVALID, "{text:?}");
        assert_eq!(r["behaviour_fail"], false);
        fs::remove_dir_all(root).unwrap();
    }
    // The oracle's --iflist record proves the stand: a failed one is INVALID, not a behaviour FAIL.
    let mut sim = Sim::new(Plan::Linux, "l12_iflist");
    sim.oracle_iflist.as_mut().unwrap().rc = 1;
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(
        check(&r, "the oracle's --iflist exited 0")["result"],
        INVALID
    );
}

#[test]
fn a_file_outside_the_runs_without_an_allowed_extension_is_invalid() {
    for (rel, bytes) in [
        ("README", b"notes\n".to_vec()),
        (".DS_Store", vec![0u8, 0, 0, 1]),
        (
            "runs_aborted/x/iflist.out",
            b"lo index=1 mac=00-00-00-00-00-00\n".to_vec(),
        ),
        ("verification/foo.csv", b"a,b\n".to_vec()),
    ] {
        let root = scratch();
        Sim::new(Plan::MacosRoot, "m11_root_iflist").write(&root);
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, bytes).unwrap();
        let res = verify_dir(&root);
        let m = run_of(&res, "manifest");
        let c = check(&m, "evidence files outside the runs");
        assert_eq!(c["result"], INVALID, "{rel}");
        assert!(c["detail"].as_str().unwrap().contains(rel), "{c}");
        assert_eq!(verdict(&m), INVALID);
        fs::remove_dir_all(root).unwrap();
    }
    // Allowed files outside the runs are fine.
    let root = scratch();
    Sim::new(Plan::MacosRoot, "m11_root_iflist").write(&root);
    fs::write(root.join("README.md"), "macOS root window\n").unwrap();
    fs::write(root.join("MANIFEST.sha256"), "").unwrap();
    assert_eq!(
        check(
            &run_of(&verify_dir(&root), "manifest"),
            "evidence files outside the runs"
        )["result"],
        PASS
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn an_unreadable_text_file_is_invalid() {
    use std::os::unix::fs::PermissionsExt;
    let mut sim = Sim::new(Plan::Linux, "l01_auto");
    sim.extra.push(("notes.txt".into(), b"a note\n".to_vec()));
    let root = scratch();
    let d = sim.write(&root);
    let p = d.join("notes.txt");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&p).is_ok() {
        // Running as root: nothing is unreadable here, the case cannot be built.
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        fs::remove_dir_all(root).unwrap();
        return;
    }
    let r = run_of(&verify_dir(&root), "l01_auto");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
    assert_verdict(&r, INVALID);
    assert_eq!(
        check(&r, "privacy: notes.txt is readable")["result"],
        INVALID
    );
    assert!(
        check(&r, "privacy:")["name"]
            != "privacy: every text file holds only allowlisted names, addresses and paths"
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_is_invalid_and_never_followed() {
    use std::os::unix::fs::symlink;
    // A loop inside a run: following it would never end.
    let root = scratch();
    let d = Sim::new(Plan::Linux, "l01_auto").write(&root);
    symlink(".", d.join("loop")).unwrap();
    let res = verify_dir(&root);
    let r = run_of(&res, "l01_auto");
    assert_verdict(&r, INVALID);
    assert_eq!(
        check(&r, "no symbolic link in the run directory")["result"],
        INVALID
    );
    assert_eq!(
        check(
            &run_of(&res, "manifest"),
            "no symbolic link in the evidence directory"
        )["result"],
        INVALID
    );
    fs::remove_dir_all(&root).unwrap();
    // A capture that points outside the evidence directory is not read.
    let outside = scratch();
    let root = scratch();
    let sim = Sim::new(Plan::Macos, "m02_user_explicit");
    let d = sim.write(&root);
    fs::write(
        outside.join("uplink.pcap"),
        pcap::encode(&vec![(T0, sim.syns[0].clone())]),
    )
    .unwrap();
    fs::remove_file(d.join("uplink.pcap")).unwrap();
    symlink(outside.join("uplink.pcap"), d.join("uplink.pcap")).unwrap();
    let r = run_of(&verify_dir(&root), "m02_user_explicit");
    assert_verdict(&r, INVALID);
    assert_eq!(
        check(&r, "uplink.pcap is a regular file")["result"],
        INVALID
    );
    assert!(
        !r["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "uplink.pcap complete pcap")
    );
    fs::remove_dir_all(&root).unwrap();
    // A run directory that is itself a link, to a directory outside.
    let root = scratch();
    let real = Sim::new(Plan::MacosRoot, "m11_root_iflist").write(&outside);
    fs::create_dir_all(root.join("runs")).unwrap();
    fs::write(root.join("manifest.json"), r#"{"autodetect":"macos-root"}"#).unwrap();
    symlink(&real, root.join("runs/m11_root_iflist")).unwrap();
    let res = verify_dir(&root);
    let r = run_of(&res, "m11_root_iflist");
    assert_verdict(&r, INVALID);
    assert_eq!(check(&r, "not a symbolic link")["result"], INVALID);
    assert_eq!(
        r["checks"].as_array().unwrap().len(),
        1,
        "nothing behind the link is read"
    );
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn oracle_output_is_held_to_the_scanner_text_rules() {
    // The realistic oracle stderr (banner, \r status lines, forced exit) is clean.
    assert_verdict(&judge(&Sim::new(Plan::Linux, "l11_parity")), PASS);
    for (file, text, needle) in [
        (
            "stderr",
            "Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2026-11-03 10:00:00 GMT\nadapter eth0 192.168.1.5\n",
            "192.168.1.5",
        ),
        (
            "stderr",
            "Initiating SYN Stealth Scan\nhello from denys-mbp\n",
            "not a line masscan prints",
        ),
        (
            "stdout",
            "Discovered open port 80/tcp on 10.1.2.3                                        \n",
            "10.1.2.3",
        ),
        ("stdout", "listening on veth-a\n", "not a Discovered line"),
    ] {
        let mut sim = Sim::new(Plan::Linux, "l11_parity");
        let o = sim.oracle.as_mut().unwrap();
        if file == "stderr" {
            o.stderr = text.into();
        } else {
            o.stdout = text.into();
        }
        let r = judge(&sim);
        assert_verdict(&r, INVALID);
        let c = check(&r, &format!("privacy: oracle/{file}.txt"));
        assert_eq!(c["result"], INVALID);
        assert!(c["detail"].as_str().unwrap().contains(needle), "{c}");
    }
}

// ------------------------------------------------------------------ pre-window lab fix round LF1

/// An ARP request from `mac` asking for `target`, 60 bytes as the scanner's resolver builds it.
fn arp_from(mac: [u8; 6], st: &Stand, target: &str) -> Vec<u8> {
    encode_request(mac, u32::from(st.scanner_ip), u32::from(ip4(target))).to_vec()
}

#[test]
fn a_refusal_with_an_arp_request_from_the_placeholder_mac_is_fail() {
    // m01 proves the masked MAC never reaches the wire: Darwin's placeholder as a source is exactly that frame.
    let placeholder = [0x02, 0, 0, 0, 0, 0];
    for (plan, tag) in [
        (Plan::Macos, "m01_user_masked"),
        (Plan::Linux, "l10_no_such_adapter"),
        (Plan::Windows, "w08b_restricted_scan"),
        // --iflist: no scanner frame either.
        (Plan::Macos, "m07_user_iflist"),
        (Plan::Linux, "l12_iflist"),
    ] {
        let mut sim = Sim::new(plan, tag);
        assert_verdict(&judge(&sim), PASS);
        let req = arp_from(placeholder, &sim.st, "198.18.0.2");
        sim.insert(T0 + 0.5, req);
        let r = judge(&sim);
        assert_verdict(&r, FAIL);
        assert_eq!(r["safety_trip"], true, "{tag}");
        let c = check(&r, "from a MAC other than the stand's scanner and peer");
        assert_eq!(c["result"], FAIL, "{tag}");
        assert!(
            c["detail"].as_str().unwrap().contains("02:00:00:00:00:00"),
            "{tag} {c}"
        );
    }
}

#[test]
fn a_scan_with_an_extra_arp_request_from_the_zero_mac_is_fail() {
    for (plan, tag) in [
        (Plan::Linux, "l01_auto"),
        (Plan::Macos, "m02_user_explicit"),
        (Plan::Windows, "w01_auto"),
        (Plan::MacosRoot, "m10_root_auto_mac"),
    ] {
        let mut sim = Sim::new(plan, tag);
        let req = arp_from([0; 6], &sim.st, "198.18.0.2");
        let t = sim.first_syn_time() - 0.05;
        sim.insert(t, req);
        let r = judge(&sim);
        assert_verdict(&r, FAIL);
        assert_eq!(r["safety_trip"], true, "{tag}");
        let c = check(&r, "from a MAC other than the stand's scanner and peer");
        assert!(
            c["detail"].as_str().unwrap().contains("00:00:00:00:00:00"),
            "{tag} {c}"
        );
    }
    // Any frame of a third device, not only ARP: a SYN-ACK from another MAC on the oracle's capture of l11.
    let mut sim = Sim::new(Plan::Linux, "l11_parity");
    let o = sim.oracle.as_mut().unwrap();
    let i = o
        .pcap
        .iter()
        .position(|(_, f)| f.get(47) == Some(&0x12) && f[12..14] == [8, 0])
        .unwrap();
    let mut third = o.pcap[i].1.clone();
    third[6..12].copy_from_slice(&[0x02, 0xaa, 0, 0, 0, 0x33]);
    let t = o.pcap[i].0 + 0.0001;
    o.pcap.push((t, third));
    o.pcap.sort_by(|a, b| a.0.total_cmp(&b.0));
    let r = judge(&sim);
    assert_verdict(&r, FAIL);
    assert_eq!(
        check(&r, "no frame on the oracle capture from a MAC other")["result"],
        FAIL
    );
    // An aborted run's capture is read by the safety walk with the same rule.
    let root = scratch();
    let mut kept = Sim::new(Plan::Linux, "l02_auto_multi");
    kept.insert(T0 + 0.4, arp_from([0; 6], &kept.st, "198.18.0.2"));
    let d = kept.write(&root);
    fs::create_dir_all(root.join("runs_aborted")).unwrap();
    fs::rename(&d, root.join("runs_aborted/l02_auto_multi.n1")).unwrap();
    let res = verify_dir(&root);
    assert_eq!(res["overall"], FAIL, "{:#?}", res["safety_scan"]);
    assert_eq!(
        res["safety_trips"],
        json!(["runs_aborted/l02_auto_multi.n1"])
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn every_synthetic_stand_capture_holds_only_the_stand_macs() {
    // The generator's runs of every case (markers, scanner, peer, the Windows guest kernel's ARP): no finding.
    for plan in [Plan::Linux, Plan::Macos, Plan::MacosRoot, Plan::Windows] {
        for tag in planned_tags(plan) {
            let sim = Sim::new(plan, tag);
            assert!(foreign_frames(&sim.peer, &sim.st).is_empty(), "{tag}");
            if let Some(o) = &sim.oracle {
                assert!(foreign_frames(&o.pcap, &sim.st).is_empty(), "{tag} oracle");
            }
        }
    }
    // The lab markers are exempt whoever sent them; any other frame of that MAC, and a frame too short to name its
    // source, is a finding.
    let st = stand(Plan::Linux);
    let marker = marker_frame(st.scanner_mac, [2, 0xbb, 0, 0, 0, 1], END_PAYLOAD);
    assert!(foreign_frames(&vec![(T0, marker.clone())], &st).is_empty());
    let mut other = marker;
    other[14..].fill(0);
    assert_eq!(
        foreign_frames(&vec![(T0, other), (T0, vec![0; 8])], &st),
        [
            "02:bb:00:00:00:01 ethertype 88b5",
            "a 8-byte frame without an Ethernet header"
        ]
    );
}

#[test]
fn committed_stand_captures_hold_only_the_stand_macs() {
    // Real witness captures of the same three stands from earlier acceptances: the allowed set derived from the
    // stand table (scanner NIC and peer) is what those wires carried, so the rule does not fail a correct live run.
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/experiments");
    for (plan, dir, only_peer) in [
        (
            Plan::Linux,
            "2026-10-25-rmasscan-windows-sendqueue-acceptance-raw/linux-functional-r1",
            false,
        ),
        (
            Plan::Macos,
            "2026-10-25-rmasscan-macos-bpf-acceptance-raw/functional-r1",
            true,
        ),
        (
            Plan::Windows,
            "2026-10-25-rmasscan-windows-sendqueue-acceptance-raw/functional-r3",
            true,
        ),
    ] {
        let d = base.join(dir);
        let st = stand(plan);
        let mut files = 0;
        let mut frames = 0;
        for rel in crate::macos_verify::relative_files(&d) {
            let name = Path::new(&rel)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if !name.ends_with(".pcap") || (only_peer && name != "peer.pcap") {
                continue;
            }
            let (_, fr) = pcap::read_pcap_records(&fs::read(d.join(&rel)).unwrap()).unwrap();
            let foreign = foreign_frames(&fr, &st);
            assert!(foreign.is_empty(), "{dir}/{rel}: {foreign:?}");
            files += 1;
            frames += fr.len();
        }
        assert!(
            files >= 10 && frames >= 500,
            "{dir}: {files} captures, {frames} frames"
        );
    }
}

#[test]
fn l12_with_the_oracles_raw_listing_kept_is_invalid() {
    // R2 for the oracle too: masscan lists on stderr, and neither of its streams of the --iflist run is evidence.
    let listing =
        " 0  veth-a \t(No description available)\n 1  lo \t(No description available)\n\n";
    for (name, text) in [("oracle/stderr.txt", listing), ("oracle/stdout.txt", "")] {
        let mut sim = Sim::new(Plan::Linux, "l12_iflist");
        sim.extra.push((name.into(), text.as_bytes().to_vec()));
        let r = judge(&sim);
        assert_verdict(&r, INVALID);
        assert_eq!(
            check(
                &r,
                &format!("the oracle's full --iflist output is not stored ({name} absent)")
            )["result"],
            INVALID
        );
    }
}

#[test]
fn w08b_with_the_products_restricted_token_text_is_pass() {
    // The product's text names the device through `{:?}`: its backslashes arrive doubled on stderr.
    let sim = Sim::new(Plan::Windows, "w08b_restricted_scan");
    let err = sim.det.error.clone().unwrap();
    assert!(
        err.contains(r#"no Npcap device named "\\Device\\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}": only loopback is visible"#),
        "{err}"
    );
    assert!(sim.stderr_text().contains(r#""\\Device\\NPF_{"#));
    assert_verdict(&judge(&sim), PASS);
    // Another device behind the same escapes is still a name off the stand.
    let mut sim = Sim::new(Plan::Windows, "w08b_restricted_scan");
    sim.det.error = Some(err.replace(
        "C4617223-A264-44F4-BDC8-0EA27F02CC40",
        "11111111-2222-3333-4444-555555555555",
    ));
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(check(&r, "privacy: guest-stderr.txt")["result"], INVALID);
}

#[test]
fn quoted_values_undo_only_the_two_debug_escapes_of_a_name() {
    assert_eq!(
        quoted_values(r#"named "\\Device\\NPF_{X}": only loopback"#),
        [r"\Device\NPF_{X}"]
    );
    // The C-form texts quote names as they are: a single backslash stays.
    assert_eq!(
        quoted_values(r#"no such interface "\Device\NPF_{X}""#),
        [r"\Device\NPF_{X}"]
    );
    // `\"` stays inside the value; `\t`, `\n`, `\u{..}` are not undone (narrow), and an open quote is still read.
    assert_eq!(
        quoted_values(r#"a "say \"hi\"" b "t\tab" c "open"#),
        [r#"say "hi""#, r"t\tab", "open"]
    );
    assert_eq!(
        quoted_values(r#"for router veth-a: "198.18.0.9""#),
        ["198.18.0.9"]
    );
    // Through the privacy rule: the stand's device escaped is the stand's device; escaped otherwise it is not.
    assert!(
        name_problems(refusal_names(
            r#"x "\\Device\\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}""#
        ))
        .is_empty()
    );
    assert!(
        !name_problems(refusal_names(
            r#"x "\\Device\\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}\t""#
        ))
        .is_empty()
    );
}

#[test]
fn a_linux_run_without_a_sealed_after_state_is_invalid() {
    // The seal after the run (`isolation-post.json`) is judged offline like the seal before it. It is taken once
    // the scanner has run, so missing or broken it is unproven evidence: INVALID, never NOT RUN.
    let mut open = json!({});
    let mut default_mode = json!({});
    for (n, b) in Sim::new(Plan::Linux, "l01_auto").files() {
        if n == "isolation.json" {
            open = serde_json::from_slice(&b).unwrap();
            default_mode = open.clone();
        }
    }
    // A stand that is no longer the autodetect seal: a default route in the peer namespace, or the default mode.
    open["default_route"]["peer_ns"] = json!("via 198.18.0.1 dev veth-b");
    default_mode["mode"] = json!("default");
    for (why, post) in [
        ("missing", None),
        ("not JSON", Some(b"{\"mode\":".to_vec())),
        ("not permitting", Some(serde_json::to_vec(&open).unwrap())),
        (
            "another mode",
            Some(serde_json::to_vec(&default_mode).unwrap()),
        ),
    ] {
        let mut sim = Sim::new(Plan::Linux, "l01_auto");
        sim.omit.push("isolation-post.json");
        sim.extra
            .extend(post.map(|b| ("isolation-post.json".to_owned(), b)));
        let r = judge(&sim);
        assert_verdict(&r, INVALID);
        assert_eq!(
            check(
                &r,
                "isolation-post.json: the stand still sealed after the run"
            )["result"],
            INVALID,
            "{why}"
        );
        assert_eq!(r["behaviour_fail"], false, "{why}");
    }
    // The generator writes the record the suite writes, and a consistent run passes with it.
    let sim = Sim::new(Plan::Linux, "l01_auto");
    assert!(sim.files().iter().any(|(n, _)| n == "isolation-post.json"));
    let r = judge(&sim);
    assert_verdict(&r, PASS);
    assert_eq!(
        check(
            &r,
            "isolation-post.json: the stand still sealed after the run"
        )["result"],
        PASS
    );
}

#[test]
fn a_linux_directory_without_the_teardown_record_is_invalid() {
    // The undo of the Linux stand is evidence: both namespaces deleted, none of the run left behind.
    let teardown = |text: Option<&str>| {
        let root = scratch();
        write_plan(&root, Plan::Linux);
        let p = root.join("teardown.json");
        match text {
            Some(t) => fs::write(&p, t).unwrap(),
            None => fs::remove_file(&p).unwrap(),
        }
        let res = verify_dir(&root);
        fs::remove_dir_all(root).unwrap();
        res
    };
    let res = teardown(Some(TEARDOWN));
    assert_eq!(res["overall"], PASS, "{res:#}");
    let name = "teardown.json: wire-lab.sh deleted both namespaces of the stand and none is left";
    assert_eq!(check(&run_of(&res, "manifest"), name)["result"], PASS);
    for (why, text) in [
        ("missing", None),
        ("not JSON", Some("{\"namespaces_left\":")),
        (
            "the namespace list could not be read",
            Some(r#"{"namespaces_deleted":[],"namespaces_left":null}"#),
        ),
        (
            "a namespace left",
            Some(r#"{"namespaces_deleted":["wl-scan-RUNID"],"namespaces_left":1}"#),
        ),
        (
            "a namespace of the lab still listed, both deleted",
            Some(r#"{"namespaces_deleted":["wl-scan-RUNID","wl-peer-RUNID"],"namespaces_left":1}"#),
        ),
        (
            "the peer namespace not deleted",
            Some(r#"{"namespaces_deleted":["wl-scan-RUNID"],"namespaces_left":0}"#),
        ),
        (
            "not the stand's namespaces",
            Some(r#"{"namespaces_deleted":["wl-scan-RUNID","other"],"namespaces_left":0}"#),
        ),
        (
            "a field of another record",
            Some(
                r#"{"namespaces_deleted":["wl-scan-RUNID","wl-peer-RUNID"],"namespaces_left":0,"ok":true}"#,
            ),
        ),
    ] {
        let res = teardown(text);
        let m = run_of(&res, "manifest");
        assert_eq!(check(&m, name)["result"], INVALID, "{why}");
        assert_eq!(verdict(&m), INVALID, "{why}");
        assert_eq!(res["overall"], INVALID, "{why}");
        assert_eq!(res["safety_trips"], json!([]), "{why}");
    }
    // Only the Linux stand is set up and torn down by wire-lab.sh: the other plans have no such record.
    for plan in [Plan::Macos, Plan::MacosRoot, Plan::Windows] {
        let root = scratch();
        write_plan(&root, plan);
        let res = verify_dir(&root);
        assert_eq!(res["overall"], PASS, "{plan:?}");
        assert!(
            !run_of(&res, "manifest")["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["name"].as_str().unwrap().starts_with("teardown.json"))
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn a_macos_privacy_filter_that_does_not_add_up_is_invalid() {
    // The macOS peer capture is published without the host's mDNS: capture.json says what was left out, and the
    // counts must add up to the capture the witness judged (kept = peer.pcap, kept + dropped = unfiltered).
    let name = "capture.json: the macOS privacy filter";
    let record = |sim: &Sim| -> Value {
        let b = sim
            .files()
            .into_iter()
            .find(|(n, _)| n == "capture.json")
            .unwrap()
            .1;
        serde_json::from_slice(&b).unwrap()
    };
    for (plan, tag) in [
        (Plan::Macos, "m02_user_explicit"),
        (Plan::Macos, "m01_user_masked"),
        (Plan::MacosRoot, "m11_root_iflist"),
    ] {
        let sim = Sim::new(plan, tag);
        let rec = record(&sim);
        assert_eq!(
            rec["privacy_filter"]["frames_kept"],
            sim.peer.len(),
            "{tag}"
        );
        let r = judge(&sim);
        assert_verdict(&r, PASS);
        assert_eq!(check(&r, name)["result"], PASS, "{tag}");
        type Edit = (&'static str, fn(&mut Value));
        let edits: [Edit; 6] = [
            ("no privacy_filter", |v| {
                v.as_object_mut().unwrap().remove("privacy_filter");
            }),
            ("no unfiltered count", |v| {
                v.as_object_mut().unwrap().remove("unfiltered");
            }),
            ("kept is not peer.pcap", |v| {
                v["privacy_filter"]["frames_kept"] = json!(v["pcap_frames"].as_u64().unwrap() + 1);
                v["unfiltered"]["pcap_frames"] =
                    json!(v["unfiltered"]["pcap_frames"].as_u64().unwrap() + 1);
            }),
            ("kept + dropped is not the witness's capture", |v| {
                v["privacy_filter"]["frames_dropped"] = json!(3);
            }),
            ("a count that is not a number", |v| {
                v["privacy_filter"]["frames_dropped"] = json!("2");
            }),
            ("another filter", |v| {
                v["privacy_filter"]["published"] = json!("not udp port 5353");
            }),
        ];
        for (why, edit) in edits {
            let mut sim = Sim::new(plan, tag);
            let mut rec = record(&sim);
            edit(&mut rec);
            sim.omit.push("capture.json");
            sim.extra.push((
                "capture.json".into(),
                serde_json::to_vec_pretty(&rec).unwrap(),
            ));
            let r = judge(&sim);
            assert_verdict(&r, INVALID);
            assert_eq!(check(&r, name)["result"], INVALID, "{tag} {why}");
            assert_eq!(r["behaviour_fail"], false, "{tag} {why}");
        }
    }
    // The other stands publish their witness as it captured: no filter, no such check.
    for (plan, tag) in [(Plan::Linux, "l01_auto"), (Plan::Windows, "w01_auto")] {
        let r = judge(&Sim::new(plan, tag));
        assert!(
            !r["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["name"].as_str().unwrap().starts_with(name)),
            "{tag}"
        );
    }
}

#[test]
fn a_teardown_record_of_another_lab_is_invalid() {
    // The record is bound to the lab whose runs it closes. Lab 1's cleanup died before writing it; lab 2, started
    // into the same --out, wrote a clean record of its own namespaces: lab 1's runs must not pass with it.
    let name = "teardown.json belongs to the lab of manifest.json (lab_id)";
    let t: TeardownRecord = serde_json::from_str(TEARDOWN).unwrap();
    assert_eq!(t.lab_id, LAB_ID);
    let dir = |manifest_id: Option<&str>, teardown: &str| {
        let root = scratch();
        write_plan(&root, Plan::Linux);
        let mut m = json!({"autodetect": "linux"});
        if let Some(id) = manifest_id {
            m["lab_id"] = json!(id);
        }
        fs::write(root.join("manifest.json"), m.to_string()).unwrap();
        fs::write(root.join("teardown.json"), teardown).unwrap();
        let res = verify_dir(&root);
        fs::remove_dir_all(root).unwrap();
        res
    };
    let other = TEARDOWN.replace(LAB_ID, "0b1e6f3d-2a4c-4f85-8d9e-7c3a1b5e2f60");
    for (why, manifest_id, teardown) in [
        ("another lab's record", Some(LAB_ID), other.as_str()),
        ("a manifest without a lab id", None, TEARDOWN),
        (
            "an empty lab id on both sides",
            Some(""),
            &TEARDOWN.replace(LAB_ID, ""),
        ),
        (
            "a lab id that is not an id",
            Some("a b"),
            &TEARDOWN.replace(LAB_ID, "a b"),
        ),
    ] {
        let res = dir(manifest_id, teardown);
        assert_eq!(res["overall"], INVALID, "{why}");
        assert_eq!(res["safety_trips"], json!([]), "{why}");
        assert_eq!(
            check(&run_of(&res, "manifest"), name)["result"],
            INVALID,
            "{why}"
        );
    }
    let res = dir(Some(LAB_ID), TEARDOWN);
    assert_eq!(res["overall"], PASS, "{res:#}");
    assert_eq!(check(&run_of(&res, "manifest"), name)["result"], PASS);
    // A record without a lab id is not a teardown record at all.
    let res = dir(
        Some(LAB_ID),
        r#"{"namespaces_deleted":["wl-scan-RUNID","wl-peer-RUNID"],"namespaces_left":0}"#,
    );
    assert_eq!(res["overall"], INVALID);
    assert_eq!(
        check(
            &run_of(&res, "manifest"),
            "teardown.json: wire-lab.sh deleted both namespaces"
        )["result"],
        INVALID
    );
}

#[test]
fn the_oracles_iflist_json_names_the_stand_in_masscans_form() {
    // Ruling: the oracle's record is reduced like rmasscan's, its stand line included (in masscan's form).
    let name = "the oracle's iflist.json stand line names the stand NIC in masscan's form";
    let sim = Sim::new(Plan::Linux, "l12_iflist");
    let r = judge(&sim);
    assert_verdict(&r, PASS);
    assert_eq!(check(&r, name)["result"], PASS);
    for (why, line) in [
        ("no stand line", None),
        (
            "another adapter",
            Some(" 2  lo \t(No description available)"),
        ),
        (
            "rmasscan's form",
            Some("veth-a index=2 mac=02-aa-00-00-00-01 ipv4=198.18.0.1 up ethernet"),
        ),
        (
            "a name that only starts with the stand's",
            Some(" 1  veth-ab \t(No description available)"),
        ),
        (
            "not masscan's form",
            Some("1 veth-a (No description available)"),
        ),
    ] {
        let mut sim = Sim::new(Plan::Linux, "l12_iflist");
        sim.oracle_iflist.as_mut().unwrap().stand_line = line.map(Into::into);
        let r = judge(&sim);
        assert_verdict(&r, INVALID);
        assert_eq!(check(&r, name)["result"], INVALID, "{why}");
        assert_eq!(r["behaviour_fail"], false, "{why}");
    }
    // The stored line is held to the same privacy rules as rmasscan's: a host NIC, or an address in the description.
    for line in [
        " 3  wlp2s0 \t(No description available)",
        " 1  veth-a \t(192.168.1.20)",
    ] {
        let mut sim = Sim::new(Plan::Linux, "l12_iflist");
        sim.oracle_iflist.as_mut().unwrap().stand_line = Some(line.into());
        let r = judge(&sim);
        assert_verdict(&r, INVALID);
        assert_eq!(
            check(&r, "privacy: oracle/iflist.json")["result"],
            INVALID,
            "{line}"
        );
    }
    assert_eq!(
        masscan_iflist_name(" 12  veth-a \t(No description available)\r"),
        Some("veth-a")
    );
    for not in [
        "veth-a index=2 mac=none",
        " 0 veth-a \t(x)",
        "  veth-a \t(x)",
        " 0  veth-a (x)",
        " 0   \t(x)",
    ] {
        assert_eq!(masscan_iflist_name(not), None, "{not:?}");
    }
}

// ------------------------------------------------------------------ final review

/// Where the first macOS window at 6c87e94 wrote `--out`: a scratch directory whose path names the account, joined
/// with dashes (`-Users-<account>`) under the per-user root `claude-<uid>`.
pub(crate) const SCRATCHPAD_OUT: &str = "/private/tmp/claude-501/-Users-alice/094668fe-1658-4758-aa06-f35202b4089e/scratchpad/autodetect-out/macos-r1";
/// The neutral `--out` of the committed macOS directories (`mktemp -d /private/tmp/rmasscan-ad.XXXXXX`).
const NEUTRAL_OUT: &str = "/private/tmp/rmasscan-ad.6qCSaM/autodetect-out/macos-r1";

#[test]
fn flattened_account_paths_and_per_user_scratch_roots_are_flagged() {
    let problems = |text: &str| token_problems(text, false);
    for bad in [
        SCRATCHPAD_OUT,
        "-Users-alice",
        "\"-home-bob/scratch\"",
        "/private/tmp/claude-501/x",
        "claude-0",
        "/private/var/folders/c3/j210wv292jl3t_dn4z86k8040000gn/T/rml-1/out",
    ] {
        assert!(!problems(bad).is_empty(), "{bad}");
    }
    // The placeholders the suites write, neutral absolute paths, and names that only contain the words.
    let neutral = format!(
        "{NEUTRAL_OUT}/.work/m01_user_masked.r69088813212522901048b64317ab8605/peer.unfiltered"
    );
    for ok in [
        "$OUT/.work/m01_user_masked.r69088813212522901048b64317ab8605/peer.unfiltered",
        "$WORK/l01_auto.r1/run/peer.pcap",
        "$HOME/rmasscan-ad-scratch.0jbUfd/autodetect-out/linux-r1",
        "-Users-$USER/x",
        "-home-$USER",
        "$USER",
        &neutral,
        "/private/tmp/x",
        "/private/var/run/rmasscan-lab/m1.json",
        "pcap-hashes-on-home-pc.txt",
        "abort-hashes-on-home-pc.txt",
        "claude",
        "claude-code",
    ] {
        assert!(problems(ok).is_empty(), "{ok}: {:?}", problems(ok));
    }
}

/// `sim` with the witness's `-w` path in `capture.json` set to `w`.
fn with_witness_path(mut sim: Sim, w: &str) -> Sim {
    let mut rec: Value = serde_json::from_slice(&Sim::published_witness(&sim.peer)).unwrap();
    rec["tcpdump_argv"][9] = json!(w);
    sim.omit.push("capture.json");
    sim.extra.push((
        "capture.json".into(),
        serde_json::to_vec_pretty(&rec).unwrap(),
    ));
    sim
}

#[test]
fn a_scratchpad_out_path_in_capture_json_is_invalid() {
    // The leak of the first macOS window at 6c87e94: every capture.json named the account through the witness's `-w`
    // path into `.work`, and the verifier passed it. Now the run is INVALID with the file named.
    let tag = "m01_user_masked";
    let unfiltered = |out: &str| format!("{out}/.work/{tag}.r1/peer.unfiltered");
    let r = judge(&with_witness_path(
        Sim::new(Plan::Macos, tag),
        &unfiltered(SCRATCHPAD_OUT),
    ));
    assert_verdict(&r, INVALID);
    let c = check(&r, "privacy: capture.json");
    assert_eq!(c["result"], INVALID);
    let detail = c["detail"].as_str().unwrap();
    assert!(
        detail.contains("-Users-alice") && detail.contains("claude-501"),
        "{detail}"
    );
    // The committed directories' neutral path, and the placeholder the suites now write, pass.
    for w in [unfiltered(NEUTRAL_OUT), unfiltered("$OUT")] {
        let r = judge(&with_witness_path(Sim::new(Plan::Macos, tag), &w));
        assert_verdict(&r, PASS);
    }
    // The macOS per-user temporary directory in a stand record is flagged as well.
    let mut sim = Sim::new(Plan::Linux, "l01_auto");
    sim.extra.push((
        "notes.txt".into(),
        b"work in /private/var/folders/c3/j210/T/tmp.x\n".to_vec(),
    ));
    let r = judge(&sim);
    assert_verdict(&r, INVALID);
    assert_eq!(check(&r, "privacy: notes.txt")["result"], INVALID);
}

/// `runs_aborted/<name>/` with `files` (relative path, bytes) under `root`.
fn write_aborted(root: &Path, name: &str, files: &[(&str, &[u8])]) {
    for (rel, b) in files {
        let p = root.join("runs_aborted").join(name).join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b).unwrap();
    }
}

#[test]
fn an_aborted_attempt_is_listed_and_a_later_run_of_its_case_never_passes() {
    // A Windows preflight NOT RUN keeps the orchestrator's records under runs_aborted/<tag>.<run id>/work/ (json and
    // txt only); a later `--only <tag>` into the same --out wrote runs/<tag>. That PASS must not overtake the attempt.
    let preflight = b"rc 0\n[+] interface = Ethernet (detected: route to 198.18.0.2)\n".as_slice();
    let root = scratch();
    write_plan(&root, Plan::Windows);
    assert_eq!(verify_dir(&root)["overall"], PASS);
    write_aborted(
        &root,
        "w06_multi_no_gateway.r1",
        &[("work/preflight.txt", preflight), ("work/argv.json", b"{}")],
    );
    let res = verify_dir(&root);
    assert_eq!(res["overall"], INVALID, "{:#}", res["aborted"]);
    let aborted = res["aborted"].as_array().unwrap();
    assert_eq!(aborted.len(), 1, "{aborted:#?}");
    assert_eq!(aborted[0]["tag"], "w06_multi_no_gateway.r1");
    assert_eq!(aborted[0]["notes"]["case"], "w06_multi_no_gateway");
    assert_eq!(
        aborted[0]["notes"]["files"],
        json!(["work/argv.json", "work/preflight.txt"])
    );
    assert_eq!(aborted[0]["safety_trip"], false);
    let r = run_of(&res, "w06_multi_no_gateway");
    assert_verdict(&r, INVALID);
    let c = check(&r, "no aborted attempt of this case");
    assert_eq!(c["result"], INVALID);
    assert!(
        c["detail"]
            .as_str()
            .unwrap()
            .contains("runs_aborted/w06_multi_no_gateway.r1"),
        "{c}"
    );
    // Every other case is untouched, and nothing is a safety finding.
    assert_verdict(&run_of(&res, "w01_auto"), PASS);
    assert_verdict(&run_of(&res, "manifest"), PASS);
    assert_eq!(res["safety_trips"], json!([]));
    // The text report names it.
    let lines = crate::verify::safety_report_lines(&res);
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("ABORTED") && l.contains("w06_multi_no_gateway.r1")),
        "{lines:?}"
    );
    fs::remove_dir_all(&root).unwrap();

    // An attempt of a case that never got a run: the case stays NOT RUN (never INVALID or PASS).
    let root = scratch();
    for tag in planned_tags(Plan::Linux)
        .into_iter()
        .filter(|t| *t != "l03_adapter")
    {
        Sim::new(Plan::Linux, tag).write(&root);
    }
    fs::write(root.join("teardown.json"), format!("{TEARDOWN}\n")).unwrap();
    write_aborted(&root, "l03_adapter.n1", &[("isolation.json", b"{}")]);
    let res = verify_dir(&root);
    assert_eq!(res["overall"], NOT_RUN);
    assert_verdict(&run_of(&res, "l03_adapter"), NOT_RUN);
    assert_eq!(res["aborted"][0]["notes"]["case"], "l03_adapter");
    fs::remove_dir_all(&root).unwrap();

    // An entry that is no attempt of a planned case (another tag, no run id, a loose file) is an INVALID directory.
    for (name, rel) in [
        ("x99_other.n1", "a.txt"),
        ("w01_auto", "a.txt"),
        ("w01_autox.n1", "a.txt"),
    ] {
        let root = scratch();
        write_plan(&root, Plan::Windows);
        write_aborted(&root, name, &[(rel, b"a\n")]);
        let res = verify_dir(&root);
        assert_eq!(res["overall"], INVALID, "{name}");
        let m = run_of(&res, "manifest");
        let c = check(&m, "runs_aborted/ holds only attempts");
        assert_eq!(c["result"], INVALID, "{name}");
        assert!(c["detail"].as_str().unwrap().contains(name), "{c}");
        assert_eq!(res["aborted"][0]["tag"], name);
        assert!(res["aborted"][0]["notes"]["case"].is_null(), "{name}");
        fs::remove_dir_all(&root).unwrap();
    }
    let root = scratch();
    write_plan(&root, Plan::Windows);
    fs::create_dir_all(root.join("runs_aborted")).unwrap();
    fs::write(root.join("runs_aborted/notes.txt"), "a\n").unwrap();
    let res = verify_dir(&root);
    assert_eq!(res["overall"], INVALID);
    assert_eq!(res["aborted"][0]["tag"], "notes.txt");
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn the_aborted_attempt_names_are_the_suites_rule() {
    // `<tag>.<run id>` of a planned tag, the rule the suites refuse a repeat by.
    assert_eq!(
        aborted_case(Plan::Windows, "w06_multi_no_gateway.r6af22fc1"),
        Some("w06_multi_no_gateway")
    );
    assert_eq!(aborted_case(Plan::Linux, "l01_auto.n1"), Some("l01_auto"));
    for (plan, name) in [
        (Plan::Linux, "l01_auto"),
        (Plan::Linux, "l01_auto."),
        (Plan::Linux, "l01_autox.n1"),
        (Plan::Linux, "w01_auto.r1"),
        (Plan::Macos, "m10_root_auto_mac.n1"),
        (Plan::Linux, "l01_auto.n1/x"),
    ] {
        assert_eq!(aborted_case(plan, name), None, "{plan:?} {name}");
    }
    let root = scratch();
    assert!(aborted_attempts(&root, "l01_auto").is_empty());
    write_aborted(&root, "l01_auto.n1", &[("a.txt", b"a\n")]);
    write_aborted(&root, "l01_auto.n2", &[("a.txt", b"a\n")]);
    write_aborted(&root, "l02_auto_multi.n1", &[("a.txt", b"a\n")]);
    assert_eq!(
        aborted_attempts(&root, "l01_auto"),
        ["runs_aborted/l01_auto.n1", "runs_aborted/l01_auto.n2"]
    );
    assert!(aborted_attempts(&root, "l03_adapter").is_empty());
    fs::remove_dir_all(&root).unwrap();
}
