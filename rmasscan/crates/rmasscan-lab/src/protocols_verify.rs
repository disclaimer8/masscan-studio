//! Offline verifier of the protocols acceptance on the sealed Linux netns stand (`protocols-verify`) and the one case
//! table of its suite (`protocols-suite linux`): design §6.2 (docs/superpowers/specs/2026-11-08-rmasscan-protocols-
//! ipv4-design.md), invariants §4.1-§4.3: ICMP Echo, UDP with the built-in payloads and ICMP 3/3, SCTP INIT with
//! INIT-ACK and ABORT, the ARP scan, and a mixed list, each against the pinned C masscan `8e6b3b0`.
//!
//! Five cases, `p01_ping` .. `p05_mixed_protos` ([`CASES`]). A case is a list of STEPS ([`steps`]): for every output
//! document of the case one rmasscan run and one run of the C oracle with the same argv, each with its own peer
//! capture. The suite writes `argv.json` of every step and `expect.json` of the case from this table and nowhere
//! else; the verifier judges every step against it. Every scan names `--seed 1` and `--source-port 40000`, so the two
//! scanners must put the same probes on the wire in the same order (BlackRock), byte for byte.
//!
//! The stand (`wire-lab.sh --suite protocols`) is the autodetect netns stand (scanner `198.18.0.1` on `veth-a`, peers
//! `198.18.0.2`-`.5` on `veth-b`) with a peer that answers every protocol the same way every time
//! ([`responder_args`], recorded per case in `peer-stack.json`, [`PeerStack`]):
//! - TCP: the peer kernel; `capture responder --ports 80,8080` listens, every other port is reset;
//! - UDP: the peer kernel; the responder binds one socket per peer address and port of [`UDP_OPEN`] and answers each
//!   datagram once with [`UDP_REPLY`]; every other port gets the kernel's ICMP 3/3;
//! - ICMP Echo and ARP: the peer kernel (Echo Reply, ARP reply for its four addresses);
//! - SCTP: the host kernel has no SCTP (`sctp_in_kernel: false`; the suite refuses the SCTP cases otherwise, so no
//!   kernel ABORT can stand beside the responder's answer); the responder answers each INIT on the link itself with
//!   [`sctp_reply`]: INIT-ACK on [`SCTP_OPEN`], ABORT elsewhere (T bit 0, the INIT's initiate tag as the verification
//!   tag, as Linux answers an INIT to a port without an endpoint). The peer kernel's ICMP 3/2 (protocol unreachable)
//!   follows each INIT; C (`proto-icmp.c` code 2) and rmasscan ignore it;
//! - `net.ipv4.icmp_ratemask = 0` in the peer namespace: no ICMP error is rate-limited, so every closed UDP probe
//!   gets its ICMP 3/3.
//!
//! What is judged, per step: the probes on the wire (rmasscan's equal the product's own plan, `ReadyPlan` and its
//! cursor, in order; the oracle's equal rmasscan's), the stand's answer to every probe (exactly the one reply the
//! stand owes; a stand that answered otherwise is INVALID, never a FAIL), the document against the replies on the
//! step's own wire (format by format, in reply order up to replies captured at most [`REPLY_REORDER_WINDOW_US`]
//! apart), rmasscan's stderr and exit, and the two scanners' documents against each other (as multisets of
//! records: [`RECORD_ORDER_VS_C`]). The differences from C that the code documents are applied by name, never by a looser
//! comparison ([`DEVIATIONS`]): each has a check that the wire is such that it cannot change the comparison, and the
//! run's notes say which applied and how often.
//!
//! The rules of `autodetect-verify` and `scan-control-verify` hold and their machinery is reused: a missing input is
//! NOT RUN, unproven evidence INVALID, a lab frame off the stand a safety FAIL, and no verdict is ever promoted. The
//! oracle never finishes a live scan on this stand (`[-] Passed the wait window but still running, forcing exit...`,
//! main.c:1489-1496): its file without the footer is expected with that line on its stderr.
//!
//! Layout of an evidence directory: `manifest.json` (key `protocols`: `linux`), `teardown.json`, `runs/<tag>/` per
//! case. A case directory holds `expect.json` ([`ProtoExpect`]), `isolation.json` and `isolation-post.json`
//! (`capture isolation --mode autodetect`), `peer-stack.json`, `hashes-before-copy.txt`, and one directory per step:
//! `argv.json`, `stdout.txt stderr.txt exit.txt`, the document under its neutral name (`output.txt`, `output.json`,
//! `output.bin`; the interactive form is `stdout.txt` itself), the peer witness `peer.pcap capture.json peer.err`
//! and `responder.json` ([`ResponderRecord`]: the peer responder at the scanner's end, with its stderr).
use crate::{
    autodetect_verify::{self as av, EVIDENCE_EXTENSIONS, Plan, Stand},
    output_verify::{BINARY_BLOCK, BINARY_REC, FLAG_NAMES, canon, fields, text_lines},
    pair_verify::{
        self, Doc, PairPlan, Record, Side, Tally, WireSummary, beh, cap, case_of, each,
        expect_steps, named_deviations, pair_steps, parse_doc_with, plan_probes, scan_tail,
        scanner_counts, scanner_frame_checks, tags_of,
    },
    pcap::Frames,
    scan_control_verify::Who,
    verify::{self, Run},
};
use rmasscan_core::{
    config::{Operation, ScanConfig, parse_rate, validate},
    massip::MassIp,
    packet::LinkType,
    probe::{AdapterBinding, NicBinding, ReadyPlan},
    targets::{add_target_string, parse_ports},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    path::Path,
};
// What the fixture tests (`protocols_verify_tests.rs`, `use super::*`) took from this module's scope before the shared
// machinery moved to `pair_verify`.
#[cfg(test)]
use crate::{
    autodetect_verify::{ArgvRecord, MANIFEST_JSON},
    scan_control_verify as sv,
    verify::{FAIL, INVALID, NOT_RUN, PASS, array, s},
};
#[cfg(test)]
use {serde_json::json, std::fs};

// ------------------------------------------------------------------ the case table

pub const TARGETS: &str = "198.18.0.2-198.18.0.5";
pub const RATE: &str = "100";
pub const WAIT: &str = "3";
/// Both scanners send from this port: the UDP payload cookies, the SCTP initiate tags and the ICMP ids depend on it.
pub const SOURCE_PORT: u16 = 40000;
/// The peer's open ports per protocol; every other scanned port of the protocol is closed.
pub const TCP_OPEN: [u16; 2] = [80, 8080];
pub const UDP_OPEN: [u16; 2] = [53, 161];
pub const SCTP_OPEN: [u16; 1] = [2905];
/// What the responder answers to every datagram on an open UDP port.
pub const UDP_REPLY: &[u8] = b"rmasscan-lab udp reply\n";
/// The responder's own INIT-ACK fields: its initiate tag, initial TSN and state cookie.
pub const PEER_INIT_TAG: u32 = 0x5eed_0001;
pub const PEER_TSN: u32 = 1;
pub const STATE_COOKIE: &[u8; 8] = b"rmlab-ck";
/// The peer interface the responder answers SCTP on (`wire-lab.sh` `IF_B`).
pub const PEER_IF: &str = "veth-b";
/// The scanner namespace's default gateway: the next hop a scan that is no ARP scan resolves with ARP.
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
pub const EXPECT_JSON: &str = "expect.json";
pub const ISOLATION_JSON: &str = "isolation.json";
pub const ISOLATION_POST_JSON: &str = "isolation-post.json";
pub const PEER_STACK_JSON: &str = "peer-stack.json";
/// The peer responder of a step at the scanner's end ([`ResponderRecord`]).
pub const RESPONDER_JSON: &str = "responder.json";
/// The peer witness of a step.
pub const PEER_FILES: [&str; 3] = ["peer.pcap", "capture.json", "peer.err"];

/// The document of a step.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Out {
    List,
    Json,
    Binary,
    /// No `-o`: the interactive `Discovered ...` lines on stdout.
    Stdout,
}
impl Out {
    pub fn flag(self) -> Option<&'static str> {
        match self {
            Out::List => Some("-oL"),
            Out::Json => Some("-oJ"),
            Out::Binary => Some("-oB"),
            Out::Stdout => None,
        }
    }
    /// The neutral name of the output file, in the scanner's working directory and in the evidence.
    pub fn file(self) -> Option<&'static str> {
        match self {
            Out::List => Some("output.txt"),
            Out::Json => Some("output.json"),
            Out::Binary => Some("output.bin"),
            Out::Stdout => None,
        }
    }
    pub(crate) fn step(self, who: Who) -> &'static str {
        match (self, who) {
            (Out::List, Who::Rmasscan) => "list",
            (Out::Json, Who::Rmasscan) => "json",
            (Out::Binary, Who::Rmasscan) => "binary",
            (Out::Stdout, Who::Rmasscan) => "stdout",
            (Out::List, Who::Oracle) => "oracle-list",
            (Out::Json, Who::Oracle) => "oracle-json",
            (Out::Binary, Who::Oracle) => "oracle-binary",
            (Out::Stdout, Who::Oracle) => "oracle-stdout",
        }
    }
}

/// The documented differences from C, by name, and the rule each applies.
pub const DEVIATIONS: [(&str, &str); 6] = [
    (
        "udp-checksum-ffff",
        "R12: a UDP checksum that computes to 0 goes out as 0xFFFF from rmasscan (RFC 768) and as 0x0000 from C; two probes that differ only there are the same probe",
    ),
    (
        "icmp-echo-code-0",
        "R11: rmasscan takes an Echo Reply only with code 0, C with any code; every Echo Reply on the wire must have code 0",
    ),
    (
        "rx-checksum-verify",
        "R11: rmasscan drops a reply whose IPv4 header checksum, ICMP, TCP or UDP checksum or SCTP CRC-32C is wrong, C reads it; every reply on the wire must carry valid sums",
    ),
    (
        "non-tcp-dedup",
        "rmasscan reports a UDP, ICMP 3/3 or SCTP reply once per (protocol, address, port, status), C prints every one (main.c:917-922); C's repeated UDP and SCTP records are collapsed before the documents are compared (never a TCP, Echo or ARP record)",
    ),
    (
        "sctp-tcp-fallthrough",
        "C main.c:920-922 goes on to read an SCTP reply as TCP (its first chunk's flags as TCP flags), rmasscan does not; every SCTP reply's chunk flags must be neither SYN-ACK nor RST, so C prints nothing more",
    ),
    (
        "arp-mac-ethernet-source",
        "the MAC of an ARP record is the Ethernet source (C proto-arp.c:39), not the sender hardware address of the design text; every ARP reply must carry the same MAC in both",
    ),
];

/// Why rmasscan's document and the oracle's are compared as multisets of records, while each one's order is judged
/// against its own wire (no deviation from C: both print in the order the replies arrive).
pub const RECORD_ORDER_VS_C: &str = "each scanner prints its records in the order the replies arrive on its own wire (judged per step: the document holds the records of the replies on its wire, in reply order, up to replies captured at most REPLY_REORDER_WINDOW_US = 50 us apart); the two runs of a document do not get the same reply order from the stand: both scanners send several probes back to back at --rate 100, and within such a burst the responder (one thread per UDP socket and for the SCTP link) and the peer kernel (ICMP at once) answer in an order that changes from run to run, as live run linux-protocols-r1 on 68ffcf3 showed (p02, p05); so rmasscan's records must equal C's field for field but the time in any order";

/// One case: what it scans and which documents it writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaseSpec {
    pub tag: &'static str,
    /// The flags that select the probes (after the targets).
    pub flags: &'static [&'static str],
    /// The same ports in the plan's grammar (`-sU -p53` is `U:53`).
    pub plan_ports: &'static str,
    pub arp: bool,
    /// `--show open,closed`: a case with closed ports.
    pub show_closed: bool,
    pub outs: &'static [Out],
    pub deviations: &'static [&'static str],
}

pub const CASES: [CaseSpec; 5] = [
    CaseSpec {
        tag: "p01_ping",
        flags: &["--ping"],
        plan_ports: "I:0",
        arp: false,
        show_closed: false,
        outs: &[Out::List],
        deviations: &["icmp-echo-code-0", "rx-checksum-verify"],
    },
    CaseSpec {
        tag: "p02_udp_payloads_and_closed",
        flags: &["-sU", "-p53,161,500,59999"],
        plan_ports: "U:53,161,500,59999",
        arp: false,
        show_closed: true,
        outs: &[Out::Json, Out::Binary],
        deviations: &["udp-checksum-ffff", "rx-checksum-verify", "non-tcp-dedup"],
    },
    CaseSpec {
        tag: "p03_sctp_init_ack_abort",
        flags: &["-sZ", "-p2905,2906"],
        plan_ports: "S:2905,2906",
        arp: false,
        show_closed: true,
        outs: &[Out::Binary, Out::List],
        deviations: &[
            "rx-checksum-verify",
            "non-tcp-dedup",
            "sctp-tcp-fallthrough",
        ],
    },
    CaseSpec {
        tag: "p04_arp_scan",
        flags: &["--arp"],
        plan_ports: "I:2",
        arp: true,
        show_closed: false,
        outs: &[Out::Stdout, Out::Binary],
        deviations: &["arp-mac-ethernet-source"],
    },
    CaseSpec {
        tag: "p05_mixed_protos",
        flags: &["-pT:80,U:53,S:2905,I:0"],
        plan_ports: "T:80,U:53,S:2905,I:0",
        arp: false,
        show_closed: true,
        outs: &[Out::Json],
        deviations: &[
            "udp-checksum-ffff",
            "icmp-echo-code-0",
            "rx-checksum-verify",
            "non-tcp-dedup",
            "sctp-tcp-fallthrough",
        ],
    },
];
pub fn case(tag: &str) -> Option<CaseSpec> {
    case_of::<Protocols>(tag)
}
pub fn planned_tags() -> Vec<&'static str> {
    tags_of::<Protocols>()
}
impl CaseSpec {
    /// The case probes SCTP: it needs a host kernel without SCTP.
    pub fn has_sctp(&self) -> bool {
        self.plan_ports.contains("S:")
    }
}

/// One scanner run of a case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepSpec {
    pub name: &'static str,
    pub who: Who,
    pub out: Out,
    pub argv: Vec<String>,
}
/// The scan of a case into `out`: targets, the case's flags, the output flag and file, `--show open,closed` when the
/// case has closed ports, `--seed 1 --rate 100 --wait 3 --source-port 40000`.
pub fn argv(c: &CaseSpec, out: Out) -> Vec<String> {
    let mut a = vec![TARGETS.to_owned()];
    a.extend(c.flags.iter().map(|f| (*f).to_owned()));
    scan_tail(&mut a, out, c.show_closed, RATE, WAIT, SOURCE_PORT);
    a
}
/// The steps of a case, in the order they run; defined here and nowhere else.
pub fn steps(tag: &str) -> Option<Vec<StepSpec>> {
    let c = case(tag)?;
    Some(pair_steps(c.outs, |out, _| argv(&c, out)))
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectStep {
    pub name: String,
    pub who: Who,
    pub out: Out,
}
/// `expect.json`: the case as the suite planned it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtoExpect {
    pub tag: String,
    pub plan_ports: String,
    pub arp: bool,
    pub steps: Vec<ExpectStep>,
}
pub fn expect(tag: &str) -> Option<ProtoExpect> {
    let c = case(tag)?;
    Some(ProtoExpect {
        tag: tag.into(),
        plan_ports: c.plan_ports.into(),
        arp: c.arp,
        steps: expect_steps(&steps(tag)?),
    })
}

/// `manifest.json` as far as this verifier reads it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProtoManifest {
    pub protocols: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lab_id: Option<String>,
}

// ------------------------------------------------------------------ the stand

pub fn stand() -> Stand {
    av::stand(Plan::Linux)
}
/// The responder's options after `capture responder` (its `--ready` aside): the stand's listeners, one UDP socket per
/// peer address and open UDP port, the SCTP answers on the peer link.
pub fn responder_args() -> Vec<String> {
    let list = |p: &[u16]| p.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    let ips = stand()
        .peer_ips
        .iter()
        .map(Ipv4Addr::to_string)
        .collect::<Vec<_>>()
        .join(",");
    vec![
        "--ports".into(),
        list(&TCP_OPEN),
        "--udp-ports".into(),
        list(&UDP_OPEN),
        "--udp-ips".into(),
        ips,
        "--sctp-iface".into(),
        PEER_IF.into(),
        "--sctp-open".into(),
        list(&SCTP_OPEN),
    ]
}
/// `peer-stack.json`: what the peer namespace answers with, read by the suite before the case.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerStack {
    /// `net.ipv4.icmp_ratemask` of the peer namespace (`0`: no ICMP error is rate-limited).
    pub icmp_ratemask: String,
    /// `net.ipv4.icmp_echo_ignore_all` of the peer namespace (`0`: Echo Requests are answered).
    pub icmp_echo_ignore_all: String,
    /// The host kernel has SCTP: `/proc/net/protocols` of the peer namespace lists it.
    pub sctp_in_kernel: bool,
    /// The responder's options ([`responder_args`]).
    pub responder: Vec<String>,
}
/// `<step>/responder.json`: the peer responder of the step as the suite found it the moment the step's scanner
/// ended. The responder never writes to its stderr while it answers; an answerer that fails ends it at once with
/// `NOT RUN: <error>` there and exit 2 (`capture responder`).
///
/// The three fields of its state are `null` while it still ran; otherwise exactly one of them says what the suite
/// found: an exit code, the signal that ended it, or why its state could not be read (no handle of it was held, or
/// `try_wait` failed). Until the final review of the stage all three were one `exited_with: -1`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ResponderRecord {
    /// Its exit code when it had already exited with one.
    pub exited_with: Option<i32>,
    /// The signal that had ended it (Unix: the process exited without a code).
    pub killed_by_signal: Option<i32>,
    /// Why its state is not known: the suite held no handle of it, or `try_wait` failed (with its error).
    pub state_unknown: Option<String>,
    /// What it had written to its stderr by then.
    pub stderr: String,
}
impl ResponderRecord {
    /// What the record says about the responder when it was not running, in words (`it exited with 2`, `it was killed
    /// by signal 9`, `its state is unknown (...)`); `None` while it ran.
    pub fn gone(&self) -> Option<String> {
        if let Some(rc) = self.exited_with {
            return Some(format!("it exited with {rc}"));
        }
        if let Some(sig) = self.killed_by_signal {
            return Some(format!("it was killed by signal {sig}"));
        }
        self.state_unknown
            .as_ref()
            .map(|why| format!("its state is unknown ({why})"))
    }
}
/// Why the peer did not answer the whole step: a responder that was gone, or whose state was unknown, when the
/// scanner ended, named with what the suite found and its own error text; `None` when it ran through the scan.
pub fn responder_problem(rec: &ResponderRecord) -> Option<String> {
    rec.gone().map(|how| {
        let said = rec.stderr.trim();
        format!(
            "the peer responder was not seen running when the scanner ended ({how}): {}",
            if said.is_empty() {
                "it wrote nothing to its stderr"
            } else {
                said
            }
        )
    })
}
/// Why a peer stack cannot answer case `c` the stand's way, or `None`.
pub fn peer_stack_problem(p: &PeerStack, c: &CaseSpec) -> Option<String> {
    if p.icmp_ratemask != "0" {
        return Some(format!(
            "net.ipv4.icmp_ratemask is {} in the peer namespace, not 0 (wire-lab.sh --suite protocols sets it): ICMP errors would be rate-limited",
            p.icmp_ratemask
        ));
    }
    if p.icmp_echo_ignore_all != "0" {
        return Some(format!(
            "net.ipv4.icmp_echo_ignore_all is {} in the peer namespace: Echo Requests would go unanswered",
            p.icmp_echo_ignore_all
        ));
    }
    if p.responder != responder_args() {
        return Some(format!(
            "the responder runs with {:?}, not the stand's {:?}",
            p.responder,
            responder_args()
        ));
    }
    if c.has_sctp() && p.sctp_in_kernel {
        return Some(
            "the host kernel has SCTP (/proc/net/protocols lists it): the peer kernel would answer every INIT with its own ABORT beside the lab responder; unload the sctp module or run on a host without it".into(),
        );
    }
    None
}
/// `/proc/net/protocols` names SCTP.
pub fn lists_sctp(protocols: &str) -> bool {
    protocols.lines().any(|l| {
        l.split_whitespace()
            .next()
            .is_some_and(|n| n.starts_with("SCTP"))
    })
}

// ------------------------------------------------------------------ frames

fn ones(data: &[u8], init: u32) -> u32 {
    let mut sum = init;
    for (i, hi) in data.iter().enumerate().step_by(2) {
        let lo = data.get(i + 1).copied().unwrap_or(0);
        sum += (u32::from(*hi) << 8) + u32::from(lo);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}
/// The one's complement sum of `data` over `init`, inverted: the value a checksum field holds.
fn inet_sum(data: &[u8], init: u32) -> u16 {
    !(ones(data, init) as u16)
}
/// CRC-32C (Castagnoli, reflected, RFC 9260 appendix B) of an SCTP packet with its checksum field read as zeros, in
/// the byte order it has on the wire.
pub fn crc32c_wire(packet: &[u8]) -> [u8; 4] {
    let mut crc = !0u32;
    for (i, b) in packet.iter().enumerate() {
        let b = if (8..12).contains(&i) { 0 } else { *b };
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
        }
    }
    (!crc).to_le_bytes()
}
/// An IPv4 frame without options: the IPv4 total length, when it fits the frame.
fn ipv4(f: &[u8]) -> Option<usize> {
    if f.len() < 34 || f[12..14] != [8, 0] || f[14] != 0x45 {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([f[16], f[17]]));
    (total >= 20 && 14 + total <= f.len()).then_some(total)
}
fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}
fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
fn src(f: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(f[26], f[27], f[28], f[29])
}
fn dst(f: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(f[30], f[31], f[32], f[33])
}
/// The IPv4 header checksum and the transport checksum of an IPv4 frame without options are right (UDP may carry no
/// sum, RFC 768; SCTP carries CRC-32C).
pub fn sums_ok(f: &[u8]) -> bool {
    let Some(total) = ipv4(f) else { return false };
    let seg = &f[34..14 + total];
    let pseudo = |proto: u8| {
        let s = ones(&f[26..34], 0);
        ones(&(seg.len() as u16).to_be_bytes(), ones(&[0, proto], s))
    };
    ones(&f[14..34], 0) == 0xffff
        && match f[23] {
            1 => ones(seg, 0) == 0xffff,
            6 => seg.len() >= 20 && ones(seg, pseudo(6)) == 0xffff,
            17 => seg.len() >= 8 && (seg[6..8] == [0, 0] || ones(seg, pseudo(17)) == 0xffff),
            132 => seg.len() >= 12 && crc32c_wire(seg) == seg[8..12],
            _ => false,
        }
}

/// The peer's answer to an SCTP INIT frame `f` addressed to `own_mac`, built on the link: INIT-ACK when the INIT's
/// destination port is one of `open`, ABORT otherwise. The common header carries the INIT's initiate tag as the
/// verification tag (RFC 9260 §8.4 rule 3, T bit 0, what Linux sends for a port without an endpoint), the ports
/// swapped and the CRC-32C; IPv4 from the INIT's destination back to its source, TTL 64, DF; Ethernet back to the
/// INIT's source. `None` for anything that is not an intact INIT to `own_mac` (wrong CRC included, as a stack drops it).
pub fn sctp_reply(f: &[u8], own_mac: [u8; 6], open: &[u16]) -> Option<Vec<u8>> {
    let total = ipv4(f)?;
    if f[0..6] != own_mac || f[23] != 132 || total < 20 + 12 + 20 || be16(f, 20) & 0x3fff != 0 {
        return None;
    }
    let s = &f[34..14 + total];
    if s[12] != 1 || be32(s, 4) != 0 || crc32c_wire(s) != s[8..12] {
        return None;
    }
    let chunk: Vec<u8> = if open.contains(&be16(s, 2)) {
        let mut c = vec![2, 0, 0, 32];
        c.extend(PEER_INIT_TAG.to_be_bytes());
        c.extend(0x0001_0000_u32.to_be_bytes());
        c.extend(10_u16.to_be_bytes());
        c.extend(10_u16.to_be_bytes());
        c.extend(PEER_TSN.to_be_bytes());
        c.extend([0, 7, 0, 12]);
        c.extend(STATE_COOKIE);
        c
    } else {
        vec![6, 0, 0, 4]
    };
    let mut sctp = Vec::with_capacity(12 + chunk.len());
    sctp.extend(&s[2..4]);
    sctp.extend(&s[0..2]);
    sctp.extend(&s[16..20]);
    sctp.extend([0; 4]);
    sctp.extend(chunk);
    let crc = crc32c_wire(&sctp);
    sctp[8..12].copy_from_slice(&crc);
    let mut out = Vec::with_capacity(34 + sctp.len());
    out.extend(&f[6..12]);
    out.extend(own_mac);
    out.extend([8, 0]);
    out.extend([0x45, 0]);
    out.extend(((20 + sctp.len()) as u16).to_be_bytes());
    out.extend([0, 0, 0x40, 0, 64, 132, 0, 0]);
    out.extend(&f[30..34]);
    out.extend(&f[26..30]);
    let sum = inet_sum(&out[14..34], 0);
    out[24..26].copy_from_slice(&sum.to_be_bytes());
    out.extend(sctp);
    Some(out)
}

/// The protocol of a record or a probe (`name_from_ip_proto`, output.c:75).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proto {
    Arp,
    Icmp,
    Tcp,
    Udp,
    Sctp,
}
impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Arp => "arp",
            Proto::Icmp => "icmp",
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Sctp => "sctp",
        }
    }
    fn number(self) -> u8 {
        match self {
            Proto::Arp => 0,
            Proto::Icmp => 1,
            Proto::Tcp => 6,
            Proto::Udp => 17,
            Proto::Sctp => 132,
        }
    }
    fn from_name(s: &str) -> Option<Proto> {
        [Proto::Arp, Proto::Icmp, Proto::Tcp, Proto::Udp, Proto::Sctp]
            .into_iter()
            .find(|p| p.name() == s)
    }
    fn from_number(n: u8) -> Option<Proto> {
        [Proto::Arp, Proto::Icmp, Proto::Tcp, Proto::Udp, Proto::Sctp]
            .into_iter()
            .find(|p| p.number() == n)
    }
}
/// The status of a record (`status_string`, output.c:103-112).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum St {
    Open,
    Closed,
    Up,
}
impl St {
    pub fn name(self) -> &'static str {
        match self {
            St::Open => "open",
            St::Closed => "closed",
            St::Up => "up",
        }
    }
    fn parse(s: &str) -> Option<St> {
        [St::Open, St::Closed, St::Up]
            .into_iter()
            .find(|x| x.name() == s)
    }
}
/// `reason_string` (output.c:120-150): the TCP flags' names, `none` for 0.
pub fn reason_string(flags: u8) -> String {
    if flags == 0 {
        return "none".into();
    }
    FLAG_NAMES
        .iter()
        .enumerate()
        .filter(|(i, _)| flags & (1 << i) != 0)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join("-")
}

/// A probe the scanner put on the wire.
#[derive(Debug, Clone, PartialEq)]
pub struct Probe {
    pub t: f64,
    pub proto: Proto,
    pub ip: Ipv4Addr,
    pub port: u16,
    pub frame: Vec<u8>,
}
impl Probe {
    /// The scanner's own port of a TCP, UDP or SCTP probe.
    fn sport(&self) -> u16 {
        be16(&self.frame, 34)
    }
}
/// A probe of the scanner (`st`'s MAC and address) in frame `f`: a TCP SYN, a UDP datagram, an Echo Request, an SCTP
/// INIT, and in an ARP scan (`arp`) a 42-byte who-has.
pub fn probe_of(t: f64, f: &[u8], st: &Stand, arp: bool) -> Option<Probe> {
    if f.get(6..12) != Some(&st.scanner_mac[..]) {
        return None;
    }
    let probe = |proto, ip, port| {
        Some(Probe {
            t,
            proto,
            ip,
            port,
            frame: f.to_vec(),
        })
    };
    if f.get(12..14) == Some(&[8, 6][..]) {
        let who_has = f.len() == 42
            && f[14..22] == [0, 1, 8, 0, 6, 4, 0, 1]
            && f[22..28] == st.scanner_mac
            && f[28..32] == st.scanner_ip.octets();
        return if arp && who_has {
            probe(Proto::Arp, Ipv4Addr::new(f[38], f[39], f[40], f[41]), 0)
        } else {
            None
        };
    }
    let total = ipv4(f)?;
    if src(f) != st.scanner_ip {
        return None;
    }
    let seg = &f[34..14 + total];
    match (f[23], seg.len()) {
        (6, 20..) if seg[13] == 0x02 => probe(Proto::Tcp, dst(f), be16(seg, 2)),
        (17, 8..) => probe(Proto::Udp, dst(f), be16(seg, 2)),
        (1, 8..) if seg[0] == 8 => probe(Proto::Icmp, dst(f), 0),
        (132, 32..) if seg[12] == 1 => probe(Proto::Sctp, dst(f), be16(seg, 2)),
        _ => None,
    }
}

/// A reply of the peer to one probe, as a scanner reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub t: f64,
    /// The probe it answers (index into [`WireView::probes`]).
    pub probe: usize,
    pub st: St,
    pub proto: Proto,
    pub ip: Ipv4Addr,
    pub port: u16,
    pub reason: String,
    pub ttl: u8,
    pub mac: [u8; 6],
    /// It came as an ICMP 3/3 (C does not deduplicate it).
    pub via_icmp: bool,
    pub frame: Vec<u8>,
}
/// What one frame from the peer is.
enum Peer {
    Reply(Reply),
    /// The peer kernel's ICMP 3/2 for an SCTP INIT (no SCTP in the kernel).
    ProtoUnreachable,
    /// The peer's ARP reply for the default gateway to the scanner's next-hop resolution (a case that is no ARP scan).
    NextHop,
    Unexpected(String),
}
/// The ports and protocol an ICMP error quotes: the probe it answers.
fn quoted(inner: &[u8], st: &Stand, probes: &[Probe]) -> Option<usize> {
    if inner.len() < 28 || inner[0] != 0x45 {
        return None;
    }
    let (s, d) = (
        Ipv4Addr::new(inner[12], inner[13], inner[14], inner[15]),
        Ipv4Addr::new(inner[16], inner[17], inner[18], inner[19]),
    );
    let proto = Proto::from_number(inner[9])?;
    let (sport, dport) = (be16(inner, 20), be16(inner, 22));
    (s == st.scanner_ip)
        .then(|| {
            probes.iter().position(|p| {
                p.proto == proto
                    && p.ip == d
                    && p.port == dport
                    && p.proto != Proto::Icmp
                    && p.sport() == sport
            })
        })
        .flatten()
}
fn answer(t: f64, f: &[u8], st: &Stand, probes: &[Probe]) -> Peer {
    let unexpected = |what: &str| Peer::Unexpected(format!("{what} ({} bytes)", f.len()));
    let mac: [u8; 6] = f[6..12].try_into().unwrap_or_default();
    let reply = |probe: usize, st_: St, reason: String, ttl: u8, via_icmp: bool| {
        let p: &Probe = &probes[probe];
        Peer::Reply(Reply {
            t,
            probe,
            st: st_,
            proto: p.proto,
            ip: p.ip,
            port: p.port,
            reason,
            ttl,
            mac,
            via_icmp,
            frame: f.to_vec(),
        })
    };
    if f.get(12..14) == Some(&[8, 6][..]) {
        let ok = f.len() >= 42
            && f[14..22] == [0, 1, 8, 0, 6, 4, 0, 2]
            && f[38..42] == st.scanner_ip.octets();
        let spa = Ipv4Addr::new(f[28], f[29], f[30], f[31]);
        let arp_scan = probes.iter().any(|p| p.proto == Proto::Arp);
        return match probes
            .iter()
            .position(|p| ok && p.proto == Proto::Arp && p.ip == spa)
        {
            Some(i) => reply(i, St::Up, "none".into(), 0, false),
            None if ok && !arp_scan && spa == GATEWAY => Peer::NextHop,
            None => unexpected("an ARP frame that answers no who-has of the scan"),
        };
    }
    let Some(total) = ipv4(f) else {
        return unexpected("neither IPv4 without options nor ARP");
    };
    let (s, ttl) = (src(f), f[22]);
    if dst(f) != st.scanner_ip {
        return unexpected("IPv4 to an address other than the scanner's");
    }
    let seg = &f[34..14 + total];
    let find = |proto: Proto, port: u16, sport: u16| {
        probes
            .iter()
            .position(|p| p.proto == proto && p.ip == s && p.port == port && p.sport() == sport)
    };
    match (f[23], seg.len()) {
        (6, 20..) => {
            let flags = seg[13];
            let i = find(Proto::Tcp, be16(seg, 0), be16(seg, 2))
                .filter(|i| be32(seg, 8) == be32(&probes[*i].frame, 38).wrapping_add(1));
            match (i, flags & 0x12 == 0x12, flags & 0x04 != 0) {
                (Some(i), true, _) => reply(i, St::Open, reason_string(flags), ttl, false),
                (Some(i), false, true) => reply(i, St::Closed, reason_string(flags), ttl, false),
                _ => unexpected("TCP that answers no SYN of the scan"),
            }
        }
        (17, 8..) => match find(Proto::Udp, be16(seg, 0), be16(seg, 2)) {
            Some(i) => reply(i, St::Open, "none".into(), ttl, false),
            None => unexpected("UDP that answers no datagram of the scan"),
        },
        (1, 8..) if seg[0] == 0 => {
            let i = probes.iter().position(|p| {
                p.proto == Proto::Icmp && p.ip == s && p.frame.get(38..42) == seg.get(4..8)
            });
            match i {
                Some(i) => reply(i, St::Open, "none".into(), ttl, false),
                None => unexpected("an Echo Reply that answers no Echo Request of the scan"),
            }
        }
        (1, 8..) if seg[0] == 3 && seg[1] == 3 => match quoted(&seg[8..], st, probes) {
            Some(i) => reply(i, St::Closed, "none".into(), ttl, true),
            None => unexpected("an ICMP 3/3 that quotes no probe of the scan"),
        },
        (1, 8..) if seg[0] == 3 && seg[1] == 2 => match quoted(&seg[8..], st, probes) {
            Some(i) if probes[i].proto == Proto::Sctp => Peer::ProtoUnreachable,
            _ => unexpected("an ICMP 3/2 that quotes no SCTP INIT of the scan"),
        },
        (132, 16..) => {
            let i = find(Proto::Sctp, be16(seg, 0), be16(seg, 2))
                .filter(|i| probes[*i].frame.get(50..54) == seg.get(4..8));
            match (i, seg[12]) {
                (Some(i), 2) => reply(i, St::Open, "none".into(), ttl, false),
                (Some(i), 6) => reply(i, St::Closed, "none".into(), ttl, false),
                _ => unexpected("SCTP that answers no INIT of the scan with INIT-ACK or ABORT"),
            }
        }
        _ => unexpected("a frame of no protocol the stand answers with"),
    }
}

/// One capture of one step, taken apart.
#[derive(Debug, Default)]
pub struct WireView {
    pub probes: Vec<Probe>,
    pub replies: Vec<Reply>,
    /// The peer kernel's ICMP 3/2 for SCTP INITs.
    pub proto_unreachable: usize,
    /// The peer's ARP replies to the next-hop resolution of a scan that is no ARP scan.
    pub next_hop_replies: usize,
    /// Frames of the scanner MAC that are no probe and belong to one of [`SCANNER_CLASSES`], by its key.
    pub scanner_named: BTreeMap<&'static str, usize>,
    /// Every other frame of the scanner MAC that is no probe: the scanner's own extra frames, described.
    pub scanner_unexplained: Vec<String>,
    /// ARP requests of the scanner MAC that are no probe (the next-hop who-has among them).
    pub arp_requests_not_probes: usize,
    /// Frames of the peer MAC that answer nothing the scan sent.
    pub peer_unexpected: Vec<String>,
    /// Probes or replies outside the witness window (last start marker .. first end marker).
    pub outside_window: usize,
}
impl WireView {
    pub fn probe_frames(&self) -> Vec<Vec<u8>> {
        self.probes.iter().map(|p| p.frame.clone()).collect()
    }
    fn arp_requests(&self) -> usize {
        self.probes.iter().filter(|p| p.proto == Proto::Arp).count() + self.arp_requests_not_probes
    }
}

impl pair_verify::StepView for WireView {
    fn probe_frames(&self) -> Vec<Vec<u8>> {
        WireView::probe_frames(self)
    }
}
/// The frames of the scanner MAC that are no probe of the scan and that the stand makes the scanner side send: the
/// key they are counted under in the notes, and what they are. Any other frame of the scanner MAC is the scanner's own
/// extra frame: a FAIL on rmasscan's step, INVALID on the oracle's.
pub const SCANNER_CLASSES: [(&str, &str); 4] = [
    (
        "next_hop_who_has",
        "the scanner's next-hop resolution: an ARP who-has 198.18.0.2 from 198.18.0.1, 60 bytes zero-padded (the resolver form of C stack-arpv4.c and rmasscan), in a scan that is no ARP scan",
    ),
    (
        "rst_to_syn_ack",
        "a TCP RST (no other flag) from 198.18.0.1 whose sequence number is the acknowledgment of a SYN-ACK of the stand: the scanner namespace kernel resets a SYN-ACK no socket owns (198.18.0.1 is its address), and C resets each distinct SYN-ACK itself once it passed its dedup (main.c:1067-1068 then main.c:1095)",
    ),
    (
        "port_unreachable_to_udp_reply",
        "an ICMP 3/3 from 198.18.0.1 quoting a UDP reply of the stand: the scanner namespace kernel, no socket on the source port",
    ),
    (
        "protocol_unreachable_to_sctp_reply",
        "an ICMP 3/2 from 198.18.0.1 quoting an SCTP INIT-ACK or ABORT of the stand: the scanner namespace kernel, no SCTP",
    ),
];
/// The most next-hop who-has rmasscan's resolver sends before it gives up: one per `ARP_INTERVAL` while less than
/// `ARP_TIMEOUT` has passed (rmasscan-net `arp_resolve.rs`, `resolve_next_hop_until`: t = 0..9 s, 10 requests).
pub const NEXT_HOP_WHO_HAS_MAX_RMASSCAN: usize = (rmasscan_net::arp_resolve::ARP_TIMEOUT.as_secs()
    / rmasscan_net::arp_resolve::ARP_INTERVAL.as_secs())
    as usize;
/// The most next-hop who-has C's resolver sends: one at the start, one more each time the second changes, and it
/// stops after the eleventh of those (`stack_arp_resolve`, stack-arpv4.c:175-187: `if (i++ >= 10) break` after the
/// send), 12 requests.
pub const NEXT_HOP_WHO_HAS_MAX_C: usize = 12;
/// How many frames of each [`SCANNER_CLASSES`] entry a step may hold, from what its scanner side can send for the
/// stand's replies on the same wire: one kernel reset per SYN-ACK frame (the scanner namespace kernel resets every
/// SYN-ACK frame; rmasscan has no RST path), plus on the oracle's step one `tcp_send_RST` of C per distinct SYN-ACK
/// (C resets only a reply that passed its dedup, main.c:1067-1068 then :1095, so a repeated SYN-ACK gets the
/// kernel's reset and no second one of C's), the resolver's request count ([`NEXT_HOP_WHO_HAS_MAX_RMASSCAN`],
/// [`NEXT_HOP_WHO_HAS_MAX_C`]), and one kernel ICMP error per UDP or SCTP reply frame (neither scanner sends one
/// itself). `(class, count, at most)` in [`SCANNER_CLASSES`] order.
pub fn scanner_bounds(v: &WireView, who: Who) -> [(&'static str, usize, usize); 4] {
    let replies = |proto: Proto, st: Option<St>| {
        v.replies
            .iter()
            .filter(|r| r.proto == proto && !r.via_icmp && st.is_none_or(|s| r.st == s))
            .count()
    };
    // C's dedup key is (ip_them, port_them, ip_me, port_me) (main.c:1067); on the stand ip_me and port_me are fixed.
    let distinct_syn_acks = v
        .replies
        .iter()
        .filter(|r| r.proto == Proto::Tcp && !r.via_icmp && r.st == St::Open)
        .map(|r| (r.ip, r.port))
        .collect::<BTreeSet<_>>()
        .len();
    let (c_resets, who_has) = match who {
        Who::Rmasscan => (0, NEXT_HOP_WHO_HAS_MAX_RMASSCAN),
        Who::Oracle => (distinct_syn_acks, NEXT_HOP_WHO_HAS_MAX_C),
    };
    let max = [
        who_has,
        replies(Proto::Tcp, Some(St::Open)) + c_resets,
        replies(Proto::Udp, None),
        replies(Proto::Sctp, None),
    ];
    let mut out = [("", 0, 0); 4];
    for (i, (k, _)) in SCANNER_CLASSES.iter().enumerate() {
        out[i] = (*k, v.scanner_named.get(k).copied().unwrap_or(0), max[i]);
    }
    out
}
/// The scanner's next-hop who-has for the default gateway, in its resolver form.
fn next_hop_who_has(f: &[u8], st: &Stand) -> bool {
    av::resolver_request(f) && f[28..32] == st.scanner_ip.octets() && f[38..42] == GATEWAY.octets()
}
/// What a frame of the scanner MAC that is no probe is: the key of its [`SCANNER_CLASSES`] entry, when it answers a
/// reply of the stand (`replies`) the way the scanner side does, or what it is otherwise.
fn scanner_frame(
    f: &[u8],
    st: &Stand,
    arp: bool,
    replies: &[Reply],
) -> Result<&'static str, String> {
    if f.get(12..14) == Some(&[8, 6][..]) {
        return match (next_hop_who_has(f, st), arp) {
            (true, false) => Ok(SCANNER_CLASSES[0].0),
            (true, true) => Err(
                "the next-hop who-has 198.18.0.2 in an ARP scan (its router MAC is given)".into(),
            ),
            _ => Err(describe(f)),
        };
    }
    if ipv4(f).is_none() || src(f) != st.scanner_ip {
        return Err(describe(f));
    }
    if av::is_reset(f) {
        let answers = verify::tcp(f).is_some_and(|t| {
            t.flags == 0x04
                && replies.iter().any(|r| {
                    r.proto == Proto::Tcp
                        && r.st == St::Open
                        && !r.via_icmp
                        && src(&r.frame) == dst(f)
                        && verify::tcp(&r.frame)
                            .is_some_and(|y| (y.sp, y.dp, y.ack) == (t.dp, t.sp, t.seq))
                })
        });
        return if answers {
            Ok(SCANNER_CLASSES[1].0)
        } else {
            Err(format!(
                "{}, which resets no SYN-ACK of the stand",
                describe(f)
            ))
        };
    }
    if f[23] == 1 && f.get(34) == Some(&3) {
        // The quoted IPv4 header and ports: the reply's own, as the stand sent it.
        let quotes = |proto: Proto| {
            f.get(42..66).is_some_and(|q| {
                q[0] == 0x45
                    && replies.iter().any(|r| {
                        r.proto == proto
                            && !r.via_icmp
                            && r.frame.get(23) == Some(&q[9])
                            && r.frame.get(26..34) == Some(&q[12..20])
                            && r.frame.get(34..38) == Some(&q[20..24])
                    })
            })
        };
        match f[35] {
            3 if quotes(Proto::Udp) => return Ok(SCANNER_CLASSES[2].0),
            2 if quotes(Proto::Sctp) => return Ok(SCANNER_CLASSES[3].0),
            _ => {}
        }
        return Err(format!(
            "{}, which quotes no UDP (3/3) or SCTP (3/2) reply of the stand",
            describe(f)
        ));
    }
    Err(describe(f))
}
/// A frame in a few words, for the detail of a check.
fn describe(f: &[u8]) -> String {
    let b = |i: usize| f.get(i).copied().unwrap_or(0);
    let port = u16::from_be_bytes([b(36), b(37)]);
    if f.get(12..14) == Some(&[8, 6][..]) {
        return format!(
            "an ARP frame of {} bytes, operation {}, for {}",
            f.len(),
            u16::from_be_bytes([b(20), b(21)]),
            Ipv4Addr::new(b(38), b(39), b(40), b(41))
        );
    }
    if ipv4(f).is_none() {
        return format!(
            "a {}-byte frame of ethertype {:02x}{:02x}",
            f.len(),
            b(12),
            b(13)
        );
    }
    let to = format!("{} > {}", src(f), dst(f));
    match f[23] {
        6 => format!("TCP flags {:#04x} {to}:{port}", b(47)),
        17 => format!("UDP {to}:{port}"),
        1 => format!("ICMP {}/{} {to}", b(34), b(35)),
        132 => format!("SCTP chunk type {} {to}:{port}", b(46)),
        p => format!("IPv4 protocol {p} {to}"),
    }
}
pub fn view(fr: &Frames, st: &Stand, arp: bool) -> WireView {
    let w = av::classify(fr, st.scanner_mac);
    let (start, end) = av::window(&w);
    let mut v = WireView::default();
    // The scanner MAC's frames that are no probe, judged once every reply of the capture is known.
    let mut mine: Vec<&Vec<u8>> = Vec::new();
    let marker = |f: &[u8]| f.get(12..14) == Some(&crate::link::MARKER_ETHERTYPE[..]);
    for (t, f) in fr {
        if marker(f) {
            continue;
        }
        if let Some(p) = probe_of(*t, f, st, arp) {
            v.outside_window += usize::from(!(start..=end).contains(t));
            v.probes.push(p);
            continue;
        }
        if f.get(6..12) == Some(&st.scanner_mac[..]) {
            mine.push(f);
            continue;
        }
        if f.get(6..12) == Some(&st.peer_mac[..]) {
            match answer(*t, f, st, &v.probes) {
                Peer::Reply(r) => {
                    v.outside_window += usize::from(!(start..=end).contains(t));
                    v.replies.push(r);
                }
                Peer::ProtoUnreachable => v.proto_unreachable += 1,
                Peer::NextHop => v.next_hop_replies += 1,
                Peer::Unexpected(why) => v.peer_unexpected.push(why),
            }
        }
    }
    for f in mine {
        if f.get(12..14) == Some(&[8, 6][..]) && f.get(20..22) == Some(&[0, 1][..]) {
            v.arp_requests_not_probes += 1;
        }
        match scanner_frame(f, st, arp, &v.replies) {
            Ok(key) => *v.scanner_named.entry(key).or_insert(0) += 1,
            Err(what) => v.scanner_unexplained.push(what),
        }
    }
    v
}
/// Probes or ICMP errors of the scanner MAC to an address off the stand, or from an address other than the
/// scanner's: a safety finding.
pub fn foreign_probes(fr: &Frames, st: &Stand) -> Vec<String> {
    let mut out = Vec::new();
    for (_, f) in fr {
        if f.get(6..12) != Some(&st.scanner_mac[..]) {
            continue;
        }
        if f.get(12..14) == Some(&[8, 6][..]) && f.len() >= 42 && f[20..22] == [0, 1] {
            let tpa = Ipv4Addr::new(f[38], f[39], f[40], f[41]);
            if !st.peer_ips.contains(&tpa) || f[28..32] != st.scanner_ip.octets() {
                out.push(format!("ARP who-has {tpa}"));
            }
        } else if ipv4(f).is_some()
            && [1, 6, 17, 132].contains(&f[23])
            && (src(f) != st.scanner_ip || !st.peer_ips.contains(&dst(f)))
        {
            out.push(format!("IPv4 {} > {} proto {}", src(f), dst(f), f[23]));
        }
    }
    out
}

// ------------------------------------------------------------------ the plan

/// The probes the case must put on the wire, in send order, from the product's own plan (`ReadyPlan::new_cli` and its
/// cursor): the stand's binding, `--seed 1`, `--source-port 40000`, the case's ports (an ARP scan's next hop is the
/// broadcast MAC).
pub fn plan_stream(c: &CaseSpec) -> Result<Vec<Vec<u8>>, String> {
    let st = stand();
    let router = if c.arp { [0xff; 6] } else { st.peer_mac };
    let binding = AdapterBinding {
        interface_id: st.iface.into(),
        link_type: LinkType::Ethernet,
        source_ipv4: u32::from(st.scanner_ip),
        source_mac: st.scanner_mac,
        next_hop_mac: router,
        source_ports: (SOURCE_PORT, SOURCE_PORT),
    };
    let mut ips = MassIp::new();
    add_target_string(ips.ipv4_mut(), TARGETS).map_err(|e| e.to_string())?;
    parse_ports(ips.ports_mut(), c.plan_ports).map_err(|e| e.to_string())?;
    let cfg = ScanConfig {
        targets: ips,
        seed: 1,
        max_rate: parse_rate(RATE).map_err(|e| e.to_string())?,
        wait_secs: 3,
        adapter_ip: Some(binding.source_ipv4),
        adapter_mac: Some(binding.source_mac),
        router_mac: Some(router),
        source_port: Some(binding.source_ports),
        adapter_name: Some(binding.interface_id.clone()),
        arpscan: c.arp,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).map_err(|e| e.to_string())?;
    let plan =
        ReadyPlan::new_cli(eff, vec![NicBinding::from(binding)]).map_err(|e| e.to_string())?;
    Ok(plan_probes(&plan)?.0)
}

/// rmasscan's probe `rm` and C's probe `c` are the same probe: equal, or (R12) two UDP datagrams that differ only in a
/// checksum that is 0xFFFF in rmasscan's, a valid sum there (one that computes to zero), and 0x0000 in C's.
/// `Some(true)` when R12 made them equal.
pub fn same_probe(rm: &[u8], c: &[u8]) -> Option<bool> {
    if rm == c {
        return Some(false);
    }
    let at = 34 + 6;
    let r12 = rm.len() == c.len()
        && ipv4(rm).is_some()
        && rm[23] == 17
        && rm.get(at..at + 2) == Some(&[0xff, 0xff][..])
        && c.get(at..at + 2) == Some(&[0, 0][..])
        && rm[..at] == c[..at]
        && rm[at + 2..] == c[at + 2..]
        && sums_ok(rm);
    r12.then_some(true)
}

// ------------------------------------------------------------------ the documents

/// One record of a document, as far as its format carries it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rec {
    pub st: St,
    pub proto: Proto,
    pub ip: Ipv4Addr,
    pub port: u16,
    pub reason: Option<String>,
    pub ttl: Option<u8>,
    pub mac: Option<[u8; 6]>,
    pub ts: Option<u64>,
}
impl Rec {
    /// What two correct scanners agree on: everything but the time.
    pub fn bare(&self) -> Rec {
        Rec {
            ts: None,
            ..self.clone()
        }
    }
    /// The record of a wire reply, in the fields `out` carries.
    fn of(r: &Reply, out: Out) -> Rec {
        let full = Rec {
            st: r.st,
            proto: r.proto,
            ip: r.ip,
            port: r.port,
            reason: Some(r.reason.clone()),
            ttl: Some(r.ttl),
            mac: (r.proto == Proto::Arp).then_some(r.mac),
            ts: None,
        };
        match out {
            Out::List => Rec {
                reason: None,
                ttl: None,
                mac: None,
                ..full
            },
            Out::Json | Out::Binary => Rec { mac: None, ..full },
            Out::Stdout => Rec {
                reason: None,
                ttl: None,
                ..full
            },
        }
    }
    fn show(&self) -> String {
        let mut s = format!(
            "{} {} {}/{}",
            self.st.name(),
            self.ip,
            self.port,
            self.proto.name()
        );
        if let Some(r) = &self.reason {
            s.push_str(&format!(" reason {r}"));
        }
        if let Some(t) = self.ttl {
            s.push_str(&format!(" ttl {t}"));
        }
        if let Some(m) = self.mac {
            s.push_str(&format!(" mac {}", crate::autodetect_suite::colon(m)));
        }
        s
    }
}
/// A document taken apart.
pub type Document = Doc<Rec>;
impl Record for Rec {
    fn ts(&self) -> Option<u64> {
        self.ts
    }
}

pub(crate) const LIST_REC: &str = "@ @ @ @ @";
pub(crate) const JSON_REC: &str = "{   \"ip\": \"@\",   \"timestamp\": \"@\", \"ports\": [ {\"port\": @, \"proto\": \"@\", \"status\": \"@\", \"reason\": \"@\", \"ttl\": @} ] }";

fn field_rec(
    st: &str,
    proto: &str,
    ip: &str,
    port: &str,
    ts: &str,
    reason: Option<&str>,
    ttl: Option<&str>,
) -> Result<Rec, String> {
    Ok(Rec {
        st: St::parse(st).ok_or(format!("status {st:?}"))?,
        proto: Proto::from_name(proto).ok_or(format!("protocol {proto:?}"))?,
        ip: canon(ip).ok_or(format!("address {ip:?}"))?,
        port: canon(port).ok_or(format!("port {port:?}"))?,
        reason: reason.map(str::to_owned),
        ttl: ttl
            .map(|t| canon::<u8>(t).ok_or(format!("ttl {t:?}")))
            .transpose()?,
        mac: None,
        ts: Some(canon(ts).ok_or(format!("time {ts:?}"))?),
    })
}
/// `Discovered %s port %u/%s on %s`, an ARP record with ` (%02x:..) %s` (output.c:766-790), padded with spaces to 79
/// characters when shorter.
fn stdout_rec(line: &str) -> Result<Rec, String> {
    let text = line.trim_end_matches(' ');
    if text.len() < 79 && line.len() != 79 || text.len() >= 79 && line.len() != text.len() {
        return Err("not padded to 79 characters the way C pads it".into());
    }
    let (head, mac) = match text.split_once(" (") {
        Some((h, rest)) => {
            let m = rest.split(')').next().unwrap_or("");
            let mac = crate::link::parse_mac(m).map_err(|e| e.to_string())?;
            (h, Some(mac))
        }
        None => (text, None),
    };
    let f = fields("Discovered @ port @/@ on @", head).ok_or("not the Discovered form")?;
    let mut r = field_rec(f[0], f[2], f[3], f[1], "0", None, None)?;
    r.ts = None;
    r.mac = mac;
    if (r.proto == Proto::Arp) != mac.is_some() {
        return Err("a MAC on a record that is not ARP, or an ARP record without one".into());
    }
    Ok(r)
}
fn binary_rec(b: &[u8]) -> Result<Rec, String> {
    let st = match (b[0], b[1], b[10]) {
        (6, 13, 1 | 6 | 17 | 132) => St::Open,
        (7, 13, 1 | 6 | 17 | 132) => St::Closed,
        (8, 13, 0) => St::Up,
        _ => return Err(format!("not a status record: {}", verify::hex(b))),
    };
    Ok(Rec {
        st,
        proto: Proto::from_number(b[10]).ok_or("protocol")?,
        ip: Ipv4Addr::new(b[6], b[7], b[8], b[9]),
        port: be16(b, 11),
        reason: Some(reason_string(b[13])),
        ttl: Some(b[14]),
        mac: None,
        ts: Some(u64::from(be32(b, 2))),
    })
}
/// A document of `out` in its C form (`out-text.c`, `out-json.c`, `out-binary.c`, output.c's interactive lines): an
/// empty file is a document without a record; a file that stops after a record, without its footer, is not `complete`;
/// any other malformation is an error.
pub fn parse_doc(out: Out, b: &[u8]) -> Result<Document, String> {
    parse_doc_with(out, b, field_rec, |b, d| {
        if out == Out::Stdout {
            let lines = text_lines(b, "\n")?;
            d.records = each(&lines, stdout_rec)?;
            d.complete = true;
            return Ok(());
        }
        if b.len() < BINARY_BLOCK || !b.starts_with(b"masscan/1.1\ns:") {
            return Err("not the 99-byte `masscan/1.1` header".into());
        }
        let rest = &b[BINARY_BLOCK..];
        let mut foot = [0u8; BINARY_BLOCK];
        foot[..11].copy_from_slice(b"masscan/1.1");
        let body = if rest.len() >= BINARY_BLOCK
            && rest.ends_with(&foot)
            && (rest.len() - BINARY_BLOCK).is_multiple_of(BINARY_REC)
        {
            d.complete = true;
            &rest[..rest.len() - BINARY_BLOCK]
        } else if rest.len().is_multiple_of(BINARY_REC) {
            rest
        } else {
            return Err(format!("{} bytes are not 99 + 15n (+ 99)", b.len()));
        };
        d.records = body
            .chunks(BINARY_REC)
            .map(binary_rec)
            .collect::<Result<_, _>>()?;
        Ok(())
    })
}

/// The records a scanner reports for the replies of its wire, in reply order: rmasscan once per (protocol, address,
/// port, status); C once per (protocol, address, port) for TCP, Echo and ARP (its dedup tables, main.c:899,
/// proto-icmp.c:126) and once per reply otherwise (`non-tcp-dedup`). `show_closed`: closed records are written.
pub fn wire_records(v: &WireView, who: Who, out: Out, show_closed: bool) -> Vec<Rec> {
    wire_records_at(v, who, out, show_closed)
        .into_iter()
        .map(|(r, _)| r)
        .collect()
}
/// [`wire_records`] with the capture time of the reply each record comes from.
pub fn wire_records_at(v: &WireView, who: Who, out: Out, show_closed: bool) -> Vec<(Rec, f64)> {
    let mut seen = BTreeSet::new();
    let mut recs = Vec::new();
    for r in &v.replies {
        let key = match who {
            Who::Rmasscan => Some((r.proto, r.ip, r.port, Some(r.st))),
            Who::Oracle => {
                let deduped = (r.proto == Proto::Tcp && !r.via_icmp)
                    || (r.proto == Proto::Icmp && r.st == St::Open)
                    || r.proto == Proto::Arp;
                deduped.then_some((r.proto, r.ip, r.port, None))
            }
        };
        if key.is_some_and(|k| !seen.insert(k)) {
            continue;
        }
        if r.st == St::Closed && !show_closed {
            continue;
        }
        recs.push((Rec::of(r, out), r.t));
    }
    recs
}
/// How far apart, in microseconds, two replies on the peer capture may be and still reach the scanner in the other
/// order; a pair exactly this far apart is inside. The witness records the peer link; the peer kernel (TCP, ICMP) and
/// the responder's threads (one per UDP socket, one for the SCTP link) send from different CPUs, and two frames a few
/// microseconds apart on the peer link can be delivered to the scanner's socket in the other order (live
/// linux-protocols-r2 on 5661a6e: 5 us; r3 on 0ed6e36: 7 us). Until the final review of the stage the window was
/// 1 ms, which inside a burst (neighbouring probes up to about 0.25 ms apart) let almost any order through; 50 us
/// admits that cross-CPU race and not the reordering of a burst's replies by a scanner's writer. The gap is measured on
/// the capture and rounded to the microsecond ([`reply_gap_us`]).
pub const REPLY_REORDER_WINDOW_US: u64 = 50;
/// The gap between two capture times in whole microseconds, rounded: the witness writes nanoseconds, the generator
/// microseconds, and a capture time near 1.8e9 s carries about a quarter of a microsecond of `f64` error, so rounding
/// makes the window's edge exact.
pub fn reply_gap_us(a: f64, b: f64) -> u64 {
    ((a - b).abs() * 1e6).round() as u64
}
/// The pairs of records a document wrote in the other order than their replies on the wire, all within
/// [`REPLY_REORDER_WINDOW_US`]: how many, and the largest gap among them (`None` without such a pair).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Swaps {
    pub pairs: usize,
    pub largest_gap_us: Option<u64>,
}
/// `got` (a document's records, time aside) holds exactly the records `want` (the wire's, in reply order, each with
/// its reply's capture time), in reply order up to records whose replies were captured at most
/// [`REPLY_REORDER_WINDOW_US`] apart. `Ok`: the pairs in the other order ([`Swaps`]); `Err`: the difference.
/// Generic over the record type: the IPv6 verifier judges its own records (`ipv6_verify::Rec`) with the same rule.
pub fn in_reply_order<R: Clone + PartialEq + Shown>(
    got: &[R],
    want: &[(R, f64)],
) -> Result<Swaps, String> {
    let plain: Vec<R> = want.iter().map(|(r, _)| r.clone()).collect();
    if got.len() != want.len() {
        return Err(first_difference(got, &plain));
    }
    // Each record onto the earliest reply of its fields not taken yet (identical records are interchangeable).
    let mut taken = vec![false; want.len()];
    let mut at = Vec::with_capacity(got.len());
    for g in got {
        match (0..want.len()).find(|&j| !taken[j] && want[j].0 == *g) {
            Some(j) => {
                taken[j] = true;
                at.push(j);
            }
            None => return Err(first_difference(got, &plain)),
        }
    }
    let mut swaps = Swaps::default();
    for i in 0..at.len() {
        for k in i + 1..at.len() {
            if at[i] < at[k] {
                continue;
            }
            let gap = reply_gap_us(want[at[i]].1, want[at[k]].1);
            if gap > REPLY_REORDER_WINDOW_US {
                return Err(format!(
                    "record {i} ({}) is written before record {k} ({}), whose reply came first on the wire, {gap} us apart (more than {REPLY_REORDER_WINDOW_US} us); in reply order: {}",
                    got[i].show(),
                    got[k].show(),
                    shown(&plain)
                ));
            }
            swaps.pairs += 1;
            swaps.largest_gap_us = Some(swaps.largest_gap_us.map_or(gap, |g| g.max(gap)));
        }
    }
    Ok(swaps)
}
/// C's records with its repeated UDP and SCTP records collapsed the way rmasscan reports them (`non-tcp-dedup`, when
/// the case applies it): what rmasscan's document must equal. Those are the records C prints once per reply (a UDP
/// reply, the ICMP 3/3 of a UDP probe, an INIT-ACK or ABORT); TCP, Echo and ARP records C deduplicates itself, so a
/// repeat of one is never collapsed. The number collapsed.
pub fn collapse(c: &[Rec], non_tcp_dedup: bool) -> (Vec<Rec>, usize) {
    let mut seen = BTreeSet::new();
    let kept: Vec<Rec> = c
        .iter()
        .filter(|r| {
            !(non_tcp_dedup && matches!(r.proto, Proto::Udp | Proto::Sctp))
                || seen.insert((r.proto, r.ip, r.port, r.st))
        })
        .map(Rec::bare)
        .collect();
    let n = c.len() - kept.len();
    (kept, n)
}

// ------------------------------------------------------------------ checks

/// A record in a few words, for the detail of a check ([`in_reply_order`], [`first_difference`]).
pub trait Shown {
    fn show(&self) -> String;
}
impl Shown for Rec {
    fn show(&self) -> String {
        Rec::show(self)
    }
}
pub(crate) fn shown<R: Shown>(recs: &[R]) -> String {
    recs.iter().map(Shown::show).collect::<Vec<_>>().join("; ")
}
/// Where two record lists first differ.
pub(crate) fn first_difference<R: PartialEq + Shown>(got: &[R], want: &[R]) -> String {
    let at = got.iter().zip(want).position(|(a, b)| a != b);
    let show = |x: Option<&R>| x.map_or("<none>".to_owned(), Shown::show);
    let i = at.unwrap_or(got.len().min(want.len()));
    format!(
        "{} records, {} wanted; first difference at {i}: {} vs {}",
        got.len(),
        want.len(),
        show(got.get(i)),
        show(want.get(i))
    )
}

/// The stand owes every probe exactly one answer of a known form; anything else on the peer side, or an answer of
/// another form, is a stand that did not behave (INVALID for both scanners).
fn stand_answers(r: &mut Run, s: &Side<WireView>, v: &WireView) {
    let st = stand();
    let mut problems = Vec::new();
    for (i, p) in v.probes.iter().enumerate() {
        let answers: Vec<&Reply> = v.replies.iter().filter(|x| x.probe == i).collect();
        let want = match p.proto {
            Proto::Tcp if TCP_OPEN.contains(&p.port) => St::Open,
            Proto::Udp if UDP_OPEN.contains(&p.port) => St::Open,
            Proto::Sctp if SCTP_OPEN.contains(&p.port) => St::Open,
            Proto::Tcp | Proto::Udp | Proto::Sctp => St::Closed,
            Proto::Icmp => St::Open,
            Proto::Arp => St::Up,
        };
        // The peer kernel may repeat a SYN-ACK (the same reply again, one status); every other answer comes once.
        let count_ok = if p.proto == Proto::Tcp {
            !answers.is_empty()
        } else {
            answers.len() == 1
        };
        let form_ok = answers.iter().all(|a| match a.proto {
            Proto::Udp if a.st == St::Open => {
                ipv4(&a.frame).is_some_and(|total| a.frame.get(42..14 + total) == Some(UDP_REPLY))
            }
            Proto::Sctp => {
                sctp_reply(&p.frame, st.peer_mac, &SCTP_OPEN).as_deref() == Some(&a.frame[..])
            }
            Proto::Arp => a.mac == st.peer_mac,
            _ => true,
        });
        if !count_ok || answers.iter().any(|a| a.st != want) || !form_ok {
            problems.push(format!(
                "{} {}/{}: {} answers ({:?}), want one {}",
                p.ip,
                p.port,
                p.proto.name(),
                answers.len(),
                answers.iter().map(|a| a.st.name()).collect::<Vec<_>>(),
                want.name()
            ));
        }
    }
    r.inv(
        &format!(
            "{}: the stand answered every probe exactly once, the stand's way (TCP 80/8080, UDP 53/161, SCTP 2905 open, the rest closed; Echo and ARP answered)",
            s.spec.name
        ),
        problems.is_empty(),
        problems.iter().take(4).cloned().collect::<Vec<_>>().join("; "),
    );
    r.inv(
        &format!(
            "{}: nothing on the peer side answers anything the scan did not send",
            s.spec.name
        ),
        v.peer_unexpected.is_empty(),
        v.peer_unexpected
            .iter()
            .take(4)
            .cloned()
            .collect::<Vec<_>>()
            .join("; "),
    );
    r.inv(
        &format!(
            "{}: every probe and reply lies inside the witness window",
            s.spec.name
        ),
        v.outside_window == 0,
        v.outside_window,
    );
}

/// What the `[+]` lines of a rmasscan step must say: the stand's interface, MAC and address detected, the next hop by
/// the route and ARP (an ARP scan: the broadcast MAC as given, no next-hop resolution), seed 1 and port 40000 given.
pub(crate) fn detection(r: &mut Run, s: &Side<WireView>, c: &CaseSpec) {
    let get = |k: &str| s.se.value(k).map(str::to_owned);
    let keys: Vec<&str> = s.se.plus.iter().map(|(k, _)| k.as_str()).collect();
    let common = get("interface").as_deref() == Some("veth-a (detected: route to 198.18.0.2)")
        && get("source-mac").as_deref() == Some("02-aa-00-00-00-01 (detected)")
        && get("source-ip").as_deref() == Some("198.18.0.1 (detected)")
        && get("seed").as_deref() == Some("1 (given)")
        && get("source-port").as_deref() == Some("40000 (given)");
    let (ok, want) = if c.arp {
        (
            common
                && keys
                    == [
                        "interface",
                        "source-mac",
                        "source-ip",
                        "router-mac",
                        "seed",
                        "source-port",
                    ]
                && get("router-mac").as_deref() == Some("ff-ff-ff-ff-ff-ff (given)"),
            "veth-a by the route, its MAC and IP, router-mac ff-ff-ff-ff-ff-ff given (no next-hop ARP), seed 1 and source port 40000 given",
        )
    } else {
        (
            common
                && keys
                    == [
                        "interface",
                        "source-mac",
                        "source-ip",
                        "router-ip",
                        "router-mac",
                        "seed",
                        "source-port",
                    ]
                && get("router-ip").as_deref() == Some("198.18.0.2 (interface default gateway)")
                && get("router-mac").is_some_and(|m| m.starts_with("02-aa-00-00-00-02 (arp: ")),
            "veth-a by the route, its MAC and IP, router 198.18.0.2 by ARP, seed 1 and source port 40000 given",
        )
    };
    beh(
        r,
        s,
        &format!("[+] lines are the stand's: {want}"),
        ok,
        format!("{:?}", s.se.plus),
    );
}

/// A rmasscan step: exit, stdout, stderr grammar, `[+] finished` against the wire and the records.
fn rmasscan_step(r: &mut Run, s: &Side<WireView>, c: &CaseSpec, doc: Option<&Document>) {
    pair_verify::rmasscan_step(
        r,
        s,
        doc,
        |r, s| detection(r, s, c),
        |v| {
            let all = wire_records(v, Who::Rmasscan, Out::Json, true);
            let open = all.iter().filter(|x| x.st == St::Open).count() as u64;
            WireSummary {
                counts: (v.probes.len() as u64, all.len() as u64, open),
                first_probe: v.probes.first().map(|p| p.t),
                last_reply: v.replies.last().map(|p| p.t),
            }
        },
    );
}

/// Each named deviation of the case: the wire condition that keeps it from changing the comparison, and the notes.
fn deviations(r: &mut Run, c: &CaseSpec, sides: &[Side<WireView>], r12: usize, collapsed: usize) {
    named_deviations(r, c.deviations, &DEVIATIONS, |name| {
        let replies = || {
            sides
                .iter()
                .filter_map(|s| s.view.as_ref())
                .flat_map(|v| &v.replies)
        };
        match name {
            "udp-checksum-ffff" => (true, format!("{r12} probe pairs equal by this rule")),
            "icmp-echo-code-0" => {
                let bad = replies()
                    .filter(|x| {
                        x.proto == Proto::Icmp && x.st == St::Open && x.frame.get(35) != Some(&0)
                    })
                    .count();
                (
                    bad == 0,
                    format!("{bad} Echo Replies with a code other than 0"),
                )
            }
            "rx-checksum-verify" => {
                let bad = replies()
                    .filter(|x| x.proto != Proto::Arp && !sums_ok(&x.frame))
                    .count();
                (bad == 0, format!("{bad} replies with a wrong sum"))
            }
            "non-tcp-dedup" => (
                true,
                format!("{collapsed} repeated UDP and SCTP records of C collapsed"),
            ),
            "sctp-tcp-fallthrough" => {
                let bad = replies()
                    .filter(|x| x.proto == Proto::Sctp)
                    .filter(|x| {
                        let fl = x.frame.get(47).copied().unwrap_or(0);
                        fl & 0x12 == 0x12 || fl & 0x04 != 0
                    })
                    .count();
                (
                    bad == 0,
                    format!("{bad} SCTP replies whose chunk flags read as SYN-ACK or RST"),
                )
            }
            "arp-mac-ethernet-source" => {
                let bad = replies()
                    .filter(|x| x.proto == Proto::Arp && x.frame.get(6..12) != x.frame.get(22..28))
                    .count();
                (
                    bad == 0,
                    format!(
                        "{bad} ARP replies whose Ethernet source differs from the sender hardware address"
                    ),
                )
            }
            _ => (false, "unknown deviation".into()),
        }
    });
}

/// Every frame of the scanner MAC is a probe of the scan or one of [`SCANNER_CLASSES`]; any other is the scanner's
/// own extra frame: a FAIL on rmasscan's step (once the evidence is proven), INVALID on the oracle's.
pub(crate) fn scanner_frames(r: &mut Run, s: &Side<WireView>, v: &WireView) {
    scanner_frame_checks(
        r,
        s,
        "every frame of the scanner MAC is a probe of the scan or of a named class the stand makes the scanner side send (next-hop who-has, RST to a SYN-ACK, ICMP 3/3 to a UDP reply, ICMP 3/2 to an SCTP reply)",
        &v.scanner_unexplained,
        "the named scanner-side frames stay within their bounds (RST to a SYN-ACK: one per SYN-ACK frame of the stand, on the oracle's step plus one per distinct SYN-ACK for C's own reset after its dedup; next-hop who-has: the resolver's request count; ICMP 3/3 and 3/2: one per UDP or SCTP reply frame)",
        &scanner_bounds(v, s.spec.who),
    );
}

/// What a case proves beyond the common checks.
fn case_checks(
    r: &mut Run,
    c: &CaseSpec,
    sides: &[Side<WireView>],
    docs: &[Option<Document>],
    st: &Stand,
) {
    for (s, d) in sides.iter().zip(docs) {
        let (Some(v), Who::Rmasscan) = (&s.view, s.spec.who) else {
            continue;
        };
        match c.tag {
            "p01_ping" => {
                let hosts: BTreeSet<Ipv4Addr> =
                    d.iter().flat_map(|d| &d.records).map(|x| x.ip).collect();
                cap(
                    r,
                    s,
                    "--ping finds every live peer 198.18.0.2-198.18.0.5 (open icmp)",
                    hosts == st.peer_ips.iter().copied().collect(),
                    format!("{hosts:?}"),
                );
            }
            "p02_udp_payloads_and_closed" => {
                let len = |port: u16| {
                    v.probes
                        .iter()
                        .filter(|p| p.port == port)
                        .map(|p| p.frame.len().saturating_sub(42))
                        .collect::<BTreeSet<_>>()
                };
                let ok = [53, 161, 500]
                    .iter()
                    .all(|p| len(*p).iter().all(|n| *n > 0) && !len(*p).is_empty())
                    && len(59999) == BTreeSet::from([0]);
                cap(
                    r,
                    s,
                    "the probes carry the built-in DNS, SNMP and ISAKMP payloads on 53, 161 and 500 and a 0-byte payload on 59999",
                    ok,
                    format!(
                        "payload bytes: 53 {:?}, 161 {:?}, 500 {:?}, 59999 {:?}",
                        len(53),
                        len(161),
                        len(500),
                        len(59999)
                    ),
                );
            }
            "p04_arp_scan" => {
                let gw = v
                    .probes
                    .iter()
                    .filter(|p| p.ip == Ipv4Addr::new(198, 18, 0, 2))
                    .count();
                cap(
                    r,
                    s,
                    "no ARP request to the default gateway: the scanner's ARP requests are the four who-has probes, 198.18.0.2 asked once",
                    v.arp_requests() == st.peer_ips.len() && gw == 1,
                    format!(
                        "{} ARP requests, {gw} for 198.18.0.2, {} who-has that are no probe",
                        v.arp_requests(),
                        v.arp_requests_not_probes
                    ),
                );
                if s.spec.out == Out::Stdout {
                    let macs: BTreeSet<Option<[u8; 6]>> =
                        d.iter().flat_map(|d| &d.records).map(|x| x.mac).collect();
                    let hosts: BTreeSet<Ipv4Addr> =
                        d.iter().flat_map(|d| &d.records).map(|x| x.ip).collect();
                    cap(
                        r,
                        s,
                        "--arp finds every neighbour 198.18.0.2-198.18.0.5 with the peer's MAC 02:aa:00:00:00:02",
                        macs == BTreeSet::from([Some(st.peer_mac)])
                            && hosts == st.peer_ips.iter().copied().collect(),
                        format!("{hosts:?} {macs:?}"),
                    );
                }
            }
            "p05_mixed_protos" => {
                let protos: BTreeSet<Proto> =
                    d.iter().flat_map(|d| &d.records).map(|x| x.proto).collect();
                cap(
                    r,
                    s,
                    "the one document holds records of tcp, udp, sctp and icmp",
                    protos == BTreeSet::from([Proto::Tcp, Proto::Udp, Proto::Sctp, Proto::Icmp]),
                    format!("{protos:?}"),
                );
            }
            _ => {}
        }
    }
}

// ------------------------------------------------------------------ privacy and evidence

/// The files a scanner wrote or that name its argv: their addresses must be the stand's.
const SCANNER_TEXT: [&str; 1] = [PEER_STACK_JSON];
fn binary_problems(b: &[u8]) -> Vec<String> {
    let st = stand();
    match parse_doc(Out::Binary, b) {
        Err(e) => vec![format!(
            "not a masscan -oB file ({e}); its bytes are not scanned as text"
        )],
        Ok(d) => d
            .records
            .iter()
            .filter(|x| !st.peer_ips.contains(&x.ip))
            .map(|x| format!("address {}", x.ip))
            .collect(),
    }
}
/// The interface a `[+] interface` line names, when it is not the stand's.
pub(crate) fn iface_problems(text: &str) -> Vec<String> {
    text.split(['\n', '\r'])
        .filter_map(|l| l.strip_prefix("[+] interface"))
        .filter_map(|v| {
            v.split_once(" = ")
                .map(|(_, v)| v.split(' ').next().unwrap_or(""))
        })
        .filter(|n| *n != "veth-a")
        .map(|n| format!("interface name {n:?}"))
        .collect()
}
pub(crate) fn evidence_extension(f: &str) -> bool {
    Path::new(f)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e == "bin" || EVIDENCE_EXTENSIONS.contains(&e))
}

// ------------------------------------------------------------------ the plan of the shared verifier

/// The protocols suite as [`pair_verify`] judges it.
pub(crate) struct Protocols;
impl PairPlan for Protocols {
    type Case = CaseSpec;
    type View = WireView;
    type Rec = Rec;
    type Expect = ProtoExpect;
    const KEY: &'static str = "protocols";
    const SCANNER_TEXT: &'static [&'static str] = &SCANNER_TEXT;
    const RECORD_ORDER_VS_C: &'static str = RECORD_ORDER_VS_C;
    const SCANNER_CLASSES: &'static [(&'static str, &'static str)] = &SCANNER_CLASSES;
    const PROBES_VS_C: &'static str = " (udp-checksum-ffff applied)";
    const PROBES_FIRST_DIFFERENCE: bool = false;
    const FOREIGN_SYN: &'static str = "SYN";
    const OWN_WIRE: &'static str = "the document holds the records of the replies on its wire, field for field, in reply order (replies captured at most 50 us apart on the peer link, rounded to the microsecond, may come in either order: REPLY_REORDER_WINDOW_US)";
    const ORACLE_NOTE: &'static str =
        "the pinned C masscan 8e6b3b0 with the same argv, one run per document, on the same stand";

    fn cases() -> Vec<CaseSpec> {
        CASES.to_vec()
    }
    fn tag(c: &CaseSpec) -> &'static str {
        c.tag
    }
    fn steps(c: &CaseSpec) -> Vec<StepSpec> {
        steps(c.tag).unwrap_or_default()
    }
    fn expect(c: &CaseSpec) -> Option<ProtoExpect> {
        expect(c.tag)
    }
    fn manifest(v: Value) -> Option<Option<String>> {
        serde_json::from_value::<ProtoManifest>(v)
            .ok()
            .filter(|x| x.protocols == "linux")
            .map(|x| x.lab_id)
    }
    fn view(c: &CaseSpec, fr: &Frames, st: &Stand) -> WireView {
        view(fr, st, c.arp)
    }
    fn parse_doc(out: Out, b: &[u8], _who: Who) -> Result<Document, String> {
        parse_doc(out, b)
    }
    fn foreign(fr: &Frames, st: &Stand) -> Vec<String> {
        foreign_probes(fr, st)
    }
    fn text_problems(text: &str, _scanner_text: bool) -> Vec<String> {
        iface_problems(text)
    }
    fn binary_problems(b: &[u8]) -> Vec<String> {
        binary_problems(b)
    }
    fn seal(r: &mut Run, d: &Path) {
        av::linux_seal(r, d);
    }
    fn case_records(r: &mut Run, d: &Path, c: &CaseSpec) {
        if let Some(p) = av::typed::<PeerStack>(r, d, PEER_STACK_JSON) {
            let problem = peer_stack_problem(&p, c);
            r.inv(
                "peer-stack.json: the peer answers the stand's way (icmp_ratemask 0, Echo answered, the stand's responder, no SCTP in the kernel for an SCTP case)",
                problem.is_none(),
                problem.unwrap_or_else(|| format!("{p:?}")),
            );
        }
    }
    fn plan(c: &CaseSpec) -> Result<Vec<Vec<u8>>, String> {
        plan_stream(c)
    }
    fn step_wire(
        r: &mut Run,
        _c: &CaseSpec,
        s: &Side<WireView>,
        v: &WireView,
    ) -> serde_json::Map<String, Value> {
        stand_answers(r, s, v);
        scanner_frames(r, s, v);
        scanner_counts(
            &SCANNER_CLASSES,
            &v.scanner_named,
            v.scanner_unexplained.len(),
            &scanner_bounds(v, s.spec.who),
        )
    }
    fn rmasscan_step(r: &mut Run, c: &CaseSpec, s: &Side<WireView>, doc: Option<&Document>) {
        rmasscan_step(r, s, c, doc);
    }
    fn wire_records_at(c: &CaseSpec, v: &WireView, who: Who, out: Out) -> Vec<(Rec, f64)> {
        wire_records_at(v, who, out, c.show_closed)
    }
    fn doc_record(x: &Rec, _who: Who) -> Rec {
        x.bare()
    }
    fn same_probe(rm: &[u8], c: &[u8]) -> Option<bool> {
        same_probe(rm, c)
    }
    fn vs_c(c: &CaseSpec, rm: &[Rec], oracle: &[Rec]) -> (Vec<Rec>, Vec<Rec>, usize, &'static str) {
        let got: Vec<Rec> = rm.iter().map(Rec::bare).collect();
        let dedup = c.deviations.contains(&"non-tcp-dedup");
        let (want, n) = collapse(oracle, dedup);
        (
            got,
            want,
            n,
            if dedup {
                " (non-tcp-dedup applied)"
            } else {
                ""
            },
        )
    }
    fn finish(
        r: &mut Run,
        c: &CaseSpec,
        sides: &[Side<WireView>],
        docs: &[Option<Document>],
        tally: Tally,
    ) {
        case_checks(r, c, sides, docs, &stand());
        deviations(r, c, sides, tally.by_rule, tally.collapsed);
    }
}

/// Judge an evidence directory: the manifest, every planned case, and a safety walk of everything else. Symbolic
/// links are never followed.
pub fn verify_dir(root: &Path) -> Value {
    pair_verify::verify_dir::<Protocols>(root)
}

/// `protocols-verify --dir DIR [--out FILE]`: 0 PASS, 1 FAIL, 2 INVALID or NOT RUN.
pub fn run(args: &[String]) -> Result<i32, String> {
    pair_verify::run::<Protocols>(args)
}

#[cfg(test)]
#[path = "protocols_verify_tests.rs"]
pub(crate) mod tests;
