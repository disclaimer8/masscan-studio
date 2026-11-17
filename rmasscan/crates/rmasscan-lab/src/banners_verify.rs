//! Offline verifier of the banners window of sub-stages 4a and 4b on the sealed Linux netns stand (`banners-verify`)
//! and the one case table of its suite (`banners-suite linux`): UDP banners (`--banners`, `--rawudp`) of the pinned C
//! masscan `8e6b3b0` and of rmasscan, against the same deterministic UDP responders (design
//! docs/superpowers/specs/2026-11-13-rmasscan-banners-design.md §7, R14; C reference
//! 2026-11-13-rmasscan-banners-c-reference-output-udp.md B0-B10, C3.2).
//!
//! Two cases, `b01_banners` and `b02_rawudp` ([`CASES`]). A case is a list of STEPS ([`steps`]): for every output
//! document of the case (`-oB`, where banners are raw bytes, and `-oL`, where they are `normalize_string` text) one
//! rmasscan run and one run of the C oracle with the same argv, each with its own peer capture and its own restarted
//! responder. Every scan names `--seed 1`, `--source-port 40000` and `--retries 0`, so the two scanners put the same
//! probes on the wire in the same order (BlackRock), byte for byte, with the same cookies in their payloads.
//!
//! The stand is the protocols stand (`wire-lab.sh --suite banners`: the autodetect netns stand, scanner `198.18.0.1`
//! on `veth-a`, peers `198.18.0.2`-`.5` on `veth-b`, `net.ipv4.icmp_ratemask = 0` in the peer namespace) with a peer
//! responder whose UDP sockets answer the eight parser ports of C (53, 123, 137, 161, 500, 5683, 11211, 16464) and one
//! port without a parser (1900) with scenario replies ([`scenario_reply`], `capture responder --udp-answer banners`):
//! one reply per datagram, chosen by the address the probe went to (one scenario per address: [`ROLES`]), with the
//! probe's identifier copied into it (the DNS and NetBIOS id, the SNMP request id, the ISAKMP initiator cookie, the
//! CoAP message id, the memcached request id) or deliberately spoiled. The replies are the C goldens of tasks 4 and 5
//! (`tests/golden/udp-banners/cases/*.bin`, whose C output in an Ethernet + IPv4 frame is pinned there) with the
//! probe's cookie; only two are built here, because a golden's text would name an address or a MAC off the stand in
//! the evidence: the NBSTAT reply with its MAC's first byte 0 (C prints the first byte six times, `00-00-..`) and the
//! ZeroAccess `retL` listing three stand addresses ([`zeroaccess_retl`]).
//!
//! What is judged, per step, under the rules of the protocols verifier (whose machinery is reused, `pair_verify`):
//! - the probes: rmasscan's equal the product's plan, in order; the oracle's equal rmasscan's, byte for byte;
//! - the stand: every probe got exactly one reply, and that reply is the table's scenario reply to that very probe
//!   (otherwise INVALID for both scanners, never a FAIL);
//! - the scanner side's frames: probes or a named class within its bound (`protocols_verify::SCANNER_CLASSES`);
//! - the document: well formed in C's byte forms; its status records are the replies of its own wire, in reply order
//!   (as in the protocols window); every banner record follows the status record of its reply with the same time;
//!   per address and port the banners' applications are the ones the scenario declares ([`Scenario::apps`], a FAIL
//!   for rmasscan and INVALID for the oracle only where the stand answered with the scenario reply); in rmasscan's
//!   `-oB` every raw banner is its reply's datagram, byte for byte;
//! - rmasscan against C: the statuses and the banner records equal C's as a multiset, field for field but the time, so
//!   the set of banners per (address, port, application) is C's; the one declared difference is C's raw banner on
//!   11211 and on ports without a parser ([`DEVIATIONS`], `udp-raw-past-datagram`, C1.1 and R2): those compare by
//!   presence and, in `-oB`, by length only.
//!
//! The rules of `protocols-verify` hold: a missing input is NOT RUN, unproven evidence INVALID, a lab frame off the
//! stand a safety FAIL, rmasscan's misbehaviour a FAIL, the oracle's an INVALID, and no verdict is ever promoted. The
//! oracle never finishes a live scan on this stand (`[-] Passed the wait window but still running, forcing exit...`):
//! its file without the footer is expected with that line on its stderr.
//!
//! UDP over IPv6 is not in this window (the IPv6 stage refuses it, its R3); IPv6 banners come over TCP (R16).
//!
//! Sub-stage 4b adds nine TCP cases ([`TCP_CASES`]): TCP banners through the user-mode stack over IPv4 and IPv6, the
//! end-of-scan flush, `--banners --noreset`, the stateless RST and `--noreset` without `--banners` (R8), two cases
//! whose source has no neighbour entry, so the peer resolves it through the scanner's own ARP and NDP replies (R9), and
//! a quiet control of rmasscan alone without the heartbeat ([`TcpCase::quiet`]: its hello and lifetime timers on a
//! link that carries nothing but the scan).
//! Both scanners run one argv from a source no interface of the scanner namespace holds ([`TCP_SOURCE`],
//! [`TCP_SOURCE6`], [`RESOLVE_SOURCE`], [`RESOLVE_SOURCE6`]) with the next hop given. The stand is the IPv6 stand
//! (`capture isolation --mode ipv6`) with the protocols stand's ICMP setting, no TIME_WAIT socket in the peer
//! namespace ([`PeerTcp`]) and permanent neighbour entries for the first two sources; the responder answers each
//! connection with the script of [`TCP_SCENARIOS`] by its local address and port and heartbeats the link
//! ([`HEARTBEAT_PAYLOAD`]). What is judged, in this order within a step so that a fault is booked on the side that made
//! it: the scanner checks whose evidence is the scanner's alone (the answers to the peer's requests in C's form, each
//! SYN once, every frame explained), the stand's behaviour (INVALID, leaving out what those explain), each scanner's
//! frames per connection (hello window, lifetime window, the stateless RST rule, no frame of a destroyed connection),
//! the banners of each connection against its scenario and in one run after its `open` (M1, rmasscan's in its own
//! step); then, before any comparison with C, C's forced exit and the deviations' conditions; then rmasscan against C:
//! the records as a multiset and every connection's scanner segments (flags, payload, relative seq and ack) in order.
//! The window's differences are E1's (`ipv6-ttl`, `ipv4-stack-checksum`, `memcached-tcp-past-segment`,
//! `no-frame-from-destroyed-tcb`, `minecraft-unsplit`), 4a's `udp-raw-past-datagram`, and the protocols stage's
//! `udp-checksum-ffff` and `rx-checksum-verify` ([`DEVIATIONS`]). The 4a UDP cases also judge M1 and M2 (rmasscan's
//! `-oL` text of the raw banner on 1900 and 11211 is the datagram's `normalize_string`, by the verifier's own escaper
//! [`c_normalize_string`]).
//!
//! Layout of an evidence directory: `manifest.json` (key `banners`: `linux`), `teardown.json`, `runs/<tag>/` per
//! case: `expect.json` ([`BannerExpect`]), `isolation.json`, `isolation-post.json`, `peer-stack.json`,
//! `peer-tcp.json` (TCP cases), `hashes-before-copy.txt`, and one directory per step: `argv.json`, `stdout.txt
//! stderr.txt exit.txt`, the document (`output.bin`, `output.txt`), the peer witness `peer.pcap capture.json peer.err`,
//! `responder.json`, and in a resolve case `neigh-flush.json` ([`NeighFlush`]).
#[cfg(test)]
use crate::verify::{self, array, s};
use crate::{
    autodetect_verify::{self as av, Plan, Stand},
    capture, ipv6_verify as iv,
    output_verify::{BINARY_BLOCK, canon, fields, text_lines},
    pair_verify::{
        self, Doc, PairPlan, Record, Side, Tally, WireSummary, beh, cap, case_of, each,
        expect_steps, named_deviations, pair_steps, plan_probes, scan_tail, scanner_counts,
        tags_of,
    },
    pcap::Frames,
    protocols_verify::{
        self as pv, ExpectStep, LIST_REC, Out, PeerStack, Shown, St, StepSpec, WireView,
        iface_problems, reason_string,
    },
    scan_control_verify::Who,
    verify::{NOT_RUN, Run, read_json},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

// ------------------------------------------------------------------ the case table

pub const TARGETS: &str = pv::TARGETS;
pub const RATE: &str = pv::RATE;
pub const WAIT: &str = pv::WAIT;
pub const SOURCE_PORT: u16 = pv::SOURCE_PORT;
/// The source-port range of a case that expects the stack's second connections (TLS `--cert`, D1) and of the
/// native stands: `--source-port 40000-40015`. Sixteen ports: the plan's hash picks the first connection's
/// port in the range, C's `_next_IP_port` the second one's.
pub const fn source_range() -> (u16, u16) {
    (SOURCE_PORT, SOURCE_PORT + 15)
}
/// The UDP ports of the window: C's eight parser ports (`src/proto-udp.c:76-113`; ZeroAccess by its first port) and
/// 1900, a port with a built-in probe and no parser (the `default` branch).
pub const PORTS: [u16; 9] = [53, 123, 137, 161, 500, 1900, 5683, 11211, 16464];
const PORTS_FLAG: &str = "-p53,123,137,161,500,1900,5683,11211,16464";
const PLAN_PORTS: &str = "U:53,123,137,161,500,1900,5683,11211,16464";
/// The ports where C's raw banner reads past the datagram (`src/proto-udp.c:97-101, 108-112, 129`; C1.1): 11211 and
/// every port without a parser.
pub const RAW_PAST_DATAGRAM_PORTS: [u16; 2] = [1900, 11211];
pub const EXPECT_JSON: &str = pv::EXPECT_JSON;
pub const ISOLATION_JSON: &str = pv::ISOLATION_JSON;
pub const ISOLATION_POST_JSON: &str = pv::ISOLATION_POST_JSON;
pub const PEER_STACK_JSON: &str = pv::PEER_STACK_JSON;
pub const RESPONDER_JSON: &str = pv::RESPONDER_JSON;
/// The responder's mode that answers with [`scenario_reply`] (`capture responder --udp-answer banners`).
pub const UDP_ANSWER: &str = "banners";

/// One case: the flag that turns banners on, and the documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaseSpec {
    pub tag: &'static str,
    pub flags: &'static [&'static str],
    /// `--rawudp`: every reply also as a raw banner (`src/proto-udp.c:120`).
    pub rawudp: bool,
    pub outs: &'static [Out],
}
pub const CASES: [CaseSpec; 2] = [
    CaseSpec {
        tag: "b01_banners",
        flags: &["-sU", PORTS_FLAG, "--banners"],
        rawudp: false,
        outs: &[Out::Binary, Out::List],
    },
    CaseSpec {
        tag: "b02_rawudp",
        flags: &["-sU", PORTS_FLAG, "--rawudp"],
        rawudp: true,
        outs: &[Out::Binary, Out::List],
    },
];
/// The UDP case (sub-stage 4a) with tag `tag`.
pub fn case(tag: &str) -> Option<CaseSpec> {
    CASES.into_iter().find(|c| c.tag == tag)
}
/// Any case of the window, UDP or TCP.
pub fn any_case(tag: &str) -> Option<Case> {
    case_of::<Banners>(tag)
}
/// Every tag of the window: the UDP cases of 4a, then the TCP cases of 4b.
pub fn planned_tags() -> Vec<&'static str> {
    tags_of::<Banners>()
}
/// The scan of a case into `out`: targets, the case's flags, the document, `--seed 1 --rate 100 --wait 3
/// --source-port 40000 --retries 0`.
pub fn argv(c: &CaseSpec, out: Out) -> Vec<String> {
    let mut a = vec![TARGETS.to_owned()];
    a.extend(c.flags.iter().map(|f| (*f).to_owned()));
    scan_tail(&mut a, out, false, RATE, WAIT, SOURCE_PORT);
    a.extend(["--retries".to_owned(), "0".to_owned()]);
    a
}
/// The steps of a case, in the order they run; defined here and nowhere else.
pub fn steps(tag: &str) -> Option<Vec<StepSpec>> {
    match any_case(tag)? {
        Case::Udp(c) => Some(pair_steps(c.outs, |out, _| argv(&c, out))),
        Case::Tcp(c) => {
            let mut s = pair_steps(c.outs, |out, _| tcp_argv(&c, out));
            // The quiet control is rmasscan's alone (TcpCase::quiet).
            s.retain(|x| !c.quiet || x.who == Who::Rmasscan);
            Some(s)
        }
    }
}
/// `expect.json`: the case as the suite planned it. `tcp` only for a TCP case (the UDP cases' record is 4a's).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BannerExpect {
    pub tag: String,
    pub plan_ports: String,
    pub rawudp: bool,
    pub steps: Vec<ExpectStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<TcpExpect>,
}
fn stand_source_ports() -> (u16, u16) {
    (SOURCE_PORT, SOURCE_PORT)
}
/// What `expect.json` records of a TCP case beyond its steps.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TcpExpect {
    pub source: String,
    pub neighbour_entry: bool,
    pub banners: bool,
    pub noreset: bool,
    /// Extra scanner arguments after `--banners` (a vuln mode of 4c).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_args: Vec<String>,
    /// The `--source-port` range, inclusive; the single stand port by default. A range lets the stack's
    /// second (TLS) connection take the next port (_next_IP_port, reference §D1).
    #[serde(default = "stand_source_ports")]
    pub source_ports: (u16, u16),
    pub connection_timeout: Option<u32>,
    pub wait: u32,
    /// The responder heartbeats the link (every TCP case but the quiet control, [`TcpCase::quiet`]).
    pub heartbeat: bool,
}
pub fn expect(tag: &str) -> Option<BannerExpect> {
    match any_case(tag)? {
        Case::Udp(c) => Some(BannerExpect {
            tag: tag.into(),
            plan_ports: PLAN_PORTS.into(),
            rawudp: c.rawudp,
            steps: expect_steps(&steps(tag)?),
            tcp: None,
        }),
        Case::Tcp(c) => Some(BannerExpect {
            tag: tag.into(),
            plan_ports: c.ports.into(),
            rawudp: false,
            steps: expect_steps(&steps(tag)?),
            tcp: Some(TcpExpect {
                source: c.source().to_string(),
                neighbour_entry: !c.resolve,
                banners: c.banners,
                noreset: c.noreset,
                extra_args: c.extra_args.iter().map(|x| (*x).to_owned()).collect(),
                source_ports: c.source_ports,
                connection_timeout: c.connection_timeout,
                wait: c.wait,
                heartbeat: !c.quiet,
            }),
        }),
    }
}
/// `manifest.json` as far as this verifier reads it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BannerManifest {
    pub banners: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lab_id: Option<String>,
}
/// The case as the protocols verifier's plan sees it (its probes, its `[+]` lines).
fn proto_case(c: &CaseSpec) -> pv::CaseSpec {
    pv::CaseSpec {
        tag: c.tag,
        flags: c.flags,
        plan_ports: PLAN_PORTS,
        arp: false,
        show_closed: false,
        outs: c.outs,
        deviations: &[],
    }
}
/// The probes the case must put on the wire, in send order, from the product's own plan.
pub fn plan_stream(c: &CaseSpec) -> Result<Vec<Vec<u8>>, String> {
    pv::plan_stream(&proto_case(c))
}

// ------------------------------------------------------------------ the TCP cases (sub-stage 4b)

/// The source of the TCP cases (R9): assigned to no interface of the scanner namespace (its kernel neither answers
/// nor resets for it, `ip_forward` 0), with a permanent neighbour entry on the scanner MAC in the peer namespace
/// (`wire-lab.sh --suite banners`), so the peer never resolves it and both scanners see the same wire.
pub const TCP_SOURCE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 9);
pub const TCP_SOURCE6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x198, 0x18, 0, 0, 0, 0, 9);
/// The source of the two resolve cases: no neighbour entry anywhere, so the peer resolves it with ARP and NDP, and the
/// scanner answers for its own address (C `src/main.c:878-887`, `src/stack-ndpv6.c:95-182`; rmasscan's responders).
/// The suite flushes the peer's entry for it before every step of those cases.
pub const RESOLVE_SOURCE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 10);
pub const RESOLVE_SOURCE6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x198, 0x18, 0, 0, 0, 0, 0xa);
/// The peer's MAC, given to both scanners as the next hop (`--router-mac`, `--router-mac-ipv6`): no next-hop
/// resolution frame on the wire, and the peer never learns the source from one.
pub const PEER_MAC_ARG: &str = "02-aa-00-00-00-02";
/// The TCP ports of the window: one port per text parser of 4b (D1-D11), the hello ports of C among them (B4: 23,
/// 80, 3389, 11211, 25565).
pub const TCP_PORTS: [u16; 11] = [21, 22, 23, 25, 80, 110, 143, 3389, 5900, 11211, 25565];
const TCP_PORTS_LIST: &str = "21,22,23,25,80,110,143,3389,5900,11211,25565";
/// The ports of C's hello table (`banner1_create`, `src/proto-banner1.c:518-610`, B4) the window scans.
pub const TCP_HELLO_PORTS: [u16; 6] = [23, 80, 443, 3389, 11211, 25565];
pub const TCP_TARGETS6: &str = "[fd00:198:18::2]-[fd00:198:18::5]";
/// The responder's mode that answers with [`TCP_SCENARIOS`] (`capture responder --tcp-answer banners`).
pub const TCP_ANSWER: &str = "banners";
/// The peer heartbeat of the TCP steps: a lab marker frame with this payload from the peer MAC to the scanner MAC
/// every [`HEARTBEAT_MS`]. C's receive thread runs its stack timers only when a frame arrives (`src/main.c:777-797`;
/// on this stand a quiet link never returns from `pcap_next`, which is why every live C run of the earlier windows
/// ended in its forced exit, `src/main.c:1489-1496`): the heartbeat turns its loop over, so its hello, lifetime RST
/// and end-of-scan flush (`tcpcon_destroy_table`, `src/main.c:1111-1113`) run on time. Both scanners drop it.
pub const HEARTBEAT_PAYLOAD: &[u8] = b"WIRELAB-BEAT";
pub const HEARTBEAT_MS: u64 = 200;
/// The largest gap between heartbeats the verifier accepts inside a TCP step's scan (otherwise INVALID).
pub const HEARTBEAT_MAX_GAP: f64 = 1.0;
/// How long the responder heartbeats after it starts: the scan's wait plus this, so that it covers the scan and
/// leaves the link quiet for the witness soon after the scanner ends.
pub const HEARTBEAT_AFTER_WAIT_S: u32 = 8;
/// The responder's pause after every write of a script (one segment each, `TCP_NODELAY`).
pub const SCRIPT_PAUSE_MS: u64 = 200;
/// At the end of a script the responder waits this long for the scanner's FIN before it sends its own.
pub const SCRIPT_END_WAIT_MS: u64 = 1000;
/// The hello leaves 1.0-3.5 s after the SYN-ACK (C: 2 s on a whole-second timer grid, `src/stack-tcp-app.c:76`,
/// `src/event-timeout.h:129`; rmasscan: 2 s on the engine clock, R6).
pub const HELLO_WINDOW: (f64, f64) = (1.0, 3.5);
/// The lifetime RST leaves `timeout` + 2 ± 2 s after the SYN-ACK (`src/stack-tcp-core.c:1970-1980`: checked on a 2 s
/// tick after `when_created + timeout`).
pub const LIFETIME_WINDOW: (f64, f64) = (0.0, 4.0);

/// One TCP case: the family and source, the targets and ports, the flags that matter, the wait and the documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpCase {
    pub tag: &'static str,
    pub v6: bool,
    /// The source has no neighbour entry in the peer namespace (the resolve cases).
    pub resolve: bool,
    pub targets: &'static str,
    /// The `-p` list.
    pub ports: &'static str,
    pub banners: bool,
    pub noreset: bool,
    /// Extra scanner arguments after `--banners` (a vuln mode of 4c).
    pub extra_args: &'static [&'static str],
    /// The `--source-port` range, inclusive; the single stand port by default. A range lets the stack's
    /// second (TLS) connection take the next port (_next_IP_port, reference §D1).
    pub source_ports: (u16, u16),
    pub connection_timeout: Option<u32>,
    pub wait: u32,
    pub outs: &'static [Out],
    pub deviations: &'static [&'static str],
    /// The quiet control: one rmasscan step and no peer heartbeat, so that rmasscan's hello and lifetime timers are
    /// judged on a link that carries nothing but the scan (the heartbeat of every other TCP step would hide a timer
    /// that runs only when a frame arrives). No oracle step: C's receive loop needs the heartbeat
    /// ([`HEARTBEAT_PAYLOAD`]).
    pub quiet: bool,
}
impl TcpCase {
    pub fn source(&self) -> IpAddr {
        match (self.v6, self.resolve) {
            (false, false) => IpAddr::V4(TCP_SOURCE),
            (false, true) => IpAddr::V4(RESOLVE_SOURCE),
            (true, false) => IpAddr::V6(TCP_SOURCE6),
            (true, true) => IpAddr::V6(RESOLVE_SOURCE6),
        }
    }
    pub fn port_list(&self) -> Vec<u16> {
        self.ports
            .split(',')
            .filter_map(|p| p.parse().ok())
            .collect()
    }
    /// The lifetime of a connection: `--connection-timeout`, 30 without it (`src/main.c:688-695`).
    pub fn lifetime(&self) -> u32 {
        self.connection_timeout.unwrap_or(30)
    }
}
const V4_TCP: &[&str] = &[
    "rx-checksum-verify",
    "ipv4-stack-checksum",
    "no-frame-from-destroyed-tcb",
    "memcached-tcp-past-segment",
    "minecraft-unsplit",
];
const V6_TCP: &[&str] = &[
    "rx-checksum-verify",
    "ipv6-ttl",
    "no-frame-from-destroyed-tcb",
    "memcached-tcp-past-segment",
    "minecraft-unsplit",
];
const V4_SHORT: &[&str] = &[
    "rx-checksum-verify",
    "ipv4-stack-checksum",
    "no-frame-from-destroyed-tcb",
];
const V6_SHORT: &[&str] = &[
    "rx-checksum-verify",
    "ipv6-ttl",
    "no-frame-from-destroyed-tcb",
];
/// The quiet control has no C step: only the condition on the peer's segments.
const QUIET: &[&str] = &["rx-checksum-verify"];
pub const TCP_CASES: [TcpCase; 12] = [
    TcpCase {
        tag: "t01_tcp4",
        v6: false,
        resolve: false,
        targets: TARGETS,
        ports: TCP_PORTS_LIST,
        banners: true,
        noreset: false,
        extra_args: &[],
        source_ports: (SOURCE_PORT, SOURCE_PORT),
        connection_timeout: Some(8),
        wait: 14,
        outs: &[Out::Binary, Out::List],
        deviations: V4_TCP,
        quiet: false,
    },
    TcpCase {
        tag: "t02_tcp6",
        v6: true,
        resolve: false,
        targets: TCP_TARGETS6,
        ports: TCP_PORTS_LIST,
        banners: true,
        noreset: false,
        extra_args: &[],
        source_ports: (SOURCE_PORT, SOURCE_PORT),
        connection_timeout: Some(8),
        wait: 14,
        outs: &[Out::Binary, Out::List],
        deviations: V6_TCP,
        quiet: false,
    },
    TcpCase {
        tag: "t03_teardown",
        v6: false,
        resolve: false,
        targets: "198.18.0.4-198.18.0.5",
        ports: "80,3389",
        banners: true,
        noreset: false,
        extra_args: &[],
        source_ports: (SOURCE_PORT, SOURCE_PORT),
        connection_timeout: None,
        wait: 6,
        outs: &[Out::Binary],
        deviations: V4_SHORT,
        quiet: false,
    },
    TcpCase {
        tag: "t04_banners_noreset",
        v6: false,
        resolve: false,
        targets: "198.18.0.4-198.18.0.5",
        ports: "80,3389",
        banners: true,
        noreset: true,
        extra_args: &[],
        source_ports: (SOURCE_PORT, SOURCE_PORT),
        connection_timeout: Some(8),
        wait: 14,
        outs: &[Out::List],
        deviations: V4_SHORT,
        quiet: false,
    },
    TcpCase {
        tag: "t05_stateless_rst",
        v6: false,
        resolve: false,
        targets: TARGETS,
        ports: "80,81",
        banners: false,
        noreset: false,
        extra_args: &[],
        source_ports: (SOURCE_PORT, SOURCE_PORT),
        connection_timeout: None,
        wait: 3,
        outs: &[Out::List],
        deviations: V4_SHORT,
        quiet: false,
    },
    TcpCase {
        tag: "t06_noreset",
        v6: false,
        resolve: false,
        targets: TARGETS,
        ports: "80,81",
        banners: false,
        noreset: true,
        extra_args: &[],
        source_ports: (SOURCE_PORT, SOURCE_PORT),
        connection_timeout: None,
        wait: 3,
        outs: &[Out::List],
        deviations: V4_SHORT,
        quiet: false,
    },
    TcpCase {
        tag: "t07_resolve_arp",
        v6: false,
        resolve: true,
        targets: "198.18.0.2",
        ports: "80",
        banners: true,
        noreset: false,
        extra_args: &[],
        source_ports: (SOURCE_PORT, SOURCE_PORT),
        connection_timeout: None,
        wait: 8,
        outs: &[Out::List],
        deviations: V4_SHORT,
        quiet: false,
    },
    TcpCase {
        tag: "t08_resolve_ndp",
        v6: true,
        resolve: true,
        targets: "[fd00:198:18::2]",
        ports: "80",
        banners: true,
        noreset: false,
        extra_args: &[],
        source_ports: (SOURCE_PORT, SOURCE_PORT),
        connection_timeout: None,
        wait: 8,
        outs: &[Out::List],
        deviations: V6_SHORT,
        quiet: false,
    },
    // M3: rmasscan alone on a quiet link: the hello on .4:80, .5:80 and .5:3389, the lifetime RST on the two held
    // connections (.4:80, .5:3389), both from the stack's own timers with no frame of the peer to wake it.
    TcpCase {
        tag: "t09_quiet_timers",
        v6: false,
        resolve: false,
        targets: "198.18.0.4-198.18.0.5",
        ports: "80,3389",
        banners: true,
        noreset: false,
        extra_args: &[],
        source_ports: (SOURCE_PORT, SOURCE_PORT),
        connection_timeout: Some(8),
        wait: 14,
        outs: &[Out::List],
        deviations: QUIET,
        quiet: true,
    },
    TcpCase {
        tag: "t10_tls4",
        v6: false,
        resolve: false,
        targets: TARGETS,
        ports: "25,443",
        banners: true,
        noreset: false,
        extra_args: &[],
        source_ports: source_range(),
        connection_timeout: Some(8),
        wait: 14,
        outs: &[Out::Binary, Out::List],
        deviations: &[
            "rx-checksum-verify",
            "ipv4-stack-checksum",
            "no-frame-from-destroyed-tcb",
            "memcached-tcp-past-segment",
            "minecraft-unsplit",
        ],
        quiet: false,
    },
    TcpCase {
        tag: "t11_tls6",
        v6: true,
        resolve: false,
        targets: TCP_TARGETS6,
        ports: "25,443",
        banners: true,
        noreset: false,
        extra_args: &[],
        source_ports: source_range(),
        connection_timeout: Some(8),
        wait: 14,
        outs: &[Out::Binary, Out::List],
        deviations: &[
            "rx-checksum-verify",
            "ipv6-ttl",
            "no-frame-from-destroyed-tcb",
            "memcached-tcp-past-segment",
            "minecraft-unsplit",
        ],
        quiet: false,
    },
    TcpCase {
        tag: "t12_heartbleed",
        v6: false,
        resolve: false,
        targets: "198.18.0.5",
        ports: "443",
        banners: true,
        noreset: false,
        extra_args: &["--heartbleed"],
        source_ports: source_range(),
        connection_timeout: Some(8),
        wait: 14,
        outs: &[Out::Binary, Out::List],
        deviations: &[
            "rx-checksum-verify",
            "ipv4-stack-checksum",
            "no-frame-from-destroyed-tcb",
            "tls-hello-random",
        ],
        quiet: false,
    },
];
pub fn tcp_case(tag: &str) -> Option<TcpCase> {
    TCP_CASES.into_iter().find(|c| c.tag == tag)
}
/// A case of the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Case {
    Udp(CaseSpec),
    Tcp(TcpCase),
}
impl Case {
    pub fn tag(&self) -> &'static str {
        match self {
            Case::Udp(c) => c.tag,
            Case::Tcp(c) => c.tag,
        }
    }
}
/// The scan of a TCP case into `out`: targets, ports, the case's flags, the source and the next hop, the document,
/// `--seed 1 --rate 100 --wait W --source-port 40000 --retries 0`. Both scanners run it as it is.
pub fn tcp_argv(c: &TcpCase, out: Out) -> Vec<String> {
    let mut a = vec![c.targets.to_owned(), format!("-p{}", c.ports)];
    if c.banners {
        a.push("--banners".into());
    }
    if c.noreset {
        a.push("--noreset".into());
    }
    a.extend(c.extra_args.iter().map(|x| (*x).to_owned()));
    if let Some(t) = c.connection_timeout {
        a.extend(["--connection-timeout".into(), t.to_string()]);
    }
    a.extend(["--adapter-ip".into(), c.source().to_string()]);
    a.extend([
        if c.v6 {
            "--router-mac-ipv6"
        } else {
            "--router-mac"
        }
        .into(),
        PEER_MAC_ARG.into(),
    ]);
    if c.source_ports == (SOURCE_PORT, SOURCE_PORT) {
        scan_tail(&mut a, out, false, RATE, &c.wait.to_string(), SOURCE_PORT);
    } else {
        if let (Some(flag), Some(file)) = (out.flag(), out.file()) {
            a.extend([flag.to_owned(), file.to_owned()]);
        }
        a.extend(
            [
                "--seed",
                "1",
                "--rate",
                RATE,
                "--wait",
                &c.wait.to_string(),
                "--source-port",
                &format!("{}-{}", c.source_ports.0, c.source_ports.1),
            ]
            .map(str::to_owned),
        );
    }
    a.extend(["--retries".to_owned(), "0".to_owned()]);
    a
}
/// The banner settings of a TCP case: its extra args as modes (the suite's own stack in tests must run what
/// the case scans with).
pub fn tcp_case_settings(c: &TcpCase) -> rmasscan_proto::TcpBannerSettings {
    let mut s = rmasscan_proto::TcpBannerSettings::default();
    if c.extra_args.contains(&"--heartbleed") {
        s.tls.heartbleed = true;
        s.tls.capture_cert = false;
        s.tls.capture_heartbleed = false;
    }
    s
}

/// The source ranges of a TCP case's table: the case's `--source-port` range and its single source address.
pub fn tcp_case_source_ranges(c: &TcpCase) -> rmasscan_core::stack::SourceRanges {
    let (ipv4, ipv6) = match c.source() {
        IpAddr::V4(a) => (Some((u32::from(a), u32::from(a))), None),
        IpAddr::V6(a) => (None, Some((u128::from(a), u128::from(a)))),
    };
    rmasscan_core::stack::SourceRanges {
        ports: c.source_ports,
        ipv4,
        ipv6,
    }
}

/// The SYNs a TCP case must put on the wire, in send order, from the product's own plan (`ReadyPlan::new_cli` on the
/// stand's binding with the case's source).
pub fn tcp_plan_stream(c: &TcpCase) -> Result<Vec<Vec<u8>>, String> {
    let plan = tcp_ready_plan(c)?;
    match plan_probes(&plan)? {
        (frames, None) => Ok(frames),
        (_, Some(e)) => Err(e),
    }
}
/// The product's plan of a TCP case (its SYNs, and the template of its stack frames).
pub fn tcp_ready_plan(c: &TcpCase) -> Result<rmasscan_core::probe::ReadyPlan, String> {
    use rmasscan_core::{
        config::{Operation, ScanConfig, parse_rate, validate},
        massip::MassIp,
        packet::LinkType,
        probe::{AdapterBinding, NicBinding, ReadyPlan},
        targets::parse_ports,
    };
    let st = stand();
    let v4 = match c.source() {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => st.scanner_ip,
    };
    let mut nic = NicBinding::from(AdapterBinding {
        interface_id: st.iface.into(),
        link_type: LinkType::Ethernet,
        source_ipv4: u32::from(v4),
        source_mac: st.scanner_mac,
        next_hop_mac: st.peer_mac,
        source_ports: c.source_ports,
    });
    if let IpAddr::V6(a) = c.source() {
        nic.source_ipv6 = Some(u128::from(a));
        nic.next_hop_mac_ipv6 = Some(st.peer_mac);
    }
    let mut ips = MassIp::new();
    ips.add_target_string(c.targets)
        .map_err(|e| e.to_string())?;
    parse_ports(ips.ports_mut(), c.ports).map_err(|e| e.to_string())?;
    let cfg = ScanConfig {
        targets: ips,
        seed: 1,
        max_rate: parse_rate(RATE).map_err(|e| e.to_string())?,
        wait_secs: c.wait,
        adapter_ip: Some(u32::from(v4)),
        adapter_mac: Some(st.scanner_mac),
        router_mac: Some(st.peer_mac),
        source_port: Some(c.source_ports),
        adapter_name: Some(st.iface.into()),
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).map_err(|e| e.to_string())?;
    ReadyPlan::new_cli(eff, vec![nic]).map_err(|e| e.to_string())
}

/// One step of a scenario script (`capture responder --tcp-answer banners`, on the peer's kernel socket of the
/// connection). The end of a script (after its last step, unless it is [`TcpStep::Reset`] or [`TcpStep::Hold`]):
/// wait up to [`SCRIPT_END_WAIT_MS`] for the scanner's FIN, then FIN, then read until the scanner's FIN or RST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpStep {
    /// One write (one segment: `TCP_NODELAY`), then [`SCRIPT_PAUSE_MS`].
    Write(&'static [u8]),
    /// Wait for the scanner's next segment and consume it (one read).
    Recv,
    /// Wait for the scanner's data and leave it unread.
    Peek,
    /// Close with the scanner's data unread: the kernel sends RST (RFC 2525, `tcp_close`); the script ends.
    Reset,
    /// Keep the connection open, reading nothing, until the scanner ends it or the responder stops; then close, the
    /// scanner's bytes (its hello, left by a [`TcpStep::Peek`]) unread, so the kernel resets: no socket of the peer is
    /// left on the 4-tuple, which the next step of the case uses again (the same seed and source port).
    Hold,
}
/// What the peer at a stand address does on one TCP port: its script, and the applications of the connection's
/// banner records in the order C flushes them (B3), from the C reference (D1-D11) and the product's parsers on the
/// whole stream (`rmasscan_proto::banner_stream`, test `tcp_scenarios_make_the_declared_banners`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpScenario {
    pub port: u16,
    /// The last octet (IPv4) or the last group (IPv6) of the peer address: 2-5.
    pub peer: u8,
    pub about: &'static str,
    pub steps: &'static [TcpStep],
    pub apps: &'static [&'static str],
    /// Delivered in more than one segment where C does not depend on the split (E2): the wire must show at least two
    /// data segments of the peer, or the step is INVALID.
    pub split: bool,
}
impl TcpScenario {
    /// The server's stream: every `Write` in order.
    pub fn stream(&self) -> Vec<u8> {
        self.steps
            .iter()
            .filter_map(|s| match s {
                TcpStep::Write(b) => Some(*b),
                _ => None,
            })
            .flatten()
            .copied()
            .collect()
    }
    /// The server's writes, in order (each one segment).
    pub fn sends(&self) -> Vec<&'static [u8]> {
        self.steps
            .iter()
            .filter_map(|s| match s {
                TcpStep::Write(b) => Some(*b),
                _ => None,
            })
            .collect()
    }
    /// The scanner ends the connection by its lifetime RST (or the scan's end): a [`TcpStep::Hold`] script.
    pub fn held(&self) -> bool {
        self.steps.contains(&TcpStep::Hold)
    }
    /// The server speaks before the scanner (its first step is a write): no hello is ever sent (B5).
    pub fn server_first(&self) -> bool {
        matches!(self.steps.first(), Some(TcpStep::Write(_)))
    }
    /// TLS from the connection's first byte: the scanner opens with a ClientHello and its first banner is
    /// the `ssl` one. Only these connections owe C's second connection (`--cert`, D1); a STARTTLS upgrade
    /// after a plaintext dialogue (server-first, `smtp` first) never has one, and a TLS stream that yields
    /// no certificate banners (`ssl`, `vuln`) still does.
    pub fn direct_tls(&self) -> bool {
        !self.server_first() && self.apps.first() == Some(&"ssl")
    }
}
const fn ts(
    port: u16,
    peer: u8,
    about: &'static str,
    steps: &'static [TcpStep],
    apps: &'static [&'static str],
    split: bool,
) -> TcpScenario {
    TcpScenario {
        port,
        peer,
        about,
        steps,
        apps,
        split,
    }
}
use TcpStep::{Hold, Peek, Recv, Reset, Write};
/// Synthetic TLS streams of the stand (ServerHello plus certificate chains of the mini certificates of the
/// x509 goldens, names under `.test` so evidence carries no host name), and a ServerHello with a heartbeat
/// answer and a fatal alert after it.
const TLS_CHAIN2: &[u8] = include_bytes!("../../../tests/golden/tls-records/cases/tls-chain2.bin");
const TLS_CHAIN2_P1: &[u8] =
    include_bytes!("../../../tests/golden/tls-records/cases/tls-chain2-part1.bin");
const TLS_CHAIN2_P2: &[u8] =
    include_bytes!("../../../tests/golden/tls-records/cases/tls-chain2-part2.bin");
const TLS_CHAIN2_P3: &[u8] =
    include_bytes!("../../../tests/golden/tls-records/cases/tls-chain2-part3.bin");
const TLS_CHAIN3: &[u8] = include_bytes!("../../../tests/golden/tls-records/cases/tls-chain3.bin");
const TLS_HEARTBLEED: &[u8] =
    include_bytes!("../../../tests/golden/tls-records/cases/heartbleed-stream.bin");
const FTP_REFUSAL: &[u8] = b"530 Please login with USER and PASS.\r\n";
const HTTP_200: &[u8] = b"HTTP/1.0 200 OK\r\nServer: rmasscan-lab\r\nContent-Type: text/html\r\n\r\n<html><title>rmasscan-lab</title></html>";
pub const TCP_SCENARIOS: [TcpScenario; 25] = [
    ts(
        21,
        2,
        "FTP greeting, AUTH TLS refused with 530 (STARTTLS refusal, D2): the AUTH reply line ends the record and closes",
        &[
            Write(b"220 rmasscan-lab FTP server ready\r\n"),
            Recv,
            Write(FTP_REFUSAL),
        ],
        &["ftp"],
        false,
    ),
    ts(
        21,
        3,
        "a two-line FTP greeting in two segments, the same refusal (FTP is split-invariant before a go-ahead, E2.8)",
        &[
            Write(b"220-rmasscan-lab\r\n"),
            Write(b"220 FTP server ready\r\n"),
            Recv,
            Write(FTP_REFUSAL),
        ],
        &["ftp"],
        true,
    ),
    ts(
        21,
        5,
        "an unknown protocol speaking first: no classifier pattern, one unknown record (B1.5)",
        &[Write(b"HELLO rmasscan-lab\r\n")],
        &["unknown"],
        false,
    ),
    ts(
        22,
        2,
        "an SSH-2.0 server ident: the scanner's ident goes back at the first LF; ssh is every byte received (D6)",
        &[Write(b"SSH-2.0-OpenSSH_9.6 rmasscan-lab\r\n"), Recv],
        &["ssh"],
        false,
    ),
    ts(
        22,
        3,
        "the same ident in two segments (SSH depends on the split only after its stop byte, E2.4)",
        &[Write(b"SSH-2.0-Open"), Write(b"SSH_9.6 rmasscan-lab\r\n"), Recv],
        &["ssh"],
        true,
    ),
    ts(
        23,
        2,
        "telnet WILL ECHO and a login prompt: one IAC DONT ECHO back (D8), telnet is every byte received",
        &[Write(b"\xff\xfb\x01\r\nrmasscan-lab login: "), Recv],
        &["telnet"],
        false,
    ),
    ts(
        25,
        2,
        "SMTP: EHLO answered with STARTTLS offered, STARTTLS refused with 454 (D3): the refusal line closes",
        &[
            Write(b"220 rmasscan-lab ESMTP\r\n"),
            Recv,
            Write(b"250-rmasscan-lab\r\n250 STARTTLS\r\n"),
            Recv,
            Write(b"454 4.7.0 TLS not available\r\n"),
        ],
        &["smtp"],
        false,
    ),
    ts(
        25,
        3,
        "the same SMTP dialogue with the greeting in two segments",
        &[
            Write(b"220 rmasscan-lab "),
            Write(b"ESMTP\r\n"),
            Recv,
            Write(b"250-rmasscan-lab\r\n250 STARTTLS\r\n"),
            Recv,
            Write(b"454 4.7.0 TLS not available\r\n"),
        ],
        &["smtp"],
        true,
    ),
    ts(
        25,
        5,
        "\"220-\" on 25: the classifier takes it as FTP (E3.3), AUTH TLS goes out and is refused",
        &[
            Write(b"220-rmasscan-lab ESMTP\r\n220 ready\r\n"),
            Recv,
            Write(b"502 5.5.1 Unrecognized command\r\n"),
        ],
        &["ftp"],
        false,
    ),
    ts(
        80,
        2,
        "the HTTP hello answered with Server and a title, then the server's FIN: http.server, title, http (D1, B3)",
        &[Recv, Write(HTTP_200)],
        &["http.server", "title", "http"],
        false,
    ),
    ts(
        80,
        3,
        "the same response in three segments (the status line whole in the first, E2.3)",
        &[
            Recv,
            Write(b"HTTP/1.0 200 OK\r\nServer: rmasscan-lab\r\n"),
            Write(b"Content-Type: text/html\r\n\r\n"),
            Write(b"<html><title>rmasscan-lab</title></html>"),
        ],
        &["http.server", "title", "http"],
        true,
    ),
    ts(
        80,
        4,
        "HTTP/1.1 without close: the connection lives until its lifetime RST (or the end of the scan)",
        &[
            Peek,
            Write(b"HTTP/1.1 200 OK\r\nServer: rmasscan-lab\r\nContent-Length: 0\r\n\r\n"),
            Hold,
        ],
        &["http.server", "http"],
        false,
    ),
    ts(
        80,
        5,
        "the server's RST in the middle of its response (the hello left unread): the banners flush at the RST",
        &[
            Peek,
            Write(b"HTTP/1.1 200 OK\r\nServer: rmasscan-lab\r\n"),
            Reset,
        ],
        &["http.server", "http"],
        false,
    ),
    ts(
        110,
        2,
        "POP3: CAPA answered with STLS, STLS refused with -ERR (D4): the refusal line closes",
        &[
            Write(b"+OK rmasscan-lab POP3 ready\r\n"),
            Recv,
            Write(b"+OK\r\nSTLS\r\n.\r\n"),
            Recv,
            Write(b"-ERR TLS not available\r\n"),
        ],
        &["pop"],
        false,
    ),
    ts(
        143,
        2,
        "an IMAP4 greeting: \"* OK\" and two closes (D5, E3.4)",
        &[Write(b"* OK [CAPABILITY IMAP4rev1] rmasscan-lab ready\r\n")],
        &["imap"],
        false,
    ),
    ts(
        3389,
        2,
        "the RDP connection request answered with a negotiation response (D9)",
        &[
            Recv,
            Write(b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x01\x08\x00\x02\x00\x00\x00"),
        ],
        &["rdp"],
        false,
    ),
    ts(
        3389,
        5,
        "a silent server: the RDP hello stays unanswered, the connection lives until its lifetime RST or the end of the scan",
        &[Peek, Hold],
        &[],
        false,
    ),
    ts(
        5900,
        2,
        "RFB 3.8: security type None offered and chosen, SecurityResult OK, ServerInit 1024x768 named rmasscan-lab (D7)",
        &[
            Write(b"RFB 003.008\n"),
            Recv,
            Write(b"\x01\x01"),
            Recv,
            Write(b"\x00\x00\x00\x00"),
            Recv,
            Write(b"\x04\x00\x03\x00\x20\x18\x00\x01\x00\xff\x00\xff\x00\xff\x10\x08\x00\x00\x00\x00\x00\x00\x00\x0crmasscan-lab"),
        ],
        &["vnc", "vnc-info"],
        false,
    ),
    ts(
        11211,
        2,
        "the memcached hello answered with stats (D10): uptime, time and version; every segment ends with LF (E1.4)",
        &[
            Recv,
            Write(b"STAT pid 1\r\nSTAT uptime 42\r\nSTAT time 1700000000\r\nSTAT version 1.6.21\r\nEND\r\n"),
        ],
        &["memcached"],
        false,
    ),
    ts(
        25565,
        2,
        "the Minecraft status request answered with its JSON in one segment (D11, E2.7): the brace count closes",
        &[
            Recv,
            Write(b"\x72\x00\x70{\"version\":{\"name\":\"1.20\",\"protocol\":763},\"players\":{\"max\":20,\"online\":0},\"description\":{\"text\":\"rmasscan-lab\"}}"),
        ],
        &["minecraft"],
        false,
    ),
    ts(
        443,
        2,
        "TLS: the ClientHello answered with a ServerHello and a two-certificate chain in one write: ssl, the chain and the leaf certificates in banout order (reference B3, B4)",
        &[Recv, Write(TLS_CHAIN2)],
        &["ssl", "X509CA", "X509"],
        false,
    ),
    ts(
        443,
        3,
        "the same TLS stream in three segments (the record parser is split-invariant, reference B1)",
        &[
            Recv,
            Write(TLS_CHAIN2_P1),
            Write(TLS_CHAIN2_P2),
            Write(TLS_CHAIN2_P3),
        ],
        &["ssl", "X509CA", "X509"],
        true,
    ),
    ts(
        443,
        4,
        "TLS: a three-certificate chain gives two X509CA records (banout_end makes a record per chain certificate, reference B4)",
        &[Recv, Write(TLS_CHAIN3)],
        &["ssl", "X509CA", "X509CA", "X509"],
        false,
    ),
    ts(
        443,
        5,
        "TLS: a heartbeat answer of declared length 16 and a fatal alert after the ServerHello: vuln on the declaration, the alert in the ssl record (reference B3, B5, B6)",
        &[Recv, Write(TLS_HEARTBLEED)],
        &["ssl", "vuln"],
        false,
    ),
    ts(
        25,
        4,
        "SMTP STARTTLS agreed: the ClientHello goes out, then ServerHello and the chain give smtp then ssl and the cert records (reference E2.8')",
        &[
            Write(b"220 rmasscan-lab ESMTP\r\n"),
            Recv,
            Write(b"250-rmasscan-lab\r\n250 STARTTLS\r\n"),
            Recv,
            Write(b"220 2.0.0 Ready\r\n"),
            Recv,
            Write(TLS_CHAIN2),
        ],
        &["smtp", "X509CA", "X509", "ssl"],
        false,
    ),
];
/// The peer role of a stand address: its last octet (198.18.0.x) or last group (fd00:198:18::x).
pub fn peer_of(ip: IpAddr) -> Option<u8> {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            (o[..3] == [198, 18, 0] && (2..=5).contains(&o[3])).then_some(o[3])
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            (s[..7] == [0xfd00, 0x198, 0x18, 0, 0, 0, 0] && (2..=5).contains(&s[7]))
                .then_some(s[7] as u8)
        }
    }
}
/// The scenario of a stand address and TCP port, or `None` (no listener: the peer kernel resets the port).
pub fn tcp_scenario(port: u16, ip: IpAddr) -> Option<&'static TcpScenario> {
    let peer = peer_of(ip)?;
    TCP_SCENARIOS
        .iter()
        .find(|s| s.port == port && s.peer == peer)
}

// ------------------------------------------------------------------ the scenarios

/// What a peer address does with every probe it gets: one scenario per address and port.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// 198.18.0.2: the reply a server gives, with the probe's identifier.
    Answer,
    /// 198.18.0.3: the same reply with a wrong identifier (where the protocol has none: another reply of it).
    Cookie,
    /// 198.18.0.4: another form of the protocol's reply.
    VariantA,
    /// 198.18.0.5: one more.
    VariantB,
}
/// The peer addresses' last octet and their roles.
pub const ROLES: [(u8, Role); 4] = [
    (2, Role::Answer),
    (3, Role::Cookie),
    (4, Role::VariantA),
    (5, Role::VariantB),
];
pub fn role_of(ip: Ipv4Addr) -> Option<Role> {
    let o = ip.octets();
    if o[..3] != [198, 18, 0] {
        return None;
    }
    ROLES.iter().find(|(x, _)| *x == o[3]).map(|(_, r)| *r)
}
/// One scenario: what the reply is (`about`) and the applications of the banners C prints for it in order, without
/// and with `--rawudp` (the C reference's table B0; the C goldens' output of the same replies).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scenario {
    pub port: u16,
    pub role: Role,
    pub about: &'static str,
    pub banners: &'static [&'static str],
    pub rawudp: &'static [&'static str],
}
impl Scenario {
    pub fn apps(&self, rawudp: bool) -> &'static [&'static str] {
        if rawudp { self.rawudp } else { self.banners }
    }
}
const U: &str = "unknown";
const fn sc(
    port: u16,
    role: Role,
    about: &'static str,
    banners: &'static [&'static str],
    rawudp: &'static [&'static str],
) -> Scenario {
    Scenario {
        port,
        role,
        about,
        banners,
        rawudp,
    }
}
use Role::{Answer, Cookie, VariantA, VariantB};
pub const SCENARIOS: [Scenario; 36] = [
    sc(
        53,
        Answer,
        "DNS CHAOS TXT version.bind answer with the probe's id (golden dns-chaos-txt): dns-ver only (handle_dns returns 1)",
        &["dns-ver"],
        &["dns-ver", U],
    ),
    sc(
        53,
        Cookie,
        "the same answer with a wrong id: dropped by the hard cookie check (proto-dns.c:373)",
        &[],
        &[U],
    ),
    sc(
        53,
        VariantA,
        "the same answer with rcode 5: dns-ver 5:REFUSED, then the raw banner (proto-dns.c:388-409)",
        &["dns-ver", U],
        &["dns-ver", U],
    ),
    sc(
        53,
        VariantB,
        "the same message with qr 0: raw only (proto-dns.c:381)",
        &[U],
        &[U],
    ),
    sc(
        123,
        Answer,
        "NTP mode 7 MON_GETLIST_1 reply of 72 bytes (golden ntp-monlist-1): ntp text, raw",
        &["ntp", U],
        &["ntp", U],
    ),
    sc(
        123,
        Cookie,
        "NTP has no cookie: the error reply code 4 (golden ntp-monlist-err-4): ntp text, raw",
        &["ntp", U],
        &["ntp", U],
    ),
    sc(
        123,
        VariantA,
        "an NTP v4 server reply (golden ntp-v4-server): raw only, version != 2",
        &[U],
        &[U],
    ),
    sc(
        123,
        VariantB,
        "MON_GETLIST_1 announcing more than 500 bytes (golden ntp-too-big-500): response-too-big",
        &["ntp", U],
        &["ntp", U],
    ),
    sc(
        137,
        Answer,
        "NBSTAT node status with the probe's id (golden nbns-nbstat, MAC first byte 0): nbtstat, raw",
        &["nbtstat", U],
        &["nbtstat", U],
    ),
    sc(
        137,
        Cookie,
        "the same reply with a wrong id: dropped (proto-netbios.c:125-130)",
        &[],
        &[U],
    ),
    sc(
        137,
        VariantA,
        "the same reply with rcode 3: raw only (proto-netbios.c:132-141)",
        &[U],
        &[U],
    ),
    sc(
        137,
        VariantB,
        "a reply without answers (golden nbns-an0): raw only",
        &[U],
        &[U],
    ),
    sc(
        161,
        Answer,
        "SNMPv1 GetResponse sysDescr.0 and sysName.0 with the probe's request id (golden snmp-sysdescr-sysname)",
        &["snmp", U],
        &["snmp", U],
    ),
    sc(
        161,
        Cookie,
        "the same reply with a wrong request id: dropped (proto-snmp.c:567-569)",
        &[],
        &[U],
    ),
    sc(
        161,
        VariantA,
        "an SNMPv2c reply with the probe's request id (golden snmp-v2c): no banner, v1 only",
        &[],
        &[U],
    ),
    sc(
        161,
        VariantB,
        "SNMPv1 with OID values (golden snmp-oid-value): snmp text, raw",
        &["snmp", U],
        &["snmp", U],
    ),
    sc(
        500,
        Answer,
        "ISAKMP main mode SA reply with the probe's initiator cookie (golden isakmp-sample1): isakmp only",
        &["isakmp"],
        &["isakmp", U],
    ),
    sc(
        500,
        Cookie,
        "the same reply with a wrong initiator cookie: raw only (proto-isakmp.c:410-420)",
        &[U],
        &[U],
    ),
    sc(
        500,
        VariantA,
        "a reply of four known vendor ids (golden isakmp-vendor-ids): isakmp only",
        &["isakmp"],
        &["isakmp", U],
    ),
    sc(
        500,
        VariantB,
        "the SA reply with the encrypted flag: v1.0 xchg=id-prot ENCRYPTED, isakmp only",
        &["isakmp"],
        &["isakmp", U],
    ),
    sc(
        1900,
        Answer,
        "80 bytes on a port without a parser: the first 64 bytes, then the raw banner",
        &[U, U],
        &[U, U],
    ),
    sc(
        1900,
        Cookie,
        "30 bytes on a port without a parser: all 30, then the raw banner",
        &[U, U],
        &[U, U],
    ),
    sc(
        1900,
        VariantA,
        "64 bytes on a port without a parser: all 64, then the raw banner",
        &[U, U],
        &[U, U],
    ),
    sc(
        1900,
        VariantB,
        "200 bytes on a port without a parser: the first 64, then the raw banner",
        &[U, U],
        &[U, U],
    ),
    sc(
        5683,
        Answer,
        "CoAP ACK 2.05 link-format with the probe's message id (golden coap-link-format): coap, raw",
        &["coap", U],
        &["coap", U],
    ),
    sc(
        5683,
        Cookie,
        "the same reply with a wrong message id: coap text ending in IP-MISMATCH, raw (soft check)",
        &["coap", U],
        &["coap", U],
    ),
    sc(
        5683,
        VariantA,
        "the same reply as a CON message: coap_parse fails, the first 64 bytes, raw",
        &[U, U],
        &[U, U],
    ),
    sc(
        5683,
        VariantB,
        "an empty ACK with the probe's message id (golden coap-empty-ack): rsp=0.0(PARSE_ERR), raw",
        &["coap", U],
        &["coap", U],
    ),
    sc(
        11211,
        Answer,
        "memcached UDP stats with the probe's request id (golden memcached-stats): memcached, raw",
        &["memcached", U],
        &["memcached", U],
    ),
    sc(
        11211,
        Cookie,
        "the same reply with a wrong request id: memcached text ending in IP-MISMATCH, raw (soft check)",
        &["memcached", U],
        &["memcached", U],
    ),
    sc(
        11211,
        VariantA,
        "a frame header with sequence 101 (golden memcached-sequence-101): the first 64 bytes, raw",
        &[U, U],
        &[U, U],
    ),
    sc(
        11211,
        VariantB,
        "5 bytes, shorter than the frame header: raw only",
        &[U],
        &[U],
    ),
    sc(
        16464,
        Answer,
        "ZeroAccess retL listing 198.18.0.2-.4: zeroaccess, raw",
        &["zeroaccess", U],
        &["zeroaccess", U],
    ),
    sc(
        16464,
        Cookie,
        "ZeroAccess has no cookie: the same retL with a broken CRC: raw only",
        &[U],
        &[U],
    ),
    sc(
        16464,
        VariantA,
        "a retL without addresses (golden zeroaccess-no-addresses): ZeroAccess:, raw",
        &["zeroaccess", U],
        &["zeroaccess", U],
    ),
    sc(
        16464,
        VariantB,
        "the getL probe echoed back (golden zeroaccess-getl-probe): raw only",
        &[U],
        &[U],
    ),
];
pub fn scenario(port: u16, role: Role) -> Option<&'static Scenario> {
    SCENARIOS.iter().find(|s| s.port == port && s.role == role)
}

// The C goldens of tasks 4 and 5 the replies are made from (their C output is pinned there, Ethernet + IPv4 frames
// included).
pub(crate) const DNS_CHAOS_TXT: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/dns-chaos-txt.bin");
const NTP_MONLIST: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/ntp-monlist-1.bin");
const NTP_ERR_4: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/ntp-monlist-err-4.bin");
const NTP_V4: &[u8] = include_bytes!("../../../tests/golden/udp-banners/cases/ntp-v4-server.bin");
const NTP_TOO_BIG: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/ntp-too-big-500.bin");
const NBNS_NBSTAT: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/nbns-nbstat.bin");
const NBNS_AN0: &[u8] = include_bytes!("../../../tests/golden/udp-banners/cases/nbns-an0.bin");
const SNMP_SYS: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/snmp-sysdescr-sysname.bin");
const SNMP_V2C: &[u8] = include_bytes!("../../../tests/golden/udp-banners/cases/snmp-v2c.bin");
const SNMP_OID: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/snmp-oid-value.bin");
const ISAKMP_SAMPLE1: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/isakmp-sample1.bin");
const ISAKMP_VIDS: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/isakmp-vendor-ids.bin");
const COAP_LINK: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/coap-link-format.bin");
const COAP_EMPTY_ACK: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/coap-empty-ack.bin");
const MEMCACHED_STATS: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/memcached-stats.bin");
const MEMCACHED_SEQ_101: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/memcached-sequence-101.bin");
const ZEROACCESS_NONE: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/zeroaccess-no-addresses.bin");
const ZEROACCESS_GETL: &[u8] =
    include_bytes!("../../../tests/golden/udp-banners/cases/zeroaccess-getl-probe.bin");
/// Where the NBSTAT golden's MAC starts (after the header, the 34-byte name, type, class, TTL, rdlength, the name count
/// and two 18-byte entries); C prints its first byte six times (`src/proto-netbios.c:87`).
const NBSTAT_MAC_AT: usize = 93;
/// Where an SNMP reply's 4-byte request id lies in the probe and in every SNMP golden used here: `30 LL 02 01 VV 04 06
/// public A? LL 02 04 <id>` (`snmp_set_cookie` writes the probe's at the same place, `src/proto-snmp.c:403-462`).
const SNMP_REQID: std::ops::Range<usize> = 17..21;
/// The ISAKMP header's flags byte; bit 0 is "encrypted" (`src/proto-isakmp.c:287-292`).
const ISAKMP_FLAGS_AT: usize = 19;

/// A port without a parser: a printable header, then bytes C and rmasscan escape (`\xNN` in `-oL`), `len` bytes.
fn parserless(len: usize) -> Vec<u8> {
    let mut v = b"HTTP/1.1 200 OK\r\nST: rmasscan-lab\r\n".to_vec();
    v.extend(
        (0..)
            .map(|i: usize| 0x80 | (i & 0x7f) as u8)
            .take(len.saturating_sub(v.len())),
    );
    v.truncate(len);
    v
}

/// The reply of the stand's peer `ip` to the probe payload `probe` on UDP `port`: the table's scenario
/// ([`SCENARIOS`]) with the probe's identifier copied in (or spoiled: its last byte inverted). `None` for an address
/// off the four peers, a port off the table, or a probe too short to carry the identifier (then the stand does not
/// answer, and the verifier names the probe it did not answer).
pub fn scenario_reply(port: u16, ip: Ipv4Addr, probe: &[u8]) -> Option<Vec<u8>> {
    let role = role_of(ip)?;
    // The template with the probe's bytes `at` copied in; with `spoil`, the last of them inverted.
    let echo = |template: &[u8], at: std::ops::Range<usize>, spoil: bool| -> Option<Vec<u8>> {
        let mut t = template.to_vec();
        let last = at.end.checked_sub(1)?;
        t.get_mut(at.clone())?.copy_from_slice(probe.get(at)?);
        if spoil {
            t[last] ^= 0xff;
        }
        Some(t)
    };
    match (port, role) {
        (53, Answer) => echo(DNS_CHAOS_TXT, 0..2, false),
        (53, Cookie) => echo(DNS_CHAOS_TXT, 0..2, true),
        (53, VariantA) => echo(DNS_CHAOS_TXT, 0..2, false).map(|mut r| {
            r[3] = (r[3] & 0xf0) | 5;
            r
        }),
        (53, VariantB) => echo(DNS_CHAOS_TXT, 0..2, false).map(|mut r| {
            r[2] = 0;
            r[3] = 0;
            r
        }),
        (123, Answer) => Some(NTP_MONLIST.to_vec()),
        (123, Cookie) => Some(NTP_ERR_4.to_vec()),
        (123, VariantA) => Some(NTP_V4.to_vec()),
        (123, VariantB) => Some(NTP_TOO_BIG.to_vec()),
        (137, r) => {
            let mut t = NBNS_NBSTAT.to_vec();
            *t.get_mut(NBSTAT_MAC_AT)? = 0;
            match r {
                Answer => echo(&t, 0..2, false),
                Cookie => echo(&t, 0..2, true),
                VariantA => echo(&t, 0..2, false).map(|mut r| {
                    r[3] = (r[3] & 0xf0) | 3;
                    r
                }),
                VariantB => echo(NBNS_AN0, 0..2, false),
            }
        }
        (161, r) => {
            if probe.get(15..17) != Some(&[2, 4][..]) {
                return None;
            }
            match r {
                Answer => echo(SNMP_SYS, SNMP_REQID, false),
                Cookie => echo(SNMP_SYS, SNMP_REQID, true),
                VariantA => echo(SNMP_V2C, SNMP_REQID, false),
                VariantB => echo(SNMP_OID, SNMP_REQID, false),
            }
        }
        (500, Answer) => echo(ISAKMP_SAMPLE1, 0..8, false),
        (500, Cookie) => echo(ISAKMP_SAMPLE1, 0..8, true),
        (500, VariantA) => echo(ISAKMP_VIDS, 0..8, false),
        (500, VariantB) => echo(ISAKMP_SAMPLE1, 0..8, false).map(|mut r| {
            r[ISAKMP_FLAGS_AT] |= 1;
            r
        }),
        (1900, r) => Some(parserless(match r {
            Answer => 80,
            Cookie => 30,
            VariantA => 64,
            VariantB => 200,
        })),
        (5683, Answer) => echo(COAP_LINK, 2..4, false),
        (5683, Cookie) => echo(COAP_LINK, 2..4, true),
        (5683, VariantA) => echo(COAP_LINK, 2..4, false).map(|mut r| {
            // version 1, type CON (0), the same token length: no longer an ACK (proto-coap.c:288-331)
            r[0] &= 0xcf;
            r
        }),
        (5683, VariantB) => echo(COAP_EMPTY_ACK, 2..4, false),
        (11211, Answer) => echo(MEMCACHED_STATS, 0..2, false),
        (11211, Cookie) => echo(MEMCACHED_STATS, 0..2, true),
        (11211, VariantA) => echo(MEMCACHED_SEQ_101, 0..2, false),
        (11211, VariantB) => echo(&MEMCACHED_STATS[..5], 0..2, false),
        (16464, Answer) => Some(zeroaccess_retl(&stand().peer_ips[..3])),
        (16464, Cookie) => {
            let mut r = zeroaccess_retl(&stand().peer_ips[..3]);
            r[16] ^= 0x01;
            Some(r)
        }
        (16464, VariantA) => Some(ZEROACCESS_NONE.to_vec()),
        (16464, VariantB) => Some(ZEROACCESS_GETL.to_vec()),
        _ => None,
    }
}

/// The cookie bits a parser checks, read from a probe (or a reply that echoes it) of UDP `port`: the DNS and
/// NetBIOS id, the SNMP request id, the ISAKMP initiator cookie's low 32 bits, the CoAP message id, the memcached
/// request id; 0 where the port has none. Each parser masks the 32-bit cookie itself (`& 0xFFFF`, `& 0x7FFFFFFF`), so
/// these bits are all it reads of it.
pub fn probe_cookie(port: u16, payload: &[u8]) -> u32 {
    let be = |r: std::ops::Range<usize>| {
        payload
            .get(r)
            .map_or(0, |b| b.iter().fold(0u32, |a, x| (a << 8) | u32::from(*x)))
    };
    match port {
        53 | 137 | 11211 => be(0..2),
        161 => be(SNMP_REQID),
        500 => be(4..8),
        5683 => be(2..4),
        _ => 0,
    }
}

// ------------------------------------------------------------------ ZeroAccess

/// CRC-32 (the reflected polynomial 0xEDB88320, `crc_calc`, `src/proto-zeroaccess.c:31-103`).
fn crc32(px: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in px {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}
/// XOR with the key `ftp2` that rotates left one bit after every 4-byte word (`zadecrypt`,
/// `src/proto-zeroaccess.c:111-129`); its own inverse.
fn za_xor(src: &[u8]) -> Vec<u8> {
    let mut key = u32::from_be_bytes(*b"ftp2");
    let mut out = Vec::with_capacity(src.len());
    for word in src.chunks(4) {
        out.extend(word.iter().zip(key.to_le_bytes()).map(|(b, k)| b ^ k));
        key = key.rotate_left(1);
    }
    out
}
/// A ZeroAccess packet sealed the way C opens it: the CRC-32 of the plaintext with its first 4 bytes zeroed, stored
/// little-endian in those bytes, then the XOR stream (`src/proto-zeroaccess.c:170-226`).
pub fn zeroaccess_seal(plain: &[u8]) -> Vec<u8> {
    let mut b = plain.to_vec();
    if let Some(h) = b.get_mut(..4) {
        h.fill(0);
        let crc = crc32(&b);
        b[..4].copy_from_slice(&crc.to_le_bytes());
    }
    za_xor(&b)
}
/// The plaintext of a ZeroAccess packet.
pub fn zeroaccess_open(cipher: &[u8]) -> Vec<u8> {
    za_xor(cipher)
}
/// A `retL` listing `addrs`: CRC, `Lter`, 4 bytes, the count, 8 bytes per peer (address and 4 more bytes).
pub fn zeroaccess_retl(addrs: &[Ipv4Addr]) -> Vec<u8> {
    let mut plain = [
        &[0u8; 4][..],
        b"Lter",
        b"mass",
        &(addrs.len() as u32).to_le_bytes(),
    ]
    .concat();
    for a in addrs {
        plain.extend(a.octets());
        plain.extend([0x5e, 0xed, 0, 1]);
    }
    zeroaccess_seal(&plain)
}

// ------------------------------------------------------------------ the stand

pub fn stand() -> Stand {
    av::stand(Plan::Linux)
}
/// The responder's options after `capture responder` (its `--ready` aside): the stand's TCP listeners, one UDP
/// socket per peer address and window port, each answering with [`scenario_reply`].
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
        list(&pv::TCP_OPEN),
        "--udp-ports".into(),
        list(&PORTS),
        "--udp-ips".into(),
        ips,
        "--udp-answer".into(),
        UDP_ANSWER.into(),
    ]
}
/// `peer-tcp.json` of a TCP case: what the peer namespace does with a closed connection. Every step of a case uses the
/// 4-tuples of the step before (seed 1, source port 40000: the same SYN cookie), and a SYN that meets a TIME_WAIT
/// socket of the peer without a later sequence number gets an ACK, not a SYN-ACK (`tcp_timewait_state_process`); so
/// the banners stand keeps no TIME_WAIT socket in the peer namespace (`net.ipv4.tcp_max_tw_buckets` 0, `wire-lab.sh
/// --suite banners`), and the suite reads it before each TCP case.
pub const PEER_TCP_JSON: &str = "peer-tcp.json";
pub const TW_BUCKETS: &str = "/proc/sys/net/ipv4/tcp_max_tw_buckets";
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerTcp {
    /// `net.ipv4.tcp_max_tw_buckets` of the peer namespace (`0`: a closed connection leaves no TIME_WAIT socket).
    pub tcp_max_tw_buckets: String,
}
/// Why the peer namespace would keep a closed connection's 4-tuple from the next step, or `None`.
pub fn peer_tcp_problem(p: &PeerTcp) -> Option<String> {
    (p.tcp_max_tw_buckets != "0").then(|| {
        format!(
            "net.ipv4.tcp_max_tw_buckets is {} in the peer namespace, not 0 (wire-lab.sh --suite banners sets it): a TIME_WAIT socket would answer the next step's SYN with an ACK",
            p.tcp_max_tw_buckets
        )
    })
}
/// `<step>/neigh-flush.json` of a resolve case: the command the suite ran in the peer namespace before the step so
/// that the peer resolves the source afresh with this step's scanner, and its exit code.
pub const NEIGH_FLUSH_JSON: &str = "neigh-flush.json";
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NeighFlush {
    pub argv: Vec<String>,
    pub rc: i32,
}
/// The flush of the peer's neighbour entry for `src` in namespace `ns`: `ip -n NS [-6] neigh flush to SRC dev
/// veth-b`.
pub fn neigh_flush_argv(ns: &str, src: IpAddr) -> Vec<String> {
    let mut a: Vec<String> = vec![crate::autodetect_suite::IP.into(), "-n".into(), ns.into()];
    if src.is_ipv6() {
        a.push("-6".into());
    }
    a.extend(["neigh", "flush", "to", &src.to_string(), "dev", pv::PEER_IF].map(str::to_owned));
    a
}
/// Why a step's flush record does not show the peer's entry for the case's source flushed, or `None`.
pub fn neigh_flush_problem(f: &NeighFlush, c: &TcpCase) -> Option<String> {
    let ns = f.argv.get(2).map_or("", String::as_str);
    if f.argv != neigh_flush_argv(ns, c.source()) || ns.is_empty() {
        return Some(format!(
            "{:?} is not the flush of the peer's entry for {} ({:?})",
            f.argv,
            c.source(),
            neigh_flush_argv("<peer namespace>", c.source())
        ));
    }
    (f.rc != 0).then(|| format!("the flush exited {}", f.rc))
}
/// The responder of a TCP case (`capture responder --tcp-answer banners`): a kernel socket on every peer address of
/// the stand (IPv4 and IPv6) and every TCP port of the window that has a scenario there, answering with
/// [`TCP_SCENARIOS`] by the connection's local address and port, and the heartbeat ([`HEARTBEAT_PAYLOAD`]) on the
/// peer link to the scanner MAC for the case's wait plus [`HEARTBEAT_AFTER_WAIT_S`] (none for the quiet control).
pub fn tcp_responder_args(c: &TcpCase) -> Vec<String> {
    let st = stand();
    let mut ips: Vec<String> = st.peer_ips.iter().map(Ipv4Addr::to_string).collect();
    ips.extend(capture::IPV6_PEERS.iter().map(|s| (*s).to_owned()));
    let ports: BTreeSet<u16> = TCP_SCENARIOS.iter().map(|x| x.port).collect();
    let mut a: Vec<String> = vec![
        "--tcp-answer".into(),
        TCP_ANSWER.into(),
        "--tcp-ips".into(),
        ips.join(","),
        "--tcp-ports".into(),
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(","),
    ];
    if c.quiet {
        return a;
    }
    a.extend([
        "--heartbeat-iface".into(),
        pv::PEER_IF.into(),
        "--heartbeat-dst".into(),
        st.scanner_mac
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
        "--heartbeat-secs".into(),
        (c.wait + HEARTBEAT_AFTER_WAIT_S).to_string(),
    ]);
    a
}
/// The responder of a case: 4a's for a UDP case, [`tcp_responder_args`] for a TCP case.
pub fn responder_args_for(c: &Case) -> Vec<String> {
    match c {
        Case::Udp(_) => responder_args(),
        Case::Tcp(t) => tcp_responder_args(t),
    }
}
/// [`peer_stack_problem`] with the responder of case `c`.
pub fn peer_stack_problem_for(p: &PeerStack, c: &Case) -> Option<String> {
    let want = responder_args_for(c);
    if p.responder != want {
        return Some(format!(
            "the responder runs with {:?}, not the stand's {want:?}",
            p.responder
        ));
    }
    peer_stack_problem(&PeerStack {
        responder: responder_args(),
        ..p.clone()
    })
}
/// Why a peer stack cannot answer the window the stand's way, or `None`: ICMP errors not rate-limited and Echo
/// answered (the protocols stand, `wire-lab.sh --suite banners` sets the first), the banners responder.
pub fn peer_stack_problem(p: &PeerStack) -> Option<String> {
    if p.icmp_ratemask != "0" {
        return Some(format!(
            "net.ipv4.icmp_ratemask is {} in the peer namespace, not 0 (wire-lab.sh --suite banners sets it)",
            p.icmp_ratemask
        ));
    }
    if p.icmp_echo_ignore_all != "0" {
        return Some(format!(
            "net.ipv4.icmp_echo_ignore_all is {} in the peer namespace",
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
    None
}

// ------------------------------------------------------------------ frames

/// The UDP payload of an Ethernet + IPv4 frame without options, within the IPv4 total length.
fn udp_payload(f: &[u8]) -> Option<&[u8]> {
    if f.len() < 42 || f[12..14] != [8, 0] || f[14] != 0x45 || f[23] != 17 {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([f[16], f[17]]));
    f.get(42..14 + total)
}

// ------------------------------------------------------------------ TCP frames

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;
/// A TCP segment of a frame (Ethernet + IPv4 without options or IPv6, `ipv6_verify::pkt`).
#[derive(Debug, Clone, PartialEq)]
pub struct TcpHead {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub ttl: u8,
    pub sp: u16,
    pub dp: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
}
pub fn tcp_head(f: &[u8]) -> Option<TcpHead> {
    let p = iv::pkt(f)?;
    if p.proto != 6 || p.l4.len() < 20 {
        return None;
    }
    let l4 = p.l4;
    let off = usize::from(l4[12] >> 4) * 4;
    if off < 20 {
        return None;
    }
    Some(TcpHead {
        src: p.src,
        dst: p.dst,
        ttl: p.ttl,
        sp: be16(l4, 0),
        dp: be16(l4, 2),
        seq: be32(l4, 4),
        ack: be32(l4, 8),
        flags: l4[13],
        payload: l4.get(off..)?.to_vec(),
    })
}
fn ones(data: &[u8], init: u32) -> u32 {
    let mut s = init;
    for c in data.chunks(2) {
        s += (u32::from(c[0]) << 8) | u32::from(*c.get(1).unwrap_or(&0));
    }
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    s
}
/// The IPv4 header checksum of a frame is right (computed here, not with the product's sum).
pub fn ipv4_header_sum_ok(f: &[u8]) -> bool {
    f.get(12..14) != Some(&[8, 0][..]) || f.get(14..34).is_some_and(|h| ones(h, 0) == 0xffff)
}
/// The TCP checksum of a frame is right, with its family's pseudo-header (RFC 793, RFC 8200 §8.1).
pub fn tcp_sum_ok(f: &[u8]) -> bool {
    l4_sum_ok(f, 6)
}
/// The ICMPv6 checksum of a frame is right (RFC 4443 §2.3: the IPv6 pseudo-header).
pub fn icmp6_sum_ok(f: &[u8]) -> bool {
    iv::pkt(f).is_some_and(|p| p.src.is_ipv6()) && l4_sum_ok(f, 58)
}
/// The upper-layer checksum of a frame whose upper protocol is `proto`, with its family's pseudo-header.
fn l4_sum_ok(f: &[u8], proto: u8) -> bool {
    let Some(p) = iv::pkt(f) else { return false };
    let mut pseudo = Vec::with_capacity(40);
    match (p.src, p.dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            pseudo.extend(s.octets());
            pseudo.extend(d.octets());
            pseudo.extend([0, proto]);
            pseudo.extend((p.l4.len() as u16).to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            pseudo.extend(s.octets());
            pseudo.extend(d.octets());
            pseudo.extend((p.l4.len() as u32).to_be_bytes());
            pseudo.extend([0, 0, 0, proto]);
        }
        _ => return false,
    }
    p.proto == proto && ones(p.l4, ones(&pseudo, 0)) == 0xffff
}
/// One segment of a connection as the comparison sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Seg {
    pub t: f64,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub payload: Vec<u8>,
    /// Both of its sums are right (IPv4 header and TCP).
    pub sums_ok: bool,
    /// Its IPv4 header checksum is right (always for IPv6).
    pub ip_sum_ok: bool,
    /// The frame as captured (the stateless RST of `t05_stateless_rst` is judged in its whole form, L-M1).
    pub frame: Vec<u8>,
}
/// A segment of the scanner, relative to its connection (the SYN's and the reply's sequence numbers): flags,
/// payload, sequence, and acknowledgment (`None` for a RST without ACK whose ack field is 0, the stateless form).
pub type RelSeg = (u8, Vec<u8>, u32, Option<u32>);
/// A SYN of the scanner.
#[derive(Debug, Clone, PartialEq)]
pub struct TcpProbe {
    pub t: f64,
    pub ip: IpAddr,
    pub port: u16,
    pub sport: u16,
    pub seq: u32,
    pub frame: Vec<u8>,
    /// A second SYN to a target an earlier probe already went to, from another source port: the stack's second
    /// connection (`stream->next`, reference §D1), not a probe of the plan.
    pub reconnect: bool,
}
/// One probe the peer answered: a connection from its SYN-ACK, or a closed port's RST.
#[derive(Debug, Clone, PartialEq)]
pub struct Conn {
    pub probe: usize,
    pub ip: IpAddr,
    pub port: u16,
    pub sport: u16,
    /// The stack's second connection to the same target (its probe is marked reconnect).
    pub reconnect: bool,
    pub open: bool,
    pub reply_t: f64,
    pub reply_flags: u8,
    pub reply_ttl: u8,
    pub reply_ack: u32,
    /// Both sums of the reply are right (IPv4 header and TCP): rmasscan drops a reply with a wrong one, C reads it.
    pub reply_sums_ok: bool,
    /// The peer's initial sequence number (its SYN-ACK's, or the RST's sequence number).
    pub iss_them: u32,
    pub iss_me: u32,
    /// Repeats of the reply (the peer kernel retransmits a SYN-ACK nobody answered).
    pub repeats: usize,
    pub scanner: Vec<Seg>,
    pub peer: Vec<Seg>,
}
impl Conn {
    fn rel(&self, s: &Seg) -> RelSeg {
        let ack = (s.flags & ACK != 0 || s.ack != 0).then(|| s.ack.wrapping_sub(self.iss_them));
        (
            s.flags,
            s.payload.clone(),
            s.seq.wrapping_sub(self.iss_me),
            ack,
        )
    }
    /// The peer's data segments, in wire order.
    pub fn peer_data(&self) -> Vec<&Seg> {
        self.peer.iter().filter(|s| !s.payload.is_empty()).collect()
    }
    /// How many segments the peer's stream came in: its data segments at distinct sequence numbers (a
    /// retransmission is no second segment of a split delivery).
    pub fn peer_segments(&self) -> usize {
        self.peer_data()
            .iter()
            .map(|s| s.seq)
            .collect::<BTreeSet<u32>>()
            .len()
    }
    /// The peer's stream: its data in sequence order, each byte once, up to the first hole.
    pub fn peer_stream(&self) -> Vec<u8> {
        let base = self.iss_them.wrapping_add(1);
        let mut segs: Vec<(usize, &[u8])> = self
            .peer_data()
            .into_iter()
            .map(|s| (s.seq.wrapping_sub(base) as usize, &s.payload[..]))
            .collect();
        segs.sort_by_key(|x| x.0);
        let mut out = Vec::new();
        for (at, p) in segs {
            if at > out.len() {
                break;
            }
            if let Some(rest) = p.get(out.len() - at..) {
                out.extend(rest);
            }
        }
        out
    }
    /// How many bytes of `sc`'s stream the peer owes on this connection, from the scanner's frames on the wire (the
    /// final review's "owed stream" rule, L-I1 and L-I2). The script (`capture::run_script`, [`TcpStep`]) starts once
    /// the handshake is complete, at the scanner's first ACK that is no reset; its leading writes are owed from
    /// there. A `Recv` or `Peek` waits for new data of the scanner (bytes past every earlier segment's, a
    /// retransmission is none) that came after the peer's last write on the wire (earlier data went to an earlier
    /// read): the scanner's FIN or RST before it, or no such data at all, ends the script there. A `Write` is owed
    /// unless the scanner's RST came before the peer had [`SCRIPT_PAUSE_MS`] to make it (from the data it answers,
    /// or from its previous write and that write's pause). `Reset` and `Hold` write nothing. A peer stream shorter than
    /// this is the stand's fault (INVALID); one shorter than the script but as long as this is the scanner's doing (no
    /// handshake, no hello, no reply the script waits for, a FIN or RST first), which the scanner's own checks and the
    /// comparisons with C judge. A write found missing ends the walk: the stream is short of what is owed already.
    pub fn owed(&self, sc: &TcpScenario) -> usize {
        let pause = SCRIPT_PAUSE_MS as f64 / 1000.0;
        if !self.open {
            return 0;
        }
        let rst = self
            .scanner
            .iter()
            .find(|g| g.flags & RST != 0)
            .map(|g| g.t);
        let fin = self
            .scanner
            .iter()
            .find(|g| g.flags & FIN != 0)
            .map(|g| g.t);
        let Some(mut at) = self
            .scanner
            .iter()
            .take_while(|g| g.flags & RST == 0)
            .find(|g| g.flags & ACK != 0 && g.flags & SYN == 0)
            .map(|g| g.t)
        else {
            return 0;
        };
        // The times of the scanner's segments that carry bytes past every earlier one's.
        let me = self.iss_me.wrapping_add(1);
        let mut high = 0u64;
        let mut fresh = Vec::new();
        for g in self.scanner.iter().filter(|g| !g.payload.is_empty()) {
            let end = u64::from(g.seq.wrapping_sub(me)) + g.payload.len() as u64;
            if end > high {
                high = end;
                fresh.push(g.t);
            }
        }
        // When the peer's byte at `offset` of its stream first went on the wire.
        let them = self.iss_them.wrapping_add(1);
        let wrote = |offset: usize| {
            self.peer
                .iter()
                .filter(|g| !g.payload.is_empty())
                .find(|g| {
                    let from = g.seq.wrapping_sub(them) as usize;
                    from <= offset && offset < from + g.payload.len()
                })
                .map(|g| g.t)
        };
        let (mut owed, mut next, mut last_write) = (0usize, 0usize, None::<f64>);
        for step in sc.steps {
            match step {
                TcpStep::Write(b) => {
                    if rst.is_some_and(|r| r <= at + pause) {
                        break;
                    }
                    let start = owed;
                    owed += b.len();
                    let Some(w) = wrote(start) else { break };
                    last_write = Some(w);
                    at = w + pause;
                }
                TcpStep::Recv | TcpStep::Peek => {
                    let Some(k) =
                        (next..fresh.len()).find(|&k| last_write.is_none_or(|w| fresh[k] > w))
                    else {
                        break;
                    };
                    let t = fresh[k];
                    if fin.is_some_and(|f| f < t) || rst.is_some_and(|r| r < t) {
                        break;
                    }
                    if *step == TcpStep::Recv {
                        next = k + 1;
                    }
                    at = at.max(t);
                }
                TcpStep::Reset | TcpStep::Hold => break,
            }
        }
        owed
    }
    /// When the connection was destroyed on the wire: the scanner's RST, the peer's RST, or the peer's ACK of the
    /// scanner's FIN after the peer's own FIN (LAST_ACK, `src/stack-tcp-core.c:2300-2313`).
    pub fn destroyed_at(&self) -> Option<f64> {
        let mut at: Vec<f64> = Vec::new();
        at.extend(
            self.scanner
                .iter()
                .find(|s| s.flags & RST != 0)
                .map(|s| s.t),
        );
        at.extend(self.peer.iter().find(|s| s.flags & RST != 0).map(|s| s.t));
        let peer_fin = self.peer.iter().find(|s| s.flags & FIN != 0).map(|s| s.t);
        if let (Some(pf), Some(sf)) = (peer_fin, self.scanner.iter().find(|s| s.flags & FIN != 0))
            && pf < sf.t
        {
            let end = sf.seq.wrapping_add(sf.payload.len() as u32 + 1);
            at.extend(
                self.peer
                    .iter()
                    .find(|p| p.t > sf.t && p.flags & ACK != 0 && p.ack == end)
                    .map(|p| p.t),
            );
        }
        at.into_iter().reduce(f64::min)
    }
    /// A segment of the scanner is the stack's RST to a FIN of the peer that came after the connection was destroyed:
    /// R8's RST to a FIN without a connection (`src/main.c:1019-1041`, `tcpcon_send_RST`,
    /// `src/stack-tcp-core.c:1261-1282`: flags 0x04, seq the FIN's ack).
    pub fn rst_to_fin_without_tcb(&self, s: &Seg) -> bool {
        let Some(d) = self.destroyed_at() else {
            return false;
        };
        s.t > d
            && s.flags == RST
            && self.peer.iter().any(|p| {
                p.t > d && p.t <= s.t && p.flags & FIN != 0 && p.flags & RST == 0 && p.ack == s.seq
            })
    }
    /// The scanner's segments after the connection was destroyed, but a RST to a FIN of the peer (the stack's RST to
    /// a FIN without a connection, [`Conn::rst_to_fin_without_tcb`]).
    pub fn after_destroy(&self) -> Vec<&Seg> {
        let Some(d) = self.destroyed_at() else {
            return Vec::new();
        };
        self.scanner
            .iter()
            .filter(|s| s.t > d && !self.rst_to_fin_without_tcb(s))
            .collect()
    }
    /// The scanner's segments as the comparison with C sees them.
    pub fn sequence(&self) -> Vec<RelSeg> {
        self.scanner.iter().map(|s| self.rel(s)).collect()
    }
}
/// One capture of a TCP step, taken apart.
#[derive(Debug, Default)]
pub struct TcpView {
    pub probes: Vec<TcpProbe>,
    pub conns: Vec<Conn>,
    /// The peer's ARP who-has and Neighbor Solicitations for the case's source.
    pub requests: Vec<(f64, Vec<u8>)>,
    /// The scanner's ARP replies and Neighbor Advertisements for its source.
    pub answers: Vec<(f64, Vec<u8>)>,
    /// Segments of a scrubbed TCB of C (E1.5): IPv4 TCP from and to 255.255.255.255, ports 65535.
    pub scrubbed: Vec<(f64, Vec<u8>)>,
    pub heartbeats: Vec<f64>,
    /// IPv6 kernel traffic of either MAC that the stand rules out (MLD, router discovery, DAD).
    pub noise: Vec<String>,
    pub scanner_unexplained: Vec<String>,
    pub peer_unexpected: Vec<String>,
    /// Frames of the peer that answer an earlier unexplained frame of the scanner (its TCP 4-tuple mirrored, or a
    /// request for the address it came from): the scanner's doing, judged by its unexplained frame, not the stand's.
    pub peer_answers_to_scanner: Vec<String>,
    /// Frames of the scanner that answer an earlier unexpected frame of the peer (its TCP 4-tuple mirrored, as the
    /// stack's RST to a FIN without a connection): the stand's doing, judged by the peer's frame.
    pub scanner_answers_to_peer: Vec<String>,
    pub outside_window: usize,
    /// The capture's window (last start marker, first end marker).
    pub window: (f64, f64),
}
impl TcpView {
    pub fn probe_frames(&self) -> Vec<Vec<u8>> {
        self.probes
            .iter()
            .filter(|p| !p.reconnect)
            .map(|p| p.frame.clone())
            .collect()
    }
    fn conn_of(&self, ip: IpAddr, port: u16, sport: u16) -> Option<usize> {
        self.conns
            .iter()
            .position(|c| c.ip == ip && c.port == port && c.sport == sport)
    }
    /// The time of the last frame of the scan on this capture.
    pub fn last_frame(&self) -> Option<f64> {
        self.conns
            .iter()
            .flat_map(|c| {
                c.scanner
                    .iter()
                    .chain(&c.peer)
                    .map(|s| s.t)
                    .chain([c.reply_t])
            })
            .chain(self.probes.iter().map(|p| p.t))
            .reduce(f64::max)
    }
}
/// ICMPv6 of a packet: its type and the target address of an NS or NA.
fn icmp6(p: &iv::Pkt) -> Option<(u8, Option<Ipv6Addr>)> {
    if p.proto != 58 || p.l4.is_empty() {
        return None;
    }
    let target =
        p.l4.get(8..24)
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .map(Ipv6Addr::from);
    Some((p.l4[0], target))
}
fn describe_frame(f: &[u8]) -> String {
    match iv::pkt(f) {
        Some(p) => match tcp_head(f) {
            Some(h) => format!(
                "TCP flags {:#04x} {}:{} > {}:{}",
                h.flags, h.src, h.sp, h.dst, h.dp
            ),
            None => format!("IP protocol {} {} > {}", p.proto, p.src, p.dst),
        },
        None => format!(
            "a {}-byte frame of ethertype {:02x}{:02x}",
            f.len(),
            f.get(12).copied().unwrap_or(0),
            f.get(13).copied().unwrap_or(0)
        ),
    }
}
/// An IPv6 frame only a kernel sends on the stand: MLD (ICMPv6 130, 131, 132, 143), a router solicitation (133) or a
/// DAD Neighbor Solicitation (from `::`).
fn ipv6_kernel_noise(f: &[u8]) -> bool {
    iv::pkt(f).is_some_and(|p| {
        p.src.is_ipv6()
            && icmp6(&p).is_some_and(|(ty, _)| {
                matches!(ty, 130 | 131 | 132 | 143 | 133)
                    || (ty == 135 && p.src == IpAddr::V6(Ipv6Addr::UNSPECIFIED))
            })
    })
}
/// A TCP 4-tuple as a frame carries it: (source, source port, destination, destination port).
type Tuple = (IpAddr, u16, IpAddr, u16);
/// The other direction of a 4-tuple.
fn mirrored(t: Tuple) -> Tuple {
    (t.2, t.3, t.0, t.1)
}
/// A capture of a TCP step: the scanner's SYNs from the case's source, every connection the peer opened or reset with
/// both sides' segments, the resolution of the source (resolve cases), the heartbeat, and everything else named. A
/// stray frame of one side that answers an earlier stray frame of the other is put to the side that began
/// ([`TcpView::peer_answers_to_scanner`], [`TcpView::scanner_answers_to_peer`]).
pub fn tcp_view(c: &TcpCase, fr: &Frames, st: &Stand) -> TcpView {
    let w = av::classify(fr, st.scanner_mac);
    let (start, end) = av::window(&w);
    let src = c.source();
    let mut v = TcpView {
        window: (start, end),
        ..TcpView::default()
    };
    let scrubbed_ip = IpAddr::V4(Ipv4Addr::BROADCAST);
    // The TCP 4-tuples of the scanner's unexplained frames and the addresses they came from, and the 4-tuples of the
    // peer's unexpected TCP frames, so far.
    let mut scanner_stray: BTreeSet<Tuple> = BTreeSet::new();
    let mut stray_sources: BTreeSet<IpAddr> = BTreeSet::new();
    let mut peer_stray: BTreeSet<Tuple> = BTreeSet::new();
    for (t, f) in fr {
        let t = *t;
        let from_scanner = f.get(6..12) == Some(&st.scanner_mac[..]);
        let from_peer = f.get(6..12) == Some(&st.peer_mac[..]);
        let odd = |what: String, v: &mut TcpView| {
            if from_scanner {
                v.scanner_unexplained.push(what);
            } else if from_peer {
                v.peer_unexpected.push(what);
            }
        };
        // A stray TCP frame: put to the side that began, by the 4-tuple of the other side's earlier stray frame.
        let tuple = tcp_head(f).map(|h| (h.src, h.sp, h.dst, h.dp));
        let stray = |what: String,
                     v: &mut TcpView,
                     scanner_stray: &mut BTreeSet<Tuple>,
                     stray_sources: &mut BTreeSet<IpAddr>,
                     peer_stray: &mut BTreeSet<Tuple>| {
            match tuple {
                Some(k) if from_scanner && peer_stray.contains(&mirrored(k)) => {
                    v.scanner_answers_to_peer.push(what);
                }
                Some(k) if from_peer && scanner_stray.contains(&mirrored(k)) => {
                    v.peer_answers_to_scanner.push(what);
                }
                Some(k) if from_scanner => {
                    scanner_stray.insert(k);
                    stray_sources.insert(k.0);
                    v.scanner_unexplained.push(what);
                }
                Some(k) if from_peer => {
                    peer_stray.insert(k);
                    v.peer_unexpected.push(what);
                }
                _ => odd(what, v),
            }
        };
        if f.get(12..14) == Some(&crate::link::MARKER_ETHERTYPE[..]) {
            if from_peer
                && f.get(14..)
                    .is_some_and(|b| b.starts_with(HEARTBEAT_PAYLOAD))
            {
                v.heartbeats.push(t);
            }
            continue;
        }
        if f.get(12..14) == Some(&[8, 6][..]) {
            let (op, spa, tpa) = (
                f.get(20..22).map(|b| be16(b, 0)),
                f.get(28..32).map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3])),
                f.get(38..42).map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3])),
            );
            match (from_peer, from_scanner, op, src) {
                (true, _, Some(1), IpAddr::V4(s)) if tpa == Some(s) => {
                    v.requests.push((t, f.clone()))
                }
                (_, true, Some(2), IpAddr::V4(s)) if spa == Some(s) => {
                    v.answers.push((t, f.clone()))
                }
                // The peer resolves the address a stray frame of the scanner came from, to answer it.
                (true, _, Some(1), _)
                    if tpa.is_some_and(|a| stray_sources.contains(&IpAddr::V4(a))) =>
                {
                    v.peer_answers_to_scanner.push(format!(
                        "{}, for a source of the scanner's stray frame",
                        describe_frame(f)
                    ))
                }
                _ => odd(describe_frame(f), &mut v),
            }
            continue;
        }
        let Some(p) = iv::pkt(f) else {
            odd(describe_frame(f), &mut v);
            continue;
        };
        if let Some((ty, target)) = icmp6(&p) {
            match (ty, src) {
                (130 | 131 | 132 | 143, _) => v.noise.push(format!("MLD (ICMPv6 {ty})")),
                (133 | 134, _) => v.noise.push(format!("router discovery (ICMPv6 {ty})")),
                (135, _) if p.src == IpAddr::V6(Ipv6Addr::UNSPECIFIED) => {
                    v.noise.push("a DAD Neighbor Solicitation".into());
                }
                (135, IpAddr::V6(s)) if from_peer && target == Some(s) => {
                    v.requests.push((t, f.clone()));
                }
                (136, IpAddr::V6(s)) if from_scanner && target == Some(s) => {
                    v.answers.push((t, f.clone()));
                }
                (135, _)
                    if from_peer
                        && target.is_some_and(|a| stray_sources.contains(&IpAddr::V6(a))) =>
                {
                    v.peer_answers_to_scanner.push(format!(
                        "{}, for a source of the scanner's stray frame",
                        describe_frame(f)
                    ))
                }
                _ => odd(describe_frame(f), &mut v),
            }
            continue;
        }
        let Some(h) = tcp_head(f) else {
            odd(describe_frame(f), &mut v);
            continue;
        };
        let seg = Seg {
            t,
            flags: h.flags,
            seq: h.seq,
            ack: h.ack,
            payload: h.payload.clone(),
            sums_ok: ipv4_header_sum_ok(f) && tcp_sum_ok(f),
            ip_sum_ok: ipv4_header_sum_ok(f),
            frame: f.clone(),
        };
        let inside = (start..=end).contains(&t);
        let mut stray = |what: String, v: &mut TcpView| {
            stray(
                what,
                v,
                &mut scanner_stray,
                &mut stray_sources,
                &mut peer_stray,
            )
        };
        if from_scanner {
            if h.src == scrubbed_ip && h.dst == scrubbed_ip && h.sp == 0xffff && h.dp == 0xffff {
                v.scrubbed.push((t, f.clone()));
            } else if h.src != src {
                stray(describe_frame(f), &mut v);
            } else if h.flags & 0x3f == SYN {
                v.outside_window += usize::from(!inside);
                let reconnect = v
                    .probes
                    .iter()
                    .any(|p| p.ip == h.dst && p.port == h.dp && p.sport != h.sp);
                v.probes.push(TcpProbe {
                    t,
                    ip: h.dst,
                    port: h.dp,
                    sport: h.sp,
                    seq: h.seq,
                    frame: f.clone(),
                    reconnect,
                });
            } else if let Some(i) = v.conn_of(h.dst, h.dp, h.sp) {
                v.conns[i].scanner.push(seg);
            } else {
                stray(
                    format!("{}, of no connection the stand opened", describe_frame(f)),
                    &mut v,
                );
            }
            continue;
        }
        if !from_peer || h.dst != src {
            stray(describe_frame(f), &mut v);
            continue;
        }
        if let Some(i) = v.conn_of(h.src, h.sp, h.dp) {
            let c = &mut v.conns[i];
            if c.open && h.flags & 0x12 == 0x12 && h.seq == c.iss_them && h.ack == c.reply_ack {
                c.repeats += 1;
            } else {
                c.peer.push(seg);
            }
            continue;
        }
        let probe = v.probes.iter().position(|p| {
            p.ip == h.src && p.port == h.sp && p.sport == h.dp && h.ack == p.seq.wrapping_add(1)
        });
        match (probe, h.flags & 0x12 == 0x12, h.flags & RST != 0) {
            (Some(i), open, rst) if open || rst => {
                v.outside_window += usize::from(!inside);
                let p = &v.probes[i];
                v.conns.push(Conn {
                    probe: i,
                    ip: p.ip,
                    port: p.port,
                    sport: p.sport,
                    reconnect: p.reconnect,
                    open,
                    reply_t: t,
                    reply_flags: h.flags,
                    reply_ttl: h.ttl,
                    reply_ack: h.ack,
                    reply_sums_ok: seg.sums_ok,
                    iss_them: h.seq,
                    iss_me: p.seq,
                    repeats: 0,
                    scanner: Vec::new(),
                    peer: Vec::new(),
                });
            }
            _ => stray(
                format!("{}, which answers no SYN of the scan", describe_frame(f)),
                &mut v,
            ),
        }
    }
    v
}

// ------------------------------------------------------------------ the documents

/// C's `-oL` text of a banner's bytes, written here from the C source and not taken from the product
/// (`normalize_string`, `src/output.c:144-170`, called with `MAX_BANNER_LENGTH` 8192 by `src/out-text.c:71`): a byte
/// that `isprint` (0x20-0x7e in the C locale) and is none of `< > & \ " '` stays, every other byte is `\x` and two
/// lowercase hex digits; a byte stays while `offset + 2 < 8192`, an escape while `offset + 5 < 8192`, else it is
/// dropped (and later bytes may still fit).
pub fn c_normalize_string(px: &[u8]) -> String {
    const BUF_LEN: usize = 8192;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::new();
    for &c in px {
        if (0x20..=0x7e).contains(&c) && !b"<>&\\\"'".contains(&c) {
            if out.len() + 2 < BUF_LEN {
                out.push(char::from(c));
            }
        } else if out.len() + 5 < BUF_LEN {
            out.push('\\');
            out.push('x');
            out.push(char::from(HEX[usize::from(c >> 4)]));
            out.push(char::from(HEX[usize::from(c & 0xf)]));
        }
    }
    out
}

/// The application of a banner record: its number (`-oB`) or its name (`-oL`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppId {
    Id(u16),
    Name(String),
}
/// The application names of the UDP banners by number (`src/masscan-app.c:8-57`): the verifier's own table.
pub const UDP_APPS: [(u16, &str); 9] = [
    (0, "unknown"),
    (6, "dns-ver"),
    (7, "snmp"),
    (8, "nbtstat"),
    (14, "zeroaccess"),
    (19, "ntp"),
    (25, "memcached"),
    (28, "coap"),
    (35, "isakmp"),
];
/// The application names of the TCP banners of 4b and the TLS records of 4c by number (`src/masscan-app.c:8-57`; `src/masscan-app.h:8-49`):
/// PROTO_HEUR (1) and the TLS hand-off's PROTO_SSL3 (9) included.
pub const TCP_APPS: [(u16, &str); 24] = [
    (1, "unknown"),
    (2, "ssh"),
    (3, "ssh"),
    (4, "http"),
    (5, "ftp"),
    (9, "ssl"),
    (10, "smb"),
    (11, "smtp"),
    (12, "pop"),
    (13, "imap"),
    (15, "X509"),
    (16, "X509CA"),
    (17, "title"),
    (18, "html"),
    (20, "vuln"),
    (21, "heartbleed"),
    (22, "ticketbleed"),
    (24, "safe"),
    (29, "telnet"),
    (30, "rdp"),
    (31, "http.server"),
    (32, "minecraft"),
    (33, "vnc"),
    (34, "vnc-info"),
];
impl AppId {
    pub fn name(&self) -> String {
        match self {
            AppId::Name(n) => n.clone(),
            AppId::Id(n) => UDP_APPS
                .iter()
                .chain(&TCP_APPS)
                .find(|(i, _)| i == n)
                .map_or_else(|| format!("({n})"), |(_, x)| (*x).to_owned()),
        }
    }
}
/// A banner's payload as its format carries it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Data {
    /// `-oB`: the bytes.
    Raw(Vec<u8>),
    /// `-oL`: `normalize_string` of the bytes.
    Text(String),
    /// A raw banner C reads past the datagram (`udp-raw-past-datagram`): only its presence and, from `-oB`, its
    /// length are compared.
    PastDatagram(Option<usize>),
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Body {
    /// A status record and the fields its format carries.
    Status {
        st: St,
        reason: Option<String>,
        ttl: Option<u8>,
    },
    /// A banner record.
    Banner {
        app: AppId,
        ttl: Option<u8>,
        data: Data,
    },
}
/// One record of a document, as far as its format carries it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rec {
    pub ip: IpAddr,
    pub port: u16,
    /// The IP protocol by its name (`name_from_ip_proto`, output.c:71-82: `arp` for 0, `err` for an unknown byte).
    pub proto: String,
    pub body: Body,
    pub ts: Option<u64>,
}
fn proto_name(p: u8) -> &'static str {
    match p {
        0 => "arp",
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        132 => "sctp",
        _ => "err",
    }
}
fn proto_of_name(s: &str) -> Option<String> {
    ["arp", "icmp", "tcp", "udp", "sctp", "err"]
        .contains(&s)
        .then(|| s.to_owned())
}
fn quoted(b: &[u8]) -> String {
    let mut s = String::from("\"");
    for c in b {
        if (0x20..0x7f).contains(c) && *c != b'"' && *c != b'\\' {
            s.push(char::from(*c));
        } else {
            s.push_str(&format!("\\x{c:02x}"));
        }
    }
    s.push('"');
    s
}
impl Rec {
    /// What two correct scanners agree on: everything but the time.
    pub fn bare(&self) -> Rec {
        Rec {
            ts: None,
            ..self.clone()
        }
    }
    pub fn is_banner(&self) -> bool {
        matches!(self.body, Body::Banner { .. })
    }
    pub fn app_name(&self) -> Option<String> {
        match &self.body {
            Body::Banner { app, .. } => Some(app.name()),
            Body::Status { .. } => None,
        }
    }
    fn with_data(&self, data: Data) -> Rec {
        let mut r = self.clone();
        if let Body::Banner { data: d, .. } = &mut r.body {
            *d = data;
        }
        r
    }
    pub fn show(&self) -> String {
        let at = format!("{} {}/{}", self.ip, self.port, self.proto);
        match &self.body {
            Body::Status { st, reason, ttl } => {
                let mut s = format!("{} {at}", st.name());
                if let Some(r) = reason {
                    s.push_str(&format!(" reason {r}"));
                }
                if let Some(t) = ttl {
                    s.push_str(&format!(" ttl {t}"));
                }
                s
            }
            Body::Banner { app, ttl, data } => {
                let mut s = format!("banner {at} {}", app.name());
                if let Some(t) = ttl {
                    s.push_str(&format!(" ttl {t}"));
                }
                match data {
                    Data::Raw(b) => s.push_str(&format!(" {} bytes {}", b.len(), quoted(b))),
                    Data::Text(t) => s.push_str(&format!(" {t:?}")),
                    Data::PastDatagram(Some(n)) => {
                        s.push_str(&format!(" {n} bytes (read past the datagram by C)"));
                    }
                    Data::PastDatagram(None) => s.push_str(" (read past the datagram by C)"),
                }
                s
            }
        }
    }
}
impl Shown for Rec {
    fn show(&self) -> String {
        Rec::show(self)
    }
}
impl Record for Rec {
    fn ts(&self) -> Option<u64> {
        self.ts
    }
}
pub type Document = Doc<Rec>;

fn status_of(name: &str) -> Option<St> {
    [St::Open, St::Closed]
        .into_iter()
        .find(|s| s.name() == name)
}
/// An `-oL` line (`out-text.c:26-73`): `<status> <proto> <port> <ip> <time>` or `banner <proto> <port> <ip> <time>
/// <app> <normalized payload>` (the space after the application always written, the payload possibly empty).
fn list_rec(l: &str) -> Result<Rec, String> {
    if let Some(rest) = l.strip_prefix("banner ") {
        let f: Vec<&str> = rest.splitn(6, ' ').collect();
        let [proto, port, ip, ts, app, text] = f[..] else {
            return Err("not `banner proto port ip time app text`".into());
        };
        return Ok(Rec {
            ip: canon(ip).ok_or(format!("address {ip:?}"))?,
            port: canon(port).ok_or(format!("port {port:?}"))?,
            proto: proto_of_name(proto).ok_or(format!("protocol {proto:?}"))?,
            body: Body::Banner {
                app: AppId::Name(app.to_owned()),
                ttl: None,
                data: Data::Text(text.to_owned()),
            },
            ts: Some(canon(ts).ok_or(format!("time {ts:?}"))?),
        });
    }
    let f = fields(LIST_REC, l).ok_or("not the record form")?;
    let [st, proto, port, ip, ts] = f[..] else {
        return Err("not the record form".into());
    };
    Ok(Rec {
        ip: canon(ip).ok_or(format!("address {ip:?}"))?,
        port: canon(port).ok_or(format!("port {port:?}"))?,
        proto: proto_of_name(proto).ok_or(format!("protocol {proto:?}"))?,
        body: Body::Status {
            st: status_of(st).ok_or(format!("status {st:?}"))?,
            reason: None,
            ttl: None,
        },
        ts: Some(canon(ts).ok_or(format!("time {ts:?}"))?),
    })
}
fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}
fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
fn v6_at(b: &[u8], i: usize) -> Ipv6Addr {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[i..i + 16]);
    Ipv6Addr::from(a)
}
/// A record body of `-oB` (`out-binary.c`): types 6/7 (IPv4 status, 13 bytes), 10/11 (IPv6 status, 26 bytes), 9 (IPv4
/// banner: time, address, protocol, port, application, ttl, payload) and 13 (IPv6 banner: time, protocol, port,
/// application, ttl, version 6, address, payload).
fn binary_rec(ty: u8, b: &[u8]) -> Result<Rec, String> {
    let st = |t: u8| {
        if t == 6 || t == 10 {
            St::Open
        } else {
            St::Closed
        }
    };
    Ok(match (ty, b.len()) {
        (6 | 7, 13) => Rec {
            ip: IpAddr::V4(Ipv4Addr::new(b[4], b[5], b[6], b[7])),
            port: be16(b, 9),
            proto: proto_name(b[8]).to_owned(),
            body: Body::Status {
                st: st(ty),
                reason: Some(reason_string(b[11])),
                ttl: Some(b[12]),
            },
            ts: Some(u64::from(be32(b, 0))),
        },
        (10 | 11, 26) if b[9] == 6 => Rec {
            ip: IpAddr::V6(v6_at(b, 10)),
            port: be16(b, 5),
            proto: proto_name(b[4]).to_owned(),
            body: Body::Status {
                st: st(ty),
                reason: Some(reason_string(b[7])),
                ttl: Some(b[8]),
            },
            ts: Some(u64::from(be32(b, 0))),
        },
        (9, 14..) => Rec {
            ip: IpAddr::V4(Ipv4Addr::new(b[4], b[5], b[6], b[7])),
            port: be16(b, 9),
            proto: proto_name(b[8]).to_owned(),
            body: Body::Banner {
                app: AppId::Id(be16(b, 11)),
                ttl: Some(b[13]),
                data: Data::Raw(b[14..].to_vec()),
            },
            ts: Some(u64::from(be32(b, 0))),
        },
        (13, 27..) if b[10] == 6 => Rec {
            ip: IpAddr::V6(v6_at(b, 11)),
            port: be16(b, 5),
            proto: proto_name(b[4]).to_owned(),
            body: Body::Banner {
                app: AppId::Id(be16(b, 7)),
                ttl: Some(b[9]),
                data: Data::Raw(b[27..].to_vec()),
            },
            ts: Some(u64::from(be32(b, 0))),
        },
        (ty, n) => return Err(format!("a record of type {ty} with a {n}-byte body")),
    })
}
/// A length (or type) of `-oB`: 7-bit groups, high bit set on every byte but the last (`in-binary.c:546-570`).
fn varint(b: &[u8]) -> Option<(usize, usize)> {
    let mut v = 0usize;
    for (i, x) in b.iter().enumerate().take(3) {
        v = (v << 7) | usize::from(x & 0x7f);
        if x & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}
fn binary_records(b: &[u8], d: &mut Document) -> Result<(), String> {
    if b.len() < BINARY_BLOCK || !b.starts_with(b"masscan/1.1\ns:") {
        return Err("not the 99-byte `masscan/1.1` header".into());
    }
    let mut foot = [0u8; BINARY_BLOCK];
    foot[..11].copy_from_slice(b"masscan/1.1");
    let mut at = BINARY_BLOCK;
    loop {
        let rest = &b[at..];
        if rest.is_empty() {
            return Ok(());
        }
        if rest == foot {
            d.complete = true;
            return Ok(());
        }
        let ty = rest[0];
        let (len, n) = varint(&rest[1..])
            .ok_or_else(|| format!("a record length past the end at byte {at}"))?;
        let body = rest.get(1 + n..1 + n + len).ok_or_else(|| {
            format!("a record of type {ty} past the end of the file at byte {at}")
        })?;
        d.records
            .push(binary_rec(ty, body).map_err(|e| format!("{e} at byte {at}"))?);
        at += 1 + n + len;
    }
}
/// A document of `out` in its C form: an empty file is a document without a record; a file that stops after a
/// record, without its footer, is not `complete`; any other malformation is an error. The window writes `-oB` and
/// `-oL` only.
pub fn parse_doc(out: Out, b: &[u8]) -> Result<Document, String> {
    if b.is_empty() {
        return Ok(Doc {
            records: Vec::new(),
            complete: true,
        });
    }
    let mut d = Doc::default();
    match out {
        Out::List => {
            let lines = text_lines(b, "\n")?;
            if lines[0] != "#masscan" {
                return Err("no `#masscan` header".into());
            }
            d.complete = lines.len() > 1 && lines.last() == Some(&"# end");
            let body = &lines[1..lines.len() - usize::from(d.complete)];
            d.records = each(body, list_rec)?;
        }
        Out::Binary => binary_records(b, &mut d)?,
        Out::Json | Out::Stdout => {
            return Err(format!("the banners window writes no {out:?} document"));
        }
    }
    if d.records.is_empty() {
        return Err(
            "a header without a record (the header is written with the first record)".into(),
        );
    }
    Ok(d)
}

/// Every record whose reply came on the window's wire: rmasscan reports a reply once per (address, port, status), C
/// every datagram (`src/proto-udp.c:63-73`); the stand answers each probe once, so both report every reply.
pub fn wire_records_at(v: &WireView, who: Who, out: Out) -> Vec<(Rec, f64)> {
    let mut seen = BTreeSet::new();
    let mut recs = Vec::new();
    for r in &v.replies {
        if who == Who::Rmasscan && !seen.insert((r.ip, r.port, r.st)) {
            continue;
        }
        let binary = out == Out::Binary;
        recs.push((
            Rec {
                ip: IpAddr::V4(r.ip),
                port: r.port,
                proto: "udp".into(),
                body: Body::Status {
                    st: r.st,
                    reason: binary.then(|| r.reason.clone()),
                    ttl: binary.then_some(r.ttl),
                },
                ts: None,
            },
            r.t,
        ));
    }
    recs
}
/// C's raw banner on 11211 and on ports without a parser ([`RAW_PAST_DATAGRAM_PORTS`]) read past the datagram:
/// the last `unknown` banner of each address and port there becomes [`Data::PastDatagram`] (its length from `-oB`,
/// nothing from `-oL`). The other `unknown` banner of those ports, the first 64 bytes (`default_udp_parse`), stays.
/// The number masked.
pub fn mask_raw_past_datagram(recs: &[Rec]) -> (Vec<Rec>, usize) {
    let mut last: BTreeMap<(IpAddr, u16), usize> = BTreeMap::new();
    for (i, r) in recs.iter().enumerate() {
        if RAW_PAST_DATAGRAM_PORTS.contains(&r.port)
            && r.proto == "udp"
            && r.app_name().as_deref() == Some("unknown")
        {
            last.insert((r.ip, r.port), i);
        }
    }
    let masked: BTreeSet<usize> = last.values().copied().collect();
    let out = recs
        .iter()
        .enumerate()
        .map(|(i, r)| match (&r.body, masked.contains(&i)) {
            (
                Body::Banner {
                    data: Data::Raw(b), ..
                },
                true,
            ) => r.with_data(Data::PastDatagram(Some(b.len()))),
            (Body::Banner { .. }, true) => r.with_data(Data::PastDatagram(None)),
            _ => r.clone(),
        })
        .collect();
    (out, masked.len())
}

// ------------------------------------------------------------------ checks

/// The documented differences from C, by name, and the rule each applies.
pub const DEVIATIONS: [(&str, &str); 9] = [
    (
        "udp-checksum-ffff",
        "R12: a UDP checksum that computes to 0 goes out as 0xFFFF from rmasscan (RFC 768) and as 0x0000 from C; two probes that differ only there are the same probe",
    ),
    (
        "rx-checksum-verify",
        "R11: rmasscan drops a reply whose IPv4 header checksum or UDP checksum is wrong, C reads it; every reply on the wire must carry valid sums",
    ),
    (
        "udp-raw-past-datagram",
        "C1.1, R2: C's raw banner on 11211 and on ports without a parser (1900 here) reads app_length bytes from frame + 2 * app_offset, past the datagram (src/proto-udp.c:97-101, 108-112, 129), rmasscan's is the datagram; those banners of both scanners are compared by presence and, in -oB, by length only; each such banner of C's -oB must have its reply's datagram length, and rmasscan's raw banner is judged against the datagram itself",
    ),
    (
        "ipv6-ttl",
        "E1.9: C sets ip_ttl for IPv4 only (src/proto-preprocess.c:127), so the ttl of its IPv6 status and banner records (tcb->ttl) is stale; rmasscan's is the SYN-ACK's hop limit; IPv6 ttls are left out when the documents are compared, and rmasscan's -oB IPv6 ttls must be their SYN-ACK's hop limit",
    ),
    (
        "ipv4-stack-checksum",
        "E1.10: C updates the IPv4 header checksum of its stack frames incrementally and folds it twice (src/templ-pkt.c:466-473), about 1e-5 of them wrong, rmasscan computes it in full; the comparison never reads that sum, but a wrong one makes the peer drop the frame: the condition is that no stack frame of C on the wire has a wrong IPv4 header checksum",
    ),
    (
        "memcached-tcp-past-segment",
        "E1.4: C's memcached parser reads px[length], one byte past the segment, in state 2 (src/proto-memcached.c:165), rmasscan never does; the condition is that every memcached segment of the peer ends with LF, so neither parser is in state 2 at a segment's end",
    ),
    (
        "no-frame-from-destroyed-tcb",
        "E1.5: C hands every event of a frame to its TCB even after one destroyed it (src/main.c:991-1018), and the scrubbed TCB sends from and to 255.255.255.255:65535; rmasscan stops at the destroying event; C's scrubbed-TCB segments are counted and left out of its connections, any such frame of rmasscan is a FAIL",
    ),
    (
        "tls-hello-random",
        "A2 of the TLS reference: a vuln-mode ClientHello's random field (bytes 11..43) carries the scan's start time and a SipHash fingerprint of it, so the two scanners' hellos differ there; hellos of the dynamic templates (lengths 74, 225, 361) that differ only in those bytes are the same hello; the static default and TLS 1.3 hellos are never masked, and every first payload on a TLS port of both scanners must be a dynamic ClientHello whose bytes outside the random field equal its template's",
    ),
    (
        "minecraft-unsplit",
        "E1.13, E2.7: C's Minecraft parser loses and zeroes bytes when a reply spans segments (src/proto-mc.c:68-89), rmasscan keeps the unsplit stream; the condition is that every Minecraft reply of the peer came in one segment",
    ),
];
/// Why rmasscan's document and the oracle's are compared as multisets.
pub const RECORD_ORDER_VS_C: &str = "each scanner writes a reply's status record and then its banners in the order the replies arrive on its own wire (judged per step); the two runs of a document do not get the same reply order from the stand (one responder thread per UDP socket), so rmasscan's status and banner records must equal C's field for field but the time in any order: the set of banners per (address, port, application) is C's; a TCP connection's banners come when it is destroyed, in an order its scenario's timing decides, so the same rule holds for them";

/// The stand owes every probe exactly one reply, and that reply is the table's scenario reply to that very probe;
/// anything else on the peer side is a stand that did not behave (INVALID for both scanners).
fn stand_answers<V>(r: &mut Run, s: &Side<V>, v: &WireView) {
    let mut problems = Vec::new();
    for (i, p) in v.probes.iter().enumerate() {
        let answers: Vec<&pv::Reply> = v.replies.iter().filter(|x| x.probe == i).collect();
        let want = udp_payload(&p.frame).and_then(|q| scenario_reply(p.port, p.ip, q));
        let ok = answers.len() == 1
            && answers[0].st == St::Open
            && want.is_some()
            && udp_payload(&answers[0].frame) == want.as_deref();
        if !ok {
            problems.push(format!(
                "{}:{}: {} answers, {}",
                p.ip,
                p.port,
                answers.len(),
                if want.is_none() {
                    "no scenario reply for this probe"
                } else {
                    "not the scenario reply"
                }
            ));
        }
    }
    r.inv(
        &format!(
            "{}: the stand answered every probe exactly once with its scenario reply (the table's reply to that probe, its identifier copied or spoiled)",
            s.spec.name
        ),
        problems.is_empty() && !v.probes.is_empty(),
        problems.iter().take(4).cloned().collect::<Vec<_>>().join("; "),
    );
    r.inv(
        &format!(
            "{}: nothing on the peer side answers anything the scan did not send",
            s.spec.name
        ),
        v.peer_unexpected.is_empty() && v.proto_unreachable == 0,
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

/// The banner records of a document per (address, port), in document order.
fn banners_by_reply(d: &Document) -> BTreeMap<(IpAddr, u16), Vec<&Rec>> {
    let mut m: BTreeMap<(IpAddr, u16), Vec<&Rec>> = BTreeMap::new();
    for x in d.records.iter().filter(|x| x.is_banner()) {
        m.entry((x.ip, x.port)).or_default().push(x);
    }
    m
}

/// What one step's document proves about its banners: each follows its reply's status record with the same time, and
/// right after it or after a banner of the same reply (M1); each reply's banners are the scenario's applications;
/// rmasscan's `-oB` raw banner is its datagram, and its `-oL` text of the raw banner on the ports where C reads past
/// the datagram is `normalize_string` of the datagram (M2).
fn banner_checks(r: &mut Run, c: &CaseSpec, s: &Side<BView>, d: &Document) {
    // M1: a UDP banner comes right after its reply's status record or a banner of the same reply: the queue hands a
    // reply's banners over with its status, nothing comes between them (engine `Output::Banner`).
    let mut apart = Vec::new();
    for (i, x) in d.records.iter().enumerate() {
        if !x.is_banner() || x.proto != "udp" {
            continue;
        }
        let ok = i
            .checked_sub(1)
            .and_then(|p| d.records.get(p))
            .is_some_and(|p| p.ip == x.ip && p.port == x.port && p.proto == x.proto);
        if !ok {
            apart.push(format!("{} at record {i}", x.show()));
        }
    }
    beh(
        r,
        s,
        "every UDP banner record comes right after the status record of its reply or a banner of the same reply (M1)",
        apart.is_empty(),
        some4(&apart, 4).join("; "),
    );
    // A banner comes after the status record of its reply (src/proto-udp.c:63-73 then the parsers) with its time.
    let mut status_seen: BTreeMap<(IpAddr, u16), Option<u64>> = BTreeMap::new();
    let mut orphans = Vec::new();
    for x in &d.records {
        match &x.body {
            Body::Status { .. } => {
                status_seen.insert((x.ip, x.port), x.ts);
            }
            Body::Banner { .. } => match status_seen.get(&(x.ip, x.port)) {
                Some(ts) if *ts == x.ts => {}
                Some(ts) => orphans.push(format!(
                    "{} at time {:?}, its status {ts:?}",
                    x.show(),
                    x.ts
                )),
                None => orphans.push(format!(
                    "{} before any status record of its reply",
                    x.show()
                )),
            },
        }
    }
    beh(
        r,
        s,
        "every banner record follows the status record of its reply, with the same time",
        orphans.is_empty(),
        orphans
            .iter()
            .take(4)
            .cloned()
            .collect::<Vec<_>>()
            .join("; "),
    );
    let Some(v) = udp_view(s) else { return };
    let by = banners_by_reply(d);
    // Only where the stand answered with the scenario reply: anything else is the stand's INVALID above.
    let mut wrong = Vec::new();
    let mut judged = 0;
    for p in &v.probes {
        let answers: Vec<&pv::Reply> = v
            .replies
            .iter()
            .filter(|x| x.ip == p.ip && x.port == p.port)
            .collect();
        let scenario_answered = answers.len() == 1
            && udp_payload(&p.frame)
                .and_then(|q| scenario_reply(p.port, p.ip, q))
                .as_deref()
                == udp_payload(&answers[0].frame);
        let Some(sc) = role_of(p.ip).and_then(|role| scenario(p.port, role)) else {
            continue;
        };
        if !scenario_answered {
            continue;
        }
        judged += 1;
        let got: Vec<String> = by
            .get(&(IpAddr::V4(p.ip), p.port))
            .map(|b| b.iter().filter_map(|x| x.app_name()).collect())
            .unwrap_or_default();
        if got != sc.apps(c.rawudp) {
            wrong.push(format!(
                "{}:{} {:?} {:?}, the scenario {:?}",
                p.ip,
                p.port,
                sc.role,
                got,
                sc.apps(c.rawudp)
            ));
        }
    }
    cap(
        r,
        s,
        "each reply's banners carry, in order, the applications of the banners the scenario declares (C's B0 table for that reply)",
        wrong.is_empty() && judged > 0,
        if wrong.is_empty() {
            format!("{judged} replies")
        } else {
            wrong.iter().take(4).cloned().collect::<Vec<_>>().join("; ")
        },
    );
    if s.spec.who == Who::Rmasscan && s.spec.out == Out::Binary {
        // R2: rmasscan's raw banner is the datagram itself, on every port (C's own on 11211 and 1900 is not).
        let mut off = Vec::new();
        let mut raw = 0;
        for a in &v.replies {
            let Some(datagram) = udp_payload(&a.frame) else {
                continue;
            };
            let last = by.get(&(IpAddr::V4(a.ip), a.port)).and_then(|b| {
                b.iter()
                    .rev()
                    .find(|x| x.app_name().as_deref() == Some("unknown"))
            });
            let Some(x) = last else { continue };
            raw += 1;
            let ok =
                matches!(&x.body, Body::Banner { data: Data::Raw(b), .. } if b[..] == *datagram);
            if !ok {
                off.push(x.show());
            }
        }
        cap(
            r,
            s,
            "rmasscan's raw banner is the reply's datagram, byte for byte (R2), on every port",
            off.is_empty(),
            if off.is_empty() {
                format!("{raw} raw banners")
            } else {
                off.iter().take(3).cloned().collect::<Vec<_>>().join("; ")
            },
        );
    }
    if s.spec.who == Who::Rmasscan && s.spec.out == Out::List {
        // M2: in -oL, rmasscan's raw banner on the ports where C reads past the datagram is the datagram's
        // normalize_string (out-text.c), not just present (udp-raw-past-datagram masks it against C); the text is the
        // verifier's own C escaper (c_normalize_string), not the product's.
        let mut off = Vec::new();
        let mut raw = 0;
        for a in v
            .replies
            .iter()
            .filter(|a| RAW_PAST_DATAGRAM_PORTS.contains(&a.port))
        {
            let Some(datagram) = udp_payload(&a.frame) else {
                continue;
            };
            let last = by.get(&(IpAddr::V4(a.ip), a.port)).and_then(|b| {
                b.iter()
                    .rev()
                    .find(|x| x.app_name().as_deref() == Some("unknown"))
            });
            let Some(x) = last else { continue };
            raw += 1;
            let want = c_normalize_string(datagram);
            if !matches!(&x.body, Body::Banner { data: Data::Text(t), .. } if *t == want) {
                off.push(format!("{}, the datagram's text {want:?}", x.show()));
            }
        }
        cap(
            r,
            s,
            "rmasscan's -oL text of the raw banner on 1900 and 11211 is normalize_string of the reply's datagram (M2)",
            off.is_empty(),
            if off.is_empty() {
                format!("{raw} raw banners")
            } else {
                some4(&off, 3).join("; ")
            },
        );
    }
}

/// The `[+]` lines of a UDP step of rmasscan (the protocols verifier's rule for a case without ARP scan): the
/// interface, its MAC and IP by the route, the router 198.18.0.2 by ARP, seed 1 and source port 40000 given.
fn udp_detection(r: &mut Run, s: &Side<BView>) {
    let get = |k: &str| s.se.value(k).map(str::to_owned);
    let keys: Vec<&str> = s.se.plus.iter().map(|(k, _)| k.as_str()).collect();
    let ok = get("interface").as_deref() == Some("veth-a (detected: route to 198.18.0.2)")
        && get("source-mac").as_deref() == Some("02-aa-00-00-00-01 (detected)")
        && get("source-ip").as_deref() == Some("198.18.0.1 (detected)")
        && get("seed").as_deref() == Some("1 (given)")
        && get("source-port").as_deref() == Some("40000 (given)")
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
        && get("router-mac").is_some_and(|m| m.starts_with("02-aa-00-00-00-02 (arp: "));
    beh(
        r,
        s,
        "[+] lines are the stand's: veth-a by the route, its MAC and IP, router 198.18.0.2 by ARP, seed 1 and source port 40000 given",
        ok,
        format!("{:?}", s.se.plus),
    );
}

/// A rmasscan step: exit, stdout, stderr grammar, the `[+]` lines, `[+] finished` against the wire and the records.
fn rmasscan_step(r: &mut Run, s: &Side<BView>, doc: Option<&Document>) {
    pair_verify::rmasscan_step(r, s, doc, udp_detection, |v| {
        let BView::Udp(v) = v else {
            return WireSummary {
                counts: (0, 0, 0),
                first_probe: None,
                last_reply: None,
            };
        };
        let all = wire_records_at(v, Who::Rmasscan, Out::Binary);
        let open = all
            .iter()
            .filter(|(x, _)| matches!(x.body, Body::Status { st: St::Open, .. }))
            .count() as u64;
        WireSummary {
            counts: (v.probes.len() as u64, all.len() as u64, open),
            first_probe: v.probes.first().map(|p| p.t),
            last_reply: v.replies.last().map(|p| p.t),
        }
    });
}

/// Each named deviation of the window: the wire condition that keeps it from changing the comparison, and the notes.
fn deviations(
    r: &mut Run,
    sides: &[Side<BView>],
    docs: &[Option<Document>],
    r12: usize,
    masked: usize,
) {
    named_deviations(
        r,
        &[
            "udp-checksum-ffff",
            "rx-checksum-verify",
            "udp-raw-past-datagram",
        ],
        &DEVIATIONS,
        |name| match name {
            "udp-checksum-ffff" => (true, format!("{r12} probe pairs equal by this rule")),
            "rx-checksum-verify" => {
                let bad = sides
                    .iter()
                    .filter_map(udp_view)
                    .flat_map(|v| &v.replies)
                    .filter(|x| !pv::sums_ok(&x.frame))
                    .count();
                (bad == 0, format!("{bad} replies with a wrong sum"))
            }
            "udp-raw-past-datagram" => {
                // C's -oB raw banner on those ports has its datagram's length.
                let (mut n, mut bad) = (0, Vec::new());
                for (s, d) in sides.iter().zip(docs) {
                    let (Some(v), Some(d), Who::Oracle, Out::Binary) =
                        (udp_view(s), d, s.spec.who, s.spec.out)
                    else {
                        continue;
                    };
                    let by = banners_by_reply(d);
                    for a in v
                        .replies
                        .iter()
                        .filter(|a| RAW_PAST_DATAGRAM_PORTS.contains(&a.port))
                    {
                        let Some(datagram) = udp_payload(&a.frame) else {
                            continue;
                        };
                        let last = by.get(&(IpAddr::V4(a.ip), a.port)).and_then(|b| {
                            b.iter()
                                .rev()
                                .find(|x| x.app_name().as_deref() == Some("unknown"))
                        });
                        n += 1;
                        let ok = matches!(last.map(|x| &x.body),
                            Some(Body::Banner { data: Data::Raw(b), .. }) if b.len() == datagram.len());
                        if !ok {
                            bad.push(format!("{}:{}", a.ip, a.port));
                        }
                    }
                }
                (
                    bad.is_empty(),
                    format!(
                        "{masked} raw banners of C past the datagram masked (presence and length in -oB, presence in -oL); C's -oB raw banners of the datagram's length: {} of {n}{}",
                        n - bad.len(),
                        if bad.is_empty() {
                            String::new()
                        } else {
                            format!(", not: {}", bad.join(" "))
                        }
                    ),
                )
            }
            _ => (false, "unknown deviation".into()),
        },
    );
}

// ------------------------------------------------------------------ TCP checks

/// A step's capture, UDP (4a) or TCP (4b).
#[derive(Debug)]
pub enum BView {
    Udp(WireView),
    Tcp(TcpView),
}
impl pair_verify::StepView for BView {
    fn probe_frames(&self) -> Vec<Vec<u8>> {
        match self {
            BView::Udp(v) => v.probe_frames(),
            BView::Tcp(v) => v.probe_frames(),
        }
    }
}
fn udp_view(s: &Side<BView>) -> Option<&WireView> {
    match &s.view {
        Some(BView::Udp(v)) => Some(v),
        _ => None,
    }
}
fn tcp_of(s: &Side<BView>) -> Option<&TcpView> {
    match &s.view {
        Some(BView::Tcp(v)) => Some(v),
        _ => None,
    }
}
fn some4<T: Clone>(v: &[T], n: usize) -> Vec<T> {
    v.iter().take(n).cloned().collect()
}
/// An address as C prints it in `[+]` lines and the verifier in its details: IPv6 in brackets
/// (`ipv6address_fmt`, `main-initadapter.c:229`).
fn ip_text(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => format!("[{}]", rmasscan_core::ranges6::format_ipv6_c(u128::from(a))),
    }
}

/// The probes that repeat the 4-tuple of an earlier SYN of the scan (`--retries 0`: each SYN of the plan goes out
/// once): the scanner's, and no answer of the stand is owed to them.
fn repeated_syns(v: &TcpView) -> Vec<usize> {
    let mut seen = BTreeSet::new();
    v.probes
        .iter()
        .enumerate()
        .filter(|(_, p)| !seen.insert((p.ip, p.port, p.sport)))
        .map(|(i, _)| i)
        .collect()
}

/// What is wrong with the scanner's answers to the peer's requests for its source: each request answered exactly once
/// before the next, in C's form ([`answer_form_problem`]), and the peer asks only once. The peer asks again only while
/// its request is unanswered or after an answer it dropped (Linux retransmits a who-has or a solicitation every second
/// while the entry is INCOMPLETE; a REACHABLE entry lasts 15-45 s, longer than a resolve step): a second request is
/// the scanner's too. No request is the stand's (the "resolved at least once" check of [`tcp_stand`]).
fn resolution_problems(c: &TcpCase, v: &TcpView, st: &Stand) -> Vec<String> {
    let src = c.source();
    let mut bad = Vec::new();
    for (i, (t, q)) in v.requests.iter().enumerate() {
        let next = v.requests.get(i + 1).map_or(f64::INFINITY, |x| x.0);
        let mine: Vec<&(f64, Vec<u8>)> = v
            .answers
            .iter()
            .filter(|(a, _)| *a >= *t && *a < next)
            .collect();
        match mine.as_slice() {
            [(_, a)] => {
                bad.extend(answer_form_problem(q, a, st, src).map(|p| format!("request {i}: {p}")))
            }
            other => bad.push(format!("{} answers to request {i}", other.len())),
        }
    }
    if v.requests.len() > 1 {
        bad.push(format!(
            "the peer asked {} times: it took no answer (it asks again only while unanswered)",
            v.requests.len()
        ));
    }
    bad
}

/// The checks of a TCP step whose evidence is the scanner's alone, judged before the stand's (FAIL on rmasscan's step
/// once the evidence is proven, INVALID on the oracle's), so that a fault of the scanner is never booked on the stand:
/// the answers to the peer's requests for the source (unanswered or dropped, they leave the peer without the SYN-ACK
/// it owes), SYNs on the wire and each once, and every frame of the scanner MAC explained (a frame of the peer that
/// answers an unexplained one is the scanner's doing, [`TcpView::peer_answers_to_scanner`]).
fn tcp_scanner_first(r: &mut Run, c: &TcpCase, s: &Side<BView>, v: &TcpView, st: &Stand) {
    if c.resolve {
        let bad = resolution_problems(c, v, st);
        cap(
            r,
            s,
            "the scanner answers every request of the peer for its source exactly once, at once and in C's form (an ARP reply of 60 bytes to the requester; a Neighbor Advertisement of 86 bytes to the requester with hop limit 255, code 0, flags 0x60, the source as its target, the scanner's MAC as its target link-layer address and a right ICMPv6 checksum), and the peer takes it (it asks once)",
            bad.is_empty(),
            if bad.is_empty() {
                format!("{} requests, {} answers", v.requests.len(), v.answers.len())
            } else {
                some4(&bad, 4).join("; ")
            },
        );
    }
    let repeated = repeated_syns(v);
    cap(
        r,
        s,
        "the scan put its SYNs on the wire, each once (--retries 0: no 4-tuple's SYN repeated)",
        !v.probes.is_empty() && repeated.is_empty(),
        if repeated.is_empty() {
            format!("{} SYNs", v.probes.len())
        } else {
            repeated
                .iter()
                .take(4)
                .map(|i| {
                    let p = &v.probes[*i];
                    format!("{}:{} again at {:.3}", ip_text(p.ip), p.port, p.t)
                })
                .collect::<Vec<_>>()
                .join("; ")
        },
    );
    pair_verify::scanner_frame_checks(
        r,
        s,
        "every frame of the scanner MAC is a SYN of the scan, a segment of one of its connections or an answer to the peer's request for its source",
        &v.scanner_unexplained,
        "the scanner's answers to the peer's requests for its source stay within one per request",
        &[("answers_for_source", v.answers.len(), v.requests.len())],
    );
}

/// The stand of a TCP step behaved (INVALID for both scanners otherwise): each SYN answered once, with a SYN-ACK
/// exactly where the table has a scenario and a reset elsewhere; each scenario's stream on the wire is its script's
/// writes up to at least what the scanner's frames on this step owe it ([`Conn::owed`]: a peer that stalls or stops
/// early on either scanner's step, the oracle's included, is the stand's fault, never a FAIL of rmasscan's records or
/// segments against C) and a split one came in more than one segment; nothing else from the peer and no IPv6 noise; the
/// heartbeat covered the scan (none at all on the quiet control); the source was resolved only in a resolve case. What
/// [`tcp_scanner_first`] puts to the scanner is left out: a repeated SYN, a SYN left unanswered after the scanner
/// failed the peer's request for its source, a frame of the peer that answers an unexplained frame of the scanner.
fn tcp_stand(r: &mut Run, c: &TcpCase, s: &Side<BView>, v: &TcpView, st: &Stand) {
    let name = s.spec.name;
    let repeated = repeated_syns(v);
    let unresolved = c.resolve && !resolution_problems(c, v, st).is_empty();
    let mut bad = Vec::new();
    let mut theirs = 0;
    for (i, p) in v.probes.iter().enumerate() {
        let answers: Vec<&Conn> = v.conns.iter().filter(|x| x.probe == i).collect();
        if repeated.contains(&i) || (unresolved && answers.is_empty()) {
            theirs += 1;
            continue;
        }
        let want_open = tcp_scenario(p.port, p.ip).is_some();
        if answers.len() != 1 || answers[0].open != want_open {
            bad.push(format!(
                "{}:{}: {} answers, a {} wanted",
                ip_text(p.ip),
                p.port,
                answers.len(),
                if want_open { "SYN-ACK" } else { "reset" }
            ));
        }
    }
    r.inv(
        &format!(
            "{name}: the stand answered every SYN exactly once, with a SYN-ACK where the table has a scenario and a reset elsewhere"
        ),
        bad.is_empty(),
        if bad.is_empty() {
            format!(
                "{} SYNs, {theirs} left to the scanner's checks (repeated, or unanswered after the scanner failed the peer's request)",
                v.probes.len()
            )
        } else {
            some4(&bad, 4).join("; ")
        },
    );
    let mut streams = Vec::new();
    let mut split = Vec::new();
    for x in v.conns.iter().filter(|x| x.open) {
        let Some(sc) = tcp_scenario(x.port, x.ip) else {
            continue;
        };
        let (got, want, owed) = (x.peer_stream(), sc.stream(), x.owed(sc));
        if !want.starts_with(&got) {
            streams.push(format!(
                "{}:{}: {} bytes that are not the script's",
                ip_text(x.ip),
                x.port,
                got.len()
            ));
        } else if got.len() < owed {
            streams.push(format!(
                "{}:{}: {} of the {} bytes the scanner's frames owe ({} in the script)",
                ip_text(x.ip),
                x.port,
                got.len(),
                owed,
                want.len()
            ));
        } else if got == want && sc.split && x.peer_segments() < 2 {
            split.push(format!(
                "{}:{}: one data segment ({} on the wire)",
                ip_text(x.ip),
                x.port,
                x.peer_data().len()
            ));
        }
    }
    r.inv(
        &format!(
            "{name}: the peer's stream of every connection is its scenario's writes, all those the scanner's frames on this step owe it (a prefix only where the scanner gave the script no cause to go on: no handshake, no data it waits for, a FIN or RST first)"
        ),
        streams.is_empty(),
        some4(&streams, 4).join("; "),
    );
    r.inv(
        &format!(
            "{name}: every split scenario came in more than one data segment at distinct sequence numbers (where C does not depend on the split, E2)"
        ),
        split.is_empty(),
        some4(&split, 4).join("; "),
    );
    r.inv(
        &format!("{name}: nothing on the peer side answers anything the scan did not send"),
        v.peer_unexpected.is_empty(),
        if v.peer_unexpected.is_empty() {
            format!(
                "{} frames of the peer answer the scanner's unexplained frames (the scanner's check)",
                v.peer_answers_to_scanner.len()
            )
        } else {
            some4(&v.peer_unexpected, 4).join("; ")
        },
    );
    r.inv(
        &format!(
            "{name}: no IPv6 kernel noise on the wire (MLD, router discovery, DAD: the stand rules them out)"
        ),
        v.noise.is_empty(),
        some4(&v.noise, 4).join("; "),
    );
    r.inv(
        &format!("{name}: every SYN and reply lies inside the witness window"),
        v.outside_window == 0,
        v.outside_window,
    );
    if c.quiet {
        // M3: the control runs rmasscan's timers with nothing but the scan on the link.
        r.inv(
            &format!(
                "{name}: no peer heartbeat on the wire (the quiet control: rmasscan's hello and lifetime timers on a quiet link)"
            ),
            v.heartbeats.is_empty(),
            format!("{} heartbeats", v.heartbeats.len()),
        );
    } else {
        // The heartbeat keeps C's receive loop turning (HEARTBEAT_PAYLOAD): it must cover the scan.
        let (lo, hi) = match (v.probes.first(), v.probes.last()) {
            (Some(a), Some(b)) => (a.t, b.t + f64::from(c.wait)),
            _ => (0.0, 0.0),
        };
        let mut beats: Vec<f64> = v.heartbeats.clone();
        beats.sort_by(f64::total_cmp);
        let mut gap = 0f64;
        let mut prev = lo;
        for b in beats.iter().copied().filter(|b| (lo..=hi).contains(b)) {
            gap = gap.max(b - prev);
            prev = b;
        }
        gap = gap.max(hi - prev);
        r.inv(
            &format!(
                "{name}: the peer heartbeat covered the scan (no gap over {HEARTBEAT_MAX_GAP} s from the first SYN to the end of the wait)"
            ),
            gap <= HEARTBEAT_MAX_GAP,
            format!("{} heartbeats, largest gap {gap:.3} s", beats.len()),
        );
    }
    r.inv(
        &format!(
            "{name}: the peer resolved the source {} (ARP who-has or Neighbor Solicitation)",
            if c.resolve {
                "at least once (no neighbour entry)"
            } else {
                "never (its neighbour entry is permanent)"
            }
        ),
        c.resolve == !v.requests.is_empty(),
        format!("{} requests", v.requests.len()),
    );
}

/// What is wrong with one answer of the scanner to a request of the peer for its source, against C's form: an ARP
/// reply of 60 bytes to the requester (`src/stack-arpv4.c:282-363`), or C's Neighbor Advertisement
/// (`src/stack-ndpv6.c:144-178`: the request with type 136, code 0, flags 0x60, the target and the target link-layer
/// option, its checksum; hop limit and length as the request's, 255 and 32 from the Linux peer) as RFC 4861 §7.1.2
/// has the peer take it: hop limit 255, code 0, a right checksum, ICMPv6 length 32 (24 and one option), to the
/// requester's MAC and address. The view takes as answers only frames of the scanner MAC for the source (an ARP reply
/// with the source as sender address, an NA with the source as target), so those fields are not judged again here.
fn answer_form_problem(req: &[u8], ans: &[u8], st: &Stand, src: IpAddr) -> Option<String> {
    let wrong = |what: &str, fields: &[(&str, bool)]| -> Option<String> {
        let off: Vec<&str> = fields
            .iter()
            .filter(|(_, ok)| !ok)
            .map(|(n, _)| *n)
            .collect();
        (!off.is_empty()).then(|| format!("{what} not in C's form: {}", off.join(", ")))
    };
    match src {
        IpAddr::V4(_) => {
            let at = |r: std::ops::Range<usize>| ans.get(r);
            wrong(
                &format!("an ARP reply of {} bytes", ans.len()),
                &[
                    ("length 60", ans.len() == 60),
                    ("to the requester's MAC", at(0..6) == req.get(22..28)),
                    (
                        "an Ethernet ARP reply",
                        at(12..22) == Some(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 2][..]),
                    ),
                    (
                        "the scanner MAC as sender",
                        at(22..28) == Some(&st.scanner_mac[..]),
                    ),
                    ("the requester as target", at(32..42) == req.get(22..32)),
                    (
                        "zero padding",
                        ans.get(42..).is_some_and(|p| p.iter().all(|b| *b == 0)),
                    ),
                ],
            )
        }
        IpAddr::V6(s) => {
            let (Some(q), Some(a)) = (iv::pkt(req), iv::pkt(ans)) else {
                return Some("a Neighbor Advertisement not in C's form: unparsable".into());
            };
            let l4 = |r: std::ops::Range<usize>| a.l4.get(r);
            let mut tlla = vec![2, 1];
            tlla.extend(st.scanner_mac);
            wrong(
                "a Neighbor Advertisement",
                &[
                    ("86 bytes", ans.len() == 86),
                    ("to the requester's MAC", ans.get(..6) == req.get(6..12)),
                    ("no extension header", !a.ext),
                    ("hop limit 255", a.ttl == 255),
                    ("from the source", a.src == IpAddr::V6(s)),
                    ("to the requester", a.dst == q.src),
                    ("ICMPv6 length 32", a.l4.len() == 32),
                    ("code 0", l4(1..2) == Some(&[0][..])),
                    ("flags 0x60", l4(4..8) == Some(&[0x60, 0, 0, 0][..])),
                    (
                        "the scanner MAC as target link-layer address",
                        l4(24..32) == Some(&tlla[..]),
                    ),
                    ("a right checksum", icmp6_sum_ok(ans)),
                ],
            )
        }
    }
}

/// What a TCP step proves about the scanner's frames once the stand is known to have behaved (FAIL on rmasscan's
/// step once the evidence is proven, INVALID on the oracle's): no frame of a destroyed connection or a scrubbed TCB,
/// right sums, the hello and lifetime windows, the stateless RST rule, the resolved connection's data.
fn tcp_scanner(r: &mut Run, c: &TcpCase, s: &Side<BView>, v: &TcpView) {
    if s.spec.who == Who::Rmasscan {
        cap(
            r,
            s,
            "no segment of a scrubbed TCB (E1.5: rmasscan stops a frame's events at the destroying one)",
            v.scrubbed.is_empty(),
            v.scrubbed.len(),
        );
    }
    let after: Vec<String> = v
        .conns
        .iter()
        .flat_map(|x| {
            x.after_destroy().into_iter().map(move |g| {
                format!(
                    "{}:{} flags {:#04x} {:.3} s after its end",
                    ip_text(x.ip),
                    x.port,
                    g.flags,
                    g.t - x.destroyed_at().unwrap_or(g.t)
                )
            })
        })
        .collect();
    cap(
        r,
        s,
        "no frame of a connection after the connection was destroyed (its RST, the peer's RST, or the peer's ACK of its FIN in LAST_ACK)",
        after.is_empty(),
        some4(&after, 4).join("; "),
    );
    let bad_sums: Vec<String> = v
        .conns
        .iter()
        .flat_map(|x| {
            x.scanner
                .iter()
                .filter(|g| !g.sums_ok)
                .map(move |_| ip_text(x.ip))
        })
        .collect();
    if s.spec.who == Who::Rmasscan {
        cap(
            r,
            s,
            "every stack frame of rmasscan carries right IPv4 header and TCP sums (E1.10: the full header checksum)",
            bad_sums.is_empty(),
            bad_sums.len(),
        );
    }
    // The hello: 1.0-3.5 s after the SYN-ACK, on the hello ports whose server waits for it.
    let mut hello = Vec::new();
    let mut hellos = 0;
    for x in v.conns.iter().filter(|x| x.open) {
        let Some(sc) = tcp_scenario(x.port, x.ip) else {
            continue;
        };
        if !c.banners || !TCP_HELLO_PORTS.contains(&x.port) || sc.server_first() {
            continue;
        }
        let first = x.scanner.iter().find(|g| !g.payload.is_empty());
        match first {
            Some(g) if (HELLO_WINDOW.0..=HELLO_WINDOW.1).contains(&(g.t - x.reply_t)) => {
                hellos += 1
            }
            Some(g) => hello.push(format!(
                "{}:{} after {:.3} s",
                ip_text(x.ip),
                x.port,
                g.t - x.reply_t
            )),
            None => hello.push(format!("{}:{} never", ip_text(x.ip), x.port)),
        }
    }
    if c.banners {
        cap(
            r,
            s,
            &format!(
                "the hello leaves {}-{} s after the SYN-ACK on every hello port whose server waits for it",
                HELLO_WINDOW.0, HELLO_WINDOW.1
            ),
            hello.is_empty(),
            if hello.is_empty() {
                format!("{hellos} hellos")
            } else {
                some4(&hello, 4).join("; ")
            },
        );
    }
    if c.banners {
        // The second connections (TLS `--cert` reconnect, reference D1) are an obligation keyed on the case
        // and the scenario, never on their own presence: a scanner that opens none must fail, not pass with
        // nothing to check. Exactly one for each open first connection whose scenario is direct TLS
        // ([`TcpScenario::direct_tls`]) in a case that scans a source-port range, and no other second
        // connection.
        let reconnects: Vec<&Conn> = v.conns.iter().filter(|x| x.reconnect).collect();
        let ranged = c.source_ports.0 < c.source_ports.1;
        let mut expected = 0usize;
        let mut counts = Vec::new();
        for x in v.conns.iter().filter(|x| x.open && !x.reconnect) {
            let tls = ranged && tcp_scenario(x.port, x.ip).is_some_and(TcpScenario::direct_tls);
            expected += usize::from(tls);
            let n = reconnects
                .iter()
                .filter(|y| y.ip == x.ip && y.port == x.port)
                .count();
            if n != usize::from(tls) {
                counts.push(format!(
                    "{}:{} {n} second connections",
                    ip_text(x.ip),
                    x.port
                ));
            }
        }
        if expected > 0 || !reconnects.is_empty() {
            cap(
                r,
                s,
                "the scanner opens C's second connection (--cert) once for each open TLS connection, and no other second connection",
                counts.is_empty(),
                if counts.is_empty() {
                    format!("{} second connections", reconnects.len())
                } else {
                    some4(&counts, 4).join("; ")
                },
            );
        }
        // Each second connection there is: from the next source port of its first by C's arithmetic over the
        // case's range, its SYN sequence number the cookie of its 4-tuple (seed 1 of the window's argv).
        if !reconnects.is_empty() {
            let (first_port, last_port) = c.source_ports;
            let next_port = |sport: u16| -> u16 {
                let next = u32::from(sport) + 1;
                if next >= u32::from(last_port) {
                    first_port
                } else {
                    next as u16
                }
            };
            let mut bad = Vec::new();
            for x in &reconnects {
                let firsts: Vec<&Conn> = v
                    .conns
                    .iter()
                    .filter(|y| !y.reconnect && y.ip == x.ip && y.port == x.port && y.open)
                    .collect();
                if firsts.len() != 1 {
                    bad.push(format!(
                        "{}:{} from {}: {} first connections",
                        ip_text(x.ip),
                        x.port,
                        x.sport,
                        firsts.len()
                    ));
                    continue;
                }
                if x.sport != next_port(firsts[0].sport) {
                    bad.push(format!(
                        "{}:{} reconnect from {}, want {} (next of {})",
                        ip_text(x.ip),
                        x.port,
                        x.sport,
                        next_port(firsts[0].sport),
                        firsts[0].sport
                    ));
                }
                let cookie = match (x.ip, c.source()) {
                    (IpAddr::V4(remote), IpAddr::V4(local)) => {
                        rmasscan_core::cookie::syn_cookie_ipv4(
                            u32::from(remote),
                            u32::from(x.port),
                            u32::from(local),
                            u32::from(x.sport),
                            1,
                        ) as u32
                    }
                    (IpAddr::V6(remote), IpAddr::V6(local)) => {
                        rmasscan_core::cookie::syn_cookie_ipv6(
                            u128::from(remote),
                            u32::from(x.port),
                            u128::from(local),
                            u32::from(x.sport),
                            1,
                        ) as u32
                    }
                    _ => 0,
                };
                if x.iss_me != cookie {
                    bad.push(format!(
                        "{}:{} reconnect SYN seq {:#x}, cookie {:#x}",
                        ip_text(x.ip),
                        x.port,
                        x.iss_me,
                        cookie
                    ));
                }
            }
            cap(
                r,
                s,
                "every second connection opens from the next source port of its first (C's _next_IP_port over the case's range) with the cookie of its 4-tuple as its SYN sequence number",
                bad.is_empty(),
                if bad.is_empty() {
                    format!("{} reconnects", reconnects.len())
                } else {
                    some4(&bad, 4).join("; ")
                },
            );
        }
        if c.extra_args.contains(&"--heartbleed") {
            let mut bad = Vec::new();
            for x in v.conns.iter().filter(|x| x.open) {
                let (mut sent, mut windows) = (false, Vec::new());
                for g in &x.scanner {
                    if !g.payload.is_empty() {
                        sent = true;
                    }
                    if sent {
                        windows.push(
                            iv::pkt(&g.frame)
                                .and_then(|pkt| pkt.l4.get(14..16).map(|b| be16(b, 0))),
                        );
                    }
                }
                if windows.iter().any(|w| *w != Some(600)) {
                    bad.push(format!(
                        "{}:{} windows {:?}",
                        ip_text(x.ip),
                        x.port,
                        windows.iter().take(4).collect::<Vec<_>>()
                    ));
                }
            }
            cap(
                r,
                s,
                "in heartbleed mode every frame from the hello on carries the small window 600 (banner_set_small_window)",
                bad.is_empty(),
                some4(&bad, 4).join("; "),
            );
        }
        // The lifetime RST: timeout + 2 ± 2 s after the SYN-ACK, on every connection the scenario holds open when the
        // case's lifetime ends inside the scan; none at all otherwise (teardown). R8's RST to a FIN of the peer after
        // the connection's end (Conn::rst_to_fin_without_tcb) is no lifetime RST: after_destroy judges it.
        let life = f64::from(c.lifetime());
        let within = c.connection_timeout.is_some();
        let mut bad = Vec::new();
        let mut rsts = 0;
        for x in v.conns.iter().filter(|x| x.open) {
            let mine: Vec<&Seg> = x
                .scanner
                .iter()
                .filter(|g| g.flags & RST != 0 && !x.rst_to_fin_without_tcb(g))
                .collect();
            let held = tcp_scenario(x.port, x.ip).is_some_and(TcpScenario::held);
            for g in &mine {
                let dt = g.t - x.reply_t;
                if !within || !(life + LIFETIME_WINDOW.0..=life + LIFETIME_WINDOW.1).contains(&dt) {
                    bad.push(format!("{}:{} RST after {dt:.3} s", ip_text(x.ip), x.port));
                }
            }
            rsts += mine.len();
            if within && held && mine.len() != 1 {
                bad.push(format!(
                    "{}:{} held open and {} RSTs",
                    ip_text(x.ip),
                    x.port,
                    mine.len()
                ));
            }
        }
        cap(
            r,
            s,
            &if within {
                format!(
                    "the lifetime RST leaves {}-{} s after the SYN-ACK (--connection-timeout {} + 2 ± 2 s) on every connection held open, and no other RST (from --noreset too)",
                    life + LIFETIME_WINDOW.0,
                    life + LIFETIME_WINDOW.1,
                    c.lifetime()
                )
            } else {
                "no RST of the scanner: the connections alive at the end of the scan are flushed without a frame (tcpcon_destroy_table)".into()
            },
            bad.is_empty(),
            if bad.is_empty() {
                format!("{rsts} RSTs")
            } else {
                some4(&bad, 4).join("; ")
            },
        );
    } else {
        // R8: the stateless RST, one per first reply of a connection (SYN-ACK or RST) that passed C's dedup, seq the
        // reply's ack, ack 0, flags 0x04 (src/main.c:1094-1100); --noreset sends none. Its whole frame is the SYN
        // template's form (`av::is_stateless_rst`: window 1200, the SYN's options and TTL, C's IPv4 id, the padding), as
        // the protocols, ipv6 and autodetect plans judge it (L-M1): t05 sends it from a source no kernel owns.
        let mut bad = Vec::new();
        for x in &v.conns {
            let want: Vec<RelSeg> = if c.noreset {
                Vec::new()
            } else {
                vec![(RST, Vec::new(), x.reply_ack.wrapping_sub(x.iss_me), None)]
            };
            let syn = v.probes.get(x.probe).map(|p| &p.frame[..]);
            let form = x
                .scanner
                .iter()
                .all(|g| syn.is_some_and(|p| av::is_stateless_rst(p, &g.frame)));
            if x.sequence() != want || !form {
                bad.push(format!(
                    "{}:{} ({}) {:?}",
                    ip_text(x.ip),
                    x.port,
                    if x.open { "SYN-ACK" } else { "reset" },
                    x.sequence()
                        .iter()
                        .map(|q| format!("{:#04x}", q.0))
                        .collect::<Vec<_>>()
                ));
            }
        }
        cap(
            r,
            s,
            &if c.noreset {
                "--noreset: no RST of the scanner, to a SYN-ACK or to a reset (R8)".to_owned()
            } else {
                "exactly one stateless RST per connection, to its SYN-ACK or its reset: seq the reply's ack, ack 0, flags 0x04, the rest the SYN template's (window 1200, the SYN's options and TTL, C's IPv4 id, padding to 60 bytes; R8, src/main.c:1094-1100, src/templ-pkt.c:419-613)".to_owned()
            },
            bad.is_empty() && !v.conns.is_empty(),
            if bad.is_empty() {
                format!("{} connections", v.conns.len())
            } else {
                some4(&bad, 4).join("; ")
            },
        );
    }
    if c.resolve {
        // The peer took the answer: its SYN-ACK came, and the connection carried data.
        let done = v
            .conns
            .iter()
            .filter(|x| x.open && !x.peer_stream().is_empty())
            .count();
        cap(
            r,
            s,
            "after the resolution the connection opens and carries its scenario's stream",
            done > 0,
            format!("{done} connections with data"),
        );
    }
}

/// The step's notes: how many frames of each kind its scanner side sent.
fn tcp_counts(v: &TcpView) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    let segs: usize = v.conns.iter().map(|x| x.scanner.len()).sum();
    let rsts: usize = v
        .conns
        .iter()
        .map(|x| x.scanner.iter().filter(|g| g.flags & RST != 0).count())
        .sum();
    m.insert("syns".into(), json!(v.probes.len()));
    m.insert(
        "connections".into(),
        json!(v.conns.iter().filter(|x| x.open).count()),
    );
    m.insert(
        "resets_of_the_peer".into(),
        json!(v.conns.iter().filter(|x| !x.open).count()),
    );
    m.insert("stack_segments".into(), json!(segs));
    m.insert("scanner_rsts".into(), json!(rsts));
    m.insert("answers_for_source".into(), json!(v.answers.len()));
    m.insert("scrubbed_tcb_segments".into(), json!(v.scrubbed.len()));
    m.insert("heartbeats".into(), json!(v.heartbeats.len()));
    m.insert("unexplained".into(), json!(v.scanner_unexplained.len()));
    m.insert(
        "answers_to_the_peers_stray_frames".into(),
        json!(v.scanner_answers_to_peer.len()),
    );
    m.insert(
        "peer_answers_to_unexplained".into(),
        json!(v.peer_answers_to_scanner.len()),
    );
    m
}

/// The records a TCP step's document holds for its wire, in reply order: an `open` per connection (C writes it at
/// the SYN-ACK, `src/main.c:1048-1102`; a closed port is not shown without `--show closed`). The oracle's IPv6 ttl
/// is masked (`ipv6-ttl`).
pub fn tcp_wire_records(v: &TcpView, who: Who, out: Out) -> Vec<(Rec, f64)> {
    let binary = out == Out::Binary;
    v.conns
        .iter()
        .filter(|x| x.open)
        .map(|x| {
            let ttl = (binary && !(who == Who::Oracle && x.ip.is_ipv6())).then_some(x.reply_ttl);
            (
                Rec {
                    ip: x.ip,
                    port: x.port,
                    proto: "tcp".into(),
                    body: Body::Status {
                        st: St::Open,
                        reason: binary.then(|| reason_string(x.reply_flags)),
                        ttl,
                    },
                    ts: None,
                },
                x.reply_t,
            )
        })
        .collect()
}
/// A record with its IPv6 ttl taken out (`ipv6-ttl`: C's is stale, E1.9).
fn without_ipv6_ttl(x: &Rec) -> Rec {
    let mut y = x.bare();
    if y.ip.is_ipv6() {
        match &mut y.body {
            Body::Status { ttl, .. } | Body::Banner { ttl, .. } => *ttl = None,
        }
    }
    y
}

/// What one TCP step's document proves about its banners: each connection's banners in one run after its `open`
/// (M1); each connection whose peer sent its whole scenario holds the scenario's applications in flush order; no
/// banner of a port the stand reset.
fn tcp_banner_checks(r: &mut Run, s: &Side<BView>, d: &Document) {
    // Per connection key: banner blocks (maximal runs of banner records of the key), each after an open of
    // the key, at most one block per open. Two connections to one (address, port) — the TLS second
    // connection — give two opens and two blocks.
    let mut opens: BTreeMap<(IpAddr, u16), usize> = BTreeMap::new();
    let mut blocks: BTreeMap<(IpAddr, u16), usize> = BTreeMap::new();
    let mut bad = Vec::new();
    let mut prev_banner_key: Option<(IpAddr, u16)> = None;
    for x in &d.records {
        let k = (x.ip, x.port);
        match &x.body {
            Body::Status { st: St::Open, .. } => {
                *opens.entry(k).or_default() += 1;
                prev_banner_key = None;
            }
            Body::Banner { .. } => {
                if prev_banner_key != Some(k) {
                    *blocks.entry(k).or_default() += 1;
                    let opened = opens.get(&k).copied().unwrap_or(0);
                    if opened < blocks[&k] {
                        bad.push(format!(
                            "{}:{}: {}",
                            ip_text(x.ip),
                            x.port,
                            if opened == 0 {
                                "a banner before its open"
                            } else {
                                "its banners are not in one run"
                            }
                        ));
                    }
                    prev_banner_key = Some(k);
                }
            }
            Body::Status { .. } => prev_banner_key = None,
        }
    }
    beh(
        r,
        s,
        "the banners of one TCP connection come in one run, after its open record (M1)",
        bad.is_empty(),
        some4(&bad, 4).join("; "),
    );
    let Some(v) = tcp_of(s) else { return };
    let by = banners_by_reply(d);
    let mut wrong = Vec::new();
    let mut judged = 0;
    let mut groups: BTreeMap<(IpAddr, u16), Vec<&Conn>> = BTreeMap::new();
    for x in &v.conns {
        groups.entry((x.ip, x.port)).or_default().push(x);
    }
    for ((ip, port), conns) in &groups {
        let got: Vec<String> = by
            .get(&(*ip, *port))
            .map(|b| b.iter().filter_map(|y| y.app_name()).collect())
            .unwrap_or_default();
        let Some(sc) = tcp_scenario(*port, *ip) else {
            if !got.is_empty() {
                wrong.push(format!(
                    "{}:{port} no scenario, banners {got:?}",
                    ip_text(*ip)
                ));
            }
            continue;
        };
        let full = conns
            .iter()
            .filter(|x| x.open && x.peer_stream() == sc.stream())
            .count();
        if full == 0 {
            if conns.iter().all(|x| !x.open) && !got.is_empty() {
                wrong.push(format!("{}:{port} reset, banners {got:?}", ip_text(*ip)));
            }
            continue;
        }
        judged += full;
        let want: Vec<&str> = sc
            .apps
            .iter()
            .copied()
            .cycle()
            .take(sc.apps.len() * full)
            .collect();
        if got.iter().map(String::as_str).collect::<Vec<_>>() != want {
            wrong.push(format!(
                "{}:{port} {got:?}, the scenario {:?} on {full} connection(s)",
                ip_text(*ip),
                sc.apps
            ));
        }
    }
    cap(
        r,
        s,
        "each connection's banners carry, in flush order, the applications its scenario declares (TCP_SCENARIOS), and a reset port has none",
        wrong.is_empty() && (judged > 0 || !d.records.iter().any(Rec::is_banner)),
        if wrong.is_empty() {
            format!("{judged} connections")
        } else {
            some4(&wrong, 4).join("; ")
        },
    );
}

/// Every ClientHello template of the product, as a full record, tagged dynamicized or static: the dynamicized
/// vuln-mode ones (heartbeat, ticketbleed, sslv3+SCSV) carry a random field (bytes 11..43 of the record) the
/// two scanners cannot share; the static default and TLS 1.3 ones are the same bytes on every run. The bytes
/// outside the random field are the template's at any moment (`TlsSettings::new(0)`).
fn hello_templates() -> Vec<(bool, Vec<u8>)> {
    use rmasscan_proto::TlsHelloKind::*;
    let kinds = rmasscan_proto::TlsSettings::new(0);
    [
        (false, Default),
        (false, Tls13),
        (true, Heartbeat),
        (true, Ticketbleed),
        (true, Sslv3Poodle),
    ]
    .into_iter()
    .map(|(dynamic, kind)| (dynamic, kinds.hello(kind).to_vec()))
    .collect()
}
/// The template a ClientHello starts with at `s[0]`, by content: every available byte outside the random
/// field (11..43) is the template's, the 11-byte head (the record header with its length, the handshake
/// head) in full — the head alone already separates the five templates. Never the TCP payload's length: a
/// hello may fill one segment, share it after other bytes (STARTTLS), or be split over several, and only
/// the connection's byte stream shows where a record starts.
fn hello_template_at<'a>(
    s: &[u8],
    templates: &'a [(bool, Vec<u8>)],
) -> Option<&'a (bool, Vec<u8>)> {
    if s.len() < 11 || s[0] != 0x16 || s[5] != 0x01 {
        return None;
    }
    templates.iter().find(|(_, t)| {
        s[..11] == t[..11] && {
            let n = s.len().min(t.len());
            n <= 43 || s[43..n] == t[43..n]
        }
    })
}

/// A sequence with every dynamicized ClientHello's random field zeroed ('tls-hello-random'): the static
/// default and TLS 1.3 hellos always compare byte for byte (reference A2). The hellos are found by content
/// in the connection's byte stream (the segments' payloads in order, spans kept), so one split over
/// segments or sharing a segment with what precedes it is masked exactly where its record lies.
fn masked_sequence(x: &Conn, mask: bool) -> Vec<RelSeg> {
    let mut seq = x.sequence();
    if !mask {
        return seq;
    }
    let templates = hello_templates();
    let mut stream: Vec<u8> = Vec::new();
    let mut spans: Vec<(usize, usize)> = Vec::with_capacity(seq.len());
    for seg in &seq {
        spans.push((stream.len(), seg.1.len()));
        stream.extend_from_slice(&seg.1);
    }
    let mut i = 0;
    while i + 11 <= stream.len() {
        match hello_template_at(&stream[i..], &templates) {
            Some((true, _)) => {
                let end = (i + 43).min(stream.len());
                stream[i + 11..end].fill(0);
                i = end;
            }
            _ => i += 1,
        }
    }
    for (seg, &(start, len)) in seq.iter_mut().zip(&spans) {
        seg.1.copy_from_slice(&stream[start..start + len]);
    }
    seq
}

/// rmasscan's connections against C's of the same document: per connection (address, port, source port) the
/// scanner's segments, flags, payload and sequence and acknowledgment relative to the SYN and the reply, equal C's
/// in order (C's scrubbed-TCB segments aside, `no-frame-from-destroyed-tcb`); the answers to the peer's ARP requests
/// equal C's byte for byte.
fn tcp_vs_c(r: &mut Run, c: &TcpCase, rm: &Side<BView>, or: &Side<BView>) {
    let (Some(a), Some(b)) = (tcp_of(rm), tcp_of(or)) else {
        return;
    };
    let mut diff = Vec::new();
    let keys: BTreeSet<(IpAddr, u16, u16)> = a
        .conns
        .iter()
        .chain(&b.conns)
        .map(|x| (x.ip, x.port, x.sport))
        .collect();
    for (ip, port, sport) in &keys {
        let mask = c.deviations.contains(&"tls-hello-random");
        let of = |v: &TcpView| {
            v.conns
                .iter()
                .find(|x| x.ip == *ip && x.port == *port && x.sport == *sport)
                .map(|x| masked_sequence(x, mask))
        };
        let (x, y) = (of(a), of(b));
        if x != y {
            let at = match (&x, &y) {
                (Some(x), Some(y)) => x
                    .iter()
                    .zip(y)
                    .position(|(p, q)| p != q)
                    .unwrap_or(x.len().min(y.len())),
                _ => 0,
            };
            diff.push(format!(
                "{}:{port}: rmasscan {} segments, C {}, first difference at {at}",
                ip_text(*ip),
                x.map_or(0, |v| v.len()),
                y.map_or(0, |v| v.len())
            ));
        }
    }
    r.cap(
        &format!(
            "{}: every connection's scanner segments equal the C oracle's ({}): flags, payload, relative seq and ack, in order",
            rm.spec.name, or.spec.name
        ),
        diff.is_empty() && !keys.is_empty(),
        if diff.is_empty() {
            format!("{} connections", keys.len())
        } else {
            some4(&diff, 4).join("; ")
        },
    );
    if c.resolve && !c.v6 {
        // How often the peer asked is the stand's, not a difference from C (M5); a scanner that failed the peer's
        // request made it ask again, which that step's own check judged (tcp_scanner_first).
        let st = stand();
        let failed = |v: &TcpView| !resolution_problems(c, v, &st).is_empty();
        r.inv(
            &format!(
                "{}: the peer asked both scanners for the source as often ({}), or one of them failed its request",
                rm.spec.name, or.spec.name
            ),
            a.requests.len() == b.requests.len() || failed(a) || failed(b),
            format!(
                "{} requests, C's step {}",
                a.requests.len(),
                b.requests.len()
            ),
        );
        let same = a
            .answers
            .iter()
            .map(|x| &x.1)
            .eq(b.answers.iter().map(|x| &x.1));
        r.cap(
            &format!(
                "{}: the ARP replies for the source equal the C oracle's ({}) byte for byte",
                rm.spec.name, or.spec.name
            ),
            same,
            format!("{} replies, C {}", a.answers.len(), b.answers.len()),
        );
    }
}

/// Before the comparisons with C of a TCP case: C's forced exit and the TCP deviations' conditions, so that an unmet
/// one makes every comparison after it INVALID ([`PairPlan::before_vs_c`]). The peer streams of both steps of a
/// document need no condition here: every step's own checks run first ([`tcp_stand`] with [`Conn::owed`]), so a peer
/// stream short of what either scanner's frames owe has made the run INVALID before these comparisons.
fn tcp_before_vs_c(
    r: &mut Run,
    c: &TcpCase,
    sides: &[Side<BView>],
    docs: &[Option<Document>],
    tally: Tally,
) {
    // C's forced exit skips tcpcon_destroy_table (src/main.c:1111-1113, :1489-1496): the banners of connections still
    // alive at the end of its scan were never written, so its document is no reference for them.
    for s in sides
        .iter()
        .filter(|s| s.spec.who == Who::Oracle && c.banners)
    {
        let alive = tcp_of(s).map_or(0, |v| {
            v.conns
                .iter()
                .filter(|x| x.open && x.destroyed_at().is_none())
                .filter(|x| !x.scanner.iter().any(|g| g.flags & FIN != 0))
                .count()
        });
        r.inv(
            &format!(
                "{}: C flushed its connections alive at the end of the scan (no forced exit with connections alive: tcpcon_destroy_table ran)",
                s.spec.name
            ),
            !(s.forced_exit && alive > 0),
            format!("forced exit {}, {alive} connections alive at the end", s.forced_exit),
        );
    }
    tcp_deviations(r, c, sides, docs, tally.collapsed);
}

/// [`tcp_vs_c`] for each document's pair of steps, the oracle's banner checks (rmasscan's are its step's) and the
/// notes of a TCP case.
fn tcp_finish(r: &mut Run, c: &TcpCase, sides: &[Side<BView>], docs: &[Option<Document>]) {
    let mut counts = serde_json::Map::new();
    for (s, d) in sides.iter().zip(docs) {
        let Some(d) = d else { continue };
        if s.spec.who == Who::Oracle {
            tcp_banner_checks(r, s, d);
        }
        let mut by_app: BTreeMap<String, usize> = BTreeMap::new();
        for name in d.records.iter().filter_map(Rec::app_name) {
            *by_app.entry(name).or_default() += 1;
        }
        counts.insert(s.spec.name.into(), json!(by_app));
    }
    for pair in sides.chunks(2) {
        if let [rm, or] = pair {
            tcp_vs_c(r, c, rm, or);
        }
    }
    r.notes
        .insert("banners_by_app".into(), Value::Object(counts));
    r.notes.insert(
        "tcp_scenarios".into(),
        json!(
            TCP_SCENARIOS
                .iter()
                .map(|x| json!({"peer": x.peer, "port": x.port, "about": x.about, "apps": x.apps, "split": x.split}))
                .collect::<Vec<_>>()
        ),
    );
}

/// Each named deviation of a TCP case: the wire condition that keeps it from changing the comparison, and the notes.
fn tcp_deviations(
    r: &mut Run,
    c: &TcpCase,
    sides: &[Side<BView>],
    docs: &[Option<Document>],
    masked: usize,
) {
    let views: Vec<(&Side<BView>, &TcpView)> = sides
        .iter()
        .filter_map(|s| tcp_of(s).map(|v| (s, v)))
        .collect();
    named_deviations(r, c.deviations, &DEVIATIONS, |name| match name {
        "rx-checksum-verify" => {
            // The replies (SYN-ACK, RST) and every later segment of the peer.
            let bad = views
                .iter()
                .flat_map(|(_, v)| &v.conns)
                .map(|x| {
                    usize::from(!x.reply_sums_ok) + x.peer.iter().filter(|g| !g.sums_ok).count()
                })
                .sum::<usize>();
            (
                bad == 0,
                format!("{bad} replies and peer segments with a wrong sum"),
            )
        }
        "ipv4-stack-checksum" => {
            // A wrong IPv4 header checksum of C makes the peer drop the frame: the two wires would part.
            let (mut n, mut bad) = (0, 0);
            for (s, v) in &views {
                if s.spec.who != Who::Oracle {
                    continue;
                }
                for g in v.conns.iter().flat_map(|x| &x.scanner) {
                    n += 1;
                    bad += usize::from(!g.ip_sum_ok);
                }
            }
            (
                bad == 0,
                format!(
                    "{bad} of C's {n} stack frames with a wrong IPv4 header checksum (rmasscan's are its own check)"
                ),
            )
        }
        "ipv6-ttl" => {
            let mut bad = 0;
            for ((s, v), d) in views.iter().zip(docs) {
                let (Some(d), Who::Rmasscan, Out::Binary) = (d, s.spec.who, s.spec.out) else {
                    continue;
                };
                for x in d.records.iter().filter(|x| x.ip.is_ipv6()) {
                    let want = v
                        .conns
                        .iter()
                        .find(|y| y.ip == x.ip && y.port == x.port)
                        .map(|y| y.reply_ttl);
                    let ttl = match &x.body {
                        Body::Status { ttl, .. } | Body::Banner { ttl, .. } => *ttl,
                    };
                    bad += usize::from(ttl != want);
                }
            }
            (
                bad == 0,
                format!(
                    "{masked} IPv6 records of C without their ttl in the comparison; rmasscan's -oB IPv6 records off their SYN-ACK's hop limit: {bad}"
                ),
            )
        }
        "memcached-tcp-past-segment" => {
            let bad = views
                .iter()
                .flat_map(|(_, v)| v.conns.iter().filter(|x| x.port == 11211))
                .flat_map(|x| x.peer_data())
                .filter(|g| g.payload.last() != Some(&b'\n'))
                .count();
            (
                bad == 0,
                format!(
                    "{bad} memcached segments of the peer that do not end with LF (C would read past them in state 2)"
                ),
            )
        }
        "tls-hello-random" => {
            // Every masked hello must be a dynamic ClientHello, and every ClientHello of the case a known
            // template: the scanner byte stream of each TLS connection, walked record by record (443 is TLS
            // from its first byte) and each handshake record matched by content against the five templates,
            // static ones included (they compare byte for byte elsewhere; here they only prove the masking
            // hid no other hello). Segment lengths are never consulted: a record may be split over segments
            // or share one.
            let templates = hello_templates();
            let mut bad = 0;
            for (_, v) in &views {
                for x in v.conns.iter().filter(|x| x.open && x.port == 443) {
                    let stream: Vec<u8> = x
                        .scanner
                        .iter()
                        .flat_map(|g| g.payload.iter().copied())
                        .collect();
                    let mut i = 0;
                    while i < stream.len() {
                        if stream[i] == 0x16
                            && hello_template_at(&stream[i..], &templates).is_none()
                        {
                            bad += 1;
                        }
                        let rec = stream
                            .get(i + 3..i + 5)
                            .map_or(0, |b| 5 + usize::from(be16(b, 0)));
                        if rec == 0 {
                            break;
                        }
                        i += rec;
                    }
                }
            }
            (
                bad == 0,
                format!(
                    "{bad} handshake records on TLS connections that are not ClientHellos of a known template"
                ),
            )
        }
        "minecraft-unsplit" => {
            let bad = views
                .iter()
                .flat_map(|(_, v)| v.conns.iter().filter(|x| x.port == 25565))
                .filter(|x| x.peer_segments() > 1)
                .count();
            (
                bad == 0,
                format!(
                    "{bad} Minecraft replies in more than one segment (C's multi-segment path)"
                ),
            )
        }
        "no-frame-from-destroyed-tcb" => {
            let n: usize = views
                .iter()
                .filter(|(s, _)| s.spec.who == Who::Oracle)
                .map(|(_, v)| v.scrubbed.len())
                .sum();
            (
                true,
                format!(
                    "{n} segments of C from a scrubbed TCB (255.255.255.255:65535), left out of its connections"
                ),
            )
        }
        _ => (false, "unknown deviation".into()),
    });
}

/// The `[+]` lines of a TCP step of rmasscan: the interface by the route to the first target, its MAC, the given
/// source and next hop, seed and source port.
fn tcp_plus(c: &TcpCase) -> Vec<(&'static str, String)> {
    let first = c.targets.split('-').next().unwrap_or_default().to_owned();
    let mut w = vec![
        ("interface", format!("veth-a (detected: route to {first})")),
        ("source-mac", "02-aa-00-00-00-01 (detected)".to_owned()),
        ("source-ip", format!("{} (given)", ip_text(c.source()))),
    ];
    w.push((
        if c.v6 {
            "router-mac-ipv6"
        } else {
            "router-mac"
        },
        format!("{PEER_MAC_ARG} (given)"),
    ));
    w.push(("seed", "1 (given)".to_owned()));
    w.push(("source-port", "40000 (given)".to_owned()));
    w
}
fn tcp_rmasscan_step(r: &mut Run, c: &TcpCase, s: &Side<BView>, doc: Option<&Document>) {
    pair_verify::rmasscan_step(
        r,
        s,
        doc,
        |r, s| {
            let want = tcp_plus(c);
            let ok = s.se.plus.len() == want.len()
                && s.se
                    .plus
                    .iter()
                    .zip(&want)
                    .all(|((k, v), (wk, wv))| k == wk && v == wv);
            beh(
                r,
                s,
                &format!(
                    "[+] lines are the stand's: {}",
                    want.iter()
                        .map(|(k, v)| format!("{k} = {v}"))
                        .collect::<Vec<_>>()
                        .join(" | ")
                ),
                ok,
                format!("{:?}", s.se.plus),
            );
        },
        |v| {
            let BView::Tcp(v) = v else {
                return WireSummary {
                    counts: (0, 0, 0),
                    first_probe: None,
                    last_reply: None,
                };
            };
            let end = v.probes.last().map(|p| p.t + f64::from(c.wait));
            WireSummary {
                counts: (
                    v.probes.iter().filter(|p| !p.reconnect).count() as u64,
                    v.conns.len() as u64,
                    v.conns.iter().filter(|x| x.open).count() as u64,
                ),
                first_probe: v.probes.first().map(|p| p.t),
                last_reply: [v.last_frame(), end].into_iter().flatten().reduce(f64::max),
            }
        },
    );
    // rmasscan's own banners (M1, the scenarios' applications) are judged here, in its step: before the oracle's
    // step, so that a C that never answered (t08) leaves rmasscan's verdict on its own document standing.
    if let Some(d) = doc {
        tcp_banner_checks(r, s, d);
    }
}

// ------------------------------------------------------------------ privacy and evidence

const SCANNER_TEXT: [&str; 1] = [PEER_STACK_JSON];
/// An address a document of the window may hold: a peer of the stand (IPv4 or IPv6).
fn stand_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => stand().peer_ips.contains(&a),
        IpAddr::V6(a) => capture::IPV6_PEERS.iter().any(|p| p.parse() == Ok(a)),
    }
}
fn binary_problems(b: &[u8]) -> Vec<String> {
    match parse_doc(Out::Binary, b) {
        Err(e) => vec![format!(
            "not a masscan -oB file ({e}); its bytes are not scanned as text"
        )],
        Ok(d) => d
            .records
            .iter()
            .filter(|x| !stand_peer(x.ip))
            .map(|x| format!("address {}", x.ip))
            .collect(),
    }
}
/// The window's sources: the 4a scanner address and the TCP cases' own (R9).
fn scanner_sources() -> [IpAddr; 5] {
    [
        IpAddr::V4(stand().scanner_ip),
        IpAddr::V4(TCP_SOURCE),
        IpAddr::V4(RESOLVE_SOURCE),
        IpAddr::V6(TCP_SOURCE6),
        IpAddr::V6(RESOLVE_SOURCE6),
    ]
}
/// SYNs that are not the scanner's (stand MAC, one of the window's sources) to a peer of the stand.
pub fn foreign_syns(fr: &Frames) -> usize {
    let st = stand();
    fr.iter()
        .filter(|(_, f)| {
            tcp_head(f).is_some_and(|h| h.flags & 0x3f == SYN)
                && !(f.get(6..12) == Some(&st.scanner_mac[..])
                    && tcp_head(f)
                        .is_some_and(|h| scanner_sources().contains(&h.src) && stand_peer(h.dst)))
        })
        .count()
}
/// Frames of the scanner MAC to an address off the stand or from an address that is none of the window's sources
/// (a safety finding): ARP, IPv4 and IPv6. C's scrubbed-TCB segment (from and to 255.255.255.255, ports 65535, E1.5)
/// stays on the sealed link and is judged by its step (FAIL for rmasscan, `no-frame-from-destroyed-tcb` for C); the
/// scanner namespace kernel's own IPv6 (from its address or link-local, to the peers or link-scope multicast) is the
/// step's noise check.
pub fn foreign(fr: &Frames, st: &Stand) -> Vec<String> {
    let sources = scanner_sources();
    let mut out = Vec::new();
    for (_, f) in fr {
        if f.get(6..12) != Some(&st.scanner_mac[..]) {
            continue;
        }
        if f.get(12..14) == Some(&[8, 6][..]) {
            if f.len() < 42 {
                continue;
            }
            let spa = IpAddr::V4(Ipv4Addr::new(f[28], f[29], f[30], f[31]));
            let tpa = IpAddr::V4(Ipv4Addr::new(f[38], f[39], f[40], f[41]));
            if !sources.contains(&spa) || !stand_peer(tpa) {
                out.push(format!("ARP operation {} {spa} > {tpa}", be16(f, 20)));
            }
            continue;
        }
        let Some(p) = iv::pkt(f) else { continue };
        match (p.src, p.dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let scrubbed = tcp_head(f).is_some_and(|h| {
                    s == Ipv4Addr::BROADCAST
                        && d == Ipv4Addr::BROADCAST
                        && h.sp == 0xffff
                        && h.dp == 0xffff
                });
                if [1, 6, 17, 132].contains(&p.proto)
                    && !scrubbed
                    && !(sources.contains(&p.src) && stand_peer(p.dst))
                {
                    out.push(format!("IPv4 {s} > {d} proto {}", p.proto));
                }
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let own = sources.contains(&p.src)
                    || s.to_string() == capture::IPV6_SCANNER
                    || s.to_string() == capture::IPV6_SCANNER_LL;
                let to = stand_peer(p.dst)
                    || d.to_string() == capture::IPV6_PEER_LL
                    || d.segments()[0] == 0xff02;
                if !own || !to {
                    out.push(format!("IPv6 {s} > {d} next header {}", p.proto));
                }
            }
            _ => {}
        }
    }
    out
}

// ------------------------------------------------------------------ the plan of the shared verifier

/// The scanner-side frame classes of the window: the protocols verifier's (UDP cases) and the TCP cases'.
pub const SCANNER_CLASSES: [(&str, &str); 11] = [
    pv::SCANNER_CLASSES[0],
    pv::SCANNER_CLASSES[1],
    pv::SCANNER_CLASSES[2],
    pv::SCANNER_CLASSES[3],
    pv::SCANNER_CLASSES[4],
    pv::SCANNER_CLASSES[5],
    pv::SCANNER_CLASSES[6],
    (
        "stack_segments",
        "TCP cases: the scanner's segments of a connection the stand opened (its user-mode stack with --banners, the stateless RST without), compared with C's per connection",
    ),
    (
        "answers_for_source",
        "TCP resolve cases: the scanner's ARP reply or Neighbor Advertisement for its own source address, one per request of the peer (C src/main.c:878-887, src/stack-ndpv6.c:95-182)",
    ),
    (
        "scrubbed_tcb_segments",
        "TCP cases, C only: a segment of a TCB C destroyed earlier in the same frame, from and to 255.255.255.255:65535 (E1.5, no-frame-from-destroyed-tcb)",
    ),
    (
        "heartbeats",
        "TCP cases: the peer's heartbeat, a lab marker frame every 200 ms that keeps C's receive loop turning (counted, from the peer)",
    ),
];
/// The ipv6 stand's seal before and after the case (`capture isolation --mode ipv6`): the banners stand is the IPv6
/// stand with the protocols stand's ICMP setting and the TCP sources' neighbour entries in the peer namespace.
fn seal(r: &mut Run, d: &Path) {
    match read_json(d.join(ISOLATION_JSON)) {
        None => r.add(
            "isolation.json present",
            NOT_RUN,
            "missing or invalid JSON",
            false,
        ),
        Some(v) => r.inv(
            "isolation.json: the sealed IPv6 stand (capture isolation --mode ipv6)",
            capture::isolation_permits_ipv6(&v),
            format!("mode {}, ipv6 {}", v["mode"], v["ipv6"]["prefix"]),
        ),
    }
    let post = read_json(d.join(ISOLATION_POST_JSON));
    r.inv(
        "isolation-post.json: the IPv6 stand still sealed after the run (capture isolation --mode ipv6)",
        post.as_ref().is_some_and(capture::isolation_permits_ipv6),
        post.map_or_else(
            || "missing or invalid JSON".to_owned(),
            |v| format!("mode {}", v["mode"]),
        ),
    );
}

/// The banners window as [`pair_verify`] judges it.
pub(crate) struct Banners;
impl PairPlan for Banners {
    type Case = Case;
    type View = BView;
    type Rec = Rec;
    type Expect = BannerExpect;
    const KEY: &'static str = "banners";
    const SCANNER_TEXT: &'static [&'static str] = &SCANNER_TEXT;
    const RECORD_ORDER_VS_C: &'static str = RECORD_ORDER_VS_C;
    const SCANNER_CLASSES: &'static [(&'static str, &'static str)] = &SCANNER_CLASSES;
    const PROBES_VS_C: &'static str = " (udp-checksum-ffff applied)";
    const PROBES_FIRST_DIFFERENCE: bool = true;
    const FOREIGN_SYN: &'static str = "SYN";
    const OWN_WIRE: &'static str = "the document's status records are the replies on its wire, field for field, in reply order (replies captured at most 50 us apart on the peer link, rounded to the microsecond, may come in either order: REPLY_REORDER_WINDOW_US); its banner records are judged against the stand's replies and the C oracle";
    const ORACLE_NOTE: &'static str = "the pinned C masscan 8e6b3b0 with the same argv, one run per document, on the same stand and the same scenario responder";
    const STRAY_PLAN: Option<Plan> = None;

    fn cases() -> Vec<Case> {
        CASES
            .into_iter()
            .map(Case::Udp)
            .chain(TCP_CASES.into_iter().map(Case::Tcp))
            .collect()
    }
    fn tag(c: &Case) -> &'static str {
        c.tag()
    }
    fn steps(c: &Case) -> Vec<StepSpec> {
        steps(c.tag()).unwrap_or_default()
    }
    fn expect(c: &Case) -> Option<BannerExpect> {
        expect(c.tag())
    }
    fn manifest(v: Value) -> Option<Option<String>> {
        serde_json::from_value::<BannerManifest>(v)
            .ok()
            .filter(|x| x.banners == "linux")
            .map(|x| x.lab_id)
    }
    fn view(c: &Case, fr: &Frames, st: &Stand) -> BView {
        match c {
            Case::Udp(_) => BView::Udp(pv::view(fr, st, false)),
            Case::Tcp(t) => BView::Tcp(tcp_view(t, fr, st)),
        }
    }
    fn parse_doc(out: Out, b: &[u8], _who: Who) -> Result<Document, String> {
        parse_doc(out, b)
    }
    fn foreign(fr: &Frames, st: &Stand) -> Vec<String> {
        foreign(fr, st)
    }
    fn foreign_syns(fr: &Frames) -> usize {
        foreign_syns(fr)
    }
    fn text_problems(text: &str, scanner_text: bool) -> Vec<String> {
        let mut p = iface_problems(text);
        p.extend(
            iv::ipv6_tokens(text)
                .into_iter()
                .filter(|ip| {
                    !(iv::ipv6_allowed(*ip, scanner_text)
                        || *ip == TCP_SOURCE6
                        || *ip == RESOLVE_SOURCE6)
                })
                .map(|ip| format!("IPv6 address {ip}")),
        );
        p
    }
    fn binary_problems(b: &[u8]) -> Vec<String> {
        binary_problems(b)
    }
    fn seal(r: &mut Run, d: &Path) {
        seal(r, d);
    }
    fn case_records(r: &mut Run, d: &Path, c: &Case) {
        if let Some(p) = av::typed::<PeerStack>(r, d, PEER_STACK_JSON) {
            let problem = peer_stack_problem_for(&p, c);
            r.inv(
                "peer-stack.json: the peer answers the stand's way (icmp_ratemask 0, Echo answered, the banners responder of the case)",
                problem.is_none(),
                problem.unwrap_or_else(|| format!("{p:?}")),
            );
        }
        if let Case::Tcp(_) = c
            && let Some(p) = av::typed::<PeerTcp>(r, d, PEER_TCP_JSON)
        {
            let problem = peer_tcp_problem(&p);
            r.inv(
                "peer-tcp.json: the peer namespace keeps no TIME_WAIT socket (tcp_max_tw_buckets 0), so each step finds the 4-tuples free",
                problem.is_none(),
                problem.unwrap_or_else(|| format!("{p:?}")),
            );
        }
        // M8: before every step of a resolve case the suite flushed the peer's entry for the source, and says so.
        if let Case::Tcp(t) = c
            && t.resolve
        {
            for spec in steps(t.tag).unwrap_or_default() {
                if let Some(f) = av::typed::<NeighFlush>(r, &d.join(spec.name), NEIGH_FLUSH_JSON) {
                    let problem = neigh_flush_problem(&f, t);
                    r.inv(
                        &format!(
                            "{}/{NEIGH_FLUSH_JSON}: the peer's neighbour entry for the source was flushed before the step",
                            spec.name
                        ),
                        problem.is_none(),
                        problem.unwrap_or_else(|| format!("{:?}", f.argv)),
                    );
                }
            }
        }
    }
    fn plan(c: &Case) -> Result<Vec<Vec<u8>>, String> {
        match c {
            Case::Udp(u) => plan_stream(u),
            Case::Tcp(t) => tcp_plan_stream(t),
        }
    }
    fn step_wire(
        r: &mut Run,
        c: &Case,
        s: &Side<BView>,
        v: &BView,
    ) -> serde_json::Map<String, Value> {
        match (c, v) {
            (Case::Udp(_), BView::Udp(v)) => {
                stand_answers(r, s, v);
                // The IPv6 stand's kernel noise (MLD, router solicitation, DAD) from the scanner MAC is the stand's,
                // not a frame of the scanner: INVALID, and left out of the scanner's own frames.
                let noise = s.frames.as_ref().map_or(0, |fr| {
                    fr.iter()
                        .filter(|(_, f)| f.get(6..12) == Some(&stand().scanner_mac[..]))
                        .filter(|(_, f)| ipv6_kernel_noise(f))
                        .count()
                });
                r.inv(
                    &format!(
                        "{}: no IPv6 kernel noise of the scanner namespace on the wire (MLD, router solicitation, DAD: the stand rules them out)",
                        s.spec.name
                    ),
                    noise == 0,
                    noise,
                );
                let mut skip = noise;
                let own: Vec<String> = v
                    .scanner_unexplained
                    .iter()
                    .filter(|x| {
                        let drop = skip > 0 && x.contains("ethertype 86dd");
                        skip -= usize::from(drop);
                        !drop
                    })
                    .cloned()
                    .collect();
                pair_verify::scanner_frame_checks(
                    r,
                    s,
                    pv::SCANNER_FRAMES_RULE,
                    &own,
                    pv::SCANNER_BOUNDS_RULE,
                    &pv::scanner_bounds(v, s.spec.who),
                );
                pv::own_frame_checks(r, s, v, &stand());
                scanner_counts(
                    &pv::SCANNER_CLASSES,
                    &v.scanner_named,
                    v.scanner_unexplained.len(),
                    &pv::scanner_bounds(v, s.spec.who),
                )
            }
            (Case::Tcp(t), BView::Tcp(v)) => {
                // The scanner's own evidence first, then the stand with what that evidence explains left out, then
                // what needs a stand that behaved (I1: a fault of the scanner is never the stand's INVALID).
                let st = stand();
                tcp_scanner_first(r, t, s, v, &st);
                tcp_stand(r, t, s, v, &st);
                tcp_scanner(r, t, s, v);
                tcp_counts(v)
            }
            _ => {
                r.inv(
                    &format!(
                        "{}: the capture is taken apart by its case's kind",
                        s.spec.name
                    ),
                    false,
                    "a UDP view of a TCP case or the other way round",
                );
                serde_json::Map::new()
            }
        }
    }
    fn rmasscan_step(r: &mut Run, c: &Case, s: &Side<BView>, doc: Option<&Document>) {
        match c {
            Case::Udp(_) => rmasscan_step(r, s, doc),
            Case::Tcp(t) => tcp_rmasscan_step(r, t, s, doc),
        }
    }
    fn wire_records_at(c: &Case, v: &BView, who: Who, out: Out) -> Vec<(Rec, f64)> {
        match (c, v) {
            (Case::Udp(_), BView::Udp(v)) => wire_records_at(v, who, out),
            (Case::Tcp(_), BView::Tcp(v)) => tcp_wire_records(v, who, out),
            _ => Vec::new(),
        }
    }
    fn doc_record(x: &Rec, who: Who) -> Rec {
        if who == Who::Oracle {
            without_ipv6_ttl(x)
        } else {
            x.bare()
        }
    }
    fn own_wire_records(records: &[Rec], who: Who) -> Vec<Rec> {
        records
            .iter()
            .filter(|x| !x.is_banner())
            .map(|x| Self::doc_record(x, who))
            .collect()
    }
    fn same_probe(rm: &[u8], c: &[u8]) -> Option<bool> {
        pv::same_probe(rm, c)
    }
    fn vs_c(c: &Case, rm: &[Rec], oracle: &[Rec]) -> (Vec<Rec>, Vec<Rec>, usize, &'static str) {
        match c {
            Case::Udp(_) => {
                let (got, _) = mask_raw_past_datagram(rm);
                let (want, n) = mask_raw_past_datagram(oracle);
                (
                    got.iter().map(Rec::bare).collect(),
                    want.iter().map(Rec::bare).collect(),
                    n,
                    " (udp-raw-past-datagram applied)",
                )
            }
            Case::Tcp(t) => {
                let n = oracle.iter().filter(|x| x.ip.is_ipv6()).count();
                (
                    rm.iter().map(without_ipv6_ttl).collect(),
                    oracle.iter().map(without_ipv6_ttl).collect(),
                    n,
                    if t.v6 { " (ipv6-ttl applied)" } else { "" },
                )
            }
        }
    }
    fn before_vs_c(
        r: &mut Run,
        c: &Case,
        sides: &[Side<BView>],
        docs: &[Option<Document>],
        tally: Tally,
    ) {
        // I2: the deviations' wire conditions and C's forced exit before any comparison with C, so that an unmet one
        // makes the comparisons INVALID instead of following a FAIL with behaviour.
        match c {
            Case::Udp(_) => deviations(r, sides, docs, tally.by_rule, tally.collapsed),
            Case::Tcp(t) => tcp_before_vs_c(r, t, sides, docs, tally),
        }
    }
    fn finish(
        r: &mut Run,
        c: &Case,
        sides: &[Side<BView>],
        docs: &[Option<Document>],
        _tally: Tally,
    ) {
        let c = match c {
            Case::Tcp(t) => return tcp_finish(r, t, sides, docs),
            Case::Udp(c) => c,
        };
        let mut counts = serde_json::Map::new();
        for (s, d) in sides.iter().zip(docs) {
            let Some(d) = d else { continue };
            banner_checks(r, c, s, d);
            let mut by_app: BTreeMap<String, usize> = BTreeMap::new();
            for name in d.records.iter().filter_map(Rec::app_name) {
                *by_app.entry(name).or_default() += 1;
            }
            counts.insert(s.spec.name.into(), json!(by_app));
            if let (Some(v), Who::Rmasscan) = (udp_view(s), s.spec.who) {
                let empty: Vec<u16> = v
                    .probes
                    .iter()
                    .filter(|p| udp_payload(&p.frame).is_none_or(<[u8]>::is_empty))
                    .map(|p| p.port)
                    .collect();
                cap(
                    r,
                    s,
                    "every probe carries the port's built-in payload (none is empty)",
                    empty.is_empty() && !v.probes.is_empty(),
                    format!("{} probes, empty on {empty:?}", v.probes.len()),
                );
            }
        }
        r.notes
            .insert("banners_by_app".into(), Value::Object(counts));
        r.notes.insert(
            "scenarios".into(),
            json!(
                SCENARIOS
                    .iter()
                    .map(|x| {
                        let o = ROLES
                            .iter()
                            .find(|(_, r)| *r == x.role)
                            .map_or(0, |(o, _)| *o);
                        json!({"peer": format!("198.18.0.{o}"), "port": x.port, "role": x.role,
                            "about": x.about, "banners": x.apps(c.rawudp)})
                    })
                    .collect::<Vec<_>>()
            ),
        );
    }
}

/// Judge an evidence directory: the manifest, every planned case, and a safety walk of everything else. Symbolic
/// links are never followed.
pub fn verify_dir(root: &Path) -> Value {
    pair_verify::verify_dir::<Banners>(root)
}

/// `banners-verify --dir DIR [--out FILE]`: 0 PASS, 1 FAIL, 2 INVALID or NOT RUN.
pub fn run(args: &[String]) -> Result<i32, String> {
    pair_verify::run::<Banners>(args)
}

#[cfg(test)]
#[path = "banners_verify_tests.rs"]
pub(crate) mod tests;
