//! Offline verifier of the IPv6 acceptance on the sealed Linux netns stand (`ipv6-verify`) and the one case table of
//! its suite (`ipv6-suite linux`): TCP SYN over IPv6 (R3: TCP only), the next hop resolved by an NDP Neighbor
//! Solicitation (R11), a mixed IPv4 + IPv6 scan, and `--router-mac-ipv6`, each against the pinned C masscan `8e6b3b0`.
//!
//! Three cases ([`CASES`]); a case is a list of STEPS ([`steps`]): for every output document of the case one rmasscan
//! run and one run of the C oracle, each with its own peer capture. Both scanners name `--seed 1`, `--rate 100`,
//! `--wait 3` and `--source-port 40000`, so they must put the same probes on the wire in the same order, byte for
//! byte. The oracle's argv is rmasscan's plus two named differences ([`DEVIATIONS`]): `--adapter-ip fd00:198:18::1`
//! (C never picks a ULA source, `rawsock-getip6.c:68-71`) and `--router-mac-ipv6 02-aa-00-00-00-02` (C resolves its
//! IPv6 router by Router Solicitation and Advertisement, `stack_ndpv6_resolve`, and a Linux peer without a daemon
//! sends no RA; rmasscan resolves the route's next hop by NS, R11).
//!
//! The stand (`wire-lab.sh --suite ipv6`) is the autodetect netns stand (scanner `198.18.0.1` on `veth-a`, peers
//! `198.18.0.2`-`.5` on `veth-b`) with IPv6 raised on the lab veth pair only ([`capture::check_ipv6_side`]): scanner
//! `fd00:198:18::1/64`, peers `fd00:198:18::2`-`::5/64`, the EUI-64 link-locals of the stand MACs, the scanner's IPv6
//! default route via the peer's link-local `fe80::aa:ff:fe00:2` (so several on-link targets resolve the interface's
//! default gateway, and rmasscan's NS goes from its global address to the router's link-local), permanent IPv6
//! neighbours on both sides (no kernel ever solicits; rmasscan's resolver never reads the neighbour table, so its NDP
//! still runs), no DAD, no router discovery, no forwarding. The peer answers TCP 80 and 8080 from IPv6 listeners
//! (`capture responder --tcp6-ips`), resets every other port, and answers rmasscan's NS with its NA (kernel).
//!
//! What is judged, per step, under the rules of the protocols verifier (whose machinery is reused): the probes on the
//! wire (rmasscan's equal the product's plan in order, the oracle's equal rmasscan's), the stand's answer to every
//! probe and every NS (a stand that answered otherwise is INVALID, never FAIL), every frame of the scanner MAC (a probe
//! or one of [`SCANNER_CLASSES`] within its bound; kernel noise of [`STAND_NOISE`] makes the step INVALID), the
//! document against its own wire (in reply order up to [`REPLY_REORDER_WINDOW_US`]), rmasscan's stderr and exit, and
//! the two scanners' documents as multisets of records. IPv6 record TTLs are never compared with C's (C reports a
//! stale value for IPv6; rmasscan's is the reply's hop limit, judged against its own wire).
//!
//! Layout of an evidence directory: `manifest.json` (key `ipv6`: `linux`), `teardown.json`, `runs/<tag>/` per case,
//! each with `expect.json` ([`Ipv6Expect`]), `isolation.json` and `isolation-post.json` (`capture isolation --mode
//! ipv6`), `ipv6-stack.json` ([`Ipv6Stack`], read before the case: a tentative address is NOT RUN),
//! `hashes-before-copy.txt`, and one directory per step: `argv.json`, `stdout.txt stderr.txt exit.txt`, the document
//! under its neutral name, `peer.pcap capture.json peer.err` and `responder.json`.
use crate::{
    autodetect_verify::{self as av, Stand},
    capture::{
        self, IPV6_PEER_LL, IPV6_PEERS, IPV6_SCANNER, IPV6_SCANNER_LL, IPV6_SYSCTLS,
        IPV6_UNUSABLE_FLAGS,
    },
    output_verify::{BINARY_BLOCK, canon},
    pair_verify::{
        self, Doc, PairPlan, Record, Side, StepView, Tally, WireSummary, beh, cap, case_of,
        expect_steps, named_deviations, pair_steps, parse_doc_with, plan_probes, scan_tail,
        scanner_counts, scanner_frame_checks, tags_of,
    },
    pcap::Frames,
    protocols_verify::{self as pv, ExpectStep, Out, Shown, St, reason_string},
    scan_control_verify::Who,
    verify::{NOT_RUN, Run, array, read_json, s},
};
use rmasscan_core::{
    blackrock::BlackRock,
    config::{EffectiveConfig, Operation, ScanConfig, parse_rate, validate},
    massip::MassIp,
    packet::LinkType,
    probe::{AdapterBinding, NicBinding, ReadyPlan},
    ranges6::format_ipv6_c,
    targets::parse_ports,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

pub use pv::{EXPECT_JSON, ISOLATION_JSON, ISOLATION_POST_JSON, PEER_FILES, RESPONDER_JSON, stand};

// ------------------------------------------------------------------ the case table

/// IPv6 targets in the one form both scanners take (C refuses an unbracketed address that starts with a letter).
pub const TARGETS_V6: &str = "[fd00:198:18::2]-[fd00:198:18::5]";
pub const TARGETS_V4: &str = "198.18.0.2-198.18.0.5";
pub const TARGETS_MIXED: &str = "198.18.0.2-198.18.0.5,[fd00:198:18::2]-[fd00:198:18::5]";
/// Port 80 open on every peer address, 81 closed (the peer kernel resets it).
pub const PORTS: &str = "80,81";
pub const RATE: &str = "100";
pub const WAIT: &str = "3";
pub const SOURCE_PORT: u16 = 40000;
/// The peer's open TCP ports (the responder's listeners); every other port is reset by its kernel.
pub const TCP_OPEN: [u16; 2] = [80, 8080];
/// The peer's MAC as both scanners take it (`--router-mac-ipv6`).
pub const PEER_MAC_ARG: &str = "02-aa-00-00-00-02";
/// The scanner namespace's IPv4 default gateway: the next hop of the IPv4 part of the mixed scan, resolved by ARP.
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
pub const IPV6_STACK_JSON: &str = "ipv6-stack.json";
/// The most Neighbor Solicitations rmasscan's resolver sends before it gives up: one per `NDP_INTERVAL` while less
/// than `NDP_TIMEOUT` has passed (rmasscan-net `ndp_resolve.rs`: t = 0..9 s, 10 requests).
pub const NEXT_HOP_NS_MAX: usize = (rmasscan_net::ndp_resolve::NDP_TIMEOUT.as_secs()
    / rmasscan_net::ndp_resolve::NDP_INTERVAL.as_secs())
    as usize;

/// The documented differences from C, by name, and the rule each applies.
pub const DEVIATIONS: [(&str, &str); 4] = [
    (
        "ndp-ns-not-rs",
        "R11: rmasscan resolves its IPv6 next hop with a Neighbor Solicitation to the route's next hop (here the interface default gateway, the peer's link-local), C with a Router Solicitation and the Router Advertisement (stack_ndpv6_resolve); a Linux peer without a router daemon sends no RA, so the oracle step is given --router-mac-ipv6 02-aa-00-00-00-02: the condition checked here is the oracle's (its wire holds no NS of the scanner); rmasscan's NS are its own checks (1 to NEXT_HOP_NS_MAX, as many as its ndp: line)",
    ),
    (
        "oracle-source-given",
        "C never takes a ULA (fc00::/7) or 2001:db8::/32 address as its IPv6 source (rawsock-getip6.c:68-71), rmasscan does; the oracle step is given --adapter-ip fd00:198:18::1, the address rmasscan detects; the condition checked here is the oracle's (every IPv6 probe of its wire leaves from it); rmasscan's detected source is its detection check",
    ),
    (
        "ipv6-ttl-not-compared",
        "T3: an IPv6 record's ttl is the reply's hop limit in rmasscan and a stale value in C (C sets ip_ttl for IPv4 only, proto-preprocess.c:127; its -oJ prints that unsigned value whole, out-json.c:51, live 7b r1 320995840, its -oB the low byte); rmasscan's IPv6 ttl is judged against its own wire (a byte), C's IPv6 ttl against nothing (in C's -oJ any 32-bit value), and IPv6 ttls are left out when the two documents are compared",
    ),
    (
        "families-one-interface",
        "R17: C sends IPv6 out of the IPv4 default interface, rmasscan routes each family by its own table and refuses a mixed scan whose families leave by different interfaces; on the stand both families route via veth-a, so the mixed scan is not refused; the condition checked here is the oracle's (both families' probes on the stand's one link); rmasscan's one interface and two source lines are its detection check",
    ),
];

/// What C's `-oJ` may hold for an IPv6 record beyond a byte, named by the well-formedness check of the oracle's
/// documents (7b r1).
pub const IPV6_DOC_RULE: &str = " (an IPv6 record's ttl may be any 32-bit value: C prints the ip_ttl it never sets for IPv6, ipv6-ttl-not-compared)";
/// Why rmasscan's document and the oracle's are compared as multisets of records (protocols R17/R21).
pub const RECORD_ORDER_VS_C: &str = "each scanner prints its records in the order the replies arrive on its own wire (judged per step, up to replies captured at most REPLY_REORDER_WINDOW_US = 50 us apart); the two runs of a document do not get the same reply order from the stand (the peer kernel answers a burst of probes in an order that changes from run to run, protocols r1), so rmasscan's records must equal C's field for field but the time, IPv6 ttl aside (ipv6-ttl-not-compared), in any order";

/// One case: what it scans and which documents it writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaseSpec {
    pub tag: &'static str,
    pub targets: &'static str,
    pub ports: &'static str,
    /// `--show open,closed`: closed records are written too.
    pub show_closed: bool,
    /// `--router-mac-ipv6 02-aa-00-00-00-02` on both steps: rmasscan sends no NS.
    pub router_mac_given: bool,
    pub outs: &'static [Out],
    pub deviations: &'static [&'static str],
}

pub const CASES: [CaseSpec; 3] = [
    CaseSpec {
        tag: "v01_ndp_and_tcp6_syn",
        targets: TARGETS_V6,
        ports: PORTS,
        show_closed: true,
        router_mac_given: false,
        outs: &[Out::Json, Out::Binary],
        deviations: &[
            "ndp-ns-not-rs",
            "oracle-source-given",
            "ipv6-ttl-not-compared",
        ],
    },
    CaseSpec {
        tag: "v02_mixed_v4_v6",
        targets: TARGETS_MIXED,
        ports: PORTS,
        show_closed: true,
        router_mac_given: false,
        outs: &[Out::Binary, Out::List],
        deviations: &[
            "ndp-ns-not-rs",
            "oracle-source-given",
            "ipv6-ttl-not-compared",
            "families-one-interface",
        ],
    },
    CaseSpec {
        tag: "v03_explicit_router_mac_ipv6",
        targets: TARGETS_V6,
        ports: PORTS,
        show_closed: false,
        router_mac_given: true,
        outs: &[Out::Json],
        deviations: &["oracle-source-given", "ipv6-ttl-not-compared"],
    },
];
pub fn case(tag: &str) -> Option<CaseSpec> {
    case_of::<Ipv6>(tag)
}
pub fn planned_tags() -> Vec<&'static str> {
    tags_of::<Ipv6>()
}
impl CaseSpec {
    pub fn has_ipv4(&self) -> bool {
        self.targets.split(',').any(|t| !t.contains(':'))
    }
}

/// One scanner run of a case: the protocols suite's step, so its driver runs both suites' steps.
pub use pv::StepSpec;
/// rmasscan's scan of a case into `out`: targets, `-p`, the output flag and file, `--show open,closed` when the case
/// shows closed ports, `--seed 1 --rate 100 --wait 3 --source-port 40000`, and `--router-mac-ipv6` when given.
pub fn argv(c: &CaseSpec, out: Out) -> Vec<String> {
    let mut a = vec![c.targets.to_owned(), format!("-p{}", c.ports)];
    scan_tail(&mut a, out, c.show_closed, RATE, WAIT, SOURCE_PORT);
    if c.router_mac_given {
        a.extend(["--router-mac-ipv6".to_owned(), PEER_MAC_ARG.to_owned()]);
    }
    a
}
/// What the oracle's argv adds to rmasscan's (`oracle-source-given`, `ndp-ns-not-rs`).
pub fn oracle_extra(c: &CaseSpec) -> Vec<String> {
    let mut a = vec!["--adapter-ip".to_owned(), IPV6_SCANNER.to_owned()];
    if !c.router_mac_given {
        a.extend(["--router-mac-ipv6".to_owned(), PEER_MAC_ARG.to_owned()]);
    }
    a
}
/// The steps of a case, in the order they run; defined here and nowhere else.
pub fn steps(tag: &str) -> Option<Vec<StepSpec>> {
    let c = case(tag)?;
    Some(pair_steps(c.outs, |out, who| {
        let mut a = argv(&c, out);
        if who == Who::Oracle {
            a.extend(oracle_extra(&c));
        }
        a
    }))
}

/// `expect.json`: the case as the suite planned it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ipv6Expect {
    pub tag: String,
    pub targets: String,
    pub ports: String,
    pub router_mac_given: bool,
    pub oracle_extra: Vec<String>,
    pub steps: Vec<ExpectStep>,
}
pub fn expect(tag: &str) -> Option<Ipv6Expect> {
    let c = case(tag)?;
    Some(Ipv6Expect {
        tag: tag.into(),
        targets: c.targets.into(),
        ports: c.ports.into(),
        router_mac_given: c.router_mac_given,
        oracle_extra: oracle_extra(&c),
        steps: expect_steps(&steps(tag)?),
    })
}

/// `manifest.json` as far as this verifier reads it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Manifest {
    pub ipv6: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lab_id: Option<String>,
}

// ------------------------------------------------------------------ the stand (the protocols stand, `pv::stand`, with IPv6)

fn a6(s: &str) -> Ipv6Addr {
    s.parse().unwrap_or(Ipv6Addr::UNSPECIFIED)
}
/// The scanner's IPv6 address (the source rmasscan detects).
pub fn scanner6() -> Ipv6Addr {
    a6(IPV6_SCANNER)
}
/// The peer's link-local address: the scanner namespace's IPv6 default gateway, the target of rmasscan's NS.
pub fn router6() -> Ipv6Addr {
    a6(IPV6_PEER_LL)
}
pub fn peers6() -> Vec<Ipv6Addr> {
    IPV6_PEERS.iter().map(|s| a6(s)).collect()
}
/// The solicited-node multicast address of `ip` and its Ethernet group (RFC 4291 §2.7.1, RFC 2464 §7), computed here
/// (not with the product's codec).
pub fn solicited(ip: Ipv6Addr) -> (Ipv6Addr, [u8; 6]) {
    let o = ip.octets();
    let addr = Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | u16::from(o[13]),
        u16::from_be_bytes([o[14], o[15]]),
    );
    (addr, [0x33, 0x33, 0xff, o[13], o[14], o[15]])
}
/// The responder's options after `capture responder` (its `--ready` aside): the TCP listeners on every peer IPv4
/// address (the wildcard) and on every peer IPv6 address.
pub fn responder_args() -> Vec<String> {
    let list = |p: &[u16]| p.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    vec![
        "--ports".into(),
        list(&TCP_OPEN),
        "--tcp6-ips".into(),
        IPV6_PEERS.join(","),
    ]
}

/// One IPv6 address of a lab veth as `ip -6 -j addr` showed it: every flag that was `true` (`tentative`, `nodad`, ...).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Addr6 {
    pub address: String,
    pub prefixlen: u64,
    pub scope: String,
    pub flags: Vec<String>,
}
/// One side's lab veth on the IPv6 stand: its [`IPV6_SYSCTLS`] as read and its addresses.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SideStack {
    pub iface: String,
    pub sysctls: Vec<(String, String)>,
    pub addresses: Vec<Addr6>,
}
/// `ipv6-stack.json`: the stand's IPv6 as the suite read it right before the case. The responder is not in it: its
/// options are a constant of the suite (a record of them could never differ), and what its listeners do is judged on
/// the wire (every probe to 80 and 8080 of a peer address of either family owes a SYN-ACK, `stand_answers`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ipv6Stack {
    pub scanner: SideStack,
    pub peer: SideStack,
}
/// The addresses of `ip -6 -j addr show dev IF` (one link), each with its `true` flags.
pub fn addresses_of(addrs: &Value) -> Result<Vec<Addr6>, String> {
    let links = addrs.as_array().ok_or("not an address list")?;
    let mut out = Vec::new();
    for l in links {
        for a in array(&l["addr_info"]) {
            let o = a.as_object().ok_or("an address that is no object")?;
            out.push(Addr6 {
                address: s(&a["local"]).to_owned(),
                prefixlen: a["prefixlen"].as_u64().unwrap_or(0),
                scope: s(&a["scope"]).to_owned(),
                flags: o
                    .iter()
                    .filter(|(_, v)| **v == Value::Bool(true))
                    .map(|(k, _)| k.clone())
                    .collect(),
            });
        }
    }
    Ok(out)
}
/// Why the stand's IPv6 was not ready for a case, or `None`: a veth whose settings are not [`IPV6_SYSCTLS`], an
/// address set that is not the stand's, an address that is tentative, failed DAD, optimistic or deprecated (it cannot
/// be bound or answer yet).
pub fn stack_problem(p: &Ipv6Stack) -> Option<String> {
    let want_sysctls: Vec<(String, String)> = IPV6_SYSCTLS
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    for (side, iface, own, ll) in [
        (&p.scanner, "veth-a", vec![scanner6()], IPV6_SCANNER_LL),
        (&p.peer, "veth-b", peers6(), IPV6_PEER_LL),
    ] {
        if side.iface != iface {
            return Some(format!(
                "the IPv6 of {} was read, not of {iface}",
                side.iface
            ));
        }
        if side.sysctls != want_sysctls {
            return Some(format!(
                "{iface} has the IPv6 settings {:?}, not the stand's {want_sysctls:?} (wire-lab.sh --suite ipv6 sets them)",
                side.sysctls
            ));
        }
        for a in &side.addresses {
            if let Some(f) = a
                .flags
                .iter()
                .find(|f| IPV6_UNUSABLE_FLAGS.contains(&f.as_str()))
            {
                return Some(format!(
                    "{} on {iface} is {f}: the stand's address was not usable when the case was to start",
                    a.address
                ));
            }
        }
        let mut got: Vec<(Option<Ipv6Addr>, u64)> = side
            .addresses
            .iter()
            .map(|a| (a.address.parse().ok(), a.prefixlen))
            .collect();
        got.sort();
        let mut want: Vec<(Option<Ipv6Addr>, u64)> = own
            .iter()
            .copied()
            .chain([a6(ll)])
            .map(|ip| (Some(ip), 64))
            .collect();
        want.sort();
        if got != want {
            return Some(format!(
                "{iface} has the IPv6 addresses {:?}, not the stand's",
                side.addresses
                    .iter()
                    .map(|a| format!("{}/{}", a.address, a.prefixlen))
                    .collect::<Vec<_>>()
            ));
        }
    }
    None
}

// ------------------------------------------------------------------ frames

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}
fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
fn v6_at(b: &[u8], i: usize) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o.copy_from_slice(&b[i..i + 16]);
    Ipv6Addr::from(o)
}
/// An IPv4 (without options) or IPv6 packet of an Ethernet frame: its addresses, the upper protocol (after the IPv6
/// Hop-by-Hop, Routing and Destination Options headers), its TTL or hop limit and the upper-layer bytes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Pkt<'a> {
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    pub(crate) proto: u8,
    pub(crate) ttl: u8,
    pub(crate) l4: &'a [u8],
    /// The IPv6 packet carried extension headers before its upper layer.
    pub(crate) ext: bool,
}
pub(crate) fn pkt(f: &[u8]) -> Option<Pkt<'_>> {
    match f.get(12..14)? {
        [8, 0] => {
            if f.len() < 34 || f[14] != 0x45 {
                return None;
            }
            let total = usize::from(be16(f, 16));
            if total < 20 || 14 + total > f.len() {
                return None;
            }
            Some(Pkt {
                src: IpAddr::V4(Ipv4Addr::new(f[26], f[27], f[28], f[29])),
                dst: IpAddr::V4(Ipv4Addr::new(f[30], f[31], f[32], f[33])),
                proto: f[23],
                ttl: f[22],
                l4: &f[34..14 + total],
                ext: false,
            })
        }
        [0x86, 0xdd] => {
            if f.len() < 54 || f[14] >> 4 != 6 {
                return None;
            }
            let end = 54 + usize::from(be16(f, 18));
            if end > f.len() {
                return None;
            }
            let (mut next, mut at) = (f[20], 54);
            while matches!(next, 0 | 43 | 60) {
                let h = f.get(at..at + 2)?;
                let len = (usize::from(h[1]) + 1) * 8;
                if at + len > end {
                    return None;
                }
                next = h[0];
                at += len;
            }
            Some(Pkt {
                src: IpAddr::V6(v6_at(f, 22)),
                dst: IpAddr::V6(v6_at(f, 38)),
                proto: next,
                ttl: f[21],
                l4: &f[at..end],
                ext: at != 54,
            })
        }
        _ => None,
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tcp {
    sp: u16,
    dp: u16,
    seq: u32,
    ack: u32,
    flags: u8,
}
fn tcp(p: &Pkt) -> Option<Tcp> {
    (p.proto == 6 && p.l4.len() >= 20).then(|| Tcp {
        sp: be16(p.l4, 0),
        dp: be16(p.l4, 2),
        seq: be32(p.l4, 4),
        ack: be32(p.l4, 8),
        flags: p.l4[13],
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
/// The ICMPv6 checksum of `p` is right (RFC 8200 §8.1 pseudo-header; computed here, not with the product's sum).
fn icmp6_sum_ok(p: &Pkt) -> bool {
    let (IpAddr::V6(src), IpAddr::V6(dst)) = (p.src, p.dst) else {
        return false;
    };
    let mut pseudo = Vec::with_capacity(40);
    pseudo.extend(src.octets());
    pseudo.extend(dst.octets());
    pseudo.extend((p.l4.len() as u32).to_be_bytes());
    pseudo.extend([0, 0, 0, 58]);
    ones(p.l4, ones(&pseudo, 0)) == 0xffff
}
fn icmp6_type(p: &Pkt) -> Option<u8> {
    (p.proto == 58 && matches!(p.src, IpAddr::V6(_)) && p.l4.len() >= 8).then(|| p.l4[0])
}

/// rmasscan's next-hop Neighbor Solicitation in the resolver's exact form: 86 bytes, to the solicited-node group of
/// the router `fe80::aa:ff:fe00:2` (`ff02::1:ff00:2`, `33:33:ff:00:00:02`), from the scanner's MAC and its global
/// address `fd00:198:18::1`, traffic class and flow label 0, payload 32, no extension header, hop limit 255, ICMPv6
/// 135 code 0 with a right checksum, reserved 0, the router as target and the scanner's MAC as Source Link-Layer
/// Address (RFC 4861 §4.3, §7.2.2).
pub fn is_next_hop_ns(f: &[u8], st: &Stand) -> bool {
    let (group, group_mac) = solicited(router6());
    let Some(p) = pkt(f) else { return false };
    let mut opt = vec![1, 1];
    opt.extend(st.scanner_mac);
    f.len() == 86
        && f[0..6] == group_mac
        && f[6..12] == st.scanner_mac
        && f[14..18] == [0x60, 0, 0, 0]
        && be16(f, 18) == 32
        && !p.ext
        && p.ttl == 255
        && p.src == IpAddr::V6(scanner6())
        && p.dst == IpAddr::V6(group)
        && icmp6_type(&p) == Some(135)
        && p.l4[1] == 0
        && icmp6_sum_ok(&p)
        && p.l4[4..8] == [0; 4]
        && v6_at(p.l4, 8) == router6()
        && p.l4[24..32] == opt[..]
}
/// The peer's Neighbor Advertisement for an NS of the scanner (source `ns_src`, target `target`, an address of the
/// peer) in the stand's form: 86 bytes to the scanner's MAC, from the target to the NS's source, payload 32, no
/// extension header, hop limit 255, ICMPv6 136 code 0 with a right checksum, flags Solicited and Override and no Router
/// flag (the peer forwards nothing), the target as target and the peer's MAC as Target Link-Layer Address (Linux
/// `ndisc_send_na` for a multicast NS). For rmasscan's resolver the target is the router `fe80::aa:ff:fe00:2`.
pub fn is_stand_na(f: &[u8], st: &Stand, ns_src: Ipv6Addr, target: Ipv6Addr) -> bool {
    let Some(p) = pkt(f) else { return false };
    let mut opt = vec![2, 1];
    opt.extend(st.peer_mac);
    f.len() == 86
        && (target == router6() || peers6().contains(&target))
        && f[0..6] == st.scanner_mac
        && f[6..12] == st.peer_mac
        && be16(f, 18) == 32
        && !p.ext
        && p.ttl == 255
        && p.src == IpAddr::V6(target)
        && p.dst == IpAddr::V6(ns_src)
        && icmp6_type(&p) == Some(136)
        && p.l4[1] == 0
        && icmp6_sum_ok(&p)
        && p.l4[4..8] == [0x60, 0, 0, 0]
        && v6_at(p.l4, 8) == target
        && p.l4[24..32] == opt[..]
}

/// The kernel traffic the stand is set up to never send during a step, by key, and why; any frame of one of these
/// makes the step INVALID (bound 0), never FAIL. rmasscan's only IPv6 frames are SYNs, the NS of its resolver (for the
/// router, [`is_next_hop_ns`]) and the NA of its responder, so each of these is a stand that was not quiet. The
/// scanner kernel and rmasscan share the scanner MAC: a frame of these classes from the scanner MAC is INVALID even if
/// rmasscan had sent it (no capture can tell the two apart by MAC), never a PASS and never rmasscan's FAIL.
pub const STAND_NOISE: [(&str, &str); 6] = [
    (
        "mld",
        "an MLD query, report or done (ICMPv6 130, 131, 132, 143) from either MAC: a host reports only when it joins or leaves a group; the stand's groups are joined when it is raised, before wire-lab.sh's settle wait (an unsolicited report is expected to repeat within mldv2_unsolicited_report_interval, 1 s), so none may fall into a step",
    ),
    (
        "router_solicitation",
        "ICMPv6 133 from either MAC: the stand sets accept_ra=0 and router_solicitations=0 on both veth ends",
    ),
    (
        "router_advertisement",
        "ICMPv6 134: no router daemon runs on the stand and both ends have forwarding=0",
    ),
    (
        "dad_ns",
        "a Neighbor Solicitation from :: (Duplicate Address Detection) from either MAC: the stand sets accept_dad=0 and adds its addresses nodad",
    ),
    (
        "peer_ns_for_scanner",
        "a Neighbor Solicitation of the peer for the scanner's address: the peer has fd00:198:18::1 as a permanent neighbour, so it never resolves the scanner",
    ),
    (
        "scanner_ns_for_peer",
        "a Neighbor Solicitation of the scanner MAC for a peer's ULA fd00:198:18::2-5: the scanner namespace kernel resolving a peer before it resets a SYN-ACK; the scanner has the peers as permanent neighbours, which prevents it. It is told apart from rmasscan's resolver NS by its target (a peer ULA, not the router fe80::aa:ff:fe00:2) and its time (after the SYN-ACKs, not before the first probe)",
    ),
];
fn noise(p: &Pkt, from_peer: bool) -> Option<&'static str> {
    let t = icmp6_type(p)?;
    match t {
        130 | 131 | 132 | 143 => Some(STAND_NOISE[0].0),
        133 => Some(STAND_NOISE[1].0),
        134 => Some(STAND_NOISE[2].0),
        135 if p.src == IpAddr::V6(Ipv6Addr::UNSPECIFIED) => Some(STAND_NOISE[3].0),
        135 if p.l4.len() >= 24 => {
            let target = v6_at(p.l4, 8);
            if from_peer {
                (target == scanner6() || target == a6(IPV6_SCANNER_LL)).then_some(STAND_NOISE[4].0)
            } else {
                peers6().contains(&target).then_some(STAND_NOISE[5].0)
            }
        }
        _ => None,
    }
}

/// A probe the scanner put on the wire: a TCP SYN from its MAC and its address of the family.
#[derive(Debug, Clone, PartialEq)]
pub struct Probe {
    pub t: f64,
    pub ip: IpAddr,
    pub port: u16,
    pub sport: u16,
    pub seq: u32,
    pub frame: Vec<u8>,
}
pub fn probe_of(t: f64, f: &[u8], st: &Stand) -> Option<Probe> {
    if f.get(6..12) != Some(&st.scanner_mac[..]) {
        return None;
    }
    let p = pkt(f)?;
    let x = tcp(&p)?;
    let mine = match p.src {
        IpAddr::V4(a) => a == st.scanner_ip,
        IpAddr::V6(a) => a == scanner6(),
    };
    (mine && x.flags == 0x02).then(|| Probe {
        t,
        ip: p.dst,
        port: x.dp,
        sport: x.sp,
        seq: x.seq,
        frame: f.to_vec(),
    })
}

/// The peer's TCP answer (SYN-ACK or RST) to one probe of either family, as a scanner reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub t: f64,
    /// The probe it answers (index into [`WireView::probes`]).
    pub probe: usize,
    pub st: St,
    pub ip: IpAddr,
    pub port: u16,
    pub reason: String,
    /// The TTL (IPv4) or hop limit (IPv6) it arrived with.
    pub ttl: u8,
    pub frame: Vec<u8>,
}
/// A Neighbor Solicitation of the scanner MAC (any form), for matching the peer's answers.
#[derive(Debug, Clone, PartialEq)]
pub struct Ns {
    pub t: f64,
    pub src: Ipv6Addr,
    pub target: Ipv6Addr,
    /// It is rmasscan's resolver NS ([`is_next_hop_ns`]): the stand owes it exactly one NA. Another NS (a FAIL of
    /// its own on rmasscan's step) is owed nothing, so a stand that does not answer it never hides that FAIL.
    pub resolver_form: bool,
}
/// The peer's NA to an NS of the scanner: which NS, whether it has the stand's form, the MAC it gives.
#[derive(Debug, Clone, PartialEq)]
pub struct Na {
    pub ns: usize,
    pub form_ok: bool,
    pub mac: Option<[u8; 6]>,
}

enum Peer {
    Reply(Reply),
    /// The peer's ARP reply for the IPv4 default gateway to the scanner's next-hop resolution.
    NextHop,
    Na(Na),
    Noise(&'static str, Option<(Ipv6Addr, Ipv6Addr)>),
    Unexpected(String),
}
fn answer(t: f64, f: &[u8], st: &Stand, v: &WireView) -> Peer {
    let unexpected = |what: &str| Peer::Unexpected(format!("{what} ({} bytes)", f.len()));
    if f.get(12..14) == Some(&[8, 6][..]) {
        let ok = f.len() >= 42
            && f[14..22] == [0, 1, 8, 0, 6, 4, 0, 2]
            && f[38..42] == st.scanner_ip.octets()
            && f[28..32] == GATEWAY.octets();
        return if ok {
            Peer::NextHop
        } else {
            unexpected("an ARP frame that answers no next-hop request of the scan")
        };
    }
    let Some(p) = pkt(f) else {
        return unexpected("neither IPv4, IPv6 nor ARP");
    };
    if let Some(n) = noise(&p, true) {
        let ns = (icmp6_type(&p) == Some(135) && p.l4.len() >= 24).then(|| {
            let IpAddr::V6(src) = p.src else {
                unreachable!("ICMPv6 is IPv6")
            };
            (src, v6_at(p.l4, 8))
        });
        return Peer::Noise(n, ns);
    }
    let to_scanner = match p.dst {
        IpAddr::V4(a) => a == st.scanner_ip,
        IpAddr::V6(a) => a == scanner6(),
    };
    if !to_scanner {
        return unexpected("a packet to an address other than the scanner's");
    }
    if let Some(x) = tcp(&p) {
        let i = v.probes.iter().position(|q| {
            q.ip == p.src && q.port == x.sp && q.sport == x.dp && x.ack == q.seq.wrapping_add(1)
        });
        let st_ = match (x.flags & 0x12 == 0x12, x.flags & 0x04 != 0) {
            (true, _) => Some(St::Open),
            (false, true) => Some(St::Closed),
            _ => None,
        };
        return match (i, st_) {
            (Some(i), Some(s_)) => Peer::Reply(Reply {
                t,
                probe: i,
                st: s_,
                ip: p.src,
                port: x.sp,
                reason: reason_string(x.flags),
                ttl: p.ttl,
                frame: f.to_vec(),
            }),
            _ => unexpected("TCP that answers no SYN of the scan"),
        };
    }
    if icmp6_type(&p) == Some(136) && p.l4.len() >= 24 {
        let target = v6_at(p.l4, 8);
        let IpAddr::V6(dst) = p.dst else {
            unreachable!("ICMPv6 is IPv6")
        };
        // The earliest NS of its target and source that has no NA yet (a resolver that repeats its NS gets one NA per
        // NS); a second NA to an answered NS counts against the last one.
        let matching = |n: &Ns| n.target == target && n.src == dst;
        let open =
            v.ns.iter()
                .enumerate()
                .position(|(i, n)| matching(n) && !v.na.iter().any(|a| a.ns == i));
        return match open.or_else(|| v.ns.iter().rposition(matching)) {
            Some(i) => Peer::Na(Na {
                ns: i,
                form_ok: is_stand_na(f, st, v.ns[i].src, v.ns[i].target),
                mac: (p.l4.len() >= 32 && p.l4[24..26] == [2, 1])
                    .then(|| p.l4[26..32].try_into().unwrap_or_default()),
            }),
            None => unexpected("an NA that answers no NS of the scanner"),
        };
    }
    unexpected("a frame of no kind the stand answers with")
}

/// One capture of one step, taken apart.
#[derive(Debug, Default)]
pub struct WireView {
    pub probes: Vec<Probe>,
    pub replies: Vec<Reply>,
    /// Every Neighbor Solicitation of the scanner MAC (DAD aside), in order.
    pub ns: Vec<Ns>,
    /// The peer's NAs to them.
    pub na: Vec<Na>,
    /// The peer's NS for the scanner's address (source, target), counted in [`Self::noise`] too.
    pub peer_ns: Vec<(Ipv6Addr, Ipv6Addr)>,
    /// The peer's ARP replies to the next-hop resolution of the IPv4 part.
    pub next_hop_replies: usize,
    /// Frames of the scanner MAC that are no probe and belong to one of [`SCANNER_CLASSES`], by its key.
    pub scanner_named: BTreeMap<&'static str, usize>,
    /// Every other frame of the scanner MAC that is no probe and no [`STAND_NOISE`]: described.
    pub scanner_unexplained: Vec<String>,
    /// [`STAND_NOISE`] frames of either side, by key.
    pub noise: BTreeMap<&'static str, usize>,
    /// Frames of the peer MAC that answer nothing the scan sent.
    pub peer_unexpected: Vec<String>,
    /// Probes, replies and NS/NA outside the witness window (last start marker .. first end marker).
    pub outside_window: usize,
}
impl WireView {
    pub fn probe_frames(&self) -> Vec<Vec<u8>> {
        self.probes.iter().map(|p| p.frame.clone()).collect()
    }
}

impl StepView for WireView {
    fn probe_frames(&self) -> Vec<Vec<u8>> {
        WireView::probe_frames(self)
    }
}
/// The frames of the scanner MAC that are no probe of the scan and that the scanner side sends on the stand.
pub const SCANNER_CLASSES: [(&str, &str); 5] = [
    (
        "next_hop_who_has",
        "the IPv4 next-hop resolution of a scan with IPv4 targets: an ARP who-has 198.18.0.2 from 198.18.0.1, 60 bytes zero-padded (the resolver form of C stack-arpv4.c and rmasscan)",
    ),
    (
        "next_hop_ns",
        "rmasscan's IPv6 next-hop resolution (R11): the Neighbor Solicitation of its resolver for the router fe80::aa:ff:fe00:2 (is_next_hop_ns), only in a case without --router-mac-ipv6",
    ),
    (
        "rst_to_syn_ack",
        "a TCP RST (no other flag) from the scanner's address of the family whose sequence number is the acknowledgment of a SYN-ACK of the stand: the scanner namespace kernel resets a SYN-ACK no socket owns, and C resets each distinct SYN-ACK itself once it passed its dedup (main.c:1067-1068, :1095; tcp_send_RST builds IPv6 too)",
    ),
    (
        "na_to_peer_ns",
        "a Neighbor Advertisement of the scanner's address answering a Neighbor Solicitation of the peer for it: the scanner namespace kernel, and on rmasscan's step its NS responder (T4)",
    ),
    (
        "rst_to_rst",
        "C's own TCP RST (no other flag) from the scanner's address of the family whose sequence number is the acknowledgment of an RST of the stand (a closed port): C resets each distinct reply that passes its cookie check and dedup, the RST as well as the SYN-ACK (main.c:1048-1101, `TCP_IS_SYNACK || TCP_IS_RST`, then tcp_send_RST; live 7b r1), in its template's form (window 1200, the MSS option); only on the oracle's step: rmasscan has no RST path and no kernel answers an RST",
    ),
];
/// How many frames of each [`SCANNER_CLASSES`] entry a step may hold: the resolver's request count when the step
/// resolves that family's next hop ([`pv::NEXT_HOP_WHO_HAS_MAX_RMASSCAN`], [`pv::NEXT_HOP_WHO_HAS_MAX_C`],
/// [`NEXT_HOP_NS_MAX`]; 0 otherwise: a scan without IPv4 targets never ARPs, a step given `--router-mac-ipv6` and C,
/// which is always given it here, never solicit), one kernel reset per SYN-ACK frame plus on the oracle's step one
/// reset of C per distinct SYN-ACK, per peer NS for the scanner one NA of the kernel plus, on rmasscan's step, one
/// of its responder, and on the oracle's step one reset of C per distinct RST of the stand (none on rmasscan's).
/// `(class, count, at most)` in [`SCANNER_CLASSES`] order.
pub fn scanner_bounds(v: &WireView, who: Who, c: &CaseSpec) -> [(&'static str, usize, usize); 5] {
    let syn_acks = v.replies.iter().filter(|r| r.st == St::Open).count();
    let distinct = v
        .replies
        .iter()
        .filter(|r| r.st == St::Open)
        .map(|r| (r.ip, r.port))
        .collect::<BTreeSet<_>>()
        .len();
    let who_has = match (c.has_ipv4(), who) {
        (false, _) => 0,
        (true, Who::Rmasscan) => pv::NEXT_HOP_WHO_HAS_MAX_RMASSCAN,
        (true, Who::Oracle) => pv::NEXT_HOP_WHO_HAS_MAX_C,
    };
    let ns = if who == Who::Rmasscan && !c.router_mac_given {
        NEXT_HOP_NS_MAX
    } else {
        0
    };
    let distinct_rst = v
        .replies
        .iter()
        .filter(|r| r.st == St::Closed)
        .map(|r| (r.ip, r.port))
        .collect::<BTreeSet<_>>()
        .len();
    let (resets, na, c_resets_of_rst) = match who {
        Who::Rmasscan => (syn_acks, 2 * v.peer_ns.len(), 0),
        Who::Oracle => (syn_acks + distinct, v.peer_ns.len(), distinct_rst),
    };
    let max = [who_has, ns, resets, na, c_resets_of_rst];
    let mut out = [("", 0, 0); 5];
    for (i, (k, _)) in SCANNER_CLASSES.iter().enumerate() {
        out[i] = (*k, v.scanner_named.get(k).copied().unwrap_or(0), max[i]);
    }
    out
}

enum Mine {
    Class(&'static str),
    Noise(&'static str),
    Other(String),
}
fn scanner_frame(f: &[u8], st: &Stand, v: &WireView) -> Mine {
    if f.get(12..14) == Some(&[8, 6][..]) {
        return if av::resolver_request(f)
            && f[28..32] == st.scanner_ip.octets()
            && f[38..42] == GATEWAY.octets()
        {
            Mine::Class(SCANNER_CLASSES[0].0)
        } else {
            Mine::Other(describe(f))
        };
    }
    let Some(p) = pkt(f) else {
        return Mine::Other(describe(f));
    };
    if let Some(n) = noise(&p, false) {
        return Mine::Noise(n);
    }
    let own = match p.src {
        IpAddr::V4(a) => a == st.scanner_ip,
        IpAddr::V6(a) => a == scanner6() || a == a6(IPV6_SCANNER_LL),
    };
    if !own {
        return Mine::Other(describe(f));
    }
    if let Some(x) = tcp(&p).filter(|x| x.flags & 0x04 != 0) {
        // the reply of status `st` that this RST answers: its ports reversed, its acknowledgment as the sequence
        let answers = |st: St| {
            x.flags == 0x04
                && v.replies.iter().any(|r| {
                    r.st == st
                        && r.ip == p.dst
                        && pkt(&r.frame)
                            .and_then(|q| tcp(&q))
                            .is_some_and(|y| (y.sp, y.dp, y.ack) == (x.dp, x.sp, x.seq))
                })
        };
        return if answers(St::Open) {
            Mine::Class(SCANNER_CLASSES[2].0)
        } else if answers(St::Closed) {
            Mine::Class(SCANNER_CLASSES[4].0)
        } else {
            Mine::Other(format!(
                "{}, which resets no SYN-ACK and no RST of the stand",
                describe(f)
            ))
        };
    }
    match icmp6_type(&p) {
        Some(135) if is_next_hop_ns(f, st) => Mine::Class(SCANNER_CLASSES[1].0),
        Some(135) => Mine::Other(format!(
            "{}, not the resolver's solicitation for {IPV6_PEER_LL}",
            describe(f)
        )),
        Some(136) if p.l4.len() >= 24 => {
            let target = v6_at(p.l4, 8);
            let answers = p.src == IpAddr::V6(target)
                && v.peer_ns
                    .iter()
                    .any(|(src, t)| *t == target && p.dst == IpAddr::V6(*src));
            if answers {
                Mine::Class(SCANNER_CLASSES[3].0)
            } else {
                Mine::Other(format!("{}, which answers no NS of the peer", describe(f)))
            }
        }
        _ => Mine::Other(describe(f)),
    }
}
/// A frame in a few words, for the detail of a check.
fn describe(f: &[u8]) -> String {
    if f.get(12..14) == Some(&[8, 6][..]) {
        let b = |i: usize| f.get(i).copied().unwrap_or(0);
        return format!(
            "an ARP frame of {} bytes, operation {}, for {}",
            f.len(),
            u16::from_be_bytes([b(20), b(21)]),
            Ipv4Addr::new(b(38), b(39), b(40), b(41))
        );
    }
    let Some(p) = pkt(f) else {
        return format!(
            "a {}-byte frame of ethertype {:02x}{:02x}",
            f.len(),
            f.get(12).copied().unwrap_or(0),
            f.get(13).copied().unwrap_or(0)
        );
    };
    let to = format!("{} > {}", show_ip(p.src), show_ip(p.dst));
    if let Some(x) = tcp(&p) {
        return format!("TCP flags {:#04x} {to}:{}", x.flags, x.dp);
    }
    match (p.proto, icmp6_type(&p)) {
        (58, Some(t)) => format!("ICMPv6 type {t} {to}"),
        (1, _) => format!("ICMP {to}"),
        (n, _) => format!("protocol {n} {to}"),
    }
}
/// An address as C prints it (`ipaddress_fmt`).
pub fn show_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => format_ipv6_c(u128::from(a)),
    }
}

pub fn view(fr: &Frames, st: &Stand) -> WireView {
    let w = av::classify(fr, st.scanner_mac);
    let (start, end) = av::window(&w);
    let inside = |t: f64| (start..=end).contains(&t);
    let mut v = WireView::default();
    let mut mine: Vec<&Vec<u8>> = Vec::new();
    let marker = |f: &[u8]| f.get(12..14) == Some(&crate::link::MARKER_ETHERTYPE[..]);
    for (t, f) in fr {
        if marker(f) {
            continue;
        }
        if let Some(p) = probe_of(*t, f, st) {
            v.outside_window += usize::from(!inside(*t));
            v.probes.push(p);
            continue;
        }
        if f.get(6..12) == Some(&st.scanner_mac[..]) {
            if let Some(p) = pkt(f).filter(|p| icmp6_type(p) == Some(135) && p.l4.len() >= 24)
                && let IpAddr::V6(src) = p.src
                && src != Ipv6Addr::UNSPECIFIED
            {
                v.outside_window += usize::from(!inside(*t));
                v.ns.push(Ns {
                    t: *t,
                    src,
                    target: v6_at(p.l4, 8),
                    resolver_form: is_next_hop_ns(f, st),
                });
            }
            mine.push(f);
            continue;
        }
        if f.get(6..12) == Some(&st.peer_mac[..]) {
            match answer(*t, f, st, &v) {
                Peer::Reply(r) => {
                    v.outside_window += usize::from(!inside(*t));
                    v.replies.push(r);
                }
                Peer::NextHop => v.next_hop_replies += 1,
                Peer::Na(n) => {
                    v.outside_window += usize::from(!inside(*t));
                    v.na.push(n);
                }
                Peer::Noise(n, ns) => {
                    *v.noise.entry(n).or_insert(0) += 1;
                    if n == STAND_NOISE[4].0
                        && let Some(x) = ns
                    {
                        v.peer_ns.push(x);
                    }
                }
                Peer::Unexpected(why) => v.peer_unexpected.push(why),
            }
        }
    }
    for f in mine {
        match scanner_frame(f, st, &v) {
            Mine::Class(k) => *v.scanner_named.entry(k).or_insert(0) += 1,
            Mine::Noise(k) => *v.noise.entry(k).or_insert(0) += 1,
            Mine::Other(what) => v.scanner_unexplained.push(what),
        }
    }
    v
}

/// IPv6 frames of the scanner MAC from an address that is not the scanner's (`fd00:198:18::1`, its link-local, `::`
/// for DAD) or to one off the stand (the peers, the router's link-local, link-scope multicast `ff02::/16`), and TCP to
/// anything but a peer: a safety finding. The IPv4 and ARP frames are judged by [`pv::foreign_probes`].
pub fn foreign_probes6(fr: &Frames, st: &Stand) -> Vec<String> {
    let srcs = [scanner6(), a6(IPV6_SCANNER_LL), Ipv6Addr::UNSPECIFIED];
    let peers = peers6();
    let mut out = Vec::new();
    for (_, f) in fr {
        if f.get(6..12) != Some(&st.scanner_mac[..]) || f.get(12..14) != Some(&[0x86, 0xdd][..]) {
            continue;
        }
        let Some(p) = pkt(f) else {
            out.push(format!(
                "an IPv6 frame that does not parse ({} bytes)",
                f.len()
            ));
            continue;
        };
        let (IpAddr::V6(src), IpAddr::V6(dst)) = (p.src, p.dst) else {
            continue;
        };
        let dst_ok = if p.proto == 6 {
            peers.contains(&dst)
        } else {
            peers.contains(&dst) || dst == router6() || dst.segments()[0] == 0xff02
        };
        if !srcs.contains(&src) || !dst_ok {
            out.push(format!(
                "IPv6 {} > {} next header {}",
                show_ip(p.src),
                show_ip(p.dst),
                p.proto
            ));
        }
    }
    out
}

// ------------------------------------------------------------------ the plan

/// The stand's binding as the product's plan takes it: `veth-a`, its MAC, `198.18.0.1` and `fd00:198:18::1`, the
/// peer's MAC as the next hop of both families, source port 40000.
pub fn nic_binding() -> NicBinding {
    let st = stand();
    let mut nic = NicBinding::from(AdapterBinding {
        interface_id: st.iface.into(),
        link_type: LinkType::Ethernet,
        source_ipv4: u32::from(st.scanner_ip),
        source_mac: st.scanner_mac,
        next_hop_mac: st.peer_mac,
        source_ports: (SOURCE_PORT, SOURCE_PORT),
    });
    nic.source_ipv6 = Some(u128::from(scanner6()));
    nic.next_hop_mac_ipv6 = Some(st.peer_mac);
    nic
}
/// The scan of `targets` and `ports` with the case table's seed, rate and wait, validated.
pub fn effective(targets: &str, ports: &str) -> Result<EffectiveConfig, String> {
    let st = stand();
    let mut ips = MassIp::new();
    ips.add_target_string(targets).map_err(|e| e.to_string())?;
    parse_ports(ips.ports_mut(), ports).map_err(|e| e.to_string())?;
    let cfg = ScanConfig {
        targets: ips,
        seed: 1,
        max_rate: parse_rate(RATE).map_err(|e| e.to_string())?,
        wait_secs: 3,
        adapter_ip: Some(u32::from(st.scanner_ip)),
        adapter_mac: Some(st.scanner_mac),
        router_mac: Some(st.peer_mac),
        source_port: Some((SOURCE_PORT, SOURCE_PORT)),
        adapter_name: Some(st.iface.into()),
        ..ScanConfig::default()
    };
    validate(&cfg, Operation::Scan).map_err(|e| e.to_string())
}
/// The probes of `targets` and `ports` in send order, from the product's own plan (`ReadyPlan::new_cli` and its
/// cursor) on [`nic_binding`].
pub fn plan_frames(targets: &str, ports: &str) -> Result<Vec<Vec<u8>>, String> {
    let eff = effective(targets, ports)?;
    let plan = ReadyPlan::new_cli(eff, vec![nic_binding()]).map_err(|e| e.to_string())?;
    match plan_probes(&plan)? {
        (frames, None) => Ok(frames),
        (_, Some(e)) => Err(e),
    }
}
pub fn plan_stream(c: &CaseSpec) -> Result<Vec<Vec<u8>>, String> {
    plan_frames(c.targets, c.ports)
}
/// The v4-order invariant on the wire, bytes: every IPv4 probe of the mixed scan is, byte for byte, the probe the
/// IPv4-only plan (the same scan without its IPv6 targets) sends to the same address and port, and the IPv4-only plan
/// sends no probe the mixed scan lacks. `Ok`: the number of IPv4 probes.
pub fn v4_bytes_invariant(probes: &[Probe]) -> Result<usize, String> {
    let only4 = plan_frames(TARGETS_V4, PORTS)?;
    let key = |f: &[u8]| {
        pkt(f)
            .and_then(|p| tcp(&p).map(|x| (p.dst, x.dp)))
            .unwrap_or((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    };
    let mut want: BTreeMap<(IpAddr, u16), Vec<u8>> =
        only4.iter().map(|f| (key(f), f.clone())).collect();
    let v4: Vec<&Probe> = probes.iter().filter(|p| p.ip.is_ipv4()).collect();
    for p in &v4 {
        match want.remove(&(p.ip, p.port)) {
            Some(f) if f == p.frame => {}
            Some(_) => {
                return Err(format!(
                    "the probe to {}:{} differs from the IPv4-only plan's",
                    p.ip, p.port
                ));
            }
            None => {
                return Err(format!(
                    "the probe to {}:{} is no probe of the IPv4-only plan, or a repeat",
                    p.ip, p.port
                ));
            }
        }
    }
    if !want.is_empty() {
        return Err(format!(
            "{} probes of the IPv4-only plan are missing: {:?}",
            want.len(),
            want.keys().take(3).collect::<Vec<_>>()
        ));
    }
    Ok(v4.len())
}
/// IPv6 in the low indices (C main.c:258-260, 325-372): with BlackRock over the whole mixed range (the plan's seed and
/// rounds), position `i` of the wire is an IPv6 probe exactly when `x = shuffle((i + rate) mod range) < range_ipv6`
/// (`--retries 0`: the index C shuffles is `i + r * rate` with `r = retries + 1`, brought below `range`, main.c:325-331),
/// and the IPv4 probe at `i` goes to the IPv4-only plan's target of index `x - range_ipv6` (`MassIp::pick` of the scan
/// without its IPv6 targets): the IPv4 index map is the IPv4-only plan's, shifted. `Ok`: (IPv6 probes, IPv4 probes).
pub fn v6_low_indices(probes: &[Probe]) -> Result<(usize, usize), String> {
    let mixed = effective(TARGETS_MIXED, PORTS)?;
    let only4 = effective(TARGETS_V4, PORTS)?;
    if probes.len() as u64 != mixed.range() {
        return Err(format!(
            "{} probes on the wire, the mixed range is {}",
            probes.len(),
            mixed.range()
        ));
    }
    let br = BlackRock::try_new(mixed.range(), mixed.seed(), mixed.blackrock_rounds())
        .map_err(|e| e.to_string())?;
    let r6 = mixed.massip().range_ipv6();
    let (range, rate) = (mixed.range(), mixed.max_rate() as u64);
    let (mut n6, mut n4) = (0, 0);
    for (i, p) in probes.iter().enumerate() {
        let mut pre = i as u64 + rate;
        if rate > range {
            pre %= range;
        } else {
            while pre >= range {
                pre -= range;
            }
        }
        let x = br.shuffle(pre);
        if x < r6 {
            if !p.ip.is_ipv6() {
                return Err(format!(
                    "position {i}: shuffled index {x} < range_ipv6 {r6}, but the probe goes to {}",
                    p.ip
                ));
            }
            n6 += 1;
        } else {
            let (ip, port) = only4.massip().pick(x - r6);
            let want = (IpAddr::V4(Ipv4Addr::from(ip)), port as u16);
            if (p.ip, p.port) != want {
                return Err(format!(
                    "position {i}: shuffled index {x}, IPv4-only index {}, wants {}:{}, the probe goes to {}:{}",
                    x - r6,
                    want.0,
                    want.1,
                    show_ip(p.ip),
                    p.port
                ));
            }
            n4 += 1;
        }
    }
    Ok((n6, n4))
}

// ------------------------------------------------------------------ the documents

/// One record of a document, as far as its format carries it (TCP only: R3).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rec {
    pub st: St,
    pub ip: IpAddr,
    pub port: u16,
    pub reason: Option<String>,
    /// A byte, but in C's `-oJ` an IPv6 record's ttl is any 32-bit value (`ipv6-ttl-not-compared`).
    pub ttl: Option<u32>,
    pub ts: Option<u64>,
}
impl Rec {
    /// Time aside.
    pub fn bare(&self) -> Rec {
        Rec {
            ts: None,
            ..self.clone()
        }
    }
    /// Time aside and, for an IPv6 record, the ttl (`ipv6-ttl-not-compared`): what C's record can be held to.
    pub fn masked(&self) -> Rec {
        Rec {
            ts: None,
            ttl: if self.ip.is_ipv6() { None } else { self.ttl },
            ..self.clone()
        }
    }
    /// The record of a wire reply in the fields `out` carries; C's IPv6 ttl is not known (masked).
    fn of(r: &Reply, out: Out, who: Who) -> Rec {
        let ttl = (out != Out::List && !(who == Who::Oracle && r.ip.is_ipv6()))
            .then_some(u32::from(r.ttl));
        Rec {
            st: r.st,
            ip: r.ip,
            port: r.port,
            reason: (out != Out::List).then(|| r.reason.clone()),
            ttl,
            ts: None,
        }
    }
}
impl Shown for Rec {
    fn show(&self) -> String {
        let mut s = format!("{} {} {}/tcp", self.st.name(), show_ip(self.ip), self.port);
        if let Some(r) = &self.reason {
            s.push_str(&format!(" reason {r}"));
        }
        if let Some(t) = self.ttl {
            s.push_str(&format!(" ttl {t}"));
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
fn ip_text(s: &str) -> Option<IpAddr> {
    if s.contains(':') {
        let a: Ipv6Addr = s.parse().ok()?;
        (format_ipv6_c(u128::from(a)) == s).then_some(IpAddr::V6(a))
    } else {
        canon::<Ipv4Addr>(s).map(IpAddr::V4)
    }
}
fn status(s: &str) -> Result<St, String> {
    [St::Open, St::Closed]
        .into_iter()
        .find(|x| x.name() == s)
        .ok_or(format!("status {s:?}"))
}
/// A record of a text form; `c_ipv6_ttl`: an IPv6 record's ttl may be any 32-bit value (C's `-oJ` prints the
/// `unsigned` ip_ttl it never sets for IPv6, `ipv6-ttl-not-compared`), otherwise every ttl is a byte.
#[allow(clippy::too_many_arguments)]
fn field_rec_with(
    st: &str,
    proto: &str,
    ip: &str,
    port: &str,
    ts: &str,
    reason: Option<&str>,
    ttl: Option<&str>,
    c_ipv6_ttl: bool,
) -> Result<Rec, String> {
    if proto != "tcp" {
        return Err(format!("protocol {proto:?} (R3: TCP only)"));
    }
    let ip = ip_text(ip).ok_or(format!("address {ip:?}"))?;
    let wide = c_ipv6_ttl && ip.is_ipv6();
    Ok(Rec {
        st: status(st)?,
        ip,
        port: canon(port).ok_or(format!("port {port:?}"))?,
        reason: reason.map(str::to_owned),
        ttl: ttl
            .map(|t| {
                if wide {
                    canon::<u32>(t)
                } else {
                    canon::<u8>(t).map(u32::from)
                }
                .ok_or(format!("ttl {t:?}"))
            })
            .transpose()?,
        ts: Some(canon(ts).ok_or(format!("time {ts:?}"))?),
    })
}
/// A record of rmasscan's text forms: every ttl a byte.
#[allow(clippy::too_many_arguments)]
fn field_rec(
    st: &str,
    proto: &str,
    ip: &str,
    port: &str,
    ts: &str,
    reason: Option<&str>,
    ttl: Option<&str>,
) -> Result<Rec, String> {
    field_rec_with(st, proto, ip, port, ts, reason, ttl, false)
}
/// A record of C's text forms: an IPv6 ttl any 32-bit value (live 7b r1: 320995840 in C's `-oJ`).
#[allow(clippy::too_many_arguments)]
fn field_rec_c(
    st: &str,
    proto: &str,
    ip: &str,
    port: &str,
    ts: &str,
    reason: Option<&str>,
    ttl: Option<&str>,
) -> Result<Rec, String> {
    field_rec_with(st, proto, ip, port, ts, reason, ttl, true)
}
/// The status records of a `-oB` file after its header: IPv4 (types 6 and 7, length 13: time, address, protocol,
/// port, reason, ttl) and IPv6 (types 10 and 11, length 26: time, protocol, port, reason, ttl, version 6, address;
/// out-binary.c:103-142), then the footer or the end of a file cut by a forced exit.
fn binary_records(rest: &[u8]) -> Result<(Vec<Rec>, bool), String> {
    let mut foot = [0u8; BINARY_BLOCK];
    foot[..11].copy_from_slice(b"masscan/1.1");
    let (mut at, mut recs) = (0, Vec::new());
    loop {
        let left = &rest[at..];
        if left.is_empty() {
            return Ok((recs, false));
        }
        if left == foot {
            return Ok((recs, true));
        }
        let (ty, len) = (left[0], left.get(1).copied().unwrap_or(0));
        let st = match ty {
            6 | 10 => St::Open,
            7 | 11 => St::Closed,
            _ => {
                return Err(format!(
                    "a record of type {ty} at byte {}",
                    BINARY_BLOCK + at
                ));
            }
        };
        let r = match (ty, len, left.len()) {
            (6 | 7, 13, 15..) => {
                if left[10] != 6 {
                    return Err(format!("protocol {} (R3: TCP only)", left[10]));
                }
                Rec {
                    st,
                    ip: IpAddr::V4(Ipv4Addr::new(left[6], left[7], left[8], left[9])),
                    port: be16(left, 11),
                    reason: Some(reason_string(left[13])),
                    ttl: Some(u32::from(left[14])),
                    ts: Some(u64::from(be32(left, 2))),
                }
            }
            (10 | 11, 26, 28..) => {
                if left[6] != 6 || left[11] != 6 {
                    return Err(format!(
                        "protocol {} version {} (R3: TCP over IPv6 only)",
                        left[6], left[11]
                    ));
                }
                Rec {
                    st,
                    ip: IpAddr::V6(v6_at(left, 12)),
                    port: be16(left, 7),
                    reason: Some(reason_string(left[9])),
                    ttl: Some(u32::from(left[10])),
                    ts: Some(u64::from(be32(left, 2))),
                }
            }
            _ => {
                return Err(format!(
                    "a record of type {ty} and length {len} at byte {} with {} bytes left",
                    BINARY_BLOCK + at,
                    left.len()
                ));
            }
        };
        recs.push(r);
        at += 2 + usize::from(len);
    }
}
/// A document of `out` in its C form (`out-text.c`, `out-json.c` through [`parse_doc_with`], `out-binary.c` types 6,
/// 7, 10, 11): an empty file is a document without a record; a file that stops after a record, without its footer,
/// is not `complete`; any other malformation is an error.
pub fn parse_doc(out: Out, b: &[u8]) -> Result<Document, String> {
    parse_doc_of(out, b, Who::Rmasscan)
}
/// [`parse_doc`] for a document of `who`: C's (the oracle's) text records may carry an IPv6 ttl of any 32-bit value
/// (`ipv6-ttl-not-compared`, [`IPV6_DOC_RULE`]); rmasscan's ttl is a byte.
pub fn parse_doc_of(out: Out, b: &[u8], who: Who) -> Result<Document, String> {
    let field = match who {
        Who::Rmasscan => field_rec,
        Who::Oracle => field_rec_c,
    };
    parse_doc_with(out, b, field, |b, d| {
        if out == Out::Stdout {
            return Err("no case of this suite writes the interactive form".into());
        }
        if b.len() < BINARY_BLOCK || !b.starts_with(b"masscan/1.1\ns:") {
            return Err("not the 99-byte `masscan/1.1` header".into());
        }
        (d.records, d.complete) = binary_records(&b[BINARY_BLOCK..])?;
        Ok(())
    })
}

/// The records a scanner reports for the replies of its wire, in reply order, each with its reply's capture time:
/// once per (address, port, status) for rmasscan, once per (address, port) for C (its TCP dedup, main.c:1067);
/// closed records only with `show_closed`.
pub fn wire_records_at(v: &WireView, who: Who, out: Out, show_closed: bool) -> Vec<(Rec, f64)> {
    let mut seen = BTreeSet::new();
    let mut recs = Vec::new();
    for r in &v.replies {
        let key = match who {
            Who::Rmasscan => (r.ip, r.port, Some(r.st)),
            Who::Oracle => (r.ip, r.port, None),
        };
        if !seen.insert(key) || (r.st == St::Closed && !show_closed) {
            continue;
        }
        recs.push((Rec::of(r, out, who), r.t));
    }
    recs
}
pub fn wire_records(v: &WireView, who: Who, out: Out, show_closed: bool) -> Vec<Rec> {
    wire_records_at(v, who, out, show_closed)
        .into_iter()
        .map(|(r, _)| r)
        .collect()
}

// ------------------------------------------------------------------ checks

fn first(v: &[String]) -> String {
    v.iter().take(4).cloned().collect::<Vec<_>>().join("; ")
}

/// The stand owes every probe its answer (TCP 80 and 8080 open, the rest reset), every NS of the scanner exactly one
/// NA of its form, and no other frame and no kernel noise; anything else is a stand that did not behave (INVALID for
/// both scanners).
fn stand_answers(r: &mut Run, s: &Side<WireView>, v: &WireView) {
    let mut problems = Vec::new();
    for (i, p) in v.probes.iter().enumerate() {
        let answers: Vec<&Reply> = v.replies.iter().filter(|x| x.probe == i).collect();
        let want = if TCP_OPEN.contains(&p.port) {
            St::Open
        } else {
            St::Closed
        };
        // The peer kernel may repeat a SYN-ACK (the same reply again, one status).
        if answers.is_empty() || answers.iter().any(|a| a.st != want) {
            problems.push(format!(
                "{}:{}: {} answers ({:?}), want {}",
                show_ip(p.ip),
                p.port,
                answers.len(),
                answers.iter().map(|a| a.st.name()).collect::<Vec<_>>(),
                want.name()
            ));
        }
    }
    for (i, n) in v.ns.iter().enumerate() {
        let nas: Vec<&Na> = v.na.iter().filter(|a| a.ns == i).collect();
        // The resolver's NS is owed exactly one NA; any other NS of the scanner at most one, of the stand's form.
        let owed = if n.resolver_form { 1..=1 } else { 0..=1 };
        if !owed.contains(&nas.len()) || nas.iter().any(|a| !a.form_ok) {
            problems.push(format!(
                "the NS for {} from {}: {} NA, {} of the stand's form",
                format_ipv6_c(u128::from(n.target)),
                format_ipv6_c(u128::from(n.src)),
                nas.len(),
                nas.iter().filter(|a| a.form_ok).count()
            ));
        }
    }
    r.inv(
        &format!(
            "{}: the stand answered every probe the stand's way (TCP 80 and 8080 open, the rest closed) and every NS of the scanner with exactly one NA of its form (from fe80::aa:ff:fe00:2, Solicited and Override, no Router flag, its MAC as target link-layer address)",
            s.spec.name
        ),
        problems.is_empty(),
        first(&problems),
    );
    r.inv(
        &format!(
            "{}: nothing on the peer side answers anything the scan did not send",
            s.spec.name
        ),
        v.peer_unexpected.is_empty(),
        first(&v.peer_unexpected),
    );
    r.inv(
        &format!(
            "{}: no kernel noise of either side in the step (STAND_NOISE: MLD, RS, RA, DAD NS, a peer NS for the scanner, a scanner NS for a peer; bound 0 each)",
            s.spec.name
        ),
        v.noise.is_empty(),
        format!("{:?}", v.noise),
    );
    r.inv(
        &format!(
            "{}: every probe, reply, NS and NA lies inside the witness window",
            s.spec.name
        ),
        v.outside_window == 0,
        v.outside_window,
    );
}

/// Every frame of the scanner MAC is a probe or of a named class within its bound.
fn scanner_frames(r: &mut Run, s: &Side<WireView>, v: &WireView, c: &CaseSpec) {
    scanner_frame_checks(
        r,
        s,
        "every frame of the scanner MAC is a probe of the scan or of a named class (next-hop who-has, next-hop NS, RST to a SYN-ACK, C's RST to an RST of the stand, NA to a peer NS)",
        &v.scanner_unexplained,
        "the named scanner-side frames stay within their bounds (who-has and NS: the resolver's request count when the step resolves that next hop, else 0; RST: one per SYN-ACK frame, on the oracle's step plus one per distinct SYN-ACK; C's RST to an RST: one per distinct RST of the stand on the oracle's step, none on rmasscan's; NA: per peer NS one of the kernel, plus one of rmasscan's responder)",
        &scanner_bounds(v, s.spec.who, c),
    );
}

/// The `[+]` lines a rmasscan step must print, in order; the resolved MACs by their prefix.
fn want_plus(c: &CaseSpec) -> Vec<(&'static str, String)> {
    let v6_first = format!("[{}]", format_ipv6_c(u128::from(peers6()[0])));
    let src6 = format!("[{IPV6_SCANNER}] (detected)");
    let mut w = vec![
        (
            "interface",
            if c.has_ipv4() {
                "veth-a (detected: route to 198.18.0.2)".to_owned()
            } else {
                format!("veth-a (detected: route to {v6_first})")
            },
        ),
        ("source-mac", "02-aa-00-00-00-01 (detected)".to_owned()),
    ];
    if c.has_ipv4() {
        w.push(("source-ip", "198.18.0.1 (detected)".to_owned()));
        w.push((
            "router-ip",
            "198.18.0.2 (interface default gateway)".to_owned(),
        ));
    }
    w.push(("source-ip", src6));
    if c.router_mac_given {
        w.push(("router-mac-ipv6", format!("{PEER_MAC_ARG} (given)")));
    } else {
        w.push((
            "router-ip",
            format!("[{IPV6_PEER_LL}] (interface default gateway)"),
        ));
        if c.has_ipv4() {
            w.push(("router-mac", format!("{PEER_MAC_ARG} (arp: ")));
        }
        w.push(("router-mac-ipv6", format!("{PEER_MAC_ARG} (ndp: ")));
    }
    w.push(("seed", "1 (given)".to_owned()));
    w.push(("source-port", "40000 (given)".to_owned()));
    w
}
/// `N` of a `MAC (arp: N requests, T ms)` or `MAC (ndp: N requests, T ms)` value.
pub fn requests_of(v: &str) -> Option<u64> {
    let rest = v.split_once(": ")?.1;
    rest.split(' ').next()?.parse().ok()
}
fn detection(r: &mut Run, s: &Side<WireView>, c: &CaseSpec) {
    let want = want_plus(c);
    let ok = s.se.plus.len() == want.len()
        && s.se.plus.iter().zip(&want).all(|((k, v), (wk, wv))| {
            k == wk
                && if wv.ends_with(": ") {
                    v.starts_with(wv.as_str()) && v.ends_with(" ms)") && requests_of(v).is_some()
                } else {
                    v == wv
                }
        });
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
}
fn plus_value<'a>(s: &'a Side<WireView>, key: &str) -> Option<&'a str> {
    s.se.plus
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// A rmasscan step: the shared checks (exit, stdout, stderr grammar, `[+] finished` against the wire, record times)
/// with this suite's `[+]` lines, then what the case proves.
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
    if let Some(v) = &s.view {
        case_checks(r, c, s, v);
    }
}

/// What a case proves beyond the common checks, on rmasscan's steps.
fn case_checks(r: &mut Run, c: &CaseSpec, s: &Side<WireView>, v: &WireView) {
    let st = stand();
    let v6_dst_ok = v
        .probes
        .iter()
        .filter(|p| p.ip.is_ipv6())
        .all(|p| p.frame[0..6] == st.peer_mac);
    if c.router_mac_given {
        cap(
            r,
            s,
            "--router-mac-ipv6 bypasses NDP: no Neighbor Solicitation of the scanner on the wire and every IPv6 probe goes to the given 02:aa:00:00:00:02",
            v.ns.is_empty() && v6_dst_ok && v.probes.iter().any(|p| p.ip.is_ipv6()),
            format!("{} NS on the wire", v.ns.len()),
        );
    } else {
        let printed = plus_value(s, "router-mac-ipv6").and_then(requests_of);
        let first_probe = v.probes.first().map_or(f64::INFINITY, |p| p.t);
        let resolver = v
            .scanner_named
            .get(SCANNER_CLASSES[1].0)
            .copied()
            .unwrap_or(0);
        let ok = (1..=NEXT_HOP_NS_MAX).contains(&v.ns.len())
            && resolver == v.ns.len()
            && printed == Some(v.ns.len() as u64)
            && v.ns.iter().all(|n| n.t < first_probe);
        cap(
            r,
            s,
            "rmasscan resolved its IPv6 next hop by NDP before its first probe: 1 to NEXT_HOP_NS_MAX Neighbor Solicitations, each in the resolver's form (from fd00:198:18::1 to ff02::1:ff00:2 for fe80::aa:ff:fe00:2), as many as its [+] router-mac-ipv6 line says it sent",
            ok,
            format!(
                "{} NS on the wire ({resolver} in the resolver's form), printed {printed:?}",
                v.ns.len()
            ),
        );
        let given =
            v.na.iter()
                .filter(|n| n.form_ok)
                .filter_map(|n| n.mac)
                .collect::<BTreeSet<_>>();
        cap(
            r,
            s,
            "every IPv6 probe goes to the MAC the stand's NA gave (02:aa:00:00:00:02)",
            given == BTreeSet::from([st.peer_mac]) && v6_dst_ok,
            format!(
                "NA gave {:?}",
                given
                    .iter()
                    .map(|m| crate::autodetect_suite::colon(*m))
                    .collect::<Vec<_>>()
            ),
        );
    }
    if c.has_ipv4() {
        let printed = plus_value(s, "router-mac").and_then(requests_of);
        let who_has = v
            .scanner_named
            .get(SCANNER_CLASSES[0].0)
            .copied()
            .unwrap_or(0);
        cap(
            r,
            s,
            "rmasscan resolved its IPv4 next hop by ARP: as many who-has 198.18.0.2 on the wire as its [+] router-mac line says",
            who_has >= 1 && printed == Some(who_has as u64),
            format!("{who_has} who-has on the wire, printed {printed:?}"),
        );
        let bytes = v4_bytes_invariant(&v.probes);
        cap(
            r,
            s,
            "v4-order invariant, bytes: every IPv4 probe of the mixed scan is the IPv4-only plan's probe of its address and port, byte for byte, and none of that plan is missing",
            bytes.is_ok(),
            bytes.map_or_else(|e| e, |n| format!("{n} IPv4 probes")),
        );
        let low = v6_low_indices(&v.probes);
        cap(
            r,
            s,
            "v4-order invariant, order: IPv6 takes the low shuffled indices (shuffle(i) < range_ipv6, main.c:258-260) and the IPv4 probe at i is the IPv4-only plan's target of shuffle(i) - range_ipv6",
            low.is_ok(),
            low.map_or_else(|e| e, |(a, b)| format!("{a} IPv6 and {b} IPv4 probes")),
        );
    }
}

/// Each named deviation of the case: the wire condition that keeps it from changing the comparison, and the notes.
fn deviations(r: &mut Run, c: &CaseSpec, sides: &[Side<WireView>], docs: &[Option<Document>]) {
    named_deviations(r, c.deviations, &DEVIATIONS, |name| {
        let views = |who: Who| {
            sides
                .iter()
                .filter(move |s| s.spec.who == who)
                .filter_map(|s| s.view.as_ref())
        };
        match name {
            // Each condition here is the ORACLE's (a broken oracle is a broken stand: INVALID). rmasscan's side of the
            // same rule is its own FAIL elsewhere: its NS count against the `ndp:` line and the plan (case_checks),
            // its detected source and interface lines (detection), its probes' source (the plan).
            "ndp-ns-not-rs" => {
                let oracle_ns: usize = views(Who::Oracle).map(|v| v.ns.len()).sum();
                let rm: Vec<usize> = views(Who::Rmasscan).map(|v| v.ns.len()).collect();
                (
                    oracle_ns == 0,
                    format!("NS of the scanner: oracle steps {oracle_ns}, rmasscan steps {rm:?}"),
                )
            }
            "oracle-source-given" => {
                let off = views(Who::Oracle)
                    .flat_map(|v| &v.probes)
                    .filter(|p| p.ip.is_ipv6())
                    .filter(|p| pkt(&p.frame).map(|q| q.src) != Some(IpAddr::V6(scanner6())))
                    .count();
                (
                    off == 0,
                    format!(
                        "{off} IPv6 probes of the oracle from another source than {IPV6_SCANNER}"
                    ),
                )
            }
            "ipv6-ttl-not-compared" => {
                let mut stale = 0;
                let mut total = 0;
                for (s, d) in sides.iter().zip(docs) {
                    let (Who::Oracle, Some(v), Some(d)) = (s.spec.who, &s.view, d) else {
                        continue;
                    };
                    for x in d
                        .records
                        .iter()
                        .filter(|x| x.ip.is_ipv6() && x.ttl.is_some())
                    {
                        total += 1;
                        let hop = v
                            .replies
                            .iter()
                            .find(|y| y.ip == x.ip && y.port == x.port)
                            .map(|y| u32::from(y.ttl));
                        stale += usize::from(hop != x.ttl);
                    }
                }
                (
                    true,
                    format!(
                        "{total} IPv6 records of C with a ttl, {stale} of them not the reply's hop limit"
                    ),
                )
            }
            "families-one-interface" => {
                // C sends both families out of its IPv4 default interface, the stand's one link: both are on the
                // oracle's wire. rmasscan's one interface and two source lines are its detection check.
                let both: Vec<(usize, usize)> = views(Who::Oracle)
                    .map(|v| {
                        let six = v.probes.iter().filter(|p| p.ip.is_ipv6()).count();
                        (v.probes.len() - six, six)
                    })
                    .collect();
                (
                    both.iter().all(|(a, b)| *a > 0 && *b > 0),
                    format!("oracle steps (IPv4, IPv6) probes on the stand's one link: {both:?}"),
                )
            }
            _ => (false, "unknown deviation".into()),
        }
    });
}

// ------------------------------------------------------------------ privacy and evidence

/// The case record whose addresses must be the stand's, beside the steps' files (`pair_verify::STEP_TEXT`).
const SCANNER_TEXT: [&str; 1] = [IPV6_STACK_JSON];
/// The IPv6 address C's own hint text names (`main-initadapter.c`: `--source-ip 2001:3b8::1234`).
const C_HINT_IPV6: &str = "2001:3b8::1234";
/// Candidate IPv6 addresses in a text: runs of hex digits, `:` and `.` with at least two colons, delimited by anything
/// that is no letter, digit, `:` or `.` (so `capture::dump` is no address), that parse as IPv6.
pub fn ipv6_tokens(text: &str) -> Vec<Ipv6Addr> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == ':' || c == '.'))
        .filter(|run| run.matches(':').count() >= 2)
        .filter_map(|run| {
            let run = run.trim_end_matches('.');
            run.chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
                .then(|| run.parse().ok())
                .flatten()
        })
        .collect()
}
/// An IPv6 address evidence may name: the stand's (`fd00:198:18::/64`, its two link-locals, the solicited-node groups
/// of its addresses) and C's hint; outside a scanner's own text also `::`, `::1`, the `fe80::` network, link-scope
/// multicast and the documentation prefix `2001:db8::/32`.
pub fn ipv6_allowed(ip: Ipv6Addr, scanner_text: bool) -> bool {
    let s = ip.segments();
    let stand = s[..4] == [0xfd00, 0x198, 0x18, 0]
        || ip == a6(IPV6_SCANNER_LL)
        || ip == router6()
        || (s[..6] == [0xff02, 0, 0, 0, 0, 1] && s[6] >> 8 == 0xff)
        || ip == a6(C_HINT_IPV6);
    stand
        || (!scanner_text
            && (ip == Ipv6Addr::UNSPECIFIED
                || ip == Ipv6Addr::LOCALHOST
                || ip == a6("fe80::")
                || s[0] == 0xff02
                || s[..2] == [0x2001, 0x0db8]))
}
fn binary_problems(b: &[u8]) -> Vec<String> {
    let st = stand();
    let peers = peers6();
    match parse_doc(Out::Binary, b) {
        Err(e) => vec![format!(
            "not a masscan -oB file ({e}); its bytes are not scanned as text"
        )],
        Ok(d) => d
            .records
            .iter()
            .filter(|x| match x.ip {
                IpAddr::V4(a) => !st.peer_ips.contains(&a),
                IpAddr::V6(a) => !peers.contains(&a),
            })
            .map(|x| format!("address {}", show_ip(x.ip)))
            .collect(),
    }
}
/// The IPv6 stand's seal before and after the case (`capture isolation --mode ipv6`).
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

// ------------------------------------------------------------------ the plan of the shared verifier

/// The IPv6 suite as [`pair_verify`] judges it.
pub(crate) struct Ipv6;
impl PairPlan for Ipv6 {
    type Case = CaseSpec;
    type View = WireView;
    type Rec = Rec;
    type Expect = Ipv6Expect;
    const KEY: &'static str = "ipv6";
    const SCANNER_TEXT: &'static [&'static str] = &SCANNER_TEXT;
    const RECORD_ORDER_VS_C: &'static str = RECORD_ORDER_VS_C;
    const SCANNER_CLASSES: &'static [(&'static str, &'static str)] = &SCANNER_CLASSES;
    const PROBES_VS_C: &'static str = "";
    const PROBES_FIRST_DIFFERENCE: bool = true;
    const FOREIGN_SYN: &'static str = "IPv4 SYN";
    const OWN_WIRE: &'static str = "the document holds the records of the replies on its wire, field for field (C's IPv6 ttl aside), in reply order (replies captured at most 50 us apart on the peer link, rounded to the microsecond, may come in either order: REPLY_REORDER_WINDOW_US)";
    const ORACLE_NOTE: &'static str = "the pinned C masscan 8e6b3b0 with rmasscan's argv plus oracle_extra, one run per document, on the same stand";

    fn cases() -> Vec<CaseSpec> {
        CASES.to_vec()
    }
    fn tag(c: &CaseSpec) -> &'static str {
        c.tag
    }
    fn steps(c: &CaseSpec) -> Vec<StepSpec> {
        steps(c.tag).unwrap_or_default()
    }
    fn expect(c: &CaseSpec) -> Option<Ipv6Expect> {
        expect(c.tag)
    }
    fn manifest(v: Value) -> Option<Option<String>> {
        serde_json::from_value::<Ipv6Manifest>(v)
            .ok()
            .filter(|x| x.ipv6 == "linux")
            .map(|x| x.lab_id)
    }
    fn view(_c: &CaseSpec, fr: &Frames, st: &Stand) -> WireView {
        view(fr, st)
    }
    fn parse_doc(out: Out, b: &[u8], who: Who) -> Result<Document, String> {
        parse_doc_of(out, b, who)
    }
    fn doc_rule(who: Who) -> &'static str {
        match who {
            Who::Rmasscan => "",
            Who::Oracle => IPV6_DOC_RULE,
        }
    }
    fn foreign(fr: &Frames, st: &Stand) -> Vec<String> {
        let mut off = pv::foreign_probes(fr, st);
        off.extend(foreign_probes6(fr, st));
        off
    }
    fn text_problems(text: &str, scanner_text: bool) -> Vec<String> {
        let mut p = pv::iface_problems(text);
        p.extend(
            ipv6_tokens(text)
                .into_iter()
                .filter(|ip| !ipv6_allowed(*ip, scanner_text))
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
    fn case_records(r: &mut Run, d: &Path, _c: &CaseSpec) {
        // The stand's IPv6 before the case: an address that was tentative (or any other unready state) means the
        // case did not run on the stand at all, so NOT RUN, never a PASS or a FAIL.
        if let Some(p) = av::typed::<Ipv6Stack>(r, d, IPV6_STACK_JSON) {
            let problem = stack_problem(&p);
            r.check(
                "ipv6-stack.json: the stand's IPv6 was ready before the case (the veth settings, the stand's addresses none tentative or failed)",
                problem.is_none(),
                problem.unwrap_or_else(|| "ready".into()),
                NOT_RUN,
                false,
            );
        }
    }
    fn plan(c: &CaseSpec) -> Result<Vec<Vec<u8>>, String> {
        plan_stream(c)
    }
    fn step_wire(
        r: &mut Run,
        c: &CaseSpec,
        s: &Side<WireView>,
        v: &WireView,
    ) -> serde_json::Map<String, Value> {
        stand_answers(r, s, v);
        scanner_frames(r, s, v, c);
        let mut counts = scanner_counts(
            &SCANNER_CLASSES,
            &v.scanner_named,
            v.scanner_unexplained.len(),
            &scanner_bounds(v, s.spec.who, c),
        );
        counts.insert("stand_noise".into(), json!(v.noise));
        counts
    }
    fn rmasscan_step(r: &mut Run, c: &CaseSpec, s: &Side<WireView>, doc: Option<&Document>) {
        rmasscan_step(r, s, c, doc);
    }
    fn wire_records_at(c: &CaseSpec, v: &WireView, who: Who, out: Out) -> Vec<(Rec, f64)> {
        wire_records_at(v, who, out, c.show_closed)
    }
    fn doc_record(x: &Rec, who: Who) -> Rec {
        match who {
            Who::Rmasscan => x.bare(),
            Who::Oracle => x.masked(),
        }
    }
    fn same_probe(rm: &[u8], c: &[u8]) -> Option<bool> {
        (rm == c).then_some(false)
    }
    fn vs_c(
        _c: &CaseSpec,
        rm: &[Rec],
        oracle: &[Rec],
    ) -> (Vec<Rec>, Vec<Rec>, usize, &'static str) {
        (
            rm.iter().map(Rec::masked).collect(),
            oracle.iter().map(Rec::masked).collect(),
            0,
            " (ipv6-ttl-not-compared applied)",
        )
    }
    fn finish(
        r: &mut Run,
        c: &CaseSpec,
        sides: &[Side<WireView>],
        docs: &[Option<Document>],
        _tally: Tally,
    ) {
        deviations(r, c, sides, docs);
        r.notes.insert(
            "stand_noise_classes".into(),
            json!(STAND_NOISE.iter().copied().collect::<BTreeMap<_, _>>()),
        );
    }
}

/// Judge an evidence directory: the manifest, every planned case, and a safety walk of everything else. Symbolic
/// links are never followed.
pub fn verify_dir(root: &Path) -> Value {
    pair_verify::verify_dir::<Ipv6>(root)
}

/// `ipv6-verify --dir DIR [--out FILE]`: 0 PASS, 1 FAIL, 2 INVALID or NOT RUN.
pub fn run(args: &[String]) -> Result<i32, String> {
    pair_verify::run::<Ipv6>(args)
}

#[cfg(test)]
#[path = "ipv6_verify_tests.rs"]
pub(crate) mod tests;
