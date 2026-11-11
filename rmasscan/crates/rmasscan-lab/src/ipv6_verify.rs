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
    autodetect_verify::{self as av, ArgvRecord, MANIFEST_JSON, Plan, Stand},
    capture::{
        self, IPV6_PEER_LL, IPV6_PEERS, IPV6_SCANNER, IPV6_SCANNER_LL, IPV6_SYSCTLS,
        IPV6_UNUSABLE_FLAGS,
    },
    macos_verify::{hashes_match_tree, tree},
    output_verify::{BINARY_BLOCK, canon, fields, text_lines},
    pcap::Frames,
    protocols_verify::{
        self as pv, ExpectStep, JSON_REC, LIST_REC, Out, REPLY_REORDER_WINDOW_US, ResponderRecord,
        Shown, St, first_difference, in_reply_order, reason_string, shown,
    },
    scan_control_verify::{self as sv, Who},
    verify::{self, FAIL, INVALID, NOT_RUN, PASS, Run, array, read_json, s},
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
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

pub use pv::{EXPECT_JSON, ISOLATION_JSON, ISOLATION_POST_JSON, PEER_FILES, RESPONDER_JSON};

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
        "R11: rmasscan resolves its IPv6 next hop with a Neighbor Solicitation to the route's next hop (here the interface default gateway, the peer's link-local), C with a Router Solicitation and the Router Advertisement (stack_ndpv6_resolve); a Linux peer without a router daemon sends no RA, so the oracle step is given --router-mac-ipv6 02-aa-00-00-00-02: its wire holds no NS of the scanner, rmasscan's holds its NS answered by the peer's NA",
    ),
    (
        "oracle-source-given",
        "C never takes a ULA (fc00::/7) or 2001:db8::/32 address as its IPv6 source (rawsock-getip6.c:68-71), rmasscan does; the oracle step is given --adapter-ip fd00:198:18::1, the address rmasscan detects: every IPv6 probe of both steps leaves from it",
    ),
    (
        "ipv6-ttl-not-compared",
        "T3: an IPv6 record's ttl is the reply's hop limit in rmasscan and a stale value in C (C sets ip_ttl for IPv4 only); rmasscan's IPv6 ttl is judged against its own wire, C's IPv6 ttl against nothing, and IPv6 ttls are left out when the two documents are compared",
    ),
    (
        "families-one-interface",
        "R17: C sends IPv6 out of the IPv4 default interface, rmasscan routes each family by its own table and refuses a mixed scan whose families leave by different interfaces; on the stand both families route via veth-a, so the mixed scan is not refused: rmasscan's step prints one interface and both source addresses",
    ),
];

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
    CASES.iter().find(|c| c.tag == tag).copied()
}
pub fn planned_tags() -> Vec<&'static str> {
    CASES.iter().map(|c| c.tag).collect()
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
    if let (Some(flag), Some(file)) = (out.flag(), out.file()) {
        a.extend([flag.to_owned(), file.to_owned()]);
    }
    if c.show_closed {
        a.extend(["--show".to_owned(), "open,closed".to_owned()]);
    }
    let port = SOURCE_PORT.to_string();
    a.extend(
        [
            "--seed",
            "1",
            "--rate",
            RATE,
            "--wait",
            WAIT,
            "--source-port",
            &port,
        ]
        .map(str::to_owned),
    );
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
    let mut v = Vec::new();
    for out in c.outs {
        for who in [Who::Rmasscan, Who::Oracle] {
            let mut a = argv(&c, *out);
            if who == Who::Oracle {
                a.extend(oracle_extra(&c));
            }
            v.push(StepSpec {
                name: out.step(who),
                who,
                out: *out,
                argv: a,
            });
        }
    }
    Some(v)
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
        steps: steps(tag)?
            .iter()
            .map(|s| ExpectStep {
                name: s.name.into(),
                who: s.who,
                out: s.out,
            })
            .collect(),
    })
}

/// `manifest.json` as far as this verifier reads it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Manifest {
    pub ipv6: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lab_id: Option<String>,
}

// ------------------------------------------------------------------ the stand

pub fn stand() -> Stand {
    av::stand(Plan::Linux)
}
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
/// `ipv6-stack.json`: the stand's IPv6 as the suite read it right before the case, and the responder it starts.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ipv6Stack {
    pub scanner: SideStack,
    pub peer: SideStack,
    pub responder: Vec<String>,
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
/// be bound or answer yet), or another responder.
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
/// makes the step INVALID (bound 0), never FAIL: rmasscan sends no such frame (its only IPv6 frames are SYNs, the NS of
/// its resolver and the NA of its responder), so each is a stand that was not quiet.
pub const STAND_NOISE: [(&str, &str); 5] = [
    (
        "mld",
        "an MLD query, report or done (ICMPv6 130, 131, 132, 143) from either kernel: a host reports only when it joins or leaves a group; the stand's groups are joined when it is raised, before wire-lab.sh's settle wait (an unsolicited report repeats within mldv2_unsolicited_report_interval, 1 s), so none may fall into a step",
    ),
    (
        "router_solicitation",
        "ICMPv6 133 from either kernel: the stand sets accept_ra=0 and router_solicitations=0 on both veth ends",
    ),
    (
        "router_advertisement",
        "ICMPv6 134: no router daemon runs on the stand and both ends have forwarding=0",
    ),
    (
        "dad_ns",
        "a Neighbor Solicitation from :: (Duplicate Address Detection): the stand sets accept_dad=0 and adds its addresses nodad",
    ),
    (
        "peer_ns_for_scanner",
        "a Neighbor Solicitation of the peer for the scanner's address: the peer has fd00:198:18::1 as a permanent neighbour, so it never resolves the scanner",
    ),
];
fn noise(p: &Pkt, from_peer: bool) -> Option<&'static str> {
    let t = icmp6_type(p)?;
    match t {
        130 | 131 | 132 | 143 => Some(STAND_NOISE[0].0),
        133 => Some(STAND_NOISE[1].0),
        134 => Some(STAND_NOISE[2].0),
        135 if p.src == IpAddr::V6(Ipv6Addr::UNSPECIFIED) => Some(STAND_NOISE[3].0),
        135 if from_peer && p.l4.len() >= 24 => {
            let target = v6_at(p.l4, 8);
            (target == scanner6() || target == a6(IPV6_SCANNER_LL)).then_some(STAND_NOISE[4].0)
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

/// A reply of the peer to one probe, as a scanner reads it.
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

/// The frames of the scanner MAC that are no probe of the scan and that the scanner side sends on the stand.
pub const SCANNER_CLASSES: [(&str, &str); 4] = [
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
];
/// How many frames of each [`SCANNER_CLASSES`] entry a step may hold: the resolver's request count when the step
/// resolves that family's next hop ([`pv::NEXT_HOP_WHO_HAS_MAX_RMASSCAN`], [`pv::NEXT_HOP_WHO_HAS_MAX_C`],
/// [`NEXT_HOP_NS_MAX`]; 0 otherwise: a scan without IPv4 targets never ARPs, a step given `--router-mac-ipv6` and C,
/// which is always given it here, never solicit), one kernel reset per SYN-ACK frame plus on the oracle's step one
/// reset of C per distinct SYN-ACK, and per peer NS for the scanner one NA of the kernel plus, on rmasscan's step, one
/// of its responder. `(class, count, at most)` in [`SCANNER_CLASSES`] order.
pub fn scanner_bounds(v: &WireView, who: Who, c: &CaseSpec) -> [(&'static str, usize, usize); 4] {
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
    let (resets, na) = match who {
        Who::Rmasscan => (syn_acks, 2 * v.peer_ns.len()),
        Who::Oracle => (syn_acks + distinct, v.peer_ns.len()),
    };
    let max = [who_has, ns, resets, na];
    let mut out = [("", 0, 0); 4];
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
        let answers = x.flags == 0x04
            && v.replies.iter().any(|r| {
                r.st == St::Open
                    && r.ip == p.dst
                    && pkt(&r.frame)
                        .and_then(|q| tcp(&q))
                        .is_some_and(|y| (y.sp, y.dp, y.ack) == (x.dp, x.sp, x.seq))
            });
        return if answers {
            Mine::Class(SCANNER_CLASSES[2].0)
        } else {
            Mine::Other(format!(
                "{}, which resets no SYN-ACK of the stand",
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
    let mut cur = plan.cursor_for_nic(0, None).map_err(|e| e.to_string())?;
    let mut frames = Vec::new();
    loop {
        let batch: Vec<Vec<u8>> = cur.preload(64).iter().map(|p| p.frame.clone()).collect();
        if batch.is_empty() {
            break;
        }
        cur.advance_sent_n(batch.len());
        frames.extend(batch);
    }
    if let Some(e) = cur.build_error() {
        return Err(e.to_string());
    }
    Ok(frames)
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
    pub ttl: Option<u8>,
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
        let ttl = (out != Out::List && !(who == Who::Oracle && r.ip.is_ipv6())).then_some(r.ttl);
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
#[derive(Debug, Clone, Default)]
pub struct Document {
    pub records: Vec<Rec>,
    /// The footer is written.
    pub complete: bool,
}
/// An address as C prints it (`ipaddress_fmt`): IPv4 dotted, IPv6 in `ipv6address_fmt`'s form.
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
    if proto != "tcp" {
        return Err(format!("protocol {proto:?} (R3: TCP only)"));
    }
    Ok(Rec {
        st: status(st)?,
        ip: ip_text(ip).ok_or(format!("address {ip:?}"))?,
        port: canon(port).ok_or(format!("port {port:?}"))?,
        reason: reason.map(str::to_owned),
        ttl: ttl
            .map(|t| canon::<u8>(t).ok_or(format!("ttl {t:?}")))
            .transpose()?,
        ts: Some(canon(ts).ok_or(format!("time {ts:?}"))?),
    })
}
fn each(lines: &[&str], parse: impl Fn(&str) -> Result<Rec, String>) -> Result<Vec<Rec>, String> {
    lines
        .iter()
        .map(|l| parse(l).map_err(|e| format!("{l:?}: {e}")))
        .collect()
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
                    ttl: Some(left[14]),
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
                    ttl: Some(left[10]),
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
/// A document of `out` in its C form (`out-text.c`, `out-json.c`, `out-binary.c` types 6, 7, 10, 11): an empty file
/// is a document without a record; a file that stops after a record, without its footer, is not `complete`; any other
/// malformation is an error.
pub fn parse_doc(out: Out, b: &[u8]) -> Result<Document, String> {
    if b.is_empty() {
        return Ok(Document {
            records: Vec::new(),
            complete: true,
        });
    }
    let mut d = Document::default();
    match out {
        Out::List => {
            let lines = text_lines(b, "\n")?;
            if lines[0] != "#masscan" {
                return Err("no `#masscan` header".into());
            }
            d.complete = lines.len() > 1 && lines.last() == Some(&"# end");
            let body = &lines[1..lines.len() - usize::from(d.complete)];
            d.records = each(body, |l| {
                let f = fields(LIST_REC, l).ok_or("not the record form")?;
                field_rec(f[0], f[1], f[3], f[2], f[4], None, None)
            })?;
        }
        Out::Json => {
            let lines = text_lines(b, "\n")?;
            if lines[0] != "[" {
                return Err("no `[` header".into());
            }
            d.complete = lines.len() > 1 && lines.last() == Some(&"]");
            let body = &lines[1..lines.len() - usize::from(d.complete)];
            if body.len().is_multiple_of(2) || body.iter().skip(1).step_by(2).any(|l| *l != ",") {
                return Err("the records are not separated by `,` lines".into());
            }
            let recs: Vec<&str> = body.iter().step_by(2).copied().collect();
            d.records = each(&recs, |l| {
                let f = fields(JSON_REC, l).ok_or("not the record form")?;
                field_rec(f[4], f[3], f[0], f[2], f[1], Some(f[5]), Some(f[6]))
            })?;
        }
        Out::Binary => {
            if b.len() < BINARY_BLOCK || !b.starts_with(b"masscan/1.1\ns:") {
                return Err("not the 99-byte `masscan/1.1` header".into());
            }
            (d.records, d.complete) = binary_records(&b[BINARY_BLOCK..])?;
        }
        Out::Stdout => return Err("no case of this suite writes the interactive form".into()),
    }
    if d.records.is_empty() {
        return Err(
            "a header without a record (the header is written with the first record)".into(),
        );
    }
    Ok(d)
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

// ------------------------------------------------------------------ what a step left

struct Side {
    spec: StepSpec,
    exit: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
    se: sv::Stderr,
    view: Option<WireView>,
    frames: Option<Frames>,
    raw: Option<Vec<u8>>,
    forced_exit: bool,
}

fn read_side(r: &mut Run, d: &Path, spec: &StepSpec, links: &[String]) -> Side {
    let name = spec.name;
    let sd = d.join(name);
    let rel = |f: &str| format!("{name}/{f}");
    let exit = av::need(r, &sd, "exit.txt").and_then(|t| {
        let rc = av::parse_exit(&t);
        if rc.is_none() {
            r.inv(
                &format!("{name}/exit.txt holds an exit code"),
                false,
                t.trim(),
            );
        }
        rc
    });
    let stdout = av::need(r, &sd, "stdout.txt");
    let stderr = av::need(r, &sd, "stderr.txt");
    let st = stand();
    let cap = av::capture(r, d, &rel(PEER_FILES[0]), links);
    if let Some(cp) = &cap {
        av::witness(r, d, &rel(PEER_FILES[0]), &rel(PEER_FILES[1]), cp, &st);
    }
    let raw = spec.out.file().and_then(|n| {
        let b = fs::read(sd.join(n)).ok();
        if b.is_none() {
            sv_beh(r, spec, &format!("{n} written"), false, "missing");
        }
        b
    });
    let se = stderr.as_deref().map(sv::parse_stderr).unwrap_or_default();
    Side {
        spec: spec.clone(),
        exit,
        forced_exit: spec.who == Who::Oracle && stderr.as_deref().is_some_and(sv::forced_exit),
        stdout,
        stderr,
        se,
        view: cap.as_ref().map(|(fr, _)| view(fr, &st)),
        frames: cap.map(|(fr, _)| fr),
        raw,
    }
}

// ------------------------------------------------------------------ checks

/// rmasscan's misbehaviour FAILs; a broken oracle is a broken stand (INVALID).
fn sv_beh(r: &mut Run, spec: &StepSpec, name: &str, ok: bool, detail: impl ToString) {
    let name = format!("{}: {name}", spec.name);
    match spec.who {
        Who::Rmasscan => r.beh(&name, ok, detail),
        Who::Oracle => r.inv(&name, ok, detail),
    }
}
fn beh(r: &mut Run, s: &Side, name: &str, ok: bool, detail: impl ToString) {
    sv_beh(r, &s.spec, name, ok, detail);
}
/// A check against the capture: FAIL only once the evidence is proven (rmasscan); INVALID for the oracle.
fn cap(r: &mut Run, s: &Side, name: &str, ok: bool, detail: impl ToString) {
    let name = format!("{}: {name}", s.spec.name);
    match s.spec.who {
        Who::Rmasscan => r.cap(&name, ok, detail),
        Who::Oracle => r.inv(&name, ok, detail),
    }
}
fn first(v: &[String]) -> String {
    v.iter().take(4).cloned().collect::<Vec<_>>().join("; ")
}

/// The stand owes every probe its answer (TCP 80 and 8080 open, the rest reset), every NS of the scanner exactly one
/// NA of its form, and no other frame and no kernel noise; anything else is a stand that did not behave (INVALID for
/// both scanners).
fn stand_answers(r: &mut Run, s: &Side, v: &WireView) {
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
            "{}: no kernel noise of either side in the step (STAND_NOISE: MLD, RS, RA, DAD NS, a peer NS for the scanner; bound 0 each)",
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
fn scanner_frames(r: &mut Run, s: &Side, v: &WireView, c: &CaseSpec) {
    cap(
        r,
        s,
        "every frame of the scanner MAC is a probe of the scan or of a named class (next-hop who-has, next-hop NS, RST to a SYN-ACK, NA to a peer NS)",
        v.scanner_unexplained.is_empty(),
        format!(
            "{} other frames: {}",
            v.scanner_unexplained.len(),
            first(&v.scanner_unexplained)
        ),
    );
    let bounds = scanner_bounds(v, s.spec.who, c);
    cap(
        r,
        s,
        "the named scanner-side frames stay within their bounds (who-has and NS: the resolver's request count when the step resolves that next hop, else 0; RST: one per SYN-ACK frame, on the oracle's step plus one per distinct SYN-ACK; NA: per peer NS one of the kernel, plus one of rmasscan's responder)",
        bounds.iter().all(|(_, n, max)| n <= max),
        bounds
            .iter()
            .map(|(k, n, max)| format!("{k} {n} of at most {max}"))
            .collect::<Vec<_>>()
            .join(", "),
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
fn detection(r: &mut Run, s: &Side, c: &CaseSpec) {
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
fn plus_value<'a>(s: &'a Side, key: &str) -> Option<&'a str> {
    s.se.plus
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// A rmasscan step: exit, stdout, stderr grammar, `[+]` lines, `[+] finished` against the wire, record times.
fn rmasscan_step(r: &mut Run, s: &Side, c: &CaseSpec, doc: Option<&Document>) {
    if let Some(rc) = s.exit {
        beh(r, s, "exit.txt is 0", rc == 0, rc);
    }
    if let Some(t) = &s.stdout {
        beh(
            r,
            s,
            "stdout.txt is empty (a file format silences stdout)",
            t.is_empty(),
            t.len(),
        );
    }
    if s.stderr.is_none() {
        return;
    }
    beh(
        r,
        s,
        "stderr.txt holds only [+] lines and rmasscan's status forms",
        s.se.stray.is_empty(),
        format!("{:?}", s.se.stray),
    );
    detection(r, s, c);
    let fin = s.se.fin.as_ref();
    beh(
        r,
        s,
        "[+] finished: Completed",
        fin.is_some_and(|f| f.reason == "Completed"),
        format!("{fin:?}"),
    );
    let Some(v) = &s.view else { return };
    let all = wire_records(v, Who::Rmasscan, Out::Json, true);
    let open = all.iter().filter(|x| x.st == St::Open).count() as u64;
    let want = (v.probes.len() as u64, all.len() as u64, open);
    cap(
        r,
        s,
        "[+] finished reports sent, replies and open equal to the probes and the distinct replies on the wire",
        fin.map(|f| (f.sent, f.replies, f.open)) == Some(want),
        format!(
            "printed {:?}, wire (sent, replies, open) {want:?}",
            fin.map(|f| (f.sent, f.replies, f.open))
        ),
    );
    if let Some(d) = doc {
        let (lo, hi) = (
            v.probes.first().map_or(0.0, |p| p.t) - 2.0,
            v.replies.last().map_or(0.0, |p| p.t) + 2.0,
        );
        let off: Vec<u64> = d
            .records
            .iter()
            .filter_map(|x| x.ts)
            .filter(|t| !(lo..=hi).contains(&(*t as f64)))
            .collect();
        cap(
            r,
            s,
            "every record's time lies within the scan on the wire (2 s either side)",
            off.is_empty(),
            format!("{off:?}"),
        );
    }
}

/// The document of a step: well formed; rmasscan's complete, the oracle's complete or cut by its forced exit.
fn doc_of(r: &mut Run, s: &Side) -> Option<Document> {
    let raw = s.raw.as_ref()?;
    let what = s.spec.out.file().unwrap_or("stdout.txt");
    match parse_doc(s.spec.out, raw) {
        Ok(d) => {
            beh(
                r,
                s,
                &format!("{what} is a well-formed document"),
                true,
                format!("{} records", d.records.len()),
            );
            if !d.complete {
                beh(
                    r,
                    s,
                    "its file lacks the footer only after masscan's forced exit (the line is on its stderr)",
                    s.spec.who == Who::Oracle && s.forced_exit,
                    "no footer",
                );
            }
            Some(d)
        }
        Err(e) => {
            beh(r, s, &format!("{what} is a well-formed document"), false, e);
            None
        }
    }
}

/// What a case proves beyond the common checks, on rmasscan's steps.
fn case_checks(r: &mut Run, c: &CaseSpec, s: &Side, v: &WireView) {
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
fn deviations(r: &mut Run, c: &CaseSpec, sides: &[Side], docs: &[Option<Document>]) {
    let mut notes = Vec::new();
    for name in c.deviations {
        let rule = DEVIATIONS
            .iter()
            .find(|(n, _)| n == name)
            .map_or("", |(_, x)| *x);
        let views = |who: Who| {
            sides
                .iter()
                .filter(move |s| s.spec.who == who)
                .filter_map(|s| s.view.as_ref())
        };
        let (ok, observed): (bool, String) = match *name {
            "ndp-ns-not-rs" => {
                let oracle_ns: usize = views(Who::Oracle).map(|v| v.ns.len()).sum();
                let rm: Vec<usize> = views(Who::Rmasscan).map(|v| v.ns.len()).collect();
                (
                    oracle_ns == 0 && rm.iter().all(|n| *n >= 1),
                    format!("NS of the scanner: rmasscan steps {rm:?}, oracle steps {oracle_ns}"),
                )
            }
            "oracle-source-given" => {
                let off = sides
                    .iter()
                    .filter_map(|s| s.view.as_ref())
                    .flat_map(|v| &v.probes)
                    .filter(|p| p.ip.is_ipv6())
                    .filter(|p| pkt(&p.frame).map(|q| q.src) != Some(IpAddr::V6(scanner6())))
                    .count();
                let detected = sides
                    .iter()
                    .filter(|s| s.spec.who == Who::Rmasscan && s.stderr.is_some())
                    .all(|s| {
                        s.se.plus.iter().any(|(k, v)| {
                            k == "source-ip" && *v == format!("[{IPV6_SCANNER}] (detected)")
                        })
                    });
                (
                    off == 0 && detected,
                    format!(
                        "{off} IPv6 probes from another source; rmasscan detected {IPV6_SCANNER}: {detected}"
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
                            .map(|y| y.ttl);
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
                let ok = sides
                    .iter()
                    .filter(|s| s.spec.who == Who::Rmasscan && s.stderr.is_some())
                    .all(|s| {
                        plus_value(s, "interface").is_some_and(|i| i.starts_with("veth-a "))
                            && s.se.plus.iter().filter(|(k, _)| k == "source-ip").count() == 2
                    });
                (
                    ok,
                    format!(
                        "rmasscan printed one interface (veth-a) and both source addresses: {ok}"
                    ),
                )
            }
            _ => (false, "unknown deviation".into()),
        };
        r.inv(&format!("deviation {name}: {rule}"), ok, &observed);
        notes.push(json!({"name": name, "rule": rule, "observed": observed}));
    }
    r.notes.insert("deviations".into(), json!(notes));
}

/// One case: every step's own checks, then each document's rmasscan step against its oracle step.
fn judge(r: &mut Run, c: &CaseSpec, sides: &[Side]) {
    let plan = match plan_stream(c) {
        Ok(p) => Some(p),
        Err(e) => {
            r.inv("the case's plan rebuilds from the case table", false, e);
            None
        }
    };
    let mut docs: Vec<Option<Document>> = Vec::new();
    let mut scanner_notes = serde_json::Map::new();
    let mut swaps = serde_json::Map::new();
    for s in sides {
        if let Some(v) = &s.view {
            stand_answers(r, s, v);
            scanner_frames(r, s, v, c);
            let mut counts: serde_json::Map<String, Value> = SCANNER_CLASSES
                .iter()
                .map(|(k, _)| {
                    (
                        (*k).into(),
                        json!(v.scanner_named.get(k).copied().unwrap_or(0)),
                    )
                })
                .collect();
            counts.insert("unexplained".into(), json!(v.scanner_unexplained.len()));
            counts.insert("stand_noise".into(), json!(v.noise));
            counts.insert(
                "at_most".into(),
                json!(
                    scanner_bounds(v, s.spec.who, c)
                        .iter()
                        .map(|(k, _, max)| (*k, *max))
                        .collect::<BTreeMap<_, _>>()
                ),
            );
            scanner_notes.insert(s.spec.name.into(), Value::Object(counts));
        }
        let d = doc_of(r, s);
        match s.spec.who {
            Who::Rmasscan => {
                rmasscan_step(r, s, c, d.as_ref());
                if let Some(v) = &s.view {
                    case_checks(r, c, s, v);
                }
            }
            Who::Oracle => {
                if let Some(rc) = s.exit {
                    beh(r, s, "exit.txt is 0", rc == 0, rc);
                }
            }
        }
        if let (Some(v), Some(d)) = (&s.view, &d) {
            let want = wire_records_at(v, s.spec.who, s.spec.out, c.show_closed);
            let got: Vec<Rec> = d
                .records
                .iter()
                .map(|x| match s.spec.who {
                    Who::Rmasscan => x.bare(),
                    Who::Oracle => x.masked(),
                })
                .collect();
            let order = in_reply_order(&got, &want);
            if let Ok(n) = order {
                swaps.insert(
                    s.spec.name.into(),
                    json!({"pairs": n.pairs, "largest_gap_us": n.largest_gap_us}),
                );
            }
            cap(
                r,
                s,
                "the document holds the records of the replies on its wire, field for field (C's IPv6 ttl aside), in reply order (replies captured at most 50 us apart on the peer link may come in either order: REPLY_REORDER_WINDOW_US)",
                order.is_ok(),
                order.map_or_else(|e| e, |_| shown(&got)),
            );
        }
        if let (Some(v), Some(p), Who::Rmasscan) = (&s.view, &plan, s.spec.who) {
            let act = v.probe_frames();
            let at = act.iter().zip(p).position(|(a, b)| a != b);
            cap(
                r,
                s,
                "the probes on the wire equal the plan (ReadyPlan of the case), in order, each once",
                act == *p,
                format!(
                    "{} probes, {} planned, first difference at {at:?}",
                    act.len(),
                    p.len()
                ),
            );
        }
        docs.push(d);
    }
    let mut order = serde_json::Map::new();
    for (i, pair) in sides.chunks(2).enumerate() {
        let [rm, or] = pair else { continue };
        let k = 2 * i;
        if let (Some(a), Some(b)) = (&rm.view, &or.view) {
            let same = a.probe_frames() == b.probe_frames();
            r.cap(
                &format!(
                    "{}: the probes equal the C oracle's ({}), byte for byte and in order",
                    rm.spec.name, or.spec.name
                ),
                same,
                format!(
                    "{} probes, the oracle {}, first difference at {:?}",
                    a.probes.len(),
                    b.probes.len(),
                    a.probes
                        .iter()
                        .zip(&b.probes)
                        .position(|(x, y)| x.frame != y.frame)
                ),
            );
        }
        if let (Some(Some(x)), Some(Some(y))) = (docs.get(k), docs.get(k + 1)) {
            let got: Vec<Rec> = x.records.iter().map(Rec::masked).collect();
            let want: Vec<Rec> = y.records.iter().map(Rec::masked).collect();
            let (mut got_set, mut want_set) = (got.clone(), want.clone());
            got_set.sort();
            want_set.sort();
            let same = got_set == want_set;
            order.insert(
                rm.spec.name.into(),
                json!(match (same, got == want) {
                    (true, true) => "the same records in the same order",
                    (true, false) => "the same records, in another order",
                    (false, _) => "other records",
                }),
            );
            r.cap(
                &format!(
                    "{}: the records equal the C oracle's ({}) field for field but the time and the IPv6 ttl, in any order (each document's order is its own wire's reply order, judged above)",
                    rm.spec.name, or.spec.name
                ),
                same,
                if same {
                    shown(&got)
                } else {
                    first_difference(&got_set, &want_set)
                },
            );
        }
    }
    r.notes.insert(
        "record_order_vs_c".into(),
        json!({"rule": RECORD_ORDER_VS_C, "documents": order}),
    );
    r.notes
        .insert("reply_order_swaps".into(), Value::Object(swaps));
    r.notes.insert(
        "reply_order_window".into(),
        json!(format!(
            "{REPLY_REORDER_WINDOW_US} us: two replies captured on the peer link at most this far apart (rounded to the microsecond) may reach the scanner in the other order; reply_order_swaps gives, per step, the pairs of records written in the other order within it and the largest gap among them"
        )),
    );
    deviations(r, c, sides, &docs);
    r.notes.insert(
        "scanner_frame_classes".into(),
        json!(SCANNER_CLASSES.iter().copied().collect::<BTreeMap<_, _>>()),
    );
    r.notes.insert(
        "stand_noise_classes".into(),
        json!(STAND_NOISE.iter().copied().collect::<BTreeMap<_, _>>()),
    );
    r.notes
        .insert("scanner_frames".into(), Value::Object(scanner_notes));
}

// ------------------------------------------------------------------ privacy and evidence

/// The files a scanner wrote or that name its argv: their addresses must be the stand's.
const SCANNER_TEXT: [&str; 8] = [
    "argv.json",
    "expect.json",
    "stdout.txt",
    "stderr.txt",
    "output.txt",
    "output.json",
    "exit.txt",
    IPV6_STACK_JSON,
];
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
fn privacy(r: &mut Run, d: &Path, files: &[String]) {
    let mut clean = true;
    let mut seen = 0;
    for rel in files {
        let ext = Path::new(rel)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        if ext != "bin" && !av::TEXT_EXTENSIONS.contains(&ext) {
            continue;
        }
        let base = rel.rsplit('/').next().unwrap_or(rel);
        let scanner_text = SCANNER_TEXT.contains(&base);
        let mut p = match fs::read(d.join(rel)) {
            Err(e) => vec![format!("unreadable: {e}")],
            Ok(b) if ext == "bin" => binary_problems(&b),
            Ok(b) => {
                // The table's case names are no host names (`v01_ndp_and_tcp6_syn` reads like a DNS-SD `_tcp` label).
                let text = CASES
                    .iter()
                    .fold(String::from_utf8_lossy(&b).into_owned(), |t, c| {
                        t.replace(c.tag, "<case>")
                    });
                let mut p = av::token_problems(&text, scanner_text);
                p.extend(pv::iface_problems(&text));
                p.extend(
                    ipv6_tokens(&text)
                        .into_iter()
                        .filter(|ip| !ipv6_allowed(*ip, scanner_text))
                        .map(|ip| format!("IPv6 address {ip}")),
                );
                p
            }
        };
        seen += 1;
        p.sort();
        p.dedup();
        if !p.is_empty() {
            clean = false;
            r.inv(
                &format!("privacy: {rel} holds only allowlisted names, addresses and paths"),
                false,
                p.join("; "),
            );
        }
    }
    if clean {
        r.add(
            "privacy: every text and binary file holds only allowlisted names, IPv4 and IPv6 addresses and paths",
            PASS,
            format!("{seen} files"),
            false,
        );
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
fn gate(r: &mut Run, d: &Path, files: &[String]) {
    match hashes_match_tree(d, true) {
        Ok(()) => r.add(
            "hashes-before-copy.txt matches every file of the case directory",
            PASS,
            files.len(),
            false,
        ),
        Err(e) => r.add(
            "hashes-before-copy.txt matches every file of the case directory",
            INVALID,
            e,
            false,
        ),
    }
    let odd: Vec<&String> = files
        .iter()
        .filter(|f| !pv::evidence_extension(f))
        .collect();
    r.inv(
        "evidence files carry only the allowed extensions (json pcap txt log err sha256 md, bin for -oB)",
        odd.is_empty(),
        format!("{odd:?}"),
    );
    seal(r, d);
}

// ------------------------------------------------------------------ one case

fn verify_run(root: &Path, c: &CaseSpec, root_links: &[String]) -> Run {
    let tag = c.tag;
    let mut r = Run::new(tag);
    let rel = format!("runs/{tag}");
    if root_links.iter().any(|l| l == "runs" || *l == rel) {
        r.inv(
            "the case directory is a real directory, not a symbolic link",
            false,
            rel,
        );
        return r;
    }
    let d = root.join("runs").join(tag);
    if !d.is_dir() {
        r.add("case directory present", NOT_RUN, "missing", false);
        return r;
    }
    let Some(specs) = steps(tag) else { return r };
    let t = tree(&d);
    r.safety(
        "no compressed capture in the case directory",
        !t.files.iter().chain(&t.links).any(|f| f.ends_with(".gz")),
        "captures are stored uncompressed; the verifier has no decompression",
    );
    let st = stand();
    let sides: Vec<Side> = specs
        .iter()
        .map(|spec| read_side(&mut r, &d, spec, &t.links))
        .collect();
    for s in &sides {
        if let Some(fr) = &s.frames {
            let who = s.spec.name;
            let n = av::foreign_syns(fr, &st);
            r.safety(
                &format!("no IPv4 SYN on the {who} capture from outside the stand binding or to an address off the stand"),
                n == 0,
                n,
            );
            let mut off = pv::foreign_probes(fr, &st);
            off.extend(foreign_probes6(fr, &st));
            r.safety(
                &format!("no frame of the scanner on the {who} capture to an IPv4 or IPv6 address off the stand or from another source"),
                off.is_empty(),
                off.iter().take(3).cloned().collect::<Vec<_>>().join(", "),
            );
            av::no_foreign_frame(&mut r, who, fr, &st);
        }
    }
    if !t.links.is_empty() {
        r.inv(
            "no symbolic link in the case directory (links are never followed)",
            false,
            format!("{:?}", t.links),
        );
        return r;
    }
    gate(&mut r, &d, &t.files);
    privacy(&mut r, &d, &t.files);
    let expect_rec: Option<Ipv6Expect> = av::typed(&mut r, &d, EXPECT_JSON);
    let expect_ok = expect_rec.as_ref() == expect(tag).as_ref();
    if expect_rec.is_some() {
        r.inv(
            "expect.json equals the case table's entry",
            expect_ok,
            format!("table {:?}", expect(tag)),
        );
    }
    let mut argv_ok = expect_ok;
    for spec in &specs {
        let rec: Option<ArgvRecord> = av::typed(&mut r, &d.join(spec.name), "argv.json");
        if let Some(a) = &rec {
            let ok = a.argv == spec.argv;
            r.inv(
                &format!(
                    "{}/argv.json is the step's argv in the case table",
                    spec.name
                ),
                ok,
                format!("{:?}, table {:?}", a.argv, spec.argv),
            );
            argv_ok &= ok;
        } else {
            argv_ok = false;
        }
    }
    r.argv_ok = argv_ok;
    for spec in &specs {
        if let Some(rec) = av::typed::<ResponderRecord>(&mut r, &d.join(spec.name), RESPONDER_JSON)
        {
            let problem = pv::responder_problem(&rec);
            r.inv(
                &format!(
                    "{}/{RESPONDER_JSON}: the peer responder ran until the scanner ended",
                    spec.name
                ),
                problem.is_none(),
                problem.unwrap_or_else(|| "it still ran".into()),
            );
        }
    }
    // The stand's IPv6 before the case: an address that was tentative (or any other unready state) means the case
    // did not run on the stand at all, so NOT RUN, never a PASS or a FAIL.
    if let Some(p) = av::typed::<Ipv6Stack>(&mut r, &d, IPV6_STACK_JSON) {
        let problem = stack_problem(&p);
        r.check(
            "ipv6-stack.json: the stand's IPv6 was ready before the case (the veth settings, the stand's addresses none tentative or failed, the stand's responder)",
            problem.is_none(),
            problem.unwrap_or_else(|| "ready".into()),
            NOT_RUN,
            false,
        );
    }
    judge(&mut r, c, &sides);
    r.notes.insert(
        "oracle".into(),
        json!("the pinned C masscan 8e6b3b0 with rmasscan's argv plus oracle_extra, one run per document, on the same stand"),
    );
    r
}

// ------------------------------------------------------------------ the directory

/// Judge an evidence directory: the manifest, every planned case, and a safety walk of everything else. Symbolic
/// links are never followed.
pub fn verify_dir(root: &Path) -> Value {
    let mut result = json!({"schema":1,"dir":root.file_name().unwrap_or_default().to_string_lossy(),"runs":[],"groups":[],"discarded":[],"aborted":[]});
    let t = tree(root);
    let mut m = Run::new("manifest");
    m.argv_ok = true;
    m.safety(
        "no compressed capture anywhere in the evidence directory",
        !t.files.iter().chain(&t.links).any(|f| f.ends_with(".gz")),
        "captures are stored uncompressed; the verifier has no decompression",
    );
    m.inv(
        "no symbolic link in the evidence directory (links are never followed)",
        t.links.is_empty(),
        format!("{:?}", t.links),
    );
    let manifest = (!t.links.iter().any(|l| l == MANIFEST_JSON))
        .then(|| read_json(root.join(MANIFEST_JSON)))
        .flatten()
        .and_then(|v| serde_json::from_value::<Ipv6Manifest>(v).ok())
        .filter(|x| x.ipv6 == "linux");
    m.check(
        "manifest.json names the ipv6 plan (linux)",
        manifest.is_some(),
        "",
        NOT_RUN,
        false,
    );
    let tags = if manifest.is_some() {
        planned_tags()
    } else {
        Vec::new()
    };
    let outside: Vec<String> = t
        .files
        .iter()
        .filter(|f| {
            *f != "verdict.json"
                && !tags
                    .iter()
                    .any(|tag| f.starts_with(&format!("runs/{tag}/")))
        })
        .cloned()
        .collect();
    let odd: Vec<&String> = outside
        .iter()
        .filter(|f| !pv::evidence_extension(f))
        .collect();
    m.inv(
        "evidence files outside the runs carry only the allowed extensions (json pcap txt log err sha256 md bin)",
        odd.is_empty(),
        format!("{odd:?}"),
    );
    privacy(&mut m, root, &outside);
    let unplanned: Vec<&str> = t
        .dirs
        .iter()
        .chain(&t.files)
        .chain(&t.links)
        .filter_map(|p| p.strip_prefix("runs/"))
        .filter(|p| !p.contains('/') && !tags.contains(p))
        .collect();
    m.inv(
        "runs/ holds only the planned case directories",
        unplanned.is_empty(),
        format!("{unplanned:?}"),
    );
    let attempts = av::attempts(&t, |name| av::attempt_of(&tags, name));
    if !attempts.is_empty() {
        let strays: Vec<&str> = attempts
            .iter()
            .filter(|a| a.case.is_none())
            .map(|a| a.name.as_str())
            .collect();
        m.inv(
            "runs_aborted/ holds only attempts of planned cases (<tag>.<run id>)",
            strays.is_empty(),
            format!("{strays:?}"),
        );
    }
    if manifest.is_some() {
        let id = manifest.as_ref().and_then(|x| x.lab_id.as_deref());
        av::teardown(&mut m, root, &t.links, id);
    }
    let mut runs = vec![m.summary()];
    if manifest.is_some() {
        runs.extend(CASES.iter().map(|c| {
            let mut r = verify_run(root, c, &t.links);
            let earlier: Vec<String> = attempts
                .iter()
                .filter(|a| a.case == Some(c.tag))
                .map(|a| format!("runs_aborted/{}", a.name))
                .collect();
            if !earlier.is_empty() {
                r.inv(
                    "no aborted attempt of this case in runs_aborted/ (a case runs once into one --out)",
                    false,
                    earlier.join(", "),
                );
            }
            r.summary()
        }));
    }
    result["runs"] = json!(runs);
    result["aborted"] = json!(
        attempts
            .iter()
            .map(av::Attempt::summary)
            .collect::<Vec<_>>()
    );
    result["safety_scan"] = json!(stray_scan(root, &tags, &t));
    verify::finish(result)
}

/// The captures outside the planned cases: `stray_scan`'s SYN and MAC checks, and the scanner's frames of either
/// family off the stand.
fn stray_scan(root: &Path, tags: &[&'static str], t: &crate::macos_verify::Tree) -> Vec<Value> {
    let planned = |rel: &str| {
        tags.iter()
            .any(|tag| rel.starts_with(&format!("runs/{tag}/")))
    };
    let st = stand();
    let mut out = av::stray_scan(root, Some(Plan::Linux), tags, t);
    for f in t
        .files
        .iter()
        .filter(|f| f.ends_with(PEER_FILES[0]) && !planned(f))
    {
        let mut r = Run::new(&format!("{f} (IPv4 and IPv6)"));
        r.argv_ok = true;
        if let Some((fr, _)) = verify::load_pcap(&mut r, &root.join(f)) {
            let mut off = pv::foreign_probes(&fr, &st);
            off.extend(foreign_probes6(&fr, &st));
            r.safety(
                "no frame of the scanner on the capture to an IPv4 or IPv6 address off the stand or from another source",
                off.is_empty(),
                off.iter().take(3).cloned().collect::<Vec<_>>().join(", "),
            );
        }
        out.push(r.summary());
    }
    out
}

/// `ipv6-verify --dir DIR [--out FILE]`: 0 PASS, 1 FAIL, 2 INVALID or NOT RUN.
pub fn run(args: &[String]) -> Result<i32, String> {
    let o = crate::windows_suite::options_for("ipv6-verify", args, &["dir", "out"])?;
    if o.contains_key("help") {
        println!("ipv6-verify --dir DIR [--out FILE]  (exit 0 PASS, 1 FAIL, 2 INVALID or NOT RUN)");
        return Ok(0);
    }
    let dir = crate::windows_suite::required(&o, "dir")?;
    let res = verify_dir(Path::new(&dir));
    if let Some(out) = o.get("out").and_then(|v| v.first()) {
        fs::write(
            out,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&res).map_err(|e| e.to_string())?
            ),
        )
        .map_err(|e| e.to_string())?;
    }
    for r in array(&res["runs"]) {
        let bad: Vec<_> = array(&r["checks"])
            .iter()
            .filter(|c| c["result"] != PASS)
            .take(3)
            .map(|c| format!("{}: {}", s(&c["result"]), s(&c["name"])))
            .collect();
        println!(
            "{:<8} {} {}",
            s(&r["verdict"]),
            s(&r["tag"]),
            bad.join("; ")
        );
    }
    for line in verify::safety_report_lines(&res) {
        println!("{line}");
    }
    println!("overall: {} {}", s(&res["overall"]), res["totals"]);
    Ok(match s(&res["overall"]) {
        PASS => 0,
        FAIL => 1,
        _ => 2,
    })
}

#[cfg(test)]
#[path = "ipv6_verify_tests.rs"]
pub(crate) mod tests;
