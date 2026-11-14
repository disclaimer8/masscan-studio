//! Offline verifier of the banners window of sub-stage 4a on the sealed Linux netns stand (`banners-verify`) and the
//! one case table of its suite (`banners-suite linux`): UDP banners (`--banners`, `--rawudp`) of the pinned C masscan
//! `8e6b3b0` and of rmasscan, against the same deterministic UDP responders (design
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
//! IPv6 is not in this window: the IPv6 stage refuses UDP over IPv6 (its R3), so live IPv6 banners arrive with TCP in
//! 4b (R16); the engine's IPv6 banner path is covered by its builder test.
//!
//! Layout of an evidence directory: `manifest.json` (key `banners`: `linux`), `teardown.json`, `runs/<tag>/` per
//! case: `expect.json` ([`BannerExpect`]), `isolation.json`, `isolation-post.json`, `peer-stack.json`,
//! `hashes-before-copy.txt`, and one directory per step: `argv.json`, `stdout.txt stderr.txt exit.txt`, the document
//! (`output.bin`, `output.txt`), the peer witness `peer.pcap capture.json peer.err` and `responder.json`.
#[cfg(test)]
use crate::verify::{self, array, s};
use crate::{
    autodetect_verify::{self as av, Plan, Stand},
    output_verify::{BINARY_BLOCK, canon, fields, text_lines},
    pair_verify::{
        self, Doc, PairPlan, Record, Side, Tally, WireSummary, beh, cap, case_of, each,
        expect_steps, named_deviations, pair_steps, scan_tail, scanner_counts, tags_of,
    },
    pcap::Frames,
    protocols_verify::{
        self as pv, ExpectStep, LIST_REC, Out, PeerStack, Shown, St, StepSpec, WireView,
        iface_problems, reason_string,
    },
    scan_control_verify::Who,
    verify::Run,
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
pub fn case(tag: &str) -> Option<CaseSpec> {
    case_of::<Banners>(tag)
}
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
    let c = case(tag)?;
    Some(pair_steps(c.outs, |out, _| argv(&c, out)))
}
/// `expect.json`: the case as the suite planned it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BannerExpect {
    pub tag: String,
    pub plan_ports: String,
    pub rawudp: bool,
    pub steps: Vec<ExpectStep>,
}
pub fn expect(tag: &str) -> Option<BannerExpect> {
    let c = case(tag)?;
    Some(BannerExpect {
        tag: tag.into(),
        plan_ports: PLAN_PORTS.into(),
        rawudp: c.rawudp,
        steps: expect_steps(&steps(tag)?),
    })
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

// ------------------------------------------------------------------ the documents

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
impl AppId {
    pub fn name(&self) -> String {
        match self {
            AppId::Name(n) => n.clone(),
            AppId::Id(n) => UDP_APPS
                .iter()
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
pub const DEVIATIONS: [(&str, &str); 3] = [
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
];
/// Why rmasscan's document and the oracle's are compared as multisets.
pub const RECORD_ORDER_VS_C: &str = "each scanner writes a reply's status record and then its banners in the order the replies arrive on its own wire (judged per step); the two runs of a document do not get the same reply order from the stand (one responder thread per UDP socket), so rmasscan's status and banner records must equal C's field for field but the time in any order: the set of banners per (address, port, application) is C's";

/// The stand owes every probe exactly one reply, and that reply is the table's scenario reply to that very probe;
/// anything else on the peer side is a stand that did not behave (INVALID for both scanners).
fn stand_answers(r: &mut Run, s: &Side<WireView>, v: &WireView) {
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

/// What one step's document proves about its banners: each follows its reply's status record with the same time;
/// each reply's banners are the scenario's applications; rmasscan's `-oB` raw banner is its datagram.
fn banner_checks(r: &mut Run, c: &CaseSpec, s: &Side<WireView>, d: &Document) {
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
    let Some(v) = &s.view else { return };
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
}

/// A rmasscan step: exit, stdout, stderr grammar, the `[+]` lines, `[+] finished` against the wire and the records.
fn rmasscan_step(r: &mut Run, s: &Side<WireView>, c: &CaseSpec, doc: Option<&Document>) {
    pair_verify::rmasscan_step(
        r,
        s,
        doc,
        |r, s| pv::detection(r, s, &proto_case(c)),
        |v| {
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
        },
    );
}

/// Each named deviation of the window: the wire condition that keeps it from changing the comparison, and the notes.
fn deviations(
    r: &mut Run,
    sides: &[Side<WireView>],
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
                    .filter_map(|s| s.view.as_ref())
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
                        (&s.view, d, s.spec.who, s.spec.out)
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

// ------------------------------------------------------------------ privacy and evidence

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
            .filter(|x| !matches!(x.ip, IpAddr::V4(a) if st.peer_ips.contains(&a)))
            .map(|x| format!("address {}", x.ip))
            .collect(),
    }
}

// ------------------------------------------------------------------ the plan of the shared verifier

/// The banners window as [`pair_verify`] judges it.
pub(crate) struct Banners;
impl PairPlan for Banners {
    type Case = CaseSpec;
    type View = WireView;
    type Rec = Rec;
    type Expect = BannerExpect;
    const KEY: &'static str = "banners";
    const SCANNER_TEXT: &'static [&'static str] = &SCANNER_TEXT;
    const RECORD_ORDER_VS_C: &'static str = RECORD_ORDER_VS_C;
    const SCANNER_CLASSES: &'static [(&'static str, &'static str)] = &pv::SCANNER_CLASSES;
    const PROBES_VS_C: &'static str = " (udp-checksum-ffff applied)";
    const PROBES_FIRST_DIFFERENCE: bool = true;
    const FOREIGN_SYN: &'static str = "SYN";
    const OWN_WIRE: &'static str = "the document's status records are the replies on its wire, field for field, in reply order (replies captured at most 50 us apart on the peer link, rounded to the microsecond, may come in either order: REPLY_REORDER_WINDOW_US); its banner records are judged against the stand's replies and the C oracle";
    const ORACLE_NOTE: &'static str = "the pinned C masscan 8e6b3b0 with the same argv, one run per document, on the same stand and the same scenario responder";

    fn cases() -> Vec<CaseSpec> {
        CASES.to_vec()
    }
    fn tag(c: &CaseSpec) -> &'static str {
        c.tag
    }
    fn steps(c: &CaseSpec) -> Vec<StepSpec> {
        steps(c.tag).unwrap_or_default()
    }
    fn expect(c: &CaseSpec) -> Option<BannerExpect> {
        expect(c.tag)
    }
    fn manifest(v: Value) -> Option<Option<String>> {
        serde_json::from_value::<BannerManifest>(v)
            .ok()
            .filter(|x| x.banners == "linux")
            .map(|x| x.lab_id)
    }
    fn view(_c: &CaseSpec, fr: &Frames, st: &Stand) -> WireView {
        pv::view(fr, st, false)
    }
    fn parse_doc(out: Out, b: &[u8], _who: Who) -> Result<Document, String> {
        parse_doc(out, b)
    }
    fn foreign(fr: &Frames, st: &Stand) -> Vec<String> {
        pv::foreign_probes(fr, st)
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
    fn case_records(r: &mut Run, d: &Path, _c: &CaseSpec) {
        if let Some(p) = av::typed::<PeerStack>(r, d, PEER_STACK_JSON) {
            let problem = peer_stack_problem(&p);
            r.inv(
                "peer-stack.json: the peer answers the stand's way (icmp_ratemask 0, Echo answered, the banners responder)",
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
        pv::scanner_frames(r, s, v);
        scanner_counts(
            &pv::SCANNER_CLASSES,
            &v.scanner_named,
            v.scanner_unexplained.len(),
            &pv::scanner_bounds(v, s.spec.who),
        )
    }
    fn rmasscan_step(r: &mut Run, c: &CaseSpec, s: &Side<WireView>, doc: Option<&Document>) {
        rmasscan_step(r, s, c, doc);
    }
    fn wire_records_at(_c: &CaseSpec, v: &WireView, who: Who, out: Out) -> Vec<(Rec, f64)> {
        wire_records_at(v, who, out)
    }
    fn doc_record(x: &Rec, _who: Who) -> Rec {
        x.bare()
    }
    fn own_wire_records(records: &[Rec], _who: Who) -> Vec<Rec> {
        records
            .iter()
            .filter(|x| !x.is_banner())
            .map(Rec::bare)
            .collect()
    }
    fn same_probe(rm: &[u8], c: &[u8]) -> Option<bool> {
        pv::same_probe(rm, c)
    }
    fn vs_c(
        _c: &CaseSpec,
        rm: &[Rec],
        oracle: &[Rec],
    ) -> (Vec<Rec>, Vec<Rec>, usize, &'static str) {
        let (got, _) = mask_raw_past_datagram(rm);
        let (want, n) = mask_raw_past_datagram(oracle);
        (
            got.iter().map(Rec::bare).collect(),
            want.iter().map(Rec::bare).collect(),
            n,
            " (udp-raw-past-datagram applied)",
        )
    }
    fn finish(
        r: &mut Run,
        c: &CaseSpec,
        sides: &[Side<WireView>],
        docs: &[Option<Document>],
        tally: Tally,
    ) {
        let mut counts = serde_json::Map::new();
        for (s, d) in sides.iter().zip(docs) {
            let Some(d) = d else { continue };
            banner_checks(r, c, s, d);
            let mut by_app: BTreeMap<String, usize> = BTreeMap::new();
            for name in d.records.iter().filter_map(Rec::app_name) {
                *by_app.entry(name).or_default() += 1;
            }
            counts.insert(s.spec.name.into(), json!(by_app));
            if let (Some(v), Who::Rmasscan) = (&s.view, s.spec.who) {
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
        deviations(r, sides, docs, tally.by_rule, tally.collapsed);
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
