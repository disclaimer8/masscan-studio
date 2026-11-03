//! Offline verifier of the autodetect acceptance runs (`autodetect-verify`) and the schema of their run
//! directories: the autodetect suites write `argv.json`, `expect.json`, `detected.json` and `iflist.json` with the
//! types defined here, and nowhere else.
//!
//! Portable and passive: it reads files and compares bytes, no network, no process. It keeps the honesty rules of
//! the Windows and macOS verifiers and reuses their machinery (`verify::Run`, `verify::finish`): a missing input is
//! NOT RUN, unproven evidence is INVALID, a lab frame on the uplink, a foreign SYN or a compressed capture is a
//! safety FAIL that nothing discards, and no verdict is ever promoted.
//!
//! Layout of an evidence directory: `manifest.json` (key `autodetect`: `linux`, `macos`, `macos-root` or
//! `windows`; other keys are the suite's own) and `runs/<tag>/` per planned case ([`planned_tags`]). A run
//! directory holds
//! - `argv.json` ([`ArgvRecord`]), `expect.json` ([`ExpectRecord`]) and `detected.json` ([`DetectedRecord`]: the
//!   stderr parsed by [`parse_stderr`]; not for `--iflist`);
//! - `stdout.txt stderr.txt exit.txt` (Windows: `guest-stdout.txt guest-stderr.txt guest-exit.txt`); an `--iflist`
//!   case has `iflist.json` ([`IflistRecord`]) and never a stdout file, since the full listing is an inventory;
//! - `peer.pcap` with its witness `capture.json` ([`PeerWitness`], the `capture dump` record);
//! - Linux `isolation.json` (`capture isolation --mode autodetect`); macOS `uplink.pcap uplink.err`, Windows
//!   `eno1.pcap eno1.err`, and on both `status-pre.json status-post.json`;
//! - `preflight.txt` for `w01`, `w06`, `m05`: `rc N`, then the stderr of the `rmasscan --offline` preflight;
//! - `l11_parity` also `oracle/{stdout,stderr,exit}.txt`, `oracle.pcap` and its witness `oracle-capture.json`;
//!   `l12_iflist` also `oracle/iflist.json` (`rc`, `lines`, `sha256` only);
//! - `hashes-before-copy.txt` (sha256sum form, every other file, nested paths with `/`).
//!
//! Evidence files carry only the extensions json pcap txt log err sha256 md.
use crate::{
    capture::{IsolationMode, isolation_permits},
    link::{END_PAYLOAD, MARKER_ETHERTYPE, START_PAYLOAD},
    macos_verify::{captured_in, has_compressed_capture, hashes_match_tree, relative_files},
    pcap::{self, Frames},
    verify::{self, FAIL, INVALID, NOT_RUN, PASS, Run, array, read_json, s, sha, tcp},
};
use rmasscan_core::{
    arp::{ARP_FRAME_LEN, ArpOp, decode, encode_request},
    config::{ScanConfig, parse_mac},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::Ipv4Addr,
    path::Path,
};

// ------------------------------------------------------------------ schema

pub const MANIFEST_JSON: &str = "manifest.json";
pub const ARGV_JSON: &str = "argv.json";
pub const EXPECT_JSON: &str = "expect.json";
pub const DETECTED_JSON: &str = "detected.json";
pub const IFLIST_JSON: &str = "iflist.json";
pub const PREFLIGHT_TXT: &str = "preflight.txt";
pub const CAPTURE_JSON: &str = "capture.json";
pub const PEER_PCAP: &str = "peer.pcap";
pub const ORACLE_PCAP: &str = "oracle.pcap";
pub const ORACLE_CAPTURE_JSON: &str = "oracle-capture.json";
pub const ORACLE_IFLIST_JSON: &str = "oracle/iflist.json";
pub const HASHES: &str = "hashes-before-copy.txt";
/// The only extensions an evidence file may carry (`*.gz` is a safety refusal of its own).
pub const EVIDENCE_EXTENSIONS: [&str; 7] = ["json", "pcap", "txt", "log", "err", "sha256", "md"];

/// Which stand and which case list an evidence directory holds (`manifest.json`, key `autodetect`).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Plan {
    /// `autodetect-suite linux` in the sealed netns pair (`l01`-`l12`).
    Linux,
    /// `autodetect-suite macos`, the user's grant window (`m01`-`m07`).
    Macos,
    /// `autodetect-suite macos --root-case`, run by the user under `sudo` (`m10`, `m11`).
    MacosRoot,
    /// `windows-suite --plan autodetect` on the `n2` guest (`w01`-`w08b`).
    Windows,
}

/// `manifest.json` as far as this verifier reads it. A suite may record more (the Windows suite's manifest carries
/// its own fields), so unknown keys are ignored here.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub autodetect: Plan,
}

/// What a case does, pinned per tag by [`case_kind`].
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CaseKind {
    /// A live scan that resolves its next hop with ARP or takes `--router-mac`: exit 0, SYNs as planned.
    Scan,
    /// The next hop never answers: exactly 10 ARP requests 1 s apart, exit 1, no SYN.
    ArpTimeout,
    /// Detection or opening refuses: exit 1, `[-] FAIL:` (or any error for `w08b`), no scanner frame.
    Refusal,
    /// `--iflist`: exit 0, only the reduced listing is stored, no scanner frame.
    Iflist,
    /// `l11_parity`: a scan whose ARP request, SYN order and results equal the C oracle's.
    Parity,
}

/// `argv.json`: the exact arguments rmasscan ran with, without the program name. The oracle of `l11_parity` ran
/// with the same list.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArgvRecord {
    pub argv: Vec<String>,
}

/// A `[+] key = value (source)` line: `value` and the text in the parentheses, verbatim (`given`, `detected`,
/// `detected: route to 198.18.0.2`, `on-link target`, `entropy`, `time`, `offline`, ...).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Sourced {
    pub value: String,
    pub source: String,
}

/// `(arp: N requests, T ms)` of a `[+] router-mac` line.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArpCount {
    pub requests: u32,
    pub ms: u64,
}

/// `[+] router-mac = MAC (given | offline | arp: N requests, T ms)`; `source` is `arp` for the last form.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RouterMac {
    pub value: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arp: Option<ArpCount>,
}

/// `[+] finished: REASON, sent N, replies N, open N`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finished {
    pub reason: String,
    pub sent: u64,
    pub replies: u64,
    pub open: u64,
}

/// `detected.json`: everything rmasscan wrote on stderr, parsed by [`parse_stderr`] (the suite writes it with that
/// function, the verifier parses stderr again and requires the two to be equal). A line that was not printed is
/// absent. MACs are in the CLI's form (`02-aa-00-00-00-01`).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DetectedRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<Sourced>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_mac: Option<Sourced>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<Sourced>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_ip: Option<Sourced>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_mac: Option<RouterMac>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<Sourced>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port: Option<Sourced>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished: Option<Finished>,
    /// The text after `[-] FAIL: `.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail: Option<String>,
    /// The text after `rmasscan: error: ` (an error that is not a detection or ARP refusal, such as opening).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The hint lines after the refusal, verbatim (`    [hint] …` or ` [hint] …`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<String>,
}

/// The detection a case expects, compared field by field with [`DetectedRecord`]. `router_ip` absent: no
/// `router-ip` line (`--router-mac` without `--router-ip`); `router_mac.source` is `arp` or `given`, and `None`
/// means no `router-mac` line (an ARP timeout or a refusal stops before it).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectDetection {
    pub interface: Sourced,
    pub source_mac: Sourced,
    pub source_ip: Sourced,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_ip: Option<Sourced>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_mac: Option<Sourced>,
}

/// The refusal a case expects: the exact text after `[-] FAIL: ` and the exact hint lines. `fail` absent (only
/// `w08b_restricted_scan`): any refusal, `[-] FAIL:` or `rmasscan: error:`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectRefusal {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<String>,
}

/// The `--iflist` line of the stand NIC: it starts with `name` and carries `mac=<mac>` (the CLI's form, or
/// `masked` where Darwin hides it from the user).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectIflist {
    pub name: String,
    pub mac: String,
}

/// What the `--offline` preflight must show for the live case to run: the stand NIC as the detected interface,
/// or the exact refusal text (exit 1).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectPreflight {
    Interface(String),
    Refusal(String),
}

/// `expect.json`: the case as the suite planned it. The parts the brief pins per tag (kind, preflight, the
/// `--iflist` line, the stand's addresses) are checked against this module's own tables.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectRecord {
    pub tag: String,
    pub kind: CaseKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection: Option<ExpectDetection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<ExpectRefusal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iflist: Option<ExpectIflist>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight: Option<ExpectPreflight>,
}

/// `iflist.json`: the `--iflist` output reduced on the spot (the full listing is an inventory of the host and is
/// never stored): exit code, line count, sha256 of the whole output, and the one line of the stand NIC (`None`
/// when it was not in the output). The oracle's record has no `stand_line`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IflistRecord {
    pub rc: i32,
    pub lines: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stand_line: Option<String>,
}

/// The fields of a `capture dump` record (`capture.json`, `oracle-capture.json`) this verifier reads: the
/// witness's own completeness verdict (markers, quiet, drops, counter window) and the identity of its pcap.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PeerWitness {
    pub valid: bool,
    pub pcap_sha256: String,
    pub pcap_frames: u64,
    pub invalid_reasons: Vec<String>,
}

// ------------------------------------------------------------------ stands and plans

/// The scanner's own address on every stand.
pub const SCANNER_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const LINUX_SCANNER_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 1];
const LINUX_PEER_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 2];
const MACOS_SCANNER_MAC: [u8; 6] = [0x02, 0xac, 0, 0, 0, 1];
const MACOS_PEER_MAC: [u8; 6] = [0x02, 0xac, 0, 0, 0, 2];
/// `windows_suite::MAC` (a test keeps the two equal).
const WINDOWS_SCANNER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x04, 0x80, 0xa9];
const WINDOWS_PEER_MAC: [u8; 6] = [0x02, 0x57, 0x4c, 0x3d, 0x2e, 0x9b];
/// The fake next hop of `--offline` and the MAC of the `--source-mac` hint.
const CLI_MACS: [[u8; 6]; 2] = [
    [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
    [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
];
/// The interface names evidence may carry: the three stands' NICs, loopback, and the adapter `l10` asks for.
const STAND_NAMES: [&str; 9] = [
    "veth-a",
    "veth-b",
    "feth4201",
    "feth4202",
    "Ethernet 2",
    crate::windows_suite::IFACE,
    "lo",
    "lo0",
    "nosuch0",
];
/// The addresses rmasscan's fixed refusal and hint texts name (documentation and reserved prefixes).
const HINT_IPV4: [Ipv4Addr; 5] = [
    Ipv4Addr::new(192, 0, 2, 1),
    Ipv4Addr::new(198, 51, 100, 17),
    Ipv4Addr::new(0, 0, 0, 0),
    Ipv4Addr::new(127, 0, 0, 0),
    Ipv4Addr::new(224, 0, 0, 0),
];
/// A scanner ARP request repeats every 1 s; one step may be off by this much.
const ARP_STEP_S: (f64, f64) = (0.7, 1.3);
/// The resolver's request budget: the ARP timeout sends exactly this many.
const ARP_REQUESTS: usize = 10;

/// The sealed stand of a plan (the brief's constants).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stand {
    /// The scanner NIC as rmasscan prints and lists it.
    pub iface: &'static str,
    pub scanner_ip: Ipv4Addr,
    pub scanner_mac: [u8; 6],
    /// The MAC of every next hop on the stand (the peer answers for all its addresses).
    pub peer_mac: [u8; 6],
    pub peer_ips: Vec<Ipv4Addr>,
    /// Ports the peer answers with a SYN-ACK; every other scanned port is closed.
    pub open_ports: Vec<u16>,
}

pub fn stand(plan: Plan) -> Stand {
    let ip = |o| Ipv4Addr::new(198, 18, 0, o);
    match plan {
        Plan::Linux => Stand {
            iface: "veth-a",
            scanner_ip: SCANNER_IP,
            scanner_mac: LINUX_SCANNER_MAC,
            peer_mac: LINUX_PEER_MAC,
            peer_ips: (2..=5).map(ip).collect(),
            open_ports: vec![80, 8080],
        },
        Plan::Macos | Plan::MacosRoot => Stand {
            iface: "feth4201",
            scanner_ip: SCANNER_IP,
            scanner_mac: MACOS_SCANNER_MAC,
            peer_mac: MACOS_PEER_MAC,
            peer_ips: vec![ip(2)],
            open_ports: (8000..=8007).collect(),
        },
        Plan::Windows => Stand {
            iface: "Ethernet 2",
            scanner_ip: SCANNER_IP,
            scanner_mac: WINDOWS_SCANNER_MAC,
            peer_mac: WINDOWS_PEER_MAC,
            peer_ips: vec![ip(2)],
            open_ports: [80, 443].into_iter().chain(8000..=8007).collect(),
        },
    }
}

const LINUX_TAGS: [&str; 12] = [
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
];
const MACOS_TAGS: [&str; 7] = [
    "m01_user_masked",
    "m02_user_explicit",
    "m03_user_router_mac",
    "m04_user_arp_timeout",
    "m05_user_no_adapter",
    "m06_user_no_ip",
    "m07_user_iflist",
];
const MACOS_ROOT_TAGS: [&str; 2] = ["m10_root_auto_mac", "m11_root_iflist"];
const WINDOWS_TAGS: [&str; 9] = [
    "w01_auto",
    "w02_adapter_npf",
    "w03_adapter_friendly",
    "w04_router_mac",
    "w05_arp_timeout",
    "w06_multi_no_gateway",
    "w07_iflist",
    "w08a_restricted_iflist",
    "w08b_restricted_scan",
];

/// Every case a plan must hold; a missing one is NOT RUN, so a partial (`--only`) directory never passes.
pub fn planned_tags(plan: Plan) -> &'static [&'static str] {
    match plan {
        Plan::Linux => &LINUX_TAGS,
        Plan::Macos => &MACOS_TAGS,
        Plan::MacosRoot => &MACOS_ROOT_TAGS,
        Plan::Windows => &WINDOWS_TAGS,
    }
}

/// The kind of a planned case (`None`: not a case of any plan).
pub fn case_kind(tag: &str) -> Option<CaseKind> {
    let all = LINUX_TAGS
        .iter()
        .chain(&MACOS_TAGS)
        .chain(&MACOS_ROOT_TAGS)
        .chain(&WINDOWS_TAGS);
    if !all.clone().any(|t| *t == tag) {
        return None;
    }
    Some(match tag {
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
    })
}

/// The preflight a case needs before it may run (R1): `w01` and `w06` must detect the stand NIC, `m05` must be
/// refused because its target is an address of this host.
pub fn preflight_expectation(tag: &str) -> Option<ExpectPreflight> {
    match tag {
        "w01_auto" | "w06_multi_no_gateway" => {
            Some(ExpectPreflight::Interface("Ethernet 2".into()))
        }
        "m05_user_no_adapter" => Some(ExpectPreflight::Refusal(
            "198.18.0.2 is an address of this host (route via lo0)".into(),
        )),
        _ => None,
    }
}

/// The `--iflist` line a case must find: the stand NIC with its MAC, masked only in the user's macOS window.
fn pinned_iflist(plan: Plan, tag: &str) -> ExpectIflist {
    let st = stand(plan);
    ExpectIflist {
        name: st.iface.into(),
        mac: if tag == "m07_user_iflist" {
            "masked".into()
        } else {
            dash(st.scanner_mac)
        },
    }
}

fn dash(m: [u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("-")
}
fn colon(m: [u8; 6]) -> String {
    dash(m).replace('-', ":")
}

// ------------------------------------------------------------------ argv

/// The options of `argv.json` the verifier models (the subset the suites use; anything else is refused, not
/// guessed). Repeatable options keep every value.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Args {
    pub targets: Vec<String>,
    pub ports: Vec<String>,
    pub exclude: Vec<String>,
    pub seed: Option<String>,
    pub rate: Option<String>,
    pub wait: Option<String>,
    pub source_port: Option<String>,
    pub adapter: Option<String>,
    pub adapter_ip: Option<String>,
    pub adapter_mac: Option<String>,
    pub router_ip: Option<String>,
    pub router_mac: Option<String>,
    pub iflist: bool,
    pub offline: bool,
}

/// Parses an rmasscan argv the way the CLI reads it: positional targets, `-pSPEC`/`-p SPEC`/`--ports`, `-e`,
/// `--opt value` and `--opt=value`, the aliases `--interface`, `--source-ip`, `--source-mac`, `--adapter-port`.
pub fn parse_argv(argv: &[String]) -> Result<Args, String> {
    fn once(slot: &mut Option<String>, key: &str, v: String) -> Result<(), String> {
        if slot.replace(v).is_some() {
            return Err(format!("{key} given twice"));
        }
        Ok(())
    }
    let mut a = Args::default();
    let mut i = 0;
    while i < argv.len() {
        let x = argv[i].as_str();
        i += 1;
        if !x.starts_with('-') {
            a.targets.push(x.to_owned());
            continue;
        }
        if x == "--iflist" || x == "--offline" {
            let f = if x == "--iflist" {
                &mut a.iflist
            } else {
                &mut a.offline
            };
            if std::mem::replace(f, true) {
                return Err(format!("{x} given twice"));
            }
            continue;
        }
        let long = x.starts_with("--");
        let (key, inline) = match (x, long) {
            ("-p", _) => ("--ports", None),
            ("-e", _) => ("--interface", None),
            (_, false) if x.starts_with("-p") => ("--ports", Some(x[2..].to_owned())),
            (_, false) if x.starts_with("-e") => ("--interface", Some(x[2..].to_owned())),
            (_, true) => match x.split_once('=') {
                Some((k, v)) => (k, Some(v.to_owned())),
                None => (x, None),
            },
            _ => return Err(format!("{x} is not an option the verifier models")),
        };
        let v = match inline {
            Some(v) => v,
            None => {
                let v = argv.get(i).ok_or_else(|| format!("{x} needs a value"))?;
                i += 1;
                v.clone()
            }
        };
        match key {
            "--ports" => a.ports.push(v),
            "--range" => a.targets.push(v),
            "--exclude" => a.exclude.push(v),
            "--seed" => once(&mut a.seed, key, v)?,
            "--rate" => once(&mut a.rate, key, v)?,
            "--wait" => once(&mut a.wait, key, v)?,
            "--source-port" | "--adapter-port" => once(&mut a.source_port, key, v)?,
            "--interface" | "--adapter" => once(&mut a.adapter, key, v)?,
            "--adapter-ip" | "--source-ip" => once(&mut a.adapter_ip, key, v)?,
            "--adapter-mac" | "--source-mac" => once(&mut a.adapter_mac, key, v)?,
            "--router-ip" => once(&mut a.router_ip, key, v)?,
            "--router-mac" => once(&mut a.router_mac, key, v)?,
            _ => return Err(format!("{x} is not an option the verifier models")),
        }
    }
    Ok(a)
}

/// The `wire_scan` argument map (`verify::plan_frames`'s form) of a live run: targets, ports and excludes from
/// `argv.json`, the binding (`--iface`, `--src-ip`, `--src-mac`, `--router-mac`) and the values rmasscan chose
/// (`--seed`, `--source-port`) from its `[+]` lines. `--rate` and `--wait` enter the plan as well (the rate shapes
/// the probe order); without them in argv they are the CLI's defaults.
pub fn plan_args_from(
    argv: &ArgvRecord,
    det: &DetectedRecord,
) -> Result<BTreeMap<String, Value>, String> {
    let a = parse_argv(&argv.argv)?;
    if a.iflist || a.offline {
        return Err("an --iflist or --offline run has no scan plan".into());
    }
    if a.targets.is_empty() || a.ports.is_empty() {
        return Err("argv.json names no target or no port".into());
    }
    let value = |x: &Option<Sourced>, k: &str| {
        x.as_ref()
            .map(|v| v.value.clone())
            .ok_or_else(|| format!("no [+] {k} line"))
    };
    let router_mac = det
        .router_mac
        .as_ref()
        .filter(|m| m.source != "offline")
        .map(|m| m.value.clone())
        .ok_or("no [+] router-mac line of a live run")?;
    let defaults = ScanConfig::default();
    let mut m = BTreeMap::new();
    for (k, v) in [
        ("--iface", value(&det.interface, "interface")?),
        ("--src-ip", value(&det.source_ip, "source-ip")?),
        ("--src-mac", value(&det.source_mac, "source-mac")?),
        ("--router-mac", router_mac),
        ("--targets", a.targets.join(",")),
        ("--ports", a.ports.join(",")),
        ("--seed", value(&det.seed, "seed")?),
        ("--source-port", value(&det.source_port, "source-port")?),
        (
            "--rate",
            a.rate.unwrap_or_else(|| defaults.max_rate.to_string()),
        ),
        (
            "--wait",
            a.wait.unwrap_or_else(|| defaults.wait_secs.to_string()),
        ),
    ] {
        m.insert(k.to_owned(), Value::String(v));
    }
    if !a.exclude.is_empty() {
        m.insert("--exclude".into(), Value::String(a.exclude.join(",")));
    }
    Ok(m)
}

// ------------------------------------------------------------------ rmasscan's own lines

const PLUS_KEYS: [&str; 8] = [
    "interface",
    "source-mac",
    "source-ip",
    "router-ip",
    "router-mac",
    "seed",
    "source-port",
    "finished",
];

fn is_dash_mac(v: &str) -> bool {
    v.len() == 17
        && v.bytes().enumerate().all(|(i, b)| {
            if i % 3 == 2 {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn is_ipv4(v: &str) -> bool {
    v.parse::<Ipv4Addr>().is_ok()
}
fn port_range(v: &str) -> Option<(u16, u16)> {
    match v.split_once('-') {
        Some((a, b)) => Some((a.parse().ok()?, b.parse().ok()?)),
        None => v.parse().ok().map(|p| (p, p)),
    }
}
/// `VALUE (SOURCE)` split at the last ` (`.
fn value_source(body: &str) -> Result<(&str, &str), String> {
    body.strip_suffix(')')
        .and_then(|b| b.rsplit_once(" ("))
        .filter(|(v, _)| !v.is_empty())
        .ok_or_else(|| "no (source)".into())
}

fn plus_line(d: &mut DetectedRecord, key: &str, body: &str) -> Result<(), String> {
    if key == "finished" {
        let num = |x: &str| x.parse::<u64>().map_err(|e| e.to_string());
        let (rest, open) = body.rsplit_once(", open ").ok_or("no open count")?;
        let (rest, replies) = rest.rsplit_once(", replies ").ok_or("no reply count")?;
        let (reason, sent) = rest.rsplit_once(", sent ").ok_or("no sent count")?;
        d.finished = Some(Finished {
            reason: reason.to_owned(),
            sent: num(sent)?,
            replies: num(replies)?,
            open: num(open)?,
        });
        return Ok(());
    }
    let (v, src) = value_source(body)?;
    let line = Sourced {
        value: v.to_owned(),
        source: src.to_owned(),
    };
    let ok = match key {
        "interface" => {
            src == "given"
                || (src == "offline" && v == "none")
                || src.strip_prefix("detected: route to ").is_some_and(is_ipv4)
        }
        "source-mac" => is_dash_mac(v) && matches!(src, "given" | "detected"),
        "source-ip" => is_ipv4(v) && matches!(src, "given" | "detected"),
        "router-ip" => {
            (is_ipv4(v)
                && matches!(
                    src,
                    "route gateway" | "on-link target" | "interface default gateway" | "given"
                ))
                || (v == "none" && src == "offline")
        }
        "router-mac" => {
            if !is_dash_mac(v) {
                false
            } else if let Some(a) = src.strip_prefix("arp: ") {
                let (n, ms) = a
                    .strip_suffix(" ms")
                    .and_then(|a| a.split_once(" requests, "))
                    .ok_or("malformed arp count")?;
                d.router_mac = Some(RouterMac {
                    value: v.to_owned(),
                    source: "arp".into(),
                    arp: Some(ArpCount {
                        requests: n.parse().map_err(|_| "malformed arp count")?,
                        ms: ms.parse().map_err(|_| "malformed arp time")?,
                    }),
                });
                return Ok(());
            } else {
                matches!(src, "given" | "offline")
            }
        }
        "seed" => v.parse::<u64>().is_ok() && matches!(src, "given" | "entropy"),
        _ => port_range(v).is_some() && matches!(src, "given" | "time"),
    };
    if !ok {
        return Err(format!("{key} = {v} ({src}) is not a form rmasscan prints"));
    }
    match key {
        "interface" => d.interface = Some(line),
        "source-mac" => d.source_mac = Some(line),
        "source-ip" => d.source_ip = Some(line),
        "router-ip" => d.router_ip = Some(line),
        "router-mac" => {
            d.router_mac = Some(RouterMac {
                value: line.value,
                source: line.source,
                arp: None,
            })
        }
        "seed" => d.seed = Some(line),
        _ => d.source_port = Some(line),
    }
    Ok(())
}

/// Parses rmasscan's stderr: the `[+]` lines in the CLI's order (each at most once), then at most one refusal
/// (`[-] FAIL: …` or `rmasscan: error: …`) and its hint lines. Any other line, a value in a form the CLI does not
/// print, or a line out of order is an error. A leading BOM and `\r` line ends (the Windows guest) are tolerated.
pub fn parse_stderr(text: &str) -> Result<DetectedRecord, String> {
    let mut d = DetectedRecord::default();
    let mut next = 0;
    for raw in text.trim_start_matches('\u{feff}').split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        let refused = d.fail.is_some() || d.error.is_some();
        if let Some(rest) = line.strip_prefix("[+] ") {
            if refused {
                return Err(format!("a [+] line after the refusal: {line:?}"));
            }
            let (key, body) = match rest.strip_prefix("finished: ") {
                Some(b) => ("finished", b),
                None => rest
                    .split_once(" = ")
                    .ok_or_else(|| format!("malformed [+] line {line:?}"))?,
            };
            let at = PLUS_KEYS
                .iter()
                .position(|k| *k == key)
                .ok_or_else(|| format!("unknown [+] line {line:?}"))?;
            if at < next {
                return Err(format!("[+] {key} repeated or out of order"));
            }
            next = at + 1;
            plus_line(&mut d, key, body).map_err(|e| format!("{line:?}: {e}"))?;
        } else if let Some(rest) = line.strip_prefix("[-] FAIL: ") {
            if refused {
                return Err(format!("a second refusal: {line:?}"));
            }
            d.fail = Some(rest.to_owned());
        } else if let Some(rest) = line.strip_prefix("rmasscan: error: ") {
            if refused {
                return Err(format!("a second refusal: {line:?}"));
            }
            d.error = Some(rest.to_owned());
        } else if line.starts_with("    [hint] ") || line.starts_with(" [hint] ") {
            if !refused {
                return Err(format!("a hint without a refusal: {line:?}"));
            }
            d.hints.push(line.to_owned());
        } else {
            return Err(format!("not a line rmasscan prints: {line:?}"));
        }
    }
    Ok(d)
}

/// `preflight.txt`: `rc N`, then the stderr of the `--offline` run.
pub fn parse_preflight(text: &str) -> Result<(i32, DetectedRecord), String> {
    let t = text.trim_start_matches('\u{feff}');
    let (first, rest) = t.split_once('\n').unwrap_or((t, ""));
    let rc = first
        .trim_end_matches('\r')
        .strip_prefix("rc ")
        .and_then(|n| n.trim().parse().ok())
        .ok_or("the first line is not `rc N`")?;
    Ok((rc, parse_stderr(rest)?))
}

/// The CLI's result line (`output.c:781-795`): `Discovered open port P/tcp on IP`, spaces to 79 characters, `\n`.
pub fn discovered_line(ip: Ipv4Addr, port: u16) -> String {
    format!(
        "{:<79}\n",
        format!("Discovered open port {port}/tcp on {ip}")
    )
}
/// The lines of a stdout file; empty, or exactly `"\n"` (the guest runner's empty output), has none.
fn stdout_lines(text: &str) -> Vec<&str> {
    let t = text.strip_prefix('\u{feff}').unwrap_or(text);
    if t.is_empty() || t == "\n" {
        return Vec::new();
    }
    t.split_inclusive('\n').collect()
}
/// `(ip, port)` of a Discovered line, whatever its padding.
fn discovered(line: &str) -> Option<(Ipv4Addr, u16)> {
    let head = line
        .strip_prefix("Discovered open port ")?
        .trim_end_matches('\n')
        .trim_end_matches(' ');
    let (port, ip) = head.split_once("/tcp on ")?;
    Some((ip.parse().ok()?, port.parse().ok()?))
}
fn parse_exit(text: &str) -> Option<i32> {
    text.trim_start_matches('\u{feff}').trim().parse().ok()
}

// ------------------------------------------------------------------ privacy

/// The text of a file the scanner produced: its addresses must be the stand's or the CLI's fixed examples.
const SCANNER_TEXT: [&str; 10] = [
    "stdout.txt",
    "stderr.txt",
    "guest-stdout.txt",
    "guest-stderr.txt",
    PREFLIGHT_TXT,
    ARGV_JSON,
    EXPECT_JSON,
    DETECTED_JSON,
    IFLIST_JSON,
    ORACLE_IFLIST_JSON,
];
const TEXT_EXTENSIONS: [&str; 6] = ["json", "txt", "err", "log", "md", "sha256"];
/// Last labels of local host names (mDNS, home routers, private zones).
const HOST_SUFFIXES: [&str; 7] = [
    "local",
    "lan",
    "home",
    "localdomain",
    "internal",
    "arpa",
    "box",
];

fn stand_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    (o[0], o[1], o[2]) == (198, 18, 0) || HINT_IPV4.contains(&ip)
}
/// Addresses that identify nobody: private, shared (carrier NAT), loopback, link-local, multicast, broadcast,
/// documentation, the benchmark /15, the `8.8.8.8` route probe of the isolation record.
fn anonymous_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    stand_ipv4(ip)
        || ip.is_private()
        || (o[0] == 100 && o[1] & 0xc0 == 64)
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || o[0] == 0
        || (o[0] == 198 && o[1] & 0xfe == 18)
        || ip == Ipv4Addr::new(8, 8, 8, 8)
}
fn allowed_mac(m: [u8; 6]) -> bool {
    [
        LINUX_SCANNER_MAC,
        LINUX_PEER_MAC,
        MACOS_SCANNER_MAC,
        MACOS_PEER_MAC,
        WINDOWS_SCANNER_MAC,
        WINDOWS_PEER_MAC,
        [0xff; 6],
        [0; 6],
    ]
    .contains(&m)
        || CLI_MACS.contains(&m)
}
fn ipv4_tokens(text: &str) -> Vec<Ipv4Addr> {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .filter_map(|run| {
            let run = run.trim_matches('.');
            let parts: Vec<&str> = run.split('.').collect();
            (parts.len() == 4 && parts.iter().all(|p| (1..=3).contains(&p.len())))
                .then(|| run.parse().ok())
                .flatten()
        })
        .collect()
}
/// Six two-digit hex groups in a row (`:` or `-` between them).
fn mac_tokens(text: &str) -> Vec<[u8; 6]> {
    let mut out = Vec::new();
    for run in text.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '-')) {
        let groups: Vec<&str> = run.split([':', '-']).collect();
        for w in groups.windows(6) {
            if w.iter().all(|g| g.len() == 2) {
                let mut m = [0u8; 6];
                for (b, g) in m.iter_mut().zip(w) {
                    *b = u8::from_str_radix(g, 16).unwrap_or_default();
                }
                out.push(m);
            }
        }
    }
    out
}
fn host_tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
        .filter(|t| {
            let l = t.to_ascii_lowercase();
            let l = l.trim_end_matches('.');
            l.contains("_tcp")
                || l.contains("_udp")
                || (l.contains('.')
                    && l.rsplit('.')
                        .next()
                        .is_some_and(|last| HOST_SUFFIXES.contains(&last)))
        })
        .map(str::to_owned)
        .collect()
}
/// `/Users/NAME`, `/home/NAME`, `\Users\NAME` with a name other than the guest's lab account or a scrubbed `$VAR`.
fn home_paths(text: &str) -> Vec<String> {
    let norm = text.replace("\\\\", "\\");
    let lower = norm.to_ascii_lowercase();
    let mut out = Vec::new();
    for lead in ["/users/", "/home/", "\\users\\"] {
        for (i, _) in lower.match_indices(lead) {
            let rest = &norm[i + lead.len()..];
            let seg: String = rest
                .chars()
                .take_while(|c| {
                    !matches!(
                        c,
                        '/' | '\\' | '"' | '\'' | ' ' | '\n' | ',' | ';' | ':' | ')'
                    )
                })
                .collect();
            if !seg.is_empty() && !seg.starts_with('$') && !seg.eq_ignore_ascii_case("lab") {
                out.push(format!("{}{seg}", &norm[i..i + lead.len()]));
            }
        }
    }
    out
}
/// Lines of the `--iflist` form (`NAME index=N mac=…`) in a text.
fn iflist_entries(text: &str) -> usize {
    text.match_indices(" index=")
        .filter(|(i, _)| {
            let rest = &text[i + 7..];
            let digits = rest.chars().take_while(char::is_ascii_digit).count();
            digits > 0 && rest[digits..].starts_with(" mac=")
        })
        .count()
}
fn token_problems(text: &str, scanner_text: bool) -> Vec<String> {
    let mut p = Vec::new();
    for ip in ipv4_tokens(text) {
        if !(stand_ipv4(ip) || (!scanner_text && anonymous_ipv4(ip))) {
            p.push(format!("address {ip}"));
        }
    }
    p.extend(
        mac_tokens(text)
            .into_iter()
            .filter(|m| !allowed_mac(*m))
            .map(|m| format!("MAC {}", colon(m))),
    );
    p.extend(
        host_tokens(text)
            .into_iter()
            .map(|h| format!("host name {h}")),
    );
    p.extend(
        home_paths(text)
            .into_iter()
            .map(|h| format!("personal path {h}")),
    );
    let n = iflist_entries(text);
    if n >= 2 {
        p.push(format!("an --iflist listing ({n} interface lines)"));
    }
    p
}
/// The interface names a refusal or error line carries: quoted values, the name after `via `, after `for router `.
fn refusal_names(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect();
    for (i, _) in text.match_indices("via ") {
        let rest = &text[i + 4..];
        let end = rest.find([',', ')', '"']).unwrap_or(rest.len());
        out.push(rest[..end].trim().to_owned());
    }
    for lead in ["for router ", "for next hop (target) "] {
        if let Some(i) = text.find(lead) {
            let rest = &text[i + lead.len()..];
            if let Some(end) = rest.find(": \"") {
                out.push(rest[..end].to_owned());
            }
        }
    }
    out
}
fn name_problems(names: impl IntoIterator<Item = String>) -> Vec<String> {
    names
        .into_iter()
        .filter(|n| !STAND_NAMES.contains(&n.as_str()) && !n.parse().is_ok_and(stand_ipv4))
        .map(|n| format!("name {n:?}"))
        .collect()
}
/// Line forms and interface names of the files the scanner wrote.
fn output_problems(rel: &str, text: &str) -> Vec<String> {
    let stderr_lines = |t: &str| -> Vec<String> {
        let mut p = Vec::new();
        for raw in t.trim_start_matches('\u{feff}').lines() {
            let line = raw.trim_end_matches('\r');
            if line.is_empty() || line.starts_with("    [hint] ") || line.starts_with(" [hint] ") {
                continue;
            }
            if let Some(rest) = line.strip_prefix("[+] interface = ") {
                match value_source(rest) {
                    Ok(("none", "offline")) => {}
                    Ok((v, _)) => p.extend(name_problems([v.to_owned()])),
                    Err(_) => p.push(format!("not a line rmasscan prints: {line:?}")),
                }
            } else if line.starts_with("[+] ") {
            } else if let Some(rest) = line
                .strip_prefix("[-] FAIL: ")
                .or_else(|| line.strip_prefix("rmasscan: error: "))
            {
                p.extend(name_problems(refusal_names(rest)));
            } else {
                p.push(format!("not a line rmasscan prints: {line:?}"));
            }
        }
        p
    };
    match rel {
        "stderr.txt" | "guest-stderr.txt" => stderr_lines(text),
        PREFLIGHT_TXT => stderr_lines(text.split_once('\n').map_or("", |(_, r)| r)),
        "stdout.txt" | "guest-stdout.txt" => stdout_lines(text)
            .into_iter()
            .filter(|l| l.trim() != "" && !l.starts_with("Discovered open port "))
            .map(|l| format!("not a Discovered line: {:?}", l.trim_end()))
            .collect(),
        ARGV_JSON => serde_json::from_str::<ArgvRecord>(text)
            .ok()
            .and_then(|a| parse_argv(&a.argv).ok())
            .map_or_else(Vec::new, |a| name_problems(a.adapter)),
        DETECTED_JSON => serde_json::from_str::<DetectedRecord>(text)
            .ok()
            .and_then(|d| d.interface)
            .filter(|i| i.source != "offline")
            .map_or_else(Vec::new, |i| name_problems([i.value])),
        EXPECT_JSON => serde_json::from_str::<ExpectRecord>(text)
            .ok()
            .map_or_else(Vec::new, |x| {
                name_problems(
                    x.detection
                        .map(|d| d.interface.value)
                        .into_iter()
                        .chain(x.iflist.map(|i| i.name)),
                )
            }),
        IFLIST_JSON | ORACLE_IFLIST_JSON => serde_json::from_str::<IflistRecord>(text)
            .ok()
            .and_then(|r| r.stand_line)
            .map_or_else(Vec::new, |l| {
                name_problems([l.split(" index=").next().unwrap_or("").to_owned()])
            }),
        _ => Vec::new(),
    }
}

/// One INVALID check per text file that names something outside the allowlist, or one PASS check for all.
fn privacy(r: &mut Run, d: &Path, files: &[String]) {
    let mut clean = true;
    let mut seen = 0;
    for rel in files {
        let ext = Path::new(rel)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        if !TEXT_EXTENSIONS.contains(&ext) {
            continue;
        }
        let Ok(bytes) = fs::read(d.join(rel)) else {
            continue;
        };
        seen += 1;
        let text = String::from_utf8_lossy(&bytes);
        let mut p = token_problems(&text, SCANNER_TEXT.contains(&rel.as_str()));
        p.extend(output_problems(rel, &text));
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
            "privacy: every text file holds only allowlisted names, addresses and paths",
            PASS,
            format!("{seen} files"),
            false,
        );
    }
}

// ------------------------------------------------------------------ the wire

fn is_marker(f: &[u8], payload: &[u8]) -> bool {
    f.get(12..14) == Some(&MARKER_ETHERTYPE[..])
        && f.get(14..).is_some_and(|b| b.starts_with(payload))
}

/// The frames of one capture, sorted by who sent them.
#[derive(Default)]
struct Wire {
    starts: Vec<f64>,
    ends: Vec<f64>,
    /// ARP requests from the scanner MAC, exactly 60 bytes with zero padding (N5).
    scanner_arp: Vec<(f64, Vec<u8>)>,
    /// 42-byte ARP requests from the scanner MAC: the scanner host's kernel.
    os_requests: usize,
    /// ARP replies from the scanner MAC: the scanner host's kernel (the Windows guest answers `who-has .1`).
    os_replies: usize,
    /// Any other ARP frame from the scanner MAC (neither form above).
    odd_arp: usize,
    /// TCP SYNs from the scanner MAC.
    syns: Vec<(f64, Vec<u8>)>,
    /// Resets of the scanner host's kernel (half-open connections the scan provoked).
    rst_from_scanner: usize,
}

fn classify(fr: &Frames, mac: [u8; 6]) -> Wire {
    let mut w = Wire::default();
    for (t, f) in fr {
        if is_marker(f, START_PAYLOAD) {
            w.starts.push(*t);
        } else if is_marker(f, END_PAYLOAD) {
            w.ends.push(*t);
        }
        if f.get(6..12) != Some(&mac[..]) {
            continue;
        }
        if f.get(12..14) == Some(&[0x08, 0x06][..]) {
            match decode(f).map(|p| p.op) {
                Ok(ArpOp::Request)
                    if f.len() == ARP_FRAME_LEN && f[42..].iter().all(|b| *b == 0) =>
                {
                    w.scanner_arp.push((*t, f.clone()))
                }
                Ok(ArpOp::Request) if f.len() == 42 => w.os_requests += 1,
                Ok(ArpOp::Reply) => w.os_replies += 1,
                _ => w.odd_arp += 1,
            }
        } else if pcap::is_syn(f) {
            w.syns.push((*t, f.clone()));
        } else if tcp(f).is_some_and(|i| i.flags & 4 != 0) {
            w.rst_from_scanner += 1;
        }
    }
    w
}
/// The capture window of the run: last start marker to first end marker.
fn window(w: &Wire) -> (f64, f64) {
    (
        w.starts.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        w.ends.iter().copied().fold(f64::INFINITY, f64::min),
    )
}
/// SYNs that are not the scanner's (stand MAC and IP) to a peer address of the stand.
fn foreign_syns(fr: &Frames, st: &Stand) -> usize {
    let (sm, src) = (colon(st.scanner_mac), st.scanner_ip.to_string());
    let peers: Vec<String> = st.peer_ips.iter().map(Ipv4Addr::to_string).collect();
    fr.iter()
        .filter(|(_, f)| {
            pcap::is_syn(f)
                && !tcp(f).is_some_and(|i| i.sm == sm && i.src == src && peers.contains(&i.dst))
        })
        .count()
}

// ------------------------------------------------------------------ one run

struct Names {
    stdout: &'static str,
    stderr: &'static str,
    exit: &'static str,
}
fn names(plan: Plan) -> Names {
    if plan == Plan::Windows {
        Names {
            stdout: "guest-stdout.txt",
            stderr: "guest-stderr.txt",
            exit: "guest-exit.txt",
        }
    } else {
        Names {
            stdout: "stdout.txt",
            stderr: "stderr.txt",
            exit: "exit.txt",
        }
    }
}

/// A file the verifier needs: its text, or a NOT RUN check.
fn need(r: &mut Run, d: &Path, name: &str) -> Option<String> {
    let t = fs::read(d.join(name))
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned());
    if t.is_none() {
        r.add(&format!("{name} present"), NOT_RUN, "missing", false);
    }
    t
}
/// A schema file: NOT RUN when missing, INVALID when it does not follow its type.
fn typed<T: DeserializeOwned>(r: &mut Run, d: &Path, name: &str) -> Option<T> {
    let text = need(r, d, name)?;
    match serde_json::from_str(&text) {
        Ok(v) => Some(v),
        Err(e) => {
            r.inv(&format!("{name} follows its schema"), false, e);
            None
        }
    }
}

/// Lab-isolation checks that need nothing but the pcaps: a frame on the uplink (stored, or counted by tcpdump), a
/// SYN that is not the scanner's. They cannot be hidden by any other missing or wrong file.
fn safety(r: &mut Run, plan: Plan, d: &Path, peer: Option<&Frames>, oracle: Option<&Frames>) {
    let st = stand(plan);
    let lan = match plan {
        Plan::Linux => None,
        Plan::Windows => Some(("eno1", "eno1.pcap", "eno1.err")),
        Plan::Macos | Plan::MacosRoot => Some(("uplink", "uplink.pcap", "uplink.err")),
    };
    if let Some((lan, pcap_name, err)) = lan {
        let up = verify::load_pcap(r, &d.join(pcap_name));
        // macOS counts `captured` (its `received by filter` is taken before the filter), Linux hosts `received`.
        let counted = if plan == Plan::Windows {
            verify::eno1_err_received(d)
        } else {
            captured_in(d, err)
        };
        if !d.join(err).exists() {
            r.add(&format!("{err} present"), NOT_RUN, "missing", false);
        } else if counted.is_none() {
            r.inv(&format!("{err} holds tcpdump's statistics"), false, "");
        }
        verify::safety_checks(
            r,
            lan,
            &Value::Null,
            "",
            None,
            up.as_ref().map(|u| &u.0),
            counted,
        );
    }
    for (who, fr) in [("peer", peer), ("oracle", oracle)] {
        if let Some(fr) = fr {
            let n = foreign_syns(fr, &st);
            r.safety(
                &format!("no SYN on the {who} capture from outside the stand binding or to an address off the stand"),
                n == 0,
                n,
            );
        }
    }
}

/// The witness record of a capture and the run window it proves.
fn witness(
    r: &mut Run,
    d: &Path,
    pcap_name: &str,
    meta: &str,
    cap: &(Frames, Vec<u8>),
    st: &Stand,
) {
    let (fr, data) = cap;
    if let Some(w) = typed::<PeerWitness>(r, d, meta) {
        r.inv(
            &format!("{meta}: the witness judged its capture complete"),
            w.valid && w.invalid_reasons.is_empty(),
            format!("valid {}, {:?}", w.valid, w.invalid_reasons),
        );
        r.inv(
            &format!("{meta} describes {pcap_name} (sha256 and frame count)"),
            w.pcap_sha256 == sha(data) && w.pcap_frames == fr.len() as u64,
            format!(
                "{} frames recorded, {} in the file",
                w.pcap_frames,
                fr.len()
            ),
        );
    }
    let w = classify(fr, st.scanner_mac);
    let (start, end) = window(&w);
    let times: Vec<f64> = w
        .scanner_arp
        .iter()
        .chain(&w.syns)
        .map(|(t, _)| *t)
        .collect();
    r.inv(
        &format!(
            "{pcap_name}: a start marker before and three end markers after every scanner frame"
        ),
        !w.starts.is_empty()
            && w.ends.len() >= 3
            && start <= end
            && times.iter().all(|t| (start..=end).contains(t)),
        format!(
            "{} start, {} end markers; window {start} .. {end}",
            w.starts.len(),
            w.ends.len()
        ),
    );
}

/// The evidence gate: hashes, file names and extensions, the stand's own record.
fn gate(r: &mut Run, plan: Plan, d: &Path, files: &[String]) {
    match hashes_match_tree(d, true) {
        Ok(()) => r.add(
            "hashes-before-copy.txt matches every file of the run directory",
            PASS,
            files.len(),
            false,
        ),
        Err(e) => r.add(
            "hashes-before-copy.txt matches every file of the run directory",
            INVALID,
            e,
            false,
        ),
    }
    let odd: Vec<&String> = files
        .iter()
        .filter(|f| {
            !Path::new(f)
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| EVIDENCE_EXTENSIONS.contains(&e))
        })
        .collect();
    r.inv(
        "evidence files carry only the allowed extensions (json pcap txt log err sha256 md)",
        odd.is_empty(),
        format!("{odd:?}"),
    );
    let (other, label) = if plan == Plan::Windows {
        (
            ["stdout.txt", "stderr.txt", "exit.txt"],
            "a Windows run uses the guest file names (no stdout.txt, stderr.txt or exit.txt)",
        )
    } else {
        (
            ["guest-stdout.txt", "guest-stderr.txt", "guest-exit.txt"],
            "a Linux or macOS run uses the plain file names (no guest-*.txt)",
        )
    };
    let present: Vec<&str> = other.into_iter().filter(|n| d.join(n).exists()).collect();
    r.inv(label, present.is_empty(), format!("{present:?}"));
    if plan == Plan::Linux {
        match read_json(d.join("isolation.json")) {
            None => r.add(
                "isolation.json present",
                NOT_RUN,
                "missing or invalid JSON",
                false,
            ),
            Some(v) => r.inv(
                "isolation.json: the sealed autodetect stand (capture isolation --mode autodetect)",
                v["mode"] == "autodetect" && isolation_permits(&v, IsolationMode::Autodetect),
                v["default_route"].to_string(),
            ),
        }
        return;
    }
    for name in ["status-pre.json", "status-post.json"] {
        let Some(v) = read_json(d.join(name)) else {
            r.add(
                &format!("{name} present"),
                NOT_RUN,
                "missing or invalid JSON",
                false,
            );
            continue;
        };
        let ok = v["raw_run_allowed"] == true && !verify::truth(&v["isolation_violations"]);
        let label = format!("{name}: raw_run_allowed true and no isolation violation");
        if name == "status-pre.json" {
            // The stand was not proven before the scanner started: as far as the verdict goes it did not run.
            r.check(&label, ok, v["raw_run_allowed"].to_string(), NOT_RUN, false);
        } else {
            r.inv(&label, ok, v["raw_run_allowed"].to_string());
        }
    }
}

/// Is `expect.json` the case as planned on this stand? Returns the problems.
fn expect_problems(plan: Plan, tag: &str, kind: CaseKind, x: &ExpectRecord) -> Vec<String> {
    let st = stand(plan);
    let mut p = Vec::new();
    let mut need = |ok: bool, what: &str| {
        if !ok {
            p.push(what.to_owned());
        }
    };
    need(x.tag == tag, "tag");
    need(x.kind == kind, "kind");
    need(x.preflight == preflight_expectation(tag), "preflight");
    let fail_text = x.refusal.as_ref().map(|f| f.fail.is_some());
    match kind {
        CaseKind::Scan | CaseKind::Parity => need(
            x.detection.as_ref().is_some_and(|d| d.router_mac.is_some())
                && x.refusal.is_none()
                && x.iflist.is_none(),
            "a scan expects a detection with a router-mac and no refusal",
        ),
        CaseKind::ArpTimeout => need(
            x.detection
                .as_ref()
                .is_some_and(|d| d.router_mac.is_none() && d.router_ip.is_some())
                && fail_text == Some(true)
                && x.iflist.is_none(),
            "an ARP timeout expects the detection up to router-ip and the refusal text",
        ),
        CaseKind::Refusal => need(
            fail_text == Some(tag != "w08b_restricted_scan") && x.iflist.is_none(),
            "a refusal expects its text (any refusal only for w08b)",
        ),
        CaseKind::Iflist => need(
            x.iflist.as_ref() == Some(&pinned_iflist(plan, tag))
                && x.detection.is_none()
                && x.refusal.is_none(),
            "--iflist expects the stand NIC line",
        ),
    }
    if let Some(dx) = &x.detection {
        need(
            dx.interface.value == st.iface
                && dx.source_mac.value == dash(st.scanner_mac)
                && dx.source_ip.value == st.scanner_ip.to_string(),
            "the detection is not the stand's NIC, MAC and address",
        );
        need(
            dx.router_mac.as_ref().is_none_or(|m| {
                m.value == dash(st.peer_mac) && matches!(m.source.as_str(), "arp" | "given")
            }),
            "router-mac is not the stand's next hop",
        );
        need(
            dx.router_ip
                .as_ref()
                .is_none_or(|i| i.value.parse().is_ok_and(stand_ipv4)),
            "router-ip is off the stand",
        );
        if tag == "m10_root_auto_mac" {
            need(
                dx.source_mac.source == "detected",
                "the root case must detect the source MAC",
            );
        }
    }
    p
}

/// Is the argv the kind of run the case is?
fn argv_fits(a: &Args, kind: CaseKind) -> bool {
    if kind == CaseKind::Iflist {
        a == &Args {
            iflist: true,
            ..Args::default()
        }
    } else {
        !a.iflist && !a.offline && !a.targets.is_empty() && !a.ports.is_empty()
    }
}

/// Do the printed sources follow argv (a given value printed as given, the rest detected or chosen)?
fn argv_agreement(a: &Args, det: &DetectedRecord) -> Vec<String> {
    let mut p = Vec::new();
    let mac = |v: &str| parse_mac(v).map(dash).unwrap_or_default();
    let mut given = |what: &str,
                     arg: &Option<String>,
                     line: Option<(&str, &str)>,
                     norm: &dyn Fn(&str) -> String| {
        let Some((value, source)) = line else { return };
        let ok = match arg {
            Some(v) => source == "given" && (what == "interface" || value == norm(v)),
            None => source != "given",
        };
        if !ok {
            p.push(format!("{what} {value} ({source})"));
        }
    };
    let id = |v: &str| v.to_owned();
    let pair = |x: &Option<Sourced>| x.as_ref().map(|l| (l.value.clone(), l.source.clone()));
    let lines = [
        ("interface", &a.adapter, pair(&det.interface)),
        ("source-ip", &a.adapter_ip, pair(&det.source_ip)),
        ("router-ip", &a.router_ip, pair(&det.router_ip)),
        ("seed", &a.seed, pair(&det.seed)),
        ("source-port", &a.source_port, pair(&det.source_port)),
    ];
    for (what, arg, line) in &lines {
        given(
            what,
            arg,
            line.as_ref().map(|(v, s)| (v.as_str(), s.as_str())),
            &id,
        );
    }
    given(
        "source-mac",
        &a.adapter_mac,
        det.source_mac
            .as_ref()
            .map(|l| (l.value.as_str(), l.source.as_str())),
        &mac,
    );
    given(
        "router-mac",
        &a.router_mac,
        det.router_mac
            .as_ref()
            .map(|l| (l.value.as_str(), l.source.as_str())),
        &mac,
    );
    if det
        .seed
        .as_ref()
        .is_some_and(|s| s.source == "entropy" && s.value == "0")
    {
        p.push("an entropy seed of 0".into());
    }
    if let Some(sp) = det.source_port.as_ref().filter(|s| s.source == "time")
        && !port_range(&sp.value).is_some_and(|(a, b)| a == b && (40000..60000).contains(&a))
    {
        p.push(format!(
            "a time source port {} outside 40000 + t % 20000",
            sp.value
        ));
    }
    p
}

/// Everything one judgement needs, read once.
struct Ev<'a> {
    plan: Plan,
    tag: &'a str,
    kind: CaseKind,
    st: Stand,
    n: Names,
    peer: Option<&'a Frames>,
    oracle: Option<&'a Frames>,
    argv: Option<ArgvRecord>,
    args: Option<Args>,
    expect: Option<ExpectRecord>,
    exit: Option<i32>,
    det: Option<DetectedRecord>,
    stdout: Option<String>,
}

fn verify_run(root: &Path, plan: Plan, tag: &str) -> Run {
    let mut r = Run::new(tag);
    let d = root.join("runs").join(tag);
    if !d.is_dir() {
        r.add("run directory present", NOT_RUN, "missing", false);
        return r;
    }
    let Some(kind) = case_kind(tag) else {
        r.add("a planned case", INVALID, tag, false);
        return r;
    };
    let st = stand(plan);
    let n = names(plan);
    // ---- safety: independent of every other file
    r.safety(
        "no compressed capture in the run directory",
        !has_compressed_capture(&d),
        "captures are stored uncompressed; the verifier has no decompression",
    );
    let peer = verify::load_pcap(&mut r, &d.join(PEER_PCAP));
    let oracle = if kind == CaseKind::Parity {
        verify::load_pcap(&mut r, &d.join(ORACLE_PCAP))
    } else {
        None
    };
    safety(
        &mut r,
        plan,
        &d,
        peer.as_ref().map(|p| &p.0),
        oracle.as_ref().map(|p| &p.0),
    );
    // ---- the evidence gate
    let files = relative_files(&d);
    gate(&mut r, plan, &d, &files);
    if let Some(p) = &peer {
        witness(&mut r, &d, PEER_PCAP, CAPTURE_JSON, p, &st);
    }
    if let Some(o) = &oracle {
        witness(&mut r, &d, ORACLE_PCAP, ORACLE_CAPTURE_JSON, o, &st);
    }
    privacy(&mut r, &d, &files);
    // ---- the case definition
    let argv: Option<ArgvRecord> = typed(&mut r, &d, ARGV_JSON);
    let expect: Option<ExpectRecord> = typed(&mut r, &d, EXPECT_JSON);
    let args = match argv.as_ref().map(|a| parse_argv(&a.argv)) {
        Some(Ok(a)) => {
            r.inv(
                "argv.json is the kind of run the case is",
                argv_fits(&a, kind),
                format!("{a:?}"),
            );
            Some(a)
        }
        Some(Err(e)) => {
            r.inv("argv.json holds only options the verifier models", false, e);
            None
        }
        None => None,
    };
    if let Some(x) = &expect {
        let p = expect_problems(plan, tag, kind, x);
        r.inv(
            "expect.json is the case as planned on this stand",
            p.is_empty(),
            p.join("; "),
        );
    }
    r.argv_ok = args.as_ref().is_some_and(|a| argv_fits(a, kind))
        && expect
            .as_ref()
            .is_some_and(|x| expect_problems(plan, tag, kind, x).is_empty());
    // ---- what the scanner wrote
    let exit = need(&mut r, &d, n.exit).and_then(|t| {
        let rc = parse_exit(&t);
        if rc.is_none() {
            r.inv(&format!("{} holds an exit code", n.exit), false, t.trim());
        }
        rc
    });
    let det = need(&mut r, &d, n.stderr).and_then(|t| match parse_stderr(&t) {
        Ok(v) => {
            r.add(
                &format!("{} parses into [+], FAIL, hint and error lines", n.stderr),
                PASS,
                "",
                false,
            );
            Some(v)
        }
        Err(e) => {
            r.inv(
                &format!("{} parses into [+], FAIL, hint and error lines", n.stderr),
                false,
                e,
            );
            None
        }
    });
    if (kind != CaseKind::Iflist || d.join(DETECTED_JSON).exists())
        && let Some(file) = typed::<DetectedRecord>(&mut r, &d, DETECTED_JSON)
    {
        r.inv(
            &format!("detected.json is the parse of {}", n.stderr),
            det.as_ref() == Some(&file),
            "",
        );
    }
    let stdout = if kind == CaseKind::Iflist {
        None
    } else {
        need(&mut r, &d, n.stdout)
    };
    if let Some(want) = preflight_expectation(tag)
        && let Some(t) = need(&mut r, &d, PREFLIGHT_TXT)
    {
        let ok = parse_preflight(&t).is_ok_and(|(rc, p)| match &want {
            ExpectPreflight::Interface(name) => {
                rc == 0 && p.interface.is_some_and(|i| i.value == *name)
            }
            ExpectPreflight::Refusal(text) => rc == 1 && p.fail.as_deref() == Some(text),
        });
        r.check(
            "preflight equals the expected detection of the case",
            ok,
            format!("expected {want:?}"),
            NOT_RUN,
            false,
        );
    }
    let ev = Ev {
        plan,
        tag,
        kind,
        st,
        n,
        peer: peer.as_ref().map(|p| &p.0),
        oracle: oracle.as_ref().map(|p| &p.0),
        argv,
        args,
        expect,
        exit,
        det,
        stdout,
    };
    behaviour(&mut r, &ev, &d);
    r
}

// ------------------------------------------------------------------ behaviour

fn behaviour(r: &mut Run, ev: &Ev, d: &Path) {
    let want = match ev.kind {
        CaseKind::Scan | CaseKind::Parity | CaseKind::Iflist => 0,
        CaseKind::Refusal | CaseKind::ArpTimeout => 1,
    };
    // An exit code that was not read is NOT RUN or INVALID already; it is never judged as behaviour.
    if let Some(rc) = ev.exit {
        r.beh(&format!("{} is {want}", ev.n.exit), rc == want, rc);
    }
    let wire = ev.peer.map(|fr| classify(fr, ev.st.scanner_mac));
    if let Some(w) = &wire {
        r.notes
            .insert("scanner_arp_requests".into(), json!(w.scanner_arp.len()));
        r.notes.insert(
            "os_arp".into(),
            json!({"requests": w.os_requests, "replies": w.os_replies}),
        );
        r.notes
            .insert("rst_from_scanner".into(), json!(w.rst_from_scanner));
        r.inv(
            "no ARP frame from the scanner MAC outside the two known forms (60-byte request, 42-byte OS request or a reply)",
            w.odd_arp == 0,
            w.odd_arp,
        );
        if ev.plan == Plan::Linux {
            r.inv(
                "OS ARP: no 42-byte request from the scanner MAC on the Linux stand (permanent neighbours)",
                w.os_requests == 0,
                w.os_requests,
            );
        }
    }
    let (Some(x), Some(det)) = (&ev.expect, &ev.det) else {
        return;
    };
    if ev.kind == CaseKind::Iflist {
        iflist(r, ev, d, det, wire.as_ref());
        return;
    }
    detection(r, ev, x, det);
    if let Some(a) = &ev.args {
        let p = argv_agreement(a, det);
        r.beh(
            "the printed sources agree with argv (a given value printed as given, the rest detected or chosen)",
            p.is_empty(),
            p.join("; "),
        );
    }
    let Some(w) = &wire else { return };
    match ev.kind {
        CaseKind::Scan | CaseKind::Parity => {
            r.beh(
                "[+] finished: Completed and no refusal",
                det.finished
                    .as_ref()
                    .is_some_and(|f| f.reason == "Completed")
                    && det.fail.is_none()
                    && det.error.is_none(),
                format!("{:?}", det.finished),
            );
            arp(r, ev, det, w);
            syns(r, ev, det, w);
        }
        CaseKind::ArpTimeout => {
            refusal_text(r, ev, x, det);
            arp(r, ev, det, w);
            r.cap(
                "no scanner SYN after an ARP timeout",
                w.syns.is_empty(),
                w.syns.len(),
            );
        }
        _ => {
            refusal_text(r, ev, x, det);
            r.cap(
                "no scanner frame (ARP request or SYN) in a refusal",
                w.scanner_arp.is_empty() && w.syns.is_empty(),
                format!(
                    "{} ARP requests, {} SYNs",
                    w.scanner_arp.len(),
                    w.syns.len()
                ),
            );
        }
    }
    results(r, ev, det, w);
    if ev.kind == CaseKind::Parity {
        parity(r, ev, d, w);
    }
}

fn detection(r: &mut Run, ev: &Ev, x: &ExpectRecord, det: &DetectedRecord) {
    match &x.detection {
        Some(dx) => {
            let mac = det
                .router_mac
                .as_ref()
                .map(|m| (m.value.as_str(), m.source.as_str()));
            let want = dx
                .router_mac
                .as_ref()
                .map(|m| (m.value.as_str(), m.source.as_str()));
            r.beh(
                "[+] detection lines equal expect.json (interface, source MAC and IP, router-ip and its reason, next hop)",
                det.interface.as_ref() == Some(&dx.interface)
                    && det.source_mac.as_ref() == Some(&dx.source_mac)
                    && det.source_ip.as_ref() == Some(&dx.source_ip)
                    && det.router_ip == dx.router_ip
                    && mac == want,
                format!("printed {det:?}"),
            );
        }
        None if x.refusal.as_ref().is_some_and(|f| f.fail.is_some()) => {
            r.beh(
                &format!(
                    "{} has no [+] detection line before this refusal",
                    ev.n.stderr
                ),
                det.interface.is_none()
                    && det.source_mac.is_none()
                    && det.source_ip.is_none()
                    && det.router_ip.is_none()
                    && det.router_mac.is_none(),
                format!("{det:?}"),
            );
        }
        None => {}
    }
}

fn refusal_text(r: &mut Run, ev: &Ev, x: &ExpectRecord, det: &DetectedRecord) {
    let Some(want) = &x.refusal else { return };
    let ok = match &want.fail {
        Some(f) => {
            det.fail.as_deref() == Some(f.as_str())
                && det.hints == want.hints
                && det.error.is_none()
        }
        None => det.fail.is_some() || det.error.is_some(),
    };
    r.beh(
        &format!(
            "{} carries the expected refusal ([-] FAIL: and masscan's hints)",
            ev.n.stderr
        ),
        ok,
        format!("{:?} {:?} {:?}", det.fail, det.error, det.hints),
    );
}

/// The scanner's binding as it printed it.
struct Bound {
    mac: [u8; 6],
    ip: Ipv4Addr,
    router_ip: Option<Ipv4Addr>,
    router_mac: Option<[u8; 6]>,
}
fn bound(det: &DetectedRecord) -> Option<Bound> {
    Some(Bound {
        mac: parse_mac(&det.source_mac.as_ref()?.value).ok()?,
        ip: det.source_ip.as_ref()?.value.parse().ok()?,
        router_ip: det
            .router_ip
            .as_ref()
            .filter(|i| i.source != "offline")
            .and_then(|i| i.value.parse().ok()),
        router_mac: det
            .router_mac
            .as_ref()
            .and_then(|m| parse_mac(&m.value).ok()),
    })
}

/// ARP replies on the wire from `router_ip` to the scanner, with their time and sender MAC.
fn router_replies(fr: &Frames, b: &Bound, router_ip: Ipv4Addr) -> Vec<(f64, [u8; 6])> {
    fr.iter()
        .filter_map(|(t, f)| {
            let p = decode(f).ok()?;
            (p.op == ArpOp::Reply
                && p.eth_src != b.mac
                && p.sender_ip == u32::from(router_ip)
                && p.target_ip == u32::from(b.ip)
                && p.target_mac == b.mac)
                .then_some((*t, p.sender_mac))
        })
        .collect()
}

fn arp(r: &mut Run, ev: &Ev, det: &DetectedRecord, w: &Wire) {
    let Some(b) = bound(det) else {
        r.inv(
            "the [+] lines name the binding (source MAC and IP)",
            false,
            "",
        );
        return;
    };
    let want = b
        .router_ip
        .map(|ip| encode_request(b.mac, u32::from(b.ip), u32::from(ip)));
    let bad = w
        .scanner_arp
        .iter()
        .filter(|(_, f)| want.is_none_or(|e| f[..] != e[..]))
        .count();
    r.cap(
        "every scanner ARP request asks for the router-ip with encode_request's bytes",
        bad == 0,
        format!(
            "{bad} of {} differ (router-ip {:?})",
            w.scanner_arp.len(),
            b.router_ip
        ),
    );
    let n = w.scanner_arp.len();
    let steps_ok = w
        .scanner_arp
        .windows(2)
        .all(|p| (ARP_STEP_S.0..=ARP_STEP_S.1).contains(&(p[1].0 - p[0].0)));
    let steps: Vec<String> = w
        .scanner_arp
        .windows(2)
        .map(|p| format!("{:.3}", p[1].0 - p[0].0))
        .collect();
    let router_given = det.router_mac.as_ref().is_some_and(|m| m.source == "given");
    if router_given {
        r.cap(
            "no scanner ARP request when --router-mac is given",
            n == 0,
            n,
        );
        return;
    }
    if ev.kind == CaseKind::ArpTimeout {
        r.cap(
            "exactly 10 scanner ARP requests, 1 ± 0.3 s apart (ARP timeout)",
            n == ARP_REQUESTS && steps_ok,
            format!("{n} requests, steps {steps:?}"),
        );
        // A reply the resolver ignored would make the timeout the scanner's fault, not the stand's silence.
        let answered = ev
            .peer
            .zip(b.router_ip)
            .map_or(0, |(fr, ip)| router_replies(fr, &b, ip).len());
        r.cap(
            "no ARP reply from the router-ip reached the scanner during the timeout",
            answered == 0,
            answered,
        );
        return;
    }
    r.cap(
        "1 to 10 scanner ARP requests, 1 ± 0.3 s apart, until the reply",
        (1..=ARP_REQUESTS).contains(&n) && steps_ok,
        format!("{n} requests, steps {steps:?}"),
    );
    if n > 1 {
        r.notes.insert(
            "arp_reply_lost".into(),
            json!({"requests": n, "kind": "the resolver asked again before the reply (a lost reply)"}),
        );
    }
    let printed = det
        .router_mac
        .as_ref()
        .and_then(|m| m.arp.as_ref())
        .map(|a| a.requests as usize);
    r.cap(
        "[+] router-mac reports the scanner ARP requests on the wire",
        printed == Some(n),
        format!("printed {printed:?}, wire {n}"),
    );
    let (Some(fr), Some(router_ip), Some(router_mac)) = (ev.peer, b.router_ip, b.router_mac) else {
        return;
    };
    let last = w.scanner_arp.last().map(|(t, _)| *t);
    let reply = last.and_then(|last| {
        router_replies(fr, &b, router_ip)
            .into_iter()
            .find(|(t, m)| *t >= last && *m == router_mac)
            .map(|(t, _)| t)
    });
    let first_syn = w.syns.first().map(|(t, _)| *t);
    r.cap(
        "the peer's ARP reply comes after the scanner's requests and before the first SYN",
        reply.is_some_and(|t| first_syn.is_none_or(|s| t <= s)),
        format!("last request {last:?}, reply {reply:?}, first SYN {first_syn:?}"),
    );
}

fn syns(r: &mut Run, ev: &Ev, det: &DetectedRecord, w: &Wire) {
    let Some(b) = bound(det) else { return };
    let (lo, hi) = det
        .source_port
        .as_ref()
        .and_then(|p| port_range(&p.value))
        .unwrap_or((1, 0));
    let dm = b.router_mac.map(colon).unwrap_or_default();
    let wrong = w
        .syns
        .iter()
        .filter(|(_, f)| {
            !tcp(f).is_some_and(|i| {
                i.dm == dm && i.src == b.ip.to_string() && (lo..=hi).contains(&i.sp)
            })
        })
        .count();
    r.cap(
        "every scanner SYN goes to the router-mac from the source IP and a port of [+] source-port",
        wrong == 0,
        format!("{wrong} of {}", w.syns.len()),
    );
    let act: Vec<Vec<u8>> = w.syns.iter().map(|(_, f)| f.clone()).collect();
    match ev
        .argv
        .as_ref()
        .ok_or_else(|| "argv.json missing".to_owned())
        .and_then(|a| plan_args_from(a, det))
        .and_then(|a| verify::plan_frames(&a))
    {
        Ok(plan) => {
            let (rc, msg) = pcap::compare_streams(&plan, &act);
            r.cap(
                "the scanner SYNs equal the plan of argv.json and the [+] lines, in order, each once",
                rc == 0,
                msg,
            );
        }
        Err(e) => r.inv(
            "the scan plan rebuilds from argv.json and the [+] lines",
            false,
            e,
        ),
    }
    let sent = det.finished.as_ref().map(|f| f.sent);
    r.cap(
        "[+] finished reports sent equal to the scanner SYNs on the wire",
        sent == Some(act.len() as u64),
        format!("printed {sent:?}, wire {}", act.len()),
    );
}

/// `(ip, port)` the peer SYN-ACKed in answer to a scanner SYN inside the run window.
fn synacked(fr: &Frames, w: &Wire, st: &Stand) -> BTreeSet<(String, u16)> {
    let asked: BTreeSet<(String, u16, u16, u32)> = w
        .syns
        .iter()
        .filter_map(|(_, f)| tcp(f))
        .map(|i| (i.dst, i.dp, i.sp, i.seq.wrapping_add(1)))
        .collect();
    let (start, end) = window(w);
    let (sm, src) = (colon(st.scanner_mac), st.scanner_ip.to_string());
    fr.iter()
        .filter(|(t, _)| (start..=end).contains(t))
        .filter_map(|(_, f)| tcp(f))
        .filter(|i| {
            i.flags & 0x12 == 0x12
                && i.dm == sm
                && i.dst == src
                && asked.contains(&(i.src.clone(), i.sp, i.dp, i.ack))
        })
        .map(|i| (i.src, i.sp))
        .collect()
}

fn results(r: &mut Run, ev: &Ev, det: &DetectedRecord, w: &Wire) {
    let Some(text) = &ev.stdout else { return };
    let lines = stdout_lines(text);
    let malformed: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| discovered(l).is_none_or(|(ip, p)| *l != discovered_line(ip, p)))
        .collect();
    r.beh(
        &format!(
            "every {} line is a Discovered line of exactly 80 bytes",
            ev.n.stdout
        ),
        malformed.is_empty(),
        format!("{malformed:?}"),
    );
    let got: Vec<(String, u16)> = lines
        .iter()
        .filter_map(|l| discovered(l))
        .map(|(ip, p)| (ip.to_string(), p))
        .collect();
    let set: BTreeSet<(String, u16)> = got.iter().cloned().collect();
    r.beh(
        &format!("{} has no result twice", ev.n.stdout),
        set.len() == got.len(),
        got.len() - set.len(),
    );
    if let Some(f) = &det.finished {
        r.beh(
            "[+] finished reports open equal to the Discovered lines",
            f.open == got.len() as u64,
            format!("printed {}, lines {}", f.open, got.len()),
        );
    }
    let Some(fr) = ev.peer else { return };
    let want = synacked(fr, w, &ev.st);
    let extra: Vec<_> = set.difference(&want).collect();
    let missing: Vec<_> = want.difference(&set).collect();
    r.cap(
        "the Discovered lines are exactly the ports the peer SYN-ACKed in the run window",
        extra.is_empty() && missing.is_empty(),
        format!("without a SYN-ACK {extra:?}, SYN-ACKed without a line {missing:?}"),
    );
}

fn parity(r: &mut Run, ev: &Ev, d: &Path, w: &Wire) {
    let o_stdout = need(r, d, "oracle/stdout.txt");
    need(r, d, "oracle/stderr.txt");
    let o_exit = need(r, d, "oracle/exit.txt").and_then(|t| parse_exit(&t));
    if let Some(rc) = o_exit {
        r.beh("the oracle exited 0", rc == 0, rc);
    }
    let Some(ofr) = ev.oracle else { return };
    let o = classify(ofr, ev.st.scanner_mac);
    let distinct =
        |w: &Wire| -> BTreeSet<Vec<u8>> { w.scanner_arp.iter().map(|(_, f)| f.clone()).collect() };
    let (mine, theirs) = (distinct(w), distinct(&o));
    r.cap(
        "the oracle's ARP request equals rmasscan's byte for byte",
        mine.len() == 1 && mine == theirs,
        format!(
            "rmasscan {:?}, oracle {:?}",
            mine.iter().map(|f| verify::hex(f)).collect::<Vec<_>>(),
            theirs.iter().map(|f| verify::hex(f)).collect::<Vec<_>>()
        ),
    );
    let exp: Vec<Vec<u8>> = o.syns.iter().map(|(_, f)| f.clone()).collect();
    let act: Vec<Vec<u8>> = w.syns.iter().map(|(_, f)| f.clone()).collect();
    let (rc, msg) = pcap::compare_streams(&exp, &act);
    r.cap(
        "the oracle's SYNs equal rmasscan's in order (compare_streams)",
        rc == 0 && !exp.is_empty(),
        msg,
    );
    if let (Some(os), Some(ms)) = (&o_stdout, &ev.stdout) {
        let set = |t: &str| -> BTreeSet<String> {
            t.split_inclusive('\n')
                .filter(|l| l.starts_with("Discovered "))
                .map(str::to_owned)
                .collect()
        };
        r.beh(
            "the oracle's Discovered lines equal rmasscan's",
            set(os) == set(ms),
            format!("oracle {}, rmasscan {}", set(os).len(), set(ms).len()),
        );
    }
}

fn iflist(r: &mut Run, ev: &Ev, d: &Path, det: &DetectedRecord, w: Option<&Wire>) {
    for name in ["stdout.txt", "guest-stdout.txt"] {
        r.inv(
            &format!("the full --iflist output is not stored ({name} absent)"),
            !d.join(name).exists(),
            "",
        );
    }
    let want = pinned_iflist(ev.plan, ev.tag);
    if let Some(rec) = typed::<IflistRecord>(r, d, IFLIST_JSON) {
        r.beh("--iflist exited 0 (iflist.json rc)", rec.rc == 0, rec.rc);
        r.beh(
            "--iflist listed at least two lines",
            rec.lines >= 2,
            rec.lines,
        );
        r.inv(
            "iflist.json sha256 is a sha256",
            rec.sha256.len() == 64 && rec.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            &rec.sha256,
        );
        r.beh(
            "iflist.json stand line names the stand NIC with its expected MAC",
            rec.stand_line.as_deref().is_some_and(|l| {
                l.starts_with(&format!("{} index=", want.name))
                    && l.contains(&format!(" mac={} ", want.mac))
            }),
            format!(
                "{:?}, expected {} with mac={}",
                rec.stand_line, want.name, want.mac
            ),
        );
        if let Some(rc) = ev.exit {
            r.beh(
                &format!("{} equals the rc of iflist.json", ev.n.exit),
                rc == rec.rc,
                format!("{rc} vs {}", rec.rc),
            );
        }
    }
    r.beh(
        &format!("{} is empty for --iflist", ev.n.stderr),
        *det == DetectedRecord::default(),
        format!("{det:?}"),
    );
    if let Some(w) = w {
        r.cap(
            "no scanner frame (ARP request or SYN) during --iflist",
            w.scanner_arp.is_empty() && w.syns.is_empty(),
            format!(
                "{} ARP requests, {} SYNs",
                w.scanner_arp.len(),
                w.syns.len()
            ),
        );
    }
    if ev.tag == "l12_iflist"
        && let Some(o) = typed::<IflistRecord>(r, d, ORACLE_IFLIST_JSON)
    {
        r.beh(
            "the oracle's --iflist exited 0 and listed at least two lines",
            o.rc == 0 && o.lines >= 2,
            format!("rc {}, lines {}", o.rc, o.lines),
        );
        r.inv(
            "the oracle's iflist.json stores only rc, lines and a sha256",
            o.stand_line.is_none()
                && o.sha256.len() == 64
                && o.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            format!("{o:?}"),
        );
    }
}

// ------------------------------------------------------------------ the directory

/// Lab-isolation findings of every directory the plan does not judge itself (unplanned tags, aborted or discarded
/// runs, work directories): only their captures are read.
fn stray_scan(root: &Path, plan: Option<Plan>, tags: &[&str]) -> Vec<Value> {
    fn dirs(d: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = fs::read_dir(d) else { return };
        for e in rd.flatten() {
            if e.path().is_dir() {
                out.push(e.path());
                dirs(&e.path(), out);
            }
        }
    }
    let mut all = Vec::new();
    dirs(root, &mut all);
    all.sort();
    let planned: Vec<std::path::PathBuf> = tags.iter().map(|t| root.join("runs").join(t)).collect();
    let mut out = Vec::new();
    for d in all {
        if planned.iter().any(|p| d.starts_with(p)) {
            continue;
        }
        let present = |n: &str| d.join(n).exists();
        if !["uplink.pcap", "eno1.pcap", PEER_PCAP, ORACLE_PCAP]
            .iter()
            .any(|n| present(n))
        {
            continue;
        }
        let name = d
            .strip_prefix(root)
            .map_or(String::new(), |p| p.to_string_lossy().into_owned());
        let mut r = Run::new(&name);
        r.argv_ok = true;
        for (lan, pcap_name) in [("uplink", "uplink.pcap"), ("eno1", "eno1.pcap")] {
            if present(pcap_name) {
                let up = verify::load_pcap(&mut r, &d.join(pcap_name));
                verify::safety_checks(
                    &mut r,
                    lan,
                    &Value::Null,
                    "",
                    None,
                    up.as_ref().map(|u| &u.0),
                    None,
                );
            }
        }
        if let Some(plan) = plan {
            for (who, pcap_name) in [("peer", PEER_PCAP), ("oracle", ORACLE_PCAP)] {
                if present(pcap_name)
                    && let Some((fr, _)) = verify::load_pcap(&mut r, &d.join(pcap_name))
                {
                    let n = foreign_syns(&fr, &stand(plan));
                    r.safety(
                        &format!("no SYN on the {who} capture from outside the stand binding or to an address off the stand"),
                        n == 0,
                        n,
                    );
                }
            }
        }
        out.push(r.summary());
    }
    out
}

/// Judge an evidence directory: the manifest, every planned case, and a safety walk of everything else.
pub fn verify_dir(root: &Path) -> Value {
    let mut result = json!({"schema":1,"dir":root.file_name().unwrap_or_default().to_string_lossy(),"runs":[],"groups":[],"discarded":[],"aborted":[]});
    let mut m = Run::new("manifest");
    m.argv_ok = true;
    m.safety(
        "no compressed capture anywhere in the evidence directory",
        !has_compressed_capture(root),
        "captures are stored uncompressed; the verifier has no decompression",
    );
    let plan = read_json(root.join(MANIFEST_JSON))
        .and_then(|v| serde_json::from_value::<Manifest>(v).ok())
        .map(|x| x.autodetect);
    m.check(
        "manifest.json names the autodetect plan (linux, macos, macos-root or windows)",
        plan.is_some(),
        "",
        NOT_RUN,
        false,
    );
    let tags = plan.map_or(&[][..], planned_tags);
    // Every text file outside the planned run directories is evidence too (the verifier's own verdict.json is not).
    let outside: Vec<String> = relative_files(root)
        .into_iter()
        .filter(|f| {
            f != "verdict.json" && !tags.iter().any(|t| f.starts_with(&format!("runs/{t}/")))
        })
        .collect();
    privacy(&mut m, root, &outside);
    let unplanned: Vec<String> = fs::read_dir(root.join("runs"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !tags.contains(&n.as_str()))
        .collect();
    m.inv(
        "runs/ holds only the planned case directories",
        unplanned.is_empty(),
        format!("{unplanned:?}"),
    );
    let mut runs = vec![m.summary()];
    if let Some(plan) = plan {
        runs.extend(tags.iter().map(|t| verify_run(root, plan, t).summary()));
    }
    result["runs"] = json!(runs);
    result["safety_scan"] = json!(stray_scan(root, plan, tags));
    verify::finish(result)
}

/// `autodetect-verify --dir DIR [--out FILE]`: 0 PASS, 1 FAIL, 2 INVALID or NOT RUN.
pub fn run(args: &[String]) -> Result<i32, String> {
    let o = crate::windows_suite::options_for("autodetect-verify", args, &["dir", "out"])?;
    if o.contains_key("help") {
        println!(
            "autodetect-verify --dir DIR [--out FILE]  (exit 0 PASS, 1 FAIL, 2 INVALID or NOT RUN)"
        );
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
#[path = "autodetect_verify_tests.rs"]
mod tests;
