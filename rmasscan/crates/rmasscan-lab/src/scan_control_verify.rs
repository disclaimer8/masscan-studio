//! Offline verifier of the scan-control acceptance on the sealed Linux netns stand (`scan-control-verify`) and the one
//! case table of its suite (`scan-control-suite linux`): design §6.2 (docs/superpowers/specs/2026-11-08-rmasscan-scan-
//! control-design.md), invariants §4.1-§4.6.
//!
//! Six cases, `sc01_shards_union` .. `sc06_dual_veth`. A case is a list of STEPS ([`steps`]): one scanner run each, with
//! its own peer-side capture. The suite writes `argv.json` of every step and `expect.json` of the case from this table
//! and nowhere else; the verifier judges every step against it. Cases with a C equivalent that this stand can run
//! (`sc01`, `sc03`) have an `oracle` step, the pinned C masscan `8e6b3b0` with the same argv; the others are
//! rmasscan-only and say so ([`oracle_note`]): `sc02` (C also pauses, but the late-reply window needs the lab's netem
//! delay and C never ends a live scan on this stand), `sc04` (`--badsum` is a stub in C, TCP options are proven
//! against C by the offline vectors), `sc05` (C never ends a live scan here), `sc06` (the C oracle is not run on the
//! second link).
//!
//! The rules of `autodetect-verify` and `output-verify` hold and their machinery is reused: a missing input is NOT RUN,
//! unproven evidence INVALID, a lab frame off the stand a safety FAIL, and no verdict is ever promoted. The oracle
//! never finishes a live scan on this stand (masscan prints `[-] Passed the wait window but still running, forcing
//! exit...` and exits 0 before `output_destroy`, main.c:1489-1496): an oracle file without its footer is expected
//! with that line on the oracle's stderr (`oracle_forced_exit` in the run's notes) and unproven evidence without it.
//!
//! Layout of an evidence directory: `manifest.json` (key `scan-control`: `linux`), `teardown.json`, `runs/<tag>/` per
//! case ([`planned_tags`]). A case directory holds `expect.json` ([`ScExpect`]), `isolation.json` and
//! `isolation-post.json` (`capture isolation --mode scan-control`), `hashes-before-copy.txt`, and one directory per
//! step: `argv.json`, `stdout.txt stderr.txt exit.txt`, the output file under its neutral name (`output.txt`,
//! `output.json`), `paused.txt` (the scanner's `paused.conf`), `scanner.pcap` (its `--pcap`), the peer witness of
//! each link (`peer.pcap capture.json peer.err`, a second link `peer2.pcap capture2.json peer2.err`), an interrupted
//! step `interrupt.json` ([`ScInterrupt`]), `sc02`'s `netem.json` ([`NetemRecord`]).
use crate::{
    autodetect_verify::{
        self as av, ArgvRecord, EVIDENCE_EXTENSIONS, MANIFEST_JSON, Piece, Plan, SECOND_PEER_MAC,
        SECOND_SCANNER_MAC, Stand,
    },
    capture::{
        IsolationMode, SECOND_ADAPTER_IP, SECOND_PEER_IF, SECOND_SCANNER_IF, isolation_permits,
    },
    macos_verify::{Tree, hashes_match_tree, tree},
    output_verify::{self as ov, Doc, Format, Key, Status},
    pcap::Frames,
    verify::{self, FAIL, INVALID, NOT_RUN, PASS, Run, array, read_json, s, tcp},
};
use rmasscan_core::{
    config::{Operation, ScanConfig, parse_rate, validate},
    massip::MassIp,
    packet::{LinkType, TcpHeaderOptions},
    probe::{AdapterBinding, NicBinding, ReadyPlan},
    scan::Shard,
    targets::{add_target_string, parse_ports},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::Ipv4Addr,
    path::Path,
};

// ------------------------------------------------------------------ the case table

pub const TARGETS: &str = ov::TARGETS;
pub const PORTS: &str = ov::PORTS;
pub const RATE: &str = ov::RATE;
/// `sc02` and `sc06`'s pause/resume scans: 20 ports (80 among them) on four hosts are 80 probes, slow enough that a
/// SIGINT [`PAUSE_AFTER_S`] after the start stops them in the middle and the rest still takes a few seconds.
pub const PAUSE_PORTS: &str = "76-95";
pub const PAUSE_RATE: &str = "10";
pub const PAUSE_WAIT: &str = "2";
pub const PAUSE_AFTER_S: f64 = 3.0;
/// `sc05`: the infinite scan runs ~16 passes of the 12 probes at 100 pps before SIGINT.
pub const INFINITE_AFTER_S: f64 = 2.0;
/// How long a scanner has to exit after SIGINT before SIGKILL.
pub const EXIT_WITHIN_S: f64 = 30.0;
/// `sc02`: the peer delays every reply by this long (netem on its own veth), so the replies to the SYNs sent in the
/// last second before SIGINT arrive inside the `--wait` window. Shorter than [`PAUSE_WAIT`].
pub const NETEM_DELAY_MS: u64 = 1000;
/// The file `paused.conf` is written to (the scanner's working directory) and its neutral name in the evidence.
pub const PAUSED_CONF: &str = "paused.conf";
pub const PAUSED_EVIDENCE: &str = "paused.txt";
/// The scanner's own `--pcap` file.
pub const SCANNER_PCAP: &str = "scanner.pcap";
pub const INTERRUPT_JSON: &str = "interrupt.json";
pub const NETEM_JSON: &str = "netem.json";
pub const EXPECT_JSON: &str = "expect.json";
pub const ISOLATION_JSON: &str = "isolation.json";
pub const ISOLATION_POST_JSON: &str = "isolation-post.json";
/// masscan's forced exit after the wait window (main.c:1489-1496).
pub const FORCED_EXIT: &str = ov::FORCED_EXIT;
/// The peer's witness files of link 0 and 1.
pub const PEER_FILES: [[&str; 3]; 2] = [
    ["peer.pcap", "capture.json", "peer.err"],
    ["peer2.pcap", "capture2.json", "peer2.err"],
];
/// What the `sc06` scanner is told about its two adapters.
const NIC_ARGS: [&str; 12] = [
    "--adapter[0]",
    "veth-a",
    "--adapter[1]",
    "veth-a2",
    "--adapter-ip[1]",
    "198.18.0.6",
    "--adapter-mac[1]",
    "02-aa-00-00-00-03",
    "--router-mac[0]",
    "02-aa-00-00-00-02",
    "--router-mac[1]",
    "02-aa-00-00-00-04",
];

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Who {
    Rmasscan,
    /// The pinned C masscan.
    Oracle,
}

/// One scanner run of a case.
#[derive(Debug, Clone, PartialEq)]
pub struct StepSpec {
    pub name: &'static str,
    pub who: Who,
    pub argv: Vec<String>,
    /// Steps with the same group run in one working directory (a resume finds the `paused.conf` and the output file
    /// of the run before it).
    pub cwd: &'static str,
    /// Links the peer witnesses: 2 for `sc06`.
    pub links: usize,
    /// SIGINT this long after the scanner started; `None` for a scan that runs to its end.
    pub interrupt_after_s: Option<f64>,
    /// The peer's replies are delayed by [`NETEM_DELAY_MS`] during this step.
    pub netem: bool,
    /// `(name in the working directory, name in the evidence)` of what the step leaves.
    pub collect: Vec<(&'static str, &'static str)>,
}
impl StepSpec {
    pub fn output_name(&self) -> Option<&'static str> {
        self.collect
            .iter()
            .map(|c| c.1)
            .find(|n| n.starts_with("output."))
    }
    fn expect(&self) -> ExpectStep {
        ExpectStep {
            name: self.name.into(),
            who: self.who,
            links: self.links,
            interrupt: self.interrupt_after_s.is_some(),
            netem: self.netem,
        }
    }
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| (*p).to_owned()).collect()
}
/// The scan of the stand: targets, `-pPORTS`, the output flags (`-oL`/`-oJ` and a file), `--show open,closed`,
/// `--seed 1 --rate R --wait W`, then `extra`.
fn scan(ports: &str, out: [&str; 2], rate: &str, wait: &str, extra: &[&str]) -> Vec<String> {
    let mut a = vec![TARGETS.to_owned(), format!("-p{ports}")];
    a.extend(argv(&[
        out[0],
        out[1],
        "--show",
        "open,closed",
        "--seed",
        "1",
    ]));
    a.extend(argv(&["--rate", rate, "--wait", wait]));
    a.extend(argv(extra));
    a
}
const LIST: [&str; 2] = ["-oL", "output.txt"];
const JSON: [&str; 2] = ["-oJ", "output.json"];

fn step(name: &'static str, who: Who, argv: Vec<String>, cwd: &'static str) -> StepSpec {
    let collect = if argv.iter().any(|a| a == "output.json") {
        vec![("output.json", "output.json")]
    } else if argv.iter().any(|a| a == "output.txt") {
        vec![("output.txt", "output.txt")]
    } else {
        Vec::new()
    };
    StepSpec {
        name,
        who,
        argv,
        cwd,
        links: 1,
        interrupt_after_s: None,
        netem: false,
        collect,
    }
}

pub const TAGS: [&str; 6] = [
    "sc01_shards_union",
    "sc02_pause_wait_resume",
    "sc03_retries",
    "sc04_packet_mods_and_pcap",
    "sc05_infinite_interrupt",
    "sc06_dual_veth",
];
pub fn planned_tags() -> Vec<&'static str> {
    TAGS.to_vec()
}

/// The steps of a case, in the order they run; defined here and nowhere else.
pub fn steps(tag: &str) -> Option<Vec<StepSpec>> {
    let full = |extra: &[&str]| scan(PORTS, LIST, RATE, "3", extra);
    Some(match tag {
        // Two shards with one seed, and the C oracle's single run to compare with.
        "sc01_shards_union" => vec![
            step("shard1", Who::Rmasscan, full(&["--shard", "1/2"]), "shard1"),
            step("shard2", Who::Rmasscan, full(&["--shard", "2/2"]), "shard2"),
            step("oracle", Who::Oracle, full(&[]), "oracle"),
        ],
        // SIGINT, `--wait 2` with a late reply (netem), `paused.conf` before the wait, then `--resume`.
        "sc02_pause_wait_resume" => {
            let mut pause = step(
                "pause",
                Who::Rmasscan,
                scan(PAUSE_PORTS, JSON, PAUSE_RATE, PAUSE_WAIT, &[]),
                "run",
            );
            pause.interrupt_after_s = Some(PAUSE_AFTER_S);
            pause.netem = true;
            pause.collect.push((PAUSED_CONF, PAUSED_EVIDENCE));
            let mut resume = step(
                "resume",
                Who::Rmasscan,
                argv(&[
                    "--resume",
                    PAUSED_CONF,
                    "--show",
                    "open,closed",
                    "--wait",
                    "3",
                ]),
                "run",
            );
            resume.collect = vec![("output.json", "output.json")];
            vec![pause, resume]
        }
        "sc03_retries" => vec![
            step(
                "retries",
                Who::Rmasscan,
                full(&["--retries", "2"]),
                "retries",
            ),
            step("oracle", Who::Oracle, full(&["--retries", "2"]), "oracle"),
        ],
        "sc04_packet_mods_and_pcap" => {
            let mut mods = step(
                "mods",
                Who::Rmasscan,
                full(&[
                    "--ttl",
                    "42",
                    "--tcp-sackok",
                    "--tcp-wscale",
                    "7",
                    "--pcap",
                    SCANNER_PCAP,
                ]),
                "mods",
            );
            mods.collect.push((SCANNER_PCAP, SCANNER_PCAP));
            vec![
                mods,
                step("badsum", Who::Rmasscan, full(&["--badsum"]), "badsum"),
            ]
        }
        "sc05_infinite_interrupt" => {
            let mut run = step("run", Who::Rmasscan, full(&["--infinite"]), "run");
            run.interrupt_after_s = Some(INFINITE_AFTER_S);
            run.collect.push((PAUSED_CONF, PAUSED_EVIDENCE));
            vec![run]
        }
        "sc06_dual_veth" => {
            let mut dual = step("dual", Who::Rmasscan, full(&NIC_ARGS), "dual");
            dual.links = 2;
            let mut pause = step(
                "dual_pause",
                Who::Rmasscan,
                scan(PAUSE_PORTS, JSON, PAUSE_RATE, PAUSE_WAIT, &NIC_ARGS),
                "run",
            );
            pause.links = 2;
            pause.interrupt_after_s = Some(PAUSE_AFTER_S);
            pause.collect.push((PAUSED_CONF, PAUSED_EVIDENCE));
            let mut resume = step(
                "dual_resume",
                Who::Rmasscan,
                argv(&[
                    "--resume",
                    PAUSED_CONF,
                    "--show",
                    "open,closed",
                    "--wait",
                    "3",
                ]),
                "run",
            );
            resume.links = 2;
            resume.collect = vec![("output.json", "output.json")];
            vec![dual, pause, resume]
        }
        _ => return None,
    })
}
/// Why a case has no oracle step (or that it has one).
pub fn oracle_note(tag: &str) -> Option<&'static str> {
    Some(match tag {
        "sc01_shards_union" | "sc03_retries" => "oracle: the pinned C masscan, same argv",
        "sc02_pause_wait_resume" => {
            "rmasscan-only: the late reply needs the lab's netem delay, and C never ends a live scan on this stand"
        }
        "sc04_packet_mods_and_pcap" => {
            "rmasscan-only: --badsum is a stub in C; the TCP options are proven against C by the offline vectors"
        }
        "sc05_infinite_interrupt" => "rmasscan-only: C never ends a live scan on this stand",
        "sc06_dual_veth" => "rmasscan-only: the C oracle is not run on the second link",
        _ => return None,
    })
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectStep {
    pub name: String,
    pub who: Who,
    pub links: usize,
    pub interrupt: bool,
    pub netem: bool,
}
/// `expect.json`: the case as the suite planned it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScExpect {
    pub tag: String,
    pub steps: Vec<ExpectStep>,
}
pub fn expect(tag: &str) -> Option<ScExpect> {
    steps(tag).map(|s| ScExpect {
        tag: tag.into(),
        steps: s.iter().map(StepSpec::expect).collect(),
    })
}

/// `interrupt.json` of a step: when the suite sent SIGINT, how the scan ended, and what it saw of `paused.conf`.
/// `signal_unix` is `None` when the scan had ended before the signal; `paused_seen_unix` the first moment the suite
/// found `paused.conf` in the scanner's directory after the signal; `paused_conf_present` whether it was there at the
/// scan's end.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScInterrupt {
    pub signal: String,
    pub after_s: f64,
    pub signal_unix: Option<f64>,
    pub exit_within_s: f64,
    pub killed: bool,
    pub paused_seen_unix: Option<f64>,
    pub paused_conf_present: bool,
}
/// `netem.json`: the delay the suite put on the peer's veth for the step, and that it took it off again.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetemRecord {
    pub iface: String,
    pub delay_ms: u64,
    pub applied: bool,
    pub removed: bool,
}
/// `manifest.json` as far as this verifier reads it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ScManifest {
    #[serde(rename = "scan-control")]
    pub scan_control: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lab_id: Option<String>,
}

// ------------------------------------------------------------------ the stand and the plan

/// The stand of link `k`: link 0 is the autodetect stand's, link 1 the second veth pair, whose scanner address
/// (`--adapter-ip[1]`) is [`SECOND_ADAPTER_IP`].
pub fn link_stand(k: usize) -> Stand {
    let base = av::stand(Plan::Linux);
    if k == 0 {
        return base;
    }
    Stand {
        iface: SECOND_SCANNER_IF,
        scanner_ip: SECOND_ADAPTER_IP.parse().unwrap_or(base.scanner_ip),
        scanner_mac: SECOND_SCANNER_MAC,
        peer_mac: SECOND_PEER_MAC,
        ..base
    }
}

/// What the plan of a scan needs beyond the case's fixed targets.
#[derive(Debug, Clone, Copy, Default)]
pub struct Mods {
    pub ttl: Option<u8>,
    pub badsum: bool,
    pub sackok: bool,
    pub wscale: Option<u8>,
}
/// One adapter of a scan as the `[+]` lines report it: its source port is rmasscan's choice.
#[derive(Debug, Clone, Copy)]
pub struct NicPlan {
    pub link: usize,
    pub port: u16,
}
#[derive(Debug, Clone)]
pub struct PlanSpec<'a> {
    pub ports: &'a str,
    pub rate: &'a str,
    pub retries: u32,
    pub shard: (u32, u32),
    pub mods: Mods,
    pub resume_index: u64,
    pub nics: Vec<NicPlan>,
}
impl<'a> PlanSpec<'a> {
    pub fn single(ports: &'a str, rate: &'a str, port: u16) -> PlanSpec<'a> {
        PlanSpec {
            ports,
            rate,
            retries: 0,
            shard: (1, 1),
            mods: Mods::default(),
            resume_index: 0,
            nics: vec![NicPlan { link: 0, port }],
        }
    }
}

/// The SYN frames of every adapter of the plan, in send order, from the product's own plan (`ReadyPlan::new_cli` and
/// its cursors): the stream the scanner must put on each link. The checks that decide a case never rest on this
/// alone: the case's own properties (counts, partitions, the oracle) are checked beside it.
pub fn plan_streams(spec: &PlanSpec) -> Result<Vec<Vec<Vec<u8>>>, String> {
    let nic_bindings: Vec<NicBinding> = spec
        .nics
        .iter()
        .map(|n| {
            let st = link_stand(n.link);
            let router = if n.link == 0 {
                st.peer_mac
            } else {
                SECOND_PEER_MAC
            };
            NicBinding::from(AdapterBinding {
                interface_id: st.iface.into(),
                link_type: LinkType::Ethernet,
                source_ipv4: u32::from(st.scanner_ip),
                source_mac: st.scanner_mac,
                next_hop_mac: router,
                source_ports: (n.port, n.port),
            })
        })
        .collect();
    let first = nic_bindings.first().ok_or("a plan needs an adapter")?;
    let mut ips = MassIp::new();
    add_target_string(ips.ipv4_mut(), TARGETS).map_err(|e| e.to_string())?;
    parse_ports(ips.ports_mut(), spec.ports).map_err(|e| e.to_string())?;
    let cfg = ScanConfig {
        targets: ips,
        seed: 1,
        max_rate: parse_rate(spec.rate).map_err(|e| e.to_string())?,
        wait_secs: 3,
        retries: spec.retries,
        shard: Shard {
            one: spec.shard.0,
            of: spec.shard.1,
        },
        resume_index: spec.resume_index,
        adapter_ip: Some(first.binding.source_ipv4),
        adapter_mac: Some(first.binding.source_mac),
        router_mac: Some(first.binding.next_hop_mac),
        source_port: Some(first.binding.source_ports),
        adapter_name: Some(first.binding.interface_id.clone()),
        ttl: spec.mods.ttl,
        badsum: spec.mods.badsum,
        tcp_opts: TcpHeaderOptions {
            sackok: spec.mods.sackok,
            wscale: spec.mods.wscale,
            ..TcpHeaderOptions::default()
        },
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).map_err(|e| e.to_string())?;
    let plan = ReadyPlan::new_cli(eff, nic_bindings).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for k in 0..spec.nics.len() {
        let mut c = plan
            .cursor_for_nic(k as u32, None)
            .map_err(|e| e.to_string())?;
        let mut frames = Vec::new();
        loop {
            let batch: Vec<Vec<u8>> = c.preload(64).iter().map(|p| p.frame.clone()).collect();
            if batch.is_empty() {
                break;
            }
            c.advance_sent_n(batch.len());
            frames.extend(batch);
        }
        out.push(frames);
    }
    Ok(out)
}

/// The ports of a spec like `80,443,8080` or `76-95`.
pub fn port_list(spec: &str) -> Vec<u16> {
    let mut v = Vec::new();
    for part in spec.split(',') {
        match part.split_once('-') {
            Some((a, b)) => {
                if let (Ok(a), Ok(b)) = (a.parse::<u16>(), b.parse::<u16>()) {
                    v.extend(a..=b);
                }
            }
            None => v.extend(part.parse::<u16>()),
        }
    }
    v
}
/// The stand's replies to a scan of `ports`: 80 and 8080 open on every peer, every other port closed (shown with
/// `--show open,closed`, which every scan of this suite uses).
pub(crate) fn stand_keys(ports: &[u16]) -> BTreeSet<Key> {
    let st = av::stand(Plan::Linux);
    let mut out = BTreeSet::new();
    for ip in &st.peer_ips {
        for port in ports {
            let open = st.open_ports.contains(port);
            let status = if open { Status::Open } else { Status::Closed };
            out.insert((Some(status), *ip, Some(*port)));
        }
    }
    out
}
/// Every `(address, port)` the scan of `ports` probes.
pub fn probe_pairs(ports: &[u16]) -> BTreeSet<(Ipv4Addr, u16)> {
    let st = av::stand(Plan::Linux);
    st.peer_ips
        .iter()
        .flat_map(|ip| ports.iter().map(move |p| (*ip, *p)))
        .collect()
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
/// A TCP option of a SYN, as RFC 9293 and RFC 7323 write them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOpt {
    Mss(u16),
    SackOk,
    WScale(u8),
    Other(u8),
}
/// The options of a TCP header up to the first end-of-list (kind 0); everything after it must be zero padding.
pub fn tcp_options(bytes: &[u8]) -> Result<Vec<TcpOpt>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            0 => {
                return if bytes[i..].iter().all(|b| *b == 0) {
                    Ok(out)
                } else {
                    Err("bytes after the end-of-list option".into())
                };
            }
            1 => {
                out.push(TcpOpt::Other(1));
                i += 1;
            }
            kind => {
                let len = usize::from(*bytes.get(i + 1).ok_or("an option without a length")?);
                let body = bytes
                    .get(i + 2..i + len)
                    .ok_or("an option past the header")?;
                if len < 2 {
                    return Err("an option shorter than its kind and length".into());
                }
                out.push(match (kind, body) {
                    (2, [a, b]) => TcpOpt::Mss(u16::from_be_bytes([*a, *b])),
                    (4, []) => TcpOpt::SackOk,
                    (3, [n]) => TcpOpt::WScale(*n),
                    _ => TcpOpt::Other(kind),
                });
                i += len;
            }
        }
    }
    Ok(out)
}
/// What the checks need of a SYN frame, read here and not with the product's parser.
#[derive(Debug, Clone)]
pub struct SynInfo {
    pub ttl: u8,
    pub ip_header_ok: bool,
    pub tcp_checksum_ok: bool,
    /// The IPv4 total length equals the frame past Ethernet.
    pub length_ok: bool,
    pub options: Result<Vec<TcpOpt>, String>,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub sp: u16,
    pub dp: u16,
}
pub fn syn_info(f: &[u8]) -> Option<SynInfo> {
    if f.len() < 54 || f[12..14] != [8, 0] || f[14] >> 4 != 4 || f[23] != 6 {
        return None;
    }
    let ihl = usize::from(f[14] & 15) * 4;
    let t = 14 + ihl;
    let doff = usize::from(f.get(t + 12)? >> 4) * 4;
    if ihl < 20 || doff < 20 || f.len() < t + doff {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([f[16], f[17]]));
    let seg = &f[t..];
    let mut pseudo = ones(&f[26..34], 0);
    pseudo = ones(&[0, 6], pseudo);
    pseudo = ones(&(seg.len() as u16).to_be_bytes(), pseudo);
    Some(SynInfo {
        ttl: f[22],
        ip_header_ok: ones(&f[14..t], 0) == 0xffff,
        tcp_checksum_ok: ones(seg, pseudo) == 0xffff,
        length_ok: total == f.len() - 14,
        options: tcp_options(&f[t + 20..t + doff]),
        src: Ipv4Addr::new(f[26], f[27], f[28], f[29]),
        dst: Ipv4Addr::new(f[30], f[31], f[32], f[33]),
        sp: u16::from_be_bytes([f[t], f[t + 1]]),
        dp: u16::from_be_bytes([f[t + 2], f[t + 3]]),
    })
}

/// One capture of one link of a step.
struct LinkCap {
    frames: Frames,
    wire: av::Wire,
    stand: Stand,
}
impl LinkCap {
    fn syn_frames(&self) -> Vec<Vec<u8>> {
        self.wire.syns.iter().map(|(_, f)| f.clone()).collect()
    }
    fn pairs(&self) -> Vec<(Ipv4Addr, u16)> {
        self.wire
            .syns
            .iter()
            .filter_map(|(_, f)| syn_info(f))
            .map(|i| (i.dst, i.dp))
            .collect()
    }
    /// The replies on the wire to this capture's SYNs inside its window, with their times: a SYN-ACK is open, an RST
    /// closed (the answer's ack is the SYN's sequence plus one, from the SYN's port, to the scanner).
    fn replies(&self) -> Vec<(f64, Key)> {
        let asked: BTreeSet<(String, u16, u16, u32)> = self
            .wire
            .syns
            .iter()
            .filter_map(|(_, f)| tcp(f))
            .map(|i| (i.dst, i.dp, i.sp, i.seq.wrapping_add(1)))
            .collect();
        let (start, end) = av::window(&self.wire);
        let (sm, src) = (
            av::dash(self.stand.scanner_mac).replace('-', ":"),
            self.stand.scanner_ip.to_string(),
        );
        self.frames
            .iter()
            .filter(|(t, _)| (start..=end).contains(t))
            .filter_map(|(t, f)| tcp(f).map(|i| (*t, i)))
            .filter(|(_, i)| {
                i.dm == sm && i.dst == src && asked.contains(&(i.src.clone(), i.sp, i.dp, i.ack))
            })
            .filter_map(|(t, i)| {
                let status = if i.flags & 0x12 == 0x12 {
                    Status::Open
                } else if i.flags & 0x04 != 0 {
                    Status::Closed
                } else {
                    return None;
                };
                Some((t, (Some(status), i.src.parse().ok()?, Some(i.sp))))
            })
            .collect()
    }
    fn reply_keys(&self) -> BTreeSet<Key> {
        self.replies().into_iter().map(|(_, k)| k).collect()
    }
}

// ------------------------------------------------------------------ stderr

/// One thing rmasscan's stderr shows, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ev {
    Running,
    Waiting,
    Infinite,
    Erase,
    Interrupt,
    Saving,
    Plus,
    Finished,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fin {
    reason: String,
    sent: u64,
    replies: u64,
    open: u64,
}
#[derive(Debug, Default)]
struct Stderr {
    events: Vec<Ev>,
    /// `[+] key = value`, the key with its `[k]` suffix, in order.
    plus: Vec<(String, String)>,
    fin: Option<Fin>,
    /// What is neither a `[+]` line nor a status form: nothing rmasscan prints.
    stray: Vec<String>,
    /// The seconds of the `waiting N-secs` ticks.
    wait_secs: Vec<i64>,
}
impl Stderr {
    fn count(&self, e: Ev) -> usize {
        self.events.iter().filter(|x| **x == e).count()
    }
    fn at(&self, e: Ev) -> Option<usize> {
        self.events.iter().position(|x| *x == e)
    }
    fn value(&self, key: &str) -> Option<&str> {
        self.plus
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
    /// The number of a `key = N (source)` value.
    fn number(&self, key: &str) -> Option<u64> {
        self.value(key)?.split(' ').next()?.parse().ok()
    }
}
/// `rate:%6.2f-kpps, syn/s=%.0f ack/s=%.0f tcb-rate=%.0f, %u-tcbs,         ` (main-status.c:214, `status::infinite_line`).
fn infinite_form(s: &str) -> bool {
    let digits = |s: &str| -> Option<usize> {
        let n = s.bytes().take_while(u8::is_ascii_digit).count();
        (n > 0).then_some(n)
    };
    let Some(rest) = s.strip_prefix("rate:") else {
        return false;
    };
    let Some((rate, mut rest)) = rest.split_once("-kpps, syn/s=") else {
        return false;
    };
    if rate.trim_start().parse::<f64>().is_err() {
        return false;
    }
    for lit in [" ack/s=", " tcb-rate=", ", "] {
        let Some(n) = digits(rest) else { return false };
        match rest[n..].strip_prefix(lit) {
            Some(r) => rest = r,
            None => return false,
        }
    }
    let Some(n) = digits(rest) else { return false };
    rest[n..] == *"-tcbs,         "
}
/// The seconds of a `waiting N-secs` status fragment.
fn waiting_secs(f: &str) -> Option<i64> {
    let rest = f.split(" waiting ").nth(1)?;
    rest.split("-secs").next()?.parse().ok()
}
fn parse_fin(rest: &str) -> Option<Fin> {
    let (reason, tail) = rest.split_once(", sent ")?;
    let (sent, tail) = tail.split_once(", replies ")?;
    let (replies, open) = tail.split_once(", open ")?;
    Some(Fin {
        reason: reason.to_owned(),
        sent: sent.parse().ok()?,
        replies: replies.parse().ok()?,
        open: open.parse().ok()?,
    })
}
const SAVING_LINE: &str = "saving resume file to: paused.conf";
fn parse_stderr(text: &str) -> Stderr {
    let mut e = Stderr::default();
    let status = |f: &str| -> Option<Ev> {
        if infinite_form(f) {
            return Some(Ev::Infinite);
        }
        match av::screen(&format!("{f}\r")).ok()?.into_iter().next()? {
            Piece::Running => Some(Ev::Running),
            Piece::Waiting => Some(Ev::Waiting),
            Piece::Erase => Some(Ev::Erase),
            _ => None,
        }
    };
    let lines: Vec<&str> = text.trim_start_matches('\u{feff}').split('\n').collect();
    for (n, raw) in lines.iter().enumerate() {
        if raw.is_empty() && n + 1 == lines.len() {
            break;
        }
        let mut frags: Vec<&str> = raw.split('\r').collect();
        let visible = frags.pop().unwrap_or_default();
        let mut pad = false;
        for f in frags {
            if f.len() == 70 && f.bytes().all(|b| b == b' ') {
                pad = true;
            } else if let Some(ev) = status(f) {
                if ev == Ev::Waiting {
                    e.wait_secs.extend(waiting_secs(f));
                }
                e.events.push(ev);
            } else {
                e.stray.push(format!("{f:?}"));
            }
        }
        if visible == SAVING_LINE && pad {
            e.events.push(Ev::Saving);
            continue;
        }
        if pad {
            e.stray.push("70 spaces without the saving line".into());
        }
        if visible.is_empty() {
            continue;
        }
        if let Some(ev) = status(visible) {
            if ev == Ev::Waiting {
                e.wait_secs.extend(waiting_secs(visible));
            }
            e.events.push(ev);
            continue;
        }
        match av::screen(visible).ok().and_then(|v| v.into_iter().next()) {
            Some(Piece::Interrupt) => e.events.push(Ev::Interrupt),
            Some(Piece::Line(l)) => {
                if let Some(rest) = l.strip_prefix("[+] finished: ") {
                    match parse_fin(rest) {
                        Some(f) if e.fin.is_none() => {
                            e.fin = Some(f);
                            e.events.push(Ev::Finished);
                        }
                        _ => e.stray.push(l),
                    }
                } else if let Some((k, v)) =
                    l.strip_prefix("[+] ").and_then(|b| b.split_once(" = "))
                {
                    e.plus.push((k.to_owned(), v.to_owned()));
                    e.events.push(Ev::Plus);
                } else {
                    e.stray.push(l);
                }
            }
            _ => e.stray.push(visible.to_owned()),
        }
    }
    e
}

// ------------------------------------------------------------------ what a step left

struct Side {
    spec: StepSpec,
    /// The step's directory name relative to the case directory.
    exit: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
    se: Stderr,
    links: Vec<Option<LinkCap>>,
    /// The output file's bytes.
    raw: Option<Vec<u8>>,
    forced_exit: bool,
    interrupt: Option<ScInterrupt>,
}
impl Side {
    fn who(&self) -> Who {
        self.spec.who
    }
    fn link(&self, k: usize) -> Option<&LinkCap> {
        self.links.get(k).and_then(Option::as_ref)
    }
    /// Every adapter's capture is there.
    fn captured(&self) -> bool {
        self.links.iter().all(Option::is_some)
    }
    fn wire_syns(&self) -> usize {
        self.links.iter().flatten().map(|l| l.wire.syns.len()).sum()
    }
}

fn forced_exit(stderr: &str) -> bool {
    stderr
        .split(['\n', '\r'])
        .any(|s| s.trim_end() == FORCED_EXIT)
}

fn format_of(spec: &StepSpec) -> Format {
    if spec.output_name() == Some("output.json") {
        Format::Json
    } else {
        Format::List
    }
}

// ------------------------------------------------------------------ privacy

/// The files a scanner wrote or that name its argv: their addresses must be the stand's.
const SCANNER_TEXT: [&str; 10] = [
    "argv.json",
    "expect.json",
    "stdout.txt",
    "stderr.txt",
    "output.txt",
    "output.json",
    PAUSED_EVIDENCE,
    INTERRUPT_JSON,
    NETEM_JSON,
    "exit.txt",
];
/// The interface names a record may carry.
const IFACE_NAMES: [&str; 4] = ["veth-a", "veth-a2", "veth-b", "veth-b2"];
fn name_problems(rel: &str, text: &str) -> Vec<String> {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    let mut names: Vec<String> = Vec::new();
    match base {
        "argv.json" => {
            if let Ok(a) = serde_json::from_str::<ArgvRecord>(text) {
                for w in a.argv.windows(2) {
                    if w[0].starts_with("--adapter[")
                        || w[0] == "--adapter"
                        || w[0] == "--interface"
                    {
                        names.push(w[1].clone());
                    }
                }
            }
        }
        "stderr.txt" => {
            for seg in text.split(['\n', '\r']) {
                if let Some(v) = seg.strip_prefix("[+] interface")
                    && let Some((_, v)) = v.split_once(" = ")
                {
                    names.push(v.split(' ').next().unwrap_or("").to_owned());
                }
            }
        }
        _ => {}
    }
    names
        .into_iter()
        .filter(|n| !IFACE_NAMES.contains(&n.as_str()))
        .map(|n| format!("interface name {n:?}"))
        .collect()
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
        if !av::TEXT_EXTENSIONS.contains(&ext) {
            continue;
        }
        let base = rel.rsplit('/').next().unwrap_or(rel);
        let mut p = match fs::read(d.join(rel)) {
            Err(e) => vec![format!("unreadable: {e}")],
            Ok(b) => {
                let text = String::from_utf8_lossy(&b);
                let mut p = av::token_problems(&text, SCANNER_TEXT.contains(&base));
                p.extend(name_problems(rel, &text));
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
            "privacy: every text file holds only allowlisted names, addresses and paths",
            PASS,
            format!("{seen} files"),
            false,
        );
    }
}

// ------------------------------------------------------------------ evidence

fn evidence_extension(f: &str) -> bool {
    Path::new(f)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| EVIDENCE_EXTENSIONS.contains(&e))
}
fn sealed(v: &Value) -> bool {
    v["mode"] == "scan-control"
        && isolation_permits(v, IsolationMode::Autodetect)
        && v["second_link"]
            == json!({"scanner": SECOND_SCANNER_IF, "peer": SECOND_PEER_IF, "adapter_ip": SECOND_ADAPTER_IP})
}
/// The stand's seal before and after the case: the autodetect stand plus the second veth pair.
fn seal(r: &mut Run, d: &Path) {
    match read_json(d.join(ISOLATION_JSON)) {
        None => r.add(
            "isolation.json present",
            NOT_RUN,
            "missing or invalid JSON",
            false,
        ),
        Some(v) => r.inv(
            "isolation.json: the sealed scan-control stand (capture isolation --mode scan-control)",
            sealed(&v),
            format!("mode {}, default_route {}", v["mode"], v["default_route"]),
        ),
    }
    let post = read_json(d.join(ISOLATION_POST_JSON));
    r.inv(
        "isolation-post.json: the stand still sealed after the case (capture isolation --mode scan-control)",
        post.as_ref().is_some_and(sealed),
        post.map_or_else(
            || "missing or invalid JSON".to_owned(),
            |v| format!("mode {}, default_route {}", v["mode"], v["default_route"]),
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
    let odd: Vec<&String> = files.iter().filter(|f| !evidence_extension(f)).collect();
    r.inv(
        "evidence files carry only the allowed extensions (json pcap txt log err sha256 md)",
        odd.is_empty(),
        format!("{odd:?}"),
    );
    seal(r, d);
}

/// Reads one step's directory, with the checks that prove its files.
fn read_side(r: &mut Run, d: &Path, spec: &StepSpec, tree_links: &[String]) -> Side {
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
    let mut links = Vec::new();
    for (k, [pcap_name, meta, _]) in PEER_FILES.iter().enumerate().take(spec.links) {
        let st = link_stand(k);
        let cap = av::capture(r, d, &rel(pcap_name), tree_links);
        if let Some(c) = &cap {
            av::witness(r, d, &rel(pcap_name), &rel(meta), c, &st);
        }
        links.push(cap.map(|(frames, _)| LinkCap {
            wire: av::classify(&frames, st.scanner_mac),
            frames,
            stand: st,
        }));
    }
    let raw = spec.output_name().and_then(|n| {
        let b = fs::read(sd.join(n)).ok();
        if b.is_none() {
            r.beh(&format!("{name}/{n} written"), false, "missing");
        }
        b
    });
    let interrupt = spec
        .interrupt_after_s
        .and_then(|_| av::typed::<ScInterrupt>(r, &sd, INTERRUPT_JSON));
    let se = stderr.as_deref().map(parse_stderr).unwrap_or_default();
    Side {
        spec: spec.clone(),
        exit,
        forced_exit: spec.who == Who::Oracle && stderr.as_deref().is_some_and(forced_exit),
        stdout,
        stderr,
        se,
        links,
        raw,
        interrupt,
    }
}

// ------------------------------------------------------------------ checks shared by the cases

/// Who wrote a side: rmasscan's misbehaviour FAILs, a broken oracle is a broken stand (INVALID).
fn beh(r: &mut Run, s: &Side, name: &str, ok: bool, detail: impl ToString) {
    let name = format!("{}: {name}", s.spec.name);
    match s.who() {
        Who::Rmasscan => r.beh(&name, ok, detail),
        Who::Oracle => r.inv(&name, ok, detail),
    }
}
/// A check against the capture: FAIL only once the evidence is proven.
fn cap(r: &mut Run, s: &Side, name: &str, ok: bool, detail: impl ToString) {
    let name = format!("{}: {name}", s.spec.name);
    match s.who() {
        Who::Rmasscan => r.cap(&name, ok, detail),
        Who::Oracle => r.inv(&name, ok, detail),
    }
}
/// The frames of a stream against the plan's, exactly and in order.
fn same_stream(act: &[Vec<u8>], plan: &[Vec<u8>]) -> (bool, String) {
    if act == plan {
        return (true, format!("{} SYNs", act.len()));
    }
    let at = act.iter().zip(plan).position(|(a, p)| a != p);
    (
        false,
        format!(
            "{} SYNs on the wire, {} in the plan, first difference at {at:?}",
            act.len(),
            plan.len()
        ),
    )
}
fn counts(pairs: impl IntoIterator<Item = (Ipv4Addr, u16)>) -> BTreeMap<(Ipv4Addr, u16), usize> {
    let mut m = BTreeMap::new();
    for p in pairs {
        *m.entry(p).or_insert(0) += 1;
    }
    m
}
fn keys(doc: &Doc) -> Vec<Key> {
    doc.records.iter().map(ov::Rec::key).collect()
}

/// What the `[+]` lines must say.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Detect {
    /// One adapter found by the route to the targets (the stand's autodetect lines); the source port is rmasscan's
    /// own choice (`time`) or came from `paused.conf` (`given`).
    Auto { given_port: bool },
    /// `--adapter[0]` and `--adapter[1]` given, routers given.
    Dual { given_port: bool },
}
fn detection(r: &mut Run, s: &Side, how: Detect) {
    let (plus, given_port) = (
        &s.se.plus,
        matches!(
            how,
            Detect::Auto { given_port: true } | Detect::Dual { given_port: true }
        ),
    );
    let port_src = if given_port { "given" } else { "time" };
    let get = |k: &str| s.se.value(k).map(str::to_owned);
    let port_ok = |k: &str| {
        s.se.value(k).is_some_and(|v| {
            v.split_once(' ')
                .is_some_and(|(n, src)| n.parse::<u16>().is_ok() && src == format!("({port_src})"))
        })
    };
    let (ok, want) = match how {
        Detect::Auto { .. } => {
            let keys: Vec<&str> = plus.iter().map(|(k, _)| k.as_str()).collect();
            (
                keys == [
                    "interface",
                    "source-mac",
                    "source-ip",
                    "router-ip",
                    "router-mac",
                    "seed",
                    "source-port",
                ] && get("interface").as_deref() == Some("veth-a (detected: route to 198.18.0.2)")
                    && get("source-mac").as_deref() == Some("02-aa-00-00-00-01 (detected)")
                    && get("source-ip").as_deref() == Some("198.18.0.1 (detected)")
                    && get("router-ip").as_deref()
                        == Some("198.18.0.2 (interface default gateway)")
                    && get("router-mac").is_some_and(|m| m.starts_with("02-aa-00-00-00-02 (arp: "))
                    && get("seed").as_deref() == Some("1 (given)")
                    && port_ok("source-port"),
                "veth-a by the route, its MAC and IP, router 198.18.0.2 by ARP, seed 1 given, one source port",
            )
        }
        Detect::Dual { .. } => {
            let mut got: Vec<&str> = plus.iter().map(|(k, _)| k.as_str()).collect();
            got.sort_unstable();
            let mut want = vec![
                "interface",
                "interface[1]",
                "router-mac",
                "router-mac[1]",
                "seed",
                "source-ip",
                "source-ip[1]",
                "source-mac",
                "source-mac[1]",
                "source-port",
                "source-port[1]",
            ];
            want.sort_unstable();
            (
                got == want
                    && get("interface").as_deref() == Some("veth-a (given)")
                    && get("interface[1]").as_deref() == Some("veth-a2 (given)")
                    && get("source-mac").as_deref() == Some("02-aa-00-00-00-01 (detected)")
                    && get("source-ip").as_deref() == Some("198.18.0.1 (detected)")
                    && get("source-mac[1]").as_deref() == Some("02-aa-00-00-00-03 (given)")
                    && get("source-ip[1]").as_deref() == Some("198.18.0.6 (given)")
                    && get("router-mac").as_deref() == Some("02-aa-00-00-00-02 (given)")
                    && get("router-mac[1]").as_deref() == Some("02-aa-00-00-00-04 (given)")
                    && get("seed").as_deref() == Some("1 (given)")
                    && port_ok("source-port")
                    && port_ok("source-port[1]"),
                "veth-a and veth-a2 given with their MACs, IPs and routers, seed 1 given, a source port each",
            )
        }
    };
    beh(
        r,
        s,
        &format!("[+] lines are the stand's: {want}"),
        ok,
        format!("{plus:?}"),
    );
}

/// The stderr and exit of a rmasscan step: the exit, a silent stdout, the status grammar, the `[+] finished` line
/// against the wire. `reasons` are the `[+] finished` reasons the step may end with.
fn common(r: &mut Run, s: &Side, reasons: &[&str]) {
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
    if s.who() != Who::Rmasscan || s.stderr.is_none() {
        return;
    }
    beh(
        r,
        s,
        "stderr.txt holds only [+] lines and rmasscan's status forms",
        s.se.stray.is_empty(),
        format!("{:?}", s.se.stray),
    );
    let fin = s.se.fin.as_ref();
    beh(
        r,
        s,
        &format!("[+] finished: {}", reasons.join(" or ")),
        fin.is_some_and(|f| reasons.contains(&f.reason.as_str())),
        format!("{fin:?}"),
    );
    if s.captured() {
        let wire = s.wire_syns() as u64;
        cap(
            r,
            s,
            "[+] finished reports sent equal to the scanner SYNs on the wire",
            fin.map(|f| f.sent) == Some(wire),
            format!("printed {:?}, wire {wire}", fin.map(|f| f.sent)),
        );
    }
}
/// The oracle's stderr must be masscan's own; its footer-less file is the forced exit (module notes).
fn oracle_doc(r: &mut Run, s: &Side, doc: &Doc) {
    if !doc.complete {
        beh(
            r,
            s,
            "its file lacks the footer only after masscan's forced exit (the line is on its stderr)",
            s.forced_exit,
            "no footer, and no forced exit on the oracle's stderr",
        );
    }
}
/// The document of a step with one output document: parsed, with the check that says so.
fn single_doc(r: &mut Run, s: &Side) -> Option<Doc> {
    let name = s.spec.output_name()?;
    let raw = s.raw.as_ref()?;
    match ov::parse_doc(format_of(&s.spec), raw) {
        Ok(d) => {
            beh(
                r,
                s,
                &format!("{name} is a well-formed document"),
                true,
                format!("{} records", d.records.len()),
            );
            Some(d)
        }
        Err(e) => {
            beh(r, s, &format!("{name} is a well-formed document"), false, e);
            None
        }
    }
}
fn no_duplicate(r: &mut Run, s: &Side, doc: &Doc) {
    let ks = keys(doc);
    let set: BTreeSet<Key> = ks.iter().copied().collect();
    beh(
        r,
        s,
        "the output holds no record twice",
        set.len() == ks.len(),
        ks.len() - set.len(),
    );
}
/// The SYNs of the wire against the plan, in order.
fn plan_check(r: &mut Run, s: &Side, k: usize, plan: &[Vec<u8>], what: &str) {
    if let Some(l) = s.link(k) {
        let (ok, d) = same_stream(&l.syn_frames(), plan);
        cap(
            r,
            s,
            &format!("link {k}: the scanner SYNs equal the {what}, in order, each once"),
            ok,
            d,
        );
    }
}
/// The source port a step printed (`source-port` or `source-port[k]`).
fn source_port(s: &Side, k: usize) -> Option<u16> {
    let key = if k == 0 {
        "source-port".to_owned()
    } else {
        format!("source-port[{k}]")
    };
    s.se.number(&key).and_then(|n| u16::try_from(n).ok())
}
fn plan_of(r: &mut Run, s: &Side, spec: &PlanSpec) -> Option<Vec<Vec<Vec<u8>>>> {
    match plan_streams(spec) {
        Ok(p) => Some(p),
        Err(e) => {
            r.inv(
                &format!(
                    "{}: the scan plan rebuilds from the case table and the [+] lines",
                    s.spec.name
                ),
                false,
                e,
            );
            None
        }
    }
}

// ------------------------------------------------------------------ sc01

fn sc01(r: &mut Run, sides: &[Side]) {
    let [s1, s2, or] = sides else { return };
    let all = probe_pairs(&port_list(PORTS));
    let mut pairs: Vec<Vec<(Ipv4Addr, u16)>> = Vec::new();
    let mut docs: Vec<Option<Doc>> = Vec::new();
    for (i, s) in [s1, s2].into_iter().enumerate() {
        common(r, s, &["Completed"]);
        if s.stderr.is_some() {
            detection(r, s, Detect::Auto { given_port: false });
        }
        let doc = single_doc(r, s);
        if let Some(d) = &doc {
            beh(
                r,
                s,
                "the output is complete (its footer written)",
                d.complete,
                "",
            );
            no_duplicate(r, s, d);
        }
        docs.push(doc);
        if let (Some(l), Some(port)) = (s.link(0), source_port(s, 0)) {
            let mut p = PlanSpec::single(PORTS, RATE, port);
            p.shard = (i as u32 + 1, 2);
            if let Some(plan) = plan_of(r, s, &p) {
                plan_check(r, s, 0, &plan[0], &format!("plan of --shard {}/2", i + 1));
            }
            pairs.push(l.pairs());
            beh(
                r,
                s,
                "the shard sends half of the 12 probes",
                l.pairs().len() == all.len() / 2,
                l.pairs().len(),
            );
        }
    }
    let [Some(p1), Some(p2)] = [pairs.first(), pairs.get(1)] else {
        return;
    };
    let (c1, c2) = (counts(p1.iter().copied()), counts(p2.iter().copied()));
    r.cap(
        "shard 1/2 and 2/2 send no probe twice and share none",
        c1.values().chain(c2.values()).all(|n| *n == 1) && c1.keys().all(|k| !c2.contains_key(k)),
        format!(
            "{} and {} probes, {} shared",
            c1.len(),
            c2.len(),
            c1.keys().filter(|k| c2.contains_key(k)).count()
        ),
    );
    let union: BTreeSet<(Ipv4Addr, u16)> = c1.keys().chain(c2.keys()).copied().collect();
    r.cap(
        "the shards' probes together are all 12 probes of the scan",
        union == all,
        format!("{} of {}", union.len(), all.len()),
    );
    // The oracle's single run: its probes, in its order, are the shards' interleaved (C's start/increment).
    if let Some(l) = or.link(0) {
        let opairs = l.pairs();
        beh(
            r,
            or,
            "the single run sends each of the 12 probes once",
            counts(opairs.iter().copied()).values().all(|n| *n == 1) && opairs.len() == all.len(),
            opairs.len(),
        );
        let mut woven = Vec::new();
        for i in 0..p1.len().max(p2.len()) {
            woven.extend(p1.get(i).copied());
            woven.extend(p2.get(i).copied());
        }
        r.cap(
            "the oracle's probes in send order are shard 1/2 and 2/2 interleaved (C: start (one-1), increment of)",
            opairs == woven,
            format!("{} probes, interleaved {}", opairs.len(), woven.len()),
        );
    }
    common(r, or, &["Completed"]);
    if let Some(d) = single_doc(r, or) {
        oracle_doc(r, or, &d);
    }
    r.notes
        .insert("oracle_forced_exit".into(), json!(or.forced_exit));
    if let ([Some(d1), Some(d2)], Some(od)) = (
        [&docs[0], &docs[1]],
        ov::parse_doc(Format::List, or.raw.as_deref().unwrap_or(b"")).ok(),
    ) {
        let (k1, k2): (BTreeSet<Key>, BTreeSet<Key>) = (
            keys(d1).into_iter().collect(),
            keys(d2).into_iter().collect(),
        );
        r.beh(
            "the shards' findings are disjoint",
            k1.is_disjoint(&k2),
            format!("{} shared", k1.intersection(&k2).count()),
        );
        let found: BTreeSet<Key> = k1.union(&k2).copied().collect();
        let theirs: BTreeSet<Key> = keys(&od).into_iter().collect();
        r.beh(
            "the shards' findings together are the stand's replies (80 and 8080 open, 443 closed on every peer)",
            found == stand_keys(&port_list(PORTS)),
            format!("{} findings", found.len()),
        );
        r.beh(
            "the shards' findings together are the oracle's findings",
            found == theirs,
            format!("rmasscan {}, oracle {}", found.len(), theirs.len()),
        );
    }
}

// ------------------------------------------------------------------ sc02

/// `key = value` lines of a `paused.conf`.
fn conf_lines(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| l.split_once(" = "))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}
fn conf_value<'a>(conf: &'a [(String, String)], key: &str) -> Option<&'a str> {
    conf.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}
fn paused_conf(d: &Path, s: &Side) -> Option<Vec<(String, String)>> {
    fs::read_to_string(d.join(s.spec.name).join(PAUSED_EVIDENCE))
        .ok()
        .map(|t| conf_lines(&t))
}
/// The pause step of `sc02` and `sc06`: SIGINT, the line, `paused.conf` saved before the wait, the wait phase, the
/// footer, `Paused`.
fn paused_step(r: &mut Run, s: &Side, wait_secs: i64) {
    let e = &s.se;
    beh(
        r,
        s,
        "stderr.txt carries the Ctrl-C line once",
        e.count(Ev::Interrupt) == 1,
        e.count(Ev::Interrupt),
    );
    beh(
        r,
        s,
        "stderr.txt carries `saving resume file to: paused.conf` once",
        e.count(Ev::Saving) == 1,
        e.count(Ev::Saving),
    );
    let first_wait = e.at(Ev::Waiting);
    beh(
        r,
        s,
        "paused.conf is saved after the Ctrl-C line and before the first `waiting N-secs` tick",
        e.at(Ev::Interrupt) < e.at(Ev::Saving)
            && e.at(Ev::Saving) < first_wait.or(Some(usize::MAX)),
        format!(
            "interrupt {:?}, saving {:?}, first wait tick {first_wait:?}",
            e.at(Ev::Interrupt),
            e.at(Ev::Saving)
        ),
    );
    beh(
        r,
        s,
        "the wait phase ran: `waiting N-secs` ticks, counting down from --wait",
        e.count(Ev::Waiting) >= 1
            && e.wait_secs.iter().all(|n| (-1..=wait_secs).contains(n))
            && e.wait_secs.windows(2).all(|w| w[0] >= w[1]),
        format!("{:?}", e.wait_secs),
    );
    beh(
        r,
        s,
        "no status line is left after the end of the wait but the erase",
        e.count(Ev::Erase) == 1,
        e.count(Ev::Erase),
    );
}
fn interrupt_checks(r: &mut Run, s: &Side, after_s: f64, window_of: Option<&LinkCap>) {
    let Some(i) = &s.interrupt else { return };
    let win = window_of.map(|l| av::window(&l.wire));
    r.inv(
        &format!("{}: interrupt.json: SIGINT about {after_s} s after the start, inside the capture window, a 30 s exit timeout", s.spec.name),
        i.signal == "INT"
            && i.after_s == after_s
            && i.exit_within_s == EXIT_WITHIN_S
            && i.signal_unix
                .is_none_or(|t| win.is_none_or(|(a, b)| (a..=b).contains(&t))),
        format!("{i:?}, window {win:?}"),
    );
    beh(
        r,
        s,
        "rmasscan was still scanning when SIGINT came",
        i.signal_unix.is_some(),
        format!("{:?}", i.signal_unix),
    );
    beh(
        r,
        s,
        "rmasscan exited within 30 s of SIGINT (no SIGKILL)",
        !i.killed,
        i.killed,
    );
    if let (Some(t), Some(l)) = (i.signal_unix, window_of) {
        let late = l.wire.syns.iter().filter(|(x, _)| *x > t + 1.0).count();
        cap(r, s, "no SYN later than 1 s after SIGINT", late == 0, late);
    }
}
fn sc02(r: &mut Run, d: &Path, sides: &[Side]) {
    let [pause, resume] = sides else { return };
    let all = port_list(PAUSE_PORTS);
    let wanted = stand_keys(&all);
    let probes = probe_pairs(&all).len();
    common(r, pause, &["Paused"]);
    if pause.stderr.is_some() {
        detection(r, pause, Detect::Auto { given_port: false });
    }
    paused_step(r, pause, 2);
    interrupt_checks(r, pause, PAUSE_AFTER_S, pause.link(0));
    // The late reply: netem held the replies back, so the ones to the last SYNs arrive after SIGINT, inside --wait.
    let netem: Option<NetemRecord> = av::typed(r, &d.join(pause.spec.name), NETEM_JSON);
    if let Some(n) = &netem {
        r.inv(
            "netem.json: the peer's replies were delayed on veth-b, by less than --wait, and the delay was taken off again",
            n.iface == "veth-b" && n.applied && n.removed && n.delay_ms == NETEM_DELAY_MS && n.delay_ms < 2000,
            format!("{n:?}"),
        );
    }
    let doc1 = single_doc(r, pause);
    if let Some(doc) = &doc1 {
        beh(
            r,
            pause,
            "the output is complete after the pause (the `]` footer written)",
            doc.complete,
            "",
        );
        no_duplicate(r, pause, doc);
    }
    if let (Some(l), Some(i), Some(doc)) = (pause.link(0), &pause.interrupt, &doc1) {
        let replies = l.replies();
        let late: BTreeSet<Key> = replies
            .iter()
            .filter(|(t, _)| i.signal_unix.is_some_and(|s| *t > s))
            .map(|(_, k)| *k)
            .collect();
        let have: BTreeSet<Key> = keys(doc).into_iter().collect();
        cap(
            r,
            pause,
            "a reply that came on the wire after SIGINT (inside the wait) is in the output",
            !late.is_empty() && late.is_subset(&have),
            format!(
                "{} late replies, {} not in the output",
                late.len(),
                late.difference(&have).count()
            ),
        );
        let all_replies: BTreeSet<Key> = replies.iter().map(|(_, k)| *k).collect();
        cap(
            r,
            pause,
            "the output holds every reply to the SYNs sent before the pause (none lost)",
            have == all_replies,
            format!("{} records, {} replies", have.len(), all_replies.len()),
        );
        // paused.conf existed before the wait ran: the suite saw it within the first second after the signal.
        beh(
            r,
            pause,
            "paused.conf was on disk within 1 s of SIGINT, before the 2 s wait ended",
            i.signal_unix
                .zip(i.paused_seen_unix)
                .is_some_and(|(sig, seen)| sig <= seen && seen <= sig + 1.0),
            format!("signal {:?}, seen {:?}", i.signal_unix, i.paused_seen_unix),
        );
    }
    // paused.conf: where the scan stopped and what the resume needs.
    let conf = paused_conf(d, pause);
    r.inv(
        "pause/paused.txt is the scanner's paused.conf",
        conf.as_ref()
            .is_some_and(|c| conf_value(c, "resume-index").is_some()),
        "",
    );
    let sent1 = pause.link(0).map_or(0, |l| l.wire.syns.len());
    let k = conf
        .as_ref()
        .and_then(|c| conf_value(c, "resume-index"))
        .and_then(|v| v.parse::<u64>().ok());
    if let (Some(c), Some(k)) = (&conf, k) {
        beh(
            r,
            pause,
            "paused.conf: resume-index is where the scan stopped, inside the scan",
            0 < k && (k as usize) < probes,
            format!("{k} of {probes}"),
        );
        cap(
            r,
            pause,
            "paused.conf: resume-index equals the SYNs sent (one adapter: exact)",
            k as usize == sent1,
            format!("{k}, {sent1} SYNs on the wire"),
        );
        beh(
            r,
            pause,
            "paused.conf: seed, rate and the source port of the run",
            conf_value(c, "seed") == Some("1")
                && conf_value(c, "rate").is_some_and(|v| v.trim().parse::<f64>() == Ok(10.0))
                && conf_value(c, "adapter-port").and_then(|v| v.parse::<u16>().ok())
                    == source_port(pause, 0),
            format!("{c:?}"),
        );
        beh(
            r,
            pause,
            "paused.conf carries the output file and format",
            conf_value(c, "output-filename") == Some("output.json")
                && conf_value(c, "output-format") == Some("json"),
            "",
        );
    }
    // The resume.
    common(r, resume, &["Completed"]);
    if resume.stderr.is_some() {
        detection(r, resume, Detect::Auto { given_port: true });
    }
    beh(
        r,
        resume,
        "the resume keeps the run's source port and seed",
        source_port(resume, 0) == source_port(pause, 0),
        format!(
            "{:?} and {:?}",
            source_port(pause, 0),
            source_port(resume, 0)
        ),
    );
    let (Some(l1), Some(l2), Some(port), Some(k)) =
        (pause.link(0), resume.link(0), source_port(pause, 0), k)
    else {
        return;
    };
    let mut p = PlanSpec::single(PAUSE_PORTS, PAUSE_RATE, port);
    if let Some(plan) = plan_of(r, pause, &p) {
        let full = &plan[0];
        let k = k as usize;
        cap(
            r,
            pause,
            "the SYNs before the pause are the plan's first ones, in order",
            l1.syn_frames() == full[..k.min(full.len())],
            format!("{} SYNs", l1.wire.syns.len()),
        );
        cap(
            r,
            resume,
            "--resume sends exactly the rest of the plan, in order, from resume-index on",
            l2.syn_frames() == full[k.min(full.len())..],
            format!(
                "{} SYNs, {} remain",
                l2.wire.syns.len(),
                full.len().saturating_sub(k)
            ),
        );
        let mut joined = l1.syn_frames();
        joined.extend(l2.syn_frames());
        let (mut a, mut b) = (joined, full.clone());
        a.sort();
        b.sort();
        cap(
            r,
            resume,
            "the SYNs of both runs are the multiset of the continuous scan (one adapter: exact, none lost, none twice)",
            a == b,
            format!("{} of {}", a.len(), b.len()),
        );
    }
    p.resume_index = k;
    // The output: the pause's file kept, the resume appended one more document.
    if let (Some(raw1), Some(raw2)) = (&pause.raw, &resume.raw) {
        beh(
            r,
            resume,
            "output-append: the file begins with the paused run's file, byte for byte",
            raw2.starts_with(raw1),
            format!("{} and {} bytes", raw1.len(), raw2.len()),
        );
        let tail = raw2.get(raw1.len()..).unwrap_or_default();
        let doc2 = ov::parse_doc(Format::Json, tail);
        match &doc2 {
            Ok(doc) => {
                beh(
                    r,
                    resume,
                    "the appended part is one well-formed, complete document",
                    doc.complete && !doc.records.is_empty(),
                    format!("{} records", doc.records.len()),
                );
                no_duplicate(r, resume, doc);
            }
            Err(e) => beh(
                r,
                resume,
                "the appended part is one well-formed, complete document",
                false,
                e,
            ),
        }
        if let (Some(d1), Ok(d2)) = (&doc1, &doc2) {
            let (k1, k2): (BTreeSet<Key>, BTreeSet<Key>) = (
                keys(d1).into_iter().collect(),
                keys(d2).into_iter().collect(),
            );
            r.beh(
                "the two documents share no record (one adapter: nothing is sent twice)",
                k1.is_disjoint(&k2),
                format!("{} shared", k1.intersection(&k2).count()),
            );
            let found: BTreeSet<Key> = k1.union(&k2).copied().collect();
            r.beh(
                "the two documents together are the stand's replies to all 80 probes",
                found == wanted,
                format!("{} of {}", found.len(), wanted.len()),
            );
        }
    }
}

// ------------------------------------------------------------------ sc03

/// `--retries 2`: C walks `(retries+1) * range` outer indices and sends `retries+1` probes at each (design §4.1), so
/// every probe is on the wire `(2+1)^2` times.
const RETRY_SENDS: usize = 9;

fn sc03(r: &mut Run, sides: &[Side]) {
    let [rm, or] = sides else { return };
    let all = probe_pairs(&port_list(PORTS));
    let wanted = stand_keys(&port_list(PORTS));
    common(r, rm, &["Completed"]);
    if rm.stderr.is_some() {
        detection(r, rm, Detect::Auto { given_port: false });
    }
    let doc = single_doc(r, rm);
    if let Some(d) = &doc {
        beh(
            r,
            rm,
            "the output is complete (its footer written)",
            d.complete,
            "",
        );
        no_duplicate(r, rm, d);
        beh(
            r,
            rm,
            "the output holds the stand's replies, each once (the repeated replies are deduplicated)",
            keys(d).into_iter().collect::<BTreeSet<_>>() == wanted,
            format!("{} records", d.records.len()),
        );
    }
    for s in [rm, or] {
        if let Some(l) = s.link(0) {
            let c = counts(l.pairs());
            beh(
                r,
                s,
                "--retries 2 puts every probe on the wire (2+1)^2 = 9 times (main.c:421-431: three passes of the index, three sends each)",
                c.len() == all.len() && c.values().all(|n| *n == RETRY_SENDS),
                format!(
                    "{} probes, counts {:?}",
                    c.len(),
                    c.values().collect::<BTreeSet<_>>()
                ),
            );
        }
    }
    if let (Some(l), Some(port)) = (rm.link(0), source_port(rm, 0)) {
        let mut p = PlanSpec::single(PORTS, RATE, port);
        p.retries = 2;
        if let Some(plan) = plan_of(r, rm, &p) {
            plan_check(r, rm, 0, &plan[0], "plan of --retries 2");
        }
        if let Some(o) = or.link(0) {
            cap(
                r,
                rm,
                "the multiset of probes on the wire equals the oracle's",
                counts(l.pairs()) == counts(o.pairs()),
                format!("{} and {} SYNs", l.pairs().len(), o.pairs().len()),
            );
        }
    }
    common(r, or, &["Completed"]);
    if let Some(d) = single_doc(r, or) {
        oracle_doc(r, or, &d);
        beh(
            r,
            or,
            "the oracle's findings are the stand's replies",
            keys(&d).into_iter().collect::<BTreeSet<_>>() == wanted,
            format!("{} records", d.records.len()),
        );
        if let Some(m) = &doc {
            r.beh(
                "rmasscan's findings equal the oracle's",
                keys(m).into_iter().collect::<BTreeSet<_>>()
                    == keys(&d).into_iter().collect::<BTreeSet<_>>(),
                format!("{} and {} records", m.records.len(), d.records.len()),
            );
        }
    }
    r.notes
        .insert("oracle_forced_exit".into(), json!(or.forced_exit));
}

// ------------------------------------------------------------------ sc04

/// The `--pcap` file: the classic header of rawsock-pcapfile.c, then 16-byte record headers and the frames.
const PCAP_HEADER: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0,
    0, 0,
];
/// The records of a scanner's own capture file, strictly: the exact header, every record header's two lengths equal
/// and within 1514 bytes, no byte left over.
pub fn scanner_pcap_frames(b: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if b.get(..24) != Some(&PCAP_HEADER[..]) {
        return Err("the 24-byte header is not the classic little-endian one (d4c3b2a1, 2.4, snaplen 65535, Ethernet)".into());
    }
    let mut i = 24;
    let mut out = Vec::new();
    while i < b.len() {
        let h = b.get(i..i + 16).ok_or("a record header cut short")?;
        let (incl, orig) = (
            u32::from_le_bytes([h[8], h[9], h[10], h[11]]) as usize,
            u32::from_le_bytes([h[12], h[13], h[14], h[15]]) as usize,
        );
        if incl != orig || incl > 1514 {
            return Err(format!(
                "record {} has lengths {incl} and {orig}",
                out.len()
            ));
        }
        out.push(
            b.get(i + 16..i + 16 + incl)
                .ok_or("a record cut short")?
                .to_vec(),
        );
        i += 16 + incl;
    }
    Ok(out)
}
fn sc04(r: &mut Run, d: &Path, sides: &[Side]) {
    let [mods, bad] = sides else { return };
    let wanted = stand_keys(&port_list(PORTS));
    common(r, mods, &["Completed"]);
    if mods.stderr.is_some() {
        detection(r, mods, Detect::Auto { given_port: false });
    }
    let doc = single_doc(r, mods);
    if let Some(dc) = &doc {
        beh(
            r,
            mods,
            "the output is complete and holds the stand's replies (the peer answered the modified SYNs)",
            dc.complete && keys(dc).into_iter().collect::<BTreeSet<_>>() == wanted,
            format!("{} records", dc.records.len()),
        );
    }
    if let Some(l) = mods.link(0) {
        let infos: Vec<Option<SynInfo>> = l.wire.syns.iter().map(|(_, f)| syn_info(f)).collect();
        let want_opts = vec![TcpOpt::Mss(1460), TcpOpt::SackOk, TcpOpt::WScale(7)];
        beh(
            r,
            mods,
            "12 SYNs on the wire",
            infos.len() == 12,
            infos.len(),
        );
        cap(
            r,
            mods,
            "every SYN has TTL 42 (--ttl 42)",
            infos
                .iter()
                .all(|i| i.as_ref().is_some_and(|i| i.ttl == 42)),
            "",
        );
        cap(
            r,
            mods,
            "every SYN carries MSS 1460, SACK-permitted and window scale 7 in that order, zero-padded (--tcp-sackok --tcp-wscale 7)",
            infos.iter().all(|i| {
                i.as_ref()
                    .is_some_and(|i| i.options.as_ref() == Ok(&want_opts))
            }),
            format!(
                "{:?}",
                infos.first().map(|i| i.as_ref().map(|i| i.options.clone()))
            ),
        );
        cap(
            r,
            mods,
            "every SYN's IPv4 header checksum, TCP checksum and total length are valid",
            infos.iter().all(|i| {
                i.as_ref()
                    .is_some_and(|i| i.ip_header_ok && i.tcp_checksum_ok && i.length_ok)
            }),
            "",
        );
        if let Some(port) = source_port(mods, 0) {
            let mut p = PlanSpec::single(PORTS, RATE, port);
            p.mods = Mods {
                ttl: Some(42),
                sackok: true,
                wscale: Some(7),
                ..Mods::default()
            };
            if let Some(plan) = plan_of(r, mods, &p) {
                plan_check(
                    r,
                    mods,
                    0,
                    &plan[0],
                    "plan with --ttl 42 --tcp-sackok --tcp-wscale 7",
                );
            }
        }
        scanner_pcap(r, d, mods, l);
    }
    // --badsum, a run of its own.
    common(r, bad, &["Completed"]);
    if bad.stderr.is_some() {
        detection(r, bad, Detect::Auto { given_port: false });
    }
    if let Some(l) = bad.link(0) {
        let infos: Vec<Option<SynInfo>> = l.wire.syns.iter().map(|(_, f)| syn_info(f)).collect();
        beh(
            r,
            bad,
            "12 SYNs on the wire",
            infos.len() == 12,
            infos.len(),
        );
        cap(
            r,
            bad,
            "every SYN's TCP checksum is invalid while its IPv4 header checksum is valid (--badsum)",
            infos.iter().all(|i| {
                i.as_ref()
                    .is_some_and(|i| !i.tcp_checksum_ok && i.ip_header_ok)
            }),
            "",
        );
        cap(
            r,
            bad,
            "every SYN has the default TTL 255",
            infos
                .iter()
                .all(|i| i.as_ref().is_some_and(|i| i.ttl == 255)),
            "",
        );
        cap(
            r,
            bad,
            "the peer answered none of them (a segment with a bad checksum is dropped)",
            l.replies().is_empty(),
            l.replies().len(),
        );
        if let Some(port) = source_port(bad, 0) {
            let mut p = PlanSpec::single(PORTS, RATE, port);
            p.mods.badsum = true;
            if let Some(plan) = plan_of(r, bad, &p) {
                plan_check(r, bad, 0, &plan[0], "plan with --badsum");
            }
        }
    }
    if let Some(dc) = single_doc(r, bad) {
        beh(
            r,
            bad,
            "the output holds no record",
            dc.records.is_empty(),
            dc.records.len(),
        );
    }
}
/// The scanner's `--pcap` file: its format, and that it holds the frames addressed to its ip:port and only those.
fn scanner_pcap(r: &mut Run, d: &Path, s: &Side, l: &LinkCap) {
    let Ok(b) = fs::read(d.join(s.spec.name).join(SCANNER_PCAP)) else {
        r.add(
            &format!("{}/{SCANNER_PCAP} present", s.spec.name),
            NOT_RUN,
            "missing",
            false,
        );
        return;
    };
    let frames = match scanner_pcap_frames(&b) {
        Ok(f) => {
            r.beh(&format!("{}: {SCANNER_PCAP} is a classic pcap with equal record lengths up to 1514 bytes", s.spec.name), true, format!("{} frames", f.len()));
            f
        }
        Err(e) => {
            r.beh(&format!("{}: {SCANNER_PCAP} is a classic pcap with equal record lengths up to 1514 bytes", s.spec.name), false, e);
            return;
        }
    };
    let Some(port) = source_port(s, 0) else {
        return;
    };
    let st = &l.stand;
    let mine = |f: &Vec<u8>| {
        tcp(f).is_some_and(|i| {
            i.dm == av::dash(st.scanner_mac).replace('-', ":")
                && i.dst == st.scanner_ip.to_string()
                && i.dp == port
                && i.src
                    .parse::<Ipv4Addr>()
                    .is_ok_and(|ip| st.peer_ips.contains(&ip))
        })
    };
    let stray = frames.iter().filter(|f| !mine(f)).count();
    r.beh(
        &format!("{}: {SCANNER_PCAP} holds only frames to the scanner's ip:port from the stand's peers (no ARP, no SYN out, no foreign frame)", s.spec.name),
        stray == 0,
        format!("{stray} of {} frames", frames.len()),
    );
    let on_wire: BTreeSet<&Vec<u8>> = l.frames.iter().map(|(_, f)| f).collect();
    let missing = frames.iter().filter(|f| !on_wire.contains(f)).count();
    r.cap(
        &format!(
            "{}: every frame of {SCANNER_PCAP} is a frame the peer sent, byte for byte",
            s.spec.name
        ),
        missing == 0,
        format!("{missing} of {} not on the peer capture", frames.len()),
    );
    // Every kind of reply the peer sent to a SYN of this run is in the file (SYN-ACK or RST, per peer address and port).
    let kind = |f: &[u8]| tcp(f).map(|i| (i.src, i.sp, i.flags & 0x12 == 0x12));
    let have: BTreeSet<_> = frames.iter().filter_map(|f| kind(f)).collect();
    let replies: BTreeSet<_> = l
        .replies()
        .into_iter()
        .map(|(_, (st_, ip, port))| (ip.to_string(), port.unwrap_or(0), st_ == Some(Status::Open)))
        .collect();
    r.cap(
        &format!("{}: {SCANNER_PCAP} holds a SYN-ACK or RST from every peer address and port that answered", s.spec.name),
        replies.is_subset(&have),
        format!("{} of {} replies", replies.intersection(&have).count(), replies.len()),
    );
}

// ------------------------------------------------------------------ sc05

fn sc05(r: &mut Run, d: &Path, sides: &[Side]) {
    let [run] = sides else { return };
    let all = probe_pairs(&port_list(PORTS));
    let wanted = stand_keys(&port_list(PORTS));
    common(r, run, &["Paused", "Stopped"]);
    if run.stderr.is_some() {
        detection(r, run, Detect::Auto { given_port: false });
    }
    let e = &run.se;
    beh(
        r,
        run,
        "stderr.txt carries the Ctrl-C line once",
        e.count(Ev::Interrupt) == 1,
        e.count(Ev::Interrupt),
    );
    beh(
        r,
        run,
        "the status line is the infinite form (syn/s ack/s tcb-rate), never a percentage",
        e.count(Ev::Infinite) >= 1 && e.count(Ev::Running) == 0,
        format!(
            "{} infinite ticks, {} percentage ticks",
            e.count(Ev::Infinite),
            e.count(Ev::Running)
        ),
    );
    beh(
        r,
        run,
        "no `saving resume file` (an infinite scan has nothing to resume)",
        e.count(Ev::Saving) == 0,
        e.count(Ev::Saving),
    );
    interrupt_checks(r, run, INFINITE_AFTER_S, run.link(0));
    if let Some(i) = &run.interrupt {
        beh(
            r,
            run,
            "no paused.conf was left in the scanner's directory",
            !i.paused_conf_present && !d.join(run.spec.name).join(PAUSED_EVIDENCE).exists(),
            i.paused_conf_present,
        );
    }
    let doc = single_doc(r, run);
    if let Some(dc) = &doc {
        beh(
            r,
            run,
            "the output is complete after the interrupt (its footer written)",
            dc.complete,
            "",
        );
        beh(
            r,
            run,
            "the output holds every one of the stand's replies",
            wanted.is_subset(&keys(dc).into_iter().collect())
                && keys(dc).into_iter().all(|k| wanted.contains(&k)),
            format!("{} records", dc.records.len()),
        );
    }
    if let Some(l) = run.link(0) {
        let pairs = l.pairs();
        let n = all.len();
        beh(
            r,
            run,
            "more than one full pass: every probe was sent at least twice",
            pairs.len() > n
                && counts(pairs.iter().copied()).values().all(|c| *c >= 2)
                && counts(pairs.iter().copied()).len() == n,
            format!("{} SYNs for {n} probes", pairs.len()),
        );
        let passes_ok = pairs
            .chunks(n)
            .filter(|c| c.len() == n)
            .all(|c| c.iter().copied().collect::<BTreeSet<_>>() == all);
        beh(
            r,
            run,
            "every full pass of the SYN stream is a permutation of the 12 probes",
            passes_ok,
            format!("{} passes", pairs.len() / n),
        );
        if let Some(port) = source_port(run, 0) {
            let plan = plan_of(r, run, &PlanSpec::single(PORTS, RATE, port));
            if let Some(p) = plan {
                let first: Vec<Vec<u8>> = l.syn_frames().into_iter().take(p[0].len()).collect();
                let (ok, d) = same_stream(&first, &p[0]);
                cap(r, run, "the first pass is the plan's, byte for byte", ok, d);
            }
        }
    }
}

// ------------------------------------------------------------------ sc06

/// A step's SYNs per link against the plan of `nics`.
fn dual_plan(
    r: &mut Run,
    s: &Side,
    ports: &str,
    rate: &str,
    resume: u64,
) -> Option<Vec<Vec<Vec<u8>>>> {
    let (p0, p1) = (source_port(s, 0)?, source_port(s, 1)?);
    let mut p = PlanSpec::single(ports, rate, p0);
    p.nics.push(NicPlan { link: 1, port: p1 });
    p.resume_index = resume;
    plan_of(r, s, &p)
}
fn sc06(r: &mut Run, d: &Path, sides: &[Side]) {
    let [dual, pause, resume] = sides else { return };
    // The whole scan over two adapters: an exact even/odd partition of the plan.
    let all = probe_pairs(&port_list(PORTS));
    common(r, dual, &["Completed"]);
    if dual.stderr.is_some() {
        detection(r, dual, Detect::Dual { given_port: false });
    }
    if let (Some(l0), Some(l1)) = (dual.link(0), dual.link(1)) {
        if let Some(plan) = dual_plan(r, dual, PORTS, RATE, 0) {
            plan_check(
                r,
                dual,
                0,
                &plan[0],
                "plan of --adapter[0] (outer indices 0, 2, 4, ...)",
            );
            plan_check(
                r,
                dual,
                1,
                &plan[1],
                "plan of --adapter[1] (outer indices 1, 3, 5, ...)",
            );
        }
        let (p0, p1) = (l0.pairs(), l1.pairs());
        beh(
            r,
            dual,
            "both adapters carried probes",
            !p0.is_empty() && !p1.is_empty(),
            format!("{} and {}", p0.len(), p1.len()),
        );
        let c = counts(p0.iter().chain(&p1).copied());
        cap(
            r,
            dual,
            "the two links together carry all 12 probes exactly once (no loss, no duplicate)",
            c.len() == all.len() && c.values().all(|n| *n == 1),
            format!("{} probes, {} SYNs", c.len(), p0.len() + p1.len()),
        );
        cap(
            r,
            dual,
            "the replies to the second adapter's SYNs came back on the second link",
            !l1.replies().is_empty() && l1.replies().len() == p1.len(),
            format!("{} replies for {} SYNs", l1.replies().len(), p1.len()),
        );
    }
    if let Some(dc) = single_doc(r, dual) {
        beh(
            r,
            dual,
            "the output is complete and holds the stand's replies, each once",
            dc.complete
                && keys(&dc).len() == stand_keys(&port_list(PORTS)).len()
                && keys(&dc).into_iter().collect::<BTreeSet<_>>() == stand_keys(&port_list(PORTS)),
            format!("{} records", dc.records.len()),
        );
    }
    // Pause and resume over two adapters: no loss, bounded duplicates (spec §4.3), not an exact multiset.
    common(r, pause, &["Paused"]);
    if pause.stderr.is_some() {
        detection(r, pause, Detect::Dual { given_port: false });
    }
    paused_step(r, pause, 2);
    interrupt_checks(r, pause, PAUSE_AFTER_S, pause.link(0));
    let doc1 = single_doc(r, pause);
    if let Some(dc) = &doc1 {
        beh(
            r,
            pause,
            "the output is complete after the pause (the `]` footer written)",
            dc.complete,
            "",
        );
        if let (Some(l0), Some(l1)) = (pause.link(0), pause.link(1)) {
            let have: BTreeSet<Key> = keys(dc).into_iter().collect();
            let wire: BTreeSet<Key> = l0.reply_keys().union(&l1.reply_keys()).copied().collect();
            cap(
                r,
                pause,
                "the output holds every reply on both links to the SYNs sent before the pause",
                have == wire,
                format!("{} records, {} replies", have.len(), wire.len()),
            );
        }
    }
    let conf = paused_conf(d, pause);
    r.inv(
        "dual_pause/paused.txt is the scanner's paused.conf",
        conf.as_ref()
            .is_some_and(|c| conf_value(c, "resume-index").is_some()),
        "",
    );
    let m = conf
        .as_ref()
        .and_then(|c| conf_value(c, "resume-index"))
        .and_then(|v| v.parse::<u64>().ok());
    let (a0, a1) = (
        pause.link(0).map_or(0, |l| l.wire.syns.len()) as u64,
        pause.link(1).map_or(0, |l| l.wire.syns.len()) as u64,
    );
    if let (Some(c), Some(m)) = (&conf, m) {
        // Adapter k's i-th probe has outer index k + 2i: after a_k probes its base is 2*a_k (main.c:269, 1408-1414).
        beh(
            r,
            pause,
            "paused.conf: resume-index is the minimum of the adapters' bases (2 x SYNs sent per link), inside the scan",
            m == (2 * a0).min(2 * a1)
                && m > 0
                && (m as usize) < probe_pairs(&port_list(PAUSE_PORTS)).len(),
            format!("{m}, links sent {a0} and {a1}"),
        );
        beh(
            r,
            pause,
            "paused.conf names both adapters",
            conf_value(c, "adapter[1]") == Some("veth-a2")
                && conf_value(c, "adapter-ip[1]") == Some("198.18.0.6"),
            format!("{c:?}"),
        );
    }
    // The resume.
    common(r, resume, &["Completed"]);
    if resume.stderr.is_some() {
        detection(r, resume, Detect::Dual { given_port: true });
    }
    let (Some(m), true) = (m, pause.captured() && resume.captured()) else {
        return;
    };
    let ports = port_list(PAUSE_PORTS);
    let (p_plan, r_plan) = (
        dual_plan(r, pause, PAUSE_PORTS, PAUSE_RATE, 0),
        dual_plan(r, resume, PAUSE_PORTS, PAUSE_RATE, m),
    );
    let mut total: BTreeMap<(Ipv4Addr, u16), usize> = BTreeMap::new();
    for k in 0..2 {
        let (Some(lp), Some(lr)) = (pause.link(k), resume.link(k)) else {
            continue;
        };
        if let Some(plan) = &p_plan {
            let n = lp.wire.syns.len();
            cap(
                r,
                pause,
                &format!("link {k}: the SYNs before the pause are the plan's first ones, in order"),
                lp.syn_frames() == plan[k][..n.min(plan[k].len())],
                format!("{n} SYNs"),
            );
        }
        if let Some(plan) = &r_plan {
            plan_check(
                r,
                resume,
                k,
                &plan[k],
                &format!("plan of the resume from resume-index {m}, adapter {k}"),
            );
        }
        for p in lp.pairs().into_iter().chain(lr.pairs()) {
            *total.entry(p).or_insert(0) += 1;
        }
    }
    let want = probe_pairs(&ports);
    r.cap(
        "no loss: every probe of the scan was sent by one of the two runs",
        want.iter().all(|p| total.contains_key(p)),
        format!(
            "{} of {} probes",
            total.keys().filter(|p| want.contains(p)).count(),
            want.len()
        ),
    );
    r.cap(
        "bounded duplicates: no probe was sent more than twice (the adapter ahead of the minimum resends its own probes once)",
        total.values().all(|n| *n <= 2),
        format!("most sent {:?} times", total.values().max()),
    );
    r.notes.insert(
        "resent_probes".into(),
        json!(total.values().filter(|n| **n > 1).count()),
    );
    if let (Some(raw1), Some(raw2)) = (&pause.raw, &resume.raw) {
        beh(
            r,
            resume,
            "output-append: the file begins with the paused run's file, byte for byte",
            raw2.starts_with(raw1),
            format!("{} and {} bytes", raw1.len(), raw2.len()),
        );
        let tail = raw2.get(raw1.len()..).unwrap_or_default();
        match (ov::parse_doc(Format::Json, tail), &doc1) {
            (Ok(doc2), Some(doc1)) => {
                beh(
                    r,
                    resume,
                    "the appended part is one well-formed, complete document",
                    doc2.complete,
                    format!("{} records", doc2.records.len()),
                );
                let (mut k1, mut k2) = (BTreeMap::new(), BTreeMap::new());
                for k in keys(doc1) {
                    *k1.entry(k).or_insert(0usize) += 1;
                }
                for k in keys(&doc2) {
                    *k2.entry(k).or_insert(0usize) += 1;
                }
                let found: BTreeSet<Key> = k1.keys().chain(k2.keys()).copied().collect();
                r.beh(
                    "no loss: the two documents together hold the stand's replies to all 80 probes",
                    found == stand_keys(&ports),
                    format!("{} of {}", found.len(), stand_keys(&ports).len()),
                );
                let worst = found
                    .iter()
                    .map(|k| k1.get(k).unwrap_or(&0) + k2.get(k).unwrap_or(&0))
                    .max();
                r.beh(
                    "bounded duplicates: no record is in the two documents more than twice",
                    worst.is_none_or(|w| w <= 2),
                    format!("{worst:?}"),
                );
            }
            (Err(e), _) => beh(
                r,
                resume,
                "the appended part is one well-formed, complete document",
                false,
                e,
            ),
            _ => {}
        }
    }
}

// ------------------------------------------------------------------ one case

fn verify_run(root: &Path, tag: &'static str, root_links: &[String]) -> Run {
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
    // ---- safety and the witnesses, per step and link
    let mut sides = Vec::new();
    for spec in &specs {
        sides.push(read_side(&mut r, &d, spec, &t.links));
    }
    for s in &sides {
        for (k, l) in s.links.iter().enumerate() {
            if let Some(l) = l {
                let who = format!("{}/link {k}", s.spec.name);
                let n = av::foreign_syns(&l.frames, &l.stand);
                r.safety(
                    &format!("no SYN on the {who} capture from outside the stand binding or to an address off the stand"),
                    n == 0,
                    n,
                );
                av::no_foreign_frame(&mut r, &who, &l.frames, &l.stand);
            }
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
    // ---- the case: expect.json and every argv.json are exactly the table's
    let expect_rec: Option<ScExpect> = av::typed(&mut r, &d, EXPECT_JSON);
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
    match tag {
        "sc01_shards_union" => sc01(&mut r, &sides),
        "sc02_pause_wait_resume" => sc02(&mut r, &d, &sides),
        "sc03_retries" => sc03(&mut r, &sides),
        "sc04_packet_mods_and_pcap" => sc04(&mut r, &d, &sides),
        "sc05_infinite_interrupt" => sc05(&mut r, &d, &sides),
        "sc06_dual_veth" => sc06(&mut r, &d, &sides),
        _ => {}
    }
    r.notes.insert("oracle".into(), json!(oracle_note(tag)));
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
        .and_then(|v| serde_json::from_value::<ScManifest>(v).ok())
        .filter(|x| x.scan_control == "linux");
    m.check(
        "manifest.json names the scan-control plan (linux)",
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
    let odd: Vec<&String> = outside.iter().filter(|f| !evidence_extension(f)).collect();
    m.inv(
        "evidence files outside the runs carry only the allowed extensions (json pcap txt log err sha256 md)",
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
        runs.extend(TAGS.iter().map(|tag| {
            let mut r = verify_run(root, tag, &t.links);
            let earlier: Vec<String> = attempts
                .iter()
                .filter(|a| a.case == Some(*tag))
                .map(|a| format!("runs_aborted/{}", a.name))
                .collect();
            if !earlier.is_empty() {
                r.inv("no aborted attempt of this case in runs_aborted/ (a case runs once into one --out)", false, earlier.join(", "));
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
    let mut scan = av::stray_scan(root, Some(Plan::Linux), &tags, &t);
    scan.extend(stray_second_link(root, &tags, &t));
    result["safety_scan"] = json!(scan);
    verify::finish(result)
}

/// The second link's captures outside the planned cases (aborted attempts): `stray_scan` reads `peer.pcap` against the
/// first stand only.
fn stray_second_link(root: &Path, tags: &[&'static str], t: &Tree) -> Vec<Value> {
    let planned = |rel: &str| {
        tags.iter()
            .any(|tag| rel.starts_with(&format!("runs/{tag}/")))
    };
    let st = link_stand(1);
    let mut out = Vec::new();
    for f in t
        .files
        .iter()
        .filter(|f| f.ends_with(PEER_FILES[1][0]) && !planned(f))
    {
        let mut r = Run::new(f);
        r.argv_ok = true;
        if let Some((fr, _)) = verify::load_pcap(&mut r, &root.join(f)) {
            let n = av::foreign_syns(&fr, &st);
            r.safety("no SYN on the second-link capture from outside the stand binding or to an address off the stand", n == 0, n);
            av::no_foreign_frame(&mut r, "second-link", &fr, &st);
        }
        out.push(r.summary());
    }
    out
}

/// `scan-control-verify --dir DIR [--out FILE]`: 0 PASS, 1 FAIL, 2 INVALID or NOT RUN.
pub fn run(args: &[String]) -> Result<i32, String> {
    let o = crate::windows_suite::options_for("scan-control-verify", args, &["dir", "out"])?;
    if o.contains_key("help") {
        println!(
            "scan-control-verify --dir DIR [--out FILE]  (exit 0 PASS, 1 FAIL, 2 INVALID or NOT RUN)"
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
#[path = "scan_control_verify_tests.rs"]
pub(crate) mod tests;
