//! The TCP banner case of the Windows VM stand (`windows-suite --plan banners`) and of the macOS `feth` stand
//! (`macos-suite --plan banners`), sub-stage 4b task 18: the one case table both suites run, the copy of the C
//! reference they take from the Linux banners window, and the offline verifier that `windows-verify` and
//! `macos-verify` hand such a directory to (manifest key [`MANIFEST_KEY`]), as they hand an `autodetect` one to
//! `autodetect-verify`.
//!
//! One case per stand ([`WINDOWS`], [`MACOS`]): the rmasscan CLI with `--banners` (`wire_scan` has no TCP stack) scans
//! the HTTP and the SSH scenario of the banners window (`banners_verify::TCP_SCENARIOS`, peer `198.18.0.2`: the HTTP
//! request answered with Server and a title, then the server's FIN; an SSH-2.0 ident answered with the scanner's).
//! The peer's kernel sockets run the scenarios' scripts (`peer listen --banners`, `capture::run_script`). Only rmasscan
//! runs on these stands, so there is no heartbeat (rmasscan's timers run on a quiet link: `t09_quiet_timers`).
//!
//! - Windows: the scanner's source is the guest's own address `198.18.0.1` (given, so the R9 warning stays silent),
//!   ports 22 and 80. masscan's README (banner checking) claims "Windows doesn't respond with RST packets, so neither
//!   of these techniques are necessary": the guest's TCP/IP stack sees every SYN-ACK and segment of the scan. Any
//!   frame of the guest MAC on a scanned connection that is not rmasscan's own stack frame is the guest's stack, and
//!   the run is INVALID with the claim noted as refuted (`windows_no_rst`); without one the claim holds for this guest
//!   (its firewall state is recorded beside, `guest-firewall.json`).
//! - macOS: the scanner's source `198.18.0.1` is assigned to no interface (`feth4201` has no IPv4, `macos-lab status`
//!   rule 2): otherwise the kernel would reset every banner connection. A frame of the scanner MAC on a scanned
//!   connection that is not rmasscan's is the kernel's (INVALID). A process that is not root may bind a reserved port on
//!   Darwin only on INADDR_ANY (`in_pcbbind` since 10.14) and the stand has no root listener and no wildcard one, so the
//!   HTTP scenario runs on 8080 and the SSH one on 2222: C's hello table sends the same request on 8080 as on 80 and
//!   nothing on 22 or 2222 (`banner1_create`, `src/proto-banner1.c:518-610`; the pinned C output
//!   `tests/golden/tcp-banners/hellos.out`, checked here, [`hello_table_problems`]), and no parser of the two looks at
//!   the port (SMTP's 25/587 rule aside, `src/proto-banner1.c:194-204`), so the records are C's with the port mapped.
//!
//! The reference ([`copy_reference`]) is C's own run of the same scenarios on the Linux stand: the C oracle's `-oL`
//! step of `t01_tcp4` (`runs/t01_tcp4/oracle-list/`: `argv.json`, `output.txt`, `peer.pcap`), copied with the hashes
//! the Linux case recorded and that window's `verdict.json`, in which `t01_tcp4` must be PASS. From it: C's records of
//! `198.18.0.2` on 22 and 80, and what C sent on those two connections (its payload segments, in order).
//!
//! The verdict is by records: rmasscan's `-oL` records of the two connections equal C's as a multiset, field for field
//! but the time (the port mapped on macOS), each connection's banners carry its scenario's applications in one run after
//! its `open` (M1), and nothing else is in the document. On the wire: the SYNs are the product plan's on the stand
//! binding, every frame of the scanner MAC is explained, rmasscan's payloads on each connection equal C's (another hello
//! than C's is a FAIL), the hello leaves 1.0-3.5 s after the SYN-ACK, no RST of rmasscan (both scenarios end with FIN;
//! R8's RST to a FIN after a connection's end aside) and no frame after a connection's end. The stand (INVALID, never a
//! FAIL): one SYN-ACK per SYN, the peer streamed its scenario, no RST or other frame of the peer, no frame of the host's
//! own stack, the reference proven, the gates and the witness. Checks run in that order (the scanner's own evidence,
//! the stand, the rest), so that `cap` books a fault on the side that made it.
//!
//! Layout of a directory: `manifest.json` (key `banners_stand`: `windows` or `macos`), `reference/` (above, with
//! `source.json` and `verdict.json`), `runs/<tag>/` with `argv.json` ([`StandCase::argv`]), `expect.json`
//! ([`StandExpect`]), `listeners.json`, `output.txt`, `peer.pcap`, `capture.json`, `status-pre.json`,
//! `status-post.json`, `hashes-before-copy.txt` and the stand's own files (Windows: `guest-stdout.txt`,
//! `guest-stderr.txt`, `guest-exit.txt`, `guest-firewall.json`, `eno1.pcap`, `eno1.err`, ...; macOS: `stdout.txt`,
//! `stderr.txt`, `exit.txt`, `alf.txt`, `uplink.pcap`, `uplink.err`, ...).
use crate::{
    autodetect_verify::{self as av, ArgvRecord, Plan},
    banners_verify::{self as bv, Body, Conn, Document, Rec, Seg, TcpScenario, tcp_head},
    ipv6_verify as iv,
    macos_verify::{Tree, hashes_match_tree, tree},
    pcap::Frames,
    protocols_verify::{Out, St},
    verify::{self, FAIL, INVALID, NOT_RUN, PASS, Run, array, read_json, s, sha},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

// ------------------------------------------------------------------ the case table

/// The manifest key that names a directory of this case and its stand (`windows` or `macos`).
pub const MANIFEST_KEY: &str = "banners_stand";
/// The scanner's `-oL` document, in its working directory and in the evidence.
pub const OUTPUT: &str = "output.txt";
pub const EXPECT_JSON: &str = "expect.json";
pub const LISTENERS_JSON: &str = "listeners.json";
/// The copy of the C reference inside an evidence directory, and its record.
pub const REFERENCE_DIR: &str = "reference";
pub const REFERENCE_SOURCE: &str = "source.json";
pub const REFERENCE_VERDICT: &str = "verdict.json";
/// The Linux window's case and C step the reference is taken from, and its files.
pub const REFERENCE_CASE: &str = "t01_tcp4";
pub const REFERENCE_STEP: &str = "oracle-list";
pub const REFERENCE_FILES: [&str; 3] = ["argv.json", "output.txt", "peer.pcap"];
/// `t01_tcp4`'s lifetime and wait: the scenarios end long before either, so rmasscan and C behave alike.
pub const CONNECTION_TIMEOUT: u32 = 8;
pub const WAIT: u32 = 14;
/// The peer of every scenario of the case.
pub const PEER: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
/// The pinned C output of `banner1_create`'s hello table (`src/proto-banner1.c:518-610`), one line per port.
const HELLOS: &str = include_str!("../../../tests/golden/tcp-banners/hellos.out");

/// The case of one stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandCase {
    pub plan: Plan,
    pub tag: &'static str,
    /// (port scanned on this stand, port of its scenario in the Linux window), in `-p` order.
    pub ports: [(u16, u16); 3],
    /// The stand's binding flags, between the ports and `-oL`.
    pub flags: &'static [&'static str],
}
/// The Windows VM stand `n2`: the guest's own address and the peer namespace's MAC as the next hop, no ARP of the
/// scanner (the peer still resolves `198.18.0.1`: the guest's kernel and rmasscan answer, `src/stack-arpv4.c:282-363`).
pub const WINDOWS: StandCase = StandCase {
    plan: Plan::Windows,
    tag: "wb01_banners",
    ports: [(22, 22), (80, 80), (443, 443)],
    flags: &[
        "--adapter-ip",
        "198.18.0.1",
        "--router-mac",
        "02-57-4c-3d-2e-9b",
    ],
};
/// The macOS `feth` stand `m1`: `m03_user_router_mac`'s binding (user mode, BPF granted), HTTP on 8080, SSH on 2222,
/// TLS on 8443 (the scenario of 443; C sends the same hello on both, so the mapping is sound by the hello table).
pub const MACOS: StandCase = StandCase {
    plan: Plan::Macos,
    tag: "mb01_banners",
    ports: [(2222, 22), (8080, 80), (8443, 443)],
    flags: &[
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
};
/// The case of a stand (`None` for the Linux plans).
pub fn case(plan: Plan) -> Option<StandCase> {
    match plan {
        Plan::Windows => Some(WINDOWS),
        Plan::Macos => Some(MACOS),
        Plan::Linux | Plan::MacosRoot => None,
    }
}
/// `expect.json`: the case as the suite planned it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StandExpect {
    pub tag: String,
    pub stand: Plan,
    pub source: String,
    /// (stand port, scenario port of the Linux window).
    pub ports: Vec<[u16; 2]>,
    /// The Linux window's case and C step the records are compared with.
    pub reference: String,
    pub connection_timeout: u32,
    pub wait: u32,
}
impl StandCase {
    /// The `-p` list.
    pub fn port_list(&self) -> String {
        self.ports
            .iter()
            .map(|(p, _)| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
    /// `peer listen --banners`: each port with its scenario's port when they differ.
    pub fn banners_arg(&self) -> String {
        self.ports
            .iter()
            .map(|(p, sp)| {
                if p == sp {
                    p.to_string()
                } else {
                    format!("{p}={sp}")
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }
    /// The scan, without the program name: the scenarios' peer and ports, `--banners` with `t01_tcp4`'s lifetime, the
    /// stand's binding, `-oL output.txt` in the scanner's working directory, `--seed 1 --rate 100 --wait 14
    /// --source-port 40000 --retries 0`.
    pub fn argv(&self) -> Vec<String> {
        let mut a = vec![
            PEER.to_string(),
            format!("-p{}", self.port_list()),
            "--banners".into(),
            "--connection-timeout".into(),
            CONNECTION_TIMEOUT.to_string(),
        ];
        a.extend(self.flags.iter().map(|f| (*f).to_owned()));
        crate::pair_verify::scan_tail(
            &mut a,
            Out::List,
            false,
            bv::RATE,
            &WAIT.to_string(),
            bv::SOURCE_PORT,
        );
        a.extend(["--retries".to_owned(), "0".to_owned()]);
        a
    }
    /// The Linux window's port of a scanned port.
    pub fn linux_port(&self, port: u16) -> Option<u16> {
        self.ports.iter().find(|(p, _)| *p == port).map(|x| x.1)
    }
    /// The scenario a scanned port answers with.
    pub fn scenario(&self, port: u16) -> Option<&'static TcpScenario> {
        bv::tcp_scenario(self.linux_port(port)?, IpAddr::V4(PEER))
    }
    pub fn expect(&self) -> StandExpect {
        StandExpect {
            tag: self.tag.into(),
            stand: self.plan,
            source: av::SCANNER_IP.to_string(),
            ports: self.ports.iter().map(|(p, sp)| [*p, *sp]).collect(),
            reference: format!("{REFERENCE_CASE}/{REFERENCE_STEP}"),
            connection_timeout: CONNECTION_TIMEOUT,
            wait: WAIT,
        }
    }
    /// The product's plan of the case on the stand's binding (its SYNs, and the template of its stack frames).
    pub fn ready_plan(&self) -> Result<rmasscan_core::probe::ReadyPlan, String> {
        use rmasscan_core::{
            config::{Operation, ScanConfig, parse_rate, validate},
            massip::MassIp,
            packet::LinkType,
            probe::{AdapterBinding, NicBinding, ReadyPlan},
            targets::parse_ports,
        };
        let st = av::stand(self.plan);
        let nic = NicBinding::from(AdapterBinding {
            interface_id: st.iface.into(),
            link_type: LinkType::Ethernet,
            source_ipv4: u32::from(st.scanner_ip),
            source_mac: st.scanner_mac,
            next_hop_mac: st.peer_mac,
            source_ports: (bv::SOURCE_PORT, bv::SOURCE_PORT),
        });
        let mut ips = MassIp::new();
        ips.add_target_string(&PEER.to_string())
            .map_err(|e| e.to_string())?;
        parse_ports(ips.ports_mut(), &self.port_list()).map_err(|e| e.to_string())?;
        let cfg = ScanConfig {
            targets: ips,
            seed: 1,
            max_rate: parse_rate(bv::RATE).map_err(|e| e.to_string())?,
            wait_secs: WAIT,
            adapter_ip: Some(u32::from(st.scanner_ip)),
            adapter_mac: Some(st.scanner_mac),
            router_mac: Some(st.peer_mac),
            source_port: Some((bv::SOURCE_PORT, bv::SOURCE_PORT)),
            adapter_name: Some(st.iface.into()),
            ..ScanConfig::default()
        };
        let eff = validate(&cfg, Operation::Scan).map_err(|e| e.to_string())?;
        ReadyPlan::new_cli(eff, vec![nic]).map_err(|e| e.to_string())
    }
}

/// C's hello for a port, from its pinned hello table (`None`: no hello, the NULL stream).
pub fn c_hello(port: u16) -> Option<String> {
    let want = format!("port={port}");
    HELLOS
        .lines()
        .filter_map(|l| l.strip_prefix("hello "))
        .find(|l| l.split(' ').next() == Some(want.as_str()))
        .and_then(|l| l.rsplit(' ').next())
        .map(str::to_owned)
}
/// The number of hello lines the table's header (`tcp-oracle hellos streams=N`) says it holds.
fn hello_table_streams() -> Option<usize> {
    HELLOS
        .lines()
        .next()?
        .strip_prefix("tcp-oracle hellos streams=")?
        .parse()
        .ok()
}
/// What is wrong with the pinned hello table for the stand's ports: its line count is not its header's (a line was
/// lost: "no line" would read as "C sends nothing"), a port whose scenario is answered by C's hello has no line, or a
/// scanned port's hello differs from the hello of its scenario's port in the Linux window (the macOS port mapping is
/// only sound when C sends the same on both).
pub fn hello_table_problems(c: &StandCase) -> Vec<String> {
    let mut out = Vec::new();
    let lines = HELLOS.lines().filter(|l| l.starts_with("hello ")).count();
    if hello_table_streams() != Some(lines) {
        out.push(format!(
            "the hello table holds {lines} lines, its header says {:?}",
            hello_table_streams()
        ));
    }
    for (p, sp) in c.ports {
        if c.scenario(p).is_some_and(|sc| !sc.server_first())
            && (c_hello(p).is_none() || c_hello(sp).is_none())
        {
            out.push(format!(
                "C's hello table has no line for {p} ({:?}) or {sp} ({:?}), whose scenario waits for the hello",
                c_hello(p),
                c_hello(sp)
            ));
        }
        if c_hello(p) != c_hello(sp) {
            out.push(format!(
                "C's hello on {p} ({:?}) is not its hello on {sp} ({:?})",
                c_hello(p),
                c_hello(sp)
            ));
        }
    }
    out
}

// ------------------------------------------------------------------ the reference

/// `reference/source.json`: where the copy of the C reference came from and what that window said of it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReferenceSource {
    /// The name of the Linux evidence directory (no path).
    pub source_dir: String,
    pub case: String,
    pub step: String,
    /// The verdict of [`REFERENCE_CASE`] in that window's `verdict.json`, and its overall one.
    pub run_verdict: String,
    pub overall: String,
    /// The sha256 of the copied `verdict.json`.
    pub verdict_sha256: String,
    /// The sha256 the Linux case recorded for each copied file (its `hashes-before-copy.txt`), by name.
    pub files: BTreeMap<String, String>,
}
/// The verdict of `tag` in a pair window's `verdict.json` (`runs[].tag`, `runs[].verdict`).
fn run_verdict(v: &Value, tag: &str) -> Option<String> {
    array(&v["runs"])
        .iter()
        .find(|r| r["tag"] == tag)
        .map(|r| s(&r["verdict"]).to_owned())
}
/// Copy the C reference from the Linux banners evidence directory `linux` into `out/reference/` (both suites, before
/// the first remote action): the window's manifest must be `banners: linux`, its `verdict.json` must say PASS for
/// `t01_tcp4` and so must the verdict of `banners-verify` on the window now (recomputed, not trusted from the file), and
/// every copied file must have the sha256 the Linux case recorded before its own copy. A copy that is
/// already there is kept only when it is the same.
pub fn copy_reference(linux: &Path, out: &Path) -> Result<ReferenceSource, String> {
    let man = read_json(linux.join("manifest.json"))
        .ok_or_else(|| format!("{}: no manifest.json", linux.display()))?;
    if man["banners"] != "linux" {
        return Err(format!(
            "{} is not a Linux banners window (manifest banners {})",
            linux.display(),
            man["banners"]
        ));
    }
    let vbytes = fs::read(linux.join(REFERENCE_VERDICT)).map_err(|e| {
        format!(
            "{}: no verdict.json ({e}); run banners-verify --dir DIR --out DIR/verdict.json first",
            linux.display()
        )
    })?;
    let verdict: Value = serde_json::from_slice(&vbytes).map_err(|e| e.to_string())?;
    let rv = run_verdict(&verdict, REFERENCE_CASE).unwrap_or_default();
    if rv != PASS {
        return Err(format!(
            "{REFERENCE_CASE} of {} is {rv:?}, not PASS: it is no reference",
            linux.display()
        ));
    }
    let case = linux.join("runs").join(REFERENCE_CASE);
    let hashes = fs::read_to_string(case.join("hashes-before-copy.txt"))
        .map_err(|e| format!("{REFERENCE_CASE}/hashes-before-copy.txt: {e}"))?;
    let recorded: BTreeMap<&str, &str> = hashes
        .lines()
        .filter_map(|l| l.split_once("  "))
        .map(|(h, n)| (n, h))
        .collect();
    let mut files = BTreeMap::new();
    let mut bytes = Vec::new();
    for f in REFERENCE_FILES {
        let rel = format!("{REFERENCE_STEP}/{f}");
        let want = recorded
            .get(rel.as_str())
            .ok_or_else(|| format!("{REFERENCE_CASE} recorded no hash of {rel}"))?;
        let b = fs::read(case.join(&rel)).map_err(|e| format!("{rel}: {e}"))?;
        if sha(&b) != *want {
            return Err(format!(
                "{rel} differs from the hash {REFERENCE_CASE} recorded"
            ));
        }
        files.insert(f.to_owned(), (*want).to_owned());
        bytes.push((rel, b));
    }
    // A verdict.json is a file that outlives the files it judged: judge the window again now.
    let fresh = run_verdict(&bv::verify_dir(linux), REFERENCE_CASE).unwrap_or_default();
    if fresh != PASS {
        return Err(format!(
            "{REFERENCE_CASE} of {} is {fresh:?} when banners-verify judges it now, though verdict.json says PASS: it is no reference",
            linux.display()
        ));
    }
    let src = ReferenceSource {
        source_dir: linux
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        case: REFERENCE_CASE.into(),
        step: REFERENCE_STEP.into(),
        run_verdict: rv,
        overall: s(&verdict["overall"]).to_owned(),
        verdict_sha256: sha(&vbytes),
        files,
    };
    let dir = out.join(REFERENCE_DIR);
    if dir.exists() {
        let had: Option<ReferenceSource> = fs::read(dir.join(REFERENCE_SOURCE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        return if had.as_ref() == Some(&src) {
            Ok(src)
        } else {
            Err(format!(
                "{} holds another reference; use a new --out",
                dir.display()
            ))
        };
    }
    let write = |rel: &str, b: &[u8]| -> Result<(), String> {
        let p = dir.join(rel);
        if let Some(d) = p.parent() {
            fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        fs::write(&p, b).map_err(|e| format!("{}: {e}", p.display()))
    };
    for (rel, b) in &bytes {
        write(rel, b)?;
    }
    write(REFERENCE_VERDICT, &vbytes)?;
    write(
        REFERENCE_SOURCE,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&src).map_err(|e| e.to_string())?
        )
        .as_bytes(),
    )?;
    Ok(src)
}

/// What the copy of the reference proves: C's records of the scenarios and what C sent on their connections.
#[derive(Debug, Clone, PartialEq)]
pub struct CReference {
    /// C's records of `198.18.0.2` on the scenarios' ports, without their time, in document order.
    pub records: Vec<Rec>,
    /// C's payload segments on each scenario's connection (by the scenario's port), each sequence number once, in
    /// wire order.
    pub payloads: BTreeMap<u16, Vec<Vec<u8>>>,
}
/// The payload segments rmasscan sent on a connection, each sequence number once, in wire order.
fn scanner_payloads(x: &Conn) -> Vec<Vec<u8>> {
    let mut seen = BTreeSet::new();
    x.scanner
        .iter()
        .filter(|g| !g.payload.is_empty() && seen.insert(g.seq))
        .map(|g| g.payload.clone())
        .collect()
}
/// The scanner's payload segments to `dst:port` from `src:sport` on a capture, each sequence number once (a
/// retransmission is no second segment), in wire order.
fn payload_segments(
    fr: &Frames,
    mac: [u8; 6],
    src: IpAddr,
    dst: IpAddr,
    port: u16,
    sport: u16,
) -> Vec<Vec<u8>> {
    let mut seen = BTreeSet::new();
    fr.iter()
        .filter(|(_, f)| f.get(6..12) == Some(&mac[..]))
        .filter_map(|(_, f)| tcp_head(f))
        .filter(|h| h.src == src && h.dst == dst && h.dp == port && h.sp == sport)
        .filter(|h| h.flags & 0x02 == 0 && !h.payload.is_empty() && seen.insert(h.seq))
        .map(|h| h.payload)
        .collect()
}
/// The reference run: the copy's record, its files and what they hold. `None` when it does not prove C's records.
pub(crate) fn judge_reference(r: &mut Run, root: &Path, c: &StandCase) -> Option<CReference> {
    let d = root.join(REFERENCE_DIR);
    let src: ReferenceSource = av::typed(r, &d, REFERENCE_SOURCE)?;
    r.inv(
        "reference/source.json names the Linux window by a plain directory name",
        crate::windows_suite::safe_id(&src.source_dir),
        &src.source_dir,
    );
    r.inv(
        &format!(
            "the reference is C's {REFERENCE_STEP} step of {REFERENCE_CASE}, PASS in its window"
        ),
        src.case == REFERENCE_CASE && src.step == REFERENCE_STEP && src.run_verdict == PASS,
        format!("{}/{} {}", src.case, src.step, src.run_verdict),
    );
    let verdict = fs::read(d.join(REFERENCE_VERDICT)).ok();
    r.inv(
        "reference/verdict.json is the window's verdict the record names, and it says the same of the case",
        verdict.as_ref().is_some_and(|b| {
            sha(b) == src.verdict_sha256
                && serde_json::from_slice::<Value>(b)
                    .ok()
                    .and_then(|v| run_verdict(&v, REFERENCE_CASE))
                    .as_deref()
                    == Some(src.run_verdict.as_str())
        }),
        &src.source_dir,
    );
    let mut copies = BTreeMap::new();
    for f in REFERENCE_FILES {
        let b = fs::read(d.join(REFERENCE_STEP).join(f)).ok();
        r.inv(
            &format!(
                "reference/{REFERENCE_STEP}/{f} has the sha256 {REFERENCE_CASE} recorded in its window"
            ),
            b.as_ref()
                .is_some_and(|b| src.files.get(f) == Some(&sha(b))),
            src.files.get(f).cloned().unwrap_or_default(),
        );
        copies.insert(f, b.unwrap_or_default());
    }
    let t01 = bv::tcp_case(REFERENCE_CASE)?;
    let argv: Option<ArgvRecord> = serde_json::from_slice(&copies["argv.json"]).ok();
    r.inv(
        "the reference ran t01_tcp4's -oL argv (banners_verify::tcp_argv)",
        argv.is_some_and(|a| a.argv == bv::tcp_argv(&t01, Out::List)),
        "",
    );
    let doc = bv::parse_doc(Out::List, &copies["output.txt"]);
    let doc = match doc {
        Ok(d) => d,
        Err(e) => {
            r.inv("the reference document is in C's -oL form", false, e);
            return None;
        }
    };
    let t01 = bv::tcp_case(REFERENCE_CASE)?;
    let ref_ports: Vec<u16> = t01.port_list();
    let ports: Vec<u16> = c
        .ports
        .iter()
        .map(|x| x.1)
        .filter(|p| ref_ports.contains(p))
        .collect();
    let records: Vec<Rec> = doc
        .records
        .iter()
        .filter(|x| x.ip == IpAddr::V4(PEER) && ports.contains(&x.port) && x.proto == "tcp")
        .map(Rec::bare)
        .collect();
    let mut bad = Vec::new();
    for &p in &ports {
        let Some(sc) = bv::tcp_scenario(p, IpAddr::V4(PEER)) else {
            bad.push(format!("no scenario on {p}"));
            continue;
        };
        let opens = records
            .iter()
            .filter(|x| x.port == p && matches!(x.body, Body::Status { st: St::Open, .. }))
            .count();
        let apps: Vec<String> = records
            .iter()
            .filter(|x| x.port == p)
            .filter_map(Rec::app_name)
            .collect();
        if opens != 1 || apps != sc.apps {
            bad.push(format!(
                "{p}: {opens} open records, banners {apps:?}, the scenario {:?}",
                sc.apps
            ));
        }
    }
    r.inv(
        "the reference holds C's open record and the scenario's banners for each of the case's scenarios",
        bad.is_empty() && doc.complete,
        if bad.is_empty() {
            format!("{} records, complete {}", records.len(), doc.complete)
        } else {
            bad.join("; ")
        },
    );
    let frames = match crate::pcap::read_pcap_records(&copies["peer.pcap"]) {
        Ok((_, f)) => f,
        Err(e) => {
            r.inv("the reference capture is a pcap", false, e);
            return None;
        }
    };
    let lst = bv::stand();
    let payloads: BTreeMap<u16, Vec<Vec<u8>>> = ports
        .iter()
        .map(|&p| {
            (
                p,
                payload_segments(
                    &frames,
                    lst.scanner_mac,
                    bv::tcp_case(REFERENCE_CASE)
                        .map(|t| t.source())
                        .unwrap_or(lst.scanner_ip.into()),
                    IpAddr::V4(PEER),
                    p,
                    bv::SOURCE_PORT,
                ),
            )
        })
        .collect();
    r.inv(
        "the reference capture holds what C sent on each scenario's connection",
        payloads.values().all(|v| !v.is_empty()),
        payloads
            .iter()
            .map(|(p, v)| format!("{p}: {} segments", v.len()))
            .collect::<Vec<_>>()
            .join(", "),
    );
    r.notes.insert(
        "c_records".into(),
        json!(records.iter().map(Rec::show).collect::<Vec<_>>()),
    );
    r.notes.insert("source".into(), json!(src));
    r.proven().then_some(CReference { records, payloads })
}

// ------------------------------------------------------------------ the wire

/// One capture of the case, taken apart.
#[derive(Debug, Default)]
pub struct StandWire {
    /// The scanner's SYNs: frames from its MAC and source equal to one of the plan's SYNs.
    pub probes: Vec<(f64, Vec<u8>)>,
    pub conns: Vec<Conn>,
    /// Frames of the scanner MAC with the scanner's source that are not rmasscan's (no SYN of the plan, no stack
    /// frame of its template): the host's own TCP/IP stack.
    pub os_frames: Vec<String>,
    /// rmasscan's stack frames of no connection the stand opened.
    pub stray_stack: Vec<String>,
    /// The peer's who-has for the source, and the scanner MAC's replies for it that are not the host kernel's
    /// 42-byte form (rmasscan's, judged by `autodetect_verify::scanner_arp_answer_problems`).
    pub requests: Vec<(f64, Vec<u8>)>,
    pub answers: Vec<(f64, Vec<u8>)>,
    /// 42-byte ARP replies of the scanner MAC: the host kernel's, bounded by the peer's requests on Windows and none
    /// at all on macOS (L-M4, [`os_arp_problems`]).
    pub os_arp_replies: Vec<(f64, Vec<u8>)>,
    /// ARP requests of the scanner MAC (none with `--router-mac`).
    pub scanner_arp_requests: usize,
    /// Every other frame of the scanner MAC: the host's own traffic (IPv6 discovery, name services), counted only.
    pub other_scanner: usize,
    pub peer_unexpected: Vec<String>,
    /// Multicast and broadcast frames of the peer, its IPv6 kernel traffic and its ARP replies to the scanner MAC's
    /// requests (the host's own), counted only.
    pub peer_noise: usize,
}
fn describe(f: &[u8]) -> String {
    match tcp_head(f) {
        Some(h) => format!(
            "TCP flags {:#04x} {}:{} > {}:{}",
            h.flags, h.src, h.sp, h.dst, h.dp
        ),
        None => format!(
            "a {}-byte frame of ethertype {:02x}{:02x}",
            f.len(),
            f.get(12).copied().unwrap_or(0),
            f.get(13).copied().unwrap_or(0)
        ),
    }
}
/// Is `f` rmasscan's own stack frame: the frame the product's builder makes from the plan's template for its fields
/// (addresses, ports, seq, ack, flags, payload, its window), byte for byte (`tcp_create_packet`,
/// `src/templ-pkt.c:419-613`)? A host stack's frame (its TTL, IP id, window rules, options) is never that frame.
fn stack_form(builder: &rmasscan_core::tcp_frame::TcpFrameBuilder, f: &[u8]) -> bool {
    use rmasscan_core::stack::{ConnAddrs, ConnKey, SegmentOut};
    let (Some(h), Some(p)) = (tcp_head(f), iv::pkt(f)) else {
        return false;
    };
    let (IpAddr::V4(local), IpAddr::V4(remote)) = (h.src, h.dst) else {
        return false;
    };
    let Some(w) = p.l4.get(14..16) else {
        return false;
    };
    let seg = SegmentOut {
        key: ConnKey {
            addrs: ConnAddrs::V4 {
                local: u32::from(local),
                remote: u32::from(remote),
            },
            local_port: h.sp,
            remote_port: h.dp,
        },
        seq: h.seq,
        ack: h.ack,
        flags: h.flags,
        payload: h.payload,
        window: Some(u16::from_be_bytes([w[0], w[1]])),
    };
    builder.build(&seg) == f
}
/// What is wrong with the 42-byte ARP replies of the scanner MAC on a stand (L-M4), as autodetect bounds them
/// (`av::os_arp_reply_problems`): on Windows each answers a who-has of the peer for the source before it, in the
/// kernel's form, at most one per request (the guest answers for its own address); on macOS there is none at all
/// (198.18.0.1 is on no interface, `macos-lab status` rule 2), so any is a reply of the scanner without C's padding.
fn os_arp_problems(plan: Plan, w: &StandWire, st: &av::Stand) -> Vec<String> {
    if plan == Plan::Windows {
        av::os_arp_reply_problems(
            &w.requests,
            &w.os_arp_replies,
            st.scanner_mac,
            st.scanner_ip,
        )
    } else {
        w.os_arp_replies
            .iter()
            .map(|(t, _)| format!("a 42-byte ARP reply at {t:.6} s"))
            .collect()
    }
}
/// Take one capture of the case apart, by the plan's SYNs and the stack template of its binding.
pub fn stand_wire(c: &StandCase, fr: &Frames, plan: &rmasscan_core::probe::ReadyPlan) -> StandWire {
    let st = av::stand(c.plan);
    let builder = rmasscan_core::tcp_frame::TcpFrameBuilder::from_plan(plan);
    let syns: Vec<Vec<u8>> = match crate::pair_verify::plan_probes(plan) {
        Ok((f, _)) => f,
        Err(_) => Vec::new(),
    };
    let src = IpAddr::V4(st.scanner_ip);
    let mut v = StandWire::default();
    // An ARP request of the scanner MAC (the host kernel's or a resolver's) so far: the peer's replies to it are the
    // host's traffic, not the stand's doing.
    let mut asked = false;
    for (t, f) in fr {
        let t = *t;
        if f.get(12..14) == Some(&crate::link::MARKER_ETHERTYPE[..]) {
            continue;
        }
        let from_scanner = f.get(6..12) == Some(&st.scanner_mac[..]);
        let from_peer = f.get(6..12) == Some(&st.peer_mac[..]);
        if !from_scanner && !from_peer {
            // Judged by the safety checks (autodetect_verify::safety).
            continue;
        }
        if f.get(12..14) == Some(&[8, 6][..]) {
            let op = f.get(20..22).map(|b| u16::from_be_bytes([b[0], b[1]]));
            let spa = f.get(28..32).map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]));
            if from_peer {
                if av::peer_request_for(f, st.peer_mac, st.scanner_ip) {
                    v.requests.push((t, f.clone()));
                } else if op == Some(2) && asked {
                    v.peer_noise += 1;
                } else {
                    v.peer_unexpected.push(describe(f));
                }
            } else {
                asked |= op == Some(1);
                match (op, f.len()) {
                    (Some(1), _) if av::resolver_request(f) => v.scanner_arp_requests += 1,
                    (Some(2), 42) => v.os_arp_replies.push((t, f.clone())),
                    (Some(2), _) if spa == Some(st.scanner_ip) => v.answers.push((t, f.clone())),
                    _ => v.other_scanner += 1,
                }
            }
            continue;
        }
        let Some(h) = tcp_head(f) else {
            if from_peer {
                // The peer's multicast and broadcast (the group bit) and its kernel's IPv6 traffic.
                if f.first().is_some_and(|b| b & 1 == 1) || f.get(12..14) == Some(&[0x86, 0xdd][..])
                {
                    v.peer_noise += 1;
                } else {
                    v.peer_unexpected.push(describe(f));
                }
            } else {
                v.other_scanner += 1;
            }
            continue;
        };
        let seg = Seg {
            t,
            flags: h.flags,
            seq: h.seq,
            ack: h.ack,
            payload: h.payload.clone(),
            sums_ok: bv::ipv4_header_sum_ok(f) && bv::tcp_sum_ok(f),
            ip_sum_ok: bv::ipv4_header_sum_ok(f),
            frame: f.clone(),
        };
        if from_scanner {
            if h.src != src {
                v.other_scanner += 1;
            } else if h.flags & 0x3f == 0x02 {
                if syns.contains(f) {
                    v.probes.push((t, f.clone()));
                } else {
                    v.os_frames
                        .push(format!("{}, no SYN of the plan", describe(f)));
                }
            } else {
                let conn = v
                    .conns
                    .iter()
                    .position(|x| x.ip == h.dst && x.port == h.dp && x.sport == h.sp);
                match (conn, stack_form(&builder, f)) {
                    (Some(i), true) => v.conns[i].scanner.push(seg),
                    (_, false) => v.os_frames.push(describe(f)),
                    (None, true) => v.stray_stack.push(format!(
                        "{}, of no connection the stand opened",
                        describe(f)
                    )),
                }
            }
            continue;
        }
        if h.dst != src {
            v.peer_unexpected.push(describe(f));
            continue;
        }
        if let Some(i) = v
            .conns
            .iter()
            .position(|x| x.ip == h.src && x.port == h.sp && x.sport == h.dp)
        {
            let x = &mut v.conns[i];
            if x.open && h.flags & 0x12 == 0x12 && h.seq == x.iss_them && h.ack == x.reply_ack {
                x.repeats += 1;
            } else {
                x.peer.push(seg);
            }
            continue;
        }
        let probe = v.probes.iter().position(|(_, p)| {
            tcp_head(p).is_some_and(|q| {
                q.dst == h.src && q.dp == h.sp && q.sp == h.dp && h.ack == q.seq.wrapping_add(1)
            })
        });
        match probe {
            Some(i) if h.flags & 0x12 == 0x12 || h.flags & 0x04 != 0 => {
                let q = tcp_head(&v.probes[i].1).unwrap_or_else(|| h.clone());
                v.conns.push(Conn {
                    probe: i,
                    ip: q.dst,
                    port: q.dp,
                    sport: q.sp,
                    reconnect: false,
                    open: h.flags & 0x12 == 0x12,
                    reply_t: t,
                    reply_flags: h.flags,
                    reply_ttl: h.ttl,
                    reply_ack: h.ack,
                    reply_sums_ok: seg.sums_ok,
                    iss_them: h.seq,
                    iss_me: q.seq,
                    repeats: 0,
                    scanner: Vec::new(),
                    peer: Vec::new(),
                });
            }
            _ => v
                .peer_unexpected
                .push(format!("{}, which answers no SYN of the scan", describe(f))),
        }
    }
    v
}

// ------------------------------------------------------------------ one run

/// The scanner's file names on a stand: the Windows guest runner's or the plain ones.
fn names(plan: Plan) -> (&'static str, &'static str, &'static str) {
    if plan == Plan::Windows {
        ("guest-stdout.txt", "guest-stderr.txt", "guest-exit.txt")
    } else {
        ("stdout.txt", "stderr.txt", "exit.txt")
    }
}
fn some4(v: &[String]) -> String {
    v.iter().take(4).cloned().collect::<Vec<_>>().join("; ")
}
/// The evidence gate of a run: hashes, extensions, the stand's file names, its own record before and after.
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
                .is_some_and(|e| av::EVIDENCE_EXTENSIONS.contains(&e))
        })
        .collect();
    r.inv(
        "evidence files carry only the allowed extensions (json pcap txt log err sha256 md)",
        odd.is_empty(),
        format!("{odd:?}"),
    );
    let (o, e, x) = names(if plan == Plan::Windows {
        Plan::Macos
    } else {
        Plan::Windows
    });
    let wrong: Vec<&str> = [o, e, x]
        .into_iter()
        .filter(|n| d.join(n).exists())
        .collect();
    r.inv(
        "the scanner's files carry the stand's names (Windows: guest-*.txt; macOS: the plain ones)",
        wrong.is_empty(),
        format!("{wrong:?}"),
    );
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
            r.check(&label, ok, v["raw_run_allowed"].to_string(), NOT_RUN, false);
        } else {
            r.inv(&label, ok, v["raw_run_allowed"].to_string());
        }
    }
}
/// The macOS peer capture is published without the peer host's own mDNS (`autodetect_suite::publish_peer_capture`):
/// `capture.json` says what was left out, and the counts add up (`autodetect_verify`'s rule, written here again).
fn mac_privacy_filter(r: &mut Run, d: &Path, fr: &Frames) {
    let Some(v) = read_json(d.join("capture.json")) else {
        return;
    };
    let pf = &v["privacy_filter"];
    let (kept, dropped, all) = (
        pf["frames_kept"].as_u64(),
        pf["frames_dropped"].as_u64(),
        v["unfiltered"]["pcap_frames"].as_u64(),
    );
    let n = fr.len() as u64;
    r.inv(
        "capture.json: the macOS privacy filter kept the frames of peer.pcap and left out only the rest of the witness's capture",
        pf["published"] == crate::macos_verify::PEER_FILTER
            && kept == Some(n)
            && kept.zip(dropped).and_then(|(k, x)| k.checked_add(x)) == all
            && all.is_some(),
        format!("filter {}, kept {kept:?}, dropped {dropped:?}, unfiltered {all:?}, peer.pcap {n}", pf["published"]),
    );
}
/// A record's port in the Linux window's terms (the port mapping of the macOS stand).
fn mapped(c: &StandCase, x: &Rec) -> Rec {
    let mut y = x.bare();
    if let Some(p) = c.linux_port(x.port) {
        y.port = p;
    }
    y
}
/// The multiset difference of two lists of records: what `a` has more than `b`.
fn more(a: &[Rec], b: &[Rec]) -> Vec<String> {
    let mut left = b.to_vec();
    let mut out = Vec::new();
    for x in a {
        match left.iter().position(|y| y == x) {
            Some(i) => {
                left.swap_remove(i);
            }
            None => out.push(x.show()),
        }
    }
    out
}
/// The checks of one run of the case. `reference` is `None` when the reference run proved nothing.
pub(crate) fn judge_run(root: &Path, c: &StandCase, reference: Option<&CReference>) -> Run {
    let d = root.join("runs").join(c.tag);
    let mut r = Run::new(c.tag);
    if !d.is_dir() {
        r.add(
            "the case's run directory is present",
            NOT_RUN,
            "missing",
            false,
        );
        return r;
    }
    let t = tree(&d);
    let mut files = t.files.clone();
    files.extend(t.links.iter().cloned());
    files.retain(|f| f != "hashes-before-copy.txt");
    // 1. The lab-isolation checks first: nothing else can hide them.
    let peer = av::capture(&mut r, &d, av::PEER_PCAP, &t.links);
    av::safety(
        &mut r,
        c.plan,
        &d,
        &t.links,
        peer.as_ref().map(|p| &p.0),
        None,
    );
    // 2. The evidence and the stand's own records.
    gate(&mut r, c.plan, &d, &files);
    // `expect.json` must equal the table (below): it names the reference case, whose `_tcp` reads as a DNS-SD name.
    let scanned_text: Vec<String> = files
        .iter()
        .filter(|f| *f != EXPECT_JSON)
        .cloned()
        .collect();
    av::privacy(&mut r, &d, &scanned_text);
    let argv: Option<ArgvRecord> = av::typed(&mut r, &d, av::ARGV_JSON);
    r.argv_ok = argv.as_ref().is_some_and(|a| a.argv == c.argv());
    if argv.is_some() {
        r.inv(
            "argv.json is the case table's argv (banners_stand::StandCase::argv)",
            r.argv_ok,
            argv.map(|a| a.argv.join(" ")).unwrap_or_default(),
        );
    }
    if let Some(x) = av::typed::<StandExpect>(&mut r, &d, EXPECT_JSON) {
        r.inv("expect.json is the case table's", x == c.expect(), "");
    }
    let listeners = read_json(d.join(LISTENERS_JSON));
    match &listeners {
        None => r.add(
            &format!("{LISTENERS_JSON} present"),
            NOT_RUN,
            "missing or invalid JSON",
            false,
        ),
        Some(v) => {
            let got: Vec<(u64, u64)> = array(&v["banners"])
                .iter()
                .map(|b| {
                    (
                        b["port"].as_u64().unwrap_or(0),
                        b["scenario_port"].as_u64().unwrap_or(0),
                    )
                })
                .collect();
            let want: Vec<(u64, u64)> = c
                .ports
                .iter()
                .map(|(p, sp)| (u64::from(*p), u64::from(*sp)))
                .collect();
            r.inv(
                "the peer's banner listeners were ready on the case's ports with their scenarios (peer listen --banners)",
                v["ready"] == true && got == want && v["bind"] == PEER.to_string(),
                format!("ready {}, banners {got:?}", v["ready"]),
            );
        }
    }
    let st = av::stand(c.plan);
    if let Some(cap) = &peer {
        av::witness(&mut r, &d, av::PEER_PCAP, av::CAPTURE_JSON, cap, &st);
        if c.plan == Plan::Macos {
            mac_privacy_filter(&mut r, &d, &cap.0);
        }
    }
    let (_, stderr_name, exit_name) = names(c.plan);
    let exit = av::need(&mut r, &d, exit_name).and_then(|x| av::parse_exit(&x));
    let stderr = av::need(&mut r, &d, stderr_name).unwrap_or_default();
    let doc_bytes = fs::read(d.join(OUTPUT)).ok();
    if doc_bytes.is_none() {
        r.add(&format!("{OUTPUT} present"), NOT_RUN, "missing", false);
    }
    if c.plan == Plan::Windows
        && let Some(fw) = read_json(d.join("guest-firewall.json"))
    {
        r.notes.insert("guest_firewall".into(), fw);
    }
    r.notes.insert(
        "finished".into(),
        json!(stderr.lines().rev().find_map(|l| {
            l.rsplit('\r')
                .next()
                .filter(|x| x.starts_with("[+] finished:"))
        })),
    );
    let (Some((fr, _)), Some(doc_bytes)) = (&peer, doc_bytes) else {
        return r;
    };
    let plan = match c.ready_plan() {
        Ok(p) => p,
        Err(e) => {
            r.inv(
                "the product plans the case on the stand's binding",
                false,
                e,
            );
            return r;
        }
    };
    let syns = crate::pair_verify::plan_probes(&plan)
        .map(|x| x.0)
        .unwrap_or_default();
    let w = stand_wire(c, fr, &plan);
    // 3. The scanner's own evidence.
    r.beh("rmasscan exited 0", exit == Some(0), format!("{exit:?}"));
    let doc: Option<Document> = match bv::parse_doc(Out::List, &doc_bytes) {
        Ok(x) => {
            r.beh(
                "rmasscan's -oL document is complete (its `# end` footer)",
                x.complete,
                x.records.len(),
            );
            Some(x)
        }
        Err(e) => {
            r.beh("rmasscan's -oL document is in C's form", false, e);
            None
        }
    };
    let wire_syns: Vec<&Vec<u8>> = w.probes.iter().map(|x| &x.1).collect();
    r.cap(
        "rmasscan's SYNs on the wire are the product plan's on the stand binding, each once, in order",
        wire_syns.len() == syns.len() && wire_syns.iter().zip(&syns).all(|(a, b)| *a == b),
        format!("{} SYNs, the plan {}", wire_syns.len(), syns.len()),
    );
    r.cap(
        "every stack frame of rmasscan belongs to a connection the stand opened",
        w.stray_stack.is_empty(),
        some4(&w.stray_stack),
    );
    r.cap(
        "no ARP request of the scanner (the next hop is given: --router-mac)",
        w.scanner_arp_requests == 0,
        w.scanner_arp_requests,
    );
    let span = w
        .probes
        .first()
        .zip(w.probes.last())
        .map(|(a, b)| (a.0, b.0));
    let arp = av::scanner_arp_answer_problems(
        &w.requests,
        &w.answers,
        av::answering(span, &c.argv()),
        st.scanner_mac,
        st.scanner_ip,
    );
    r.cap(
        "the peer's who-has for the source gets rmasscan's answer in C's form (src/stack-arpv4.c:282-363)",
        arp.is_empty(),
        if arp.is_empty() {
            format!("{} requests, {} answers", w.requests.len(), w.answers.len())
        } else {
            some4(&arp)
        },
    );
    let os_arp = os_arp_problems(c.plan, &w, &st);
    r.cap(
        if c.plan == Plan::Windows {
            "every 42-byte ARP reply of the scanner MAC answers a who-has of the peer for the source, at most one per request (the guest's own reply; an unpadded reply of rmasscan's would be another)"
        } else {
            "no 42-byte ARP reply of the scanner MAC (198.18.0.1 is on no interface of the Mac: its kernel owes none, so such a reply is an unpadded one of rmasscan's)"
        },
        os_arp.is_empty(),
        if os_arp.is_empty() {
            format!(
                "{} replies for {} requests",
                w.os_arp_replies.len(),
                w.requests.len()
            )
        } else {
            some4(&os_arp)
        },
    );
    // 4. The stand.
    let mut stand_bad = Vec::new();
    for (i, (_, p)) in w.probes.iter().enumerate() {
        let h = tcp_head(p);
        let answered: Vec<&Conn> = w.conns.iter().filter(|x| x.probe == i).collect();
        match (answered.first(), h) {
            (Some(x), Some(h)) if answered.len() == 1 && x.open => {
                let Some(sc) = c.scenario(h.dp) else {
                    stand_bad.push(format!("{}: no scenario", h.dp));
                    continue;
                };
                // The owed-stream rule of the banners window (L-I2, `bv::Conn::owed`): the peer must stream what the
                // scanner's frames on this connection owe it. A scanner that never sent the hello the HTTP script
                // waits for owes it nothing after the handshake (the payload check's FAIL below); the SSH server
                // speaks first and owes its ident once the handshake is complete, whatever the scanner sends after.
                let (got, owed) = (x.peer_stream(), x.owed(sc));
                if !sc.stream().starts_with(&got) || got.len() < owed {
                    stand_bad.push(format!(
                        "{}: the peer sent {} bytes, the scanner's frames owe {} of its scenario's {}",
                        h.dp,
                        got.len(),
                        owed,
                        sc.stream().len()
                    ));
                }
                if x.peer.iter().any(|g| g.flags & 0x04 != 0) {
                    stand_bad.push(format!("{}: a RST of the peer", h.dp));
                }
            }
            (_, h) => stand_bad.push(format!(
                "{}: {} answers, open {:?}",
                h.map_or(0, |h| h.dp),
                answered.len(),
                answered.first().map(|x| x.open)
            )),
        }
    }
    r.inv(
        "the stand answered each SYN with one SYN-ACK and streamed the scenario of its port as far as the scanner's frames owe it (all of it unless the scanner gave the script no cause: no handshake, no hello, a FIN or RST first), without a RST",
        stand_bad.is_empty() && !w.probes.is_empty(),
        if stand_bad.is_empty() {
            format!("{} connections", w.conns.len())
        } else {
            some4(&stand_bad)
        },
    );
    // L-I2: what the peer's scripts recorded when the listener stopped (`peer listen --banners`, `script_errors`). A
    // script that failed on a connection the scanner did not reset failed for the stand's reasons; after the scanner's
    // RST a failed write or shutdown is the scanner's doing, which its own checks judge. A record without the key comes
    // from a lab build before the final review (or a listener killed before it could write): noted, not judged.
    match listeners.as_ref().map(|v| &v["script_errors"]) {
        Some(Value::Array(errors)) => {
            let reset: BTreeSet<u64> = w
                .conns
                .iter()
                .filter(|x| x.scanner.iter().any(|g| g.flags & 0x04 != 0))
                .map(|x| u64::from(x.port))
                .collect();
            let stand: Vec<String> = errors
                .iter()
                .filter(|e| e["port"].as_u64().is_none_or(|p| !reset.contains(&p)))
                .map(|e| format!("{}: {}", e["port"], s(&e["error"])))
                .collect();
            r.inv(
                "the peer's banner scripts ran without an error, but on a connection the scanner reset (peer listen --banners, script_errors)",
                stand.is_empty(),
                if stand.is_empty() {
                    format!("{} errors", errors.len())
                } else {
                    some4(&stand)
                },
            );
        }
        Some(Value::Null) => {
            r.notes.insert(
                "peer_script_errors".into(),
                json!("not recorded: listeners.json has no script_errors (a lab build before the final review, or a listener that did not stop on its own)"),
            );
        }
        Some(_) => r.inv(
            "the peer's banner scripts ran without an error (peer listen --banners, script_errors)",
            false,
            "script_errors is not a list",
        ),
        None => {}
    }
    r.inv(
        "no other frame of the peer (its multicast and IPv6 kernel traffic aside)",
        w.peer_unexpected.is_empty(),
        some4(&w.peer_unexpected),
    );
    let host = if c.plan == Plan::Windows {
        "no frame of the guest's own TCP/IP stack for the source (masscan README: \"Windows doesn't respond with RST packets\")"
    } else {
        "no frame of the Mac's kernel for the source (198.18.0.1 is assigned to no interface: otherwise its kernel resets the banner connections)"
    };
    r.inv(host, w.os_frames.is_empty(), some4(&w.os_frames));
    if c.plan == Plan::Windows {
        r.notes.insert(
            "windows_no_rst".into(),
            json!(if w.os_frames.is_empty() {
                format!(
                    "holds on this guest: no frame of its own stack on {} connections from its own address",
                    w.conns.len()
                )
            } else {
                format!(
                    "refuted on this guest: {} frame(s) of its own stack, first {}",
                    w.os_frames.len(),
                    w.os_frames[0]
                )
            }),
        );
    }
    r.inv(
        "the C reference of the scenarios is proven (run `reference`)",
        reference.is_some(),
        "",
    );
    // 5. rmasscan against its scenarios and against C.
    let mut wrong = Vec::new();
    let mut hello = Vec::new();
    let mut rsts = Vec::new();
    let mut after = Vec::new();
    let mut sent = BTreeMap::new();
    for x in w.conns.iter().filter(|x| x.open) {
        let Some(lp) = c.linux_port(x.port) else {
            continue;
        };
        let mine = scanner_payloads(x);
        sent.insert(
            x.port.to_string(),
            json!(
                mine.iter()
                    .map(|p| bv::c_normalize_string(p))
                    .collect::<Vec<_>>()
            ),
        );
        if let Some(rf) = reference {
            match rf.payloads.get(&lp) {
                Some(want) if want != &mine => {
                    wrong.push(format!(
                        "{}: rmasscan sent {:?}, C {:?}",
                        x.port,
                        mine.iter()
                            .map(|p| bv::c_normalize_string(p))
                            .collect::<Vec<_>>(),
                        Some(
                            want.iter()
                                .map(|p| bv::c_normalize_string(p))
                                .collect::<Vec<_>>(),
                        )
                    ));
                }
                None if lp == 443 => {
                    // No C reference on this stand for TLS (the Linux window's reference case does not scan
                    // 443): the first payload must be the ClientHello (a handshake record of 198 bytes).
                    let ok = mine.first().is_some_and(|p| {
                        p.len() == 198 && p.starts_with(b"\x16\x03\x01\x00\xc1\x01")
                    });
                    if !ok {
                        wrong.push(format!(
                            "{}: first payload is not the default ClientHello: {:?}",
                            x.port,
                            mine.first().map(|p| bv::c_normalize_string(p))
                        ));
                    }
                }
                _ => {}
            }
        }
        if c.scenario(x.port).is_some_and(|sc| !sc.server_first()) {
            match x.scanner.iter().find(|g| !g.payload.is_empty()) {
                Some(g)
                    if (bv::HELLO_WINDOW.0..=bv::HELLO_WINDOW.1).contains(&(g.t - x.reply_t)) => {}
                Some(g) => hello.push(format!("{} after {:.3} s", x.port, g.t - x.reply_t)),
                None => hello.push(format!("{} never", x.port)),
            }
        }
        rsts.extend(
            x.scanner
                .iter()
                .filter(|g| g.flags & 0x04 != 0 && !x.rst_to_fin_without_tcb(g))
                .map(|g| format!("{} at {:.3} s", x.port, g.t - x.reply_t)),
        );
        after.extend(
            x.after_destroy()
                .into_iter()
                .map(|g| format!("{} flags {:#04x}", x.port, g.flags)),
        );
    }
    r.notes.insert("scanner_payloads".into(), json!(sent));
    r.cap(
        "rmasscan's payload segments on each connection are C's on the same scenario (its hello, its SSH ident), in order",
        wrong.is_empty() && reference.is_some(),
        some4(&wrong),
    );
    r.cap(
        &format!(
            "the hello leaves {}-{} s after the SYN-ACK where the server waits for it",
            bv::HELLO_WINDOW.0,
            bv::HELLO_WINDOW.1
        ),
        hello.is_empty(),
        some4(&hello),
    );
    r.cap(
        "no RST of rmasscan on the connections (both scenarios end with FIN; R8's RST to a FIN after a connection's end aside, src/main.c:1019-1041)",
        rsts.is_empty(),
        some4(&rsts),
    );
    r.cap(
        "no frame of a connection after the connection was destroyed",
        after.is_empty(),
        some4(&after),
    );
    let Some(doc) = doc else { return r };
    let scanned: BTreeSet<u16> = c.ports.iter().map(|x| x.0).collect();
    let foreign: Vec<String> = doc
        .records
        .iter()
        .filter(|x| x.ip != IpAddr::V4(PEER) || !scanned.contains(&x.port) || x.proto != "tcp")
        .map(Rec::show)
        .collect();
    r.beh(
        "every record of rmasscan's document is of a scanned port of 198.18.0.2",
        foreign.is_empty(),
        some4(&foreign),
    );
    // M1: one run of banners per connection, after its open record.
    let mut m1 = Vec::new();
    for &p in &scanned {
        let at: Vec<usize> = doc
            .records
            .iter()
            .enumerate()
            .filter(|(_, x)| x.port == p && x.is_banner())
            .map(|(i, _)| i)
            .collect();
        let open = doc
            .records
            .iter()
            .position(|x| x.port == p && matches!(x.body, Body::Status { st: St::Open, .. }));
        if let (Some(a), Some(b)) = (at.first(), at.last())
            && (b - a + 1 != at.len() || open.is_none_or(|o| o > *a))
        {
            m1.push(format!("{p}: banners at {at:?}, open at {open:?}"));
        }
    }
    r.beh(
        "the banners of one connection come in one run, after its open record (M1)",
        m1.is_empty(),
        some4(&m1),
    );
    let mut apps_bad = Vec::new();
    for x in w.conns.iter().filter(|x| x.open) {
        let Some(sc) = c.scenario(x.port) else {
            continue;
        };
        let got: Vec<String> = doc
            .records
            .iter()
            .filter(|y| y.port == x.port)
            .filter_map(Rec::app_name)
            .collect();
        if got != sc.apps {
            apps_bad.push(format!("{} {got:?}, the scenario {:?}", x.port, sc.apps));
        }
    }
    r.cap(
        "each connection's banners carry, in flush order, the applications its scenario declares (TCP_SCENARIOS)",
        apps_bad.is_empty() && !w.conns.is_empty(),
        some4(&apps_bad),
    );
    let ref_ports: Vec<u16> = bv::tcp_case(REFERENCE_CASE)
        .map(|t| t.port_list())
        .unwrap_or_default();
    let mine: Vec<Rec> = doc
        .records
        .iter()
        .map(|x| mapped(c, x))
        .filter(|x| ref_ports.contains(&x.port))
        .collect();
    if let Some(rf) = reference {
        let (extra, lost) = (more(&mine, &rf.records), more(&rf.records, &mine));
        r.cap(
            "rmasscan's records equal C's records of the same scenarios as a multiset, field for field but the time (the Linux window's ports)",
            extra.is_empty() && lost.is_empty(),
            if extra.is_empty() && lost.is_empty() {
                format!("{} records", mine.len())
            } else {
                format!("rmasscan has more: {}; C has more: {}", some4(&extra), some4(&lost))
            },
        );
    }
    let mut by_app: BTreeMap<String, usize> = BTreeMap::new();
    for a in doc.records.iter().filter_map(Rec::app_name) {
        *by_app.entry(a).or_default() += 1;
    }
    r.notes.insert("banners_by_app".into(), json!(by_app));
    r.notes.insert(
        "records".into(),
        json!(doc.records.iter().map(Rec::show).collect::<Vec<_>>()),
    );
    r.notes.insert(
        "wire".into(),
        json!({"syns": w.probes.len(), "connections": w.conns.len(),
            "peer_requests_for_source": w.requests.len(), "rmasscan_arp_answers": w.answers.len(),
            "host_arp_replies": w.os_arp_replies.len(), "host_frames_counted": w.other_scanner,
            "peer_noise": w.peer_noise}),
    );
    if c.plan == Plan::Macos {
        r.notes.insert(
            "port_map".into(),
            json!(
                c.ports
                    .iter()
                    .map(|(p, sp)| format!("{p} -> {sp}"))
                    .collect::<Vec<_>>()
            ),
        );
    }
    r
}

// ------------------------------------------------------------------ the directory

/// Does `man` describe a directory of this case (`banners_stand` names its stand)?
pub(crate) fn is_stand_dir(man: &Value) -> bool {
    man.get(MANIFEST_KEY).is_some()
}
pub(crate) fn stand_dir(root: &Path) -> bool {
    read_json(root.join("manifest.json")).is_some_and(|m| is_stand_dir(&m))
}
/// `t` without the reference copy: its capture is the Linux stand's (judged by its own window) and would read as
/// foreign frames on this stand.
fn without_reference(t: &Tree) -> Tree {
    let keep = |p: &String| p != REFERENCE_DIR && !p.starts_with(&format!("{REFERENCE_DIR}/"));
    Tree {
        files: t.files.iter().filter(|p| keep(p)).cloned().collect(),
        dirs: t.dirs.iter().filter(|p| keep(p)).cloned().collect(),
        links: t.links.iter().filter(|p| keep(p)).cloned().collect(),
    }
}
/// Judge an evidence directory of the case: the manifest, the reference, the run, the aborted attempts and a safety
/// walk of everything else (the reference copy aside). Symbolic links are never followed.
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
    let plan: Option<Plan> = read_json(root.join("manifest.json"))
        .and_then(|v| serde_json::from_value(v[MANIFEST_KEY].clone()).ok());
    let c = plan.and_then(case);
    m.check(
        "manifest.json names the stand of the TCP banner case (banners_stand: windows or macos)",
        c.is_some(),
        format!("{plan:?}"),
        NOT_RUN,
        false,
    );
    let tags: Vec<&'static str> = c.iter().map(|c| c.tag).collect();
    if let Some(c) = &c {
        let p = hello_table_problems(c);
        m.inv(
            "C's hello on each scanned port is its hello on the scenario's port in the Linux window (tests/golden/tcp-banners/hellos.out)",
            p.is_empty(),
            some4(&p),
        );
    }
    let inside = |f: &String| {
        f.starts_with(&format!("{REFERENCE_DIR}/"))
            || tags
                .iter()
                .any(|tag| f.starts_with(&format!("runs/{tag}/")))
    };
    let outside: Vec<String> = t
        .files
        .iter()
        .filter(|f| !inside(f) && *f != "verdict.json")
        .cloned()
        .collect();
    let odd: Vec<&String> = outside
        .iter()
        .filter(|f| {
            !Path::new(f)
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| av::EVIDENCE_EXTENSIONS.contains(&e))
        })
        .collect();
    m.inv(
        "evidence files outside the run carry only the allowed extensions (json pcap txt log err sha256 md)",
        odd.is_empty(),
        format!("{odd:?}"),
    );
    // The reference is the Linux window's evidence, under its own privacy rule (banners-verify, privacy-scan); its
    // record here names only that directory, the case and the hashes (checked by the reference run).
    av::privacy(&mut m, root, &outside);
    let unplanned: Vec<&str> = t
        .dirs
        .iter()
        .chain(&t.files)
        .chain(&t.links)
        .filter_map(|p| p.strip_prefix("runs/"))
        .filter(|p| !p.contains('/') && !tags.contains(p))
        .collect();
    m.inv(
        "runs/ holds only the case's directory",
        unplanned.is_empty(),
        format!("{unplanned:?}"),
    );
    let attempts = av::attempts(&t, |name| av::attempt_of(&tags, name));
    let strays: Vec<&str> = attempts
        .iter()
        .filter(|a| a.case.is_none())
        .map(|a| a.name.as_str())
        .collect();
    if !attempts.is_empty() {
        m.inv(
            "runs_aborted/ holds only attempts of the case (<tag>.<run id>)",
            strays.is_empty(),
            format!("{strays:?}"),
        );
    }
    let mut runs = vec![m.summary()];
    if let Some(c) = &c {
        let mut rr = Run::new(REFERENCE_DIR);
        rr.argv_ok = true;
        let reference = judge_reference(&mut rr, root, c);
        runs.push(rr.summary());
        let mut r = judge_run(root, c, reference.as_ref());
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
        runs.push(r.summary());
    }
    result["runs"] = json!(runs);
    result["aborted"] = json!(
        attempts
            .iter()
            .map(av::Attempt::summary)
            .collect::<Vec<_>>()
    );
    result["safety_scan"] = json!(av::stray_scan(root, plan, &tags, &without_reference(&t)));
    verify::finish(result)
}
/// The verdict of the run `tag` and whether it failed by rmasscan's behaviour (for a suite's rerun rule).
pub fn run_status(root: &Path, tag: &str) -> (String, bool) {
    array(&verify_dir(root)["runs"])
        .iter()
        .find(|r| s(&r["tag"]) == tag)
        .map_or((NOT_RUN.into(), false), |r| {
            (s(&r["verdict"]).to_owned(), r["behaviour_fail"] == true)
        })
}
/// `windows-verify --dir DIR` or `macos-verify --dir DIR` on a directory of this case: 0 PASS, 1 FAIL, 2 INVALID or
/// NOT RUN; `--out FILE` writes the verdict.
pub fn run(args: &[String]) -> Result<i32, String> {
    let mut dir = None;
    let mut out = None;
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let v = it.next().ok_or_else(|| format!("value required for {k}"))?;
        match k.as_str() {
            "--dir" => dir = Some(v),
            "--out" => out = Some(v),
            _ => return Err(format!("unknown argument {k}")),
        }
    }
    let res = verify_dir(Path::new(dir.ok_or("--dir required")?));
    if let Some(out) = out {
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
        let bad: Vec<String> = array(&r["checks"])
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
    println!("overall {}", s(&res["overall"]));
    Ok(match s(&res["overall"]) {
        PASS => 0,
        FAIL => 1,
        _ => 2,
    })
}

#[cfg(test)]
#[path = "banners_stand_tests.rs"]
pub(crate) mod tests;
