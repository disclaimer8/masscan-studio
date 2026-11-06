//! Offline verifier of the output-format acceptance on the sealed Linux netns stand (`output-verify`) and the one case
//! table of its suite (`output-suite linux`): design §6.2 (docs/superpowers/specs/2026-11-06-rmasscan-output-formats-
//! design.md), byte forms of docs/superpowers/specs/2026-11-06-rmasscan-output-formats-c-reference.md §1.
//!
//! The suite runs the C oracle (masscan `8e6b3b0`) and rmasscan on the autodetect stand (`198.18.0.1` scanning
//! `198.18.0.2-198.18.0.5`; the peer answers 80 and 8080, every other port is reset) with the same argv, each in a
//! working directory of its own, and keeps every output file under a neutral name. This module judges what it kept.
//! The rules of `autodetect-verify` hold and its machinery is reused: a missing input is NOT RUN, unproven evidence
//! INVALID, a lab frame off the stand a safety FAIL, and no verdict is ever promoted.
//!
//! Layout of an evidence directory: `manifest.json` (key `output`: `linux`), `teardown.json`, `runs/<tag>/` per planned
//! case ([`planned_tags`]). A run directory holds `argv.json`, `expect.json` ([`OutputExpect`]), `isolation.json` and
//! `isolation-post.json`, rmasscan's `stdout.txt stderr.txt exit.txt`, its output file `output.txt` (`output.bin` for
//! `-oB`), `peer.pcap` with its witness `capture.json` and `peer.err`; a case with the oracle also `oracle/` (the same
//! four files of the C oracle) and `oracle.pcap`, `oracle-capture.json`, `oracle.err`; an interrupted scan
//! `interrupt.json` ([`InterruptRecord`]); `o17_readscan` its inputs `input-rmasscan.bin` and `input-oracle.bin`, the
//! `-oB` outputs of `o06_binary`; and `hashes-before-copy.txt`.
//!
//! Record times are the only fields that differ between two correct scanners: they are masked (`<T>`) in every
//! comparison and checked against the run's capture window instead; so are the clock fields of headers and footers
//! (XML `start`, `finished`, `timestr`, `elapsed`, the grepable times, the binary `s:`). The order of records is
//! normalised, since replies may arrive in another order.
use crate::{
    autodetect_verify::{
        self as av, ArgvRecord, CAPTURE_JSON, EVIDENCE_EXTENSIONS, MANIFEST_JSON,
        ORACLE_CAPTURE_JSON, ORACLE_PCAP, PEER_PCAP, Piece, Plan, Sourced,
    },
    macos_verify::{hashes_match_tree, tree},
    pcap::{self, Frames},
    verify::{self, FAIL, INVALID, NOT_RUN, PASS, Run, array, read_json, s, sha, tcp},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, net::Ipv4Addr, path::Path};

// ------------------------------------------------------------------ the case table

/// The targets and ports every scan of the stand names, and the common arguments (`--rate` aside).
pub const TARGETS: &str = "198.18.0.2-198.18.0.5";
pub const PORTS: &str = "80,443,8080";
pub const RATE: &str = "100";
/// An interrupted scan: slow and long, so that SIGINT ~2 s after the start stops it in the middle.
pub const INTERRUPT_PORTS: &str = "1-1000";
pub const INTERRUPT_RATE: &str = "20";
/// When the suite sends SIGINT, and how long rmasscan then has to exit before SIGKILL.
pub const INTERRUPT_AFTER_S: f64 = 2.0;
pub const INTERRUPT_EXIT_S: f64 = 30.0;
/// The output file `o13_open_fail` asks for: its directory does not exist.
pub const UNOPENABLE: &str = "/nonexistent-rmasscan-dir/x";
/// rmasscan's refusal when the output file does not open (rmasscan-cli `output/pipeline.rs`, C `output.c` text).
pub const OPEN_FAILURE: &str = "out: could not open file for writing";
/// The same refusal of `--append-output`.
const OPEN_FAILURE_APPEND: &str = "out: could not open file for appending";
/// The inputs of `o17_readscan`: the `-oB` outputs of [`BINARY_TAG`], rmasscan's and the oracle's.
pub const READSCAN_INPUTS: [&str; 2] = ["input-rmasscan.bin", "input-oracle.bin"];
pub const BINARY_TAG: &str = "o06_binary";
pub const INTERRUPT_JSON: &str = "interrupt.json";
pub const ORACLE_DIR: &str = "oracle";

/// A masscan output format (`-o<letter>`).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    List,
    Json,
    Ndjson,
    Grepable,
    Xml,
    Binary,
    Hostonly,
    Unicornscan,
}
impl Format {
    pub fn letter(self) -> char {
        match self {
            Format::List => 'L',
            Format::Json => 'J',
            Format::Ndjson => 'D',
            Format::Grepable => 'G',
            Format::Xml => 'X',
            Format::Binary => 'B',
            Format::Hostonly => 'H',
            Format::Unicornscan => 'U',
        }
    }
    /// The neutral name of the output file, in the scanner's working directory and in the evidence.
    pub fn file(self) -> &'static str {
        if self == Format::Binary {
            "output.bin"
        } else {
            "output.txt"
        }
    }
}

/// What a case does.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OutputKind {
    /// A live scan of the stand to its end.
    Scan,
    /// The output file does not open: exit 1 before any frame.
    OpenFailure,
    /// A live scan stopped by SIGINT: exit 0, the output file complete.
    Interrupt,
    /// `--readscan` of `o06_binary`'s outputs, offline, after the live cases.
    Readscan,
}

/// Where the format goes.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Target {
    /// A file in the scanner's working directory, [`Format::file`].
    File,
    /// `-`: stdout.
    Stdout,
    /// [`UNOPENABLE`].
    Unopenable,
}

/// What stdout holds.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StdoutForm {
    /// Nothing: a file format without `--interactive` silences stdout (`output.c:766`).
    Silent,
    /// The output document itself (`-o<letter> -`).
    Document,
    /// `--interactive`: a `Discovered` line per open record.
    Discovered,
    /// `--nostatus`: `N milliseconds elapsed` (`main.c:1548-1552`).
    Elapsed,
}

/// The status line a case shows on stderr.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StatusForm {
    /// The text status line, ended by the 77-space erase right before `[+] finished`.
    Text,
    /// `--nostatus`: none.
    Off,
    /// No scan loop runs (an open failure, `--readscan`): none.
    None,
}

/// One planned case, defined here and nowhere else: the suite writes `argv.json` from [`OutputCase::argv`] and
/// `expect.json` from [`OutputCase::expect`], and the verifier judges every run against this entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputCase {
    pub tag: &'static str,
    pub kind: OutputKind,
    pub format: Format,
    pub target: Target,
    /// `--show open,closed`.
    pub show_closed: bool,
    pub interactive: bool,
    pub nostatus: bool,
    /// The C oracle runs the same argv after rmasscan. Not for the open failure and the interrupts (rmasscan's own
    /// behaviour), nor for `--nostatus`: masscan `8e6b3b0` never ends a live `--nostatus` scan with `--wait` above 0
    /// (main.c:1509-1520 joins the transmit thread, which waits for `is_rx_done`, main.c:470, that only the status
    /// loop or a second Ctrl-C sets).
    pub oracle: bool,
}

/// `expect.json`: the case as the suite planned it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutputExpect {
    pub tag: String,
    pub kind: OutputKind,
    pub format: Format,
    pub target: Target,
    pub show_closed: bool,
    pub stdout: StdoutForm,
    pub status: StatusForm,
    pub oracle: bool,
}

/// `interrupt.json`: when the suite sent SIGINT to rmasscan and how the scan ended. `signal_unix` is `None` when the
/// scan had ended before the signal; `killed` when it was still running [`INTERRUPT_EXIT_S`] after it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InterruptRecord {
    pub signal: String,
    pub after_s: f64,
    pub signal_unix: Option<f64>,
    pub exit_within_s: f64,
    pub killed: bool,
}

/// `manifest.json` as far as this verifier reads it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OutputManifest {
    pub output: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lab_id: Option<String>,
}

const SCAN: OutputCase = OutputCase {
    tag: "",
    kind: OutputKind::Scan,
    format: Format::List,
    target: Target::File,
    show_closed: true,
    interactive: false,
    nostatus: false,
    oracle: true,
};
const ONLY_RMASSCAN: OutputCase = OutputCase {
    oracle: false,
    ..SCAN
};
const CASES: [OutputCase; 17] = [
    OutputCase {
        tag: "o01_list",
        ..SCAN
    },
    OutputCase {
        tag: "o02_json",
        format: Format::Json,
        ..SCAN
    },
    OutputCase {
        tag: "o03_ndjson",
        format: Format::Ndjson,
        ..SCAN
    },
    OutputCase {
        tag: "o04_grepable",
        format: Format::Grepable,
        ..SCAN
    },
    OutputCase {
        tag: "o05_xml",
        format: Format::Xml,
        ..SCAN
    },
    OutputCase {
        tag: "o06_binary",
        format: Format::Binary,
        ..SCAN
    },
    OutputCase {
        tag: "o07_hostonly",
        format: Format::Hostonly,
        ..SCAN
    },
    OutputCase {
        tag: "o08_unicornscan",
        format: Format::Unicornscan,
        ..SCAN
    },
    OutputCase {
        tag: "o09_json_default_show",
        format: Format::Json,
        show_closed: false,
        ..SCAN
    },
    OutputCase {
        tag: "o10_list_stdout",
        target: Target::Stdout,
        show_closed: false,
        ..SCAN
    },
    OutputCase {
        tag: "o11_interactive",
        show_closed: false,
        interactive: true,
        ..SCAN
    },
    OutputCase {
        tag: "o12_nostatus",
        format: Format::Json,
        show_closed: false,
        nostatus: true,
        ..ONLY_RMASSCAN
    },
    OutputCase {
        tag: "o13_open_fail",
        kind: OutputKind::OpenFailure,
        target: Target::Unopenable,
        show_closed: false,
        ..ONLY_RMASSCAN
    },
    OutputCase {
        tag: "o14_interrupt_json",
        kind: OutputKind::Interrupt,
        format: Format::Json,
        ..ONLY_RMASSCAN
    },
    OutputCase {
        tag: "o15_interrupt_xml",
        kind: OutputKind::Interrupt,
        format: Format::Xml,
        ..ONLY_RMASSCAN
    },
    OutputCase {
        tag: "o16_interrupt_binary",
        kind: OutputKind::Interrupt,
        format: Format::Binary,
        ..ONLY_RMASSCAN
    },
    OutputCase {
        tag: "o17_readscan",
        kind: OutputKind::Readscan,
        ..SCAN
    },
];

/// Every case, in the brief's order: the live ones, then `o17_readscan`, which reads `o06_binary`'s outputs.
pub fn cases() -> &'static [OutputCase] {
    &CASES
}
pub fn planned_tags() -> Vec<&'static str> {
    CASES.iter().map(|c| c.tag).collect()
}
pub fn case(tag: &str) -> Option<OutputCase> {
    CASES.iter().find(|c| c.tag == tag).copied()
}

impl OutputCase {
    pub fn ports(&self) -> &'static str {
        if self.kind == OutputKind::Interrupt {
            INTERRUPT_PORTS
        } else {
            PORTS
        }
    }
    pub fn rate(&self) -> &'static str {
        if self.kind == OutputKind::Interrupt {
            INTERRUPT_RATE
        } else {
            RATE
        }
    }
    /// The argument `-o<letter>` takes.
    pub fn output_arg(&self) -> &'static str {
        match self.target {
            Target::File => self.format.file(),
            Target::Stdout => "-",
            Target::Unopenable => UNOPENABLE,
        }
    }
    /// `argv.json`: the targets, `-pPORTS`, the output flags and `--seed 1 --rate R --wait 3`; `o17_readscan`
    /// `--readscan` of its two inputs into `-oL`. Output files are named relative to the scanner's working directory.
    pub fn argv(&self) -> Vec<String> {
        let mut a: Vec<String> = Vec::new();
        if self.kind == OutputKind::Readscan {
            a.push("--readscan".into());
            a.extend(READSCAN_INPUTS.map(str::to_owned));
        } else {
            a.push(TARGETS.into());
            a.push(format!("-p{}", self.ports()));
        }
        a.push(format!("-o{}", self.format.letter()));
        a.push(self.output_arg().into());
        if self.show_closed {
            a.extend(["--show", "open,closed"].map(str::to_owned));
        }
        if self.interactive {
            a.push("--interactive".into());
        }
        if self.nostatus {
            a.push("--nostatus".into());
        }
        if self.kind != OutputKind::Readscan {
            a.extend(["--seed", "1", "--rate", self.rate(), "--wait", "3"].map(str::to_owned));
        }
        a
    }
    pub fn stdout(&self) -> StdoutForm {
        if self.target == Target::Stdout {
            StdoutForm::Document
        } else if self.interactive {
            StdoutForm::Discovered
        } else if self.nostatus {
            StdoutForm::Elapsed
        } else {
            StdoutForm::Silent
        }
    }
    pub fn status(&self) -> StatusForm {
        match self.kind {
            OutputKind::OpenFailure | OutputKind::Readscan => StatusForm::None,
            _ if self.nostatus => StatusForm::Off,
            _ => StatusForm::Text,
        }
    }
    pub fn expect(&self) -> OutputExpect {
        OutputExpect {
            tag: self.tag.into(),
            kind: self.kind,
            format: self.format,
            target: self.target,
            show_closed: self.show_closed,
            stdout: self.stdout(),
            status: self.status(),
            oracle: self.oracle,
        }
    }
    /// Does the scanner leave an output file in its working directory?
    pub fn writes_file(&self) -> bool {
        self.target == Target::File && self.kind != OutputKind::OpenFailure
    }
    /// Live: the scanner may put frames on the wire (the peer's responder runs).
    pub fn live(&self) -> bool {
        self.kind != OutputKind::Readscan
    }
}

// ------------------------------------------------------------------ the documents

/// The status of a record (`status_string`, `output.c:103-112`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Status {
    Open,
    Closed,
}
impl Status {
    fn parse(s: &str) -> Option<Status> {
        match s {
            "open" => Some(Status::Open),
            "closed" => Some(Status::Closed),
            _ => None,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Status::Open => "open",
            Status::Closed => "closed",
        }
    }
}

/// What a record says, as far as a format carries it: `-oH` only the address, `-oU` no time.
pub(crate) type Key = (Option<Status>, Ipv4Addr, Option<u16>);

/// One record of a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rec {
    pub(crate) status: Option<Status>,
    pub(crate) ip: Ipv4Addr,
    pub(crate) port: Option<u16>,
    pub(crate) ts: Option<u64>,
    /// The record as the file holds it, its time replaced by `<T>`: what two correct scanners agree on.
    pub(crate) masked: String,
}
impl Rec {
    pub(crate) fn key(&self) -> Key {
        (self.status, self.ip, self.port)
    }
}

/// A document of one format, taken apart.
#[derive(Debug, Clone, Default)]
pub(crate) struct Doc {
    /// Header and footer with their clock fields masked (empty for a format without one, or an empty file).
    pub(crate) header: String,
    pub(crate) footer: String,
    pub(crate) records: Vec<Rec>,
    /// The footer is written (always for the formats without one).
    pub(crate) complete: bool,
    /// The clock fields of header and footer, Unix seconds: XML `start` and `finished time`, the binary `s:`, the
    /// grepable times.
    pub(crate) clock: Vec<u64>,
    /// XML `<hosts up down total>`.
    pub(crate) hosts: Option<(u64, u64, u64)>,
}

const MASK: &str = "<T>";
/// Record templates of the C reference §1; `@` is a field.
const LIST_REC: &str = "@ tcp @ @ @";
const JSON_REC: &str = "{   \"ip\": \"@\",   \"timestamp\": \"@\", \"ports\": [ {\"port\": @, \"proto\": \"tcp\", \"status\": \"@\", \"reason\": \"@\", \"ttl\": @} ] }";
const NDJSON_REC: &str = "{\"ip\":\"@\",\"timestamp\":\"@\",\"port\":@,\"proto\":\"tcp\",\"rec_type\":\"status\",\"data\":{\"status\":\"@\",\"reason\":\"@\",\"ttl\":@}}";
const GREPABLE_REC: &str = "Timestamp: @\tHost: @ ()\tPorts: @/@/tcp//@//";
const GREPABLE_HEAD: &str = "# Masscan 1.3.9-integration scan initiated @";
const GREPABLE_FOOT: &str = "# Masscan done at @";
const GREPABLE_PORTS: (&str, &str) = ("# Ports scanned: TCP(", ") UDP(0;) SCTP(0;) PROTOCOLS(0;)");
const XML_HEAD: [&str; 4] = [
    "<?xml version=\"1.0\"?>",
    "<!-- masscan v1.0 scan -->",
    "<nmaprun scanner=\"masscan\" start=\"@\" version=\"1.0-BETA\"  xmloutputversion=\"1.03\">",
    "<scaninfo type=\"syn\" protocol=\"tcp\" />",
];
const XML_REC: &str = "<host endtime=\"@\"><address addr=\"@\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"@\"><state state=\"@\" reason=\"@\" reason_ttl=\"@\"/></port></ports></host>";
const XML_FOOT: [&str; 5] = [
    "<runstats>",
    "<finished time=\"@\" timestr=\"@\" elapsed=\"@\" />",
    "<hosts up=\"@\" down=\"@\" total=\"@\" />",
    "</runstats>",
    "</nmaprun>",
];
const UNICORN_REC: &str = "TCP @\t@[@]\t\tfrom @  ttl @";
/// `-oB`: header and footer are 99 bytes each, a status record 15 (`out-binary.c`).
const BINARY_BLOCK: usize = 99;
const BINARY_REC: usize = 15;
const BINARY_MAGIC: &[u8] = b"masscan/1.1";
/// `reason_string` (`output.c:118-136`): these flag names in this order, joined by `-`, or `none`.
const FLAG_NAMES: [&str; 8] = ["fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"];

/// The `@` fields of `template` in `s`, each the shortest text up to the literal after it; `None` unless every
/// literal matches.
fn fields<'a>(template: &str, s: &'a str) -> Option<Vec<&'a str>> {
    let mut parts = template.split('@');
    let mut rest = s.strip_prefix(parts.next()?)?;
    let lits: Vec<&str> = parts.collect();
    let mut out = Vec::new();
    for (i, lit) in lits.iter().enumerate() {
        let at = if i + 1 == lits.len() {
            rest.strip_suffix(lit)?.len()
        } else {
            rest.find(lit)?
        };
        out.push(&rest[..at]);
        rest = &rest[at + lit.len()..];
    }
    rest.is_empty().then_some(out)
}
/// `template` with its `@` fields filled in order.
fn fill(template: &str, vals: &[&str]) -> String {
    let mut out = String::new();
    for (i, part) in template.split('@').enumerate() {
        if i > 0 {
            out.push_str(vals.get(i - 1).copied().unwrap_or(""));
        }
        out.push_str(part);
    }
    out
}
/// A value printed the way C prints it: parsed and printed again, it is the same text (no sign, pad or zero).
fn canon<T: std::str::FromStr + ToString>(s: &str) -> Option<T> {
    s.parse::<T>().ok().filter(|v| v.to_string() == s)
}
fn reason_form(s: &str) -> bool {
    if s == "none" {
        return true;
    }
    let mut at = 0;
    s.split('-').all(|name| {
        FLAG_NAMES[at..]
            .iter()
            .position(|f| *f == name)
            .map(|i| at += i + 1)
            .is_some()
    })
}
/// The fields of a record that every format checks the same way.
fn rec(
    status: Option<&str>,
    ip: &str,
    port: Option<&str>,
    ts: Option<&str>,
    reason: Option<&str>,
    ttl: Option<&str>,
    masked: String,
) -> Result<Rec, String> {
    let status = status
        .map(|s| Status::parse(s).ok_or(format!("status {s:?}")))
        .transpose()?;
    let ip = canon(ip).ok_or(format!("address {ip:?}"))?;
    let port = port
        .map(|p| canon::<u16>(p).ok_or(format!("port {p:?}")))
        .transpose()?;
    let ts = ts
        .map(|t| canon::<u64>(t).ok_or(format!("time {t:?}")))
        .transpose()?;
    if let Some(x) = reason.filter(|x| !reason_form(x)) {
        return Err(format!("reason {x:?}"));
    }
    if let Some(t) = ttl.filter(|t| canon::<u8>(t).is_none()) {
        return Err(format!("ttl {t:?}"));
    }
    Ok(Rec {
        status,
        ip,
        port,
        ts,
        masked,
    })
}
/// A record of the templated formats: `order` names the role of each field (`s` status, `i` address, `p` port, `t`
/// time, `r` reason, `l` ttl, `v` service).
fn templated(template: &str, order: &str, line: &str) -> Result<Rec, String> {
    let f = fields(template, line).ok_or("not the record form")?;
    let at = |role: char| order.find(role).map(|i| f[i]);
    if let Some(v) = at('v').filter(|v| v.is_empty() || v.contains(['/', '\t', ' '])) {
        return Err(format!("service {v:?}"));
    }
    let masked: Vec<&str> = order
        .chars()
        .zip(&f)
        .map(|(role, v)| if role == 't' { MASK } else { *v })
        .collect();
    rec(
        at('s'),
        at('i').unwrap_or(""),
        at('p'),
        at('t'),
        at('r'),
        at('l'),
        fill(template, &masked),
    )
}
/// `TCP %s\t%16s[%5d]\t\tfrom %s  ttl %-3d` (`out-unicornscan.c:36-42`): the widths are checked by printing again.
fn unicorn_rec(line: &str) -> Result<Rec, String> {
    let f = fields(UNICORN_REC, line).ok_or("not the record form")?;
    let (svc, port, ttl) = (f[1].trim_start(), f[2].trim_start(), f[4].trim_end());
    let printed = format!("{svc:>16}") == f[1]
        && format!("{port:>5}") == f[2]
        && format!("{ttl:<3}") == f[4]
        && !svc.is_empty()
        && !svc.contains(char::is_whitespace);
    if !printed {
        return Err("a field is not padded the way C prints it".into());
    }
    rec(
        Some(f[0]),
        f[3],
        Some(port),
        None,
        None,
        Some(ttl),
        line.to_owned(),
    )
}

/// The lines of a text document, each ended by `end` (`\n`, XML `\r\n`); no other line break inside.
fn text_lines<'a>(b: &'a [u8], end: &str) -> Result<Vec<&'a str>, String> {
    let t = std::str::from_utf8(b).map_err(|e| format!("not UTF-8: {e}"))?;
    let body = t
        .strip_suffix(end)
        .ok_or_else(|| format!("the last line is not ended by {end:?}"))?;
    let lines: Vec<&str> = body.split(end).collect();
    match lines.iter().find(|l| l.contains(['\r', '\n'])) {
        Some(l) => Err(format!("a stray line break in {l:?}")),
        None => Ok(lines),
    }
}
fn records(
    lines: &[&str],
    parse: impl Fn(&str) -> Result<Rec, String>,
) -> Result<Vec<Rec>, String> {
    if lines.is_empty() {
        return Err(
            "a header without a record (the header is written with the first record)".into(),
        );
    }
    lines
        .iter()
        .map(|l| parse(l).map_err(|e| format!("{l:?}: {e}")))
        .collect()
}

/// A document of format `fmt` taken apart: header, records, footer, every byte in its C form (reference §1). An
/// empty file is a document without a record (masscan writes the header lazily, with the first record). A file that
/// stops after a record, without its footer, is a document that is not `complete`; any other malformation is an error.
pub(crate) fn parse_doc(fmt: Format, b: &[u8]) -> Result<Doc, String> {
    if b.is_empty() {
        return Ok(Doc {
            complete: true,
            ..Doc::default()
        });
    }
    let mut d = Doc::default();
    match fmt {
        Format::List | Format::Unicornscan => {
            let lines = text_lines(b, "\n")?;
            if lines[0] != "#masscan" {
                return Err("no `#masscan` header".into());
            }
            d.complete = lines.len() > 1 && lines.last() == Some(&"# end");
            let body = &lines[1..lines.len() - usize::from(d.complete)];
            d.records = if fmt == Format::List {
                records(body, |l| templated(LIST_REC, "spit", l))?
            } else {
                records(body, unicorn_rec)?
            };
            d.header = "#masscan".into();
            d.footer = if d.complete {
                "# end".into()
            } else {
                String::new()
            };
        }
        Format::Json => {
            let lines = text_lines(b, "\n")?;
            if lines[0] != "[" {
                return Err("no `[` header".into());
            }
            d.complete = lines.len() > 1 && lines.last() == Some(&"]");
            let body = &lines[1..lines.len() - usize::from(d.complete)];
            // `,\n` before every record but the first (`out-json.c:42-46`).
            if body.len().is_multiple_of(2) || body.iter().skip(1).step_by(2).any(|l| *l != ",") {
                return Err("the records are not separated by `,` lines".into());
            }
            let recs: Vec<&str> = body.iter().step_by(2).copied().collect();
            d.records = records(&recs, |l| templated(JSON_REC, "itpsrl", l))?;
            d.header = "[".into();
            d.footer = if d.complete {
                "]".into()
            } else {
                String::new()
            };
        }
        Format::Ndjson | Format::Hostonly => {
            let lines = text_lines(b, "\n")?;
            d.records = if fmt == Format::Ndjson {
                records(&lines, |l| templated(NDJSON_REC, "itpsrl", l))?
            } else {
                records(&lines, |l| {
                    rec(None, l, None, None, None, None, l.to_owned())
                })?
            };
            d.complete = true;
        }
        Format::Grepable => {
            let lines = text_lines(b, "\n")?;
            let at = |l: &str, t: &str| {
                fields(t, l)
                    .and_then(|f| c_time(f[0]))
                    .ok_or_else(|| format!("{l:?} is not `{t}` with a C-locale time"))
            };
            d.clock.push(at(lines[0], GREPABLE_HEAD)?);
            let ports = lines.get(1).copied().unwrap_or("");
            if !(ports.starts_with(GREPABLE_PORTS.0) && ports.ends_with(GREPABLE_PORTS.1)) {
                return Err(format!("{ports:?} is not the `# Ports scanned:` line"));
            }
            let last = lines.last().copied().unwrap_or("");
            d.complete = lines.len() > 2 && fields(GREPABLE_FOOT, last).is_some();
            if d.complete {
                d.clock.push(at(last, GREPABLE_FOOT)?);
                d.footer = fill(GREPABLE_FOOT, &[MASK]);
            }
            let body = &lines[2.min(lines.len())..lines.len() - usize::from(d.complete)];
            d.records = records(body, |l| templated(GREPABLE_REC, "tipsv", l))?;
            d.header = format!("{}\n{ports}", fill(GREPABLE_HEAD, &[MASK]));
        }
        Format::Xml => {
            let lines = text_lines(b, "\r\n")?;
            if lines.len() < XML_HEAD.len()
                || lines[0] != XML_HEAD[0]
                || lines[1] != XML_HEAD[1]
                || lines[3] != XML_HEAD[3]
            {
                return Err("not the XML header".into());
            }
            let start = fields(XML_HEAD[2], lines[2])
                .and_then(|f| canon::<u64>(f[0]))
                .ok_or("not the <nmaprun> line")?;
            d.clock.push(start);
            d.header = [
                XML_HEAD[0],
                XML_HEAD[1],
                &fill(XML_HEAD[2], &[MASK]),
                XML_HEAD[3],
            ]
            .join("\r\n");
            let foot = lines
                .iter()
                .position(|l| *l == XML_FOOT[0])
                .unwrap_or(lines.len());
            d.records = records(&lines[4..foot], |l| templated(XML_REC, "tipsrl", l))?;
            let tail = &lines[foot..];
            if tail.len() > XML_FOOT.len() {
                return Err("lines after </nmaprun>".into());
            }
            let mut masked = Vec::new();
            for (i, l) in tail.iter().enumerate() {
                let f = fields(XML_FOOT[i], l)
                    .ok_or_else(|| format!("{l:?} is not the footer's line"))?;
                match i {
                    1 => {
                        let time = canon::<u64>(f[0]).ok_or("finished time")?;
                        canon::<u64>(f[2]).ok_or("elapsed")?;
                        if !local_time_form(f[1]) {
                            return Err(format!("timestr {:?}", f[1]));
                        }
                        d.clock.push(time);
                        masked.push(fill(XML_FOOT[1], &[MASK, MASK, MASK]));
                    }
                    2 => {
                        let n: Vec<u64> = f
                            .iter()
                            .map(|x| canon::<u64>(x))
                            .collect::<Option<_>>()
                            .ok_or("hosts")?;
                        d.hosts = Some((n[0], n[1], n[2]));
                        masked.push((*l).to_owned());
                    }
                    _ => masked.push((*l).to_owned()),
                }
            }
            d.complete = tail.len() == XML_FOOT.len();
            d.footer = masked.join("\r\n");
        }
        Format::Binary => {
            if b.len() < BINARY_BLOCK {
                return Err(format!(
                    "{} bytes, shorter than the 99-byte header",
                    b.len()
                ));
            }
            let (head, rest) = b.split_at(BINARY_BLOCK);
            let after = head
                .strip_prefix(b"masscan/1.1\ns:".as_slice())
                .ok_or("the header is not `masscan/1.1\\ns:`")?;
            let digits = after.iter().take_while(|c| c.is_ascii_digit()).count();
            let start = std::str::from_utf8(&after[..digits])
                .ok()
                .and_then(canon::<u64>)
                .ok_or("the header's start time")?;
            if after.get(digits) != Some(&b'\n') || after[digits + 1..].iter().any(|x| *x != 0) {
                return Err("the header is not padded with zeros to 99 bytes".into());
            }
            d.clock.push(start);
            d.header = format!("masscan/1.1 s:{MASK} (99 bytes)");
            let mut foot = [0u8; BINARY_BLOCK];
            foot[..BINARY_MAGIC.len()].copy_from_slice(BINARY_MAGIC);
            let body = if rest.len() >= BINARY_BLOCK
                && rest.ends_with(&foot)
                && (rest.len() - BINARY_BLOCK).is_multiple_of(BINARY_REC)
            {
                d.complete = true;
                d.footer = "masscan/1.1 (99 bytes)".into();
                &rest[..rest.len() - BINARY_BLOCK]
            } else if rest.len().is_multiple_of(BINARY_REC) {
                rest
            } else {
                return Err(format!("{} bytes are not 99 + 15n + 99", b.len()));
            };
            if body.is_empty() {
                return Err("a header without a record".into());
            }
            d.records = body
                .chunks(BINARY_REC)
                .map(binary_rec)
                .collect::<Result<_, _>>()?;
        }
    }
    Ok(d)
}
/// A 15-byte status record (`out-binary.c:154-211`): type 6 open or 7 closed, length 13, time, address, protocol 6,
/// port, reason byte, ttl, all big-endian.
fn binary_rec(b: &[u8]) -> Result<Rec, String> {
    let status = match (b[0], b[1], b[10]) {
        (6, 13, 6) => Status::Open,
        (7, 13, 6) => Status::Closed,
        _ => return Err(format!("not a TCP status record: {}", verify::hex(b))),
    };
    let ip = Ipv4Addr::new(b[6], b[7], b[8], b[9]);
    let port = u16::from_be_bytes([b[11], b[12]]);
    Ok(Rec {
        status: Some(status),
        ip,
        port: Some(port),
        ts: Some(u64::from(u32::from_be_bytes([b[2], b[3], b[4], b[5]]))),
        masked: format!(
            "{} {ip} port {port} reason 0x{:02x} ttl {} at {MASK}",
            status.name(),
            b[13],
            b[14]
        ),
    })
}
/// `%Y-%m-%d %H:%M:%S` (the XML footer's local time): its form only, the zone is the host's.
fn local_time_form(s: &str) -> bool {
    s.len() == 19
        && s.bytes().enumerate().all(|(i, c)| match i {
            4 | 7 => c == b'-',
            10 => c == b' ',
            13 | 16 => c == b':',
            _ => c.is_ascii_digit(),
        })
}
/// `strftime("%c")` of the C locale in GMT (`out-grepable.c:78-84`): `%a %b %e %H:%M:%S %Y`, the day padded with a
/// space. The Unix time, or `None` for any other text (a wrong weekday, a zero-padded day, a day not in the month).
pub(crate) fn c_time(s: &str) -> Option<u64> {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // The weekday is checked by printing the date again.
    let (_weekday, rest) = s.split_once(' ')?;
    let (mon, rest) = rest.split_once(' ')?;
    let (day, rest) = (rest.get(..2)?, rest.get(3..)?);
    let (hms, year) = rest.split_once(' ')?;
    let m = MONTHS.iter().position(|x| *x == mon)? as i64 + 1;
    let d: i64 = day.trim_start().parse().ok()?;
    let y: i64 = canon(year)?;
    let t: Vec<i64> = hms
        .split(':')
        .map(|x| x.parse().ok())
        .collect::<Option<_>>()?;
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if t.len() != 3
        || !(1..=month_days[m as usize - 1]).contains(&d)
        || t[0] > 23
        || t[1] > 59
        || t[2] > 60
    {
        return None;
    }
    // Days from the civil date (H. Hinnant's algorithm), 1970-01-01 is day 0, a Thursday.
    let (yy, mm) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    let printed = format!(
        "{} {mon} {d:>2} {:02}:{:02}:{:02} {y}",
        DAYS[(days + 4).rem_euclid(7) as usize],
        t[0],
        t[1],
        t[2]
    );
    (printed == s && days >= 0).then(|| (days * 86_400 + t[0] * 3600 + t[1] * 60 + t[2]) as u64)
}
/// `--readscan` of `inputs` into `-oL` with `--show open,closed`: every status record in file order, its own time.
pub(crate) fn readscan_list(inputs: &[&[u8]]) -> Result<Vec<u8>, String> {
    let mut lines = Vec::new();
    for b in inputs {
        for r in parse_doc(Format::Binary, b)?.records {
            lines.push(format!(
                "{} tcp {} {} {}\n",
                r.status.map_or("", Status::name),
                r.port.unwrap_or_default(),
                r.ip,
                r.ts.unwrap_or_default()
            ));
        }
    }
    if lines.is_empty() {
        return Ok(Vec::new());
    }
    Ok(format!("#masscan\n{}# end\n", lines.concat()).into_bytes())
}

// ------------------------------------------------------------------ the wire

/// `(status, ip, port)` the peer answered to a scanner SYN inside the capture window: a SYN-ACK is open, an RST
/// closed (the answer's ack is the SYN's sequence plus one, from the SYN's port).
fn wire_replies(fr: &Frames, w: &av::Wire, st: &av::Stand) -> BTreeSet<Key> {
    let asked: BTreeSet<(String, u16, u16, u32)> = w
        .syns
        .iter()
        .filter_map(|(_, f)| tcp(f))
        .map(|i| (i.dst, i.dp, i.sp, i.seq.wrapping_add(1)))
        .collect();
    let (start, end) = av::window(w);
    let (sm, src) = (
        av::dash(st.scanner_mac).replace('-', ":"),
        st.scanner_ip.to_string(),
    );
    fr.iter()
        .filter(|(t, _)| (start..=end).contains(t))
        .filter_map(|(_, f)| tcp(f))
        .filter(|i| {
            i.dm == sm && i.dst == src && asked.contains(&(i.src.clone(), i.sp, i.dp, i.ack))
        })
        .filter_map(|i| {
            let status = if i.flags & 0x12 == 0x12 {
                Status::Open
            } else if i.flags & 0x04 != 0 {
                Status::Closed
            } else {
                return None;
            };
            Some((Some(status), i.src.parse().ok()?, Some(i.sp)))
        })
        .collect()
}
/// The frames a scanner sent (its MAC), the lab's markers aside.
fn scanner_frames(fr: &Frames, st: &av::Stand) -> usize {
    use crate::link::{END_PAYLOAD, START_PAYLOAD};
    fr.iter()
        .filter(|(_, f)| f.get(6..12) == Some(&st.scanner_mac[..]))
        .filter(|(_, f)| !av::is_marker(f, START_PAYLOAD) && !av::is_marker(f, END_PAYLOAD))
        .count()
}
/// The keys `fmt` can show of `keys`: `-oH` only the address.
fn project(fmt: Format, keys: impl IntoIterator<Item = Key>) -> Vec<Key> {
    let mut v: Vec<Key> = keys
        .into_iter()
        .map(|k| {
            if fmt == Format::Hostonly {
                (None, k.1, None)
            } else {
                k
            }
        })
        .collect();
    v.sort();
    v
}
/// The stand's replies to a scan of the case: 80 and 8080 open on every peer, 443 closed with `--show open,closed`.
fn stand_replies(c: &OutputCase) -> BTreeSet<Key> {
    let st = av::stand(Plan::Linux);
    let mut out = BTreeSet::new();
    for ip in &st.peer_ips {
        for port in [80u16, 443, 8080] {
            let open = st.open_ports.contains(&port);
            if open || c.show_closed {
                out.insert((
                    Some(if open { Status::Open } else { Status::Closed }),
                    *ip,
                    Some(port),
                ));
            }
        }
    }
    out
}

// ------------------------------------------------------------------ privacy

/// The files a scanner wrote or that name its argv: their addresses must be the stand's.
const SCANNER_TEXT: [&str; 8] = [
    "argv.json",
    "expect.json",
    "stdout.txt",
    "stderr.txt",
    "output.txt",
    "oracle/stdout.txt",
    "oracle/stderr.txt",
    "oracle/output.txt",
];
/// The line forms of a scanner's stderr, beside the ones `autodetect-verify` knows: rmasscan's open failure (its
/// path is [`UNOPENABLE`]); the oracle's `[+] --readscan` lines of the two inputs.
fn line_problems(rel: &str, text: &str) -> Vec<String> {
    let keep = |drop: &dyn Fn(&str) -> bool| {
        text.split('\n')
            .filter(|l| !drop(l.trim_end_matches('\r')))
            .collect::<Vec<_>>()
            .join("\n")
    };
    match rel {
        // A line is what follows its last `\r` (the status line's grammar is a behaviour check of its own).
        "stderr.txt" => av::output_problems(
            rel,
            &keep(&|l| {
                l == OPEN_FAILURE
                    || l == OPEN_FAILURE_APPEND
                    || l.starts_with(&format!("{UNOPENABLE}: "))
            })
            .split('\n')
            .map(|l| {
                let l = l.strip_suffix('\r').unwrap_or(l);
                l.rsplit('\r').next().unwrap_or(l)
            })
            .collect::<Vec<_>>()
            .join("\n"),
        ),
        "oracle/stderr.txt" => av::oracle_stderr_problems(&keep(&|l| {
            READSCAN_INPUTS
                .iter()
                .any(|n| l == format!("[+] --readscan {n}"))
        })),
        _ => Vec::new(),
    }
}
/// A binary document holds addresses as bytes: it must parse, and every record must be the stand's.
fn binary_problems(b: &[u8]) -> Vec<String> {
    let st = av::stand(Plan::Linux);
    match parse_doc(Format::Binary, b) {
        Err(e) => vec![format!(
            "not a masscan -oB file ({e}); its bytes are not scanned as text"
        )],
        Ok(d) => d
            .records
            .iter()
            .filter(|r| !st.peer_ips.contains(&r.ip))
            .map(|r| format!("address {}", r.ip))
            .collect(),
    }
}
/// One INVALID check per file that names something outside the allowlist, or one PASS check for all.
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
        let mut p = match fs::read(d.join(rel)) {
            Err(e) => vec![format!("unreadable: {e}")],
            Ok(b) if ext == "bin" => binary_problems(&b),
            Ok(b) => {
                let text = String::from_utf8_lossy(&b);
                let mut p = av::token_problems(&text, SCANNER_TEXT.contains(&rel.as_str()));
                p.extend(line_problems(rel, &text));
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
            "privacy: every text and binary file holds only allowlisted names, addresses and paths",
            PASS,
            format!("{seen} files"),
            false,
        );
    }
}

// ------------------------------------------------------------------ one run

/// Who wrote a side of the run: rmasscan (its misbehaviour FAILs) or the C oracle (a broken oracle is a broken stand:
/// INVALID).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Who {
    Rmasscan,
    Oracle,
}
impl Who {
    fn dir(self) -> &'static str {
        match self {
            Who::Rmasscan => "",
            Who::Oracle => "oracle/",
        }
    }
    fn beh(self, r: &mut Run, name: &str, ok: bool, detail: impl ToString) {
        match self {
            Who::Rmasscan => r.beh(name, ok, detail),
            Who::Oracle => r.inv(name, ok, detail),
        }
    }
    /// A check against the capture: FAIL only once the evidence is proven.
    fn cap(self, r: &mut Run, name: &str, ok: bool, detail: impl ToString) {
        match self {
            Who::Rmasscan => r.cap(name, ok, detail),
            Who::Oracle => r.inv(name, ok, detail),
        }
    }
}

/// What one scanner left in the run directory, and its capture.
struct Side {
    who: Who,
    exit: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
    /// The document (`output.txt`/`output.bin`, or stdout for `-` targets), by its file name, parsed.
    doc: Option<(String, Doc)>,
    /// Its document's raw bytes (`o17_readscan` compares them).
    raw: Option<Vec<u8>>,
    frames: Option<Frames>,
}

fn read_side(r: &mut Run, d: &Path, c: &OutputCase, who: Who, frames: Option<Frames>) -> Side {
    let dir = who.dir();
    let exit = av::need(r, d, &format!("{dir}exit.txt")).and_then(|t| {
        let rc = av::parse_exit(&t);
        if rc.is_none() {
            r.inv(
                &format!("{dir}exit.txt holds an exit code"),
                false,
                t.trim(),
            );
        }
        rc
    });
    let stdout = av::need(r, d, &format!("{dir}stdout.txt"));
    let stderr = av::need(r, d, &format!("{dir}stderr.txt"));
    let name = match c.target {
        Target::File if c.writes_file() => Some(format!("{dir}{}", c.format.file())),
        Target::Stdout => Some(format!("{dir}stdout.txt")),
        _ => None,
    };
    let (mut doc, mut raw) = (None, None);
    if let Some(name) = name {
        match fs::read(d.join(&name)) {
            Err(_) => who.beh(r, &format!("{name} written"), false, "missing"),
            Ok(b) => {
                match parse_doc(c.format, &b) {
                    Ok(x) => {
                        who.beh(
                            r,
                            &format!("{name} is a well-formed {} document", fmt_name(c.format)),
                            true,
                            format!("{} records", x.records.len()),
                        );
                        doc = Some((name, x));
                    }
                    Err(e) => who.beh(
                        r,
                        &format!("{name} is a well-formed {} document", fmt_name(c.format)),
                        false,
                        e,
                    ),
                }
                raw = Some(b);
            }
        }
    }
    Side {
        who,
        exit,
        stdout,
        stderr,
        doc,
        raw,
        frames,
    }
}
fn fmt_name(f: Format) -> String {
    serde_json::to_value(f)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The checks of a document against the case, its capture and the clock.
fn doc_checks(r: &mut Run, c: &OutputCase, s: &Side, w: Option<&av::Wire>) {
    let (Some((name, doc)), who) = (&s.doc, s.who) else {
        return;
    };
    let keys: Vec<Key> = doc.records.iter().map(Rec::key).collect();
    let set: BTreeSet<Key> = keys.iter().copied().collect();
    if c.format != Format::Hostonly {
        who.beh(
            r,
            &format!("{name} holds no record twice"),
            set.len() == keys.len(),
            keys.len() - set.len(),
        );
    }
    if let Some((up, down, total)) = doc.hosts {
        let open = keys.iter().filter(|k| k.0 == Some(Status::Open)).count() as u64;
        let closed = keys.len() as u64 - open;
        who.beh(
            r,
            &format!("{name} <hosts> up and down equal its open and closed records"),
            (up, down, total) == (open, closed, open + closed),
            format!("up {up} down {down} total {total}, records {open} open {closed} closed"),
        );
    }
    if c.format == Format::Grepable {
        let want = format!(
            "{}3;80-80,443-443,8080-8080{}",
            GREPABLE_PORTS.0, GREPABLE_PORTS.1
        );
        who.beh(
            r,
            &format!("{name} names the scanned ports"),
            doc.header.ends_with(&want),
            &doc.header,
        );
    }
    match c.kind {
        OutputKind::Scan => {
            who.beh(
                r,
                &format!("{name} is complete (its footer written)"),
                doc.complete,
                "",
            );
            let want = project(c.format, stand_replies(c));
            who.beh(
                r,
                &format!("{name} records are the stand's replies (80 and 8080 open on every peer, 443 closed with --show open,closed)"),
                project(c.format, keys.iter().copied()) == want,
                format!("{} records, {} expected", keys.len(), want.len()),
            );
        }
        OutputKind::Interrupt => {
            who.beh(
                r,
                &format!("{name} is complete after the interrupt (JSON closed by ], XML by </nmaprun>, binary 99-byte footer)"),
                doc.complete,
                "",
            );
            r.inv(
                &format!("{name} holds a record (only then does the interrupt prove the footer)"),
                !keys.is_empty(),
                keys.len(),
            );
        }
        _ => {}
    }
    let (Some(fr), Some(w)) = (&s.frames, w) else {
        return;
    };
    let st = av::stand(Plan::Linux);
    let wire: BTreeSet<Key> = wire_replies(fr, w, &st)
        .into_iter()
        .filter(|k| k.0 == Some(Status::Open) || c.show_closed)
        .collect();
    let mine = project(c.format, keys.iter().copied());
    let theirs = project(c.format, wire.iter().copied());
    if c.kind == OutputKind::Interrupt {
        // A stop ends the receiver too: replies to the last SYNs may come after it.
        let extra: Vec<&Key> = set.difference(&wire).collect();
        who.cap(
            r,
            &format!("{name} records are replies on the wire (a subset after the stop)"),
            extra.is_empty(),
            format!("without a reply {extra:?}"),
        );
    } else {
        who.cap(
            r,
            &format!("{name} records are the replies on the wire in the run window"),
            mine == theirs,
            format!("{} records, {} replies", mine.len(), theirs.len()),
        );
    }
    let (start, end) = av::window(w);
    let inside = |t: u64| (start.floor()..=end).contains(&(t as f64));
    let late: Vec<u64> = doc
        .records
        .iter()
        .filter_map(|x| x.ts)
        .filter(|t| !inside(*t))
        .collect();
    who.cap(
        r,
        &format!("{name} record times lie in the capture window"),
        late.is_empty(),
        format!("{late:?} outside {start} .. {end}"),
    );
    let off: Vec<u64> = doc.clock.iter().copied().filter(|t| !inside(*t)).collect();
    who.cap(
        r,
        &format!("{name} header and footer clocks lie in the capture window"),
        off.is_empty(),
        format!("{off:?} outside {start} .. {end}"),
    );
}

/// stdout as the case wants it.
fn stdout_checks(r: &mut Run, c: &OutputCase, s: &Side) {
    let (Some(text), who) = (&s.stdout, s.who) else {
        return;
    };
    let name = format!("{}stdout.txt", who.dir());
    match c.stdout() {
        StdoutForm::Silent => who.beh(
            r,
            &format!("{name} is empty (a file format silences stdout)"),
            text.is_empty(),
            text.len(),
        ),
        StdoutForm::Document => {}
        StdoutForm::Discovered => {
            let lines = av::stdout_lines(text);
            let got: Vec<Key> = lines
                .iter()
                .filter_map(|l| {
                    av::discovered(l).filter(|(ip, p)| *l == av::discovered_line(*ip, *p))
                })
                .map(|(ip, p)| (Some(Status::Open), ip, Some(p)))
                .collect();
            let want: Vec<Key> = s
                .doc
                .as_ref()
                .map(|(_, d)| {
                    d.records
                        .iter()
                        .map(Rec::key)
                        .filter(|k| k.0 == Some(Status::Open))
                        .collect()
                })
                .unwrap_or_default();
            let (mut a, mut b) = (got.clone(), want);
            a.sort();
            b.sort();
            who.beh(
                r,
                &format!(
                    "{name} holds a Discovered line of 80 bytes per open record (--interactive)"
                ),
                got.len() == lines.len() && a == b,
                format!(
                    "{} lines, {} parsed, {} open records",
                    lines.len(),
                    got.len(),
                    b.len()
                ),
            );
        }
        StdoutForm::Elapsed => {
            let n = text
                .strip_suffix(" milliseconds elapsed\n")
                .and_then(canon::<u64>);
            who.beh(
                r,
                &format!(
                    "{name} is `N milliseconds elapsed` of a scan that waited 3 s (--nostatus)"
                ),
                n.is_some_and(|n| n >= 3000),
                text.trim_end(),
            );
        }
    }
}

/// rmasscan's stderr of a live scan: the status line's grammar and place, the `[+]` lines, the Ctrl-C line, and
/// `[+] finished` against the wire and the records.
fn scan_stderr(
    r: &mut Run,
    c: &OutputCase,
    s: &Side,
    w: Option<&av::Wire>,
    argv: Option<&ArgvRecord>,
    int: Option<&InterruptRecord>,
) {
    let Some(text) = &s.stderr else { return };
    let pieces = match av::screen(text) {
        Ok(p) => {
            r.beh(
                "stderr.txt: every fragment before a \\r follows the status line grammar",
                true,
                "",
            );
            p
        }
        Err(e) => {
            r.beh(
                "stderr.txt: every fragment before a \\r follows the status line grammar",
                false,
                e,
            );
            return;
        }
    };
    let det = match av::parse_stderr(text) {
        Ok(d) => {
            r.add(
                "stderr.txt parses into [+] lines and the status line",
                PASS,
                "",
                false,
            );
            d
        }
        Err(e) => {
            r.inv(
                "stderr.txt parses into [+] lines and the status line",
                false,
                e,
            );
            return;
        }
    };
    let st = av::stand(Plan::Linux);
    let sourced = |v: &str, src: &str| {
        Some(Sourced {
            value: v.into(),
            source: src.into(),
        })
    };
    r.beh(
        "[+] detection lines are the stand's (veth-a by the route, its MAC and IP, router 198.18.0.2 by ARP), seed 1 given",
        det.interface == sourced(st.iface, "detected: route to 198.18.0.2")
            && det.source_mac == sourced(&av::dash(st.scanner_mac), "detected")
            && det.source_ip == sourced(&st.scanner_ip.to_string(), "detected")
            && det.router_ip == sourced("198.18.0.2", "interface default gateway")
            && det.router_mac.as_ref().is_some_and(|m| m.value == av::dash(st.peer_mac) && m.source == "arp")
            && det.seed == sourced("1", "given")
            && det.fail.is_none()
            && det.error.is_none(),
        format!("{det:?}"),
    );
    let stopped = c.kind == OutputKind::Interrupt;
    let reason = if stopped { "Stopped" } else { "Completed" };
    r.beh(
        &format!("[+] finished: {reason}"),
        det.finished.as_ref().is_some_and(|f| f.reason == reason),
        format!("{:?}", det.finished),
    );
    let ticks = pieces
        .iter()
        .filter(|p| matches!(p, Piece::Running | Piece::Waiting))
        .count();
    let erases = pieces.iter().filter(|p| **p == Piece::Erase).count();
    let ndjson = pieces.iter().filter(|p| **p == Piece::Ndjson).count();
    let before_finished = pieces
        .iter()
        .position(|p| matches!(p, Piece::Line(l) if l.starts_with("[+] finished: ")))
        .and_then(|i| i.checked_sub(1))
        .map(|i| &pieces[i]);
    match c.status() {
        StatusForm::Text => r.beh(
            "stderr.txt: the status line ticks and ends with the 77-space erase right before [+] finished",
            ticks >= 1 && erases == 1 && ndjson == 0 && before_finished == Some(&Piece::Erase),
            format!("{ticks} ticks, {erases} erases, {ndjson} ndjson, before [+] finished {before_finished:?}"),
        ),
        _ => r.beh(
            "stderr.txt has no status line (--nostatus)",
            ticks + erases + ndjson == 0,
            format!("{ticks} ticks, {erases} erases, {ndjson} ndjson"),
        ),
    }
    let ctrl_c = pieces.iter().filter(|p| **p == Piece::Interrupt).count();
    if stopped {
        r.beh(
            "stderr.txt carries the Ctrl-C line once",
            ctrl_c == 1,
            ctrl_c,
        );
    } else {
        r.beh("stderr.txt carries no Ctrl-C line", ctrl_c == 0, ctrl_c);
    }
    if let (Some(f), Some((_, doc))) = (&det.finished, &s.doc) {
        let open = doc
            .records
            .iter()
            .filter(|x| x.status == Some(Status::Open))
            .count() as u64;
        let all = doc.records.len() as u64;
        r.beh(
            "[+] finished reports open (-oH has no status) and, with --show open,closed, replies equal to the records",
            (c.format == Format::Hostonly || f.open == open) && (!c.show_closed || f.replies == all),
            format!("open {} replies {}, records {open} open of {all}", f.open, f.replies),
        );
    }
    let Some(w) = w else { return };
    let act: Vec<Vec<u8>> = w.syns.iter().map(|(_, f)| f.clone()).collect();
    let sent = det.finished.as_ref().map(|f| f.sent);
    r.cap(
        "[+] finished reports sent equal to the scanner SYNs on the wire",
        sent == Some(act.len() as u64),
        format!("printed {sent:?}, wire {}", act.len()),
    );
    let plan = argv
        .ok_or_else(|| "argv.json missing".to_owned())
        .map(|a| ArgvRecord {
            argv: scan_argv(&a.argv),
        })
        .and_then(|a| av::plan_args_from(&a, &det))
        .and_then(|a| verify::plan_frames(&a));
    let plan = match plan {
        Ok(p) => p,
        Err(e) => {
            r.inv(
                "the scan plan rebuilds from argv.json (output flags aside) and the [+] lines",
                false,
                e,
            );
            return;
        }
    };
    if !stopped {
        let (rc, msg) = pcap::compare_streams(&plan, &act);
        r.cap(
            "the scanner SYNs equal the plan of argv.json and the [+] lines, in order, each once",
            rc == 0,
            msg,
        );
        return;
    }
    r.beh(
        "the interrupted scan stopped before its end (sent below the plan)",
        act.len() < plan.len(),
        format!("{} of {}", act.len(), plan.len()),
    );
    r.cap(
        "the scanner SYNs are the plan's first ones, in order",
        act.len() <= plan.len() && plan[..act.len()] == act[..],
        format!("{} SYNs", act.len()),
    );
    let Some(i) = int else { return };
    let (start, end) = av::window(w);
    r.inv(
        "interrupt.json: SIGINT about 2 s after the start, inside the capture window, a 30 s exit timeout",
        i.signal == "INT"
            && i.after_s == INTERRUPT_AFTER_S
            && i.exit_within_s == INTERRUPT_EXIT_S
            && i.signal_unix.is_none_or(|t| (start..=end).contains(&t)),
        format!("{i:?}, window {start} .. {end}"),
    );
    r.beh(
        "rmasscan was still scanning when SIGINT came",
        i.signal_unix.is_some(),
        format!("{:?}", i.signal_unix),
    );
    r.beh(
        "rmasscan exited within 30 s of SIGINT (no SIGKILL)",
        !i.killed,
        i.killed,
    );
    if let Some(t) = i.signal_unix {
        let late = w.syns.iter().filter(|(x, _)| *x > t + 1.0).count();
        r.cap("no SYN later than 1 s after SIGINT", late == 0, late);
    }
}
/// The scan's own argv: the output and status flags out (the verifier's argv model knows scans only).
fn scan_argv(argv: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        i += 1;
        if a == "--show" || (a.len() == 3 && a.starts_with("-o")) {
            i += 1;
        } else if !matches!(a, "--interactive" | "--nostatus") {
            out.push(a.to_owned());
        }
    }
    out
}

/// Does a file carry an extension evidence may carry: the autodetect ones and `bin` (`-oB` documents)?
fn evidence_extension(f: &str) -> bool {
    Path::new(f)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e == "bin" || EVIDENCE_EXTENSIONS.contains(&e))
}
/// The evidence gate: hashes, extensions (and `bin` for `-oB` documents), the stand's seal before and after.
fn gate(r: &mut Run, d: &Path, files: &[String]) {
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
    let odd: Vec<&String> = files.iter().filter(|f| !evidence_extension(f)).collect();
    r.inv(
        "evidence files carry only the allowed extensions (json pcap txt log err sha256 md, bin for -oB)",
        odd.is_empty(),
        format!("{odd:?}"),
    );
    av::linux_seal(r, d);
}

fn verify_run(root: &Path, c: &OutputCase, root_links: &[String]) -> Run {
    let mut r = Run::new(c.tag);
    let rel = format!("runs/{}", c.tag);
    if root_links.iter().any(|l| l == "runs" || *l == rel) {
        r.inv(
            "the run directory is a real directory, not a symbolic link",
            false,
            rel,
        );
        return r;
    }
    let d = root.join("runs").join(c.tag);
    if !d.is_dir() {
        r.add("run directory present", NOT_RUN, "missing", false);
        return r;
    }
    let t = tree(&d);
    let st = av::stand(Plan::Linux);
    // ---- safety: independent of every other file
    r.safety(
        "no compressed capture in the run directory",
        !t.files.iter().chain(&t.links).any(|f| f.ends_with(".gz")),
        "captures are stored uncompressed; the verifier has no decompression",
    );
    let peer = av::capture(&mut r, &d, PEER_PCAP, &t.links);
    let oracle = if c.oracle {
        av::capture(&mut r, &d, ORACLE_PCAP, &t.links)
    } else {
        None
    };
    av::safety(
        &mut r,
        Plan::Linux,
        &d,
        &t.links,
        peer.as_ref().map(|p| &p.0),
        oracle.as_ref().map(|p| &p.0),
    );
    if !t.links.is_empty() {
        r.inv(
            "no symbolic link in the run directory (links are never followed)",
            false,
            format!("{:?}", t.links),
        );
        return r;
    }
    // ---- the evidence gate
    gate(&mut r, &d, &t.files);
    if let Some(p) = &peer {
        av::witness(&mut r, &d, PEER_PCAP, CAPTURE_JSON, p, &st);
    }
    if let Some(o) = &oracle {
        av::witness(&mut r, &d, ORACLE_PCAP, ORACLE_CAPTURE_JSON, o, &st);
    }
    privacy(&mut r, &d, &t.files);
    // ---- the case: argv.json and expect.json are exactly the table's
    let argv: Option<ArgvRecord> = av::typed(&mut r, &d, "argv.json");
    let expect: Option<OutputExpect> = av::typed(&mut r, &d, "expect.json");
    let argv_ok = argv.as_ref().is_some_and(|a| a.argv == c.argv());
    if let Some(a) = &argv {
        r.inv(
            "argv.json is the case's argv in the case table",
            argv_ok,
            format!("{:?}, table {:?}", a.argv, c.argv()),
        );
    }
    let expect_ok = expect.as_ref() == Some(&c.expect());
    if expect.is_some() {
        r.inv(
            "expect.json equals the case table's entry",
            expect_ok,
            format!("table {:?}", c.expect()),
        );
    }
    r.argv_ok = argv_ok && expect_ok;
    let int: Option<InterruptRecord> = (c.kind == OutputKind::Interrupt)
        .then(|| av::typed(&mut r, &d, INTERRUPT_JSON))
        .flatten();
    // ---- what the scanners wrote
    let rm = read_side(&mut r, &d, c, Who::Rmasscan, peer.map(|p| p.0));
    let or = c
        .oracle
        .then(|| read_side(&mut r, &d, c, Who::Oracle, oracle.map(|p| p.0)));
    behaviour(
        &mut r,
        root,
        c,
        &rm,
        or.as_ref(),
        argv.as_ref(),
        int.as_ref(),
    );
    r
}

fn behaviour(
    r: &mut Run,
    root: &Path,
    c: &OutputCase,
    rm: &Side,
    or: Option<&Side>,
    argv: Option<&ArgvRecord>,
    int: Option<&InterruptRecord>,
) {
    let st = av::stand(Plan::Linux);
    let wire = |s: &Side| s.frames.as_ref().map(|fr| av::classify(fr, st.scanner_mac));
    let want_exit = if c.kind == OutputKind::OpenFailure {
        1
    } else {
        0
    };
    for s in std::iter::once(rm).chain(or) {
        if let Some(rc) = s.exit {
            s.who.beh(
                r,
                &format!("{}exit.txt is {want_exit}", s.who.dir()),
                rc == want_exit,
                rc,
            );
        }
        stdout_checks(r, c, s);
        if c.kind != OutputKind::Readscan {
            doc_checks(r, c, s, wire(s).as_ref());
        }
    }
    match c.kind {
        OutputKind::Scan | OutputKind::Interrupt => {
            scan_stderr(r, c, rm, wire(rm).as_ref(), argv, int);
            if let Some(o) = or {
                parity(r, c, rm, o);
            }
        }
        OutputKind::OpenFailure => {
            let lines = rm.stderr.as_deref().map(|t| {
                av::screen(t).map(|p| {
                    p.into_iter()
                        .map(|x| match x {
                            Piece::Line(l) => l,
                            other => format!("{other:?}"),
                        })
                        .collect::<Vec<_>>()
                })
            });
            let want: Vec<String> = DETECTION_LINES
                .iter()
                .map(|l| (*l).to_owned())
                .chain([OPEN_FAILURE.to_owned()])
                .collect();
            if let Some(lines) = lines {
                let ok = lines.as_ref().is_ok_and(|l| {
                    l.len() == want.len() + 1
                        && l[..want.len()] == want[..]
                        && l[want.len()]
                            .strip_prefix(&format!("{UNOPENABLE}: "))
                            .is_some_and(|e| !e.is_empty())
                });
                r.beh(
                    "stderr.txt: the four [+] detection lines, then `out: could not open file for writing` and `<path>: <error>`, no status line",
                    ok,
                    format!("{lines:?}"),
                );
            }
            r.inv(
                "output.txt is not in the run (the file could not open)",
                !root.join("runs").join(c.tag).join("output.txt").exists(),
                "",
            );
            if let Some(fr) = &rm.frames {
                let n = scanner_frames(fr, &st);
                r.cap("no scanner frame (ARP or SYN, markers aside) when the output file does not open", n == 0, n);
            }
        }
        OutputKind::Readscan => readscan(r, root, c, rm, or),
    }
}
/// The four `[+]` lines rmasscan prints on the stand before it opens the output file (Р8: the file opens before ARP).
const DETECTION_LINES: [&str; 4] = [
    "[+] interface = veth-a (detected: route to 198.18.0.2)",
    "[+] source-mac = 02-aa-00-00-00-01 (detected)",
    "[+] source-ip = 198.18.0.1 (detected)",
    "[+] router-ip = 198.18.0.2 (interface default gateway)",
];

/// rmasscan against the oracle on the same stand and argv: records, header and footer, stdout, time masked.
fn parity(r: &mut Run, c: &OutputCase, rm: &Side, or: &Side) {
    if let (Some((name, a)), Some((_, b))) = (&rm.doc, &or.doc) {
        fn masked(d: &Doc) -> Vec<&str> {
            let mut v: Vec<&str> = d.records.iter().map(|x| x.masked.as_str()).collect();
            v.sort();
            v
        }
        r.beh(
            &format!("{name} records equal the oracle's after masking the time (order normalised)"),
            masked(a) == masked(b),
            format!("rmasscan {}, oracle {}", a.records.len(), b.records.len()),
        );
        r.beh(
            &format!("{name} header and footer equal the oracle's after masking the clock"),
            a.header == b.header && a.footer == b.footer,
            format!(
                "rmasscan {:?} {:?}, oracle {:?} {:?}",
                a.header, a.footer, b.header, b.footer
            ),
        );
    }
    if c.stdout() == StdoutForm::Discovered
        && let (Some(a), Some(b)) = (&rm.stdout, &or.stdout)
    {
        let set = |t: &str| -> BTreeSet<String> {
            av::stdout_lines(t).into_iter().map(str::to_owned).collect()
        };
        r.beh(
            "stdout.txt Discovered lines equal the oracle's",
            set(a) == set(b),
            format!("rmasscan {}, oracle {}", set(a).len(), set(b).len()),
        );
    }
}

/// `o17_readscan`: both scanners read `o06_binary`'s two outputs and write the same list, nothing on the wire.
fn readscan(r: &mut Run, root: &Path, c: &OutputCase, rm: &Side, or: Option<&Side>) {
    let d = root.join("runs").join(c.tag);
    let o6 = root.join("runs").join(BINARY_TAG);
    let mut inputs = Vec::new();
    for (name, source) in READSCAN_INPUTS
        .iter()
        .zip(["output.bin", "oracle/output.bin"])
    {
        let (mine, theirs) = (fs::read(d.join(name)).ok(), fs::read(o6.join(source)).ok());
        r.inv(
            &format!("{name} is {BINARY_TAG}'s {source}, byte for byte"),
            mine.is_some() && mine == theirs,
            format!(
                "{} {}",
                mine.as_ref().map_or("missing".into(), |b| sha(b)),
                theirs.as_ref().map_or("missing".into(), |b| sha(b))
            ),
        );
        inputs.push(mine.unwrap_or_default());
    }
    let want = readscan_list(&inputs.iter().map(Vec::as_slice).collect::<Vec<_>>());
    r.inv(
        "the inputs are masscan -oB files",
        want.is_ok(),
        want.as_ref().err().cloned().unwrap_or_default(),
    );
    let want = want.unwrap_or_default();
    let st = av::stand(Plan::Linux);
    for s in std::iter::once(rm).chain(or) {
        let dir = s.who.dir();
        s.who.cap(
            r,
            &format!("{dir}output.txt is the list of the inputs' records in file order, each with its own time"),
            s.raw.as_ref() == Some(&want),
            format!("{} bytes, {} expected", s.raw.as_ref().map_or(0, Vec::len), want.len()),
        );
        if let Some(text) = &s.stderr {
            let lines = av::screen(text).map(|p| p.into_iter().collect::<Vec<_>>());
            let want_lines: Vec<Piece> = READSCAN_INPUTS
                .iter()
                .map(|n| Piece::Line(format!("[+] --readscan {n}")))
                .collect();
            if s.who == Who::Rmasscan {
                r.beh(
                    "stderr.txt is one `[+] --readscan FILE` line per input, no status line",
                    lines.as_ref().is_ok_and(|l| *l == want_lines),
                    format!("{lines:?}"),
                );
            }
        }
        if let Some(fr) = &s.frames {
            let n = scanner_frames(fr, &st);
            s.who.cap(
                r,
                &format!("no scanner frame during {dir}--readscan (markers aside)"),
                n == 0,
                n,
            );
        }
    }
    if let (Some(a), Some(b)) = (&rm.raw, or.and_then(|o| o.raw.as_ref())) {
        r.cap(
            "output.txt is byte for byte the oracle's",
            a == b,
            format!("{} and {} bytes", a.len(), b.len()),
        );
    }
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
        .and_then(|v| serde_json::from_value::<OutputManifest>(v).ok())
        .filter(|x| x.output == "linux");
    m.check(
        "manifest.json names the output plan (linux)",
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
    // An aborted attempt may hold an `-oB` document: the same extensions and privacy rules as a run.
    let odd: Vec<&String> = outside.iter().filter(|f| !evidence_extension(f)).collect();
    m.inv(
        "evidence files outside the runs carry only the allowed extensions (json pcap txt log err sha256 md, bin for -oB)",
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
        runs.extend(cases().iter().map(|c| {
            let mut r = verify_run(root, c, &t.links);
            let earlier: Vec<String> = attempts
                .iter()
                .filter(|a| a.case == Some(c.tag))
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
    result["safety_scan"] = json!(av::stray_scan(root, Some(Plan::Linux), &tags, &t));
    verify::finish(result)
}

/// `output-verify --dir DIR [--out FILE]`: 0 PASS, 1 FAIL, 2 INVALID or NOT RUN.
pub fn run(args: &[String]) -> Result<i32, String> {
    let o = crate::windows_suite::options_for("output-verify", args, &["dir", "out"])?;
    if o.contains_key("help") {
        println!(
            "output-verify --dir DIR [--out FILE]  (exit 0 PASS, 1 FAIL, 2 INVALID or NOT RUN)"
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
#[path = "output_verify_tests.rs"]
pub(crate) mod tests;
