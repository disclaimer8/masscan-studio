//! `fuzz udp`: the mutation fuzzer of the UDP banner parsers (`rmasscan_proto::handle_udp`), design R15: pure Rust
//! (libFuzzer pulls in C++), deterministic by seed, a short run in `cargo test`, and live runs of at least an hour per
//! parser family per sub-stage.
//!
//! ```text
//! rmasscan-lab fuzz udp --seed N (--duration D | --count N) [--port P] [--corpus DIR]... [--pcap FILE]...
//!                       [--out FILE]
//! ```
//!
//! - The corpus: the stand's scenario replies (`banners_verify::scenario_reply` to each built-in probe, the replies the
//!   banners window puts on the wire) always; `--corpus DIR`: a UDP golden directory (`tests/golden/udp-banners`: its
//!   `manifest.json` names each case's port and cookie, `cases/<case>.bin` the datagram), the C goldens of tasks 4 and
//!   5; `--pcap FILE`: every IPv4 UDP datagram from one of the fuzzed ports in a classic pcap (the window's captures).
//!   A seed keeps the cookie that makes its reply pass the parser's check ([`banners_verify::probe_cookie`]).
//! - An input: a seed of the port's family, one to four mutations (bit flips, random and boundary bytes and 16-bit
//!   words, truncation, insertion, deletion, duplication of a range, a splice with another seed of the family, a
//!   random tail), sometimes a random datagram instead; ZeroAccess seeds are opened, mutated as plaintext and sealed
//!   again with a right CRC half the time (a mutated ciphertext fails the CRC at once). Inputs are cut at
//!   [`MAX_INPUT`], the largest UDP payload the receive path accepts (frames over 1514 bytes are dropped before any
//!   parser, `src/main.c:799`, R2). The cookie is the seed's three times in four, else random; `--rawudp` at random.
//! - Per input: `handle_udp` under `catch_unwind` (a panic is a crash), its time (over [`SLOW`] is timed twice more
//!   and counted when the fastest of the three is still over: a scheduler stall is not a slow input), and the output
//!   invariants of the parsers' never-panic test: at most three banners, each a UDP application and at most R5's
//!   65 536 bytes, the raw banner last and equal to the datagram with `--rawudp`.
//! - Memory: the process's resident set (`/proc/self/status` on Linux, `ps -o rss=` elsewhere) after the first
//!   [`WARMUP_INPUTS`] inputs and every [`RSS_EVERY`]; the growth from the first sample to the last must stay under
//!   [`RSS_GROWTH_LIMIT_KIB`].
//!
//! The report (JSON, `--out`) counts inputs, inputs that reached a parser's text, crashes, slow inputs and invariant
//! failures per port, keeps the first findings (input hex, cookie, `--rawudp`, message), the resident set samples and
//! the SHA-256 of the input stream (two runs with the same seed and count draw the same inputs). Exit 0 without a
//! finding, 1 with one, 2 on a refused argument.
use crate::banners_verify::{
    probe_cookie, role_of, scenario_reply, zeroaccess_open, zeroaccess_seal,
};
use rmasscan_core::payloads::PayloadTable;
use rmasscan_proto::{MAX_BANNER_BYTES, UdpContext, handle_udp};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    net::Ipv4Addr,
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};

/// The parser families fuzzed: C's eight UDP parser ports (ZeroAccess by 16464; its other three ports share the
/// parser and keep their own port when a seed comes from them).
pub const FUZZ_PORTS: [u16; 8] = [53, 123, 137, 161, 500, 5683, 11211, 16464];
/// The largest UDP payload of a frame the receive path accepts: 1514 - 14 - 20 - 8.
pub const MAX_INPUT: usize = 1472;
/// An input slower than this (the fastest of three timings) is a finding.
pub const SLOW: Duration = Duration::from_millis(100);
/// The resident set is first sampled after this many inputs (allocator and corpus settled).
pub const WARMUP_INPUTS: u64 = 1000;
/// And then this often.
pub const RSS_EVERY: Duration = Duration::from_secs(10);
/// The most the resident set may grow from its first sample to its last.
pub const RSS_GROWTH_LIMIT_KIB: u64 = 64 * 1024;
/// How many findings of each kind the report keeps whole.
const KEEP: usize = 16;

/// The parser family of a port: ZeroAccess's four ports are one.
pub fn family(port: u16) -> Option<u16> {
    match port {
        16464 | 16465 | 16470 | 16471 => Some(16464),
        p if FUZZ_PORTS.contains(&p) => Some(p),
        _ => None,
    }
}

/// Where a seed came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {
    Scenario,
    Golden,
    Capture,
}
impl Origin {
    fn name(self) -> &'static str {
        match self {
            Origin::Scenario => "scenario",
            Origin::Golden => "golden",
            Origin::Capture => "capture",
        }
    }
}
/// One datagram of the corpus, with the port it came from and the cookie that passes its parser's check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed {
    pub port: u16,
    pub cookie: u32,
    pub payload: Vec<u8>,
    pub origin: Origin,
}

/// The stand's scenario replies to each built-in probe of the fuzzed ports (the probe's cookie a fixed value).
pub fn scenario_seeds() -> Vec<Seed> {
    let table = PayloadTable::builtin();
    let mut out = Vec::new();
    for port in FUZZ_PORTS {
        let probe = table
            .get(port)
            .map(|e| e.with_cookie(0x5eed_1234))
            .unwrap_or_default();
        for o in 2..=5 {
            let ip = Ipv4Addr::new(198, 18, 0, o);
            if role_of(ip).is_none() {
                continue;
            }
            if let Some(payload) = scenario_reply(port, ip, &probe) {
                out.push(Seed {
                    port,
                    cookie: probe_cookie(port, &probe),
                    payload,
                    origin: Origin::Scenario,
                });
            }
        }
    }
    out
}

/// The cases of a UDP golden directory (`manifest.json` and `cases/*.bin`) on the fuzzed ports.
pub fn golden_seeds(dir: &Path) -> Result<Vec<Seed>, String> {
    let man: Value = serde_json::from_slice(
        &fs::read(dir.join("manifest.json")).map_err(|e| format!("{}: {e}", dir.display()))?,
    )
    .map_err(|e| format!("manifest.json: {e}"))?;
    let cases = man["cases"]
        .as_array()
        .ok_or("manifest.json has no cases")?;
    let mut out = Vec::new();
    for c in cases {
        let (Some(port), Some(input)) = (c["port"].as_u64(), c["input"].as_str()) else {
            return Err(format!("a case without port or input: {c}"));
        };
        let Ok(port) = u16::try_from(port) else {
            continue;
        };
        if family(port).is_none() {
            continue;
        }
        let cookie = c["cookie"]
            .as_str()
            .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .ok_or_else(|| format!("{}: cookie", c["name"]))?;
        let payload = fs::read(dir.join(input)).map_err(|e| format!("{input}: {e}"))?;
        out.push(Seed {
            port,
            cookie,
            payload,
            origin: Origin::Golden,
        });
    }
    Ok(out)
}

/// Every IPv4 UDP datagram in a classic pcap whose source port is a fuzzed one (a reply of the stand).
pub fn capture_seeds(pcap: &[u8]) -> Result<Vec<Seed>, String> {
    let (_, frames) = crate::pcap::read_pcap_records(pcap)?;
    let mut out = Vec::new();
    for (_, f) in &frames {
        if f.len() < 42 || f[12..14] != [8, 0] || f[14] != 0x45 || f[23] != 17 {
            continue;
        }
        let total = usize::from(u16::from_be_bytes([f[16], f[17]]));
        let sport = u16::from_be_bytes([f[34], f[35]]);
        let (Some(payload), Some(_)) = (f.get(42..14 + total), family(sport)) else {
            continue;
        };
        out.push(Seed {
            port: sport,
            cookie: probe_cookie(sport, payload),
            payload: payload.to_vec(),
            origin: Origin::Capture,
        });
    }
    Ok(out)
}

/// xorshift64*: deterministic, no crate.
#[derive(Debug, Clone)]
pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        self.next_u64().to_le_bytes()[0]
    }
}
const BYTES: [u8; 12] = [
    0, 1, 2, 0x0c, 0x10, 0x20, 0x3f, 0x40, 0x7f, 0x80, 0xc0, 0xff,
];

/// One mutation of `px`; `other` is another seed of the family for a splice.
fn mutate(rng: &mut Rng, px: &mut Vec<u8>, other: &[u8]) {
    let n = px.len();
    match rng.below(10) {
        0 if n > 0 => {
            let i = rng.below(n);
            px[i] ^= 1 << rng.below(8);
        }
        1 if n > 0 => {
            let i = rng.below(n);
            px[i] = rng.byte();
        }
        2 if n > 0 => {
            let i = rng.below(n);
            px[i] = BYTES[rng.below(BYTES.len())];
        }
        3 => px.truncate(rng.below(n + 1)),
        4 => {
            let at = rng.below(n + 1);
            let k = 1 + rng.below(16);
            let ins: Vec<u8> = (0..k).map(|_| rng.byte()).collect();
            px.splice(at..at, ins);
        }
        5 if n > 0 => {
            let a = rng.below(n);
            let b = (a + 1 + rng.below(16)).min(n);
            px.drain(a..b);
        }
        6 if n > 0 => {
            let a = rng.below(n);
            let b = (a + 1 + rng.below(32)).min(n);
            let chunk = px[a..b].to_vec();
            let at = rng.below(n + 1);
            px.splice(at..at, chunk);
        }
        7 => {
            let a = rng.below(n + 1);
            let b = rng.below(other.len() + 1);
            px.truncate(a);
            px.extend_from_slice(&other[b..]);
        }
        8 if n >= 2 => {
            let i = rng.below(n - 1);
            let words = [
                0u16,
                1,
                0x7fff,
                0x8000,
                0xffff,
                n as u16,
                (n as u16).wrapping_sub(1),
                (n as u16).wrapping_add(1),
            ];
            px[i..i + 2].copy_from_slice(&words[rng.below(words.len())].to_be_bytes());
        }
        _ => {
            let k = rng.below(64);
            px.extend((0..k).map(|_| rng.byte()));
        }
    }
}

/// The input stream: from the corpus of each family, round robin over `ports`.
pub struct Inputs<'a> {
    rng: Rng,
    ports: Vec<u16>,
    by_family: BTreeMap<u16, Vec<&'a Seed>>,
    next_port: usize,
}
/// One input: the port and cookie its parser sees, `--rawudp`, the datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    pub port: u16,
    pub cookie: u32,
    pub rawudp: bool,
    pub payload: Vec<u8>,
}
impl<'a> Inputs<'a> {
    pub fn new(seed: u64, ports: &[u16], corpus: &'a [Seed]) -> Result<Inputs<'a>, String> {
        let mut by_family: BTreeMap<u16, Vec<&Seed>> = BTreeMap::new();
        for s in corpus {
            if let Some(f) = family(s.port) {
                by_family.entry(f).or_default().push(s);
            }
        }
        for p in ports {
            if !by_family.contains_key(p) {
                return Err(format!("no seed for port {p}"));
            }
        }
        Ok(Inputs {
            rng: Rng::new(seed),
            ports: ports.to_vec(),
            by_family,
            next_port: 0,
        })
    }
    pub fn draw(&mut self) -> Input {
        let fam = self.ports[self.next_port % self.ports.len()];
        self.next_port += 1;
        let seeds = &self.by_family[&fam];
        let rng = &mut self.rng;
        let s = seeds[rng.below(seeds.len())];
        let other = &seeds[rng.below(seeds.len())].payload;
        let mut px = if rng.below(16) == 0 {
            let n = rng.below(MAX_INPUT + 1);
            (0..n).map(|_| rng.byte()).collect()
        } else {
            s.payload.clone()
        };
        let sealed = fam == 16464 && rng.below(2) == 0;
        if sealed {
            px = zeroaccess_open(&px);
        }
        for _ in 0..1 + rng.below(4) {
            mutate(rng, &mut px, other);
        }
        if sealed {
            px.truncate(MAX_INPUT);
            px = zeroaccess_seal(&px);
        }
        px.truncate(MAX_INPUT);
        let cookie = if rng.below(4) < 3 {
            s.cookie
        } else {
            (rng.next_u64() >> 32) as u32
        };
        Input {
            port: s.port,
            cookie,
            rawudp: rng.below(2) == 1,
            payload: px,
        }
    }
}

/// What `handle_udp` gave that breaks the parsers' invariants, or `None`; and whether a parser's text came out.
fn invariants(i: &Input, got: &[(u16, Vec<u8>)]) -> (Option<String>, bool) {
    const APPS: [u16; 9] = [0, 6, 7, 8, 14, 19, 25, 28, 35];
    let text = got.iter().any(|(a, _)| *a != 0);
    if got.len() > 3 {
        return (Some(format!("{} banners", got.len())), text);
    }
    if i.rawudp && got.last() != Some(&(0, i.payload.clone())) {
        return (
            Some("--rawudp without the datagram as the last banner".into()),
            text,
        );
    }
    for (a, b) in got {
        if !APPS.contains(a) {
            return (Some(format!("application {a}")), text);
        }
        if b.len() > MAX_BANNER_BYTES {
            return (Some(format!("a banner of {} bytes", b.len())), text);
        }
        if *a != 35 && b.len() > 20 * i.payload.len() + 64 {
            return (
                Some(format!(
                    "a banner of {} bytes from {}",
                    b.len(),
                    i.payload.len()
                )),
                text,
            );
        }
    }
    (None, text)
}

/// The resident set of this process in KiB, where it can be read without `unsafe`.
pub fn rss_kib() -> Option<u64> {
    if let Ok(s) = fs::read_to_string("/proc/self/status") {
        return s
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok());
    }
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// The last panic message, recorded by the quiet hook `run` installs (empty under `cargo test`).
static LAST_PANIC: Mutex<Option<String>> = Mutex::new(None);

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PortStats {
    pub inputs: u64,
    pub parser_text: u64,
    pub crashes: u64,
    pub slow: u64,
    pub invariant_failures: u64,
    pub max_ns: u64,
    pub total_ns: u128,
    pub max_input: usize,
    pub max_output: usize,
}
/// A finding: the input and what happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: &'static str,
    pub input: Input,
    pub what: String,
}
#[derive(Debug, Clone)]
pub struct Outcome {
    pub inputs: u64,
    pub elapsed: Duration,
    pub per_port: BTreeMap<u16, PortStats>,
    pub findings: Vec<Finding>,
    pub crashes: u64,
    pub slow: u64,
    pub invariant_failures: u64,
    /// Seconds since the start and the resident set in KiB.
    pub rss: Vec<(f64, u64)>,
    pub sha256: String,
}
impl Outcome {
    pub fn rss_growth_kib(&self) -> Option<i64> {
        let (first, last) = (self.rss.first()?, self.rss.last()?);
        Some(last.1 as i64 - first.1 as i64)
    }
    pub fn clean(&self) -> bool {
        self.crashes == 0
            && self.slow == 0
            && self.invariant_failures == 0
            && self
                .rss_growth_kib()
                .is_none_or(|g| g < RSS_GROWTH_LIMIT_KIB as i64)
    }
}

/// The banners `handle_udp` gives, or the panic it raised.
type Banners = std::thread::Result<Vec<(u16, Vec<u8>)>>;
fn timed(i: &Input) -> (Banners, Duration) {
    let cx = UdpContext {
        port_them: i.port,
        cookie: i.cookie,
        rawudp: i.rawudp,
    };
    let t = Instant::now();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_udp(&cx, &i.payload)));
    (r, t.elapsed())
}

/// Fuzz until `done(inputs, elapsed)`: the input stream of `seed` over `ports` from `corpus`.
pub fn fuzz(
    seed: u64,
    ports: &[u16],
    corpus: &[Seed],
    mut done: impl FnMut(u64, Duration) -> bool,
) -> Result<Outcome, String> {
    let mut inputs = Inputs::new(seed, ports, corpus)?;
    let start = Instant::now();
    let mut o = Outcome {
        inputs: 0,
        elapsed: Duration::ZERO,
        per_port: ports.iter().map(|p| (*p, PortStats::default())).collect(),
        findings: Vec::new(),
        crashes: 0,
        slow: 0,
        invariant_failures: 0,
        rss: Vec::new(),
        sha256: String::new(),
    };
    let mut hash = Sha256::new();
    let mut next_rss: Option<Instant> = None;
    while !done(o.inputs, start.elapsed()) {
        let i = inputs.draw();
        hash.update(i.port.to_be_bytes());
        hash.update(i.cookie.to_be_bytes());
        hash.update([u8::from(i.rawudp)]);
        hash.update((i.payload.len() as u32).to_be_bytes());
        hash.update(&i.payload);
        o.inputs += 1;
        let fam = family(i.port).unwrap_or(i.port);
        let (res, mut dt) = timed(&i);
        let st = o.per_port.entry(fam).or_default();
        st.inputs += 1;
        st.max_input = st.max_input.max(i.payload.len());
        let mut finding = None;
        match res {
            Err(_) => {
                st.crashes += 1;
                o.crashes += 1;
                let msg = LAST_PANIC
                    .lock()
                    .ok()
                    .and_then(|mut m| m.take())
                    .unwrap_or_else(|| "panic".into());
                finding = Some(("crash", msg));
            }
            Ok(got) => {
                let (bad, text) = invariants(&i, &got);
                st.parser_text += u64::from(text);
                st.max_output = st
                    .max_output
                    .max(got.iter().map(|(_, b)| b.len()).sum::<usize>());
                if let Some(what) = bad {
                    st.invariant_failures += 1;
                    o.invariant_failures += 1;
                    finding = Some(("invariant", what));
                }
            }
        }
        if dt > SLOW {
            // A scheduler stall is not a slow input: the fastest of three timings decides.
            for _ in 0..2 {
                dt = dt.min(timed(&i).1);
            }
            if dt > SLOW {
                st.slow += 1;
                o.slow += 1;
                finding.get_or_insert(("slow", format!("{} ms", dt.as_millis())));
            }
        }
        let ns = u64::try_from(dt.as_nanos()).unwrap_or(u64::MAX);
        st.max_ns = st.max_ns.max(ns);
        st.total_ns += u128::from(ns);
        if let Some((kind, what)) = finding
            && o.findings.iter().filter(|f| f.kind == kind).count() < KEEP
        {
            o.findings.push(Finding {
                kind,
                input: i.clone(),
                what,
            });
        }
        let now = Instant::now();
        if o.inputs == WARMUP_INPUTS || next_rss.is_some_and(|t| now >= t) {
            if let Some(kib) = rss_kib() {
                o.rss.push((start.elapsed().as_secs_f64(), kib));
            }
            next_rss = Some(now + RSS_EVERY);
        }
    }
    if let Some(kib) = rss_kib().filter(|_| o.inputs >= WARMUP_INPUTS) {
        o.rss.push((start.elapsed().as_secs_f64(), kib));
    }
    o.elapsed = start.elapsed();
    o.sha256 = hex(&hash.finalize());
    Ok(o)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
/// The report of a run.
pub fn report(seed: u64, ports: &[u16], limit: &str, corpus: &[Seed], o: &Outcome) -> Value {
    let mut origins: BTreeMap<&str, usize> = BTreeMap::new();
    for s in corpus {
        *origins.entry(s.origin.name()).or_default() += 1;
    }
    let per_port: BTreeMap<String, Value> = o
        .per_port
        .iter()
        .map(|(p, s)| {
            (
                p.to_string(),
                json!({"inputs": s.inputs, "parser_text": s.parser_text, "crashes": s.crashes,
                    "slow_over_100ms": s.slow, "invariant_failures": s.invariant_failures,
                    "max_us": s.max_ns / 1000,
                    "mean_ns": if s.inputs == 0 { 0 } else { s.total_ns / u128::from(s.inputs) },
                    "max_input_bytes": s.max_input, "max_output_bytes": s.max_output}),
            )
        })
        .collect();
    json!({
        "schema": 1,
        "tool": "rmasscan-lab fuzz udp",
        "seed": seed,
        "ports": ports,
        "limit": limit,
        "elapsed_s": o.elapsed.as_secs_f64(),
        "inputs": o.inputs,
        "inputs_sha256": o.sha256,
        "corpus": origins,
        "max_input_bytes": MAX_INPUT,
        "slow_threshold_ms": SLOW.as_millis() as u64,
        "crashes": o.crashes,
        "slow_over_100ms": o.slow,
        "invariant_failures": o.invariant_failures,
        "per_port": per_port,
        "rss_kib": {
            "samples": o.rss.iter().map(|(t, k)| json!([(t * 10.0).round() / 10.0, k])).collect::<Vec<_>>(),
            "first": o.rss.first().map(|x| x.1),
            "last": o.rss.last().map(|x| x.1),
            "max": o.rss.iter().map(|x| x.1).max(),
            "growth": o.rss_growth_kib(),
            "growth_limit": RSS_GROWTH_LIMIT_KIB,
        },
        "findings": o.findings.iter().map(|f| json!({"kind": f.kind, "port": f.input.port,
            "cookie": format!("{:#010x}", f.input.cookie), "rawudp": f.input.rawudp,
            "input": hex(&f.input.payload), "what": f.what})).collect::<Vec<_>>(),
        "clean": o.clean(),
    })
}

/// `3600`, `3600s`, `60m`, `1h`.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let (n, mul) = match s.as_bytes().last()? {
        b's' => (&s[..s.len() - 1], 1),
        b'm' => (&s[..s.len() - 1], 60),
        b'h' => (&s[..s.len() - 1], 3600),
        _ => (s, 1),
    };
    n.parse::<u64>().ok().map(|v| Duration::from_secs(v * mul))
}

const USAGE: &str = "fuzz udp --seed N (--duration D | --count N) [--port P] [--corpus DIR]... [--pcap FILE]... [--out FILE]
  D: seconds, or with s/m/h; P: one of 53 123 137 161 500 5683 11211 16464 (default: all, round robin)
  exit 0 nothing found, 1 a crash, a slow input (over 100 ms), an invariant failure or memory growth, 2 a refused argument";

/// `fuzz udp ...`.
pub fn run(args: &[String]) -> Result<i32, String> {
    let Some((what, rest)) = args.split_first() else {
        return Err(format!("fuzz what?\n{USAGE}"));
    };
    if matches!(what.as_str(), "--help" | "-h" | "help") {
        println!("{USAGE}");
        return Ok(0);
    }
    if what != "udp" {
        return Err(format!("unknown fuzz target {what}; only udp\n{USAGE}"));
    }
    let o = crate::windows_suite::options_for(
        "fuzz udp",
        rest,
        &["seed", "duration", "count", "port", "corpus", "pcap", "out"],
    )?;
    if o.contains_key("help") {
        println!("{USAGE}");
        return Ok(0);
    }
    let one = |k: &str| o.get(k).and_then(|v| v.first()).cloned();
    let seed: u64 = one("seed")
        .ok_or("--seed is required")?
        .parse()
        .map_err(|e| format!("--seed: {e}"))?;
    let duration = one("duration")
        .map(|d| parse_duration(&d).ok_or(format!("--duration {d}: seconds, or with s, m or h")))
        .transpose()?;
    let count = one("count")
        .map(|c| c.parse::<u64>().map_err(|e| format!("--count: {e}")))
        .transpose()?;
    if duration.is_some() == count.is_some() {
        return Err("give exactly one of --duration and --count".into());
    }
    let ports: Vec<u16> = match one("port") {
        None => FUZZ_PORTS.to_vec(),
        Some(p) => {
            let p: u16 = p.parse().map_err(|e| format!("--port: {e}"))?;
            if !FUZZ_PORTS.contains(&p) {
                return Err(format!("--port {p}: one of {FUZZ_PORTS:?}"));
            }
            vec![p]
        }
    };
    let mut corpus = scenario_seeds();
    for d in o.get("corpus").into_iter().flatten() {
        corpus.extend(golden_seeds(Path::new(d))?);
    }
    for f in o.get("pcap").into_iter().flatten() {
        corpus.extend(capture_seeds(
            &fs::read(f).map_err(|e| format!("{f}: {e}"))?,
        )?);
    }
    // A panic of a parser is a finding: the hook records its message instead of printing it.
    std::panic::set_hook(Box::new(|info| {
        if let Ok(mut m) = LAST_PANIC.lock() {
            *m = Some(info.to_string());
        }
    }));
    let outcome = fuzz(seed, &ports, &corpus, |n, t| match (duration, count) {
        (Some(d), _) => t >= d,
        (_, Some(c)) => n >= c,
        _ => true,
    })?;
    let _ = std::panic::take_hook();
    let limit = duration.map_or_else(
        || format!("{} inputs", count.unwrap_or(0)),
        |d| format!("{} s", d.as_secs()),
    );
    let rep = report(seed, &ports, &limit, &corpus, &outcome);
    if let Some(out) = one("out") {
        fs::write(
            &out,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&rep).map_err(|e| e.to_string())?
            ),
        )
        .map_err(|e| format!("{out}: {e}"))?;
    }
    println!(
        "fuzz udp ports {ports:?} seed {seed}: {} inputs in {:.0} s, crashes {}, slow {}, invariant failures {}, rss growth {:?} KiB: {}",
        outcome.inputs,
        outcome.elapsed.as_secs_f64(),
        outcome.crashes,
        outcome.slow,
        outcome.invariant_failures,
        outcome.rss_growth_kib(),
        if outcome.clean() { "CLEAN" } else { "FINDINGS" }
    );
    Ok(if outcome.clean() { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/udp-banners")
    }
    fn corpus() -> Vec<Seed> {
        let mut c = scenario_seeds();
        c.extend(golden_seeds(&golden_dir()).unwrap());
        c
    }

    #[test]
    fn the_corpus_has_seeds_of_every_family_from_the_goldens_and_the_stand() {
        let c = corpus();
        for p in FUZZ_PORTS {
            for origin in [Origin::Scenario, Origin::Golden] {
                assert!(
                    c.iter()
                        .any(|s| family(s.port) == Some(p) && s.origin == origin),
                    "{p} {origin:?}"
                );
            }
        }
        // 4 scenario replies per fuzzed port; the goldens' default-branch ports (7, 19, 0, 65535, 9999) left out.
        assert_eq!(
            c.iter().filter(|s| s.origin == Origin::Scenario).count(),
            32
        );
        assert!(c.iter().all(|s| family(s.port).is_some()));
        // A seed's cookie passes its parser: the stand's DNS answer gives dns-ver with it.
        let dns = c
            .iter()
            .find(|s| s.port == 53 && s.origin == Origin::Scenario)
            .unwrap();
        let got = handle_udp(
            &UdpContext {
                port_them: 53,
                cookie: dns.cookie,
                rawudp: false,
            },
            &dns.payload,
        );
        assert_eq!(got[0].0, 6, "{got:?}");
    }

    #[test]
    fn the_input_stream_is_a_function_of_the_seed() {
        let c = corpus();
        let run = |seed| fuzz(seed, &FUZZ_PORTS, &c, |n, _| n >= 3000).unwrap();
        let (a, b, other) = (run(7), run(7), run(8));
        assert_eq!(a.sha256, b.sha256);
        assert_ne!(a.sha256, other.sha256);
        assert_eq!(a.inputs, 3000);
        let counts = |o: &Outcome| {
            o.per_port
                .iter()
                .map(|(p, s)| (*p, s.inputs, s.parser_text))
                .collect::<Vec<_>>()
        };
        assert_eq!(counts(&a), counts(&b));
        // Round robin: every family gets its share; inputs stay within the receive path's datagram size.
        for s in a.per_port.values() {
            assert_eq!(s.inputs, 375);
            assert!(s.max_input <= MAX_INPUT);
        }
    }

    #[test]
    fn mutations_reach_every_parsers_text_and_zeroaccess_is_resealed() {
        let c = corpus();
        let o = fuzz(11, &FUZZ_PORTS, &c, |n, _| n >= 16_000).unwrap();
        for (p, s) in &o.per_port {
            // A noticeable share of the inputs gets past the parser's checks into its text.
            assert!(s.parser_text * 10 > s.inputs, "{p}: {s:?}");
        }
    }

    #[test]
    fn a_crash_a_slow_input_and_a_broken_invariant_are_findings() {
        let i = Input {
            port: 53,
            cookie: 0,
            rawudp: true,
            payload: b"abc".to_vec(),
        };
        assert_eq!(invariants(&i, &[(0, b"abc".to_vec())]).0, None);
        assert!(
            invariants(&i, &[(6, b"x".to_vec())]).0.is_some(),
            "rawudp without the raw banner last"
        );
        assert!(
            invariants(&i, &[(99, vec![]), (0, b"abc".to_vec())])
                .0
                .is_some()
        );
        assert!(
            invariants(
                &i,
                &[(6, vec![0; MAX_BANNER_BYTES + 1]), (0, b"abc".to_vec())]
            )
            .0
            .is_some()
        );
        let four = vec![(6, vec![]), (6, vec![]), (6, vec![]), (0, b"abc".to_vec())];
        assert!(invariants(&i, &four).0.is_some());
        // An outcome with any finding, or with the resident set grown past the limit, is not clean.
        let mut o = fuzz(1, &[53], &corpus(), |n, _| n >= 10).unwrap();
        assert!(o.clean());
        o.rss = vec![(0.0, 10_000), (1.0, 10_000 + RSS_GROWTH_LIMIT_KIB)];
        assert!(!o.clean());
        o.rss.clear();
        o.slow = 1;
        assert!(!o.clean());
    }

    #[test]
    fn durations_and_arguments() {
        assert_eq!(parse_duration("3600"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("10s"), Some(Duration::from_secs(10)));
        assert_eq!(parse_duration("61m"), Some(Duration::from_secs(3660)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("x"), None);
        let a = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert!(run(&a(&["tcp"])).is_err());
        assert!(
            run(&a(&["udp", "--seed", "1"])).is_err(),
            "a limit is required"
        );
        assert!(
            run(&a(&[
                "udp", "--seed", "1", "--count", "5", "--port", "1900"
            ]))
            .is_err()
        );
        assert!(
            run(&a(&[
                "udp",
                "--seed",
                "1",
                "--count",
                "5",
                "--duration",
                "5"
            ]))
            .is_err()
        );
    }

    /// The short mode of R15: ten seconds over every family finds nothing.
    #[test]
    fn ten_seconds_of_fuzzing_every_family_find_nothing() {
        let c = corpus();
        let o = fuzz(20261113, &FUZZ_PORTS, &c, |_, t| {
            t >= Duration::from_secs(10)
        })
        .unwrap();
        assert!(o.inputs > 1000, "{} inputs", o.inputs);
        assert_eq!(
            (o.crashes, o.slow, o.invariant_failures),
            (0, 0, 0),
            "{:#?}",
            o.findings
        );
        for (p, s) in &o.per_port {
            assert!(s.inputs > 100 && s.parser_text > 0, "{p}: {s:?}");
        }
    }
}
