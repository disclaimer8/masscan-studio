//! `fuzz udp` and `fuzz tcp`: the mutation fuzzers of the banner parsers and the TCP stack, design R15: pure Rust
//! (libFuzzer pulls in C++), deterministic by seed, a short run in `cargo test`, and live runs of at least an hour per
//! parser family per sub-stage.
//!
//! ```text
//! rmasscan-lab fuzz udp --seed N (--duration D | --count N) [--port P] [--corpus DIR...] [--pcap FILE...]
//!                       [--out FILE]
//! rmasscan-lab fuzz tcp --family F --seed N (--duration D | --count N) [--corpus DIR...] [--pcap FILE...]
//!                       [--out FILE]
//! ```
//!
//! `fuzz udp` (sub-stage 4a, `rmasscan_proto::handle_udp`):
//!
//! - The corpus: the stand's scenario replies (`banners_verify::scenario_reply` to each built-in probe, the replies the
//!   banners window puts on the wire) always; `--corpus DIR...`: UDP golden directories (`tests/golden/udp-banners`:
//!   its `manifest.json` names each case's port and cookie, `cases/<case>.bin` the datagram), the C goldens of tasks 4
//!   and 5; `--pcap FILE...`: every IPv4 UDP datagram from one of the fuzzed ports in classic pcaps (the window's
//!   captures). Several directories or captures follow one flag; a repeated flag is refused.
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
//!
//! `fuzz tcp` (sub-stage 4b, one family per run, [`TCP_FAMILIES`]):
//!
//! - The corpus: the server streams of the window's TCP scenarios (`banners_verify::TCP_SCENARIOS`) always;
//!   `--corpus DIR...`: `tests/golden/tcp-banners` (`manifest.json` and each case's `tcp-banner-input v1` file: port,
//!   `--capture html`, the stream); `--pcap FILE...`: the server side of every TCP connection in classic pcaps (the
//!   source of a SYN-ACK; IPv4 and IPv6), its payload in sequence order from the SYN-ACK's number up to the first hole.
//!   A seed belongs to the family of the parser the classifier picks on its whole stream, else to its port's.
//! - A parser family (`http` ... `minecraft`) runs `rmasscan_proto::banner_stream` with `force_app` (the parser from
//!   the first byte, the classifier skipped), `framework` without it (the classifier, the HEUR record and its replay,
//!   banout). An input: a seed of the family, the mutations of `fuzz udp` (the splice partner of the family, one in
//!   eight of any) plus, sometimes, a range repeated up to [`MAX_STREAM`] (the classifier window and R5's record limit
//!   are 64 KiB), cut at [`MAX_STREAM`]; a random split into segments of 1 to [`MAX_SEGMENT`] bytes (one in eight byte
//!   by byte). Both the whole stream (one segment) and the split go through the parser; besides a panic and the time
//!   (of the whole-stream run, best of three; the split run is timed apart, `max_split_us`), the result of the split must equal the whole stream's (R13, rmasscan gives
//!   C's whole-stream result in every split, `split_problem`): the application and the records exactly, the
//!   parser's sends and closes in order exactly too, except Telnet's answers and Minecraft's closes, which follow the
//!   parse calls as in C by design (C reference, after table E2); and every record is a known application with 1 to
//!   65 536 bytes (`src/proto-banout.c` flushes only non-empty buffers, R5).
//! - `stack`: the product's `TcpStack` with the banner sessions (`rmasscan_proto::tcp_stack_factory`) on one to six
//!   connections, IPv4 and IPv6, with random table parameters. Half the inputs are chaos: SYN-ACKs, segments with any
//!   flags, numbers at and around the ones the stack last sent and random ones, payloads from the connection's
//!   (mutated) seed or random, ticks with delays and jumps (as the stack's own never-panic test, but from the outside:
//!   the numbers are read off the stack's segments). The other half deliver one connection's stream: the server
//!   speaks at once, in segments of the split, with duplicates, overlaps and segments from the future, each ACKing all
//!   the scanner sent; when every server byte got ACKed and the framework closes nowhere on the whole stream, the
//!   connection's records must equal the framework's on the whole stream (R13 through the stack; where C's stack
//!   itself depends on the split, after the parser's close, no comparison is made). A delivery that stops short is
//!   compared on the ACKed prefix, and three segments at the stack's ACK point that ACK all the scanner sent and
//!   still move nothing are an `invariant` finding (C ACKs in-order data always, `src/stack-tcp-core.c:1917-1949`),
//!   unless C itself drops data: the scanner sent a FIN, the connection is gone, the whole stream closes, or the
//!   scanner still holds data of its own it has not sent (C stays in `ESTABLISHED_SEND` until its queue is empty and
//!   drops data there, `:2053-2076`; a replay of the delivery with one more tick shows the queue's head; counted as
//!   `delivered.stalled_on_own_queue`). The
//!   stack's contract is checked on every call: segments only to the input's connections, only C's flags (RST, ACK,
//!   FIN-ACK, PSH-ACK, FIN-PSH-ACK), at most `tcb->mss` 1400 bytes (`src/stack-tcp-core.c:1031`), the template window;
//!   banner sets non-empty, records of a connection of the input, TCP, with the creating SYN-ACK's TTL; no more live
//!   connections than the capacity; a full table takes nothing and sends nothing; `finish` sends nothing, ends exactly
//!   `max` connections and reports the rest, and leaves none.
//!
//! Both: memory is the process's resident set (`/proc/self/status` on Linux, `ps -o rss=` elsewhere) after the first
//! [`WARMUP_INPUTS`] inputs, every [`RSS_EVERY`] and at the end; the growth from the first sample to the last must stay
//! under [`RSS_GROWTH_LIMIT_KIB`]. A run past the warm-up with fewer than two samples has not measured its memory and is
//! not clean ("memory not measured", exit 2; before, no sample counted as no growth: 4a review M3). The input streams
//! are drawn by xorshift64* seeded through splitmix64 ([`Rng::new`], 4a review M4).
//!
//! The report (JSON, `--out`) counts inputs and what they reached, crashes, slow inputs, invariant failures (and for
//! TCP split mismatches), keeps the first findings whole (the input in hex; for the stack its parameters and every
//! event fed), the resident set samples and the SHA-256 of the input stream (two runs with the same seed and count draw
//! the same inputs). Exit 0 without a finding, 1 with one, 2 on a refused argument or with memory not measured.
use crate::banners_verify::{
    TCP_SCENARIOS, probe_cookie, role_of, scenario_reply, tcp_head, zeroaccess_open,
    zeroaccess_seal,
};
use rmasscan_core::payloads::PayloadTable;
use rmasscan_core::stack::{
    ConnAddrs, ConnKey, SegmentIn, StackOutput, StackStats, TableParams, TcpStack, TcpStackFactory,
};
use rmasscan_proto::{
    MAX_BANNER_BYTES, StreamAction, StreamResult, TcpBannerSettings, UdpContext, app_id,
    banner_stream, handle_udp, tcp_stack_factory,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::{Arc, Mutex},
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
/// The state that stands in for 0, xorshift's fixed point, which splitmix64 gives only [`SPLITMIX_ZERO_SEED`].
const ZERO_STATE_REPLACEMENT: u64 = 0x9e37_79b9_7f4a_7c15;
/// The one seed whose splitmix64 is 0: `-0x9e3779b97f4a7c15` (every step after the addition maps 0 to 0).
pub const SPLITMIX_ZERO_SEED: u64 = 0x61c8_8646_80b5_83eb;
impl Rng {
    /// The state is splitmix64 of the seed, a bijection, so every seed has its own stream; the one seed it maps to 0
    /// (xorshift's fixed point: all zeros forever) gets [`ZERO_STATE_REPLACEMENT`] instead. 4a review M4: the earlier
    /// `seed * K | 1` gave two seeds whose products differ only in bit 0 one stream (0 and `K⁻¹ mod 2⁶⁴`).
    pub fn new(seed: u64) -> Rng {
        let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        Rng(if z == 0 { ZERO_STATE_REPLACEMENT } else { z })
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
    fn u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
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

/// The resident-set samples of a run: after the first [`WARMUP_INPUTS`] inputs, every [`RSS_EVERY`] after that and
/// once more at the end of a run that got past the warm-up. `probe` is [`rss_kib`], or a stand-in in tests.
struct Sampler<P: FnMut() -> Option<u64>> {
    probe: P,
    start: Instant,
    next: Option<Instant>,
    samples: Vec<(f64, u64)>,
}
impl<P: FnMut() -> Option<u64>> Sampler<P> {
    fn new(probe: P, start: Instant) -> Self {
        Sampler {
            probe,
            start,
            next: None,
            samples: Vec::new(),
        }
    }
    fn take(&mut self) {
        if let Some(kib) = (self.probe)() {
            self.samples.push((self.start.elapsed().as_secs_f64(), kib));
        }
    }
    /// After the `inputs`-th input.
    fn after_input(&mut self, inputs: u64) {
        let now = Instant::now();
        if inputs == WARMUP_INPUTS || self.next.is_some_and(|t| now >= t) {
            self.take();
            self.next = Some(now + RSS_EVERY);
        }
    }
    fn end(mut self, inputs: u64) -> Vec<(f64, u64)> {
        if inputs >= WARMUP_INPUTS {
            self.take();
        }
        self.samples
    }
}

/// Whether a run measured its memory: one of at most [`WARMUP_INPUTS`] inputs is not expected to, a longer one needs
/// two samples to have a growth at all (4a review M3).
pub fn memory_measured(inputs: u64, rss: &[(f64, u64)]) -> bool {
    inputs <= WARMUP_INPUTS || rss.len() >= 2
}
fn rss_growth(rss: &[(f64, u64)]) -> Option<i64> {
    let (first, last) = (rss.first()?, rss.last()?);
    Some(last.1 as i64 - first.1 as i64)
}
fn grew_too_much(rss: &[(f64, u64)]) -> bool {
    rss_growth(rss).is_some_and(|g| g >= RSS_GROWTH_LIMIT_KIB as i64)
}
/// The verdict of a run. A finding (memory growth over the limit included) is exit 1; otherwise a run whose memory was
/// not measured ([`memory_measured`]) is exit 2, and only the rest is clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Findings,
    MemoryNotMeasured,
}
impl Verdict {
    pub fn of(found: bool, inputs: u64, rss: &[(f64, u64)]) -> Verdict {
        if found || grew_too_much(rss) {
            Verdict::Findings
        } else if !memory_measured(inputs, rss) {
            Verdict::MemoryNotMeasured
        } else {
            Verdict::Clean
        }
    }
    pub fn exit_code(self) -> i32 {
        match self {
            Verdict::Clean => 0,
            Verdict::Findings => 1,
            Verdict::MemoryNotMeasured => 2,
        }
    }
    pub fn word(self) -> &'static str {
        match self {
            Verdict::Clean => "CLEAN",
            Verdict::Findings => "FINDINGS",
            Verdict::MemoryNotMeasured => "MEMORY NOT MEASURED",
        }
    }
}
/// `, memory not measured (...)` for a run that did not measure it (printed with a finding too), else nothing.
fn memory_note(inputs: u64, rss: &[(f64, u64)]) -> String {
    if memory_measured(inputs, rss) {
        String::new()
    } else {
        format!(
            ", memory not measured ({} resident-set samples after {inputs} inputs)",
            rss.len()
        )
    }
}
fn rss_json(rss: &[(f64, u64)], inputs: u64) -> Value {
    json!({
        "samples": rss.iter().map(|(t, k)| json!([(t * 10.0).round() / 10.0, k])).collect::<Vec<_>>(),
        "first": rss.first().map(|x| x.1),
        "last": rss.last().map(|x| x.1),
        "max": rss.iter().map(|x| x.1).max(),
        "growth": rss_growth(rss),
        "growth_limit": RSS_GROWTH_LIMIT_KIB,
        "measured": memory_measured(inputs, rss),
    })
}

/// The last panic message, recorded by the quiet hook `run` installs (empty under `cargo test`).
static LAST_PANIC: Mutex<Option<String>> = Mutex::new(None);
fn last_panic() -> String {
    LAST_PANIC
        .lock()
        .ok()
        .and_then(|mut m| m.take())
        .unwrap_or_else(|| "panic".into())
}

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
        rss_growth(&self.rss)
    }
    pub fn verdict(&self) -> Verdict {
        Verdict::of(
            self.crashes + self.slow + self.invariant_failures > 0,
            self.inputs,
            &self.rss,
        )
    }
    pub fn clean(&self) -> bool {
        self.verdict() == Verdict::Clean
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
    done: impl FnMut(u64, Duration) -> bool,
) -> Result<Outcome, String> {
    fuzz_with(seed, ports, corpus, rss_kib, done)
}

/// [`fuzz`] with the resident set read by `probe`.
pub fn fuzz_with(
    seed: u64,
    ports: &[u16],
    corpus: &[Seed],
    probe: impl FnMut() -> Option<u64>,
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
    let mut rss = Sampler::new(probe, start);
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
                finding = Some(("crash", last_panic()));
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
        rss.after_input(o.inputs);
    }
    o.rss = rss.end(o.inputs);
    o.elapsed = start.elapsed();
    o.sha256 = hex(&hash.finalize());
    Ok(o)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("not hex: {:.40}", s));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
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
        "rss_kib": rss_json(&o.rss, o.inputs),
        "memory_measured": memory_measured(o.inputs, &o.rss),
        "findings": o.findings.iter().map(|f| json!({"kind": f.kind, "port": f.input.port,
            "cookie": format!("{:#010x}", f.input.cookie), "rawudp": f.input.rawudp,
            "input": hex(&f.input.payload), "what": f.what})).collect::<Vec<_>>(),
        "verdict": o.verdict().word(),
        "clean": o.clean(),
    })
}
/// The line `fuzz udp` prints.
pub fn summary(ports: &[u16], seed: u64, o: &Outcome) -> String {
    format!(
        "fuzz udp ports {ports:?} seed {seed}: {} inputs in {:.0} s, crashes {}, slow {}, invariant failures {}, rss growth {:?} KiB{}: {}",
        o.inputs,
        o.elapsed.as_secs_f64(),
        o.crashes,
        o.slow,
        o.invariant_failures,
        o.rss_growth_kib(),
        memory_note(o.inputs, &o.rss),
        o.verdict().word()
    )
}

/// `3600`, `3600s`, `60m`, `1h`; `None` for anything else, a number of seconds past `u64` included (L-M6).
pub fn parse_duration(s: &str) -> Option<Duration> {
    let (n, mul) = match s.as_bytes().last()? {
        b's' => (&s[..s.len() - 1], 1u64),
        b'm' => (&s[..s.len() - 1], 60),
        b'h' => (&s[..s.len() - 1], 3600),
        _ => (s, 1),
    };
    n.parse::<u64>()
        .ok()
        .and_then(|v| v.checked_mul(mul))
        .map(Duration::from_secs)
}

const USAGE: &str = "fuzz udp --seed N (--duration D | --count N) [--port P] [--corpus DIR...] [--pcap FILE...] [--out FILE]
  D: seconds, or with s/m/h, and N: above 0; P: one of 53 123 137 161 500 5683 11211 16464 (default: all, round robin); several
  directories or captures follow one --corpus or --pcap
fuzz tcp --family F --seed N (--duration D | --count N) [--corpus DIR...] [--pcap FILE...] [--out FILE]
  F: http ftp smtp pop3 imap4 ssh vnc telnet rdp memcached minecraft (the parser, forced), framework (the classifier
  and the parser it picks), stack (the TCP stack with the banner sessions); DIR: a tcp-banners golden directory;
  FILE: a classic pcap of the banners window (the servers' TCP streams)
exit 0 nothing found, 1 a crash, a slow input (over 100 ms), an invariant failure, a split that changes the result or
  memory growth, 2 a refused argument or memory not measured (a run past 1000 inputs with under two resident-set
  samples)";

/// The options both fuzzers share: the seed, the limit (exactly one of `--duration` and `--count`) and its name.
struct Common {
    seed: u64,
    duration: Option<Duration>,
    count: Option<u64>,
    out: Option<String>,
}
impl Common {
    fn parse(o: &BTreeMap<String, Vec<String>>) -> Result<Common, String> {
        let one = |k: &str| o.get(k).and_then(|v| v.first()).cloned();
        let seed: u64 = one("seed")
            .ok_or("--seed is required")?
            .parse()
            .map_err(|e| format!("--seed: {e}"))?;
        let duration = one("duration")
            .map(|d| {
                parse_duration(&d).ok_or(format!("--duration {d}: seconds, or with s, m or h"))
            })
            .transpose()?;
        let count = one("count")
            .map(|c| c.parse::<u64>().map_err(|e| format!("--count: {e}")))
            .transpose()?;
        if duration.is_some() == count.is_some() {
            return Err("give exactly one of --duration and --count".into());
        }
        // A run of no input proves nothing: refused (exit 2), never CLEAN (L-M6).
        if duration.is_some_and(|d| d.is_zero()) || count == Some(0) {
            return Err("--duration 0 or --count 0: a run needs at least one input".into());
        }
        Ok(Common {
            seed,
            duration,
            count,
            out: one("out"),
        })
    }
    fn done(&self, n: u64, t: Duration) -> bool {
        match (self.duration, self.count) {
            (Some(d), _) => t >= d,
            (_, Some(c)) => n >= c,
            _ => true,
        }
    }
    fn limit(&self) -> String {
        self.duration.map_or_else(
            || format!("{} inputs", self.count.unwrap_or(0)),
            |d| format!("{} s", d.as_secs()),
        )
    }
    fn write(&self, rep: &Value) -> Result<(), String> {
        if let Some(out) = &self.out {
            fs::write(
                out,
                format!(
                    "{}\n",
                    serde_json::to_string_pretty(rep).map_err(|e| e.to_string())?
                ),
            )
            .map_err(|e| format!("{out}: {e}"))?;
        }
        Ok(())
    }
}

/// A panic of a parser or the stack is a finding: the hook records its message instead of printing it.
fn quiet_panics() {
    std::panic::set_hook(Box::new(|info| {
        if let Ok(mut m) = LAST_PANIC.lock() {
            *m = Some(info.to_string());
        }
    }));
}

/// `fuzz udp|tcp ...`.
pub fn run(args: &[String]) -> Result<i32, String> {
    let Some((what, rest)) = args.split_first() else {
        return Err(format!("fuzz what?\n{USAGE}"));
    };
    match what.as_str() {
        "--help" | "-h" | "help" => {
            println!("{USAGE}");
            Ok(0)
        }
        "udp" => run_udp(rest),
        "tcp" => run_tcp(rest),
        _ => Err(format!("unknown fuzz target {what}; udp or tcp\n{USAGE}")),
    }
}

fn run_udp(rest: &[String]) -> Result<i32, String> {
    let o = crate::windows_suite::options_for(
        "fuzz udp",
        rest,
        &["seed", "duration", "count", "port", "corpus", "pcap", "out"],
    )?;
    if o.contains_key("help") {
        println!("{USAGE}");
        return Ok(0);
    }
    let common = Common::parse(&o)?;
    let ports: Vec<u16> = match o.get("port").and_then(|v| v.first()) {
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
    quiet_panics();
    let outcome = fuzz(common.seed, &ports, &corpus, |n, t| common.done(n, t))?;
    let _ = std::panic::take_hook();
    common.write(&report(
        common.seed,
        &ports,
        &common.limit(),
        &corpus,
        &outcome,
    ))?;
    println!("{}", summary(&ports, common.seed, &outcome));
    Ok(outcome.verdict().exit_code())
}

// ------------------------------------------------------------------ fuzz tcp (sub-stage 4b)

/// The families of `fuzz tcp`: the eleven parsers of 4b with `force_app`, the framework, the stack.
pub const TCP_FAMILIES: [&str; 13] = [
    "http",
    "ftp",
    "smtp",
    "pop3",
    "imap4",
    "ssh",
    "vnc",
    "telnet",
    "rdp",
    "memcached",
    "minecraft",
    "framework",
    "stack",
];
/// The longest server stream of an input: R5's record limit and the classifier's window, 64 KiB.
pub const MAX_STREAM: usize = 65_536;
/// The longest segment of a split: the TCP payload of a 1514-byte IPv4 frame (longer frames are dropped before the
/// stack, `src/main.c:799`).
pub const MAX_SEGMENT: usize = 1460;
/// The scanner's segments carry at most `tcb->mss` bytes (`src/stack-tcp-core.c:1031`).
const MSS: usize = 1400;
/// A delivery input's stream holds at most this many segments of its split (the time of one input stays small).
const DELIVERY_SEGMENTS: usize = 2048;
/// A delivery input's banner budget: no record is cut by it (the CLI's default is 512 MiB).
const DELIVERY_BUDGET: usize = 1 << 30;
/// Ports a framework or stack input may move to: the classifier's port rules (`src/proto-banner1.c:147-153`) and the
/// hello table's ports (`:518-610`).
const PORTS: [u16; 18] = [
    21, 22, 23, 25, 80, 110, 143, 443, 445, 465, 587, 2525, 3389, 5900, 8080, 9999, 11211, 25565,
];
const SEC: u64 = 1_000_000;
const MS: u64 = 1_000;
/// The engine clock of a stack input: microseconds, as `rmasscan-engine` gives them.
const T0: u64 = 1_700_000_000_000_000;
/// TCP flags (`TCP_IS_*`, `src/stack-tcp-core.h:15-21`).
const FIN: u8 = 0x01;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;
const SYN_ACK: u8 = 0x12;
const FIN_ACK: u8 = 0x11;
const PSH_ACK: u8 = 0x18;
const FIN_PSH_ACK: u8 = 0x19;

/// The application a parser family forces and the port it serves: the C numbers of the branches of
/// `banner1_parse` (`src/proto-banner1.c:187-316`).
pub fn family_app(family: &str) -> Option<(u16, u16)> {
    Some(match family {
        "http" => (app_id::HTTP, 80),
        "ftp" => (app_id::FTP, 21),
        "smtp" => (app_id::SMTP, 25),
        "pop3" => (app_id::POP3, 110),
        "imap4" => (app_id::IMAP4, 143),
        "ssh" => (app_id::SSH2, 22),
        "vnc" => (app_id::VNC_RFB, 5900),
        "telnet" => (app_id::TELNET, 23),
        "rdp" => (app_id::RDP, 3389),
        "memcached" => (app_id::MEMCACHED, 11211),
        "minecraft" => (app_id::MC, 25565),
        _ => return None,
    })
}
/// The parser family of the application the classifier picked.
fn family_of_app(app: u16) -> Option<&'static str> {
    if app == app_id::SSH1 {
        return Some("ssh");
    }
    TCP_FAMILIES
        .iter()
        .copied()
        .find(|f| family_app(f).is_some_and(|(a, _)| a == app))
}
/// The parser family of a port without a classified stream: the parsers' ports and the mail ports.
fn family_of_port(port: u16) -> Option<&'static str> {
    Some(match port {
        80 | 8080 | 8530 => "http",
        21 => "ftp",
        25 | 465 | 587 | 2525 => "smtp",
        110 => "pop3",
        143 => "imap4",
        22 | 2222 => "ssh",
        5900 => "vnc",
        23 => "telnet",
        3389 => "rdp",
        11211 => "memcached",
        25565 => "minecraft",
        _ => return None,
    })
}

fn settings(capture_html: bool) -> TcpBannerSettings {
    TcpBannerSettings {
        capture_html,
        ..TcpBannerSettings::default()
    }
}
/// The stream as one segment (no segment at all when empty: the stack never hands the parser an empty one).
fn whole_of(stream: &[u8]) -> Vec<&[u8]> {
    if stream.is_empty() {
        Vec::new()
    } else {
        vec![stream]
    }
}

/// One server stream of the corpus: its port, `--capture html`, the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSeed {
    pub port: u16,
    pub capture_html: bool,
    pub stream: Vec<u8>,
    pub origin: Origin,
}
impl TcpSeed {
    /// The family of the parser the classifier picks on the whole stream, else the port's.
    pub fn family(&self) -> Option<&'static str> {
        let r = std::panic::catch_unwind(|| {
            banner_stream(
                &settings(self.capture_html),
                self.port,
                None,
                &whole_of(&self.stream),
            )
            .app_proto
        });
        r.ok()
            .flatten()
            .and_then(family_of_app)
            .or_else(|| family_of_port(self.port))
    }
}

/// The server streams of the window's TCP scenarios (`banners_verify::TCP_SCENARIOS`).
pub fn tcp_scenario_seeds() -> Vec<TcpSeed> {
    TCP_SCENARIOS
        .iter()
        .map(|s| (s.port, s.stream()))
        .filter(|(_, stream)| !stream.is_empty())
        .map(|(port, stream)| TcpSeed {
            port,
            capture_html: false,
            stream,
            origin: Origin::Scenario,
        })
        .collect()
}

/// A `tcp-banner-input v1` file (`tests/golden/tcp-banners/README.md`): the port, `--capture html` and the stream (the
/// segments concatenated, `repeat=N:HEX` the unit repeated and cut to N bytes), cut at [`MAX_STREAM`].
pub fn parse_tcp_input(text: &str) -> Result<(u16, bool, Vec<u8>), String> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'));
    if lines.next() != Some("tcp-banner-input v1") {
        return Err("not a tcp-banner-input v1 file".into());
    }
    let (mut port, mut capture_html, mut stream) = (None, false, Vec::new());
    for l in lines {
        let (k, v) = l.split_once(' ').ok_or_else(|| format!("line {l:?}"))?;
        match k {
            "port" => port = Some(v.parse::<u16>().map_err(|e| format!("port {v}: {e}"))?),
            "capture" => {
                capture_html = match v {
                    "html" => true,
                    "none" => false,
                    _ => return Err(format!("capture {v}")),
                }
            }
            "segment" => match v.strip_prefix("repeat=") {
                Some(r) => {
                    let (n, unit) = r.split_once(':').ok_or_else(|| format!("segment {v}"))?;
                    let n: usize = n.parse().map_err(|e| format!("repeat {n}: {e}"))?;
                    let unit = unhex(unit)?;
                    if unit.is_empty() && n > 0 {
                        return Err(format!("segment {v}: an empty unit"));
                    }
                    let room = MAX_STREAM.saturating_sub(stream.len());
                    stream.extend(unit.iter().copied().cycle().take(n.min(room)));
                }
                None => stream.extend(unhex(v)?),
            },
            _ => return Err(format!("unknown directive {k}")),
        }
    }
    stream.truncate(MAX_STREAM);
    Ok((port.ok_or("no port")?, capture_html, stream))
}

/// The response cases of a `tcp-banners` golden directory: `manifest.json` names each case's input file.
pub fn tcp_golden_seeds(dir: &Path) -> Result<Vec<TcpSeed>, String> {
    let man: Value = serde_json::from_slice(
        &fs::read(dir.join("manifest.json")).map_err(|e| format!("{}: {e}", dir.display()))?,
    )
    .map_err(|e| format!("manifest.json: {e}"))?;
    let cases = man["cases"]
        .as_array()
        .ok_or("manifest.json has no cases")?;
    let mut out = Vec::new();
    for c in cases {
        let input = c["input"]
            .as_str()
            .ok_or_else(|| format!("a case without input: {}", c["name"]))?;
        let text = fs::read_to_string(dir.join(input)).map_err(|e| format!("{input}: {e}"))?;
        let (port, capture_html, stream) =
            parse_tcp_input(&text).map_err(|e| format!("{input}: {e}"))?;
        out.push(TcpSeed {
            port,
            capture_html,
            stream,
            origin: Origin::Golden,
        });
    }
    Ok(out)
}

/// A record: the application and its bytes.
type Record = (u16, Vec<u8>);
/// A segment's payload with its sequence number.
type Numbered = (u32, Vec<u8>);

/// The server side of every TCP connection in a classic pcap (IPv4 and IPv6): the source of a SYN-ACK, its payload
/// placed by sequence number from the SYN-ACK's number + 1 (retransmissions and overlaps fall on the same bytes),
/// up to the first hole and at most [`MAX_STREAM`] bytes. A SYN-ACK with another number starts a new connection.
pub fn tcp_capture_seeds(pcap: &[u8]) -> Result<Vec<TcpSeed>, String> {
    type Flow = (IpAddr, u16, IpAddr, u16);
    let (_, frames) = crate::pcap::read_pcap_records(pcap)?;
    // Per connection: the server's port, its first sequence number, its data segments.
    let mut conns: Vec<(u16, u32, Vec<Numbered>)> = Vec::new();
    let mut current: BTreeMap<Flow, usize> = BTreeMap::new();
    for (_, f) in &frames {
        let Some(h) = tcp_head(f) else {
            continue;
        };
        let flow = (h.src, h.sp, h.dst, h.dp);
        if h.flags & SYN_ACK == SYN_ACK {
            let start = h.seq.wrapping_add(1);
            if current.get(&flow).is_none_or(|&i| conns[i].1 != start) {
                current.insert(flow, conns.len());
                conns.push((h.sp, start, Vec::new()));
            }
        } else if !h.payload.is_empty()
            && let Some(&i) = current.get(&flow)
        {
            conns[i].2.push((h.seq, h.payload));
        }
    }
    let mut out = Vec::new();
    for (port, start, segs) in conns {
        let end = segs
            .iter()
            .map(|(seq, p)| (seq.wrapping_sub(start) as usize, p.len()))
            .filter(|(off, _)| *off < MAX_STREAM)
            .map(|(off, n)| (off + n).min(MAX_STREAM))
            .max()
            .unwrap_or(0);
        let (mut buf, mut have) = (vec![0u8; end], vec![false; end]);
        for (seq, p) in &segs {
            let off = seq.wrapping_sub(start) as usize;
            for (j, b) in p.iter().enumerate() {
                let Some(at) = off.checked_add(j).filter(|at| *at < end) else {
                    break;
                };
                buf[at] = *b;
                have[at] = true;
            }
        }
        let n = have.iter().position(|h| !h).unwrap_or(end);
        if n > 0 {
            buf.truncate(n);
            out.push(TcpSeed {
                port,
                capture_html: false,
                stream: buf,
                origin: Origin::Capture,
            });
        }
    }
    Ok(out)
}

/// A parser or framework input: the stream, the port, the parser forced (`None` for the framework), `--capture
/// html`, and the split (segment lengths, each 1 to [`MAX_SEGMENT`], their sum the stream's length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamInput {
    pub port: u16,
    pub force_app: Option<u16>,
    pub capture_html: bool,
    pub stream: Vec<u8>,
    pub split: Vec<usize>,
}
impl StreamInput {
    pub fn segments(&self) -> Vec<&[u8]> {
        let mut at = 0;
        self.split
            .iter()
            .map(|n| {
                let s = &self.stream[at..at + n];
                at += n;
                s
            })
            .collect()
    }
}
/// A stack input: the table's parameters, the connections (their keys and the servers' streams), and how the events
/// are drawn: `script` seeds them, read off the stack's own segments as they come, so the same plan gives the same
/// events again (the stack is deterministic). `delivery`: connection 0 delivers its stream in segments of at most
/// `max_segment` bytes; else `events` chaos events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackPlan {
    pub delivery: bool,
    /// `--connection-timeout` (0: 30 s).
    pub lifetime: u32,
    pub capacity: usize,
    pub budget: usize,
    pub table_seed: u64,
    pub script: u64,
    pub events: usize,
    pub max_segment: usize,
    pub capture_html: bool,
    pub keys: Vec<ConnKey>,
    pub streams: Vec<Vec<u8>>,
}
/// One input of `fuzz tcp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpInput {
    Stream(StreamInput),
    Stack(StackPlan),
}
fn key_bytes(k: &ConnKey) -> Vec<u8> {
    let mut b = Vec::new();
    match k.addrs {
        ConnAddrs::V4 { local, remote } => {
            b.push(4);
            b.extend(local.to_be_bytes());
            b.extend(remote.to_be_bytes());
        }
        ConnAddrs::V6 { local, remote } => {
            b.push(6);
            b.extend(local.to_be_bytes());
            b.extend(remote.to_be_bytes());
        }
    }
    b.extend(k.local_port.to_be_bytes());
    b.extend(k.remote_port.to_be_bytes());
    b
}
impl TcpInput {
    fn hash_into(&self, h: &mut Sha256) {
        let n = |h: &mut Sha256, v: usize| h.update((v as u64).to_be_bytes());
        match self {
            TcpInput::Stream(s) => {
                h.update([0]);
                h.update(s.port.to_be_bytes());
                h.update(s.force_app.unwrap_or(0).to_be_bytes());
                h.update([u8::from(s.capture_html)]);
                n(h, s.stream.len());
                h.update(&s.stream);
                n(h, s.split.len());
                for x in &s.split {
                    n(h, *x);
                }
            }
            TcpInput::Stack(p) => {
                h.update([1, u8::from(p.delivery), u8::from(p.capture_html)]);
                h.update(p.lifetime.to_be_bytes());
                n(h, p.capacity);
                n(h, p.budget);
                h.update(p.table_seed.to_be_bytes());
                h.update(p.script.to_be_bytes());
                n(h, p.events);
                n(h, p.max_segment);
                n(h, p.keys.len());
                for (k, s) in p.keys.iter().zip(&p.streams) {
                    h.update(key_bytes(k));
                    n(h, s.len());
                    h.update(s);
                }
            }
        }
    }
}

/// A connection of a stack input: the scanner at 198.18.0.1 or 2001:db8::1, port 40000; the server at its own address
/// per connection.
fn stack_key(i: usize, port: u16, v6: bool) -> ConnKey {
    let i = u32::try_from(i).unwrap_or(0);
    ConnKey {
        addrs: if v6 {
            ConnAddrs::V6 {
                local: (0x2001_0db8u128 << 96) | 1,
                remote: (0x2001_0db8u128 << 96) | 0x100 | u128::from(i),
            }
        } else {
            ConnAddrs::V4 {
                local: 0xc612_0001,
                remote: 0xc612_0002 + i,
            }
        },
        local_port: 40000,
        remote_port: port,
    }
}
fn remote_ip(k: &ConnKey) -> IpAddr {
    match k.addrs {
        ConnAddrs::V4 { remote, .. } => IpAddr::V4(Ipv4Addr::from(remote)),
        ConnAddrs::V6 { remote, .. } => IpAddr::V6(Ipv6Addr::from(remote)),
    }
}

/// A long stream: a range of the input or of another seed (1 to 256 bytes) repeated at a random place up to a random
/// length within [`MAX_STREAM`]; only so do inputs reach the classifier window and R5's record limit.
fn grow(rng: &mut Rng, px: &mut Vec<u8>, other: &[u8]) {
    let use_other = px.is_empty() || (rng.below(2) == 0 && !other.is_empty());
    let src: &[u8] = if use_other { other } else { &px[..] };
    if src.is_empty() {
        return;
    }
    let a = rng.below(src.len());
    let b = (a + 1 + rng.below(256)).min(src.len());
    let unit = src[a..b].to_vec();
    let n = rng.below(MAX_STREAM.saturating_sub(px.len()) + 1);
    let at = rng.below(px.len() + 1);
    let ins: Vec<u8> = unit.iter().copied().cycle().take(n).collect();
    px.splice(at..at, ins);
}
/// The largest segment of a split: byte by byte one time in eight, else up to 16, 256 or [`MAX_SEGMENT`] bytes.
fn split_bound(rng: &mut Rng) -> usize {
    match rng.below(8) {
        0 => 1,
        1 | 2 => 1 + rng.below(16),
        3 | 4 => 1 + rng.below(256),
        _ => MAX_SEGMENT,
    }
}
fn split(rng: &mut Rng, len: usize, bound: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut left = len;
    while left > 0 {
        let n = (1 + rng.below(bound)).min(left);
        out.push(n);
        left -= n;
    }
    out
}

/// The input stream of one family.
pub struct TcpInputs<'a> {
    rng: Rng,
    family: &'static str,
    seeds: Vec<&'a TcpSeed>,
    all: Vec<&'a TcpSeed>,
}
impl<'a> TcpInputs<'a> {
    pub fn new(seed: u64, family: &str, corpus: &'a [TcpSeed]) -> Result<TcpInputs<'a>, String> {
        let family = TCP_FAMILIES
            .iter()
            .copied()
            .find(|f| *f == family)
            .ok_or_else(|| format!("unknown family {family}; one of {}", TCP_FAMILIES.join(" ")))?;
        let all: Vec<&TcpSeed> = corpus.iter().collect();
        let seeds: Vec<&TcpSeed> = if family_app(family).is_some() {
            corpus
                .iter()
                .filter(|s| s.family() == Some(family))
                .collect()
        } else {
            all.clone()
        };
        if seeds.is_empty() {
            return Err(format!("no seed for family {family}"));
        }
        Ok(TcpInputs {
            rng: Rng::new(seed),
            family,
            seeds,
            all,
        })
    }
    pub fn family(&self) -> &'static str {
        self.family
    }
    pub fn family_seeds(&self) -> usize {
        self.seeds.len()
    }
    fn seed(&mut self) -> &'a TcpSeed {
        self.seeds[self.rng.below(self.seeds.len())]
    }
    /// A seed's stream with the mutations of `fuzz udp`, sometimes grown, sometimes random instead, cut at
    /// [`MAX_STREAM`]; the splice partner is of the family seven times in eight, else of any.
    fn mutated(&mut self, s: &TcpSeed) -> Vec<u8> {
        let other = if self.rng.below(8) == 0 {
            self.all[self.rng.below(self.all.len())]
        } else {
            self.seed()
        };
        let rng = &mut self.rng;
        let mut px = if rng.below(16) == 0 {
            let n = if rng.below(8) == 0 {
                rng.below(MAX_STREAM + 1)
            } else {
                rng.below(2049)
            };
            rng.bytes(n)
        } else {
            s.stream.clone()
        };
        for _ in 0..1 + rng.below(4) {
            mutate(rng, &mut px, &other.stream);
        }
        if rng.below(8) == 0 {
            grow(rng, &mut px, &other.stream);
        }
        px.truncate(MAX_STREAM);
        px
    }
    pub fn draw(&mut self) -> TcpInput {
        if self.family == "stack" {
            TcpInput::Stack(self.draw_stack())
        } else {
            TcpInput::Stream(self.draw_stream())
        }
    }
    fn draw_stream(&mut self) -> StreamInput {
        let s = self.seed();
        let stream = self.mutated(s);
        let rng = &mut self.rng;
        let (force_app, port) = match family_app(self.family) {
            Some((app, port)) => {
                let app = if app == app_id::SSH2 && rng.below(2) == 0 {
                    app_id::SSH1
                } else {
                    app
                };
                (Some(app), if rng.below(8) == 0 { port } else { s.port })
            }
            None => (
                None,
                if rng.below(8) == 0 {
                    PORTS[rng.below(PORTS.len())]
                } else {
                    s.port
                },
            ),
        };
        let capture_html =
            s.capture_html || (matches!(self.family, "http" | "framework") && rng.below(4) == 0);
        let bound = split_bound(rng);
        let split = split(rng, stream.len(), bound);
        StreamInput {
            port,
            force_app,
            capture_html,
            stream,
            split,
        }
    }
    fn draw_stack(&mut self) -> StackPlan {
        let delivery = self.rng.below(2) == 0;
        let n = if delivery { 1 } else { 1 + self.rng.below(6) };
        let (mut keys, mut streams, mut capture_html) = (Vec::new(), Vec::new(), false);
        for i in 0..n {
            let s = self.seed();
            capture_html |= s.capture_html;
            streams.push(self.mutated(s));
            let port = if self.rng.below(8) == 0 {
                PORTS[self.rng.below(PORTS.len())]
            } else {
                s.port
            };
            let v6 = self.rng.below(3) == 0;
            keys.push(stack_key(i, port, v6));
        }
        let rng = &mut self.rng;
        let max_segment = split_bound(rng);
        if delivery {
            streams[0].truncate(max_segment.saturating_mul(DELIVERY_SEGMENTS));
        }
        StackPlan {
            delivery,
            lifetime: if delivery {
                0
            } else {
                [0, 1, 6, 30, u32::MAX][rng.below(5)]
            },
            capacity: if delivery {
                1 + rng.below(4)
            } else {
                [0, 1, 3, 8][rng.below(4)]
            },
            budget: if delivery {
                DELIVERY_BUDGET
            } else {
                [0, 7, 300, 1 << 20, 512 << 20][rng.below(5)]
            },
            table_seed: rng.next_u64(),
            script: rng.next_u64(),
            events: if delivery { 0 } else { 50 + rng.below(551) },
            max_segment,
            capture_html,
            keys,
            streams,
        }
    }
}

/// What a parser run of the fuzzer calls: [`banner_stream`], or a stand-in in tests.
pub type StreamFn = fn(&TcpBannerSettings, u16, Option<u16>, &[&[u8]]) -> StreamResult;
/// What makes a stack: [`tcp_stack_factory`], or a stand-in in tests.
pub type StackFn = fn(TcpBannerSettings, u32) -> Arc<dyn TcpStackFactory>;
/// The code under test.
#[derive(Clone, Copy)]
pub struct Target {
    pub stream: StreamFn,
    pub stack: StackFn,
}
impl Target {
    pub const PRODUCT: Target = Target {
        stream: banner_stream,
        stack: tcp_stack_factory,
    };
}

/// One event a stack input fed (the finding's reproducer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackEvent {
    Tick {
        now: u64,
    },
    Segment {
        now: u64,
        conn: usize,
        seq: u32,
        ack: u32,
        flags: u8,
        ttl: u8,
        payload: Vec<u8>,
    },
    Finish {
        max: usize,
    },
}
impl StackEvent {
    pub fn text(&self) -> String {
        match self {
            StackEvent::Tick { now } => format!("tick {now}"),
            StackEvent::Segment {
                now,
                conn,
                seq,
                ack,
                flags,
                ttl,
                payload,
            } => format!(
                "segment {now} conn={conn} seq={seq:#010x} ack={ack:#010x} flags={flags:#04x} ttl={ttl} {}",
                if payload.is_empty() {
                    "-".to_owned()
                } else {
                    hex(payload)
                }
            ),
            StackEvent::Finish { max } => format!("finish {max}"),
        }
    }
}

/// What the fuzzer read off the stack's segments about one connection: the SYN-ACK that created it (their ISN, the
/// ACK that became the scanner's number, its TTL), the end of the scanner's furthest segment and the last
/// acknowledgment number the scanner sent.
#[derive(Debug, Clone, Copy, Default)]
struct Seen {
    created: bool,
    isn: u32,
    our_isn: u32,
    ttl: u8,
    our_next: u32,
    their_ack: Option<u32>,
    /// The scanner sent a FIN (C closes: after its FIN is ACKed the stack ignores data).
    fin: bool,
}

/// A table under a stack input: feeds events, records them and checks every output against the stack's contract.
struct Feeder<'p> {
    plan: &'p StackPlan,
    st: Box<dyn TcpStack>,
    now: u64,
    seen: Vec<Seen>,
    /// Shared with the caller, who keeps them when the stack panics.
    events: &'p RefCell<Vec<StackEvent>>,
    /// Every banner set with its connection.
    sets: Vec<(usize, Vec<Record>)>,
    problem: Option<(&'static str, String)>,
    data_segments: u64,
    records: u64,
}
impl Feeder<'_> {
    fn fail(&mut self, what: String) {
        if self.problem.is_none() {
            self.problem = Some(("invariant", what));
        }
    }
    fn tick(&mut self, now: u64) {
        self.now = now;
        self.events.borrow_mut().push(StackEvent::Tick { now });
        let mut out = StackOutput::default();
        self.st.on_tick(now, &mut out);
        self.observe(out);
    }
    fn segment(
        &mut self,
        conn: usize,
        (seq, ack, flags, ttl): (u32, u32, u8, u8),
        payload: Vec<u8>,
    ) -> bool {
        // Recorded before the stack sees it: a crash keeps the segment that caused it.
        self.events.borrow_mut().push(StackEvent::Segment {
            now: self.now,
            conn,
            seq,
            ack,
            flags,
            ttl,
            payload: payload.clone(),
        });
        let before = self.st.stats();
        let mut out = StackOutput::default();
        let seg = SegmentIn {
            key: self.plan.keys[conn],
            seq,
            ack,
            flags,
            ttl,
            payload: &payload,
        };
        let took = self.st.on_segment(self.now, &seg, &mut out);
        let after = self.st.stats();
        if flags & SYN_ACK == SYN_ACK && after.tcbs_created > before.tcbs_created {
            self.seen[conn] = Seen {
                created: true,
                isn: seq,
                our_isn: ack,
                ttl,
                our_next: ack,
                their_ack: None,
                fin: false,
            };
        }
        if after.table_full > before.table_full && (took || !out.segments.is_empty()) {
            self.fail("a full table took a SYN-ACK or answered it".into());
        }
        self.observe(out);
        took
    }
    /// `finish(max)`: no segment, exactly `min(max, live)` connections end, `true` while some are left.
    fn finish(&mut self, max: usize) -> bool {
        let live = self.st.stats().tcbs_live;
        let mut out = StackOutput::default();
        self.events.borrow_mut().push(StackEvent::Finish { max });
        let more = self.st.finish(max, &mut out);
        let left = self.st.stats().tcbs_live;
        if !out.segments.is_empty() {
            self.fail(format!("finish sent {} segments", out.segments.len()));
        }
        if left != live.saturating_sub(max as u64) {
            self.fail(format!(
                "finish({max}) of {live} live connections left {left}"
            ));
        }
        if more != (left > 0) {
            self.fail(format!("finish({max}) said more={more} with {left} left"));
        }
        self.observe(out);
        more
    }
    fn observe(&mut self, out: StackOutput) {
        for s in &out.segments {
            let Some(c) = self.plan.keys.iter().position(|k| *k == s.key) else {
                self.fail(format!(
                    "a segment to {:?}, a connection the input never had",
                    s.key
                ));
                continue;
            };
            if !matches!(s.flags, RST | ACK | FIN_ACK | PSH_ACK | FIN_PSH_ACK) {
                self.fail(format!("a segment with flags {:#04x}", s.flags));
            }
            if s.payload.len() > MSS {
                self.fail(format!(
                    "a segment of {} bytes (tcb->mss 1400)",
                    s.payload.len()
                ));
            }
            if s.window.is_some() {
                self.fail(format!(
                    "a segment with window {:?} (4b sends the template's)",
                    s.window
                ));
            }
            self.data_segments += u64::from(!s.payload.is_empty());
            let seen = &mut self.seen[c];
            let end = s
                .seq
                .wrapping_add(s.payload.len() as u32)
                .wrapping_add(u32::from(s.flags & FIN != 0));
            if seen.created && (end.wrapping_sub(seen.our_next) as i32) > 0 {
                seen.our_next = end;
            }
            seen.fin |= seen.created && s.flags & FIN != 0;
            if s.flags & ACK != 0 {
                seen.their_ack = Some(s.ack);
            }
        }
        for set in out.banners {
            if set.is_empty() {
                self.fail("an empty banner set".into());
                continue;
            }
            let mut conn = None;
            let mut recs = Vec::new();
            for r in set {
                let Some(c) = self
                    .plan
                    .keys
                    .iter()
                    .position(|k| k.remote_port == r.port && remote_ip(k) == r.ip)
                else {
                    self.fail(format!(
                        "a record of {}:{}, a connection the input never had",
                        r.ip, r.port
                    ));
                    continue;
                };
                if conn.is_some_and(|x| x != c) {
                    self.fail("one banner set over two connections".into());
                }
                conn = Some(c);
                let seen = self.seen[c];
                if !seen.created {
                    self.fail(format!("a record of connection {c}, never created"));
                } else if r.ttl != seen.ttl {
                    self.fail(format!(
                        "a record with TTL {} of a connection its SYN-ACK created with TTL {}",
                        r.ttl, seen.ttl
                    ));
                }
                if r.ip_proto != 6 {
                    self.fail(format!("a TCP record with IP protocol {}", r.ip_proto));
                }
                if let Some(bad) = records_problem(&[(r.app, r.payload.clone())]) {
                    self.fail(bad);
                }
                self.records += 1;
                recs.push((r.app, r.payload));
            }
            if let Some(c) = conn {
                self.sets.push((c, recs));
            }
        }
        let s: StackStats = self.st.stats();
        if s.tcbs_live > self.plan.capacity as u64 {
            self.fail(format!(
                "{} live connections in a table of {}",
                s.tcbs_live, self.plan.capacity
            ));
        }
        if s.tcbs_live > s.tcbs_created {
            self.fail(format!(
                "{} live connections of {} created",
                s.tcbs_live, s.tcbs_created
            ));
        }
    }
}

/// Chaos: SYN-ACKs, segments with C's flags and random ones, numbers at, around and away from the stack's own, payloads
/// from the connection's stream or random, ticks with delays and jumps (`stack_never_panics` of `rmasscan-proto`,
/// from the outside).
fn chaos(f: &mut Feeder<'_>, rng: &mut Rng) {
    let plan = f.plan;
    let mut now = if rng.below(10) == 0 {
        rng.next_u64() >> 2
    } else {
        T0
    };
    f.now = now;
    for _ in 0..plan.events {
        if f.problem.is_some() {
            return;
        }
        if rng.below(4) == 0 {
            now = now.saturating_add(match rng.below(40) {
                0 => 1 + rng.next_u64() % (6 * SEC),
                1 if rng.below(10) == 0 => 10_000_000 * SEC,
                _ => rng.next_u64() % (400 * MS),
            });
            f.tick(now);
            continue;
        }
        let conn = rng.below(plan.keys.len());
        let s = f.seen[conn];
        let flags = match rng.below(20) {
            0..=2 => SYN_ACK,
            3..=5 => ACK,
            6..=10 => PSH_ACK,
            11 | 12 => FIN_ACK,
            13 => FIN_PSH_ACK,
            14 => RST,
            15 => RST | ACK,
            16 => FIN,
            _ => rng.byte(),
        };
        let seq = if flags & SYN_ACK == SYN_ACK {
            if s.created && rng.below(3) != 0 {
                s.isn
            } else {
                rng.u32()
            }
        } else {
            match s.their_ack {
                Some(a) if rng.below(4) != 0 => a,
                Some(a) => a.wrapping_add(rng.below(3000) as u32).wrapping_sub(1500),
                None => rng.u32(),
            }
        };
        let ack = if !s.created || rng.below(8) == 0 {
            rng.u32()
        } else {
            let span = s.our_next.wrapping_sub(s.our_isn) as usize;
            match rng.below(6) {
                0 => s.our_isn,
                1 => s.our_isn.wrapping_add(rng.below(span + 1) as u32),
                2 => s.our_next.wrapping_add(1),
                _ => s.our_next,
            }
        };
        let n = match rng.below(10) {
            0 => rng.below(MAX_SEGMENT + 1),
            1..=3 => 0,
            _ => rng.below(64),
        };
        let stream = &plan.streams[conn];
        let off = seq.wrapping_sub(s.isn.wrapping_add(1)) as usize;
        let payload = match stream.get(off..) {
            Some(rest) if s.created && !rest.is_empty() && rng.below(4) != 0 => {
                rest[..n.min(rest.len())].to_vec()
            }
            _ => rng.bytes(n),
        };
        let ttl = rng.byte();
        f.segment(conn, (seq, ack, flags, ttl), payload);
    }
}

/// Delivery: one connection's SYN-ACK, then its stream from the server at once (so no hello: `src/stack-tcp-app.c:
/// 100-105`), in segments of at most `max_segment` bytes, mostly where the stack's last ACK points, sometimes behind it
/// (a duplicate or an overlap) or ahead (dropped, `src/stack-tcp-core.c:1917-1949`), each ACKing everything the scanner
/// sent (sometimes an old number); stalls get a 2-second tick (the scanner's queue moves on its timer).
fn deliver(f: &mut Feeder<'_>, rng: &mut Rng) -> Delivery {
    let plan = f.plan;
    let stream = &plan.streams[0];
    let len = stream.len();
    let bound = plan.max_segment.max(1);
    let mut now = T0 + rng.below(1000) as u64;
    f.now = now;
    let isn = rng.u32();
    let our_isn = rng.u32();
    let ttl = rng.byte();
    f.segment(0, (isn, our_isn, SYN_ACK, ttl), Vec::new());
    let start = isn.wrapping_add(1);
    let at_of = |s: &Seen| s.their_ack.map(|a| a.wrapping_sub(start) as usize);
    let (mut stalled, mut jumps) = (0u32, 0u32);
    let mut stall = Stall::default();
    let cap = 256 + 4 * (len / bound.div_ceil(2) + 1);
    for _ in 0..cap {
        if f.problem.is_some() {
            return done(f, false, stall);
        }
        let s = f.seen[0];
        let Some(at) = at_of(&s) else {
            return done(f, false, stall);
        };
        if at >= len {
            if rng.below(2) == 0 {
                now += rng.below(3000) as u64;
                f.now = now;
                f.segment(
                    0,
                    (start.wrapping_add(len as u32), s.our_next, FIN_ACK, ttl),
                    Vec::new(),
                );
            }
            return done(f, true, Stall::default());
        }
        let off = match rng.below(10) {
            0 => at.saturating_sub(1 + rng.below(2 * bound)),
            1 => (at + 1 + rng.below(bound)).min(len - 1),
            _ => at,
        };
        let n = (1 + rng.below(bound)).min(len - off);
        let flags = if off + n == len && rng.below(4) == 0 {
            FIN_PSH_ACK
        } else {
            PSH_ACK
        };
        let ack = if stall.progressed && rng.below(8) == 0 {
            s.our_isn
        } else {
            s.our_next
        };
        now += rng.below(3000) as u64;
        f.now = now;
        f.segment(
            0,
            (start.wrapping_add(off as u32), ack, flags, ttl),
            stream[off..off + n].to_vec(),
        );
        if rng.below(16) == 0 {
            f.tick(now);
        }
        if at_of(&f.seen[0]) == Some(at) {
            stalled += 1;
            // The next byte, with the number the scanner's data is ACKed up to: the stack must take it (the ACK step
            // of the frame comes before the data step, so a scanner whose sent data is all ACKed and whose queue is
            // empty leaves its sending state), unless it still holds data it has not sent (`STALL_LIMIT`).
            if off == at && ack == s.our_next {
                stall.strict += 1;
                stall.sent = s.our_next;
            }
        } else {
            stalled = 0;
            stall = Stall {
                progressed: true,
                ..Stall::default()
            };
        }
        // Not before the server's first byte got in: a tick then would send the hello (`App_SendNext`, where the
        // server's bytes are ACKed but not parsed, `src/stack-tcp-app.c:90-99`); ten jumps of at most 2.5 s stay
        // inside the 30 s life.
        if stall.progressed && stalled >= 3 && jumps < 10 {
            now += 2 * SEC + rng.below(500_000) as u64;
            f.tick(now);
            jumps += 1;
            stalled = 0;
        }
    }
    let complete = at_of(&f.seen[0]).is_some_and(|at| at >= len);
    done(f, complete, stall)
}

/// The stall of a delivery since its last progress.
#[derive(Debug, Clone, Copy, Default)]
struct Stall {
    /// Segments at the stack's ACK point, ACKing all the scanner sent, that moved nothing.
    strict: u32,
    /// What the scanner had sent (the end of its furthest segment) at the last of them.
    sent: u32,
    /// The stack took some of the server's bytes before (the parser had them: `App_ReceiveNext`, so no hello follows,
    /// `src/stack-tcp-app.c:100-105`, and while the stall lasts nothing joins the scanner's queue).
    progressed: bool,
}
/// How far a delivery got.
struct Delivery {
    /// Bytes of the stream the stack ACKed (`None`: no connection ever answered).
    at: Option<usize>,
    complete: bool,
    stall: Stall,
}
fn done(f: &Feeder<'_>, complete: bool, stall: Stall) -> Delivery {
    let len = f.plan.streams[0].len();
    let start = f.seen[0].isn.wrapping_add(1);
    Delivery {
        at: f.seen[0]
            .their_ack
            .map(|a| (a.wrapping_sub(start) as usize).min(len)),
        complete,
        stall,
    }
}

/// Stalled segments at the ACK point, with every byte the scanner sent ACKed, after which in-order data still is not
/// taken: C ACKs an in-order segment in `ESTABLISHED` always (`src/stack-tcp-core.c:1917-1949`), so the stall is the
/// stack's, unless it is in `ESTABLISHED_SEND`, which ignores DATA (`:2071-2076`) and which the ACK step of the same
/// frame leaves only when the queue is empty (`:2053-2066`): its queue still holds data it has not sent (only the head
/// goes out at once, `:1405-1412`, the rest one segment per timeout as the head is ACKed, `_tcb_seg_resend`,
/// `:1290-1312`). [`holds_unsent`] tells.
const STALL_LIMIT: u32 = 3;
/// How long after the delivery's last event [`holds_unsent`] ticks: past every deadline the stack can have set then
/// (2 s from its last timeout, 5 s in `TIME_WAIT`).
const PROBE_AFTER: u64 = 6 * SEC;

/// Whether the scanner of a stalled delivery still holds data of its own it had not sent at the last stall (from
/// `sent` on): the delivery's `events` replayed on a new table of the plan whose connections outlive any tick (a
/// table keeps a connection to its lifetime RST, which comes only on a tick, so the replay is the same run up to
/// here: a connection alive at the end met no tick past its life), then one tick [`PROBE_AFTER`] later. On it C's
/// timeout in `ESTABLISHED_SEND` sends the head of the queue (`_tcb_seg_resend`, `src/stack-tcp-core.c:1290-1312`)
/// and in `ESTABLISHED_RECV`, after the server's first bytes, nothing (`App_ReceiveNext`, `src/stack-tcp-app.c:
/// 137-146`): a data segment of connection 0 at or past `sent` is data the scanner held unsent.
fn holds_unsent(t: &Target, plan: &StackPlan, events: &[StackEvent], sent: u32) -> bool {
    let mut st = (t.stack)(settings(plan.capture_html), u32::MAX).new_table(TableParams {
        seed: plan.table_seed,
        capacity: plan.capacity,
        banner_byte_budget: plan.budget,
    });
    let mut last = T0;
    for e in events {
        let mut out = StackOutput::default();
        match e {
            StackEvent::Tick { now } => {
                last = *now;
                st.on_tick(*now, &mut out);
            }
            StackEvent::Segment {
                now,
                conn,
                seq,
                ack,
                flags,
                ttl,
                payload,
            } => {
                last = *now;
                let seg = SegmentIn {
                    key: plan.keys[*conn],
                    seq: *seq,
                    ack: *ack,
                    flags: *flags,
                    ttl: *ttl,
                    payload,
                };
                st.on_segment(*now, &seg, &mut out);
            }
            // A delivery ends before `finish`.
            StackEvent::Finish { .. } => return false,
        }
    }
    let mut out = StackOutput::default();
    st.on_tick(last + PROBE_AFTER, &mut out);
    out.segments.iter().any(|s| {
        s.key == plan.keys[0] && !s.payload.is_empty() && (s.seq.wrapping_sub(sent) as i32) >= 0
    })
}

/// How a delivery input ended: compared with the framework on the whole stream, or stopped short (compared on the
/// ACKed prefix; a stall on in-order data is a finding before it gets here), or not compared because the parser closes
/// (after its FIN C's stack stops reading: FIN_WAIT2 ignores data, `src/stack-tcp-core.c:2241-2263`, so the split
/// decides what it still parses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivered {
    Compared,
    Incomplete,
    Closed,
}
/// What one input gave.
#[derive(Debug, Default)]
struct Checked {
    crash: Option<String>,
    problem: Option<(&'static str, String)>,
    records: u64,
    acted: bool,
    segments: usize,
    max_record: usize,
    connections: u64,
    delivered: Option<Delivered>,
    /// A delivery stalled where the scanner still held data it had not sent ([`holds_unsent`]).
    own_queue: bool,
    events: Vec<StackEvent>,
    /// What the 100 ms budget is held against: a parser input's run on the whole stream, a stack input's whole run.
    timed: Duration,
    /// A parser input's run on its split (reported, not held against the budget: a 64 KiB stream in single bytes is
    /// 65 000 calls).
    split_timed: Duration,
}

/// A record that is not a known application with 1 to 65 536 bytes (`src/proto-banout.c` flushes only non-empty
/// buffers of a protocol, R5).
fn records_problem(recs: &[(u16, Vec<u8>)]) -> Option<String> {
    recs.iter().find_map(|(app, b)| {
        if *app == 0 || *app > app_id::ERROR {
            Some(format!("a record of application {app}"))
        } else if b.is_empty() || b.len() > MAX_BANNER_BYTES {
            Some(format!("a record of {} bytes", b.len()))
        } else {
            None
        }
    })
}
fn show_record(r: Option<&(u16, Vec<u8>)>) -> String {
    r.map_or_else(
        || "none".to_owned(),
        |(app, b)| {
            format!(
                "{} {} bytes {:?}",
                rmasscan_proto::app_name(*app),
                b.len(),
                String::from_utf8_lossy(&b[..b.len().min(48)])
            )
        },
    )
}
fn records_diff(got: &[(u16, Vec<u8>)], want: &[(u16, Vec<u8>)]) -> String {
    let i = (0..got.len().max(want.len()))
        .find(|&i| got.get(i) != want.get(i))
        .unwrap_or(0);
    format!(
        "{} records against {}; record {}: {} against {}",
        got.len(),
        want.len(),
        i + 1,
        show_record(got.get(i)),
        show_record(want.get(i))
    )
}
fn show_action(a: Option<&StreamAction>) -> String {
    match a {
        None => "none".into(),
        Some(StreamAction::Close) => "close".into(),
        Some(StreamAction::Send(b)) => format!("send {} bytes", b.len()),
    }
}
/// How the split's result differs from the whole stream's.
fn result_diff(whole: &StreamResult, split: &StreamResult) -> String {
    if whole.app_proto != split.app_proto {
        return format!(
            "application {:?} split, {:?} whole",
            split.app_proto, whole.app_proto
        );
    }
    if whole.records != split.records {
        return format!("records: {}", records_diff(&split.records, &whole.records));
    }
    let i = (0..whole.actions.len().max(split.actions.len()))
        .find(|&i| whole.actions.get(i) != split.actions.get(i))
        .unwrap_or(0);
    format!(
        "actions: {} split against {}; action {}: {} against {}",
        split.actions.len(),
        whole.actions.len(),
        i + 1,
        show_action(split.actions.get(i)),
        show_action(whole.actions.get(i))
    )
}

fn check_stream(t: &Target, i: &StreamInput) -> Checked {
    let s = settings(i.capture_html);
    let run = |segs: &[&[u8]]| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (t.stream)(&s, i.port, i.force_app, segs)
        }))
    };
    let segs = i.segments();
    let mut c = Checked {
        segments: segs.len(),
        ..Checked::default()
    };
    let started = Instant::now();
    let whole = run(&whole_of(&i.stream));
    c.timed = started.elapsed();
    let whole = match whole {
        Ok(r) => r,
        Err(_) => {
            c.crash = Some(format!("the whole stream: {}", last_panic()));
            return c;
        }
    };
    let started = Instant::now();
    let split = run(&segs);
    c.split_timed = started.elapsed();
    let split = match split {
        Ok(r) => r,
        Err(_) => {
            c.crash = Some(format!("{} segments: {}", segs.len(), last_panic()));
            return c;
        }
    };
    c.records = whole.records.len() as u64;
    c.acted = !whole.actions.is_empty();
    c.max_record = whole
        .records
        .iter()
        .chain(&split.records)
        .map(|r| r.1.len())
        .max()
        .unwrap_or(0);
    if let Some(bad) = records_problem(&whole.records).or_else(|| records_problem(&split.records)) {
        c.problem = Some(("invariant", bad));
    } else if whole.app_proto == Some(app_id::TELNET)
        && let Err(e) = telnet_answers(&whole.actions)
    {
        // The parser's own reply on the whole stream is malformed: not a matter of the split.
        c.problem = Some(("invariant", format!("the whole stream: {e}")));
    } else if let Some(diff) = split_problem(&whole, &split) {
        c.problem = Some(("split", format!("{} segments: {diff}", segs.len())));
    }
    c
}

/// R13: how the split's result differs from the whole stream's, or `None`. The application and the records must be
/// equal; the actions too, except where 4b keeps C's per-call behaviour (C reference E2: "sends are compared only on
/// the unsplit run"). Telnet answers once per parse call (`src/proto-tcp-telnet.c:248`), so a split may group and
/// repeat its refusals differently, but every negotiated option gets the same last answer; Minecraft closes at the end
/// of every call whose brace count is at or below zero (E2.7, `src/proto-mc.c:59-65`), so when the whole stream closes
/// the split closes too, and neither sends.
fn split_problem(whole: &StreamResult, split: &StreamResult) -> Option<String> {
    if whole.app_proto != split.app_proto || whole.records != split.records {
        return Some(result_diff(whole, split));
    }
    match whole.app_proto {
        Some(app_id::TELNET) => match (
            telnet_answers(&whole.actions),
            telnet_answers(&split.actions),
        ) {
            (Ok(w), Ok(s)) if w == s => None,
            (Ok(w), Ok(s)) => Some(format!("telnet answers {s:?} split against {w:?} whole")),
            (Err(e), _) => Some(format!("the whole stream: {e}")),
            (_, Err(e)) => Some(format!("the split: {e}")),
        },
        Some(app_id::MC) => {
            let closes =
                |a: &[StreamAction]| a.iter().filter(|x| **x == StreamAction::Close).count();
            if closes(&whole.actions) != whole.actions.len()
                || closes(&split.actions) != split.actions.len()
            {
                Some(result_diff(whole, split))
            } else if closes(&whole.actions) > 0 && closes(&split.actions) == 0 {
                Some("the whole stream closes, the split never".into())
            } else {
                None
            }
        }
        _ => (whole.actions != split.actions).then(|| result_diff(whole, split)),
    }
}
/// Telnet's answers: the last command each option got (`IAC WONT` 252 or `IAC DONT` 254), over every reply in
/// order, and the closes; a reply that is not ascending `IAC cmd option` triples is an error.
fn telnet_answers(actions: &[StreamAction]) -> Result<(BTreeMap<u8, u8>, usize), String> {
    let (mut last, mut closes) = (BTreeMap::new(), 0);
    for a in actions {
        match a {
            StreamAction::Close => closes += 1,
            StreamAction::Send(b) => {
                if b.is_empty() || b.len() % 3 != 0 {
                    return Err(format!("a telnet reply of {} bytes", b.len()));
                }
                let mut prev: Option<u8> = None;
                for t in b.chunks(3) {
                    if t[0] != 255 || !matches!(t[1], 252 | 254) || prev.is_some_and(|p| p >= t[2])
                    {
                        return Err(format!("a telnet reply {t:02x?} after option {prev:?}"));
                    }
                    prev = Some(t[2]);
                    last.insert(t[2], t[1]);
                }
            }
        }
    }
    Ok((last, closes))
}

/// How often `finish` may be called before a table that keeps its connections is a finding.
const FINISH_ROUNDS: usize = 10_000;

fn check_stack(t: &Target, plan: &StackPlan) -> Checked {
    let mut c = Checked::default();
    let log = RefCell::new(Vec::new());
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drive(t, plan, &log)));
    c.events = log.take();
    c.segments = c.events.len();
    match r {
        Err(_) => c.crash = Some(last_panic()),
        Ok(d) => {
            c.problem = d.problem;
            c.records = d.records;
            c.acted = d.data_segments > 0;
            c.max_record = d.max_record;
            c.connections = d.created;
            c.delivered = d.delivered;
            c.own_queue = d.own_queue;
        }
    }
    c
}

struct Driven {
    problem: Option<(&'static str, String)>,
    records: u64,
    max_record: usize,
    data_segments: u64,
    created: u64,
    delivered: Option<Delivered>,
    own_queue: bool,
}
fn drive(t: &Target, plan: &StackPlan, log: &RefCell<Vec<StackEvent>>) -> Driven {
    let s = settings(plan.capture_html);
    let st = (t.stack)(s.clone(), plan.lifetime).new_table(TableParams {
        seed: plan.table_seed,
        capacity: plan.capacity,
        banner_byte_budget: plan.budget,
    });
    let mut f = Feeder {
        plan,
        st,
        now: T0,
        seen: vec![Seen::default(); plan.keys.len()],
        events: log,
        sets: Vec::new(),
        problem: None,
        data_segments: 0,
        records: 0,
    };
    let mut rng = Rng::new(plan.script);
    let delivery = if plan.delivery {
        Some(deliver(&mut f, &mut rng))
    } else {
        chaos(&mut f, &mut rng);
        None
    };
    let delivered_events = log.borrow().len();
    // Before `finish` ends every connection: whether the stack still held this one, and whether it closed it.
    let (live, fin) = (f.st.stats().tcbs_live > 0, f.seen[0].fin);
    for _ in 0..FINISH_ROUNDS {
        if f.problem.is_some() || !f.finish(rng.below(4)) {
            break;
        }
    }
    let left = f.st.stats().tcbs_live;
    if left != 0 {
        f.fail(format!(
            "{left} connections live after {FINISH_ROUNDS} calls of finish"
        ));
    }
    let mut delivered = None;
    let mut own_queue = false;
    if let Some(d) = delivery
        && f.problem.is_none()
    {
        let stream = &plan.streams[0];
        let whole = (t.stream)(&s, plan.keys[0].remote_port, None, &whole_of(stream));
        let closes = |r: &StreamResult| r.actions.contains(&StreamAction::Close);
        let at = d.at.unwrap_or(0);
        // The C stack takes no data where it drops it itself: after its own FIN (it closed), once the connection is
        // gone, or while it still holds data of its own it has not sent (`ESTABLISHED_SEND`, `STALL_LIMIT`); where
        // the whole stream closes the split decides what the parser still gets. Anything else that stalls on
        // in-order data is the stack's.
        if !d.complete && d.stall.strict >= STALL_LIMIT && live && !fin && !closes(&whole) {
            own_queue = d.stall.progressed
                && holds_unsent(t, plan, &log.borrow()[..delivered_events], d.stall.sent);
            if !own_queue {
                // Before the stack took a byte the probe does not run (a queued hello could have come mid-stall).
                let probed = if d.stall.progressed {
                    ", and a timeout shows no unsent data of its own"
                } else {
                    ""
                };
                f.fail(format!(
                    "the stack stopped taking in-order data at byte {at} of {}: {} segments at its ACK point, each \
                     ACKing all the scanner sent, moved nothing{probed}",
                    stream.len(),
                    d.stall.strict
                ));
            }
        }
        // On the part of the stream the stack ACKed, its records equal the framework's (on all of it when complete).
        let prefix = (t.stream)(&s, plan.keys[0].remote_port, None, &whole_of(&stream[..at]));
        delivered = Some(
            if closes(&whole) || (!d.complete && (fin || closes(&prefix))) {
                if d.complete {
                    Delivered::Closed
                } else {
                    Delivered::Incomplete
                }
            } else if d.at.is_none() {
                Delivered::Incomplete
            } else {
                let got: Vec<(u16, Vec<u8>)> = f
                    .sets
                    .iter()
                    .filter(|(c, _)| *c == 0)
                    .flat_map(|(_, r)| r.iter().cloned())
                    .collect();
                let want = if d.complete { &whole } else { &prefix };
                if f.problem.is_none() && got != want.records {
                    let segments = f
                    .events
                    .borrow()
                    .iter()
                    .filter(
                        |e| matches!(e, StackEvent::Segment { payload, .. } if !payload.is_empty()),
                    )
                    .count();
                    f.problem = Some((
                        "split",
                        format!(
                            "the stack's records of a stream delivered in {segments} data segments against the whole \
                         stream's ({at} of {} bytes ACKed): {}",
                            stream.len(),
                            records_diff(&got, &want.records)
                        ),
                    ));
                }
                if d.complete {
                    Delivered::Compared
                } else {
                    Delivered::Incomplete
                }
            },
        );
    }
    Driven {
        max_record: f
            .sets
            .iter()
            .flat_map(|(_, r)| r.iter().map(|x| x.1.len()))
            .max()
            .unwrap_or(0),
        problem: f.problem,
        records: f.records,
        data_segments: f.data_segments,
        created: f.st.stats().tcbs_created,
        delivered,
        own_queue,
    }
}

fn check(t: &Target, i: &TcpInput) -> Checked {
    match i {
        TcpInput::Stream(s) => check_stream(t, s),
        TcpInput::Stack(p) => {
            let start = Instant::now();
            let mut c = check_stack(t, p);
            c.timed = start.elapsed();
            c
        }
    }
}

/// What a run of one family reached.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TcpStats {
    /// Inputs whose run gave a record (the whole stream's; the stack's over all connections).
    pub with_records: u64,
    pub records: u64,
    /// Parser families: inputs whose parser sent or closed on the whole stream; stack: inputs where the scanner sent
    /// data (a hello or a parser's reply).
    pub with_actions: u64,
    pub max_stream: usize,
    /// The most segments of a split (stack: events of an input).
    pub max_segments: usize,
    pub max_record: usize,
    /// Stack: connections created.
    pub connections: u64,
    pub delivered_compared: u64,
    pub delivered_incomplete: u64,
    pub delivered_closed: u64,
    /// Incomplete deliveries that stalled where the scanner still held data it had not sent (C drops data in
    /// `ESTABLISHED_SEND`, `src/stack-tcp-core.c:2071-2076`): not findings.
    pub delivered_own_queue: u64,
    pub max_ns: u64,
    pub total_ns: u128,
    /// The slowest run of a parser input on its split.
    pub max_split_ns: u64,
}
/// A finding of `fuzz tcp`: the input, what happened and, for the stack, every event it fed.
#[derive(Debug, Clone)]
pub struct TcpFinding {
    /// The input's place in the seed's stream (the first is 1): replay is the first `index` draws.
    pub index: u64,
    pub kind: &'static str,
    pub input: TcpInput,
    pub what: String,
    pub events: Vec<StackEvent>,
}
#[derive(Debug, Clone, Default)]
pub struct TcpOutcome {
    pub family: &'static str,
    pub family_seeds: usize,
    pub inputs: u64,
    pub elapsed: Duration,
    pub stats: TcpStats,
    pub findings: Vec<TcpFinding>,
    pub crashes: u64,
    pub slow: u64,
    pub invariant_failures: u64,
    pub split_mismatches: u64,
    pub rss: Vec<(f64, u64)>,
    pub sha256: String,
}
impl TcpOutcome {
    pub fn rss_growth_kib(&self) -> Option<i64> {
        rss_growth(&self.rss)
    }
    pub fn verdict(&self) -> Verdict {
        Verdict::of(
            self.crashes + self.slow + self.invariant_failures + self.split_mismatches > 0,
            self.inputs,
            &self.rss,
        )
    }
    pub fn clean(&self) -> bool {
        self.verdict() == Verdict::Clean
    }
}

/// Fuzz `family` until `done(inputs, elapsed)`: the input stream of `seed` from `corpus`.
pub fn fuzz_tcp(
    family: &str,
    seed: u64,
    corpus: &[TcpSeed],
    done: impl FnMut(u64, Duration) -> bool,
) -> Result<TcpOutcome, String> {
    fuzz_tcp_with(family, seed, corpus, Target::PRODUCT, rss_kib, done)
}

/// [`fuzz_tcp`] against `target`, with the resident set read by `probe`.
pub fn fuzz_tcp_with(
    family: &str,
    seed: u64,
    corpus: &[TcpSeed],
    target: Target,
    probe: impl FnMut() -> Option<u64>,
    mut done: impl FnMut(u64, Duration) -> bool,
) -> Result<TcpOutcome, String> {
    let mut inputs = TcpInputs::new(seed, family, corpus)?;
    let start = Instant::now();
    let mut o = TcpOutcome {
        family: inputs.family(),
        family_seeds: inputs.family_seeds(),
        ..TcpOutcome::default()
    };
    let mut hash = Sha256::new();
    let mut rss = Sampler::new(probe, start);
    while !done(o.inputs, start.elapsed()) {
        let i = inputs.draw();
        i.hash_into(&mut hash);
        o.inputs += 1;
        let c = check(&target, &i);
        let mut dt = c.timed;
        let split_dt = c.split_timed;
        let st = &mut o.stats;
        st.with_records += u64::from(c.records > 0);
        st.records += c.records;
        st.with_actions += u64::from(c.acted);
        st.max_segments = st.max_segments.max(c.segments);
        st.max_record = st.max_record.max(c.max_record);
        st.connections += c.connections;
        match c.delivered {
            Some(Delivered::Compared) => st.delivered_compared += 1,
            Some(Delivered::Incomplete) => st.delivered_incomplete += 1,
            Some(Delivered::Closed) => st.delivered_closed += 1,
            None => {}
        }
        st.delivered_own_queue += u64::from(c.own_queue);
        st.max_stream = st.max_stream.max(match &i {
            TcpInput::Stream(s) => s.stream.len(),
            TcpInput::Stack(p) => p.streams.iter().map(Vec::len).max().unwrap_or(0),
        });
        let Checked {
            crash,
            problem,
            events,
            ..
        } = c;
        let mut finding = None;
        if let Some(msg) = crash {
            o.crashes += 1;
            finding = Some(("crash", msg));
        } else if let Some((kind, what)) = problem {
            if kind == "split" {
                o.split_mismatches += 1;
            } else {
                o.invariant_failures += 1;
            }
            finding = Some((kind, what));
        }
        if dt > SLOW {
            // A scheduler stall is not a slow input: the fastest of three timings decides.
            for _ in 0..2 {
                dt = dt.min(check(&target, &i).timed);
            }
            if dt > SLOW {
                o.slow += 1;
                finding.get_or_insert(("slow", format!("{} ms", dt.as_millis())));
            }
        }
        let ns = u64::try_from(dt.as_nanos()).unwrap_or(u64::MAX);
        let split_ns = u64::try_from(split_dt.as_nanos()).unwrap_or(u64::MAX);
        o.stats.max_split_ns = o.stats.max_split_ns.max(split_ns);
        o.stats.max_ns = o.stats.max_ns.max(ns);
        o.stats.total_ns += u128::from(ns);
        if let Some((kind, what)) = finding
            && o.findings.iter().filter(|f| f.kind == kind).count() < KEEP
        {
            o.findings.push(TcpFinding {
                index: o.inputs,
                kind,
                input: i,
                what,
                events,
            });
        }
        rss.after_input(o.inputs);
    }
    o.rss = rss.end(o.inputs);
    o.elapsed = start.elapsed();
    o.sha256 = hex(&hash.finalize());
    Ok(o)
}

fn plan_json(p: &StackPlan) -> Value {
    json!({
        "delivery": p.delivery, "connection_timeout": p.lifetime, "capacity": p.capacity,
        "banner_byte_budget": p.budget, "table_seed": p.table_seed, "script": p.script, "events": p.events,
        "max_segment": p.max_segment, "capture_html": p.capture_html,
        "connections": p.keys.iter().zip(&p.streams).map(|(k, s)| json!({
            "remote": remote_ip(k).to_string(), "port": k.remote_port, "local_port": k.local_port,
            "stream": hex(s)})).collect::<Vec<_>>(),
    })
}
fn tcp_finding_json(f: &TcpFinding) -> Value {
    match &f.input {
        TcpInput::Stream(s) => {
            json!({"kind": f.kind, "index": f.index, "port": s.port, "force_app": s.force_app,
            "capture_html": s.capture_html, "input": hex(&s.stream), "split": s.split, "what": f.what})
        }
        TcpInput::Stack(p) => json!({"kind": f.kind, "index": f.index, "plan": plan_json(p),
            "events": f.events.iter().map(StackEvent::text).collect::<Vec<_>>(), "what": f.what}),
    }
}
/// The report of a `fuzz tcp` run.
pub fn tcp_report(seed: u64, limit: &str, corpus: &[TcpSeed], o: &TcpOutcome) -> Value {
    let mut origins: BTreeMap<&str, usize> = BTreeMap::new();
    for s in corpus {
        *origins.entry(s.origin.name()).or_default() += 1;
    }
    let s = &o.stats;
    json!({
        "schema": 1,
        "tool": "rmasscan-lab fuzz tcp",
        "family": o.family,
        "seed": seed,
        "limit": limit,
        "elapsed_s": o.elapsed.as_secs_f64(),
        "inputs": o.inputs,
        "inputs_sha256": o.sha256,
        "corpus": origins,
        "family_seeds": o.family_seeds,
        "max_stream_bytes": MAX_STREAM,
        "max_segment_bytes": MAX_SEGMENT,
        "slow_threshold_ms": SLOW.as_millis() as u64,
        "crashes": o.crashes,
        "slow_over_100ms": o.slow,
        "invariant_failures": o.invariant_failures,
        "split_mismatches": o.split_mismatches,
        "stats": {
            "inputs_with_records": s.with_records, "records": s.records, "inputs_with_actions": s.with_actions,
            "max_stream_bytes": s.max_stream, "max_segments": s.max_segments, "max_record_bytes": s.max_record,
            "connections": s.connections,
            "delivered": {"compared": s.delivered_compared, "incomplete": s.delivered_incomplete,
                "closed": s.delivered_closed, "stalled_on_own_queue": s.delivered_own_queue},
            "max_us": s.max_ns / 1000,
            "max_split_us": s.max_split_ns / 1000,
            "mean_ns": if o.inputs == 0 { 0 } else { s.total_ns / u128::from(o.inputs) },
        },
        "rss_kib": rss_json(&o.rss, o.inputs),
        "memory_measured": memory_measured(o.inputs, &o.rss),
        "findings": o.findings.iter().map(tcp_finding_json).collect::<Vec<_>>(),
        "verdict": o.verdict().word(),
        "clean": o.clean(),
    })
}
/// The line `fuzz tcp` prints.
pub fn tcp_summary(seed: u64, o: &TcpOutcome) -> String {
    format!(
        "fuzz tcp family {} seed {seed}: {} inputs in {:.0} s, crashes {}, slow {}, invariant failures {}, split mismatches {}, rss growth {:?} KiB{}: {}",
        o.family,
        o.inputs,
        o.elapsed.as_secs_f64(),
        o.crashes,
        o.slow,
        o.invariant_failures,
        o.split_mismatches,
        o.rss_growth_kib(),
        memory_note(o.inputs, &o.rss),
        o.verdict().word()
    )
}

fn run_tcp(rest: &[String]) -> Result<i32, String> {
    let o = crate::windows_suite::options_for(
        "fuzz tcp",
        rest,
        &[
            "family", "seed", "duration", "count", "corpus", "pcap", "out",
        ],
    )?;
    if o.contains_key("help") {
        println!("{USAGE}");
        return Ok(0);
    }
    let family = match o.get("family").map(Vec::as_slice) {
        Some([f]) if TCP_FAMILIES.contains(&f.as_str()) => f.clone(),
        Some([f]) => {
            return Err(format!("--family {f}: one of {}", TCP_FAMILIES.join(" ")));
        }
        Some(_) => return Err("--family takes one family".into()),
        None => return Err("--family is required".into()),
    };
    let common = Common::parse(&o)?;
    let mut corpus = tcp_scenario_seeds();
    for d in o.get("corpus").into_iter().flatten() {
        corpus.extend(tcp_golden_seeds(Path::new(d))?);
    }
    for f in o.get("pcap").into_iter().flatten() {
        corpus.extend(tcp_capture_seeds(
            &fs::read(f).map_err(|e| format!("{f}: {e}"))?,
        )?);
    }
    quiet_panics();
    let outcome = fuzz_tcp(&family, common.seed, &corpus, |n, t| common.done(n, t));
    let _ = std::panic::take_hook();
    let outcome = outcome?;
    common.write(&tcp_report(common.seed, &common.limit(), &corpus, &outcome))?;
    println!("{}", tcp_summary(common.seed, &outcome));
    Ok(outcome.verdict().exit_code())
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
    fn tcp_golden_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/tcp-banners")
    }
    fn tcp_corpus() -> Vec<TcpSeed> {
        let mut c = tcp_scenario_seeds();
        c.extend(tcp_golden_seeds(&tcp_golden_dir()).unwrap());
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
        assert_eq!(o.verdict().exit_code(), 1);
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
        // L-M6: a product past u64 seconds is no duration (it panicked in a debug build, wrapped in release).
        assert_eq!(parse_duration("99999999999999999h"), None);
        assert_eq!(parse_duration("18446744073709551615m"), None);
        assert_eq!(
            parse_duration("18446744073709551615s"),
            Some(Duration::from_secs(u64::MAX))
        );
        let a = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        // A run of no input is refused, for both fuzzers, whatever the spelling of zero.
        for zero in [
            &["udp", "--seed", "1", "--count", "0"][..],
            &["udp", "--seed", "1", "--duration", "0"],
            &["udp", "--seed", "1", "--duration", "0h"],
            &["tcp", "--family", "http", "--seed", "1", "--count", "0"],
            &[
                "tcp",
                "--family",
                "stack",
                "--seed",
                "1",
                "--duration",
                "0s",
            ],
            &["udp", "--seed", "1", "--duration", "99999999999999999h"],
        ] {
            let e = run(&a(zero)).unwrap_err();
            assert!(
                e.contains("--duration") || e.contains("--count"),
                "{zero:?}: {e}"
            );
        }
        assert!(run(&a(&["sctp"])).is_err());
        assert!(run(&a(&["tcp"])).is_err(), "a family is required");
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

    // ------------------------------------------------------------------ M4, M3

    /// 4a review M4: the state is splitmix64 of the seed. Adjacent seeds share no draw among their first 64 and their
    /// first draws differ in about half the bits; the pair the old `seed * K | 1` collapsed (0 and `K⁻¹`) is apart;
    /// the seed splitmix64 maps to 0 does not stall xorshift at zero; the fuzzers' input streams differ.
    #[test]
    fn rng_adjacent_seeds_give_different_streams() {
        let stream = |seed: u64| {
            let mut r = Rng::new(seed);
            (0..64).map(|_| r.next_u64()).collect::<Vec<_>>()
        };
        let seeds: Vec<u64> = (0..1000)
            .chain(u64::MAX - 1000..u64::MAX)
            .chain(SPLITMIX_ZERO_SEED - 3..SPLITMIX_ZERO_SEED + 3)
            .chain([20261113, 20261115, 4_000_053])
            .collect();
        let mut bits = 0u64;
        for &s in &seeds {
            let (a, b) = (stream(s), stream(s.wrapping_add(1)));
            assert!(
                a.iter().all(|x| !b.contains(x)),
                "seeds {s} and {}",
                s.wrapping_add(1)
            );
            bits += u64::from((a[0] ^ b[0]).count_ones());
        }
        let mean = bits as f64 / seeds.len() as f64;
        assert!(
            (29.0..=35.0).contains(&mean),
            "{mean} bits differ on average"
        );

        let k = 0x9e37_79b9_7f4a_7c15u64;
        let mut inv = k;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(k.wrapping_mul(inv)));
        }
        assert_eq!(k.wrapping_mul(inv), 1);
        let old = |s: u64| s.wrapping_mul(k) | 1;
        assert_eq!(old(0), old(inv), "the defect M4 names");
        assert_ne!(stream(0), stream(inv));

        let mut z = Rng::new(SPLITMIX_ZERO_SEED);
        assert_eq!(z.0, ZERO_STATE_REPLACEMENT);
        let draws: Vec<u64> = (0..64).map(|_| z.next_u64()).collect();
        assert!(draws.iter().all(|x| *x != 0));
        assert_ne!(draws[0], draws[1]);

        let c = corpus();
        let udp = |seed| fuzz(seed, &FUZZ_PORTS, &c, |n, _| n >= 200).unwrap().sha256;
        assert_ne!(udp(41), udp(42));
        let t = tcp_corpus();
        let tcp = |seed| {
            fuzz_tcp("framework", seed, &t, |n, _| n >= 50)
                .unwrap()
                .sha256
        };
        assert_ne!(tcp(41), tcp(42));
    }

    /// 4a review M3: a run past [`WARMUP_INPUTS`] with fewer than two resident-set samples says "memory not measured"
    /// and exits 2 (a finding still exits 1, and the line still says it); a short run and a measured one do not.
    #[test]
    fn rss_unmeasured_is_reported() {
        let c = corpus();
        let past = |n: u64, _: Duration| n > WARMUP_INPUTS;
        let none = fuzz_with(1, &[53], &c, || None, past).unwrap();
        assert!(none.rss.is_empty());
        assert_eq!(none.verdict(), Verdict::MemoryNotMeasured);
        assert_eq!(none.verdict().exit_code(), 2);
        assert!(!none.clean());
        let line = summary(&[53], 1, &none);
        assert!(
            line.contains(", memory not measured (0 resident-set samples after 1001 inputs)")
                && line.ends_with(": MEMORY NOT MEASURED"),
            "{line}"
        );
        let rep = report(1, &[53], "1001 inputs", &c, &none);
        assert_eq!(
            (&rep["memory_measured"], &rep["clean"], &rep["verdict"]),
            (&json!(false), &json!(false), &json!("MEMORY NOT MEASURED"))
        );
        assert_eq!(rep["rss_kib"]["measured"], false);

        let mut first = true;
        let one = fuzz_with(
            1,
            &[53],
            &c,
            move || std::mem::replace(&mut first, false).then_some(4096),
            past,
        )
        .unwrap();
        assert_eq!(one.rss.len(), 1);
        assert_eq!(one.verdict().exit_code(), 2, "one sample is no growth");

        let mut found = none.clone();
        found.crashes = 1;
        assert_eq!(found.verdict().exit_code(), 1);
        assert!(summary(&[53], 1, &found).contains("memory not measured"));

        let short = fuzz_with(1, &[53], &c, || None, |n, _| n >= WARMUP_INPUTS).unwrap();
        assert!(short.rss.is_empty());
        assert_eq!(short.verdict(), Verdict::Clean, "a run of the warm-up only");
        let measured = fuzz_with(1, &[53], &c, || Some(4096), past).unwrap();
        assert!(measured.rss.len() >= 2, "the warm-up's sample and the last");
        assert!(measured.clean());
        assert!(!summary(&[53], 1, &measured).contains("memory"));

        let t = tcp_corpus();
        let tcp = fuzz_tcp_with("ftp", 1, &t, Target::PRODUCT, || None, past).unwrap();
        assert_eq!(tcp.verdict(), Verdict::MemoryNotMeasured);
        assert!(
            tcp_summary(1, &tcp)
                .contains("memory not measured (0 resident-set samples after 1001 inputs)")
        );
        assert_eq!(
            tcp_report(1, "1001 inputs", &t, &tcp)["memory_measured"],
            false
        );
        let tcp = fuzz_tcp_with("ftp", 1, &t, Target::PRODUCT, || Some(4096), past).unwrap();
        assert!(tcp.clean(), "{:#?}", tcp.findings);
    }

    // ------------------------------------------------------------------ fuzz tcp

    #[test]
    fn the_tcp_corpus_has_seeds_of_every_parser_family_from_the_goldens_and_the_stand() {
        let c = tcp_corpus();
        let man: Value =
            serde_json::from_slice(&fs::read(tcp_golden_dir().join("manifest.json")).unwrap())
                .unwrap();
        let cases = man["cases"].as_array().unwrap().len();
        assert_eq!(
            c.iter().filter(|s| s.origin == Origin::Golden).count(),
            cases
        );
        // Every scenario with a server stream (the silent 3389 server has none).
        assert_eq!(
            c.iter().filter(|s| s.origin == Origin::Scenario).count(),
            TCP_SCENARIOS.len() - 1
        );
        for f in TCP_FAMILIES.iter().filter(|f| family_app(f).is_some()) {
            for origin in [Origin::Scenario, Origin::Golden] {
                assert!(
                    c.iter()
                        .any(|s| s.origin == origin && s.family() == Some(f)),
                    "{f} {origin:?}"
                );
            }
        }
        // The 70 000-byte cases are cut at 64 KiB; `--capture html` cases keep it.
        assert_eq!(c.iter().map(|s| s.stream.len()).max(), Some(MAX_STREAM));
        assert!(c.iter().any(|s| s.capture_html));
        assert_eq!(
            parse_tcp_input(
                "tcp-banner-input v1\n# x\nport 21\ncapture none\nsegment 3232\nsegment repeat=5:6162\n"
            ),
            Ok((21, false, b"22ababa".to_vec()))
        );
        assert!(parse_tcp_input("tcp-oracle v1\n").is_err());
        assert!(parse_tcp_input("tcp-banner-input v1\nport 21\nsegment 3\n").is_err());
        assert!(
            parse_tcp_input("tcp-banner-input v1\nsegment 33\n").is_err(),
            "no port"
        );
        // A UDP golden directory is not a TCP corpus.
        assert!(tcp_golden_seeds(&golden_dir()).is_err());
    }

    /// An Ethernet frame of a TCP segment (no checksums: the capture reader does not need them).
    fn frame(
        src: IpAddr,
        dst: IpAddr,
        sp: u16,
        dp: u16,
        seq: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend(sp.to_be_bytes());
        tcp.extend(dp.to_be_bytes());
        tcp.extend(seq.to_be_bytes());
        tcp.extend(7u32.to_be_bytes());
        tcp.extend([0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        tcp.extend(payload);
        let mut f = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2];
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                f.extend([8, 0, 0x45, 0]);
                f.extend((20 + tcp.len() as u16).to_be_bytes());
                f.extend([0, 0, 0x40, 0, 64, 6, 0, 0]);
                f.extend(s.octets());
                f.extend(d.octets());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                f.extend([0x86, 0xdd, 0x60, 0, 0, 0]);
                f.extend((tcp.len() as u16).to_be_bytes());
                f.extend([6, 64]);
                f.extend(s.octets());
                f.extend(d.octets());
            }
            _ => unreachable!(),
        }
        f.extend(tcp);
        f
    }

    #[test]
    fn capture_streams_are_the_servers_bytes_in_sequence_order() {
        let (srv, me) = (IpAddr::from([198, 18, 0, 2]), IpAddr::from([198, 18, 0, 1]));
        let (srv6, me6): (IpAddr, IpAddr) = (
            "fd00:198:18::2".parse().unwrap(),
            "fd00:198:18::1".parse().unwrap(),
        );
        let frames: Vec<Vec<u8>> = vec![
            frame(me, srv, 40000, 21, 99, 0x02, b""),
            frame(srv, me, 21, 40000, 1000, SYN_ACK, b""),
            // Out of order, a retransmission overlapping both, the scanner's own data, a segment past a hole.
            frame(srv, me, 21, 40000, 1008, PSH_ACK, b"lo\r\n"),
            frame(srv, me, 21, 40000, 1001, PSH_ACK, b"220 hel"),
            frame(srv, me, 21, 40000, 1005, PSH_ACK, b"hello"),
            frame(me, srv, 40000, 21, 100, PSH_ACK, b"AUTH TLS\r\n"),
            frame(srv, me, 21, 40000, 1100, PSH_ACK, b"zz"),
            // The same 4-tuple with another ISN is another connection; IPv6 too; data without a SYN-ACK is not.
            frame(srv, me, 21, 40000, 5000, SYN_ACK, b""),
            frame(srv, me, 21, 40000, 5001, PSH_ACK, b"530 no\r\n"),
            frame(srv6, me6, 22, 40000, u32::MAX, SYN_ACK, b""),
            frame(srv6, me6, 22, 40000, 0, PSH_ACK, b"SSH-2.0-x\r\n"),
            frame(srv, me, 80, 40001, 1, PSH_ACK, b"HTTP/1.0 200 OK\r\n"),
        ];
        let pcap = crate::pcap::encode(&frames.into_iter().map(|f| (1.0, f)).collect());
        let got = tcp_capture_seeds(&pcap).unwrap();
        let want: Vec<(u16, &[u8])> = vec![
            (21, b"220 hello\r\n"),
            (21, b"530 no\r\n"),
            (22, b"SSH-2.0-x\r\n"),
        ];
        assert_eq!(
            got.iter()
                .map(|s| (s.port, &s.stream[..]))
                .collect::<Vec<_>>(),
            want
        );
        assert!(got.iter().all(|s| s.origin == Origin::Capture));
        assert_eq!(got[0].family(), Some("ftp"));
        assert_eq!(got[2].family(), Some("ssh"));
    }

    #[test]
    fn tcp_inputs_are_a_function_of_the_seed_and_stay_in_bounds() {
        let c = tcp_corpus();
        for fam in ["ssh", "framework"] {
            let mut i = TcpInputs::new(5, fam, &c).unwrap();
            let (mut long, mut bytewise, mut ssh1) = (0, 0, 0);
            for _ in 0..3000 {
                let TcpInput::Stream(s) = i.draw() else {
                    panic!("a stream family draws streams");
                };
                assert!(s.stream.len() <= MAX_STREAM);
                assert_eq!(s.split.iter().sum::<usize>(), s.stream.len());
                assert!(s.split.iter().all(|n| (1..=MAX_SEGMENT).contains(n)));
                assert_eq!(s.segments().concat(), s.stream);
                long += usize::from(s.stream.len() > 60_000);
                bytewise += usize::from(s.stream.len() > 1 && s.split.iter().all(|n| *n == 1));
                match fam {
                    "ssh" => {
                        assert!(matches!(s.force_app, Some(app_id::SSH1 | app_id::SSH2)));
                        ssh1 += usize::from(s.force_app == Some(app_id::SSH1));
                    }
                    _ => assert_eq!(s.force_app, None),
                }
            }
            assert!(
                long > 3 && bytewise > 100,
                "{fam}: {long} long, {bytewise} byte by byte"
            );
            if fam == "ssh" {
                assert!(ssh1 > 1000);
            }
        }
        let mut i = TcpInputs::new(5, "stack", &c).unwrap();
        let mut delivery = 0;
        for _ in 0..500 {
            let TcpInput::Stack(p) = i.draw() else {
                panic!("the stack draws plans");
            };
            assert_eq!(p.keys.len(), p.streams.len());
            assert!((1..=6).contains(&p.keys.len()));
            if p.delivery {
                delivery += 1;
                assert_eq!(p.keys.len(), 1);
                assert!(p.capacity >= 1 && p.budget == DELIVERY_BUDGET && p.lifetime == 0);
                assert!(p.streams[0].len() <= p.max_segment * DELIVERY_SEGMENTS);
            }
        }
        assert!((150..350).contains(&delivery), "{delivery}");
        // The same seed and count draw the same inputs; another seed others.
        let sha = |fam: &str, seed| fuzz_tcp(fam, seed, &c, |n, _| n >= 60).unwrap().sha256;
        assert_eq!(sha("stack", 9), sha("stack", 9));
        assert_ne!(sha("stack", 9), sha("stack", 10));
        assert_eq!(sha("http", 9), sha("http", 9));
        assert!(TcpInputs::new(1, "smb", &c).is_err());
        assert!(
            TcpInputs::new(1, "ftp", &[]).is_err(),
            "no seed for the family"
        );
    }

    /// A parser that reads only its first segment: the split changes the result as soon as there are two.
    fn first_segment_only(
        s: &TcpBannerSettings,
        port: u16,
        force: Option<u16>,
        segs: &[&[u8]],
    ) -> StreamResult {
        banner_stream(s, port, force, &segs[..segs.len().min(1)])
    }
    /// A stack whose records count the server's data segments: the split shows in delivery inputs.
    #[derive(Debug)]
    struct Counting(Arc<dyn TcpStackFactory>);
    struct CountingStack {
        inner: Box<dyn TcpStack>,
        data: usize,
    }
    impl CountingStack {
        fn mark(&self, out: &mut StackOutput, from: usize) {
            for set in &mut out.banners[from..] {
                if let Some(r) = set.first_mut() {
                    r.payload = format!("{} data segments", self.data).into_bytes();
                }
            }
        }
    }
    impl TcpStack for CountingStack {
        fn on_tick(&mut self, now: u64, out: &mut StackOutput) {
            let from = out.banners.len();
            self.inner.on_tick(now, out);
            self.mark(out, from);
        }
        fn on_segment(&mut self, now: u64, seg: &SegmentIn<'_>, out: &mut StackOutput) -> bool {
            self.data += usize::from(!seg.payload.is_empty());
            let from = out.banners.len();
            let took = self.inner.on_segment(now, seg, out);
            self.mark(out, from);
            took
        }
        fn finish(&mut self, max: usize, out: &mut StackOutput) -> bool {
            let from = out.banners.len();
            let more = self.inner.finish(max, out);
            self.mark(out, from);
            more
        }
        fn stats(&self) -> StackStats {
            self.inner.stats()
        }
    }
    impl TcpStackFactory for Counting {
        fn new_table(&self, p: TableParams) -> Box<dyn TcpStack> {
            Box::new(CountingStack {
                inner: self.0.new_table(p),
                data: 0,
            })
        }
    }
    fn counting_stack(s: TcpBannerSettings, t: u32) -> Arc<dyn TcpStackFactory> {
        Arc::new(Counting(tcp_stack_factory(s, t)))
    }

    /// R13: a parser whose result depends on the split, and a stack whose records do, are findings of kind `split`
    /// with their input; the product on the same input stream finds none.
    #[test]
    fn split_invariant_violation_is_a_finding() {
        let c = tcp_corpus();
        let fake = Target {
            stream: first_segment_only,
            ..Target::PRODUCT
        };
        let o = fuzz_tcp_with("ftp", 3, &c, fake, rss_kib, |n, _| n >= 300).unwrap();
        assert!(o.split_mismatches > 20, "{}", o.split_mismatches);
        assert_eq!((o.crashes, o.invariant_failures), (0, 0));
        assert_eq!(o.verdict().exit_code(), 1);
        let f = o.findings.iter().find(|f| f.kind == "split").unwrap();
        let TcpInput::Stream(s) = &f.input else {
            panic!("a stream input");
        };
        assert!(
            s.split.len() > 1 && f.what.starts_with(&format!("{} segments: ", s.split.len())),
            "{}",
            f.what
        );
        // The finding is its own reproducer: the fake parser on its split differs from the whole stream.
        let st = settings(s.capture_html);
        assert_ne!(
            first_segment_only(&st, s.port, s.force_app, &s.segments()),
            banner_stream(&st, s.port, s.force_app, &whole_of(&s.stream))
        );
        let rep = tcp_report(3, "300 inputs", &c, &o);
        assert_eq!(rep["split_mismatches"], o.split_mismatches);
        let j = rep["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|j| j["kind"] == "split")
            .unwrap();
        assert_eq!(j["input"], hex(&s.stream));
        assert_eq!(j["split"].as_array().unwrap().len(), s.split.len());
        assert!(tcp_summary(3, &o).ends_with(": FINDINGS"));
        let p = fuzz_tcp("ftp", 3, &c, |n, _| n >= 300).unwrap();
        assert_eq!(p.sha256, o.sha256, "the same inputs");
        assert_no_findings(&p);

        let fake = Target {
            stack: counting_stack,
            ..Target::PRODUCT
        };
        let o = fuzz_tcp_with("stack", 4, &c, fake, rss_kib, |n, _| n >= 200).unwrap();
        assert!(
            o.split_mismatches > 5,
            "{} {:?}",
            o.split_mismatches,
            o.stats
        );
        assert_eq!(
            (o.crashes, o.invariant_failures),
            (0, 0),
            "{:#?}",
            o.findings
        );
        let f = o.findings.iter().find(|f| f.kind == "split").unwrap();
        assert!(
            f.what.contains("data segments against the whole stream's"),
            "{}",
            f.what
        );
        assert!(f.events.iter().any(|e| e.text().starts_with("segment ")));
        let TcpInput::Stack(plan) = &f.input else {
            panic!("a stack input");
        };
        assert!(plan.delivery);
        let j = &tcp_report(4, "200 inputs", &c, &o)["findings"][0];
        assert!(
            j["events"].as_array().is_some_and(|e| !e.is_empty()) && j["plan"]["delivery"] == true
        );
        let p = fuzz_tcp("stack", 4, &c, |n, _| n >= 200).unwrap();
        assert_eq!(p.sha256, o.sha256);
        assert_no_findings(&p);
        assert!(p.stats.delivered_compared > 20, "{:?}", p.stats);
    }

    /// R13 for the actions: exact, except Telnet (answers per call: the same last answer per option) and Minecraft
    /// (closes per call: the whole stream's close is the split's too); records and the application always exact.
    #[test]
    fn per_call_actions_of_telnet_and_minecraft_follow_their_rule() {
        use StreamAction::{Close, Send};
        let r = |app: u16, actions: Vec<StreamAction>| StreamResult {
            app_proto: Some(app),
            records: vec![(app, b"x".to_vec())],
            actions,
        };
        let t = app_id::TELNET;
        let whole = r(t, vec![Send(vec![255, 252, 1, 255, 254, 3])]);
        let regrouped = r(
            t,
            vec![
                Send(vec![255, 254, 1]),
                Send(vec![255, 252, 1]),
                Send(vec![255, 254, 3]),
            ],
        );
        assert_eq!(split_problem(&whole, &regrouped), None);
        for bad in [
            vec![Send(vec![255, 252, 1]), Send(vec![255, 252, 3])],
            vec![Send(vec![255, 252, 1])],
            vec![Send(vec![255, 254, 3, 255, 252, 1])],
            vec![Send(vec![255, 252])],
            vec![Send(vec![255, 251, 1]), Send(vec![255, 254, 3])],
        ] {
            assert!(
                split_problem(&whole, &r(t, bad.clone())).is_some(),
                "{bad:?}"
            );
        }
        let mut other = regrouped.clone();
        other.records[0].1.push(b'y');
        assert!(
            split_problem(&whole, &other)
                .unwrap()
                .starts_with("records: ")
        );
        let mc = app_id::MC;
        assert_eq!(
            split_problem(&r(mc, vec![Close]), &r(mc, vec![Close, Close])),
            None
        );
        assert_eq!(split_problem(&r(mc, vec![]), &r(mc, vec![Close])), None);
        assert!(split_problem(&r(mc, vec![Close]), &r(mc, vec![])).is_some());
        assert!(split_problem(&r(mc, vec![Close]), &r(mc, vec![Close, Send(vec![1])])).is_some());
        // Every other parser: the actions exactly.
        let f = app_id::FTP;
        assert!(split_problem(&r(f, vec![Close]), &r(f, vec![Close, Close])).is_some());
        assert!(
            split_problem(&r(f, vec![Send(b"AUTH TLS\r\n".to_vec())]), &r(f, vec![])).is_some()
        );
        assert_eq!(split_problem(&r(f, vec![Close]), &r(f, vec![Close])), None);
    }

    fn panics(_: &TcpBannerSettings, _: u16, _: Option<u16>, segs: &[&[u8]]) -> StreamResult {
        assert!(segs.len() < 3, "a fake parser fails on three segments");
        StreamResult {
            app_proto: None,
            records: Vec::new(),
            actions: Vec::new(),
        }
    }
    fn oversized(_: &TcpBannerSettings, _: u16, _: Option<u16>, _: &[&[u8]]) -> StreamResult {
        StreamResult {
            app_proto: Some(app_id::FTP),
            records: vec![(app_id::FTP, vec![b'x'; MAX_BANNER_BYTES + 1])],
            actions: Vec::new(),
        }
    }
    /// A stack that answers every SYN-ACK with a SYN, which C's stack never sends.
    #[derive(Debug)]
    struct Syn(Arc<dyn TcpStackFactory>);
    struct SynStack(Box<dyn TcpStack>);
    impl TcpStack for SynStack {
        fn on_tick(&mut self, now: u64, out: &mut StackOutput) {
            self.0.on_tick(now, out);
        }
        fn on_segment(&mut self, now: u64, seg: &SegmentIn<'_>, out: &mut StackOutput) -> bool {
            let took = self.0.on_segment(now, seg, out);
            if seg.flags == SYN_ACK
                && let Some(s) = out.segments.first_mut()
            {
                s.flags = 0x02;
            }
            took
        }
        fn finish(&mut self, max: usize, out: &mut StackOutput) -> bool {
            self.0.finish(max, out)
        }
        fn stats(&self) -> StackStats {
            self.0.stats()
        }
    }
    impl TcpStackFactory for Syn {
        fn new_table(&self, p: TableParams) -> Box<dyn TcpStack> {
            Box::new(SynStack(self.0.new_table(p)))
        }
    }
    fn syn_stack(s: TcpBannerSettings, t: u32) -> Arc<dyn TcpStackFactory> {
        Arc::new(Syn(tcp_stack_factory(s, t)))
    }

    /// A stack that takes no in-order data of 1 or 2 bytes: no ACK, no parse (the reviewer's mutation of the Data step
    /// of `tcp/stack.rs`), or panics on its third segment.
    struct Faulty {
        inner: Box<dyn TcpStack>,
        small: bool,
        calls: usize,
    }
    impl TcpStack for Faulty {
        fn on_tick(&mut self, now: u64, out: &mut StackOutput) {
            self.inner.on_tick(now, out);
        }
        fn on_segment(&mut self, now: u64, seg: &SegmentIn<'_>, out: &mut StackOutput) -> bool {
            self.calls += 1;
            assert!(self.small || self.calls < 3, "the third segment");
            if self.small && (1..=2).contains(&seg.payload.len()) {
                return false;
            }
            self.inner.on_segment(now, seg, out)
        }
        fn finish(&mut self, max: usize, out: &mut StackOutput) -> bool {
            self.inner.finish(max, out)
        }
        fn stats(&self) -> StackStats {
            self.inner.stats()
        }
    }
    #[derive(Debug)]
    struct FaultyFactory(Arc<dyn TcpStackFactory>, bool);
    impl TcpStackFactory for FaultyFactory {
        fn new_table(&self, p: TableParams) -> Box<dyn TcpStack> {
            Box::new(Faulty {
                inner: self.0.new_table(p),
                small: self.1,
                calls: 0,
            })
        }
    }
    fn small_dropping_stack(s: TcpBannerSettings, t: u32) -> Arc<dyn TcpStackFactory> {
        Arc::new(FaultyFactory(tcp_stack_factory(s, t), true))
    }
    fn panicking_stack(s: TcpBannerSettings, t: u32) -> Arc<dyn TcpStackFactory> {
        Arc::new(FaultyFactory(tcp_stack_factory(s, t), false))
    }
    /// A stack that never shows the data its timer sends (the queue behind the head stays with it): the data
    /// segments of every tick are dropped on the way out.
    struct Hoard(Box<dyn TcpStack>);
    impl TcpStack for Hoard {
        fn on_tick(&mut self, now: u64, out: &mut StackOutput) {
            self.0.on_tick(now, out);
            out.segments.retain(|s| s.payload.is_empty());
        }
        fn on_segment(&mut self, now: u64, seg: &SegmentIn<'_>, out: &mut StackOutput) -> bool {
            self.0.on_segment(now, seg, out)
        }
        fn finish(&mut self, max: usize, out: &mut StackOutput) -> bool {
            self.0.finish(max, out)
        }
        fn stats(&self) -> StackStats {
            self.0.stats()
        }
    }
    #[derive(Debug)]
    struct HoardFactory(Arc<dyn TcpStackFactory>);
    impl TcpStackFactory for HoardFactory {
        fn new_table(&self, p: TableParams) -> Box<dyn TcpStack> {
            Box::new(Hoard(self.0.new_table(p)))
        }
    }
    fn hoarding_stack(s: TcpBannerSettings, t: u32) -> Arc<dyn TcpStackFactory> {
        Arc::new(HoardFactory(tcp_stack_factory(s, t)))
    }
    fn bad_telnet(_: &TcpBannerSettings, _: u16, _: Option<u16>, _: &[&[u8]]) -> StreamResult {
        StreamResult {
            app_proto: Some(app_id::TELNET),
            records: vec![(app_id::TELNET, b"x".to_vec())],
            actions: vec![StreamAction::Send(vec![255, 252])],
        }
    }

    /// I1: a stack that never ACKs in-order data (so the delivery stops short) is a finding of the stack family, not
    /// an uncounted "incomplete" delivery; the product on the same inputs is clean and stalls only where C itself
    /// drops data.
    #[test]
    fn a_stack_that_never_acks_in_order_data_is_a_finding() {
        let c = tcp_corpus();
        let o = fuzz_tcp_with(
            "stack",
            11,
            &c,
            Target {
                stack: small_dropping_stack,
                ..Target::PRODUCT
            },
            rss_kib,
            |n, _| n >= 3000,
        )
        .unwrap();
        assert!(o.invariant_failures > 20, "{:?}", o.stats);
        assert_eq!((o.crashes, o.split_mismatches), (0, 0));
        assert_eq!(o.verdict().exit_code(), 1);
        let f = o.findings.iter().find(|f| f.kind == "invariant").unwrap();
        assert!(
            f.what.starts_with("the stack stopped taking in-order data"),
            "{}",
            f.what
        );
        let p = fuzz_tcp("stack", 11, &c, |n, _| n >= 3000).unwrap();
        assert_eq!(p.sha256, o.sha256);
        assert_no_findings(&p);
        assert!(p.stats.delivered_incomplete > 0, "{:?}", p.stats);
    }

    /// A run of the product with the real resident-set probe has no finding of any kind. Its verdict is CLEAN where
    /// the probe reads the resident set (`/proc` on Linux, `ps` on macOS); on Windows (neither) a run past the
    /// warm-up is "memory not measured", a state of its own (exit 2), not a finding (4b acceptance, guest gate).
    fn assert_no_findings(o: &TcpOutcome) {
        assert_eq!(
            (o.crashes, o.slow, o.invariant_failures, o.split_mismatches),
            (0, 0, 0, 0),
            "{:#?}",
            o.findings
        );
        assert!(o.findings.is_empty(), "{:#?}", o.findings);
        let want = if memory_measured(o.inputs, &o.rss) {
            Verdict::Clean
        } else {
            Verdict::MemoryNotMeasured
        };
        assert_eq!(o.verdict(), want, "rss {:?}", o.rss);
    }

    /// A delivery that stalls because the scanner still holds data of its own it has not sent is C's rule, not a
    /// finding (4b acceptance, `stack` seed 413): each SSH packet of the stream queues the parser's KEX blob, C sends
    /// the head at once and the rest one segment per timeout as the head is ACKed (`src/stack-tcp-core.c:1405-1412`,
    /// `:1290-1312`), and in `ESTABLISHED_SEND` drops the server's data (`:2053-2076`). The stall is counted. A stack
    /// that keeps its queued data and never sends it stalls the same way and is a finding.
    #[test]
    fn a_stall_on_the_scanners_own_unsent_data_is_c_and_a_hoarded_queue_is_a_finding() {
        let mut stream = b"SSH-2.0-x\r\n".to_vec();
        for _ in 0..20 {
            stream.extend_from_slice(b"\x00\x00\x00\x08\x04\x14abcde");
        }
        let plan = StackPlan {
            delivery: true,
            lifetime: 0,
            capacity: 1,
            budget: DELIVERY_BUDGET,
            table_seed: 7,
            script: 2,
            events: 0,
            max_segment: 1460,
            capture_html: false,
            keys: vec![stack_key(0, 22, false)],
            streams: vec![stream],
        };
        let c = check_stack(&Target::PRODUCT, &plan);
        assert!(c.problem.is_none() && c.own_queue, "{:?}", c.problem);
        assert_eq!(c.delivered, Some(Delivered::Incomplete));
        let h = check_stack(
            &Target {
                stack: hoarding_stack,
                ..Target::PRODUCT
            },
            &plan,
        );
        let (kind, what) = h.problem.expect("a hoarding stack is a finding");
        assert_eq!(kind, "invariant");
        assert!(
            what.starts_with("the stack stopped taking in-order data")
                && what.ends_with("moved nothing, and a timeout shows no unsent data of its own"),
            "{what}"
        );
        assert!(!h.own_queue);
        // The report counts such stalls.
        let mut o = TcpOutcome::default();
        o.stats.delivered_own_queue = 3;
        assert_eq!(
            tcp_report(1, "1 input", &tcp_corpus(), &o)["stats"]["delivered"]["stalled_on_own_queue"],
            3
        );
    }

    /// M1 to M4 of the review: a finding carries its input index; a stack crash keeps its events; a malformed reply of
    /// the parser on the whole stream is an invariant, not a split mismatch; the budget is the whole-stream run, the
    /// split run is reported apart.
    #[test]
    fn findings_carry_index_events_and_a_label_of_their_own() {
        let c = tcp_corpus();
        let o = fuzz_tcp_with(
            "stack",
            4,
            &c,
            Target {
                stack: panicking_stack,
                ..Target::PRODUCT
            },
            rss_kib,
            |n, _| n >= 100,
        )
        .unwrap();
        let f = o.findings.iter().find(|f| f.kind == "crash").unwrap();
        assert!(f.index >= 1 && f.index <= 100, "{}", f.index);
        assert!(
            f.events.len() >= 3 && matches!(f.events.last(), Some(StackEvent::Segment { .. })),
            "{} {:?}",
            f.what,
            f.events.len()
        );
        let j = &tcp_report(4, "100 inputs", &c, &o)["findings"][0];
        assert_eq!(j["index"], o.findings[0].index);
        assert!(j["events"].as_array().is_some_and(|e| e.len() >= 3));
        let o = fuzz_tcp_with(
            "telnet",
            5,
            &c,
            Target {
                stream: bad_telnet,
                ..Target::PRODUCT
            },
            rss_kib,
            |n, _| n >= 50,
        )
        .unwrap();
        assert_eq!((o.split_mismatches, o.invariant_failures), (0, 50));
        assert!(
            o.findings[0]
                .what
                .starts_with("the whole stream: a telnet reply of 2 bytes"),
            "{}",
            o.findings[0].what
        );
        let p = fuzz_tcp("http", 5, &c, |n, _| n >= 50).unwrap();
        assert!(
            p.stats.max_split_ns > 0 && p.stats.max_ns > 0,
            "{:?}",
            p.stats
        );
        assert!(tcp_report(5, "50", &c, &p)["stats"]["max_split_us"].is_u64());
    }

    #[test]
    fn tcp_crashes_and_broken_invariants_are_findings() {
        let c = tcp_corpus();
        let run = |fam, t: Target| fuzz_tcp_with(fam, 6, &c, t, rss_kib, |n, _| n >= 100).unwrap();
        let o = run(
            "http",
            Target {
                stream: panics,
                ..Target::PRODUCT
            },
        );
        assert!(o.crashes > 10, "{}", o.crashes);
        assert!(
            o.findings
                .iter()
                .any(|f| f.kind == "crash" && f.what.contains(" segments: "))
        );
        assert_eq!(o.verdict().exit_code(), 1);
        let o = run(
            "framework",
            Target {
                stream: oversized,
                ..Target::PRODUCT
            },
        );
        assert_eq!(o.invariant_failures, 100);
        assert!(
            o.findings[0].what.contains("a record of 65537 bytes"),
            "{}",
            o.findings[0].what
        );
        let o = run(
            "stack",
            Target {
                stack: syn_stack,
                ..Target::PRODUCT
            },
        );
        assert!(o.invariant_failures > 30, "{}", o.invariant_failures);
        assert!(
            o.findings
                .iter()
                .all(|f| f.what == "a segment with flags 0x02"),
            "{:#?}",
            o.findings
        );
        assert_eq!(
            records_problem(&[(0, b"x".to_vec())]),
            Some("a record of application 0".into())
        );
        assert_eq!(
            records_problem(&[(app_id::FTP, Vec::new())]),
            Some("a record of 0 bytes".into())
        );
        assert_eq!(
            records_problem(&[(app_id::ERROR, vec![1; MAX_BANNER_BYTES])]),
            None
        );
    }

    #[test]
    fn tcp_arguments() {
        let a = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        for bad in [
            &["tcp", "--seed", "1", "--count", "5"][..],
            &["tcp", "--family", "smb", "--seed", "1", "--count", "5"],
            &[
                "tcp", "--family", "ftp", "smtp", "--seed", "1", "--count", "5",
            ],
            &["tcp", "--family", "ftp", "--seed", "1"],
            &[
                "tcp",
                "--family",
                "ftp",
                "--seed",
                "1",
                "--count",
                "5",
                "--duration",
                "5",
            ],
            &[
                "tcp", "--family", "ftp", "--seed", "1", "--count", "5", "--port", "21",
            ],
        ] {
            assert!(run(&a(bad)).is_err(), "{bad:?}");
        }
        let udp = golden_dir().display().to_string();
        assert!(
            run(&a(&[
                "tcp", "--family", "ftp", "--seed", "1", "--count", "5", "--corpus", &udp
            ]))
            .is_err()
        );
        let dir = std::env::temp_dir().join(format!("rmasscan-fuzz-tcp-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let out = dir.join("fuzz.json");
        let golden = tcp_golden_dir().display().to_string();
        let args = [
            "tcp",
            "--family",
            "stack",
            "--seed",
            "1",
            "--count",
            "20",
            "--corpus",
            &golden,
            "--out",
            out.to_str().unwrap(),
        ];
        assert_eq!(run(&a(&args)), Ok(0));
        let rep: Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
        assert_eq!(
            (
                &rep["tool"],
                &rep["family"],
                &rep["inputs"],
                &rep["verdict"]
            ),
            (
                &json!("rmasscan-lab fuzz tcp"),
                &json!("stack"),
                &json!(20),
                &json!("CLEAN")
            )
        );
        assert!(rep["corpus"]["golden"].as_u64() > Some(200));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The short mode of R15 for 4b: ten seconds over the thirteen TCP families find nothing, and every family gets
    /// past its parser's first checks (records, sends and closes; the stack creates connections, sends, flushes and
    /// compares delivered streams with the framework).
    #[test]
    fn fuzz_short_mode_all_tcp_families() {
        let c = tcp_corpus();
        let each = Duration::from_secs(10) / TCP_FAMILIES.len() as u32;
        for fam in TCP_FAMILIES {
            let o = fuzz_tcp(fam, 20261115, &c, |_, t| t >= each).unwrap();
            assert_eq!(
                (o.crashes, o.slow, o.invariant_failures, o.split_mismatches),
                (0, 0, 0, 0),
                "{fam}: {:#?}",
                o.findings
            );
            let s = &o.stats;
            eprintln!("{}; {s:?}", tcp_summary(20261115, &o));
            assert!(
                o.inputs >= 20 && s.with_records * 10 > o.inputs,
                "{fam}: {} inputs, {s:?}",
                o.inputs
            );
            if !matches!(fam, "http" | "rdp" | "memcached" | "framework") {
                assert!(s.with_actions > 0, "{fam}: {s:?}");
            }
            if fam == "stack" {
                assert!(
                    s.connections > o.inputs && s.with_actions > 0 && s.delivered_compared > 0,
                    "{s:?}"
                );
            }
        }
    }
}
