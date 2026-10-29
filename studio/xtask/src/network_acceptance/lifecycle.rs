//! Offline consistency checks. Files alone never authenticate capture provenance.
use super::{topology::*, wire, witness};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use studio_protocol::{Id, NetworkReport, Row, Status};

pub const QUIET_NS: u64 = 2_000_000_000;
pub const CLOCK_ERROR_NS: u64 = 5_000_000;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stamp {
    pub wall_ns: u64,
    pub mono_ns: u64,
    pub uncertainty_ns: u64,
}
impl Stamp {
    pub fn now(origin: Instant) -> Result<Self, String> {
        let before = origin.elapsed().as_nanos();
        let wall_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let after = origin.elapsed().as_nanos();
        Ok(Self {
            wall_ns: wall_ns.try_into().map_err(|_| "clock overflow")?,
            mono_ns: after.try_into().map_err(|_| "clock overflow")?,
            uncertainty_ns: (after - before).try_into().map_err(|_| "clock overflow")?,
        })
    }
    pub fn low(&self) -> Result<u64, String> {
        self.wall_ns
            .checked_sub(self.uncertainty_ns + CLOCK_ERROR_NS)
            .ok_or("clock underflow".into())
    }
    pub fn high(&self) -> Result<u64, String> {
        self.wall_ns
            .checked_add(self.uncertainty_ns + CLOCK_ERROR_NS)
            .ok_or("clock overflow".into())
    }
}
pub fn clocks(stamps: &[Stamp]) -> Result<(), String> {
    for s in stamps {
        if s.uncertainty_ns > CLOCK_ERROR_NS {
            return Err("ambiguous clock sample".into());
        }
        s.low()?;
        s.high()?;
    }
    if let Some(first) = stamps.first() {
        for last in stamps.iter().skip(1) {
            let wall = last
                .wall_ns
                .checked_sub(first.wall_ns)
                .ok_or("wall clock reversed")?;
            let mono = last
                .mono_ns
                .checked_sub(first.mono_ns)
                .ok_or("monotonic clock reversed")?;
            if wall.abs_diff(mono) > CLOCK_ERROR_NS {
                return Err("cumulative wall/monotonic divergence".into());
            }
        }
    }
    for p in stamps.windows(2) {
        let wall = p[1]
            .wall_ns
            .checked_sub(p[0].wall_ns)
            .ok_or("wall clock reversed")?;
        let mono = p[1]
            .mono_ns
            .checked_sub(p[0].mono_ns)
            .ok_or("monotonic clock reversed")?;
        if wall.abs_diff(mono) > CLOCK_ERROR_NS {
            return Err("wall/monotonic clock divergence".into());
        }
    }
    Ok(())
}
/// Independent sampling continues during Controller/native blocking operations.
pub struct Sampler {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<Result<Vec<Stamp>, String>>>,
    origin: Instant,
}
impl Sampler {
    pub fn start(origin: Instant, first: Stamp) -> Self {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut samples = vec![first];
            while !flag.load(std::sync::atomic::Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(50));
                samples.push(Stamp::now(origin)?);
            }
            Ok(samples)
        });
        Self {
            stop,
            worker: Some(worker),
            origin,
        }
    }
    pub fn finish(mut self) -> Result<(Stamp, Vec<Stamp>), String> {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        let mut samples = self
            .worker
            .take()
            .ok_or("missing clock worker")?
            .join()
            .map_err(|_| "clock worker panic")??;
        let final_stamp = Stamp::now(self.origin)?;
        samples.push(final_stamp.clone());
        Ok((final_stamp, samples))
    }
}
impl Drop for Sampler {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(t) = self.worker.take() {
            let _ = t.join();
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ticket {
    pub nonce: String,
    pub case: String,
    pub seal_generation: String,
    pub tooling_sha256: String,
    pub runner_sha256: String,
    pub ready: Stamp,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attempt {
    pub ticket: Ticket,
    pub driver_pid: u32,
    pub driver_uid: u32,
    pub process_identity: String,
    pub driver_started: Stamp,
    pub start: Stamp,
    pub control: Option<Stamp>,
    pub terminal: Stamp,
    pub joined: Stamp,
    pub samples: Vec<Stamp>,
    pub scan: Id,
    pub attempt: Id,
    pub status: Status,
    pub report: Option<Vec<u8>>,
    pub checkpoint: Option<Vec<u8>>,
    pub next_index: Option<String>,
    pub rows: Vec<Row>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Window {
    pub ticket: Ticket,
    pub opened: Stamp,
    pub stopped: Stamp,
    pub samples: Vec<Stamp>,
    pub children_clean: bool,
    pub peer_drops: Option<u64>,
}
pub struct Input<'a> {
    pub attempt: &'a Attempt,
    pub window: &'a Window,
    pub peer: &'a [u8],
    pub peer_stats: &'a str,
    pub uplink: &'a [u8],
    pub uplink_stats: &'a str,
}
#[derive(Debug)]
pub struct Checked {
    pub probes: Vec<wire::Syn>,
    pub replies: BTreeSet<wire::Syn>,
    pub cursor: u64,
}
pub fn verify(input: Input<'_>, previous: Option<(&Attempt, &Checked)>) -> Result<Checked, String> {
    let Input {
        attempt: a,
        window: w,
        peer,
        peer_stats,
        uplink,
        uplink_stats,
    } = input;
    if a.ticket != w.ticket
        || !w.children_clean
        || w.peer_drops != Some(0)
        || a.driver_pid == 0
        || a.driver_uid == 0
        || a.process_identity.trim().is_empty()
    {
        return Err("capture provenance/owned child health mismatch".into());
    }
    for (s, n) in [
        (&a.ticket.nonce, 32),
        (&a.ticket.seal_generation, 32),
        (&a.ticket.tooling_sha256, 64),
        (&a.ticket.runner_sha256, 64),
    ] {
        if s.len() != n || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("invalid ticket identity/hash".into());
        }
    }
    clocks(&[
        a.driver_started.clone(),
        a.start.clone(),
        a.terminal.clone(),
        a.joined.clone(),
    ])?;
    clocks(&a.samples)?;
    clocks(&[w.opened.clone(), w.ticket.ready.clone(), w.stopped.clone()])?;
    clocks(&w.samples)?;
    if a.samples.first() != Some(&a.driver_started)
        || a.samples.last() != Some(&a.joined)
        || w.samples.first() != Some(&w.opened)
        || w.samples.last() != Some(&w.stopped)
        || a.samples
            .windows(2)
            .any(|p| p[1].mono_ns - p[0].mono_ns > 1_000_000_000)
        || w.samples
            .windows(2)
            .any(|p| p[1].mono_ns - p[0].mono_ns > 1_000_000_000)
        || w.ticket.ready.high()? >= a.start.low()?
        || a.joined
            .high()?
            .max(a.terminal.high()?)
            .checked_add(QUIET_NS)
            .ok_or("time overflow")?
            >= w.stopped.low()?
        || w.stopped.mono_ns - w.opened.mono_ns > 120_000_000_000
    {
        return Err("wrong capture window, missing clock samples or quiet interval".into());
    }
    let case = a.ticket.case.as_str();
    let expected = match case {
        "complete" | "resume" => Status::Completed,
        "pause" => Status::Paused,
        "stop-preparing" | "stop-running" => Status::Stopped,
        "guard" => Status::Interrupted,
        _ => return Err("unknown lifecycle case".into()),
    };
    if a.status != expected {
        return Err("wrong terminal status".into());
    }
    if matches!(case, "pause" | "stop-preparing" | "stop-running" | "guard") {
        let c = a
            .control
            .as_ref()
            .ok_or("missing explicit control/guard phase")?;
        clocks(&[a.start.clone(), c.clone(), a.terminal.clone()])?;
    } else if a.control.is_some() {
        return Err("unexpected control action".into());
    }
    let packets = witness::frames(peer)?;
    if witness::stats(peer_stats)? != packets.len() as u64 {
        return Err("capture count mismatch".into());
    }
    if witness::stats(uplink_stats)? != 0 || !witness::frames(uplink)?.is_empty() {
        return Err("ISOLATION BREACH: lab frame on uplink".into());
    }
    let mut probes = Vec::new();
    let mut replies = BTreeSet::new();
    let mut resets = BTreeSet::new();
    let mut arp = std::collections::BTreeMap::<_, Vec<u64>>::new();
    let mut first_syn = None;
    let mut before_control = 0;
    for p in packets {
        // Classic pcap has at most microsecond quantisation; also apply the
        // explicitly bounded clock error. Overlap is ambiguity, never grace.
        let lo = p.time_ns.saturating_sub(CLOCK_ERROR_NS + 1000);
        let hi = p
            .time_ns
            .checked_add(CLOCK_ERROR_NS + 1000)
            .ok_or("packet time overflow")?;
        if lo <= w.opened.high()? || hi >= w.stopped.low()? {
            return Err("packet outside capture window or ambiguous clock".into());
        }
        let frame = wire::classify(p.frame)?;
        if matches!(frame, wire::Frame::Syn(_) | wire::Frame::ArpRequest(_))
            && (lo <= a.start.high()? || hi >= a.terminal.low()?)
        {
            return Err(
                "scanner packet before Start or at/after terminal (or ambiguous clock)".into(),
            );
        }
        match frame {
            wire::Frame::Syn(s) => {
                if a.control
                    .as_ref()
                    .is_some_and(|c| c.low().is_ok_and(|t| hi < t))
                {
                    before_control += 1;
                }
                first_syn.get_or_insert(p.time_ns);
                probes.push(s);
            }
            wire::Frame::Response(s) => {
                if !probes.contains(&s) || !replies.insert(s) {
                    return Err("uncorrelated/duplicate response".into());
                }
            }
            wire::Frame::KernelReset(s) => {
                if !replies.contains(&s) || !resets.insert(s) {
                    return Err("uncorrelated/duplicate kernel reset".into());
                }
            }
            wire::Frame::ArpRequest(ip) => arp.entry(ip).or_default().push(p.time_ns),
            _ => {}
        }
    }
    if case == "stop-preparing" {
        if !probes.is_empty()
            || !a.rows.is_empty()
            || a.checkpoint.is_some()
            || a.next_index.is_some()
            || previous.is_some()
        {
            return Err("preparation Stop has TCP/checkpoint/previous attempt".into());
        }
        if let Some(bytes) = &a.report {
            validate_report(&NetworkReport::decode(bytes)?)?;
        }
        if arp.values().any(|v| v.len() > 3) {
            return Err("preparation ARP count exceeds bounded retries".into());
        }
        return Ok(Checked {
            probes,
            replies,
            cursor: 0,
        });
    }
    if matches!(case, "pause" | "stop-running" | "guard") && before_control < 4 {
        return Err("control phase lacks four earlier captured probes (or ambiguous clock)".into());
    }
    let report = NetworkReport::decode(a.report.as_deref().ok_or("missing frozen report")?)?;
    validate_report(&report)?;
    let plan = job().prepare_network(&report)?;
    let start = if case == "resume" {
        let (old, checked) =
            previous.ok_or("Resume needs independently verified paused capture")?;
        if old.ticket.case != "pause"
            || old.scan != a.scan
            || old.attempt == a.attempt
            || old.driver_pid == a.driver_pid
            || old.report != a.report
            || old.ticket.nonce == a.ticket.nonce
            || old.ticket.seal_generation != a.ticket.seal_generation
            || old.ticket.tooling_sha256 != a.ticket.tooling_sha256
            || old.ticket.runner_sha256 != a.ticket.runner_sha256
            || old.joined.high()? >= a.driver_started.low()?
        {
            return Err("Resume scan/attempt/process/frozen provenance mismatch".into());
        }
        checked.cursor
    } else {
        if previous.is_some() {
            return Err("unexpected prior attempt".into());
        }
        0
    };
    let mut cursor =
        rmasscan_core::probe::ProbeCursor::new(&plan, start).map_err(|e| e.to_string())?;
    for syn in &probes {
        let p = cursor.current().ok_or("too many probes")?;
        if syn.target != std::net::Ipv4Addr::from(p.ip_them)
            || syn.port != p.port_them
            || syn.sequence != p.seqno
        {
            return Err("probe prefix has duplicate/gap/order/cookie mismatch".into());
        }
        cursor.advance_sent();
    }
    let end = cursor.position();
    if matches!(case, "complete" | "resume") {
        if end != 96
            || replies.len() != probes.len()
            || a.checkpoint.is_some()
            || a.next_index.is_some()
        {
            return Err("incomplete completed/cumulative witness".into());
        }
    } else if !(4..96).contains(&end) {
        return Err("partial case is not a bounded nonempty prefix".into());
    }
    if case == "pause" {
        let bytes = a
            .checkpoint
            .as_deref()
            .ok_or("Pause lacks durable checkpoint")?;
        studio_protocol::validate_checkpoint(
            &job(),
            a.scan,
            a.attempt,
            bytes,
            a.next_index.as_deref().ok_or("Pause lacks index")?,
        )?;
        let envelope = studio_protocol::NetworkCheckpoint::decode(bytes)?;
        let cp =
            rmasscan_engine::Checkpoint::from_bytes(&envelope.engine).map_err(|e| e.to_string())?;
        if cp.next_index != end || envelope.report != report {
            return Err("paused cursor/frozen map differs from packets".into());
        }
    } else if a.checkpoint.is_some() || a.next_index.is_some() {
        return Err("unexpected checkpoint".into());
    }
    for hop in [A, B, GATEWAY] {
        if !arp.get(&hop).is_some_and(|v| (1..=3).contains(&v.len())) {
            return Err("missing eligible neighbour ARP".into());
        }
    }
    if case == "resume" {
        if arp.len() != 3 {
            return Err("Resume rescanned formerly missing neighbour".into());
        }
    } else {
        let times = arp.get(&MISSING).ok_or("missing unresolved ARP witness")?;
        if arp.len() != 4
            || times.len() != 3
            || times.windows(2).any(|p| p[1] - p[0] < 1_000_000_000)
            || first_syn.unwrap_or(0) < times[2] + 1_000_000_000
        {
            return Err("missing-neighbour retry/answer window differs".into());
        }
    }
    let mut allowed = replies
        .iter()
        .map(|s| (s.target.to_string(), s.port))
        .collect::<BTreeSet<_>>();
    if let Some((old, _)) = previous {
        allowed.extend(old.rows.iter().map(|r| (r.ip.clone(), r.port)));
    }
    let mut rows = BTreeSet::new();
    for row in &a.rows {
        let key = (row.ip.clone(), row.port);
        if !allowed.contains(&key) || row.open != (row.port % 2 == 0) || !rows.insert(key) {
            return Err("retained result not correlated to captured response".into());
        }
    }
    if a.rows.is_empty() || (matches!(case, "complete" | "resume") && a.rows.len() != 96) {
        return Err("missing retained/completed results".into());
    }
    if let Some((old, _)) = previous
        && old
            .rows
            .iter()
            .any(|r| !rows.contains(&(r.ip.clone(), r.port)))
    {
        return Err("Resume lost paused rows".into());
    }
    Ok(Checked {
        probes,
        replies,
        cursor: end,
    })
}

#[cfg(all(test, target_os = "macos"))]
pub(super) fn sample_attempt(case: &str) -> (Attempt, Window) {
    tests::sample(case)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmasscan_core::probe::ProbeCursor;
    pub fn report() -> NetworkReport {
        use rmasscan_net::ExcludedReason::*;
        NetworkReport {
            job_digest: job().original_digest().unwrap(),
            routes: rmasscan_net::PhysicalRoutePlan {
                interface_name: SCANNER.into(),
                interface_index: 42,
                source_ipv4: SOURCE,
                source_mac: Some(SOURCE_MAC),
                next_hops: [(A, A), (B, B), (MISSING, MISSING), (ROUTED, GATEWAY)].into(),
                excluded: [
                    ("198.18.42.0".parse().unwrap(), NetworkAddress),
                    (SOURCE, OwnAddress),
                    ("198.18.42.7".parse().unwrap(), BroadcastAddress),
                ]
                .into(),
            },
            destinations: [(A, A_MAC), (B, B_MAC), (ROUTED, GATEWAY_MAC)].into(),
            unresolved: vec![MISSING],
        }
    }
    fn stamp(seconds: u64) -> Stamp {
        Stamp {
            wall_ns: (100 + seconds) * 1_000_000_000,
            mono_ns: seconds * 1_000_000_000,
            uncertainty_ns: 0,
        }
    }
    fn header() -> Vec<u8> {
        vec![
            0x4d, 0x3c, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 1, 0, 0, 0,
        ]
    }
    fn append(c: &mut Vec<u8>, time: u64, frame: &[u8]) {
        c.extend_from_slice(&((time / 1_000_000_000) as u32).to_le_bytes());
        c.extend_from_slice(&((time % 1_000_000_000) as u32).to_le_bytes());
        c.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        c.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        c.extend_from_slice(frame);
    }
    struct Fixture {
        a: Attempt,
        w: Window,
        p: Vec<u8>,
        u: Vec<u8>,
        stats: String,
    }
    impl Fixture {
        fn check(&self, prev: Option<(&Attempt, &Checked)>) -> Result<Checked, String> {
            verify(
                Input {
                    attempt: &self.a,
                    window: &self.w,
                    peer: &self.p,
                    peer_stats: &self.stats,
                    uplink: &self.u,
                    uplink_stats: "0 packets captured\n0 packets dropped by kernel",
                },
                prev,
            )
        }
    }
    fn fixture(case: &str, first: u64, end: u64) -> Fixture {
        let report = report();
        let plan = job().prepare_network(&report).unwrap();
        let mut cursor = ProbeCursor::new(&plan, first).unwrap();
        let ticket = Ticket {
            nonce: "1".repeat(32),
            case: case.into(),
            seal_generation: "2".repeat(32),
            tooling_sha256: "3".repeat(64),
            runner_sha256: "4".repeat(64),
            ready: stamp(1),
        };
        let mut p = header();
        let mut rows = Vec::new();
        let mut count = 0;
        if case != "stop-preparing" {
            for (s, ip) in [
                (3, A),
                (3, B),
                (3, GATEWAY),
                (3, MISSING),
                (4, MISSING),
                (5, MISSING),
            ] {
                if case == "resume" && ip == MISSING {
                    continue;
                }
                append(
                    &mut p,
                    stamp(s).wall_ns,
                    &rmasscan_core::arp::encode_request(SOURCE_MAC, SOURCE.into(), ip.into()),
                );
                count += 1;
            }
        }
        for i in first..end {
            let probe = cursor.current().unwrap();
            append(&mut p, stamp(7 + i - first).wall_ns, &probe.frame);
            append(
                &mut p,
                stamp(7 + i - first).wall_ns + 10_000,
                &wire::reply(&probe.frame).unwrap().unwrap(),
            );
            rows.push(Row {
                ip: std::net::Ipv4Addr::from(probe.ip_them).to_string(),
                port: probe.port_them,
                open: probe.port_them.is_multiple_of(2),
            });
            count += 2;
            cursor.advance_sent();
        }
        let terminal = stamp(8 + end - first);
        let status = match case {
            "pause" => Status::Paused,
            "complete" | "resume" => Status::Completed,
            "guard" => Status::Interrupted,
            _ => Status::Stopped,
        };
        let checkpoint = (case == "pause").then(|| {
            studio_protocol::NetworkCheckpoint {
                report: report.clone(),
                engine: rmasscan_engine::Checkpoint {
                    format_version: rmasscan_engine::CHECKPOINT_FORMAT_VERSION,
                    engine_version: studio_protocol::ENGINE_VERSION,
                    scan_id: [1; 16],
                    attempt_id: [2; 16],
                    job_digest: rmasscan_engine::job_digest(&plan),
                    next_index: end,
                }
                .to_bytes(),
            }
            .encode()
            .unwrap()
        });
        let a = Attempt {
            ticket: ticket.clone(),
            driver_pid: 123,
            driver_uid: 501,
            process_identity: "synthetic driver process".into(),
            driver_started: stamp(1),
            start: stamp(2),
            control: (!matches!(case, "complete" | "resume")).then(|| {
                stamp(if case == "stop-preparing" {
                    6
                } else {
                    7 + end - first
                })
            }),
            terminal: terminal.clone(),
            joined: stamp(9 + end - first),
            samples: (1..=9 + end - first).map(stamp).collect(),
            scan: [1; 16],
            attempt: [2; 16],
            status,
            report: (case != "stop-preparing").then(|| report.encode().unwrap()),
            checkpoint,
            next_index: (case == "pause").then(|| end.to_string()),
            rows,
        };
        let w = Window {
            ticket,
            opened: stamp(0),
            stopped: stamp(12 + end - first),
            samples: (0..=12 + end - first).map(stamp).collect(),
            children_clean: true,
            peer_drops: Some(0),
        };
        Fixture {
            a,
            w,
            p,
            u: header(),
            stats: format!("{count} packets captured\n0 packets dropped by kernel"),
        }
    }
    #[test]
    fn partial_prefix_and_checkpoint_are_required() {
        let f = fixture("pause", 0, 4);
        let result = f.check(None).unwrap();
        assert_eq!(result.cursor, 4);
        assert_eq!(result.probes.len(), 4);
    }
    #[test]
    fn stopped_preparation_and_running_guard_have_distinct_contracts() {
        assert_eq!(
            fixture("stop-preparing", 0, 0).check(None).unwrap().cursor,
            0
        );
        for case in ["stop-running", "guard"] {
            let mut f = fixture(case, 0, 4);
            assert_eq!(f.check(None).unwrap().cursor, 4);
            f.a.rows.clear();
            assert!(f.check(None).is_err());
        }
        assert!(fixture("stop-running", 0, 96).check(None).is_err());
        assert!(fixture("stop-preparing", 0, 1).check(None).is_err());
    }
    #[test]
    fn late_scanner_packet_and_ambiguous_clock_fail_but_late_response_is_allowed() {
        let mut f = fixture("pause", 0, 4);
        let packet = rmasscan_core::arp::encode_request(SOURCE_MAC, SOURCE.into(), A.into());
        append(&mut f.p, f.a.terminal.wall_ns + 100_000_000, &packet);
        f.stats = "15 packets captured\n0 packets dropped by kernel".into();
        assert!(f.check(None).unwrap_err().contains("terminal"));
        let mut f = fixture("pause", 0, 4);
        let last = f.p.len() - 76; // 16-byte record + 60-byte reply
        let t = f.a.terminal.wall_ns + 100_000_000;
        f.p[last..last + 4].copy_from_slice(&((t / 1_000_000_000) as u32).to_le_bytes());
        f.p[last + 4..last + 8].copy_from_slice(&((t % 1_000_000_000) as u32).to_le_bytes());
        assert!(
            f.check(None).is_ok(),
            "peer reply after terminal is not a new scanner probe"
        );
        let mut f = fixture("pause", 0, 4);
        f.a.terminal.wall_ns = stamp(10).wall_ns + 1_000;
        f.a.terminal.mono_ns = stamp(10).mono_ns + 1_000;
        f.a.control = Some(stamp(9));
        assert!(f.check(None).unwrap_err().contains("terminal"));
        let mut f = fixture("pause", 0, 4);
        f.w.samples[2].wall_ns += 10_000_000;
        assert!(f.check(None).is_err());
    }
    #[test]
    fn wrong_windows_drops_ticket_checkpoint_and_missing_duplicate_tuples_fail() {
        for change in [
            |f: &mut Fixture| f.w.ticket.nonce = "a".repeat(32),
            |f: &mut Fixture| f.w.stopped = stamp(13),
            |f: &mut Fixture| f.w.peer_drops = None,
            |f: &mut Fixture| f.w.children_clean = false,
            |f: &mut Fixture| f.stats = "14 packets captured\n1 packet dropped by kernel".into(),
            |f: &mut Fixture| f.a.next_index = Some("5".into()),
            |f: &mut Fixture| f.a.attempt = [9; 16],
            |f: &mut Fixture| {
                f.p.drain(24 + 6 * 76..24 + 8 * 76);
                f.stats = "12 packets captured\n0 packets dropped by kernel".into();
            },
            |f: &mut Fixture| {
                let start = 24 + 6 * 76;
                let bytes = f.p[start..start + 152].to_vec();
                f.p.splice(start..start, bytes);
                f.stats = "16 packets captured\n0 packets dropped by kernel".into();
            },
        ] {
            let mut f = fixture("pause", 0, 4);
            change(&mut f);
            assert!(f.check(None).is_err());
        }
    }
    fn shift(f: &mut Fixture, seconds: u64) {
        let delta = seconds * 1_000_000_000;
        let adjust = |s: &mut Stamp| s.wall_ns += delta;
        for s in [
            &mut f.a.driver_started,
            &mut f.a.start,
            &mut f.a.terminal,
            &mut f.a.joined,
            &mut f.a.ticket.ready,
            &mut f.w.opened,
            &mut f.w.stopped,
            &mut f.w.ticket.ready,
        ] {
            adjust(s);
        }
        if let Some(c) = &mut f.a.control {
            adjust(c);
        }
        for s in f.a.samples.iter_mut().chain(f.w.samples.iter_mut()) {
            adjust(s);
        }
        let mut offset = 24;
        while offset < f.p.len() {
            let second = u32::from_le_bytes(f.p[offset..offset + 4].try_into().unwrap());
            f.p[offset..offset + 4].copy_from_slice(&(second + seconds as u32).to_le_bytes());
            offset +=
                16 + u32::from_le_bytes(f.p[offset + 8..offset + 12].try_into().unwrap()) as usize;
        }
    }
    #[test]
    fn new_process_resume_preserves_frozen_map_and_covers_exact_cumulative_cursor() {
        let paused = fixture("pause", 0, 4);
        let checked = paused.check(None).unwrap();
        let resumed = || {
            let mut f = fixture("resume", 4, 96);
            f.a.attempt = [3; 16];
            f.a.driver_pid = 124;
            f.a.ticket.nonce = "5".repeat(32);
            f.w.ticket = f.a.ticket.clone();
            f.a.rows.extend(paused.a.rows.clone());
            shift(&mut f, 30);
            f
        };
        assert_eq!(
            resumed().check(Some((&paused.a, &checked))).unwrap().cursor,
            96
        );
        for change in [
            |f: &mut Fixture| f.a.attempt = [2; 16],
            |f: &mut Fixture| f.a.driver_pid = 123,
            |f: &mut Fixture| f.a.ticket.seal_generation = "6".repeat(32),
            |f: &mut Fixture| f.a.ticket.runner_sha256 = "7".repeat(64),
            |f: &mut Fixture| {
                f.a.rows.pop();
            },
            |f: &mut Fixture| {
                f.p.drain(24 + 3 * 76..24 + 5 * 76);
                f.stats = "185 packets captured\n0 packets dropped by kernel".into();
            },
        ] {
            let mut f = resumed();
            change(&mut f);
            assert!(f.check(Some((&paused.a, &checked))).is_err());
        }
        let mut wrong = fixture("resume", 3, 96);
        wrong.a.attempt = [3; 16];
        wrong.a.driver_pid = 124;
        wrong.a.ticket.nonce = "5".repeat(32);
        wrong.w.ticket = wrong.a.ticket.clone();
        shift(&mut wrong, 30);
        assert!(wrong.check(Some((&paused.a, &checked))).is_err());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn reopened_store_checkpoint_and_rows_match_partial_capture() {
        let _test_lock = super::super::TEST_PROCESS_LOCK.lock().unwrap();
        use studio_protocol::{Envelope, Event};
        let mut fixture = fixture("pause", 0, 4);
        let dir = std::env::temp_dir().join(format!(
            "witness-store-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        let mut store = studio_store::Store::open(&dir).unwrap();
        store
            .begin(fixture.a.scan, fixture.a.attempt, &job(), false)
            .unwrap();
        let events = [
            Event::NetworkPrepared {
                bytes: fixture.a.report.clone().unwrap(),
            },
            Event::Started { total: "96".into() },
            Event::Results(fixture.a.rows.clone()),
            Event::Checkpoint {
                bytes: fixture.a.checkpoint.clone().unwrap(),
                next_index: "4".into(),
            },
        ];
        for (n, event) in events.into_iter().enumerate() {
            store
                .apply(&Envelope::new(
                    [9; 16],
                    fixture.a.scan,
                    fixture.a.attempt,
                    n as u64 + 1,
                    event,
                ))
                .unwrap();
        }
        drop(store);
        let store = studio_store::Store::open(&dir).unwrap();
        let saved = store.scans().unwrap().remove(0);
        fixture.a.report = saved.network_report;
        fixture.a.checkpoint = saved.checkpoint;
        fixture.a.next_index = saved.next_index;
        fixture.a.rows = store.rows(saved.scan).unwrap();
        fixture.a.status = saved.status;
        assert_eq!(fixture.check(None).unwrap().cursor, 4);
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn independent_clock_sampler_brackets_blocking_work() {
        let origin = Instant::now();
        let first = Stamp::now(origin).unwrap();
        let sampler = Sampler::start(origin, first.clone());
        std::thread::sleep(std::time::Duration::from_millis(65));
        let (last, samples) = sampler.finish().unwrap();
        assert_eq!(samples.first(), Some(&first));
        assert_eq!(samples.last(), Some(&last));
        assert!(samples.len() >= 3);
        clocks(&samples).unwrap();
        let checked = fixture("pause", 0, 4).check(None).unwrap();
        assert_eq!(checked.replies.len(), 4);
    }
    #[cfg(target_os = "macos")]
    pub(super) fn sample(case: &str) -> (Attempt, Window) {
        let f = fixture(case, 0, 4);
        (f.a, f.w)
    }
}
