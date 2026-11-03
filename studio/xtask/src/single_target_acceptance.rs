//! Offline packet verification and the fixed root capture child entry point.
use rmasscan_core::probe::ProbeCursor;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::Path,
};
use studio_protocol::{
    NetworkReport,
    single_target::{Context, Permit},
};
type Result<T> = std::result::Result<T, String>;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stats {
    pub recorded: u64,
    pub received: u32,
    pub dropped: u32,
    pub interface_dropped: u32,
}
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct Verified {
    pub probes: usize,
    pub replies: usize,
    pub duplicate_replies: usize,
    pub kernel_resets: usize,
    pub arp_requests: usize,
    pub arp_replies: usize,
    pub background_arp: usize,
    pub unanswered_ports: Vec<u16>,
    pub results: BTreeMap<u16, bool>,
    pub first_probe_ns: Option<u64>,
    pub last_probe_ns: Option<u64>,
    pub minimum_gap_ns: Option<u64>,
}
pub fn verify(
    permit: &Permit,
    report: &NetworkReport,
    pcap: &[u8],
    stats: &Stats,
) -> Result<Verified> {
    // Offline structural context is not proof of root provenance or a live grant.
    permit.admit_report(
        report,
        &Context {
            now: permit.created,
            owner_uid: permit.owner_uid,
            tooling_sha256: &permit.tooling_sha256,
            helper_sha256: &permit.helper_sha256,
        },
    )?;
    let mac = *report
        .destinations
        .get(&permit.target)
        .ok_or("Target neighbour unresolved; no complete probe witness")?;
    let packets = super::network_acceptance::witness::frames(pcap)?;
    if packets.len() > 1024
        || stats.recorded != packets.len() as u64
        || stats.dropped != 0
        || stats.interface_dropped != 0
        || (stats.received as usize) < packets.len()
    {
        return Err("Capture drops, inconsistent statistics or packet budget exceeded".into());
    }
    let start = permit
        .created
        .checked_mul(1_000_000_000)
        .ok_or("Invalid permit capture time")?;
    let end = permit
        .expires
        .checked_mul(1_000_000_000)
        .ok_or("Invalid permit capture time")?;
    let plan = permit.job().prepare_network(report)?;
    let mut expected = ProbeCursor::new(&plan, 0).map_err(|e| e.to_string())?;
    let mut seen = BTreeSet::new();
    let mut out = Verified::default();
    for packet in packets {
        if packet.time_ns < start || packet.time_ns >= end {
            return Err("Packet outside permit lifetime".into());
        }
        match classify(packet.frame, permit, mac)? {
            Frame::ArpRequest => {
                out.arp_requests += 1;
            }
            Frame::ArpReply => {
                if out.arp_requests == 0 {
                    return Err("Next-hop ARP reply precedes the observed request".into());
                }
                out.arp_replies += 1;
            }
            Frame::BackgroundArp => out.background_arp += 1,
            Frame::Syn { port, sequence } => {
                if out.arp_requests == 0 || out.arp_replies == 0 {
                    return Err("TCP probe precedes witnessed next-hop resolution".into());
                }
                let probe = expected.current().ok_or("Extra or duplicate TCP probe")?;
                if port != probe.port_them || sequence != probe.seqno || !seen.insert(port) {
                    return Err(
                        "TCP probe order, cookie or uniqueness differs from permitted job".into(),
                    );
                }
                if let Some(previous) = out.last_probe_ns {
                    let gap = packet.time_ns - previous;
                    // Capture timestamps allow 50 ms measurement tolerance at 1 pps.
                    if gap < 950_000_000 {
                        return Err("Captured probe spacing below 950ms at configured 1pps".into());
                    }
                    out.minimum_gap_ns = Some(out.minimum_gap_ns.map_or(gap, |old| old.min(gap)));
                }
                out.first_probe_ns.get_or_insert(packet.time_ns);
                out.last_probe_ns = Some(packet.time_ns);
                out.probes += 1;
                expected.advance_sent();
            }
            Frame::Reply {
                port,
                sequence,
                open,
            } => {
                if !seen.contains(&port) || sequence != cookie(permit, port) {
                    return Err("Uncorrelated TCP response".into());
                }
                if let Some(prior) = out.results.insert(port, open) {
                    if prior != open {
                        return Err("Conflicting TCP states for one permitted port".into());
                    }
                    out.duplicate_replies += 1;
                } else {
                    out.replies += 1;
                }
            }
            Frame::Reset { port, sequence } => {
                if out.results.get(&port) != Some(&true)
                    || sequence != cookie(permit, port).wrapping_add(1)
                {
                    return Err("Uncorrelated outgoing kernel reset".into());
                }
                out.kernel_resets += 1;
            }
        }
    }
    if expected.current().is_some() || out.probes != permit.ports.len() {
        return Err("Incomplete single-target probe capture".into());
    }
    out.unanswered_ports = permit
        .ports
        .iter()
        .copied()
        .filter(|p| !out.results.contains_key(p))
        .collect();
    Ok(out)
}
#[derive(Debug)]
enum Frame {
    ArpRequest,
    ArpReply,
    BackgroundArp,
    Syn {
        port: u16,
        sequence: u32,
    },
    Reply {
        port: u16,
        sequence: u32,
        open: bool,
    },
    Reset {
        port: u16,
        sequence: u32,
    },
}
fn word(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn dword(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|p| u32::from(p[0]) * 256 + u32::from(*p.get(1).unwrap_or(&0)))
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn cookie(p: &Permit, port: u16) -> u32 {
    rmasscan_core::cookie::syn_cookie_ipv4(
        p.target.into(),
        u32::from(port),
        p.interface.source_ipv4.into(),
        40000,
        p.seed,
    ) as u32
}
fn options(mut bytes: &[u8], tcp: bool) -> Result<()> {
    while let Some(&kind) = bytes.first() {
        match kind {
            0 => {
                return if bytes.iter().skip(1).all(|b| *b == 0) {
                    Ok(())
                } else {
                    Err("Nonzero option padding after EOL".into())
                };
            }
            1 => bytes = &bytes[1..],
            _ => {
                let size = usize::from(*bytes.get(1).ok_or("Truncated option length")?);
                if size < 2 || size > bytes.len() {
                    return Err("Invalid option length".into());
                }
                if tcp
                    && match kind {
                        2 => size != 4,
                        3 => size != 3,
                        4 => size != 2,
                        5 => size < 10 || !(size - 2).is_multiple_of(8),
                        8 => size != 10,
                        _ => false,
                    }
                {
                    return Err("Malformed known TCP option length".into());
                }
                bytes = &bytes[size..];
            }
        }
    }
    Ok(())
}
fn classify(f: &[u8], p: &Permit, hop_mac: [u8; 6]) -> Result<Frame> {
    if f.len() < 14 {
        return Err("Truncated Ethernet frame".into());
    }
    let source_mac = p.interface.source_mac;
    if f[12..14] == [8, 6] {
        if !(42..=60).contains(&f.len())
            || f[14..20] != [0, 1, 8, 0, 6, 4]
            || ![1, 2].contains(&word(&f[20..22]))
        {
            return Err("Malformed captured ARP".into());
        }
        if f[6..12] != source_mac && f[..6] != source_mac {
            return Err("ARP outside local capture scope".into());
        }
        let sender = &f[28..32];
        let target = &f[38..42];
        let source = p.interface.source_ipv4.octets();
        let hop = p.interface.next_hop.octets();
        if sender == source && target == hop && word(&f[20..22]) == 1 {
            if f[..6] != [255; 6]
                || f[6..12] != source_mac
                || f[22..28] != source_mac
                || f[32..38] != [0; 6]
            {
                return Err("Unexpected next-hop ARP request identity".into());
            }
            return Ok(Frame::ArpRequest);
        }
        if sender == hop && target == source && word(&f[20..22]) == 2 {
            if f[..6] != source_mac
                || f[6..12] != hop_mac
                || f[22..28] != hop_mac
                || f[32..38] != source_mac
            {
                return Err("Next-hop ARP reply disagrees with frozen route report".into());
            }
            return Ok(Frame::ArpReply);
        }
        return Ok(Frame::BackgroundArp);
    }
    if f[12..14] != [8, 0] || f.len() < 34 || f[14] >> 4 != 4 {
        return Err("Non-IPv4 frame in TCP capture scope".into());
    }
    let ihl = usize::from(f[14] & 15) * 4;
    let tcp = 14 + ihl;
    let end = 14 + usize::from(word(&f[16..18]));
    if !(20..=60).contains(&ihl)
        || end < tcp + 20
        || end > f.len()
        || f.len() > end.max(60)
        || word(&f[20..22]) & 0xbfff != 0
        || f[23] != 6
        || f[22] == 0
        || checksum(&f[14..tcp]) != 0
    {
        return Err("Malformed, fragmented or truncated IPv4 TCP packet".into());
    }
    options(&f[34..tcp], false)?;
    let thl = usize::from(f[tcp + 12] >> 4) * 4;
    if !(20..=60).contains(&thl)
        || tcp + thl != end
        || f[tcp + 12] & 15 != 0
        || word(&f[tcp + 18..tcp + 20]) != 0
    {
        return Err("Unexpected TCP header, payload or reserved bits".into());
    }
    options(&f[tcp + 20..end], true)?;
    let mut pseudo = f[26..34].to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&((end - tcp) as u16).to_be_bytes());
    pseudo.extend_from_slice(&f[tcp..end]);
    if checksum(&pseudo) != 0 {
        return Err("Invalid captured TCP checksum".into());
    }
    let source = p.interface.source_ipv4.octets();
    let target = p.target.octets();
    let flags = f[tcp + 13];
    let sequence = dword(&f[tcp + 4..tcp + 8]);
    if f[26..30] == source {
        let port = word(&f[tcp + 2..tcp + 4]);
        if f[30..34] != target
            || f[6..12] != source_mac
            || f[..6] != hop_mac
            || word(&f[tcp..tcp + 2]) != 40000
            || !p.ports.contains(&port)
            || dword(&f[tcp + 8..tcp + 12]) != 0
            || ihl != 20
        {
            return Err("Outgoing TCP tuple or MAC outside permit".into());
        }
        return match flags {
            2 if thl == 24 && f[tcp + 20..end] == [2, 4, 5, 180] => {
                Ok(Frame::Syn { port, sequence })
            }
            4 if thl == 20 && word(&f[tcp + 14..tcp + 16]) == 0 => {
                Ok(Frame::Reset { port, sequence })
            }
            _ => Err("Unexpected outgoing TCP flags/options".into()),
        };
    }
    let port = word(&f[tcp..tcp + 2]);
    if f[26..30] != target
        || f[30..34] != source
        || f[..6] != source_mac
        || f[6..12] != hop_mac
        || word(&f[tcp + 2..tcp + 4]) != 40000
        || !p.ports.contains(&port)
        || ![0x12, 0x14].contains(&flags)
    {
        return Err("Response tuple, MAC or flags outside permit".into());
    }
    Ok(Frame::Reply {
        port,
        sequence: dword(&f[tcp + 8..tcp + 12]).wrapping_sub(1),
        open: flags == 0x12,
    })
}
fn read(path: &str, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(Path::new(path))
        .map_err(|e| e.to_string())?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("Evidence file exceeds size bound".into());
    }
    Ok(bytes)
}
pub fn main_entry() -> super::Result<()> {
    let args: Vec<_> = std::env::args().skip(2).collect();
    #[cfg(target_os = "macos")]
    if let [action, evidence, report] = args.as_slice()
        && action == "verify-evidence"
    {
        let bytes = read(
            evidence,
            super::network_acceptance::witness::MAX_CAPTURE + 16385,
        )?;
        let report = NetworkReport::decode(&read(report, studio_protocol::MAX_NETWORK_BLOB)?)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&verify_evidence(&bytes, &report)?)?
        );
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    if let [action, uid, generation] = args.as_slice()
        && action == "capture"
    {
        let result = studio_platform::single_target::recording::run(uid.parse()?, generation)?;
        println!("{}", serde_json::to_string(&result)?);
        if result.measurements.error.is_some() {
            return Err("Capture failed; partial root evidence retained".into());
        }
        return Ok(());
    }
    let [action, permit, report, pcap, stats] = args.as_slice() else {
        return Err(
            "Usage: single-target-acceptance verify PERMIT.json REPORT.bin CAPTURE.pcap STATS.json | verify-evidence EXPORT.bin REPORT.bin | capture UID GENERATION (installed root child only)"
                .into(),
        );
    };
    if action != "verify" {
        return Err("Unknown single-target acceptance command".into());
    }
    let permit: Permit = serde_json::from_slice(&read(permit, 16384)?)?;
    let report = NetworkReport::decode(&read(report, studio_protocol::MAX_NETWORK_BLOB)?)?;
    let stats: Stats = serde_json::from_slice(&read(stats, 4096)?)?;
    let result = verify(
        &permit,
        &report,
        &read(pcap, super::network_acceptance::witness::MAX_CAPTURE)?,
        &stats,
    )?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
#[cfg(target_os = "macos")]
fn verify_evidence(bytes: &[u8], report: &NetworkReport) -> Result<Verified> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Metadata {
        permit: Permit,
        completion: studio_platform::single_target::CaptureCompletion,
    }
    let boundary = bytes
        .iter()
        .take(16385)
        .position(|b| *b == b'\n')
        .ok_or("Missing or oversized capture metadata header")?;
    let metadata: Metadata =
        serde_json::from_slice(&bytes[..boundary]).map_err(|e| e.to_string())?;
    let pcap = &bytes[boundary + 1..];
    metadata
        .completion
        .validate_export(&metadata.permit, pcap)?;
    // Completion has second resolution: include its final second, never the
    // following second. Buffered background packets may predate publication;
    // scanner SYNs must not predate the readiness second.
    let end = metadata
        .completion
        .finished
        .checked_add(1)
        .and_then(|t| t.checked_mul(1_000_000_000))
        .ok_or("Capture completion time overflow")?;
    let ready = metadata
        .completion
        .witness
        .created
        .checked_mul(1_000_000_000)
        .ok_or("Capture readiness time overflow")?;
    for packet in super::network_acceptance::witness::frames(pcap)? {
        if packet.time_ns >= end {
            return Err("Packet occurs after capture completion".into());
        }
    }
    let measurements = &metadata.completion.measurements;
    if measurements.error.is_some() {
        return Err("Capture producer reported failure; evidence cannot pass".into());
    }
    let stats = measurements
        .statistics
        .as_ref()
        .ok_or("Missing capture statistics")?;
    let verified = verify(
        &metadata.permit,
        report,
        pcap,
        &Stats {
            recorded: measurements.recorded,
            received: stats.received,
            dropped: stats.dropped,
            interface_dropped: stats.interface_dropped,
        },
    )?;
    if verified.first_probe_ns.is_some_and(|first| first < ready) {
        return Err("Probe precedes capture readiness".into());
    }
    Ok(verified)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> (Permit, NetworkReport, Vec<Vec<u8>>) {
        let p = Permit {
            version: 1,
            generation: "1".repeat(32),
            owner_uid: 501,
            created: 1000,
            expires: 1300,
            tooling_sha256: "a".repeat(64),
            helper_sha256: "b".repeat(64),
            target: "45.33.32.156".parse().unwrap(),
            ports: vec![22, 80, 443, 65535],
            seed: 42,
            interface: studio_protocol::single_target::InterfaceBinding {
                name: "en0".into(),
                index: 5,
                source_ipv4: "10.0.0.2".parse().unwrap(),
                source_mac: [2, 1, 2, 3, 4, 5],
                next_hop: "10.0.0.1".parse().unwrap(),
            },
        };
        let r = NetworkReport {
            job_digest: p.job().original_digest().unwrap(),
            routes: p.plan(),
            destinations: [(p.target, [2, 6, 7, 8, 9, 10])].into(),
            unresolved: vec![],
        };
        let plan = p.job().prepare_network(&r).unwrap();
        let mut cursor = ProbeCursor::new(&plan, 0).unwrap();
        let mut frames = Vec::new();
        while let Some(probe) = cursor.current() {
            frames.push(probe.frame.clone());
            cursor.advance_sent();
        }
        (p, r, frames)
    }
    fn arp(reply: bool) -> Vec<u8> {
        let (p, r, _) = setup();
        let own = p.interface.source_mac;
        let hop = r.destinations[&p.target];
        let mut f = vec![0; 60];
        f[..6].copy_from_slice(&if reply { own } else { [255; 6] });
        f[6..12].copy_from_slice(&if reply { hop } else { own });
        f[12..14].copy_from_slice(&[8, 6]);
        f[14..20].copy_from_slice(&[0, 1, 8, 0, 6, 4]);
        f[20..22].copy_from_slice(&(if reply { 2u16 } else { 1 }).to_be_bytes());
        f[22..28].copy_from_slice(&if reply { hop } else { own });
        f[28..32].copy_from_slice(&if reply {
            p.interface.next_hop.octets()
        } else {
            p.interface.source_ipv4.octets()
        });
        f[32..38].copy_from_slice(&if reply { own } else { [0; 6] });
        f[38..42].copy_from_slice(&if reply {
            p.interface.source_ipv4.octets()
        } else {
            p.interface.next_hop.octets()
        });
        f
    }
    fn pcap(frames: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0,
        ];
        let mut records = vec![
            (1_000_000_000_000, arp(false)),
            (1_000_050_000_000, arp(true)),
        ];
        records.extend_from_slice(frames);
        for (ns, frame) in &records {
            out.extend_from_slice(&((*ns / 1_000_000_000) as u32).to_le_bytes());
            out.extend_from_slice(&(((*ns % 1_000_000_000) / 1000) as u32).to_le_bytes());
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(frame);
        }
        out
    }
    fn stats(n: usize) -> Stats {
        Stats {
            recorded: (n + 2) as u64,
            received: (n + 2) as u32,
            dropped: 0,
            interface_dropped: 0,
        }
    }
    fn spaced(frames: &[Vec<u8>]) -> Vec<(u64, Vec<u8>)> {
        frames
            .iter()
            .enumerate()
            .map(|(n, f)| ((1001 + n as u64) * 1_000_000_000, f.clone()))
            .collect()
    }
    fn sum(bytes: &[u8]) -> u16 {
        let mut n: u32 = bytes
            .chunks(2)
            .map(|p| u32::from(p[0]) * 256 + u32::from(*p.get(1).unwrap_or(&0)))
            .sum();
        while n > 65535 {
            n = (n & 65535) + (n >> 16);
        }
        !(n as u16)
    }
    fn repair(f: &mut [u8]) {
        let ihl = usize::from(f[14] & 15) * 4;
        let tcp = 14 + ihl;
        let end = 14 + usize::from(u16::from_be_bytes([f[16], f[17]]));
        f[24..26].fill(0);
        let checksum = sum(&f[14..tcp]);
        f[24..26].copy_from_slice(&checksum.to_be_bytes());
        f[tcp + 16..tcp + 18].fill(0);
        let mut pseudo = f[26..34].to_vec();
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&((end - tcp) as u16).to_be_bytes());
        pseudo.extend_from_slice(&f[tcp..end]);
        let checksum = sum(&pseudo);
        f[tcp + 16..tcp + 18].copy_from_slice(&checksum.to_be_bytes());
    }
    fn reply(syn: &[u8], open: bool, options: bool) -> Vec<u8> {
        let ihl = if options { 24 } else { 20 };
        let thl = if options { 32 } else { 20 };
        let end = 14 + ihl + thl;
        let mut f = vec![0; end.max(60)];
        f[..6].copy_from_slice(&syn[6..12]);
        f[6..12].copy_from_slice(&syn[..6]);
        f[12..14].copy_from_slice(&[8, 0]);
        f[14] = 0x40 + (ihl / 4) as u8;
        f[16..18].copy_from_slice(&((ihl + thl) as u16).to_be_bytes());
        f[22] = 52;
        f[23] = 6;
        f[26..30].copy_from_slice(&syn[30..34]);
        f[30..34].copy_from_slice(&syn[26..30]);
        if options {
            f[34..38].copy_from_slice(&[1, 1, 1, 0]);
        }
        let t = 14 + ihl;
        f[t..t + 2].copy_from_slice(&syn[36..38]);
        f[t + 2..t + 4].copy_from_slice(&syn[34..36]);
        f[t + 4..t + 8].copy_from_slice(&123u32.to_be_bytes());
        let cookie = u32::from_be_bytes(syn[38..42].try_into().unwrap());
        f[t + 8..t + 12].copy_from_slice(&cookie.wrapping_add(1).to_be_bytes());
        f[t + 12] = (thl / 4) as u8 * 16;
        f[t + 13] = if open { 0x12 } else { 0x14 };
        f[t + 14..t + 16].copy_from_slice(&4096u16.to_be_bytes());
        if options {
            f[t + 20..t + 32].copy_from_slice(&[2, 4, 5, 180, 1, 1, 4, 2, 1, 1, 1, 0]);
        }
        repair(&mut f);
        f
    }
    #[test]
    fn complete_silent_capture_has_no_invented_port_states() {
        let (p, r, f) = setup();
        let out = verify(&p, &r, &pcap(&spaced(&f)), &stats(f.len())).unwrap();
        assert_eq!(out.probes, 4);
        assert_eq!(out.replies, 0);
        assert!(out.results.is_empty());
        assert_eq!(out.unanswered_ports, p.ports);
        assert_eq!(out.minimum_gap_ns, Some(1_000_000_000));
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn export_envelope_checks_hash_identity_failure_and_exact_packet_results() {
        use sha2::{Digest, Sha256};
        use studio_platform::single_target::{
            CaptureCompletion, CaptureFinish, CaptureStatistics, CaptureWitness,
        };
        let hash = |bytes: &[u8]| {
            Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        let (permit, report, frames) = setup();
        let bytes = pcap(&spaced(&frames));
        let count = super::super::network_acceptance::witness::frames(&bytes)
            .unwrap()
            .len();
        let completion = CaptureCompletion {
            witness: CaptureWitness {
                generation: permit.generation.clone(),
                nonce: "2".repeat(32),
                permit_sha256: hash(&serde_json::to_vec(&permit).unwrap()),
                created: 1000,
                process: studio_platform::unix::Identity {
                    uid: 0,
                    pid: 123,
                    birth: [1, 2],
                    executable: studio_platform::macos::installed_path(&permit.tooling_sha256)
                        .unwrap(),
                },
                lease_file: [1, 2],
            },
            finished: 1006,
            measurements: CaptureFinish {
                elapsed_millis: 6000,
                recorded: count as u64,
                statistics: Some(CaptureStatistics {
                    received: count as u32,
                    dropped: 0,
                    interface_dropped: 0,
                }),
                error: None,
            },
            pcap_bytes: bytes.len() as u64,
            pcap_sha256: hash(&bytes),
        };
        let envelope = |c: &CaptureCompletion, p: &Permit, pcap: &[u8]| {
            let mut out =
                serde_json::to_vec(&serde_json::json!({"permit":p,"completion":c})).unwrap();
            out.push(b'\n');
            out.extend_from_slice(pcap);
            out
        };
        let result = verify_evidence(&envelope(&completion, &permit, &bytes), &report).unwrap();
        assert_eq!(result.probes, 4);
        assert!(result.results.is_empty());
        for kind in 0..7 {
            let mut bad = completion.clone();
            match kind {
                0 => bad.pcap_sha256 = "0".repeat(64),
                1 => bad.witness.permit_sha256 = "0".repeat(64),
                2 => bad.measurements.error = Some("control lost".into()),
                3 => bad.measurements.statistics.as_mut().unwrap().dropped = 1,
                4 => bad.measurements.recorded += 1,
                5 => {
                    bad.finished = 1001;
                    bad.measurements.elapsed_millis = 1000;
                }
                _ => {
                    bad.witness.created = 1002;
                }
            };
            assert!(verify_evidence(&envelope(&bad, &permit, &bytes), &report).is_err());
        }
        assert!(verify_evidence(&vec![b'x'; 16385], &report).is_err());
    }
    #[test]
    fn correlated_replies_with_options_and_duplicates_have_exact_unique_states() {
        let (p, r, f) = setup();
        let mut records = spaced(&f);
        let a = reply(&f[0], true, true);
        let b = reply(&f[1], false, false);
        records.push((1_001_100_000_000, a.clone()));
        records.push((1_001_200_000_000, a));
        records.push((1_002_100_000_000, b));
        records.sort_by_key(|(t, _)| *t);
        let out = verify(&p, &r, &pcap(&records), &stats(records.len())).unwrap();
        assert_eq!(out.replies, 2);
        assert_eq!(out.duplicate_replies, 1);
        assert_eq!(out.unanswered_ports.len(), 2);
        assert!(out.results[&u16::from_be_bytes(f[0][36..38].try_into().unwrap())]);
        assert!(!out.results[&u16::from_be_bytes(f[1][36..38].try_into().unwrap())]);
    }
    #[test]
    fn next_hop_witness_exact_capture_length_and_permit_window_are_required() {
        let (p, r, f) = setup();
        let bytes = pcap(&spaced(&f));
        // Remove both ARP records while keeping an otherwise complete TCP scan.
        let mut without_arp = bytes[..24].to_vec();
        without_arp.extend_from_slice(&bytes[24 + 2 * (16 + 60)..]);
        let mut st = stats(f.len());
        st.recorded -= 2;
        st.received -= 2;
        assert!(verify(&p, &r, &without_arp, &st).is_err());
        let mut mismatch = stats(f.len());
        mismatch.recorded += 1;
        assert!(verify(&p, &r, &bytes, &mismatch).is_err());
        let mut wrong_mac = bytes.clone();
        wrong_mac[24 + 16 + 60 + 16 + 22] ^= 1;
        assert!(verify(&p, &r, &wrong_mac, &stats(f.len())).is_err());
        let mut short = p.clone();
        short.expires = 1003;
        assert!(verify(&short, &r, &bytes, &stats(f.len())).is_err());
    }
    #[test]
    fn kernel_reset_requires_a_prior_correlated_open_reply() {
        let (p, r, f) = setup();
        let mut reset = f[0].clone();
        reset[16..18].copy_from_slice(&40u16.to_be_bytes());
        reset[46] = 0x50;
        reset[47] = 4;
        reset[48..50].fill(0);
        reset[54..].fill(0);
        let sequence = u32::from_be_bytes(reset[38..42].try_into().unwrap()).wrapping_add(1);
        reset[38..42].copy_from_slice(&sequence.to_be_bytes());
        repair(&mut reset);
        let mut records = spaced(&f);
        records.push((1_001_200_000_000, reset));
        records.sort_by_key(|(t, _)| *t);
        assert!(verify(&p, &r, &pcap(&records), &stats(records.len())).is_err());
        records.push((1_001_100_000_000, reply(&f[0], true, false)));
        records.sort_by_key(|(t, _)| *t);
        assert_eq!(
            verify(&p, &r, &pcap(&records), &stats(records.len()))
                .unwrap()
                .kernel_resets,
            1
        );
    }
    #[test]
    fn malformed_known_tcp_option_lengths_are_not_credited_as_responses() {
        let (p, r, f) = setup();
        for (kind, size) in [(2, 2), (3, 2), (4, 3), (5, 3), (8, 2)] {
            let mut response = reply(&f[0], true, true);
            let tcp = 14 + usize::from(response[14] & 15) * 4;
            response[tcp + 20..tcp + 32].fill(1);
            response[tcp + 20] = kind;
            response[tcp + 21] = size;
            repair(&mut response);
            let mut records = spaced(&f);
            records.push((1_001_100_000_000, response));
            records.sort_by_key(|(t, _)| *t);
            assert!(
                verify(&p, &r, &pcap(&records), &stats(records.len())).is_err(),
                "TCP option {kind}/{size} was accepted"
            );
        }
    }
    #[test]
    fn incomplete_duplicate_reordered_fast_or_corrupt_probes_are_rejected() {
        let (p, r, f) = setup();
        let normal = spaced(&f);
        let mut cases = vec![normal[..3].to_vec()];
        let mut duplicate = normal.clone();
        duplicate.push((1_005_000_000_000, f[0].clone()));
        cases.push(duplicate);
        let mut swapped = normal.clone();
        swapped[0].1 = f[1].clone();
        swapped[1].1 = f[0].clone();
        cases.push(swapped);
        let mut fast = normal.clone();
        fast[1].0 = fast[0].0 + 500_000_000;
        cases.push(fast);
        for offset in [0, 6, 26, 30, 36, 38, 47, 50] {
            let mut bad = normal.clone();
            bad[0].1[offset] ^= 1;
            if offset != 50 {
                repair(&mut bad[0].1);
            }
            cases.push(bad);
        }
        for case in cases {
            assert!(verify(&p, &r, &pcap(&case), &stats(case.len())).is_err());
        }
    }
    #[test]
    fn foreign_early_fragmented_or_corrupt_replies_and_capture_loss_fail() {
        let (p, r, f) = setup();
        for kind in 0..5 {
            let mut response = reply(&f[0], true, false);
            let mut when = 1_001_100_000_000;
            match kind {
                0 => when = 1_000_100_000_000,
                1 => response[42] ^= 1,
                2 => response[26] ^= 1,
                3 => response[20] |= 0x20,
                _ => response[47] = 0x10,
            };
            repair(&mut response);
            let mut records = spaced(&f);
            records.push((when, response));
            records.sort_by_key(|(t, _)| *t);
            assert!(verify(&p, &r, &pcap(&records), &stats(records.len())).is_err());
        }
        let bytes = pcap(&spaced(&f));
        assert!(verify(&p, &r, &bytes[..bytes.len() - 1], &stats(f.len())).is_err());
        let mut lost = stats(f.len());
        lost.dropped = 1;
        assert!(verify(&p, &r, &bytes, &lost).is_err());
    }
}
