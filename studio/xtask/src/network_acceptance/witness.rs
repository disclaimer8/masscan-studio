//! Offline independent classic-pcap witness; malformed/incomplete evidence fails closed.
use super::{topology::*, wire};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_CAPTURE: usize = 16 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct Verified {
    pub probes: usize,
    pub kernel_resets: usize,
}

pub struct Captured<'a> {
    time_ns: u64,
    frame: &'a [u8],
}

pub fn frames(bytes: &[u8]) -> Result<Vec<Captured<'_>>, String> {
    if !(24..=MAX_CAPTURE).contains(&bytes.len()) {
        return Err("pcap missing header or exceeds16MiB limit".into());
    }
    let (little, nanos) = match bytes[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err("unsupported pcap magic".into()),
    };
    let u16at = |at: usize| {
        let b = [bytes[at], bytes[at + 1]];
        if little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }
    };
    let u32at = |at: usize| {
        let b = [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
        if little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        }
    };
    let snap = u32at(16);
    if u16at(4) != 2 || u16at(6) != 4 || !(60..=262144).contains(&snap) || u32at(20) != 1 {
        return Err("pcap version/snapshot/link type differs".into());
    }
    let mut offset = 24;
    let mut out = Vec::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 16 {
            return Err("truncated pcap record header".into());
        }
        let length = u32at(offset + 8) as usize;
        if length < 14
            || length > snap as usize
            || length != u32at(offset + 12) as usize
            || length > bytes.len() - offset - 16
            || u32at(offset + 4) >= if nanos { 1_000_000_000 } else { 1_000_000 }
        {
            return Err("truncated/invalid pcap record".into());
        }
        let time_ns = u64::from(u32at(offset)) * 1_000_000_000
            + u64::from(u32at(offset + 4)) * if nanos { 1 } else { 1000 };
        if out
            .last()
            .is_some_and(|prior: &Captured<'_>| prior.time_ns > time_ns)
        {
            return Err("capture time moved backwards".into());
        }
        offset += 16;
        out.push(Captured {
            time_ns,
            frame: &bytes[offset..offset + length],
        });
        offset += length;
        if out.len() > 20000 {
            return Err("pcap packet count exceeds fixture budget".into());
        }
    }
    Ok(out)
}

pub fn stats(text: &str) -> Result<u64, String> {
    let mut captured = None;
    let mut dropped = None;
    for line in text.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        if words.len() < 3 || !matches!(words[1], "packet" | "packets") {
            continue;
        }
        let value: u64 = words[0].parse().map_err(|_| "malformed tcpdump count")?;
        match &words[2..] {
            ["captured"] if captured.replace(value).is_none() => {}
            ["dropped", "by", "kernel"] if dropped.replace(value).is_none() => {}
            ["captured"] | ["dropped", "by", "kernel"] => {
                return Err("duplicate tcpdump statistics".into());
            }
            _ => {}
        }
    }
    match (captured, dropped) {
        (Some(n), Some(0)) => Ok(n),
        _ => Err("missing tcpdump statistics or capture drops".into()),
    }
}

pub fn verify(
    peer: &[u8],
    peer_stats: &str,
    uplink: &[u8],
    uplink_stats: &str,
) -> Result<Verified, String> {
    let peer = frames(peer)?;
    let uplink = frames(uplink)?;
    if stats(uplink_stats)? != 0 || !uplink.is_empty() {
        return Err("ISOLATION BREACH: lab frame on uplink".into());
    }
    if stats(peer_stats)? != peer.len() as u64 {
        return Err("peer capture count mismatch".into());
    }
    let mut probes = BTreeSet::new();
    let mut replies = BTreeSet::new();
    let mut requests = BTreeMap::new();
    let mut missing_times = Vec::new();
    let mut first_syn = None;
    let mut resets = BTreeSet::new();
    for packet in peer {
        match wire::classify(packet.frame)? {
            wire::Frame::ArpRequest(target) => {
                *requests.entry(target).or_insert(0usize) += 1;
                if target == MISSING {
                    missing_times.push(packet.time_ns);
                }
            }
            wire::Frame::Response(s) => {
                if !probes.contains(&s) || !replies.insert(s) {
                    return Err("uncorrelated or duplicate TCP response in capture".into());
                }
            }
            wire::Frame::Syn(s) => {
                first_syn.get_or_insert(packet.time_ns);
                let cookie = rmasscan_core::cookie::syn_cookie_ipv4(
                    s.target.into(),
                    u32::from(s.port),
                    SOURCE.into(),
                    40000,
                    42,
                ) as u32;
                if s.sequence != cookie {
                    return Err("probe cookie differs from fixed job".into());
                }
                if !probes.insert(s) {
                    return Err("duplicate SYN in completed acceptance window".into());
                }
            }
            wire::Frame::KernelReset(s) => {
                if !replies.contains(&s) || !resets.insert(s) {
                    return Err("uncorrelated or duplicate kernel reset".into());
                }
            }
            wire::Frame::ArpReply(_) | wire::Frame::Unrelated | wire::Frame::KernelMulticast => {}
        }
    }
    if probes.len() != 3 * usize::from(PORT_LAST - PORT_FIRST + 1) {
        return Err("incomplete direct/routed SYN witness".into());
    }
    if replies != probes {
        return Err("SYN/result reply correspondence incomplete".into());
    }
    if requests.get(&MISSING) != Some(&3)
        || [A, B, GATEWAY]
            .iter()
            .any(|ip| !requests.get(ip).is_some_and(|n| (1..=3).contains(n)))
        || requests.len() != 4
    {
        return Err("missing or unexpected next-hop ARP request witness".into());
    }
    if missing_times
        .windows(2)
        .any(|p| p[1] - p[0] < 1_000_000_000)
        || first_syn.unwrap_or(0) < missing_times[2] + 1_000_000_000
    {
        return Err(
            "missing neighbour retries/last response window shorter than one second".into(),
        );
    }
    Ok(Verified {
        probes: probes.len(),
        kernel_resets: resets.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn header() -> Vec<u8> {
        vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ]
    }
    #[test]
    fn malformed_truncated_or_non_ethernet_capture_is_refused() {
        assert!(frames(&header()).unwrap().is_empty());
        for n in 0..24 {
            assert!(frames(&header()[..n]).is_err());
        }
        let mut wrong = header();
        wrong[20] = 0;
        assert!(frames(&wrong).is_err());
        let mut truncated = header();
        truncated.extend_from_slice(&[0; 15]);
        assert!(frames(&truncated).is_err());
        let mut cut = header();
        cut.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 42]);
        assert!(frames(&cut).is_err());
    }
    #[test]
    fn witness_statistics_never_treat_missing_or_dropped_as_zero() {
        assert_eq!(
            stats("0 packets captured\n0 packets dropped by kernel\n").unwrap(),
            0
        );
        for s in [
            "",
            "0 packets captured",
            "0 packets captured\n1 packet dropped by kernel",
            "0 packets captured\n0 packets captured\n0 packets dropped by kernel",
        ] {
            assert!(stats(s).is_err());
        }
    }
    #[test]
    fn header_only_isolation_does_not_claim_completed_scan() {
        let stats = "0 packets captured\n0 packets dropped by kernel\n";
        assert!(verify(&header(), stats, &header(), stats).is_err());
    }
    #[test]
    fn full_capture_requires_replies_cookie_macs_missing_arp_and_no_uplink() {
        let mut capture = header();
        let mut count = 0;
        let mut append = |second: u32, frame: &[u8]| {
            capture.extend_from_slice(&second.to_le_bytes());
            capture.extend_from_slice(&[0; 4]);
            capture.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            capture.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            capture.extend_from_slice(frame);
            count += 1;
        };
        for (second, hop) in [
            (1, A),
            (1, B),
            (1, GATEWAY),
            (1, MISSING),
            (2, MISSING),
            (3, MISSING),
        ] {
            let f = rmasscan_core::arp::encode_request(SOURCE_MAC, SOURCE.into(), hop.into());
            append(second, &f);
        }
        for target in [A, B, ROUTED] {
            for port in PORT_FIRST..=PORT_LAST {
                let seq = rmasscan_core::cookie::syn_cookie_ipv4(
                    target.into(),
                    u32::from(port),
                    SOURCE.into(),
                    40000,
                    42,
                ) as u32;
                let mut frame = Vec::new();
                rmasscan_core::packet::TcpSynTemplate::new(
                    SOURCE_MAC,
                    destination_mac(target).unwrap(),
                    rmasscan_core::packet::LinkType::Ethernet,
                )
                .build_syn(
                    target.into(),
                    port,
                    SOURCE.into(),
                    40000,
                    seq,
                    &mut frame,
                );
                append(4, &frame);
                append(4, &wire::reply(&frame).unwrap().unwrap());
            }
        }
        let stats = format!("{count} packets captured\n0 packets dropped by kernel");
        let clean = "0 packets captured\n0 packets dropped by kernel";
        assert_eq!(
            verify(&capture, &stats, &header(), clean),
            Ok(Verified {
                probes: 96,
                kernel_resets: 0
            })
        );
        let with_extra = |frame: &[u8]| {
            let mut extra = capture.clone();
            extra.extend_from_slice(&4u32.to_le_bytes());
            extra.extend_from_slice(&[0; 4]);
            extra.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            extra.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            extra.extend_from_slice(frame);
            extra
        };
        let extra_stats = format!(
            "{} packets captured\n0 packets dropped by kernel",
            count + 1
        );
        let expected_reset = wire::test_reset(A, 8000);
        assert_eq!(
            verify(&with_extra(&expected_reset), &extra_stats, &header(), clean),
            Ok(Verified {
                probes: 96,
                kernel_resets: 1
            })
        );
        for kind in [[8, 0], [8, 6], [0x86, 0xdd]] {
            let mut short = vec![0; 14];
            short[..6].copy_from_slice(&SOURCE_MAC);
            short[6..12].copy_from_slice(&A_MAC);
            short[12..14].copy_from_slice(&kind);
            assert!(verify(&with_extra(&short), &extra_stats, &header(), clean).is_err());
        }
        // A syntactically valid reset before its SYN-ACK is not attributable
        // to this scan and must not be silently discarded.
        let mut premature = header();
        premature.extend_from_slice(&1u32.to_le_bytes());
        premature.extend_from_slice(&[0; 4]);
        premature.extend_from_slice(&(expected_reset.len() as u32).to_le_bytes());
        premature.extend_from_slice(&(expected_reset.len() as u32).to_le_bytes());
        premature.extend_from_slice(&expected_reset);
        premature.extend_from_slice(&capture[24..]);
        assert!(
            verify(&premature, &extra_stats, &header(), clean)
                .unwrap_err()
                .contains("uncorrelated")
        );
        for target in [MISSING, GATEWAY, std::net::Ipv4Addr::new(203, 0, 113, 17)] {
            let frame = wire::test_reset(target, 8000);
            let mut extra = capture.clone();
            extra.extend_from_slice(&4u32.to_le_bytes());
            extra.extend_from_slice(&[0; 4]);
            extra.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            extra.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            extra.extend_from_slice(&frame);
            let extra_stats = format!(
                "{} packets captured\n0 packets dropped by kernel",
                count + 1
            );
            assert!(
                verify(&extra, &extra_stats, &header(), clean).is_err(),
                "foreign/missing/excluded target reset must fail complete witness"
            );
        }
        let mut early = capture.clone();
        let fifth = 24 + 4 * (16 + 60);
        early[fifth..fifth + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(
            verify(&early, &stats, &header(), clean)
                .unwrap_err()
                .contains("response window")
        );
        assert!(
            verify(&capture, &stats, &capture, &stats)
                .unwrap_err()
                .contains("ISOLATION BREACH")
        );
        let mut corrupt = capture.clone();
        let last = corrupt.len() - 10;
        corrupt[last] ^= 1;
        assert!(verify(&corrupt, &stats, &header(), clean).is_err());
    }
}
