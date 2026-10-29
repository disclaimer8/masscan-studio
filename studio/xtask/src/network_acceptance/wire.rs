//! Independent bounded fixture packet classification and response construction.
use super::topology::*;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Syn {
    pub target: Ipv4Addr,
    pub port: u16,
    pub sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Unrelated,
    KernelMulticast,
    ArpRequest(Ipv4Addr),
    ArpReply(Ipv4Addr),
    Syn(Syn),
    Response(Syn),
    KernelReset(Syn),
}

fn fixture_mac(mac: &[u8]) -> bool {
    [SOURCE_MAC, PEER_MAC, A_MAC, B_MAC, GATEWAY_MAC]
        .iter()
        .any(|m| mac == m)
}
fn fixture_ip(address: Ipv4Addr) -> bool {
    u32::from(address) & 0xfffffff8 == u32::from(Ipv4Addr::new(198, 18, 42, 0)) || address == ROUTED
}

/// Every fixture-associated packet has one explicit class or is an error.
/// No TCP flags are discarded before identity, tuple and header validation.
pub fn classify(f: &[u8]) -> Result<Frame, String> {
    if f.len() < 14 {
        return Err("truncated Ethernet".into());
    }
    let associated = fixture_mac(&f[..6]) || fixture_mac(&f[6..12]);
    match &f[12..14] {
        [8, 6] => {
            let associated = associated
                || (f.len() >= 42 && (fixture_ip(ip(&f[28..32])) || fixture_ip(ip(&f[38..42]))));
            if !associated {
                return Ok(Frame::Unrelated);
            }
            classify_arp(f)
        }
        [8, 0] => {
            let associated = associated
                || (f.len() >= 34 && (fixture_ip(ip(&f[26..30])) || fixture_ip(ip(&f[30..34]))));
            if !associated {
                return Ok(Frame::Unrelated);
            }
            classify_ipv4(f)
        }
        [0x86, 0xdd] if associated => {
            classify_ipv6_multicast(f)?;
            Ok(Frame::KernelMulticast)
        }
        _ if associated => Err("unclassified fixture Ethernet protocol".into()),
        _ => Ok(Frame::Unrelated),
    }
}

fn arp_mac(address: Ipv4Addr) -> Option<[u8; 6]> {
    match address {
        A => Some(A_MAC),
        B => Some(B_MAC),
        GATEWAY => Some(GATEWAY_MAC),
        _ => None,
    }
}
fn classify_arp(f: &[u8]) -> Result<Frame, String> {
    if !(42..=60).contains(&f.len()) || f[14..20] != [0, 1, 8, 0, 6, 4] {
        return Err("truncated or malformed fixture ARP".into());
    }
    let sender = ip(&f[28..32]);
    let target = ip(&f[38..42]);
    match word(&f[20..22]) {
        1 if sender == SOURCE
            && f[..6] == [255; 6]
            && f[6..12] == SOURCE_MAC
            && f[22..28] == SOURCE_MAC
            && f[32..38] == [0; 6]
            && [A, B, GATEWAY, MISSING].contains(&target) =>
        {
            Ok(Frame::ArpRequest(target))
        }
        2 if target == SOURCE && f[..6] == SOURCE_MAC && f[32..38] == SOURCE_MAC => {
            let mac = arp_mac(sender).ok_or("ARP reply outside next-hop allowlist")?;
            if f[6..12] != mac || f[22..28] != mac {
                return Err("ARP reply MAC differs".into());
            }
            Ok(Frame::ArpReply(sender))
        }
        _ => Err("unexpected fixture ARP identity/opcode/target".into()),
    }
}

fn classify_ipv4(f: &[u8]) -> Result<Frame, String> {
    if f.len() < 34 || f[14] != 0x45 || word(&f[20..22]) & 0xbfff != 0 || checksum(&f[14..34]) != 0
    {
        return Err("malformed fixture IPv4 header".into());
    }
    let end = 14 + usize::from(word(&f[16..18]));
    if end < 34 || end > f.len() || f.len() > end.max(60) {
        return Err("truncated fixture IPv4 packet".into());
    }
    let source = ip(&f[26..30]);
    let destination = ip(&f[30..34]);
    if f[23] == 17 {
        // Explicitly permit valid kernel mDNS multicast, never arbitrary UDP.
        if source != SOURCE
            || destination != Ipv4Addr::new(224, 0, 0, 251)
            || f[6..12] != SOURCE_MAC
            || f[..6] != [1, 0, 0x5e, 0, 0, 0xfb]
            || end < 42
            || word(&f[34..36]) != 5353
            || word(&f[36..38]) != 5353
            || usize::from(word(&f[38..40])) != end - 34
        {
            return Err("unclassified fixture UDP".into());
        }
        if word(&f[40..42]) != 0 {
            let mut pseudo = f[26..34].to_vec();
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&((end - 34) as u16).to_be_bytes());
            pseudo.extend_from_slice(&f[34..end]);
            if checksum(&pseudo) != 0 {
                return Err("invalid kernel multicast UDP checksum".into());
            }
        }
        return Ok(Frame::KernelMulticast);
    }
    if f[23] != 6 || end < 54 || tcp_checksum(f, end) != 0 {
        return Err("malformed or unclassified fixture TCP".into());
    }
    let header = usize::from(f[46] >> 4) * 4;
    if header < 20 || 34 + header != end || f[46] & 15 != 0 || word(&f[52..54]) != 0 {
        return Err("fixture TCP data/reserved bits/header invalid".into());
    }
    if source == SOURCE {
        let mac = destination_mac(destination).ok_or("scanner TCP outside eligible targets")?;
        let port = word(&f[36..38]);
        if f[..6] != mac
            || f[6..12] != SOURCE_MAC
            || word(&f[34..36]) != 40000
            || !(PORT_FIRST..=PORT_LAST).contains(&port)
            || dword(&f[42..46]) != 0
        {
            return Err("unexpected scanner TCP tuple/MAC/acknowledgement".into());
        }
        let sequence = dword(&f[38..42]);
        match f[47] {
            2 if header == 24 && f[54..58] == [2, 4, 5, 0xb4] => Ok(Frame::Syn(Syn {
                target: destination,
                port,
                sequence,
            })),
            // RFC793 reset in response to our SYN-ACK: SEQ=received ACK,
            // ACK unset/zero, no payload/options/window. Correlate in witness.
            4 if header == 20 && word(&f[48..50]) == 0 && port.is_multiple_of(2) => {
                Ok(Frame::KernelReset(Syn {
                    target: destination,
                    port,
                    sequence: sequence.wrapping_sub(1),
                }))
            }
            _ => Err("unexpected scanner TCP flags/reset shape".into()),
        }
    } else if destination == SOURCE {
        let mac = destination_mac(source).ok_or("TCP reply outside eligible targets")?;
        let port = word(&f[34..36]);
        if f[..6] != SOURCE_MAC
            || f[6..12] != mac
            || word(&f[36..38]) != 40000
            || !(PORT_FIRST..=PORT_LAST).contains(&port)
            || header != 20
            || f[47] != if port.is_multiple_of(2) { 0x12 } else { 0x14 }
            || dword(&f[38..42]) != 123
            || word(&f[48..50]) != 4096
        {
            return Err("invalid fixture TCP response".into());
        }
        Ok(Frame::Response(Syn {
            target: source,
            port,
            sequence: dword(&f[42..46]).wrapping_sub(1),
        }))
    } else {
        Err("fixture TCP has unexpected IP endpoints".into())
    }
}

fn classify_ipv6_multicast(f: &[u8]) -> Result<(), String> {
    if f.len() < 54
        || f[14] >> 4 != 6
        || ![SOURCE_MAC, PEER_MAC].iter().any(|m| f[6..12] == *m)
        || f[38] != 0xff
        || f[..2] != [0x33, 0x33]
        || f[2..6] != f[50..54]
    {
        return Err("malformed/unclassified fixture IPv6".into());
    }
    let end = 54 + usize::from(word(&f[18..20]));
    if end > f.len() || end < 62 || f.len() > end.max(60) {
        return Err("truncated fixture IPv6 payload".into());
    }
    match f[20] {
        17 if word(&f[54..56]) == 5353
            && word(&f[56..58]) == 5353
            && usize::from(word(&f[58..60])) == end - 54
            && f[38..54] == [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb] => {}
        58 if f[55] == 0
            && ((f[54] == 133 && end >= 62)
                || (f[54] == 134 && end >= 70)
                || ([135, 136].contains(&f[54]) && end >= 78)) => {}
        _ => return Err("unclassified fixture IPv6 multicast protocol".into()),
    }
    let mut pseudo = f[22..54].to_vec();
    pseudo.extend_from_slice(&((end - 54) as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, f[20]]);
    pseudo.extend_from_slice(&f[54..end]);
    if checksum(&pseudo) != 0 {
        return Err("invalid fixture IPv6 multicast checksum".into());
    }
    Ok(())
}

pub fn reply(frame: &[u8]) -> Result<Option<Vec<u8>>, String> {
    match classify(frame)? {
        Frame::ArpRequest(target) => {
            let Some(mac) = arp_mac(target) else {
                return Ok(None);
            };
            let mut out = vec![0; 60];
            out[..6].copy_from_slice(&SOURCE_MAC);
            out[6..12].copy_from_slice(&mac);
            out[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 2]);
            out[22..28].copy_from_slice(&mac);
            out[28..32].copy_from_slice(&target.octets());
            out[32..38].copy_from_slice(&SOURCE_MAC);
            out[38..42].copy_from_slice(&SOURCE.octets());
            Ok(Some(out))
        }
        Frame::Syn(_) => tcp_reply(frame),
        _ => Ok(None),
    }
}

fn ip(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}
fn word(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn dword(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn checksum(b: &[u8]) -> u16 {
    let mut n: u32 = b
        .chunks(2)
        .map(|p| u32::from(p[0]) * 256 + u32::from(*p.get(1).unwrap_or(&0)))
        .sum();
    while n > 65535 {
        n = (n & 65535) + (n >> 16);
    }
    !(n as u16)
}
fn tcp_checksum(f: &[u8], end: usize) -> u16 {
    let mut p = f[26..34].to_vec();
    p.extend_from_slice(&[0, 6]);
    p.extend_from_slice(&((end - 34) as u16).to_be_bytes());
    p.extend_from_slice(&f[34..end]);
    checksum(&p)
}

fn tcp_reply(f: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let Frame::Syn(probe) = classify(f)? else {
        return Ok(None);
    };
    let mut out = vec![0; 60];
    out[..6].copy_from_slice(&SOURCE_MAC);
    out[6..12].copy_from_slice(&destination_mac(probe.target).unwrap());
    out[12..14].copy_from_slice(&[8, 0]);
    out[14] = 0x45;
    out[16..18].copy_from_slice(&40_u16.to_be_bytes());
    out[22] = 64;
    out[23] = 6;
    out[26..30].copy_from_slice(&probe.target.octets());
    out[30..34].copy_from_slice(&SOURCE.octets());
    out[34..36].copy_from_slice(&probe.port.to_be_bytes());
    out[36..38].copy_from_slice(&40000_u16.to_be_bytes());
    out[38..42].copy_from_slice(&123_u32.to_be_bytes());
    out[42..46].copy_from_slice(&probe.sequence.wrapping_add(1).to_be_bytes());
    out[46] = 0x50;
    out[47] = if probe.port % 2 == 0 { 0x12 } else { 0x14 };
    out[48..50].copy_from_slice(&4096_u16.to_be_bytes());
    let sum = checksum(&out[14..34]);
    out[24..26].copy_from_slice(&sum.to_be_bytes());
    let sum = tcp_checksum(&out, 54);
    out[50..52].copy_from_slice(&sum.to_be_bytes());
    Ok(Some(out))
}

#[cfg(test)]
pub fn test_reset(target: Ipv4Addr, port: u16) -> Vec<u8> {
    let cookie = rmasscan_core::cookie::syn_cookie_ipv4(
        target.into(),
        u32::from(port),
        SOURCE.into(),
        40000,
        42,
    ) as u32;
    let mut f = Vec::new();
    rmasscan_core::packet::TcpSynTemplate::new(
        SOURCE_MAC,
        destination_mac(target).unwrap_or(GATEWAY_MAC),
        rmasscan_core::packet::LinkType::Ethernet,
    )
    .build_syn(
        target.into(),
        port,
        SOURCE.into(),
        40000,
        cookie.wrapping_add(1),
        &mut f,
    );
    f.truncate(54);
    f[16..18].copy_from_slice(&40u16.to_be_bytes());
    f[46] = 0x50;
    f[47] = 4;
    f[48..50].fill(0);
    f[24..26].fill(0);
    f[50..52].fill(0);
    let c = checksum(&f[14..34]);
    f[24..26].copy_from_slice(&c.to_be_bytes());
    let c = tcp_checksum(&f, 54);
    f[50..52].copy_from_slice(&c.to_be_bytes());
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn truncated_fixture_ip_and_arp_are_errors_not_unrelated_frames() {
        for kind in [[8, 0], [8, 6], [0x86, 0xdd]] {
            let mut f = vec![0; 14];
            f[..6].copy_from_slice(&SOURCE_MAC);
            f[6..12].copy_from_slice(&A_MAC);
            f[12..14].copy_from_slice(&kind);
            assert!(
                reply(&f).is_err(),
                "malformed fixture frame silently ignored"
            );
        }
    }
    #[test]
    fn replies_to_each_allowlisted_arp_but_never_missing_or_foreign_sender() {
        for ip in [A, B, GATEWAY] {
            let request = rmasscan_core::arp::encode_request(SOURCE_MAC, SOURCE.into(), ip.into());
            assert!(reply(&request).unwrap().is_some(), "{ip} must answer");
        }
        let request = rmasscan_core::arp::encode_request(SOURCE_MAC, SOURCE.into(), MISSING.into());
        assert!(reply(&request).unwrap().is_none());
        let request = rmasscan_core::arp::encode_request(PEER_MAC, SOURCE.into(), A.into());
        assert!(reply(&request).is_err());
    }
    #[test]
    fn direct_and_routed_syn_replies_preserve_cookie_and_valid_checksums() {
        for target in [A, B, ROUTED] {
            for port in [8000, 8001] {
                let mut f = Vec::new();
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
                    u32::MAX,
                    &mut f,
                );
                let out = reply(&f).unwrap().unwrap();
                assert_eq!(out[47], if port == 8000 { 0x12 } else { 0x14 });
                assert_eq!(dword(&out[42..46]), 0);
                assert_eq!(checksum(&out[14..34]), 0);
                assert_eq!(tcp_checksum(&out, 54), 0);
                f[0] ^= 2;
                assert!(reply(&f).is_err());
            }
        }
    }
    #[test]
    fn truncated_and_corrupt_packets_never_produce_reply() {
        let mut f = Vec::new();
        rmasscan_core::packet::TcpSynTemplate::new(
            SOURCE_MAC,
            A_MAC,
            rmasscan_core::packet::LinkType::Ethernet,
        )
        .build_syn(A.into(), 8000, SOURCE.into(), 40000, 17, &mut f);
        for n in 0..f.len() {
            assert!(reply(&f[..n]).ok().flatten().is_none());
        }
        f[38] ^= 1;
        assert!(reply(&f).is_err());
    }
}
