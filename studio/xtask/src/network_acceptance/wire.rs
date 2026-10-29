//! Independent bounded Ethernet/IP/TCP fixture codec, not Engine output.
use super::topology::*;
use std::net::Ipv4Addr;

pub fn reply(frame: &[u8]) -> Result<Option<Vec<u8>>, String> {
    if frame.len() < 14 {
        return Err("truncated Ethernet".into());
    }
    // Ignore unrelated traffic (e.g. host IPv6/mDNS). Never answer it.
    match &frame[12..14] {
        [8, 6] => arp_reply(frame),
        [8, 0] => tcp_reply(frame),
        _ => Ok(None),
    }
}

fn arp_reply(f: &[u8]) -> Result<Option<Vec<u8>>, String> {
    if f.len() < 42 || f[14..22] != [0, 1, 8, 0, 6, 4, 0, 1] {
        return Ok(None);
    }
    let sender = ip(&f[28..32]);
    let target = ip(&f[38..42]);
    if sender != SOURCE {
        return Ok(None);
    }
    if f[..6] != [255; 6]
        || f[6..12] != SOURCE_MAC
        || f[22..28] != SOURCE_MAC
        || f[32..38] != [0; 6]
    {
        return Err("unexpected lab ARP identity".into());
    }
    let mac = match target {
        A => A_MAC,
        B => B_MAC,
        GATEWAY => GATEWAY_MAC,
        MISSING => return Ok(None),
        _ => return Err("ARP outside fixture next-hop allowlist".into()),
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Syn {
    pub target: Ipv4Addr,
    pub port: u16,
    pub sequence: u32,
}

pub fn response(f: &[u8]) -> Result<Option<Syn>, String> {
    if f.len() < 34 || f[12..14] != [8, 0] || ip(&f[30..34]) != SOURCE {
        return Ok(None);
    }
    let target = ip(&f[26..30]);
    let mac = destination_mac(target).ok_or("reply source outside eligible targets")?;
    let end = 14 + usize::from(word(&f[16..18]));
    if f.len() < 54
        || end > f.len()
        || end < 54
        || f[14] != 0x45
        || f[23] != 6
        || checksum(&f[14..34]) != 0
        || tcp_checksum(f, end) != 0
        || f[..6] != SOURCE_MAC
        || f[6..12] != mac
        || word(&f[36..38]) != 40000
    {
        return Err("invalid captured TCP reply".into());
    }
    let port = word(&f[34..36]);
    if !(PORT_FIRST..=PORT_LAST).contains(&port)
        || f[47] != if port.is_multiple_of(2) { 0x12 } else { 0x14 }
    {
        return Err("unexpected captured port result".into());
    }
    Ok(Some(Syn {
        target,
        port,
        sequence: dword(&f[42..46]).wrapping_sub(1),
    }))
}

pub fn arp_request_target(f: &[u8]) -> Result<Option<Ipv4Addr>, String> {
    if f.len() < 42 || f[12..22] != [8, 6, 0, 1, 8, 0, 6, 4, 0, 1] || ip(&f[28..32]) != SOURCE {
        return Ok(None);
    }
    arp_reply(f)?; // Also validates the deliberately unanswered missing peer.
    Ok(Some(ip(&f[38..42])))
}

/// This parser is shared by the responder and offline witness, never by the product.
pub fn syn(f: &[u8]) -> Result<Option<Syn>, String> {
    if f.len() < 34 || f[12..14] != [8, 0] {
        return Ok(None);
    }
    // Ordinary kernel multicast/UDP on the isolated wire is not scanner TCP.
    if f[23] != 6 {
        return Ok(None);
    }
    if ip(&f[26..30]) != SOURCE {
        if f[6..12] == SOURCE_MAC {
            return Err("scanner TCP has wrong source IPv4".into());
        }
        return Ok(None);
    }
    if f[14] != 0x45 || f[23] != 6 || word(&f[20..22]) & 0x3fff != 0 {
        return Err("unexpected lab IPv4 header/fragment".into());
    }
    let end = 14 + usize::from(word(&f[16..18]));
    if end < 54 || end > f.len() || checksum(&f[14..34]) != 0 || tcp_checksum(f, end) != 0 {
        return Err("truncated lab TCP or invalid checksum".into());
    }
    let header = usize::from(f[46] >> 4) * 4;
    if header < 20 || 34 + header != end {
        return Err("TCP data or invalid header length".into());
    }
    // Kernel resets on the scanner are recorded but are not probes/replied to.
    if f[47] == 4 || f[47] == 0x14 {
        return Ok(None);
    }
    let target = ip(&f[30..34]);
    let mac = destination_mac(target).ok_or("TCP outside eligible fixture targets")?;
    let port = word(&f[36..38]);
    if f[..6] != mac
        || f[6..12] != SOURCE_MAC
        || word(&f[34..36]) != 40000
        || !(PORT_FIRST..=PORT_LAST).contains(&port)
        || f[47] != 2
        || dword(&f[42..46]) != 0
    {
        return Err("unexpected fixture SYN Ethernet identity/ports/flags".into());
    }
    Ok(Some(Syn {
        target,
        port,
        sequence: dword(&f[38..42]),
    }))
}

fn tcp_reply(f: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let Some(probe) = syn(f)? else {
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
mod tests {
    use super::*;
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
