//! Fixed, isolated acceptance tooling. Never opens the product release gate.
#![forbid(unsafe_code)]
#[cfg(target_os = "macos")]
mod controller;
#[cfg(target_os = "macos")]
mod native;
mod ownership;
mod topology;
mod wire;
mod witness;
use std::{fs::File, io::Read, path::Path};

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() > limit {
        return Err(format!("{} exceeds evidence limit", path.display()));
    }
    Ok(data)
}

/// Refuse existing routes overlapping either fixture range; default is retained.
fn validate_route_table(text: &str) -> Result<(), String> {
    let mut column = None;
    for line in text.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        if words.first() == Some(&"Destination") {
            column = Some(
                words
                    .iter()
                    .position(|s| *s == "Netif")
                    .ok_or("route header has no Netif")?,
            );
            continue;
        }
        let Some(col) = column else {
            continue;
        };
        if words.is_empty() {
            continue;
        }
        if words.len() <= col {
            return Err("unreadable route table row".into());
        }
        if words[0] == "default" {
            continue;
        }
        let (addr, prefix) = words[0]
            .split_once('/')
            .map_or((words[0], None), |(a, p)| (a, Some(p)));
        let parts: Vec<_> = addr.split('.').collect();
        if parts.is_empty() || parts.len() > 4 {
            return Err("unreadable route destination".into());
        }
        let mut bytes = [0; 4];
        for (i, p) in parts.iter().enumerate() {
            bytes[i] = p.parse::<u8>().map_err(|_| "invalid route address")?;
        }
        let prefix = match prefix {
            Some(p) => p.parse::<u32>().map_err(|_| "invalid route prefix")?,
            None => parts.len() as u32 * 8,
        };
        if prefix > 32 {
            return Err("invalid route prefix".into());
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let start = u32::from_be_bytes(bytes) & mask;
        let end = start | !mask;
        let a = u32::from(std::net::Ipv4Addr::new(198, 18, 42, 0));
        let b = a + 7;
        let remote = u32::from(topology::ROUTED);
        if (start <= b && end >= a) || (start <= remote && end >= remote) {
            return Err(format!("existing route overlaps fixture: {}", words[0]));
        }
    }
    column.ok_or("missing IPv4 route table header")?;
    Ok(())
}

pub fn main_entry() -> super::Result<()> {
    let args: Vec<_> = std::env::args().skip(2).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["plan"] => {
            println!("{}",serde_json::to_string_pretty(&serde_json::json!({"schema":1,"scanner":topology::SCANNER,"peer":topology::PEER,"job":topology::job(),"setup_argv":ownership::setup_steps(),"native_scan":"BLOCKED until candidate pre-ARP and pre-ACK interlocks reviewed","cleanup":"only root-journalled matching interface index/MAC/peer and exact host route; preserve drift"}))?);
            Ok(())
        },
        ["verify",dir] => {
            let dir=Path::new(dir);
            let report=studio_protocol::NetworkReport::decode(&read_bounded(&dir.join("network-report.bin"),24576)?)?;
            topology::validate_report(&report)?;
            let peer=read_bounded(&dir.join("peer.pcap"),witness::MAX_CAPTURE)?;
            let uplink=read_bounded(&dir.join("uplink.pcap"),witness::MAX_CAPTURE)?;
            let peer_stats=String::from_utf8(read_bounded(&dir.join("peer.stderr"),65536)?)?;
            let uplink_stats=String::from_utf8(read_bounded(&dir.join("uplink.stderr"),65536)?)?;
            let count=witness::verify(&peer,&peer_stats,&uplink,&uplink_stats)?;
            println!("Packet subset PASS: {} unique direct/routed SYNs, {} strictly correlated kernel resets, correct frozen report, no captured uplink frame. Lifecycle acceptance requires controller/store evidence.",count.probes,count.kernel_resets);
            Ok(())
        },
        #[cfg(target_os="macos")]
        ["up"] => native::up().map_err(Into::into),
        #[cfg(target_os="macos")]
        ["down"] => native::down().map_err(Into::into),
        #[cfg(target_os="macos")]
        ["status"] => native::status().map_err(Into::into),
        #[cfg(target_os="macos")]
        ["peer"] => native::peer().map_err(Into::into),
        #[cfg(target_os="macos")]
        ["stop-peer"] => native::stop_peer().map_err(Into::into),
        #[cfg(target_os="macos")]
        ["drive",case,runner,out] => controller::drive(case,Path::new(runner),Path::new(out)).map_err(Into::into),
        _=>Err("Usage: cargo xtask network-acceptance plan | verify DIR | up | status | down; native scan unavailable pending candidate safety interlocks".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preexisting_routes_cannot_be_silently_overridden() {
        let h = "Routing tables\nInternet:\nDestination Gateway Flags Netif Expire\ndefault 192.0.2.1 UGSc en0\n127 127.0.0.1 UCS lo0\n";
        assert!(validate_route_table(h).is_ok());
        for route in [
            "198.18/15",
            "198.18.42/24",
            "198.19.42.2",
            "198.18.42.3",
            "0/0",
        ] {
            assert!(validate_route_table(&format!("{h}{route} 192.0.2.1 UGSc en0\n")).is_err());
        }
        assert!(validate_route_table("").is_err());
    }
}
