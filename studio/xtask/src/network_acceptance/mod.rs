//! Fixed, isolated acceptance tooling for the unmerged fixture-only candidate.
#![forbid(unsafe_code)]
mod capture;
#[cfg(target_os = "macos")]
mod capture_native;
#[cfg(target_os = "macos")]
mod controller;
#[cfg(any(target_os = "macos", test))]
mod lifecycle;
#[cfg(target_os = "macos")]
mod native;
mod ownership;
#[cfg(target_os = "macos")]
mod supervision;
mod topology;
mod wire;
mod witness;
use std::{fs::File, io::Read, path::Path};
// Darwin process spawning can transiently retain the Store's flock across a
// concurrent immediate reopen. Serialize only these test fixtures through reap.
#[cfg(all(test, target_os = "macos"))]
static TEST_PROCESS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
            println!("{}",serde_json::to_string_pretty(&serde_json::json!({"schema":1,"scanner":topology::SCANNER,"peer":topology::PEER,"job":topology::job(),"setup_argv":ownership::setup_steps(),"native_scan":"fixture-only candidate; supervision and native grant still required","cleanup":"only root-journalled matching interface index/MAC/peer and exact host route; preserve drift"}))?);
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
        ["capture",role,iface] => capture_native::run(role,iface).map_err(Into::into),
        #[cfg(target_os="macos")]
        ["stop-peer"] => native::stop_peer().map_err(Into::into),
        #[cfg(target_os="macos")]
        ["drive",case,runner,out,ticket] => controller::drive(case,Path::new(runner),Path::new(out),Path::new(ticket)).map_err(Into::into),
        #[cfg(target_os="macos")]
        ["prepare-drive",case,out] => controller::prepare(case,Path::new(out)).map_err(Into::into),
        #[cfg(target_os="macos")]
        ["supervise",case,out,uid,hash] => supervision::supervise(case,Path::new(out),uid.parse()?,hash,None).map_err(Into::into),
        #[cfg(target_os="macos")]
        ["supervise",case,out,uid,hash,prior] => supervision::supervise(case,Path::new(out),uid.parse()?,hash,Some(prior)).map_err(Into::into),
        #[cfg(target_os="macos")]
        ["verify-lifecycle",dir] => supervision::verify_dir(Path::new(dir),None).map_err(Into::into),
        #[cfg(target_os="macos")]
        ["verify-lifecycle",dir,prior] => supervision::verify_dir(Path::new(dir),Some(Path::new(prior))).map_err(Into::into),
        _=>Err("Usage: network-acceptance plan | verify DIR | prepare-drive CASE DIR | supervise CASE DIR UID RUNNER_SHA256 [PAUSE_NONCE] | drive CASE RUNNER DIR TICKET | verify-lifecycle DIR [PAUSE_DIR] | up | status | down; native commands require reviewed candidate and explicit grant".into()),
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
