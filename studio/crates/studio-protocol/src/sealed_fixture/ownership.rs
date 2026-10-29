//! Pure fixed command plan and conservative ownership predicates.
//! A name alone is never proof that a resource belongs to this fixture.
use super::topology::*;

pub fn fresh_lease(created: u64, expires: u64, now: u64) -> Result<(), String> {
    if created > now || expires <= now || expires.checked_sub(created) != Some(1800) {
        return Err("fixture seal expired or clock moved backwards; down/up required".into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceIdentity {
    pub name: String,
    pub index: u32,
    pub mac: [u8; 6],
    pub peer: Option<String>,
    pub ipv4: Vec<std::net::Ipv4Addr>,
    pub ipv4_prefixes: Vec<(std::net::Ipv4Addr, u8)>,
    pub bridges: Vec<String>,
    pub up: bool,
}

pub fn can_destroy(
    recorded: &InterfaceIdentity,
    observed: Option<&InterfaceIdentity>,
) -> Result<bool, String> {
    let Some(observed) = observed else {
        return Ok(false);
    };
    if ![SCANNER, PEER].contains(&recorded.name.as_str())
        || recorded.index == 0
        || !cleanup_match(recorded, observed)
    {
        return Err(
            "interface ownership changed; preserve resource for operator inspection".into(),
        );
    }
    Ok(true)
}

fn cleanup_match(recorded: &InterfaceIdentity, observed: &InterfaceIdentity) -> bool {
    let mut expected = recorded.clone();
    // The only expected external modification is the documented scanner
    // guard experiment. It never authorizes aliases, prefixes or membership.
    if recorded.name == SCANNER && recorded.up && !observed.up {
        expected.up = false;
    }
    &expected == observed
}

pub fn memberships(text: &str, name: &str) -> Result<Vec<String>, String> {
    let mut parent = None;
    let mut members = std::collections::BTreeSet::new();
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) && !line.is_empty() {
            parent = Some(line.split_once(':').ok_or("unreadable interface header")?.0);
        }
        let words: Vec<_> = line.split_whitespace().collect();
        if words.first() == Some(&"member:") {
            let member = words.get(1).ok_or("unreadable interface membership")?;
            if *member == name {
                members.insert(
                    parent
                        .ok_or("membership without interface header")?
                        .to_owned(),
                );
            }
        }
    }
    Ok(members.into_iter().collect())
}

/// Commands are argv, never shell text; fixed host route only, never a default route.
pub fn setup_steps() -> Vec<Vec<&'static str>> {
    vec![
        vec!["/sbin/ifconfig", SCANNER, "create"],
        vec!["/sbin/ifconfig", PEER, "create"],
        vec!["/sbin/ifconfig", SCANNER, "lladdr", "02:ac:42:00:00:01"],
        vec!["/sbin/ifconfig", PEER, "lladdr", "02:ac:42:00:00:02"],
        vec!["/sbin/ifconfig", SCANNER, "peer", PEER],
        vec!["/sbin/ifconfig", PEER, "up"],
        vec![
            "/sbin/ifconfig",
            SCANNER,
            "inet",
            "198.18.42.1",
            "netmask",
            "255.255.255.248",
            "up",
        ],
        vec![
            "/sbin/route",
            "-n",
            "add",
            "-host",
            "198.19.42.2",
            "198.18.42.4",
        ],
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedRoute {
    pub destination: String,
    pub prefix: u8,
    pub flags: String,
    pub gateway: String,
    pub interface: String,
}
pub fn delete_route(
    recorded: &OwnedRoute,
    observed: Option<&OwnedRoute>,
) -> Result<Option<Vec<String>>, String> {
    let Some(observed) = observed else {
        return Ok(None);
    };
    if recorded != observed
        || recorded.destination != ROUTED.to_string()
        || recorded.prefix != 32
        || !['U', 'G', 'H', 'S']
            .iter()
            .all(|flag| recorded.flags.contains(*flag))
        || recorded.gateway != GATEWAY.to_string()
        || recorded.interface != SCANNER
    {
        return Err("host route ownership changed; preserve route".into());
    }
    Ok(Some(vec![
        "/sbin/route".into(),
        "-n".into(),
        "delete".into(),
        "-host".into(),
        recorded.destination.clone(),
        recorded.gateway.clone(),
    ]))
}

pub fn exact_route(text: &str) -> Result<Option<OwnedRoute>, String> {
    if text.len() > 65536 {
        return Err("route evidence exceeds limit".into());
    }
    let mut columns = None;
    let mut found = None;
    for line in text.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        if words.first() == Some(&"Destination") {
            if columns.is_some() {
                return Err("ambiguous route table headers".into());
            }
            let column = |name| {
                words
                    .iter()
                    .position(|word| *word == name)
                    .ok_or("missing route table column")
            };
            columns = Some((column("Gateway")?, column("Flags")?, column("Netif")?));
            continue;
        }
        let Some((gateway, flags, interface)) = columns else {
            continue;
        };
        if words.is_empty() {
            continue;
        }
        if words.len() <= gateway.max(flags).max(interface) {
            return Err("truncated route evidence".into());
        }
        let (destination, prefix) = words[0].split_once('/').unwrap_or((words[0], "32"));
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| "invalid route prefix evidence")?;
        if prefix > 32 {
            return Err("invalid route prefix evidence".into());
        }
        if destination != ROUTED.to_string() || prefix != 32 {
            if [SCANNER, PEER].contains(&words[interface]) && route_covers(words[0], ROUTED)? {
                return Err("foreign broader route uses fixture interface; preserve stand".into());
            }
            continue;
        }
        if !['U', 'G', 'H', 'S']
            .iter()
            .all(|flag| words[flags].contains(*flag))
        {
            return Err("fixture /32 lacks up/gateway/host/static route flags".into());
        }
        if found.is_some() {
            return Err("ambiguous duplicate fixture host route".into());
        }
        found = Some(OwnedRoute {
            destination: destination.into(),
            prefix,
            flags: words[flags].into(),
            gateway: words[gateway].into(),
            interface: words[interface].into(),
        });
    }
    columns.ok_or("missing IPv4 route table header")?;
    Ok(found)
}

fn route_covers(text: &str, address: std::net::Ipv4Addr) -> Result<bool, String> {
    if text == "default" {
        return Ok(true);
    }
    let (address_text, prefix) = text
        .split_once('/')
        .map_or((text, None), |(a, p)| (a, Some(p)));
    let parts: Vec<_> = address_text.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return Err("invalid route destination".into());
    }
    let mut octets = [0; 4];
    for (i, p) in parts.iter().enumerate() {
        octets[i] = p.parse::<u8>().map_err(|_| "invalid route address")?;
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
    Ok(u32::from_be_bytes(octets) & mask == u32::from(address) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_or_extended_manifest_never_authorizes_native_work() {
        assert!(fresh_lease(100, 1900, 100).is_ok());
        assert!(fresh_lease(100, 1900, 1899).is_ok());
        for (created, expires, now) in [
            (100, 1900, 99),
            (100, 1900, 1900),
            (100, 1901, 200),
            (100, 99, 100),
        ] {
            assert!(fresh_lease(created, expires, now).is_err());
        }
    }
    #[test]
    fn cleanup_preserves_foreign_or_recreated_resources_and_handles_absence() {
        let ours = InterfaceIdentity {
            name: SCANNER.into(),
            index: 42,
            mac: SOURCE_MAC,
            peer: Some(PEER.into()),
            ipv4: vec![SOURCE],
            ipv4_prefixes: vec![(SOURCE, 29)],
            bridges: vec![],
            up: true,
        };
        assert_eq!(can_destroy(&ours, None), Ok(false));
        assert_eq!(can_destroy(&ours, Some(&ours)), Ok(true));
        let mut changed = ours.clone();
        changed.index += 1;
        assert!(can_destroy(&ours, Some(&changed)).is_err());
        changed = ours.clone();
        changed.peer = Some("feth99".into());
        assert!(can_destroy(&ours, Some(&changed)).is_err());
        let route = OwnedRoute {
            destination: ROUTED.to_string(),
            prefix: 32,
            flags: "UGHS".into(),
            gateway: GATEWAY.to_string(),
            interface: SCANNER.into(),
        };
        assert_eq!(delete_route(&route, None), Ok(None));
        assert!(delete_route(&route, Some(&route)).unwrap().is_some());
        let mut changed = route.clone();
        changed.interface = "en0".into();
        assert!(delete_route(&route, Some(&changed)).is_err());
    }
    fn fresh(name: &str, index: u32) -> InterfaceIdentity {
        InterfaceIdentity {
            name: name.into(),
            index,
            mac: [2, 1, 2, 3, 4, index as u8],
            peer: None,
            ipv4: vec![],
            ipv4_prefixes: vec![],
            bridges: vec![],
            up: false,
        }
    }

    #[test]
    fn cleanup_preserves_added_addresses_prefixes_and_bridge_membership() {
        let mut ours = fresh(SCANNER, 42);
        ours.mac = SOURCE_MAC;
        ours.ipv4_prefixes = vec![(SOURCE, 29)];
        ours.ipv4 = vec![SOURCE];
        ours.up = true;
        let mut changed = ours.clone();
        changed.ipv4_prefixes.push((A, 32));
        assert!(
            can_destroy(&ours, Some(&changed)).is_err(),
            "added alias must be preserved"
        );
        changed = ours.clone();
        changed.ipv4_prefixes[0].1 = 24;
        assert!(can_destroy(&ours, Some(&changed)).is_err());
        changed = ours.clone();
        changed.bridges.push("bridge0".into());
        assert!(can_destroy(&ours, Some(&changed)).is_err());
        changed = ours.clone();
        changed.up = false;
        assert_eq!(
            can_destroy(&ours, Some(&changed)),
            Ok(true),
            "documented scanner guard link-down remains cleanable"
        );
        changed = ours.clone();
        changed.ipv4.push(A);
        assert!(
            can_destroy(&ours, Some(&changed)).is_err(),
            "address missing a prefix must still be preserved"
        );
    }

    #[test]
    fn membership_parser_identifies_parent_bridge_without_substring_matches() {
        let all = "feth4203: flags=1\n\tether 02:ac:42:00:00:01\nbridge0: flags=1\n\tmember: feth4203 flags=3\nbridge1: flags=1\n\tmember: feth42030 flags=3\n";
        assert_eq!(memberships(all, SCANNER).unwrap(), vec!["bridge0"]);
        assert!(memberships("\tmember: feth4203 flags=1\n", SCANNER).is_err());
    }
    #[test]
    fn broader_route_through_same_gateway_and_interface_is_not_owned_host() {
        let header = "Routing tables\nInternet:\nDestination Gateway Flags Netif Expire\n";
        let host = format!("{header}{ROUTED} {GATEWAY} UGHS {SCANNER}\n");
        let recorded = exact_route(&host).unwrap().unwrap();
        for destination in ["198.19.42/24", "198.19/16", "default"] {
            let fallback = format!("{header}{destination} {GATEWAY} UGS {SCANNER}\n");
            assert!(
                exact_route(&fallback)
                    .unwrap_err()
                    .contains("foreign broader route"),
                "broader selected route must not authorize owned /32 or interface destruction"
            );
        }
        let absent = format!("{header}default 192.0.2.1 UGS en0\n");
        assert!(exact_route(&absent).unwrap().is_none());
        assert!(delete_route(&recorded, None).unwrap().is_none());
    }
    #[test]
    fn exact_route_requires_host_flags_and_unambiguous_complete_table() {
        let header = "Destination Gateway Flags Netif Expire\n";
        let row = format!("{ROUTED}/32 {GATEWAY} UGHS {SCANNER}\n");
        assert_eq!(
            exact_route(&format!("{header}{row}"))
                .unwrap()
                .unwrap()
                .prefix,
            32
        );
        for text in [
            format!("{header}{ROUTED} {GATEWAY} UGS {SCANNER}\n"),
            format!("{header}{row}{row}"),
            format!("{header}{ROUTED} {GATEWAY}\n"),
            String::new(),
        ] {
            assert!(exact_route(&text).is_err());
        }
    }
}
