//! Exact fixture mutation plan and conservative cleanup decisions.
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
        || recorded != observed
    {
        return Err(
            "interface ownership changed; preserve resource for operator inspection".into(),
        );
    }
    Ok(true)
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
            gateway: GATEWAY.to_string(),
            interface: SCANNER.into(),
        };
        assert_eq!(delete_route(&route, None), Ok(None));
        assert!(delete_route(&route, Some(&route)).unwrap().is_some());
        let mut changed = route.clone();
        changed.interface = "en0".into();
        assert!(delete_route(&route, Some(&changed)).is_err());
    }
}
