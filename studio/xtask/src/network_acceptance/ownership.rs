//! Executable fixture setup orchestration stays in the operator tooling.
use super::topology::*;
use studio_protocol::sealed_fixture::State;
pub use studio_protocol::sealed_fixture::ownership::*;

pub fn verify_owned(
    state: &State,
    scanner: Option<&InterfaceIdentity>,
    peer: Option<&InterfaceIdentity>,
    route: Option<&OwnedRoute>,
    after_guard: bool,
) -> Result<(), String> {
    if !state.sealed {
        return Err("fixture setup incomplete; inspect retained state".into());
    }
    for (recorded, observed) in [(&state.scanner, scanner), (&state.peer, peer)] {
        let recorded = recorded.as_ref().ok_or("missing owned interface")?;
        if !can_destroy(recorded, observed)? {
            return Err("owned interface disappeared".into());
        }
    }
    if after_guard {
        let mut expected = state.scanner.clone().ok_or("missing owned scanner")?;
        if !expected.up {
            return Err("guard requires an originally up scanner".into());
        }
        expected.up = false;
        if scanner != Some(&expected) || peer != state.peer.as_ref() {
            return Err(
                "guard terminal interfaces differ from the exact owned down transition".into(),
            );
        }
    }
    let recorded_route = state.route.as_ref().ok_or("missing owned host route")?;
    // Validate the recorded fixed route even when the kernel removed it.
    delete_route(recorded_route, Some(recorded_route))?;
    let present = delete_route(recorded_route, route)?;
    // ifconfig down can remove this host route. Absence is acceptable only
    // after the exact guard transition; any replacement still fails above.
    // This predicate neither enables packet I/O nor changes cleanup ownership.
    if present.is_none() && !after_guard {
        return Err("owned route disappeared".into());
    }
    Ok(())
}

pub trait SetupHost {
    fn identity(&mut self, name: &str) -> Result<Option<InterfaceIdentity>, String>;
    fn command(&mut self, argv: &[&str]) -> Result<(), String>;
}

/// One confirmed operation, followed by journal identities. The native caller
/// persists the returned state before executing the next step.
pub fn setup_step(
    host: &mut dyn SetupHost,
    index: usize,
    scanner: &mut Option<InterfaceIdentity>,
    peer: &mut Option<InterfaceIdentity>,
) -> Result<(), String> {
    let steps = setup_steps();
    let step = steps.get(index).ok_or("invalid setup step")?;
    for prior in [scanner.as_ref(), peer.as_ref()].into_iter().flatten() {
        if host.identity(&prior.name)?.as_ref() != Some(prior) {
            return Err("owned interface changed before setup operation".into());
        }
    }
    let (mut expected_scanner, mut expected_peer) = (scanner.clone(), peer.clone());
    if index <= 1 {
        let name = if index == 0 { SCANNER } else { PEER };
        if host.identity(name)?.is_some()
            || (if index == 0 {
                scanner.is_some()
            } else {
                peer.is_some()
            })
        {
            return Err("fixture interface already exists; creation refused".into());
        }
    } else {
        match index {
            2 => expected_scanner.as_mut().ok_or("scanner not owned")?.mac = SOURCE_MAC,
            3 => expected_peer.as_mut().ok_or("peer not owned")?.mac = PEER_MAC,
            4 => {
                expected_scanner.as_mut().ok_or("scanner not owned")?.peer = Some(PEER.into());
                expected_peer.as_mut().ok_or("peer not owned")?.peer = Some(SCANNER.into());
            }
            5 => expected_peer.as_mut().ok_or("peer not owned")?.up = true,
            6 => {
                let s = expected_scanner.as_mut().ok_or("scanner not owned")?;
                s.ipv4_prefixes = vec![(SOURCE, 29)];
                s.ipv4 = vec![SOURCE];
                s.up = true;
            }
            7 => {}
            _ => return Err("invalid setup transition".into()),
        }
    }
    host.command(step)?;
    if index <= 1 {
        let name = if index == 0 { SCANNER } else { PEER };
        let created = host
            .identity(name)?
            .ok_or("created interface disappeared")?;
        if created.name != name
            || created.index == 0
            || created.mac == [0; 6]
            || created.mac[0] & 1 != 0
            || created.peer.is_some()
            || !created.ipv4.is_empty()
            || !created.ipv4_prefixes.is_empty()
            || !created.bridges.is_empty()
            || created.up
        {
            return Err("new interface has unexpected state; ownership not adopted".into());
        }
        if index == 0 {
            expected_scanner = Some(created);
        } else {
            expected_peer = Some(created);
        }
    }
    for expected in [expected_scanner.as_ref(), expected_peer.as_ref()]
        .into_iter()
        .flatten()
    {
        if host.identity(&expected.name)?.as_ref() != Some(expected) {
            return Err("unexpected interface transition; prior journal retained".into());
        }
    }
    *scanner = expected_scanner;
    *peer = expected_peer;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn guard_terminal_allows_route_removal_only_with_exact_owned_down_transition() {
        let mut host = FakeSetup::default();
        let (mut scanner, mut peer) = (None, None);
        for index in 0..setup_steps().len() {
            setup_step(&mut host, index, &mut scanner, &mut peer).unwrap();
        }
        let state = State {
            version: 1,
            generation: "1".repeat(32),
            created_utc_seconds: 1,
            expires_utc_seconds: 1801,
            tooling_sha256: "a".repeat(64),
            sealed: true,
            scanner: scanner.clone(),
            peer: peer.clone(),
            route: Some(OwnedRoute {
                destination: ROUTED.to_string(),
                prefix: 32,
                flags: "UGHS".into(),
                gateway: GATEWAY.to_string(),
                interface: SCANNER.into(),
            }),
        };
        assert!(verify_owned(&state, scanner.as_ref(), peer.as_ref(), None, false).is_err());
        assert!(verify_owned(&state, scanner.as_ref(), peer.as_ref(), None, true).is_err());
        assert!(
            verify_owned(
                &state,
                scanner.as_ref(),
                peer.as_ref(),
                state.route.as_ref(),
                true
            )
            .is_err()
        );
        let mut down = scanner.unwrap();
        down.up = false;
        verify_owned(&state, Some(&down), peer.as_ref(), None, true).unwrap();
        let mut invalid_seal = state.clone();
        invalid_seal.route.as_mut().unwrap().interface = "en0".into();
        assert!(verify_owned(&invalid_seal, Some(&down), peer.as_ref(), None, true).is_err());
        verify_owned(
            &state,
            Some(&down),
            peer.as_ref(),
            state.route.as_ref(),
            true,
        )
        .unwrap();
        assert!(verify_owned(&state, Some(&down), peer.as_ref(), None, false).is_err());
        let mut foreign = state.route.clone().unwrap();
        foreign.interface = "en0".into();
        assert!(verify_owned(&state, Some(&down), peer.as_ref(), Some(&foreign), true).is_err());
        for field in 0..5 {
            let mut changed = down.clone();
            match field {
                0 => changed.index += 1,
                1 => changed.mac[5] ^= 1,
                2 => changed.ipv4.push(A),
                3 => changed.bridges.push("bridge0".into()),
                _ => changed.ipv4_prefixes[0].1 = 24,
            }
            assert!(verify_owned(&state, Some(&changed), peer.as_ref(), None, true).is_err());
        }
        let mut changed_peer = peer.unwrap();
        changed_peer.up = false;
        assert!(verify_owned(&state, Some(&down), Some(&changed_peer), None, true).is_err());
        assert!(verify_owned(&state, None, Some(&changed_peer), None, true).is_err());
    }
    #[derive(Default)]
    struct FakeSetup {
        interfaces: std::collections::BTreeMap<String, InterfaceIdentity>,
        commands: usize,
        foreign_peer: bool,
    }
    impl SetupHost for FakeSetup {
        fn identity(&mut self, name: &str) -> Result<Option<InterfaceIdentity>, String> {
            Ok(self.interfaces.get(name).cloned())
        }
        fn command(&mut self, argv: &[&str]) -> Result<(), String> {
            self.commands += 1;
            match argv {
                ["/sbin/ifconfig", name, "create"] => {
                    if self.interfaces.contains_key(*name) {
                        return Err("already exists".into());
                    }
                    self.interfaces.insert(
                        (*name).into(),
                        fresh(name, if *name == SCANNER { 42 } else { 43 }),
                    );
                    // Another owner creates PEER after global preflight, while
                    // our scanner command runs successfully.
                    if *name == SCANNER && self.foreign_peer {
                        self.interfaces.insert(PEER.into(), fresh(PEER, 99));
                    }
                }
                ["/sbin/ifconfig", name, "lladdr", _] => {
                    self.interfaces.get_mut(*name).unwrap().mac = if *name == SCANNER {
                        SOURCE_MAC
                    } else {
                        PEER_MAC
                    };
                }
                ["/sbin/ifconfig", SCANNER, "peer", PEER] => {
                    self.interfaces.get_mut(SCANNER).unwrap().peer = Some(PEER.into());
                    self.interfaces.get_mut(PEER).unwrap().peer = Some(SCANNER.into());
                }
                ["/sbin/ifconfig", PEER, "up"] => self.interfaces.get_mut(PEER).unwrap().up = true,
                ["/sbin/ifconfig", SCANNER, "inet", _, "netmask", _, "up"] => {
                    let s = self.interfaces.get_mut(SCANNER).unwrap();
                    s.ipv4 = vec![SOURCE];
                    s.ipv4_prefixes = vec![(SOURCE, 29)];
                    s.up = true;
                }
                ["/sbin/route", "-n", "add", "-host", _, _] => {}
                _ => return Err("unexpected fake operation".into()),
            }
            Ok(())
        }
    }
    #[test]
    fn setup_never_adopts_foreign_peer_that_appears_during_scanner_creation() {
        let mut host = FakeSetup {
            foreign_peer: true,
            ..Default::default()
        };
        let (mut scanner, mut peer) = (None, None);
        setup_step(&mut host, 0, &mut scanner, &mut peer).unwrap();
        assert!(scanner.is_some());
        assert!(
            peer.is_none(),
            "foreign peer was adopted without successful create"
        );
        assert!(setup_step(&mut host, 1, &mut scanner, &mut peer).is_err());
        assert_eq!(host.interfaces[PEER].index, 99);
        assert!(peer.is_none());
    }
    #[test]
    fn later_setup_step_refuses_changed_owned_identity_before_mutation() {
        let mut host = FakeSetup::default();
        let (mut scanner, mut peer) = (None, None);
        setup_step(&mut host, 0, &mut scanner, &mut peer).unwrap();
        host.interfaces.get_mut(SCANNER).unwrap().mac = [2, 9, 9, 9, 9, 9];
        let before = host.commands;
        assert!(setup_step(&mut host, 2, &mut scanner, &mut peer).is_err());
        assert_eq!(host.commands, before);
    }
    #[test]
    fn successful_setup_records_only_expected_transitions() {
        let mut host = FakeSetup::default();
        let (mut scanner, mut peer) = (None, None);
        for index in 0..setup_steps().len() {
            setup_step(&mut host, index, &mut scanner, &mut peer).unwrap();
        }
        let scanner = scanner.unwrap();
        let peer = peer.unwrap();
        assert_eq!(scanner.ipv4, vec![SOURCE]);
        assert_eq!(scanner.ipv4_prefixes, vec![(SOURCE, 29)]);
        assert!(peer.ipv4.is_empty());
        assert_eq!(peer.mac, PEER_MAC);
        assert_eq!(scanner.peer, Some(PEER.into()));
        assert_eq!(peer.peer, Some(SCANNER.into()));
    }
}
