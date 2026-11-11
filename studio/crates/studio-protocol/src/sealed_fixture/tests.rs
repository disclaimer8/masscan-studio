use super::*;

fn state() -> State {
    State {
        version: 1,
        generation: "1".repeat(32),
        tooling_sha256: "2".repeat(64),
        created_utc_seconds: 100,
        expires_utc_seconds: 1900,
        sealed: true,
        scanner: Some(InterfaceIdentity {
            name: SCANNER.into(),
            index: 42,
            mac: SOURCE_MAC,
            peer: Some(PEER.into()),
            ipv4: vec![SOURCE],
            ipv4_prefixes: vec![(SOURCE, 29)],
            bridges: vec![],
            up: true,
        }),
        peer: Some(InterfaceIdentity {
            name: PEER.into(),
            index: 43,
            mac: PEER_MAC,
            peer: Some(SCANNER.into()),
            ipv4: vec![],
            ipv4_prefixes: vec![],
            bridges: vec![],
            up: true,
        }),
        route: Some(OwnedRoute {
            destination: ROUTED.to_string(),
            prefix: 32,
            flags: "UGHS".into(),
            gateway: GATEWAY.to_string(),
            interface: SCANNER.into(),
        }),
    }
}
#[test]
fn seal_pins_entire_generation_and_refuses_missing_expired_or_replaced_identity() {
    let s = state();
    let mut pin = Pin::default();
    assert_eq!(pin.check(&s, 100).unwrap(), 42);
    assert!(pin.check(&s, 1899).is_ok());
    assert!(pin.check(&s, 1900).is_err());
    for mutate in [
        |s: &mut State| s.generation = "3".repeat(32),
        |s: &mut State| s.scanner.as_mut().unwrap().index += 1,
        |s: &mut State| s.peer.as_mut().unwrap().index += 2,
        |s: &mut State| s.tooling_sha256 = "3".repeat(64),
        |s: &mut State| s.scanner = None,
        |s: &mut State| s.sealed = false,
        |s: &mut State| s.route = None,
        |s: &mut State| s.scanner.as_mut().unwrap().bridges.push("bridge0".into()),
        |s: &mut State| s.peer.as_mut().unwrap().ipv4.push(A),
    ] {
        let mut changed = s.clone();
        mutate(&mut changed);
        assert!(pin.check(&changed, 101).is_err());
    }
    assert!(pin.check(&s, 99).is_err());
    assert!(pin.check(&s, 101).is_ok());
}
#[test]
fn eligible_resume_is_exact_and_pinned_without_reintroducing_missing() {
    let full = topology::expected_plan();
    assert_eq!(validate_neighbour_plan(&full, 42), Ok(false));
    let mut eligible = full.clone();
    eligible.next_hops.remove(&MISSING);
    assert_eq!(validate_neighbour_plan(&eligible, 42), Ok(true));
    assert!(validate_neighbour_plan(&eligible, 43).is_err());
    eligible.next_hops.remove(&B);
    assert!(validate_neighbour_plan(&eligible, 42).is_err());
    let mut fallback = full;
    fallback.next_hops.insert(ROUTED, SOURCE);
    assert!(validate_neighbour_plan(&fallback, 42).is_err());
}
#[test]
fn persisted_report_requires_exact_saved_job_bytes_and_macs() {
    let report = NetworkReport {
        job_digest: job().original_digest().unwrap(),
        routes: topology::expected_plan(),
        destinations: [(A, A_MAC), (B, B_MAC), (ROUTED, GATEWAY_MAC)].into(),
        unresolved: vec![MISSING],
    };
    assert!(validate_persisted(&job(), Some(&report.encode().unwrap())).is_ok());
    assert!(validate_persisted(&job(), None).is_err());
    let mut wrong = report;
    wrong.destinations.insert(B, A_MAC);
    assert!(validate_persisted(&job(), Some(&wrong.encode().unwrap())).is_err());
    let mut changed_job = job();
    changed_job.rate += 1;
    assert!(validate_job(&changed_job).is_err());
}
