use studio_platform::network::{Snapshot, validate};

fn sealed() -> Snapshot {
    Snapshot {
        manifest: serde_json::json!({"state":"sealed","scanner_if":"feth4201","peer_if":"feth4202","scanner_mac":"02:ac:00:00:00:01","peer_mac":"02:ac:00:00:00:02","source_ip":"198.18.0.1","peer_ip":"198.18.0.2","uplink":"en0","gateway":"192.168.1.1"}),
        scanner: "feth4201: flags=UP\n ether 02:ac:00:00:00:01\n peer: feth4202\n status: active\n".into(),
        peer: "feth4202: flags=UP\n ether 02:ac:00:00:00:02\n inet 198.18.0.2 netmask 0xfffffffc\n peer: feth4201\n status: active\n".into(),
        interfaces: "en0: flags=UP\n inet 192.168.1.5 netmask 0xffffff00\nfeth4201: flags=UP\nfeth4202: flags=UP\n inet 198.18.0.2 netmask 0xfffffffc\n".into(),
        default_route: "interface: en0\ngateway: 192.168.1.1\n".into(),
        source_route: "interface: feth4202\n".into(),
        peer_route: "interface: lo0\n".into(),
        public_route: "interface: en0\n".into(),
        routes: "Routing tables\nInternet:\nDestination Gateway Flags Netif Expire\ndefault 192.168.1.1 UGScg en0\n198.18.0/30 link#20 UCS feth4202\n198.18.0.1 2:ac:0:0:0:1 UHLWI feth4202\n198.18.0.2 127.0.0.1 UHS lo0\n".into(),
        arp: "? (198.18.0.1) at 2:ac:0:0:0:1 on feth4202 ifscope permanent [ethernet]\n".into(),
        forwarding: "0\n".into(),
    }
}

#[test]
fn sealed_pair_passes_but_each_isolation_mutation_refuses() {
    assert!(validate(&sealed()).is_ok());
    for mutation in 0..14 {
        let mut s = sealed();
        match mutation {
            0 => s.manifest["state"] = "creating".into(),
            1 => s.scanner.push_str(" inet 198.18.0.1 netmask 0xfffffffc\n"),
            2 => s.peer = s.peer.replace("0xfffffffc", "0xffffff00"),
            3 => s.peer = s.peer.replace("status: active", "status: inactive"),
            4 => s.source_route = "interface: utun5\n".into(),
            5 => s.peer_route = "interface: en0\n".into(),
            6 => s.routes.push_str("198.18/15 10.1.1.1 UGSc utun5\n"),
            7 => s.routes.push_str("10/8 link#20 UCS feth4202\n"),
            8 => s.interfaces.push_str(" member: feth4202 flags=3\n"),
            9 => s.arp = s.arp.replace("permanent", "expires"),
            10 => s.forwarding = "1".into(),
            11 => s.default_route = "interface: en1\ngateway: 192.168.1.1\n".into(),
            12 => s.routes = s.routes.replace("Netif", "Unknown"),
            13 => s
                .interfaces
                .push_str("utun5: flags=UP\n inet 198.18.0.1 netmask 0xffffffff\n"),
            _ => unreachable!(),
        }
        assert!(validate(&s).is_err(), "mutation {mutation}");
    }
}

#[test]
fn unreadable_or_conflicting_routes_fail_closed() {
    for route in [
        "198.18.0/99 link#20 UCS feth4202",
        "198.18.garbage link#20 UCS en0",
        "broken",
        "128/1 link#20 UCS utun0",
    ] {
        let mut s = sealed();
        s.routes.push_str(route);
        assert!(validate(&s).is_err(), "{route}");
    }
}
