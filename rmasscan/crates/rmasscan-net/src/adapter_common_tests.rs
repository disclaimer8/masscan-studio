//! The helpers shared by the three adapters: the errno numbers they rest on, the kind each errno maps to and the
//! texts of `check_binding` for each adapter name. The texts themselves are pinned per adapter by
//! `error_texts_are_byte_identical`; here the shared module is checked on its own.

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;

use super::{IFNAMSIZ, check_binding, errno, errno_msg, map_setup_errno, valid_ifname};
use crate::NetError;

fn binding() -> AdapterBinding {
    AdapterBinding {
        interface_id: "if0".into(),
        link_type: LinkType::Ethernet,
        source_ipv4: 0xc612_0001,
        source_mac: [0x02, 0, 0, 0, 0, 0x0a],
        next_hop_mac: [0x02, 0, 0, 0, 0, 0x0b],
        source_ports: (40000, 40015),
    }
}

#[test]
fn adapter_common_errnos_match_every_os() {
    // The macOS table (own constants, so it exists on every host) and the shared one agree.
    use crate::macos::abi::errno as mac;
    assert_eq!(errno::EPERM, mac::EPERM);
    assert_eq!(errno::EACCES, mac::EACCES);
    assert_eq!(errno::ENXIO, mac::ENXIO);
    assert_eq!(errno::ENODEV, mac::ENODEV);
    // Where `libc` exists (Linux and macOS) the numbers are the OS ones.
    #[cfg(unix)]
    {
        assert_eq!(errno::EPERM, libc::EPERM);
        assert_eq!(errno::EACCES, libc::EACCES);
        assert_eq!(errno::ENXIO, libc::ENXIO);
        assert_eq!(errno::ENODEV, libc::ENODEV);
        assert_eq!(IFNAMSIZ, libc::IFNAMSIZ);
    }
    // The kind of each errno, and the text of each kind.
    for (e, kind) in [
        (
            errno::EPERM,
            "permission denied (raw packet access needs elevated privileges)",
        ),
        (
            errno::EACCES,
            "permission denied (raw packet access needs elevated privileges)",
        ),
        (errno::ENXIO, "interface does not match the binding"),
        (errno::ENODEV, "interface does not match the binding"),
        (5, "system error"),
        (2, "system error"),
    ] {
        assert_eq!(
            map_setup_errno("setup", e).to_string(),
            format!("{kind}: {}", errno_msg("setup", e)),
            "errno {e}"
        );
    }
    assert!(matches!(
        map_setup_errno("op", errno::EPERM),
        NetError::PermissionDenied(_)
    ));
    assert!(matches!(
        map_setup_errno("op", errno::ENODEV),
        NetError::InterfaceMismatch(_)
    ));
    assert!(matches!(map_setup_errno("op", 5), NetError::System(_)));
}

#[test]
fn interface_names_follow_the_ifnamsiz_limit() {
    let longest = "a".repeat(IFNAMSIZ - 1);
    assert!(valid_ifname(&longest));
    assert!(!valid_ifname(&format!("{longest}a")));
    for bad in ["", ".", "..", "a/b", "a b", "a\0b", "a\tb"] {
        assert!(!valid_ifname(bad), "{bad:?}");
    }
}

#[test]
fn check_binding_texts_name_the_adapter() {
    for adapter in ["macOS BPF adapter", "Windows Npcap adapter"] {
        let refused = |b: &AdapterBinding| check_binding(b, adapter).unwrap_err().to_string();
        assert!(check_binding(&binding(), adapter).is_ok());
        let mut b = binding();
        b.link_type = LinkType::Raw;
        assert_eq!(
            refused(&b),
            format!("unsupported link type: Raw ({adapter} supports Ethernet only)")
        );
        // The other two texts do not carry the adapter name.
        let mut b = binding();
        b.source_mac = [0x01, 0, 0x5e, 0, 0, 1];
        assert_eq!(
            refused(&b),
            "interface does not match the binding: source MAC 01:00:5e:00:00:01 is not a unicast address"
        );
        let mut b = binding();
        b.source_mac = [0; 6];
        assert_eq!(
            refused(&b),
            "interface does not match the binding: source MAC 00:00:00:00:00:00 is not a unicast address"
        );
        let mut b = binding();
        b.next_hop_mac = b.source_mac;
        assert_eq!(
            refused(&b),
            "interface does not match the binding: source MAC equals the next-hop MAC: own transmitted \
             frames could not be told from replies"
        );
    }
}
