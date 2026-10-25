//! Подставной `IfaceInfo` (имена как в `linux/tests.rs`) и тесты на реальной
//! ОС без привилегий.

use std::sync::Mutex;

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;

use crate::NetError;
use crate::macos::Errno;
use crate::macos::ifinfo::{IfaceInfo, LinkInfo, OsIface, nic_mac, verify_binding};
use crate::macos::sys::IFT_ETHER;

const IFINDEX: u32 = 9;
const MAC: [u8; 6] = [2, 0xac, 0, 0, 0, 1];
const IP: u32 = 0xC612_0001;

struct FakeIface {
    index: Option<u32>,
    link: Option<LinkInfo>,
    queried: Mutex<Vec<&'static str>>,
}

impl FakeIface {
    fn ok() -> Self {
        FakeIface {
            index: Some(IFINDEX),
            link: Some(LinkInfo {
                sdl_type: IFT_ETHER,
                mac: Some(MAC),
            }),
            queried: Mutex::new(Vec::new()),
        }
    }
}

impl IfaceInfo for FakeIface {
    fn ifindex(&self, _: &str) -> Result<Option<u32>, Errno> {
        self.queried.lock().unwrap().push("ifindex");
        Ok(self.index)
    }
    fn link(&self, _: &str) -> Result<Option<LinkInfo>, Errno> {
        self.queried.lock().unwrap().push("link");
        Ok(self.link)
    }
}

fn binding() -> AdapterBinding {
    AdapterBinding {
        interface_id: "feth4201".into(),
        link_type: LinkType::Ethernet,
        source_ipv4: IP,
        source_mac: MAC,
        next_hop_mac: [2, 0xac, 0, 0, 0, 2],
        source_ports: (40000, 40000),
    }
}

#[test]
fn binding_matching_the_os_yields_the_ifindex() {
    assert_eq!(verify_binding(&FakeIface::ok(), &binding()), Ok(IFINDEX));
}

#[test]
fn non_ethernet_link_type_is_rejected_before_any_os_query() {
    for lt in [LinkType::Null, LinkType::Raw] {
        let q = FakeIface::ok();
        let mut b = binding();
        b.link_type = lt;
        assert!(matches!(
            verify_binding(&q, &b),
            Err(NetError::UnsupportedLink(_))
        ));
        assert!(q.queried.lock().unwrap().is_empty());
    }
}

#[test]
fn non_ethernet_interface_is_unsupported_link() {
    // lo0 IFT_LOOP 24, utun IFT_OTHER 1, bridge0 IFT_BRIDGE 209.
    for ty in [24u8, 1, 209] {
        let mut q = FakeIface::ok();
        q.link = Some(LinkInfo {
            sdl_type: ty,
            mac: None,
        });
        assert!(
            matches!(
                verify_binding(&q, &binding()),
                Err(NetError::UnsupportedLink(_))
            ),
            "{ty}"
        );
    }
    let mut q = FakeIface::ok();
    q.link = Some(LinkInfo {
        sdl_type: IFT_ETHER,
        mac: None,
    });
    assert!(matches!(
        verify_binding(&q, &binding()),
        Err(NetError::UnsupportedLink(_))
    ));
}

#[test]
fn missing_interface_is_a_mismatch() {
    let mut q = FakeIface::ok();
    q.index = None;
    assert!(matches!(
        verify_binding(&q, &binding()),
        Err(NetError::InterfaceMismatch(_))
    ));
    let mut q = FakeIface::ok();
    q.link = None;
    assert!(matches!(
        verify_binding(&q, &binding()),
        Err(NetError::InterfaceMismatch(_))
    ));
}

#[test]
fn source_ip_and_mac_are_not_validated_against_the_os() {
    let q = FakeIface::ok();
    let mut b = binding();
    b.source_ipv4 = IP ^ 0xff;
    b.source_mac = [2, 0xee, 0, 0, 0, 9];
    assert_eq!(verify_binding(&q, &b), Ok(IFINDEX));
}

#[test]
fn hostile_interface_names_never_reach_the_os() {
    for name in [
        "",
        "a b",
        "a/b",
        "..",
        ".",
        "x\0y",
        "0123456789abcdef",
        "ve;rm -rf",
        "a\tb",
    ] {
        let q = FakeIface::ok();
        let mut b = binding();
        b.interface_id = name.into();
        let r = verify_binding(&q, &b);
        assert!(matches!(r, Err(NetError::InterfaceMismatch(_))), "{name:?}");
        assert!(q.queried.lock().unwrap().is_empty(), "{name:?}");
    }
}

#[test]
fn lo0_is_not_ethernet() {
    let mut b = binding();
    b.interface_id = "lo0".into();
    assert!(matches!(
        verify_binding(&OsIface, &b),
        Err(NetError::UnsupportedLink(_))
    ));
}

#[test]
fn a_nonexistent_interface_is_a_mismatch() {
    let mut b = binding();
    b.interface_id = "nope0".into();
    assert!(matches!(
        verify_binding(&OsIface, &b),
        Err(NetError::InterfaceMismatch(_))
    ));
}

#[test]
fn nic_mac_of_lo0_is_none() {
    assert_eq!(nic_mac("lo0"), None);
    assert_eq!(nic_mac("nope0"), None);
}

#[test]
fn inventory_lists_lo0_and_bpf0_without_opening_anything() {
    let inv = crate::inventory_bpf().expect("inventory");
    let lo = inv
        .interfaces
        .iter()
        .find(|i| i.name == "lo0")
        .expect("lo0");
    assert!(!lo.ethernet);
    assert!(lo.up);
    assert!(lo.ipv4.contains(&std::net::Ipv4Addr::LOCALHOST));
    let bpf0 = inv
        .devices
        .iter()
        .find(|d| d.path == "/dev/bpf0")
        .expect("/dev/bpf0");
    let meta = std::fs::metadata("/dev/bpf0").unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(bpf0.mode & 0o777, meta.mode() & 0o777);
    if let Some(max) = inv.bpf_maxdevices {
        assert!(inv.devices.len() <= max as usize);
    }
    let mut paths: Vec<_> = inv.devices.iter().map(|d| d.path.clone()).collect();
    let sorted = paths.clone();
    paths.sort_by_key(|p| p["/dev/bpf".len()..].parse::<u32>().unwrap());
    assert_eq!(paths, sorted, "contiguous ascending from bpf0");
    assert!(inv.os_version.as_deref().is_some_and(|v| v.contains('(')));
    assert!(inv.instant_clock.starts_with("CLOCK_UPTIME_RAW"));
}
