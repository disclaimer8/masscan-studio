//! Подставной `IfaceInfo` (имена как в `linux/tests.rs`) и тесты на реальной
//! ОС без привилегий.

use std::sync::Mutex;

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;

use crate::NetError;
use crate::discover::DARWIN_MASKED_MAC;
use crate::macos::Errno;
use crate::macos::ifinfo::{
    AddrKind, IfaceInfo, LinkInfo, OsIface, RawAddr, addr_kind, iface_exists, link_from_bytes,
    merge, nic_mac, verify_binding,
};
use crate::macos::sys::{BpfFd, IFT_ETHER};

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
    for (i, d) in inv.devices.iter().enumerate() {
        assert_eq!(d.path, format!("/dev/bpf{i}"), "contiguous from bpf0");
    }
    assert!(inv.os_version.as_deref().is_some_and(|v| v.contains('(')));
    assert!(inv.instant_clock.starts_with("CLOCK_UPTIME_RAW"));
}

/// Запись `sockaddr_dl`: len, family(18), index(2), type, nlen, alen, slen, data.
fn dl(len: usize, ty: u8, nlen: u8, alen: u8, data: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; len];
    r[0] = len as u8;
    r[1] = 18;
    r[4] = ty;
    r[5] = nlen;
    r[6] = alen;
    let n = data.len().min(len.saturating_sub(8));
    r[8..8 + n].copy_from_slice(&data[..n]);
    r
}

#[test]
fn parse_link_reads_the_mac_after_the_name() {
    let mut data = b"en0".to_vec();
    data.extend_from_slice(&MAC);
    let rec = dl(20, IFT_ETHER, 3, 6, &data);
    assert_eq!(
        link_from_bytes(&rec),
        Some(LinkInfo {
            sdl_type: IFT_ETHER,
            mac: Some(MAC)
        })
    );
}

#[test]
fn parse_link_reads_past_the_twelve_declared_data_bytes() {
    let mut data = b"feth4201xyz".to_vec(); // nlen 11
    data.extend_from_slice(&MAC); // MAC at data[11..17], beyond [i8; 12]
    let rec = dl(8 + 17, IFT_ETHER, 11, 6, &data);
    assert_eq!(link_from_bytes(&rec).unwrap().mac, Some(MAC));
}

#[test]
fn parse_link_rejects_hostile_lengths_without_reading_out_of_bounds() {
    // alen != 6
    for alen in [0u8, 5, 7, 8, 255] {
        let rec = dl(20, IFT_ETHER, 3, alen, &[0; 12]);
        assert_eq!(link_from_bytes(&rec).unwrap().mac, None, "alen {alen}");
    }
    // MAC would end past sdl_len
    assert_eq!(
        link_from_bytes(&dl(20, IFT_ETHER, 7, 6, &[0; 12]))
            .unwrap()
            .mac,
        None
    );
    assert_eq!(
        link_from_bytes(&dl(20, IFT_ETHER, 255, 6, &[0; 12]))
            .unwrap()
            .mac,
        None
    );
    // record shorter than the 8-byte header
    for len in 0..8 {
        assert_eq!(link_from_bytes(&vec![0u8; len]), None, "len {len}");
    }
    // exactly header, no data
    assert_eq!(link_from_bytes(&dl(8, 24, 0, 0, &[])).unwrap().sdl_type, 24);
}

#[test]
fn masked_placeholder_mac_is_unknown_never_a_value() {
    let link = |mac| LinkInfo {
        sdl_type: IFT_ETHER,
        mac: Some(mac),
    };
    assert_eq!(link(DARWIN_MASKED_MAC).visible_mac(), None);
    assert!(link(DARWIN_MASKED_MAC).masked());
    assert_eq!(link(MAC).visible_mac(), Some(MAC));
    assert!(!link(MAC).masked());

    let addrs = |mac| {
        vec![RawAddr {
            name: "feth4201".into(),
            flags: 0,
            kind: AddrKind::Link(link(mac)),
        }]
    };
    let fake = FakeIface::ok();
    let masked = merge(&addrs(DARWIN_MASKED_MAC), &fake);
    assert_eq!(masked[0].mac, None);
    assert!(masked[0].mac_masked);
    assert!(masked[0].ethernet);
    let real = merge(&addrs(MAC), &fake);
    assert_eq!(real[0].mac, Some(MAC));
    assert!(!real[0].mac_masked);
}

#[test]
fn iface_existence_does_not_depend_on_the_mac() {
    assert_eq!(iface_exists("lo0"), Some(true));
    assert_eq!(iface_exists("nope0"), Some(false));
}

#[test]
fn open_node_of_a_missing_index_is_enoent() {
    // No privileges needed: the node does not exist, so `open` fails before any permission check.
    assert_eq!(BpfFd::open_node(100_000).err(), Some(libc::ENOENT));
}

/// `sockaddr_in`: len, family, port, address, 8 bytes of padding (`len` 16 as the OS reports it).
fn sin(len: usize, a: [u8; 4]) -> Vec<u8> {
    let mut r = vec![0u8; len.max(2)];
    r[0] = len as u8;
    r[1] = libc::AF_INET as u8;
    for (i, b) in a.iter().enumerate() {
        if 4 + i < len {
            r[4 + i] = *b;
        }
    }
    r
}

/// Netmask record of `len` bytes: `[len, 2, 0, 0, 255, …]` with the first `ones` octets set.
fn mask(len: usize, ones: usize) -> Vec<u8> {
    let mut r = vec![0u8; len];
    for (i, b) in r.iter_mut().enumerate() {
        *b = match i {
            0 => len as u8,
            1 => libc::AF_INET as u8,
            4..=7 if i - 4 < ones => 255,
            _ => 0,
        };
    }
    r
}

#[test]
fn addr_kind_reads_a_full_v4_record_with_its_prefix() {
    let a = sin(16, [198, 51, 100, 9]);
    let m = mask(16, 3);
    assert_eq!(
        addr_kind(Some(&a), Some(&m)),
        AddrKind::V4 {
            address: "198.51.100.9".parse().unwrap(),
            prefix: Some(24)
        }
    );
}

#[test]
fn addr_kind_v4_boundary_is_eight_bytes() {
    let a8 = sin(8, [10, 0, 0, 1]);
    assert_eq!(
        addr_kind(Some(&a8), None),
        AddrKind::V4 {
            address: "10.0.0.1".parse().unwrap(),
            prefix: None
        }
    );
    let a7 = sin(7, [10, 0, 0, 1]);
    assert_eq!(addr_kind(Some(&a7), None), AddrKind::Other);
}

#[test]
fn addr_kind_netmask_lengths_decode_as_on_base() {
    let a = sin(16, [10, 1, 2, 3]);
    let want = |prefix| AddrKind::V4 {
        address: "10.1.2.3".parse().unwrap(),
        prefix,
    };
    // Darwin sends 0.0.0.0 as a zero-length record; an empty slice is allowed and means no prefix.
    assert_eq!(addr_kind(Some(&a), Some(&[])), want(None));
    assert_eq!(addr_kind(Some(&a), Some(&[1])), want(None));
    assert_eq!(addr_kind(Some(&a), Some(&mask(5, 1))), want(Some(8)));
    assert_eq!(addr_kind(Some(&a), Some(&mask(6, 2))), want(Some(16)));
    assert_eq!(addr_kind(Some(&a), Some(&mask(7, 3))), want(Some(24)));
    assert_eq!(addr_kind(Some(&a), Some(&mask(8, 4))), want(Some(32)));
    assert_eq!(
        addr_kind(Some(&a), Some(&[8, 2, 0, 0, 255, 0, 255, 0])),
        want(None)
    );
}

#[test]
fn addr_kind_reads_v6_without_the_kame_zone() {
    let mut a = vec![0u8; 28];
    a[0] = 28;
    a[1] = libc::AF_INET6 as u8;
    let ip: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
    a[8..24].copy_from_slice(&ip.octets());
    a[10] = 0;
    a[11] = 4; // KAME embeds the zone index in s6_addr[2..4]
    assert_eq!(addr_kind(Some(&a), None), AddrKind::V6(ip));
    a[0] = 23; // one byte short of the address field (sin6_addr ends at 24)
    assert_eq!(addr_kind(Some(&a), None), AddrKind::Other);
}

#[test]
fn addr_kind_reads_a_link_record() {
    let mut data = b"en0".to_vec();
    data.extend_from_slice(&MAC);
    let rec = dl(20, IFT_ETHER, 3, 6, &data);
    assert_eq!(
        addr_kind(Some(&rec), None),
        AddrKind::Link(LinkInfo {
            sdl_type: IFT_ETHER,
            mac: Some(MAC)
        })
    );
}

#[test]
fn addr_kind_short_or_missing_addresses_are_other() {
    assert_eq!(addr_kind(None, None), AddrKind::Other);
    // sa_len 0 and 1: only the two header bytes are read (the family is byte 1), nothing is parsed.
    for len in [0u8, 1] {
        for fam in [libc::AF_INET, libc::AF_INET6, 18] {
            assert_eq!(addr_kind(Some(&[len, fam as u8]), None), AddrKind::Other);
        }
    }
    // A record whose sa_len claims more than the slice holds must not panic.
    assert_eq!(
        addr_kind(Some(&[16, libc::AF_INET as u8, 0, 0, 1, 2]), None),
        AddrKind::Other
    );
}

#[test]
fn addr_kind_is_the_same_from_an_unaligned_offset() {
    let a = sin(16, [172, 16, 0, 5]);
    let m = mask(7, 3);
    let aligned = addr_kind(Some(&a), Some(&m));
    let (mut ba, mut bm) = (vec![0xEEu8], vec![0xEEu8]);
    ba.extend_from_slice(&a);
    bm.extend_from_slice(&m);
    assert_eq!(addr_kind(Some(&ba[1..]), Some(&bm[1..])), aligned);
    assert_eq!(
        aligned,
        AddrKind::V4 {
            address: "172.16.0.5".parse().unwrap(),
            prefix: Some(24)
        }
    );
}
