use super::*;
use std::cell::Cell;
use std::time::Duration;
use windows_sys::Win32::Networking::WinSock::{AF_INET6, IN_ADDR, IN_ADDR_0, SOCKADDR};

fn future() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

// A single contiguous allocation, just like IP Helper's output. Addresses and
// distinct prefixes are chosen independently of the parser's representation.
fn fixture() -> Vec<u64> {
    let mut buf = vec![0u64; 256];
    let base = buf.as_mut_ptr().cast::<u8>();
    let mut adapter = IP_ADAPTER_ADDRESSES_LH::default();
    adapter.Anonymous1.Anonymous.Length = size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32;
    adapter.Anonymous1.Anonymous.IfIndex = 7;
    adapter.IfType = 6;
    adapter.OperStatus = IfOperStatusUp;
    adapter.PhysicalAddressLength = 6;
    adapter.PhysicalAddress[..6].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    // SAFETY: all fixture offsets are aligned/in bounds, point to their declared
    // structures, and remain valid until buf is dropped (it is never resized).
    unsafe {
        adapter.AdapterName = base.add(1024);
        adapter.FriendlyName = base.add(1100).cast();
        adapter.FirstUnicastAddress = base.add(512).cast();
        base.cast::<IP_ADAPTER_ADDRESSES_LH>().write(adapter);
        std::ptr::copy_nonoverlapping(
            c"{01234567-89AB-CDEF-0123-456789ABCDEF}".as_ptr().cast(),
            base.add(1024),
            39,
        );
        for (i, unit) in "Ethernet with spaces\0".encode_utf16().enumerate() {
            base.add(1100 + i * 2).cast::<u16>().write(unit);
        }
        for (n, (ip, prefix)) in [([198, 18, 0, 1], 24), ([192, 0, 2, 3], 31)]
            .into_iter()
            .enumerate()
        {
            let mut u = IP_ADAPTER_UNICAST_ADDRESS_LH::default();
            u.Anonymous.Anonymous.Length = size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>() as u32;
            u.Next = if n == 0 {
                base.add(640).cast()
            } else {
                std::ptr::null_mut()
            };
            u.OnLinkPrefixLength = prefix;
            u.Address.lpSockaddr = base.add(768 + n * 32).cast::<SOCKADDR>();
            u.Address.iSockaddrLength = size_of::<SOCKADDR_IN>() as i32;
            base.add(512 + n * 128)
                .cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>()
                .write(u);
            base.add(768 + n * 32)
                .cast::<SOCKADDR_IN>()
                .write(SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(ip),
                        },
                    },
                    ..Default::default()
                });
        }
    }
    buf
}

fn change_unicast(buf: &mut [u64], change: impl FnOnce(&mut IP_ADAPTER_UNICAST_ADDRESS_LH)) {
    // SAFETY: fixture() places a full aligned unicast node at offset 512.
    let node = unsafe {
        &mut *buf
            .as_mut_ptr()
            .cast::<u8>()
            .add(512)
            .cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>()
    };
    change(node);
}

#[test]
fn observation_preserves_every_ipv4_prefix_and_adapter_identity() {
    let buf = fixture();
    let observations = decode_adapters(&buf, future(), &|| false).unwrap();
    assert_eq!(observations.len(), 1);
    let (adapter, prefixes) = &observations[0];
    assert_eq!(
        adapter.ipv4,
        [Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(192, 0, 2, 3)]
    );
    assert_eq!(
        prefixes,
        &[
            Ipv4Prefix {
                address: Ipv4Addr::new(198, 18, 0, 1),
                length: 24
            },
            Ipv4Prefix {
                address: Ipv4Addr::new(192, 0, 2, 3),
                length: 31
            },
        ]
    );
    let iface = iface_from_adapter(adapter);
    assert_eq!(iface.name, "Ethernet with spaces");
    assert_eq!(
        iface.device_id,
        "\\Device\\NPF_{01234567-89AB-CDEF-0123-456789ABCDEF}"
    );
    assert_eq!(iface.index, 7);
    assert_eq!(iface.mac, Some([2, 3, 4, 5, 6, 7]));
}

#[test]
fn observation_rejects_malformed_sockaddr_and_prefix_without_partial_success() {
    for len in [
        -1,
        i32::MIN,
        0,
        (size_of::<SOCKADDR_IN>() - 1) as i32,
        i32::MAX,
    ] {
        let mut buf = fixture();
        change_unicast(&mut buf, |u| u.Address.iSockaddrLength = len);
        assert!(
            decode_adapters(&buf, future(), &|| false).is_err(),
            "length {len}"
        );
    }
    for length in [33, 128, 255] {
        let mut buf = fixture();
        change_unicast(&mut buf, |u| u.OnLinkPrefixLength = length);
        assert!(
            decode_adapters(&buf, future(), &|| false).is_err(),
            "prefix {length}"
        );
    }
    let mut buf = fixture();
    change_unicast(&mut buf, |u| u.Address.lpSockaddr = std::ptr::null_mut());
    assert!(decode_adapters(&buf, future(), &|| false).is_err());
}

#[test]
fn observation_rejects_missing_prefix_field_and_cyclic_lists() {
    let mut buf = fixture();
    change_unicast(&mut buf, |u| u.Anonymous.Anonymous.Length = 16);
    assert!(decode_adapters(&buf, future(), &|| false).is_err());
    let mut buf = fixture();
    change_unicast(&mut buf, |u| u.Next = std::ptr::from_mut(u));
    assert!(decode_adapters(&buf, future(), &|| false).is_err());
    let mut buf = fixture();
    // SAFETY: fixture starts with a full adapter structure.
    unsafe {
        let ptr = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        (*ptr).Next = ptr;
    }
    assert!(decode_adapters(&buf, future(), &|| false).is_err());
}

#[test]
fn non_ipv4_sockaddr_is_not_interpreted_as_an_ipv4_prefix() {
    let mut buf = fixture();
    // SAFETY: fixture's first sockaddr is fully in bounds.
    unsafe {
        (*buf.as_mut_ptr().cast::<u8>().add(768).cast::<SOCKADDR_IN>()).sin_family = AF_INET6;
    }
    let observations = decode_adapters(&buf, future(), &|| false).unwrap();
    assert_eq!(
        observations[0].1,
        [Ipv4Prefix {
            address: Ipv4Addr::new(192, 0, 2, 3),
            length: 31
        }]
    );
}

#[test]
fn cancellation_and_expiry_prevent_ip_helper_calls() {
    for cancelled in [true, false] {
        let deadline = if cancelled { future() } else { Instant::now() };
        let result = adapters_buffer_with(deadline, &|| cancelled, |_, _| {
            panic!("IP Helper must not be called")
        });
        assert!(result.is_err());
    }
}

#[test]
fn cancellation_during_ip_helper_discards_success_and_no_data() {
    for status in [0, ERROR_NO_DATA] {
        let cancelled = Cell::new(false);
        let result = adapters_buffer_with(future(), &|| cancelled.get(), |_, _| {
            cancelled.set(true);
            status
        });
        assert!(result.unwrap_err().to_string().contains("cancelled"));
    }
}

#[test]
fn expired_ip_helper_result_is_discarded() {
    let deadline = Instant::now() + Duration::from_millis(20);
    let result = adapters_buffer_with(deadline, &|| false, |_, _| {
        std::thread::sleep(Duration::from_millis(30));
        ERROR_NO_DATA
    });
    assert!(result.unwrap_err().to_string().contains("deadline"));
}

#[test]
fn overflowing_adapter_buffers_are_bounded_in_size_and_retries() {
    let calls = Cell::new(0);
    let oversized = adapters_buffer_with(future(), &|| false, |_, size| {
        calls.set(calls.get() + 1);
        *size = u32::MAX;
        ERROR_BUFFER_OVERFLOW
    });
    assert!(oversized.is_err());
    assert_eq!(calls.get(), 1);
    calls.set(0);
    let repeated = adapters_buffer_with(future(), &|| false, |_, size| {
        calls.set(calls.get() + 1);
        *size += 8;
        ERROR_BUFFER_OVERFLOW
    });
    assert!(repeated.is_err());
    assert_eq!(calls.get(), 4);
}

#[test]
fn cancelled_or_expired_parser_never_returns_a_partial_observation() {
    let buf = fixture();
    assert!(decode_adapters(&buf, Instant::now(), &|| false).is_err());
    let checks = Cell::new(0);
    let result = decode_adapters(&buf, future(), &|| {
        checks.set(checks.get() + 1);
        checks.get() > 3
    });
    assert!(result.unwrap_err().to_string().contains("cancelled"));
}
