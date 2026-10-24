//! Проверка лабораторного адаптера (общий код живых тестов, только Windows).
//!
//! Живые тесты берут имя устройства и MAC из окружения. Прежде чем отправить
//! хоть один кадр, они обязаны убедиться, что устройство по имени
//! `\Device\NPF_{GUID}` действительно имеет заявленный MAC (иначе ошибка в
//! переменной окружения отправит кадры с НЕ того адаптера, например с
//! управляющего NAT). Это проверка ТЕСТА, а не продукта: продукт не требует
//! владения source MAC интерфейсом ОС.

use std::ffi::{CStr, c_char};

use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

/// MAC адаптера по GUID (`{...}`), либо `None`, если такого адаптера нет.
pub fn adapter_mac_by_guid(guid: &str) -> Option<[u8; 6]> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 32 * 1024;
    // u64: выравнивание 8, как требует IP_ADAPTER_ADDRESSES_LH.
    let mut buf: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
    for _ in 0..4 {
        // SAFETY: buf имеет не менее `size` байт и выровнен по 8; size это
        // выходной/входной параметр API; reserved должен быть NULL.
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                std::ptr::null(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if rc == ERROR_BUFFER_OVERFLOW {
            buf = vec![0; (size as usize).div_ceil(8)];
            continue;
        }
        assert_eq!(rc, 0, "GetAdaptersAddresses failed with error {rc}");
        let mut p = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !p.is_null() {
            // SAFETY: p указывает на узел списка внутри buf (заполнен API,
            // buf жив); Next ведёт в тот же буфер или NULL.
            let a = unsafe { &*p };
            if !a.AdapterName.is_null() {
                // SAFETY: AdapterName NUL-терминированная строка внутри buf.
                let name = unsafe { CStr::from_ptr(a.AdapterName as *const c_char) };
                if name.to_string_lossy().eq_ignore_ascii_case(guid) && a.PhysicalAddressLength == 6
                {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&a.PhysicalAddress[..6]);
                    return Some(mac);
                }
            }
            p = a.Next;
        }
        return None;
    }
    panic!("GetAdaptersAddresses kept overflowing");
}

/// Паникует, если `device` (`\Device\NPF_{GUID}`) не имеет MAC `expected`.
pub fn verify_device_mac(device: &str, expected: [u8; 6]) {
    let guid = device
        .strip_prefix("\\Device\\NPF_")
        .unwrap_or_else(|| panic!("not an NPF device name: {device:?}"));
    let got = adapter_mac_by_guid(guid)
        .unwrap_or_else(|| panic!("no Windows adapter with GUID {guid} (device {device:?})"));
    assert_eq!(
        got, expected,
        "REFUSING TO SEND: device {device} has MAC {got:02x?}, the lab binding says {expected:02x?}"
    );
}
