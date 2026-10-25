//! Подставной загрузчик и таблица функций: Npcap не нужен, порядок
//! create/close/unload фиксируется в журнале сценария (см. `fake`).

use std::ffi::{CStr, CString, c_char, c_void};
use std::mem::{align_of, offset_of, size_of};
use std::sync::Arc;

mod adapter_tests;
mod fake;

use super::ffi::*;
use super::handle::*;
use super::loader::*;
use crate::NetError;
use fake::*;

// ---------- подставные Module/Loader ----------

struct FakeModule {
    no_init: bool,
    missing: Vec<&'static str>,
    null_syms: Vec<&'static str>,
    diag: Vec<DllInfo>,
}

fn good_diag() -> Vec<DllInfo> {
    let mk = |name: &str, path: &str| DllInfo {
        name: name.into(),
        path: path.into(),
        sha256: "00".repeat(32),
        version: Some("1.90.0.0".into()),
    };
    vec![
        mk("wpcap.dll", GOOD_PATH),
        mk("Packet.dll", "C:\\Windows\\System32\\Npcap\\Packet.dll"),
    ]
}
// SAFETY: символы возвращают реальные тестовые функции с верными сигнатурами.
unsafe impl Module for FakeModule {
    fn symbol(&self, name: &CStr) -> Option<*const c_void> {
        let n = name.to_str().ok()?;
        if n == "pcap_init" && self.no_init {
            return None;
        }
        if self.missing.contains(&n) {
            return None;
        }
        if self.null_syms.contains(&n) {
            return Some(std::ptr::null());
        }
        symbol_addr(n)
    }
    fn describe(&self) -> Result<Vec<DllInfo>, NetError> {
        Ok(self.diag.clone())
    }
}
impl Drop for FakeModule {
    fn drop(&mut self) {
        log("unload");
    }
}

struct FakeLoader {
    no_init: bool,
    result: Result<Vec<&'static str>, LoadFailure>,
    null_syms: Vec<&'static str>,
    diag: Option<Vec<DllInfo>>,
}
impl FakeLoader {
    fn ok() -> Self {
        FakeLoader {
            no_init: false,
            result: Ok(vec![]),
            null_syms: vec![],
            diag: None,
        }
    }
}
impl Loader for FakeLoader {
    fn load(&self, full_path: &str) -> Result<Box<dyn Module>, LoadFailure> {
        log(&format!("load {full_path}"));
        match &self.result {
            Ok(missing) => Ok(Box::new(FakeModule {
                no_init: self.no_init,
                missing: missing.clone(),
                null_syms: self.null_syms.clone(),
                diag: self.diag.clone().unwrap_or_else(good_diag),
            })),
            Err(f) => Err(f.clone()),
        }
    }
}

fn good_api() -> Arc<NpcapApi> {
    NpcapApi::load_with(&FakeLoader::ok(), GOOD_PATH).unwrap()
}

const PARAMS: OpenParams = OpenParams {
    snaplen: 2048,
    promisc: false,
    timeout_ms: 20,
    immediate: true,
    buffer_bytes: 1 << 20,
};

fn dev(s: &str) -> CString {
    CString::new(s).unwrap()
}

// ---------- загрузка ----------

#[test]
fn dll_missing_is_driver_unavailable_and_nothing_to_unload() {
    reset(|_| {});
    let l = FakeLoader {
        result: Err(LoadFailure::NotFound("os error 126".into())),
        ..FakeLoader::ok()
    };
    let e = NpcapApi::load_with(&l, GOOD_PATH).unwrap_err();
    assert!(
        matches!(e, NetError::DriverUnavailable(ref m) if m.contains("never installs")),
        "{e:?}"
    );
    assert_eq!(events(), [format!("load {GOOD_PATH}")]);
}

#[test]
fn missing_symbol_is_missing_capability_naming_it_and_unloads() {
    reset(|_| {});
    let l = FakeLoader {
        result: Ok(vec!["pcap_set_immediate_mode", "pcap_stats"]),
        ..FakeLoader::ok()
    };
    let e = NpcapApi::load_with(&l, GOOD_PATH).unwrap_err();
    match e {
        NetError::MissingCapability(m) => {
            assert!(
                m.contains("pcap_set_immediate_mode") && m.contains("pcap_stats"),
                "{m}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(events().last().unwrap(), "unload");
}

#[test]
fn wrong_architecture_is_abi_mismatch() {
    reset(|_| {});
    let l = FakeLoader {
        result: Err(LoadFailure::BadImage("os error 193".into())),
        ..FakeLoader::ok()
    };
    let e = NpcapApi::load_with(&l, GOOD_PATH).unwrap_err();
    assert!(matches!(e, NetError::AbiMismatch(_)), "{e:?}");
}

#[test]
fn other_os_failure_is_driver_unavailable() {
    reset(|_| {});
    let l = FakeLoader {
        result: Err(LoadFailure::Other("os error 5".into())),
        ..FakeLoader::ok()
    };
    assert!(matches!(
        NpcapApi::load_with(&l, GOOD_PATH),
        Err(NetError::DriverUnavailable(_))
    ));
}

#[test]
fn init_failure_null_version_is_driver_unavailable_and_unloads() {
    reset(|s| s.version_null = true);
    let e = NpcapApi::load_with(&FakeLoader::ok(), GOOD_PATH).unwrap_err();
    assert!(matches!(e, NetError::DriverUnavailable(_)), "{e:?}");
    assert_eq!(events().last().unwrap(), "unload");
}

#[test]
fn successful_load_exposes_version_and_diagnostics() {
    reset(|_| {});
    let api = good_api();
    assert_eq!(
        api.lib_version(),
        "Npcap version 1.90, based on libpcap 1.10.7"
    );
    assert_eq!(api.diagnostics().len(), 2);
    assert_eq!(api.diagnostics()[0].version.as_deref(), Some("1.90.0.0"));
    assert!(!events().contains(&"unload".to_string()));
}

// ---------- владение: порядок close/unload ----------

#[test]
fn close_after_partial_open_precedes_unload() {
    reset(|s| s.activate_rc = -1);
    let api = good_api();
    let e = PcapHandle::open(&api, &dev(DEV1), PARAMS).err().unwrap();
    assert!(
        matches!(e, NetError::System(ref m) if m.contains("fake driver says no")),
        "{e:?}"
    );
    let ev = events();
    assert!(pos(&ev, "create") < pos(&ev, "activate"));
    assert!(pos(&ev, "activate") < pos(&ev, "close"));
    assert!(
        !ev.contains(&"unload".to_string()),
        "api still held: {ev:?}"
    );
    drop(api);
    let ev = events();
    assert!(pos(&ev, "close") < pos(&ev, "unload"), "{ev:?}");
    assert_eq!(ev.iter().filter(|e| *e == "close").count(), 1);
}

#[test]
fn activate_error_codes_are_mapped() {
    for (rc, want) in [
        (-5, "mismatch"),
        (-8, "perm"),
        (-11, "perm"),
        (-3, "system"),
    ] {
        reset(|s| s.activate_rc = rc);
        let api = good_api();
        let e = PcapHandle::open(&api, &dev(DEV1), PARAMS).err().unwrap();
        let got = match e {
            NetError::InterfaceMismatch(_) => "mismatch",
            NetError::PermissionDenied(_) => "perm",
            NetError::System(_) => "system",
            other => panic!("{other:?}"),
        };
        assert_eq!(got, want, "rc {rc}");
    }
}

#[test]
fn positive_activate_warning_is_accepted() {
    reset(|s| s.activate_rc = 2);
    let api = good_api();
    assert!(PcapHandle::open(&api, &dev(DEV1), PARAMS).is_ok());
}

#[test]
fn create_failure_leaves_nothing_to_close() {
    reset(|s| s.create_null = true);
    let api = good_api();
    let e = PcapHandle::open(&api, &dev(DEV1), PARAMS).err().unwrap();
    assert!(
        matches!(e, NetError::System(ref m) if m.contains("no such device")),
        "{e:?}"
    );
    assert!(!events().contains(&"close".to_string()));
}

#[test]
fn library_unloads_only_after_both_handles_close() {
    reset(|_| {});
    let api = good_api();
    let tx = PcapHandle::open(&api, &dev(DEV1), PARAMS).unwrap();
    let rx = PcapHandle::open(&api, &dev(DEV1), PARAMS).unwrap();
    drop(api);
    assert!(!events().contains(&"unload".to_string()));
    drop(tx);
    assert!(!events().contains(&"unload".to_string()));
    drop(rx);
    let ev = events();
    let closes: Vec<_> = ev
        .iter()
        .enumerate()
        .filter(|(_, e)| *e == "close")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(closes.len(), 2);
    assert!(closes[1] < pos(&ev, "unload"), "{ev:?}");
}

#[test]
fn handle_moves_to_another_thread_and_closes_there_before_unload() {
    reset(|_| {});
    let api = good_api();
    let h = PcapHandle::open(&api, &dev(DEV1), PARAMS).unwrap();
    drop(api);
    // Журнал общий (STATE глобален), поэтому закрытие в другом потоке видно.
    std::thread::spawn(move || {
        let _ = h.datalink();
    })
    .join()
    .unwrap();
    let ev = events();
    assert_eq!(count("close:1"), 1, "{ev:?}");
    assert!(pos(&ev, "close:1") < pos(&ev, "unload"), "{ev:?}");
}

#[test]
fn ownership_types_have_the_intended_auto_traits() {
    fn send<T: Send>() {}
    fn send_sync<T: Send + Sync>() {}
    send::<PcapHandle>();
    send_sync::<NpcapApi>();
    send_sync::<PcapFns>();
}

// ---------- канал ----------

#[test]
fn ethernet_is_accepted_loopback_and_monitor_are_unsupported_link() {
    assert!(check_link(DLT_EN10MB).is_ok());
    for dlt in [DLT_NULL, DLT_IEEE802_11_RADIO, 105, 119, 12] {
        assert!(
            matches!(check_link(dlt), Err(NetError::UnsupportedLink(_))),
            "dlt {dlt}"
        );
    }
}

#[test]
fn open_ethernet_closes_a_non_ethernet_handle() {
    reset(|s| s.dlt = DLT_NULL);
    let api = good_api();
    let e = PcapHandle::open_ethernet(&api, &dev(LOOP), PARAMS)
        .err()
        .unwrap();
    assert!(matches!(e, NetError::UnsupportedLink(_)), "{e:?}");
    assert!(events().contains(&"close".to_string()));
}

// ---------- устройства ----------

#[test]
fn enumerates_devices_and_frees_the_list_once() {
    reset(|_| {});
    let api = good_api();
    let d = list_devices(&api).unwrap();
    assert_eq!(d.len(), 3);
    assert_eq!(d[0].name, DEV1);
    assert_eq!(d[0].description.as_deref(), Some("Intel(R) Ethernet"));
    assert_eq!(d[1].description, None);
    assert_eq!(d[2].flags & PCAP_IF_LOOPBACK, PCAP_IF_LOOPBACK);
    assert_eq!(events().iter().filter(|e| *e == "freealldevs").count(), 1);
}

#[test]
fn empty_device_list_is_ok_and_not_freed() {
    reset(|s| s.devices.clear());
    let api = good_api();
    assert!(list_devices(&api).unwrap().is_empty());
}

#[test]
fn findalldevs_failure_is_reported() {
    reset(|s| s.findalldevs_rc = -1);
    let api = good_api();
    let e = list_devices(&api).unwrap_err();
    assert!(
        matches!(e, NetError::System(ref m) if m.contains("enum failed")),
        "{e:?}"
    );
}

#[test]
fn resolve_refuses_the_loopback_adapter_before_any_open() {
    reset(|_| {});
    let api = good_api();
    let e = resolve_device(&api, LOOP).unwrap_err();
    assert!(matches!(e, NetError::UnsupportedLink(_)), "{e:?}");
    assert_eq!(count("create"), 0);
}

#[test]
fn resolve_accepts_backslash_name_any_case_and_returns_canonical() {
    reset(|_| {});
    let api = good_api();
    let c = resolve_device(&api, &DEV1.to_ascii_lowercase()).unwrap();
    assert_eq!(c.to_str().unwrap(), DEV1);
}

#[test]
fn resolve_rejects_nul_empty_long_and_unknown() {
    reset(|_| {});
    let api = good_api();
    for bad in [
        "".to_string(),
        format!("{DEV1}\0evil"),
        "x".repeat(MAX_DEVICE_NAME + 1),
        "\\Device\\NPF_{00000000-0000-0000-0000-000000000000}".to_string(),
        "eth0".to_string(),
    ] {
        let e = resolve_device(&api, &bad).unwrap_err();
        assert!(
            matches!(e, NetError::InterfaceMismatch(_)),
            "{bad:?}: {e:?}"
        );
    }
    // NUL и длина отклоняются ДО обращения к драйверу.
    reset(|_| {});
    let api = good_api();
    let _ = resolve_device(&api, "a\0b");
    let _ = resolve_device(&api, &"y".repeat(5000));
    assert!(!events().contains(&"findalldevs".to_string()));
}

#[test]
fn resolve_accepts_a_name_at_the_length_limit_if_enumerated() {
    let long = format!("\\Device\\NPF_{}", "A".repeat(MAX_DEVICE_NAME - 12));
    assert_eq!(long.len(), MAX_DEVICE_NAME);
    reset(|s| s.devices = vec![(long.clone(), None, 0)]);
    let api = good_api();
    assert_eq!(resolve_device(&api, &long).unwrap().to_str().unwrap(), long);
}

// ---------- путь и хэш ----------

#[test]
fn dll_path_is_built_from_an_absolute_system_directory_only() {
    assert_eq!(npcap_dll_path("C:\\Windows\\System32").unwrap(), GOOD_PATH);
    assert_eq!(
        npcap_dll_path("C:\\Windows\\System32\\").unwrap(),
        GOOD_PATH
    );
    assert_eq!(
        npcap_dll_path("\\\\srv\\share\\System32").unwrap(),
        "\\\\srv\\share\\System32\\Npcap\\wpcap.dll"
    );
    for bad in [
        "",
        "System32",
        ".\\System32",
        "Npcap",
        "C:System32",
        "C:\\a\0b",
    ] {
        assert!(
            matches!(npcap_dll_path(bad), Err(NetError::DriverUnavailable(_))),
            "{bad:?}"
        );
    }
}

#[test]
fn sha256_known_vector() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

// ---------- раскладка во время выполнения (дублирует const-assert) ----------

#[test]
fn windows_abi_layout_matches_the_npcap_headers() {
    assert_eq!((size_of::<Timeval>(), align_of::<Timeval>()), (8, 4));
    assert_eq!(size_of::<PcapPkthdr>(), 16);
    assert_eq!(offset_of!(PcapPkthdr, caplen), 8);
    assert_eq!(size_of::<PcapStat>(), 24);
    assert_eq!(offset_of!(PcapStat, ps_ifdrop), 8);
    assert_eq!(size_of::<SockAddr>(), 16);
    assert_eq!(size_of::<PcapIf>(), 40);
    assert_eq!(offset_of!(PcapIf, flags), 32);
    assert_eq!(size_of::<PcapAddr>(), 40);
}

#[test]
fn required_symbols_are_unique_and_prefixed() {
    let mut v = REQUIRED_SYMBOLS.to_vec();
    v.sort_unstable();
    v.dedup();
    assert_eq!(v.len(), REQUIRED_SYMBOLS.len());
    assert!(REQUIRED_SYMBOLS.iter().all(|s| s.starts_with("pcap_")));
    for s in REQUIRED_SYMBOLS {
        assert!(symbol_addr(s).is_some(), "fake lacks {s}");
    }
    assert!(
        !REQUIRED_SYMBOLS.contains(&SYM_PCAP_INIT),
        "pcap_init is optional"
    );
    assert!(symbol_addr(SYM_PCAP_INIT).is_some());
}

// ---------- инварианты символов и модуля ----------

#[test]
fn null_symbol_address_is_rejected_as_missing_not_transmuted() {
    reset(|_| {});
    let l = FakeLoader {
        null_syms: vec!["pcap_activate", "pcap_close"],
        ..FakeLoader::ok()
    };
    match NpcapApi::load_with(&l, GOOD_PATH).unwrap_err() {
        NetError::MissingCapability(m) => {
            assert!(
                m.contains("pcap_activate") && m.contains("pcap_close"),
                "{m}"
            )
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(events().last().unwrap(), "unload");
}

#[test]
fn missing_packet_dll_is_rejected_and_unloads() {
    reset(|_| {});
    let mut d = good_diag();
    d.retain(|i| i.name != "Packet.dll");
    let l = FakeLoader {
        diag: Some(d),
        ..FakeLoader::ok()
    };
    let e = NpcapApi::load_with(&l, GOOD_PATH).unwrap_err();
    assert!(
        matches!(e, NetError::System(ref m) if m.contains("untrusted Npcap module") && m.contains("Packet.dll")),
        "{e:?}"
    );
    assert_eq!(events().last().unwrap(), "unload");
}

#[test]
fn packet_dll_from_another_directory_is_rejected() {
    reset(|_| {});
    let mut d = good_diag();
    d[1].path = "C:\\Users\\x\\Packet.dll".into();
    let l = FakeLoader {
        diag: Some(d),
        ..FakeLoader::ok()
    };
    assert!(matches!(
        NpcapApi::load_with(&l, GOOD_PATH),
        Err(NetError::System(_))
    ));
}

#[test]
fn wpcap_loaded_from_an_unrequested_path_is_rejected() {
    reset(|_| {});
    let mut d = good_diag();
    d[0].path = "C:\\Evil\\wpcap.dll".into();
    let l = FakeLoader {
        diag: Some(d),
        ..FakeLoader::ok()
    };
    let e = NpcapApi::load_with(&l, GOOD_PATH).unwrap_err();
    assert!(
        matches!(e, NetError::System(ref m) if m.contains("untrusted Npcap module") && m.contains("Evil")),
        "{e:?}"
    );
    assert_eq!(events().last().unwrap(), "unload");
}

#[test]
fn untrusted_module_is_rejected_before_any_export_runs() {
    reset(|_| {});
    let mut d = good_diag();
    d[0].path = "C:\\Evil\\wpcap.dll".into();
    let l = FakeLoader {
        diag: Some(d),
        ..FakeLoader::ok()
    };
    let e = NpcapApi::load_with(&l, GOOD_PATH).unwrap_err();
    assert!(matches!(e, NetError::System(_)), "{e:?}");
    let ev = events();
    assert!(
        !ev.iter()
            .any(|x| x.starts_with("init") || x == "lib_version"),
        "no export may run before the provenance check: {ev:?}"
    );
    assert_eq!(ev.last().unwrap(), "unload");
}

#[test]
fn diagnostic_paths_compare_case_insensitively() {
    reset(|_| {});
    let mut d = good_diag();
    d[0].path = GOOD_PATH.to_ascii_uppercase();
    d[1].path = d[1].path.to_ascii_lowercase();
    let l = FakeLoader {
        diag: Some(d),
        ..FakeLoader::ok()
    };
    assert!(NpcapApi::load_with(&l, GOOD_PATH).is_ok());
}

// ---------- DropCounter ----------

#[test]
fn drop_counter_is_cumulative_and_idempotent_on_repeated_reads() {
    let mut c = DropCounter::new(0);
    assert_eq!(c.update(0), 0);
    assert_eq!(c.update(5), 5);
    assert_eq!(c.update(5), 5);
    assert_eq!(c.update(9), 9);
}

#[test]
fn drop_counter_baseline_is_subtracted() {
    let mut c = DropCounter::new(1000);
    assert_eq!(c.update(1000), 0);
    assert_eq!(c.update(1007), 7);
}

#[test]
fn drop_counter_survives_u32_wraparound() {
    let mut c = DropCounter::new(u32::MAX - 2);
    assert_eq!(c.update(u32::MAX), 2);
    // 0 это следующее значение после u32::MAX: ещё одна потеря
    assert_eq!(c.update(0), 3);
    assert_eq!(c.update(4), 7);
}

#[test]
fn drop_counter_reset_looks_like_a_wrap_and_fails_safe() {
    let mut c = DropCounter::new(0);
    assert_eq!(c.update(10), 10);
    // сброс на 0: огромная дельта (RxLoss), но не 0 и не уменьшение
    assert!(c.update(0) > 10);
}

// ---------- перечень (--inventory) ----------

#[test]
fn inventory_lists_devices_without_opening_or_sending() {
    reset(|_| {});
    let api = good_api();
    let mac = [2, 0, 0, 0, 0, 9];
    let inv = super::inventory::build(
        &api,
        &|n| (n == DEV1).then_some(mac),
        Some("1.2.3.4".into()),
    )
    .unwrap();
    // Ни одного pcap_create (адаптер не открывался), ни одной отправки.
    let (creates, sends) = {
        let mut r = (0, 0);
        with(|s| r = (s.creates, s.send_calls));
        r
    };
    assert_eq!((creates, sends), (0, 0), "inventory must not open or send");
    assert_eq!(count("freealldevs"), 1);
    assert_eq!(inv.devices.len(), 3);
    assert_eq!(inv.devices[0].name, DEV1);
    assert_eq!(inv.devices[0].mac, Some(mac));
    assert_eq!(inv.devices[1].mac, None, "unknown MAC is None, not zeros");
    assert!(inv.devices[2].loopback && !inv.devices[0].loopback);
    assert_eq!(inv.lib_version, api.lib_version());
    assert_eq!(inv.driver_version.as_deref(), Some("1.2.3.4"));
    assert_eq!(inv.dlls.len(), api.diagnostics().len());
    assert!(inv.dlls.iter().all(|d| d.sha256.len() == 64));
}

#[test]
fn inventory_reports_enumeration_failure() {
    reset(|s| s.findalldevs_rc = -1);
    let api = good_api();
    assert!(matches!(
        super::inventory::build(&api, &|_| None, None),
        Err(NetError::System(_))
    ));
}

#[test]
fn npf_guid_is_extracted_only_from_a_wellformed_device_name() {
    use super::inventory::npf_guid;
    assert_eq!(
        npf_guid(DEV1),
        Some("{11111111-2222-3333-4444-555555555555}")
    );
    assert_eq!(npf_guid(LOOP), None);
    assert_eq!(npf_guid("\\Device\\NPF_{}"), None);
    assert_eq!(npf_guid("eth0"), None);
    assert_eq!(npf_guid("\\Device\\NPF_{abc"), None);
}

// ---------- Admin-only Npcap: имя не найдено из-за нехватки прав ----------

#[test]
fn resolve_with_only_loopback_visible_is_permission_denied() {
    reset(|s| s.devices = vec![(LOOP.into(), None, PCAP_IF_LOOPBACK)]);
    let api = good_api();
    let e = resolve_device(&api, DEV1).unwrap_err();
    assert!(
        matches!(e, NetError::PermissionDenied(ref m) if m.contains("Administrators-only")),
        "{e:?}"
    );
    with(|s| assert_eq!(s.creates, 0));
}

#[test]
fn resolve_with_an_empty_device_list_is_permission_denied() {
    reset(|s| s.devices.clear());
    let api = good_api();
    let e = resolve_device(&api, DEV1).unwrap_err();
    assert!(matches!(e, NetError::PermissionDenied(_)), "{e:?}");
    with(|s| assert_eq!(s.creates, 0));
}

#[test]
fn resolve_unknown_name_among_real_adapters_stays_interface_mismatch() {
    reset(|_| {});
    let api = good_api();
    let e =
        resolve_device(&api, "\\Device\\NPF_{00000000-0000-0000-0000-000000000000}").unwrap_err();
    assert!(matches!(e, NetError::InterfaceMismatch(_)), "{e:?}");
}

// ---------- ограниченное чтение буфера ошибки ----------

#[test]
fn errbuf_text_is_bounded_when_the_buffer_has_no_nul() {
    let buf = [b'x' as c_char; PCAP_ERRBUF_SIZE];
    let s = errbuf_text(&buf);
    assert_eq!(s.len(), PCAP_ERRBUF_SIZE);
    assert!(s.bytes().all(|b| b == b'x'));
}

#[test]
fn errbuf_text_stops_at_the_first_nul() {
    let mut buf = [0 as c_char; PCAP_ERRBUF_SIZE];
    for (i, b) in b"boom".iter().enumerate() {
        buf[i] = *b as c_char;
    }
    buf[10] = b'z' as c_char;
    assert_eq!(errbuf_text(&buf), "boom");
}
