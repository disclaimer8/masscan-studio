//! Подставной загрузчик и таблица функций: Npcap не нужен, порядок
//! create/close/unload фиксируется в журнале потока.

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::mem::{align_of, offset_of, size_of};
use std::sync::Arc;

use super::ffi::*;
use super::handle::*;
use super::loader::*;
use crate::NetError;

const GOOD_PATH: &str = "C:\\Windows\\System32\\Npcap\\wpcap.dll";
const DEV1: &str = "\\Device\\NPF_{11111111-2222-3333-4444-555555555555}";
const DEV2: &str = "\\Device\\NPF_{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}";
const LOOP: &str = "\\Device\\NPF_Loopback";

// ---------- журнал и сценарий (на поток теста) ----------

#[derive(Default)]
struct Scenario {
    log: Vec<String>,
    version_null: bool,
    activate_rc: c_int,
    dlt: c_int,
    devices: Vec<(String, Option<String>, u32)>,
    findalldevs_rc: c_int,
    create_null: bool,
    /// Узлы списка устройств, выданные findalldevs (освобождает freealldevs).
    #[allow(clippy::vec_box)] // узлы обязаны иметь стабильные адреса
    lists: Vec<Vec<Box<PcapIf>>>,
}

thread_local! {
    static S: RefCell<Scenario> = RefCell::new(Scenario::default());
}

fn log(s: &str) {
    S.with(|x| x.borrow_mut().log.push(s.to_string()));
}
fn events() -> Vec<String> {
    S.with(|x| x.borrow().log.clone())
}
fn reset(f: impl FnOnce(&mut Scenario)) {
    S.with(|x| {
        let mut s = x.borrow_mut();
        *s = Scenario {
            dlt: DLT_EN10MB,
            devices: vec![
                (DEV1.into(), Some("Intel(R) Ethernet".into()), 0),
                (DEV2.into(), None, 0),
                (
                    LOOP.into(),
                    Some("Adapter for loopback".into()),
                    PCAP_IF_LOOPBACK,
                ),
            ],
            ..Scenario::default()
        };
        f(&mut s);
    });
}
fn pos(ev: &[String], what: &str) -> usize {
    ev.iter()
        .position(|e| e == what)
        .unwrap_or_else(|| panic!("{what} missing in {ev:?}"))
}

// ---------- подставные функции wpcap ----------

static VERSION: &[u8] = b"Npcap version 1.90, based on libpcap 1.10.7\0";
const FAKE_T: usize = 0x1000;

unsafe extern "C" fn f_lib_version() -> *const c_char {
    log("lib_version");
    if S.with(|x| x.borrow().version_null) {
        std::ptr::null()
    } else {
        VERSION.as_ptr().cast()
    }
}
unsafe extern "C" fn f_findalldevs(out: *mut *mut PcapIf, err: *mut c_char) -> c_int {
    log("findalldevs");
    S.with(|x| {
        let mut s = x.borrow_mut();
        if s.findalldevs_rc != 0 {
            let msg = b"enum failed\0";
            // SAFETY: тестовый буфер имеет PCAP_ERRBUF_SIZE байт.
            unsafe { std::ptr::copy_nonoverlapping(msg.as_ptr().cast(), err, msg.len()) };
            return s.findalldevs_rc;
        }
        let mut nodes: Vec<Box<PcapIf>> = Vec::new();
        for (name, desc, flags) in s.devices.clone() {
            nodes.push(Box::new(PcapIf {
                next: std::ptr::null_mut(),
                name: CString::new(name).unwrap().into_raw(),
                description: desc
                    .map(|d| CString::new(d).unwrap().into_raw())
                    .unwrap_or(std::ptr::null_mut()),
                addresses: std::ptr::null_mut(),
                flags,
            }));
        }
        for i in (0..nodes.len().saturating_sub(1)).rev() {
            let next: *mut PcapIf = &mut *nodes[i + 1];
            nodes[i].next = next;
        }
        let head: *mut PcapIf = nodes
            .first_mut()
            .map(|b| &mut **b as *mut PcapIf)
            .unwrap_or(std::ptr::null_mut());
        s.lists.push(nodes);
        // SAFETY: out валидный выходной указатель вызывающего.
        unsafe { *out = head };
        0
    })
}
unsafe extern "C" fn f_freealldevs(_head: *mut PcapIf) {
    log("freealldevs");
}
unsafe extern "C" fn f_create(_d: *const c_char, err: *mut c_char) -> *mut PcapT {
    log("create");
    if S.with(|x| x.borrow().create_null) {
        let msg = b"no such device\0";
        // SAFETY: тестовый буфер имеет PCAP_ERRBUF_SIZE байт.
        unsafe { std::ptr::copy_nonoverlapping(msg.as_ptr().cast(), err, msg.len()) };
        return std::ptr::null_mut();
    }
    FAKE_T as *mut PcapT
}
unsafe extern "C" fn f_set_snaplen(_p: *mut PcapT, _v: c_int) -> c_int {
    log("set_snaplen");
    0
}
unsafe extern "C" fn f_set_promisc(_p: *mut PcapT, _v: c_int) -> c_int {
    log("set_promisc");
    0
}
unsafe extern "C" fn f_set_timeout(_p: *mut PcapT, _v: c_int) -> c_int {
    log("set_timeout");
    0
}
unsafe extern "C" fn f_set_immediate(_p: *mut PcapT, _v: c_int) -> c_int {
    log("set_immediate_mode");
    0
}
unsafe extern "C" fn f_set_buffer(_p: *mut PcapT, _v: c_int) -> c_int {
    log("set_buffer_size");
    0
}
unsafe extern "C" fn f_activate(_p: *mut PcapT) -> c_int {
    log("activate");
    S.with(|x| x.borrow().activate_rc)
}
unsafe extern "C" fn f_open_live(
    _d: *const c_char,
    _s: c_int,
    _p: c_int,
    _t: c_int,
    _e: *mut c_char,
) -> *mut PcapT {
    log("open_live");
    FAKE_T as *mut PcapT
}
unsafe extern "C" fn f_next_ex(
    _p: *mut PcapT,
    _h: *mut *mut PcapPkthdr,
    _d: *mut *const u8,
) -> c_int {
    0
}
unsafe extern "C" fn f_sendpacket(_p: *mut PcapT, _b: *const u8, _n: c_int) -> c_int {
    0
}
unsafe extern "C" fn f_datalink(_p: *mut PcapT) -> c_int {
    S.with(|x| x.borrow().dlt)
}
unsafe extern "C" fn f_geterr(_p: *mut PcapT) -> *mut c_char {
    c"fake driver says no".as_ptr() as *mut c_char
}
unsafe extern "C" fn f_stats(_p: *mut PcapT, _s: *mut PcapStat) -> c_int {
    0
}
unsafe extern "C" fn f_close(_p: *mut PcapT) {
    log("close");
}

fn symbol_addr(name: &str) -> Option<*const c_void> {
    Some(match name {
        "pcap_lib_version" => f_lib_version as *const c_void,
        "pcap_findalldevs" => f_findalldevs as *const c_void,
        "pcap_freealldevs" => f_freealldevs as *const c_void,
        "pcap_create" => f_create as *const c_void,
        "pcap_set_snaplen" => f_set_snaplen as *const c_void,
        "pcap_set_promisc" => f_set_promisc as *const c_void,
        "pcap_set_timeout" => f_set_timeout as *const c_void,
        "pcap_set_immediate_mode" => f_set_immediate as *const c_void,
        "pcap_set_buffer_size" => f_set_buffer as *const c_void,
        "pcap_activate" => f_activate as *const c_void,
        "pcap_open_live" => f_open_live as *const c_void,
        "pcap_next_ex" => f_next_ex as *const c_void,
        "pcap_sendpacket" => f_sendpacket as *const c_void,
        "pcap_datalink" => f_datalink as *const c_void,
        "pcap_geterr" => f_geterr as *const c_void,
        "pcap_stats" => f_stats as *const c_void,
        "pcap_close" => f_close as *const c_void,
        _ => return None,
    })
}

// ---------- подставные Module/Loader ----------

struct FakeModule {
    missing: Vec<&'static str>,
}
impl Module for FakeModule {
    fn symbol(&self, name: &CStr) -> Option<*const c_void> {
        let n = name.to_str().ok()?;
        if self.missing.contains(&n) {
            return None;
        }
        symbol_addr(n)
    }
    fn describe(&self) -> Result<Vec<DllInfo>, NetError> {
        Ok(vec![DllInfo {
            name: "wpcap.dll".into(),
            path: GOOD_PATH.into(),
            sha256: "00".repeat(32),
            version: Some("1.90.0.0".into()),
        }])
    }
}
impl Drop for FakeModule {
    fn drop(&mut self) {
        log("unload");
    }
}

struct FakeLoader {
    result: Result<Vec<&'static str>, LoadFailure>,
}
impl Loader for FakeLoader {
    fn load(&self, full_path: &str) -> Result<Box<dyn Module>, LoadFailure> {
        log(&format!("load {full_path}"));
        match &self.result {
            Ok(missing) => Ok(Box::new(FakeModule {
                missing: missing.clone(),
            })),
            Err(f) => Err(f.clone()),
        }
    }
}

fn good_api() -> Arc<NpcapApi> {
    NpcapApi::load_with(&FakeLoader { result: Ok(vec![]) }, GOOD_PATH).unwrap()
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
    };
    let e = NpcapApi::load_with(&l, GOOD_PATH).unwrap_err();
    assert!(matches!(e, NetError::AbiMismatch(_)), "{e:?}");
}

#[test]
fn other_os_failure_is_driver_unavailable() {
    reset(|_| {});
    let l = FakeLoader {
        result: Err(LoadFailure::Other("os error 5".into())),
    };
    assert!(matches!(
        NpcapApi::load_with(&l, GOOD_PATH),
        Err(NetError::DriverUnavailable(_))
    ));
}

#[test]
fn init_failure_null_version_is_driver_unavailable_and_unloads() {
    reset(|s| s.version_null = true);
    let e = NpcapApi::load_with(&FakeLoader { result: Ok(vec![]) }, GOOD_PATH).unwrap_err();
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
    assert_eq!(api.diagnostics().len(), 1);
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
    // Журнал потоковый: проверяем только компиляцию Send и отсутствие паник.
    std::thread::spawn(move || {
        let _ = h.datalink();
    })
    .join()
    .unwrap();
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
}
