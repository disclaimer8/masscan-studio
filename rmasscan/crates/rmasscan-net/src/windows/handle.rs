//! Владеемые handle Npcap и перечисление устройств.
//!
//! Send/Sync для [`PcapHandle`]. `pcap_t` не привязан к потоку, поэтому
//! перенос владения между потоками (`Send`) допустим: адаптер передаёт TX и RX
//! handle своим worker-потокам. `Sync` НЕ реализуется: libpcap не
//! синхронизирует один `pcap_t` (ни кадровый буфер, ни `pcap_geterr`), поэтому
//! одновременный доступ из двух потоков запрещён типом. Каждый handle
//! принадлежит ровно одному worker. Библиотека живёт, пока жив любой handle
//! (`Arc<NpcapApi>` в поле), и выгружается после `pcap_close` последнего.

use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr::{self, NonNull};
use std::sync::Arc;

use super::ffi::{DLT_EN10MB, DLT_IEEE802_11_RADIO, DLT_NULL, PCAP_ERRBUF_SIZE, PcapIf, PcapT};
use super::loader::NpcapApi;
use crate::NetError;

/// Верхняя граница длины имени устройства (`\Device\NPF_{GUID}` это 49 байт).
pub(crate) const MAX_DEVICE_NAME: usize = 1024;

const PCAP_ERROR_NO_SUCH_DEVICE: c_int = -5;
const PCAP_ERROR_PERM_DENIED: c_int = -8;
const PCAP_ERROR_PROMISC_PERM_DENIED: c_int = -11;

fn errbuf_text(buf: &[c_char; PCAP_ERRBUF_SIZE]) -> String {
    // SAFETY: буфер имеет размер PCAP_ERRBUF_SIZE и обнулён перед вызовом;
    // библиотека пишет NUL-терминированную строку не длиннее буфера.
    let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
    s.to_string_lossy().into_owned()
}

/// Параметры открытия.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OpenParams {
    pub snaplen: i32,
    pub promisc: bool,
    pub timeout_ms: i32,
    pub immediate: bool,
    pub buffer_bytes: i32,
}

/// Владеемый активированный `pcap_t`.
pub(crate) struct PcapHandle {
    raw: NonNull<PcapT>,
    // Последним: выгрузка библиотеки после `pcap_close` в Drop.
    api: Arc<NpcapApi>,
}

// SAFETY: pcap_t не имеет потоковой привязки; PcapHandle единственный владелец
// указателя и не клонируется. `Sync` намеренно не реализован.
unsafe impl Send for PcapHandle {}

impl Drop for PcapHandle {
    fn drop(&mut self) {
        // SAFETY: raw получен из pcap_create/pcap_open_live этой же
        // библиотеки, ещё не закрыт (Drop выполняется один раз), api держит
        // DLL загруженной.
        unsafe { (self.api.fns.close)(self.raw.as_ptr()) };
    }
}

impl PcapHandle {
    /// create + настройки + activate. Любая ошибка после `pcap_create`
    /// закрывает handle (Drop) раньше, чем отпускается `Arc` библиотеки.
    pub(crate) fn open(
        api: &Arc<NpcapApi>,
        device: &CStr,
        p: OpenParams,
    ) -> Result<PcapHandle, NetError> {
        let mut err = [0 as c_char; PCAP_ERRBUF_SIZE];
        // SAFETY: device NUL-терминирован, err имеет размер PCAP_ERRBUF_SIZE.
        let raw = unsafe { (api.fns.create)(device.as_ptr(), err.as_mut_ptr()) };
        let Some(raw) = NonNull::new(raw) else {
            return Err(NetError::System(format!(
                "pcap_create failed: {}",
                errbuf_text(&err)
            )));
        };
        let h = PcapHandle {
            raw,
            api: Arc::clone(api),
        };
        h.set("pcap_set_snaplen", h.api.fns.set_snaplen, p.snaplen)?;
        h.set(
            "pcap_set_promisc",
            h.api.fns.set_promisc,
            p.promisc as c_int,
        )?;
        h.set("pcap_set_timeout", h.api.fns.set_timeout, p.timeout_ms)?;
        h.set(
            "pcap_set_immediate_mode",
            h.api.fns.set_immediate_mode,
            p.immediate as c_int,
        )?;
        h.set(
            "pcap_set_buffer_size",
            h.api.fns.set_buffer_size,
            p.buffer_bytes,
        )?;
        // SAFETY: raw валиден и принадлежит h.
        let rc = unsafe { (h.api.fns.activate)(h.raw.as_ptr()) };
        if rc < 0 {
            return Err(map_activate_error(rc, &h.last_error()));
        }
        Ok(h)
    }

    fn set(&self, what: &str, f: super::ffi::SetIntFn, v: c_int) -> Result<(), NetError> {
        // SAFETY: raw валиден; f разрешён из той же библиотеки.
        let rc = unsafe { f(self.raw.as_ptr(), v) };
        if rc != 0 {
            return Err(NetError::System(format!("{what} failed: code {rc}")));
        }
        Ok(())
    }

    /// Текст последней ошибки handle (`pcap_geterr`), копия.
    pub(crate) fn last_error(&self) -> String {
        // SAFETY: raw валиден; geterr возвращает указатель на внутренний
        // буфер pcap_t, мы копируем его до любого другого вызова.
        let p = unsafe { (self.api.fns.geterr)(self.raw.as_ptr()) };
        if p.is_null() {
            return String::new();
        }
        // SAFETY: p не NULL, NUL-терминированная строка внутри pcap_t.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }

    /// Тип канала (`DLT_*`).
    pub(crate) fn datalink(&self) -> i32 {
        // SAFETY: raw валиден и активирован.
        unsafe { (self.api.fns.datalink)(self.raw.as_ptr()) }
    }

    /// Открывает адаптер и требует Ethernet; иначе закрывает handle.
    pub(crate) fn open_ethernet(
        api: &Arc<NpcapApi>,
        device: &CStr,
        p: OpenParams,
    ) -> Result<PcapHandle, NetError> {
        let h = PcapHandle::open(api, device, p)?;
        check_link(h.datalink())?;
        Ok(h)
    }
}

fn map_activate_error(rc: c_int, msg: &str) -> NetError {
    let text = format!("pcap_activate failed (code {rc}): {msg}");
    match rc {
        PCAP_ERROR_NO_SUCH_DEVICE => NetError::InterfaceMismatch(text),
        PCAP_ERROR_PERM_DENIED | PCAP_ERROR_PROMISC_PERM_DENIED => NetError::PermissionDenied(text),
        _ => NetError::System(text),
    }
}

/// Принимается только Ethernet. Loopback (`DLT_NULL`) и 802.11/monitor не
/// интерпретируются как Ethernet.
pub(crate) fn check_link(dlt: i32) -> Result<(), NetError> {
    match dlt {
        DLT_EN10MB => Ok(()),
        DLT_NULL => Err(NetError::UnsupportedLink(
            "loopback (DLT_NULL) is not Ethernet".into(),
        )),
        DLT_IEEE802_11_RADIO | 105 | 119 | 163 => Err(NetError::UnsupportedLink(format!(
            "802.11/monitor link type {dlt} is not Ethernet"
        ))),
        other => Err(NetError::UnsupportedLink(format!(
            "DLT {other} is not Ethernet (DLT_EN10MB)"
        ))),
    }
}

/// Устройство из `pcap_findalldevs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceInfo {
    pub name: String,
    pub description: Option<String>,
    pub flags: u32,
}

/// `pcap_freealldevs` по выходу из области видимости.
struct DevList<'a> {
    head: *mut PcapIf,
    api: &'a NpcapApi,
}

impl Drop for DevList<'_> {
    fn drop(&mut self) {
        if !self.head.is_null() {
            // SAFETY: head получен из pcap_findalldevs этой библиотеки и
            // ещё не освобождён.
            unsafe { (self.api.fns.freealldevs)(self.head) };
        }
    }
}

/// Перечисляет устройства; строки копируются до `pcap_freealldevs`.
pub(crate) fn list_devices(api: &NpcapApi) -> Result<Vec<DeviceInfo>, NetError> {
    let mut head: *mut PcapIf = ptr::null_mut();
    let mut err = [0 as c_char; PCAP_ERRBUF_SIZE];
    // SAFETY: head и err это валидные выходные буферы нужных размеров.
    let rc = unsafe { (api.fns.findalldevs)(&mut head, err.as_mut_ptr()) };
    let list = DevList { head, api };
    if rc != 0 {
        return Err(NetError::System(format!(
            "pcap_findalldevs failed: {}",
            errbuf_text(&err)
        )));
    }
    let mut out = Vec::new();
    let mut cur = list.head;
    while !cur.is_null() {
        // SAFETY: cur это узел связного списка, принадлежащего list; узлы
        // живут до freealldevs в Drop списка.
        let node = unsafe { &*cur };
        if !node.name.is_null() {
            // SAFETY: name не NULL, NUL-терминирован, принадлежит узлу.
            let name = unsafe { CStr::from_ptr(node.name) }
                .to_string_lossy()
                .into_owned();
            let description = if node.description.is_null() {
                None
            } else {
                // SAFETY: description не NULL, NUL-терминирован.
                Some(
                    unsafe { CStr::from_ptr(node.description) }
                        .to_string_lossy()
                        .into_owned(),
                )
            };
            out.push(DeviceInfo {
                name,
                description,
                flags: node.flags,
            });
        }
        cur = node.next;
    }
    Ok(out)
}

/// Проверяет имя `interface_id` и сопоставляет его с перечнем API.
/// Возвращает каноническое имя из перечня.
pub(crate) fn resolve_device(api: &NpcapApi, interface_id: &str) -> Result<CString, NetError> {
    if interface_id.is_empty() || interface_id.len() > MAX_DEVICE_NAME {
        return Err(NetError::InterfaceMismatch(format!(
            "device name length {} is outside 1..={MAX_DEVICE_NAME}",
            interface_id.len()
        )));
    }
    if interface_id.contains('\0') {
        return Err(NetError::InterfaceMismatch(
            "device name contains an interior NUL".into(),
        ));
    }
    let devices = list_devices(api)?;
    let found = devices
        .iter()
        .find(|d| d.name.eq_ignore_ascii_case(interface_id));
    match found {
        // Имя из перечня не содержит NUL (получено из CStr).
        Some(d) => CString::new(d.name.as_bytes())
            .map_err(|_| NetError::InterfaceMismatch("device name contains NUL".into())),
        None => Err(NetError::InterfaceMismatch(format!(
            "no Npcap device named {interface_id:?} ({} devices enumerated)",
            devices.len()
        ))),
    }
}
