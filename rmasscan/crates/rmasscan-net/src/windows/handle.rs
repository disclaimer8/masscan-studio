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

use super::ffi::{
    BPF_RET_K, BpfInsn, BpfProgram, DLT_EN10MB, DLT_IEEE802_11_RADIO, DLT_NULL, NEXT_EX_EOF,
    NEXT_EX_OK, NEXT_EX_TIMEOUT, PCAP_ERRBUF_SIZE, PCAP_IF_LOOPBACK, PCAP_NETMASK_UNKNOWN, PcapIf,
    PcapPkthdr, PcapStat, PcapT,
};
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
    /// Заданный `snaplen`: `caplen` больше него это нарушение контракта.
    snaplen: usize,
    // Последним: выгрузка библиотеки после `pcap_close` в Drop.
    api: Arc<NpcapApi>,
}

// SAFETY: pcap_t не имеет потоковой привязки; PcapHandle единственный владелец
// указателя и не клонируется. `Sync` намеренно не реализован.
unsafe impl Send for PcapHandle {}

impl Drop for PcapHandle {
    fn drop(&mut self) {
        // SAFETY: raw получен из pcap_create этой же
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
            snaplen: usize::try_from(p.snaplen).unwrap_or(0),
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

/// Результат одного чтения с копированием кадра в буфер вызывающего.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Polled {
    /// Кадр целиком (`caplen == len`) скопирован в начало буфера.
    Frame(usize),
    /// Кадр усечён (`caplen != len`) или не помещается в буфер: отброшен.
    Truncated,
    /// rc 0: нет кадра (в nonblocking режиме это «пусто»).
    Empty,
    /// rc -1 или неизвестный код: текст через `last_error`.
    Error(c_int),
    /// rc -2.
    Eof,
    /// Библиотека нарушила контракт (rc 1 с NULL-указателем или `caplen`
    /// больше `snaplen`): handle ненадёжен, кадр не читался.
    Malformed(&'static str),
}

/// Заимствующий результат для живого спайка (только тесты на Windows).
#[cfg(all(test, windows))]
#[derive(Debug)]
pub(crate) enum NextEx<'a> {
    Frame { hdr: PcapPkthdr, data: &'a [u8] },
    Timeout,
    Error(c_int),
    Eof,
}

/// Сырой результат `pcap_next_ex` после проверки указателей и `caplen`.
enum RawNext {
    Frame { hdr: PcapPkthdr, data: *const u8 },
    Empty,
    Error(c_int),
    Eof,
    Malformed(&'static str),
}

impl PcapHandle {
    /// `pcap_setnonblock`; при ошибке возвращает текст errbuf.
    pub(crate) fn set_nonblock(&mut self, on: bool) -> Result<(), NetError> {
        let mut err = [0 as c_char; PCAP_ERRBUF_SIZE];
        // SAFETY: raw валиден и активирован; err имеет PCAP_ERRBUF_SIZE байт.
        let rc =
            unsafe { (self.api.fns.setnonblock)(self.raw.as_ptr(), on as c_int, err.as_mut_ptr()) };
        if rc != 0 {
            return Err(NetError::System(format!(
                "pcap_setnonblock failed (code {rc}): {}",
                errbuf_text(&err)
            )));
        }
        Ok(())
    }

    /// `pcap_getnonblock`: 0/1, либо отрицательный код ошибки.
    pub(crate) fn get_nonblock(&mut self) -> c_int {
        let mut err = [0 as c_char; PCAP_ERRBUF_SIZE];
        // SAFETY: raw валиден и активирован; err имеет PCAP_ERRBUF_SIZE байт.
        unsafe { (self.api.fns.getnonblock)(self.raw.as_ptr(), err.as_mut_ptr()) }
    }

    /// Один `pcap_next_ex`. Указатель кадра действителен до следующего вызова
    /// на этом handle; `&mut self` не даёт сделать такой вызов, пока жив
    /// результат вызывающей функции.
    fn raw_next(&mut self) -> RawNext {
        let mut hdr: *mut PcapPkthdr = ptr::null_mut();
        let mut data: *const u8 = ptr::null();
        // SAFETY: raw валиден; hdr/data выходные указатели.
        let rc = unsafe { (self.api.fns.next_ex)(self.raw.as_ptr(), &mut hdr, &mut data) };
        match rc {
            NEXT_EX_OK => {
                if hdr.is_null() || data.is_null() {
                    return RawNext::Malformed("pcap_next_ex returned a frame with a NULL pointer");
                }
                // SAFETY: при rc == 1 hdr указывает на действительный
                // pcap_pkthdr внутри pcap_t (до следующего вызова); читаем
                // копию без предположений о выравнивании.
                let h = unsafe { ptr::read_unaligned(hdr) };
                if h.caplen as usize > self.snaplen {
                    return RawNext::Malformed("pcap_next_ex returned caplen above the snaplen");
                }
                RawNext::Frame { hdr: h, data }
            }
            NEXT_EX_TIMEOUT => RawNext::Empty,
            NEXT_EX_EOF => RawNext::Eof,
            other => RawNext::Error(other),
        }
    }

    /// Читает один кадр и НЕМЕДЛЕННО копирует его в `buf`: указатели pcap не
    /// покидают эту функцию. Длины проверяются до копирования: усечённый
    /// (`caplen != len`) и не помещающийся в `buf` кадр не копируется.
    pub(crate) fn poll_into(&mut self, buf: &mut [u8]) -> Polled {
        match self.raw_next() {
            RawNext::Frame { hdr, data } => {
                let caplen = hdr.caplen as usize;
                if caplen != hdr.len as usize || caplen > buf.len() {
                    return Polled::Truncated;
                }
                // SAFETY: data не NULL и по контракту pcap_next_ex указывает
                // на caplen читаемых байт до следующего вызова на этом handle
                // (`&mut self` не даёт его сделать); caplen <= snaplen и
                // caplen <= buf.len() проверены выше; буфер вызывающего не
                // пересекается с памятью pcap_t.
                unsafe { ptr::copy_nonoverlapping(data, buf.as_mut_ptr(), caplen) };
                Polled::Frame(caplen)
            }
            RawNext::Empty => Polled::Empty,
            RawNext::Error(rc) => Polled::Error(rc),
            RawNext::Eof => Polled::Eof,
            RawNext::Malformed(why) => Polled::Malformed(why),
        }
    }

    /// Заимствующее чтение для живого спайка (измеряет сам `pcap_next_ex`).
    #[cfg(all(test, windows))]
    pub(crate) fn next_ex(&mut self) -> NextEx<'_> {
        match self.raw_next() {
            RawNext::Frame { hdr, data } => {
                // SAFETY: data не NULL, caplen <= snaplen проверен в raw_next;
                // срез живёт не дольше заимствования `&mut self`.
                let d = unsafe { std::slice::from_raw_parts(data, hdr.caplen as usize) };
                NextEx::Frame { hdr, data: d }
            }
            RawNext::Empty => NextEx::Timeout,
            RawNext::Error(rc) => NextEx::Error(rc),
            RawNext::Eof => NextEx::Eof,
            RawNext::Malformed(_) => NextEx::Error(-1),
        }
    }

    /// Синхронный `pcap_sendpacket`: сырой код (0 успех, иначе ошибка). Кадр
    /// длиннее `i32::MAX` отвергается без вызова (-1).
    pub(crate) fn send_raw(&mut self, frame: &[u8]) -> c_int {
        let Ok(n) = c_int::try_from(frame.len()) else {
            return -1;
        };
        // SAFETY: raw валиден; frame валиден на n байт на время вызова.
        unsafe { (self.api.fns.sendpacket)(self.raw.as_ptr(), frame.as_ptr(), n) }
    }

    /// `pcap_stats`: структура при rc 0, иначе сырой код ошибки.
    pub(crate) fn stats_raw(&mut self) -> Result<PcapStat, c_int> {
        let mut st = PcapStat::default();
        // SAFETY: raw валиден и активирован; st это структура полного
        // размера libpcap для Windows (ABI проверен в ffi).
        let rc = unsafe { (self.api.fns.stats)(self.raw.as_ptr(), &mut st) };
        if rc == 0 { Ok(st) } else { Err(rc) }
    }
}

/// Скомпилированная программа BPF; `pcap_freecode` в Drop. Держит `Arc`
/// библиотеки, поэтому не переживает её.
pub(crate) struct CompiledFilter {
    prog: BpfProgram,
    api: Arc<NpcapApi>,
}

impl Drop for CompiledFilter {
    fn drop(&mut self) {
        // SAFETY: prog заполнена успешным pcap_compile этой же библиотеки и
        // освобождается ровно один раз; api держит DLL загруженной.
        unsafe { (self.api.fns.freecode)(&mut self.prog) };
    }
}

impl PcapHandle {
    /// `pcap_compile` выражения (ASCII без NUL). Маска сети не нужна.
    pub(crate) fn compile(&mut self, expr: &str) -> Result<CompiledFilter, NetError> {
        let c = CString::new(expr)
            .map_err(|_| NetError::System("capture filter contains NUL".into()))?;
        let mut prog = BpfProgram {
            bf_len: 0,
            bf_insns: ptr::null_mut(),
        };
        // SAFETY: raw валиден и активирован; c NUL-терминирован; prog это
        // выходная структура полного размера (ABI проверен в ffi).
        let rc = unsafe {
            (self.api.fns.compile)(
                self.raw.as_ptr(),
                &mut prog,
                c.as_ptr(),
                1,
                PCAP_NETMASK_UNKNOWN,
            )
        };
        if rc != 0 {
            return Err(NetError::System(format!(
                "pcap_compile({expr:?}) failed (code {rc}): {}",
                self.last_error()
            )));
        }
        Ok(CompiledFilter {
            prog,
            api: Arc::clone(&self.api),
        })
    }

    /// `pcap_setfilter` для скомпилированной программы (библиотека копирует её).
    pub(crate) fn set_filter(&mut self, f: &mut CompiledFilter) -> Result<(), NetError> {
        // SAFETY: raw валиден; f.prog заполнена pcap_compile и жива.
        let rc = unsafe { (self.api.fns.setfilter)(self.raw.as_ptr(), &mut f.prog) };
        if rc != 0 {
            return Err(NetError::System(format!(
                "pcap_setfilter failed (code {rc}): {}",
                self.last_error()
            )));
        }
        Ok(())
    }

    /// Фильтр «не пропускать ничего» (`ret #0`): кадры отбрасываются в драйвере
    /// и не копятся в буфере. Программа из одной инструкции, без pcap_compile.
    pub(crate) fn set_drop_all_filter(&mut self) -> Result<(), NetError> {
        let mut insns = [BpfInsn {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: 0,
        }];
        let mut prog = BpfProgram {
            bf_len: 1,
            bf_insns: insns.as_mut_ptr(),
        };
        // SAFETY: raw валиден; prog описывает массив insns из одной валидной
        // инструкции, живущий дольше вызова; setfilter копирует программу.
        let rc = unsafe { (self.api.fns.setfilter)(self.raw.as_ptr(), &mut prog) };
        if rc != 0 {
            return Err(NetError::System(format!(
                "pcap_setfilter(drop-all) failed (code {rc}): {}",
                self.last_error()
            )));
        }
        Ok(())
    }
}

/// Кумулятивный счётчик потерь из 32-битного `ps_drop` (`u_int`). Npcap не
/// сбрасывает счётчик при чтении, но он оборачивается через 2^32; сумма
/// дельт по `wrapping_sub` честна, пока между двумя чтениями происходит
/// меньше 2^32 потерь. Сброс счётчика назад даёт огромную дельту (отказ
/// безопасен: RxLoss), кроме случая, когда новое значение уже превысило
/// прежнее: тогда потери недосчитаны, но результат всё равно ненулевой, а не
/// молчаливый ноль.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DropCounter {
    last: u32,
    total: u64,
}

impl DropCounter {
    /// `baseline` это значение `ps_drop`, прочитанное в начале попытки.
    pub(crate) fn new(baseline: u32) -> Self {
        Self {
            last: baseline,
            total: 0,
        }
    }

    /// Учитывает новое сырое значение и возвращает кумулятивные потери с
    /// начала попытки.
    pub(crate) fn update(&mut self, raw: u32) -> u64 {
        self.total += u64::from(raw.wrapping_sub(self.last));
        self.last = raw;
        self.total
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
        // Loopback-адаптер Npcap это не Ethernet: отказ до открытия.
        Some(d) if d.flags & PCAP_IF_LOOPBACK != 0 => Err(NetError::UnsupportedLink(format!(
            "{:?} is the Npcap loopback adapter, not Ethernet",
            d.name
        ))),
        // Имя из перечня не содержит NUL (получено из CStr).
        Some(d) => CString::new(d.name.as_bytes())
            .map_err(|_| NetError::InterfaceMismatch("device name contains NUL".into())),
        // Admin-only Npcap скрывает от токена без прав все адаптеры, кроме
        // loopback: это нехватка прав, а не неверное имя.
        None if devices.iter().all(|d| d.flags & PCAP_IF_LOOPBACK != 0) => {
            Err(NetError::PermissionDenied(format!(
                "no Npcap device named {interface_id:?}: only loopback is visible: Npcap may be installed in Administrators-only mode and this process lacks rights ({} devices enumerated)",
                devices.len()
            )))
        }
        None => Err(NetError::InterfaceMismatch(format!(
            "no Npcap device named {interface_id:?} ({} devices enumerated)",
            devices.len()
        ))),
    }
}
