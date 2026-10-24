//! Подставная таблица функций wpcap с ГЛОБАЛЬНЫМ сценарием: движок вызывает
//! адаптер из своих потоков, поэтому состояние не может быть потоковым.
//! Тесты, использующие подставную таблицу, сериализуются замком, который
//! `reset` берёт на время жизни потока теста.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::{CString, c_char, c_int, c_uint, c_void};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use crate::windows::ffi::*;

pub(super) const GOOD_PATH: &str = "C:\\Windows\\System32\\Npcap\\wpcap.dll";
pub(super) const DEV1: &str = "\\Device\\NPF_{11111111-2222-3333-4444-555555555555}";
pub(super) const DEV2: &str = "\\Device\\NPF_{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}";
pub(super) const LOOP: &str = "\\Device\\NPF_Loopback";

/// Очередной ответ `pcap_next_ex`.
#[derive(Clone)]
pub(super) enum NextStep {
    /// rc 1, `caplen == len == data.len()`.
    Frame(Vec<u8>),
    /// rc 1 с заданными (возможно лживыми) caplen/len.
    Raw {
        caplen: u32,
        len: u32,
        data: Vec<u8>,
    },
    NullHdr,
    NullData,
    /// rc 0.
    Empty,
    Err(c_int),
    Eof,
}

pub(super) type Responder = Arc<dyn Fn(&[u8]) -> Vec<Vec<u8>> + Send + Sync>;

pub(super) struct Scenario {
    pub log: Vec<String>,
    pub version_null: bool,
    pub activate_rc: c_int,
    /// `(номер create с 1, rc)`: activate этого handle вернёт rc.
    pub activate_fail_nth: Option<(usize, c_int)>,
    pub dlt: c_int,
    pub devices: Vec<(String, Option<String>, u32)>,
    pub findalldevs_rc: c_int,
    pub create_null: bool,
    /// create с этим номером (с 1) вернёт NULL.
    pub create_null_nth: Option<usize>,
    /// Узлы списка устройств, выданные findalldevs (освобождает freealldevs).
    #[allow(clippy::vec_box)] // узлы обязаны иметь стабильные адреса
    pub lists: Vec<Vec<Box<PcapIf>>>,
    pub creates: usize,
    // ---- чтение ----
    pub next_script: VecDeque<NextStep>,
    /// Когда сценарий пуст, отдавать этот кадр бесконечно (поток мусора).
    pub junk_forever: Option<Vec<u8>>,
    pub next_calls: usize,
    cur_hdr: Box<PcapPkthdr>,
    cur_data: Vec<u8>,
    // ---- отправка ----
    pub send_rcs: VecDeque<c_int>,
    pub send_calls: usize,
    pub sent: Vec<Vec<u8>>,
    pub responder: Option<Responder>,
    /// Каждый успешно отправленный кадр возвращается в очередь чтения (спайк:
    /// RX-handle видит собственные TX-кадры).
    pub echo_tx: bool,
    // ---- статистика ----
    /// `Ok(ps_drop)` или `Err(rc)` на очередной вызов; пусто: `stats_drop`.
    pub stats_script: VecDeque<Result<u32, c_int>>,
    pub stats_drop: u32,
    pub stats_calls: usize,
    // ---- фильтры ----
    pub compile_rc: c_int,
    pub setfilter_rc: c_int,
    /// Отказ `pcap_setfilter` только у handle с этим номером.
    pub setfilter_fail_hid: Option<(usize, c_int)>,
    /// `(handle#, выражение)`.
    pub compiled: Vec<(usize, String)>,
    /// `(handle#, инструкции)`.
    pub filters: Vec<(usize, Vec<BpfInsn>)>,
    pub freecode_calls: usize,
    /// Текст `pcap_geterr`.
    pub geterr: CString,
    pub setnonblock_rc: c_int,
    pub getnonblock_override: Option<c_int>,
    nonblock: Vec<(usize, bool)>,
    // ---- pcap_init ----
    pub init_rc: c_int,
    pub init_opts: Vec<c_uint>,
}

impl Default for Scenario {
    fn default() -> Self {
        Scenario {
            log: Vec::new(),
            version_null: false,
            activate_rc: 0,
            activate_fail_nth: None,
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
            findalldevs_rc: 0,
            create_null: false,
            create_null_nth: None,
            lists: Vec::new(),
            creates: 0,
            next_script: VecDeque::new(),
            junk_forever: None,
            next_calls: 0,
            cur_hdr: Box::default(),
            cur_data: Vec::new(),
            send_rcs: VecDeque::new(),
            send_calls: 0,
            sent: Vec::new(),
            responder: None,
            echo_tx: false,
            stats_script: VecDeque::new(),
            stats_drop: 0,
            stats_calls: 0,
            compile_rc: 0,
            setfilter_rc: 0,
            setfilter_fail_hid: None,
            compiled: Vec::new(),
            filters: Vec::new(),
            freecode_calls: 0,
            geterr: CString::new("fake driver says no").unwrap(),
            setnonblock_rc: 0,
            getnonblock_override: None,
            nonblock: Vec::new(),
            init_rc: 0,
            init_opts: Vec::new(),
        }
    }
}

// SAFETY: сырые указатели сценария ведут только в его собственные кучи
// (узлы списка устройств, программы фильтров) и используются исключительно
// под замком `STATE`.
unsafe impl Send for Scenario {}

static STATE: LazyLock<Mutex<Scenario>> = LazyLock::new(|| Mutex::new(Scenario::default()));
static TEST_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    static HELD: RefCell<Option<MutexGuard<'static, ()>>> = const { RefCell::new(None) };
}

fn st() -> MutexGuard<'static, Scenario> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Начинает сценарий: берёт замок сериализации (один раз на поток теста) и
/// подменяет состояние. Замок отпускается при завершении потока теста.
pub(super) fn reset(f: impl FnOnce(&mut Scenario)) {
    HELD.with(|h| {
        let mut h = h.borrow_mut();
        if h.is_none() {
            *h = Some(TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()));
        }
    });
    let mut s = st();
    *s = Scenario::default();
    f(&mut s);
}

/// Изменяет сценарий посреди теста.
pub(super) fn with(f: impl FnOnce(&mut Scenario)) {
    f(&mut st());
}

pub(super) fn events() -> Vec<String> {
    st().log.clone()
}

pub(super) fn count(ev: &str) -> usize {
    st().log.iter().filter(|e| *e == ev).count()
}

pub(super) fn pos(ev: &[String], what: &str) -> usize {
    ev.iter()
        .position(|e| e == what)
        .unwrap_or_else(|| panic!("{what} missing in {ev:?}"))
}

pub(super) fn log(s: &str) {
    st().log.push(s.to_string());
}

// ---------- подставные функции wpcap ----------

static VERSION: &[u8] = b"Npcap version 1.90, based on libpcap 1.10.7\0";
const FAKE_T: usize = 0x1000;
const STEP: usize = 0x10;

/// Номер handle (с 1) по указателю.
fn hid(p: *mut PcapT) -> usize {
    (p as usize - FAKE_T) / STEP
}

fn put_err(err: *mut c_char, msg: &[u8]) {
    // SAFETY: тестовый буфер имеет PCAP_ERRBUF_SIZE байт, msg короче.
    unsafe { std::ptr::copy_nonoverlapping(msg.as_ptr().cast(), err, msg.len()) };
}

pub(super) unsafe extern "C" fn f_init(opts: c_uint, _err: *mut c_char) -> c_int {
    let mut s = st();
    s.log.push(format!("init:{opts}"));
    s.init_opts.push(opts);
    s.init_rc
}
pub(super) unsafe extern "C" fn f_lib_version() -> *const c_char {
    let mut s = st();
    s.log.push("lib_version".into());
    if s.version_null {
        std::ptr::null()
    } else {
        VERSION.as_ptr().cast()
    }
}
unsafe extern "C" fn f_findalldevs(out: *mut *mut PcapIf, err: *mut c_char) -> c_int {
    let mut s = st();
    s.log.push("findalldevs".into());
    if s.findalldevs_rc != 0 {
        put_err(err, b"enum failed\0");
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
}
unsafe extern "C" fn f_freealldevs(_head: *mut PcapIf) {
    log("freealldevs");
}
unsafe extern "C" fn f_create(_d: *const c_char, err: *mut c_char) -> *mut PcapT {
    let mut s = st();
    s.log.push("create".into());
    s.creates += 1;
    if s.create_null || s.create_null_nth == Some(s.creates) {
        put_err(err, b"no such device\0");
        return std::ptr::null_mut();
    }
    (FAKE_T + s.creates * STEP) as *mut PcapT
}
unsafe extern "C" fn f_set_snaplen(_p: *mut PcapT, _v: c_int) -> c_int {
    log("set_snaplen");
    0
}
unsafe extern "C" fn f_set_promisc(_p: *mut PcapT, v: c_int) -> c_int {
    log(&format!("set_promisc:{v}"));
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
unsafe extern "C" fn f_activate(p: *mut PcapT) -> c_int {
    let mut s = st();
    s.log.push("activate".into());
    match s.activate_fail_nth {
        Some((n, rc)) if n == hid(p) => rc,
        _ => s.activate_rc,
    }
}
unsafe extern "C" fn f_next_ex(
    _p: *mut PcapT,
    h: *mut *mut PcapPkthdr,
    d: *mut *const u8,
) -> c_int {
    let mut s = st();
    s.next_calls += 1;
    // Предыдущий кадр больше не действителен: затираем, чтобы тест поймал
    // использование указателя после следующего вызова.
    s.cur_data.fill(0xAA);
    let step = match s.next_script.pop_front() {
        Some(step) => step,
        None => s
            .junk_forever
            .clone()
            .map_or(NextStep::Empty, NextStep::Frame),
    };
    let (caplen, len, data) = match step {
        NextStep::Empty => return 0,
        NextStep::Err(rc) => return rc,
        NextStep::Eof => return -2,
        NextStep::Frame(v) => (v.len() as u32, v.len() as u32, v),
        NextStep::Raw { caplen, len, data } => (caplen, len, data),
        NextStep::NullHdr => {
            // SAFETY: выходные указатели вызывающего валидны.
            unsafe {
                *h = std::ptr::null_mut();
                *d = s.cur_data.as_ptr();
            }
            return 1;
        }
        NextStep::NullData => {
            *s.cur_hdr = PcapPkthdr {
                caplen: 60,
                len: 60,
                ..PcapPkthdr::default()
            };
            // SAFETY: выходные указатели вызывающего валидны.
            unsafe {
                *h = &mut *s.cur_hdr;
                *d = std::ptr::null();
            }
            return 1;
        }
    };
    s.cur_data = data;
    *s.cur_hdr = PcapPkthdr {
        caplen,
        len,
        ..PcapPkthdr::default()
    };
    // SAFETY: выходные указатели вызывающего валидны; указатели ведут в
    // состояние сценария, живущее до следующего вызова.
    unsafe {
        *h = &mut *s.cur_hdr;
        *d = s.cur_data.as_ptr();
    }
    1
}
unsafe extern "C" fn f_sendpacket(_p: *mut PcapT, b: *const u8, n: c_int) -> c_int {
    let mut s = st();
    s.send_calls += 1;
    s.log.push("sendpacket".into());
    let rc = s.send_rcs.pop_front().unwrap_or(0);
    if rc == 0 {
        // SAFETY: вызывающий передаёт n читаемых байт.
        let frame = unsafe { std::slice::from_raw_parts(b, n as usize) }.to_vec();
        if s.echo_tx {
            s.next_script.push_back(NextStep::Frame(frame.clone()));
        }
        if let Some(r) = s.responder.clone() {
            for f in r(&frame) {
                s.next_script.push_back(NextStep::Frame(f));
            }
        }
        s.sent.push(frame);
    }
    rc
}
unsafe extern "C" fn f_datalink(_p: *mut PcapT) -> c_int {
    st().dlt
}
unsafe extern "C" fn f_geterr(_p: *mut PcapT) -> *mut c_char {
    st().geterr.as_ptr() as *mut c_char
}
unsafe extern "C" fn f_setnonblock(p: *mut PcapT, on: c_int, _e: *mut c_char) -> c_int {
    let mut s = st();
    if s.setnonblock_rc == 0 {
        let id = hid(p);
        s.nonblock.retain(|(i, _)| *i != id);
        s.nonblock.push((id, on != 0));
    }
    s.log.push(format!("setnonblock:{on}"));
    s.setnonblock_rc
}
unsafe extern "C" fn f_getnonblock(p: *mut PcapT, _e: *mut c_char) -> c_int {
    let s = st();
    if let Some(v) = s.getnonblock_override {
        return v;
    }
    let id = hid(p);
    c_int::from(s.nonblock.iter().any(|(i, on)| *i == id && *on))
}
unsafe extern "C" fn f_stats(_p: *mut PcapT, out: *mut PcapStat) -> c_int {
    let mut s = st();
    s.stats_calls += 1;
    s.log.push("stats".into());
    let step = s.stats_script.pop_front().unwrap_or(Ok(s.stats_drop));
    match step {
        Ok(drop) => {
            // SAFETY: out это структура полного размера вызывающего.
            unsafe {
                *out = PcapStat {
                    ps_recv: 1000,
                    ps_drop: drop,
                    ..PcapStat::default()
                };
            }
            0
        }
        Err(rc) => rc,
    }
}
unsafe extern "C" fn f_compile(
    p: *mut PcapT,
    prog: *mut BpfProgram,
    expr: *const c_char,
    _opt: c_int,
    _mask: u32,
) -> c_int {
    let mut s = st();
    s.log.push("compile".into());
    // SAFETY: expr NUL-терминирован.
    let e = unsafe { std::ffi::CStr::from_ptr(expr) }
        .to_string_lossy()
        .into_owned();
    s.compiled.push((hid(p), e));
    if s.compile_rc != 0 {
        return s.compile_rc;
    }
    let insns: Box<[BpfInsn]> = Box::new([BpfInsn {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0xffff,
    }]);
    // SAFETY: prog это выходная структура вызывающего; память вернёт freecode.
    unsafe {
        *prog = BpfProgram {
            bf_len: 1,
            bf_insns: Box::leak(insns).as_mut_ptr(),
        };
    }
    0
}
unsafe extern "C" fn f_setfilter(p: *mut PcapT, prog: *mut BpfProgram) -> c_int {
    let mut s = st();
    s.log.push("setfilter".into());
    // SAFETY: prog валидная программа вызывающего.
    let insns = unsafe {
        let pr = &*prog;
        std::slice::from_raw_parts(pr.bf_insns, pr.bf_len as usize).to_vec()
    };
    s.filters.push((hid(p), insns));
    match s.setfilter_fail_hid {
        Some((n, rc)) if n == hid(p) => rc,
        _ => s.setfilter_rc,
    }
}
unsafe extern "C" fn f_freecode(prog: *mut BpfProgram) {
    let mut s = st();
    s.log.push("freecode".into());
    s.freecode_calls += 1;
    // SAFETY: prog заполнена f_compile (leaked Box<[BpfInsn; 1]>).
    unsafe {
        let pr = &mut *prog;
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            pr.bf_insns,
            pr.bf_len as usize,
        )));
        pr.bf_insns = std::ptr::null_mut();
    }
}
unsafe extern "C" fn f_close(_p: *mut PcapT) {
    log("close");
}

pub(super) fn symbol_addr(name: &str) -> Option<*const c_void> {
    Some(match name {
        "pcap_init" => f_init as *const c_void,
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
        "pcap_next_ex" => f_next_ex as *const c_void,
        "pcap_sendpacket" => f_sendpacket as *const c_void,
        "pcap_datalink" => f_datalink as *const c_void,
        "pcap_geterr" => f_geterr as *const c_void,
        "pcap_setnonblock" => f_setnonblock as *const c_void,
        "pcap_getnonblock" => f_getnonblock as *const c_void,
        "pcap_stats" => f_stats as *const c_void,
        "pcap_close" => f_close as *const c_void,
        "pcap_compile" => f_compile as *const c_void,
        "pcap_setfilter" => f_setfilter as *const c_void,
        "pcap_freecode" => f_freecode as *const c_void,
        _ => return None,
    })
}
