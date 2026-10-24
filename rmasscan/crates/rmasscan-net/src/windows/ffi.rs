//! Объявления ABI Npcap/libpcap для Windows x64 (LLP64: `long` = 32 бита).
//!
//! Источники раскладки (заголовки только как справка, в сборку не входят):
//! - `pcap/pcap.h` libpcap 1.10 (Npcap 1.x собирается из него): `struct
//!   pcap_pkthdr`, `struct pcap_stat` (ветка `_WIN32` добавляет `ps_capt`,
//!   `ps_sent`, `ps_netdrop`), `struct pcap_if`, `struct pcap_addr`,
//!   `PCAP_ERRBUF_SIZE` = 256, `PCAP_IF_*`;
//! - `pcap/bpf.h`/`pcap/pcap.h`: `struct timeval` берётся из `winsock2.h`
//!   (`{ long tv_sec; long tv_usec; }`, на Windows `long` = 32 бита, это НЕ
//!   Unix `timeval`);
//! - `pcap/dlt.h`: `DLT_NULL` = 0, `DLT_EN10MB` = 1, `DLT_IEEE802_11_RADIO` =
//!   127; документация: npcap.com/guide/wpcap/pcap.html;
//! - `winsock2.h`: `struct sockaddr { u_short sa_family; char sa_data[14]; }`.
//!
//! Размеры, выравнивания и смещения проверяются `const _: () = assert!(..)`:
//! расхождение ломает сборку. Утверждения не зависят от хоста, пока он
//! 64-битный, поэтому те же проверки выполняются и на Mac/Linux. На Windows
//! дополнительно сверяем с `windows-sys`.

use std::ffi::{c_char, c_int, c_uint, c_void};
use std::mem::{align_of, offset_of, size_of};

/// Непрозрачный `pcap_t`.
#[repr(C)]
pub(crate) struct PcapT {
    _opaque: [u8; 0],
}

/// `struct timeval` Windows: два 32-битных поля.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Timeval {
    pub tv_sec: i32,
    pub tv_usec: i32,
}

/// `struct pcap_pkthdr`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PcapPkthdr {
    pub ts: Timeval,
    pub caplen: u32,
    pub len: u32,
}

/// `struct pcap_stat` с веткой `_WIN32` (шесть `u_int`). `pcap_stats` пишет
/// первые три поля; остальные нужны, чтобы буфер вызывающего был не меньше
/// структуры библиотеки.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PcapStat {
    pub ps_recv: c_uint,
    pub ps_drop: c_uint,
    pub ps_ifdrop: c_uint,
    pub ps_capt: c_uint,
    pub ps_sent: c_uint,
    pub ps_netdrop: c_uint,
}

/// `struct sockaddr`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct SockAddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

/// `struct pcap_addr`.
#[repr(C)]
pub(crate) struct PcapAddr {
    pub next: *mut PcapAddr,
    pub addr: *mut SockAddr,
    pub netmask: *mut SockAddr,
    pub broadaddr: *mut SockAddr,
    pub dstaddr: *mut SockAddr,
}

/// `struct pcap_if`.
#[repr(C)]
pub(crate) struct PcapIf {
    pub next: *mut PcapIf,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub addresses: *mut PcapAddr,
    pub flags: u32,
}

pub(crate) const PCAP_ERRBUF_SIZE: usize = 256;
pub(crate) const PCAP_IF_LOOPBACK: u32 = 0x1;
pub(crate) const DLT_NULL: c_int = 0;
pub(crate) const DLT_EN10MB: c_int = 1;
pub(crate) const DLT_IEEE802_11_RADIO: c_int = 127;
/// Возврат `pcap_next_ex`: кадр прочитан / таймаут / ошибка / EOF.
pub(crate) const NEXT_EX_OK: c_int = 1;
pub(crate) const NEXT_EX_TIMEOUT: c_int = 0;

// Раскладка. Эти утверждения верны для любого 64-битного хоста с 4-байтным
// `u_int` (указатели 8 байт, как на Windows x64).
const _: () = assert!(size_of::<Timeval>() == 8 && align_of::<Timeval>() == 4);
const _: () = assert!(offset_of!(Timeval, tv_sec) == 0 && offset_of!(Timeval, tv_usec) == 4);
const _: () = assert!(size_of::<PcapPkthdr>() == 16 && align_of::<PcapPkthdr>() == 4);
const _: () = assert!(offset_of!(PcapPkthdr, ts) == 0);
const _: () = assert!(offset_of!(PcapPkthdr, caplen) == 8);
const _: () = assert!(offset_of!(PcapPkthdr, len) == 12);
const _: () = assert!(size_of::<PcapStat>() == 24 && align_of::<PcapStat>() == 4);
const _: () = assert!(offset_of!(PcapStat, ps_recv) == 0);
const _: () = assert!(offset_of!(PcapStat, ps_drop) == 4);
const _: () = assert!(offset_of!(PcapStat, ps_ifdrop) == 8);
const _: () = assert!(offset_of!(PcapStat, ps_capt) == 12);
const _: () = assert!(offset_of!(PcapStat, ps_sent) == 16);
const _: () = assert!(offset_of!(PcapStat, ps_netdrop) == 20);
const _: () = assert!(size_of::<SockAddr>() == 16 && align_of::<SockAddr>() == 2);
const _: () = assert!(offset_of!(SockAddr, sa_data) == 2);
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(size_of::<PcapAddr>() == 40 && align_of::<PcapAddr>() == 8);
    assert!(offset_of!(PcapAddr, next) == 0);
    assert!(offset_of!(PcapAddr, addr) == 8);
    assert!(offset_of!(PcapAddr, netmask) == 16);
    assert!(offset_of!(PcapAddr, broadaddr) == 24);
    assert!(offset_of!(PcapAddr, dstaddr) == 32);
    assert!(size_of::<PcapIf>() == 40 && align_of::<PcapIf>() == 8);
    assert!(offset_of!(PcapIf, next) == 0);
    assert!(offset_of!(PcapIf, name) == 8);
    assert!(offset_of!(PcapIf, description) == 16);
    assert!(offset_of!(PcapIf, addresses) == 24);
    assert!(offset_of!(PcapIf, flags) == 32);
};

// Сверка с windows-sys (только на Windows).
#[cfg(windows)]
const _: () = {
    use windows_sys::Win32::Networking::WinSock::{SOCKADDR, TIMEVAL};
    assert!(size_of::<TIMEVAL>() == size_of::<Timeval>());
    assert!(align_of::<TIMEVAL>() == align_of::<Timeval>());
    assert!(size_of::<SOCKADDR>() == size_of::<SockAddr>());
    assert!(align_of::<SOCKADDR>() == align_of::<SockAddr>());
};

// Сигнатуры `PCAP_API` (cdecl; на x64 соглашение одно).
pub(crate) type LibVersionFn = unsafe extern "C" fn() -> *const c_char;
pub(crate) type FindAllDevsFn = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
pub(crate) type FreeAllDevsFn = unsafe extern "C" fn(*mut PcapIf);
pub(crate) type CreateFn = unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut PcapT;
pub(crate) type SetIntFn = unsafe extern "C" fn(*mut PcapT, c_int) -> c_int;
pub(crate) type ActivateFn = unsafe extern "C" fn(*mut PcapT) -> c_int;
pub(crate) type OpenLiveFn =
    unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut PcapT;
pub(crate) type NextExFn =
    unsafe extern "C" fn(*mut PcapT, *mut *mut PcapPkthdr, *mut *const u8) -> c_int;
pub(crate) type SendPacketFn = unsafe extern "C" fn(*mut PcapT, *const u8, c_int) -> c_int;
pub(crate) type DatalinkFn = unsafe extern "C" fn(*mut PcapT) -> c_int;
pub(crate) type GetErrFn = unsafe extern "C" fn(*mut PcapT) -> *mut c_char;
pub(crate) type StatsFn = unsafe extern "C" fn(*mut PcapT, *mut PcapStat) -> c_int;
pub(crate) type CloseFn = unsafe extern "C" fn(*mut PcapT);

/// Одно место, где перечислены все символы wpcap: имя, тип, поле таблицы.
macro_rules! pcap_api {
    ($($field:ident : $ty:ty = $name:literal),+ $(,)?) => {
        /// Иммутабельная таблица функций. Только `fn`-указатели, поэтому
        /// автоматически `Send + Sync` без `unsafe impl`.
        #[derive(Clone, Copy)]
        pub(crate) struct PcapFns {
            $(pub(crate) $field: $ty,)+
        }

        /// Имена обязательных символов.
        pub(crate) const REQUIRED_SYMBOLS: &[&str] = &[$($name),+];

        impl PcapFns {
            /// Разрешает все символы; при отсутствии (или нулевом адресе)
            /// возвращает ВСЕ недостающие имена. Безопасность держится на
            /// контракте `unsafe trait Module`, через который идёт lookup.
            pub(crate) fn resolve(
                lookup: &mut dyn FnMut(&str) -> Option<*const c_void>,
            ) -> Result<PcapFns, Vec<&'static str>> {
                let mut missing: Vec<&'static str> = Vec::new();
                $(
                    // Нулевой адрес считается отсутствующим символом.
                    let $field: Option<*const c_void> =
                        lookup($name).filter(|p| !p.is_null());
                    if $field.is_none() {
                        missing.push($name);
                    }
                )+
                if !missing.is_empty() {
                    return Err(missing);
                }
                Ok(PcapFns {
                    $($field: {
                        let Some(p) = $field else {
                            unreachable!("missing symbols were rejected above")
                        };
                        // SAFETY: p не нулевой (отфильтровано выше). По
                        // контракту `unsafe trait Module` lookup возвращает
                        // реальный экспорт $name с сигнатурой, заданной типом
                        // поля, живой, пока жив модуль; указатель данных и
                        // fn-указатель одного размера на всех целях.
                        unsafe { std::mem::transmute::<*const c_void, $ty>(p) }
                    },)+
                })
            }
        }
    };
}

pcap_api! {
    lib_version: LibVersionFn = "pcap_lib_version",
    findalldevs: FindAllDevsFn = "pcap_findalldevs",
    freealldevs: FreeAllDevsFn = "pcap_freealldevs",
    create: CreateFn = "pcap_create",
    set_snaplen: SetIntFn = "pcap_set_snaplen",
    set_promisc: SetIntFn = "pcap_set_promisc",
    set_timeout: SetIntFn = "pcap_set_timeout",
    set_immediate_mode: SetIntFn = "pcap_set_immediate_mode",
    set_buffer_size: SetIntFn = "pcap_set_buffer_size",
    activate: ActivateFn = "pcap_activate",
    open_live: OpenLiveFn = "pcap_open_live",
    next_ex: NextExFn = "pcap_next_ex",
    sendpacket: SendPacketFn = "pcap_sendpacket",
    datalink: DatalinkFn = "pcap_datalink",
    geterr: GetErrFn = "pcap_geterr",
    stats: StatsFn = "pcap_stats",
    close: CloseFn = "pcap_close",
}
