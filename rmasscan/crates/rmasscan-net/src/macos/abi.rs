//! Переносимая часть BPF ABI macOS: структуры без указателей, смещения
//! заголовка записи, `DLT_*` и номера errno macOS. Модуль не использует `libc`,
//! поэтому собирается в тестах на любой ОС (seam-тесты адаптера идут на Linux и
//! Windows). Соответствие `libc` и SDK-заголовку проверяется в
//! `tests/layout_tests.rs` на macOS.

/// `struct bpf_insn`: одна инструкция классического BPF.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// `struct bpf_stat` (`BIOCGSTATS`): `bs_drop` это кумулятивный `u32`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BpfStat {
    pub bs_recv: u32,
    pub bs_drop: u32,
}

/// Байты заголовка записи, которые пишет ядро (`SIZEOF_BPF_HDR`, bsd/net/bpf.c):
/// нижняя граница `bh_hdrlen`; не шаг и не смещение кадра.
pub(crate) const SIZEOF_BPF_HDR: usize = 18;
/// Смещения полей `struct bpf_hdr` (LP64, `timeval32`); сверяются с
/// `offset_of!` в `sys.rs` на этапе компиляции.
pub(crate) const HDR_OFF_CAPLEN: usize = 8;
pub(crate) const HDR_OFF_DATALEN: usize = 12;
pub(crate) const HDR_OFF_HDRLEN: usize = 16;
/// Допустимый диапазон `bh_hdrlen` при разборе записей.
pub(crate) const MAX_HDRLEN: usize = 64;

pub(crate) const DLT_NULL: u32 = 0;
pub(crate) const DLT_EN10MB: u32 = 1;
pub(crate) const BPF_ALIGNMENT: usize = 4;

/// `BPF_WORDALIGN`: округление вверх до кратного `BPF_ALIGNMENT`.
pub(crate) const fn bpf_wordalign(x: usize) -> usize {
    (x + (BPF_ALIGNMENT - 1)) & !(BPF_ALIGNMENT - 1)
}

/// Номера errno macOS (`sys/errno.h`). Свои константы: `libc` недоступна в
/// сборке тестов на Windows. Равенство `libc` проверяет `layout_tests`.
pub(crate) mod errno {
    pub(crate) const EPERM: i32 = 1;
    pub(crate) const ENOENT: i32 = 2;
    pub(crate) const EINTR: i32 = 4;
    pub(crate) const ENXIO: i32 = 6;
    pub(crate) const EACCES: i32 = 13;
    pub(crate) const EBUSY: i32 = 16;
    pub(crate) const ENODEV: i32 = 19;
    pub(crate) const EAGAIN: i32 = 35;
    pub(crate) const EMSGSIZE: i32 = 40;
    pub(crate) const ENOBUFS: i32 = 55;
}

/// Поля заголовка записи, прочитанные из проверенного по границам среза.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecordHeader {
    pub caplen: u32,
    pub datalen: u32,
    pub hdrlen: u16,
}

/// Читает поля заголовка записи из `rec` (не из структуры целиком):
/// `None`, если в срезе меньше [`SIZEOF_BPF_HDR`] байт.
pub(crate) fn read_record_header(rec: &[u8]) -> Option<RecordHeader> {
    let h = rec.get(..SIZEOF_BPF_HDR)?;
    let u32_at = |off: usize| -> Option<u32> {
        Some(u32::from_ne_bytes(h.get(off..off + 4)?.try_into().ok()?))
    };
    Some(RecordHeader {
        caplen: u32_at(HDR_OFF_CAPLEN)?,
        datalen: u32_at(HDR_OFF_DATALEN)?,
        hdrlen: u16::from_ne_bytes(h.get(HDR_OFF_HDRLEN..HDR_OFF_HDRLEN + 2)?.try_into().ok()?),
    })
}
