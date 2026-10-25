//! Объявления BPF ABI macOS (aarch64, LP64) и тонкие обёртки `sysctlbyname`.
//! Собственные объявления: часть ioctl (`BIOCSSEESENT`, `BIOCGSEESENT`) и все
//! `DLT_*`/`IFT_*` отсутствуют в `libc`, поэтому константы заданы здесь и
//! сверяются с `libc` и SDK-заголовком в `tests/layout_tests.rs`.

use std::ffi::CString;

use super::Errno;

/// `struct bpf_hdr` (net/bpf.h, `__LP64__`: `BPF_TIMEVAL = timeval32`): sizeof 20 (tail
/// padding), как `libc::bpf_hdr`. Заголовок записи, который реально пишет ядро, это
/// [`SIZEOF_BPF_HDR`] = 18 байт, а не `size_of::<Self>()`. Задача 4 обязана
/// читать поля из проверенного по границам байтового среза (`buf.get(off..off + 18)`,
/// затем `from_ne_bytes` по `offset_of!`), а не читать структуру целиком: чтение
/// 20 байт после проверки 18 выходит за буфер. Шаг по буферу только
/// `bpf_wordalign(bh_hdrlen + bh_caplen)`, кадр начинается с `bh_hdrlen`.
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))] // used from task 4
pub(crate) struct BpfHdr {
    pub bh_tstamp: libc::timeval32,
    pub bh_caplen: u32,
    pub bh_datalen: u32,
    pub bh_hdrlen: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))] // used from task 4
pub(crate) struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))] // used from task 4
pub(crate) struct BpfProgram {
    pub bf_len: u32,
    pub bf_insns: *mut BpfInsn,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[cfg_attr(not(test), allow(dead_code))] // used from task 4
pub(crate) struct BpfStat {
    pub bs_recv: u32,
    pub bs_drop: u32,
}

/// Байты заголовка записи, которые пишет ядро (`SIZEOF_BPF_HDR`, bsd/net/bpf.c):
/// нижняя граница `bh_hdrlen`; не шаг и не смещение кадра.
#[cfg_attr(not(test), allow(dead_code))] // used from task 4
pub(crate) const SIZEOF_BPF_HDR: usize =
    std::mem::offset_of!(BpfHdr, bh_hdrlen) + std::mem::size_of::<u16>();

#[cfg_attr(not(test), allow(dead_code))] // used from task 4
pub(crate) const BIOCSETF: libc::c_ulong = 0x8010_4267;
#[cfg_attr(not(test), allow(dead_code))] // used from task 4
pub(crate) const BIOCSETFNR: libc::c_ulong = 0x8010_427e;
#[cfg_attr(not(test), allow(dead_code))] // used from task 4
pub(crate) const BIOCSSEESENT: libc::c_ulong = 0x8004_4277;
#[cfg_attr(not(test), allow(dead_code))] // used from task 4
pub(crate) const BIOCGSEESENT: libc::c_ulong = 0x4004_4276;
#[cfg_attr(not(test), allow(dead_code))] // used from task 4
pub(crate) const BIOCSRTIMEOUT: libc::c_ulong = 0x8010_426d;

#[cfg_attr(not(test), allow(dead_code))] // used from task 4
pub(crate) const DLT_NULL: u32 = 0;
#[cfg_attr(not(test), allow(dead_code))] // used from task 4
pub(crate) const DLT_EN10MB: u32 = 1;
pub(crate) const IFT_ETHER: u8 = 0x06;
#[cfg_attr(not(test), allow(dead_code))] // used from task 4
pub(crate) const BPF_ALIGNMENT: usize = 4;

/// `BPF_WORDALIGN`: округление вверх до кратного `BPF_ALIGNMENT`.
#[cfg_attr(not(test), allow(dead_code))] // used from task 4
pub(crate) const fn bpf_wordalign(x: usize) -> usize {
    (x + (BPF_ALIGNMENT - 1)) & !(BPF_ALIGNMENT - 1)
}

/// Читает значение `sysctlbyname` в буфер. Возвращает число записанных байт.
fn sysctl_read(name: &str, buf: Option<&mut [u8]>) -> Result<usize, Errno> {
    let c = CString::new(name).map_err(|_| libc::EINVAL)?;
    let (ptr, mut len) = match buf {
        Some(b) => (b.as_mut_ptr().cast::<libc::c_void>(), b.len()),
        None => (std::ptr::null_mut(), 0),
    };
    // SAFETY: `c` это NUL-terminated строка, живущая весь вызов; `ptr` либо
    // null (запрос размера, `len == 0`), либо указывает на `len` записываемых
    // байт буфера вызывающего; новое значение не задаётся (null, 0).
    let rc = unsafe { libc::sysctlbyname(c.as_ptr(), ptr, &mut len, std::ptr::null_mut(), 0) };
    if rc == 0 {
        Ok(len)
    } else {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    }
}

/// Строковый sysctl (без завершающего NUL). `Err(ENOENT)`, если ключа нет.
pub(crate) fn sysctl_string(name: &str) -> Result<String, Errno> {
    let need = sysctl_read(name, None)?;
    let mut buf = vec![0u8; need.max(1)];
    let got = sysctl_read(name, Some(&mut buf))?;
    buf.truncate(got);
    while buf.last() == Some(&0) {
        buf.pop();
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Целочисленный (32-битный) sysctl.
pub(crate) fn sysctl_u32(name: &str) -> Result<u32, Errno> {
    let mut buf = [0u8; 4];
    let got = sysctl_read(name, Some(&mut buf))?;
    if got != 4 {
        return Err(libc::EINVAL);
    }
    Ok(u32::from_ne_bytes(buf))
}
