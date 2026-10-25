//! Объявления BPF ABI macOS (aarch64, LP64), тонкие обёртки `sysctlbyname` и
//! единственная реализация шва [`BpfIo`]/[`BpfSetup`] над настоящим
//! `/dev/bpfN` (`open`, `ioctl`, `read`, `write`, `poll`). Собственные
//! объявления: часть ioctl (`BIOCSSEESENT`, `BIOCGSEESENT`) и все
//! `DLT_*`/`IFT_*` отсутствуют в `libc`, поэтому константы заданы здесь и
//! сверяются с `libc` и SDK-заголовком в `tests/layout_tests.rs`.
//!
//! Каждый дескриптор живёт в `OwnedFd` и принадлежит одному потоку; `Sync` не
//! реализуется. Выбор `poll`/`kevent` скрыт за [`BpfIo::poll_in`], поэтому
//! замена по итогам спайка меняет только этот файл.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use super::Errno;
use super::abi::{BpfInsn, BpfStat, HDR_OFF_CAPLEN, HDR_OFF_DATALEN, HDR_OFF_HDRLEN};
use super::adapter::{BpfIo, BpfOpener, BpfSetup, Readiness};

/// `struct bpf_hdr` (net/bpf.h, `__LP64__`: `BPF_TIMEVAL = timeval32`): sizeof 20 (tail
/// padding), как `libc::bpf_hdr`. Заголовок записи, который реально пишет ядро, это
/// [`SIZEOF_BPF_HDR`](super::abi::SIZEOF_BPF_HDR) = 18 байт, а не `size_of::<Self>()`.
/// Продуктовый разбор читает поля из проверенного по границам байтового среза
/// (`abi::read_record_header`), а не структуру целиком: чтение 20 байт после
/// проверки 18 выходит за буфер. Структура здесь только описывает раскладку:
/// смещения сверяются с `abi` на этапе компиляции.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BpfHdr {
    pub bh_tstamp: libc::timeval32,
    pub bh_caplen: u32,
    pub bh_datalen: u32,
    pub bh_hdrlen: u16,
}

const _: () = {
    assert!(std::mem::offset_of!(BpfHdr, bh_caplen) == HDR_OFF_CAPLEN);
    assert!(std::mem::offset_of!(BpfHdr, bh_datalen) == HDR_OFF_DATALEN);
    assert!(std::mem::offset_of!(BpfHdr, bh_hdrlen) == HDR_OFF_HDRLEN);
    assert!(
        std::mem::offset_of!(BpfHdr, bh_hdrlen) + std::mem::size_of::<u16>()
            == super::abi::SIZEOF_BPF_HDR
    );
};

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BpfProgram {
    pub bf_len: u32,
    pub bf_insns: *mut BpfInsn,
}

pub(crate) const BIOCSETF: libc::c_ulong = 0x8010_4267;
pub(crate) const BIOCSSEESENT: libc::c_ulong = 0x8004_4277;
// Справочные ABI-константы: в продукте не используются (дедлайн через
// `O_NONBLOCK` + `poll`, фильтр ставится с сбросом), проверяются тестами
// раскладки.
#[cfg(test)]
pub(crate) const BIOCSETFNR: libc::c_ulong = 0x8010_427e;
#[cfg(test)]
pub(crate) const BIOCGSEESENT: libc::c_ulong = 0x4004_4276;
#[cfg(test)]
pub(crate) const BIOCSRTIMEOUT: libc::c_ulong = 0x8010_426d;

pub(crate) const IFT_ETHER: u8 = 0x06;

fn last_errno() -> Errno {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// `ioctl` с указателем на значение вызывающего.
fn ioctl_ptr<T>(fd: RawFd, req: libc::c_ulong, arg: &mut T) -> Result<(), Errno> {
    // SAFETY: `fd` это открытый дескриптор владельца `OwnedFd`; `arg` это
    // исключительная ссылка на `T`, живущая весь вызов, а размер `T` совпадает
    // с размером, закодированным в `req` (проверено тестами раскладки).
    let rc = unsafe { libc::ioctl(fd, req, std::ptr::from_mut(arg)) };
    if rc < 0 { Err(last_errno()) } else { Ok(()) }
}

/// Открытый `/dev/bpfN`, неблокирующий.
pub(crate) struct BpfFd {
    fd: OwnedFd,
    buflen: usize,
}

impl BpfFd {
    /// `open("/dev/bpfN", O_RDWR | O_NONBLOCK | O_CLOEXEC)`.
    fn open_node(index: u32) -> Result<BpfFd, Errno> {
        let path = CString::new(format!("/dev/bpf{index}")).map_err(|_| libc::EINVAL)?;
        // SAFETY: `path` это NUL-terminated строка, живущая весь вызов; флаги
        // это целые, предусловий по памяти нет.
        let raw = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(last_errno());
        }
        // SAFETY: `raw` только что вернул open(), он >= 0 и больше нигде не
        // хранится, поэтому `OwnedFd` единственный владелец.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(BpfFd { fd, buflen: 0 })
    }

    fn set_flag(&mut self, req: libc::c_ulong, on: bool) -> Result<(), Errno> {
        let mut v = u32::from(on);
        ioctl_ptr(self.fd.as_raw_fd(), req, &mut v)
    }
}

impl BpfIo for BpfFd {
    fn write(&mut self, frame: &[u8]) -> Result<usize, Errno> {
        // SAFETY: указатель и длина описывают именно срез `frame`; дескриптор
        // открыт (владеет `OwnedFd`).
        let n = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                frame.as_ptr().cast::<libc::c_void>(),
                frame.len(),
            )
        };
        usize::try_from(n).map_err(|_| last_errno())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Errno> {
        // SAFETY: указатель и длина описывают именно срез `buf`, доступный
        // для записи; дескриптор открыт.
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        usize::try_from(n).map_err(|_| last_errno())
    }

    fn poll_in(&mut self, timeout_ms: i32) -> Result<Readiness, Errno> {
        let mut p = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `p` это одна валидная `pollfd`, `nfds == 1`.
        let rc = unsafe { libc::poll(&mut p, 1, timeout_ms) };
        if rc < 0 {
            return Err(last_errno());
        }
        Ok(if rc == 0 {
            Readiness::Timeout
        } else if p.revents & libc::POLLIN != 0 {
            Readiness::Ready
        } else {
            Readiness::Failed
        })
    }

    fn stats(&mut self) -> Result<BpfStat, Errno> {
        let mut st = BpfStat::default();
        ioctl_ptr(self.fd.as_raw_fd(), libc::BIOCGSTATS, &mut st)?;
        Ok(st)
    }

    fn backoff(&mut self, wait: Duration) {
        std::thread::sleep(wait);
    }

    fn buffer_len(&self) -> usize {
        self.buflen
    }
}

impl BpfSetup for BpfFd {
    fn set_buffer_len(&mut self, requested: u32) -> Result<(), Errno> {
        let mut v = requested;
        ioctl_ptr(self.fd.as_raw_fd(), libc::BIOCSBLEN, &mut v)
    }

    fn bind_interface(&mut self, name: &str) -> Result<(), Errno> {
        // SAFETY: `ifreq` это набор целых и массивов целых; нулевой образ корректен.
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() >= req.ifr_name.len() || bytes.contains(&0) {
            return Err(libc::EINVAL);
        }
        for (dst, src) in req.ifr_name.iter_mut().zip(bytes) {
            *dst = *src as libc::c_char;
        }
        ioctl_ptr(self.fd.as_raw_fd(), libc::BIOCSETIF, &mut req)
    }

    fn data_link(&mut self) -> Result<u32, Errno> {
        let mut v = 0u32;
        ioctl_ptr(self.fd.as_raw_fd(), libc::BIOCGDLT, &mut v)?;
        Ok(v)
    }

    fn set_immediate(&mut self, on: bool) -> Result<(), Errno> {
        self.set_flag(libc::BIOCIMMEDIATE, on)
    }

    fn set_see_sent(&mut self, on: bool) -> Result<(), Errno> {
        self.set_flag(BIOCSSEESENT, on)
    }

    fn set_hdr_complete(&mut self, on: bool) -> Result<(), Errno> {
        self.set_flag(libc::BIOCSHDRCMPLT, on)
    }

    fn set_filter(&mut self, prog: &[BpfInsn]) -> Result<(), Errno> {
        let mut insns = prog.to_vec();
        let mut p = BpfProgram {
            bf_len: u32::try_from(insns.len()).map_err(|_| libc::EINVAL)?,
            bf_insns: insns.as_mut_ptr(),
        };
        // `bf_insns` указывает на `insns`, который живёт до конца вызова;
        // ядро копирует программу внутри `BIOCSETF`.
        ioctl_ptr(self.fd.as_raw_fd(), BIOCSETF, &mut p)
    }

    fn refresh_buffer_len(&mut self) -> Result<(), Errno> {
        let mut v = 0u32;
        ioctl_ptr(self.fd.as_raw_fd(), libc::BIOCGBLEN, &mut v)?;
        self.buflen = usize::try_from(v).map_err(|_| libc::EINVAL)?;
        Ok(())
    }
}

/// Настоящий перебор `/dev/bpfN`.
pub(crate) struct SysOpener;

/// Потолок буфера BPF (решение плана: 4 МиБ).
const MAX_BPF_BUFFER: u32 = 4 << 20;

impl BpfOpener for SysOpener {
    type Dev = BpfFd;

    fn max_buffer(&self) -> u32 {
        sysctl_u32("debug.bpf_maxbufsize")
            .map_or(MAX_BPF_BUFFER, |m| m.min(MAX_BPF_BUFFER))
            .max(4096)
    }

    fn open_node(&mut self, index: u32) -> Result<BpfFd, Errno> {
        BpfFd::open_node(index)
    }
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
