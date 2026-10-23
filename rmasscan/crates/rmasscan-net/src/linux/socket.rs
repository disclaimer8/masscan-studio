//! Private FFI-слой Linux AF_PACKET. ЕДИНСТВЕННОЕ место с `unsafe` во всём
//! workspace. Каждый syscall завернут в безопасную функцию/метод; наружу не
//! выходят сырые указатели и неочищаемые ресурсы:
//!
//! * fd всегда живёт в `OwnedFd` (закрывается в Drop ровно один раз);
//! * все буферы это срезы Rust, длина берётся из самого среза;
//! * C-структуры инициализируются нулями (`mem::zeroed`) только для типов,
//!   состоящих из целых и массивов целых, для которых нулевой образ корректен;
//! * других ресурсов libc, требующих освобождения, нет.

use std::ffi::CString;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::{Errno, IfaceInfo, KernelStats, PacketIo, Readiness, RecvMeta};

fn last_errno() -> Errno {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// ETH_P_ALL в сетевом порядке байт для `sll_protocol`.
pub(super) const ETH_P_ALL_BE: u16 = (libc::ETH_P_ALL as u16).to_be();

/// Минимальный размер адреса, при котором доступны `sll_ifindex` и
/// `sll_pkttype` (offsetof(sll_addr) == 12).
const SLL_MIN_LEN: usize = 12;

/// Неблокирующий AF_PACKET SOCK_RAW fd, привязанный к одному ifindex.
pub(super) struct PacketFd {
    fd: OwnedFd,
}

impl PacketFd {
    /// Создаёт сокет БЕЗ протокола (ничего не принимает до bind) и привязывает
    /// его к `ifindex`. `protocol_be == 0` для TX, `ETH_P_ALL_BE` для RX.
    pub(super) fn open(ifindex: u32, protocol_be: u16) -> Result<PacketFd, Errno> {
        // SAFETY: socket() принимает только целые аргументы; предусловий по
        // памяти нет. Результат проверяется ниже.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(last_errno());
        }
        // SAFETY: `raw` только что вернул socket(), он >= 0 и больше нигде не
        // хранится, поэтому OwnedFd становится единственным владельцем.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: sockaddr_ll состоит из целых и массива u8; нулевой образ
        // корректен.
        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as libc::c_ushort;
        addr.sll_protocol = protocol_be;
        addr.sll_ifindex = ifindex as libc::c_int;
        // SAFETY: `addr` живёт до конца вызова, указатель и длина описывают
        // именно этот объект; fd валиден (владеет OwnedFd).
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast::<libc::sockaddr>(),
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            // `fd` закрывается Drop'ом на выходе.
            return Err(last_errno());
        }
        Ok(PacketFd { fd })
    }
}

impl PacketIo for PacketFd {
    fn send(&mut self, frame: &[u8]) -> Result<usize, Errno> {
        // SAFETY: указатель и длина берутся из одного живого среза; fd
        // валиден. MSG_NOSIGNAL исключает SIGPIPE.
        let n = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                frame.as_ptr().cast::<libc::c_void>(),
                frame.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        usize::try_from(n).map_err(|_| last_errno())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<RecvMeta, Errno> {
        // SAFETY: sockaddr_ll: целые поля, нулевой образ корректен.
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        let mut slen = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        // SAFETY: буфер описан срезом (ptr+len одного объекта, ядро пишет не
        // более len байт); `sll` и `slen` это живые локальные объекты, `slen`
        // содержит их реальный размер. MSG_TRUNC заставляет вернуть
        // ИСТИННУЮ длину кадра даже если он длиннее буфера.
        let n = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                libc::MSG_TRUNC,
                (&raw mut sll).cast::<libc::sockaddr>(),
                &raw mut slen,
            )
        };
        let len = usize::try_from(n).map_err(|_| last_errno())?;
        if (slen as usize) < SLL_MIN_LEN {
            // Без pkttype нельзя отличить исходящий кадр: не выдаём его.
            return Err(libc::EPROTO);
        }
        Ok(RecvMeta {
            len,
            pkttype: sll.sll_pkttype,
            ifindex: sll.sll_ifindex,
        })
    }

    fn poll(&mut self, write: bool, timeout_ms: i32) -> Result<Readiness, Errno> {
        let want = if write { libc::POLLOUT } else { libc::POLLIN };
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: want,
            revents: 0,
        };
        // SAFETY: передаётся ровно один живой pollfd (nfds == 1).
        let rc = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
        match rc {
            r if r < 0 => Err(last_errno()),
            0 => Ok(Readiness::Timeout),
            _ if pfd.revents & want != 0 => Ok(Readiness::Ready),
            _ => Ok(Readiness::Failed),
        }
    }

    fn packet_stats(&mut self) -> Result<KernelStats, Errno> {
        let mut st = libc::tpacket_stats {
            tp_packets: 0,
            tp_drops: 0,
        };
        let mut len = mem::size_of::<libc::tpacket_stats>() as libc::socklen_t;
        // SAFETY: `st` и `len` живые локальные объекты; len равен размеру st,
        // ядро запишет не более len байт.
        let rc = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                (&raw mut st).cast::<libc::c_void>(),
                &raw mut len,
            )
        };
        if rc < 0 {
            return Err(last_errno());
        }
        if (len as usize) < mem::size_of::<libc::tpacket_stats>() {
            return Err(libc::EPROTO);
        }
        Ok(KernelStats {
            packets: st.tp_packets,
            drops: st.tp_drops,
        })
    }
}

/// Проверка интерфейса через ОС (if_nametoindex, SIOCGIFHWADDR).
/// Не требует привилегий.
pub(super) struct OsIface;

fn ifreq_for(name: &str) -> Result<libc::ifreq, Errno> {
    let bytes = name.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ || bytes.contains(&0) {
        return Err(libc::EINVAL);
    }
    // SAFETY: ifreq это union/массивы целых и указатель; нулевой образ
    // (в т.ч. нулевой указатель ifru_data) корректен.
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    for (dst, src) in ifr.ifr_name.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    Ok(ifr)
}

impl IfaceInfo for OsIface {
    fn ifindex(&self, name: &str) -> Result<Option<u32>, Errno> {
        let c = CString::new(name).map_err(|_| libc::EINVAL)?;
        // SAFETY: `c` NUL-терминирован и живёт до конца вызова.
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        if idx != 0 {
            return Ok(Some(idx));
        }
        match last_errno() {
            libc::ENODEV => Ok(None),
            e => Err(e),
        }
    }

    fn hw_addr(&self, name: &str) -> Result<(u16, [u8; 6]), Errno> {
        let mut ifr = ifreq_for(name)?;
        // SAFETY: socket() только с целыми аргументами.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(last_errno());
        }
        // SAFETY: `raw` свежий fd >= 0, единственный владелец теперь OwnedFd.
        let sock = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: `ifr` живой ifreq с NUL-терминированным именем; для
        // SIOCGIFHWADDR ядро читает имя и пишет sockaddr в тот же объект.
        let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFHWADDR as _, &raw mut ifr) };
        if rc < 0 {
            return Err(last_errno());
        }
        // SAFETY: после успешного SIOCGIFHWADDR активен вариант ifru_hwaddr.
        let sa = unsafe { ifr.ifr_ifru.ifru_hwaddr };
        let mut mac = [0u8; 6];
        for (dst, src) in mac.iter_mut().zip(sa.sa_data.iter()) {
            *dst = *src as u8;
        }
        Ok((sa.sa_family, mac))
    }
}
