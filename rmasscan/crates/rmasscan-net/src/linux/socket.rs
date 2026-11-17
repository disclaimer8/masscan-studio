//! Private FFI-слой Linux AF_PACKET. Каждый syscall завернут в безопасную
//! функцию/метод; наружу не выходят сырые указатели и неочищаемые ресурсы.
//! `socket`, `poll` одного fd и `setsockopt` целого идут через общие
//! примитивы `crate::unix_sys`; здесь остаются `bind`, `send`, `recvfrom`,
//! `getsockopt` и ioctl интерфейса:
//!
//! * fd всегда живёт в `OwnedFd` (закрывается в Drop ровно один раз);
//! * все буферы это срезы Rust, длина берётся из самого среза;
//! * `sockaddr_ll` собирается литералом структуры (все поля публичны);
//!   нулями (`mem::zeroed`) инициализируется только `ifreq` (union);
//! * других ресурсов libc, требующих освобождения, нет.

use std::ffi::CString;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use super::{Errno, IfaceInfo, KernelStats, PacketIo, Readiness, RecvMeta};
use crate::unix_sys::{last_errno, poll_one, setsockopt_int, socket};

/// Буфер приёма, который просит RX-сокет (P5): 4 MiB. С буфером по умолчанию (`net.core.rmem_default`, около
/// 208 KiB, ≈190 кадров RST) пауза потока RX в несколько миллисекунд при десятках тысяч ответов в секунду
/// переполняет очередь сокета, а движок считает любую потерю ядра фатальной (`RxLoss`).
const RX_SOCKET_BUFFER: libc::c_int = 4 << 20;

/// Запрос буфера приёма RX-сокета через `set(name, value)` = `setsockopt(SOL_SOCKET, name, value)`: сначала
/// `SO_RCVBUFFORCE` (нужен CAP_NET_ADMIN, снимает предел `net.core.rmem_max`), при `EPERM` — `SO_RCVBUF` (ядро
/// ограничивает его `rmem_max`). Ядро хранит и отдаёт `getsockopt` удвоенное значение. Возвращает итог последнего
/// вызова; открытие сокета его игнорирует.
fn request_rx_buffer(
    mut set: impl FnMut(libc::c_int, libc::c_int) -> Result<(), Errno>,
) -> Result<(), Errno> {
    match set(libc::SO_RCVBUFFORCE, RX_SOCKET_BUFFER) {
        Err(libc::EPERM) => set(libc::SO_RCVBUF, RX_SOCKET_BUFFER),
        r => r,
    }
}

/// ETH_P_ALL в сетевом порядке байт для `sll_protocol`.
pub(super) const ETH_P_ALL_BE: u16 = (libc::ETH_P_ALL as u16).to_be();

/// Минимальный размер адреса, при котором доступны `sll_ifindex` и
/// `sll_pkttype` (offsetof(sll_addr) == 12).
pub(super) const SLL_MIN_LEN: usize = mem::offset_of!(libc::sockaddr_ll, sll_addr);

/// `sockaddr_ll` с семейством, протоколом и ifindex; остальные поля нулевые.
fn sockaddr_ll(
    family: libc::c_ushort,
    protocol_be: u16,
    ifindex: libc::c_int,
) -> libc::sockaddr_ll {
    libc::sockaddr_ll {
        sll_family: family,
        sll_protocol: protocol_be,
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    }
}

/// Неблокирующий AF_PACKET SOCK_RAW fd, привязанный к одному ifindex.
pub(super) struct PacketFd {
    fd: OwnedFd,
}

impl PacketFd {
    /// Создаёт сокет БЕЗ протокола (ничего не принимает до bind) и привязывает
    /// его к `ifindex`. `protocol_be == 0` для TX, `ETH_P_ALL_BE` для RX.
    pub(super) fn open(ifindex: u32, protocol_be: u16) -> Result<PacketFd, Errno> {
        let fd = socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )?;
        if protocol_be == ETH_P_ALL_BE {
            // Только RX-сокет, до bind (после bind кадры уже идут в очередь): буфер приёма 4 MiB (P5). Любой отказ
            // безвреден, как у PACKET_IGNORE_OUTGOING ниже: сокет остаётся с буфером по умолчанию.
            let _ = request_rx_buffer(|name, value| {
                setsockopt_int(fd.as_fd(), libc::SOL_SOCKET, name, value)
            });
        }

        let addr = sockaddr_ll(
            libc::AF_PACKET as libc::c_ushort,
            protocol_be,
            ifindex as libc::c_int,
        );
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
        if protocol_be == ETH_P_ALL_BE {
            // Только RX-сокет (ETH_P_ALL); TX-сокет открыт с протоколом 0 и ничего не принимает.
            // RX-сокет не должен получать в очередь копии НАШИХ ЖЕ исходящих кадров: при 100k pps
            // user-space фильтр PACKET_OUTGOING не успевает их вычитывать, очередь сокета
            // переполняется и ядро роняет настоящие ответы. PACKET_IGNORE_OUTGOING
            // (SOL_PACKET, 23, Linux 4.20+) отбрасывает их в ядре. На старых ядрах setsockopt
            // безвредно падает, и запасным остаётся user-space фильтр PACKET_OUTGOING.
            // Результат намеренно игнорируется (см. выше).
            let _ = setsockopt_int(
                fd.as_fd(),
                libc::SOL_PACKET,
                libc::PACKET_IGNORE_OUTGOING,
                1,
            );
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
        let mut sll = sockaddr_ll(0, 0, 0);
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
        let (n, revents) = poll_one(self.fd.as_fd(), want, timeout_ms)?;
        Ok(match n {
            0 => Readiness::Timeout,
            _ if revents & want != 0 => Readiness::Ready,
            _ => Readiness::Failed,
        })
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
        Ok(KernelStats { drops: st.tp_drops })
    }

    fn backoff(&mut self, wait: std::time::Duration) {
        std::thread::sleep(wait);
    }
}

/// Датаграммный сокет AF_INET только для ioctl `SIOCGIFHWADDR` (без привилегий, `SOCK_CLOEXEC`).
pub(super) fn ioctl_socket() -> Result<OwnedFd, Errno> {
    socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)
}

/// Проверка интерфейса через ОС (if_nametoindex, SIOCGIFHWADDR).
/// Не требует привилегий.
pub(super) struct OsIface;

pub(super) fn ifreq_for(name: &str) -> Result<libc::ifreq, Errno> {
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

    fn link_family(&self, name: &str) -> Result<u16, Errno> {
        let mut ifr = ifreq_for(name)?;
        let sock = ioctl_socket()?;
        // SAFETY: `ifr` живой ifreq с NUL-терминированным именем; для
        // SIOCGIFHWADDR ядро читает имя и пишет sockaddr в тот же объект.
        let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFHWADDR as _, &raw mut ifr) };
        if rc < 0 {
            return Err(last_errno());
        }
        // SAFETY: после успешного SIOCGIFHWADDR активен вариант ifru_hwaddr (sockaddr из целых).
        Ok(unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_family })
    }
}

#[cfg(test)]
#[path = "socket_tests.rs"]
mod tests;
