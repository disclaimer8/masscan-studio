//! Private FFI-слой Linux AF_PACKET. Каждый syscall завернут в безопасную
//! функцию/метод; наружу не выходят сырые указатели и неочищаемые ресурсы.
//! `socket`, `poll` одного fd и `setsockopt` целого идут через общие
//! примитивы `crate::unix_sys`; здесь остаются `bind`, `send`, `sendmmsg`
//! (пачка передачи), `recvmmsg` (единственный приём: и пачка, и прямой
//! `recv`), `getsockopt` и ioctl интерфейса:
//!
//! * fd всегда живёт в `OwnedFd` (закрывается в Drop ровно один раз);
//! * все буферы это срезы Rust, длина берётся из самого среза;
//! * `sockaddr_ll`, `iovec`, `msghdr` и `mmsghdr` собираются литералами
//!   структур (все поля публичны); нулями (`mem::zeroed`) инициализируется
//!   только `ifreq` (union);
//! * других ресурсов libc, требующих освобождения, нет.

use std::ffi::CString;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::ptr;

use super::{
    Errno, IfaceInfo, KernelStats, PacketIo, RX_BATCH, RX_SLOT, Readiness, RecvMeta, SlotMeta,
    TX_BATCH_FRAMES, batch_len, send_count,
};
use crate::unix_sys::{last_errno, poll_one, setsockopt_int, socket, socklen_of};

/// Буфер приёма, который просит RX-сокет (P5): 4 MiB. С буфером по умолчанию (`net.core.rmem_default`, около
/// 208 KiB, ≈190 кадров RST) пауза потока RX в несколько миллисекунд при десятках тысяч ответов в секунду
/// переполняет очередь сокета, а движок считает любую потерю ядра фатальной (`RxLoss`).
const RX_SOCKET_BUFFER: libc::c_int = 4 << 20;

/// Буфер передачи, который просит TX-сокет (P3, решение пользователя): 4 MiB обычным `SO_SNDBUF`, ядро режет запрос
/// до `net.core.wmem_max` и хранит удвоенное значение. На стенде veth эффект не измерим: поток TX там ни разу не ждал
/// места в буфере (0 `poll` на 1000 кадров, `BENCHMARKS.md`, «Задача 17»).
const TX_SOCKET_BUFFER: libc::c_int = 4 << 20;

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
#[allow(
    clippy::cast_possible_truncation,
    reason = "ETH_P_ALL is 3; the assert proves that it fits u16"
)]
pub(super) const ETH_P_ALL_BE: u16 = {
    assert!(libc::ETH_P_ALL >= 0 && libc::ETH_P_ALL <= 0xFFFF);
    (libc::ETH_P_ALL as u16).to_be()
};

/// `AF_PACKET` как `sll_family` (`c_ushort`).
#[allow(
    clippy::cast_possible_truncation,
    reason = "AF_PACKET is 17; the assert proves that it fits c_ushort"
)]
const AF_PACKET_FAMILY: libc::c_ushort = {
    assert!(libc::AF_PACKET >= 0 && libc::AF_PACKET <= 0xFFFF);
    libc::AF_PACKET as libc::c_ushort
};

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

/// Куда [`PacketFd::recv_msgs`] кладёт сообщения.
enum RecvInto<'a> {
    /// Слоты кольца RX: сообщение `i` в `slots[i]`, `iov_len` ровно `RX_SLOT`.
    Slots(&'a mut [[u8; RX_SLOT]]),
    /// Один буфер вызывающего (прямой путь): `iov_len` — его длина.
    One(&'a mut [u8]),
}

/// `iovec` без буфера: запись массива за пределами `vlen` вызова; ядро её не читает.
const NO_IOV: libc::iovec = libc::iovec {
    iov_base: ptr::null_mut(),
    iov_len: 0,
};

/// `mmsghdr` без адреса и буфера: запись массива за пределами `vlen` вызова; ядро её не читает.
const NO_MSG: libc::mmsghdr = libc::mmsghdr {
    msg_hdr: libc::msghdr {
        msg_name: ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: ptr::null_mut(),
        msg_iovlen: 0,
        msg_control: ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    },
    msg_len: 0,
};

impl PacketFd {
    /// Создаёт сокет БЕЗ протокола (ничего не принимает до bind) и привязывает
    /// его к `ifindex`. `protocol_be == 0` для TX, `ETH_P_ALL_BE` для RX.
    pub(super) fn open(ifindex: u32, protocol_be: u16) -> Result<PacketFd, Errno> {
        Self::open_with_qdisc_bypass(ifindex, protocol_be, true)
    }

    /// То же, что [`Self::open`], но позволяет отключить `PACKET_QDISC_BYPASS` на TX-сокете
    /// (используется лабораторией `rmasscan-lab`, когда `tcpdump` слушает тот же интерфейс).
    pub(super) fn open_with_qdisc_bypass(
        ifindex: u32,
        protocol_be: u16,
        qdisc_bypass: bool,
    ) -> Result<PacketFd, Errno> {
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

        let addr = sockaddr_ll(AF_PACKET_FAMILY, protocol_be, ifindex.cast_signed());
        // SAFETY: `addr` живёт до конца вызова, указатель и длина описывают
        // именно этот объект; fd валиден (владеет OwnedFd).
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast::<libc::sockaddr>(),
                socklen_of::<libc::sockaddr_ll>(),
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
        } else {
            // Только TX-сокет (protocol 0), P3 по решению пользователя: буфер передачи 4 MiB. Отказ безвреден, как
            // выше: сокет остаётся с буфером по умолчанию (`net.core.wmem_default`).
            let _ = setsockopt_int(
                fd.as_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                TX_SOCKET_BUFFER,
            );
            if qdisc_bypass {
                // P3 по решению пользователя: кадры идут в драйвер мимо qdisc интерфейса (Linux 3.14+): шейпинг `tc` на
                // них не действует, буфера qdisc нет (занятую очередь передачи драйвера ядро отдаёт как ENOBUFS, его
                // повторяет `TxHalf`), и другие AF_PACKET сокеты (tcpdump на интерфейсе скана) их не видят. Отказ
                // безвреден: кадры идут прежним путём через qdisc.
                let _ = setsockopt_int(fd.as_fd(), libc::SOL_PACKET, libc::PACKET_QDISC_BYPASS, 1);
            }
        }
        Ok(PacketFd { fd })
    }

    /// Единственный приём сокета: `recvmmsg` (MSG_TRUNC, таймаут NULL) до `batch_len` сообщений в слоты кольца или
    /// одного сообщения в буфер вызывающего. `Ok(n)`, n ≥ 1: `metas[..n]` заполнены; пусто — `Err(EAGAIN)`.
    /// Метаданные: длина — `msg_len` (истинная при MSG_TRUNC, может быть больше буфера), `pkttype` и `ifindex` — из
    /// адреса; `msg_namelen` выставляется перед вызовом и проверяется после: адрес короче `SLL_MIN_LEN` даёт
    /// `Err(EPROTO)` в слоте (без `pkttype` свой исходящий кадр не отличить). Ошибка не-EAGAIN после принятого
    /// префикса: ядро отдаёт префикс, а ошибку — следующим вызовом; исход тот же, что у покадрового пути, на вызов
    /// позже.
    fn recv_msgs(&mut self, into: RecvInto<'_>, metas: &mut [SlotMeta]) -> Result<usize, Errno> {
        let mut iov = [NO_IOV; RX_BATCH];
        let n = match into {
            RecvInto::Slots(slots) => {
                let n = batch_len(slots.len(), metas.len())?;
                for (v, slot) in iov.iter_mut().zip(slots.iter_mut()).take(n) {
                    *v = libc::iovec {
                        iov_base: slot.as_mut_ptr().cast::<libc::c_void>(),
                        iov_len: slot.len(),
                    };
                }
                n
            }
            RecvInto::One(buf) => {
                let n = batch_len(1, metas.len())?;
                iov[0] = libc::iovec {
                    iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
                    iov_len: buf.len(),
                };
                n
            }
        };
        let mut addrs = [sockaddr_ll(0, 0, 0); RX_BATCH];
        let mut msgs = [NO_MSG; RX_BATCH];
        for ((m, addr), v) in msgs
            .iter_mut()
            .zip(addrs.iter_mut())
            .zip(iov.iter_mut())
            .take(n)
        {
            *m = libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: (&raw mut *addr).cast::<libc::c_void>(),
                    msg_namelen: socklen_of::<libc::sockaddr_ll>(),
                    msg_iov: &raw mut *v,
                    msg_iovlen: 1,
                    msg_control: ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            };
        }
        let vlen = libc::c_uint::try_from(n).map_err(|_| libc::EINVAL)?;
        // SAFETY: ядру передаются первые `vlen` = n записей `msgs`, n = `batch_len(..)` ≤ RX_BATCH = длине `msgs`,
        // `addrs` и `iov` (проверено выше). У каждой из этих записей `msg_iov` указывает на свой живой `iovec`
        // (`msg_iovlen` 1), а тот — на свой слот `slots[i]` (i < n ≤ `slots.len()`) длиной ровно RX_SLOT или на буфер
        // вызывающего с его длиной: ядро пишет в буфер не больше `iov_len` байт. `msg_name` указывает на свой живой
        // `sockaddr_ll`, `msg_namelen` — его размер, ядро пишет не больше. Управляющих данных нет (NULL, 0), таймаут
        // NULL. Массивы и буферы живут до конца вызова и не перемещаются; fd валиден (владеет OwnedFd).
        let rc = unsafe {
            libc::recvmmsg(
                self.fd.as_raw_fd(),
                msgs.as_mut_ptr(),
                vlen,
                libc::MSG_TRUNC,
                ptr::null_mut(),
            )
        };
        // Ядро возвращает не больше `vlen` сообщений и при `vlen` ≥ 1 не возвращает 0; оба случая всё же сводятся к
        // контракту шва (не больше n, пусто — EAGAIN).
        let got = usize::try_from(rc).map_err(|_| last_errno())?.min(n);
        if got == 0 {
            return Err(libc::EAGAIN);
        }
        for ((meta, m), addr) in metas.iter_mut().zip(&msgs).zip(&addrs).take(got) {
            *meta = if usize::try_from(m.msg_hdr.msg_namelen).unwrap_or(usize::MAX) < SLL_MIN_LEN {
                // Без pkttype нельзя отличить исходящий кадр: не выдаём его.
                Err(libc::EPROTO)
            } else {
                Ok(RecvMeta {
                    len: usize::try_from(m.msg_len).unwrap_or(usize::MAX),
                    pkttype: addr.sll_pkttype,
                    ifindex: addr.sll_ifindex,
                })
            };
        }
        Ok(got)
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

    /// Одна пачка передачи: `sendmmsg` (MSG_NOSIGNAL, как `send`) первых `send_count` кадров, по одному `iovec` на
    /// сообщение, без адреса (сокет привязан к ifindex, как у `send`). Массивы — на стеке вызова, длины
    /// `TX_BATCH_FRAMES`; сырые указатели не переживают вызов, поэтому `PacketFd` остаётся `Send`.
    fn send_many(&mut self, frames: &[&[u8]], lens: &mut [usize]) -> Result<usize, Errno> {
        let n = send_count(frames.len(), lens.len())?;
        let mut iov = [NO_IOV; TX_BATCH_FRAMES];
        for (v, frame) in iov.iter_mut().zip(frames).take(n) {
            *v = libc::iovec {
                // Ядро только читает буфер передачи; `*mut` требует тип поля `iovec`.
                iov_base: frame.as_ptr().cast_mut().cast::<libc::c_void>(),
                iov_len: frame.len(),
            };
        }
        let mut msgs = [NO_MSG; TX_BATCH_FRAMES];
        for (m, v) in msgs.iter_mut().zip(iov.iter_mut()).take(n) {
            *m = libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: &raw mut *v,
                    msg_iovlen: 1,
                    msg_control: ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            };
        }
        let vlen = libc::c_uint::try_from(n).map_err(|_| libc::EINVAL)?;
        // SAFETY: ядру передаются первые `vlen` = n записей `msgs`, n = `send_count(..)` ≤ TX_BATCH_FRAMES = длине
        // `msgs` и `iov` (проверено выше), n ≤ `frames.len()` и n ≤ `lens.len()`. У каждой из этих записей `msg_iov`
        // указывает на свой живой `iovec` (`msg_iovlen` 1), а тот — на живой срез кадра `frames[i]` (i < n) с его
        // длиной: срезы заимствованы на весь вызов, ядро их только читает. Адреса нет (NULL, 0), управляющих данных
        // нет (NULL, 0). Ядро пишет только `msg_len` записей `msgs`, массивы живут до конца вызова и не перемещаются;
        // fd валиден (владеет OwnedFd).
        let rc = unsafe {
            libc::sendmmsg(
                self.fd.as_raw_fd(),
                msgs.as_mut_ptr(),
                vlen,
                libc::MSG_NOSIGNAL,
            )
        };
        // Ядро возвращает не больше `vlen` сообщений; -1 с errno — ошибка первого сообщения.
        let k = usize::try_from(rc).map_err(|_| last_errno())?.min(n);
        for (len, m) in lens.iter_mut().zip(&msgs).take(k) {
            *len = usize::try_from(m.msg_len).unwrap_or(usize::MAX);
        }
        Ok(k)
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<RecvMeta, Errno> {
        let mut meta: [SlotMeta; 1] = [Err(libc::EAGAIN)];
        self.recv_msgs(RecvInto::One(buf), &mut meta)?;
        let [meta] = meta;
        meta
    }

    fn recv_batch(
        &mut self,
        slots: &mut [[u8; RX_SLOT]],
        metas: &mut [SlotMeta],
    ) -> Result<usize, Errno> {
        self.recv_msgs(RecvInto::Slots(slots), metas)
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
        let mut len = socklen_of::<libc::tpacket_stats>();
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
        if len < socklen_of::<libc::tpacket_stats>() {
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
        *dst = libc::c_char::from_ne_bytes([*src]);
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
        let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFHWADDR, &raw mut ifr) };
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
