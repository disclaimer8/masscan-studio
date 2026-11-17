//! Номера Linux, которые читает переносимая логика адаптера (`TxHalf`, `RxHalf`, `verify_binding`) и её тесты: errno,
//! тип канала `ARPHRD_ETHER` и `PACKET_OUTGOING`. Модуль не использует `libc`, поэтому эта логика и `linux/tests.rs`
//! собираются в тестах на любой ОС (образец: `macos::abi`). Равенство `libc` проверяет `layout_tests` на Linux.
//!
//! На Mac и Windows `errno_msg` печатает эти номера таблицей хоста (номер Linux 11 на Mac выглядит как EDEADLK),
//! поэтому переносимые тесты сверяют вид ошибки, а текст строят той же функцией хоста.

/// Тип канала Ethernet (`ifi_type`, `sa_family` адреса `SIOCGIFHWADDR`); один источник с разбором наблюдения.
pub(crate) use crate::route_parse::ARPHRD_ETHER;

/// `sll_pkttype` собственного исходящего кадра (`linux/if_packet.h`).
pub(crate) const PACKET_OUTGOING: u8 = 4;

/// Номера errno Linux (`asm-generic/errno-base.h`, `asm-generic/errno.h`). Номера, по которым настройка выбирает
/// вид ошибки, общие с macOS и берутся из `adapter_common::errno`.
///
/// Каждый номер собирается только там, где его читают, иначе clippy `-D warnings` отвергает тупиковый код на одной из
/// ОС: номера только для тестов стоят под `cfg(test)` (`EPROTO` — запись с коротким адресом в сценариях шва; сокет
/// Linux берёт его из `libc`, как и прежде), а `ENOBUFS` сейчас читает одна сверка с `libc` на Linux.
pub(crate) mod errno {
    pub(crate) use crate::adapter_common::errno::ENODEV;
    #[cfg(test)]
    pub(crate) use crate::adapter_common::errno::{EACCES, ENXIO, EPERM};

    pub(crate) const EINTR: i32 = 4;
    /// `sendmmsg` без принятых сообщений и без errno (`TxHalf::send_batch`).
    pub(crate) const EIO: i32 = 5;
    pub(crate) const EBADF: i32 = 9;
    pub(crate) const EAGAIN: i32 = 11;
    /// Пачка приёма без слотов или метаданных (`batch_len`), пачка передачи без кадров или мест для длин (`send_count`).
    pub(crate) const EINVAL: i32 = 22;
    /// На Linux равен `EAGAIN`.
    pub(crate) const EWOULDBLOCK: i32 = 11;
    #[cfg(test)]
    pub(crate) const EPROTO: i32 = 71;
    #[cfg(test)]
    pub(crate) const ENOPROTOOPT: i32 = 92;
    #[cfg(test)]
    pub(crate) const ENETDOWN: i32 = 100;
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) const ENOBUFS: i32 = 105;
}
