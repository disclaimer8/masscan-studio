//! Общие примитивы Unix (Linux и macOS): одно проверенное место для вызовов, которые раньше повторялись в
//! `linux::{socket, route}`, `macos::{route, sys}`, `interrupt` и `lab_io`. Каждый `unsafe`-блок узкий и опирается
//! только на то, что обёртка проверяет сама; наружу не выходят сырые указатели и неочищаемые fd.
//!
//! Флаги, тексты ошибок, округление таймаутов и повторы после `EINTR` остаются у вызывающих: примитивы передают
//! аргументы ядру как есть и возвращают сырой errno.

use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use libc::{c_int, c_short};

/// errno последнего вызова; `EIO`, если ОС не дала номера.
pub(crate) fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// `socket(domain, ty, proto)`: флаги (`SOCK_CLOEXEC`, `SOCK_NONBLOCK`) передаются как есть, своих не добавляется.
/// `Err` несёт errno; fd при ошибке не создаётся.
pub(crate) fn socket(domain: c_int, ty: c_int, proto: c_int) -> Result<OwnedFd, i32> {
    // SAFETY: socket() принимает только целые аргументы; предусловий по памяти нет.
    let raw = unsafe { libc::socket(domain, ty, proto) };
    if raw < 0 {
        return Err(last_errno());
    }
    // SAFETY: `raw` только что вернул успешный socket() (>= 0) и больше нигде не хранится, поэтому `OwnedFd`
    // становится его единственным владельцем.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// `poll` одного fd: `(n, revents)` при успехе; толкование (таймаут, готовность, ошибка сокета) у вызывающего.
pub(crate) fn poll_one(
    fd: BorrowedFd<'_>,
    events: c_short,
    timeout_ms: c_int,
) -> Result<(c_int, c_short), i32> {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events,
        revents: 0,
    };
    // SAFETY: передаётся ровно одна живая `pollfd` (nfds == 1); `fd` заимствован, поэтому открыт весь вызов.
    let n = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
    if n < 0 {
        Err(last_errno())
    } else {
        Ok((n, pfd.revents))
    }
}

/// `size_of::<T>()` как `socklen_t` (длина адреса или опции сокета). Размер сверяется с `socklen_t::MAX` при
/// компиляции: тип, который не помещается, не собирается, поэтому `as` здесь значения не теряет.
#[cfg(any(target_os = "linux", test))]
#[allow(
    clippy::cast_possible_truncation,
    reason = "the const assert proves that size_of::<T>() fits socklen_t"
)]
pub(crate) const fn socklen_of<T>() -> libc::socklen_t {
    const { assert!(std::mem::size_of::<T>() <= libc::socklen_t::MAX as usize) };
    std::mem::size_of::<T>() as libc::socklen_t
}

/// `setsockopt` целого значения; `Err` несёт errno.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn setsockopt_int(
    fd: BorrowedFd<'_>,
    level: c_int,
    name: c_int,
    value: c_int,
) -> Result<(), i32> {
    // SAFETY: указатель и длина описывают живой локальный `value` (`c_int`); `fd` заимствован, поэтому открыт весь
    // вызов.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&raw const value).cast::<libc::c_void>(),
            socklen_of::<c_int>(),
        )
    };
    if rc < 0 { Err(last_errno()) } else { Ok(()) }
}

/// Обработчик `handler` сигнала `sig` через `sigaction`: `SA_RESTART`, пустая маска, без `SA_RESETHAND` (обработчик
/// остаётся на следующие сигналы). `Err` несёт errno.
///
/// `handler` обязан быть async-signal-safe (трогать только статические атомики и вызовы, допустимые в обработчике
/// сигнала): его зовут `interrupt::on_sigint` (атомарный счётчик и `_exit`) и `lab_io::on_signal` (запись в атомик),
/// оба async-signal-safe.
pub(crate) fn install_handler(sig: c_int, handler: extern "C" fn(c_int)) -> Result<(), i32> {
    // SAFETY: поля `sigaction` это адрес обработчика (целое `sighandler_t`), `sigset_t` (массив целых), `sa_flags` и
    // на Linux `sa_restorer` (`Option` указателя на функцию, нулевой образ это `None`); нулевой образ каждого поля
    // допустим как начальное значение.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    // Адрес функции как целое `sighandler_t` (`size_t`): указатель на функцию переводится в адрес только `as`
    // (иначе `transmute`), значение не меняется.
    action.sa_sigaction = handler as libc::sighandler_t;
    action.sa_flags = libc::SA_RESTART;
    // SAFETY: `sa_mask` это поле живой локальной `action`, указатель исключительный и действует весь вызов.
    unsafe { libc::sigemptyset(&raw mut action.sa_mask) };
    // SAFETY: указатель на новое действие ссылается на живую, полностью инициализированную локальную `action`;
    // указатель на старое нулевой, что `sigaction` допускает; `handler` это `extern "C"` функция.
    let rc = unsafe { libc::sigaction(sig, &raw const action, std::ptr::null_mut()) };
    if rc != 0 { Err(last_errno()) } else { Ok(()) }
}

/// Адрес ядра для netlink: `AF_NETLINK`, `nl_pid` 0 (ядро), без групп.
#[cfg(target_os = "linux")]
pub(crate) fn nl_kernel_addr() -> libc::sockaddr_nl {
    // SAFETY: `sockaddr_nl` состоит из целых полей (одно из них закрытый паддинг, поэтому литерал структуры
    // невозможен); нулевой образ корректен: `nl_pid` 0 это ядро, `nl_groups` 0 это без групп.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr
}

/// Первые шесть байт массива `c_char` (`sa_data` адреса канального уровня) как MAC; более короткий источник
/// оставляет хвост нулевым.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn mac_from_c_chars(src: &[libc::c_char]) -> [u8; 6] {
    let mut mac = [0u8; 6];
    for (dst, src) in mac.iter_mut().zip(src) {
        *dst = u8::from_ne_bytes(src.to_ne_bytes());
    }
    mac
}

#[cfg(test)]
#[path = "unix_sys_tests.rs"]
mod tests;
