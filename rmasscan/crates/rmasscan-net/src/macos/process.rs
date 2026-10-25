//! Измерения собственного процесса для harness (macOS): CPU, пик RSS, RSS,
//! потоки, дескрипторы, идентификаторы потоков. Служебный API, не продуктовый.
//!
//! Правило честности: то, что измерить не удалось, это `None`, а не 0.
//! `handles` это число записей `/dev/fd` минус 1: сам дескриптор, открытый
//! `read_dir` для перечисления, в списке присутствует и не является ресурсом
//! процесса. Это неатомарный снимок: пока другие потоки открывают и закрывают fd,
//! значение может быть неточным в обе стороны; точно оно у неподвижного процесса.
//! На Linux harness считает `/proc/self/fd` без вычитания, то есть на 1 больше.

use crate::ProcessSample;

/// `PROC_PIDLISTTHREADIDS`: приватный (SPI) flavor XNU `proc_info_private.h`, в
/// публичном SDK и в `libc` его нет; поведение измерено на macOS 27.0.1. Не
/// `PROC_PIDLISTTHREADS` (6): тот отдаёт thread handle (адрес TSD), не равный
/// `pthread_threadid_np`. Защита от смены смысла в будущей ОС: `thread_ids()`
/// возвращает `None`, если в списке нет текущего потока.
const PROC_PIDLISTTHREADIDS: libc::c_int = 28;

/// Миллисекунды `timeval`; `None` при отрицательных или переполняющих значениях.
fn tv_ms(t: &libc::timeval) -> Option<u64> {
    let s = u64::try_from(t.tv_sec).ok()?;
    let us = u64::try_from(t.tv_usec).ok()?;
    s.checked_mul(1000)?.checked_add(us / 1000)
}

fn rusage_self() -> Option<libc::rusage> {
    // SAFETY: `rusage` это POD из чисел, нулевое значение допустимо.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `ru` живёт на стеке и достаточен по размеру; RUSAGE_SELF это
    // валидный `who`, функция пишет только в `ru`.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    (rc == 0).then_some(ru)
}

fn task_info() -> Option<libc::proc_taskinfo> {
    // SAFETY: `proc_taskinfo` это POD из чисел, нулевое значение допустимо.
    let mut ti: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_taskinfo>()).ok()?;
    // SAFETY: буфер `ti` валиден на `size` байт; pid собственного процесса;
    // ядро пишет не более `size` байт и возвращает число записанных.
    let n = unsafe {
        libc::proc_pidinfo(
            getpid(),
            libc::PROC_PIDTASKINFO,
            0,
            std::ptr::from_mut(&mut ti).cast(),
            size,
        )
    };
    (n == size).then_some(ti)
}

fn fd_count() -> Option<u64> {
    let n = std::fs::read_dir("/dev/fd").ok()?.count() as u64;
    n.checked_sub(1)
}

pub(crate) fn process_sample() -> ProcessSample {
    let ru = rusage_self();
    let ti = task_info();
    ProcessSample {
        handles: fd_count(),
        threads: ti.and_then(|t| u64::try_from(t.pti_threadnum).ok()),
        working_set_bytes: ti.map(|t| t.pti_resident_size),
        // На macOS `ru_maxrss` в байтах (не в КиБ, как на Linux).
        peak_working_set_bytes: ru.and_then(|r| u64::try_from(r.ru_maxrss).ok()),
        cpu_user_ms: ru.as_ref().and_then(|r| tv_ms(&r.ru_utime)),
        cpu_kernel_ms: ru.as_ref().and_then(|r| tv_ms(&r.ru_stime)),
    }
}

/// Идентификатор текущего потока (тот же, что даёт `PROC_PIDLISTTHREADIDS`).
pub(crate) fn current_thread_id() -> Option<u64> {
    let mut id: u64 = 0;
    // SAFETY: NULL означает «текущий поток»; `id` валиден для записи u64.
    let rc = unsafe { libc::pthread_threadid_np(0, &mut id) };
    (rc == 0).then_some(id)
}

/// Идентификаторы всех потоков процесса.
pub(crate) fn thread_ids() -> Option<Vec<u64>> {
    let pid = getpid();
    let mut cap = 64usize;
    for _ in 0..8 {
        let mut buf = vec![0u64; cap];
        let bytes = libc::c_int::try_from(cap * 8).ok()?;
        // SAFETY: `buf` валиден на `bytes` байт; ядро пишет не более
        // `bytes` и возвращает число записанных байт или <= 0 при ошибке.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                PROC_PIDLISTTHREADIDS,
                0,
                buf.as_mut_ptr().cast(),
                bytes,
            )
        };
        if n <= 0 {
            return None;
        }
        let n = usize::try_from(n).ok()? / 8;
        // Заполнен весь буфер: потоков могло быть больше, расширяем.
        if n < cap {
            buf.truncate(n);
            // Fail closed: SPI-flavor обязан вернуть наш собственный id.
            let me = current_thread_id()?;
            return buf.contains(&me).then_some(buf);
        }
        cap *= 4;
    }
    None
}

fn getpid() -> libc::c_int {
    // SAFETY: `getpid` не имеет предусловий и не может завершиться ошибкой.
    unsafe { libc::getpid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_sample_fields_are_some_on_macos() {
        let s = process_sample();
        assert!(s.threads.is_some_and(|t| t >= 1), "{s:?}");
        assert!(s.handles.is_some_and(|h| h >= 3), "{s:?}");
        assert!(s.working_set_bytes.is_some(), "{s:?}");
        assert!(s.peak_working_set_bytes.is_some(), "{s:?}");
        assert!(
            s.cpu_user_ms.is_some() && s.cpu_kernel_ms.is_some(),
            "{s:?}"
        );
    }

    #[test]
    fn thread_ids_contain_the_current_thread() {
        let me = current_thread_id().expect("pthread_threadid_np");
        let all = thread_ids().expect("PROC_PIDLISTTHREADIDS");
        assert!(all.contains(&me), "{me} not in {all:?}");
        // Новый поток виден в списке, пока он жив, и исчезает после join.
        let (tx, rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            tx.send(current_thread_id().unwrap()).unwrap();
            go_rx.recv().unwrap();
        });
        let other = rx.recv().unwrap();
        assert_ne!(other, me);
        assert!(thread_ids().unwrap().contains(&other));
        go_tx.send(()).unwrap();
        h.join().unwrap();
        // После join id исчезает; ядро убирает поток чуть позже, ждём ограниченно
        // (до 1 с) без опоры на точность sleep.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while thread_ids().unwrap().contains(&other) {
            assert!(
                std::time::Instant::now() < deadline,
                "{other} still listed after join"
            );
            std::thread::yield_now();
        }
    }
}
