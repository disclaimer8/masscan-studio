//! Измерения собственного процесса для harness (только Windows): handle,
//! потоки, рабочий набор, времена CPU и флаги токена. Весь FFI здесь, под
//! lint-ами crate (`undocumented_unsafe_blocks`); пример вызывает безопасные
//! функции. Всё, что измерить не удалось, это `None`, не 0.

use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, HandleOrInvalid, OwnedHandle};

use windows_sys::Win32::Foundation::{FILETIME, GetLastError, HANDLE, SetLastError};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsTokenRestricted, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, GetProcessHandleCount,
    GetProcessTimes, OpenProcessToken,
};

use crate::{ProcessSample, TokenFlags};

// Размеры структур Win32 как `DWORD` (`dwSize`, `cb`, длина буфера): `as` в `const` рядом с проверкой, что размер
// помещается в `u32`.
#[allow(
    clippy::cast_possible_truncation,
    reason = "the assert proves that the size fits u32"
)]
const THREADENTRY32_SIZE: u32 = {
    assert!(size_of::<THREADENTRY32>() <= 0xFFFF_FFFF);
    size_of::<THREADENTRY32>() as u32
};
#[allow(
    clippy::cast_possible_truncation,
    reason = "the assert proves that the size fits u32"
)]
const PROCESS_MEMORY_COUNTERS_SIZE: u32 = {
    assert!(size_of::<PROCESS_MEMORY_COUNTERS>() <= 0xFFFF_FFFF);
    size_of::<PROCESS_MEMORY_COUNTERS>() as u32
};
#[allow(
    clippy::cast_possible_truncation,
    reason = "the assert proves that the size fits u32"
)]
const TOKEN_ELEVATION_SIZE: u32 = {
    assert!(size_of::<TOKEN_ELEVATION>() <= 0xFFFF_FFFF);
    size_of::<TOKEN_ELEVATION>() as u32
};

fn ft_ms(f: &FILETIME) -> u64 {
    // FILETIME это 100-нс интервалы.
    ((u64::from(f.dwHighDateTime) << 32) | u64::from(f.dwLowDateTime)) / 10_000
}

/// Снимок потоков Toolhelp во владении (`CloseHandle` в `Drop`, ровно один раз); `None`, если снимок не создан
/// (`INVALID_HANDLE_VALUE`).
fn thread_snapshot() -> Option<OwnedHandle> {
    // SAFETY: вызов без указателей.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    // SAFETY: `raw` это результат CreateToolhelp32Snapshot: при сбое INVALID_HANDLE_VALUE (`try_from` отвергает его,
    // ничего не закрывая), иначе новый handle снимка, которым больше никто не владеет.
    OwnedHandle::try_from(unsafe { HandleOrInvalid::from_raw_handle(raw) }).ok()
}

/// Идентификаторы потоков процесса `me` в снимке `snap`, в порядке снимка: `Thread32First`, затем `Thread32Next` до
/// первого FALSE.
fn snapshot_thread_ids(snap: &OwnedHandle, me: u32) -> impl Iterator<Item = u64> {
    let mut e = THREADENTRY32 {
        dwSize: THREADENTRY32_SIZE,
        ..Default::default()
    };
    let mut first = true;
    std::iter::from_fn(move || {
        let h = snap.as_raw_handle();
        // SAFETY: h это живой снимок потоков (`snap` заимствован итератором), e имеет верный dwSize.
        let ok = unsafe {
            if first {
                Thread32First(h, &mut e)
            } else {
                Thread32Next(h, &mut e)
            }
        };
        first = false;
        (ok != 0).then_some(e)
    })
    .filter(move |e| e.th32OwnerProcessID == me)
    .map(|e| u64::from(e.th32ThreadID))
}

/// Число потоков процесса по одному снимку Toolhelp ([`thread_ids`]; `None` там же, где у него). Снимок может
/// разойтись с действительностью на потоки, которые рождаются или завершаются в этот момент (та же гонка, что у
/// `/proc/self/task` на Linux).
fn thread_count() -> Option<u64> {
    // Длина `Vec` помещается в `u64` (`usize::BITS <= 64`, lib.rs): запасная ветка недостижима.
    thread_ids().map(|ids| u64::try_from(ids.len()).unwrap_or(u64::MAX))
}

/// Идентификатор текущего потока ОС (для сверки потоков движка до и после join).
pub(crate) fn current_thread_id() -> Option<u64> {
    // SAFETY: GetCurrentThreadId без предусловий.
    Some(u64::from(unsafe { GetCurrentThreadId() }))
}

/// Идентификаторы всех потоков процесса по снимку Toolhelp (`None`, если снимок
/// недоступен или пуст). Нужны, чтобы проверить конкретные потоки движка, а не
/// общее число потоков: системные рабочие потоки Windows переживают join.
pub(crate) fn thread_ids() -> Option<Vec<u64>> {
    let snap = thread_snapshot()?;
    // SAFETY: GetCurrentProcessId без предусловий.
    let me = unsafe { GetCurrentProcessId() };
    let ids: Vec<u64> = snapshot_thread_ids(&snap, me).collect();
    // В живом процессе хотя бы один поток есть: пустой снимок неполон. Снимок закрывается после обхода (`Drop`).
    (!ids.is_empty()).then_some(ids)
}

pub(crate) fn process_sample() -> ProcessSample {
    let mut s = ProcessSample::default();
    // SAFETY: псевдо-handle текущего процесса не требует закрытия.
    let me = unsafe { GetCurrentProcess() };

    let mut count = 0u32;
    // SAFETY: me валиден, count это валидный выходной параметр.
    if unsafe { GetProcessHandleCount(me, &mut count) } != 0 {
        s.handles = Some(u64::from(count));
    }

    let z = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut create, mut exit, mut kernel, mut user) = (z, z, z, z);
    // SAFETY: me валиден, четыре FILETIME это валидные выходные параметры.
    if unsafe { GetProcessTimes(me, &mut create, &mut exit, &mut kernel, &mut user) } != 0 {
        s.cpu_kernel_ms = Some(ft_ms(&kernel));
        s.cpu_user_ms = Some(ft_ms(&user));
    }

    // SAFETY: структура из нулей допустима для PROCESS_MEMORY_COUNTERS.
    let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    pmc.cb = PROCESS_MEMORY_COUNTERS_SIZE;
    // SAFETY: me валиден, pmc имеет размер cb.
    if unsafe { K32GetProcessMemoryInfo(me, &mut pmc, pmc.cb) } != 0 {
        s.working_set_bytes = u64::try_from(pmc.WorkingSetSize).ok();
        s.peak_working_set_bytes = u64::try_from(pmc.PeakWorkingSetSize).ok();
    }
    s.threads = thread_count();
    s
}

/// `IsTokenRestricted` возвращает 0 и для «не ограничен», и для ошибки: отличить
/// можно только по `GetLastError` (0 при успехе, если его обнулили заранее).
/// Неизвестное это `None`, не `Some(false)`.
fn restricted_from(rc: i32, last_error: u32) -> Option<bool> {
    if rc != 0 {
        Some(true)
    } else if last_error == 0 {
        Some(false)
    } else {
        None
    }
}

pub(crate) fn token_flags() -> TokenFlags {
    let mut raw: HANDLE = std::ptr::null_mut();
    // SAFETY: псевдо-handle процесса; raw валидный выходной параметр.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return TokenFlags::default();
    }
    // SAFETY: OpenProcessToken успешен: raw это открытый им handle токена, которым больше никто не владеет;
    // `OwnedHandle` закрывает его ровно один раз.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut el = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret = 0u32;
    // SAFETY: token открыт с TOKEN_QUERY и жив; el имеет размер size_of::<TOKEN_ELEVATION>().
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&raw mut el).cast(),
            TOKEN_ELEVATION_SIZE,
            &mut ret,
        )
    };
    // SAFETY: SetLastError/GetLastError без предусловий; token открыт нами с
    // TOKEN_QUERY и жив. Код ошибки обнуляется заранее, иначе 0 не отличить от сбоя.
    let (rc, last_error) = unsafe {
        SetLastError(0);
        let rc = IsTokenRestricted(token.as_raw_handle());
        (rc, GetLastError())
    };
    // Закрытие там же, где прежний `CloseHandle`: после IsTokenRestricted и GetLastError.
    drop(token);
    TokenFlags {
        elevated: (ok != 0).then_some(el.TokenIsElevated != 0),
        restricted: restricted_from(rc, last_error),
    }
}

#[cfg(test)]
mod tests {
    use super::{current_thread_id, restricted_from, thread_count, thread_ids};

    /// One Toolhelp snapshot: the calling thread is among the process's threads.
    #[test]
    fn thread_ids_contain_the_current_thread() {
        let me = current_thread_id().expect("current thread id");
        let ids = thread_ids().expect("a thread snapshot of a live process is not empty");
        assert!(ids.contains(&me), "thread {me} not in {ids:?}");
    }

    /// One Toolhelp snapshot: a live process has at least one thread.
    #[test]
    fn thread_count_is_at_least_one() {
        let n = thread_count();
        assert!(n.is_some_and(|n| n >= 1), "{n:?}");
    }

    #[test]
    fn restricted_result_zero_with_an_error_is_unknown() {
        assert_eq!(restricted_from(1, 0), Some(true));
        assert_eq!(restricted_from(0, 0), Some(false));
        // 0 при ненулевом GetLastError это сбой вызова, не «не ограничен».
        assert_eq!(restricted_from(0, 5), None);
    }
}
