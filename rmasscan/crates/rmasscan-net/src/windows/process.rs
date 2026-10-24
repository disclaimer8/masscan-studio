//! Измерения собственного процесса для harness (только Windows): handle,
//! потоки, рабочий набор, времена CPU и флаги токена. Весь FFI здесь, под
//! lint-ами crate (`undocumented_unsafe_blocks`); пример вызывает безопасные
//! функции. Всё, что измерить не удалось, это `None`, не 0.

use std::mem::size_of;

use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
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

fn ft_ms(f: &FILETIME) -> u64 {
    // FILETIME это 100-нс интервалы.
    ((u64::from(f.dwHighDateTime) << 32) | u64::from(f.dwLowDateTime)) / 10_000
}

/// Число потоков процесса по снимку Toolhelp. Снимок может разойтись с
/// действительностью на потоки, которые рождаются или завершаются в этот момент
/// (та же гонка, что у `/proc/self/task` на Linux).
fn thread_count() -> Option<u64> {
    // SAFETY: вызов без указателей; результат проверяется на INVALID_HANDLE_VALUE.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return None;
    }
    // SAFETY: GetCurrentProcessId без предусловий.
    let me = unsafe { GetCurrentProcessId() };
    // SAFETY: структура из нулей допустима для THREADENTRY32.
    let mut e: THREADENTRY32 = unsafe { std::mem::zeroed() };
    e.dwSize = size_of::<THREADENTRY32>() as u32;
    let mut n = 0u64;
    let mut ok = true;
    // SAFETY: snap это живой снимок потоков, e имеет верный dwSize.
    let mut more = unsafe { Thread32First(snap, &mut e) } != 0;
    while more {
        if e.th32OwnerProcessID == me {
            n += 1;
        }
        // SAFETY: snap жив, e по-прежнему с верным dwSize.
        more = unsafe { Thread32Next(snap, &mut e) } != 0;
    }
    if n == 0 {
        ok = false; // в живом процессе хотя бы один поток есть: снимок неполон
    }
    // SAFETY: snap это открытый нами handle, закрывается один раз.
    unsafe { CloseHandle(snap) };
    ok.then_some(n)
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
    // SAFETY: вызов без указателей; результат проверяется на INVALID_HANDLE_VALUE.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return None;
    }
    // SAFETY: GetCurrentProcessId без предусловий.
    let me = unsafe { GetCurrentProcessId() };
    // SAFETY: структура из нулей допустима для THREADENTRY32.
    let mut e: THREADENTRY32 = unsafe { std::mem::zeroed() };
    e.dwSize = size_of::<THREADENTRY32>() as u32;
    let mut ids = Vec::new();
    // SAFETY: snap это живой снимок потоков, e имеет верный dwSize.
    let mut more = unsafe { Thread32First(snap, &mut e) } != 0;
    while more {
        if e.th32OwnerProcessID == me {
            ids.push(u64::from(e.th32ThreadID));
        }
        // SAFETY: snap жив, e по-прежнему с верным dwSize.
        more = unsafe { Thread32Next(snap, &mut e) } != 0;
    }
    // SAFETY: snap это открытый нами handle, закрывается один раз.
    unsafe { CloseHandle(snap) };
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
    pmc.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    // SAFETY: me валиден, pmc имеет размер cb.
    if unsafe { K32GetProcessMemoryInfo(me, &mut pmc, pmc.cb) } != 0 {
        s.working_set_bytes = Some(pmc.WorkingSetSize as u64);
        s.peak_working_set_bytes = Some(pmc.PeakWorkingSetSize as u64);
    }
    s.threads = thread_count();
    s
}

pub(crate) fn token_flags() -> TokenFlags {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: псевдо-handle процесса; token валидный выходной параметр.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return TokenFlags::default();
    }
    let mut el = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret = 0u32;
    // SAFETY: token открыт с TOKEN_QUERY; el имеет размер size_of::<TOKEN_ELEVATION>().
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut el as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
    };
    // SAFETY: token открыт нами с TOKEN_QUERY.
    let restricted = unsafe { IsTokenRestricted(token) } != 0;
    // SAFETY: token это открытый нами handle, закрывается один раз.
    unsafe { CloseHandle(token) };
    TokenFlags {
        elevated: (ok != 0).then_some(el.TokenIsElevated != 0),
        restricted: Some(restricted),
    }
}
