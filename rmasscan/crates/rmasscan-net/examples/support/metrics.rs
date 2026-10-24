//! Измерения процесса для harness: handle/fd, потоки, рабочий набор, CPU.
//!
//! Правило честности: то, что на данной ОС измерить нельзя, это `None`
//! (в JSON `null`), а не 0. Linux читает `/proc/self`; Windows использует
//! поддерживаемые API (`GetProcessHandleCount`, `GetProcessTimes`,
//! `K32GetProcessMemoryInfo`, токен процесса). Число потоков на Windows не
//! измеряется (`None`): отдельного поддерживаемого дешёвого вызова нет, а
//! снимок Toolhelp дал бы гонку со вспомогательными потоками.

/// Один снимок. Каждое поле независимо: `None` значит «недоступно».
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sample {
    /// Открытые fd (Linux) или handle (Windows).
    pub handles: Option<u64>,
    pub threads: Option<u64>,
    pub working_set_bytes: Option<u64>,
    pub peak_working_set_bytes: Option<u64>,
    pub cpu_user_ms: Option<u64>,
    pub cpu_kernel_ms: Option<u64>,
}

/// `Some(n)` это число, `None` это `null`. Никогда не подставляет 0.
pub fn json_opt(v: Option<u64>) -> String {
    v.map_or_else(|| "null".to_string(), |n| n.to_string())
}

pub fn json_opt_bool(v: Option<bool>) -> String {
    v.map_or_else(|| "null".to_string(), |b| b.to_string())
}

#[cfg(target_os = "linux")]
mod os {
    use super::Sample;

    fn count_dir(p: &str) -> Option<u64> {
        std::fs::read_dir(p).ok().map(|d| d.count() as u64)
    }

    /// Значение строки `/proc/self/status` вида `VmRSS:  1234 kB` в байтах.
    fn status_kb(key: &str) -> Option<u64> {
        let text = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = text.lines().find(|l| l.starts_with(key))?;
        let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kb * 1024)
    }

    pub fn sample() -> Sample {
        Sample {
            handles: count_dir("/proc/self/fd"),
            threads: count_dir("/proc/self/task"),
            working_set_bytes: status_kb("VmRSS:"),
            peak_working_set_bytes: status_kb("VmHWM:"),
            // CPU-время на Linux harness не измеряет (нужен CLK_TCK через libc).
            cpu_user_ms: None,
            cpu_kernel_ms: None,
        }
    }

    pub fn elevated() -> Option<bool> {
        None
    }

    pub fn restricted() -> Option<bool> {
        None
    }
}

#[cfg(windows)]
mod os {
    use super::Sample;
    use std::mem::size_of;

    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, IsTokenRestricted, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetProcessHandleCount, GetProcessTimes, OpenProcessToken,
    };

    fn ft_ms(f: &FILETIME) -> u64 {
        // FILETIME это 100-нс интервалы.
        ((u64::from(f.dwHighDateTime) << 32) | u64::from(f.dwLowDateTime)) / 10_000
    }

    pub fn sample() -> Sample {
        let mut s = Sample::default();
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
        s
    }

    /// Токен процесса повышен (запуск «от администратора»)? `None`, если токен
    /// прочитать не удалось.
    pub fn elevated() -> Option<bool> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: псевдо-handle процесса; token валидный выходной параметр.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return None;
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
        // SAFETY: token это открытый нами handle, закрывается один раз.
        unsafe { CloseHandle(token) };
        (ok != 0).then_some(el.TokenIsElevated != 0)
    }

    /// Токен ограничен (restricted token, например `runas /trustlevel`)?
    pub fn restricted() -> Option<bool> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: псевдо-handle процесса; token валидный выходной параметр.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return None;
        }
        // SAFETY: token открыт с TOKEN_QUERY.
        let r = unsafe { IsTokenRestricted(token) } != 0;
        // SAFETY: token это открытый нами handle, закрывается один раз.
        unsafe { CloseHandle(token) };
        Some(r)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod os {
    use super::Sample;

    pub fn sample() -> Sample {
        Sample::default()
    }

    pub fn elevated() -> Option<bool> {
        None
    }

    pub fn restricted() -> Option<bool> {
        None
    }
}

pub fn sample() -> Sample {
    os::sample()
}

/// Повышен ли токен процесса (только Windows; иначе `None`).
pub fn elevated() -> Option<bool> {
    os::elevated()
}

/// Ограничен ли токен процесса (только Windows; иначе `None`).
pub fn restricted() -> Option<bool> {
    os::restricted()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_is_null_never_zero() {
        assert_eq!(json_opt(None), "null");
        assert_eq!(json_opt(Some(0)), "0");
        assert_eq!(json_opt(Some(7)), "7");
        assert_eq!(json_opt_bool(None), "null");
    }

    #[cfg(windows)]
    #[test]
    fn windows_reports_real_numbers_and_no_thread_count() {
        let s = sample();
        assert!(s.handles.is_some_and(|h| h > 0), "{s:?}");
        assert!(s.working_set_bytes.is_some_and(|w| w > 0), "{s:?}");
        assert!(
            s.cpu_user_ms.is_some() && s.cpu_kernel_ms.is_some(),
            "{s:?}"
        );
        assert_eq!(s.threads, None, "thread count is not measured on Windows");
        assert!(elevated().is_some());
        assert!(restricted().is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_reads_proc() {
        let s = sample();
        assert!(s.handles.is_some_and(|h| h > 0), "{s:?}");
        assert!(s.threads.is_some_and(|h| h > 0), "{s:?}");
        assert!(s.working_set_bytes.is_some_and(|w| w > 0), "{s:?}");
        assert_eq!(s.cpu_user_ms, None);
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    #[test]
    fn no_proc_means_all_null() {
        assert_eq!(sample(), Sample::default());
        assert_eq!(sample().handles, None);
    }
}
