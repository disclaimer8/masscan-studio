//! Измерения процесса для harness: handle/fd, потоки, рабочий набор, CPU.
//!
//! Правило честности: то, что на данной ОС измерить нельзя, это `None`
//! (в JSON `null`), а не 0. Linux читает `/proc/self`; macOS `getrusage` и `proc_pidinfo`; Windows использует
//! поддерживаемые API (`GetProcessHandleCount`, `GetProcessTimes`,
//! `K32GetProcessMemoryInfo`, токен процесса, снимок потоков Toolhelp); вызовы
//! находятся в private-модуле crate net, пример их не содержит.

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

// Windows: FFI живёт в private-модуле crate net (`windows::process`); здесь
// только безопасные вызовы его служебного API.
#[cfg(windows)]
mod os {
    use super::Sample;

    pub fn sample() -> Sample {
        let p = rmasscan_net::process_sample();
        Sample {
            handles: p.handles,
            threads: p.threads,
            working_set_bytes: p.working_set_bytes,
            peak_working_set_bytes: p.peak_working_set_bytes,
            cpu_user_ms: p.cpu_user_ms,
            cpu_kernel_ms: p.cpu_kernel_ms,
        }
    }

    pub fn elevated() -> Option<bool> {
        rmasscan_net::token_flags().elevated
    }

    pub fn restricted() -> Option<bool> {
        rmasscan_net::token_flags().restricted
    }
}

#[cfg(target_os = "macos")]
mod os {
    use super::Sample;

    // FFI живёт в private-модуле crate net (`macos::process`); `handles` это
    // записи `/dev/fd` минус дескриптор самого перечисления.
    pub fn sample() -> Sample {
        let p = rmasscan_net::process_sample();
        Sample {
            handles: p.handles,
            threads: p.threads,
            working_set_bytes: p.working_set_bytes,
            peak_working_set_bytes: p.peak_working_set_bytes,
            cpu_user_ms: p.cpu_user_ms,
            cpu_kernel_ms: p.cpu_kernel_ms,
        }
    }

    pub fn elevated() -> Option<bool> {
        None
    }

    pub fn restricted() -> Option<bool> {
        None
    }
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
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
    fn windows_reports_real_numbers_including_threads() {
        let s = sample();
        assert!(s.handles.is_some_and(|h| h > 0), "{s:?}");
        assert!(s.working_set_bytes.is_some_and(|w| w > 0), "{s:?}");
        assert!(
            s.cpu_user_ms.is_some() && s.cpu_kernel_ms.is_some(),
            "{s:?}"
        );
        assert!(s.threads.is_some_and(|t| t > 0), "{s:?}");
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

    #[cfg(target_os = "macos")]
    #[test]
    fn process_sample_fields_are_some_on_macos() {
        let s = sample();
        assert!(s.threads.is_some_and(|t| t >= 1), "{s:?}");
        assert!(s.handles.is_some_and(|h| h >= 3), "{s:?}");
        assert!(s.working_set_bytes.is_some(), "{s:?}");
        assert!(s.peak_working_set_bytes.is_some(), "{s:?}");
        assert!(
            s.cpu_user_ms.is_some() && s.cpu_kernel_ms.is_some(),
            "{s:?}"
        );
        // Токена Windows на macOS нет: не измерено, а не false.
        assert_eq!(elevated(), None);
        assert_eq!(restricted(), None);
    }

    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    #[test]
    fn no_proc_means_all_null() {
        assert_eq!(sample(), Sample::default());
        assert_eq!(sample().handles, None);
    }
}
