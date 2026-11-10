//! Смещение местного времени от UTC (AGPL-3.0) для `timestr` подвала `-oX`: C печатает его через `localtime`
//! (`out-xml.c:37–59`, `safe_localtime` = `localtime_r` на Unix, `localtime_s` на Windows) из masscan © Robert David
//! Graham. Здесь только смещение; дату из него собирает чистый Rust в `rmasscan-cli`. Unix: `localtime_r` и
//! `tm_gmtoff`; Windows: `FILETIME` → `SYSTEMTIME` UTC → `SystemTimeToTzSpecificLocalTime` (пояс системы с правилами
//! летнего времени на ту дату) → `FILETIME`, смещение = местное − UTC.

use crate::NetError;

/// Секунды, которые надо прибавить к UTC, чтобы получить местное время в момент `unix` (Unix-секунды).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn utc_offset_secs(unix: i64) -> Result<i32, NetError> {
    let t = libc::time_t::try_from(unix)
        .map_err(|_| NetError::System(format!("time {unix} does not fit time_t")))?;
    // SAFETY: `tm` это POD из чисел и указателя на имя пояса; нулевое значение допустимо, его перезаписывают целиком.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: оба указателя на живые локальные значения; `localtime_r` пишет только в `tm` и потокобезопасна.
    let r = unsafe { libc::localtime_r(&t, &mut tm) };
    if r.is_null() {
        return Err(NetError::System(format!(
            "localtime_r: {}",
            std::io::Error::last_os_error()
        )));
    }
    i32::try_from(tm.tm_gmtoff)
        .map_err(|_| NetError::System(format!("tm_gmtoff {} out of range", tm.tm_gmtoff)))
}

#[cfg(windows)]
pub fn utc_offset_secs(unix: i64) -> Result<i32, NetError> {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::Time::{
        FileTimeToSystemTime, SystemTimeToFileTime, SystemTimeToTzSpecificLocalTime,
    };

    /// Секунды между 1601-01-01 (эпоха `FILETIME`) и 1970-01-01.
    const EPOCH_1601: i64 = 11_644_473_600;
    /// Интервалы `FILETIME` (100 нс) в секунде.
    const TICKS: i64 = 10_000_000;
    let fail =
        |what: &str| NetError::System(format!("{what}: {}", std::io::Error::last_os_error()));
    let utc_ticks = unix
        .checked_add(EPOCH_1601)
        .and_then(|s| s.checked_mul(TICKS))
        .and_then(|t| u64::try_from(t).ok())
        .ok_or_else(|| NetError::System(format!("time {unix} out of FILETIME range")))?;
    let utc_ft = FILETIME {
        dwLowDateTime: utc_ticks as u32,
        dwHighDateTime: (utc_ticks >> 32) as u32,
    };
    let mut utc = SYSTEMTIME::default();
    // SAFETY: оба указателя на живые локальные структуры; функция только читает `utc_ft` и пишет `utc`.
    if unsafe { FileTimeToSystemTime(&utc_ft, &mut utc) } == 0 {
        return Err(fail("FileTimeToSystemTime"));
    }
    let mut local = SYSTEMTIME::default();
    // SAFETY: NULL значит «текущий пояс системы»; `utc` читается, `local` пишется, оба живые.
    if unsafe { SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) } == 0 {
        return Err(fail("SystemTimeToTzSpecificLocalTime"));
    }
    let mut local_ft = FILETIME::default();
    // SAFETY: оба указателя на живые локальные структуры; функция только читает `local` и пишет `local_ft`.
    if unsafe { SystemTimeToFileTime(&local, &mut local_ft) } == 0 {
        return Err(fail("SystemTimeToFileTime"));
    }
    let local_ticks =
        (u64::from(local_ft.dwHighDateTime) << 32) | u64::from(local_ft.dwLowDateTime);
    let diff = (i128::from(local_ticks) - i128::from(utc_ticks)) / i128::from(TICKS);
    i32::try_from(diff).map_err(|_| NetError::System(format!("UTC offset {diff} s out of range")))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn utc_offset_secs(_unix: i64) -> Result<i32, NetError> {
    Err(NetError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Самые дальние пояса мира: UTC−12 и UTC+14. Окружение `TZ` тест не меняет.
    #[test]
    fn utc_offset_is_within_14_hours() {
        for t in [now(), 0] {
            let off = utc_offset_secs(t).unwrap();
            assert!(off.abs() <= 50_400, "{t}: {off}");
        }
    }

    #[test]
    fn utc_offset_is_stable() {
        let t = now();
        assert_eq!(utc_offset_secs(t).unwrap(), utc_offset_secs(t).unwrap());
        assert_eq!(utc_offset_secs(0).unwrap(), utc_offset_secs(0).unwrap());
    }
}
