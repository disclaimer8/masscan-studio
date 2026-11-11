//! POSIX process-owned lock. Querying never acquires a reader lock, so readers
//! cannot impersonate a live producer by briefly contending with each other.
use super::Result;
use std::{fs::File, os::fd::AsRawFd};
fn record() -> libc::flock {
    libc::flock {
        l_start: 0,
        l_len: 0,
        l_pid: 0,
        l_type: libc::F_WRLCK,
        l_whence: libc::SEEK_SET as i16,
    }
}
pub(super) fn acquire(file: &File) -> Result<()> {
    let lock = record();
    // SAFETY: valid owned descriptor and initialized Darwin flock. F_SETLK is
    // nonblocking; the process owns this lock until explicitly unlocked or closed.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) } == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}
pub(super) fn owner(file: &File) -> Result<Option<u32>> {
    let mut lock = record();
    // SAFETY: writable initialized flock and valid descriptor; F_GETLK only queries.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) } == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    match lock.l_type {
        libc::F_UNLCK => Ok(None),
        libc::F_WRLCK if lock.l_pid > 0 => Ok(Some(lock.l_pid as u32)),
        _ => Err("Capture lease has an unexpected lock owner/type".into()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn child_observes_exact_owner_or_released_lock() {
        let Some(path) = std::env::var_os("STUDIO_CAPTURE_LOCK_TEST_FILE") else {
            return;
        };
        let expected: u32 = std::env::var("STUDIO_CAPTURE_LOCK_TEST_PID")
            .unwrap()
            .parse()
            .unwrap();
        let file = File::open(path).unwrap();
        assert_eq!(owner(&file).unwrap(), (expected != 0).then_some(expected));
    }
    #[test]
    fn kernel_owner_disappears_on_close_without_any_marker_write() {
        let path = std::env::temp_dir().join(format!(
            "studio-capture-lock-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        acquire(&file).unwrap();
        let check = |pid| {
            let output=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","single_target::capture_lock::tests::child_observes_exact_owner_or_released_lock","--nocapture"])
                .env("STUDIO_CAPTURE_LOCK_TEST_FILE",&path).env("STUDIO_CAPTURE_LOCK_TEST_PID",format!("{pid}")).output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        };
        check(std::process::id());
        drop(file);
        check(0);
        std::fs::remove_file(path).unwrap();
    }
}
