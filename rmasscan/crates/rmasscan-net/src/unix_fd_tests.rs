//! Test helper: the flags of ONE descriptor, so that each place that creates a socket can pin the flags it is
//! created with (`O_NONBLOCK`, `FD_CLOEXEC`). It never counts or scans the descriptors of the process, which other
//! tests running in parallel change.

use std::ffi::c_int;
use std::os::fd::{AsRawFd, BorrowedFd};

/// `(F_GETFL status flags, FD_CLOEXEC is set)` of `fd`.
pub(crate) fn fd_flags(fd: BorrowedFd<'_>) -> (c_int, bool) {
    // SAFETY: `fd` is borrowed, so it stays open for the whole call; F_GETFL takes no pointer argument.
    let status = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    assert!(
        status >= 0,
        "fcntl(F_GETFL): {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: as above; F_GETFD takes no pointer argument.
    let descriptor = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    assert!(
        descriptor >= 0,
        "fcntl(F_GETFD): {}",
        std::io::Error::last_os_error()
    );
    (status, descriptor & libc::FD_CLOEXEC != 0)
}
