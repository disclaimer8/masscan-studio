//! Read-only, descriptor-anchored access to the unprivileged acceptance driver.
use std::{
    ffi::CString,
    fs::{File, Metadata},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
    time::Instant,
};
const FILES: &[&str] = &[
    "prepared-complete",
    "prepared-pause",
    "prepared-resume",
    "prepared-stop-preparing",
    "prepared-stop-running",
    "prepared-guard",
    "complete-phase.json",
    "pause-phase.json",
    "resume-phase.json",
    "stop-preparing-phase.json",
    "stop-running-phase.json",
    "guard-phase.json",
    "complete-attempt.json",
    "pause-attempt.json",
    "resume-attempt.json",
    "stop-preparing-attempt.json",
    "stop-running-attempt.json",
    "guard-attempt.json",
];
fn err(e: impl ToString) -> String {
    e.to_string()
}
fn open_at(parent: &File, name: &std::ffi::OsStr, directory: bool) -> Result<File, String> {
    let name = CString::new(name.as_bytes()).map_err(err)?;
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    // SAFETY: live borrowed directory descriptor and NUL-terminated one-component
    // name. The new owned descriptor is transferred exactly once into File.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn identity(m: &Metadata) -> (u64, u64) {
    (m.dev(), m.ino())
}
fn walk(path: &Path) -> Result<Vec<File>, String> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 || path.components().count() > 64 {
        return Err("evidence directory must be absolute".into());
    }
    let mut dirs = vec![File::open("/").map_err(err)?];
    for c in path.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(name) => {
                let f = open_at(dirs.last().ok_or("missing root")?, name, true)?;
                dirs.push(f);
            }
            _ => return Err("evidence path must contain only normal components".into()),
        }
    }
    if dirs.len() < 2 {
        return Err("root is not a driver directory".into());
    }
    Ok(dirs)
}
pub struct EvidenceDirectory {
    path: PathBuf,
    dirs: Vec<File>,
    uid: u32,
}
impl EvidenceDirectory {
    pub fn open(path: &Path, uid: u32) -> Result<Self, String> {
        if uid == 0 {
            return Err("driver must be unprivileged".into());
        }
        let dirs = walk(path)?;
        let md = dirs
            .last()
            .ok_or("missing directory")?
            .metadata()
            .map_err(err)?;
        if md.uid() != uid || !md.is_dir() || md.mode() & 0o022 != 0 {
            return Err("driver directory owner/type/mode differs".into());
        }
        Ok(Self {
            path: path.into(),
            dirs,
            uid,
        })
    }
    pub fn read(
        &self,
        name: &str,
        limit: usize,
        deadline: Instant,
    ) -> Result<Option<Vec<u8>>, String> {
        if !FILES.contains(&name) || limit > 1_048_576 || Instant::now() >= deadline {
            return Err("evidence basename/limit/deadline refused".into());
        }
        let fresh = walk(&self.path)?;
        if fresh.len() != self.dirs.len()
            || fresh.iter().zip(&self.dirs).any(|(a, b)| {
                a.metadata()
                    .ok()
                    .zip(b.metadata().ok())
                    .is_none_or(|(a, b)| identity(&a) != identity(&b))
            })
        {
            return Err("driver directory path replaced".into());
        }
        let dir = self.dirs.last().ok_or("missing pinned directory")?;
        let directory_md = dir.metadata().map_err(err)?;
        if directory_md.uid() != self.uid || directory_md.mode() & 0o022 != 0 {
            return Err("driver directory ownership/mode changed".into());
        }
        let mut f = match open_at(dir, std::ffi::OsStr::new(name), false) {
            Ok(f) => f,
            Err(e) => {
                // Absence is checked on the anchored directory too.
                let exists = fresh.last().ok_or("missing directory")?;
                let name = CString::new(name).map_err(err)?;
                // SAFETY: valid pinned directory fd and fixed NUL-terminated basename;
                // flags avoid following symlinks. No file is opened/read by this call.
                let rc = unsafe {
                    libc::faccessat(
                        exists.as_raw_fd(),
                        name.as_ptr(),
                        libc::F_OK,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound
                {
                    return Ok(None);
                }
                return Err(e);
            }
        };
        let md = f.metadata().map_err(err)?;
        if !md.is_file()
            || md.uid() != self.uid
            || md.nlink() != 1
            || md.mode() & 0o022 != 0
            || md.len() > limit as u64
        {
            return Err("evidence owner/type/link/mode/size refused".into());
        }
        let mut bytes = Vec::new();
        f.by_ref()
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        let after = f.metadata().map_err(err)?;
        if md.len() != after.len()
            || md.mtime() != after.mtime()
            || md.mtime_nsec() != after.mtime_nsec()
            || after.uid() != self.uid
            || after.nlink() != 1
            || after.mode() & 0o022 != 0
        {
            return Err("evidence changed during read".into());
        }
        if bytes.len() > limit || Instant::now() >= deadline {
            return Err("evidence size/deadline exceeded".into());
        }
        Ok(Some(bytes))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink, time::Duration};
    #[test]
    fn pinned_reader_rejects_substitution_links_types_owners_and_limits() {
        let base = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "evidence-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        fs::create_dir(&base).unwrap();
        let path = base.join("driver");
        fs::create_dir(&path).unwrap();
        let uid = fs::metadata(&path).unwrap().uid();
        assert_ne!(uid, 0, "run portable test without root");
        let read = EvidenceDirectory::open(&path, uid).unwrap();
        let deadline = || Instant::now() + Duration::from_secs(1);
        assert!(EvidenceDirectory::open(&path, uid + 1).is_err());
        assert!(read.read("../../../etc/passwd", 10, deadline()).is_err());
        assert!(
            read.read("pause-phase.json", 10, deadline())
                .unwrap()
                .is_none()
        );
        fs::write(path.join("pause-phase.json"), b"ok").unwrap();
        assert_eq!(
            read.read("pause-phase.json", 10, deadline())
                .unwrap()
                .unwrap(),
            b"ok"
        );
        assert!(read.read("pause-phase.json", 1, deadline()).is_err());
        fs::hard_link(path.join("pause-phase.json"), path.join("link")).unwrap();
        assert!(read.read("pause-phase.json", 10, deadline()).is_err());
        fs::remove_file(path.join("link")).unwrap();
        fs::remove_file(path.join("pause-phase.json")).unwrap();
        symlink("/etc/passwd", path.join("pause-phase.json")).unwrap();
        assert!(read.read("pause-phase.json", 100000, deadline()).is_err());
        fs::remove_file(path.join("pause-phase.json")).unwrap();
        fs::create_dir(path.join("pause-phase.json")).unwrap();
        assert!(read.read("pause-phase.json", 100, deadline()).is_err());
        fs::rename(&path, base.join("old")).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(read.read("pause-phase.json", 10, deadline()).is_err());
        let other = base.with_extension("moved");
        fs::rename(&base, &other).unwrap();
        fs::create_dir(&base).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(read.read("pause-phase.json", 10, deadline()).is_err());
        fs::remove_dir_all(base).unwrap();
        fs::remove_dir_all(other).unwrap();
    }
}
