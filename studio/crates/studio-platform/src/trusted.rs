#![forbid(unsafe_code)]
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};
pub fn file_hash(path: &Path) -> Result<String, String> {
    let mut f = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut sha = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
    }
    Ok(sha
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
#[cfg(unix)]
pub fn verify(path: &Path, expected_hash: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() || fs::canonicalize(path).map_err(|e| e.to_string())? != path {
        return Err("Installed runner path must be canonical, without symlinks".into());
    }
    for (i, entry) in path.ancestors().enumerate() {
        #[cfg(target_os = "macos")]
        crate::macos::reject_extended_acl(entry)?;
        let md = fs::symlink_metadata(entry).map_err(|e| e.to_string())?;
        if md.uid() != 0
            || md.mode() & 0o022 != 0
            || (i == 0 && (!md.is_file() || md.mode() & 0o111 == 0))
            || (i != 0 && !md.is_dir())
        {
            return Err(format!(
                "Runner installation is not administrator-owned: {}",
                entry.display()
            ));
        }
    }
    if file_hash(path)? != expected_hash {
        return Err("Installed runner does not match this application build".into());
    }
    Ok(())
}
#[cfg(not(unix))]
pub fn verify(_: &Path, _: &str) -> Result<(), String> {
    Err("Administrator-owned Windows installation validation is not implemented".into())
}
