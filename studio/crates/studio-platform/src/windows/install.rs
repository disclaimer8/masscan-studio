//! Handle-bound trust checks for the immutable Windows runner installation.
use super::{Local, error, local_string, owned};
use sha2::{Digest, Sha256};
use std::{
    ffi::c_void,
    fs::File,
    io::Read,
    os::windows::io::{AsRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::Com::CoTaskMemFree,
    UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath},
};
type Result<T> = std::result::Result<T, String>;
const TRUSTED: [&str; 3] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];
const WRITE_MASK: u32 = 0x500d0156;

pub fn program_files() -> Result<PathBuf> {
    let mut value = null_mut();
    // SAFETY: fixed known-folder GUID, current-user token and writable PWSTR.
    let hr = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, null_mut(), &mut value) };
    if hr < 0 {
        return Err(format!("Program Files lookup failed: {hr:#x}"));
    }
    if value.is_null() {
        return Err("Program Files lookup returned no path".into());
    }
    let mut n = 0;
    // SAFETY: successful API returns a NUL-terminated CoTaskMem UTF-16 string.
    while unsafe { *value.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: measured live string; allocation is freed after copying.
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(value, n) })
        .map(PathBuf::from)
        .map_err(|e| e.to_string());
    // SAFETY: successful SHGetKnownFolderPath allocation uses CoTaskMem.
    unsafe {
        CoTaskMemFree(value.cast());
    }
    result
}
pub fn installed_path(hash: &str) -> Result<PathBuf> {
    crate::win_setup::validate_hash(hash)?;
    Ok(program_files()?
        .join("Masscan Studio")
        .join("Runner")
        .join(hash)
        .join("studio-runner.exe"))
}
fn sid_string(sid: PSID) -> Result<String> {
    if sid.is_null() {
        return Err("Missing security principal".into());
    }
    let mut value = null_mut();
    // SAFETY: SID originates in a valid descriptor retained by the caller.
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return Err(error());
    }
    // SAFETY: successful conversion returns LocalAlloc-owned terminated text.
    unsafe { local_string(value) }
}
fn check_descriptor(owner: PSID, dacl: *const ACL, volume_root: bool) -> Result<()> {
    if !TRUSTED.contains(&sid_string(owner)?.as_str()) {
        return Err("Installation owner is not SYSTEM/Administrators/TrustedInstaller".into());
    }
    if dacl.is_null() {
        return Err("Null installation DACL".into());
    }
    // SAFETY: pointer comes from GetSecurityInfo or a retained parsed descriptor.
    if unsafe { IsValidAcl(dacl) } == 0 {
        return Err("Invalid installation DACL".into());
    }
    // SAFETY: validated ACL includes its header.
    let count = unsafe { (*dacl).AceCount } as u32;
    let danger = if volume_root {
        WRITE_MASK & !FILE_ADD_SUBDIRECTORY
    } else {
        WRITE_MASK
    };
    for index in 0..count {
        let mut ptr: *mut c_void = null_mut();
        // SAFETY: valid ACL, bounded index and writable output pointer.
        if unsafe { GetAce(dacl, index, &mut ptr) } == 0 {
            return Err(error());
        }
        // SAFETY: GetAce returned an ACE within a validated ACL.
        let header = unsafe { &*ptr.cast::<ACE_HEADER>() };
        if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
            continue;
        }
        if header.AceType == 1 {
            continue;
        } // ACCESS_DENIED_ACE_TYPE cannot grant rights.
        if header.AceType != 0 || header.AceSize < 16 {
            return Err("Unsupported installation DACL entry".into());
        }
        // Check SID bounds explicitly: IsValidAcl alone does not establish them.
        // SAFETY: GetAce returned this complete ACE from an OS-owned descriptor.
        let bytes =
            unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), header.AceSize as usize) };
        if bytes[8] != 1 || bytes[9] > 15 || 16 + 4 * bytes[9] as usize > bytes.len() {
            return Err("Invalid SID bounds in installation DACL".into());
        }
        // SAFETY: an ACCESS_ALLOWED_ACE begins with header + mask + SID. Both
        // the fixed header and revision/count-sized SID fit within this ACE.
        let ace = unsafe { &*ptr.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
        let principal = sid_string(sid)?;
        if !TRUSTED.contains(&principal.as_str()) && ace.Mask & danger != 0 {
            return Err(format!("Installation is writable by {principal}"));
        }
    }
    Ok(())
}
fn check_handle(handle: HANDLE, directory: bool, volume_root: bool) -> Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: live file handle and correctly sized output structure.
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err("Installation contains a reparse point or wrong object type".into());
    }
    let (mut owner, mut dacl, mut descriptor) = (null_mut(), null_mut(), null_mut());
    // SAFETY: retained handle has READ_CONTROL; outputs refer into descriptor.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32).to_string());
    }
    let _allocation = Local(descriptor);
    check_descriptor(owner, dacl, volume_root)
}
fn pin(path: &Path, directory: bool, volume_root: bool) -> Result<OwnedHandle> {
    let handle = open_object(path, directory)?;
    check_handle(handle.as_raw_handle(), directory, volume_root)?;
    Ok(handle)
}
fn open_object(path: &Path, directory: bool) -> Result<OwnedHandle> {
    use std::os::windows::ffi::OsStrExt;
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: terminated path, no inherited handle, existing object only. Opening
    // the reparse point itself lets check_handle reject it. No write/delete
    // sharing keeps the verified object pinned until the launch completes.
    owned(unsafe {
        CreateFileW(
            path.as_ptr(),
            READ_CONTROL
                | if directory {
                    FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY
                } else {
                    FILE_GENERIC_READ
                },
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    })
    .map_err(|e| e.to_string())
}

pub struct Installed {
    path: PathBuf,
    _file: File,
    _ancestors: Vec<OwnedHandle>,
}
impl Installed {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn open(hash: &str) -> Result<Self> {
        let path = installed_path(hash)?;
        let mut ancestors = Vec::new();
        // Walk top-down: once the parent is pinned and its rights validated, an
        // unprivileged process cannot redirect lookup of the next component.
        let parents: Vec<_> = path.ancestors().skip(1).collect();
        for ancestor in parents.into_iter().rev() {
            ancestors.push(pin(ancestor, true, ancestor.parent().is_none())?);
        }
        let mut file = File::from(pin(&path, false, false)?);
        let mut sha = Sha256::new();
        let mut buffer = [0; 65536];
        loop {
            let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            sha.update(&buffer[..n]);
        }
        if format!("{:x}", sha.finalize()) != hash {
            return Err("Installed runner hash mismatch".into());
        }
        Ok(Self {
            path,
            _file: file,
            _ancestors: ancestors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::wide;
    use super::*;
    #[test]
    fn retained_directory_handle_refuses_delete_access() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = std::env::temp_dir().join(format!("studio-pin-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let pinned = open_object(&dir, true).unwrap();
        let deleting = std::fs::OpenOptions::new()
            .access_mode(DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&dir);
        let denied = deleting.is_err();
        drop(deleting);
        drop(pinned);
        std::fs::remove_dir(dir).unwrap();
        assert!(
            denied,
            "metadata-only handle failed to pin directory against deletion"
        );
    }
    fn policy(sddl: &str, root: bool) -> Result<()> {
        let mut descriptor = null_mut();
        // SAFETY: terminated fixed fixture, writable LocalAlloc descriptor output.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(error());
        }
        let _allocation = Local(descriptor);
        let (mut owner, mut defaulted) = (null_mut(), 0);
        let (mut dacl, mut present) = (null_mut(), 0);
        // SAFETY: live parsed descriptor, correctly typed writable scalar outputs.
        if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } == 0 {
            return Err(error());
        }
        // SAFETY: same retained descriptor and correctly typed writable outputs.
        if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            == 0
        {
            return Err(error());
        }
        check_descriptor(owner, dacl, root)
    }
    #[test]
    fn installation_acl_refuses_unprivileged_writes_and_unknown_forms() {
        assert!(policy("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)", false).is_ok());
        for bad in [
            "O:BUG:BUD:(A;;FA;;;BA)",
            "O:BA",
            "O:BAD:(A;;GW;;;BU)",
            "O:BAD:(A;;WD;;;WD)",
            "O:BAD:(A;;DC;;;AU)",
            "O:BAD:(A;;WO;;;BU)",
        ] {
            assert!(policy(bad, false).is_err(), "{bad}");
        }
        assert!(policy("O:BAD:(A;IO;FA;;;BU)(A;;FRFX;;;BU)", false).is_ok());
        assert!(policy("O:BAD:(A;;0x4;;;AU)", true).is_ok());
        assert!(policy("O:BAD:(A;;0x4;;;AU)", false).is_err());
        assert!(policy("O:BAD:(A;;0x2;;;AU)", true).is_err());
    }
    #[test]
    fn missing_install_and_invalid_hash_are_refused() {
        assert!(Installed::open("../bad").is_err());
        assert!(Installed::open(&"0".repeat(64)).is_err());
        assert!(program_files().unwrap().is_absolute());
    }
    #[test]
    fn unsupported_effective_aces_and_wrong_object_types_are_refused() {
        for sddl in ["O:BAD:(OA;;GR;;;BU)", "O:BAD:(OD;;GW;;;BU)"] {
            assert!(policy(sddl, false).unwrap_err().contains("Unsupported"));
        }
        let dir = program_files().unwrap();
        assert!(
            pin(&dir, false, false)
                .err()
                .unwrap()
                .contains("wrong object type")
        );
        let file = std::env::temp_dir().join(format!("studio-type-{}", std::process::id()));
        std::fs::write(&file, b"fixture").unwrap();
        let result = pin(&file, true, false);
        std::fs::remove_file(file).unwrap();
        assert!(result.err().unwrap().contains("wrong object type"));
    }
}
