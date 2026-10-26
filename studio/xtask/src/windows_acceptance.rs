//! CI-only restricted-token owner fixtures. Never used by the application.
use super::*;
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::Threading::*,
};
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn handle(raw: HANDLE) -> Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: caller transfers a newly allocated, non-inherited Win32 handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
pub fn limited(args: &[&str]) -> Result<()> {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
        return Err("Restricted fixtures require disposable GitHub VM".into());
    }
    let mut token = null_mut();
    // SAFETY: current process pseudo-handle; correctly sized token output.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let token = handle(token)?;
    let mut restricted = null_mut();
    // SAFETY: derive only a less privileged token of this CI account, no external
    // token/account/credentials. Zero array lengths accompany null pointers.
    if unsafe {
        CreateRestrictedToken(
            token.as_raw_handle(),
            LUA_TOKEN | DISABLE_MAX_PRIVILEGE,
            0,
            null(),
            0,
            null(),
            0,
            null(),
            &mut restricted,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let restricted = handle(restricted)?;
    let mut sid = null_mut();
    // SAFETY: fixed valid medium-integrity SID and writable LocalAlloc result.
    if unsafe { ConvertStringSidToSidW(wide("S-1-16-8192").as_ptr(), &mut sid) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: SE_GROUP_INTEGRITY,
        },
    };
    // SAFETY: SID and sized mandatory-label structure live through synchronous call.
    let ok = unsafe {
        SetTokenInformation(
            restricted.as_raw_handle(),
            TokenIntegrityLevel,
            (&label as *const TOKEN_MANDATORY_LABEL).cast(),
            std::mem::size_of_val(&label) as u32 + GetLengthSid(sid),
        )
    };
    // SAFETY: ConvertStringSidToSidW allocated this SID with LocalAlloc.
    unsafe {
        LocalFree(sid);
    }
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let exe = std::env::current_exe()?;
    let exe = exe
        .to_str()
        .ok_or("Fixture executable path is not Unicode")?;
    let mut argv = vec![exe];
    argv.extend_from_slice(args);
    let mut line = wide(&studio_platform::win_setup::command_line(&argv)?);
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: explicit executable, mutable terminated command line, no inherited
    // handles. Current environment is inherited; restricted token is our own.
    if unsafe {
        CreateProcessAsUserW(
            restricted.as_raw_handle(),
            wide(exe).as_ptr(),
            line.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_NO_WINDOW,
            null(),
            null(),
            &startup,
            &mut info,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let process = handle(info.hProcess)?;
    let _thread = handle(info.hThread)?;
    // SAFETY: retained process supports wait; bounded fixture deadline.
    if unsafe { WaitForSingleObject(process.as_raw_handle(), 60000) } != WAIT_OBJECT_0 {
        // SAFETY: only the newly created disposable fixture is terminated.
        unsafe {
            TerminateProcess(process.as_raw_handle(), 1);
        }
        return Err("Restricted fixture timed out".into());
    }
    let mut exit = 0;
    // SAFETY: retained process handle and writable DWORD exit status.
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if exit != 0 {
        return Err(format!("Restricted fixture failed with {exit}").into());
    }
    Ok(())
}
pub fn token_probe() -> Result<()> {
    let me = studio_platform::windows::Process::open(std::process::id())?;
    println!(
        "CI host token: {:?}; logon={:?}",
        me.elevation()?,
        me.identity().logon
    );
    limited(&["windows-limited-token-fixture"])?;
    println!("PASS: same-account restricted owner reports unelevated token");
    Ok(())
}
pub fn token_fixture() -> Result<()> {
    let me = studio_platform::windows::Process::open(std::process::id())?;
    let status = me.elevation()?;
    if status.elevated {
        return Err("Restricted fixture is still elevated".into());
    }
    Ok(())
}
