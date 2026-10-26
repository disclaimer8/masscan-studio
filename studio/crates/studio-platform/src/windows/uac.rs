//! Same-account, session-only elevation and OS-owned runner lifetime.
use super::*;
use windows_sys::Win32::System::JobObjects::*;

const JOB_PREFIX: &str = "Local\\MasscanStudioJob-";
pub struct LifetimeJob {
    handle: OwnedHandle,
    name: String,
}
impl LifetimeJob {
    pub fn create() -> Result<Self> {
        let owner = Identity::current()?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
        let name = format!(
            "{JOB_PREFIX}{}",
            nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let sddl = wide(&format!("O:{}D:P(A;;GA;;;{})", owner.sid, owner.sid));
        let mut descriptor = null_mut();
        // SAFETY: terminated SDDL, sized writable descriptor pointer; LocalAlloc ownership.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(error());
        }
        let descriptor = Local(descriptor);
        let security = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        // SAFETY: descriptors/name live throughout call, result handle uniquely owned.
        let handle = owned(unsafe { CreateJobObjectW(&security, wide(&name).as_ptr()) })
            .map_err(|e| e.to_string())?;
        // SAFETY: immediate thread-local error from successful CreateJobObjectW.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            return Err("Job endpoint already exists".into());
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: exact class/layout and size; live job handle.
        if unsafe {
            SetInformationJobObject(
                handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(error());
        }
        Ok(Self { handle, name })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn contains(&self, pid: u32) -> Result<bool> {
        let process = Process::open(pid)?;
        let mut member = 0;
        // SAFETY: retained process/job handles and writable BOOL.
        if unsafe {
            IsProcessInJob(
                process.handle.as_raw_handle(),
                self.handle.as_raw_handle(),
                &mut member,
            )
        } == 0
        {
            return Err(error());
        }
        Ok(member != 0)
    }
    pub fn join(name: &str, owner_sid: &str) -> Result<()> {
        let suffix = name
            .strip_prefix(JOB_PREFIX)
            .ok_or("Invalid session job name")?;
        if suffix.len() != 32 || !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid session job name".into());
        }
        // SAFETY: validated terminated local name; no inherited handle.
        let handle = owned(unsafe {
            OpenJobObjectW(
                JOB_OBJECT_ASSIGN_PROCESS | JOB_OBJECT_QUERY | READ_CONTROL,
                0,
                wide(name).as_ptr(),
            )
        })
        .map_err(|e| e.to_string())?;
        let (mut owner, mut descriptor) = (null_mut(), null_mut());
        // SAFETY: retained job, owner output points inside returned descriptor.
        let status = unsafe {
            GetSecurityInfo(
                handle.as_raw_handle(),
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32).to_string());
        }
        let _descriptor = Local(descriptor);
        let mut sid = null_mut();
        // SAFETY: owner SID comes from retained OS-produced descriptor.
        if unsafe { ConvertSidToStringSidW(owner, &mut sid) } == 0 {
            return Err(error());
        }
        // SAFETY: successful conversion returns terminated LocalAlloc allocation.
        if unsafe { local_string(sid)? } != owner_sid {
            return Err("Session job owner differs from UI".into());
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: class-matched output allocation and size; live job handle.
        if unsafe {
            QueryInformationJobObject(
                handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
                null_mut(),
            )
        } == 0
        {
            return Err(error());
        }
        if limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 {
            return Err("Session job lacks kill-on-close".into());
        }
        // SAFETY: assigns only this process. It has not started any engine. The
        // temporary job handle is closed immediately: UI must be sole holder.
        if unsafe { AssignProcessToJobObject(handle.as_raw_handle(), GetCurrentProcess()) } == 0 {
            return Err(error());
        }
        drop(handle);
        Ok(())
    }
}
