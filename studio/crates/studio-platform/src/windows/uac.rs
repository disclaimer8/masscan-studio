//! Same-account, session-only elevation and OS-owned runner lifetime.
use super::*;
use std::{path::Path, sync::mpsc};
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::SystemServices::{JOB_OBJECT_ASSIGN_PROCESS, JOB_OBJECT_QUERY};
use windows_sys::Win32::{
    System::Com::*,
    UI::{Shell::*, WindowsAndMessaging::SW_HIDE},
};

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
        self.contains_process(&process)
    }
    fn contains_process(&self, process: &Process) -> Result<bool> {
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

static PROMPT_ACTIVE: AtomicBool = AtomicBool::new(false);
struct Prompt;
impl Drop for Prompt {
    fn drop(&mut self) {
        PROMPT_ACTIVE.store(false, Ordering::Release);
    }
}
struct Apartment;
impl Drop for Apartment {
    fn drop(&mut self) {
        // SAFETY: exactly balances successful CoInitializeEx on this worker thread.
        unsafe {
            CoUninitialize();
        }
    }
}
struct Launched {
    process: Process,
    installation: install::Installed,
}
fn launch(
    installation: install::Installed,
    owner: Identity,
    pipe: String,
    job: String,
    hash: String,
) -> Result<Launched> {
    let process = Process::from_handle(execute(&installation, &owner, &pipe, &job, &hash)?)?;
    if process.identity.sid != owner.sid {
        return Err(
            "Use the same Windows account for UAC; alternate-account authorization is unsupported"
                .into(),
        );
    }
    if !process.elevation()?.elevated {
        return Err("Windows did not elevate the runner".into());
    }
    same_executable(&process.identity.executable, installation.path())?;
    Ok(Launched {
        process,
        installation,
    })
}
fn execute(
    installation: &install::Installed,
    owner: &Identity,
    pipe: &str,
    job: &str,
    hash: &str,
) -> Result<OwnedHandle> {
    // SAFETY: called only on a fresh launcher thread; no apartment existed there.
    let hr = unsafe {
        CoInitializeEx(
            null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    if hr < 0 {
        return Err(format!("Cannot initialize UAC launcher: {hr:#x}"));
    }
    let _apartment = Apartment;
    let executable = installation
        .path()
        .to_str()
        .ok_or("Installed runner path is not Unicode")?;
    let directory = installation
        .path()
        .parent()
        .and_then(Path::to_str)
        .ok_or("Installed runner directory missing")?;
    let identity = serde_json::to_string(owner).map_err(|e| e.to_string())?;
    let parameters =
        crate::win_setup::command_line(&["--authorized-pipe", pipe, &identity, job, hash])?;
    let (verb, file, cwd, args) = (
        wide("runas"),
        wide(executable),
        wide(directory),
        wide(&parameters),
    );
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: args.as_ptr(),
        lpDirectory: cwd.as_ptr(),
        nShow: SW_HIDE,
        ..Default::default()
    };
    // SAFETY: all terminated strings and pinned executable live through this
    // synchronous OS call; hProcess ownership transfers to Process on success.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        return Err(format!(
            "Windows authorization failed or was cancelled: {}",
            error()
        ));
    }
    owned(info.hProcess).map_err(|e| e.to_string())
}
fn same_executable(actual: &Path, expected: &Path) -> Result<()> {
    if std::fs::canonicalize(actual).map_err(|e| e.to_string())?
        != std::fs::canonicalize(expected).map_err(|e| e.to_string())?
    {
        return Err("Launched process is not the pinned installed runner".into());
    }
    Ok(())
}
fn await_launch<T>(
    rx: mpsc::Receiver<Result<T>>,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<T> {
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(
                "Authorization wait cancelled; dismiss any remaining Windows dialog".into(),
            );
        }
        if Instant::now() >= deadline {
            return Err("Windows authorization timed out".into());
        }
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(value) => return value,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("Windows launcher disconnected".into());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}
pub struct Authorized {
    pub stream: Stream,
    job: Option<LifetimeJob>,
    _installation: install::Installed,
}
impl Authorized {
    pub fn open(hash: &str, cancelled: &AtomicBool) -> Result<Self> {
        Self::open_with(hash, cancelled, launch)
    }
    fn open_with<F>(hash: &str, cancelled: &AtomicBool, launcher: F) -> Result<Self>
    where
        F: FnOnce(install::Installed, Identity, String, String, String) -> Result<Launched>
            + Send
            + 'static,
    {
        if cancelled.load(Ordering::Acquire) {
            return Err("Authorization cancelled".into());
        }
        let me = Process::open(std::process::id())?;
        if me.elevation()?.elevated {
            return Err("Run Studio normally, not as Administrator".into());
        }
        let installation = install::Installed::open(hash)?;
        let endpoint = Endpoint::create()?;
        let job = LifetimeJob::create()?;
        if PROMPT_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(
                "A Windows authorization dialog is still pending; dismiss it before retrying"
                    .into(),
            );
        }
        let prompt = Prompt;
        let (tx, rx) = mpsc::sync_channel(1);
        let (owner, pipe, name, hash) = (
            me.identity.clone(),
            endpoint.name().to_owned(),
            job.name().to_owned(),
            hash.to_owned(),
        );
        // Worker owns no endpoint/job handle: cancellation drops both immediately.
        // A late elevated process cannot join a destroyed job or activate a session.
        std::thread::Builder::new()
            .name("studio-uac-launch".into())
            .spawn(move || {
                let _prompt = prompt;
                let _ = tx.send(launcher(installation, owner, pipe, name, hash));
            })
            .map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(180);
        let launched = await_launch(rx, cancelled, deadline)?;
        if cancelled.load(Ordering::Acquire) {
            return Err("Authorization cancelled after launch".into());
        }
        let stream = endpoint.accept_elevated(
            launched.process,
            deadline.saturating_duration_since(Instant::now()),
            cancelled,
        )?;
        // Connecting is the runner's readiness barrier: it joins the job first.
        // ShellExecuteEx alone may return before the child has executed any code.
        if !job.contains_process(&stream.0.peer)? {
            return Err("Runner did not join the UI lifetime job".into());
        }
        Ok(Self {
            stream,
            job: Some(job),
            _installation: launched.installation,
        })
    }
    pub fn runner_pid(&self) -> u32 {
        self.stream.0.peer.identity.pid
    }
    pub fn wait_closed(&self, timeout: Duration) -> Result<()> {
        self.stream.0.peer.wait_closed(timeout)
    }
}
impl Drop for Authorized {
    fn drop(&mut self) {
        self.stream.shutdown();
        self.job.take();
    }
}
pub struct RunnerConnection {
    pub stream: Stream,
    _installation: install::Installed,
}
impl RunnerConnection {
    pub fn open(pipe: &str, ui: &Identity, job: &str, hash: &str) -> Result<Self> {
        let me = Process::open(std::process::id())?;
        if !me.elevation()?.elevated || me.identity.sid != ui.sid {
            return Err("Runner requires same-account UAC elevation".into());
        }
        runner_environment::initialize()?;
        let owner = Process::open(ui.pid)?;
        owner.verify(ui)?;
        if owner.elevation()?.elevated {
            return Err("Studio UI must not run as Administrator".into());
        }
        let installation = install::Installed::open(hash)?;
        same_executable(&me.identity.executable, installation.path())?;
        LifetimeJob::join(job, &ui.sid)?;
        let stream =
            Stream::connect_elevated(pipe, ui, Duration::from_secs(10), &AtomicBool::new(false))?;
        Ok(Self {
            stream,
            _installation: installation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_and_timed_out_launches_reject_late_completion() {
        for cancel in [true, false] {
            let (tx, rx) = mpsc::sync_channel::<Result<()>>(1);
            assert!(await_launch(rx, &AtomicBool::new(cancel), Instant::now()).is_err());
            assert!(tx.send(Ok(())).is_err());
        }
    }
    #[test]
    fn pre_cancel_never_opens_a_windows_prompt() {
        assert!(
            Authorized::open("invalid", &AtomicBool::new(true))
                .err()
                .unwrap()
                .contains("cancelled")
        );
    }

    #[test]
    #[ignore = "requires installed runner and disposable native UAC CI"]
    fn cancellation_destroys_endpoints_before_late_runner_and_allows_retry() {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        let hash = std::env::var("STUDIO_TEST_UAC_HASH").unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let (resources_tx, resources_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (exit_tx, exit_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let (flag, copy) = (cancelled.clone(), hash.clone());
        let owner = std::thread::spawn(move || {
            let result =
                Authorized::open_with(&copy, &flag, move |installation, owner, pipe, job, hash| {
                    resources_tx.send((pipe.clone(), job.clone())).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    let exit = (|| -> Result<()> {
                        let process = execute(&installation, &owner, &pipe, &job, &hash)?;
                        // SAFETY: exact ShellExecute process handle; only a signalled
                        // retained handle proves the late runner terminated.
                        if unsafe { WaitForSingleObject(process.as_raw_handle(), 2000) }
                            != WAIT_OBJECT_0
                        {
                            return Err("Late runner survived cancelled authorization".into());
                        }
                        Ok(())
                    })();
                    exit_tx.send(exit).unwrap();
                    Err("Late launch fixture completed".into())
                });
            result_tx.send(result.err().unwrap()).unwrap();
        });
        let (pipe, job) = resources_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        cancelled.store(true, Ordering::Release);
        assert!(
            result_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .contains("cancelled")
        );
        owner.join().unwrap();
        // While the fake OS prompt is blocked, a second launch must not start.
        let pending = Authorized::open_with(&hash, &AtomicBool::new(false), |_, _, _, _, _| {
            panic!("second prompt started")
        })
        .err()
        .unwrap();
        assert!(pending.contains("still pending"), "{pending}");
        // SAFETY: validated local name from this fixture, no handle inheritance.
        assert!(
            owned(unsafe { OpenJobObjectW(JOB_OBJECT_QUERY, 0, wide(&job).as_ptr()) }).is_err(),
            "cancelled job remains live"
        );
        assert_eq!(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(pipe)
                .unwrap_err()
                .raw_os_error(),
            Some(ERROR_FILE_NOT_FOUND as i32)
        );
        release_tx.send(()).unwrap();
        exit_rx
            .recv_timeout(Duration::from_secs(190))
            .unwrap()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while PROMPT_ACTIVE.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let retry = Authorized::open_with(&hash, &AtomicBool::new(false), |_, _, _, _, _| {
            Err("retry reached launcher".into())
        })
        .err()
        .unwrap();
        assert_eq!(retry, "retry reached launcher");
    }
}
