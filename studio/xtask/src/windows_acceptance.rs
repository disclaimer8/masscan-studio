//! CI-only restricted-token owner fixtures. Never used by the application.
use super::*;
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::{SystemServices::SE_GROUP_INTEGRITY, Threading::*},
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
    limited_observed(args, |_| Ok(()))
}
fn limited_observed(args: &[&str], observe: impl FnOnce(&OwnedHandle) -> Result<()>) -> Result<()> {
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
            Attributes: SE_GROUP_INTEGRITY as u32,
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
    let label_error = std::io::Error::last_os_error();
    // SAFETY: ConvertStringSidToSidW allocated this SID with LocalAlloc.
    unsafe {
        LocalFree(sid);
    }
    if ok == 0 {
        return Err(label_error.into());
    }
    let exe = std::env::current_exe()?;
    let exe = exe
        .to_str()
        .ok_or("Fixture executable path is not Unicode")?;
    let mut argv = vec![exe];
    argv.extend_from_slice(args);
    let mut line = wide(&studio_platform::win_setup::command_line(&argv)?);
    let log_path = std::env::temp_dir().join(format!(
        "studio-limited-{}.log",
        studio_protocol::new_id()?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let log = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .read(true)
        .open(&log_path)?;
    let input = fs::File::open("NUL")?;
    for h in [log.as_raw_handle(), input.as_raw_handle()] {
        // SAFETY: retained fixture-only file handles; no concurrent child launch.
        if unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: input.as_raw_handle(),
        hStdOutput: log.as_raw_handle(),
        hStdError: log.as_raw_handle(),
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: explicit executable, mutable terminated command line; only the
    // fixture log/NUL are inheritable. Current environment and own limited token.
    if unsafe {
        CreateProcessAsUserW(
            restricted.as_raw_handle(),
            wide(exe).as_ptr(),
            line.as_mut_ptr(),
            null(),
            null(),
            1,
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
    let observed = observe(&process);
    if observed.is_err() {
        // SAFETY: only this disposable fixture child is terminated on failure.
        unsafe {
            TerminateProcess(process.as_raw_handle(), 1);
        }
    }
    // SAFETY: retained process supports wait; bounded fixture deadline.
    if unsafe { WaitForSingleObject(process.as_raw_handle(), 600000) } != WAIT_OBJECT_0 {
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
    drop(log);
    print!("{}", fs::read_to_string(&log_path)?);
    fs::remove_file(log_path)?;
    observed?;
    if exit != 0 {
        return Err(format!("Restricted fixture failed with {exit}").into());
    }
    Ok(())
}

pub fn verify_uac(root: &Path) -> Result<()> {
    use std::time::{Duration, Instant};
    use studio_platform::{
        trusted,
        windows::{Process, install::Installed},
    };
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || studio_protocol::raw_profile_enabled(studio_protocol::Backend::MacFeth)
        || !studio_protocol::RAW_PROFILES.is_empty()
    {
        return Err("Requires disposable Windows CI with raw scanning disabled".into());
    }
    if std::env::var_os("CARGO_TARGET_DIR").is_some() {
        return Err("CI probe requires default target directory".into());
    }
    let hash = trusted::file_hash(&root.join("target/debug/studio-runner.exe"))?;
    let _pinned = Installed::open(&hash)?;
    limited(&["windows-uac-cancel-fixture", &hash])?;
    for mode in ["close", "disconnect", "drop"] {
        limited(&["windows-uac-fixture", &hash, mode])?;
    }
    let ready = std::env::temp_dir().join(format!(
        "studio-uac-owner-{}.json",
        studio_protocol::id_text(studio_protocol::new_id()?)
    ));
    let result = limited_observed(
        &[
            "windows-uac-fixture",
            &hash,
            "owner",
            ready.to_str().ok_or("Non-Unicode ready path")?,
        ],
        |owner| {
            let deadline = Instant::now() + Duration::from_secs(190);
            let identity = loop {
                if let Ok(bytes) = fs::read(&ready)
                    && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
                    && let Ok(value) = serde_json::from_value::<studio_platform::windows::Identity>(
                        value["runner"].clone(),
                    )
                {
                    break value;
                }
                // SAFETY: retained fixture process; nonblocking liveness check.
                if unsafe { WaitForSingleObject(owner.as_raw_handle(), 0) } != WAIT_TIMEOUT {
                    return Err("UAC owner exited before readiness".into());
                }
                if Instant::now() >= deadline {
                    return Err("UAC owner readiness timed out".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let runner = Process::open(identity.pid)?;
            runner.verify(&identity)?;
            // SAFETY: terminate only the exact retained disposable UI fixture.
            if unsafe { TerminateProcess(owner.as_raw_handle(), 0) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            runner.wait_closed(Duration::from_secs(2))?;
            Ok(())
        },
    );
    let _ = fs::remove_file(ready);
    result?;
    println!(
        "PASS: actual runas from restricted same-account owner, pinned image, Hello, repeated preflight, CloseSession, IPC loss, job drop and abrupt owner death. No desktop consent or packet claim."
    );
    Ok(())
}

pub fn uac_fixture() -> Result<()> {
    let hash = std::env::args()
        .nth(2)
        .ok_or("Supply installed runner SHA-256")?;
    let mode = std::env::args().nth(3).unwrap_or("close".into());
    if mode != "close"
        && std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        && std::env::var("STUDIO_UAC_LAB_ACCEPTANCE").as_deref() != Ok("1")
    {
        return Err("Destructive fixture modes require disposable CI".into());
    }
    use std::{sync::atomic::AtomicBool, time::Duration};
    use studio_platform::windows::{Process, uac::Authorized};
    use studio_protocol::{Command as Message, *};
    let auth = Authorized::open(&hash, &AtomicBool::new(false))?;
    let runner = Process::open(auth.runner_pid())?;
    println!(
        "Owner token={:?}, logon={:?}; runner token={:?}, logon={:?}",
        Process::open(std::process::id())?.elevation()?,
        Process::open(std::process::id())?.identity().logon,
        runner.elevation()?,
        runner.identity().logon
    );
    let session = new_id()?;
    let mut order = ReceiveOrder::new(session, [0; 16], [0; 16]);
    for (i, command) in [Message::Hello, Message::CheckNetwork, Message::CheckNetwork]
        .into_iter()
        .enumerate()
    {
        let stream = auth.stream.clone();
        let (done, wait) = std::sync::mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            if wait.recv_timeout(Duration::from_secs(10)).is_err() {
                stream.shutdown();
            }
        });
        let result = (|| -> Result<()> {
            write_frame(
                &mut auth.stream.clone(),
                &Envelope::new(session, [0; 16], [0; 16], i as u64 + 1, command),
            )?;
            let reply = read_frame::<Event>(&mut auth.stream.clone())?;
            order.accept(&reply)?;
            match (i, reply.payload) {
                (0, Event::Hello { engine }) if engine == ENGINE_VERSION => {}
                (1 | 2, Event::NetworkChecked { ready: false, .. }) => {}
                _ => return Err("Unexpected UAC protocol reply or raw readiness".into()),
            }
            Ok(())
        })();
        let _ = done.send(());
        let _ = watchdog.join();
        result?;
    }
    match mode.as_str() {
        "close" => {
            write_frame(
                &mut auth.stream.clone(),
                &Envelope::new(session, [0; 16], [0; 16], 4, Message::CloseSession),
            )?;
            auth.wait_closed(Duration::from_secs(2))?;
        }
        "disconnect" => {
            auth.stream.shutdown();
            auth.wait_closed(Duration::from_secs(2))?;
        }
        "drop" => {
            drop(auth);
            runner.wait_closed(Duration::from_secs(2))?;
        }
        "owner" => {
            let path = std::env::args().nth(4).ok_or("Missing readiness path")?;
            use std::io::Write;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?
                .write_all(&serde_json::to_vec(&serde_json::json!({"runner":runner.identity(),"owner":Process::open(std::process::id())?.identity()}))?)?;
            std::thread::sleep(Duration::from_secs(15));
            return Err("CI did not terminate UAC owner fixture".into());
        }
        _ => return Err("Unknown fixture mode".into()),
    }
    println!("PASS: UAC session {mode}, raw scanning stayed disabled");
    Ok(())
}

pub fn cancel_fixture() -> Result<()> {
    let hash = std::env::args()
        .nth(2)
        .ok_or("Supply installed runner hash")?;
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
        return Err("Requires disposable CI".into());
    }
    run(Command::new("cargo").args(["test", "--locked", "-p", "studio-platform", "--lib", "windows::uac::tests::cancellation_destroys_endpoints_before_late_runner_and_allows_retry", "--", "--ignored", "--exact", "--nocapture"]).env("STUDIO_TEST_UAC_HASH", hash))
}

pub fn package_tests(root: &Path) -> Result<()> {
    let output = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "-p",
            "studio-platform",
            "--lib",
            "--no-run",
            "--message-format=json-render-diagnostics",
        ])
        .output()?;
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Err("Native acceptance fixture build failed".into());
    }
    let exe = String::from_utf8(output.stdout)?
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|v| {
            v["reason"] == "compiler-artifact"
                && v["target"]["name"] == "studio_platform"
                && v["profile"]["test"] == true
        })
        .filter_map(|v| v["executable"].as_str().map(PathBuf::from))
        .next_back()
        .ok_or("Native fixture executable missing")?;
    let dir = root.join("dist").join("uac-acceptance");
    fs::create_dir_all(&dir)?;
    let target = dir.join("studio-uac-tests.exe");
    fs::copy(exe, &target)?;
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"sha256":digest(&target)?,"source_commit":text(Command::new("git").args(["rev-parse","HEAD"]))?,"cargo_lock_sha256":digest(&root.join("Cargo.lock"))?,"raw_profiles":studio_protocol::RAW_PROFILES}),
        )?,
    )?;
    println!("Native acceptance fixture: {}", target.display());
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

pub fn guard_probe(root: &Path) -> Result<()> {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || !studio_platform::windows::Process::open(std::process::id())?
            .elevation()?
            .elevated
    {
        return Err("Guard probe requires disposable elevated Windows CI".into());
    }
    run(Command::new("cargo").args(["build", "--locked", "-p", "studio-runner"]))?;
    if std::env::var_os("CARGO_TARGET_DIR").is_some() {
        return Err("Guard probe requires default target directory".into());
    }
    for args in [vec!["--stdio"], vec!["--connect-pipe", "invalid", "{}"]] {
        let output = Command::new(root.join("target/debug/studio-runner.exe"))
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()?;
        let error = String::from_utf8_lossy(&output.stderr);
        if output.status.success()
            || !error.contains("Elevated runner requires an authenticated UAC session")
        {
            return Err(
                format!("Privileged launch bypass was not rejected at entry: {error}").into(),
            );
        }
    }
    println!("PASS: elevated stdio and ordinary pipe entry points refused");
    Ok(())
}
