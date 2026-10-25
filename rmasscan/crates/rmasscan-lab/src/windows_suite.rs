use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
pub(crate) fn safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
        && !s.contains("..")
}
pub(crate) fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}
/// Unguessable per-process run identifier: `r` plus 16 bytes from the operating system RNG
/// as hex. It binds every guest Verify report and every returned artifact to one invocation,
/// so it must not be derivable from the pid or the clock.
pub(crate) fn nonce() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the operating system RNG is unavailable");
    format!("r{}", hex_of(&bytes))
}
fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn invocation_nonce(run: &str, tag: &str) -> String {
    let tag_hash = Sha256::digest(tag.as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    format!("{run}-{tag_hash}")
}
pub(crate) fn epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
pub(crate) fn fresh_report(suite: &str, tag: &str, nonce: &str) -> Result<String, String> {
    if ![suite, tag, nonce].iter().all(|s| safe_id(s)) {
        return Err("unsafe run identifier".into());
    }
    Ok(format!("t4/in/{suite}.{tag}.{nonce}.verify.json"))
}
fn gate_fetch_allowed(rc: i32, want: &str, got: &str) -> Result<(), String> {
    if rc != 0 || want != got {
        Err("Verify invocation failed or report nonce mismatches".into())
    } else {
        Ok(())
    }
}
fn invoke_fresh_report(
    nonce: &str,
    invoke: impl FnOnce() -> Result<Output, String>,
    fetch: impl FnOnce() -> Result<Value, String>,
) -> Result<Value, String> {
    let result = invoke()?;
    if result.rc != 0 {
        return Err(format!(
            "Verify failed with rc={}; refusing to fetch any report",
            result.rc
        ));
    }
    let report = fetch()?;
    gate_fetch_allowed(
        result.rc,
        nonce,
        report["verification_nonce"].as_str().unwrap_or(""),
    )?;
    Ok(report)
}
pub(crate) fn may_discard(verdict: &str, behaviour_fail: bool) -> bool {
    matches!(verdict, "INVALID" | "NOT RUN") && !behaviour_fail
}
pub(crate) fn parse_tcpdump(s: &str) -> Value {
    let num = |suffix: &str| -> Option<u64> {
        s.lines().find_map(|l| {
            let mut p = l.split_whitespace();
            let n = p.next()?.parse().ok()?;
            let tail = p.collect::<Vec<_>>().join(" ");
            (tail == format!("packets {suffix}") || tail == format!("packet {suffix}")).then_some(n)
        })
    };
    json!({"listening":s.contains("listening on"),"captured":num("captured"),"received":num("received by filter"),"dropped_kernel":num("dropped by kernel"),"dropped_if":num("dropped by interface")})
}
pub(crate) fn read_json(p: impl AsRef<Path>) -> Result<Value, String> {
    serde_json::from_slice(
        &fs::read(p.as_ref()).map_err(|e| format!("{}: {e}", p.as_ref().display()))?,
    )
    .map_err(|e| e.to_string())
}
pub(crate) fn write_json(p: impl AsRef<Path>, v: &Value) -> Result<(), String> {
    fs::write(p, serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}
pub(crate) fn hash(p: impl AsRef<Path>) -> Result<String, String> {
    Ok(Sha256::digest(fs::read(p).map_err(|e| e.to_string())?)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
pub(crate) fn options(args: &[String]) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut o = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let k = &args[i];
        if !k.starts_with("--") {
            return Err(format!("expected option, got {k}"));
        }
        i += 1;
        let mut v = vec![];
        while i < args.len() && !args[i].starts_with("--") {
            v.push(args[i].clone());
            i += 1;
        }
        o.insert(k.trim_start_matches("--").into(), v);
    }
    Ok(o)
}
pub(crate) fn opt(o: &BTreeMap<String, Vec<String>>, k: &str, d: &str) -> String {
    o.get(k)
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| d.into())
}
pub(crate) fn required(o: &BTreeMap<String, Vec<String>>, k: &str) -> Result<String, String> {
    let v = opt(o, k, "");
    if v.is_empty() {
        Err(format!("--{k} required"))
    } else {
        Ok(v)
    }
}
pub(crate) struct Output {
    pub rc: i32,
    pub stdout: String,
    pub stderr: String,
}
pub(crate) fn command(argv: &[String], timeout: u64, check: bool) -> Result<Output, String> {
    let program = argv.first().ok_or("empty command")?;
    let mut cmd = Command::new(program);
    cmd.args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut p = cmd.spawn().map_err(|e| format!("{program}: {e}"))?;
    let pid = p.id();
    let mut so = p.stdout.take().ok_or("stdout unavailable")?;
    let mut se = p.stderr.take().ok_or("stderr unavailable")?;
    let (ot, output) = std::sync::mpsc::channel();
    let (et, error) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut b = String::new();
        let _ = so.read_to_string(&mut b);
        let _ = ot.send(b);
    });
    thread::spawn(move || {
        let mut b = String::new();
        let _ = se.read_to_string(&mut b);
        let _ = et.send(b);
    });
    let start = Instant::now();
    let mut rc = loop {
        if let Some(st) = p.try_wait().map_err(|e| e.to_string())? {
            break st.code().unwrap_or(-1);
        }
        if rmasscan_net::lab_io::stop_requested() {
            kill_command_tree(pid);
            let _ = p.kill();
            let _ = p.wait();
            break 130;
        }
        if start.elapsed() > Duration::from_secs(timeout) {
            kill_command_tree(pid);
            let _ = p.kill();
            let _ = p.wait();
            break 124;
        }
        thread::sleep(Duration::from_millis(20));
    };
    // A descendant can inherit a pipe after the direct child has exited (scp's
    // ProxyJump helpers hold stderr briefly). Both pipes share one drain window
    // that never extends past the command deadline, so the deadline never
    // depends on that descendant closing its handles.
    let drain_end = Instant::now()
        + Duration::from_secs(timeout)
            .saturating_sub(start.elapsed())
            .min(Duration::from_secs(5));
    let stdout = output.recv_timeout(drain_end.saturating_duration_since(Instant::now()));
    let stderr = error.recv_timeout(drain_end.saturating_duration_since(Instant::now()));
    if stdout.is_err() || stderr.is_err() {
        kill_command_tree(pid);
        rc = 124;
    }
    let r = Output {
        rc,
        stdout: stdout.unwrap_or_default(),
        stderr: stderr.unwrap_or_else(|_| "command output collection exceeded deadline".into()),
    };
    if check && rc != 0 {
        Err(format!(
            "{} failed ({rc}): {} {}",
            argv[0],
            r.stderr.chars().take(600).collect::<String>(),
            r.stdout.chars().take(600).collect::<String>()
        ))
    } else {
        Ok(r)
    }
}
fn kill_command_tree(pid: u32) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{pid}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
pub(crate) fn strings(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).into()).collect()
}
fn copy_tree(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    for en in fs::read_dir(src).map_err(|e| e.to_string())? {
        let en = en.map_err(|e| e.to_string())?;
        let to = dst.join(en.file_name());
        if en.file_type().map_err(|e| e.to_string())?.is_dir() {
            copy_tree(&en.path(), &to)?;
        } else {
            fs::copy(en.path(), to).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
/// Every external process of the orchestrator (ssh, scp) goes through this seam, so gate and
/// run behaviour is testable offline with a recording stand and nothing can reach a host by
/// accident.
pub(crate) trait Exec {
    fn exec(&self, argv: &[String], timeout: u64) -> Result<Output, String>;
    /// Bytes of `path` (relative to the repository root) in the tree of `commit`, read with
    /// `git show`. The guest scripts come from here, never from a compile-time path.
    fn file_at_commit(&self, repo: &Path, commit: &str, path: &str) -> Result<Vec<u8>, String>;
    fn pause(&self, d: Duration) {
        thread::sleep(d);
    }
}
pub(crate) struct Real;
impl Exec for Real {
    fn exec(&self, argv: &[String], timeout: u64) -> Result<Output, String> {
        command(argv, timeout, false)
    }
    fn file_at_commit(&self, repo: &Path, commit: &str, path: &str) -> Result<Vec<u8>, String> {
        if !crate::deploy::full_commit(commit) || path.starts_with('-') || path.contains("..") {
            return Err("unsafe commit or path".into());
        }
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            .arg("show")
            .arg(format!("{commit}:{path}"))
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("git: {e}"))?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(format!(
                "git show {commit}:{path} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}
/// A suite failure with the exit code that operator scripts key off. NOT RUN (2) is a refusal
/// before any remote change (read-only preflights excepted); the others happen once a run has begun or on an unusable directory.
#[derive(Debug, PartialEq)]
pub(crate) enum SuiteError {
    NotRun(String),
    Abort(String),
    RerunRefused(String),
    SchemaTooOld(String),
}
pub const EXIT_NOT_RUN: i32 = 2;
pub const EXIT_ABORT: i32 = 10;
pub const EXIT_RERUN_REFUSED: i32 = 11;
pub const EXIT_SCHEMA_TOO_OLD: i32 = 12;
/// Directories written by this suite carry this capture schema (3: nonce chain mandatory).
pub(crate) const CAPTURE_SCHEMA: u64 = 3;

// Dead-man bounds (`timeout -k 10 BOUND`) of the detached remote tools. The bound is a safety net for an
// orchestrator that died, not a limit on a healthy run: `timeout` stopping tcpdump or the link-restoring
// tool in the middle of a slow run would turn it INVALID (or leave a link down until the handler ran),
// so every bound is twice the worst-case expected run time. Expected times come from the tools' own
// arguments in `one_inner`: inject `--wait-first 120 --duration 2.0`, flood `--duration 40`, linkloss
// `--wait-first 120 --down-after 2.0 --hold-max 40` plus restore/exit slack.
pub(crate) const INJECT_EXPECTED_S: u64 = 120 + 2 + 3;
pub(crate) const INJECT_BOUND_S: u64 = 2 * INJECT_EXPECTED_S;
pub(crate) const FLOOD_EXPECTED_S: u64 = 40 + 5;
pub(crate) const FLOOD_BOUND_S: u64 = 2 * FLOOD_EXPECTED_S;
pub(crate) const LINKLOSS_EXPECTED_S: u64 = 120 + 2 + 40 + 30;
pub(crate) const LINKLOSS_BOUND_S: u64 = 2 * LINKLOSS_EXPECTED_S;
/// Worst-case seconds a capture or the listener lives for one run: the per-run timeout plus the longest
// tail (linkloss: marker 15 + tool exit 30 + link restore 60 + quiet 40 + end marker 15 = 160, rounded up).
pub(crate) const fn capture_expected_s(run_timeout: u64) -> u64 {
    run_timeout + 165
}
/// Fixed seconds one run spends besides sending and waiting: the gate's guest Verify, the runner's
/// start and the result transfer. The 240 s per-run default is its generous multiple.
pub(crate) const PERF_OVERHEAD_S: u64 = 60;
/// Seconds one perf cell takes on the guest when healthy: sending at the requested pace (rounded up)
/// plus the scanner's wait.
pub(crate) fn perf_nominal_s(item: &Value) -> u64 {
    let c = crate::verify::perf_case(item["rate"].as_u64().unwrap_or(1));
    c["syn"]
        .as_u64()
        .unwrap_or(0)
        .div_ceil(c["rate"].as_u64().unwrap_or(1).max(1))
        + c["wait"].as_u64().unwrap_or(0)
}
/// Per-run timeout of a perf cell: at least twice (nominal + overhead), and never below the operator's
/// `--run-timeout`. It also sets the dead-man bound of the listener and captures (see `Suite::bound`).
pub(crate) fn perf_run_timeout(item: &Value, floor: u64) -> u64 {
    floor.max(2 * (perf_nominal_s(item) + PERF_OVERHEAD_S))
}
impl SuiteError {
    pub(crate) fn code(&self) -> i32 {
        match self {
            Self::NotRun(_) => EXIT_NOT_RUN,
            Self::Abort(_) => EXIT_ABORT,
            Self::RerunRefused(_) => EXIT_RERUN_REFUSED,
            Self::SchemaTooOld(_) => EXIT_SCHEMA_TOO_OLD,
        }
    }
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::NotRun(m) | Self::Abort(m) | Self::RerunRefused(m) | Self::SchemaTooOld(m) => m,
        }
    }
}
impl From<String> for SuiteError {
    fn from(m: String) -> Self {
        Self::NotRun(m)
    }
}
impl From<&str> for SuiteError {
    fn from(m: &str) -> Self {
        Self::NotRun(m.into())
    }
}
/// A directory written before the current capture schema cannot be extended: its runs lack
/// the nonce chain and the verifier would reject new runs next to them.
pub(crate) fn schema_too_old(manifest: &Value) -> bool {
    manifest["capture_schema"].as_u64().unwrap_or(1) < CAPTURE_SCHEMA
}
const NETNS: &str = "wvp-n2";
/// The exact tcpdump command lines the suite starts, and the eno1 filter. The
/// verifier validates the recorded argv against the same shape.
pub(crate) fn capture_commands(netns: &str, rev: &str, pm: &str) -> (String, String, String) {
    let filter = format!(
        "net 198.18.0.0/30 or (arp and (host 198.18.0.1 or host 198.18.0.2)) or ether host {MAC} or ether host {pm} or ether proto 0x88b5 or ether proto 0x88b6"
    );
    let peer = format!(
        "ip netns exec {netns} tcpdump -i lab0 -n -U --immediate-mode -B 16384 -s 0 -Z root -w {}",
        quote(&format!("{rev}/peer.pcap"))
    );
    let eno = format!(
        "tcpdump -i eno1 -n -U --immediate-mode -B 4096 -s 0 -Z root -w {} {}",
        quote(&format!("{rev}/eno1.pcap")),
        quote(&filter)
    );
    (peer, eno, filter)
}
const GUEST: &str = "C:\\Users\\lab\\t4";
const IFACE: &str = "\\Device\\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}";
const MAC: &str = "52:54:00:04:80:a9";
struct Suite<'a> {
    exec: &'a dyn Exec,
    out: PathBuf,
    suite: String,
    run_id: String,
    remote: String,
    remote_ev: String,
    qmp: String,
    manifest: String,
    guest_exe: String,
    plan: String,
    timeout: u64,
    pm: String,
}
/// `check` turns a non-zero exit into an error, like `command(.., check)`.
fn checked(out: Output, argv0: &str, check: bool) -> Result<Output, String> {
    if check && out.rc != 0 {
        Err(format!(
            "{argv0} failed ({}): {} {}",
            out.rc,
            out.stderr.chars().take(600).collect::<String>(),
            out.stdout.chars().take(600).collect::<String>()
        ))
    } else {
        Ok(out)
    }
}
impl Suite<'_> {
    fn run_cmd(&self, argv: &[String], timeout: u64, check: bool) -> Result<Output, String> {
        let out = self.exec.exec(argv, timeout)?;
        checked(out, argv.first().map_or("", String::as_str), check)
    }
    fn home(&self, cmd: &str, check: bool) -> Result<Output, String> {
        self.run_cmd(
            &strings(&[
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=15",
                "home-pc",
                cmd,
            ]),
            180,
            check,
        )
    }
    fn guest(&self, cmd: &str, check: bool) -> Result<Output, String> {
        self.run_cmd(
            &strings(&[
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=15",
                "-J",
                "home-pc",
                "-p",
                "2222",
                "lab@127.0.0.1",
                cmd,
            ]),
            self.timeout,
            check,
        )
    }
    fn transfer(
        &self,
        guest: bool,
        to: bool,
        local: &Path,
        remote: &str,
        check: bool,
    ) -> Result<(), String> {
        let mut a = strings(&["scp", "-q", "-o", "BatchMode=yes"]);
        let remote = if guest {
            a.extend(strings(&["-J", "home-pc", "-P", "2222"]));
            format!(
                "lab@127.0.0.1:{}",
                remote
                    .strip_prefix("C:\\Users\\lab\\")
                    .unwrap_or(remote)
                    .replace('\\', "/")
            )
        } else {
            format!("home-pc:{remote}")
        };
        let local = local.to_string_lossy().into_owned();
        a.extend(if to {
            vec![local, remote]
        } else {
            vec![remote, local]
        });
        self.run_cmd(&a, 180, check).map(|_| ())
    }
    /// Best-effort copy of a remote scratch directory into local evidence (never fails the caller).
    fn fetch_dir(&self, remote: &str, local: &Path) {
        let _ = fs::create_dir_all(local);
        let a = vec![
            "scp".to_string(),
            "-q".into(),
            "-r".into(),
            "-o".into(),
            "BatchMode=yes".into(),
            format!("home-pc:{remote}/."),
            local.to_string_lossy().into_owned(),
        ];
        let _ = self.run_cmd(&a, 180, false);
    }
    fn peer(&self, args: &str) -> String {
        format!(
            "sudo -n ip netns exec wvp-n2 {} peer {args}",
            quote(&self.remote)
        )
    }
    /// Start a root process detached on home-pc. It runs under `timeout` (dead-man): if this
    /// orchestrator dies, nothing outlives `bound` seconds, and a TERM to the recorded pid is
    /// forwarded to the child so link-restoring handlers still run.
    fn bg(&self, cmd: &str, pid: &str, err: &str, bound: u64) -> Result<(), String> {
        self.home(
            &format!(
                "nohup sudo -n sh -c {} > /dev/null 2> {} < /dev/null &",
                    quote(&format!("born=$(awk '{{print $22}}' /proc/$$/stat) || exit 1; printf '%s %s\\n' \"$$\" \"$born\" > {}; exec timeout -k 10 {bound} {cmd}", quote(pid))),
                quote(err)
            ),
            true,
        )
        .map(|_| ())
    }
    fn stop(&self, pid: &str, sig: &str) {
        let _ = self.home(&owned_process_command(pid, Some(sig)), false);
    }
    fn wait(&self, condition: &str, secs: u64) -> Result<(), String> {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(secs) {
            if self.home(condition, false)?.rc == 0 {
                return Ok(());
            }
            self.exec.pause(Duration::from_millis(200));
        }
        Err(format!("timeout waiting for {condition}"))
    }
    fn exited(&self, pid: &str, secs: u64) -> bool {
        self.wait(&owned_process_command(pid, None), secs).is_ok()
    }
    fn counters(&self) -> Result<(u64, u64), String> {
        let r = self.home(&self.peer("counters --iface lab0"), true)?;
        let n = r
            .stdout
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        if n.len() != 2 {
            return Err("invalid peer counters".into());
        }
        Ok((n[0], n[1]))
    }
    fn interface_drops(&self, peer: bool) -> Result<u64, String> {
        let cmd = if peer {
            "sudo -n ip netns exec wvp-n2 cat /sys/class/net/lab0/statistics/rx_dropped"
        } else {
            "cat /sys/class/net/eno1/statistics/rx_dropped"
        };
        self.home(cmd, true)?
            .stdout
            .trim()
            .parse::<u64>()
            .map_err(|e| e.to_string())
    }
    fn status(&self, ev: &Path, name: &str) -> Result<Value, String> {
        let r = self.home(
            &format!(
                "{} vm-lab status --run-id n2 --manifest {}",
                quote(&self.remote),
                quote(&self.manifest)
            ),
            true,
        )?;
        fs::write(ev.join(name), &r.stdout).map_err(|e| e.to_string())?;
        serde_json::from_str(&r.stdout).map_err(|e| e.to_string())
    }
    /// The per-run raw-run gate. Returns the guest Verify exit code (always 0 on success) so
    /// it is recorded in the run's evidence. Nothing here sends a frame.
    fn gate(&self, ev: &Path, rev: &str, tag: &str) -> Result<i32, String> {
        let invocation_nonce = invocation_nonce(&self.run_id, tag);
        let report = fresh_report(&self.suite, tag, &self.run_id)?;
        let gp = format!("C:\\Users\\lab\\{}", report.replace('/', "\\"));
        let cmd = format!(
            "pwsh -NoProfile -File C:\\Users\\lab\\windows-vm-lab.ps1 -Manifest C:\\Users\\lab\\n2.json -Action Verify -VerificationNonce {} -ReportPath {}",
            cmdquote(&invocation_nonce)?,
            cmdquote(&gp)?
        );
        let verify_rc = std::cell::Cell::new(-1);
        let fresh = invoke_fresh_report(
            &invocation_nonce,
            || {
                let out = self.guest(&cmd, false)?;
                verify_rc.set(out.rc);
                fs::write(ev.join("guest-verify-stdout.txt"), &out.stdout)
                    .map_err(|e| e.to_string())?;
                fs::write(ev.join("guest-verify-stderr.txt"), &out.stderr)
                    .map_err(|e| e.to_string())?;
                Ok(out)
            },
            || {
                self.transfer(true, false, &ev.join("guest-verify.json"), &report, true)?;
                read_json(ev.join("guest-verify.json"))
            },
        )?;
        // The scanner is told which NPF device to open; it must be the lab NIC this very
        // Verify just proved, not a constant that may have drifted from the guest.
        let npf = fresh["npf"]
            .as_str()
            .or(fresh["lab"]["Npf"].as_str())
            .unwrap_or("");
        if npf != IFACE {
            return Err(format!(
                "freshly verified lab NIC {npf:?} differs from scanner --iface {IFACE:?}"
            ));
        }
        self.transfer(
            false,
            true,
            &ev.join("guest-verify.json"),
            &format!("{rev}/guest-verify.json"),
            true,
        )?;
        self.home(
            &format!(
                "{} vm-lab record-guest --run-id n2 --manifest {} --verify-json {} --nonce {}",
                quote(&self.remote),
                quote(&self.manifest),
                quote(&format!("{rev}/guest-verify.json")),
                quote(&invocation_nonce)
            ),
            true,
        )?;
        let st = self.status(ev, "status-pre.json")?;
        if st["raw_run_allowed"] != true
            || st["isolation_violations"]
                .as_array()
                .is_some_and(|v| !v.is_empty())
        {
            return Err("raw run isolation gate refused".into());
        }
        if st["guest_verify_nonce"].as_str() != Some(invocation_nonce.as_str()) {
            return Err(format!(
                "raw run gate refused: the host status relied on another guest Verify ({})",
                st["guest_verify_nonce"]
            ));
        }
        Ok(verify_rc.get())
    }
    fn cp(&self, n: u64) -> String {
        format!("{GUEST}\\cp\\{}\\{}\\N{n}.bin", self.suite, self.run_id)
    }
    fn runner(
        &self,
        ev: &Path,
        tag: &str,
        argv: &[String],
        forge: bool,
        restricted: bool,
    ) -> Result<String, String> {
        let name = if forge {
            "forge-argv.json"
        } else {
            "argv.json"
        };
        write_json(
            ev.join(name),
            &json!({"exe":self.guest_exe,"argv":argv,"invocation_nonce":invocation_nonce(&self.run_id,tag)}),
        )?;
        let input = format!("t4/in/{}.{}.{}.{}", self.suite, self.run_id, tag, name);
        self.transfer(true, true, &ev.join(name), &input, true)?;
        let gout = format!(
            "{GUEST}\\out\\{}\\{}\\{tag}{}",
            self.suite,
            self.run_id,
            if forge { ".forge" } else { "" }
        );
        let gi = format!("C:\\Users\\lab\\{}", input.replace('/', "\\"));
        let cmd = if restricted {
            format!(
                "{GUEST}\\windows_wire_runas.cmd {} {} 150",
                cmdquote(&gi)?,
                cmdquote(&gout)?
            )
        } else {
            format!(
                "pwsh -NoProfile -File {GUEST}\\windows_wire_run.ps1 -ArgvFile {} -OutDir {}",
                cmdquote(&gi)?,
                cmdquote(&gout)?
            )
        };
        // The PowerShell runner exits zero when it has successfully recorded a scanner failure.
        // An SSH or runner failure cannot authorize fetching any previous result.
        self.guest(&cmd, true)?;
        Ok(gout)
    }
    fn one(
        &self,
        item: &Value,
        argv: Vec<String>,
        forge: Option<Vec<String>>,
        cp_used: Option<String>,
    ) -> Result<(), String> {
        let tag = item["tag"].as_str().ok_or("run missing tag")?;
        if !safe_id(tag) {
            return Err("unsafe tag".into());
        }
        let ev = self.out.join("runs").join(tag);
        if ev.exists() {
            return Err(format!("{} already exists", ev.display()));
        }
        fs::create_dir_all(&ev).map_err(|e| e.to_string())?;
        let rev = format!("{}/{}/{}/{tag}", self.remote_ev, self.suite, self.run_id);
        self.home(
            &scratch_create(&self.remote_ev, &self.suite, &self.run_id, tag)?,
            true,
        )?;
        let result = self.one_inner(item, &argv, forge, cp_used, &ev, &rev);
        for n in ["listener", "inject", "flood", "linkloss", "peer", "eno1"] {
            self.stop(&format!("{rev}/{n}.pid"), "TERM");
        }
        if result.is_ok() {
            // Successful copies were hash checked before this point.
            self.home(&remove_scratch_command(&rev), true)?;
        } else {
            // Keep the remote scratch directory and also bring a copy home, so an aborted
            // run leaves its tcpdump/listener logs in the evidence tree.
            self.fetch_dir(
                &rev,
                &self
                    .out
                    .join("runs_aborted")
                    .join(format!("{tag}.{}", self.run_id)),
            );
        }
        result
    }
    fn one_inner(
        &self,
        item: &Value,
        argv: &[String],
        forge: Option<Vec<String>>,
        cp_used: Option<String>,
        ev: &Path,
        rev: &str,
    ) -> Result<(), String> {
        let tag = item["tag"].as_str().ok_or("tag missing")?;
        let kind = item["kind"].as_str().unwrap_or("");
        let verify_exit = self.gate(ev, rev, tag)?;
        if kind == "resume" {
            let n = item["n"].as_u64().ok_or("resume n missing")?;
            let saved = self
                .out
                .join("runs")
                .join(format!("pause_N{n}"))
                .join("checkpoint.bin");
            self.transfer(true, true, &saved, &self.cp(n), true)?;
        }
        if let Some(forge) = forge {
            let out = self.runner(ev, tag, &forge, true, false)?;
            self.transfer(
                true,
                false,
                &ev.join("forge-stdout.txt"),
                &format!("{out}\\stdout.txt"),
                true,
            )?;
            if kind == "ckpt_refuse" {
                let p =
                    arg_value(&forge, "--checkpoint-out").ok_or("forge checkpoint path missing")?;
                self.transfer(true, false, &ev.join("checkpoint-forged.bin"), p, true)?;
                let used = mutate_checkpoint(
                    item["variant"].as_str().unwrap_or(""),
                    &fs::read(ev.join("checkpoint-forged.bin")).map_err(|e| e.to_string())?,
                )?;
                fs::write(ev.join("checkpoint-used.bin"), used).map_err(|e| e.to_string())?;
                self.transfer(
                    true,
                    true,
                    &ev.join("checkpoint-used.bin"),
                    cp_used.as_deref().ok_or("checkpoint destination missing")?,
                    true,
                )?;
            }
        }
        let silent = if self.plan == "failure" {
            "8099,8100-8119"
        } else {
            "8099"
        };
        let lis = format!("{rev}/listener.pid");
        self.bg(
            &self.peer(&format!(
                "listen --open 80,443,8000-8007 --silent {silent} --ready {}",
                quote(&format!("{rev}/listener.json"))
            )),
            &lis,
            &format!("{rev}/listener.err"),
            self.bound(),
        )?;
        self.wait(
            &format!("test -s {}", quote(&format!("{rev}/listener.json"))),
            30,
        )?;
        self.transfer(
            false,
            false,
            &ev.join("listeners.json"),
            &format!("{rev}/listener.json"),
            true,
        )?;
        let (peer_cmd, eno_cmd, filter) = capture_commands(NETNS, rev, &self.pm);
        let c0 = self.counters()?;
        let drops0 = (self.interface_drops(true)?, self.interface_drops(false)?);
        for (n, cmd) in [("peer", &peer_cmd), ("eno1", &eno_cmd)] {
            self.bg(
                cmd,
                &format!("{rev}/{n}.pid"),
                &format!("{rev}/{n}.err"),
                self.bound(),
            )?;
        }
        self.wait(
            &format!(
                "grep -q 'listening on' {} && grep -q 'listening on' {}",
                quote(&format!("{rev}/peer.err")),
                quote(&format!("{rev}/eno1.err"))
            ),
            20,
        )?;
        let c1 = self.counters()?;
        let cap_start = epoch();
        self.home(
            &self.peer(&format!(
                "marker --iface lab0 --src {} --dst {MAC}",
                self.pm
            )),
            true,
        )?;
        self.wait(
            &format!(
                "test \"$(tcpdump -nr {} ether proto 0x88b5 2>/dev/null | wc -l)\" -ge 1",
                quote(&format!("{rev}/peer.pcap"))
            ),
            15,
        )?;
        if kind == "foreign" {
            let sport = arg_value(argv, "--source-port")
                .unwrap_or("40000")
                .split('-')
                .next()
                .unwrap_or("40000");
            self.bg(&self.peer(&format!("inject --iface lab0 --peer-mac {} --guest-mac {MAC} --src-ip 198.18.0.1 --sport {sport} --silent 8099 --out {} --wait-first 120 --duration 2.0",self.pm,quote(&format!("{rev}/injector.json")))),&format!("{rev}/inject.pid"),&format!("{rev}/inject.err"),INJECT_BOUND_S)?;
            self.exec.pause(Duration::from_millis(500));
        }
        let flood = kind == "rxloss" || (kind == "stop" && item["scenario"] == "load");
        if flood {
            self.bg(
                &self.peer(&format!(
                    "flood --guest-mac {MAC} --pps {} --size 60 --duration 40 --out {}",
                    if kind == "rxloss" { 20000 } else { 10000 },
                    quote(&format!("{rev}/flood.json"))
                )),
                &format!("{rev}/flood.pid"),
                &format!("{rev}/flood.err"),
                FLOOD_BOUND_S,
            )?;
            self.exec.pause(Duration::from_millis(1500));
        }
        if kind == "linkloss" {
            self.bg(&self.peer(&format!("linkloss --guest-mac {MAC} --sock {} --down-after 2.0 --hold-max 40 --stop-file {} --out {}",quote(&self.qmp),quote(&format!("{rev}/linkloss.stop")),quote(&format!("{rev}/linkloss.json")))),&format!("{rev}/linkloss.pid"),&format!("{rev}/linkloss.err"),LINKLOSS_BOUND_S)?;
            self.exec.pause(Duration::from_millis(500));
        }
        let gstart = epoch();
        let gout = self.runner(ev, tag, argv, false, kind == "perm_restricted")?;
        let gend = epoch();
        let mut meta = json!({"tag":tag,"kind":kind,"argv_file":"argv.json","invocation_nonce":invocation_nonce(&self.run_id,tag),"guest_started_utc":gstart,"guest_finished_utc":gend,"guest_ssh_rc":0,"capture_started_utc":cap_start});
        if matches!(kind, "linkloss" | "rxloss")
            && let Some(cp) = arg_value(argv, "--checkpoint-out")
        {
            meta["checkpoint_file_exists"] = json!(
                self.guest(&format!("cmd /c if exist {} echo yes", cmdquote(cp)?), true)?
                    .stdout
                    .contains("yes")
            );
        }
        if kind == "perm_restricted" {
            meta["restricted_via"] = json!("runas /trustlevel:0x20000 (windows_wire_runas.cmd)");
        }
        if flood {
            self.stop(&format!("{rev}/flood.pid"), "TERM");
            self.exited(&format!("{rev}/flood.pid"), 20);
        }
        if kind == "linkloss" {
            self.home(
                &format!("touch -- {}", quote(&format!("{rev}/linkloss.stop"))),
                true,
            )?;
            if !self.exited(&format!("{rev}/linkloss.pid"), 30) {
                return Err("link restore process failed to exit".into());
            }
            let start = Instant::now();
            loop {
                if self.status(ev, "status-link-restored.json")?["raw_run_allowed"] == true {
                    break;
                }
                if start.elapsed() > Duration::from_secs(60) {
                    return Err("link did not restore".into());
                }
                self.exec.pause(Duration::from_secs(1));
            }
        }
        self.stop(&lis, "TERM");
        if kind == "foreign" {
            self.exited(&format!("{rev}/inject.pid"), 15);
        }
        let quiet = wait_quiet(|| self.counters(), 1.5, 0.5, 40.0)?;
        self.home(
            &self.peer(&format!(
                "marker --iface lab0 --src {} --dst {MAC} --payload WIRELAB-END",
                self.pm
            )),
            true,
        )?;
        let end_seen=self.wait(&format!("test \"$(tcpdump -nr {} -A ether proto 0x88b5 2>/dev/null | grep -c WIRELAB-END)\" -ge 3",quote(&format!("{rev}/peer.pcap"))),15).is_ok();
        meta["end_marker_seen"] = json!(end_seen);
        let c2 = self.counters()?;
        for n in ["peer", "eno1"] {
            self.stop(&format!("{rev}/{n}.pid"), "INT");
        }
        let ep = self.exited(&format!("{rev}/peer.pid"), 20);
        let ee = self.exited(&format!("{rev}/eno1.pid"), 20);
        let drops1 = (self.interface_drops(true)?, self.interface_drops(false)?);
        meta["capture_stopped_utc"] = json!(epoch());
        let hs = self
            .home(
                &format!(
                    "cd {} && sha256sum peer.pcap eno1.pcap && stat -c '%n %s' peer.pcap eno1.pcap",
                    quote(rev)
                ),
                true,
            )?
            .stdout;
        fs::write(ev.join("pcap-hashes-on-home-pc.txt"), &hs).map_err(|e| e.to_string())?;
        let mut sums = BTreeMap::<String, Value>::new();
        for l in hs.lines() {
            let p = l.split_whitespace().collect::<Vec<_>>();
            if p.len() != 2 {
                continue;
            }
            if p[0].len() == 64 {
                sums.insert(p[1].into(), json!({"sha256":p[0]}));
            } else if let Some(v) = sums.get_mut(p[0]) {
                v["size"] = json!(p[1].parse::<u64>().map_err(|e| e.to_string())?);
            }
        }
        for n in [
            "peer.pcap",
            "eno1.pcap",
            "peer.err",
            "eno1.err",
            "listener.err",
            "inject.err",
            "injector.json",
            "flood.json",
            "flood.err",
            "linkloss.json",
            "linkloss.err",
        ] {
            self.transfer(
                false,
                false,
                &ev.join(n),
                &format!("{rev}/{n}"),
                matches!(n, "peer.pcap" | "eno1.pcap" | "peer.err" | "eno1.err"),
            )?;
        }
        for n in [
            "stdout.txt",
            "stderr.txt",
            "exit.txt",
            "runner.json",
            "nic.json",
            "runner.log",
            "runner.rc",
        ] {
            self.transfer(
                true,
                false,
                &ev.join(format!("guest-{n}")),
                &if matches!(n, "runner.log" | "runner.rc") {
                    format!("{gout}.{n}")
                } else {
                    format!("{gout}\\{n}")
                },
                matches!(
                    n,
                    "stdout.txt" | "stderr.txt" | "exit.txt" | "runner.json" | "nic.json"
                ),
            )?;
        }
        let post = self.status(ev, "status-post.json")?;
        let so = fs::read_to_string(ev.join("guest-stdout.txt")).map_err(|e| e.to_string())?;
        if let Some(line) = so
            .trim_start_matches('\u{feff}')
            .lines()
            .rev()
            .find(|l| l.starts_with('{'))
        {
            write_json(
                ev.join("run.json"),
                &serde_json::from_str(line).map_err(|e| e.to_string())?,
            )?;
        }
        let runner = read_json(ev.join("guest-runner.json"))?;
        meta["exe_sha256"] = runner["exe_sha256"].clone();
        meta["guest_times"] = runner["times"].clone();
        meta["guest_verify_exit"] = json!(verify_exit);
        meta["guest_exit"] = json!(
            fs::read_to_string(ev.join("guest-exit.txt"))
                .map_err(|e| e.to_string())?
                .trim_start_matches('\u{feff}')
                .trim()
                .parse::<i32>()
                .map_err(|e| e.to_string())?
        );
        fs::rename(ev.join("guest-nic.json"), ev.join("nic.json")).map_err(|e| e.to_string())?;
        let mut cap = json!({"capture_schema":CAPTURE_SCHEMA,"quiet":{"reached":quiet,"quiet_s":if quiet{1.5}else{0.0}},"status_post_raw_run_allowed":post["raw_run_allowed"]});
        for (n, cmd, exited, filt) in [
            ("peer", &peer_cmd, ep, "(none: every frame on lab0)"),
            ("eno1", &eno_cmd, ee, filter.as_str()),
        ] {
            let stats = parse_tcpdump(
                &fs::read_to_string(ev.join(format!("{n}.err"))).map_err(|e| e.to_string())?,
            );
            let file = format!("{n}.pcap");
            let mut record = sums
                .get(&file)
                .cloned()
                .ok_or("missing remote capture hash")?;
            if hash(ev.join(&file))? != record["sha256"].as_str().unwrap_or("") {
                return Err("capture transfer hash mismatch".into());
            }
            record["frames"] = json!(
                crate::pcap::read_pcap_records(
                    &fs::read(ev.join(&file)).map_err(|e| e.to_string())?
                )
                .ok()
                .map(|(_, r)| r.len())
            );
            let mut tc = stats.clone();
            tc.as_object_mut()
                .ok_or("counter object")?
                .remove("listening");
            cap[n] = json!({"filter":filt,"cmd":cmd.split_whitespace().collect::<Vec<_>>(),"exited":exited,"listening":stats["listening"],"tcpdump":tc,"pcap":record});
        }
        cap["peer"]["counters"] = json!({"rx_before":c0.0,"tx_before":c0.1,"rx_ready":c1.0,"tx_ready":c1.1,"rx_end":c2.0,"tx_end":c2.1});
        cap["peer"]["interface_drop_delta"] = json!(drops1.0.checked_sub(drops0.0));
        cap["eno1"]["interface_drop_delta"] = json!(drops1.1.checked_sub(drops0.1));
        write_json(ev.join("capture.json"), &cap)?;
        write_json(ev.join("meta.json"), &meta)?;
        let mut artifact_hashes = serde_json::Map::new();
        for file in [
            "argv.json",
            "run.json",
            "guest-runner.json",
            "guest-verify.json",
            "guest-verify-stdout.txt",
            "guest-verify-stderr.txt",
        ] {
            artifact_hashes.insert(file.into(), json!(hash(ev.join(file))?));
        }
        write_json(
            ev.join("run-artifacts.json"),
            &json!({"invocation_nonce":meta["invocation_nonce"],"files":artifact_hashes}),
        )?;
        if kind == "pause" {
            self.transfer(
                true,
                false,
                &ev.join("checkpoint.bin"),
                &self.cp(item["n"].as_u64().ok_or("pause n missing")?),
                true,
            )?;
        }
        eno1_interlock(&cap)
    }
    /// Dead-man bound of the listener and both captures: twice the worst-case seconds one run keeps them
    /// alive (see [`capture_expected_s`]). A dead orchestrator leaves nothing running past this bound.
    fn bound(&self) -> u64 {
        2 * capture_expected_s(self.timeout)
    }
}
/// Live isolation interlock: any lab frame on the user's LAN interface, or an eno1 capture
/// that cannot be read back, aborts the suite before another raw run starts.
pub(crate) fn eno1_interlock(cap: &Value) -> Result<(), String> {
    match cap["eno1"]["pcap"]["frames"].as_u64() {
        Some(0) => Ok(()),
        Some(n) => Err(format!(
            "eno1 interlock: {n} lab frame(s) captured on the host LAN interface; no further raw run"
        )),
        None => Err(
            "eno1 interlock: the eno1 capture is unreadable, so LAN isolation is unproven; no further raw run"
                .into(),
        ),
    }
}
/// Remote scratch removal: only the exact, symlink-free run directory this suite created.
pub(crate) fn remove_scratch_command(rev: &str) -> String {
    format!(
        "if test -e {p} || test -L {p}; then test \"$(readlink -f -- {p})\" = {p} && test ! -L {p} && rm -rf -- {p}; fi",
        p = quote(rev)
    )
}
fn cmdquote(s: &str) -> Result<String, String> {
    if s.chars().any(|c| "\"%\r\n!&|<>^".contains(c)) {
        return Err("unsafe Windows command path".into());
    }
    Ok(format!("\"{s}\""))
}
pub(crate) fn arg_value<'a>(a: &'a [String], k: &str) -> Option<&'a str> {
    a.iter()
        .position(|x| x == k)
        .and_then(|i| a.get(i + 1))
        .map(String::as_str)
}
/// Time source of [`wait_quiet_with`]; tests drive it with virtual time.
pub(crate) trait Clock {
    fn now(&self) -> f64;
    fn sleep(&self, secs: f64);
    fn stopped(&self) -> bool;
}
/// Wall-clock [`Clock`]. `interruptible` clocks report the process stop flag; a witness that is
/// already finalising after a stop request must not abort its own quiescence wait, so it uses
/// an uninterruptible one.
pub(crate) struct RealClock {
    start: Instant,
    interruptible: bool,
}
impl RealClock {
    pub(crate) fn new() -> Self {
        Self {
            start: Instant::now(),
            interruptible: true,
        }
    }
    pub(crate) fn uninterruptible() -> Self {
        Self {
            start: Instant::now(),
            interruptible: false,
        }
    }
}
impl Clock for RealClock {
    fn now(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }
    fn sleep(&self, secs: f64) {
        thread::sleep(Duration::from_secs_f64(secs));
    }
    fn stopped(&self) -> bool {
        self.interruptible && rmasscan_net::lab_io::stop_requested()
    }
}
pub(crate) fn wait_quiet<T: PartialEq>(
    read: impl FnMut() -> Result<T, String>,
    quiet: f64,
    poll: f64,
    timeout: f64,
) -> Result<bool, String> {
    wait_quiet_with(read, quiet, poll, timeout, &RealClock::new())
}
/// Block until `read()` was unchanged for `quiet` seconds: true once quiet, false at `timeout`.
/// The quiet period starts at the first sample, so the elapsed-quiet arithmetic needs no `None`.
pub(crate) fn wait_quiet_with<T: PartialEq>(
    mut read: impl FnMut() -> Result<T, String>,
    quiet: f64,
    poll: f64,
    timeout: f64,
    clock: &dyn Clock,
) -> Result<bool, String> {
    let start = clock.now();
    let mut prev = None;
    let mut since = clock.now();
    while clock.now() - start < timeout {
        if clock.stopped() {
            return Err("suite interrupted".into());
        }
        clock.sleep(poll);
        let cur = read()?;
        if prev.as_ref() != Some(&cur) {
            prev = Some(cur);
            since = clock.now();
        } else if clock.now() - since >= quiet {
            return Ok(true);
        }
    }
    Ok(false)
}
pub(crate) fn mutate_checkpoint(variant: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() != 120 {
        return Err("checkpoint must have exact 120-byte layout".into());
    }
    let mut d = data.to_vec();
    match variant {
        "wrong_ports" | "wrong_seed" => {}
        "corrupt_next_index" => d[87] ^= 1,
        "corrupt_checksum" => d[119] ^= 255,
        "truncated" => d.truncate(60),
        "empty" => d.clear(),
        "future_format" | "future_engine" => {
            let o = if variant == "future_format" { 8 } else { 12 };
            d[o..o + 4].copy_from_slice(&99u32.to_be_bytes());
            let digest = Sha256::digest(&d[..88]);
            d[88..].copy_from_slice(&digest);
        }
        _ => return Err("unknown checkpoint mutation".into()),
    }
    Ok(d)
}
/// Entry point of `windows-suite`. NOT RUN refusals (exit 2) are returned as errors; once a
/// run has begun or a directory is unusable the distinct exit codes 10/11/12 are returned.
pub fn run(args: &[String]) -> Result<i32, String> {
    match run_with(args, &Real) {
        Ok(code) => Ok(code),
        Err(SuiteError::NotRun(m)) => Err(m),
        Err(e) => {
            let label = match e {
                SuiteError::Abort(_) => "ABORT",
                SuiteError::RerunRefused(_) => "RERUN REFUSED",
                _ => "SCHEMA TOO OLD",
            };
            eprintln!("{label}: {}", e.message());
            Ok(e.code())
        }
    }
}
fn home_cmd(exec: &dyn Exec, cmd: &str, check: bool) -> Result<Output, String> {
    let argv = strings(&[
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
        "home-pc",
        cmd,
    ]);
    checked(exec.exec(&argv, 180)?, "ssh", check)
}
fn remote_home(exec: &dyn Exec) -> Result<String, String> {
    // The physical path: the scratch removal compares `readlink -f` with the path it was given, which
    // fails for a home reached through a symlink (macOS /var, /home -> /data/home, ...).
    let home = home_cmd(exec, "cd \"$HOME\" && printf '%s' \"$(pwd -P)\"", true)?.stdout;
    if !home.starts_with('/') || home.contains('\n') {
        return Err("invalid remote home".into());
    }
    Ok(home)
}
/// Stop every pidfile-recorded remote process (pid + start time must match), then remove the
/// suite's scratch directory. Used by `--cleanup` and at suite start, so a dead orchestrator
/// never blocks the next one.
fn sweep_remote(exec: &dyn Exec, suite: &str) -> Result<(), String> {
    if !safe_id(suite) {
        return Err("--suite must be a safe identifier".into());
    }
    let ev = format!("{}/winvm/t4-ev", remote_home(exec)?);
    // A first-ever start (or --cleanup) must not end NOT RUN because the evidence root is absent.
    home_cmd(exec, &format!("mkdir -p -- {}", quote(&ev)), true)?;
    home_cmd(exec, &sweep_command(&ev, "TERM"), false)?;
    exec.pause(Duration::from_secs(3));
    home_cmd(exec, &sweep_command(&ev, "KILL"), false)?;
    home_cmd(
        exec,
        &remove_scratch_command(&format!("{ev}/{suite}")),
        true,
    )?;
    Ok(())
}
pub(crate) fn run_with(args: &[String], exec: &dyn Exec) -> Result<i32, SuiteError> {
    let o = options(args)?;
    if o.contains_key("help") {
        println!(
            "windows-suite --out DIR --commit SHA --guest-exe PATH --fixtures DIR --remote-lab /absolute/linux/rmasscan-lab --deploy-manifest FILE [--repo DIR] [--suite ID] [--plan functional|failure|perf] [--only TAG ...] [--rerun] [--list]\nwindows-suite --cleanup [--suite ID]   stop every recorded remote process, remove the suite scratch directory\nExit codes: 0 done, 1 reserved, 2 NOT RUN (refused before any remote change), 10 aborted, 11 rerun refused, 12 directory capture schema too old"
        );
        return Ok(0);
    }
    let plan = opt(&o, "plan", "functional");
    if !matches!(plan.as_str(), "functional" | "failure" | "perf") {
        return Err("unknown suite plan".to_string().into());
    }
    let items = crate::verify::planned(&json!({"plan":plan}));
    if o.contains_key("list") {
        for i in items {
            println!(
                "{} {}",
                i["tag"].as_str().unwrap_or(""),
                i["kind"].as_str().unwrap_or("")
            );
        }
        return Ok(0);
    }
    let suite = opt(&o, "suite", "functional");
    if plan == "perf" && !o.contains_key("suite") {
        return Err(SuiteError::NotRun(
            "--plan perf needs an explicit --suite ID (for example perf-r1): the default would reuse the functional suite id"
                .into(),
        ));
    }
    if !safe_id(&suite) {
        return Err("--suite must be a safe identifier".to_string().into());
    }
    if o.contains_key("cleanup") {
        sweep_remote(exec, &suite)?;
        println!("remote processes stopped and scratch directory removed for suite {suite}");
        return Ok(0);
    }
    let out = PathBuf::from(required(&o, "out")?);
    let commit = required(&o, "commit")?;
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("--commit requires full SHA".to_string().into());
    }
    let remote = required(&o, "remote-lab")?;
    if !remote.starts_with('/') || remote.contains('\n') {
        return Err("--remote-lab must be absolute Linux binary path"
            .to_string()
            .into());
    }
    let guest_exe = required(&o, "guest-exe")?;
    cmdquote(&guest_exe)?;
    let deploy_path = PathBuf::from(required(&o, "deploy-manifest")?);
    let deploy = read_json(&deploy_path)?;
    let allowed = crate::deploy::allowed_binary_hashes(&deploy, &commit, &remote)?;
    let fixtures = PathBuf::from(required(&o, "fixtures")?);
    let fx = read_json(fixtures.join("manifest.json"))?;
    if fx["all_valid"] != true {
        return Err("oracle fixtures are not all valid".to_string().into());
    }
    let only = o.get("only").cloned().unwrap_or_default();
    for tag in &only {
        if !safe_id(tag) || !items.iter().any(|i| i["tag"] == *tag) {
            return Err(format!("unknown/unsafe tag {tag}").into());
        }
    }
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let old = read_json(out.join("manifest.json")).ok();
    if old
        .as_ref()
        .is_some_and(|m| m["code_commit"] != commit || m["plan"] != plan || m["suite"] != suite)
    {
        return Err("existing manifest identity differs".to_string().into());
    }
    if old.as_ref().is_some_and(schema_too_old) {
        return Err(SuiteError::SchemaTooOld(format!(
            "use a new directory: capture schema is older than {CAPTURE_SCHEMA}"
        )));
    }
    let mut moves = vec![];
    if o.contains_key("rerun") {
        if only.is_empty() {
            return Err("--rerun requires explicit --only tags".to_string().into());
        }
        for tag in &only {
            let p = out.join("runs").join(tag);
            if p.exists() {
                let (v, b) = crate::verify::run_status(&out, tag);
                if !may_discard(&v, b) {
                    return Err(SuiteError::RerunRefused(format!(
                        "cannot discard {tag}: {v}, behaviour failure={b}"
                    )));
                }
                moves.push(p);
            }
        }
    }
    // Local, before any remote action: the guest scripts of the commit under test, kept as
    // evidence next to the deploy manifest that vouches for the remote binary.
    let repo = PathBuf::from(opt(&o, "repo", "."));
    // Which build of this tool orchestrates the run (it is also the verifier of its evidence).
    let orchestrator = crate::provenance::collect(&repo);
    if let Some(why) = crate::provenance::problem(&orchestrator) {
        return Err(SuiteError::NotRun(format!(
            "cannot establish the orchestrator build provenance ({why}); run from the work tree of the commit under test or pass --repo: {orchestrator}"
        )));
    }
    let staged = crate::deploy::StagedScripts::load(|p| exec.file_at_commit(&repo, &commit, p))?;
    let deploy_dir = out.join("deploy");
    staged.write_to(&deploy_dir.join("guest-scripts"))?;
    fs::copy(&deploy_path, deploy_dir.join("deploy-manifest.json")).map_err(|e| e.to_string())?;
    let mut s = Suite {
        exec,
        out,
        suite,
        run_id: nonce(),
        remote,
        remote_ev: String::new(),
        qmp: String::new(),
        manifest: String::new(),
        guest_exe,
        plan,
        timeout: opt(&o, "run-timeout", "240")
            .parse()
            .map_err(|_| "bad run timeout".to_string())?,
        pm: String::new(),
    };
    let home = remote_home(exec)?;
    s.remote_ev = format!("{home}/winvm/t4-ev");
    s.qmp = format!("{home}/winvm/qmp.sock");
    s.manifest = format!("{home}/winvm/lab/n2.json");
    // The binary about to run as root must be the one the deploy manifest vouches for.
    let remote_sum = s.home(&format!("sha256sum -- {}", quote(&s.remote)), false)?;
    if remote_sum.rc != 0 {
        return Err(format!(
            "cannot hash the remote rmasscan-lab: {}",
            remote_sum.stderr.trim()
        )
        .into());
    }
    let remote_sha = crate::deploy::parse_sha256sum(&remote_sum.stdout)?;
    crate::deploy::check_remote_binary(&allowed, &remote_sha)?;
    // Nothing from a dead earlier orchestrator may still be running when this one starts.
    sweep_remote(exec, &s.suite)?;
    s.home(
        &format!(
            "test -x {} && mkdir -p -- {}",
            quote(&s.remote),
            quote(&s.remote_ev)
        ),
        true,
    )?;
    s.pm = s
        .home(
            "sudo -n ip netns exec wvp-n2 cat /sys/class/net/lab0/address",
            true,
        )?
        .stdout
        .trim()
        .into();
    if !valid_mac(&s.pm) {
        return Err("invalid peer MAC".to_string().into());
    }
    let stage = deploy_dir.join("guest-scripts");
    for (name, guest, _, _) in &staged.files {
        s.transfer(true, true, &stage.join(name), guest, true)?;
    }
    // What sits on the guest is what the commit contains, byte for byte.
    for (name, guest, bytes, sha) in &staged.files {
        let abs = format!("C:\\Users\\lab\\{}", guest.replace('/', "\\"));
        let reply = s
            .guest(
                &format!(
                    "pwsh -NoProfile -File {GUEST}\\windows_wire_hash.ps1 -Path {}",
                    cmdquote(&abs)?
                ),
                true,
            )?
            .stdout;
        let seen = reply.split_whitespace().collect::<Vec<_>>();
        if seen.len() != 2 || seen[0] != sha || seen[1] != bytes.len().to_string() {
            return Err(
                format!("guest copy of {name} does not match the commit: {reply:?}").into(),
            );
        }
    }
    // record-guest rejects a Verify report outside +5/-60 s of the home-pc clock.
    let home_clock = |s: &Suite| -> Result<f64, String> {
        crate::deploy::parse_epoch(&s.home("date -u +%s.%N", true)?.stdout)
    };
    let before = home_clock(&s)?;
    let guest_clock = crate::deploy::parse_epoch(
        &s.guest(
            &format!("pwsh -NoProfile -File {GUEST}\\windows_wire_clock.ps1"),
            true,
        )?
        .stdout,
    )?;
    let after = home_clock(&s)?;
    let clock = crate::deploy::clock_verdict(before, guest_clock, after)?;
    write_json(
        deploy_dir.join(format!("preflight-{}.json", s.run_id)),
        &json!({
            "run_id": s.run_id, "suite": s.suite, "commit": commit,
            "deploy_manifest_sha256": hash(&deploy_path)?,
            "remote_lab": {"path": s.remote, "sha256": remote_sha},
            "guest_scripts": staged.record(),
            "orchestrator": orchestrator,
            "clock": {"guest_minus_home_s": clock.offset, "uncertainty_s": clock.uncertainty,
                      "limits": {"guest_ahead_s": crate::vm_lab::VERIFY_FUTURE_SKEW_S, "guest_behind_s": crate::vm_lab::VERIFY_MAX_AGE_S}},
            "checked_utc": epoch(),
        }),
    )?;
    s.guest(
        &format!(
            "pwsh -NoProfile -File {GUEST}\\windows_wire_prepare.ps1 -Suite {} -RunId {}",
            cmdquote(&s.suite)?,
            cmdquote(&s.run_id)?
        ),
        true,
    )?;
    for p in moves {
        let dst = s.out.join("runs_discarded");
        fs::create_dir_all(&dst).map_err(|e| e.to_string())?;
        let leaf = p.file_name().ok_or("run filename")?.to_string_lossy();
        fs::rename(&p, dst.join(format!("{leaf}.{}", s.run_id))).map_err(|e| e.to_string())?;
    }
    let man = if let Some(old) = old {
        if old["code_commit"] != commit || old["plan"] != s.plan || old["suite"] != s.suite {
            return Err("existing manifest identity differs".to_string().into());
        }
        old
    } else {
        let eh = s
            .guest(
                &format!(
                    "pwsh -NoProfile -File {GUEST}\\windows_wire_hash.ps1 -Path {}",
                    cmdquote(&s.guest_exe)?
                ),
                true,
            )?
            .stdout;
        let eh = eh.split_whitespace().collect::<Vec<_>>();
        if eh.len() != 2 {
            return Err("invalid executable hash response".to_string().into());
        }
        let mut man = json!({"schema":1,"capture_schema":CAPTURE_SCHEMA,"suite":s.suite,"code_commit":commit,"exe":{"sha256":eh[0],"size":eh[1].parse::<u64>().map_err(|e|e.to_string())?,"guest_path":s.guest_exe,"build":"Rust static CRT wire_scan from code_commit"},"binding":{"iface":IFACE,"src_ip":"198.18.0.1","src_mac":MAC,"router_mac":s.pm,"peer_ip":"198.18.0.2","seed":1,"rate":100,"wait":3},"stand":{"run_id":"n2","netns":"wvp-n2","manifest":s.manifest},"listeners":{"open":[80,443,8000,8001,8002,8003,8004,8005,8006,8007],"silent":if s.plan=="failure"{(vec![8099]).into_iter().chain(8100..8120).collect::<Vec<_>>()}else{vec![8099]}},"plan":s.plan,"pause":{"case":"c03_multi_ports","n":[0,1,8,15]},"oracle":fx["oracle"],"orchestrator":orchestrator,"created_utc":epoch()});
        if s.plan == "perf" {
            man["perf"] = json!({"rates":crate::verify::PERF_RATES,"reps":crate::verify::PERF_REPS,"order":"rep-major","target":"198.18.0.2"});
        }
        write_json(s.out.join("manifest.json"), &man)?;
        copy_tree(&fixtures, &s.out.join("fixtures"))?;
        man
    };
    let base_timeout = s.timeout;
    for item in items {
        let tag = item["tag"].as_str().ok_or("planned tag missing")?;
        if !only.is_empty() && !only.iter().any(|t| t == tag) {
            continue;
        }
        if s.plan == "perf" {
            // Guest timeouts and dead-man bounds follow this cell; the operator's value is a floor.
            s.timeout = perf_run_timeout(&item, base_timeout);
        }
        let kind = item["kind"].as_str().unwrap_or("");
        let cp = if matches!(kind, "pause" | "resume") {
            s.cp(item["n"].as_u64().ok_or("pause n")?)
        } else if kind == "complete_nopause" {
            s.cp(16)
        } else if kind == "refuse_completed" {
            s.cp(99)
        } else {
            format!("{GUEST}\\cp\\{}\\{}\\{tag}.bin", s.suite, s.run_id)
        };
        let mut paths = BTreeMap::new();
        paths.insert("--checkpoint-out".into(), cp.clone());
        paths.insert("--resume-checkpoint".into(), cp.clone());
        let argv = crate::verify::expected_args(&item, &man, &paths)?;
        let mut forge = None;
        if matches!(kind, "refuse_completed" | "ckpt_refuse") {
            let mut base_item = item.clone();
            base_item["forge"] = json!(true);
            let mut a = crate::verify::expected_args(&base_item, &man, &paths)?;
            if kind == "ckpt_refuse" {
                let p = a
                    .iter()
                    .position(|v| v == "--checkpoint-out")
                    .ok_or("forge output missing")?;
                a[p + 1] = format!("{cp}.forged");
            }
            forge = Some(a);
        }
        s.one(&item, argv, forge, Some(cp))
            .map_err(SuiteError::Abort)?;
    }
    println!(
        "all planned runs executed; verify offline with rmasscan-lab windows-verify --dir {}",
        s.out.display()
    );
    Ok(0)
}
pub(crate) fn valid_mac(m: &str) -> bool {
    let p = m.split(':').collect::<Vec<_>>();
    p.len() == 6
        && p.iter()
            .all(|v| v.len() == 2 && v.bytes().all(|b| b.is_ascii_hexdigit()))
}
fn scratch_create(root: &str, suite: &str, nonce: &str, tag: &str) -> Result<String, String> {
    if !root.starts_with('/')
        || root.contains("/../")
        || ![suite, nonce, tag].iter().all(|v| safe_id(v))
    {
        return Err("unsafe scratch path".into());
    }
    let mut commands = Vec::new();
    let mut path = root.to_string();
    for part in ["", suite, nonce] {
        if !part.is_empty() {
            path.push('/');
            path.push_str(part);
        }
        commands.push(format!(
            "test ! -L {p} && mkdir -p -- {p} && test \"$(readlink -f -- {p})\" = {p}",
            p = quote(&path)
        ));
    }
    let leaf = format!("{path}/{tag}");
    commands.push(format!(
        "test ! -e {p} && test ! -L {p} && mkdir -- {p}",
        p = quote(&leaf)
    ));
    Ok(commands.join(" && "))
}
fn owned_process_command(pidfile: &str, signal: Option<&str>) -> String {
    owned_process_body(&quote(pidfile), signal)
}
/// `p` is an already shell-quoted word (a quoted path or `"$pidfile"`).
fn owned_process_body(p: &str, signal: Option<&str>) -> String {
    let action = match signal {
        Some("TERM") => "sudo -n kill -TERM -- \"$pid\" 2>/dev/null",
        Some("INT") => "sudo -n kill -INT -- \"$pid\" 2>/dev/null",
        Some("KILL") => {
            // The recorded pid is the `timeout` wrapper, which makes itself the leader of a new
            // process group that holds the tool. SIGKILL cannot be forwarded by the wrapper, so the
            // group is killed first and the wrapper second.
            "sudo -n kill -KILL -- \"-$pid\" 2>/dev/null; sudo -n kill -KILL -- \"$pid\" 2>/dev/null"
        }
        None => "false",
        _ => "false",
    };
    // proc stat's comm field can contain whitespace/parentheses. Strip through
    // its final ')' before selecting starttime (field 20 of the remainder).
    format!(
        "test ! -s {p} || {{ read -r pid born extra < {p}; case \"$pid:$born\" in *[!0-9:]*|:*|*:) exit 1;; esac; test -z \"$extra\" || exit 1; actual=$(sed 's/.*) //' /proc/\"$pid\"/stat 2>/dev/null | awk '{{print $20}}'); if test \"$actual\" != \"$born\"; then exit 0; fi; {action}; }}"
    )
}
/// Signal every process whose pidfile sits under `<ev>/<suite>/<run>/<tag>/`. A pidfile whose
/// recorded start time no longer matches (pid reuse) is skipped, exactly like a single stop.
pub(crate) fn sweep_command(ev: &str, signal: &str) -> String {
    format!(
        "for pidfile in {}/*/*/*/*.pid; do ( {} ); done; true",
        quote(ev),
        owned_process_body("\"$pidfile\"", Some(signal))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quiescence_waits_for_unchanged_counters() {
        let mut reads = 0u32;
        let mut last_change = None;
        let started = Instant::now();
        let quiet = wait_quiet(
            || {
                reads += 1;
                // 1, 2, 3 then constant: the counters last change on the third read.
                let value = reads.min(3);
                if reads <= 3 {
                    last_change = Some(Instant::now());
                }
                Ok(value)
            },
            0.12,
            0.03,
            10.0,
        )
        .unwrap();
        assert!(quiet);
        assert!(
            last_change.unwrap().elapsed().as_secs_f64() >= 0.12,
            "returned before a full quiet period"
        );
        assert!(reads >= 3 + 3, "reads={reads}");
        assert!(started.elapsed().as_secs_f64() < 5.0);
    }
    #[test]
    fn quiescence_times_out_on_endless_traffic_and_propagates_read_errors() {
        let mut n = 0u64;
        let started = Instant::now();
        let quiet = wait_quiet(
            || {
                n += 1;
                Ok(n)
            },
            0.1,
            0.02,
            0.3,
        )
        .unwrap();
        assert!(!quiet);
        assert!(started.elapsed().as_secs_f64() >= 0.3);
        let err = wait_quiet(
            || Err::<u8, _>("counters unreadable".to_string()),
            0.1,
            0.01,
            1.0,
        );
        assert_eq!(err, Err("counters unreadable".into()));
    }
    #[test]
    fn scanner_argv_carries_every_explicit_parameter() {
        let man = json!({"binding":{"iface":IFACE,"src_ip":"198.18.0.1","src_mac":MAC,"router_mac":"02:57:4c:3d:2e:9b","seed":1,"wait":3,"rate":100}});
        let item = crate::verify::planned(&json!({"plan":"functional"}))
            .into_iter()
            .find(|i| i["tag"] == "c04_exclude.run1")
            .unwrap();
        let case = crate::verify::case_by_name("c04_exclude").unwrap();
        let argv = crate::verify::expected_args(&item, &man, &BTreeMap::new()).unwrap();
        assert_eq!(arg_value(&argv, "--exclude"), case["exclude"].as_str());
        assert_eq!(arg_value(&argv, "--src-mac"), Some(MAC));
        assert_eq!(arg_value(&argv, "--router-mac"), Some("02:57:4c:3d:2e:9b"));
        assert_eq!(arg_value(&argv, "--seed"), Some("1"));
        assert_eq!(arg_value(&argv, "--wait"), Some("3"));
        assert_eq!(arg_value(&argv, "--rate"), Some("100"));
        assert_eq!(arg_value(&argv, "--targets"), case["targets"].as_str());
        assert_eq!(arg_value(&argv, "--ports"), case["ports"].as_str());
        assert!(!argv.iter().any(|a| a == "--allow-foreign-source-mac"));
    }
    #[test]
    fn remote_cleanup_matches_pid_starttime_before_signalling() {
        for signal in [Some("TERM"), Some("INT"), None] {
            let cmd = owned_process_command("/tmp/owned-run/listener.pid", signal);
            assert!(cmd.contains("read -r pid born extra"));
            assert!(cmd.contains("/stat"));
            let compare = cmd.find("test \"$actual\" != \"$born\"").unwrap();
            if signal.is_some() {
                assert!(compare < cmd.find("sudo -n kill").unwrap());
            } else {
                assert!(!cmd.contains("kill"));
            }
        }
    }
    #[test]
    fn every_planned_nonce_is_accepted_by_powershell_contract() {
        let root = nonce();
        let mut seen = std::collections::BTreeSet::new();
        for plan in ["functional", "failure"] {
            for item in crate::verify::planned(&json!({"plan":plan})) {
                let n = invocation_nonce(&root, item["tag"].as_str().unwrap());
                assert!((16..=128).contains(&n.len()));
                assert!(
                    n.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                );
                assert!(seen.insert(n));
            }
        }
    }
    #[cfg(unix)]
    #[test]
    fn command_deadline_kills_owned_descendants_and_never_joins_open_pipes() {
        for script in ["sleep 30 & wait", "sleep 30 & exit 0"] {
            let start = Instant::now();
            let out = command(&strings(&["sh", "-c", script]), 1, false).unwrap();
            assert_eq!(out.rc, 124);
            assert!(start.elapsed() < Duration::from_secs(3));
        }
        let out = command(
            &strings(&["sh", "-c", "printf success; printf error >&2"]),
            2,
            true,
        )
        .unwrap();
        assert_eq!(out.stdout, "success");
        assert_eq!(out.stderr, "error");
    }
    #[cfg(unix)]
    #[test]
    fn a_descendant_briefly_holding_stderr_after_exit_is_not_a_timeout() {
        // scp leaves its ProxyJump `ssh -W` helpers holding stderr for a moment
        // after it exits; that drain must not turn a success into rc 124.
        let start = Instant::now();
        let out = command(
            &strings(&["sh", "-c", "(sleep 0.6 >/dev/null) & printf ok"]),
            10,
            true,
        )
        .unwrap();
        assert_eq!(out.rc, 0);
        assert_eq!(out.stdout, "ok");
        assert!(start.elapsed() >= Duration::from_millis(500));
        assert!(start.elapsed() < Duration::from_secs(3));
    }
    #[cfg(unix)]
    #[test]
    fn a_descendant_holding_stderr_for_ten_seconds_is_cut_at_the_five_second_drain_ceiling() {
        // The shared drain window is capped at 5 s: a descendant that keeps stderr open far longer turns
        // into rc 124 after about that long, not after its own 10 s and not after the 30 s deadline.
        let start = Instant::now();
        let out = command(
            &strings(&["sh", "-c", "(sleep 10 >/dev/null) & printf ok"]),
            30,
            false,
        )
        .unwrap();
        let took = start.elapsed();
        assert_eq!(out.rc, 124);
        assert!(
            took >= Duration::from_millis(4500) && took <= Duration::from_secs(7),
            "{took:?}"
        );
    }
    #[test]
    fn failed_verify_never_calls_fetch_even_with_successful_old_report() {
        let fetched = std::cell::Cell::new(false);
        let r = invoke_fresh_report(
            "new-run",
            || {
                Ok(Output {
                    rc: 1,
                    stdout: String::new(),
                    stderr: "Verify failed".into(),
                })
            },
            || {
                fetched.set(true);
                Ok(json!({"verification_nonce":"old-run","ok":true}))
            },
        );
        assert!(r.is_err());
        assert!(!fetched.get());
        assert!(
            invoke_fresh_report(
                "new-run",
                || Ok(Output {
                    rc: 0,
                    stdout: String::new(),
                    stderr: String::new()
                }),
                || Ok(json!({"verification_nonce":"old-run","ok":true}))
            )
            .is_err()
        );
    }
    #[test]
    fn scratch_creation_never_deletes_and_checks_symlink_containment() {
        let cmd = scratch_create("/home/lab/winvm/t4-ev", "suite", "nonce", "tag").unwrap();
        assert!(!cmd.contains("rm "));
        assert!(cmd.contains("readlink -f"));
        assert!(cmd.contains("test ! -L"));
        assert!(scratch_create("/tmp/../etc", "suite", "nonce", "tag").is_err());
        assert!(scratch_create("/tmp/lab", "../escape", "nonce", "tag").is_err());
        assert_eq!(quote("a'b"), "'a'\"'\"'b'");
    }
    #[test]
    fn windows_shell_paths_refuse_expansion_and_command_tokens() {
        for p in ["C:\\x%PATH%", "C:\\x&whoami", "C:\\x\"", "C:\\x\n"] {
            assert!(cmdquote(p).is_err());
        }
        assert_eq!(
            cmdquote("C:\\Program Files\\wire_scan.exe").unwrap(),
            "\"C:\\Program Files\\wire_scan.exe\""
        );
    }
    #[test]
    fn checkpoint_mutations_preserve_layout_and_reseal_only_versions() {
        let mut raw = vec![0u8; 120];
        raw[88..].copy_from_slice(&Sha256::digest([0u8; 88]));
        for v in ["wrong_ports", "wrong_seed"] {
            assert_eq!(mutate_checkpoint(v, &raw).unwrap(), raw);
        }
        for v in ["corrupt_next_index", "corrupt_checksum"] {
            let changed = mutate_checkpoint(v, &raw).unwrap();
            assert_ne!(&changed[88..], Sha256::digest(&changed[..88]).as_slice());
        }
        assert_eq!(mutate_checkpoint("truncated", &raw).unwrap().len(), 60);
        assert!(mutate_checkpoint("empty", &raw).unwrap().is_empty());
        for (v, at) in [("future_format", 8), ("future_engine", 12)] {
            let changed = mutate_checkpoint(v, &raw).unwrap();
            assert_eq!(&changed[at..at + 4], 99u32.to_be_bytes());
            assert_eq!(&changed[88..], Sha256::digest(&changed[..88]).as_slice());
        }
        assert!(mutate_checkpoint("empty", &[0; 60]).is_err());
    }
    #[test]
    fn every_planned_kind_has_explicit_scanner_argv_and_forge_contract() {
        let man = json!({"binding":{"iface":IFACE,"src_ip":"198.18.0.1","src_mac":MAC,"router_mac":"02:57:4c:3d:2e:9b"}});
        let paths = BTreeMap::from([
            ("--checkpoint-out".into(), "C:\\new\\out.bin".into()),
            ("--resume-checkpoint".into(), "C:\\new\\in.bin".into()),
        ]);
        for plan in ["functional", "failure"] {
            for mut item in crate::verify::planned(&json!({"plan":plan})) {
                let argv = crate::verify::expected_args(&item, &man, &paths).unwrap();
                assert!(!argv.iter().any(|a| a.contains(concat!("py", "thon"))));
                if !(item["kind"] == "perm_restricted" && item["variant"] == "inventory") {
                    assert_eq!(arg_value(&argv, "--iface"), Some(IFACE));
                    assert_eq!(arg_value(&argv, "--src-ip"), Some("198.18.0.1"));
                }
                if item["kind"] == "ckpt_refuse" || item["kind"] == "refuse_completed" {
                    item["forge"] = json!(true);
                    let forge = crate::verify::expected_args(&item, &man, &paths).unwrap();
                    assert!(arg_value(&forge, "--forge-checkpoint-next-index").is_some());
                    assert_eq!(arg_value(&forge, "--ports"), Some("8000-8015"));
                    assert_eq!(arg_value(&forge, "--seed"), Some("1"));
                }
            }
        }
    }
    #[test]
    fn scratch_cannot_escape_or_inject() {
        for s in ["../x", "a/b", "", "x;touch /tmp/x", "x'", ".", "-x"] {
            assert!(!safe_id(s));
        }
        assert!(safe_id("functional-r1_smoke"));
    }
    #[test]
    fn reports_bound_to_invocation_and_failure_never_fetches() {
        let a = fresh_report("functional", "c01", "nonce1").unwrap();
        let b = fresh_report("functional", "c01", "nonce2").unwrap();
        assert_ne!(a, b);
        assert!(gate_fetch_allowed(1, "nonce1", "nonce1").is_err());
        assert!(gate_fetch_allowed(0, "nonce1", "nonce2").is_err());
        assert!(gate_fetch_allowed(0, "nonce1", "nonce1").is_ok());
    }
    #[test]
    fn evidence_rerun_policy_preserves_failures() {
        assert!(may_discard("INVALID", false));
        assert!(may_discard("NOT RUN", false));
        for (v, b) in [("PASS", false), ("FAIL", false), ("INVALID", true)] {
            assert!(!may_discard(v, b));
        }
    }
    #[test]
    fn unknown_counters_stay_unknown() {
        assert_eq!(
            parse_tcpdump("listening on lab0")["captured"],
            serde_json::Value::Null
        );
        assert_eq!(
            parse_tcpdump(
                "1 packet captured\n2 packets received by filter\n0 packets dropped by kernel"
            )["received"],
            2
        );
    }
}
#[cfg(test)]
#[path = "windows_suite_tests.rs"]
mod suite_tests;
