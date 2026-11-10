//! `protocols-suite linux`: the live runs of the protocols acceptance (design §6.2) on the sealed Linux netns stand that
//! `wire-lab.sh --suite protocols` raises: the autodetect stand with `net.ipv4.icmp_ratemask = 0` in the peer
//! namespace. Every planned case of the verifier's table (`protocols_verify::steps`; no case is defined here) becomes
//! one `runs/<tag>/` directory that `protocols-verify` judges offline: `expect.json`, `peer-stack.json`,
//! `isolation.json`, `isolation-post.json`, `hashes-before-copy.txt`, and per step `argv.json`, the scanner's
//! `stdout.txt stderr.txt exit.txt`, its document under the table's neutral name (`output.txt`, `output.json`,
//! `output.bin`), the peer witness `peer.pcap capture.json peer.err`, and `responder.json`: whether the step's
//! responder still ran when the scanner ended, with its stderr (a responder that died mid-step is named in the
//! verdict; one that never became ready is named in the NOT RUN reason).
//!
//! The driver is the other Linux suites' ([`Linux`]): the namespaces, the seal before and after each case, the
//! witness, the oracle under a masked `/etc/masscan`, the evidence copy with its hashes, the aborted runs under
//! `runs_aborted/`, `--out`, `--work` and the account scrubbed from every record. Each step runs in a working directory
//! of its own; commands are argument arrays with absolute paths, the shell runs one constant script
//! ([`IN_DIR_SCRIPT`]); every target is in 198.18.0.0/24.
//!
//! The peer: `capture responder` with [`pv::responder_args`] (TCP listeners, one UDP socket per peer address and open
//! port, the SCTP answers on the peer link), restarted for every step so that nothing of an earlier scan answers into
//! the next. Before anything starts the suite reads the peer stack in the peer namespace ([`peer_stack`]: the two ICMP
//! sysctls and whether the host kernel has SCTP) and refuses every selected case it cannot answer the stand's way as
//! NOT RUN (an SCTP case on a host whose kernel has SCTP: the kernel would answer every INIT beside the responder; a
//! peer namespace that rate-limits ICMP errors). Each case records the stack it ran on in `peer-stack.json`. The suite
//! never loads a kernel module and never opens an SCTP socket.
use crate::{
    autodetect_suite::{
        self as ad, Linux, LinuxHost, LinuxTools, RESPONDER_POLLS, SH, addresses_outside_the_lab,
        io, not_run, p2s, say, write_exit, write_record,
    },
    autodetect_verify::{ArgvRecord, CAPTURE_JSON},
    protocols_verify::{self as pv, CaseSpec, PeerStack, StepSpec},
    scan_control_suite::IN_DIR_SCRIPT,
    scan_control_verify::Who,
    windows_suite::{SuiteError, nonce, options_for, required},
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// `wire-lab.sh`'s mode that raises the stand for this suite.
const SUITE: &str = "wire-lab.sh --suite protocols";
/// Reads a file of the peer namespace's `/proc` (absolute path, like every tool the suite runs).
pub(crate) const CAT: &str = "/bin/cat";
pub(crate) const RATEMASK: &str = "/proc/sys/net/ipv4/icmp_ratemask";
pub(crate) const ECHO_IGNORE: &str = "/proc/sys/net/ipv4/icmp_echo_ignore_all";
pub(crate) const PROTOCOLS: &str = "/proc/net/protocols";
const USAGE: &str = "protocols-suite linux --out DIR --work DIR --ns-a NS --ns-b NS --iface-a IF --iface-b IF --mac-a MAC --mac-b MAC --rmasscan PATH --oracle PATH --conf-masked 0|1 --lab-id ID [--only TAG ...]   (run by wire-lab.sh --suite protocols, as root)
exit 0 every selected run executed, 2 NOT RUN, 10 ABORT, 13 ISOLATION BREACH, 130 INTERRUPTED; judge the directory with protocols-verify";

/// The cases to run: the whole table in its order, or the `--only` subset of it.
fn selected(only: &[String]) -> Result<Vec<&'static str>, SuiteError> {
    let all = pv::planned_tags();
    if let Some(t) = only.iter().find(|t| !all.contains(&t.as_str())) {
        return Err(not_run(format!(
            "{t} is not a protocols case ({})",
            all.join(" ")
        )));
    }
    Ok(all
        .into_iter()
        .filter(|t| only.is_empty() || only.iter().any(|o| o == t))
        .collect())
}

/// `protocols-suite linux`, inside the lab `wire-lab.sh --suite protocols` sealed. `lab` is this binary.
pub(crate) fn linux_with(
    args: &[String],
    host: &dyn LinuxHost,
    lab: &Path,
) -> Result<i32, SuiteError> {
    let o = options_for("protocols-suite linux", args, ad::LINUX_OPTIONS)?;
    if o.contains_key("help") {
        say(USAGE);
        return Ok(0);
    }
    let euid = host.euid()?;
    if euid != 0 {
        return Err(not_run(format!(
            "protocols-suite linux runs as root inside {SUITE} (effective uid {euid}); it never calls sudo itself"
        )));
    }
    let (out, work) = (
        PathBuf::from(required(&o, "out")?),
        PathBuf::from(required(&o, "work")?),
    );
    let sc = crate::capture::Scrubber::new(&out, Some(&work), host.account().as_deref());
    linux_run(&o, host, lab, out, work, &sc).map_err(|e| e.map_message(|m| sc.str(m)))
}

fn linux_run(
    o: &BTreeMap<String, Vec<String>>,
    host: &dyn LinuxHost,
    lab: &Path,
    out: PathBuf,
    work: PathBuf,
    sc: &crate::capture::Scrubber,
) -> Result<i32, SuiteError> {
    let a = ad::linux_args(o, SUITE)?;
    let tags = selected(ad::only_of(o)?)?;
    for tag in &tags {
        for s in pv::steps(tag).unwrap_or_default() {
            let bad = addresses_outside_the_lab(&s.argv);
            if !bad.is_empty() {
                return Err(not_run(format!(
                    "{tag}/{} names addresses outside 198.18.0.0/24: {bad:?}",
                    s.name
                )));
            }
        }
    }
    ad::attested_stand(&out, SUITE)?;
    let plan = ("protocols", json!("linux"), "protocols-suite linux");
    let suite = ad::linux_driver(
        host,
        lab,
        out.clone(),
        work,
        a,
        sc,
        &tags,
        plan,
        pv::verify_dir,
    )?;
    // The peer stack before anything starts: every selected case it cannot answer the stand's way is refused now.
    let stack = peer_stack(&suite).map_err(|e| {
        not_run(format!(
            "the peer stack could not be read ({e}); nothing was started"
        ))
    })?;
    let refused: Vec<String> = tags
        .iter()
        .filter_map(|t| pv::case(t))
        .filter_map(|c| pv::peer_stack_problem(&stack, &c).map(|p| format!("{}: {p}", c.tag)))
        .collect();
    if !refused.is_empty() {
        return Err(not_run(format!(
            "{}; nothing was started (select the other cases with --only, or fix the host)",
            refused.join("; ")
        )));
    }
    for tag in &tags {
        if host.stopped() {
            return Err(SuiteError::Interrupted(format!(
                "stop requested before {tag} started; nothing was left running"
            )));
        }
        let (Some(c), Some(specs)) = (pv::case(tag), pv::steps(tag)) else {
            continue;
        };
        suite.one_with(tag, |base, run, t| one(&suite, &c, &specs, base, run, t))?;
        say(&format!("done {0} -> runs/{0}", tag));
    }
    say(&sc.str(&format!(
        "all selected runs executed; verify offline with rmasscan-lab protocols-verify --dir {}",
        out.display()
    )));
    Ok(0)
}

/// The peer stack, read in the peer namespace: `net.ipv4.icmp_ratemask`, `net.ipv4.icmp_echo_ignore_all`, whether
/// `/proc/net/protocols` lists SCTP (the host kernel has it), and the responder the suite starts.
pub(crate) fn peer_stack(l: &Linux) -> Result<PeerStack, String> {
    let read = |path: &str| -> Result<String, String> {
        let o = l.host.exec(
            &l.ns(&l.ns_b, [CAT.to_owned(), path.to_owned()]),
            ad::EXEC_TIMEOUT,
        )?;
        if o.rc != 0 {
            return Err(format!("{path}: exit {}: {}", o.rc, o.stderr.trim()));
        }
        Ok(o.stdout)
    };
    Ok(PeerStack {
        icmp_ratemask: read(RATEMASK)?.trim().to_owned(),
        icmp_echo_ignore_all: read(ECHO_IGNORE)?.trim().to_owned(),
        sctp_in_kernel: pv::lists_sctp(&read(PROTOCOLS)?),
        responder: pv::responder_args(),
    })
}

/// One case: the seal, the peer stack, the case's records, every step in order, the seal again.
fn one(
    l: &Linux,
    c: &CaseSpec,
    specs: &[StepSpec],
    base: &Path,
    run: &Path,
    t: &mut LinuxTools,
) -> Result<(), SuiteError> {
    let tag = c.tag;
    ad::binaries_unchanged(&l.binaries)?;
    l.isolation(&run.join(pv::ISOLATION_JSON)).map_err(|e| {
        not_run(format!(
            "{tag}: the sealed protocols stand is not proven ({e}); nothing was started"
        ))
    })?;
    let stack = peer_stack(l).map_err(|e| {
        not_run(format!(
            "{tag}: the peer stack could not be read ({e}); nothing was started"
        ))
    })?;
    write_record(&run.join(pv::PEER_STACK_JSON), &stack)?;
    if let Some(p) = pv::peer_stack_problem(&stack, c) {
        return Err(not_run(format!("{tag}: {p}; nothing was started")));
    }
    let expect = pv::expect(tag).ok_or_else(|| not_run(format!("{tag} is not a case")))?;
    write_record(&run.join(pv::EXPECT_JSON), &expect)?;
    for s in specs {
        let dir = run.join(s.name);
        io(fs::create_dir_all(&dir), "the step's evidence directory")?;
        write_record(
            &dir.join("argv.json"),
            &ArgvRecord {
                argv: s.argv.clone(),
            },
        )?;
    }
    for s in specs {
        step(l, tag, s, base, run, t)?;
    }
    if let Some(mut p) = t.responder.take() {
        ad::stop(p.as_mut(), "TERM", &l.pause(), RESPONDER_POLLS);
    }
    // The seal after the case: a stand that changed stops the suite (the run is kept under runs_aborted).
    l.isolation(&run.join(pv::ISOLATION_POST_JSON))
        .map_err(|e| {
            SuiteError::Abort(format!(
                "{tag}: the stand is not sealed after the run ({e}); no further run"
            ))
        })
}

/// The peer's responder of the protocols stand ([`pv::responder_args`]), restarted for every step.
fn responder(l: &Linux, base: &Path, t: &mut LinuxTools) -> Result<(), SuiteError> {
    if let Some(mut p) = t.responder.take() {
        ad::stop(p.as_mut(), "TERM", &l.pause(), RESPONDER_POLLS);
    }
    let ready = base.join(format!("responder-{}.ready", nonce()));
    let mut args = vec!["capture".to_owned(), "responder".to_owned()];
    args.extend(pv::responder_args());
    args.extend(["--ready".to_owned(), p2s(&ready)]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let argv = l.ns(&l.ns_b, l.lab(&refs));
    t.responder = Some(l.host.spawn(
        &argv,
        &base.join("responder.out.txt"),
        &base.join(RESPONDER_ERR),
    )?);
    if !ad::poll(&l.pause(), RESPONDER_POLLS, || ready.exists()) {
        let rec = responder_state(l, base, t);
        let said = if rec.stderr.is_empty() {
            "nothing on its stderr"
        } else {
            &rec.stderr
        };
        let state = match rec.exited_with {
            Some(rc) => format!("it exited with {rc}: {said}"),
            None => format!("it still runs: {said}"),
        };
        return Err(not_run(format!(
            "the peer responder did not become ready ({state}); the scanner was not started"
        )));
    }
    Ok(())
}

/// The responder's stderr in the step's work directory (`capture responder` prints its error there).
const RESPONDER_ERR: &str = "responder.err.txt";
/// The responder of the step in work directory `base` as it is now: its exit code once it is gone, and its stderr
/// (trimmed, with `--out`, `--work` and the account scrubbed). A responder whose state cannot be read counts as gone.
fn responder_state(l: &Linux, base: &Path, t: &mut LinuxTools) -> pv::ResponderRecord {
    let exited_with = match t.responder.as_mut() {
        Some(p) => p.try_wait().unwrap_or(Some(-1)),
        None => Some(-1),
    };
    let stderr = fs::read(base.join(RESPONDER_ERR))
        .map(|b| String::from_utf8_lossy(&b).trim().to_owned())
        .unwrap_or_else(|e| format!("({RESPONDER_ERR} unreadable: {e})"));
    pv::ResponderRecord {
        exited_with,
        stderr: l.scrub.str(&stderr),
    }
}

/// One step: its own responder and witness, the scanner in its own working directory, the document collected.
fn step(
    l: &Linux,
    tag: &str,
    s: &StepSpec,
    base: &Path,
    run: &Path,
    t: &mut LinuxTools,
) -> Result<(), SuiteError> {
    let (sd, sb) = (run.join(s.name), base.join(format!("step-{}", s.name)));
    io(fs::create_dir_all(&sb), "the step's work directory")?;
    let cwd = base.join(format!("cwd-{}", s.name));
    io(fs::create_dir_all(&cwd), "the scanner's working directory")?;
    responder(l, &sb, t)?;
    let w = l.witness(&sb, &sd, pv::PEER_FILES[0], t)?;
    if l.host.stopped() {
        return Err(SuiteError::Interrupted(format!(
            "stop requested before {tag}/{} started its scanner",
            s.name
        )));
    }
    let mut argv = vec![SH.to_owned(), "-c".into(), IN_DIR_SCRIPT.into(), p2s(&cwd)];
    match s.who {
        Who::Oracle => argv.extend(l.oracle_cmd(&sb, s.argv.clone())?),
        Who::Rmasscan => {
            argv.push(l.rmasscan.clone());
            argv.extend(s.argv.clone());
        }
    }
    t.scanner = Some(l.host.spawn(
        &l.ns(&l.ns_a, argv),
        &sd.join("stdout.txt"),
        &sd.join("stderr.txt"),
    )?);
    let rc = l.wait(t, &format!("{tag}/{}", s.name))?;
    write_exit(&sd, rc)?;
    // Did the peer answer the whole scan? A responder gone before the scanner ended is named in the verdict.
    write_record(&sd.join(pv::RESPONDER_JSON), &responder_state(l, &sb, t))?;
    l.finish_witness(&w, t, &sd, CAPTURE_JSON, pv::PEER_FILES[2])?;
    // What the scanner left, under the table's neutral name; nothing else in its directory is evidence.
    if let Some(name) = s.out.file() {
        let file = cwd.join(name);
        if file.is_file() {
            io(fs::copy(&file, sd.join(name)), name)?;
        }
    }
    if let Some(mut p) = t.responder.take() {
        ad::stop(p.as_mut(), "TERM", &l.pause(), RESPONDER_POLLS);
    }
    Ok(())
}

/// The Linux suite, refused at once off Linux. One code path on every OS: it is compiled and linted everywhere.
fn linux_entry(args: &[String], exe: &Path) -> Result<i32, SuiteError> {
    if !cfg!(target_os = "linux") {
        return Err(not_run(format!(
            "protocols-suite linux runs on the Linux lab host, inside {SUITE}"
        )));
    }
    linux_with(args, &ad::RealLinux, exe)
}

/// `protocols-suite linux ...`: 0 every selected run executed, 2 NOT RUN, 10 ABORT, 13 ISOLATION BREACH,
/// 130 INTERRUPTED. Whether a run passed is `protocols-verify`'s verdict, never this exit code.
pub fn run(args: &[String]) -> Result<i32, String> {
    let Some((stand, rest)) = args.split_first() else {
        return Err(format!("which stand?\n{USAGE}"));
    };
    if matches!(stand.as_str(), "--help" | "-h" | "help") {
        say(USAGE);
        return Ok(0);
    }
    rmasscan_net::lab_io::install_signal_handlers()
        .map_err(|e| format!("cannot install the stop-signal handlers: {e}"))?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    ad::report(match stand.as_str() {
        "linux" => linux_entry(rest, &exe),
        other => Err(not_run(format!(
            "unknown stand {other}; the protocols suite runs on linux"
        ))),
    })
}

#[cfg(test)]
#[path = "protocols_suite_tests.rs"]
mod tests;
