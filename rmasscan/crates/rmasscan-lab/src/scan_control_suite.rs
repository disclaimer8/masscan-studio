//! `scan-control-suite linux`: the live runs of the scan-control acceptance (design §6.2) on the sealed Linux netns stand,
//! the autodetect stand plus one more veth pair for `--adapter[1]`, which `wire-lab.sh --suite scan-control` raises.
//! Every planned case of the verifier's table (`scan_control_verify::steps`, no case is defined here) becomes one
//! `runs/<tag>/` directory with one directory per step that `scan-control-verify` judges offline: `argv.json`,
//! rmasscan's (or the oracle's) `stdout.txt stderr.txt exit.txt`, what it left in its working directory under the
//! table's evidence names (`output.txt`, `output.json`, `paused.txt`, `scanner.pcap`), the peer witness of each link
//! (`peer.pcap capture.json peer.err`, a second link `peer2.pcap capture2.json peer2.err`), an interrupted step
//! `interrupt.json`, `sc02`'s `netem.json`; at the case level `expect.json`, `isolation.json`, `isolation-post.json` and
//! `hashes-before-copy.txt`.
//!
//! The driver is `output-suite linux`'s and `autodetect-suite linux`'s ([`Linux`]): the namespaces, the seal before and
//! after each case (`capture isolation --mode scan-control`), the peer's responder and witness, the oracle under a
//! masked `/etc/masscan`, the evidence copy with its hashes, the aborted runs under `runs_aborted/`, `--out`, `--work`
//! and the account scrubbed from every record. Each step runs in a working directory of its own group inside the
//! case's work directory (a resume shares the directory of the run it resumes, so it finds `paused.conf` and the output
//! file); commands are argument arrays with absolute paths, and the shell runs one constant script
//! ([`IN_DIR_SCRIPT`]). The second veth pair, its witness, its addresses and the netem delay of `sc02` are fixed here
//! and in `wire-lab.sh`; nothing the suite starts can name a host interface, and every target is in 198.18.0.0/24.
//!
//! An interrupted step gets SIGINT [`StepSpec::interrupt_after_s`] seconds after rmasscan started, to its process alone
//! (`ip netns exec` and the script exec it, so the child's pid is rmasscan's), never to the suite's process group;
//! rmasscan then has 30 s to exit before SIGKILL. `interrupt.json` keeps when the signal went, the first moment
//! `paused.conf` was seen in the scanner's directory, whether it was there at the end, and whether the kill was needed.
use crate::{
    autodetect_suite::{
        self as ad, Linux, LinuxHost, LinuxTools, POLL, RESPONDER_POLLS, SH, WitnessLink,
        addresses_outside_the_lab, io, not_run, p2s, say, write_exit, write_record,
    },
    autodetect_verify::{ArgvRecord, CAPTURE_JSON},
    capture::IsolationMode,
    capture::{SECOND_PEER_IF, SECOND_SCANNER_IF, Scrubber, isolation_permits},
    scan_control_verify::{
        self as sv, EXIT_WITHIN_S, INTERRUPT_JSON, ISOLATION_JSON, NETEM_DELAY_MS, NETEM_JSON,
        NetemRecord, PAUSED_CONF, PEER_FILES, ScInterrupt, StepSpec, Who,
    },
    windows_suite::{SuiteError, options_for, read_json, required},
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// Runs a program in a directory: `$0` is the directory, `$@` the program and its arguments. A constant script; no
/// value is ever spliced into it.
pub(crate) const IN_DIR_SCRIPT: &str = "cd \"$0\" && exec \"$@\"";
/// `wire-lab.sh`'s mode that raises the stand for this suite.
const SUITE: &str = "wire-lab.sh --suite scan-control";
/// The traffic shaper of the netem delay, in the peer namespace only.
pub(crate) const TC: &str = "/sbin/tc";
/// The second link: the peer end the witness records on, the scanner end that sends its start marker, and the MACs.
const SECOND_LINK: WitnessLink<'static> = WitnessLink {
    peer_if: SECOND_PEER_IF,
    scanner_if: SECOND_SCANNER_IF,
    scanner_mac: "02:aa:00:00:00:03",
    peer_mac: "02:aa:00:00:00:04",
};
const USAGE: &str = "scan-control-suite linux --out DIR --work DIR --ns-a NS --ns-b NS --iface-a IF --iface-b IF --mac-a MAC --mac-b MAC --rmasscan PATH --oracle PATH --conf-masked 0|1 --lab-id ID [--only TAG ...]   (run by wire-lab.sh --suite scan-control, as root)
exit 0 every selected run executed, 2 NOT RUN, 10 ABORT, 13 ISOLATION BREACH, 130 INTERRUPTED; judge the directory with scan-control-verify";

/// The cases to run: the whole table in its order, or the `--only` subset of it.
fn selected(only: &[String]) -> Result<Vec<&'static str>, SuiteError> {
    let all = sv::planned_tags();
    if let Some(t) = only.iter().find(|t| !all.contains(&t.as_str())) {
        return Err(not_run(format!(
            "{t} is not a scan-control case ({})",
            all.join(" ")
        )));
    }
    Ok(all
        .into_iter()
        .filter(|t| only.is_empty() || only.iter().any(|o| o == t))
        .collect())
}

/// `wire-lab.sh`'s own `isolation.json` in `out`: the sealed scan-control stand, the autodetect stand with the second
/// veth pair (a record of the plain autodetect stand does not attest it).
fn attested_stand(out: &Path) -> Result<(), SuiteError> {
    let iso = read_json(out.join(ISOLATION_JSON)).map_err(|e| {
        not_run(format!(
            "wire-lab.sh's isolation.json is missing ({e}); the suite runs only inside {SUITE}"
        ))
    })?;
    let second = json!({"scanner": SECOND_SCANNER_IF, "peer": SECOND_PEER_IF, "adapter_ip": crate::capture::SECOND_ADAPTER_IP});
    if iso["mode"] != "scan-control"
        || !isolation_permits(&iso, IsolationMode::Autodetect)
        || iso["second_link"] != second
    {
        return Err(not_run(format!(
            "isolation.json does not attest the sealed scan-control stand (mode {}, default_route {}, second_link {})",
            iso["mode"], iso["default_route"], iso["second_link"]
        )));
    }
    Ok(())
}

/// `scan-control-suite linux`, inside the lab `wire-lab.sh --suite scan-control` sealed. `lab` is this binary.
pub(crate) fn linux_with(
    args: &[String],
    host: &dyn LinuxHost,
    lab: &Path,
) -> Result<i32, SuiteError> {
    let o = options_for("scan-control-suite linux", args, ad::LINUX_OPTIONS)?;
    if o.contains_key("help") {
        say(USAGE);
        return Ok(0);
    }
    let euid = host.euid()?;
    if euid != 0 {
        return Err(not_run(format!(
            "scan-control-suite linux runs as root inside {SUITE} (effective uid {euid}); it never calls sudo itself"
        )));
    }
    let (out, work) = (
        PathBuf::from(required(&o, "out")?),
        PathBuf::from(required(&o, "work")?),
    );
    let sc = Scrubber::new(&out, Some(&work), host.account().as_deref());
    linux_run(&o, host, lab, out, work, &sc).map_err(|e| e.map_message(|m| sc.str(m)))
}

fn linux_run(
    o: &BTreeMap<String, Vec<String>>,
    host: &dyn LinuxHost,
    lab: &Path,
    out: PathBuf,
    work: PathBuf,
    sc: &Scrubber,
) -> Result<i32, SuiteError> {
    let a = ad::linux_args(o, SUITE)?;
    let tags = selected(ad::only_of(o)?)?;
    for tag in &tags {
        for s in sv::steps(tag).unwrap_or_default() {
            let bad = addresses_outside_the_lab(&s.argv);
            if !bad.is_empty() {
                return Err(not_run(format!(
                    "{tag}/{} names addresses outside 198.18.0.0/24: {bad:?}",
                    s.name
                )));
            }
        }
    }
    attested_stand(&out)?;
    let plan = ("scan-control", json!("linux"), "scan-control-suite linux");
    let suite = ad::linux_driver(
        host,
        lab,
        out.clone(),
        work,
        a,
        sc,
        &tags,
        plan,
        sv::verify_dir,
    )?;
    for tag in &tags {
        if host.stopped() {
            return Err(SuiteError::Interrupted(format!(
                "stop requested before {tag} started; nothing was left running"
            )));
        }
        let specs = sv::steps(tag).unwrap_or_default();
        suite.one_with(tag, |base, run, t| one(&suite, tag, &specs, base, run, t))?;
        say(&format!("done {0} -> runs/{0}", tag));
    }
    say(&sc.str(&format!(
        "all selected runs executed; verify offline with rmasscan-lab scan-control-verify --dir {}",
        out.display()
    )));
    Ok(0)
}

/// One case: the seal, the case's records, every step in order, the seal again.
fn one(
    l: &Linux,
    tag: &str,
    specs: &[StepSpec],
    base: &Path,
    run: &Path,
    t: &mut LinuxTools,
) -> Result<(), SuiteError> {
    ad::binaries_unchanged(&l.binaries)?;
    l.isolation_mode(&run.join(ISOLATION_JSON), "scan-control")
        .map_err(|e| {
            not_run(format!(
                "{tag}: the sealed scan-control stand is not proven ({e}); nothing was started"
            ))
        })?;
    let expect = sv::expect(tag).ok_or_else(|| not_run(format!("{tag} is not a case")))?;
    write_record(&run.join(sv::EXPECT_JSON), &expect)?;
    for s in specs {
        // Each step keeps its own records; nothing of an earlier step is touched by a later one but the working
        // directory its group shares.
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
    l.isolation_mode(&run.join(sv::ISOLATION_POST_JSON), "scan-control")
        .map_err(|e| {
            SuiteError::Abort(format!(
                "{tag}: the stand is not sealed after the run ({e}); no further run"
            ))
        })
}

/// `tc qdisc add|del dev veth-b root netem ...` in the peer namespace: the one change the suite makes to the stand
/// besides starting processes, on this run's own veth and undone before the witness finishes.
fn netem(l: &Linux, add: bool) -> Result<(), String> {
    let mut tail = vec![
        TC.to_owned(),
        "qdisc".into(),
        if add { "add" } else { "del" }.into(),
        "dev".into(),
        ad::LINUX_PEER_IF.into(),
        "root".into(),
    ];
    if add {
        tail.extend([
            "netem".into(),
            "delay".into(),
            format!("{NETEM_DELAY_MS}ms"),
        ]);
    }
    let o = l.host.exec(&l.ns(&l.ns_b, tail), ad::EXEC_TIMEOUT)?;
    if o.rc != 0 {
        return Err(format!(
            "tc qdisc {} exited {}: {}",
            if add { "add" } else { "del" },
            o.rc,
            o.stderr.trim()
        ));
    }
    Ok(())
}

/// Takes the netem delay off on every exit path of a step that set it; netns deletion remains the last safety net.
struct NetemGuard<'a> {
    l: &'a Linux<'a>,
    armed: bool,
}
impl Drop for NetemGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = netem(self.l, false);
        }
    }
}

/// One step: its own responder and witnesses, the scanner in its group's working directory, the collected files.
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
    let cwd = base.join(format!("cwd-{}", s.cwd));
    io(fs::create_dir_all(&cwd), "the scanner's working directory")?;
    if s.interrupt_after_s.is_some() && cwd.join(PAUSED_CONF).exists() {
        return Err(not_run(format!(
            "{tag}/{}: a paused.conf is already in the scanner's directory; nothing was started",
            s.name
        )));
    }
    l.responder(&sb, t)?;
    let mut guard = NetemGuard { l, armed: false };
    if s.netem {
        netem(l, true).map_err(|e| {
            not_run(format!(
                "{tag}/{}: the netem delay of the late-reply window could not be set ({e}); the scanner was not started",
                s.name
            ))
        })?;
    }
    guard.armed = s.netem;
    let w0 = l.witness(&sb, &sd, PEER_FILES[0][0], t)?;
    let w1 = if s.links == 2 {
        Some(l.witness_link(&sb, &sd, PEER_FILES[1][0], t, &SECOND_LINK, true)?)
    } else {
        None
    };
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
    let rc = match s.interrupt_after_s {
        Some(after) if s.who == Who::Rmasscan => interrupt(l, t, tag, s, &sd, &cwd, after)?,
        _ => l.wait(t, &format!("{tag}/{}", s.name))?,
    };
    write_exit(&sd, rc)?;
    l.finish_witness(&w0, t, &sd, CAPTURE_JSON, PEER_FILES[0][2])?;
    if let Some(w) = &w1 {
        l.finish_witness2(w, t, &sd, PEER_FILES[1][1], PEER_FILES[1][2])?;
    }
    if s.netem {
        // After the witnesses: replies still held back are not cut off before the capture is complete.
        let removed = netem(l, false);
        guard.armed = false;
        write_record(
            &sd.join(NETEM_JSON),
            &NetemRecord {
                iface: ad::LINUX_PEER_IF.into(),
                delay_ms: NETEM_DELAY_MS,
                applied: true,
                removed: removed.is_ok(),
            },
        )?;
        removed.map_err(|e| {
            SuiteError::Abort(format!(
                "{tag}/{}: the netem delay could not be taken off ({e}); no further run",
                s.name
            ))
        })?;
    }
    // What the scanner left, under the table's neutral names; nothing else in its directory is evidence.
    for (from, to) in &s.collect {
        let file = cwd.join(from);
        if file.is_file() {
            io(fs::copy(&file, sd.join(to)), to)?;
        }
    }
    if let Some(mut p) = t.responder.take() {
        ad::stop(p.as_mut(), "TERM", &l.pause(), RESPONDER_POLLS);
    }
    Ok(())
}

/// The interrupt of an interrupted step: `after` seconds after the start SIGINT to rmasscan alone, then up to 30 s
/// for it to exit (SIGKILL after that). `interrupt.json` records the signal's time, the first moment `paused.conf`
/// was in the scanner's directory, whether it still was at the end, and whether the kill was needed. The exit code.
fn interrupt(
    l: &Linux,
    t: &mut LinuxTools,
    tag: &str,
    s: &StepSpec,
    sd: &Path,
    cwd: &Path,
    after: f64,
) -> Result<i32, SuiteError> {
    let pause = l.pause();
    let p = t.scanner.as_mut().ok_or("the scanner is not running")?;
    let (wait_polls, exit_polls) = ((after * 20.0) as u32, (EXIT_WITHIN_S * 20.0) as u32);
    let mut rc = None;
    for _ in 0..wait_polls {
        rc = p.try_wait()?;
        if rc.is_some() {
            break;
        }
        if l.host.stopped() {
            return Err(SuiteError::Interrupted(format!(
                "stopped while the scanner of {tag}/{} was running",
                s.name
            )));
        }
        pause(POLL);
    }
    let mut rec = ScInterrupt {
        signal: "INT".into(),
        after_s: after,
        signal_unix: None,
        exit_within_s: EXIT_WITHIN_S,
        killed: false,
        paused_seen_unix: None,
        paused_conf_present: false,
    };
    if rc.is_none() {
        rec.signal_unix = Some(l.host.now());
        p.signal("INT");
        for _ in 0..exit_polls {
            // paused.conf is looked for before the exit is: a file that is there at once is what the claim needs
            if rec.paused_seen_unix.is_none() && cwd.join(PAUSED_CONF).exists() {
                rec.paused_seen_unix = Some(l.host.now());
            }
            rc = p.try_wait()?;
            if rc.is_some() {
                break;
            }
            if l.host.stopped() {
                return Err(SuiteError::Interrupted(format!(
                    "stopped while the scanner of {tag}/{} was exiting after SIGINT",
                    s.name
                )));
            }
            pause(POLL);
        }
        if rc.is_none() {
            rec.killed = true;
            p.kill();
            rc = p.try_wait()?;
        }
    }
    rec.paused_conf_present = cwd.join(PAUSED_CONF).exists();
    write_record(&sd.join(INTERRUPT_JSON), &rec)?;
    t.scanner = None;
    Ok(rc.unwrap_or(-1))
}

/// The Linux suite, refused at once off Linux. One code path on every OS: it is compiled and linted everywhere.
fn linux_entry(args: &[String], exe: &Path) -> Result<i32, SuiteError> {
    if !cfg!(target_os = "linux") {
        return Err(not_run(format!(
            "scan-control-suite linux runs on the Linux lab host, inside {SUITE}"
        )));
    }
    linux_with(args, &ad::RealLinux, exe)
}

/// `scan-control-suite linux ...`: 0 every selected run executed, 2 NOT RUN, 10 ABORT, 13 ISOLATION BREACH,
/// 130 INTERRUPTED. Whether a run passed is `scan-control-verify`'s verdict, never this exit code.
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
            "unknown stand {other}; the scan-control suite runs on linux"
        ))),
    })
}

#[cfg(test)]
#[path = "scan_control_suite_tests.rs"]
mod tests;
