//! `output-suite linux`: the live runs of the output-format acceptance (design §6.2) on the sealed Linux netns stand,
//! the autodetect stand that `wire-lab.sh --suite output` raises. Every planned case of the verifier's table
//! (`output_verify::cases`, no case is defined here) becomes one `runs/<tag>/` directory that `output-verify` judges
//! offline: `argv.json` and `expect.json` from the table, `isolation.json` and `isolation-post.json`, rmasscan's
//! `stdout.txt stderr.txt exit.txt`, its output file under its neutral name (`output.txt`, `output.bin`), the peer
//! witness of `capture dump` (`peer.pcap capture.json peer.err`); with the C oracle the same under `oracle/` and its
//! own capture (`oracle.pcap oracle-capture.json oracle.err`); an interrupted scan `interrupt.json`; `o17_readscan` its
//! two inputs; and `hashes-before-copy.txt`.
//!
//! The driver is `autodetect-suite linux`'s ([`Linux`]): the namespaces, the seal before and after each run, the
//! peer's responder and witness, the oracle under a masked `/etc/masscan`, the evidence copy with its hashes, the
//! aborted runs under `runs_aborted/`, `--out`, `--work` and the account scrubbed from every record. Each scanner runs
//! in a working directory of its own inside the run's work directory, so `-o<letter> output.txt` and the inputs of
//! `--readscan` are relative names and `argv.json` is exactly the table's; what it wrote there is copied into the
//! evidence byte for byte (the verifier's privacy scan reads it like stdout and stderr). Commands are argument arrays
//! with absolute paths; the shell runs one constant script ([`IN_DIR_SCRIPT`]).
//!
//! An interrupted case (`o14`-`o16`) gets SIGINT ~2 s after rmasscan started, to its process alone (`ip netns exec`
//! and the script exec it, so the child's pid is rmasscan's), never to the suite's process group; rmasscan then has
//! 30 s to exit before SIGKILL, and `interrupt.json` keeps when the signal went and whether the kill was needed.
use crate::{
    autodetect_suite::{
        self as ad, Linux, LinuxHost, LinuxTools, POLL, RESPONDER_POLLS, SH,
        addresses_outside_the_lab, io, not_run, p2s, say, write_exit, write_record,
    },
    autodetect_verify::{
        ArgvRecord, CAPTURE_JSON, ISOLATION_POST_JSON, ORACLE_CAPTURE_JSON, ORACLE_PCAP, PEER_PCAP,
    },
    capture::Scrubber,
    output_verify::{self as ov, InterruptRecord, OutputCase, OutputKind},
    windows_suite::{SuiteError, options_for, required},
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
const SUITE: &str = "wire-lab.sh --suite output";
/// ~2 s before SIGINT, then 30 s for rmasscan to exit, in polls of [`POLL`].
const INTERRUPT_POLLS: u32 = (ov::INTERRUPT_AFTER_S * 20.0) as u32;
const INTERRUPT_EXIT_POLLS: u32 = (ov::INTERRUPT_EXIT_S * 20.0) as u32;
const USAGE: &str = "output-suite linux --out DIR --work DIR --ns-a NS --ns-b NS --iface-a IF --iface-b IF --mac-a MAC --mac-b MAC --rmasscan PATH --oracle PATH --conf-masked 0|1 --lab-id ID [--only TAG ...]   (run by wire-lab.sh --suite output, as root)
exit 0 every selected run executed, 2 NOT RUN, 10 ABORT, 13 ISOLATION BREACH, 130 INTERRUPTED; judge the directory with output-verify";

/// The cases to run: the whole table in its order, or the `--only` subset of it.
fn selected(only: &[String]) -> Result<Vec<OutputCase>, SuiteError> {
    let all = ov::planned_tags();
    if let Some(t) = only.iter().find(|t| !all.contains(&t.as_str())) {
        return Err(not_run(format!(
            "{t} is not an output case ({})",
            all.join(" ")
        )));
    }
    Ok(ov::cases()
        .iter()
        .filter(|c| only.is_empty() || only.iter().any(|o| o == c.tag))
        .copied()
        .collect())
}

/// `output-suite linux`, inside the lab `wire-lab.sh --suite output` sealed. `lab` is this binary.
pub(crate) fn linux_with(
    args: &[String],
    host: &dyn LinuxHost,
    lab: &Path,
) -> Result<i32, SuiteError> {
    let o = options_for("output-suite linux", args, ad::LINUX_OPTIONS)?;
    if o.contains_key("help") {
        say(USAGE);
        return Ok(0);
    }
    let euid = host.euid()?;
    if euid != 0 {
        return Err(not_run(format!(
            "output-suite linux runs as root inside {SUITE} (effective uid {euid}); it never calls sudo itself"
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
    let cases = selected(ad::only_of(o)?)?;
    for c in &cases {
        let bad = addresses_outside_the_lab(&c.argv());
        if !bad.is_empty() {
            return Err(not_run(format!(
                "{} names addresses outside 198.18.0.0/24: {bad:?}",
                c.tag
            )));
        }
    }
    ad::attested_stand(&out, SUITE)?;
    // o17 reads o06's two outputs: o06 runs before it in this invocation, or has its run in this --out already.
    let o6 = cases.iter().any(|c| c.tag == ov::BINARY_TAG);
    if cases.iter().any(|c| c.kind == OutputKind::Readscan)
        && !o6
        && !o06_outputs(&out).iter().all(|p| p.is_file())
    {
        return Err(not_run(format!(
            "o17_readscan reads the -oB outputs of {} (runs/{0}/output.bin and oracle/output.bin), which this --out does not hold; run {0} first",
            ov::BINARY_TAG
        )));
    }
    let tags: Vec<&str> = cases.iter().map(|c| c.tag).collect();
    let plan = ("output", json!("linux"), "output-suite linux");
    let suite = ad::linux_driver(
        host,
        lab,
        out.clone(),
        work,
        a,
        sc,
        &tags,
        plan,
        ov::verify_dir,
    )?;
    for c in &cases {
        if host.stopped() {
            return Err(SuiteError::Interrupted(format!(
                "stop requested before {} started; nothing was left running",
                c.tag
            )));
        }
        suite.one_with(c.tag, |base, run, t| one(&suite, c, base, run, t))?;
        say(&format!("done {0} -> runs/{0}", c.tag));
    }
    say(&sc.str(&format!(
        "all selected runs executed; verify offline with rmasscan-lab output-verify --dir {}",
        out.display()
    )));
    Ok(0)
}

/// `o06_binary`'s two `-oB` outputs in the evidence directory, in the order of [`ov::READSCAN_INPUTS`].
fn o06_outputs(out: &Path) -> [PathBuf; 2] {
    let d = out.join("runs").join(ov::BINARY_TAG);
    [
        d.join("output.bin"),
        d.join(ov::ORACLE_DIR).join("output.bin"),
    ]
}

/// One run: the seal, the case's records, rmasscan and (for its cases) the oracle, the seal again.
fn one(
    l: &Linux,
    c: &OutputCase,
    base: &Path,
    run: &Path,
    t: &mut LinuxTools,
) -> Result<(), SuiteError> {
    let tag = c.tag;
    ad::binaries_unchanged(&l.binaries)?;
    l.isolation(&run.join("isolation.json")).map_err(|e| {
        not_run(format!(
            "{tag}: the sealed autodetect stand is not proven ({e}); nothing was started"
        ))
    })?;
    write_record(&run.join("argv.json"), &ArgvRecord { argv: c.argv() })?;
    write_record(&run.join("expect.json"), &c.expect())?;
    let mut inputs = Vec::new();
    if c.kind == OutputKind::Readscan {
        for (name, from) in ov::READSCAN_INPUTS.iter().zip(o06_outputs(&l.out)) {
            let b = io(
                fs::read(&from),
                &format!("{} of {}", p2s(&from), ov::BINARY_TAG),
            )?;
            io(fs::write(run.join(name), &b), name)?;
            inputs.push((*name, b));
        }
    }
    scan(l, c, false, base, run, t, &inputs)?;
    if c.oracle {
        scan(l, c, true, base, run, t, &inputs)?;
    }
    if let Some(mut p) = t.responder.take() {
        ad::stop(p.as_mut(), "TERM", &l.pause(), RESPONDER_POLLS);
    }
    // The seal after the run: a stand that changed stops the suite (the run is kept under runs_aborted).
    l.isolation(&run.join(ISOLATION_POST_JSON)).map_err(|e| {
        SuiteError::Abort(format!(
            "{tag}: the stand is not sealed after the run ({e}); no further run"
        ))
    })
}

/// One scanner of a run (`oracle`: the C oracle) under its own witness, in its own working directory.
fn scan(
    l: &Linux,
    c: &OutputCase,
    oracle: bool,
    base: &Path,
    run: &Path,
    t: &mut LinuxTools,
    inputs: &[(&str, Vec<u8>)],
) -> Result<(), SuiteError> {
    let (who, pcap, record, err) = if oracle {
        ("oracle", ORACLE_PCAP, ORACLE_CAPTURE_JSON, "oracle.err")
    } else {
        ("rmasscan", PEER_PCAP, CAPTURE_JSON, "peer.err")
    };
    let cwd = base.join(format!("cwd-{who}"));
    io(fs::create_dir_all(&cwd), "the scanner's working directory")?;
    for (name, b) in inputs {
        io(fs::write(cwd.join(name), b), name)?;
    }
    let dest = if oracle {
        run.join(ov::ORACLE_DIR)
    } else {
        run.to_path_buf()
    };
    io(
        fs::create_dir_all(&dest),
        "the scanner's evidence directory",
    )?;
    if c.live() {
        l.responder(base, t)?;
    }
    let w = l.witness(base, run, pcap, t)?;
    if l.host.stopped() {
        return Err(SuiteError::Interrupted(format!(
            "stop requested before {} started its {who}",
            c.tag
        )));
    }
    let mut argv = vec![SH.to_owned(), "-c".into(), IN_DIR_SCRIPT.into(), p2s(&cwd)];
    if oracle {
        argv.extend(l.oracle_cmd(base, c.argv())?);
    } else {
        argv.push(l.rmasscan.clone());
        argv.extend(c.argv());
    }
    t.scanner = Some(l.host.spawn(
        &l.ns(&l.ns_a, argv),
        &dest.join("stdout.txt"),
        &dest.join("stderr.txt"),
    )?);
    let rc = if c.kind == OutputKind::Interrupt && !oracle {
        interrupt(l, t, c.tag, run)?
    } else {
        l.wait(t, c.tag)?
    };
    write_exit(&dest, rc)?;
    l.finish_witness(&w, t, run, record, err)?;
    // The document, under its neutral name; nothing else the scanner may have left in its directory is evidence.
    let file = cwd.join(c.format.file());
    if c.writes_file() && file.is_file() {
        io(fs::copy(&file, dest.join(c.format.file())), c.format.file())?;
    }
    Ok(())
}

/// The interrupt of `o14`-`o16`: ~2 s after the start SIGINT to rmasscan alone, then up to 30 s for it to exit,
/// SIGKILL after that; `interrupt.json` records the signal's time and whether the kill was needed. The exit code.
fn interrupt(l: &Linux, t: &mut LinuxTools, tag: &str, run: &Path) -> Result<i32, SuiteError> {
    let pause = l.pause();
    let p = t.scanner.as_mut().ok_or("the scanner is not running")?;
    let mut rc = None;
    for _ in 0..INTERRUPT_POLLS {
        rc = p.try_wait()?;
        if rc.is_some() {
            break;
        }
        if l.host.stopped() {
            return Err(SuiteError::Interrupted(format!(
                "stopped while the scanner of {tag} was running"
            )));
        }
        pause(POLL);
    }
    let mut rec = InterruptRecord {
        signal: "INT".into(),
        after_s: ov::INTERRUPT_AFTER_S,
        signal_unix: None,
        exit_within_s: ov::INTERRUPT_EXIT_S,
        killed: false,
    };
    if rc.is_none() {
        rec.signal_unix = Some(l.host.now());
        p.signal("INT");
        for _ in 0..INTERRUPT_EXIT_POLLS {
            rc = p.try_wait()?;
            if rc.is_some() {
                break;
            }
            pause(POLL);
        }
        if rc.is_none() {
            rec.killed = true;
            p.kill();
            rc = p.try_wait()?;
        }
    }
    write_record(&run.join(ov::INTERRUPT_JSON), &rec)?;
    t.scanner = None;
    Ok(rc.unwrap_or(-1))
}

/// The Linux suite, refused at once off Linux. One code path on every OS: it is compiled and linted everywhere.
fn linux_entry(args: &[String], exe: &Path) -> Result<i32, SuiteError> {
    if !cfg!(target_os = "linux") {
        return Err(not_run(format!(
            "output-suite linux runs on the Linux lab host, inside {SUITE}"
        )));
    }
    linux_with(args, &ad::RealLinux, exe)
}

/// `output-suite linux ...`: 0 every selected run executed, 2 NOT RUN, 10 ABORT, 13 ISOLATION BREACH,
/// 130 INTERRUPTED. Whether a run passed is `output-verify`'s verdict, never this exit code.
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
            "unknown stand {other}; the output suite runs on linux"
        ))),
    })
}

#[cfg(test)]
#[path = "output_suite_tests.rs"]
mod tests;
