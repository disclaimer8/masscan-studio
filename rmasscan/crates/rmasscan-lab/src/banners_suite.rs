//! `banners-suite linux`: the live runs of the banners window of sub-stage 4a (UDP banners, `--banners` and
//! `--rawudp`) on the sealed Linux netns stand that `wire-lab.sh --suite banners` raises: the protocols stand (the
//! autodetect stand with `net.ipv4.icmp_ratemask = 0` in the peer namespace). Every planned case of the verifier's table
//! (`banners_verify::steps`; no case is defined here) becomes one `runs/<tag>/` directory that `banners-verify` judges
//! offline: `expect.json`, `peer-stack.json`, `isolation.json`, `isolation-post.json`, `hashes-before-copy.txt`, and
//! per step `argv.json`, the scanner's `stdout.txt stderr.txt exit.txt`, its document (`output.bin`, `output.txt`), the
//! peer witness `peer.pcap capture.json peer.err` and `responder.json`.
//!
//! The driver is the protocols suite's (`protocols_suite::step`: one restarted responder and one witness per step, the
//! scanner in its own working directory, the oracle under a masked `/etc/masscan`) on the other Linux suites' stand
//! machinery (`autodetect_suite::Linux`). The one difference is the peer's responder: `capture responder` with
//! [`bv::responder_args`], one UDP socket per peer address and window port, each datagram answered once with the
//! scenario reply of its address and port (`banners_verify::scenario_reply`: the probe's identifier copied in or
//! spoiled). Before anything starts and again before every case the suite reads the peer stack in the peer namespace
//! (`protocols_suite::peer_stack_with`) and refuses (NOT RUN) a peer that rate-limits ICMP errors, ignores Echo, or
//! would run another responder. Every target is in 198.18.0.0/24. The suite never loads a kernel module.
use crate::{
    autodetect_suite::{
        self as ad, Linux, LinuxHost, LinuxTools, RESPONDER_POLLS, addresses_outside_the_lab,
        not_run, write_record,
    },
    banners_verify::{self as bv, CaseSpec},
    protocols_suite::{
        SuiteDef, linux_entry_def, linux_with_def, peer_stack_with, run_cases, run_def,
        selected_of, step, write_step_argv,
    },
    protocols_verify::StepSpec,
    windows_suite::SuiteError,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// `wire-lab.sh`'s mode that raises the stand for this suite.
const SUITE: &str = "wire-lab.sh --suite banners";
const USAGE: &str = "banners-suite linux --out DIR --work DIR --ns-a NS --ns-b NS --iface-a IF --iface-b IF --mac-a MAC --mac-b MAC --rmasscan PATH --oracle PATH --conf-masked 0|1 --lab-id ID [--only TAG ...]   (run by wire-lab.sh --suite banners, as root)
exit 0 every selected run executed, 2 NOT RUN, 10 ABORT, 13 ISOLATION BREACH, 130 INTERRUPTED; judge the directory with banners-verify";

const BANNERS_SUITE: SuiteDef = SuiteDef {
    wire_lab: SUITE,
    name: "banners",
    a_case: "a banners case",
    usage: USAGE,
};

/// `banners-suite linux`, inside the lab `wire-lab.sh --suite banners` sealed. `lab` is this binary.
pub(crate) fn linux_with(
    args: &[String],
    host: &dyn LinuxHost,
    lab: &Path,
) -> Result<i32, SuiteError> {
    linux_with_def(args, host, lab, &BANNERS_SUITE, linux_run)
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
    let tags = selected_of(ad::only_of(o)?, bv::planned_tags(), &BANNERS_SUITE)?;
    for tag in &tags {
        for s in bv::steps(tag).unwrap_or_default() {
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
    let plan = ("banners", json!("linux"), "banners-suite linux");
    let suite = ad::linux_driver(
        host,
        lab,
        out.clone(),
        work,
        a,
        sc,
        &tags,
        plan,
        bv::verify_dir,
    )?;
    // The peer stack before anything starts: a peer that cannot answer the window the stand's way refuses it now.
    let stack = peer_stack_with(&suite, bv::responder_args()).map_err(|e| {
        not_run(format!(
            "the peer stack could not be read ({e}); nothing was started"
        ))
    })?;
    if let Some(p) = bv::peer_stack_problem(&stack) {
        return Err(not_run(format!(
            "{p}; nothing was started (fix the host or run inside {SUITE})"
        )));
    }
    run_cases(
        &suite,
        &tags,
        &BANNERS_SUITE,
        &out,
        sc,
        |tag, base, run, t| {
            let (Some(c), Some(specs)) = (bv::case(tag), bv::steps(tag)) else {
                return Err(not_run(format!("{tag} is not a case")));
            };
            one(&suite, &c, &specs, base, run, t)
        },
    )
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
    l.isolation(&run.join(bv::ISOLATION_JSON)).map_err(|e| {
        not_run(format!(
            "{tag}: the sealed banners stand is not proven ({e}); nothing was started"
        ))
    })?;
    let stack = peer_stack_with(l, bv::responder_args()).map_err(|e| {
        not_run(format!(
            "{tag}: the peer stack could not be read ({e}); nothing was started"
        ))
    })?;
    write_record(&run.join(bv::PEER_STACK_JSON), &stack)?;
    if let Some(p) = bv::peer_stack_problem(&stack) {
        return Err(not_run(format!("{tag}: {p}; nothing was started")));
    }
    let expect = bv::expect(tag).ok_or_else(|| not_run(format!("{tag} is not a case")))?;
    write_record(&run.join(bv::EXPECT_JSON), &expect)?;
    write_step_argv(run, specs)?;
    let options = bv::responder_args();
    for s in specs {
        step(l, tag, s, base, run, t, &options)?;
    }
    if let Some(mut p) = t.responder.take() {
        ad::stop(p.as_mut(), "TERM", &l.pause(), RESPONDER_POLLS);
    }
    // The seal after the case: a stand that changed stops the suite (the run is kept under runs_aborted).
    l.isolation(&run.join(bv::ISOLATION_POST_JSON))
        .map_err(|e| {
            SuiteError::Abort(format!(
                "{tag}: the stand is not sealed after the run ({e}); no further run"
            ))
        })
}

/// The Linux suite, refused at once off Linux. One code path on every OS: it is compiled and linted everywhere.
fn linux_entry(args: &[String], exe: &Path) -> Result<i32, SuiteError> {
    linux_entry_def(args, exe, &BANNERS_SUITE, linux_with)
}

/// `banners-suite linux ...`: 0 every selected run executed, 2 NOT RUN, 10 ABORT, 13 ISOLATION BREACH,
/// 130 INTERRUPTED. Whether a run passed is `banners-verify`'s verdict, never this exit code.
pub fn run(args: &[String]) -> Result<i32, String> {
    run_def(args, &BANNERS_SUITE, linux_entry)
}

#[cfg(test)]
#[path = "banners_suite_tests.rs"]
mod tests;
