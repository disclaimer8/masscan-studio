//! `banners-suite linux`: the live runs of the banners window (sub-stage 4a: UDP banners, `--banners` and `--rawudp`;
//! sub-stage 4b: TCP banners through the user-mode stack, the stateless RST and `--noreset`) on the sealed Linux netns
//! stand that `wire-lab.sh --suite banners` raises: the IPv6 stand (`capture isolation --mode ipv6`) with
//! `net.ipv4.icmp_ratemask = 0` and permanent neighbour entries for the TCP sources 198.18.0.9 and fd00:198:18::9 on
//! the scanner MAC in the peer namespace. Every planned case of the verifier's table (`banners_verify::steps`; no case
//! is defined here) becomes one `runs/<tag>/` directory that `banners-verify` judges offline: `expect.json`,
//! `peer-stack.json`, `peer-tcp.json` (TCP cases), `isolation.json`, `isolation-post.json`, `hashes-before-copy.txt`,
//! and per step `argv.json`, the
//! scanner's `stdout.txt stderr.txt exit.txt`, its document (`output.bin`, `output.txt`), the peer witness `peer.pcap
//! capture.json peer.err` and `responder.json`.
//!
//! The driver is the protocols suite's (`protocols_suite::step`: one restarted responder and one witness per step, the
//! scanner in its own working directory, the oracle under a masked `/etc/masscan`) on the other Linux suites' stand
//! machinery (`autodetect_suite::Linux`). The one difference is the peer's responder
//! (`banners_verify::responder_args_for`): for a UDP case `capture responder` with one UDP socket per peer address and
//! window port, each datagram answered once with the scenario reply of its address and port
//! (`banners_verify::scenario_reply`); for a TCP case a kernel
//! socket per peer address (IPv4 and IPv6) and scenario port, every connection running its scenario's script
//! (`banners_verify::TCP_SCENARIOS`), and the peer heartbeat that keeps C's receive loop turning. Before every step of
//! a resolve case (no neighbour entry for its source) the suite flushes the peer's entry for that source, so each
//! scanner is asked for its address afresh. Before anything starts and again before every case the suite reads the
//! peer stack in the peer namespace (`protocols_suite::peer_stack_with`) and the stand's IPv6
//! (`ipv6_suite::ipv6_stack`), and refuses (NOT RUN) a peer that rate-limits ICMP errors, ignores Echo, would run
//! another responder, or an IPv6 stand that is not ready, and before each TCP case the peer's
//! `net.ipv4.tcp_max_tw_buckets` (`peer-tcp.json`: 0, or NOT RUN). Every target is in 198.18.0.0/24 or
//! fd00:198:18::/64. The suite never loads a kernel module.
use crate::{
    autodetect_suite::{
        self as ad, IP, Linux, LinuxHost, LinuxTools, RESPONDER_POLLS, addresses_outside_the_lab,
        not_run, write_record,
    },
    banners_verify::{self as bv, Case},
    capture::{self, IPV6_PREFIX},
    ipv6_suite::{ipv6_outside_the_lab, ipv6_stack},
    ipv6_verify as iv,
    protocols_suite::{
        CAT, SuiteDef, linux_entry_def, linux_with_def, peer_stack_with, run_cases, run_def,
        selected_of, step, write_step_argv,
    },
    protocols_verify::StepSpec,
    windows_suite::{SuiteError, read_json},
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
            let mut bad = addresses_outside_the_lab(&s.argv);
            bad.extend(ipv6_outside_the_lab(&s.argv));
            if !bad.is_empty() {
                return Err(not_run(format!(
                    "{tag}/{} names addresses outside 198.18.0.0/24 and {IPV6_PREFIX}: {bad:?}",
                    s.name
                )));
            }
        }
    }
    attested_stand(&out)?;
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
    // The stand's IPv6 before anything starts (the TCP cases over IPv6): a tentative address refuses every case now.
    let six = ipv6_stack(&suite).map_err(|e| {
        not_run(format!(
            "the stand's IPv6 could not be read ({e}); nothing was started"
        ))
    })?;
    if let Some(p) = iv::stack_problem(&six) {
        return Err(not_run(format!(
            "the stand's IPv6 is not ready: {p}; nothing was started"
        )));
    }
    run_cases(
        &suite,
        &tags,
        &BANNERS_SUITE,
        &out,
        sc,
        |tag, base, run, t| {
            let (Some(c), Some(specs)) = (bv::any_case(tag), bv::steps(tag)) else {
                return Err(not_run(format!("{tag} is not a case")));
            };
            one(&suite, &c, &specs, base, run, t)
        },
    )
}

/// `wire-lab.sh`'s own `isolation.json` in `out`: the sealed IPv6 stand of the banners window.
fn attested_stand(out: &Path) -> Result<(), SuiteError> {
    let iso = read_json(out.join(bv::ISOLATION_JSON)).map_err(|e| {
        not_run(format!(
            "wire-lab.sh's isolation.json is missing ({e}); the suite runs only inside {SUITE}"
        ))
    })?;
    if !capture::isolation_permits_ipv6(&iso) {
        return Err(not_run(format!(
            "isolation.json does not attest the sealed banners stand of {SUITE} (mode {}, ipv6 {})",
            iso["mode"], iso["ipv6"]["prefix"]
        )));
    }
    Ok(())
}

/// The peer namespace's TCP setting the TCP cases rely on (`banners_verify::PeerTcp`), read with `cat`.
fn peer_tcp(l: &Linux) -> Result<bv::PeerTcp, String> {
    let o = l.host.exec(
        &l.ns(&l.ns_b, [CAT.to_owned(), bv::TW_BUCKETS.to_owned()]),
        ad::EXEC_TIMEOUT,
    )?;
    if o.rc != 0 {
        return Err(format!(
            "{}: exit {}: {}",
            bv::TW_BUCKETS,
            o.rc,
            o.stderr.trim()
        ));
    }
    Ok(bv::PeerTcp {
        tcp_max_tw_buckets: o.stdout.trim().to_owned(),
    })
}

/// Before a step of a resolve case: the peer namespace forgets the case's source (`ip neigh flush to`), so that it
/// resolves it afresh with this step's scanner (`banners_verify::RESOLVE_SOURCE`, `RESOLVE_SOURCE6`).
fn forget_source(l: &Linux, tag: &str, src: std::net::IpAddr) -> Result<(), SuiteError> {
    let mut argv: Vec<String> = vec![IP.into(), "-n".into(), l.ns_b.clone()];
    if src.is_ipv6() {
        argv.push("-6".into());
    }
    argv.extend(["neigh", "flush", "to", &src.to_string(), "dev", "veth-b"].map(str::to_owned));
    let o = l.host.exec(&argv, ad::EXEC_TIMEOUT).map_err(|e| {
        not_run(format!(
            "{tag}: the peer's entry for {src} could not be flushed ({e})"
        ))
    })?;
    if o.rc != 0 {
        return Err(not_run(format!(
            "{tag}: ip neigh flush to {src} exit {}: {}; the scanner was not started",
            o.rc,
            o.stderr.trim()
        )));
    }
    Ok(())
}

/// One case: the seal, the peer stack, the case's records, every step in order, the seal again.
fn one(
    l: &Linux,
    c: &Case,
    specs: &[StepSpec],
    base: &Path,
    run: &Path,
    t: &mut LinuxTools,
) -> Result<(), SuiteError> {
    let tag = c.tag();
    ad::binaries_unchanged(&l.binaries)?;
    l.isolation_mode(&run.join(bv::ISOLATION_JSON), "ipv6")
        .map_err(|e| {
            not_run(format!(
                "{tag}: the sealed banners stand is not proven ({e}); nothing was started"
            ))
        })?;
    let options = bv::responder_args_for(c);
    let stack = peer_stack_with(l, options.clone()).map_err(|e| {
        not_run(format!(
            "{tag}: the peer stack could not be read ({e}); nothing was started"
        ))
    })?;
    write_record(&run.join(bv::PEER_STACK_JSON), &stack)?;
    if let Some(p) = bv::peer_stack_problem_for(&stack, c) {
        return Err(not_run(format!("{tag}: {p}; nothing was started")));
    }
    if let Case::Tcp(_) = c {
        let tcp = peer_tcp(l).map_err(|e| {
            not_run(format!(
                "{tag}: the peer's TCP settings could not be read ({e}); nothing was started"
            ))
        })?;
        write_record(&run.join(bv::PEER_TCP_JSON), &tcp)?;
        if let Some(p) = bv::peer_tcp_problem(&tcp) {
            return Err(not_run(format!("{tag}: {p}; nothing was started")));
        }
    }
    let expect = bv::expect(tag).ok_or_else(|| not_run(format!("{tag} is not a case")))?;
    write_record(&run.join(bv::EXPECT_JSON), &expect)?;
    write_step_argv(run, specs)?;
    for s in specs {
        if let Case::Tcp(tc) = c
            && tc.resolve
        {
            forget_source(l, tag, tc.source())?;
        }
        step(l, tag, s, base, run, t, &options)?;
    }
    if let Some(mut p) = t.responder.take() {
        ad::stop(p.as_mut(), "TERM", &l.pause(), RESPONDER_POLLS);
    }
    // The seal after the case: a stand that changed stops the suite (the run is kept under runs_aborted).
    l.isolation_mode(&run.join(bv::ISOLATION_POST_JSON), "ipv6")
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
