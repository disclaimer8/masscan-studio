//! `ipv6-suite linux`: the live runs of the IPv6 acceptance on the sealed Linux netns stand that `wire-lab.sh --suite
//! ipv6` raises: the autodetect stand with IPv6 on the lab veth pair only (`capture::check_ipv6_side`). Every planned
//! case of the verifier's table (`ipv6_verify::steps`; no case is defined here) becomes one `runs/<tag>/` directory that
//! `ipv6-verify` judges offline: `expect.json`, `ipv6-stack.json`, `isolation.json`, `isolation-post.json`,
//! `hashes-before-copy.txt`, and per step `argv.json`, the scanner's `stdout.txt stderr.txt exit.txt`, its document under
//! the table's neutral name, the peer witness `peer.pcap capture.json peer.err` and `responder.json`.
//!
//! The driver is the protocols suite's (`protocols_suite::step`: one restarted responder and one witness per step, the
//! scanner in its own working directory, the oracle under a masked `/etc/masscan`) on the other Linux suites' stand
//! machinery (`autodetect_suite::Linux`). Differences: the seal is `capture isolation --mode ipv6`, the responder adds
//! IPv6 listeners (`ipv6_verify::responder_args`), and before anything starts and again before every case the suite
//! reads the stand's IPv6 ([`ipv6_stack`]: each lab veth's IPv6 settings and addresses with their flags) and refuses
//! (NOT RUN) while an address is tentative or anything else is not the stand's. Every target is in `198.18.0.0/24` or
//! `fd00:198:18::/64`.
use crate::{
    autodetect_suite::{
        self as ad, IP, Linux, LinuxHost, LinuxTools, RESPONDER_POLLS, addresses_outside_the_lab,
        io, not_run, say, write_record,
    },
    autodetect_verify::ArgvRecord,
    capture::{self, IPV6_PREFIX, IPV6_SYSCTLS},
    ipv6_verify::{self as iv, CaseSpec, Ipv6Stack, SideStack, StepSpec},
    protocols_suite::{CAT, step},
    windows_suite::{SuiteError, options_for, read_json, required},
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    net::Ipv6Addr,
    path::{Path, PathBuf},
};

/// `wire-lab.sh`'s mode that raises the stand for this suite.
const SUITE: &str = "wire-lab.sh --suite ipv6";
const USAGE: &str = "ipv6-suite linux --out DIR --work DIR --ns-a NS --ns-b NS --iface-a IF --iface-b IF --mac-a MAC --mac-b MAC --rmasscan PATH --oracle PATH --conf-masked 0|1 --lab-id ID [--only TAG ...]   (run by wire-lab.sh --suite ipv6, as root)
exit 0 every selected run executed, 2 NOT RUN, 10 ABORT, 13 ISOLATION BREACH, 130 INTERRUPTED; judge the directory with ipv6-verify";

/// The cases to run: the whole table in its order, or the `--only` subset of it.
fn selected(only: &[String]) -> Result<Vec<&'static str>, SuiteError> {
    let all = iv::planned_tags();
    if let Some(t) = only.iter().find(|t| !all.contains(&t.as_str())) {
        return Err(not_run(format!(
            "{t} is not an ipv6 case ({})",
            all.join(" ")
        )));
    }
    Ok(all
        .into_iter()
        .filter(|t| only.is_empty() || only.iter().any(|o| o == t))
        .collect())
}

/// Every IPv6 address, `a-b` range (bracketed or not) or CIDR block an argv names outside `fd00:198:18::/64` (a
/// prefix shorter than /64 included), and anything with a `:` that is no IPv6 address. MACs (`02-aa-..`) are not
/// addresses; IPv4 is [`addresses_outside_the_lab`]'s.
pub(crate) fn ipv6_outside_the_lab(argv: &[String]) -> Vec<String> {
    let inside = |s: &str| {
        s.trim_matches(|c| c == '[' || c == ']')
            .parse::<Ipv6Addr>()
            .is_ok_and(|a| a.segments()[..4] == [0xfd00, 0x198, 0x18, 0])
    };
    let mut bad = Vec::new();
    for arg in argv {
        let value = arg.split_once('=').map_or(arg.as_str(), |(_, v)| v);
        for item in value.split(',').filter(|i| i.contains(':')) {
            let ok = if let Some((a, n)) = item.split_once('/') {
                inside(a) && n.parse::<u8>().is_ok_and(|n| (64..=128).contains(&n))
            } else if let Some((a, b)) = item.split_once("]-[").or_else(|| item.split_once('-')) {
                inside(a) && inside(b)
            } else {
                inside(item)
            };
            if !ok {
                bad.push(item.to_owned());
            }
        }
    }
    bad
}

/// `wire-lab.sh`'s own `isolation.json` in `out`: the sealed IPv6 stand.
fn attested_stand(out: &Path) -> Result<(), SuiteError> {
    let iso = read_json(out.join("isolation.json")).map_err(|e| {
        not_run(format!(
            "wire-lab.sh's isolation.json is missing ({e}); the suite runs only inside {SUITE}"
        ))
    })?;
    if !capture::isolation_permits_ipv6(&iso) {
        return Err(not_run(format!(
            "isolation.json does not attest the sealed IPv6 stand (mode {}, ipv6 {})",
            iso["mode"], iso["ipv6"]["prefix"]
        )));
    }
    Ok(())
}

/// `ipv6-suite linux`, inside the lab `wire-lab.sh --suite ipv6` sealed. `lab` is this binary.
pub(crate) fn linux_with(
    args: &[String],
    host: &dyn LinuxHost,
    lab: &Path,
) -> Result<i32, SuiteError> {
    let o = options_for("ipv6-suite linux", args, ad::LINUX_OPTIONS)?;
    if o.contains_key("help") {
        say(USAGE);
        return Ok(0);
    }
    let euid = host.euid()?;
    if euid != 0 {
        return Err(not_run(format!(
            "ipv6-suite linux runs as root inside {SUITE} (effective uid {euid}); it never calls sudo itself"
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
        for s in iv::steps(tag).unwrap_or_default() {
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
    let plan = ("ipv6", json!("linux"), "ipv6-suite linux");
    let suite = ad::linux_driver(
        host,
        lab,
        out.clone(),
        work,
        a,
        sc,
        &tags,
        plan,
        iv::verify_dir,
    )?;
    // The stand's IPv6 before anything starts: a tentative address (DAD still running) or any other state that is not
    // the stand's refuses every case now.
    let stack = ipv6_stack(&suite).map_err(|e| {
        not_run(format!(
            "the stand's IPv6 could not be read ({e}); nothing was started"
        ))
    })?;
    if let Some(p) = iv::stack_problem(&stack) {
        return Err(not_run(format!(
            "the stand's IPv6 is not ready: {p}; nothing was started"
        )));
    }
    for tag in &tags {
        if host.stopped() {
            return Err(SuiteError::Interrupted(format!(
                "stop requested before {tag} started; nothing was left running"
            )));
        }
        let (Some(c), Some(specs)) = (iv::case(tag), iv::steps(tag)) else {
            continue;
        };
        suite.one_with(tag, |base, run, t| one(&suite, &c, &specs, base, run, t))?;
        say(&format!("done {0} -> runs/{0}", tag));
    }
    say(&sc.str(&format!(
        "all selected runs executed; verify offline with rmasscan-lab ipv6-verify --dir {}",
        out.display()
    )));
    Ok(0)
}

/// The stand's IPv6, read in each namespace: the lab veth's [`IPV6_SYSCTLS`] (one `cat` of their `/proc` files) and
/// its addresses with their flags (`ip -6 -j addr show dev <veth>`), and the responder the suite starts.
pub(crate) fn ipv6_stack(l: &Linux) -> Result<Ipv6Stack, String> {
    let side = |ns: &str, iface: &str| -> Result<SideStack, String> {
        let mut cat = vec![CAT.to_owned()];
        cat.extend(
            IPV6_SYSCTLS
                .iter()
                .map(|(k, _)| format!("/proc/sys/net/ipv6/conf/{iface}/{k}")),
        );
        let o = l.host.exec(&l.ns(ns, cat), ad::EXEC_TIMEOUT)?;
        if o.rc != 0 {
            return Err(format!("{CAT} exit {}: {}", o.rc, o.stderr.trim()));
        }
        let values: Vec<&str> = o.stdout.lines().map(str::trim).collect();
        let sysctls = IPV6_SYSCTLS
            .iter()
            .enumerate()
            .map(|(i, (k, _))| {
                (
                    (*k).to_owned(),
                    values.get(i).copied().unwrap_or("").to_owned(),
                )
            })
            .collect();
        let argv: Vec<String> = [IP, "-n", ns, "-6", "-j", "addr", "show", "dev", iface]
            .map(str::to_owned)
            .to_vec();
        let o = l.host.exec(&argv, ad::EXEC_TIMEOUT)?;
        if o.rc != 0 {
            return Err(format!("ip -6 addr exit {}: {}", o.rc, o.stderr.trim()));
        }
        let v = serde_json::from_str(&o.stdout).map_err(|e| format!("ip -6 -j addr: {e}"))?;
        Ok(SideStack {
            iface: iface.to_owned(),
            sysctls,
            addresses: iv::addresses_of(&v)?,
        })
    };
    Ok(Ipv6Stack {
        scanner: side(&l.ns_a, "veth-a")?,
        peer: side(&l.ns_b, "veth-b")?,
        responder: iv::responder_args(),
    })
}

/// One case: the seal, the stand's IPv6, the case's records, every step in order, the seal again.
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
    l.isolation_mode(&run.join(iv::ISOLATION_JSON), "ipv6")
        .map_err(|e| {
            not_run(format!(
                "{tag}: the sealed IPv6 stand is not proven ({e}); nothing was started"
            ))
        })?;
    let stack = ipv6_stack(l).map_err(|e| {
        not_run(format!(
            "{tag}: the stand's IPv6 could not be read ({e}); nothing was started"
        ))
    })?;
    write_record(&run.join(iv::IPV6_STACK_JSON), &stack)?;
    if let Some(p) = iv::stack_problem(&stack) {
        return Err(not_run(format!(
            "{tag}: the stand's IPv6 is not ready: {p}; nothing was started"
        )));
    }
    let expect = iv::expect(tag).ok_or_else(|| not_run(format!("{tag} is not a case")))?;
    write_record(&run.join(iv::EXPECT_JSON), &expect)?;
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
    let options = iv::responder_args();
    for s in specs {
        step(l, tag, s, base, run, t, &options)?;
    }
    if let Some(mut p) = t.responder.take() {
        ad::stop(p.as_mut(), "TERM", &l.pause(), RESPONDER_POLLS);
    }
    l.isolation_mode(&run.join(iv::ISOLATION_POST_JSON), "ipv6")
        .map_err(|e| {
            SuiteError::Abort(format!(
                "{tag}: the stand is not sealed after the run ({e}); no further run"
            ))
        })
}

/// The Linux suite, refused at once off Linux. One code path on every OS: it is compiled and linted everywhere.
fn linux_entry(args: &[String], exe: &Path) -> Result<i32, SuiteError> {
    if !cfg!(target_os = "linux") {
        return Err(not_run(format!(
            "ipv6-suite linux runs on the Linux lab host, inside {SUITE}"
        )));
    }
    linux_with(args, &ad::RealLinux, exe)
}

/// `ipv6-suite linux ...`: 0 every selected run executed, 2 NOT RUN, 10 ABORT, 13 ISOLATION BREACH, 130 INTERRUPTED.
/// Whether a run passed is `ipv6-verify`'s verdict, never this exit code.
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
            "unknown stand {other}; the ipv6 suite runs on linux"
        ))),
    })
}

#[cfg(test)]
#[path = "ipv6_suite_tests.rs"]
mod tests;
