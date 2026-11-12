//! The verifier machinery the protocols suite and the IPv6 suite share (R22): on the sealed Linux netns stand a case is
//! a list of steps, for every output document of the case one rmasscan run and one run of the C oracle, each with its
//! own peer capture. What differs between the two suites (the case table, what a frame is, the records, the stand's
//! answers, the seal, the case's own records, the named deviations) is a [`PairPlan`]; everything else is here, once:
//! the steps of a table, the text documents, a step's files ([`Side`]), the checks of a rmasscan step's stderr and
//! document, the step loop of the judge (own-wire order, the plan, rmasscan against C), privacy, the evidence gate,
//! the case directory, the evidence directory and the `*-verify` command.
//!
//! The rules are those of `protocols-verify` (and through it of `autodetect-verify` and `scan-control-verify`): a
//! missing input is NOT RUN, unproven evidence INVALID, a lab frame off the stand a safety FAIL, rmasscan's misbehaviour
//! a FAIL once the evidence is proven, the oracle's an INVALID, and no verdict is ever promoted. The check names and
//! details the protocols verifier wrote before this module existed are kept byte for byte.
use crate::{
    autodetect_verify::{self as av, ArgvRecord, MANIFEST_JSON, Plan, Stand},
    macos_verify::{Tree, hashes_match_tree, tree},
    output_verify::{fields, text_lines},
    pcap::Frames,
    protocols_verify::{
        EXPECT_JSON, ExpectStep, JSON_REC, LIST_REC, Out, PEER_FILES, REPLY_REORDER_WINDOW_US,
        RESPONDER_JSON, ResponderRecord, Shown, StepSpec, evidence_extension, first_difference,
        in_reply_order, responder_problem, shown,
    },
    scan_control_verify::{self as sv, Who},
    verify::{self, FAIL, INVALID, NOT_RUN, PASS, Run, array, read_json, s},
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, fs, path::Path};

// ------------------------------------------------------------------ what a plan defines

/// A record of a document: what the comparisons need of it.
pub trait Record: Clone + PartialEq + Ord + Shown {
    /// The record's time, when its format carries one.
    fn ts(&self) -> Option<u64>;
}
/// One capture of one step, taken apart by the plan.
pub trait StepView {
    /// The probes the scanner put on the wire, in send order.
    fn probe_frames(&self) -> Vec<Vec<u8>>;
}
/// A document taken apart.
#[derive(Debug, Clone)]
pub struct Doc<R> {
    pub records: Vec<R>,
    /// The footer is written (always for the interactive form).
    pub complete: bool,
}
impl<R> Default for Doc<R> {
    fn default() -> Self {
        Doc {
            records: Vec::new(),
            complete: false,
        }
    }
}
/// What the step loop counts for the plan's deviations: probe pairs equal only by a named rule, C's records collapsed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Tally {
    pub by_rule: usize,
    pub collapsed: usize,
}
/// The fields of [`Doc`]'s text forms in the order the record parser takes them: status, protocol, address, port,
/// time, reason, ttl.
pub type FieldRec<R> =
    fn(&str, &str, &str, &str, &str, Option<&str>, Option<&str>) -> Result<R, String>;

/// One suite's part of the verifier.
pub(crate) trait PairPlan {
    type Case: Copy;
    type View: StepView;
    type Rec: Record;
    type Expect: DeserializeOwned + PartialEq + std::fmt::Debug;
    /// The plan's key in `manifest.json` and the prefix of its command: `protocols`, `ipv6`.
    const KEY: &'static str;
    /// The plan's own case record whose addresses must be the stand's, besides [`STEP_TEXT`].
    const SCANNER_TEXT: &'static [&'static str];
    /// Why rmasscan's document and the oracle's are compared as multisets (`notes.record_order_vs_c.rule`).
    const RECORD_ORDER_VS_C: &'static str;
    /// The named scanner-side frame classes (`notes.scanner_frame_classes`).
    const SCANNER_CLASSES: &'static [(&'static str, &'static str)];
    /// The rule the probes of the two steps are compared under, appended to that check's name.
    const PROBES_VS_C: &'static str;
    /// Whether that check's detail names the first probe that differs (`, first difference at Some(i)`).
    const PROBES_FIRST_DIFFERENCE: bool;
    /// What the stand's SYN safety check counts (`av::foreign_syns`: IPv4 SYNs), as its name says it.
    const FOREIGN_SYN: &'static str;
    /// The own-wire check's name.
    const OWN_WIRE: &'static str;
    /// `notes.oracle`.
    const ORACLE_NOTE: &'static str;

    fn cases() -> Vec<Self::Case>;
    fn tag(c: &Self::Case) -> &'static str;
    fn steps(c: &Self::Case) -> Vec<StepSpec>;
    fn expect(c: &Self::Case) -> Option<Self::Expect>;
    /// `manifest.json` names this plan: `Some(lab id)`.
    fn manifest(v: Value) -> Option<Option<String>>;
    fn view(c: &Self::Case, fr: &Frames, st: &Stand) -> Self::View;
    fn parse_doc(out: Out, b: &[u8]) -> Result<Doc<Self::Rec>, String>;
    /// Frames of the scanner off the stand (a safety finding).
    fn foreign(fr: &Frames, st: &Stand) -> Vec<String>;
    /// What a text file names beyond `token_problems`' allowlist.
    fn text_problems(text: &str, scanner_text: bool) -> Vec<String>;
    /// What an `-oB` file names outside the stand.
    fn binary_problems(b: &[u8]) -> Vec<String>;
    /// The stand's seal before and after the case.
    fn seal(r: &mut Run, d: &Path);
    /// The case's own records (its stack), after `expect.json`, the argv and the responders.
    fn case_records(r: &mut Run, d: &Path, c: &Self::Case);
    /// The probes of the case from the product's plan.
    fn plan(c: &Self::Case) -> Result<Vec<Vec<u8>>, String>;
    /// The checks of one capture (the stand's answers, the scanner's frames) and the step's `notes.scanner_frames`.
    fn step_wire(
        r: &mut Run,
        c: &Self::Case,
        s: &Side<Self::View>,
        v: &Self::View,
    ) -> Map<String, Value>;
    /// A rmasscan step's own checks ([`rmasscan_step`] and the plan's case checks).
    fn rmasscan_step(
        r: &mut Run,
        c: &Self::Case,
        s: &Side<Self::View>,
        doc: Option<&Doc<Self::Rec>>,
    );
    /// The records a scanner reports for the replies of its wire, in reply order, with the capture times.
    fn wire_records_at(c: &Self::Case, v: &Self::View, who: Who, out: Out)
    -> Vec<(Self::Rec, f64)>;
    /// A document's record as its own wire is judged against it (time aside, and what the plan masks).
    fn doc_record(x: &Self::Rec, who: Who) -> Self::Rec;
    /// rmasscan's probe and C's are the same probe: `Some(true)` when only a named rule made them equal.
    fn same_probe(rm: &[u8], c: &[u8]) -> Option<bool>;
    /// rmasscan's records and C's as they are compared, how many of C's were collapsed, the check name's suffix.
    fn vs_c(
        c: &Self::Case,
        rm: &[Self::Rec],
        oracle: &[Self::Rec],
    ) -> (Vec<Self::Rec>, Vec<Self::Rec>, usize, &'static str);
    /// After the step loop: the plan's case checks, deviations and notes.
    fn finish(
        r: &mut Run,
        c: &Self::Case,
        sides: &[Side<Self::View>],
        docs: &[Option<Doc<Self::Rec>>],
        tally: Tally,
    );
}

// ------------------------------------------------------------------ the case table

/// The steps of a case: per document of `outs`, one rmasscan step and one oracle step, each with `argv(out, who)`.
pub fn pair_steps(outs: &[Out], argv: impl Fn(Out, Who) -> Vec<String>) -> Vec<StepSpec> {
    let mut v = Vec::new();
    for out in outs {
        for who in [Who::Rmasscan, Who::Oracle] {
            v.push(StepSpec {
                name: out.step(who),
                who,
                out: *out,
                argv: argv(*out, who),
            });
        }
    }
    v
}
/// The steps as `expect.json` lists them.
pub fn expect_steps(steps: &[StepSpec]) -> Vec<ExpectStep> {
    steps
        .iter()
        .map(|s| ExpectStep {
            name: s.name.into(),
            who: s.who,
            out: s.out,
        })
        .collect()
}

// ------------------------------------------------------------------ documents

pub fn each<R>(
    lines: &[&str],
    parse: impl Fn(&str) -> Result<R, String>,
) -> Result<Vec<R>, String> {
    lines
        .iter()
        .map(|l| parse(l).map_err(|e| format!("{l:?}: {e}")))
        .collect()
}
/// A document of `out` in its C form: an empty file is a document without a record; the text forms (`out-text.c`,
/// `out-json.c`) are parsed here with `field` making each record; `other` parses every other form into the document;
/// a file that stops after a record, without its footer, is not `complete`; a header without a record is an error.
pub fn parse_doc_with<R>(
    out: Out,
    b: &[u8],
    field: FieldRec<R>,
    other: impl FnOnce(&[u8], &mut Doc<R>) -> Result<(), String>,
) -> Result<Doc<R>, String> {
    if b.is_empty() {
        return Ok(Doc {
            records: Vec::new(),
            complete: true,
        });
    }
    let mut d = Doc::default();
    match out {
        Out::List => {
            let lines = text_lines(b, "\n")?;
            if lines[0] != "#masscan" {
                return Err("no `#masscan` header".into());
            }
            d.complete = lines.len() > 1 && lines.last() == Some(&"# end");
            let body = &lines[1..lines.len() - usize::from(d.complete)];
            d.records = each(body, |l| {
                let f = fields(LIST_REC, l).ok_or("not the record form")?;
                field(f[0], f[1], f[3], f[2], f[4], None, None)
            })?;
        }
        Out::Json => {
            let lines = text_lines(b, "\n")?;
            if lines[0] != "[" {
                return Err("no `[` header".into());
            }
            d.complete = lines.len() > 1 && lines.last() == Some(&"]");
            let body = &lines[1..lines.len() - usize::from(d.complete)];
            if body.len().is_multiple_of(2) || body.iter().skip(1).step_by(2).any(|l| *l != ",") {
                return Err("the records are not separated by `,` lines".into());
            }
            let recs: Vec<&str> = body.iter().step_by(2).copied().collect();
            d.records = each(&recs, |l| {
                let f = fields(JSON_REC, l).ok_or("not the record form")?;
                field(f[4], f[3], f[0], f[2], f[1], Some(f[5]), Some(f[6]))
            })?;
        }
        Out::Binary | Out::Stdout => other(b, &mut d)?,
    }
    if d.records.is_empty() && out != Out::Stdout {
        return Err(
            "a header without a record (the header is written with the first record)".into(),
        );
    }
    Ok(d)
}

// ------------------------------------------------------------------ what a step left

pub struct Side<V> {
    pub spec: StepSpec,
    pub exit: Option<i32>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub(crate) se: sv::Stderr,
    pub view: Option<V>,
    /// The raw capture, for the safety checks.
    pub frames: Option<Frames>,
    /// The document's bytes (stdout for the interactive form).
    pub raw: Option<Vec<u8>>,
    pub forced_exit: bool,
}

pub(crate) fn read_side<V>(
    r: &mut Run,
    d: &Path,
    spec: &StepSpec,
    links: &[String],
    view: impl FnOnce(&Frames, &Stand) -> V,
) -> Side<V> {
    let name = spec.name;
    let sd = d.join(name);
    let rel = |f: &str| format!("{name}/{f}");
    let exit = av::need(r, &sd, "exit.txt").and_then(|t| {
        let rc = av::parse_exit(&t);
        if rc.is_none() {
            r.inv(
                &format!("{name}/exit.txt holds an exit code"),
                false,
                t.trim(),
            );
        }
        rc
    });
    let stdout = av::need(r, &sd, "stdout.txt");
    let stderr = av::need(r, &sd, "stderr.txt");
    let st = av::stand(Plan::Linux);
    let cap = av::capture(r, d, &rel(PEER_FILES[0]), links);
    if let Some(cp) = &cap {
        av::witness(r, d, &rel(PEER_FILES[0]), &rel(PEER_FILES[1]), cp, &st);
    }
    let raw = match spec.out.file() {
        Some(n) => {
            let b = fs::read(sd.join(n)).ok();
            if b.is_none() {
                sv_beh(r, spec, &format!("{n} written"), false, "missing");
            }
            b
        }
        None => fs::read(sd.join("stdout.txt")).ok(),
    };
    let se = stderr.as_deref().map(sv::parse_stderr).unwrap_or_default();
    Side {
        spec: spec.clone(),
        exit,
        forced_exit: spec.who == Who::Oracle && stderr.as_deref().is_some_and(sv::forced_exit),
        stdout,
        stderr,
        se,
        view: cap.as_ref().map(|(fr, _)| view(fr, &st)),
        frames: cap.map(|(fr, _)| fr),
        raw,
    }
}

// ------------------------------------------------------------------ checks

/// rmasscan's misbehaviour FAILs; a broken oracle is a broken stand (INVALID).
pub(crate) fn sv_beh(r: &mut Run, spec: &StepSpec, name: &str, ok: bool, detail: impl ToString) {
    let name = format!("{}: {name}", spec.name);
    match spec.who {
        Who::Rmasscan => r.beh(&name, ok, detail),
        Who::Oracle => r.inv(&name, ok, detail),
    }
}
pub(crate) fn beh<V>(r: &mut Run, s: &Side<V>, name: &str, ok: bool, detail: impl ToString) {
    sv_beh(r, &s.spec, name, ok, detail);
}
/// A check against the capture: FAIL only once the evidence is proven (rmasscan); INVALID for the oracle.
pub(crate) fn cap<V>(r: &mut Run, s: &Side<V>, name: &str, ok: bool, detail: impl ToString) {
    let name = format!("{}: {name}", s.spec.name);
    match s.spec.who {
        Who::Rmasscan => r.cap(&name, ok, detail),
        Who::Oracle => r.inv(&name, ok, detail),
    }
}

/// What a rmasscan step's `[+] finished` line and its record times are held to on its wire.
#[derive(Debug, Clone, Copy)]
pub struct WireSummary {
    /// (probes, distinct replies as rmasscan reports them, open among them).
    pub counts: (u64, u64, u64),
    pub first_probe: Option<f64>,
    pub last_reply: Option<f64>,
}
/// A rmasscan step: exit, stdout, stderr grammar, the plan's `[+]` lines (`detection`), `[+] finished` against the
/// wire and the records' times.
pub(crate) fn rmasscan_step<V, R: Record>(
    r: &mut Run,
    s: &Side<V>,
    doc: Option<&Doc<R>>,
    detection: impl FnOnce(&mut Run, &Side<V>),
    wire: impl FnOnce(&V) -> WireSummary,
) {
    if let Some(rc) = s.exit {
        beh(r, s, "exit.txt is 0", rc == 0, rc);
    }
    if s.spec.out != Out::Stdout
        && let Some(t) = &s.stdout
    {
        beh(
            r,
            s,
            "stdout.txt is empty (a file format silences stdout)",
            t.is_empty(),
            t.len(),
        );
    }
    if s.stderr.is_none() {
        return;
    }
    beh(
        r,
        s,
        "stderr.txt holds only [+] lines and rmasscan's status forms",
        s.se.stray.is_empty(),
        format!("{:?}", s.se.stray),
    );
    detection(r, s);
    let fin = s.se.fin.as_ref();
    beh(
        r,
        s,
        "[+] finished: Completed",
        fin.is_some_and(|f| f.reason == "Completed"),
        format!("{fin:?}"),
    );
    if let Some(v) = &s.view {
        let w = wire(v);
        let want = w.counts;
        cap(
            r,
            s,
            "[+] finished reports sent, replies and open equal to the probes and the distinct replies on the wire",
            fin.map(|f| (f.sent, f.replies, f.open)) == Some(want),
            format!(
                "printed {:?}, wire (sent, replies, open) {want:?}",
                fin.map(|f| (f.sent, f.replies, f.open))
            ),
        );
        if let Some(d) = doc {
            let (lo, hi) = (
                w.first_probe.unwrap_or(0.0) - 2.0,
                w.last_reply.unwrap_or(0.0) + 2.0,
            );
            let off: Vec<u64> = d
                .records
                .iter()
                .filter_map(Record::ts)
                .filter(|t| !(lo..=hi).contains(&(*t as f64)))
                .collect();
            cap(
                r,
                s,
                "every record's time lies within the scan on the wire (2 s either side)",
                off.is_empty(),
                format!("{off:?}"),
            );
        }
    }
}

/// The document of a step: well formed; rmasscan's complete, the oracle's complete or cut by its forced exit.
fn doc_of<P: PairPlan>(r: &mut Run, s: &Side<P::View>) -> Option<Doc<P::Rec>> {
    let raw = s.raw.as_ref()?;
    let what = s.spec.out.file().unwrap_or("stdout.txt");
    match P::parse_doc(s.spec.out, raw) {
        Ok(d) => {
            beh(
                r,
                s,
                &format!("{what} is a well-formed document"),
                true,
                format!("{} records", d.records.len()),
            );
            if !d.complete {
                beh(
                    r,
                    s,
                    "its file lacks the footer only after masscan's forced exit (the line is on its stderr)",
                    s.spec.who == Who::Oracle && s.forced_exit,
                    "no footer",
                );
            }
            Some(d)
        }
        Err(e) => {
            beh(r, s, &format!("{what} is a well-formed document"), false, e);
            None
        }
    }
}

/// One case: every step's own checks, then each document's rmasscan step against its oracle step.
fn judge<P: PairPlan>(r: &mut Run, c: &P::Case, sides: &[Side<P::View>]) {
    let plan = match P::plan(c) {
        Ok(p) => Some(p),
        Err(e) => {
            r.inv("the case's plan rebuilds from the case table", false, e);
            None
        }
    };
    let mut docs: Vec<Option<Doc<P::Rec>>> = Vec::new();
    let mut scanner_notes = Map::new();
    // Per step: pairs of records in the other order than their replies on the peer capture, within the window.
    let mut swaps = Map::new();
    for s in sides {
        if let Some(v) = &s.view {
            let counts = P::step_wire(r, c, s, v);
            scanner_notes.insert(s.spec.name.into(), Value::Object(counts));
        }
        let d = doc_of::<P>(r, s);
        match s.spec.who {
            Who::Rmasscan => P::rmasscan_step(r, c, s, d.as_ref()),
            Who::Oracle => {
                if let Some(rc) = s.exit {
                    beh(r, s, "exit.txt is 0", rc == 0, rc);
                }
            }
        }
        if let (Some(v), Some(d)) = (&s.view, &d) {
            let want = P::wire_records_at(c, v, s.spec.who, s.spec.out);
            let got: Vec<P::Rec> = d
                .records
                .iter()
                .map(|x| P::doc_record(x, s.spec.who))
                .collect();
            let order = in_reply_order(&got, &want);
            if let Ok(n) = order {
                swaps.insert(
                    s.spec.name.into(),
                    json!({"pairs": n.pairs, "largest_gap_us": n.largest_gap_us}),
                );
            }
            cap(
                r,
                s,
                P::OWN_WIRE,
                order.is_ok(),
                order.map_or_else(|e| e, |_| shown(&got)),
            );
        }
        if let (Some(v), Some(p), Who::Rmasscan) = (&s.view, &plan, s.spec.who) {
            let act = v.probe_frames();
            let at = act.iter().zip(p).position(|(a, b)| a != b);
            cap(
                r,
                s,
                "the probes on the wire equal the plan (ReadyPlan of the case), in order, each once",
                act == *p,
                format!(
                    "{} probes, {} planned, first difference at {at:?}",
                    act.len(),
                    p.len()
                ),
            );
        }
        docs.push(d);
    }
    // Each document: rmasscan's step against the oracle's step of the same document.
    let mut tally = Tally::default();
    let mut order = Map::new();
    for (i, pair) in sides.chunks(2).enumerate() {
        let [rm, or] = pair else { continue };
        let k = 2 * i;
        if let (Some(a), Some(b)) = (&rm.view, &or.view) {
            let (a, b) = (a.probe_frames(), b.probe_frames());
            let mut same = a.len() == b.len();
            for (x, y) in a.iter().zip(&b) {
                match P::same_probe(x, y) {
                    Some(true) => tally.by_rule += 1,
                    Some(false) => {}
                    None => same = false,
                }
            }
            r.cap(
                &format!(
                    "{}: the probes equal the C oracle's ({}), byte for byte and in order{}",
                    rm.spec.name,
                    or.spec.name,
                    P::PROBES_VS_C
                ),
                same,
                if P::PROBES_FIRST_DIFFERENCE {
                    format!(
                        "{} probes, the oracle {}, first difference at {:?}",
                        a.len(),
                        b.len(),
                        a.iter().zip(&b).position(|(x, y)| x != y)
                    )
                } else {
                    format!("{} probes, the oracle {}", a.len(), b.len())
                },
            );
        }
        if let (Some(Some(x)), Some(Some(y))) = (docs.get(k), docs.get(k + 1)) {
            let (got, want, n, applied) = P::vs_c(c, &x.records, &y.records);
            tally.collapsed += n;
            // The order of each document is its own wire's reply order (judged above, for both scanners); the two
            // wires need not answer in the same order (RECORD_ORDER_VS_C), so the records are compared as a multiset.
            let (mut got_set, mut want_set) = (got.clone(), want.clone());
            got_set.sort();
            want_set.sort();
            let same = got_set == want_set;
            order.insert(
                rm.spec.name.into(),
                json!(match (same, got == want) {
                    (true, true) => "the same records in the same order",
                    (true, false) => "the same records, in another order",
                    (false, _) => "other records",
                }),
            );
            r.cap(
                &format!(
                    "{}: the records equal the C oracle's ({}) field for field but the time, in any order (each document's order is its own wire's reply order, judged above; the two wires' reply orders may differ){applied}",
                    rm.spec.name, or.spec.name,
                ),
                same,
                if same {
                    shown(&got)
                } else {
                    first_difference(&got_set, &want_set)
                },
            );
        }
    }
    r.notes.insert(
        "record_order_vs_c".into(),
        json!({"rule": P::RECORD_ORDER_VS_C, "documents": order}),
    );
    r.notes
        .insert("reply_order_swaps".into(), Value::Object(swaps));
    r.notes.insert(
        "reply_order_window".into(),
        json!(format!(
            "{REPLY_REORDER_WINDOW_US} us: two replies captured on the peer link at most this far apart (rounded to the microsecond; exactly {REPLY_REORDER_WINDOW_US} us is inside) may reach the scanner in the other order (two CPUs send them); reply_order_swaps gives, per step, the pairs of records written in the other order within it (pairs) and the largest gap among them in microseconds (largest_gap_us, null without such a pair)"
        )),
    );
    P::finish(r, c, sides, &docs, tally);
    r.notes.insert(
        "scanner_frame_classes".into(),
        json!(
            P::SCANNER_CLASSES
                .iter()
                .copied()
                .collect::<BTreeMap<_, _>>()
        ),
    );
    r.notes
        .insert("scanner_frames".into(), Value::Object(scanner_notes));
}

/// `notes.scanner_frames.<step>`: the count of every named class, the unexplained frames and the bounds.
pub fn scanner_counts(
    classes: &[(&str, &str)],
    named: &BTreeMap<&'static str, usize>,
    unexplained: usize,
    bounds: &[(&'static str, usize, usize)],
) -> Map<String, Value> {
    let mut counts: Map<String, Value> = classes
        .iter()
        .map(|(k, _)| ((*k).into(), json!(named.get(k).copied().unwrap_or(0))))
        .collect();
    counts.insert("unexplained".into(), json!(unexplained));
    counts.insert(
        "at_most".into(),
        json!(
            bounds
                .iter()
                .map(|(k, _, max)| (*k, *max))
                .collect::<BTreeMap<_, _>>()
        ),
    );
    counts
}

// ------------------------------------------------------------------ privacy and evidence

/// The files a scanner wrote or that name its argv, in either plan: their addresses must be the stand's.
pub const STEP_TEXT: [&str; 7] = [
    "argv.json",
    "expect.json",
    "stdout.txt",
    "stderr.txt",
    "output.txt",
    "output.json",
    "exit.txt",
];
fn privacy<P: PairPlan>(r: &mut Run, d: &Path, files: &[String]) {
    let mut clean = true;
    let mut seen = 0;
    let tags: Vec<&str> = P::cases().iter().map(P::tag).collect();
    for rel in files {
        let ext = Path::new(rel)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        if ext != "bin" && !av::TEXT_EXTENSIONS.contains(&ext) {
            continue;
        }
        let base = rel.rsplit('/').next().unwrap_or(rel);
        let mut p = match fs::read(d.join(rel)) {
            Err(e) => vec![format!("unreadable: {e}")],
            Ok(b) if ext == "bin" => P::binary_problems(&b),
            Ok(b) => {
                // The table's own case names are no host names (`p02_udp_...` reads like a DNS-SD `_udp` label).
                let text = tags
                    .iter()
                    .fold(String::from_utf8_lossy(&b).into_owned(), |t, tag| {
                        t.replace(tag, "<case>")
                    });
                let scanner_text = STEP_TEXT.contains(&base) || P::SCANNER_TEXT.contains(&base);
                let mut p = av::token_problems(&text, scanner_text);
                p.extend(P::text_problems(&text, scanner_text));
                p
            }
        };
        seen += 1;
        p.sort();
        p.dedup();
        if !p.is_empty() {
            clean = false;
            r.inv(
                &format!("privacy: {rel} holds only allowlisted names, addresses and paths"),
                false,
                p.join("; "),
            );
        }
    }
    if clean {
        r.add(
            "privacy: every text and binary file holds only allowlisted names, addresses and paths",
            PASS,
            format!("{seen} files"),
            false,
        );
    }
}
fn gate<P: PairPlan>(r: &mut Run, d: &Path, files: &[String]) {
    match hashes_match_tree(d, true) {
        Ok(()) => r.add(
            "hashes-before-copy.txt matches every file of the case directory",
            PASS,
            files.len(),
            false,
        ),
        Err(e) => r.add(
            "hashes-before-copy.txt matches every file of the case directory",
            INVALID,
            e,
            false,
        ),
    }
    let odd: Vec<&String> = files.iter().filter(|f| !evidence_extension(f)).collect();
    r.inv(
        "evidence files carry only the allowed extensions (json pcap txt log err sha256 md, bin for -oB)",
        odd.is_empty(),
        format!("{odd:?}"),
    );
    P::seal(r, d);
}

// ------------------------------------------------------------------ one case

fn verify_run<P: PairPlan>(root: &Path, c: &P::Case, root_links: &[String]) -> Run {
    let tag = P::tag(c);
    let mut r = Run::new(tag);
    let rel = format!("runs/{tag}");
    if root_links.iter().any(|l| l == "runs" || *l == rel) {
        r.inv(
            "the case directory is a real directory, not a symbolic link",
            false,
            rel,
        );
        return r;
    }
    let d = root.join("runs").join(tag);
    if !d.is_dir() {
        r.add("case directory present", NOT_RUN, "missing", false);
        return r;
    }
    let specs = P::steps(c);
    let t = tree(&d);
    r.safety(
        "no compressed capture in the case directory",
        !t.files.iter().chain(&t.links).any(|f| f.ends_with(".gz")),
        "captures are stored uncompressed; the verifier has no decompression",
    );
    let st = av::stand(Plan::Linux);
    let sides: Vec<Side<P::View>> = specs
        .iter()
        .map(|spec| read_side(&mut r, &d, spec, &t.links, |fr, st| P::view(c, fr, st)))
        .collect();
    for s in &sides {
        if let Some(fr) = &s.frames {
            let who = s.spec.name;
            let n = av::foreign_syns(fr, &st);
            r.safety(
                &format!(
                    "no {} on the {who} capture from outside the stand binding or to an address off the stand",
                    P::FOREIGN_SYN
                ),
                n == 0,
                n,
            );
            let off = P::foreign(fr, &st);
            r.safety(
                &format!("no frame of the scanner on the {who} capture to an address off the stand or from another source"),
                off.is_empty(),
                off.iter().take(3).cloned().collect::<Vec<_>>().join(", "),
            );
            av::no_foreign_frame(&mut r, who, fr, &st);
        }
    }
    if !t.links.is_empty() {
        r.inv(
            "no symbolic link in the case directory (links are never followed)",
            false,
            format!("{:?}", t.links),
        );
        return r;
    }
    gate::<P>(&mut r, &d, &t.files);
    privacy::<P>(&mut r, &d, &t.files);
    let expect_rec: Option<P::Expect> = av::typed(&mut r, &d, EXPECT_JSON);
    let expect_ok = expect_rec.as_ref() == P::expect(c).as_ref();
    if expect_rec.is_some() {
        r.inv(
            "expect.json equals the case table's entry",
            expect_ok,
            format!("table {:?}", P::expect(c)),
        );
    }
    let mut argv_ok = expect_ok;
    for spec in &specs {
        let rec: Option<ArgvRecord> = av::typed(&mut r, &d.join(spec.name), "argv.json");
        if let Some(a) = &rec {
            let ok = a.argv == spec.argv;
            r.inv(
                &format!(
                    "{}/argv.json is the step's argv in the case table",
                    spec.name
                ),
                ok,
                format!("{:?}, table {:?}", a.argv, spec.argv),
            );
            argv_ok &= ok;
        } else {
            argv_ok = false;
        }
    }
    r.argv_ok = argv_ok;
    // A responder that died mid-step is a stand that stopped answering: named here, with its own error.
    for spec in &specs {
        if let Some(rec) = av::typed::<ResponderRecord>(&mut r, &d.join(spec.name), RESPONDER_JSON)
        {
            let problem = responder_problem(&rec);
            r.inv(
                &format!(
                    "{}/{RESPONDER_JSON}: the peer responder ran until the scanner ended",
                    spec.name
                ),
                problem.is_none(),
                problem.unwrap_or_else(|| "it still ran".into()),
            );
        }
    }
    P::case_records(&mut r, &d, c);
    judge::<P>(&mut r, c, &sides);
    r.notes.insert("oracle".into(), json!(P::ORACLE_NOTE));
    r
}

// ------------------------------------------------------------------ the directory

/// Judge an evidence directory of plan `P`: the manifest, every planned case, and a safety walk of everything else.
/// Symbolic links are never followed.
pub(crate) fn verify_dir<P: PairPlan>(root: &Path) -> Value {
    let mut result = json!({"schema":1,"dir":root.file_name().unwrap_or_default().to_string_lossy(),"runs":[],"groups":[],"discarded":[],"aborted":[]});
    let t = tree(root);
    let mut m = Run::new("manifest");
    m.argv_ok = true;
    m.safety(
        "no compressed capture anywhere in the evidence directory",
        !t.files.iter().chain(&t.links).any(|f| f.ends_with(".gz")),
        "captures are stored uncompressed; the verifier has no decompression",
    );
    m.inv(
        "no symbolic link in the evidence directory (links are never followed)",
        t.links.is_empty(),
        format!("{:?}", t.links),
    );
    let manifest = (!t.links.iter().any(|l| l == MANIFEST_JSON))
        .then(|| read_json(root.join(MANIFEST_JSON)))
        .flatten()
        .and_then(P::manifest);
    m.check(
        &format!("manifest.json names the {} plan (linux)", P::KEY),
        manifest.is_some(),
        "",
        NOT_RUN,
        false,
    );
    let cases = if manifest.is_some() {
        P::cases()
    } else {
        Vec::new()
    };
    let tags: Vec<&'static str> = cases.iter().map(P::tag).collect();
    let outside: Vec<String> = t
        .files
        .iter()
        .filter(|f| {
            *f != "verdict.json"
                && !tags
                    .iter()
                    .any(|tag| f.starts_with(&format!("runs/{tag}/")))
        })
        .cloned()
        .collect();
    let odd: Vec<&String> = outside.iter().filter(|f| !evidence_extension(f)).collect();
    m.inv(
        "evidence files outside the runs carry only the allowed extensions (json pcap txt log err sha256 md bin)",
        odd.is_empty(),
        format!("{odd:?}"),
    );
    privacy::<P>(&mut m, root, &outside);
    let unplanned: Vec<&str> = t
        .dirs
        .iter()
        .chain(&t.files)
        .chain(&t.links)
        .filter_map(|p| p.strip_prefix("runs/"))
        .filter(|p| !p.contains('/') && !tags.contains(p))
        .collect();
    m.inv(
        "runs/ holds only the planned case directories",
        unplanned.is_empty(),
        format!("{unplanned:?}"),
    );
    let attempts = av::attempts(&t, |name| av::attempt_of(&tags, name));
    if !attempts.is_empty() {
        let strays: Vec<&str> = attempts
            .iter()
            .filter(|a| a.case.is_none())
            .map(|a| a.name.as_str())
            .collect();
        m.inv(
            "runs_aborted/ holds only attempts of planned cases (<tag>.<run id>)",
            strays.is_empty(),
            format!("{strays:?}"),
        );
    }
    if let Some(id) = &manifest {
        av::teardown(&mut m, root, &t.links, id.as_deref());
    }
    let mut runs = vec![m.summary()];
    runs.extend(cases.iter().map(|c| {
        let mut r = verify_run::<P>(root, c, &t.links);
        let earlier: Vec<String> = attempts
            .iter()
            .filter(|a| a.case == Some(P::tag(c)))
            .map(|a| format!("runs_aborted/{}", a.name))
            .collect();
        if !earlier.is_empty() {
            r.inv(
                "no aborted attempt of this case in runs_aborted/ (a case runs once into one --out)",
                false,
                earlier.join(", "),
            );
        }
        r.summary()
    }));
    result["runs"] = json!(runs);
    result["aborted"] = json!(
        attempts
            .iter()
            .map(av::Attempt::summary)
            .collect::<Vec<_>>()
    );
    result["safety_scan"] = json!(stray_scan::<P>(root, &tags, &t));
    verify::finish(result)
}

/// The captures outside the planned cases (aborted attempts, every step directory under them): `stray_scan`'s SYN and
/// MAC checks, and the plan's frames of the scanner off the stand.
fn stray_scan<P: PairPlan>(root: &Path, tags: &[&'static str], t: &Tree) -> Vec<Value> {
    let planned = |rel: &str| {
        tags.iter()
            .any(|tag| rel.starts_with(&format!("runs/{tag}/")))
    };
    let st = av::stand(Plan::Linux);
    let mut out = av::stray_scan(root, Some(Plan::Linux), tags, t);
    for f in t
        .files
        .iter()
        .filter(|f| f.ends_with(PEER_FILES[0]) && !planned(f))
    {
        let mut r = Run::new(&format!("{f} (every protocol)"));
        r.argv_ok = true;
        if let Some((fr, _)) = verify::load_pcap(&mut r, &root.join(f)) {
            let off = P::foreign(&fr, &st);
            r.safety(
                "no frame of the scanner on the capture to an address off the stand or from another source",
                off.is_empty(),
                off.iter().take(3).cloned().collect::<Vec<_>>().join(", "),
            );
        }
        out.push(r.summary());
    }
    out
}

/// `<KEY>-verify --dir DIR [--out FILE]`: 0 PASS, 1 FAIL, 2 INVALID or NOT RUN.
pub(crate) fn run<P: PairPlan>(args: &[String]) -> Result<i32, String> {
    let name = format!("{}-verify", P::KEY);
    let o = crate::windows_suite::options_for(&name, args, &["dir", "out"])?;
    if o.contains_key("help") {
        println!("{name} --dir DIR [--out FILE]  (exit 0 PASS, 1 FAIL, 2 INVALID or NOT RUN)");
        return Ok(0);
    }
    let dir = crate::windows_suite::required(&o, "dir")?;
    let res = verify_dir::<P>(Path::new(&dir));
    if let Some(out) = o.get("out").and_then(|v| v.first()) {
        fs::write(
            out,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&res).map_err(|e| e.to_string())?
            ),
        )
        .map_err(|e| e.to_string())?;
    }
    for r in array(&res["runs"]) {
        let bad: Vec<_> = array(&r["checks"])
            .iter()
            .filter(|c| c["result"] != PASS)
            .take(3)
            .map(|c| format!("{}: {}", s(&c["result"]), s(&c["name"])))
            .collect();
        println!(
            "{:<8} {} {}",
            s(&r["verdict"]),
            s(&r["tag"]),
            bad.join("; ")
        );
    }
    for line in verify::safety_report_lines(&res) {
        println!("{line}");
    }
    println!("overall: {} {}", s(&res["overall"]), res["totals"]);
    Ok(match s(&res["overall"]) {
        PASS => 0,
        FAIL => 1,
        _ => 2,
    })
}

// ------------------------------------------------------------------ small pieces of both tables and verifiers

/// The case of plan `P` with tag `tag`.
pub(crate) fn case_of<P: PairPlan>(tag: &str) -> Option<P::Case> {
    P::cases().into_iter().find(|c| P::tag(c) == tag)
}
/// The tags of plan `P`'s table, in its order.
pub(crate) fn tags_of<P: PairPlan>() -> Vec<&'static str> {
    P::cases().iter().map(P::tag).collect()
}
/// The part of a scan's argv both tables share, after the targets and the probe flags: the document's flag and file,
/// `--show open,closed` for a case with closed records, `--seed 1 --rate RATE --wait WAIT --source-port PORT`.
pub fn scan_tail(
    a: &mut Vec<String>,
    out: Out,
    show_closed: bool,
    rate: &str,
    wait: &str,
    source_port: u16,
) {
    if let (Some(flag), Some(file)) = (out.flag(), out.file()) {
        a.extend([flag.to_owned(), file.to_owned()]);
    }
    if show_closed {
        a.extend(["--show".to_owned(), "open,closed".to_owned()]);
    }
    let port = source_port.to_string();
    a.extend(
        [
            "--seed",
            "1",
            "--rate",
            rate,
            "--wait",
            wait,
            "--source-port",
            &port,
        ]
        .map(str::to_owned),
    );
}
/// Every probe of `plan`'s adapter 0 in send order (its cursor drained in batches), and the cursor's build error if
/// one stopped it.
pub fn plan_probes(
    plan: &rmasscan_core::probe::ReadyPlan,
) -> Result<(Vec<Vec<u8>>, Option<String>), String> {
    let mut cur = plan.cursor_for_nic(0, None).map_err(|e| e.to_string())?;
    let mut frames = Vec::new();
    loop {
        let batch: Vec<Vec<u8>> = cur.preload(64).iter().map(|p| p.frame.clone()).collect();
        if batch.is_empty() {
            break;
        }
        cur.advance_sent_n(batch.len());
        frames.extend(batch);
    }
    Ok((frames, cur.build_error().map(|e| e.to_string())))
}
/// A step's two checks of the scanner MAC's frames: every one a probe or of a named class (`unexplained` lists the
/// others), and every named class within its bound (`bounds`: class, count, at most). The names are the plan's.
pub(crate) fn scanner_frame_checks<V>(
    r: &mut Run,
    s: &Side<V>,
    unexplained_name: &str,
    unexplained: &[String],
    bounds_name: &str,
    bounds: &[(&'static str, usize, usize)],
) {
    cap(
        r,
        s,
        unexplained_name,
        unexplained.is_empty(),
        format!(
            "{} other frames: {}",
            unexplained.len(),
            unexplained
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ),
    );
    // A named class is judged per frame above; here its count: no more than the scanner side can send.
    cap(
        r,
        s,
        bounds_name,
        bounds.iter().all(|(_, n, max)| n <= max),
        bounds
            .iter()
            .map(|(k, n, max)| format!("{k} {n} of at most {max}"))
            .collect::<Vec<_>>()
            .join(", "),
    );
}
/// Each named deviation of a case (`names`, their rules in `table`): `judge(name)` gives whether the wire condition
/// that keeps it from changing the comparison holds and what was observed; an INVALID check and `notes.deviations`.
pub(crate) fn named_deviations(
    r: &mut Run,
    names: &[&str],
    table: &[(&str, &str)],
    mut judge: impl FnMut(&str) -> (bool, String),
) {
    let mut notes = Vec::new();
    for name in names {
        let rule = table
            .iter()
            .find(|(n, _)| n == name)
            .map_or("", |(_, x)| *x);
        let (ok, observed) = judge(name);
        r.inv(&format!("deviation {name}: {rule}"), ok, &observed);
        notes.push(json!({"name": name, "rule": rule, "observed": observed}));
    }
    r.notes.insert("deviations".into(), json!(notes));
}
