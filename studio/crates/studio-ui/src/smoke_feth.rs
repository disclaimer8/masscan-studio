//! `--smoke-feth`: a state machine that drives the Mac feth profile through the same `Action`s a user's clicks
//! send and records a JSON chronicle of every `Update` it sees. It is platform neutral and touches neither the UI,
//! nor SQLite, nor the runner: the caller feeds it `Update`s and executes the `Step`s it returns.
//!
//! Deviation from the brief's sketch: there is no `Step::Wait`; an empty step list means "nothing to do".
//! The caller turns `Send(Start(job))` into the form path (fill the settings fields, press Start), `Send(Stop)` into
//! the Stop button, and the rest into `Controller::send`; the driver itself only knows `Action`s.
//! On the failure path `Lock` is nominal: the controller ignores it while a scan is active, and the session is
//! closed when the process exits (`Controller` and `Client` drop, the runner stops on disconnect).
use serde::Serialize;
use std::{
    collections::HashSet,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use studio_app::{Action, Update};
use studio_protocol::{Backend, Job, Status, id_text};

/// Pause or Stop is sent this long after `Scanning`.
pub const ACTION_DELAY: Duration = Duration::from_millis(1500);
pub const PHASE_TIMEOUT: Duration = Duration::from_secs(60);
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(200);
pub const TOTAL_DEADLINE: Duration = Duration::from_secs(420);
/// A quiet gap after the last event of a case before the next action, so that the verifier can tell the cases
/// apart by `mono_ms` alone.
pub const SETTLE: Duration = Duration::from_millis(100);

pub struct ScanCase {
    pub tag: &'static str,
    pub job: Job,
    pub pause_after: Option<Duration>,
    pub stop_after: Option<Duration>,
}
pub struct Plan {
    pub scans: Vec<ScanCase>,
}
fn feth_job(ports: &str, seed: &str, rate: u32) -> Job {
    Job {
        targets: "198.18.0.2".into(),
        ports: ports.into(),
        exclusions: String::new(),
        seed: seed.into(),
        rate,
        backend: Backend::MacFeth,
    }
}
impl Plan {
    /// The three cases of one authorized session: a full scan, a pause with resume, a stop.
    pub fn feth() -> Self {
        Self {
            scans: vec![
                ScanCase {
                    tag: "s1_full",
                    job: feth_job("80,443,8000-8007,9000-9009", "1", 100),
                    pause_after: None,
                    stop_after: None,
                },
                ScanCase {
                    tag: "s2_pause",
                    job: feth_job("9000-9031", "2", 4),
                    pause_after: Some(ACTION_DELAY),
                    stop_after: None,
                },
                ScanCase {
                    tag: "s3_stop",
                    job: feth_job("1-2000", "3", 300),
                    pause_after: None,
                    stop_after: Some(ACTION_DELAY),
                },
            ],
        }
    }
}

pub enum Step {
    Send(Action),
    Quit { ok: bool, reason: String },
}

#[derive(Serialize)]
pub struct EventRecord {
    pub utc: String,
    pub mono_ms: i64,
    pub kind: &'static str,
    pub status: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<usize>,
}
#[derive(Serialize)]
pub struct ActionRecord {
    pub utc: String,
    pub mono_ms: i64,
    pub action: String,
}
#[derive(Serialize)]
pub struct CaseRecord {
    pub tag: &'static str,
    pub job: Job,
    pub scan_id_hex: Option<String>,
    pub rows_seen: usize,
    pub started_utc: Option<String>,
    pub finished_utc: Option<String>,
    pub finished_status: Option<String>,
    pub paused_next_index: Option<u64>,
    pub pause_to_paused_ms: Option<i64>,
    pub stop_to_stopped_ms: Option<i64>,
}
#[derive(Serialize)]
pub struct Chronicle {
    pub schema: u32,
    pub started_utc: String,
    pub result: String,
    pub plan: Vec<CaseRecord>,
    pub events: Vec<EventRecord>,
    pub actions: Vec<ActionRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Phase {
    Init,
    Authorize { granted: bool, busy: bool },
    Settle { next: Option<usize>, since: Instant },
    AwaitScanning(usize),
    Scanning(usize, Instant),
    AwaitPaused(usize),
    AwaitPausedHistory(usize),
    AwaitResumed(usize),
    Resumed(usize),
    AwaitStopped(usize),
    AwaitHistory(usize),
    Locking,
    Done,
}

pub struct Driver {
    plan: Plan,
    t0: Instant,
    phase: Phase,
    phase_since: Instant,
    chron: Chronicle,
    rows: HashSet<(String, u16)>,
    /// `mono_ms` of the Pause or Stop action in flight.
    action_mono: i64,
}

impl Driver {
    pub fn new(plan: Plan, now: Instant) -> Self {
        let records = plan
            .scans
            .iter()
            .map(|c| CaseRecord {
                tag: c.tag,
                job: c.job.clone(),
                scan_id_hex: None,
                rows_seen: 0,
                started_utc: None,
                finished_utc: None,
                finished_status: None,
                paused_next_index: None,
                pause_to_paused_ms: None,
                stop_to_stopped_ms: None,
            })
            .collect();
        Self {
            plan,
            t0: now,
            phase: Phase::Init,
            phase_since: now,
            chron: Chronicle {
                schema: 1,
                started_utc: String::new(),
                result: String::new(),
                plan: records,
                events: Vec::new(),
                actions: Vec::new(),
            },
            rows: HashSet::new(),
            action_mono: 0,
        }
    }
    /// The caller could not do what a step asked (for example the settings form did not reproduce the planned
    /// job): ends the run with a recorded failure.
    pub fn abort(&mut self, reason: String, now: Instant, utc: String) -> Vec<Step> {
        let mut out = Vec::new();
        if self.phase != Phase::Done {
            let stop = self.scan_may_run();
            self.fail(reason, stop, now, &utc, &mut out);
        }
        out
    }
    pub fn chronicle(&self) -> &Chronicle {
        &self.chron
    }
    fn mono(&self, now: Instant) -> i64 {
        now.saturating_duration_since(self.t0).as_millis() as i64
    }
    fn set_phase(&mut self, phase: Phase, now: Instant) {
        self.phase = phase;
        self.phase_since = now;
    }
    fn act(&mut self, name: String, now: Instant, utc: &str, out: &mut Vec<Step>, a: Action) {
        let mono = self.mono(now);
        self.chron.actions.push(ActionRecord {
            utc: utc.to_owned(),
            mono_ms: mono,
            action: name,
        });
        self.action_mono = mono;
        out.push(Step::Send(a));
    }
    /// Ends the run with a failure: the session is locked and the reason is the result. `stop_first` also sends
    /// Stop, for a scan that may still be running. `Lock` is nominal here: the controller ignores it while a scan
    /// is active, and the session really ends when the process exits.
    fn fail(
        &mut self,
        reason: String,
        stop_first: bool,
        now: Instant,
        utc: &str,
        out: &mut Vec<Step>,
    ) {
        let reason = scrub(&reason);
        if stop_first {
            self.act("Stop".into(), now, utc, out, Action::Stop);
        }
        self.act("Lock".into(), now, utc, out, Action::Lock);
        self.chron.result = reason.clone();
        self.phase = Phase::Done;
        out.push(Step::Quit { ok: false, reason });
    }
    fn record(&mut self, u: &Update, now: Instant, utc: &str) {
        let (kind, status, detail, authorized, rows) = match u {
            Update::Authorization {
                busy,
                authorized,
                detail,
            } => (
                "Authorization",
                if *busy { "busy" } else { "idle" }.to_owned(),
                detail.clone(),
                Some(*authorized),
                None,
            ),
            Update::State(s, d) => ("State", format!("{s:?}"), d.clone(), None, None),
            Update::Notice(t) => ("Notice", String::new(), t.clone(), None, None),
            Update::Progress(sent, received) => (
                "Progress",
                String::new(),
                format!("sent {sent} received {received}"),
                None,
                None,
            ),
            Update::Rows(v) => ("Rows", String::new(), String::new(), None, Some(v.len())),
            Update::History(v, selected) => (
                "History",
                String::new(),
                format!(
                    "{} scans, selected {}",
                    v.len(),
                    selected.map_or("none".into(), id_text)
                ),
                None,
                None,
            ),
            _ => return,
        };
        self.chron.events.push(EventRecord {
            utc: utc.to_owned(),
            mono_ms: self.mono(now),
            kind,
            status,
            detail: scrub(&detail),
            authorized,
            rows,
        });
    }
    fn case_of(&self) -> Option<usize> {
        match self.phase {
            Phase::AwaitScanning(i)
            | Phase::Scanning(i, _)
            | Phase::AwaitPaused(i)
            | Phase::AwaitPausedHistory(i)
            | Phase::AwaitResumed(i)
            | Phase::Resumed(i)
            | Phase::AwaitStopped(i)
            | Phase::AwaitHistory(i) => Some(i),
            _ => None,
        }
    }
    fn scan_may_run(&self) -> bool {
        matches!(
            self.phase,
            Phase::AwaitScanning(_)
                | Phase::Scanning(..)
                | Phase::AwaitPaused(_)
                | Phase::AwaitResumed(_)
                | Phase::Resumed(_)
                | Phase::AwaitStopped(_)
        )
    }
    /// The case reached a terminal state; its History update is next.
    fn finish(&mut self, i: usize, status: &Status, now: Instant, utc: &str) {
        let r = &mut self.chron.plan[i];
        r.finished_utc = Some(utc.to_owned());
        r.finished_status = Some(format!("{status:?}"));
        self.set_phase(Phase::AwaitHistory(i), now);
    }
    fn on_update(&mut self, u: &Update, now: Instant, utc: &str, out: &mut Vec<Step>) {
        match (self.phase, u) {
            (
                Phase::Authorize { granted, .. },
                Update::Authorization {
                    busy,
                    authorized,
                    detail,
                },
            ) => {
                if *busy {
                    // The system dialog is open; from here on a stored-scan replay can no longer be mistaken
                    // for a failure of this run.
                    self.phase = Phase::Authorize {
                        granted,
                        busy: true,
                    };
                } else if !*authorized {
                    self.fail(
                        format!("Authorization failed: {detail}"),
                        false,
                        now,
                        utc,
                        out,
                    );
                } else {
                    self.phase = Phase::Authorize {
                        granted: true,
                        busy: true,
                    };
                }
            }
            (Phase::Authorize { granted, .. }, Update::Notice(t)) => {
                if t.contains("Network preflight refused") {
                    self.fail(t.clone(), false, now, utc, out);
                } else if t.contains("Network preflight passed") && granted {
                    self.set_phase(
                        Phase::Settle {
                            next: Some(0),
                            since: now,
                        },
                        now,
                    );
                }
            }
            (Phase::Locking, Update::Notice(t)) if t.contains("Runner session closed") => {
                self.chron.result = "ok".into();
                self.phase = Phase::Done;
                out.push(Step::Quit {
                    ok: true,
                    reason: "ok".into(),
                });
            }
            (
                Phase::Authorize { busy: true, .. } | Phase::Locking,
                Update::State(s @ (Status::Failed | Status::Interrupted), detail),
            ) => {
                self.fail(format!("State {s:?}: {detail}"), false, now, utc, out);
            }
            (Phase::Init | Phase::Authorize { .. } | Phase::Locking | Phase::Done, _) => {}
            (
                _,
                Update::Authorization {
                    authorized: false,
                    detail,
                    ..
                },
            ) => {
                let stop = self.scan_may_run();
                self.fail(format!("Authorization lost: {detail}"), stop, now, utc, out);
            }
            (_, Update::Rows(v)) => {
                if let Some(i) = self.case_of() {
                    self.rows
                        .extend(v.iter().map(|s| (s.row.ip.clone(), s.row.port)));
                    self.chron.plan[i].rows_seen = self.rows.len();
                }
            }
            (_, Update::State(s @ (Status::Failed | Status::Interrupted), detail)) => {
                self.fail(format!("State {s:?}: {detail}"), false, now, utc, out);
            }
            (Phase::AwaitScanning(i), Update::State(Status::Scanning, _)) => {
                self.set_phase(Phase::Scanning(i, now), now);
            }
            (Phase::Scanning(i, _), Update::State(s @ Status::Completed, _))
                if self.plan.scans[i].pause_after.is_none()
                    && self.plan.scans[i].stop_after.is_none() =>
            {
                self.finish(i, s, now, utc);
            }
            (Phase::AwaitPaused(i), Update::State(Status::Paused, _)) => {
                let ms = self.mono(now) - self.action_mono;
                self.chron.plan[i].pause_to_paused_ms = Some(ms);
                self.set_phase(Phase::AwaitPausedHistory(i), now);
            }
            (Phase::AwaitResumed(i), Update::State(Status::Scanning, _)) => {
                self.set_phase(Phase::Resumed(i), now);
            }
            (Phase::Resumed(i), Update::State(s @ Status::Completed, _)) => {
                self.finish(i, s, now, utc);
            }
            (Phase::AwaitStopped(i), Update::State(s @ Status::Stopped, _)) => {
                let ms = self.mono(now) - self.action_mono;
                self.chron.plan[i].stop_to_stopped_ms = Some(ms);
                self.finish(i, s, now, utc);
            }
            (Phase::AwaitPausedHistory(i), Update::History(scans, Some(id))) => {
                let next = scans
                    .iter()
                    .find(|s| s.scan == *id && s.status == Status::Paused)
                    .and_then(|s| s.next_index.as_deref())
                    .and_then(|n| n.parse::<u64>().ok());
                let Some(next) = next else {
                    self.fail(
                        "Paused scan has no next_index in history".into(),
                        false,
                        now,
                        utc,
                        out,
                    );
                    return;
                };
                let r = &mut self.chron.plan[i];
                r.scan_id_hex = Some(id_text(*id));
                r.paused_next_index = Some(next);
                self.act("Resume".into(), now, utc, out, Action::Resume);
                self.set_phase(Phase::AwaitResumed(i), now);
            }
            (Phase::AwaitHistory(i), Update::History(_, Some(id))) => {
                self.chron.plan[i].scan_id_hex = Some(id_text(*id));
                let next = (i + 1 < self.plan.scans.len()).then_some(i + 1);
                self.set_phase(Phase::Settle { next, since: now }, now);
            }
            // Harmless repeats: the start of an attempt, a second Scanning, the pause drain, anything after the
            // terminal state of the case.
            (_, Update::State(Status::Starting | Status::Scanning, _))
            | (Phase::AwaitPaused(_), Update::State(Status::Saving, _))
            | (Phase::AwaitHistory(_) | Phase::Settle { .. }, Update::State(..)) => {}
            // Any other state in a running case is a surprise: fail now instead of timing out.
            (_, Update::State(s, d)) => {
                let stop = self.scan_may_run();
                let phase = self.phase;
                self.fail(
                    format!("State {s:?} unexpected in {phase:?}: {d}"),
                    stop,
                    now,
                    utc,
                    out,
                );
            }
            _ => {}
        }
    }
    fn on_tick(&mut self, now: Instant, utc: &str, out: &mut Vec<Step>) {
        let waited = now.saturating_duration_since(self.phase_since);
        match self.phase {
            Phase::Init => {
                self.chron.started_utc = utc.to_owned();
                self.act("Authorize".into(), now, utc, out, Action::Authorize);
                self.set_phase(
                    Phase::Authorize {
                        granted: false,
                        busy: false,
                    },
                    now,
                );
                return;
            }
            Phase::Done => return,
            Phase::Settle { next, since } => {
                if now.saturating_duration_since(since) >= SETTLE {
                    if let Some(i) = next {
                        let (tag, job) = (self.plan.scans[i].tag, self.plan.scans[i].job.clone());
                        self.rows.clear();
                        self.chron.plan[i].started_utc = Some(utc.to_owned());
                        self.act(format!("Start:{tag}"), now, utc, out, Action::Start(job));
                        self.set_phase(Phase::AwaitScanning(i), now);
                    } else {
                        self.act("Lock".into(), now, utc, out, Action::Lock);
                        self.set_phase(Phase::Locking, now);
                    }
                }
                return;
            }
            Phase::Scanning(i, since) => {
                let case = &self.plan.scans[i];
                let after = now.saturating_duration_since(since);
                if case.pause_after.is_some_and(|d| after >= d) {
                    self.act("Pause".into(), now, utc, out, Action::Pause);
                    self.set_phase(Phase::AwaitPaused(i), now);
                    return;
                }
                if case.stop_after.is_some_and(|d| after >= d) {
                    self.act("Stop".into(), now, utc, out, Action::Stop);
                    self.set_phase(Phase::AwaitStopped(i), now);
                    return;
                }
            }
            _ => {}
        }
        let (limit, name) = match self.phase {
            Phase::Authorize { .. } => (AUTH_TIMEOUT, "authorization"),
            _ => (PHASE_TIMEOUT, "phase"),
        };
        let total = now.saturating_duration_since(self.t0);
        let reason = if waited > limit {
            Some(format!(
                "timeout: {name} {:?} exceeded {} s",
                self.phase,
                limit.as_secs()
            ))
        } else if total > TOTAL_DEADLINE {
            Some(format!(
                "timeout: the run exceeded {} s",
                TOTAL_DEADLINE.as_secs()
            ))
        } else {
            None
        };
        if let Some(reason) = reason {
            let stop = self.scan_may_run();
            self.fail(reason, stop, now, utc, out);
        }
    }
    /// One `Update` (or a timer tick when `None`) in, the steps to execute out.
    pub fn step(&mut self, update: Option<&Update>, now: Instant, utc: String) -> Vec<Step> {
        let mut out = Vec::new();
        if let Some(u) = update
            && self.phase != Phase::Done
        {
            self.record(u, now, &utc);
            self.on_update(u, now, &utc, &mut out);
        }
        self.on_tick(now, &utc, &mut out);
        out
    }
}

/// `YYYY-MM-DDTHH:MM:SS.fffZ` for a time since the Unix epoch.
pub fn utc_text(since_epoch: Duration) -> String {
    let secs = since_epoch.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60,
        since_epoch.subsec_millis()
    )
}
pub fn utc_now() -> String {
    utc_text(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default(),
    )
}
/// Replaces user home directories in a text with `$HOME`, so that the chronicle carries no personal paths.
pub fn scrub(text: &str) -> String {
    let mut s = text.to_owned();
    if let Some(home) = std::env::var_os("HOME").and_then(|h| h.into_string().ok())
        && home.len() > 1
    {
        s = s.replace(&home, "$HOME");
    }
    for root in ["/Users/", "/home/"] {
        let mut out = String::new();
        let mut rest = s.as_str();
        while let Some(i) = rest.find(root) {
            out.push_str(&rest[..i]);
            out.push_str("$HOME");
            let after = &rest[i + root.len()..];
            let end = after
                .find(|c: char| {
                    c == '/' || c.is_whitespace() || matches!(c, '"' | '\'' | ':' | ',')
                })
                .unwrap_or(after.len());
            rest = &after[end..];
        }
        out.push_str(rest);
        s = out;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use studio_store::{SavedRow, SavedScan};

    const ID1: [u8; 16] = [1; 16];
    const ID2: [u8; 16] = [2; 16];
    const ID3: [u8; 16] = [3; 16];

    struct T {
        d: Driver,
        t0: Instant,
        sent: Vec<String>,
        quit: Option<(bool, String)>,
    }
    fn name(a: &Action, d: &Driver) -> String {
        match a {
            Action::Authorize => "Authorize".into(),
            Action::Start(j) => format!(
                "Start:{}",
                d.plan.scans.iter().find(|c| &c.job == j).unwrap().tag
            ),
            Action::Pause => "Pause".into(),
            Action::Resume => "Resume".into(),
            Action::Stop => "Stop".into(),
            Action::Lock => "Lock".into(),
            _ => "other".into(),
        }
    }
    impl T {
        fn new() -> Self {
            let t0 = Instant::now();
            Self {
                d: Driver::new(Plan::feth(), t0),
                t0,
                sent: vec![],
                quit: None,
            }
        }
        /// Feeds one update (or a tick) at `ms` and records what the driver asked for.
        fn at(&mut self, ms: u64, u: Option<Update>) -> usize {
            let utc = format!(
                "2026-10-26T10:{:02}:{:02}.{:03}Z",
                ms / 60000,
                ms / 1000 % 60,
                ms % 1000
            );
            let steps = self
                .d
                .step(u.as_ref(), self.t0 + Duration::from_millis(ms), utc);
            let n = steps.len();
            for s in steps {
                match s {
                    Step::Send(a) => {
                        let n = name(&a, &self.d);
                        self.sent.push(n);
                    }
                    Step::Quit { ok, reason } => self.quit = Some((ok, reason)),
                }
            }
            n
        }
        fn state(&mut self, ms: u64, s: Status, detail: &str) {
            self.at(ms, Some(Update::State(s, detail.into())));
        }
        fn notice(&mut self, ms: u64, t: &str) {
            self.at(ms, Some(Update::Notice(t.into())));
        }
        fn authorize(&mut self) {
            self.at(0, None);
            self.at(
                10,
                Some(Update::Authorization {
                    busy: true,
                    authorized: false,
                    detail: "Waiting".into(),
                }),
            );
            self.at(
                20,
                Some(Update::Authorization {
                    busy: false,
                    authorized: true,
                    detail: "ok".into(),
                }),
            );
            self.notice(30, "Network preflight passed: ready");
        }
        fn history(&mut self, ms: u64, id: [u8; 16], status: Status, next: Option<&str>) {
            let job = Plan::feth().scans[0].job.clone();
            let scan = SavedScan {
                scan: id,
                attempt: [9; 16],
                job,
                status,
                checkpoint: None,
                next_index: next.map(Into::into),
                detail: String::new(),
                name: None,
                created_at: None,
            };
            self.at(ms, Some(Update::History(vec![scan], Some(id))));
        }
        fn rows(&mut self, ms: u64, ports: &[u16]) {
            let v = ports
                .iter()
                .map(|p| SavedRow {
                    row: studio_protocol::Row {
                        ip: "198.18.0.2".into(),
                        port: *p,
                        open: true,
                    },
                    discovered_at: None,
                })
                .collect();
            self.at(ms, Some(Update::Rows(v)));
        }
        /// Runs the whole session; returns the time of the last event.
        fn full_session(&mut self) {
            self.authorize();
            self.at(200, None); // Start s1
            self.state(210, Status::Starting, "Starting scanner");
            self.state(300, Status::Scanning, "Scanning 20 endpoints");
            self.rows(500, &[8000, 8001]);
            self.rows(600, &[8001, 8002]);
            self.state(900, Status::Completed, "done");
            self.history(900, ID1, Status::Completed, None);
            self.at(1000, None); // Start s2
            self.state(1010, Status::Starting, "Starting scanner");
            self.state(1100, Status::Scanning, "Scanning 32 endpoints");
            self.at(2599, None);
            self.at(2600, None); // Pause
            self.state(2610, Status::Saving, "Pausing and draining replies…");
            self.state(2700, Status::Saving, "Checkpoint saved; confirming pause…");
            self.state(5700, Status::Paused, "Checkpoint committed by Studio");
            assert_eq!(
                self.sent.last().unwrap(),
                "Pause",
                "no Resume on the Paused state alone"
            );
            self.history(5750, ID2, Status::Paused, Some("7")); // Resume
            self.state(5760, Status::Starting, "Resuming saved scan");
            self.state(5800, Status::Scanning, "Scanning 32 endpoints");
            self.state(9000, Status::Completed, "done");
            self.history(9000, ID2, Status::Completed, None);
            self.at(9100, None); // Start s3
            self.state(9110, Status::Starting, "Starting scanner");
            self.state(9200, Status::Scanning, "Scanning 2000 endpoints");
            self.at(10700, None); // Stop
            self.state(10730, Status::Stopped, "Stopped");
            self.history(10730, ID3, Status::Stopped, None);
            self.at(10830, None); // Lock
            self.at(
                10840,
                Some(Update::Authorization {
                    busy: false,
                    authorized: false,
                    detail: "Runner session closed".into(),
                }),
            );
            self.notice(10850, "Runner session closed");
        }
    }

    #[test]
    fn driver_authorizes_then_runs_the_three_cases_in_order_and_locks() {
        let mut t = T::new();
        t.full_session();
        let actions: Vec<_> =
            t.d.chronicle()
                .actions
                .iter()
                .map(|a| a.action.as_str())
                .collect();
        assert_eq!(
            actions,
            [
                "Authorize",
                "Start:s1_full",
                "Start:s2_pause",
                "Pause",
                "Resume",
                "Start:s3_stop",
                "Stop",
                "Lock"
            ]
        );
        assert_eq!(t.d.chronicle().result, "ok");
        assert!(matches!(t.quit, Some((true, _))));
        let c = t.d.chronicle();
        assert_eq!(c.plan[0].scan_id_hex.as_deref(), Some(&id_text(ID1)[..]));
        assert_eq!(c.plan[0].rows_seen, 3, "unique rows, not row updates");
        assert_eq!(c.plan[0].finished_status.as_deref(), Some("Completed"));
        assert_eq!(c.plan[1].paused_next_index, Some(7));
        // From the Pause action (2600) to Paused (5700), not to the first Saving (2610).
        assert_eq!(c.plan[1].pause_to_paused_ms, Some(3100));
        // Resume only after the Paused History (5750).
        let resume = c.actions.iter().find(|a| a.action == "Resume").unwrap();
        assert_eq!(resume.mono_ms, 5750);
        // What was sent is what was recorded.
        let recorded: Vec<String> = c.actions.iter().map(|a| a.action.clone()).collect();
        assert_eq!(t.sent, recorded);
        assert_eq!(c.plan[2].finished_status.as_deref(), Some("Stopped"));
        assert!(
            c.events
                .iter()
                .any(|e| e.kind == "Authorization" && e.authorized == Some(true))
        );
        // Every action starts strictly after the last event of the case before it.
        let start2 = c
            .actions
            .iter()
            .find(|a| a.action == "Start:s2_pause")
            .unwrap();
        let done1 = c.plan[0].finished_utc.clone().unwrap();
        assert!(start2.utc > done1);
        let start1 = c
            .actions
            .iter()
            .find(|a| a.action == "Start:s1_full")
            .unwrap();
        let passed = c
            .events
            .iter()
            .find(|e| e.detail.contains("Network preflight passed"))
            .unwrap();
        assert!(start1.mono_ms > passed.mono_ms);
        let lock = c.actions.iter().find(|a| a.action == "Lock").unwrap();
        let last_state = c.events.iter().rev().find(|e| e.kind == "State").unwrap();
        assert!(lock.mono_ms > last_state.mono_ms);
    }

    #[test]
    fn preflight_refused_locks_and_fails_without_start() {
        let mut t = T::new();
        t.at(0, None);
        t.at(
            20,
            Some(Update::Authorization {
                busy: false,
                authorized: true,
                detail: "ok".into(),
            }),
        );
        t.notice(30, "Network preflight refused: stand is down");
        assert_eq!(t.sent, ["Authorize", "Lock"]);
        let (ok, reason) = t.quit.clone().unwrap();
        assert!(!ok);
        assert!(reason.contains("refused"), "{reason}");
        assert_eq!(t.d.chronicle().result, reason);
        t.at(500, None);
        assert_eq!(t.sent.len(), 2, "nothing after the failure");
    }

    #[test]
    fn failed_state_during_a_case_quits_without_the_next_case() {
        for bad in [Status::Failed, Status::Interrupted] {
            let mut t = T::new();
            t.authorize();
            t.at(200, None);
            t.state(210, Status::Starting, "Starting scanner");
            t.state(300, bad.clone(), "Runner refused raw");
            assert_eq!(t.sent, ["Authorize", "Start:s1_full", "Lock"]);
            assert!(matches!(&t.quit, Some((false, r)) if r.contains(&format!("{bad:?}"))));
            assert!(!t.d.chronicle().result.starts_with("timeout"));
            t.at(900, None);
            assert_eq!(t.sent.len(), 3);
        }
    }

    #[test]
    fn interrupted_while_authorizing_or_locking_fails_at_once() {
        // A stored scan replayed before the dialog is not a failure of this run ...
        let mut t = T::new();
        t.at(0, None);
        t.state(5, Status::Interrupted, "old scan");
        assert!(t.quit.is_none());
        // ... but after the dialog was opened it is.
        t.at(
            10,
            Some(Update::Authorization {
                busy: true,
                authorized: false,
                detail: "Waiting".into(),
            }),
        );
        t.state(20, Status::Interrupted, "runner died");
        assert!(matches!(&t.quit, Some((false, r)) if r.contains("Interrupted")));
        assert!(!t.d.chronicle().result.starts_with("timeout"));
        // Locking.
        let mut l = T::new();
        l.authorize();
        l.at(200, None);
        l.state(300, Status::Scanning, "s1");
        l.state(400, Status::Completed, "done");
        l.history(400, ID1, Status::Completed, None);
        l.at(500, None);
        l.state(600, Status::Scanning, "s2");
        l.at(2100, None);
        l.state(2200, Status::Paused, "Checkpoint committed by Studio");
        l.history(2200, ID2, Status::Paused, Some("3"));
        l.state(2300, Status::Scanning, "s2");
        l.state(2400, Status::Completed, "done");
        l.history(2400, ID2, Status::Completed, None);
        l.at(2500, None);
        l.state(2600, Status::Scanning, "s3");
        l.at(4100, None);
        l.state(4137, Status::Stopped, "Stopped");
        l.history(4137, ID3, Status::Stopped, None);
        l.at(4300, None);
        assert_eq!(l.sent.last().unwrap(), "Lock");
        l.state(4310, Status::Interrupted, "runner gone");
        assert!(matches!(&l.quit, Some((false, r)) if r.contains("Interrupted")));
    }

    #[test]
    fn unexpected_states_fail_at_once_not_by_timeout() {
        // Paused while waiting for Completed of a scan that is not to be paused.
        let mut t = T::new();
        t.authorize();
        t.at(200, None);
        t.state(300, Status::Scanning, "s1");
        t.state(400, Status::Paused, "surprise");
        assert!(
            matches!(&t.quit, Some((false, r)) if r.contains("Paused") && !r.starts_with("timeout"))
        );
        assert_eq!(t.sent[t.sent.len() - 2..], ["Stop", "Lock"]);
        // Completed right after Start, before Scanning.
        let mut u = T::new();
        u.authorize();
        u.at(200, None);
        u.state(250, Status::Completed, "surprise");
        assert!(matches!(&u.quit, Some((false, r)) if r.contains("Completed")));
    }

    #[test]
    fn authorization_lost_after_busy_quits() {
        let mut t = T::new();
        t.at(0, None);
        t.at(
            10,
            Some(Update::Authorization {
                busy: true,
                authorized: false,
                detail: "Waiting".into(),
            }),
        );
        t.at(
            20,
            Some(Update::Authorization {
                busy: false,
                authorized: false,
                detail: "User cancelled".into(),
            }),
        );
        assert_eq!(t.sent, ["Authorize", "Lock"]);
        assert!(matches!(&t.quit, Some((false, r)) if r.contains("User cancelled")));
    }

    #[test]
    fn pause_is_sent_only_after_scanning_and_after_the_delay() {
        let mut t = T::new();
        t.authorize();
        t.at(200, None);
        t.state(300, Status::Scanning, "s1");
        t.state(400, Status::Completed, "done");
        t.history(400, ID1, Status::Completed, None);
        t.at(500, None); // Start s2
        t.state(510, Status::Starting, "Starting scanner");
        let before = t.sent.len();
        t.at(3000, None);
        assert_eq!(
            t.sent.len(),
            before,
            "no Pause while only Starting was seen"
        );
        t.state(3100, Status::Scanning, "s2");
        t.at(4599, None);
        assert_eq!(
            t.sent.last().unwrap(),
            "Start:s2_pause",
            "1.5 s not elapsed"
        );
        t.at(4600, None);
        assert_eq!(t.sent.last().unwrap(), "Pause");
        t.at(4700, None);
        assert_eq!(
            t.sent.iter().filter(|s| *s == "Pause").count(),
            1,
            "sent once"
        );
    }

    #[test]
    fn stop_latency_is_measured_from_the_action_to_stopped() {
        let mut t = T::new();
        t.authorize();
        t.at(200, None);
        t.state(300, Status::Scanning, "s1");
        t.state(400, Status::Completed, "done");
        t.history(400, ID1, Status::Completed, None);
        t.at(500, None);
        t.state(600, Status::Scanning, "s2");
        t.at(2100, None); // Pause
        t.state(2200, Status::Paused, "Checkpoint committed by Studio");
        t.history(2200, ID2, Status::Paused, Some("3"));
        t.state(2300, Status::Scanning, "s2");
        t.state(2400, Status::Completed, "done");
        t.history(2400, ID2, Status::Completed, None);
        t.at(2500, None); // Start s3
        t.state(2600, Status::Scanning, "s3");
        t.at(4100, None); // Stop
        t.state(4137, Status::Stopped, "Stopped");
        let c = t.d.chronicle();
        assert_eq!(c.plan[2].stop_to_stopped_ms, Some(37));
        assert_eq!(c.plan[1].pause_to_paused_ms, Some(100));
        let stop = c
            .actions
            .iter()
            .find(|a| a.action == "Stop")
            .unwrap()
            .mono_ms;
        let stopped = c
            .events
            .iter()
            .find(|e| e.status == "Stopped")
            .unwrap()
            .mono_ms;
        assert_eq!(stopped - stop, 37);
    }

    #[test]
    fn phase_timeout_quits_with_reason() {
        let mut t = T::new();
        t.authorize();
        t.at(200, None);
        t.state(300, Status::Scanning, "s1");
        t.at(300 + 60_001, None);
        let (ok, reason) = t.quit.clone().unwrap();
        assert!(!ok);
        assert!(reason.starts_with("timeout"), "{reason}");
        assert_eq!(t.d.chronicle().result, reason);
        assert_eq!(
            t.sent[t.sent.len() - 2..],
            ["Stop", "Lock"],
            "a running scan is stopped first"
        );
        // Authorization may take up to 200 s.
        let mut a = T::new();
        a.at(0, None);
        a.at(150_000, None);
        assert!(a.quit.is_none());
        a.at(200_001, None);
        assert!(matches!(&a.quit, Some((false, r)) if r.starts_with("timeout")));
    }

    #[test]
    fn chronicle_serializes_without_personal_paths() {
        let mut t = T::new();
        t.at(0, None);
        t.at(
            20,
            Some(Update::Authorization {
                busy: false,
                authorized: false,
                detail: "cannot run /Users/alice/Library/x/studio-runner: denied".into(),
            }),
        );
        let json = serde_json::to_string(t.d.chronicle()).unwrap();
        assert!(!json.contains("/Users/"), "{json}");
        assert!(json.contains("$HOME"));
        assert!(!scrub("/home/bob/.local").contains("bob"));
        assert_eq!(json_value(&json)["schema"], 1);
    }
    fn json_value(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn chronicle_matches_the_verifier_schema() {
        let mut t = T::new();
        t.full_session();
        let v = json_value(&serde_json::to_string(t.d.chronicle()).unwrap());
        assert_eq!(v["schema"], 1);
        assert_eq!(v["result"], "ok");
        let p = &v["plan"][1];
        assert_eq!(p["tag"], "s2_pause");
        assert_eq!(
            p["job"],
            serde_json::json!({"targets":"198.18.0.2","ports":"9000-9031","exclusions":"","seed":"2","rate":4,"backend":"MacFeth"})
        );
        assert_eq!(p["paused_next_index"], 7);
        assert!(p["pause_to_paused_ms"].is_i64());
        assert!(p["scan_id_hex"].is_string());
        let e = v["events"].as_array().unwrap();
        assert!(
            e.iter()
                .all(|x| x["mono_ms"].is_i64() && x["utc"].is_string())
        );
        let auth = e
            .iter()
            .find(|x| x["kind"] == "Authorization" && x["authorized"] == true);
        assert!(auth.is_some());
        let paused = e.iter().find(|x| x["status"] == "Paused").unwrap();
        assert_eq!(paused["detail"], "Checkpoint committed by Studio");
    }

    #[test]
    fn utc_text_formats_millis_and_leap_days() {
        assert_eq!(
            utc_text(Duration::from_millis(0)),
            "1970-01-01T00:00:00.000Z"
        );
        assert_eq!(
            utc_text(Duration::from_millis(1_782_468_245_123)),
            "2026-06-26T10:04:05.123Z"
        );
        // 2024-02-29T23:59:59.999Z
        assert_eq!(
            utc_text(Duration::from_millis(1_709_251_199_999)),
            "2024-02-29T23:59:59.999Z"
        );
    }
}
