use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Manual,
    Smoke,
    Bench,
}
impl Mode {
    pub fn from_args() -> Self {
        if std::env::args().any(|a| a == "--bench") {
            Self::Bench
        } else if std::env::args().any(|a| a == "--smoke") {
            Self::Smoke
        } else {
            Self::Manual
        }
    }
}
pub enum Action {
    Filter(String),
    StartStream,
    Finish,
}
#[derive(Serialize)]
pub struct Sample {
    phase: &'static str,
    query: String,
    pub elapsed_ms: f64,
    rows: usize,
    received: usize,
    render_callback_ms: f64,
}

pub struct Benchmark {
    pub mode: Mode,
    start: Instant,
    last: Instant,
    index: usize,
    stream_start: Option<Instant>,
    pending: Option<(Instant, String, &'static str)>,
    samples: Vec<Sample>,
    done: bool,
    pub renderer_notifier: bool,
    revision: u64,
    queued_revision: Option<u64>,
    render_callback_ms: f64,
}
impl Benchmark {
    pub fn new(mode: Mode) -> Self {
        let now = Instant::now();
        Self {
            mode,
            start: now,
            last: now,
            index: 0,
            stream_start: None,
            pending: None,
            samples: Vec::new(),
            done: false,
            renderer_notifier: true,
            revision: 0,
            queued_revision: None,
            render_callback_ms: 0.,
        }
    }
    pub fn next(&mut self, producer_drained: bool) -> Option<Action> {
        if self.done || self.mode == Mode::Manual {
            return None;
        }
        if self.start.elapsed() > Duration::from_secs(120) {
            self.done = true;
            return Some(Action::Finish);
        }
        if self.pending.is_some() && self.mode != Mode::Smoke {
            return None;
        }
        if self.mode == Mode::Smoke {
            if self.index == 0 {
                self.index += 1;
                return Some(Action::Filter("https".into()));
            }
            if self.index == 1 {
                self.index += 1;
                return Some(Action::StartStream);
            }
            if self.start.elapsed() > Duration::from_secs(3) {
                self.done = true;
                return Some(Action::Finish);
            }
            return None;
        }
        if self.stream_start.is_none() && self.last.elapsed() < Duration::from_millis(50) {
            return None;
        }
        if self.index == 105 && self.stream_start.is_none() {
            self.stream_start = Some(Instant::now());
            return Some(Action::StartStream);
        }
        if self.index >= 205 {
            let elapsed = self.stream_start.unwrap().elapsed();
            if elapsed >= Duration::from_secs(60)
                && (producer_drained || elapsed >= Duration::from_millis(60_100))
            {
                self.done = true;
                return Some(Action::Finish);
            }
            return None;
        }
        if let Some(start) = self.stream_start {
            // 100 requests at 0.59..59.0 s, inside the producer's 60-second window.
            let due = Duration::from_millis((self.index - 104) as u64 * 590);
            if start.elapsed() < due {
                return None;
            }
        }
        let query = crate::queries()[self.index.saturating_sub(5) % 100].clone();
        self.index += 1;
        self.last = Instant::now();
        Some(Action::Filter(query))
    }
    pub fn begin_filter(&mut self, query: String) {
        self.revision += 1;
        let phase = if self.index <= 5 {
            "warmup"
        } else if self.stream_start.is_some() {
            "stream"
        } else {
            "idle"
        };
        self.pending = Some((Instant::now(), query, phase));
    }
    pub fn frame_ready(&mut self) -> Option<u64> {
        let start = self.pending.as_ref()?.0;
        if self.queued_revision == Some(self.revision) {
            return None;
        }
        self.render_callback_ms = start.elapsed().as_secs_f64() * 1000.;
        self.queued_revision = Some(self.revision);
        Some(self.revision)
    }
    pub fn rendered(&mut self, revision: u64, rows: usize, received: usize) {
        if revision != self.revision {
            return;
        }
        if let Some((start, query, phase)) = self.pending.take() {
            let sample = Sample {
                phase,
                query,
                elapsed_ms: start.elapsed().as_secs_f64() * 1000.,
                rows,
                received,
                render_callback_ms: self.render_callback_ms,
            };
            println!(
                "{}",
                serde_json::json!({"event":"filter_frame","sample":sample})
            );
            self.samples.push(sample);
        }
    }
    pub fn evidence_complete(&self, received: usize) -> bool {
        if self.mode == Mode::Manual {
            return true;
        }
        if self.mode == Mode::Smoke {
            return (!self.samples.is_empty() || !self.renderer_notifier) && received > 0;
        }
        if self.pending.is_some() || !self.renderer_notifier {
            return false;
        }
        received == 60_000
            && self.samples.iter().filter(|s| s.phase == "idle").count() == 100
            && self
                .samples
                .iter()
                .filter(|s| s.phase == "stream" && s.received > 0 && s.received < 60_000)
                .count()
                == 100
    }
    pub fn report(&self, adapter: &str, rows: usize, received: usize, producer_on_time: bool) {
        for phase in ["idle", "stream"] {
            let mut times: Vec<_> = self
                .samples
                .iter()
                .filter(|s| s.phase == phase)
                .map(|s| s.elapsed_ms)
                .collect();
            times.sort_by(f64::total_cmp);
            let percentile = |p: f64| {
                times
                    .get(((times.len() as f64 * p).ceil() as usize).saturating_sub(1))
                    .copied()
            };
            println!(
                "{}",
                serde_json::json!({"event":"summary","adapter":adapter,"phase":phase,"samples":times.len(),"p50_ms":percentile(0.5),"p95_ms":percentile(0.95),"max_ms":times.last(),"rows":rows,"received":received,"pending_frame":self.pending.is_some(),"elapsed_s":self.start.elapsed().as_secs_f64(),"workload_complete":self.evidence_complete(received) && (self.mode!=Mode::Bench || producer_on_time),"producer_on_time":producer_on_time,"a1":"INCONCLUSIVE","timing":"UI event-loop acknowledgement queued from AfterRendering; not physical display presentation","note":"memory and remaining parity checks require separate evidence"})
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn measured() -> Benchmark {
        let mut b = Benchmark::new(Mode::Bench);
        for phase in ["idle", "stream"] {
            for _ in 0..100 {
                b.samples.push(Sample {
                    phase,
                    query: "https".into(),
                    elapsed_ms: 10.,
                    rows: 100_000,
                    received: if phase == "stream" { 1000 } else { 0 },
                    render_callback_ms: 9.,
                });
            }
        }
        b
    }
    #[test]
    fn rejects_short_workload_and_samples_after_stream_finished() {
        let mut b = measured();
        assert!(!b.evidence_complete(58_000));
        assert!(b.evidence_complete(60_000));
        b.samples.last_mut().unwrap().received = 60_000;
        assert!(!b.evidence_complete(60_000));
    }
    #[test]
    fn unsupported_renderer_cannot_pass_benchmark() {
        let mut b = measured();
        b.renderer_notifier = false;
        assert!(!b.evidence_complete(60_000));
    }
    #[test]
    fn stale_frame_ack_cannot_consume_a_new_query() {
        let mut b = Benchmark::new(Mode::Bench);
        b.begin_filter("old".into());
        let old = b.frame_ready().unwrap();
        b.begin_filter("new".into());
        b.rendered(old, 100, 0);
        assert!(b.samples.is_empty());
        let current = b.frame_ready().unwrap();
        b.rendered(current, 100, 0);
        assert_eq!(b.samples[0].query, "new");
    }
}
