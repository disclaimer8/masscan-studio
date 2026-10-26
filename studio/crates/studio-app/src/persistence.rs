//! Bounded commit batches; commands remain responsive while the batch fills.
use std::time::{Duration, Instant};
use studio_protocol::{Envelope, Event};

#[derive(Default)]
pub(crate) struct Pending {
    events: Vec<Envelope<Event>>,
    rows: usize,
    since: Option<Instant>,
    urgent: bool,
}
impl Pending {
    pub fn can_fit(&self, e: &Envelope<Event>) -> bool {
        let count = if let Event::Results(rows) = &e.payload {
            rows.len()
        } else {
            0
        };
        self.events.is_empty() || (self.rows + count <= 1000 && self.events.len() < 16)
    }
    pub fn push(&mut self, e: Envelope<Event>, now: Instant) {
        self.since.get_or_insert(now);
        match &e.payload {
            Event::Results(rows) => self.rows += rows.len(),
            Event::Progress { .. } => {}
            _ => self.urgent = true,
        }
        self.events.push(e);
    }
    pub fn ready(&self, now: Instant) -> bool {
        self.urgent
            || self.rows >= 1000
            || self.events.len() >= 16
            || self
                .since
                .is_some_and(|start| now.duration_since(start) >= Duration::from_millis(250))
    }
    pub fn take(&mut self) -> Vec<Envelope<Event>> {
        std::mem::take(self).events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use studio_protocol::{Row, Status};
    fn results(n: usize) -> Envelope<Event> {
        Envelope::new(
            [1; 16],
            [2; 16],
            [3; 16],
            1,
            Event::Results(vec![
                Row {
                    ip: "198.18.0.2".into(),
                    port: 80,
                    open: true,
                };
                n
            ]),
        )
    }
    #[test]
    fn rows_wait_for_count_or_deadline_and_never_overfill_a_batch() {
        let now = Instant::now();
        let mut batch = Pending::default();
        batch.push(results(600), now);
        assert!(!batch.ready(now + Duration::from_millis(249)));
        assert!(!batch.can_fit(&results(500)));
        assert!(batch.can_fit(&results(400)));
        batch.push(results(400), now);
        assert!(batch.ready(now));
        assert_eq!(batch.take().len(), 2);
        assert!(!batch.ready(now + Duration::from_secs(1)));
        batch.push(results(1), now);
        assert!(batch.ready(now + Duration::from_millis(250)));
    }
    #[test]
    fn checkpoint_and_terminal_force_prior_results_to_commit() {
        for event in [
            Event::Checkpoint {
                bytes: vec![],
                next_index: "1".into(),
            },
            Event::Finished {
                status: Status::Completed,
                detail: String::new(),
            },
        ] {
            let now = Instant::now();
            let mut batch = Pending::default();
            batch.push(results(1), now);
            batch.push(Envelope::new([1; 16], [2; 16], [3; 16], 2, event), now);
            assert!(batch.ready(now));
            assert_eq!(batch.take().len(), 2);
        }
    }
}
