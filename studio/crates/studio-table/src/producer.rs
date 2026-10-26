//! At most one 50-row callback is in flight; the producer waits for its ACK.
use crate::{Change, INITIAL_ROWS, Row};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub struct Producer {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    pub stats: Arc<Stats>,
}
pub struct Stats {
    pub offered: AtomicUsize,
    pub applied: AtomicUsize,
    pub done: AtomicBool,
    start: Instant,
    last_ack_us: AtomicU64,
    last_offer_us: AtomicU64,
}
impl Stats {
    pub fn meets_target(&self) -> bool {
        self.done.load(Ordering::Relaxed)
            && self.offered.load(Ordering::Relaxed) == 60_000
            && self.applied.load(Ordering::Relaxed) == 60_000
            && self.last_offer_us.load(Ordering::Relaxed) <= 60_000_000
            // Two 50ms scheduling quanta to drain the final in-flight batch.
            && self.last_ack_us.load(Ordering::Relaxed) <= 60_100_000
    }
    pub fn report(&self) {
        println!(
            "{}",
            serde_json::json!({"event":"producer_summary","offered":self.offered.load(Ordering::Relaxed),"applied":self.applied.load(Ordering::Relaxed),"done":self.done.load(Ordering::Relaxed),"drain_allowance_ms":100,"last_offer_ms":self.last_offer_us.load(Ordering::Relaxed) as f64 / 1000.,"last_ack_ms":self.last_ack_us.load(Ordering::Relaxed) as f64 / 1000.,"elapsed_s":self.start.elapsed().as_secs_f64(),"target_events":60000,"target_duration_s":60,"maximum_in_flight_batches":1})
        );
    }
}
impl Producer {
    pub fn start(
        first: u64,
        deliver: impl Fn(Vec<Change>, SyncSender<()>) -> bool + Send + 'static,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let stats = Arc::new(Stats {
            offered: AtomicUsize::new(0),
            applied: AtomicUsize::new(0),
            done: AtomicBool::new(false),
            start: Instant::now(),
            last_ack_us: AtomicU64::new(0),
            last_offer_us: AtomicU64::new(0),
        });
        let worker_stats = stats.clone();
        let join = thread::spawn(move || {
            for batch in 0..1200 {
                // Absolute schedule: ACK/scheduler delays do not accumulate drift.
                let deadline = worker_stats.start + Duration::from_millis(batch * 50);
                if let Some(wait) = deadline.checked_duration_since(Instant::now()) {
                    thread::sleep(wait);
                }
                if worker_stop.load(Ordering::Relaxed) {
                    break;
                }
                let offset = first + batch * 25;
                let rows = (0..25)
                    .flat_map(|i| {
                        [
                            Change::Append(Row::synthetic(offset + i)),
                            Change::Update(Row::updated(
                                (batch * 25 + i) % INITIAL_ROWS as u64,
                                batch,
                            )),
                        ]
                    })
                    .collect();
                let (tx, rx) = mpsc::sync_channel(1);
                if !deliver(rows, tx) {
                    break;
                }
                worker_stats.offered.fetch_add(50, Ordering::Relaxed);
                worker_stats.last_offer_us.store(
                    worker_stats.start.elapsed().as_micros() as u64,
                    Ordering::Relaxed,
                );
                loop {
                    match rx.recv_timeout(Duration::from_millis(50)) {
                        Ok(()) => {
                            worker_stats.applied.fetch_add(50, Ordering::Relaxed);
                            worker_stats.last_ack_us.store(
                                worker_stats.start.elapsed().as_micros() as u64,
                                Ordering::Relaxed,
                            );
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => return,
                        Err(_) if worker_stop.load(Ordering::Relaxed) => return,
                        Err(_) => {}
                    }
                }
            }
            worker_stats.done.store(true, Ordering::Relaxed);
        });
        Self {
            stop,
            join: Some(join),
            stats,
        }
    }
}
impl Drop for Producer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn late_workload_does_not_meet_sixty_second_target() {
        let stats = Stats {
            offered: AtomicUsize::new(60_000),
            applied: AtomicUsize::new(60_000),
            done: AtomicBool::new(true),
            start: Instant::now(),
            last_ack_us: AtomicU64::new(60_100_001),
            last_offer_us: AtomicU64::new(59_950_000),
        };
        assert!(!stats.meets_target());
        stats.last_ack_us.store(59_999_999, Ordering::Relaxed);
        assert!(stats.meets_target());
        stats.last_offer_us.store(60_000_001, Ordering::Relaxed);
        assert!(!stats.meets_target());
    }
}
