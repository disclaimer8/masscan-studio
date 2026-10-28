//! Attempt-local environment supervision. No packet or configuration writes.
use rmasscan_engine::CancelHandle;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime},
};

const FRESHNESS: Duration = Duration::from_secs(3);
const SUSPENSION: Duration = Duration::from_secs(5);
// Only macOS currently has a production raw observer. Other platforms exercise
// these variants through test inspectors until their raw profiles exist.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub enum Observation {
    Valid,
    Cancelled,
}
pub type Inspector = Box<dyn FnMut(&dyn Fn() -> bool) -> Result<Observation, String> + Send>;

pub(crate) struct Clock {
    tick: Instant,
    wall: SystemTime,
}
impl Clock {
    pub(crate) fn new() -> Self {
        Self {
            tick: Instant::now(),
            wall: SystemTime::now(),
        }
    }
    pub(crate) fn check(&mut self, tick: Instant, wall: SystemTime) -> Option<String> {
        let gap = tick.saturating_duration_since(self.tick) > SUSPENSION
            || !wall
                .duration_since(self.wall)
                .is_ok_and(|d| d <= SUSPENSION);
        self.tick = tick;
        self.wall = wall;
        gap.then(|| "System suspension, scheduling gap or clock change detected".into())
    }
}

struct Health {
    good_since: Instant,
    error: Option<String>,
}
impl Health {
    fn record_success(&mut self, began: Instant, now: Instant, cancel: &CancelHandle) {
        if now.saturating_duration_since(self.good_since) >= FRESHNESS {
            self.fail("Network observation became stale".into(), cancel);
        } else {
            self.good_since = began;
        }
    }
    fn fail(&mut self, error: String, cancel: &CancelHandle) {
        if self.error.is_none() {
            self.error = Some(format!(
                "Attempt interrupted: {error}. Start a new scan after checking the network."
            ));
            cancel.stop();
        }
    }
}

pub struct Guard {
    cancel: CancelHandle,
    clock: Clock,
    health: Arc<Mutex<Health>>,
    closing: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    observing: bool,
}
impl Guard {
    pub fn new(cancel: CancelHandle, inspect: Option<Inspector>) -> Result<Self, String> {
        let tick = Instant::now();
        let health = Arc::new(Mutex::new(Health {
            good_since: tick,
            error: None,
        }));
        let closing = Arc::new(AtomicBool::new(false));
        let observing = inspect.is_some();
        let worker = if let Some(mut inspect) = inspect {
            let health = health.clone();
            let closing = closing.clone();
            let cancel = cancel.clone();
            Some(
                thread::Builder::new()
                    .name("studio-network-guard".into())
                    .spawn(move || {
                        while !closing.load(Ordering::Acquire) {
                            let began = Instant::now();
                            let cancelled =
                                || closing.load(Ordering::Acquire) || began.elapsed() >= FRESHNESS;
                            let result = inspect(&cancelled);
                            let mut state = health.lock().unwrap_or_else(|p| p.into_inner());
                            if let Err(error) = result {
                                state.fail(error, &cancel);
                            } else if closing.load(Ordering::Acquire) {
                                break;
                            } else if began.elapsed() >= FRESHNESS {
                                state.fail("Network observation timed out".into(), &cancel);
                            } else if matches!(result, Ok(Observation::Cancelled)) {
                                state.fail(
                                    "Network observation cancelled unexpectedly".into(),
                                    &cancel,
                                );
                            } else {
                                // Age the whole observation, not just its last command.
                                state.record_success(began, Instant::now(), &cancel);
                            }
                            if state.error.is_some() {
                                break;
                            }
                            drop(state);
                            thread::park_timeout(Duration::from_secs(1));
                        }
                    })
                    .map_err(|e| format!("Cannot start network observer: {e}"))?,
            )
        } else {
            None
        };
        Ok(Self {
            cancel,
            clock: Clock {
                tick,
                wall: SystemTime::now(),
            },
            health,
            closing,
            worker,
            observing,
        })
    }
    pub fn poll(&mut self) -> Option<String> {
        self.poll_at(Instant::now(), SystemTime::now())
    }
    fn poll_at(&mut self, tick: Instant, wall: SystemTime) -> Option<String> {
        let mut state = self.health.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(error) = self.clock.check(tick, wall) {
            state.fail(error, &self.cancel);
        }
        if let Some(worker) = &self.worker
            && worker.is_finished()
        {
            state.fail("Network observer exited".into(), &self.cancel);
        }
        if self.observing && tick.saturating_duration_since(state.good_since) >= FRESHNESS {
            state.fail("Network observation became stale".into(), &self.cancel);
        }
        state.error.clone()
    }
    fn shutdown(&mut self) {
        self.closing.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            if worker.join().is_err() {
                self.health
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .fail("Network observer panicked".into(), &self.cancel);
            }
        }
    }
    pub fn finish(mut self) -> Option<String> {
        // Freeze the observation before choosing the terminal state. Otherwise
        // a concurrently failing worker could be lost behind Completed/Paused.
        self.poll();
        self.shutdown();
        self.poll()
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmasscan_engine::{Engine, EngineHandle, EngineOptions};
    use std::sync::mpsc;

    #[test]
    fn late_success_cannot_hide_a_gap_between_valid_observations() {
        let engine = engine();
        let first = Instant::now();
        let mut health = Health {
            good_since: first,
            error: None,
        };
        // A successful short probe after a long scheduling gap is still stale.
        health.record_success(
            first + FRESHNESS,
            first + FRESHNESS + Duration::from_millis(10),
            &engine.cancel_handle(),
        );
        assert!(health.error.unwrap().contains("stale"));
        assert_eq!(
            engine.join().unwrap().reason,
            rmasscan_engine::Reason::Stopped
        );
    }

    #[test]
    fn finishing_does_not_discard_an_in_flight_failure() {
        let engine = engine();
        let (entered, ready) = mpsc::channel();
        let guard = Guard::new(
            engine.cancel_handle(),
            Some(Box::new(move |cancelled| {
                entered.send(()).unwrap();
                while !cancelled() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                // A genuine observation failure, even when shutdown raced with it.
                Err("route changed".into())
            })),
        )
        .unwrap();
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(guard.finish().unwrap().contains("route changed"));
        assert_eq!(
            engine.join().unwrap().reason,
            rmasscan_engine::Reason::Stopped
        );
    }

    #[test]
    fn observer_panic_during_finish_is_an_interruption() {
        let engine = engine();
        let (entered, ready) = mpsc::channel();
        let guard = Guard::new(
            engine.cancel_handle(),
            Some(Box::new(move |cancelled| {
                entered.send(()).unwrap();
                while !cancelled() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                panic!("observer failed during finish");
            })),
        )
        .unwrap();
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(guard.finish().unwrap().contains("observer"));
        assert_eq!(
            engine.join().unwrap().reason,
            rmasscan_engine::Reason::Stopped
        );
    }

    fn engine() -> EngineHandle {
        let mut job = studio_protocol::Job::example(studio_protocol::Backend::Simulation);
        job.rate = 1;
        job.ports = "1-100".into();
        Engine::start(
            job.prepare().unwrap(),
            rmasscan_engine::fake::FakeAdapter::new().pair(),
            EngineOptions::new([1; 16], [2; 16]),
        )
        .unwrap()
    }

    #[test]
    fn observation_failure_stops_engine_and_stays_failed() {
        let engine = engine();
        let mut guard = Guard::new(
            engine.cancel_handle(),
            Some(Box::new(|_| Err("route changed".into()))),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let error = loop {
            if let Some(e) = guard.poll() {
                break Some(e);
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        assert!(error.as_ref().unwrap().contains("route changed"));
        assert_eq!(guard.poll(), error);
        assert_eq!(
            engine.join().unwrap().reason,
            rmasscan_engine::Reason::Stopped
        );
    }

    #[test]
    fn stale_observation_stops_engine_and_drop_cancels_probe() {
        let engine = engine();
        let (tx, rx) = mpsc::channel();
        let (done, ended) = mpsc::channel();
        let mut guard = Guard::new(
            engine.cancel_handle(),
            Some(Box::new(move |cancelled| {
                tx.send(()).unwrap();
                while !cancelled() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                done.send(()).unwrap();
                Err("cancelled".into())
            })),
        )
        .unwrap();
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let error = guard.poll_at(
            Instant::now() + FRESHNESS + Duration::from_millis(1),
            SystemTime::now(),
        );
        assert!(error.unwrap().contains("stale"));
        drop(guard);
        ended.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            engine.join().unwrap().reason,
            rmasscan_engine::Reason::Stopped
        );
    }

    #[test]
    fn healthy_observer_is_cancellable_and_simulation_needs_no_network() {
        let engine = engine();
        let (tx, rx) = mpsc::channel();
        let mut guard = Guard::new(
            engine.cancel_handle(),
            Some(Box::new(move |_| {
                tx.send(()).unwrap();
                Ok(Observation::Valid)
            })),
        )
        .unwrap();
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(guard.poll().is_none());
        let began = Instant::now();
        drop(guard);
        assert!(began.elapsed() < Duration::from_millis(500));
        assert!(engine.outcome().is_none());
        let mut guard = Guard::new(engine.cancel_handle(), None).unwrap();
        assert!(guard.poll().is_none());
        assert!(
            guard
                .poll_at(
                    Instant::now(),
                    SystemTime::now() + SUSPENSION + Duration::from_secs(1)
                )
                .is_some()
        );
        assert_eq!(
            engine.join().unwrap().reason,
            rmasscan_engine::Reason::Stopped
        );
    }

    #[test]
    fn dead_observer_is_not_a_successful_check() {
        let engine = engine();
        let mut guard = Guard::new(
            engine.cancel_handle(),
            Some(Box::new(|_| panic!("probe failure"))),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut error = None;
        while Instant::now() < deadline {
            error = guard.poll();
            if error.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(error.unwrap().contains("observer"));
        assert_eq!(
            engine.join().unwrap().reason,
            rmasscan_engine::Reason::Stopped
        );
    }

    #[test]
    fn suspension_is_detected_even_when_monotonic_clock_does_not_advance() {
        let tick = Instant::now();
        let wall = SystemTime::now();
        let mut clock = Clock { tick, wall };
        assert!(
            clock
                .check(tick, wall + SUSPENSION + Duration::from_millis(1))
                .is_some()
        );
    }

    #[test]
    fn scheduling_gap_and_backwards_clock_are_not_silent() {
        let tick = Instant::now();
        let wall = SystemTime::now();
        let mut clock = Clock { tick, wall };
        assert!(
            clock
                .check(tick + SUSPENSION + Duration::from_millis(1), wall)
                .is_some()
        );
        let mut clock = Clock { tick, wall };
        assert!(clock.check(tick, wall - Duration::from_secs(1)).is_some());
        let mut clock = Clock { tick, wall };
        assert!(
            clock
                .check(tick + Duration::from_secs(1), wall + Duration::from_secs(1))
                .is_none()
        );
    }
}
