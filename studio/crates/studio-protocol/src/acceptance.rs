//! Shared clock samples and records for independently supervised acceptance runs.
use crate::{Id, Row, Status};
use serde::{Deserialize, Serialize};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const QUIET_NS: u64 = 2_000_000_000;
pub const CLOCK_ERROR_NS: u64 = 5_000_000;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stamp {
    pub wall_ns: u64,
    pub mono_ns: u64,
    pub uncertainty_ns: u64,
}
impl Stamp {
    pub fn now(origin: Instant) -> Result<Self, String> {
        let before = origin.elapsed().as_nanos();
        let wall_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let after = origin.elapsed().as_nanos();
        Ok(Self {
            wall_ns: wall_ns.try_into().map_err(|_| "clock overflow")?,
            mono_ns: after.try_into().map_err(|_| "clock overflow")?,
            uncertainty_ns: (after - before).try_into().map_err(|_| "clock overflow")?,
        })
    }
    pub fn low(&self) -> Result<u64, String> {
        self.wall_ns
            .checked_sub(self.margin()?)
            .ok_or("clock underflow".into())
    }
    pub fn high(&self) -> Result<u64, String> {
        self.wall_ns
            .checked_add(self.margin()?)
            .ok_or("clock overflow".into())
    }
    fn margin(&self) -> Result<u64, String> {
        if self.uncertainty_ns > CLOCK_ERROR_NS {
            return Err("ambiguous clock sample".into());
        }
        self.uncertainty_ns
            .checked_add(CLOCK_ERROR_NS)
            .ok_or("clock overflow".into())
    }
}
pub fn clocks(stamps: &[Stamp]) -> Result<(), String> {
    for s in stamps {
        if s.uncertainty_ns > CLOCK_ERROR_NS {
            return Err("ambiguous clock sample".into());
        }
        s.low()?;
        s.high()?;
    }
    if let Some(first) = stamps.first() {
        for last in stamps.iter().skip(1) {
            let wall = last
                .wall_ns
                .checked_sub(first.wall_ns)
                .ok_or("wall clock reversed")?;
            let mono = last
                .mono_ns
                .checked_sub(first.mono_ns)
                .ok_or("monotonic clock reversed")?;
            if wall.abs_diff(mono) > CLOCK_ERROR_NS {
                return Err("cumulative wall/monotonic divergence".into());
            }
        }
    }
    for p in stamps.windows(2) {
        let wall = p[1]
            .wall_ns
            .checked_sub(p[0].wall_ns)
            .ok_or("wall clock reversed")?;
        let mono = p[1]
            .mono_ns
            .checked_sub(p[0].mono_ns)
            .ok_or("monotonic clock reversed")?;
        if wall.abs_diff(mono) > CLOCK_ERROR_NS {
            return Err("wall/monotonic clock divergence".into());
        }
    }
    Ok(())
}
/// Independent sampling continues during Controller/native blocking operations.
pub struct Sampler {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<Result<Vec<Stamp>, String>>>,
    origin: Instant,
}
impl Sampler {
    pub fn start(origin: Instant, first: Stamp) -> Self {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut samples = vec![first];
            while !flag.load(std::sync::atomic::Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(50));
                samples.push(Stamp::now(origin)?);
            }
            Ok(samples)
        });
        Self {
            stop,
            worker: Some(worker),
            origin,
        }
    }
    pub fn finish(mut self) -> Result<(Stamp, Vec<Stamp>), String> {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        let mut samples = self
            .worker
            .take()
            .ok_or("missing clock worker")?
            .join()
            .map_err(|_| "clock worker panic")??;
        let final_stamp = Stamp::now(self.origin)?;
        samples.push(final_stamp.clone());
        Ok((final_stamp, samples))
    }
}
impl Drop for Sampler {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(t) = self.worker.take() {
            let _ = t.join();
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ticket {
    pub nonce: String,
    pub case: String,
    pub seal_generation: String,
    pub tooling_sha256: String,
    pub runner_sha256: String,
    pub ready: Stamp,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attempt {
    pub ticket: Ticket,
    pub driver_pid: u32,
    pub driver_uid: u32,
    pub process_identity: String,
    pub driver_started: Stamp,
    pub start: Stamp,
    pub control: Option<Stamp>,
    pub terminal: Stamp,
    pub joined: Stamp,
    pub samples: Vec<Stamp>,
    pub scan: Id,
    pub attempt: Id,
    pub status: Status,
    pub report: Option<Vec<u8>>,
    pub checkpoint: Option<Vec<u8>>,
    pub next_index: Option<String>,
    pub rows: Vec<Row>,
}
impl Attempt {
    /// Used on deserialized evidence before full clock/order verification.
    pub fn quiet_until(&self) -> Result<u64, String> {
        self.joined
            .high()?
            .max(self.terminal.high()?)
            .checked_add(QUIET_NS)
            .ok_or("clock overflow".into())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Window {
    pub ticket: Ticket,
    pub opened: Stamp,
    pub stopped: Stamp,
    pub samples: Vec<Stamp>,
    pub children_clean: bool,
    pub peer_drops: Option<u64>,
}
