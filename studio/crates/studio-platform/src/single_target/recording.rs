//! Bounded read-only recording for the single-target capture child.
use super::{CAPTURE_HEADER, CAPTURE_SECONDS, Result};
use crate::pcap::{Packet, Statistics};
use std::{io::Write, time::Duration};
mod native;
pub use native::run;

const MAX_PACKETS: u64 = 1024;
pub(super) const MAX_BYTES: usize = 16 * 1024 * 1024;
trait Source {
    fn next(&mut self) -> Result<Option<Packet>>;
    fn statistics(&mut self) -> Result<Statistics>;
}
trait Runtime {
    fn ready(&mut self) -> Result<()>;
    fn end(&mut self) -> Result<()>;
    /// Non-fallible kernel lease release, independent of durable marker writes.
    fn invalidate(&mut self);
    fn elapsed(&self) -> Duration;
    fn stop(&mut self) -> Result<bool>;
    fn idle(&mut self);
}
#[derive(Default)]
struct Recorded {
    recorded: u64,
    stats: Option<Statistics>,
    error: Option<String>,
}
impl Recorded {
    fn fail(&mut self, error: String) {
        match &mut self.error {
            Some(old) => {
                old.push_str("; ");
                old.push_str(&error);
            }
            None => self.error = Some(error),
        }
    }
}
fn record(
    source: &mut impl Source,
    output: &mut impl Write,
    runtime: &mut impl Runtime,
) -> Recorded {
    let mut result = Recorded::default();
    let mut ended = false;
    let run = (|| -> Result<()> {
        output.write_all(&CAPTURE_HEADER).map_err(super::err)?;
        output.flush().map_err(super::err)?;
        runtime.ready()?;
        let mut drain = None;
        let mut bytes = CAPTURE_HEADER.len();
        let mut previous = None;
        loop {
            let check_time = |now| -> Result<()> {
                if now >= Duration::from_secs(CAPTURE_SECONDS) {
                    return Err("Capture deadline expired".into());
                }
                if drain.is_some_and(|end| now >= end) {
                    return Err("Capture drain deadline expired".into());
                }
                Ok(())
            };
            check_time(runtime.elapsed())?;
            if drain.is_none() && runtime.stop()? {
                let end = runtime.end();
                runtime.invalidate();
                end?;
                ended = true;
                drain = Some(runtime.elapsed() + Duration::from_millis(500));
            }
            let packet = source.next()?;
            if runtime.elapsed() >= Duration::from_secs(CAPTURE_SECONDS) {
                return Err("Capture deadline expired".into());
            }
            if drain.is_some_and(|end| runtime.elapsed() >= end) {
                return Err("Capture drain deadline expired".into());
            }
            let Some(p) = packet else {
                if drain.is_some() {
                    break;
                }
                runtime.idle();
                continue;
            };
            if !(14..=131072).contains(&p.bytes.len())
                || p.bytes.len() != p.original_len as usize
                || p.micros >= 1_000_000
            {
                return Err("Invalid or truncated capture packet".into());
            }
            let time = (p.seconds, p.micros);
            if previous.is_some_and(|old| old > time) {
                return Err("Capture timestamp went backward".into());
            }
            if result.recorded >= MAX_PACKETS || bytes + 16 + p.bytes.len() > MAX_BYTES {
                return Err("Capture packet/byte budget exceeded".into());
            }
            for field in [p.seconds, p.micros, p.original_len, p.original_len] {
                output.write_all(&field.to_le_bytes()).map_err(super::err)?;
            }
            output.write_all(&p.bytes).map_err(super::err)?;
            output.flush().map_err(super::err)?;
            bytes += 16 + p.bytes.len();
            result.recorded += 1;
            previous = Some(time);
        }
        Ok(())
    })();
    if let Err(e) = run {
        result.fail(e);
    }
    // Invalidate readiness on every exit, including a failed read/write/control
    // observation, while the caller still owns the open capture handle.
    if !ended && let Err(e) = runtime.end() {
        result.fail(e);
    }
    runtime.invalidate();
    match source.statistics() {
        Ok(stats) => {
            if stats.dropped != 0
                || stats.interface_dropped != 0
                || u64::from(stats.received) < result.recorded
            {
                result.fail("Capture statistics report loss or inconsistent count".into());
            }
            result.stats = Some(stats);
        }
        Err(e) => result.fail(e),
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};
    #[derive(Default)]
    struct State {
        elapsed: Duration,
        events: Vec<&'static str>,
    }
    struct Input {
        shared: Rc<RefCell<State>>,
        queue: VecDeque<Packet>,
        stats: Statistics,
        broken: bool,
        step: Duration,
    }
    impl Source for Input {
        fn next(&mut self) -> Result<Option<Packet>> {
            let mut s = self.shared.borrow_mut();
            s.events.push("read");
            s.elapsed += self.step;
            if self.broken {
                Err("read failed".into())
            } else {
                Ok(self.queue.pop_front())
            }
        }
        fn statistics(&mut self) -> Result<Statistics> {
            self.shared.borrow_mut().events.push("stats");
            Ok(self.stats)
        }
    }
    struct Clock {
        shared: Rc<RefCell<State>>,
        stop: Duration,
        broken: bool,
        ready_error: bool,
        end_error: bool,
    }
    impl Runtime for Clock {
        fn ready(&mut self) -> Result<()> {
            self.shared.borrow_mut().events.push("ready");
            if self.ready_error {
                Err("partial publish".into())
            } else {
                Ok(())
            }
        }
        fn end(&mut self) -> Result<()> {
            self.shared.borrow_mut().events.push("end");
            if self.end_error {
                Err("end marker failure".into())
            } else {
                Ok(())
            }
        }
        fn invalidate(&mut self) {
            self.shared.borrow_mut().events.push("invalidate");
        }
        fn elapsed(&self) -> Duration {
            self.shared.borrow().elapsed
        }
        fn stop(&mut self) -> Result<bool> {
            if self.broken {
                Err("control lost".into())
            } else {
                Ok(self.elapsed() >= self.stop)
            }
        }
        fn idle(&mut self) {
            self.shared.borrow_mut().elapsed += Duration::from_millis(10);
        }
    }
    fn packet() -> Packet {
        Packet {
            seconds: 1000,
            micros: 1,
            original_len: 60,
            bytes: vec![0; 60],
        }
    }
    fn setup(packets: Vec<Packet>) -> (Input, Clock) {
        let shared = Rc::new(RefCell::new(State::default()));
        (
            Input {
                shared: shared.clone(),
                stats: Statistics {
                    received: packets.len() as u32,
                    ..Statistics::default()
                },
                queue: packets.into(),
                broken: false,
                step: Duration::from_millis(10),
            },
            Clock {
                shared,
                stop: Duration::from_millis(30),
                broken: false,
                ready_error: false,
                end_error: false,
            },
        )
    }
    #[test]
    fn readiness_precedes_reads_and_explicit_stop_ends_before_statistics() {
        let (mut input, mut clock) = setup(vec![packet(), packet()]);
        let mut output = Vec::new();
        let r = record(&mut input, &mut output, &mut clock);
        assert_eq!(r.recorded, 2);
        assert_eq!(r.error, None);
        assert_eq!(&output[..24], &super::super::CAPTURE_HEADER);
        let s = input.shared.borrow();
        assert_eq!(s.events[0], "ready");
        assert_eq!(s.events.iter().filter(|e| **e == "end").count(), 1);
        assert!(
            s.events.iter().position(|e| *e == "end") < s.events.iter().position(|e| *e == "stats")
        );
    }
    #[test]
    fn deadline_and_lost_control_invalidate_readiness_with_no_false_success() {
        for broken in [false, true] {
            let (mut input, mut clock) = setup(vec![]);
            clock.stop = Duration::MAX;
            clock.broken = broken;
            let r = record(&mut input, &mut Vec::new(), &mut clock);
            assert!(r.error.as_deref().unwrap().contains(if broken {
                "control"
            } else {
                "deadline"
            }));
            assert!(clock.elapsed() <= Duration::from_secs(40));
            assert!(input.shared.borrow().events.contains(&"end"));
        }
    }
    #[test]
    fn read_failure_and_drops_preserve_partial_count_but_fail() {
        let (mut input, mut clock) = setup(vec![packet()]);
        input.broken = true;
        let r = record(&mut input, &mut Vec::new(), &mut clock);
        assert_eq!(r.recorded, 0);
        assert!(r.error.unwrap().contains("read failed"));
        assert!(input.shared.borrow().events.contains(&"end"));
        let (mut input, mut clock) = setup(vec![packet()]);
        input.stats.dropped = 1;
        let r = record(&mut input, &mut Vec::new(), &mut clock);
        assert_eq!(r.recorded, 1);
        assert!(r.error.unwrap().contains("statistics"));
    }
    #[test]
    fn packet_count_and_time_order_fail_before_credit() {
        let (mut input, mut clock) = setup(std::iter::repeat_with(packet).take(1025).collect());
        input.step = Duration::ZERO;
        clock.stop = Duration::ZERO;
        let r = record(&mut input, &mut Vec::new(), &mut clock);
        assert_eq!(r.recorded, 1024);
        assert!(r.error.unwrap().contains("budget"));
        let mut earlier = packet();
        earlier.seconds -= 1;
        let (mut input, mut clock) = setup(vec![packet(), earlier]);
        let r = record(&mut input, &mut Vec::new(), &mut clock);
        assert_eq!(r.recorded, 1);
        assert!(r.error.unwrap().contains("backward"));
    }
    #[test]
    fn blocked_read_and_never_quiet_drain_are_bounded_and_revoke_readiness() {
        let (mut input, mut clock) = setup(vec![packet()]);
        input.step = Duration::from_secs(40);
        let r = record(&mut input, &mut Vec::new(), &mut clock);
        assert!(r.error.unwrap().contains("deadline"));
        assert_eq!(r.recorded, 0);
        assert!(input.shared.borrow().events.contains(&"end"));
        let (mut input, mut clock) = setup(std::iter::repeat_with(packet).take(100).collect());
        clock.stop = Duration::ZERO;
        let r = record(&mut input, &mut Vec::new(), &mut clock);
        assert!(r.error.unwrap().contains("drain"));
        assert!(clock.elapsed() <= Duration::from_millis(500));
    }
    #[test]
    fn partial_disk_write_never_credits_a_packet_or_leaves_ready() {
        struct Disk {
            remaining: usize,
        }
        impl Write for Disk {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.remaining == 0 {
                    return Err(std::io::Error::other("disk full"));
                }
                let n = self.remaining.min(bytes.len());
                self.remaining -= n;
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for remaining in [0, 24 + 16 + 30] {
            let (mut input, mut clock) = setup(vec![packet()]);
            let r = record(&mut input, &mut Disk { remaining }, &mut clock);
            assert_eq!(r.recorded, 0);
            assert!(r.error.unwrap().contains("disk full"));
            assert!(input.shared.borrow().events.contains(&"end"));
            assert_eq!(
                input.shared.borrow().events.contains(&"ready"),
                remaining != 0
            );
        }
    }
    #[test]
    fn malformed_packet_never_gets_written() {
        for kind in 0..4 {
            let mut p = packet();
            match kind {
                0 => p.original_len += 1,
                1 => p.micros = 1_000_000,
                2 => p.bytes.truncate(13),
                _ => p.bytes = vec![0; 131073],
            };
            let (mut input, mut clock) = setup(vec![p]);
            let mut out = Vec::new();
            let r = record(&mut input, &mut out, &mut clock);
            assert_eq!(r.recorded, 0);
            assert!(r.error.unwrap().contains("truncated"));
            assert_eq!(out, CAPTURE_HEADER);
        }
    }
    #[test]
    fn partial_publication_and_failed_end_still_invalidate_before_return() {
        for at_ready in [true, false] {
            let (mut input, mut clock) = setup(vec![packet()]);
            clock.ready_error = at_ready;
            clock.end_error = true;
            let r = record(&mut input, &mut Vec::new(), &mut clock);
            assert!(r.error.as_deref().unwrap().contains("end marker"));
            if at_ready {
                assert!(r.error.unwrap().contains("partial publish"));
            }
            let s = input.shared.borrow();
            assert!(
                s.events.iter().position(|e| *e == "invalidate")
                    < s.events.iter().position(|e| *e == "stats")
            );
        }
    }
}
