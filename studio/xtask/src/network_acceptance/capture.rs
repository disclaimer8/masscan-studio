//! Independent bounded witness recording; never uses the scanner's adapters.
use std::{io::Write, time::Duration};
#[cfg(target_os = "macos")]
pub const UPLINK_FILTER: &str = "net 198.18.42.0/29 or host 198.19.42.2 or ether host 02:ac:42:00:00:01 or ether host 02:ac:42:00:00:02 or ether host 02:ac:42:00:01:02 or ether host 02:ac:42:00:01:03 or ether host 02:ac:42:00:01:04";
pub fn read_stop(mut input: impl std::io::Read) -> Result<(), String> {
    let mut byte = [0];
    input
        .read_exact(&mut byte)
        .map_err(|e| format!("capture control lost: {e}"))?;
    if byte != *b"S" {
        return Err("invalid capture stop command".into());
    }
    Ok(())
}

#[derive(Clone)]
pub struct Packet {
    pub seconds: u32,
    pub micros: u32,
    pub original_len: u32,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    pub received: u32,
    pub dropped: u32,
    pub interface_dropped: u32,
}
pub trait Source {
    fn next(&mut self) -> Result<Option<Packet>, String>;
    fn stats(&mut self) -> Result<Stats, String>;
}
pub trait Runtime {
    fn elapsed(&self) -> Duration;
    fn stop(&mut self) -> Result<bool, String>;
    fn idle(&mut self);
    fn ready(&mut self) -> Result<(), String> {
        Ok(())
    }
}
pub fn validate_stats(count: u64, stats: Stats) -> Result<(), String> {
    if stats.dropped != 0 || stats.interface_dropped != 0 || u64::from(stats.received) < count {
        return Err("capture statistics report drops or inconsistent received count".into());
    }
    Ok(())
}
pub fn record(
    source: &mut impl Source,
    out: &mut impl Write,
    runtime: &mut impl Runtime,
) -> Result<u64, String> {
    let header: [u8; 24] = [
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0,
    ];
    out.write_all(&header).map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    runtime.ready()?;
    let mut drain = None;
    let mut bytes = header.len();
    let mut count = 0;
    let mut previous = None;
    loop {
        let now = runtime.elapsed();
        if now >= Duration::from_secs(120) {
            return Err("capture deadline expired".into());
        }
        if drain.is_none() && runtime.stop()? {
            drain = Some(now + Duration::from_millis(500));
        }
        if drain.is_some_and(|deadline| now >= deadline) {
            return Err("capture drain deadline expired".into());
        }
        let packet = source.next()?;
        if runtime.elapsed() >= Duration::from_secs(120) {
            return Err("capture deadline expired".into());
        }
        if drain.is_some_and(|deadline| runtime.elapsed() >= deadline) {
            return Err("capture drain deadline expired".into());
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
            return Err("invalid/truncated capture packet".into());
        }
        let timestamp = (p.seconds, p.micros);
        if previous.is_some_and(|prior| prior > timestamp) {
            return Err("capture timestamp went backward".into());
        }
        if count >= 20_000 || bytes + 16 + p.bytes.len() > super::witness::MAX_CAPTURE {
            return Err("capture exceeds packet/byte budget".into());
        }
        let mut record = Vec::with_capacity(16 + p.bytes.len());
        for field in [p.seconds, p.micros, p.original_len, p.original_len] {
            record.extend_from_slice(&field.to_le_bytes());
        }
        record.extend_from_slice(&p.bytes);
        out.write_all(&record).map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())?;
        bytes += record.len();
        count += 1;
        previous = Some(timestamp);
    }
    validate_stats(count, source.stats()?)?;
    out.flush().map_err(|e| e.to_string())?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, collections::VecDeque, rc::Rc};
    #[test]
    fn only_explicit_stop_byte_accepts_and_eof_is_failure() {
        assert!(read_stop(&b"S"[..]).is_ok());
        assert!(read_stop(&b""[..]).is_err());
        assert!(read_stop(&b"X"[..]).is_err());
    }
    struct Fake {
        queue: VecDeque<Packet>,
        stats: Stats,
        clock: Rc<Cell<Duration>>,
        endless: bool,
        read_step: Duration,
    }
    impl Source for Fake {
        fn next(&mut self) -> Result<Option<Packet>, String> {
            self.clock.set(self.clock.get() + self.read_step);
            Ok(if self.endless {
                Some(packet())
            } else {
                self.queue.pop_front()
            })
        }
        fn stats(&mut self) -> Result<Stats, String> {
            Ok(self.stats)
        }
    }
    struct Clock {
        clock: Rc<Cell<Duration>>,
        stop_after: Duration,
        broken: bool,
    }
    impl Runtime for Clock {
        fn elapsed(&self) -> Duration {
            self.clock.get()
        }
        fn stop(&mut self) -> Result<bool, String> {
            if self.broken {
                Err("control EOF".into())
            } else {
                Ok(self.elapsed() >= self.stop_after)
            }
        }
        fn idle(&mut self) {
            self.clock.set(self.clock.get() + Duration::from_millis(10));
        }
    }
    fn packet() -> Packet {
        Packet {
            seconds: 100,
            micros: 123,
            original_len: 60,
            bytes: vec![0; 60],
        }
    }
    fn fixture(packets: Vec<Packet>) -> (Fake, Clock) {
        let clock = Rc::new(Cell::new(Duration::ZERO));
        (
            Fake {
                stats: Stats {
                    received: packets.len() as u32,
                    ..Stats::default()
                },
                queue: packets.into(),
                clock: clock.clone(),
                endless: false,
                read_step: Duration::from_millis(10),
            },
            Clock {
                clock,
                stop_after: Duration::ZERO,
                broken: false,
            },
        )
    }
    #[test]
    fn empty_capture_stops_with_valid_header_and_zero_counters() {
        let (mut source, mut clock) = fixture(vec![]);
        clock.stop_after = Duration::from_millis(40);
        let mut out = Vec::new();
        assert_eq!(record(&mut source, &mut out, &mut clock).unwrap(), 0);
        assert_eq!(out.len(), 24);
        assert!(super::super::witness::frames(&out).unwrap().is_empty());
        assert!(clock.elapsed() < Duration::from_millis(100));
    }
    #[test]
    fn stop_drains_queued_packets_and_preserves_capture_timestamps() {
        let (mut source, mut clock) = fixture(vec![packet(), packet()]);
        let mut out = Vec::new();
        assert_eq!(record(&mut source, &mut out, &mut clock).unwrap(), 2);
        let frames = super::super::witness::frames(&out).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].time_ns, 100_000_123_000);
        assert_eq!(frames[0].frame.len(), 60);
    }
    #[test]
    fn lost_control_and_never_quiet_backlog_fail() {
        let (mut source, mut clock) = fixture(vec![]);
        clock.broken = true;
        assert!(
            record(&mut source, &mut Vec::new(), &mut clock)
                .unwrap_err()
                .contains("control")
        );
        clock.broken = false;
        source.endless = true;
        assert!(
            record(&mut source, &mut Vec::new(), &mut clock)
                .unwrap_err()
                .contains("drain")
        );
    }
    #[test]
    fn deadline_is_not_renewed_by_idle_reads() {
        let (mut source, mut clock) = fixture(vec![]);
        clock.stop_after = Duration::MAX;
        assert!(
            record(&mut source, &mut Vec::new(), &mut clock)
                .unwrap_err()
                .contains("deadline")
        );
        assert!(clock.elapsed() <= Duration::from_secs(121));
    }
    #[test]
    fn malformed_and_backward_packets_fail_before_record_credit() {
        for modify in [
            |p: &mut Packet| p.original_len = 61,
            |p: &mut Packet| p.micros = 1_000_000,
            |p: &mut Packet| p.bytes = vec![0; 131073],
            |p: &mut Packet| p.bytes = vec![0; 13],
        ] {
            let mut p = packet();
            modify(&mut p);
            let (mut source, mut clock) = fixture(vec![p]);
            let mut out = Vec::new();
            assert!(record(&mut source, &mut out, &mut clock).is_err());
            assert_eq!(out.len(), 24);
        }
        let mut earlier = packet();
        earlier.seconds = 99;
        let (mut source, mut clock) = fixture(vec![packet(), earlier]);
        assert!(
            record(&mut source, &mut Vec::new(), &mut clock)
                .unwrap_err()
                .contains("backward")
        );
    }
    #[test]
    fn measured_drops_and_inconsistent_counters_cannot_succeed() {
        for stats in [
            Stats {
                received: 1,
                dropped: 1,
                interface_dropped: 0,
            },
            Stats {
                received: 1,
                dropped: 0,
                interface_dropped: 1,
            },
            Stats::default(),
        ] {
            let (mut source, mut clock) = fixture(vec![packet()]);
            source.stats = stats;
            assert!(
                record(&mut source, &mut Vec::new(), &mut clock)
                    .unwrap_err()
                    .contains("statistics")
            );
        }
    }
    #[test]
    fn writer_failure_propagates() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (mut source, mut clock) = fixture(vec![]);
        assert!(
            record(&mut source, &mut Broken, &mut clock)
                .unwrap_err()
                .contains("disk full")
        );
    }
    #[test]
    fn capture_budget_accepts_twenty_thousand_packets_but_refuses_one_more() {
        for count in [20_000, 20_001] {
            let (mut source, mut clock) = fixture(vec![packet(); count]);
            source.read_step = Duration::ZERO;
            let result = record(&mut source, &mut Vec::new(), &mut clock);
            if count == 20_000 {
                assert_eq!(result.unwrap(), 20_000);
            } else {
                assert!(result.unwrap_err().contains("budget"));
            }
        }
    }
    #[test]
    fn capture_budget_accepts_exact_sixteen_mib_but_refuses_one_extra_byte() {
        for extra in [0, 1] {
            let large = Packet {
                bytes: vec![0; 131072],
                original_len: 131072,
                ..packet()
            };
            let mut packets = vec![large; 127];
            packets.push(Packet {
                bytes: vec![0; 129000 + extra],
                original_len: 129000 + extra as u32,
                ..packet()
            });
            let (mut source, mut clock) = fixture(packets);
            source.read_step = Duration::ZERO;
            let mut out = Vec::new();
            let result = record(&mut source, &mut out, &mut clock);
            if extra == 0 {
                assert_eq!(result.unwrap(), 128);
                assert_eq!(out.len(), 16 * 1024 * 1024);
            } else {
                assert!(result.unwrap_err().contains("budget"));
            }
        }
    }
}
