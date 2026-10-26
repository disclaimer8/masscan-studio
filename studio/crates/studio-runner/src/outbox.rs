//! Nonblocking output bounded by serialized bytes, including the in-flight frame.
use std::{
    io::{self, Write},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use studio_protocol::{Envelope, Event, write_frame};

const BYTE_LIMIT: usize = 4 * 1024 * 1024;
// Independent bound on allocation/channel overhead for tiny control frames.
const FRAME_LIMIT: usize = 1024;
pub struct Sender {
    tx: mpsc::SyncSender<Frame>,
    used: Arc<AtomicUsize>,
    limit: usize,
    activity: Arc<Activity>,
}
struct Activity {
    start: Instant,
    last_write_ms: AtomicU64,
}
pub struct Receipt(Arc<OnceLock<Instant>>);
impl Receipt {
    pub fn delivered(&self) -> Option<Instant> {
        self.0.get().copied()
    }
}
pub struct Frame {
    bytes: Vec<u8>,
    used: Arc<AtomicUsize>,
    pub rows: usize,
    receipt: Option<Arc<OnceLock<Instant>>>,
    activity: Arc<Activity>,
}
impl Frame {
    pub fn write(&self, out: &mut impl Write) -> io::Result<()> {
        out.write_all(&self.bytes)?;
        out.flush()?;
        let now = Instant::now();
        self.activity.last_write_ms.store(
            self.activity.start.elapsed().as_millis() as u64,
            Ordering::Release,
        );
        if let Some(receipt) = &self.receipt {
            let _ = receipt.set(now);
        }
        Ok(())
    }
}
impl Drop for Frame {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes.len(), Ordering::AcqRel);
    }
}
pub fn channel() -> (Sender, mpsc::Receiver<Frame>) {
    bounded(BYTE_LIMIT)
}
fn bounded(limit: usize) -> (Sender, mpsc::Receiver<Frame>) {
    let (tx, rx) = mpsc::sync_channel(FRAME_LIMIT);
    (
        Sender {
            tx,
            used: Arc::new(AtomicUsize::new(0)),
            limit,
            activity: Arc::new(Activity {
                start: Instant::now(),
                last_write_ms: AtomicU64::new(0),
            }),
        },
        rx,
    )
}
impl Sender {
    pub fn try_send(&self, event: Envelope<Event>) -> Result<(), String> {
        self.enqueue(event, None)
    }
    pub fn try_send_tracked(&self, event: Envelope<Event>) -> Result<Receipt, String> {
        let receipt = Arc::new(OnceLock::new());
        self.enqueue(event, Some(receipt.clone()))?;
        Ok(Receipt(receipt))
    }
    pub fn idle_for(&self) -> Duration {
        let now = self.activity.start.elapsed().as_millis() as u64;
        Duration::from_millis(
            now.saturating_sub(self.activity.last_write_ms.load(Ordering::Acquire)),
        )
    }
    fn enqueue(
        &self,
        event: Envelope<Event>,
        receipt: Option<Arc<OnceLock<Instant>>>,
    ) -> Result<(), String> {
        let rows = match &event.payload {
            Event::Results(rows) => rows.len(),
            _ => 0,
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &event).map_err(|e| e.to_string())?;
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes.len())
                    .filter(|total| *total <= self.limit)
            })
            .map_err(|_| "Event pipe exhausted its 4 MiB serialized byte budget")?;
        self.tx
            .try_send(Frame {
                bytes,
                used: self.used.clone(),
                rows,
                receipt,
                activity: self.activity.clone(),
            })
            .map_err(|_| "Event pipe frame limit reached or writer closed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use studio_protocol::{Row, read_frame};
    fn event() -> Envelope<Event> {
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
                500
            ]),
        )
    }
    #[test]
    fn small_frames_use_the_byte_budget_instead_of_failing_at_32_frames() {
        let (tx, rx) = channel();
        let mut count = 0;
        while tx.try_send(event()).is_ok() {
            count += 1;
        }
        assert!(count > 32);
        assert!(tx.used.load(Ordering::Acquire) <= BYTE_LIMIT);
        let frame = rx.recv().unwrap();
        assert!(
            tx.try_send(event()).is_err(),
            "in-flight frame is still reserved"
        );
        drop(frame);
        tx.try_send(event()).unwrap();
        drop(rx);
        assert_eq!(tx.used.load(Ordering::Acquire), 0);
        assert!(tx.try_send(event()).is_err());
        assert_eq!(tx.used.load(Ordering::Acquire), 0);
    }
    #[test]
    fn encoded_frames_preserve_protocol_and_release_budget_after_write_failure() {
        let (tx, rx) = channel();
        tx.try_send(event()).unwrap();
        let frame = rx.recv().unwrap();
        let parsed: Envelope<Event> = read_frame(&mut frame.bytes.as_slice()).unwrap();
        assert_eq!(parsed.payload, event().payload);
        assert!(
            frame
                .write(&mut io::Cursor::new(&mut [0u8; 1][..]))
                .is_err()
        );
        assert!(tx.used.load(Ordering::Acquire) > 0);
        drop(frame);
        assert_eq!(tx.used.load(Ordering::Acquire), 0);
    }
    #[test]
    fn oversized_reservation_leaves_no_budget_debt() {
        let (tx, _rx) = bounded(1);
        assert!(tx.try_send(event()).is_err());
        assert_eq!(tx.used.load(Ordering::Acquire), 0);
    }
    #[test]
    fn tiny_frame_count_limit_releases_the_rejected_reservation() {
        let (tx, _rx) = channel();
        let event = Envelope::new(
            [1; 16],
            [2; 16],
            [3; 16],
            1,
            Event::Progress {
                sent: "0".into(),
                received: "0".into(),
            },
        );
        for _ in 0..FRAME_LIMIT {
            tx.try_send(event.clone()).unwrap();
        }
        let used = tx.used.load(Ordering::Acquire);
        assert!(used < BYTE_LIMIT);
        assert!(tx.try_send(event).is_err());
        assert_eq!(tx.used.load(Ordering::Acquire), used);
    }
    #[test]
    fn receipt_is_ready_only_after_the_frame_is_flushed() {
        let (tx, rx) = channel();
        let receipt = tx.try_send_tracked(event()).unwrap();
        assert!(receipt.delivered().is_none());
        let frame = rx.recv().unwrap();
        assert!(receipt.delivered().is_none());
        assert!(
            frame
                .write(&mut io::Cursor::new(&mut [0u8; 1][..]))
                .is_err()
        );
        assert!(receipt.delivered().is_none());
        frame.write(&mut Vec::new()).unwrap();
        assert!(receipt.delivered().is_some());
    }
}
