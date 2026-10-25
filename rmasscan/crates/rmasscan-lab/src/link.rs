//! Laboratory frame I/O on top of the adapter the product itself uses (`open_explicit`):
//! the same AF_PACKET TX/RX halves, with their deadlines, back-pressure statuses and counters.
//! No raw descriptor is opened by the lab, so this crate stays free of `unsafe`.
//!
//! Capture is not done here: the witness is the independent `tcpdump` (see `dump`).
use rmasscan_core::{packet::LinkType, probe::AdapterBinding};
use rmasscan_engine::{Rx, SendStatus, Tx};
#[cfg(not(target_os = "macos"))]
use std::fs;
use std::time::{Duration, Instant};

/// Ethertype of the lab marker frames (IEEE 802 local experimental).
pub const MARKER_ETHERTYPE: [u8; 2] = [0x88, 0xb5];
pub const START_PAYLOAD: &[u8] = b"WIRELAB-READY";
pub const END_PAYLOAD: &[u8] = b"WIRELAB-END";
/// How long one frame may wait behind a full device queue before the sender gives up. The earlier
/// senders blocked in `send`; this is the same behaviour with a bound, so a dead link cannot hang
/// the lab forever.
pub const SEND_PATIENCE: Duration = Duration::from_secs(30);
const ATTEMPT: Duration = Duration::from_millis(50);

pub struct Link {
    pub tx: Box<dyn Tx>,
    pub rx: Box<dyn Rx>,
}

/// An interface name the lab may hand to the OS: no path separators or traversal.
pub fn safe_iface(iface: &str) -> bool {
    !iface.is_empty()
        && iface.len() < 16
        && iface != "."
        && iface != ".."
        && !iface
            .bytes()
            .any(|b| b == 0 || b == b'/' || b.is_ascii_whitespace())
}

pub fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 || parts.iter().any(|p| p.len() != 2) {
        return Err(format!("invalid MAC {s:?}"));
    }
    let mut out = [0u8; 6];
    for (o, p) in out.iter_mut().zip(&parts) {
        *o = u8::from_str_radix(p, 16).map_err(|_| format!("invalid MAC {s:?}"))?;
    }
    Ok(out)
}

pub fn iface_mac(iface: &str) -> Result<[u8; 6], String> {
    if !safe_iface(iface) {
        return Err(format!("invalid interface name {iface:?}"));
    }
    iface_mac_os(iface)
}

/// macOS: the interface's link-layer address through the product's `getifaddrs` wrapper.
#[cfg(target_os = "macos")]
fn iface_mac_os(iface: &str) -> Result<[u8; 6], String> {
    rmasscan_net::nic_mac(iface).ok_or_else(|| format!("{iface}: no link-layer address"))
}

#[cfg(not(target_os = "macos"))]
fn iface_mac_os(iface: &str) -> Result<[u8; 6], String> {
    let text = fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .map_err(|e| format!("{iface}: {e}"))?;
    parse_mac(text.trim())
}

/// Open TX and RX on `iface` through the product adapter. Needs CAP_NET_RAW, like the product.
pub fn open(iface: &str) -> Result<Link, String> {
    let binding = AdapterBinding {
        interface_id: iface.to_string(),
        link_type: LinkType::Ethernet,
        source_ipv4: 0,
        source_mac: iface_mac(iface)?,
        next_hop_mac: [0; 6],
        source_ports: (0, 0),
    };
    let opened = rmasscan_net::open_explicit(&binding).map_err(|e| e.to_string())?;
    Ok(Link {
        tx: opened.io.tx,
        rx: opened.io.rx,
    })
}

/// A lab marker frame: `dst`, `src`, ethertype 0x88b5, `payload`, zero-padded to 60 bytes.
pub fn marker_frame(dst: [u8; 6], src: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut f = dst.to_vec();
    f.extend(src);
    f.extend(MARKER_ETHERTYPE);
    f.extend(payload);
    if f.len() < 60 {
        f.resize(60, 0);
    }
    f
}

/// How many frames are lab markers carrying `payload` at the start of their payload.
pub fn count_markers<'a>(frames: impl IntoIterator<Item = &'a [u8]>, payload: &[u8]) -> usize {
    frames
        .into_iter()
        .filter(|f| f.get(12..14) == Some(&MARKER_ETHERTYPE) && f[14..].starts_with(payload))
        .count()
}

/// Send one frame with blocking/back-pressure semantics: a full device queue
/// (`WouldBlockUnsent`) is retried until `patience` runs out; `Uncertain` and I/O errors are
/// failures. Returns how many times the queue was full. Stops early when `stop()` turns true.
pub fn send_blocking(
    tx: &mut dyn Tx,
    frame: &[u8],
    patience: Duration,
    stop: &dyn Fn() -> bool,
) -> Result<u64, String> {
    let start = Instant::now();
    let mut waits = 0;
    loop {
        match tx.send(frame, ATTEMPT).map_err(|e| e.to_string())? {
            SendStatus::Sent => return Ok(waits),
            SendStatus::WouldBlockUnsent => {
                waits += 1;
                if stop() {
                    return Err("interrupted while the TX queue was full".into());
                }
                if start.elapsed() >= patience {
                    return Err(format!(
                        "TX queue stayed full for {} ms",
                        patience.as_millis()
                    ));
                }
            }
            SendStatus::Uncertain => {
                return Err("send outcome uncertain (partial write)".into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmasscan_engine::IoError;
    use std::collections::VecDeque;

    struct Scripted(VecDeque<Result<SendStatus, IoError>>, usize);
    impl Tx for Scripted {
        fn send(&mut self, _frame: &[u8], _timeout: Duration) -> Result<SendStatus, IoError> {
            self.1 += 1;
            self.0.pop_front().unwrap_or(Ok(SendStatus::Sent))
        }
    }
    fn tx(steps: Vec<Result<SendStatus, IoError>>) -> Scripted {
        Scripted(steps.into(), 0)
    }

    #[test]
    fn a_full_queue_is_retried_until_the_frame_is_sent() {
        let mut t = tx(vec![
            Ok(SendStatus::WouldBlockUnsent),
            Ok(SendStatus::WouldBlockUnsent),
            Ok(SendStatus::Sent),
        ]);
        let waits = send_blocking(&mut t, &[0; 60], Duration::from_secs(5), &|| false).unwrap();
        assert_eq!((waits, t.1), (2, 3));
    }

    #[test]
    fn a_queue_that_never_drains_gives_up_after_the_patience() {
        struct AlwaysFull;
        impl Tx for AlwaysFull {
            fn send(&mut self, _: &[u8], _: Duration) -> Result<SendStatus, IoError> {
                std::thread::sleep(Duration::from_millis(5));
                Ok(SendStatus::WouldBlockUnsent)
            }
        }
        let mut t = AlwaysFull;
        let started = Instant::now();
        let e = send_blocking(&mut t, &[0; 60], Duration::from_millis(30), &|| false).unwrap_err();
        assert!(e.contains("stayed full"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn an_interrupt_ends_the_wait_and_failures_are_never_retried() {
        let mut t = tx(vec![Ok(SendStatus::WouldBlockUnsent)]);
        let e = send_blocking(&mut t, &[0; 60], Duration::from_secs(5), &|| true).unwrap_err();
        assert!(e.contains("interrupted"), "{e}");
        let mut t = tx(vec![Ok(SendStatus::Uncertain)]);
        assert!(
            send_blocking(&mut t, &[0; 60], Duration::from_secs(5), &|| false)
                .unwrap_err()
                .contains("uncertain")
        );
        assert_eq!(t.1, 1, "an uncertain send is not repeated");
        let mut t = tx(vec![Err(IoError::new("adapter closed"))]);
        assert!(send_blocking(&mut t, &[0; 60], Duration::from_secs(5), &|| false).is_err());
        assert_eq!(t.1, 1);
    }

    #[test]
    fn marker_frames_are_padded_ordered_and_never_truncated() {
        let f = marker_frame([1; 6], [2; 6], START_PAYLOAD);
        assert_eq!(f.len(), 60);
        assert_eq!(&f[..6], &[1; 6], "destination first");
        assert_eq!(&f[6..12], &[2; 6]);
        assert_eq!(&f[12..14], &MARKER_ETHERTYPE);
        assert_eq!(&f[14..27], START_PAYLOAD);
        let long = marker_frame([1; 6], [2; 6], &[7; 100]);
        assert_eq!(long.len(), 14 + 100, "a longer payload is kept whole");
    }

    #[test]
    fn markers_are_counted_by_payload_and_short_frames_never_panic() {
        let ready = marker_frame([1; 6], [2; 6], START_PAYLOAD);
        let end = marker_frame([1; 6], [2; 6], END_PAYLOAD);
        let mut other_type = ready.clone();
        other_type[12] = 0x08;
        let frames: Vec<&[u8]> = vec![&ready, &end, &end, &end, &other_type];
        assert_eq!(count_markers(frames.iter().copied(), START_PAYLOAD), 1);
        assert_eq!(count_markers(frames.iter().copied(), END_PAYLOAD), 3);
        for n in 0..14 {
            assert_eq!(count_markers([&ready[..n]], START_PAYLOAD), 0);
        }
        assert_eq!(count_markers([&ready[..14]], START_PAYLOAD), 0);
    }

    #[test]
    fn interface_names_and_macs_are_validated() {
        assert!(safe_iface("veth-b") && safe_iface("lab0"));
        for bad in ["", ".", "..", "a/b", "a b", "0123456789abcdef", "a\0b"] {
            assert!(!safe_iface(bad), "{bad:?}");
        }
        assert_eq!(
            parse_mac("02:aa:00:00:00:01").unwrap(),
            [2, 0xaa, 0, 0, 0, 1]
        );
        for bad in [
            "",
            "02:aa:00:00:00",
            "02:aa:00:00:00:01:02",
            "2:aa:00:00:00:01",
            "02:aa:00:00:00:zz",
        ] {
            assert!(parse_mac(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn opening_a_missing_interface_is_a_clean_error_without_privileges() {
        // On Linux without such an interface, and on any other platform, open() fails before any
        // frame is sent; it never panics and never needs root to say no.
        assert!(open("rml-nonexistent0").is_err());
    }
}
