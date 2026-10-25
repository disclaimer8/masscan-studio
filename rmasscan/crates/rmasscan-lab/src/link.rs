//! Laboratory frame I/O on top of the adapter the product itself uses (`open_explicit`):
//! the same AF_PACKET TX/RX halves, with their deadlines, back-pressure statuses and counters.
//! No raw descriptor is opened by the lab, so this crate stays free of `unsafe`.
//!
//! Capture is not done here: the witness is the independent `tcpdump` (see `dump`).
use rmasscan_core::{packet::LinkType, probe::AdapterBinding};
use rmasscan_engine::{Rx, SendStatus, Tx, TxBatch};
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

#[cfg(target_os = "macos")]
/// The MAC from `ifconfig IFACE` output (`ether xx:..`, octets without leading zeros are
/// normalised). Unprivileged `getifaddrs` and `NET_RT_IFLIST` report the placeholder
/// `02:00:00:00:00:00` for every Ethernet interface on recent macOS, while `ifconfig` shows the
/// real address, so that placeholder is "unknown", never a MAC.
pub fn mac_from_ifconfig(iface: &str, text: &str) -> Result<[u8; 6], String> {
    let mac = crate::macos_lab::parse_ifconfig(text)
        .ether
        .ok_or_else(|| format!("{iface}: ifconfig shows no ether line"))?;
    if mac == "02:00:00:00:00:00" {
        return Err(format!(
            "{iface}: the MAC is masked (02:00:00:00:00:00); it is unknown, not a real address"
        ));
    }
    parse_mac(&mac)
}

/// macOS: the interface's link-layer address from `/sbin/ifconfig` (never from
/// `rmasscan_net::nic_mac`, which is masked for unprivileged processes).
#[cfg(target_os = "macos")]
fn iface_mac_os(iface: &str) -> Result<[u8; 6], String> {
    let out = std::process::Command::new("/sbin/ifconfig")
        .arg(iface)
        .output()
        .map_err(|e| format!("ifconfig: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{iface}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    mac_or_stand_plan(iface, &String::from_utf8_lossy(&out.stdout))
}

/// Like [`mac_from_ifconfig`], except for the two stand interfaces when the OS masks the MAC
/// (Darwin hides MACs from processes descended from an ad-hoc-signed executable): then the MAC
/// is the stand plan's constant. The placeholder itself is never returned as a MAC; root verified
/// the real ones at `up`, and `macos-lab status` checks the stand against the manifest.
#[cfg(target_os = "macos")]
pub fn mac_or_stand_plan(iface: &str, text: &str) -> Result<[u8; 6], String> {
    use crate::macos_lab::{MASKED_MAC, PEER_IF, PEER_MAC, SCANNER_IF, SCANNER_MAC};
    match mac_from_ifconfig(iface, text) {
        Ok(m) => Ok(m),
        Err(e) => {
            let masked =
                crate::macos_lab::parse_ifconfig(text).ether.as_deref() == Some(MASKED_MAC);
            let plan = match iface {
                SCANNER_IF => Some(SCANNER_MAC),
                PEER_IF => Some(PEER_MAC),
                _ => None,
            };
            match (masked, plan) {
                (true, Some(p)) => parse_mac(p),
                _ => Err(e),
            }
        }
    }
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

/// The macOS stand MACs (scanner side, peer side) as bytes: the only addresses the guard below lets the lab write.
pub const STAND_SCANNER_MAC: [u8; 6] = [0x02, 0xac, 0, 0, 0, 0x01];
pub const STAND_PEER_MAC: [u8; 6] = [0x02, 0xac, 0, 0, 0, 0x02];

/// The one rule for every frame the lab itself writes on the macOS stand: peer MAC to scanner MAC, and either the
/// lab marker ethertype (0x88b5) or IPv4 from 198.18.0.2 to 198.18.0.1. Nothing else is ever written.
pub fn injection_allowed(f: &[u8]) -> bool {
    if f.len() < 14 || f[0..6] != STAND_SCANNER_MAC || f[6..12] != STAND_PEER_MAC {
        return false;
    }
    match [f[12], f[13]] {
        [0x88, 0xb5] => true,
        [0x08, 0x00] => {
            f.len() >= 34
                && f[14] >> 4 == 4
                && f[26..30] == [198, 18, 0, 2]
                && f[30..34] == [198, 18, 0, 1]
        }
        _ => false,
    }
}

/// Wraps a `Tx`; a frame outside [`injection_allowed`] is refused (an error) and counted, never written.
pub struct GuardedTx {
    pub inner: Box<dyn Tx>,
    pub refused: std::sync::Arc<std::sync::atomic::AtomicU64>,
}
impl Tx for GuardedTx {
    fn send(
        &mut self,
        frame: &[u8],
        timeout: Duration,
    ) -> Result<SendStatus, rmasscan_engine::IoError> {
        if !injection_allowed(frame) {
            self.refused
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(rmasscan_engine::IoError::new(
                "refused: the frame is outside the lab's peer-side guard",
            ));
        }
        self.inner.send(frame, timeout)
    }

    fn max_batch(&self) -> usize {
        self.inner.max_batch()
    }

    /// Every frame of the batch is checked first; one outside the guard refuses the whole batch (an error, nothing
    /// written) and counts each offending frame.
    fn send_batch(
        &mut self,
        frames: &[&[u8]],
        timeout: Duration,
    ) -> Result<TxBatch, rmasscan_engine::IoError> {
        let bad = frames.iter().filter(|f| !injection_allowed(f)).count();
        if bad > 0 {
            self.refused
                .fetch_add(bad as u64, std::sync::atomic::Ordering::Relaxed);
            return Err(rmasscan_engine::IoError::new(
                "refused: a frame of the batch is outside the lab's peer-side guard",
            ));
        }
        self.inner.send_batch(frames, timeout)
    }
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

    #[cfg(target_os = "macos")]
    #[test]
    fn the_mac_comes_from_ifconfig_text_and_a_masked_placeholder_is_refused() {
        let real = "feth4201: flags=8863<UP> mtu 1500\n\tether 2:ac:0:0:0:1\n\tstatus: active\n";
        assert_eq!(
            mac_from_ifconfig("feth4201", real).unwrap(),
            [0x02, 0xac, 0, 0, 0, 1]
        );
        let masked = "en0: flags=8863<UP>\n\tether 02:00:00:00:00:00\n";
        assert!(
            mac_from_ifconfig("en0", masked)
                .unwrap_err()
                .contains("masked")
        );
        let masked_short = "en0: flags=8863<UP>\n\tether 2:0:0:0:0:0\n";
        assert!(mac_from_ifconfig("en0", masked_short).is_err());
        assert!(mac_from_ifconfig("lo0", "lo0: flags=8049<UP>\n").is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_masked_stand_mac_is_the_plan_constant_and_nothing_else_is() {
        let masked = "feth4201: flags=8843<UP>\n\tether 02:00:00:00:00:00\n";
        assert_eq!(
            mac_or_stand_plan("feth4201", masked).unwrap(),
            [0x02, 0xac, 0, 0, 0, 1]
        );
        assert_eq!(
            mac_or_stand_plan("feth4202", masked).unwrap(),
            [0x02, 0xac, 0, 0, 0, 2]
        );
        // Any other interface keeps the strict refusal; the placeholder is never a MAC.
        assert!(
            mac_or_stand_plan("en0", masked)
                .unwrap_err()
                .contains("masked")
        );
        // A real MAC on a stand interface is returned as it is (so a mismatch is visible).
        let other = "feth4201: flags=8843<UP>\n\tether 02:ac:00:00:00:09\n";
        assert_eq!(
            mac_or_stand_plan("feth4201", other).unwrap(),
            [0x02, 0xac, 0, 0, 0, 9]
        );
        // No ether line at all is an error, not the plan.
        assert!(mac_or_stand_plan("feth4201", "feth4201: flags=8843<UP>\n").is_err());
    }

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
