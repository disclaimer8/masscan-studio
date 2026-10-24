//! The Linux capture witness. `tcpdump`, an independent program, records both directions of the
//! peer veth with the same completeness rules as the Windows stand: packet-buffered writes
//! (`-U --immediate-mode`), a readiness proof before the scanner starts (the start marker is in
//! the pcap), an end proof before it is trusted (three end markers sent after the interface
//! counters went quiet), tcpdump's own packet statistics, and the veth rx+tx counter window.
//! Anything less is INVALID. This module only starts tcpdump, sends the markers and applies the
//! rules; it never writes a captured frame itself.
use crate::{
    link::{self, END_PAYLOAD, START_PAYLOAD},
    pcap,
    windows_suite::{RealClock, parse_tcpdump, wait_quiet_with},
    wire_suite::capture_complete,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Start markers required in the capture before the scanner may start.
pub const START_MARKERS_REQUIRED: usize = 1;
/// End markers sent (and required) after the interface went quiet.
pub const END_MARKERS_REQUIRED: usize = 3;

/// The exact tcpdump command line of the witness.
pub fn tcpdump_argv(iface: &str, pcap: &str) -> Vec<String> {
    [
        "tcpdump",
        "-i",
        iface,
        "-n",
        "-U",
        "--immediate-mode",
        "-s",
        "0",
        "-B",
        "262144",
        "--time-stamp-precision=nano",
        "-Z",
        "root",
        "-w",
        pcap,
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

/// Everything the completeness decision depends on.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub start_markers: usize,
    pub end_markers: usize,
    pub quiesced: bool,
    pub captured: Option<u64>,
    pub received: Option<u64>,
    pub dropped_kernel: Option<u64>,
    pub dropped_if: Option<u64>,
    pub interface_drop_delta: Option<u64>,
    pub pcap_frames: u64,
    pub pcap_error: Option<String>,
    pub tcpdump_exited: bool,
    /// rx+tx counter delta from "listening" to just before the end markers, and to after stop.
    pub window_lo: Option<u64>,
    pub window_hi: Option<u64>,
}

/// Why the capture is not proven complete. Empty means valid.
pub fn problems(f: &Facts) -> Vec<String> {
    let mut p = Vec::new();
    if let Some(e) = &f.pcap_error {
        p.push(format!("pcap unreadable: {e}"));
    }
    if !f.tcpdump_exited {
        p.push("tcpdump did not exit after SIGINT".into());
    }
    if f.start_markers < START_MARKERS_REQUIRED {
        p.push("start marker never captured".into());
    }
    if f.end_markers < END_MARKERS_REQUIRED {
        p.push(format!(
            "{} of {END_MARKERS_REQUIRED} end markers captured: the tail of the capture is not proven",
            f.end_markers
        ));
    }
    if !f.quiesced {
        p.push("peer interface counters never went quiet".into());
    }
    if f.interface_drop_delta != Some(0) {
        p.push(format!(
            "interface rx_dropped delta is {:?}, not a measured 0",
            f.interface_drop_delta
        ));
    }
    let (Some(lo), Some(hi)) = (f.window_lo, f.window_hi) else {
        p.push("interface counters decreased or were unreadable".into());
        return p;
    };
    if !capture_complete(
        f.captured,
        f.received,
        f.dropped_kernel,
        f.dropped_if.or(f.interface_drop_delta),
        f.pcap_frames,
        lo,
        hi,
    ) {
        p.push(format!(
            "tcpdump completeness: captured={:?} received_by_filter={:?} kernel_drops={:?} interface_drops={:?} pcap_frames={} window=[{lo},{hi}]",
            f.captured, f.received, f.dropped_kernel, f.dropped_if, f.pcap_frames
        ));
    }
    p
}

/// What the witness needs from the host. Production reads sysfs and sends frames; tests script it.
pub trait Probe {
    /// rx_packets + tx_packets of the capture interface.
    fn counters(&mut self) -> Result<u64, String>;
    /// rx_dropped of the capture interface.
    fn interface_drops(&mut self) -> Result<u64, String>;
    /// Send the end markers (3 frames) on the capture interface.
    fn send_end(&mut self) -> Result<(), String>;
    fn stop_requested(&self) -> bool;
}

/// Timing knobs; production uses [`Config::standard`].
pub struct Config {
    pub argv: Vec<String>,
    pub pcap: PathBuf,
    pub err: PathBuf,
    pub ready: PathBuf,
    pub ack: PathBuf,
    pub start_timeout: Duration,
    pub settle: Duration,
    pub poll: Duration,
    pub quiet: f64,
    pub quiet_poll: f64,
    pub quiet_timeout: f64,
    pub end_timeout: Duration,
    pub stop_timeout: Duration,
}

impl Config {
    pub fn standard(iface: &str, pcap: &Path, ready: &Path, ack: &Path) -> Self {
        let p = pcap.to_string_lossy().into_owned();
        Self {
            argv: tcpdump_argv(iface, &p),
            pcap: pcap.to_path_buf(),
            err: PathBuf::from(format!("{p}.tcpdump.err")),
            ready: ready.to_path_buf(),
            ack: ack.to_path_buf(),
            start_timeout: Duration::from_secs(15),
            settle: Duration::from_millis(300),
            poll: Duration::from_millis(50),
            quiet: 1.5,
            quiet_poll: 0.25,
            quiet_timeout: 20.0,
            end_timeout: Duration::from_secs(15),
            stop_timeout: Duration::from_secs(30),
        }
    }
}

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn marker_counts(pcap: &Path) -> (usize, usize) {
    // tcpdump -U may leave a partial record at the end of the file mid-read: that parse error
    // means "not yet", the next poll reads the finished record.
    let Ok(bytes) = fs::read(pcap) else {
        return (0, 0);
    };
    let Ok((_, frames)) = pcap::read_pcap_records(&bytes) else {
        return (0, 0);
    };
    let it = || frames.iter().map(|(_, f)| f.as_slice());
    (
        link::count_markers(it(), START_PAYLOAD),
        link::count_markers(it(), END_PAYLOAD),
    )
}

fn sigint(child: &Child) {
    let _ = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Run one capture. Returns the meta document; its `valid` is the verdict. `Err` is a harness
/// failure (tcpdump would not start); an incomplete capture is `Ok` with `valid: false`.
pub fn witness(cfg: &Config, probe: &mut dyn Probe) -> Result<Value, String> {
    let c0 = probe.counters()?;
    let drops0 = probe.interface_drops()?;
    let err_file = fs::File::create(&cfg.err).map_err(|e| format!("{}: {e}", cfg.err.display()))?;
    let child = Command::new(&cfg.argv[0])
        .args(&cfg.argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(err_file))
        .spawn()
        .map_err(|e| format!("{}: {e}", cfg.argv[0]))?;
    let mut tcpdump = Guard(child);
    let started = Instant::now();
    while !fs::read_to_string(&cfg.err)
        .unwrap_or_default()
        .contains("listening on")
    {
        if probe.stop_requested() {
            return Err("interrupted during tcpdump startup".into());
        }
        if let Some(st) = tcpdump.0.try_wait().map_err(|e| e.to_string())? {
            return Err(format!(
                "tcpdump exited at startup ({st}): {}",
                fs::read_to_string(&cfg.err)
                    .unwrap_or_default()
                    .chars()
                    .take(300)
                    .collect::<String>()
            ));
        }
        if started.elapsed() > cfg.start_timeout {
            return Err("tcpdump did not start".into());
        }
        thread::sleep(cfg.poll);
    }
    thread::sleep(cfg.settle);
    let c1 = probe.counters()?;
    fs::write(
        &cfg.ready,
        format!("{}\n", json!({"tcpdump_pid":tcpdump.0.id()})),
    )
    .map_err(|e| e.to_string())?;

    // Readiness: acknowledge the start marker once it is in the pcap, then capture until asked
    // to stop.
    let mut acked = false;
    while !probe.stop_requested() {
        if !acked && marker_counts(&cfg.pcap).0 >= START_MARKERS_REQUIRED {
            fs::write(&cfg.ack, "ack\n").map_err(|e| e.to_string())?;
            acked = true;
        }
        if let Some(st) = tcpdump.0.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("tcpdump exited while capturing ({st})"));
        }
        thread::sleep(cfg.poll);
    }

    // Finalise. The stop request that got us here must not abort the quiescence wait.
    let clock = RealClock::uninterruptible();
    let quiesced = wait_quiet_with(
        || probe.counters(),
        cfg.quiet,
        cfg.quiet_poll,
        cfg.quiet_timeout,
        &clock,
    )?;
    // Counters read BEFORE the end markers: every frame counted up to here precedes the markers
    // in the capture, so once the markers are in the pcap all of them have been written.
    let c2 = probe.counters()?;
    probe.send_end()?;
    let end_started = Instant::now();
    while marker_counts(&cfg.pcap).1 < END_MARKERS_REQUIRED
        && end_started.elapsed() < cfg.end_timeout
    {
        thread::sleep(cfg.poll);
    }
    sigint(&tcpdump.0);
    let stop_started = Instant::now();
    let mut exited = false;
    while stop_started.elapsed() < cfg.stop_timeout {
        if tcpdump.0.try_wait().map_err(|e| e.to_string())?.is_some() {
            exited = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let c3 = probe.counters()?;
    let drops1 = probe.interface_drops()?;
    let stats = parse_tcpdump(&fs::read_to_string(&cfg.err).unwrap_or_default());
    let bytes = fs::read(&cfg.pcap).map_err(|e| format!("{}: {e}", cfg.pcap.display()))?;
    let (frames, pcap_error) = match pcap::read_pcap_records(&bytes) {
        Ok((_, f)) => (f, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    let it = || frames.iter().map(|(_, f)| f.as_slice());
    let facts = Facts {
        start_markers: link::count_markers(it(), START_PAYLOAD),
        end_markers: link::count_markers(it(), END_PAYLOAD),
        quiesced,
        captured: stats["captured"].as_u64(),
        received: stats["received"].as_u64(),
        dropped_kernel: stats["dropped_kernel"].as_u64(),
        dropped_if: stats["dropped_if"].as_u64(),
        interface_drop_delta: drops1.checked_sub(drops0),
        pcap_frames: frames.len() as u64,
        pcap_error,
        tcpdump_exited: exited,
        window_lo: c2.checked_sub(c1),
        window_hi: c3.checked_sub(c0),
    };
    let why = problems(&facts);
    Ok(json!({
        "tcpdump_captured":stats["captured"],
        "received_by_filter":stats["received"],
        "kernel_drops":stats["dropped_kernel"],
        "interface_drops":stats["dropped_if"],
        "interface_drop_delta":facts.interface_drop_delta,
        "pcap_frames":facts.pcap_frames,
        "start_marker_frames":facts.start_markers,
        "end_marker_frames":facts.end_markers,
        "iface_rxtx_delta_lo":facts.window_lo,
        "iface_rxtx_delta_hi":facts.window_hi,
        "quiesced_before_stop":quiesced,
        "tcpdump_argv":cfg.argv,
        "pcap_sha256":crate::windows_suite::hash(&cfg.pcap)?,
        "pcap_size_bytes":bytes.len(),
        "invalid_reasons":why,
        "valid":why.is_empty(),
    }))
}

struct SysProbe {
    iface: String,
    tx: Box<dyn rmasscan_engine::Tx>,
    src: [u8; 6],
    dst: [u8; 6],
}
fn stat(iface: &str, name: &str) -> Result<u64, String> {
    if !link::safe_iface(iface) {
        return Err("invalid interface".into());
    }
    fs::read_to_string(format!("/sys/class/net/{iface}/statistics/{name}"))
        .map_err(|e| format!("{iface} {name}: {e}"))?
        .trim()
        .parse()
        .map_err(|e| format!("{iface} {name}: {e}"))
}
impl Probe for SysProbe {
    fn counters(&mut self) -> Result<u64, String> {
        Ok(stat(&self.iface, "rx_packets")? + stat(&self.iface, "tx_packets")?)
    }
    fn interface_drops(&mut self) -> Result<u64, String> {
        stat(&self.iface, "rx_dropped")
    }
    fn send_end(&mut self) -> Result<(), String> {
        let f = link::marker_frame(self.dst, self.src, END_PAYLOAD);
        for _ in 0..END_MARKERS_REQUIRED {
            link::send_blocking(&mut *self.tx, &f, link::SEND_PATIENCE, &|| false)?;
            thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }
    fn stop_requested(&self) -> bool {
        rmasscan_net::lab_io::stop_requested()
    }
}

fn get<'a>(a: &'a BTreeMap<String, String>, k: &str) -> Result<&'a str, String> {
    a.get(k)
        .map(String::as_str)
        .ok_or_else(|| format!("--{k} required"))
}

/// `capture dump`: run inside the peer namespace. `--ready` appears once tcpdump listens,
/// `--ack` once the scanner-side start marker is in the pcap; SIGTERM/SIGINT finalises.
pub fn run(a: &BTreeMap<String, String>) -> Result<i32, String> {
    let iface = get(a, "iface")?;
    if !link::safe_iface(iface) {
        return Err("invalid interface".into());
    }
    let dst = link::parse_mac(get(a, "end-dst")?)?;
    let cfg = Config::standard(
        iface,
        Path::new(get(a, "pcap")?),
        Path::new(get(a, "ready")?),
        Path::new(get(a, "ack")?),
    );
    rmasscan_net::lab_io::install_signal_handlers().map_err(|e| e.to_string())?;
    // The RX half is dropped at once; only the end markers are sent from here.
    let link::Link { tx, rx } = link::open(iface)?;
    drop(rx);
    let mut probe = SysProbe {
        iface: iface.to_string(),
        tx,
        src: link::iface_mac(iface)?,
        dst,
    };
    let meta = witness(&cfg, &mut probe)?;
    let mut text = serde_json::to_vec_pretty(&meta).map_err(|e| e.to_string())?;
    text.push(b'\n');
    fs::write(get(a, "meta")?, text).map_err(|e| e.to_string())?;
    Ok(0)
}

#[cfg(test)]
#[path = "dump_tests.rs"]
mod tests;
