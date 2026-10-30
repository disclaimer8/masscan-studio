//! Root-only capture worker, controlled solely through its inherited stdin pipe.
use super::{
    capture::{self, Packet, Runtime, Source, Stats},
    native,
    topology::{PEER, SCANNER},
};
use std::{
    fs::File,
    io::Write,
    os::{
        fd::AsFd,
        unix::fs::{FileTypeExt, MetadataExt},
    },
    sync::mpsc,
    time::{Duration, Instant},
};
use studio_platform::{pcap::Capture, sealed_fixture, trusted};

impl Source for Capture {
    fn next(&mut self) -> Result<Option<Packet>, String> {
        self.read_packet().map(|p| {
            p.map(|p| Packet {
                seconds: p.seconds,
                micros: p.micros,
                original_len: p.original_len,
                bytes: p.bytes,
            })
        })
    }
    fn stats(&mut self) -> Result<Stats, String> {
        self.statistics().map(|s| Stats {
            received: s.received,
            dropped: s.dropped,
            interface_dropped: s.interface_dropped,
        })
    }
}
struct Control {
    started: Instant,
    receiver: mpsc::Receiver<Result<(), String>>,
    interface: String,
}
impl Runtime for Control {
    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
    fn stop(&mut self) -> Result<bool, String> {
        match self.receiver.try_recv() {
            Ok(result) => result.map(|()| true),
            Err(mpsc::TryRecvError::Empty) => Ok(false),
            Err(mpsc::TryRecvError::Disconnected) => Err("capture control worker lost".into()),
        }
    }
    fn idle(&mut self) {
        std::thread::sleep(Duration::from_millis(10));
    }
    fn ready(&mut self) -> Result<(), String> {
        let mut err = std::io::stderr().lock();
        writeln!(
            err,
            "capture ready: {}, system {}; nonblocking Ethernet",
            self.interface,
            Capture::version()
        )
        .map_err(|e| e.to_string())?;
        err.flush().map_err(|e| e.to_string())
    }
}
pub fn run(role: &str, interface: &str) -> Result<(), String> {
    if native::command(&["/usr/bin/id", "-u"])?.trim() != "0" {
        return Err("capture requires root supervisor".into());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let state = sealed_fixture::load(deadline, &|| false)?;
    studio_protocol::sealed_fixture::validate_state(&state, sealed_fixture::now()?)?;
    let exe = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    trusted::verify(&exe, &state.tooling_sha256)?;
    native::supervision_check(&state, true)?;
    let filter = match role {
        "peer" if interface == PEER => None,
        "uplink" if ![SCANNER, PEER].contains(&interface) => {
            let route = native::command(&["/sbin/route", "-n", "get", "default"])?;
            let names = route
                .lines()
                .filter_map(|l| l.trim().strip_prefix("interface:").map(str::trim))
                .collect::<Vec<_>>();
            if names != [interface] {
                return Err("capture uplink differs from current default route".into());
            }
            Some(capture::UPLINK_FILTER)
        }
        _ => return Err("capture role/interface refused".into()),
    };
    // The supervisor supplies owned anonymous control pipe and freshly created
    // root0600 regular output. No path from driver files is opened by this worker.
    let input = File::from(
        std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|e| e.to_string())?,
    );
    if !input
        .metadata()
        .map_err(|e| e.to_string())?
        .file_type()
        .is_fifo()
    {
        return Err("capture control must be a pipe".into());
    }
    let mut output = File::from(
        std::io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|e| e.to_string())?,
    );
    let md = output.metadata().map_err(|e| e.to_string())?;
    if !md.is_file() || md.uid() != 0 || md.mode() & 0o077 != 0 || md.nlink() != 1 || md.len() != 0
    {
        return Err("capture output must be a new private root-owned regular file".into());
    }
    let mut source = Capture::open(interface, filter)?;
    native::supervision_check(&state, true)?;
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let _ = sender.send(capture::read_stop(input));
    });
    let mut runtime = Control {
        started: Instant::now(),
        receiver,
        interface: interface.into(),
    };
    let count = capture::record(&mut source, &mut output, &mut runtime)?;
    reader.join().map_err(|_| "capture control worker panic")?;
    let stats = source.stats()?;
    capture::validate_stats(count, stats)?;
    output.sync_all().map_err(|e| e.to_string())?;
    drop(source);
    eprintln!(
        "{count} packets captured\n{} packets received by filter\n{} packets dropped by kernel\n{} packets dropped by interface",
        stats.received, stats.dropped, stats.interface_dropped
    );
    Ok(())
}
