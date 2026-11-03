//! Fixed installed-issuer child. No interface/path/filter override is accepted.
use super::*;
use crate::{
    pcap::Capture,
    single_target::{
        CaptureCompletion, CaptureFinish, CaptureLease, CaptureStatistics, CaptureWitness, Lease,
        Store,
    },
    unix::Identity,
    work_session::{self, Config},
};
use std::{
    fs::File,
    io::Read,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::FileTypeExt,
    },
    time::Instant,
};
use studio_protocol::single_target::{Context, Permit};

impl Source for Capture {
    fn next(&mut self) -> Result<Option<Packet>> {
        self.read_packet()
    }
    fn statistics(&mut self) -> Result<Statistics> {
        Capture::statistics(self)
    }
}
fn context(config: &Config) -> Result<Context<'_>> {
    Ok(Context {
        now: crate::sealed_fixture::now()?,
        owner_uid: config.uid,
        tooling_sha256: &config.tool_hash,
        helper_sha256: &config.runner_hash,
    })
}
fn filter(permit: &Permit) -> String {
    let mac = permit
        .interface
        .source_mac
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let ip = u32::from(permit.interface.source_ipv4);
    format!(
        "ether host {mac} and ((ip and tcp port 40000) or (arp and (arp[14:4] = {ip} or arp[24:4] = {ip})))"
    )
}
fn route(permit: &Permit, config: &Config, deadline: Instant) -> Result<()> {
    let plan = rmasscan_net::plan_physical(
        &permit.job().network_targets()?,
        rmasscan_net::os_route_table()
            .map_err(super::super::err)?
            .as_ref(),
        rmasscan_net::os_interfaces()
            .map_err(super::super::err)?
            .as_ref(),
        deadline,
        &|| false,
    )
    .map_err(super::super::err)?;
    permit.admit_plan(&plan, &context(config)?)
}
fn control_pipe() -> Result<File> {
    let input = File::from(
        std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map_err(super::super::err)?,
    );
    if !input
        .metadata()
        .map_err(super::super::err)?
        .file_type()
        .is_fifo()
    {
        return Err("Capture requires its host's anonymous control pipe".into());
    }
    // SAFETY: owned valid descriptor; F_GETFL takes no variadic argument and
    // F_SETFL receives its integer flags. Nonblocking reads cannot hold up expiry.
    let flags = unsafe { libc::fcntl(input.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(input.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(input)
}
struct Control<'a> {
    store: &'a Store,
    permit: &'a Permit,
    config: &'a Config,
    host: Identity,
    input: File,
    started: Instant,
    checked: Instant,
    witness: Option<CaptureWitness>,
    lease: Lease,
    capture_lease: Option<CaptureLease>,
}
impl Control<'_> {
    fn check(&mut self) -> Result<()> {
        if self.elapsed() >= Duration::from_secs(CAPTURE_SECONDS) {
            return Err("Capture deadline expired".into());
        }
        if work_session::host_config(self.config.uid)?.as_ref() != Some(self.config)
            || Identity::read(self.host.pid)? != self.host
        {
            return Err("Capture host changed or exited".into());
        }
        let context = context(self.config)?;
        if self.store.load(&context)? != *self.permit {
            return Err("Capture permit changed".into());
        }
        self.lease.check(self.permit, &context)?;
        route(
            self.permit,
            self.config,
            (Instant::now() + Duration::from_secs(2))
                .min(self.started + Duration::from_secs(CAPTURE_SECONDS)),
        )?;
        self.checked = Instant::now();
        Ok(())
    }
}
impl Runtime for Control<'_> {
    fn ready(&mut self) -> Result<()> {
        self.check()?;
        self.witness = Some(
            self.store.publish_capture(
                self.permit,
                &context(self.config)?,
                self.capture_lease
                    .as_ref()
                    .ok_or("Capture kernel lease missing")?,
            )?,
        );
        Ok(())
    }
    fn end(&mut self) -> Result<()> {
        match &self.witness {
            Some(w) => self.store.end_capture(self.permit, w),
            None => Ok(()),
        }
    }
    fn invalidate(&mut self) {
        drop(self.capture_lease.take());
    }
    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
    fn stop(&mut self) -> Result<bool> {
        let mut byte = [0];
        match self.input.read(&mut byte) {
            Ok(1) if byte == *b"S" => return Ok(true),
            Ok(0) => return Err("Capture control lost".into()),
            Ok(_) => return Err("Invalid capture stop command".into()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.to_string()),
        }
        if self.checked.elapsed() >= Duration::from_millis(250) {
            self.check()?;
        }
        Ok(false)
    }
    fn idle(&mut self) {
        std::thread::sleep(Duration::from_millis(5));
    }
}
/// Root-only, exact installed issuer, live matching parent host, trusted permit
/// and observed route are required before libpcap can open. This sends no packets.
pub fn run(uid: u32, generation: &str) -> Result<CaptureCompletion> {
    let started = Instant::now();
    let process = Identity::current()?;
    if process.uid != 0 {
        return Err("Single-target capture requires root".into());
    }
    if uid == 0 || !work_session::valid_hex(generation, 32) || generation.bytes().all(|b| b == b'0')
    {
        return Err("Invalid capture owner or generation".into());
    }
    let config = work_session::host_config(uid)?.ok_or("Capture host absent")?;
    let installed = crate::macos::installed_path(&config.tool_hash)?;
    if process.executable != installed {
        return Err("Capture is not the installed issuer".into());
    }
    crate::trusted::verify(&installed, &config.tool_hash)?;
    let host = Identity::read(config.pid)?;
    // SAFETY: getppid has no pointer arguments and cannot mutate process state.
    if host.uid != 0
        || host.executable != installed
        || unsafe { libc::getppid() } != host.pid as i32
    {
        return Err("Capture parent is not the trusted working host".into());
    }
    let input = control_pipe()?;
    let store = Store::root()?;
    let permit = store.load(&context(&config)?)?;
    if permit.generation != generation {
        return Err("Capture generation differs".into());
    }
    route(&permit, &config, started + Duration::from_secs(3))?;
    let mut output = store.begin_capture(&permit, &context(&config)?)?;
    let capture_lease = store.capture_lease(&permit, &context(&config)?)?;
    let mut source = Capture::open(&permit.interface.name, Some(&filter(&permit)))?;
    let mut runtime = Control {
        store: &store,
        permit: &permit,
        config: &config,
        host,
        input,
        started,
        checked: started,
        witness: None,
        lease: Lease::default(),
        capture_lease: Some(capture_lease),
    };
    let mut result = record(&mut source, &mut output, &mut runtime);
    if let Err(e) = output.sync_all() {
        result.fail(e.to_string());
    }
    drop(source);
    drop(output);
    let witness = runtime.witness.as_ref().ok_or_else(|| {
        result
            .error
            .clone()
            .unwrap_or("Capture never became ready".into())
    })?;
    let data = CaptureFinish {
        elapsed_millis: started
            .elapsed()
            .as_millis()
            .try_into()
            .map_err(super::super::err)?,
        recorded: result.recorded,
        statistics: result.stats.map(|s| CaptureStatistics {
            received: s.received,
            dropped: s.dropped,
            interface_dropped: s.interface_dropped,
        }),
        error: result.error.map(|mut e| {
            e.truncate(e.floor_char_boundary(1024));
            e
        }),
    };
    store.finish_capture(&permit, witness, &data)
}
#[cfg(test)]
mod tests {
    #[test]
    fn system_bpf_captures_only_own_scanner_tcp_and_own_arp_without_device_access() {
        let permit = studio_protocol::single_target::Permit {
            version: 1,
            generation: "1".repeat(32),
            owner_uid: 501,
            created: 1000,
            expires: 1300,
            tooling_sha256: "a".repeat(64),
            helper_sha256: "b".repeat(64),
            target: "45.33.32.156".parse().unwrap(),
            ports: vec![80],
            seed: 42,
            interface: studio_protocol::single_target::InterfaceBinding {
                name: "en0".into(),
                index: 5,
                source_ipv4: "10.0.0.2".parse().unwrap(),
                source_mac: [2, 1, 2, 3, 4, 5],
                next_hop: "10.0.0.1".parse().unwrap(),
            },
        };
        let own = permit.interface.source_mac;
        let mut syn = vec![0; 60];
        syn[..6].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
        syn[6..12].copy_from_slice(&own);
        syn[12..14].copy_from_slice(&[8, 0]);
        syn[14] = 0x45;
        syn[23] = 6;
        syn[34..36].copy_from_slice(&40000u16.to_be_bytes());
        syn[36..38].copy_from_slice(&80u16.to_be_bytes());
        let mut reply = syn.clone();
        reply[..6].copy_from_slice(&own);
        reply[6..12].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
        reply[34..36].copy_from_slice(&80u16.to_be_bytes());
        reply[36..38].copy_from_slice(&40000u16.to_be_bytes());
        let mut foreign = syn.clone();
        foreign[6..12].copy_from_slice(&[2, 3, 3, 3, 3, 3]);
        let mut other_port = syn.clone();
        other_port[34..36].copy_from_slice(&40001u16.to_be_bytes());
        let mut arp = vec![0; 60];
        arp[..6].fill(255);
        arp[6..12].copy_from_slice(&own);
        arp[12..14].copy_from_slice(&[8, 6]);
        arp[28..32].copy_from_slice(&[10, 0, 0, 2]);
        arp[38..42].copy_from_slice(&[10, 0, 0, 1]);
        let mut arp_reply = arp.clone();
        arp_reply[..6].copy_from_slice(&own);
        arp_reply[6..12].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
        arp_reply[28..32].copy_from_slice(&[10, 0, 0, 1]);
        arp_reply[38..42].copy_from_slice(&[10, 0, 0, 2]);
        let mut foreign_arp = arp.clone();
        foreign_arp[6..12].fill(3);
        let actual = crate::pcap::filter_matches(
            &super::filter(&permit),
            &[syn, reply, foreign, other_port, arp, arp_reply, foreign_arp],
        )
        .unwrap();
        assert_eq!(actual, vec![true, true, false, false, true, true, false]);
    }
    #[test]
    fn ordinary_user_cannot_start_capture_or_create_root_records() {
        if crate::unix::Identity::current().unwrap().uid != 0 {
            assert!(
                super::run(501, &"1".repeat(32))
                    .unwrap_err()
                    .contains("requires root")
            );
        }
    }
}
