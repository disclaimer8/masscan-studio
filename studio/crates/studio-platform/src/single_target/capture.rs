//! A one-use capture witness belongs to a live root process, never the GUI.
use super::*;
use crate::unix::Identity;
pub const CAPTURE_SECONDS: u64 = 40;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureStatistics {
    pub received: u32,
    pub dropped: u32,
    pub interface_dropped: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureFinish {
    pub elapsed_millis: u64,
    pub recorded: u64,
    pub statistics: Option<CaptureStatistics>,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline: Option<CaptureTimeline>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureTimeline {
    pub opened: studio_protocol::acceptance::Stamp,
    pub ready: studio_protocol::acceptance::Stamp,
    pub stopped: studio_protocol::acceptance::Stamp,
    pub closed: studio_protocol::acceptance::Stamp,
    pub samples: Vec<studio_protocol::acceptance::Stamp>,
}
impl CaptureTimeline {
    pub(super) fn sampled(
        opened: studio_protocol::acceptance::Stamp,
        ready: studio_protocol::acceptance::Stamp,
        stopped: studio_protocol::acceptance::Stamp,
        closed: studio_protocol::acceptance::Stamp,
        samples: Vec<studio_protocol::acceptance::Stamp>,
    ) -> Result<Self> {
        if !(2..=1000).contains(&samples.len())
            || samples.first() != Some(&opened)
            || samples.last() != Some(&closed)
        {
            return Err("Missing original capture samples".into());
        }
        // Validate every 50ms observation before retaining a 500ms series.
        // A discarded sample can never hide a clock discontinuity.
        studio_protocol::acceptance::clocks(&samples)?;
        let mut retained: Vec<_> = samples.iter().step_by(10).cloned().collect();
        if retained.last() != Some(&closed) {
            retained.push(closed.clone());
        }
        let timeline = Self {
            opened,
            ready,
            stopped,
            closed,
            samples: retained,
        };
        timeline.validate()?;
        Ok(timeline)
    }
    pub fn validate(&self) -> Result<()> {
        use studio_protocol::acceptance::clocks;
        clocks(&[
            self.opened.clone(),
            self.ready.clone(),
            self.stopped.clone(),
            self.closed.clone(),
        ])?;
        clocks(&self.samples)?;
        if !(2..=128).contains(&self.samples.len())
            || self.samples.first() != Some(&self.opened)
            || self.samples.last() != Some(&self.closed)
            || self
                .samples
                .windows(2)
                .any(|p| p[1].mono_ns - p[0].mono_ns > 1_000_000_000)
            || self.closed.mono_ns >= CAPTURE_SECONDS * 1_000_000_000
        {
            return Err("Capture clock coverage is incomplete or expired".into());
        }
        Ok(())
    }
}
impl CaptureFinish {
    fn validate(&self, witness: &CaptureWitness, finished: u64) -> Result<()> {
        if let Some(timeline) = &self.timeline {
            timeline.validate()?;
            let ready = witness
                .created
                .checked_mul(1_000_000_000)
                .ok_or("Capture clock overflow")?;
            let end = finished
                .checked_add(1)
                .and_then(|s| s.checked_mul(1_000_000_000))
                .ok_or("Capture clock overflow")?;
            if timeline.ready.wall_ns < ready
                || timeline.closed.wall_ns >= end
                || timeline.closed.mono_ns / 1_000_000 > self.elapsed_millis
            {
                return Err("Capture clock differs from completion record".into());
            }
        }
        if self.recorded > 1024
            || self
                .error
                .as_ref()
                .is_some_and(|e| e.is_empty() || e.len() > 1024)
        {
            return Err("Invalid capture completion bounds".into());
        }
        if self.error.is_none() {
            let stats = self
                .statistics
                .as_ref()
                .ok_or("Capture statistics missing")?;
            if stats.dropped != 0
                || stats.interface_dropped != 0
                || u64::from(stats.received) < self.recorded
                || self.elapsed_millis >= CAPTURE_SECONDS * 1000
                || finished < witness.created
                || !witness
                    .created
                    .checked_add(CAPTURE_SECONDS)
                    .is_some_and(|end| finished < end)
            {
                return Err("Capture loss, count or lifetime cannot be successful".into());
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureCompletion {
    pub witness: CaptureWitness,
    pub finished: u64,
    pub measurements: CaptureFinish,
    pub pcap_bytes: u64,
    pub pcap_sha256: String,
}
pub struct CaptureEvidence {
    pub permit: Permit,
    pub completion: CaptureCompletion,
    pub pcap: Vec<u8>,
}
impl CaptureCompletion {
    /// Pure exported-content consistency check, never proof of root provenance or
    /// a live capture. Issued permits use the canonical serde encoding below.
    pub fn validate_export(&self, permit: &Permit, pcap: &[u8]) -> Result<()> {
        self.witness.validate(
            permit,
            &digest(&serde_json::to_vec(permit).map_err(err)?),
            &Context {
                now: self.witness.created,
                owner_uid: permit.owner_uid,
                tooling_sha256: &permit.tooling_sha256,
                helper_sha256: &permit.helper_sha256,
            },
            &self.witness.process,
        )?;
        self.measurements.validate(&self.witness, self.finished)?;
        if pcap.len() > super::recording::MAX_BYTES
            || self.pcap_bytes != pcap.len() as u64
            || self.pcap_sha256 != digest(pcap)
        {
            return Err("Exported capture size or hash differs".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureWitness {
    pub generation: String,
    pub nonce: String,
    pub permit_sha256: String,
    pub created: u64,
    pub process: Identity,
    pub lease_file: [u64; 2],
}
/// Sole descriptor for a process-owned kernel lock. Never reopen this file in the
/// publisher: POSIX closing *any* descriptor for that inode releases its locks.
pub struct CaptureLease {
    file: File,
    generation: String,
    pid: u32,
}
pub const CAPTURE_HEADER: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0,
];
/// Pins one trusted witness and bounds it by monotonic time, even if a capture
/// process stays alive after its recording worker stalls. Call only after live_capture.
#[derive(Default)]
pub struct CapturePin {
    value: Option<CaptureWitness>,
    deadline: Option<Instant>,
    last_wall: Option<u64>,
    rejected: bool,
}
impl CapturePin {
    pub fn pinned(&self) -> Result<(&CaptureWitness, Instant)> {
        if self.rejected {
            return Err("Capture pin invalidated".into());
        }
        Ok((
            self.value.as_ref().ok_or("Capture not pinned")?,
            self.deadline.ok_or("Capture deadline missing")?,
        ))
    }
    pub fn check(&mut self, witness: &CaptureWitness, now_wall: u64) -> Result<()> {
        self.check_at(witness, now_wall, Instant::now())
    }
    fn check_at(&mut self, witness: &CaptureWitness, now_wall: u64, now: Instant) -> Result<()> {
        let result = (|| {
            if self.rejected
                || self.value.as_ref().is_some_and(|old| old != witness)
                || self.last_wall.is_some_and(|old| now_wall < old)
                || now_wall < witness.created
            {
                return Err(
                    "Capture session replaced, invalidated or clock moved backwards".into(),
                );
            }
            let end = witness
                .created
                .checked_add(CAPTURE_SECONDS)
                .ok_or("Invalid capture expiry")?;
            if now_wall >= end {
                return Err("Capture readiness expired".into());
            }
            if self.deadline.is_none() {
                self.deadline = Some(
                    now.checked_add(Duration::from_secs(end - now_wall))
                        .ok_or("Invalid monotonic capture expiry")?,
                );
                self.value = Some(witness.clone());
            }
            if now >= self.deadline.ok_or("Missing capture deadline")? {
                return Err("Monotonic capture lifetime expired".into());
            }
            self.last_wall = Some(now_wall);
            Ok(())
        })();
        if result.is_err() {
            self.invalidate();
        }
        result
    }
    pub fn invalidate(&mut self) {
        self.rejected = true;
    }
}
impl CaptureWitness {
    fn validate(
        &self,
        permit: &Permit,
        hash: &str,
        context: &Context<'_>,
        live: &Identity,
    ) -> Result<()> {
        permit.validate(context)?;
        if self.generation != permit.generation
            || self.permit_sha256 != hash
            || !crate::work_session::valid_hex(&self.nonce, 32)
            || self.nonce.bytes().all(|b| b == b'0')
            || self.created < permit.created
            || self.created > context.now
            || !self
                .created
                .checked_add(CAPTURE_SECONDS)
                .is_some_and(|end| context.now < end)
            || self.process.uid != 0
            || self.process.pid == 0
            || self.process.pid > i32::MAX as u32
            || self.process.birth == [0, 0]
            || self.lease_file == [0, 0]
            || &self.process != live
            || self.process.executable != crate::macos::installed_path(context.tooling_sha256)?
        {
            return Err("Capture witness identity, permit or lifetime differs".into());
        }
        Ok(())
    }
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
impl Store {
    /// Read only completed fixed-name evidence belonging to the authenticated UID.
    /// A revoked/expired permit may be exported; this never grants execution.
    pub fn capture_evidence(&self, uid: u32, generation: &str) -> Result<CaptureEvidence> {
        let deadline = budget();
        let _lock = self.lock(deadline)?;
        let bytes = self.read(&self.marker("capture-permit", generation)?, deadline)?;
        let permit: Permit = serde_json::from_slice(&bytes).map_err(err)?;
        if uid == 0 || permit.owner_uid != uid || permit.generation != generation {
            return Err("Capture evidence owner or generation differs".into());
        }
        let completion: CaptureCompletion = serde_json::from_slice(
            &self.read(&self.marker("capture-result", generation)?, deadline)?,
        )
        .map_err(err)?;
        let w = &completion.witness;
        w.validate(
            &permit,
            &digest(&bytes),
            &Context {
                now: w.created,
                owner_uid: uid,
                tooling_sha256: &permit.tooling_sha256,
                helper_sha256: &permit.helper_sha256,
            },
            &w.process,
        )?;
        completion.measurements.validate(w, completion.finished)?;
        for prefix in ["capture-ready", "capture-ended"] {
            let stored: CaptureWitness =
                serde_json::from_slice(&self.read(&self.marker(prefix, generation)?, deadline)?)
                    .map_err(err)?;
            if &stored != w {
                return Err("Capture evidence witness differs".into());
            }
        }
        let pcap = self.read_limit(
            &self.capture_path(generation)?,
            deadline,
            super::recording::MAX_BYTES as u64,
        )?;
        if completion.pcap_bytes != pcap.len() as u64 || completion.pcap_sha256 != digest(&pcap) {
            return Err("Capture evidence bytes or hash differ".into());
        }
        Ok(CaptureEvidence {
            permit,
            completion,
            pcap,
        })
    }
    pub fn capture_lease(&self, permit: &Permit, context: &Context<'_>) -> Result<CaptureLease> {
        let deadline = budget();
        let _lock = self.lock(deadline)?;
        let bytes = self.capture_permit(permit, context, deadline)?;
        if self.read(
            &self.marker("capture-permit", &permit.generation)?,
            deadline,
        )? != bytes
        {
            return Err("Capture lease snapshot differs".into());
        }
        for prefix in ["claim", "capture-ready", "capture-ended"] {
            absent(&self.marker(prefix, &permit.generation)?)?;
        }
        let path = self.marker("capture-live", &permit.generation)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(err)?;
        metadata(&file.metadata().map_err(err)?, self.owner, false)?;
        trusted(&path, self.owner, false, deadline)?;
        same_file(
            &file.metadata().map_err(err)?,
            &fs::symlink_metadata(&path).map_err(err)?,
        )?;
        super::capture_lock::acquire(&file)?;
        file.sync_all().map_err(err)?;
        self.sync()?;
        Ok(CaptureLease {
            file,
            generation: permit.generation.clone(),
            pid: std::process::id(),
        })
    }
    fn live_lease(&self, witness: &CaptureWitness, deadline: Instant) -> Result<()> {
        if witness.process.pid == std::process::id() {
            return Err("Capture publisher cannot reopen its POSIX lease file".into());
        }
        let path = self.marker("capture-live", &witness.generation)?;
        trusted(&path, self.owner, false, deadline)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(err)?;
        let fd = file.metadata().map_err(err)?;
        metadata(&fd, self.owner, false)?;
        same_file(&fd, &fs::symlink_metadata(&path).map_err(err)?)?;
        if fd.len() != 0
            || [fd.dev(), fd.ino()] != witness.lease_file
            || super::capture_lock::owner(&file)? != Some(witness.process.pid)
        {
            return Err("Capture kernel lease released or owner changed".into());
        }
        Ok(())
    }
    /// Persist final measurements only after readiness has ended, from the same
    /// root process incarnation. The actual fixed-name PCAP is bounded and hashed;
    /// no caller-supplied output path or digest is accepted. Failures stay evidence.
    pub fn finish_capture(
        &self,
        permit: &Permit,
        witness: &CaptureWitness,
        data: &CaptureFinish,
    ) -> Result<CaptureCompletion> {
        let process = Identity::current()?;
        crate::trusted::verify(&process.executable, &permit.tooling_sha256)?;
        self.finish_owned(
            permit,
            witness,
            data,
            crate::sealed_fixture::now()?,
            &process,
        )
    }
    fn finish_owned(
        &self,
        permit: &Permit,
        witness: &CaptureWitness,
        data: &CaptureFinish,
        finished: u64,
        process: &Identity,
    ) -> Result<CaptureCompletion> {
        data.validate(witness, finished)?;
        let deadline = budget();
        let _lock = self.lock(deadline)?;
        let bytes = self.read(
            &self.marker("capture-permit", &permit.generation)?,
            deadline,
        )?;
        let snapshot: Permit = serde_json::from_slice(&bytes).map_err(err)?;
        if &snapshot != permit {
            return Err("Capture completion permit differs".into());
        }
        witness.validate(
            permit,
            &digest(&bytes),
            &Context {
                now: witness.created,
                owner_uid: permit.owner_uid,
                tooling_sha256: &permit.tooling_sha256,
                helper_sha256: &permit.helper_sha256,
            },
            process,
        )?;
        for prefix in ["capture-ready", "capture-ended"] {
            let stored: CaptureWitness = serde_json::from_slice(
                &self.read(&self.marker(prefix, &permit.generation)?, deadline)?,
            )
            .map_err(err)?;
            if &stored != witness {
                return Err("Capture completion witness differs".into());
            }
        }
        let pcap = self.read_limit(
            &self.capture_path(&permit.generation)?,
            deadline,
            super::recording::MAX_BYTES as u64,
        )?;
        if data.error.is_none() {
            if !pcap.starts_with(&CAPTURE_HEADER) {
                return Err("Capture completion header differs".into());
            }
            let mut remaining = &pcap[24..];
            let mut count = 0;
            while !remaining.is_empty() {
                if remaining.len() < 16 {
                    return Err("Partial capture record".into());
                }
                let n = u32::from_le_bytes(remaining[8..12].try_into().map_err(err)?) as usize;
                if !(14..=131072).contains(&n)
                    || remaining[8..12] != remaining[12..16]
                    || remaining.len() < 16 + n
                {
                    return Err("Invalid capture record length".into());
                }
                remaining = &remaining[16 + n..];
                count += 1;
            }
            if count != data.recorded {
                return Err("Capture completion count differs".into());
            }
        }
        let result = CaptureCompletion {
            witness: witness.clone(),
            finished,
            measurements: data.clone(),
            pcap_bytes: pcap.len() as u64,
            pcap_sha256: digest(&pcap),
        };
        self.create(
            &self.marker("capture-result", &permit.generation)?,
            &serde_json::to_vec(&result).map_err(err)?,
            deadline,
        )?;
        Ok(result)
    }
    fn capture_path(&self, generation: &str) -> Result<PathBuf> {
        Ok(self.marker("capture", generation)?.with_extension("pcap"))
    }
    fn capture_permit(
        &self,
        permit: &Permit,
        context: &Context<'_>,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        let (actual, bytes) = self.load_locked(context, deadline)?;
        if &actual != permit {
            return Err("Capture permit changed".into());
        }
        Ok(bytes)
    }
    /// Create private evidence exactly once, before opening a read-only capture.
    /// This does not publish readiness and cannot authorize a scanner.
    pub fn begin_capture(&self, permit: &Permit, context: &Context<'_>) -> Result<File> {
        let deadline = budget();
        let _lock = self.lock(deadline)?;
        let bytes = self.capture_permit(permit, context, deadline)?;
        for prefix in ["claim", "capture-ready", "capture-ended"] {
            absent(&self.marker(prefix, &permit.generation)?)?;
        }
        self.create(
            &self.marker("capture-permit", &permit.generation)?,
            &bytes,
            deadline,
        )?;
        let path = self.capture_path(&permit.generation)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(err)?;
        metadata(&file.metadata().map_err(err)?, self.owner, false)?;
        trusted(&path, self.owner, false, deadline)?;
        file.sync_all().map_err(err)?;
        self.sync()?;
        Ok(file)
    }
    /// Only the exact installed issuer executable running as root may publish.
    /// The caller must already own a successfully opened libpcap handle and keep
    /// it alive until end_capture; this API alone is not a capture implementation.
    pub fn publish_capture(
        &self,
        permit: &Permit,
        context: &Context<'_>,
        lease: &CaptureLease,
    ) -> Result<CaptureWitness> {
        let process = Identity::current()?;
        if process.uid != 0 {
            return Err("Only the root capture process can publish readiness".into());
        }
        permit.validate(context)?;
        if process.executable != crate::macos::installed_path(context.tooling_sha256)? {
            return Err("Capture is not the installed issuer executable".into());
        }
        crate::trusted::verify(&process.executable, context.tooling_sha256)?;
        let deadline = budget();
        let _lock = self.lock(deadline)?;
        let lease_md = lease.file.metadata().map_err(err)?;
        let lease_path = self.marker("capture-live", &permit.generation)?;
        trusted(&lease_path, self.owner, false, deadline)?;
        metadata(&lease_md, self.owner, false)?;
        same_file(&lease_md, &fs::symlink_metadata(&lease_path).map_err(err)?)?;
        if lease.generation != permit.generation || lease.pid != process.pid || lease_md.len() != 0
        {
            return Err("Capture lease does not belong to this publisher".into());
        }
        let bytes = self.capture_permit(permit, context, deadline)?;
        for prefix in ["claim", "capture-ended"] {
            absent(&self.marker(prefix, &permit.generation)?)?;
        }
        if self.read(
            &self.marker("capture-permit", &permit.generation)?,
            deadline,
        )? != bytes
        {
            return Err("Capture snapshot differs from active permit".into());
        }
        let path = self.capture_path(&permit.generation)?;
        trusted(&path, self.owner, false, deadline)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(err)?;
        let before = file.metadata().map_err(err)?;
        metadata(&before, self.owner, false)?;
        let mut header = [0; 24];
        file.read_exact(&mut header).map_err(err)?;
        let after = fs::symlink_metadata(&path).map_err(err)?;
        metadata(&after, self.owner, false)?;
        same_file(&before, &after)?;
        if before.len() != 24 || after.len() != 24 || header != CAPTURE_HEADER {
            return Err("Capture header is not freshly persisted".into());
        }
        // Order the header on disk before publishing the durable ready record.
        file.sync_all().map_err(err)?;
        let witness = CaptureWitness {
            generation: permit.generation.clone(),
            nonce: studio_protocol::id_text(studio_protocol::new_id()?),
            permit_sha256: digest(&bytes),
            created: context.now,
            process,
            lease_file: [lease_md.dev(), lease_md.ino()],
        };
        witness.validate(permit, &digest(&bytes), context, &witness.process)?;
        self.create(
            &self.marker("capture-ready", &permit.generation)?,
            &serde_json::to_vec(&witness).map_err(err)?,
            deadline,
        )?;
        Ok(witness)
    }
    /// Readiness is bounded, tied to a process incarnation, and fails after end.
    /// The permit-aware environment must pin this value and invalidate its lease
    /// on every error. No execution path is connected to this API yet.
    pub fn live_capture(&self, permit: &Permit, context: &Context<'_>) -> Result<CaptureWitness> {
        let deadline = budget();
        let _lock = self.lock(deadline)?;
        let bytes = self.capture_permit(permit, context, deadline)?;
        absent(&self.marker("capture-ended", &permit.generation)?)?;
        let witness: CaptureWitness = serde_json::from_slice(
            &self.read(&self.marker("capture-ready", &permit.generation)?, deadline)?,
        )
        .map_err(err)?;
        let live = Identity::read(witness.process.pid)?;
        witness.validate(permit, &digest(&bytes), context, &live)?;
        crate::trusted::verify(&live.executable, context.tooling_sha256)?;
        self.live_lease(&witness, deadline)?;
        crate::sealed_fixture::check(deadline, &|| false)?;
        Ok(witness)
    }
    /// Invalidate readiness before closing capture/draining evidence. Cleanup may
    /// run after expiry; its structural context never admits scanner execution.
    pub fn end_capture(&self, permit: &Permit, witness: &CaptureWitness) -> Result<()> {
        let process = Identity::current()?;
        if process.uid != 0 {
            return Err("Capture cleanup requires its root process".into());
        }
        let deadline = budget();
        let _lock = self.lock(deadline)?;
        let bytes = self.read(
            &self.marker("capture-permit", &permit.generation)?,
            deadline,
        )?;
        let snapshot: Permit = serde_json::from_slice(&bytes).map_err(err)?;
        if &snapshot != permit {
            return Err("Capture cleanup permit differs".into());
        }
        let stored: CaptureWitness = serde_json::from_slice(
            &self.read(&self.marker("capture-ready", &permit.generation)?, deadline)?,
        )
        .map_err(err)?;
        if &stored != witness {
            return Err("Capture cleanup witness differs".into());
        }
        witness.validate(
            permit,
            &digest(&bytes),
            &Context {
                now: witness.created,
                owner_uid: permit.owner_uid,
                tooling_sha256: &permit.tooling_sha256,
                helper_sha256: &permit.helper_sha256,
            },
            &process,
        )?;
        self.create(
            &self.marker("capture-ended", &permit.generation)?,
            &serde_json::to_vec(witness).map_err(err)?,
            deadline,
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn permit() -> Permit {
        Permit {
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
        }
    }
    fn context(p: &Permit, now: u64) -> Context<'_> {
        Context {
            now,
            owner_uid: p.owner_uid,
            tooling_sha256: &p.tooling_sha256,
            helper_sha256: &p.helper_sha256,
        }
    }
    #[test]
    fn compact_clock_evidence_checks_even_the_discarded_samples() {
        use studio_protocol::acceptance::Stamp;
        let samples: Vec<_> = (0..=780)
            .map(|index| Stamp {
                wall_ns: 1_000_000_000_000 + index * 50_000_000,
                mono_ns: index * 50_000_000,
                uncertainty_ns: 0,
            })
            .collect();
        let build = |samples: Vec<Stamp>| {
            CaptureTimeline::sampled(
                samples[0].clone(),
                samples[1].clone(),
                samples[779].clone(),
                samples[780].clone(),
                samples,
            )
        };
        let timeline = build(samples.clone()).unwrap();
        assert_eq!(timeline.samples.len(), 79);
        assert!(serde_json::to_vec(&timeline).unwrap().len() < 14000);
        let mut bad = samples.clone();
        bad[3].wall_ns += 10_000_000;
        assert!(build(bad).is_err());
        let mut sparse = timeline.clone();
        sparse.samples.drain(1..5);
        assert!(sparse.validate().is_err());
        let mut late = timeline;
        late.closed.mono_ns = CAPTURE_SECONDS * 1_000_000_000;
        assert!(late.validate().is_err());
    }
    #[test]
    fn child_observes_store_kernel_lease() {
        let Some(path) = std::env::var_os("STUDIO_CAPTURE_STORE_TEST_DIR") else {
            return;
        };
        let store = Store::at(path.into(), Identity::current().unwrap().uid).unwrap();
        let w: CaptureWitness =
            serde_json::from_str(&std::env::var("STUDIO_CAPTURE_STORE_TEST_WITNESS").unwrap())
                .unwrap();
        let expected = std::env::var("STUDIO_CAPTURE_STORE_TEST_EXPECT").unwrap() == "true";
        assert_eq!(store.live_lease(&w, budget()).is_ok(), expected);
    }
    #[test]
    fn store_refuses_released_lease_even_while_publisher_lives_without_ended_marker() {
        let path = std::env::temp_dir().join(format!(
            "studio-capture-live-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let path = fs::canonicalize(path).unwrap();
        let store = Store::at(path.clone(), Identity::current().unwrap().uid).unwrap();
        let p = permit();
        let c = context(&p, 1001);
        store.prepare(&p, &c).unwrap();
        let _output = store.begin_capture(&p, &c).unwrap();
        let lease = store.capture_lease(&p, &c).unwrap();
        let mut w = witness(&p);
        w.process = Identity::current().unwrap();
        let md = lease.file.metadata().unwrap();
        w.lease_file = [md.dev(), md.ino()];
        // A mistaken same-process query must refuse before opening/closing a
        // second descriptor, which would otherwise drop the process's lock.
        assert!(
            store
                .live_lease(&w, budget())
                .unwrap_err()
                .contains("cannot reopen")
        );
        let check = |w: &CaptureWitness, expected: bool| {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "single_target::capture::tests::child_observes_store_kernel_lease",
                    "--nocapture",
                ])
                .env("STUDIO_CAPTURE_STORE_TEST_DIR", &path)
                .env(
                    "STUDIO_CAPTURE_STORE_TEST_WITNESS",
                    serde_json::to_string(w).unwrap(),
                )
                .env("STUDIO_CAPTURE_STORE_TEST_EXPECT", expected.to_string())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        };
        check(&w, true);
        let mut wrong = w.clone();
        wrong.lease_file[1] += 1;
        check(&wrong, false);
        let mut wrong = w.clone();
        wrong.process.pid += 1;
        check(&wrong, false);
        drop(lease);
        check(&w, false);
        assert!(
            !store
                .marker("capture-ended", &p.generation)
                .unwrap()
                .exists()
        );
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn completed_evidence_requires_ended_owner_and_is_private_immutable_and_hashed() {
        let path = std::env::temp_dir().join(format!(
            "studio-capture-finish-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let path = fs::canonicalize(path).unwrap();
        let store = Store::at(path.clone(), Identity::current().unwrap().uid).unwrap();
        let p = permit();
        let c = context(&p, 1001);
        store.prepare(&p, &c).unwrap();
        let mut file = store.begin_capture(&p, &c).unwrap();
        file.write_all(&CAPTURE_HEADER).unwrap();
        file.sync_all().unwrap();
        let mut w = witness(&p);
        w.permit_sha256 = digest(&serde_json::to_vec(&p).unwrap());
        let data = CaptureFinish {
            timeline: None,
            elapsed_millis: 1000,
            recorded: 0,
            statistics: Some(CaptureStatistics {
                received: 0,
                dropped: 0,
                interface_dropped: 0,
            }),
            error: None,
        };
        assert!(store.finish_owned(&p, &w, &data, 1002, &w.process).is_err());
        for prefix in ["capture-ready", "capture-ended"] {
            store
                .create(
                    &store.marker(prefix, &p.generation).unwrap(),
                    &serde_json::to_vec(&w).unwrap(),
                    budget(),
                )
                .unwrap();
        }
        let mut wrong = w.process.clone();
        wrong.birth[0] += 1;
        assert!(store.finish_owned(&p, &w, &data, 1002, &wrong).is_err());
        let result = store.finish_owned(&p, &w, &data, 1002, &w.process).unwrap();
        assert_eq!(result.pcap_bytes, 24);
        assert_eq!(result.pcap_sha256, digest(&CAPTURE_HEADER));
        assert!(store.finish_owned(&p, &w, &data, 1002, &w.process).is_err());
        let output = store.marker("capture-result", &p.generation).unwrap();
        assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o600);
        let saved: CaptureCompletion = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(saved, result);
        let evidence = store.capture_evidence(p.owner_uid, &p.generation).unwrap();
        assert_eq!(evidence.pcap, CAPTURE_HEADER);
        assert_eq!(evidence.completion, result);
        result.validate_export(&p, &evidence.pcap).unwrap();
        let mut invalid = result.clone();
        invalid.witness.permit_sha256 = "0".repeat(64);
        assert!(invalid.validate_export(&p, &evidence.pcap).is_err());
        assert!(
            store
                .capture_evidence(p.owner_uid + 1, &p.generation)
                .is_err()
        );
        fs::write(store.capture_path(&p.generation).unwrap(), b"changed").unwrap();
        assert!(store.capture_evidence(p.owner_uid, &p.generation).is_err());
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn completion_cannot_label_loss_missing_stats_or_expired_recording_as_success() {
        let p = permit();
        let w = witness(&p);
        let good = CaptureFinish {
            timeline: None,
            elapsed_millis: 1000,
            recorded: 1,
            statistics: Some(CaptureStatistics {
                received: 1,
                dropped: 0,
                interface_dropped: 0,
            }),
            error: None,
        };
        good.validate(&w, 1002).unwrap();
        for kind in 0..6 {
            let mut bad = good.clone();
            match kind {
                0 => bad.statistics = None,
                1 => bad.statistics.as_mut().unwrap().dropped = 1,
                2 => bad.statistics.as_mut().unwrap().received = 0,
                3 => bad.recorded = 1025,
                4 => bad.elapsed_millis = 40_000,
                _ => bad.statistics.as_mut().unwrap().interface_dropped = 1,
            }
            assert!(bad.validate(&w, 1002).is_err());
        }
        assert!(good.validate(&w, 1000).is_err());
        assert!(good.validate(&w, 1041).is_err());
        let failed = CaptureFinish {
            timeline: None,
            elapsed_millis: 40_100,
            recorded: 1,
            statistics: None,
            error: Some("deadline expired".into()),
        };
        failed.validate(&w, 1042).unwrap();
    }
    fn witness(p: &Permit) -> CaptureWitness {
        CaptureWitness {
            generation: p.generation.clone(),
            nonce: "2".repeat(32),
            permit_sha256: "c".repeat(64),
            created: 1001,
            process: Identity {
                uid: 0,
                pid: 123,
                birth: [1, 2],
                executable: crate::macos::installed_path(&p.tooling_sha256).unwrap(),
            },
            lease_file: [1, 2],
        }
    }
    #[test]
    fn capture_pin_never_renews_after_expiry_replacement_or_observation_failure() {
        let p = permit();
        let w = witness(&p);
        let start = Instant::now();
        let mut pin = CapturePin::default();
        pin.check_at(&w, 1002, start).unwrap();
        pin.check_at(&w, 1002, start + Duration::from_secs(38))
            .unwrap();
        assert!(
            pin.check_at(&w, 1002, start + Duration::from_secs(39))
                .is_err()
        );
        assert!(pin.check_at(&w, 1002, start).is_err());
        let mut pin = CapturePin::default();
        pin.check_at(&w, 1002, start).unwrap();
        let mut changed = w.clone();
        changed.nonce = "3".repeat(32);
        assert!(pin.check_at(&changed, 1002, start).is_err());
        assert!(pin.check_at(&w, 1002, start).is_err());
        let mut pin = CapturePin::default();
        pin.check_at(&w, 1002, start).unwrap();
        pin.invalidate();
        assert!(pin.check_at(&w, 1002, start).is_err());
        let mut pin = CapturePin::default();
        pin.check_at(&w, 1002, start).unwrap();
        assert!(pin.check_at(&w, 1001, start).is_err());
    }
    #[test]
    fn witness_requires_exact_permit_live_process_incarnation_and_short_lifetime() {
        let p = permit();
        let w = witness(&p);
        w.validate(&p, &"c".repeat(64), &context(&p, 1002), &w.process)
            .unwrap();
        assert!(
            w.validate(&p, &"d".repeat(64), &context(&p, 1002), &w.process)
                .is_err()
        );
        assert!(
            w.validate(&p, &"c".repeat(64), &context(&p, 1000), &w.process)
                .is_err()
        );
        assert!(
            w.validate(&p, &"c".repeat(64), &context(&p, 1041), &w.process)
                .is_err()
        );
        let mut live = w.process.clone();
        live.birth[1] += 1;
        assert!(
            w.validate(&p, &"c".repeat(64), &context(&p, 1002), &live)
                .is_err()
        );
        for kind in 0..5 {
            let mut bad = w.clone();
            match kind {
                0 => bad.process.uid = 501,
                1 => bad.process.executable = "/tmp/capture".into(),
                2 => bad.generation = "3".repeat(32),
                3 => bad.nonce = "0".repeat(32),
                _ => bad.process.pid = 0,
            };
            assert!(
                bad.validate(&p, &"c".repeat(64), &context(&p, 1002), &bad.process)
                    .is_err()
            );
        }
    }
    #[test]
    fn existing_capture_link_never_overwrites_its_target_or_publishes_readiness() {
        let path = std::env::temp_dir().join(format!(
            "studio-capture-link-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let path = fs::canonicalize(path).unwrap();
        let store = Store::at(path.clone(), Identity::current().unwrap().uid).unwrap();
        let p = permit();
        let c = context(&p, 1001);
        store.prepare(&p, &c).unwrap();
        let target = path.join("untouched");
        fs::write(&target, b"existing content").unwrap();
        std::os::unix::fs::symlink(&target, store.capture_path(&p.generation).unwrap()).unwrap();
        assert!(store.begin_capture(&p, &c).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"existing content");
        assert!(
            !path
                .join(format!("capture-ready-{}.json", p.generation))
                .exists()
        );
        assert!(
            path.join(format!("capture-permit-{}.json", p.generation))
                .is_file()
        );
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn capture_file_is_private_once_and_cannot_start_after_claim() {
        let path = std::env::temp_dir().join(format!(
            "studio-capture-store-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let path = fs::canonicalize(path).unwrap();
        let store = Store::at(path.clone(), Identity::current().unwrap().uid).unwrap();
        let p = permit();
        let c = context(&p, 1001);
        store.prepare(&p, &c).unwrap();
        let file = store.begin_capture(&p, &c).unwrap();
        let lease = store.capture_lease(&p, &c).unwrap();
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
        assert_eq!(file.metadata().unwrap().len(), 0);
        drop(file);
        assert!(store.begin_capture(&p, &c).is_err());
        if Identity::current().unwrap().uid != 0 {
            assert!(store.publish_capture(&p, &c, &lease).is_err());
        }
        assert!(store.live_capture(&p, &c).is_err());
        store.revoke(501, &p.generation).unwrap();
        let mut q = p;
        q.generation = "2".repeat(32);
        let c = context(&q, 1001);
        store.prepare(&q, &c).unwrap();
        store.claim(&q, &c, [1; 16]).unwrap();
        assert!(store.begin_capture(&q, &c).is_err());
        fs::remove_dir_all(path).unwrap();
    }
}
