//! A one-use capture witness belongs to a live root process, never the GUI.
use super::*;
use crate::unix::Identity;
pub const CAPTURE_SECONDS: u64 = 40;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureWitness {
    pub generation: String,
    pub nonce: String,
    pub permit_sha256: String,
    pub created: u64,
    pub process: Identity,
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
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
        assert_eq!(file.metadata().unwrap().len(), 0);
        drop(file);
        assert!(store.begin_capture(&p, &c).is_err());
        if Identity::current().unwrap().uid != 0 {
            assert!(store.publish_capture(&p, &c).is_err());
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
