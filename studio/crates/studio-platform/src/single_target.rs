//! Root-only permit records and atomic one-use claims for physical acceptance.
//! Used by the typed candidate; the installed legacy retained host is unchanged.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use studio_protocol::single_target::{Context, Permit};
type Result<T> = std::result::Result<T, String>;
const DIRECTORY: &str = "/Library/PrivilegedHelperTools/MasscanStudio/single-target-v1";
const LIMIT: u64 = 16384;
mod capture;
mod capture_lock;
mod transmission;
pub use capture::{
    CAPTURE_HEADER, CAPTURE_SECONDS, CaptureCompletion, CaptureEvidence, CaptureFinish,
    CaptureLease, CapturePin, CaptureStatistics, CaptureWitness,
};
pub use transmission::TransmissionLease;
pub mod recording;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub generation: String,
    pub permit_sha256: String,
    pub attempt: studio_protocol::Id,
    pub helper_pid: u32,
}
/// Pins a session to both wall-clock policy and a monotonic maximum lifetime.
#[derive(Default)]
pub struct Lease {
    pin: studio_protocol::single_target::Pin,
    deadline: Option<Instant>,
    rejected: bool,
}
impl Lease {
    pub fn deadline(&self) -> Result<Instant> {
        if self.rejected {
            return Err("Single-target lease invalidated".into());
        }
        self.deadline.ok_or("Single-target lease not pinned".into())
    }
    pub fn check(&mut self, permit: &Permit, context: &Context<'_>) -> Result<()> {
        self.check_at(permit, context, Instant::now())
    }
    fn check_at(&mut self, permit: &Permit, context: &Context<'_>, now: Instant) -> Result<()> {
        let result = (|| {
            if self.rejected {
                return Err("Single-target lease invalidated".into());
            }
            self.pin.check(permit, context)?;
            if self.deadline.is_none() {
                self.deadline = Some(
                    now.checked_add(Duration::from_secs(permit.expires - context.now))
                        .ok_or("Invalid monotonic permit deadline")?,
                );
            }
            if now >= self.deadline.ok_or("Missing monotonic permit deadline")? {
                return Err("Single-target monotonic lifetime expired".into());
            }
            Ok(())
        })();
        if result.is_err() {
            self.invalidate();
        }
        result
    }
    /// Any failed trusted observation invalidates the whole helper session.
    pub fn invalidate(&mut self) {
        self.rejected = true;
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub permit: Permit,
    pub claimed: bool,
    pub revoked: bool,
}
pub struct Store {
    directory: PathBuf,
    owner: u32,
}
impl Store {
    /// Only production constructor: no environment, caller path or owner override.
    pub fn root() -> Result<Self> {
        Self::production(true)
    }
    /// Runtime reads never initialize a missing permission namespace.
    pub fn existing_root() -> Result<Self> {
        Self::production(false)
    }
    fn production(create: bool) -> Result<Self> {
        if crate::unix::Identity::current()?.uid != 0 {
            return Err("Single-target records require the root helper".into());
        }
        let directory = PathBuf::from(DIRECTORY);
        let deadline = budget();
        for ancestor in directory.ancestors().skip(1) {
            let m = fs::symlink_metadata(ancestor).map_err(err)?;
            if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err("Untrusted single-target parent directory".into());
            }
            no_acl(ancestor, deadline)?;
        }
        if create {
            match fs::DirBuilder::new().mode(0o700).create(&directory) {
                Ok(()) => File::open(directory.parent().ok_or("Missing permit parent")?)
                    .map_err(err)?
                    .sync_all()
                    .map_err(err)?,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        Self::at(directory, 0)
    }
    fn at(directory: PathBuf, owner: u32) -> Result<Self> {
        let store = Self { directory, owner };
        store.directory(budget())?;
        Ok(store)
    }
    fn directory(&self, deadline: Instant) -> Result<()> {
        trusted(&self.directory, self.owner, true, deadline)?;
        if fs::canonicalize(&self.directory).map_err(err)? != self.directory {
            return Err("Single-target directory must be canonical".into());
        }
        Ok(())
    }
    fn lock(&self, deadline: Instant) -> Result<File> {
        self.directory(deadline)?;
        let path = self.directory.join("records.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(err)?;
        let fd = file.metadata().map_err(err)?;
        metadata(&fd, self.owner, false)?;
        trusted(&path, self.owner, false, deadline)?;
        same_file(&fd, &fs::symlink_metadata(&path).map_err(err)?)?;
        loop {
            crate::sealed_fixture::check(deadline, &|| false)?;
            match file.try_lock() {
                Ok(()) => break,
                Err(fs::TryLockError::WouldBlock) => std::thread::sleep(
                    Duration::from_millis(5)
                        .min(deadline.saturating_duration_since(Instant::now())),
                ),
                Err(fs::TryLockError::Error(e)) => return Err(err(e)),
            }
        }
        // The inode must still be the named lock after waiting for another
        // legitimate recorder/helper reader. Contention never renews the budget.
        same_file(
            &file.metadata().map_err(err)?,
            &fs::symlink_metadata(&path).map_err(err)?,
        )?;
        crate::sealed_fixture::check(deadline, &|| false)?;
        Ok(file)
    }
    fn read(&self, path: &Path, deadline: Instant) -> Result<Vec<u8>> {
        self.read_limit(path, deadline, LIMIT)
    }
    fn read_limit(&self, path: &Path, deadline: Instant, limit: u64) -> Result<Vec<u8>> {
        trusted(path, self.owner, false, deadline)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(err)?;
        let before = file.metadata().map_err(err)?;
        metadata(&before, self.owner, false)?;
        if before.len() > limit {
            return Err("Oversized single-target record".into());
        }
        let mut bytes = Vec::new();
        (&file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        let after = fs::symlink_metadata(path).map_err(err)?;
        metadata(&after, self.owner, false)?;
        same_file(&before, &after)?;
        if bytes.len() as u64 != before.len()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || bytes.len() as u64 > limit
        {
            return Err("Single-target record changed during read or exceeds limit".into());
        }
        crate::sealed_fixture::check(deadline, &|| false)?;
        Ok(bytes)
    }
    fn create(&self, path: &Path, bytes: &[u8], deadline: Instant) -> Result<()> {
        if bytes.len() as u64 > LIMIT {
            return Err("Oversized single-target record".into());
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(err)?;
        metadata(&file.metadata().map_err(err)?, self.owner, false)?;
        trusted(path, self.owner, false, deadline)?;
        // A partial/failed create is deliberately retained and blocks reuse.
        file.write_all(bytes).map_err(err)?;
        file.sync_all().map_err(err)?;
        self.sync()
    }
    fn sync(&self) -> Result<()> {
        File::open(&self.directory)
            .map_err(err)?
            .sync_all()
            .map_err(err)
    }
    fn permit_path(&self, uid: u32) -> Result<PathBuf> {
        if uid == 0 {
            return Err("Permit owner must be an ordinary user".into());
        }
        Ok(self.directory.join(format!("permit-{uid}.json")))
    }
    fn marker(&self, prefix: &str, generation: &str) -> Result<PathBuf> {
        if generation.len() != 32
            || !generation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || generation.bytes().all(|b| b == b'0')
        {
            return Err("Invalid single-target generation".into());
        }
        Ok(self.directory.join(format!("{prefix}-{generation}.json")))
    }
    fn not_revoked(&self, generation: &str) -> Result<()> {
        absent(&self.marker("revoked", generation)?)
    }
    fn load_locked(&self, context: &Context<'_>, deadline: Instant) -> Result<(Permit, Vec<u8>)> {
        let bytes = self.read(&self.permit_path(context.owner_uid)?, deadline)?;
        let permit = Permit::decode(&bytes, context)?;
        self.not_revoked(&permit.generation)?;
        Ok((permit, bytes))
    }
    /// Read-only maintenance status, including expired permits. Never admission.
    pub fn inspect(&self, uid: u32) -> Result<Option<Record>> {
        let path = self.permit_path(uid)?;
        let deadline = budget();
        let _lock = self.lock(deadline)?;
        if missing(&path)? {
            return Ok(None);
        }
        let bytes = self.read(&path, deadline)?;
        let permit: Permit = serde_json::from_slice(&bytes).map_err(err)?;
        // Structural validation at creation time is for display/cleanup only.
        // Execution still requires load with independently observed live context.
        permit.validate(&Context {
            now: permit.created,
            owner_uid: uid,
            tooling_sha256: &permit.tooling_sha256,
            helper_sha256: &permit.helper_sha256,
        })?;
        let claimed = !missing(&self.marker("claim", &permit.generation)?)?;
        let revoked = !missing(&self.marker("revoked", &permit.generation)?)?;
        Ok(Some(Record {
            permit,
            claimed,
            revoked,
        }))
    }
    pub fn prepare(&self, permit: &Permit, context: &Context<'_>) -> Result<()> {
        permit.validate(context)?;
        let deadline = budget();
        let _lock = self.lock(deadline)?;
        self.not_revoked(&permit.generation)?;
        absent(&self.marker("claim", &permit.generation)?)?;
        self.create(
            &self.permit_path(permit.owner_uid)?,
            &serde_json::to_vec(permit).map_err(err)?,
            deadline,
        )
    }
    pub fn load(&self, context: &Context<'_>) -> Result<Permit> {
        let deadline = budget();
        let _lock = self.lock(deadline)?;
        self.load_locked(context, deadline).map(|(p, _)| p)
    }
    pub fn claim(
        &self,
        expected: &Permit,
        context: &Context<'_>,
        attempt: studio_protocol::Id,
    ) -> Result<Claim> {
        if attempt == [0; 16] {
            return Err("Missing single-target attempt identity".into());
        }
        let deadline = budget();
        let _lock = self.lock(deadline)?;
        let (permit, bytes) = self.load_locked(context, deadline)?;
        if &permit != expected {
            return Err("Single-target permit changed before claim".into());
        }
        let claim = Claim {
            generation: permit.generation.clone(),
            permit_sha256: Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            attempt,
            helper_pid: std::process::id(),
        };
        self.create(
            &self.marker("claim", &permit.generation)?,
            &serde_json::to_vec(&claim).map_err(err)?,
            deadline,
        )?;
        Ok(claim)
    }
    /// Recheck the durable claim on the same helper process before packet I/O.
    pub fn verify_claim(
        &self,
        expected: &Permit,
        context: &Context<'_>,
        claim: &Claim,
        expected_attempt: studio_protocol::Id,
    ) -> Result<()> {
        let deadline = budget();
        let _lock = self.lock(deadline)?;
        let (permit, bytes) = self.load_locked(context, deadline)?;
        let hash: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if &permit != expected
            || claim.generation != permit.generation
            || claim.attempt == [0; 16]
            || claim.attempt != expected_attempt
            || claim.helper_pid != std::process::id()
            || claim.permit_sha256 != hash
        {
            return Err(
                "Single-target claim does not belong to this attempt, process or permit".into(),
            );
        }
        let stored: Claim = serde_json::from_slice(
            &self.read(&self.marker("claim", &permit.generation)?, deadline)?,
        )
        .map_err(err)?;
        if &stored != claim {
            return Err("Single-target durable claim changed".into());
        }
        Ok(())
    }
    /// Cleanup can revoke an expired permit, but never authorizes its execution.
    pub fn revoke(&self, uid: u32, generation: &str) -> Result<()> {
        let marker = self.marker("revoked", generation)?;
        let path = self.permit_path(uid)?;
        let deadline = budget();
        let _lock = self.lock(deadline)?;
        let bytes = self.read(&path, deadline)?;
        let permit: Permit = serde_json::from_slice(&bytes).map_err(err)?;
        if permit.owner_uid != uid || permit.generation != generation {
            return Err("Revocation differs from active permit identity".into());
        }
        let record = serde_json::to_vec(&(uid, generation)).map_err(err)?;
        match fs::symlink_metadata(&marker) {
            Ok(_) => {
                if self.read(&marker, deadline)? != record {
                    return Err("Revocation record differs".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.create(&marker, &record, deadline)?
            }
            Err(e) => return Err(e.to_string()),
        }
        fs::remove_file(path).map_err(err)?;
        self.sync()
    }
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn budget() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn missing(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.to_string()),
        Ok(_) => Ok(false),
    }
}
fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
        Ok(_) => Err("Single-target record already exists; generation cannot be reused".into()),
    }
}
fn metadata(m: &fs::Metadata, owner: u32, directory: bool) -> Result<()> {
    if m.uid() != owner
        || m.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
        || m.file_type().is_symlink()
        || if directory {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1
        }
    {
        return Err("Untrusted single-target filesystem identity".into());
    }
    Ok(())
}
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> Result<()> {
    if a.dev() != b.dev() || a.ino() != b.ino() {
        return Err("Single-target file replaced".into());
    }
    Ok(())
}
fn no_acl(path: &Path, deadline: Instant) -> Result<()> {
    let text = crate::sealed_fixture::command(
        &[
            "/bin/ls",
            "-lde",
            "-n",
            path.to_str().ok_or("Invalid permit path")?,
        ],
        deadline,
        &|| false,
    )?;
    if text.lines().count() != 1 {
        return Err("Extended ACL on single-target record".into());
    }
    Ok(())
}
fn trusted(path: &Path, owner: u32, directory: bool, deadline: Instant) -> Result<()> {
    crate::sealed_fixture::check(deadline, &|| false)?;
    metadata(&fs::symlink_metadata(path).map_err(err)?, owner, directory)?;
    no_acl(path, deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    const TOOL: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HELPER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    fn context() -> Context<'static> {
        Context {
            now: 1001,
            owner_uid: 501,
            tooling_sha256: TOOL,
            helper_sha256: HELPER,
        }
    }
    fn permit() -> Permit {
        Permit {
            version: 1,
            generation: "11111111111111111111111111111111".into(),
            owner_uid: 501,
            created: 1000,
            expires: 1900,
            tooling_sha256: TOOL.into(),
            helper_sha256: HELPER.into(),
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
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "studio-single-target-{}",
                studio_protocol::id_text(studio_protocol::new_id().unwrap())
            ));
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(fs::canonicalize(p).unwrap())
        }
        fn store(&self) -> Store {
            Store::at(
                self.0.clone(),
                crate::unix::Identity::current().unwrap().uid,
            )
            .unwrap()
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn legitimate_recorder_helper_lock_overlap_waits_within_a_fixed_deadline() {
        let t = Temp::new();
        let store = t.store();
        store.prepare(&permit(), &context()).unwrap();
        let held = store.lock(budget()).unwrap();
        let other = t.store();
        let (started, ready) = std::sync::mpsc::channel();
        let (result, done) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            started.send(()).unwrap();
            result.send(other.load(&context())).unwrap();
        });
        ready.recv().unwrap();
        assert!(matches!(
            done.recv_timeout(Duration::from_millis(60)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        drop(held);
        assert_eq!(
            done.recv_timeout(Duration::from_secs(2)).unwrap().unwrap(),
            permit()
        );
        worker.join().unwrap();
        let held = store.lock(budget()).unwrap();
        let began = Instant::now();
        assert!(store.lock(began + Duration::from_millis(40)).is_err());
        assert!(began.elapsed() >= Duration::from_millis(35));
        assert!(began.elapsed() < Duration::from_secs(1));
        drop(held);
    }
    #[test]
    fn one_claim_survives_reopen_and_refuses_another_attempt_or_permit() {
        let t = Temp::new();
        let s = t.store();
        let p = permit();
        let c = context();
        s.prepare(&p, &c).unwrap();
        assert_eq!(s.load(&c).unwrap(), p);
        assert!(s.prepare(&p, &c).is_err());
        let first = s.claim(&p, &c, [1; 16]).unwrap();
        assert_eq!(first.attempt, [1; 16]);
        assert!(t.store().claim(&p, &c, [1; 16]).is_err());
        assert!(t.store().claim(&p, &c, [2; 16]).is_err());
        let mut q = p.clone();
        q.ports = vec![443];
        assert!(t.store().claim(&q, &c, [3; 16]).is_err());
    }
    #[test]
    fn symlinks_hardlinks_modes_and_oversized_records_are_not_trusted() {
        use std::os::unix::fs::symlink;
        let t = Temp::new();
        let s = t.store();
        let p = permit();
        let c = context();
        s.prepare(&p, &c).unwrap();
        let path = t.0.join("permit-501.json");
        let bytes = fs::read(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(s.load(&c).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = t.0.join("second-name");
        fs::hard_link(&path, &link).unwrap();
        assert!(s.load(&c).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_file(&path).unwrap();
        let original = t.0.join("original");
        fs::write(&original, &bytes).unwrap();
        symlink(&original, &path).unwrap();
        assert!(s.load(&c).is_err());
        assert!(s.prepare(&p, &c).is_err());
        assert_eq!(fs::read(&original).unwrap(), bytes);
        fs::remove_file(&path).unwrap();
        fs::write(&path, vec![b' '; 16385]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(s.load(&c).is_err());
    }
    #[test]
    fn revocation_removes_only_the_expected_permit_and_prevents_generation_reuse() {
        let t = Temp::new();
        let s = t.store();
        let p = permit();
        let c = context();
        s.prepare(&p, &c).unwrap();
        assert!(s.revoke(501, &"2".repeat(32)).is_err());
        assert_eq!(s.load(&c).unwrap(), p);
        s.claim(&p, &c, [1; 16]).unwrap();
        s.revoke(501, &p.generation).unwrap();
        assert!(s.load(&c).is_err());
        assert!(s.prepare(&p, &c).is_err());
        assert!(t.0.join(format!("claim-{}.json", p.generation)).is_file());
        let mut q = p;
        q.generation = "2".repeat(32);
        s.prepare(&q, &c).unwrap();
        assert_eq!(s.load(&c).unwrap(), q);
    }
    #[test]
    fn invalid_inputs_do_not_create_a_permit_or_claim() {
        let t = Temp::new();
        let s = t.store();
        let mut p = permit();
        let c = context();
        p.ports = vec![0];
        assert!(s.prepare(&p, &c).is_err());
        assert!(!t.0.join("permit-501.json").exists());
        let p = permit();
        s.prepare(&p, &c).unwrap();
        assert!(s.claim(&p, &c, [0; 16]).is_err());
        assert!(!t.0.join(format!("claim-{}.json", p.generation)).exists());
        assert!(
            s.load(&Context {
                now: 1900,
                ..context()
            })
            .is_err()
        );
        // Cleanup remains possible after expiry without reauthorizing execution.
        s.revoke(501, &p.generation).unwrap();
        assert!(!t.0.join("permit-501.json").exists());
    }
    #[test]
    fn exactly_one_concurrent_helper_claims_and_deleted_permit_does_not_reset_it() {
        let t = Temp::new();
        let s = t.store();
        let p = permit();
        let c = context();
        s.prepare(&p, &c).unwrap();
        let barrier = std::sync::Barrier::new(8);
        let successes = std::thread::scope(|scope| {
            let tasks: Vec<_> = (1..=8)
                .map(|n| {
                    let barrier = &barrier;
                    let s = &s;
                    let p = &p;
                    let c = &c;
                    scope.spawn(move || {
                        barrier.wait();
                        s.claim(p, c, [n; 16]).is_ok()
                    })
                })
                .collect();
            tasks
                .into_iter()
                .map(|t| t.join().unwrap())
                .filter(|ok| *ok)
                .count()
        });
        assert_eq!(successes, 1);
        assert!(s.claim(&p, &c, [9; 16]).is_err());
        fs::remove_file(t.0.join("permit-501.json")).unwrap();
        assert!(s.prepare(&p, &c).is_err());
    }
    #[test]
    fn claim_verification_rejects_replacement_tampering_and_another_process() {
        let t = Temp::new();
        let s = t.store();
        let p = permit();
        let c = context();
        s.prepare(&p, &c).unwrap();
        let claim = s.claim(&p, &c, [1; 16]).unwrap();
        s.verify_claim(&p, &c, &claim, [1; 16]).unwrap();
        assert!(s.verify_claim(&p, &c, &claim, [2; 16]).is_err());
        let mut wrong = claim.clone();
        wrong.helper_pid = 0;
        assert!(s.verify_claim(&p, &c, &wrong, [1; 16]).is_err());
        wrong = claim.clone();
        wrong.attempt = [2; 16];
        assert!(s.verify_claim(&p, &c, &wrong, [1; 16]).is_err());
        let path = t.0.join(format!("claim-{}.json", p.generation));
        fs::write(&path, b"{}").unwrap();
        assert!(s.verify_claim(&p, &c, &claim, [1; 16]).is_err());
        fs::write(&path, serde_json::to_vec(&claim).unwrap()).unwrap();
        let mut altered = p.clone();
        altered.ports = vec![443];
        fs::write(
            t.0.join("permit-501.json"),
            serde_json::to_vec(&altered).unwrap(),
        )
        .unwrap();
        assert!(s.verify_claim(&p, &c, &claim, [1; 16]).is_err());
        assert!(s.verify_claim(&altered, &c, &claim, [1; 16]).is_err());
    }
    #[test]
    fn extended_acl_and_symlinked_claim_fail_closed() {
        use std::os::unix::fs::symlink;
        let t = Temp::new();
        let s = t.store();
        let p = permit();
        let c = context();
        s.prepare(&p, &c).unwrap();
        let path = t.0.join("permit-501.json");
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(s.load(&c).is_err());
        assert!(
            std::process::Command::new("/bin/chmod")
                .arg("-N")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let original = fs::read(&path).unwrap();
        symlink(&path, t.0.join(format!("claim-{}.json", p.generation))).unwrap();
        assert!(s.claim(&p, &c, [1; 16]).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }
    #[test]
    fn partial_records_block_reuse_and_failed_cleanup_preserves_evidence() {
        let t = Temp::new();
        let s = t.store();
        let p = permit();
        let c = context();
        s.prepare(&p, &c).unwrap();
        let claim = t.0.join(format!("claim-{}.json", p.generation));
        fs::write(&claim, b"{").unwrap();
        fs::set_permissions(&claim, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(s.claim(&p, &c, [1; 16]).is_err());
        let revoked = t.0.join(format!("revoked-{}.json", p.generation));
        fs::write(&revoked, b"{").unwrap();
        fs::set_permissions(&revoked, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(s.load(&c).is_err());
        assert!(s.revoke(501, &p.generation).is_err());
        assert!(t.0.join("permit-501.json").exists());
        fs::write(t.0.join("permit-501.json"), b"{").unwrap();
        assert!(s.revoke(501, &p.generation).is_err());
        assert_eq!(fs::read(&claim).unwrap(), b"{");
        assert_eq!(fs::read(&revoked).unwrap(), b"{");
    }
    #[test]
    fn monotonic_expiry_and_external_failure_cannot_revive_a_session() {
        let p = permit();
        let c = context();
        let start = Instant::now();
        let mut lease = Lease::default();
        lease.check_at(&p, &c, start).unwrap();
        lease
            .check_at(&p, &c, start + Duration::from_secs(898))
            .unwrap();
        assert!(
            lease
                .check_at(&p, &c, start + Duration::from_secs(899))
                .is_err()
        );
        assert!(lease.check_at(&p, &c, start).is_err());
        let mut lease = Lease::default();
        lease.check_at(&p, &c, start).unwrap();
        lease.invalidate();
        assert!(lease.check_at(&p, &c, start).is_err());
    }
    #[test]
    fn lease_rejects_changed_identity_and_wall_clock_rollback_permanently() {
        let p = permit();
        let c = context();
        let start = Instant::now();
        let mut lease = Lease::default();
        lease.check_at(&p, &c, start).unwrap();
        assert!(
            lease
                .check_at(
                    &p,
                    &Context {
                        now: 1000,
                        ..context()
                    },
                    start
                )
                .is_err()
        );
        assert!(lease.check_at(&p, &c, start).is_err());
        let mut lease = Lease::default();
        lease.check_at(&p, &c, start).unwrap();
        let mut q = p.clone();
        q.generation = "2".repeat(32);
        assert!(lease.check_at(&q, &c, start).is_err());
        assert!(lease.check_at(&p, &c, start).is_err());
    }
    #[test]
    fn maintenance_inspection_reports_consumed_expired_records_without_admitting_them() {
        let t = Temp::new();
        let s = t.store();
        let p = permit();
        let c = context();
        assert!(s.inspect(501).unwrap().is_none());
        s.prepare(&p, &c).unwrap();
        let record = s.inspect(501).unwrap().unwrap();
        assert_eq!(record.permit, p);
        assert!(!record.claimed);
        s.claim(&p, &c, [1; 16]).unwrap();
        assert!(s.inspect(501).unwrap().unwrap().claimed);
        assert!(
            s.load(&Context {
                now: 2000,
                ..context()
            })
            .is_err()
        );
        assert_eq!(s.inspect(501).unwrap().unwrap().permit, p);
        s.revoke(501, &p.generation).unwrap();
        assert!(s.inspect(501).unwrap().is_none());
    }
    #[test]
    fn wrong_owner_and_nonprivate_directory_are_rejected() {
        let t = Temp::new();
        let uid = crate::unix::Identity::current().unwrap().uid;
        assert!(Store::at(t.0.clone(), uid + 1).is_err());
        fs::set_permissions(&t.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Store::at(t.0.clone(), uid).is_err());
        if uid != 0 {
            assert!(Store::root().is_err());
        }
    }
}
