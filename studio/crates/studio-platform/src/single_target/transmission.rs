//! Preopened immutable root records and a live kernel capture lease at each send.
//! Expensive trust/hash/ACL checks happen at construction and in the route guard;
//! the packet path uses descriptor/name metadata and kernel process/lock queries.
use super::*;
struct ObservedFile {
    path: PathBuf,
    file: File,
    metadata: fs::Metadata,
    owner: u32,
    mode: u32,
}
impl ObservedFile {
    fn verify_json<T: serde::de::DeserializeOwned + PartialEq>(
        &mut self,
        expected: &T,
    ) -> Result<()> {
        let mut bytes = Vec::new();
        (&mut self.file)
            .take(LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        if bytes.len() as u64 > LIMIT
            || serde_json::from_slice::<T>(&bytes).map_err(err)? != *expected
        {
            return Err("Pinned packet record differs from admitted record".into());
        }
        self.check()
    }
    fn verify_hash(&mut self, expected: &str, deadline: Instant) -> Result<()> {
        let mut sha = Sha256::new();
        let mut reader = (&mut self.file).take(self.metadata.len().saturating_add(1));
        let mut bytes = [0; 65536];
        loop {
            crate::sealed_fixture::check(deadline, &|| false)?;
            let count = reader.read(&mut bytes).map_err(err)?;
            if count == 0 {
                break;
            }
            sha.update(&bytes[..count]);
        }
        if sha
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            != expected
        {
            return Err("Pinned packet file hash differs from admitted file".into());
        }
        self.check()
    }
    fn open(path: PathBuf, owner: u32, mode: u32) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(err)?;
        let metadata = file.metadata().map_err(err)?;
        let result = Self {
            path,
            file,
            metadata,
            owner,
            mode,
        };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        for current in [
            self.file.metadata().map_err(err)?,
            fs::symlink_metadata(&self.path).map_err(err)?,
        ] {
            if !current.is_file()
                || current.file_type().is_symlink()
                || current.uid() != self.owner
                || current.mode() & 0o7777 != self.mode
                || current.nlink() != 1
                || current.dev() != self.metadata.dev()
                || current.ino() != self.metadata.ino()
                || current.len() != self.metadata.len()
                || current.mtime() != self.metadata.mtime()
                || current.mtime_nsec() != self.metadata.mtime_nsec()
                || current.ctime() != self.metadata.ctime()
                || current.ctime_nsec() != self.metadata.ctime_nsec()
            {
                return Err("Packet permission record or executable changed".into());
            }
        }
        Ok(())
    }
}
struct ObservedDirectory {
    path: PathBuf,
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
}
impl ObservedDirectory {
    fn open(path: PathBuf) -> Result<Self> {
        let m = fs::symlink_metadata(&path).map_err(err)?;
        let result = Self {
            path,
            device: m.dev(),
            inode: m.ino(),
            owner: m.uid(),
            mode: m.mode() & 0o7777,
        };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        let m = fs::symlink_metadata(&self.path).map_err(err)?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || m.uid() != 0
            || self.owner != 0
            || m.mode() & 0o022 != 0
            || m.mode() & 0o7777 != self.mode
            || m.dev() != self.device
            || m.ino() != self.inode
        {
            return Err("Packet permission directory changed".into());
        }
        Ok(())
    }
}
pub struct TransmissionLease {
    files: Vec<ObservedFile>,
    directories: Vec<ObservedDirectory>,
    capture_file: ObservedFile,
    witness: CaptureWitness,
    host: crate::unix::Identity,
    ended: PathBuf,
    revoked: PathBuf,
    deadline: Instant,
    expires: u64,
    last_wall: u64,
    failed: bool,
}
impl TransmissionLease {
    /// No disk writes, hashing, external commands or lock acquisition on this
    /// path. Every WouldBlock retry must call again. A late check sends nothing.
    pub fn check(&mut self, io_deadline: Instant) -> Result<Instant> {
        let result = (|| {
            self.time(io_deadline)?;
            for directory in &self.directories {
                directory.check()?;
            }
            for file in &self.files {
                file.check()?;
            }
            self.capture_file.check()?;
            absent(&self.ended)?;
            absent(&self.revoked)?;
            if [
                self.capture_file.metadata.dev(),
                self.capture_file.metadata.ino(),
            ] != self.witness.lease_file
                || super::capture_lock::owner(&self.capture_file.file)?
                    != Some(self.witness.process.pid)
                || crate::unix::Identity::read(self.witness.process.pid)? != self.witness.process
                || crate::unix::Identity::read(self.host.pid)? != self.host
            {
                return Err("Packet capture lease released or process changed".into());
            }
            self.time(io_deadline)?;
            Ok(self.deadline.min(io_deadline))
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn time(&mut self, io_deadline: Instant) -> Result<()> {
        let now = crate::sealed_fixture::now()?;
        if self.failed
            || now < self.last_wall
            || now >= self.expires
            || Instant::now() >= self.deadline
            || Instant::now() >= io_deadline
        {
            return Err(
                "Packet permission invalidated, expired or check exceeded its deadline".into(),
            );
        }
        self.last_wall = now;
        Ok(())
    }
}
impl Store {
    pub fn transmission_lease(
        &self,
        permit: &Permit,
        context: &Context<'_>,
        claim: &Claim,
        attempt: studio_protocol::Id,
        witness: &CaptureWitness,
        deadline: Instant,
    ) -> Result<TransmissionLease> {
        self.verify_claim(permit, context, claim, attempt)?;
        if self.live_capture(permit, context)? != *witness {
            return Err("Packet capture witness replaced".into());
        }
        // The publisher must never open a second descriptor for its POSIX lock.
        if witness.process.pid == std::process::id() {
            return Err("Capture publisher cannot transmit".into());
        }
        let config = crate::work_session::host_config(permit.owner_uid)?
            .ok_or("Packet host configuration missing")?;
        let host = crate::unix::Identity::read(config.pid)?;
        if config.tool_hash != permit.tooling_sha256
            || config.runner_hash != permit.helper_sha256
            || host.uid != 0
            || host.executable != crate::macos::installed_path(&permit.tooling_sha256)?
        {
            return Err("Packet host identity differs from permit".into());
        }
        let end = permit.expires.min(
            witness
                .created
                .checked_add(CAPTURE_SECONDS)
                .ok_or("Invalid capture expiry")?,
        );
        let remaining = end
            .checked_sub(context.now)
            .filter(|n| *n > 0)
            .ok_or("Packet grant expired")?;
        let deadline = deadline.min(Instant::now() + Duration::from_secs(remaining));
        let paths = [
            self.permit_path(permit.owner_uid)?,
            self.marker("claim", &permit.generation)?,
            self.marker("capture-ready", &permit.generation)?,
        ];
        let budget = budget();
        let _lock = self.lock(budget)?;
        let mut files = Vec::new();
        for path in paths {
            trusted(&path, self.owner, false, budget)?;
            files.push(ObservedFile::open(path, self.owner, 0o600)?);
        }
        // Bind admission to the exact descriptors retained by the fast path,
        // including changes between initial validation and these opens.
        files[0].verify_hash(&claim.permit_sha256, budget)?;
        files[1].verify_json(claim)?;
        files[2].verify_json(witness)?;
        for hash in [&permit.tooling_sha256, &permit.helper_sha256] {
            let path = crate::macos::installed_path(hash)?;
            crate::trusted::verify(&path, hash)?;
            let mut file = ObservedFile::open(path, 0, 0o755)?;
            file.verify_hash(hash, budget)?;
            files.push(file);
        }
        let mut host_file = ObservedFile::open(
            crate::work_session::directory(permit.owner_uid).join("host.json"),
            0,
            0o644,
        )?;
        host_file.verify_json(&config)?;
        files.push(host_file);
        let capture_path = self.marker("capture-live", &permit.generation)?;
        trusted(&capture_path, self.owner, false, budget)?;
        let capture_file = ObservedFile::open(capture_path, self.owner, 0o600)?;
        let mut directories = Vec::new();
        for path in self.directory.ancestors() {
            directories.push(ObservedDirectory::open(path.to_owned())?);
        }
        for file in &files {
            if let Some(parent) = file.path.parent()
                && !directories.iter().any(|d| d.path == parent)
            {
                directories.push(ObservedDirectory::open(parent.to_owned())?);
            }
        }
        let mut lease = TransmissionLease {
            files,
            directories,
            capture_file,
            witness: witness.clone(),
            host,
            ended: self.marker("capture-ended", &permit.generation)?,
            revoked: self.marker("revoked", &permit.generation)?,
            deadline,
            expires: end,
            last_wall: context.now,
            failed: false,
        };
        lease.check(budget)?;
        Ok(lease)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn child_checks_composed_transmission_lease() {
        let Some(path) = std::env::var_os("STUDIO_TRANSMISSION_TEST_FILE") else {
            return;
        };
        let path = PathBuf::from(path);
        let pid = std::env::var("STUDIO_TRANSMISSION_TEST_PID")
            .unwrap()
            .parse()
            .unwrap();
        let identity = crate::unix::Identity::read(pid).unwrap();
        let owner = crate::unix::Identity::current().unwrap().uid;
        let now = crate::sealed_fixture::now().unwrap();
        let ready = Instant::now();
        for kind in 0..10 {
            let capture_file = ObservedFile::open(path.clone(), owner, 0o600).unwrap();
            let mut lease = TransmissionLease {
                files: vec![],
                directories: vec![],
                witness: CaptureWitness {
                    generation: "1".repeat(32),
                    nonce: "2".repeat(32),
                    permit_sha256: "a".repeat(64),
                    created: now,
                    process: identity.clone(),
                    lease_file: [capture_file.metadata.dev(), capture_file.metadata.ino()],
                },
                capture_file,
                host: identity.clone(),
                ended: path.with_extension("ended"),
                revoked: path.with_extension("revoked"),
                deadline: ready + Duration::from_secs(10),
                expires: now + 10,
                last_wall: now,
                failed: false,
            };
            let io = ready + Duration::from_secs(5);
            lease.check(io).unwrap();
            match kind {
                0 => fs::write(&lease.ended, b"ended").unwrap(),
                1 => fs::write(&lease.revoked, b"revoked").unwrap(),
                2 => lease.witness.process.birth[0] ^= 1,
                3 => lease.host.birth[0] ^= 1,
                4 => lease.witness.lease_file[1] ^= 1,
                5 => lease.deadline = ready,
                6 => lease.expires = now,
                7 => lease.last_wall = now + 60,
                8 => {
                    assert!(lease.check(ready).is_err());
                }
                _ => fs::write(&path, b"tampered").unwrap(),
            }
            assert!(lease.check(io).is_err(), "condition {kind}");
            for marker in [&lease.ended, &lease.revoked] {
                if marker.exists() {
                    fs::remove_file(marker).unwrap();
                }
            }
            lease.witness.process = identity.clone();
            lease.host = identity.clone();
            lease.witness.lease_file = [
                lease.capture_file.metadata.dev(),
                lease.capture_file.metadata.ino(),
            ];
            lease.deadline = ready + Duration::from_secs(10);
            lease.expires = now + 10;
            lease.last_wall = now;
            assert!(
                lease.check(io).is_err(),
                "failure must stay latched: {kind}"
            );
        }
    }
    #[test]
    fn composed_token_checks_kernel_owner_and_sticky_invalidation() {
        let path = std::env::temp_dir().join(format!(
            "studio-transmission-token-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        super::super::capture_lock::acquire(&file).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "single_target::transmission::tests::child_checks_composed_transmission_lease",
                "--nocapture",
            ])
            .env("STUDIO_TRANSMISSION_TEST_FILE", &path)
            .env(
                "STUDIO_TRANSMISSION_TEST_PID",
                std::process::id().to_string(),
            )
            .output()
            .unwrap();
        drop(file);
        fs::remove_file(path).unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn descriptor_verification_rejects_reopened_different_bytes() {
        let path = std::env::temp_dir().join(format!(
            "studio-transmission-bytes-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        let owner = crate::unix::Identity::current().unwrap().uid;
        let mut writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        writer.write_all(b"42").unwrap();
        drop(writer);
        ObservedFile::open(path.clone(), owner, 0o600)
            .unwrap()
            .verify_json(&42u32)
            .unwrap();
        assert!(
            ObservedFile::open(path.clone(), owner, 0o600)
                .unwrap()
                .verify_json(&43u32)
                .is_err()
        );
        let expected = Sha256::digest(b"42")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        ObservedFile::open(path.clone(), owner, 0o600)
            .unwrap()
            .verify_hash(&expected, budget())
            .unwrap();
        fs::write(&path, b"43").unwrap();
        assert!(
            ObservedFile::open(path.clone(), owner, 0o600)
                .unwrap()
                .verify_hash(&expected, budget())
                .is_err()
        );
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn preopened_records_refuse_content_replacement_permissions_links_and_renames() {
        for kind in 0..4 {
            let path = std::env::temp_dir().join(format!(
                "studio-transmit-record-{}",
                studio_protocol::id_text(studio_protocol::new_id().unwrap())
            ));
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(b"trusted").unwrap();
            drop(file);
            let record = ObservedFile::open(
                path.clone(),
                crate::unix::Identity::current().unwrap().uid,
                0o600,
            )
            .unwrap();
            record.check().unwrap();
            let renamed = path.with_extension("old");
            match kind {
                0 => fs::write(&path, b"changed!").unwrap(),
                1 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                2 => {
                    fs::rename(&path, &renamed).unwrap();
                    fs::write(&path, b"trusted").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                _ => {
                    fs::rename(&path, &renamed).unwrap();
                    std::os::unix::fs::symlink(&renamed, &path).unwrap();
                }
            }
            assert!(record.check().is_err());
            fs::remove_file(path).unwrap();
            if renamed.exists() {
                fs::remove_file(renamed).unwrap();
            }
        }
    }
}
