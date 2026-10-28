//! Durable scan history owned only by the unprivileged application.
#![forbid(unsafe_code)]
mod history;
mod profiles;
pub use profiles::SavedProfile;
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    fs::{self, File, OpenOptions},
    path::Path,
};
use studio_protocol::*;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type StoredFields = (
    Vec<u8>,
    String,
    String,
    Option<Vec<u8>>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
);
pub struct Store {
    db: Connection,
    _lock: File,
}
#[derive(Debug, Clone)]
pub struct SavedScan {
    pub scan: Id,
    pub attempt: Id,
    pub job: Job,
    pub status: Status,
    pub checkpoint: Option<Vec<u8>>,
    pub next_index: Option<String>,
    /// Canonical committed network provenance; present even when no neighbour answered.
    pub network_report: Option<Vec<u8>>,
    pub detail: String,
    pub name: Option<String>,
    pub created_at: Option<String>,
}
#[derive(Debug, Clone)]
pub struct SavedRow {
    pub row: Row,
    pub discovered_at: Option<String>,
}
fn private_file(path: &Path) -> Result<File> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("Symlinks are not accepted for history files".into());
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    Ok(opts.open(path)?)
}
impl Store {
    pub fn open(dir: &Path) -> Result<Self> {
        if fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("History directory cannot be a symlink".into());
        }
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        let dir = fs::canonicalize(dir)?;
        let lock = private_file(&dir.join("instance.lock"))?;
        lock.try_lock()
            .map_err(|_| "Studio is already using this history directory")?;
        drop(private_file(&dir.join("history.sqlite3"))?);
        let mut db = Connection::open(dir.join("history.sqlite3"))?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > 5 {
            return Err("History was created by a newer Studio version".into());
        }
        // Permuted scan keys dirty many index pages. The default 1,000-page
        // checkpoint repeatedly rewrites them on the commit thread on Windows.
        // This 4,096-page trigger (~16 MiB at 4 KiB/page, not a size cap) reduces
        // that write amplification. FULL still syncs every WAL commit.
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA wal_autocheckpoint=4096;")?;
        if version > 0 && version < 5 {
            let backup = dir.join(format!("before-v5-{}.sqlite3", id_text(new_id()?)));
            let partial = backup.with_extension("partial");
            let file = private_file(&partial)?;
            let mut destination = Connection::open(&partial)?;
            {
                let copy = rusqlite::backup::Backup::new(&db, &mut destination)?;
                if copy.step(-1)? != rusqlite::backup::StepResult::Done {
                    return Err("History backup is busy; migration was not started".into());
                }
            }
            destination.pragma_update(None, "journal_mode", "DELETE")?;
            destination.close().map_err(|(_, e)| e)?;
            file.sync_all()?;
            drop(file);
            fs::rename(partial, backup)?;
        }
        let migration = db.transaction()?;
        migration.execute_batch("
            CREATE TABLE IF NOT EXISTS scans (id BLOB PRIMARY KEY, attempt BLOB NOT NULL, job TEXT NOT NULL, status TEXT NOT NULL, sequence TEXT NOT NULL DEFAULT '0', checkpoint BLOB, next_index TEXT, detail TEXT NOT NULL DEFAULT '', updated INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS results (scan BLOB NOT NULL REFERENCES scans(id), ip TEXT NOT NULL, port INTEGER NOT NULL, open INTEGER NOT NULL, PRIMARY KEY(scan,ip,port));
            CREATE TABLE IF NOT EXISTS host_details (scan BLOB NOT NULL REFERENCES scans(id),ip TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(scan,ip));
            CREATE TABLE IF NOT EXISTS profiles (id BLOB PRIMARY KEY,name TEXT NOT NULL,name_key TEXT NOT NULL UNIQUE,job TEXT NOT NULL);")?;
        if version < 2 {
            migration.execute_batch("ALTER TABLE results ADD COLUMN discovered_at TEXT;")?;
        }
        if version < 3 {
            migration.execute_batch("ALTER TABLE scans ADD COLUMN name TEXT; ALTER TABLE scans ADD COLUMN created_at TEXT;")?;
        }
        if version < 5 {
            migration.execute_batch("ALTER TABLE scans ADD COLUMN network_report BLOB;")?;
        }
        migration.execute_batch("PRAGMA user_version=5;")?;
        migration.commit()?;
        let mut pending = db.prepare("SELECT scan,ip,data FROM host_details")?;
        let saved = pending
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(pending);
        for (scan, ip, json) in saved {
            let mut info: studio_inspection::HostInfo = serde_json::from_str(&json)?;
            let old = info.clone();
            info.recover();
            if info != old {
                db.execute(
                    "UPDATE host_details SET data=?3 WHERE scan=?1 AND ip=?2",
                    params![scan, ip, serde_json::to_string(&info)?],
                )?;
            }
        }
        db.execute("UPDATE scans SET status=CASE WHEN status IN ('\"Starting\"','\"Preparing\"') AND checkpoint IS NOT NULL THEN '\"Paused\"' ELSE '\"Interrupted\"' END, detail='Previous attempt ended before a terminal state was saved' WHERE status IN ('\"Starting\"','\"Preparing\"','\"Scanning\"','\"Saving\"')",[])?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in [
                "history.sqlite3",
                "history.sqlite3-wal",
                "history.sqlite3-shm",
                "instance.lock",
            ] {
                let p = dir.join(name);
                if p.exists() {
                    fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
                }
            }
        }
        Ok(Self { db, _lock: lock })
    }
    pub fn begin(&mut self, scan: Id, attempt: Id, job: &Job, resume: bool) -> Result<()> {
        job.validate()?;
        let tx = self.db.transaction()?;
        if resume {
            let old = Self::find(&tx, scan)?.ok_or("No saved scan")?;
            if old.status != Status::Paused || old.job != *job || old.attempt == attempt {
                return Err("This scan cannot be resumed".into());
            }
            validate_checkpoint(
                job,
                scan,
                checkpoint_origin(old.checkpoint.as_deref().ok_or("No checkpoint")?)?,
                old.checkpoint.as_deref().ok_or("No checkpoint")?,
                old.next_index.as_deref().ok_or("No checkpoint index")?,
            )?;
            if job.backend == Backend::MacNetwork {
                let envelope =
                    NetworkCheckpoint::decode(old.checkpoint.as_deref().ok_or("No checkpoint")?)?;
                if old.network_report.as_deref() != Some(envelope.report.encode()?.as_slice()) {
                    return Err(
                        "Checkpoint network report differs from durable scan coverage".into(),
                    );
                }
            }
            tx.execute("UPDATE scans SET attempt=?2,status='\"Starting\"',sequence='0',detail='',updated=unixepoch() WHERE id=?1",params![scan.as_slice(),attempt.as_slice()])?;
        } else {
            tx.execute("INSERT INTO scans(id,attempt,job,status,updated,created_at) VALUES(?1,?2,?3,'\"Starting\"',unixepoch(),?4)",params![scan.as_slice(),attempt.as_slice(),serde_json::to_string(job)?,studio_inspection::now()])?;
        }
        tx.commit()?;
        Ok(())
    }
    fn find(db: &Connection, scan: Id) -> Result<Option<SavedScan>> {
        let raw: Option<StoredFields> = db
            .query_row(
                "SELECT attempt,job,status,checkpoint,next_index,detail,name,created_at,network_report FROM scans WHERE id=?1",
                [scan.as_slice()],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                },
            )
            .optional()?;
        raw.map(
            |(
                attempt,
                job,
                status,
                checkpoint,
                next_index,
                detail,
                name,
                created_at,
                network_report,
            )| {
                let job: Job = serde_json::from_str(&job)?;
                if job.backend == Backend::MacNetwork {
                    if let Some(bytes) = &network_report {
                        NetworkReport::decode(bytes)?.validate_for(&job)?;
                    }
                    if let Some(bytes) = &checkpoint {
                        let envelope = NetworkCheckpoint::decode(bytes)?;
                        if network_report.as_deref() != Some(envelope.report.encode()?.as_slice()) {
                            return Err(
                                "Checkpoint network report differs from durable scan coverage"
                                    .into(),
                            );
                        }
                        validate_checkpoint(
                            &job,
                            scan,
                            checkpoint_origin(bytes)?,
                            bytes,
                            next_index.as_deref().ok_or("Missing checkpoint index")?,
                        )?;
                    }
                }
                Ok(SavedScan {
                    scan,
                    attempt: attempt.try_into().map_err(|_| "Invalid attempt id")?,
                    job,
                    status: serde_json::from_str(&status)?,
                    checkpoint,
                    next_index,
                    network_report,
                    detail,
                    name,
                    created_at,
                })
            },
        )
        .transpose()
    }
    pub fn scans(&self) -> Result<Vec<SavedScan>> {
        let mut st = self
            .db
            .prepare("SELECT id FROM scans ORDER BY updated DESC,rowid DESC")?;
        let ids = st
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|id| {
                Self::find(&self.db, id.try_into().map_err(|_| "Invalid scan id")?)?
                    .ok_or("Missing scan".into())
            })
            .collect()
    }
    pub fn rows(&self, scan: Id) -> Result<Vec<Row>> {
        let mut st = self
            .db
            .prepare("SELECT ip,port,open FROM results WHERE scan=?1 ORDER BY rowid")?;
        Ok(st
            .query_map([scan.as_slice()], |r| {
                Ok(Row {
                    ip: r.get(0)?,
                    port: r.get(1)?,
                    open: r.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }
    pub fn observations(&self, scan: Id) -> Result<Vec<SavedRow>> {
        let mut stmt = self.db.prepare(
            "SELECT ip,port,open,discovered_at FROM results WHERE scan=?1 ORDER BY rowid",
        )?;
        Ok(stmt
            .query_map([scan.as_slice()], |r| {
                Ok(SavedRow {
                    row: Row {
                        ip: r.get(0)?,
                        port: r.get(1)?,
                        open: r.get(2)?,
                    },
                    discovered_at: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }
    pub fn hosts(&self, scan: Id) -> Result<Vec<studio_inspection::HostInfo>> {
        let mut stmt = self
            .db
            .prepare("SELECT data FROM host_details WHERE scan=?1")?;
        let json = stmt
            .query_map([scan.as_slice()], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        json.iter()
            .map(|s| serde_json::from_str(s).map_err(Into::into))
            .collect()
    }
    pub fn save_host(&mut self, scan: Id, info: &studio_inspection::HostInfo) -> Result<()> {
        info.ip.parse::<std::net::Ipv4Addr>()?;
        let exists: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM results WHERE scan=?1 AND ip=?2)",
            params![scan.as_slice(), info.ip],
            |r| r.get(0),
        )?;
        if !exists {
            return Err("Host is not present in this scan".into());
        }
        self.db.execute("INSERT INTO host_details(scan,ip,data) VALUES(?1,?2,?3) ON CONFLICT(scan,ip) DO UPDATE SET data=excluded.data",params![scan.as_slice(),info.ip,serde_json::to_string(info)?])?;
        Ok(())
    }
    /// Full transaction before the controller may ACK a checkpoint or display results.
    pub fn apply(&mut self, event: &Envelope<Event>) -> Result<Vec<SavedRow>> {
        Ok(self.apply_batch(std::slice::from_ref(event))?.remove(0))
    }
    /// Ordered frames share one FULL commit. No rows escape on partial failure.
    pub fn apply_batch(&mut self, events: &[Envelope<Event>]) -> Result<Vec<Vec<SavedRow>>> {
        let began = std::time::Instant::now();
        let tx = self.db.transaction()?;
        let observed = events
            .iter()
            .map(|event| Self::apply_event(&tx, event))
            .collect::<Result<Vec<_>>>()?;
        let applied = began.elapsed();
        let committing = std::time::Instant::now();
        tx.commit()?;
        if std::env::var_os("STUDIO_TRACE_TIMINGS").is_some() && began.elapsed().as_millis() >= 50 {
            eprintln!(
                "sqlite batch: rows={} apply_ms={} commit_ms={}",
                observed.iter().map(Vec::len).sum::<usize>(),
                applied.as_millis(),
                committing.elapsed().as_millis()
            );
        }
        Ok(observed)
    }
    fn apply_event(tx: &Connection, event: &Envelope<Event>) -> Result<Vec<SavedRow>> {
        if event.version != VERSION {
            return Err("Unsupported protocol".into());
        }
        let saved = Self::find(tx, event.scan)?.ok_or("Unknown scan")?;
        if saved.attempt != event.attempt {
            return Err("Stale attempt".into());
        }
        let seq: String = tx.query_row(
            "SELECT sequence FROM scans WHERE id=?1",
            [event.scan.as_slice()],
            |r| r.get(0),
        )?;
        let previous = decimal(&seq)?;
        if event.sequence <= previous {
            return Ok(Vec::new());
        }
        if event.sequence != previous + 1 {
            return Err("Missing event sequence".into());
        }
        let mut observed = Vec::new();
        match &event.payload {
            Event::PreparingNetwork => {
                if saved.job.backend != Backend::MacNetwork
                    || !matches!(saved.status, Status::Starting | Status::Preparing)
                {
                    return Err("Unexpected network preparation".into());
                }
                tx.execute(
                    "UPDATE scans SET status='\"Preparing\"' WHERE id=?1",
                    [event.scan.as_slice()],
                )?;
            }
            Event::NetworkPrepared { bytes } => {
                if saved.job.backend != Backend::MacNetwork
                    || !matches!(saved.status, Status::Starting | Status::Preparing)
                {
                    return Err("Unexpected network report".into());
                }
                let report = NetworkReport::decode(bytes)?;
                report.validate_for(&saved.job)?;
                if saved
                    .network_report
                    .as_ref()
                    .is_some_and(|old| old != bytes)
                {
                    return Err("Frozen network report cannot change within a scan".into());
                }
                tx.execute(
                    "UPDATE scans SET network_report=?2 WHERE id=?1",
                    params![event.scan.as_slice(), bytes],
                )?;
            }
            Event::Results(rows) => {
                // One prepared write inside one transaction. RETURNING retains
                // the original discovery date on conflict, including legacy NULL.
                // Avoid a separate autocommit read/lock cycle for every UI row.
                let now = studio_inspection::now();
                let mut insert = tx.prepare("INSERT INTO results(scan,ip,port,open,discovered_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(scan,ip,port) DO UPDATE SET open=excluded.open RETURNING discovered_at")?;
                for row in rows {
                    let discovered_at = insert.query_row(
                        params![event.scan.as_slice(), row.ip, row.port, row.open, now],
                        |r| r.get(0),
                    )?;
                    observed.push(SavedRow {
                        row: row.clone(),
                        discovered_at,
                    });
                }
            }
            Event::Checkpoint { bytes, next_index } => {
                validate_checkpoint(&saved.job, event.scan, event.attempt, bytes, next_index)?;
                if saved.job.backend == Backend::MacNetwork {
                    let envelope = NetworkCheckpoint::decode(bytes)?;
                    if saved.network_report.as_deref() != Some(envelope.report.encode()?.as_slice())
                    {
                        return Err(
                            "Checkpoint network report differs from durable scan coverage".into(),
                        );
                    }
                }
                tx.execute(
                    "UPDATE scans SET checkpoint=?2,next_index=?3,status='\"Paused\"' WHERE id=?1",
                    params![event.scan.as_slice(), bytes, next_index],
                )?;
            }
            Event::Started { total } => {
                if saved.job.backend == Backend::MacNetwork {
                    let report = NetworkReport::decode(
                        saved
                            .network_report
                            .as_deref()
                            .ok_or("Network report must be committed before TCP starts")?,
                    )?;
                    if saved.job.prepare_network(&report)?.range() != decimal(total)? {
                        return Err("Started total differs from frozen network plan".into());
                    }
                }
                tx.execute(
                    "UPDATE scans SET status='\"Scanning\"',checkpoint=NULL,next_index=NULL WHERE id=?1",
                    [event.scan.as_slice()],
                )?;
            }
            Event::Finished { status, detail } => {
                if *status == Status::Paused && saved.checkpoint.is_none() {
                    return Err("Paused without durable checkpoint".into());
                }
                let status = if *status == Status::Failed
                    && matches!(saved.status, Status::Starting | Status::Preparing)
                    && saved.checkpoint.is_some()
                {
                    &Status::Paused
                } else {
                    status
                };
                tx.execute(
                    "UPDATE scans SET status=?2,detail=?3 WHERE id=?1",
                    params![
                        event.scan.as_slice(),
                        serde_json::to_string(status)?,
                        detail
                    ],
                )?;
            }
            _ => {}
        }
        tx.execute(
            "UPDATE scans SET sequence=?2,updated=unixepoch() WHERE id=?1",
            params![event.scan.as_slice(), event.sequence.to_string()],
        )?;
        Ok(observed)
    }
    pub fn interrupt(&mut self, scan: Id, detail: &str) -> Result<()> {
        self.db.execute("UPDATE scans SET status=CASE WHEN status IN ('\"Starting\"','\"Preparing\"') AND checkpoint IS NOT NULL THEN '\"Paused\"' ELSE '\"Interrupted\"' END,detail=?2 WHERE id=?1 AND status != '\"Paused\"'",params![scan.as_slice(),detail])?;
        Ok(())
    }
}
