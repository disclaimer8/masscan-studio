//! Durable scan history owned only by the unprivileged application.
#![forbid(unsafe_code)]
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
    pub detail: String,
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
        let db = Connection::open(dir.join("history.sqlite3"))?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > 1 {
            return Err("History was created by a newer Studio version".into());
        }
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS scans (id BLOB PRIMARY KEY, attempt BLOB NOT NULL, job TEXT NOT NULL, status TEXT NOT NULL, sequence TEXT NOT NULL DEFAULT '0', checkpoint BLOB, next_index TEXT, detail TEXT NOT NULL DEFAULT '', updated INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS results (scan BLOB NOT NULL REFERENCES scans(id), ip TEXT NOT NULL, port INTEGER NOT NULL, open INTEGER NOT NULL, PRIMARY KEY(scan,ip,port));
            PRAGMA user_version=1;")?;
        db.execute("UPDATE scans SET status='\"Interrupted\"', detail='Previous attempt ended before a terminal state was saved' WHERE status IN ('\"Starting\"','\"Scanning\"','\"Saving\"')",[])?;
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
        job.prepare()?;
        let tx = self.db.transaction()?;
        if resume {
            let old = Self::find(&tx, scan)?.ok_or("No saved scan")?;
            if old.status != Status::Paused || old.job != *job || old.attempt == attempt {
                return Err("This scan cannot be resumed".into());
            }
            validate_checkpoint(
                job,
                scan,
                old.attempt,
                old.checkpoint.as_deref().ok_or("No checkpoint")?,
                old.next_index.as_deref().ok_or("No checkpoint index")?,
            )?;
            tx.execute("UPDATE scans SET attempt=?2,status='\"Starting\"',sequence='0',checkpoint=NULL,next_index=NULL,detail='',updated=unixepoch() WHERE id=?1",params![scan.as_slice(),attempt.as_slice()])?;
        } else {
            tx.execute("INSERT INTO scans(id,attempt,job,status,updated) VALUES(?1,?2,?3,'\"Starting\"',unixepoch())",params![scan.as_slice(),attempt.as_slice(),serde_json::to_string(job)?])?;
        }
        tx.commit()?;
        Ok(())
    }
    fn find(db: &Connection, scan: Id) -> Result<Option<SavedScan>> {
        let raw: Option<StoredFields> = db
            .query_row(
                "SELECT attempt,job,status,checkpoint,next_index,detail FROM scans WHERE id=?1",
                [scan.as_slice()],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .optional()?;
        raw.map(|(attempt, job, status, checkpoint, next_index, detail)| {
            Ok(SavedScan {
                scan,
                attempt: attempt.try_into().map_err(|_| "Invalid attempt id")?,
                job: serde_json::from_str(&job)?,
                status: serde_json::from_str(&status)?,
                checkpoint,
                next_index,
                detail,
            })
        })
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
    /// Full transaction before the controller may ACK a checkpoint or display results.
    pub fn apply(&mut self, event: &Envelope<Event>) -> Result<()> {
        if event.version != VERSION {
            return Err("Unsupported protocol".into());
        }
        let tx = self.db.transaction()?;
        let saved = Self::find(&tx, event.scan)?.ok_or("Unknown scan")?;
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
            return Ok(());
        }
        if event.sequence != previous + 1 {
            return Err("Missing event sequence".into());
        }
        match &event.payload {
            Event::Results(rows) => {
                for row in rows {
                    tx.execute("INSERT INTO results(scan,ip,port,open) VALUES(?1,?2,?3,?4) ON CONFLICT(scan,ip,port) DO UPDATE SET open=excluded.open",params![event.scan.as_slice(),row.ip,row.port,row.open])?;
                }
            }
            Event::Checkpoint { bytes, next_index } => {
                validate_checkpoint(&saved.job, event.scan, event.attempt, bytes, next_index)?;
                tx.execute(
                    "UPDATE scans SET checkpoint=?2,next_index=?3,status='\"Paused\"' WHERE id=?1",
                    params![event.scan.as_slice(), bytes, next_index],
                )?;
            }
            Event::Started { .. } => {
                tx.execute(
                    "UPDATE scans SET status='\"Scanning\"' WHERE id=?1",
                    [event.scan.as_slice()],
                )?;
            }
            Event::Finished { status, detail } => {
                if *status == Status::Paused && saved.checkpoint.is_none() {
                    return Err("Paused without durable checkpoint".into());
                }
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
        tx.commit()?;
        Ok(())
    }
    pub fn interrupt(&mut self, scan: Id, detail: &str) -> Result<()> {
        self.db.execute("UPDATE scans SET status='\"Interrupted\"',detail=?2 WHERE id=?1 AND status != '\"Paused\"'",params![scan.as_slice(),detail])?;
        Ok(())
    }
}
