use super::{Result, Store, legacy};
use rusqlite::{OptionalExtension, params};
use studio_protocol::{Backend, Id, id_text, new_id};

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ImportReport {
    pub imported: usize,
    pub skipped: usize,
    pub conflicts: usize,
    pub results: usize,
    pub duplicates: usize,
    pub warnings: Vec<String>,
}
impl ImportReport {
    pub fn summary(&self) -> String {
        let mut text = format!(
            "Swift import: {} imported, {} unchanged, {} conflicts, {} result rows, {} duplicate endpoints. Originals unchanged. Legacy checkpoints cannot resume in rmasscan.",
            self.imported, self.skipped, self.conflicts, self.results, self.duplicates
        );
        for warning in &self.warnings {
            text.push('\n');
            text.push_str(warning);
        }
        text
    }
}
impl Store {
    pub fn import_swift(&mut self, archive: &legacy::Archive) -> Result<ImportReport> {
        let mut report = ImportReport {
            warnings: archive.warnings.clone(),
            ..Default::default()
        };
        let tx = self.db.transaction()?;
        let active: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM scans WHERE status IN ('\"Starting\"','\"Scanning\"','\"Saving\"'))", [], |r| r.get(0))?;
        if active {
            return Err("Finish the active scan before importing Swift history".into());
        }
        for s in &archive.sessions {
            if s.job.backend != Backend::SwiftImport {
                return Err("Import cannot create executable jobs".into());
            }
            if skip(&tx, "session", s.id, &s.fingerprint, &mut report)? {
                continue;
            }
            let scan = new_id()?;
            let attempt = new_id()?;
            let detail = format!(
                "Imported Swift history · original status {} · progress {}% · interface {} · seed {} · legacy index {}. Read-only archive; the external masscan checkpoint is incompatible with rmasscan. Original log and metadata retained.",
                s.original_status,
                s.percent,
                s.interface,
                s.job.seed,
                s.resume_index.as_deref().unwrap_or("none")
            );
            let timestamp = chrono::DateTime::parse_from_rfc3339(&s.created_at)?.timestamp();
            tx.execute("INSERT INTO scans(id,attempt,job,status,detail,name,created_at,updated) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![scan.as_slice(),attempt.as_slice(),serde_json::to_string(&s.job)?,serde_json::to_string(&s.status)?,detail,s.name,s.created_at,timestamp])?;
            {
                let mut insert = tx.prepare(
                    "INSERT INTO results(scan,ip,port,open,discovered_at) VALUES(?1,?2,?3,?4,?5)",
                )?;
                for r in &s.rows {
                    insert.execute(params![
                        scan.as_slice(),
                        r.row.ip,
                        r.row.port,
                        r.row.open,
                        r.discovered_at
                    ])?;
                }
            }
            for host in &s.hosts {
                tx.execute(
                    "INSERT INTO host_details(scan,ip,data) VALUES(?1,?2,?3)",
                    params![scan.as_slice(), host.ip, serde_json::to_string(host)?],
                )?;
            }
            tx.execute("INSERT INTO legacy_records(origin,kind,source_id,fingerprint,data,scan) VALUES('swift-v0','session',?1,?2,?3,?4)",params![s.id.as_slice(),s.fingerprint,s.json,scan.as_slice()])?;
            report.imported += 1;
            report.results += s.rows.len();
            report.duplicates += s.duplicates;
        }
        for p in &archive.profiles {
            if p.job.backend != Backend::SwiftImport {
                return Err("Import cannot create executable profiles".into());
            }
            if skip(&tx, "profile", p.id, &p.fingerprint, &mut report)? {
                continue;
            }
            tx.execute("INSERT INTO legacy_records(origin,kind,source_id,fingerprint,data) VALUES('swift-v0','profile',?1,?2,?3)",params![p.id.as_slice(),p.fingerprint,p.json])?;
            report.imported += 1;
        }
        tx.execute("INSERT INTO import_reports(id,data) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET data=excluded.data", [serde_json::to_string(&report)?])?;
        tx.commit()?;
        Ok(report)
    }
    pub fn last_import_report(&self) -> Result<Option<ImportReport>> {
        let json: Option<String> = self
            .db
            .query_row("SELECT data FROM import_reports WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        json.map(|s| serde_json::from_str(&s).map_err(Into::into))
            .transpose()
    }
    pub fn profiles(&self) -> Result<Vec<legacy::Profile>> {
        let mut stmt=self.db.prepare("SELECT data FROM legacy_records WHERE origin='swift-v0' AND kind='profile' ORDER BY rowid")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.iter()
            .map(|raw| {
                let mut notes = Vec::new();
                legacy::profile(serde_json::from_str(raw)?, &mut notes).map_err(Into::into)
            })
            .collect()
    }
}
fn skip(
    db: &rusqlite::Connection,
    kind: &str,
    id: Id,
    fingerprint: &str,
    report: &mut ImportReport,
) -> Result<bool> {
    let existing: Option<String>=db.query_row("SELECT fingerprint FROM legacy_records WHERE origin='swift-v0' AND kind=?1 AND source_id=?2",params![kind,id.as_slice()],|r|r.get(0)).optional()?;
    if let Some(old) = existing {
        if old == fingerprint {
            report.skipped += 1;
        } else {
            report.conflicts += 1;
            if report.warnings.len() < 100 {
                report.warnings.push(format!(
                    "Conflict: Swift {kind} {} changed; existing record retained",
                    id_text(id)
                ));
            }
        }
        Ok(true)
    } else {
        Ok(false)
    }
}
