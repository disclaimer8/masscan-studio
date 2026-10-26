use super::{Result, Store};
use rusqlite::{Connection, params};
use studio_protocol::{Id, Status};

fn editable(db: &Connection, scan: Id) -> Result<()> {
    let saved = Store::find(db, scan)?.ok_or("This scan no longer exists")?;
    if matches!(
        saved.status,
        Status::Starting | Status::Scanning | Status::Saving
    ) {
        return Err("An active scan cannot be changed or deleted".into());
    }
    Ok(())
}

impl Store {
    pub fn rename_scan(&mut self, scan: Id, name: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty()
            || name.chars().count() > 128
            || name.len() > 512
            || name.chars().any(char::is_control)
        {
            return Err(
                "Scan name must contain 1–128 characters without control characters".into(),
            );
        }
        let tx = self.db.transaction()?;
        editable(&tx, scan)?;
        // Naming does not reorder history or alter the job/checkpoint identity.
        tx.execute(
            "UPDATE scans SET name=?2 WHERE id=?1",
            params![scan.as_slice(), name],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_scan(&mut self, scan: Id) -> Result<()> {
        let tx = self.db.transaction()?;
        editable(&tx, scan)?;
        tx.execute("DELETE FROM host_details WHERE scan=?1", [scan.as_slice()])?;
        tx.execute("DELETE FROM results WHERE scan=?1", [scan.as_slice()])?;
        // Older databases may retain archive metadata with a foreign key. No
        // parser/import functionality is needed to remove that scan's children.
        let archived: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('legacy_records') WHERE name='scan')",
            [],
            |r| r.get(0),
        )?;
        if archived {
            tx.execute(
                "DELETE FROM legacy_records WHERE scan=?1",
                [scan.as_slice()],
            )?;
        }
        tx.execute("DELETE FROM scans WHERE id=?1", [scan.as_slice()])?;
        tx.commit()?;
        Ok(())
    }
}
