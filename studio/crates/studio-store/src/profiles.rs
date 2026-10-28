use super::{Result, Store};
use rusqlite::{OptionalExtension, params};
use studio_protocol::{Id, Job, new_id};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedProfile {
    pub id: Id,
    pub name: String,
    pub job: Job,
}
impl Store {
    pub fn profiles(&self) -> Result<Vec<SavedProfile>> {
        let mut statement = self
            .db
            .prepare("SELECT id,name,job FROM profiles ORDER BY name_key,id")?;
        let values = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        values
            .into_iter()
            .map(|(id, name, job)| {
                Ok(SavedProfile {
                    id: id.try_into().map_err(|_| "Invalid profile id")?,
                    name,
                    job: serde_json::from_str(&job)?,
                })
            })
            .collect()
    }
    pub fn save_profile(&mut self, id: Option<Id>, name: &str, job: &Job) -> Result<SavedProfile> {
        job.validate()?;
        let name = name.trim();
        if name.is_empty()
            || name.chars().count() > 128
            || name.len() > 512
            || name.chars().any(char::is_control)
        {
            return Err(
                "Profile name must contain 1–128 characters without control characters".into(),
            );
        }
        let key = name.to_lowercase();
        let tx = self.db.transaction()?;
        let count: i64 = tx.query_row("SELECT count(*) FROM profiles", [], |r| r.get(0))?;
        if id.is_none() && count >= 100 {
            return Err("Keep at most 100 profiles; update or delete an existing profile".into());
        }
        if let Some(id) = id {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM profiles WHERE id=?1)",
                [id.as_slice()],
                |r| r.get(0),
            )?;
            if !exists {
                return Err("This profile no longer exists".into());
            }
        }
        let id = match id {
            Some(id) => id,
            None => new_id()?,
        };
        let conflict: Option<Vec<u8>> = tx
            .query_row("SELECT id FROM profiles WHERE name_key=?1", [&key], |r| {
                r.get(0)
            })
            .optional()?;
        if conflict.is_some_and(|other| other != id) {
            return Err("A profile with this name already exists".into());
        }
        tx.execute("INSERT INTO profiles(id,name,name_key,job) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET name=excluded.name,name_key=excluded.name_key,job=excluded.job",params![id.as_slice(),name,key,serde_json::to_string(job)?])?;
        tx.commit()?;
        Ok(SavedProfile {
            id,
            name: name.into(),
            job: job.clone(),
        })
    }
    pub fn delete_profile(&mut self, id: Id) -> Result<()> {
        if self
            .db
            .execute("DELETE FROM profiles WHERE id=?1", [id.as_slice()])?
            != 1
        {
            return Err("This profile no longer exists".into());
        }
        Ok(())
    }
}
