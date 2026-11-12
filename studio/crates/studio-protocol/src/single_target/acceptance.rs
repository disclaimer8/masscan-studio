//! GUI evidence is a consistency record, never a grant to send packets.
use super::{Context, Permit, hex};
use crate::{
    Id, NetworkReport, Row, Status,
    acceptance::{Stamp, clocks},
};
use serde::{Deserialize, Serialize};
pub const MAX_GUI_EVIDENCE: usize = 262144;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    pub permit: Permit,
    pub capture_nonce: String,
    pub capture_pid: u32,
    pub capture_created: u64,
}
impl Ticket {
    pub fn validate(&self, context: &Context<'_>) -> Result<(), String> {
        self.permit.validate(context)?;
        if !hex(&self.capture_nonce, 32)
            || self.capture_pid == 0
            || self.capture_pid > i32::MAX as u32
            || self.capture_created < self.permit.created
            || self.capture_created > context.now
            || !self
                .capture_created
                .checked_add(40)
                .is_some_and(|end| context.now < end)
        {
            return Err("GUI capture ticket invalid or expired".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub ticket: Ticket,
    pub driver_pid: u32,
    pub driver_uid: u32,
    pub process_identity: String,
    pub ui_sha256: String,
    pub driver_started: Stamp,
    pub start: Stamp,
    pub terminal: Stamp,
    pub joined: Stamp,
    pub samples: Vec<Stamp>,
    pub scan: Id,
    pub attempt: Id,
    pub status: Status,
    pub report: Vec<u8>,
    pub rows: Vec<Row>,
    pub displayed_rows: usize,
    pub displayed_results: Vec<Row>,
    pub sent: u64,
}
impl Attempt {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_GUI_EVIDENCE {
            return Err("Oversized GUI evidence".into());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), String> {
        let p = &self.ticket.permit;
        let context = Context {
            now: self.start.wall_ns / 1_000_000_000,
            owner_uid: self.driver_uid,
            tooling_sha256: &p.tooling_sha256,
            helper_sha256: &p.helper_sha256,
        };
        self.ticket.validate(&context)?;
        p.admit_report(&NetworkReport::decode(&self.report)?, &context)?;
        if self.status != Status::Completed
            || self.sent != p.ports.len() as u64
            || self.driver_pid == 0
            || self.driver_pid > i32::MAX as u32
            || self.driver_uid != p.owner_uid
            || self.process_identity.is_empty()
            || self.process_identity.len() > 8192
            || !hex(&self.ui_sha256, 64)
            || self.scan == [0; 16]
            || self.attempt == [0; 16]
            || self.displayed_rows != self.rows.len()
            || self.rows.len() > p.ports.len()
        {
            return Err("GUI completion identity, counters or display differs".into());
        }
        clocks(&[
            self.driver_started.clone(),
            self.start.clone(),
            self.terminal.clone(),
            self.joined.clone(),
        ])?;
        clocks(&self.samples)?;
        if !(2..=1000).contains(&self.samples.len())
            || self.samples.first() != Some(&self.driver_started)
            || self.samples.last() != Some(&self.joined)
            || self
                .samples
                .windows(2)
                .any(|p| p[1].mono_ns - p[0].mono_ns > 1_000_000_000)
            || self.joined.mono_ns >= 35_000_000_000
            || self.joined.wall_ns / 1_000_000_000 >= p.expires
        {
            return Err("GUI clock coverage incomplete or expired".into());
        }
        let mut visible = self.displayed_results.clone();
        let mut saved = self.rows.clone();
        visible.sort_by_key(|row| (row.ip.clone(), row.port));
        saved.sort_by_key(|row| (row.ip.clone(), row.port));
        if visible != saved {
            return Err("Visible GUI result projection differs from saved rows".into());
        }
        let mut ports = std::collections::BTreeSet::new();
        for row in &self.rows {
            if row.ip != p.target.to_string()
                || !p.ports.contains(&row.port)
                || !ports.insert(row.port)
            {
                return Err("GUI result outside permit or duplicated".into());
            }
        }
        Ok(())
    }
}
