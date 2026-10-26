//! Versioned Studio IPC and immutable scan settings.
#![forbid(unsafe_code)]
use rmasscan_core::{
    config::{Operation, ScanConfig, validate},
    massip::MassIp,
    packet::LinkType,
    probe::{AdapterBinding, ReadyPlan},
    targets::{add_target_string, parse_ports},
};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const VERSION: u32 = 2;
pub const ENGINE_VERSION: u32 = rmasscan_engine::ENGINE_ALGORITHM_VERSION;
/// Release gate, not a user-configurable escape hatch.
pub const RAW_SCANNING_ENABLED: bool = false;
pub const MAX_FRAME: usize = 131_072;
pub const MAX_QUEUE: usize = 4 * 1024 * 1024;
pub type Id = [u8; 16];
pub fn new_id() -> Result<Id, String> {
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|e| e.to_string())?;
    Ok(id)
}
pub fn id_text(id: Id) -> String {
    id.iter().map(|v| format!("{v:02x}")).collect()
}
pub fn decimal(s: &str) -> Result<u64, String> {
    let n = s
        .parse::<u64>()
        .map_err(|_| "Invalid unsigned decimal".to_string())?;
    if n.to_string() != s {
        return Err("Noncanonical unsigned decimal".into());
    }
    Ok(n)
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Backend {
    Simulation,
    MacFeth,
    SwiftImport,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub targets: String,
    pub ports: String,
    pub exclusions: String,
    pub seed: String,
    pub rate: u32,
    pub backend: Backend,
}
impl Job {
    pub fn example(backend: Backend) -> Self {
        Self {
            targets: "198.18.0.2".into(),
            ports: "8000-8007".into(),
            exclusions: String::new(),
            seed: "42".into(),
            rate: 100,
            backend,
        }
    }
    pub fn prepare(&self) -> Result<ReadyPlan, String> {
        if self.backend == Backend::SwiftImport {
            return Err(
                "Imported Swift history is read-only; its checkpoint cannot run in rmasscan".into(),
            );
        }
        let seed = decimal(&self.seed)?;
        if seed == 0 || !(1..=10_000_000).contains(&self.rate) {
            return Err("Seed must be nonzero; rate must be 1–10000000".into());
        }
        for text in [&self.targets, &self.exclusions, &self.ports] {
            if text.len() >= 65536 {
                return Err("Input exceeds 65535 UTF-8 bytes".into());
            }
        }
        let targets: Vec<_> = self
            .targets
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|s| !s.is_empty())
            .collect();
        if targets.is_empty() || targets.len() > 4096 {
            return Err("Enter 1–4096 IPv4 targets".into());
        }
        if self.backend == Backend::MacFeth
            && (targets != ["198.18.0.2"] || !self.exclusions.trim().is_empty())
        {
            return Err("This build only scans the isolated Mac feth peer 198.18.0.2".into());
        }
        let mut mass = MassIp::new();
        let mut excludes = MassIp::new();
        for t in targets {
            add_target_string(mass.ipv4_mut(), t).map_err(|e| e.to_string())?;
        }
        for t in self
            .exclusions
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|s| !s.is_empty())
        {
            add_target_string(excludes.ipv4_mut(), t).map_err(|e| e.to_string())?;
        }
        // The UI accepts TCP ports only; no protocol prefixes, zero, or wrapped values.
        if self.ports.is_empty()
            || !self
                .ports
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b',' || b == b'-')
        {
            return Err("TCP ports must be numbers or ranges".into());
        }
        for part in self.ports.split(',') {
            for end in part.split('-') {
                let n = end.parse::<u16>().map_err(|_| "Port outside 1–65535")?;
                if n == 0 {
                    return Err("Port zero is not supported".into());
                }
            }
        }
        parse_ports(mass.ports_mut(), &self.ports).map_err(|e| e.to_string())?;
        let eff = validate(
            &ScanConfig {
                targets: mass,
                excludes,
                seed,
                max_rate: f64::from(self.rate),
                wait_secs: 3,
                ..Default::default()
            },
            Operation::Scan,
        )
        .map_err(|e| e.to_string())?;
        ReadyPlan::new(
            eff,
            AdapterBinding {
                interface_id: if self.backend == Backend::Simulation {
                    "simulation"
                } else {
                    "feth4201"
                }
                .into(),
                link_type: LinkType::Ethernet,
                source_ipv4: u32::from_be_bytes([198, 18, 0, 1]),
                source_mac: [2, 172, 0, 0, 0, 1],
                next_hop_mac: [2, 172, 0, 0, 0, 2],
                source_ports: (40000, 40000),
            },
        )
        .map_err(|e| e.to_string())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Command {
    Hello,
    CheckNetwork,
    Start(Job),
    Resume { job: Job, checkpoint: Vec<u8> },
    Pause,
    Stop,
    AckCheckpoint { through: u64 },
    CloseSession,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Status {
    Ready,
    Starting,
    Scanning,
    Saving,
    Paused,
    Stopped,
    Completed,
    Failed,
    Interrupted,
}
impl Status {
    pub fn terminal(&self) -> bool {
        matches!(
            self,
            Self::Paused | Self::Stopped | Self::Completed | Self::Failed | Self::Interrupted
        )
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Row {
    pub ip: String,
    pub port: u16,
    pub open: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Event {
    Hello { engine: u32 },
    NetworkChecked { ready: bool, detail: String },
    Started { total: String },
    Results(Vec<Row>),
    Progress { sent: String, received: String },
    Checkpoint { bytes: Vec<u8>, next_index: String },
    Finished { status: Status, detail: String },
    CheckpointAcked,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T> {
    pub version: u32,
    pub session: Id,
    pub scan: Id,
    pub attempt: Id,
    pub sequence: u64,
    pub payload: T,
}
impl<T> Envelope<T> {
    pub fn new(session: Id, scan: Id, attempt: Id, sequence: u64, payload: T) -> Self {
        Self {
            version: VERSION,
            session,
            scan,
            attempt,
            sequence,
            payload,
        }
    }
}
pub struct ReceiveOrder {
    session: Id,
    scan: Id,
    attempt: Id,
    next: u64,
}
impl ReceiveOrder {
    pub fn new(session: Id, scan: Id, attempt: Id) -> Self {
        Self {
            session,
            scan,
            attempt,
            next: 1,
        }
    }
    pub fn accept<T>(&mut self, e: &Envelope<T>) -> Result<(), String> {
        if e.version != VERSION
            || e.session != self.session
            || e.scan != self.scan
            || e.attempt != self.attempt
            || e.sequence != self.next
        {
            return Err("IPC identity/version/sequence mismatch".into());
        }
        self.next = self.next.checked_add(1).ok_or("Sequence exhausted")?;
        Ok(())
    }
}
pub fn read_frame<T: serde::de::DeserializeOwned>(
    reader: &mut impl Read,
) -> io::Result<Envelope<T>> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let n = u32::from_be_bytes(header) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPC frame too large or empty",
        ));
    }
    let mut bytes = vec![0; n];
    reader.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
pub fn write_frame<T: Serialize>(writer: &mut impl Write, e: &Envelope<T>) -> io::Result<()> {
    let bytes = serde_json::to_vec(e)?;
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPC frame too large",
        ));
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}
pub fn validate_checkpoint(
    job: &Job,
    scan: Id,
    attempt: Id,
    bytes: &[u8],
    index: &str,
) -> Result<(), String> {
    let cp = rmasscan_engine::Checkpoint::from_bytes(bytes).map_err(|e| e.to_string())?;
    let plan = job.prepare()?;
    if cp.engine_version != rmasscan_engine::ENGINE_ALGORITHM_VERSION
        || cp.scan_id != scan
        || cp.attempt_id != attempt
        || cp.job_digest != rmasscan_engine::job_digest(&plan)
        || cp.next_index != decimal(index)?
        || cp.next_index >= plan.range()
    {
        return Err("Checkpoint does not match the saved job/attempt".into());
    }
    Ok(())
}

/// Origin of a previously persisted checkpoint; a failed resume attempt does
/// not change the attempt that originally produced these bytes.
pub fn checkpoint_origin(bytes: &[u8]) -> Result<Id, String> {
    rmasscan_engine::Checkpoint::from_bytes(bytes)
        .map(|cp| cp.attempt_id)
        .map_err(|e| e.to_string())
}
