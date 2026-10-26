//! Read-only, bounded decoding of the archived Swift Codable format.
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata},
    io::Read,
    path::Path,
};
use studio_inspection::{CheckState, HostInfo, Inspection, LegacyEvidence, Service};
use studio_protocol::{Backend, Id, Job, Row, Status};
type Result<T> = std::result::Result<T, String>;
const SESSIONS_LIMIT: usize = 32 * 1024 * 1024;
const PROFILES_LIMIT: usize = 4 * 1024 * 1024;
type Extra = BTreeMap<String, Value>;

#[derive(Debug)]
pub struct Archive {
    pub sessions: Vec<Session>,
    pub profiles: Vec<Profile>,
    pub warnings: Vec<String>,
}
#[derive(Debug)]
pub struct ImportedRow {
    pub row: Row,
    pub discovered_at: String,
}
#[derive(Debug)]
pub struct Session {
    pub id: Id,
    pub name: String,
    pub created_at: String,
    pub job: Job,
    pub status: Status,
    pub original_status: String,
    pub log: String,
    pub percent: f64,
    pub resume_index: Option<String>,
    pub interface: String,
    pub rows: Vec<ImportedRow>,
    pub hosts: Vec<HostInfo>,
    pub duplicates: usize,
    pub json: String,
    pub fingerprint: String,
}
#[derive(Debug, Clone)]
pub struct Profile {
    pub id: Id,
    pub name: String,
    pub job: Job,
    pub interface: String,
    pub resume_index: Option<String>,
    pub json: String,
    pub fingerprint: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    targets: String,
    ports: String,
    exclusions: String,
    interface: String,
    rate: u32,
    seed: u64,
    resume_index: Option<u64>,
    resolve_hostnames: Option<bool>,
    #[serde(flatten)]
    extra: Extra,
}
impl Config {
    fn job(&self) -> Result<Job> {
        if !self.interface.is_empty()
            && (self.interface.len() > 32
                || !self.interface.as_bytes()[0].is_ascii_alphabetic()
                || !self
                    .interface
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)))
        {
            return Err("Invalid legacy interface".into());
        }
        let mut job = Job {
            targets: self.targets.clone(),
            ports: self
                .ports
                .split(|c: char| c.is_whitespace() || c == ',')
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join(","),
            exclusions: self.exclusions.clone(),
            rate: self.rate,
            seed: self.seed.max(1).to_string(),
            backend: Backend::Simulation,
        };
        // Validate input syntax independently of the old interface/scan order.
        job.prepare()?;
        job.seed = self.seed.to_string(); // Swift also allowed an explicit zero seed.
        job.backend = Backend::SwiftImport;
        Ok(job)
    }
}
#[derive(Deserialize)]
struct SwiftSession {
    id: String,
    name: String,
    date: f64,
    config: Config,
    status: String,
    results: Vec<SwiftRow>,
    log: String,
    percent: f64,
    #[serde(flatten)]
    extra: Extra,
}
#[derive(Deserialize)]
struct SwiftProfile {
    id: String,
    name: String,
    config: Config,
    #[serde(flatten)]
    extra: Extra,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SwiftRow {
    ip: String,
    port: u16,
    proto: String,
    discovered_at: f64,
    hostname: Option<String>,
    hostname_status: Option<String>,
    device_hint: Option<String>,
    device_evidence: Option<String>,
    inspection: Option<SwiftInspection>,
    #[serde(flatten)]
    extra: Extra,
}
#[derive(Deserialize)]
struct SwiftInspection {
    ip: String,
    date: f64,
    ports: Vec<u16>,
    services: Vec<Value>,
    #[serde(flatten)]
    extra: Extra,
}
fn uuid(s: &str) -> Result<Id> {
    if s.len() != 36 || ![8, 13, 18, 23].into_iter().all(|i| s.as_bytes()[i] == b'-') {
        return Err("Invalid UUID".into());
    }
    let digits: Vec<_> = s
        .bytes()
        .enumerate()
        .filter_map(|(i, b)| (![8, 13, 18, 23].contains(&i)).then_some(b))
        .collect();
    let mut id = [0; 16];
    for (out, p) in id.iter_mut().zip(digits.as_chunks::<2>().0) {
        let hi = (p[0] as char).to_digit(16).ok_or("Invalid UUID")?;
        let lo = (p[1] as char).to_digit(16).ok_or("Invalid UUID")?;
        *out = (hi * 16 + lo) as u8;
    }
    Ok(id)
}
pub fn swift_date(value: f64) -> Result<String> {
    if !value.is_finite() || !(-63_113_904_000.0..=252_423_993_599.0).contains(&value) {
        return Err("Swift date is outside supported calendar range".into());
    }
    // Split before adding the epoch offset so the fractional part is not lost.
    let whole = value.floor();
    let nanos = ((value - whole) * 1_000_000_000.0).round() as u32;
    let seconds = whole as i64 + 978_307_200 + i64::from(nanos == 1_000_000_000);
    chrono::DateTime::from_timestamp(seconds, nanos % 1_000_000_000)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
        .ok_or("Invalid Swift date".into())
}
fn note(notes: &mut Vec<String>, message: String) {
    if notes.len() < 100 {
        notes.push(message.chars().take(512).collect());
    } else if notes.len() == 100 {
        notes
            .push("Additional import warnings omitted; full original records are archived.".into());
    }
}
fn unknown(notes: &mut Vec<String>, label: &str, fields: &Extra) {
    for key in fields.keys() {
        note(
            notes,
            format!("{label}: unknown field {key} retained in archive"),
        );
    }
}
fn limited(s: &str, size: usize, what: &str) -> Result<()> {
    if s.len() > size {
        Err(format!("{what} exceeds {size} bytes"))
    } else {
        Ok(())
    }
}
fn original(value: &Value) -> Result<(String, String)> {
    let json = serde_json::to_string(value).map_err(|e| e.to_string())?;
    let mut canonical = value.clone();
    if let Some(s) = canonical
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
    {
        canonical["id"] = Value::String(s);
    }
    let fingerprint = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&canonical).map_err(|e| e.to_string())?)
    );
    Ok((json, fingerprint))
}
fn inspection(source: SwiftInspection, ip: &str, notes: &mut Vec<String>) -> Result<Inspection> {
    unknown(notes, "inspection", &source.extra);
    if source.ip != ip
        || source.ports.len() > 64
        || source.ports.contains(&0)
        || source.ports.iter().collect::<BTreeSet<_>>().len() != source.ports.len()
    {
        return Err("Invalid inspection host/ports".into());
    }
    let mut services = Vec::new();
    let mut seen = BTreeSet::new();
    for mut raw in source.services {
        let obj = raw.as_object_mut().ok_or("Service must be an object")?;
        for (old, new) in [
            ("extraInfo", "extra_info"),
            ("deviceType", "device_type"),
            ("osType", "os_type"),
            ("reportedHostname", "reported_hostname"),
        ] {
            if let Some(v) = obj.remove(old) {
                obj.insert(new.into(), v);
            }
        }
        let mut merged = serde_json::to_value(Service::default()).map_err(|e| e.to_string())?;
        for (key, value) in obj {
            if merged.get(key).is_some() {
                merged[key] = value.clone();
            } else {
                note(
                    notes,
                    format!("inspection service: unknown {key} retained in archive"),
                );
            }
        }
        let s: Service = serde_json::from_value(merged).map_err(|e| e.to_string())?;
        if !source.ports.contains(&s.port) || !seen.insert(s.port) || s.cpes.len() > 16 {
            return Err("Invalid/duplicate inspection service port".into());
        }
        for text in [
            &s.state,
            &s.name,
            &s.product,
            &s.version,
            &s.extra_info,
            &s.tunnel,
            &s.device_type,
            &s.os_type,
            &s.reported_hostname,
            &s.method,
            &s.confidence,
        ] {
            limited(text, 4096, "Service field")?;
        }
        for cpe in &s.cpes {
            limited(cpe, 4096, "CPE")?;
        }
        services.push(s);
    }
    Ok(Inspection {
        ip: ip.into(),
        ports: source.ports,
        checked_at: swift_date(source.date)?,
        services,
    })
}
fn session(value: Value, notes: &mut Vec<String>) -> Result<Session> {
    let (json, fingerprint) = original(&value)?;
    let s: SwiftSession = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    let id = uuid(&s.id)?;
    limited(&s.name, 1024, "Session name")?;
    limited(&s.log, 1024 * 1024, "Session log")?;
    if !s.percent.is_finite() || !(0.0..=100.0).contains(&s.percent) {
        return Err("Invalid progress percentage".into());
    }
    unknown(notes, "session", &s.extra);
    unknown(notes, "configuration", &s.config.extra);
    let _ = s.config.resolve_hostnames; // Archived exactly; importing never starts DNS.
    let status = match s.status.as_str() {
        "Starting" | "Scanning" | "Authorizing" | "Stopping" | "Interrupted" => Status::Interrupted,
        "Ready" => Status::Ready,
        "Completed" => Status::Completed,
        "Paused" => Status::Paused,
        "Stopped" => Status::Stopped,
        "Failed" => Status::Failed,
        _ => return Err(format!("Unknown session status {}", s.status)),
    };
    let mut rows = Vec::new();
    let mut hosts: BTreeMap<String, HostInfo> = BTreeMap::new();
    let mut endpoints = BTreeSet::new();
    let mut duplicates = 0;
    for row in s.results {
        unknown(notes, "result", &row.extra);
        let ip = row
            .ip
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| "Invalid result IPv4")?
            .to_string();
        if row.port == 0 || row.proto != "tcp" {
            return Err("Only IPv4/TCP result ports 1–65535 are supported".into());
        }
        let discovered_at = swift_date(row.discovered_at)?;
        let dns_state = match row.hostname_status.as_deref() {
            None | Some("pending" | "not-checked") => CheckState::NotChecked,
            Some("resolved") => CheckState::Complete,
            Some("not-found") => CheckState::NotFound,
            Some(other) => return Err(format!("Unknown hostnameStatus {other}")),
        };
        let hostname = row.hostname;
        if let Some(h) = &hostname {
            limited(h, 4096, "Historical hostname")?;
            // Swift's PTR decoder accepted printable labels such as printer_office.
            // Retain historical evidence; URL creation still validates independently.
            if studio_inspection::valid_hostname(h).is_none() {
                note(
                    notes,
                    format!(
                        "{ip}: historical hostname retained; it does not meet current hostname URL rules"
                    ),
                );
            }
        }
        let report = row
            .inspection
            .map(|s| inspection(s, &ip, notes))
            .transpose()?;
        let hint = row.device_hint.unwrap_or_default();
        let evidence = row.device_evidence.unwrap_or_default();
        limited(&hint, 4096, "Device hint")?;
        limited(&evidence, 16384, "Device evidence")?;
        // Validate even duplicates; original JSON retains every source entry.
        if !endpoints.insert((ip.clone(), row.port)) {
            duplicates += 1;
            continue;
        }
        let host = hosts
            .entry(ip.clone())
            .or_insert_with(|| HostInfo::new(ip.clone()));
        if host.hostname.is_some() && host.hostname != hostname {
            note(
                notes,
                format!(
                    "{ip}: differing historical hostnames; first retained in view, all retained in archive"
                ),
            );
        } else if host.hostname.is_none() {
            host.hostname = hostname;
            host.dns_state = dns_state;
        }
        if let Some(report) = report
            && host.inspection.as_ref().is_none_or(|old| {
                chrono::DateTime::parse_from_rfc3339(&old.checked_at).unwrap()
                    < chrono::DateTime::parse_from_rfc3339(&report.checked_at).unwrap()
            })
        {
            host.inspection = Some(report);
            host.nmap_state = CheckState::Complete;
        }
        if !hint.is_empty() || !evidence.is_empty() {
            host.legacy.insert(
                row.port,
                LegacyEvidence {
                    device_hint: hint,
                    evidence,
                },
            );
        }
        rows.push(ImportedRow {
            row: Row {
                ip,
                port: row.port,
                open: true,
            },
            discovered_at,
        });
    }
    if duplicates > 0 {
        note(
            notes,
            format!(
                "{}: {duplicates} duplicate endpoints omitted from view; originals archived",
                s.name
            ),
        );
    }
    Ok(Session {
        id,
        name: s.name,
        created_at: swift_date(s.date)?,
        job: s.config.job()?,
        status,
        original_status: s.status,
        log: s.log,
        percent: s.percent,
        resume_index: s.config.resume_index.map(|n| n.to_string()),
        interface: s.config.interface,
        rows,
        hosts: hosts.into_values().collect(),
        duplicates,
        json,
        fingerprint,
    })
}
pub(super) fn profile(value: Value, notes: &mut Vec<String>) -> Result<Profile> {
    let (json, fingerprint) = original(&value)?;
    let p: SwiftProfile = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    limited(&p.name, 1024, "Profile name")?;
    unknown(notes, "profile", &p.extra);
    unknown(notes, "configuration", &p.config.extra);
    Ok(Profile {
        id: uuid(&p.id)?,
        name: p.name,
        job: p.config.job()?,
        interface: p.config.interface,
        resume_index: p.config.resume_index.map(|n| n.to_string()),
        json,
        fingerprint,
    })
}
pub fn decode(sessions: &[u8], profiles: &[u8]) -> Result<Archive> {
    if sessions.len() > SESSIONS_LIMIT || profiles.len() > PROFILES_LIMIT {
        return Err("Swift source exceeds import size limit".into());
    }
    let sessions: Vec<Value> =
        serde_json::from_slice(sessions).map_err(|e| format!("sessions.json: {e}"))?;
    let profiles: Vec<Value> =
        serde_json::from_slice(profiles).map_err(|e| format!("profiles.json: {e}"))?;
    if sessions.len() + profiles.len() > 10_000 {
        return Err("Import exceeds 10000 records".into());
    }
    let total: usize = sessions
        .iter()
        .filter_map(|s| s.get("results").and_then(Value::as_array))
        .map(Vec::len)
        .sum();
    if total > 100_000 {
        return Err("Import exceeds 100000 result rows".into());
    }
    let mut warnings = Vec::new();
    let mut seen = BTreeSet::new();
    let mut decoded = Vec::new();
    for (i, v) in sessions.into_iter().enumerate() {
        let s = session(v, &mut warnings).map_err(|e| format!("sessions[{i}]: {e}"))?;
        if !seen.insert(s.id) {
            return Err(format!("sessions[{i}]: duplicate UUID"));
        }
        decoded.push(s);
    }
    seen.clear();
    let mut saved_profiles = Vec::new();
    for (i, v) in profiles.into_iter().enumerate() {
        let p = profile(v, &mut warnings).map_err(|e| format!("profiles[{i}]: {e}"))?;
        if !seen.insert(p.id) {
            return Err(format!("profiles[{i}]: duplicate UUID"));
        }
        saved_profiles.push(p);
    }
    Ok(Archive {
        sessions: decoded,
        profiles: saved_profiles,
        warnings,
    })
}
fn same(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if a.dev() != b.dev() || a.ino() != b.ino() {
            return false;
        }
    }
    a.is_file() && b.is_file() && a.len() == b.len() && a.modified().ok() == b.modified().ok()
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !before.is_file() || before.len() > limit as u64 {
        return Err("Import source must be a bounded regular file, not a symlink".into());
    }
    let file = File::open(path).map_err(|e| e.to_string())?;
    if !same(&before, &file.metadata().map_err(|e| e.to_string())?) {
        return Err("Import source changed while opening".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let after = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if bytes.len() > limit || bytes.len() != before.len() as usize || !same(&before, &after) {
        return Err("Import source changed while reading; close Swift and retry".into());
    }
    Ok(bytes)
}
pub fn read_directory(path: &Path) -> Result<Archive> {
    if !fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .is_dir()
    {
        return Err("Select a real Swift history directory".into());
    }
    let s = read(&path.join("sessions.json"), SESSIONS_LIMIT)?;
    let p = read(&path.join("profiles.json"), PROFILES_LIMIT)?;
    let archive = decode(&s, &p)?;
    if s != read(&path.join("sessions.json"), SESSIONS_LIMIT)?
        || p != read(&path.join("profiles.json"), PROFILES_LIMIT)?
    {
        return Err("Swift files changed during validation; close Swift and retry".into());
    }
    Ok(archive)
}
