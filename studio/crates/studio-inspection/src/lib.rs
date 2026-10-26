//! Unprivileged host inspection; independent of scanner/runner/UI/storage crates.
#![forbid(unsafe_code)]
pub mod process;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::Ipv4Addr};
pub type Result<T> = std::result::Result<T, String>;
pub const MAX_XML: usize = 2_097_152;
/// Write in the destination directory, then atomically replace the selected file.
/// Failed serialization/writes preserve any existing export. Tempfiles are 0600 on Unix.
pub fn write_export(path: &std::path::Path, rows: &[ExportRow], as_json: bool) -> Result<()> {
    use std::io::Write;
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("Export destination cannot be a symlink".into());
    }
    let bytes = if as_json { json(rows)? } else { csv(rows)? };
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    file.write_all(bytes.as_bytes())
        .map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}
pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
pub fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(1024).collect()
}
pub fn valid_hostname(raw: &str) -> Option<String> {
    let s = raw.strip_suffix('.').unwrap_or(raw);
    if s.is_empty()
        || s.len() > 253
        || !s.split('.').all(|p| {
            !p.is_empty()
                && p.len() <= 63
                && !p.starts_with('-')
                && !p.ends_with('-')
                && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        None
    } else {
        Some(s.to_owned())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub ip: Ipv4Addr,
    pub ports: Vec<u16>,
}
impl Request {
    pub fn new(ip: &str, ports: Vec<u16>) -> Result<Self> {
        let ip = ip.parse::<Ipv4Addr>().map_err(|_| "Select one IPv4 host")?;
        let ports: BTreeSet<_> = ports.into_iter().collect();
        if ports.is_empty() || ports.len() > 64 || ports.contains(&0) {
            return Err("Detailed checks support 1–64 discovered open TCP ports per host".into());
        }
        let ports: Vec<_> = ports.into_iter().filter(|p| *p != 9100).collect();
        if ports.is_empty() {
            return Err("Port 9100 is excluded to avoid sending probes to a raw printer".into());
        }
        Ok(Self { ip, ports })
    }
    pub fn args(&self) -> Vec<String> {
        [
            "--unprivileged",
            "-sT",
            "-sV",
            "--version-light",
            "-Pn",
            "-n",
            "--host-timeout",
            "45s",
            "--max-retries",
            "1",
            "-T3",
            "-p",
        ]
        .into_iter()
        .map(str::to_owned)
        .chain([
            self.ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
            "-oX".into(),
            "-".into(),
            self.ip.to_string(),
        ])
        .collect()
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Service {
    pub port: u16,
    pub state: String,
    pub name: String,
    pub product: String,
    pub version: String,
    pub extra_info: String,
    pub tunnel: String,
    pub device_type: String,
    pub os_type: String,
    pub reported_hostname: String,
    pub method: String,
    pub confidence: String,
    pub cpes: Vec<String>,
}
impl Service {
    pub fn summary(&self) -> String {
        let description = [
            self.name.as_str(),
            self.product.as_str(),
            self.version.as_str(),
            self.extra_info.as_str(),
        ]
        .into_iter()
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>()
        .join(" · ");
        if self.method == "probed" {
            description
        } else {
            format!("{description} (port-table hint)")
        }
    }
    pub fn device_hint(&self) -> Option<String> {
        if self.state != "open" || self.method != "probed" {
            return None;
        }
        if !self.device_type.is_empty() {
            Some(format!("Possible {}", self.device_type))
        } else if !self.os_type.is_empty() {
            Some(format!("Possible {} host", self.os_type))
        } else {
            None
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inspection {
    pub ip: String,
    pub ports: Vec<u16>,
    pub checked_at: String,
    pub services: Vec<Service>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum CheckState {
    #[default]
    NotChecked,
    Pending,
    Complete,
    NotFound,
    Failed,
    Cancelled,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub dns_state: CheckState,
    pub dns_checked_at: Option<String>,
    pub dns_error: String,
    pub inspection: Option<Inspection>,
    pub nmap_state: CheckState,
    pub nmap_error: String,
}
impl HostInfo {
    pub fn new(ip: String) -> Self {
        Self {
            ip,
            ..Default::default()
        }
    }
    pub fn recover(&mut self) {
        if self.dns_state == CheckState::Pending {
            self.dns_state = CheckState::Cancelled;
            self.dns_error = "Studio closed before the lookup completed".into();
        }
        if self.nmap_state == CheckState::Pending {
            self.nmap_state = CheckState::Cancelled;
            self.nmap_error = "Studio closed before inspection completed".into();
        }
    }
    pub fn service(&self, port: u16) -> Option<&Service> {
        self.inspection
            .as_ref()?
            .services
            .iter()
            .find(|s| s.port == port)
    }
    pub fn evidence(&self, port: u16) -> String {
        let mut out = format!(
            "Hostname lookup: {:?}. {}\nService inspection: {:?}. {}",
            self.dns_state, self.dns_error, self.nmap_state, self.nmap_error
        );
        if let Some(at) = &self.dns_checked_at {
            out.push_str(&format!("\nHostname checked: {at}"));
        }
        if let Some(s) = self.service(port) {
            out.push_str(&format!("\nNmap: {}\nState: {} · method: {} · confidence: {}\nReported hostname: {}\nCPE: {}\nDevice/OS hints are estimates from service responses, not verified hardware.",s.summary(),s.state,s.method,s.confidence,s.reported_hostname,s.cpes.join(", ")));
            if let Some(i) = &self.inspection {
                out.push_str(&format!("\nServices checked: {}", i.checked_at));
            }
        }
        out
    }
}
pub fn parse_xml(bytes: &[u8], request: &Request) -> Result<Inspection> {
    if bytes.len() > MAX_XML {
        return Err("Nmap response exceeds 2 MiB".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "Nmap XML must be UTF-8")?;
    if text.to_ascii_uppercase().contains("<!ENTITY") {
        return Err("XML entities are not allowed".into());
    }
    let doc = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            nodes_limit: 50_000,
            ..Default::default()
        },
    )
    .map_err(|e| format!("Invalid Nmap XML: {e}"))?;
    let root = doc.root_element();
    if !root.has_tag_name("nmaprun") {
        return Err("Expected Nmap XML".into());
    }
    let hosts: Vec<_> = root.children().filter(|n| n.has_tag_name("host")).collect();
    if hosts.len() != 1 {
        return Err("Nmap did not return exactly one host".into());
    }
    let host = hosts[0];
    if host.attribute("timedout") == Some("true") {
        return Err("Nmap host check timed out".into());
    }
    let addresses: Vec<_> = host
        .children()
        .filter(|n| n.has_tag_name("address") && n.attribute("addrtype") == Some("ipv4"))
        .collect();
    if addresses.len() != 1
        || addresses[0].attribute("addr") != Some(request.ip.to_string().as_str())
    {
        return Err("Nmap returned a different host".into());
    }
    let finished: Vec<_> = root
        .children()
        .filter(|n| n.has_tag_name("runstats"))
        .flat_map(|n| n.children())
        .filter(|n| n.has_tag_name("finished"))
        .collect();
    if finished.len() != 1 || finished[0].attribute("exit") != Some("success") {
        return Err("Nmap did not finish successfully".into());
    }
    let mut services = Vec::new();
    let mut seen = BTreeSet::new();
    for node in host
        .children()
        .filter(|n| n.has_tag_name("ports"))
        .flat_map(|n| n.children())
        .filter(|n| n.has_tag_name("port"))
    {
        let port = node
            .attribute("portid")
            .and_then(|p| p.parse::<u16>().ok())
            .ok_or("Bad Nmap port")?;
        if node.attribute("protocol") != Some("tcp")
            || !request.ports.contains(&port)
            || !seen.insert(port)
        {
            return Err("Unexpected or duplicate Nmap port".into());
        }
        let states: Vec<_> = node
            .children()
            .filter(|n| n.has_tag_name("state"))
            .collect();
        if states.len() != 1 {
            return Err("Missing/ambiguous Nmap port state".into());
        }
        let found: Vec<_> = node
            .children()
            .filter(|n| n.has_tag_name("service"))
            .collect();
        if found.len() > 1 {
            return Err("Ambiguous service response".into());
        }
        let a = |key| clean(found.first().and_then(|n| n.attribute(key)).unwrap_or(""));
        let cpes = found
            .iter()
            .flat_map(|n| n.children())
            .filter(|n| n.has_tag_name("cpe"))
            .take(16)
            .map(|n| clean(n.text().unwrap_or("")))
            .collect();
        services.push(Service {
            port,
            state: clean(states[0].attribute("state").unwrap_or("unknown")),
            name: a("name"),
            product: a("product"),
            version: a("version"),
            extra_info: a("extrainfo"),
            tunnel: a("tunnel"),
            device_type: a("devicetype"),
            os_type: a("ostype"),
            reported_hostname: a("hostname"),
            method: a("method"),
            confidence: a("conf"),
            cpes,
        });
    }
    services.sort_by_key(|s| s.port);
    Ok(Inspection {
        ip: request.ip.to_string(),
        ports: request.ports.clone(),
        checked_at: now(),
        services,
    })
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportRow {
    pub ip: String,
    pub port: u16,
    pub open: bool,
    pub hostname: Option<String>,
    pub service: String,
    pub device_hint: String,
    pub discovered_at: Option<String>,
    pub source: String,
    pub inspection: Option<Service>,
    pub inspection_checked_at: Option<String>,
}
pub fn csv_cell(value: &str) -> String {
    let safe = if value.trim_start().starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if safe.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", safe.replace('"', "\"\""))
    } else {
        safe
    }
}
pub fn csv(rows: &[ExportRow]) -> Result<String> {
    let mut text =
        "IP,Hostname,Port,Protocol,State,Service,Device hint,Discovered,Source\r\n".to_string();
    for r in rows {
        let cols = [
            r.ip.clone(),
            r.hostname.clone().unwrap_or_default(),
            r.port.to_string(),
            "TCP".into(),
            if r.open { "open" } else { "closed" }.into(),
            r.service.clone(),
            r.device_hint.clone(),
            r.discovered_at.clone().unwrap_or_default(),
            r.source.clone(),
        ];
        text.push_str(
            &cols
                .iter()
                .map(|c| csv_cell(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        text.push_str("\r\n");
    }
    Ok(text)
}
pub fn json(rows: &[ExportRow]) -> Result<String> {
    serde_json::to_string_pretty(&serde_json::json!({"format":"masscan-studio-results","version":1,"exported_at":now(),"rows":rows})).map_err(|e|e.to_string())
}
/// DNS-SD PTR RDATA is uncompressed; reject pointers/truncation and invalid names.
pub fn decode_ptr(bytes: &[u8]) -> Option<String> {
    let mut labels = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let n = bytes[offset] as usize;
        offset += 1;
        if n == 0 {
            return (offset == bytes.len())
                .then(|| valid_hostname(&labels.join(".")))
                .flatten();
        }
        if n > 63 || offset + n >= bytes.len() {
            return None;
        }
        labels.push(
            std::str::from_utf8(&bytes[offset..offset + n])
                .ok()?
                .to_owned(),
        );
        offset += n;
    }
    None
}
pub mod tasks;
