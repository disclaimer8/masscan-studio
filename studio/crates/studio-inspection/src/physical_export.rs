//! Portable export data: no dependency on application, protocol or persistence.
use crate::{ExportRow, Result, csv, csv_cell, json, now, write_export_bytes};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportJob {
    pub backend: String,
    pub targets: String,
    pub ports: String,
    pub exclusions: String,
    pub seed: String,
    pub rate: u32,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageCount {
    pub targets: u64,
    pub probes: u64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageAddress {
    pub ip: String,
    pub reason: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportRoute {
    pub destination: String,
    pub next_hop: String,
    pub destination_mac: Option<String>,
}
/// Frozen scan-wide preparation facts. Eligibility does not assert that probes were sent.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportCoverage {
    pub scan_id: String,
    pub original_job: ExportJob,
    pub original_job_digest: String,
    pub requested_inputs: usize,
    pub requested: CoverageCount,
    pub candidate: CoverageCount,
    pub effective: CoverageCount,
    pub eligible: CoverageCount,
    pub unscanned: CoverageCount,
    pub automatically_excluded: CoverageCount,
    pub interface_name: String,
    pub interface_index: u32,
    pub source_ipv4: String,
    pub source_mac: Option<String>,
    pub routes: Vec<ExportRoute>,
    pub unresolved: Vec<CoverageAddress>,
    pub excluded: Vec<CoverageAddress>,
}

/// Legacy callers retain their format; physical reports put metadata and rows in
/// one file. Rows are the caller's filtered/sorted snapshot; coverage is scan-wide.
pub fn write_export_with_coverage(
    path: &std::path::Path,
    rows: &[ExportRow],
    coverage: Option<&ExportCoverage>,
    as_json: bool,
) -> Result<()> {
    let bytes = if as_json {
        json_with_coverage(rows, coverage)?
    } else {
        csv_with_coverage(rows, coverage)?
    };
    write_export_bytes(path, &bytes)
}
pub fn json_with_coverage(rows: &[ExportRow], coverage: Option<&ExportCoverage>) -> Result<String> {
    let Some(coverage) = coverage else {
        return json(rows);
    };
    serde_json::to_string_pretty(&serde_json::json!({
        "format": "masscan-studio-results", "version": 2, "exported_at": now(),
        "coverage_scope": "whole scan; eligible counts are the prepared plan, not probes sent",
        "rows_scope": "visible filtered results in displayed order", "coverage": coverage, "rows": rows
    })).map_err(|e| e.to_string())
}
pub fn csv_with_coverage(rows: &[ExportRow], coverage: Option<&ExportCoverage>) -> Result<String> {
    let Some(coverage) = coverage else {
        return csv(rows);
    };
    let mut text = "Record kind,IP,Hostname,Port,Protocol,State,Service,Device hint,Discovered,Source,Detail\r\n".to_string();
    let mut record = |kind: &str, cols: [String; 9], detail: &str| {
        let mut cells = vec![csv_cell(kind)];
        cells.extend(cols.iter().map(|v| csv_cell(v)));
        cells.push(csv_cell(detail));
        text.push_str(&cells.join(","));
        text.push_str("\r\n");
    };
    // One explicit metadata record retains the entire typed report (including
    // exact original settings/routes/counts) in this same atomic CSV file.
    record(
        "scan_coverage",
        Default::default(),
        &serde_json::to_string(coverage).map_err(|e| e.to_string())?,
    );
    for address in &coverage.unresolved {
        let mut cols: [String; 9] = Default::default();
        cols[0] = address.ip.clone();
        record("not_scanned", cols, &address.reason);
    }
    for address in &coverage.excluded {
        let mut cols: [String; 9] = Default::default();
        cols[0] = address.ip.clone();
        record("automatically_excluded", cols, &address.reason);
    }
    for r in rows {
        record(
            "result",
            [
                r.ip.clone(),
                r.hostname.clone().unwrap_or_default(),
                r.port.to_string(),
                "TCP".into(),
                if r.open { "open" } else { "closed" }.into(),
                r.service.clone(),
                r.device_hint.clone(),
                r.discovered_at.clone().unwrap_or_default(),
                r.source.clone(),
            ],
            "",
        );
    }
    Ok(text)
}
