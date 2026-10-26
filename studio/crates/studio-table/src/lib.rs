//! In-memory result table. Synthetic producers are retained for offline benchmarks;
//! the Studio UI only inserts persisted engine observations.
pub mod benchmark;
pub mod producer;

use std::{collections::HashSet, net::Ipv4Addr};

pub const INITIAL_ROWS: usize = 100_000;
pub const COLUMNS: [&str; 7] = [
    "IP",
    "Hostname",
    "Port",
    "Protocol",
    "Service",
    "Device hint",
    "Discovered",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub id: u64,
    pub ip: u32,
    pub port: u16,
    pub cells: [String; 7],
    pub service: String,
    pub evidence: String,
    search: String,
}

impl Row {
    pub fn refresh_search(&mut self) {
        self.search = format!("{} {}", self.cells.join(" "), self.evidence).to_lowercase();
    }
    /// A persisted engine observation. Simulation is explicitly labelled by the caller.
    pub fn observation(id: u64, ip: Ipv4Addr, port: u16, open: bool, simulation: bool) -> Self {
        let status = if open { "Open" } else { "Closed" };
        let source = if simulation {
            "Simulation"
        } else {
            "BPF observation"
        };
        let cells = [
            ip.to_string(),
            "Not resolved".into(),
            port.to_string(),
            "TCP".into(),
            status.into(),
            source.into(),
            "Saved in history".into(),
        ];
        let evidence = format!(
            "{source}\n\nTCP {status} result from rmasscan-engine. Saved transactionally in SQLite. Hostname and service inspection have not run."
        );
        let search = format!("{} {evidence}", cells.join(" ")).to_lowercase();
        Self {
            id,
            ip: u32::from(ip),
            port,
            cells,
            service: status.into(),
            evidence,
            search,
        }
    }
    /// A record emitted by the explicit fake scanner, not a network observation.
    pub fn process_fixture(id: u64, ip: Ipv4Addr, port: u16, discovered: String) -> Self {
        let cells = [
            ip.to_string(),
            "Not resolved".into(),
            port.to_string(),
            "TCP".into(),
            "Not inspected".into(),
            "Process fixture".into(),
            discovered,
        ];
        let evidence =
            "Synthetic result received from the fake-masscan child process. No packets were sent."
                .to_owned();
        let search = format!("{} {evidence}", cells.join(" ")).to_lowercase();
        Self {
            id,
            ip: u32::from(ip),
            port,
            cells,
            service: "Not inspected".into(),
            evidence,
            search,
        }
    }
    pub fn synthetic(id: u64) -> Self {
        // Fixed permutation makes lexical IP ordering visibly incorrect.
        let ip = 0x0a00_0000 | ((id as u32).wrapping_mul(7919) & 0x00ff_ffff);
        let port = [22, 80, 443, 8080, 53, 9100][id as usize % 6];
        let service =
            ["ssh", "http", "https", "http-alt", "dns", "printer"][id as usize % 6].to_owned();
        let evidence = if id.is_multiple_of(20) {
            "Synthetic evidence, no network observation. ".repeat(8)
        } else {
            "Synthetic fixture".into()
        };
        let cells = [
            Ipv4Addr::from(ip).to_string(),
            format!("host-{id:06}.example.invalid"),
            port.to_string(),
            "TCP".into(),
            service.clone(),
            format!("fixture-{}", id % 37),
            format!("2026-10-23 12:{:02}:{:02}", (id / 60) % 60, id % 60),
        ];
        let search = format!("{} {evidence}", cells.join(" ")).to_lowercase();
        Self {
            id,
            ip,
            port,
            cells,
            service,
            evidence,
            search,
        }
    }
    pub fn updated(id: u64, revision: u64) -> Self {
        let mut row = Self::synthetic(id);
        row.cells[5] = format!("updated-{revision}");
        row.search = format!("{} {}", row.cells.join(" "), row.evidence).to_lowercase();
        row
    }
}

pub enum Change {
    Append(Row),
    Update(Row),
}

pub fn generate(count: usize) -> Vec<Row> {
    (0..count as u64).map(Row::synthetic).collect()
}

pub fn queries() -> Vec<String> {
    let cases = [
        "",
        "https",
        "10.0.",
        "host-000",
        "fixture-1",
        "22",
        "printer",
        "no-such-device",
        "TCP",
        "synthetic",
    ];
    (0..100).map(|i| cases[i % cases.len()].into()).collect()
}

pub struct Table {
    pub rows: Vec<Row>,
    pub view: Vec<usize>,
    pub selected: HashSet<u64>,
    pub received: usize,
    pub updated: usize,
    pub focused: Option<u64>,
    anchor: Option<u64>,
    query: String,
    order: Option<(usize, bool)>,
}

impl Table {
    pub fn new(count: usize) -> Self {
        Self {
            rows: generate(count),
            view: (0..count).collect(),
            selected: HashSet::new(),
            received: 0,
            updated: 0,
            focused: None,
            anchor: None,
            query: String::new(),
            order: None,
        }
    }
    pub fn filter(&mut self, query: &str) {
        self.query = query.to_lowercase();
        self.rebuild();
    }
    pub fn sort(&mut self, column: usize, descending: bool) {
        if column < 7 {
            self.order = Some((column, descending));
            self.rebuild();
        }
    }
    fn rebuild(&mut self) {
        self.view.clear();
        self.view.extend(
            self.rows
                .iter()
                .enumerate()
                .filter_map(|(i, r)| r.search.contains(&self.query).then_some(i)),
        );
        if let Some((col, desc)) = self.order {
            let rows = &self.rows;
            self.view.sort_unstable_by(|&a, &b| {
                let a = &rows[a];
                let b = &rows[b];
                let order = match col {
                    0 => a.ip.cmp(&b.ip),
                    2 => a.port.cmp(&b.port),
                    _ => a.cells[col].cmp(&b.cells[col]),
                }
                .then(a.id.cmp(&b.id));
                if desc { order.reverse() } else { order }
            });
        }
    }
    pub fn row(&self, visual: usize) -> Option<&Row> {
        self.view.get(visual).map(|&i| &self.rows[i])
    }
    pub fn select(&mut self, visual: usize, extend: bool) {
        self.select_with_modifiers(visual, extend, false);
    }
    /// Unique selected IPs in visible order. Never copy hidden or merely focused rows.
    pub fn selected_ips(&self) -> String {
        let mut seen = HashSet::new();
        self.view
            .iter()
            .map(|&i| &self.rows[i])
            .filter(|r| self.selected.contains(&r.id) && seen.insert(r.ip))
            .map(|r| r.cells[0].as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }
    /// Deselect without losing the focus position used by the next arrow key.
    pub fn clear_selection(&mut self) {
        self.selected.clear();
        self.anchor = None;
    }
    /// Navigate the current view, resolving focus by stable ID after sort/filter.
    pub fn navigate(&mut self, delta: i32, range: bool) -> Option<usize> {
        let last = self.view.len().checked_sub(1)?;
        let current = self
            .focused
            .and_then(|id| self.view.iter().position(|&i| self.rows[i].id == id));
        let next = match delta {
            i32::MIN => 0,
            i32::MAX => last,
            _ => current
                .map(|i| (i as i64 + i64::from(delta)).clamp(0, last as i64) as usize)
                .unwrap_or(if delta < 0 { last } else { 0 }),
        };
        if current.is_none() {
            self.anchor = Some(self.rows[self.view[next]].id);
        }
        self.select_with_modifiers(next, false, range);
        Some(next)
    }
    pub fn select_visible(&mut self) {
        self.selected = self.view.iter().map(|&i| self.rows[i].id).collect();
        if !self.focused.is_some_and(|id| self.selected.contains(&id)) {
            self.focused = self.row(0).map(|r| r.id);
            self.anchor = self.focused;
        }
    }
    pub fn select_with_modifiers(&mut self, visual: usize, extend: bool, range: bool) {
        let Some(id) = self.row(visual).map(|r| r.id) else {
            return;
        };
        let anchor_id = self.anchor.or(self.focused);
        self.focused = Some(id);
        if range {
            let anchor = anchor_id
                .and_then(|id| self.view.iter().position(|&i| self.rows[i].id == id))
                .unwrap_or(visual);
            self.anchor = Some(self.rows[self.view[anchor]].id);
            if !extend {
                self.selected.clear();
            }
            for i in anchor.min(visual)..=anchor.max(visual) {
                self.selected.insert(self.rows[self.view[i]].id);
            }
            return;
        }
        self.anchor = Some(id);
        if !extend {
            self.selected.clear();
        }
        if !self.selected.insert(id) {
            self.selected.remove(&id);
        }
    }
    pub fn append_batch(&mut self, count: usize) {
        let start = self.rows.len() as u64;
        self.append_rows((start..start + count as u64).map(Row::synthetic).collect());
    }
    pub fn append_rows(&mut self, batch: Vec<Row>) {
        self.received += batch.len();
        self.rows.extend(batch);
        self.rebuild();
    }
    pub fn is_plain(&self) -> bool {
        self.query.is_empty() && self.order.is_none()
    }
    pub fn apply(&mut self, batch: Vec<Change>) {
        for change in batch {
            match change {
                Change::Append(row) => {
                    assert_eq!(
                        row.id,
                        self.rows.len() as u64,
                        "synthetic IDs must be contiguous"
                    );
                    self.rows.push(row);
                }
                Change::Update(row) => {
                    let index = row.id as usize;
                    assert_eq!(self.rows[index].id, row.id);
                    self.rows[index] = row;
                    self.updated += 1;
                }
            }
            self.received += 1;
        }
        self.rebuild();
    }
}
