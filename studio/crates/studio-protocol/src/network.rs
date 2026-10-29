//! Compact, canonical network provenance. These pure checks never observe the OS.
use crate::*;
use rmasscan_core::{ranges::RangeList, targets::range_parse_ipv4};
use rmasscan_net::{ExcludedReason, PhysicalRoutePlan, PhysicalTargets};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

pub const MAX_NETWORK_BLOB: usize = 24_576;
pub const MAX_NETWORK_PROBES: u64 = 1_048_576;
// Big endian v1: magic[8], job digest[32], name length:u8/name, interface:u32,
// source IPv4[4]/MAC[6], four u16 counts, sorted hop IPv4 table, sorted MAC table,
// sorted (destination IPv4, hop:u16, MAC:u16 or 0xffff unresolved) records,
// sorted (excluded IPv4, reason:u8) records, SHA256[32]. Checkpoint v1 wraps
// report length:u16/report + unchanged engine[120] + SHA256[32]. Checksums detect
// corruption; authenticity comes from authenticated IPC and persisted-report equality.
const REPORT_MAGIC: &[u8; 8] = b"STNETR01";
const CHECKPOINT_MAGIC: &[u8; 8] = b"STNETC01";
const ENGINE_BYTES: usize = 120;
const CHECKPOINT_OVERHEAD: usize = 8 + 2 + ENGINE_BYTES + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkReport {
    pub job_digest: [u8; 32],
    pub routes: PhysicalRoutePlan,
    pub destinations: BTreeMap<Ipv4Addr, [u8; 6]>,
    pub unresolved: Vec<Ipv4Addr>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkCheckpoint {
    pub report: NetworkReport,
    pub engine: Vec<u8>,
}
fn selectors(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
}
fn ranges(s: &str) -> Result<Vec<(Ipv4Addr, Ipv4Addr)>, String> {
    let mut list = RangeList::new();
    for t in selectors(s) {
        let range = range_parse_ipv4(t).map_err(|e| e.to_string())?;
        list.add_range(range.begin, range.end);
    }
    list.sort_and_merge();
    Ok(list
        .as_slice()
        .iter()
        .map(|r| (r.begin.into(), r.end.into()))
        .collect())
}
fn ports(job: &Job) -> Result<RangeList, String> {
    if job.ports.is_empty()
        || !job
            .ports
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b',' || b == b'-')
    {
        return Err("TCP ports must be numbers or ranges".into());
    }
    for part in job.ports.split(',') {
        for end in part.split('-') {
            if end.parse::<u16>().map_err(|_| "Port outside 1–65535")? == 0 {
                return Err("Port zero is not supported".into());
            }
        }
    }
    let mut list = RangeList::new();
    parse_ports(&mut list, &job.ports).map_err(|e| e.to_string())?;
    list.sort_and_merge();
    Ok(list)
}
impl Job {
    /// Settings validation is intentionally independent of release gate and OS.
    /// Effective limits require admit_network after the read-only route planner.
    pub fn validate(&self) -> Result<(), String> {
        if self.backend != Backend::MacNetwork {
            return self.prepare().map(|_| ());
        }
        if decimal(&self.seed)? == 0 || !(1..=1000).contains(&self.rate) {
            return Err("Network seed must be nonzero; rate must be 1–1000".into());
        }
        if [&self.targets, &self.exclusions, &self.ports]
            .iter()
            .any(|s| s.len() >= 65536)
        {
            return Err("Input exceeds 65535 UTF-8 bytes".into());
        }
        ports(self)?;
        self.network_targets()?;
        let frame = Envelope::new(
            [255; 16],
            [255; 16],
            [255; 16],
            u64::MAX,
            Command::Start(self.clone()),
        );
        if serde_json::to_vec(&frame).map_err(|e| e.to_string())?.len() > MAX_FRAME {
            return Err("Start frame exceeds IPC size limit".into());
        }
        Ok(())
    }
    pub fn network_targets(&self) -> Result<PhysicalTargets, String> {
        if self.backend != Backend::MacNetwork {
            return Err("Not a physical network job".into());
        }
        if self.targets.len() >= 65536
            || self.exclusions.len() >= 65536
            || selectors(&self.targets).count() > 2048
            || selectors(&self.exclusions).count() > 2048
        {
            return Err("Physical target input too large".into());
        }
        let explicit = selectors(&self.targets)
            .filter(|s| !s.contains(['/', '-']))
            .map(|s| {
                range_parse_ipv4(s)
                    .map(|range| Ipv4Addr::from(range.begin))
                    .map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        PhysicalTargets::new(
            &ranges(&self.targets)?,
            &explicit,
            &ranges(&self.exclusions)?,
        )
        .map_err(|e| e.to_string())
    }
    pub fn original_digest(&self) -> Result<[u8; 32], String> {
        let mut bytes = b"studio-original-job-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|e| e.to_string())?);
        Ok(rmasscan_engine::identity::digest_bytes(&bytes))
    }
    /// Required before ARP, including the worst possible resolved report/checkpoint.
    /// A GUI snapshot may have a masked source; execution separately requires validate_executable.
    pub fn admit_network(&self, plan: &PhysicalRoutePlan) -> Result<(), String> {
        self.validate()?;
        let targets = self.network_targets()?;
        let n = plan.next_hops.len();
        if n == 0
            || n > 1024
            || plan.excluded.len() > 2048 - n
            || n as u64 * ports(self)?.count() > MAX_NETWORK_PROBES
        {
            return Err(
                "Network limit is 1024 effective addresses, 2048 candidates and 1048576 probes"
                    .into(),
            );
        }
        let mut partition: BTreeSet<_> = plan.next_hops.keys().copied().collect();
        for ip in plan.excluded.keys() {
            if !partition.insert(*ip) || targets.explicit_singletons().contains(ip) {
                return Err("Invalid excluded target provenance".into());
            }
        }
        if partition.into_iter().collect::<Vec<_>>() != targets.addresses() {
            return Err("Network plan does not cover original requested targets".into());
        }
        if plan.interface_name.is_empty() || plan.interface_name.len() > 63 {
            return Err("Invalid interface name length".into());
        }
        // Header, maximal unique hop/MAC tables, fixed-width destination and skipped records,
        // report checksum and frozen engine checkpoint. No unresolved-host discount.
        let worst = 8
            + 32
            + 1
            + 63
            + 4
            + 4
            + 6
            + 8
            + n * (4 + 6 + 8)
            + plan.excluded.len() * 5
            + 32
            + CHECKPOINT_OVERHEAD;
        if worst > MAX_NETWORK_BLOB {
            return Err("Network checkpoint exceeds compact blob limit".into());
        }
        check_future_frames(worst)?;
        let resume = Envelope::new(
            [255; 16],
            [255; 16],
            [255; 16],
            u64::MAX,
            Command::Resume {
                job: self.clone(),
                checkpoint: vec![255; worst],
            },
        );
        if serde_json::to_vec(&resume)
            .map_err(|e| e.to_string())?
            .len()
            > MAX_FRAME
        {
            return Err("Future Resume frame exceeds IPC limit".into());
        }
        Ok(())
    }
    pub fn prepare_network(&self, report: &NetworkReport) -> Result<ReadyPlan, String> {
        report.validate_for(self)?;
        if report.destinations.is_empty() {
            return Err("No targets eligible for TCP: no neighbour response".into());
        }
        let mut mass = MassIp::new();
        for ip in report.destinations.keys() {
            mass.ipv4_mut().add_range(u32::from(*ip), u32::from(*ip));
        }
        parse_ports(mass.ports_mut(), &self.ports).map_err(|e| e.to_string())?;
        let effective = validate(
            &ScanConfig {
                targets: mass,
                seed: decimal(&self.seed)?,
                max_rate: f64::from(self.rate),
                wait_secs: 3,
                ..Default::default()
            },
            Operation::Scan,
        )
        .map_err(|e| e.to_string())?;
        let source_mac = report
            .routes
            .source_mac
            .ok_or("Missing executable source MAC")?;
        ReadyPlan::with_destinations(
            effective,
            AdapterBinding {
                interface_id: report.routes.interface_name.clone(),
                link_type: LinkType::Ethernet,
                source_ipv4: report.routes.source_ipv4.into(),
                source_mac,
                next_hop_mac: *report
                    .destinations
                    .values()
                    .next()
                    .ok_or("Missing destination MAC")?,
                source_ports: (40000, 40000),
            },
            report
                .destinations
                .iter()
                .map(|(ip, mac)| (u32::from(*ip), *mac))
                .collect(),
        )
        .map_err(|e| e.to_string())
    }
}
fn check_future_frames(size: usize) -> Result<(), String> {
    for event in [
        Event::NetworkPrepared {
            bytes: vec![255; size],
        },
        Event::Checkpoint {
            bytes: vec![255; size],
            next_index: u64::MAX.to_string(),
        },
    ] {
        let e = Envelope::new([255; 16], [255; 16], [255; 16], u64::MAX, event);
        if serde_json::to_vec(&e).map_err(|e| e.to_string())?.len() > MAX_FRAME {
            return Err("Future network frame exceeds IPC limit".into());
        }
    }
    Ok(())
}
impl NetworkReport {
    pub fn validate_for(&self, job: &Job) -> Result<(), String> {
        if self.job_digest != job.original_digest()? {
            return Err("Network report belongs to another original job".into());
        }
        job.admit_network(&self.routes)?;
        self.validate_structure()
    }
    fn validate_structure(&self) -> Result<(), String> {
        self.routes
            .validate_executable()
            .map_err(|e| e.to_string())?;
        if self
            .destinations
            .len()
            .saturating_add(self.unresolved.len())
            != self.routes.next_hops.len()
        {
            return Err("Incomplete destination/unresolved partition".into());
        }
        if self.unresolved.windows(2).any(|w| w[0] >= w[1]) {
            return Err("Unresolved targets must be sorted and unique".into());
        }
        let mut coverage: BTreeSet<_> = self.destinations.keys().copied().collect();
        let mut hop_macs = BTreeMap::new();
        for (ip, mac) in &self.destinations {
            if mac == &[0; 6] || mac[0] & 1 != 0 {
                return Err("Invalid destination MAC".into());
            }
            let hop = self
                .routes
                .next_hops
                .get(ip)
                .ok_or("Destination outside frozen routes")?;
            if let Some(old) = hop_macs.insert(hop, mac)
                && old != mac
            {
                return Err("Conflicting MACs for one next hop".into());
            }
        }
        for ip in &self.unresolved {
            if !coverage.insert(*ip)
                || self.routes.next_hops.get(ip) != Some(ip)
                || hop_macs.contains_key(ip)
            {
                return Err("Unresolved target must be an unscanned on-link address".into());
            }
        }
        if coverage != self.routes.next_hops.keys().copied().collect() {
            return Err("Incomplete destination/unresolved partition".into());
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate_structure()?;
        let hops: Vec<_> = self
            .routes
            .next_hops
            .values()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let macs: Vec<_> = self
            .destinations
            .values()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut b = REPORT_MAGIC.to_vec();
        b.extend(self.job_digest);
        b.push(self.routes.interface_name.len() as u8);
        b.extend(self.routes.interface_name.as_bytes());
        b.extend(self.routes.interface_index.to_be_bytes());
        b.extend(self.routes.source_ipv4.octets());
        b.extend(self.routes.source_mac.ok_or("Missing source MAC")?);
        for n in [
            hops.len(),
            macs.len(),
            self.routes.next_hops.len(),
            self.routes.excluded.len(),
        ] {
            put16(&mut b, n);
        }
        for ip in &hops {
            b.extend(ip.octets());
        }
        for mac in &macs {
            b.extend(mac);
        }
        for (ip, hop) in &self.routes.next_hops {
            b.extend(ip.octets());
            put16(&mut b, hops.binary_search(hop).map_err(|_| "Missing hop")?);
            let mac_index = match self.destinations.get(ip) {
                Some(mac) => macs.binary_search(mac).map_err(|_| "Missing MAC")?,
                None => u16::MAX as usize,
            };
            put16(&mut b, mac_index);
        }
        for (ip, why) in &self.routes.excluded {
            b.extend(ip.octets());
            b.push(match why {
                ExcludedReason::OwnAddress => 1,
                ExcludedReason::NetworkAddress => 2,
                ExcludedReason::BroadcastAddress => 3,
                ExcludedReason::ForbiddenAddress => 4,
            });
        }
        checksum(&mut b);
        if b.len() + CHECKPOINT_OVERHEAD > MAX_NETWORK_BLOB {
            return Err("Network report leaves no room for checkpoint".into());
        }
        Ok(b)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes, REPORT_MAGIC)?;
        let job_digest = r.array()?;
        let name_len = r.byte()? as usize;
        if name_len > 63 {
            return Err("Interface name too long".into());
        }
        let interface_name =
            String::from_utf8(r.take(name_len)?.to_vec()).map_err(|_| "Invalid interface UTF-8")?;
        let interface_index = u32::from_be_bytes(r.array()?);
        let source_ipv4 = Ipv4Addr::from(r.array::<4>()?);
        let source_mac = Some(r.array()?);
        let (nh, nm, nd, ne) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
        if nh > 1024 || nm > 1024 || nd > 1024 || nd + ne > 2048 {
            return Err("Network report count bound exceeded".into());
        }
        let hops = (0..nh)
            .map(|_| r.array::<4>().map(Ipv4Addr::from))
            .collect::<Result<Vec<_>, _>>()?;
        let macs = (0..nm)
            .map(|_| r.array::<6>())
            .collect::<Result<Vec<_>, _>>()?;
        let mut next_hops = BTreeMap::new();
        let mut destinations = BTreeMap::new();
        let mut unresolved = Vec::new();
        for _ in 0..nd {
            let ip = Ipv4Addr::from(r.array::<4>()?);
            let hi = r.u16()?;
            let mi = r.u16()?;
            let hop = *hops.get(hi).ok_or("Invalid next-hop reference")?;
            if next_hops.insert(ip, hop).is_some() {
                return Err("Duplicate target".into());
            }
            if mi == u16::MAX as usize {
                unresolved.push(ip);
            } else {
                destinations.insert(ip, *macs.get(mi).ok_or("Invalid MAC reference")?);
            }
        }
        let mut excluded = BTreeMap::new();
        for _ in 0..ne {
            let ip = Ipv4Addr::from(r.array::<4>()?);
            let reason = match r.byte()? {
                1 => ExcludedReason::OwnAddress,
                2 => ExcludedReason::NetworkAddress,
                3 => ExcludedReason::BroadcastAddress,
                4 => ExcludedReason::ForbiddenAddress,
                _ => return Err("Invalid exclusion reason".into()),
            };
            if excluded.insert(ip, reason).is_some() {
                return Err("Duplicate exclusion".into());
            }
        }
        if !r.bytes.is_empty() {
            return Err("Trailing network report bytes".into());
        }
        let report = Self {
            job_digest,
            routes: PhysicalRoutePlan {
                interface_name,
                interface_index,
                source_ipv4,
                source_mac,
                next_hops,
                excluded,
            },
            destinations,
            unresolved,
        };
        if report.encode()? != bytes {
            return Err("Noncanonical network report".into());
        }
        Ok(report)
    }
}
impl NetworkCheckpoint {
    pub fn is_envelope(bytes: &[u8]) -> bool {
        bytes.starts_with(CHECKPOINT_MAGIC)
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        rmasscan_engine::Checkpoint::from_bytes(&self.engine).map_err(|e| e.to_string())?;
        let report = self.report.encode()?;
        let mut b = CHECKPOINT_MAGIC.to_vec();
        put16(&mut b, report.len());
        b.extend(report);
        b.extend(&self.engine);
        checksum(&mut b);
        if b.len() > MAX_NETWORK_BLOB {
            return Err("Network checkpoint exceeds blob limit".into());
        }
        Ok(b)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes, CHECKPOINT_MAGIC)?;
        let n = r.u16()?;
        let report = NetworkReport::decode(r.take(n)?)?;
        let engine = r.take(ENGINE_BYTES)?.to_vec();
        if !r.bytes.is_empty() {
            return Err("Trailing checkpoint bytes".into());
        }
        rmasscan_engine::Checkpoint::from_bytes(&engine).map_err(|e| e.to_string())?;
        Ok(Self { report, engine })
    }
}
fn put16(b: &mut Vec<u8>, n: usize) {
    b.extend((n as u16).to_be_bytes());
}
fn checksum(b: &mut Vec<u8>) {
    let hash = rmasscan_engine::identity::digest_bytes(b);
    b.extend(hash);
}
struct Reader<'a> {
    bytes: &'a [u8],
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], magic: &[u8; 8]) -> Result<Self, String> {
        if bytes.len() < 40 || bytes.len() > MAX_NETWORK_BLOB || !bytes.starts_with(magic) {
            return Err("Invalid network blob length/version".into());
        }
        let (body, sum) = bytes.split_at(bytes.len() - 32);
        if rmasscan_engine::identity::digest_bytes(body) != sum {
            return Err("Network blob checksum mismatch".into());
        }
        Ok(Self { bytes: &body[8..] })
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.bytes.len() {
            return Err("Truncated network blob".into());
        }
        let (head, tail) = self.bytes.split_at(n);
        self.bytes = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.take(N)?
            .try_into()
            .map_err(|_| "Truncated field".into())
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<usize, String> {
        Ok(u16::from_be_bytes(self.array()?) as usize)
    }
}
