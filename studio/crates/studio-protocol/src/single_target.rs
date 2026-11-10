//! Pure admission policy for a future one-shot physical acceptance path.
//! Not wired to any execution gate. Root storage/claiming and witness admission
//! are required separately; a parsed permit is not permission to open an adapter.
pub mod acceptance;
use crate::{Backend, Job, NetworkReport};
use rmasscan_core::probe::AdapterBinding;
use rmasscan_net::PhysicalRoutePlan;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Bounded operator intent. Interface identity and executable hashes come from root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub target: Ipv4Addr,
    pub ports: Vec<u16>,
    pub seed: u64,
}
impl Intent {
    /// Exact canonical shape selection, not a permission or a fallback gate.
    pub fn from_job(job: &Job) -> Result<Self, String> {
        let intent = Self {
            target: job
                .targets
                .parse()
                .map_err(|_| "Single-target job needs one literal IPv4")?,
            ports: job
                .ports
                .split(',')
                .map(|s| {
                    s.parse::<u16>()
                        .map_err(|_| "Single-target job needs explicit ports".to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?,
            seed: job.seed.parse().map_err(|_| "Invalid single-target seed")?,
        };
        intent.validate()?;
        if &intent.job() != job {
            return Err("Single-target job is not canonical".into());
        }
        Ok(intent)
    }
    pub fn validate(&self) -> Result<(), String> {
        if !public_candidate(self.target)
            || self.ports.is_empty()
            || self.ports.len() > 4
            || self.ports.contains(&0)
            || self.ports.windows(2).any(|p| p[0] >= p[1])
            || self.seed == 0
        {
            return Err(
                "Permit requires one public target and one to four sorted unique TCP ports".into(),
            );
        }
        self.job().validate()
    }
    pub fn job(&self) -> Job {
        Job {
            backend: Backend::MacNetwork,
            targets: self.target.to_string(),
            ports: self
                .ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
            exclusions: String::new(),
            seed: self.seed.to_string(),
            rate: 1,
        }
    }
}
/// Unprivileged durable-report veto only. Root permit/capture/claim checks remain
/// mandatory in the helper; these persisted bytes do not grant adapter access.
pub fn validate_persisted(job: &Job, bytes: Option<&[u8]>) -> Result<(), String> {
    let intent = Intent::from_job(job)?;
    let report = NetworkReport::decode(bytes.ok_or("Single-target persisted report missing")?)?;
    report.validate_for(job)?;
    let suffix = report
        .routes
        .interface_name
        .strip_prefix("en")
        .unwrap_or("");
    if suffix.is_empty()
        || suffix.len() > 4
        || !suffix.bytes().all(|b| b.is_ascii_digit())
        || report.routes.next_hops.len() != 1
        || !report.routes.next_hops.contains_key(&intent.target)
        || !report.routes.excluded.is_empty()
    {
        return Err("Single-target persisted route shape differs".into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceBinding {
    pub name: String,
    pub index: u32,
    pub source_ipv4: Ipv4Addr,
    pub source_mac: [u8; 6],
    pub next_hop: Ipv4Addr,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permit {
    pub version: u8,
    pub generation: String,
    pub owner_uid: u32,
    pub created: u64,
    pub expires: u64,
    pub tooling_sha256: String,
    pub helper_sha256: String,
    pub target: Ipv4Addr,
    pub ports: Vec<u16>,
    pub seed: u64,
    pub interface: InterfaceBinding,
}
/// All fields must come from trusted root-side identity/time observations.
pub struct Context<'a> {
    pub now: u64,
    pub owner_uid: u32,
    pub tooling_sha256: &'a str,
    pub helper_sha256: &'a str,
}
impl Permit {
    pub fn validate(&self, context: &Context<'_>) -> Result<(), String> {
        if self.version != 1
            || !hex(&self.generation, 32)
            || self.owner_uid == 0
            || self.owner_uid != context.owner_uid
            || !hex(&self.tooling_sha256, 64)
            || !hex(&self.helper_sha256, 64)
            || self.tooling_sha256 != context.tooling_sha256
            || self.helper_sha256 != context.helper_sha256
        {
            return Err("Single-target permit identity or executable hashes differ".into());
        }
        if self.created == 0
            || self.created > context.now
            || self.expires <= context.now
            || !self
                .expires
                .checked_sub(self.created)
                .is_some_and(|ttl| (1..=900).contains(&ttl))
        {
            return Err("Single-target permit expired or invalid lifetime".into());
        }
        self.intent().validate()?;
        let number = self.interface.name.strip_prefix("en").unwrap_or("");
        if number.is_empty() || number.len() > 4 || !number.bytes().all(|b| b.is_ascii_digit()) {
            return Err("Single-target acceptance requires a physical en interface".into());
        }
        self.plan()
            .validate_executable()
            .map_err(|e| e.to_string())?;
        self.job().validate()
    }
    pub fn intent(&self) -> Intent {
        Intent {
            target: self.target,
            ports: self.ports.clone(),
            seed: self.seed,
        }
    }
    pub fn job(&self) -> Job {
        self.intent().job()
    }
    pub fn admit_job(&self, job: &Job, context: &Context<'_>) -> Result<(), String> {
        self.validate(context)?;
        if job != &self.job() {
            return Err("Job differs from the exact single-target permit".into());
        }
        Ok(())
    }
    pub fn plan(&self) -> PhysicalRoutePlan {
        PhysicalRoutePlan {
            interface_name: self.interface.name.clone(),
            interface_index: self.interface.index,
            source_ipv4: self.interface.source_ipv4,
            source_mac: Some(self.interface.source_mac),
            next_hops: [(self.target, self.interface.next_hop)].into(),
            excluded: Default::default(),
        }
    }
    pub fn admit_plan(
        &self,
        plan: &PhysicalRoutePlan,
        context: &Context<'_>,
    ) -> Result<(), String> {
        self.validate(context)?;
        if plan != &self.plan() {
            return Err("Single-target interface, source or route changed".into());
        }
        Ok(())
    }
    pub fn admit_report(
        &self,
        report: &NetworkReport,
        context: &Context<'_>,
    ) -> Result<(), String> {
        self.admit_plan(&report.routes, context)?;
        report.validate_for(&self.job())
    }
    /// `resolved` must be the frozen MAC from the trusted neighbour result;
    /// None permits only the broadcast binding used for neighbour preparation.
    pub fn admit_binding(
        &self,
        binding: &AdapterBinding,
        resolved: Option<[u8; 6]>,
        context: &Context<'_>,
    ) -> Result<(), String> {
        self.validate(context)?;
        if resolved.is_some_and(|mac| mac == [0; 6] || mac[0] & 1 != 0)
            || binding.interface_id != self.interface.name
            || binding.link_type != rmasscan_core::packet::LinkType::Ethernet
            || binding.source_ipv4 != u32::from(self.interface.source_ipv4)
            || binding.source_mac != self.interface.source_mac
            || binding.source_ports != (40000, 40000)
            || binding.next_hop_mac != resolved.unwrap_or([255; 6])
        {
            return Err(
                "Adapter binding differs from the single-target permit or resolved MAC".into(),
            );
        }
        Ok(())
    }
    pub fn decode(bytes: &[u8], context: &Context<'_>) -> Result<Self, String> {
        if bytes.len() > 16384 {
            return Err("Oversized single-target permit".into());
        }
        let permit: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        permit.validate(context)?;
        Ok(permit)
    }
}
#[derive(Default)]
pub struct Pin {
    value: Option<(Permit, u64)>,
    rejected: bool,
}
impl Pin {
    /// Any admission failure permanently invalidates this pin, including expiry.
    pub fn check(&mut self, permit: &Permit, context: &Context<'_>) -> Result<(), String> {
        if self.rejected {
            return Err("Single-target session invalidated; new helper session required".into());
        }
        let result = self.check_current(permit, context);
        if result.is_err() {
            self.rejected = true;
        }
        result
    }
    fn check_current(&mut self, permit: &Permit, context: &Context<'_>) -> Result<(), String> {
        permit.validate(context)?;
        if let Some((old, last_seen)) = self.value.as_mut() {
            if old != permit || context.now < *last_seen {
                return Err("Single-target permit replaced or clock moved backwards; new helper session required".into());
            }
            *last_seen = context.now;
        } else {
            self.value = Some((permit.clone(), context.now));
        }
        Ok(())
    }
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && value.bytes().any(|b| b != b'0')
}
/// Conservative candidate scope, not a universal Internet-routability oracle.
/// Root-observed routing and explicit target permission are separate requirements.
fn public_candidate(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    ![
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
    ]
    .into_iter()
    .any(|(network, prefix)| {
        let mask = u32::MAX << (32 - prefix);
        value & mask == u32::from(Ipv4Addr::from(network))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const TOOL: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HELPER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    fn context() -> Context<'static> {
        Context {
            now: 1001,
            owner_uid: 501,
            tooling_sha256: TOOL,
            helper_sha256: HELPER,
        }
    }
    // Public address is test data only, not authorization and never contacted.
    fn permit() -> Permit {
        Permit {
            version: 1,
            generation: "11111111111111111111111111111111".into(),
            owner_uid: 501,
            created: 1000,
            expires: 1900,
            tooling_sha256: TOOL.into(),
            helper_sha256: HELPER.into(),
            target: "45.33.32.156".parse().unwrap(),
            ports: vec![22, 80, 443, 65000],
            seed: u64::MAX,
            interface: InterfaceBinding {
                name: "en0".into(),
                index: 5,
                source_ipv4: "10.0.0.2".parse().unwrap(),
                source_mac: [2, 1, 2, 3, 4, 5],
                next_hop: "10.0.0.1".parse().unwrap(),
            },
        }
    }
    #[test]
    fn canonical_job_selector_refuses_every_expansion_or_alternate_spelling() {
        let p = permit();
        let job = p.job();
        assert_eq!(Intent::from_job(&job).unwrap(), p.intent());
        for kind in 0..10 {
            let mut bad = job.clone();
            match kind {
                0 => bad.targets.push_str("/32"),
                1 => bad.targets = "scanme.nmap.org".into(),
                2 => bad.ports = "22-80".into(),
                3 => bad.ports = "22,080,443,65000".into(),
                4 => bad.seed = "00042".into(),
                5 => bad.rate = 2,
                6 => bad.exclusions = job.targets.clone(),
                7 => bad.backend = Backend::Simulation,
                8 => bad.targets = "10.0.0.1".into(),
                _ => bad.targets = format!("{} ", job.targets),
            };
            assert!(Intent::from_job(&bad).is_err());
        }
    }
    #[test]
    fn durable_public_report_predicate_checks_exact_job_and_physical_route_shape() {
        let p = permit();
        let job = p.job();
        let report = NetworkReport {
            job_digest: job.original_digest().unwrap(),
            routes: p.plan(),
            destinations: [(p.target, [2, 6, 7, 8, 9, 10])].into(),
            unresolved: vec![],
        };
        validate_persisted(&job, Some(&report.encode().unwrap())).unwrap();
        assert!(validate_persisted(&job, None).is_err());
        for kind in 0..3 {
            let mut bad = report.clone();
            match kind {
                0 => bad.routes.interface_name = "utun3".into(),
                1 => bad.job_digest[0] ^= 1,
                _ => {
                    let other = "1.1.1.1".parse().unwrap();
                    bad.routes.next_hops.insert(other, p.interface.next_hop);
                    bad.destinations.insert(other, [2, 6, 7, 8, 9, 10]);
                }
            };
            assert!(validate_persisted(&job, Some(&bad.encode().unwrap())).is_err());
        }
    }
    #[test]
    fn intent_refuses_private_targets_and_port_expansion_before_route_observation() {
        let valid = Intent {
            target: "45.33.32.156".parse().unwrap(),
            ports: vec![22, 80, 443, 65535],
            seed: 42,
        };
        valid.validate().unwrap();
        assert_eq!(valid.job().rate, 1);
        for ports in [
            vec![],
            vec![0],
            vec![80, 80],
            vec![443, 80],
            vec![1, 2, 3, 4, 5],
        ] {
            assert!(
                Intent {
                    ports,
                    ..valid.clone()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            Intent {
                target: "10.0.0.1".parse().unwrap(),
                ..valid.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            Intent {
                seed: 0,
                ..valid.clone()
            }
            .validate()
            .is_err()
        );
        let mut value = serde_json::to_value(&valid).unwrap();
        value["interface"] = serde_json::json!("en0");
        assert!(serde_json::from_value::<Intent>(value).is_err());
    }
    #[test]
    fn only_exact_single_host_ports_rate_and_seed_are_admitted() {
        let p = permit();
        let c = context();
        let job = Job {
            backend: Backend::MacNetwork,
            targets: "45.33.32.156".into(),
            ports: "22,80,443,65000".into(),
            exclusions: String::new(),
            seed: "18446744073709551615".into(),
            rate: 1,
        };
        assert_eq!(p.job(), job);
        assert!(p.admit_job(&job, &c).is_ok());
        for targets in [
            "45.33.32.156/32",
            "45.33.32.156/24",
            "45.33.32.156,45.33.32.157",
            "scanme.nmap.org",
        ] {
            let mut other = job.clone();
            other.targets = targets.into();
            assert!(p.admit_job(&other, &c).is_err());
        }
        for ports in ["1-65535", "22,80,443", "80,22,443,65000", "22,80,443,65001"] {
            let mut other = job.clone();
            other.ports = ports.into();
            assert!(p.admit_job(&other, &c).is_err());
        }
        let mut other = job.clone();
        other.rate = 2;
        assert!(p.admit_job(&other, &c).is_err());
        let mut other = job.clone();
        other.seed = "42".into();
        assert!(p.admit_job(&other, &c).is_err());
        let mut other = job.clone();
        other.exclusions = "45.33.32.157".into();
        assert!(p.admit_job(&other, &c).is_err());
        let mut other = job;
        other.backend = Backend::Simulation;
        assert!(p.admit_job(&other, &c).is_err());
    }
    #[test]
    fn expired_replaced_wrong_owner_and_unbounded_permits_are_rejected() {
        let p = permit();
        let c = context();
        assert!(p.validate(&c).is_ok());
        for now in [0, 999, 1900, u64::MAX] {
            assert!(p.validate(&Context { now, ..context() }).is_err());
        }
        assert!(
            p.validate(&Context {
                owner_uid: 502,
                ..context()
            })
            .is_err()
        );
        assert!(
            p.validate(&Context {
                helper_sha256: TOOL,
                ..context()
            })
            .is_err()
        );
        assert!(
            p.validate(&Context {
                tooling_sha256: HELPER,
                ..context()
            })
            .is_err()
        );
        let mut cases = vec![];
        let mut q = p.clone();
        q.version = 2;
        cases.push(q);
        let mut q = p.clone();
        q.owner_uid = 0;
        cases.push(q);
        let mut q = p.clone();
        q.generation = "0".repeat(32);
        cases.push(q);
        let mut q = p.clone();
        q.expires = 1901;
        cases.push(q);
        let mut q = p.clone();
        q.expires = 999;
        cases.push(q);
        let mut q = p.clone();
        q.seed = 0;
        cases.push(q);
        for ports in [
            vec![],
            vec![0],
            vec![80, 80],
            vec![443, 80],
            vec![1, 2, 3, 4, 5],
        ] {
            let mut q = p.clone();
            q.ports = ports;
            cases.push(q);
        }
        for q in cases {
            assert!(q.validate(&c).is_err(), "accepted {q:?}");
        }
        let mut pin = Pin::default();
        assert!(pin.check(&p, &c).is_ok());
        assert!(pin.check(&p, &c).is_ok());
        let mut replacement = p.clone();
        replacement.generation = "2".repeat(32);
        assert!(pin.check(&replacement, &c).is_err());
        assert!(pin.check(&p, &c).is_err());
    }
    #[test]
    fn pinned_permit_rejects_clock_rollback_within_an_otherwise_valid_lease() {
        let p = permit();
        let mut pin = Pin::default();
        pin.check(&p, &context()).unwrap();
        let earlier = Context {
            now: 1000,
            ..context()
        };
        assert!(p.validate(&earlier).is_ok());
        assert!(pin.check(&p, &earlier).is_err());
        assert!(pin.check(&p, &context()).is_err());
    }

    #[test]
    fn expired_pin_cannot_recover_when_the_clock_is_restored() {
        let p = permit();
        let mut pin = Pin::default();
        pin.check(&p, &context()).unwrap();
        assert!(
            pin.check(
                &p,
                &Context {
                    now: 1900,
                    ..context()
                }
            )
            .is_err()
        );
        assert!(
            pin.check(
                &p,
                &Context {
                    now: 1002,
                    ..context()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn special_networks_and_nonphysical_or_changed_source_routes_fail_closed() {
        for ip in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.2",
            "172.16.0.1",
            "192.168.1.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            let mut p = permit();
            p.target = ip.parse().unwrap();
            assert!(p.validate(&context()).is_err(), "accepted {ip}");
        }
        for name in [
            "lo0",
            "utun0",
            "feth4203",
            "bridge0",
            "en",
            "en0;id",
            "en0/other",
        ] {
            let mut p = permit();
            p.interface.name = name.into();
            assert!(p.validate(&context()).is_err());
        }
        let p = permit();
        let c = context();
        let plan = p.plan();
        assert!(p.admit_plan(&plan, &c).is_ok());
        let mut wrong = plan.clone();
        wrong.interface_index += 1;
        assert!(p.admit_plan(&wrong, &c).is_err());
        let mut wrong = plan.clone();
        wrong.source_mac = None;
        assert!(p.admit_plan(&wrong, &c).is_err());
        let mut wrong = plan.clone();
        wrong
            .next_hops
            .insert(p.target, "10.0.0.254".parse().unwrap());
        assert!(p.admit_plan(&wrong, &c).is_err());
        let mut wrong = plan;
        wrong
            .next_hops
            .insert("45.33.32.157".parse().unwrap(), p.interface.next_hop);
        assert!(p.admit_plan(&wrong, &c).is_err());
    }
    #[test]
    fn report_and_adapter_cannot_expand_the_trusted_route_or_mac_map() {
        let p = permit();
        let c = context();
        let mac = [2, 9, 8, 7, 6, 5];
        let report = NetworkReport {
            job_digest: p.job().original_digest().unwrap(),
            routes: p.plan(),
            destinations: [(p.target, mac)].into(),
            unresolved: vec![],
        };
        assert!(p.admit_report(&report, &c).is_ok());
        let mut wrong = report.clone();
        wrong.job_digest = [0; 32];
        assert!(p.admit_report(&wrong, &c).is_err());
        let mut wrong = report;
        wrong
            .destinations
            .insert("45.33.32.157".parse().unwrap(), mac);
        assert!(p.admit_report(&wrong, &c).is_err());
        let binding = AdapterBinding {
            interface_id: "en0".into(),
            link_type: rmasscan_core::packet::LinkType::Ethernet,
            source_ipv4: u32::from(p.interface.source_ipv4),
            source_mac: p.interface.source_mac,
            next_hop_mac: mac,
            source_ports: (40000, 40000),
        };
        assert!(p.admit_binding(&binding, Some(mac), &c).is_ok());
        assert!(p.admit_binding(&binding, None, &c).is_err());
        let mut arp = binding.clone();
        arp.next_hop_mac = [255; 6];
        assert!(p.admit_binding(&arp, None, &c).is_ok());
        assert!(p.admit_binding(&arp, Some([255; 6]), &c).is_err());
        assert!(p.admit_binding(&binding, Some([0; 6]), &c).is_err());
        assert!(
            p.admit_binding(&binding, Some([2, 1, 1, 1, 1, 1]), &c)
                .is_err()
        );
        let mut wrong = binding.clone();
        wrong.source_ports = (40000, 40001);
        assert!(p.admit_binding(&wrong, Some(mac), &c).is_err());
        let mut wrong = binding;
        wrong.source_ipv4 += 1;
        assert!(p.admit_binding(&wrong, Some(mac), &c).is_err());
    }
    #[test]
    fn bounded_decode_rejects_unknown_fields_and_does_not_round_the_seed() {
        let p = permit();
        let c = context();
        let bytes = serde_json::to_vec(&p).unwrap();
        assert_eq!(Permit::decode(&bytes, &c).unwrap().seed, u64::MAX);
        let mut v = serde_json::to_value(&p).unwrap();
        v["allow_any_target"] = serde_json::Value::Bool(true);
        assert!(Permit::decode(&serde_json::to_vec(&v).unwrap(), &c).is_err());
        let mut oversized = bytes;
        oversized.resize(16385, b' ');
        assert!(Permit::decode(&oversized, &c).is_err());
    }
}
