use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use studio_inspection::{
    CheckState, HostInfo, Request,
    tasks::{Kind, Outcome, Task, Tasks},
};
use studio_protocol::{Backend, Id};
use studio_store::Store;
type Result<T> = std::result::Result<T, String>;
struct Pending {
    id: u64,
    cancel: Arc<AtomicBool>,
}
pub(crate) struct Hosts {
    tasks: Tasks,
    selected: Option<(Id, Backend)>,
    info: HashMap<String, HostInfo>,
    pending: HashMap<(Ipv4Addr, Kind), Pending>,
    queried: HashSet<Ipv4Addr>,
    next: u64,
}
impl Hosts {
    pub fn new(resolver: PathBuf) -> Self {
        Self {
            tasks: Tasks::new(resolver, studio_inspection::process::find_nmap()),
            selected: None,
            info: HashMap::new(),
            pending: HashMap::new(),
            queried: HashSet::new(),
            next: 0,
        }
    }
    pub fn select(&mut self, scan: Id, backend: Backend, db: &mut Store) -> Result<Vec<HostInfo>> {
        let cancellation = self.cancel(db);
        self.selected = Some((scan, backend));
        self.queried.clear();
        self.info.clear();
        cancellation?;
        self.info = db
            .hosts(scan)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|h| (h.ip.clone(), h))
            .collect();
        Ok(self.info.values().cloned().collect())
    }
    fn target(&self) -> Result<Id> {
        match self.selected {
            Some((_, Backend::Simulation)) => {
                Err("Simulation results cannot trigger network lookups or Nmap checks".into())
            }
            Some((scan, _)) => Ok(scan),
            None => Err("Select a saved scan first".into()),
        }
    }
    fn launch(&mut self, ip: Ipv4Addr, kind: Kind, request: Option<Request>) -> Result<()> {
        if let Some(old) = self.pending.remove(&(ip, kind)) {
            old.cancel.store(true, Ordering::Release);
        }
        self.next = self
            .next
            .checked_add(1)
            .ok_or("Inspection request counter exhausted")?;
        let cancel = Arc::new(AtomicBool::new(false));
        self.tasks.submit(
            kind,
            Task {
                id: self.next,
                ip,
                request,
                cancel: cancel.clone(),
            },
        )?;
        self.pending.insert(
            (ip, kind),
            Pending {
                id: self.next,
                cancel,
            },
        );
        Ok(())
    }
    pub fn dns(
        &mut self,
        ips: Vec<String>,
        refresh: bool,
        db: &mut Store,
    ) -> Result<Vec<HostInfo>> {
        let scan = self.target()?;
        let ips: HashSet<Ipv4Addr> = ips
            .iter()
            .map(|s| s.parse().map_err(|_| "Invalid IPv4 host"))
            .collect::<std::result::Result<_, _>>()?;
        if ips.is_empty() || ips.len() > 512 || self.queried.union(&ips).count() > 512 {
            return Err(
                "Hostname lookup is limited to 512 hosts per scan selection; narrow the filter"
                    .into(),
            );
        }
        let known: HashSet<_> = db
            .rows(scan)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|r| r.ip)
            .collect();
        if ips.iter().any(|ip| !known.contains(&ip.to_string())) {
            return Err("Lookup host is not present in the selected scan".into());
        }
        let mut updated = Vec::new();
        for ip in ips {
            self.queried.insert(ip);
            let mut info = self
                .info
                .get(&ip.to_string())
                .cloned()
                .unwrap_or_else(|| HostInfo::new(ip.to_string()));
            info.dns_error.clear();
            if let Some(old) = self.pending.remove(&(ip, Kind::Dns)) {
                old.cancel.store(true, Ordering::Release);
            }
            if !refresh && let Some(name) = self.tasks.cached(ip) {
                info.hostname = name;
                info.dns_state = if info.hostname.is_some() {
                    CheckState::Complete
                } else {
                    CheckState::NotFound
                };
                info.dns_checked_at = Some(studio_inspection::now());
            } else {
                match self.launch(ip, Kind::Dns, None) {
                    Ok(()) => info.dns_state = CheckState::Pending,
                    Err(e) => {
                        info.dns_state = CheckState::Failed;
                        info.dns_error = e;
                    }
                }
            }
            if let Err(e) = db.save_host(scan, &info) {
                if let Some(p) = self.pending.remove(&(ip, Kind::Dns)) {
                    p.cancel.store(true, Ordering::Release);
                }
                return Err(e.to_string());
            }
            self.info.insert(info.ip.clone(), info.clone());
            updated.push(info);
        }
        Ok(updated)
    }
    pub fn nmap(&mut self, ip: String, db: &mut Store) -> Result<Vec<HostInfo>> {
        let scan = self.target()?;
        let ports = db
            .rows(scan)
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|r| r.ip == ip && r.open)
            .map(|r| r.port)
            .collect();
        let request = Request::new(&ip, ports)?;
        let addr = request.ip;
        let mut info = self
            .info
            .get(&ip)
            .cloned()
            .unwrap_or_else(|| HostInfo::new(ip));
        self.launch(addr, Kind::Nmap, Some(request))?;
        info.nmap_state = CheckState::Pending;
        info.nmap_error.clear();
        if let Err(e) = db.save_host(scan, &info) {
            if let Some(p) = self.pending.remove(&(addr, Kind::Nmap)) {
                p.cancel.store(true, Ordering::Release);
            }
            return Err(e.to_string());
        }
        self.info.insert(info.ip.clone(), info.clone());
        Ok(vec![info])
    }
    pub fn cancel(&mut self, db: &mut Store) -> Result<Vec<HostInfo>> {
        let mut dirty = HashSet::new();
        for ((ip, kind), pending) in self.pending.drain() {
            pending.cancel.store(true, Ordering::Release);
            if let Some(info) = self.info.get_mut(&ip.to_string()) {
                match kind {
                    Kind::Dns => {
                        info.dns_state = CheckState::Cancelled;
                        info.dns_error = "Cancelled".into();
                    }
                    Kind::Nmap => {
                        info.nmap_state = CheckState::Cancelled;
                        info.nmap_error = "Cancelled".into();
                    }
                }
                dirty.insert(ip.to_string());
            }
        }
        let mut result = Vec::new();
        if let Some((scan, _)) = self.selected {
            for ip in dirty {
                let info = self.info[&ip].clone();
                db.save_host(scan, &info).map_err(|e| e.to_string())?;
                result.push(info);
            }
        }
        Ok(result)
    }
    pub fn poll(&mut self, db: &mut Store) -> Result<Vec<HostInfo>> {
        self.receive(self.tasks.poll(), db)
    }
    fn receive(
        &mut self,
        events: Vec<studio_inspection::tasks::Completion>,
        db: &mut Store,
    ) -> Result<Vec<HostInfo>> {
        let mut updated = Vec::new();
        for event in events {
            let key = (event.ip, event.kind);
            if !self.pending.get(&key).is_some_and(|p| p.id == event.id) {
                continue;
            }
            self.pending.remove(&key);
            let Some((scan, _)) = self.selected else {
                continue;
            };
            let Some(info) = self.info.get_mut(&event.ip.to_string()) else {
                continue;
            };
            match event.outcome {
                Outcome::Dns(result) => {
                    info.dns_checked_at = Some(studio_inspection::now());
                    match result {
                        Ok(name) => {
                            info.hostname = name.clone();
                            info.dns_state = if name.is_some() {
                                CheckState::Complete
                            } else {
                                CheckState::NotFound
                            };
                            info.dns_error.clear();
                            self.tasks.remember(event.ip, name);
                        }
                        Err(e) => {
                            info.dns_state = if e == "Cancelled" {
                                CheckState::Cancelled
                            } else {
                                CheckState::Failed
                            };
                            info.dns_error = e;
                        }
                    }
                }
                Outcome::Nmap(result) => match result {
                    Ok(i) => {
                        info.inspection = Some(i);
                        info.nmap_state = CheckState::Complete;
                        info.nmap_error.clear();
                    }
                    Err(e) => {
                        info.nmap_state = if e == "Cancelled" {
                            CheckState::Cancelled
                        } else {
                            CheckState::Failed
                        };
                        info.nmap_error = e;
                    }
                },
            }
            db.save_host(scan, info).map_err(|e| e.to_string())?;
            updated.push(info.clone());
        }
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use studio_inspection::tasks::Completion;
    use studio_protocol::*;
    fn setup() -> (std::path::PathBuf, Store, Hosts) {
        let dir = std::env::temp_dir().join(format!("studio-hosts-{}", id_text(new_id().unwrap())));
        let mut db = Store::open(&dir).unwrap();
        for scan in [[1; 16], [2; 16]] {
            db.begin(scan, [3; 16], &Job::example(Backend::Simulation), false)
                .unwrap();
            db.apply(&Envelope::new(
                [4; 16],
                scan,
                [3; 16],
                1,
                Event::Results(vec![Row {
                    ip: "198.18.0.2".into(),
                    port: 8000,
                    open: true,
                }]),
            ))
            .unwrap();
        }
        let h = Hosts::new(dir.join("nonexistent-resolver"));
        (dir, db, h)
    }
    #[test]
    fn simulation_refuses_all_network_actions() {
        let (dir, mut db, mut h) = setup();
        h.select([1; 16], Backend::Simulation, &mut db).unwrap();
        assert!(
            h.dns(vec!["198.18.0.2".into()], true, &mut db)
                .unwrap_err()
                .contains("Simulation")
        );
        assert!(
            h.nmap("198.18.0.2".into(), &mut db)
                .unwrap_err()
                .contains("Simulation")
        );
        assert!(h.pending.is_empty());
        drop(h);
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn late_reply_cannot_cross_scan_or_overwrite_new_request() {
        let (dir, mut db, mut h) = setup();
        h.select([1; 16], Backend::MacFeth, &mut db).unwrap();
        let ip: Ipv4Addr = "198.18.0.2".parse().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut info = HostInfo::new(ip.to_string());
        info.dns_state = CheckState::Pending;
        h.info.insert(ip.to_string(), info.clone());
        db.save_host([1; 16], &info).unwrap();
        h.pending.insert(
            (ip, Kind::Dns),
            Pending {
                id: 1,
                cancel: cancel.clone(),
            },
        );
        h.select([2; 16], Backend::MacFeth, &mut db).unwrap();
        assert!(cancel.load(Ordering::Acquire));
        assert_eq!(
            db.hosts([1; 16]).unwrap()[0].dns_state,
            CheckState::Cancelled
        );
        h.info.insert(ip.to_string(), HostInfo::new(ip.to_string()));
        h.pending.insert(
            (ip, Kind::Dns),
            Pending {
                id: 2,
                cancel: Arc::new(AtomicBool::new(false)),
            },
        );
        let event = |id, name: &str| Completion {
            id,
            ip,
            kind: Kind::Dns,
            outcome: Outcome::Dns(Ok(Some(name.into()))),
        };
        assert!(
            h.receive(vec![event(1, "stale.local")], &mut db)
                .unwrap()
                .is_empty()
        );
        assert!(db.hosts([2; 16]).unwrap().is_empty());
        assert_eq!(
            h.receive(vec![event(2, "current.local")], &mut db).unwrap()[0].hostname,
            Some("current.local".into())
        );
        assert_eq!(db.hosts([1; 16]).unwrap()[0].hostname, None);
        drop(h);
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn cached_lookup_cancels_older_refresh_and_manual_refresh_bypasses_cache() {
        let (dir, mut db, mut h) = setup();
        h.select([1; 16], Backend::MacFeth, &mut db).unwrap();
        let ip: Ipv4Addr = "198.18.0.2".parse().unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        h.pending.insert(
            (ip, Kind::Dns),
            Pending {
                id: 1,
                cancel: flag.clone(),
            },
        );
        h.tasks.remember(ip, Some("cache.local".into()));
        let info = h.dns(vec![ip.to_string()], false, &mut db).unwrap();
        assert_eq!(info[0].hostname, Some("cache.local".into()));
        assert!(flag.load(Ordering::Acquire));
        assert!(h.pending.is_empty());
        let info = h.dns(vec![ip.to_string()], true, &mut db).unwrap();
        assert_eq!(info[0].dns_state, CheckState::Pending);
        h.cancel(&mut db).unwrap();
        assert!(h.pending.is_empty());
        assert!(h.dns(vec!["198.18.0.99".into()], true, &mut db).is_err());
        drop(h);
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
