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
    /// The selected scan was deleted transactionally. Cancel in-flight work
    /// without attempting to write its terminal state into the removed scan.
    pub fn forget(&mut self) {
        for pending in self.pending.drain().map(|(_, p)| p) {
            pending.cancel.store(true, Ordering::Release);
        }
        self.selected = None;
        self.info.clear();
        self.queried.clear();
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
        if let Some(old) = self.pending.insert(
            (ip, kind),
            Pending {
                id: self.next,
                cancel,
            },
        ) {
            old.cancel.store(true, Ordering::Release);
        }
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
            let previous = info.clone();
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
            if let Err(e) = db.save_host(scan, info) {
                // Every drained completion must reach a terminal state, even
                // if another host failed to persist. Keep the last saved data
                // and expose the write failure without interrupting scanning.
                match event.kind {
                    Kind::Dns => {
                        info.hostname = previous.hostname;
                        info.dns_checked_at = previous.dns_checked_at;
                        info.dns_state = CheckState::Failed;
                        info.dns_error = format!("Cannot save hostname result: {e}");
                    }
                    Kind::Nmap => {
                        info.inspection = previous.inspection;
                        info.nmap_state = CheckState::Failed;
                        info.nmap_error = format!("Cannot save inspection result: {e}");
                    }
                }
            } else if event.kind == Kind::Dns
                && matches!(info.dns_state, CheckState::Complete | CheckState::NotFound)
            {
                self.tasks.remember(event.ip, info.hostname.clone());
            }
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
    fn deleting_selection_cancels_requests_and_ignores_late_completions() {
        let (dir, mut db, mut h) = setup();
        let scan = [1; 16];
        h.select(scan, Backend::MacFeth, &mut db).unwrap();
        let ip: Ipv4Addr = "198.18.0.2".parse().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        h.pending.insert(
            (ip, Kind::Dns),
            Pending {
                id: 1,
                cancel: cancel.clone(),
            },
        );
        h.info.insert(ip.to_string(), HostInfo::new(ip.to_string()));
        db.interrupt(scan, "test").unwrap();
        db.delete_scan(scan).unwrap();
        h.forget();
        assert!(cancel.load(Ordering::Acquire));
        assert!(
            h.receive(
                vec![Completion {
                    id: 1,
                    ip,
                    kind: Kind::Dns,
                    outcome: Outcome::Dns(Ok(Some("late.local".into()))),
                }],
                &mut db
            )
            .unwrap()
            .is_empty()
        );
        assert!(h.target().is_err());
        assert!(db.hosts(scan).unwrap().is_empty());
        h.select([2; 16], Backend::MacFeth, &mut db).unwrap();
        assert!(
            h.receive(
                vec![Completion {
                    id: 1,
                    ip,
                    kind: Kind::Dns,
                    outcome: Outcome::Dns(Ok(Some("late.local".into()))),
                }],
                &mut db
            )
            .unwrap()
            .is_empty()
        );
        assert!(db.hosts([2; 16]).unwrap().is_empty());
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
        let _process_reopen_guard = crate::PROCESS_REOPEN_TEST_LOCK.lock().unwrap();
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
    #[test]
    fn failed_dns_is_not_cached_but_authoritative_absence_is() {
        let (dir, mut db, mut h) = setup();
        h.select([1; 16], Backend::MacFeth, &mut db).unwrap();
        let ip: Ipv4Addr = "198.18.0.2".parse().unwrap();
        h.info.insert(ip.to_string(), HostInfo::new(ip.to_string()));
        for (id, outcome) in [(1, Err("System DNS resolver failed".into())), (2, Ok(None))] {
            h.pending.insert(
                (ip, Kind::Dns),
                Pending {
                    id,
                    cancel: Arc::new(AtomicBool::new(false)),
                },
            );
            let result = h
                .receive(
                    vec![Completion {
                        id,
                        ip,
                        kind: Kind::Dns,
                        outcome: Outcome::Dns(outcome),
                    }],
                    &mut db,
                )
                .unwrap();
            if id == 1 {
                assert_eq!(result[0].dns_state, CheckState::Failed);
                assert_eq!(h.tasks.cached(ip), None);
                assert!(result[0].dns_error.contains("resolver failed"));
            } else {
                assert_eq!(result[0].dns_state, CheckState::NotFound);
                assert_eq!(h.tasks.cached(ip), Some(None));
            }
        }
        drop(h);
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod queue_regression {
    use super::*;
    #[test]
    fn queue_full_preserves_existing_request_for_cancel_and_completion() {
        let mut h = Hosts::new(PathBuf::from("nonexistent"));
        let ip = "127.0.0.1".parse().unwrap();
        // Fill the completion channel (5), block the worker's sixth completion,
        // and leave the seventh request queued. No tool or network is started.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut sent = 0;
        while sent < 7 && std::time::Instant::now() < deadline {
            if h.tasks
                .submit(
                    Kind::Nmap,
                    Task {
                        id: sent,
                        ip,
                        request: None,
                        cancel: Arc::new(AtomicBool::new(false)),
                    },
                )
                .is_ok()
            {
                sent += 1;
            } else {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        assert_eq!(sent, 7);
        let old = Arc::new(AtomicBool::new(false));
        h.pending.insert(
            (ip, Kind::Nmap),
            Pending {
                id: 100,
                cancel: old.clone(),
            },
        );
        assert!(
            h.launch(
                ip,
                Kind::Nmap,
                Some(Request::new("127.0.0.1", vec![80]).unwrap())
            )
            .is_err()
        );
        assert!(
            h.pending.contains_key(&(ip, Kind::Nmap)),
            "old request lost on queue-full"
        );
        assert!(!old.load(Ordering::Acquire));
    }
}

#[cfg(test)]
mod persistence_regression {
    use super::*;
    use studio_inspection::tasks::Completion;
    use studio_protocol::*;
    #[test]
    fn failed_save_does_not_discard_other_host_completions() {
        let dir =
            std::env::temp_dir().join(format!("studio-host-save-{}", id_text(new_id().unwrap())));
        let mut db = Store::open(&dir).unwrap();
        let scan = [1; 16];
        db.begin(scan, [2; 16], &Job::example(Backend::Simulation), false)
            .unwrap();
        let ips = ["198.18.0.2", "198.18.0.3"];
        db.apply(&Envelope::new(
            [3; 16],
            scan,
            [2; 16],
            1,
            Event::Results(
                ips.iter()
                    .map(|s| Row {
                        ip: s.to_string(),
                        port: 8000,
                        open: true,
                    })
                    .collect(),
            ),
        ))
        .unwrap();
        let mut h = Hosts::new(dir.join("missing"));
        h.select(scan, Backend::MacFeth, &mut db).unwrap();
        let mut events = Vec::new();
        for (i, ip) in ips.iter().enumerate() {
            let ip: Ipv4Addr = ip.parse().unwrap();
            let mut info = HostInfo::new(ip.to_string());
            info.dns_state = CheckState::Pending;
            db.save_host(scan, &info).unwrap();
            h.info.insert(ip.to_string(), info);
            h.pending.insert(
                (ip, Kind::Dns),
                Pending {
                    id: i as u64,
                    cancel: Arc::new(AtomicBool::new(false)),
                },
            );
            events.push(Completion {
                id: i as u64,
                ip,
                kind: Kind::Dns,
                outcome: Outcome::Dns(Ok(Some(format!("host{i}.local")))),
            });
        }
        let sql = rusqlite::Connection::open(dir.join("history.sqlite3")).unwrap();
        sql.execute_batch("CREATE TRIGGER fail_first_host BEFORE INSERT ON host_details WHEN NEW.ip='198.18.0.2' BEGIN SELECT RAISE(ABORT,'injected disk failure'); END;").unwrap();
        let result = h.receive(events, &mut db).unwrap();
        assert_eq!(result.len(), 2);
        assert!(h.pending.is_empty());
        assert_eq!(result[0].dns_state, CheckState::Failed);
        assert!(result[0].dns_error.contains("save"));
        assert_eq!(result[0].hostname, None);
        assert_eq!(result[1].dns_state, CheckState::Complete);
        assert_eq!(
            db.hosts(scan)
                .unwrap()
                .into_iter()
                .find(|h| h.ip == ips[1])
                .unwrap()
                .hostname,
            Some("host1.local".into())
        );
        drop(sql);
        drop(h);
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
