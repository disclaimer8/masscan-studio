//! Five bounded workers: four DNS, one Nmap. Dropping the manager cancels and
//! reaps running subprocesses; queued jobs are discarded without execution.
use crate::{Inspection, Request, Result};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Dns,
    Nmap,
}
pub enum Outcome {
    Dns(Result<Option<String>>),
    Nmap(Result<Inspection>),
}
pub struct Completion {
    pub id: u64,
    pub ip: Ipv4Addr,
    pub kind: Kind,
    pub outcome: Outcome,
}
pub struct Task {
    pub id: u64,
    pub ip: Ipv4Addr,
    pub request: Option<Request>,
    pub cancel: Arc<AtomicBool>,
}
pub struct Tasks {
    dns: Option<mpsc::SyncSender<Task>>,
    nmap: Option<mpsc::SyncSender<Task>>,
    events: Option<mpsc::Receiver<Completion>>,
    stop: Arc<AtomicBool>,
    active: Arc<Mutex<Vec<Arc<AtomicBool>>>>,
    workers: Vec<thread::JoinHandle<()>>,
    cache: HashMap<Ipv4Addr, (Instant, Option<String>)>,
}
impl Tasks {
    pub fn new(resolver: PathBuf, nmap: Option<PathBuf>) -> Self {
        let (tx, events) = mpsc::sync_channel(5);
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(Mutex::new(Vec::new()));
        let mut workers = Vec::new();
        let mut start = |kind, exe: Option<PathBuf>, count, capacity| {
            let (jobs, rx) = mpsc::sync_channel::<Task>(capacity);
            let rx = Arc::new(Mutex::new(rx));
            for _ in 0..count {
                let (rx, tx, stop, active, exe) = (
                    rx.clone(),
                    tx.clone(),
                    stop.clone(),
                    active.clone(),
                    exe.clone(),
                );
                workers.push(thread::spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        let task = match rx.lock().unwrap().recv_timeout(Duration::from_millis(50))
                        {
                            Ok(t) => t,
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(_) => break,
                        };
                        {
                            let mut running = active.lock().unwrap();
                            if stop.load(Ordering::Acquire) {
                                break;
                            }
                            running.push(task.cancel.clone());
                        }
                        let outcome = match kind {
                            Kind::Dns => Outcome::Dns(match &exe {
                                Some(p) => crate::process::resolve(p, task.ip, &task.cancel),
                                None => Err("DNS worker is unavailable".into()),
                            }),
                            Kind::Nmap => Outcome::Nmap(match (&exe, &task.request) {
                                (Some(p), Some(r)) => crate::process::inspect(p, r, &task.cancel),
                                _ => {
                                    Err("Nmap was not found. Install Nmap and restart Studio."
                                        .into())
                                }
                            }),
                        };
                        active
                            .lock()
                            .unwrap()
                            .retain(|c| !Arc::ptr_eq(c, &task.cancel));
                        if tx
                            .send(Completion {
                                id: task.id,
                                ip: task.ip,
                                kind,
                                outcome,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                }));
            }
            jobs
        };
        let dns = start(Kind::Dns, Some(resolver), 4, 512);
        let nmap = start(Kind::Nmap, nmap, 1, 1);
        Self {
            dns: Some(dns),
            nmap: Some(nmap),
            events: Some(events),
            stop,
            active,
            workers,
            cache: HashMap::new(),
        }
    }
    pub fn submit(&self, kind: Kind, task: Task) -> Result<()> {
        let sender = match kind {
            Kind::Dns => self.dns.as_ref(),
            Kind::Nmap => self.nmap.as_ref(),
        }
        .ok_or("Inspection workers stopped")?;
        sender
            .try_send(task)
            .map_err(|_| "Inspection queue is full; wait or cancel the current check".into())
    }
    pub fn poll(&self) -> Vec<Completion> {
        self.events
            .as_ref()
            .map(|e| e.try_iter().collect())
            .unwrap_or_default()
    }
    pub fn cached(&self, ip: Ipv4Addr) -> Option<Option<String>> {
        self.cache
            .get(&ip)
            .filter(|(t, _)| t.elapsed() < Duration::from_secs(300))
            .map(|(_, v)| v.clone())
    }
    pub fn remember(&mut self, ip: Ipv4Addr, value: Option<String>) {
        self.cache
            .retain(|_, (t, _)| t.elapsed() < Duration::from_secs(300));
        if self.cache.len() >= 512 {
            self.cache.clear();
        }
        self.cache.insert(ip, (Instant::now(), value));
    }
}
impl Drop for Tasks {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for f in self.active.lock().unwrap().iter() {
            f.store(true, Ordering::Release);
        }
        self.dns.take();
        self.nmap.take();
        self.events.take();
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
    }
}
