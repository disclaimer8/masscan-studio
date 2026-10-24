//! Живые испытания Windows-адаптера через ПУБЛИЧНЫЙ API и общий runtime
//! (`open_explicit` + `Engine`) на лабораторном NIC. Каждый тест `#[ignore]`
//! и требует окружения; без него он ПАДАЕТ как «NOT RUN», а не проходит молча.
//! В обычном `cargo test` и CI пакетов нет.
//!
//! Окружение (все обязательны, кроме помеченных):
//!   RMASSCAN_NPCAP_LAB_DEVICE      `\Device\NPF_{GUID}` лабораторного NIC
//!   RMASSCAN_NPCAP_LAB_SRC_MAC     MAC этого NIC (СВЕРЯЕТСЯ с ОС до отправки)
//!   RMASSCAN_NPCAP_LAB_PEER_MAC    MAC Linux-пира (lab0)
//!   RMASSCAN_NPCAP_OUT_DIR         каталог для CSV/KV
//!   RMASSCAN_NPCAP_LAB_OPEN_PORTS  порты пира с listener, через запятую
//!   RMASSCAN_NPCAP_LAB_CLOSED_PORTS порты пира без listener (отвечают RST)
//!   RMASSCAN_NPCAP_COND            метка условия (необязательно)
//!   RMASSCAN_NPCAP_START_AT / _DOWN_AT / _UP_AT / _TOTAL_MS  (epoch мс; для
//!   испытаний потери линка, линк переключает внешний оркестратор по QMP)
//!
//! Защита: каждый кадр, уходящий через runtime, проходит `GuardTx`
//! (dst MAC = пир, src MAC = лабораторный NIC, IPv4 dst = 198.18.0.2). Цели
//! планов только 198.18.0.2. Управляющий NIC нигде не называется.
#![cfg(windows)]

#[path = "support/lab_nic.rs"]
mod lab_nic;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::{LinkType, TcpSynTemplate};
use rmasscan_core::probe::{AdapterBinding, ReadyPlan};
use rmasscan_core::receive::{PortStatus, Reply};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_engine::{
    AdapterPair, CancelHandle, Checkpoint, Engine, EngineHandle, EngineOptions, Event, FailReason,
    IoError, Outcome, Reason, SendStatus, Tx,
};
use rmasscan_net::{NetStats, open_explicit};

const SRC_IP: u32 = 0xC612_0001; // 198.18.0.1
const DST_IP: u32 = 0xC612_0002; // 198.18.0.2
const SEED: u64 = 0x5eed_0b5e_55ed;

// ---------- окружение ----------

fn need(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("NOT RUN: environment variable {name} is not set"))
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

fn parse_mac(s: &str) -> [u8; 6] {
    let v: Vec<u8> = s
        .split([':', '-'])
        .map(|p| u8::from_str_radix(p, 16).expect("bad MAC"))
        .collect();
    v.try_into().expect("MAC needs 6 octets")
}

fn ports_of(s: &str) -> Vec<u16> {
    s.split(',')
        .filter(|p| !p.is_empty())
        .map(|p| p.trim().parse().expect("bad port"))
        .collect()
}

#[derive(Clone)]
struct Lab {
    device: String,
    src_mac: [u8; 6],
    peer_mac: [u8; 6],
    out_dir: String,
    cond: String,
}

/// Читает окружение и ДО любой отправки сверяет MAC устройства с ОС.
fn lab() -> Lab {
    let l = Lab {
        device: need("RMASSCAN_NPCAP_LAB_DEVICE"),
        src_mac: parse_mac(&need("RMASSCAN_NPCAP_LAB_SRC_MAC")),
        peer_mac: parse_mac(&need("RMASSCAN_NPCAP_LAB_PEER_MAC")),
        out_dir: need("RMASSCAN_NPCAP_OUT_DIR"),
        cond: std::env::var("RMASSCAN_NPCAP_COND").unwrap_or_else(|_| "unlabelled".into()),
    };
    lab_nic::verify_device_mac(&l.device, l.src_mac);
    l
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn kv(lab: &Lab, what: &str, body: &str) {
    println!("KV {}/{what} {body}", lab.cond);
}

fn binding(lab: &Lab) -> AdapterBinding {
    AdapterBinding {
        interface_id: lab.device.clone(),
        link_type: LinkType::Ethernet,
        source_ipv4: SRC_IP,
        source_mac: lab.src_mac,
        next_hop_mac: lab.peer_mac,
        source_ports: (40000, 40000),
    }
}

fn plan(lab: &Lab, ports: &str, rate: f64, wait: u32) -> ReadyPlan {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), "198.18.0.2").unwrap();
    parse_ports(m.ports_mut(), ports).unwrap();
    let cfg = ScanConfig {
        targets: m,
        seed: SEED,
        max_rate: rate,
        wait_secs: wait,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).unwrap();
    ReadyPlan::new(eff, binding(lab)).unwrap()
}

// ---------- защита и декораторы TX ----------

/// Единственный путь кадра в сеть: проверка лабораторных адресов.
fn assert_lab_frame(lab: &Lab, f: &[u8]) {
    assert!(f.len() >= 34, "frame too short for an IPv4 header");
    assert_eq!(f[0..6], lab.peer_mac, "dst MAC is not the lab peer");
    assert_eq!(f[6..12], lab.src_mac, "src MAC is not the lab NIC");
    assert_eq!(f[12..14], [0x08, 0x00], "not IPv4");
    assert_eq!(f[30..34], DST_IP.to_be_bytes(), "dst IP is not 198.18.0.2");
}

struct GuardTx {
    lab: Lab,
    inner: Box<dyn Tx>,
    /// Если задано: после стольких реальных отправок вернуть Uncertain, не
    /// вызывая адаптер (синтетический сбой для проверки runtime).
    uncertain_after: Option<u64>,
    /// Если задано: паника на отправке с этим номером (с нуля).
    panic_at: Option<u64>,
    n: u64,
}

impl Tx for GuardTx {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError> {
        assert_lab_frame(&self.lab, frame);
        if self.panic_at == Some(self.n) {
            panic!("injected tx panic at send #{}", self.n);
        }
        if self.uncertain_after == Some(self.n) {
            return Ok(SendStatus::Uncertain);
        }
        let r = self.inner.send(frame, timeout)?;
        if r == SendStatus::Sent {
            self.n += 1;
        }
        Ok(r)
    }
}

fn guarded(
    lab: &Lab,
    io: AdapterPair,
    uncertain_after: Option<u64>,
    panic_at: Option<u64>,
) -> AdapterPair {
    AdapterPair {
        tx: Box::new(GuardTx {
            lab: lab.clone(),
            inner: io.tx,
            uncertain_after,
            panic_at,
            n: 0,
        }),
        rx: io.rx,
    }
}

// ---------- запуск движка ----------

struct Run {
    outcome: Outcome,
    replies: Vec<Reply>,
    checkpoint: Option<Checkpoint>,
    stats_final: NetStats,
    stats_handle: rmasscan_net::NetStatsHandle,
    /// От вызова `stop`/`pause` до появления исхода, если команда подавалась.
    command_to_outcome: Option<Duration>,
    /// Прогресс (sent) в момент исхода.
    sent_at_outcome: u64,
    /// Эпоха (мс) получения `Finished`.
    finished_ms: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Command {
    None,
    StopAfter(Duration),
    PauseAfterSent(u64),
}

/// Обратный вызов раз в ~5 мс: хендл движка и время от старта.
type Tick<'a> = &'a mut dyn FnMut(&EngineHandle, Duration);

struct Spec<'a> {
    plan: &'a ReadyPlan,
    attempt: u8,
    resume: Option<Checkpoint>,
    command: Command,
    uncertain_after: Option<u64>,
    panic_at: Option<u64>,
    /// Вызывается раз в ~5 мс с прогрессом (sent) и временем от старта.
    tick: Option<Tick<'a>>,
}

impl<'a> Spec<'a> {
    fn new(plan: &'a ReadyPlan, attempt: u8) -> Self {
        Spec {
            plan,
            attempt,
            resume: None,
            command: Command::None,
            uncertain_after: None,
            panic_at: None,
            tick: None,
        }
    }
}

fn run_engine(lab: &Lab, mut spec: Spec<'_>) -> Run {
    let opened = open_explicit(spec.plan.binding()).expect("open_explicit");
    let stats = opened.stats.clone();
    let io = guarded(lab, opened.io, spec.uncertain_after, spec.panic_at);
    let opts = EngineOptions::new([7; 16], [spec.attempt; 16]);
    let started = Instant::now();
    let h = match &spec.resume {
        Some(cp) => Engine::resume(spec.plan.clone(), cp.clone(), io, opts),
        None => Engine::start(spec.plan.clone(), io, opts),
    }
    .expect("engine start");
    let cancel: Arc<OnceLock<CancelHandle>> = Arc::default();
    let _ = cancel.set(h.cancel_handle());
    let mut replies = Vec::new();
    let mut commanded_at: Option<Instant> = None;
    let mut command_to_outcome = None;
    let mut sent_at_outcome = 0;
    let mut finished_ms = 0;
    loop {
        if let Some(t) = spec.tick.as_mut() {
            t(&h, started.elapsed());
        }
        if commanded_at.is_none() {
            let sent = h.progress().sent;
            let fire = match spec.command {
                Command::None => false,
                Command::PauseAfterSent(n) => sent >= n,
                Command::StopAfter(d) => started.elapsed() >= d,
            };
            if fire {
                commanded_at = Some(Instant::now());
                match spec.command {
                    Command::PauseAfterSent(_) => h.pause(),
                    _ => h.stop(),
                }
            }
        }
        if command_to_outcome.is_none()
            && let Some(at) = commanded_at
            && h.outcome().is_some()
        {
            command_to_outcome = Some(at.elapsed());
            sent_at_outcome = h.progress().sent;
        }
        match h.recv_event_timeout(Duration::from_millis(5)) {
            Ok(Event::Results { replies: r }) => replies.extend(r),
            Ok(Event::Finished { .. }) => {
                finished_ms = now_ms();
                break;
            }
            Ok(_) => {}
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => break,
        }
    }
    let checkpoint = h.checkpoint();
    let (outcome, rest) = h.join_drain().expect("join");
    for ev in rest {
        if let Event::Results { replies: r } = ev {
            replies.extend(r);
        }
    }
    Run {
        outcome,
        replies,
        checkpoint,
        stats_final: stats.snapshot(),
        stats_handle: stats,
        command_to_outcome,
        sent_at_outcome,
        finished_ms,
    }
}

fn summarize(lab: &Lab, what: &str, r: &Run) {
    let s = &r.stats_final;
    kv(
        lab,
        what,
        &format!(
            "reason={:?} sent={} next_index={} received={} discarded={} duplicates={} \
             rx_health={:?} net.tx_sent={} net.tx_uncertain={} net.tx_errors={} \
             net.rx_packets={} net.rx_outgoing={} net.rx_truncated={} net.rx_errors={} \
             net.kernel_drops={:?} command_to_outcome_ms={:?} checkpoint={}",
            r.outcome.reason,
            r.outcome.progress.sent,
            r.outcome.progress.next_index,
            r.outcome.progress.received,
            r.outcome.progress.discarded,
            r.outcome.progress.duplicates,
            r.outcome.rx_health.kernel_drops,
            s.tx_sent,
            s.tx_uncertain,
            s.tx_errors,
            s.rx_packets,
            s.rx_outgoing,
            s.rx_truncated,
            s.rx_errors,
            s.kernel_drops,
            r.command_to_outcome.map(|d| d.as_secs_f64() * 1000.0),
            r.checkpoint.is_some(),
        ),
    );
}

/// Ничего не уходит после исхода: счётчик TX не меняется за окно наблюдения.
fn assert_silent_after(
    lab: &Lab,
    what: &str,
    stats: &rmasscan_net::NetStatsHandle,
    window: Duration,
) {
    let before = stats.snapshot().tx_sent;
    std::thread::sleep(window);
    let after = stats.snapshot().tx_sent;
    kv(
        lab,
        what,
        &format!(
            "tx_sent_before={before} tx_sent_after={after} window_ms={}",
            window.as_millis()
        ),
    );
    assert_eq!(before, after, "a send happened after the run ended");
}

// ---------- статистика задержек ----------

#[derive(Default)]
struct Lat {
    us: Vec<u64>,
}

impl Lat {
    fn push(&mut self, d: Duration) {
        self.us.push(d.as_micros() as u64);
    }
    fn pct(&self, p: f64) -> u64 {
        let mut s = self.us.clone();
        s.sort_unstable();
        if s.is_empty() {
            return 0;
        }
        s[((s.len() as f64 - 1.0) * p).round() as usize]
    }
    fn max(&self) -> u64 {
        self.us.iter().copied().max().unwrap_or(0)
    }
    fn over(&self, limit: Duration) -> usize {
        self.us
            .iter()
            .filter(|u| **u > limit.as_micros() as u64)
            .count()
    }
    fn line(&self, label: &str) -> String {
        format!(
            "{label} n={} p50_us={} p95_us={} p99_us={} max_us={} over50ms={}",
            self.us.len(),
            self.pct(0.5),
            self.pct(0.95),
            self.pct(0.99),
            self.max(),
            self.over(Duration::from_millis(50)),
        )
    }
}

fn write_csv(lab: &Lab, name: &str, rows: &str) {
    let path = format!("{}\\{}__{name}.csv", lab.out_dir, lab.cond);
    std::fs::write(&path, rows).unwrap_or_else(|e| panic!("cannot write {path}: {e}"));
}

// =====================================================================
// Малый настоящий скан до пира: SYN наружу, SYN-ACK/RST внутрь, результаты
// =====================================================================

#[test]
#[ignore = "live: needs the lab NIC and a peer with listeners (see module docs)"]
fn live_scan_small_with_results() {
    let lab = lab();
    let open = ports_of(&need("RMASSCAN_NPCAP_LAB_OPEN_PORTS"));
    let closed = ports_of(&need("RMASSCAN_NPCAP_LAB_CLOSED_PORTS"));
    let mut all: Vec<u16> = open.iter().chain(closed.iter()).copied().collect();
    all.sort_unstable();
    let list = all.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    let p = plan(&lab, &list, 100.0, 3);
    for round in 0..2u8 {
        let r = run_engine(&lab, Spec::new(&p, 2 + round));
        summarize(&lab, &format!("scan_small_round{round}"), &r);
        assert_eq!(r.outcome.reason, Reason::Completed, "{:?}", r.outcome);
        assert_eq!(r.outcome.progress.sent, all.len() as u64);
        assert_eq!(r.stats_final.tx_sent, all.len() as u64);
        assert_eq!(r.stats_final.tx_uncertain, 0);
        // Подтверждённый ноль потерь очереди NPF, из движка и из счётчиков.
        assert_eq!(r.outcome.rx_health.kernel_drops, Some(0));
        assert_eq!(r.stats_final.kernel_drops, Some(0));
        let mut got: BTreeMap<u16, PortStatus> = BTreeMap::new();
        for rep in &r.replies {
            assert_eq!(rep.remote_ip, DST_IP);
            got.insert(rep.remote_port, rep.status);
        }
        for port in &open {
            assert_eq!(
                got.get(port),
                Some(&PortStatus::Open),
                "port {port} must be SYN-ACK"
            );
        }
        for port in &closed {
            assert_eq!(
                got.get(port),
                Some(&PortStatus::Closed),
                "port {port} must be RST"
            );
        }
        assert_eq!(got.len(), all.len());
    }
}

// =====================================================================
// Stop, Pause/Resume, Uncertain, panic через общий runtime
// =====================================================================

#[test]
#[ignore = "live: needs the lab NIC and a peer (see module docs)"]
fn live_stop_is_prompt_and_nothing_is_sent_afterwards() {
    let lab = lab();
    let p = plan(&lab, "1-2000", 300.0, 3);
    let mut spec = Spec::new(&p, 2);
    spec.command = Command::StopAfter(Duration::from_millis(1500));
    let r = run_engine(&lab, spec);
    summarize(&lab, "stop", &r);
    assert_eq!(r.outcome.reason, Reason::Stopped, "{:?}", r.outcome);
    let d = r.command_to_outcome.expect("stop was commanded");
    assert!(d < Duration::from_secs(1), "Stop took {d:?}");
    assert!(r.outcome.progress.sent > 100 && r.outcome.progress.sent < 2000);
    assert_eq!(r.stats_final.tx_sent, r.outcome.progress.sent);
    assert_eq!(r.outcome.rx_health.kernel_drops, Some(0));
    // Ничего не уходит после исхода; число SYN у пира сверяет оркестратор.
    assert_silent_after(
        &lab,
        "stop_silence",
        &r.stats_handle,
        Duration::from_millis(700),
    );
}

#[test]
#[ignore = "live: needs the lab NIC and a peer (see module docs)"]
fn live_pause_stops_tx_then_resume_completes_without_duplicates() {
    let lab = lab();
    let p = plan(&lab, "9000-9011", 10.0, 3);
    let leg1 = run_engine(&lab, {
        let mut s = Spec::new(&p, 2);
        s.command = Command::PauseAfterSent(4);
        s
    });
    summarize(&lab, "pause_leg1", &leg1);
    assert_eq!(leg1.outcome.reason, Reason::Paused, "{:?}", leg1.outcome);
    let d = leg1.command_to_outcome.expect("pause was commanded");
    kv(
        &lab,
        "pause_command_to_outcome",
        &format!("ms={}", d.as_millis()),
    );
    assert!(
        d < Duration::from_secs(3 + 1),
        "pause + RX drain wait=3 must finish within 4 s, took {d:?}"
    );
    let cp = leg1
        .checkpoint
        .clone()
        .expect("paused run has a checkpoint");
    assert_eq!(cp.next_index, leg1.outcome.progress.sent);
    assert_eq!(leg1.stats_final.tx_sent, leg1.outcome.progress.sent);
    assert_eq!(leg1.outcome.rx_health.kernel_drops, Some(0));
    // TX остановился не позже 1 с после команды: sent на момент исхода уже
    // равен итоговому (в окно drain ничего не уходило).
    assert_eq!(leg1.sent_at_outcome, leg1.outcome.progress.sent);

    let leg2 = run_engine(&lab, {
        let mut s = Spec::new(&p, 3);
        s.resume = Some(cp.clone());
        s
    });
    summarize(&lab, "pause_leg2", &leg2);
    assert_eq!(leg2.outcome.reason, Reason::Completed, "{:?}", leg2.outcome);
    assert_eq!(
        leg1.stats_final.tx_sent + leg2.stats_final.tx_sent,
        12,
        "exactly one send per probe across both legs"
    );
    let mut ports: Vec<u16> = leg1
        .replies
        .iter()
        .chain(leg2.replies.iter())
        .map(|r| r.remote_port)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    assert_eq!(ports, (9000..=9011).collect::<Vec<u16>>());
}

#[test]
#[ignore = "live: needs the lab NIC and a peer (see module docs)"]
fn live_uncertain_send_fails_without_checkpoint_or_further_sends() {
    let lab = lab();
    let p = plan(&lab, "9100-9119", 100.0, 3);
    let r = run_engine(&lab, {
        let mut s = Spec::new(&p, 2);
        s.uncertain_after = Some(3);
        s
    });
    summarize(&lab, "uncertain", &r);
    assert_eq!(
        r.outcome.reason,
        Reason::Failed(FailReason::TxUncertain),
        "{:?}",
        r.outcome
    );
    assert_eq!(r.outcome.progress.sent, 3);
    assert_eq!(r.stats_final.tx_sent, 3);
    assert!(r.checkpoint.is_none(), "Uncertain forbids a checkpoint");
    assert_silent_after(
        &lab,
        "uncertain_silence",
        &r.stats_handle,
        Duration::from_millis(500),
    );
}

#[test]
#[ignore = "live: needs the lab NIC and a peer (see module docs)"]
fn live_worker_panic_ends_the_run_and_the_adapter_is_usable_again() {
    let lab = lab();
    let p = plan(&lab, "9200-9219", 100.0, 3);
    let r = run_engine(&lab, {
        let mut s = Spec::new(&p, 2);
        s.panic_at = Some(3);
        s
    });
    summarize(&lab, "panic", &r);
    assert_eq!(
        r.outcome.reason,
        Reason::Failed(FailReason::WorkerPanicked),
        "{:?}",
        r.outcome
    );
    assert!(r.checkpoint.is_none());
    assert_eq!(r.stats_final.tx_sent, 3);
    assert_silent_after(
        &lab,
        "panic_silence",
        &r.stats_handle,
        Duration::from_millis(500),
    );
    // К моменту Finished handle RX закрыт: итог потерь зафиксирован.
    assert!(r.stats_final.kernel_drops.is_some());
    // Следом адаптер снова открывается и скан завершается.
    let p2 = plan(&lab, "9300-9303", 100.0, 3);
    let r2 = run_engine(&lab, Spec::new(&p2, 3));
    summarize(&lab, "panic_followup", &r2);
    assert_eq!(r2.outcome.reason, Reason::Completed, "{:?}", r2.outcome);
}

#[test]
#[ignore = "live: needs the lab NIC, a peer and a peer-side flood (see module docs)"]
fn live_scan_under_junk_flood_is_honest_about_loss() {
    let lab = lab();
    // Пир заливает NIC мусором (ethertype 0x88b5) на время скана; результат
    // обязан быть честным: либо Completed с подтверждённым Some(0), либо Failed
    // с RxLoss и тем же ненулевым счётом. Completed при потерях недопустим.
    let p = plan(&lab, "1-400", 100.0, 3);
    let r = run_engine(&lab, Spec::new(&p, 2));
    summarize(&lab, "scan_under_flood", &r);
    let final_drops = r.stats_final.kernel_drops.expect("drops are measured");
    match &r.outcome.reason {
        Reason::Completed => {
            assert_eq!(r.outcome.rx_health.kernel_drops, Some(0));
            assert_eq!(
                final_drops, 0,
                "Completed although the NPF queue dropped frames"
            );
        }
        Reason::Failed(FailReason::RxLoss { kernel_drops }) => {
            assert!(*kernel_drops > 0);
            assert!(final_drops >= *kernel_drops);
            assert!(r.checkpoint.is_none());
        }
        other => panic!("unexpected outcome {other:?}"),
    }
}

// =====================================================================
// Свои TX-кадры не доходят до RX; SYN-ACK/RST пира проходят
// =====================================================================

fn tcp_flags(f: &[u8]) -> Option<u8> {
    (f.len() >= 14 + 20 + 14 && f[12..14] == [0x08, 0x00] && f[23] == 6).then(|| {
        let ihl = usize::from(f[14] & 0x0f) * 4;
        f[14 + ihl + 13]
    })
}

#[test]
#[ignore = "live: needs the lab NIC and a peer with listeners (see module docs)"]
fn live_own_tx_never_reaches_rx_and_peer_replies_do() {
    let lab = lab();
    let open = ports_of(&need("RMASSCAN_NPCAP_LAB_OPEN_PORTS"));
    let closed = ports_of(&need("RMASSCAN_NPCAP_LAB_CLOSED_PORTS"));
    let opened = open_explicit(&binding(&lab)).expect("open_explicit");
    let stats = opened.stats.clone();
    let AdapterPair { mut tx, mut rx } = opened.io;
    let tpl = TcpSynTemplate::new(lab.src_mac, lab.peer_mac, LinkType::Ethernet);
    let mut buf = vec![0u8; 2048];
    let (mut own, mut synack, mut rst, mut other) = (0u32, 0u32, 0u32, 0u32);
    let mut f = Vec::new();
    for i in 0..40u32 {
        let port = if i % 2 == 0 { open[0] } else { closed[0] };
        tpl.build_syn(DST_IP, port, SRC_IP, 41_000 + i as u16, 0x1000 + i, &mut f);
        assert_lab_frame(&lab, &f);
        assert_eq!(
            tx.send(&f, Duration::from_millis(50)).unwrap(),
            SendStatus::Sent
        );
        let until = Instant::now() + Duration::from_millis(60);
        while Instant::now() < until {
            if let Some(n) = rx.recv(&mut buf, Duration::from_millis(50)).unwrap() {
                let fr = &buf[..n];
                if n >= 12 && fr[6..12] == lab.src_mac {
                    own += 1;
                } else if let Some(fl) = tcp_flags(fr) {
                    match fl & 0x17 {
                        0x12 => synack += 1,
                        x if x & 0x04 != 0 => rst += 1,
                        _ => other += 1,
                    }
                } else {
                    other += 1;
                }
            }
        }
    }
    let s = stats.snapshot();
    kv(
        &lab,
        "own_tx_filter",
        &format!(
            "own_frames_returned={own} synack={synack} rst={rst} other={other} \
             net.rx_outgoing={} net.rx_packets={} net.tx_sent={}",
            s.rx_outgoing, s.rx_packets, s.tx_sent
        ),
    );
    assert_eq!(own, 0, "a frame with our own source MAC reached the caller");
    assert!(synack >= 10, "peer SYN-ACKs were filtered: {synack}");
    assert!(rst >= 10, "peer RSTs were filtered: {rst}");
    assert_eq!(s.tx_sent, 40);
}

// =====================================================================
// Реальный бюджетированный вызов: p50/p95/max recv / health / send
// =====================================================================

#[test]
#[ignore = "live: needs the lab NIC (see module docs)"]
fn live_budgeted_calls() {
    let lab = lab();
    let opened = open_explicit(&binding(&lab)).expect("open_explicit");
    let stats = opened.stats.clone();
    let AdapterPair { mut tx, mut rx } = opened.io;
    let tpl = TcpSynTemplate::new(lab.src_mac, lab.peer_mac, LinkType::Ethernet);
    let recv_calls = env_u64("RMASSCAN_NPCAP_RECV_CALLS").unwrap_or(600) as usize;
    let mut buf = vec![0u8; 2048];
    let (mut recv_empty, mut recv_frame, mut health, mut send) = (
        Lat::default(),
        Lat::default(),
        Lat::default(),
        Lat::default(),
    );
    let mut rows = String::from("t_epoch_ms,op,dur_us,result\n");
    let mut frames = 0u64;
    let mut f = Vec::new();
    for i in 0..recv_calls {
        let t = now_ms();
        let t0 = Instant::now();
        let r = rx.recv(&mut buf, Duration::from_millis(50)).expect("recv");
        let d = t0.elapsed();
        match r {
            Some(n) => {
                recv_frame.push(d);
                frames += 1;
                let _ = writeln!(rows, "{t},recv_frame,{},{n}", d.as_micros());
            }
            None => {
                recv_empty.push(d);
                let _ = writeln!(rows, "{t},recv_empty,{},", d.as_micros());
            }
        }
        if i % 2 == 0 {
            let t = now_ms();
            let t0 = Instant::now();
            let h = rx.health(Duration::from_millis(50)).expect("health");
            let d = t0.elapsed();
            health.push(d);
            let _ = writeln!(rows, "{t},health,{},{:?}", d.as_micros(), h.kernel_drops);
        }
        if i % 4 == 0 {
            tpl.build_syn(
                DST_IP,
                9400 + (i % 50) as u16,
                SRC_IP,
                42_000,
                i as u32,
                &mut f,
            );
            assert_lab_frame(&lab, &f);
            let t = now_ms();
            let t0 = Instant::now();
            let st = tx.send(&f, Duration::from_millis(50)).expect("send");
            let d = t0.elapsed();
            send.push(d);
            let _ = writeln!(rows, "{t},send,{},{st:?}", d.as_micros());
            assert_eq!(st, SendStatus::Sent);
        }
    }
    write_csv(&lab, "budgeted_calls", &rows);
    kv(&lab, "budgeted_recv_empty", &recv_empty.line("recv_empty"));
    kv(&lab, "budgeted_recv_frame", &recv_frame.line("recv_frame"));
    kv(&lab, "budgeted_health", &health.line("health"));
    kv(&lab, "budgeted_send", &send.line("send"));
    let s = stats.snapshot();
    kv(
        &lab,
        "budgeted_stats",
        &format!("frames_returned={frames} {s:?}"),
    );
    // Контракт 50 мс не повышается; срывы планировщика сверх бюджета считаются
    // с тем же запасом, что в тестах Linux (< 100 мс).
    for (label, l) in [
        ("recv_empty", &recv_empty),
        ("recv_frame", &recv_frame),
        ("health", &health),
        ("send", &send),
    ] {
        assert!(
            l.max() < 100_000,
            "{label}: a call took {} us (slack limit 100 ms)",
            l.max()
        );
    }
    assert!(s.kernel_drops.is_some());
}

// =====================================================================
// Потеря линка гостя (QMP set_link выполняет оркестратор)
// =====================================================================

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Phase {
    Before,
    Down,
    After,
}

fn phase_at(t: u64, down: u64, up: u64) -> Phase {
    if t < down {
        Phase::Before
    } else if t < up {
        Phase::Down
    } else {
        Phase::After
    }
}

/// Ждёт эпоху `t` и отмечает прогресс, чтобы сторож не принял ожидание за
/// зависший вызов адаптера.
fn sleep_until_epoch_ms(t: u64, progress: &AtomicU64) {
    loop {
        progress.fetch_add(1, Ordering::Relaxed);
        let n = now_ms();
        if n >= t {
            return;
        }
        std::thread::sleep(Duration::from_millis((t - n).min(100)));
    }
}

/// Сторожевой поток: зависший вызов адаптера не должен держать стенд.
fn watchdog(progress: Arc<AtomicU64>, label: &'static str) {
    std::thread::spawn(move || {
        let mut last = progress.load(Ordering::Relaxed);
        let mut since = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let cur = progress.load(Ordering::Relaxed);
            if cur != last {
                last = cur;
                since = Instant::now();
            } else if since.elapsed() > Duration::from_secs(8) {
                println!(
                    "KV HANG {label}: no adapter call completed for 8 s; exiting the test process"
                );
                std::process::exit(99);
            }
        }
    });
}

#[test]
#[ignore = "live: needs the lab NIC and an external link toggle (see module docs)"]
fn live_link_loss_raw_calls() {
    let lab = lab();
    let start = env_u64("RMASSCAN_NPCAP_START_AT").expect("NOT RUN: RMASSCAN_NPCAP_START_AT");
    let down = env_u64("RMASSCAN_NPCAP_DOWN_AT").expect("NOT RUN: RMASSCAN_NPCAP_DOWN_AT");
    let up = env_u64("RMASSCAN_NPCAP_UP_AT").expect("NOT RUN: RMASSCAN_NPCAP_UP_AT");
    let total = env_u64("RMASSCAN_NPCAP_TOTAL_MS").unwrap_or(30_000);
    let opened = open_explicit(&binding(&lab)).expect("open_explicit");
    let stats = opened.stats.clone();
    let AdapterPair { mut tx, mut rx } = opened.io;
    let tpl = TcpSynTemplate::new(lab.src_mac, lab.peer_mac, LinkType::Ethernet);
    let progress = Arc::new(AtomicU64::new(0));
    watchdog(progress.clone(), "raw calls");
    sleep_until_epoch_ms(start, &progress);
    let mut rows = String::from("t_epoch_ms,phase,op,dur_us,result\n");
    let mut lat: BTreeMap<(Phase, &'static str), Lat> = BTreeMap::new();
    let mut results: BTreeMap<(Phase, &'static str, String), u64> = BTreeMap::new();
    let mut first_errors: Vec<String> = Vec::new();
    let mut buf = vec![0u8; 2048];
    let mut f = Vec::new();
    let mut i = 0u32;
    let mut last_health = 0u64;
    let end = start + total;
    while now_ms() < end {
        i += 1;
        // send
        tpl.build_syn(DST_IP, 9500 + (i % 50) as u16, SRC_IP, 43_000, i, &mut f);
        assert_lab_frame(&lab, &f);
        let t = now_ms();
        let ph = phase_at(t, down, up);
        let t0 = Instant::now();
        let r = tx.send(&f, Duration::from_millis(50));
        let d = t0.elapsed();
        progress.fetch_add(1, Ordering::Relaxed);
        let res = match &r {
            Ok(st) => format!("{st:?}"),
            Err(e) => {
                if first_errors.len() < 5 {
                    first_errors.push(format!("send: {}", e.message));
                }
                "IoError".into()
            }
        };
        lat.entry((ph, "send")).or_default().push(d);
        *results.entry((ph, "send", res.clone())).or_default() += 1;
        let _ = writeln!(rows, "{t},{ph:?},send,{},{res}", d.as_micros());
        // recv
        let t = now_ms();
        let ph = phase_at(t, down, up);
        let t0 = Instant::now();
        let r = rx.recv(&mut buf, Duration::from_millis(50));
        let d = t0.elapsed();
        progress.fetch_add(1, Ordering::Relaxed);
        let res = match &r {
            Ok(Some(_)) => "frame".to_string(),
            Ok(None) => "empty".to_string(),
            Err(e) => {
                if first_errors.len() < 5 {
                    first_errors.push(format!("recv: {}", e.message));
                }
                "IoError".into()
            }
        };
        lat.entry((ph, "recv")).or_default().push(d);
        *results.entry((ph, "recv", res.clone())).or_default() += 1;
        let _ = writeln!(rows, "{t},{ph:?},recv,{},{res}", d.as_micros());
        // health (каждые 250 мс, как движок)
        let t = now_ms();
        if t >= last_health + 250 {
            last_health = t;
            let ph = phase_at(t, down, up);
            let t0 = Instant::now();
            let r = rx.health(Duration::from_millis(50));
            let d = t0.elapsed();
            progress.fetch_add(1, Ordering::Relaxed);
            let res = match &r {
                Ok(h) => format!("{:?}", h.kernel_drops),
                Err(e) => {
                    if first_errors.len() < 5 {
                        first_errors.push(format!("health: {}", e.message));
                    }
                    "Err".into()
                }
            };
            lat.entry((ph, "health")).or_default().push(d);
            *results.entry((ph, "health", res.clone())).or_default() += 1;
            let _ = writeln!(rows, "{t},{ph:?},health,{},{res}", d.as_micros());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    write_csv(&lab, "link_loss_raw", &rows);
    for ((ph, op), l) in &lat {
        kv(&lab, &format!("link_{ph:?}_{op}"), &l.line(op));
    }
    for ((ph, op, res), n) in &results {
        kv(
            &lab,
            &format!("link_results_{ph:?}_{op}"),
            &format!("{res}={n}"),
        );
    }
    for e in &first_errors {
        kv(&lab, "link_first_error", e);
    }
    kv(&lab, "link_final_stats", &format!("{:?}", stats.snapshot()));
    let worst = lat.values().map(Lat::max).max().unwrap_or(0);
    assert!(
        worst < 100_000,
        "a call took {worst} us (slack limit 100 ms)"
    );
}

#[test]
#[ignore = "live: needs the lab NIC and an external link toggle (see module docs)"]
fn live_link_loss_engine_stop() {
    let lab = lab();
    let start = env_u64("RMASSCAN_NPCAP_START_AT").expect("NOT RUN: RMASSCAN_NPCAP_START_AT");
    let down = env_u64("RMASSCAN_NPCAP_DOWN_AT").expect("NOT RUN: RMASSCAN_NPCAP_DOWN_AT");
    let up = env_u64("RMASSCAN_NPCAP_UP_AT").expect("NOT RUN: RMASSCAN_NPCAP_UP_AT");
    let progress = Arc::new(AtomicU64::new(0));
    watchdog(progress.clone(), "engine stop");
    sleep_until_epoch_ms(start, &progress);
    // Скан идёт через потерю линка; Stop подаётся, когда линк уже лежит.
    let p = plan(&lab, "1-3000", 100.0, 3);
    let stop_at = down + 4_000;
    let mut samples = String::from("t_epoch_ms,phase,sent,received,discarded\n");
    let mut tick = |h: &EngineHandle, _e: Duration| {
        progress.fetch_add(1, Ordering::Relaxed);
        let t = now_ms();
        let pr = h.progress();
        let _ = writeln!(
            samples,
            "{t},{:?},{},{},{}",
            phase_at(t, down, up),
            pr.sent,
            pr.received,
            pr.discarded
        );
    };
    let mut spec = Spec::new(&p, 2);
    spec.tick = Some(&mut tick);
    // Время Stop задаётся по эпохе: StopAfter считает от старта прогона.
    let run_started_ms = now_ms();
    spec.command = Command::StopAfter(Duration::from_millis(
        stop_at.saturating_sub(run_started_ms),
    ));
    let r = run_engine(&lab, spec);
    write_csv(&lab, "link_loss_engine_progress", &samples);
    summarize(&lab, "link_engine_stop", &r);
    // Потеря линка: pcap_sendpacket сразу возвращает ошибку, адаптер отдаёт
    // Uncertain, и движок падает без checkpoint ДО подачи Stop. Если бы Stop
    // успел раньше, он обязан уложиться в 1 с.
    match &r.outcome.reason {
        Reason::Failed(FailReason::TxUncertain) => {
            let lag = r.finished_ms.saturating_sub(down);
            kv(&lab, "link_engine_detect_ms", &format!("{lag}"));
            assert!(lag < 1_000, "link loss was noticed after {lag} ms");
            assert!(r.checkpoint.is_none());
        }
        Reason::Stopped => {
            let d = r.command_to_outcome.expect("stop was commanded");
            assert!(
                d < Duration::from_secs(1),
                "Stop under link loss took {d:?}"
            );
        }
        other => panic!("unexpected outcome under link loss: {other:?}"),
    }
    assert_silent_after(
        &lab,
        "link_engine_silence",
        &r.stats_handle,
        Duration::from_millis(500),
    );
    // Дождаться возврата линка и убедиться, что адаптер снова рабочий.
    sleep_until_epoch_ms(up + 3_000, &progress);
    let p2 = plan(&lab, "9600-9603", 100.0, 3);
    let r2 = run_engine(&lab, Spec::new(&p2, 3));
    summarize(&lab, "link_engine_after_restore", &r2);
    assert_eq!(r2.outcome.reason, Reason::Completed, "{:?}", r2.outcome);
    assert_eq!(r2.replies.len(), 4, "the restored link must answer");
}
