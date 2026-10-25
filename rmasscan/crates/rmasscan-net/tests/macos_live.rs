//! Живые испытания macOS-адаптера через ПУБЛИЧНЫЙ API и общий runtime
//! (`open_explicit` + `Engine`) на запечатанном стенде `feth4201` (сторона
//! сканера) ↔ `feth4202` (сторона пира). Каждый тест `#[ignore]` и требует
//! окружения; без него он ПАДАЕТ как «NOT RUN», а не проходит молча. В обычном
//! `cargo test` и CI пакетов нет.
//!
//! Запуск оператором на стенде (стенд поднят пользователем `macos-lab up`,
//! доступ к `/dev/bpf*` выдан `macos-lab bpf-access --grant`):
//!   cargo test --locked -p rmasscan-net --test macos_live -- --ignored
//!
//! Окружение (обе переменные обязательны):
//!   RMASSCAN_BPF_LAB_MANIFEST  манифест стенда (`$HOME/.rmasscan-lab/macos-m1.json`);
//!                              файл должен существовать
//!   RMASSCAN_BPF_OUT_DIR       каталог для KV-строк прогона
//!
//! Защита: адреса стенда фиксированы константами (`feth4201`
//! `02:ac:00:00:00:01`, пир `02:ac:00:00:00:02`, цель только `198.18.0.2`).
//! ДО любой отправки MAC `feth4201` сверяется с ОС, а каждый кадр, уходящий
//! через runtime, проходит `GuardTx`. Независимый свидетель (`tcpdump` на
//! `feth4202`) и захват uplink с ожиданием 0 кадров ведёт оператор снаружи:
//! эти тесты их не заменяют.
#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant};

use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{AdapterBinding, ReadyPlan};
use rmasscan_core::receive::{PortStatus, Reply};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_engine::{
    AdapterPair, Checkpoint, Engine, EngineHandle, EngineOptions, Event, FailReason, IoError,
    Outcome, Reason, Rx, RxHealth, SendStatus, Tx,
};
use rmasscan_net::{NetStats, NetStatsHandle, nic_mac, open_explicit};

const IFACE: &str = "feth4201";
const SRC_MAC: [u8; 6] = [0x02, 0xac, 0x00, 0x00, 0x00, 0x01];
const PEER_MAC: [u8; 6] = [0x02, 0xac, 0x00, 0x00, 0x00, 0x02];
const SRC_IP: u32 = 0xC612_0001; // 198.18.0.1
const DST_IP: u32 = 0xC612_0002; // 198.18.0.2
const SEED: u64 = 0x5eed_0b5e_55ed;
/// Порты пира с listener; остальные отвечают RST ядра.
const OPEN_PORTS: &str = "80,443,8000-8007";

// ---------- окружение ----------

fn need(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("NOT RUN: environment variable {name} is not set"))
}

struct Lab {
    out_dir: String,
    test: &'static str,
}

/// Читает окружение и ДО любой отправки сверяет MAC `feth4201` с ОС.
fn lab(test: &'static str) -> Lab {
    let manifest = need("RMASSCAN_BPF_LAB_MANIFEST");
    assert!(
        std::path::Path::new(&manifest).is_file(),
        "NOT RUN: no stand manifest at {manifest}"
    );
    let out_dir = need("RMASSCAN_BPF_OUT_DIR");
    let mac = nic_mac(IFACE).unwrap_or_else(|| panic!("NOT RUN: interface {IFACE} is absent"));
    assert_eq!(
        mac, SRC_MAC,
        "REFUSING TO SEND: {IFACE} has MAC {mac:02x?}, the stand constants say {SRC_MAC:02x?}"
    );
    Lab { out_dir, test }
}

fn kv(lab: &Lab, what: &str, body: &str) {
    let line = format!("KV {}/{what} {body}", lab.test);
    println!("{line}");
    let path = format!("{}/macos_live__{}.kv", lab.out_dir, lab.test);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{line}");
    }
}

fn binding() -> AdapterBinding {
    AdapterBinding {
        interface_id: IFACE.into(),
        link_type: LinkType::Ethernet,
        source_ipv4: SRC_IP,
        source_mac: SRC_MAC,
        next_hop_mac: PEER_MAC,
        source_ports: (40000, 40000),
    }
}

fn plan(ports: &str, rate: f64, wait: u32) -> ReadyPlan {
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
    ReadyPlan::new(eff, binding()).unwrap()
}

// ---------- защита и декораторы ----------

/// Единственный путь кадра в сеть: проверка адресов стенда.
fn assert_lab_frame(f: &[u8]) {
    assert!(f.len() >= 34, "frame too short for an IPv4 header");
    assert_eq!(f[0..6], PEER_MAC, "dst MAC is not the stand peer");
    assert_eq!(f[6..12], SRC_MAC, "src MAC is not feth4201");
    assert_eq!(f[12..14], [0x08, 0x00], "not IPv4");
    assert_eq!(f[30..34], DST_IP.to_be_bytes(), "dst IP is not 198.18.0.2");
}

struct GuardTx {
    inner: Box<dyn Tx>,
    /// После стольких реальных отправок вернуть `Uncertain`, не вызывая
    /// адаптер (синтетический сбой для проверки runtime).
    uncertain_after: Option<u64>,
    n: u64,
}

impl Tx for GuardTx {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError> {
        assert_lab_frame(frame);
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

/// Читатель, который окно времени не читает (кадры копятся в буфере BPF).
struct StalledRx {
    inner: Box<dyn Rx>,
    from: Instant,
    until: Instant,
}

impl Rx for StalledRx {
    fn recv(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<Option<usize>, IoError> {
        let now = Instant::now();
        if now >= self.from && now < self.until {
            std::thread::sleep(timeout.min(Duration::from_millis(10)));
            return Ok(None);
        }
        self.inner.recv(buffer, timeout)
    }

    fn health(&mut self, timeout: Duration) -> Result<RxHealth, IoError> {
        self.inner.health(timeout)
    }
}

// ---------- запуск движка ----------

struct Run {
    outcome: Outcome,
    replies: Vec<Reply>,
    checkpoint: Option<Checkpoint>,
    stats_final: NetStats,
    stats_handle: NetStatsHandle,
    /// От вызова `stop`/`pause` до появления исхода.
    command_to_outcome: Option<Duration>,
    sent_at_outcome: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Command {
    None,
    StopAfter(Duration),
    PauseAfterSent(u64),
}

struct Spec<'a> {
    plan: &'a ReadyPlan,
    attempt: u8,
    resume: Option<Checkpoint>,
    command: Command,
    uncertain_after: Option<u64>,
    /// Окно (от старта), в которое читатель стоит.
    stall: Option<(Duration, Duration)>,
}

impl<'a> Spec<'a> {
    fn new(plan: &'a ReadyPlan, attempt: u8) -> Self {
        Spec {
            plan,
            attempt,
            resume: None,
            command: Command::None,
            uncertain_after: None,
            stall: None,
        }
    }
}

fn run_engine(spec: Spec<'_>) -> Run {
    let opened = open_explicit(spec.plan.binding()).expect("open_explicit");
    let stats = opened.stats.clone();
    let started = Instant::now();
    let rx: Box<dyn Rx> = match spec.stall {
        Some((a, b)) => Box::new(StalledRx {
            inner: opened.io.rx,
            from: started + a,
            until: started + b,
        }),
        None => opened.io.rx,
    };
    let io = AdapterPair {
        tx: Box::new(GuardTx {
            inner: opened.io.tx,
            uncertain_after: spec.uncertain_after,
            n: 0,
        }),
        rx,
    };
    let opts = EngineOptions::new([7; 16], [spec.attempt; 16]);
    let h: EngineHandle = match &spec.resume {
        Some(cp) => Engine::resume(spec.plan.clone(), cp.clone(), io, opts),
        None => Engine::start(spec.plan.clone(), io, opts),
    }
    .expect("engine start");
    let mut replies = Vec::new();
    let mut commanded_at: Option<Instant> = None;
    let mut command_to_outcome = None;
    let mut sent_at_outcome = 0;
    loop {
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
            Ok(Event::Finished { .. }) => break,
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
    }
}

fn summarize(lab: &Lab, what: &str, r: &Run) {
    let s = &r.stats_final;
    kv(
        lab,
        what,
        &format!(
            "reason={:?} sent={} next_index={} received={} rx_health={:?} net.tx_sent={} \
             net.tx_would_block={} net.tx_uncertain={} net.tx_errors={} net.rx_packets={} \
             net.rx_outgoing={} net.rx_truncated={} net.rx_errors={} net.kernel_drops={:?} \
             command_to_outcome_ms={:?} checkpoint={}",
            r.outcome.reason,
            r.outcome.progress.sent,
            r.outcome.progress.next_index,
            r.outcome.progress.received,
            r.outcome.rx_health.kernel_drops,
            s.tx_sent,
            s.tx_would_block,
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
/// Число SYN в захвате пира после исхода сверяет оператор (свидетель).
fn assert_silent_after(lab: &Lab, what: &str, stats: &NetStatsHandle, window: Duration) {
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

// =====================================================================
// Полный скан через движок: ровно один advance на Sent
// =====================================================================

#[test]
#[ignore = "live: needs the sealed feth stand (see module docs)"]
fn a_full_scan_through_the_engine_completes_with_exactly_one_advance_per_sent() {
    let lab = lab("full_scan");
    let ports = format!("{OPEN_PORTS},9000-9009");
    let probes = 2 + 8 + 10;
    let p = plan(&ports, 100.0, 3);
    for round in 0..2u8 {
        let r = run_engine(Spec::new(&p, 2 + round));
        summarize(&lab, &format!("round{round}"), &r);
        assert_eq!(r.outcome.reason, Reason::Completed, "{:?}", r.outcome);
        assert_eq!(r.outcome.progress.sent, probes);
        assert_eq!(
            r.outcome.progress.next_index, probes,
            "one advance per Sent"
        );
        assert_eq!(r.stats_final.tx_sent, probes);
        assert_eq!(r.stats_final.tx_uncertain, 0);
        // Подтверждённый ноль потерь буфера BPF, из движка и из счётчиков.
        assert_eq!(r.outcome.rx_health.kernel_drops, Some(0));
        assert_eq!(r.stats_final.kernel_drops, Some(0));
        let mut got: BTreeMap<u16, PortStatus> = BTreeMap::new();
        for rep in &r.replies {
            assert_eq!(rep.remote_ip, DST_IP);
            got.insert(rep.remote_port, rep.status);
        }
        assert_eq!(got.len() as u64, probes);
        for (port, st) in got {
            let open = port == 80 || port == 443 || (8000..=8007).contains(&port);
            let want = if open {
                PortStatus::Open
            } else {
                PortStatus::Closed
            };
            assert_eq!(st, want, "port {port}");
        }
    }
}

// =====================================================================
// Stop, Pause/Resume, Uncertain, потеря RX через общий runtime
// =====================================================================

#[test]
#[ignore = "live: needs the sealed feth stand (see module docs)"]
fn stop_ends_the_run_quickly_and_nothing_is_sent_afterwards() {
    let lab = lab("stop");
    let p = plan("1-2000", 300.0, 3);
    let mut spec = Spec::new(&p, 2);
    spec.command = Command::StopAfter(Duration::from_millis(1500));
    let r = run_engine(spec);
    summarize(&lab, "stop", &r);
    assert_eq!(r.outcome.reason, Reason::Stopped, "{:?}", r.outcome);
    let d = r.command_to_outcome.expect("stop was commanded");
    assert!(d < Duration::from_secs(1), "Stop took {d:?}");
    assert!(r.outcome.progress.sent > 100 && r.outcome.progress.sent < 2000);
    assert_eq!(r.stats_final.tx_sent, r.outcome.progress.sent);
    assert_eq!(r.outcome.rx_health.kernel_drops, Some(0));
    assert_silent_after(
        &lab,
        "stop_silence",
        &r.stats_handle,
        Duration::from_millis(700),
    );
}

#[test]
#[ignore = "live: needs the sealed feth stand (see module docs)"]
fn pause_stops_tx_then_resume_continues_without_gaps_or_duplicates() {
    let lab = lab("pause_resume");
    let p = plan("9000-9011", 10.0, 3);
    let mut s = Spec::new(&p, 2);
    s.command = Command::PauseAfterSent(4);
    let leg1 = run_engine(s);
    summarize(&lab, "leg1", &leg1);
    assert_eq!(leg1.outcome.reason, Reason::Paused, "{:?}", leg1.outcome);
    let d = leg1.command_to_outcome.expect("pause was commanded");
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
    // TX остановился не позже 1 с после команды: в окно drain ничего не уходило.
    assert_eq!(leg1.sent_at_outcome, leg1.outcome.progress.sent);

    let mut s = Spec::new(&p, 3);
    s.resume = Some(cp);
    let leg2 = run_engine(s);
    summarize(&lab, "leg2", &leg2);
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
    assert_eq!(ports, (9000..=9011).collect::<Vec<u16>>(), "no gaps");
}

#[test]
#[ignore = "live: needs the sealed feth stand (see module docs)"]
fn rx_loss_from_a_stalled_reader_fails_the_run_and_keeps_the_results() {
    let lab = lab("rx_loss");
    // Быстрый скан закрытых портов: RST пира заполняют буфер BPF, пока читатель
    // стоит. До окна читатель работает, поэтому часть результатов уже у движка.
    let p = plan("1-40000", 20_000.0, 1);
    let mut s = Spec::new(&p, 2);
    s.stall = Some((Duration::from_millis(300), Duration::from_millis(1500)));
    let r = run_engine(s);
    summarize(&lab, "rx_loss", &r);
    match &r.outcome.reason {
        Reason::Failed(FailReason::RxLoss { kernel_drops }) => {
            assert!(*kernel_drops > 0);
            assert!(r.stats_final.kernel_drops.unwrap_or(0) >= *kernel_drops);
        }
        other => panic!("expected RxLoss, got {other:?}"),
    }
    assert!(r.checkpoint.is_none(), "a lossy run has no checkpoint");
    assert!(
        !r.replies.is_empty(),
        "results gathered before the loss are kept"
    );
}

#[test]
#[ignore = "live: needs the sealed feth stand (see module docs)"]
fn an_uncertain_send_fails_the_run_without_checkpoint_retry_or_more_sends() {
    let lab = lab("uncertain");
    let p = plan("9100-9119", 100.0, 3);
    let mut s = Spec::new(&p, 2);
    s.uncertain_after = Some(3);
    let r = run_engine(s);
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
