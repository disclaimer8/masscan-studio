//! Лабораторный harness этапа 2B-Linux (AGPL-3.0). НЕ пользовательский CLI
//! сканирования: все параметры явные (цели, порты, binding, seed, rate), без
//! авто-выбора адаптера, маршрута или MAC. Запускается только внутри
//! замкнутого стенда (`scripts/wire-lab.sh`, netns + veth, без uplink).
//!
//! Использует `ReadyPlan` + `Engine` + `open_explicit`. Движку отдаётся
//! `OpenedAdapter.io`; handle статистики остаётся у harness. В stdout уходит
//! ровно одна строка JSON (summary), checkpoint пишется в файл и в hex.
//!
//! Обязательные: --iface --src-ip --src-mac --router-mac --targets --ports
//! --seed. Остальные: --rate (100) --wait (3) --source-port A[-B] (40000)
//! --exclude T --scan-id HEX32 --attempt-id HEX32 --pause-after N
//! --resume-checkpoint FILE --checkpoint-out FILE --ready-file FILE
//! --stop-after-ms MS --stop-file FILE --pause-file FILE --stop-in-drain
//! --no-consume --result-capacity N --observe-ms MS
//! --rx-stall-ms MS (только стенд: RX-поток спит MS перед первым чтением, сокет
//! переполняется, ядро считает drops; так воспроизводится RxLoss)
//! --forge-checkpoint-next-index N (записать checkpoint и выйти, без сети).
//!
//! Коды выхода: 0 Completed/Paused/Stopped; 2 ошибка аргументов/плана/
//! открытия адаптера; 3 Failed; 4 resume отвергнут до открытия адаптера.

use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rmasscan_core::config::{Operation, ScanConfig, parse_mac, parse_source_port, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{AdapterBinding, ReadyPlan};
use rmasscan_core::receive::{PortStatus, Reply};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_engine::io::{AdapterPair, IoError, Rx, RxHealth, SendStatus, Tx};
use rmasscan_engine::{
    CancelHandle, Checkpoint, ENGINE_ALGORITHM_VERSION, Engine, EngineOptions, Event, Reason,
    job_digest,
};
use rmasscan_net::open_explicit;

#[derive(Default)]
struct Args {
    iface: String,
    src_ip: String,
    src_mac: String,
    router_mac: String,
    targets: String,
    ports: String,
    exclude: Option<String>,
    seed: u64,
    rate: f64,
    wait: u32,
    source_port: String,
    scan_id: [u8; 16],
    attempt_id: [u8; 16],
    pause_after: Option<u64>,
    resume_checkpoint: Option<String>,
    checkpoint_out: Option<String>,
    ready_file: Option<String>,
    stop_after_ms: Option<u64>,
    stop_file: Option<String>,
    pause_file: Option<String>,
    stop_in_drain: bool,
    no_consume: bool,
    result_capacity: Option<usize>,
    observe_ms: u64,
    rx_stall_ms: u64,
    forge_next_index: Option<u64>,
}

fn parse_hex16(s: &str) -> Result<[u8; 16], String> {
    if s.len() != 32 || !s.is_ascii() {
        return Err(format!("expected 32 hex digits, got {s:?}"));
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// RX-декоратор стенда: один раз спит перед первым чтением, пока TX и ядро
/// заполняют буфер сокета. Только harness; продуктовый API не меняется.
struct StallRx {
    inner: Box<dyn Rx>,
    stall: Option<Duration>,
}

impl Rx for StallRx {
    fn recv(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<Option<usize>, IoError> {
        if let Some(d) = self.stall.take() {
            std::thread::sleep(d);
        }
        self.inner.recv(buffer, timeout)
    }

    fn health(&mut self, timeout: Duration) -> Result<RxHealth, IoError> {
        self.inner.health(timeout)
    }
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        rate: 100.0,
        wait: 3,
        source_port: "40000".into(),
        scan_id: [1; 16],
        attempt_id: [2; 16],
        observe_ms: 0,
        ..Args::default()
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut val = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        match k.as_str() {
            "--iface" => a.iface = val(&k)?,
            "--src-ip" => a.src_ip = val(&k)?,
            "--src-mac" => a.src_mac = val(&k)?,
            "--router-mac" => a.router_mac = val(&k)?,
            "--targets" => a.targets = val(&k)?,
            "--ports" => a.ports = val(&k)?,
            "--exclude" => a.exclude = Some(val(&k)?),
            "--seed" => a.seed = val(&k)?.parse().map_err(|e| format!("--seed: {e}"))?,
            "--rate" => a.rate = val(&k)?.parse().map_err(|e| format!("--rate: {e}"))?,
            "--wait" => a.wait = val(&k)?.parse().map_err(|e| format!("--wait: {e}"))?,
            "--source-port" => a.source_port = val(&k)?,
            "--scan-id" => a.scan_id = parse_hex16(&val(&k)?)?,
            "--attempt-id" => a.attempt_id = parse_hex16(&val(&k)?)?,
            "--pause-after" => {
                a.pause_after = Some(val(&k)?.parse().map_err(|e| format!("{k}: {e}"))?);
            }
            "--resume-checkpoint" => a.resume_checkpoint = Some(val(&k)?),
            "--checkpoint-out" => a.checkpoint_out = Some(val(&k)?),
            "--ready-file" => a.ready_file = Some(val(&k)?),
            "--stop-after-ms" => {
                a.stop_after_ms = Some(val(&k)?.parse().map_err(|e| format!("{k}: {e}"))?);
            }
            "--stop-file" => a.stop_file = Some(val(&k)?),
            "--pause-file" => a.pause_file = Some(val(&k)?),
            "--stop-in-drain" => a.stop_in_drain = true,
            "--no-consume" => a.no_consume = true,
            "--result-capacity" => {
                a.result_capacity = Some(val(&k)?.parse().map_err(|e| format!("{k}: {e}"))?);
            }
            "--rx-stall-ms" => a.rx_stall_ms = val(&k)?.parse().map_err(|e| format!("{k}: {e}"))?,
            "--observe-ms" => a.observe_ms = val(&k)?.parse().map_err(|e| format!("{k}: {e}"))?,
            "--forge-checkpoint-next-index" => {
                a.forge_next_index = Some(val(&k)?.parse().map_err(|e| format!("{k}: {e}"))?);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    for (n, v) in [
        ("--iface", &a.iface),
        ("--src-ip", &a.src_ip),
        ("--src-mac", &a.src_mac),
        ("--router-mac", &a.router_mac),
        ("--targets", &a.targets),
        ("--ports", &a.ports),
    ] {
        if v.is_empty() {
            return Err(format!("{n} is required"));
        }
    }
    if a.seed == 0 {
        return Err("--seed is required and must be non-zero".into());
    }
    Ok(a)
}

fn build_plan(a: &Args) -> Result<ReadyPlan, String> {
    let ip: Ipv4Addr = a.src_ip.parse().map_err(|e| format!("--src-ip: {e}"))?;
    let src_mac = parse_mac(&a.src_mac).map_err(|e| e.to_string())?;
    let router_mac = parse_mac(&a.router_mac).map_err(|e| e.to_string())?;
    let sp = parse_source_port(&a.source_port).map_err(|e| e.to_string())?;
    let mut targets = MassIp::new();
    add_target_string(targets.ipv4_mut(), &a.targets).map_err(|e| e.to_string())?;
    parse_ports(targets.ports_mut(), &a.ports).map_err(|e| e.to_string())?;
    let mut excludes = MassIp::new();
    if let Some(x) = &a.exclude {
        add_target_string(excludes.ipv4_mut(), x).map_err(|e| e.to_string())?;
    }
    let cfg = ScanConfig {
        targets,
        excludes,
        seed: a.seed,
        max_rate: a.rate,
        wait_secs: a.wait,
        adapter_ip: Some(u32::from(ip)),
        adapter_mac: Some(src_mac),
        router_mac: Some(router_mac),
        source_port: Some(sp),
        adapter_name: Some(a.iface.clone()),
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).map_err(|e| e.to_string())?;
    ReadyPlan::new(
        eff,
        AdapterBinding {
            interface_id: a.iface.clone(),
            link_type: LinkType::Ethernet,
            source_ipv4: u32::from(ip),
            source_mac: src_mac,
            next_hop_mac: router_mac,
            source_ports: sp,
        },
    )
    .map_err(|e| e.to_string())
}

fn js(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn fail_json(stage: &str, kind: &str, msg: &str, opened: bool) -> String {
    format!(
        "{{\"status\":\"error\",\"stage\":{},\"error\":{},\"message\":{},\"opened_adapter\":{opened},\"tx_sent\":0}}",
        js(stage),
        js(kind),
        js(msg)
    )
}

fn count_dir(p: &str) -> usize {
    std::fs::read_dir(p).map_or(0, |d| d.count())
}

/// Тайминги подтверждённых отправок (для steady-state скорости).
struct TxTiming {
    t0: Instant,
    mark_at: u64,
    first_ns: AtomicU64,
    mark_ns: AtomicU64,
    last_ns: AtomicU64,
    last_idx: AtomicU64,
}

/// TX-декоратор: реальный ввод-вывод внутри; после `pause_after`
/// подтверждённых отправок просит Pause и НЕ пропускает кадр N+1
/// (возвращает `WouldBlockUnsent`, кадр остаётся у курсора).
struct HarnessTx {
    inner: Box<dyn Tx>,
    pause_after: Option<u64>,
    sent: u64,
    cancel: Arc<OnceLock<CancelHandle>>,
    timing: Arc<TxTiming>,
}

impl Tx for HarnessTx {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError> {
        if self.pause_after == Some(self.sent) {
            let c = loop {
                if let Some(c) = self.cancel.get() {
                    break c;
                }
                std::thread::yield_now();
            };
            c.pause();
            return Ok(SendStatus::WouldBlockUnsent);
        }
        let r = self.inner.send(frame, timeout)?;
        if r == SendStatus::Sent {
            self.sent += 1;
            let ns = u64::try_from(self.timing.t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
            if self.sent == 1 {
                self.timing.first_ns.store(ns, Ordering::Relaxed);
            }
            if self.sent == self.timing.mark_at {
                self.timing.mark_ns.store(ns, Ordering::Relaxed);
            }
            self.timing.last_ns.store(ns, Ordering::Relaxed);
            self.timing.last_idx.store(self.sent, Ordering::Release);
        }
        Ok(r)
    }
}

fn reply_str(r: &Reply) -> String {
    let st = match r.status {
        PortStatus::Open => "open",
        PortStatus::Closed => "closed",
    };
    format!("{}:{}:{st}", Ipv4Addr::from(r.remote_ip), r.remote_port)
}

fn main() {
    let a = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            println!("{}", fail_json("args", "BadArgs", &e, false));
            std::process::exit(2);
        }
    };
    std::process::exit(run(&a));
}

fn run(a: &Args) -> i32 {
    let plan = match build_plan(a) {
        Ok(p) => p,
        Err(e) => {
            println!("{}", fail_json("plan", "BadPlan", &e, false));
            return 2;
        }
    };
    let digest = job_digest(&plan);

    if let Some(n) = a.forge_next_index {
        let cp = Checkpoint {
            format_version: rmasscan_engine::CHECKPOINT_FORMAT_VERSION,
            engine_version: ENGINE_ALGORITHM_VERSION,
            scan_id: a.scan_id,
            attempt_id: a.attempt_id,
            job_digest: digest,
            next_index: n,
        };
        if let Some(p) = &a.checkpoint_out
            && let Err(e) = std::fs::write(p, cp.to_bytes())
        {
            println!("{}", fail_json("forge", "Io", &e.to_string(), false));
            return 2;
        }
        println!(
            "{{\"status\":\"forged\",\"next_index\":{n},\"range\":{},\"opened_adapter\":false,\"tx_sent\":0}}",
            plan.range()
        );
        return 0;
    }

    // ---- resume: ВСЯ проверка до открытия адаптера (до любой отправки) ----
    let mut resume: Option<Checkpoint> = None;
    if let Some(path) = &a.resume_checkpoint {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                println!("{}", fail_json("resume-read", "Io", &e.to_string(), false));
                return 2;
            }
        };
        let cp = match Checkpoint::from_bytes(&bytes) {
            Ok(c) => c,
            Err(e) => {
                println!(
                    "{}",
                    fail_json("resume-preflight", &format!("{e:?}"), &e.to_string(), false)
                );
                return 4;
            }
        };
        let pre = if cp.engine_version != ENGINE_ALGORITHM_VERSION {
            Some("EngineVersionMismatch")
        } else if cp.job_digest != digest {
            Some("JobMismatch")
        } else if cp.scan_id != a.scan_id {
            Some("ScanIdMismatch")
        } else if cp.attempt_id == a.attempt_id {
            Some("AttemptIdReused")
        } else if cp.next_index == plan.range() {
            Some("AlreadyCompleted")
        } else {
            None
        };
        if let Some(kind) = pre {
            println!(
                "{}",
                fail_json(
                    "resume-preflight",
                    kind,
                    "rejected before the adapter was opened",
                    false
                )
            );
            return 4;
        }
        resume = Some(cp);
    }

    let fds_before = count_dir("/proc/self/fd");
    let threads_before = count_dir("/proc/self/task");
    let opened = match open_explicit(plan.binding()) {
        Ok(o) => o,
        Err(e) => {
            println!("{}", fail_json("open", "NetError", &e.to_string(), false));
            return 2;
        }
    };
    let fds_open = count_dir("/proc/self/fd");
    let stats = opened.stats.clone();

    let start_index = resume.as_ref().map_or(0, |c| c.next_index);
    let expected_total = plan.range() - start_index;
    let timing = Arc::new(TxTiming {
        t0: Instant::now(),
        mark_at: (expected_total / 10).max(1),
        first_ns: AtomicU64::new(0),
        mark_ns: AtomicU64::new(0),
        last_ns: AtomicU64::new(0),
        last_idx: AtomicU64::new(0),
    });
    let cancel: Arc<OnceLock<CancelHandle>> = Arc::default();
    let AdapterPair { tx, rx } = opened.io;
    let io = AdapterPair {
        tx: Box::new(HarnessTx {
            inner: tx,
            pause_after: a.pause_after,
            sent: 0,
            cancel: cancel.clone(),
            timing: timing.clone(),
        }),
        rx: if a.rx_stall_ms > 0 {
            Box::new(StallRx {
                inner: rx,
                stall: Some(Duration::from_millis(a.rx_stall_ms)),
            })
        } else {
            rx
        },
    };
    let mut opts = EngineOptions::new(a.scan_id, a.attempt_id);
    if let Some(c) = a.result_capacity {
        opts.result_capacity = c;
    }
    let started = Instant::now();
    let handle = match &resume {
        Some(cp) => Engine::resume(plan.clone(), cp.clone(), io, opts),
        None => Engine::start(plan.clone(), io, opts),
    };
    let handle = match handle {
        Ok(h) => h,
        Err(e) => {
            println!(
                "{}",
                fail_json("engine-start", &format!("{e:?}"), &e.to_string(), true)
            );
            return 4;
        }
    };
    let _ = cancel.set(handle.cancel_handle());
    if let Some(p) = &a.ready_file {
        let _ = std::fs::write(p, "started\n");
    }

    let mut replies: Vec<Reply> = Vec::new();
    let mut stop_at: Option<Instant> = None;
    let mut pause_requested = false;
    let mut outcome_at: Option<Instant> = None;
    let exists = |p: &Option<String>| p.as_ref().is_some_and(|p| std::path::Path::new(p).exists());
    loop {
        if outcome_at.is_none() && handle.outcome().is_some() {
            outcome_at = Some(Instant::now());
        }
        if a.no_consume && outcome_at.is_some() {
            break;
        }
        if stop_at.is_none() {
            let timed = a
                .stop_after_ms
                .is_some_and(|ms| started.elapsed() >= Duration::from_millis(ms));
            let drained = a.stop_in_drain
                && handle.progress().sent >= expected_total
                && handle.outcome().is_none();
            if timed || drained || exists(&a.stop_file) {
                stop_at = Some(Instant::now());
                handle.stop();
            }
        }
        if !pause_requested && exists(&a.pause_file) {
            pause_requested = true;
            handle.pause();
        }
        if a.no_consume {
            std::thread::sleep(Duration::from_millis(5));
            continue;
        }
        match handle.recv_event_timeout(Duration::from_millis(5)) {
            Ok(Event::Results { replies: r }) => replies.extend(r),
            Ok(Event::Finished { .. }) => break,
            Ok(_) => {}
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => break,
        }
    }
    let outcome_seen = outcome_at.unwrap_or_else(Instant::now);
    let checkpoint = handle.checkpoint();
    let scan_id = handle.scan_id();
    let attempt_id = handle.attempt_id();
    let resumed_from = handle.resumed_from_attempt();
    let join_t0 = Instant::now();
    let (outcome_j, rest) = match handle.join_drain() {
        Ok(v) => v,
        Err(e) => {
            println!(
                "{}",
                fail_json("join", &format!("{e:?}"), &e.to_string(), true)
            );
            return 3;
        }
    };
    let join_ms = join_t0.elapsed().as_secs_f64() * 1000.0;
    for ev in rest {
        if let Event::Results { replies: r } = ev {
            replies.extend(r);
        }
    }
    // pthread_join возвращается до того, как ядро убрало запись задачи из
    // /proc/self/task; поэтому фиксируем и мгновенное значение, и «осевшее»
    // (не дольше 1 с) вместе со временем оседания.
    let threads_immediate = count_dir("/proc/self/task");
    let settle_t0 = Instant::now();
    let mut threads_after = threads_immediate;
    while threads_after > threads_before && settle_t0.elapsed() < Duration::from_secs(1) {
        std::thread::sleep(Duration::from_millis(1));
        threads_after = count_dir("/proc/self/task");
    }
    let threads_settle_ms = settle_t0.elapsed().as_secs_f64() * 1000.0;
    let fds_after = count_dir("/proc/self/fd");
    let stats_at_join = stats.snapshot();
    if a.observe_ms > 0 {
        std::thread::sleep(Duration::from_millis(a.observe_ms));
    }
    let stats_end = stats.snapshot();

    let (reason, fail_detail) = match &outcome_j.reason {
        Reason::Completed => ("Completed", String::new()),
        Reason::Stopped => ("Stopped", String::new()),
        Reason::Paused => ("Paused", String::new()),
        Reason::Failed(f) => ("Failed", format!("{f:?}")),
    };
    if let (Some(cp), Some(p)) = (&checkpoint, &a.checkpoint_out)
        && let Err(e) = std::fs::write(p, cp.to_bytes())
    {
        println!(
            "{}",
            fail_json("checkpoint-write", "Io", &e.to_string(), true)
        );
        return 2;
    }

    let mut rs: Vec<String> = replies.iter().map(reply_str).collect();
    let reply_total = rs.len();
    rs.sort();
    let mut uniq = rs.clone();
    uniq.dedup();
    let p = &outcome_j.progress;
    let t = &timing;
    let first = t.first_ns.load(Ordering::Relaxed);
    let mark = t.mark_ns.load(Ordering::Relaxed);
    let last = t.last_ns.load(Ordering::Relaxed);
    let last_idx = t.last_idx.load(Ordering::Acquire);
    // steady state: от 10 % отправок этого запуска до последней; без старта и wait.
    let steady = if last_idx > t.mark_at && last > mark {
        (last_idx - t.mark_at) as f64 / ((last - mark) as f64 / 1e9)
    } else {
        0.0
    };
    let s = &stats_end;
    let mut j = String::new();
    let _ = write!(
        j,
        "{{\"status\":\"ok\",\"reason\":{},\"fail_detail\":{},\"opened_adapter\":true,\
\"range\":{},\"start_index\":{start_index},\"expected_total\":{expected_total},\
\"sent\":{},\"next_index\":{},\"received\":{},\"discarded\":{},\"duplicates\":{},\
\"rx_health\":{{\"kernel_drops\":{}}},\
\"scan_id\":{},\"attempt_id\":{},\"resumed_from_attempt\":{},",
        js(reason),
        js(&fail_detail),
        plan.range(),
        p.sent,
        p.next_index,
        p.received,
        p.discarded,
        p.duplicates,
        // Неизвестное качество приёма это null, а не 0.
        outcome_j
            .rx_health
            .kernel_drops
            .map_or("null".to_string(), |d| d.to_string()),
        js(&hex(&scan_id)),
        js(&hex(&attempt_id)),
        resumed_from.map_or("null".to_string(), |r| js(&hex(&r))),
    );
    let _ = write!(
        j,
        "\"replies\":[{}],\"reply_total\":{reply_total},\"reply_unique\":{},\
\"checkpoint\":{},\"checkpoint_next_index\":{},\"checkpoint_hex\":{},",
        rs.iter().map(|x| js(x)).collect::<Vec<_>>().join(","),
        uniq.len(),
        checkpoint.is_some(),
        checkpoint
            .as_ref()
            .map_or("null".to_string(), |c| c.next_index.to_string()),
        checkpoint
            .as_ref()
            .map_or("null".to_string(), |c| js(&hex(&c.to_bytes()))),
    );
    let _ = write!(
        j,
        "\"net\":{{\"tx_sent\":{},\"tx_would_block\":{},\"tx_uncertain\":{},\"tx_errors\":{},\
\"rx_packets\":{},\"rx_truncated\":{},\"rx_outgoing\":{},\"rx_wrong_interface\":{},\"rx_errors\":{},\"kernel_drops\":{}}},\
\"tx_sent_at_join\":{},\"tx_sent_after_observe\":{},\"observe_ms\":{},",
        s.tx_sent,
        s.tx_would_block,
        s.tx_uncertain,
        s.tx_errors,
        s.rx_packets,
        s.rx_truncated,
        s.rx_outgoing,
        s.rx_wrong_interface,
        s.rx_errors,
        s.kernel_drops.map_or("null".to_string(), |d| d.to_string()),
        stats_at_join.tx_sent,
        stats_end.tx_sent,
        a.observe_ms,
    );
    let _ = write!(
        j,
        "\"timing\":{{\"first_send_s\":{:.6},\"last_send_s\":{:.6},\"steady_pps\":{:.1},\"mark_idx\":{},\"last_idx\":{last_idx},\
\"stop_requested\":{},\"stop_to_outcome_ms\":{},\"join_ms\":{join_ms:.3},\"total_s\":{:.6}}},\
\"resources\":{{\"fds_before_open\":{fds_before},\"fds_open\":{fds_open},\"fds_after_join\":{fds_after},\
\"threads_before\":{threads_before},\"threads_after_join_immediate\":{threads_immediate},\"threads_settle_ms\":{threads_settle_ms:.3},\"threads_after_join\":{threads_after}}}}}",
        first as f64 / 1e9,
        last as f64 / 1e9,
        steady,
        t.mark_at,
        stop_at.is_some(),
        stop_at.map_or("null".to_string(), |s| format!(
            "{:.3}",
            outcome_seen.saturating_duration_since(s).as_secs_f64() * 1000.0
        )),
        started.elapsed().as_secs_f64(),
    );
    println!("{j}");
    if reason == "Failed" { 3 } else { 0 }
}
