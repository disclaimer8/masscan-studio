//! Лабораторный harness этапа 2B-Linux (AGPL-3.0). НЕ пользовательский CLI
//! сканирования: все параметры явные (цели, порты, binding, seed, rate), без
//! авто-выбора адаптера, маршрута или MAC. Запускается только внутри
//! замкнутого стенда (`scripts/wire-lab.sh`, netns + veth, без uplink).
//!
//! Использует `ReadyPlan` + `Engine` + `open_explicit`. Движку отдаётся
//! `OpenedAdapter.io`; handle статистики остаётся у harness. В stdout уходит
//! ровно одна строка JSON (summary), checkpoint пишется в файл и в hex.
//!
//! Обязательные: --iface --src-ip --router-mac --targets --ports --seed и
//! --src-mac (на Windows --src-mac можно опустить: берётся MAC выбранного NIC;
//! явный MAC, отличный от MAC NIC, отвергается, см. --allow-foreign-source-mac).
//! Без явных параметров скан не стартует. Остальные: --rate (100) --wait (3) --source-port A[-B] (40000)
//! --exclude T --scan-id HEX32 --attempt-id HEX32 --pause-after N
//! --resume-checkpoint FILE --checkpoint-out FILE --ready-file FILE
//! --stop-after-ms MS --stop-file FILE --pause-file FILE --stop-in-drain
//! --no-consume --result-capacity N --observe-ms MS
//! --rx-stall-ms MS (только стенд: RX-поток спит MS перед первым чтением, сокет
//! переполняется, ядро считает drops; так воспроизводится RxLoss)
//! --forge-checkpoint-next-index N (записать checkpoint и выйти, без сети).
//!
//! Безопасные режимы (ни один не отправляет кадры):
//! --inventory                  перечень Npcap/адаптеров/версий/идентичности;
//!                              адаптер не открывается.
//!                              На macOS: sysctl BPF, stat узлов /dev/bpf*, интерфейсы
//!                              (getifaddrs); BPF не открывается. MAC, скрытый ОС,
//!                              выводится как null с mac_masked:true.
//! --write-reference-pcap FILE  ожидаемые SYN-кадры для заданного binding;
//!                              DLL не загружается, адаптер не открывается
//!                              (нужны те же явные параметры, включая --src-mac).
//! --allow-foreign-source-mac   осознанно разрешить --src-mac, отличный от MAC
//!                              NIC (без promiscuous ответы не придут).
//!
//! Идентичность (коммит, sha256 бинарника, ОС, Npcap/драйвер/DLL, ABI) есть
//! в каждом JSON-выводе.
//!
//! Коды выхода: 0 Completed/Paused/Stopped; 2 ошибка аргументов/плана/чтения
//! checkpoint/открытия адаптера (в том числе устаревший Npcap и недоверенный
//! модуль) и сбой записи checkpoint после запуска (opened_adapter true);
//! 3 Failed или сбой join; 4 resume отвергнут до открытия адаптера, а также
//! сбой engine-start уже после открытия (opened_adapter true);
//! 5 нет Npcap или недостаточно прав (Admin-only Npcap, в том числе когда
//! виден только loopback): нужна инструкция; 6 source MAC не совпадает с MAC
//! выбранного NIC. Полная таблица: docs/windows-wire-lab.md.
//!
//! macOS: --src-mac обязателен; нет интерфейса (if_nametoindex) это InterfaceMismatch,
//! код 2, до открытия BPF; MAC интерфейса, отличный от --src-mac, код 6; если ОС скрыла
//! MAC (плейсхолдер 02:00:00:00:00:00), сверка пропускается: src_mac_check "os-masked",
//! nic_mac "masked". EACCES на /dev/bpf* это код 5; подсказка про
//! `macos-lab bpf-access --grant` приходит из текста PermissionDenied адаптера.

#![forbid(unsafe_code)]

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
use rmasscan_engine::io::{AdapterPair, IoError, Rx, RxHealth, SendStatus, Tx, TxBatch};
use rmasscan_engine::{
    CancelHandle, Checkpoint, ENGINE_ALGORITHM_VERSION, Engine, EngineOptions, Event, Reason,
    job_digest,
};
use rmasscan_net::{BpfInventory, Inventory, NetError, NetStats, open_explicit};

mod support;
use support::metrics;
use support::{hex, identity_json, js, mac_text, npcap_json, sha256_hex};

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
    inventory: bool,
    reference_pcap: Option<String>,
    allow_foreign_mac: bool,
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

/// RX-декоратор стенда: один раз спит перед первым чтением, пока TX и ядро
/// заполняют буфер сокета. Только harness; продуктовый API не меняется.
struct StallRx {
    inner: Box<dyn Rx>,
    stall: Option<Duration>,
}

/// RX-декоратор: запоминает ОС-идентификатор RX-потока движка (первый вызов `recv`/`health`).
struct IdRx {
    inner: Box<dyn Rx>,
    tid: Arc<OnceLock<u64>>,
}

impl IdRx {
    fn note(&self) {
        if let Some(id) = rmasscan_net::lab_current_thread_id() {
            let _ = self.tid.set(id);
        }
    }
}

impl Rx for IdRx {
    fn recv(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<Option<usize>, IoError> {
        self.note();
        self.inner.recv(buffer, timeout)
    }

    fn health(&mut self, timeout: Duration) -> Result<RxHealth, IoError> {
        self.note();
        self.inner.health(timeout)
    }
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

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut a = Args {
        rate: 100.0,
        wait: 3,
        source_port: "40000".into(),
        scan_id: [1; 16],
        attempt_id: [2; 16],
        observe_ms: 0,
        ..Args::default()
    };
    let mut it = args.into_iter();
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
                let n: usize = val(&k)?.parse().map_err(|e| format!("{k}: {e}"))?;
                if n == 0 {
                    return Err("--result-capacity must be > 0".into());
                }
                a.result_capacity = Some(n);
            }
            "--rx-stall-ms" => a.rx_stall_ms = val(&k)?.parse().map_err(|e| format!("{k}: {e}"))?,
            "--observe-ms" => a.observe_ms = val(&k)?.parse().map_err(|e| format!("{k}: {e}"))?,
            "--forge-checkpoint-next-index" => {
                a.forge_next_index = Some(val(&k)?.parse().map_err(|e| format!("{k}: {e}"))?);
            }
            "--inventory" => a.inventory = true,
            "--write-reference-pcap" => a.reference_pcap = Some(val(&k)?),
            "--allow-foreign-source-mac" => a.allow_foreign_mac = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if a.inventory {
        if a.reference_pcap.is_some() || a.forge_next_index.is_some() {
            return Err("--inventory cannot be combined with other modes".into());
        }
        // Перечень не требует параметров скана; лишние параметры игнорируются.
        return Ok(a);
    }
    if a.reference_pcap.is_some() && a.forge_next_index.is_some() {
        return Err("--write-reference-pcap cannot be combined with other modes".into());
    }
    // Оффлайн-режимы не обращаются к ОС, поэтому MAC обязан быть явным; в
    // режиме скана на Windows его можно взять у NIC (решает `run`).
    let offline = a.reference_pcap.is_some() || a.forge_next_index.is_some();
    let mut required = vec![
        ("--iface", &a.iface),
        ("--src-ip", &a.src_ip),
        ("--router-mac", &a.router_mac),
        ("--targets", &a.targets),
        ("--ports", &a.ports),
    ];
    // На macOS (как на Linux) MAC явный всегда: он сверяется с MAC интерфейса в `run`.
    if offline || cfg!(target_os = "macos") {
        required.push(("--src-mac", &a.src_mac));
    }
    for (n, v) in required {
        if v.is_empty() {
            return Err(format!("{n} is required"));
        }
    }
    if a.seed == 0 {
        return Err("--seed is required and must be non-zero".into());
    }
    Ok(a)
}

fn build_plan(a: &Args, src_mac: [u8; 6], rate: f64, wait: u32) -> Result<ReadyPlan, String> {
    let ip: Ipv4Addr = a.src_ip.parse().map_err(|e| format!("--src-ip: {e}"))?;
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
        max_rate: rate,
        wait_secs: wait,
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

fn fail_json(stage: &str, kind: &str, msg: &str, opened: bool) -> String {
    fail_json_job(stage, kind, msg, opened, None)
}

/// Как `fail_json`, но с `job` (что именно собирались сканировать), если план уже построен.
fn fail_json_job(stage: &str, kind: &str, msg: &str, opened: bool, job: Option<&str>) -> String {
    fail_json_sent(stage, kind, msg, opened, job, 0)
}

/// Как `fail_json_job`, но с реальным числом отправленных кадров: отказ после
/// отправки (join, запись checkpoint) не должен выглядеть как «ничего не ушло».
fn fail_json_sent(
    stage: &str,
    kind: &str,
    msg: &str,
    opened: bool,
    job: Option<&str>,
    tx_sent: u64,
) -> String {
    fail_json_sent_mac(stage, kind, msg, opened, job, tx_sent, None)
}

/// Как `fail_json_sent`, плюс `src_mac`/`src_mac_check`/`nic_mac` (готовый фрагмент JSON):
/// отказ после отправки обязан нести ту же идентичность MAC, что и успешный отчёт.
fn fail_json_sent_mac(
    stage: &str,
    kind: &str,
    msg: &str,
    opened: bool,
    job: Option<&str>,
    tx_sent: u64,
    mac_fields: Option<&str>,
) -> String {
    let mac = mac_fields.map_or(String::new(), |m| format!(",{m}"));
    format!(
        "{{\"status\":\"error\",\"stage\":{},\"error\":{},\"message\":{},\"opened_adapter\":{opened},\"tx_sent\":{tx_sent}{mac},\"job\":{},\"identity\":{}}}",
        js(stage),
        js(kind),
        js(msg),
        job.unwrap_or("null"),
        identity_json()
    )
}

/// Что именно сканировалось: все явные параметры и дайджест задания. Попадает
/// в scan, reference, forge и в ошибки после построения плана, чтобы архив
/// можно было привязать к заданию. Повторы, шард и раунды BlackRock не
/// настраиваются harness-ом (значения по умолчанию ScanConfig, план требует 0, 1/1, 14).
fn job_json(a: &Args, src_mac: [u8; 6], rate: f64, wait: u32, digest: &[u8]) -> String {
    format!(
        "{{\"iface\":{},\"src_ip\":{},\"src_mac\":{},\"router_mac\":{},\"source_port\":{},\
\"targets\":{},\"exclude\":{},\"ports\":{},\"seed\":{},\"rate\":{rate},\"wait\":{wait},\
\"retries\":0,\"shard\":\"1/1\",\"blackrock_rounds\":14,\"job_digest\":{}}}",
        js(&a.iface),
        js(&a.src_ip),
        js(&mac_text(&src_mac)),
        js(&a.router_mac),
        js(&a.source_port),
        js(&a.targets),
        support::json_opt_str(a.exclude.as_deref()),
        js(&a.ports),
        a.seed,
        js(&hex(digest)),
    )
}

/// Тайминги подтверждённых отправок (для steady-state скорости).
struct TxTiming {
    t0: Instant,
    /// Unix-время (мс) в момент `t0`: связывает относительные отметки с часами хоста (выравнивание по pcap пира).
    t0_utc_ms: u64,
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
    /// ОС-идентификатор TX-потока движка (первый вызов `send`): сверяется после join.
    tid: Arc<OnceLock<u64>>,
}

impl HarnessTx {
    fn note_tid(&self) {
        if let Some(id) = rmasscan_net::lab_current_thread_id() {
            let _ = self.tid.set(id);
        }
    }

    /// Просит Pause; кадр N+1 остаётся у курсора.
    fn pause_now(&self) -> SendStatus {
        let c = loop {
            if let Some(c) = self.cancel.get() {
                break c;
            }
            std::thread::yield_now();
        };
        c.pause();
        SendStatus::WouldBlockUnsent
    }

    /// Учитывает `n` подтверждённых кадров одного вызова адаптера; отметки
    /// времени относятся к его завершению.
    fn record(&mut self, n: u64) {
        if n == 0 {
            return;
        }
        let before = self.sent;
        self.sent += n;
        let ns = u64::try_from(self.timing.t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
        if before == 0 {
            self.timing.first_ns.store(ns, Ordering::Relaxed);
        }
        if before < self.timing.mark_at && self.timing.mark_at <= self.sent {
            self.timing.mark_ns.store(ns, Ordering::Relaxed);
        }
        self.timing.last_ns.store(ns, Ordering::Relaxed);
        self.timing.last_idx.store(self.sent, Ordering::Release);
    }
}

impl Tx for HarnessTx {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError> {
        self.note_tid();
        if self.pause_after == Some(self.sent) {
            return Ok(self.pause_now());
        }
        let r = self.inner.send(frame, timeout)?;
        if r == SendStatus::Sent {
            self.record(1);
        }
        Ok(r)
    }

    fn max_batch(&self) -> usize {
        self.inner.max_batch()
    }

    /// Режет пачку ровно на `pause_after`: префикс уходит во внутренний
    /// адаптер, кадр N+1 не пропускается (как в одиночном пути).
    fn send_batch(&mut self, frames: &[&[u8]], timeout: Duration) -> Result<TxBatch, IoError> {
        self.note_tid();
        let room = self.pause_after.map_or(usize::MAX, |p| {
            usize::try_from(p - self.sent).unwrap_or(usize::MAX)
        });
        if room == 0 {
            return Ok(TxBatch {
                sent: 0,
                rest: self.pause_now(),
            });
        }
        let take = frames.len().min(room);
        let r = self.inner.send_batch(&frames[..take], timeout)?;
        self.record(r.sent as u64);
        if r.rest == SendStatus::Sent && take < frames.len() {
            return Ok(TxBatch {
                sent: r.sent,
                rest: self.pause_now(),
            });
        }
        Ok(r)
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Жив ли каждый из потоков движка по снимку ОС (`None`: поток не наблюдался или ОС не даёт список).
fn engine_alive(ids: &[Option<u64>; 2]) -> [Option<bool>; 2] {
    let all = rmasscan_net::lab_thread_ids();
    [0, 1].map(|i| ids[i].and_then(|id| all.as_ref().map(|v| v.contains(&id))))
}

fn json_opt_u64(v: Option<u64>) -> String {
    v.map_or_else(|| "null".to_string(), |n| n.to_string())
}

fn json_opt_bool(v: Option<bool>) -> String {
    v.map_or_else(|| "null".to_string(), |b| b.to_string())
}

fn reply_str(r: &Reply) -> String {
    let st = match r.status {
        PortStatus::Open => "open",
        PortStatus::Closed => "closed",
    };
    format!("{}:{}:{st}", Ipv4Addr::from(r.remote_ip), r.remote_port)
}

/// Всё, что harness берёт у ОС и Npcap. Шов нужен тестам: подставной backend
/// считает обращения и доказывает, что безопасные режимы и отказы до открытия
/// не доходят до адаптера.
trait Backend {
    fn inventory(&self) -> Result<Inventory, NetError>;
    /// macOS: перечень BPF (sysctl, stat узлов, getifaddrs), без открытия BPF.
    fn bpf_inventory(&self) -> Result<BpfInventory, NetError>;
    fn nic_mac(&self, interface_id: &str) -> Option<[u8; 6]>;
    /// macOS: существует ли интерфейс (не зависит от MAC); `None`: не удалось спросить.
    fn iface_exists(&self, interface_id: &str) -> Option<bool>;
    /// macOS: ОС скрыла MAC плейсхолдером (`nic_mac` тогда `None`).
    fn nic_mac_masked(&self, interface_id: &str) -> bool;
    fn open(&self, binding: &AdapterBinding) -> Result<Opened, NetError>;
}

/// Открытый адаптер для harness: пара TX/RX для движка и независимое чтение
/// счётчиков сети (переживает закрытие адаптера; нужно и подставному backend).
struct Opened {
    io: AdapterPair,
    stats: Box<dyn Fn() -> NetStats>,
}

struct RealBackend;

impl Backend for RealBackend {
    fn inventory(&self) -> Result<Inventory, NetError> {
        rmasscan_net::inventory()
    }
    fn bpf_inventory(&self) -> Result<BpfInventory, NetError> {
        rmasscan_net::inventory_bpf()
    }
    fn nic_mac(&self, interface_id: &str) -> Option<[u8; 6]> {
        rmasscan_net::nic_mac(interface_id)
    }
    fn iface_exists(&self, interface_id: &str) -> Option<bool> {
        rmasscan_net::iface_exists(interface_id)
    }
    fn nic_mac_masked(&self, interface_id: &str) -> bool {
        rmasscan_net::nic_mac_masked(interface_id)
    }
    fn open(&self, binding: &AdapterBinding) -> Result<Opened, NetError> {
        let o = open_explicit(binding)?;
        let stats = o.stats.clone();
        Ok(Opened {
            io: o.io,
            stats: Box::new(move || stats.snapshot()),
        })
    }
}

/// Результат режима: код выхода и ровно одна строка JSON для stdout.
type Out = (i32, String);

fn main() {
    let (code, json) = match parse_args(std::env::args().skip(1)) {
        Ok(a) => run(&a, &RealBackend),
        Err(e) => (2, fail_json("args", "BadArgs", &e, false)),
    };
    println!("{json}");
    std::process::exit(code);
}

/// Нет Npcap или нет прав: wrapper печатает инструкцию (код 5).
fn net_error_code(e: &NetError) -> i32 {
    match e {
        NetError::DriverUnavailable(_) | NetError::PermissionDenied(_) => 5,
        _ => 2,
    }
}

/// macOS: перечень BPF без открытия `/dev/bpf*` и без отправки. Режимы узлов
/// выводятся и числом (`mode`, десятичное), и строкой (`mode_octal`, `0600`).
fn bpf_inventory_mode(be: &dyn Backend) -> Out {
    let inv = match be.bpf_inventory() {
        Ok(i) => i,
        Err(e) => {
            return (
                net_error_code(&e),
                fail_json("inventory", &format!("{e:?}"), &e.to_string(), false),
            );
        }
    };
    let devices = inv
        .devices
        .iter()
        .map(|d| {
            format!(
                "{{\"path\":{},\"mode\":{},\"mode_octal\":{},\"uid\":{},\"gid\":{}}}",
                js(&d.path),
                d.mode,
                js(&format!("{:04o}", d.mode)),
                d.uid,
                d.gid
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let interfaces = inv
        .interfaces
        .iter()
        .map(|i| {
            let ips = i
                .ipv4
                .iter()
                .map(|ip| js(&ip.to_string()))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"name\":{},\"index\":{},\"mac\":{},\"mac_masked\":{},\"ethernet\":{},\"up\":{},\"ipv4\":[{ips}]}}",
                js(&i.name),
                i.index,
                support::json_opt_str(i.mac.as_ref().map(mac_text).as_deref()),
                i.mac_masked,
                i.ethernet,
                i.up
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let hint = if inv.devices.is_empty() {
        "no /dev/bpf* nodes are visible"
    } else {
        ""
    };
    let json = format!(
        "{{\"status\":\"ok\",\"mode\":\"inventory\",\"opened_adapter\":false,\"tx_sent\":0,\
\"bpf\":{{\"os_version\":{},\"kernel_version\":{},\"bpf_maxbufsize\":{},\"bpf_maxdevices\":{}}},\
\"instant_clock\":{},\"devices\":[{devices}],\"interfaces\":[{interfaces}],\"access_hint\":{},\"identity\":{}}}",
        support::json_opt_str(inv.os_version.as_deref()),
        support::json_opt_str(inv.kernel_version.as_deref()),
        json_opt_u64(inv.bpf_maxbufsize.map(u64::from)),
        json_opt_u64(inv.bpf_maxdevices.map(u64::from)),
        js(inv.instant_clock),
        js(hint),
        identity_json()
    );
    (0, json)
}

fn inventory_mode(be: &dyn Backend) -> Out {
    if cfg!(target_os = "macos") {
        return bpf_inventory_mode(be);
    }
    match be.inventory() {
        Ok(inv) => {
            let devices = inv
                .devices
                .iter()
                .map(|d| {
                    format!(
                        "{{\"name\":{},\"description\":{},\"loopback\":{},\"mac\":{}}}",
                        js(&d.name),
                        support::json_opt_str(d.description.as_deref()),
                        d.loopback,
                        support::json_opt_str(d.mac.as_ref().map(mac_text).as_deref()),
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            // Admin-only Npcap скрывает адаптеры от сессии без прав: остаётся
            // пусто или только loopback (измерено на Npcap 1.90 с ограниченным
            // токеном, где флаг elevated при этом остаётся true). Это не ошибка
            // перечня, но использовать нечего: код 5, и wrapper печатает инструкцию.
            let hidden = inv.devices.iter().all(|d| d.loopback);
            let hint = if hidden {
                "no usable (non-loopback) adapter is visible: Npcap may be installed in Administrators-only mode and this session lacks rights, or the machine has no Ethernet adapter"
            } else {
                ""
            };
            let json = format!(
                "{{\"status\":\"ok\",\"mode\":\"inventory\",\"opened_adapter\":false,\"tx_sent\":0,\
\"npcap\":{},\"devices\":[{devices}],\"access_hint\":{},\"identity\":{}}}",
                npcap_json(&inv),
                js(hint),
                identity_json()
            );
            (if hidden { 5 } else { 0 }, json)
        }
        Err(e) => (
            net_error_code(&e),
            fail_json("inventory", &format!("{e:?}"), &e.to_string(), false),
        ),
    }
}

/// Верхняя граница числа кадров эталонного pcap (защита от случайного /8).
const MAX_REFERENCE_FRAMES: u64 = 1_000_000;

/// Классический pcap (LINKTYPE_ETHERNET), время 0: файл воспроизводим побайтно.
fn pcap_bytes(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    o.extend_from_slice(&2u16.to_le_bytes());
    o.extend_from_slice(&4u16.to_le_bytes());
    o.extend_from_slice(&0i32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&65535u32.to_le_bytes());
    o.extend_from_slice(&1u32.to_le_bytes());
    for f in frames {
        o.extend_from_slice(&0u32.to_le_bytes());
        o.extend_from_slice(&0u32.to_le_bytes());
        o.extend_from_slice(&(f.len() as u32).to_le_bytes());
        o.extend_from_slice(&(f.len() as u32).to_le_bytes());
        o.extend_from_slice(f);
    }
    o
}

/// Ожидаемые кадры: тот же движок и тот же план, но вместо адаптера память.
/// Ни Npcap, ни ОС не затрагиваются.
fn reference_mode(a: &Args, path: &str) -> Out {
    let bad = |stage: &str, kind: &str, msg: &str| (2, fail_json(stage, kind, msg, false));
    let src_mac = match parse_mac(&a.src_mac) {
        Ok(m) => m,
        Err(e) => return bad("plan", "BadPlan", &e.to_string()),
    };
    // Темп и ожидание влияют только на время, не на содержимое кадров.
    let plan = match build_plan(a, src_mac, 1.0e9, 0) {
        Ok(p) => p,
        Err(e) => return bad("plan", "BadPlan", &e),
    };
    // Задание записывается так, как его запросил пользователь (его rate/wait и дайджест).
    let job = match build_plan(a, src_mac, a.rate, a.wait) {
        Ok(p) => job_json(a, src_mac, a.rate, a.wait, &job_digest(&p)),
        Err(e) => return bad("plan", "BadPlan", &e),
    };
    if plan.range() > MAX_REFERENCE_FRAMES {
        return bad(
            "reference",
            "TooLarge",
            &format!(
                "{} frames exceed the reference limit {MAX_REFERENCE_FRAMES}",
                plan.range()
            ),
        );
    }
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    let handle = match Engine::start(
        plan.clone(),
        fake.pair(),
        EngineOptions::new(a.scan_id, a.attempt_id),
    ) {
        Ok(h) => h,
        Err(e) => return bad("reference", &format!("{e:?}"), &e.to_string()),
    };
    let t0 = Instant::now();
    loop {
        match handle.recv_event_timeout(Duration::from_millis(20)) {
            Ok(Event::Finished { .. }) | Err(TryRecvError::Disconnected) => break,
            Ok(_) | Err(TryRecvError::Empty) => {}
        }
        if t0.elapsed() > Duration::from_secs(120) {
            handle.stop();
            return bad(
                "reference",
                "Timeout",
                "reference generation took over 120 s",
            );
        }
    }
    let reason_ok = matches!(
        handle.join_drain().map(|(o, _)| o.reason),
        Ok(Reason::Completed)
    );
    let frames = fake.sent_frames();
    if !reason_ok || frames.len() as u64 != plan.range() {
        return bad(
            "reference",
            "Incomplete",
            &format!("generated {} of {} frames", frames.len(), plan.range()),
        );
    }
    let bytes = pcap_bytes(&frames);
    if let Err(e) = std::fs::write(path, &bytes) {
        return bad("reference-write", "Io", &e.to_string());
    }
    (
        0,
        format!(
            "{{\"status\":\"ok\",\"mode\":\"reference-pcap\",\"frames\":{},\"file\":{},\
\"pcap_sha256\":{},\"opened_adapter\":false,\"npcap_loaded\":false,\"tx_sent\":0,\"job\":{job},\"identity\":{}}}",
            frames.len(),
            js(path),
            js(&sha256_hex(&bytes)),
            identity_json()
        ),
    )
}

fn run(a: &Args, be: &dyn Backend) -> Out {
    if a.inventory {
        return inventory_mode(be);
    }
    if let Some(path) = &a.reference_pcap {
        return reference_mode(a, path);
    }

    // ---- MAC источника: у NIC или явный, но тогда сверенный с NIC ----
    let nic_mac = be.nic_mac(&a.iface);
    // macOS: привязка проверяется ДО открытия адаптера. Отсутствие интерфейса
    // (`if_nametoindex`, не зависит от MAC, который ОС может скрыть) это
    // InterfaceMismatch: BPF не открывался, ни одного кадра не отправлено.
    if cfg!(target_os = "macos")
        && a.forge_next_index.is_none()
        && be.iface_exists(&a.iface) != Some(true)
    {
        let e = NetError::InterfaceMismatch(match be.iface_exists(&a.iface) {
            Some(false) => format!(
                "interface {} was not found (if_nametoindex); no BPF device was opened and nothing was sent",
                a.iface
            ),
            _ => format!(
                "could not determine whether interface {} exists (if_nametoindex failed); refusing to continue, no BPF device was opened and nothing was sent",
                a.iface
            ),
        });
        return (
            net_error_code(&e),
            fail_json("binding", "InterfaceMismatch", &e.to_string(), false),
        );
    }
    let (src_mac, mac_check) = if a.src_mac.is_empty() {
        match nic_mac {
            Some(m) => (m, "nic-default"),
            None => {
                return (
                    2,
                    fail_json(
                        "plan",
                        "BadArgs",
                        "--src-mac is required: the MAC of the selected NIC could not be determined",
                        false,
                    ),
                );
            }
        }
    } else {
        let m = match parse_mac(&a.src_mac) {
            Ok(m) => m,
            Err(e) => return (2, fail_json("plan", "BadPlan", &e.to_string(), false)),
        };
        match nic_mac {
            // Без promiscuous ответы приходят только на MAC самого NIC: чужой
            // MAC дал бы скан без единого ответа, который выглядит успешным.
            Some(n) if n != m && !a.allow_foreign_mac && a.forge_next_index.is_none() => {
                return (
                    6,
                    fail_json(
                        "source-mac",
                        "SourceMacMismatch",
                        &format!(
                            "--src-mac {} differs from the MAC of {} ({}); replies would never arrive \
because promiscuous mode is not enabled. {}",
                            mac_text(&m),
                            a.iface,
                            mac_text(&n),
                            if cfg!(target_os = "macos") {
                                "Pass the NIC MAC as --src-mac, or --allow-foreign-source-mac to override knowingly"
                            } else {
                                "Omit --src-mac to use the NIC MAC, or pass --allow-foreign-source-mac to override knowingly"
                            }
                        ),
                        false,
                    ),
                );
            }
            Some(n) if n != m => {
                eprintln!(
                    "WARNING: --src-mac {} differs from the NIC MAC {}; replies will not arrive without promiscuous mode",
                    mac_text(&m),
                    mac_text(&n)
                );
                (m, "override-foreign")
            }
            Some(_) => (m, "explicit-equal"),
            // macOS 27 скрывает MAC от процесса: сверка невозможна, берём явный --src-mac.
            None if be.nic_mac_masked(&a.iface) => (m, "os-masked"),
            None => (m, "unverified"),
        }
    };

    // JSON-значение: строка с MAC, "masked" (ОС скрыла MAC) или null (неизвестен).
    let nic_mac_json = match nic_mac {
        Some(n) => js(&mac_text(&n)),
        None if mac_check == "os-masked" => js("masked"),
        None => "null".to_string(),
    };
    let mac_fields = format!(
        "\"src_mac\":{},\"src_mac_check\":{},\"nic_mac\":{}",
        js(&mac_text(&src_mac)),
        js(mac_check),
        nic_mac_json
    );
    let plan = match build_plan(a, src_mac, a.rate, a.wait) {
        Ok(p) => p,
        Err(e) => return (2, fail_json("plan", "BadPlan", &e, false)),
    };
    let digest = job_digest(&plan);
    let job = job_json(a, src_mac, a.rate, a.wait, &digest);

    if let Some(n) = a.forge_next_index {
        if n > plan.range() {
            return (
                2,
                fail_json(
                    "forge",
                    "NextIndexBeyondRange",
                    &format!("next_index {n} is beyond the range {}", plan.range()),
                    false,
                ),
            );
        }
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
            return (2, fail_json("forge", "Io", &e.to_string(), false));
        }
        return (
            0,
            format!(
                "{{\"status\":\"forged\",\"next_index\":{n},\"range\":{},\"opened_adapter\":false,\"tx_sent\":0,\"job\":{job},\"identity\":{}}}",
                plan.range(),
                identity_json()
            ),
        );
    }

    // ---- resume: ВСЯ проверка до открытия адаптера (до любой отправки) ----
    let mut resume: Option<Checkpoint> = None;
    if let Some(path) = &a.resume_checkpoint {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => return (2, fail_json("resume-read", "Io", &e.to_string(), false)),
        };
        let cp = match Checkpoint::from_bytes(&bytes) {
            Ok(c) => c,
            Err(e) => {
                return (
                    4,
                    fail_json_job(
                        "resume-preflight",
                        &format!("{e:?}"),
                        &e.to_string(),
                        false,
                        Some(&job),
                    ),
                );
            }
        };
        // Всё, что Engine::resume проверит иначе только после открытия адаптера.
        let pre = if cp.format_version != rmasscan_engine::CHECKPOINT_FORMAT_VERSION {
            Some("UnsupportedFormat")
        } else if cp.engine_version != ENGINE_ALGORITHM_VERSION {
            Some("EngineVersionMismatch")
        } else if cp.job_digest != digest {
            Some("JobMismatch")
        } else if cp.scan_id != a.scan_id {
            Some("ScanIdMismatch")
        } else if cp.attempt_id == a.attempt_id {
            Some("AttemptIdReused")
        } else if cp.next_index == plan.range() {
            Some("AlreadyCompleted")
        } else if cp.next_index > plan.range() {
            Some("NextIndexBeyondRange")
        } else {
            None
        };
        if let Some(kind) = pre {
            return (
                4,
                fail_json_job(
                    "resume-preflight",
                    kind,
                    "rejected before the adapter was opened",
                    false,
                    Some(&job),
                ),
            );
        }
        resume = Some(cp);
    }

    // Состав Npcap для идентичности (только чтение; сбой не мешает скану).
    let npcap = be.inventory().map_or_else(
        |e| npcap_unavailable_json(&e, cfg!(windows)),
        |i| npcap_json(&i),
    );

    let before = metrics::sample();
    let opened = match be.open(plan.binding()) {
        Ok(o) => o,
        Err(e) => {
            return (
                net_error_code(&e),
                fail_json_job("open", &format!("{e:?}"), &e.to_string(), false, Some(&job)),
            );
        }
    };
    let during = metrics::sample();
    let stats = opened.stats;

    let start_index = resume.as_ref().map_or(0, |c| c.next_index);
    let expected_total = plan.range() - start_index;
    let tx_tid: Arc<OnceLock<u64>> = Arc::default();
    let rx_tid: Arc<OnceLock<u64>> = Arc::default();
    let timing = Arc::new(TxTiming {
        t0: Instant::now(),
        t0_utc_ms: unix_ms(),
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
            tid: tx_tid.clone(),
        }),
        rx: Box::new(IdRx {
            inner: if a.rx_stall_ms > 0 {
                Box::new(StallRx {
                    inner: rx,
                    stall: Some(Duration::from_millis(a.rx_stall_ms)),
                })
            } else {
                rx
            },
            tid: rx_tid.clone(),
        }),
    };
    let mut opts = EngineOptions::new(a.scan_id, a.attempt_id);
    if let Some(c) = a.result_capacity {
        opts.result_capacity = c;
    }
    let started = Instant::now();
    let started_utc_ms = unix_ms();
    let handle = match &resume {
        Some(cp) => Engine::resume(plan.clone(), cp.clone(), io, opts),
        None => Engine::start(plan.clone(), io, opts),
    };
    let handle = match handle {
        Ok(h) => h,
        Err(e) => {
            return (
                4,
                fail_json_job(
                    "engine-start",
                    &format!("{e:?}"),
                    &e.to_string(),
                    true,
                    Some(&job),
                ),
            );
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
    let outcome_utc_ms = started_utc_ms
        + u64::try_from(outcome_seen.saturating_duration_since(started).as_millis()).unwrap_or(0);
    let checkpoint = handle.checkpoint();
    let scan_id = handle.scan_id();
    let attempt_id = handle.attempt_id();
    let resumed_from = handle.resumed_from_attempt();
    let join_t0 = Instant::now();
    let (outcome_j, rest) = match handle.join_drain() {
        Ok(v) => v,
        Err(e) => {
            return (
                3,
                fail_json_sent_mac(
                    "join",
                    &format!("{e:?}"),
                    &e.to_string(),
                    true,
                    Some(&job),
                    stats().tx_sent,
                    Some(&mac_fields),
                ),
            );
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
    // (не дольше 1 с) вместе со временем оседания. Где потоки не измеряются
    // (Windows), все три значения null.
    let immediate = metrics::sample();
    let threads_immediate = immediate.threads;
    let settle_t0 = Instant::now();
    let mut threads_after = threads_immediate;
    if let (Some(before_n), Some(mut now)) = (before.threads, threads_after) {
        while now > before_n && settle_t0.elapsed() < Duration::from_secs(1) {
            std::thread::sleep(Duration::from_millis(1));
            now = metrics::sample().threads.unwrap_or(now);
        }
        threads_after = Some(now);
    }
    let threads_settle_ms = settle_t0.elapsed().as_secs_f64() * 1000.0;
    // потоки самого движка (TX и RX), а не общее число потоков процесса: системные рабочие потоки Windows
    // переживают join. Ждём не дольше 1 с, пока ОС уберёт запись завершённого потока.
    let engine_tids = [tx_tid.get().copied(), rx_tid.get().copied()];
    let workers_t0 = Instant::now();
    let mut alive = engine_alive(&engine_tids);
    while alive.contains(&Some(true)) && workers_t0.elapsed() < Duration::from_secs(1) {
        std::thread::sleep(Duration::from_millis(1));
        alive = engine_alive(&engine_tids);
    }
    let workers_settle_ms = workers_t0.elapsed().as_secs_f64() * 1000.0;
    let after = metrics::sample();
    let stats_at_join = stats();
    if a.observe_ms > 0 {
        std::thread::sleep(Duration::from_millis(a.observe_ms));
    }
    let stats_end = stats();

    let (reason, fail_detail) = match &outcome_j.reason {
        Reason::Completed => ("Completed", String::new()),
        Reason::Stopped => ("Stopped", String::new()),
        Reason::Paused => ("Paused", String::new()),
        Reason::Failed(f) => ("Failed", format!("{f:?}")),
    };
    if let (Some(cp), Some(p)) = (&checkpoint, &a.checkpoint_out)
        && let Err(e) = std::fs::write(p, cp.to_bytes())
    {
        return (
            2,
            fail_json_sent_mac(
                "checkpoint-write",
                "Io",
                &e.to_string(),
                true,
                Some(&job),
                stats().tx_sent,
                Some(&mac_fields),
            ),
        );
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
\"scan_id\":{},\"attempt_id\":{},\"resumed_from_attempt\":{},\"src_mac\":{},\"src_mac_check\":{},\"nic_mac\":{},",
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
        js(&mac_text(&src_mac)),
        js(mac_check),
        nic_mac_json,
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
\"resources\":{{\"fds_before_open\":{},\"fds_open\":{},\"fds_after_join\":{},\
\"threads_before\":{},\"threads_after_join_immediate\":{},\"threads_settle_ms\":{threads_settle_ms:.3},\"threads_after_join\":{},\
\"working_set_bytes_after_join\":{},\"peak_working_set_bytes\":{},\"cpu_user_ms\":{},\"cpu_kernel_ms\":{}}},\
\"workers\":{{\"tx_tid\":{},\"rx_tid\":{},\"tx_alive_after_join\":{},\"rx_alive_after_join\":{},\"settle_ms\":{workers_settle_ms:.3}}},\
\"wall\":{{\"t0_utc_ms\":{},\"started_utc_ms\":{started_utc_ms},\"outcome_utc_ms\":{},\"join_done_utc_ms\":{}}},\
\"npcap\":{npcap},\"job\":{job},\"identity\":{}}}",
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
        metrics::json_opt(before.handles),
        metrics::json_opt(during.handles),
        metrics::json_opt(after.handles),
        metrics::json_opt(before.threads),
        metrics::json_opt(threads_immediate),
        metrics::json_opt(threads_after),
        metrics::json_opt(after.working_set_bytes),
        metrics::json_opt(after.peak_working_set_bytes),
        metrics::json_opt(after.cpu_user_ms),
        metrics::json_opt(after.cpu_kernel_ms),
        json_opt_u64(engine_tids[0]),
        json_opt_u64(engine_tids[1]),
        json_opt_bool(alive[0]),
        json_opt_bool(alive[1]),
        t.t0_utc_ms,
        outcome_utc_ms,
        unix_ms(),
        identity_json(),
    );
    (if reason == "Failed" { 3 } else { 0 }, j)
}

/// Блок `npcap` в `run.json`, когда состав Npcap не прочитан. Вне Windows Npcap не
/// используется вовсе (macOS работает через BPF, Linux через AF_PACKET), и текст
/// `NetError::UnsupportedPlatform` («raw packet I/O is not implemented») там вводил бы в
/// заблуждение: сырой ввод-вывод на этих платформах есть. Поле никем не проверяется
/// как строка; ранее записанные свидетельства сохраняют прежний текст.
fn npcap_unavailable_json(e: &NetError, windows: bool) -> String {
    let text = if windows {
        e.to_string()
    } else {
        "not applicable: Npcap is Windows-only; this platform uses its own raw backend (BPF on macOS, AF_PACKET on Linux)".to_string()
    };
    format!("{{\"unavailable\":{}}}", js(&text))
}

#[cfg(test)]
mod tests {
    #[test]
    fn npcap_block_off_windows_says_it_does_not_apply_and_never_claims_raw_io_is_missing() {
        let e = NetError::UnsupportedPlatform;
        let off = npcap_unavailable_json(&e, false);
        assert!(off.contains("Npcap is Windows-only"), "{off}");
        assert!(off.contains("BPF"), "{off}");
        assert!(!off.contains("not implemented"), "{off}");
        let on = npcap_unavailable_json(&e, true);
        assert!(
            on.contains("not implemented"),
            "Windows keeps the driver error: {on}"
        );
    }

    use super::*;
    use std::cell::Cell;

    const NIC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x11];

    /// Считает обращения к «ОС»; `open` всегда отказывает, поэтому любой
    /// переход к адаптеру виден по счётчику и по коду выхода.
    #[derive(Default)]
    struct Mock {
        nic: Option<[u8; 6]>,
        devices: Vec<rmasscan_net::DeviceReport>,
        bpf_devices: Vec<rmasscan_net::BpfDevice>,
        /// macOS: интерфейса нет в ОС.
        missing_iface: bool,
        /// macOS: сам запрос `if_nametoindex` завершился ошибкой (`iface_exists` = None).
        iface_query_error: bool,
        /// macOS: ОС скрыла MAC плейсхолдером (nic_mac None).
        masked: bool,
        inventory_calls: Cell<u32>,
        open_calls: Cell<u32>,
        nic_calls: Cell<u32>,
        /// `open` отвечает PermissionDenied (Admin-only Npcap без прав).
        open_denied: bool,
        fake: Option<rmasscan_engine::fake::FakeAdapter>,
    }

    impl Backend for Mock {
        fn inventory(&self) -> Result<Inventory, NetError> {
            self.inventory_calls.set(self.inventory_calls.get() + 1);
            Ok(Inventory {
                lib_version: "Npcap version test".into(),
                utf8_text: true,
                dlls: vec![],
                driver_version: Some("1.2.3.4".into()),
                devices: self.devices.clone(),
            })
        }
        fn bpf_inventory(&self) -> Result<BpfInventory, NetError> {
            self.inventory_calls.set(self.inventory_calls.get() + 1);
            Ok(BpfInventory {
                os_version: Some("27.0.1 (26A434)".into()),
                kernel_version: Some("Darwin test".into()),
                bpf_maxbufsize: Some(524_288),
                bpf_maxdevices: Some(256),
                devices: self.bpf_devices.clone(),
                interfaces: vec![],
                instant_clock: "test clock",
            })
        }
        fn nic_mac(&self, _: &str) -> Option<[u8; 6]> {
            self.nic_calls.set(self.nic_calls.get() + 1);
            self.nic
        }
        fn iface_exists(&self, _: &str) -> Option<bool> {
            (!self.iface_query_error).then_some(!self.missing_iface)
        }
        fn nic_mac_masked(&self, _: &str) -> bool {
            self.masked
        }
        fn open(&self, _: &AdapterBinding) -> Result<Opened, NetError> {
            self.open_calls.set(self.open_calls.get() + 1);
            if self.open_denied {
                return Err(NetError::PermissionDenied(
                    "mock: only loopback is visible".into(),
                ));
            }
            let Some(fake) = &self.fake else {
                return Err(NetError::System(
                    "mock: adapter must not be opened here".into(),
                ));
            };
            let counted = fake.clone();
            Ok(Opened {
                io: fake.pair(),
                stats: Box::new(move || NetStats {
                    tx_sent: counted.sent_count() as u64,
                    ..NetStats::default()
                }),
            })
        }
    }

    fn args(list: &[&str]) -> Result<Args, String> {
        parse_args(list.iter().map(|s| (*s).to_string()))
    }

    const BASE: &[&str] = &[
        "--iface",
        "\\Device\\NPF_{11111111-2222-3333-4444-555555555555}",
        "--src-ip",
        "198.18.0.1",
        "--router-mac",
        "02:00:00:00:00:22",
        "--targets",
        "198.18.0.2",
        "--ports",
        "80,81",
        "--seed",
        "7",
    ];

    fn with(extra: &[&str]) -> Args {
        let mut v: Vec<&str> = BASE.to_vec();
        // macOS требует явный --src-mac; последующий --src-mac из `extra` его переопределяет.
        #[cfg(target_os = "macos")]
        v.extend_from_slice(&["--src-mac", "02:00:00:00:00:11"]);
        v.extend_from_slice(extra);
        args(&v).unwrap()
    }

    fn tmp(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("wire_scan_{}_{name}", std::process::id()));
        p.display().to_string()
    }

    #[test]
    fn default_run_without_explicit_parameters_does_not_start_a_scan() {
        assert!(args(&[]).is_err());
        // Любой неполный набор тоже отвергается, ни одно значение не берётся «по умолчанию».
        for skip in 0..6 {
            let mut v: Vec<&str> = Vec::new();
            for (i, pair) in BASE.chunks(2).enumerate() {
                if i != skip {
                    v.extend_from_slice(pair);
                }
            }
            assert!(args(&v).is_err(), "missing pair {skip} must be rejected");
        }
        assert!(args(&["--seed", "0", "--iface", "x"]).is_err());
        // Без seed сканирование не стартует, даже если остальное задано.
        let no_seed: Vec<&str> = BASE[..BASE.len() - 2].to_vec();
        assert!(args(&no_seed).is_err());
    }

    #[cfg(not(target_os = "macos"))]
    fn eth() -> rmasscan_net::DeviceReport {
        rmasscan_net::DeviceReport {
            name: "\\Device\\NPF_{11111111-2222-3333-4444-555555555555}".into(),
            description: Some("Test NIC".into()),
            loopback: false,
            mac: Some(NIC),
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn inventory_with_only_hidden_or_loopback_adapters_asks_for_instructions() {
        for devices in [
            vec![],
            vec![rmasscan_net::DeviceReport {
                loopback: true,
                ..eth()
            }],
        ] {
            let be = Mock {
                devices,
                ..Mock::default()
            };
            let (code, json) = run(&args(&["--inventory"]).unwrap(), &be);
            assert_eq!(code, 5, "{json}");
            assert!(json.contains("Administrators-only"), "{json}");
            assert_eq!(be.open_calls.get(), 0);
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn inventory_never_opens_the_adapter() {
        let be = Mock {
            devices: vec![eth()],
            ..Mock::default()
        };
        let (code, json) = run(&args(&["--inventory"]).unwrap(), &be);
        assert_eq!(code, 0, "{json}");
        assert_eq!(be.open_calls.get(), 0);
        assert_eq!(be.inventory_calls.get(), 1);
        assert!(json.contains("\"mode\":\"inventory\""), "{json}");
        assert!(json.contains("\"opened_adapter\":false"), "{json}");
        assert!(json.contains("\"tx_sent\":0"), "{json}");
        assert!(json.contains("\"identity\":{"), "{json}");
        assert!(json.contains("\"driver_version\":\"1.2.3.4\""), "{json}");
    }

    #[test]
    fn inventory_does_not_combine_with_other_modes() {
        assert!(args(&["--inventory", "--write-reference-pcap", "x"]).is_err());
    }

    #[test]
    fn reference_pcap_touches_neither_the_dll_nor_the_adapter() {
        let be = Mock::default();
        let path = tmp("ref.pcap");
        let a = with(&[
            "--src-mac",
            "02:00:00:00:00:11",
            "--write-reference-pcap",
            &path,
        ]);
        let (code, json) = run(&a, &be);
        assert_eq!(code, 0, "{json}");
        assert_eq!(
            (
                be.open_calls.get(),
                be.inventory_calls.get(),
                be.nic_calls.get()
            ),
            (0, 0, 0),
            "reference mode must not load Npcap, query the OS or open an adapter"
        );
        assert!(json.contains("\"frames\":2"), "{json}");
        assert!(json.contains("\"npcap_loaded\":false"), "{json}");
        let data = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        // заголовок 24 + две записи (16 + 58 байт SYN: Ethernet+IP+TCP с опциями)
        assert_eq!(&data[..4], &0xa1b2_c3d4u32.to_le_bytes());
        assert_eq!(data.len(), 24 + 2 * (16 + 58), "{}", data.len());
        assert!(json.contains(&sha256_hex(&data)), "{json}");
    }

    #[test]
    fn reference_pcap_is_reproducible_and_needs_an_explicit_src_mac() {
        let be = Mock::default();
        let (p1, p2) = (tmp("r1.pcap"), tmp("r2.pcap"));
        for p in [&p1, &p2] {
            let a = with(&[
                "--src-mac",
                "02:00:00:00:00:11",
                "--write-reference-pcap",
                p,
            ]);
            assert_eq!(run(&a, &be).0, 0);
        }
        let (d1, d2) = (std::fs::read(&p1).unwrap(), std::fs::read(&p2).unwrap());
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
        assert_eq!(d1, d2);
        assert!(args(&[BASE, &["--write-reference-pcap", "x"]].concat()).is_err());
    }

    #[test]
    fn mismatched_checkpoint_is_rejected_before_adapter_open() {
        let be = Mock {
            nic: Some(NIC),
            ..Mock::default()
        };
        // Контрольная точка от ДРУГОГО набора портов.
        let cp = tmp("other.cp");
        let forge = with(&[
            "--src-mac",
            "02:00:00:00:00:11",
            "--ports",
            "9000",
            "--forge-checkpoint-next-index",
            "0",
            "--checkpoint-out",
            &cp,
        ]);
        let (c, j) = run(&forge, &be);
        assert_eq!(c, 0, "{j}");
        let mut a = with(&["--resume-checkpoint", &cp, "--attempt-id", &"03".repeat(16)]);
        a.scan_id = [1; 16];
        let (code, json) = run(&a, &be);
        let _ = std::fs::remove_file(&cp);
        assert_eq!(code, 4, "{json}");
        assert!(json.contains("JobMismatch"), "{json}");
        assert_eq!(
            be.open_calls.get(),
            0,
            "adapter opened despite a bad checkpoint"
        );
    }

    #[test]
    fn corrupt_checkpoint_is_rejected_before_adapter_open() {
        let be = Mock {
            nic: Some(NIC),
            ..Mock::default()
        };
        let cp = tmp("junk.cp");
        std::fs::write(&cp, b"not a checkpoint").unwrap();
        let (code, json) = run(&with(&["--resume-checkpoint", &cp]), &be);
        let _ = std::fs::remove_file(&cp);
        assert_eq!(code, 4, "{json}");
        assert_eq!(be.open_calls.get(), 0);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn source_mac_defaults_to_the_nic_and_foreign_mac_is_refused() {
        // Без --src-mac берётся MAC NIC: открытие адаптера достигнуто (мок отказывает).
        let be = Mock {
            nic: Some(NIC),
            ..Mock::default()
        };
        let (code, json) = run(&with(&[]), &be);
        assert_eq!(be.open_calls.get(), 1, "{json}");
        assert_eq!(code, 2, "{json}");

        // Чужой MAC без override: отказ ДО открытия, код 6.
        let be = Mock {
            nic: Some(NIC),
            ..Mock::default()
        };
        let (code, json) = run(&with(&["--src-mac", "02:aa:bb:cc:dd:ee"]), &be);
        assert_eq!(code, 6, "{json}");
        assert!(json.contains("SourceMacMismatch"), "{json}");
        assert_eq!(be.open_calls.get(), 0);

        // Явное разрешение: идём дальше (мок отказывает при open).
        let be = Mock {
            nic: Some(NIC),
            ..Mock::default()
        };
        let (_, json) = run(
            &with(&[
                "--src-mac",
                "02:aa:bb:cc:dd:ee",
                "--allow-foreign-source-mac",
            ]),
            &be,
        );
        assert_eq!(be.open_calls.get(), 1, "{json}");

        // NIC неизвестен и MAC не задан: скан не стартует.
        let be = Mock::default();
        let (code, json) = run(&with(&[]), &be);
        assert_eq!(code, 2, "{json}");
        assert_eq!(be.open_calls.get(), 0);
    }

    #[cfg(target_os = "macos")]
    fn bpf_node(mode: u32) -> rmasscan_net::BpfDevice {
        rmasscan_net::BpfDevice {
            path: "/dev/bpf0".into(),
            mode,
            uid: 0,
            gid: 0,
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inventory_mode_never_opens_bpf_or_sends() {
        // Подставной backend: узлы 0600, адаптер не открывается ни разу.
        {
            let be = Mock {
                bpf_devices: vec![bpf_node(0o600)],
                ..Mock::default()
            };
            let (code, json) = run(&args(&["--inventory"]).unwrap(), &be);
            assert_eq!(code, 0, "{json}");
            assert_eq!(be.open_calls.get(), 0);
            assert!(json.contains("\"opened_adapter\":false"), "{json}");
            assert!(json.contains("\"tx_sent\":0"), "{json}");
            assert!(json.contains("\"instant_clock\":\"test clock\""), "{json}");
            assert!(
                json.contains(
                    "\"devices\":[{\"path\":\"/dev/bpf0\",\"mode\":384,\"mode_octal\":\"0600\""
                ),
                "{json}"
            );
            assert!(json.contains("\"raw_io_abi\":"), "{json}");
        }
        // Настоящий backend: перечень читает sysctl/stat/getifaddrs, BPF не открывает,
        // поэтому проходит при любых правах на /dev/bpf* (в том числе 0600 root:wheel).
        {
            let (code, json) = run(&args(&["--inventory"]).unwrap(), &RealBackend);
            assert_eq!(code, 0, "{json}");
            assert!(json.contains("\"mode\":\"inventory\""), "{json}");
            assert!(json.contains("\"opened_adapter\":false"), "{json}");
            assert!(
                json.contains("\"instant_clock\":\"CLOCK_UPTIME_RAW"),
                "{json}"
            );
        }
    }

    #[test]
    fn reference_pcap_mode_needs_no_bpf() {
        let be = Mock::default();
        let p = tmp("nobpf.pcap");
        let a = with(&[
            "--src-mac",
            "02:00:00:00:00:11",
            "--write-reference-pcap",
            &p,
        ]);
        let (code, json) = run(&a, &be);
        let _ = std::fs::remove_file(&p);
        assert_eq!(code, 0, "{json}");
        assert_eq!(be.open_calls.get(), 0);
        assert_eq!(be.inventory_calls.get(), 0);
        assert_eq!(be.nic_calls.get(), 0, "reference mode must not ask the OS");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_requires_src_mac_and_checks_it_against_the_interface() {
        // --src-mac обязателен как на Linux.
        assert!(args(BASE).is_err());

        // Интерфейса нет: InterfaceMismatch, rc 2, адаптер не открыт.
        let be = Mock {
            missing_iface: true,
            ..Mock::default()
        };
        let (code, json) = run(&with(&[]), &be);
        assert_eq!(code, 2, "{json}");
        assert!(json.contains("InterfaceMismatch"), "{json}");
        assert_eq!(be.open_calls.get(), 0);

        // Чужой MAC без override: код 6 до открытия.
        let be = Mock {
            nic: Some(NIC),
            ..Mock::default()
        };
        let (code, json) = run(&with(&["--src-mac", "02:aa:bb:cc:dd:ee"]), &be);
        assert_eq!(code, 6, "{json}");
        assert!(json.contains("SourceMacMismatch"), "{json}");
        assert_eq!(be.open_calls.get(), 0);

        // С явным разрешением идём к открытию (мок отказывает).
        let be = Mock {
            nic: Some(NIC),
            ..Mock::default()
        };
        let (_, json) = run(
            &with(&[
                "--src-mac",
                "02:aa:bb:cc:dd:ee",
                "--allow-foreign-source-mac",
            ]),
            &be,
        );
        assert_eq!(be.open_calls.get(), 1, "{json}");

        // ОС скрыла MAC: сверки нет (не rc 6), берётся явный --src-mac, JSON говорит masked.
        let be = Mock {
            masked: true,
            fake: Some(rmasscan_engine::fake::FakeAdapter::new()),
            ..Mock::default()
        };
        let (code, json) = run(
            &with(&["--src-mac", "02:ac:00:00:00:01", "--wait", "0"]),
            &be,
        );
        assert_eq!(code, 0, "{json}");
        assert!(json.contains("\"src_mac_check\":\"os-masked\""), "{json}");
        assert!(json.contains("\"nic_mac\":\"masked\""), "{json}");
        assert!(json.contains("\"src_mac\":\"02:ac:00:00:00:01\""), "{json}");

        // N1: ошибка запроса существования интерфейса отказ, а не «unverified».
        let be = Mock {
            iface_query_error: true,
            ..Mock::default()
        };
        let (code, json) = run(&with(&["--src-mac", "02:ac:00:00:00:01"]), &be);
        assert_eq!(code, 2, "{json}");
        assert!(json.contains("\"stage\":\"binding\""), "{json}");
        assert!(json.contains("could not determine"), "{json}");
        assert_eq!(be.open_calls.get(), 0, "{json}");

        // N3: MAC неизвестен и не скрыт: nic_mac это null, а не строка.
        let be = Mock {
            fake: Some(rmasscan_engine::fake::FakeAdapter::new()),
            ..Mock::default()
        };
        let (code, json) = run(
            &with(&["--src-mac", "02:ac:00:00:00:01", "--wait", "0"]),
            &be,
        );
        assert_eq!(code, 0, "{json}");
        assert!(json.contains("\"src_mac_check\":\"unverified\""), "{json}");
        assert!(json.contains("\"nic_mac\":null"), "{json}");

        // Настоящее расхождение при видимом MAC остаётся кодом 6 (повтор для ясности).
        let be = Mock {
            nic: Some(NIC),
            masked: false,
            ..Mock::default()
        };
        assert_eq!(run(&with(&["--src-mac", "02:ac:00:00:00:01"]), &be).0, 6);

        // Offline forge не зависит от ОС: нет интерфейса, и всё равно rc 0 без открытия.
        let be = Mock {
            missing_iface: true,
            ..Mock::default()
        };
        let cp = tmp("forge_skip.cp");
        let (code, json) = run(
            &with(&[
                "--forge-checkpoint-next-index",
                "0",
                "--checkpoint-out",
                &cp,
            ]),
            &be,
        );
        let _ = std::fs::remove_file(&cp);
        assert_eq!(code, 0, "{json}");
        assert_eq!(be.open_calls.get(), 0);

        // Равный MAC: открытие достигнуто.
        let be = Mock {
            nic: Some(NIC),
            ..Mock::default()
        };
        let _ = run(&with(&[]), &be);
        assert_eq!(be.open_calls.get(), 1);
    }

    #[test]
    fn checkpoint_beyond_the_range_is_rejected_before_adapter_open() {
        let be = Mock {
            nic: Some(NIC),
            ..Mock::default()
        };
        // Контрольная точка нужного задания, но next_index за пределом диапазона (2 пробы).
        let a = with(&[]);
        let plan = build_plan(&a, NIC, a.rate, a.wait).unwrap();
        let cp = Checkpoint {
            format_version: rmasscan_engine::CHECKPOINT_FORMAT_VERSION,
            engine_version: ENGINE_ALGORITHM_VERSION,
            scan_id: a.scan_id,
            attempt_id: [9; 16],
            job_digest: job_digest(&plan),
            next_index: 999,
        };
        let path = tmp("beyond.cp");
        std::fs::write(&path, cp.to_bytes()).unwrap();
        let a = with(&[
            "--resume-checkpoint",
            &path,
            "--attempt-id",
            &format!("{}0a", "09".repeat(15)),
        ]);
        let (code, json) = run(&a, &be);
        let _ = std::fs::remove_file(&path);
        assert_eq!(code, 4, "{json}");
        assert!(json.contains("NextIndexBeyondRange"), "{json}");
        assert_eq!(
            be.open_calls.get(),
            0,
            "adapter opened for an out-of-range checkpoint"
        );
        // и forge не создаёт такую точку
        let (c, j) = run(
            &with(&[
                "--src-mac",
                "02:00:00:00:00:11",
                "--forge-checkpoint-next-index",
                "999",
            ]),
            &be,
        );
        assert_eq!(c, 2, "{j}");
    }

    #[test]
    fn zero_result_capacity_is_rejected_at_argument_parsing() {
        let mut v: Vec<&str> = BASE.to_vec();
        v.extend_from_slice(&["--result-capacity", "0"]);
        assert!(args(&v).err().unwrap().contains("result-capacity"));
    }

    #[test]
    fn job_is_recorded_in_reference_forge_and_preflight_errors() {
        let be = Mock {
            nic: Some(NIC),
            ..Mock::default()
        };
        let path = tmp("job.pcap");
        let (code, json) = run(
            &with(&[
                "--src-mac",
                "02:00:00:00:00:11",
                "--write-reference-pcap",
                &path,
            ]),
            &be,
        );
        let _ = std::fs::remove_file(&path);
        assert_eq!(code, 0, "{json}");
        for k in [
            "\"job\":{\"iface\":",
            "\"src_ip\":\"198.18.0.1\"",
            "\"router_mac\":\"02:00:00:00:00:22\"",
            "\"targets\":\"198.18.0.2\"",
            "\"ports\":\"80,81\"",
            "\"seed\":7",
            "\"rate\":100",
            "\"job_digest\":\"",
        ] {
            assert!(json.contains(k), "{k} missing: {json}");
        }
        let cp = tmp("junkjob.cp");
        std::fs::write(&cp, b"x").unwrap();
        let (_, j) = run(&with(&["--resume-checkpoint", &cp]), &be);
        let _ = std::fs::remove_file(&cp);
        assert!(j.contains("\"job\":null") || j.contains("\"job\":{"), "{j}");
    }

    #[test]
    fn permission_denied_on_open_exits_5_with_the_open_stage() {
        let be = Mock {
            nic: Some(NIC),
            open_denied: true,
            ..Mock::default()
        };
        let (code, json) = run(&with(&[]), &be);
        assert_eq!(be.open_calls.get(), 1, "{json}");
        assert_eq!(code, 5, "{json}");
        assert!(json.contains("PermissionDenied"), "{json}");
    }

    #[test]
    fn denied_or_missing_npcap_maps_to_exit_5() {
        assert_eq!(net_error_code(&NetError::PermissionDenied("x".into())), 5);
        assert_eq!(net_error_code(&NetError::DriverUnavailable("x".into())), 5);
        assert_eq!(net_error_code(&NetError::System("x".into())), 2);
    }

    #[test]
    fn failure_after_sending_reports_the_real_tx_counters() {
        // Pause после 1 отправки даёт checkpoint; запись в каталог падает
        // (checkpoint-write). Кадр уже ушёл: tx_sent обязан быть 1, не 0.
        let be = Mock {
            nic: Some(NIC),
            fake: Some(rmasscan_engine::fake::FakeAdapter::new()),
            ..Mock::default()
        };
        let dir = std::env::temp_dir().display().to_string();
        let (code, json) = run(
            &with(&[
                "--wait",
                "0",
                "--pause-after",
                "1",
                "--checkpoint-out",
                &dir,
            ]),
            &be,
        );
        assert_eq!(code, 2, "{json}");
        assert!(json.contains("\"stage\":\"checkpoint-write\""), "{json}");
        assert!(json.contains("\"tx_sent\":1,"), "{json}");
        assert!(json.contains("\"opened_adapter\":true"), "{json}");
        assert!(json.contains("\"job\":{"), "{json}");
    }

    #[test]
    fn success_json_reports_engine_threads_and_wall_clock() {
        let be = Mock {
            nic: Some(NIC),
            fake: Some(rmasscan_engine::fake::FakeAdapter::new()),
            ..Mock::default()
        };
        let (code, json) = run(&with(&["--wait", "0"]), &be);
        assert_eq!(code, 0, "{json}");
        for k in [
            "\"workers\":{\"tx_tid\":",
            "\"rx_tid\":",
            "\"tx_alive_after_join\":",
            "\"wall\":{\"t0_utc_ms\":",
            "\"started_utc_ms\":",
            "\"outcome_utc_ms\":",
            "\"join_done_utc_ms\":",
        ] {
            assert!(json.contains(k), "{k} missing: {json}");
        }
        // where the OS gives thread ids, both engine threads were seen and are gone after join
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        assert!(
            json.contains("\"tx_alive_after_join\":false")
                && json.contains("\"rx_alive_after_join\":false"),
            "{json}"
        );
    }

    #[test]
    fn every_failure_json_carries_the_identity() {
        let j = fail_json("args", "BadArgs", "boom", false);
        assert!(j.contains("\"identity\":{\"source_commit\":"), "{j}");
        assert!(j.contains("\"binary_sha256\":\""), "{j}");
    }

    #[test]
    fn post_send_failure_json_carries_the_mac_identity() {
        let fields = "\"src_mac\":\"02:ac:00:00:00:01\",\"src_mac_check\":\"os-masked\",\"nic_mac\":\"masked\"";
        let j = fail_json_sent_mac("join", "Panicked", "x", true, None, 7, Some(fields));
        assert!(
            j.contains("\"tx_sent\":7,\"src_mac\":\"02:ac:00:00:00:01\""),
            "{j}"
        );
        assert!(j.contains("\"src_mac_check\":\"os-masked\""), "{j}");
        assert!(j.contains("\"nic_mac\":\"masked\""), "{j}");
        let plain = fail_json_sent("join", "Panicked", "x", true, None, 7);
        assert!(!plain.contains("src_mac"), "{plain}");
    }

    fn harness_over(
        fake: &rmasscan_engine::fake::FakeAdapter,
        pause_after: Option<u64>,
    ) -> (HarnessTx, Arc<OnceLock<CancelHandle>>, Arc<TxTiming>) {
        let cancel: Arc<OnceLock<CancelHandle>> = Arc::default();
        let timing = Arc::new(TxTiming {
            t0: Instant::now(),
            t0_utc_ms: 0,
            mark_at: 3,
            first_ns: AtomicU64::new(0),
            mark_ns: AtomicU64::new(0),
            last_ns: AtomicU64::new(0),
            last_idx: AtomicU64::new(0),
        });
        let tx = HarnessTx {
            inner: fake.pair().tx,
            pause_after,
            sent: 0,
            cancel: cancel.clone(),
            timing: timing.clone(),
            tid: Arc::default(),
        };
        (tx, cancel, timing)
    }

    #[test]
    fn harness_forwards_max_batch() {
        let fake = rmasscan_engine::fake::FakeAdapter::new();
        let (tx, _, _) = harness_over(&fake, None);
        assert_eq!(tx.max_batch(), 1, "the default is the single path");
        fake.set_max_batch(8);
        assert_eq!(tx.max_batch(), 8);
        // ... and the whole batch reaches the inner adapter in ONE call.
        let (mut tx, _, timing) = harness_over(&fake, None);
        let frames: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 60]).collect();
        let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        let r = tx.send_batch(&refs, Duration::from_millis(1)).unwrap();
        assert_eq!(
            r,
            TxBatch {
                sent: 8,
                rest: SendStatus::Sent
            }
        );
        assert_eq!(fake.batch_sizes(), vec![8]);
        assert_eq!(fake.sent_frames(), frames);
        assert_eq!(timing.last_idx.load(Ordering::Acquire), 8);
        assert!(timing.first_ns.load(Ordering::Relaxed) <= timing.last_ns.load(Ordering::Relaxed));
        // mark_at (3) lies inside the batch and was stamped.
        assert_eq!(
            timing.mark_ns.load(Ordering::Relaxed),
            timing.last_ns.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn pause_after_inside_a_batch_cuts_the_batch_exactly_at_n() {
        let fake = rmasscan_engine::fake::FakeAdapter::new();
        fake.set_max_batch(8);
        let (mut tx, cancel, timing) = harness_over(&fake, Some(5));
        // Pause needs a handle: a real engine is not needed, the cell is only
        // read, so give it one from a throwaway engine handle.
        let plan = {
            let mut m = MassIp::new();
            add_target_string(m.ipv4_mut(), "10.0.0.1").unwrap();
            parse_ports(m.ports_mut(), "80").unwrap();
            let cfg = ScanConfig {
                targets: m,
                seed: 1,
                max_rate: 1.0,
                ..ScanConfig::default()
            };
            ReadyPlan::new(
                validate(&cfg, Operation::Scan).unwrap(),
                AdapterBinding {
                    interface_id: "fake0".into(),
                    link_type: LinkType::Ethernet,
                    source_ipv4: 0x0aff_0001,
                    source_mac: [2, 0, 0, 0, 0, 1],
                    next_hop_mac: [2, 0, 0, 0, 0, 2],
                    source_ports: (40000, 40000),
                },
            )
            .unwrap()
        };
        let eng = rmasscan_engine::Engine::start(
            plan,
            rmasscan_engine::fake::FakeAdapter::new().pair(),
            EngineOptions::new([1; 16], [2; 16]),
        )
        .unwrap();
        cancel.set(eng.cancel_handle()).ok();

        let frames: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 60]).collect();
        let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        let r = tx.send_batch(&refs, Duration::from_millis(1)).unwrap();
        // The inner adapter saw exactly 5 frames, then the pause fired and the
        // 6th frame stayed with the cursor.
        assert_eq!(
            r,
            TxBatch {
                sent: 5,
                rest: SendStatus::WouldBlockUnsent
            }
        );
        assert_eq!(fake.batch_sizes(), vec![5]);
        assert_eq!(fake.sent_frames(), frames[..5].to_vec());
        assert_eq!(timing.last_idx.load(Ordering::Acquire), 5);
        // A further call at the boundary sends nothing at all.
        let r = tx.send_batch(&refs[5..], Duration::from_millis(1)).unwrap();
        assert_eq!(
            r,
            TxBatch {
                sent: 0,
                rest: SendStatus::WouldBlockUnsent
            }
        );
        assert_eq!(fake.batch_calls(), 1, "no inner call at the boundary");
        assert_eq!(fake.sent_count(), 5);
        eng.stop();
        let _ = eng.join();
    }
}
