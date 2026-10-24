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
//! --write-reference-pcap FILE  ожидаемые SYN-кадры для заданного binding;
//!                              DLL не загружается, адаптер не открывается
//!                              (нужны те же явные параметры, включая --src-mac).
//! --allow-foreign-source-mac   осознанно разрешить --src-mac, отличный от MAC
//!                              NIC (без promiscuous ответы не придут).
//!
//! Идентичность (коммит, sha256 бинарника, ОС, Npcap/драйвер/DLL, ABI) есть
//! в каждом JSON-выводе.
//!
//! Коды выхода: 0 Completed/Paused/Stopped; 2 ошибка аргументов/плана/
//! открытия адаптера; 3 Failed; 4 resume отвергнут до открытия адаптера;
//! 5 нет Npcap или недостаточно прав (Admin-only Npcap): нужна инструкция;
//! 6 source MAC не совпадает с MAC выбранного NIC.

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
use rmasscan_net::{Inventory, NetError, OpenedAdapter, open_explicit};

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
                a.result_capacity = Some(val(&k)?.parse().map_err(|e| format!("{k}: {e}"))?);
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
    if offline {
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
    format!(
        "{{\"status\":\"error\",\"stage\":{},\"error\":{},\"message\":{},\"opened_adapter\":{opened},\"tx_sent\":0,\"identity\":{}}}",
        js(stage),
        js(kind),
        js(msg),
        identity_json()
    )
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

/// Всё, что harness берёт у ОС и Npcap. Шов нужен тестам: подставной backend
/// считает обращения и доказывает, что безопасные режимы и отказы до открытия
/// не доходят до адаптера.
trait Backend {
    fn inventory(&self) -> Result<Inventory, NetError>;
    fn nic_mac(&self, interface_id: &str) -> Option<[u8; 6]>;
    fn open(&self, binding: &AdapterBinding) -> Result<OpenedAdapter, NetError>;
}

struct RealBackend;

impl Backend for RealBackend {
    fn inventory(&self) -> Result<Inventory, NetError> {
        rmasscan_net::inventory()
    }
    fn nic_mac(&self, interface_id: &str) -> Option<[u8; 6]> {
        rmasscan_net::nic_mac(interface_id)
    }
    fn open(&self, binding: &AdapterBinding) -> Result<OpenedAdapter, NetError> {
        open_explicit(binding)
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

fn inventory_mode(be: &dyn Backend) -> Out {
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
\"pcap_sha256\":{},\"opened_adapter\":false,\"npcap_loaded\":false,\"tx_sent\":0,\"identity\":{}}}",
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
because promiscuous mode is not enabled. Omit --src-mac to use the NIC MAC, or pass \
--allow-foreign-source-mac to override knowingly",
                            mac_text(&m),
                            a.iface,
                            mac_text(&n)
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
            None => (m, "unverified"),
        }
    };

    let plan = match build_plan(a, src_mac, a.rate, a.wait) {
        Ok(p) => p,
        Err(e) => return (2, fail_json("plan", "BadPlan", &e, false)),
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
            return (2, fail_json("forge", "Io", &e.to_string(), false));
        }
        return (
            0,
            format!(
                "{{\"status\":\"forged\",\"next_index\":{n},\"range\":{},\"opened_adapter\":false,\"tx_sent\":0,\"identity\":{}}}",
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
                    fail_json("resume-preflight", &format!("{e:?}"), &e.to_string(), false),
                );
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
            return (
                4,
                fail_json(
                    "resume-preflight",
                    kind,
                    "rejected before the adapter was opened",
                    false,
                ),
            );
        }
        resume = Some(cp);
    }

    // Состав Npcap для идентичности (только чтение; сбой не мешает скану).
    let npcap = be.inventory().map_or_else(
        |e| format!("{{\"unavailable\":{}}}", js(&e.to_string())),
        |i| npcap_json(&i),
    );

    let before = metrics::sample();
    let opened = match be.open(plan.binding()) {
        Ok(o) => o,
        Err(e) => {
            return (
                net_error_code(&e),
                fail_json("open", &format!("{e:?}"), &e.to_string(), false),
            );
        }
    };
    let during = metrics::sample();
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
            return (
                4,
                fail_json("engine-start", &format!("{e:?}"), &e.to_string(), true),
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
                fail_json("join", &format!("{e:?}"), &e.to_string(), true),
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
    let after = metrics::sample();
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
        return (2, fail_json("checkpoint-write", "Io", &e.to_string(), true));
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
\"scan_id\":{},\"attempt_id\":{},\"resumed_from_attempt\":{},\"src_mac\":{},\"src_mac_check\":{},",
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
\"npcap\":{npcap},\"identity\":{}}}",
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
        identity_json(),
    );
    (if reason == "Failed" { 3 } else { 0 }, j)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const NIC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x11];

    /// Считает обращения к «ОС»; `open` всегда отказывает, поэтому любой
    /// переход к адаптеру виден по счётчику и по коду выхода.
    #[derive(Default)]
    struct Mock {
        nic: Option<[u8; 6]>,
        devices: Vec<rmasscan_net::DeviceReport>,
        inventory_calls: Cell<u32>,
        open_calls: Cell<u32>,
        nic_calls: Cell<u32>,
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
        fn nic_mac(&self, _: &str) -> Option<[u8; 6]> {
            self.nic_calls.set(self.nic_calls.get() + 1);
            self.nic
        }
        fn open(&self, _: &AdapterBinding) -> Result<OpenedAdapter, NetError> {
            self.open_calls.set(self.open_calls.get() + 1);
            Err(NetError::System(
                "mock: adapter must not be opened here".into(),
            ))
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

    fn eth() -> rmasscan_net::DeviceReport {
        rmasscan_net::DeviceReport {
            name: "\\Device\\NPF_{11111111-2222-3333-4444-555555555555}".into(),
            description: Some("Test NIC".into()),
            loopback: false,
            mac: Some(NIC),
        }
    }

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

    #[test]
    fn denied_or_missing_npcap_maps_to_exit_5() {
        assert_eq!(net_error_code(&NetError::PermissionDenied("x".into())), 5);
        assert_eq!(net_error_code(&NetError::DriverUnavailable("x".into())), 5);
        assert_eq!(net_error_code(&NetError::System("x".into())), 2);
    }

    #[test]
    fn every_failure_json_carries_the_identity() {
        let j = fail_json("args", "BadArgs", "boom", false);
        assert!(j.contains("\"identity\":{\"source_commit\":"), "{j}");
        assert!(j.contains("\"binary_sha256\":\""), "{j}");
    }
}
