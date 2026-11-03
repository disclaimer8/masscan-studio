//! Живой путь CLI (AGPL-3.0): обнаружение адаптера и шлюза, ARP, план, открытие адаптера, engine и приёмник; плюс
//! `--offline` (обнаружение только чтением) и `--iflist`. Порт `masscan_initialize_adapter` (`main-initadapter.c`) и
//! `main_scan` (`main.c`) masscan © Robert David Graham (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0) в форме
//! решений плана: интерфейс по маршруту к целям, ARP к следующему хопу, один порт источника по умолчанию.
//!
//! Порядок: `defaults (seed, порт) → validate → detect → пробная сборка ReadyPlan → печать [+] → ARP → ReadyPlan →
//! open → Engine → события → Sink → join`. Пробный план (next hop ещё нулевой) проверяет ограничения runtime
//! (`--retries`, `--shard`, rounds, legacy resume) до ARP, чтобы отклонённый engine скан не стоил ни одного ARP-кадра;
//! настоящий план строится после ARP, потому что binding неизменяем. Всё состояние ОС приходит через шов
//! [`Backend`]; обнаружение, `--offline` и `--iflist` ничего не открывают. Единственный кадр до engine это ARP-запрос
//! резолвера с отдельного короткоживущего адаптера, закрытого до открытия адаптера скана. Ctrl-C не перехватывается,
//! `paused.conf` не пишется.

#![forbid(unsafe_code)]

use std::io::Write;
use std::net::Ipv4Addr;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

use rmasscan_core::config::{EffectiveConfig, Operation, ScanConfig, validate};
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{
    AdapterBinding, Probe, ReadyPlan, for_each_probe as core_for_each_probe,
};
use rmasscan_core::receive::PortStatus;
use rmasscan_core::throttle::Clock;
use rmasscan_engine::{AdapterPair, Engine, EngineOptions, Event, Outcome, Reason};
use rmasscan_net::arp_resolve::{ArpPolicy, NextHopKind, arp_binding, resolve_next_hop};
use rmasscan_net::discover::{NextHopWhy, Source, usable_source_mac};
use rmasscan_net::{
    DetectError, Detected, Iface, Interfaces, NetError, NextHop, Overrides, RouteTable, detect,
    detect_offline, iflist_text, probe_targets,
};

use crate::args::SeedPolicy;
use crate::output::{Sink, io_fail};

/// Префикс отказов обнаружения и ARP в форме C (`[-] FAIL: …` и подсказки); [`crate::error_text`] не оборачивает их.
pub const REFUSAL_PREFIX: &str = "[-] ";

/// Всё, что CLI берёт у ОС. Тесты подставляют fake (его `open` паникует или выдаёт `FakeAdapter`); настоящая
/// реализация (`OsBackend`) живёт только в бинарнике, в `src/os_backend.rs` под `#[cfg(not(test))]`.
pub trait Backend {
    /// Таблица маршрутов (только чтение, без привилегий).
    fn routes(&self) -> Result<Box<dyn RouteTable>, NetError>;
    /// Список интерфейсов (только чтение, без привилегий).
    fn interfaces(&self) -> Result<Box<dyn Interfaces>, NetError>;
    /// Открывает адаптер по явному binding: единственное место, где нужны root/Administrator/BPF.
    fn open(&self, binding: &AdapterBinding) -> Result<AdapterPair, NetError>;
    /// 64 бита энтропии ОС, не 0 (seed живого скана, идентификаторы запуска).
    fn entropy64(&self) -> u64;
    /// Секунды Unix-времени (порт источника по умолчанию `40000 + t % 20000`).
    fn unix_time(&self) -> u64;
    /// Интервал и срок ARP.
    fn arp_policy(&self) -> ArpPolicy;
    /// Часы резолвера ARP, engine и трассы `--packet-trace` (одни и те же).
    fn clock(&self) -> Arc<dyn Clock + Send + Sync>;
}

/// Подготовленный скан: проверенная конфигурация, обнаружение и binding. `binding.next_hop_mac` для
/// `NextHop::Resolve` нулевой: его заполняет ARP в [`run_live`].
#[derive(Debug, Clone)]
pub struct Prepared {
    pub eff: EffectiveConfig,
    pub detected: Detected,
    pub binding: AdapterBinding,
    /// `Source::Detected` значит «из энтропии».
    pub seed: (u64, Source),
    /// `Source::Detected` значит «по времени».
    pub source_ports: ((u16, u16), Source),
}

fn refusal(e: impl std::fmt::Display) -> String {
    format!("{REFUSAL_PREFIX}{e}")
}

/// `--offline` с явными `--adapter-ip`, `--adapter-mac` и `--source-port` (решение 6): ОС не опрашивается вовсе
/// (golden-тесты герметичны). Без любого из трёх идёт обычное обнаружение только чтением, поэтому `--offline`
/// годится как preflight живого прогона (R1). `port` это источник порта до подстановки умолчания.
fn hermetic_offline(eff: &EffectiveConfig, port: Source) -> bool {
    eff.offline()
        && eff.adapter_ip().is_some()
        && eff.adapter_mac().is_some()
        && port == Source::Given
}

/// Фиктивный MAC шлюза `--offline` (C `main-initadapter.c:163`).
const OFFLINE_ROUTER_MAC: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

/// Обнаружение для герметичного `--offline`: все значения заданы, интерфейс не ищется.
fn given_offline(eff: &EffectiveConfig, ip: u32, mac: [u8; 6]) -> Result<Detected, String> {
    let name = eff.adapter_name().unwrap_or("offline").to_string();
    if !usable_source_mac(mac) {
        return Err(refusal(DetectError::NoMac(name)));
    }
    Ok(Detected {
        iface: Iface {
            name: name.clone(),
            index: 0,
            device_id: name,
            description: None,
            mac: Some(mac),
            mac_masked: false,
            ethernet: true,
            up: true,
            ipv4: vec![Ipv4Addr::from(ip)],
        },
        iface_source: Source::Given,
        source_ipv4: (Ipv4Addr::from(ip), Source::Given),
        source_mac: (mac, Source::Given),
        next_hop: NextHop::Mac(OFFLINE_ROUTER_MAC, Source::Given),
    })
}

/// `defaults → validate(Scan) → probe_targets → detect | detect_offline`; ничего не открывает.
pub fn prepare(
    cfg: &ScanConfig,
    seed: SeedPolicy,
    backend: &dyn Backend,
    offline: bool,
) -> Result<Prepared, String> {
    let mut cfg = cfg.clone();
    cfg.offline = offline;
    let seed = match (cfg.seed, seed) {
        (0, SeedPolicy::Entropy) => (backend.entropy64(), Source::Detected),
        (s, _) => (s, Source::Given),
    };
    cfg.seed = seed.0;
    // C: один порт `40000 + time % 20000` и диапазон {p, p+16}; здесь один порт (решение 6).
    let source_ports = match cfg.source_port {
        Some(p) => (p, Source::Given),
        None => {
            let p = 40000 + (backend.unix_time() % 20000) as u16;
            ((p, p), Source::Detected)
        }
    };
    cfg.source_port = Some(source_ports.0);
    let eff = validate(&cfg, Operation::Scan).map_err(|e| e.to_string())?;
    let detected = if let (true, Some(ip), Some(mac)) = (
        hermetic_offline(&eff, source_ports.1),
        eff.adapter_ip(),
        eff.adapter_mac(),
    ) {
        given_offline(&eff, ip, mac)?
    } else {
        let targets =
            probe_targets(eff.massip()).ok_or_else(|| refusal(DetectError::NoUnicastTargets))?;
        let ov = Overrides {
            adapter: eff.adapter_name().map(str::to_string),
            adapter_ip: eff.adapter_ip().map(Ipv4Addr::from),
            adapter_mac: eff.adapter_mac(),
            router_ip: eff.router_ip().map(Ipv4Addr::from),
            router_mac: eff.router_mac(),
        };
        let os = |e: NetError| refusal(DetectError::Os(e));
        let routes = backend.routes().map_err(os)?;
        let ifaces = backend.interfaces().map_err(os)?;
        let found = if offline {
            detect_offline(&targets, &ov, routes.as_ref(), ifaces.as_ref())
        } else {
            detect(&targets, &ov, routes.as_ref(), ifaces.as_ref())
        };
        found.map_err(refusal)?
    };
    let binding = AdapterBinding {
        interface_id: detected.iface.device_id.clone(),
        link_type: LinkType::Ethernet,
        source_ipv4: u32::from(detected.source_ipv4.0),
        source_mac: detected.source_mac.0,
        next_hop_mac: match detected.next_hop {
            NextHop::Mac(m, _) => m,
            NextHop::Resolve { .. } => [0; 6],
        },
        source_ports: source_ports.0,
    };
    Ok(Prepared {
        eff,
        detected,
        binding,
        seed,
        source_ports,
    })
}

fn fmt_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

fn given_or(s: Source, detected: &str) -> &str {
    match s {
        Source::Given => "given",
        Source::Detected => detected,
    }
}

fn line(log: &mut dyn Write, s: &str) -> Result<(), String> {
    writeln!(log, "[+] {s}").map_err(|e| format!("write failed: {e}"))
}

/// Строки `[+]` обнаружения из таблицы констант: `interface`, `source-mac`, `source-ip`, `router-ip` (если известен)
/// и `router-mac`, если он известен без ARP. Строку ARP (`router-mac … (arp: …)`) печатает [`run_live`] после
/// резолвера, затем идут `seed` и `source-port`, поэтому порядок stderr одинаков на обоих путях.
pub fn print_detection(p: &Prepared, log: &mut dyn Write) -> Result<(), String> {
    let d = &p.detected;
    let offline = p.eff.offline();
    let iface = if hermetic_offline(&p.eff, p.source_ports.1) && p.eff.adapter_name().is_none() {
        "none (offline)".to_string()
    } else {
        match d.iface_source {
            Source::Given => format!("{} (given)", d.iface.name),
            Source::Detected => {
                let first = probe_targets(p.eff.massip()).map(|t| t.first);
                let first = first.map_or_else(String::new, |ip| format!(" to {ip}"));
                format!("{} (detected: route{first})", d.iface.name)
            }
        }
    };
    line(log, &format!("interface = {iface}"))?;
    line(
        log,
        &format!(
            "source-mac = {} ({})",
            fmt_mac(d.source_mac.0),
            given_or(d.source_mac.1, "detected")
        ),
    )?;
    line(
        log,
        &format!(
            "source-ip = {} ({})",
            d.source_ipv4.0,
            given_or(d.source_ipv4.1, "detected")
        ),
    )?;
    if offline {
        line(log, "router-ip = none (offline)")?;
        return line(
            log,
            &format!("router-mac = {} (offline)", fmt_mac(OFFLINE_ROUTER_MAC)),
        );
    }
    match d.next_hop {
        NextHop::Resolve { ip, why } => {
            let why = match why {
                NextHopWhy::Given => "given",
                NextHopWhy::RouteGateway => "route gateway",
                NextHopWhy::OnLinkTarget => "on-link target",
                NextHopWhy::InterfaceDefaultGateway => "interface default gateway",
            };
            line(log, &format!("router-ip = {ip} ({why})"))
        }
        NextHop::Mac(m, _) => {
            // `--router-mac`: ARP не нужен, `--router-ip` только печатается (C его тогда не ищет).
            if let Some(ip) = p.eff.router_ip() {
                line(log, &format!("router-ip = {} (given)", Ipv4Addr::from(ip)))?;
            }
            line(log, &format!("router-mac = {} (given)", fmt_mac(m)))
        }
    }
}

/// `seed` и `source-port`: после строк обнаружения и ARP.
fn print_parameters(p: &Prepared, log: &mut dyn Write) -> Result<(), String> {
    line(
        log,
        &format!("seed = {} ({})", p.seed.0, given_or(p.seed.1, "entropy")),
    )?;
    let ((first, last), src) = p.source_ports;
    let ports = if first == last {
        first.to_string()
    } else {
        format!("{first}-{last}")
    };
    line(
        log,
        &format!("source-port = {ports} ({})", given_or(src, "time")),
    )
}

/// Подсказка для `PermissionDenied` при открытии адаптера: что нужно на этой ОС.
fn privilege_hint() -> &'static str {
    if cfg!(target_os = "linux") {
        "run as root (sudo), or grant the binary CAP_NET_RAW"
    } else if cfg!(target_os = "macos") {
        "run as root (sudo), or grant read/write access to /dev/bpf*"
    } else if cfg!(windows) {
        "run as Administrator; Npcap must be installed (Admin-only mode needs an elevated prompt)"
    } else {
        "run as root"
    }
}

fn open(
    backend: &dyn Backend,
    name: &str,
    binding: &AdapterBinding,
) -> Result<AdapterPair, String> {
    backend.open(binding).map_err(|e| {
        let hint = match e {
            NetError::PermissionDenied(_) => format!("\n    [hint] {}", privilege_hint()),
            _ => String::new(),
        };
        format!("cannot open adapter \"{name}\": {e}{hint}")
    })
}

fn ids(backend: &dyn Backend) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&backend.entropy64().to_le_bytes());
    id[8..].copy_from_slice(&backend.entropy64().to_le_bytes());
    id
}

/// `[+] finished: <итог>, sent N, …` с `sent` engine (верификатор сверяет его с SYN на проводе).
fn print_finished(
    outcome: &Outcome,
    replies: u64,
    open: u64,
    log: &mut dyn Write,
) -> Result<(), String> {
    line(
        log,
        &format!(
            "finished: {:?}, sent {}, replies {replies}, open {open}",
            outcome.reason, outcome.progress.sent
        ),
    )
}

/// `[+] finished: …` и решение о коде выхода: `Completed`/`Stopped` → `Ok` (exit 0), иначе `Err` (exit 1).
pub fn conclude(
    outcome: &Outcome,
    replies: u64,
    open: u64,
    log: &mut dyn Write,
) -> Result<(), String> {
    print_finished(outcome, replies, open, log)?;
    match &outcome.reason {
        Reason::Completed | Reason::Stopped => Ok(()),
        Reason::Failed(f) => Err(format!("scan failed: {f:?}")),
        Reason::Paused => Err("scan paused without a checkpoint consumer".into()),
    }
}

/// Живой скан: `prepare` → проверка плана → `[+]` → ARP (если нужен) → `ReadyPlan` → `open` → engine → `sink` →
/// `join`.
pub fn run_live(
    cfg: &ScanConfig,
    backend: &dyn Backend,
    sink: &mut dyn Sink,
    log: &mut dyn Write,
) -> Result<Outcome, String> {
    let p = prepare(cfg, SeedPolicy::Entropy, backend, false)?;
    // Ограничения runtime v1 (`--retries`, `--shard`, rounds, legacy resume) до ARP: отказ плана не стоит кадра.
    // Next hop в binding тут ещё нулевой; настоящий план строится после ARP (binding неизменяем).
    ReadyPlan::new(p.eff.clone(), p.binding.clone()).map_err(|e| e.to_string())?;
    print_detection(&p, log)?;
    let clock = backend.clock();
    let mut binding = p.binding.clone();
    let name = p.detected.iface.name.as_str();
    if let NextHop::Resolve { ip, why } = p.detected.next_hop {
        let (my_ip, my_mac) = (p.detected.source_ipv4.0, p.detected.source_mac.0);
        let kind = match why {
            NextHopWhy::OnLinkTarget => NextHopKind::Target,
            NextHopWhy::Given | NextHopWhy::RouteGateway | NextHopWhy::InterfaceDefaultGateway => {
                NextHopKind::Router
            }
        };
        let arp = arp_binding(&binding.interface_id, my_ip, my_mac, binding.source_ports);
        let mut pair = open(backend, name, &arp)?;
        let r = resolve_next_hop(
            &mut pair,
            name,
            my_mac,
            my_ip,
            ip,
            kind,
            &backend.arp_policy(),
            clock.as_ref(),
        );
        // Адаптер фазы ARP закрывается до открытия адаптера скана.
        drop(pair);
        let report = r.map_err(refusal)?;
        line(
            log,
            &format!(
                "router-mac = {} (arp: {} requests, {} ms)",
                fmt_mac(report.mac),
                report.requests_sent,
                report.elapsed.as_millis()
            ),
        )?;
        binding.next_hop_mac = report.mac;
    }
    print_parameters(&p, log)?;
    let plan = ReadyPlan::new(p.eff, binding.clone()).map_err(|e| e.to_string())?;
    let io = open(backend, name, &binding)?;
    let options = EngineOptions::new(ids(backend), ids(backend));
    // Решение 4: те же часы, что у резолвера; в `OsBackend` это `SystemClock`, то есть поведение `Engine::start`.
    let handle = Engine::start_with_clock(plan, io, options, clock)
        .map_err(|e| format!("cannot start the scan: {e}"))?;
    let (mut replies, mut open_count) = (0u64, 0u64);
    let mut sink_error = None;
    'events: loop {
        match handle.recv_event_timeout(Duration::from_millis(250)) {
            Ok(Event::Results { replies: batch }) => {
                for r in &batch {
                    replies += 1;
                    if r.status == PortStatus::Open {
                        open_count += 1;
                    }
                    if let Err(e) = sink.report(r) {
                        sink_error = Some(e);
                        handle.stop();
                        break 'events;
                    }
                }
            }
            Ok(Event::Finished { .. }) | Err(TryRecvError::Disconnected) => break,
            Ok(_) | Err(TryRecvError::Empty) => {}
        }
    }
    let outcome = handle
        .join()
        .map_err(|e| format!("scan engine error: {e}"))?;
    let sunk = match sink_error {
        Some(e) => Err(e),
        None => sink.finish(),
    };
    if let Err(e) = sunk {
        // Ошибка приёмника (EPIPE уже завершил процесс в `io_fail`) не прячет `sent` engine; exit 1 от неё.
        print_finished(&outcome, replies, open_count, log)?;
        return Err(e);
    }
    conclude(&outcome, replies, open_count, log)?;
    Ok(outcome)
}

/// Поток кадров `transmit_thread` без сети (генерация в `rmasscan_core::probe`); ошибка callback останавливает
/// генератор сразу (`ControlFlow::Break`).
pub(crate) fn for_each_probe(
    eff: &EffectiveConfig,
    binding: &AdapterBinding,
    mut f: impl FnMut(&Probe) -> Result<(), String>,
) -> Result<(), String> {
    match core_for_each_probe(eff, binding, |p| match f(p) {
        Ok(()) => ControlFlow::Continue(()),
        Err(e) => ControlFlow::Break(e),
    })
    .map_err(|e| e.to_string())?
    {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(e) => Err(e),
    }
}

/// main-ptrace.c:97: `SENT (%5.4f) TCP  %-21s > %-21s %s`. Адреса и флаги разбираются из самого кадра, как
/// `preprocess_frame` в C.
fn trace_line(secs: f64, frame: &[u8]) -> String {
    let (ip, tcp) = (14, 34);
    let src = Ipv4Addr::new(
        frame[ip + 12],
        frame[ip + 13],
        frame[ip + 14],
        frame[ip + 15],
    );
    let dst = Ipv4Addr::new(
        frame[ip + 16],
        frame[ip + 17],
        frame[ip + 18],
        frame[ip + 19],
    );
    let sport = u16::from_be_bytes([frame[tcp], frame[tcp + 1]]);
    let dport = u16::from_be_bytes([frame[tcp + 2], frame[tcp + 3]]);
    let flags = match frame[tcp + 13] {
        0x02 => "SYN".to_string(),
        other => format!("flags-{other:#04x}"),
    };
    format!(
        "SENT ({secs:5.4}) TCP  {:<21} > {:<21} {flags}\n",
        format!("[{src}]:{sport}"),
        format!("[{dst}]:{dport}")
    )
}

/// `--offline`: обнаружение только чтением (`detect_offline`, следующий хоп не ищется, MAC шлюза фиктивный), строки
/// `[+]`; с `packet_trace` строка `SENT` на каждый SYN в `out`. Адаптер не открывается, ARP не шлётся.
pub fn run_offline(
    cfg: &ScanConfig,
    backend: &dyn Backend,
    packet_trace: bool,
    out: &mut dyn Write,
    log: &mut dyn Write,
) -> Result<(), String> {
    let p = prepare(cfg, SeedPolicy::Required, backend, true)?;
    print_detection(&p, log)?;
    print_parameters(&p, log)?;
    if packet_trace {
        let clock = backend.clock();
        let start = clock.now_micros();
        for_each_probe(&p.eff, &p.binding, |pr| {
            let secs = clock.now_micros().saturating_sub(start) as f64 / 1e6;
            out.write_all(trace_line(secs, &pr.frame).as_bytes())
                .map_err(io_fail)
        })?;
    }
    Ok(())
}

/// `--iflist`: интерфейсы и маршруты по умолчанию (свой формат, stdout); только чтение.
pub fn iflist(backend: &dyn Backend, out: &mut dyn Write) -> Result<(), String> {
    let fail = |e: NetError| format!("cannot list interfaces: {e}");
    let list = backend.interfaces().and_then(|i| i.list()).map_err(fail)?;
    let defaults = backend
        .routes()
        .and_then(|r| r.default_routes())
        .map_err(fail)?;
    out.write_all(iflist_text(&list, &defaults).as_bytes())
        .map_err(io_fail)
}
