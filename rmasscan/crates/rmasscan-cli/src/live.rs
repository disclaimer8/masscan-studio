//! Живой путь CLI (AGPL-3.0): обнаружение адаптера и шлюза, ARP, план, открытие адаптера, engine и приёмник; плюс
//! `--offline` (обнаружение только чтением) и `--iflist`. Порт `masscan_initialize_adapter` (`main-initadapter.c`) и
//! `main_scan` (`main.c`) masscan © Robert David Graham (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0) в форме
//! решений плана: интерфейс по маршруту к целям, ARP к следующему хопу, один порт источника по умолчанию.
//!
//! Порядок: `defaults (seed, порт) → validate → detect → пробная сборка ReadyPlan → печать [+] → ARP → ReadyPlan →
//! open → Engine → события → Sink → join`. Пробный план (next hop ещё нулевой) проверяет ограничения плана
//! (rounds, shard, `resume-index` за пределом) до ARP, чтобы отклонённый engine скан не стоил ни одного ARP-кадра;
//! настоящий план строится после ARP, потому что binding неизменяем. Всё состояние ОС приходит через шов
//! [`Backend`]; обнаружение, `--offline` и `--iflist` ничего не открывают. Единственный кадр до engine это ARP-запрос
//! резолвера с отдельного короткоживущего адаптера, закрытого до открытия адаптера скана. Ctrl-C (Р18, порт
//! `control_c_handler`, `main.c:1131–1155`): [`Backend::interrupts`] ставит обработчик до ARP, цикл событий видит
//! первое нажатие и печатает строку C. До старта engine скан просто останавливается (итог `Stopped`, exit 0). После
//! старта нажатие ставит engine на паузу (Р4): передача встаёт, приём ещё `--wait` секунд берёт поздние ответы, а
//! `paused.conf` с нормализованным `resume-index` пишется сразу, до отсчёта ожидания (`main.c:1447-1456`,
//! `main-conf.c:395-416`); приёмник дописывает принятое и подвал, итог `Paused` (exit 0), либо `Completed`, если
//! передача успела закончиться до нажатия. Второе нажатие завершает процесс с кодом 1 из самого обработчика, а
//! `paused.conf` к этому времени уже на диске.

#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

use crate::conf::{FullConf, format_paused_conf};
use crate::status::{InfiniteTotals, StatusLine, StatusMode};
use rmasscan_core::config::{EffectiveConfig, Operation, ScanConfig, validate};
use rmasscan_core::packet::LinkType;
use rmasscan_core::payloads::PayloadTable;
use rmasscan_core::probe::{
    AdapterBinding, NicBinding, Probe, ReadyPlan, check_scan_ports,
    for_each_probe_nic_with_payloads as core_for_each_probe_nic_with_payloads,
};
use rmasscan_core::receive::PortStatus;
use rmasscan_core::throttle::Clock;
use rmasscan_engine::{
    AdapterPair, Engine, EngineOptions, Event, Outcome, Progress, Reason, RxHealth,
};
use rmasscan_net::arp_resolve::{ArpPolicy, NextHopKind, arp_binding, resolve_next_hop_until};
use rmasscan_net::discover::{NextHopWhy, Source, usable_source_mac};
use rmasscan_net::{
    DetectError, Detected, Iface, Interfaces, NetError, NextHop, Overrides, RouteTable, detect,
    detect_offline, iflist_text, probe_targets,
};

use crate::args::SeedPolicy;
use crate::output::{ServiceNames, Sink, Wall, io_fail};
use crate::pcap_writer::{PcapTarget, PcapWriter};

/// Префикс отказов обнаружения и ARP в форме C (`[-] FAIL: …` и подсказки); [`crate::error_text`] не оборачивает их.
pub const REFUSAL_PREFIX: &str = "[-] ";

/// Строка C первого Ctrl-C (`main.c:1136–1139`): 44 пробела затирают хвост строки статуса.
const INTERRUPT_LINE: &str = concat!(
    "waiting several seconds to exit...",
    "                                            \n"
);

/// Всё, что CLI берёт у ОС. Тесты подставляют fake (его `open` паникует или выдаёт `FakeAdapter`); настоящая
/// реализация (`OsBackend`) живёт только в бинарнике, в `src/os_backend.rs` под `#[cfg(not(test))]`.
pub trait Backend: Wall {
    /// Таблица маршрутов (только чтение, без привилегий).
    fn routes(&self) -> Result<Box<dyn RouteTable>, NetError>;
    /// Список интерфейсов (только чтение, без привилегий).
    fn interfaces(&self) -> Result<Box<dyn Interfaces>, NetError>;
    /// Открывает адаптер по явному binding: единственное место, где нужны root/Administrator/BPF.
    fn open(&self, binding: &AdapterBinding) -> Result<AdapterPair, NetError>;
    /// 64 бита энтропии ОС, не 0 (seed живого скана, идентификаторы запуска).
    fn entropy64(&self) -> u64;
    /// Интервал и срок ARP.
    fn arp_policy(&self) -> ArpPolicy;
    /// Часы резолвера ARP, engine и трассы `--packet-trace` (одни и те же).
    fn clock(&self) -> Arc<dyn Clock + Send + Sync>;
    /// Имена TCP-сервисов для `-oG` и `-oU` (`getservbyport` C); [`crate::run`] читает их только для этих форматов.
    fn services(&self) -> ServiceNames;
    /// Нажатия Ctrl-C (Р18). Первый вызов ставит обработчик; его делает только [`run_live_with`], один раз до ARP, и
    /// затем опрашивает счётчик в цикле событий. Остальные операции не зовут его, у них поведение ОС по умолчанию.
    fn interrupts(&self) -> u32;
    /// Пишет `paused.conf` в рабочий каталог (`masscan_save_state`, `main-conf.c:395-416`: файл `paused.conf`, режим
    /// `wt`). Ошибка ФС возвращается строкой: CLI печатает `[-] FAIL: saving resume file`, всё равно доводит фазу
    /// `--wait` и подвал вывода, но завершается кодом 1 (Р1: в C скан молча идёт дальше). Фейковые бэкенды тестов сохраняют строку в памяти и диска не касаются.
    fn write_paused_conf(&self, content: &str) -> Result<(), String>;
    /// Создаёт файл `--pcap` (`pcapfile_openwrite`, `rawsock-pcapfile.c:669-712`: `fopen(.., "wb")`). Ошибка пути
    /// отказывает до ARP и engine (Р8). Тесты подставляют память.
    fn create_pcap(&self, path: &str) -> Result<Box<dyn Write + Send>, String> {
        let f = std::fs::File::create(path).map_err(|e| format!("{path}: {e}"))?;
        Ok(Box::new(io::BufWriter::new(f)))
    }
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
    /// Адаптеры `nic[1..n)` (`--adapter[i]`, Задача 7, `main.c:1257-1390`); `detected`/`binding`/`source_ports`
    /// выше это `nic[0]`.
    pub extra: Vec<NicPrepared>,
    /// Таблица нагрузок UDP: 28 встроенных, затем `--pcap-payloads` и `--nmap-payloads` (main-conf.c:3156-3195).
    pub payloads: Arc<PayloadTable>,
}

/// Обнаружение и binding одного адаптера `nic[k]`, `k >= 1`.
#[derive(Debug, Clone)]
pub struct NicPrepared {
    pub detected: Detected,
    pub binding: AdapterBinding,
    pub source_ports: ((u16, u16), Source),
}

impl Prepared {
    /// Привязки всех адаптеров по порядку `nic[0..n)` (`next_hop_mac` ещё нулевой там, где нужен ARP).
    fn bindings(&self) -> Vec<AdapterBinding> {
        std::iter::once(self.binding.clone())
            .chain(self.extra.iter().map(|e| e.binding.clone()))
            .collect()
    }

    /// Обнаружение адаптера `k`.
    fn detected(&self, k: usize) -> &Detected {
        if k == 0 {
            &self.detected
        } else {
            &self.extra[k - 1].detected
        }
    }

    /// Источник порта адаптера `k`.
    fn source_ports(&self, k: usize) -> ((u16, u16), Source) {
        if k == 0 {
            self.source_ports
        } else {
            self.extra[k - 1].source_ports
        }
    }
}

fn refusal(e: impl std::fmt::Display) -> String {
    format!("{REFUSAL_PREFIX}{e}")
}

/// Адаптер `k` плана CLI. `--adapter-ip A-B` живёт только в `nics[k]` (одиночное поле хранит первый адрес `nic[0]`):
/// диапазон берётся оттуда, если его первый адрес и есть источник привязки (обнаруженный адрес диапазона не имеет).
/// Флаг 17 портов принадлежит этому же адаптеру (спека Р6).
fn nic_binding(
    eff: &EffectiveConfig,
    k: usize,
    binding: &AdapterBinding,
) -> Result<NicBinding, String> {
    let nic = eff.nics().get(k);
    let source_ipv4_last = match nic.and_then(|n| n.adapter_ip) {
        None => binding.source_ipv4,
        Some((first, last)) if first == binding.source_ipv4 && last >= first => last,
        Some((first, last)) => {
            return Err(refusal(format!(
                "adapter-ip range {}-{} does not start at the source address {}",
                Ipv4Addr::from(first),
                Ipv4Addr::from(last),
                Ipv4Addr::from(binding.source_ipv4)
            )));
        }
    };
    Ok(NicBinding {
        source_ipv4_last,
        legacy_c_17_port_mask: nic.is_some_and(|n| n.legacy_c_17_port_mask),
        binding: binding.clone(),
    })
}

/// Адаптеры плана по привязкам `nic[0..n)`.
fn nic_bindings(
    eff: &EffectiveConfig,
    bindings: &[AdapterBinding],
) -> Result<Vec<NicBinding>, String> {
    bindings
        .iter()
        .enumerate()
        .map(|(k, b)| nic_binding(eff, k, b))
        .collect()
}

/// Файл `--pcap` (Р8): открывается до ARP и engine, один потокобезопасный писатель на все адаптеры. Фильтр "наш адрес
/// и порт" строится из адаптеров плана (`main.c:829, 935`). `None`, если `--pcap` не задан.
fn open_pcap(
    path: Option<&str>,
    backend: &dyn Backend,
    clock: &(dyn Clock + Send + Sync),
    nics: &[NicBinding],
) -> Result<Option<Arc<PcapWriter>>, String> {
    let Some(path) = path.filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    let targets = nics
        .iter()
        .map(|n| PcapTarget {
            ip_first: n.binding.source_ipv4,
            ip_last: n.source_ipv4_last,
            port_first: n.binding.source_ports.0,
            port_last: n.binding.source_ports.1,
        })
        .collect();
    // Время записи: Unix-время открытия минус показание часов engine в тот же момент.
    let wall = backend.unix_time().saturating_mul(1_000_000);
    let offset = wall.saturating_sub(clock.now_micros());
    let out = backend
        .create_pcap(path)
        .map_err(|e| format!("could not open capture file: {e}"))?;
    PcapWriter::new(out, targets, offset).map(|w| Some(Arc::new(w)))
}

/// План живого скана CLI (`ReadyPlan::new_cli`): `--retries`, `--shard`, `--blackrock-rounds`, `resume-index` и
/// `resume-count` из конфигурации и `--resume` (`main.c:212-223, 269-273`), 1..=8 адаптеров с общим потоком индексов
/// (`nic_offset`, `main.c:269`). `adapter-port` из 17 портов, который пишет сам C (`main.c:1318`), принимается флагом
/// `legacy_c_17_port_mask`. Порядок адаптеров в плане это порядок RX-потоков: `rx_plan` ставит адаптер `k` первым,
/// поэтому приёмник каждого адаптера проверяет диапазон адресов и портов именно своего (T6, замечание 4).
fn cli_plan(
    eff: &EffectiveConfig,
    bindings: &[AdapterBinding],
    payloads: &PayloadTable,
) -> Result<ReadyPlan, String> {
    let plan = ReadyPlan::new_cli_with_payloads(
        eff.clone(),
        nic_bindings(eff, bindings)?,
        payloads.clone(),
    )
    .map_err(|e| e.to_string())?;
    // Курсоры строятся здесь же: `resume-index` за пределом скана отказывает до ARP, а не после него.
    for k in 0..plan.nics().len() as u32 {
        plan.cursor_for_nic(k, None).map_err(|e| e.to_string())?;
    }
    Ok(plan)
}

/// `--offline` с явными ненулевыми `--adapter-ip` и `--adapter-mac` и с `--source-port` (решение 6): ОС не
/// опрашивается вовсе (golden-тесты герметичны). Нулевой адрес или MAC значит «не задан», как в C (`effective()`
/// их отбрасывает). Без любого из трёх идёт обычное обнаружение только чтением, поэтому `--offline` годится как
/// preflight живого прогона (R1). `port` это источник порта до подстановки умолчания.
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
    // `--offline --packet-trace` печатает поток одного адаптера; поток `nic[k]` зависит от числа адаптеров
    // (`nic_count`, смещение и скорость), поэтому с несколькими адаптерами офлайн-режим отказывает.
    if offline && eff.nics().len() > 1 {
        return Err(format!(
            "{} adapters are configured, but --offline supports one adapter",
            eff.nics().len()
        ));
    }
    let detected = if let (true, Some(ip), Some(mac)) = (
        hermetic_offline(&eff, source_ports.1),
        eff.adapter_ip(),
        eff.adapter_mac(),
    ) {
        given_offline(&eff, ip, mac)?
    } else {
        let targets =
            probe_targets(eff.massip()).ok_or_else(|| refusal(DetectError::NoUnicastTargets))?;
        detect_nic(&eff, 0, &targets, backend, offline)?
    };
    let binding = binding_of(&detected, source_ports.0);
    // Адаптеры `nic[1..n)` (`main.c:1257-1390`): у каждого своё обнаружение по его ключам; порт источника по
    // умолчанию общий, шлюз ищется ARP-ом на самом адаптере.
    let mut extra = Vec::new();
    if eff.nics().len() > 1 {
        let targets =
            probe_targets(eff.massip()).ok_or_else(|| refusal(DetectError::NoUnicastTargets))?;
        for k in 1..eff.nics().len() {
            let detected = detect_nic(&eff, k, &targets, backend, false)?;
            let ports = match eff.nics()[k].source_port {
                Some(p) => (p, Source::Given),
                // inherited from nic 0 (paused.conf keeps only the unindexed `adapter-port`, as C): so is its provenance
                None => (source_ports.0, source_ports.1),
            };
            extra.push(NicPrepared {
                binding: binding_of(&detected, ports.0),
                detected,
                source_ports: ports,
            });
        }
    }
    // main.c:1644 `masscan_load_database_files`: файлы читаются до скана, любой отказ до первого кадра и строки `[+]`.
    let payloads = Arc::new(load_payload_table(
        eff.pcap_payloads(),
        eff.nmap_payloads(),
    )?);
    Ok(Prepared {
        eff,
        detected,
        binding,
        seed,
        source_ports,
        extra,
        payloads,
    })
}

/// Привязки адаптера по результату обнаружения.
fn binding_of(detected: &Detected, source_ports: (u16, u16)) -> AdapterBinding {
    AdapterBinding {
        interface_id: detected.iface.device_id.clone(),
        link_type: LinkType::Ethernet,
        source_ipv4: u32::from(detected.source_ipv4.0),
        source_mac: detected.source_mac.0,
        next_hop_mac: match detected.next_hop {
            NextHop::Mac(m, _) => m,
            NextHop::Resolve { .. } => [0; 6],
        },
        source_ports,
    }
}

/// Ключи обнаружения адаптера `k`: для `nic[0]` одиночные поля (в них нули уже отброшены `effective()`), для
/// остальных `nics[k]` с теми же правилами нуля (`main-initadapter.c:122-126, 170`).
fn overrides(eff: &EffectiveConfig, k: usize) -> Overrides {
    if k == 0 {
        return Overrides {
            adapter: eff.adapter_name().map(str::to_string),
            adapter_ip: eff.adapter_ip().map(Ipv4Addr::from),
            adapter_mac: eff.adapter_mac(),
            router_ip: eff.router_ip().map(Ipv4Addr::from),
            router_mac: eff.router_mac(),
        };
    }
    let n = &eff.nics()[k];
    Overrides {
        adapter: n.adapter_name.clone(),
        adapter_ip: n
            .adapter_ip
            .map(|(first, _)| first)
            .filter(|&ip| ip != 0)
            .map(Ipv4Addr::from),
        adapter_mac: n.adapter_mac.filter(|m| *m != [0u8; 6]),
        router_ip: n.router_ip.map(Ipv4Addr::from),
        router_mac: n
            .router_mac_ipv4
            .or(n.router_mac_ipv6)
            .filter(|m| *m != [0u8; 6]),
    }
}

/// Обнаружение адаптера `k` только чтением таблиц ОС (`detect` или `detect_offline`).
fn detect_nic(
    eff: &EffectiveConfig,
    k: usize,
    targets: &rmasscan_net::discover::Targets,
    backend: &dyn Backend,
    offline: bool,
) -> Result<Detected, String> {
    let ov = overrides(eff, k);
    let os = |e: NetError| refusal(DetectError::Os(e));
    let routes = backend.routes().map_err(os)?;
    let ifaces = backend.interfaces().map_err(os)?;
    let found = if offline {
        detect_offline(targets, &ov, routes.as_ref(), ifaces.as_ref())
    } else {
        detect(targets, &ov, routes.as_ref(), ifaces.as_ref())
    };
    found.map_err(refusal)
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

/// `stderr` как в C: ошибки записи и сброса игнорируются (util-logger.c:25-31 `vfprintf`+`fflush` без проверки,
/// main-status.c:216-280, main.c:1136-1140, in-binary.c:488-637). Первый сбой отключает `log` до конца вызова;
/// код выхода определяют только скан, приёмник и stdout.
pub(crate) struct BestEffort<'a> {
    inner: &'a mut dyn Write,
    dead: bool,
}

impl<'a> BestEffort<'a> {
    pub(crate) fn new(inner: &'a mut dyn Write) -> Self {
        BestEffort { inner, dead: false }
    }
}

impl Write for BestEffort<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.dead && self.inner.write_all(buf).is_err() {
            self.dead = true;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if !self.dead && self.inner.flush().is_err() {
            self.dead = true;
        }
        Ok(())
    }
}

fn line(log: &mut dyn Write, s: &str) -> Result<(), String> {
    writeln!(log, "[+] {s}").map_err(|e| format!("write failed: {e}"))
}

/// Строки `[+]` обнаружения из таблицы констант: `interface`, `source-mac`, `source-ip`, `router-ip` (если известен)
/// и `router-mac`, если он известен без ARP. Строку ARP (`router-mac … (arp: …)`) печатает [`run_live`] после
/// резолвера, затем идут `seed` и `source-port`, поэтому порядок stderr одинаков на обоих путях.
pub fn print_detection(p: &Prepared, log: &mut dyn Write) -> Result<(), String> {
    (0..=p.extra.len()).try_for_each(|k| print_nic_detection(p, k, log))
}

/// Строки `[+]` адаптера `k`; ключи адаптеров с `k >= 1` несут суффикс `[k]`, как в `paused.conf`.
fn print_nic_detection(p: &Prepared, k: usize, log: &mut dyn Write) -> Result<(), String> {
    let d = p.detected(k);
    let sfx = if k == 0 {
        String::new()
    } else {
        format!("[{k}]")
    };
    let given_router_ip = if k == 0 {
        p.eff.router_ip()
    } else {
        p.eff.nics()[k].router_ip
    };
    let offline = p.eff.offline();
    let iface =
        if k == 0 && hermetic_offline(&p.eff, p.source_ports.1) && p.eff.adapter_name().is_none() {
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
    line(log, &format!("interface{sfx} = {iface}"))?;
    line(
        log,
        &format!(
            "source-mac{sfx} = {} ({})",
            fmt_mac(d.source_mac.0),
            given_or(d.source_mac.1, "detected")
        ),
    )?;
    line(
        log,
        &format!(
            "source-ip{sfx} = {} ({})",
            d.source_ipv4.0,
            given_or(d.source_ipv4.1, "detected")
        ),
    )?;
    if offline {
        line(log, &format!("router-ip{sfx} = none (offline)"))?;
        return line(
            log,
            &format!(
                "router-mac{sfx} = {} (offline)",
                fmt_mac(OFFLINE_ROUTER_MAC)
            ),
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
            line(log, &format!("router-ip{sfx} = {ip} ({why})"))
        }
        NextHop::Mac(m, _) => {
            // `--router-mac`: ARP не нужен, `--router-ip` только печатается (C его тогда не ищет).
            if let Some(ip) = given_router_ip {
                line(
                    log,
                    &format!("router-ip{sfx} = {} (given)", Ipv4Addr::from(ip)),
                )?;
            }
            line(log, &format!("router-mac{sfx} = {} (given)", fmt_mac(m)))
        }
    }
}

/// `seed` и `source-port`: после строк обнаружения и ARP.
fn print_parameters(p: &Prepared, log: &mut dyn Write) -> Result<(), String> {
    line(
        log,
        &format!("seed = {} ({})", p.seed.0, given_or(p.seed.1, "entropy")),
    )?;
    for k in 0..=p.extra.len() {
        let ((first, last), src) = p.source_ports(k);
        let ports = if first == last {
            first.to_string()
        } else {
            format!("{first}-{last}")
        };
        let sfx = if k == 0 {
            String::new()
        } else {
            format!("[{k}]")
        };
        line(
            log,
            &format!("source-port{sfx} = {ports} ({})", given_or(src, "time")),
        )?;
    }
    Ok(())
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

/// `[+] finished: …` и решение о коде выхода: `Completed`/`Stopped`/`Paused` → `Ok` (exit 0), иначе `Err` (exit 1).
pub fn conclude(
    outcome: &Outcome,
    replies: u64,
    open: u64,
    log: &mut dyn Write,
) -> Result<(), String> {
    print_finished(outcome, replies, open, log)?;
    match &outcome.reason {
        // `Paused`: первое Ctrl-C после старта (Р4), после `--wait` скан заканчивается обычным выходом, как в C (`main.c:1447-1540`).
        Reason::Completed | Reason::Stopped | Reason::Paused => Ok(()),
        Reason::Failed(f) => Err(format!("scan failed: {f:?}")),
    }
}

/// Остановка до старта engine: файл вывода закрывается (`sink.finish`, пустой остаётся 0 байт), строка статуса
/// гасится, итог `Stopped, sent 0, replies 0, open 0`, выход 0 (C `main.c:1131–1154`, Р18).
fn stopped_before_start(
    mode: StatusMode,
    now_micros: u64,
    sink: &mut dyn Sink,
    log: &mut dyn Write,
) -> Result<(Outcome, u64), String> {
    let _ = StatusLine::new(mode, now_micros).finish(log);
    sink.finish()?;
    let outcome = Outcome {
        reason: Reason::Stopped,
        progress: Progress {
            sent: 0,
            next_index: 0,
            received: 0,
            discarded: 0,
            duplicates: 0,
            rate: 0.0,
        },
        rx_health: RxHealth { kernel_drops: None },
    };
    conclude(&outcome, 0, 0, log)?;
    Ok((outcome, 0))
}

/// Живой скан: `prepare` → проверка плана → `[+]` → файл вывода → обработчик Ctrl-C → ARP (если нужен) → `ReadyPlan`
/// → `open` → engine → `sink` → `join`.
pub fn run_live(
    cfg: &ScanConfig,
    backend: &dyn Backend,
    sink: &mut dyn Sink,
    log: &mut dyn Write,
) -> Result<Outcome, String> {
    run_live_with(cfg, backend, sink, log, StatusMode::Text).map(|(outcome, _)| outcome)
}

/// [`run_live`] с режимом строки статуса. Второе значение результата это миллисекунды от открытия адаптера до
/// конца скана на часах бэкенда (`usec_start` в `main.c:1548`); их печатает `--nostatus`.
pub fn run_live_with(
    cfg: &ScanConfig,
    backend: &dyn Backend,
    sink: &mut dyn Sink,
    log: &mut dyn Write,
    mode: StatusMode,
) -> Result<(Outcome, u64), String> {
    let full = FullConf {
        scan: cfg.clone(),
        ndjson_status: mode == StatusMode::Ndjson,
        ..FullConf::default()
    };
    run_live_conf(&full, backend, sink, log, mode)
}

/// [`run_live_with`] с полной конфигурацией: `full.output`, `pcap-filename` и `ndjson-status` попадают в `paused.conf`
/// по первому Ctrl-C (`masscan_echo`, `main-conf.c:395-416`).
pub fn run_live_conf(
    full: &FullConf,
    backend: &dyn Backend,
    sink: &mut dyn Sink,
    log: &mut dyn Write,
    mode: StatusMode,
) -> Result<(Outcome, u64), String> {
    let cfg = &full.scan;
    let mut best_effort = BestEffort::new(log);
    let log: &mut dyn Write = &mut best_effort;
    let p = prepare(cfg, SeedPolicy::Entropy, backend, false)?;
    // Ограничения плана (rounds, shard, `resume-index` за пределом, ширина портов) до ARP: отказ плана не стоит
    // кадра. Next hop в binding тут ещё нулевой; настоящий план строится после ARP (binding неизменяем).
    cli_plan(&p.eff, &p.bindings(), &p.payloads)?;
    print_detection(&p, log)?;
    // Р8: файл открывается до ARP и engine; отказ не стоит ни одного кадра.
    sink.open()?;
    let clock = backend.clock();
    let pcap = open_pcap(
        full.pcap_filename.as_deref(),
        backend,
        clock.as_ref(),
        &nic_bindings(&p.eff, &p.bindings())?,
    )?;
    // Р18: обработчик Ctrl-C ставится до ARP и держится весь скан (первый же опрос его устанавливает). Нажатие до
    // первого SYN останавливает скан без адаптера скана и без единого кадра (C `main.c:1131–1154`: первое нажатие
    // только останавливает передачу; в C до `rawsock_init_adapter`/`main.c:1275` кадров ещё нет).
    let early_stop = |log: &mut dyn Write, sink: &mut dyn Sink| {
        let _ = log.write_all(INTERRUPT_LINE.as_bytes());
        let _ = log.flush();
        stopped_before_start(mode, clock.now_micros(), sink, log)
    };
    if backend.interrupts() > 0 {
        return early_stop(log, sink);
    }
    // ARP по очереди для каждого адаптера: адаптер фазы ARP закрывается до открытия следующего и до адаптеров скана.
    let mut bindings = p.bindings();
    for (k, binding) in bindings.iter_mut().enumerate() {
        let d = p.detected(k);
        let sfx = if k == 0 {
            String::new()
        } else {
            format!("[{k}]")
        };
        let name = d.iface.name.as_str();
        if let NextHop::Resolve { ip, why } = d.next_hop {
            let (my_ip, my_mac) = (d.source_ipv4.0, d.source_mac.0);
            let kind = match why {
                NextHopWhy::OnLinkTarget => NextHopKind::Target,
                NextHopWhy::Given
                | NextHopWhy::RouteGateway
                | NextHopWhy::InterfaceDefaultGateway => NextHopKind::Router,
            };
            let arp = arp_binding(&binding.interface_id, my_ip, my_mac, binding.source_ports);
            let mut pair = open(backend, name, &arp)?;
            let r = resolve_next_hop_until(
                &mut pair,
                name,
                my_mac,
                my_ip,
                ip,
                kind,
                &backend.arp_policy(),
                clock.as_ref(),
                &mut || backend.interrupts() > 0,
            );
            // Адаптер фазы ARP закрывается до открытия адаптера скана.
            drop(pair);
            let Some(report) = r.map_err(refusal)? else {
                return early_stop(log, sink);
            };
            line(
                log,
                &format!(
                    "router-mac{sfx} = {} (arp: {} requests, {} ms)",
                    fmt_mac(report.mac),
                    report.requests_sent,
                    report.elapsed.as_millis()
                ),
            )?;
            binding.next_hop_mac = report.mac;
        }
    }
    print_parameters(&p, log)?;
    let plan = cli_plan(&p.eff, &bindings, &p.payloads)?;
    // Нажатие, пришедшее после ARP, но до открытия адаптера скана: ни адаптера, ни SYN.
    if backend.interrupts() > 0 {
        return early_stop(log, sink);
    }
    let mut ios = Vec::with_capacity(bindings.len());
    for (k, binding) in bindings.iter().enumerate() {
        ios.push(open(backend, p.detected(k).iface.name.as_str(), binding)?);
    }
    let options = EngineOptions::new(ids(backend), ids(backend));
    // Решение 4: те же часы, что у резолвера; в `OsBackend` это `SystemClock`, то есть поведение `Engine::start`.
    let started = clock.now_micros();
    // Конец передачи для строки статуса: `min_k effective_end(k)`, то есть эффективный конец самого медленного адаптера. При усечённом `resume-count`
    // позиция никогда не дойдёт до `range`, а движок всё равно завершает скан на своём `effective_end`.
    let tx_end = (0..plan.nics().len() as u32)
        .map(|k| plan.effective_end(k))
        .min()
        .unwrap_or(0);
    let handle = Engine::start_cli_with_clock(
        plan,
        ios,
        options,
        clock.clone(),
        pcap.as_ref().map(PcapWriter::sink),
    )
    .map_err(|e| format!("cannot start the scan: {e}"))?;
    let (mut replies, mut open_count) = (0u64, 0u64);
    let mut sink_error = None;
    let wait_secs = i64::from(cfg.wait_secs);
    let mut status = StatusLine::new(mode, started);
    let infinite = p.eff.infinite();
    // Момент, с которого идёт обратный отсчёт `--wait`: конец передачи (`main.c:1427, 1496`) либо остановка передачи
    // паузой.
    let (mut max_count, mut wait_started) = (0u64, None::<u64>);
    let (mut interrupted, mut paused_saved) = (false, false);
    // `paused.conf` с эффективными `seed` и портом источника: без них возобновление пошло бы по другой перестановке.
    let mut saved_conf = full.clone();
    saved_conf.scan.seed = p.seed.0;
    saved_conf.scan.source_port = Some(p.source_ports.0);
    for (k, n) in saved_conf.scan.nics.iter_mut().enumerate() {
        n.source_port = Some(p.source_ports(k).0);
    }
    // `masscan_save_state` (`main-conf.c:395-416`) по условию `min_index < count_ips * count_ports`
    // (`main.c:1447-1456`); `--infinite` не имеет конца и сохранять нечего (Р5).
    let save_paused = |base: u64, log: &mut dyn Write| -> Option<String> {
        if base >= tx_end || p.eff.infinite() {
            return None;
        }
        let _ = log.write_all(
            concat!(
                "                                   ",
                "                                   \r",
                "saving resume file to: paused.conf\n"
            )
            .as_bytes(),
        );
        let failed = backend
            .write_paused_conf(&format_paused_conf(&saved_conf, base))
            .err();
        if let Some(e) = &failed {
            let _ = writeln!(log, "[-] FAIL: saving resume file\n[-] paused.conf: {e}");
        }
        let _ = log.flush();
        failed
    };
    // Отказ записи `paused.conf` не рвёт ожидание, но даёт код 1 (Р1).
    let mut paused_error: Option<String> = None;
    // `log` best-effort (`BestEffort`): мёртвый stderr (EPIPE с первого байта или `2>&1 | tee` после Ctrl-C) не останавливает скан и не
    // меняет код выхода, как в C.
    'events: loop {
        // Р18: счётчик проверяется на каждой итерации (не реже раза в 250 мс). После паузы цикл дочитывает события
        // до `Finished`, поэтому приёмник получает каждый принятый ответ, в том числе позднюю фазу `--wait`.
        if !interrupted && backend.interrupts() > 0 {
            interrupted = true;
            let _ = log.write_all(INTERRUPT_LINE.as_bytes());
            let _ = log.flush();
            handle.pause();
        }
        // Р4: `paused.conf` пишется сразу, как только передача встала, до окончания `--wait` (второе Ctrl-C и
        // `--nostatus` его не теряют). Событие `CheckpointReady` приходит только после `wait`.
        if interrupted
            && !paused_saved
            && let Some(base) = handle.pause_resume_base()
        {
            paused_saved = true;
            wait_started.get_or_insert(clock.now_micros());
            paused_error = save_paused(base, log);
        }
        match handle.recv_event_timeout(Duration::from_millis(250)) {
            Ok(Event::Started { range }) => max_count = range,
            Ok(Event::Progress(prog)) => {
                let now = clock.now_micros();
                // Конец передачи это `tx_end` (самый медленный адаптер, `effective_end` = `(retries + 1) * range`, с
                // усечённым `resume-count` тоже): от него engine отсчитывает `--wait`. Процент ниже остаётся от
                // `max_count` как у C (`main.c:1427-1437`), поэтому с `--retries` он переходит 100% до отсчёта.
                // `--infinite` конца не имеет (`main.c:1425` `min_index >= range && !is_infinite`).
                if !infinite && prog.next_index >= tx_end {
                    wait_started.get_or_insert(now);
                }
                let exiting = wait_started
                    .map(|t| wait_secs.saturating_sub((now.saturating_sub(t) / 1_000_000) as i64));
                let _ = if infinite {
                    // `status->is_infinite` (`main-status.c:210-225`): строка `*` вместо процента, и в передаче, и в ожидании.
                    let totals = InfiniteTotals {
                        syns: prog.sent,
                        synacks: open_count,
                        tcbs: 0,
                        index: prog.next_index,
                    };
                    status.tick_infinite(now, totals, prog.rate, exiting.is_some(), log)
                } else {
                    status.tick(
                        now,
                        prog.next_index,
                        max_count,
                        prog.rate,
                        open_count,
                        exiting,
                        log,
                    )
                };
            }
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
            // Страховка: событие пришло раньше, чем цикл увидел остановку передачи.
            Ok(Event::CheckpointReady { next_index }) => {
                if !paused_saved {
                    paused_saved = true;
                    wait_started.get_or_insert(clock.now_micros());
                    paused_error = save_paused(next_index, log);
                }
            }
            Ok(Event::Finished { .. }) | Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }
    }
    // `join` и `sink.finish()` идут всегда, до любого `?`: ошибка engine не оставляет файл
    // вывода без подвала.
    let joined = handle.join().map_err(|e| format!("scan engine error: {e}"));
    let elapsed_ms = clock.now_micros().saturating_sub(started) / 1000;
    let _ = status.finish(log);
    let sunk = match sink_error {
        Some(e) => Err(e),
        None => sink.finish(),
    };
    // Ошибка записи захвата это отказ скана (exit 1), как ошибка файла вывода; RX-потоки к этому времени остановлены.
    let captured = pcap.as_ref().map_or(Ok(()), |w| w.finish());
    let outcome = joined?;
    if let Err(e) = sunk {
        // Ошибка приёмника (EPIPE stdout уже завершил процесс в `write_failed`; EPIPE файла это обычная ошибка) не
        // прячет `sent` engine; exit 1 от неё.
        print_finished(&outcome, replies, open_count, log)?;
        return Err(e);
    }
    conclude(&outcome, replies, open_count, log)?;
    captured?;
    if let Some(e) = paused_error {
        return Err(format!("cannot save paused.conf: {e}"));
    }
    Ok((outcome, elapsed_ms))
}

/// Поток кадров `transmit_thread` без сети (генерация в `rmasscan_core::probe`); ошибка callback останавливает
/// генератор сразу (`ControlFlow::Break`).
#[cfg(test)]
pub(crate) fn for_each_probe(
    eff: &EffectiveConfig,
    binding: &AdapterBinding,
    f: impl FnMut(&Probe) -> Result<(), String>,
) -> Result<(), String> {
    for_each_probe_with(eff, binding, &PayloadTable::builtin(), f)
}

/// [`for_each_probe`] с таблицей нагрузок UDP плана (`--pcap-payloads`, `--nmap-payloads`).
pub(crate) fn for_each_probe_with(
    eff: &EffectiveConfig,
    binding: &AdapterBinding,
    payloads: &PayloadTable,
    mut f: impl FnMut(&Probe) -> Result<(), String>,
) -> Result<(), String> {
    match core_for_each_probe_nic_with_payloads(
        eff,
        &nic_binding(eff, 0, binding)?,
        payloads,
        |p| match f(p) {
            Ok(()) => ControlFlow::Continue(()),
            Err(e) => ControlFlow::Break(e),
        },
    )
    .map_err(|e| e.to_string())?
    {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(e) => Err(e),
    }
}

/// main-ptrace.c:97: `SENT (%5.4f) TCP  %-21s > %-21s %s` (для ICMP :67-70, UDP :57-59 и SCTP :108-111, см. ниже). Адреса и флаги разбираются из самого кадра, как
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
    if frame[ip + 9] == 1 {
        // main-ptrace.c:67-70: ICMP печатает `type` в поле порта источника и `code` в поле порта получателя
        // (proto-preprocess.c:184-187), после второго адреса остаётся пробел (формат `%-21s \n`).
        return format!(
            "SENT ({secs:5.4}) ICMP {:<21} > {:<21} \n",
            format!("[{src}]:{}", frame[tcp]),
            format!("[{dst}]:{}", frame[tcp + 1])
        );
    }
    let sport = u16::from_be_bytes([frame[tcp], frame[tcp + 1]]);
    let dport = u16::from_be_bytes([frame[tcp + 2], frame[tcp + 3]]);
    if frame[ip + 9] == 17 {
        // main-ptrace.c:57-59 (`FOUND_UDP`, `FOUND_DNS`): `%s (%5.4f) UDP  %-21s > %-21s \n`, без флагов и числа байт.
        return format!(
            "SENT ({secs:5.4}) UDP  {:<21} > {:<21} \n",
            format!("[{src}]:{sport}"),
            format!("[{dst}]:{dport}")
        );
    }
    if frame[ip + 9] == 132 {
        // main-ptrace.c:108-111: у C нет ветки `FOUND_SCTP`, и `packet_trace()` печатает `default`: `UNK  %-21s > %-21s
        // [%u]\n` с номером `FOUND_SCTP` (7, proto-preprocess.h:15); трейлинг-пробела UDP/ICMP здесь нет.
        return format!(
            "SENT ({secs:5.4}) UNK  {:<21} > {:<21} [7]\n",
            format!("[{src}]:{sport}"),
            format!("[{dst}]:{dport}")
        );
    }
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
    let mut best_effort = BestEffort::new(log);
    let log: &mut dyn Write = &mut best_effort;
    let p = prepare(cfg, SeedPolicy::Required, backend, true)?;
    // Р1: `--packet-trace` как и живой скан не шлёт `O:*` и `I:n` (проверка плана CLI, `cli_plan`); без
    // трассировки `--offline` ничего не строит и отказа нет.
    if packet_trace {
        check_scan_ports(p.eff.massip().ports()).map_err(|e| e.to_string())?;
    }
    print_detection(&p, log)?;
    print_parameters(&p, log)?;
    if packet_trace {
        let clock = backend.clock();
        let start = clock.now_micros();
        for_each_probe_with(&p.eff, &p.binding, &p.payloads, |pr| {
            let secs = clock.now_micros().saturating_sub(start) as f64 / 1e6;
            out.write_all(trace_line(secs, &pr.frame).as_bytes())
                .map_err(io_fail)
        })?;
    }
    Ok(())
}

/// Таблица нагрузок UDP (`masscan_load_database_files`, main-conf.c:3156-3195): встроенные 28 записей, затем файл
/// `--pcap-payloads`, затем `--nmap-payloads`, каждый заменяет записи своих портов. Отличие от C: нечитаемый файл и
/// синтаксическая ошибка отказывают запуск (C печатает сообщение и сканирует дальше с тем, что успел прочитать, а
/// пропавшую нагрузку на порту никто не заметит).
pub fn load_payload_table(pcap: Option<&str>, nmap: Option<&str>) -> Result<PayloadTable, String> {
    let mut table = PayloadTable::builtin();
    if let Some(file) = pcap {
        let data =
            std::fs::read(file).map_err(|e| format!("cannot read --pcap-payloads {file}: {e}"))?;
        table
            .load_pcap_payloads(&data)
            .map_err(|e| format!("--pcap-payloads {file}: {e}"))?;
    }
    if let Some(file) = nmap {
        let data =
            std::fs::read(file).map_err(|e| format!("cannot read --nmap-payloads {file}: {e}"))?;
        table
            .load_nmap_payloads_bytes(&data)
            .map_err(|e| format!("--nmap-payloads {file}: {e}"))?;
    }
    Ok(table)
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
