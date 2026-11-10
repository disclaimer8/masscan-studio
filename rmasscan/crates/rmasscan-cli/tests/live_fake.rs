//! Живой путь CLI end-to-end на fake-бэкенде (AGPL-3.0): обнаружение → `[+]` → ARP → `ReadyPlan` → `open` → engine →
//! `Sink`, Ctrl-C (счётчик нажатий fake), `--offline` и `--iflist`. Синтетические таблицы маршрутов и интерфейсов,
//! `FakeAdapter` с ответчиком ARP и `reply_to_syn`, `ManualClock` для резолвера и engine, фиксированные энтропия и
//! время. Ни один тест не достигает ОС: `OsBackend` существует только в бинарнике, а `open` здесь выдаёт
//! `FakeAdapter` или паникует (`panic_on_open`).
//! Адреса и MAC только документационные (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) и локальные `02:…`,
//! кроме гостя n2 и Mac стенда m1: они воспроизводят лабораторные стенды (`198.18.0.0/30`), n2 ещё и NIC QEMU
//! (`10.0.2.0/24`, `52:54:00:…`).

#[path = "common/scratch.rs"]
mod scratch;

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use scratch::Scratch;

use rmasscan_cli::args::{Cli, SeedPolicy};
use rmasscan_cli::live::{self, Backend};
use rmasscan_cli::output::{
    Interactive, OutputEnv, Pipeline, ServiceNames, Sink, Wall, discovered_line,
};
use rmasscan_cli::status::normalize_stderr_line;
use rmasscan_core::arp::{ArpOp, decode, encode_reply, encode_request};
use rmasscan_core::config::ScanConfig;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;
use rmasscan_core::receive::{PortStatus, Reply};
use rmasscan_core::throttle::Clock;
use rmasscan_engine::fake::{FakeAdapter, HealthStep, ManualClock, RxStep, reply_to_syn};
use rmasscan_engine::{AdapterPair, FailReason, Outcome, Progress, Reason, RxHealth};
use rmasscan_net::arp_resolve::{ArpPolicy, arp_binding};
use rmasscan_net::discover::{NextHopWhy, Source};
use rmasscan_net::{Iface, Interfaces, NetError, NextHop, Route, RouteTable};

const IF_NAME: &str = "eth0";
const IF_INDEX: u32 = 2;
const MY_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 1];
const MY_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 5);
const GW: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const GW_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 2];
const OFFLINE_MAC: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
const ENTROPY: u64 = 0x1234_5678_9abc_def1;
/// `40000 + 1_800_012_345 % 20000 = 52345`.
const UNIX_TIME: u64 = 1_800_012_345;
const TIME_PORT: u16 = 52345;
const T1: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const T2: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
/// Открытые порты фиктивной сети; остальное отвечает RST.
const OPEN: [(Ipv4Addr, u16); 2] = [(T1, 80), (T2, 81)];
/// `--wait 1` идёт по `ManualClock` (около 20 пустых `recv` по 50 мс, миллисекунды реального времени); при `--wait 0`
/// RX engine выходит в той же итерации, где увидел конец TX, и ответы фиктивной сети, ещё лежащие в очереди, теряются.
const LIVE: [&str; 4] = ["198.51.100.1-198.51.100.2", "-p80,81", "--wait", "1"];

fn route(gateway: Option<Ipv4Addr>) -> Route {
    Route {
        ifindex: IF_INDEX,
        ifname: IF_NAME.to_string(),
        gateway,
        local: false,
    }
}

fn eth0() -> Iface {
    Iface {
        name: IF_NAME.to_string(),
        index: IF_INDEX,
        device_id: IF_NAME.to_string(),
        description: None,
        mac: Some(MY_MAC),
        mac_masked: false,
        ethernet: true,
        up: true,
        ipv4: vec![MY_IP],
    }
}

fn lo() -> Iface {
    Iface {
        name: "lo".to_string(),
        index: 1,
        device_id: "lo".to_string(),
        description: None,
        mac: None,
        mac_masked: false,
        ethernet: false,
        up: true,
        ipv4: vec![Ipv4Addr::LOCALHOST],
    }
}

/// Таблица: правила (от, до, маршрут или None), первое подходящее; журнал lookup.
#[derive(Clone)]
struct FakeRoutes {
    rules: Vec<(u32, u32, Option<Route>)>,
    defaults: Vec<Route>,
    defaults_panic: bool,
    lookups: Arc<Mutex<Vec<Ipv4Addr>>>,
}

impl RouteTable for FakeRoutes {
    fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, NetError> {
        self.lookups.lock().unwrap().push(dst);
        let d = u32::from(dst);
        Ok(self
            .rules
            .iter()
            .find(|(a, b, _)| *a <= d && d <= *b)
            .and_then(|(_, _, r)| r.clone()))
    }
    fn default_routes(&self) -> Result<Vec<Route>, NetError> {
        assert!(!self.defaults_panic, "default_routes must not be consulted");
        Ok(self.defaults.clone())
    }
}

struct FakeIfaces(Vec<Iface>);

impl Interfaces for FakeIfaces {
    fn list(&self) -> Result<Vec<Iface>, NetError> {
        Ok(self.0.clone())
    }
}

/// Один открытый адаптер: binding, его фиктивный адаптер, сколько handle прежних адаптеров жили в момент открытия и
/// сколько раз до открытия опрошен счётчик Ctrl-C.
struct Opened {
    binding: AdapterBinding,
    adapter: FakeAdapter,
    alive_before: usize,
    polls_before: usize,
}

struct FakeBackend {
    routes: FakeRoutes,
    ifaces: Vec<Iface>,
    /// `routes()`/`interfaces()` паникуют: ОС не опрашивается.
    tables_panic: bool,
    /// `entropy64()`/`unix_time()` паникуют.
    entropy_and_time_panic: bool,
    panic_on_open: bool,
    open_error: Option<NetError>,
    /// Соседи, отвечающие на ARP (пусто: ARP-таймаут).
    neighbors: Vec<(Ipv4Addr, [u8; 6])>,
    health: Option<HealthStep>,
    unix_time: u64,
    clock: Arc<ManualClock>,
    opened: Mutex<Vec<Opened>>,
    /// Каждый вызов `open`, до любой ошибки.
    attempts: Mutex<Vec<AdapterBinding>>,
    /// Общий журнал TX: каждый успешно отправленный кадр любого адаптера, по порядку.
    tx: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Нажатия Ctrl-C, которые видит `interrupts()`; поднимают их тест или ответчик ARP (`press_during_arp`).
    presses: Arc<AtomicU32>,
    /// Вызовы `interrupts()`.
    polls: Arc<AtomicUsize>,
    /// Ctrl-C во время ARP: уход ARP-запроса считается одним нажатием.
    press_during_arp: bool,
    /// Цели молчат: SYN остаётся без ответа (ARP отвечает как обычно).
    silent_targets: bool,
    /// Ctrl-C посреди передачи (Р4, Задача 4).
    press_in_tx: Option<PressInTx>,
    /// Записи `paused.conf`: показание часов на момент записи и содержимое. Диска фейк не касается.
    paused_writes: Mutex<Vec<(u64, String)>>,
    /// Ошибка записи `paused.conf`: запись не сохраняется.
    paused_write_error: Option<String>,
    /// Файл `--pcap` в памяти: байты и имена, под которыми его открывали.
    pcap: Arc<Mutex<Vec<u8>>>,
    pcap_opened: Mutex<Vec<String>>,
    /// На каждый SYN сверх обычного ответа приходят RST с плохим cookie на наш `ip:port` и кадр на чужой адрес.
    inject_noise: bool,
}

/// Файл захвата в памяти.
struct MemPcap(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for MemPcap {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Сценарий «Ctrl-C посреди передачи»: после `at`-го SYN адаптера скана поток TX поднимает счётчик нажатий и ждёт,
/// пока цикл событий CLI его увидит и поставит паузу (следующий опрос `interrupts()` плюс запас на сам `pause()`).
/// С `late_first` ответ на первый SYN (всегда SYN-ACK) придерживается и выдаётся приёмнику после 40 пустых
/// `recv` (2 с часов), то есть уже в окне `--wait`.
#[derive(Clone, Copy)]
struct PressInTx {
    at: usize,
    late_first: bool,
}

impl FakeBackend {
    fn new() -> Self {
        let world = [
            (
                Ipv4Addr::new(127, 0, 0, 0),
                Ipv4Addr::new(127, 255, 255, 255),
                {
                    let mut r = route(None);
                    r.local = true;
                    r.ifname = "lo".into();
                    r.ifindex = 1;
                    Some(r)
                },
            ),
            (
                Ipv4Addr::new(192, 0, 2, 0),
                Ipv4Addr::new(192, 0, 2, 255),
                Some(route(None)),
            ),
            (
                Ipv4Addr::new(203, 0, 113, 0),
                Ipv4Addr::new(203, 0, 113, 255),
                None,
            ),
            (
                Ipv4Addr::new(0, 0, 0, 0),
                Ipv4Addr::new(255, 255, 255, 255),
                Some(route(Some(GW))),
            ),
        ];
        FakeBackend {
            routes: FakeRoutes {
                rules: world
                    .into_iter()
                    .map(|(a, b, r)| (u32::from(a), u32::from(b), r))
                    .collect(),
                defaults: vec![route(Some(GW))],
                defaults_panic: false,
                lookups: Arc::new(Mutex::new(Vec::new())),
            },
            ifaces: vec![lo(), eth0()],
            tables_panic: false,
            entropy_and_time_panic: false,
            panic_on_open: false,
            open_error: None,
            neighbors: vec![(GW, GW_MAC)],
            health: None,
            unix_time: UNIX_TIME,
            clock: ManualClock::new(),
            opened: Mutex::new(Vec::new()),
            attempts: Mutex::new(Vec::new()),
            tx: Arc::new(Mutex::new(Vec::new())),
            presses: Arc::new(AtomicU32::new(0)),
            polls: Arc::new(AtomicUsize::new(0)),
            press_during_arp: false,
            silent_targets: false,
            press_in_tx: None,
            paused_writes: Mutex::new(Vec::new()),
            paused_write_error: None,
            pcap: Arc::new(Mutex::new(Vec::new())),
            pcap_opened: Mutex::new(Vec::new()),
            inject_noise: false,
        }
    }

    fn attempts(&self) -> Vec<AdapterBinding> {
        self.attempts.lock().unwrap().clone()
    }

    fn tx_journal(&self) -> Vec<Vec<u8>> {
        self.tx.lock().unwrap().clone()
    }

    fn lookups(&self) -> Vec<Ipv4Addr> {
        self.routes.lookups.lock().unwrap().clone()
    }

    fn opened(&self) -> std::sync::MutexGuard<'_, Vec<Opened>> {
        self.opened.lock().unwrap()
    }

    fn polls(&self) -> usize {
        self.polls.load(Ordering::SeqCst)
    }

    fn presses(&self) -> u32 {
        self.presses.load(Ordering::SeqCst)
    }

    fn pcap_bytes(&self) -> Vec<u8> {
        self.pcap.lock().unwrap().clone()
    }

    fn paused_writes(&self) -> Vec<(u64, String)> {
        self.paused_writes.lock().unwrap().clone()
    }
}

/// Ответчик фиктивной сети: ARP-запрос к соседу → ответ соседа; SYN → SYN-ACK для [`OPEN`], иначе RST.
fn respond(frame: &[u8], neighbors: &[(Ipv4Addr, [u8; 6])]) -> Vec<Vec<u8>> {
    match frame.get(12..14) {
        Some([0x08, 0x06]) => {
            let Ok(p) = decode(frame) else { return vec![] };
            neighbors
                .iter()
                .find(|(ip, _)| p.op == ArpOp::Request && u32::from(*ip) == p.target_ip)
                .map(|(ip, mac)| {
                    vec![encode_reply(*mac, u32::from(*ip), p.sender_mac, p.sender_ip).to_vec()]
                })
                .unwrap_or_default()
        }
        Some([0x08, 0x00]) => {
            let (ip, port) = syn_dst(frame);
            let flags = if OPEN.contains(&(ip, port)) {
                0x12
            } else {
                0x04
            };
            reply_to_syn(frame, flags).into_iter().collect()
        }
        _ => vec![],
    }
}

impl Wall for FakeBackend {
    fn unix_time(&self) -> u64 {
        assert!(!self.entropy_and_time_panic, "time must not be read");
        self.unix_time
    }
    fn utc_offset_secs(&self, _: u64) -> i32 {
        0
    }
}

impl Backend for FakeBackend {
    fn routes(&self) -> Result<Box<dyn RouteTable>, NetError> {
        assert!(!self.tables_panic, "the route table must not be queried");
        Ok(Box::new(self.routes.clone()))
    }
    fn interfaces(&self) -> Result<Box<dyn Interfaces>, NetError> {
        assert!(!self.tables_panic, "the interface list must not be queried");
        Ok(Box::new(FakeIfaces(self.ifaces.clone())))
    }
    fn open(&self, binding: &AdapterBinding) -> Result<AdapterPair, NetError> {
        assert!(!self.panic_on_open, "open must not be called in this test");
        self.attempts.lock().unwrap().push(binding.clone());
        if let Some(e) = &self.open_error {
            return Err(e.clone());
        }
        let mut opened = self.opened();
        let alive_before = opened.iter().map(|o| o.adapter.alive_handles()).sum();
        let adapter = FakeAdapter::new().with_clock(self.clock.clone());
        if let Some(h) = &self.health {
            adapter.set_health(h.clone());
        }
        let (neighbors, tx) = (self.neighbors.clone(), self.tx.clone());
        let (presses, press_during_arp) = (self.presses.clone(), self.press_during_arp);
        let silent_targets = self.silent_targets;
        let inject_noise = self.inject_noise;
        // Сценарий действует на адаптер скана (не на ARP-адаптер, открытый первым).
        let scenario = self.press_in_tx.filter(|_| !opened.is_empty());
        let held: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let (held_r, first_syn) = (held.clone(), Arc::new(AtomicU32::new(0)));
        let hook_presses = presses.clone();
        adapter.set_responder(move |f| {
            tx.lock().unwrap().push(f.to_vec());
            if press_during_arp && is_arp(f) {
                presses.fetch_max(1, Ordering::SeqCst);
            }
            if silent_targets && !is_arp(f) {
                return vec![];
            }
            if scenario.is_some_and(|s| s.late_first)
                && is_syn(f)
                && first_syn.fetch_add(1, Ordering::SeqCst) == 0
            {
                *held_r.lock().unwrap() = reply_to_syn(f, 0x12);
                return vec![];
            }
            let mut replies = respond(f, &neighbors);
            if inject_noise && is_syn(f) {
                replies.extend(noise_for(f));
            }
            replies
        });
        if let Some(PressInTx { at, .. }) = scenario {
            let (polls, handle) = (self.polls.clone(), adapter.clone());
            adapter.set_send_hook(move |count| {
                if count != at {
                    return;
                }
                let before = polls.load(Ordering::SeqCst);
                hook_presses.fetch_max(1, Ordering::SeqCst);
                // Цикл событий опрашивает `interrupts()` на каждой итерации; следующий опрос видит нажатие и ставит
                // паузу. Запас в 500 мс покрывает вызов `pause()` сразу после опроса.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while polls.load(Ordering::SeqCst) <= before && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
                if let Some(frame) = held.lock().unwrap().take() {
                    handle.push_rx(RxStep::Idle(40));
                    handle.push_frame(frame);
                }
            });
        }
        let pair = adapter.pair();
        opened.push(Opened {
            binding: binding.clone(),
            adapter,
            alive_before,
            polls_before: self.polls(),
        });
        Ok(pair)
    }
    fn entropy64(&self) -> u64 {
        assert!(!self.entropy_and_time_panic, "entropy must not be read");
        ENTROPY
    }
    fn arp_policy(&self) -> ArpPolicy {
        ArpPolicy::default()
    }
    fn clock(&self) -> Arc<dyn Clock + Send + Sync> {
        self.clock.clone()
    }
    fn services(&self) -> ServiceNames {
        ServiceNames::parse("http 80/tcp\n")
    }
    fn interrupts(&self) -> u32 {
        self.polls.fetch_add(1, Ordering::SeqCst);
        self.presses()
    }
    fn create_pcap(&self, path: &str) -> Result<Box<dyn std::io::Write + Send>, String> {
        self.pcap_opened.lock().unwrap().push(path.to_string());
        Ok(Box::new(MemPcap(self.pcap.clone())))
    }
    fn write_paused_conf(&self, content: &str) -> Result<(), String> {
        if let Some(e) = &self.paused_write_error {
            return Err(e.clone());
        }
        self.paused_writes
            .lock()
            .unwrap()
            .push((self.clock.now_micros(), content.to_string()));
        Ok(())
    }
}

/// Шум к SYN: RST на наш `ip:port` с испорченным ack (плохой SYN-cookie) и валидный ответ на чужой адрес.
fn noise_for(syn: &[u8]) -> Vec<Vec<u8>> {
    let mut bad_cookie = reply_to_syn(syn, 0x04).unwrap();
    bad_cookie[42] ^= 0xff;
    let mut foreign = reply_to_syn(syn, 0x12).unwrap();
    foreign[30..34].copy_from_slice(&[192, 0, 2, 99]);
    vec![bad_cookie, foreign]
}

fn parse(args: &[&str]) -> Cli {
    Cli::try_parse_masscan(std::iter::once("rmasscan").chain(args.iter().copied())).unwrap()
}

fn config(args: &[&str]) -> ScanConfig {
    parse(args).to_config().unwrap()
}

fn with<'a>(base: &[&'a str], extra: &[&'a str]) -> Vec<&'a str> {
    base.iter().chain(extra).copied().collect()
}

/// Весь CLI (`rmasscan_cli::run`): итог, stdout, stderr.
fn cli(b: &FakeBackend, args: &[&str]) -> (Result<(), String>, String, String) {
    let (mut out, mut log) = (Vec::new(), Vec::new());
    let r = rmasscan_cli::run(&parse(args), b, &mut out, &mut log);
    (
        r,
        String::from_utf8(out).unwrap(),
        String::from_utf8(log).unwrap(),
    )
}

/// `run_live` с интерактивным приёмником в память.
fn live_run(b: &FakeBackend, args: &[&str]) -> (Result<Outcome, String>, String, String) {
    let (mut out, mut log) = (Vec::new(), Vec::new());
    let r = {
        let mut sink = Interactive::new(&mut out);
        live::run_live(&config(args), b, &mut sink, &mut log)
    };
    (
        r,
        String::from_utf8(out).unwrap(),
        String::from_utf8(log).unwrap(),
    )
}

fn is_arp(f: &[u8]) -> bool {
    f.get(12..14) == Some(&[0x08, 0x06][..])
}

fn is_syn(f: &[u8]) -> bool {
    f.get(12..14) == Some(&[0x08, 0x00][..]) && f.get(47) == Some(&0x02)
}

fn syn_dst(f: &[u8]) -> (Ipv4Addr, u16) {
    (
        Ipv4Addr::new(f[30], f[31], f[32], f[33]),
        u16::from_be_bytes([f[36], f[37]]),
    )
}

fn plus_lines(log: &str) -> Vec<&str> {
    log.lines()
        .map(normalize_stderr_line)
        .filter(|l| l.starts_with("[+] "))
        .collect()
}

#[test]
fn live_scan_detects_resolves_and_prints_discovered_lines() {
    let b = FakeBackend::new();
    let (r, out, log) = cli(&b, &LIVE);
    r.unwrap();
    let opened = b.opened();
    assert_eq!(opened.len(), 2, "one ARP adapter, then one scan adapter");
    let (arp, scan) = (&opened[0], &opened[1]);

    // Ровно один ARP-запрос "who has GW" с выбранного интерфейса, до первого SYN.
    assert_eq!(
        arp.adapter.sent_frames(),
        vec![encode_request(MY_MAC, u32::from(MY_IP), u32::from(GW)).to_vec()]
    );
    let syns = scan.adapter.sent_frames();
    assert!(!syns.is_empty());
    assert!(
        syns.iter().all(|f| is_syn(f) && !is_arp(f)),
        "scan adapter sends only SYN"
    );
    for f in &syns {
        assert_eq!(&f[0..6], &GW_MAC, "SYN goes to the resolved MAC");
        assert_eq!(&f[6..12], &MY_MAC, "SYN source MAC is the detected one");
        assert_eq!(
            &f[26..30],
            &MY_IP.octets(),
            "SYN source IP is the detected one"
        );
        assert_eq!(
            &f[34..36],
            &TIME_PORT.to_be_bytes(),
            "source port by the time formula"
        );
    }
    assert_eq!(syns.len(), 4, "2 addresses x 2 ports");
    let journal = b.tx_journal();
    assert_eq!(
        journal.len(),
        1 + syns.len(),
        "every frame on the wire: 1 ARP + the SYNs"
    );
    assert!(is_arp(&journal[0]), "the ARP request comes first");
    assert_eq!(
        &journal[1..],
        &syns[..],
        "then only the scan adapter's SYNs"
    );
    assert_eq!(
        scan.binding,
        AdapterBinding {
            interface_id: IF_NAME.into(),
            link_type: LinkType::Ethernet,
            source_ipv4: u32::from(MY_IP),
            source_mac: MY_MAC,
            next_hop_mac: GW_MAC,
            source_ports: (TIME_PORT, TIME_PORT),
        }
    );

    let expected = [
        "[+] interface = eth0 (detected: route to 198.51.100.1)".to_string(),
        "[+] source-mac = 02-aa-00-00-00-01 (detected)".to_string(),
        "[+] source-ip = 192.0.2.5 (detected)".to_string(),
        "[+] router-ip = 192.0.2.1 (route gateway)".to_string(),
        "[+] router-mac = 02-aa-00-00-00-02 (arp: 1 requests, 0 ms)".to_string(),
        format!("[+] seed = {ENTROPY} (entropy)"),
        format!("[+] source-port = {TIME_PORT} (time)"),
        format!(
            "[+] finished: Completed, sent {}, replies 4, open 2",
            syns.len()
        ),
    ];
    assert_eq!(plus_lines(&log), expected, "{log}");
    assert_eq!(log.lines().count(), expected.len(), "only [+] lines: {log}");

    // stdout: строки Discovered в порядке ответов (= порядок SYN), по 80 байт, только open.
    let want: String = syns
        .iter()
        .map(|f| syn_dst(f))
        .filter(|d| OPEN.contains(d))
        .map(|(ip, port)| discovered_line(ip, port))
        .collect();
    assert_eq!(out, want);
    assert_eq!(out.len(), 2 * 80);
}

#[test]
fn router_mac_override_sends_no_arp() {
    let b = FakeBackend::new();
    let (r, out, log) = cli(&b, &with(&LIVE, &["--router-mac", "02-aa-00-00-00-09"]));
    r.unwrap();
    let opened = b.opened();
    assert_eq!(opened.len(), 1, "no ARP adapter");
    let frames = opened[0].adapter.sent_frames();
    assert_eq!(frames.len(), 4);
    assert!(
        frames
            .iter()
            .all(|f| is_syn(f) && f[0..6] == [0x02, 0xaa, 0, 0, 0, 9])
    );
    let plus = plus_lines(&log);
    assert!(
        plus.contains(&"[+] router-mac = 02-aa-00-00-00-09 (given)"),
        "{log}"
    );
    assert!(
        !log.contains("router-ip"),
        "router-ip is neither given nor looked up: {log}"
    );
    assert!(!log.contains("(arp:"), "{log}");
    assert_eq!(out.len(), 2 * 80);
}

#[test]
fn arp_timeout_sends_no_syn_and_fails_with_hints() {
    let mut b = FakeBackend::new();
    b.neighbors.clear();
    let t0 = b.clock.now_micros();
    let (r, out, log) = cli(&b, &LIVE);
    let e = r.unwrap_err();
    assert_eq!(
        e,
        "[-] FAIL: ARP timed-out resolving MAC address for router eth0: \"192.0.2.1\"\n    \
         [hint] try \"--router-ip 192.0.2.1\" to specify different router\n    \
         [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP\n    \
         [hint] try \"--interface eth0\" to change interface"
    );
    assert_eq!(
        rmasscan_cli::error_text(&e),
        e,
        "C form, no rmasscan: error: wrapper"
    );
    assert_eq!(
        b.clock.now_micros() - t0,
        10_000_000,
        "the resolver gives up at 10 s"
    );
    let opened = b.opened();
    assert_eq!(opened.len(), 1, "the scan adapter is never opened");
    let frames = opened[0].adapter.sent_frames();
    assert_eq!(frames.len(), 10, "ten ARP requests");
    assert!(
        frames
            .iter()
            .all(|f| *f == encode_request(MY_MAC, u32::from(MY_IP), u32::from(GW)).to_vec())
    );
    assert!(out.is_empty());
    assert!(
        !log.contains("router-mac") && !log.contains("finished"),
        "{log}"
    );
}

#[test]
fn detection_failure_opens_nothing() {
    let mut b = FakeBackend::new();
    b.panic_on_open = true;
    for (args, want) in [
        (
            &["203.0.113.9", "-p80"][..],
            "[-] FAIL: could not determine default interface\n    [hint] try \"--interface ethX\"",
        ),
        (
            &["198.51.100.1", "-p80", "--adapter", "nosuch0"][..],
            "[-] FAIL: no such interface \"nosuch0\"\n    [hint] did you spell the name correctly?",
        ),
        (
            &["198.51.100.1", "-p80", "--adapter", "lo"][..],
            "[-] FAIL: interface \"lo\" is not usable: not Ethernet\n    [hint] try \"--interface ethX\"",
        ),
        // `--adapter` без `--router-ip`/`--router-mac`: on-link и удалённая цель идут через eth0 разными шлюзами;
        // интерфейс уже задан, поэтому подсказки маршрутизатора C.
        (
            &["192.0.2.9,198.51.100.1", "-p80", "--adapter", "eth0"][..],
            "[-] FAIL: targets are routed differently (192.0.2.9 via eth0, 198.51.100.1 via eth0)\n    [hint] try \"--router-ip 192.0.2.1\" to specify different router\n    [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP\n    [hint] try \"--interface eth0\" to change interface",
        ),
    ] {
        let (r, out, log) = cli(&b, args);
        let e = r.unwrap_err();
        assert_eq!(e, want, "{args:?}");
        assert_eq!(rmasscan_cli::error_text(&e), e, "{args:?}");
        assert!(out.is_empty() && log.is_empty(), "{args:?}: {log}");
    }
}

/// Ограничения плана и конфигурации (rounds 0 и shard 4/3 отвергает `validate`/разбор, `resume-index` за
/// `(retries + 1) * range` отвергает курсор плана `new_cli`) проверяются до ARP: отказ не стоит ни одного кадра. `--retries`, `--shard`, `--resume-index` и
/// `--blackrock-rounds` в допустимых пределах скан запускают (Задача 3).
#[test]
fn unsupported_plan_options_are_refused_before_any_frame() {
    let mut b = FakeBackend::new();
    b.panic_on_open = true;
    for (extra, word) in [
        (&["--blackrock-rounds", "0"][..], "rounds"),
        (&["--blackrock-rounds", "64"][..], "rounds"),
        (&["--resume-index", "5"][..], "beyond"),
        (&["--shard", "4/3"][..], "shard"),
    ] {
        let args: Vec<&str> = LIVE.iter().chain(extra).copied().collect();
        let (r, out, log) = cli(&b, &args);
        let e = r.unwrap_err();
        assert!(e.contains(word), "{extra:?}: {e}");
        assert!(out.is_empty() && log.is_empty(), "{extra:?}: {log}");
    }
}

/// Разрешённые пределы плана (Задача 3): шардирование делит поток, повторы удлиняют его, `--resume-index` и
/// `--resume-count` режут его; скан завершается `Completed`.
#[test]
fn retries_shard_and_resume_window_run_on_the_live_path() {
    let sent = |extra: &[&str]| {
        let b = FakeBackend::new();
        let (r, _, log) = cli(&b, &with(&LIVE, extra));
        r.unwrap();
        assert!(log.contains("finished: Completed"), "{extra:?}: {log}");
        let opened = b.opened();
        opened.last().unwrap().adapter.sent_frames()
    };
    // range = 2 адреса x 2 порта = 4; поток одного адаптера 1/1.
    let all = sent(&["--seed", "7"]);
    assert_eq!(all.len(), 4);
    // Две половины shard 1/2 + 2/2 вместе дают ровно тот же набор кадров.
    let mut halves = sent(&["--seed", "7", "--shard", "1/2"]);
    halves.extend(sent(&["--seed", "7", "--shard", "2/2"]));
    assert_eq!(halves.len(), 4);
    let (mut a, mut h) = (all.clone(), halves);
    a.sort();
    h.sort();
    assert_eq!(a, h, "shard 1/2 + 2/2 == shard 1/1");
    // `--retries 1`: (1 + 1) * (4 + 4) = 16 кадров, каждая пара (ip, порт) по 4 раза.
    let retried = sent(&["--seed", "7", "--retries", "1"]);
    assert_eq!(retried.len(), 16);
    for f in &all {
        assert_eq!(
            retried.iter().filter(|r| syn_dst(r) == syn_dst(f)).count(),
            4
        );
    }
    // `--resume-index 1 --resume-count 2` шлёт ровно два кадра и завершается.
    assert_eq!(
        sent(&["--seed", "7", "--resume-index", "1", "--resume-count", "2"]),
        all[1..3].to_vec()
    );
}

/// `--resume <file>` end-to-end: файл задаёт цели, seed, `resume-index`; ключ правее файла (`--rate`) его
/// переопределяет. Отправлен ровно остаток потока `resume-index..range`.
#[test]
fn resume_file_continues_the_scan_from_its_index() {
    let b = FakeBackend::new();
    let (r, _, _) = cli(&b, &with(&LIVE, &["--seed", "7"]));
    r.unwrap();
    let all = b.opened().last().unwrap().adapter.sent_frames();
    assert_eq!(all.len(), 4);

    let dir = Scratch::new();
    let file = dir.write(
        "paused.conf",
        b"\n# resume information\nresume-index = 1\nseed = 7\nrate = 100\nwait = 1\n\
nocapture = servername\nnocapture = servername\n\n\n\
# TARGET SELECTION (IP, PORTS, EXCLUDES)\nports = 80,81\nrange = 198.51.100.1-198.51.100.2\n",
    );
    let f = file.to_str().unwrap();
    let b = FakeBackend::new();
    let (r, _, log) = cli(&b, &["--resume", f]);
    r.unwrap();
    assert!(log.contains("finished: Completed"), "{log}");
    assert_eq!(b.opened().last().unwrap().adapter.sent_frames(), all[1..]);

    // Ключ правее файла переопределяет его: `--resume-index 3` шлёт один последний кадр.
    let b = FakeBackend::new();
    let (r, _, _) = cli(&b, &["--resume", f, "--resume-index", "3"]);
    r.unwrap();
    assert_eq!(b.opened().last().unwrap().adapter.sent_frames(), all[3..]);
}

#[test]
fn permission_denied_on_open_names_the_os_hint_and_sends_nothing() {
    let hint = if cfg!(target_os = "linux") {
        "CAP_NET_RAW"
    } else if cfg!(target_os = "macos") {
        "/dev/bpf*"
    } else if cfg!(windows) {
        "Npcap"
    } else {
        "root"
    };
    let scan_binding = AdapterBinding {
        interface_id: IF_NAME.into(),
        link_type: LinkType::Ethernet,
        source_ipv4: u32::from(MY_IP),
        source_mac: MY_MAC,
        next_hop_mac: [0x02, 0xaa, 0, 0, 0, 9],
        source_ports: (TIME_PORT, TIME_PORT),
    };
    // Отказ первого open: ARP-адаптера (без --router-mac) или адаптера скана (с --router-mac). После него ни одной
    // попытки открыть что-то ещё и ни одного кадра.
    for (args, only_attempt) in [
        (
            LIVE.to_vec(),
            arp_binding(IF_NAME, MY_IP, MY_MAC, (TIME_PORT, TIME_PORT)),
        ),
        (
            with(&LIVE, &["--router-mac", "02-aa-00-00-00-09"]),
            scan_binding,
        ),
    ] {
        let mut b = FakeBackend::new();
        b.open_error = Some(NetError::PermissionDenied("/dev/x".into()));
        let (r, out, _) = cli(&b, &args);
        let e = r.unwrap_err();
        assert!(e.contains("permission denied"), "{e}");
        assert!(e.contains("[hint]") && e.contains(hint), "{e}");
        if cfg!(windows) {
            assert!(e.contains("Administrator"), "{e}");
        }
        assert!(
            rmasscan_cli::error_text(&e).starts_with("rmasscan: error: "),
            "an open error keeps the wrapper: {e}"
        );
        assert!(out.is_empty());
        assert_eq!(
            b.attempts(),
            vec![only_attempt],
            "{args:?}: exactly one open attempt, no scan open after the failed one"
        );
        assert!(b.tx_journal().is_empty(), "{args:?}: no frame was sent");
    }
}

#[test]
fn arp_adapter_is_closed_before_the_scan_adapter_opens() {
    let b = FakeBackend::new();
    let (r, _, _) = cli(&b, &LIVE);
    r.unwrap();
    let opened = b.opened();
    assert_eq!(opened.len(), 2);
    assert_eq!(
        opened[0].binding,
        arp_binding(IF_NAME, MY_IP, MY_MAC, (TIME_PORT, TIME_PORT)),
        "the ARP adapter has a broadcast next hop"
    );
    assert_eq!(opened[0].binding.next_hop_mac, [0xff; 6]);
    assert_eq!(
        opened[1].alive_before, 0,
        "ARP handles dropped before the scan open"
    );
    assert_eq!(opened[1].binding.next_hop_mac, GW_MAC);
    assert!(opened.iter().all(|o| o.adapter.alive_handles() == 0));
}

#[test]
fn seed_defaults_to_entropy_and_is_printed() {
    let b = FakeBackend::new();
    let p = live::prepare(&config(&LIVE), SeedPolicy::Entropy, &b, false).unwrap();
    assert_eq!(p.seed, (ENTROPY, Source::Detected));
    assert_eq!(p.eff.seed(), ENTROPY);
    let given = live::prepare(
        &config(&with(&LIVE, &["--seed", "9"])),
        SeedPolicy::Entropy,
        &b,
        false,
    )
    .unwrap();
    assert_eq!(given.seed, (9, Source::Given));
    let (r, _, log) = live_run(&b, &with(&LIVE, &["--router-mac", "02-aa-00-00-00-09"]));
    r.unwrap();
    assert!(
        plus_lines(&log).contains(&format!("[+] seed = {ENTROPY} (entropy)").as_str()),
        "{log}"
    );
    let (r, _, log) = live_run(
        &b,
        &with(&LIVE, &["--router-mac", "02-aa-00-00-00-09", "--seed", "9"]),
    );
    r.unwrap();
    assert!(plus_lines(&log).contains(&"[+] seed = 9 (given)"), "{log}");
}

#[test]
fn source_port_defaults_to_time_formula() {
    let mut b = FakeBackend::new();
    let p = live::prepare(&config(&LIVE), SeedPolicy::Entropy, &b, false).unwrap();
    assert_eq!(p.source_ports, ((TIME_PORT, TIME_PORT), Source::Detected));
    assert_eq!(p.binding.source_ports, (TIME_PORT, TIME_PORT));
    assert_eq!(p.eff.source_port(), Some((TIME_PORT, TIME_PORT)));
    b.unix_time = 1_800_000_000;
    let p = live::prepare(&config(&LIVE), SeedPolicy::Entropy, &b, false).unwrap();
    assert_eq!(p.source_ports.0, (40000, 40000));
    b.unix_time = UNIX_TIME;
    let args = with(&LIVE, &["--router-mac", "02-aa-00-00-00-09"]);
    let (r, _, log) = live_run(&b, &args);
    r.unwrap();
    assert!(
        plus_lines(&log).contains(&format!("[+] source-port = {TIME_PORT} (time)").as_str()),
        "{log}"
    );
    let (r, _, log) = live_run(&b, &with(&args, &["--source-port", "50000-50015"]));
    r.unwrap();
    assert!(
        plus_lines(&log).contains(&"[+] source-port = 50000-50015 (given)"),
        "{log}"
    );
}

#[test]
fn internet_wide_range_without_exclude_is_refused_before_detection() {
    let mut b = FakeBackend::new();
    b.tables_panic = true;
    b.panic_on_open = true;
    let (r, out, log) = cli(&b, &["0.0.0.0/0", "-p80"]);
    let e = r.unwrap_err();
    assert!(e.contains("range too big"), "{e}");
    assert!(
        rmasscan_cli::error_text(&e).starts_with("rmasscan: error: "),
        "{e}"
    );
    assert!(out.is_empty() && log.is_empty());
    assert!(b.lookups().is_empty());
}

#[test]
fn internet_wide_range_with_the_canonical_exclude_probes_unicast_targets() {
    let mut b = FakeBackend::new();
    b.panic_on_open = true;
    let cfg = config(&["0.0.0.0/0", "-p80", "--exclude", "255.255.255.255"]);
    let p = live::prepare(&cfg, SeedPolicy::Entropy, &b, false).unwrap();
    assert_eq!(
        b.lookups(),
        vec![Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(223, 255, 255, 255)]
    );
    assert_eq!(p.detected.iface.name, IF_NAME);
    assert_eq!(
        p.detected.next_hop,
        NextHop::Resolve {
            ip: GW,
            why: NextHopWhy::RouteGateway
        }
    );
}

#[test]
fn offline_uses_the_fake_router_mac_even_with_router_mac_and_no_next_hop_lookup() {
    let mut b = FakeBackend::new();
    b.panic_on_open = true;
    b.routes.defaults_panic = true;
    let base = [
        "--offline",
        "198.51.100.7",
        "-p80",
        "--seed",
        "1",
        "--router-mac",
        "02-aa-00-00-00-09",
        "--router-ip",
        "192.0.2.1",
    ];
    // С --adapter: ни одного lookup (следующий хоп не ищется).
    let args = with(&base, &["--adapter", "eth0"]);
    let p = live::prepare(&config(&args), SeedPolicy::Required, &b, true).unwrap();
    assert!(b.lookups().is_empty(), "{:?}", b.lookups());
    assert_eq!(
        p.detected.next_hop,
        NextHop::Mac(OFFLINE_MAC, Source::Given)
    );
    assert_eq!(p.binding.next_hop_mac, OFFLINE_MAC);
    let (r, out, log) = cli(&b, &args);
    r.unwrap();
    assert!(out.is_empty(), "no --packet-trace: only [+] lines");
    assert_eq!(
        plus_lines(&log),
        [
            "[+] interface = eth0 (given)",
            "[+] source-mac = 02-aa-00-00-00-01 (detected)",
            "[+] source-ip = 192.0.2.5 (detected)",
            "[+] router-ip = none (offline)",
            "[+] router-mac = 66-55-44-33-22-11 (offline)",
            "[+] seed = 1 (given)",
            &format!("[+] source-port = {TIME_PORT} (time)"),
        ]
    );
    // Без --adapter: один lookup первой цели (выбор интерфейса), маршрутизатор не ищется.
    let p = live::prepare(&config(&base), SeedPolicy::Required, &b, true).unwrap();
    assert_eq!(b.lookups(), vec![Ipv4Addr::new(198, 51, 100, 7)]);
    assert_eq!(p.binding.next_hop_mac, OFFLINE_MAC);
}

/// `--offline` с явными IP и MAC, но без `--source-port` не герметичен: интерфейс ищется по маршруту к цели, поэтому
/// preflight `--offline` (R1) видит обнаруженный интерфейс и отказы маршрута.
#[test]
fn offline_with_explicit_ip_and_mac_but_no_port_still_consults_the_os() {
    let mut b = FakeBackend::new();
    b.panic_on_open = true;
    b.routes.defaults_panic = true;
    let base = [
        "--offline",
        "-p80",
        "--seed",
        "1",
        "--adapter-ip",
        "10.255.0.1",
        "--adapter-mac",
        "00-11-22-33-44-55",
    ];
    let (r, out, log) = cli(&b, &with(&base, &["198.51.100.7"]));
    r.unwrap();
    assert!(out.is_empty());
    assert_eq!(b.lookups(), vec![Ipv4Addr::new(198, 51, 100, 7)]);
    assert_eq!(
        plus_lines(&log),
        [
            "[+] interface = eth0 (detected: route to 198.51.100.7)",
            "[+] source-mac = 00-11-22-33-44-55 (given)",
            "[+] source-ip = 10.255.0.1 (given)",
            "[+] router-ip = none (offline)",
            "[+] router-mac = 66-55-44-33-22-11 (offline)",
            "[+] seed = 1 (given)",
            &format!("[+] source-port = {TIME_PORT} (time)"),
        ]
    );
    // Отказ, зависящий от маршрута, не скрыт.
    let (r, _, log) = cli(&b, &with(&base, &["203.0.113.9"]));
    assert_eq!(
        r.unwrap_err(),
        "[-] FAIL: could not determine default interface\n    [hint] try \"--interface ethX\""
    );
    assert!(log.is_empty(), "{log}");
}

/// Прежний набор `TRACE` (lib-тесты): явные IP, MAC, MAC шлюза и порт.
const TRACE: [&str; 13] = [
    "--offline",
    "--packet-trace",
    "10.0.0.0/30",
    "-p80,443",
    "--seed",
    "5",
    "--adapter-ip",
    "10.255.0.1",
    "--adapter-mac",
    "00-11-22-33-44-55",
    "--router-mac",
    "66-55-44-33-22-11",
    "--source-port=40000-40003",
];

fn hermetic() -> FakeBackend {
    let mut b = FakeBackend::new();
    b.tables_panic = true;
    b.entropy_and_time_panic = true;
    b.panic_on_open = true;
    b
}

#[test]
fn offline_with_explicit_ip_mac_and_port_never_queries_the_os() {
    let b = hermetic();
    let args: Vec<&str> = TRACE
        .iter()
        .copied()
        .filter(|a| *a != "--packet-trace")
        .collect();
    let (r, out, log) = cli(&b, &args);
    r.unwrap();
    assert!(out.is_empty());
    assert_eq!(
        plus_lines(&log),
        [
            "[+] interface = none (offline)",
            "[+] source-mac = 00-11-22-33-44-55 (given)",
            "[+] source-ip = 10.255.0.1 (given)",
            "[+] router-ip = none (offline)",
            "[+] router-mac = 66-55-44-33-22-11 (offline)",
            "[+] seed = 5 (given)",
            "[+] source-port = 40000-40003 (given)",
        ]
    );
    let (r, _, log) = cli(&b, &with(&args, &["--adapter", "eth9"]));
    r.unwrap();
    assert!(
        plus_lines(&log).contains(&"[+] interface = eth9 (given)"),
        "{log}"
    );
}

/// stdout бинарника HEAD `2804fce` для `TRACE` (время из инжектированных часов, поэтому `0.0000`).
const TRACE_GOLDEN: &str = "\
SENT (0.0000) TCP  [10.255.0.1]:40002    > [10.0.0.2]:443        SYN
SENT (0.0000) TCP  [10.255.0.1]:40000    > [10.0.0.1]:80         SYN
SENT (0.0000) TCP  [10.255.0.1]:40000    > [10.0.0.3]:443        SYN
SENT (0.0000) TCP  [10.255.0.1]:40002    > [10.0.0.2]:80         SYN
SENT (0.0000) TCP  [10.255.0.1]:40003    > [10.0.0.3]:80         SYN
SENT (0.0000) TCP  [10.255.0.1]:40003    > [10.0.0.0]:80         SYN
SENT (0.0000) TCP  [10.255.0.1]:40003    > [10.0.0.1]:443        SYN
SENT (0.0000) TCP  [10.255.0.1]:40001    > [10.0.0.0]:443        SYN
";

#[test]
fn offline_packet_trace_golden_unchanged() {
    let b = hermetic();
    let (r, out, log) = cli(&b, &TRACE);
    r.unwrap();
    assert_eq!(out, TRACE_GOLDEN);
    assert_eq!(plus_lines(&log).len(), 7, "{log}");
}

/// C `main-initadapter.c:122–126`: source IP 0 значит «определить у интерфейса». `--adapter-ip 0.0.0.0` и алиас
/// `--source-ip 0.0.0.0` дают адрес интерфейса: в строке `[+]`, в ARP и в SYN.
#[test]
fn zero_adapter_ip_is_unset_and_the_interface_address_is_detected() {
    for flag in ["--adapter-ip", "--source-ip"] {
        let b = FakeBackend::new();
        let (r, out, log) = cli(&b, &with(&LIVE, &[flag, "0.0.0.0"]));
        r.unwrap();
        assert!(
            plus_lines(&log).contains(&"[+] source-ip = 192.0.2.5 (detected)"),
            "{flag}: {log}"
        );
        assert!(!log.contains("0.0.0.0"), "{flag}: {log}");
        let opened = b.opened();
        assert_eq!(opened.len(), 2, "{flag}: one ARP adapter, then the scan");
        assert_eq!(
            opened[0].adapter.sent_frames(),
            vec![encode_request(MY_MAC, u32::from(MY_IP), u32::from(GW)).to_vec()],
            "{flag}: the ARP sender IP is the interface address"
        );
        assert_eq!(opened[1].binding.source_ipv4, u32::from(MY_IP), "{flag}");
        let syns = opened[1].adapter.sent_frames();
        assert_eq!(syns.len(), 4, "{flag}");
        assert!(
            syns.iter().all(|f| f[26..30] == MY_IP.octets()),
            "{flag}: SYNs come from the interface address"
        );
        assert_eq!(out.len(), 2 * 80, "{flag}");
    }
}

/// C `main-initadapter.c:170`: нулевой MAC шлюза значит «искать ARP-ом». `--router-mac 00-00-00-00-00-00` ведёт себя
/// как отсутствие флага: ARP к шлюзу маршрута, SYN на его MAC.
#[test]
fn zero_router_mac_is_unset_and_the_router_is_resolved_with_arp() {
    let b = FakeBackend::new();
    let (r, out, log) = cli(&b, &with(&LIVE, &["--router-mac", "00-00-00-00-00-00"]));
    r.unwrap();
    let plus = plus_lines(&log);
    assert!(
        plus.contains(&"[+] router-ip = 192.0.2.1 (route gateway)"),
        "{log}"
    );
    assert!(
        plus.contains(&"[+] router-mac = 02-aa-00-00-00-02 (arp: 1 requests, 0 ms)"),
        "{log}"
    );
    assert!(!log.contains("00-00-00-00-00-00"), "{log}");
    let opened = b.opened();
    assert_eq!(opened.len(), 2, "one ARP adapter, then the scan");
    assert_eq!(
        opened[0].adapter.sent_frames(),
        vec![encode_request(MY_MAC, u32::from(MY_IP), u32::from(GW)).to_vec()]
    );
    assert_eq!(opened[1].binding.next_hop_mac, GW_MAC);
    let syns = opened[1].adapter.sent_frames();
    assert_eq!(syns.len(), 4);
    assert!(
        syns.iter().all(|f| f[0..6] == GW_MAC),
        "SYNs go to the resolved MAC"
    );
    assert_eq!(out.len(), 2 * 80);
}

/// Воспроизведение ревью: `--offline --packet-trace` с `--adapter-ip 0.0.0.0` печатал `source-ip = 0.0.0.0 (given)`
/// и `SENT … [0.0.0.0]:40000`. Нулевой IP не задан, поэтому прогон не герметичен и берёт адрес интерфейса.
#[test]
fn offline_zero_adapter_ip_is_detected_not_sent_from_zero() {
    let mut b = FakeBackend::new();
    b.panic_on_open = true;
    b.routes.defaults_panic = true;
    let args = [
        "--offline",
        "--packet-trace",
        "10.0.0.1",
        "-p80",
        "--seed",
        "1",
        "--adapter-ip",
        "0.0.0.0",
        "--adapter-mac",
        "02-aa-00-00-00-01",
        "--source-port",
        "40000",
    ];
    let (r, out, log) = cli(&b, &args);
    r.unwrap();
    assert!(
        !out.contains("0.0.0.0") && !log.contains("0.0.0.0"),
        "{log}{out}"
    );
    assert_eq!(b.lookups(), vec![Ipv4Addr::new(10, 0, 0, 1)]);
    assert_eq!(
        plus_lines(&log),
        [
            "[+] interface = eth0 (detected: route to 10.0.0.1)",
            "[+] source-mac = 02-aa-00-00-00-01 (given)",
            "[+] source-ip = 192.0.2.5 (detected)",
            "[+] router-ip = none (offline)",
            "[+] router-mac = 66-55-44-33-22-11 (offline)",
            "[+] seed = 1 (given)",
            "[+] source-port = 40000 (given)",
        ]
    );
    assert_eq!(
        out,
        "SENT (0.0000) TCP  [192.0.2.5]:40000     > [10.0.0.1]:80         SYN\n"
    );
}

/// Приёмник, у которого запись падает не EPIPE (например, полный диск): на первой open-строке или, с `on_finish`,
/// только на завершающем flush.
struct FailingSink {
    reports: usize,
    on_finish: bool,
}

const SINK_ERROR: &str = "write failed: No space left on device (os error 28)";

impl Sink for FailingSink {
    fn open(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn report(&mut self, reply: &Reply) -> Result<(), String> {
        self.reports += 1;
        if reply.status == PortStatus::Open && !self.on_finish {
            return Err(SINK_ERROR.into());
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<(), String> {
        assert!(
            self.on_finish,
            "finish must not be called after a failed report"
        );
        Err(SINK_ERROR.into())
    }
}

/// Ошибка приёмника (не EPIPE) не прячет `[+] finished … sent N`: строка с `sent` engine печатается, затем
/// возвращается ошибка приёмника (exit 1, обёртка `rmasscan: error:`).
#[test]
fn sink_report_failure_still_prints_finished_with_the_engine_sent_count() {
    let b = FakeBackend::new();
    let mut log = Vec::new();
    let mut sink = FailingSink {
        reports: 0,
        on_finish: false,
    };
    let r = live::run_live(&config(&LIVE), &b, &mut sink, &mut log);
    let log = String::from_utf8(log).unwrap();
    let e = r.unwrap_err();
    assert_eq!(e, SINK_ERROR);
    assert_eq!(
        rmasscan_cli::error_text(&e),
        format!("rmasscan: error: {SINK_ERROR}")
    );
    let sent = b.opened()[1].adapter.sent_count();
    let fin = plus_lines(&log).last().copied().unwrap_or_default();
    let reason = fin
        .strip_prefix("[+] finished: ")
        .and_then(|s| s.split(',').next())
        .unwrap_or_default();
    assert!(
        reason == "Stopped" || reason == "Completed",
        "the stopped engine's outcome: {log}"
    );
    assert_eq!(
        fin,
        format!(
            "[+] finished: {reason}, sent {sent}, replies {}, open 1",
            sink.reports
        ),
        "{log}"
    );
    assert!(sent > 0, "the engine sent SYNs before the sink failed");
}

/// Сбой только завершающего flush приёмника: скан закончился сам, строка finished та же, что при успехе.
#[test]
fn sink_finish_failure_still_prints_finished() {
    let b = FakeBackend::new();
    let mut log = Vec::new();
    let mut sink = FailingSink {
        reports: 0,
        on_finish: true,
    };
    let r = live::run_live(&config(&LIVE), &b, &mut sink, &mut log);
    let log = String::from_utf8(log).unwrap();
    assert_eq!(r.unwrap_err(), SINK_ERROR);
    assert_eq!(
        plus_lines(&log).last().copied(),
        Some("[+] finished: Completed, sent 4, replies 4, open 2"),
        "{log}"
    );
}

#[test]
fn iflist_prints_interfaces_and_default_routes() {
    let mut b = FakeBackend::new();
    b.panic_on_open = true;
    let (r, out, log) = cli(&b, &["--iflist"]);
    r.unwrap();
    assert_eq!(
        out,
        "lo index=1 mac=none ipv4=127.0.0.1 up other\n\
         eth0 index=2 mac=02-aa-00-00-00-01 ipv4=192.0.2.5 up ethernet\n\
         default via 192.0.2.1 dev eth0\n"
    );
    assert!(log.is_empty());
    assert!(b.lookups().is_empty());
}

fn outcome(reason: Reason) -> Outcome {
    Outcome {
        reason,
        progress: Progress {
            sent: 3,
            next_index: 3,
            received: 1,
            discarded: 0,
            duplicates: 0,
            rate: 0.0,
        },
        rx_health: RxHealth {
            kernel_drops: Some(0),
        },
    }
}

#[test]
fn stopped_completed_and_paused_outcomes_exit_zero() {
    for (reason, line) in [
        (
            Reason::Stopped,
            "[+] finished: Stopped, sent 3, replies 1, open 1\n",
        ),
        (
            Reason::Completed,
            "[+] finished: Completed, sent 3, replies 1, open 1\n",
        ),
        // Р4: первое Ctrl-C после старта это пауза, и C выходит с кодом 0.
        (
            Reason::Paused,
            "[+] finished: Paused, sent 3, replies 1, open 1\n",
        ),
    ] {
        let mut log = Vec::new();
        live::conclude(&outcome(reason), 1, 1, &mut log).unwrap();
        assert_eq!(String::from_utf8(log).unwrap(), line);
    }
}

#[test]
fn failed_outcome_exits_one_with_reason() {
    let mut log = Vec::new();
    let e = live::conclude(
        &outcome(Reason::Failed(FailReason::TxError("link down".into()))),
        0,
        0,
        &mut log,
    )
    .unwrap_err();
    assert!(e.contains("TxError") && e.contains("link down"), "{e}");
    assert_eq!(
        String::from_utf8(log).unwrap(),
        "[+] finished: Failed(TxError(\"link down\")), sent 3, replies 0, open 0\n"
    );
    // End-to-end: приём без статистики → Failed(RxStatsUnavailable), exit 1 (Err), строка finished напечатана.
    let mut b = FakeBackend::new();
    b.health = Some(HealthStep::Unavailable);
    let (r, _, log) = cli(&b, &LIVE);
    let e = r.unwrap_err();
    assert!(e.contains("RxStatsUnavailable"), "{e}");
    assert!(
        rmasscan_cli::error_text(&e).starts_with("rmasscan: error: "),
        "{e}"
    );
    let sent = b.opened()[1].adapter.sent_count();
    let fin = plus_lines(&log)
        .last()
        .copied()
        .unwrap_or_default()
        .to_string();
    assert!(
        fin.starts_with(&format!(
            "[+] finished: Failed(RxStatsUnavailable), sent {sent}, "
        )),
        "{log}"
    );
}

// ---------- Гость n2 (Windows 11, лабораторный стенд w01–w08b; PF3) ----------

const N2_LAB_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const N2_LAB_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x04, 0x80, 0xa9];

/// Гость n2: «Ethernet 2» 198.18.0.1/30 без шлюза, «Ethernet» 10.0.2.15 с единственным маршрутом по умолчанию через
/// 10.0.2.2, Loopback Pseudo-Interface 1. Маршруты это ровно то, что `route_parse` (IP Helper) теперь выдаёт для строк
/// гостя; в `rmasscan-net` это закрепляет `route_parse_tests::guest_n2_broadcast_is_on_link_own_address_and_loopback_
/// interface_are_local` на дословной таблице `Get-NetRoute`: 198.18.0.1 локален (адрес адаптера), сосед .2 и
/// широковещательный .3 on-link через «Ethernet 2», остальное через «Ethernet». Открытие адаптера паникует.
fn guest_n2() -> FakeBackend {
    let lab = |local| Route {
        ifindex: 14,
        ifname: "Ethernet 2".into(),
        gateway: None,
        local,
    };
    let mgmt = Route {
        ifindex: 3,
        ifname: "Ethernet".into(),
        gateway: Some(Ipv4Addr::new(10, 0, 2, 2)),
        local: false,
    };
    let nic = |name: &str, index: u32, guid: &str, mac: Option<[u8; 6]>, ethernet, ip| Iface {
        name: name.into(),
        index,
        device_id: format!("\\Device\\NPF_{guid}"),
        description: Some(name.into()),
        mac,
        mac_masked: false,
        ethernet,
        up: true,
        ipv4: vec![ip],
    };
    let mut b = FakeBackend::new();
    b.routes.rules = vec![
        (u32::from(N2_LAB_IP), u32::from(N2_LAB_IP), Some(lab(true))),
        (
            u32::from(Ipv4Addr::new(198, 18, 0, 0)),
            u32::from(Ipv4Addr::new(198, 18, 0, 3)),
            Some(lab(false)),
        ),
        (0, u32::MAX, Some(mgmt.clone())),
    ];
    b.routes.defaults = vec![mgmt];
    b.ifaces = vec![
        nic(
            "Ethernet",
            3,
            "{00000000-0000-0000-0000-000000000003}",
            Some([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
            true,
            Ipv4Addr::new(10, 0, 2, 15),
        ),
        nic(
            "Ethernet 2",
            14,
            "{C4617223-A264-44F4-BDC8-0EA27F02CC40}",
            Some(N2_LAB_MAC),
            true,
            N2_LAB_IP,
        ),
        nic(
            "Loopback Pseudo-Interface 1",
            1,
            "{00000000-0000-0000-0000-000000000001}",
            None,
            false,
            Ipv4Addr::LOCALHOST,
        ),
    ];
    b.neighbors.clear();
    b.panic_on_open = true;
    b
}

/// w06_multi_no_gateway из `WINDOWS_CASES` (rmasscan-lab `autodetect_verify.rs`): `CaseSpec::argv` (цели, `-p`, флагов
/// нет, `COMMON_ARGS`); его preflight это тот же argv с `--offline` (`autodetect_suite::preflight_argv`).
const W06: [&str; 8] = [
    "198.18.0.2-198.18.0.3",
    "-p80,443,8000-8007,8099",
    "--seed",
    "1",
    "--rate",
    "100",
    "--wait",
    "3",
];

/// w06 на таблице гостя. Preflight `--offline` печатает то, чего ждёт `preflight_expectation("w06_multi_no_gateway")`
/// (`Preflight::Interface("Ethernet 2")`: rc 0 и `[+] interface = Ethernet 2 (detected: route to 198.18.0.2)`), и
/// только строки `[+]`. Живой argv отказывает текстом и подсказками строки w06 (`fail`, `hints: ROUTER_HINTS`) без
/// единой строки `[+]` (`detection: None`) и до открытия адаптера. На 9496cd7 тот же preflight на госте напечатал
/// `[-] FAIL: 198.18.0.3 is an address of this host (route via Ethernet 2)`.
#[test]
fn guest_n2_w06_preflight_shows_ethernet_2_and_the_live_run_refuses_no_gateway() {
    let mut b = guest_n2();
    b.routes.defaults_panic = true;
    let (r, out, log) = cli(&b, &with(&W06, &["--offline"]));
    assert_eq!(r, Ok(()), "{log}");
    assert!(out.is_empty(), "{out}");
    assert_eq!(
        log,
        format!(
            "[+] interface = Ethernet 2 (detected: route to 198.18.0.2)\n\
             [+] source-mac = 52-54-00-04-80-a9 (detected)\n\
             [+] source-ip = 198.18.0.1 (detected)\n\
             [+] router-ip = none (offline)\n\
             [+] router-mac = 66-55-44-33-22-11 (offline)\n\
             [+] seed = 1 (given)\n\
             [+] source-port = {TIME_PORT} (time)\n"
        )
    );
    assert_eq!(
        b.lookups(),
        [Ipv4Addr::new(198, 18, 0, 2), Ipv4Addr::new(198, 18, 0, 3)]
    );

    let b = guest_n2();
    let (r, out, log) = cli(&b, &W06);
    let e = r.unwrap_err();
    assert_eq!(
        e,
        "[-] FAIL: no default gateway on interface \"Ethernet 2\" for several on-link targets\n    \
         [hint] try \"--router-ip 192.0.2.1\" to specify different router\n    \
         [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP\n    \
         [hint] try \"--interface eth0\" to change interface"
    );
    assert_eq!(
        rmasscan_cli::error_text(&e),
        e,
        "C form, no rmasscan: error: wrapper"
    );
    assert!(out.is_empty() && log.is_empty(), "{log}");
    assert!(b.attempts().is_empty(), "nothing is opened");
}

/// Одна цель 198.18.0.3 (широковещательный адрес /30 стенда) на таблице гостя: on-link, следующий хоп это сама цель
/// (её разрешает ARP, как на Linux). Только `prepare` и строки `[+]` обнаружения: ни открытия, ни кадров. Адрес адаптера
/// 198.18.0.1 остаётся отказом `LocalTarget`; 224.0.0.0/4 и 255.255.255.255 по-прежнему не цели-пробы.
#[test]
fn guest_n2_single_broadcast_target_resolves_itself_on_link_and_own_address_refuses() {
    let b = guest_n2();
    let p = live::prepare(
        &config(&["198.18.0.3", "-p80", "--seed", "1"]),
        SeedPolicy::Required,
        &b,
        false,
    )
    .unwrap();
    assert_eq!(
        p.detected.next_hop,
        NextHop::Resolve {
            ip: Ipv4Addr::new(198, 18, 0, 3),
            why: NextHopWhy::OnLinkTarget,
        }
    );
    let mut log = Vec::new();
    live::print_detection(&p, &mut log).unwrap();
    assert_eq!(
        String::from_utf8(log).unwrap(),
        "[+] interface = Ethernet 2 (detected: route to 198.18.0.3)\n\
         [+] source-mac = 52-54-00-04-80-a9 (detected)\n\
         [+] source-ip = 198.18.0.1 (detected)\n\
         [+] router-ip = 198.18.0.3 (on-link target)\n"
    );
    assert!(b.attempts().is_empty(), "nothing is opened");

    let (r, out, log) = cli(&b, &["198.18.0.1", "-p80"]);
    assert_eq!(
        r.unwrap_err(),
        "[-] FAIL: 198.18.0.1 is an address of this host (route via Ethernet 2)\n    \
         [hint] try \"--interface ethX\" and \"--router-ip 192.0.2.1\""
    );
    assert!(out.is_empty() && log.is_empty(), "{log}");

    let b = guest_n2();
    let (r, _, log) = cli(&b, &["224.0.0.1,255.255.255.255", "-p80"]);
    assert_eq!(
        r.unwrap_err(),
        "[-] FAIL: no unicast target addresses to route to\n    \
         [hint] targets must include an address outside 0.0.0.0/8, 127.0.0.0/8 and 224.0.0.0/3"
    );
    assert!(log.is_empty() && b.lookups().is_empty(), "{log}");
}

// ---------- Mac стенда m1 (autodetect-suite macos, m01–m11; PF4) ----------

const M1_SCANNER_MAC: [u8; 6] = [0x02, 0xac, 0, 0, 0, 1];
const M1_PEER_MAC: [u8; 6] = [0x02, 0xac, 0, 0, 0, 2];

/// Mac стенда m1: feth4201 (сканер, без IPv4), feth4202 198.18.0.2/30 (IP-стек Mac в роли пира), lo0 и uplink en0
/// (документационные 192.0.2.10/24 через 192.0.2.1). Маршруты это то, что `route_parse` (route socket) теперь выдаёт
/// для ответов `RTM_GET` Mac при любом состоянии кеша маршрутов; в `rmasscan-net` это закрепляет
/// `route_parse_tests::mac_m1_only_addresses_of_this_host_are_local_and_they_route_via_lo0` на ответах из окна:
/// 198.18.0.2 (адрес feth4202), 127.0.0.0/8 и адрес en0 это адреса хоста через lo0, остальное в /30 on-link через
/// feth4202, прочее через en0. `root`: MAC видны, иначе скрыты ОС. Открытие адаптера паникует.
fn mac_m1(root: bool) -> FakeBackend {
    let lo0 = Route {
        ifindex: 1,
        ifname: "lo0".into(),
        gateway: None,
        local: true,
    };
    let peer = Route {
        ifindex: 36,
        ifname: "feth4202".into(),
        gateway: None,
        local: false,
    };
    let en0 = |gateway| Route {
        ifindex: 14,
        ifname: "en0".into(),
        gateway,
        local: false,
    };
    let nic = |name: &str, index, mac: Option<[u8; 6]>, ethernet, ipv4| Iface {
        name: name.into(),
        index,
        device_id: name.into(),
        description: None,
        mac: mac.filter(|_| root),
        mac_masked: mac.is_some() && !root,
        ethernet,
        up: true,
        ipv4,
    };
    let v4 = |a, b, c, d| u32::from(Ipv4Addr::new(a, b, c, d));
    let mut b = FakeBackend::new();
    b.routes.rules = vec![
        (v4(198, 18, 0, 2), v4(198, 18, 0, 2), Some(lo0.clone())),
        (v4(198, 18, 0, 0), v4(198, 18, 0, 3), Some(peer)),
        (v4(127, 0, 0, 0), v4(127, 255, 255, 255), Some(lo0.clone())),
        (v4(192, 0, 2, 10), v4(192, 0, 2, 10), Some(lo0)),
        (v4(192, 0, 2, 0), v4(192, 0, 2, 255), Some(en0(None))),
        (0, u32::MAX, Some(en0(Some(GW)))),
    ];
    b.routes.defaults = vec![en0(Some(GW))];
    b.ifaces = vec![
        nic("lo0", 1, None, false, vec![Ipv4Addr::LOCALHOST]),
        nic(
            "en0",
            14,
            Some([0x02, 0xbb, 0, 0, 0, 14]),
            true,
            vec![Ipv4Addr::new(192, 0, 2, 10)],
        ),
        nic("feth4201", 35, Some(M1_SCANNER_MAC), true, vec![]),
        nic(
            "feth4202",
            36,
            Some(M1_PEER_MAC),
            true,
            vec![Ipv4Addr::new(198, 18, 0, 2)],
        ),
    ];
    b.neighbors.clear();
    b.panic_on_open = true;
    b
}

/// argv строки `MACOS_CASES` (rmasscan-lab `autodetect_verify.rs`, `CaseSpec::argv`): цель 198.18.0.2, `-p` строк
/// `MACOS`/`MACOS_REFUSAL`, флаги строки и `COMMON_ARGS`.
fn m1_argv(flags: &[&'static str]) -> Vec<&'static str> {
    ["198.18.0.2", "-p8000-8007,9000-9003"]
        .into_iter()
        .chain(flags.iter().copied())
        .chain(["--seed", "1", "--rate", "100", "--wait", "3"])
        .collect()
}

/// Отказ строки m05_user_no_adapter дословно: `[-] FAIL: ` и `LOCAL_TARGET` (его же ждёт
/// `preflight_expectation("m05_user_no_adapter")`, `Preflight::Refusal`), затем `LOCAL_HINT`.
const M05_REFUSAL: &str = "[-] FAIL: 198.18.0.2 is an address of this host (route via lo0)\n    \
                           [hint] try \"--interface ethX\" and \"--router-ip 192.0.2.1\"";

/// m05_user_no_adapter: его preflight (argv строки и `--offline` в конце, `autodetect_suite::preflight_argv`) и живой
/// argv печатают ровно отказ и подсказку строки, без единой строки `[+]`, после одного lookup и без открытия; под root
/// тоже. В окне на b7e397a этот preflight напечатал `[-] FAIL: MAC of interface "feth4202" is os-masked (…)`: маршрут
/// подсети через feth4202 не считался адресом хоста (герметичный RED/GREEN этого в `route_parse_tests::mac_m1_*`).
#[test]
fn mac_m1_m05_preflight_and_live_run_print_the_local_target_refusal() {
    for root in [false, true] {
        for argv in [with(&m1_argv(&[]), &["--offline"]), m1_argv(&[])] {
            let b = mac_m1(root);
            let (r, out, log) = cli(&b, &argv);
            let e = r.unwrap_err();
            assert_eq!(e, M05_REFUSAL, "root {root}, {argv:?}");
            assert_eq!(rmasscan_cli::error_text(&e), e, "C form, no wrapper");
            assert!(out.is_empty() && log.is_empty(), "{log}");
            assert_eq!(b.lookups(), [Ipv4Addr::new(198, 18, 0, 2)]);
            assert!(b.attempts().is_empty(), "nothing is opened");
        }
    }
}

/// Остальные строки `MACOS_CASES` и `MACOS_ROOT_CASES` с их argv: у случаев с `--adapter` и `--router-ip`/`--router-mac`
/// маршруты не ищутся вовсе. Обнаружение печатает строки `[+]` по `detection`, `router_ip`, `router_mac` строки (строку
/// ARP `router-mac … (arp: …)` печатает живой путь после резолвера), отказы m01 и m06 это `fail` и `hints` строк,
/// `--iflist` (m07, m11) показывает строку стенда feth4201 с MAC `masked` без root и настоящим MAC под root. Ничего не
/// открывается.
#[test]
fn mac_m1_adapter_cases_skip_the_route_lookup_and_print_the_table_lines() {
    let scanner = ["--adapter", "feth4201", "--adapter-ip", "198.18.0.1"];
    let mac = ["--adapter-mac", "02-ac-00-00-00-01"];
    let router = ["--router-ip", "198.18.0.2"];
    let given_lines = "[+] interface = feth4201 (given)\n\
                       [+] source-mac = 02-ac-00-00-00-01 (given)\n\
                       [+] source-ip = 198.18.0.1 (given)\n";
    for (tag, root, flags, lines) in [
        (
            "m02_user_explicit",
            false,
            [&scanner[..], &mac, &router].concat(),
            format!("{given_lines}[+] router-ip = 198.18.0.2 (given)\n"),
        ),
        (
            "m03_user_router_mac",
            false,
            [
                &scanner[..],
                &mac,
                &router,
                &["--router-mac", "02-ac-00-00-00-02"],
            ]
            .concat(),
            format!(
                "{given_lines}[+] router-ip = 198.18.0.2 (given)\n\
                 [+] router-mac = 02-ac-00-00-00-02 (given)\n"
            ),
        ),
        (
            "m04_user_arp_timeout",
            false,
            [&scanner[..], &mac, &["--router-ip", "198.18.0.3"]].concat(),
            format!("{given_lines}[+] router-ip = 198.18.0.3 (given)\n"),
        ),
        (
            "m10_root_auto_mac",
            true,
            [&scanner[..], &router].concat(),
            "[+] interface = feth4201 (given)\n\
             [+] source-mac = 02-ac-00-00-00-01 (detected)\n\
             [+] source-ip = 198.18.0.1 (given)\n\
             [+] router-ip = 198.18.0.2 (given)\n"
                .to_string(),
        ),
    ] {
        let b = mac_m1(root);
        let p = live::prepare(&config(&m1_argv(&flags)), SeedPolicy::Required, &b, false)
            .unwrap_or_else(|e| panic!("{tag}: {e}"));
        let mut log = Vec::new();
        live::print_detection(&p, &mut log).unwrap();
        assert_eq!(String::from_utf8(log).unwrap(), lines, "{tag}");
        assert!(b.lookups().is_empty(), "{tag}: no route lookup");
        assert!(b.attempts().is_empty(), "{tag}: nothing is opened");
    }

    for (tag, flags, refusal) in [
        (
            "m01_user_masked",
            [&scanner[..], &router].concat(),
            "[-] FAIL: MAC of interface \"feth4201\" is os-masked (Darwin hides MACs from unprivileged processes)\n    \
             [hint] run as root, or try something like \"--source-mac 00-11-22-33-44-55\"",
        ),
        (
            "m06_user_no_ip",
            [&["--adapter", "feth4201"][..], &mac, &router].concat(),
            "[-] FAIL: failed to detect IP of interface \"feth4201\"\n    \
             [hint] did you spell the name correctly?\n    \
             [hint] if it has no IP address, manually set with something like \"--source-ip 198.51.100.17\"",
        ),
    ] {
        let b = mac_m1(false);
        let (r, out, log) = cli(&b, &m1_argv(&flags));
        assert_eq!(r.unwrap_err(), refusal, "{tag}");
        assert!(out.is_empty() && log.is_empty(), "{tag}: {log}");
        assert!(b.lookups().is_empty(), "{tag}: no route lookup");
    }

    for (tag, root, macs) in [
        ("m07_user_iflist", false, ["masked"; 3]),
        (
            "m11_root_iflist",
            true,
            [
                "02-bb-00-00-00-0e",
                "02-ac-00-00-00-01",
                "02-ac-00-00-00-02",
            ],
        ),
    ] {
        let b = mac_m1(root);
        let (r, out, log) = cli(&b, &["--iflist"]);
        r.unwrap();
        assert_eq!(
            out,
            format!(
                "lo0 index=1 mac=none ipv4=127.0.0.1 up other\n\
                 en0 index=14 mac={} ipv4=192.0.2.10 up ethernet\n\
                 feth4201 index=35 mac={} ipv4=- up ethernet\n\
                 feth4202 index=36 mac={} ipv4=198.18.0.2 up ethernet\n\
                 default via 192.0.2.1 dev en0\n",
                macs[0], macs[1], macs[2]
            ),
            "{tag}"
        );
        assert!(log.is_empty() && b.lookups().is_empty(), "{tag}: {log}");
    }
}

/// Открытые порты в порядке ответов (= порядок SYN адаптера скана).
fn open_in_reply_order(b: &FakeBackend) -> Vec<(Ipv4Addr, u16)> {
    b.opened()[1]
        .adapter
        .sent_frames()
        .iter()
        .map(|f| syn_dst(f))
        .filter(|d| OPEN.contains(d))
        .collect()
}

fn list_line((ip, port): (Ipv4Addr, u16)) -> String {
    format!("open tcp {port} {ip} {UNIX_TIME}\n")
}

/// `-oL FILE`: записи с временем стенки в файл, stdout молчит (Р3), строки `[+]` те же.
#[test]
fn live_scan_writes_list_file_and_keeps_stdout_silent() {
    let scratch = Scratch::new();
    let path = scratch.path("scan.list");
    let b = FakeBackend::new();
    let (r, out, log) = cli(&b, &with(&LIVE, &["-oL", path.to_str().unwrap()]));
    r.unwrap();
    assert_eq!(out, "", "stdout is silent with a file format");
    let open = open_in_reply_order(&b);
    assert_eq!(open.len(), 2);
    let body: String = open.into_iter().map(list_line).collect();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("#masscan\n{body}# end\n")
    );
    assert_eq!(
        plus_lines(&log).last().copied(),
        Some("[+] finished: Completed, sent 4, replies 4, open 2"),
        "{log}"
    );
}

/// Review Focus 2: `--interactive -oL -` пишет обе ветки в один stdout в порядке C (`output.c:766–876`): строка
/// `Discovered`, затем ленивый заголовок у первой записи, затем запись; подвал в конце.
#[test]
fn interactive_and_list_to_stdout_interleave_like_c() {
    let b = FakeBackend::new();
    let (r, out, _) = cli(&b, &with(&LIVE, &["--interactive", "-oL", "-"]));
    r.unwrap();
    let open = open_in_reply_order(&b);
    let mut want = String::new();
    for (i, d) in open.iter().enumerate() {
        want.push_str(&discovered_line(d.0, d.1));
        if i == 0 {
            want.push_str("#masscan\n");
        }
        want.push_str(&list_line(*d));
    }
    want.push_str("# end\n");
    assert_eq!(out, want);
}

/// `-oG -`: заголовок называет порты конфигурации (слитые, как `massip_optimize`), имена сервисов из бэкенда.
#[test]
fn live_grepable_names_the_scanned_ports_and_backend_services() {
    let b = FakeBackend::new();
    let (r, out, _) = cli(&b, &with(&LIVE, &["-oG", "-"]));
    r.unwrap();
    let mut want = String::from(
        "# Masscan 1.3.9-integration scan initiated Fri Jan 15 11:25:45 2027\n\
         # Ports scanned: TCP(2;80-81) UDP(0;) SCTP(0;) PROTOCOLS(0;)\n",
    );
    for (ip, port) in open_in_reply_order(&b) {
        let name = if port == 80 { "http" } else { "unknown" };
        want.push_str(&format!(
            "Timestamp: {UNIX_TIME}\tHost: {ip} ()\tPorts: {port}/open/tcp//{name}//\n"
        ));
    }
    want.push_str("# Masscan done at Fri Jan 15 11:25:45 2027\n");
    assert_eq!(out, want);
}

/// Р8: файл не открылся (каталог вместо файла) - exit 1, текст C без обёртки, ни одного кадра и ни одного ARP.
#[test]
fn open_failure_sends_no_frame() {
    let scratch = Scratch::new();
    let dir = scratch.dir();
    for (extra, word) in [
        (&[][..], "writing"),
        (&["--append-output"][..], "appending"),
    ] {
        let b = FakeBackend::new();
        let mut args = with(&LIVE, extra);
        args.extend(["-oL", dir.to_str().unwrap()]);
        let (r, out, _) = cli(&b, &args);
        let e = r.unwrap_err();
        let mut lines = e.lines();
        assert_eq!(
            lines.next(),
            Some(format!("out: could not open file for {word}").as_str())
        );
        assert!(
            lines
                .next()
                .unwrap()
                .starts_with(&format!("{}: ", dir.display())),
            "{e}"
        );
        assert_eq!(rmasscan_cli::error_text(&e), e, "C form, no wrapper");
        assert!(out.is_empty());
        assert!(b.attempts().is_empty(), "no adapter was opened");
        assert!(b.tx_journal().is_empty(), "no frame, not even ARP");
    }
}

/// main.c:1720-1742: цели и порты проверяются до `main_scan` и до `output_create` (output.c:799-803), поэтому
/// отказ по целям/портам идёт раньше отказа «нет файла вывода».
#[test]
fn target_and_port_refusal_precedes_the_output_file_refusal() {
    for (args, want) in [
        (
            &["--output-format", "json"][..],
            "target IP address list empty",
        ),
        (
            &["-p80", "--output-format", "json"][..],
            "target IP address list empty",
        ),
        (
            &["198.51.100.1", "--output-format", "json"][..],
            "no ports were specified",
        ),
    ] {
        let b = FakeBackend::new();
        let (r, out, log) = cli(&b, args);
        let e = r.unwrap_err();
        assert!(!e.contains("no output file"), "{args:?}: {e}");
        assert!(e.contains(want), "{args:?}: {e}");
        assert!(out.is_empty() && log.is_empty(), "{args:?}: {log}");
        assert!(b.attempts().is_empty() && b.tx_journal().is_empty());
    }
}

/// Решение 2 контроллера: реальный формат без имени файла отклоняется до обнаружения ARP и кадров.
#[test]
fn file_format_without_a_filename_sends_no_frame() {
    let b = FakeBackend::new();
    let (r, out, log) = cli(&b, &with(&LIVE, &["--output-format", "json"]));
    assert_eq!(
        r.unwrap_err(),
        "[-] ERR: no output file, use `--output-filename <filename>` to set one\n\
         [-] ERR: for `stdout`, use `--output-filename -`"
    );
    assert!(out.is_empty() && log.is_empty(), "{log}");
    assert!(b.attempts().is_empty() && b.tx_journal().is_empty());
    // `none` скан идёт, но ничего не пишет: ни stdout, ни файла.
    let b = FakeBackend::new();
    let (r, out, _) = cli(&b, &with(&LIVE, &["--output-format", "none"]));
    r.unwrap();
    assert_eq!(out, "");
    assert_eq!(b.opened()[1].adapter.sent_count(), 4);
}

/// stdout, который отказывает (не EPIPE) после `limit` байт.
struct FailAfter {
    bytes: Vec<u8>,
    limit: usize,
}

impl std::io::Write for FailAfter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len() + b.len() > self.limit {
            return Err(std::io::Error::other("No space left on device"));
        }
        self.bytes.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Review Focus 1: ошибка записи посреди скана останавливает engine, `[+] finished:` с `sent` печатается, итог `Err`
/// (exit 1); подвал после ошибки не пишется.
#[test]
fn write_error_mid_scan_stops_and_fails() {
    let b = FakeBackend::new();
    let header_and_one = "#masscan\n".len() + list_line((T1, 80)).len();
    let mut out = FailAfter {
        bytes: Vec::new(),
        limit: header_and_one,
    };
    let mut log = Vec::new();
    let r = rmasscan_cli::run(&parse(&with(&LIVE, &["-oL", "-"])), &b, &mut out, &mut log);
    let log = String::from_utf8(log).unwrap();
    let e = r.unwrap_err();
    assert_eq!(e, "write failed: No space left on device");
    let first = open_in_reply_order(&b)[0];
    assert_eq!(
        String::from_utf8(out.bytes).unwrap(),
        format!("#masscan\n{}", list_line(first))
    );
    let fin = plus_lines(&log).last().copied().unwrap_or_default();
    assert!(fin.starts_with("[+] finished: "), "{log}");
    assert!(
        fin.contains(&format!("sent {}", b.opened()[1].adapter.sent_count())),
        "{log}"
    );
}

/// `--readscan` не открывает адаптер и не читает таблицы ОС.
#[test]
fn readscan_opens_nothing_and_reads_no_tables() {
    let mut b = FakeBackend::new();
    b.tables_panic = true;
    b.panic_on_open = true;
    let scratch = Scratch::new();
    let missing = scratch.path("missing.scan");
    let (r, out, log) = cli(&b, &["--readscan", missing.to_str().unwrap(), "-oL", "-"]);
    assert_eq!(rmasscan_cli::error_text(&r.unwrap_err()), "");
    assert!(out.is_empty());
    assert!(log.contains("[-] FAIL: --readscan\n"), "{log}");
    assert!(b.lookups().is_empty() && b.attempts().is_empty());
}

/// Все `.rs` под `dir`, рекурсивно, в стабильном порядке.
fn rs_files_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            found.extend(rs_files_under(&p));
        } else if p.extension().is_some_and(|e| e == "rs") {
            found.push(p);
        }
    }
    found
}

/// Исходник вне `main.rs` и `os_backend.rs` не знает `OsBackend`: ни модуля, ни открытия адаптеров, ни таблиц ОС.
fn assert_no_os_backend_reach(name: &str, src: &str) {
    assert!(!src.contains("mod os_backend"), "{name}");
    assert!(
        !src.contains("open_explicit("),
        "{name} must not open adapters"
    );
    assert!(!src.contains("os_route_table("), "{name}");
    assert!(!src.contains("os_interfaces("), "{name}");
}

/// `OsBackend` недостижим из тестов: модуль и `fn main` бинарника под `cfg(not(test))`, библиотека его не знает,
/// а `open_explicit` зовёт только `os_backend.rs` (compile-time отсутствие экспорта проверяет doctest
/// `compile_fail` в `lib.rs`).
#[test]
fn os_backend_is_absent_under_test() {
    let main = include_str!("../src/main.rs");
    assert!(main.contains("#[cfg(not(test))]\nmod os_backend;"));
    assert!(main.contains("#[cfg(not(test))]\nfn main("));
    assert!(!main.contains("#[test]"), "unit tests live in the library");
    // Каждый `.rs` под `src/` (кроме `main.rs` и `os_backend.rs`, у которых свои утверждения): новый модуль
    // попадает под проверку сам, без правки списка.
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = rs_files_under(&src_dir);
    assert!(
        files.len() >= 10,
        "the walk must see the whole tree: {files:?}"
    );
    for path in files {
        let name = path.strip_prefix(&src_dir).unwrap().to_string_lossy();
        if name == "main.rs" || name == "os_backend.rs" {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap();
        assert_no_os_backend_reach(&name, &src);
    }
    let os = include_str!("../src/os_backend.rs");
    assert!(os.contains("open_explicit("));
}

const LIVE5: [&str; 4] = ["198.51.100.1-198.51.100.2", "-p80,81", "--wait", "5"];

/// Фрагменты статуса (`\r`-терминированные) из stderr.
fn status_fragments(log: &str) -> Vec<&str> {
    log.split(['\r', '\n'])
        .filter(|l| l.starts_with("rate:") || l.starts_with("{\"state\""))
        .collect()
}

#[test]
fn status_lines_on_stderr_by_default() {
    let b = FakeBackend::new();
    // Каждый sleep ManualClock двигает время; ждём достаточно долго, чтобы прошли отсчёты по 250 мс.
    let (r, _, log) = cli(&b, &with(&LIVE5, &[]));
    r.unwrap();
    let frags = status_fragments(&log);
    assert!(!frags.is_empty(), "no status line: {log:?}");
    assert!(frags.iter().all(|f| f.contains("-kpps")), "{frags:?}");
    // Последний фрагмент затёрт 77 пробелами, после него отдельная строка [+] finished.
    let last = log.lines().last().unwrap();
    assert!(
        last.starts_with(&" ".repeat(77)) || last.contains(&format!("{}\r", " ".repeat(77))),
        "{last:?}"
    );
    assert!(
        normalize_stderr_line(last).starts_with("[+] finished: "),
        "{last:?}"
    );
}

#[test]
fn nostatus_prints_elapsed_to_stdout() {
    let b = FakeBackend::new();
    let (r, out, log) = cli(&b, &with(&LIVE, &["--nostatus"]));
    r.unwrap();
    assert!(!log.contains("rate:") && !log.contains('\r'), "{log:?}");
    let last = out.lines().last().unwrap();
    let ms = last.strip_suffix(" milliseconds elapsed").unwrap();
    assert!(ms.parse::<u64>().is_ok(), "{out:?}");
    assert!(out.ends_with(" milliseconds elapsed\n"));
}

/// `-oJ - --nostatus`: stdout это файл вывода. C закрывает его в `close_rotate` (`fp = stdout` из `output.c:216`,
/// `fclose` на `output.c:268`) до `printf` времени скана (`main.c:1551`), поэтому в stdout только документ JSON. С
/// настоящим файлом строка времени остаётся в stdout.
#[test]
fn nostatus_with_stdout_format_keeps_stdout_pure() {
    let b = FakeBackend::new();
    let (r, out, log) = cli(&b, &with(&LIVE, &["-oJ", "-", "--nostatus"]));
    r.unwrap();
    assert!(!log.contains("rate:") && !log.contains('\r'), "{log:?}");
    let open = open_replies(&b);
    assert_eq!(open.len(), 2);
    assert_eq!(out, json_file(&open));

    let scratch = Scratch::new();
    let path = scratch.path("nostatus.json");
    let b = FakeBackend::new();
    let (r, out, _) = cli(
        &b,
        &with(&LIVE, &["-oJ", path.to_str().unwrap(), "--nostatus"]),
    );
    r.unwrap();
    let ms = out.strip_suffix(" milliseconds elapsed\n").unwrap();
    assert!(ms.parse::<u64>().is_ok(), "{out:?}");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        json_file(&open_replies(&b))
    );
}

#[test]
fn ndjson_status_lines() {
    let b = FakeBackend::new();
    let (r, out, log) = cli(&b, &with(&LIVE5, &["--ndjson-status"]));
    r.unwrap();
    let frags = status_fragments(&log);
    assert!(!frags.is_empty(), "no ndjson status: {log:?}");
    assert!(
        frags
            .iter()
            .all(|f| f.ends_with("}}") || f.ends_with("}}}")),
        "{frags:?}"
    );
    assert!(!out.contains("milliseconds elapsed"), "{out:?}");
    assert!(!log.contains("rate:"), "{log:?}");
}

// ---------- Ctrl-C (Р18) ----------

/// Ожидание `--wait 3600` идёт по `ManualClock` (72 000 пустых `recv`): скан не успевает закончиться сам раньше, чем
/// цикл событий увидит нажатие, поэтому итог `Stopped` детерминирован.
const LONG_WAIT: [&str; 4] = ["198.51.100.1-198.51.100.2", "-p80,81", "--wait", "3600"];

/// Короткое окно `--wait` (20 с часов = 400 пустых `recv`) для тестов паузы: нажатие приходит из потока TX, пока передача
/// ещё идёт (`PressInTx`), и скан после паузы быстро заканчивается.
const SHORT_WAIT: [&str; 4] = ["198.51.100.1-198.51.100.2", "-p80,81", "--wait", "20"];

/// Строка C первого Ctrl-C (`main.c:1136–1139`): текст, 44 пробела, `\n`.
fn waiting_line() -> String {
    format!("waiting several seconds to exit...{}\n", " ".repeat(44))
}

/// Конвейер вывода, который «нажимает Ctrl-C» на первом открытом ответе: счётчик fake поднимается посреди первой
/// пачки `Results`, цикл событий увидит его на следующей итерации. Запоминает каждый переданный ответ.
struct PressOnFirstOpen<'a> {
    pipeline: Pipeline<'a>,
    presses: Arc<AtomicU32>,
    reported: Vec<Reply>,
}

impl Sink for PressOnFirstOpen<'_> {
    fn open(&mut self) -> Result<(), String> {
        self.pipeline.open()
    }
    fn report(&mut self, reply: &Reply) -> Result<(), String> {
        self.pipeline.report(reply)?;
        if reply.status == PortStatus::Open {
            self.presses.fetch_max(1, Ordering::SeqCst);
        }
        self.reported.push(*reply);
        Ok(())
    }
    fn finish(&mut self) -> Result<(), String> {
        self.pipeline.finish()
    }
}

/// Ответы `open` фиктивной сети в порядке SYN адаптера скана, как их видит приёмник (`reply_to_syn`: TTL 64).
fn open_replies(b: &FakeBackend) -> Vec<Reply> {
    open_in_reply_order(b)
        .into_iter()
        .map(|(ip, port)| Reply {
            remote_ip: u32::from(ip),
            remote_port: port,
            local_ip: u32::from(MY_IP),
            local_port: TIME_PORT,
            status: PortStatus::Open,
            tcp_flags: 0x12,
            ttl: 64,
        })
        .collect()
}

/// `-oJ` с записями `open` (время стенки fake): `[`, записи через `,`, `]`.
fn json_file(open: &[Reply]) -> String {
    let records: Vec<String> = open
        .iter()
        .map(|r| {
            format!(
                "{{   \"ip\": \"{}\",   \"timestamp\": \"{UNIX_TIME}\", \"ports\": [ {{\"port\": {}, \"proto\": \
                 \"tcp\", \"status\": \"open\", \"reason\": \"syn-ack\", \"ttl\": {}}} ] }}\n",
                Ipv4Addr::from(r.remote_ip),
                r.remote_port,
                r.ttl
            )
        })
        .collect();
    format!("[\n{}]\n", records.join(",\n"))
}

/// `-oX` с записями `open`: заголовок, записи и подвал `runstats` (`2027-01-15 11:25:45` это `UNIX_TIME` в UTC).
fn xml_file(open: &[Reply]) -> String {
    let mut s = format!(
        "<?xml version=\"1.0\"?>\r\n<!-- masscan v1.0 scan -->\r\n<nmaprun scanner=\"masscan\" \
         start=\"{UNIX_TIME}\" version=\"1.0-BETA\"  xmloutputversion=\"1.03\">\r\n\
         <scaninfo type=\"syn\" protocol=\"tcp\" />\r\n"
    );
    for r in open {
        s.push_str(&format!(
            "<host endtime=\"{UNIX_TIME}\"><address addr=\"{}\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" \
             portid=\"{}\"><state state=\"open\" reason=\"syn-ack\" reason_ttl=\"{}\"/></port></ports></host>\r\n",
            Ipv4Addr::from(r.remote_ip),
            r.remote_port,
            r.ttl
        ));
    }
    let n = open.len();
    s.push_str(&format!(
        "<runstats>\r\n<finished time=\"{UNIX_TIME}\" timestr=\"2027-01-15 11:25:45\" elapsed=\"0\" />\r\n\
         <hosts up=\"{n}\" down=\"0\" total=\"{n}\" />\r\n</runstats>\r\n</nmaprun>\r\n"
    ));
    s
}

/// Р18, Р4: первое Ctrl-C посреди передачи печатает строку C и ставит engine на паузу; приёмник дописывает записи и
/// подвал (`-oJ` закрыт `]\n`, `-oX` закрыт `</nmaprun>\r\n`), `[+] finished: Paused`, `Ok` (exit 0). Ни один принятый
/// ответ не теряется: в файле ровно открытые ответы, переданные приёмнику, включая пачки после остановки.
#[test]
fn first_interrupt_pauses_and_finishes_outputs() {
    for format in ["-oJ", "-oX"] {
        let scratch = Scratch::new();
        let path = scratch.path(&format!("interrupt{format}"));
        let mut b = FakeBackend::new();
        b.press_in_tx = Some(PressInTx {
            at: 2,
            late_first: false,
        });
        let parsed = parse(&with(&SHORT_WAIT, &[format, path.to_str().unwrap()]));
        let (mut stdout, mut log) = (Vec::new(), Vec::new());
        let (r, reported) = {
            let env = OutputEnv {
                wall: &b,
                services: ServiceNames::empty(),
                tcp_ports: Vec::new(),
                scan_started: None,
            };
            let mut sink = PressOnFirstOpen {
                pipeline: Pipeline::new(parsed.output_options().unwrap(), &mut stdout, env),
                presses: Arc::new(AtomicU32::new(0)),
                reported: Vec::new(),
            };
            let r = live::run_live(&parsed.to_config().unwrap(), &b, &mut sink, &mut log);
            (r, sink.reported)
        };
        let log = String::from_utf8(log).unwrap();
        assert_eq!(
            r.unwrap().reason,
            Reason::Paused,
            "{format}: {:?}",
            plus_lines(&log)
        );
        assert_eq!(b.presses(), 1, "one press");
        assert_eq!(
            log.matches(&waiting_line()).count(),
            1,
            "{:?}",
            plus_lines(&log)
        );
        let open: Vec<Reply> = reported
            .iter()
            .copied()
            .filter(|r| r.status == PortStatus::Open)
            .collect();
        assert!(
            !open.is_empty(),
            "the first two probes include an open reply"
        );
        let sent = b.opened()[1].adapter.sent_count();
        let finished = format!(
            "[+] finished: Paused, sent {sent}, replies {}, open {}",
            reported.len(),
            open.len()
        );
        assert_eq!(plus_lines(&log).last().copied(), Some(finished.as_str()));
        assert!(log.find(&waiting_line()).unwrap() < log.find("[+] finished: ").unwrap());
        assert!(stdout.is_empty(), "stdout is silent with a file format");
        let want = if format == "-oJ" {
            json_file(&open)
        } else {
            xml_file(&open)
        };
        assert_eq!(std::fs::read_to_string(&path).unwrap(), want, "{format}");
    }
}

/// Review Focus 5, Р18 (`main.c:1131-1154`): Ctrl-C во время ARP (ответ уже пришёл) до первой записи: файл остаётся
/// 0 байт, без заголовка и подвала, `[+] finished: Stopped, sent 0, replies 0, open 0`, exit 0, адаптер скана не
/// открывается и ни один SYN не уходит. Обработчик ставится ровно один раз, до открытия адаптера ARP.
#[test]
fn interrupt_without_records_leaves_empty_file() {
    for format in ["-oJ", "-oX"] {
        let scratch = Scratch::new();
        let path = scratch.path(&format!("interrupt-empty{format}"));
        let mut b = FakeBackend::new();
        b.press_during_arp = true;
        b.silent_targets = true;
        let (r, out, log) = cli(&b, &with(&LONG_WAIT, &[format, path.to_str().unwrap()]));
        r.unwrap();
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(std::fs::read(&path).unwrap(), b"", "{format}");
        assert_eq!(b.presses(), 1, "one press");
        assert_eq!(
            log.matches(&waiting_line()).count(),
            1,
            "{:?}",
            plus_lines(&log)
        );
        assert_eq!(
            plus_lines(&log).last().copied(),
            Some("[+] finished: Stopped, sent 0, replies 0, open 0")
        );
        assert_eq!(b.opened().len(), 1, "only the ARP adapter is opened");
        assert!(
            b.tx.lock().unwrap().iter().all(|f| is_arp(f)),
            "no SYN leaves the host"
        );
        assert_eq!(
            b.opened()[0].polls_before,
            1,
            "the handler is installed once, before the ARP adapter opens"
        );
    }
}

/// Р18: Ctrl-C при молчащем роутере (ARP без ответа): сразу `Ok` и `Stopped`, а не отказ `ARP timed-out` через
/// 10 с; адаптер скана не открывается, SYN нет, файл 0 байт.
#[test]
fn interrupt_during_unanswered_arp_stops_instead_of_timing_out() {
    let scratch = Scratch::new();
    let path = scratch.path("interrupt-silent-arp.json");
    let mut b = FakeBackend::new();
    b.neighbors.clear();
    b.press_during_arp = true;
    let t0 = b.clock.now_micros();
    let (r, out, log) = cli(&b, &with(&LONG_WAIT, &["-oJ", path.to_str().unwrap()]));
    r.unwrap_or_else(|e| panic!("{e}\n{log}"));
    assert!(out.is_empty(), "{out:?}");
    assert!(!log.contains("timed-out"), "{log}");
    assert_eq!(std::fs::read(&path).unwrap(), b"");
    assert_eq!(
        plus_lines(&log).last().copied(),
        Some("[+] finished: Stopped, sent 0, replies 0, open 0")
    );
    assert_eq!(log.matches(&waiting_line()).count(), 1, "{log:?}");
    assert_eq!(b.opened().len(), 1, "only the ARP adapter is opened");
    assert!(b.tx.lock().unwrap().iter().all(|f| is_arp(f)));
    assert!(
        b.clock.now_micros() - t0 < 10_000_000,
        "the press ends ARP before the 10 s timeout"
    );
}

/// Р18: Ctrl-C до ARP (счётчик уже ненулевой при старте): ни адаптера, ни кадра.
#[test]
fn interrupt_before_arp_opens_no_adapter() {
    let b = FakeBackend::new();
    b.presses.store(1, Ordering::SeqCst);
    let (r, out, log) = live_run(&b, &LIVE);
    assert_eq!(r.unwrap().reason, Reason::Stopped);
    assert!(out.is_empty() || !out.contains("Discovered"), "{out:?}");
    assert!(b.opened().is_empty(), "no adapter is opened");
    assert!(b.tx.lock().unwrap().is_empty());
    assert_eq!(
        plus_lines(&log).last().copied(),
        Some("[+] finished: Stopped, sent 0, replies 0, open 0")
    );
}

/// Ctrl-C перехватывает только живой скан: `--readscan`, `-sL`, `--echo`, `--offline` и `--iflist` не ставят
/// обработчик (поведение ОС по умолчанию), `interrupts()` у них не зовётся ни разу.
#[test]
fn only_a_live_scan_traps_ctrl_c() {
    let scratch = Scratch::new();
    let path = scratch.path("trap.scan");
    let file = path.to_str().unwrap();
    let b = FakeBackend::new();
    let (r, _, _) = cli(&b, &with(&LIVE, &["-oB", file]));
    r.unwrap();
    assert_eq!(b.opened()[0].polls_before, 1, "installed before ARP");
    assert!(b.polls() > 1, "the event loop polls the counter");
    for args in [
        &["--readscan", file, "-oL", "-"][..],
        &["-sL", "198.51.100.1", "-p80", "--seed", "1"][..],
        &["--echo", "198.51.100.1", "-p80", "--seed", "1"][..],
        &TRACE[..],
        &["--iflist"][..],
    ] {
        let b = FakeBackend::new();
        let (r, _, log) = cli(&b, args);
        assert!(r.is_ok(), "{args:?}: {r:?} {log}");
        assert_eq!(b.polls(), 0, "{args:?}");
    }
}

/// Где ломается stderr (`BrokenPipe`, как EPIPE от умершего читателя `2>&1 | tee`).
#[derive(Clone, Copy)]
enum Breaks {
    /// Каждая запись после строки первого Ctrl-C.
    AfterWaitingLine,
    /// Только затирание строки статуса в конце (`status_finish`: 77 пробелов и `\r`).
    OnStatusFinish,
}

struct BrokenStderr {
    bytes: Vec<u8>,
    breaks: Breaks,
}

impl BrokenStderr {
    fn new(breaks: Breaks) -> Self {
        BrokenStderr {
            bytes: Vec::new(),
            breaks,
        }
    }
}

impl std::io::Write for BrokenStderr {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let broken = match self.breaks {
            Breaks::AfterWaitingLine => {
                String::from_utf8_lossy(&self.bytes).contains(&waiting_line())
            }
            Breaks::OnStatusFinish => b == format!("{}\r", " ".repeat(77)).as_bytes(),
        };
        if broken {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Broken pipe",
            ));
        }
        self.bytes.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Сбой stderr после первого Ctrl-C (`… -oJ out.json 2>&1 | tee scan.log`, SIGINT убил и `tee`): запись в `log`
/// best-effort (util-logger.c:25-31, main.c:1136-1140 игнорируют ошибки stderr), приёмник дописывает записи и подвал
/// `]\n`, итог `Ok` (exit 0). Строка `[+] finished` в мёртвый stderr не попадает.
#[test]
fn broken_stderr_after_the_first_press_still_finishes_the_file() {
    let scratch = Scratch::new();
    let path = scratch.path("interrupt-broken-stderr.json");
    let mut b = FakeBackend::new();
    b.press_in_tx = Some(PressInTx {
        at: 2,
        late_first: false,
    });
    let parsed = parse(&with(&SHORT_WAIT, &["-oJ", path.to_str().unwrap()]));
    let mut stdout = Vec::new();
    let mut log = BrokenStderr::new(Breaks::AfterWaitingLine);
    let (r, reported) = {
        let env = OutputEnv {
            wall: &b,
            services: ServiceNames::empty(),
            tcp_ports: Vec::new(),
            scan_started: None,
        };
        let mut sink = PressOnFirstOpen {
            pipeline: Pipeline::new(parsed.output_options().unwrap(), &mut stdout, env),
            presses: Arc::new(AtomicU32::new(0)),
            reported: Vec::new(),
        };
        let r = live::run_live(&parsed.to_config().unwrap(), &b, &mut sink, &mut log);
        (r, sink.reported)
    };
    r.unwrap();
    let text = String::from_utf8(log.bytes).unwrap();
    assert_eq!(
        text.matches(&waiting_line()).count(),
        1,
        "{:?}",
        plus_lines(&text)
    );
    assert!(!text.contains("[+] finished"), "{:?}", plus_lines(&text));
    let open: Vec<Reply> = reported
        .iter()
        .copied()
        .filter(|r| r.status == PortStatus::Open)
        .collect();
    assert!(!open.is_empty());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), json_file(&open));
}

/// Сбой только последней записи строки статуса (скан закончился сам; main-status.c:216-280 игнорирует ошибки
/// stderr): файл `-oJ` закрыт `]\n`, итог `Ok` (exit 0).
#[test]
fn status_finish_failure_still_finishes_the_file() {
    let scratch = Scratch::new();
    let path = scratch.path("status-finish-broken.json");
    let b = FakeBackend::new();
    let mut out = Vec::new();
    let mut log = BrokenStderr::new(Breaks::OnStatusFinish);
    let r = rmasscan_cli::run(
        &parse(&with(&LIVE, &["-oJ", path.to_str().unwrap()])),
        &b,
        &mut out,
        &mut log,
    );
    r.unwrap();
    let open = open_replies(&b);
    assert_eq!(open.len(), 2);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), json_file(&open));
    assert!(out.is_empty());
}

/// stderr, мёртвый с первого байта (EPIPE: читатель канала ушёл до первой записи): каждая запись и сброс отказывают.
/// Настоящий `2>&-` сюда не годится: стандартный `stderr` Rust глотает EBADF и ошибки не видит.
struct ClosedStderr;

impl std::io::Write for ClosedStderr {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(9))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::from_raw_os_error(9))
    }
}

/// Мёртвый с первого байта stderr (EPIPE) на живом скане (util-logger.c:25-31, main-status.c:216-280): все пробы отправлены, скан не остановлен
/// раньше времени, файл `-oJ` полон, итог `Ok`.
#[test]
fn closed_stderr_live_scan_completes_all_probes() {
    let scratch = Scratch::new();
    let path = scratch.path("closed-stderr.json");
    let b = FakeBackend::new();
    let mut out = Vec::new();
    let r = rmasscan_cli::run(
        &parse(&with(&LIVE, &["-oJ", path.to_str().unwrap()])),
        &b,
        &mut out,
        &mut ClosedStderr,
    );
    r.unwrap();
    assert_eq!(b.opened()[1].adapter.sent_count(), 4);
    let open = open_replies(&b);
    assert_eq!(open.len(), 2);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), json_file(&open));
    assert!(out.is_empty());
}

/// Мёртвый с первого байта stderr (EPIPE) на `--readscan` (in-binary.c:488-637 игнорирует ошибки stderr): записи дошли до stdout, итог `Ok`.
#[test]
fn closed_stderr_readscan_still_reports() {
    let scratch = Scratch::new();
    let path = scratch.path("closed-stderr.scan");
    let file = path.to_str().unwrap();
    let b = FakeBackend::new();
    let (r, _, _) = cli(&b, &with(&LIVE, &["-oB", file]));
    r.unwrap();
    let mut out = Vec::new();
    let r = rmasscan_cli::run(
        &parse(&["--readscan", file, "-oL", "-"]),
        &b,
        &mut out,
        &mut ClosedStderr,
    );
    r.unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(out.starts_with("#masscan\n"), "{out}");
    assert_eq!(out.matches("open tcp").count(), 2, "{out}");
}

// ---------- Пауза по Ctrl-C и фаза `--wait` (Р4, Задача 4) ----------

/// `--wait 300` (6000 пустых `recv`, не меньше 0,6 с реального времени): запись `paused.conf` обязана попасть в начало
/// окна ожидания, а не в его конец.
const PAUSE_WAIT: [&str; 4] = ["198.51.100.1-198.51.100.2", "-p80,81", "--wait", "300"];

/// Строка C `masscan_save_state` (`main-conf.c:398-399`): 70 пробелов, `\r`, текст.
fn saving_line() -> String {
    format!("{}\rsaving resume file to: paused.conf\n", " ".repeat(70))
}

/// Числа N всех фрагментов `waiting N-secs` в `stderr`.
fn waiting_secs(log: &str) -> Vec<i64> {
    log.match_indices("waiting ")
        .filter_map(|(i, _)| {
            let rest = &log[i + "waiting ".len()..];
            let (n, tail) = rest.split_once("-secs")?;
            let _ = tail;
            n.parse().ok()
        })
        .collect()
}

/// Запускает скан с `-oJ`, сценарием `PressInTx` и записью всех ответов приёмника; возвращает итог, `stderr`, файл
/// `-oJ` и ответы, переданные приёмнику.
fn pause_run(
    b: &FakeBackend,
    args: &[&str],
    path: &std::path::Path,
) -> (Result<Outcome, String>, String, String, Vec<Reply>) {
    let parsed = parse(&with(args, &["-oJ", path.to_str().unwrap()]));
    let (mut stdout, mut log) = (Vec::new(), Vec::new());
    let (r, reported) = {
        let env = OutputEnv {
            wall: b,
            services: ServiceNames::empty(),
            tcp_ports: Vec::new(),
            scan_started: None,
        };
        let mut sink = PressOnFirstOpen {
            pipeline: Pipeline::new(parsed.output_options().unwrap(), &mut stdout, env),
            presses: Arc::new(AtomicU32::new(0)),
            reported: Vec::new(),
        };
        let mode = parsed.status_mode();
        let r = live::run_live_with(&parsed.to_config().unwrap(), b, &mut sink, &mut log, mode)
            .map(|(o, _)| o);
        (r, sink.reported)
    };
    let file = std::fs::read_to_string(path).unwrap_or_default();
    (r, String::from_utf8(log).unwrap(), file, reported)
}

/// Р4 (`main.c:1447-1540`, `main-conf.c:395-416`): Ctrl-C после 2 из 4 SYN. Передача встаёт, `paused.conf` пишется с
/// нормализованным `resume-index = 2` и эффективным `seed`, приёмник ещё `--wait` секунд берёт поздний SYN-ACK на
/// первый SYN, строка статуса отсчитывает `waiting N-secs`, подвал `-oJ` закрыт, итог `Paused`, `Ok`.
#[test]
fn first_ctrl_c_pauses_saves_conf_waits_for_late_reply_and_closes_footer() {
    let scratch = Scratch::new();
    let path = scratch.path("paused.json");
    let mut b = FakeBackend::new();
    b.press_in_tx = Some(PressInTx {
        at: 2,
        late_first: true,
    });
    let (r, log, file, reported) = pause_run(&b, &PAUSE_WAIT, &path);
    let outcome = r.unwrap();
    assert_eq!(outcome.reason, Reason::Paused, "{:?}", plus_lines(&log));
    assert_eq!(b.presses(), 1, "one press");
    assert_eq!(log.matches(&waiting_line()).count(), 1, "{log:?}");
    assert_eq!(log.matches(&saving_line()).count(), 1, "{log:?}");
    assert!(log.find(&waiting_line()).unwrap() < log.find(&saving_line()).unwrap());
    // Review Focus 3: файл записан до первого тика отсчёта `waiting N-secs`.
    assert!(
        log.find(&saving_line()).unwrap() < log.find("-secs").unwrap(),
        "{log:?}"
    );
    // Ровно один файл, нормализованный индекс и эффективный seed (иначе возобновление пойдёт по другой перестановке).
    let writes = b.paused_writes();
    assert_eq!(writes.len(), 1, "paused.conf is written once");
    let conf = &writes[0].1;
    assert!(conf.contains("resume-index = 2\n"), "{conf}");
    assert!(conf.contains(&format!("seed = {ENTROPY}\n")), "{conf}");
    // C не пишет `wait` в `paused.conf` (`masscan_echo` его не знает), поэтому его нет и здесь.
    assert!(!conf.contains("wait ="), "{conf}");
    assert_eq!(outcome.progress.next_index, 2);
    // Поздний ответ на первый SYN дошёл до приёмника внутри окна ожидания и попал в файл.
    let first_syn = syn_dst(&b.opened()[1].adapter.sent_frames()[0]);
    assert!(
        reported.iter().any(|r| r.status == PortStatus::Open
            && (Ipv4Addr::from(r.remote_ip), r.remote_port) == first_syn),
        "late reply to {first_syn:?} missing: {reported:?}"
    );
    let open: Vec<Reply> = reported
        .iter()
        .copied()
        .filter(|r| r.status == PortStatus::Open)
        .collect();
    assert_eq!(file, json_file(&open));
    assert!(file.ends_with("]\n"), "{file:?}");
    // Отсчёт ожидания стартует с `--wait` и убывает.
    let secs = waiting_secs(&log);
    assert!(
        secs.iter().any(|n| *n < 300) && secs.iter().all(|n| (0..=300).contains(n)),
        "{secs:?}"
    );
    let sent = b.opened()[1].adapter.sent_count();
    assert_eq!(sent, 2);
    let finished = format!(
        "[+] finished: Paused, sent {sent}, replies {}, open {}",
        reported.len(),
        open.len()
    );
    assert_eq!(plus_lines(&log).last().copied(), Some(finished.as_str()));
}

/// Review Focus 3 (`main.c:1399, 1530`): при `--nostatus` обратный отсчёт `--wait` не привязан к печати статуса и не
/// зависает, а `paused.conf` записан до первого тика ожидания: показание часов на момент записи отстоит от конца скана
/// не меньше чем на половину окна. Так второе нажатие (немедленный `exit(1)` из обработчика) не теряет файл.
#[test]
fn first_ctrl_c_waits_with_nostatus_and_writes_paused_conf_before_wait() {
    let scratch = Scratch::new();
    let path = scratch.path("paused-nostatus.json");
    let mut b = FakeBackend::new();
    b.press_in_tx = Some(PressInTx {
        at: 2,
        late_first: true,
    });
    let args = with(&PAUSE_WAIT, &["--nostatus"]);
    let (r, log, file, reported) = pause_run(&b, &args, &path);
    assert_eq!(r.unwrap().reason, Reason::Paused, "{:?}", plus_lines(&log));
    let end = b.clock.now_micros();
    let writes = b.paused_writes();
    assert_eq!(writes.len(), 1);
    assert!(
        writes[0].1.contains("resume-index = 2\n"),
        "{}",
        writes[0].1
    );
    assert!(
        end - writes[0].0 >= 150_000_000,
        "paused.conf was written {} us before the end of a 300 s wait",
        end - writes[0].0
    );
    assert!(waiting_secs(&log).is_empty(), "{log:?}");
    assert_eq!(log.matches(&saving_line()).count(), 1, "{log:?}");
    let open: Vec<Reply> = reported
        .iter()
        .copied()
        .filter(|r| r.status == PortStatus::Open)
        .collect();
    assert_eq!(file, json_file(&open));
}

/// `main.c:1447`: если передача к моменту Ctrl-C уже закончилась (`min_index >= range`), `paused.conf` не пишется,
/// скан дожидается `--wait` и заканчивается `Completed`.
#[test]
fn ctrl_c_after_tx_done_skips_paused_conf() {
    let scratch = Scratch::new();
    let path = scratch.path("completed.json");
    let mut b = FakeBackend::new();
    b.press_in_tx = Some(PressInTx {
        at: 4,
        late_first: false,
    });
    let (r, log, file, reported) = pause_run(&b, &SHORT_WAIT, &path);
    assert_eq!(
        r.unwrap().reason,
        Reason::Completed,
        "{:?}",
        plus_lines(&log)
    );
    assert!(b.paused_writes().is_empty(), "no paused.conf after tx done");
    assert!(!log.contains("saving resume file"), "{log:?}");
    assert_eq!(log.matches(&waiting_line()).count(), 1, "{log:?}");
    let open: Vec<Reply> = reported
        .iter()
        .copied()
        .filter(|r| r.status == PortStatus::Open)
        .collect();
    assert_eq!(file, json_file(&open));
}

/// Через весь CLI (`rmasscan_cli::run`) `paused.conf` несёт опции вывода и режим статуса из командной строки, чтобы
/// `--resume paused.conf` писал туда же, куда писал прерванный скан.
#[test]
fn paused_conf_carries_output_options_and_ndjson_status() {
    let scratch = Scratch::new();
    let path = scratch.path("paused-cli.json");
    let mut b = FakeBackend::new();
    b.press_in_tx = Some(PressInTx {
        at: 2,
        late_first: false,
    });
    let args = with(
        &SHORT_WAIT,
        &["-oJ", path.to_str().unwrap(), "--ndjson-status"],
    );
    let (r, _, log) = cli(&b, &args);
    r.unwrap();
    let writes = b.paused_writes();
    assert_eq!(writes.len(), 1, "{log:?}");
    let conf = &writes[0].1;
    assert!(conf.contains("resume-index = 2\n"), "{conf}");
    assert!(conf.contains("output-format = json\n"), "{conf}");
    assert!(
        conf.contains(&format!("output-filename = {}\n", path.to_str().unwrap())),
        "{conf}"
    );
    assert!(conf.contains("ndjson-status = true\n"), "{conf}");
}

/// Р1: отказ записи `paused.conf` печатает строки C, но не рвёт фазу `--wait`: поздний ответ принят, подвал `-oJ`
/// закрыт, `[+] finished: Paused` напечатан; процесс при этом завершается кодом 1 (`Err`), а не молчаливым 0.
#[test]
fn paused_conf_write_failure_exits_one() {
    let scratch = Scratch::new();
    let path = scratch.path("paused-fail.json");
    let mut b = FakeBackend::new();
    b.press_in_tx = Some(PressInTx {
        at: 2,
        late_first: true,
    });
    b.paused_write_error = Some("Permission denied".into());
    let (r, log, file, reported) = pause_run(&b, &PAUSE_WAIT, &path);
    let e = r.unwrap_err();
    assert!(e.contains("Permission denied"), "{e}");
    assert!(
        log.contains("[-] FAIL: saving resume file\n[-] paused.conf: Permission denied\n"),
        "{log:?}"
    );
    assert!(b.paused_writes().is_empty());
    assert!(
        plus_lines(&log)
            .last()
            .unwrap()
            .starts_with("[+] finished: Paused"),
        "{:?}",
        plus_lines(&log)
    );
    let first_syn = syn_dst(&b.opened()[1].adapter.sent_frames()[0]);
    assert!(
        reported
            .iter()
            .any(|r| (Ipv4Addr::from(r.remote_ip), r.remote_port) == first_syn)
    );
    let open: Vec<Reply> = reported
        .iter()
        .copied()
        .filter(|r| r.status == PortStatus::Open)
        .collect();
    assert_eq!(file, json_file(&open));
}

/// `--infinite` (Р5, `main.c:225-228, 445-449, 1447`): диапазон из 3 целей проходится заново с `seed + 1`, пока не
/// придёт Ctrl-C; прерывание штатно завершает скан (exit 0) и не пишет `paused.conf`.
#[test]
fn infinite_scan_runs_multiple_passes_until_ctrl_c() {
    let mut b = FakeBackend::new();
    b.press_in_tx = Some(PressInTx {
        at: 10,
        late_first: false,
    });
    let args = [
        "198.51.100.1-198.51.100.3",
        "-p80",
        "--wait",
        "1",
        "--seed",
        "7",
        "--infinite",
    ];
    let (r, _, log) = cli(&b, &args);
    r.unwrap();
    assert_eq!(b.presses(), 1);
    assert!(log.contains("finished: Paused"), "{:?}", plus_lines(&log));
    assert!(!log.contains("saving resume file"), "{log}");
    assert!(
        b.paused_writes().is_empty(),
        "no paused.conf for --infinite"
    );
    let frames = b.opened()[1].adapter.sent_frames();
    assert!(frames.len() >= 9, "sent {}", frames.len());
    let first: BTreeSet<_> = frames[..3].iter().map(|f| syn_dst(f)).collect();
    assert_eq!(first.len(), 3, "pass 1 covers each target once");
    let (passes, _) = frames.as_chunks::<3>();
    for pass in passes {
        let set: BTreeSet<_> = pass.iter().map(|f| syn_dst(f)).collect();
        assert_eq!(set, first, "every pass is a permutation of the range");
    }
}

/// `-sL --infinite` (C зацикливает список, `main-listscan.c:68`) отвергается явно, а не молча даёт один проход.
#[test]
fn list_scan_with_infinite_is_refused() {
    for list in ["-sL", "--list"] {
        let r = Cli::try_parse_masscan([
            "rmasscan",
            list,
            "--infinite",
            "10.0.0.0/30",
            "-p80",
            "--seed",
            "1",
        ]);
        assert!(r.is_err(), "{list} --infinite must be refused");
    }
}

/// Т6 (Р6): `--adapter-ip A-B` с шириной степени двойки ротирует адрес источника в `--packet-trace`
/// (main.c:378-385); ширина 3 отклоняется до скана (main-conf.c:2483).
#[test]
fn adapter_ip_range_rotates_the_packet_trace_source_and_rejects_other_widths() {
    let b = hermetic();
    let mut args = TRACE.to_vec();
    args[2] = "10.0.0.0/28";
    args[7] = "10.255.0.4-10.255.0.7";
    let (r, out, _) = cli(&b, &args);
    r.unwrap();
    let sources: std::collections::BTreeSet<&str> = out
        .lines()
        .filter(|l| l.starts_with("SENT"))
        .map(|l| l.split(['[', ']']).nth(1).unwrap())
        .collect();
    assert_eq!(out.lines().count(), 32);
    assert!(
        sources.len() > 1
            && sources
                .iter()
                .all(|s| ["10.255.0.4", "10.255.0.5", "10.255.0.6", "10.255.0.7"].contains(s)),
        "{sources:?}"
    );
    args[7] = "10.255.0.4-10.255.0.6";
    let (r, out, _) = cli(&b, &args);
    assert!(r.unwrap_err().contains("--adapter-ip"), "{out}");
}

/// Записи `.pcap` после 24-байтового заголовка: `(ts_sec, ts_usec, incl_len, orig_len, кадр)`.
fn pcap_records(bytes: &[u8]) -> Vec<(u32, u32, u32, u32, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 24;
    while at < bytes.len() {
        let w = |i: usize| u32::from_le_bytes(bytes[at + i..at + i + 4].try_into().unwrap());
        let (sec, usec, incl, orig) = (w(0), w(4), w(8), w(12));
        let frame = bytes[at + 16..at + 16 + incl as usize].to_vec();
        out.push((sec, usec, incl, orig, frame));
        at += 16 + incl as usize;
    }
    assert_eq!(at, bytes.len(), "trailing bytes in the capture");
    out
}

/// Задача 7, Р8, `main.c:829, 935, 943-951`: захват пишет входящие кадры на наш `ip:port` до проверки cookie. Валидный
/// SYN-ACK и RST с плохим cookie попадают в файл, ответ на чужой адрес нет; заголовок файла и записи верны.
#[test]
fn pcap_captures_inbound_frames_to_scanner_only() {
    let mut b = FakeBackend::new();
    b.inject_noise = true;
    let (r, _, log) = cli(
        &b,
        &[
            "198.51.100.1",
            "-p80",
            "--wait",
            "1",
            "--seed",
            "7",
            "--pcap",
            "cap.pcap",
        ],
    );
    r.unwrap();
    assert_eq!(*b.pcap_opened.lock().unwrap(), ["cap.pcap"]);
    let bytes = b.pcap_bytes();
    assert_eq!(
        bytes[..24],
        [
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0,
            0, 1, 0, 0, 0
        ]
    );
    let recs = pcap_records(&bytes);
    assert_eq!(recs.len(), 2, "SYN-ACK and the bad-cookie RST only: {log}");
    // Тот же порядок, что у ответчика: SYN-ACK, затем RST.
    assert_eq!(recs[0].4[47], 0x12, "first record is the SYN-ACK");
    assert_eq!(recs[1].4[47], 0x04, "second record is the RST");
    for (sec, _, incl, orig, frame) in &recs {
        assert_eq!((*incl, *orig), (frame.len() as u32, frame.len() as u32));
        assert_eq!(&frame[30..34], &MY_IP.octets(), "addressed to our ip");
        assert!(*sec >= UNIX_TIME as u32, "wall-clock seconds");
    }
    // Чужой кадр не записан и не принят.
    assert!(
        !recs.iter().any(|r| r.4[30..34] == [192, 0, 2, 99]),
        "foreign frame leaked into the capture"
    );
}

/// `--pcap` только для живого скана (Р8): с `--offline` и `-sL` отказ до открытия файла.
#[test]
fn pcap_is_refused_with_offline_and_list() {
    let b = FakeBackend::new();
    for extra in [
        &["--offline", "--seed", "1"][..],
        &["-sL", "--seed", "1"][..],
    ] {
        let mut args = vec!["198.51.100.1", "-p80", "--pcap", "cap.pcap"];
        args.extend_from_slice(extra);
        let (r, out, _) = cli(&b, &args);
        let e = r.unwrap_err();
        assert!(e.contains("--pcap"), "{extra:?}: {e}");
        assert!(out.is_empty(), "{extra:?}: {out}");
    }
    assert!(b.pcap_opened.lock().unwrap().is_empty());
    assert!(b.attempts().is_empty());
}

/// `pcap-filename` из `--resume`-файла (раньше разбирался и не использовался) включает захват.
#[test]
fn pcap_filename_from_a_resume_file_is_honoured() {
    let dir = Scratch::new();
    let file = dir.write(
        "paused.conf",
        b"\n# resume information\nresume-index = 0\nseed = 7\nrate = 100\nwait = 1\n\
pcap-filename = from-file.pcap\nnocapture = servername\nnocapture = servername\n\n\n\
# TARGET SELECTION (IP, PORTS, EXCLUDES)\nports = 80\nrange = 198.51.100.1\n",
    );
    let mut b = FakeBackend::new();
    b.inject_noise = true;
    let (r, _, _) = cli(&b, &["--resume", file.to_str().unwrap()]);
    r.unwrap();
    assert_eq!(*b.pcap_opened.lock().unwrap(), ["from-file.pcap"]);
    assert_eq!(pcap_records(&b.pcap_bytes()).len(), 2);
    // Ключ правее файла переопределяет его.
    let mut b = FakeBackend::new();
    b.inject_noise = true;
    let (r, _, _) = cli(
        &b,
        &["--resume", file.to_str().unwrap(), "--pcap", "cli.pcap"],
    );
    r.unwrap();
    assert_eq!(*b.pcap_opened.lock().unwrap(), ["cli.pcap"]);
}

/// `-c FILE` и `-iL FILE` end-to-end (Р7): цели, порты и `pcap-filename` из файла, дополнительные цели из `-iL`;
/// ключ правее файла (`--pcap`) переопределяет его.
#[test]
fn conf_file_and_includefile_drive_a_live_scan() {
    let dir = Scratch::new();
    let conf = dir.write(
        "scan.conf",
        b"# live scan from a file\nseed = 7\nports = 80\nrange = 198.51.100.1\nwait = 1\npcap-filename = from-conf.pcap\n",
    );
    let inc = dir.write("more.txt", b"198.51.100.2 # second target\n");
    let (c, i) = (conf.to_str().unwrap(), inc.to_str().unwrap());
    let mut b = FakeBackend::new();
    b.inject_noise = true;
    let (r, _, log) = cli(&b, &["-c", c, "-iL", i]);
    r.unwrap();
    assert!(log.contains("finished: Completed"), "{log}");
    assert_eq!(b.opened().last().unwrap().adapter.sent_count(), 2);
    assert_eq!(*b.pcap_opened.lock().unwrap(), ["from-conf.pcap"]);

    let b = FakeBackend::new();
    let (r, _, _) = cli(&b, &["-c", c, "--pcap", "cli.pcap"]);
    r.unwrap();
    assert_eq!(*b.pcap_opened.lock().unwrap(), ["cli.pcap"]);
    // Левее файла файл побеждает.
    let b = FakeBackend::new();
    let (r, _, _) = cli(&b, &["--pcap", "cli.pcap", "-c", c]);
    r.unwrap();
    assert_eq!(*b.pcap_opened.lock().unwrap(), ["from-conf.pcap"]);
}

const ETH1_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 6);
const ETH1_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 3];

fn eth1() -> Iface {
    Iface {
        name: "eth1".to_string(),
        index: 3,
        device_id: "eth1".to_string(),
        description: None,
        mac: Some(ETH1_MAC),
        mac_masked: false,
        ethernet: true,
        up: true,
        ipv4: vec![ETH1_IP],
    }
}

/// Два адаптера, шлюз задан `--router-mac[i]` (ARP не нужен).
fn two_nic_backend() -> FakeBackend {
    let mut b = FakeBackend::new();
    b.ifaces.push(eth1());
    b
}

const TWO_NICS: [&str; 13] = [
    "198.51.100.1-198.51.100.2",
    "-p80,81",
    "--wait",
    "1",
    "--seed",
    "7",
    "--adapter[0]",
    "eth0",
    "--adapter[1]",
    "eth1",
    "--router-mac[0]",
    "02-aa-00-00-00-02",
    "--router-mac[1]=02-aa-00-00-00-02",
];

/// Review Focus 4 и T3 M-8. Индекс адаптера вне `0..=7` отказывает (exit 1) до любого кадра. `--adapter[0]` и
/// `--adapter[1]` на двух `FakeAdapter` делят зонды по чётности внешнего индекса (`main.c:269`: `start = nic_index`,
/// `increment = nic_count`) и пишут ответы в единый `Sink`.
#[test]
fn adapter_index_out_of_bounds_fails() {
    let mut b = FakeBackend::new();
    b.panic_on_open = true;
    for bad in [
        &["--adapter[8]", "eth0"][..],
        &["--adapter[-1]", "eth0"][..],
        &["--adapter-ip[8]=192.0.2.9"][..],
    ] {
        let (r, out, log) = cli(&b, &with(&LIVE, bad));
        let e = r.unwrap_err();
        assert!(e.contains("adapter"), "{bad:?}: {e}");
        assert!(out.is_empty() && log.is_empty(), "{bad:?}: {log}");
    }

    // Поток одного адаптера: внешние индексы 0..4 по порядку.
    let b1 = FakeBackend::new();
    let (r, _, _) = cli(&b1, &with(&LIVE, &["--seed", "7"]));
    r.unwrap();
    let all = b1.opened().last().unwrap().adapter.sent_frames();
    assert_eq!(all.len(), 4);

    let b = two_nic_backend();
    let (r, out, log) = cli(&b, &TWO_NICS);
    r.unwrap();
    assert!(log.contains("finished: Completed"), "{log}");
    let opened = b.opened();
    assert_eq!(opened.len(), 2, "no ARP adapter: both routers are given");
    let dsts = |k: usize| -> Vec<(Ipv4Addr, u16)> {
        opened[k]
            .adapter
            .sent_frames()
            .iter()
            .map(|f| syn_dst(f))
            .collect()
    };
    let stream: Vec<_> = all.iter().map(|f| syn_dst(f)).collect();
    assert_eq!(
        dsts(0),
        [stream[0], stream[2]],
        "even outer indices go to nic 0"
    );
    assert_eq!(
        dsts(1),
        [stream[1], stream[3]],
        "odd outer indices go to nic 1"
    );
    // Каждый адаптер шлёт со своего адреса.
    for (k, ip) in [MY_IP, ETH1_IP].into_iter().enumerate() {
        assert!(
            opened[k]
                .adapter
                .sent_frames()
                .iter()
                .all(|f| f[26..30] == ip.octets()),
            "nic {k}"
        );
        assert_eq!(opened[k].binding.source_ipv4, u32::from(ip));
    }
    // Один `Sink`: обе открытые цели (T1:80, T2:81) напечатаны, хотя их принимают разные адаптеры.
    let mut got: Vec<&str> = out.lines().collect();
    got.sort_unstable();
    assert_eq!(got.len(), 2, "{out}");
    assert!(
        got[0].contains("198.51.100.1") && got[1].contains("198.51.100.2"),
        "{out}"
    );
    // Строки `[+]` второго адаптера несут суффикс `[1]`.
    for key in [
        "interface[1] = eth1 (given)",
        "source-ip[1] = 192.0.2.6 (detected)",
    ] {
        assert!(log.contains(key), "{key}: {log}");
    }
}

/// `--pcap` с двумя адаптерами: один писатель, кадры обоих адаптеров, ни один чужой.
#[test]
fn pcap_with_two_adapters_shares_one_writer() {
    let mut b = two_nic_backend();
    b.inject_noise = true;
    let (r, _, _) = cli(&b, &with(&TWO_NICS, &["--pcap", "cap.pcap"]));
    r.unwrap();
    let recs = pcap_records(&b.pcap_bytes());
    // 4 зонда: 4 ответа обычных (SYN-ACK или RST) + по одному RST с плохим cookie на каждый SYN; чужие не пишутся.
    assert_eq!(recs.len(), 8, "{} records", recs.len());
    let to = |ip: Ipv4Addr| recs.iter().filter(|r| r.4[30..34] == ip.octets()).count();
    assert_eq!((to(MY_IP), to(ETH1_IP)), (4, 4));
    assert!(!recs.iter().any(|r| r.4[30..34] == [192, 0, 2, 99]));
}

/// T3/T4: `paused.conf` с несколькими адаптерами пишется и читается обратно (раньше возобновление отказывало
/// «until T7»). Ctrl-C посреди передачи второго адаптера; возобновление из записанного файла досылает остаток, и
/// вместе оба прогона покрывают весь набор зондов.
#[test]
fn multi_adapter_paused_conf_round_trips_and_resumes() {
    let whole = {
        let b = two_nic_backend();
        let (r, _, _) = cli(&b, &TWO_NICS);
        r.unwrap();
        let o = b.opened();
        let mut v: Vec<(Ipv4Addr, u16)> = o
            .iter()
            .flat_map(|x| x.adapter.sent_frames())
            .map(|f| syn_dst(&f))
            .collect();
        v.sort_unstable();
        v
    };
    assert_eq!(whole.len(), 4);

    let mut b = two_nic_backend();
    b.press_in_tx = Some(PressInTx {
        at: 1,
        late_first: false,
    });
    let (r, _, log) = cli(&b, &TWO_NICS);
    r.unwrap();
    assert!(log.contains("saving resume file to: paused.conf"), "{log}");
    let writes = b.paused_writes();
    assert_eq!(writes.len(), 1);
    let conf = &writes[0].1;
    for key in [
        "adapter[0] = eth0",
        "adapter[1] = eth1",
        "router-mac-ipv4[1] = 02-aa-00-00-00-02",
    ] {
        assert!(conf.contains(key), "{key}: {conf}");
    }
    // Сценарий известен: адаптер 0 закончил оба своих зонда (внешние индексы 0 и 2), адаптер 1 встал после первого
    // (индекс 1). Исчерпанный адаптер в минимум не входит (T7 I-2), база возобновления это база адаптера 1:
    // позиция 3 минус смещение 1.
    let dsts = |b: &FakeBackend, k: usize| -> Vec<(Ipv4Addr, u16)> {
        b.opened()[k]
            .adapter
            .sent_frames()
            .iter()
            .map(|f| syn_dst(f))
            .collect()
    };
    let stream: Vec<(Ipv4Addr, u16)> = {
        let b1 = FakeBackend::new();
        let (r, _, _) = cli(&b1, &with(&LIVE, &["--seed", "7"]));
        r.unwrap();
        let o = b1.opened();
        o.last()
            .unwrap()
            .adapter
            .sent_frames()
            .iter()
            .map(|f| syn_dst(f))
            .collect()
    };
    assert_eq!(
        dsts(&b, 0),
        [stream[0], stream[2]],
        "nic 0 finished its stream"
    );
    assert_eq!(
        dsts(&b, 1),
        [stream[1]],
        "nic 1 paused after its first probe"
    );
    assert!(conf.contains("resume-index = 2\n"), "{conf}");
    let first: Vec<(Ipv4Addr, u16)> = (0..2).flat_map(|k| dsts(&b, k)).collect();

    // Возобновление: файл читается, второй адаптер не отвергается, остаток отправляется.
    let dir = Scratch::new();
    let file = dir.write("paused.conf", conf.as_bytes());
    let b2 = two_nic_backend();
    let (r, _, log2) = cli(&b2, &["--resume", file.to_str().unwrap()]);
    r.unwrap();
    assert!(log2.contains("finished: Completed"), "{log2}");
    assert_eq!(b2.opened().len(), 2);
    // Адаптер 0 был впереди минимума: он заново шлёт индекс 2; адаптер 1 шлёт 3.
    assert_eq!(
        dsts(&b2, 0),
        [stream[2]],
        "resumed nic 0 re-sends its probe past the min"
    );
    assert_eq!(dsts(&b2, 1), [stream[3]]);
    let second: Vec<(Ipv4Addr, u16)> = (0..2).flat_map(|k| dsts(&b2, k)).collect();

    // Без потерь: объединение равно всему потоку; ни один зонд не отправлен больше двух раз; единственный
    // дубликат (индекс 2) принадлежит адаптеру, бывшему впереди минимума.
    let mut union: Vec<_> = first.iter().chain(&second).copied().collect();
    union.sort_unstable();
    let mut whole = stream.clone();
    whole.sort_unstable();
    let mut deduped = union.clone();
    deduped.dedup();
    assert_eq!(deduped, whole, "no probe is lost");
    for probe in &whole {
        let n = union.iter().filter(|p| *p == probe).count();
        assert!(n <= 2, "{probe:?} sent {n} times");
        assert_eq!(
            n == 2,
            *probe == stream[2],
            "only nic 0's probe past the min repeats"
        );
    }
}
