//! Живой путь CLI end-to-end на fake-бэкенде (AGPL-3.0): обнаружение → `[+]` → ARP → `ReadyPlan` → `open` → engine →
//! `Sink`, Ctrl-C (счётчик нажатий fake), `--offline` и `--iflist`. Синтетические таблицы маршрутов и интерфейсов,
//! `FakeAdapter` с ответчиком ARP и `reply_to_syn`, `ManualClock` для резолвера и engine, фиксированные энтропия и
//! время. Ни один тест не достигает ОС: `OsBackend` существует только в бинарнике, а `open` здесь выдаёт
//! `FakeAdapter` или паникует (`panic_on_open`).
//! Адреса и MAC только документационные (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) и локальные `02:…`,
//! кроме гостя n2 и Mac стенда m1: они воспроизводят лабораторные стенды (`198.18.0.0/30`), n2 ещё и NIC QEMU
//! (`10.0.2.0/24`, `52:54:00:…`).

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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
use rmasscan_engine::fake::{FakeAdapter, HealthStep, ManualClock, reply_to_syn};
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
    polls: AtomicUsize,
    /// Ctrl-C во время ARP: уход ARP-запроса считается одним нажатием.
    press_during_arp: bool,
    /// Цели молчат: SYN остаётся без ответа (ARP отвечает как обычно).
    silent_targets: bool,
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
            polls: AtomicUsize::new(0),
            press_during_arp: false,
            silent_targets: false,
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
        adapter.set_responder(move |f| {
            tx.lock().unwrap().push(f.to_vec());
            if press_during_arp && is_arp(f) {
                presses.fetch_max(1, Ordering::SeqCst);
            }
            if silent_targets && !is_arp(f) {
                return vec![];
            }
            respond(f, &neighbors)
        });
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

/// Ограничения runtime v1 (`ReadyPlan`: retries 0, shard 1/1, rounds 14, без legacy resume) проверяются до ARP:
/// отказ плана не стоит ни одного кадра.
#[test]
fn unsupported_plan_options_are_refused_before_any_frame() {
    let mut b = FakeBackend::new();
    b.panic_on_open = true;
    for (extra, word) in [
        (&["--retries", "1"][..], "retries"),
        (&["--shard", "2/3"][..], "shard"),
        (&["--blackrock-rounds", "4"][..], "rounds"),
        (&["--resume-index", "1"][..], "resume"),
    ] {
        let args: Vec<&str> = LIVE.iter().chain(extra).copied().collect();
        let (r, out, log) = cli(&b, &args);
        let e = r.unwrap_err();
        assert!(e.contains(word), "{extra:?}: {e}");
        assert!(out.is_empty() && log.is_empty(), "{extra:?}: {log}");
    }
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
fn stopped_outcome_exits_zero() {
    for (reason, line) in [
        (
            Reason::Stopped,
            "[+] finished: Stopped, sent 3, replies 1, open 1\n",
        ),
        (
            Reason::Completed,
            "[+] finished: Completed, sent 3, replies 1, open 1\n",
        ),
    ] {
        let mut log = Vec::new();
        live::conclude(&outcome(reason), 1, 1, &mut log).unwrap();
        assert_eq!(String::from_utf8(log).unwrap(), line);
    }
    let mut log = Vec::new();
    assert!(live::conclude(&outcome(Reason::Paused), 1, 1, &mut log).is_err());
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

fn tmp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("rmasscan-live-{}-{name}", std::process::id()))
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
    let path = tmp("scan.list");
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
    let _ = std::fs::remove_file(path);
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
    let dir = std::env::temp_dir();
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
    let missing = tmp("missing.scan");
    let (r, out, log) = cli(&b, &["--readscan", missing.to_str().unwrap(), "-oL", "-"]);
    assert_eq!(rmasscan_cli::error_text(&r.unwrap_err()), "");
    assert!(out.is_empty());
    assert!(log.contains("[-] FAIL: --readscan\n"), "{log}");
    assert!(b.lookups().is_empty() && b.attempts().is_empty());
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
    for (name, src) in [
        ("lib.rs", include_str!("../src/lib.rs")),
        ("live.rs", include_str!("../src/live.rs")),
        ("output/mod.rs", include_str!("../src/output/mod.rs")),
        ("output/record.rs", include_str!("../src/output/record.rs")),
        (
            "output/formats.rs",
            include_str!("../src/output/formats.rs"),
        ),
        (
            "output/pipeline.rs",
            include_str!("../src/output/pipeline.rs"),
        ),
        (
            "output/services.rs",
            include_str!("../src/output/services.rs"),
        ),
        ("args.rs", include_str!("../src/args.rs")),
    ] {
        assert!(!src.contains("mod os_backend"), "{name}");
        assert!(
            !src.contains("open_explicit("),
            "{name} must not open adapters"
        );
        assert!(!src.contains("os_route_table("), "{name}");
        assert!(!src.contains("os_interfaces("), "{name}");
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

/// Р18: первое Ctrl-C посреди скана печатает строку C, останавливает engine; приёмник дописывает записи и подвал
/// (`-oJ` закрыт `]\n`, `-oX` закрыт `</nmaprun>\r\n`), `[+] finished: Stopped`, `Ok` (exit 0). Ни один принятый
/// ответ не теряется: в файле ровно открытые ответы, переданные приёмнику, включая пачки после остановки.
#[test]
fn first_interrupt_stops_and_finishes_outputs() {
    for format in ["-oJ", "-oX"] {
        let path = tmp(&format!("interrupt{format}"));
        let b = FakeBackend::new();
        let parsed = parse(&with(&LONG_WAIT, &[format, path.to_str().unwrap()]));
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
                presses: b.presses.clone(),
                reported: Vec::new(),
            };
            let r = live::run_live(&parsed.to_config().unwrap(), &b, &mut sink, &mut log);
            (r, sink.reported)
        };
        let log = String::from_utf8(log).unwrap();
        assert_eq!(
            r.unwrap().reason,
            Reason::Stopped,
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
        assert!(!open.is_empty(), "the press came after an open reply");
        let sent = b.opened()[1].adapter.sent_count();
        let finished = format!(
            "[+] finished: Stopped, sent {sent}, replies {}, open {}",
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
        let _ = std::fs::remove_file(path);
    }
}

/// Review Focus 5: Ctrl-C до первой записи (во время ARP; цели молчат): файл остаётся 0 байт, без заголовка и
/// подвала, `[+] finished: Stopped`, exit 0, второго нажатия не нужно. Обработчик ставится ровно один раз, до
/// открытия адаптера ARP.
#[test]
fn interrupt_without_records_leaves_empty_file() {
    for format in ["-oJ", "-oX"] {
        let path = tmp(&format!("interrupt-empty{format}"));
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
        let sent = b.opened()[1].adapter.sent_count();
        assert_eq!(
            plus_lines(&log).last().copied(),
            Some(format!("[+] finished: Stopped, sent {sent}, replies 0, open 0").as_str())
        );
        assert_eq!(
            b.opened()[0].polls_before,
            1,
            "the handler is installed once, before the ARP adapter opens"
        );
        let _ = std::fs::remove_file(path);
    }
}

/// Ctrl-C перехватывает только живой скан: `--readscan`, `-sL`, `--echo`, `--offline` и `--iflist` не ставят
/// обработчик (поведение ОС по умолчанию), `interrupts()` у них не зовётся ни разу.
#[test]
fn only_a_live_scan_traps_ctrl_c() {
    let path = tmp("trap.scan");
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
    let _ = std::fs::remove_file(path);
}
