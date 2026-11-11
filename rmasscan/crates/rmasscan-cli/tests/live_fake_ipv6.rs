//! Живой путь CLI с целями IPv6 на fake-бэкенде (AGPL-3.0, IPv6 stage Task 5): обнаружение IPv6 по маршруту →
//! `[+]` → ARP (только при целях IPv4) → NDP Neighbor Solicitation к следующему хопу IPv6 (R11) → `ReadyPlan` →
//! `open` → engine → `Sink`. Синтетические таблицы IPv4/IPv6, `FakeAdapter` с ответчиками ARP, NS→NA и SYN поверх
//! обеих семей, `ManualClock`. Ни один тест не достигает ОС. Адреса: `2001:db8::/32`, `fd00::/8`, link-local,
//! `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; MAC только локальные `02:…`.

#[path = "common/scratch.rs"]
mod scratch;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use rmasscan_cli::args::Cli;
use rmasscan_cli::conf::{FullConf, format_paused_conf};
use rmasscan_cli::live::Backend;
use rmasscan_cli::output::{ServiceNames, Wall};
use rmasscan_cli::status::normalize_stderr_line;
use rmasscan_core::arp::{ArpOp, decode, encode_reply};
use rmasscan_core::config::{Operation, validate};
use rmasscan_core::ndp::{
    decode_neighbor_advertisement, decode_neighbor_solicitation, encode_neighbor_advertisement,
    encode_neighbor_solicitation, solicited_node_mac,
};
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{AdapterBinding, NicBinding, TargetIp, for_each_probe_nic};
use rmasscan_core::throttle::Clock;
use rmasscan_engine::AdapterPair;
use rmasscan_engine::fake::{FakeAdapter, ManualClock, reply_to_syn, reply_to_syn6};
use rmasscan_net::arp_resolve::ArpPolicy;
use rmasscan_net::{Iface, Interfaces, NetError, Route, RouteTable, RouteV6};
use scratch::Scratch;

const MY_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 1];
const MY_MAC1: [u8; 6] = [0x02, 0xab, 0, 0, 0, 1];
const MY_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 5);
const GW: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const GW_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 2];
const GW6_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 6];
const GIVEN_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 9];
const ENTROPY: u64 = 0x1234_5678_9abc_def1;
const UNIX_TIME: u64 = 1_800_012_345;
const TIME_PORT: u16 = 52345;

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn my_ip6() -> Ipv6Addr {
    v6("2001:db8:1::5")
}

fn gw6() -> Ipv6Addr {
    v6("fe80::1")
}

fn iface(name: &str, index: u32, mac: [u8; 6], ipv4: Vec<Ipv4Addr>) -> Iface {
    Iface {
        name: name.into(),
        index,
        device_id: name.into(),
        description: None,
        mac: Some(mac),
        mac_masked: false,
        ethernet: true,
        up: true,
        ipv4,
    }
}

#[derive(Clone, Default)]
struct Tables {
    rules4: Vec<(u32, u32, Route)>,
    rules6: Vec<(u128, u128, RouteV6)>,
    ifaces: Vec<Iface>,
    addrs6: Vec<(u32, Vec<Ipv6Addr>)>,
}

impl RouteTable for Tables {
    fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, NetError> {
        let d = u32::from(dst);
        Ok(self
            .rules4
            .iter()
            .find(|(a, b, _)| *a <= d && d <= *b)
            .map(|(_, _, r)| r.clone()))
    }
    fn default_routes(&self) -> Result<Vec<Route>, NetError> {
        Ok(Vec::new())
    }
    fn lookup_v6(&self, dst: Ipv6Addr) -> Result<Option<RouteV6>, NetError> {
        let d = u128::from(dst);
        Ok(self
            .rules6
            .iter()
            .find(|(a, b, _)| *a <= d && d <= *b)
            .map(|(_, _, r)| r.clone()))
    }
}

impl Interfaces for Tables {
    fn list(&self) -> Result<Vec<Iface>, NetError> {
        Ok(self.ifaces.clone())
    }
    fn ipv6_addrs(&self, iface: &Iface) -> Result<Vec<Ipv6Addr>, NetError> {
        Ok(self
            .addrs6
            .iter()
            .find(|(i, _)| *i == iface.index)
            .map(|(_, a)| a.clone())
            .unwrap_or_default())
    }
}

struct Opened {
    binding: AdapterBinding,
    adapter: FakeAdapter,
}

struct FakeBackend {
    tables: Tables,
    neighbors4: Vec<(Ipv4Addr, [u8; 6])>,
    neighbors6: Vec<(Ipv6Addr, [u8; 6])>,
    /// Открытые цели: (адрес, порт) отвечают SYN-ACK, остальные RST.
    open4: Vec<(Ipv4Addr, u16)>,
    open6: Vec<(Ipv6Addr, u16)>,
    /// На первый SYN соседний роутер спрашивает наш адрес IPv6 (NS): ответ NA есть только у скана IPv6.
    ns_on_first_syn: bool,
    panic_on_open: bool,
    clock: Arc<ManualClock>,
    opened: Mutex<Vec<Opened>>,
    tx: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl FakeBackend {
    /// `eth0` (2): IPv4 `192.0.2.5/24` (шлюз `192.0.2.1`), IPv6 link-local и `2001:db8:1::5/64` (шлюз `fe80::1`);
    /// `eth1` (3): IPv4 `203.0.113.5/24`, IPv6 `2001:db8:3::5/64`, оба on-link.
    fn new() -> Self {
        let r4 = |ifindex, ifname: &str, gateway| Route {
            ifindex,
            ifname: ifname.into(),
            gateway,
            local: false,
        };
        let r6 = |ifindex, ifname: &str, gateway, source| RouteV6 {
            ifindex,
            ifname: ifname.into(),
            gateway,
            source,
            local: false,
        };
        let range4 = |a: &str, b: &str| {
            (
                u32::from(a.parse::<Ipv4Addr>().unwrap()),
                u32::from(b.parse::<Ipv4Addr>().unwrap()),
            )
        };
        let range6 = |a: &str, b: &str| (u128::from(v6(a)), u128::from(v6(b)));
        let (a, b) = range4("192.0.2.0", "192.0.2.255");
        let (c, d) = range4("203.0.113.0", "203.0.113.255");
        let (e, f) = range4("0.0.0.0", "255.255.255.255");
        let (g, h) = range6("2001:db8:1::", "2001:db8:1::ffff");
        let (i, j) = range6("2001:db8:3::", "2001:db8:3::ffff");
        let (k, l) = range6("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
        FakeBackend {
            tables: Tables {
                rules4: vec![
                    (a, b, r4(2, "eth0", None)),
                    (c, d, r4(3, "eth1", None)),
                    (e, f, r4(2, "eth0", Some(GW))),
                ],
                rules6: vec![
                    (g, h, r6(2, "eth0", None, None)),
                    (i, j, r6(3, "eth1", None, None)),
                    (k, l, r6(2, "eth0", Some(gw6()), Some(my_ip6()))),
                ],
                ifaces: vec![
                    iface("eth0", 2, MY_MAC, vec![MY_IP]),
                    iface("eth1", 3, MY_MAC1, vec![Ipv4Addr::new(203, 0, 113, 5)]),
                ],
                addrs6: vec![
                    (2, vec![v6("fe80::aa"), my_ip6()]),
                    (3, vec![v6("fe80::ab"), v6("2001:db8:3::5")]),
                ],
            },
            neighbors4: vec![(GW, GW_MAC)],
            neighbors6: vec![(gw6(), GW6_MAC)],
            open4: vec![(Ipv4Addr::new(198, 51, 100, 1), 80)],
            open6: vec![(v6("2001:db8:9::1"), 80), (v6("2001:db8:9::2"), 443)],
            ns_on_first_syn: false,
            panic_on_open: false,
            clock: ManualClock::new(),
            opened: Mutex::new(Vec::new()),
            tx: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

fn respond(
    f: &[u8],
    neighbors4: &[(Ipv4Addr, [u8; 6])],
    neighbors6: &[(Ipv6Addr, [u8; 6])],
    open4: &[(Ipv4Addr, u16)],
    open6: &[(Ipv6Addr, u16)],
) -> Vec<Vec<u8>> {
    match f.get(12..14) {
        Some([0x08, 0x06]) => {
            let Ok(p) = decode(f) else { return vec![] };
            neighbors4
                .iter()
                .find(|(ip, _)| p.op == ArpOp::Request && u32::from(*ip) == p.target_ip)
                .map(|(ip, mac)| {
                    vec![encode_reply(*mac, u32::from(*ip), p.sender_mac, p.sender_ip).to_vec()]
                })
                .unwrap_or_default()
        }
        Some([0x86, 0xdd]) if is_ns(f) => {
            let Ok(ns) = decode_neighbor_solicitation(f) else {
                return vec![];
            };
            neighbors6
                .iter()
                .find(|(ip, _)| u128::from(*ip) == ns.target)
                .map(|(ip, mac)| {
                    vec![
                        encode_neighbor_advertisement(*mac, u128::from(*ip), ns.eth_src, ns.src_ip)
                            .to_vec(),
                    ]
                })
                .unwrap_or_default()
        }
        Some([0x86, 0xdd]) if is_syn6(f) => {
            let (ip, port) = syn6_dst(f);
            let flags = if open6.contains(&(ip, port)) {
                0x12
            } else {
                0x04
            };
            reply_to_syn6(f, flags).into_iter().collect()
        }
        Some([0x08, 0x00]) => {
            let ip = Ipv4Addr::new(f[30], f[31], f[32], f[33]);
            let port = u16::from_be_bytes([f[36], f[37]]);
            let flags = if open4.contains(&(ip, port)) {
                0x12
            } else {
                0x04
            };
            reply_to_syn(f, flags).into_iter().collect()
        }
        _ => vec![],
    }
}

impl Wall for FakeBackend {
    fn unix_time(&self) -> u64 {
        UNIX_TIME
    }
    fn utc_offset_secs(&self, _: u64) -> i32 {
        0
    }
}

impl Backend for FakeBackend {
    fn routes(&self) -> Result<Box<dyn RouteTable>, NetError> {
        Ok(Box::new(self.tables.clone()))
    }
    fn interfaces(&self) -> Result<Box<dyn Interfaces>, NetError> {
        Ok(Box::new(self.tables.clone()))
    }
    fn open(&self, binding: &AdapterBinding) -> Result<AdapterPair, NetError> {
        assert!(!self.panic_on_open, "no adapter may be opened in this test");
        let adapter = FakeAdapter::new().with_clock(self.clock.clone());
        let (n4, n6) = (self.neighbors4.clone(), self.neighbors6.clone());
        let (o4, o6) = (self.open4.clone(), self.open6.clone());
        let tx = self.tx.clone();
        let mut ask = self.ns_on_first_syn;
        adapter.set_responder(move |f| {
            tx.lock().unwrap().push(f.to_vec());
            let mut out = respond(f, &n4, &n6, &o4, &o6);
            if ask && (is_syn6(f) || is_syn4(f)) {
                ask = false;
                out.push(
                    encode_neighbor_solicitation(GW6_MAC, u128::from(gw6()), u128::from(my_ip6()))
                        .to_vec(),
                );
            }
            out
        });
        let pair = adapter.pair();
        self.opened.lock().unwrap().push(Opened {
            binding: binding.clone(),
            adapter,
        });
        Ok(pair)
    }
    fn entropy64(&self) -> u64 {
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
        0
    }
    fn write_paused_conf(&self, _: &str) -> Result<(), String> {
        panic!("no Ctrl-C in these tests")
    }
}

fn is_ns(f: &[u8]) -> bool {
    f.len() >= 78 && f[20] == 58 && f[54] == 135
}

fn is_na(f: &[u8]) -> bool {
    f.len() >= 78 && f[12..14] == [0x86, 0xdd] && f[20] == 58 && f[54] == 136
}

fn is_syn6(f: &[u8]) -> bool {
    f.len() >= 74 && f[12..14] == [0x86, 0xdd] && f[20] == 6 && f[67] == 0x02
}

fn is_syn4(f: &[u8]) -> bool {
    f.get(12..14) == Some(&[0x08, 0x00][..]) && f.get(47) == Some(&0x02)
}

fn syn6_dst(f: &[u8]) -> (Ipv6Addr, u16) {
    (
        Ipv6Addr::from(<[u8; 16]>::try_from(&f[38..54]).unwrap()),
        u16::from_be_bytes([f[56], f[57]]),
    )
}

fn parse(args: &[&str]) -> Cli {
    Cli::try_parse_masscan(std::iter::once("rmasscan").chain(args.iter().copied())).unwrap()
}

fn cli(b: &FakeBackend, args: &[&str]) -> (Result<(), String>, String, String) {
    let (mut out, mut log) = (Vec::new(), Vec::new());
    let r = rmasscan_cli::run(&parse(args), b, &mut out, &mut log);
    (
        r,
        String::from_utf8(out).unwrap(),
        String::from_utf8(log).unwrap(),
    )
}

fn plus_lines(log: &str) -> Vec<String> {
    log.lines()
        .map(normalize_stderr_line)
        .filter(|l| l.starts_with("[+] "))
        .map(str::to_string)
        .collect()
}

const LIVE6: [&str; 4] = ["2001:db8:9::1-2001:db8:9::2", "-p80,443", "--wait", "1"];

/// R11: следующий хоп IPv6 это шлюз маршрута ОС (`fe80::1`), его MAC резолвит один NS (86 байт, solicited-node) с
/// короткоживущего адаптера фазы NDP, закрытого до адаптера скана; затем SYN поверх IPv6 на этот MAC с источника,
/// который выбрала ОС для маршрута. ARP нет (целей IPv4 нет), строк IPv4 в `[+]` тоже (C `main-initadapter.c:122`).
#[test]
fn live_ipv6_scan_resolves_the_next_hop_with_ndp_then_scans() {
    let b = FakeBackend::new();
    let (r, out, log) = cli(&b, &LIVE6);
    r.unwrap();
    let opened = b.opened.lock().unwrap();
    assert_eq!(opened.len(), 2, "one NDP adapter, then one scan adapter");
    let (ndp, scan) = (&opened[0], &opened[1]);
    assert_eq!(
        ndp.adapter.sent_frames(),
        vec![
            encode_neighbor_solicitation(MY_MAC, u128::from(my_ip6()), u128::from(gw6())).to_vec()
        ],
        "exactly one Neighbor Solicitation for the gateway"
    );
    assert_eq!(
        ndp.binding.next_hop_mac,
        solicited_node_mac(u128::from(gw6()))
    );
    let syns = scan.adapter.sent_frames();
    assert_eq!(syns.len(), 4, "2 addresses x 2 ports");
    for f in &syns {
        assert!(is_syn6(f), "only IPv6 SYNs");
        assert_eq!(&f[0..6], &GW6_MAC, "to the NDP-resolved MAC");
        assert_eq!(&f[6..12], &MY_MAC);
        assert_eq!(
            &f[22..38],
            &my_ip6().octets(),
            "source chosen by the OS route"
        );
        assert_eq!(&f[54..56], &TIME_PORT.to_be_bytes());
    }
    assert!(
        !b.tx
            .lock()
            .unwrap()
            .iter()
            .any(|f| f[12..14] == [0x08, 0x06]),
        "no ARP without IPv4 targets"
    );
    assert_eq!(
        scan.binding,
        AdapterBinding {
            interface_id: "eth0".into(),
            link_type: LinkType::Ethernet,
            source_ipv4: 0,
            source_mac: MY_MAC,
            next_hop_mac: [0; 6],
            source_ports: (TIME_PORT, TIME_PORT),
        }
    );
    assert_eq!(
        plus_lines(&log),
        [
            "[+] interface = eth0 (detected: route to [2001:db8:9::1])".to_string(),
            "[+] source-mac = 02-aa-00-00-00-01 (detected)".to_string(),
            "[+] source-ip = [2001:db8:1::5] (detected)".to_string(),
            "[+] router-ip = [fe80::1] (route gateway)".to_string(),
            "[+] router-mac-ipv6 = 02-aa-00-00-00-06 (ndp: 1 requests, 0 ms)".to_string(),
            format!("[+] seed = {ENTROPY} (entropy)"),
            format!("[+] source-port = {TIME_PORT} (time)"),
            "[+] finished: Completed, sent 4, replies 4, open 2".to_string(),
        ],
        "{log}"
    );
    let mut lines: Vec<&str> = out.lines().map(str::trim_end).collect();
    lines.sort_unstable();
    assert_eq!(
        lines,
        [
            "Discovered open port 443/tcp on 2001:db8:9::2",
            "Discovered open port 80/tcp on 2001:db8:9::1",
        ]
    );
}

/// `--router-mac-ipv6` (C `main-conf.c:2614-2624`) обходит NDP и не трогает IPv4: шлюз IPv4 смешанного скана
/// по-прежнему резолвит ARP, и кадры IPv4 идут на его MAC, а не на MAC IPv6 (forward note T4, `live.rs` `.or`).
#[test]
fn router_mac_ipv6_bypasses_ndp_and_never_becomes_the_ipv4_router_mac() {
    let b = FakeBackend::new();
    let mac = "02-aa-00-00-00-09";
    let (r, _, log) = cli(
        &b,
        &[
            "198.51.100.1",
            "2001:db8:9::1",
            "-p80",
            "--wait",
            "1",
            "--router-mac-ipv6",
            mac,
        ],
    );
    r.unwrap();
    let opened = b.opened.lock().unwrap();
    assert_eq!(
        opened.len(),
        2,
        "ARP adapter, then the scan adapter; no NDP adapter"
    );
    assert!(
        opened[0]
            .adapter
            .sent_frames()
            .iter()
            .all(|f| f[12..14] == [0x08, 0x06])
    );
    let frames = opened[1].adapter.sent_frames();
    assert_eq!(frames.len(), 2);
    for f in &frames {
        if is_syn6(f) {
            assert_eq!(&f[0..6], &GIVEN_MAC, "IPv6 to --router-mac-ipv6");
        } else {
            assert!(is_syn4(f));
            assert_eq!(&f[0..6], &GW_MAC, "IPv4 to the ARP-resolved router");
        }
    }
    assert!(!b.tx.lock().unwrap().iter().any(|f| is_ns(f)), "no NS");
    let plus = plus_lines(&log);
    assert!(
        plus.contains(&"[+] router-mac-ipv6 = 02-aa-00-00-00-09 (given)".to_string()),
        "{log}"
    );
    assert!(
        plus.contains(&"[+] router-ip = 192.0.2.1 (route gateway)".to_string()),
        "{log}"
    );
    // `--router-ipv6` это синоним C (MAC, не адрес).
    let b = FakeBackend::new();
    let (r, _, _) = cli(
        &b,
        &["2001:db8:9::1", "-p80", "--wait", "1", "--router-ipv6", mac],
    );
    r.unwrap();
    assert_eq!(b.opened.lock().unwrap().len(), 1, "no NDP adapter");
}

/// Смешанный скан через один интерфейс: ARP шлюза IPv4, затем NS шлюза IPv6 (порядок C, `main-initadapter.c:122,
/// 212`), потом один адаптер скана с кадрами обеих семей на свои MAC. NS соседа к нашему адресу IPv6 во время скана
/// получает NA (ответчик T4 включён только при `source_ipv6`); у чистого скана IPv4 его нет.
#[test]
fn mixed_scan_resolves_arp_then_ndp_and_answers_ns_only_with_ipv6_targets() {
    let mut b = FakeBackend::new();
    b.ns_on_first_syn = true;
    let (r, _, log) = cli(
        &b,
        &[
            "198.51.100.1-198.51.100.2",
            "2001:db8:9::1",
            "-p80",
            "--wait",
            "1",
        ],
    );
    r.unwrap();
    {
        let opened = b.opened.lock().unwrap();
        assert_eq!(opened.len(), 3, "ARP, NDP, scan");
        assert!(
            opened[0]
                .adapter
                .sent_frames()
                .iter()
                .all(|f| f[12..14] == [0x08, 0x06])
        );
        assert!(opened[1].adapter.sent_frames().iter().all(|f| is_ns(f)));
        let frames = opened[2].adapter.sent_frames();
        let syns: Vec<_> = frames.iter().filter(|f| is_syn4(f) || is_syn6(f)).collect();
        assert_eq!(syns.len(), 3);
        for f in &syns {
            let want = if is_syn6(f) { GW6_MAC } else { GW_MAC };
            assert_eq!(&f[0..6], &want);
        }
        let nas: Vec<_> = frames.iter().filter(|f| is_na(f)).collect();
        assert_eq!(nas.len(), 1, "the scan answers the NS for its IPv6 source");
        let na = decode_neighbor_advertisement(nas[0]).unwrap();
        assert_eq!(na.target, u128::from(my_ip6()));
    }
    let plus = plus_lines(&log);
    let want = [
        "[+] interface = eth0 (detected: route to 198.51.100.1)",
        "[+] source-mac = 02-aa-00-00-00-01 (detected)",
        "[+] source-ip = 192.0.2.5 (detected)",
        "[+] router-ip = 192.0.2.1 (route gateway)",
        "[+] source-ip = [2001:db8:1::5] (detected)",
        "[+] router-ip = [fe80::1] (route gateway)",
        "[+] router-mac = 02-aa-00-00-00-02 (arp: 1 requests, 0 ms)",
        "[+] router-mac-ipv6 = 02-aa-00-00-00-06 (ndp: 1 requests, 0 ms)",
    ];
    assert_eq!(&plus[..want.len()], &want, "{log}");

    // Чистый IPv4: тот же NS остаётся без ответа (источника IPv6 у скана нет).
    let mut b = FakeBackend::new();
    b.ns_on_first_syn = true;
    let (r, _, log) = cli(&b, &["198.51.100.1-198.51.100.2", "-p80", "--wait", "1"]);
    r.unwrap();
    let opened = b.opened.lock().unwrap();
    assert_eq!(opened.len(), 2, "ARP, scan; no NDP adapter");
    assert!(!opened[1].adapter.sent_frames().iter().any(|f| is_na(f)));
    assert!(
        !log.contains("ipv6") && !log.contains("source-ip = ["),
        "{log}"
    );
}

/// Смешанный скан, чьи семьи уходят разными интерфейсами: явный отказ (exit 1) до любого адаптера; C отправил бы
/// кадры IPv6 в интерфейс маршрута IPv4 (`main-initadapter.c:44-57, 212-219`).
#[test]
fn mixed_scan_split_across_interfaces_is_refused_before_any_adapter() {
    let mut b = FakeBackend::new();
    b.panic_on_open = true;
    let (r, out, log) = cli(&b, &["203.0.113.9", "2001:db8:9::1", "-p80"]);
    let e = r.unwrap_err();
    assert_eq!(
        e,
        "[-] FAIL: IPv4 and IPv6 targets are routed via different interfaces (203.0.113.9 via eth1, \
         [2001:db8:9::1] via eth0)\n    [hint] scan the IPv4 and the IPv6 targets separately, or try \
         \"--interface ethX\""
    );
    assert_eq!(rmasscan_cli::error_text(&e), e, "C form, exit 1");
    assert!(out.is_empty() && log.is_empty(), "{log}");
    // `--offline` (preflight) отказывает так же.
    let (r, _, _) = cli(
        &b,
        &[
            "--offline",
            "203.0.113.9",
            "2001:db8:9::1",
            "-p80",
            "--seed",
            "1",
        ],
    );
    assert!(r.unwrap_err().contains("routed via different interfaces"));
}

/// NDP без ответа: отказ текстом резолвера T4 через 10 с часов, адаптер скана не открывается, SYN нет.
#[test]
fn ndp_timeout_refuses_before_the_scan_adapter() {
    let mut b = FakeBackend::new();
    b.neighbors6.clear();
    let (r, out, _) = cli(&b, &LIVE6);
    let e = r.unwrap_err();
    assert!(
        e.starts_with(
            "[-] FAIL: NDP timed-out resolving MAC address for router eth0: \"fe80::1\"\n    \
             [hint] try \"--router-mac-ipv6 66-55-44-33-22-11\" instead to bypass NDP"
        ),
        "{e}"
    );
    let opened = b.opened.lock().unwrap();
    assert_eq!(opened.len(), 1, "the scan adapter is never opened");
    assert_eq!(
        opened[0].adapter.sent_frames().len(),
        10,
        "ten solicitations"
    );
    assert!(out.is_empty());
}

/// `--router-ip <IPv6>`: NS к заданному адресу вместо шлюза маршрута (R11; у C ключ только IPv4). Единственная
/// on-link цель резолвится сама.
#[test]
fn given_router_ipv6_and_on_link_target_are_solicited() {
    let mut b = FakeBackend::new();
    b.neighbors6.push((v6("fe80::fe"), GIVEN_MAC));
    b.neighbors6.push((v6("2001:db8:1::77"), GW_MAC));
    b.open6.push((v6("2001:db8:1::77"), 80));
    let (r, _, log) = cli(
        &b,
        &[
            "2001:db8:9::1",
            "-p80",
            "--wait",
            "1",
            "--router-ip",
            "fe80::fe",
        ],
    );
    r.unwrap();
    let plus = plus_lines(&log);
    assert!(
        plus.contains(&"[+] router-ip = [fe80::fe] (given)".to_string()),
        "{log}"
    );
    {
        let opened = b.opened.lock().unwrap();
        assert_eq!(&opened[1].adapter.sent_frames()[0][0..6], &GIVEN_MAC);
    }
    let b2 = FakeBackend {
        neighbors6: b.neighbors6.clone(),
        open6: b.open6.clone(),
        ..FakeBackend::new()
    };
    let (r, out, log) = cli(&b2, &["2001:db8:1::77", "-p80", "--wait", "1"]);
    r.unwrap();
    assert!(
        plus_lines(&log).contains(&"[+] router-ip = [2001:db8:1::77] (on-link target)".to_string()),
        "{log}"
    );
    assert!(
        out.contains("Discovered open port 80/tcp on 2001:db8:1::77"),
        "{out}"
    );
}

/// `--offline` с целями IPv6 (C `main-initadapter.c:236-238`): обнаружение только чтением, MAC шлюза IPv6
/// фиктивный, NS нет; `--packet-trace` строит кадры на этот MAC.
#[test]
fn offline_ipv6_prints_the_ipv6_lines_with_the_fake_router_mac() {
    let mut b = FakeBackend::new();
    b.panic_on_open = true;
    let (r, out, log) = cli(
        &b,
        &[
            "--offline",
            "--packet-trace",
            "2001:db8:9::1",
            "-p80",
            "--seed",
            "1",
            "--source-port",
            "40000",
        ],
    );
    r.unwrap();
    assert_eq!(
        plus_lines(&log),
        [
            "[+] interface = eth0 (detected: route to [2001:db8:9::1])",
            "[+] source-mac = 02-aa-00-00-00-01 (detected)",
            "[+] source-ip = [2001:db8:1::5] (detected)",
            "[+] router-mac-ipv6 = 66-55-44-33-22-11 (offline)",
            "[+] seed = 1 (given)",
            "[+] source-port = 40000 (given)",
        ],
        "{log}"
    );
    // main-ptrace.c:97: `%-21s > %-21s SYN`.
    assert_eq!(
        out,
        format!(
            "SENT (0.0000) TCP  {:<21} > {:<21} SYN\n",
            "[2001:db8:1::5]:40000", "[2001:db8:9::1]:80"
        )
    );
}

/// R15: `paused.conf` смешанного скана несёт цели IPv6 и заданные ключи IPv6 (адрес источника, MAC шлюза IPv6) и
/// только их; обнаруженные значения не пишутся (как C, `main-initadapter.c:16-19`). Возобновление по нему даёт ровно
/// хвост исходного потока кадров с `resume-index`, IPv6 и IPv4 в том же порядке.
#[test]
fn paused_conf_of_a_mixed_scan_resumes_exactly_the_tail() {
    let args = [
        "2001:db8::/126",
        "198.51.100.0/30",
        "-p80,443",
        "--seed",
        "7",
        "--source-port",
        "40000",
        "--adapter-ip",
        "192.0.2.5",
        "--adapter-ip[0]=2001:db8:1::5",
        "--router-mac-ipv6",
        "02-aa-00-00-00-06",
        "--rate",
        "1000",
    ];
    let cfg = parse(&args).to_config().unwrap();
    let text = format_paused_conf(
        &FullConf {
            scan: cfg.clone(),
            ..FullConf::default()
        },
        5,
    );
    for line in [
        "resume-index = 5\n",
        "adapter-ip = 192.0.2.5\nadapter-ip = 2001:db8:1::5\n",
        "router-mac-ipv6 = 02-aa-00-00-00-06\n",
        "range = 198.51.100.0/30\nrange = 2001:db8::/126\n",
    ] {
        assert!(text.contains(line), "{line:?} in\n{text}");
    }
    assert!(!text.contains("router-mac-ipv4"), "{text}");
    let s = Scratch::new();
    let f = s.write("paused.conf", text.as_bytes());
    let resumed = parse(&["--resume", f.to_str().unwrap()])
        .to_config()
        .unwrap();
    let nic = || {
        let mut n = NicBinding::from(AdapterBinding {
            interface_id: "eth0".into(),
            link_type: LinkType::Ethernet,
            source_ipv4: u32::from(MY_IP),
            source_mac: MY_MAC,
            next_hop_mac: GW_MAC,
            source_ports: (40000, 40000),
        });
        n.source_ipv6 = Some(u128::from(my_ip6()));
        n.next_hop_mac_ipv6 = Some(GW6_MAC);
        n
    };
    let stream = |c| {
        let eff = validate(c, Operation::Scan).unwrap();
        let mut v = Vec::new();
        let flow = for_each_probe_nic(&eff, &nic(), |p| {
            v.push(p.clone());
            std::ops::ControlFlow::<()>::Continue(())
        });
        assert_eq!(flow, Ok(std::ops::ControlFlow::Continue(())));
        v
    };
    let (all, tail) = (stream(&cfg), stream(&resumed));
    assert_eq!(all.len(), 16);
    assert!(all.iter().any(|p| matches!(p.target, TargetIp::V6(_))));
    let want: Vec<_> = all.into_iter().filter(|p| p.index >= 5).collect();
    assert_eq!(tail, want);
}
