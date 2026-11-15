//! Живой путь CLI с целями IPv6 на fake-бэкенде (AGPL-3.0, IPv6 stage Task 5): обнаружение IPv6 по маршруту →
//! `[+]` → ARP (только при целях IPv4) → NDP Neighbor Solicitation к следующему хопу IPv6 (R11) → `ReadyPlan` →
//! `open` → engine → `Sink`. Синтетические таблицы IPv4/IPv6, `FakeAdapter` с ответчиками ARP, NS→NA и SYN поверх
//! обеих семей, `ManualClock`. Ни один тест не достигает ОС. Адреса: `2001:db8::/32`, `fd00::/8`, link-local,
//! `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; MAC только локальные `02:…`.

#[path = "common/scratch.rs"]
mod scratch;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
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

/// Наш кадр TCP поверх IPv6 глазами пира: флаги, seq, ack, нагрузка.
type Seen6 = (u8, u32, u32, Vec<u8>);

struct FakeBackend {
    tables: Tables,
    neighbors4: Vec<(Ipv4Addr, [u8; 6])>,
    neighbors6: Vec<(Ipv6Addr, [u8; 6])>,
    /// Открытые цели: (адрес, порт) отвечают SYN-ACK, остальные RST.
    open4: Vec<(Ipv4Addr, u16)>,
    open6: Vec<(Ipv6Addr, u16)>,
    /// На первый SYN соседний роутер спрашивает наш адрес IPv6 (NS): ответ NA есть только у скана IPv6.
    ns_on_first_syn: bool,
    /// Ctrl-C во время NDP: уход Neighbor Solicitation считается одним нажатием (ответа нет).
    press_during_ndp: bool,
    presses: Arc<AtomicU32>,
    panic_on_open: bool,
    clock: Arc<ManualClock>,
    opened: Mutex<Vec<Opened>>,
    tx: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Сервер HTTP поверх IPv6 с настоящими номерами (задача 14): на наш первый сегмент с данными отвечает этими
    /// байтами и FIN; его порт 80 вместо `open6`.
    http6: Option<Vec<u8>>,
    /// Наши кадры TCP поверх IPv6 после SYN.
    seen6: Arc<Mutex<Vec<Seen6>>>,
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
            press_during_ndp: false,
            presses: Arc::new(AtomicU32::new(0)),
            panic_on_open: false,
            clock: ManualClock::new(),
            opened: Mutex::new(Vec::new()),
            tx: Arc::new(Mutex::new(Vec::new())),
            http6: None,
            seen6: Arc::new(Mutex::new(Vec::new())),
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
        // Только SYN: на RST без состояния (Р8) хост не отвечает.
        Some([0x08, 0x00]) if is_syn4(f) => {
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
        let (http6, seen6) = (self.http6.clone(), self.seen6.clone());
        let mut http6_next = None::<u32>;
        let mut ask = self.ns_on_first_syn;
        let (presses, press_during_ndp) = (self.presses.clone(), self.press_during_ndp);
        adapter.set_responder(move |f| {
            tx.lock().unwrap().push(f.to_vec());
            if press_during_ndp && is_ns(f) {
                presses.fetch_max(1, Ordering::SeqCst);
                return vec![];
            }
            if let Some(body) = http6.as_ref().filter(|_| is_tcp6(f)) {
                return http6_peer(f, body, &mut http6_next, &seen6);
            }
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
        self.presses.load(Ordering::SeqCst)
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

/// Кадр TCP нашего адаптера: семья, MAC назначения, адрес и порт источника, адрес и порт назначения, seq, ack, флаги.
type TcpOut = (bool, [u8; 6], Vec<u8>, u16, Vec<u8>, u16, u32, u32, u8);

fn tcp_out(f: &[u8]) -> TcpOut {
    let v6 = f[12..14] == [0x86, 0xdd];
    let (src, dst, tcp) = if v6 {
        (22..38, 38..54, 54)
    } else {
        (26..30, 30..34, 34)
    };
    let be32 = |i: usize| u32::from_be_bytes(f[i..i + 4].try_into().unwrap());
    (
        v6,
        f[0..6].try_into().unwrap(),
        f[src].to_vec(),
        u16::from_be_bytes([f[tcp], f[tcp + 1]]),
        f[dst].to_vec(),
        u16::from_be_bytes([f[tcp + 2], f[tcp + 3]]),
        be32(tcp + 4),
        be32(tcp + 8),
        f[tcp + 13],
    )
}

/// Р8 (`src/main.c:1094-1100`, справка A7): кадры адаптера скана это SYN (IPv4 и IPv6) и ровно один RST без состояния
/// на каждый ответ, той же семьи, на тот же MAC, адрес и порт назначения и с тех же адреса и порта источника, что его
/// SYN (C берёт их из ответа): seq = ack ответа (seq SYN + 1), ack 0, флаги `0x04`, после своего SYN. Фиктивная сеть
/// отвечает на каждый SYN. Возвращает SYN по порядку.
fn syns_and_one_rst_per_reply(frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let (mut syns, mut want, mut got) = (Vec::new(), Vec::new(), Vec::new());
    for f in frames {
        let (v6, mac, src, sport, dst, port, seq, ack, flags) = tcp_out(f);
        if flags == 0x02 {
            syns.push(f.clone());
            want.push((v6, mac, src, sport, dst, port, seq.wrapping_add(1)));
            continue;
        }
        assert_eq!((flags, ack), (0x04, 0), "only SYNs and stateless RSTs");
        let rst = (v6, mac, src, sport, dst, port, seq);
        assert!(want.contains(&rst), "an RST follows its SYN: {rst:?}");
        got.push(rst);
    }
    want.sort_unstable();
    got.sort_unstable();
    assert_eq!(got, want, "one RST per reply");
    syns
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

/// `--wait 10`, а не 1 (ревью задачи 14, I3): RST без состояния последнего ответа уходит из очереди TX в окне ожидания,
/// а часы `ManualClock` двигает опрос приёма; под нагрузкой окно в 1 с кончалось, пока TX стоял.
const LIVE6: [&str; 4] = ["2001:db8:9::1-2001:db8:9::2", "-p80,443", "--wait", "10"];

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
    let frames = scan.adapter.sent_frames();
    let syns = syns_and_one_rst_per_reply(&frames);
    assert_eq!(syns.len(), 4, "2 addresses x 2 ports");
    assert!(syns.iter().all(|f| is_syn6(f)), "only IPv6 SYNs");
    for f in &frames {
        assert_eq!(&f[12..14], &[0x86, 0xdd], "IPv6 SYNs and RSTs only");
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
            "10",
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
    // Р8: RST без состояния идёт той же семьёй и на тот же MAC, что SYN его ответа.
    let frames = opened[1].adapter.sent_frames();
    assert_eq!(syns_and_one_rst_per_reply(&frames).len(), 2);
    assert_eq!(frames.len(), 4);
    for f in &frames {
        if f[12..14] == [0x86, 0xdd] {
            assert_eq!(&f[0..6], &GIVEN_MAC, "IPv6 to --router-mac-ipv6");
        } else {
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

/// Р18 в фазе NDP: Ctrl-C, пока ждём Neighbor Advertisement, останавливает запуск так же, как в фазе ARP
/// (`early_stop`, C `main.c:1131-1154`): строка C, итог `Stopped`, exit 0, без отказа `NDP timed-out`; адаптер скана
/// не открывается, кроме одного NS ничего не уходит.
#[test]
fn interrupt_during_ndp_stops_before_the_scan_adapter() {
    let mut b = FakeBackend::new();
    b.press_during_ndp = true;
    let t0 = b.clock.now_micros();
    let (r, out, log) = cli(&b, &LIVE6);
    r.unwrap_or_else(|e| panic!("{e}\n{log}"));
    assert!(out.is_empty(), "{out:?}");
    assert!(!log.contains("timed-out"), "{log}");
    assert_eq!(
        log.matches("waiting several seconds to exit...").count(),
        1,
        "{log}"
    );
    assert_eq!(
        plus_lines(&log).last().map(String::as_str),
        Some("[+] finished: Stopped, sent 0, replies 0, open 0")
    );
    assert!(!log.contains("router-mac-ipv6"), "{log}");
    let opened = b.opened.lock().unwrap();
    assert_eq!(opened.len(), 1, "only the NDP adapter is opened");
    assert_eq!(opened[0].adapter.sent_frames().len(), 1, "one solicitation");
    assert!(
        b.tx.lock().unwrap().iter().all(|f| is_ns(f)),
        "no SYN leaves the host"
    );
    assert!(
        b.clock.now_micros() - t0 < 10_000_000,
        "the press ends NDP before the timeout"
    );
}

// ---------- TCP-баннеры поверх IPv6 (задача 14) ----------

/// ISN пира: тот же, что у `reply_to_syn6`.
const PEER_ISN: u32 = 0x0bad_f00d;

fn is_tcp6(f: &[u8]) -> bool {
    f.len() >= 74 && f[12..14] == [0x86, 0xdd] && f[20] == 6
}

/// Сегмент пира поверх IPv6 в ответ на наш кадр: MAC, адреса и порты наоборот, hop limit 64, сумма TCP по RFC 8200.
fn peer_frame6(ours: &[u8], flags: u8, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
    let me = u128::from_be_bytes(ours[22..38].try_into().unwrap());
    let them = u128::from_be_bytes(ours[38..54].try_into().unwrap());
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&ours[56..58]);
    t[2..4].copy_from_slice(&ours[54..56]);
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 5 << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&1024u16.to_be_bytes());
    t.extend_from_slice(payload);
    let c = rmasscan_core::checksum::checksum_ipv6(them, me, 6, &t);
    t[16..18].copy_from_slice(&c.to_be_bytes());
    let mut f = Vec::new();
    f.extend_from_slice(&ours[6..12]);
    f.extend_from_slice(&ours[0..6]);
    f.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    f.extend_from_slice(&(t.len() as u16).to_be_bytes());
    f.extend_from_slice(&[6, 64]);
    f.extend_from_slice(&them.to_be_bytes());
    f.extend_from_slice(&me.to_be_bytes());
    f.extend_from_slice(&t);
    f
}

/// Сервер HTTP на порту 80 поверх IPv6 (одно соединение): SYN-ACK, на наш первый сегмент с данными `body` и FIN, на
/// наш FIN голый ACK; прочие порты RST. Записывает наши кадры после SYN.
fn http6_peer(
    f: &[u8],
    body: &[u8],
    next: &mut Option<u32>,
    seen: &Mutex<Vec<Seen6>>,
) -> Vec<Vec<u8>> {
    let plen = usize::from(u16::from_be_bytes([f[18], f[19]]));
    let doff = usize::from(f[54 + 12] >> 4) * 4;
    let flags = f[54 + 13];
    let be32 = |i: usize| u32::from_be_bytes(f[i..i + 4].try_into().unwrap());
    let (seq, ack) = (be32(58), be32(62));
    let payload = f[54 + doff..54 + plen].to_vec();
    if flags == 0x02 {
        if u16::from_be_bytes([f[56], f[57]]) != 80 {
            return reply_to_syn6(f, 0x04).into_iter().collect();
        }
        *next = Some(PEER_ISN.wrapping_add(1));
        return reply_to_syn6(f, 0x12).into_iter().collect();
    }
    let mut log = seen.lock().unwrap();
    let first_data = !payload.is_empty() && log.iter().all(|s| s.3.is_empty());
    log.push((flags, seq, ack, payload.clone()));
    let Some(n) = *next else { return vec![] };
    let ours = seq.wrapping_add(payload.len() as u32);
    if first_data {
        *next = Some(n.wrapping_add(body.len() as u32 + 1));
        return vec![
            peer_frame6(f, 0x18, n, ours, body),
            peer_frame6(f, 0x11, n.wrapping_add(body.len() as u32), ours, &[]),
        ];
    }
    if flags & 0x01 != 0 {
        return vec![peer_frame6(f, 0x10, n, seq.wrapping_add(1), &[])];
    }
    vec![]
}

/// Баннеры по IPv6 (Р16, справка A10): тот же сценарий HTTP, что по IPv4 (эталон C `http-gws`: `http.server`, `title`,
/// `http` в порядке banout), hello порта 80 через 2 с, наш FIN после FIN сервера; записи с адресом IPv6. Окно
/// `--wait 20` и допуск повтора hello по правилу сценариев `live_fake.rs` (ревью задачи 14, I3): часы движка двигает
/// опрос приёма, и под нагрузкой TX может опоздать с hello на тик повтора.
#[test]
fn live_fake_ipv6_banner() {
    let golden = |rel: &str| {
        std::fs::read_to_string(format!(
            "{}/../../tests/golden/tcp-banners/{rel}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let unhex = |s: &str| -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    };
    let input = golden("cases/http-gws.in.txt");
    let stream: Vec<u8> = input
        .lines()
        .filter_map(|l| l.strip_prefix("segment "))
        .flat_map(unhex)
        .collect();
    assert!(golden("cases/http-gws.out").contains(
        "run whole calls=1\napp_proto 4\nrecord 31 3 \"gws\"\nrecord 17 1 \"x\"\nrecord 4 31 =stream\nend"
    ));
    let hello = golden("hellos.out")
        .lines()
        .find(|l| l.starts_with("hello port=80 "))
        .map(|l| unhex(l.rsplit(' ').next().unwrap()))
        .unwrap();
    let mut b = FakeBackend::new();
    b.http6 = Some(stream.clone());
    let (r, out, log) = cli(
        &b,
        &[
            "2001:db8:9::1",
            "-p80",
            "--banners",
            "--wait",
            "20",
            "-oL",
            "-",
        ],
    );
    r.unwrap();
    assert!(
        log.contains("finished: Completed, sent 1, replies 1, open 1"),
        "{log}"
    );
    let header = String::from_utf8_lossy(&stream[..31])
        .replace('\r', "\\x0d")
        .replace('\n', "\\x0a");
    let ip = "2001:db8:9::1";
    assert_eq!(
        out,
        format!(
            "#masscan\nopen tcp 80 {ip} {UNIX_TIME}\n\
             banner tcp 80 {ip} {UNIX_TIME} http.server gws\n\
             banner tcp 80 {ip} {UNIX_TIME} title x\n\
             banner tcp 80 {ip} {UNIX_TIME} http {header}\n# end\n"
        )
    );
    let seen = b.seen6.lock().unwrap().clone();
    assert_eq!((seen[0].0, seen[0].2), (0x10, PEER_ISN + 1), "{seen:?}");
    let data: Vec<&Vec<u8>> = seen
        .iter()
        .map(|s| &s.3)
        .filter(|p| !p.is_empty())
        .collect();
    assert!(!data.is_empty(), "{seen:?}");
    assert!(
        data.iter().all(|p| **p == hello),
        "only the C hello of port 80 (a retransmission allowed): {seen:?}"
    );
    assert!(seen.iter().any(|s| s.0 & 0x01 != 0), "our FIN: {seen:?}");
    assert!(seen.iter().all(|s| s.0 & 0x04 == 0), "{seen:?}");
}

/// Р9 (решение D19): одна строка на скан на любой ОС, если `--banners`, хотя бы один порт TCP и хотя бы один адрес
/// источника выбран автоопределением, с этими адресами через ` and ` (IPv6 в скобках, как в `[+] source-ip`); с
/// заданными `--adapter-ip` (обе семьи) строки нет, без `--banners` тоже. Скан только UDP с `--banners` или
/// `--rawudp` (ревью задачи 14, решение по замечанию 1): ядро баннерам UDP не мешает, строки нет, и stderr тот же, что
/// у 4a, то есть строки `[…]` те же, что у того же скана без баннеров; с портом TCP рядом с UDP строка есть.
#[test]
fn banners_warning_once_for_os_owned_source() {
    let warning = |ips: &str| {
        format!(
            "[-] warning: --banners uses the OS's own address {ips}: its kernel resets the banner \
             connections; give --adapter-ip an unused address on the subnet or drop the --source-port \
             traffic in the firewall\n"
        )
    };
    let run = |args: &[&str]| {
        let b = FakeBackend::new();
        let (r, _, log) = cli(&b, args);
        r.unwrap_or_else(|e| panic!("{args:?}: {e}"));
        log
    };
    let v4 = ["198.51.100.1", "-p80", "--wait", "1", "--banners"];
    let v6 = ["2001:db8:9::1", "-p80", "--wait", "1", "--banners"];
    let mixed = [
        "198.51.100.1",
        "2001:db8:9::1",
        "-p80",
        "--wait",
        "1",
        "--banners",
    ];
    for (args, ips) in [
        (&v4[..], "192.0.2.5"),
        (&v6[..], "[2001:db8:1::5]"),
        (&mixed[..], "192.0.2.5 and [2001:db8:1::5]"),
    ] {
        let log = run(args);
        assert_eq!(
            log.matches("[-] warning: --banners").count(),
            1,
            "{args:?}: {log}"
        );
        assert!(log.contains(&warning(ips)), "{args:?}: {log}");
        // После строк обнаружения адаптера, до ARP/NDP и строк `seed` и `source-port`.
        assert!(
            log.find(&warning(ips)).unwrap() < log.find("[+] seed = ").unwrap(),
            "{log}"
        );
    }
    // Один адрес задан, другой найден: в строке только найденный.
    let log = run(&with(&mixed, &["--adapter-ip", "192.0.2.5"]));
    assert!(log.contains(&warning("[2001:db8:1::5]")), "{log}");
    let given = [
        &with(&v4, &["--adapter-ip", "192.0.2.77"])[..],
        &with(&v6, &["--adapter-ip", "2001:db8:1::77"]),
        &with(
            &mixed,
            &["--adapter-ip", "192.0.2.5", "--adapter-ip[0]=2001:db8:1::5"],
        ),
        &["198.51.100.1", "2001:db8:9::1", "-p80", "--wait", "1"],
    ];
    for args in given {
        let log = run(args);
        assert!(!log.contains("[-] warning"), "{args:?}: {log}");
    }
    // Строки `[+]`/`[-]` stderr (строка статуса стёрта `\r`, поэтому режем и по нему).
    let bracketed = |log: &str| -> Vec<String> {
        log.split(['\r', '\n'])
            .filter(|l| l.starts_with('['))
            .map(str::to_string)
            .collect()
    };
    let udp = ["198.51.100.1", "-pU:53", "--wait", "1"];
    let plain = bracketed(&run(&udp));
    for flag in ["--banners", "--rawudp"] {
        let log = run(&with(&udp, &[flag]));
        assert!(!log.contains("[-] warning"), "{flag}: {log}");
        assert!(!log.contains("[-] banners:"), "{flag}: {log}");
        assert_eq!(bracketed(&log), plain, "{flag}: stderr as in 4a: {log}");
    }
    let log = run(&["198.51.100.1", "-pU:53,T:80", "--wait", "1", "--banners"]);
    assert_eq!(log.matches("[-] warning: --banners").count(), 1, "{log}");
    assert!(log.contains(&warning("192.0.2.5")), "{log}");
}

fn with<'a>(base: &[&'a str], extra: &[&'a str]) -> Vec<&'a str> {
    base.iter().chain(extra).copied().collect()
}
