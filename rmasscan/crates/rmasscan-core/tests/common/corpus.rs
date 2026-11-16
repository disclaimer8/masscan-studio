//! Входы корпусов страховки рефакторинга (AGPL-3.0, masscan © Robert David Graham): детерминированный генератор
//! `XorShift64Star`, построители строк целей и портов, файлов nmap-payloads и pcap, списков диапазонов, ответов на
//! зонды и кадров NDP. Суммы ответов считает [`rfc1071`] этого файла, а не ядро: ответ не должен зависеть от кода,
//! который меняет рефакторинг. CRC SCTP берётся из `checksum::sctp_crc32c` (его план не меняет).
#![allow(dead_code)]

use std::net::Ipv4Addr;

use rmasscan_core::arp;
use rmasscan_core::checksum::sctp_crc32c;
use rmasscan_core::massip::TargetIp;
use rmasscan_core::ndp;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::Probe;
use rmasscan_core::targets::{
    TEMPL_ARP, TEMPL_ICMP_ECHO, TEMPL_SCTP, TEMPL_SCTP_LAST, TEMPL_UDP, TEMPL_UDP_LAST,
};

/// xorshift64* (Vigna): `x ^= x >> 12; x ^= x << 25; x ^= x >> 27; x * 0x2545F4914F6CDD1D`.
pub struct XorShift64Star {
    s: u64,
}

impl XorShift64Star {
    /// Нулевое состояние у xorshift неподвижно, поэтому seed 0 заменяется константой.
    pub fn new(seed: u64) -> Self {
        XorShift64Star {
            s: if seed == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seed
            },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.s;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.s = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// `next_u64() % n`, `n > 0`.
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "below(0)");
        self.next_u64() % n
    }

    /// Старший байт `next_u64()`.
    pub fn byte(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }

    pub fn u128(&mut self) -> u128 {
        (u128::from(self.next_u64()) << 64) | u128::from(self.next_u64())
    }

    pub fn fill(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

/// Сумма RFC 1071 над склейкой частей (как один поток байт; нечётный хвост дополняется нулём), уже инвертированная:
/// значение для поля суммы при нулевом поле.
pub fn rfc1071(parts: &[&[u8]]) -> u16 {
    let mut sum: u64 = 0;
    let mut high: Option<u8> = None;
    for part in parts {
        for &b in *part {
            match high.take() {
                None => high = Some(b),
                Some(h) => sum += u64::from(u16::from_be_bytes([h, b])),
            }
        }
    }
    if let Some(h) = high {
        sum += u64::from(h) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// --- цели и порты ---

fn ipv4_text(rng: &mut XorShift64Star) -> String {
    let o: Vec<u64> = (0..4).map(|_| rng.below(256)).collect();
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

/// Два значения; в трёх случаях из четырёх по возрастанию, иначе как выпали (диапазон бывает обратным).
fn ordered(rng: &mut XorShift64Star, a: u64, b: u64) -> (u64, u64) {
    if rng.below(4) != 0 {
        (a.min(b), a.max(b))
    } else {
        (a, b)
    }
}

/// Номер токена по весам `weights` (сумма весов это знаменатель).
fn weighted(rng: &mut XorShift64Star, weights: &[u64]) -> usize {
    let mut x = rng.below(weights.iter().sum());
    for (i, &w) in weights.iter().enumerate() {
        if x < w {
            return i;
        }
        x -= w;
    }
    unreachable!()
}

/// Веса токенов [`target_string`] по порядку ветвей: адреса и разделители чаще, заведомо плохие токены реже.
const TARGET_WEIGHTS: [u64; 15] = [6, 1, 1, 1, 3, 1, 1, 1, 2, 1, 1, 8, 4, 2, 1];

/// 1–8 токенов подряд, без разделителей между ними (разделители `,`, пробел и таб сами токены).
pub fn target_string(rng: &mut XorShift64Star) -> String {
    let mut s = String::new();
    for _ in 0..1 + rng.below(8) {
        match weighted(rng, &TARGET_WEIGHTS) {
            0 => s.push_str(&ipv4_text(rng)),
            1 => s.push_str("/8"),
            2 => s.push_str("/31"),
            3 => s.push_str("/33"),
            4 => {
                let (a, b) = (rng.next_u64() as u32, rng.next_u64() as u32);
                let (a, b) = ordered(rng, u64::from(a), u64::from(b));
                let (a, b) = (Ipv4Addr::from(a as u32), Ipv4Addr::from(b as u32));
                s.push_str(&format!("{a}-{b}"));
            }
            5 => s.push_str("0.0.0.0/31"),
            6 => s.push_str("::1"),
            7 => s.push_str("2001:db8::/120"),
            8 => {
                let (a, b) = (rng.below(0x1_0000), rng.below(0x1_0000));
                let (a, b) = ordered(rng, a, b);
                s.push_str(&format!("2001:db8::{a:x}-2001:db8::{b:x}"));
            }
            9 => s.push_str("1.2.3"),
            10 => s.push_str("300.1.1.1"),
            11 => s.push(','),
            12 => s.push(' '),
            13 => s.push('\t'),
            _ => s.push(char::from(rng.below(128) as u8)),
        }
    }
    s
}

const PORT_TOKENS: [&str; 17] = [
    "80", "0", "65535", "65536", "1-1024", "T:80", "U:53", "U:", "S:2905", "I:0", "I:2", "O:6",
    "I:600", ",", "-", " ", "x",
];

/// Веса [`PORT_TOKENS`] и последним случайного байта: порты и `,` чаще, `-`, `x` и случайный байт реже.
const PORT_WEIGHTS: [u64; 18] = [3, 1, 1, 1, 2, 2, 2, 1, 2, 2, 1, 1, 1, 8, 1, 1, 1, 1];

/// 1–6 токенов из [`PORT_TOKENS`] и случайного байта ASCII.
pub fn port_string(rng: &mut XorShift64Star) -> String {
    let mut s = String::new();
    for _ in 0..1 + rng.below(6) {
        let k = weighted(rng, &PORT_WEIGHTS);
        match PORT_TOKENS.get(k) {
            Some(t) => s.push_str(t),
            None => s.push(char::from(rng.below(128) as u8)),
        }
    }
    s
}

// --- nmap-payloads и pcap ---

const NMAP_LINES: [&[u8]; 9] = [
    br#"udp 53 "\x00\x01abc""#,
    br#"udp 1-3,7 "a\8\9\0\x4""#,
    b"# comment line",
    b"source 53",
    br#"udp U:5 "q""#,
    br#"tcp 80 "x""#,
    b"",
    b"udp 53",
    br#""unterminated \x4"#,
];

/// 1–10 строк из [`NMAP_LINES`] и случайной строки (0–23 байт без `\n`), через `\n`.
pub fn nmap_file(rng: &mut XorShift64Star) -> Vec<u8> {
    let mut out = Vec::new();
    for k in 0..1 + rng.below(10) {
        if k > 0 {
            out.push(b'\n');
        }
        let i = rng.below(NMAP_LINES.len() as u64 + 1) as usize;
        match NMAP_LINES.get(i) {
            Some(l) => out.extend_from_slice(l),
            None => {
                for _ in 0..rng.below(24) {
                    let b = rng.byte();
                    out.push(if b == b'\n' { b' ' } else { b });
                }
            }
        }
    }
    out
}

fn mac(rng: &mut XorShift64Star) -> [u8; 6] {
    let mut m = [0u8; 6];
    for b in &mut m {
        *b = rng.byte();
    }
    m
}

fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = dst.to_vec();
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Пакет IPv4 без опций, DF, с верной суммой заголовка.
pub fn ipv4(src: u32, dst: u32, proto: u8, ttl: u8, id: u16, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![0u8; 20];
    h[0] = 0x45;
    h[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    h[4..6].copy_from_slice(&id.to_be_bytes());
    h[6] = 0x40;
    h[8] = ttl;
    h[9] = proto;
    h[12..16].copy_from_slice(&src.to_be_bytes());
    h[16..20].copy_from_slice(&dst.to_be_bytes());
    let c = rfc1071(&[&h]);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

/// Пакет IPv6 (traffic class и flow label нулевые).
pub fn ipv6(src: u128, dst: u128, next: u8, hop: u8, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![0x60, 0, 0, 0];
    h.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    h.push(next);
    h.push(hop);
    h.extend_from_slice(&src.to_be_bytes());
    h.extend_from_slice(&dst.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

fn pseudo4(src: u32, dst: u32, proto: u8, len: usize) -> Vec<u8> {
    let mut p = src.to_be_bytes().to_vec();
    p.extend_from_slice(&dst.to_be_bytes());
    p.push(0);
    p.push(proto);
    p.extend_from_slice(&(len as u16).to_be_bytes());
    p
}

fn pseudo6(src: u128, dst: u128, next: u8, len: usize) -> Vec<u8> {
    let mut p = src.to_be_bytes().to_vec();
    p.extend_from_slice(&dst.to_be_bytes());
    p.extend_from_slice(&(len as u32).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, next]);
    p
}

/// Заголовок TCP без опций; сумма по псевдозаголовку `pseudo` (длина сегмента уже в нём).
#[allow(clippy::too_many_arguments)]
fn tcp_header(
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    pseudo: impl Fn(usize) -> Vec<u8>,
) -> Vec<u8> {
    let mut s = vec![0u8; 20];
    s[0..2].copy_from_slice(&sport.to_be_bytes());
    s[2..4].copy_from_slice(&dport.to_be_bytes());
    s[4..8].copy_from_slice(&seq.to_be_bytes());
    s[8..12].copy_from_slice(&ack.to_be_bytes());
    s[12] = 0x50;
    s[13] = flags;
    s[14..16].copy_from_slice(&window.to_be_bytes());
    s.extend_from_slice(payload);
    let c = rfc1071(&[&pseudo(s.len()), &s]);
    s[16..18].copy_from_slice(&c.to_be_bytes());
    s
}

fn udp_v4(src: u32, dst: u32, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut s = sport.to_be_bytes().to_vec();
    s.extend_from_slice(&dport.to_be_bytes());
    s.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    s.extend_from_slice(&[0, 0]);
    s.extend_from_slice(payload);
    let c = match rfc1071(&[&pseudo4(src, dst, 17, s.len()), &s]) {
        0 => 0xffff,
        c => c,
    };
    s[6..8].copy_from_slice(&c.to_be_bytes());
    s
}

fn pcap_frame(rng: &mut XorShift64Star) -> Vec<u8> {
    let (dst, src) = (mac(rng), mac(rng));
    let (ip_src, ip_dst) = (rng.next_u64() as u32, rng.next_u64() as u32);
    let (sport, dport) = (rng.next_u64() as u16, rng.next_u64() as u16);
    let len = rng.below(41) as usize;
    let payload = rng.fill(len);
    match rng.below(4) {
        0 | 1 => {
            let udp = udp_v4(ip_src, ip_dst, sport, dport, &payload);
            eth(dst, src, 0x0800, &ipv4(ip_src, ip_dst, 17, 64, 1, &udp))
        }
        2 => {
            let seg = tcp_header(sport, dport, 1, 2, 0x18, 512, &payload, |n| {
                pseudo4(ip_src, ip_dst, 6, n)
            });
            eth(dst, src, 0x0800, &ipv4(ip_src, ip_dst, 6, 64, 1, &seg))
        }
        _ => {
            let (a, b) = (rng.u128(), rng.u128());
            let mut udp = sport.to_be_bytes().to_vec();
            udp.extend_from_slice(&dport.to_be_bytes());
            udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            udp.extend_from_slice(&[0, 0]);
            udp.extend_from_slice(&payload);
            eth(dst, src, 0x86dd, &ipv6(a, b, 17, 64, &udp))
        }
    }
}

/// Файл pcap: глобальный заголовок (порядок байт BE или LE, linktype 1, 0, 12 или случайный), 1–5 записей (UDP
/// поверх IPv4 и IPv6, TCP; каждая четвёртая обрезана до случайной `caplen` при полной `origlen`), иногда обрезанный
/// хвост файла, затем 0–3 случайные замены байтов.
pub fn pcap_file(rng: &mut XorShift64Star) -> Vec<u8> {
    let big = rng.below(2) == 0;
    let w16 = |v: &mut Vec<u8>, x: u16| {
        v.extend_from_slice(&if big {
            x.to_be_bytes()
        } else {
            x.to_le_bytes()
        })
    };
    let w32 = |v: &mut Vec<u8>, x: u32| {
        v.extend_from_slice(&if big {
            x.to_be_bytes()
        } else {
            x.to_le_bytes()
        })
    };
    let mut f = Vec::new();
    w32(&mut f, 0xa1b2_c3d4);
    w16(&mut f, 2);
    w16(&mut f, 4);
    w32(&mut f, 0);
    w32(&mut f, 0);
    w32(&mut f, 65535);
    let link = match rng.below(4) {
        0 => 1,
        1 => 0,
        2 => 12,
        _ => rng.next_u64() as u32,
    };
    w32(&mut f, link);
    for _ in 0..1 + rng.below(5) {
        let mut frame = pcap_frame(rng);
        let orig = frame.len();
        if rng.below(4) == 0 {
            frame.truncate(rng.below(orig as u64 + 1) as usize);
        }
        w32(&mut f, rng.below(1 << 31) as u32);
        w32(&mut f, rng.below(1_000_000) as u32);
        w32(&mut f, frame.len() as u32);
        w32(&mut f, orig as u32);
        f.extend_from_slice(&frame);
    }
    if rng.below(8) == 0 {
        let cut = rng.below(20) as usize;
        f.truncate(f.len() - cut);
    }
    for _ in 0..rng.below(4) {
        let i = rng.below(f.len() as u64) as usize;
        f[i] = rng.byte();
    }
    f
}

/// 0–4 случайные замены байтов, затем обрезка до случайной длины `0..=len`.
pub fn snmp_input(base: &[u8], rng: &mut XorShift64Star) -> Vec<u8> {
    let mut px = base.to_vec();
    for _ in 0..rng.below(5) {
        let i = rng.below(px.len() as u64) as usize;
        px[i] = rng.byte();
    }
    px.truncate(rng.below(px.len() as u64 + 1) as usize);
    px
}

// --- списки диапазонов ---

/// Вход корпуса `ranges`: добавления (иногда `begin > end`), сортировка, исключения (иногда от `0.0.0.0`) и 16
/// случайных значений для `is_contains`.
pub struct RangesInput {
    pub adds: Vec<(u32, u32)>,
    pub sort: bool,
    pub excludes: Option<Vec<(u32, u32)>>,
    pub probes: Vec<u32>,
}

fn v32(rng: &mut XorShift64Star) -> u32 {
    match rng.below(4) {
        0 => rng.below(64) as u32,
        1 => rng.below(1 << 16) as u32,
        2 => *rng.pick(&[0, 1, 2, u32::MAX - 1, u32::MAX]),
        _ => rng.next_u64() as u32,
    }
}

/// Диапазон; если вышел обратным, в трёх случаях из четырёх концы меняются местами.
fn range32(rng: &mut XorShift64Star) -> (u32, u32) {
    let b = v32(rng);
    let e = match rng.below(3) {
        0 => b.saturating_add(rng.below(64) as u32),
        1 => v32(rng),
        _ => b,
    };
    if b > e && rng.below(4) != 0 {
        (e, b)
    } else {
        (b, e)
    }
}

pub fn ranges_input(rng: &mut XorShift64Star) -> RangesInput {
    let adds = (0..1 + rng.below(30)).map(|_| range32(rng)).collect();
    let sort = rng.below(2) == 0;
    let excludes = (rng.below(4) != 0).then(|| {
        let mut ex: Vec<(u32, u32)> = (0..rng.below(9)).map(|_| range32(rng)).collect();
        if rng.below(3) == 0 {
            // исключение от 0.0.0.0: накрывает цель целиком и оставляет `{2,1}` (massip-rangesv4.c:766)
            ex.insert(0, (0, v32(rng)));
        }
        ex
    });
    let probes = (0..16).map(|_| v32(rng)).collect();
    RangesInput {
        adds,
        sort,
        excludes,
        probes,
    }
}

/// Вход корпуса `ranges6`: добавления (иногда `begin > end`), сортировка, 1–300 исключений (всегда `begin <= end`:
/// обратное исключение, которое делит последний диапазон, зацикливает `remove_range`: верхняя половина сливается с
/// усечённой целью и воссоздаёт её), `::` и `ffff:…:ffff` на краях.
pub struct Ranges6Input {
    pub adds: Vec<(u128, u128)>,
    pub sort: bool,
    pub excludes: Vec<(u128, u128)>,
    pub probes: Vec<u128>,
}

fn v128(rng: &mut XorShift64Star) -> u128 {
    match rng.below(5) {
        0 => u128::from(rng.below(300)),
        1 => u128::MAX - u128::from(rng.below(300)),
        2 => (0x2001_0db8u128 << 96) | u128::from(rng.below(1 << 16)),
        3 => *rng.pick(&[0, 1, u128::MAX - 1, u128::MAX]),
        _ => rng.u128(),
    }
}

fn range128(rng: &mut XorShift64Star) -> (u128, u128) {
    let b = v128(rng);
    let e = match rng.below(3) {
        0 => b.saturating_add(u128::from(rng.below(300))),
        1 => v128(rng),
        _ => b,
    };
    (b, e)
}

pub fn ranges6_input(rng: &mut XorShift64Star) -> Ranges6Input {
    let adds = (0..1 + rng.below(30))
        .map(|_| {
            let (b, e) = range128(rng);
            if b > e && rng.below(4) != 0 {
                (e, b)
            } else {
                (b, e)
            }
        })
        .collect();
    let sort = rng.below(2) == 0;
    // Узкие исключения (до 8 адресов) пробивают дыры и делят диапазоны; от `::` и до `ffff:…:ffff` по 1/32;
    // широкое (между двумя случайными значениями) только первым и в четверти входов, иначе список почти всегда пуст.
    let excludes = (0..1 + rng.below(300))
        .map(|i| {
            if i == 0 && rng.below(4) == 0 {
                let (b, e) = (v128(rng), v128(rng));
                return (b.min(e), b.max(e));
            }
            match rng.below(32) {
                0 => (0, u128::from(rng.below(300))),
                1 => (u128::MAX - u128::from(rng.below(300)), u128::MAX),
                _ => {
                    let b = v128(rng);
                    (b, b.saturating_add(u128::from(rng.below(8))))
                }
            }
        })
        .collect();
    let probes = (0..16).map(|_| v128(rng)).collect();
    Ranges6Input {
        adds,
        sort,
        excludes,
        probes,
    }
}

// --- ответы на зонды ---

/// Смещение IPv4/IPv6 в кадре зонда: Ethernet 14, Null 4, Raw 0.
pub fn ip_offset(link: LinkType) -> usize {
    match link {
        LinkType::Ethernet => 14,
        LinkType::Null => 4,
        LinkType::Raw => 0,
    }
}

/// Кадр ответа на зонд: Ethernet от MAC назначения зонда к его MAC источника (набивка нулями до 60 байт), Null с
/// `AF_INET` 2 в порядке LE (как шаблон зонда на всех целевых платформах), Raw без заголовка.
fn reply_frame(link: LinkType, probe_frame: &[u8], ethertype: u16, ip: &[u8]) -> Vec<u8> {
    match link {
        LinkType::Ethernet => {
            let mut f = probe_frame[6..12].to_vec();
            f.extend_from_slice(&probe_frame[0..6]);
            f.extend_from_slice(&ethertype.to_be_bytes());
            f.extend_from_slice(ip);
            if f.len() < 60 {
                f.resize(60, 0);
            }
            f
        }
        LinkType::Null => {
            let mut f = vec![2, 0, 0, 0];
            f.extend_from_slice(ip);
            f
        }
        LinkType::Raw => ip.to_vec(),
    }
}

/// ICMP 3/3 с цитатой заголовка IPv4 зонда и 8 байт за ним.
fn port_unreachable(p: &Probe, link: LinkType, them: u32, rng: &mut XorShift64Star) -> Vec<u8> {
    let off = ip_offset(link);
    let ihl = usize::from(p.frame[off] & 0x0f) * 4;
    let mut msg = vec![3, 3, 0, 0, 0, 0, 0, 0];
    msg.extend_from_slice(&p.frame[off..(off + ihl + 8).min(p.frame.len())]);
    let c = rfc1071(&[&msg]);
    msg[2..4].copy_from_slice(&c.to_be_bytes());
    let ip = ipv4(them, p.ip_me, 1, 64, rng.next_u64() as u16, &msg);
    reply_frame(link, &p.frame, 0x0800, &ip)
}

fn swap_ranges(f: &mut [u8], a: usize, b: usize, n: usize) {
    for i in 0..n {
        f.swap(a + i, b + i);
    }
}

/// Кадр зонда с переставленными адресами (MAC, IP, порты L4; у ARP `sha/spa` с `tha/tpa`).
pub fn swapped_probe(p: &Probe, link: LinkType) -> Vec<u8> {
    let mut f = p.frame.clone();
    if p.port_index == TEMPL_ARP {
        swap_ranges(&mut f, 0, 6, 6);
        swap_ranges(&mut f, 22, 32, 10);
        return f;
    }
    if link == LinkType::Ethernet {
        swap_ranges(&mut f, 0, 6, 6);
    }
    let off = ip_offset(link);
    match p.target {
        TargetIp::V4(_) => {
            swap_ranges(&mut f, off + 12, off + 16, 4);
            let l4 = off + usize::from(f[off] & 0x0f) * 4;
            if matches!(f[off + 9], 6 | 17 | 132) {
                swap_ranges(&mut f, l4, l4 + 2, 2);
            }
        }
        TargetIp::V6(_) => {
            swap_ranges(&mut f, off + 8, off + 24, 16);
            if f[off + 6] == 6 {
                swap_ranges(&mut f, off + 40, off + 42, 2);
            }
        }
    }
    f
}

/// Настоящие ответы на зонд `p` с верными суммами и затем сам зонд с переставленными адресами:
/// - TCP: SYN-ACK и RST/ACK с `ack = seqno + 1` (IPv4 и IPv6), у IPv4 ещё ICMP 3/3;
/// - UDP: датаграмма с порта цели на порт зонда, ICMP 3/3;
/// - SCTP: INIT-ACK и ABORT с verification tag `seqno` (CRC `sctp_crc32c`), ICMP 3/3;
/// - ICMP Echo: эхо-ответ с тем же `[id|seq]` и данными;
/// - ARP: ответ `arp::encode_reply` от цели к адресу зонда.
pub fn replies(
    p: &Probe,
    link: LinkType,
    my_ipv6: Option<u128>,
    rng: &mut XorShift64Star,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let ack = p.seqno.wrapping_add(1);
    match p.target {
        TargetIp::V6(them) => {
            let me = my_ipv6.expect("an IPv6 probe comes from a plan with source_ipv6");
            for (flags, seq, window) in [(0x12, rng.next_u64() as u32, 65535), (0x14, 0, 0)] {
                let seg = tcp_header(p.port_them, p.port_me, seq, ack, flags, window, &[], |n| {
                    pseudo6(them, me, 6, n)
                });
                out.push(reply_frame(
                    link,
                    &p.frame,
                    0x86dd,
                    &ipv6(them, me, 6, 64, &seg),
                ));
            }
        }
        TargetIp::V4(them) => {
            let me = p.ip_me;
            let pi = p.port_index;
            let id = rng.next_u64() as u16;
            if pi == TEMPL_ARP {
                let mut sender = mac(rng);
                sender[0] &= 0xfe;
                let our: [u8; 6] = p.frame[6..12].try_into().expect("6 bytes");
                out.push(arp::encode_reply(sender, them, our, me).to_vec());
            } else if pi == TEMPL_ICMP_ECHO {
                let off = ip_offset(link);
                let ihl = usize::from(p.frame[off] & 0x0f) * 4;
                let total = usize::from(u16::from_be_bytes([p.frame[off + 2], p.frame[off + 3]]));
                let mut msg = p.frame[off + ihl..off + total].to_vec();
                msg[0] = 0;
                msg[2..4].fill(0);
                let c = rfc1071(&[&msg]);
                msg[2..4].copy_from_slice(&c.to_be_bytes());
                out.push(reply_frame(
                    link,
                    &p.frame,
                    0x0800,
                    &ipv4(them, me, 1, 64, id, &msg),
                ));
            } else if (TEMPL_UDP..=TEMPL_UDP_LAST).contains(&pi) {
                let len = rng.below(17) as usize;
                let payload = rng.fill(len);
                let udp = udp_v4(them, me, p.port_them, p.port_me, &payload);
                out.push(reply_frame(
                    link,
                    &p.frame,
                    0x0800,
                    &ipv4(them, me, 17, 64, id, &udp),
                ));
                out.push(port_unreachable(p, link, them, rng));
            } else if (TEMPL_SCTP..=TEMPL_SCTP_LAST).contains(&pi) {
                let init_ack = {
                    let mut c = vec![2, 0, 0, 20];
                    c.extend_from_slice(&(rng.next_u64() as u32).to_be_bytes());
                    c.extend_from_slice(&[0, 1, 0, 0, 0, 10, 0, 10]);
                    c.extend_from_slice(&(rng.next_u64() as u32).to_be_bytes());
                    c
                };
                for chunk in [init_ack, vec![6, 0, 0, 4]] {
                    let mut s = p.port_them.to_be_bytes().to_vec();
                    s.extend_from_slice(&p.port_me.to_be_bytes());
                    s.extend_from_slice(&p.seqno.to_be_bytes());
                    s.extend_from_slice(&[0, 0, 0, 0]);
                    s.extend_from_slice(&chunk);
                    let crc = sctp_crc32c(&s);
                    s[8..12].copy_from_slice(&crc.to_be_bytes());
                    out.push(reply_frame(
                        link,
                        &p.frame,
                        0x0800,
                        &ipv4(them, me, 132, 64, id, &s),
                    ));
                }
                out.push(port_unreachable(p, link, them, rng));
            } else {
                for (flags, seq, window) in [(0x12, rng.next_u64() as u32, 65535), (0x14, 0, 0)] {
                    let seg =
                        tcp_header(p.port_them, p.port_me, seq, ack, flags, window, &[], |n| {
                            pseudo4(them, me, 6, n)
                        });
                    out.push(reply_frame(
                        link,
                        &p.frame,
                        0x0800,
                        &ipv4(them, me, 6, 64, id, &seg),
                    ));
                }
                out.push(port_unreachable(p, link, them, rng));
            }
        }
    }
    out.push(swapped_probe(p, link));
    out
}

/// 1–3 случайные замены байтов; в половине случаев ещё обрезка до случайной длины `0..=len`.
pub fn mutate(frame: &[u8], rng: &mut XorShift64Star) -> Vec<u8> {
    let mut f = frame.to_vec();
    if !f.is_empty() {
        for _ in 0..1 + rng.below(3) {
            let i = rng.below(f.len() as u64) as usize;
            f[i] = rng.byte();
        }
    }
    if rng.below(2) == 0 {
        f.truncate(rng.below(f.len() as u64 + 1) as usize);
    }
    f
}

// --- NDP ---

fn v6_host(rng: &mut XorShift64Star) -> u128 {
    match rng.below(6) {
        0 => 0,
        1 => 0xff02_0000_0000_0000_0000_0000_0000_0001,
        2 => (0xfe80u128 << 112) | u128::from(rng.next_u64()),
        _ => rng.u128(),
    }
}

/// NS или NA от случайного соседа (MAC иногда multicast, адрес иногда `::` или `ff02::1`); NS спрашивает наш адрес
/// в половине случаев, NA адресован нам в половине случаев.
pub fn ndp_frame(our_mac: [u8; 6], our_ip: u128, rng: &mut XorShift64Star) -> Vec<u8> {
    let mut m = mac(rng);
    if rng.below(8) != 0 {
        m[0] &= 0xfe;
    }
    let ip = v6_host(rng);
    if rng.below(2) == 0 {
        let target = if rng.below(2) == 0 {
            our_ip
        } else {
            v6_host(rng)
        };
        ndp::encode_neighbor_solicitation(m, ip, target).to_vec()
    } else {
        let (dst_mac, dst_ip) = if rng.below(2) == 0 {
            (our_mac, our_ip)
        } else {
            (mac(rng), v6_host(rng))
        };
        ndp::encode_neighbor_advertisement(m, ip, dst_mac, dst_ip).to_vec()
    }
}
