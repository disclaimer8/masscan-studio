//! Эталонные копии функций, которые рефакторинг ядра перепишет (AGPL-3.0, порт masscan © Robert David Graham).
//! Тела скопированы дословно с базы `a275ea9e` (`rmasscan/crates/rmasscan-core/src/{checksum,cookie,blackrock,
//! packet}.rs`), переименованы и сделаны самостоятельными; диапазоны строк базы указаны у каждой копии. Копии ничего
//! не "улучшают": это оракул, и менять их после записи базы нельзя. Из ядра берётся только то, что план не меняет:
//! `blackrock::SBOX`, `packet::DEFAULT_*_TEMPLATE`, `PacketModifiers`, `TcpHeaderOptions`, `LinkType`,
//! `checksum::{word_sum, udp_ipv4_checksum, sctp_crc32c}`, `PayloadEntry::with_cookie`.
#![allow(dead_code)]

use rmasscan_core::blackrock::SBOX;
use rmasscan_core::checksum::{sctp_crc32c, udp_ipv4_checksum, word_sum};
use rmasscan_core::packet::{
    DEFAULT_ICMP_PING_TEMPLATE, DEFAULT_SCTP_INIT_TEMPLATE, DEFAULT_TCP_TEMPLATE,
    DEFAULT_UDP_TEMPLATE, LinkType, PacketModifiers, TcpHeaderOptions,
};
use rmasscan_core::payloads::PayloadEntry;
use siphasher::sip::SipHasher24;
use std::hash::Hasher;

/// `targets::TEMPL_ICMP_ECHO` (`65536 * 3`), targets.rs:30 на базе; числом, чтобы не зависеть от файла, который
/// план меняет.
const REF_TEMPL_ICMP_ECHO: u32 = 65536 * 3;

// ---------------------------------------------------------------------
// checksum.rs (база :8-80)
// ---------------------------------------------------------------------

/// Байт или 0 за границей буфера (C читает за границей без проверки). checksum.rs:8-10 на базе.
fn byte(buf: &[u8], i: usize) -> u32 {
    u32::from(buf.get(i).copied().unwrap_or(0))
}

/// Слово big-endian `buf[i]<<8 | buf[i+1]`. checksum.rs:13-15 на базе.
fn be16(buf: &[u8], i: usize) -> u32 {
    byte(buf, i) << 8 | byte(buf, i + 1)
}

/// `ip_header_checksum`, checksum.rs:36-50 на базе.
pub fn ref_ip_header_checksum(px: &[u8], offset_ip: usize, max: usize) -> u16 {
    let header_length = ((byte(px, offset_ip) & 0xF) * 4) as usize;
    let max = max.min(offset_ip + header_length);
    let mut xsum = 0u32;
    let mut i = offset_ip;
    while i < max {
        xsum = xsum.wrapping_add(be16(px, i));
        i += 2;
    }
    // Три свёртки, как в C (:200-202).
    for _ in 0..3 {
        xsum = (xsum & 0xFFFF) + (xsum >> 16);
    }
    xsum as u16
}

/// `fold`, checksum.rs:56-62 на базе.
pub fn ref_fold(sum: u64) -> u16 {
    let mut x = sum;
    for _ in 0..3 {
        x = (x >> 16) + (x & 0xFFFF);
    }
    x as u16
}

/// `tcp_ipv4_partial`, checksum.rs:68-80 на базе.
pub fn ref_tcp_ipv4_partial(
    px: &[u8],
    offset_ip: usize,
    offset_tcp: usize,
    offset_app: usize,
) -> u16 {
    let mut xsum = 6u32;
    xsum = xsum.wrapping_add(offset_app.wrapping_sub(offset_tcp) as u32);
    for k in [12, 14, 16, 18] {
        xsum = xsum.wrapping_add(be16(px, offset_ip + k));
    }
    let mut i = offset_tcp;
    while i < offset_app {
        xsum = xsum.wrapping_add(be16(px, i));
        i += 2;
    }
    ref_fold(u64::from(xsum))
}

// ---------------------------------------------------------------------
// cookie.rs (база :11-68)
// ---------------------------------------------------------------------

/// `siphash24`, cookie.rs:11-15 на базе.
pub fn ref_siphash24(data: &[u8], k0: u64, k1: u64) -> u64 {
    let mut h = SipHasher24::new_with_keys(k0, k1);
    h.write(data);
    h.finish()
}

/// `syn_cookie_ipv4`, cookie.rs:18-36 на базе.
pub fn ref_syn_cookie_ipv4(
    ip_them: u32,
    port_them: u32,
    ip_me: u32,
    port_me: u32,
    entropy: u64,
) -> u64 {
    let mut data = [0u8; 16];
    data[0..4].copy_from_slice(&ip_them.to_le_bytes());
    data[4..8].copy_from_slice(&port_them.to_le_bytes());
    data[8..12].copy_from_slice(&ip_me.to_le_bytes());
    data[12..16].copy_from_slice(&port_me.to_le_bytes());
    // x[0] = x[1] = entropy (syn-cookie.c:142-143).
    ref_siphash24(&data, entropy, entropy)
}

/// `syn_cookie_ipv6`, cookie.rs:46-61 на базе.
pub fn ref_syn_cookie_ipv6(
    ip_them: u128,
    port_them: u32,
    ip_me: u128,
    port_me: u32,
    entropy: u64,
) -> u64 {
    let mut data = [0u8; 40];
    data[0..8].copy_from_slice(&((ip_them >> 64) as u64).to_le_bytes());
    data[8..16].copy_from_slice(&(ip_them as u64).to_le_bytes());
    data[16..24].copy_from_slice(&((ip_me >> 64) as u64).to_le_bytes());
    data[24..32].copy_from_slice(&(ip_me as u64).to_le_bytes());
    let ports = (port_them << 16) | port_me;
    data[32..40].copy_from_slice(&u64::from(ports).to_le_bytes());
    ref_siphash24(&data, entropy, entropy)
}

/// `icmp_echo_cookie`, cookie.rs:66-68 на базе (через `ref_syn_cookie_ipv4`).
pub fn ref_icmp_echo_cookie(ip_them: u32, ip_me: u32, entropy: u64) -> u32 {
    ref_syn_cookie_ipv4(ip_them, REF_TEMPL_ICMP_ECHO, ip_me, 0, entropy) as u32
}

// ---------------------------------------------------------------------
// blackrock.rs (база :41-140 и :144-203)
// ---------------------------------------------------------------------

/// `BlackRock`, blackrock.rs:41-47 на базе.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefBlackRock {
    a: u64,
    b: u64,
    rounds: u32,
    seed: u64,
    range: u64,
}

impl RefBlackRock {
    /// `BlackRock::try_new` без ошибок, blackrock.rs:52-83 на базе (поля :41-47): `range == 0` и `rounds >= 64` запрещены
    /// вызывающим (в базе это `Err`).
    pub fn new(range: u64, seed: u64, rounds: u32) -> RefBlackRock {
        assert!(
            range != 0 && rounds < 64,
            "RefBlackRock: range 0 or rounds >= 64"
        );
        let root = (range as f64).sqrt();
        let (a, mut b) = match range {
            1 => (1, 1),
            2 => (1, 2),
            3 => (2, 2),
            4..=6 => (2, 3),
            7 | 8 => (3, 3),
            _ => ((root - 2.0) as u64, (root + 3.0) as u64),
        };
        while a.wrapping_mul(b) <= range {
            b = b.wrapping_add(1);
        }
        RefBlackRock {
            a,
            b,
            rounds,
            seed,
            range,
        }
    }

    /// `shuffle`, blackrock.rs:95-101 на базе.
    pub fn shuffle(&self, m: u64) -> u64 {
        let mut c = ref_encrypt(self.rounds, self.a, self.b, m, self.seed);
        while c >= self.range {
            c = ref_encrypt(self.rounds, self.a, self.b, c, self.seed);
        }
        c
    }

    /// `domain`, blackrock.rs:104-106 на базе.
    pub fn domain(&self) -> u64 {
        self.a.wrapping_mul(self.b)
    }

    /// `unshuffle`, blackrock.rs:134-140 на базе.
    pub fn unshuffle(&self, m: u64) -> u64 {
        let mut c = ref_unencrypt(self.rounds, self.a, self.b, m, self.seed);
        while c >= self.range {
            c = ref_unencrypt(self.rounds, self.a, self.b, c, self.seed);
        }
        c
    }
}

/// `read`, blackrock.rs:144-158 на базе.
fn ref_read(r: u64, big_r: u64, seed: u64) -> u64 {
    let big_r = big_r ^ (seed.wrapping_shl(r as u32) ^ seed.wrapping_shr((64 - r) as u32));
    let byte = |n: u32| -> usize { ((((big_r >> (n * 8)) ^ seed ^ r) & 0xFF) as u8) as usize };
    let s = |n: u32| -> u32 { SBOX[byte(n)] as u32 };
    let r0 = (s(0) as u64) | ((s(1) as u64) << 8);
    let r1 = (((s(2) as u64) << 16) | ((s(3) as u64) << 24)) & 0xffff_ffff;
    let r2 = (s(4) as u64) | ((s(5) as u64) << 8);
    let r3 = (((s(6) as u64) << 16) | ((s(7) as u64) << 24)) & 0xffff_ffff;
    r0 ^ r1 ^ r2.wrapping_shl(23) ^ r3.wrapping_shl(33)
}

/// `encrypt`, blackrock.rs:161-175 на базе.
fn ref_encrypt(r: u32, a: u64, b: u64, m: u64, seed: u64) -> u64 {
    let mut l = m % a;
    let mut rr = m / a;
    for j in 1..=r {
        let t = l.wrapping_add(ref_read(j as u64, rr, seed));
        let tmp = if j & 1 != 0 { t % a } else { t % b };
        l = rr;
        rr = tmp;
    }
    if r & 1 != 0 {
        a.wrapping_mul(l).wrapping_add(rr)
    } else {
        a.wrapping_mul(rr).wrapping_add(l)
    }
}

/// `unencrypt`, blackrock.rs:178-203 на базе.
fn ref_unencrypt(r: u32, a: u64, b: u64, m: u64, seed: u64) -> u64 {
    let (mut l, mut rr);
    if r & 1 != 0 {
        rr = m % a;
        l = m / a;
    } else {
        l = m % a;
        rr = m / a;
    }
    for j in (1..=r).rev() {
        let modulus = if j & 1 != 0 { a } else { b };
        let mut tmp = ref_read(j as u64, l, seed);
        if tmp > rr {
            tmp -= rr;
            tmp = modulus - (tmp % modulus);
            if tmp == modulus {
                tmp = 0;
            }
        } else {
            tmp = (rr - tmp) % modulus;
        }
        rr = l;
        l = tmp;
    }
    a.wrapping_mul(rr).wrapping_add(l)
}

// ---------------------------------------------------------------------
// packet.rs: общие части (база :87-120, :184-193)
// ---------------------------------------------------------------------

/// `tcp_option_bytes`, packet.rs:87-113 на базе.
fn ref_tcp_option_bytes(o: &TcpHeaderOptions) -> Vec<u8> {
    let mut b = Vec::new();
    if let Some(mss) = o.mss {
        b.extend_from_slice(&[2, 4]);
        b.extend_from_slice(&mss.to_be_bytes());
    }
    if o.sackok {
        b.extend_from_slice(&[4, 2]);
    }
    if let Some(ws) = o.wscale {
        b.extend_from_slice(&[3, 3, ws]);
    }
    if let Some(ts) = o.tsecho {
        b.extend_from_slice(&[8, 10]);
        b.extend_from_slice(&ts.to_be_bytes());
        b.extend_from_slice(&[0; 4]);
    }
    while b.len() % 4 != 0 {
        b.push(0);
    }
    b
}

/// `corrupt_tcp_checksum`, packet.rs:118-120 на базе.
fn ref_corrupt_tcp_checksum(csum: u16) -> u16 {
    if csum == 0 { 1 } else { csum - 1 }
}

/// Расклад канального уровня ("DATALINK KLUDGE", templ-pkt.c:1342-1360), packet.rs:184-193 (TCP), :453-462 (ICMP), :538-547 (UDP), :630-639 (SCTP) на базе: одинаков у TCP,
/// ICMP, UDP и SCTP (`px`, смещение IP, смещение L4).
fn ref_datalink(
    link: LinkType,
    px: Vec<u8>,
    offset_ip: usize,
    offset_l4: usize,
) -> (Vec<u8>, usize, usize) {
    match link {
        LinkType::Ethernet => (px, offset_ip, offset_l4),
        LinkType::Null => {
            let mut p = 2u32.to_ne_bytes().to_vec();
            p.extend_from_slice(&px[offset_ip..]);
            (p, 4, offset_l4 - (offset_ip - 4))
        }
        LinkType::Raw => (px[offset_ip..].to_vec(), 0, offset_l4 - offset_ip),
    }
}

// ---------------------------------------------------------------------
// TCP SYN (база packet.rs :123-203 и :223-263)
// ---------------------------------------------------------------------

/// `TcpSynTemplate`, packet.rs:124-131 на базе.
#[derive(Clone, Debug)]
pub struct RefTcpSyn {
    packet: Vec<u8>,
    offset_ip: usize,
    offset_tcp: usize,
    checksum_tcp: u16,
    badsum: bool,
}

impl RefTcpSyn {
    /// `TcpSynTemplate::new_with_options`, packet.rs:149-202 на базе.
    pub fn new(
        source_mac: [u8; 6],
        router_mac: [u8; 6],
        link: LinkType,
        mods: &PacketModifiers,
    ) -> Self {
        let mut px = DEFAULT_TCP_TEMPLATE[..54].to_vec();
        px.extend_from_slice(&ref_tcp_option_bytes(&mods.tcp));
        let (offset_ip, offset_tcp, offset_app) = (14usize, 34usize, px.len());
        let tcp_len = offset_app - offset_tcp;
        px[offset_ip + 2..offset_ip + 4]
            .copy_from_slice(&((offset_app - offset_ip) as u16).to_be_bytes());
        px[offset_tcp + 12] = ((tcp_len / 4) as u8) << 4;
        px[offset_ip + 8] = mods.ttl;

        px[0..6].copy_from_slice(&router_mac);
        px[6..12].copy_from_slice(&source_mac);

        px[offset_ip + 4..offset_ip + 6].fill(0);
        px[offset_ip + 10..offset_ip + 12].fill(0);
        px[offset_ip + 12..offset_ip + 20].fill(0);

        px[offset_tcp..offset_tcp + 8].fill(0);
        px[offset_tcp + 16..offset_tcp + 18].fill(0);
        let checksum_tcp = ref_tcp_ipv4_partial(&px, offset_ip, offset_tcp, offset_app);

        let (packet, offset_ip, offset_tcp) = ref_datalink(link, px, offset_ip, offset_tcp);
        Self {
            packet,
            offset_ip,
            offset_tcp,
            checksum_tcp,
            badsum: mods.badsum,
        }
    }

    /// `TcpSynTemplate::build_syn`, packet.rs:223-263 на базе; кадр в свежий `Vec`.
    pub fn build_syn(
        &self,
        ip_them: u32,
        port_them: u16,
        ip_me: u32,
        port_me: u16,
        seqno: u32,
    ) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&self.packet);
        let (oi, ot) = (self.offset_ip, self.offset_tcp);
        let ip_id = ip_them ^ u32::from(port_them) ^ seqno; // :942

        let total_length = (self.packet.len() - oi) as u16;
        out[oi + 2..oi + 4].copy_from_slice(&total_length.to_be_bytes());
        out[oi + 4..oi + 6].copy_from_slice(&(ip_id as u16).to_be_bytes());
        out[oi + 12..oi + 16].copy_from_slice(&ip_me.to_be_bytes());
        out[oi + 16..oi + 20].copy_from_slice(&ip_them.to_be_bytes());
        out[oi + 10..oi + 12].fill(0);
        let xsum2 = !ref_ip_header_checksum(&out, oi, out.len()); // :988
        out[oi + 10..oi + 12].copy_from_slice(&xsum2.to_be_bytes());

        out[ot..ot + 2].copy_from_slice(&port_me.to_be_bytes());
        out[ot + 2..ot + 4].copy_from_slice(&port_them.to_be_bytes());
        out[ot + 4..ot + 8].copy_from_slice(&seqno.to_be_bytes());

        let xsum = u64::from(self.checksum_tcp)
            + u64::from(ip_me)
            + u64::from(ip_them)
            + u64::from(port_me)
            + u64::from(port_them)
            + u64::from(seqno);
        let mut csum = !ref_fold(xsum);
        if self.badsum {
            csum = ref_corrupt_tcp_checksum(csum);
        }
        out[ot + 16..ot + 18].copy_from_slice(&csum.to_be_bytes());
        out
    }
}

// ---------------------------------------------------------------------
// ICMP Echo (база packet.rs :430-501)
// ---------------------------------------------------------------------

/// `IcmpEchoTemplate`, packet.rs:430-436 на базе.
#[derive(Clone, Debug)]
pub struct RefIcmpEcho {
    packet: Vec<u8>,
    offset_ip: usize,
    offset_icmp: usize,
    checksum_icmp: u16,
}

impl RefIcmpEcho {
    /// `IcmpEchoTemplate::new`, packet.rs:441-469 на базе.
    pub fn new(source_mac: [u8; 6], router_mac: [u8; 6], link: LinkType, ttl: u8) -> Self {
        let mut px = DEFAULT_ICMP_PING_TEMPLATE.to_vec();
        let (offset_ip, offset_icmp) = (14usize, 34usize);
        px[0..6].copy_from_slice(&router_mac);
        px[6..12].copy_from_slice(&source_mac);
        px[offset_ip + 8] = ttl;
        px[offset_ip + 4..offset_ip + 6].fill(0);
        px[offset_ip + 10..offset_ip + 12].fill(0);
        px[offset_ip + 12..offset_ip + 20].fill(0);
        let checksum_icmp = ref_fold(word_sum(&px[offset_icmp..]));
        let (packet, offset_ip, offset_icmp) = ref_datalink(link, px, offset_ip, offset_icmp);
        Self {
            packet,
            offset_ip,
            offset_icmp,
            checksum_icmp,
        }
    }

    /// `IcmpEchoTemplate::build_echo`, packet.rs:474-501 на базе; кадр в свежий `Vec`.
    pub fn build_echo(&self, ip_them: u32, ip_me: u32, seqno: u32, entropy: u64) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&self.packet);
        let (oi, oc) = (self.offset_ip, self.offset_icmp);
        let ip_id = ip_them ^ REF_TEMPL_ICMP_ECHO ^ seqno;
        let total_length = (self.packet.len() - oi) as u16;
        out[oi + 2..oi + 4].copy_from_slice(&total_length.to_be_bytes());
        out[oi + 4..oi + 6].copy_from_slice(&(ip_id as u16).to_be_bytes());
        out[oi + 12..oi + 16].copy_from_slice(&ip_me.to_be_bytes());
        out[oi + 16..oi + 20].copy_from_slice(&ip_them.to_be_bytes());
        out[oi + 10..oi + 12].fill(0);
        let xsum2 = !ref_ip_header_checksum(&out, oi, out.len()); // :988
        out[oi + 10..oi + 12].copy_from_slice(&xsum2.to_be_bytes());

        let cookie = ref_icmp_echo_cookie(ip_them, ip_me, entropy);
        out[oc + 4..oc + 8].copy_from_slice(&cookie.to_be_bytes());
        let csum = !ref_fold(u64::from(self.checksum_icmp) + u64::from(cookie));
        out[oc + 2..oc + 4].copy_from_slice(&csum.to_be_bytes());
        out
    }
}

// ---------------------------------------------------------------------
// UDP (база packet.rs :518-590)
// ---------------------------------------------------------------------

/// `UdpTemplate`, packet.rs:518-522 на базе.
#[derive(Clone, Debug)]
pub struct RefUdp {
    packet: Vec<u8>,
    offset_ip: usize,
    offset_udp: usize,
}

impl RefUdp {
    /// `UdpTemplate::new`, packet.rs:527-553 на базе.
    pub fn new(source_mac: [u8; 6], router_mac: [u8; 6], link: LinkType, ttl: u8) -> Self {
        let mut px = DEFAULT_UDP_TEMPLATE.to_vec();
        let (offset_ip, offset_udp) = (14usize, 34usize);
        px[0..6].copy_from_slice(&router_mac);
        px[6..12].copy_from_slice(&source_mac);
        px[offset_ip + 8] = ttl;
        px[offset_ip + 4..offset_ip + 6].fill(0);
        px[offset_ip + 10..offset_ip + 12].fill(0);
        px[offset_ip + 12..offset_ip + 20].fill(0);
        px[offset_udp + 6..offset_udp + 8].fill(0);
        let (packet, offset_ip, offset_udp) = ref_datalink(link, px, offset_ip, offset_udp);
        Self {
            packet,
            offset_ip,
            offset_udp,
        }
    }

    /// `UdpTemplate::build_udp`, packet.rs:559-590 на базе; кадр в свежий `Vec`.
    pub fn build_udp(
        &self,
        (ip_them, port_them): (u32, u16),
        (ip_me, port_me): (u32, u16),
        seqno: u32,
        payload: Option<&PayloadEntry>,
    ) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&self.packet);
        if let Some(e) = payload {
            out.extend_from_slice(&e.with_cookie(seqno));
        }
        let (oi, ou) = (self.offset_ip, self.offset_udp);
        let ip_id = ip_them ^ u32::from(port_them) ^ seqno; // :942
        let total_length = (out.len() - oi) as u16;
        out[oi + 2..oi + 4].copy_from_slice(&total_length.to_be_bytes());
        out[oi + 4..oi + 6].copy_from_slice(&(ip_id as u16).to_be_bytes());
        out[oi + 12..oi + 16].copy_from_slice(&ip_me.to_be_bytes());
        out[oi + 16..oi + 20].copy_from_slice(&ip_them.to_be_bytes());
        out[oi + 10..oi + 12].fill(0);
        let xsum2 = !ref_ip_header_checksum(&out, oi, out.len()); // :988
        out[oi + 10..oi + 12].copy_from_slice(&xsum2.to_be_bytes());

        let udp_length = (out.len() - ou) as u16; // :1030
        out[ou..ou + 2].copy_from_slice(&port_me.to_be_bytes());
        out[ou + 2..ou + 4].copy_from_slice(&port_them.to_be_bytes());
        out[ou + 4..ou + 6].copy_from_slice(&udp_length.to_be_bytes());
        out[ou + 6..ou + 8].fill(0);
        let csum = udp_ipv4_checksum(ip_me, ip_them, &out[ou..]);
        out[ou + 6..ou + 8].copy_from_slice(&csum.to_be_bytes());
        out
    }
}

// ---------------------------------------------------------------------
// SCTP INIT (база packet.rs :611-677)
// ---------------------------------------------------------------------

/// `SctpTemplate`, packet.rs:611-615 на базе.
#[derive(Clone, Debug)]
pub struct RefSctp {
    packet: Vec<u8>,
    offset_ip: usize,
    offset_sctp: usize,
}

impl RefSctp {
    /// `SctpTemplate::new`, packet.rs:620-645 на базе.
    pub fn new(source_mac: [u8; 6], router_mac: [u8; 6], link: LinkType, ttl: u8) -> Self {
        let mut px = DEFAULT_SCTP_INIT_TEMPLATE.to_vec();
        let (offset_ip, offset_sctp) = (14usize, 34usize);
        px[0..6].copy_from_slice(&router_mac);
        px[6..12].copy_from_slice(&source_mac);
        px[offset_ip + 8] = ttl;
        px[offset_ip + 4..offset_ip + 6].fill(0);
        px[offset_ip + 10..offset_ip + 12].fill(0);
        px[offset_ip + 12..offset_ip + 20].fill(0);
        let (packet, offset_ip, offset_sctp) = ref_datalink(link, px, offset_ip, offset_sctp);
        Self {
            packet,
            offset_ip,
            offset_sctp,
        }
    }

    /// `SctpTemplate::build_init`, packet.rs:652-677 на базе; кадр в свежий `Vec`.
    pub fn build_init(
        &self,
        (ip_them, port_them): (u32, u16),
        (ip_me, port_me): (u32, u16),
        seqno: u32,
    ) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&self.packet);
        let (oi, os) = (self.offset_ip, self.offset_sctp);
        let ip_id = ip_them ^ u32::from(port_them) ^ seqno; // :942
        let total_length = (self.packet.len() - oi) as u16;
        out[oi + 2..oi + 4].copy_from_slice(&total_length.to_be_bytes());
        out[oi + 4..oi + 6].copy_from_slice(&(ip_id as u16).to_be_bytes());
        out[oi + 12..oi + 16].copy_from_slice(&ip_me.to_be_bytes());
        out[oi + 16..oi + 20].copy_from_slice(&ip_them.to_be_bytes());
        out[oi + 10..oi + 12].fill(0);
        let xsum2 = !ref_ip_header_checksum(&out, oi, out.len()); // :988
        out[oi + 10..oi + 12].copy_from_slice(&xsum2.to_be_bytes());

        out[os..os + 2].copy_from_slice(&port_me.to_be_bytes());
        out[os + 2..os + 4].copy_from_slice(&port_them.to_be_bytes());
        out[os + 16..os + 20].copy_from_slice(&seqno.to_be_bytes());
        let xsum = sctp_crc32c(&out[os..]);
        out[os + 8..os + 12].copy_from_slice(&xsum.to_be_bytes());
        out
    }
}
