//! Шаблон TCP SYN и заполнение цели (AGPL-3.0). Порт `src/templ-pkt.c`
//! (`default_tcp_template` :30, `_template_init` :1218, `template_set_target_ipv4`
//! :877), masscan © Robert David Graham (github.com/robertdavidgraham/masscan,
//! HEAD 8e6b3b0). Кадры должны совпадать побайтно с C.

use crate::checksum::{fold, ip_header_checksum, tcp_ipv4_partial, word_sum};
use crate::cookie::icmp_echo_cookie;
use crate::targets::TEMPL_ICMP_ECHO;

/// Тип канального уровня (спека §4.8): `PCAP_DLT_ETHERNET` 1, `PCAP_DLT_NULL` 0,
/// `PCAP_DLT_RAW` 12.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    Null,
    Raw,
}

/// `default_tcp_template`, templ-pkt.c:30-53: Ethernet 14 + IP 20 + TCP 20 +
/// опция MSS 1460 (`02 04 05 b4`), всего 58 байт.
pub const DEFAULT_TCP_TEMPLATE: &[u8] = &[
    // Ethernet: dst, src, ethertype IPv4
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x08, 0x00,
    // IP: 0x45, tos, total length 0x2c, id, flags/frag, TTL 255, proto TCP, checksum, src, dst
    0x45, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0xff, 0x06, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
    // TCP: ports, seqno, ack, header length 0x60, SYN, window 1024, checksum, urgent
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x60, 0x02, 0x04, 0x01, 0xff, 0xff, 0x00, 0x00,
    // опция MSS 1460
    0x02, 0x04, 0x05, 0xb4,
];

/// main-conf.c:2143 `default_mss`.
pub const DEFAULT_TCP_MSS: u16 = 1460;
/// main-conf.c:2201 `default_value`.
pub const DEFAULT_TCP_WSCALE: u8 = 3;
/// main-conf.c:2254 `default_value`.
pub const DEFAULT_TCP_TSECHO: u32 = 0x1234_5678;

/// Опции TCP SYN (templ-tcp-hdr.c:1066-1119, main-conf.c:2141-2345).
/// `Default`: MSS 1460 включён, остальное выключено. Порядок опций в
/// кадре: `mss -> sackok -> wscale -> tsecho`. Один тип на `config` и `packet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeaderOptions {
    pub mss: Option<u16>,
    pub sackok: bool,
    pub wscale: Option<u8>,
    pub tsecho: Option<u32>,
}

impl Default for TcpHeaderOptions {
    fn default() -> Self {
        TcpHeaderOptions {
            mss: Some(DEFAULT_TCP_MSS),
            sackok: false,
            wscale: None,
            tsecho: None,
        }
    }
}

/// Параметры зонда поверх шаблона: `--ttl`, `--badsum` и опции TCP.
/// `Default` даёт байты `DEFAULT_TCP_TEMPLATE` (TTL 255, MSS 1460).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketModifiers {
    pub ttl: u8,
    pub badsum: bool,
    pub tcp: TcpHeaderOptions,
}

impl Default for PacketModifiers {
    fn default() -> Self {
        PacketModifiers {
            ttl: 255,
            badsum: false,
            tcp: TcpHeaderOptions::default(),
        }
    }
}

/// Байты опций TCP, дополненные нулями (EOL) до границы 4 байт
/// (templ-tcp-hdr.c:1066-1119 `templ_tcp_apply_options`, :843 `tcp_add_opt`).
/// Не длиннее 20 байт, поэтому `doff <= 10`.
fn tcp_option_bytes(o: &TcpHeaderOptions) -> Vec<u8> {
    let mut b = Vec::new();
    if let Some(mss) = o.mss {
        // kind 2, len 4.
        b.extend_from_slice(&[2, 4]);
        b.extend_from_slice(&mss.to_be_bytes());
    }
    if o.sackok {
        // kind 4, len 2.
        b.extend_from_slice(&[4, 2]);
    }
    if let Some(ws) = o.wscale {
        // kind 3, len 3.
        b.extend_from_slice(&[3, 3, ws]);
    }
    if let Some(ts) = o.tsecho {
        // kind 8, len 10: TSval и нулевой TSecr. Все 4 байта значения (Р9:
        // C затирает `field[2]` на :1111-1112 и теряет `ts >> 8`).
        b.extend_from_slice(&[8, 10]);
        b.extend_from_slice(&ts.to_be_bytes());
        b.extend_from_slice(&[0; 4]);
    }
    while b.len() % 4 != 0 {
        b.push(0);
    }
    b
}

/// Заведомо неверная TCP-сумма для `--badsum` (Р9): `csum - 1`. Для 0 нужна
/// единица: `0xFFFF` это тот же ноль в арифметике дополнения до единицы и
/// сумма осталась бы верной.
fn corrupt_tcp_checksum(csum: u16) -> u16 {
    if csum == 0 { 1 } else { csum - 1 }
}

/// Готовый шаблон с частичными суммами (`struct TemplatePacket.ipv4`).
#[derive(Clone, Debug)]
pub struct TcpSynTemplate {
    packet: Vec<u8>,
    offset_ip: usize,
    offset_tcp: usize,
    checksum_ip: u16,
    checksum_tcp: u16,
    badsum: bool,
}

impl TcpSynTemplate {
    /// `_template_init` для TCP, templ-pkt.c:1218-1352.
    ///
    /// Значение `linkproto` для `DLT_NULL`: C пишет литерал `int linkproto = 2;
    /// /* AF_INET */` (templ-pkt.c:1343), а не системную константу, и копирует `int`
    /// в порядке байт хоста (:1349). Порт делает то же: 2 в порядке байт хоста
    /// (`to_ne_bytes`), на всех целевых платформах (LE) это `02 00 00 00`. Значения
    /// `AF_INET` на Linux и macOS оба равны 2; расхождение есть только у `AF_INET6`
    /// (:1100 `#define AF_INET6 23`, :1161), к IPv4 это не относится.
    pub fn new(source_mac: [u8; 6], router_mac: [u8; 6], link: LinkType) -> Self {
        Self::new_with_options(source_mac, router_mac, link, &PacketModifiers::default())
    }

    /// [`TcpSynTemplate::new`] с `--ttl`, `--badsum` и опциями TCP
    /// (templ-pkt.c:1474-1488 `template_set_ttl`, templ-tcp-hdr.c:1066-1119).
    /// При `PacketModifiers::default()` байты равны `DEFAULT_TCP_TEMPLATE`.
    pub fn new_with_options(
        source_mac: [u8; 6],
        router_mac: [u8; 6],
        link: LinkType,
        mods: &PacketModifiers,
    ) -> Self {
        // Базовые 54 байта и опции TCP отдельно.
        let mut px = DEFAULT_TCP_TEMPLATE[..54].to_vec();
        px.extend_from_slice(&tcp_option_bytes(&mods.tcp));
        let (offset_ip, offset_tcp, offset_app) = (14usize, 34usize, px.len());
        // Длина IP и смещение данных TCP под новые опции.
        let tcp_len = offset_app - offset_tcp;
        px[offset_ip + 2..offset_ip + 4]
            .copy_from_slice(&((offset_app - offset_ip) as u16).to_be_bytes());
        px[offset_tcp + 12] = ((tcp_len / 4) as u8) << 4;
        // templ-pkt.c:1483 `px[offset+8] = ttl`; сумма IP пересчитывается ниже.
        px[offset_ip + 8] = mods.ttl;

        // MAC-адреса, templ-pkt.c:1272-1273.
        px[0..6].copy_from_slice(&router_mac);
        px[6..12].copy_from_slice(&source_mac);

        // Обнулить поля, которые заполнит build_syn, templ-pkt.c:1290-1292:
        // IP ID, checksum, адреса.
        px[offset_ip + 4..offset_ip + 6].fill(0);
        px[offset_ip + 10..offset_ip + 12].fill(0);
        px[offset_ip + 12..offset_ip + 20].fill(0);
        let checksum_ip = ip_header_checksum(&px, offset_ip, px.len());

        // templ-pkt.c:1317-1318: байты TCP 0..8 (порты и seqno; комментарий C
        // говорит только о порте назначения, но memset покрывает оба) и checksum.
        px[offset_tcp..offset_tcp + 8].fill(0);
        px[offset_tcp + 16..offset_tcp + 18].fill(0);
        let checksum_tcp = tcp_ipv4_partial(&px, offset_ip, offset_tcp, offset_app);

        // DATALINK KLUDGE, templ-pkt.c:1342-1360.
        let (packet, offset_ip, offset_tcp) = match link {
            LinkType::Ethernet => (px, offset_ip, offset_tcp),
            LinkType::Null => {
                let mut p = 2u32.to_ne_bytes().to_vec();
                p.extend_from_slice(&px[offset_ip..]);
                (p, 4, offset_tcp - (offset_ip - 4))
            }
            LinkType::Raw => (px[offset_ip..].to_vec(), 0, offset_tcp - offset_ip),
        };
        Self {
            packet,
            offset_ip,
            offset_tcp,
            checksum_ip,
            checksum_tcp,
            badsum: mods.badsum,
        }
    }

    /// `tmpl->proto == Proto_TCP` (templ-pkt.c:1319, selftest :1524).
    pub fn proto_is_tcp(&self) -> bool {
        self.packet.get(self.offset_ip + 9) == Some(&6)
    }

    /// Частичная IP-сумма шаблона, templ-pkt.c:1293.
    pub fn checksum_ip(&self) -> u16 {
        self.checksum_ip
    }

    /// `template_set_target_ipv4`, ветка `Proto_TCP`, templ-pkt.c:942-1021.
    /// `out` очищается и получает кадр целиком.
    pub fn build_syn(
        &self,
        ip_them: u32,
        port_them: u16,
        ip_me: u32,
        port_me: u16,
        seqno: u32,
        out: &mut Vec<u8>,
    ) {
        out.clear();
        out.extend_from_slice(&self.packet);
        let (oi, ot) = (self.offset_ip, self.offset_tcp);
        let ip_id = ip_them ^ u32::from(port_them) ^ seqno; // :942

        let total_length = (self.packet.len() - oi) as u16;
        out[oi + 2..oi + 4].copy_from_slice(&total_length.to_be_bytes());
        out[oi + 4..oi + 6].copy_from_slice(&(ip_id as u16).to_be_bytes());
        out[oi + 12..oi + 16].copy_from_slice(&ip_me.to_be_bytes());
        out[oi + 16..oi + 20].copy_from_slice(&ip_them.to_be_bytes());
        out[oi + 10..oi + 12].fill(0);
        let xsum2 = !ip_header_checksum(out, oi, out.len()); // :988
        out[oi + 10..oi + 12].copy_from_slice(&xsum2.to_be_bytes());

        out[ot..ot + 2].copy_from_slice(&port_me.to_be_bytes());
        out[ot + 2..ot + 4].copy_from_slice(&port_them.to_be_bytes());
        out[ot + 4..ot + 8].copy_from_slice(&seqno.to_be_bytes());

        // :1009-1018: сумма в uint64_t, три свёртки, инверсия.
        let xsum = u64::from(self.checksum_tcp)
            + u64::from(ip_me)
            + u64::from(ip_them)
            + u64::from(port_me)
            + u64::from(port_them)
            + u64::from(seqno);
        let mut csum = !fold(xsum);
        if self.badsum {
            // Р9: IPv4-сумма остаётся верной, портится только L4.
            csum = corrupt_tcp_checksum(csum);
        }
        out[ot + 16..ot + 18].copy_from_slice(&csum.to_be_bytes());
    }
}

/// `default_icmp_ping_template`, templ-pkt.c:105-136: Ethernet 14 + IP 20 (`ip_len = 76`, TTL 255, proto 1) + ICMP
/// Echo Request 8 (`08 00`, сумма 0, `[id|seq]` 0) + 48 байт паттерна `0x08..=0x37`, всего 90 байт.
pub const DEFAULT_ICMP_PING_TEMPLATE: &[u8] = &[
    // Ethernet: dst, src, ethertype IPv4
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x08, 0x00,
    // IP: 0x45, tos, total length 0x4c, id, flags/frag, TTL 255, proto ICMP, checksum, src, dst
    0x45, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
    // ICMP: type 8, code 0, checksum, id, seqno
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // паттерн 0x08..=0x37
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
];

/// Шаблон ICMP Echo Request (`Proto_ICMP_ping`) с частичными суммами.
#[derive(Clone, Debug)]
pub struct IcmpEchoTemplate {
    packet: Vec<u8>,
    offset_ip: usize,
    offset_icmp: usize,
    /// Сумма ICMP-сообщения без инверсии при нулевых `[id|seq]`: `icmp_checksum2`, templ-pkt.c:320-336.
    checksum_icmp: u16,
}

impl IcmpEchoTemplate {
    /// `_template_init` для ICMP, templ-pkt.c:1285-1313; `--ttl` как `template_set_ttl` (:1474-1488).
    /// Опции TCP и `--badsum` к ICMP не относятся (в C `badsum` ни на что не влияет: main-conf.c:2758).
    pub fn new(source_mac: [u8; 6], router_mac: [u8; 6], link: LinkType, ttl: u8) -> Self {
        let mut px = DEFAULT_ICMP_PING_TEMPLATE.to_vec();
        let (offset_ip, offset_icmp) = (14usize, 34usize);
        px[0..6].copy_from_slice(&router_mac);
        px[6..12].copy_from_slice(&source_mac);
        px[offset_ip + 8] = ttl;
        // :1290-1292: ID, сумма и адреса обнуляются перед частичной суммой.
        px[offset_ip + 4..offset_ip + 6].fill(0);
        px[offset_ip + 10..offset_ip + 12].fill(0);
        px[offset_ip + 12..offset_ip + 20].fill(0);
        // icmp_checksum2: сумма слов всего сообщения (поле суммы и [id|seq] нулевые), три свёртки.
        let checksum_icmp = fold(word_sum(&px[offset_icmp..]));
        // DATALINK KLUDGE, templ-pkt.c:1342-1360 (как у TCP).
        let (packet, offset_ip, offset_icmp) = match link {
            LinkType::Ethernet => (px, offset_ip, offset_icmp),
            LinkType::Null => {
                let mut p = 2u32.to_ne_bytes().to_vec();
                p.extend_from_slice(&px[offset_ip..]);
                (p, 4, offset_icmp - (offset_ip - 4))
            }
            LinkType::Raw => (px[offset_ip..].to_vec(), 0, offset_icmp - offset_ip),
        };
        Self {
            packet,
            offset_ip,
            offset_icmp,
            checksum_icmp,
        }
    }

    /// `template_set_target_ipv4`, ветка `Proto_ICMP_ping`, templ-pkt.c:942-988 и :1065-1080. `seqno` вызывающего
    /// потока (cookie с реальным `port_me`) идёт только в `ip_id`; `[id|seq]` это `icmp_echo_cookie` с
    /// `port_me = 0`. `out` очищается и получает кадр целиком.
    pub fn build_echo(
        &self,
        ip_them: u32,
        ip_me: u32,
        seqno: u32,
        entropy: u64,
        out: &mut Vec<u8>,
    ) {
        out.clear();
        out.extend_from_slice(&self.packet);
        let (oi, oc) = (self.offset_ip, self.offset_icmp);
        // :942: `port_them` здесь индекс Templ_ICMP_echo (196608), в ip_id берутся младшие 16 бит.
        let ip_id = ip_them ^ TEMPL_ICMP_ECHO ^ seqno;
        let total_length = (self.packet.len() - oi) as u16;
        out[oi + 2..oi + 4].copy_from_slice(&total_length.to_be_bytes());
        out[oi + 4..oi + 6].copy_from_slice(&(ip_id as u16).to_be_bytes());
        out[oi + 12..oi + 16].copy_from_slice(&ip_me.to_be_bytes());
        out[oi + 16..oi + 20].copy_from_slice(&ip_them.to_be_bytes());
        out[oi + 10..oi + 12].fill(0);
        let xsum2 = !ip_header_checksum(out, oi, out.len()); // :988
        out[oi + 10..oi + 12].copy_from_slice(&xsum2.to_be_bytes());

        // :1067-1079: cookie в [id|seq], сумма = ~fold(checksum_tcp + cookie) в uint64_t.
        let cookie = icmp_echo_cookie(ip_them, ip_me, entropy);
        out[oc + 4..oc + 8].copy_from_slice(&cookie.to_be_bytes());
        let csum = !fold(u64::from(self.checksum_icmp) + u64::from(cookie));
        out[oc + 2..oc + 4].copy_from_slice(&csum.to_be_bytes());
    }
}

/// Независимая проверка TCP-суммы Ethernet-кадра (RFC 1071): псевдозаголовок +
/// весь сегмент, включая поле checksum, должны свернуться в 0xFFFF.
#[cfg(test)]
pub(crate) fn tcp_checksum_is_valid(f: &[u8]) -> bool {
    let seg = &f[34..];
    let mut sum: u32 = 6 + seg.len() as u32;
    for c in f[26..34].chunks(2).chain(seg.chunks(2)) {
        sum += u32::from(c[0]) << 8 | u32::from(*c.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum == 0xFFFF
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;
    use crate::cookie::syn_cookie_ipv4;

    fn hex6(s: &str) -> [u8; 6] {
        let mut o = [0u8; 6];
        for i in 0..6 {
            o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        o
    }
    fn hexv(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }
    fn tmpl(link: LinkType) -> TcpSynTemplate {
        TcpSynTemplate::new(hex6("001122334455"), hex6("665544332211"), link)
    }

    #[test]
    fn default_template_is_58_bytes() {
        assert_eq!(DEFAULT_TCP_TEMPLATE.len(), 58);
    }

    #[test]
    fn syn_frame_fixed_fields() {
        let t = tmpl(LinkType::Ethernet);
        let mut f = Vec::new();
        t.build_syn(0x0a00_0001, 80, 0xc0a8_0101, 40000, 0x1234_5678, &mut f);
        assert_eq!(f.len(), 58);
        assert_eq!(&f[0..6], &hex6("665544332211"));
        assert_eq!(&f[6..12], &hex6("001122334455"));
        assert_eq!(&f[12..14], &[0x08, 0x00]);
        assert_eq!(f[14], 0x45);
        assert_eq!(f[22], 0xff);
        assert_eq!(f[23], 0x06);
        let ip_id = (0x0a00_0001u32 ^ 80 ^ 0x1234_5678) as u16;
        assert_eq!(&f[18..20], &ip_id.to_be_bytes());
        assert_eq!(&f[26..30], &0xc0a8_0101u32.to_be_bytes());
        assert_eq!(&f[30..34], &0x0a00_0001u32.to_be_bytes());
        assert_eq!(&f[34..36], &40000u16.to_be_bytes());
        assert_eq!(&f[36..38], &80u16.to_be_bytes());
        assert_eq!(&f[38..42], &0x1234_5678u32.to_be_bytes());
        assert_eq!(f[46], 0x60);
        assert_eq!(f[47], 0x02);
        assert_eq!(&f[48..50], &[0x04, 0x01]);
        assert_eq!(&f[54..58], &[0x02, 0x04, 0x05, 0xb4]);
    }

    #[test]
    fn syn_frame_checksums_validate() {
        let t = tmpl(LinkType::Ethernet);
        let mut f = Vec::new();
        t.build_syn(0x0808_0808, 443, 0x0a00_0002, 12345, 0xdead_beef, &mut f);
        assert_eq!(checksum::ip_header_checksum(&f, 14, 34), 0xffff);
        assert!(tcp_checksum_is_valid(&f));
        // Независимо через checksum_ipv4: вычитает текущее поле и инвертирует.
        let c = checksum::checksum_ipv4(0x0a00_0002, 0x0808_0808, 6, &f[34..]);
        assert_eq!(&f[50..52], &c.to_be_bytes());
    }

    #[test]
    fn syn_checksums_validate_when_u64_sum_exceeds_2_pow_32() {
        // checksum_tcp + ip_me + ip_them + ports + seqno > 2^32: свёртка через
        // u32 дала бы другой результат.
        let t = tmpl(LinkType::Ethernet);
        let (me, them, seq) = (0xC0A8_0101u32, 0xFFFF_FFFEu32, 0xFFFF_FFFFu32);
        assert!(u64::from(me) + u64::from(them) + u64::from(seq) > 1 << 32);
        let mut f = Vec::new();
        t.build_syn(them, 0xFFFF, me, 0xFFFF, seq, &mut f);
        assert!(tcp_checksum_is_valid(&f));
        assert_eq!(checksum::ip_header_checksum(&f, 14, 34), 0xffff);
        t.build_syn(0xFFFF_FFFF, 65535, 0xFFFF_FFFF, 65535, 0xFFFF_FFFF, &mut f);
        assert!(tcp_checksum_is_valid(&f));
    }

    #[test]
    fn template_proto_detection() {
        assert!(tmpl(LinkType::Ethernet).proto_is_tcp());
        assert!(tmpl(LinkType::Null).proto_is_tcp());
        assert!(tmpl(LinkType::Raw).proto_is_tcp());
    }

    #[test]
    fn null_and_raw_are_trimmed_ethernet_frames() {
        let (them, pt, me, pm, seq) = (0x0a00_0001, 80, 0xc0a8_0101, 40000, 0x1234_5678);
        let (mut e, mut n, mut r) = (Vec::new(), Vec::new(), Vec::new());
        tmpl(LinkType::Ethernet).build_syn(them, pt, me, pm, seq, &mut e);
        tmpl(LinkType::Null).build_syn(them, pt, me, pm, seq, &mut n);
        tmpl(LinkType::Raw).build_syn(them, pt, me, pm, seq, &mut r);
        assert_eq!(r.len(), 44);
        assert_eq!(n.len(), 48);
        assert_eq!(&r[..], &e[14..]);
        assert_eq!(&n[4..], &e[14..]);
        // templ-pkt.c:1343,1349: литерал 2 в порядке байт хоста (LE).
        assert_eq!(&n[0..4], &2u32.to_ne_bytes());
        #[cfg(target_endian = "little")]
        assert_eq!(&n[0..4], &[2, 0, 0, 0]);
    }

    /// Кадры из настоящего C (templ-pkt.c:1290-1352, :942-1021 дословно):
    /// кадры посчитаны харнесом ревьюера (не закоммичен); воспроизводятся
    /// линковкой немодифицированного templ-pkt.c (8e6b3b0).
    /// seqno = (unsigned)syn_cookie_ipv4 (main.c:402), энтропия 0x1122334455667788.
    /// (link, ip_them, port_them, ip_me, port_me, seqno, кадр). Первые три строки:
    /// принудительный seqno 0xFFFFFFFF и сумма u64 > 2^32.
    const C_FRAMES: &[(u8, u32, u16, u32, u16, u32, &str)] = &[
        (
            0,
            4294967294,
            65535,
            3232235777,
            65535,
            4294967295,
            "66554433221100112233445508004500002cfffe0000ff06fa24c0a80101fffffffeffffffffffffffff0000000060020401d27d0000020405b4",
        ),
        (
            1,
            4294967294,
            65535,
            3232235777,
            65535,
            4294967295,
            "020000004500002cfffe0000ff06fa24c0a80101fffffffeffffffffffffffff0000000060020401d27d0000020405b4",
        ),
        (
            2,
            4294967294,
            65535,
            3232235777,
            65535,
            4294967295,
            "4500002cfffe0000ff06fa24c0a80101fffffffeffffffffffffffff0000000060020401d27d0000020405b4",
        ),
        (
            0,
            763135994,
            22709,
            3356672117,
            31044,
            934503152,
            "66554433221100112233445508004500002cbdbf0000ff06c00dc812c0752d7c87fa794458b537b362f00000000060020401e9890000020405b4",
        ),
        (
            0,
            304951204,
            49666,
            3208649979,
            18182,
            3456709357,
            "66554433221100112233445508004500002cdf4b0000ff06be73bf401cfb122d2fa44706c202ce0932ed00000000600204016c190000020405b4",
        ),
        (
            0,
            3868134019,
            63614,
            1467798614,
            1038,
            3201461334,
            "66554433221100112233445508004500002c9eab0000ff06003b577cd456e68f0a83040ef87ebed26c5600000000600204014f8a0000020405b4",
        ),
        (
            1,
            1100314947,
            39927,
            2609013617,
            56576,
            956017378,
            "020000004500002c48560000ff06b9a99b82637141957943dd009bf738fbaae200000000600204017d830000020405b4",
        ),
        (
            2,
            3495411307,
            2496,
            4269534167,
            30675,
            3856473362,
            "4500002caab90000ff0697fbfe7bebd7d057be6b77d309c0e5dd1d120000000060020401968b0000020405b4",
        ),
    ];

    #[test]
    fn syn_frame_matches_c_bytes() {
        let mut f = Vec::new();
        for &(link, them, pt, me, pm, seq, hex) in C_FRAMES {
            let link = [LinkType::Ethernet, LinkType::Null, LinkType::Raw][link as usize];
            if them != 0xFFFF_FFFE {
                // main.c:402: seqno = (unsigned)cookie.
                let cookie = crate::cookie::syn_cookie_ipv4(
                    them,
                    pt.into(),
                    me,
                    pm.into(),
                    0x1122_3344_5566_7788,
                );
                assert_eq!(cookie as u32, seq);
            }
            tmpl(link).build_syn(them, pt, me, pm, seq, &mut f);
            assert_eq!(f, hexv(hex), "{link:?} {them:#x}:{pt}");
        }
    }

    fn mods(tcp: TcpHeaderOptions) -> PacketModifiers {
        PacketModifiers {
            tcp,
            ..PacketModifiers::default()
        }
    }

    fn syn_with(m: &PacketModifiers) -> Vec<u8> {
        let t = TcpSynTemplate::new_with_options(
            hex6("001122334455"),
            hex6("665544332211"),
            LinkType::Ethernet,
            m,
        );
        let mut f = Vec::new();
        t.build_syn(0x0808_0808, 443, 0x0a00_0002, 12345, 0xdead_beef, &mut f);
        f
    }

    /// Только заголовки опций кадра: байты `54..`, `ip.total_len` и `tcp.doff`.
    fn shape(f: &[u8]) -> (&[u8], u16, u8) {
        (&f[54..], u16::from_be_bytes([f[16], f[17]]), f[46])
    }

    #[test]
    fn default_template_bytes_unchanged() {
        // Студия строит кадры из умолчания: `canonical_job_bytes` зависит от них.
        for link in [LinkType::Ethernet, LinkType::Null, LinkType::Raw] {
            let (mut a, mut b) = (Vec::new(), Vec::new());
            let old = tmpl(link);
            let new = TcpSynTemplate::new_with_options(
                hex6("001122334455"),
                hex6("665544332211"),
                link,
                &PacketModifiers::default(),
            );
            old.build_syn(0x0a00_0001, 80, 0xc0a8_0101, 40000, 0x1234_5678, &mut a);
            new.build_syn(0x0a00_0001, 80, 0xc0a8_0101, 40000, 0x1234_5678, &mut b);
            assert_eq!(a, b, "{link:?}");
            assert_eq!(old.checksum_ip(), new.checksum_ip());
        }
        // Пустая заготовка совпадает с константой побайтно (58 байт).
        let mut px = DEFAULT_TCP_TEMPLATE[..54].to_vec();
        px.extend_from_slice(&tcp_option_bytes(&TcpHeaderOptions::default()));
        px[14 + 8] = PacketModifiers::default().ttl;
        assert_eq!(px, DEFAULT_TCP_TEMPLATE);
        assert_eq!(syn_with(&PacketModifiers::default()).len(), 58);
    }

    #[test]
    fn tcp_options_layout_and_padding_match_c() {
        let none = TcpHeaderOptions {
            mss: None,
            ..TcpHeaderOptions::default()
        };
        let f = syn_with(&mods(none));
        assert_eq!(f.len(), 54);
        assert_eq!(shape(&f), (&[][..], 40, 0x50));
        assert!(tcp_checksum_is_valid(&f));

        let f = syn_with(&mods(TcpHeaderOptions {
            mss: Some(1400),
            sackok: true,
            ..none
        }));
        assert_eq!(
            shape(&f),
            (
                &[0x02, 0x04, 0x05, 0x78, 0x04, 0x02, 0x00, 0x00][..],
                48,
                0x70
            )
        );
        assert!(tcp_checksum_is_valid(&f));

        let f = syn_with(&mods(TcpHeaderOptions {
            wscale: Some(7),
            ..TcpHeaderOptions::default()
        }));
        assert_eq!(
            shape(&f),
            (
                &[0x02, 0x04, 0x05, 0xb4, 0x03, 0x03, 0x07, 0x00][..],
                48,
                0x70
            )
        );
        assert!(tcp_checksum_is_valid(&f));

        let f = syn_with(&mods(TcpHeaderOptions {
            tsecho: Some(0xdead_beef),
            ..TcpHeaderOptions::default()
        }));
        assert_eq!(
            shape(&f),
            (
                &[
                    0x02, 0x04, 0x05, 0xb4, 0x08, 0x0a, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0
                ][..],
                56,
                0x90
            )
        );
        assert!(tcp_checksum_is_valid(&f));
        assert_eq!(checksum::ip_header_checksum(&f, 14, 34), 0xffff);
    }

    fn all_options() -> TcpHeaderOptions {
        TcpHeaderOptions {
            mss: Some(1460),
            sackok: true,
            wscale: Some(7),
            tsecho: Some(0xdead_beef),
        }
    }

    #[test]
    fn all_tcp_options_and_badsum_keep_valid_ipv4_header() {
        // Review Focus 5: 4 + 2 + 3 + 10 = 19 байт, EOL до 20, `doff = 10`.
        let m = PacketModifiers {
            ttl: 64,
            badsum: true,
            tcp: all_options(),
        };
        let f = syn_with(&m);
        assert_eq!(f[22], 64);
        let (opts, total, doff) = shape(&f);
        assert_eq!(opts.len(), 20);
        assert_eq!(opts[19], 0, "EOL pad");
        assert_eq!((total, doff), (60, 0xa0));
        assert!(doff >> 4 <= 15);
        assert_eq!(checksum::ip_header_checksum(&f, 14, 34), 0xffff);
        assert!(!tcp_checksum_is_valid(&f));
        // Без badsum тот же кадр верен, а расходятся ровно два байта суммы.
        let good = syn_with(&PacketModifiers { badsum: false, ..m });
        assert!(tcp_checksum_is_valid(&good));
        let diff: Vec<_> = (0..f.len()).filter(|&i| f[i] != good[i]).collect();
        assert!(diff.iter().all(|&i| (50..52).contains(&i)), "{diff:?}");
        assert_eq!(
            u16::from_be_bytes([f[50], f[51]]),
            u16::from_be_bytes([good[50], good[51]]).wrapping_sub(1)
        );
    }

    #[test]
    fn badsum_is_never_valid_even_for_a_zero_checksum() {
        // 0xFFFF это тот же ноль в арифметике дополнения: `wrapping_sub(1)` от
        // нуля оставил бы сумму верной.
        assert_eq!(corrupt_tcp_checksum(0), 1);
        assert_eq!(corrupt_tcp_checksum(1), 0);
        assert_eq!(corrupt_tcp_checksum(0xffff), 0xfffe);
        for seq in 0..2000u32 {
            let t = TcpSynTemplate::new_with_options(
                hex6("001122334455"),
                hex6("665544332211"),
                LinkType::Ethernet,
                &PacketModifiers {
                    badsum: true,
                    ..PacketModifiers::default()
                },
            );
            let mut f = Vec::new();
            t.build_syn(0x0a00_0001, 80, 0x0a00_0002, 1000, seq, &mut f);
            assert!(!tcp_checksum_is_valid(&f), "seq {seq}");
        }
    }

    #[test]
    fn ttl_lands_in_every_link_type_with_a_valid_header_sum() {
        for link in [LinkType::Ethernet, LinkType::Null, LinkType::Raw] {
            let t = TcpSynTemplate::new_with_options(
                hex6("001122334455"),
                hex6("665544332211"),
                link,
                &PacketModifiers {
                    ttl: 1,
                    ..PacketModifiers::default()
                },
            );
            let mut f = Vec::new();
            t.build_syn(0x0a00_0001, 80, 0x0a00_0002, 1000, 7, &mut f);
            let oi = match link {
                LinkType::Ethernet => 14,
                LinkType::Null => 4,
                LinkType::Raw => 0,
            };
            assert_eq!(f[oi + 8], 1, "{link:?}");
            assert_eq!(checksum::ip_header_checksum(&f, oi, oi + 20), 0xffff);
        }
    }

    // Кадры ниже получены из C: masscan 8e6b3b0, `template_packet_init` + `template_set_target_ipv4` (templ-pkt.c)
    // в тестовой обвязке без сети (ни один кадр не передавался); seqno = `syn_cookie(ip_them, 196608, ip_me,
    // port_me, entropy)` как main.c:389. MAC: dst 66:55:44:33:22:11, src 00:11:22:33:44:55.
    const C_ICMP_FRAME_A: &str = "66554433221100112233445508004500004c9aaf0000ff0198ecc0000201c61200010800cb5706873b1e08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637";
    const C_ICMP_FRAME_B_TTL64: &str = "66554433221100112233445508004500004c3a34000040016f6b0aff0001c613fffe0800178bfe0df76308090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637";

    fn icmp_tmpl(link: LinkType, ttl: u8) -> IcmpEchoTemplate {
        IcmpEchoTemplate::new(hex6("001122334455"), hex6("665544332211"), link, ttl)
    }

    #[test]
    fn icmp_echo_frame_and_cookie_match_c() {
        assert_eq!(DEFAULT_ICMP_PING_TEMPLATE.len(), 90);
        assert!(
            DEFAULT_ICMP_PING_TEMPLATE[42..]
                .iter()
                .copied()
                .eq(0x08u8..=0x37)
        );
        let mut f = Vec::new();
        // A: 198.18.0.1 <- 192.0.2.1, порт источника 41000 (в cookie не входит), seed 0x0123456789abcdef.
        let (them, me, port_me, seed) = (
            0xc612_0001u32,
            0xc000_0201u32,
            41000u32,
            0x0123_4567_89ab_cdefu64,
        );
        let seqno = syn_cookie_ipv4(them, 196_608, me, port_me, seed) as u32;
        assert_eq!(seqno, 0xd078_9aae);
        icmp_tmpl(LinkType::Ethernet, 255).build_echo(them, me, seqno, seed, &mut f);
        assert_eq!(f, hexv(C_ICMP_FRAME_A));
        assert_eq!(f.len(), 90);
        assert_eq!(&f[16..18], &[0x00, 0x4c], "ip_len = 76");
        assert_eq!(
            &f[18..20],
            &[0x9a, 0xaf],
            "ip_id = ip_them ^ 196608 ^ seqno"
        );
        assert_eq!(
            &f[38..42],
            &[0x06, 0x87, 0x3b, 0x1e],
            "[id|seq] = cookie, port_me = 0"
        );
        // независимая проверка сумм: IP-заголовок и ICMP-сообщение (56 байт) сворачиваются в 0xFFFF
        assert_eq!(checksum::ip_header_checksum(&f, 14, 34), 0xffff);
        let sum: u32 = f[34..]
            .chunks(2)
            .map(|w| u32::from(w[0]) << 8 | u32::from(w[1]))
            .sum();
        assert_eq!(fold(u64::from(sum)), 0xffff);
        // B: --ttl 64, другой seed и источник
        let (them, me, port_me, seed) = (0xc613_fffeu32, 0x0aff_0001u32, 40003u32, 0x1234_5678u64);
        let seqno = syn_cookie_ipv4(them, 196_608, me, port_me, seed) as u32;
        assert_eq!(seqno, 0x0ead_c5ca);
        icmp_tmpl(LinkType::Ethernet, 64).build_echo(them, me, seqno, seed, &mut f);
        assert_eq!(f, hexv(C_ICMP_FRAME_B_TTL64));
    }

    #[test]
    fn icmp_echo_null_and_raw_are_trimmed_ethernet_frames() {
        let (them, me, seqno, seed) = (0xc612_0001u32, 0xc000_0201u32, 7u32, 9u64);
        let (mut eth, mut null, mut raw) = (Vec::new(), Vec::new(), Vec::new());
        icmp_tmpl(LinkType::Ethernet, 255).build_echo(them, me, seqno, seed, &mut eth);
        icmp_tmpl(LinkType::Null, 255).build_echo(them, me, seqno, seed, &mut null);
        icmp_tmpl(LinkType::Raw, 255).build_echo(them, me, seqno, seed, &mut raw);
        assert_eq!(&null[..4], &2u32.to_ne_bytes());
        assert_eq!(&null[4..], &eth[14..]);
        assert_eq!(&raw[..], &eth[14..]);
    }
}
