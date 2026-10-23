//! Шаблон TCP SYN и заполнение цели (AGPL-3.0). Порт `src/templ-pkt.c`
//! (`default_tcp_template` :30, `_template_init` :1218, `template_set_target_ipv4`
//! :877), masscan © Robert David Graham (github.com/robertdavidgraham/masscan,
//! HEAD 8e6b3b0). Кадры должны совпадать побайтно с C.

use crate::checksum::{fold, ip_header_checksum, tcp_ipv4_partial};

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

/// Готовый шаблон с частичными суммами (`struct TemplatePacket.ipv4`).
#[derive(Clone, Debug)]
pub struct TcpSynTemplate {
    packet: Vec<u8>,
    offset_ip: usize,
    offset_tcp: usize,
    checksum_ip: u16,
    checksum_tcp: u16,
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
        let mut px = DEFAULT_TCP_TEMPLATE.to_vec();
        let (offset_ip, offset_tcp, offset_app) = (14usize, 34usize, px.len());

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
        out[ot + 16..ot + 18].copy_from_slice(&(!fold(xsum)).to_be_bytes());
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

    /// Кадры из настоящего C (templ-pkt.c:1290-1352, :942-1021 дословно), см.
    /// харнес /private/tmp/claude-501/-Users-denyskolomiiets-masscan/
    /// db8417b2-853e-45c6-bc9c-f3bcc0978668/scratchpad/task7/h7.c.
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
}
