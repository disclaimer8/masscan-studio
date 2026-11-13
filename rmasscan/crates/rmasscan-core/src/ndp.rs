//! Кодек IPv6 Neighbor Discovery: Neighbor Solicitation (ICMPv6 135) и Neighbor Advertisement (136) поверх
//! Ethernet (AGPL-3.0). Порт ответчика `stack_ndpv6_incoming_request` (`src/stack-ndpv6.c:95-182`) и разбора
//! `proto-preprocess.c:parse_icmpv6` (:315-335), masscan © Robert David Graham (HEAD 8e6b3b0), плюс кодировщик
//! Neighbor Solicitation и разбор Neighbor Advertisement по RFC 4861 (§4.3, §4.4, §7.1, §7.2.4).
//!
//! Отличия от C, намеренные (каждое идёт в README):
//! * В C нет кодировщика Neighbor Solicitation: `stack_ndpv6_resolve` (:312-487) ищет маршрутизатор Router
//!   Solicitation (133) и ждёт Router Advertisement (134). Здесь соседа и шлюз разрешают Neighbor Solicitation
//!   на solicited-node multicast (RFC 4861 §7.2.2), как ARP-резолвер.
//! * Ответчик C отвечает только по случайному совпадению: `parsed->opcode` (проверка `!= 135`, :112) заполняет один разбор ARP
//!   (`proto-preprocess.c:604-605`), а `parse_icmpv6` кладёт тип в `port_src` и `opcode` не трогает; `main.c:833`
//!   и `:845` читают `parsed.opcode` ICMPv6-кадра, то есть чужое значение. Здесь тип читается из самого кадра.
//! * C копирует запрос целиком (:145) и не переписывает IPv6 `payload_length`: на запрос без опции Source
//!   Link-Layer (payload 24) уходит кадр с 32 байтами ICMPv6 и длиной 24, получатель его обрезает и сумма не
//!   сходится. Здесь длина всегда 32 (86 байт кадра).
//! * C не проверяет hop limit 255, code 0, сумму и не отличает `::` как источник запроса (RFC 4861 §7.1.1). Здесь
//!   запрос с любым из этих нарушений молча отбрасывается, а запрос от `::` (проверка дубликата адреса, DAD) не
//!   получает ответа: C ответил бы на `::`.
//! * Hop limit ответа 255 (RFC 4861 §7.1.2), а не копия запроса; traffic class и flow label нулевые (C копирует).
//! * MAC получателя ответа C берёт из Ethernet-источника запроса (:149), как и здесь; опцию Source Link-Layer
//!   Address запроса игнорируют оба.
//! * Расширения IPv6 в кадрах NDP не допускаются (`next_header` обязан быть 58): C проходит цепочку расширений.

use crate::checksum::checksum_ipv6;

/// Длина кадра NS и NA: Ethernet 14 + IPv6 40 + ICMPv6 32 (заголовок 8, адрес цели 16, одна опция 8).
pub const NDP_FRAME_LEN: usize = 86;
const ETH: usize = 14;
const IP: usize = 40;
const ICMP: usize = 32;
const NEXT_HEADER_ICMPV6: u8 = 58;
const HOP_LIMIT: u8 = 255;
/// ICMPv6 type 135 (RFC 4861 §4.3).
pub const NEIGHBOR_SOLICITATION: u8 = 135;
/// ICMPv6 type 136 (RFC 4861 §4.4).
pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;
/// Опции Source / Target Link-Layer Address (RFC 4861 §4.6.1).
const OPT_SLLA: u8 = 1;
const OPT_TLLA: u8 = 2;
/// Флаги NA в ответе C (:161): `0x60` = Solicited | Override. Router (0x80) не ставится.
pub const NA_FLAGS_SOLICITED_OVERRIDE: u8 = 0x60;
const NA_FLAG_SOLICITED: u8 = 0x40;

/// `ff02::1:ff00:0/104` | младшие 24 бита адреса цели (RFC 4291 §2.7.1).
pub fn solicited_node_address(target: u128) -> u128 {
    0xff02_0000_0000_0000_0000_0001_ff00_0000u128 | (target & 0x00ff_ffff)
}

/// Ethernet-адрес группы solicited-node: `33:33:ff:XX:XX:XX` (RFC 2464 §7).
pub fn solicited_node_mac(target: u128) -> [u8; 6] {
    let t = target.to_be_bytes();
    [0x33, 0x33, 0xff, t[13], t[14], t[15]]
}

fn is_multicast(ip: u128) -> bool {
    ip >> 120 == 0xff
}

/// Поля кадра NS/NA (всё остальное у них общее).
struct Msg {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src_ip: u128,
    dst_ip: u128,
    icmp_type: u8,
    flags: u8,
    target: u128,
    option_type: u8,
    option_mac: [u8; 6],
}

fn build(m: Msg) -> [u8; NDP_FRAME_LEN] {
    let Msg {
        dst_mac,
        src_mac,
        src_ip,
        dst_ip,
        icmp_type,
        flags,
        target,
        option_type,
        option_mac,
    } = m;
    let mut f = [0u8; NDP_FRAME_LEN];
    f[0..6].copy_from_slice(&dst_mac);
    f[6..12].copy_from_slice(&src_mac);
    f[12..14].copy_from_slice(&[0x86, 0xdd]);
    f[14] = 0x60;
    f[18..20].copy_from_slice(&(ICMP as u16).to_be_bytes());
    f[20] = NEXT_HEADER_ICMPV6;
    f[21] = HOP_LIMIT;
    f[22..38].copy_from_slice(&src_ip.to_be_bytes());
    f[38..54].copy_from_slice(&dst_ip.to_be_bytes());
    let i = ETH + IP;
    f[i] = icmp_type;
    // code 0, checksum 0 для расчёта
    f[i + 4] = flags;
    f[i + 8..i + 24].copy_from_slice(&target.to_be_bytes());
    f[i + 24] = option_type;
    f[i + 25] = 1;
    f[i + 26..i + 32].copy_from_slice(&option_mac);
    let x = checksum_ipv6(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &f[i..]);
    f[i + 2..i + 4].copy_from_slice(&x.to_be_bytes());
    f
}

/// Neighbor Solicitation "кто имеет `target`" (RFC 4861 §7.2.2): Ethernet на группу solicited-node цели, IPv6
/// `my_ip` -> `ff02::1:ffXX:XXXX`, hop limit 255, опция Source Link-Layer Address = `my_mac`. 86 байт.
pub fn encode_neighbor_solicitation(
    my_mac: [u8; 6],
    my_ip: u128,
    target: u128,
) -> [u8; NDP_FRAME_LEN] {
    build(Msg {
        dst_mac: solicited_node_mac(target),
        src_mac: my_mac,
        src_ip: my_ip,
        dst_ip: solicited_node_address(target),
        icmp_type: NEIGHBOR_SOLICITATION,
        flags: 0,
        target,
        option_type: OPT_SLLA,
        option_mac: my_mac,
    })
}

/// Neighbor Advertisement (Solicited | Override, как `stack-ndpv6.c:161`) от `my_ip`/`my_mac` к `dst_mac`/`dst_ip`
/// с опцией Target Link-Layer Address = `my_mac`. Всегда 86 байт и `payload_length` 32 (ошибка длины C :145).
pub fn encode_neighbor_advertisement(
    my_mac: [u8; 6],
    my_ip: u128,
    dst_mac: [u8; 6],
    dst_ip: u128,
) -> [u8; NDP_FRAME_LEN] {
    build(Msg {
        dst_mac,
        src_mac: my_mac,
        src_ip: my_ip,
        dst_ip,
        icmp_type: NEIGHBOR_ADVERTISEMENT,
        flags: NA_FLAGS_SOLICITED_OVERRIDE,
        target: my_ip,
        option_type: OPT_TLLA,
        option_mac: my_mac,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NdpError {
    #[error("truncated NDP frame ({0} bytes)")]
    Truncated(usize),
    #[error("not an IPv6 frame (ethertype 0x{0:04x})")]
    NotIpv6(u16),
    #[error("not an IPv6 ICMPv6 packet without extension headers (next header {0})")]
    NotIcmpv6(u8),
    #[error("IPv6 payload length {payload} exceeds the {available} bytes present")]
    PayloadBeyondFrame { payload: usize, available: usize },
    #[error("ICMPv6 type {0} is not the expected Neighbor message")]
    WrongType(u8),
    #[error("hop limit {0} is not 255 (RFC 4861 §7.1)")]
    HopLimit(u8),
    #[error("ICMPv6 code {0} is not 0")]
    Code(u8),
    #[error("ICMPv6 length {0} is below 24")]
    Length(usize),
    #[error("ICMPv6 checksum mismatch")]
    Checksum,
    #[error("target address is multicast")]
    TargetMulticast,
    #[error("an option has length 0 or runs past the packet")]
    BadOption,
    #[error("no Target Link-Layer Address option")]
    NoTargetLla,
    #[error("source is the unspecified address (duplicate address detection)")]
    UnspecifiedSource,
    #[error("multicast destination with the Solicited flag set (RFC 4861 §7.1.2)")]
    SolicitedToMulticast,
}

/// Общая проверка RFC 4861 §7.1: кадр Ethernet/IPv6, `next_header` 58, hop limit 255, code 0, длина >= 24, сумма.
/// Возвращает (адреса, ICMPv6 после обрезки Ethernet-трейлера по `payload_length`).
fn common(frame: &[u8], icmp_type: u8) -> Result<(u128, u128, &[u8]), NdpError> {
    if frame.len() < ETH + IP + 4 {
        return Err(NdpError::Truncated(frame.len()));
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x86dd {
        return Err(NdpError::NotIpv6(ethertype));
    }
    let ip = &frame[ETH..];
    if ip[0] >> 4 != 6 {
        return Err(NdpError::NotIpv6(ethertype));
    }
    if ip[6] != NEXT_HEADER_ICMPV6 {
        return Err(NdpError::NotIcmpv6(ip[6]));
    }
    let payload = usize::from(u16::from_be_bytes([ip[4], ip[5]]));
    let available = ip.len() - IP;
    if payload > available {
        return Err(NdpError::PayloadBeyondFrame { payload, available });
    }
    let icmp = &ip[IP..IP + payload];
    let src = u128::from_be_bytes(ip[8..24].try_into().expect("16 bytes"));
    let dst = u128::from_be_bytes(ip[24..40].try_into().expect("16 bytes"));
    if icmp.len() < 4 {
        return Err(NdpError::Length(icmp.len()));
    }
    if icmp[0] != icmp_type {
        return Err(NdpError::WrongType(icmp[0]));
    }
    if ip[7] != HOP_LIMIT {
        return Err(NdpError::HopLimit(ip[7]));
    }
    if icmp[1] != 0 {
        return Err(NdpError::Code(icmp[1]));
    }
    if icmp.len() < 24 {
        return Err(NdpError::Length(icmp.len()));
    }
    let stored = u16::from_be_bytes([icmp[2], icmp[3]]);
    if checksum_ipv6(src, dst, NEXT_HEADER_ICMPV6, icmp) != stored {
        return Err(NdpError::Checksum);
    }
    Ok((src, dst, icmp))
}

/// Первая опция заданного типа длиной 8 байт (RFC 4861 §4.6: длина в 8-байтных единицах, 0 недопустима).
fn find_lla(options: &[u8], wanted: u8) -> Result<Option<[u8; 6]>, NdpError> {
    let mut found = None;
    let mut o = options;
    while !o.is_empty() {
        if o.len() < 2 {
            return Err(NdpError::BadOption);
        }
        let len = usize::from(o[1]) * 8;
        if len == 0 || len > o.len() {
            return Err(NdpError::BadOption);
        }
        if o[0] == wanted && len == 8 && found.is_none() {
            found = Some(o[2..8].try_into().expect("6 bytes"));
        }
        o = &o[len..];
    }
    Ok(found)
}

/// Разобранный Neighbor Advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighborAdvertisement {
    pub eth_dst: [u8; 6],
    pub eth_src: [u8; 6],
    pub src_ip: u128,
    pub dst_ip: u128,
    pub flags: u8,
    pub target: u128,
    /// Опция Target Link-Layer Address.
    pub target_lla: [u8; 6],
}

/// Разбор NA по RFC 4861 §7.1.2: hop limit 255, code 0, длина >= 24, верная сумма, цель не multicast, опции
/// корректны, при multicast-получателе флаг Solicited сброшен. NA без опции Target Link-Layer Address не годится
/// для разрешения (`NoTargetLla`).
pub fn decode_neighbor_advertisement(frame: &[u8]) -> Result<NeighborAdvertisement, NdpError> {
    let (src, dst, icmp) = common(frame, NEIGHBOR_ADVERTISEMENT)?;
    let flags = icmp[4];
    let target = u128::from_be_bytes(icmp[8..24].try_into().expect("16 bytes"));
    if is_multicast(target) {
        return Err(NdpError::TargetMulticast);
    }
    if is_multicast(dst) && flags & NA_FLAG_SOLICITED != 0 {
        return Err(NdpError::SolicitedToMulticast);
    }
    let target_lla = find_lla(&icmp[24..], OPT_TLLA)?.ok_or(NdpError::NoTargetLla)?;
    Ok(NeighborAdvertisement {
        eth_dst: frame[0..6].try_into().expect("6 bytes"),
        eth_src: frame[6..12].try_into().expect("6 bytes"),
        src_ip: src,
        dst_ip: dst,
        flags,
        target,
        target_lla,
    })
}

/// Разобранный Neighbor Solicitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighborSolicitation {
    pub eth_src: [u8; 6],
    pub src_ip: u128,
    pub dst_ip: u128,
    pub target: u128,
}

/// Разбор NS по RFC 4861 §7.1.1 (hop limit 255, code 0, длина >= 24, сумма, цель не multicast, опции корректны).
/// Источник `::` (DAD) это `UnspecifiedSource`: ответа на него нет.
pub fn decode_neighbor_solicitation(frame: &[u8]) -> Result<NeighborSolicitation, NdpError> {
    let (src, dst, icmp) = common(frame, NEIGHBOR_SOLICITATION)?;
    let target = u128::from_be_bytes(icmp[8..24].try_into().expect("16 bytes"));
    if is_multicast(target) {
        return Err(NdpError::TargetMulticast);
    }
    if src == 0 {
        return Err(NdpError::UnspecifiedSource);
    }
    find_lla(&icmp[24..], OPT_SLLA)?;
    Ok(NeighborSolicitation {
        eth_src: frame[6..12].try_into().expect("6 bytes"),
        src_ip: src,
        dst_ip: dst,
        target,
    })
}

/// Ответ на входящий NS для нашего адреса (`stack_ndpv6_incoming_request`, `stack-ndpv6.c:95-182`): `None`, если
/// кадр не валидный NS, цель не `my_ip` (:128-130, `is_my_ip`) или адресат не наш адрес и не его solicited-node. Ответ идёт на Ethernet-источник и IPv6-источник
/// запроса (:149-150), от `my_ip`/`my_mac`.
pub fn answer_neighbor_solicitation(
    frame: &[u8],
    my_mac: [u8; 6],
    my_ip: u128,
) -> Option<[u8; NDP_FRAME_LEN]> {
    let ns = decode_neighbor_solicitation(frame).ok()?;
    // Ответ идёт на источник запроса: multicast в качестве адресата недопустим (RFC 4861 §7.2.4 отвечает только
    // unicast-источнику), поэтому такой NS отбрасывается. Ethernet-источник multicast/broadcast тоже.
    if is_multicast(ns.src_ip) || ns.eth_src[0] & 1 != 0 {
        return None;
    }
    // Адресат: наш адрес или solicited-node multicast нашего адреса (RFC 4861 §7.1.1); C берёт любой ff02::/16.
    if ns.target != my_ip || (ns.dst_ip != my_ip && ns.dst_ip != solicited_node_address(my_ip)) {
        return None;
    }
    Some(encode_neighbor_advertisement(
        my_mac, my_ip, ns.eth_src, ns.src_ip,
    ))
}

/// Ожидающее разрешение соседа, как `arp::PendingResolve`: принимает только NA, подходящий под наш NS.
#[derive(Clone, Debug)]
pub struct PendingNdp {
    my_mac: [u8; 6],
    my_ip: u128,
    target: u128,
    resolved: Option<[u8; 6]>,
}

impl PendingNdp {
    pub fn new(my_mac: [u8; 6], my_ip: u128, target: u128) -> Self {
        Self {
            my_mac,
            my_ip,
            target,
            resolved: None,
        }
    }

    /// Кадр запроса (86 байт).
    pub fn request_frame(&self) -> [u8; NDP_FRAME_LEN] {
        encode_neighbor_solicitation(self.my_mac, self.my_ip, self.target)
    }

    /// Принимает кадр: NA по RFC 4861 §7.1.2, цель равна искомой, адресован нам (IPv6 и Ethernet), опция Target
    /// Link-Layer Address не multicast и не нулевая. Иначе `None`, состояние не меняется.
    pub fn offer(&mut self, frame: &[u8]) -> Option<[u8; 6]> {
        let na = decode_neighbor_advertisement(frame).ok()?;
        if na.target != self.target || na.dst_ip != self.my_ip || na.eth_dst != self.my_mac {
            return None;
        }
        if na.target_lla[0] & 1 != 0 || na.target_lla == [0; 6] {
            return None;
        }
        self.resolved = Some(na.target_lla);
        self.resolved
    }

    pub fn resolved(&self) -> Option<[u8; 6]> {
        self.resolved
    }
}

#[cfg(test)]
#[path = "ndp_tests.rs"]
mod ndp_tests;
