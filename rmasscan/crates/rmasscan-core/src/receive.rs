//! Разбор входящих кадров и проверка ответа (AGPL-3.0). Порт ветки
//! `receive_thread` из `src/main.c:533` (SYN-ACK/RST, :970 и :1048-1065) и
//! `preprocess_frame` из `src/proto-preprocess.c:60`, masscan © Robert David
//! Graham (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Вход недоверенный. Парсер сначала проверяет границы, потом читает байты;
//! индексирования без проверки здесь нет (`get`/`split_at_checked`).
//!
//! # Правило приёма (main.c:823-825, :829, :935, :1048-1065)
//! Ответ принимается, если одновременно:
//! 1. IPv4, не фрагмент, TCP (или ICMP Echo Reply и Port Unreachable `3/3`: [`parse_icmp`], UDP: [`parse_udp_reply`], SCTP INIT-ACK и
//!    ABORT: [`parse_sctp_reply`], у них свои правила, описанные у функций); адрес назначения лежит в диапазоне `source_ipv4..=source_ipv4_last` плана
//!    (`--adapter-ip A-B`; один адрес это диапазон из одного);
//! 2. порт назначения лежит в `source_ports` плана (`is_my_port`);
//! 3. флаги: `(flags & 0x12) == 0x12` даёт Open, `flags & 0x04` даёт Closed
//!    (RST перекрывает SYN-ACK, как в C: статус сначала Open, затем Closed);
//! 4. удалённые IP и порт входят в ИТОГОВЫЙ набор целей задания
//!    (`effective().massip()`, после исключений; не `source_targets`); поиск
//!    двоичный, проверка идёт до cookie и контрольных сумм;
//! 5. `cookie == ackno - 1` (беззнаковая арифметика `unsigned`), где
//!    `cookie = syn_cookie_ipv4(ip_them, port_them, ip_me, port_me, seed) as u32`.
//!
//! Всё остальное это `Ok(None)` (в C `continue`), не ошибка и не Open.
//!
//! # Отличия от C (намеренные, жёстче)
//! - IHL < 5 и смещение данных TCP < 5 отклоняются (C: `px[12]>>2` без маски
//!   и без нижней границы).
//! - VLAN (0x8100/0x88A8/0x9100) возвращает [`ParseError::Unsupported`], а не
//!   разбирается; в IPv4 не интерпретируется никогда.
//! - Кадр длиннее 1514 байт это [`ParseError::FrameTooLong`] (C: `continue`).
//! - Контрольные суммы IPv4/TCP проверяются (C этого не делает, "TODO: verify
//!   checksum"); политика задаётся [`ChecksumPolicy`], по умолчанию `Verify`.
//! - Принимаются только ответы на цели ЭТОГО плана (эффективные цели без
//!   исключений, порты, source-порты). Приёмный путь C не проверяет множество
//!   целей: он опирается только на cookie, поэтому поздний корректный ответ
//!   старого скана с тем же seed попадал бы в результаты. Порт намеренно
//!   ужесточает это (ревью 2A, P2).

use crate::arp::{ArpOp, decode};
use crate::checksum::{
    checksum_ipv4, checksum_ipv6, fold, ip_header_checksum, sctp_crc32c, udp_ipv4_checksum_ok,
    word_sum,
};
use crate::cookie::{icmp_echo_cookie, syn_cookie_ipv4, syn_cookie_ipv6};
use crate::ndp::{NDP_FRAME_LEN, answer_neighbor_solicitation};
use crate::packet::LinkType;
use crate::probe::ReadyPlan;
use crate::ranges::RangeList;
use crate::targets::{TEMPL_ICMP_ECHO, TEMPL_SCTP, TEMPL_TCP, TEMPL_UDP};

/// main.c:773 `if (length > 1514) continue;`.
pub const MAX_FRAME_LEN: usize = 1514;

const FLAG_RST: u8 = 0x04;
const FLAG_SYNACK_MASK: u8 = 0x12;

/// Как относиться к контрольным суммам входящих кадров. Это явный выбор
/// вызывающего, а не глобальный флаг.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ChecksumPolicy {
    /// Проверять суммы IPv4-заголовка и TCP-сегмента.
    #[default]
    Verify,
    /// Не проверять: только если адаптер сам проверил суммы (RX checksum
    /// offload) и нечитаемые поля в кадре не гарантированы. Cookie проверяется
    /// всегда.
    TrustHardware,
}

/// Что остановка разбора не поддерживает.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// 802.1Q / QinQ: теги не снимаются, кадр не трактуется как IPv4.
    Vlan,
}

/// Ошибки разбора. `Ok(None)` (не наш пакет) от них отличается.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("frame of {0} bytes exceeds {MAX_FRAME_LEN}")]
    FrameTooLong(usize),
    #[error("truncated {0}")]
    Truncated(&'static str),
    #[error("not IPv4: version nibble {0}")]
    BadIpVersion(u8),
    #[error("bad IPv4 header length: IHL {0}")]
    BadIpv4HeaderLength(u8),
    #[error("IPv4 total length {total} is smaller than header length {header}")]
    TotalLengthBelowHeader { total: u16, header: usize },
    #[error("IPv4 total length {total} exceeds the {available} bytes present")]
    TotalLengthBeyondFrame { total: u16, available: usize },
    #[error("IPv4 fragment")]
    Fragment,
    #[error("IPv6 payload length {payload} exceeds the {available} bytes present after the header")]
    Ipv6PayloadBeyondFrame { payload: u16, available: usize },
    #[error("bad TCP data offset {0}")]
    BadTcpDataOffset(u8),
    #[error("unsupported: {0:?}")]
    Unsupported(Unsupported),
    #[error("unknown loopback address family 0x{0:08x}")]
    UnknownNullFamily(u32),
    #[error("unsupported link type {0}")]
    UnsupportedLinkType(u32),
    #[error("bad IPv4 header checksum")]
    BadIpChecksum,
    #[error("bad TCP checksum")]
    BadTcpChecksum,
    #[error("bad ICMP checksum")]
    BadIcmpChecksum,
    #[error("bad UDP length {0}")]
    BadUdpLength(u16),
    #[error("bad UDP checksum")]
    BadUdpChecksum,
    #[error("bad SCTP checksum")]
    BadSctpChecksum,
}

/// Открыт или закрыт порт (main.c:1052-1057).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortStatus {
    Open,
    Closed,
    /// ARP-сосед отозвался (`PortStatus_Arp`, `output.c:109–116`, печатается как `up`).
    Arp,
}

/// Адреса IPv6-ответа (R2): у ответа IPv6 `remote_ip` и `local_ip` равны 0, потому что Студия читает `remote_ip`
/// как IPv4; настоящие адреса лежат в [`Reply::ip6`]. Порядок `u128` старший байт первый (сетевой), как у
/// `ipv6address {hi, lo}` в C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyIpv6 {
    /// Источник ответа (`ip_them`, цель скана).
    pub remote: u128,
    /// Получатель ответа (`ip_me`, наш `source_ipv6`).
    pub local: u128,
}

/// Принятый ответ. Время ставит engine, не парсер.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub remote_ip: u32,
    pub remote_port: u16,
    pub local_ip: u32,
    pub local_port: u16,
    pub status: PortStatus,
    /// Байт флагов TCP (`px[transport_offset + 13]`).
    pub tcp_flags: u8,
    pub ttl: u8,
    /// Номер IP-протокола ответа (`output_report_status(.., ip_proto, ..)`, `output.c:75–86`): 6 TCP, 17 UDP,
    /// 132 SCTP, 1 ICMP, 0 ARP. Разбор TCP этого файла всегда ставит 6.
    pub ip_proto: u8,
    /// MAC соседа (`sha` ответа ARP); `None` у всех остальных ответов.
    pub mac: Option<[u8; 6]>,
    /// Адреса ответа поверх IPv6; `None` у каждого IPv4-ответа (его байты и поля прежние). У `Some` поля
    /// `remote_ip` и `local_ip` равны 0 и не значат адреса. Ключ дедупа `DedupCache` (rmasscan-engine) берёт эти
    /// адреса целиком; `ttl` у такого ответа это hop limit (`px[offset_ip + 7]`).
    pub ip6: Option<ReplyIpv6>,
}

/// Преобразование pcap DLT в [`LinkType`]; остальное это явная ошибка.
pub fn link_type_from_dlt(dlt: u32) -> Result<LinkType, ParseError> {
    match dlt {
        0 => Ok(LinkType::Null),
        1 => Ok(LinkType::Ethernet),
        12 => Ok(LinkType::Raw),
        other => Err(ParseError::UnsupportedLinkType(other)),
    }
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn be32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(i)?,
        *b.get(i + 1)?,
        *b.get(i + 2)?,
        *b.get(i + 3)?,
    ]))
}

/// [`parse_reply_with`] с политикой [`ChecksumPolicy::Verify`].
pub fn parse_reply(
    frame: &[u8],
    link: LinkType,
    plan: &ReadyPlan,
) -> Result<Option<Reply>, ParseError> {
    parse_reply_with(frame, link, plan, ChecksumPolicy::Verify)
}

/// Разбирает кадр и применяет правило приёма из описания модуля.
pub fn parse_reply_with(
    frame: &[u8],
    link: LinkType,
    plan: &ReadyPlan,
    policy: ChecksumPolicy,
) -> Result<Option<Reply>, ParseError> {
    if frame.len() > MAX_FRAME_LEN {
        return Err(ParseError::FrameTooLong(frame.len()));
    }
    // ARP-скан: ответ ARP это не IPv4, он разбирается до `locate_ipv4` (main.c:874-906, `FOUND_ARP`).
    if link == LinkType::Ethernet && be16(frame, 12) == Some(0x0806) {
        return Ok(parse_arp_reply(frame, plan));
    }
    let Some(ip) = locate_ipv4(frame, link)? else {
        // Не IPv4: IPv6 (`parse_ipv6`, proto-preprocess.c:215) или прочее (ARP разобран выше, NDP и остальное C
        // обрабатывает вне TCP-ветки, здесь это `None`).
        // План без `source_ipv6` (IPv4 и Студия) не принимает IPv6 вовсе: такой кадр ни свой, ни ошибка, и пути
        // IPv4 остаются как были.
        if plan.nics()[0].source_ipv6.is_none() {
            return Ok(None);
        }
        return match locate_ipv6(frame, link)? {
            Some(ip6) => parse_ipv6_tcp(ip6, plan, policy),
            None => Ok(None),
        };
    };
    parse_ipv4_tcp(ip, plan, policy)
}

/// Полезная нагрузка UDP-датаграммы кадра (`px + parsed->app_offset`, `parsed->app_length`,
/// `src/proto-preprocess.c:165-174`): то, что UDP-парсеры баннеров получают в C (`src/proto-udp.c:76-131`).
///
/// Разбор канального уровня и IP общий с [`parse_reply`] (`locate_ipv4`/`locate_ipv6`, `ipv4_packet`, `ipv6_packet`),
/// поэтому для кадра, который [`parse_reply`] принял как ответ UDP, это нагрузка того же кадра. Конец нагрузки, как у C,
/// конец IP-пакета (полная длина IPv4, `payload_length` IPv6), а не поле длины UDP: C его не читает
/// (`length = offset + total_length`, `src/proto-preprocess.c:109`, затем `app_length = length - app_offset`, `:173`).
/// `None`: кадр не UDP (ARP, TCP, ICMP, ...), искажён или длиннее [`MAX_FRAME_LEN`]. Для IPv6 ответ есть, хотя
/// [`parse_reply`] UDP поверх IPv6 пока не принимает (R3 этапа IPv6).
pub fn udp_payload(frame: &[u8], link: LinkType) -> Option<&[u8]> {
    if frame.len() > MAX_FRAME_LEN {
        return None;
    }
    if link == LinkType::Ethernet && be16(frame, 12) == Some(0x0806) {
        return None;
    }
    let seg = match locate_ipv4(frame, link).ok()? {
        Some(ip) => {
            let p = ipv4_packet(ip).ok()?;
            if p.proto != 17 {
                return None;
            }
            p.ip.get(p.header_len..)?
        }
        None => {
            let p = ipv6_packet(locate_ipv6(frame, link).ok()??).ok()?;
            if p.next != 17 {
                return None;
            }
            p.ip.get(p.offset..)?
        }
    };
    // proto-preprocess.c:167: заголовок UDP 8 байт (`VERIFY_REMAINING(8, FOUND_UDP)`).
    seg.get(8..)
}

/// Ответ на входящий Neighbor Solicitation для `source_ipv6` адаптера `nic[0]` (`main.c:829-840` и `:859`,
/// `stack_ndpv6_incoming_request`, `stack-ndpv6.c:95-182`): готовый кадр Neighbor Advertisement (86 байт,
/// `payload_length` 32) или `None`. `None` для плана без `source_ipv6` (IPv4 и Студия), для не Ethernet, для кадра
/// не NS и для NS чужого адреса. Кадр не парсится как зонд и в результаты не попадает.
///
/// Отличие от C: адресат NS это наш адрес либо его solicited-node multicast (RFC 4861 §7.1.1); C принимает любой
/// `ff02::/16` (`is_ipv6_multicast`, main.c:515-520).
pub fn ndp_reply_for(
    frame: &[u8],
    link: LinkType,
    plan: &ReadyPlan,
) -> Option<[u8; NDP_FRAME_LEN]> {
    if link != LinkType::Ethernet {
        return None;
    }
    let nic = plan.nics().first()?;
    let my_ip = nic.source_ipv6?;
    answer_neighbor_solicitation(frame, nic.binding.source_mac, my_ip)
}

/// Находит заголовок IPv6 (`parse_ethertype` `0x86dd`, proto-preprocess.c:505; Null :522-531; Raw :534-538).
/// `Ok(None)`: кадр не IPv6. Вызывается только после [`locate_ipv4`] вернул `None`, поэтому ошибки VLAN и версии
/// там уже обработаны.
fn locate_ipv6(frame: &[u8], link: LinkType) -> Result<Option<&[u8]>, ParseError> {
    match link {
        LinkType::Ethernet => match be16(frame, 12) {
            Some(0x86dd) if frame.len() >= 14 => Ok(Some(&frame[14..])),
            _ => Ok(None),
        },
        LinkType::Null => {
            // Значения 24, 28, 30 (`AF_INET6` разных ОС), в любом порядке байт (proto-preprocess.c:523-531).
            let family = be32(frame, 0).ok_or(ParseError::Truncated("null header"))?;
            match family {
                0x1800_0000 | 0x0000_0018 | 0x1c00_0000 | 0x0000_001c | 0x1e00_0000
                | 0x0000_001e => Ok(Some(&frame[4..])),
                _ => Ok(None),
            }
        }
        LinkType::Raw => match frame.first().map(|b| b >> 4) {
            Some(6) => Ok(Some(frame)),
            _ => Ok(None),
        },
    }
}

/// Находит IPv4-заголовок. `Ok(None)`: кадр не IPv4 (ARP, IPv6, прочее).
fn locate_ipv4(frame: &[u8], link: LinkType) -> Result<Option<&[u8]>, ParseError> {
    match link {
        LinkType::Ethernet => {
            let ethertype = be16(frame, 12).ok_or(ParseError::Truncated("ethernet header"))?;
            if frame.len() < 14 {
                return Err(ParseError::Truncated("ethernet header"));
            }
            match ethertype {
                0x0800 => Ok(Some(&frame[14..])),
                0x8100 | 0x88a8 | 0x9100 => Err(ParseError::Unsupported(Unsupported::Vlan)),
                _ => Ok(None),
            }
        }
        LinkType::Null => {
            // proto-preprocess.c:495-509: семейство в первых 4 байтах, в любом порядке.
            let family = be32(frame, 0).ok_or(ParseError::Truncated("null header"))?;
            match family {
                0x0200_0000 | 0x0000_0002 => Ok(Some(&frame[4..])),
                0x1800_0000 | 0x0000_0018 | 0x1c00_0000 | 0x0000_001c | 0x1e00_0000
                | 0x0000_001e => Ok(None),
                other => Err(ParseError::UnknownNullFamily(other)),
            }
        }
        LinkType::Raw => {
            let first = *frame.first().ok_or(ParseError::Truncated("raw header"))?;
            match first >> 4 {
                4 => Ok(Some(frame)),
                6 => Ok(None),
                other => Err(ParseError::BadIpVersion(other)),
            }
        }
    }
}

/// Двоичный поиск в отсортированных непересекающихся диапазонах: O(log n).
fn in_sorted_ranges(list: &RangeList, value: u32) -> bool {
    let ranges = list.as_slice();
    let idx = ranges.partition_point(|r| r.begin <= value);
    idx.checked_sub(1)
        .and_then(|i| ranges.get(i))
        .is_some_and(|r| value <= r.end)
}

/// Проверенный пакет IPv4: обрезан по полю полной длины, заголовок и его поля прочитаны.
struct Ipv4Packet<'a> {
    /// Пакет до `total_length` (трейлер Ethernet отброшен).
    ip: &'a [u8],
    header_len: usize,
    ttl: u8,
    proto: u8,
    ip_them: u32,
    ip_me: u32,
}

/// Заголовок IPv4 (proto-preprocess.c:104-146): общий разбор [`parse_reply`] и [`udp_payload`], поэтому оба видят
/// один и тот же пакет.
fn ipv4_packet(ip: &[u8]) -> Result<Ipv4Packet<'_>, ParseError> {
    let b0 = *ip.first().ok_or(ParseError::Truncated("ipv4 header"))?;
    if ip.len() < 20 {
        return Err(ParseError::Truncated("ipv4 header"));
    }
    if b0 >> 4 != 4 {
        return Err(ParseError::BadIpVersion(b0 >> 4));
    }
    let ihl = b0 & 0x0f;
    if ihl < 5 {
        return Err(ParseError::BadIpv4HeaderLength(ihl));
    }
    let header_len = usize::from(ihl) * 4;
    if ip.len() < header_len {
        return Err(ParseError::Truncated("ipv4 options"));
    }
    let frag = be16(ip, 6).ok_or(ParseError::Truncated("ipv4 header"))?;
    if frag & 0x3fff != 0 {
        return Err(ParseError::Fragment);
    }
    let total = be16(ip, 2).ok_or(ParseError::Truncated("ipv4 header"))?;
    if usize::from(total) < header_len {
        return Err(ParseError::TotalLengthBelowHeader {
            total,
            header: header_len,
        });
    }
    if usize::from(total) > ip.len() {
        return Err(ParseError::TotalLengthBeyondFrame {
            total,
            available: ip.len(),
        });
    }
    // Трейлер Ethernet (padding) отбрасывается: "length = offset + total_length".
    let ip = &ip[..usize::from(total)];
    Ok(Ipv4Packet {
        ip,
        header_len,
        ttl: ip[8],
        proto: ip[9],
        ip_them: be32(ip, 12).ok_or(ParseError::Truncated("ipv4 header"))?,
        ip_me: be32(ip, 16).ok_or(ParseError::Truncated("ipv4 header"))?,
    })
}

fn parse_ipv4_tcp(
    ip: &[u8],
    plan: &ReadyPlan,
    policy: ChecksumPolicy,
) -> Result<Option<Reply>, ParseError> {
    // proto-preprocess.c:104-146.
    let Ipv4Packet {
        ip,
        header_len,
        ttl,
        proto,
        ip_them,
        ip_me,
    } = ipv4_packet(ip)?;
    match proto {
        1 => return parse_icmp(ip, header_len, (ip_them, ip_me, ttl), plan, policy),
        17 => return parse_udp_reply(ip, header_len, (ip_them, ip_me, ttl), plan, policy),
        132 => return parse_sctp_reply(ip, header_len, (ip_them, ip_me, ttl), plan, policy),
        6 => {}
        // прочее: не наш SYN-ответ.
        _ => return Ok(None),
    }

    // proto-preprocess.c:208-218.
    let seg = &ip[header_len..];
    if seg.len() < 20 {
        return Err(ParseError::Truncated("tcp header"));
    }
    let data_offset = seg[12] >> 4;
    if data_offset < 5 {
        return Err(ParseError::BadTcpDataOffset(data_offset));
    }
    if seg.len() < usize::from(data_offset) * 4 {
        return Err(ParseError::Truncated("tcp options"));
    }
    let port_them = be16(seg, 0).ok_or(ParseError::Truncated("tcp header"))?;
    let port_me = be16(seg, 2).ok_or(ParseError::Truncated("tcp header"))?;
    let ackno = be32(seg, 8).ok_or(ParseError::Truncated("tcp header"))?;
    let flags = seg[13];

    // main.c:829: is_my_ip. `--adapter-ip A-B`: любой адрес диапазона `first..=last` адаптера `nic[0]` плана.
    let binding = plan.binding();
    let ip_last = plan.nics()[0].source_ipv4_last;
    if !(binding.source_ipv4..=ip_last).contains(&ip_me) {
        return Ok(None);
    }
    // main.c:935: is_my_port.
    let (first, last) = binding.source_ports;
    if port_me < first || port_me > last {
        return Ok(None);
    }
    // Ответ должен относиться к текущему заданию: отбрасывает поздние ответы
    // прошлого скана с тем же seed и исключённые адреса/порты. Диапазоны
    // итогового набора отсортированы и слиты (`validate` вызывает optimize).
    let targets = plan.effective().massip();
    if !in_sorted_ranges(targets.ipv4(), ip_them)
        || !in_sorted_ranges(targets.ports(), u32::from(port_them))
    {
        return Ok(None);
    }
    // main.c:1048-1057.
    let mut status = None;
    if flags & FLAG_SYNACK_MASK == FLAG_SYNACK_MASK {
        status = Some(PortStatus::Open);
    }
    if flags & FLAG_RST != 0 {
        status = Some(PortStatus::Closed);
    }
    let Some(status) = status else {
        return Ok(None);
    };
    // main.c:825, :1059: cookie == seqno_me - 1.
    let cookie = syn_cookie_ipv4(
        ip_them,
        u32::from(port_them),
        ip_me,
        u32::from(port_me),
        plan.effective().seed(),
    ) as u32;
    if cookie != ackno.wrapping_sub(1) {
        return Ok(None);
    }

    // Суммы проверяются после дешёвых фильтров: сюда доходит только кадр,
    // прошедший криптографический cookie.
    if policy == ChecksumPolicy::Verify {
        if ip_header_checksum(ip, 0, header_len) != 0xffff {
            return Err(ParseError::BadIpChecksum);
        }
        let stored = be16(seg, 16).ok_or(ParseError::Truncated("tcp header"))?;
        if checksum_ipv4(ip_them, ip_me, 6, seg) != stored {
            return Err(ParseError::BadTcpChecksum);
        }
    }

    Ok(Some(Reply {
        remote_ip: ip_them,
        remote_port: port_them,
        local_ip: ip_me,
        local_port: port_me,
        status,
        tcp_flags: flags,
        ttl,
        ip_proto: 6,
        mac: None,
        ip6: None,
    }))
}

/// Двоичный поиск адреса IPv6 в отсортированных непересекающихся диапазонах (`validate` вызывает `optimize`).
fn in_sorted_ranges6(list: &crate::ranges6::Range6List, value: u128) -> bool {
    let ranges = list.as_slice();
    let idx = ranges.partition_point(|r| r.begin <= value);
    idx.checked_sub(1)
        .and_then(|i| ranges.get(i))
        .is_some_and(|r| value <= r.end)
}

/// SYN-ACK и RST поверх IPv6 (`receive_thread`, main.c:830-1065 с `preprocess_frame`, proto-preprocess.c:215-312).
///
/// Порядок и правила как у [`parse_ipv4_tcp`], с отличиями IPv6:
/// - заголовок 40 байт, версия 6, `payload_length` обязан поместиться (:227-228) и обрезает кадр (:229-230,
///   Ethernet-трейлер отбрасывается); IPv6 не имеет суммы заголовка;
/// - цепочка расширений: Next Header 0 (Hop-by-Hop) пропускается и читается заново
///   (:285-309; длина по RFC 8200, не по :306, см. ниже); TCP (6) разбирается; ВСЁ ОСТАЛЬНОЕ (UDP, ICMPv6, SCTP, Fragment 44, Routing 43, ...) это `None`: в C
///   `return 0` (:292-296) или другая ветка, а IPv6-скан этого порта только TCP (R3);
/// - адрес назначения сверяется с `source_ipv6` адаптера `nic[0]` целиком (`is_my_ip`, stack-src.c:13-14); без
///   `source_ipv6` ни один кадр не свой;
/// - cookie это `syn_cookie_ipv6(...)` младшие 32 бита против `ackno - 1` (main.c:825, :1059);
/// - TCP-сумма это RFC 8200 [`checksum_ipv6`] по сегменту после расширений (политика [`ChecksumPolicy`]);
/// - `ttl` ответа это hop limit `px[offset_ip + 7]`. Это отличие от C: `parse_ipv6` не заполняет `ip_ttl` (оно
///   выставляется только в IPv4-ветке, :127), и `main.c:1085` отдал бы мусор из прошлой итерации.
fn parse_ipv6_tcp(
    ip: &[u8],
    plan: &ReadyPlan,
    policy: ChecksumPolicy,
) -> Result<Option<Reply>, ParseError> {
    let Ipv6Packet {
        ip,
        offset,
        next,
        hop_limit,
        ip_them,
        ip_me,
    } = ipv6_packet(ip)?;
    // proto-preprocess.c:285-296: TCP разбирается, всё остальное не наш SYN-ответ (R3).
    if next != 6 {
        return Ok(None);
    }
    parse_ipv6_segment(&ip[offset..], (ip_them, ip_me, hop_limit), plan, policy)
}

/// Проверенный пакет IPv6: обрезан по `payload_length`, цепочка Hop-by-Hop пройдена.
struct Ipv6Packet<'a> {
    /// Пакет до `40 + payload_length` (трейлер Ethernet отброшен).
    ip: &'a [u8],
    /// Смещение транспортного заголовка в `ip` (после расширений Hop-by-Hop).
    offset: usize,
    /// Next Header транспорта: первый заголовок цепочки, который не Hop-by-Hop.
    next: u8,
    hop_limit: u8,
    ip_them: u128,
    ip_me: u128,
}

/// Заголовок IPv6 и цепочка Hop-by-Hop (proto-preprocess.c:215-312): общий разбор [`parse_reply`] и
/// [`udp_payload`].
fn ipv6_packet(ip: &[u8]) -> Result<Ipv6Packet<'_>, ParseError> {
    let b0 = *ip.first().ok_or(ParseError::Truncated("ipv6 header"))?;
    if ip.len() < 40 {
        return Err(ParseError::Truncated("ipv6 header"));
    }
    if b0 >> 4 != 6 {
        return Err(ParseError::BadIpVersion(b0 >> 4));
    }
    let payload_length = be16(ip, 4).ok_or(ParseError::Truncated("ipv6 header"))?;
    if 40 + usize::from(payload_length) > ip.len() {
        return Err(ParseError::Ipv6PayloadBeyondFrame {
            payload: payload_length,
            available: ip.len() - 40,
        });
    }
    let ip = &ip[..40 + usize::from(payload_length)];
    let hop_limit = ip[7];
    let ip_them = u128::from_be_bytes(ip[8..24].try_into().expect("16 bytes"));
    let ip_me = u128::from_be_bytes(ip[24..40].try_into().expect("16 bytes"));

    // proto-preprocess.c:285-309.
    let mut next = ip[6];
    let mut offset = 40usize;
    while next == 0 {
        let ext = ip
            .get(offset..offset + 8)
            .ok_or(ParseError::Truncated("ipv6 hop-by-hop header"))?;
        next = ext[0];
        // RFC 8200 §4.3: `Hdr Ext Len` это число 8-байтовых единиц ПОСЛЕ первых 8 байт. C считает
        // `px[offset+1] + 8` БАЙТ (proto-preprocess.c:306); при 0 это совпадает (8 байт), при n > 0 C
        // недоскочил бы до TCP и потерял ответ. Порт берёт длину по RFC.
        let len = (usize::from(ext[1]) + 1) * 8;
        if offset + len > ip.len() {
            return Err(ParseError::Truncated("ipv6 hop-by-hop header"));
        }
        offset += len;
    }
    Ok(Ipv6Packet {
        ip,
        offset,
        next,
        hop_limit,
        ip_them,
        ip_me,
    })
}

/// Сегмент TCP поверх IPv6 после [`ipv6_packet`]: правило приёма [`parse_ipv6_tcp`].
fn parse_ipv6_segment(
    seg: &[u8],
    (ip_them, ip_me, hop_limit): (u128, u128, u8),
    plan: &ReadyPlan,
    policy: ChecksumPolicy,
) -> Result<Option<Reply>, ParseError> {
    if seg.len() < 20 {
        return Err(ParseError::Truncated("tcp header"));
    }
    let data_offset = seg[12] >> 4;
    if data_offset < 5 {
        return Err(ParseError::BadTcpDataOffset(data_offset));
    }
    if seg.len() < usize::from(data_offset) * 4 {
        return Err(ParseError::Truncated("tcp options"));
    }
    let port_them = be16(seg, 0).ok_or(ParseError::Truncated("tcp header"))?;
    let port_me = be16(seg, 2).ok_or(ParseError::Truncated("tcp header"))?;
    let ackno = be32(seg, 8).ok_or(ParseError::Truncated("tcp header"))?;
    let flags = seg[13];

    // main.c:829: is_my_ip (stack-src.c:13-14, один адрес IPv6).
    if plan.nics()[0].source_ipv6 != Some(ip_me) {
        return Ok(None);
    }
    // main.c:935: is_my_port.
    let (first, last) = plan.binding().source_ports;
    if port_me < first || port_me > last {
        return Ok(None);
    }
    // Как у IPv4: ответ относится к текущему заданию (итоговые цели и порты).
    let targets = plan.effective().massip();
    if !in_sorted_ranges6(targets.ipv6(), ip_them)
        || !in_sorted_ranges(targets.ports(), u32::from(port_them))
    {
        return Ok(None);
    }
    // main.c:1048-1057.
    let mut status = None;
    if flags & FLAG_SYNACK_MASK == FLAG_SYNACK_MASK {
        status = Some(PortStatus::Open);
    }
    if flags & FLAG_RST != 0 {
        status = Some(PortStatus::Closed);
    }
    let Some(status) = status else {
        return Ok(None);
    };
    // main.c:825, :1059.
    let cookie = syn_cookie_ipv6(
        ip_them,
        u32::from(port_them),
        ip_me,
        u32::from(port_me),
        plan.effective().seed(),
    ) as u32;
    if cookie != ackno.wrapping_sub(1) {
        return Ok(None);
    }

    if policy == ChecksumPolicy::Verify {
        let stored = be16(seg, 16).ok_or(ParseError::Truncated("tcp header"))?;
        if checksum_ipv6(ip_them, ip_me, 6, seg) != stored {
            return Err(ParseError::BadTcpChecksum);
        }
    }

    Ok(Some(Reply {
        remote_ip: 0,
        remote_port: port_them,
        local_ip: 0,
        local_port: port_me,
        status,
        tcp_flags: flags,
        ttl: hop_limit,
        ip_proto: 6,
        mac: None,
        ip6: Some(ReplyIpv6 {
            remote: ip_them,
            local: ip_me,
        }),
    }))
}

/// Ответ ARP на наш ARP-скан (ветка `FOUND_ARP`, main.c:874-906, и `arp_recv_response`, proto-arp.c:14-41).
///
/// Принимается, если план это ARP-скан (`scan_type.arp`, :893), opcode равен 2 (:889), `tpa` наш адрес и `spa`
/// входит в итоговый набор целей (:896). `tpa` сверяется, как в C: приёмник отбрасывает каждый кадр, адрес назначения
/// которого не наш, ещё до ветки ARP (main.c:829–837, `is_my_ip(stack->src, ip_me)` и `continue`), а у ARP адрес
/// назначения это `tpa` (proto-preprocess.c:619–621). Поэтому ответ другому узлу, увиденный на проводе, и gratuitous
/// ARP (`tpa == spa`) результатом не становятся. В `local_ip` кладётся `tpa`, как `ip_me` у `dedup_is_duplicate`
/// (:899). MAC результата это MAC источника Ethernet-кадра (`parsed->mac_src`, proto-arp.c:39), а не `sha`; в обычном
/// ответе они равны. Дубликаты отсекает `DedupCache` по `(spa, tpa)`, как в C.
///
/// Строже C: кодек [`decode`] принимает только Ethernet/IPv4 с длинами 6 и 4 (C берёт любые длины из заголовка), а
/// кадр с VLAN-тегом и всё нечитаемое это `None` (в C `continue`). Это не ошибка разбора: чужой ARP на проводе
/// обычное дело.
fn parse_arp_reply(frame: &[u8], plan: &ReadyPlan) -> Option<Reply> {
    if !plan.is_arp_scan() {
        return None;
    }
    let a = decode(frame).ok()?;
    // main.c:829–837: адрес назначения (`tpa`) не наш, кадр отбрасывается до ветки ARP.
    if !is_my_ip(plan, a.target_ip) {
        return None;
    }
    if a.op != ArpOp::Reply || !in_sorted_ranges(plan.effective().massip().ipv4(), a.sender_ip) {
        return None;
    }
    Some(Reply {
        remote_ip: a.sender_ip,
        remote_port: 0,
        local_ip: a.target_ip,
        local_port: 0,
        status: PortStatus::Arp,
        tcp_flags: 0,
        ttl: 0,
        ip_proto: 0,
        mac: Some(a.eth_src),
        ip6: None,
    })
}

/// Наш ли адрес назначения (`is_my_ip`, main.c:829): диапазон адресов источника адаптера `nic[0]` плана.
fn is_my_ip(plan: &ReadyPlan, ip_me: u32) -> bool {
    (plan.binding().source_ipv4..=plan.nics()[0].source_ipv4_last).contains(&ip_me)
}

/// Один из адресов и портов источника ЛЮБОГО адаптера плана (`matches_me`, proto-icmp.c:12-22: цикл по `out->src[8]`).
fn matches_me(plan: &ReadyPlan, ip: u32, port: u16) -> bool {
    plan.nics().iter().any(|n| {
        let (first, last) = n.binding.source_ports;
        (n.binding.source_ipv4..=n.source_ipv4_last).contains(&ip) && (first..=last).contains(&port)
    })
}

/// Ответ UDP на наш зонд (`handle_udp`, proto-udp.c:55-72: любая датаграмма на наш адрес и порт это `Open`, номер
/// протокола 17, `reason` 0, TTL из IP-заголовка; разбор прикладных ответов C делает после этого и порт не меняет).
///
/// Отличия от C (жёстче, как у TCP): порт и адрес цели обязаны входить в итоговый набор целей плана (`U:порт`), C
/// отвечает на любую датаграмму к нашему порту; суммы IPv4 и UDP проверяются при [`ChecksumPolicy::Verify`] (поле
/// суммы 0 допустимо по RFC 768); длина UDP обязана помещаться в пакет. Cookie не проверяется, как в C: в датаграмме
/// UDP ему нет места, а прикладные поля (DNS, SNMP, ...) вне границ приёмника.
fn parse_udp_reply(
    ip: &[u8],
    header_len: usize,
    (ip_them, ip_me, ttl): (u32, u32, u8),
    plan: &ReadyPlan,
    policy: ChecksumPolicy,
) -> Result<Option<Reply>, ParseError> {
    let seg = &ip[header_len..];
    if seg.len() < 8 {
        return Err(ParseError::Truncated("udp header"));
    }
    let port_them = be16(seg, 0).ok_or(ParseError::Truncated("udp header"))?;
    let port_me = be16(seg, 2).ok_or(ParseError::Truncated("udp header"))?;
    // main.c:829, :935 (`is_nic_port` для UDP, :911).
    if !is_my_ip(plan, ip_me) {
        return Ok(None);
    }
    let (first, last) = plan.binding().source_ports;
    if port_me < first || port_me > last {
        return Ok(None);
    }
    let targets = plan.effective().massip();
    if !in_sorted_ranges(targets.ipv4(), ip_them)
        || !in_sorted_ranges(targets.ports(), TEMPL_UDP + u32::from(port_them))
    {
        return Ok(None);
    }
    let udp_len = be16(seg, 4).ok_or(ParseError::Truncated("udp header"))?;
    if usize::from(udp_len) < 8 || usize::from(udp_len) > seg.len() {
        return Err(ParseError::BadUdpLength(udp_len));
    }
    if policy == ChecksumPolicy::Verify {
        if ip_header_checksum(ip, 0, header_len) != 0xffff {
            return Err(ParseError::BadIpChecksum);
        }
        if !udp_ipv4_checksum_ok(ip_them, ip_me, &seg[..usize::from(udp_len)]) {
            return Err(ParseError::BadUdpChecksum);
        }
    }
    Ok(Some(Reply {
        remote_ip: ip_them,
        remote_port: port_them,
        local_ip: ip_me,
        local_port: port_me,
        status: PortStatus::Open,
        tcp_flags: 0,
        ttl,
        ip_proto: 17,
        mac: None,
        ip6: None,
    }))
}

/// Ответ SCTP на наш INIT (`handle_sctp`, proto-sctp.c:137-189): verification tag ответа равен cookie
/// `syn_cookie(ip_them, port_them | (Proto_SCTP << 16), ip_me, port_me, entropy)` (main.c:822, это `initiate_tag`
/// нашего INIT); первый чанк типа 2 (INIT-ACK) даёт `Open`, типа 6 (ABORT) даёт `Closed`, всё прочее молча
/// отбрасывается. Номер протокола 132, `reason` 0, TTL внешнего пакета, порт цели это порт источника ответа. Мы
/// ничего не отвечаем (C тоже: ABORT в ответ не шлётся).
///
/// Отличия от C (жёстче, как у остальных приёмников): адрес и порт источника обязаны входить в итоговый набор целей
/// плана (`S:порт`), а порт назначения обязан лежать в `source_ports` (в C `handle_sctp` вызывается до `is_my_port` и
/// отчёт уходит при любом порте); суммы IPv4 и CRC-32C SCTP проверяются при [`ChecksumPolicy::Verify`] (C их не
/// проверяет, "TODO: verify checksum"); короче общего заголовка (12 байт) это ошибка разбора.
fn parse_sctp_reply(
    ip: &[u8],
    header_len: usize,
    (ip_them, ip_me, ttl): (u32, u32, u8),
    plan: &ReadyPlan,
    policy: ChecksumPolicy,
) -> Result<Option<Reply>, ParseError> {
    let seg = &ip[header_len..];
    // proto-preprocess.c:198-207: общий заголовок SCTP 12 байт.
    if seg.len() < 12 {
        return Err(ParseError::Truncated("sctp header"));
    }
    let port_them = be16(seg, 0).ok_or(ParseError::Truncated("sctp header"))?;
    let port_me = be16(seg, 2).ok_or(ParseError::Truncated("sctp header"))?;
    let tag = be32(seg, 4).ok_or(ParseError::Truncated("sctp header"))?;
    // main.c:829: is_my_ip; main.c:935: is_my_port (в C после отчёта, здесь до него).
    if !is_my_ip(plan, ip_me) {
        return Ok(None);
    }
    let (first, last) = plan.binding().source_ports;
    if port_me < first || port_me > last {
        return Ok(None);
    }
    let targets = plan.effective().massip();
    if !in_sorted_ranges(targets.ipv4(), ip_them)
        || !in_sorted_ranges(targets.ports(), TEMPL_SCTP + u32::from(port_them))
    {
        return Ok(None);
    }
    // proto-sctp.c:150-153: verification tag это cookie; main.c:822: `port_them | (Proto_SCTP << 16)` = индекс порта.
    let cookie = syn_cookie_ipv4(
        ip_them,
        TEMPL_SCTP + u32::from(port_them),
        ip_me,
        u32::from(port_me),
        plan.effective().seed(),
    ) as u32;
    if cookie != tag {
        return Ok(None);
    }
    // proto-sctp.c:155-156: `offset + 16 > length` (заголовок чанка 4 байта).
    let Some(&chunk_type) = seg.get(12).filter(|_| seg.len() >= 16) else {
        return Ok(None);
    };
    let status = match chunk_type {
        2 => PortStatus::Open,   // INIT ACK
        6 => PortStatus::Closed, // ABORT
        _ => return Ok(None),
    };
    // Суммы проверяются после дешёвых фильтров и cookie.
    if policy == ChecksumPolicy::Verify {
        if ip_header_checksum(ip, 0, header_len) != 0xffff {
            return Err(ParseError::BadIpChecksum);
        }
        // CRC-32C считается по всему пакету SCTP (по длине IP-пакета, без трейлера кадра), поле суммы как нули.
        if be32(seg, 8) != Some(sctp_crc32c(seg)) {
            return Err(ParseError::BadSctpChecksum);
        }
    }
    Ok(Some(Reply {
        remote_ip: ip_them,
        remote_port: port_them,
        local_ip: ip_me,
        local_port: port_me,
        status,
        tcp_flags: 0,
        ttl,
        ip_proto: 132,
        mac: None,
        ip6: None,
    }))
}

/// Диспетчер ICMP по `type`/`code` (`handle_icmp`, proto-icmp.c:94-226): Echo Reply `0/0` и Port Unreachable `3/3`.
fn parse_icmp(
    ip: &[u8],
    header_len: usize,
    addrs: (u32, u32, u8),
    plan: &ReadyPlan,
    policy: ChecksumPolicy,
) -> Result<Option<Reply>, ParseError> {
    let msg = &ip[header_len..];
    if msg.len() >= 8 && msg[0] == 3 && msg[1] == 3 {
        return parse_port_unreachable(ip, header_len, addrs, plan, policy);
    }
    parse_icmp_echo_reply(ip, header_len, addrs, plan, policy)
}

/// ICMP Type 3 Code 3 с цитатой нашего зонда (proto-icmp.c:157-199): внутри заголовок IPv4 и первые 8 байт L4
/// (RFC 792). Порт цели закрыт: `Closed`, номер протокола внутренний (6, 17 или 132), `reason` 0, TTL внешнего пакета.
///
/// Проверка как в C (`parse_port_unreachable` :27-47 и `matches_me`): цитата не короче 24 байт, источник цитаты
/// (адрес и порт) наш; других типов и кодов Type 3 (сеть, хост, протокол недоступны) C не использует. Cookie C здесь
/// не сверяет (в `proto-icmp.c` её нет), порт тоже. Отличия (жёстче, как у остальных приёмников): цитата обязана быть
/// IPv4 с IHL не меньше 5 и помещаться целиком (C при большом IHL читает за границей), цель цитаты и её порт
/// (со сдвигом протокола) обязаны входить в итоговый набор целей плана, суммы внешнего IPv4 и ICMP проверяются при
/// [`ChecksumPolicy::Verify`].
fn parse_port_unreachable(
    ip: &[u8],
    header_len: usize,
    (_router, ip_me, ttl): (u32, u32, u8),
    plan: &ReadyPlan,
    policy: ChecksumPolicy,
) -> Result<Option<Reply>, ParseError> {
    let msg = &ip[header_len..];
    // main.c:829: адрес назначения внешнего пакета наш.
    if !is_my_ip(plan, ip_me) {
        return Ok(None);
    }
    let q = &msg[8..];
    if q.len() < 24 || q[0] >> 4 != 4 {
        return Ok(None);
    }
    let inner_header = usize::from(q[0] & 0x0F) * 4;
    if inner_header < 20 || q.len() < inner_header + 4 {
        return Ok(None);
    }
    let (Some(ip_me2), Some(ip_them2), Some(port_me2), Some(port_them2)) = (
        be32(q, 12),
        be32(q, 16),
        be16(q, inner_header),
        be16(q, inner_header + 2),
    ) else {
        return Ok(None);
    };
    if !matches_me(plan, ip_me2, port_me2) {
        return Ok(None);
    }
    // proto-icmp.c:157-196: только TCP, UDP и SCTP.
    let ip_proto = q[9];
    let offset = match ip_proto {
        6 => TEMPL_TCP,
        17 => TEMPL_UDP,
        132 => TEMPL_SCTP,
        _ => return Ok(None),
    };
    let targets = plan.effective().massip();
    if !in_sorted_ranges(targets.ipv4(), ip_them2)
        || !in_sorted_ranges(targets.ports(), offset + u32::from(port_them2))
    {
        return Ok(None);
    }
    if policy == ChecksumPolicy::Verify {
        if ip_header_checksum(ip, 0, header_len) != 0xffff {
            return Err(ParseError::BadIpChecksum);
        }
        if fold(word_sum(msg)) != 0xffff {
            return Err(ParseError::BadIcmpChecksum);
        }
    }
    Ok(Some(Reply {
        remote_ip: ip_them2,
        remote_port: port_them2,
        local_ip: ip_me2,
        local_port: port_me2,
        status: PortStatus::Closed,
        tcp_flags: 0,
        ttl,
        ip_proto,
        mac: None,
        ip6: None,
    }))
}

/// ICMP Echo Reply на наш Echo Request (proto-icmp.c:200-226, `handle_icmp`).
///
/// Принимается только `type 0, code 0`, у которого `[id|seq]` (байты 4..8 ICMP, `seqno_me`) равны
/// `icmp_echo_cookie(ip_them, ip_me, seed)`: `syn_cookie(ip_them, Templ_ICMP_echo, ip_me, 0, entropy)` с
/// `port_me = 0` (:203). Отличие от C (жёстче): C берёт любой `code` при `type 0` и не проверяет суммы; здесь
/// `code != 0` отбрасывается, суммы проверяются при [`ChecksumPolicy::Verify`], а адрес и порт `I:0` должны
/// входить в итоговый набор целей задания (как у TCP). Порта у ICMP нет: `remote_port = local_port = 0`.
fn parse_icmp_echo_reply(
    ip: &[u8],
    header_len: usize,
    (ip_them, ip_me, ttl): (u32, u32, u8),
    plan: &ReadyPlan,
    policy: ChecksumPolicy,
) -> Result<Option<Reply>, ParseError> {
    let msg = &ip[header_len..];
    if msg.len() < 8 {
        return Err(ParseError::Truncated("icmp header"));
    }
    // main.c:829: is_my_ip, как у TCP.
    let ip_last = plan.nics()[0].source_ipv4_last;
    if !(plan.binding().source_ipv4..=ip_last).contains(&ip_me) {
        return Ok(None);
    }
    if msg[0] != 0 || msg[1] != 0 {
        return Ok(None);
    }
    let targets = plan.effective().massip();
    if !in_sorted_ranges(targets.ipv4(), ip_them)
        || !in_sorted_ranges(targets.ports(), TEMPL_ICMP_ECHO)
    {
        return Ok(None);
    }
    let seqno_me = be32(msg, 4).ok_or(ParseError::Truncated("icmp header"))?;
    if icmp_echo_cookie(ip_them, ip_me, plan.effective().seed()) != seqno_me {
        return Ok(None);
    }
    if policy == ChecksumPolicy::Verify {
        if ip_header_checksum(ip, 0, header_len) != 0xffff {
            return Err(ParseError::BadIpChecksum);
        }
        // RFC 792: сумма всего сообщения вместе с полем суммы сворачивается в 0xFFFF (без псевдозаголовка).
        if fold(word_sum(msg)) != 0xffff {
            return Err(ParseError::BadIcmpChecksum);
        }
    }
    Ok(Some(Reply {
        remote_ip: ip_them,
        remote_port: 0,
        local_ip: ip_me,
        local_port: 0,
        status: PortStatus::Open,
        tcp_flags: 0,
        ttl,
        ip_proto: 1,
        mac: None,
        ip6: None,
    }))
}

#[cfg(test)]
mod tests_ipv6 {
    //! IPv6 stage, Task 3: приём SYN-ACK/RST поверх IPv6. Кадры собираются здесь по RFC 8200/9293, независимо от
    //! парсера; cookie взят из настоящего C (`syn_cookie_ipv6`, syn-cookie.c:155-171, значение напечатано
    //! собранным `syn-cookie.c`), сумма TCP считается своим верификатором RFC 8200 §8.1.
    use super::*;
    use crate::config::{Operation, ScanConfig, validate};
    use crate::massip::MassIp;
    use crate::probe::{AdapterBinding, NicBinding};
    use crate::targets::parse_ports;

    const THEM: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0001;
    const ME: u128 = 0xfd00_0000_0000_0000_0000_0000_0000_0002;
    const SEED: u64 = 0x0123_4567_89ab_cdef;
    /// `syn_cookie_ipv6(THEM, 80, ME, 40000, SEED)` из C: 0x8edac6d1824e4617; `main.c:825` берёт младшие 32 бита.
    const C_COOKIE: u32 = 0x824e_4617;
    const MAC_ME: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAC_NH: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02];

    fn plan(link: LinkType, source_ipv6: Option<u128>) -> ReadyPlan {
        let mut m = MassIp::new();
        // 2001:db8::/120 (256 адресов), порт 80.
        m.ipv6_mut().add(THEM & !0xff, THEM | 0xff);
        parse_ports(m.ports_mut(), "80").unwrap();
        let cfg = ScanConfig {
            targets: m,
            seed: SEED,
            max_rate: 100.0,
            ..ScanConfig::default()
        };
        let eff = validate(&cfg, Operation::Scan).unwrap();
        ReadyPlan::new_cli(
            eff,
            vec![NicBinding {
                binding: AdapterBinding {
                    interface_id: "t0".into(),
                    link_type: link,
                    source_ipv4: 0x0aff_0001,
                    source_mac: MAC_ME,
                    next_hop_mac: MAC_NH,
                    source_ports: (40000, 40015),
                },
                source_ipv4_last: 0x0aff_0001,
                legacy_c_17_port_mask: false,
                source_ipv6,
                next_hop_mac_ipv6: None,
            }],
        )
        .unwrap()
    }

    /// Описание входящего кадра; поля можно портить до сборки.
    #[derive(Clone)]
    struct Spec {
        src: u128,
        dst: u128,
        port_them: u16,
        port_me: u16,
        ack: u32,
        flags: u8,
        hop: u8,
        /// Цепочка расширений: `(next-header вслед за ним уже подставит сборщик, тело)`; тело = байты после
        /// первых двух (next, len) и длина кратна 8 минус 2.
        ext: Vec<Vec<u8>>,
        /// Next Header основного заголовка, когда расширений нет или они есть (первое звено цепочки).
        proto: u8,
        trailer: Vec<u8>,
    }

    impl Spec {
        fn synack() -> Spec {
            Spec {
                src: THEM,
                dst: ME,
                port_them: 80,
                port_me: 40000,
                ack: C_COOKIE.wrapping_add(1),
                flags: 0x12,
                hop: 59,
                ext: vec![],
                proto: 6,
                trailer: vec![],
            }
        }
        fn hbh(mut self) -> Spec {
            // Hop-by-Hop 8 байт: next (подставится), len 0, PadN(4): 01 04 00 00 00 00.
            self.ext.push(vec![0, 0x01, 0x04, 0, 0, 0, 0]);
            self
        }

        fn segment(&self) -> Vec<u8> {
            let mut tcp = vec![0u8; 20];
            tcp[0..2].copy_from_slice(&self.port_them.to_be_bytes());
            tcp[2..4].copy_from_slice(&self.port_me.to_be_bytes());
            tcp[4..8].copy_from_slice(&0x0bad_f00du32.to_be_bytes());
            tcp[8..12].copy_from_slice(&self.ack.to_be_bytes());
            tcp[12] = 0x50;
            tcp[13] = self.flags;
            tcp[14..16].copy_from_slice(&0x0400u16.to_be_bytes());
            let sum = rfc8200_checksum(self.src, self.dst, &tcp);
            tcp[16..18].copy_from_slice(&sum.to_be_bytes());
            tcp
        }

        /// IPv6 + расширения + TCP, без канального заголовка.
        fn ip_packet(&self) -> Vec<u8> {
            let tcp = self.segment();
            let mut chain: Vec<u8> = Vec::new();
            for (i, e) in self.ext.iter().enumerate() {
                // next header звена: следующее расширение (0 = Hop-by-Hop) или TCP.
                let next = if i + 1 < self.ext.len() { 0 } else { 6 };
                let mut z = vec![next, e[0]];
                z.extend_from_slice(&e[1..]);
                chain.extend_from_slice(&z);
            }
            let first = if self.ext.is_empty() { self.proto } else { 0 };
            let mut p = vec![0x60, 0, 0, 0];
            p.extend_from_slice(&((chain.len() + tcp.len()) as u16).to_be_bytes());
            p.push(first);
            p.push(self.hop);
            p.extend_from_slice(&self.src.to_be_bytes());
            p.extend_from_slice(&self.dst.to_be_bytes());
            p.extend_from_slice(&chain);
            p.extend_from_slice(&tcp);
            p.extend_from_slice(&self.trailer);
            p
        }

        fn frame(&self, link: LinkType) -> Vec<u8> {
            let ip = self.ip_packet();
            match link {
                LinkType::Ethernet => {
                    let mut f = vec![0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
                    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);
                    f.extend_from_slice(&[0x86, 0xdd]);
                    f.extend_from_slice(&ip);
                    f
                }
                // proto-preprocess.c:515-529: семейство 0x1e (macOS AF_INET6 = 30), любой порядок.
                LinkType::Null => [&[0x1e, 0, 0, 0][..], &ip].concat(),
                LinkType::Raw => ip,
            }
        }
    }

    /// RFC 8200 §8.1, независимо от `checksum_ipv6`: псевдозаголовок + сегмент с нулевым полем суммы.
    fn rfc8200_checksum(src: u128, dst: u128, seg: &[u8]) -> u16 {
        let mut w: Vec<u8> = Vec::new();
        w.extend_from_slice(&src.to_be_bytes());
        w.extend_from_slice(&dst.to_be_bytes());
        w.extend_from_slice(&(seg.len() as u32).to_be_bytes());
        w.extend_from_slice(&[0, 0, 0, 6]);
        w.extend_from_slice(seg);
        let mut s: u64 = w
            .chunks(2)
            .map(|c| u64::from(c[0]) << 8 | u64::from(*c.get(1).unwrap_or(&0)))
            .sum();
        while s > 0xFFFF {
            s = (s & 0xFFFF) + (s >> 16);
        }
        !(s as u16)
    }

    const LINKS: [LinkType; 3] = [LinkType::Ethernet, LinkType::Null, LinkType::Raw];

    #[test]
    fn receive_v6_handles_hop_by_hop_extension_and_records_hop_limit() {
        // proto-preprocess.c:300-312 (`parse_ipv6_hop_by_hop`: next = px[offset], пропуск расширения) и
        // main.c:1048-1065 (SYN-ACK = Open, `cookie == ackno - 1`, ttl в отчёт).
        for link in LINKS {
            let plan = plan(link, Some(ME));
            let s = Spec::synack().hbh();
            let r = parse_reply(&s.frame(link), link, &plan)
                .unwrap()
                .unwrap_or_else(|| panic!("{link:?}: reply expected"));
            assert_eq!(r.status, PortStatus::Open, "{link:?}");
            assert_eq!(r.ttl, 59, "hop limit = px[offset_ip + 7]");
            assert_eq!((r.remote_port, r.local_port), (80, 40000));
            assert_eq!(r.tcp_flags, 0x12);
            assert_eq!(r.ip_proto, 6);
            assert_eq!(
                r.ip6,
                Some(ReplyIpv6 {
                    remote: THEM,
                    local: ME
                })
            );
            // IPv4-поля IPv6-ответа не несут адресов (Студия читает `remote_ip` как IPv4).
            assert_eq!((r.remote_ip, r.local_ip), (0, 0));
            assert_eq!(r.mac, None);
            // ackno - 1 обязан равняться cookie из C: сдвиг на единицу в любую сторону это не наш ответ.
            for bad in [C_COOKIE, C_COOKIE.wrapping_add(2)] {
                let s = Spec {
                    ack: bad,
                    ..Spec::synack().hbh()
                };
                assert_eq!(
                    parse_reply(&s.frame(link), link, &plan),
                    Ok(None),
                    "{bad:#x}"
                );
            }
        }
    }

    /// Hop-by-Hop длиннее 8 байт (`Hdr Ext Len = 1` это 16 байт по RFC 8200 §4.3; C считал бы `1 + 8 = 9` байт,
    /// proto-preprocess.c:306, отличие порта) и две цепочки подряд (после расширения `parse_ipv6_next` снова видит 0,
    /// :285-287).
    #[test]
    fn receive_v6_walks_longer_and_chained_hop_by_hop() {
        let plan = plan(LinkType::Ethernet, Some(ME));
        let mut long = Spec::synack();
        // len = 1 -> 16 байт: next, len, 14 байт паддинга.
        long.ext.push([vec![1u8], vec![0u8; 14]].concat());
        let r = parse_reply(&long.frame(LinkType::Ethernet), LinkType::Ethernet, &plan);
        assert_eq!(r.unwrap().map(|r| r.status), Some(PortStatus::Open));
        let chained = Spec::synack().hbh().hbh();
        let r = parse_reply(
            &chained.frame(LinkType::Ethernet),
            LinkType::Ethernet,
            &plan,
        );
        assert_eq!(r.unwrap().map(|r| r.ttl), Some(59));
    }

    #[test]
    fn receive_v6_plain_synack_and_rst() {
        let plan = plan(LinkType::Ethernet, Some(ME));
        let open = Spec::synack();
        let r = parse_reply(&open.frame(LinkType::Ethernet), LinkType::Ethernet, &plan)
            .unwrap()
            .unwrap();
        assert_eq!((r.status, r.tcp_flags, r.ttl), (PortStatus::Open, 0x12, 59));
        // RST|ACK: Closed (main.c:1048-1057, RST перекрывает), cookie тот же (`ackno - 1`).
        let rst = Spec {
            flags: 0x14,
            ..Spec::synack()
        };
        let r = parse_reply(&rst.frame(LinkType::Ethernet), LinkType::Ethernet, &plan)
            .unwrap()
            .unwrap();
        assert_eq!((r.status, r.tcp_flags), (PortStatus::Closed, 0x14));
        // Один SYN без ACK не ответ.
        let syn = Spec {
            flags: 0x02,
            ..Spec::synack()
        };
        assert_eq!(
            parse_reply(&syn.frame(LinkType::Ethernet), LinkType::Ethernet, &plan),
            Ok(None)
        );
        // Ethernet-трейлер после payload_length отбрасывается (proto-preprocess.c:229-230).
        let padded = Spec {
            trailer: vec![0; 6],
            ..Spec::synack()
        };
        assert!(
            parse_reply(&padded.frame(LinkType::Ethernet), LinkType::Ethernet, &plan)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn receive_v6_rejects_what_is_not_ours() {
        let plan = plan(LinkType::Ethernet, Some(ME));
        let rx = |s: &Spec| parse_reply(&s.frame(LinkType::Ethernet), LinkType::Ethernet, &plan);
        // is_my_ip (stack-src.c:13-14): адрес назначения обязан совпасть с source_ipv6 целиком.
        for dst in [ME ^ 1, ME ^ (1 << 64), ME ^ (1 << 127)] {
            assert_eq!(
                rx(&Spec {
                    dst,
                    ..Spec::synack()
                }),
                Ok(None),
                "{dst:#x}"
            );
        }
        // is_my_port.
        assert_eq!(
            rx(&Spec {
                port_me: 40016,
                ..Spec::synack()
            }),
            Ok(None)
        );
        // Источник вне итогового набора целей (строже C, как у IPv4) и порт цели вне набора.
        let outside = 0x2001_0db8_0000_0000_0000_0000_0001_0001u128;
        assert_eq!(
            rx(&Spec {
                src: outside,
                ..Spec::synack()
            }),
            Ok(None)
        );
        assert_eq!(
            rx(&Spec {
                port_them: 81,
                ..Spec::synack()
            }),
            Ok(None)
        );
        // План без source_ipv6: ни один IPv6-ответ не "мой".
        let no_src = self::plan(LinkType::Ethernet, None);
        assert_eq!(
            parse_reply(
                &Spec::synack().frame(LinkType::Ethernet),
                LinkType::Ethernet,
                &no_src
            ),
            Ok(None)
        );
        // Битый IPv6-кадр на плане без `source_ipv6` это "не наш", а не ошибка разбора.
        let mut broken = Spec::synack().frame(LinkType::Ethernet);
        broken[14 + 4] = 0xff;
        assert_eq!(parse_reply(&broken, LinkType::Ethernet, &no_src), Ok(None));
        // Не-TCP поверх IPv6 (R3): UDP (17), ICMPv6 (58), SCTP (132), Fragment (44, :292-293) не разбираются.
        for proto in [17u8, 58, 132, 44, 43, 50] {
            let s = Spec {
                proto,
                ..Spec::synack()
            };
            assert_eq!(rx(&s), Ok(None), "next header {proto}");
        }
    }

    #[test]
    fn receive_v6_checksum_policy() {
        let plan = plan(LinkType::Ethernet, Some(ME));
        let mut f = Spec::synack().frame(LinkType::Ethernet);
        let at = 14 + 40 + 16;
        f[at] ^= 0x01;
        assert_eq!(
            parse_reply(&f, LinkType::Ethernet, &plan),
            Err(ParseError::BadTcpChecksum)
        );
        // TrustHardware не проверяет сумму, cookie проверяется всегда.
        assert!(
            parse_reply_with(&f, LinkType::Ethernet, &plan, ChecksumPolicy::TrustHardware)
                .unwrap()
                .is_some()
        );
        // Сумма с расширением считается по длине TCP-сегмента, не по всему payload_length: верный кадр с HBH проходит.
        let ok = Spec::synack().hbh().frame(LinkType::Ethernet);
        assert!(
            parse_reply(&ok, LinkType::Ethernet, &plan)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn receive_v6_hostile_lengths_are_errors_not_panics() {
        let plan = plan(LinkType::Ethernet, Some(ME));
        let good = Spec::synack().hbh().frame(LinkType::Ethernet);
        for n in 0..good.len() {
            // Каждый строгий префикс: ошибка или "не наш", но не паника.
            let _ = parse_reply(&good[..n], LinkType::Ethernet, &plan);
        }
        // payload_length больше фактически присутствующих байт (:228 VERIFY_REMAINING).
        let mut f = good.clone();
        f[14 + 4] = 0xff;
        assert!(matches!(
            parse_reply(&f, LinkType::Ethernet, &plan),
            Err(ParseError::Ipv6PayloadBeyondFrame { .. })
        ));
        // Hop-by-Hop объявляет длину за пределами кадра (:308 VERIFY_REMAINING).
        let mut f = good.clone();
        f[14 + 40 + 1] = 0xff;
        assert!(matches!(
            parse_reply(&f, LinkType::Ethernet, &plan),
            Err(ParseError::Truncated(_))
        ));
        // Неверная версия.
        let mut f = good.clone();
        f[14] = 0x40;
        assert!(parse_reply(&f, LinkType::Ethernet, &plan).is_err());
    }

    /// Ответчик NS (main.c:829-840): только для плана с `source_ipv6`, только Ethernet, только NS для нашего адреса.
    #[test]
    fn ndp_reply_for_answers_only_our_address_on_ethernet() {
        use crate::ndp::{
            encode_neighbor_advertisement, encode_neighbor_solicitation, solicited_node_address,
        };
        let router_mac = [0x0a, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        let router_ip = 0xfe80_0000_0000_0000_0000_0000_0000_abcdu128;
        // NS роутера на ME: кадр собирает кодировщик (его байты проверены против C в ndp_tests).
        let mut ns = encode_neighbor_solicitation(router_mac, router_ip, ME);
        // Адресат это solicited-node ME (кодировщик так и ставит).
        assert_eq!(
            u128::from_be_bytes(ns[38..54].try_into().unwrap()),
            solicited_node_address(ME)
        );
        let with = plan(LinkType::Ethernet, Some(ME));
        let na = ndp_reply_for(&ns, LinkType::Ethernet, &with).unwrap();
        assert_eq!(na.len(), 86);
        assert_eq!(&na[0..6], &router_mac);
        assert_eq!(&na[6..12], &MAC_ME);
        assert_eq!(
            na,
            encode_neighbor_advertisement(MAC_ME, ME, router_mac, router_ip)
        );
        // План без source_ipv6 (IPv4, Студия) и не Ethernet не отвечают.
        assert!(ndp_reply_for(&ns, LinkType::Ethernet, &plan(LinkType::Ethernet, None)).is_none());
        assert!(ndp_reply_for(&ns, LinkType::Raw, &with).is_none());
        // NS для чужого адреса.
        ns = encode_neighbor_solicitation(router_mac, router_ip, ME + 1);
        assert!(ndp_reply_for(&ns, LinkType::Ethernet, &with).is_none());
    }
}

#[cfg(test)]
mod tests_udp_payload {
    //! `udp_payload` (баннеры UDP, подэтап 4a): нагрузка датаграммы того же кадра, который принимает `parse_reply`.
    //! Кадры собираются здесь по RFC 791/768; суммы не нужны (`udp_payload` их не проверяет, это делает
    //! `parse_reply`). Адреса RFC 5737 и `2001:db8::/32`.
    use super::*;

    /// Пакет IPv4 + UDP: IHL `ihl` (5..=15, опции NOP), поле фрагментации `frag`, длина UDP `udp_len` (по умолчанию
    /// 8 + нагрузка), полная длина IPv4 по фактическим байтам.
    fn ipv4_udp(ihl: u8, frag: u16, udp_len: Option<u16>, payload: &[u8]) -> Vec<u8> {
        let header = usize::from(ihl) * 4;
        let total = u16::try_from(header + 8 + payload.len()).unwrap();
        let mut ip = vec![0x40 | ihl, 0];
        ip.extend(total.to_be_bytes());
        ip.extend([0x12, 0x34]);
        ip.extend(frag.to_be_bytes());
        ip.extend([64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1]);
        ip.resize(header, 0x01);
        ip.extend(53u16.to_be_bytes());
        ip.extend(40000u16.to_be_bytes());
        let len = udp_len.unwrap_or(u16::try_from(8 + payload.len()).unwrap());
        ip.extend(len.to_be_bytes());
        ip.extend([0, 0]);
        ip.extend(payload);
        ip
    }

    /// Пакет IPv6 + UDP с цепочкой Hop-by-Hop из `hbh` заголовков по 8 байт.
    fn ipv6_udp(hbh: usize, payload: &[u8]) -> Vec<u8> {
        let plen = u16::try_from(hbh * 8 + 8 + payload.len()).unwrap();
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend(plen.to_be_bytes());
        ip.extend([if hbh > 0 { 0 } else { 17 }, 57]);
        ip.extend(0x2001_0db8_0000_0000_0000_0000_0000_0005u128.to_be_bytes());
        ip.extend(0x2001_0db8_0000_0000_0000_0000_0000_0001u128.to_be_bytes());
        for i in 0..hbh {
            ip.extend([if i + 1 == hbh { 17 } else { 0 }, 0, 1, 4, 0, 0, 0, 0]);
        }
        ip.extend(53u16.to_be_bytes());
        ip.extend(40000u16.to_be_bytes());
        ip.extend((8 + u16::try_from(payload.len()).unwrap()).to_be_bytes());
        ip.extend([0, 0]);
        ip.extend(payload);
        ip
    }

    fn eth(ethertype: u16, ip: &[u8]) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
        f.extend(ethertype.to_be_bytes());
        f.extend(ip);
        f
    }

    fn eth4(ip: &[u8]) -> Vec<u8> {
        eth(0x0800, ip)
    }

    #[test]
    fn ethernet_padding_is_not_payload() {
        let mut f = eth4(&ipv4_udp(5, 0, None, b"abc"));
        assert_eq!(f.len(), 45);
        f.resize(60, 0);
        assert_eq!(udp_payload(&f, LinkType::Ethernet), Some(&b"abc"[..]));
    }

    #[test]
    fn ipv4_options_raw_and_null_links_give_the_payload() {
        for ihl in 5..=15 {
            let ip = ipv4_udp(ihl, 0, None, b"hello");
            assert_eq!(
                udp_payload(&eth4(&ip), LinkType::Ethernet),
                Some(&b"hello"[..]),
                "IHL {ihl}"
            );
            assert_eq!(
                udp_payload(&ip, LinkType::Raw),
                Some(&b"hello"[..]),
                "IHL {ihl}"
            );
            for family in [[2, 0, 0, 0], [0, 0, 0, 2]] {
                let f = [&family[..], &ip].concat();
                assert_eq!(
                    udp_payload(&f, LinkType::Null),
                    Some(&b"hello"[..]),
                    "IHL {ihl}"
                );
            }
        }
        // DF не фрагмент.
        let df = ipv4_udp(5, 0x4000, None, b"df");
        assert_eq!(
            udp_payload(&eth4(&df), LinkType::Ethernet),
            Some(&b"df"[..])
        );
    }

    #[test]
    fn ipv6_with_and_without_hop_by_hop_gives_the_payload() {
        for hbh in 0..3 {
            let ip = ipv6_udp(hbh, b"v6");
            assert_eq!(
                udp_payload(&eth(0x86dd, &ip), LinkType::Ethernet),
                Some(&b"v6"[..])
            );
            assert_eq!(udp_payload(&ip, LinkType::Raw), Some(&b"v6"[..]));
            for family in [[24, 0, 0, 0], [0, 0, 0, 28], [30, 0, 0, 0]] {
                let f = [&family[..], &ip].concat();
                assert_eq!(udp_payload(&f, LinkType::Null), Some(&b"v6"[..]));
            }
        }
    }

    #[test]
    fn fragments_and_everything_not_udp_give_none() {
        let ok = ipv4_udp(5, 0, None, b"x");
        // MF и смещение фрагмента (`proto-preprocess.c:104-108`).
        for frag in [0x2000, 0x0001, 0x1fff, 0x6000] {
            let f = eth4(&ipv4_udp(5, frag, None, b"x"));
            assert_eq!(udp_payload(&f, LinkType::Ethernet), None, "frag {frag:#x}");
        }
        // TCP, ICMP, SCTP.
        for proto in [6u8, 1, 132] {
            let mut ip = ok.clone();
            ip[9] = proto;
            assert_eq!(
                udp_payload(&eth4(&ip), LinkType::Ethernet),
                None,
                "proto {proto}"
            );
        }
        // 802.1Q, QinQ: VLAN не разбирается (`locate_ipv4`), ARP и неизвестный EtherType.
        for ethertype in [0x8100, 0x88a8, 0x9100, 0x0806, 0x88cc] {
            assert_eq!(udp_payload(&eth(ethertype, &ok), LinkType::Ethernet), None);
        }
        // Полная длина за кадром, меньше заголовка, версия не 4.
        let mut beyond = ok.clone();
        beyond[2..4].copy_from_slice(&(u16::try_from(ok.len()).unwrap() + 1).to_be_bytes());
        assert_eq!(udp_payload(&eth4(&beyond), LinkType::Ethernet), None);
        let mut below = ok.clone();
        below[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert_eq!(udp_payload(&eth4(&below), LinkType::Ethernet), None);
        let mut v5 = ok.clone();
        v5[0] = 0x55;
        assert_eq!(udp_payload(&eth4(&v5), LinkType::Ethernet), None);
        // Заголовок UDP в 7 байт: полная длина IPv4 обрезает его (`VERIFY_REMAINING(8, FOUND_UDP)`).
        let mut short = ipv4_udp(5, 0, None, b"");
        short.truncate(27);
        short[2..4].copy_from_slice(&27u16.to_be_bytes());
        assert_eq!(udp_payload(&eth4(&short), LinkType::Ethernet), None);
        // Next Header IPv6 не UDP.
        let mut tcp6 = ipv6_udp(0, b"x");
        tcp6[6] = 6;
        assert_eq!(udp_payload(&eth(0x86dd, &tcp6), LinkType::Ethernet), None);
    }

    #[test]
    fn empty_datagram_and_frame_length_limit() {
        let f = eth4(&ipv4_udp(5, 0, None, b""));
        assert_eq!(udp_payload(&f, LinkType::Ethernet), Some(&b""[..]));
        // 1514 байт кадра (`MAX_FRAME_LEN`, `src/main.c:799`): 1472 байта нагрузки; на байт длиннее ничего.
        let max = eth4(&ipv4_udp(5, 0, None, &[0x5a; 1472]));
        assert_eq!(max.len(), MAX_FRAME_LEN);
        assert_eq!(
            udp_payload(&max, LinkType::Ethernet).map(<[u8]>::len),
            Some(1472)
        );
        let over = eth4(&ipv4_udp(5, 0, None, &[0x5a; 1473]));
        assert_eq!(over.len(), MAX_FRAME_LEN + 1);
        assert_eq!(udp_payload(&over, LinkType::Ethernet), None);
    }

    /// Длина UDP короче IP-пакета: нагрузка идёт до конца IP-пакета, как `app_length` C (`length = offset +
    /// total_length`, `src/proto-preprocess.c:109`, `app_length = length - app_offset`, `:173`); поле длины UDP C не
    /// читает. `parse_reply` проверяет сумму UDP только по `udp_len` байтам, поэтому хвост за ним в сырой баннер
    /// попадает непроверенным (README, блок «Баннеры»).
    #[test]
    fn udp_length_shorter_than_the_ip_payload_keeps_the_tail_like_c() {
        let ip = ipv4_udp(5, 0, Some(13), b"helloTRAIL");
        assert_eq!(
            udp_payload(&eth4(&ip), LinkType::Ethernet),
            Some(&b"helloTRAIL"[..])
        );
    }

    /// Каждый префикс кадра (и каждый из трёх каналов) разбирается без паники; полный кадр даёт нагрузку.
    #[test]
    fn every_truncated_prefix_returns_without_panic() {
        let frames = [
            (eth4(&ipv4_udp(7, 0, None, b"payload")), LinkType::Ethernet),
            (eth(0x86dd, &ipv6_udp(2, b"payload")), LinkType::Ethernet),
            (ipv4_udp(5, 0, None, b"payload"), LinkType::Raw),
            (
                [&[24, 0, 0, 0][..], &ipv6_udp(1, b"payload")].concat(),
                LinkType::Null,
            ),
            (
                [&[0, 0, 0, 2][..], &ipv4_udp(6, 0, None, b"payload")].concat(),
                LinkType::Null,
            ),
        ];
        for (f, link) in &frames {
            for n in 0..f.len() {
                let got = udp_payload(&f[..n], *link);
                assert!(got.is_none(), "{link:?} prefix {n}: {got:?}");
            }
            assert_eq!(udp_payload(f, *link), Some(&b"payload"[..]));
        }
    }
}
