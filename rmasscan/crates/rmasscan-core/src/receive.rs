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
//! 1. IPv4, не фрагмент, TCP; адрес назначения равен `source_ipv4` плана;
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

use crate::checksum::{checksum_ipv4, ip_header_checksum};
use crate::cookie::syn_cookie_ipv4;
use crate::packet::LinkType;
use crate::probe::ReadyPlan;
use crate::ranges::RangeList;

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
}

/// Открыт или закрыт порт (main.c:1052-1057).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortStatus {
    Open,
    Closed,
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
    let Some(ip) = locate_ipv4(frame, link)? else {
        return Ok(None);
    };
    parse_ipv4_tcp(ip, plan, policy)
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

fn parse_ipv4_tcp(
    ip: &[u8],
    plan: &ReadyPlan,
    policy: ChecksumPolicy,
) -> Result<Option<Reply>, ParseError> {
    // proto-preprocess.c:104-146.
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
    let ttl = ip[8];
    let proto = ip[9];
    let ip_them = be32(ip, 12).ok_or(ParseError::Truncated("ipv4 header"))?;
    let ip_me = be32(ip, 16).ok_or(ParseError::Truncated("ipv4 header"))?;
    if proto != 6 {
        // UDP, ICMP, SCTP и прочее: не наш SYN-ответ.
        return Ok(None);
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

    // main.c:829: is_my_ip.
    let binding = plan.binding();
    if ip_me != binding.source_ipv4 {
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
    }))
}
