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
    checksum_ipv4, fold, ip_header_checksum, sctp_crc32c, udp_ipv4_checksum_ok, word_sum,
};
use crate::cookie::{icmp_echo_cookie, syn_cookie_ipv4};
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
    }))
}
