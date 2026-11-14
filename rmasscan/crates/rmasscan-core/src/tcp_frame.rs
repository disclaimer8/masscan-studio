//! Сегмент TCP и кадры пользовательского стека (AGPL-3.0, подэтап 4b). Порт разбора входящего кадра приёмного потока
//! (`src/main.c:799-951`, `preprocess_frame` из `src/proto-preprocess.c`), `tcp_create_packet`
//! (`src/templ-pkt.c:419-613`) и RST без состояния (`src/main.c:1094-1100`, `tcp_send_RST`
//! `src/stack-tcp-core.c:1176-1219`), masscan © Robert David Graham (github.com/robertdavidgraham/masscan, HEAD
//! 8e6b3b0). Справка: `docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-tcp.md` A6, A7, E1.9, E1.10.
//!
//! Вход недоверенный: разбор тотален (границы через `get`, никаких паник на данных кадра). Приём отличается от C тем,
//! что сегмент с неверной суммой отбрасывается ([`tcp_segment`], справка E1.15). Кадры совпадают с кадрами C побайтно
//! (эталоны `tests/golden/tcp-frames`), кроме двух названных отличий:
//! - сумма заголовка IPv4 всегда полная (E1.10, класс г): C обновляет её приращением и сворачивает дважды
//!   (`src/templ-pkt.c:466-473`), и примерно в 1e-5 кадров стека она неверна;
//! - TSval `--tcp-tsecho` целиком, как в SYN rmasscan (C пишет `field[2]` дважды, `src/templ-tcp-hdr.c:1111-1112`):
//!   кадры стека копируют шаблон SYN и несут его опции.

use crate::checksum::{checksum_ipv4, checksum_ipv6, ip_header_checksum};
use crate::cookie::{syn_cookie_ipv4, syn_cookie_ipv6};
use crate::packet::{LinkType, Tcp6SynTemplate, TcpSynTemplate};
use crate::probe::ReadyPlan;
use crate::receive::{
    MAX_FRAME_LEN, Reply, be16, ipv4_packet, ipv6_packet, is_my_ip, is_my_ip6, is_my_port,
    locate_ipv4, locate_ipv6, tcp_header,
};
use crate::stack::{ConnAddrs, ConnKey, SegmentIn, SegmentOut};

/// Окно каждого кадра стека (`src/templ-pkt.c:497-498`, `:598-599`): не окно шаблона SYN (1024).
pub const STACK_WINDOW: u16 = 1200;

/// `sizeof(response->px)` (`src/stack-queue.h:13`): кадр длиннее C не строит (`too much payload`,
/// `src/templ-pkt.c:440-443`, `:521-524`).
const C_FRAME_BUFFER: usize = 2040;

/// Минимум Ethernet, до которого C добивает кадр IPv4 нулями на любом канале (`src/templ-pkt.c:510-513`).
const MIN_FRAME_LEN: usize = 60;

const FLAG_RST: u8 = 0x04;
const FLAG_SYNACK_MASK: u8 = 0x12;

/// Входящий сегмент TCP, адресованный нам: тот же разбор канала, IP и заголовка TCP, что у
/// [`crate::receive::parse_reply`] (`locate_ipv4`/`locate_ipv6`, `ipv4_packet`/`ipv6_packet`, `tcp_header`), до
/// `is_my_ip` (`src/main.c:829`), `is_my_port` (`:935`) и проверки сумм IPv4 и TCP включительно. Флаги, набор целей
/// и cookie не проверяются: это дело движка и стека (`src/main.c:962-1043`).
///
/// `None`: кадр длиннее 1514 байт (`src/main.c:799`), не TCP, искажён, адресован не нам или с неверной суммой.
/// IPv6 свой, только если у плана есть `source_ipv6` (как у `parse_reply`). `ttl` это TTL IPv4 или hop limit IPv6
/// (E1.9: C для IPv6 его не заполняет, `src/proto-preprocess.c:127`). Нагрузка кончается с IP-пакетом (полная длина
/// IPv4, `payload_length` IPv6), без набивки Ethernet и хвоста захвата.
///
/// Отличие от C (справка E1.15): C на приёме сумм не проверяет вовсе (`src/proto-preprocess.c:10`, `:96` `TODO: verify
/// checksum`; `src/main.c:808-1043` идёт от `preprocess_frame` прямо к `is_my_ip`/`is_my_port` и стеку), и сегмент с
/// неверной суммой заголовка IPv4 или TCP доходит до его стека (ACK, нагрузка парсеру баннера, FIN и RST); rmasscan
/// отбрасывает такой сегмент до стека, как `parse_reply` с политикой по умолчанию `Verify` отбрасывает SYN-ACK с
/// неверной суммой. Параметра [`crate::receive::ChecksumPolicy`] у функции нет: путь стека проверяет суммы всегда.
pub fn tcp_segment<'a>(frame: &'a [u8], link: LinkType, plan: &ReadyPlan) -> Option<SegmentIn<'a>> {
    if frame.len() > MAX_FRAME_LEN {
        return None;
    }
    // ARP разбирается до IPv4 и в стек не идёт (main.c:874-906).
    if link == LinkType::Ethernet && be16(frame, 12) == Some(0x0806) {
        return None;
    }
    match locate_ipv4(frame, link).ok()? {
        Some(ip) => {
            let p = ipv4_packet(ip).ok()?;
            if p.proto != 6 {
                return None;
            }
            let seg = p.ip.get(p.header_len..)?;
            let h = tcp_header(seg).ok()?;
            if !is_my_ip(plan, p.ip_me) || !is_my_port(plan, h.port_me) {
                return None;
            }
            if ip_header_checksum(p.ip, 0, p.header_len) != 0xffff
                || checksum_ipv4(p.ip_them, p.ip_me, 6, seg) != h.checksum
            {
                return None;
            }
            Some(SegmentIn {
                key: ConnKey {
                    addrs: ConnAddrs::V4 {
                        local: p.ip_me,
                        remote: p.ip_them,
                    },
                    local_port: h.port_me,
                    remote_port: h.port_them,
                },
                seq: h.seqno,
                ack: h.ackno,
                flags: h.flags,
                ttl: p.ttl,
                payload: seg.get(h.header_len..)?,
            })
        }
        None => {
            // План без `source_ipv6` (IPv4 и Студия) IPv6 не принимает вовсе, как `parse_reply`.
            plan.nics().first()?.source_ipv6?;
            let p = ipv6_packet(locate_ipv6(frame, link).ok()??).ok()?;
            if p.next != 6 {
                return None;
            }
            let seg = p.ip.get(p.offset..)?;
            let h = tcp_header(seg).ok()?;
            if !is_my_ip6(plan, p.ip_me) || !is_my_port(plan, h.port_me) {
                return None;
            }
            if checksum_ipv6(p.ip_them, p.ip_me, 6, seg) != h.checksum {
                return None;
            }
            Some(SegmentIn {
                key: ConnKey {
                    addrs: ConnAddrs::V6 {
                        local: p.ip_me,
                        remote: p.ip_them,
                    },
                    local_port: h.port_me,
                    remote_port: h.port_them,
                },
                seq: h.seqno,
                ack: h.ackno,
                flags: h.flags,
                ttl: p.hop_limit,
                payload: seg.get(h.header_len..)?,
            })
        }
    }
}

/// Шаблон кадра стека: копия шаблона SYN и смещения IP, TCP и данных.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FrameTemplate {
    /// Байты до начала данных (`offset_app`): канал, IP, TCP с опциями.
    head: Vec<u8>,
    offset_ip: usize,
    offset_tcp: usize,
}

impl FrameTemplate {
    /// `offset_payload = offset_tcp + doff * 4` (`src/templ-pkt.c:435`): данные начинаются после опций шаблона.
    fn new((packet, offset_ip, offset_tcp): (&[u8], usize, usize)) -> FrameTemplate {
        let doff = packet
            .get(offset_tcp + 12)
            .map_or(5, |b| usize::from(b >> 4));
        let offset_app = (offset_tcp + doff * 4).min(packet.len());
        FrameTemplate {
            head: packet.get(..offset_app).unwrap_or(packet).to_vec(),
            offset_ip,
            offset_tcp,
        }
    }

    fn offset_app(&self) -> usize {
        self.head.len()
    }
}

/// Записать `bytes` в `px` с `at`; за границей ничего (кадр своего шаблона, границы известны заранее).
fn put(px: &mut [u8], at: usize, bytes: &[u8]) {
    if let Some(dst) = at
        .checked_add(bytes.len())
        .and_then(|end| px.get_mut(at..end))
    {
        dst.copy_from_slice(bytes);
    }
}

/// Построитель кадров стека: шаблоны TCP плана (адаптер `nic[0]`, тот же, что у приёмника `parse_reply`) с теми же
/// опциями, что у SYN (`--tcp-mss/--tcp-wscale/--tcp-tsecho/--tcp-sackok`, `--ttl`): в C это один шаблон
/// `&parms->tmplset->pkts[Proto_TCP]` и для SYN, и для стека (`src/main.c:612-620`).
///
/// `--badsum` портит только SYN (Р9): кадры стека строятся с верными суммами, как `tcp_create_packet`. Карта доставки
/// Студии (`ReadyPlan::destinations`) не читается: стек и RST без состояния есть только у плана CLI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpFrameBuilder {
    v4: FrameTemplate,
    /// Шаблон IPv6, только при `source_ipv6` адаптера; MAC шлюза IPv6 как у зонда (без него нули).
    v6: Option<FrameTemplate>,
}

impl TcpFrameBuilder {
    pub fn from_plan(plan: &ReadyPlan) -> Self {
        let binding = plan.binding();
        let mods = plan.effective().packet_modifiers();
        let v4 = TcpSynTemplate::new_with_options(
            binding.source_mac,
            binding.next_hop_mac,
            binding.link_type,
            &mods,
        );
        let v6 = plan
            .nics()
            .first()
            .filter(|n| n.source_ipv6.is_some())
            .map(|n| {
                let t = Tcp6SynTemplate::new_with_options(
                    binding.source_mac,
                    n.next_hop_mac_ipv6.unwrap_or([0; 6]),
                    binding.link_type,
                    &mods,
                );
                FrameTemplate::new(t.frame_template())
            });
        TcpFrameBuilder {
            v4: FrameTemplate::new(v4.frame_template()),
            v6,
        }
    }

    /// Кадр сегмента (`tcp_create_packet`, `src/templ-pkt.c:419-613`, и `tcp_set_window` при `window: Some`,
    /// `src/stack-tcp-core.c:1163-1164`). Пустой `Vec`: кадра нет, потому что он длиннее буфера C (2040 байт, C
    /// возвращает длину 0) или сегмент IPv6, а у плана нет `source_ipv6`.
    pub fn build(&self, s: &SegmentOut) -> Vec<u8> {
        match s.key.addrs {
            ConnAddrs::V4 { local, remote } => build_v4(&self.v4, local, remote, s),
            ConnAddrs::V6 { local, remote } => match &self.v6 {
                Some(t) => build_v6(t, local, remote, s),
                None => Vec::new(),
            },
        }
    }
}

/// Поля TCP, общие для обоих семейств (`src/templ-pkt.c:480-501`, `:581-602`): порты, seq, ack, байт флагов
/// целиком, окно 1200 (или `tcp_set_window`), сумма обнулена.
fn put_tcp_fields(px: &mut [u8], ot: usize, s: &SegmentOut) {
    put(px, ot, &s.key.local_port.to_be_bytes());
    put(px, ot + 2, &s.key.remote_port.to_be_bytes());
    put(px, ot + 4, &s.seq.to_be_bytes());
    put(px, ot + 8, &s.ack.to_be_bytes());
    put(px, ot + 13, &[s.flags]);
    put(px, ot + 14, &s.window.unwrap_or(STACK_WINDOW).to_be_bytes());
    put(px, ot + 16, &[0, 0]);
}

/// Ветка IPv4 `tcp_create_packet` (`src/templ-pkt.c:430-514`).
fn build_v4(t: &FrameTemplate, local: u32, remote: u32, s: &SegmentOut) -> Vec<u8> {
    let new_length = t.offset_app() + s.payload.len();
    if new_length > C_FRAME_BUFFER {
        return Vec::new();
    }
    let (oi, ot) = (t.offset_ip, t.offset_tcp);
    let mut px = Vec::with_capacity(new_length.max(MIN_FRAME_LEN));
    px.extend_from_slice(&t.head);
    px.extend_from_slice(&s.payload);

    // :447-464: длина, ID, адреса. `ip_id = ip_them ^ port_them ^ seqno` (:432), в поле младшие 16 бит.
    let ip_len = new_length.saturating_sub(oi) as u16;
    let ip_id = remote ^ u32::from(s.key.remote_port) ^ s.seq;
    put(&mut px, oi + 2, &ip_len.to_be_bytes());
    put(&mut px, oi + 4, &(ip_id as u16).to_be_bytes());
    put(&mut px, oi + 12, &local.to_be_bytes());
    put(&mut px, oi + 16, &remote.to_be_bytes());
    // E1.10: сумма заголовка заново и полностью, а не приращением C с двумя свёртками (:466-473).
    put(&mut px, oi + 10, &[0, 0]);
    let ip_sum = !ip_header_checksum(&px, oi, px.len());
    put(&mut px, oi + 10, &ip_sum.to_be_bytes());

    put_tcp_fields(&mut px, ot, s);
    // :503-508: полная сумма сегмента с псевдозаголовком (нечётный хвост дополняется нулём).
    let tcp_sum = px
        .get(ot..)
        .map_or(0, |seg| checksum_ipv4(local, remote, 6, seg));
    put(&mut px, ot + 16, &tcp_sum.to_be_bytes());

    // :510-513: набивка нулями до 60 на любом канале.
    if px.len() < MIN_FRAME_LEN {
        px.resize(MIN_FRAME_LEN, 0);
    }
    px
}

/// Ветка IPv6 `tcp_create_packet` (`src/templ-pkt.c:515-611`): `payload_length`, адреса, те же поля TCP, сумма
/// RFC 8200; hop limit шаблона (всегда 255: `template_set_ttl` правит только IPv4, `:1473-1488`), без набивки.
fn build_v6(t: &FrameTemplate, local: u128, remote: u128, s: &SegmentOut) -> Vec<u8> {
    let new_length = t.offset_app() + s.payload.len();
    if new_length > C_FRAME_BUFFER {
        return Vec::new();
    }
    let (oi, ot) = (t.offset_ip, t.offset_tcp);
    let mut px = Vec::with_capacity(new_length);
    px.extend_from_slice(&t.head);
    px.extend_from_slice(&s.payload);

    // :535-539: всё после 40 байт заголовка IPv6.
    let payload_length = new_length.saturating_sub(oi + 40) as u16;
    put(&mut px, oi + 4, &payload_length.to_be_bytes());
    put(&mut px, oi + 8, &local.to_be_bytes());
    put(&mut px, oi + 24, &remote.to_be_bytes());

    put_tcp_fields(&mut px, ot, s);
    // :604-606.
    let tcp_sum = px
        .get(ot..)
        .map_or(0, |seg| checksum_ipv6(local, remote, 6, seg));
    put(&mut px, ot + 16, &tcp_sum.to_be_bytes());
    px
}

/// RST без состояния (Р8, справка A7): ответ на SYN-ACK или RST, прошедший cookie (`src/main.c:1094-1100`,
/// `tcp_send_RST(templ, stack, ip_them, ip_me, port_them, port_me, 0, seqno_me)`). seq это наш ack ответа
/// (`seqno_me`, равный `cookie + 1` после проверки `src/main.c:1059`), ack 0, флаги `0x04`, окно шаблона стека.
/// C отвечает так и на RST закрытого порта (справка E3.6).
///
/// Вызывающий отдаёт сюда только ответ, прошедший и дедупликацию: C шлёт RST после `dedup_is_duplicate`
/// (`src/main.c:1066-1068` раньше `:1094`), поэтому повтор того же SYN-ACK или RST второго RST не получает.
///
/// `None`, если ответ не TCP или флаги не SYN-ACK (`(flags & 0x12) == 0x12`) и не RST (`flags & 0x04`): ICMP Port
/// Unreachable на зонд TCP (`ip_proto` 6, флагов нет), UDP, SCTP, ICMP, ARP. Cookie считается заново по адресам
/// ответа: `Reply` своего ack не несёт, а `parse_reply` принял ответ только при `cookie == ack - 1`.
pub fn stateless_rst(reply: &Reply, seed: u64) -> Option<SegmentOut> {
    let f = reply.tcp_flags;
    if reply.ip_proto != 6 || (f & FLAG_SYNACK_MASK != FLAG_SYNACK_MASK && f & FLAG_RST == 0) {
        return None;
    }
    let (port_them, port_me) = (u32::from(reply.remote_port), u32::from(reply.local_port));
    let (addrs, cookie) = match reply.ip6 {
        Some(a) => (
            ConnAddrs::V6 {
                local: a.local,
                remote: a.remote,
            },
            syn_cookie_ipv6(a.remote, port_them, a.local, port_me, seed) as u32,
        ),
        None => (
            ConnAddrs::V4 {
                local: reply.local_ip,
                remote: reply.remote_ip,
            },
            syn_cookie_ipv4(reply.remote_ip, port_them, reply.local_ip, port_me, seed) as u32,
        ),
    };
    Some(SegmentOut {
        key: ConnKey {
            addrs,
            local_port: reply.local_port,
            remote_port: reply.remote_port,
        },
        seq: cookie.wrapping_add(1),
        ack: 0,
        flags: FLAG_RST,
        payload: Vec::new(),
        window: None,
    })
}
