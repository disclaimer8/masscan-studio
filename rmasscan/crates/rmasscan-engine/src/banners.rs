//! Баннеры UDP-ответов (`handle_udp`, `src/proto-udp.c:54-132`): аддитивный API движка (Р11).
//!
//! Движок не зависит от `rmasscan-proto`: новая обычная зависимость изменила бы `Cargo.lock` Studio, которая
//! собирается с `--locked` и не меняется ни на байт. Поэтому разбор датаграммы приходит снаружи, указателем на функцию
//! в [`BannerOptions::udp_parser`] (CLI передаёт туда `rmasscan_proto::handle_udp`), а тип записи
//! ([`BannerRecord`]) живёт в ядре.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rmasscan_core::banner::{BannerRecord, MAX_BANNER_BYTES};
use rmasscan_core::cookie::{syn_cookie_ipv4, syn_cookie_ipv6};
use rmasscan_core::packet::LinkType;
use rmasscan_core::receive::{PortStatus, Reply, udp_payload};
use rmasscan_core::targets::TEMPL_UDP;

use crate::events::Event;

/// Разбор одного UDP-ответа в баннеры, как `handle_udp` крейта `rmasscan-proto`: порт источника ответа, cookie
/// `(unsigned)syn_cookie(ip_them, port_them | Templ_UDP, ip_me, port_me, entropy)`, флаг `--rawudp` и полезная
/// нагрузка датаграммы. Возвращает `(номер приложения, байты)` в порядке C, без записи статуса.
pub type UdpBannerParser =
    fn(port_them: u16, cookie: u32, rawudp: bool, payload: &[u8]) -> Vec<(u16, Vec<u8>)>;

/// Включает баннеры UDP (`--banners`, `--rawudp`). По умолчанию в [`crate::EngineOptions`] их нет (`None`): тогда
/// движок не разбирает ни одной датаграммы и [`Output::Banner`] не выдаёт.
#[derive(Clone, Copy, Debug)]
pub struct BannerOptions {
    /// `--rawudp` (`is_banner_rawudp`, `src/proto-udp.c:120`): сырой баннер за каждым ответом.
    pub rawudp: bool,
    /// Разбор датаграммы (см. [`UdpBannerParser`]).
    pub udp_parser: UdpBannerParser,
}

/// Событие или баннер, по порядку очереди (`EngineHandle::recv_output_timeout`).
///
/// Гарантия порядка: баннеры ответа приходят сразу после того [`Event::Results`], в котором последним стоит этот
/// ответ, и раньше записи любого более позднего ответа. Пачка `Results` с баннерами обрывается на ответе, за которым
/// идут его баннеры.
#[derive(Debug, Clone, PartialEq)]
pub enum Output {
    Event(Event),
    Banner(BannerRecord),
}

/// Баннеры, которые движок выдаёт за принятым и прошедшим дедуп ответом `reply` (кадр `frame` канала `link`, seed
/// задания `seed`). Пусто для всего, что не датаграмма UDP: TCP, SCTP, ICMP, ARP и `closed udp` из ICMP 3/3 баннеров
/// у C не дают (`src/proto-icmp.c:194-204`, справка B9).
///
/// - Cookie: `syn_cookie_ipv4`/`syn_cookie_ipv6` по индексу `Templ_UDP + порт`, как у зонда (`src/main.c:389`) и у
///   приёма C (`src/proto-dns.c:369`, справка B10). Для пользовательской нагрузки (`--nmap-payloads`,
///   `--pcap-payloads`) мутатора нет и зонд cookie не несёт (`src/templ-payloads.c:619-680`), а cookie приёма тот же:
///   DNS, NBNS и SNMP молчат, CoAP и memcached пишут ` IP-MISMATCH`, ISAKMP уходит в сырой баннер (справка B10).
/// - Время записи 0: у [`Reply`] времени нет, его ставит потребитель записи статуса (CLI, Р9 этапа вывода); баннер
///   получает время своей записи статуса там же. TTL тот же, что у статуса (`parsed->ip_ttl`, справка A0).
/// - Р5: нагрузка каждой записи не длиннее [`MAX_BANNER_BYTES`]. Парсеры ограничены датаграммой, а текст ISAKMP
///   обрезан ровно на этом пределе, поэтому вывод от этого не меняется; предел здесь страхует любой будущий парсер.
pub fn udp_reply_banners(
    options: &BannerOptions,
    frame: &[u8],
    link: LinkType,
    reply: &Reply,
    seed: u64,
) -> Vec<BannerRecord> {
    if reply.ip_proto != 17 || reply.status != PortStatus::Open {
        return Vec::new();
    }
    let Some(payload) = udp_payload(frame, link) else {
        return Vec::new();
    };
    let port_index = TEMPL_UDP + u32::from(reply.remote_port);
    let local_port = u32::from(reply.local_port);
    let (ip, cookie) = match reply.ip6 {
        Some(a) => (
            IpAddr::V6(Ipv6Addr::from(a.remote)),
            syn_cookie_ipv6(a.remote, port_index, a.local, local_port, seed) as u32,
        ),
        None => (
            IpAddr::V4(Ipv4Addr::from(reply.remote_ip)),
            syn_cookie_ipv4(
                reply.remote_ip,
                port_index,
                reply.local_ip,
                local_port,
                seed,
            ) as u32,
        ),
    };
    (options.udp_parser)(reply.remote_port, cookie, options.rawudp, payload)
        .into_iter()
        .map(|(app, mut bytes)| {
            bytes.truncate(MAX_BANNER_BYTES);
            BannerRecord {
                timestamp: 0,
                ip,
                ip_proto: 17,
                port: reply.remote_port,
                app,
                ttl: reply.ttl,
                payload: bytes,
            }
        })
        .collect()
}
