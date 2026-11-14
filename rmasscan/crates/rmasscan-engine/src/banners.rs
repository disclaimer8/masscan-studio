//! Баннеры UDP-ответов (`handle_udp`, `src/proto-udp.c:54-132`) и стек TCP (подэтап 4b): аддитивный API движка
//! (Р11).
//!
//! Движок не зависит от `rmasscan-proto`: новая обычная зависимость изменила бы `Cargo.lock` Studio, которая
//! собирается с `--locked` и не меняется ни на байт. Поэтому разбор датаграммы приходит снаружи, указателем на функцию
//! в [`BannerOptions::udp_parser`] (CLI передаёт туда `rmasscan_proto::handle_udp`), таблица соединений TCP через
//! фабрику [`TcpStackOptions::factory`] (трейт ядра `rmasscan_core::stack`), а тип записи ([`BannerRecord`]) живёт
//! в ядре.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use rmasscan_core::banner::{BannerRecord, MAX_BANNER_BYTES};
use rmasscan_core::cookie::{syn_cookie_ipv4, syn_cookie_ipv6};
use rmasscan_core::packet::LinkType;
use rmasscan_core::receive::{PortStatus, Reply, udp_payload};
use rmasscan_core::stack::{StackStats, TcpStackFactory};
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
/// идут его баннеры. Баннеры соединений ([`Output::ConnectionBanner`]) между ответом и его баннерами не встают
/// (каждый набор кладётся под одной блокировкой очереди), записи одного соединения идут подряд, в порядке C, и тоже
/// обрывают пачку `Results`.
#[derive(Debug, Clone, PartialEq)]
pub enum Output {
    Event(Event),
    /// Баннер последнего ответа перед ним. `timestamp` всегда 0: у [`Reply`] времени нет, и потребитель ставит баннеру
    /// время записи статуса его ответа (CLI: `Sink::report_reply_banner`); `ttl` уже как у ответа.
    Banner(BannerRecord),
    /// Баннер соединения TCP (сброс TCB, `banner_flush`, `src/stack-tcp-core.c:800-830`): к предыдущему ответу не
    /// привязан, приходит, когда соединение кончилось (FIN, RST, жизнь) или в сбросе таблицы в конце скана.
    /// `timestamp` всегда 0: потребитель ставит время в момент обработки (`global_now` C при сбросе, справка B3; CLI:
    /// `Sink::report_connection_banner`); `ttl` это TTL SYN-ACK соединения. Только с [`TcpStackOptions`].
    ConnectionBanner(BannerRecord),
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

/// Включает пользовательский стек TCP (`--banners`, подэтап 4b). По умолчанию в [`crate::EngineOptions`] его нет
/// (`None`, так у Studio): ни один сегмент не идёт в стек, тиков нет, [`Output::ConnectionBanner`] не выдаётся, кадры
/// и события побайтно прежние.
///
/// Реализация таблицы приходит снаружи, через фабрику (CLI передаёт фабрику `rmasscan-proto`): обычная зависимость
/// движка от `rmasscan-proto` изменила бы `Cargo.lock` Studio (Р11), как и для [`BannerOptions::udp_parser`].
/// Каждый RX-поток получает свою таблицу (в C своя таблица у каждого `receive_thread`, `src/main.c:612`) с параметрами
/// `TableParams { seed скана, capacity: max(1024, table_capacity / адаптеров), banner_byte_budget: banner_byte_budget
/// / адаптеров }`.
#[derive(Debug, Clone)]
pub struct TcpStackOptions {
    pub factory: Arc<dyn TcpStackFactory>,
    /// Предел живых соединений на скан (C предела не знает, `src/stack-tcp-core.c:673-697`).
    pub table_capacity: usize,
    /// Бюджет байтов баннеров живых соединений на скан.
    pub banner_byte_budget: usize,
}

/// Счётчики стека скана ([`crate::EngineHandle::stack_stats`]): сумма таблиц всех RX-потоков и кадры стека. Кадр
/// выброшен, если очередь кадров адаптера полна (`STACK_OUT_CAP`, RX не ждёт, Р7), если построитель его не строит
/// (длиннее буфера C или IPv6 без `source_ipv6`, `TcpFrameBuilder::build`) или если его выдал сброс таблицы в конце
/// (`tcpcon_destroy_table` кадров не шлёт, `src/stack-tcp-core.c:933-961`). Отправленные кадры считает TX.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StackSummary {
    pub stack: StackStats,
    pub frames_sent: u64,
    pub frames_dropped: u64,
}

impl StackSummary {
    /// Сумма счётчиков таблиц (насыщающая).
    pub(crate) fn add_table(&mut self, s: &StackStats) {
        let t = &mut self.stack;
        t.tcbs_created = t.tcbs_created.saturating_add(s.tcbs_created);
        t.tcbs_live = t.tcbs_live.saturating_add(s.tcbs_live);
        t.table_full = t.table_full.saturating_add(s.table_full);
        t.banner_bytes_dropped = t
            .banner_bytes_dropped
            .saturating_add(s.banner_bytes_dropped);
    }
}
