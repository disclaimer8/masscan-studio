//! Баннеры UDP через engine (`--banners`, `--rawudp`, `handle_udp`, `src/proto-udp.c:54-132`) на фиктивном адаптере
//! и `ManualClock` (AGPL-3.0). Только офлайн: ни один кадр не уходит в сеть. Адреса документационные (RFC 5737,
//! `2001:db8::/32`) и `10.0.0.0/29` общих тестов движка.

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant};

use common::*;
use rmasscan_core::banner::{BannerRecord, MAX_BANNER_BYTES};
use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::cookie::{syn_cookie_ipv4, syn_cookie_ipv6};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::LinkType;
use rmasscan_core::payloads::PayloadTable;
use rmasscan_core::probe::{AdapterBinding, NicBinding, ReadyPlan};
use rmasscan_core::receive::{PortStatus, Reply, ReplyIpv6, udp_payload};
use rmasscan_core::targets::{TEMPL_UDP, add_target_string, parse_ports};
use rmasscan_core::throttle::Clock;
use rmasscan_engine::fake::{FakeAdapter, ManualClock, port_unreachable_for, reply_to_udp};
use rmasscan_engine::{
    BannerOptions, Engine, EngineHandle, EngineOptions, Event, Outcome, Output, udp_reply_banners,
};
use rmasscan_proto::app_id;

/// Настоящие парсеры `rmasscan-proto` в форме указателя, которую принимает движок.
fn proto_parser(port_them: u16, cookie: u32, rawudp: bool, payload: &[u8]) -> Vec<(u16, Vec<u8>)> {
    rmasscan_proto::handle_udp(
        &rmasscan_proto::UdpContext {
            port_them,
            cookie,
            rawudp,
        },
        payload,
    )
}

fn banner_options(rawudp: bool) -> BannerOptions {
    BannerOptions {
        rawudp,
        udp_parser: proto_parser,
    }
}

fn with_banners(rawudp: bool) -> EngineOptions {
    let mut o = no_stall_opts();
    o.banners = Some(banner_options(rawudp));
    o
}

/// План `U:` на `10.0.0.0/29` с одним портом источника: повтор зонда (`--retries`) уходит с тем же портом, и его
/// ответ это настоящий дубль для `DedupCache`.
fn plan_with(ports: &str, retries: u32, payloads: PayloadTable) -> ReadyPlan {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), "10.0.0.0/29").unwrap();
    parse_ports(m.ports_mut(), ports).unwrap();
    let cfg = ScanConfig {
        targets: m,
        seed: SEED,
        max_rate: 1_000_000.0,
        wait_secs: 3,
        retries,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).unwrap();
    ReadyPlan::new_cli_with_payloads(
        eff,
        vec![NicBinding::from(AdapterBinding {
            interface_id: "fake0".into(),
            link_type: LinkType::Ethernet,
            source_ipv4: IP_ME,
            source_mac: [0, 0x11, 0x22, 0x33, 0x44, 0x55],
            next_hop_mac: [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            source_ports: (40000, 40000),
        })],
        payloads,
    )
    .unwrap()
}

fn plan(ports: &str) -> ReadyPlan {
    plan_with(ports, 0, PayloadTable::builtin())
}

fn is_udp(f: &[u8]) -> bool {
    f.len() >= 42 && f[23] == 17
}

fn dport(f: &[u8]) -> u16 {
    u16::from_be_bytes([f[36], f[37]])
}

fn target(f: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(f[30], f[31], f[32], f[33])
}

/// Нагрузка зонда (после заголовка UDP).
fn probe_payload(f: &[u8]) -> &[u8] {
    &f[42..]
}

/// Ответ на зонд version.bind TXT CHAOS (`src/templ-payloads.c:76-86`): id из зонда, RCODE 0, одна строка TXT.
fn dns_chaos(id: [u8; 2], text: &[u8]) -> Vec<u8> {
    let mut v = id.to_vec();
    v.extend([0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0]);
    v.extend(b"\x07version\x04bind\x00\x00\x10\x00\x03");
    v.extend([0xC0, 0x0C, 0x00, 0x10, 0x00, 0x03, 0, 0, 0, 0]);
    v.extend(u16::try_from(text.len() + 1).unwrap().to_be_bytes());
    v.push(u8::try_from(text.len()).unwrap());
    v.extend(text);
    v
}

/// Ответ NBSTAT (`src/proto-netbios.c:110-169`): id из зонда, одно имя и MAC.
fn nbstat(id: [u8; 2]) -> Vec<u8> {
    let mut rdata = vec![1];
    rdata.extend(b"HOST1          \x00\x04\x00");
    rdata.extend([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    let mut v = id.to_vec();
    v.extend([
        0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0, 1, b'A', 0, 0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0,
    ]);
    v.extend(u16::try_from(rdata.len()).unwrap().to_be_bytes());
    v.extend(rdata);
    v
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut v = vec![tag, u8::try_from(value.len()).unwrap()];
    v.extend(value);
    v
}

/// SNMPv1 GetResponse с request-id `id` (4 байта, как в зонде) и sysName = `rmasscan` (`src/proto-snmp.c:536-584`).
fn snmp_response(id: &[u8]) -> Vec<u8> {
    let oid = [0x2B, 6, 1, 2, 1, 1, 5, 0];
    let vb = tlv(0x30, &[tlv(6, &oid), tlv(4, b"rmasscan")].concat());
    let pdu = tlv(
        0xA2,
        &[tlv(2, id), tlv(2, &[0]), tlv(2, &[0]), tlv(0x30, &vb)].concat(),
    );
    tlv(0x30, &[tlv(2, &[0]), tlv(4, b"public"), pdu].concat())
}

/// Ответ ISAKMP main mode: cookie инициатора из зонда, selftest-вектор C `sample1` (`src/proto-isakmp.c:464-470`).
fn isakmp_response(init_cookie: &[u8]) -> Vec<u8> {
    let tail = [
        0xbe, 0x3d, 0xc6, 0x8e, 0xea, 0xf2, 0xda, 0xac, 0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x01,
        0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x05, 0x80, 0x02, 0x00, 0x02, 0x80, 0x04, 0x00, 0x02,
        0x80, 0x03, 0x00, 0x01, 0x80, 0x0b, 0x00, 0x01, 0x80, 0x0c, 0x00, 0x01,
    ];
    [init_cookie, &tail[..]].concat()
}

/// memcached UDP `stats`: request id из зонда (`src/proto-memcached.c:298-392`).
fn memcached_response(id: &[u8]) -> Vec<u8> {
    [
        id,
        &[0, 0, 0, 1, 0, 0],
        b"STAT uptime 12345\r\nSTAT version 1.6.21\r\nEND\r\n",
    ]
    .concat()
}

/// Ответ сервера, который копирует идентификатор зонда в своё поле, как настоящий: DNS/NBNS байты 0-1, SNMP
/// request-id (байты 17-20 зонда, раскладка встроенного и пользовательского зондов одна), ISAKMP байты 0-7, CoAP
/// message id байты 2-3, memcached байты 0-1.
fn echo_reply(port: u16, probe: &[u8]) -> Option<Vec<u8>> {
    Some(match port {
        53 => dns_chaos([probe[0], probe[1]], b"9.18.24"),
        137 => nbstat([probe[0], probe[1]]),
        161 => snmp_response(&probe[17..21]),
        500 => isakmp_response(&probe[..8]),
        5683 => vec![0x60, 0x45, probe[2], probe[3]],
        11211 => memcached_response(&probe[..2]),
        _ => return None,
    })
}

/// Ответчик: на каждый зонд UDP `copies` одинаковых датаграмм с нагрузкой `payload(зонд)`.
fn udp_responder(
    copies: usize,
    payload: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static,
) -> impl FnMut(&[u8]) -> Vec<Vec<u8>> + Send + 'static {
    move |f: &[u8]| {
        if !is_udp(f) {
            return vec![];
        }
        let Some(p) = payload(f) else {
            return vec![];
        };
        let r = reply_to_udp(f, &p).unwrap();
        vec![r; copies]
    }
}

/// Запуск: все элементы `recv_output_timeout` до `Finished` включительно, отправленные кадры, итог.
fn run_outputs(
    plan: &ReadyPlan,
    responder: impl FnMut(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
    options: EngineOptions,
) -> (Vec<Output>, Vec<Vec<u8>>, Outcome) {
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    fake.set_responder(responder);
    let h = start_manual(plan, &fake, &clock, options);
    let outputs = drain_outputs(&h);
    let outcome = h.join().unwrap();
    (outputs, fake.sent_frames(), outcome)
}

fn drain_outputs(h: &EngineHandle) -> Vec<Output> {
    let mut v = Vec::new();
    let t = Instant::now();
    loop {
        match h.recv_output_timeout(Duration::from_millis(50)) {
            Ok(o) => {
                let fin = matches!(o, Output::Event(Event::Finished { .. }));
                v.push(o);
                if fin {
                    return v;
                }
            }
            Err(TryRecvError::Empty) => {
                assert!(t.elapsed() < Duration::from_secs(10), "no Finished: {v:?}");
            }
            Err(TryRecvError::Disconnected) => return v,
        }
    }
}

/// Записи статуса и баннеры в порядке выдачи.
#[derive(Debug, Clone, PartialEq)]
enum Item {
    Status(Reply),
    Banner(BannerRecord),
}

fn items(outputs: &[Output]) -> Vec<Item> {
    outputs
        .iter()
        .flat_map(|o| match o {
            Output::Event(Event::Results { replies }) => {
                replies.iter().copied().map(Item::Status).collect()
            }
            Output::Banner(b) => vec![Item::Banner(b.clone())],
            Output::Event(_) => vec![],
        })
        .collect()
}

/// Баннеры по записи статуса: каждая запись и баннеры, которые идут за ней до следующей записи. Баннер без записи
/// перед ним (нарушение порядка) роняет тест.
fn grouped(outputs: &[Output]) -> Vec<(Reply, Vec<BannerRecord>)> {
    let mut groups: Vec<(Reply, Vec<BannerRecord>)> = Vec::new();
    for it in items(outputs) {
        match it {
            Item::Status(r) => groups.push((r, Vec::new())),
            Item::Banner(b) => groups
                .last_mut()
                .expect("a banner before any status record")
                .1
                .push(b),
        }
    }
    groups
}

fn reply_ip(r: &Reply) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(r.remote_ip))
}

/// Каждый баннер принадлежит записи перед ним: тот же адрес, порт и TTL, протокол 17, время 0 (его ставит
/// потребитель вместе с временем записи статуса).
fn assert_banner_of(r: &Reply, b: &BannerRecord) {
    assert_eq!(
        (b.ip, b.port, b.ip_proto, b.ttl, b.timestamp),
        (reply_ip(r), r.remote_port, 17, r.ttl, 0),
        "{b:?} after {r:?}"
    );
}

/// DNS CHAOS TXT: запись `open udp` (как без баннеров), затем `dns-ver` с текстом, без сырого баннера (C: RCODE 0 и
/// ответ CHAOS TXT дают только текст, справка B0). Баннер стоит сразу за своей записью, пачка `Results` на нём
/// обрывается.
#[test]
fn udp_banner_follows_its_status() {
    let p = plan("U:53");
    let (outputs, _, outcome) = run_outputs(
        &p,
        udp_responder(1, |f| {
            let q = probe_payload(f);
            (dport(f) == 53).then(|| dns_chaos([q[0], q[1]], b"9.18.24"))
        }),
        with_banners(false),
    );
    assert_eq!(outcome.reason, rmasscan_engine::Reason::Completed);
    let groups = grouped(&outputs);
    assert_eq!(groups.len(), 8, "{outputs:?}");
    for (r, banners) in &groups {
        assert_eq!(
            (r.status, r.ip_proto, r.remote_port, r.ttl),
            (PortStatus::Open, 17, 53, 64)
        );
        assert_eq!(banners.len(), 1, "{banners:?}");
        assert_banner_of(r, &banners[0]);
        assert_eq!(
            (banners[0].app, &banners[0].payload[..]),
            (app_id::DNS_VERSIONBIND, &b"9.18.24"[..])
        );
    }
    // Пачка ответов с баннером кончается этим ответом: следующий элемент очереди это его баннер.
    for w in outputs.windows(2) {
        if let [Output::Event(Event::Results { replies }), next] = w {
            assert!(matches!(next, Output::Banner(b) if b.ip == reply_ip(replies.last().unwrap())));
        }
    }
}

fn result_replies(events: &[Event]) -> Vec<Reply> {
    let mut v = all_replies(events);
    v.sort_by_key(|r| (r.remote_ip, r.remote_port));
    v
}

fn drain_events(plan: &ReadyPlan, options: EngineOptions) -> (Vec<Event>, Vec<Vec<u8>>) {
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    fake.set_responder(udp_responder(1, |f| {
        let q = probe_payload(f);
        (dport(f) == 53).then(|| dns_chaos([q[0], q[1]], b"9.18.24"))
    }));
    let c: Arc<dyn Clock + Send + Sync> = clock.clone();
    let h = Engine::start_with_clock(plan.clone(), fake.pair(), options, c).unwrap();
    let events = drain_to_finished(&h);
    h.join().unwrap();
    (events, fake.sent_frames())
}

/// Без `banners` движок прежний: кадры те же, что у независимого `ProbeCursor`, `recv_output_timeout` выдаёт только
/// события (те же ответы, что `recv_event_timeout`), а с баннерами `recv_event_timeout` их пропускает, и кадры и
/// ответы не меняются ни на байт.
#[test]
fn banners_off_changes_nothing() {
    let p = plan("U:53,U:59999");
    let (events_off, frames_off) = drain_events(&p, no_stall_opts());
    assert_eq!(frames_off, reference_frames(&p, 16));
    let (outputs, frames_out, _) = run_outputs(
        &p,
        udp_responder(1, |f| {
            let q = probe_payload(f);
            (dport(f) == 53).then(|| dns_chaos([q[0], q[1]], b"9.18.24"))
        }),
        no_stall_opts(),
    );
    assert!(
        outputs.iter().all(|o| matches!(o, Output::Event(_))),
        "{outputs:?}"
    );
    let events_out: Vec<Event> = outputs
        .into_iter()
        .filter_map(|o| match o {
            Output::Event(e) => Some(e),
            Output::Banner(_) => None,
        })
        .collect();
    assert_eq!(frames_out, frames_off);
    assert_eq!(result_replies(&events_out), result_replies(&events_off));
    let (events_on, frames_on) = drain_events(&p, with_banners(true));
    assert_eq!(frames_on, frames_off);
    assert_eq!(result_replies(&events_on), result_replies(&events_off));
    assert_eq!(result_replies(&events_off).len(), 8);
    for evs in [&events_off, &events_on] {
        assert!(matches!(evs.first(), Some(Event::Started { range: 16 })));
        assert!(matches!(evs.last(), Some(Event::Finished { .. })));
    }
}

/// Review Focus 3: две копии датаграммы на каждый зонд и повторы зонда (`--retries 1`) дают несколько одинаковых ответов на
/// цель. У C каждая датаграмма это запись статуса и баннеры (справка C1.3); у rmasscan статус дедуплицирован, и
/// баннеры идут только за ответом, прошедшим дедуп: одна запись и один набор баннеров на цель.
#[test]
fn udp_duplicate_reply_gives_one_status_and_one_banner_set() {
    let p = plan_with("U:53", 1, PayloadTable::builtin());
    let (outputs, frames, outcome) = run_outputs(
        &p,
        udp_responder(2, |f| {
            let q = probe_payload(f);
            (dport(f) == 53).then(|| dns_chaos([q[0], q[1]], b"9.18.24"))
        }),
        with_banners(true),
    );
    // `--retries 1` шлёт каждой цели повторы одного и того же кадра (порт источника один, cookie тот же).
    assert!(frames.len() >= 16, "{}", frames.len());
    let mut distinct = frames.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        8,
        "every retry repeats its probe byte for byte"
    );
    // Две датаграммы на каждый кадр: все, кроме первой на цель, повторы.
    assert_eq!(outcome.progress.duplicates, 2 * frames.len() as u64 - 8);
    let groups = grouped(&outputs);
    assert_eq!(groups.len(), 8, "{outputs:?}");
    let mut ips: Vec<IpAddr> = groups.iter().map(|(r, _)| reply_ip(r)).collect();
    ips.sort();
    ips.dedup();
    assert_eq!(ips.len(), 8);
    for (r, banners) in &groups {
        let apps: Vec<u16> = banners.iter().map(|b| b.app).collect();
        assert_eq!(apps, [app_id::DNS_VERSIONBIND, app_id::NONE], "{banners:?}");
        for b in banners {
            assert_banner_of(r, b);
        }
    }
}

/// DNS с чужим id (cookie не совпал): запись `open udp` есть, баннеров нет (`src/proto-dns.c:369-374`: `return 1`, и
/// сырой баннер без `--rawudp` не пишется).
#[test]
fn wrong_cookie_dns_gives_status_without_banner() {
    let p = plan("U:53");
    let (outputs, _, _) = run_outputs(
        &p,
        udp_responder(1, |f| {
            let q = probe_payload(f);
            (dport(f) == 53).then(|| dns_chaos([q[0] ^ 0x01, q[1]], b"9.18.24"))
        }),
        with_banners(false),
    );
    let groups = grouped(&outputs);
    assert_eq!(groups.len(), 8);
    assert!(
        groups
            .iter()
            .all(|(r, b)| b.is_empty() && r.status == PortStatus::Open),
        "{groups:?}"
    );
}

/// `--rawudp` (`src/proto-udp.c:120`): сырой баннер (вся датаграмма) и там, где без него его нет: за текстом
/// `dns-ver` при верном cookie и один при неверном. Порт без парсера даёт первые 64 байта и сырой с флагом и без.
#[test]
fn rawudp_adds_raw_everywhere() {
    let p = plan("U:53,U:9999");
    // Нечётные адреса отвечают DNS с чужим id (старший байт id с инвертированным младшим битом).
    let reply = |f: &[u8]| -> Option<Vec<u8>> {
        let q = probe_payload(f);
        let odd = target(f).octets()[3] % 2 == 1;
        match dport(f) {
            53 => Some(dns_chaos([q[0] ^ u8::from(odd), q[1]], b"9.18.24")),
            9999 => Some((0u8..100).collect()),
            _ => None,
        }
    };
    for rawudp in [false, true] {
        let (outputs, _, _) = run_outputs(&p, udp_responder(1, reply), with_banners(rawudp));
        let groups = grouped(&outputs);
        assert_eq!(groups.len(), 16, "{outputs:?}");
        for (r, banners) in &groups {
            for b in banners {
                assert_banner_of(r, b);
            }
            let got: Vec<(u16, Vec<u8>)> =
                banners.iter().map(|b| (b.app, b.payload.clone())).collect();
            // Датаграмма ответчика восстанавливается независимо: id это cookie зонда (`dns_set_cookie`).
            let cookie = syn_cookie_ipv4(
                r.remote_ip,
                TEMPL_UDP + u32::from(r.remote_port),
                r.local_ip,
                u32::from(r.local_port),
                SEED,
            ) as u16;
            let odd = r.remote_ip % 2 == 1;
            let [hi, lo] = cookie.to_be_bytes();
            let sent = dns_chaos([hi ^ u8::from(odd), lo], b"9.18.24");
            let mut want = match (r.remote_port, odd) {
                (53, false) => vec![(app_id::DNS_VERSIONBIND, b"9.18.24".to_vec())],
                (53, true) => vec![],
                _ => vec![(app_id::NONE, (0u8..64).collect())],
            };
            if r.remote_port == 9999 {
                want.push((app_id::NONE, (0u8..100).collect()));
            } else if rawudp {
                want.push((app_id::NONE, sent));
            }
            assert_eq!(got, want, "rawudp {rawudp}, {r:?}");
        }
    }
}

/// Кадр Ethernet + IPv6 + UDP от `src` порта `sport` к нашему `dst`:`dport`, hop limit `hlim`.
fn eth_ipv6_udp(src: u128, sport: u16, dst: u128, dport: u16, hlim: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x86, 0xdd];
    let len = u16::try_from(8 + payload.len()).unwrap();
    f.extend([0x60, 0, 0, 0]);
    f.extend(len.to_be_bytes());
    f.extend([17, hlim]);
    f.extend(src.to_be_bytes());
    f.extend(dst.to_be_bytes());
    f.extend(sport.to_be_bytes());
    f.extend(dport.to_be_bytes());
    f.extend(len.to_be_bytes());
    f.extend([0, 0]);
    f.extend(payload);
    f
}

/// Баннер UDP поверх IPv6: cookie это `syn_cookie_ipv6` по индексу `Templ_UDP + порт` (справка B10), адрес IPv6, TTL
/// это hop limit ответа. Скан UDP поверх IPv6 пока отказывает до первого кадра (R3 этапа IPv6, `parse_reply`
/// такой ответ не принимает), поэтому путь проверяется на построителе баннеров движка напрямую.
#[test]
fn udp_banner_ipv6() {
    let them: u128 = u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5));
    let me: u128 = u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let cookie6 = syn_cookie_ipv6(them, TEMPL_UDP + 53, me, 40000, SEED) as u32;
    let reply = Reply {
        remote_ip: 0,
        remote_port: 53,
        local_ip: 0,
        local_port: 40000,
        status: PortStatus::Open,
        tcp_flags: 0,
        ttl: 57,
        ip_proto: 17,
        mac: None,
        ip6: Some(ReplyIpv6 {
            remote: them,
            local: me,
        }),
    };
    let id = (cookie6 as u16).to_be_bytes();
    let frame = eth_ipv6_udp(them, 53, me, 40000, 57, &dns_chaos(id, b"9.18.24"));
    assert_eq!(
        udp_payload(&frame, LinkType::Ethernet),
        Some(&dns_chaos(id, b"9.18.24")[..])
    );
    let got = udp_reply_banners(
        &banner_options(false),
        &frame,
        LinkType::Ethernet,
        &reply,
        SEED,
    );
    assert_eq!(
        got,
        vec![BannerRecord {
            timestamp: 0,
            ip: IpAddr::V6(Ipv6Addr::from(them)),
            ip_proto: 17,
            port: 53,
            app: app_id::DNS_VERSIONBIND,
            ttl: 57,
            payload: b"9.18.24".to_vec(),
        }]
    );
    // Cookie IPv4 с теми же числами здесь не годится: id от него молчит.
    let cookie4 = syn_cookie_ipv4(0, TEMPL_UDP + 53, 0, 40000, SEED) as u32;
    assert_ne!(cookie4 as u16, cookie6 as u16);
    let wrong = eth_ipv6_udp(
        them,
        53,
        me,
        40000,
        57,
        &dns_chaos((cookie4 as u16).to_be_bytes(), b"9.18.24"),
    );
    assert!(
        udp_reply_banners(
            &banner_options(false),
            &wrong,
            LinkType::Ethernet,
            &reply,
            SEED
        )
        .is_empty()
    );
}

/// Таблица нагрузок со встроенными записями, где порты 53, 137, 161, 500, 5683 и 11211 заменены нагрузкой файла
/// `--nmap-payloads` (у неё нет мутатора cookie, `src/templ-payloads.c:619-680`). Раскладка полей та же, что у
/// встроенных зондов, идентификаторы постоянные.
fn user_payloads() -> PayloadTable {
    let mut t = PayloadTable::builtin();
    let text = concat!(
        "udp 53 \"\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00",
        "\\x07version\\x04bind\\x00\\x00\\x10\\x00\\x03\"\n",
        "udp 137 \"\\x12\\x34\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00 ",
        "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\x00\\x00\\x21\\x00\\x01\"\n",
        "udp 161 \"\\x30\\x26\\x02\\x01\\x00\\x04\\x06public\\xa0\\x19\\x02\\x04\\x01\\x02\\x03\\x04",
        "\\x02\\x01\\x00\\x02\\x01\\x00\\x30\\x0b\\x30\\x09\\x06\\x05\\x2b\\x06\\x01\\x02\\x01\\x05\\x00\"\n",
        "udp 500 \"\\xaa\\xbb\\xcc\\xdd\\xee\\xff\\x11\\x22\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00",
        "\\x01\\x10\\x02\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x1c\"\n",
        "udp 5683 \"\\x40\\x01\\x12\\x34\"\n",
        "udp 11211 \"\\x12\\x34\\x00\\x00\\x00\\x01\\x00\\x00stats\\r\\n\"\n",
    );
    assert_eq!(t.load_nmap_payloads(text).unwrap(), 6);
    for port in [53, 137, 161, 500, 5683, 11211] {
        assert_eq!(t.get(port).unwrap().set_cookie, None, "port {port}");
    }
    t
}

/// Review Focus 4 (справка B10): у пользовательской нагрузки нет мутатора, зонд cookie не несёт, а приём сверяет тот
/// же cookie. Сервер честно копирует идентификатор зонда, и всё равно DNS, NBNS и SNMP молчат, CoAP и memcached
/// пишут ` IP-MISMATCH`, ISAKMP уходит в сырой баннер. Со встроенными нагрузками тот же ответчик даёт совпадение.
#[test]
fn user_payload_cookie_semantics() {
    let ports = "U:53,U:137,U:161,U:500,U:5683,U:11211";
    let responder = || udp_responder(1, |f| echo_reply(dport(f), probe_payload(f)));
    // Баннеры каждой цели по порту источника ответа: восемь целей на порт.
    type Hosts = Vec<Vec<(u16, Vec<u8>)>>;
    let by_port = |outputs: &[Output]| {
        let mut m: std::collections::BTreeMap<u16, Hosts> = Default::default();
        for (r, banners) in grouped(outputs) {
            for b in &banners {
                assert_banner_of(&r, b);
            }
            m.entry(r.remote_port)
                .or_default()
                .push(banners.iter().map(|b| (b.app, b.payload.clone())).collect());
        }
        assert_eq!(m.len(), 6, "{m:?}");
        assert!(m.values().all(|hosts| hosts.len() == 8), "{m:?}");
        m
    };

    let user = plan_with(ports, 0, user_payloads());
    let (outputs, _, _) = run_outputs(&user, responder(), with_banners(false));
    let got = by_port(&outputs);
    for port in [53, 137, 161] {
        assert!(got[&port].iter().all(Vec::is_empty), "port {port}: {got:?}");
    }
    for h in &got[&500] {
        assert_eq!(h.len(), 1, "{h:?}");
        assert_eq!(h[0].0, app_id::NONE);
        assert_eq!(h[0].1, isakmp_response(b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22"));
    }
    for h in &got[&5683] {
        assert_eq!(
            h,
            &vec![
                (
                    app_id::COAP,
                    b"rsp=2.5(Content) text-plain IP-MISMATCH".to_vec()
                ),
                (app_id::NONE, vec![0x60, 0x45, 0x12, 0x34]),
            ]
        );
    }
    for h in &got[&11211] {
        assert_eq!(
            h,
            &vec![
                (
                    app_id::MEMCACHED,
                    b"uptime=12345 version=1.6.21  IP-MISMATCH".to_vec()
                ),
                (app_id::NONE, memcached_response(&[0x12, 0x34])),
            ]
        );
    }

    // Встроенные нагрузки (мутаторы `dns_set_cookie`, `snmp_set_cookie`, ...): тот же ответчик, cookie совпадает.
    let builtin = plan(ports);
    let (outputs, _, _) = run_outputs(&builtin, responder(), with_banners(false));
    let got = by_port(&outputs);
    let apps = |h: &[(u16, Vec<u8>)]| h.iter().map(|b| b.0).collect::<Vec<u16>>();
    for h in &got[&53] {
        assert_eq!(h, &vec![(app_id::DNS_VERSIONBIND, b"9.18.24".to_vec())]);
    }
    for h in &got[&137] {
        assert_eq!(apps(h), [app_id::NBTSTAT, app_id::NONE]);
        assert_eq!(h[0].1, b"HOST1          <00>\n52-52-52-52-52-52");
    }
    for h in &got[&161] {
        assert_eq!(apps(h), [app_id::SNMP, app_id::NONE]);
        assert_eq!(h[0].1, b"sysName:rmasscan");
    }
    for h in &got[&500] {
        assert_eq!(apps(h), [app_id::ISAKMP]);
    }
    for h in &got[&5683] {
        assert_eq!(apps(h), [app_id::COAP, app_id::NONE]);
        assert_eq!(h[0].1, b"rsp=2.5(Content) text-plain");
    }
    for h in &got[&11211] {
        assert_eq!(apps(h), [app_id::MEMCACHED, app_id::NONE]);
        assert_eq!(h[0].1, b"uptime=12345 version=1.6.21 ");
    }
}

/// TTL баннера равен TTL его записи статуса (`parsed->ip_ttl`, справка A0); время записи движок оставляет 0 у всех
/// баннеров, а время записи статуса и её баннеров ставит потребитель одно (CLI, тест
/// `timestamp_of_banner_equals_its_status` в `rmasscan-cli/tests/live_fake.rs`): у `Reply` времени нет.
#[test]
fn timestamp_of_banner_equals_its_status() {
    let p = plan("U:53");
    let (outputs, _, _) = run_outputs(
        &p,
        |f: &[u8]| {
            if !is_udp(f) {
                return vec![];
            }
            let q = probe_payload(f);
            let mut r = reply_to_udp(f, &dns_chaos([q[0], q[1]], b"9.18.24")).unwrap();
            // TTL ответа свой у каждой цели: 40 + последний октет; сумма IPv4 пересчитывается.
            r[22] = 40 + f[33];
            r[24..26].copy_from_slice(&[0, 0]);
            let mut sum = 0u32;
            for c in r[14..34].chunks(2) {
                sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            r[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
            vec![r]
        },
        with_banners(true),
    );
    let groups = grouped(&outputs);
    assert_eq!(groups.len(), 8);
    for (r, banners) in &groups {
        assert_eq!(u32::from(r.ttl), 40 + (r.remote_ip & 0xff));
        assert_eq!(banners.len(), 2);
        for b in banners {
            assert_eq!((b.ttl, b.timestamp), (r.ttl, 0));
        }
    }
}

/// Р5: нагрузка каждой записи не длиннее `MAX_BANNER_BYTES`. Порт без парсера отдаёт 64 байта и всю датаграмму; у
/// датаграммы в 70 000 байт сырой баннер обрезается ровно до 65 536 (живой приём такую не пропустит, предел
/// страхует построитель).
#[test]
fn banner_payload_is_capped_at_max_banner_bytes() {
    let payload: Vec<u8> = (0..70_000u32).map(|i| i as u8).collect();
    let got = proto_parser(9999, 0, false, &payload);
    assert_eq!(got[1].1.len(), 70_000, "the parser itself does not cap");
    let options = BannerOptions {
        rawudp: false,
        udp_parser: |_, _, _, px| vec![(0, px.repeat(2))],
    };
    let frame = reply_to_udp_frame(9999, &payload[..1000]);
    let r = udp_reply(9999);
    let got = udp_reply_banners(&options, &frame, LinkType::Ethernet, &r, SEED);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].payload.len(), 2000);
    let big = BannerOptions {
        rawudp: false,
        udp_parser: |_, _, _, _| vec![(0, vec![0x41; 70_000]), (1, vec![0x42; MAX_BANNER_BYTES])],
    };
    let got = udp_reply_banners(&big, &frame, LinkType::Ethernet, &r, SEED);
    assert_eq!(got[0].payload, vec![0x41; MAX_BANNER_BYTES]);
    assert_eq!(got[1].payload, vec![0x42; MAX_BANNER_BYTES]);
}

/// Зонд к `10.0.0.1:port` от нашего `IP_ME:40000` и ответ на него с нагрузкой `payload`.
fn reply_to_udp_frame(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut probe = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x08, 0x00,
    ];
    probe.extend([0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0]);
    probe.extend(IP_ME.to_be_bytes());
    probe.extend([10, 0, 0, 1]);
    probe.extend(40000u16.to_be_bytes());
    probe.extend(port.to_be_bytes());
    probe.extend([0, 8, 0, 0]);
    reply_to_udp(&probe, payload).unwrap()
}

fn udp_reply(port: u16) -> Reply {
    Reply {
        remote_ip: 0x0a00_0001,
        remote_port: port,
        local_ip: IP_ME,
        local_port: 40000,
        status: PortStatus::Open,
        tcp_flags: 0,
        ttl: 64,
        ip_proto: 17,
        mac: None,
        ip6: None,
    }
}

/// `assert(info->app_length < 2000)` (`src/proto-preprocess.c:174`) у C живой (в Makefile нет `-DNDEBUG`), но в приём
/// скана такая датаграмма не попадает ни у C, ни у нас: кадр длиннее 1514 байт отбрасывается до разбора
/// (`src/main.c:799`, `MAX_FRAME_LEN`). Ответ в 2000 байт нагрузки молча отброшен (ни записи, ни баннера, ни
/// падения), а самый длинный кадр (1514 байт, 1472 байта нагрузки) даёт запись и баннеры. Построитель и парсеры
/// принимают датаграмму любой длины: 4000 байт на каждом порту с парсером дают баннеры без паники.
#[test]
fn udp_reply_of_2000_bytes_is_dropped_like_c_and_parsers_take_any_length() {
    let p = plan("U:53,U:9999");
    let (outputs, _, outcome) = run_outputs(
        &p,
        udp_responder(1, |f| match dport(f) {
            53 => Some(vec![0x5a; 2000]),
            _ => Some(vec![0x5b; 1472]),
        }),
        with_banners(true),
    );
    let groups = grouped(&outputs);
    assert_eq!(groups.len(), 8, "only the 1514-byte frames: {outputs:?}");
    assert!(outcome.progress.discarded >= 8, "{outcome:?}");
    for (r, banners) in &groups {
        assert_eq!(r.remote_port, 9999);
        let apps: Vec<(u16, usize)> = banners.iter().map(|b| (b.app, b.payload.len())).collect();
        assert_eq!(apps, [(app_id::NONE, 64), (app_id::NONE, 1472)]);
    }

    let datagram: Vec<u8> = (0..4000u32).map(|i| (i * 7) as u8).collect();
    for port in [53, 123, 137, 161, 500, 5683, 11211, 16464, 9999] {
        let frame = reply_to_udp_frame(port, &datagram[..1472]);
        let r = udp_reply(port);
        let got = udp_reply_banners(&banner_options(true), &frame, LinkType::Ethernet, &r, SEED);
        assert_eq!(
            got.last().map(|b| (b.app, b.payload.len())),
            Some((app_id::NONE, 1472)),
            "port {port}"
        );
        let all = proto_parser(port, 0, true, &datagram);
        assert_eq!(
            all.last(),
            Some(&(app_id::NONE, datagram.clone())),
            "port {port}"
        );
    }
}

/// `--pcap-payloads` с датаграммой в 2000 байт: C проходит `preprocess_frame` захвата (`src/templ-payloads.c:743`) и
/// падает на `assert(app_length < 2000)` (`src/proto-preprocess.c:174`, SIGABRT); rmasscan такую нагрузку загружает
/// (предел 2006 байт, `MAX_PAYLOAD_LEN`).
#[test]
fn pcap_payload_of_2000_bytes_loads_where_c_aborts() {
    // Кадр UDP к порту 4000 с нагрузкой 2000 байт: ответ на ответ идёт обратно к порту 4000.
    let frame = reply_to_udp(&reply_to_udp_frame(4000, &[]), &[0x77; 2000]).unwrap();
    assert_eq!(u16::from_be_bytes([frame[36], frame[37]]), 4000);
    let mut pcap = Vec::new();
    pcap.extend(0xa1b2_c3d4u32.to_le_bytes());
    pcap.extend([2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    pcap.extend(65_535u32.to_le_bytes());
    pcap.extend(1u32.to_le_bytes());
    pcap.extend(1u32.to_le_bytes());
    pcap.extend(0u32.to_le_bytes());
    let len = u32::try_from(frame.len()).unwrap();
    pcap.extend(len.to_le_bytes());
    pcap.extend(len.to_le_bytes());
    pcap.extend(&frame);
    let mut t = PayloadTable::empty();
    assert_eq!(t.load_pcap_payloads(&pcap), Ok(1));
    assert_eq!(t.get(4000).unwrap().payload.len(), 2000);
}

/// Закрытый порт UDP (ICMP 3/3) и ответы не UDP баннеров не дают (`src/proto-icmp.c:194-204`, справка B9).
#[test]
fn icmp_port_unreachable_gives_no_banner() {
    let p = plan("U:59999");
    let (outputs, _, _) = run_outputs(
        &p,
        |f: &[u8]| port_unreachable_for(f, 0x0a00_00fe).into_iter().collect(),
        with_banners(true),
    );
    let groups = grouped(&outputs);
    assert_eq!(groups.len(), 8);
    assert!(
        groups
            .iter()
            .all(|(r, b)| r.status == PortStatus::Closed && b.is_empty())
    );
}

/// Ёмкость очереди считает и баннеры: ответ принимается, пока очередь не полна, и встаёт вместе со своими баннерами.
/// Потребитель не читает: при ёмкости 4 и двух баннерах на ответ принимаются два ответа (2 + 2 + 2 элемента, второй
/// ответ встал при трёх), третий уже не помещается, и запуск кончается `ConsumerTooSlow`, как без баннеров
/// (`backpressure.rs`); принятое остаётся для чтения, баннеры на своих местах.
#[test]
fn banners_count_toward_the_result_capacity() {
    let p = plan("U:53");
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    fake.set_responder(udp_responder(1, |f| {
        let q = probe_payload(f);
        Some(dns_chaos([q[0], q[1]], b"9.18.24"))
    }));
    let mut o = with_banners(true);
    o.result_capacity = 4;
    let h = start_manual(&p, &fake, &clock, o);
    wait_for("outcome", || h.outcome().is_some());
    let outputs = drain_outputs(&h);
    let outcome = h.join().unwrap();
    assert_eq!(
        outcome.reason,
        rmasscan_engine::Reason::Failed(rmasscan_engine::FailReason::ConsumerTooSlow)
    );
    assert_eq!(outcome.progress.received, 2);
    let groups = grouped(&outputs);
    assert_eq!(groups.len(), 2, "{outputs:?}");
    for (r, banners) in &groups {
        let apps: Vec<u16> = banners.iter().map(|b| b.app).collect();
        assert_eq!(apps, [app_id::DNS_VERSIONBIND, app_id::NONE], "{r:?}");
    }
}
