//! Сторона приёма стека TCP в движке (подэтап 4b, задача 4) на фиктивном адаптере и `ManualClock` (AGPL-3.0). Стек
//! здесь сценарный двойник [`Scripted`]: он пишет журнал того, что видел, и выдаёт сегменты и баннеры по сценарию.
//! Порядок приёма справки A1 (`src/main.c:753-1123`): таймеры, стек (`:962-1043`), затем статус и дедуп
//! (`:1048-1092`); сброс таблицы в конце (`tcpcon_destroy_table`, `:1111-1113`). Только офлайн, адреса `10.0.0.0/8`
//! общих тестов движка и `2001:db8::/32`.

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use common::*;
use rmasscan_core::banner::BannerRecord;
use rmasscan_core::checksum::{checksum_ipv4, ip_header_checksum};
use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{AdapterBinding, NicBinding, ReadyPlan};
use rmasscan_core::receive::{PortStatus, Reply};
use rmasscan_core::stack::{
    ConnAddrs, ConnKey, SegmentIn, SegmentOut, StackOutput, StackStats, TableParams, TcpStack,
    TcpStackFactory,
};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_core::throttle::Clock;
use rmasscan_engine::fake::{FakeAdapter, ManualClock, reply_to_syn, reply_to_syn6, reply_to_udp};
use rmasscan_engine::{
    BannerOptions, CancelHandle, Engine, EngineHandle, EngineOptions, Event, FailReason, Outcome,
    Output, Reason, STACK_OUT_CAP, StackSummary, TcpStackOptions,
};

fn lk<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ------------------------------------------------------------ двойник ---

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const FIN: u8 = 0x01;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;

/// Номер приложения записи `i` соединения у двойника (порядок записей набора).
const APP_BASE: u16 = 100;

/// Сценарий двойника.
#[derive(Clone, Debug, Default)]
struct Script {
    /// SYN-ACK без соединения создаёт соединение; `false`: таблица «полна», статус всё равно пишется.
    create: bool,
    /// Сколько ACK выдать на новый SYN-ACK и длина их нагрузки.
    acks: usize,
    ack_payload: usize,
    /// Длины нагрузки записей соединения при сбросе (запись `i` с приложением `APP_BASE + i`). Пусто: одна запись
    /// с байтами сервера (нагрузка сегментов соединения).
    records: Vec<usize>,
    /// FIN сервера закрывает соединение и сбрасывает его записи во время скана.
    close_on_fin: bool,
    /// Жизнь соединения на тике: `now > created + life` закрывает и сбрасывает (`src/stack-tcp-core.c:1970-1980`).
    lifetime_micros: Option<u64>,
}

#[derive(Clone, Debug)]
struct Seen {
    key: ConnKey,
    flags: u8,
    ttl: u8,
    payload: Vec<u8>,
}

/// Журнал одной таблицы.
#[derive(Debug, Default)]
struct Log {
    ticks: Vec<u64>,
    segs: Vec<Seen>,
    finish_calls: usize,
    /// Тиков к первому `finish`.
    ticks_at_finish: Option<usize>,
    closed_by_fin: usize,
    closed_by_lifetime: usize,
    flushed_by_finish: usize,
}

struct Conn {
    key: ConnKey,
    created: u64,
    ttl: u8,
    received: Vec<u8>,
}

struct Scripted {
    script: Script,
    params: TableParams,
    log: Arc<Mutex<Log>>,
    conns: Vec<Conn>,
    stats: StackStats,
}

fn remote_ip(key: &ConnKey) -> IpAddr {
    match key.addrs {
        ConnAddrs::V4 { remote, .. } => IpAddr::V4(Ipv4Addr::from(remote)),
        ConnAddrs::V6 { remote, .. } => IpAddr::V6(Ipv6Addr::from(remote)),
    }
}

impl Scripted {
    fn records(&self, c: &Conn) -> Vec<BannerRecord> {
        let rec = |i: usize, payload: Vec<u8>| BannerRecord {
            timestamp: 0,
            ip: remote_ip(&c.key),
            ip_proto: 6,
            port: c.key.remote_port,
            app: APP_BASE + i as u16,
            ttl: c.ttl,
            payload,
        };
        if self.script.records.is_empty() {
            return vec![rec(0, c.received.clone())];
        }
        self.script
            .records
            .iter()
            .enumerate()
            .map(|(i, &len)| rec(i, vec![b'a' + i as u8; len]))
            .collect()
    }

    fn sync_live(&mut self) {
        self.stats.tcbs_live = self.conns.len() as u64;
    }
}

impl TcpStack for Scripted {
    fn on_tick(&mut self, now: u64, out: &mut StackOutput) {
        lk(&self.log).ticks.push(now);
        let Some(life) = self.script.lifetime_micros else {
            return;
        };
        let mut i = 0;
        while i < self.conns.len() {
            if now > self.conns[i].created + life {
                let c = self.conns.remove(i);
                out.banners.push(self.records(&c));
                lk(&self.log).closed_by_lifetime += 1;
            } else {
                i += 1;
            }
        }
        self.sync_live();
    }

    fn on_segment(&mut self, now: u64, seg: &SegmentIn<'_>, out: &mut StackOutput) -> bool {
        lk(&self.log).segs.push(Seen {
            key: seg.key,
            flags: seg.flags,
            ttl: seg.ttl,
            payload: seg.payload.to_vec(),
        });
        let pos = self.conns.iter().position(|c| c.key == seg.key);
        if seg.flags & (SYN | ACK) == SYN | ACK {
            if pos.is_some() {
                return true;
            }
            if !self.script.create || self.conns.len() >= self.params.capacity {
                self.stats.table_full += 1;
                return false;
            }
            self.conns.push(Conn {
                key: seg.key,
                created: now,
                ttl: seg.ttl,
                received: Vec::new(),
            });
            self.stats.tcbs_created += 1;
            self.sync_live();
            for _ in 0..self.script.acks {
                out.segments.push(SegmentOut {
                    key: seg.key,
                    seq: seg.ack,
                    ack: seg.seq.wrapping_add(1),
                    flags: ACK,
                    payload: vec![0; self.script.ack_payload],
                    window: None,
                });
            }
            return true;
        }
        let Some(i) = pos else {
            return false;
        };
        self.conns[i].received.extend_from_slice(seg.payload);
        if seg.flags & FIN != 0 && self.script.close_on_fin {
            let c = self.conns.remove(i);
            out.banners.push(self.records(&c));
            lk(&self.log).closed_by_fin += 1;
            self.sync_live();
        }
        true
    }

    fn finish(&mut self, max_connections: usize, out: &mut StackOutput) -> bool {
        {
            let mut log = lk(&self.log);
            log.finish_calls += 1;
            if log.ticks_at_finish.is_none() {
                log.ticks_at_finish = Some(log.ticks.len());
            }
        }
        let n = max_connections.min(self.conns.len());
        let gone: Vec<Conn> = self.conns.drain(..n).collect();
        for c in &gone {
            out.banners.push(self.records(c));
        }
        lk(&self.log).flushed_by_finish += n;
        self.sync_live();
        !self.conns.is_empty()
    }

    fn stats(&self) -> StackStats {
        self.stats
    }
}

/// Фабрика: каждая таблица со своим журналом, параметры таблиц запоминаются.
#[derive(Debug)]
struct ScriptedFactory {
    script: Script,
    tables: Mutex<Vec<(TableParams, Arc<Mutex<Log>>)>>,
}

impl ScriptedFactory {
    fn new(script: Script) -> Arc<Self> {
        Arc::new(ScriptedFactory {
            script,
            tables: Mutex::new(Vec::new()),
        })
    }

    fn log(&self, k: usize) -> Arc<Mutex<Log>> {
        lk(&self.tables)[k].1.clone()
    }

    fn params(&self) -> Vec<TableParams> {
        lk(&self.tables).iter().map(|(p, _)| *p).collect()
    }
}

impl TcpStackFactory for ScriptedFactory {
    fn new_table(&self, p: TableParams) -> Box<dyn TcpStack> {
        let log = Arc::new(Mutex::new(Log::default()));
        lk(&self.tables).push((p, log.clone()));
        Box::new(Scripted {
            script: self.script.clone(),
            params: p,
            log,
            conns: Vec::new(),
            stats: StackStats::default(),
        })
    }
}

// ------------------------------------------------------------- кадры ---

/// Наш IPv4 SYN (Ethernet).
fn is_tcp_syn(f: &[u8]) -> bool {
    f.len() >= 54 && f[12..14] == [0x08, 0x00] && f[23] == 6 && f[47] == SYN
}

fn is_udp(f: &[u8]) -> bool {
    f.len() >= 42 && f[12..14] == [0x08, 0x00] && f[23] == 17
}

fn syn_seq(syn: &[u8]) -> u32 {
    u32::from_be_bytes(syn[38..42].try_into().unwrap())
}

fn syn_target(syn: &[u8]) -> u32 {
    u32::from_be_bytes(syn[30..34].try_into().unwrap())
}

/// Сегмент от цели к нам в ответ на наш SYN (Ethernet/IPv4, верные суммы, TTL 64): флаги, ack и нагрузка любые.
fn from_target(syn: &[u8], flags: u8, ack: u32, payload: &[u8]) -> Vec<u8> {
    let (me, them) = (
        u32::from_be_bytes(syn[26..30].try_into().unwrap()),
        syn_target(syn),
    );
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&syn[36..38]);
    t[2..4].copy_from_slice(&syn[34..36]);
    t[4..8].copy_from_slice(&0x0bad_f00du32.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 5 << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&1024u16.to_be_bytes());
    t.extend_from_slice(payload);
    let sum = checksum_ipv4(them, me, 6, &t);
    t[16..18].copy_from_slice(&sum.to_be_bytes());
    let mut i = vec![0u8; 20];
    i[0] = 0x45;
    i[2..4].copy_from_slice(&(20 + t.len() as u16).to_be_bytes());
    i[8] = 64;
    i[9] = 6;
    i[12..16].copy_from_slice(&them.to_be_bytes());
    i[16..20].copy_from_slice(&me.to_be_bytes());
    let s = !ip_header_checksum(&i, 0, 20);
    i[10..12].copy_from_slice(&s.to_be_bytes());
    let mut f = Vec::new();
    f.extend_from_slice(&syn[6..12]);
    f.extend_from_slice(&syn[0..6]);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(&i);
    f.extend_from_slice(&t);
    f
}

/// Верный ack ответа на SYN (`cookie + 1`).
fn good_ack(syn: &[u8]) -> u32 {
    syn_seq(syn).wrapping_add(1)
}

/// Ответчик: на каждый наш SYN IPv4 кадры `reply(SYN)`; на остальное ничего.
fn tcp_server(
    reply: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
) -> impl FnMut(&[u8]) -> Vec<Vec<u8>> + Send + 'static {
    move |f: &[u8]| if is_tcp_syn(f) { reply(f) } else { vec![] }
}

fn synack(syn: &[u8]) -> Vec<u8> {
    reply_to_syn(syn, SYN | ACK).unwrap()
}

// ----------------------------------------------------------- запуск ---

fn nic(k: u8) -> NicBinding {
    NicBinding::from(AdapterBinding {
        interface_id: format!("fake{k}"),
        link_type: LinkType::Ethernet,
        source_ipv4: IP_ME + u32::from(k),
        source_mac: [0, 0x11, 0x22, 0x33, 0x44, 0x55 + k],
        next_hop_mac: [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        source_ports: (40000 + 100 * u16::from(k), 40000 + 100 * u16::from(k)),
    })
}

fn plan_n(targets: &str, ports: &str, wait_secs: u32, nics: u8) -> ReadyPlan {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), targets).unwrap();
    parse_ports(m.ports_mut(), ports).unwrap();
    let cfg = ScanConfig {
        targets: m,
        seed: SEED,
        max_rate: 1_000_000.0,
        wait_secs,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).unwrap();
    ReadyPlan::new_cli(eff, (0..nics).map(nic).collect()).unwrap()
}

fn plan_v4(targets: &str, ports: &str, wait_secs: u32) -> ReadyPlan {
    plan_n(targets, ports, wait_secs, 1)
}

fn stack_options(factory: &Arc<ScriptedFactory>) -> EngineOptions {
    let mut o = no_stall_opts();
    o.tcp_stack = Some(TcpStackOptions {
        factory: factory.clone(),
        table_capacity: 4096,
        banner_byte_budget: 1 << 20,
    });
    o
}

/// Все элементы `recv_output_timeout` до `Finished` включительно; `pause` между чтениями делает потребителя
/// медленным (на результат не влияет, ограничено 20 с).
fn drain_outputs(h: &EngineHandle, pause: Duration) -> Vec<Output> {
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
                if !pause.is_zero() {
                    std::thread::sleep(pause);
                }
            }
            Err(TryRecvError::Empty) => {
                assert!(t.elapsed() < Duration::from_secs(20), "no Finished: {v:?}");
            }
            Err(TryRecvError::Disconnected) => return v,
        }
    }
}

struct Run {
    outputs: Vec<Output>,
    outcome: Outcome,
    summary: StackSummary,
}

fn run(
    plan: &ReadyPlan,
    responder: impl FnMut(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
    options: EngineOptions,
) -> Run {
    run_paced(plan, responder, options, Duration::ZERO)
}

fn run_paced(
    plan: &ReadyPlan,
    responder: impl FnMut(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
    options: EngineOptions,
    pause: Duration,
) -> Run {
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    fake.set_responder(responder);
    let h = start_manual(plan, &fake, &clock, options);
    let outputs = drain_outputs(&h, pause);
    let summary = h.stack_stats();
    let outcome = h.join().unwrap();
    Run {
        outputs,
        outcome,
        summary,
    }
}

/// Записи статуса, баннеры ответов и баннеры соединений в порядке выдачи.
#[derive(Debug, Clone, PartialEq)]
enum Item {
    Status(Reply),
    Banner(BannerRecord),
    Conn(BannerRecord),
}

fn items(outputs: &[Output]) -> Vec<Item> {
    outputs
        .iter()
        .flat_map(|o| match o {
            Output::Event(Event::Results { replies }) => {
                replies.iter().copied().map(Item::Status).collect()
            }
            Output::Banner(b) => vec![Item::Banner(b.clone())],
            Output::ConnectionBanner(b) => vec![Item::Conn(b.clone())],
            Output::Event(_) => vec![],
        })
        .collect()
}

fn replies_of(outputs: &[Output]) -> Vec<Reply> {
    items(outputs)
        .into_iter()
        .filter_map(|i| match i {
            Item::Status(r) => Some(r),
            _ => None,
        })
        .collect()
}

fn conn_banners(outputs: &[Output]) -> Vec<BannerRecord> {
    items(outputs)
        .into_iter()
        .filter_map(|i| match i {
            Item::Conn(b) => Some(b),
            _ => None,
        })
        .collect()
}

fn ipv4(r: &Reply) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(r.remote_ip))
}

/// Каждый набор соединения стоит целиком: запись `APP_BASE + i` того же адреса и порта сразу за `APP_BASE + i - 1`.
fn assert_sets_whole(outputs: &[Output], per_set: usize) {
    let conns = conn_banners(outputs);
    assert_eq!(conns.len() % per_set, 0, "{conns:?}");
    for set in conns.chunks(per_set) {
        for (i, b) in set.iter().enumerate() {
            assert_eq!(
                (b.ip, b.port, b.app, b.ip_proto, b.timestamp),
                (set[0].ip, set[0].port, APP_BASE + i as u16, 6, 0),
                "{set:?}"
            );
        }
    }
}

fn ack_segments(log: &Log) -> Vec<Seen> {
    log.segs
        .iter()
        .filter(|s| s.flags & (SYN | ACK) == SYN | ACK)
        .cloned()
        .collect()
}

// ------------------------------------------------------------- тесты ---

/// SYN-ACK с плохим cookie (`ack != cookie + 1`): ни стек, ни запись статуса его не видят (`src/main.c:969-975`:
/// `LOG(2, "bad cookie")` и `continue` до статусного блока). Так и при живом соединении у двойника на том же
/// 4-кортеже: C делает `continue` до события TCB, и двойник, который взял бы такой SYN-ACK (`true`), его не получает, а
/// кадр считается выброшенным.
#[test]
fn bad_cookie_synack_changes_neither_stack_nor_status() {
    let plan = plan_v4("10.0.0.1", "80", 1);
    // Без соединения.
    let f = ScriptedFactory::new(Script {
        create: true,
        ..Script::default()
    });
    let r = run(
        &plan,
        tcp_server(|s| vec![from_target(s, SYN | ACK, good_ack(s).wrapping_add(1), b"")]),
        stack_options(&f),
    );
    assert_eq!(r.outcome.reason, Reason::Completed);
    assert!(replies_of(&r.outputs).is_empty(), "{:?}", r.outputs);
    assert!(lk(&f.log(0)).segs.is_empty(), "{:?}", lk(&f.log(0)).segs);
    assert_eq!(r.outcome.progress.discarded, 1);
    assert_eq!(r.summary.stack.tcbs_created, 0);

    // С живым соединением: верный SYN-ACK, затем тот же 4-кортеж с плохим cookie.
    let f = ScriptedFactory::new(Script {
        create: true,
        ..Script::default()
    });
    let r = run(
        &plan,
        tcp_server(|s| {
            vec![
                synack(s),
                from_target(s, SYN | ACK, good_ack(s).wrapping_sub(7), b""),
            ]
        }),
        stack_options(&f),
    );
    assert_eq!(r.outcome.reason, Reason::Completed);
    let log = f.log(0);
    let log = lk(&log);
    assert_eq!(log.segs.len(), 1, "{:?}", log.segs);
    assert_eq!(replies_of(&r.outputs).len(), 1);
    assert_eq!(
        r.outcome.progress.discarded, 1,
        "the bad SYN-ACK is discarded"
    );
    assert_eq!(r.outcome.progress.duplicates, 0);
    assert_eq!(r.summary.stack.tcbs_created, 1);
}

/// Стек стоит до дедупа (`src/main.c:962-1043` раньше `:1066`): повтор SYN-ACK стек видит, запись статуса одна.
#[test]
fn stack_sees_duplicate_synack_status_once() {
    let plan = plan_v4("10.0.0.1", "80", 1);
    let f = ScriptedFactory::new(Script {
        create: true,
        ..Script::default()
    });
    let r = run(
        &plan,
        tcp_server(|s| vec![synack(s), synack(s)]),
        stack_options(&f),
    );
    assert_eq!(r.outcome.reason, Reason::Completed);
    assert_eq!(ack_segments(&lk(&f.log(0))).len(), 2);
    assert_eq!(replies_of(&r.outputs).len(), 1);
    assert_eq!(r.outcome.progress.duplicates, 1);
    assert_eq!(r.outcome.progress.received, 1);
    assert_eq!(r.summary.stack.tcbs_created, 1);
}

/// SYN|ACK|RST с верным cookie: запись `closed` (RST перекрывает, `src/main.c:1048-1057`) и стек видит сегмент (C
/// создаёт TCB и для него, `:976-986`).
#[test]
fn synack_rst_with_good_cookie_reaches_stack_and_status() {
    let plan = plan_v4("10.0.0.1", "80", 1);
    let f = ScriptedFactory::new(Script {
        create: true,
        ..Script::default()
    });
    let r = run(
        &plan,
        tcp_server(|s| vec![reply_to_syn(s, SYN | ACK | RST).unwrap()]),
        stack_options(&f),
    );
    let replies = replies_of(&r.outputs);
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].status, PortStatus::Closed);
    let log = f.log(0);
    let log = lk(&log);
    assert_eq!(log.segs.len(), 1);
    assert_eq!(log.segs[0].flags, SYN | ACK | RST);
    assert_eq!(r.summary.stack.tcbs_created, 1);
}

/// Анти-цель «тихая потеря статуса»: таблица не создаёт соединений (полна), запись `open` всё равно в очереди.
#[test]
fn status_written_when_stack_table_full() {
    let plan = plan_v4("10.0.0.0/29", "80", 1);
    let f = ScriptedFactory::new(Script::default());
    let r = run(&plan, tcp_server(|s| vec![synack(s)]), stack_options(&f));
    assert_eq!(r.outcome.reason, Reason::Completed);
    let replies = replies_of(&r.outputs);
    assert_eq!(replies.len(), 8);
    assert!(replies.iter().all(|r| r.status == PortStatus::Open));
    assert_eq!(r.summary.stack.table_full, 8);
    assert_eq!(r.summary.stack.tcbs_created, 0);
    assert!(conn_banners(&r.outputs).is_empty());
}

/// Сегмент, который взял стек (данные и FIN соединения), в `Progress.discarded` не идёт; сегмент без соединения
/// (стек вернул `false`) идёт, как и без стека вовсе.
#[test]
fn stack_segments_not_counted_as_discarded() {
    let plan = plan_v4("10.0.0.1", "80", 1);
    let server = || {
        tcp_server(|s| {
            vec![
                // До SYN-ACK соединения нет: стек его не берёт.
                from_target(s, ACK | PSH, good_ack(s), b"early"),
                synack(s),
                from_target(s, ACK | PSH, good_ack(s), b"SSH-2.0-x\r\n"),
                from_target(s, ACK | FIN, good_ack(s), b""),
            ]
        })
    };
    let f = ScriptedFactory::new(Script {
        create: true,
        close_on_fin: true,
        ..Script::default()
    });
    let r = run(&plan, server(), stack_options(&f));
    assert_eq!(r.outcome.reason, Reason::Completed);
    assert_eq!(lk(&f.log(0)).segs.len(), 4);
    // Нагрузка кончается с IP-пакетом, без набивки Ethernet (`tcp_segment`).
    assert_eq!(lk(&f.log(0)).segs[2].payload, b"SSH-2.0-x\r\n");
    assert_eq!(r.outcome.progress.discarded, 1);
    assert_eq!(r.outcome.progress.received, 1);

    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    fake.set_responder(server());
    let h = start_manual(&plan, &fake, &clock, no_stall_opts());
    drain_outputs(&h, Duration::ZERO);
    let o = h.join().unwrap();
    assert_eq!(o.progress.discarded, 3, "without a stack: unchanged");
}

/// Таймеры стека идут на каждой итерации RX по часам движка, и без единого кадра (`src/main.c:777-787`): время тиков
/// это `ManualClock` (не часы ОС), не убывает и покрывает окно `--wait`.
#[test]
fn ticks_follow_engine_clock_on_idle_rx() {
    let plan = plan_v4("10.0.0.1", "80", 2);
    let f = ScriptedFactory::new(Script {
        create: true,
        ..Script::default()
    });
    let clock = ManualClock::new();
    let t0 = clock.now_micros();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    let h = start_manual(&plan, &fake, &clock, stack_options(&f));
    drain_outputs(&h, Duration::ZERO);
    let o = h.join().unwrap();
    let t1 = clock.now_micros();
    assert_eq!(o.reason, Reason::Completed);
    let log = f.log(0);
    let log = lk(&log);
    assert!(log.segs.is_empty());
    let ticks = &log.ticks;
    // 2 с ожидания по 50 мс на пустой приём.
    assert!(ticks.len() >= 40, "{}", ticks.len());
    assert!(ticks.windows(2).all(|w| w[0] <= w[1]), "{ticks:?}");
    assert!(ticks.iter().all(|&t| (t0..=t1).contains(&t)), "{ticks:?}");
    assert!(ticks.last().unwrap() - ticks[0] >= 2_000_000, "{ticks:?}");
    assert_eq!(
        log.ticks_at_finish,
        Some(ticks.len()),
        "finish after the last tick"
    );
}

/// Конец скана: живые соединения сбрасываются после `--wait` (`tcpcon_destroy_table`, `src/main.c:1111-1113`), их
/// баннеры идут после последнего `Results` и до `Finished`, время 0, TTL соединения.
#[test]
fn finish_flushes_conn_banners_after_wait() {
    let plan = plan_v4("10.0.0.0/29", "80", 1);
    let f = ScriptedFactory::new(Script {
        create: true,
        records: vec![5],
        ..Script::default()
    });
    let r = run(&plan, tcp_server(|s| vec![synack(s)]), stack_options(&f));
    assert_eq!(r.outcome.reason, Reason::Completed);
    let it = items(&r.outputs);
    let last_status = it
        .iter()
        .rposition(|i| matches!(i, Item::Status(_)))
        .unwrap();
    let first_conn = it.iter().position(|i| matches!(i, Item::Conn(_))).unwrap();
    assert!(first_conn > last_status, "{it:?}");
    assert!(matches!(
        r.outputs.last(),
        Some(Output::Event(Event::Finished { .. }))
    ));
    let mut conns: Vec<IpAddr> = conn_banners(&r.outputs).iter().map(|b| b.ip).collect();
    let mut opened: Vec<IpAddr> = replies_of(&r.outputs).iter().map(ipv4).collect();
    conns.sort();
    opened.sort();
    assert_eq!(conns, opened);
    for b in conn_banners(&r.outputs) {
        assert_eq!(
            (b.port, b.ttl, b.timestamp, &b.payload[..]),
            (80, 64, 0, &b"aaaaa"[..])
        );
    }
    let log = f.log(0);
    let log = lk(&log);
    assert_eq!(log.flushed_by_finish, 8);
    // Сброс после окна ожидания по часам движка.
    assert!(log.ticks.last().unwrap() - log.ticks[0] >= 1_000_000);
    assert_eq!(r.summary.stack.tcbs_live, 0);
}

/// Review Focus 1: живых соединений больше `result_capacity`, байтов больше `result_byte_capacity`, `finish` идёт
/// порциями по 64, потребитель читает медленно. Сброс ждёт места в очереди (`push_conn_banners_waiting`): все наборы
/// доставлены целиком, итог `Completed`, а не `Failed(ConsumerTooSlow)`.
#[test]
fn finish_flush_larger_than_queue_is_delivered_whole() {
    let plan = plan_v4("10.0.0.0/25", "80", 1);
    let f = ScriptedFactory::new(Script {
        create: true,
        records: vec![300, 300],
        ..Script::default()
    });
    let mut o = stack_options(&f);
    o.result_capacity = 200; // все 128 записей статуса помещаются, 256 баннеров нет
    o.result_byte_capacity = 700; // один набор (600 байт) за раз
    let r = run_paced(
        &plan,
        tcp_server(|s| vec![synack(s)]),
        o,
        Duration::from_micros(200),
    );
    assert_eq!(r.outcome.reason, Reason::Completed);
    assert_eq!(replies_of(&r.outputs).len(), 128);
    assert_eq!(conn_banners(&r.outputs).len(), 256);
    assert_sets_whole(&r.outputs, 2);
    let mut ips: Vec<IpAddr> = conn_banners(&r.outputs).iter().map(|b| b.ip).collect();
    ips.dedup();
    assert_eq!(ips.len(), 128);
    let log = f.log(0);
    assert_eq!(lk(&log).finish_calls, 2, "64 + 64");
}

/// Stop прерывает ожидающий сброс: RX выходит, итог `Stopped`, доставлено только то, что встало до остановки.
#[test]
fn finish_interrupted_by_stop() {
    let plan = plan_v4("10.0.0.0/27", "80", 1);
    let f = ScriptedFactory::new(Script {
        create: true,
        records: vec![300, 300],
        ..Script::default()
    });
    let mut o = stack_options(&f);
    o.result_capacity = 100;
    // Один набор, пока в очереди не больше 100 байт: после первой записи (300 байт осталось) второй набор ждёт.
    o.result_byte_capacity = 700;
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    fake.set_responder(tcp_server(|s| vec![synack(s)]));
    let h = start_manual(&plan, &fake, &clock, o);
    let mut got = Vec::new();
    let t = Instant::now();
    loop {
        match h.recv_output_timeout(Duration::from_millis(50)) {
            Ok(Output::ConnectionBanner(b)) => {
                got.push(Output::ConnectionBanner(b));
                break;
            }
            Ok(x) => got.push(x),
            Err(_) => assert!(t.elapsed() < Duration::from_secs(10), "{got:?}"),
        }
    }
    // Сброс стоит: второй набор не помещается, пока потребитель не читает (в очереди вторая запись первого набора).
    assert_eq!(lk(&f.log(0)).finish_calls, 1);
    assert!(h.outcome().is_none());
    h.stop();
    // RX бросает сброс сам, без чтения: Stop перепроверяется не реже раза в 50 мс. Потребитель читает только после
    // итога, иначе освобождённое место приняло бы следующий набор раньше, чем RX увидит Stop.
    let t = Instant::now();
    wait_for("RX gives up the flush on Stop", || h.outcome().is_some());
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    let rest = drain_outputs(&h, Duration::ZERO);
    let outcome = join_within(h, Duration::from_secs(5));
    assert_eq!(outcome.reason, Reason::Stopped);
    got.extend(rest);
    assert_eq!(replies_of(&got).len(), 32);
    assert_eq!(conn_banners(&got).len(), 2, "only the first set");
    assert_sets_whole(&got, 2);
}

/// Набор соединения во время скана встаёт целиком или не встаёт: не вместился по байтам → `ConsumerTooSlow`, и ни
/// одной записи этого набора в очереди.
#[test]
fn conn_banner_set_is_all_or_nothing() {
    let plan = plan_v4("10.0.0.0/30", "80", 1);
    let f = ScriptedFactory::new(Script {
        create: true,
        close_on_fin: true,
        records: vec![400, 400],
        ..Script::default()
    });
    let mut o = stack_options(&f);
    o.result_byte_capacity = 1000;
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    fake.set_responder(tcp_server(|s| {
        vec![synack(s), from_target(s, ACK | FIN, good_ack(s), b"")]
    }));
    let h = start_manual(&plan, &fake, &clock, o);
    // Потребитель не читает, пока скан не кончится: первый набор (800 байт) встаёт, второй нет.
    wait_for("outcome", || h.outcome().is_some());
    let outputs = drain_outputs(&h, Duration::ZERO);
    let outcome = h.join().unwrap();
    assert_eq!(outcome.reason, Reason::Failed(FailReason::ConsumerTooSlow));
    assert_eq!(conn_banners(&outputs).len(), 2, "{outputs:?}");
    assert_sets_whole(&outputs, 2);
    assert_eq!(lk(&f.log(0)).finish_calls, 0, "no flush after Failed");
}

/// Байты баннеров соединений занимают бюджет очереди и освобождаются при чтении: сброс ждёт, пока потребитель не
/// прочтёт предыдущий набор; набор больше бюджета встаёт в пустую очередь.
#[test]
fn conn_banners_count_in_byte_budget() {
    let plan = plan_v4("10.0.0.0/30", "80", 1);
    let f = ScriptedFactory::new(Script {
        create: true,
        records: vec![600],
        ..Script::default()
    });
    let mut o = stack_options(&f);
    o.result_byte_capacity = 500; // меньше любого набора: каждый встаёт только в пустую очередь
    let r = run(&plan, tcp_server(|s| vec![synack(s)]), o);
    assert_eq!(r.outcome.reason, Reason::Completed);
    assert_eq!(conn_banners(&r.outputs).len(), 4);
}

/// Потребитель только событий (`recv_event_timeout`, как Студия) баннеров соединений не видит, а пропуск
/// освобождает место: сброс, ждущий места, доходит до конца, итог `Completed`.
#[test]
fn events_consumer_never_sees_conn_banners() {
    let plan = plan_v4("10.0.0.0/28", "80", 1);
    let f = ScriptedFactory::new(Script {
        create: true,
        records: vec![300, 300],
        ..Script::default()
    });
    let mut o = stack_options(&f);
    o.result_byte_capacity = 700;
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    fake.set_responder(tcp_server(|s| vec![synack(s)]));
    let h = start_manual(&plan, &fake, &clock, o);
    let events = drain_to_finished(&h);
    let outcome = h.join().unwrap();
    assert_eq!(outcome.reason, Reason::Completed);
    assert_eq!(all_replies(&events).len(), 16);
    assert_eq!(lk(&f.log(0)).flushed_by_finish, 16);
}

/// `join` без чтения не висит на сбросе в конце: непрочитанные баннеры `join` и так отбрасывает.
#[test]
fn join_without_reading_does_not_block_on_the_end_flush() {
    let plan = plan_v4("10.0.0.0/28", "80", 1);
    let f = ScriptedFactory::new(Script {
        create: true,
        records: vec![300, 300],
        ..Script::default()
    });
    let mut o = stack_options(&f);
    o.result_byte_capacity = 700;
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    fake.set_responder(tcp_server(|s| vec![synack(s)]));
    let h = start_manual(&plan, &fake, &clock, o);
    let outcome = join_within(h, Duration::from_secs(10));
    assert_eq!(outcome.reason, Reason::Completed);
    assert_eq!(lk(&f.log(0)).flushed_by_finish, 16);
}

/// Очередь кадров стека (`STACK_OUT_CAP` = `BUFFER_COUNT - 1`, `src/stack-queue.c:105-124`) переполняется без ожидания
/// RX (Р7, у C RX ждёт свободный буфер, E1.12): лишний кадр выбрасывается и считается, скан идёт дальше.
#[test]
fn stack_queue_overflow_is_counted_not_blocking() {
    assert_eq!(STACK_OUT_CAP, 16_383);
    let plan = plan_v4("10.0.0.1", "80", 1);
    let f = ScriptedFactory::new(Script {
        create: true,
        acks: 20_000,
        ..Script::default()
    });
    let r = run(&plan, tcp_server(|s| vec![synack(s)]), stack_options(&f));
    assert_eq!(r.outcome.reason, Reason::Completed);
    assert_eq!(r.summary.frames_dropped, 20_000 - 16_383);
    assert_eq!(
        r.summary.frames_sent, 0,
        "TX sends stack frames from Task 5 on"
    );
    assert_eq!(replies_of(&r.outputs).len(), 1);
}

/// Кадр, который построитель не строит (длиннее буфера C, `src/templ-pkt.c:440-443`), в очередь не встаёт и
/// считается выброшенным.
#[test]
fn unbuildable_stack_frame_is_counted_dropped() {
    let plan = plan_v4("10.0.0.1", "80", 1);
    let f = ScriptedFactory::new(Script {
        create: true,
        acks: 3,
        ack_payload: 3000,
        ..Script::default()
    });
    let r = run(&plan, tcp_server(|s| vec![synack(s)]), stack_options(&f));
    assert_eq!(r.outcome.reason, Reason::Completed);
    assert_eq!(r.summary.frames_dropped, 3);
}

const ME6: u128 = 0xfd00_0000_0000_0000_0000_0000_0000_0063;

/// Сегмент IPv6 доходит до стека с адресами IPv6 и hop limit как TTL (справка A10, E1.9), кадр ACK строится (не
/// выбрасывается), баннер соединения несёт адрес IPv6.
#[test]
fn ipv6_segment_reaches_stack() {
    let mut m = MassIp::new();
    m.add_target_string("2001:db8::7").unwrap();
    parse_ports(m.ports_mut(), "80").unwrap();
    let cfg = ScanConfig {
        targets: m,
        seed: SEED,
        max_rate: 1_000_000.0,
        wait_secs: 1,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).unwrap();
    let mut n = nic(0);
    n.source_ipv6 = Some(ME6);
    n.next_hop_mac_ipv6 = Some([0x02, 0, 0, 0, 0, 0x20]);
    let plan = ReadyPlan::new_cli(eff, vec![n]).unwrap();
    let f = ScriptedFactory::new(Script {
        create: true,
        acks: 1,
        records: vec![4],
        ..Script::default()
    });
    let r = run(
        &plan,
        |syn: &[u8]| reply_to_syn6(syn, SYN | ACK).into_iter().collect(),
        stack_options(&f),
    );
    assert_eq!(r.outcome.reason, Reason::Completed);
    let them: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0007;
    let log = f.log(0);
    let log = lk(&log);
    assert_eq!(log.segs.len(), 1);
    assert_eq!(
        log.segs[0].key.addrs,
        ConnAddrs::V6 {
            local: ME6,
            remote: them
        }
    );
    assert_eq!(log.segs[0].ttl, 64);
    assert_eq!(r.summary.frames_dropped, 0, "the IPv6 ACK frame is built");
    let replies = replies_of(&r.outputs);
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].ip6.map(|a| a.remote), Some(them));
    let conns = conn_banners(&r.outputs);
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].ip, IpAddr::V6(Ipv6Addr::from(them)));
}

/// Review Focus 1: сервер держит соединение (баннер SSH, FIN нет), `--wait` 10 короче жизни 30 с. Соединение живо в
/// конце, его баннер с байтами сервера приходит из сброса таблицы, итог `Completed`. С `--wait` 40 то же соединение
/// закрывает тик жизни во время ожидания, и баннер приходит из него, а сбрасывать в конце нечего.
#[test]
fn keepalive_banner_flushed_at_end_of_wait() {
    let banner = b"SSH-2.0-OpenSSH_9.6\r\n";
    for (wait, by_finish) in [(10, true), (40, false)] {
        let plan = plan_v4("10.0.0.1", "22", wait);
        let f = ScriptedFactory::new(Script {
            create: true,
            lifetime_micros: Some(30_000_000),
            ..Script::default()
        });
        let r = run(
            &plan,
            tcp_server(move |s| vec![synack(s), from_target(s, ACK | PSH, good_ack(s), banner)]),
            stack_options(&f),
        );
        assert_eq!(r.outcome.reason, Reason::Completed, "wait {wait}");
        let conns = conn_banners(&r.outputs);
        assert_eq!(conns.len(), 1, "wait {wait}: {:?}", r.outputs);
        assert_eq!(
            (conns[0].port, &conns[0].payload[..]),
            (22, &banner[..]),
            "wait {wait}"
        );
        let log = f.log(0);
        let log = lk(&log);
        assert_eq!(
            (log.flushed_by_finish, log.closed_by_lifetime),
            if by_finish { (1, 0) } else { (0, 1) },
            "wait {wait}"
        );
        // Баннер после записи статуса своего соединения.
        let it = items(&r.outputs);
        let status = it
            .iter()
            .position(|i| matches!(i, Item::Status(_)))
            .unwrap();
        let conn = it.iter().position(|i| matches!(i, Item::Conn(_))).unwrap();
        assert!(status < conn, "{it:?}");
    }
}

/// Ответ DNS CHAOS TXT (`src/proto-dns.c`) на зонд version.bind: id из зонда.
fn dns_chaos(id: [u8; 2]) -> Vec<u8> {
    let text = b"9.18.24";
    let mut v = id.to_vec();
    v.extend([0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0]);
    v.extend(b"\x07version\x04bind\x00\x00\x10\x00\x03");
    v.extend([0xC0, 0x0C, 0x00, 0x10, 0x00, 0x03, 0, 0, 0, 0]);
    v.extend(((text.len() + 1) as u16).to_be_bytes());
    v.push(text.len() as u8);
    v.extend(text);
    v
}

/// Ответчик смешанного скана: на SYN порта 80 SYN-ACK и сразу FIN (стек закрывает соединение и сбрасывает баннер во
/// время скана), на зонд DNS ответ с баннером.
fn mixed_server(f: &[u8]) -> Vec<Vec<u8>> {
    if is_tcp_syn(f) {
        return vec![synack(f), from_target(f, ACK | FIN, good_ack(f), b"")];
    }
    if is_udp(f) && u16::from_be_bytes([f[36], f[37]]) == 53 {
        return vec![reply_to_udp(f, &dns_chaos([f[42], f[43]])).unwrap()];
    }
    vec![]
}

/// M1 ревью 4a: запись перед баннером ответа это его запись статуса или баннер того же адреса и порта.
fn assert_udp_adjacency(it: &[Item]) {
    for (i, item) in it.iter().enumerate() {
        let Item::Banner(b) = item else { continue };
        let ok = match i.checked_sub(1).map(|p| &it[p]) {
            Some(Item::Status(r)) => (ipv4(r), r.remote_port, r.ip_proto) == (b.ip, b.port, 17),
            Some(Item::Banner(p)) => (p.ip, p.port) == (b.ip, b.port),
            _ => false,
        };
        assert!(ok, "banner {i} detached from its status: {it:?}");
    }
}

/// Review Focus 2 (`-p80,U:53 --banners`): баннер UDP идёт сразу за своим статусом, баннеры соединений TCP приходят во
/// время скана и в конце, и эту смежность не рвут. Два адаптера: два RX-потока кладут в общую очередь одновременно.
#[test]
fn mixed_tcp_udp_banners_keep_udp_adjacency() {
    for nics in [1u8, 2] {
        let plan = plan_n("10.0.0.0/26", "80,U:53", 1, nics);
        let f = ScriptedFactory::new(Script {
            create: true,
            close_on_fin: true,
            records: vec![3, 3],
            ..Script::default()
        });
        let mut o = stack_options(&f);
        o.banners = Some(BannerOptions {
            rawudp: false,
            udp_parser: rmasscan_proto::udp_banner_parser,
        });
        let clock = ManualClock::new();
        let fakes: Vec<FakeAdapter> = (0..nics)
            .map(|_| {
                let fk = FakeAdapter::new().with_clock(clock.clone());
                fk.set_responder(mixed_server);
                fk
            })
            .collect();
        let c: Arc<dyn Clock + Send + Sync> = clock.clone();
        let h = Engine::start_cli_with_clock(
            plan.clone(),
            fakes.iter().map(FakeAdapter::pair).collect(),
            o,
            c,
            None,
        )
        .unwrap();
        let outputs = drain_outputs(&h, Duration::ZERO);
        let summary = h.stack_stats();
        let outcome = h.join().unwrap();
        assert_eq!(outcome.reason, Reason::Completed, "nics {nics}");
        let it = items(&outputs);
        assert_udp_adjacency(&it);
        assert_sets_whole(&outputs, 2);
        let replies = replies_of(&outputs);
        assert_eq!(replies.len(), 128, "nics {nics}");
        let udp_banners = it.iter().filter(|i| matches!(i, Item::Banner(_))).count();
        assert_eq!(udp_banners, 64, "nics {nics}");
        assert_eq!(conn_banners(&outputs).len(), 128, "nics {nics}");
        // Баннеры соединений встают и посреди скана, между записями статуса, а не только после них.
        let last_status = it
            .iter()
            .rposition(|i| matches!(i, Item::Status(_)))
            .unwrap();
        assert!(
            it[..last_status].iter().any(|i| matches!(i, Item::Conn(_))),
            "nics {nics}: {it:?}"
        );
        assert_eq!(summary.stack.tcbs_created, 64, "nics {nics}");
        assert_eq!(f.params().len(), usize::from(nics));
    }
}

/// Пауза: SYN встают, RX дорабатывает `--wait`, затем живые соединения сбрасываются, их баннеры до `CheckpointReady`
/// и `Finished`, итог `Paused` (справка A9, решение 21).
#[test]
fn pause_flushes_live_connections_after_wait() {
    let plan = plan_v4("10.0.0.0/29", "80", 2);
    let f = ScriptedFactory::new(Script {
        create: true,
        records: vec![2],
        ..Script::default()
    });
    let clock = ManualClock::new();
    let fake = FakeAdapter::new().with_clock(clock.clone());
    fake.set_responder(tcp_server(|s| vec![synack(s)]));
    let cell: Arc<OnceLock<CancelHandle>> = Arc::default();
    let c2 = cell.clone();
    let paused = Arc::new(AtomicBool::new(false));
    let p2 = paused.clone();
    fake.set_send_hook(move |sent| {
        if sent == 3 && !p2.swap(true, Ordering::SeqCst) {
            let c = loop {
                if let Some(c) = c2.get() {
                    break c;
                }
                std::thread::yield_now();
            };
            c.pause();
        }
    });
    let h = start_manual(&plan, &fake, &clock, stack_options(&f));
    cell.set(h.cancel_handle()).ok();
    let outputs = drain_outputs(&h, Duration::ZERO);
    let outcome = h.join().unwrap();
    assert_eq!(outcome.reason, Reason::Paused);
    let opened = replies_of(&outputs).len();
    assert_eq!(opened, fake.sent_count());
    assert!(opened < 8, "{opened}");
    assert_eq!(conn_banners(&outputs).len(), opened);
    let first_conn = outputs
        .iter()
        .position(|o| matches!(o, Output::ConnectionBanner(_)))
        .unwrap();
    let checkpoint = outputs
        .iter()
        .position(|o| matches!(o, Output::Event(Event::CheckpointReady { .. })))
        .unwrap();
    let last_results = outputs
        .iter()
        .rposition(|o| matches!(o, Output::Event(Event::Results { .. })))
        .unwrap();
    assert!(
        last_results < first_conn && first_conn < checkpoint,
        "{outputs:?}"
    );
    let log = f.log(0);
    let log = lk(&log);
    assert!(log.ticks.last().unwrap() - log.ticks[0] >= 2_000_000);
}

/// У каждого RX-потока своя таблица (`TableParams`: seed скана, ёмкость `max(1024, table_capacity / адаптеров)`,
/// бюджет `banner_byte_budget / адаптеров`), `stack_stats` суммирует их.
#[test]
fn each_rx_thread_has_its_own_table_and_stats_sum() {
    let plan = plan_n("10.0.0.0/29", "80", 1, 2);
    let f = ScriptedFactory::new(Script {
        create: true,
        records: vec![1],
        ..Script::default()
    });
    let mut o = stack_options(&f);
    o.tcp_stack = Some(TcpStackOptions {
        factory: f.clone(),
        table_capacity: 5000,
        banner_byte_budget: 1000,
    });
    let clock = ManualClock::new();
    let fakes: Vec<FakeAdapter> = (0..2)
        .map(|_| {
            let fk = FakeAdapter::new().with_clock(clock.clone());
            fk.set_responder(tcp_server(|s| vec![synack(s)]));
            fk
        })
        .collect();
    let c: Arc<dyn Clock + Send + Sync> = clock.clone();
    let h = Engine::start_cli_with_clock(
        plan.clone(),
        fakes.iter().map(FakeAdapter::pair).collect(),
        o,
        c,
        None,
    )
    .unwrap();
    let outputs = drain_outputs(&h, Duration::ZERO);
    let summary = h.stack_stats();
    assert_eq!(h.join().unwrap().reason, Reason::Completed);
    let params = f.params();
    assert_eq!(params.len(), 2);
    for p in &params {
        assert_eq!(
            (p.seed, p.capacity, p.banner_byte_budget),
            (SEED, 2500, 500)
        );
    }
    assert_eq!(summary.stack.tcbs_created, 8);
    for k in 0..2 {
        assert_eq!(lk(&f.log(k)).flushed_by_finish, 4, "table {k}");
        // Таблица адаптера видит только свои соединения.
        let local = IP_ME + k as u32;
        assert!(lk(&f.log(k)).segs.iter().all(|s| matches!(
            s.key.addrs,
            ConnAddrs::V4 { local: l, .. } if l == local
        )));
    }
    assert_eq!(conn_banners(&outputs).len(), 8);

    // Маленькая ёмкость поднимается до 1024.
    let f = ScriptedFactory::new(Script::default());
    let mut o = stack_options(&f);
    o.tcp_stack = Some(TcpStackOptions {
        factory: f.clone(),
        table_capacity: 10,
        banner_byte_budget: 10,
    });
    run(&plan_v4("10.0.0.1", "80", 0), |_: &[u8]| vec![], o);
    assert_eq!(
        f.params()
            .iter()
            .map(|p| (p.capacity, p.banner_byte_budget))
            .collect::<Vec<_>>(),
        [(1024, 10)]
    );
}

/// Без стека (`tcp_stack: None`, по умолчанию и у Студии) сводка нулевая.
#[test]
fn no_stack_gives_zero_summary() {
    let plan = plan_v4("10.0.0.0/30", "80", 1);
    let r = run(&plan, tcp_server(|s| vec![synack(s)]), no_stall_opts());
    assert_eq!(r.outcome.reason, Reason::Completed);
    assert_eq!(r.summary, StackSummary::default());
    assert!(no_stall_opts().tcp_stack.is_none());
}
