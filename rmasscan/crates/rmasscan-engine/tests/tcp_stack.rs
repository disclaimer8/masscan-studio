//! Сторона приёма стека TCP в движке (подэтап 4b, задача 4) на фиктивном адаптере и `ManualClock` (AGPL-3.0). Стек
//! здесь сценарный двойник [`Scripted`]: он пишет журнал того, что видел, и выдаёт сегменты и баннеры по сценарию.
//! Порядок приёма справки A1 (`src/main.c:753-1123`): таймеры, стек (`:962-1043`), затем статус и дедуп
//! (`:1048-1092`); сброс таблицы в конце (`tcpcon_destroy_table`, `:1111-1113`). Только офлайн, адреса `10.0.0.0/8`
//! общих тестов движка и `2001:db8::/32`.

mod common;

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
use rmasscan_core::tcp_frame::{TcpFrameBuilder, stateless_rst};
use rmasscan_core::throttle::{Clock, Throttler};
use rmasscan_engine::fake::{
    FakeAdapter, ManualClock, TxStep, port_unreachable_for, reply_to_syn, reply_to_syn6,
    reply_to_udp,
};
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
    /// `finish` отвечает «ещё есть», ничего не выдавая и не уничтожая (нарушение контракта).
    stall_finish: bool,
}

#[derive(Clone, Debug)]
struct Seen {
    key: ConnKey,
    flags: u8,
    ttl: u8,
    payload: Vec<u8>,
    /// Сколько тиков было до этого сегмента: тик с большим номером идёт на следующей итерации RX, то есть после
    /// выдачи этого сегмента в очередь кадров адаптера.
    tick: usize,
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
        {
            let mut log = lk(&self.log);
            let tick = log.ticks.len();
            log.segs.push(Seen {
                key: seg.key,
                flags: seg.flags,
                ttl: seg.ttl,
                payload: seg.payload.to_vec(),
                tick,
            });
        }
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
        if self.script.stall_finish {
            return true;
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
    plan_full(targets, ports, wait_secs, nics, 1_000_000.0, 0)
}

fn plan_full(
    targets: &str,
    ports: &str,
    wait_secs: u32,
    nics: u8,
    max_rate: f64,
    retries: u32,
) -> ReadyPlan {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), targets).unwrap();
    parse_ports(m.ports_mut(), ports).unwrap();
    let cfg = ScanConfig {
        targets: m,
        seed: SEED,
        max_rate,
        retries,
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

/// Прогон на фиктивном адаптере без часов: `ManualClock` двигает только сон throttle TX, поэтому окно `--wait` стоит,
/// пока тест не сдвинет часы сам. Тест ждёт `settled` (например, TX отправил кадры стека), затем шагами по 60 с
/// доводит RX до конца окна и читает всё до `Finished`. Так TX, который дожёвывает очередь кадров (задача 5), не
/// соревнуется с концом RX: на фиктивном адаптере с часами пустой приём RX двигает окно наперегонки с отправкой.
fn run_settled(
    plan: &ReadyPlan,
    responder: impl FnMut(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
    options: EngineOptions,
    settled: impl Fn(&EngineHandle, &FakeAdapter) -> bool,
) -> (Run, FakeAdapter) {
    let clock = ManualClock::new();
    let fake = FakeAdapter::new();
    fake.set_responder(responder);
    let h = start_manual(plan, &fake, &clock, options);
    wait_for("settled", || settled(&h, &fake));
    advance_until(&clock, Duration::from_secs(60), "outcome", || {
        h.outcome().is_some()
    });
    let outputs = drain_outputs(&h, Duration::ZERO);
    let summary = h.stack_stats();
    let outcome = h.join().unwrap();
    (
        Run {
            outputs,
            outcome,
            summary,
        },
        fake,
    )
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

/// То же с пределом по числу записей: байтов вдоволь, а набор из 60 записей при `result_capacity = 100` не встаёт
/// рядом с предыдущим. Сброс ждёт места из-за записей, все наборы доставлены целиком, итог `Completed`.
#[test]
fn finish_flush_waits_on_entry_capacity() {
    let plan = plan_v4("10.0.0.0/29", "80", 1);
    let f = ScriptedFactory::new(Script {
        create: true,
        records: vec![10; 60],
        ..Script::default()
    });
    let mut o = stack_options(&f);
    o.result_capacity = 100; // 8 записей статуса и один набор (60), второй набор ждёт
    o.result_byte_capacity = 1 << 20;
    let r = run_paced(
        &plan,
        tcp_server(|s| vec![synack(s)]),
        o,
        Duration::from_micros(200),
    );
    assert_eq!(r.outcome.reason, Reason::Completed);
    assert_eq!(replies_of(&r.outputs).len(), 8);
    assert_eq!(conn_banners(&r.outputs).len(), 8 * 60);
    assert_sets_whole(&r.outputs, 60);
    assert_eq!(r.summary.flush_abandoned, 0);
}

/// Таблица отвечает на `finish` «ещё есть» без продвижения: сброс не крутится вечно и не молчит. Брошенные
/// соединения посчитаны в `flush_abandoned`, итог `Completed`.
#[test]
fn finish_without_progress_is_counted_not_silent() {
    let plan = plan_v4("10.0.0.0/29", "80", 1);
    let f = ScriptedFactory::new(Script {
        create: true,
        stall_finish: true,
        ..Script::default()
    });
    let r = run(&plan, tcp_server(|s| vec![synack(s)]), stack_options(&f));
    assert_eq!(r.outcome.reason, Reason::Completed);
    assert_eq!(replies_of(&r.outputs).len(), 8);
    assert!(conn_banners(&r.outputs).is_empty());
    assert_eq!(r.summary.flush_abandoned, 8);
    assert_eq!(r.summary.stack.tcbs_live, 8);
    assert_eq!(lk(&f.log(0)).finish_calls, 1);
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
/// RX (Р7, у C RX ждёт свободный буфер, E1.12): лишний кадр выбрасывается и считается, скан идёт дальше. Вставшие
/// кадры TX отправляет после зонда (задача 5). Окно `--wait` длинное: на `ManualClock` сон throttle при 16 383 кадрах
/// сдвигает часы на секунды, а часы общие с окном RX.
#[test]
fn stack_queue_overflow_is_counted_not_blocking() {
    assert_eq!(STACK_OUT_CAP, 16_383);
    let plan = plan_v4("10.0.0.1", "80", 3600);
    let f = ScriptedFactory::new(Script {
        create: true,
        acks: 20_000,
        ..Script::default()
    });
    let (r, fake) = run_settled(
        &plan,
        tcp_server(|s| vec![synack(s)]),
        stack_options(&f),
        |h, _| h.stack_stats().frames_sent == 16_383,
    );
    assert_eq!(r.outcome.reason, Reason::Completed);
    assert_eq!(r.summary.frames_dropped, 20_000 - 16_383);
    assert_eq!(r.summary.frames_sent, 16_383);
    assert_eq!(fake.sent_count(), 1 + 16_383);
    assert_eq!(
        r.outcome.progress.sent, 1,
        "Progress.sent counts probes only"
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
    let (r, fake) = run_settled(
        &plan,
        |syn: &[u8]| reply_to_syn6(syn, SYN | ACK).into_iter().collect(),
        stack_options(&f),
        |h, _| h.stack_stats().frames_sent == 1,
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
    assert_eq!(r.summary.frames_sent, 1);
    // SYN IPv6, затем ACK стека IPv6 (`ethertype` 0x86dd, флаги ACK).
    let sent = fake.sent_frames();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1][12..14], [0x86, 0xdd]);
    assert_eq!(sent[1][14 + 40 + 13], ACK);
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

// ---------------------------------------------------- сторона передачи ---
//
// Задача 5. Кадры стека и RST без состояния отправляет TX своего адаптера: в каждой пачке throttle сначала кадры из
// очереди адаптера, остаток пачки SYN (`src/main.c:282-299`, `stack_flush_packets` `src/stack-queue.c:46-96`), каждый
// кадр в счёт `--rate`; после последнего зонда TX дожёвывает очередь под тем же throttle, пока не кончится RX
// (`src/main.c:470-494`). Прогоны идут на фиктивном адаптере без часов: `ManualClock` двигает только сон throttle, и
// окно `--wait` стоит, пока тест не сдвинет часы сам.

/// Флаги TCP кадра Ethernet/IPv4 без опций IP.
fn tcp_flags(f: &[u8]) -> u8 {
    f[47]
}

fn dst_ip(f: &[u8]) -> u32 {
    u32::from_be_bytes(f[30..34].try_into().unwrap())
}

/// Синхронизация TX с RX (только для порядка в тестах): ответчик даёт SYN-ACK на каждый SYN и считает их, хук
/// отправки (поток TX, после каждого кадра, принятого адаптером) пишет время отправки по `ManualClock` и ждёт, пока
/// таблица не увидит столько же SYN-ACK и не получит тик после последнего из них. Тик идёт на следующей итерации RX,
/// после выдачи кадров этого сегмента в очередь адаптера, поэтому к возврату хука кадры стека на каждый отправленный
/// SYN уже стоят в очереди. Затем хук зовёт `after(число отправленных)`. Ожидание ограничено 10 с: чего не хватило,
/// покажут проверки теста. Возвращает время каждого отправленного кадра, по порядку отправки.
fn sync_tx_to_rx(
    fake: &FakeAdapter,
    f: &Arc<ScriptedFactory>,
    clock: &Arc<ManualClock>,
    after: impl Fn(usize) + Send + Sync + 'static,
) -> Arc<Mutex<Vec<u64>>> {
    let syns = Arc::new(AtomicUsize::new(0));
    let s2 = syns.clone();
    fake.set_responder(move |frame: &[u8]| {
        if is_tcp_syn(frame) {
            s2.fetch_add(1, Ordering::SeqCst);
            vec![synack(frame)]
        } else {
            vec![]
        }
    });
    let times = Arc::new(Mutex::new(Vec::new()));
    let (t2, f2, c2) = (times.clone(), f.clone(), clock.clone());
    fake.set_send_hook(move |sent| {
        lk(&t2).push(c2.now_micros());
        let want = syns.load(Ordering::SeqCst);
        let t = Instant::now();
        while !synacks_delivered(&f2, want) && t.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_micros(20));
        }
        after(sent);
    });
    times
}

/// Таблица 0 видела `want` SYN-ACK, и после последнего был тик.
fn synacks_delivered(f: &ScriptedFactory, want: usize) -> bool {
    let tables = lk(&f.tables);
    let Some((_, log)) = tables.first() else {
        return want == 0;
    };
    let log = lk(log);
    let seen: Vec<usize> = log
        .segs
        .iter()
        .filter(|s| s.flags & (SYN | ACK) == SYN | ACK)
        .map(|s| s.tick)
        .collect();
    seen.len() >= want && seen.last().is_none_or(|&t| log.ticks.len() > t)
}

/// Кадры на проводе по порядку, каждый со временем отправки по часам движка.
type Timed = Vec<(Wire, u64)>;

/// Кадр на проводе: SYN зонда `j` или кадр стека в ответ на SYN-ACK зонда `j`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wire {
    Syn(usize),
    Stack(usize),
}

/// Модель TX для прогона под [`sync_tx_to_rx`], где на каждый новый SYN-ACK стек выдаёт `acks` кадров и они стоят в
/// очереди к следующей пачке. Каждая пачка throttle сначала берёт кадры стека (каждый занимает место в пачке и идёт в
/// счёт throttle, `src/stack-queue.c:56`, `:93`), остаток идёт SYN (`src/main.c:289-299`); после последнего зонда очередь
/// дожёвывается тем же throttle (`:470-494`). Часы движка двигает только сон throttle, поэтому модель на своём
/// `ManualClock` с тем же началом повторяет движок точно. Выдаёт кадры с временем отправки и пачки `(стека, SYN)`.
fn model_tx(rate: f64, probes: usize, acks: usize) -> (Timed, Vec<(usize, usize)>) {
    let clock = ManualClock::new();
    let mut thr = Throttler::start(rate, &*clock);
    let mut queue: VecDeque<usize> = VecDeque::new();
    let (mut next, mut sent) = (0usize, 0u64);
    let (mut wire, mut batches) = (Vec::new(), Vec::new());
    while next < probes || !queue.is_empty() {
        let b = thr.next_batch(sent, &*clock) as usize;
        let now = clock.now_micros();
        let stack = b.min(queue.len());
        for _ in 0..stack {
            wire.push((Wire::Stack(queue.pop_front().unwrap()), now));
        }
        let syns = (b - stack).min(probes - next);
        for j in next..next + syns {
            wire.push((Wire::Syn(j), now));
            queue.extend(std::iter::repeat_n(j, acks));
        }
        next += syns;
        sent += (stack + syns) as u64;
        batches.push((stack, syns));
    }
    (wire, batches)
}

/// Прогон под [`sync_tx_to_rx`] на адаптере без часов: все `probes * (1 + acks)` кадров ушли, затем окно `--wait`
/// доводится до конца. Кадры на проводе с временем отправки и итог.
fn run_synced(plan: &ReadyPlan, acks: usize) -> (Timed, Run) {
    let f = ScriptedFactory::new(Script {
        create: true,
        acks,
        ..Script::default()
    });
    let clock = ManualClock::new();
    let fake = FakeAdapter::new();
    let times = sync_tx_to_rx(&fake, &f, &clock, |_| {});
    let h = start_manual(plan, &fake, &clock, stack_options(&f));
    let probes = plan.range() as usize;
    let total = probes * (1 + acks);
    let t = Instant::now();
    while fake.sent_count() < total {
        assert!(
            t.elapsed() < Duration::from_secs(20),
            "{} of {total} frames sent",
            fake.sent_count()
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    advance_until(&clock, Duration::from_secs(60), "outcome", || {
        h.outcome().is_some()
    });
    let outputs = drain_outputs(&h, Duration::ZERO);
    let summary = h.stack_stats();
    let outcome = h.join().unwrap();
    let reference = reference_frames(plan, probes);
    let syn_of = |ip: u32| reference.iter().position(|s| syn_target(s) == ip).unwrap();
    let times = lk(&times).clone();
    let sent = fake.sent_frames();
    assert_eq!(sent.len(), times.len());
    let wire = sent
        .iter()
        .zip(times)
        .map(|(fr, at)| match tcp_flags(fr) {
            SYN => {
                let j = syn_of(dst_ip(fr));
                assert_eq!(fr, &reference[j]);
                (Wire::Syn(j), at)
            }
            ACK => (Wire::Stack(syn_of(dst_ip(fr))), at),
            x => panic!("unexpected flags {x:#x}"),
        })
        .collect();
    (
        wire,
        Run {
            outputs,
            outcome,
            summary,
        },
    )
}

/// Каждая пачка throttle сначала берёт кадры стека, остаток пачки идёт SYN (`src/main.c:289-299`: «This takes
/// priority over sending SYN packets»), и кадр стека занимает в пачке место SYN. На малой пачке (1 кадр) SYN
/// следующего зонда ждёт, пока не уйдут все кадры стека ответа на предыдущий; на /23 throttle растит пачку, и в
/// одной пачке едут и кадры стека, и SYN. Порядок и время каждого кадра совпадают с моделью [`model_tx`].
#[test]
fn stack_frames_go_before_syns_in_the_same_batch() {
    for (targets, acks) in [("10.0.0.0/29", 3), ("10.0.0.0/23", 1)] {
        let plan = plan_full(targets, "80", 60, 1, 1_000_000.0, 0);
        let probes = plan.range() as usize;
        let (wire, r) = run_synced(&plan, acks);
        assert_eq!(r.outcome.reason, Reason::Completed, "{targets}");
        let (model, batches) = model_tx(1_000_000.0, probes, acks);
        assert_eq!(wire, model, "{targets}");
        if probes == 8 {
            // Пачка всегда 1: SYN j, затем `acks` кадров стека его ответа, затем SYN j + 1.
            let order: Vec<Wire> = (0..probes)
                .flat_map(|j| std::iter::once(Wire::Syn(j)).chain(vec![Wire::Stack(j); acks]))
                .collect();
            assert_eq!(wire.iter().map(|w| w.0).collect::<Vec<_>>(), order);
        } else {
            assert!(
                batches.iter().any(|&(s, y)| s > 0 && y > 0),
                "no batch carried both: {batches:?}"
            );
        }
        assert_eq!(r.summary.frames_sent, (probes * acks) as u64);
        assert_eq!(r.summary.frames_dropped, 0);
        assert_eq!(r.outcome.progress.sent, probes as u64);
    }
}

/// `--rate` несёт кадры стека вместе с SYN (справка A8, `src/stack-queue.c:93`: `(*packets_sent)++` на каждый кадр
/// очереди): N кадров стека и M зондов на скорости R занимают (N + M) / R по часам движка, ровно столько же, сколько
/// N + M одних зондов (throttle их не различает). Одни зонды заняли бы M / R, и кадры стека без счёта ушли бы в тех
/// же пачках. Последние кадры стека уходят уже после зондов, под тем же throttle. `Progress.sent` считает только
/// зонды.
#[test]
fn stack_frames_count_against_rate() {
    let rate = 100.0;
    let acks = 4;
    let plan = plan_full("10.0.0.0/29", "80", 60, 1, rate, 0);
    let probes = plan.range() as usize;
    let t0 = ManualClock::new().now_micros();
    let (wire, r) = run_synced(&plan, acks);
    assert_eq!(r.outcome.reason, Reason::Completed);
    let (model, _) = model_tx(rate, probes, acks);
    assert_eq!(wire, model);
    let frames = probes * (1 + acks);
    let last = wire.last().unwrap().1;
    // Тот же throttle на N + M одних зондах.
    let (probes_only, _) = model_tx(rate, frames, 0);
    assert_eq!(last, probes_only.last().unwrap().1);
    // Точность самого throttle на этих часах: 40 зондов на 100/с уходят за 0,46 с (порт C, `src/main-throttle.c`).
    let span = (last - t0) as f64 / 1e6;
    let expected = frames as f64 / rate;
    assert!(
        (0.9 * expected..=1.2 * expected).contains(&span),
        "{frames} frames at {rate}/s took {span} s, expected {expected} s"
    );
    // Последний SYN ушёл после кадров стека всех ответов, кроме своего: позже, чем M / R.
    let last_syn = wire
        .iter()
        .rev()
        .find(|w| matches!(w.0, Wire::Syn(_)))
        .unwrap();
    assert!(
        (last_syn.1 - t0) as f64 / 1e6 > 2.0 * probes as f64 / rate,
        "{wire:?}"
    );
    assert_eq!(r.summary.frames_sent, (probes * acks) as u64);
    assert_eq!(r.outcome.progress.sent, probes as u64);
}

/// После последнего зонда TX дожёвывает очередь кадров стека, пока не кончится RX (`src/main.c:470-494`). SYN-ACK,
/// пришедший за 1 с до конца окна `--wait` 10 с (часы движка), получает свои кадры стека; итог `Completed`, ничего не
/// выброшено. Без linger TX ушёл бы сразу после зонда, и кадры остались бы в очереди.
#[test]
fn tx_lingers_for_stack_frames_until_rx_ends() {
    let plan = plan_v4("10.0.0.1", "80", 10);
    let f = ScriptedFactory::new(Script {
        create: true,
        acks: 3,
        records: vec![1],
        ..Script::default()
    });
    let clock = ManualClock::new();
    let fake = FakeAdapter::new();
    let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::default();
    let c2 = captured.clone();
    fake.set_responder(move |fr: &[u8]| {
        if is_tcp_syn(fr) {
            *lk(&c2) = Some(fr.to_vec());
        }
        vec![]
    });
    let h = start_manual(&plan, &fake, &clock, stack_options(&f));
    wait_for("the probe", || fake.sent_count() == 1);
    // Зонд один: после него у TX нет пачек, кадры ниже может отправить только linger. Срок окна RX отсчитан от
    // момента, когда RX увидел конец TX, то есть не раньше этих часов: SYN-ACK через 9 с ещё в окне 10 с.
    clock.advance(Duration::from_secs(9));
    let syn = lk(&captured).clone().unwrap();
    fake.push_frame(synack(&syn));
    wait_for("stack frames sent in the wait window", || {
        fake.sent_count() == 4
    });
    advance_until(&clock, Duration::from_secs(60), "outcome", || {
        h.outcome().is_some()
    });
    let outputs = drain_outputs(&h, Duration::ZERO);
    let summary = h.stack_stats();
    let outcome = h.join().unwrap();
    assert_eq!(outcome.reason, Reason::Completed);
    let sent = fake.sent_frames();
    assert!(is_tcp_syn(&sent[0]));
    assert!(
        sent[1..]
            .iter()
            .all(|fr| tcp_flags(fr) == ACK && dst_ip(fr) == 0x0a00_0001),
        "{sent:?}"
    );
    assert_eq!((summary.frames_sent, summary.frames_dropped), (3, 0));
    assert_eq!(outcome.progress.sent, 1);
    assert_eq!(replies_of(&outputs).len(), 1);
    assert_eq!(conn_banners(&outputs).len(), 1);
}

fn rst_options() -> EngineOptions {
    let mut o = opts();
    o.stateless_rst = true;
    o
}

/// RST без состояния на ответ (`stateless_rst`, справка A7), собранный построителем кадров адаптера.
fn expected_rst(plan: &ReadyPlan, r: &Reply) -> Option<Vec<u8>> {
    stateless_rst(r, SEED).map(|s| TcpFrameBuilder::from_plan(plan).build(&s))
}

/// Без стека и с `stateless_rst` за каждым свежим (прошедшим cookie и дедуп) ответом SYN-ACK и RST идёт один RST
/// (`src/main.c:1094-1100`, после `dedup_is_duplicate` `:1066-1068`), байты как у `stateless_rst`. Повтор ответа RST не
/// получает, ICMP Port Unreachable (`closed` без флагов TCP) тоже, цель без ответа тоже. Каждый RST в счёт
/// `frames_sent`, не в `Progress.sent`.
#[test]
fn stateless_rst_for_synack_and_rst_reply() {
    let plan = plan_v4("10.0.0.0/29", "80", 60);
    let responder = tcp_server(|s| {
        let rst = || reply_to_syn(s, RST | ACK).unwrap();
        match syn_target(s) & 7 {
            0 | 1 => vec![synack(s)],
            2 | 3 => vec![rst()],
            4 => vec![synack(s), synack(s)],
            5 => vec![port_unreachable_for(s, 0x0a00_00fe).unwrap()],
            6 => vec![rst(), rst()],
            _ => vec![],
        }
    });
    let (r, fake) = run_settled(&plan, responder, rst_options(), |h, fk| {
        let p = h.progress();
        p.received + p.duplicates == 9 && fk.sent_count() >= 8 + 6
    });
    assert_eq!(r.outcome.reason, Reason::Completed);
    let replies = replies_of(&r.outputs);
    assert_eq!(replies.len(), 7);
    let mut want: Vec<Vec<u8>> = replies
        .iter()
        .filter_map(|rp| expected_rst(&plan, rp))
        .collect();
    assert_eq!(want.len(), 6);
    let sent = fake.sent_frames();
    let mut rsts: Vec<Vec<u8>> = sent.iter().filter(|fr| !is_tcp_syn(fr)).cloned().collect();
    assert!(rsts.iter().all(|fr| tcp_flags(fr) == RST), "{rsts:?}");
    want.sort();
    rsts.sort();
    assert_eq!(rsts, want);
    // Ни RST цели с ICMP `closed` (.5) и без ответа (.7), по одному целям с повтором (.4, .6).
    let mut to: Vec<u32> = rsts.iter().map(|fr| dst_ip(fr) & 7).collect();
    to.sort();
    assert_eq!(to, [0, 1, 2, 3, 4, 6]);
    assert_eq!(sent.iter().filter(|fr| is_tcp_syn(fr)).count(), 8);
    assert_eq!((r.summary.frames_sent, r.summary.frames_dropped), (6, 0));
    assert_eq!(r.outcome.progress.sent, 8);
    assert_eq!(r.outcome.progress.duplicates, 2);
}

/// RST без состояния уходит и на SYN-ACK, пришедший в окне `--wait` после последнего зонда: TX ждёт конца RX и в
/// этом режиме (решение S3 предполётного ревью: linger при `ndp || tcp_stack || stateless_rst`).
#[test]
fn stateless_rst_sent_for_synack_in_wait_window() {
    let plan = plan_v4("10.0.0.1", "80", 10);
    let clock = ManualClock::new();
    let fake = FakeAdapter::new();
    let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::default();
    let c2 = captured.clone();
    fake.set_responder(move |fr: &[u8]| {
        if is_tcp_syn(fr) {
            *lk(&c2) = Some(fr.to_vec());
        }
        vec![]
    });
    let h = start_manual(&plan, &fake, &clock, rst_options());
    wait_for("the probe", || fake.sent_count() == 1);
    // Как в `tx_lingers_for_stack_frames_until_rx_ends`: RST может отправить только linger, SYN-ACK через 9 с ещё в
    // окне 10 с.
    clock.advance(Duration::from_secs(9));
    let syn = lk(&captured).clone().unwrap();
    fake.push_frame(synack(&syn));
    wait_for("RST sent in the wait window", || fake.sent_count() == 2);
    advance_until(&clock, Duration::from_secs(60), "outcome", || {
        h.outcome().is_some()
    });
    let outputs = drain_outputs(&h, Duration::ZERO);
    let summary = h.stack_stats();
    let outcome = h.join().unwrap();
    assert_eq!(outcome.reason, Reason::Completed);
    let replies = replies_of(&outputs);
    assert_eq!(replies.len(), 1);
    assert_eq!(
        fake.sent_frames()[1],
        expected_rst(&plan, &replies[0]).unwrap()
    );
    assert_eq!((summary.frames_sent, summary.frames_dropped), (1, 0));
    assert_eq!(outcome.progress.sent, 1);
}

/// Пауза посреди пачки повторов досылает остаток пачки мимо throttle (`batch = u64::MAX`); эта досылка кадры стека не
/// берёт: они ждут linger, который после Pause работает до конца окна ожидания RX. Порядок: 4 копии SYN цели, затем
/// кадры стека её ответа; итог `Paused`.
#[test]
fn pause_burst_does_not_drain_stack_frames() {
    let plan = plan_full("10.0.0.0/31", "80", 60, 1, 1_000_000.0, 3);
    let f = ScriptedFactory::new(Script {
        create: true,
        acks: 2,
        ..Script::default()
    });
    let clock = ManualClock::new();
    let fake = FakeAdapter::new();
    let cell: Arc<OnceLock<CancelHandle>> = Arc::default();
    let c2 = cell.clone();
    // Pause после первой копии, когда кадры стека её ответа уже в очереди.
    sync_tx_to_rx(&fake, &f, &clock, move |sent| {
        if sent == 1 {
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
    wait_for("burst and stack frames", || fake.sent_count() == 6);
    advance_until(&clock, Duration::from_secs(60), "outcome", || {
        h.outcome().is_some()
    });
    drain_outputs(&h, Duration::ZERO);
    let summary = h.stack_stats();
    let outcome = h.join().unwrap();
    assert_eq!(outcome.reason, Reason::Paused);
    let kinds: Vec<u8> = fake.sent_frames().iter().map(|fr| tcp_flags(fr)).collect();
    assert_eq!(kinds, [SYN, SYN, SYN, SYN, ACK, ACK]);
    let first = syn_target(&fake.sent_frames()[0]);
    assert!(
        fake.sent_frames()[..4]
            .iter()
            .all(|fr| syn_target(fr) == first)
    );
    assert_eq!((summary.frames_sent, summary.frames_dropped), (2, 0));
    assert_eq!(outcome.progress.sent, 4);
}

/// Отправка кадра стека, которая не удалась (ошибка адаптера, `Uncertain`, `WouldBlockUnsent`), как у Neighbor
/// Advertisement скан не валит и не повторяется: кадр считается в `frames_dropped` (C результат
/// `rawsock_send_packet` для кадров стека не смотрит, `src/stack-queue.c:74`). И в пачках скана, и после зондов.
#[test]
fn stack_frame_send_error_counted_not_fatal() {
    let plan = plan_full("10.0.0.0/31", "80", 60, 1, 1_000_000.0, 0);
    let f = ScriptedFactory::new(Script {
        create: true,
        acks: 3,
        ..Script::default()
    });
    let clock = ManualClock::new();
    let fake = FakeAdapter::new();
    // По порядку вызовов `send`: SYN 1, три кадра его ответа (в пачках скана), SYN 2, три кадра его ответа (после
    // зондов).
    fake.script_tx([
        TxStep::Sent,
        TxStep::Fail("boom".into()),
        TxStep::Uncertain,
        TxStep::Sent,
        TxStep::Sent,
        TxStep::WouldBlockUnsent,
        TxStep::Fail("boom".into()),
        TxStep::Sent,
    ]);
    sync_tx_to_rx(&fake, &f, &clock, |_| {});
    let h = start_manual(&plan, &fake, &clock, stack_options(&f));
    wait_for("all attempts", || fake.send_calls() == 8);
    advance_until(&clock, Duration::from_secs(60), "outcome", || {
        h.outcome().is_some()
    });
    drain_outputs(&h, Duration::ZERO);
    let summary = h.stack_stats();
    let outcome = h.join().unwrap();
    assert_eq!(outcome.reason, Reason::Completed);
    let kinds: Vec<u8> = fake.sent_frames().iter().map(|fr| tcp_flags(fr)).collect();
    assert_eq!(kinds, [SYN, ACK, SYN, ACK]);
    assert_eq!((summary.frames_sent, summary.frames_dropped), (2, 4));
    assert_eq!(fake.uncertain_frames().len(), 1);
    assert_eq!(fake.would_block_count(), 1);
    assert_eq!(fake.send_calls(), 8, "no retry");
    assert_eq!(outcome.progress.sent, 2);
}

/// Р11: `EngineOptions::new` (`stateless_rst: false`, `tcp_stack: None`, так у Studio) шлёт только зонды, побайтно те
/// же, что у независимого курсора, ни одного RST на SYN-ACK и RST; ответы и `Progress` те же, что с `stateless_rst`,
/// который сверх зондов даёт по RST на ответ.
#[test]
fn no_new_frames_without_options() {
    let o = opts();
    assert!(!o.stateless_rst);
    assert!(o.tcp_stack.is_none());
    let plan = plan_v4("10.0.0.0/29", "80", 60);
    let responder = || {
        tcp_server(|s| match syn_target(s) & 1 {
            0 => vec![synack(s)],
            _ => vec![reply_to_syn(s, RST | ACK).unwrap()],
        })
    };
    let (r, fake) = run_settled(&plan, responder(), opts(), |h, _| {
        h.progress().received == 8
    });
    assert_eq!(r.outcome.reason, Reason::Completed);
    assert_eq!(fake.sent_frames(), reference_frames(&plan, 8));
    assert_eq!(r.summary, StackSummary::default());
    assert!(
        r.outputs.iter().all(|x| matches!(x, Output::Event(_))),
        "{:?}",
        r.outputs
    );

    let (with_rst, fake_rst) = run_settled(&plan, responder(), rst_options(), |h, fk| {
        h.progress().received == 8 && fk.sent_count() == 16
    });
    assert_eq!(replies_of(&with_rst.outputs), replies_of(&r.outputs));
    assert_eq!(with_rst.outcome.progress.sent, r.outcome.progress.sent);
    assert_eq!(with_rst.outcome.progress.received, 8);
    let syns: Vec<Vec<u8>> = fake_rst
        .sent_frames()
        .into_iter()
        .filter(|fr| is_tcp_syn(fr))
        .collect();
    assert_eq!(syns, reference_frames(&plan, 8));
    assert_eq!(with_rst.summary.frames_sent, 8);
}

/// Кадры, которые TX уже не отправит (здесь Stop посреди очереди после зонда), не теряются молча: к `Finished` они в
/// `frames_dropped`, и каждый кадр стека посчитан ровно в одном из двух счётчиков (C бросает их в очереди).
#[test]
fn stack_frames_left_unsent_are_counted() {
    let plan = plan_v4("10.0.0.1", "80", 60);
    let f = ScriptedFactory::new(Script {
        create: true,
        acks: 50,
        ..Script::default()
    });
    let clock = ManualClock::new();
    let fake = FakeAdapter::new();
    let cell: Arc<OnceLock<CancelHandle>> = Arc::default();
    let c2 = cell.clone();
    // Stop после SYN и пяти кадров стека.
    sync_tx_to_rx(&fake, &f, &clock, move |sent| {
        if sent == 6 {
            let c = loop {
                if let Some(c) = c2.get() {
                    break c;
                }
                std::thread::yield_now();
            };
            c.stop();
        }
    });
    let h = start_manual(&plan, &fake, &clock, stack_options(&f));
    cell.set(h.cancel_handle()).ok();
    drain_outputs(&h, Duration::ZERO);
    let summary = h.stack_stats();
    let outcome = h.join().unwrap();
    assert_eq!(outcome.reason, Reason::Stopped);
    assert_eq!(fake.sent_count(), 6);
    assert_eq!((summary.frames_sent, summary.frames_dropped), (5, 45));
}
