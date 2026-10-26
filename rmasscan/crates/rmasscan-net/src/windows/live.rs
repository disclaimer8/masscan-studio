//! Opt-in live spike for Npcap TX/RX deadlines and the drop counter (task 2 of
//! stage 2B-Windows). Every test here is `#[ignore]` and needs the lab device
//! in the environment, so default runs and CI never open a handle or send.
//!
//! Environment (all required; a missing variable FAILS the test as NOT RUN):
//!   RMASSCAN_NPCAP_LAB_DEVICE    `\Device\NPF_{GUID}` of the isolated lab NIC
//!   RMASSCAN_NPCAP_LAB_SRC_MAC   aa:bb:cc:dd:ee:ff of that NIC
//!   RMASSCAN_NPCAP_LAB_PEER_MAC  MAC of the Linux peer (lab0)
//!   RMASSCAN_NPCAP_OUT_DIR       directory for raw per-call CSV samples
//! Optional: RMASSCAN_NPCAP_COND (label of the externally arranged
//! condition), RMASSCAN_NPCAP_START_AT / _DOWN_AT / _UP_AT (epoch ms), ...
//!
//! Safety rails: frames are built only for 198.18.0.1 -> 198.18.0.2 and every
//! send passes `assert_lab_frame` (dst MAC = peer, src MAC = lab NIC, dst IP =
//! 198.18.0.2). The management NIC is never named. The 2B tests send one frame
//! per `pcap_sendpacket`; the `live_sendqueue_*` tests (task 3 of the sendqueue
//! stage) use `SendQueue`/`transmit_raw`. Neither has a detached thread; stop
//! is observed between calls only.
//! Sendqueue tests also read RMASSCAN_NPCAP_SQ_SIZES / _SQ_ROUNDS / _SQ_BATCH /
//! _SQ_SECS / _SQ_PPS / _SQ_REUSE_CALLS / _SQ_ALLOC_CALLS and
//! RMASSCAN_NPCAP_STOP_ROUNDS (defaults documented at the sendqueue section).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rmasscan_core::packet::{LinkType, TcpSynTemplate};

use super::ffi::PcapStat;
use super::handle::{NextEx, OpenParams, PcapHandle, list_devices};
use super::loader::NpcapApi;
use crate::drop_counter::DropCounter;

const SRC_IP: u32 = 0xC612_0001; // 198.18.0.1
const DST_IP: u32 = 0xC612_0002; // 198.18.0.2
const JUNK_ETHERTYPE: u16 = 0x88b5;
const MAGIC: &[u8; 4] = b"RMSP";
const MS50: Duration = Duration::from_millis(50);

// ---------- окружение ----------

// Общий с интеграционными тестами код: сверка MAC устройства из окружения.
#[path = "../../tests/support/lab_nic.rs"]
mod lab_nic;

fn need(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("NOT RUN: environment variable {name} is not set"))
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn parse_mac(s: &str) -> [u8; 6] {
    let v: Vec<u8> = s
        .split([':', '-'])
        .map(|p| u8::from_str_radix(p, 16).expect("bad MAC"))
        .collect();
    v.try_into().expect("MAC needs 6 octets")
}

struct Lab {
    device: String,
    src_mac: [u8; 6],
    peer_mac: [u8; 6],
    out_dir: String,
    cond: String,
}

/// Читает окружение и ДО любой отправки проверяет, что устройство из
/// переменной действительно имеет MAC лабораторной привязки.
fn lab() -> Lab {
    let l = Lab {
        device: need("RMASSCAN_NPCAP_LAB_DEVICE"),
        src_mac: parse_mac(&need("RMASSCAN_NPCAP_LAB_SRC_MAC")),
        peer_mac: parse_mac(&need("RMASSCAN_NPCAP_LAB_PEER_MAC")),
        out_dir: need("RMASSCAN_NPCAP_OUT_DIR"),
        cond: std::env::var("RMASSCAN_NPCAP_COND").unwrap_or_else(|_| "unlabelled".into()),
    };
    lab_nic::verify_device_mac(&l.device, l.src_mac);
    l
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn sleep_until_epoch_ms(t: u64) {
    loop {
        let n = now_ms();
        if n >= t {
            return;
        }
        std::thread::sleep(Duration::from_millis((t - n).min(100)));
    }
}

// ---------- образцы и сводка ----------

#[derive(Default)]
struct Samples {
    t_ms: Vec<u64>,
    dur_us: Vec<u64>,
    rc: Vec<i64>,
}

impl Samples {
    fn push(&mut self, t_ms: u64, d: Duration, rc: i64) {
        self.t_ms.push(t_ms);
        self.dur_us.push(d.as_micros() as u64);
        self.rc.push(rc);
    }

    fn pct(sorted: &[u64], p: f64) -> u64 {
        if sorted.is_empty() {
            return 0;
        }
        let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
        sorted[i]
    }

    /// n, p50, p95, p99, max (микросекунды) и распределение rc.
    fn summary(&self, label: &str) -> String {
        let mut s = self.dur_us.clone();
        s.sort_unstable();
        let mut rcs: BTreeMap<i64, usize> = BTreeMap::new();
        for r in &self.rc {
            *rcs.entry(*r).or_default() += 1;
        }
        format!(
            "SUMMARY {label} n={} p50_us={} p95_us={} p99_us={} max_us={} rc={rcs:?}",
            s.len(),
            Self::pct(&s, 0.50),
            Self::pct(&s, 0.95),
            Self::pct(&s, 0.99),
            s.last().copied().unwrap_or(0),
        )
    }

    fn report(&self, lab: &Lab, label: &str) {
        println!("{}", self.summary(&format!("{}/{label}", lab.cond)));
        let mut out = String::from("t_epoch_ms,dur_us,rc\n");
        for i in 0..self.dur_us.len() {
            let _ = writeln!(out, "{},{},{}", self.t_ms[i], self.dur_us[i], self.rc[i]);
        }
        let path = format!("{}\\{}__{label}.csv", lab.out_dir, lab.cond);
        std::fs::write(&path, out).unwrap_or_else(|e| panic!("cannot write {path}: {e}"));
    }
}

/// Одна строка с ключами для разбора скриптом.
fn kv(lab: &Lab, what: &str, body: &str) {
    println!("KV {}/{what} {body}", lab.cond);
}

// ---------- кадры ----------

fn syn_frames(lab: &Lab) -> TcpSynTemplate {
    TcpSynTemplate::new(lab.src_mac, lab.peer_mac, LinkType::Ethernet)
}

fn syn(lab: &Lab, t: &TcpSynTemplate, i: u32, out: &mut Vec<u8>) {
    t.build_syn(DST_IP, 80, SRC_IP, 40_000 + (i % 1000) as u16, i, out);
    assert_lab_frame(lab, out);
}

/// Единственная дверь к `send_raw`: кадр может уйти только лабораторному пиру.
fn assert_lab_frame(lab: &Lab, f: &[u8]) {
    if f.is_empty() {
        return; // пустой кадр на провод не попадает; проверяем код ошибки
    }
    assert!(f.len() >= 34, "frame too short for an IPv4 header");
    assert_eq!(f[0..6], lab.peer_mac, "dst MAC is not the lab peer");
    assert_eq!(f[6..12], lab.src_mac, "src MAC is not the lab NIC");
    assert_eq!(f[12..14], [0x08, 0x00], "not IPv4");
    assert_eq!(f[30..34], DST_IP.to_be_bytes(), "dst IP is not 198.18.0.2");
}

fn send_checked(lab: &Lab, h: &mut PcapHandle, f: &[u8]) -> i32 {
    assert_lab_frame(lab, f);
    h.send_raw(f)
}

// ---------- открытие ----------

fn rx_params(buffer_bytes: i32) -> OpenParams {
    OpenParams {
        snaplen: 2048,
        promisc: false,
        timeout_ms: 1,
        immediate: true,
        buffer_bytes,
    }
}

fn open(api: &Arc<NpcapApi>, lab: &Lab, p: OpenParams) -> PcapHandle {
    let dev = super::handle::resolve_device(api, &lab.device)
        .unwrap_or_else(|e| panic!("lab device not enumerated: {e}"));
    PcapHandle::open_ethernet(api, &dev, p).unwrap_or_else(|e| panic!("open failed: {e}"))
}

fn open_rx(api: &Arc<NpcapApi>, lab: &Lab, buf: i32) -> PcapHandle {
    let mut h = open(api, lab, rx_params(buf));
    h.set_nonblock(true).expect("setnonblock");
    assert_eq!(h.get_nonblock(), 1, "nonblocking mode did not stick");
    h
}

/// TX handle конфигурации СПАЙКА: малые snaplen и буфер. Уменьшение буфера
/// НЕ мешает непрочитанному TX handle копить и терять кадры (спайк r03: 37 264
/// потерь из 38 094); продуктовый адаптер дополнительно ставит фильтр `ret #0`
/// (`live_tx_filter_keeps_the_tx_handle_empty`).
fn open_tx(api: &Arc<NpcapApi>, lab: &Lab) -> PcapHandle {
    let mut h = open(
        api,
        lab,
        OpenParams {
            snaplen: 64,
            promisc: false,
            timeout_ms: 1,
            immediate: true,
            buffer_bytes: 65_536,
        },
    );
    h.set_nonblock(true).expect("setnonblock");
    h
}

// ---------- RX: прототип вызова адаптера ----------

#[derive(Clone, Copy, Debug)]
enum Wait {
    Spin,
    Sleep1ms,
    /// Спит по 1 мс, пока до дедлайна больше 3 мс, затем крутится с yield.
    Hybrid,
}

enum Recv {
    Frame { caplen: u32, len: u32 },
    Empty,
}

/// Собственный абсолютный дедлайн поверх nonblocking `pcap_next_ex`.
fn recv_deadline(
    h: &mut PcapHandle,
    buf: &mut [u8],
    timeout: Duration,
    wait: Wait,
) -> Result<Recv, i32> {
    let deadline = Instant::now() + timeout.min(MS50);
    loop {
        match h.next_ex() {
            NextEx::Frame { hdr, data } => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                return Ok(Recv::Frame {
                    caplen: hdr.caplen,
                    len: hdr.len,
                });
            }
            NextEx::Timeout => {
                let now = Instant::now();
                if now >= deadline {
                    return Ok(Recv::Empty);
                }
                match wait {
                    Wait::Spin => std::thread::yield_now(),
                    Wait::Sleep1ms => {
                        std::thread::sleep((deadline - now).min(Duration::from_millis(1)))
                    }
                    Wait::Hybrid => {
                        if deadline - now > Duration::from_millis(3) {
                            std::thread::sleep(Duration::from_millis(1));
                        } else {
                            std::thread::yield_now();
                        }
                    }
                }
            }
            NextEx::Error(rc) => return Err(rc),
            NextEx::Eof => return Err(-2),
        }
    }
}

#[derive(Default)]
struct FrameCounts {
    junk: u64,
    junk_dupes: u64,
    other: u64,
    own_tx: u64,
    seen: Vec<bool>,
}

impl FrameCounts {
    fn note(&mut self, lab: &Lab, f: &[u8]) {
        if f.len() >= 22 && f[12..14] == JUNK_ETHERTYPE.to_be_bytes() && &f[18..22] == MAGIC {
            let seq = u32::from_be_bytes(f[14..18].try_into().unwrap()) as usize;
            if seq < 8_000_000 {
                if self.seen.len() <= seq {
                    self.seen.resize(seq + 1, false);
                }
                if self.seen[seq] {
                    self.junk_dupes += 1;
                } else {
                    self.seen[seq] = true;
                    self.junk += 1;
                }
            }
        } else {
            self.other += 1;
            if f.len() >= 12 && f[6..12] == lab.src_mac {
                self.own_tx += 1;
            }
        }
    }
}

fn stats_timed(h: &mut PcapHandle, s: &mut Samples) -> Option<PcapStat> {
    let t = now_ms();
    let t0 = Instant::now();
    let r = h.stats_raw();
    let d = t0.elapsed();
    match r {
        Ok(st) => {
            s.push(t, d, 0);
            Some(st)
        }
        Err(rc) => {
            s.push(t, d, i64::from(rc));
            None
        }
    }
}

fn stat_line(st: &PcapStat) -> String {
    format!(
        "recv={} drop={} ifdrop={} capt={} sent={} netdrop={}",
        st.ps_recv, st.ps_drop, st.ps_ifdrop, st.ps_capt, st.ps_sent, st.ps_netdrop
    )
}

fn load() -> Arc<NpcapApi> {
    NpcapApi::load().expect("Npcap must be installed")
}

// =====================================================================
// S1: перечень, открытие/закрытие, ошибки открытия
// =====================================================================

#[test]
#[ignore = "live: needs the lab NIC (see module docs)"]
fn live_open_close() {
    let lab = lab();
    let api = load();
    println!("VERSION {}", api.lib_version());
    for d in api.diagnostics() {
        println!("DLL {d:?}");
    }
    for d in list_devices(&api).unwrap() {
        println!("DEVICE {d:?}");
    }
    let dev = super::handle::resolve_device(&api, &lab.device).unwrap();

    // Пофазовые длительности на сырых вызовах (чтобы увидеть create/activate/close по отдельности).
    let f = &api.fns;
    let (mut create, mut setters, mut activate, mut close) = (
        Samples::default(),
        Samples::default(),
        Samples::default(),
        Samples::default(),
    );
    for _ in 0..30 {
        let mut err = [0 as std::ffi::c_char; 256];
        let t = now_ms();
        let t0 = Instant::now();
        // SAFETY: dev NUL-терминирован, err имеет 256 байт.
        let p = unsafe { (f.create)(dev.as_ptr(), err.as_mut_ptr()) };
        create.push(t, t0.elapsed(), i64::from(!p.is_null()));
        assert!(!p.is_null());
        let t = now_ms();
        let t0 = Instant::now();
        // SAFETY: p валиден и ещё не активирован.
        let rcs = unsafe {
            [
                (f.set_snaplen)(p, 2048),
                (f.set_promisc)(p, 0),
                (f.set_timeout)(p, 1),
                (f.set_immediate_mode)(p, 1),
                (f.set_buffer_size)(p, 262_144),
            ]
        };
        setters.push(t, t0.elapsed(), rcs.iter().map(|r| i64::from(*r)).sum());
        let t = now_ms();
        let t0 = Instant::now();
        // SAFETY: p валиден.
        let rc = unsafe { (f.activate)(p) };
        activate.push(t, t0.elapsed(), i64::from(rc));
        assert_eq!(rc, 0, "activate rc {rc}");
        let t = now_ms();
        let t0 = Instant::now();
        // SAFETY: p валиден, закрывается ровно один раз.
        unsafe { (f.close)(p) };
        close.push(t, t0.elapsed(), 0);
    }
    create.report(&lab, "pcap_create");
    setters.report(&lab, "pcap_set_x5");
    activate.report(&lab, "pcap_activate");
    close.report(&lab, "pcap_close");

    // Два независимых handle на одном устройстве, оба Ethernet; getnonblock.
    let mut tx = open_tx(&api, &lab);
    let mut rx = open_rx(&api, &lab, 1 << 20);
    kv(
        &lab,
        "two_handles",
        &format!(
            "dlt_tx={} dlt_rx={} nonblock_tx={} nonblock_rx={}",
            tx.datalink(),
            rx.datalink(),
            tx.get_nonblock(),
            rx.get_nonblock()
        ),
    );
    let s = rx.stats_raw().unwrap();
    kv(&lab, "fresh_rx_stats", &stat_line(&s));
    let s = tx.stats_raw().unwrap();
    kv(&lab, "fresh_tx_stats", &stat_line(&s));
    drop(rx);
    drop(tx);

    // Ошибки открытия: несуществующее устройство. Спайк (r01): `pcap_create`
    // возвращает NULL с текстом errbuf, `pcap_activate` не достигается.
    let bogus =
        std::ffi::CString::new("\\Device\\NPF_{00000000-0000-0000-0000-000000000000}").unwrap();
    let t0 = Instant::now();
    let r = PcapHandle::open(&api, &bogus, rx_params(65_536));
    kv(
        &lab,
        "open_bogus_device",
        &format!("dur_us={} result={:?}", t0.elapsed().as_micros(), r.err()),
    );
    // Имя вне перечня отвергается нашим resolve_device до create.
    kv(
        &lab,
        "resolve_bogus",
        &format!(
            "{:?}",
            super::handle::resolve_device(&api, "\\Device\\NPF_{DEAD}").err()
        ),
    );
}

// =====================================================================
// S2: матрица условий (idle / flood / down): RX, health, TX, Stop
// =====================================================================

#[test]
#[ignore = "live: needs the lab NIC (see module docs)"]
fn live_io_matrix() {
    let lab = lab();
    let api = load();
    let tpl = syn_frames(&lab);
    let mut tx = open_tx(&api, &lab);
    let mut rx = open_rx(&api, &lab, 1 << 20);
    let mut buf = vec![0u8; 2048];
    let mut counts = FrameCounts::default();
    let base = rx.stats_raw().expect("baseline stats");
    let mut drops = DropCounter::new(base.ps_drop);
    kv(&lab, "baseline", &stat_line(&base));

    // 1. сырые nonblocking-чтения
    let mut s = Samples::default();
    let mut frames = 0u64;
    for _ in 0..3000 {
        let t = now_ms();
        let t0 = Instant::now();
        let (rc, got) = match rx.next_ex() {
            NextEx::Frame { data, .. } => {
                counts.note(&lab, data);
                (1, true)
            }
            NextEx::Timeout => (0, false),
            NextEx::Error(rc) => (i64::from(rc), false),
            NextEx::Eof => (-2, false),
        };
        s.push(t, t0.elapsed(), rc);
        frames += u64::from(got);
        std::thread::sleep(Duration::from_micros(300));
    }
    s.report(&lab, "rx_raw_next_ex");
    kv(&lab, "rx_raw_frames", &format!("{frames}"));

    // 2. вызов с дедлайном 50 мс, обе стратегии ожидания
    for wait in [Wait::Spin, Wait::Sleep1ms, Wait::Hybrid] {
        let mut s = Samples::default();
        let mut over = Samples::default();
        let mut got = 0u64;
        for _ in 0..60 {
            let t = now_ms();
            let t0 = Instant::now();
            let r = recv_deadline(&mut rx, &mut buf, MS50, wait);
            let d = t0.elapsed();
            let rc = match r {
                Ok(Recv::Frame { caplen, len }) => {
                    counts.note(&lab, &buf[..(caplen as usize).min(buf.len())]);
                    got += 1;
                    assert!(caplen <= len);
                    1
                }
                Ok(Recv::Empty) => 0,
                Err(rc) => i64::from(rc),
            };
            s.push(t, d, rc);
            if rc == 0 {
                over.push(t, d.saturating_sub(MS50), 0);
            }
        }
        s.report(&lab, &format!("rx_deadline50_{wait:?}"));
        if !over.dur_us.is_empty() {
            over.report(&lab, &format!("rx_deadline50_overshoot_{wait:?}"));
        }
        kv(
            &lab,
            &format!("rx_deadline50_{wait:?}_frames"),
            &got.to_string(),
        );
    }

    // 3. health: pcap_stats с интервалом 5 мс
    let mut hs = Samples::default();
    let mut last = None;
    for _ in 0..200 {
        if let Some(st) = stats_timed(&mut rx, &mut hs) {
            last = Some(st);
            drops.update(st.ps_drop);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    hs.report(&lab, "health_pcap_stats");
    if let Some(st) = last {
        kv(
            &lab,
            "health_last",
            &format!("{} cum_drops={}", stat_line(&st), drops.update(st.ps_drop)),
        );
    }

    // 4. TX: 1000 кадров через 1 мс
    let mut f = Vec::new();
    let mut s = Samples::default();
    for i in 0..1000u32 {
        syn(&lab, &tpl, i, &mut f);
        let t = now_ms();
        let t0 = Instant::now();
        let rc = tx.send_raw(&f);
        s.push(t, t0.elapsed(), i64::from(rc));
        std::thread::sleep(Duration::from_millis(1));
    }
    s.report(&lab, "tx_paced_1000");
    // чтение своих кадров обратно: видит ли RX свой TX?
    let until = Instant::now() + Duration::from_millis(500);
    while Instant::now() < until {
        match recv_deadline(&mut rx, &mut buf, MS50, Wait::Sleep1ms) {
            Ok(Recv::Frame { caplen, .. }) => {
                counts.note(&lab, &buf[..(caplen as usize).min(buf.len())])
            }
            Ok(Recv::Empty) => {}
            Err(rc) => panic!("rx error {rc}"),
        }
    }
    kv(
        &lab,
        "rx_after_tx_paced",
        &format!(
            "junk={} other={} own_tx={}",
            counts.junk, counts.other, counts.own_tx
        ),
    );

    // 5. TX: 5000 кадров подряд
    let mut s = Samples::default();
    for i in 0..5000u32 {
        syn(&lab, &tpl, 10_000 + i, &mut f);
        let t = now_ms();
        let t0 = Instant::now();
        let rc = tx.send_raw(&f);
        s.push(t, t0.elapsed(), i64::from(rc));
    }
    s.report(&lab, "tx_burst_5000");

    // 6. Stop: TX и RX потоки одновременно, как у движка
    let (mut tx_lat, mut rx_lat, mut join_lat) =
        (Samples::default(), Samples::default(), Samples::default());
    let (mut tx_slow, mut rx_slow) = (Samples::default(), Samples::default());
    let rounds = env_u64("RMASSCAN_NPCAP_STOP_ROUNDS", 60);
    let mut total_bad_rc = 0u64;
    let mut total_rx_errors = 0u64;
    for round in 0..rounds {
        let stop = AtomicBool::new(false);
        let bad_rc = std::sync::atomic::AtomicU64::new(0);
        let rx_errors = std::sync::atomic::AtomicU64::new(0);
        let (t_stop, tx_seen, rx_seen, joined, tx_slowest, rx_slowest) = std::thread::scope(|sc| {
            let txj = sc.spawn(|| {
                let mut f = Vec::new();
                let mut i = 0u32;
                let mut slowest = Duration::ZERO;
                while !stop.load(Ordering::Acquire) {
                    syn(&lab, &tpl, 100_000 + i, &mut f);
                    let t0 = Instant::now();
                    let rc = tx.send_raw(&f);
                    slowest = slowest.max(t0.elapsed());
                    if rc != 0 {
                        bad_rc.fetch_add(1, Ordering::Relaxed);
                    }
                    i = i.wrapping_add(1);
                }
                (Instant::now(), slowest)
            });
            let rxj = sc.spawn(|| {
                let mut b = vec![0u8; 2048];
                let mut slowest = Duration::ZERO;
                while !stop.load(Ordering::Acquire) {
                    let t0 = Instant::now();
                    // Ошибка чтения не теряется: считается и проверяется ниже.
                    if recv_deadline(&mut rx, &mut b, MS50, Wait::Hybrid).is_err() {
                        rx_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    slowest = slowest.max(t0.elapsed());
                }
                (Instant::now(), slowest)
            });
            std::thread::sleep(Duration::from_millis(20 + (round % 7) * 13));
            let t_stop = Instant::now();
            stop.store(true, Ordering::Release);
            let (tx_seen, tx_slowest) = txj.join().unwrap();
            let (rx_seen, rx_slowest) = rxj.join().unwrap();
            (
                t_stop,
                tx_seen,
                rx_seen,
                Instant::now(),
                tx_slowest,
                rx_slowest,
            )
        });
        let t = now_ms();
        total_bad_rc += bad_rc.load(Ordering::Relaxed);
        total_rx_errors += rx_errors.load(Ordering::Relaxed);
        tx_lat.push(t, tx_seen.duration_since(t_stop), 0);
        rx_lat.push(t, rx_seen.duration_since(t_stop), 0);
        tx_slow.push(t, tx_slowest, 0);
        rx_slow.push(t, rx_slowest, 0);
        join_lat.push(t, joined.duration_since(t_stop), 0);
    }
    kv(
        &lab,
        "stop_rounds_send_nonzero_rc",
        &total_bad_rc.to_string(),
    );
    kv(
        &lab,
        "stop_rounds_recv_errors",
        &total_rx_errors.to_string(),
    );
    assert_eq!(total_rx_errors, 0, "an RX read failed during a Stop round");
    // самый долгий отдельный вызов в каждом раунде
    tx_slow.report(&lab, "stop_rounds_slowest_send_per_round");
    rx_slow.report(&lab, "stop_rounds_slowest_recv_per_round");
    tx_lat.report(&lab, "stop_latency_tx_thread");
    rx_lat.report(&lab, "stop_latency_rx_thread");
    join_lat.report(&lab, "stop_latency_joined_both");

    // Ошибочные пути send (наружу ничего не уходит или уходит только пиру)
    let t0 = Instant::now();
    let rc0 = tx.send_raw(&[]);
    let d0 = t0.elapsed();
    kv(
        &lab,
        "send_empty",
        &format!(
            "rc={rc0} dur_us={} err={:?}",
            d0.as_micros(),
            tx.last_error()
        ),
    );
    syn(&lab, &tpl, 7, &mut f);
    let mut big = f.clone();
    big.resize(9000, 0);
    let t0 = Instant::now();
    let rc9 = send_checked(&lab, &mut tx, &big);
    kv(
        &lab,
        "send_9000",
        &format!(
            "rc={rc9} dur_us={} err={:?}",
            t0.elapsed().as_micros(),
            tx.last_error()
        ),
    );

    // Итоговые счётчики обоих handle
    let s = rx.stats_raw().unwrap();
    kv(
        &lab,
        "final_rx_stats",
        &format!("{} cum_drops={}", stat_line(&s), drops.update(s.ps_drop)),
    );
    let s = tx.stats_raw().unwrap();
    kv(&lab, "final_tx_stats", &stat_line(&s));
    kv(
        &lab,
        "frames_seen",
        &format!(
            "junk={} dupes={} other={} own_tx={}",
            counts.junk, counts.junk_dupes, counts.other, counts.own_tx
        ),
    );

    // Закрытие под нагрузкой: длительность
    let t0 = Instant::now();
    drop(rx);
    let c1 = t0.elapsed();
    let t0 = Instant::now();
    drop(tx);
    kv(
        &lab,
        "close_after_load",
        &format!(
            "rx_us={} tx_us={}",
            c1.as_micros(),
            t0.elapsed().as_micros()
        ),
    );
}

// =====================================================================
// S3: переполнение RX, сравнение с независимым счётом
// =====================================================================

fn drain(h: &mut PcapHandle, lab: &Lab, counts: &mut FrameCounts) -> u64 {
    let mut n = 0u64;
    let mut empties = 0;
    let mut buf = vec![0u8; 2048];
    while empties < 5 {
        match recv_deadline(h, &mut buf, Duration::from_millis(40), Wait::Hybrid) {
            Ok(Recv::Frame { caplen, .. }) => {
                counts.note(lab, &buf[..(caplen as usize).min(buf.len())]);
                n += 1;
                empties = 0;
            }
            Ok(Recv::Empty) => empties += 1,
            Err(rc) => panic!("drain rc {rc}"),
        }
    }
    n
}

#[test]
#[ignore = "live: needs the lab NIC and a peer flood (see module docs)"]
fn live_overflow() {
    let lab = lab();
    let api = load();
    let start_at = env_u64("RMASSCAN_NPCAP_START_AT", 0);
    let hold_ms = env_u64("RMASSCAN_NPCAP_HOLD_MS", 6000);
    let small = env_u64("RMASSCAN_NPCAP_SMALL_BUF", 32_768) as i32;
    let mut a = open_rx(&api, &lab, small); // медленный читатель
    let mut b = open_rx(&api, &lab, 64 << 20); // независимый счётчик (большой буфер)
    let (sa0, sb0) = (a.stats_raw().unwrap(), b.stats_raw().unwrap());
    kv(&lab, "baseline_A", &stat_line(&sa0));
    kv(&lab, "baseline_B", &stat_line(&sb0));
    let mut drops = DropCounter::new(sa0.ps_drop);
    let mut hs = Samples::default();
    sleep_until_epoch_ms(start_at);
    // Держим оба handle непрочитанными, только health раз в 250 мс.
    let until = start_at + hold_ms;
    let mut series = String::new();
    while now_ms() < until {
        if let Some(st) = stats_timed(&mut a, &mut hs) {
            let _ = write!(
                series,
                "[{} {} {}]",
                now_ms() - start_at,
                st.ps_recv,
                st.ps_drop
            );
            drops.update(st.ps_drop);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    hs.report(&lab, "health_during_overflow");
    kv(&lab, "health_series_ms_recv_drop", &series);
    let (mut r1, mut r2, mut r3) = (Samples::default(), Samples::default(), Samples::default());
    let a1 = stats_timed(&mut a, &mut r1).unwrap();
    let a2 = stats_timed(&mut a, &mut r2).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let a3 = stats_timed(&mut a, &mut r3).unwrap();
    kv(
        &lab,
        "A_before_drain_x3",
        &format!(
            "{} | {} | {}",
            stat_line(&a1),
            stat_line(&a2),
            stat_line(&a3)
        ),
    );
    let b1 = b.stats_raw().unwrap();
    kv(&lab, "B_before_drain", &stat_line(&b1));
    let (mut ca, mut cb) = (FrameCounts::default(), FrameCounts::default());
    let na = drain(&mut a, &lab, &mut ca);
    let nb = drain(&mut b, &lab, &mut cb);
    let a4 = a.stats_raw().unwrap();
    let b4 = b.stats_raw().unwrap();
    kv(&lab, "A_after_drain", &stat_line(&a4));
    kv(&lab, "B_after_drain", &stat_line(&b4));
    kv(
        &lab,
        "A_read",
        &format!(
            "frames={na} junk={} dupes={} other={}",
            ca.junk, ca.junk_dupes, ca.other
        ),
    );
    kv(
        &lab,
        "B_read",
        &format!(
            "frames={nb} junk={} dupes={} other={}",
            cb.junk, cb.junk_dupes, cb.other
        ),
    );
    let indep_loss_junk = cb.junk.saturating_sub(ca.junk);
    let indep_loss_all = nb.saturating_sub(na);
    let cum = drops.update(a4.ps_drop);
    kv(
        &lab,
        "compare",
        &format!(
            "indep_loss_junk={indep_loss_junk} indep_loss_all={indep_loss_all} A_ps_drop={} cumulative_since_start={cum} ok_ge_junk={} ok_ge_all={} recv_minus_drop_vs_read={} ",
            a4.ps_drop,
            u64::from(a4.ps_drop) >= indep_loss_junk,
            u64::from(a4.ps_drop) >= indep_loss_all,
            i64::from(a4.ps_recv) - i64::from(a4.ps_drop) - na as i64,
        ),
    );
    // Свежий handle после потока: счётчик per-handle или общий на драйвер?
    let mut c = open_rx(&api, &lab, 65_536);
    let sc = c.stats_raw().unwrap();
    kv(&lab, "fresh_C_after_flood", &stat_line(&sc));
    let t0 = Instant::now();
    drop(a);
    drop(b);
    drop(c);
    kv(
        &lab,
        "close_3_handles_us",
        &t0.elapsed().as_micros().to_string(),
    );
}

// =====================================================================
// S4: отключение lab-линка посреди работы (фазы по epoch-времени)
// =====================================================================

#[test]
#[ignore = "live: needs the lab NIC and an external link-down (see module docs)"]
fn live_unplug_phases() {
    let lab = lab();
    let api = load();
    let tpl = syn_frames(&lab);
    let start_at = env_u64("RMASSCAN_NPCAP_START_AT", 0);
    let total_ms = env_u64("RMASSCAN_NPCAP_TOTAL_MS", 30_000);
    let down_at = env_u64("RMASSCAN_NPCAP_DOWN_AT", u64::MAX);
    let up_at = env_u64("RMASSCAN_NPCAP_UP_AT", u64::MAX);
    let mut tx = open_tx(&api, &lab);
    let mut rx = open_rx(&api, &lab, 1 << 20);
    let base = rx.stats_raw().unwrap();
    let mut drops = DropCounter::new(base.ps_drop);
    sleep_until_epoch_ms(start_at);
    let end = start_at + total_ms;
    let (mut txs, mut rxs, mut hs) = (Samples::default(), Samples::default(), Samples::default());
    let mut series = String::new();
    let mut f = Vec::new();
    let mut buf = vec![0u8; 2048];
    let mut next_health = now_ms();
    let mut next_tx = Instant::now();
    let mut i = 0u32;
    while now_ms() < end {
        // RX: вызов с дедлайном
        let t = now_ms();
        let t0 = Instant::now();
        let rc = match recv_deadline(&mut rx, &mut buf, MS50, Wait::Hybrid) {
            Ok(Recv::Frame { .. }) => 1,
            Ok(Recv::Empty) => 0,
            Err(rc) => i64::from(rc),
        };
        rxs.push(t, t0.elapsed(), rc);
        // TX: ~200 кадров/с
        if Instant::now() >= next_tx {
            syn(&lab, &tpl, i, &mut f);
            i += 1;
            let t = now_ms();
            let t0 = Instant::now();
            let rc = tx.send_raw(&f);
            txs.push(t, t0.elapsed(), i64::from(rc));
            next_tx += Duration::from_millis(5);
        }
        if now_ms() >= next_health {
            if let Some(st) = stats_timed(&mut rx, &mut hs) {
                let _ = write!(
                    series,
                    "[{} {} {}]",
                    now_ms() - start_at,
                    st.ps_recv,
                    st.ps_drop
                );
                drops.update(st.ps_drop);
            }
            next_health += 250;
        }
    }
    kv(
        &lab,
        "phase_marks",
        &format!("start={start_at} down={down_at} up={up_at} end={end}"),
    );
    txs.report(&lab, "unplug_tx_send");
    rxs.report(&lab, "unplug_rx_deadline50");
    hs.report(&lab, "unplug_health");
    kv(&lab, "health_series_ms_recv_drop", &series);
    let st = rx.stats_raw().unwrap();
    kv(
        &lab,
        "final_rx_stats",
        &format!("{} cum_drops={}", stat_line(&st), drops.update(st.ps_drop)),
    );
    kv(&lab, "tx_sent_frames", &i.to_string());
}

// =====================================================================
// S5: ошибка запроса pcap_stats (неактивированный handle)
// =====================================================================

#[test]
#[ignore = "live: needs Npcap and the lab device name (no packets are sent)"]
fn live_health_error() {
    let lab = lab();
    let api = load();
    let dev = super::handle::resolve_device(&api, &lab.device).unwrap();
    let f = &api.fns;
    let mut err = [0 as std::ffi::c_char; 256];
    // SAFETY: dev NUL-терминирован, err имеет 256 байт.
    let p = unsafe { (f.create)(dev.as_ptr(), err.as_mut_ptr()) };
    assert!(!p.is_null());
    let mut st = PcapStat::default();
    let t0 = Instant::now();
    // SAFETY: p валиден (создан, не активирован), st полного размера.
    let rc = unsafe { (f.stats)(p, &mut st) };
    let d = t0.elapsed();
    // SAFETY: p валиден.
    let e = unsafe { std::ffi::CStr::from_ptr((f.geterr)(p)) }
        .to_string_lossy()
        .into_owned();
    kv(
        &lab,
        "stats_on_unactivated",
        &format!(
            "rc={rc} dur_us={} geterr={e:?} stat_after={}",
            d.as_micros(),
            stat_line(&st)
        ),
    );
    // SAFETY: p валиден, закрывается один раз.
    unsafe { (f.close)(p) };
    assert!(rc < 0, "an unactivated handle must not report statistics");
}

/// Продуктовая настройка TX handle (малые snaplen/буфер + фильтр `ret #0`)
/// не копит кадры: после серии отправок `ps_recv`/`ps_drop` этого handle не
/// растут, тогда как спайк без фильтра терял десятки тысяч.
#[test]
#[ignore = "live: needs the lab NIC (see module docs)"]
fn live_tx_filter_keeps_the_tx_handle_empty() {
    let lab = lab();
    let api = load();
    let tpl = syn_frames(&lab);
    let mut tx = open_tx(&api, &lab);
    let before = tx.stats_raw().expect("stats");
    tx.set_drop_all_filter().expect("drop-all filter");
    let mut f = Vec::new();
    for i in 0..5000u32 {
        syn(&lab, &tpl, 20_000 + i, &mut f);
        assert_eq!(send_checked(&lab, &mut tx, &f), 0);
    }
    std::thread::sleep(Duration::from_millis(500));
    let after = tx.stats_raw().expect("stats");
    kv(&lab, "tx_filter_before", &stat_line(&before));
    kv(&lab, "tx_filter_after", &stat_line(&after));
    assert_eq!(
        after.ps_drop, before.ps_drop,
        "the filtered TX handle still dropped captured frames"
    );
}

// =====================================================================
// Спайк sendqueue (задача 3 этапа Windows sendqueue): тайминги по размеру
// пачки, граница частичного transmit, повторное использование очереди,
// Stop и потеря линка. Очередь и transmit это `SendQueue`/`transmit_raw`
// задачи 2 напрямую (адаптера в этих тестах нет).
//
// Дополнительное окружение:
//   RMASSCAN_NPCAP_SQ_SIZES   список n через запятую (по умолчанию 1,16,64,256,1024,4096)
//   RMASSCAN_NPCAP_SQ_ROUNDS  transmit на размер (по умолчанию 200)
//   RMASSCAN_NPCAP_SQ_BATCH   размер пачки для stop/linkdown (по умолчанию 64 = TX_BATCH_FRAMES)
//   RMASSCAN_NPCAP_SQ_SECS    длительность linkdown-прогона, с (по умолчанию 25)
//   RMASSCAN_NPCAP_SQ_PPS     потолок средней скорости, кадров/с (по умолчанию 100000)
// =====================================================================

use std::sync::atomic::AtomicU64;

use sha2::{Digest, Sha256};

use super::ffi::PcapPkthdr;
use super::handle::SendQueue;
use super::process::process_sample;

const SQ_RECORD_HEADER: u32 = 16;
/// Предел кадра продукта (`MAX_TX_FRAME`): байты очереди = n × (16 + 1518).
const SQ_MAX_FRAME: u32 = 1518;
/// Бюджет вызова (`IO_BUDGET`) и порог выбора p99.9 (половина бюджета).
const SQ_BUDGET_US: u64 = 42_000;
const SQ_P999_LIMIT_US: u64 = 21_000;

fn sq_sizes() -> Vec<usize> {
    std::env::var("RMASSCAN_NPCAP_SQ_SIZES")
        .unwrap_or_else(|_| "1,16,64,256,1024,4096".into())
        .split(',')
        .map(|s| s.trim().parse().expect("bad RMASSCAN_NPCAP_SQ_SIZES"))
        .collect()
}

fn sq_pps() -> f64 {
    env_u64("RMASSCAN_NPCAP_SQ_PPS", 100_000) as f64
}

/// TX handle продуктовой конфигурации: малые snaplen и буфер плюс фильтр
/// `ret #0` (как `open_with` в адаптере).
fn open_tx_product(api: &Arc<NpcapApi>, lab: &Lab) -> PcapHandle {
    let mut h = open(
        api,
        lab,
        OpenParams {
            snaplen: 64,
            promisc: false,
            timeout_ms: 1,
            immediate: true,
            buffer_bytes: 65_536,
        },
    );
    h.set_drop_all_filter().expect("drop-all filter");
    h
}

/// SYN с порядковым номером `seq` в `seqno`; порт назначения обходит 1-65535.
fn sq_syn(lab: &Lab, t: &TcpSynTemplate, seq: u32, out: &mut Vec<u8>) {
    let dport = 1 + (seq % 65_535) as u16;
    t.build_syn(
        DST_IP,
        dport,
        SRC_IP,
        40_000 + (seq % 1000) as u16,
        seq,
        out,
    );
    assert_lab_frame(lab, out);
}

/// Спит так, чтобы средняя скорость `frames` кадров с `start` не превышала `pps`.
/// Точность сна ни на что не влияет: это только потолок скорости.
fn pace(start: Instant, frames: u64, pps: f64) {
    let want = Duration::from_secs_f64(frames as f64 / pps);
    let have = start.elapsed();
    if want > have {
        std::thread::sleep(want - have);
    }
}

fn pct_nr(sorted: &[u64], p: f64) -> u64 {
    // nearest-rank: наименьшее значение, ниже которого не меньше доли p выборки
    if sorted.is_empty() {
        return 0;
    }
    let rank = (p * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

#[derive(Default)]
struct TxRows {
    t_ms: Vec<u64>,
    n: Vec<u64>,
    queued: Vec<u64>,
    sent: Vec<u64>,
    dur_us: Vec<u64>,
}

impl TxRows {
    /// Предвыделенные и прогретые столбцы: страницы записываются сразу,
    /// иначе рабочий набор рос бы по мере записи журнала (40 Б на вызов), и
    /// измерение рабочего набора видело бы журнал теста вместо очереди и драйвера.
    fn with_capacity(calls: usize) -> TxRows {
        fn warm(calls: usize) -> Vec<u64> {
            let mut v = vec![1u64; calls];
            v.clear();
            v
        }
        TxRows {
            t_ms: warm(calls),
            n: warm(calls),
            queued: warm(calls),
            sent: warm(calls),
            dur_us: warm(calls),
        }
    }

    fn push(&mut self, t_ms: u64, n: usize, queued: u32, sent: u32, d: Duration) {
        self.t_ms.push(t_ms);
        self.n.push(n as u64);
        self.queued.push(u64::from(queued));
        self.sent.push(u64::from(sent));
        self.dur_us.push(d.as_micros() as u64);
    }

    fn csv(&self, lab: &Lab, label: &str) {
        let mut out = String::from("t_ms,n,bytes_queued,bytes_sent,dur_us\n");
        for i in 0..self.t_ms.len() {
            let _ = writeln!(
                out,
                "{},{},{},{},{}",
                self.t_ms[i], self.n[i], self.queued[i], self.sent[i], self.dur_us[i]
            );
        }
        let path = format!("{}\\{}__{label}.csv", lab.out_dir, lab.cond);
        std::fs::write(&path, out).unwrap_or_else(|e| panic!("cannot write {path}: {e}"));
    }

    /// Строка KV: перцентили, потолок pps (Σn / Σdur), число неполных transmit.
    fn summary(&self, lab: &Lab, label: &str, n: usize) -> (u64, u64, bool) {
        let mut s = self.dur_us.clone();
        s.sort_unstable();
        let sum_dur: u64 = s.iter().sum();
        let sum_n: u64 = self.n.iter().sum();
        let short = (0..self.sent.len())
            .filter(|&i| self.sent[i] != self.queued[i])
            .count();
        let p999 = pct_nr(&s, 0.999);
        let max = s.last().copied().unwrap_or(0);
        let pass = p999 <= SQ_P999_LIMIT_US && max <= SQ_BUDGET_US && short == 0;
        kv(
            lab,
            label,
            &format!(
                "n={n} calls={} p50_us={} p95_us={} p99_us={} p999_us={p999} max_us={max} sum_frames={sum_n} sum_dur_us={sum_dur} pps_ceiling={:.0} short_transmits={short} pass={pass}",
                s.len(),
                pct_nr(&s, 0.50),
                pct_nr(&s, 0.95),
                pct_nr(&s, 0.99),
                sum_n as f64 * 1e6 / sum_dur.max(1) as f64,
            ),
        );
        (p999, max, pass)
    }
}

/// Один transmit пачки из `n` SYN с последовательными номерами с `*seq`.
/// Возвращает (поставлено байт, принято драйвером, длительность).
fn sq_batch(
    lab: &Lab,
    tpl: &TcpSynTemplate,
    tx: &mut PcapHandle,
    q: &mut SendQueue,
    n: usize,
    seq: &mut u32,
    f: &mut Vec<u8>,
) -> (u32, u32, Duration) {
    q.clear();
    for _ in 0..n {
        sq_syn(lab, tpl, *seq, f);
        *seq = seq.wrapping_add(1);
        q.push(f).expect("queue is full");
    }
    let queued = q.queued_bytes();
    let t0 = Instant::now();
    let sent = tx.transmit_raw(q, false);
    (queued, sent, t0.elapsed())
}

/// Отсчёт процесса: номер вызова, рабочий набор, handles, потоки.
type WsSample = (usize, Option<u64>, Option<u64>, Option<u64>);

fn sq_queue_bytes(max_n: usize) -> u32 {
    (max_n as u32) * (SQ_RECORD_HEADER + SQ_MAX_FRAME)
}

#[test]
#[ignore = "live: needs the lab NIC (see module docs)"]
fn live_sendqueue_transmit_timing() {
    let lab = lab();
    let api = load();
    let tpl = syn_frames(&lab);
    let sizes = sq_sizes();
    let rounds = env_u64("RMASSCAN_NPCAP_SQ_ROUNDS", 200) as usize;
    let pps = sq_pps();
    let mut tx = open_tx_product(&api, &lab);
    let mut q = SendQueue::alloc(&api, sq_queue_bytes(*sizes.iter().max().unwrap())).unwrap();
    let mut f = Vec::new();
    let mut seq = 0u32;
    let mut sigma = 0u64;
    let mut chosen: Option<usize> = None;
    kv(
        &lab,
        "config",
        &format!("sizes={sizes:?} rounds={rounds} pps_cap={pps}"),
    );
    for &n in &sizes {
        let mut rows = TxRows::default();
        let seq_first = seq;
        let start = Instant::now();
        let mut frames = 0u64;
        for _ in 0..rounds {
            let t = now_ms();
            let (queued, sent, d) = sq_batch(&lab, &tpl, &mut tx, &mut q, n, &mut seq, &mut f);
            rows.push(t, n, queued, sent, d);
            frames += n as u64;
            pace(start, frames, pps);
        }
        sigma += frames;
        rows.csv(&lab, &format!("sq_timing_n{n}"));
        let (_, _, pass) = rows.summary(&lab, &format!("sq_n{n}"), n);
        kv(
            &lab,
            &format!("sq_n{n}_seq"),
            &format!("first={seq_first} frames={frames}"),
        );
        if pass {
            chosen = Some(n);
        }
    }

    // n = 1: очередь против pcap_sendpacket, по 1000 вызовов, тот же потолок скорости
    let calls = 1000usize;
    let mut rq = TxRows::default();
    let mut rs = Samples::default();
    let seq_cmp = seq;
    let start = Instant::now();
    for i in 0..calls {
        let t = now_ms();
        let (queued, sent, d) = sq_batch(&lab, &tpl, &mut tx, &mut q, 1, &mut seq, &mut f);
        rq.push(t, 1, queued, sent, d);
        pace(start, 2 * i as u64 + 1, pps);
    }
    for i in 0..calls {
        sq_syn(&lab, &tpl, seq, &mut f);
        seq = seq.wrapping_add(1);
        let t = now_ms();
        let t0 = Instant::now();
        let rc = send_checked(&lab, &mut tx, &f);
        rs.push(t, t0.elapsed(), i64::from(rc));
        pace(start, 2 * i as u64 + 2, pps);
    }
    sigma += 2 * calls as u64;
    rq.csv(&lab, "sq_cmp_queue_n1");
    rs.report(&lab, "sq_cmp_sendpacket");
    rq.summary(&lab, "sq_cmp_queue_n1", 1);
    kv(
        &lab,
        "sq_cmp_seq",
        &format!("first={seq_cmp} calls_each={calls}"),
    );
    println!("{}", rs.summary(&format!("{}/sq_cmp_sendpacket", lab.cond)));

    kv(&lab, "sigma_frames", &sigma.to_string());
    kv(
        &lab,
        "largest_passing_n",
        &chosen.map_or("none".into(), |n| n.to_string()),
    );
    let s = tx.stats_raw().expect("tx stats");
    kv(&lab, "final_tx_stats", &stat_line(&s));
}

// ---------- граница частичного transmit ----------

#[derive(Clone, Copy, Debug)]
enum Reject {
    Frame9000,
    Caplen0,
    Caplen20Len60,
}

impl Reject {
    fn name(self) -> &'static str {
        match self {
            Reject::Frame9000 => "frame9000",
            Reject::Caplen0 => "caplen0",
            Reject::Caplen20Len60 => "caplen20_len60",
        }
    }
}

/// seq = BASE + attempt × 512 + индекс записи в очереди: пир по seq однозначно
/// называет попытку и позицию каждого дошедшего SYN.
const PB_ATTEMPT_STRIDE: u32 = 512;

#[test]
#[ignore = "live: needs the lab NIC (see module docs)"]
fn live_sendqueue_partial_boundary() {
    let lab = lab();
    let api = load();
    let tpl = syn_frames(&lab);
    let mut tx = open_tx_product(&api, &lab);
    let mut q = SendQueue::alloc(&api, 1 << 20).unwrap();
    let m = 5usize;
    let mut f = Vec::new();
    let mut csv = String::from(
        "attempt,reject,k,m,seq_first,records,bytes_queued,boundary_k,bytes_sent,outcome,geterr\n",
    );
    let mut attempt = 0u32;
    let mut stop_reasons: Vec<String> = Vec::new();
    for reject in [Reject::Frame9000, Reject::Caplen0, Reject::Caplen20Len60] {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        let mut ks: Vec<usize> = vec![7; 20];
        ks.push(0);
        ks.push(255);
        for k in ks {
            q.clear();
            let base = attempt * PB_ATTEMPT_STRIDE;
            for j in 0..k {
                sq_syn(&lab, &tpl, base + j as u32, &mut f);
                q.push(&f).unwrap();
            }
            // отвергаемая запись: все кадры идут только пиру (assert_lab_frame)
            sq_syn(&lab, &tpl, base + 500, &mut f);
            match reject {
                Reject::Frame9000 => {
                    let mut big = f.clone();
                    big.resize(9000, 0);
                    assert_lab_frame(&lab, &big);
                    q.push(&big).unwrap();
                }
                Reject::Caplen0 => {
                    let hdr = PcapPkthdr {
                        caplen: 0,
                        len: 0,
                        ..PcapPkthdr::default()
                    };
                    q.push_raw(&hdr, &[]).unwrap();
                }
                Reject::Caplen20Len60 => {
                    let hdr = PcapPkthdr {
                        caplen: 20,
                        len: 60,
                        ..PcapPkthdr::default()
                    };
                    q.push_raw(&hdr, &f).unwrap();
                }
            }
            for i in 0..m {
                sq_syn(&lab, &tpl, base + (k + 1 + i) as u32, &mut f);
                q.push(&f).unwrap();
            }
            let sizes: Vec<u32> = q.record_sizes().to_vec();
            let boundary: u64 = sizes[..k].iter().map(|s| u64::from(*s)).sum();
            let queued = q.queued_bytes();
            let t0 = Instant::now();
            let sent = tx.transmit_raw(&mut q, false);
            let d = t0.elapsed();
            let err = tx.last_error().replace([',', '\r', '\n'], " ");
            let outcome = if u64::from(sent) == boundary {
                "boundary_k"
            } else if sent == queued {
                "all_accepted"
            } else if sent == 0 {
                "zero"
            } else {
                // граница другой записи или середина записи
                let mut acc = 0u64;
                let mut on_b = false;
                for s in &sizes {
                    acc += u64::from(*s);
                    if acc == u64::from(sent) {
                        on_b = true;
                    }
                }
                if on_b { "other_boundary" } else { "mid_record" }
            };
            *counts.entry(outcome).or_default() += 1;
            let _ = writeln!(
                csv,
                "{attempt},{},{k},{m},{base},{},{queued},{boundary},{sent},{outcome},{err}",
                reject.name(),
                sizes.len()
            );
            println!(
                "ATTEMPT {attempt} {} k={k} queued={queued} boundary={boundary} sent={sent} outcome={outcome} dur_us={} geterr={err:?}",
                reject.name(),
                d.as_micros()
            );
            attempt += 1;
            std::thread::sleep(Duration::from_millis(30));
        }
        kv(
            &lab,
            &format!("partial_{}", reject.name()),
            &format!("{counts:?}"),
        );
        if counts.keys().any(|k| *k != "boundary_k") {
            stop_reasons.push(format!("{}: {counts:?}", reject.name()));
        }
    }
    let path = format!("{}\\{}__sq_partial.csv", lab.out_dir, lab.cond);
    std::fs::write(&path, csv).unwrap_or_else(|e| panic!("cannot write {path}: {e}"));
    kv(&lab, "partial_attempts", &attempt.to_string());
    kv(&lab, "partial_nonboundary", &format!("{stop_reasons:?}"));
}

// ---------- повторное использование очереди ----------

#[test]
#[ignore = "live: needs the lab NIC (see module docs)"]
fn live_sendqueue_reuse_no_leak() {
    let lab = lab();
    let api = load();
    let tpl = syn_frames(&lab);
    let pps = sq_pps();
    let reuse_calls = env_u64("RMASSCAN_NPCAP_SQ_REUSE_CALLS", 10_000) as usize;
    let alloc_calls = env_u64("RMASSCAN_NPCAP_SQ_ALLOC_CALLS", 1_000) as usize;
    let n = 64usize;
    let mut tx = open_tx_product(&api, &lab);
    let mut f = Vec::new();
    let mut seq = 0u32;
    let mut verdicts = Vec::new();
    for (phase, calls) in [("clear", reuse_calls), ("destroy_alloc", alloc_calls)] {
        let mut rows = TxRows::with_capacity(calls);
        let mut ws: Vec<WsSample> = Vec::with_capacity(16);
        let seq_first = seq;
        let mut q = SendQueue::alloc(&api, sq_queue_bytes(n)).unwrap();
        let start = Instant::now();
        let mut frames = 0u64;
        for c in 0..calls {
            if phase == "destroy_alloc" {
                drop(q);
                q = SendQueue::alloc(&api, sq_queue_bytes(n)).unwrap();
            }
            let t = now_ms();
            let (queued, sent, d) = sq_batch(&lab, &tpl, &mut tx, &mut q, n, &mut seq, &mut f);
            rows.push(t, n, queued, sent, d);
            frames += n as u64;
            pace(start, frames, pps);
            if (c + 1) % (calls / 10).max(1) == 0 {
                let s = process_sample();
                ws.push((c + 1, s.working_set_bytes, s.handles, s.threads));
            }
        }
        rows.csv(&lab, &format!("sq_reuse_{phase}"));
        rows.summary(&lab, &format!("sq_reuse_{phase}"), n);
        kv(
            &lab,
            &format!("sq_reuse_{phase}_seq"),
            &format!("first={seq_first} frames={frames}"),
        );
        let mut csv = String::from("call,working_set_bytes,handles,threads\n");
        for (c, w, h, t) in &ws {
            let _ = writeln!(
                csv,
                "{c},{},{},{}",
                w.unwrap_or(0),
                h.unwrap_or(0),
                t.unwrap_or(0)
            );
            kv(
                &lab,
                &format!("sq_reuse_{phase}_sample"),
                &format!("call={c} working_set={w:?} handles={h:?} threads={t:?}"),
            );
        }
        let path = format!(
            "{}\\{}__sq_reuse_{phase}_process.csv",
            lab.out_dir, lab.cond
        );
        std::fs::write(&path, csv).unwrap_or_else(|e| panic!("cannot write {path}: {e}"));
        let first = ws.first().and_then(|x| x.1).unwrap_or(0);
        let last = ws.last().and_then(|x| x.1).unwrap_or(0);
        let growth = last as i64 - first as i64;
        let short = (0..rows.sent.len())
            .filter(|&i| rows.sent[i] != rows.queued[i])
            .count();
        kv(
            &lab,
            &format!("sq_reuse_{phase}_verdict"),
            &format!(
                "ws_growth_10pct_to_100pct={growth} short_transmits={short} under_1mib={}",
                growth < (1 << 20)
            ),
        );
        verdicts.push((phase, growth, short));
        drop(q);
    }
    for (phase, growth, short) in verdicts {
        assert_eq!(short, 0, "{phase}: bytes_sent != bytes_queued");
        assert!(
            growth < (1 << 20),
            "{phase}: working set grew by {growth} bytes"
        );
    }
}

// ---------- задержка Stop ----------

#[test]
#[ignore = "live: needs the lab NIC (see module docs)"]
fn live_sendqueue_stop_latency() {
    let lab = lab();
    let api = load();
    let tpl = syn_frames(&lab);
    let batch = env_u64("RMASSCAN_NPCAP_SQ_BATCH", 64) as usize;
    let pps = sq_pps();
    let rounds = env_u64("RMASSCAN_NPCAP_STOP_ROUNDS", 60);
    let mut tx = open_tx_product(&api, &lab);
    let mut q = SendQueue::alloc(&api, sq_queue_bytes(batch)).unwrap();
    let mut rx = open_rx(&api, &lab, 1 << 20);
    let (mut tx_lat, mut rx_lat, mut join_lat, mut slow) = (
        Samples::default(),
        Samples::default(),
        Samples::default(),
        Samples::default(),
    );
    let seq_g = AtomicU64::new(0);
    let total_short = AtomicU64::new(0);
    let total_rx_err = AtomicU64::new(0);
    let mut worst_excess_us = 0i64;
    let mut rounds_csv = String::from(
        "round,delay_ms,tx_exit_us,rx_exit_us,join_us,tx_slowest_transmit_us,tx_excess_over_slowest_us\n",
    );
    for round in 0..rounds {
        let stop = AtomicBool::new(false);
        // «Случайный» момент: SHA-256 от номера раунда и часов
        let h = Sha256::digest(
            format!(
                "{round}:{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )
            .as_bytes(),
        );
        let delay_ms = 20 + u64::from(u16::from_le_bytes([h[0], h[1]])) % 280;
        let (t_stop, tx_seen, rx_seen, joined, tx_slowest) = std::thread::scope(|sc| {
            let txj = sc.spawn(|| {
                let mut f = Vec::new();
                let mut slowest = Duration::ZERO;
                let start = Instant::now();
                let mut frames = 0u64;
                while !stop.load(Ordering::Acquire) {
                    let mut seq = seq_g.fetch_add(batch as u64, Ordering::Relaxed) as u32;
                    let (queued, sent, d) =
                        sq_batch(&lab, &tpl, &mut tx, &mut q, batch, &mut seq, &mut f);
                    if queued != sent {
                        total_short.fetch_add(1, Ordering::Relaxed);
                    }
                    slowest = slowest.max(d);
                    frames += batch as u64;
                    pace(start, frames, pps);
                }
                (Instant::now(), slowest)
            });
            let rxj = sc.spawn(|| {
                let mut b = vec![0u8; 2048];
                while !stop.load(Ordering::Acquire) {
                    if recv_deadline(&mut rx, &mut b, Duration::from_millis(42), Wait::Hybrid)
                        .is_err()
                    {
                        total_rx_err.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Instant::now()
            });
            std::thread::sleep(Duration::from_millis(delay_ms));
            let t_stop = Instant::now();
            stop.store(true, Ordering::Release);
            let (tx_seen, tx_slowest) = txj.join().unwrap();
            let rx_seen = rxj.join().unwrap();
            (t_stop, tx_seen, rx_seen, Instant::now(), tx_slowest)
        });
        let t = now_ms();
        let txl = tx_seen.duration_since(t_stop);
        let rxl = rx_seen.duration_since(t_stop);
        let jl = joined.duration_since(t_stop);
        tx_lat.push(t, txl, 0);
        rx_lat.push(t, rxl, 0);
        join_lat.push(t, jl, 0);
        slow.push(t, tx_slowest, 0);
        let excess = txl.as_micros() as i64 - tx_slowest.as_micros() as i64;
        worst_excess_us = worst_excess_us.max(excess);
        let _ = writeln!(
            rounds_csv,
            "{round},{delay_ms},{},{},{},{},{excess}",
            txl.as_micros(),
            rxl.as_micros(),
            jl.as_micros(),
            tx_slowest.as_micros()
        );
    }
    let path = format!("{}\\{}__sq_stop_rounds.csv", lab.out_dir, lab.cond);
    std::fs::write(&path, rounds_csv).unwrap_or_else(|e| panic!("cannot write {path}: {e}"));
    tx_lat.report(&lab, "sq_stop_latency_tx");
    rx_lat.report(&lab, "sq_stop_latency_rx");
    join_lat.report(&lab, "sq_stop_latency_joined");
    slow.report(&lab, "sq_stop_slowest_transmit_per_round");
    let max_join = join_lat.dur_us.iter().copied().max().unwrap_or(0);
    kv(
        &lab,
        "sq_stop_verdict",
        &format!(
            "batch={batch} rounds={rounds} frames={} max_join_us={max_join} worst_tx_excess_over_slowest_transmit_us={worst_excess_us} short_transmits={} rx_errors={}",
            seq_g.load(Ordering::Relaxed),
            total_short.load(Ordering::Relaxed),
            total_rx_err.load(Ordering::Relaxed)
        ),
    );
    assert_eq!(total_rx_err.load(Ordering::Relaxed), 0, "an RX read failed");
    assert_eq!(
        total_short.load(Ordering::Relaxed),
        0,
        "a transmit was short"
    );
    assert!(max_join <= 1_000_000, "join took {max_join} us (> 1 s)");
}

// ---------- потеря линка (информационно, не критерий GO) ----------

#[test]
#[ignore = "live: needs the lab NIC (see module docs)"]
fn live_sendqueue_linkdown() {
    let lab = lab();
    let api = load();
    let tpl = syn_frames(&lab);
    let batch = env_u64("RMASSCAN_NPCAP_SQ_BATCH", 16) as usize;
    let secs = env_u64("RMASSCAN_NPCAP_SQ_SECS", 25);
    let pps = env_u64("RMASSCAN_NPCAP_SQ_PPS", 5_000) as f64;
    let mut tx = open_tx_product(&api, &lab);
    let mut q = SendQueue::alloc(&api, sq_queue_bytes(batch)).unwrap();
    let mut f = Vec::new();
    let mut seq = 0u32;
    let mut rows = TxRows::default();
    let mut short = Vec::new();
    let start = Instant::now();
    let mut frames = 0u64;
    while start.elapsed() < Duration::from_secs(secs) {
        let t = now_ms();
        let (queued, sent, d) = sq_batch(&lab, &tpl, &mut tx, &mut q, batch, &mut seq, &mut f);
        rows.push(t, batch, queued, sent, d);
        if sent != queued {
            let sizes = q.record_sizes();
            let mut acc = 0u32;
            let on_b = sent == 0
                || sizes.iter().any(|s| {
                    acc += *s;
                    acc == sent
                });
            short.push(format!(
                "t={t} queued={queued} sent={sent} on_boundary={on_b} geterr={:?}",
                tx.last_error()
            ));
        }
        frames += batch as u64;
        pace(start, frames, pps);
    }
    rows.csv(&lab, "sq_linkdown");
    rows.summary(&lab, "sq_linkdown", batch);
    kv(
        &lab,
        "sq_linkdown_frames",
        &format!("{frames} seq_end={seq}"),
    );
    kv(&lab, "sq_linkdown_short_count", &short.len().to_string());
    for s in short.iter().take(20) {
        kv(&lab, "sq_linkdown_short", s);
    }
}
