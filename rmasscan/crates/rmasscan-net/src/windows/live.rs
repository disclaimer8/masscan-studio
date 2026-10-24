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
//! 198.18.0.2). The management NIC is never named. One frame per
//! `pcap_sendpacket`: no sendqueue, no detached thread; stop is observed
//! between calls only.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rmasscan_core::packet::{LinkType, TcpSynTemplate};

use super::ffi::PcapStat;
use super::handle::{DropCounter, NextEx, OpenParams, PcapHandle, list_devices};
use super::loader::NpcapApi;

const SRC_IP: u32 = 0xC612_0001; // 198.18.0.1
const DST_IP: u32 = 0xC612_0002; // 198.18.0.2
const JUNK_ETHERTYPE: u16 = 0x88b5;
const MAGIC: &[u8; 4] = b"RMSP";
const MS50: Duration = Duration::from_millis(50);

// ---------- окружение ----------

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

fn lab() -> Lab {
    Lab {
        device: need("RMASSCAN_NPCAP_LAB_DEVICE"),
        src_mac: parse_mac(&need("RMASSCAN_NPCAP_LAB_SRC_MAC")),
        peer_mac: parse_mac(&need("RMASSCAN_NPCAP_LAB_PEER_MAC")),
        out_dir: need("RMASSCAN_NPCAP_OUT_DIR"),
        cond: std::env::var("RMASSCAN_NPCAP_COND").unwrap_or_else(|_| "unlabelled".into()),
    }
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

/// TX handle: минимальный буфер ядра, чтобы непрочитанный захват не копился.
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

    // Ошибки открытия: несуществующее устройство (create успешен, activate нет).
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
    for round in 0..rounds {
        let stop = AtomicBool::new(false);
        let bad_rc = std::sync::atomic::AtomicU64::new(0);
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
                    let _ = recv_deadline(&mut rx, &mut b, MS50, Wait::Hybrid);
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
