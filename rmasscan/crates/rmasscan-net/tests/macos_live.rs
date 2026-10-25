//! Живые испытания macOS-адаптера через ПУБЛИЧНЫЙ API и общий runtime
//! (`open_explicit` + `Engine`) на запечатанном стенде `feth4201` (сторона
//! сканера) ↔ `feth4202` (сторона пира). Каждый тест `#[ignore]` и требует
//! окружения; без него он ПАДАЕТ как «NOT RUN», а не проходит молча. В обычном
//! `cargo test` и CI пакетов нет.
//!
//! Запуск оператором на стенде (стенд поднят пользователем `macos-lab up`,
//! доступ к `/dev/bpf*` выдан `macos-lab bpf-access --grant`):
//!   cargo test --locked -p rmasscan-net --test macos_live -- --ignored --test-threads=1
//!   (тесты ещё и сериализуются статическим замком внутри процесса)
//!
//! Окружение (обе переменные обязательны):
//!   RMASSCAN_BPF_LAB_MANIFEST  манифест стенда (`/var/run/rmasscan-lab/m1.json`, root, 0644);
//!                              он только подтверждает стенд: интерфейсы, MAC и IP
//!                              обязаны совпасть с константами плана, `state` = `sealed`
//!   RMASSCAN_BPF_OUT_DIR       каталог для строк `KV` (`macos_live__<тест>.txt`)
//!
//! Пир для `full_scan`: тест сам открывает listener на 198.18.0.2:8000-8007
//! (без root, адрес принадлежит `feth4202`) и закрывает их в конце. Порты 80 и 443
//! закрыты (EACCES при bind без root), «тихих» портов на Darwin нет (syncookies),
//! поэтому открытых ответов ровно 8.
//!
//! Защита ДО любой отправки: оба интерфейса существуют (`iface_exists`), а MAC
//! сканера (константа плана, подтверждённая манифестом) сверяется с ОС только когда ОС его показывает; если ОС
//! скрыла MAC плейсхолдером (Darwin 27), в KV пишется `mac_check=os-masked`, и
//! сверка с плейсхолдером никогда не делается. Каждый кадр, уходящий через
//! runtime, проходит `GuardTx` (MAC стенда, IPv4/TCP, 198.18.0.1 → 198.18.0.2).
//!
//! Свидетели: «пир» в этих тестах это второй адаптер через тот же публичный
//! API на `feth4202` (счётчик SYN, источник мусорных кадров). Независимый
//! свидетель (`tcpdump` на `feth4202`) и захват uplink с ожиданием 0 кадров
//! ведёт оператор снаружи: эти тесты их не заменяют.
#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::{LinkType, TcpSynTemplate};
use rmasscan_core::probe::{AdapterBinding, ReadyPlan};
use rmasscan_core::receive::{PortStatus, Reply};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_engine::{
    AdapterPair, Checkpoint, Engine, EngineHandle, EngineOptions, Event, FailReason, IoError,
    Outcome, Reason, Rx, RxHealth, SendStatus, Tx, TxBatch,
};
use rmasscan_net::{
    NetStats, NetStatsHandle, OpenedAdapter, iface_exists, inventory_bpf, nic_mac, nic_mac_masked,
    open_explicit,
};

const SRC_IP: u32 = 0xC612_0001; // 198.18.0.1
const DST_IP: u32 = 0xC612_0002; // 198.18.0.2
const SEED: u64 = 0x5eed_0b5e_55ed;
/// Порты, которые сканирует тест (80 и 443 вместе с listener-портами 8000-8007).
/// Listener на стороне пира только на 8000-8007 (`PEER_LISTEN`): bind на 80 и 443
/// без root на macOS даёт EACCES, поэтому 80 и 443 тут ЗАКРЫТЫ (RST ядра, с
/// ограничением частоты), как и остальные порты вне `PEER_LISTEN`.
const OPEN_PORTS: &str = "80,443,8000-8007";
/// Единственные открытые порты стенда Mac: listener на 198.18.0.2.
const PEER_LISTEN: std::ops::RangeInclusive<u16> = 8000..=8007;
const JUNK_ETHERTYPE: [u8; 2] = [0x88, 0xb5];
/// Окно простоя читателя в тесте потери RX (от старта движка).
const STALL: (Duration, Duration) = (Duration::from_millis(1800), Duration::from_millis(3400));
/// Константы плана стенда: манифест их лишь подтверждает.
const SCAN_IF: &str = "feth4201";
const PEER_IF: &str = "feth4202";
const SRC_MAC: [u8; 6] = [0x02, 0xac, 0x00, 0x00, 0x00, 0x01];
const PEER_MAC: [u8; 6] = [0x02, 0xac, 0x00, 0x00, 0x00, 0x02];

/// Живые тесты делят стенд: по одному за раз (мусор и свидетели иначе смешиваются).
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------- окружение ----------

fn need(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("NOT RUN: environment variable {name} is not set"))
}

/// Строковое значение ключа из манифеста (минимальный разбор: формат
/// записывает `macos-lab`, ключи верхнего уровня, значения строки).
fn manifest_str(text: &str, key: &str) -> Option<String> {
    let at = text.find(&format!("\"{key}\""))? + key.len() + 2;
    let rest = text[at..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    Some(rest[..rest.find('"')?].to_string())
}

fn parse_mac(s: &str) -> [u8; 6] {
    let v: Vec<u8> = s
        .split(':')
        .map(|p| u8::from_str_radix(p, 16).unwrap_or_else(|_| panic!("bad MAC {s:?}")))
        .collect();
    v.try_into()
        .unwrap_or_else(|_| panic!("MAC needs 6 octets: {s:?}"))
}

#[derive(Clone)]
struct Lab {
    out_dir: String,
    test: &'static str,
    scan_if: String,
    peer_if: String,
    src_mac: [u8; 6],
    peer_mac: [u8; 6],
}

/// Читает окружение и манифест и ДО любой отправки проверяет стенд.
fn lab(test: &'static str) -> Lab {
    let manifest = need("RMASSCAN_BPF_LAB_MANIFEST");
    let text = std::fs::read_to_string(&manifest)
        .unwrap_or_else(|e| panic!("NOT RUN: cannot read the stand manifest {manifest}: {e}"));
    let field =
        |k: &str| manifest_str(&text, k).unwrap_or_else(|| panic!("NOT RUN: manifest lacks {k:?}"));
    // Манифест подтверждает, но не задаёт стенд: каждое значение сверяется с константой.
    for (k, want) in [
        ("scanner_if", SCAN_IF),
        ("peer_if", PEER_IF),
        ("scanner_mac", "02:ac:00:00:00:01"),
        ("peer_mac", "02:ac:00:00:00:02"),
        ("source_ip", "198.18.0.1"),
        ("peer_ip", "198.18.0.2"),
        ("state", "sealed"),
    ] {
        let got = field(k);
        assert_eq!(
            got, want,
            "REFUSING TO SEND: manifest {k} is {got:?}, the plan says {want:?}"
        );
    }
    assert_eq!(parse_mac(&field("scanner_mac")), SRC_MAC);
    assert_eq!(parse_mac(&field("peer_mac")), PEER_MAC);
    let l = Lab {
        out_dir: need("RMASSCAN_BPF_OUT_DIR"),
        test,
        scan_if: SCAN_IF.to_string(),
        peer_if: PEER_IF.to_string(),
        src_mac: SRC_MAC,
        peer_mac: PEER_MAC,
    };
    for name in [&l.scan_if, &l.peer_if] {
        assert_eq!(
            iface_exists(name),
            Some(true),
            "NOT RUN: interface {name} does not exist"
        );
    }
    let mac_check = match nic_mac(&l.scan_if) {
        Some(m) => {
            assert_eq!(
                m, l.src_mac,
                "REFUSING TO SEND: {} has MAC {m:02x?}, the manifest says {:02x?}",
                l.scan_if, l.src_mac
            );
            "os-verified"
        }
        None if nic_mac_masked(&l.scan_if) => "os-masked",
        None => panic!(
            "NOT RUN: the OS neither shows the MAC of {} nor reports it masked; the gate cannot be verified",
            l.scan_if
        ),
    };
    kv(
        &l,
        "gate",
        &format!(
            "scanner_if={} peer_if={} src_mac={:02x?} peer_mac={:02x?} mac_check={mac_check}",
            l.scan_if, l.peer_if, l.src_mac, l.peer_mac
        ),
    );
    l
}

/// Строка в stdout и в `macos_live__<тест>.txt`; ошибка записи это паника.
fn kv(lab: &Lab, what: &str, body: &str) {
    let line = format!("KV {}/{what} {body}", lab.test);
    println!("{line}");
    let path = format!("{}/macos_live__{}.txt", lab.out_dir, lab.test);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("cannot open evidence file {path}: {e}"));
    writeln!(f, "{line}").unwrap_or_else(|e| panic!("cannot write evidence file {path}: {e}"));
}

fn scan_binding(lab: &Lab) -> AdapterBinding {
    AdapterBinding {
        interface_id: lab.scan_if.clone(),
        link_type: LinkType::Ethernet,
        source_ipv4: SRC_IP,
        source_mac: lab.src_mac,
        next_hop_mac: lab.peer_mac,
        source_ports: (40000, 40000),
    }
}

/// Привязка стороны пира: источник MAC пира, следующий хоп MAC сканера.
fn peer_binding(lab: &Lab) -> AdapterBinding {
    AdapterBinding {
        interface_id: lab.peer_if.clone(),
        link_type: LinkType::Ethernet,
        source_ipv4: DST_IP,
        source_mac: lab.peer_mac,
        next_hop_mac: lab.src_mac,
        source_ports: (40000, 40000),
    }
}

fn plan(lab: &Lab, ports: &str, rate: f64, wait: u32) -> ReadyPlan {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), "198.18.0.2").unwrap();
    parse_ports(m.ports_mut(), ports).unwrap();
    let cfg = ScanConfig {
        targets: m,
        seed: SEED,
        max_rate: rate,
        wait_secs: wait,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).unwrap();
    ReadyPlan::new(eff, scan_binding(lab)).unwrap()
}

// ---------- защита и декораторы ----------

/// Единственный путь кадра сканера в сеть: адреса и протокол стенда.
fn assert_lab_frame(f: &[u8]) {
    assert!(f.len() >= 54, "frame too short for IPv4 + TCP");
    assert_eq!(f[0..6], PEER_MAC, "dst MAC is not the stand peer");
    assert_eq!(f[6..12], SRC_MAC, "src MAC is not the scanner interface");
    assert_eq!(f[12..14], [0x08, 0x00], "not IPv4");
    assert_eq!(f[23], 6, "not TCP");
    assert_eq!(f[26..30], SRC_IP.to_be_bytes(), "src IP is not 198.18.0.1");
    assert_eq!(f[30..34], DST_IP.to_be_bytes(), "dst IP is not 198.18.0.2");
}

struct GuardTx {
    inner: Box<dyn Tx>,
    /// После стольких реальных отправок вернуть `Uncertain`, не вызывая
    /// адаптер (синтетический сбой для проверки runtime).
    uncertain_after: Option<u64>,
    n: u64,
}

impl Tx for GuardTx {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError> {
        assert_lab_frame(frame);
        if self.uncertain_after == Some(self.n) {
            return Ok(SendStatus::Uncertain);
        }
        let r = self.inner.send(frame, timeout)?;
        if r == SendStatus::Sent {
            self.n += 1;
        }
        Ok(r)
    }

    fn max_batch(&self) -> usize {
        self.inner.max_batch()
    }

    /// Каждый кадр пачки проверяется до проброса; `uncertain_after` режет
    /// пачку ровно на своём номере.
    fn send_batch(&mut self, frames: &[&[u8]], timeout: Duration) -> Result<TxBatch, IoError> {
        for f in frames {
            assert_lab_frame(f);
        }
        let room = self
            .uncertain_after
            .filter(|&t| t >= self.n)
            .map(|t| usize::try_from(t - self.n).unwrap_or(usize::MAX));
        let take = room.map_or(frames.len(), |r| frames.len().min(r));
        if take == 0 {
            return Ok(TxBatch {
                sent: 0,
                rest: SendStatus::Uncertain,
            });
        }
        let r = self.inner.send_batch(&frames[..take], timeout)?;
        self.n += r.sent as u64;
        if r.rest == SendStatus::Sent && take < frames.len() {
            return Ok(TxBatch {
                sent: r.sent,
                rest: SendStatus::Uncertain,
            });
        }
        Ok(r)
    }
}

/// Читатель, который окно времени не читает (кадры копятся в буфере BPF).
struct StalledRx {
    inner: Box<dyn Rx>,
    from: Instant,
    until: Instant,
}

impl Rx for StalledRx {
    fn recv(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<Option<usize>, IoError> {
        let now = Instant::now();
        if now >= self.from && now < self.until {
            std::thread::sleep(timeout.min(Duration::from_millis(10)));
            return Ok(None);
        }
        self.inner.recv(buffer, timeout)
    }

    fn health(&mut self, timeout: Duration) -> Result<RxHealth, IoError> {
        self.inner.health(timeout)
    }
}

// ---------- свидетель на стороне пира ----------

#[derive(Default, Clone)]
struct WState {
    syns: u64,
    ports: Vec<u16>,
    alive: bool,
    drops: Option<u64>,
}

/// RX-адаптер на `feth4202`: считает SYN сканера (src MAC сканера, IPv4/TCP,
/// флаг SYN без ACK) и запоминает порты назначения, пока жив. Это свидетель в
/// процессе теста, не замена `tcpdump` оператора. Его показания годны только
/// если поток жив и `kernel_drops == Some(0)`: иначе тест INVALID, не PASS.
struct PeerWitness {
    st: Arc<Mutex<WState>>,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl PeerWitness {
    fn start(lab: &Lab, mut rx: Box<dyn Rx>) -> Self {
        let st = Arc::new(Mutex::new(WState {
            alive: true,
            ..WState::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let (st2, stop2, src) = (Arc::clone(&st), Arc::clone(&stop), lab.src_mac);
        let join = std::thread::spawn(move || {
            let mut buf = vec![0u8; 2048];
            while !stop2.load(Ordering::Relaxed) {
                match rx.recv(&mut buf, Duration::from_millis(20)) {
                    Ok(Some(n)) => {
                        let f = &buf[..n];
                        let ihl = f.get(14).map_or(0, |b| usize::from(b & 0x0f) * 4);
                        // Все индексы ограничены длиной кадра.
                        let syn = ihl >= 20
                            && n >= 14 + ihl + 14
                            && f[6..12] == src
                            && f[12..14] == [0x08, 0x00]
                            && f[23] == 6
                            && f[14 + ihl + 13] & 0x12 == 0x02;
                        if syn {
                            let dport = u16::from_be_bytes([f[14 + ihl + 2], f[14 + ihl + 3]]);
                            let mut s = st2.lock().unwrap();
                            s.syns += 1;
                            s.ports.push(dport);
                        }
                    }
                    Ok(None) => {}
                    Err(_) => {
                        st2.lock().unwrap().alive = false;
                        return;
                    }
                }
            }
            let drops = rx
                .health(Duration::from_millis(50))
                .ok()
                .and_then(|h| h.kernel_drops);
            st2.lock().unwrap().drops = drops;
        });
        PeerWitness {
            st,
            stop,
            join: Some(join),
        }
    }

    fn count(&self) -> u64 {
        self.st.lock().unwrap().syns
    }

    /// Останавливает поток и отдаёт показания; поток, упавший с паникой, это
    /// `alive == false`.
    fn finish(&mut self) -> WState {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take()
            && j.join().is_err()
        {
            self.st.lock().unwrap().alive = false;
        }
        self.st.lock().unwrap().clone()
    }
}

impl Drop for PeerWitness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Показания свидетеля годятся только живыми и без потерь.
fn assert_witness_valid(rep: &WState) {
    assert!(rep.alive, "INVALID: the peer-side witness thread died");
    assert_eq!(
        rep.drops,
        Some(0),
        "INVALID: the peer-side witness lost frames or could not measure loss"
    );
}

/// Охрана инжектора: единственный разрешённый кадр это мусор пира сканеру.
struct GuardPeerTx {
    inner: Box<dyn Tx>,
}

impl Tx for GuardPeerTx {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError> {
        assert_eq!(frame.len(), 60, "injector frame length");
        assert_eq!(frame[0..6], SRC_MAC, "injector dst MAC is not the scanner");
        assert_eq!(frame[6..12], PEER_MAC, "injector src MAC is not the peer");
        assert_eq!(frame[12..14], JUNK_ETHERTYPE, "injector ethertype");
        self.inner.send(frame, timeout)
    }

    fn max_batch(&self) -> usize {
        self.inner.max_batch()
    }

    fn send_batch(&mut self, frames: &[&[u8]], timeout: Duration) -> Result<TxBatch, IoError> {
        for frame in frames {
            assert_eq!(frame.len(), 60, "injector frame length");
            assert_eq!(frame[0..6], SRC_MAC, "injector dst MAC is not the scanner");
            assert_eq!(frame[6..12], PEER_MAC, "injector src MAC is not the peer");
            assert_eq!(frame[12..14], JUNK_ETHERTYPE, "injector ethertype");
        }
        self.inner.send_batch(frames, timeout)
    }
}

/// Открывает адаптер пира и отдаёт (TX, свидетель, статистика).
fn open_peer(lab: &Lab) -> (Box<dyn Tx>, PeerWitness, NetStatsHandle) {
    let o: OpenedAdapter = open_explicit(&peer_binding(lab)).expect("open the peer-side adapter");
    let w = PeerWitness::start(lab, o.io.rx);
    (Box::new(GuardPeerTx { inner: o.io.tx }), w, o.stats)
}

// ---------- запуск движка ----------

struct Run {
    outcome: Outcome,
    replies: Vec<Reply>,
    checkpoint: Option<Checkpoint>,
    stats_final: NetStats,
    /// От вызова `stop`/`pause` до появления исхода.
    command_to_outcome: Option<Duration>,
    sent_at_outcome: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Command {
    None,
    StopAfter(Duration),
    PauseAfterSent(u64),
}

struct Spec<'a> {
    plan: &'a ReadyPlan,
    attempt: u8,
    resume: Option<Checkpoint>,
    command: Command,
    uncertain_after: Option<u64>,
    /// Окно (от старта), в которое читатель стоит.
    stall: Option<(Duration, Duration)>,
    /// Вызывается один раз, когда открыт адаптер сканера и запущен движок;
    /// получает момент старта (для потоков, привязанных к его часам).
    on_start: Option<Box<dyn FnOnce(Instant) + 'a>>,
}

impl<'a> Spec<'a> {
    fn new(plan: &'a ReadyPlan, attempt: u8) -> Self {
        Spec {
            plan,
            attempt,
            resume: None,
            command: Command::None,
            uncertain_after: None,
            stall: None,
            on_start: None,
        }
    }
}

fn run_engine(mut spec: Spec<'_>) -> Run {
    let opened = open_explicit(spec.plan.binding()).expect("open_explicit");
    let stats = opened.stats.clone();
    let started = Instant::now();
    let rx: Box<dyn Rx> = match spec.stall {
        Some((a, b)) => Box::new(StalledRx {
            inner: opened.io.rx,
            from: started + a,
            until: started + b,
        }),
        None => opened.io.rx,
    };
    let io = AdapterPair {
        tx: Box::new(GuardTx {
            inner: opened.io.tx,
            uncertain_after: spec.uncertain_after,
            n: 0,
        }),
        rx,
    };
    let opts = EngineOptions::new([7; 16], [spec.attempt; 16]);
    let h: EngineHandle = match &spec.resume {
        Some(cp) => Engine::resume(spec.plan.clone(), cp.clone(), io, opts),
        None => Engine::start(spec.plan.clone(), io, opts),
    }
    .expect("engine start");
    if let Some(f) = spec.on_start.take() {
        f(started);
    }
    let mut replies = Vec::new();
    let mut commanded_at: Option<Instant> = None;
    let mut command_to_outcome = None;
    let mut sent_at_outcome = 0;
    loop {
        if commanded_at.is_none() {
            let sent = h.progress().sent;
            let fire = match spec.command {
                Command::None => false,
                Command::PauseAfterSent(n) => sent >= n,
                Command::StopAfter(d) => started.elapsed() >= d,
            };
            if fire {
                commanded_at = Some(Instant::now());
                match spec.command {
                    Command::PauseAfterSent(_) => h.pause(),
                    _ => h.stop(),
                }
            }
        }
        if command_to_outcome.is_none()
            && let Some(at) = commanded_at
            && h.outcome().is_some()
        {
            command_to_outcome = Some(at.elapsed());
            sent_at_outcome = h.progress().sent;
        }
        match h.recv_event_timeout(Duration::from_millis(5)) {
            Ok(Event::Results { replies: r }) => replies.extend(r),
            Ok(Event::Finished { .. }) => break,
            Ok(_) => {}
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => break,
        }
    }
    let checkpoint = h.checkpoint();
    let (outcome, rest) = h.join_drain().expect("join");
    for ev in rest {
        if let Event::Results { replies: r } = ev {
            replies.extend(r);
        }
    }
    Run {
        outcome,
        replies,
        checkpoint,
        stats_final: stats.snapshot(),
        command_to_outcome,
        sent_at_outcome,
    }
}

fn summarize(lab: &Lab, what: &str, r: &Run) {
    let s = &r.stats_final;
    kv(
        lab,
        what,
        &format!(
            "reason={:?} sent={} next_index={} received={} rx_health={:?} net.tx_sent={} \
             net.tx_would_block={} net.tx_uncertain={} net.tx_errors={} net.rx_packets={} \
             net.rx_outgoing={} net.rx_truncated={} net.rx_errors={} net.kernel_drops={:?} \
             command_to_outcome_ms={:?} checkpoint={}",
            r.outcome.reason,
            r.outcome.progress.sent,
            r.outcome.progress.next_index,
            r.outcome.progress.received,
            r.outcome.rx_health.kernel_drops,
            s.tx_sent,
            s.tx_would_block,
            s.tx_uncertain,
            s.tx_errors,
            s.rx_packets,
            s.rx_outgoing,
            s.rx_truncated,
            s.rx_errors,
            s.kernel_drops,
            r.command_to_outcome.map(|d| d.as_secs_f64() * 1000.0),
            r.checkpoint.is_some(),
        ),
    );
}

/// После исхода ничего не уходит. Свидетель на стороне пира (второй адаптер на
/// `feth4202`) живёт всё время прогона, поэтому видит каждый SYN, в том числе
/// отправленный между командой и исходом: итог свидетеля обязан РАВНЯТЬСЯ числу
/// отправленных рантаймом (больше значит, что после исхода что-то ушло; меньше
/// значит, что свидетель слеп). Показания принимаются только от живого
/// свидетеля без потерь. Возвращает итог свидетеля.
fn assert_silent_on_the_wire(lab: &Lab, what: &str, w: &mut PeerWitness, sent: u64) -> u64 {
    std::thread::sleep(Duration::from_millis(300));
    let before = w.count();
    std::thread::sleep(Duration::from_millis(700));
    let rep = w.finish();
    kv(
        lab,
        what,
        &format!(
            "witness_syns_settled={before} witness_syns_after={} runtime_sent={sent} witness_alive={} witness_drops={:?}",
            rep.syns, rep.alive, rep.drops
        ),
    );
    assert_witness_valid(&rep);
    assert_eq!(
        before, rep.syns,
        "a SYN reached the peer after the run ended"
    );
    assert_eq!(
        rep.syns, sent,
        "the witness count differs from the runtime's sent"
    );
    rep.syns
}

/// Listener пира на 198.18.0.2:8000-8007 (без root). Живут до конца теста; bind на
/// чужой адрес или занятый порт это NOT RUN, не молчаливый пропуск.
struct PeerListeners {
    _held: Vec<std::net::TcpListener>,
}

impl PeerListeners {
    fn bind() -> Self {
        let ip = std::net::Ipv4Addr::from(DST_IP);
        let held = PEER_LISTEN
            .map(|p| {
                std::net::TcpListener::bind((ip, p))
                    .unwrap_or_else(|e| panic!("NOT RUN: cannot listen on {ip}:{p}: {e}"))
            })
            .collect();
        PeerListeners { _held: held }
    }
}

// =====================================================================
// Полный скан через движок: ровно один advance на Sent
// =====================================================================

#[test]
#[ignore = "live: needs the sealed feth stand (see module docs)"]
fn a_full_scan_through_the_engine_completes_with_exactly_one_advance_per_sent() {
    let _serial = serial();
    let lab = lab("full_scan");
    let ports = format!("{OPEN_PORTS},9000-9009");
    let probes = 2 + 8 + 10;
    let _listeners = PeerListeners::bind();
    let p = plan(&lab, &ports, 100.0, 3);
    for round in 0..2u8 {
        let r = run_engine(Spec::new(&p, 2 + round));
        summarize(&lab, &format!("round{round}"), &r);
        assert_eq!(r.outcome.reason, Reason::Completed, "{:?}", r.outcome);
        assert_eq!(r.outcome.progress.sent, probes);
        assert_eq!(
            r.outcome.progress.next_index, probes,
            "one advance per Sent"
        );
        assert_eq!(r.stats_final.tx_sent, probes);
        assert_eq!(r.stats_final.tx_uncertain, 0);
        // Подтверждённый ноль потерь буфера BPF, из движка и из счётчиков.
        assert_eq!(r.outcome.rx_health.kernel_drops, Some(0));
        assert_eq!(r.stats_final.kernel_drops, Some(0));
        // SYN-ACK открытых портов не ограничиваются ядром; RST закрытых могут
        // ограничиваться (net.inet.tcp.rst_rlc_enable), поэтому для закрытых
        // портов проверяется только статус полученных ответов.
        let mut got: BTreeMap<u16, PortStatus> = BTreeMap::new();
        for rep in &r.replies {
            assert_eq!(rep.remote_ip, DST_IP);
            got.insert(rep.remote_port, rep.status);
        }
        for (port, st) in &got {
            let open = PEER_LISTEN.contains(port);
            let want = if open {
                PortStatus::Open
            } else {
                PortStatus::Closed
            };
            assert_eq!(*st, want, "port {port}");
        }
        let open_seen = got.values().filter(|s| **s == PortStatus::Open).count();
        assert_eq!(
            open_seen,
            PEER_LISTEN.count(),
            "every listener port (8000-8007) must answer SYN-ACK: {got:?}"
        );
    }
}

// =====================================================================
// Stop, Pause/Resume, Uncertain, потеря RX через общий runtime
// =====================================================================

#[test]
#[ignore = "live: needs the sealed feth stand (see module docs)"]
fn stop_ends_the_run_quickly_and_nothing_is_sent_afterwards() {
    let _serial = serial();
    let lab = lab("stop");
    let (_peer_tx, mut witness, _) = open_peer(&lab);
    let p = plan(&lab, "1-2000", 300.0, 3);
    let mut spec = Spec::new(&p, 2);
    spec.command = Command::StopAfter(Duration::from_millis(1500));
    let r = run_engine(spec);
    summarize(&lab, "stop", &r);
    assert_eq!(r.outcome.reason, Reason::Stopped, "{:?}", r.outcome);
    let d = r.command_to_outcome.expect("stop was commanded");
    assert!(d < Duration::from_secs(1), "Stop took {d:?}");
    assert!(r.outcome.progress.sent > 100 && r.outcome.progress.sent < 2000);
    assert_eq!(r.stats_final.tx_sent, r.outcome.progress.sent);
    // TX остановился не позже, чем появился исход.
    assert_eq!(r.sent_at_outcome, r.outcome.progress.sent);
    assert_eq!(r.outcome.rx_health.kernel_drops, Some(0));
    let seen =
        assert_silent_on_the_wire(&lab, "stop_silence", &mut witness, r.outcome.progress.sent);
    assert!(seen > 0, "the peer-side witness saw no SYN at all");
}

#[test]
#[ignore = "live: needs the sealed feth stand (see module docs)"]
fn pause_stops_tx_then_resume_continues_without_gaps_or_duplicates() {
    let _serial = serial();
    let lab = lab("pause_resume");
    let (_peer_tx, mut witness, _) = open_peer(&lab);
    let p = plan(&lab, "9000-9011", 10.0, 3);
    let mut s = Spec::new(&p, 2);
    s.command = Command::PauseAfterSent(4);
    let leg1 = run_engine(s);
    summarize(&lab, "leg1", &leg1);
    assert_eq!(leg1.outcome.reason, Reason::Paused, "{:?}", leg1.outcome);
    let d = leg1.command_to_outcome.expect("pause was commanded");
    assert!(
        d < Duration::from_secs(3 + 1),
        "pause + RX drain wait=3 must finish within 4 s, took {d:?}"
    );
    let cp = leg1
        .checkpoint
        .clone()
        .expect("paused run has a checkpoint");
    assert_eq!(cp.next_index, leg1.outcome.progress.sent);
    assert_eq!(leg1.stats_final.tx_sent, leg1.outcome.progress.sent);
    assert_eq!(leg1.outcome.rx_health.kernel_drops, Some(0));
    // TX остановился не позже 1 с после команды: в окно drain ничего не уходило.
    assert_eq!(leg1.sent_at_outcome, leg1.outcome.progress.sent);

    let mut s = Spec::new(&p, 3);
    s.resume = Some(cp);
    let leg2 = run_engine(s);
    summarize(&lab, "leg2", &leg2);
    assert_eq!(leg2.outcome.reason, Reason::Completed, "{:?}", leg2.outcome);
    assert_eq!(
        leg1.stats_final.tx_sent + leg2.stats_final.tx_sent,
        12,
        "exactly one send per probe across both legs"
    );
    // Ни пропусков, ни дублей: свидетель на стороне пира видел SYN на каждый порт
    // 9000..=9011 ровно один раз за обе части (RST закрытых портов могут
    // ограничиваться ядром, поэтому доказательство идёт по SYN, а не по ответам).
    std::thread::sleep(Duration::from_millis(300));
    let rep = witness.finish();
    let mut ports = rep.ports.clone();
    ports.sort_unstable();
    kv(
        &lab,
        "witness_ports",
        &format!("alive={} drops={:?} ports={ports:?}", rep.alive, rep.drops),
    );
    assert_witness_valid(&rep);
    assert_eq!(
        ports,
        (9000..=9011).collect::<Vec<u16>>(),
        "gap or duplicate"
    );
}

/// Сколько мусорных кадров нужно, чтобы переполнить буфер BPF сканера: больше
/// 2 × размера буфера (store + hold) с запасом 1.5. Размер берётся из
/// `debug.bpf_maxbufsize` (адаптер просит `min(4 MiB, это значение)`), запись
/// BPF для 60-байтового кадра занимает 80 байт (заголовок 18 + кадр, выравнивание 4).
fn junk_frames_needed() -> (u64, u64) {
    let maxbuf = u64::from(
        inventory_bpf()
            .expect("inventory_bpf")
            .bpf_maxbufsize
            .expect("debug.bpf_maxbufsize is unreadable"),
    );
    let buflen = maxbuf.min(4 << 20);
    const RECORD: u64 = 80;
    (buflen, (buflen * 2 * 3 / 2).div_ceil(RECORD))
}

fn junk_frame(lab: &Lab, i: u64) -> Vec<u8> {
    let mut f = vec![0u8; 60];
    f[0..6].copy_from_slice(&lab.src_mac); // адресовано сканеру
    f[6..12].copy_from_slice(&lab.peer_mac); // от пира (не наш MAC: фильтр ядра пропускает)
    f[12..14].copy_from_slice(&JUNK_ETHERTYPE);
    f[14..22].copy_from_slice(&i.to_be_bytes());
    f
}

#[test]
#[ignore = "live: needs the sealed feth stand (see module docs)"]
fn rx_loss_from_a_stalled_reader_fails_the_run_and_keeps_the_results() {
    let _serial = serial();
    let lab = lab("rx_loss");
    let (buflen, needed) = junk_frames_needed();
    kv(
        &lab,
        "load",
        &format!("bpf_buffer_len={buflen} junk_frames_needed={needed} ethertype=0x88b5"),
    );
    // Нагрузка идёт со стороны пира (второй адаптер через публичный API), а не
    // от RST ядра: RST ограничиваются (net.inet.tcp.rst_rlc_enable). Сканер
    // сначала нормально читает ответы, затем читатель стоит, и в это окно пир
    // заливает feth4201 мусором.
    let (mut peer_tx, _witness, peer_stats) = open_peer(&lab);
    let p = plan(&lab, &format!("{OPEN_PORTS},9000-9099"), 100.0, 4);
    let sent_junk = Arc::new(AtomicU64::new(0));
    let flood_lab = lab.clone();
    let burst_end_ms = Arc::new(AtomicU64::new(u64::MAX));
    let burst_end = Arc::clone(&burst_end_ms);
    let counter = Arc::clone(&sent_junk);
    let mut spec = Spec::new(&p, 2);
    spec.stall = Some((STALL.0, STALL.1));
    let flood: Arc<std::sync::Mutex<Option<std::thread::JoinHandle<()>>>> = Arc::default();
    let flood_slot = Arc::clone(&flood);
    spec.on_start = Some(Box::new(move |started: Instant| {
        let h = std::thread::spawn(move || {
            while started.elapsed() < Duration::from_millis(2000) {
                std::thread::sleep(Duration::from_millis(5));
            }
            let mut i = 0u64;
            while i < needed {
                // Нагрузка обязана уложиться в окно простоя читателя.
                if started.elapsed() > STALL.1 {
                    break;
                }
                let f = junk_frame(&flood_lab, i);
                match peer_tx
                    .send(&f, Duration::from_millis(50))
                    .expect("peer send")
                {
                    SendStatus::Sent => {
                        i += 1;
                        counter.store(i, Ordering::Relaxed);
                    }
                    SendStatus::WouldBlockUnsent => {}
                    SendStatus::Uncertain => panic!("peer-side send was Uncertain"),
                }
            }
            burst_end.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
        });
        *flood_slot.lock().unwrap() = Some(h);
    }));
    let r = run_engine(spec);
    if let Some(h) = flood.lock().unwrap().take() {
        h.join().expect("junk generator");
    }
    summarize(&lab, "rx_loss", &r);
    let ps = peer_stats.snapshot();
    kv(
        &lab,
        "load_result",
        &format!(
            "junk_sent={} peer.tx_sent={} peer.tx_would_block={} scanner.rx_packets={} scanner.kernel_drops={:?}",
            sent_junk.load(Ordering::Relaxed),
            ps.tx_sent,
            ps.tx_would_block,
            r.stats_final.rx_packets,
            r.stats_final.kernel_drops
        ),
    );
    assert_eq!(
        sent_junk.load(Ordering::Relaxed),
        needed,
        "INVALID: the junk generator did not deliver its burst inside the stall window (precondition failed, not a PASS)"
    );
    let end = burst_end_ms.load(Ordering::Relaxed);
    kv(
        &lab,
        "burst_end",
        &format!("burst_end_ms={end} stall_end_ms={}", STALL.1.as_millis()),
    );
    assert!(
        end <= STALL.1.as_millis() as u64,
        "INVALID: the burst ended after the stall window"
    );
    match &r.outcome.reason {
        Reason::Failed(FailReason::RxLoss { kernel_drops }) => {
            assert!(*kernel_drops > 0);
            assert!(r.stats_final.kernel_drops.unwrap_or(0) >= *kernel_drops);
        }
        other => panic!("expected RxLoss after {needed} junk frames, got {other:?}"),
    }
    assert!(r.checkpoint.is_none(), "a lossy run has no checkpoint");
    assert!(
        !r.replies.is_empty(),
        "results gathered before the loss are kept"
    );
}

#[test]
#[ignore = "live: needs the sealed feth stand (see module docs)"]
fn an_uncertain_send_fails_the_run_without_checkpoint_retry_or_more_sends() {
    let _serial = serial();
    let lab = lab("uncertain");
    let (_peer_tx, mut witness, _) = open_peer(&lab);
    let p = plan(&lab, "9100-9119", 100.0, 3);
    let mut s = Spec::new(&p, 2);
    s.uncertain_after = Some(3);
    let r = run_engine(s);
    summarize(&lab, "uncertain", &r);
    assert_eq!(
        r.outcome.reason,
        Reason::Failed(FailReason::TxUncertain),
        "{:?}",
        r.outcome
    );
    assert_eq!(r.outcome.progress.sent, 3);
    assert_eq!(r.stats_final.tx_sent, 3);
    assert!(r.checkpoint.is_none(), "Uncertain forbids a checkpoint");
    assert_silent_on_the_wire(&lab, "uncertain_silence", &mut witness, 3);
}

// =====================================================================
// Задержки отдельных вызовов (для решения спайка об IO_BUDGET)
// =====================================================================

#[derive(Default)]
struct Lat {
    us: Vec<u64>,
}

impl Lat {
    fn push(&mut self, d: Duration) {
        self.us.push(d.as_micros() as u64);
    }
    fn pct(&self, p: f64) -> u64 {
        let mut s = self.us.clone();
        s.sort_unstable();
        if s.is_empty() {
            return 0;
        }
        s[((s.len() as f64 - 1.0) * p).round() as usize]
    }
    fn max(&self) -> u64 {
        self.us.iter().copied().max().unwrap_or(0)
    }
    fn over(&self, limit: Duration) -> usize {
        self.us
            .iter()
            .filter(|u| **u > limit.as_micros() as u64)
            .count()
    }
    fn line(&self, label: &str) -> String {
        format!(
            "{label} n={} p50_us={} p95_us={} p99_us={} max_us={} over50ms={}",
            self.us.len(),
            self.pct(0.5),
            self.pct(0.95),
            self.pct(0.99),
            self.max(),
            self.over(Duration::from_millis(50)),
        )
    }
}

#[test]
#[ignore = "live: needs the sealed feth stand (see module docs)"]
fn per_call_latency_stays_within_the_io_budget() {
    let _serial = serial();
    let lab = lab("latency");
    let opened = open_explicit(&scan_binding(&lab)).expect("open_explicit");
    let AdapterPair { mut tx, mut rx } = opened.io;
    let tpl = TcpSynTemplate::new(lab.src_mac, lab.peer_mac, LinkType::Ethernet);
    let (mut send_l, mut recv_l, mut health_l) = (Lat::default(), Lat::default(), Lat::default());
    let mut buf = vec![0u8; 2048];
    let mut f = Vec::new();
    let mut max_wait_recv = 0u64;
    for i in 0..1000u32 {
        tpl.build_syn(
            DST_IP,
            80,
            SRC_IP,
            41_000 + (i % 1000) as u16,
            0x2000 + i,
            &mut f,
        );
        assert_lab_frame(&f);
        let t = Instant::now();
        let st = tx.send(&f, Duration::from_millis(50)).expect("send");
        send_l.push(t.elapsed());
        assert_eq!(st, SendStatus::Sent);
        let t = Instant::now();
        let _ = rx.recv(&mut buf, Duration::from_millis(50)).expect("recv");
        recv_l.push(t.elapsed());
        if i % 50 == 0 {
            let t = Instant::now();
            rx.health(Duration::from_millis(50)).expect("health");
            health_l.push(t.elapsed());
        }
    }
    // Пустое ожидание: вызов обязан вернуться по таймауту, не позже контракта.
    for _ in 0..20 {
        let t = Instant::now();
        let _ = rx.recv(&mut buf, Duration::from_millis(50)).expect("recv");
        max_wait_recv = max_wait_recv.max(t.elapsed().as_micros() as u64);
    }
    // Максимум на тип вызова (контракт ≤50 мс на вызов): одна строка для отчёта.
    kv(
        &lab,
        "max_per_call",
        &format!(
            "max_us_recv={} max_us_send={} max_us_health={} max_us_idle_recv={max_wait_recv}",
            recv_l.max(),
            send_l.max(),
            health_l.max()
        ),
    );
    kv(&lab, "send", &send_l.line("send"));
    kv(&lab, "recv", &recv_l.line("recv"));
    kv(&lab, "health", &health_l.line("health"));
    kv(
        &lab,
        "idle_recv",
        &format!("idle_recv_max_us={max_wait_recv}"),
    );
    let limit = Duration::from_millis(50);
    assert_eq!(send_l.over(limit), 0, "send exceeded 50 ms");
    assert_eq!(recv_l.over(limit), 0, "recv exceeded 50 ms");
    assert_eq!(health_l.over(limit), 0, "health exceeded 50 ms");
    assert!(
        max_wait_recv <= limit.as_micros() as u64,
        "idle recv exceeded 50 ms"
    );
}
