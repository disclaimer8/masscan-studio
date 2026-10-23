//! Фиктивный адаптер в памяти для тестов: записывает отправленные кадры и
//! выдаёт заранее заданные ответы, ошибки, задержки и дубли. Сокетов и сетевого
//! API здесь нет. Детерминированные часы: [`ManualClock`].

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use rmasscan_core::throttle::Clock;

use crate::io::{AdapterPair, IoError, Rx, SendStatus, Tx};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Детерминированные часы. Время двигают только `advance`, `sleep_micros`
/// (режим по умолчанию: сон мгновенно продвигает время) и фиктивный Rx на
/// простое. В режиме `hold` сон НЕ продвигает время и спит реально по 1 мс:
/// так тест удерживает поток внутри ожидания throttle, пока не выставит отмену.
#[derive(Debug)]
pub struct ManualClock {
    micros: AtomicU64,
    hold: AtomicBool,
    sleeps: AtomicU64,
}

impl ManualClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            micros: AtomicU64::new(1_000_000),
            hold: AtomicBool::new(false),
            sleeps: AtomicU64::new(0),
        })
    }

    pub fn advance_micros(&self, us: u64) {
        self.micros.fetch_add(us, Ordering::AcqRel);
    }

    pub fn advance(&self, d: Duration) {
        self.advance_micros(d.as_micros() as u64);
    }

    pub fn set_hold(&self, hold: bool) {
        self.hold.store(hold, Ordering::Release);
    }

    /// Сколько раз кто-то вызвал `sleep_micros`.
    pub fn sleep_calls(&self) -> u64 {
        self.sleeps.load(Ordering::Acquire)
    }
}

impl Clock for ManualClock {
    fn now_micros(&self) -> u64 {
        self.micros.load(Ordering::Acquire)
    }

    fn sleep_micros(&self, us: u64) {
        self.sleeps.fetch_add(1, Ordering::AcqRel);
        if self.hold.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        } else {
            self.advance_micros(us);
            std::thread::yield_now();
        }
    }
}

/// Шаг сценария отправки (по умолчанию `Sent`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxStep {
    Sent,
    WouldBlockUnsent,
    Uncertain,
    Fail(String),
    /// Сон по часам адаптера, затем `Sent`.
    DelayThenSent(u64),
}

/// Шаг сценария приёма. Пустая очередь = таймаут (`Ok(None)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RxStep {
    Frame(Vec<u8>),
    Fail(String),
    /// Столько таймаутов подряд.
    Idle(u32),
}

type Responder = Box<dyn FnMut(&[u8]) -> Vec<Vec<u8>> + Send>;
type SendHook = Arc<dyn Fn(usize) + Send + Sync>;

#[derive(Default)]
struct State {
    tx_script: VecDeque<TxStep>,
    rx: VecDeque<RxStep>,
    sent: Vec<Vec<u8>>,
    uncertain: Vec<Vec<u8>>,
    would_block: u64,
    send_calls: u64,
    responder: Option<Responder>,
    hook: Option<SendHook>,
}

/// Фиктивный адаптер. Клонирование даёт второй вид на то же состояние (для
/// теста), handles Tx/Rx берутся через [`FakeAdapter::pair`].
#[derive(Clone)]
pub struct FakeAdapter {
    st: Arc<Mutex<State>>,
    clock: Option<Arc<ManualClock>>,
    alive: Arc<AtomicUsize>,
}

impl Default for FakeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeAdapter {
    pub fn new() -> Self {
        Self {
            st: Arc::new(Mutex::new(State::default())),
            clock: None,
            alive: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Подключает часы: пустой приём продвигает их на таймаут, задержки
    /// отправки спят по ним.
    pub fn with_clock(mut self, clock: Arc<ManualClock>) -> Self {
        self.clock = Some(clock);
        self
    }

    pub fn script_tx(&self, steps: impl IntoIterator<Item = TxStep>) {
        lock(&self.st).tx_script.extend(steps);
    }

    pub fn push_rx(&self, step: RxStep) {
        lock(&self.st).rx.push_back(step);
    }

    pub fn push_frame(&self, frame: Vec<u8>) {
        self.push_rx(RxStep::Frame(frame));
    }

    /// Один и тот же кадр `n` раз (дубли).
    pub fn push_frame_n(&self, frame: &[u8], n: usize) {
        let mut st = lock(&self.st);
        for _ in 0..n {
            st.rx.push_back(RxStep::Frame(frame.to_vec()));
        }
    }

    /// Реактивный ответчик: на каждый УСПЕШНО отправленный кадр возвращает
    /// кадры, которые Rx выдаст следом.
    pub fn set_responder(&self, f: impl FnMut(&[u8]) -> Vec<Vec<u8>> + Send + 'static) {
        lock(&self.st).responder = Some(Box::new(f));
    }

    /// Хук после каждой успешной отправки (аргумент: сколько кадров ушло).
    /// Вызывается в потоке TX вне блокировок адаптера, внутри `send`.
    pub fn set_send_hook(&self, f: impl Fn(usize) + Send + Sync + 'static) {
        lock(&self.st).hook = Some(Arc::new(f));
    }

    /// Кадры со статусом `Sent`, по порядку.
    pub fn sent_frames(&self) -> Vec<Vec<u8>> {
        lock(&self.st).sent.clone()
    }

    pub fn sent_count(&self) -> usize {
        lock(&self.st).sent.len()
    }

    pub fn uncertain_frames(&self) -> Vec<Vec<u8>> {
        lock(&self.st).uncertain.clone()
    }

    pub fn would_block_count(&self) -> u64 {
        lock(&self.st).would_block
    }

    /// Все вызовы `send`, включая неуспешные.
    pub fn send_calls(&self) -> u64 {
        lock(&self.st).send_calls
    }

    /// Сколько выданных handle ещё не уничтожено (проверка join/освобождения).
    pub fn alive_handles(&self) -> usize {
        self.alive.load(Ordering::Acquire)
    }

    /// Выдаёт новую пару handle (каждый для своего потока).
    pub fn pair(&self) -> AdapterPair {
        self.alive.fetch_add(2, Ordering::AcqRel);
        AdapterPair {
            tx: Box::new(FakeTx {
                a: self.clone(),
                _live: Live(self.alive.clone()),
            }),
            rx: Box::new(FakeRx {
                a: self.clone(),
                _live: Live(self.alive.clone()),
            }),
        }
    }
}

struct Live(Arc<AtomicUsize>);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct FakeTx {
    a: FakeAdapter,
    _live: Live,
}

impl Tx for FakeTx {
    fn send(&mut self, frame: &[u8], _timeout: Duration) -> Result<SendStatus, IoError> {
        let step = {
            let mut st = lock(&self.a.st);
            st.send_calls += 1;
            st.tx_script.pop_front().unwrap_or(TxStep::Sent)
        };
        match step {
            TxStep::Sent => {}
            TxStep::DelayThenSent(us) => {
                if let Some(c) = &self.a.clock {
                    c.sleep_micros(us);
                }
            }
            TxStep::WouldBlockUnsent => {
                lock(&self.a.st).would_block += 1;
                return Ok(SendStatus::WouldBlockUnsent);
            }
            TxStep::Uncertain => {
                lock(&self.a.st).uncertain.push(frame.to_vec());
                return Ok(SendStatus::Uncertain);
            }
            TxStep::Fail(m) => return Err(IoError::new(m)),
        }
        let (count, hook) = {
            let mut st = lock(&self.a.st);
            st.sent.push(frame.to_vec());
            if let Some(r) = st.responder.as_mut() {
                let replies = r(frame);
                st.rx.extend(replies.into_iter().map(RxStep::Frame));
            }
            (st.sent.len(), st.hook.clone())
        };
        if let Some(h) = hook {
            h(count);
        }
        Ok(SendStatus::Sent)
    }
}

struct FakeRx {
    a: FakeAdapter,
    _live: Live,
}

impl FakeRx {
    fn idle(&self, timeout: Duration) {
        if let Some(c) = &self.a.clock {
            c.advance(timeout);
        }
        std::thread::sleep(Duration::from_micros(100));
    }
}

impl Rx for FakeRx {
    fn recv(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<Option<usize>, IoError> {
        let step = lock(&self.a.st).rx.pop_front();
        match step {
            Some(RxStep::Frame(f)) => {
                let n = f.len().min(buffer.len());
                buffer[..n].copy_from_slice(&f[..n]);
                Ok(Some(n))
            }
            Some(RxStep::Fail(m)) => Err(IoError::new(m)),
            Some(RxStep::Idle(k)) => {
                if k > 1 {
                    lock(&self.a.st).rx.push_front(RxStep::Idle(k - 1));
                }
                self.idle(timeout);
                Ok(None)
            }
            None => {
                self.idle(timeout);
                Ok(None)
            }
        }
    }
}

// ---------------------------------------------------------- frame helper ---

fn rfc1071(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let all: Vec<u8> = parts.concat();
    for c in all.chunks(2) {
        sum += u32::from(c[0]) << 8 | u32::from(*c.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Строит корректный ответ (Ethernet/IPv4/TCP, верные суммы) на наш SYN-кадр:
/// `flags` 0x12 даёт SYN-ACK, 0x04 даёт RST. ack = seqno + 1, как у
/// настоящего хоста, поэтому проходит проверку cookie. `None`, если вход не
/// похож на наш Ethernet SYN.
pub fn reply_to_syn(syn: &[u8], flags: u8) -> Option<Vec<u8>> {
    if syn.len() < 14 + 20 + 20 || syn[12..14] != [0x08, 0x00] {
        return None;
    }
    let ip = &syn[14..];
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    let tcp = ip.get(ihl..ihl + 20)?;
    let (src, dst) = (&ip[12..16], &ip[16..20]);
    let seq = u32::from_be_bytes(tcp[4..8].try_into().ok()?);

    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&tcp[2..4]); // sport = их dport
    t[2..4].copy_from_slice(&tcp[0..2]);
    t[4..8].copy_from_slice(&0x0bad_f00du32.to_be_bytes());
    t[8..12].copy_from_slice(&seq.wrapping_add(1).to_be_bytes());
    t[12] = 5 << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&1024u16.to_be_bytes());
    let mut i = vec![0u8; 20];
    i[0] = 0x45;
    i[2..4].copy_from_slice(&40u16.to_be_bytes());
    i[8] = 64;
    i[9] = 6;
    i[12..16].copy_from_slice(dst); // от цели к нам
    i[16..20].copy_from_slice(src);
    let c = rfc1071(&[&i]);
    i[10..12].copy_from_slice(&c.to_be_bytes());
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&i[12..16]);
    pseudo.extend_from_slice(&i[16..20]);
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&20u16.to_be_bytes());
    let c = rfc1071(&[&pseudo, &t]);
    t[16..18].copy_from_slice(&c.to_be_bytes());

    let mut f = Vec::with_capacity(54);
    f.extend_from_slice(&syn[6..12]); // dst mac = наш src mac
    f.extend_from_slice(&syn[0..6]);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(&i);
    f.extend_from_slice(&t);
    Some(f)
}
