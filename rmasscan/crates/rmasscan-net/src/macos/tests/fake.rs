//! Подставной шов BPF: `FakeOpener` выдаёт `FakeDev`, все они пишут в один
//! `World` (журнал ioctl, сценарии `write`/`read`/`poll`/`stats`). Состояние
//! принадлежит тесту (`Arc<Mutex<World>>`), глобального состояния нет, поэтому
//! тесты идут параллельно. Первое открытие это RX (устройство 1), второе TX
//! (устройство 2): так их открывает `open_with`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::macos::Errno;
use crate::macos::abi::errno::{EAGAIN, EBUSY, ENOENT};
use crate::macos::abi::{BpfInsn, BpfStat, DLT_EN10MB, SIZEOF_BPF_HDR, bpf_wordalign};
use crate::macos::adapter::{BpfIo, BpfOpener, BpfSetup, Readiness};

pub(super) type Responder = Arc<dyn Fn(&[u8]) -> Vec<Vec<u8>> + Send + Sync>;

pub(super) struct World {
    /// Журнал: `open:N`, `<dev>:<ioctl>[:arg]`, `<dev>:close`.
    pub log: Vec<String>,
    // ---- открытие ----
    /// Узлы с номером `>= node_count` отвечают `ENOENT`.
    pub node_count: u32,
    /// Ошибка открытия конкретного узла.
    pub open_errors: HashMap<u32, Errno>,
    pub next_dev: usize,
    /// Узлы, открытые живыми устройствами: повторное открытие даёт `EBUSY`, как в ядре.
    pub in_use: Vec<u32>,
    // ---- ioctl ----
    /// `(устройство, ioctl, errno)`: этот ioctl этого устройства падает.
    pub setup_fail: Vec<(usize, &'static str, Errno)>,
    pub dlt: u32,
    pub max_buffer: u32,
    /// Что вернёт `BIOCGBLEN` (ядро могло урезать запрошенное).
    pub blen: u32,
    pub filters: Vec<(usize, Vec<BpfInsn>)>,
    // ---- запись ----
    pub writes: VecDeque<Result<usize, Errno>>,
    pub write_forever: Option<Errno>,
    pub write_calls: usize,
    /// Кадры, принятые целиком.
    pub written: Vec<Vec<u8>>,
    pub responder: Option<Responder>,
    /// Принятый целиком кадр возвращается в очередь чтения (как будто фильтр
    /// и `BIOCSSEESENT 0` не сработали).
    pub echo_tx: bool,
    // ---- чтение ----
    pub reads: VecDeque<Result<Vec<u8>, Errno>>,
    pub read_forever: Option<Errno>,
    /// Бесконечный (но конечный по числу) поток мусора: оставшееся число чтений
    /// и сама пачка.
    pub junk: Option<(usize, Vec<u8>)>,
    pub read_calls: usize,
    // ---- poll ----
    pub polls: VecDeque<Result<Readiness, Errno>>,
    pub poll_ms: Vec<i32>,
    pub poll_calls: usize,
    // ---- статистика ----
    pub stats: VecDeque<Result<BpfStat, Errno>>,
    pub stats_drop: u32,
    pub stats_calls: usize,
    // ---- паузы ----
    pub backoffs: Vec<Duration>,
    /// Вызовы по устройствам: `write:2`, `read:1`, `stats:1`.
    pub per_dev: HashMap<String, usize>,
}

impl Default for World {
    fn default() -> Self {
        World {
            log: Vec::new(),
            node_count: 16,
            open_errors: HashMap::new(),
            next_dev: 0,
            in_use: Vec::new(),
            setup_fail: Vec::new(),
            dlt: DLT_EN10MB,
            max_buffer: 524_288,
            blen: 262_144,
            filters: Vec::new(),
            writes: VecDeque::new(),
            write_forever: None,
            write_calls: 0,
            written: Vec::new(),
            responder: None,
            echo_tx: false,
            reads: VecDeque::new(),
            read_forever: None,
            junk: None,
            read_calls: 0,
            polls: VecDeque::new(),
            poll_ms: Vec::new(),
            poll_calls: 0,
            stats: VecDeque::new(),
            stats_drop: 0,
            stats_calls: 0,
            backoffs: Vec::new(),
            per_dev: HashMap::new(),
        }
    }
}

pub(super) type Shared = Arc<Mutex<World>>;

pub(super) fn world() -> Shared {
    Arc::new(Mutex::new(World::default()))
}

pub(super) fn lock(w: &Shared) -> MutexGuard<'_, World> {
    w.lock().unwrap_or_else(|e| e.into_inner())
}

pub(super) fn count(w: &Shared, line: &str) -> usize {
    lock(w).log.iter().filter(|l| *l == line).count()
}

pub(super) fn calls(w: &Shared, key: &str) -> usize {
    lock(w).per_dev.get(key).copied().unwrap_or(0)
}

pub(super) struct FakeOpener {
    pub w: Shared,
}

impl BpfOpener for FakeOpener {
    type Dev = FakeDev;

    fn max_buffer(&self) -> u32 {
        lock(&self.w).max_buffer
    }

    fn open_node(&mut self, index: u32) -> Result<FakeDev, Errno> {
        let mut s = lock(&self.w);
        if index >= s.node_count {
            return Err(ENOENT);
        }
        if s.in_use.contains(&index) {
            s.log.push(format!("open:{index}:err{EBUSY}"));
            return Err(EBUSY);
        }
        if let Some(e) = s.open_errors.get(&index) {
            let e = *e;
            s.log.push(format!("open:{index}:err{e}"));
            return Err(e);
        }
        s.next_dev += 1;
        s.in_use.push(index);
        let id = s.next_dev;
        s.log.push(format!("open:{index}"));
        drop(s);
        Ok(FakeDev {
            w: Arc::clone(&self.w),
            id,
            node: index,
            buflen: 0,
        })
    }
}

pub(super) struct FakeDev {
    w: Shared,
    id: usize,
    node: u32,
    buflen: usize,
}

impl Drop for FakeDev {
    fn drop(&mut self) {
        let id = self.id;
        let mut s = lock(&self.w);
        s.in_use.retain(|n| *n != self.node);
        s.log.push(format!("{id}:close"));
    }
}

impl FakeDev {
    fn bump(&self, s: &mut World, what: &str) {
        *s.per_dev.entry(format!("{what}:{}", self.id)).or_insert(0) += 1;
    }

    /// Журнал ioctl и возможный сценарный отказ.
    fn ioctl(&self, op: &'static str, arg: Option<String>) -> Result<(), Errno> {
        let mut s = lock(&self.w);
        let line = match arg {
            Some(a) => format!("{}:{op}:{a}", self.id),
            None => format!("{}:{op}", self.id),
        };
        s.log.push(line);
        match s
            .setup_fail
            .iter()
            .find(|(d, o, _)| *d == self.id && *o == op)
        {
            Some((_, _, e)) => Err(*e),
            None => Ok(()),
        }
    }
}

impl BpfIo for FakeDev {
    fn write(&mut self, frame: &[u8]) -> Result<usize, Errno> {
        let mut s = lock(&self.w);
        s.write_calls += 1;
        self.bump(&mut s, "write");
        let r = match s.writes.pop_front() {
            Some(r) => r,
            None => match s.write_forever {
                Some(e) => Err(e),
                None => Ok(frame.len()),
            },
        };
        if r == Ok(frame.len()) {
            s.written.push(frame.to_vec());
            let mut batch = Vec::new();
            if s.echo_tx {
                batch.extend(record(SIZEOF_BPF_HDR, frame));
            }
            if let Some(resp) = s.responder.clone() {
                for reply in resp(frame) {
                    batch.extend(record(SIZEOF_BPF_HDR, &reply));
                }
            }
            if !batch.is_empty() {
                s.reads.push_back(Ok(batch));
            }
        }
        r
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut s = lock(&self.w);
        s.read_calls += 1;
        self.bump(&mut s, "read");
        // BPF требует буфер ровно длины BIOCGBLEN.
        assert_eq!(buf.len(), self.buflen, "read buffer must be BIOCGBLEN long");
        let data = match s.reads.pop_front() {
            Some(Ok(d)) => d,
            Some(Err(e)) => return Err(e),
            None => {
                if let Some((left, batch)) = s.junk.as_mut()
                    && *left > 0
                {
                    *left -= 1;
                    batch.clone()
                } else {
                    return Err(s.read_forever.unwrap_or(EAGAIN));
                }
            }
        };
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }

    fn poll_in(&mut self, timeout_ms: i32) -> Result<Readiness, Errno> {
        let next = {
            let mut s = lock(&self.w);
            s.poll_ms.push(timeout_ms);
            s.poll_calls += 1;
            s.polls.pop_front()
        };
        match next {
            Some(r) => r,
            None => {
                // Пустой сценарий: ждём запрошенное и сообщаем таймаут.
                std::thread::sleep(Duration::from_millis(timeout_ms.max(0) as u64));
                Ok(Readiness::Timeout)
            }
        }
    }

    fn stats(&mut self) -> Result<BpfStat, Errno> {
        let mut s = lock(&self.w);
        s.stats_calls += 1;
        self.bump(&mut s, "stats");
        s.log.push(format!("{}:BIOCGSTATS", self.id));
        match s.stats.pop_front() {
            Some(r) => r,
            None => Ok(BpfStat {
                bs_recv: 0,
                bs_drop: s.stats_drop,
            }),
        }
    }

    fn backoff(&mut self, wait: Duration) {
        lock(&self.w).backoffs.push(wait);
        // Часы дедлайна реальные: пауза должна двигать время.
        std::thread::sleep(wait);
    }

    fn buffer_len(&self) -> usize {
        self.buflen
    }
}

impl BpfSetup for FakeDev {
    fn set_buffer_len(&mut self, requested: u32) -> Result<(), Errno> {
        self.ioctl("BIOCSBLEN", Some(requested.to_string()))
    }

    fn bind_interface(&mut self, name: &str) -> Result<(), Errno> {
        self.ioctl("BIOCSETIF", Some(name.to_string()))
    }

    fn data_link(&mut self) -> Result<u32, Errno> {
        self.ioctl("BIOCGDLT", None)?;
        Ok(lock(&self.w).dlt)
    }

    fn set_immediate(&mut self, on: bool) -> Result<(), Errno> {
        self.ioctl("BIOCIMMEDIATE", Some(u8::from(on).to_string()))
    }

    fn set_see_sent(&mut self, on: bool) -> Result<(), Errno> {
        self.ioctl("BIOCSSEESENT", Some(u8::from(on).to_string()))
    }

    fn set_hdr_complete(&mut self, on: bool) -> Result<(), Errno> {
        self.ioctl("BIOCSHDRCMPLT", Some(u8::from(on).to_string()))
    }

    fn set_filter(&mut self, prog: &[BpfInsn]) -> Result<(), Errno> {
        self.ioctl("BIOCSETF", Some(prog.len().to_string()))?;
        lock(&self.w).filters.push((self.id, prog.to_vec()));
        Ok(())
    }

    fn refresh_buffer_len(&mut self) -> Result<(), Errno> {
        self.ioctl("BIOCGBLEN", None)?;
        self.buflen = lock(&self.w).blen as usize;
        Ok(())
    }
}

/// Запись `bpf_hdr` с кадром целиком (`caplen == datalen`), с хвостовым
/// выравниванием до `BPF_ALIGNMENT`.
pub(super) fn record(hdrlen: usize, data: &[u8]) -> Vec<u8> {
    raw_record(hdrlen, data.len() as u32, data.len() as u32, data)
}

/// Запись с произвольными (возможно лживыми) полями заголовка.
pub(super) fn raw_record(hdrlen: usize, caplen: u32, datalen: u32, data: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; hdrlen.max(SIZEOF_BPF_HDR)];
    r[8..12].copy_from_slice(&caplen.to_ne_bytes());
    r[12..16].copy_from_slice(&datalen.to_ne_bytes());
    r[16..18].copy_from_slice(&(hdrlen as u16).to_ne_bytes());
    // Поле hdrlen пишется как есть, даже если оно меньше физического заголовка.
    r.extend_from_slice(data);
    r.resize(bpf_wordalign(r.len()), 0);
    r
}
