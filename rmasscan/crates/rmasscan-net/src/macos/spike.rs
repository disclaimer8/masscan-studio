//! Живой спайк BPF на запечатанном стенде `feth4201` <-> `feth4202` (задача 3 этапа 2C).
//! Временный измерительный код: открывает `/dev/bpfN` напрямую, пишет CSV/логи в
//! `RMASSCAN_BPF_OUT_DIR`. Все тесты `#[ignore]`; без `RMASSCAN_BPF_LAB_MANIFEST`,
//! `RMASSCAN_BPF_OUT_DIR`, `RMASSCAN_BPF_COND` тест падает с `NOT RUN`.
//!
//! Каждый записанный кадр проходит `assert_lab_frame` внутри единственного пути записи
//! [`Dev::send`]: сторона сканера (`feth4201`) шлёт только dst MAC пира, src MAC сканера или
//! спайковый `02:ac:00:00:00:11`, dst IP `198.18.0.2`; сторона пира (`feth4202`) шлёт только
//! ethertype 0x88b5 от пира к сканеру. Ничего другого не записывается.

use std::fmt::Write as _;
use std::io::Write as _;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::abi::{BpfInsn, BpfStat, MAX_HDRLEN, SIZEOF_BPF_HDR, bpf_wordalign, read_record_header};
use super::adapter::{drop_all_filter, own_mac_filter};
use super::sys::{BIOCSETF, BIOCSSEESENT, BpfProgram, ioctl_ptr};

const SCAN: [u8; 6] = [0x02, 0xac, 0, 0, 0, 0x01];
const PEER: [u8; 6] = [0x02, 0xac, 0, 0, 0, 0x02];
const SPIKE: [u8; 6] = [0x02, 0xac, 0, 0, 0, 0x11];
const IF_SCAN: &str = "feth4201";
const IF_PEER: &str = "feth4202";
const SRC_IP: [u8; 4] = [198, 18, 0, 1];
const DST_IP: [u8; 4] = [198, 18, 0, 2];
const ETH_JUNK: u16 = 0x88b5;

// ---------------------------------------------------------------- окружение и вывод

struct Env {
    out: PathBuf,
    cond: String,
}

fn env() -> Env {
    let get = |k: &str| {
        std::env::var(k).unwrap_or_else(|_| panic!("NOT RUN: environment variable {k} is not set"))
    };
    let manifest = get("RMASSCAN_BPF_LAB_MANIFEST");
    let out = PathBuf::from(get("RMASSCAN_BPF_OUT_DIR"));
    let cond = get("RMASSCAN_BPF_COND");
    let text = std::fs::read_to_string(&manifest)
        .unwrap_or_else(|e| panic!("NOT RUN: manifest {manifest}: {e}"));
    for needle in [
        "\"state\": \"sealed\"",
        IF_SCAN,
        IF_PEER,
        "02:ac:00:00:00:01",
    ] {
        assert!(text.contains(needle), "NOT RUN: manifest lacks {needle}");
    }
    std::fs::create_dir_all(&out).expect("create out dir");
    Env { out, cond }
}

struct Log {
    file: std::io::BufWriter<std::fs::File>,
}

impl Log {
    fn new(env: &Env, name: &str) -> Log {
        let f = std::fs::File::create(env.out.join(format!("{name}.log"))).expect("log");
        let mut l = Log {
            file: std::io::BufWriter::new(f),
        };
        l.line(&format!("test={name} cond={}", env.cond));
        l
    }
    fn line(&mut self, s: &str) {
        eprintln!("{s}");
        writeln!(self.file, "{s}").expect("log write");
        self.file.flush().expect("log flush");
    }
    fn stats(&mut self, label: &str, ns: &[u64]) {
        let (p50, p95, max) = pcts(ns);
        self.line(&format!(
            "{label}: n={} p50_us={:.1} p95_us={:.1} max_us={:.1}",
            ns.len(),
            p50 as f64 / 1e3,
            p95 as f64 / 1e3,
            max as f64 / 1e3
        ));
    }
}

fn pcts(ns: &[u64]) -> (u64, u64, u64) {
    if ns.is_empty() {
        return (0, 0, 0);
    }
    let mut v = ns.to_vec();
    v.sort_unstable();
    let n = v.len();
    (v[n / 2], v[(n * 95 / 100).min(n - 1)], v[n - 1])
}

fn csv(env: &Env, name: &str, header: &str) -> std::io::BufWriter<std::fs::File> {
    let f = std::fs::File::create(env.out.join(format!("{name}.csv"))).expect("csv");
    let mut w = std::io::BufWriter::new(f);
    writeln!(w, "{header}").expect("csv header");
    w
}

// ---------------------------------------------------------------- кадры

fn csum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut odd: Option<u8> = None;
    for p in parts {
        for &b in *p {
            match odd.take() {
                Some(hi) => sum += u32::from(u16::from_be_bytes([hi, b])),
                None => odd = Some(b),
            }
        }
    }
    if let Some(hi) = odd {
        sum += u32::from(u16::from_be_bytes([hi, 0]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Ethernet + IPv4 + TCP (без опций) от `src_mac`/198.18.0.1 к пиру/198.18.0.2.
fn tcp_frame(
    src_mac: [u8; 6],
    flags: u8,
    sport: u16,
    dport: u16,
    seq: u32,
    payload: usize,
) -> Vec<u8> {
    let tcp_len = 20 + payload;
    let mut tcp = vec![0u8; tcp_len];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&1024u16.to_be_bytes());
    let pseudo_len = (tcp_len as u16).to_be_bytes();
    let c = csum(&[&SRC_IP, &DST_IP, &[0, 6], &pseudo_len, &tcp]);
    tcp[16..18].copy_from_slice(&c.to_be_bytes());
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((20 + tcp_len) as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&(seq as u16).to_be_bytes());
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&SRC_IP);
    ip[16..20].copy_from_slice(&DST_IP);
    let c = csum(&[&ip]);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    let mut f = Vec::with_capacity(14 + 20 + tcp_len);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f.extend_from_slice(&ip);
    f.extend_from_slice(&tcp);
    f
}

const SYN: u8 = 0x02;
const RST: u8 = 0x04;

/// Кадр-мусор пира: 0x88b5, от пира к сканеру, 60 байт.
fn junk_frame(i: u32) -> Vec<u8> {
    let mut f = vec![0u8; 60];
    f[0..6].copy_from_slice(&SCAN);
    f[6..12].copy_from_slice(&PEER);
    f[12..14].copy_from_slice(&ETH_JUNK.to_be_bytes());
    f[14..18].copy_from_slice(&i.to_be_bytes());
    f
}

fn mac_text(m: &[u8]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn ethertype(f: &[u8]) -> u16 {
    f.get(12..14)
        .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]))
}

fn describe(f: &[u8]) -> String {
    let mut s = String::new();
    if f.len() < 14 {
        return format!("short({})", f.len());
    }
    let _ = write!(
        s,
        "dst={} src={} type=0x{:04x} len={}",
        mac_text(&f[0..6]),
        mac_text(&f[6..12]),
        ethertype(f),
        f.len()
    );
    if ethertype(f) == 0x0800 && f.len() >= 54 && f[23] == 6 {
        let _ = write!(
            s,
            " ip={}.{}.{}.{}>{}.{}.{}.{} tcp={}>{} flags=0x{:02x}",
            f[26],
            f[27],
            f[28],
            f[29],
            f[30],
            f[31],
            f[32],
            f[33],
            u16::from_be_bytes([f[34], f[35]]),
            u16::from_be_bytes([f[36], f[37]]),
            f[47]
        );
    }
    s
}

/// `assert_lab_frame`: единственная проверка перед любой записью.
fn assert_lab_frame(iface: &str, f: &[u8]) {
    assert!(
        f.len() >= 14,
        "lab frame guard: frame shorter than an Ethernet header"
    );
    let dst = &f[0..6];
    let src = &f[6..12];
    match iface {
        IF_SCAN => {
            assert_eq!(dst, PEER, "lab frame guard: dst MAC");
            assert!(src == SCAN || src == SPIKE, "lab frame guard: src MAC");
            assert_eq!(ethertype(f), 0x0800, "lab frame guard: ethertype");
            assert!(f.len() >= 34 && f[14] >> 4 == 4, "lab frame guard: IPv4");
            assert_eq!(&f[30..34], &DST_IP, "lab frame guard: dst IP");
        }
        IF_PEER => {
            assert_eq!(dst, SCAN, "lab frame guard: peer junk dst MAC");
            assert_eq!(src, PEER, "lab frame guard: peer junk src MAC");
            assert_eq!(
                ethertype(f),
                ETH_JUNK,
                "lab frame guard: peer junk ethertype"
            );
        }
        other => panic!("lab frame guard: interface {other} is not a lab interface"),
    }
}

// ---------------------------------------------------------------- дескриптор BPF

struct Dev {
    fd: RawFd,
    iface: &'static str,
    buflen: usize,
    kq: RawFd,
}

impl Drop for Dev {
    fn drop(&mut self) {
        // SAFETY: дескрипторы принадлежат только этому значению и закрываются один раз.
        unsafe {
            if self.kq >= 0 {
                libc::close(self.kq);
            }
            libc::close(self.fd);
        }
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

const ACCEPT_ALL: [BpfInsn; 1] = [BpfInsn {
    code: 0x06,
    jt: 0,
    jf: 0,
    k: 0xffff_ffff,
}];

struct Cfg {
    blen: u32,
    see_sent: bool,
    hdr_complete: bool,
    filter: Vec<BpfInsn>,
}

impl Dev {
    /// `open(/dev/bpfN, O_RDWR|O_NONBLOCK)` с перебором занятых узлов, затем настройка.
    fn open(iface: &'static str, cfg: &Cfg) -> Dev {
        assert!(iface == IF_SCAN || iface == IF_PEER, "only lab interfaces");
        let mut fd = -1;
        for n in 0..16 {
            let path = std::ffi::CString::new(format!("/dev/bpf{n}")).expect("path");
            // SAFETY: `path` это NUL-terminated строка, живущая весь вызов.
            let r = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if r >= 0 {
                fd = r;
                break;
            }
            let e = errno();
            assert!(
                e == libc::EBUSY,
                "open /dev/bpf{n}: errno {e} (BPF access not granted?)"
            );
        }
        assert!(fd >= 0, "no free /dev/bpf node");
        let mut d = Dev {
            fd,
            iface,
            buflen: 0,
            kq: -1,
        };
        let chk = |what: &str, r: Result<(), i32>| {
            if let Err(e) = r {
                panic!("{what}: errno {e}");
            }
        };
        let mut blen = cfg.blen;
        chk("BIOCSBLEN", ioctl_ptr(fd, libc::BIOCSBLEN, &mut blen));
        // SAFETY: `ifreq` состоит из целых и union; нулевой образ корректен.
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in req.ifr_name.iter_mut().zip(iface.as_bytes()) {
            *dst = *src as libc::c_char;
        }
        chk("BIOCSETIF", ioctl_ptr(fd, libc::BIOCSETIF, &mut req));
        let mut dlt = 0u32;
        chk("BIOCGDLT", ioctl_ptr(fd, libc::BIOCGDLT, &mut dlt));
        assert_eq!(dlt, 1, "DLT_EN10MB expected");
        let mut on = 1u32;
        chk("BIOCIMMEDIATE", ioctl_ptr(fd, libc::BIOCIMMEDIATE, &mut on));
        let mut v = u32::from(cfg.see_sent);
        chk("BIOCSSEESENT", ioctl_ptr(fd, BIOCSSEESENT, &mut v));
        let mut v = u32::from(cfg.hdr_complete);
        chk("BIOCSHDRCMPLT", ioctl_ptr(fd, libc::BIOCSHDRCMPLT, &mut v));
        let mut insns = cfg.filter.clone();
        let mut prog = BpfProgram {
            bf_len: insns.len() as u32,
            bf_insns: insns.as_mut_ptr(),
        };
        chk("BIOCSETF", ioctl_ptr(fd, BIOCSETF, &mut prog));
        let mut bl = 0u32;
        chk("BIOCGBLEN", ioctl_ptr(fd, libc::BIOCGBLEN, &mut bl));
        d.buflen = bl as usize;
        d
    }

    /// Единственный путь записи: guard, затем один `write` на кадр.
    fn send(&mut self, f: &[u8]) -> Result<usize, i32> {
        assert_lab_frame(self.iface, f);
        // SAFETY: указатель и длина описывают срез `f`; дескриптор открыт.
        let n = unsafe { libc::write(self.fd, f.as_ptr().cast(), f.len()) };
        usize::try_from(n).map_err(|_| errno())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, i32> {
        // SAFETY: указатель и длина описывают записываемый срез `buf`.
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        usize::try_from(n).map_err(|_| errno())
    }

    /// `poll(POLLIN)`: (rc, revents).
    fn poll(&mut self, ms: i32) -> (i32, i16) {
        let mut p = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: одна валидная `pollfd`, nfds == 1.
        let rc = unsafe { libc::poll(&mut p, 1, ms) };
        (rc, p.revents)
    }

    /// `kevent(EVFILT_READ)`: rc (0 таймаут, 1 готово, <0 ошибка), флаги события.
    fn kevent(&mut self, ms: i32) -> (i32, u16) {
        if self.kq < 0 {
            // SAFETY: kqueue без аргументов.
            self.kq = unsafe { libc::kqueue() };
            assert!(self.kq >= 0, "kqueue errno {}", errno());
            // SAFETY: нулевой образ `kevent` корректен.
            let mut ch: libc::kevent = unsafe { std::mem::zeroed() };
            ch.ident = self.fd as usize;
            ch.filter = libc::EVFILT_READ;
            ch.flags = libc::EV_ADD | libc::EV_ENABLE;
            // SAFETY: одно изменение из живой локальной структуры, eventlist пуст.
            let rc =
                unsafe { libc::kevent(self.kq, &ch, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
            assert!(rc >= 0, "kevent register errno {}", errno());
        }
        let ts = libc::timespec {
            tv_sec: (ms / 1000) as libc::time_t,
            tv_nsec: ((ms % 1000) as libc::c_long) * 1_000_000,
        };
        // SAFETY: нулевой образ `kevent` корректен.
        let mut ev: libc::kevent = unsafe { std::mem::zeroed() };
        // SAFETY: пустой changelist, один слот eventlist в живой локальной структуре.
        let rc = unsafe { libc::kevent(self.kq, std::ptr::null(), 0, &mut ev, 1, &ts) };
        (rc, ev.flags)
    }

    fn stats(&mut self) -> Result<BpfStat, i32> {
        let mut st = BpfStat::default();
        ioctl_ptr(self.fd, libc::BIOCGSTATS, &mut st)?;
        Ok(st)
    }

    fn buf(&self) -> Vec<u8> {
        vec![0u8; self.buflen]
    }
}

fn rx_cfg(filter: &[BpfInsn], see_sent: bool, blen: u32) -> Cfg {
    Cfg {
        blen,
        see_sent,
        hdr_complete: false,
        filter: filter.to_vec(),
    }
}

fn tx_cfg() -> Cfg {
    Cfg {
        blen: 4096,
        see_sent: false,
        hdr_complete: true,
        filter: drop_all_filter().to_vec(),
    }
}

const BLEN: u32 = 4 << 20;

#[derive(Debug, Clone)]
struct Rec {
    hdrlen: usize,
    caplen: usize,
    datalen: usize,
    off: usize,
}

/// Разбор буфера по `bh_hdrlen` и `BPF_WORDALIGN`; `Err`, если остаток не нулевой.
fn parse(buf: &[u8], mut f: impl FnMut(&Rec, &[u8])) -> Result<usize, String> {
    let mut off = 0;
    let mut n = 0;
    while off < buf.len() {
        let h = read_record_header(&buf[off..]).ok_or("truncated header")?;
        let hdrlen = usize::from(h.hdrlen);
        if !(SIZEOF_BPF_HDR..=MAX_HDRLEN).contains(&hdrlen) {
            return Err(format!("bad hdrlen {hdrlen} at {off}"));
        }
        let (cap, dl) = (h.caplen as usize, h.datalen as usize);
        let end = off + hdrlen + cap;
        if end > buf.len() {
            return Err(format!("record overruns buffer at {off}"));
        }
        let r = Rec {
            hdrlen,
            caplen: cap,
            datalen: dl,
            off,
        };
        f(&r, &buf[off + hdrlen..end]);
        off += bpf_wordalign(hdrlen + cap);
        n += 1;
    }
    if off != buf.len() && off != bpf_wordalign(buf.len()) {
        return Err(format!("remainder: consumed {off} of {}", buf.len()));
    }
    Ok(n)
}

/// Читает до `EAGAIN`; возвращает число записей и вызывает `f` на каждом кадре.
fn drain(d: &mut Dev, f: &mut impl FnMut(&Rec, &[u8])) -> usize {
    let mut buf = d.buf();
    let mut total = 0;
    loop {
        match d.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => total += parse(&buf[..n], &mut *f).unwrap_or_else(|e| panic!("parse: {e}")),
            Err(e) if e == libc::EAGAIN => break,
            Err(e) => panic!("read errno {e}"),
        }
    }
    total
}

/// Ждёт `total` (опрос порциями по 50 мс), собирая кадры; возвращает число записей.
fn collect(d: &mut Dev, total: Duration, f: &mut impl FnMut(&Rec, &[u8])) -> usize {
    let end = Instant::now() + total;
    let mut n = 0;
    while Instant::now() < end {
        if d.poll(50).0 > 0 {
            n += drain(d, f);
        }
    }
    n
}

fn sleep_ms(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

/// Спин до абсолютного момента (без опоры на точность `sleep`).
fn wait_until(t: Instant) {
    while Instant::now() < t {
        std::hint::spin_loop();
    }
}

fn scan_tx() -> Dev {
    Dev::open(IF_SCAN, &tx_cfg())
}
fn peer_tx() -> Dev {
    Dev::open(IF_PEER, &tx_cfg())
}

/// Поток мусора пира: `rate` пакетов/с (0 = как можно быстрее), до `stop` или `max` кадров.
fn flood(rate: u64, max: u64, stop: &AtomicBool, sent: &AtomicU64, errs: &AtomicU64) {
    let mut d = peer_tx();
    let start = Instant::now();
    let mut i: u64 = 0;
    while i < max && !stop.load(Ordering::Relaxed) {
        if let Some(per) = 1_000_000_000u64.checked_div(rate) {
            wait_until(start + Duration::from_nanos(i * per));
        }
        match d.send(&junk_frame(i as u32)) {
            Ok(_) => {
                sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                errs.fetch_add(1, Ordering::Relaxed);
            }
        }
        i += 1;
    }
}

struct Flood {
    stop: Arc<AtomicBool>,
    sent: Arc<AtomicU64>,
    errs: Arc<AtomicU64>,
    h: Option<std::thread::JoinHandle<()>>,
}

impl Flood {
    fn start(rate: u64, max: u64) -> Flood {
        let stop = Arc::new(AtomicBool::new(false));
        let sent = Arc::new(AtomicU64::new(0));
        let errs = Arc::new(AtomicU64::new(0));
        let (s, a, e) = (stop.clone(), sent.clone(), errs.clone());
        let h = std::thread::spawn(move || flood(rate, max, &s, &a, &e));
        Flood {
            stop,
            sent,
            errs,
            h: Some(h),
        }
    }
    fn finish(mut self) -> (u64, u64) {
        self.stop.store(true, Ordering::Relaxed);
        self.h.take().expect("handle").join().expect("flood thread");
        (
            self.sent.load(Ordering::Relaxed),
            self.errs.load(Ordering::Relaxed),
        )
    }
    fn join_done(mut self) -> (u64, u64) {
        self.h.take().expect("handle").join().expect("flood thread");
        (
            self.sent.load(Ordering::Relaxed),
            self.errs.load(Ordering::Relaxed),
        )
    }
}

// ---------------------------------------------------------------- 1. стенд, раскладка

#[test]
#[ignore = "live: needs the sealed macOS feth stand and BPF access"]
fn live_stand_path() {
    let env = env();
    let mut log = Log::new(&env, "live_stand_path");
    let mut rx = Dev::open(IF_SCAN, &rx_cfg(&own_mac_filter(SCAN), false, BLEN));
    let mut peer = Dev::open(IF_PEER, &rx_cfg(&ACCEPT_ALL, true, BLEN));
    let mut tx = scan_tx();
    log.line(&format!("rx_buflen={} (requested {BLEN})", rx.buflen));
    // один SYN на :8000 (listener; :80 недоступен без root при bind на 198.18.0.2), один на :81 (закрыт)
    tx.send(&tcp_frame(SCAN, SYN, 40000, 8000, 1000, 0))
        .expect("syn8000");
    tx.send(&tcp_frame(SCAN, SYN, 40001, 81, 2000, 0))
        .expect("syn81");
    let (mut synack, mut rst, mut first) = (0, 0, true);
    let mut ethertypes = vec![];
    let mut rx_lines = vec![];
    collect(&mut rx, Duration::from_millis(2500), &mut |r, f| {
        if first {
            first = false;
            log.line(&format!(
                "FIRST_RECORD bh_hdrlen={} bh_caplen={} bh_datalen={} off={} frame[12..14]={:02x}{:02x}",
                r.hdrlen, r.caplen, r.datalen, r.off, f[12], f[13]
            ));
        }
        assert_eq!(r.caplen, r.datalen, "caplen != datalen");
        ethertypes.push(ethertype(f));
        if ethertype(f) == 0x0800 && f.len() >= 48 && f[23] == 6 {
            let fl = f[47] & 0x17;
            if fl == 0x12 && f[6..12] == PEER {
                synack += 1;
            }
            if fl & 0x04 != 0 && f[6..12] == PEER {
                rst += 1;
            }
        }
        rx_lines.push(format!("RX hdrlen={} {}", r.hdrlen, describe(f)));
    });
    for l in &rx_lines {
        log.line(l);
    }
    let mut peer_lines = vec![];
    let (mut peer_rst_for_scanner, mut peer_arp) = (0, 0);
    drain(&mut peer, &mut |_, f| {
        if ethertype(f) == 0x0806 {
            peer_arp += 1;
        }
        // RST с src IP сканера: ядро отвечает за сканера
        if ethertype(f) == 0x0800
            && f.len() >= 48
            && f[23] == 6
            && f[26..30] == SRC_IP
            && f[47] & 0x04 != 0
            && f[6..12] != SCAN
        {
            peer_rst_for_scanner += 1;
        }
        peer_lines.push(format!("PEER {}", describe(f)));
    });
    for l in &peer_lines {
        log.line(l);
    }
    log.line(&format!(
        "RESULT rx_synack_from_peer={synack} rx_rst_from_peer={rst} peer_side_arp_frames={peer_arp} peer_side_rst_with_scanner_ip_not_from_scanner_mac={peer_rst_for_scanner}"
    ));
    assert!(synack >= 1, "STOP: SYN-ACK did not reach BPF on feth4201");
    assert!(rst >= 1, "STOP: RST did not reach BPF on feth4201");
    assert!(
        ethertypes
            .iter()
            .all(|t| [0x0800, 0x0806, 0x88b5, 0x86dd].contains(t)),
        "unexpected ethertype {ethertypes:?}"
    );

    // несколько записей в одном read: 20 SYN на закрытый порт без чтения RX
    let before = rx.stats().expect("stats");
    for i in 0..20u16 {
        tx.send(&tcp_frame(SCAN, SYN, 41000 + i, 81, 3000 + u32::from(i), 0))
            .expect("syn");
    }
    sleep_ms(400);
    let mut buf = rx.buf();
    let n = rx.read(&mut buf).expect("one read");
    let mut hdrlens = vec![];
    let recs = parse(&buf[..n], |r, f| {
        hdrlens.push(r.hdrlen);
        assert_eq!(r.caplen, r.datalen);
        assert_eq!(ethertype(f), 0x0800);
    })
    .unwrap_or_else(|e| panic!("multi-record parse: {e}"));
    let after = rx.stats().expect("stats");
    log.line(&format!(
        "MULTI one_read_bytes={n} records={recs} hdrlens={hdrlens:?} stats_before={before:?} stats_after={after:?}"
    ));
    assert!(recs >= 2, "expected several records in one read");
    drain(&mut rx, &mut |_, _| {});
    drain(&mut peer, &mut |_, _| {});
}

// ---------------------------------------------------------------- 2. RX дедлайн

fn deadline_series(
    log: &mut Log,
    w: &mut impl std::io::Write,
    label: &str,
    d: &mut Dev,
    kev: bool,
    calls: usize,
    budget_ms: i32,
) -> Vec<u64> {
    let mut over = vec![];
    let (mut ready, mut bad) = (0, 0);
    let mut maxdur = 0u64;
    let mut buf = d.buf();
    for i in 0..calls {
        let t0 = Instant::now();
        let (rc, rev) = if kev {
            let (rc, fl) = d.kevent(budget_ms);
            (rc, i16::from(fl & libc::EV_ERROR != 0))
        } else {
            d.poll(budget_ms)
        };
        let ns = t0.elapsed().as_nanos() as u64;
        let timeout = rc == 0;
        let flagged = if kev {
            rev != 0
        } else {
            rev & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0
        };
        if flagged || rc < 0 {
            bad += 1;
        }
        if rc > 0 {
            ready += 1;
            // освободить дескриптор, чтобы уровень не залипал
            loop {
                match d.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
        writeln!(w, "{label},{i},{ns},{rc},{rev},{}", u8::from(timeout)).expect("csv");
        maxdur = maxdur.max(ns);
        if timeout {
            over.push(ns.saturating_sub(budget_ms as u64 * 1_000_000));
        }
    }
    log.line(&format!("{label}: calls={calls} timeouts={} ready={ready} pollerr_nval_or_error={bad} max_call_us={:.1}", over.len(), maxdur as f64 / 1e3));
    log.stats(
        &format!("{label} overshoot (duration - {budget_ms} ms), timeouts only"),
        &over,
    );
    over
}

#[test]
#[ignore = "live: needs the sealed macOS feth stand and BPF access"]
fn live_rx_deadline_idle() {
    let env = env();
    let mut log = Log::new(&env, "live_rx_deadline_idle");
    let mut w = csv(
        &env,
        "live_rx_deadline_idle",
        "label,i,ns,rc,revents_or_evflags,timeout",
    );
    let mut rx = Dev::open(IF_SCAN, &rx_cfg(&own_mac_filter(SCAN), false, BLEN));
    let mut all = vec![];
    for (label, kev, ms) in [
        ("poll50", false, 50),
        ("kevent50", true, 50),
        ("poll42", false, 42),
        ("poll1", false, 1),
    ] {
        let n = if ms == 1 {
            1000
        } else if label == "poll42" {
            300
        } else {
            1000
        };
        let v = deadline_series(&mut log, &mut w, label, &mut rx, kev, n, ms);
        all.push((label, v));
    }
    w.flush().expect("flush");
}

#[test]
#[ignore = "live: needs the sealed macOS feth stand and BPF access"]
fn live_rx_deadline_flood() {
    let env = env();
    let mut log = Log::new(&env, "live_rx_deadline_flood");
    let mut w = csv(
        &env,
        "live_rx_deadline_flood",
        "label,i,ns,rc,revents_or_evflags,timeout",
    );
    // (метка, kevent, фильтр, число вызовов): accept = вызовы возвращаются по кадрам,
    // dropall = кадры идут в ядре, но RX-фильтр отбрасывает всё: честные таймауты под нагрузкой
    for (label, kev, accept, calls) in [
        ("flood20k_accept_poll", false, true, 20_000usize),
        ("flood20k_accept_kevent", true, true, 20_000),
        ("flood20k_dropall_poll", false, false, 200),
        ("flood20k_dropall_kevent", true, false, 200),
    ] {
        let filter: Vec<BpfInsn> = if accept {
            ACCEPT_ALL.to_vec()
        } else {
            drop_all_filter().to_vec()
        };
        let mut rx = Dev::open(IF_SCAN, &rx_cfg(&filter, false, BLEN));
        let fl = Flood::start(20_000, u64::MAX);
        sleep_ms(200);
        deadline_series(&mut log, &mut w, label, &mut rx, kev, calls, 50);
        let st = rx.stats().expect("stats");
        let (sent, errs) = fl.finish();
        log.line(&format!(
            "{label}: peer_sent={sent} peer_write_errors={errs} rx_stats={st:?}"
        ));
    }
    w.flush().expect("flush");
}

#[test]
#[ignore = "live: needs the sealed macOS feth stand and BPF access"]
fn live_rx_wakeup() {
    let env = env();
    let mut log = Log::new(&env, "live_rx_wakeup");
    let mut w = csv(&env, "live_rx_wakeup", "label,i,latency_ns,rc");
    let mut rx = Dev::open(IF_SCAN, &rx_cfg(&own_mac_filter(SCAN), false, BLEN));
    let mut txp = peer_tx();
    for (label, kev) in [("poll", false), ("kevent", true)] {
        let mut lat = vec![];
        let mut misses = 0;
        for i in 0..200u32 {
            let t0 = Instant::now();
            txp.send(&junk_frame(i)).expect("junk");
            let rc = if kev { rx.kevent(50).0 } else { rx.poll(50).0 };
            let ns = t0.elapsed().as_nanos() as u64;
            writeln!(w, "{label},{i},{ns},{rc}").expect("csv");
            if rc > 0 {
                lat.push(ns);
            } else {
                misses += 1;
            }
            drain(&mut rx, &mut |_, _| {});
        }
        log.line(&format!(
            "{label}: wakeups={} misses_within_50ms={misses}",
            lat.len()
        ));
        log.stats(&format!("{label} send->ready latency"), &lat);
        assert_eq!(misses, 0, "{label} did not wake on frame arrival");
    }
    w.flush().expect("flush");
}

// ---------------------------------------------------------------- 3. свои кадры

#[test]
#[ignore = "live: needs the sealed macOS feth stand and BPF access"]
fn live_own_frames() {
    let env = env();
    let mut log = Log::new(&env, "live_own_frames");
    let mut rx0 = Dev::open(IF_SCAN, &rx_cfg(&ACCEPT_ALL, false, BLEN));
    let mut rx1 = Dev::open(IF_SCAN, &rx_cfg(&ACCEPT_ALL, true, BLEN));
    let mut peer = Dev::open(IF_PEER, &rx_cfg(&ACCEPT_ALL, true, BLEN));
    let mut tx = scan_tx();
    for i in 0..1000u32 {
        tx.send(&tcp_frame(SCAN, RST, 42000, 81, i, 0))
            .expect("send");
    }
    for i in 0..20u32 {
        tx.send(&tcp_frame(SPIKE, RST, 42001, 81, i, 0))
            .expect("send");
    }
    sleep_ms(500);
    let own = |f: &[u8]| f.len() >= 12 && (f[6..12] == SCAN || f[6..12] == SPIKE);
    let (mut own0, mut own1, mut scan1, mut spike1) = (0, 0, 0, 0);
    let all0 = drain(&mut rx0, &mut |_, f| own0 += usize::from(own(f)));
    let all1 = drain(&mut rx1, &mut |_, f| {
        own1 += usize::from(own(f));
        scan1 += usize::from(f[6..12] == SCAN);
        spike1 += usize::from(f[6..12] == SPIKE);
    });
    let (mut p_scan, mut p_spike, mut p_other) = (0, 0, 0);
    let pall = drain(&mut peer, &mut |_, f| {
        if f[6..12] == SCAN {
            p_scan += 1;
        } else if f[6..12] == SPIKE {
            p_spike += 1;
        } else {
            p_other += 1;
        }
    });
    log.line(&format!(
        "SEESENT0 rx_records={all0} own_frames_seen={own0} (sent 1020 from SCAN/SPIKE)"
    ));
    log.line(&format!("SEESENT1 control rx_records={all1} own_frames_seen={own1} scan_mac={scan1} spike_mac={spike1}"));
    log.line(&format!(
        "PEER_WITNESS records={pall} src_scan={p_scan} src_spike_0x11={p_spike} other={p_other}"
    ));
    assert_eq!(own0, 0, "own frames visible with BIOCSSEESENT 0");
    assert!(own1 > 0, "control with BIOCSSEESENT 1 saw nothing");
    assert_eq!(p_spike, 20, "kernel altered the spike source MAC");
}

// ---------------------------------------------------------------- 4. TX

fn tx_series(
    log: &mut Log,
    w: &mut impl std::io::Write,
    label: &str,
    tx: &mut Dev,
    frames: usize,
    period: Option<Duration>,
    full_csv: bool,
) -> Vec<u64> {
    let mut ns = Vec::with_capacity(frames);
    let (mut ok, mut again, mut nobufs, mut other) = (0u64, 0u64, 0u64, 0u64);
    let mut slow = [0u64; 3];
    let proto = tcp_frame(SCAN, RST, 43000, 81, 0, 0);
    let start = Instant::now();
    for i in 0..frames {
        if let Some(p) = period {
            wait_until(start + p * i as u32);
        }
        let mut f = proto.clone();
        f[38..42].copy_from_slice(&(i as u32).to_be_bytes());
        let t0 = Instant::now();
        let r = tx.send(&f);
        let d = t0.elapsed().as_nanos() as u64;
        match r {
            Ok(n) if n == f.len() => ok += 1,
            Ok(_) => other += 1,
            Err(e) if e == libc::EAGAIN => again += 1,
            Err(e) if e == libc::ENOBUFS => nobufs += 1,
            Err(_) => other += 1,
        }
        for (k, lim) in [1_000_000u64, 10_000_000, 50_000_000].iter().enumerate() {
            slow[k] += u64::from(d > *lim);
        }
        let rc = match r {
            Ok(n) => n as i64,
            Err(e) => -i64::from(e),
        };
        if full_csv || d > 1_000_000 {
            writeln!(w, "{label},{i},{d},{rc},{}", start.elapsed().as_nanos()).expect("csv");
        }
        ns.push(d);
    }
    let wall = start.elapsed();
    log.line(&format!(
        "{label}: frames={frames} full_writes={ok} EAGAIN={again} ENOBUFS={nobufs} other={other} wall_ms={:.1} calls_over_1ms={} over_10ms={} over_50ms={}",
        wall.as_secs_f64() * 1e3, slow[0], slow[1], slow[2]
    ));
    log.stats(&format!("{label} write()"), &ns);
    assert_eq!(other, 0, "{label}: unexpected write outcome");
    ns
}

#[test]
#[ignore = "live: needs the sealed macOS feth stand and BPF access"]
fn live_tx() {
    let env = env();
    let mut log = Log::new(&env, "live_tx");
    let mut w = csv(
        &env,
        "live_tx",
        "label,i,write_ns,rc_or_negerrno,t_since_start_ns",
    );
    let mut tx = scan_tx();
    tx_series(
        &mut log,
        &mut w,
        "tx_5000_back_to_back",
        &mut tx,
        5000,
        None,
        true,
    );
    tx_series(
        &mut log,
        &mut w,
        "tx_1000_at_1khz",
        &mut tx,
        1000,
        Some(Duration::from_millis(1)),
        true,
    );
    // 1514 принимается, 1515 и больше нет
    let ok = tcp_frame(SCAN, RST, 43001, 81, 1, 1514 - 54);
    assert_eq!(ok.len(), 1514);
    let r = tx.send(&ok);
    log.line(&format!("tx_len_1514 -> {r:?}"));
    // Измерение, не утверждение: где ядро отказывает (кадры лабораторные, принятые уходят пиру).
    for len in [
        1515usize, 1516, 1518, 1600, 2000, 4095, 4096, 4097, 8192, 16384,
    ] {
        let big = tcp_frame(SCAN, RST, 43002, 81, 1, len - 54);
        assert_eq!(big.len(), len);
        let r = tx.send(&big);
        log.line(&format!(
            "tx_len_{len} -> {r:?} (EMSGSIZE={} EIO={})",
            libc::EMSGSIZE,
            libc::EIO
        ));
    }
    // длинная серия: 200k кадров как можно быстрее
    let ns = tx_series(
        &mut log,
        &mut w,
        "tx_burst_200k",
        &mut tx,
        200_000,
        None,
        false,
    );
    let mut top: Vec<(usize, u64)> = ns.iter().copied().enumerate().collect();
    top.sort_by_key(|x| std::cmp::Reverse(x.1));
    for (i, d) in top.iter().take(10) {
        log.line(&format!(
            "tx_burst_200k slowest idx={i} write_us={:.1}",
            *d as f64 / 1e3
        ));
    }
    w.flush().expect("flush");
}

// ---------------------------------------------------------------- 5. RX health

#[test]
#[ignore = "live: needs the sealed macOS feth stand and BPF access"]
fn live_rx_health() {
    let env = env();
    let mut log = Log::new(&env, "live_rx_health");
    let mut w = csv(
        &env,
        "live_rx_health",
        "phase,t_ms,bs_recv,bs_drop,stats_call_ns",
    );
    // чистый прогон
    {
        let mut a = Dev::open(IF_SCAN, &rx_cfg(&own_mac_filter(SCAN), false, BLEN));
        let mut tx = scan_tx();
        let base = a.stats().expect("base");
        for i in 0..100u16 {
            tx.send(&tcp_frame(SCAN, SYN, 44000 + i, 81, 1, 0))
                .expect("syn");
        }
        sleep_ms(500);
        let read = drain(&mut a, &mut |_, _| {});
        let mut calls = vec![];
        let mut st = BpfStat::default();
        for _ in 0..200 {
            let t0 = Instant::now();
            st = a.stats().expect("stats");
            calls.push(t0.elapsed().as_nanos() as u64);
        }
        log.line(&format!("CLEAN base={base:?} read={read} stats={st:?}"));
        log.stats("CLEAN BIOCGSTATS call", &calls);
        assert_eq!(st.bs_drop, 0, "clean run has drops");
        assert_eq!(u64::from(st.bs_recv - base.bs_recv), read as u64);
    }
    // переполнение
    let mut a = Dev::open(IF_SCAN, &rx_cfg(&own_mac_filter(SCAN), false, 512 * 1024));
    let a_len = a.buflen;
    let b_stop = Arc::new(AtomicBool::new(false));
    let bs = b_stop.clone();
    let b = std::thread::spawn(move || {
        let mut b = Dev::open(IF_SCAN, &rx_cfg(&own_mac_filter(SCAN), false, BLEN));
        let mut read = 0usize;
        let mut buf = b.buf();
        let mut done_empty = false;
        loop {
            let stopped = bs.load(Ordering::Relaxed);
            match b.read(&mut buf) {
                Ok(n) if n > 0 => {
                    read += parse(&buf[..n], |_, _| {}).expect("B parse");
                    done_empty = false;
                }
                _ => {
                    if stopped && done_empty {
                        break;
                    }
                    done_empty = stopped;
                    b.poll(5);
                }
            }
        }
        (read, b.stats().expect("B stats"))
    });
    let a0 = a.stats().expect("a0");
    let t_start = Instant::now();
    let fl = Flood::start(0, 200_000);
    let mut series = vec![];
    let mut last = a0;
    while t_start.elapsed() < Duration::from_millis(2500) {
        sleep_ms(250);
        let t0 = Instant::now();
        let st = a.stats().expect("stats during hold");
        let ns = t0.elapsed().as_nanos() as u64;
        writeln!(
            w,
            "hold,{},{},{},{ns}",
            t_start.elapsed().as_millis(),
            st.bs_recv,
            st.bs_drop
        )
        .expect("csv");
        assert!(
            st.bs_recv >= last.bs_recv && st.bs_drop >= last.bs_drop,
            "counter went backwards"
        );
        last = st;
        series.push(ns);
    }
    let (sent, errs) = fl.join_done();
    let before_read = a.stats().expect("before read");
    let read = drain(&mut a, &mut |_, _| {});
    let s1 = a.stats().expect("s1");
    let s2 = a.stats().expect("s2");
    let s3 = a.stats().expect("s3");
    sleep_ms(300);
    let s4 = a.stats().expect("s4");
    b_stop.store(true, Ordering::Relaxed);
    let (b_read, b_st) = b.join().expect("B thread");
    log.line(&format!(
        "OVERFLOW a_buflen={a_len} peer_sent={sent} peer_write_errors={errs} a_base={a0:?}"
    ));
    log.line(&format!("A before_read={before_read:?} read_records={read} after_drain={s1:?} again={s2:?} again2={s3:?} later={s4:?}"));
    log.line(&format!(
        "B (continuous reader, 4 MiB) read_records={b_read} stats={b_st:?}"
    ));
    log.stats("OVERFLOW BIOCGSTATS call during hold", &series);
    let dr = u64::from(s1.bs_recv - a0.bs_recv);
    let dd = u64::from(s1.bs_drop - a0.bs_drop);
    log.line(&format!(
        "A delta_recv={dr} delta_drop={dd} read={read} recv-drop-read={}",
        dr as i64 - dd as i64 - read as i64
    ));
    log.line(&format!(
        "B delta: recv={} drop={} read={b_read}",
        b_st.bs_recv, b_st.bs_drop
    ));
    assert!(dd > 0, "overflow produced no bs_drop");
    assert_eq!(s1, s2, "stats read reset or changed the counters");
    assert_eq!(s1, s3);
    assert_eq!(s1, s4);
    assert_eq!(dr - dd, read as u64, "recv - drop != read");
}

// ---------------------------------------------------------------- 6. Stop

#[test]
#[ignore = "live: needs the sealed macOS feth stand and BPF access"]
fn live_stop() {
    let env = env();
    let mut log = Log::new(&env, "live_stop");
    let mut w = csv(
        &env,
        "live_stop",
        "variant,round,tx_ms,rx_ms,join_both_ms,tx_writes_before_stop",
    );
    for (variant, with_flood) in [("idle_rx", false), ("rx_under_flood20k", true)] {
        let (mut tx_ms, mut rx_ms, mut join_ms) = (vec![], vec![], vec![]);
        let mut tx_dev = Some(scan_tx());
        let mut rx_dev = Some(Dev::open(IF_SCAN, &rx_cfg(&drop_all_filter(), false, BLEN)));
        let fl = with_flood.then(|| Flood::start(20_000, u64::MAX));
        for round in 0..60 {
            let flag = Arc::new(AtomicBool::new(false));
            let writes = Arc::new(AtomicU64::new(0));
            let (mut txd, mut rxd) = (tx_dev.take().expect("tx"), rx_dev.take().expect("rx"));
            let (f1, w1) = (flag.clone(), writes.clone());
            let th_tx = std::thread::spawn(move || {
                let frame = tcp_frame(SCAN, RST, 45000, 81, 0, 0);
                while !f1.load(Ordering::Relaxed) {
                    let _ = txd.send(&frame);
                    w1.fetch_add(1, Ordering::Relaxed);
                }
                (txd, Instant::now())
            });
            let f2 = flag.clone();
            let th_rx = std::thread::spawn(move || {
                while !f2.load(Ordering::Relaxed) {
                    rxd.poll(50);
                }
                (rxd, Instant::now())
            });
            while writes.load(Ordering::Relaxed) < 200 {
                std::hint::spin_loop();
            }
            // фаза RX-цикла не синхронизируется со Stop: сдвиг по раундам
            sleep_ms(5 + (round % 7) * 9);
            let n_before = writes.load(Ordering::Relaxed);
            let t0 = Instant::now();
            flag.store(true, Ordering::Relaxed);
            let (t, t_tx) = th_tx.join().expect("tx");
            let (r, t_rx) = th_rx.join().expect("rx");
            let joined = t0.elapsed();
            tx_dev = Some(t);
            rx_dev = Some(r);
            let ms = |i: Instant| i.saturating_duration_since(t0).as_secs_f64() * 1e3;
            writeln!(
                w,
                "{variant},{round},{:.3},{:.3},{:.3},{n_before}",
                ms(t_tx),
                ms(t_rx),
                joined.as_secs_f64() * 1e3
            )
            .expect("csv");
            tx_ms.push((ms(t_tx) * 1e6) as u64);
            rx_ms.push((ms(t_rx) * 1e6) as u64);
            join_ms.push(joined.as_nanos() as u64);
        }
        if let Some(f) = fl {
            f.finish();
        }
        log.line(&format!("variant={variant}"));
        log.stats("stop TX thread (inside write burst)", &tx_ms);
        log.stats("stop RX thread (poll 50 ms loop)", &rx_ms);
        log.stats("stop join both", &join_ms);
        assert!(pcts(&join_ms).2 < 1_000_000_000, "Stop exceeded 1 s");
    }
    w.flush().expect("flush");
}

/// Длинные серии `poll`/`kevent` на пустом канале: максимум превышения для `IO_BUDGET`.
#[test]
#[ignore = "live: needs the sealed macOS feth stand and BPF access"]
fn live_rx_deadline_long() {
    let env = env();
    let mut log = Log::new(&env, "live_rx_deadline_long");
    let mut w = csv(
        &env,
        "live_rx_deadline_long",
        "label,i,ns,rc,revents_or_evflags,timeout",
    );
    let mut rx = Dev::open(IF_SCAN, &rx_cfg(&own_mac_filter(SCAN), false, BLEN));
    for (label, kev, ms, n) in [
        ("poll50", false, 50, 3000),
        ("poll43", false, 43, 3000),
        ("kevent50", true, 50, 1500),
        ("kevent43", true, 43, 1500),
    ] {
        deadline_series(&mut log, &mut w, label, &mut rx, kev, n, ms);
    }
    w.flush().expect("flush");
}
