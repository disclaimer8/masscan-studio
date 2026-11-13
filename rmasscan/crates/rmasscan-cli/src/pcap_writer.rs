//! Захват `--pcap` (AGPL-3.0): классический `.pcap` (LE, микросекунды, Ethernet) входящих кадров, адресованных
//! сканеру. Порт `pcapfile_openwrite` (`rawsock-pcapfile.c:669-712`), `pcapfile_writeframe`
//! (`rawsock-pcapfile.c:857-932`) и места записи в приёмном потоке (`main.c:829, 935, 943-951`) из masscan
//! © Robert David Graham (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Движок отдаёт приёмнику каждый входящий кадр не длиннее 1514 байт до разбора; фильтр "кадр адресован нашему
//! `ip_me` и `port_me`" принадлежит писателю (`is_my_ip` `main.c:829`, `is_my_port` `main.c:935`). Запись идёт до
//! проверки SYN-cookie и дедупликации (`main.c:943-951`), поэтому SYN-ACK и RST с плохим cookie на наш адрес и порт
//! оба попадают в файл, а чужой кадр нет. Один писатель под `Mutex` обслуживает все RX-потоки всех адаптеров (в C
//! каждый поток открывает файл сам и затирает чужие записи, `main.c:585`; Р8).

use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard};

use rmasscan_engine::PcapSink;

/// Самый длинный кадр, который C пишет в захват (`main.c:943`).
pub const MAX_FRAME: usize = 1514;

/// Заголовок файла: magic LE `d4 c3 b2 a1`, версия 2.4, `snaplen = 65535`, `linktype = 1` (Ethernet)
/// (`rawsock-pcapfile.c:669-712`: `buf[20] = linktype`).
pub const FILE_HEADER: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
];

/// Адрес и порт одного адаптера скана: диапазон `--adapter-ip A-B` и `source_ports` (`is_my_ip`, `is_my_port`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcapTarget {
    pub ip_first: u32,
    pub ip_last: u32,
    /// Адрес источника IPv6 адаптера (`src.ipv6`, один адрес, `stack-src.c:13-14`); `None` у скана без целей IPv6.
    pub ipv6: Option<u128>,
    pub port_first: u16,
    pub port_last: u16,
}

struct State {
    out: Box<dyn Write + Send>,
    /// Первая ошибка записи: после неё запись прекращается (C закрывает файл, `rawsock-pcapfile.c:922-931`);
    /// [`PcapWriter::finish`] сообщает её, и скан завершается кодом 1 (отличие от C, Р8).
    error: Option<String>,
}

/// Потокобезопасный писатель захвата.
pub struct PcapWriter {
    state: Mutex<State>,
    targets: Vec<PcapTarget>,
    /// Микросекунды Unix на нулевое показание часов engine: время записи = смещение + показание.
    wall_offset_micros: u64,
}

impl PcapWriter {
    /// Пишет 24-байтовый заголовок файла и готов принимать кадры. `targets` это адаптеры скана, `wall_offset_micros`
    /// переводит часы engine в Unix-время.
    pub fn new(
        mut out: Box<dyn Write + Send>,
        targets: Vec<PcapTarget>,
        wall_offset_micros: u64,
    ) -> Result<PcapWriter, String> {
        out.write_all(&FILE_HEADER)
            .and_then(|()| out.flush())
            .map_err(|e| format!("could not write capture file header: {e}"))?;
        Ok(PcapWriter {
            state: Mutex::new(State { out, error: None }),
            targets,
            wall_offset_micros,
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Адресован ли кадр одному из наших адаптеров: Ethernet/IPv4, не фрагмент, TCP, адрес назначения в диапазоне
    /// `adapter-ip` и порт назначения в `source_ports` (`main.c:829, 935`); либо Ethernet/IPv6 (после необязательного
    /// Hop-by-Hop, как приёмник), TCP, адрес назначения это `source_ipv6` адаптера.
    pub fn is_ours(&self, frame: &[u8]) -> bool {
        if frame.len() <= MAX_FRAME && frame.get(12..14) == Some(&[0x86, 0xdd][..]) {
            return self.is_ours_v6(frame);
        }
        if frame.len() > MAX_FRAME || frame.len() < 14 + 20 + 4 || frame[12..14] != [0x08, 0x00] {
            return false;
        }
        let ip = &frame[14..];
        let ihl = usize::from(ip[0] & 0x0f) * 4;
        // MF (0x2000) и смещение (0x1fff): первый фрагмент C тоже отбрасывает (proto-preprocess.c:100-102).
        let fragment = u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0;
        if ip[0] >> 4 != 4 || ihl < 20 || fragment || ip[9] != 6 || ip.len() < ihl + 4 {
            return false;
        }
        let dst = u32::from_be_bytes([ip[16], ip[17], ip[18], ip[19]]);
        let port = u16::from_be_bytes([ip[ihl + 2], ip[ihl + 3]]);
        self.targets.iter().any(|t| {
            (t.ip_first..=t.ip_last).contains(&dst) && (t.port_first..=t.port_last).contains(&port)
        })
    }

    /// IPv6: `next_header` TCP (6) сразу или после одного Hop-by-Hop (0, длина `(len + 1) * 8`, RFC 8200, как
    /// `receive.rs`), адрес назначения это `source_ipv6` адаптера, порт назначения в `source_ports`.
    fn is_ours_v6(&self, frame: &[u8]) -> bool {
        const IP: usize = 14;
        let Some(ip) = frame.get(IP..IP + 40) else {
            return false;
        };
        if ip[0] >> 4 != 6 {
            return false;
        }
        let (mut next, mut l4) = (ip[6], IP + 40);
        if next == 0 {
            let Some(ext) = frame.get(l4..l4 + 2) else {
                return false;
            };
            next = ext[0];
            l4 += (usize::from(ext[1]) + 1) * 8;
        }
        let Some(port) = frame.get(l4 + 2..l4 + 4) else {
            return false;
        };
        if next != 6 {
            return false;
        }
        let dst = u128::from_be_bytes(ip[24..40].try_into().expect("16 bytes"));
        let port = u16::from_be_bytes([port[0], port[1]]);
        self.targets
            .iter()
            .any(|t| t.ipv6 == Some(dst) && (t.port_first..=t.port_last).contains(&port))
    }

    /// Записывает кадр, если он наш: 16 байт LE `[ts_sec, ts_usec, incl_len, orig_len]` и сам кадр
    /// (`rawsock-pcapfile.c:857-932`, `pcapfile_writeframe(.., length, length, secs, usecs)`).
    pub fn record(&self, frame: &[u8], clock_micros: u64) {
        if !self.is_ours(frame) {
            return;
        }
        let ts = self.wall_offset_micros.saturating_add(clock_micros);
        let len = frame.len() as u32;
        let mut rec = [0u8; 16];
        rec[0..4].copy_from_slice(&((ts / 1_000_000) as u32).to_le_bytes());
        rec[4..8].copy_from_slice(&((ts % 1_000_000) as u32).to_le_bytes());
        rec[8..12].copy_from_slice(&len.to_le_bytes());
        rec[12..16].copy_from_slice(&len.to_le_bytes());
        let mut st = self.lock();
        if st.error.is_some() {
            return;
        }
        if let Err(e) = st
            .out
            .write_all(&rec)
            .and_then(|()| st.out.write_all(frame))
        {
            st.error = Some(format!("could not write capture file: {e}"));
        }
    }

    /// Сбрасывает буфер и возвращает первую ошибку записи.
    pub fn finish(&self) -> Result<(), String> {
        let mut st = self.lock();
        if let Err(e) = st.out.flush() {
            st.error
                .get_or_insert(format!("could not write capture file: {e}"));
        }
        match &st.error {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }

    /// Приёмник для `Engine::start_cli_with_clock`.
    pub fn sink(self: &Arc<Self>) -> PcapSink {
        let w = Arc::clone(self);
        Arc::new(move |frame: &[u8], micros: u64| w.record(frame, micros))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Приёмник байтов, доступный и писателю, и тесту.
    #[derive(Clone, Default)]
    struct Mem(Arc<Mutex<Vec<u8>>>);

    impl Write for Mem {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const ME: u32 = 0xc612_0005;

    /// Ethernet + IPv4 + 20 байт TCP на `dst:port`; остальное нули.
    fn frame(dst: u32, port: u16, len: usize) -> Vec<u8> {
        let mut f = vec![0u8; len.max(54)];
        f[12..14].copy_from_slice(&[0x08, 0x00]);
        f[14] = 0x45;
        f[23] = 6;
        f[30..34].copy_from_slice(&dst.to_be_bytes());
        f[36..38].copy_from_slice(&port.to_be_bytes());
        f
    }

    fn writer(mem: &Mem, targets: Vec<PcapTarget>) -> PcapWriter {
        PcapWriter::new(Box::new(mem.clone()), targets, 1_800_000_000_000_000).unwrap()
    }

    fn one(ip_last: u32) -> Vec<PcapTarget> {
        vec![PcapTarget {
            ipv6: None,
            ip_first: ME,
            ip_last,
            port_first: 40000,
            port_last: 40015,
        }]
    }

    /// `rawsock-pcapfile.c:669-712`: 24 байта заголовка байт в байт, `linktype = 1`.
    #[test]
    fn writes_the_exact_global_header_on_open() {
        let mem = Mem::default();
        let _w = writer(&mem, one(ME));
        assert_eq!(
            *mem.0.lock().unwrap(),
            [
                0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
                0, 0, 1, 0, 0, 0
            ]
        );
    }

    /// `rawsock-pcapfile.c:857-932`: 16 байт LE `[ts_sec, ts_usec, len, len]`, затем кадр.
    #[test]
    fn record_header_is_little_endian_sec_usec_len_len() {
        let mem = Mem::default();
        let w = writer(&mem, one(ME));
        let f = frame(ME, 40003, 60);
        w.record(&f, 2_500_001);
        w.finish().unwrap();
        let bytes = mem.0.lock().unwrap().clone();
        assert_eq!(bytes.len(), 24 + 16 + 60);
        let rec = &bytes[24..40];
        assert_eq!(
            u32::from_le_bytes(rec[0..4].try_into().unwrap()),
            1_800_000_002
        );
        assert_eq!(u32::from_le_bytes(rec[4..8].try_into().unwrap()), 500_001);
        assert_eq!(u32::from_le_bytes(rec[8..12].try_into().unwrap()), 60);
        assert_eq!(u32::from_le_bytes(rec[12..16].try_into().unwrap()), 60);
        assert_eq!(&bytes[40..], &f[..]);
    }

    /// `main.c:829, 935`: любой адрес диапазона `--adapter-ip A-B`, порт из `source_ports`; чужой адрес, чужой порт,
    /// не TCP, фрагмент и слишком длинный кадр отбрасываются.
    #[test]
    fn only_frames_to_our_ip_range_and_port_are_recorded() {
        let mem = Mem::default();
        let w = writer(&mem, one(ME + 3));
        w.record(&frame(ME, 40000, 60), 1);
        w.record(&frame(ME + 3, 40015, 60), 2);
        w.record(&frame(ME + 4, 40000, 60), 3); // адрес вне диапазона
        w.record(&frame(ME, 40016, 60), 4); // порт вне диапазона
        w.record(&frame(ME, 39999, 60), 5);
        let mut udp = frame(ME, 40000, 60);
        udp[23] = 17;
        w.record(&udp, 6);
        let mut frag = frame(ME, 40000, 60);
        frag[20] = 0x00;
        frag[21] = 0x08;
        w.record(&frag, 7);
        let mut first_frag = frame(ME, 40000, 60);
        first_frag[20] = 0x20; // MF, смещение 0
        w.record(&first_frag, 7);
        w.record(&frame(ME, 40000, MAX_FRAME + 1), 8);
        w.record(&frame(ME, 40000, MAX_FRAME), 9);
        w.record(&[0u8; 10], 10);
        w.finish().unwrap();
        assert_eq!(
            mem.0.lock().unwrap().len(),
            24 + (16 + 60) * 2 + 16 + MAX_FRAME
        );
    }

    /// IPv6 (T5): кадр на `source_ipv6` адаптера и порт `source_ports`, TCP сразу или после Hop-by-Hop (как
    /// приёмник), попадает в захват; чужой адрес, чужой порт, не TCP и адаптер без IPv6 нет; IPv4 как раньше.
    #[test]
    fn ipv6_frames_to_our_source_ipv6_and_port_are_recorded() {
        const ME6: u128 = 0x2001_0db8_0001_0000_0000_0000_0000_0005;
        let frame6 = |dst: u128, port: u16, hbh: bool| {
            let mut f = vec![0u8; 14 + 40];
            f[12..14].copy_from_slice(&[0x86, 0xdd]);
            f[14] = 0x60;
            f[14 + 24..14 + 40].copy_from_slice(&dst.to_be_bytes());
            if hbh {
                f[14 + 6] = 0;
                f.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
            } else {
                f[14 + 6] = 6;
            }
            let mut tcp = [0u8; 20];
            tcp[2..4].copy_from_slice(&port.to_be_bytes());
            f.extend_from_slice(&tcp);
            f
        };
        let mem = Mem::default();
        let mut t = one(ME);
        t[0].ipv6 = Some(ME6);
        let w = writer(&mem, t);
        assert!(w.is_ours(&frame6(ME6, 40000, false)));
        assert!(w.is_ours(&frame6(ME6, 40015, true)));
        assert!(!w.is_ours(&frame6(ME6 + 1, 40000, false)));
        assert!(!w.is_ours(&frame6(ME6, 40016, false)));
        let mut udp = frame6(ME6, 40000, false);
        udp[14 + 6] = 17;
        assert!(!w.is_ours(&udp));
        assert!(!w.is_ours(&frame6(ME6, 40000, false)[..57]), "port cut off");
        assert!(w.is_ours(&frame(ME, 40000, 60)));
        let v4_only = writer(&Mem::default(), one(ME));
        assert!(!v4_only.is_ours(&frame6(ME6, 40000, false)));
    }

    /// Несколько адаптеров: кадр нужен, если он адресован любому из них.
    #[test]
    fn several_adapters_share_one_writer() {
        let mem = Mem::default();
        let other = PcapTarget {
            ipv6: None,
            ip_first: ME + 100,
            ip_last: ME + 100,
            port_first: 50000,
            port_last: 50000,
        };
        let mut t = one(ME);
        t.push(other);
        let w = writer(&mem, t);
        w.record(&frame(ME + 100, 50000, 60), 1);
        w.record(&frame(ME, 40000, 60), 2);
        w.record(&frame(ME + 100, 40000, 60), 3); // адрес одного, порт другого
        w.finish().unwrap();
        assert_eq!(mem.0.lock().unwrap().len(), 24 + 2 * (16 + 60));
    }

    struct Failing(usize);
    impl Write for Failing {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return Err(std::io::Error::other("disk full"));
            }
            self.0 -= 1;
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Ошибка записи не роняет приёмный поток, а возвращается из `finish` (exit 1).
    #[test]
    fn write_error_is_reported_by_finish_and_stops_recording() {
        let w = PcapWriter::new(Box::new(Failing(1)), one(ME), 0).unwrap();
        w.record(&frame(ME, 40000, 60), 1);
        w.record(&frame(ME, 40000, 60), 2);
        let e = w.finish().unwrap_err();
        assert!(e.contains("disk full"), "{e}");
        assert!(PcapWriter::new(Box::new(Failing(0)), one(ME), 0).is_err());
    }
}
