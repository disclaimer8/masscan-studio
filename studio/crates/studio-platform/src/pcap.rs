//! Read-only system-libpcap boundary for independent acceptance witnesses.
use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    ptr::{self, NonNull},
};
#[repr(C)]
struct Header {
    ts: libc::timeval,
    captured: u32,
    original: u32,
    comment: [c_char; 256],
}
#[repr(C)]
struct Program {
    len: u32,
    insns: *mut c_void,
}
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Statistics {
    pub received: u32,
    pub dropped: u32,
    pub interface_dropped: u32,
}
#[link(name = "pcap")]
unsafe extern "C" {
    fn pcap_create(name: *const c_char, err: *mut c_char) -> *mut c_void;
    fn pcap_set_snaplen(p: *mut c_void, n: c_int) -> c_int;
    fn pcap_set_promisc(p: *mut c_void, n: c_int) -> c_int;
    fn pcap_set_immediate_mode(p: *mut c_void, n: c_int) -> c_int;
    fn pcap_set_timeout(p: *mut c_void, n: c_int) -> c_int;
    fn pcap_activate(p: *mut c_void) -> c_int;
    fn pcap_datalink(p: *mut c_void) -> c_int;
    fn pcap_get_tstamp_precision(p: *mut c_void) -> c_int;
    fn pcap_compile(
        p: *mut c_void,
        b: *mut Program,
        f: *const c_char,
        opt: c_int,
        mask: u32,
    ) -> c_int;
    fn pcap_setfilter(p: *mut c_void, b: *mut Program) -> c_int;
    fn pcap_freecode(b: *mut Program);
    fn pcap_setnonblock(p: *mut c_void, n: c_int, err: *mut c_char) -> c_int;
    fn pcap_getnonblock(p: *mut c_void, err: *mut c_char) -> c_int;
    fn pcap_next_ex(p: *mut c_void, h: *mut *mut Header, b: *mut *const u8) -> c_int;
    fn pcap_stats(p: *mut c_void, s: *mut Statistics) -> c_int;
    fn pcap_geterr(p: *mut c_void) -> *const c_char;
    fn pcap_close(p: *mut c_void);
    fn pcap_lib_version() -> *const c_char;
}
pub struct Packet {
    pub seconds: u32,
    pub micros: u32,
    pub original_len: u32,
    pub bytes: Vec<u8>,
}
/// Owns one nonblocking read-only capture handle. NonNull keeps it !Send/!Sync.
pub struct Capture {
    handle: NonNull<c_void>,
}
impl Capture {
    pub fn open(interface: &str, filter: Option<&str>) -> Result<Self, String> {
        if interface.is_empty()
            || interface.len() > 63
            || !interface.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err("invalid capture interface".into());
        }
        let name = CString::new(interface).map_err(|e| e.to_string())?;
        let filter = filter
            .map(CString::new)
            .transpose()
            .map_err(|e| e.to_string())?;
        let mut err = [0 as c_char; 256];
        // SAFETY: NUL-terminated name and writable PCAP_ERRBUF_SIZE storage;
        // returned ownership is immediately put under Drop, including setup errors.
        let handle = NonNull::new(unsafe { pcap_create(name.as_ptr(), err.as_mut_ptr()) })
            .ok_or_else(|| error_buffer(&err))?;
        let capture = Self { handle };
        let p = capture.handle.as_ptr();
        // SAFETY: live exclusively owned handle. Configuration calls precede activation.
        unsafe {
            for (label, status) in [
                ("snaplen", pcap_set_snaplen(p, 131072)),
                ("non-promiscuous mode", pcap_set_promisc(p, 0)),
                ("immediate mode", pcap_set_immediate_mode(p, 1)),
                ("buffer timeout", pcap_set_timeout(p, 50)),
            ] {
                if status != 0 {
                    return Err(format!("pcap {label}: {}", capture.error()));
                }
            }
            // Warnings also refuse; do not silently accept degraded capture settings.
            if pcap_activate(p) != 0 {
                return Err(format!("pcap activate: {}", capture.error()));
            }
            if pcap_datalink(p) != 1 || pcap_get_tstamp_precision(p) != 0 {
                return Err("capture requires Ethernet and microsecond timestamps".into());
            }
            if let Some(filter) = filter {
                let mut program = Program {
                    len: 0,
                    insns: ptr::null_mut(),
                };
                if pcap_compile(p, &mut program, filter.as_ptr(), 1, u32::MAX) != 0 {
                    return Err(capture.error());
                }
                let status = pcap_setfilter(p, &mut program);
                pcap_freecode(&mut program);
                if status != 0 {
                    return Err(capture.error());
                }
            }
            if pcap_setnonblock(p, 1, err.as_mut_ptr()) != 0
                || pcap_getnonblock(p, err.as_mut_ptr()) != 1
            {
                return Err(format!("pcap nonblocking mode: {}", error_buffer(&err)));
            }
        }
        Ok(capture)
    }
    fn error(&self) -> String {
        // SAFETY: libpcap guarantees a NUL-terminated error buffer while handle is live.
        let p = unsafe { pcap_geterr(self.handle.as_ptr()) };
        if p.is_null() {
            "unknown libpcap error".into()
        } else {
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        }
    }
    pub fn read_packet(&mut self) -> Result<Option<Packet>, String> {
        let mut header = ptr::null_mut();
        let mut bytes = ptr::null();
        // SAFETY: live nonblocking handle and writable output pointer slots. Buffers
        // are borrowed only until the next libpcap call, and copied before returning.
        let status = unsafe { pcap_next_ex(self.handle.as_ptr(), &mut header, &mut bytes) };
        if status == 0 {
            return Ok(None);
        }
        if status != 1 {
            return Err(format!("capture read status {status}: {}", self.error()));
        }
        if header.is_null() || bytes.is_null() {
            return Err("libpcap returned null packet".into());
        }
        // SAFETY: successful pcap_next_ex supplies a valid Apple SDK pcap_pkthdr.
        let h = unsafe { &*header };
        let (seconds, micros) = validate_header(h.ts.tv_sec, h.ts.tv_usec, h.captured, h.original)?;
        // SAFETY: validated bounded caplen, equal to original length, backed by the
        // successful libpcap packet. No further libpcap call before the copy.
        let bytes = unsafe { std::slice::from_raw_parts(bytes, h.captured as usize) }.to_vec();
        Ok(Some(Packet {
            seconds,
            micros,
            original_len: h.original,
            bytes,
        }))
    }
    pub fn statistics(&mut self) -> Result<Statistics, String> {
        let mut stats = Statistics::default();
        // SAFETY: live handle and exact Unix pcap_stat layout with writable storage.
        if unsafe { pcap_stats(self.handle.as_ptr(), &mut stats) } != 0 {
            return Err(self.error());
        }
        Ok(stats)
    }
    pub fn version() -> String {
        // SAFETY: system libpcap returns a static NUL-terminated library version.
        unsafe { CStr::from_ptr(pcap_lib_version()) }
            .to_string_lossy()
            .into_owned()
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        // SAFETY: this object is the sole owner and closes exactly once.
        unsafe { pcap_close(self.handle.as_ptr()) };
    }
}
fn error_buffer(err: &[c_char; 256]) -> String {
    String::from_utf8_lossy(
        &err.iter()
            .take_while(|b| **b != 0)
            .map(|b| *b as u8)
            .collect::<Vec<_>>(),
    )
    .into_owned()
}
fn validate_header(
    seconds: i64,
    micros: i32,
    captured: u32,
    original: u32,
) -> Result<(u32, u32), String> {
    if !(0..=i64::from(u32::MAX)).contains(&seconds)
        || !(0..1_000_000).contains(&micros)
        || !(14..=131072).contains(&captured)
        || captured != original
    {
        return Err("invalid/truncated libpcap packet header".into());
    }
    Ok((seconds as u32, micros as u32))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pcap_header_validation_keeps_time_and_refuses_truncated_or_oversize_data() {
        assert_eq!(validate_header(100, 123, 60, 60).unwrap(), (100, 123));
        for args in [
            (-1, 0, 60, 60),
            (i64::from(u32::MAX) + 1, 0, 60, 60),
            (1, -1, 60, 60),
            (1, 1_000_000, 60, 60),
            (1, 0, 60, 61),
            (1, 0, 13, 13),
            (1, 0, 131073, 131073),
        ] {
            assert!(validate_header(args.0, args.1, args.2, args.3).is_err());
        }
    }
}
