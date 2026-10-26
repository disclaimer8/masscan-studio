//! DNS-SD callbacks execute synchronously inside DNSServiceProcessResult here.
//! No dispatch queue is registered; the state allocation outlives the service.
#![deny(unsafe_op_in_unsafe_fn)]
use std::{
    ffi::{CString, c_char, c_void},
    net::Ipv4Addr,
    time::{Duration, Instant},
};
type Ref = *mut c_void;
type Callback = unsafe extern "C" fn(
    Ref,
    u32,
    u32,
    i32,
    *const c_char,
    u16,
    u16,
    u16,
    *const c_void,
    u32,
    *mut c_void,
);
// DNS-SD is re-exported by libSystem on macOS (including SDK stub linking).
#[link(name = "System")]
unsafe extern "C" {
    fn DNSServiceQueryRecord(
        out: *mut Ref,
        flags: u32,
        interface: u32,
        name: *const c_char,
        kind: u16,
        class: u16,
        callback: Callback,
        context: *mut c_void,
    ) -> i32;
    fn DNSServiceRefSockFD(service: Ref) -> i32;
    fn DNSServiceProcessResult(service: Ref) -> i32;
    fn DNSServiceRefDeallocate(service: Ref);
}
struct Service(Ref);
impl Drop for Service {
    fn drop(&mut self) {
        // SAFETY: successful API-owned reference; deallocated once, no later calls.
        unsafe { DNSServiceRefDeallocate(self.0) };
    }
}
#[derive(Default)]
struct State {
    name: Option<String>,
    done: bool,
}
unsafe extern "C" fn callback(
    _: Ref,
    flags: u32,
    _: u32,
    error: i32,
    _: *const c_char,
    kind: u16,
    _: u16,
    len: u16,
    data: *const c_void,
    _: u32,
    context: *mut c_void,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: lookup supplies a live boxed State; callbacks are synchronous on
    // this one thread and finish before the box is freed.
    let state = unsafe { &mut *context.cast::<State>() };
    if error != 0 {
        state.done = true;
        return;
    }
    if flags & 2 == 0 || kind != 12 || data.is_null() || len == 0 {
        return;
    }
    // SAFETY: DNS-SD guarantees rdata readable for rdlen during this callback.
    let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len as usize) };
    state.name = studio_inspection::decode_ptr(bytes);
    state.done = state.name.is_some();
}
pub fn lookup(ip: Ipv4Addr) -> Option<String> {
    let octets = ip.octets();
    let query = CString::new(format!(
        "{}.{}.{}.{}.in-addr.arpa.",
        octets[3], octets[2], octets[1], octets[0]
    ))
    .ok()?;
    let mut state = Box::<State>::default();
    let mut reference = std::ptr::null_mut();
    // SAFETY: stable writable out-pointer and live CString/boxed context. The
    // callback ABI matches dns_sd.h; reference only used after successful init.
    let result = unsafe {
        DNSServiceQueryRecord(
            &mut reference,
            0,
            0,
            query.as_ptr(),
            12,
            1,
            callback,
            (&mut *state as *mut State).cast(),
        )
    };
    if result != 0 || reference.is_null() {
        return None;
    }
    let service = Service(reference);
    // SAFETY: service is a live successful reference.
    let fd = unsafe { DNSServiceRefSockFD(service.0) };
    if fd < 0 {
        return None;
    }
    let deadline = Instant::now() + Duration::from_millis(2800);
    while !state.done && Instant::now() < deadline {
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one writable pollfd, valid borrowed service fd; finite wait.
        let ready = unsafe { libc::poll(&mut p, 1, 50) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if ready > 0 {
            if p.revents & libc::POLLIN == 0 {
                break;
            }
            // SAFETY: live ref; callback accesses only the stable state box.
            if unsafe { DNSServiceProcessResult(service.0) } != 0 {
                break;
            }
        }
    }
    drop(service);
    state.name.take()
}
