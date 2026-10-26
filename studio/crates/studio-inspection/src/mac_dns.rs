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
    error: Option<String>,
}
impl State {
    fn finish(self) -> studio_inspection::Result<Option<String>> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if !self.done {
            return Err("Hostname lookup deadline exceeded".into());
        }
        Ok(self.name)
    }
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
        // dns_sd.h: only authoritative missing name/record is a negative answer.
        if !matches!(error, -65538 | -65554) {
            state.error = Some(format!("System DNS resolver failed ({error})"));
        }
        state.done = true;
        return;
    }
    if flags & 2 == 0 || kind != 12 {
        return;
    }
    state.done = true;
    if data.is_null() || len == 0 {
        state.error = Some("System DNS resolver returned an invalid PTR record".into());
        return;
    }
    // SAFETY: DNS-SD guarantees rdata readable for rdlen during this callback.
    let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len as usize) };
    state.name = studio_inspection::decode_ptr(bytes);
    if state.name.is_none() {
        state.error = Some("System DNS resolver returned an invalid PTR record".into());
    }
}
pub fn lookup(ip: Ipv4Addr) -> studio_inspection::Result<Option<String>> {
    let octets = ip.octets();
    let query = CString::new(format!(
        "{}.{}.{}.{}.in-addr.arpa.",
        octets[3], octets[2], octets[1], octets[0]
    ))
    .map_err(|e| e.to_string())?;
    let mut state = Box::<State>::default();
    let mut reference = std::ptr::null_mut();
    // SAFETY: stable writable out-pointer and live CString/boxed context. The
    // callback ABI matches dns_sd.h; reference only used after successful init.
    let result = unsafe {
        DNSServiceQueryRecord(
            &mut reference,
            0x1000, // ReturnIntermediates: deliver authoritative NXDOMAIN.
            0,
            query.as_ptr(),
            12,
            1,
            callback,
            (&mut *state as *mut State).cast(),
        )
    };
    if result != 0 || reference.is_null() {
        return Err(format!("Cannot start system DNS query ({result})"));
    }
    let service = Service(reference);
    // SAFETY: service is a live successful reference.
    let fd = unsafe { DNSServiceRefSockFD(service.0) };
    if fd < 0 {
        return Err("System DNS resolver has no connection".into());
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
            return Err(format!(
                "System DNS resolver poll failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if ready > 0 {
            if p.revents & libc::POLLIN == 0 {
                return Err("System DNS resolver connection closed".into());
            }
            // SAFETY: live ref; callback accesses only the stable state box.
            let error = unsafe { DNSServiceProcessResult(service.0) };
            if error != 0 {
                return Err(format!("System DNS resolver failed ({error})"));
            }
        }
    }
    drop(service);
    state.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolver_errors_and_deadline_are_not_missing_names() {
        let mut state = State::default();
        // SAFETY: valid unique State, synchronous call, no rdata for errors.
        unsafe {
            callback(
                std::ptr::null_mut(),
                0,
                0,
                -65563,
                std::ptr::null(),
                12,
                1,
                0,
                std::ptr::null(),
                0,
                (&mut state as *mut State).cast(),
            )
        };
        assert!(state.finish().unwrap_err().contains("-65563"));
        assert!(State::default().finish().unwrap_err().contains("deadline"));
    }
    #[test]
    fn authoritative_absence_and_valid_ptr_are_distinct_from_bad_data() {
        for code in [-65538, -65554] {
            let mut state = State::default();
            unsafe {
                callback(
                    std::ptr::null_mut(),
                    0,
                    0,
                    code,
                    std::ptr::null(),
                    12,
                    1,
                    0,
                    std::ptr::null(),
                    0,
                    (&mut state as *mut State).cast(),
                )
            };
            assert_eq!(state.finish().unwrap(), None);
        }
        for (data, valid) in [
            (&b"\x04host\x05local\0"[..], true),
            (&b"\xc0\x0c"[..], false),
        ] {
            let mut state = State::default();
            unsafe {
                callback(
                    std::ptr::null_mut(),
                    2,
                    0,
                    0,
                    std::ptr::null(),
                    12,
                    1,
                    data.len() as u16,
                    data.as_ptr().cast(),
                    0,
                    (&mut state as *mut State).cast(),
                )
            };
            if valid {
                assert_eq!(state.finish().unwrap(), Some("host.local".into()));
            } else {
                assert!(state.finish().is_err());
            }
        }
    }
}
