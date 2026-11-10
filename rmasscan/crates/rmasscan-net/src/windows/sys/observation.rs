//! Read-only IP Helper observations. Calls are synchronous: checks before and
//! after them reject late/cancelled results but cannot interrupt WinAPI itself.
use std::collections::BTreeSet;
use std::mem::size_of;
use std::net::Ipv4Addr;
use std::time::Instant;

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

use crate::NetError;
use crate::network_plan::{InterfaceObservation, Ipv4Prefix, check_observation};
use crate::route_parse::{WinAdapter, iface_from_adapter};

const MAX_BUFFER_BYTES: usize = 16 * 1024 * 1024;
const MAX_NODES: usize = 65_536;
const MAX_STRING_UNITS: usize = 1024;
type AdapterObservation = (WinAdapter, Vec<Ipv4Prefix>);

fn malformed(detail: &str) -> NetError {
    NetError::System(format!("invalid IP Helper observation: {detail}"))
}

/// Four attempts, a fixed allocation limit, and checks surrounding every API
/// invocation. The callback is the synchronous OS boundary, also exercised by
/// tests for cancellation that arrives while that boundary is executing.
fn adapters_buffer_with(
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
    mut query: impl FnMut(*mut IP_ADAPTER_ADDRESSES_LH, &mut u32) -> u32,
) -> Result<Option<Vec<u64>>, NetError> {
    let mut size = 32 * 1024u32;
    for attempt in 0..4 {
        check_observation(deadline, cancelled)?;
        if (size as usize) < size_of::<IP_ADAPTER_ADDRESSES_LH>()
            || size as usize > MAX_BUFFER_BYTES
        {
            return Err(malformed("adapter buffer size exceeds bounds"));
        }
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        check_observation(deadline, cancelled)?;
        let capacity = size;
        let rc = query(buf.as_mut_ptr().cast(), &mut size);
        // This must precede every return path, including NO_DATA and OS errors.
        check_observation(deadline, cancelled)?;
        match rc {
            0 if size > 0 && size <= capacity => return Ok(Some(buf)),
            0 => return Err(malformed("invalid successful adapter buffer size")),
            ERROR_NO_DATA => return Ok(None),
            ERROR_BUFFER_OVERFLOW if attempt < 3 && size > capacity => {}
            ERROR_BUFFER_OVERFLOW => return Err(malformed("adapter buffer retry limit reached")),
            e => return Err(NetError::System(format!("GetAdaptersAddresses error {e}"))),
        }
    }
    unreachable!("every final attempt returns")
}

/// Check all raw pointers against the single live allocation before reading.
/// A malformed linked list cannot escape the allocation or run forever.
struct Buffer<'a>(&'a [u64]);
impl Buffer<'_> {
    fn extent<T>(&self, p: *const T, bytes: usize) -> Result<(), NetError> {
        let base = self.0.as_ptr() as usize;
        let offset = (p as usize)
            .checked_sub(base)
            .ok_or_else(|| malformed("pointer before adapter buffer"))?;
        if p.is_null()
            || offset
                .checked_add(bytes)
                .is_none_or(|end| end > std::mem::size_of_val(self.0))
        {
            return Err(malformed("pointer outside adapter buffer"));
        }
        Ok(())
    }

    fn ansi(&self, p: *const u8) -> Result<String, NetError> {
        let mut bytes = Vec::new();
        for i in 0..MAX_STRING_UNITS {
            // wrapping_add avoids pointer arithmetic UB before extent validates it.
            let at = p.wrapping_add(i);
            self.extent(at, 1)?;
            // SAFETY: extent verified this byte lies in the live initialized buffer.
            let b = unsafe { at.read() };
            if b == 0 {
                return Ok(String::from_utf8_lossy(&bytes).into_owned());
            }
            bytes.push(b);
        }
        Err(malformed("unterminated adapter name"))
    }

    fn wide(&self, p: *const u16) -> Result<Option<String>, NetError> {
        if p.is_null() {
            return Ok(None);
        }
        let mut units = Vec::new();
        for i in 0..MAX_STRING_UNITS {
            let at = p.wrapping_add(i);
            self.extent(at, size_of::<u16>())?;
            // SAFETY: extent verified both bytes; unaligned UTF-16 is supported.
            let u = unsafe { at.read_unaligned() };
            if u == 0 {
                return Ok((!units.is_empty()).then(|| String::from_utf16_lossy(&units)));
            }
            units.push(u);
        }
        Err(malformed("unterminated adapter friendly name"))
    }
}

fn decode_adapters(
    buf: &[u64],
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<AdapterObservation>, NetError> {
    check_observation(deadline, cancelled)?;
    if std::mem::size_of_val(buf) > MAX_BUFFER_BYTES {
        return Err(malformed("adapter buffer size exceeds bounds"));
    }
    let buffer = Buffer(buf);
    let mut adapters = Vec::new();
    let mut seen = BTreeSet::new();
    let mut remaining_nodes = MAX_NODES;
    let mut p = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !p.is_null() {
        check_observation(deadline, cancelled)?;
        if remaining_nodes == 0 || !seen.insert(p as usize) {
            return Err(malformed("adapter list cycle or node limit"));
        }
        remaining_nodes -= 1;
        buffer.extent(p, size_of::<IP_ADAPTER_ADDRESSES_LH>())?;
        // SAFETY: the complete struct lies in buf; its fields are integer values,
        // arrays, integer unions and pointers. No dereference uses unchecked pointers.
        let a = unsafe { p.read_unaligned() };
        // SAFETY: both union variants consist exclusively of integers.
        let header = unsafe { a.Anonymous1.Anonymous };
        if (header.Length as usize) < size_of::<IP_ADAPTER_ADDRESSES_LH>() {
            return Err(malformed("adapter structure is too short"));
        }
        buffer.extent(p, header.Length as usize)?;
        let prefixes = unicast_prefixes(
            &buffer,
            a.FirstUnicastAddress,
            &mut remaining_nodes,
            deadline,
            cancelled,
        )?;
        let adapter = WinAdapter {
            if_index: header.IfIndex,
            if_type: a.IfType,
            oper_up: a.OperStatus == IfOperStatusUp,
            adapter_name: buffer.ansi(a.AdapterName)?,
            friendly_name: buffer.wide(a.FriendlyName)?,
            mac: (a.PhysicalAddressLength == 6).then(|| {
                let mut mac = [0; 6];
                mac.copy_from_slice(&a.PhysicalAddress[..6]);
                mac
            }),
            ipv4: prefixes.iter().map(|p| p.address).collect(),
        };
        adapters.push((adapter, prefixes));
        p = a.Next;
    }
    check_observation(deadline, cancelled)?;
    Ok(adapters)
}

fn unicast_prefixes(
    buffer: &Buffer<'_>,
    mut p: *const IP_ADAPTER_UNICAST_ADDRESS_LH,
    remaining_nodes: &mut usize,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<Ipv4Prefix>, NetError> {
    let mut prefixes = Vec::new();
    let mut seen = BTreeSet::new();
    while !p.is_null() {
        check_observation(deadline, cancelled)?;
        if *remaining_nodes == 0 || !seen.insert(p as usize) {
            return Err(malformed("unicast list cycle or node limit"));
        }
        *remaining_nodes -= 1;
        buffer.extent(p, size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>())?;
        // SAFETY: the complete unicast struct is in the initialized buffer and
        // consists solely of integer values, integer unions and pointers.
        let u = unsafe { p.read_unaligned() };
        // SAFETY: the union's two variants are integer-only representations.
        let length = unsafe { u.Anonymous.Anonymous.Length } as usize;
        if length < size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>() {
            return Err(malformed("unicast structure has no prefix length"));
        }
        buffer.extent(p, length)?;
        let sa = u.Address.lpSockaddr;
        let length = usize::try_from(u.Address.iSockaddrLength)
            .map_err(|_| malformed("negative sockaddr length"))?;
        if length < size_of::<u16>() {
            return Err(malformed("short sockaddr family"));
        }
        buffer.extent(sa, length)?;
        // SAFETY: the two-byte address family was checked above.
        if unsafe { sa.cast::<u16>().read_unaligned() } == AF_INET {
            if length < size_of::<SOCKADDR_IN>() || u.OnLinkPrefixLength > 32 {
                return Err(malformed("invalid IPv4 sockaddr or prefix length"));
            }
            // SAFETY: the full IPv4 sockaddr lies in buf. All fields, including
            // the IN_ADDR union's S_addr, are integer representations.
            let raw = unsafe {
                sa.cast::<SOCKADDR_IN>()
                    .read_unaligned()
                    .sin_addr
                    .S_un
                    .S_addr
            };
            prefixes.push(Ipv4Prefix {
                address: Ipv4Addr::from(raw.to_ne_bytes()),
                length: u.OnLinkPrefixLength,
            });
        }
        p = u.Next;
    }
    check_observation(deadline, cancelled)?;
    Ok(prefixes)
}

fn observed_adapters(
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<AdapterObservation>, NetError> {
    let Some(buf) = adapters_buffer_with(deadline, cancelled, |out, size| {
        // SAFETY: the callback receives an 8-byte aligned buffer with at least
        // *size bytes; reserved is NULL and size is a live in/out parameter.
        unsafe {
            GetAdaptersAddresses(
                u32::from(AF_INET),
                super::GAA_FLAGS,
                std::ptr::null(),
                out,
                size,
            )
        }
    })?
    else {
        return Ok(Vec::new());
    };
    decode_adapters(&buf, deadline, cancelled)
}

pub(crate) fn adapters_until(
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<WinAdapter>, NetError> {
    let adapters = observed_adapters(deadline, cancelled)?
        .into_iter()
        .map(|(adapter, _)| adapter)
        .collect();
    check_observation(deadline, cancelled)?;
    Ok(adapters)
}

pub(crate) fn interfaces_until(
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<InterfaceObservation>, NetError> {
    let mut interfaces = Vec::new();
    for (adapter, ipv4_prefixes) in observed_adapters(deadline, cancelled)? {
        check_observation(deadline, cancelled)?;
        interfaces.push(InterfaceObservation {
            iface: iface_from_adapter(&adapter),
            ipv4_prefixes,
        });
    }
    check_observation(deadline, cancelled)?;
    Ok(interfaces)
}

#[cfg(test)]
#[path = "observation_tests.rs"]
mod tests;
