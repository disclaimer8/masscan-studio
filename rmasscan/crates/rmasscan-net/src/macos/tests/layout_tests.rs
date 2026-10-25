//! Раскладка структур и номера ioctl BPF macOS (aarch64, LP64).

use std::mem::{align_of, offset_of, size_of};

use crate::macos::abi::*;
use crate::macos::sys::*;

/// `_IOC` из sys/ioccom.h.
fn ioc(dir: u32, group: u8, num: u32, len: usize) -> u32 {
    dir | (((len as u32) & 0x1fff) << 16) | (u32::from(group) << 8) | num
}
const VOID: u32 = 0x2000_0000;
const OUT: u32 = 0x4000_0000;
const IN: u32 = 0x8000_0000;

fn iow(num: u32, len: usize) -> u32 {
    ioc(IN, b'B', num, len)
}
fn ior(num: u32, len: usize) -> u32 {
    ioc(OUT, b'B', num, len)
}

#[test]
fn struct_layouts_match_lp64() {
    // sizeof(struct bpf_hdr) = 20 (как libc); запись ядра = SIZEOF_BPF_HDR = 18.
    assert_eq!(size_of::<BpfHdr>(), 20);
    assert_eq!(align_of::<BpfHdr>(), 4);
    assert_eq!(size_of::<BpfHdr>(), size_of::<libc::bpf_hdr>());
    assert_eq!(align_of::<BpfHdr>(), align_of::<libc::bpf_hdr>());
    assert_eq!(
        offset_of!(BpfHdr, bh_tstamp),
        offset_of!(libc::bpf_hdr, bh_tstamp)
    );
    assert_eq!(offset_of!(BpfHdr, bh_caplen), 8);
    assert_eq!(offset_of!(BpfHdr, bh_datalen), 12);
    assert_eq!(offset_of!(BpfHdr, bh_hdrlen), 16);
    assert_eq!(
        offset_of!(BpfHdr, bh_caplen),
        offset_of!(libc::bpf_hdr, bh_caplen)
    );
    assert_eq!(
        offset_of!(BpfHdr, bh_datalen),
        offset_of!(libc::bpf_hdr, bh_datalen)
    );
    assert_eq!(
        offset_of!(BpfHdr, bh_hdrlen),
        offset_of!(libc::bpf_hdr, bh_hdrlen)
    );
    assert_eq!(SIZEOF_BPF_HDR, 18);
    assert_eq!(bpf_wordalign(SIZEOF_BPF_HDR), 20);
    assert_eq!(bpf_wordalign(18), 20);
    assert_eq!(size_of::<BpfInsn>(), 8);
    assert_eq!(size_of::<BpfProgram>(), 16);
    assert_eq!(size_of::<BpfStat>(), 8);
    assert_eq!(size_of::<libc::ifreq>(), 32);
    assert_eq!(size_of::<libc::timeval32>(), 8);
}

#[test]
fn wordalign_rounds_up_to_four() {
    for (x, y) in [(0, 0), (1, 4), (4, 4), (5, 8), (19, 20), (20, 20), (21, 24)] {
        assert_eq!(bpf_wordalign(x), y, "{x}");
    }
}

#[test]
fn ioc_reproduces_every_libc_constant() {
    let ifreq = size_of::<libc::ifreq>();
    assert_eq!(iow(108, ifreq), 0x8020_426c);
    assert_eq!(iow(108, ifreq), libc::BIOCSETIF as u32);
    assert_eq!(ior(107, ifreq), libc::BIOCGETIF as u32);
    assert_eq!(iow(112, 4), libc::BIOCIMMEDIATE as u32);
    assert_eq!(iow(112, 4), 0x8004_4270);
    assert_eq!(ioc(IN | OUT, b'B', 102, 4), libc::BIOCSBLEN as u32);
    assert_eq!(ioc(IN | OUT, b'B', 102, 4), 0xc004_4266);
    assert_eq!(ior(102, 4), libc::BIOCGBLEN as u32);
    assert_eq!(ior(102, 4), 0x4004_4266);
    assert_eq!(ior(111, size_of::<BpfStat>()), libc::BIOCGSTATS as u32);
    assert_eq!(ior(111, 8), 0x4008_426f);
    assert_eq!(iow(117, 4), libc::BIOCSHDRCMPLT as u32);
    assert_eq!(iow(117, 4), 0x8004_4275);
    assert_eq!(ior(116, 4), libc::BIOCGHDRCMPLT as u32);
    assert_eq!(ior(106, 4), libc::BIOCGDLT as u32);
    assert_eq!(ior(106, 4), 0x4004_426a);
    assert_eq!(ior(113, 4), libc::BIOCVERSION as u32);
    assert_eq!(ioc(VOID, b'B', 105, 0), libc::BIOCPROMISC);
    assert_eq!(ioc(VOID, b'B', 105, 0), 0x2000_4269);
    assert_eq!(ioc(VOID, b'B', 104, 0), libc::BIOCFLUSH);
    assert_eq!(ioc(VOID, b'B', 104, 0), 0x2000_4268);
}

#[test]
fn own_constants_are_derived_from_the_ioc_formula() {
    let prog = size_of::<BpfProgram>();
    let tv = size_of::<libc::timeval>();
    assert_eq!(BIOCSETF as u32, iow(103, prog));
    assert_eq!(BIOCSETFNR as u32, iow(126, prog));
    assert_eq!(BIOCSSEESENT as u32, iow(119, 4));
    assert_eq!(BIOCGSEESENT as u32, ior(118, 4));
    assert_eq!(BIOCSRTIMEOUT as u32, iow(109, tv));
    // Те же значения, что в libc там, где libc их объявляет.
    assert_eq!(BIOCSETF, libc::BIOCSETF);
    assert_eq!(BIOCSETFNR, libc::BIOCSETFNR);
    assert_eq!(BIOCSRTIMEOUT, libc::BIOCSRTIMEOUT);
    assert_eq!(
        (DLT_NULL, DLT_EN10MB, IFT_ETHER, BPF_ALIGNMENT),
        (0, 1, 6, 4)
    );
}

#[test]
fn own_constants_match_the_sdk_header() {
    const HDR: &str = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/net/bpf.h";
    let Ok(text) = std::fs::read_to_string(HDR) else {
        assert!(
            std::env::var("RMASSCAN_REQUIRE_SDK").as_deref() != Ok("1"),
            "NOT RUN: {HDR} missing and RMASSCAN_REQUIRE_SDK=1"
        );
        eprintln!("NOT RUN: {HDR} missing (not a PASS)");
        return;
    };
    let squashed: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let norm = |s: &str| s.replace(", ", ",");
    let squashed = norm(&squashed);
    for want in [
        "BIOCSETF _IOW('B',103,struct bpf_program)",
        "BIOCSRTIMEOUT _IOW('B',109,struct timeval)",
        "BIOCGSEESENT _IOR('B',118,u_int)",
        "BIOCSSEESENT _IOW('B',119,u_int)",
        "BIOCSETFNR _IOW('B',126,struct bpf_program)",
        "#define BPF_TIMEVAL timeval32",
    ] {
        assert!(squashed.contains(want), "SDK header lacks {want:?}");
    }
    // timeval32 выбирается именно под __LP64__.
    let lp64 = squashed
        .find("#if defined(__LP64__)")
        .expect("__LP64__ block");
    let tv = squashed.find("#define BPF_TIMEVAL timeval32").unwrap();
    let els = squashed[lp64..].find("#else").map(|i| i + lp64).unwrap();
    assert!(lp64 < tv && tv < els, "timeval32 is not under __LP64__");
}

#[test]
fn portable_errno_and_header_constants_match_libc() {
    use crate::macos::abi::errno::*;
    assert_eq!(EPERM, libc::EPERM);
    assert_eq!(ENOENT, libc::ENOENT);
    assert_eq!(EINTR, libc::EINTR);
    assert_eq!(ENXIO, libc::ENXIO);
    assert_eq!(EACCES, libc::EACCES);
    assert_eq!(EBUSY, libc::EBUSY);
    assert_eq!(ENODEV, libc::ENODEV);
    assert_eq!(EAGAIN, libc::EAGAIN);
    assert_eq!(EAGAIN, libc::EWOULDBLOCK);
    assert_eq!(EMSGSIZE, libc::EMSGSIZE);
    assert_eq!(ENOBUFS, libc::ENOBUFS);
    assert_eq!(HDR_OFF_CAPLEN, offset_of!(BpfHdr, bh_caplen));
    assert_eq!(HDR_OFF_DATALEN, offset_of!(BpfHdr, bh_datalen));
    assert_eq!(HDR_OFF_HDRLEN, offset_of!(BpfHdr, bh_hdrlen));
    assert_eq!(
        SIZEOF_BPF_HDR,
        offset_of!(BpfHdr, bh_hdrlen) + size_of::<u16>()
    );
}

#[test]
#[allow(unsafe_code)] // test-only: the checks below never reach the kernel with a valid fd
fn ioctl_ptr_refuses_an_argument_whose_size_differs_from_the_request() {
    // Размер проверяется до системного вызова; дескриптор не открывается.
    let mut wrong = 0u64;
    assert_eq!(
        // SAFETY: fd -1 никуда не ведёт; `u64` допускает любой образ, размер не совпал
        // и вызов до ядра не доходит.
        unsafe { crate::macos::sys::ioctl_ptr(-1, libc::BIOCGBLEN, &mut wrong) },
        Err(libc::EINVAL)
    );
    let mut right = 0u32;
    assert_eq!(
        // SAFETY: fd -1 ядро отвергает (EBADF); `u32` допускает любой образ.
        unsafe { crate::macos::sys::ioctl_ptr(-1, libc::BIOCGBLEN, &mut right) },
        Err(libc::EBADF),
        "the right size reaches the kernel, which rejects the fd"
    );
    let mut stat = BpfStat::default();
    assert_eq!(
        // SAFETY: fd -1 ядро отвергает (EBADF); `BpfStat` из целых.
        unsafe { crate::macos::sys::ioctl_ptr(-1, libc::BIOCGSTATS, &mut stat) },
        Err(libc::EBADF)
    );
}
