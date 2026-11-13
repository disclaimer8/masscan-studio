//! Synthetic captures only: frames are built here byte by byte (an mDNS answer with a compressed name, a clean TCP
//! segment); no real capture or name is in the repository.
use super::*;
use crate::windows_suite::nonce;
use std::path::PathBuf;

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-privacy-scan-{}", nonce()));
    fs::create_dir_all(&d).unwrap();
    d
}
fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}
fn label(s: &str) -> Vec<u8> {
    let mut v = vec![s.len() as u8];
    v.extend(s.as_bytes());
    v
}
/// An mDNS response: one PTR record `_svc._tcp.local` whose data is `pcname` + a pointer back to that name, so the
/// data name is compressed.
fn mdns_message(pcname: &str) -> Vec<u8> {
    let mut m = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    for l in ["_svc", "_tcp", "local"] {
        m.extend(label(l));
    }
    m.push(0);
    m.extend([0, 12, 0x80, 1, 0, 0, 0, 120]);
    let mut data = label(pcname);
    data.extend([0xc0, 12]);
    m.extend((data.len() as u16).to_be_bytes());
    m.extend(data);
    m
}
fn eth_ipv4_udp(sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![
        0x01, 0x00, 0x5e, 0, 0, 0xfb, 2, 0xaa, 0, 0, 0, 1, 8, 0, 0x45, 0,
    ];
    f.extend(((28 + payload.len()) as u16).to_be_bytes());
    f.extend([0, 0, 0, 0, 1, 17, 0, 0, 198, 18, 0, 1, 224, 0, 0, 251]);
    f.extend(sp.to_be_bytes());
    f.extend(dp.to_be_bytes());
    f.extend(((8 + payload.len()) as u16).to_be_bytes());
    f.extend([0, 0]);
    f.extend(payload);
    f
}
fn tcp_frame() -> Vec<u8> {
    let mut f = eth_ipv4_udp(1000, 80, &[0; 12]);
    f[23] = 6;
    f
}
fn write_pcap(dir: &Path, name: &str, frames: &[Vec<u8>]) {
    let fr: Frames = frames
        .iter()
        .enumerate()
        .map(|(i, f)| (i as f64, f.clone()))
        .collect();
    fs::write(dir.join(name), pcap::encode(&fr)).unwrap();
}

#[test]
fn an_mdns_record_with_a_compressed_name_is_a_hit_with_masked_names_and_the_frame_number() {
    let d = scratch();
    write_pcap(
        &d,
        "peer.pcap",
        &[
            tcp_frame(),
            eth_ipv4_udp(5353, 5353, &mdns_message("secret-pc")),
        ],
    );
    let hits = scan(&d, &[]).unwrap();
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(
        (hits[0].file.as_str(), hits[0].place.as_str()),
        ("peer.pcap", "frame 2")
    );
    let line = hits[0].line();
    // the owner name and the compressed data name are both decoded, and only their first three characters are shown
    assert!(
        line.contains("mDNS") && line.contains("_sv…") && line.contains("sec…"),
        "{line}"
    );
    assert!(
        !line.contains("secret") && !line.contains("_tcp") && !line.contains("local"),
        "{line}"
    );
    let names = dns_names(&mdns_message("secret-pc"));
    assert_eq!(names, ["_svc._tcp.local", "secret-pc._svc._tcp.local"]);
    assert_eq!(mask("secret-pc"), "sec…");
    assert_eq!(mask("ab"), "ab…");
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn llmnr_nbns_ipv6_and_vlan_frames_are_hits_too() {
    let d = scratch();
    let q = |name: &str| {
        let mut m = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend(label(name));
        m.extend([0, 0, 1, 0, 1]);
        m
    };
    // NBNS name `HOST` padded to 16 characters, first-level encoded
    let mut nb = [b' '; 16];
    nb[..4].copy_from_slice(b"HOST");
    let enc: String = nb
        .iter()
        .flat_map(|b| [char::from(b'A' + (b >> 4)), char::from(b'A' + (b & 15))])
        .collect();
    let mut vlan = eth_ipv4_udp(5355, 5355, &q("somehost"));
    vlan.splice(12..14, [0x81, 0x00, 0, 5, 8, 0]);
    let mut v6 = vec![0u8; 12];
    v6.extend([0x86, 0xdd, 0x60, 0, 0, 0, 0, 0, 17, 1]);
    v6.extend([0u8; 32]);
    let udp_payload = q("v6host");
    v6.extend(5353u16.to_be_bytes());
    v6.extend(5353u16.to_be_bytes());
    v6.extend(((8 + udp_payload.len()) as u16).to_be_bytes());
    v6.extend([0, 0]);
    v6.extend(&udp_payload);
    write_pcap(&d, "a.pcap", &[eth_ipv4_udp(137, 137, &q(&enc)), vlan, v6]);
    let hits = scan(&d, &[]).unwrap();
    assert_eq!(hits.len(), 3, "{hits:?}");
    assert!(
        hits[0].what.contains("NBNS") && hits[0].what.contains("HOS…"),
        "{:?}",
        hits[0]
    );
    assert!(hits[1].what.contains("LLMNR") && hits[1].what.contains("som…"));
    assert!(hits[2].what.contains("mDNS") && hits[2].what.contains("v6h…"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn a_pcapng_with_an_mdns_frame_is_a_hit() {
    let d = scratch();
    let f = eth_ipv4_udp(5353, 5353, &mdns_message("ng-host"));
    let mut b = vec![
        0x0a, 0x0d, 0x0d, 0x0a, 28, 0, 0, 0, 0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0,
    ];
    b.extend([0xff; 8]);
    b.extend([28, 0, 0, 0]);
    let padded = (f.len() + 3) & !3;
    let len = (32 + padded) as u32;
    b.extend(6u32.to_le_bytes());
    b.extend(len.to_le_bytes());
    b.extend([0; 12]);
    b.extend((f.len() as u32).to_le_bytes());
    b.extend((f.len() as u32).to_le_bytes());
    b.extend(&f);
    b.extend(vec![0; padded - f.len()]);
    b.extend(len.to_le_bytes());
    fs::write(d.join("x.pcapng"), b).unwrap();
    let hits = scan(&d, &[]).unwrap();
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].what.contains("ng-…"), "{:?}", hits[0]);
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn a_clean_directory_has_no_hit_and_exits_zero() {
    let d = scratch();
    write_pcap(
        &d,
        "peer.pcap",
        &[tcp_frame(), eth_ipv4_udp(4000, 4001, &[1, 2, 3])],
    );
    fs::write(d.join("note.txt"), "198.18.0.1 veth-a\nnothing private\n").unwrap();
    fs::write(d.join("broken.pcap"), b"not a capture").unwrap();
    assert_eq!(scan(&d, &strings(&["acme-host"])).unwrap(), []);
    assert_eq!(
        run(&strings(&[
            "--dir",
            d.to_str().unwrap(),
            "--forbid",
            "acme-host"
        ])),
        Ok(0)
    );
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn a_forbidden_token_in_a_text_file_or_a_capture_exits_one_without_printing_the_token() {
    let d = scratch();
    fs::create_dir_all(d.join("runs/x")).unwrap();
    fs::write(
        d.join("runs/x/stderr.txt"),
        "line one\nsee ACME-Host here\n",
    )
    .unwrap();
    let hits = scan(&d, &strings(&["acme-host"])).unwrap();
    assert_eq!(
        hits,
        [Hit {
            file: "runs/x/stderr.txt".into(),
            place: "line 2".into(),
            what: "forbidden token #1".into()
        }]
    );
    assert!(!hits[0].line().to_lowercase().contains("acme"));
    assert_eq!(
        run(&strings(&[
            "--forbid",
            "acme-host",
            "--forbid",
            "zzzz",
            "--dir",
            d.to_str().unwrap()
        ])),
        Ok(1)
    );
    // a host name inside a capture, outside any DNS frame, is found as raw bytes
    let mut f = tcp_frame();
    f.extend(b"ACME-HOST");
    write_pcap(&d, "runs/x/peer.pcap", &[f]);
    let hits = scan(&d, &strings(&["zzzz", "acme-host"])).unwrap();
    assert!(
        hits.iter()
            .any(|h| h.file == "runs/x/peer.pcap" && h.what == "forbidden token #2"),
        "{hits:?}"
    );
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn bad_arguments_and_pointer_loops_are_handled() {
    assert!(run(&[]).is_err());
    assert!(run(&strings(&["--dir"])).is_err());
    assert!(run(&strings(&["--dir", "/nonexistent-privacy-scan-dir"])).is_err());
    assert_eq!(run(&strings(&["--help"])), Ok(0));
    // a name that points at itself ends, it does not loop
    let mut m = vec![0u8; 12];
    m[5] = 1;
    m.extend([0xc0, 12, 0, 1, 0, 1]);
    assert_eq!(dns_names(&m), Vec::<String>::new());
}

#[test]
fn forbidden_tokens_shorter_than_four_bytes_are_refused_without_printing_them() {
    let d = scratch();
    let dir = d.to_str().unwrap();
    // "é" is 2 bytes, "qzé" 4 bytes: the limit counts bytes, as the search does
    for short in ["", "qz", "qzx", "é"] {
        let e = run(&strings(&[
            "--dir",
            dir,
            "--forbid",
            "long-token",
            "--forbid",
            short,
        ]))
        .unwrap_err();
        assert!(e.contains("--forbid #2") && e.contains("4 bytes"), "{e}");
        assert!(short.is_empty() || !e.contains(short), "{e}");
    }
    assert_eq!(
        run(&strings(&[
            "--dir", dir, "--forbid", "qzx1", "--forbid", "qzé"
        ])),
        Ok(0)
    );
    fs::remove_dir_all(d).unwrap();
}

/// A pcapng section header block with one `opt_comment` and an Enhanced Packet Block whose timestamp is `ts`.
fn pcapng_with(comment: &[u8], ts: [u8; 8], f: &[u8]) -> Vec<u8> {
    let pad = |n: usize| (n + 3) & !3;
    let mut opts = Vec::new();
    opts.extend(1u16.to_le_bytes());
    opts.extend((comment.len() as u16).to_le_bytes());
    opts.extend(comment);
    opts.extend(vec![0; pad(comment.len()) - comment.len()]);
    opts.extend([0; 4]);
    let shb_len = (28 + opts.len()) as u32;
    let mut b = vec![0x0a, 0x0d, 0x0d, 0x0a];
    b.extend(shb_len.to_le_bytes());
    b.extend([0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0]);
    b.extend([0xff; 8]);
    b.extend(&opts);
    b.extend(shb_len.to_le_bytes());
    let epb_len = (32 + pad(f.len())) as u32;
    b.extend(6u32.to_le_bytes());
    b.extend(epb_len.to_le_bytes());
    b.extend([0; 4]);
    b.extend(ts);
    b.extend((f.len() as u32).to_le_bytes());
    b.extend((f.len() as u32).to_le_bytes());
    b.extend(f);
    b.extend(vec![0; pad(f.len()) - f.len()]);
    b.extend(epb_len.to_le_bytes());
    b
}

/// T8b: the raw-bytes pass over a capture skips the record headers (timestamps, lengths), whose bytes matched a short
/// token by chance in r3, and still searches the frames, the pcapng text blocks and a capture that does not parse.
#[test]
fn a_token_in_capture_record_headers_is_not_a_hit_but_in_frames_and_pcapng_text_it_is() {
    let d = scratch();
    let t = strings(&["wxyz"]);
    // classic pcap: the first record's seconds field (bytes 24..28, after the 24-byte global header) is `WXYZ`
    let mut hdr = pcap::encode(&vec![(0.0, tcp_frame())]);
    hdr[24..28].copy_from_slice(b"WXYZ");
    fs::write(d.join("hdr.pcap"), &hdr).unwrap();
    // pcapng: the packet block's timestamp is `WXYZWXYZ`, the comment is clean
    fs::write(
        d.join("hdr.pcapng"),
        pcapng_with(b"clean", *b"WXYZWXYZ", &tcp_frame()),
    )
    .unwrap();
    assert_eq!(scan(&d, &t).unwrap(), []);
    // the token in a frame, in a pcapng comment, or anywhere in a capture that does not parse is a hit
    let mut f = tcp_frame();
    f.extend(b"wxyz");
    write_pcap(&d, "frame.pcap", &[f]);
    fs::write(
        d.join("note.pcapng"),
        pcapng_with(b"host wxyz-1", [0; 8], &tcp_frame()),
    )
    .unwrap();
    fs::write(d.join("broken.pcap"), b"not a capture WXYZ").unwrap();
    let files: Vec<String> = scan(&d, &t)
        .unwrap()
        .into_iter()
        .map(|h| format!("{} {} {}", h.file, h.place, h.what))
        .collect();
    assert_eq!(
        files,
        [
            "broken.pcap bytes forbidden token #1",
            "frame.pcap bytes forbidden token #1",
            "note.pcapng bytes forbidden token #1"
        ]
    );
    fs::remove_dir_all(d).unwrap();
}

/// An Ethernet + IPv6 frame carrying ICMPv6 `icmp` (checksum left 0: the scan reads names, not sums).
fn eth_ipv6_icmp(icmp: &[u8]) -> Vec<u8> {
    let mut f = vec![
        0x33, 0x33, 0, 0, 0, 1, 2, 0xaa, 0, 0, 0, 2, 0x86, 0xdd, 0x60, 0, 0, 0,
    ];
    f.extend((icmp.len() as u16).to_be_bytes());
    f.extend([58, 255]);
    f.extend([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0, 0xff, 0xfe, 0, 0, 2,
    ]);
    f.extend([0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    f.extend(icmp);
    f
}
/// A Router Advertisement with a DNS Search List option (RFC 8106, type 31) naming `domain`.
fn ra_with_dnssl(domain: &str) -> Vec<u8> {
    let mut icmp = vec![134, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut names = Vec::new();
    for l in domain.split('.') {
        names.extend(label(l));
    }
    names.push(0);
    while (8 + names.len()) % 8 != 0 {
        names.push(0);
    }
    icmp.extend([31, ((8 + names.len()) / 8) as u8, 0, 0, 0, 0, 0x0e, 0x10]);
    icmp.extend(names);
    icmp
}
/// An ICMPv6 Node Information Reply (RFC 4620, type 140) with a Node Name (Qtype 2): TTL, then the DNS-encoded name.
fn node_name_reply(name: &str) -> Vec<u8> {
    let mut icmp = vec![140, 0, 0, 0, 0, 2, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0];
    for l in name.split('.') {
        icmp.extend(label(l));
    }
    icmp.push(0);
    icmp
}

#[test]
fn icmpv6_messages_that_carry_names_are_hits_with_masked_names_and_ndp_without_names_is_not() {
    let d = scratch();
    // an NS (ICMPv6 135, no name) is no hit
    let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
    ns.extend([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0, 0xff, 0xfe, 0, 0, 2, 1, 1, 2, 0xaa, 0, 0, 0, 1,
    ]);
    write_pcap(
        &d,
        "peer.pcap",
        &[
            eth_ipv6_icmp(&ns),
            eth_ipv6_icmp(&ra_with_dnssl("corp.example")),
            eth_ipv6_icmp(&node_name_reply("hostname.example")),
        ],
    );
    let hits = scan(&d, &[]).unwrap();
    let lines: Vec<String> = hits.iter().map(Hit::line).collect();
    assert_eq!(hits.len(), 2, "{lines:#?}");
    assert_eq!(
        lines[0],
        "peer.pcap: frame 2: NDP Router Advertisement DNS Search List frame, names: cor…"
    );
    assert_eq!(
        lines[1],
        "peer.pcap: frame 3: ICMPv6 Node Information frame, names: hos…"
    );
    assert!(
        lines
            .iter()
            .all(|l| !l.contains("corp.example") && !l.contains("hostname"))
    );
    fs::remove_dir_all(&d).unwrap();
}

/// A UDP frame of the Linux stand: scanner 198.18.0.1:40000 to `peer`:137 (`probe`) or back.
fn stand_udp(peer: u8, probe: bool, payload: &[u8]) -> Vec<u8> {
    let (a, b) = ([2u8, 0xaa, 0, 0, 0, 1], [2u8, 0xaa, 0, 0, 0, 2]);
    let (s, d) = (
        std::net::Ipv4Addr::new(198, 18, 0, 1),
        std::net::Ipv4Addr::new(198, 18, 0, peer),
    );
    let mut u = Vec::new();
    let (sp, dp) = if probe {
        (40000u16, 137u16)
    } else {
        (137, 40000)
    };
    u.extend(sp.to_be_bytes());
    u.extend(dp.to_be_bytes());
    u.extend(((8 + payload.len()) as u16).to_be_bytes());
    u.extend([0, 0]);
    u.extend(payload);
    if probe {
        crate::protocols_verify::tests::ip_frame(b, a, s, d, 17, u)
    } else {
        crate::protocols_verify::tests::ip_frame(a, b, d, s, 17, u)
    }
}

#[test]
fn the_banners_stands_own_nbns_probes_and_replies_are_counted_not_hits_and_nothing_else_is() {
    let d = scratch();
    let probe = rmasscan_core::payloads::PayloadTable::builtin()
        .get(137)
        .unwrap()
        .with_cookie(0x4321);
    let mut frames = Vec::new();
    for peer in 2..=5u8 {
        let ip = std::net::Ipv4Addr::new(198, 18, 0, peer);
        frames.push(stand_udp(peer, true, &probe));
        frames.push(stand_udp(
            peer,
            false,
            &crate::banners_verify::scenario_reply(137, ip, &probe).unwrap(),
        ));
    }
    assert!(frames.iter().all(|f| stand_nbns(f)));
    write_pcap(&d, "peer.pcap", &frames);
    assert_eq!(scan_counted(&d, &[]).unwrap(), (Vec::new(), 8));
    // A changed name byte, another address, another port, a VLAN tag: each an NBNS frame that is a hit again.
    let reply =
        crate::banners_verify::scenario_reply(137, std::net::Ipv4Addr::new(198, 18, 0, 2), &probe)
            .unwrap();
    let mut renamed = reply.clone();
    renamed[60] ^= 0x20;
    let mut off_stand = stand_udp(2, false, &reply);
    off_stand[29] = 9;
    let mut other_port = stand_udp(2, false, &reply);
    other_port[37] = 1;
    let others = [stand_udp(2, false, &renamed), off_stand, other_port];
    for f in &others {
        assert!(!stand_nbns(f));
    }
    write_pcap(&d, "other.pcap", &others);
    let (hits, stand) = scan_counted(&d, &[]).unwrap();
    assert_eq!(stand, 8);
    assert_eq!(hits.len(), 3, "{hits:?}");
    assert!(
        hits.iter()
            .all(|h| h.file == "other.pcap" && h.what.starts_with("NBNS frame"))
    );
    fs::remove_dir_all(&d).unwrap();
}
