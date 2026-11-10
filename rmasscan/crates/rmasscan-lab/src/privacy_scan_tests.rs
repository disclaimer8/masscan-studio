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
            "zzz",
            "--dir",
            d.to_str().unwrap()
        ])),
        Ok(1)
    );
    // a host name inside a capture, outside any DNS frame, is found as raw bytes
    let mut f = tcp_frame();
    f.extend(b"ACME-HOST");
    write_pcap(&d, "runs/x/peer.pcap", &[f]);
    let hits = scan(&d, &strings(&["zzz", "acme-host"])).unwrap();
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
