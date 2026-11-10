//! `privacy-scan --dir DIR [--forbid TOKEN]...`: the pre-commit privacy scan of an evidence directory, OUTSIDE every
//! verdict (the verifiers' rules, and with them the committed verdicts, are not touched by it).
//!
//! 1. Every `.pcap` and `.pcapng` under DIR is parsed, and any mDNS (UDP 5353), LLMNR (5355) or NBNS (137) frame is a
//!    hit: such frames announce the host names of the machines on the lab NIC (a guest OS's own LAN discovery), which
//!    the verifiers' pcap rules allow as OS traffic. The DNS names in them are decoded from wire form (length-prefixed
//!    labels, compression pointers, names in PTR/CNAME/NS/SRV data, NetBIOS first-level names) and printed MASKED (the
//!    first three characters and an ellipsis), with the file and the frame number. A text search for `_tcp.local` does
//!    not find them: the labels are length-prefixed on the wire.
//! 2. Every other file is searched as text, and every capture as raw bytes, for the forbidden tokens the operator passes
//!    with `--forbid TOKEN` (repeatable; no real name lives in the repository). A hit prints the file, the line and the
//!    number of the token, never the token.
//!
//! Exit 0 only without a hit, 1 on any hit, 2 when the directory cannot be read.
use crate::pcap::{self, Frames};
use std::{fs, path::Path};

const PORTS: [(u16, &str); 3] = [(5353, "mDNS"), (5355, "LLMNR"), (137, "NBNS")];

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub file: String,
    /// `frame 12` or `line 3`.
    pub place: String,
    pub what: String,
}
impl Hit {
    pub fn line(&self) -> String {
        format!("{}: {}: {}", self.file, self.place, self.what)
    }
}

/// `abcdef` as `abc…`; short names are masked whole.
pub fn mask(name: &str) -> String {
    format!("{}…", name.chars().take(3).collect::<String>())
}

/// The name at `at` in a DNS message, with compression; its end offset in the uncompressed part. `None` for a malformed
/// name or a pointer loop (more than 32 jumps).
fn name_at(msg: &[u8], mut at: usize) -> Option<(String, usize)> {
    let (mut labels, mut end, mut jumps) = (Vec::new(), None, 0);
    loop {
        let len = *msg.get(at)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(at + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let to = ((len & 0x3f) << 8) | *msg.get(at + 1)? as usize;
            end.get_or_insert(at + 2);
            jumps += 1;
            if jumps > 32 {
                return None;
            }
            at = to;
        } else if len & 0xc0 != 0 {
            return None;
        } else {
            let label = msg.get(at + 1..at + 1 + len)?;
            // a NetBIOS first-level name: 32 letters A-P, two per byte
            let text = if len == 32 && label.iter().all(|b| (b'A'..=b'P').contains(b)) {
                label
                    .chunks(2)
                    .map(|p| char::from(((p[0] - b'A') << 4) | (p[1] - b'A')))
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            } else {
                String::from_utf8_lossy(label).into_owned()
            };
            labels.push(text);
            at += 1 + len;
        }
    }
}
/// Every name of a DNS message (mDNS, LLMNR, NBNS share the header): the questions' and records' owner names and the
/// names inside NS, CNAME, PTR and SRV data.
pub fn dns_names(msg: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let count = |o: usize| {
        msg.get(o..o + 2)
            .map_or(0, |b| usize::from(u16::from_be_bytes([b[0], b[1]])))
    };
    let (qd, rr) = (count(4), count(6) + count(8) + count(10));
    let mut at = 12;
    for _ in 0..qd {
        let Some((n, e)) = name_at(msg, at) else {
            return out;
        };
        out.push(n);
        at = e + 4;
    }
    for _ in 0..rr {
        let Some((n, e)) = name_at(msg, at) else {
            return out;
        };
        out.push(n);
        let Some(h) = msg.get(e..e + 10) else {
            return out;
        };
        let (ty, len) = (
            u16::from_be_bytes([h[0], h[1]]),
            usize::from(u16::from_be_bytes([h[8], h[9]])),
        );
        let data = e + 10;
        let inner = match ty {
            2 | 5 | 12 => Some(data),
            33 => Some(data + 6),
            _ => None,
        };
        if let Some((n, _)) = inner.and_then(|o| name_at(msg, o)) {
            out.push(n);
        }
        at = data + len;
    }
    out
}

/// The UDP payload and its protocol of an Ethernet frame to or from 5353, 5355 or 137.
fn lan_discovery(f: &[u8]) -> Option<(&'static str, &[u8])> {
    let mut t = u16::from_be_bytes([*f.get(12)?, *f.get(13)?]);
    let mut at = 14;
    while t == 0x8100 || t == 0x88a8 {
        t = u16::from_be_bytes([*f.get(at + 2)?, *f.get(at + 3)?]);
        at += 4;
    }
    let udp = match t {
        0x0800 => {
            let ihl = usize::from(f.get(at)? & 15) * 4;
            (*f.get(at + 9)? == 17).then_some(at + ihl)?
        }
        0x86dd => {
            // the next header chain: skip hop-by-hop, routing, destination options
            let (mut next, mut o) = (*f.get(at + 6)?, at + 40);
            while matches!(next, 0 | 43 | 60) {
                let len = (usize::from(*f.get(o + 1)?) + 1) * 8;
                next = *f.get(o)?;
                o += len;
            }
            (next == 17).then_some(o)?
        }
        _ => return None,
    };
    let port = |o: usize| {
        f.get(udp + o..udp + o + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
    };
    let (sp, dp) = (port(0)?, port(2)?);
    let name = PORTS.iter().find(|(p, _)| *p == sp || *p == dp)?.1;
    Some((name, f.get(udp + 8..)?))
}

/// The frames of a `.pcapng` file (Enhanced and Simple Packet Blocks), either byte order.
fn pcapng_frames(b: &[u8]) -> Frames {
    let mut out = Vec::new();
    if b.get(..4) != Some(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        return out;
    }
    let le = b.get(8..12) == Some(&[0x4d, 0x3c, 0x2b, 0x1a]);
    let u32_at = |o: usize| {
        b.get(o..o + 4).map(|x| {
            let a = [x[0], x[1], x[2], x[3]];
            if le {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            }
        })
    };
    let mut o = 0;
    while let (Some(ty), Some(len)) = (u32_at(o), u32_at(o + 4)) {
        let len = len as usize;
        if len < 12 || o + len > b.len() {
            break;
        }
        match ty {
            6 => {
                if let Some(cap) = u32_at(o + 20)
                    && let Some(d) = b.get(o + 28..o + 28 + cap as usize)
                {
                    out.push((0.0, d.to_vec()));
                }
            }
            3 => {
                if let Some(d) = b.get(o + 12..o + len - 4) {
                    out.push((0.0, d.to_vec()));
                }
            }
            _ => {}
        }
        o += (len + 3) & !3;
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let ty = e.file_type().map_err(|e| e.to_string())?;
        if ty.is_dir() {
            walk(&e.path(), out)?;
        } else if ty.is_file() {
            out.push(e.path());
        }
    }
    Ok(())
}

/// Scans `dir`: every hit, in file and frame order.
pub fn scan(dir: &Path, forbid: &[String]) -> Result<Vec<Hit>, String> {
    let mut files = Vec::new();
    walk(dir, &mut files)?;
    let mut hits = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(dir)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&path).map_err(|e| format!("{rel}: {e}"))?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let frames = match ext {
            "pcap" => Some(pcap::read_pcap_records(&bytes).map_or_else(|_| Vec::new(), |r| r.1)),
            "pcapng" => Some(pcapng_frames(&bytes)),
            _ => None,
        };
        if let Some(frames) = frames {
            for (n, (_, f)) in frames.iter().enumerate() {
                if let Some((proto, payload)) = lan_discovery(f) {
                    let names: Vec<String> = dns_names(payload).iter().map(|n| mask(n)).collect();
                    hits.push(Hit {
                        file: rel.clone(),
                        place: format!("frame {}", n + 1),
                        what: format!(
                            "{proto} frame, names: {}",
                            if names.is_empty() {
                                "none decoded".into()
                            } else {
                                names.join(" ")
                            }
                        ),
                    });
                }
            }
            // raw bytes: a host name sits in a capture whole
            for (i, t) in forbid.iter().enumerate() {
                let t = t.as_bytes();
                if !t.is_empty() && bytes.windows(t.len()).any(|w| w.eq_ignore_ascii_case(t)) {
                    hits.push(Hit {
                        file: rel.clone(),
                        place: "bytes".into(),
                        what: format!("forbidden token #{}", i + 1),
                    });
                }
            }
            continue;
        }
        let text = String::from_utf8_lossy(&bytes).to_lowercase();
        for (n, line) in text.lines().enumerate() {
            for (i, t) in forbid.iter().enumerate() {
                if !t.is_empty() && line.contains(&t.to_lowercase()) {
                    hits.push(Hit {
                        file: rel.clone(),
                        place: format!("line {}", n + 1),
                        what: format!("forbidden token #{}", i + 1),
                    });
                }
            }
        }
    }
    Ok(hits)
}

/// `privacy-scan --dir DIR [--forbid TOKEN]...`: 0 no hit, 1 a hit, 2 NOT RUN.
pub fn run(args: &[String]) -> Result<i32, String> {
    let (mut dir, mut forbid) = (None, Vec::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--help" | "-h" => {
                println!(
                    "privacy-scan --dir DIR [--forbid TOKEN]...  (exit 0 no hit, 1 a hit; mDNS/LLMNR/NBNS frames in captures, forbidden tokens in every file)"
                );
                return Ok(0);
            }
            "--dir" => dir = Some(it.next().ok_or("--dir needs a directory")?.clone()),
            "--forbid" => forbid.push(it.next().ok_or("--forbid needs a token")?.clone()),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let dir = dir.ok_or("--dir is required")?;
    let hits = scan(Path::new(&dir), &forbid)?;
    for h in &hits {
        println!("HIT {}", h.line());
    }
    println!("privacy-scan: {} hits in {dir}", hits.len());
    Ok(i32::from(!hits.is_empty()))
}

#[cfg(test)]
#[path = "privacy_scan_tests.rs"]
mod tests;
