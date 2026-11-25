//! Ответчик ARP на адреса источника IPv4 (AGPL-3.0, подэтап 4b, задача 14a).
//!
//! Эталоны `tests/golden/arp-replies` сняты C-оракулом `arp-reply-oracle` (вне репозитория, Р14): путь приёма masscan
//! © Robert David Graham (HEAD 8e6b3b0) для кадра Ethernet, `src/main.c:799-887`, с настоящими `preprocess_frame`
//! (`src/proto-preprocess.c`), `is_my_ip` (`src/stack-src.c:8-18`) и `stack_arp_incoming_request`
//! (`src/stack-arpv4.c:282-363`). Для каждого кадра кейса ответ rmasscan ([`answer_request`]) обязан совпасть с кадром
//! C байт в байт, а «ответа нет» с «ответа нет» C.
//!
//! Входы строит [`cases`]; закоммиченные `cases/*.in.txt` обязаны с ним совпадать. С переменной
//! `RMASSCAN_ARP_REPLIES_INPUTS=DIR` тест [`inputs_match_generator`] вместо сверки пишет `DIR/cases/*.in.txt` и
//! `DIR/cases.tsv` для оракула (README эталонов).

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use proptest::prelude::*;
use rmasscan_core::arp::{ARP_FRAME_LEN, answer_request, incoming_request};

#[path = "common/sha256.rs"]
mod sha256;

#[path = "common/golden.rs"]
mod golden;

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/arp-replies"
);
const ORACLE_GIT_HEAD: &str = "8e6b3b0c07a81e8ea61d557c06134a21a6881614";

/// MAC сканера и его адреса: 192.0.2.250, диапазон `--adapter-ip` до 192.0.2.253.
const MY_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const ME: u32 = 0xc000_02fa;
const ME_LAST: u32 = 0xc000_02fd;
/// Спрашивающий (шлюз 192.0.2.1), другой источник Ethernet и чужой хост сегмента.
const ROUTER: u32 = 0xc000_0201;
const ROUTER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0xfe];
const OTHER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0b];
const HOST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0c];
const BCAST: [u8; 6] = [0xff; 6];

// --- генератор входов ---

struct Frame {
    about: String,
    bytes: Vec<u8>,
    /// Ожидание генератора: отвечает ли C. Тест требует, чтобы C с ним согласился.
    reply: bool,
}

struct Case {
    name: &'static str,
    about: &'static str,
    first: u32,
    last: u32,
    frames: Vec<Frame>,
}

impl Case {
    fn input(&self) -> String {
        let mut s = String::from("arp-reply-input v1\n");
        let _ = writeln!(s, "# {}", self.about);
        let m = MY_MAC;
        let _ = writeln!(
            s,
            "me mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} first={:08x} last={:08x}",
            m[0], m[1], m[2], m[3], m[4], m[5], self.first, self.last
        );
        for (i, f) in self.frames.iter().enumerate() {
            let _ = writeln!(s, "# {i}: {}", f.about);
            let _ = writeln!(s, "frame {}", hex_or_dash(&f.bytes));
        }
        s
    }

    fn replies(&self) -> usize {
        self.frames.iter().filter(|f| f.reply).count()
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn hex_or_dash(b: &[u8]) -> String {
    if b.is_empty() { "-".into() } else { hex(b) }
}

fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(60);
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f
}

/// Заголовок ARP: тип оборудования, тип протокола, длины адресов, opcode.
fn arp_hdr(f: &mut Vec<u8>, ht: u16, pt: u16, hl: u8, pl: u8, op: u16) {
    f.extend_from_slice(&ht.to_be_bytes());
    f.extend_from_slice(&pt.to_be_bytes());
    f.extend_from_slice(&[hl, pl]);
    f.extend_from_slice(&op.to_be_bytes());
}

/// Обычный ARP Ethernet/IPv4 (6/4) с opcode `op`, без дополнения (42 байта).
fn arp(
    dst: [u8; 6],
    src: [u8; 6],
    op: u16,
    sha: [u8; 6],
    spa: u32,
    tha: [u8; 6],
    tpa: u32,
) -> Vec<u8> {
    let mut f = eth(dst, src, 0x0806);
    arp_hdr(&mut f, 1, 0x0800, 6, 4, op);
    f.extend_from_slice(&sha);
    f.extend_from_slice(&spa.to_be_bytes());
    f.extend_from_slice(&tha);
    f.extend_from_slice(&tpa.to_be_bytes());
    f
}

fn pad(mut f: Vec<u8>, n: usize, byte: u8) -> Vec<u8> {
    if f.len() < n {
        f.resize(n, byte);
    }
    f
}

/// Запрос шлюза «кто имеет `tpa`», широковещательный, дополненный до 60.
fn who_has(tpa: u32) -> Vec<u8> {
    pad(
        arp(BCAST, ROUTER_MAC, 1, ROUTER_MAC, ROUTER, [0; 6], tpa),
        60,
        0,
    )
}

fn frame(about: impl Into<String>, bytes: Vec<u8>, reply: bool) -> Frame {
    Frame {
        about: about.into(),
        bytes,
        reply,
    }
}

/// Кадр с заголовком ARP `ht/pt/hl/pl/op` и телом `body` (адреса в порядке sha, spa, tha, tpa произвольной длины),
/// дополненный нулями до `len`.
fn odd(ht: u16, pt: u16, hl: u8, pl: u8, op: u16, body: &[u8], len: usize) -> Vec<u8> {
    let mut f = eth(BCAST, ROUTER_MAC, 0x0806);
    arp_hdr(&mut f, ht, pt, hl, pl, op);
    f.extend_from_slice(body);
    pad(f, len, 0)
}

fn cases() -> Vec<Case> {
    let me = ME.to_be_bytes();
    let router = ROUTER.to_be_bytes();
    let plain = vec![
        frame(
            "who-has .250 tell .1, broadcast, padded to 60",
            who_has(ME),
            true,
        ),
        frame(
            "the same, unicast to our MAC",
            pad(
                arp(MY_MAC, ROUTER_MAC, 1, ROUTER_MAC, ROUTER, [0; 6], ME),
                60,
                0,
            ),
            true,
        ),
        frame(
            "the same, 42 bytes without padding",
            arp(BCAST, ROUTER_MAC, 1, ROUTER_MAC, ROUTER, [0; 6], ME),
            true,
        ),
        frame(
            "Ethernet source differs from the ARP sender MAC: the reply goes to the sender MAC",
            pad(
                arp(BCAST, OTHER_MAC, 1, ROUTER_MAC, ROUTER, [0; 6], ME),
                60,
                0,
            ),
            true,
        ),
        frame(
            "Ethernet destination is another host: C does not check it",
            pad(
                arp(HOST_MAC, ROUTER_MAC, 1, ROUTER_MAC, ROUTER, [0; 6], ME),
                60,
                0,
            ),
            true,
        ),
        frame(
            "target hardware address is not zero",
            pad(
                arp(BCAST, ROUTER_MAC, 1, ROUTER_MAC, ROUTER, [0xff; 6], ME),
                60,
                0,
            ),
            true,
        ),
        frame(
            "ARP probe (RFC 5227, sender IP 0.0.0.0) for our address",
            pad(arp(BCAST, HOST_MAC, 1, HOST_MAC, 0, [0; 6], ME), 60, 0),
            true,
        ),
        frame(
            "padding of 0xee: the reply's padding is zero",
            pad(
                arp(BCAST, ROUTER_MAC, 1, ROUTER_MAC, ROUTER, [0; 6], ME),
                60,
                0xee,
            ),
            true,
        ),
        frame("who-has .251 (not ours)", who_has(ME + 1), false),
        frame("who-has .249 (not ours)", who_has(ME - 1), false),
        frame(
            "opcode 2 (a reply to us), not the ARP-scan path here",
            pad(
                arp(MY_MAC, ROUTER_MAC, 2, ROUTER_MAC, ROUTER, MY_MAC, ME),
                60,
                0,
            ),
            false,
        ),
        frame(
            "opcode 3 (RARP request) for our address",
            pad(
                arp(BCAST, ROUTER_MAC, 3, ROUTER_MAC, ROUTER, [0; 6], ME),
                60,
                0,
            ),
            false,
        ),
        frame(
            "opcode 0x0101",
            pad(
                arp(BCAST, ROUTER_MAC, 0x0101, ROUTER_MAC, ROUTER, [0; 6], ME),
                60,
                0,
            ),
            false,
        ),
        frame(
            "gratuitous request of the router (who-has .1 tell .1)",
            pad(
                arp(BCAST, ROUTER_MAC, 1, ROUTER_MAC, ROUTER, [0; 6], ROUTER),
                60,
                0,
            ),
            false,
        ),
        frame(
            "IPv4 TCP SYN-ACK to our address (not ARP)",
            syn_ack_to_me(),
            false,
        ),
    ];
    let range = vec![
        frame("who-has .250", who_has(ME), true),
        frame("who-has .251", who_has(ME + 1), true),
        frame("who-has .252", who_has(ME + 2), true),
        frame("who-has .253", who_has(ME + 3), true),
        frame("who-has .249 (below the range)", who_has(ME - 1), false),
        frame("who-has .254 (past the range)", who_has(ME_LAST + 1), false),
    ];
    let full = arp(BCAST, ROUTER_MAC, 1, ROUTER_MAC, ROUTER, [0; 6], ME);
    let mut truncated: Vec<Frame> = [0usize, 6, 13, 14, 15, 21, 22, 23, 28, 33, 34, 38, 41]
        .iter()
        .map(|&n| {
            frame(
                format!("plain request cut to {n} bytes"),
                full[..n].to_vec(),
                false,
            )
        })
        .collect();
    truncated.push(frame("the whole 42 bytes", full.clone(), true));
    let tagged = |tci: u16| {
        let mut f = eth(BCAST, ROUTER_MAC, 0x8100);
        f.extend_from_slice(&tci.to_be_bytes());
        f.extend_from_slice(&0x0806u16.to_be_bytes());
        f.extend_from_slice(&full[14..]);
        pad(f, 64, 0)
    };
    let mut qinq = eth(BCAST, ROUTER_MAC, 0x88a8);
    qinq.extend_from_slice(&[0x00, 0x0a, 0x81, 0x00, 0x00, 0x64, 0x08, 0x06]);
    qinq.extend_from_slice(&full[14..]);
    let mut double = eth(BCAST, ROUTER_MAC, 0x8100);
    double.extend_from_slice(&[0x00, 0x0a, 0x81, 0x00, 0x00, 0x64, 0x08, 0x06]);
    double.extend_from_slice(&full[14..]);
    let mut snap = eth(BCAST, ROUTER_MAC, 36);
    snap.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06]);
    snap.extend_from_slice(&full[14..]);
    let encapsulated = vec![
        frame(
            "802.1Q tag (VLAN 100) around the request",
            tagged(0x0064),
            false,
        ),
        frame(
            "802.1Q tag with priority 7 (TCI 0xe064)",
            tagged(0xe064),
            false,
        ),
        frame(
            "802.1ad outer tag 0x88a8, then 802.1Q",
            pad(qinq, 68, 0),
            false,
        ),
        frame("two 802.1Q tags", pad(double, 68, 0), false),
        frame(
            "802.3 length field with LLC/SNAP around the request",
            pad(snap, 60, 0),
            false,
        ),
    ];
    let sha_long = [0x02, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x11, 0x22];
    let quirks = vec![
        frame(
            "hardware type 6 (IEEE 802), accepted by C",
            odd(
                6,
                0x0800,
                6,
                4,
                1,
                &[&ROUTER_MAC[..], &router, &[0; 6], &me].concat(),
                60,
            ),
            true,
        ),
        frame(
            "hardware type 2",
            odd(
                2,
                0x0800,
                6,
                4,
                1,
                &[&ROUTER_MAC[..], &router, &[0; 6], &me].concat(),
                60,
            ),
            false,
        ),
        frame(
            "protocol type 0x86dd",
            odd(
                1,
                0x86dd,
                6,
                4,
                1,
                &[&ROUTER_MAC[..], &router, &[0; 6], &me].concat(),
                60,
            ),
            false,
        ),
        frame(
            "lengths 6/5: one wrong length passes C's && check; addresses at the 6/5 offsets",
            odd(
                1,
                0x0800,
                6,
                5,
                1,
                &[&ROUTER_MAC[..], &router, &[0x77], &[0; 6], &me, &[0x88]].concat(),
                60,
            ),
            true,
        ),
        frame(
            "lengths 8/4: the reply carries the first 6 of the 8 sender hardware bytes",
            odd(
                1,
                0x0800,
                8,
                4,
                1,
                &[&sha_long[..], &router, &[0; 8], &me].concat(),
                60,
            ),
            true,
        ),
        frame(
            "lengths 0/4: the 6 'MAC' bytes C copies are the sender and target IP bytes",
            odd(1, 0x0800, 0, 4, 1, &[&router[..], &me].concat(), 60),
            true,
        ),
        frame(
            "lengths 6/0, padded: the sender IP is read from the target MAC, the target IP from the padding",
            {
                let mut f = odd(
                    1,
                    0x0800,
                    6,
                    0,
                    1,
                    &[&ROUTER_MAC[..], &[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]].concat(),
                    60,
                );
                f[34..38].copy_from_slice(&me);
                f
            },
            true,
        ),
        frame(
            "lengths 5/4: the 6 copied MAC bytes run into the sender IP",
            odd(
                1,
                0x0800,
                5,
                4,
                1,
                &[&ROUTER_MAC[..5], &router, &[0; 5], &me].concat(),
                60,
            ),
            true,
        ),
        frame(
            "lengths 7/3: both wrong",
            odd(
                1,
                0x0800,
                7,
                3,
                1,
                &[&ROUTER_MAC[..], &[0], &router[..3], &[0; 7], &me[..3]].concat(),
                60,
            ),
            false,
        ),
        frame(
            "lengths 6/255, 544 bytes: the target IP sits at offset 289",
            {
                let mut f = odd(
                    1,
                    0x0800,
                    6,
                    255,
                    1,
                    &[&ROUTER_MAC[..], &router].concat(),
                    544,
                );
                f[289..293].copy_from_slice(&me);
                f
            },
            true,
        ),
        frame(
            "lengths 6/255, one byte short of 544",
            {
                let mut f = odd(
                    1,
                    0x0800,
                    6,
                    255,
                    1,
                    &[&ROUTER_MAC[..], &router].concat(),
                    543,
                );
                f[289..293].copy_from_slice(&me);
                f
            },
            false,
        ),
    ];
    let oversize = vec![
        frame(
            "request padded to 1514 bytes",
            pad(full.clone(), 1514, 0),
            true,
        ),
        frame(
            "request padded to 1515 bytes (main.c:799)",
            pad(full.clone(), 1515, 0),
            false,
        ),
    ];
    let unspecified = vec![
        frame("who-has 0.0.0.0", who_has(0), true),
        frame("who-has .250", who_has(ME), false),
    ];
    vec![
        Case {
            name: "plain",
            about: "one source address 192.0.2.250",
            first: ME,
            last: ME,
            frames: plain,
        },
        Case {
            name: "range",
            about: "--adapter-ip 192.0.2.250-192.0.2.253",
            first: ME,
            last: ME_LAST,
            frames: range,
        },
        Case {
            name: "truncated",
            about: "one source address, the plain request cut short",
            first: ME,
            last: ME,
            frames: truncated,
        },
        Case {
            name: "encapsulated",
            about: "one source address, the request inside VLAN tags and LLC/SNAP",
            first: ME,
            last: ME,
            frames: encapsulated,
        },
        Case {
            name: "header-quirks",
            about: "one source address, odd hardware and protocol types and address lengths",
            first: ME,
            last: ME,
            frames: quirks,
        },
        Case {
            name: "oversize",
            about: "one source address, frames at and past 1514 bytes",
            first: ME,
            last: ME,
            frames: oversize,
        },
        Case {
            name: "unspecified-source",
            about: "IPv4 source 0.0.0.0-0.0.0.0, as C leaves it in a scan without IPv4 targets",
            first: 0,
            last: 0,
            frames: unspecified,
        },
    ]
}

/// SYN-ACK от 198.51.100.1:80 на наш адрес (заголовки без проверки сумм: до TCP дело не доходит).
fn syn_ack_to_me() -> Vec<u8> {
    let mut f = eth(MY_MAC, ROUTER_MAC, 0x0800);
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&40u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&0xc633_6401u32.to_be_bytes());
    ip[16..20].copy_from_slice(&ME.to_be_bytes());
    f.extend_from_slice(&ip);
    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&80u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&40000u16.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x12;
    f.extend_from_slice(&tcp);
    pad(f, 60, 0)
}

// --- сверка с C ---

fn read(p: &Path) -> Vec<u8> {
    fs::read(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Вывод оракула: на каждый кадр `None` (ответа нет) или кадр ответа.
fn c_output(name: &str) -> Vec<Option<Vec<u8>>> {
    let text =
        String::from_utf8(read(&Path::new(DIR).join(format!("cases/{name}.out")))).expect("utf-8");
    let mut lines = text.lines();
    let head = lines.next().expect("header");
    let rest: Vec<&str> = lines.collect();
    let (frames, replies) = head
        .strip_prefix("arp-reply-oracle v1 frames=")
        .and_then(|r| r.split_once(" replies="))
        .unwrap_or_else(|| panic!("{name}: header {head}"));
    let frames: usize = frames.parse().expect("frames");
    let replies: usize = replies.parse().expect("replies");
    assert_eq!(rest.len(), frames, "{name}: lines");
    let mut out = Vec::new();
    for (i, l) in rest.iter().enumerate() {
        let tail = l
            .strip_prefix(&format!("frame {i} "))
            .unwrap_or_else(|| panic!("{name}: line {l}"));
        if tail == "none" {
            out.push(None);
        } else {
            let (len, bytes) = tail
                .strip_prefix("reply len=")
                .and_then(|r| r.split_once(' '))
                .unwrap_or_else(|| panic!("{name}: line {l}"));
            let bytes = unhex(bytes);
            assert_eq!(
                bytes.len(),
                len.parse::<usize>().expect("len"),
                "{name}: {l}"
            );
            out.push(Some(bytes));
        }
    }
    assert_eq!(
        out.iter().filter(|o| o.is_some()).count(),
        replies,
        "{name}: replies"
    );
    out
}

#[test]
fn inputs_match_generator() {
    let all = cases();
    if let Some(dir) = std::env::var_os("RMASSCAN_ARP_REPLIES_INPUTS") {
        let dir = Path::new(&dir);
        fs::create_dir_all(dir.join("cases")).expect("mkdir");
        let mut tsv = String::new();
        for c in &all {
            fs::write(dir.join(format!("cases/{}.in.txt", c.name)), c.input())
                .expect("write input");
            let _ = writeln!(
                tsv,
                "{}\t{}\t{}\t{}",
                c.name,
                c.frames.len(),
                c.replies(),
                c.about
            );
        }
        fs::write(dir.join("cases.tsv"), tsv).expect("write tsv");
        return;
    }
    let mut names = std::collections::BTreeSet::new();
    for c in &all {
        assert!(names.insert(c.name), "duplicate case {}", c.name);
        assert!(!c.about.contains(['"', '\\', '\t', '\n']), "{}", c.name);
        let file = read(&Path::new(DIR).join(format!("cases/{}.in.txt", c.name)));
        assert!(
            file == c.input().into_bytes(),
            "{}.in.txt drifted from the generator",
            c.name
        );
    }
    for e in fs::read_dir(Path::new(DIR).join("cases")).expect("cases dir") {
        let f = e.expect("entry").file_name().into_string().expect("utf-8");
        let stem = f
            .strip_suffix(".in.txt")
            .or_else(|| f.strip_suffix(".out"))
            .unwrap_or_else(|| panic!("unexpected file cases/{f}"));
        assert!(
            names.contains(stem),
            "cases/{f} has no case in the generator"
        );
    }
}

/// Ответ rmasscan на каждый кадр равен ответу C байт в байт, кроме пяти заявленных отличий бага B3
/// (`quirks` кадры 0, 3, 4, 5, 6: `ht == 6` или неверная длина `hl`/`pl`, на которые C отвечает по ошибке
/// `src/stack-arpv4.c:70-75`, а rmasscan отказывает). Счёт кейсов, кадров и ответов закреплён.
#[test]
fn replies_match_c_byte_for_byte() {
    let (mut frames, mut replies, mut b3_rejected) = (0usize, 0usize, 0usize);
    for c in cases() {
        let want = c_output(c.name);
        assert_eq!(want.len(), c.frames.len(), "{}: frame count", c.name);
        for (i, (f, w)) in c.frames.iter().zip(&want).enumerate() {
            assert_eq!(
                w.is_some(),
                f.reply,
                "{} frame {i} ({}): C {} a reply",
                c.name,
                f.about,
                if w.is_some() {
                    "sends"
                } else {
                    "does not send"
                }
            );
            let got = answer_request(&f.bytes, MY_MAC, c.first, c.last);
            let is_b3_quirk = c.name == "header-quirks" && matches!(i, 0 | 3 | 4 | 5 | 6 | 7 | 9);
            if is_b3_quirk {
                assert!(w.is_some(), "{} frame {i}: C replied due to B3", c.name);
                assert_eq!(
                    got, None,
                    "{} frame {i} ({}): B3 fix rejects bad ht/hl/pl",
                    c.name, f.about
                );
                b3_rejected += 1;
            } else {
                assert_eq!(
                    got.map(|r| r.to_vec()),
                    w.clone(),
                    "{} frame {i} ({})",
                    c.name,
                    f.about
                );
            }
            if let Some(r) = w {
                assert_eq!(r.len(), ARP_FRAME_LEN);
                replies += 1;
            }
            frames += 1;
        }
    }
    assert_eq!(b3_rejected, 7, "exact B3 declared differences");
    assert_eq!(
        (frames, replies),
        (55, 22),
        "frames and replies in the goldens"
    );
}

#[test]
fn manifest_hashes_match_files() {
    let manifest = String::from_utf8(read(&Path::new(DIR).join("manifest.json"))).expect("utf-8");
    let n =
        golden::check_manifest_hashes(Path::new(DIR), &manifest).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(n, 2 * cases().len(), "input and output of every case");
    assert!(
        manifest.contains(&format!("\"masscan_git_head\": \"{ORACLE_GIT_HEAD}\"")),
        "manifest pins the C commit"
    );
    for c in cases() {
        assert!(
            manifest.contains(&format!("\"name\": \"{}\"", c.name)),
            "{} in manifest",
            c.name
        );
    }
}

// --- то, чего нет в эталонах ---

/// Класс а (Р1): при длинах 6/0..6/3 C читает адрес назначения за краем кадра, если кадр короче `38 + pl` байт
/// (`src/proto-preprocess.c:619-621` и `src/stack-arpv4.c:89-90`; ASan оракула: heap-buffer-overflow в
/// `preprocess_frame`). rmasscan на такой кадр не отвечает; тот же кадр, дополненный до 60, читается в пределах кадра
/// и отвечается, как у C.
#[test]
fn target_address_past_the_frame_end_gets_no_reply() {
    let me = ME.to_be_bytes();
    for pl in 0u8..4 {
        let p = usize::from(pl);
        // sha (6), spa (pl), tha (6): адрес назначения начинается с 34 + pl, проверено только 34 + 2 * pl байт.
        let base = odd(
            1,
            0x0800,
            6,
            pl,
            1,
            &[&ROUTER_MAC[..], &ROUTER.to_be_bytes()[..p], &[0; 6]].concat(),
            0,
        );
        assert_eq!(base.len(), 34 + p);
        for len in 34 + 2 * p..38 + p {
            let mut f = base.clone();
            f.extend_from_slice(&me[..len - base.len()]);
            assert_eq!(
                answer_request(&f, MY_MAC, ME, ME),
                None,
                "6/{pl}, {len} bytes"
            );
        }
        let mut padded = pad(base, 60, 0);
        padded[34 + p..38 + p].copy_from_slice(&me);
        // Исправление бага B3: неверная длина протокола `pl != 4` отвергается и с добивкой до 60.
        assert_eq!(
            answer_request(&padded, MY_MAC, ME, ME),
            None,
            "6/{pl} padded rejected by B3"
        );
    }
}

/// Ответ это `encode_reply`: Ethernet и `tha` получают `sha` запроса (6 байт с `px + 22`), `tpa` ответа это `spa`
/// запроса, отправитель это мы с запрошенным адресом диапазона.
#[test]
fn reply_layout_follows_stack_arp_incoming_request() {
    let f = pad(
        arp(BCAST, OTHER_MAC, 1, ROUTER_MAC, ROUTER, [0; 6], ME + 2),
        60,
        0xee,
    );
    let r = answer_request(&f, MY_MAC, ME, ME_LAST).expect("reply");
    assert_eq!(&r[0..6], &ROUTER_MAC);
    assert_eq!(&r[6..12], &MY_MAC);
    assert_eq!(
        &r[12..22],
        &[0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]
    );
    assert_eq!(&r[22..28], &MY_MAC);
    assert_eq!(&r[28..32], &(ME + 2).to_be_bytes());
    assert_eq!(&r[32..38], &ROUTER_MAC);
    assert_eq!(&r[38..42], &ROUTER.to_be_bytes());
    assert!(r[42..].iter().all(|&b| b == 0));
    let req = incoming_request(&f).expect("request");
    assert_eq!(
        (req.sender_mac, req.sender_ip, req.target_ip),
        (ROUTER_MAC, ROUTER, ME + 2)
    );
}

/// Структурный генератор: заголовок ARP с произвольными типами, длинами и opcode и тело нужной длины (иногда короче
/// или длиннее), иногда с нашим адресом на месте адреса назначения C.
fn structured() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![3 => Just(1u16), 1 => Just(6u16), 1 => any::<u16>()],
        prop_oneof![4 => Just(0x0800u16), 1 => any::<u16>()],
        prop_oneof![3 => Just(6u8), 1 => 0u8..=10, 1 => any::<u8>()],
        prop_oneof![3 => Just(4u8), 1 => 0u8..=8, 1 => any::<u8>()],
        prop_oneof![3 => Just(1u16), 1 => Just(2u16), 1 => any::<u16>()],
        proptest::collection::vec(any::<u8>(), 1..64),
        prop_oneof![3 => Just(0i32), 1 => -8i32..8],
        proptest::bool::weighted(0.8),
    )
        .prop_map(|(ht, pt, hl, pl, op, junk, skew, tpa_me)| {
            let need = 22 + 2 * usize::from(hl) + 2 * usize::from(pl);
            let mut f = eth(BCAST, ROUTER_MAC, 0x0806);
            arp_hdr(&mut f, ht, pt, hl, pl, op);
            f.extend(junk.iter().cycle().take(need - 22));
            let at = 22 + 2 * usize::from(hl) + usize::from(pl);
            if tpa_me && f.len() >= at + 4 {
                f[at..at + 4].copy_from_slice(&ME.to_be_bytes());
            }
            let len = usize::try_from(i32::try_from(need).unwrap_or(i32::MAX) + skew).unwrap_or(0);
            f.resize(len, 0);
            f
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// Тотальность (Р1 класс б): ни один кадр не роняет разбор и сборку ответа.
    #[test]
    fn never_panics_on_random_frames(f in proptest::collection::vec(any::<u8>(), 0..1600)) {
        let _ = incoming_request(&f);
        let _ = answer_request(&f, MY_MAC, 0, u32::MAX);
    }
}

/// Тот же разбор на структурном входе, со счётом достигнутых ответов: тест доказывает, что генератор проходит все
/// проверки заголовка, а не останавливается на первом байте.
#[test]
fn never_panics_on_structured_requests_and_reaches_replies() {
    use proptest::test_runner::{Config, TestRunner};
    let (reached, total) = (std::cell::Cell::new(0usize), std::cell::Cell::new(0usize));
    TestRunner::new(Config {
        cases: 20_000,
        ..Config::default()
    })
    .run(&structured(), |f| {
        total.set(total.get() + 1);
        if let Some(r) = answer_request(&f, MY_MAC, ME, ME) {
            prop_assert_eq!(&r[6..12], &MY_MAC);
            prop_assert_eq!(&r[28..32], &ME.to_be_bytes());
            reached.set(reached.get() + 1);
        }
        Ok(())
    })
    .unwrap();
    println!(
        "reach arp responder: total={} replies={}",
        total.get(),
        reached.get()
    );
    assert!(
        reached.get() * 20 >= total.get(),
        "only {} of {} got a reply",
        reached.get(),
        total.get()
    );
}
