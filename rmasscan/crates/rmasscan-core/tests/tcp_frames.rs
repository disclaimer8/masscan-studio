//! Кадры стека TCP, разбор входящего сегмента и RST без состояния (AGPL-3.0, подэтап 4b, задача 3).
//!
//! Эталоны `tests/golden/tcp-frames` сняты C-оракулом `tcp-frame-oracle` (вне репозитория, Р14): неизменённый
//! `tcp_create_packet` masscan © Robert David Graham (`src/templ-pkt.c:419-613`, HEAD 8e6b3b0) над шаблоном из
//! `template_packet_init` с опциями кейса и `template_set_ttl` (`src/main.c:1301-1329`), окно 600 через
//! `tcp_set_window` (`src/stack-tcp-core.c:1163-1164`). Кадр rmasscan обязан совпасть с кадром C байт в байт, кроме
//! двух названных отличий, которые тест воспроизводит из нашего кадра и сверяет с C тоже побайтно:
//! - E1.10: сумма заголовка IPv4 у C свёрнута дважды (`src/templ-pkt.c:466-473`), в кадрах [`E1_10`] она неверна;
//!   наша верна;
//! - `--tcp-tsecho`: C пишет `field[2]` дважды (`src/templ-tcp-hdr.c:1111-1112`), TSval теряет `ts >> 8`; наш
//!   шаблон SYN пишет TSval целиком (дизайн scan-control, `packet.rs` `tcp_option_bytes`), и кадры стека несут те же
//!   опции, что SYN.
//!
//! Входы строит [`cases`]; закоммиченные `cases/*.in.txt` обязаны с ним совпадать. С переменной
//! `RMASSCAN_TCP_FRAMES_INPUTS=DIR` тест [`inputs_match_generator`] вместо сверки пишет `DIR/cases/*.in.txt` и
//! `DIR/cases.tsv` для оракула (README эталонов).

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use proptest::prelude::*;
use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::cookie::{syn_cookie_ipv4, syn_cookie_ipv6};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::{
    LinkType, PacketModifiers, Tcp6SynTemplate, TcpHeaderOptions, TcpSynTemplate,
};
use rmasscan_core::probe::{AdapterBinding, NicBinding, ReadyPlan};
use rmasscan_core::receive::{PortStatus, Reply, ReplyIpv6, parse_reply};
use rmasscan_core::stack::{ConnAddrs, ConnKey, SegmentIn, SegmentOut};
use rmasscan_core::targets::parse_ports;
use rmasscan_core::tcp_frame::{TcpFrameBuilder, stateless_rst, tcp_segment};

// Манифест эталонов проверяется общим кодом без serde: сумма файла, `golden.rs` берёт `super::sha256`.
#[path = "common/sha256.rs"]
mod sha256;

#[path = "common/golden.rs"]
mod golden;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/tcp-frames");
const ORACLE_GIT_HEAD: &str = "8e6b3b0c07a81e8ea61d557c06134a21a6881614";

const MAC_SRC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const MAC_R4: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0xfe];
const MAC_R6: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0xfd];
const SEED: u64 = 0x0123_4567_89ab_cdef;
/// Наш адрес в тестах разбора: 10.255.0.1 и fd00::2; порты источника 40000..=40015.
const ME4: u32 = 0x0aff_0001;
const ME6: u128 = 0xfd00_0000_0000_0000_0000_0000_0000_0002;
const PEER4: u32 = 0x0a00_0005;
const PEER6: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0005;

/// Вектор E1.10 справки: `ip_me=0xd5a30aac ip_them=0x4ba3e552 port_them=55289 seqno=0x3e8f982c`, шаблон по
/// умолчанию, без нагрузки: C пишет сумму `0xffff`, верная `0xfffe`.
const E1_10_ME: u32 = 0xd5a3_0aac;
const E1_10_THEM: u32 = 0x4ba3_e552;
const E1_10_PORT_THEM: u16 = 55289;
const E1_10_SEQ: u32 = 0x3e8f_982c;

/// Кадры, где сумма заголовка IPv4 у C неверна (E1.10): `(кейс, номер кадра)`. Тест требует, чтобы у C она была
/// неверна ровно в них.
const E1_10: &[(&str, usize)] = &[
    ("eth-default-v4-e1-10", 0),
    ("eth-default-v4-e1-10", 1),
    ("eth-default-v4-e1-10", 2),
];

// --- генератор входов ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mss {
    /// MSS 1460 шаблона (`--tcp-mss` не задан).
    Default,
    /// `--tcp-mss false`: опции нет.
    Off,
    Value(u16),
}

/// Опции шаблона кейса: то, что CLI кладёт в `TemplateOptions` и `--ttl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Template {
    mss: Mss,
    sackok: bool,
    wscale: Option<u8>,
    tsecho: Option<u32>,
    ttl: Option<u8>,
}

const DEFAULT_TEMPLATE: Template = Template {
    mss: Mss::Default,
    sackok: false,
    wscale: None,
    tsecho: None,
    ttl: None,
};

impl Template {
    fn tcp_options(&self) -> TcpHeaderOptions {
        TcpHeaderOptions {
            mss: match self.mss {
                Mss::Default => Some(1460),
                Mss::Off => None,
                Mss::Value(v) => Some(v),
            },
            sackok: self.sackok,
            wscale: self.wscale,
            tsecho: self.tsecho,
        }
    }

    fn modifiers(&self) -> PacketModifiers {
        PacketModifiers {
            ttl: self.ttl.unwrap_or(255),
            badsum: false,
            tcp: self.tcp_options(),
        }
    }

    fn line(&self) -> String {
        let mss = match self.mss {
            Mss::Default => "default".to_string(),
            Mss::Off => "off".to_string(),
            Mss::Value(v) => v.to_string(),
        };
        let opt = |v: Option<String>| v.unwrap_or_else(|| "-".into());
        format!(
            "template mss={mss} sackok={} wscale={} tsecho={} ttl={}",
            u8::from(self.sackok),
            opt(self.wscale.map(|w| w.to_string())),
            opt(self.tsecho.map(|t| format!("0x{t:08x}"))),
            opt(self.ttl.map(|t| t.to_string())),
        )
    }
}

/// Один кадр кейса: аргументы `tcp_create_packet` и окно `tcp_set_window`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FrameSpec {
    v6: bool,
    them: u128,
    port_them: u16,
    me: u128,
    port_me: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: Option<u16>,
    payload_len: usize,
    payload_seed: u8,
}

impl FrameSpec {
    /// Байт `k` нагрузки: `(seed + 131 * k) & 0xFF` (оракул делает то же).
    fn payload(&self) -> Vec<u8> {
        (0..self.payload_len)
            .map(|k| (usize::from(self.payload_seed) + 131 * k) as u8)
            .collect()
    }

    fn segment(&self) -> SegmentOut {
        let addrs = if self.v6 {
            ConnAddrs::V6 {
                local: self.me,
                remote: self.them,
            }
        } else {
            ConnAddrs::V4 {
                local: self.me as u32,
                remote: self.them as u32,
            }
        };
        SegmentOut {
            key: ConnKey {
                addrs,
                local_port: self.port_me,
                remote_port: self.port_them,
            },
            seq: self.seq,
            ack: self.ack,
            flags: self.flags,
            payload: self.payload(),
            window: self.window,
        }
    }

    fn line(&self) -> String {
        let addr = |a: u128| {
            if self.v6 {
                format!("{a:032x}")
            } else {
                format!("{:08x}", a as u32)
            }
        };
        format!(
            "frame {} them={} port_them={} me={} port_me={} seq=0x{:08x} ack=0x{:08x} flags=0x{:02x} window={} \
             payload={}:{}",
            if self.v6 { "v6" } else { "v4" },
            addr(self.them),
            self.port_them,
            addr(self.me),
            self.port_me,
            self.seq,
            self.ack,
            self.flags,
            self.window
                .map_or_else(|| "-".to_string(), |w| w.to_string()),
            self.payload_len,
            self.payload_seed,
        )
    }
}

struct CaseSpec {
    name: String,
    about: String,
    link: LinkType,
    template: Template,
    frames: Vec<FrameSpec>,
}

fn link_name(l: LinkType) -> &'static str {
    match l {
        LinkType::Ethernet => "ethernet",
        LinkType::Null => "null",
        LinkType::Raw => "raw",
    }
}

impl CaseSpec {
    fn input(&self) -> String {
        let mac = |m: [u8; 6]| {
            m.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        };
        let mut s = String::from("tcp-frame-input v1\n");
        let _ = writeln!(s, "# {}: {}", self.name, self.about);
        let _ = writeln!(s, "link {}", link_name(self.link));
        let _ = writeln!(
            s,
            "macs src={} router4={} router6={}",
            mac(MAC_SRC),
            mac(MAC_R4),
            mac(MAC_R6)
        );
        let _ = writeln!(s, "{}", self.template.line());
        for f in &self.frames {
            let _ = writeln!(s, "{}", f.line());
        }
        s
    }
}

/// splitmix64: детерминированные параметры кадров, своя последовательность у каждого кейса.
struct Rng(u64);

impl Rng {
    fn for_name(name: &str) -> Rng {
        // FNV-1a 64.
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for b in name.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        Rng(h)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn addr(&mut self, v6: bool) -> u128 {
        if v6 {
            u128::from(self.next()) << 64 | u128::from(self.next())
        } else {
            u128::from(self.next() as u32)
        }
    }
}

/// Флаги кадров стека (справка A6): ACK, данные, данные+FIN, повтор чистого FIN, RST.
const STACK_FLAGS: [u8; 5] = [0x10, 0x18, 0x19, 0x11, 0x04];
/// Нагрузки: пусто, нечётная длина (сумма с хвостом), один полный сегмент `mss` стека (1400, справка A3).
const PAYLOADS: [usize; 3] = [0, 1, 1400];

/// Кадры обычного кейса: 15 сочетаний флагов и нагрузок, два крайних (все единицы, все нули) и, у Ethernet IPv4,
/// окно 600.
fn frames_for(name: &str, link: LinkType, v6: bool) -> Vec<FrameSpec> {
    let mut r = Rng::for_name(name);
    let mut out = Vec::new();
    for flags in STACK_FLAGS {
        for payload_len in PAYLOADS {
            out.push(FrameSpec {
                v6,
                them: r.addr(v6),
                port_them: r.next() as u16,
                me: r.addr(v6),
                port_me: r.next() as u16,
                seq: r.next() as u32,
                ack: r.next() as u32,
                flags,
                window: None,
                payload_len,
                payload_seed: r.next() as u8,
            });
        }
    }
    let ones = if v6 { u128::MAX } else { u128::from(u32::MAX) };
    out.push(FrameSpec {
        v6,
        them: ones,
        port_them: u16::MAX,
        me: ones,
        port_me: u16::MAX,
        seq: u32::MAX,
        ack: u32::MAX,
        flags: 0x10,
        window: None,
        payload_len: 1,
        payload_seed: 0xff,
    });
    out.push(FrameSpec {
        v6,
        them: 0,
        port_them: 0,
        me: 0,
        port_me: 0,
        seq: 0,
        ack: 0,
        flags: 0x04,
        window: None,
        payload_len: 0,
        payload_seed: 0,
    });
    // `tcp_set_window` разбирает кадр как Ethernet (`src/templ-pkt.c:382`), а для IPv6 считает сумму с
    // псевдозаголовком IPv4 (`tcp_checksum2`): окно 600 (heartbleed, 4c) снято только у Ethernet IPv4.
    if link == LinkType::Ethernet && !v6 {
        out.push(FrameSpec {
            v6,
            them: r.addr(v6),
            port_them: 443,
            me: r.addr(v6),
            port_me: 40000,
            seq: r.next() as u32,
            ack: r.next() as u32,
            flags: 0x18,
            window: Some(600),
            payload_len: 1400,
            payload_seed: r.next() as u8,
        });
    }
    out
}

/// Все кейсы эталонов, в порядке манифеста.
fn cases() -> Vec<CaseSpec> {
    let templates: [(&str, &str, Template); 8] = [
        (
            "default",
            "шаблон по умолчанию: MSS 1460, TTL 255",
            DEFAULT_TEMPLATE,
        ),
        (
            "mss-1400",
            "--tcp-mss 1400",
            Template {
                mss: Mss::Value(1400),
                ..DEFAULT_TEMPLATE
            },
        ),
        (
            "mss-off",
            "--tcp-mss false: без опций, doff 5",
            Template {
                mss: Mss::Off,
                ..DEFAULT_TEMPLATE
            },
        ),
        (
            "sackok",
            "--tcp-sackok",
            Template {
                sackok: true,
                ..DEFAULT_TEMPLATE
            },
        ),
        (
            "wscale-7",
            "--tcp-wscale 7",
            Template {
                wscale: Some(7),
                ..DEFAULT_TEMPLATE
            },
        ),
        (
            "tsecho",
            "--tcp-tsecho (0x12345678): TSval C теряет ts >> 8 (src/templ-tcp-hdr.c:1111-1112)",
            Template {
                tsecho: Some(0x1234_5678),
                ..DEFAULT_TEMPLATE
            },
        ),
        (
            "ttl-64",
            "--ttl 64 (у IPv6 hop limit остаётся 255)",
            Template {
                ttl: Some(64),
                ..DEFAULT_TEMPLATE
            },
        ),
        (
            "all-options",
            "--tcp-mss 1400 --tcp-sackok --tcp-wscale 7 --tcp-tsecho --ttl 64: doff 10",
            Template {
                mss: Mss::Value(1400),
                sackok: true,
                wscale: Some(7),
                tsecho: Some(0x1234_5678),
                ttl: Some(64),
            },
        ),
    ];
    let mut out = Vec::new();
    let mut push =
        |link: LinkType, prefix: &str, t: &str, about: &str, tmpl: Template, v6: bool| {
            let fam = if v6 { "v6" } else { "v4" };
            let name = format!("{prefix}-{t}-{fam}");
            let frames = frames_for(&name, link, v6);
            out.push(CaseSpec {
                about: format!(
                    "{}, {}, {about}",
                    link_name(link),
                    if v6 { "IPv6" } else { "IPv4" }
                ),
                name,
                link,
                template: tmpl,
                frames,
            });
        };
    for (t, about, tmpl) in templates {
        for v6 in [false, true] {
            push(LinkType::Ethernet, "eth", t, about, tmpl, v6);
        }
    }
    let mss_off = templates[2].2;
    let raw_pad = "набивка до 60 байт и без Ethernet (src/templ-pkt.c:510-513)";
    push(
        LinkType::Raw,
        "raw",
        "default",
        raw_pad,
        DEFAULT_TEMPLATE,
        false,
    );
    push(
        LinkType::Raw,
        "raw",
        "default",
        "без набивки",
        DEFAULT_TEMPLATE,
        true,
    );
    push(LinkType::Raw, "raw", "mss-off", raw_pad, mss_off, false);
    push(
        LinkType::Raw,
        "raw",
        "mss-off",
        "ровно 60 байт",
        mss_off,
        true,
    );
    // DLT_NULL эталона нет: C на Linux строит IPv6-шаблон с `AF_INET6` хоста (10, `src/templ-pkt.c:1160-1162`),
    // а `preprocess_frame` знает только 24, 28 и 30, и `template_packet_init` выходит с `FAILED: bad packet
    // template` (`:1202-1205`).

    let mut r = Rng::for_name("eth-default-v4-e1-10");
    let mut vector = |flags: u8, payload_len: usize| FrameSpec {
        v6: false,
        them: u128::from(E1_10_THEM),
        port_them: E1_10_PORT_THEM,
        me: u128::from(E1_10_ME),
        port_me: 40000,
        seq: E1_10_SEQ,
        ack: r.next() as u32,
        flags,
        window: None,
        payload_len,
        payload_seed: 0x41,
    };
    let frames = vec![
        vector(0x10, 0),
        vector(0x04, 0),
        vector(0x11, 0),
        vector(0x18, 1),
    ];
    out.push(CaseSpec {
        name: "eth-default-v4-e1-10".into(),
        about: "ethernet, IPv4, вектор E1.10: без нагрузки сумма IP у C 0xffff вместо 0xfffe, с байтом нагрузки верна"
            .into(),
        link: LinkType::Ethernet,
        template: DEFAULT_TEMPLATE,
        frames,
    });
    out
}

// --- план и проверки ---

fn plan(link: LinkType, mods: &PacketModifiers, source_ipv6: Option<u128>) -> ReadyPlan {
    let mut targets = MassIp::new();
    targets.add_target_string("10.0.0.0/8").expect("v4 targets");
    targets
        .add_target_string("2001:db8::/120")
        .expect("v6 targets");
    parse_ports(targets.ports_mut(), "80").expect("ports");
    let cfg = ScanConfig {
        targets,
        seed: SEED,
        max_rate: 100.0,
        ttl: (mods.ttl != 255).then_some(mods.ttl),
        tcp_opts: mods.tcp,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).expect("config");
    ReadyPlan::new_cli(
        eff,
        vec![NicBinding {
            binding: AdapterBinding {
                interface_id: "t0".into(),
                link_type: link,
                source_ipv4: ME4,
                source_mac: MAC_SRC,
                next_hop_mac: MAC_R4,
                source_ports: (40000, 40015),
            },
            source_ipv4_last: ME4,
            legacy_c_17_port_mask: false,
            source_ipv6,
            next_hop_mac_ipv6: Some(MAC_R6),
        }],
    )
    .expect("plan")
}

fn builder(link: LinkType, t: &Template) -> TcpFrameBuilder {
    TcpFrameBuilder::from_plan(&plan(link, &t.modifiers(), Some(ME6)))
}

fn link_len(l: LinkType) -> usize {
    match l {
        LinkType::Ethernet => 14,
        LinkType::Null => 4,
        LinkType::Raw => 0,
    }
}

/// Сумма 16-битных слов big-endian (RFC 1071), нечётный хвост дополняется нулём.
fn sum16(b: &[u8]) -> u64 {
    b.chunks(2)
        .map(|c| u64::from(c[0]) << 8 | u64::from(c.get(1).copied().unwrap_or(0)))
        .sum()
}

fn fold_all(mut s: u64) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

fn ipv4_header_ok(h: &[u8]) -> bool {
    fold_all(sum16(&h[..20])) == 0xffff
}

/// Сумма псевдозаголовка TCP: адреса источника и назначения, протокол 6, длина сегмента.
fn pseudo(src: &[u8], dst: &[u8], len: usize) -> u64 {
    sum16(src) + sum16(dst) + 6 + len as u64
}

/// Сегмент TCP кадра и сумма с псевдозаголовком сворачивается в `0xffff`.
fn tcp_ok(frame: &[u8], oi: usize, v6: bool) -> bool {
    let (src, dst, seg) = tcp_parts(frame, oi, v6);
    fold_all(pseudo(src, dst, seg.len()) + sum16(seg)) == 0xffff
}

/// (адрес источника, адрес назначения, сегмент TCP до конца IP-пакета).
fn tcp_parts(frame: &[u8], oi: usize, v6: bool) -> (&[u8], &[u8], &[u8]) {
    if v6 {
        let plen = usize::from(u16::from_be_bytes([frame[oi + 4], frame[oi + 5]]));
        (
            &frame[oi + 8..oi + 24],
            &frame[oi + 24..oi + 40],
            &frame[oi + 40..oi + 40 + plen],
        )
    } else {
        let total = usize::from(u16::from_be_bytes([frame[oi + 2], frame[oi + 3]]));
        (
            &frame[oi + 12..oi + 16],
            &frame[oi + 16..oi + 20],
            &frame[oi + 20..oi + total],
        )
    }
}

/// Пересчитать сумму TCP кадра.
fn fix_tcp_checksum(frame: &mut [u8], oi: usize, v6: bool) {
    let ot = oi + if v6 { 40 } else { 20 };
    frame[ot + 16] = 0;
    frame[ot + 17] = 0;
    let (src, dst, seg) = tcp_parts(frame, oi, v6);
    let c = !fold_all(pseudo(src, dst, seg.len()) + sum16(seg));
    frame[ot + 16..ot + 18].copy_from_slice(&c.to_be_bytes());
}

/// Сумма заголовка IPv4, как её пишет C (`src/templ-pkt.c:466-473`): частичная сумма шаблона (ID, сумма и адреса
/// нулевые, длина шаблона), плюс `ip_id`, оба адреса целыми 32-битными числами и прирост длины, две свёртки.
fn c_ipv4_header_checksum(header: &[u8], payload_len: usize) -> u16 {
    let mut t = header[..20].to_vec();
    let total = u16::from_be_bytes([t[2], t[3]]);
    let old_len = total - payload_len as u16;
    t[2..4].copy_from_slice(&old_len.to_be_bytes());
    t[4..6].fill(0);
    t[10..20].fill(0);
    let checksum_ip = fold_all(sum16(&t));
    let word = |i: usize| {
        u64::from(u32::from_be_bytes([
            header[i],
            header[i + 1],
            header[i + 2],
            header[i + 3],
        ]))
    };
    let mut x = u64::from(checksum_ip)
        + u64::from(u16::from_be_bytes([header[4], header[5]]))
        + word(12)
        + word(16)
        + payload_len as u64;
    x = (x >> 16) + (x & 0xffff);
    x = (x >> 16) + (x & 0xffff);
    !(x as u16)
}

/// Значение TSval, как его пишет C: `field[2]` дважды, `field[3]` ноль (`src/templ-tcp-hdr.c:1108-1113`).
fn c_tsval(ts: u32) -> [u8; 4] {
    [(ts >> 24) as u8, (ts >> 16) as u8, ts as u8, 0]
}

/// Смещение TSval (байты 2..6 опции kind 8) в кадре: обход опций TCP от `ot + 20` до конца заголовка.
fn tsval_offset(frame: &[u8], ot: usize) -> Option<usize> {
    let end = ot + usize::from(frame[ot + 12] >> 4) * 4;
    let mut i = ot + 20;
    while i < end {
        match frame[i] {
            0 => return None,
            1 => i += 1,
            8 => return Some(i + 2),
            _ => i += usize::from(*frame.get(i + 1)?).max(2),
        }
    }
    None
}

/// Вывод оракула: `tcp-frame-oracle v1 frames=N`, затем `frame I len=L HEX`.
fn read_c_frames(name: &str) -> Vec<Vec<u8>> {
    let text = fs::read_to_string(Path::new(DIR).join(format!("cases/{name}.out")))
        .unwrap_or_else(|e| panic!("{name}.out: {e}"));
    let mut lines = text.lines();
    let head = lines.next().expect("header");
    let n: usize = head
        .strip_prefix("tcp-frame-oracle v1 frames=")
        .expect("oracle header")
        .parse()
        .expect("frame count");
    let frames: Vec<Vec<u8>> = lines
        .enumerate()
        .map(|(i, l)| {
            let mut w = l.split(' ');
            assert_eq!(w.next(), Some("frame"), "{name}: {l}");
            assert_eq!(
                w.next(),
                Some(i.to_string().as_str()),
                "{name}: frame index"
            );
            let len: usize = w
                .next()
                .and_then(|x| x.strip_prefix("len="))
                .expect("len")
                .parse()
                .expect("len number");
            let hex = w.next().unwrap_or("");
            let bytes: Vec<u8> = (0..hex.len() / 2)
                .map(|k| u8::from_str_radix(&hex[2 * k..2 * k + 2], 16).expect("hex"))
                .collect();
            assert_eq!(bytes.len(), len, "{name} frame {i}");
            bytes
        })
        .collect();
    assert_eq!(frames.len(), n, "{name}: frame count");
    frames
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// --- эталоны ---

/// Закоммиченные входы равны выводу генератора; с `RMASSCAN_TCP_FRAMES_INPUTS=DIR` они пишутся в `DIR` для оракула.
#[test]
fn inputs_match_generator() {
    let all = cases();
    if let Some(dir) = std::env::var_os("RMASSCAN_TCP_FRAMES_INPUTS") {
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
                link_name(c.link),
                c.frames.len(),
                c.about
            );
        }
        fs::write(dir.join("cases.tsv"), tsv).expect("write tsv");
        return;
    }
    let mut names = std::collections::BTreeSet::new();
    for c in &all {
        assert!(names.insert(c.name.clone()), "duplicate case {}", c.name);
        assert!(!c.about.contains(['"', '\\', '\t', '\n']), "{}", c.name);
        let file = read(&Path::new(DIR).join(format!("cases/{}.in.txt", c.name)));
        assert!(
            file == c.input().into_bytes(),
            "{}.in.txt drifted from the generator",
            c.name
        );
    }
    // Каждый файл каталога принадлежит кейсу.
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
    assert_eq!(all.len(), 21);
    assert_eq!(all.iter().map(|c| c.frames.len()).sum::<usize>(), 352);
}

/// Кадр `TcpFrameBuilder::build` равен кадру C байт в байт, кроме двух названных отличий (E1.10 и TSval), а наши
/// суммы IPv4 и TCP верны в каждом кадре.
#[test]
fn tcp_frame_golden_matches_c() {
    let mut e1_10 = Vec::new();
    let mut tsecho_frames = 0usize;
    let mut total = 0usize;
    for c in cases() {
        let b = builder(c.link, &c.template);
        let c_frames = read_c_frames(&c.name);
        assert_eq!(c_frames.len(), c.frames.len(), "{}", c.name);
        let oi = link_len(c.link);
        for (i, (spec, c_frame)) in c.frames.iter().zip(&c_frames).enumerate() {
            let ours = b.build(&spec.segment());
            let what = format!("{} frame {i}", c.name);
            assert!(!ours.is_empty(), "{what}: no frame");
            let ot = oi + if spec.v6 { 40 } else { 20 };
            if !spec.v6 {
                assert!(ipv4_header_ok(&ours[oi..]), "{what}: our IPv4 header sum");
                if !ipv4_header_ok(&c_frame[oi..]) {
                    e1_10.push((c.name.clone(), i));
                }
            }
            assert!(tcp_ok(&ours, oi, spec.v6), "{what}: our TCP sum");
            assert!(tcp_ok(c_frame, oi, spec.v6), "{what}: C TCP sum");

            // Наш кадр, переведённый в C по двум названным отличиям.
            let mut want = ours.clone();
            if let Some(ts) = c.template.tsecho {
                let at = tsval_offset(&want, ot).expect("TSval option");
                assert_eq!(&want[at..at + 4], &ts.to_be_bytes(), "{what}: our TSval");
                want[at..at + 4].copy_from_slice(&c_tsval(ts));
                fix_tcp_checksum(&mut want, oi, spec.v6);
                tsecho_frames += 1;
            }
            if E1_10.contains(&(c.name.as_str(), i)) {
                let h = c_ipv4_header_checksum(&want[oi..oi + 20], spec.payload_len);
                want[oi + 10..oi + 12].copy_from_slice(&h.to_be_bytes());
            }
            assert!(
                want == *c_frame,
                "{what}: frame differs from C\n ours {}\n    C {}",
                hex(&want),
                hex(c_frame)
            );
            total += 1;
        }
    }
    let declared: Vec<(String, usize)> = E1_10.iter().map(|&(n, i)| (n.to_string(), i)).collect();
    assert_eq!(
        e1_10, declared,
        "C frames with a wrong IPv4 header sum (E1.10)"
    );
    assert_eq!(total, 352);
    // tsecho и all-options, IPv4 18 кадров и IPv6 17.
    assert_eq!(tsecho_frames, 2 * (18 + 17));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Суммы манифеста равны sha256 файлов (вход и вывод каждого кейса), коммит C в манифесте это пин.
#[test]
fn manifest_hashes_match_files() {
    let manifest = String::from_utf8(read(&Path::new(DIR).join("manifest.json"))).expect("utf-8");
    let n =
        golden::check_manifest_hashes(Path::new(DIR), &manifest).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(n, 2 * cases().len(), "вход и вывод каждого кейса");
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

// --- свойства кадров ---

fn seg4(local: u32, remote: u32, local_port: u16, remote_port: u16) -> SegmentOut {
    SegmentOut {
        key: ConnKey {
            addrs: ConnAddrs::V4 { local, remote },
            local_port,
            remote_port,
        },
        seq: 1,
        ack: 2,
        flags: 0x10,
        payload: Vec::new(),
        window: None,
    }
}

fn seg6(local: u128, remote: u128, local_port: u16, remote_port: u16) -> SegmentOut {
    SegmentOut {
        key: ConnKey {
            addrs: ConnAddrs::V6 { local, remote },
            local_port,
            remote_port,
        },
        ..seg4(0, 0, local_port, remote_port)
    }
}

/// E1.10: сумма заголовка IPv4 всегда верна, в том числе на векторе, где C пишет `0xffff`, а верная `0xfffe`.
#[test]
fn ipv4_header_checksum_always_right() {
    let b = builder(LinkType::Ethernet, &DEFAULT_TEMPLATE);
    let mut s = seg4(E1_10_ME, E1_10_THEM, 40000, E1_10_PORT_THEM);
    s.seq = E1_10_SEQ;
    let f = b.build(&s);
    assert_eq!(&f[24..26], &[0xff, 0xfe], "right sum of the E1.10 vector");
    assert_eq!(
        c_ipv4_header_checksum(&f[14..34], 0),
        0xffff,
        "C writes 0xffff there"
    );
    assert!(ipv4_header_ok(&f[14..]));
    // Случайные кадры с разными шаблонами и длинами: сумма верна всегда, а формула C иногда нет.
    let mut r = Rng::for_name("ipv4_header_checksum_always_right");
    let mut c_wrong = 0;
    for t in [
        DEFAULT_TEMPLATE,
        Template {
            ttl: Some(64),
            mss: Mss::Off,
            ..DEFAULT_TEMPLATE
        },
    ] {
        let b = builder(LinkType::Ethernet, &t);
        for _ in 0..20_000 {
            let mut s = seg4(
                r.next() as u32,
                r.next() as u32,
                r.next() as u16,
                r.next() as u16,
            );
            s.seq = r.next() as u32;
            s.payload = vec![0x5a; (r.next() % 1401) as usize];
            let f = b.build(&s);
            assert!(ipv4_header_ok(&f[14..]), "{s:?}");
            if c_ipv4_header_checksum(&f[14..34], s.payload.len())
                != u16::from_be_bytes([f[24], f[25]])
            {
                c_wrong += 1;
            }
        }
    }
    // Порядка 1e-5 кадров (справка E1.10): на 40 000 кадров единицы, не десятки.
    assert!(c_wrong < 20, "{c_wrong}");
}

/// Кадр IPv4 короче 60 байт добивается нулями до 60 на любом канале (`src/templ-pkt.c:510-513`), длина IP при этом
/// прежняя.
#[test]
fn ethernet_frame_padded_to_60() {
    let mss_off = Template {
        mss: Mss::Off,
        ..DEFAULT_TEMPLATE
    };
    for (link, t, payload, len, ip_total) in [
        (LinkType::Ethernet, DEFAULT_TEMPLATE, 0, 60, 44),
        (LinkType::Ethernet, DEFAULT_TEMPLATE, 1, 60, 45),
        (LinkType::Ethernet, DEFAULT_TEMPLATE, 2, 60, 46),
        (LinkType::Ethernet, DEFAULT_TEMPLATE, 3, 61, 47),
        (LinkType::Ethernet, mss_off, 0, 60, 40),
        (LinkType::Raw, DEFAULT_TEMPLATE, 0, 60, 44),
        (LinkType::Raw, DEFAULT_TEMPLATE, 16, 60, 60),
        (LinkType::Raw, DEFAULT_TEMPLATE, 17, 61, 61),
        (LinkType::Null, mss_off, 0, 60, 40),
    ] {
        let mut s = seg4(ME4, PEER4, 40000, 80);
        s.payload = vec![0xa5; payload];
        let f = builder(link, &t).build(&s);
        let oi = link_len(link);
        assert_eq!(f.len(), len, "{link:?} {payload}");
        assert_eq!(
            usize::from(u16::from_be_bytes([f[oi + 2], f[oi + 3]])),
            ip_total
        );
        let end = oi + ip_total;
        assert!(
            f[end..].iter().all(|&b| b == 0),
            "{link:?} {payload}: zero padding"
        );
        assert!(f[end - payload..end].iter().all(|&b| b == 0xa5));
    }
}

/// IPv6 без набивки, hop limit 255 даже при `--ttl` (`template_set_ttl` правит только IPv4, `src/templ-pkt.c:1473-1488`).
#[test]
fn ipv6_frame_unpadded_hop_limit_255() {
    let ttl64 = Template {
        ttl: Some(64),
        ..DEFAULT_TEMPLATE
    };
    let b = builder(LinkType::Ethernet, &ttl64);
    let f = b.build(&seg6(ME6, PEER6, 40000, 80));
    assert_eq!(f.len(), 14 + 40 + 24);
    assert_eq!(&f[12..14], &[0x86, 0xdd]);
    assert_eq!(&f[18..20], &24u16.to_be_bytes(), "payload length");
    assert_eq!(f[14 + 7], 255, "hop limit");
    assert_eq!(f[14 + 6], 6, "next header");
    assert!(tcp_ok(&f, 14, true));
    // Тот же построитель, IPv4: TTL 64.
    assert_eq!(b.build(&seg4(ME4, PEER4, 40000, 80))[22], 64);
    // Raw без опций: ровно 60 байт, с байтом нагрузки 61, не добивается.
    let mss_off = Template {
        mss: Mss::Off,
        ..ttl64
    };
    let b = builder(LinkType::Raw, &mss_off);
    assert_eq!(b.build(&seg6(ME6, PEER6, 40000, 80)).len(), 60);
    let mut s = seg6(ME6, PEER6, 40000, 80);
    s.payload = vec![7];
    let f = b.build(&s);
    assert_eq!(f.len(), 61);
    assert_eq!(&f[4..6], &21u16.to_be_bytes());
    assert_eq!(f[7], 255);
    // План без `source_ipv6`: шаблона IPv6 нет, кадра тоже.
    let b = TcpFrameBuilder::from_plan(&plan(LinkType::Ethernet, &ttl64.modifiers(), None));
    assert!(b.build(&seg6(ME6, PEER6, 40000, 80)).is_empty());
    assert!(!b.build(&seg4(ME4, PEER4, 40000, 80)).is_empty());
}

/// Окно 1200 вместо 1024 шаблона SYN (`src/templ-pkt.c:497-498`), `Some(w)` пишет `w`; опции и `doff` те же, что у
/// SYN (`src/templ-pkt.c:434`, копия шаблона).
#[test]
fn window_forced_1200_and_options_repeated() {
    let all = Template {
        mss: Mss::Value(1400),
        sackok: true,
        wscale: Some(7),
        tsecho: Some(0xdead_beef),
        ttl: Some(64),
    };
    for t in [DEFAULT_TEMPLATE, all] {
        let mods = t.modifiers();
        let b = builder(LinkType::Ethernet, &t);
        let mut syn = Vec::new();
        TcpSynTemplate::new_with_options(MAC_SRC, MAC_R4, LinkType::Ethernet, &mods)
            .build_syn(PEER4, 80, ME4, 40000, 5, &mut syn);
        let mut s = seg4(ME4, PEER4, 40000, 80);
        s.flags = 0x18;
        s.payload = b"hello".to_vec();
        let f = b.build(&s);
        assert_eq!(&syn[48..50], &[0x04, 0x01], "SYN window 1024");
        assert_eq!(&f[48..50], &1200u16.to_be_bytes());
        assert_eq!(f[46], syn[46], "data offset");
        let opt_end = 34 + usize::from(syn[46] >> 4) * 4;
        assert_eq!(&f[54..opt_end], &syn[54..opt_end], "options");
        assert_eq!(&f[opt_end..opt_end + 5], b"hello");
        assert_eq!(f[47], 0x18, "flags byte whole");
        s.window = Some(600);
        let f = b.build(&s);
        assert_eq!(&f[48..50], &600u16.to_be_bytes());
        assert!(tcp_ok(&f, 14, false));

        // IPv6: те же опции, что у SYN IPv6.
        let mut syn6 = Vec::new();
        Tcp6SynTemplate::new_with_options(MAC_SRC, MAC_R6, LinkType::Ethernet, &mods)
            .build_syn(PEER6, 80, ME6, 40000, 5, &mut syn6);
        let f = b.build(&seg6(ME6, PEER6, 40000, 80));
        let ot = 54;
        let opt_end = ot + usize::from(syn6[ot + 12] >> 4) * 4;
        assert_eq!(&syn6[ot + 14..ot + 16], &[0x04, 0x01], "SYN window 1024");
        assert_eq!(&f[ot + 14..ot + 16], &1200u16.to_be_bytes());
        assert_eq!(f[ot + 12], syn6[ot + 12], "data offset");
        assert_eq!(&f[ot + 20..opt_end], &syn6[ot + 20..opt_end], "options");
        assert_eq!(f.len(), opt_end, "no payload, no padding");
    }
}

/// IP ID `(ip_them ^ port_them ^ seqno) & 0xFFFF` (`src/templ-pkt.c:432`).
#[test]
fn ip_id_is_them_port_seq() {
    let b = builder(LinkType::Ethernet, &DEFAULT_TEMPLATE);
    let mut r = Rng::for_name("ip_id_is_them_port_seq");
    for _ in 0..1000 {
        let (them, port_them, seq) = (r.next() as u32, r.next() as u16, r.next() as u32);
        let mut s = seg4(r.next() as u32, them, r.next() as u16, port_them);
        s.seq = seq;
        let f = b.build(&s);
        let want = (them ^ u32::from(port_them) ^ seq) as u16;
        assert_eq!(&f[18..20], &want.to_be_bytes());
        assert_eq!(&f[38..42], &seq.to_be_bytes());
    }
}

// --- RST без состояния ---

fn reply4(flags: u8, status: PortStatus, ip_proto: u8) -> Reply {
    Reply {
        remote_ip: PEER4,
        remote_port: 80,
        local_ip: ME4,
        local_port: 40003,
        status,
        tcp_flags: flags,
        ttl: 57,
        ip_proto,
        mac: None,
        ip6: None,
    }
}

/// RST без состояния (`src/main.c:1094-1100`, `tcp_send_RST` `src/stack-tcp-core.c:1176-1219`): seq это наш ack
/// ответа (`cookie + 1`), ack 0, флаги `0x04`; только ответ TCP с SYN-ACK или RST.
#[test]
fn stateless_rst_fields() {
    let cookie4 = syn_cookie_ipv4(PEER4, 80, ME4, 40003, SEED) as u32;
    for flags in [0x12, 0x14, 0x04, 0x16, 0x1a, 0x52] {
        let status = if flags & 0x04 != 0 {
            PortStatus::Closed
        } else {
            PortStatus::Open
        };
        let rst = stateless_rst(&reply4(flags, status, 6), SEED).expect("rst");
        assert_eq!(
            rst,
            SegmentOut {
                key: ConnKey {
                    addrs: ConnAddrs::V4 {
                        local: ME4,
                        remote: PEER4
                    },
                    local_port: 40003,
                    remote_port: 80,
                },
                seq: cookie4.wrapping_add(1),
                ack: 0,
                flags: 0x04,
                payload: Vec::new(),
                window: None,
            },
            "flags 0x{flags:02x}"
        );
    }
    // Не SYN-ACK и не RST, ICMP Port Unreachable на зонд TCP (`ip_proto` 6, флагов нет), UDP, SCTP, ICMP Echo, ARP.
    for r in [
        reply4(0x10, PortStatus::Open, 6),
        reply4(0x02, PortStatus::Open, 6),
        reply4(0x00, PortStatus::Closed, 6),
        reply4(0x00, PortStatus::Open, 17),
        reply4(0x00, PortStatus::Closed, 17),
        reply4(0x00, PortStatus::Open, 132),
        reply4(0x00, PortStatus::Closed, 132),
        reply4(0x00, PortStatus::Open, 1),
        reply4(0x00, PortStatus::Arp, 0),
        reply4(0x12, PortStatus::Open, 17),
    ] {
        assert_eq!(stateless_rst(&r, SEED), None, "{r:?}");
    }
    // IPv6: cookie `syn_cookie_ipv6`, ключ из `ip6`.
    let r6 = Reply {
        remote_ip: 0,
        local_ip: 0,
        ip6: Some(ReplyIpv6 {
            remote: PEER6,
            local: ME6,
        }),
        ..reply4(0x12, PortStatus::Open, 6)
    };
    let rst = stateless_rst(&r6, SEED).expect("rst v6");
    assert_eq!(
        rst.key.addrs,
        ConnAddrs::V6 {
            local: ME6,
            remote: PEER6
        }
    );
    assert_eq!(
        rst.seq,
        (syn_cookie_ipv6(PEER6, 80, ME6, 40003, SEED) as u32).wrapping_add(1)
    );
    assert_eq!((rst.ack, rst.flags), (0, 0x04));

    // От кадра до кадра: SYN-ACK с ack `cookie + 1` проходит `parse_reply`, RST несёт этот ack в seq.
    let p = plan(LinkType::Ethernet, &PacketModifiers::default(), Some(ME6));
    for (v6, flags) in [(false, 0x12), (false, 0x14), (true, 0x12), (true, 0x04)] {
        let cookie = if v6 {
            syn_cookie_ipv6(PEER6, 80, ME6, 40003, SEED) as u32
        } else {
            cookie4
        };
        let f = In {
            v6,
            src: if v6 { PEER6 } else { u128::from(PEER4) },
            dst: if v6 { ME6 } else { u128::from(ME4) },
            sport: 80,
            dport: 40003,
            seq: 0x5555_0000,
            ack: cookie.wrapping_add(1),
            flags,
            ..In::default()
        }
        .frame(LinkType::Ethernet);
        let reply = parse_reply(&f, LinkType::Ethernet, &p)
            .expect("parse")
            .expect("reply");
        let rst = stateless_rst(&reply, SEED).expect("rst");
        assert_eq!(rst.seq, cookie.wrapping_add(1));
        let out = TcpFrameBuilder::from_plan(&p).build(&rst);
        let ot = if v6 { 54 } else { 34 };
        assert_eq!(out[ot + 13], 0x04);
        assert_eq!(&out[ot + 4..ot + 8], &cookie.wrapping_add(1).to_be_bytes());
        assert_eq!(&out[ot + 8..ot + 12], &[0, 0, 0, 0]);
        assert_eq!(&out[ot..ot + 2], &40003u16.to_be_bytes());
        assert_eq!(&out[ot + 2..ot + 4], &80u16.to_be_bytes());
        assert_eq!(out.len(), if v6 { 78 } else { 60 });
    }
}

// --- разбор входящего сегмента ---

/// Входящий кадр, собранный здесь по RFC 791/8200/9293, независимо от построителя.
#[derive(Clone, Debug)]
struct In {
    v6: bool,
    src: u128,
    dst: u128,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    ttl: u8,
    payload: Vec<u8>,
    /// Байты после IP-пакета (набивка Ethernet, FCS).
    trailer: Vec<u8>,
    /// Испортить сумму TCP / заголовка IPv4.
    bad_tcp: bool,
    bad_ip: bool,
    proto: u8,
}

impl Default for In {
    fn default() -> Self {
        In {
            v6: false,
            src: u128::from(PEER4),
            dst: u128::from(ME4),
            sport: 80,
            dport: 40001,
            seq: 0x1000_0000,
            ack: 0x2000_0000,
            flags: 0x18,
            ttl: 51,
            payload: b"SSH-2.0-x\r\n".to_vec(),
            trailer: Vec::new(),
            bad_tcp: false,
            bad_ip: false,
            proto: 6,
        }
    }
}

impl In {
    fn frame(&self, link: LinkType) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&self.sport.to_be_bytes());
        tcp.extend_from_slice(&self.dport.to_be_bytes());
        tcp.extend_from_slice(&self.seq.to_be_bytes());
        tcp.extend_from_slice(&self.ack.to_be_bytes());
        // doff 6: одна опция NOP x4, чтобы нагрузка начиналась не с 20-го байта.
        tcp.extend_from_slice(&[0x60, self.flags, 0x20, 0x00, 0, 0, 0, 0]);
        tcp.extend_from_slice(&[1, 1, 1, 1]);
        tcp.extend_from_slice(&self.payload);
        let (src, dst): (Vec<u8>, Vec<u8>) = if self.v6 {
            (
                self.src.to_be_bytes().to_vec(),
                self.dst.to_be_bytes().to_vec(),
            )
        } else {
            (
                (self.src as u32).to_be_bytes().to_vec(),
                (self.dst as u32).to_be_bytes().to_vec(),
            )
        };
        let mut c = !fold_all(pseudo(&src, &dst, tcp.len()) + sum16(&tcp));
        if self.bad_tcp {
            c ^= 0x0100;
        }
        tcp[16..18].copy_from_slice(&c.to_be_bytes());
        let mut ip = Vec::new();
        if self.v6 {
            ip.extend_from_slice(&[0x60, 0, 0, 0]);
            ip.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
            ip.extend_from_slice(&[self.proto, self.ttl]);
            ip.extend_from_slice(&src);
            ip.extend_from_slice(&dst);
        } else {
            ip.extend_from_slice(&[0x45, 0]);
            ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
            ip.extend_from_slice(&[0x12, 0x34, 0x40, 0x00, self.ttl, self.proto, 0, 0]);
            ip.extend_from_slice(&src);
            ip.extend_from_slice(&dst);
            let mut h = !fold_all(sum16(&ip));
            if self.bad_ip {
                h ^= 0x0001;
            }
            ip[10..12].copy_from_slice(&h.to_be_bytes());
        }
        let mut f = match link {
            LinkType::Ethernet => {
                let mut f = MAC_SRC.to_vec();
                f.extend_from_slice(&MAC_R4);
                f.extend_from_slice(if self.v6 {
                    &[0x86, 0xdd]
                } else {
                    &[0x08, 0x00]
                });
                f
            }
            LinkType::Null => (if self.v6 { 30u32 } else { 2u32 }).to_le_bytes().to_vec(),
            LinkType::Raw => Vec::new(),
        };
        f.extend_from_slice(&ip);
        f.extend_from_slice(&tcp);
        f.extend_from_slice(&self.trailer);
        f
    }

    /// Ожидаемый сегмент: ключ с нашей стороны.
    fn expected(&self) -> SegmentIn<'_> {
        let addrs = if self.v6 {
            ConnAddrs::V6 {
                local: self.dst,
                remote: self.src,
            }
        } else {
            ConnAddrs::V4 {
                local: self.dst as u32,
                remote: self.src as u32,
            }
        };
        SegmentIn {
            key: ConnKey {
                addrs,
                local_port: self.dport,
                remote_port: self.sport,
            },
            seq: self.seq,
            ack: self.ack,
            flags: self.flags,
            ttl: self.ttl,
            payload: &self.payload,
        }
    }
}

fn v6_in() -> In {
    In {
        v6: true,
        src: PEER6,
        dst: ME6,
        ..In::default()
    }
}

/// Кадр `build` для ACK, данных, данных+FIN, FIN и RST, IPv4 и IPv6, на каждом канале разбирается в тот же
/// сегмент (ключ с другой стороны, TTL шаблона, нагрузка без набивки).
#[test]
fn tcp_segment_round_trip() {
    let ttl64 = Template {
        ttl: Some(64),
        ..DEFAULT_TEMPLATE
    };
    let mut r = Rng::for_name("tcp_segment_round_trip");
    for link in [LinkType::Ethernet, LinkType::Raw, LinkType::Null] {
        // Кадр построителя идёт от `local` к `remote`; чтобы он был "нам", `remote` это наш адрес.
        let p = plan(link, &ttl64.modifiers(), Some(ME6));
        let b = TcpFrameBuilder::from_plan(&p);
        for v6 in [false, true] {
            if v6 && link == LinkType::Null {
                // DLT_NULL IPv6: `AF_INET6` построителя это значение ОС сборки (`packet.rs`), а приёмник
                // принимает 24, 28 и 30; на Linux (10) кадр не разбирается, как и в C.
                continue;
            }
            for (flags, plen) in [
                (0x10, 0),
                (0x18, 5),
                (0x19, 1400),
                (0x11, 0),
                (0x04, 0),
                (0x18, 1),
            ] {
                let addrs = if v6 {
                    ConnAddrs::V6 {
                        local: PEER6,
                        remote: ME6,
                    }
                } else {
                    ConnAddrs::V4 {
                        local: PEER4,
                        remote: ME4,
                    }
                };
                let out = SegmentOut {
                    key: ConnKey {
                        addrs,
                        local_port: 443,
                        remote_port: 40007,
                    },
                    seq: r.next() as u32,
                    ack: r.next() as u32,
                    flags,
                    payload: (0..plen).map(|k| (k * 7) as u8).collect(),
                    window: None,
                };
                let frame = b.build(&out);
                let got = tcp_segment(&frame, link, &p)
                    .unwrap_or_else(|| panic!("{link:?} v6={v6} 0x{flags:02x}"));
                let back = if v6 {
                    ConnAddrs::V6 {
                        local: ME6,
                        remote: PEER6,
                    }
                } else {
                    ConnAddrs::V4 {
                        local: ME4,
                        remote: PEER4,
                    }
                };
                assert_eq!(
                    got,
                    SegmentIn {
                        key: ConnKey {
                            addrs: back,
                            local_port: 40007,
                            remote_port: 443,
                        },
                        seq: out.seq,
                        ack: out.ack,
                        flags,
                        ttl: if v6 { 255 } else { 64 },
                        payload: &out.payload,
                    },
                    "{link:?} v6={v6} 0x{flags:02x}"
                );
            }
        }
    }
}

/// Чужой адрес или порт назначения и неверные суммы отбрасываются; флаги, набор целей и cookie не проверяются.
#[test]
fn tcp_segment_rejects_foreign_address_port_and_bad_checksum() {
    let p = plan(LinkType::Ethernet, &PacketModifiers::default(), Some(ME6));
    let eth = LinkType::Ethernet;
    for base in [In::default(), v6_in()] {
        let f = base.frame(eth);
        assert_eq!(
            tcp_segment(&f, eth, &p),
            Some(base.expected()),
            "v6={}",
            base.v6
        );
        // Без фильтра флагов, целей и cookie: чистый ACK от адреса вне целей с любым ack принимается.
        let other = In {
            src: if base.v6 {
                0x2001_0db9 << 96
            } else {
                0xc000_0201
            },
            flags: 0x10,
            ack: 7,
            sport: 9999,
            payload: Vec::new(),
            ..base.clone()
        };
        assert_eq!(
            tcp_segment(&other.frame(eth), eth, &p),
            Some(other.expected())
        );

        let reject = |what: &str, i: In| {
            assert_eq!(
                tcp_segment(&i.frame(eth), eth, &p),
                None,
                "{what} v6={}",
                base.v6
            );
        };
        reject(
            "foreign address",
            In {
                dst: base.dst + 1,
                ..base.clone()
            },
        );
        reject(
            "port below the range",
            In {
                dport: 39999,
                ..base.clone()
            },
        );
        reject(
            "port above the range",
            In {
                dport: 40016,
                ..base.clone()
            },
        );
        reject(
            "bad tcp checksum",
            In {
                bad_tcp: true,
                ..base.clone()
            },
        );
        reject(
            "udp",
            In {
                proto: 17,
                ..base.clone()
            },
        );
        if !base.v6 {
            reject(
                "bad ip checksum",
                In {
                    bad_ip: true,
                    ..base.clone()
                },
            );
        }
        // Обрезанный кадр.
        let f = base.frame(eth);
        for cut in [0, 13, 14, 33, 40, 53, 60] {
            assert_eq!(
                tcp_segment(&f[..cut.min(f.len())], eth, &p),
                None,
                "cut {cut}"
            );
        }
    }
    // Без `source_ipv6` IPv6 не наш никогда.
    let p4 = plan(LinkType::Ethernet, &PacketModifiers::default(), None);
    assert_eq!(tcp_segment(&v6_in().frame(eth), eth, &p4), None);
    // Тег 802.1Q (VLAN 100) перед IPv4 или IPv6: теги не снимаются, кадр не наш (`Unsupported::Vlan`, как у
    // `parse_reply`; C разбирает 802.1Q, `src/proto-preprocess.c:334-338`, `:506`).
    for base in [In::default(), v6_in()] {
        let f = base.frame(eth);
        assert!(tcp_segment(&f, eth, &p).is_some());
        let tagged = [&f[..12], &[0x81, 0x00, 0x00, 0x64][..], &f[12..]].concat();
        assert_eq!(tcp_segment(&tagged, eth, &p), None, "802.1Q v6={}", base.v6);
    }
    // ARP и кадр длиннее 1514 байт.
    let mut arp = vec![0xff; 6];
    arp.extend_from_slice(&MAC_R4);
    arp.extend_from_slice(&[0x08, 0x06]);
    arp.extend_from_slice(&[0; 28]);
    assert_eq!(tcp_segment(&arp, eth, &p), None);
    let long = In {
        payload: vec![0; 1514 - 14 - 20 - 24 + 1],
        ..In::default()
    };
    let f = long.frame(eth);
    assert_eq!(f.len(), 1515);
    assert_eq!(tcp_segment(&f, eth, &p), None);
    let max = In {
        payload: vec![0; 1514 - 14 - 20 - 24],
        ..In::default()
    };
    assert_eq!(tcp_segment(&max.frame(eth), eth, &p), Some(max.expected()));
}

/// IPv6 с расширением Hop-by-Hop перед TCP: цепочка проходится (длина по RFC 8200, `(Hdr Ext Len + 1) * 8`, как у
/// `parse_reply`; C считает `px[offset+1] + 8` байт, `src/proto-preprocess.c:306`), сегмент тот же, что без
/// расширения. За Hop-by-Hop не TCP: не наш.
#[test]
fn tcp_segment_walks_ipv6_hop_by_hop() {
    let p = plan(LinkType::Ethernet, &PacketModifiers::default(), Some(ME6));
    let eth = LinkType::Ethernet;
    let base = v6_in();
    let f = base.frame(eth);
    // Вставить расширение после 40 байт заголовка: Next Header 0 в заголовке, в расширении Next Header 6.
    let with_hbh = |ext_len: u8, next: u8| {
        let len = (usize::from(ext_len) + 1) * 8;
        let mut ext = vec![next, ext_len, 1, (len - 4) as u8];
        ext.resize(len, 0);
        let mut g = [&f[..54], &ext[..], &f[54..]].concat();
        g[14 + 6] = 0;
        let plen = u16::from_be_bytes([g[18], g[19]]) + len as u16;
        g[18..20].copy_from_slice(&plen.to_be_bytes());
        g
    };
    for ext_len in [0u8, 1, 2] {
        let g = with_hbh(ext_len, 6);
        assert_eq!(
            tcp_segment(&g, eth, &p),
            Some(base.expected()),
            "Hdr Ext Len {ext_len}"
        );
        assert_eq!(
            tcp_segment(&with_hbh(ext_len, 17), eth, &p),
            None,
            "UDP after Hop-by-Hop"
        );
    }
}

/// Нагрузка кончается с IP-пакетом: набивка Ethernet до 60 и хвост вроде FCS в нагрузку не входят.
#[test]
fn tcp_segment_payload_excludes_padding() {
    let p = plan(LinkType::Ethernet, &PacketModifiers::default(), Some(ME6));
    let eth = LinkType::Ethernet;
    let one = In {
        payload: vec![0x42],
        trailer: vec![0xaa; 1],
        ..In::default()
    };
    let f = one.frame(eth);
    assert_eq!(f.len(), 60);
    let got = tcp_segment(&f, eth, &p).expect("segment");
    assert_eq!(got.payload, &[0x42]);
    for base in [In::default(), v6_in()] {
        let i = In {
            payload: vec![0x33; 100],
            trailer: vec![0xde, 0xad, 0xbe, 0xef],
            ..base
        };
        let f = i.frame(eth);
        let got = tcp_segment(&f, eth, &p).expect("segment");
        assert_eq!(got.payload, &[0x33; 100][..], "v6={}", i.v6);
    }
    // Пустая нагрузка с набивкой.
    let empty = In {
        payload: Vec::new(),
        flags: 0x10,
        trailer: vec![0; 2],
        ..In::default()
    };
    assert_eq!(
        tcp_segment(&empty.frame(eth), eth, &p)
            .expect("segment")
            .payload,
        b""
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Тотальность: любой кадр до 1600 байт на любом канале, случайный или испорченный настоящий, без паники.
    #[test]
    fn tcp_segment_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..1600),
        link in prop_oneof![Just(LinkType::Ethernet), Just(LinkType::Null), Just(LinkType::Raw)],
        v6 in any::<bool>(),
        cut in any::<prop::sample::Index>(),
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..6),
    ) {
        let p = plan(link, &PacketModifiers::default(), Some(ME6));
        let _ = tcp_segment(&bytes, link, &p);
        let base = if v6 { v6_in() } else { In::default() };
        let mut f = In { payload: bytes.iter().copied().take(64).collect(), ..base }.frame(link);
        for (i, b) in &flips {
            let k = i.index(f.len());
            f[k] ^= *b;
        }
        let _ = tcp_segment(&f, link, &p);
        let n = cut.index(f.len() + 1);
        let _ = tcp_segment(&f[..n], link, &p);
    }
}

/// Кадр, не помещающийся в буфер C (`sizeof(response->px)` 2040, `src/stack-queue.h:13`), не строится: C печатает
/// `too much payload` и отдаёт длину 0 (`src/templ-pkt.c:440-443`, `:521-524`).
#[test]
fn build_refuses_payload_past_c_buffer() {
    let b = builder(LinkType::Ethernet, &DEFAULT_TEMPLATE);
    let mut s = seg4(ME4, PEER4, 40000, 80);
    s.payload = vec![0; 2040 - 58];
    assert_eq!(b.build(&s).len(), 2040);
    s.payload.push(0);
    assert!(b.build(&s).is_empty());
    let mut s = seg6(ME6, PEER6, 40000, 80);
    s.payload = vec![0; 2040 - 78];
    assert_eq!(b.build(&s).len(), 2040);
    s.payload.push(0);
    assert!(b.build(&s).is_empty());
}
