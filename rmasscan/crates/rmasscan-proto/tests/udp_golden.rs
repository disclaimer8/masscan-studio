//! Паритет UDP-парсеров баннеров с C (AGPL-3.0). Каждый кейс `tests/golden/udp-banners` это датаграмма ответа и
//! вывод C-оракула `udp-oracle`: настоящий `handle_udp` masscan © Robert David Graham (HEAD 8e6b3b0) с заглушками
//! вывода (README эталонов). Ожидание (`cases/<кейс>.out`) снято с датаграммой в роли кадра (`app_offset` 0) и
//! `-ftrivial-auto-var-init=pattern`: так C адресует датаграмму, а не кадр, и не видит мусора стека, то есть ведёт
//! себя, как решено для rmasscan (Р1, Р2). Вывод того же C в кадре Ethernet (`cases/<кейс>.eth.out`, только если он
//! другой) сверяется с ожиданием по правилам названных отличий: сырой баннер за концом датаграммы (11211 и порты
//! без парсера) совпадает длиной, остальные отличия перечислены в [`FRAME_DEPENDENT`].
//!
//! Датаграммы строит `examples/udp_golden_inputs.rs`; закоммиченные `cases/*.bin` обязаны с ним совпадать.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use rmasscan_proto::{UdpContext, app_id, handle_udp};

#[path = "../examples/udp_golden_inputs.rs"]
#[allow(dead_code)]
mod udp_golden_inputs;

use udp_golden_inputs::{Case, cases};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/udp-banners"
);
const ORACLE_GIT_HEAD: &str = "8e6b3b0c07a81e8ea61d557c06134a21a6881614";

/// Кейсы, у которых C в кадре Ethernet печатает другое не только в сыром баннере за концом датаграммы: (кейс,
/// отличие). Каждое отличие названо в README эталонов и в `src/udp/mod.rs`.
const FRAME_DEPENDENT: &[(&str, &str)] = &[
    (
        "dns-pointer-to-id",
        "указатель сжатия `c0 00`: у C это смещение 0 кадра (MAC), имя проходит проверку и печатается dns-ver; у нас \
         смещение 0 сообщения DNS (id), имя неверно, сырой баннер",
    ),
    (
        "dns-pointer-chain-5",
        "пять указателей подряд: у C цепочка уходит в байты заголовков кадра и обрывается раньше пятого перехода, имя \
         проходит; у нас пятый переход, имя неверно, сырой баннер",
    ),
];

/// Ожидаемые байты баннера в файле оракула.
#[derive(Debug)]
enum Bytes {
    /// `=datagram`: первые LEN байт датаграммы раздела.
    Datagram,
    Literal(Vec<u8>),
}

#[derive(Debug)]
struct Section {
    label: String,
    banners: Vec<(u16, usize, Bytes)>,
}

struct Out {
    header: String,
    sections: Vec<Section>,
}

fn parse_bytes(s: &str) -> Bytes {
    if s == "-" {
        return Bytes::Literal(Vec::new());
    }
    if s == "=datagram" {
        return Bytes::Datagram;
    }
    let inner = s
        .strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .unwrap_or_else(|| panic!("bad bytes field {s:?}"));
    let raw = inner.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\\' {
            assert_eq!(raw.get(i + 1), Some(&b'x'), "bad escape in {s:?}");
            let hex = std::str::from_utf8(&raw[i + 2..i + 4]).expect("hex");
            out.push(u8::from_str_radix(hex, 16).expect("hex"));
            i += 4;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    Bytes::Literal(out)
}

fn parse_out(text: &str, what: &str) -> Out {
    let mut lines = text.lines();
    let header = lines
        .next()
        .unwrap_or_else(|| panic!("{what}: empty"))
        .to_string();
    let mut sections: Vec<Section> = Vec::new();
    for line in lines {
        if let Some(label) = line.strip_prefix("section ") {
            sections.push(Section {
                label: label.to_string(),
                banners: Vec::new(),
            });
        } else if line == "status open count=1" {
            // handle_udp всегда пишет одну запись статуса (src/proto-udp.c:63-73); её пишет движок, не парсер.
        } else if let Some(rest) = line.strip_prefix("banner ") {
            let mut it = rest.splitn(3, ' ');
            let app: u16 = it.next().and_then(|v| v.parse().ok()).expect("app");
            let len: usize = it.next().and_then(|v| v.parse().ok()).expect("len");
            let bytes = parse_bytes(it.next().expect("bytes"));
            if let Bytes::Literal(b) = &bytes {
                assert_eq!(b.len(), len, "{what}: {line}");
            }
            sections
                .last_mut()
                .unwrap_or_else(|| panic!("{what}: banner before section"))
                .banners
                .push((app, len, bytes));
        } else {
            panic!("{what}: unexpected line {line:?}");
        }
    }
    Out { header, sections }
}

fn resolve(banners: &[(u16, usize, Bytes)], datagram: &[u8]) -> Vec<(u16, Vec<u8>)> {
    banners
        .iter()
        .map(|(app, len, b)| {
            let bytes = match b {
                Bytes::Datagram => datagram[..*len].to_vec(),
                Bytes::Literal(v) => v.clone(),
            };
            (*app, bytes)
        })
        .collect()
}

fn show(banners: &[(u16, Vec<u8>)]) -> String {
    banners
        .iter()
        .map(|(app, b)| format!("({app}, {:?})", String::from_utf8_lossy(b)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn header_for(c: &Case, framing: &str) -> String {
    format!(
        "udp-oracle port={} cookie=0x{:08x} rawudp={} mode={} sections={} framing={framing}",
        c.port,
        c.cookie,
        u8::from(c.rawudp),
        c.mode.arg(),
        c.sections().len()
    )
}

/// Порты, на которых C берёт сырой баннер за концом датаграммы (`src/proto-udp.c:97-101, 108-112`).
fn overreads(port: u16) -> bool {
    !matches!(
        port,
        53 | 123 | 137 | 161 | 500 | 5683 | 16464 | 16465 | 16470 | 16471
    )
}

#[test]
fn udp_golden_matches_c() {
    let dir = Path::new(DIR);
    let manifest = String::from_utf8(read(&dir.join("manifest.json"))).expect("utf-8");
    assert!(
        manifest.contains(&format!("\"masscan_git_head\": \"{ORACLE_GIT_HEAD}\"")),
        "oracle pin"
    );
    let all = cases();
    let mut names = BTreeSet::new();
    let mut failures = Vec::new();
    let mut sections_checked = 0usize;
    for c in &all {
        assert!(names.insert(c.name), "duplicate case {}", c.name);
        assert!(
            manifest.contains(&format!("\"name\": \"{}\"", c.name)),
            "{} not in manifest.json",
            c.name
        );
        assert_eq!(
            read(&dir.join(format!("cases/{}.bin", c.name))),
            c.payload,
            "{}.bin drifted from the generator",
            c.name
        );
        let text =
            String::from_utf8(read(&dir.join(format!("cases/{}.out", c.name)))).expect("utf-8");
        let out = parse_out(&text, c.name);
        assert_eq!(out.header, header_for(c, "payload"), "{}", c.name);
        let sections = c.sections();
        assert_eq!(out.sections.len(), sections.len(), "{}", c.name);
        let cx = UdpContext {
            port_them: c.port,
            cookie: c.cookie,
            rawudp: c.rawudp,
        };
        for ((label, datagram), want) in sections.iter().zip(&out.sections) {
            assert_eq!(&want.label, label, "{}", c.name);
            let want = resolve(&want.banners, datagram);
            let got = handle_udp(&cx, datagram);
            sections_checked += 1;
            if got != want {
                failures.push(format!(
                    "{} [{label}]\n  C:    {}\n  Rust: {}",
                    c.name,
                    show(&want),
                    show(&got)
                ));
            }
        }
        check_eth(dir, c, &out, &mut failures);
    }
    // Каждый файл каталога принадлежит кейсу генератора.
    for entry in fs::read_dir(dir.join("cases")).expect("cases dir") {
        let file = entry
            .expect("entry")
            .file_name()
            .into_string()
            .expect("utf-8 name");
        let stem = file
            .strip_suffix(".eth.out")
            .or_else(|| file.strip_suffix(".out"))
            .or_else(|| file.strip_suffix(".bin"))
            .unwrap_or_else(|| panic!("unexpected file cases/{file}"));
        assert!(
            names.contains(stem),
            "cases/{file} has no case in the generator"
        );
    }
    for (name, _) in FRAME_DEPENDENT {
        assert!(
            names.contains(name),
            "FRAME_DEPENDENT lists unknown case {name}"
        );
    }
    assert!(
        failures.is_empty(),
        "{} of {sections_checked} sections differ from C:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!(
        "udp_golden_matches_c: {} cases, {sections_checked} sections",
        all.len()
    );
}

/// Вывод C в кадре Ethernet: файла нет, если он равен ожиданию; иначе каждое отличие раздела названо.
fn check_eth(dir: &Path, c: &Case, out: &Out, failures: &mut Vec<String>) {
    let path = dir.join(format!("cases/{}.eth.out", c.name));
    let frame_dependent = FRAME_DEPENDENT.iter().any(|(n, _)| *n == c.name);
    if !path.exists() {
        assert!(
            !frame_dependent,
            "{}: listed in FRAME_DEPENDENT but has no .eth.out",
            c.name
        );
        return;
    }
    let text = String::from_utf8(read(&path)).expect("utf-8");
    let eth = parse_out(&text, c.name);
    assert_eq!(eth.header, header_for(c, "eth"), "{}", c.name);
    assert_eq!(eth.sections.len(), out.sections.len(), "{}", c.name);
    let mut differs = 0;
    for ((section, (_, datagram)), e) in out.sections.iter().zip(c.sections()).zip(&eth.sections) {
        assert_eq!(section.label, e.label, "{}", c.name);
        let want = resolve(&section.banners, &datagram);
        let got = resolve(&e.banners, &datagram);
        if want == got {
            continue;
        }
        differs += 1;
        let raw_past_datagram = overreads(c.port)
            && want.len() == got.len()
            && want[..want.len() - 1] == got[..got.len() - 1]
            && matches!((want.last(), got.last()), (Some((a, x)), Some((b, y)))
                if *a == app_id::NONE && *b == app_id::NONE && x.len() == y.len());
        if !raw_past_datagram && !frame_dependent {
            failures.push(format!(
                "{} [{}]: C in an Ethernet frame differs without a named difference\n  payload: {}\n  eth:     {}",
                c.name,
                section.label,
                show(&want),
                show(&got)
            ));
        }
    }
    assert!(differs > 0, "{}: .eth.out equals .out, remove it", c.name);
}

/// Мутации эталонных датаграмм (байт, обрезка, вставка) не роняют `handle_udp` ни на одном порту.
#[test]
fn udp_golden_mutations_never_panic() {
    let mut state: u64 = 0xD1B5_4A32_D192_ED03;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for c in cases() {
        for _ in 0..200 {
            let mut px = c.payload.clone();
            let r = next();
            let at = usize::try_from(r % (px.len() as u64 + 1)).expect("index");
            match (r >> 32) % 3 {
                0 if at < px.len() => px[at] = (r >> 40) as u8,
                1 => px.truncate(at),
                _ => px.insert(at, (r >> 40) as u8),
            }
            for port in [c.port, 53, 123, 137, 161] {
                let cx = UdpContext {
                    port_them: port,
                    cookie: c.cookie,
                    rawudp: r & 1 == 1,
                };
                let got = handle_udp(&cx, &px);
                if cx.rawudp {
                    assert_eq!(got.last(), Some(&(app_id::NONE, px.clone())));
                }
            }
        }
    }
}
