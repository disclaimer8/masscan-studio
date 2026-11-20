//! Паритет разбора X.509 с C (AGPL-3.0, подэтап 4c, задача 3). Каждый кейс `tests/golden/x509` — один
//! сертификат DER и вывод C-оракула (режимы `x509`/`x509-vectors` вне репозитория, Р14): настоящий
//! `x509_decode` masscan © Robert David Graham (HEAD 8e6b3b0, `src/proto-x509.c`) с `count` как ставит
//! `parse_server_cert`. Эталон — прогон C на целом DER (`run whole`, Р13); прогон по байту хранится рядом.
//!
//! [`x509_stream`] прогоняется целиком, по байту и в 8 случайных нарезках; записи обязаны совпасть с `whole`
//! в каждой.

use std::fs;
use std::path::Path;

use rmasscan_proto::x509_stream;

#[path = "../../rmasscan-core/tests/common/sha256.rs"]
mod sha256;

#[path = "../../rmasscan-core/tests/common/golden.rs"]
mod golden;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/x509");
const CASES: usize = 32;

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix('"')?.strip_prefix(key)?;
    let rest = rest.strip_prefix("\": ")?;
    Some(rest.trim_end_matches(',').trim_matches('"'))
}

struct Case {
    name: String,
    count: u32,
    input: String,
    output: String,
}

fn cases() -> Vec<Case> {
    let dir = Path::new(DIR);
    let manifest = String::from_utf8(read(&dir.join("manifest.json"))).expect("manifest utf8");
    let mut out: Vec<Case> = Vec::new();
    let mut cur: Option<Case> = None;
    for line in manifest.lines() {
        if let Some(v) = field(line, "name") {
            if let Some(c) = cur.take() {
                out.push(c);
            }
            cur = Some(Case {
                name: v.to_owned(),
                count: 0,
                input: String::new(),
                output: String::new(),
            });
        } else if let Some(c) = cur.as_mut() {
            if let Some(v) = field(line, "input") {
                c.input = v.to_owned();
            } else if let Some(v) = field(line, "output") {
                c.output = v.to_owned();
            } else if line.trim_start().starts_with("\"count\":") {
                c.count = line
                    .split(':')
                    .nth(1)
                    .map(|s| s.trim().trim_end_matches(',').parse().expect("count"))
                    .expect("count");
            }
        }
    }
    if let Some(c) = cur.take() {
        out.push(c);
    }
    out.retain(|c| !c.input.is_empty());
    out
}

fn parse_input(text: &str) -> (u32, Vec<u8>) {
    let mut count = None;
    let mut der = Vec::new();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("count ") {
            count = v.trim().parse().ok();
        } else if let Some(hex) = line.strip_prefix("der ") {
            for i in (0..hex.len()).step_by(2) {
                der.push(u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"));
            }
        }
    }
    (count.expect("count"), der)
}

/// `"..."` с `\xNN` вывода оракула; `-` — пусто.
fn unquote(tok: &str) -> Vec<u8> {
    if tok == "-" {
        return Vec::new();
    }
    let b = tok
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .expect("quoted")
        .as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && b.get(i + 1) == Some(&b'x') {
            let h = std::str::from_utf8(&b[i + 2..i + 4]).expect("hex");
            out.push(u8::from_str_radix(h, 16).expect("hex"));
            i += 4;
        } else if b[i] == b'\\' {
            out.push(b[i + 1]);
            i += 2;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// Записи прогона `whole` из вывода оракула.
fn whole_records(text: &str) -> Vec<(u16, Vec<u8>)> {
    let mut in_whole = false;
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with("run ") {
            in_whole = line.starts_with("run whole");
        } else if in_whole && let Some(rest) = line.strip_prefix("record ") {
            let mut w = rest.splitn(3, ' ');
            let app: u16 = w.next().expect("app").parse().expect("app");
            let len: usize = w.next().expect("len").parse().expect("len");
            let bytes = unquote(w.next().expect("bytes"));
            assert_eq!(bytes.len(), len);
            out.push((app, bytes));
        }
    }
    out
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

fn random_splits<'a>(der: &'a [u8], rng: &mut Rng) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < der.len() {
        let n = 1 + (rng.next() % 97) as usize;
        let end = (at + n).min(der.len());
        out.push(&der[at..end]);
        at = end;
    }
    if out.is_empty() {
        out.push(der);
    }
    out
}

/// Каждый кейс целиком, по байту и в 8 случайных нарезках равен прогону C на целом DER (Р13).
#[test]
fn x509_golden_matches_c() {
    let dir = Path::new(DIR);
    let cases = cases();
    assert_eq!(cases.len(), CASES);
    for c in &cases {
        let in_text = String::from_utf8(read(&dir.join(&c.input))).expect("input utf8");
        let (count, der) = parse_input(&in_text);
        assert_eq!(count, c.count, "{}", c.name);
        let out_text = String::from_utf8(read(&dir.join(&c.output))).expect("output utf8");
        let want = whole_records(&out_text);

        assert_eq!(x509_stream(count, &[&der]), want, "{}: whole", c.name);
        let bytewise: Vec<&[u8]> = der.chunks(1).collect();
        assert_eq!(x509_stream(count, &bytewise), want, "{}: bytewise", c.name);
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ (der.len() as u64));
        for k in 0..8 {
            let splits = random_splits(&der, &mut rng);
            assert_eq!(x509_stream(count, &splits), want, "{}: split {k}", c.name);
        }
    }
}

/// Суммы манифеста совпадают с файлами.
#[test]
fn manifest_hashes_match_files() {
    let dir = Path::new(DIR);
    let manifest = String::from_utf8(read(&dir.join("manifest.json"))).expect("manifest utf8");
    let checked = golden::check_manifest_hashes(dir, &manifest).expect("hashes");
    assert_eq!(checked, CASES * 2);
}

/// Имена цепочки: CN подавляется при count>1, SAN — нет (справка §C4, кейсы оракула выше).
#[test]
fn only_leaf_names_emitted() {
    let dir = Path::new(DIR);
    let by_name: std::collections::HashMap<String, Vec<(u16, Vec<u8>)>> = cases()
        .iter()
        .map(|c| {
            let (_, der) = parse_input(&String::from_utf8(read(&dir.join(&c.input))).unwrap());
            (c.name.clone(), x509_stream(c.count, &[&der]))
        })
        .collect();
    let text = |name: &str| -> String {
        by_name[name]
            .first()
            .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    };
    assert_eq!(text("google-leaf"), ", www.google.com, www.google.com");
    assert_eq!(text("google-count2"), ", www.google.com");
    assert!(text("case1-leaf-count2").starts_with(", *.google.com, *.android.com"));
    assert_eq!(text("mini-san-count2"), ", a.test");
}

/// Мутации DER и случайные байты при случайных длинах init и нарезках: ни паники, записи только `ssl` и не
/// длиннее предела Р5, результат не зависит от нарезки.
#[test]
fn x509_never_panics() {
    let dir = Path::new(DIR);
    let google = cases()
        .into_iter()
        .find(|c| c.name == "google-leaf")
        .map(|c| parse_input(&String::from_utf8(read(&dir.join(c.input))).unwrap()).1)
        .expect("google case");
    let mut rng = Rng(0xC0FF_EE12_3456_789A);
    for round in 0..400 {
        let mut der = google.clone();
        match round % 3 {
            0 => {
                for _ in 0..1 + rng.next() % 24 {
                    let at = (rng.next() as usize) % der.len();
                    der[at] = rng.next() as u8;
                }
            }
            1 => der.truncate((rng.next() as usize) % (der.len() + 1)),
            _ => {
                der = (0..(rng.next() % 300) as usize)
                    .map(|_| rng.next() as u8)
                    .collect();
            }
        }
        let count = (rng.next() % 4) as u32;
        let whole = x509_stream(count, &[&der]);
        for (app, bytes) in &whole {
            assert_eq!(*app, rmasscan_proto::app_id::SSL3);
            assert!(bytes.len() <= rmasscan_proto::MAX_BANNER_BYTES);
        }
        let splits = random_splits(&der, &mut rng);
        assert_eq!(x509_stream(count, &splits), whole, "round {round}");
    }
}
