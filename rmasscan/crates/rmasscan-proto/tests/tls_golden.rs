//! Паритет парсера TLS-записей с C (AGPL-3.0, подэтап 4c, задача 4). Каждый кейс `tests/golden/tls-records` —
//! поток TLS одного соединения с флагами захвата и режимов и вывод C-оракула (режим `tls`, вне репозитория,
//! Р14): настоящий `ssl_parse_record` masscan © Robert David Graham (HEAD 8e6b3b0, `src/proto-ssl.c`).
//! Эталон — прогон C на целом потоке (`run whole`, Р13): записи и действия; прогоны по байту и по сегментам
//! хранятся как свидетельство (справка §B1, §F E2).
//!
//! [`tls_stream`] прогоняется целиком, по байту, по заданным сегментам и в 8 случайных нарезках; действия
//! сравниваются только целиком, как у каркаса (справка TCP E2: отправки парсеров зависят от вызовов).

use std::fs;
use std::path::Path;

use rmasscan_proto::{StreamAction, tls_stream};

#[path = "../../rmasscan-core/tests/common/sha256.rs"]
mod sha256;

#[path = "../../rmasscan-core/tests/common/golden.rs"]
mod golden;

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/tls-records"
);
const CASES: usize = 39;

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix('"')?.strip_prefix(key)?;
    let rest = rest.strip_prefix("\": ")?;
    Some(rest.trim_end_matches(',').trim_matches('"'))
}

#[derive(Clone, Copy, Default)]
struct Flags {
    cert: bool,
    cap_hb: bool,
    cap_tb: bool,
    heartbleed: bool,
    ticketbleed: bool,
    poodle: bool,
}

struct Case {
    name: String,
    flags: Flags,
    segments: Vec<Vec<u8>>,
    output: String,
}

fn cases() -> Vec<Case> {
    let dir = Path::new(DIR);
    let manifest = String::from_utf8(read(&dir.join("manifest.json"))).expect("manifest utf8");
    let mut out = Vec::new();
    let mut name = String::new();
    let mut input = String::new();
    let mut output = String::new();
    for line in manifest.lines() {
        if let Some(v) = field(line, "name") {
            name = v.to_owned();
        } else if let Some(v) = field(line, "input") {
            input = v.to_owned();
        } else if let Some(v) = field(line, "output") {
            output = v.to_owned();
        } else if field(line, "output_sha256").is_some() && !name.is_empty() {
            let in_text = String::from_utf8(read(&dir.join(&input))).expect("input utf8");
            let mut flags = Flags {
                cert: true,
                ..Flags::default()
            };
            let mut segments = Vec::new();
            for l in in_text.lines() {
                if let Some(rest) = l.strip_prefix("flags ") {
                    for tok in rest.split(' ') {
                        match tok {
                            "cert" => flags.cert = true,
                            "nocert" => flags.cert = false,
                            "cap-hb" => flags.cap_hb = true,
                            "cap-tb" => flags.cap_tb = true,
                            "heartbleed" => flags.heartbleed = true,
                            "ticketbleed" => flags.ticketbleed = true,
                            "poodle" => flags.poodle = true,
                            other => panic!("flag {other}"),
                        }
                    }
                } else if let Some(hex) = l.strip_prefix("segment ") {
                    segments.push(
                        (0..hex.len())
                            .step_by(2)
                            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                            .collect::<Vec<u8>>(),
                    );
                }
            }
            out.push(Case {
                name: std::mem::take(&mut name),
                flags,
                segments,
                output: output.clone(),
            });
        }
    }
    out
}

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

/// Прогон `whole` оракула: (записи, действия). `=stream` разворачивается в префикс потока.
fn whole_run(text: &str, stream: &[u8]) -> (Vec<(u16, Vec<u8>)>, Vec<StreamAction>) {
    let mut in_whole = false;
    let mut records = Vec::new();
    let mut actions = Vec::new();
    for line in text.lines() {
        if line.starts_with("run ") {
            in_whole = line.starts_with("run whole");
        } else if in_whole && let Some(rest) = line.strip_prefix("record ") {
            let mut w = rest.splitn(3, ' ');
            let app: u16 = w.next().expect("app").parse().expect("app");
            let len: usize = w.next().expect("len").parse().expect("len");
            let tok = w.next().expect("bytes");
            let bytes = if tok == "=stream" {
                stream[..len].to_vec()
            } else {
                unquote(tok)
            };
            assert_eq!(bytes.len(), len);
            records.push((app, bytes));
        } else if in_whole && line == "action close" {
            actions.push(StreamAction::Close);
        } else if in_whole && let Some(rest) = line.strip_prefix("action send ") {
            let mut w = rest.splitn(3, ' ');
            let _flags = w.next().expect("flags");
            let len: usize = w.next().expect("len").parse().expect("len");
            let bytes = unquote(w.next().expect("bytes"));
            assert_eq!(bytes.len(), len);
            actions.push(StreamAction::Send(bytes));
        }
    }
    (records, actions)
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

fn run(f: &Flags, segs: &[&[u8]]) -> rmasscan_proto::StreamResult {
    tls_stream(
        f.cert,
        f.cap_hb,
        f.cap_tb,
        f.heartbleed,
        f.ticketbleed,
        f.poodle,
        segs,
    )
}

/// Каждый кейс: записи как C на целом потоке в каждой нарезке; действия как C целиком.
#[test]
fn tls_golden_matches_c() {
    let dir = Path::new(DIR);
    let cases = cases();
    assert_eq!(cases.len(), CASES);
    for c in &cases {
        let stream: Vec<u8> = c.segments.concat();
        let out_text = String::from_utf8(read(&dir.join(&c.output))).expect("output utf8");
        let (want_records, want_actions) = whole_run(&out_text, &stream);

        let whole = run(&c.flags, &[&stream]);
        assert_eq!(whole.records, want_records, "{}: whole records", c.name);
        assert_eq!(whole.actions, want_actions, "{}: whole actions", c.name);

        let bytewise: Vec<&[u8]> = stream.chunks(1).collect();
        assert_eq!(
            run(&c.flags, &bytewise).records,
            want_records,
            "{}: bytewise",
            c.name
        );
        let given: Vec<&[u8]> = c.segments.iter().map(Vec::as_slice).collect();
        assert_eq!(
            run(&c.flags, &given).records,
            want_records,
            "{}: given",
            c.name
        );
        let mut rng = Rng(0x51_5A ^ stream.len() as u64);
        for k in 0..8 {
            let mut splits: Vec<&[u8]> = Vec::new();
            let mut at = 0;
            while at < stream.len() {
                let n = 1 + (rng.next() % 131) as usize;
                let end = (at + n).min(stream.len());
                splits.push(&stream[at..end]);
                at = end;
            }
            assert_eq!(
                run(&c.flags, &splits).records,
                want_records,
                "{}: split {k}",
                c.name
            );
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

/// Зонд heartbleed уходит ровно один раз на ServerHello и байтами C (`src/proto-ssl.c:584-587`).
#[test]
fn heartbleed_probe_sent_once_on_server_hello() {
    let f = Flags {
        heartbleed: true,
        ..Flags::default()
    };
    // Одна запись ServerHello целиком строится из кейса heartbleed-probe.
    let c = cases()
        .into_iter()
        .find(|c| c.name == "heartbleed-probe")
        .expect("case");
    let stream: Vec<u8> = c.segments.concat();
    let r = run(&f, &[&stream]);
    assert_eq!(
        r.actions,
        [StreamAction::Send(
            b"\x15\x03\x02\x00\x02\x01\x80\x18\x03\x02\x00\x03\x01\x40\x00".to_vec()
        )]
    );
}

/// Без флага захвата записей сертификатов нет, а имена листа всё равно разбираются.
#[test]
fn cert_capture_off_by_flag() {
    let c = cases()
        .into_iter()
        .find(|c| c.name == "case3-nocapture")
        .expect("case");
    let stream: Vec<u8> = c.segments.concat();
    let r = run(&c.flags, &[&stream]);
    assert!(r.records.iter().all(|(app, _)| *app == 9));
    assert!(
        String::from_utf8_lossy(&r.records[0].1)
            .starts_with("TLS/1.0 cipher:0x88, ubuntu.localdomain")
    );
}

/// Мутации потоков кейсов: ни паники, записи ограничены пределом Р5, результат не зависит от нарезки.
#[test]
fn tls_never_panics() {
    let mut streams: Vec<Vec<u8>> = cases()
        .iter()
        .filter(|c| c.name.starts_with("case"))
        .map(|c| c.segments.concat())
        .collect();
    assert!(!streams.is_empty());
    let mut rng = Rng(0x7E57_1E57_0000_0001);
    for round in 0..300 {
        let mut stream = streams[(rng.next() as usize) % streams.len()].clone();
        match round % 3 {
            0 => {
                for _ in 0..1 + rng.next() % 16 {
                    let at = (rng.next() as usize) % stream.len().max(1);
                    if let Some(b) = stream.get_mut(at) {
                        *b = rng.next() as u8;
                    }
                }
            }
            1 => stream.truncate((rng.next() as usize) % (stream.len() + 1)),
            _ => {
                stream = (0..(rng.next() % 400) as usize)
                    .map(|_| rng.next() as u8)
                    .collect();
            }
        }
        let f = Flags {
            cert: rng.next() & 1 == 0,
            cap_hb: rng.next() & 1 == 0,
            cap_tb: rng.next() & 1 == 0,
            heartbleed: rng.next() & 1 == 0,
            ticketbleed: rng.next() & 1 == 0,
            poodle: rng.next() & 1 == 0,
        };
        let whole = run(&f, &[&stream]);
        for (_, bytes) in &whole.records {
            assert!(bytes.len() <= rmasscan_proto::MAX_BANNER_BYTES);
            assert!(!bytes.is_empty());
        }
        let mut splits: Vec<&[u8]> = Vec::new();
        let mut at = 0;
        while at < stream.len() {
            let n = 1 + (rng.next() % 57) as usize;
            let end = (at + n).min(stream.len());
            splits.push(&stream[at..end]);
            at = end;
        }
        assert_eq!(run(&f, &splits).records, whole.records, "round {round}");
        let _ = &mut streams;
    }
}

/// Список сертификатов короче длины первого сертификата: C на этом входе зависает в `parse_server_cert`
/// (кусок длины 0 без продвижения индекса; оракул подтвердил hang на обоих прогонах). Исправление класса E1
/// (справка §F): байт за исчерпанным списком потребляется, разбор завершается; частичный захват первых
/// байтов сертификата остаётся, как у C до зависания.
#[test]
fn cert_list_shorter_than_cert_terminates() {
    fn rec(t: u8, p: &[u8]) -> Vec<u8> {
        let mut v = vec![t, 3, 3];
        v.extend_from_slice(&(p.len() as u16).to_be_bytes());
        v.extend_from_slice(p);
        v
    }
    fn hs(t: u8, b: &[u8]) -> Vec<u8> {
        let mut v = vec![t];
        v.extend_from_slice(&(b.len() as u32).to_be_bytes()[1..]);
        v.extend_from_slice(b);
        v
    }
    let mut hello = vec![3u8, 3];
    hello.extend(0u8..32);
    hello.extend_from_slice(&[0, 0xc0, 0x2f, 0]);
    let mut certs = (10u32).to_be_bytes()[1..].to_vec();
    certs.extend_from_slice(&(100u32).to_be_bytes()[1..]);
    certs.extend_from_slice(&[0u8; 120]);
    let stream = [rec(22, &hs(2, &hello)), rec(22, &hs(11, &certs))].concat();
    let r = tls_stream(true, false, false, false, false, false, &[&stream]);
    assert_eq!(
        r.records.iter().map(|(a, _)| *a).collect::<Vec<_>>(),
        [9, 15]
    );
    // By byte: the same, and it terminates (the regression this pins).
    let segs: Vec<&[u8]> = stream.chunks(1).collect();
    let r2 = tls_stream(true, false, false, false, false, false, &segs);
    assert_eq!(r2.records, r.records);
}
