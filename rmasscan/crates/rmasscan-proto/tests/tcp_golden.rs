//! Паритет каркаса баннеров TCP и парсеров задач 9-12 с C (AGPL-3.0, подэтап 4b, задачи 8-12). Каждый
//! кейс `tests/golden/tcp-banners` это поток сервера одного соединения и вывод C-оракула `tcp-oracle` (вне
//! репозитория, Р14): настоящий `banner1_parse` masscan © Robert David Graham (HEAD 8e6b3b0,
//! `src/proto-banner1.c:113-325`) с `banner1_create`, `banout` и парсерами C, `tcpapi_*` записывают действия (README
//! эталонов). Эталон это прогон C на целом потоке (`run whole`,
//! Р13); прогоны C по байту и по заданным сегментам хранятся как свидетельство зависимостей C от нарезки (справка
//! E2).
//!
//! [`banner_stream`] прогоняется на каждом кейсе целиком, по байту, по заданным сегментам и в 8 случайных нарезках, и
//! сравнивается с C по виду ожидания кейса ([`Expect`]):
//! - `records`: записи в порядке C (каждая запись C обрезана до 65 536 байт, Р5) и `app_proto` в каждой нарезке,
//!   действия только целиком;
//! - `declared-4b`: именованное правило и `app_proto` C: `unknown-stream` (весь поток одной записью `unknown`,
//!   без действий) или `starttls-tls` (после согласия на STARTTLS — ClientHello и TLS-парсер; эталон — прогон C
//!   по заданным сегментам, [`starttls_expect`]).
//!
//! Входы строит `tcp_golden/inputs.rs`; закоммиченные `cases/*.in.txt` обязаны с ним совпадать. С переменной
//! `RMASSCAN_TCP_BANNERS_INPUTS=DIR` тест [`inputs_match_generator`] вместо сверки пишет `DIR/cases/*.in.txt` и
//! `DIR/cases.tsv` для оракула.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use rmasscan_proto::{
    MAX_BANNER_BYTES, StreamAction, StreamResult, TcpBannerSettings, app_id, banner_stream,
};

#[path = "tcp_golden/inputs.rs"]
mod inputs;

use inputs::{Case, Expect, STARTTLS_TLS, UNKNOWN_STREAM, cases};

// Манифест эталонов проверяется общим кодом rmasscan-core (без serde): сумма файла, `golden.rs` берёт `super::sha256`.
#[path = "../../rmasscan-core/tests/common/sha256.rs"]
mod sha256;

#[path = "../../rmasscan-core/tests/common/golden.rs"]
mod golden;

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/tcp-banners"
);
const ORACLE_GIT_HEAD: &str = "8e6b3b0c07a81e8ea61d557c06134a21a6881614";

/// Число кейсов по видам ожидания: `records`, `declared-4b`.
const COUNTS: (usize, usize) = (219, 10);

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// --- вывод оракула ---

/// Один прогон C: `app_proto` после всех вызовов, действия `tcpapi_*` по порядку, записи `banner_flush`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CRun {
    app_proto: u16,
    actions: Vec<StreamAction>,
    records: Vec<(u16, Vec<u8>)>,
}

#[derive(Debug)]
struct COut {
    whole: CRun,
    bytewise: CRun,
    given: Option<CRun>,
}

/// `BYTES` вывода оракула: `-`, `=stream` (первые `len` байт потока) или байты в кавычках с `\xNN`.
fn parse_bytes(tok: &str, len: usize, stream: &[u8]) -> Vec<u8> {
    if tok == "-" {
        assert_eq!(len, 0, "{tok}");
        return Vec::new();
    }
    if tok == "=stream" {
        return stream.get(..len).expect("=stream past the stream").to_vec();
    }
    let body = tok
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .unwrap_or_else(|| panic!("bad bytes {tok}"));
    let b = body.as_bytes();
    let mut out = Vec::with_capacity(len);
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            assert_eq!(b.get(i + 1), Some(&b'x'), "{tok}");
            let h = std::str::from_utf8(&b[i + 2..i + 4]).expect("hex");
            out.push(u8::from_str_radix(h, 16).expect("hex"));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    assert_eq!(out.len(), len, "{tok}");
    out
}

/// Первые `n` слов строки через пробел и остаток.
fn words(line: &str, n: usize) -> (Vec<&str>, &str) {
    let mut rest = line;
    let mut out = Vec::new();
    for _ in 0..n {
        let (w, r) = rest.split_once(' ').unwrap_or((rest, ""));
        out.push(w);
        rest = r;
    }
    (out, rest)
}

fn parse_run<'a>(lines: &mut impl Iterator<Item = &'a str>, stream: &[u8]) -> CRun {
    let mut run = CRun {
        app_proto: u16::MAX,
        actions: Vec::new(),
        records: Vec::new(),
    };
    for line in lines.by_ref() {
        if line == "end" {
            assert_ne!(run.app_proto, u16::MAX, "run without app_proto");
            return run;
        }
        assert!(
            !line.starts_with("hang") && !line.starts_with("crash"),
            "C did not return: {line}"
        );
        if let Some(v) = line.strip_prefix("app_proto ") {
            run.app_proto = v.parse().expect("app_proto");
        } else if line == "action close" {
            run.actions.push(StreamAction::Close);
        } else if line.starts_with("action send ") {
            let (w, rest) = words(line, 4);
            let len: usize = w[3].parse().expect("len");
            run.actions
                .push(StreamAction::Send(parse_bytes(rest, len, stream)));
        } else if line.starts_with("record ") {
            let (w, rest) = words(line, 3);
            let app: u16 = w[1].parse().expect("app");
            let len: usize = w[2].parse().expect("len");
            run.records.push((app, parse_bytes(rest, len, stream)));
        } else {
            panic!("unexpected oracle line {line}");
        }
    }
    panic!("run without end");
}

fn parse_out(c: &Case, text: &str) -> COut {
    let stream = c.stream();
    let mut lines = text.lines();
    let head = lines.next().expect("header");
    let want = format!(
        "tcp-oracle v1 port={} capture={} segments={} bytes={}",
        c.port,
        if c.capture_html { "html" } else { "none" },
        c.segments.len(),
        stream.len()
    );
    assert_eq!(head, want, "{}", c.name);
    let (mut whole, mut bytewise, mut given) = (None, None, None);
    while let Some(line) = lines.next() {
        let run = parse_run(&mut lines, &stream);
        match line.split(' ').nth(1) {
            Some("whole") => whole = Some(run),
            Some("bytewise") => bytewise = Some(run),
            Some("given") => given = Some(run),
            _ => panic!("{}: unexpected {line}", c.name),
        }
    }
    assert_eq!(given.is_some(), c.segments.len() > 1, "{}", c.name);
    COut {
        whole: whole.expect("whole run"),
        bytewise: bytewise.expect("bytewise run"),
        given,
    }
}

fn c_out(c: &Case) -> COut {
    let text = String::from_utf8(read(&Path::new(DIR).join(format!("cases/{}.out", c.name))))
        .expect("utf-8");
    parse_out(c, &text)
}

// --- нарезки ---

/// Детерминированный xorshift64*.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).expect("n")).expect("index")
    }
}

/// Нарезки потока: целиком, по байту, заданные сегменты кейса и 8 случайных (seed от имени кейса).
fn splittings(c: &Case) -> Vec<(String, Vec<Vec<u8>>)> {
    let stream = c.stream();
    let mut out = vec![
        ("whole".to_owned(), vec![stream.clone()]),
        (
            "bytewise".to_owned(),
            stream.iter().map(|b| vec![*b]).collect(),
        ),
        ("given".to_owned(), c.segment_bytes()),
    ];
    let seed = c.name.bytes().fold(0x9E37_79B9_7F4A_7C15u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01B3)
    }) | 1;
    let mut rng = Rng(seed);
    for k in 0..8 {
        let mut cuts = BTreeSet::new();
        if stream.len() > 1 {
            let n = 1 + rng.below(stream.len().min(24));
            for _ in 0..n {
                cuts.insert(1 + rng.below(stream.len() - 1));
            }
        }
        let mut segs = Vec::new();
        let mut at = 0;
        for cut in cuts.into_iter().chain([stream.len()]) {
            segs.push(stream[at..cut].to_vec());
            at = cut;
        }
        out.push((format!("random-{k}"), segs));
    }
    out
}

fn run(c: &Case, segs: &[Vec<u8>]) -> StreamResult {
    let s = TcpBannerSettings {
        capture_html: c.capture_html,
        ..TcpBannerSettings::default()
    };
    let refs: Vec<&[u8]> = segs.iter().map(Vec::as_slice).collect();
    banner_stream(&s, c.port, None, &refs)
}

fn capped(records: &[(u16, Vec<u8>)]) -> Vec<(u16, Vec<u8>)> {
    records
        .iter()
        .map(|(app, b)| (*app, b[..b.len().min(MAX_BANNER_BYTES)].to_vec()))
        .collect()
}

fn c_app(r: &CRun) -> Option<u16> {
    (r.app_proto != 0).then_some(r.app_proto)
}

/// Ожидание правила `starttls-tls` (справка §F E2.8'): первый сегмент кейса кончается строкой согласия на
/// STARTTLS. Эталон — прогон C по заданным сегментам (`given`, без хвоста `whole`): после согласия у C там
/// уже TLS. Записи этого прогона целиком и его действия по ClientHello включительно (первая отправка,
/// начинающаяся байтом записи TLS 0x16, `tcpapi_send(banner_ssl.hello)`): у C на целом потоке после hello
/// бывают вторые команды текстового парсера по хвосту того же сегмента, которых по правилу нет.
fn starttls_expect(c: &Case, cout: &COut) -> (Vec<(u16, Vec<u8>)>, Vec<StreamAction>) {
    let segs = c.segment_bytes();
    let run = match segs.len() {
        1 => &cout.whole,
        2 => cout.given.as_ref().expect("given run"),
        n => panic!("{}: {n} segments, want 1 or 2", c.name),
    };
    let tls = |a: &StreamAction| matches!(a, StreamAction::Send(b) if b.first() == Some(&0x16));
    let hello = run
        .actions
        .iter()
        .position(tls)
        .unwrap_or_else(|| panic!("{}: no TLS hello in C's run", c.name));
    (run.records.clone(), run.actions[..=hello].to_vec())
}

/// Записи и `app_proto` rmasscan в каждой нарезке равны C на целом потоке по виду ожидания кейса; действия
/// сравниваются только целиком (Telnet отвечает на каждый сегмент по устройству, справка E2).
#[test]
fn tcp_golden_matches_c() {
    let mut kinds = (0usize, 0usize);
    for c in cases() {
        let cout = c_out(&c);
        let want_app = c_app(&cout.whole);
        let stream = c.stream();
        for (cut, segs) in splittings(&c) {
            let got = run(&c, &segs);
            let at = format!("{} ({cut})", c.name);
            assert_eq!(got.app_proto, want_app, "{at}: app_proto");
            match c.expect {
                Expect::Records => {
                    assert_eq!(got.records, capped(&cout.whole.records), "{at}: records");
                    if cut == "whole" {
                        assert_eq!(got.actions, cout.whole.actions, "{at}: actions");
                    }
                }
                Expect::Declared(UNKNOWN_STREAM) => {
                    assert_eq!(
                        got.records,
                        capped(&[(app_id::HEUR, stream.clone())]),
                        "{at}: declared records"
                    );
                    assert!(got.actions.is_empty(), "{at}: declared actions");
                }
                Expect::Declared(STARTTLS_TLS) => {
                    let (records, actions) = starttls_expect(&c, &cout);
                    assert_eq!(got.records, records, "{at}: declared records");
                    if cut == "whole" {
                        assert_eq!(got.actions, actions, "{at}: declared actions");
                    }
                }
                Expect::Declared(rule) => panic!("{at}: unknown rule {rule}"),
            }
        }
        match c.expect {
            Expect::Records => kinds.0 += 1,
            Expect::Declared(_) => kinds.1 += 1,
        }
    }
    assert_eq!(kinds, COUNTS);
}

/// Свидетельства C, на которые опираются правила неразрезанного потока (справка E2.1, E2.2) и Р5: если оракул их не
/// показывает, правило описывает не то поведение C.
#[test]
fn c_split_evidence_matches_the_reference() {
    let by_name = |name: &str| {
        let c = cases()
            .into_iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("{name}"));
        let out = c_out(&c);
        (c, out)
    };
    // E2.1: совпадение во втором сегменте оставляет у C запись unknown с байтами до него.
    let (_, out) = by_name("http-split-after-2");
    let given = out.given.expect("given run");
    assert_eq!(given.app_proto, app_id::HTTP);
    assert_eq!(given.records.first(), Some(&(app_id::HEUR, b"HT".to_vec())));
    assert!(out.whole.records.iter().all(|r| r.0 != app_id::HEUR));
    assert!(out.bytewise.records.iter().any(|r| r.0 == app_id::HEUR));
    // E2.3: неуспешный статус целиком не записан, а при разрезе C уже записал прошлый сегмент HTTP.
    let (_, out) = by_name("http-failure-given");
    assert!(out.whole.records.is_empty());
    assert_eq!(
        out.given.expect("given failure").records,
        [(app_id::HTTP, b"HTTP/1.".to_vec())]
    );
    // E2.2: после отвергнутого SSL3 C по сегментам находит {" или IAC, целиком нет.
    for (name, later) in [
        ("ssl3-then-mc", app_id::MC),
        ("ssl3-then-iac", app_id::TELNET),
    ] {
        let (_, out) = by_name(name);
        assert_eq!(out.whole.app_proto, 0, "{name}");
        assert_eq!(out.given.expect("given").app_proto, later, "{name}");
    }
    // Р5: у C предела записи нет.
    let (c, out) = by_name("no-match-70000");
    assert_eq!(out.whole.records, [(app_id::HEUR, c.stream())]);
    assert_eq!(c.stream().len(), 70_000);
    // Правило `starttls-tls`: после согласия на STARTTLS C ведёт остаток того же сегмента текстовым парсером с
    // состояния 0 (`src/proto-ftp.c:101`, `src/proto-smtp.c:147`, `src/proto-pop3.c:129`, цикл продолжается), так что
    // хвост целиком это новое приветствие со второй командой, а по сегментам он уходит в TLS. Справка E2 считает FTP,
    // SMTP и POP3 независимыми от нарезки; правило 4c (E2.8') ведёт остаток в TLS в любой нарезке.
    for (name, cmd) in [
        ("ftp-auth-234-dash-25-tail", &b"AUTH TLS\r\n"[..]),
        ("smtp-starttls-220-tail", b"EHLO masscan\r\n"),
        ("pop3-stls-ok-tail", b"CAPA\r\n"),
    ] {
        let (_, out) = by_name(name);
        let sent = |r: &CRun| {
            r.actions
                .iter()
                .filter(|a| **a == StreamAction::Send(cmd.to_vec()))
                .count()
        };
        assert_eq!(out.whole.app_proto, app_id::SSL3, "{name}");
        assert_eq!(sent(&out.whole), 2, "{name}: whole");
        assert_eq!(sent(out.given.as_ref().expect("given")), 1, "{name}: given");
        assert_eq!(sent(&out.bytewise), 1, "{name}: bytewise");
    }
    // E2.4: после байта остановки SSH C целиком дописывает ровно один байт, а по сегментам ещё первый байт
    // каждого следующего (здесь по байту, поэтому весь поток).
    let (c, out) = by_name("ssh-ident-nul");
    assert_eq!(
        out.whole.records,
        [(app_id::SSH2, c.stream()[..11].to_vec())]
    );
    assert!(
        out.bytewise.records.contains(&(app_id::SSH2, c.stream())),
        "ssh-ident-nul bytewise"
    );
    // E2.5: UNKNOWN у RDP дописывает у C текущий сегмент с его начала: в заданной нарезке только хвост второго
    // сегмента, целиком весь поток.
    let (c, out) = by_name("rdp-second-non3");
    assert!(
        out.whole.records.contains(&(app_id::HEUR, c.stream())),
        "rdp-second-non3 whole"
    );
    assert!(
        out.given
            .expect("given run")
            .records
            .contains(&(app_id::HEUR, b"Xtail".to_vec())),
        "rdp-second-non3 given"
    );
    // E2.9: RFB_DONE у C закрывает на первом байте каждого следующего сегмента; записи от нарезки не зависят.
    let (_, out) = by_name("vnc38-error-lowbyte");
    let closes = |r: &CRun| {
        r.actions
            .iter()
            .filter(|a| **a == StreamAction::Close)
            .count()
    };
    assert_eq!(closes(&out.whole), 2, "vnc38-error-lowbyte whole");
    assert_eq!(closes(&out.bytewise), 4, "vnc38-error-lowbyte bytewise");
    assert!(
        out.bytewise
            .records
            .contains(&(app_id::VNC_INFO, b"ERROR: bad".to_vec())),
        "vnc38-error-lowbyte bytewise records"
    );
    // E2.6: у C ключевое слово команды, разрезанное границей сегментов, теряется (состояние 0 сбрасывает smack):
    // в заданной нарезке записи нет, целиком есть.
    let (_, out) = by_name("memcached-split-keyword");
    assert_eq!(
        out.whole.records,
        [(app_id::MEMCACHED, b"uptime=5 ".to_vec())]
    );
    assert!(out.given.expect("given run").records.is_empty());
    // E2.7: у C по сегментам Minecraft дописывает только сегмент, на котором счётчик скобок опустился до нуля;
    // целиком запись это весь поток.
    let (c, out) = by_name("mc-favicon");
    assert_eq!(out.whole.records, [(app_id::MC, c.stream())]);
    assert_eq!(
        out.given.expect("given run").records,
        [(app_id::MC, c.segment_bytes()[1].clone())]
    );
}

#[test]
fn inputs_match_generator() {
    let all = cases();
    if let Some(dir) = std::env::var_os("RMASSCAN_TCP_BANNERS_INPUTS") {
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
                c.expect.name(),
                c.expect.declared(),
                c.about
            );
        }
        fs::write(dir.join("cases.tsv"), tsv).expect("write tsv");
        return;
    }
    let manifest = String::from_utf8(read(&Path::new(DIR).join("manifest.json"))).expect("utf-8");
    assert!(manifest.contains(&format!("\"masscan_git_head\": \"{ORACLE_GIT_HEAD}\"")));
    // Сборка C с AddressSanitizer дала тот же вывод без отчётов на каждом кейсе и каждой таблице (README эталонов).
    assert_eq!(
        manifest
            .matches("\"asan\": {\"same_output\": true, \"reports\": 0}")
            .count(),
        all.len() + 3
    );
    assert_eq!(manifest.matches("\"asan\": {").count(), all.len() + 3);
    let mut names = BTreeSet::new();
    for c in &all {
        assert!(names.insert(c.name.clone()), "duplicate case {}", c.name);
        assert!(!c.about.contains(['"', '\\', '\t', '\n']), "{}", c.name);
        assert!(
            c.segments.iter().all(|s| !s.bytes().is_empty()),
            "{}",
            c.name
        );
        let file = read(&Path::new(DIR).join(format!("cases/{}.in.txt", c.name)));
        assert!(
            file == c.input().into_bytes(),
            "{}.in.txt drifted from the generator",
            c.name
        );
        // Манифест называет кейс с его видом ожидания и правилом.
        let block = manifest
            .split_once(&format!("\"name\": \"{}\"", c.name))
            .unwrap_or_else(|| panic!("{} missing from manifest.json", c.name))
            .1;
        let block = block.split("\"name\": ").next().unwrap_or(block);
        assert!(
            block.contains(&format!("\"expect\": \"{}\"", c.expect.name())),
            "{}: expect in manifest.json",
            c.name
        );
        assert!(
            block.contains(&format!("\"declared\": \"{}\"", c.expect.declared())),
            "{}: declared in manifest.json",
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
}

#[test]
fn manifest_hashes_match_files() {
    let manifest = String::from_utf8(read(&Path::new(DIR).join("manifest.json"))).expect("utf-8");
    let n =
        golden::check_manifest_hashes(Path::new(DIR), &manifest).unwrap_or_else(|e| panic!("{e}"));
    // Вход и вывод каждого кейса, вход и вывод сценариев banout, таблицы шаблонов и hello.
    assert_eq!(n, 2 * cases().len() + 2 + 2 + 2 * 27);
}
