//! Офлайн-паритет форматов вывода с C (AGPL-3.0), проект §6.1. Каждый кейс `tests/golden/formats/manifest.json` это
//! прогон `--readscan` C-оракула masscan © Robert David Graham (HEAD 8e6b3b0, `scripts/build-format-goldens.sh`);
//! здесь тот же argv идёт через [`rmasscan_cli::run`] в процессе с fake-бэкендом: имена сервисов из закоммиченного
//! `services.txt` (`getent services` хоста оракула), смещение UTC 0, часы стенки постоянны. Байты файла вывода равны
//! эталону после масок манифеста (поля, которые C берёт из часов при записи: XML `start`, `finished`
//! `time`/`timestr`/`elapsed`, `# Masscan done at …` grepable); stdout и stderr равны дословно (путь входа заменён на
//! `@INPUT@`). Кейсы `many` (входы и выходы больше `store_max_bytes`) сверяются по sha256 после масок: вход строится
//! тем же генератором `examples/format_inputs.rs`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmasscan_cli::args::Cli;
use rmasscan_cli::live::Backend;
use rmasscan_cli::output::{ServiceNames, Wall};
use rmasscan_cli::run;
use rmasscan_core::probe::AdapterBinding;
use rmasscan_core::throttle::Clock;
use rmasscan_engine::AdapterPair;
use rmasscan_net::arp_resolve::ArpPolicy;
use rmasscan_net::{Interfaces, NetError, RouteTable};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[path = "common/scratch.rs"]
mod scratch;

use scratch::Scratch;

#[path = "../examples/format_inputs.rs"]
#[allow(dead_code)]
mod format_inputs;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/formats");
/// Часы стенки fake-бэкенда: время открытия файла, заголовка XML и подвалов (маскируется).
const WALL: u64 = 1_800_000_000;
const ORACLE_GIT_HEAD: &str = "8e6b3b0c07a81e8ea61d557c06134a21a6881614";
const ORACLE_SHA256: &str = "8afc8ec81f2e051389116908b01a4482b42e020bc48254585b7dcca4b25e2a3e";
/// Кейсы, которые сознательно не сверяются: (имя кейса, решение проекта и причина). Каждый пропуск печатается.
const SKIPS: &[(&str, &str)] = &[];

#[derive(Deserialize)]
struct Manifest {
    oracle: Oracle,
    inputs: Vec<Input>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Oracle {
    git_head: String,
    binary_sha256: String,
}

#[derive(Deserialize)]
struct Input {
    name: String,
    sha256: String,
    stored: bool,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    input: String,
    args: Vec<String>,
    /// `None`: выход не хранится (вход больше `store_max_bytes`), сверка по `masked_sha256`.
    output: Option<String>,
    sha256: String,
    masked_sha256: String,
    masks: Vec<Mask>,
    stdout: String,
    stderr: String,
}

#[derive(Deserialize)]
struct Mask {
    kind: String,
}

fn manifest() -> Manifest {
    let text = fs::read_to_string(format!("{DIR}/manifest.json")).expect("manifest.json");
    serde_json::from_str(&text).expect("manifest.json parses")
}

fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// `--readscan` не трогает ОС: всё, кроме часов и имён сервисов, паникует.
struct ReadscanOnly {
    services: ServiceNames,
}

impl Wall for ReadscanOnly {
    fn unix_time(&self) -> u64 {
        WALL
    }
    fn utc_offset_secs(&self, _: u64) -> i32 {
        0
    }
}

impl Backend for ReadscanOnly {
    fn routes(&self) -> Result<Box<dyn RouteTable>, NetError> {
        panic!("--readscan never reads the route table")
    }
    fn interfaces(&self) -> Result<Box<dyn Interfaces>, NetError> {
        panic!("--readscan never lists interfaces")
    }
    fn open(&self, _: &AdapterBinding) -> Result<AdapterPair, NetError> {
        panic!("--readscan never opens an adapter")
    }
    fn entropy64(&self) -> u64 {
        panic!("--readscan needs no entropy")
    }
    fn arp_policy(&self) -> ArpPolicy {
        panic!("--readscan never resolves ARP")
    }
    fn clock(&self) -> Arc<dyn Clock + Send + Sync> {
        panic!("--readscan needs no engine clock")
    }
    fn services(&self) -> ServiceNames {
        self.services.clone()
    }
    fn interrupts(&self) -> u32 {
        panic!("--readscan never traps Ctrl-C")
    }
    fn write_paused_conf(&self, _: &str) -> Result<(), String> {
        panic!("--readscan never writes paused.conf")
    }
}

/// Часть шаблона маски: `Lit` остаётся, остальное заменяется на `*`. Те же правила, что выражения `sed -E` в
/// `mask_args` скрипта съёмки; шаблон привязан к началу строки, хвост строки остаётся.
enum Part {
    Lit(&'static [u8]),
    /// `[0-9]+`
    Digits,
    /// `[^"]*`
    NotQuote,
    /// `.*$`: всё до `\n`.
    Rest,
}

fn mask_pattern(kind: &str) -> &'static [Part] {
    use Part::*;
    match kind {
        "xml_start" => &[
            Lit(b"<nmaprun scanner=\"masscan\" start=\""),
            Digits,
            Lit(b"\""),
        ],
        "xml_finished" => &[
            Lit(b"<finished time=\""),
            Digits,
            Lit(b"\" timestr=\""),
            NotQuote,
            Lit(b"\" elapsed=\""),
            Digits,
            Lit(b"\""),
        ],
        "grepable_done" => &[Lit(b"# Masscan done at "), Rest],
        other => panic!("unknown mask kind {other}"),
    }
}

/// Строка с маской или `None`, если шаблон не совпал.
fn mask_line(pattern: &[Part], line: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(line.len());
    let mut i = 0;
    for part in pattern {
        let rest = &line[i..];
        let n = match part {
            Part::Lit(s) => {
                if !rest.starts_with(s) {
                    return None;
                }
                out.extend_from_slice(s);
                i += s.len();
                continue;
            }
            Part::Digits => rest.iter().take_while(|b| b.is_ascii_digit()).count(),
            Part::NotQuote => rest.iter().take_while(|&&b| b != b'"').count(),
            Part::Rest => rest.iter().take_while(|&&b| b != b'\n').count(),
        };
        if matches!(part, Part::Digits) && n == 0 {
            return None;
        }
        out.push(b'*');
        i += n;
    }
    out.extend_from_slice(&line[i..]);
    Some(out)
}

/// Маски манифеста по строкам; каждая обязана сработать ровно на одной строке.
fn apply_masks(bytes: &[u8], masks: &[Mask]) -> Result<Vec<u8>, String> {
    let patterns: Vec<&[Part]> = masks.iter().map(|m| mask_pattern(&m.kind)).collect();
    let mut hits = vec![0usize; masks.len()];
    let mut out = Vec::with_capacity(bytes.len());
    for line in bytes.split_inclusive(|&b| b == b'\n') {
        let mut line = line.to_vec();
        for (p, hit) in patterns.iter().zip(&mut hits) {
            if let Some(masked) = mask_line(p, &line) {
                line = masked;
                *hit += 1;
            }
        }
        out.extend_from_slice(&line);
    }
    for (m, n) in masks.iter().zip(hits) {
        if n != 1 {
            return Err(format!("mask {} hits {n} lines, want 1", m.kind));
        }
    }
    Ok(out)
}

/// Первая различающаяся строка, для сообщения об ошибке.
fn first_difference(got: &[u8], want: &[u8]) -> String {
    let g: Vec<&[u8]> = got.split_inclusive(|&b| b == b'\n').collect();
    let w: Vec<&[u8]> = want.split_inclusive(|&b| b == b'\n').collect();
    let i = g.iter().zip(&w).take_while(|(a, b)| a == b).count();
    let show = |l: Option<&&[u8]>| {
        l.map_or("<end of file>".into(), |l| {
            format!("{:?}", String::from_utf8_lossy(l))
        })
    };
    format!(
        "line {}: rmasscan {} vs C {}",
        i + 1,
        show(g.get(i)),
        show(w.get(i))
    )
}

/// Один кейс: тот же argv через `run`, сверка выхода (после масок), stdout и stderr.
fn check_case(
    case: &Case,
    input: &Path,
    backend: &ReadscanOnly,
    scratch: &Path,
) -> Result<(), String> {
    let input = input.to_str().expect("UTF-8 input path");
    let out_path = scratch.join(format!("{}.out", case.name));
    let out = out_path.to_str().expect("UTF-8 output path");
    let mut argv = vec!["rmasscan".to_string()];
    argv.extend(
        case.args
            .iter()
            .map(|a| a.replace("@INPUT@", input).replace("@OUTPUT@", out)),
    );
    let cli = Cli::try_parse_masscan(argv).map_err(|e| format!("parse: {e}"))?;
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    run(&cli, backend, &mut stdout, &mut stderr).map_err(|e| format!("run: {e}"))?;
    let stdout = String::from_utf8_lossy(&stdout).replace(input, "@INPUT@");
    let stderr = String::from_utf8_lossy(&stderr)
        .replace(input, "@INPUT@")
        .replace(out, "@OUTPUT@");
    if stdout != case.stdout {
        return Err(format!("stdout {stdout:?}, C {:?}", case.stdout));
    }
    if stderr != case.stderr {
        return Err(format!("stderr {stderr:?}, C {:?}", case.stderr));
    }
    let got = fs::read(&out_path).map_err(|e| format!("{out}: {e}"))?;
    let got = apply_masks(&got, &case.masks).map_err(|e| format!("rmasscan output: {e}"))?;
    match &case.output {
        Some(rel) => {
            let want = fs::read(format!("{DIR}/{rel}")).map_err(|e| format!("{rel}: {e}"))?;
            assert_eq!(sha256_hex(&want), case.sha256, "{rel}: golden file changed");
            let want = apply_masks(&want, &case.masks).map_err(|e| format!("{rel}: {e}"))?;
            assert_eq!(
                sha256_hex(&want),
                case.masked_sha256,
                "{rel}: the Rust masks disagree with the sed masks of the capture script"
            );
            if got != want {
                return Err(first_difference(&got, &want));
            }
        }
        None => {
            let h = sha256_hex(&got);
            if h != case.masked_sha256 {
                return Err(format!(
                    "masked sha256 {h}, C {} ({} bytes from rmasscan)",
                    case.masked_sha256,
                    got.len()
                ));
            }
        }
    }
    Ok(())
}

/// Итог сверки одного входа.
#[derive(Default)]
struct Tally {
    checked: usize,
    skipped: usize,
    failures: Vec<String>,
}

/// Все кейсы одного входа; пропуски только по [`SKIPS`], каждый печатается.
fn check_input(m: &Manifest, input: &Input, tally: &mut Tally) {
    let scratch = Scratch::new();
    let path = if input.stored {
        PathBuf::from(format!("{DIR}/inputs/{}", input.name))
    } else {
        let (_, bytes) = format_inputs::inputs()
            .into_iter()
            .find(|(n, _)| *n == input.name)
            .unwrap_or_else(|| panic!("the generator does not make {}", input.name));
        assert_eq!(
            sha256_hex(&bytes),
            input.sha256,
            "{}: generator drifted",
            input.name
        );
        let p = scratch.path(&input.name);
        fs::write(&p, bytes).expect("write generated input");
        p
    };
    let services = fs::read_to_string(format!("{DIR}/services.txt")).expect("services.txt");
    let backend = ReadscanOnly {
        services: ServiceNames::parse(&services),
    };
    for c in m.cases.iter().filter(|c| c.input == input.name) {
        if let Some((_, why)) = SKIPS.iter().find(|(n, _)| *n == c.name) {
            eprintln!("SKIP {}: {why}", c.name);
            tally.skipped += 1;
            continue;
        }
        match check_case(c, &path, &backend, scratch.dir()) {
            Ok(()) => tally.checked += 1,
            Err(e) => tally.failures.push(format!("{}: {e}", c.name)),
        }
    }
}

/// Каждый кейс манифеста сверен с C: число сверенных кейсов равно числу кейсов манифеста за вычетом названных
/// пропусков [`SKIPS`].
#[test]
fn every_golden_case_is_checked() {
    let m = manifest();
    let mut tally = Tally::default();
    for input in &m.inputs {
        check_input(&m, input, &mut tally);
    }
    assert!(
        tally.failures.is_empty(),
        "{} of {} cases differ from C:\n{}",
        tally.failures.len(),
        m.cases.len(),
        tally.failures.join("\n")
    );
    assert_eq!(tally.skipped, SKIPS.len());
    assert_eq!(tally.checked + tally.skipped, m.cases.len());
}

/// Закоммиченные входы это ровно вывод генератора, и C читал именно их (sha256 манифеста); вход, выходы которого
/// не хранятся, не коммитится.
#[test]
fn inputs_are_the_generator_output() {
    let m = manifest();
    let generated = format_inputs::inputs();
    assert_eq!(generated.len(), m.inputs.len());
    for (name, bytes) in &generated {
        let meta = m
            .inputs
            .iter()
            .find(|i| i.name == *name)
            .unwrap_or_else(|| panic!("{name} is not in the manifest"));
        assert_eq!(sha256_hex(bytes), meta.sha256, "{name}");
        let committed = fs::read(format!("{DIR}/inputs/{name}"));
        if meta.stored {
            assert_eq!(&committed.expect(name), bytes, "{name}");
        } else {
            assert!(committed.is_err(), "{name} must not be committed");
        }
    }
}

/// Манифест снят с закреплённого оракула и содержит всю матрицу скрипта: 4 входа × 2 режима `--show` ×
/// (8 форматов + `-oX --webxml`) и 2 кейса фильтра; имена уникальны, пропуски называют существующие кейсы, у
/// хранимых входов есть файл эталона, у остальных его нет.
#[test]
fn manifest_covers_the_capture_matrix() {
    let m = manifest();
    assert_eq!(m.oracle.git_head, ORACLE_GIT_HEAD);
    assert_eq!(m.oracle.binary_sha256, ORACLE_SHA256);
    assert_eq!(m.inputs.len(), 4);
    assert_eq!(m.cases.len(), 4 * 2 * 9 + 2);
    let mut names: Vec<&str> = m.cases.iter().map(|c| c.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), m.cases.len(), "case names are unique");
    for (skip, _) in SKIPS {
        assert!(names.contains(skip), "SKIPS names an unknown case {skip}");
    }
    for c in &m.cases {
        let input = m
            .inputs
            .iter()
            .find(|i| i.name == c.input)
            .unwrap_or_else(|| panic!("{}: input {} is not in the manifest", c.name, c.input));
        assert_eq!(c.output.is_some(), input.stored, "{}", c.name);
        if let Some(rel) = &c.output {
            assert!(Path::new(&format!("{DIR}/{rel}")).is_file(), "{rel}");
        }
        assert!(c.args.iter().any(|a| a == "@INPUT@"), "{}", c.name);
        assert!(c.args.iter().any(|a| a == "@OUTPUT@"), "{}", c.name);
    }
}
