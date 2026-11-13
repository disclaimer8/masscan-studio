//! Офлайн-паритет форматов вывода с C (AGPL-3.0), проект §6.1. Каждый кейс `tests/golden/formats/manifest.json` это
//! прогон `--readscan` C-оракула masscan © Robert David Graham (HEAD 8e6b3b0, `scripts/build-format-goldens.sh`);
//! здесь тот же argv идёт через [`rmasscan_cli::run`] в процессе с fake-бэкендом: имена сервисов из закоммиченного
//! `services.txt` (`getent services` хоста оракула, `/tcp` и `/udp`) и `protocols.txt` (`getent protocols`: имя сервиса
//! ICMP и SCTP в `-oG`), смещение UTC 0, часы стенки постоянны. Байты файла вывода равны эталону после масок
//! манифеста (поля, которые C берёт из часов при записи: XML `start`, `finished` `time`/`timestr`/`elapsed`,
//! `# Masscan done at …` grepable); stdout и stderr равны дословно (путь входа заменён на `@INPUT@`). Кейсы `many`
//! (входы и выходы больше `store_max_bytes`) сверяются по sha256 после масок: вход строится тем же генератором
//! `examples/format_inputs.rs`. У кейсов с баннерами certs и формата по умолчанию stdout C лежит файлом
//! (`stdout_output`: сырые байты PEM или длинные строки `Banner on port`) и сверяется побайтно; у формата по умолчанию
//! файла вывода нет вовсе (в `args` нет `@OUTPUT@`).

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
    /// `None`: выход не хранится (вход больше `store_max_bytes`), сверка по `masked_sha256`; или у кейса нет файла
    /// вывода (в `args` нет `@OUTPUT@`).
    output: Option<String>,
    /// `None` только у кейса без `@OUTPUT@`.
    sha256: Option<String>,
    masked_sha256: Option<String>,
    masks: Vec<Mask>,
    /// stdout C строкой; `None`, когда он лежит файлом [`Case::stdout_output`].
    stdout: Option<String>,
    /// stdout C файлом (байты как есть) и его sha256.
    #[serde(default)]
    stdout_output: Option<String>,
    #[serde(default)]
    stdout_sha256: Option<String>,
    stderr: String,
}

impl Case {
    fn has_output_file(&self) -> bool {
        self.args.iter().any(|a| a == "@OUTPUT@")
    }
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
    match (&case.stdout, &case.stdout_output) {
        (Some(want), None) => {
            let got = String::from_utf8_lossy(&stdout).replace(input, "@INPUT@");
            if got != *want {
                return Err(format!("stdout {got:?}, C {want:?}"));
            }
        }
        (None, Some(rel)) => {
            let want = fs::read(format!("{DIR}/{rel}")).map_err(|e| format!("{rel}: {e}"))?;
            assert_eq!(
                Some(sha256_hex(&want)),
                case.stdout_sha256,
                "{rel}: golden file changed"
            );
            if stdout != want {
                return Err(format!("stdout: {}", first_difference(&stdout, &want)));
            }
        }
        _ => panic!("{}: exactly one of stdout and stdout_output", case.name),
    }
    let stderr = String::from_utf8_lossy(&stderr)
        .replace(input, "@INPUT@")
        .replace(out, "@OUTPUT@");
    if stderr != case.stderr {
        return Err(format!("stderr {stderr:?}, C {:?}", case.stderr));
    }
    if !case.has_output_file() {
        // Формат по умолчанию: C файла не открывает (`src/output.c:479`), rmasscan пути не получил.
        return Ok(());
    }
    let sha = case.sha256.as_deref().expect("sha256 of a file case");
    let masked_sha = case
        .masked_sha256
        .as_deref()
        .expect("masked_sha256 of a file case");
    let got = fs::read(&out_path).map_err(|e| format!("{out}: {e}"))?;
    let got = apply_masks(&got, &case.masks).map_err(|e| format!("rmasscan output: {e}"))?;
    match &case.output {
        Some(rel) => {
            let want = fs::read(format!("{DIR}/{rel}")).map_err(|e| format!("{rel}: {e}"))?;
            assert_eq!(sha256_hex(&want), sha, "{rel}: golden file changed");
            let want = apply_masks(&want, &case.masks).map_err(|e| format!("{rel}: {e}"))?;
            assert_eq!(
                sha256_hex(&want),
                masked_sha,
                "{rel}: the Rust masks disagree with the sed masks of the capture script"
            );
            if got != want {
                return Err(first_difference(&got, &want));
            }
        }
        None => {
            let h = sha256_hex(&got);
            if h != masked_sha {
                return Err(format!(
                    "masked sha256 {h}, C {masked_sha} ({} bytes from rmasscan)",
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
    let protocols = fs::read_to_string(format!("{DIR}/protocols.txt")).expect("protocols.txt");
    let backend = ReadscanOnly {
        services: ServiceNames::parse(&services).with_protocols(&protocols),
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

/// Манифест снят с закреплённого оракула и содержит всю матрицу скрипта: 8 входов × 2 режима `--show` ×
/// (8 форматов + `-oX --webxml`), 2 кейса фильтра на `basic` (`--range` и `-p80`), 2 на `protocols` (только
/// `--range`: фильтр `-p` по не-TCP записям это отличие Р5, его эталонов C нет) и 7 на `ipv6` (адресный фильтр
/// со смешанным списком, из одного IPv4, порты и порты со смешанным списком; фильтр из одних диапазонов IPv6 не
/// снят: C его игнорирует, rmasscan фильтрует, R14); на каждом из двух входов с баннерами certs и формат по умолчанию
/// с `--show` и без, 2 × 3 кейса `--banner-types` (`dns-ver`; `ssl` и `http` двумя опциями) на `banners`, фильтр
/// адреса и порта на `banners` (`-oL`, `-oG`) и на `banners-legacy` (`-oL`). Имена уникальны, пропуски называют
/// существующие кейсы, у хранимых входов есть файл эталона, у остальных его нет; у кейса без `@OUTPUT@` нет файла
/// вывода, а stdout лежит файлом.
#[test]
fn manifest_covers_the_capture_matrix() {
    let m = manifest();
    assert_eq!(m.oracle.git_head, ORACLE_GIT_HEAD);
    assert_eq!(m.oracle.binary_sha256, ORACLE_SHA256);
    assert_eq!(m.inputs.len(), 8);
    assert_eq!(m.cases.len(), 8 * 2 * 9 + 2 + 2 + 7 + 2 * 3 + 2 * 3 + 2 + 1);
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
        if c.has_output_file() {
            assert_eq!(c.output.is_some(), input.stored, "{}", c.name);
            assert!(
                c.sha256.is_some() && c.masked_sha256.is_some(),
                "{}",
                c.name
            );
        } else {
            assert!(
                c.output.is_none() && c.sha256.is_none() && c.stdout_output.is_some(),
                "{}",
                c.name
            );
        }
        if let Some(rel) = &c.output {
            assert!(Path::new(&format!("{DIR}/{rel}")).is_file(), "{rel}");
        }
        assert_ne!(c.stdout.is_some(), c.stdout_output.is_some(), "{}", c.name);
        if let Some(rel) = &c.stdout_output {
            assert!(input.stored, "{}", c.name);
            assert!(c.stdout_sha256.is_some(), "{}", c.name);
            assert!(Path::new(&format!("{DIR}/{rel}")).is_file(), "{rel}");
        }
        assert!(c.args.iter().any(|a| a == "@INPUT@"), "{}", c.name);
    }
}

/// Задача 6, Review Focus 5: вход `ipv6` читается C-оракулом и rmasscan одинаково, а кейсы фильтра фиксируют то, чем
/// C делает со смешанным фильтром и фильтром из одного IPv4 (`in-binary.c:254`): фильтр с IPv4 отбрасывает записи IPv6
/// вне своих диапазонов. Фильтр из одних диапазонов IPv6 C игнорирует, здесь он не снят (R14).
/// Сам разбор сверяет `every_golden_case_is_checked`; здесь выписаны ожидаемые строки (снято с оракула).
#[test]
fn ipv6_cases_pin_the_c_filter_semantics() {
    let m = manifest();
    let lines = |name: &str| -> Vec<String> {
        let c = m.cases.iter().find(|c| c.name == name).expect(name);
        let rel = c.output.as_ref().expect("stored output");
        let text = fs::read_to_string(format!("{DIR}/{rel}")).expect(rel);
        text.lines()
            .filter(|l| !l.starts_with('#'))
            .map(str::to_owned)
            .collect()
    };
    // Every record of the input, in file order, IPv4 among IPv6 (`--show open,closed`).
    let all = lines("ipv6.open-closed.list");
    assert_eq!(all.len(), 18);
    assert_eq!(all[0], "open tcp 80 2001:db8::1 1700014400");
    assert_eq!(all[1], "open tcp 80 192.0.2.1 1700014400");
    assert_eq!(all[2], "closed tcp 443 2001:db8::1:0:0:0:1 1700014400");
    assert_eq!(all[9], "closed tcp 25 ::ffff:c000:201 1700014404");
    // `--range 192.0.2.0/24`: an IPv4 range drops every IPv6 record.
    assert_eq!(
        lines("filter.ipv6.only4.list"),
        vec![
            "open tcp 80 192.0.2.1 1700014400",
            "open tcp 22 192.0.2.3 1700014407"
        ]
    );
    // `--range 2001:db8::/48,192.0.2.0/24`: IPv6 records are matched against the IPv6 ranges.
    let mixed = lines("filter.ipv6.mixed.list");
    assert!(mixed.iter().any(|l| l.ends_with("2001:db8::53 1700014405")));
    assert!(
        !mixed
            .iter()
            .any(|l| l.contains("2a03:9060") || l.contains("fe80"))
    );
}

/// Задача 3 подэтапа 4a: кейсы с баннерами фиксируют то, что C делает с записями баннеров в `--readscan`
/// (`in-binary.c:584-627`, справка A5) и при их выводе (A1, A4). Сам разбор сверяет `every_golden_case_is_checked`;
/// здесь выписаны ожидаемые строки, снятые с оракула.
#[test]
fn banner_cases_pin_the_c_readscan_semantics() {
    let m = manifest();
    let bytes = |rel: &str| fs::read(format!("{DIR}/{rel}")).expect(rel);
    let output = |name: &str| -> Vec<u8> {
        let c = m.cases.iter().find(|c| c.name == name).expect(name);
        bytes(c.output.as_deref().expect("stored output"))
    };
    let stdout = |name: &str| -> Vec<u8> {
        let c = m.cases.iter().find(|c| c.name == name).expect(name);
        bytes(c.stdout_output.as_deref().expect("stdout file"))
    };
    let text = |b: Vec<u8>| String::from_utf8(b).expect("ASCII output");

    // `--banner-types dns-ver`: no status record is parsed (the input starts with one at 1700021600), so the -oB
    // scan start is the first banner's time, before the application filter (`in-binary.c:437-438`).
    assert_eq!(
        text(output("banner-types.dns-ver.list")),
        "#masscan\nbanner udp 53 192.0.2.21 1700021601 dns-ver 9.18.24\n\
         banner tcp 1006 198.51.100.7 1700021604 dns-ver banner-6\n\
         banner udp 53 2001:db8::53 1700021611 dns-ver \n# end\n"
    );
    assert!(output("banner-types.dns-ver.binary").starts_with(b"masscan/1.1\ns:1700021601\n"));
    // Two names are two options (`ssl,http` is one bad name: `FAIL: bad banner app: ssl,http`, exit 1, measured).
    let ssl_http = text(output("banner-types.ssl-http.list"));
    assert_eq!(
        ssl_http
            .lines()
            .filter(|l| l.starts_with("banner "))
            .count(),
        5
    );
    assert!(!ssl_http.contains("\nopen ") && !ssl_http.contains("\nclosed "));

    // Legacy types 3/4/5 pass the address, port and application filters; type 9 and status records do not.
    let legacy = text(output("filter.banners-legacy.list"));
    assert_eq!(
        legacy.lines().filter(|l| l.starts_with("banner ")).count(),
        8
    );
    assert!(!legacy.contains("192.0.2.40"));
    // Type 3 is always TCP with TTL 0; type 4's extra byte is the last payload byte (`9.18.24`) or, with a 12-byte
    // length, the low byte of the application (`ssl`).
    assert!(legacy.contains("banner udp 53 10.4.0.1 1700028802 dns-ver 9.18.24\n"));
    assert!(legacy.contains("banner tcp 443 10.4.0.2 1700028803 ssl \n"));
    // -oB rewrites the legacy records as type 9 with TTL 0.
    let rewritten = output("banners-legacy.open.binary");
    assert_eq!(&rewritten[99..101], [9, 14 + 19]);
    assert_eq!(rewritten[99 + 2 + 13], 0, "TTL 0");

    // XML `reason` is keyed on the application id (`out-xml.c:106-109`): dns-ver says `syn-ack` even over TCP.
    let xml = text(output("banners.open.xml"));
    assert!(xml.contains(
        "<port protocol=\"tcp\" portid=\"1006\"><state state=\"open\" reason=\"syn-ack\" reason_ttl=\"6\" />"
    ));
    // `normalize_string` holes (`output.c:143-170`): once `\xNN` no longer fits, printable bytes are still added.
    let list = text(output("banners.open.list"));
    let long = list
        .lines()
        .find(|l| l.starts_with("banner tcp 8443 "))
        .expect("16369-byte banner");
    assert!(
        long.ends_with("\\xdb\\xdc !#"),
        "{}",
        &long[long.len() - 40..]
    );
    assert_eq!(
        long.len() - "banner tcp 8443 192.0.2.25 1700021613 html ".len(),
        8190
    );

    // certs: `{finished: 1}` in the file, one PEM block per banner on stdout, `cert:` stripped only past 5 bytes.
    assert_eq!(output("banners.open.certs"), b"{finished: 1}\n");
    let pem = stdout("banners.open.certs");
    let blocks = pem
        .windows(28)
        .filter(|w| *w == b"-----BEGIN CERTIFICATE-----\n")
        .count();
    assert_eq!(blocks, 56);
    assert!(pem.windows(22).any(|w| w == b"\nMIIBszCCAVmgAwIBAgIJ\n"));
    assert!(pem.windows(7).any(|w| w == b"\ncert:\n"));

    // Default format: `Discovered` and `Banner on port` lines, padded to 79 columns when shorter.
    let console = text(stdout("banners.open.default"));
    assert!(console.starts_with(
        "Discovered open port 80/tcp on 192.0.2.20                                      \n\
         Banner on port 80/tcp on 192.0.2.20: [http] HTTP/1.1 200 OK\\x0d\\x0aServer: nginx\\x0d\\x0a\\x0d\\x0a\n"
    ));
    assert!(console.contains(&format!(
        "Banner on port 53/udp on 2001:db8::53: [dns-ver] {:width$}\n",
        "",
        width = 79 - "Banner on port 53/udp on 2001:db8::53: [dns-ver] ".len()
    )));
}
