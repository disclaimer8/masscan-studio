//! Приёмка проводного трафика Linux (этап 2B-Linux, задача 6).
//!
//! Первая группа тестов — обычные и офлайн (чистая логика независимого
//! сравнения pcap, идёт и на Mac). Вторая группа `#[ignore]` и проверяет
//! артефакты ЗАМКНУТОГО стенда: каталог результатов, который создал
//! `scripts/wire-lab.sh --suite rust` (и `--suite perf`) на машине с netns/veth.
//!
//!   RMASSCAN_WIRE_RESULTS=<dir>        результаты `--suite rust`
//!   RMASSCAN_WIRE_PERF_RESULTS=<dir>   результаты `--suite perf` (по желанию)
//!   RMASSCAN_WIRE_FIXTURES=<dir>       эталоны C (по умолчанию tests/golden/wire)
//!
//! Сравнение здесь написано независимо от Python-сравнивателя (`verify-wire.py`):
//! второй независимый путь к тому же вердикту. Если окружение не задано, тест
//! ПАДАЕТ с «NOT RUN», а не проходит молча: пропуск никогда не PASS.
//! Рабочий запуск (привилегии, команды, сырые результаты) описан в
//! `docs/experiments/2026-10-23-rmasscan-stage2b-linux.md`.

use std::path::{Path, PathBuf};

// ------------------------------------------------------------------ pcap ---

#[derive(Debug, PartialEq, Eq)]
enum PcapError {
    Truncated(&'static str),
    BadMagic,
    Snapped(usize),
}

/// Строгий разбор classic pcap: любая обрезка или snaplen-усечение — ошибка
/// (INVALID, не PASS).
fn read_pcap(data: &[u8]) -> Result<Vec<Vec<u8>>, PcapError> {
    if data.len() < 24 {
        return Err(PcapError::Truncated("global header"));
    }
    let big = match &data[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => false,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => true,
        _ => return Err(PcapError::BadMagic),
    };
    let u32_at = |i: usize| {
        let b = [data[i], data[i + 1], data[i + 2], data[i + 3]];
        if big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    };
    let mut frames = Vec::new();
    let mut off = 24;
    while off < data.len() {
        if off + 16 > data.len() {
            return Err(PcapError::Truncated("record header"));
        }
        let caplen = u32_at(off + 8) as usize;
        let origlen = u32_at(off + 12) as usize;
        off += 16;
        if caplen != origlen {
            return Err(PcapError::Snapped(frames.len()));
        }
        if off + caplen > data.len() {
            return Err(PcapError::Truncated("record body"));
        }
        frames.push(data[off..off + caplen].to_vec());
        off += caplen;
    }
    Ok(frames)
}

/// IPv4/TCP с ровно флагом SYN (как `verify-wire.py::is_syn`).
fn is_syn(f: &[u8]) -> bool {
    if f.len() < 54 || f[12..14] != [0x08, 0x00] {
        return false;
    }
    let ihl = usize::from(f[14] & 0x0f) * 4;
    if f[14] >> 4 != 4 || ihl < 20 || f[23] != 6 {
        return false;
    }
    if u16::from_be_bytes([f[20], f[21]]) & 0x1fff != 0 {
        return false;
    }
    let t = 14 + ihl;
    f.len() >= t + 14 && (f[t + 13] & 0x3f) == 0x02
}

fn syn_stream(frames: &[Vec<u8>]) -> Vec<&[u8]> {
    frames
        .iter()
        .filter(|f| is_syn(f))
        .map(Vec::as_slice)
        .collect()
}

fn load_syns(path: &Path) -> Vec<Vec<u8>> {
    let data = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let frames =
        read_pcap(&data).unwrap_or_else(|e| panic!("{}: INVALID pcap: {e:?}", path.display()));
    syn_stream(&frames)
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect()
}

// ----------------------------------------------------------- self checks ---

fn syn(dport: u16, seq: u32) -> Vec<u8> {
    let mut f = vec![0u8; 54];
    f[0..6].copy_from_slice(&[2, 0xaa, 0, 0, 0, 2]);
    f[6..12].copy_from_slice(&[2, 0xaa, 0, 0, 0, 1]);
    f[12..14].copy_from_slice(&[8, 0]);
    f[14] = 0x45;
    f[23] = 6;
    f[34..36].copy_from_slice(&40000u16.to_be_bytes());
    f[36..38].copy_from_slice(&dport.to_be_bytes());
    f[38..42].copy_from_slice(&seq.to_be_bytes());
    f[47] = 0x02;
    f
}

fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut o = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    o.extend_from_slice(&[0; 8]);
    o.extend_from_slice(&65535u32.to_le_bytes());
    o.extend_from_slice(&1u32.to_le_bytes());
    for (i, f) in frames.iter().enumerate() {
        o.extend_from_slice(&(i as u32).to_le_bytes());
        o.extend_from_slice(&0u32.to_le_bytes());
        o.extend_from_slice(&(f.len() as u32).to_le_bytes());
        o.extend_from_slice(&(f.len() as u32).to_le_bytes());
        o.extend_from_slice(f);
    }
    o
}

fn concat_syns(legs: &[&[Vec<u8>]]) -> Vec<Vec<u8>> {
    legs.iter()
        .flat_map(|l| syn_stream(l).into_iter().map(<[u8]>::to_vec))
        .collect()
}

#[test]
fn pcap_parser_is_strict() {
    let good = pcap(&[syn(80, 1), syn(81, 2)]);
    assert_eq!(read_pcap(&good).unwrap().len(), 2);
    assert_eq!(
        read_pcap(&good[..good.len() - 3]),
        Err(PcapError::Truncated("record body"))
    );
    assert_eq!(
        read_pcap(&good[..10]),
        Err(PcapError::Truncated("global header"))
    );
    assert_eq!(read_pcap(&[0u8; 64]), Err(PcapError::BadMagic));
    let mut snapped = good.clone();
    snapped[24 + 8] = 10; // caplen != origlen
    assert!(matches!(read_pcap(&snapped), Err(PcapError::Snapped(_))));
}

#[test]
fn syn_filter_ignores_other_frames() {
    let mut rst = syn(80, 1);
    rst[47] = 0x04;
    let mut synack = syn(80, 1);
    synack[47] = 0x12;
    let arp = vec![0u8; 42];
    let frames = vec![arp, syn(80, 1), rst, synack, syn(81, 2)];
    assert_eq!(syn_stream(&frames).len(), 2);
}

#[test]
fn pause_plus_resume_must_equal_continuous_and_detects_seam_defects() {
    let all: Vec<Vec<u8>> = (0..6).map(|i| syn(80 + i, u32::from(i))).collect();
    let cont = concat_syns(&[&all]);
    for k in 0..=all.len() {
        let (a, b) = all.split_at(k);
        assert_eq!(concat_syns(&[a, b]), cont, "split at {k}");
    }
    // дубль на стыке, пропуск на стыке, перестановка ног
    let dup = concat_syns(&[&all[..3], &all[2..]]);
    assert_ne!(dup, cont);
    let skip = concat_syns(&[&all[..3], &all[4..]]);
    assert_ne!(skip, cont);
    let swapped = concat_syns(&[&all[3..], &all[..3]]);
    assert_ne!(swapped, cont);
}

// ------------------------------------------------------------- lab tests ---

fn lab_dir(var: &str) -> PathBuf {
    match std::env::var_os(var) {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => panic!(
            "NOT RUN: {var} is not set. These tests inspect the artifacts of a sealed-lab run \
             (scripts/wire-lab.sh --suite rust|perf); a skipped lab test is never a pass."
        ),
    }
}

fn fixtures() -> PathBuf {
    std::env::var_os("RMASSCAN_WIRE_FIXTURES").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/wire"),
        PathBuf::from,
    )
}

/// Сжатый вид JSON без пробелов: для простых проверок подстрок без serde.
fn compact(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

const CASES: [&str; 6] = [
    "c01_one_addr_port_synack",
    "c02_one_addr_port_rst",
    "c03_multi_addr_ports",
    "c04_exclude",
    "c05_srcport_single",
    "c06_srcport_range",
];

#[test]
#[ignore = "sealed-lab artifacts: set RMASSCAN_WIRE_RESULTS (see module docs)"]
fn lab_rust_syn_stream_equals_c_oracle_for_every_case_and_run() {
    let res = lab_dir("RMASSCAN_WIRE_RESULTS");
    let fx = fixtures();
    for case in CASES {
        let want = load_syns(&fx.join(format!("{case}.run1.pcap")));
        assert!(!want.is_empty(), "{case}: empty C fixture");
        for run in 1..=2 {
            let tag = format!("rust.{case}.run{run}");
            let meta = compact(&res.join(format!("{tag}.capture.json")));
            assert!(
                meta.contains("\"valid\":true") && meta.contains("\"drops\":0"),
                "{tag}: INVALID capture {meta}"
            );
            let got = load_syns(&res.join(format!("{tag}.pcap")));
            assert_eq!(got.len(), want.len(), "{tag}: SYN count");
            for (i, (g, w)) in got.iter().zip(&want).enumerate() {
                assert_eq!(g, w, "{tag}: SYN #{i} differs from the C oracle");
            }
            let sum = compact(&res.join(format!("{tag}.summary.json")));
            assert!(sum.contains("\"reason\":\"Completed\""), "{tag}: {sum}");
        }
    }
}

#[test]
#[ignore = "sealed-lab artifacts: set RMASSCAN_WIRE_RESULTS (see module docs)"]
fn lab_pause_resume_pcap_concat_equals_continuous_trace() {
    let res = lab_dir("RMASSCAN_WIRE_RESULTS");
    let cont = load_syns(&res.join("rust.c03_multi_addr_ports.run1.pcap"));
    let c_fixture = load_syns(&fixtures().join("c03_multi_addr_ports.run1.pcap"));
    assert_eq!(cont.len(), 16);
    assert_eq!(cont, c_fixture, "continuous Rust trace != C fixture");
    for n in [0usize, 1, 8, 15] {
        let pause = load_syns(&res.join(format!("pr_N{n}.pause.pcap")));
        let resume = load_syns(&res.join(format!("pr_N{n}.resume.pcap")));
        assert_eq!(pause.len(), n, "N={n}: pause leg sent exactly N probes");
        assert_eq!(resume.len(), 16 - n, "N={n}: resume leg sent the rest");
        let joined: Vec<Vec<u8>> = pause.into_iter().chain(resume).collect();
        assert_eq!(
            joined, cont,
            "N={n}: pause+resume != continuous (byte-for-byte)"
        );
        // checkpoint: ровно 120 байт; ids в summary
        let cp = std::fs::read(res.join(format!("pr_N{n}.checkpoint.bin"))).unwrap();
        assert_eq!(cp.len(), 120, "N={n}: checkpoint length");
        let s1 = compact(&res.join(format!("pr_N{n}.pause.summary.json")));
        let s2 = compact(&res.join(format!("pr_N{n}.resume.summary.json")));
        assert!(
            s1.contains("\"reason\":\"Paused\"") && s1.contains("\"checkpoint\":true"),
            "{s1}"
        );
        assert!(s2.contains("\"reason\":\"Completed\""), "{s2}");
        let scan = format!("\"scan_id\":\"{}\"", "11".repeat(16));
        assert!(
            s1.contains(&scan) && s2.contains(&scan),
            "N={n}: scan_id preserved"
        );
        assert!(
            s1.contains(&format!("\"attempt_id\":\"{}\"", "aa".repeat(16)))
                && s2.contains(&format!("\"attempt_id\":\"{}\"", "bb".repeat(16)))
                && s2.contains(&format!("\"resumed_from_attempt\":\"{}\"", "aa".repeat(16))),
            "N={n}: attempt_id changed and origin recorded"
        );
    }
}

#[test]
#[ignore = "sealed-lab artifacts: set RMASSCAN_WIRE_RESULTS (see module docs)"]
fn lab_rejected_resumes_never_open_the_adapter_or_touch_the_wire() {
    let res = lab_dir("RMASSCAN_WIRE_RESULTS");
    let mut seen = 0;
    for e in std::fs::read_dir(&res).unwrap() {
        let name = e.unwrap().file_name().to_string_lossy().into_owned();
        let Some(tag) = name
            .strip_prefix("rej_")
            .and_then(|n| n.strip_suffix(".summary.json"))
        else {
            continue;
        };
        let sum = compact(&res.join(&name));
        assert!(
            sum.contains("\"status\":\"error\"")
                && sum.contains("\"opened_adapter\":false")
                && sum.contains("\"tx_sent\":0"),
            "rej_{tag}: {sum}"
        );
        assert!(
            load_syns(&res.join(format!("rej_{tag}.pcap"))).is_empty(),
            "rej_{tag}: a SYN reached the wire after a rejected resume"
        );
        seen += 1;
    }
    assert!(
        seen >= 13,
        "expected at least 13 rejection scenarios, saw {seen}"
    );
}

#[test]
#[ignore = "sealed-lab artifacts: set RMASSCAN_WIRE_RESULTS (see module docs)"]
fn lab_veth_removal_fails_diagnosably_without_a_checkpoint() {
    let res = lab_dir("RMASSCAN_WIRE_RESULTS");
    let sum = compact(&res.join("veth_removal.summary.json"));
    assert!(sum.contains("\"reason\":\"Failed\""), "{sum}");
    assert!(
        sum.contains("RxError") || sum.contains("TxError"),
        "no diagnosable cause: {sum}"
    );
    assert!(
        sum.contains("\"checkpoint\":false") && sum.contains("\"checkpoint_hex\":null"),
        "{sum}"
    );
    assert!(
        !res.join("veth_removal.checkpoint.bin").exists(),
        "a checkpoint file exists after an I/O failure"
    );
}

#[test]
#[ignore = "sealed-lab artifacts: set RMASSCAN_WIRE_RESULTS (see module docs)"]
fn lab_all_recorded_checks_pass_none_failed_none_not_run() {
    let res = lab_dir("RMASSCAN_WIRE_RESULTS");
    let all = compact(&res.join("results.json"));
    assert!(!all.contains("\"partial\":true"), "partial results");
    assert!(
        !all.contains("\"result\":\"FAIL\""),
        "a lab check FAILED: see results.json"
    );
    assert!(!all.contains("\"result\":\"NOTRUN\"") && !all.contains("\"result\":\"NOT RUN\""));
    for group in ["parity", "pause", "reject", "stop", "veth"] {
        assert!(
            all.contains(&format!("\"group\":\"{group}\"")),
            "group {group} missing"
        );
    }
    assert!(all.matches("\"result\":\"PASS\"").count() >= 100);
}

#[test]
#[ignore = "sealed-lab artifacts: set RMASSCAN_WIRE_PERF_RESULTS (see module docs)"]
fn lab_perf_matrix_is_complete_and_invalid_cells_are_never_normalised() {
    let res = lab_dir("RMASSCAN_WIRE_PERF_RESULTS");
    let all = compact(&res.join("results.json"));
    for rate in [100, 1000, 10000, 100000] {
        assert!(
            all.contains(&format!("\"rate\":{rate}")),
            "rate {rate} missing"
        );
    }
    let cells_c = all.matches("\"impl\":\"c\"").count();
    let cells_rust = all.matches("\"impl\":\"rust\"").count();
    assert_eq!(cells_c, 20, "C cells");
    assert_eq!(cells_rust, 20, "Rust cells");
    // INVALID-ячейка помечена valid=false и несёт причину; медианы считает только по valid.
    assert!(all.contains("\"perf_summary\""));
    // Полнота приёма ответов сканером: ОТДЕЛЬНО от валидности захвата (INVALID-захват это не потеря ответов).
    let incomplete: Vec<&str> = all
        .split("\"rust_rx_incomplete_runs\":")
        .skip(1)
        .map(|t| t.split(',').next().unwrap())
        .collect();
    assert_eq!(incomplete.len(), 4, "rust_rx_incomplete_runs per rate");
    assert!(
        incomplete.iter().all(|v| *v == "0"),
        "Rust lost in-job replies: rx_incomplete_runs {incomplete:?}"
    );
    let drops: Vec<&str> = all
        .split("\"rust_kernel_drops_per_run\":[")
        .skip(1)
        .map(|t| t.split(']').next().unwrap())
        .collect();
    assert_eq!(drops.len(), 4, "rust_kernel_drops_per_run per rate");
    for d in &drops {
        assert!(
            d.split(',').all(|v| v == "0"),
            "RX socket kernel drops {d}: replies may have been lost"
        );
    }
    // ±20% — открытый gate: этот тест НЕ утверждает паритет скорости.
}
