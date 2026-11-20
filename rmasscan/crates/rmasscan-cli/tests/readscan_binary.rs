//! `--readscan` через настоящий бинарник (AGPL-3.0): операция только читает файлы `-oB`, поэтому её можно запускать в
//! тестах (маркер `--readscan` в `tests/common/spawn.rs`). Здесь то, что видно только через `main`: ошибка чтения
//! печатается в stderr ровно один раз, отказы разбора masscan (`main-conf.c:3401–3459`, `:1745–1790`) печатаются как
//! есть с exit 1, а stdout `-oL -` доходит целиком.

#[path = "common/spawn.rs"]
mod spawn;

#[path = "common/scratch.rs"]
mod scratch;

use scratch::Scratch;
use spawn::spawn_readonly;

/// Файл `-oB` по справке C: заголовок 99 байт, одна запись open 1.2.3.4:80 (15 байт), подвал 99 байт.
fn one_record_scan() -> Vec<u8> {
    let mut v = b"masscan/1.1\ns:1700000000\n".to_vec();
    v.resize(99, 0);
    v.extend_from_slice(&[6, 13]);
    v.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    v.extend_from_slice(&[1, 2, 3, 4, 6, 0, 80, 0x12, 57]);
    let mut foot = b"masscan/1.1".to_vec();
    foot.resize(99, 0);
    v.extend_from_slice(&foot);
    v
}

#[test]
fn readscan_converts_to_list_on_stdout() {
    let scratch = Scratch::new();
    let path = scratch
        .write("one.scan", &one_record_scan())
        .to_string_lossy()
        .into_owned();
    let out = spawn_readonly(&["--readscan", &path, "-oL", "-"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "#masscan\nopen tcp 80 1.2.3.4 1700000000\n# end\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!("[+] --readscan {path}\n")
    );
}

/// Решение 3 контроллера: `run_readscan` уже записал строки C в stderr; `main` выходит с 1 и не печатает их снова.
#[test]
fn readscan_read_errors_are_printed_once() {
    let scratch = Scratch::new();
    let missing = scratch.path("missing.scan").to_string_lossy().into_owned();
    let out = spawn_readonly(&["--readscan", &missing, "-oL", "-"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.matches(&format!("[-] {missing}: ")).count(), 1, "{err}");
    assert_eq!(err.matches("[-] FAIL: --readscan").count(), 1, "{err}");
    assert!(!err.contains("rmasscan: error:"), "{err}");
    // `in-binary.c:486-493`: `fopen` раньше `[+] --readscan`, строки `[+]` для отсутствующего файла нет.
    assert!(!err.contains("[+]"), "{err}");
    assert_eq!(err.lines().count(), 2, "{err}");

    let corrupt = scratch
        .write("corrupt.scan", &one_record_scan()[..99 + 9])
        .to_string_lossy()
        .into_owned();
    let out = spawn_readonly(&["--readscan", &corrupt, "-oL", "-"]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        err,
        format!("[+] --readscan {corrupt}\n[-] file corrupt\n"),
        "exactly once, no second copy from main"
    );
}

#[test]
fn masscan_parse_refusals_print_the_c_text_and_exit_one() {
    for (argv, want) in [
        (
            &["--readscan", "f", "-oA", "x"][..],
            "nmap(-oA): unsupported output format\n",
        ),
        (&["--readscan", "f", "-oL"][..], "missing output filename\n"),
        (
            &["--readscan", "f", "--show", "bogus"][..],
            "FAIL: unknown 'show' spec: bogus\n",
        ),
    ] {
        let out = spawn_readonly(argv);
        assert_eq!(out.status.code(), Some(1), "{argv:?}");
        assert!(out.stdout.is_empty(), "{argv:?}");
        assert_eq!(String::from_utf8_lossy(&out.stderr), want, "{argv:?}");
    }
}

/// Файл `-oB` с TLS-записями одного соединения: статус, затем баннеры типа 9 в порядке сброса стека
/// (ssl, X509 листа, два X509CA цепочки, vuln). Байты по `binary_out_banner` (тип 9: время, адрес, протокол,
/// порт, приложение, TTL, сырая нагрузка).
fn tls_records_scan() -> Vec<u8> {
    fn banner(app: u16, payload: &[u8]) -> Vec<u8> {
        let head = 14usize;
        let len = payload.len() + head;
        assert!(payload.len() < 128 - head, "small test payloads only");
        let mut v = vec![9u8, len as u8];
        v.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        v.extend_from_slice(&[1, 2, 3, 4, 6]);
        v.extend_from_slice(&443u16.to_be_bytes());
        v.extend_from_slice(&app.to_be_bytes());
        v.push(57);
        v.extend_from_slice(payload);
        v
    }
    let mut v = b"masscan/1.1\ns:1700000000\n".to_vec();
    v.resize(99, 0);
    v.extend_from_slice(&[6, 13]);
    v.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    v.extend_from_slice(&[1, 2, 3, 4, 6, 0x01, 0xbb, 0x12, 57]);
    for rec in [
        banner(9, b"TLS/1.2 cipher:0xc02f, leaf.test"),
        banner(15, b"MIIBszCCAVmgAwIBAgIBAT"),
        banner(16, b"MIICAQ"),
        banner(16, b"MIIDCA"),
        banner(20, b"SSL[HEARTBLEED] "),
    ] {
        v.extend_from_slice(&rec);
    }
    let mut foot = b"masscan/1.1".to_vec();
    foot.resize(99, 0);
    v.extend_from_slice(&foot);
    v
}

/// `--readscan` TLS-записей: конверсия байт в байт как C, две `X509CA` одного соединения обе проходят (задача
/// 11; сверено с пином C на реалистичном входе из эталонов TLS — все форматы и certs сошлись побайтно).
#[test]
fn readscan_tls_records_match_c_all_formats() {
    let scratch = Scratch::new();
    let path = scratch
        .write("tls.scan", &tls_records_scan())
        .to_string_lossy()
        .into_owned();
    let out = spawn_readonly(&["--readscan", &path, "-oL", "-"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "#masscan\n\
         open tcp 443 1.2.3.4 1700000000\n\
         banner tcp 443 1.2.3.4 1700000000 ssl TLS/1.2 cipher:0xc02f, leaf.test\n\
         banner tcp 443 1.2.3.4 1700000000 X509 MIIBszCCAVmgAwIBAgIBAT\n\
         banner tcp 443 1.2.3.4 1700000000 X509CA MIICAQ\n\
         banner tcp 443 1.2.3.4 1700000000 X509CA MIIDCA\n\
         banner tcp 443 1.2.3.4 1700000000 vuln SSL[HEARTBLEED] \n\
         # end\n"
    );
    for fmt in ["-oJ", "-oX", "-oG"] {
        let out = spawn_readonly(&["--readscan", &path, fmt, "-"]);
        assert_eq!(out.status.code(), Some(0), "{fmt}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("TLS/1.2 cipher:0xc02f"), "{fmt}: {text}");
        assert_eq!(text.matches("X509CA").count(), 2, "{fmt}: {text}");
    }
}

/// `--output-format certs` на том же входе (`src/out-certs.c`): PEM каждой записи баннера в stdout (не только
/// X509), файл получает только подвал `{finished: 1}`.
#[test]
fn certs_format_matches_c() {
    let scratch = Scratch::new();
    let path = scratch
        .write("tls.scan", &tls_records_scan())
        .to_string_lossy()
        .into_owned();
    let certs_path = scratch.path("certs.out");
    let out = spawn_readonly(&[
        "--readscan",
        &path,
        "--output-format",
        "certs",
        "--output-filename",
        certs_path.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "-----BEGIN CERTIFICATE-----\n\
         TLS/1.2 cipher:0xc02f, leaf.test\n\
         -----END CERTIFICATE-----\n\
         -----BEGIN CERTIFICATE-----\n\
         MIIBszCCAVmgAwIBAgIBAT\n\
         -----END CERTIFICATE-----\n\
         -----BEGIN CERTIFICATE-----\n\
         MIICAQ\n\
         -----END CERTIFICATE-----\n\
         -----BEGIN CERTIFICATE-----\n\
         MIIDCA\n\
         -----END CERTIFICATE-----\n\
         -----BEGIN CERTIFICATE-----\n\
         SSL[HEARTBLEED] \n\
         -----END CERTIFICATE-----\n"
    );
    assert_eq!(std::fs::read(&certs_path).unwrap(), b"{finished: 1}\n");
}

/// `--json-status`/`--status-json` (`main-conf.c:1519-1531`): две строки C в stderr, exit 1, файлы не открываются.
#[test]
fn json_status_is_refused_with_the_c_lines() {
    for name in ["json-status", "status-json"] {
        let out = spawn_readonly(&[&format!("--{name}"), "--readscan", "missing-file.scan"]);
        assert_eq!(out.status.code(), Some(1), "{name}");
        assert!(out.stdout.is_empty(), "{name}");
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            format!(
                "[-] FAIL: {name} not supported, use --status-ndjson\n    hint: new-line delimited JSON status is what we use\n"
            ),
            "{name}"
        );
    }
}
