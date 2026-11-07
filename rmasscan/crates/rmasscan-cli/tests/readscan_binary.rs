//! `--readscan` через настоящий бинарник (AGPL-3.0): операция только читает файлы `-oB`, поэтому её можно запускать в
//! тестах (маркер `--readscan` в `tests/common/spawn.rs`). Здесь то, что видно только через `main`: ошибка чтения
//! печатается в stderr ровно один раз, отказы разбора masscan (`main-conf.c:3401–3459`, `:1745–1790`) печатаются как
//! есть с exit 1, а stdout `-oL -` доходит целиком.

#[path = "common/spawn.rs"]
mod spawn;

use spawn::spawn_readonly;

fn tmp(name: &str) -> String {
    std::env::temp_dir()
        .join(format!(
            "rmasscan-readscan-bin-{}-{name}",
            std::process::id()
        ))
        .to_string_lossy()
        .into_owned()
}

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
    let path = tmp("one.scan");
    std::fs::write(&path, one_record_scan()).unwrap();
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
    let _ = std::fs::remove_file(path);
}

/// Решение 3 контроллера: `run_readscan` уже записал строки C в stderr; `main` выходит с 1 и не печатает их снова.
#[test]
fn readscan_read_errors_are_printed_once() {
    let missing = tmp("missing.scan");
    let out = spawn_readonly(&["--readscan", &missing, "-oL", "-"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.matches(&format!("[-] {missing}: ")).count(), 1, "{err}");
    assert_eq!(err.matches("[-] FAIL: --readscan").count(), 1, "{err}");
    assert!(!err.contains("rmasscan: error:"), "{err}");
    assert_eq!(err.lines().count(), 3, "{err}");

    let corrupt = tmp("corrupt.scan");
    std::fs::write(&corrupt, &one_record_scan()[..99 + 9]).unwrap();
    let out = spawn_readonly(&["--readscan", &corrupt, "-oL", "-"]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        err,
        format!("[+] --readscan {corrupt}\n[-] file corrupt\n"),
        "exactly once, no second copy from main"
    );
    let _ = std::fs::remove_file(corrupt);
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
