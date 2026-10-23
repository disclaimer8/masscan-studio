//! Страж правила «без C в сборке» (спека §6.1): любая будущая зависимость,
//! тянущая `cc`, `cmake`, `bindgen` и подобные, роняет этот тест.
//!
//! Граф: `--locked --workspace --target all -e normal,build,dev`. Один
//! `-e build` не видит обычных зависимостей (например, `pcap`), dev-рёбра
//! нужны из-за criterion -> alloca -> cc, `--target all` ловит
//! платформенные зависимости (`[target.'cfg(..)'.dependencies]`), которых нет
//! на хосте. Имена сравниваются целиком (первый токен строки), а не
//! подстрокой: `cc` не совпадает с `cc-rs-helper` и наоборот. Суффикс `-sys`
//! сам по себе не запрещён: linux-raw-sys и windows-sys написаны на Rust.

use std::collections::BTreeSet;

const BANNED: [&str; 10] = [
    "cc",
    "cmake",
    "bindgen",
    "pkg-config",
    "pcap",
    "pcap-sys",
    "libpcap",
    "libpcap-sys",
    "pnet",
    "libfuzzer-sys",
];

/// Имена пакетов из вывода `cargo tree --prefix none`: первый токен строки.
fn package_names(tree: &str) -> BTreeSet<&str> {
    tree.lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect()
}

fn banned_in(tree: &str) -> Vec<&'static str> {
    let names = package_names(tree);
    BANNED
        .iter()
        .copied()
        .filter(|b| names.contains(b))
        .collect()
}

#[test]
fn matcher_compares_whole_names() {
    let tree = "rmasscan-core v0.1.0 (/x)\ncc-helper v1.0.0\nsome-cc v1.0.0\nlibc v0.2.1\n";
    assert!(banned_in(tree).is_empty());
    assert_eq!(
        banned_in("a v1\ncc v1.0.83\npcap-sys v0.1.0\nlibpcap-sys v0.1.0\n"),
        ["cc", "pcap-sys", "libpcap-sys"]
    );
    // Строки повторного вхождения `(*)` тоже начинаются с имени.
    assert_eq!(banned_in("a v1\npkg-config v0.3.0 (*)\n"), ["pkg-config"]);
}

#[test]
fn build_graph_has_no_c_toolchain_crates() {
    let out = std::process::Command::new(env!("CARGO"))
        .args([
            "tree",
            "--locked",
            "--workspace",
            "--target",
            "all",
            "-e",
            "normal,build,dev",
            "--prefix",
            "none",
        ])
        .output()
        .expect("cargo tree запускается");
    // Без этой проверки сбой самого `cargo tree` дал бы пустой вывод и ложный PASS.
    assert!(
        out.status.success(),
        "cargo tree завершился с ошибкой:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let names = package_names(&text);
    for own in ["rmasscan-core", "rmasscan-cli"] {
        assert!(
            names.contains(own),
            "в выводе cargo tree нет {own}:\n{text}"
        );
    }
    let found = banned_in(&text);
    assert!(
        found.is_empty(),
        "запрещённые crates в графе: {found:?}\n{text}"
    );
}
