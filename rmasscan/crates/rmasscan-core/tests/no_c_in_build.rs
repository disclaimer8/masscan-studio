//! Страж правила «без C в сборке» (спека §6.1): любая будущая зависимость,
//! тянущая `cc`, `cmake`, `bindgen` и подобные, роняет этот тест.
//!
//! Рёбра `normal,build,dev`: одного `-e build` мало, он не видит обычных
//! зависимостей (например, `pcap`), а dev-рёбра нужны из-за criterion ->
//! alloca -> cc. Суффикс `-sys` не запрещён: linux-raw-sys и windows-sys
//! написаны на чистом Rust.

#[test]
fn build_graph_has_no_c_toolchain_crates() {
    let out = std::process::Command::new(env!("CARGO"))
        .args([
            "tree",
            "-e",
            "normal,build,dev",
            "--prefix",
            "none",
            "-p",
            "rmasscan-core",
            "-p",
            "rmasscan-cli",
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
    assert!(
        text.contains("rmasscan-core "),
        "в выводе cargo tree нет самого workspace:\n{text}"
    );
    for banned in [
        "cc ",
        "cmake ",
        "bindgen ",
        "pkg-config ",
        "libpcap",
        "pcap ",
    ] {
        assert!(
            !text.contains(banned),
            "запрещённый build-crate в графе: {banned}\n{text}"
        );
    }
}
