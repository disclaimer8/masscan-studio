//! Проверка test-only SHA-256 из `common` (AGPL-3.0, masscan © Robert David
//! Graham). Единственный golden-тест `-sL` на production-коде живёт в
//! `scan_golden.rs`; здесь остаётся только проверка test-only SHA-256.

mod common;

use common::Sha256;

#[test]
fn sha256_known_vectors() {
    let mut s = Sha256::new();
    s.update(b"abc");
    assert_eq!(
        s.finish(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        Sha256::new().finish(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}
