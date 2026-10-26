#![cfg(unix)]
use studio_platform::trusted::{file_hash, verify};
#[test]
fn expected_hash_does_not_make_a_user_writable_binary_trusted() {
    let path = std::env::current_exe().unwrap();
    let hash = file_hash(&path).unwrap();
    assert!(verify(&path, &hash).is_err());
    let system = std::path::Path::new("/bin/echo").canonicalize().unwrap();
    let hash = file_hash(&system).unwrap();
    assert!(verify(&system, &hash).is_ok());
    assert!(verify(&system, &"00".repeat(32)).is_err());
}
