use studio_platform::trusted::file_hash;

#[test]
fn file_hash_preserves_sha256_installation_and_manifest_encoding() {
    // Standard SHA-256 vectors, including a file larger than the read buffer.
    // Missing zero-padding, uppercase output or an incomplete read must fail.
    let vectors = [
        (
            Vec::new(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc".to_vec(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            vec![b'a'; 1_000_000],
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        ),
    ];
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("studio-hash-{}-{nonce}", std::process::id()));
    for (bytes, expected) in vectors {
        use std::io::Write;
        let mut file = std::fs::File::create_new(&path).unwrap();
        file.write_all(&bytes).unwrap();
        drop(file);
        let actual = file_hash(&path);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(actual.unwrap(), expected);
    }
}
