#![cfg(unix)]
use studio_platform::linux::{install_script, installed_path, shell_quote};
#[test]
fn linux_install_is_immutable_hash_addressed_and_shell_safe() {
    let hash = "a".repeat(64);
    assert_eq!(
        installed_path(&hash).unwrap().to_str().unwrap(),
        format!("/usr/local/libexec/masscan-studio/{hash}/studio-runner")
    );
    for bad in ["", "../bad", &"G".repeat(64)] {
        assert!(installed_path(bad).is_err());
    }
    for value in ["a b", "a'b", "$(false)", "`false`", "line\nline", ""] {
        let out = std::process::Command::new("/bin/sh")
            .args(["-c", &format!("printf %s {}", shell_quote(value).unwrap())])
            .output()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, value.as_bytes());
    }
    assert!(shell_quote("bad\0value").is_err());
    let script = install_script(std::path::Path::new("/tmp/a'b/runner"), &hash).unwrap();
    assert!(script.contains("sha256sum"));
    assert!(script.contains("No overwrite"));
    assert!(!script.contains("systemctl"));
    assert!(!script.contains("polkit-1"));
    assert!(
        std::process::Command::new("/bin/sh")
            .args(["-n", "-c", &script])
            .status()
            .unwrap()
            .success()
    );
    assert!(install_script(std::path::Path::new("relative"), &hash).is_err());
}
#[test]
fn linux_runner_rejects_custom_loader_and_search_paths() {
    use studio_platform::linux::validate_elf;
    let headers = "[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]";
    let dynamic =
        "0x1 (NEEDED) Shared library: [libgcc_s.so.1]\n0x1 (NEEDED) Shared library: [libc.so.6]";
    assert!(validate_elf(headers, dynamic).is_ok());
    assert!(validate_elf("", dynamic).is_err());
    assert!(validate_elf("[Requesting program interpreter: /tmp/loader]", dynamic).is_err());
    for bad in [
        "0x1 (RPATH) Library rpath: [/tmp]",
        "0x1 (RUNPATH) Library runpath: [$ORIGIN]",
        "0x1 (NEEDED) Shared library: [/tmp/libc.so.6]",
        "0x1 (NEEDED) Shared library: [libQt.so]",
    ] {
        assert!(validate_elf(headers, &format!("{dynamic}\n{bad}")).is_err());
    }
}
