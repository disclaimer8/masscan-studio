#![cfg(target_os = "macos")]
use studio_platform::macos::{applescript, install_script, installed_path, shell_quote};
#[test]
fn launch_arguments_round_trip_without_shell_expansion() {
    for s in [
        "a b",
        "'quote'",
        "$(touch /tmp/never-studio)",
        "`id`",
        "\\\"x\nline",
        "",
    ] {
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &format!("printf %s {}", shell_quote(s).unwrap())])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, s.as_bytes());
    }
    assert!(shell_quote("a\0b").is_err());
    assert_eq!(
        applescript("a\"b\\c\nd"),
        "do shell script \"a\\\"b\\\\c\\nd\" with administrator privileges"
    );
}
#[test]
fn installation_is_hash_addressed_and_cannot_inject_destination() {
    let hash = "a".repeat(64);
    assert_eq!(
        installed_path(&hash).unwrap().to_str().unwrap(),
        format!("/Library/PrivilegedHelperTools/MasscanStudio/{hash}/studio-runner")
    );
    for bad in ["../evil", "", &"z".repeat(64)] {
        assert!(installed_path(bad).is_err());
    }
    let script = install_script(std::path::Path::new("/tmp/a'b/runner"), &hash).unwrap();
    assert!(script.contains("/usr/bin/shasum -a 256"));
    assert!(script.contains("/usr/bin/codesign --verify --strict"));
    let check = std::process::Command::new("/bin/sh")
        .arg("-n")
        .arg("-c")
        .arg(script)
        .status()
        .unwrap();
    assert!(check.success());
}

#[test]
fn acl_write_grants_are_not_hidden_by_posix_mode() {
    let path = std::env::temp_dir().join(format!("studio-acl-{}", std::process::id()));
    std::fs::write(&path, b"fixture").unwrap();
    studio_platform::macos::reject_extended_acl(&path).unwrap();
    assert!(
        std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow write"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert!(studio_platform::macos::reject_extended_acl(&path).is_err());
    assert!(
        std::process::Command::new("/bin/chmod")
            .arg("-N")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    std::fs::remove_file(path).unwrap();
}
