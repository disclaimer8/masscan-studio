#![cfg(target_os = "macos")]
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn packaged_launcher_forwards_literal_arguments_and_child_exit_status() {
    let dir = std::env::temp_dir().join(format!(
        "studio launcher {}",
        studio_protocol::id_text(studio_protocol::new_id().unwrap())
    ));
    fs::create_dir(&dir).unwrap();
    let launcher = dir.join("studio-launcher");
    fs::copy(env!("CARGO_BIN_EXE_studio-launcher"), &launcher).unwrap();
    let ui = dir.join("studio-ui");
    fs::write(&ui, "#!/bin/sh\nprintf '%s\\n' \"$@\"\nexit 17\n").unwrap();
    fs::set_permissions(&ui, fs::Permissions::from_mode(0o700)).unwrap();
    let result = Command::new(&launcher)
        .args(["--smoke", "path with spaces", "$(false); literal"])
        .output()
        .unwrap();
    fs::remove_dir_all(dir).unwrap();
    assert_eq!(result.status.code(), Some(17));
    assert_eq!(
        result.stdout,
        b"--smoke\npath with spaces\n$(false); literal\n"
    );
}
