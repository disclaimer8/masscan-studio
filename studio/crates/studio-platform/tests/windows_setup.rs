use studio_platform::win_setup::{install_script, powershell_quote, validate_hash};

#[test]
fn windows_installer_accepts_data_not_commands() {
    assert_eq!(
        powershell_quote("C:\\a'b;$(bad)\\runner.exe").unwrap(),
        "'C:\\a''b;$(bad)\\runner.exe'"
    );
    assert!(powershell_quote("a\0b").is_err());
    let hash = "ab".repeat(32);
    validate_hash(&hash).unwrap();
    for bad in ["A".repeat(64), "a".repeat(63), "../bad".into()] {
        assert!(validate_hash(&bad).is_err());
    }
    let script = install_script("C:\\build's\\studio-runner.exe", &hash).unwrap();
    assert!(script.contains("'C:\\build''s\\studio-runner.exe'"));
    assert!(script.contains("#requires -RunAsAdministrator"));
    assert!(script.contains("GetFolderPath"));
    assert!(script.contains("Directory]::Move"));
    assert!(!script.contains("-Force"));
    assert!(!script.contains("Start-Process"));
    assert!(install_script("relative.exe", &hash).is_err());
    assert!(install_script("\\\\server\\share\\runner.exe", &hash).is_err());
}
