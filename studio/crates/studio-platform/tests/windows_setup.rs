use studio_platform::win_setup::{install_script, powershell_quote, validate_hash};

#[test]
fn windows_installer_accepts_data_not_commands() {
    let encoded = powershell_quote("C:\\a'b;$(bad)\\runner.exe").unwrap();
    assert!(encoded.is_ascii());
    assert!(!encoded.contains("$(bad)"));
    assert!(powershell_quote("a\0b").is_err());
    let hash = "ab".repeat(32);
    validate_hash(&hash).unwrap();
    for bad in ["A".repeat(64), "a".repeat(63), "../bad".into()] {
        assert!(validate_hash(&bad).is_err());
    }
    let script = install_script("C:\\build's\\studio-runner.exe", &hash).unwrap();
    assert!(script.contains(&powershell_quote("C:\\build's\\studio-runner.exe").unwrap()));
    assert!(script.contains("#requires -Version 7.0"));
    assert!(script.contains("#requires -RunAsAdministrator"));
    assert!(script.contains("GetFolderPath"));
    assert!(script.contains("Directory]::Move"));
    assert!(!script.contains("-Force"));
    assert!(!script.contains("Start-Process"));
    assert!(install_script("relative.exe", &hash).is_err());
    assert!(install_script("\\\\server\\share\\runner.exe", &hash).is_err());
}

#[cfg(windows)]
fn powershell_test(script: &str) -> std::process::Output {
    use std::{fs, process::Command};
    let nonce = studio_protocol_free_nonce();
    let dir = std::env::temp_dir().join(format!("studio-ps-{nonce}"));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("test.ps1");
    fs::write(&path, script).unwrap();
    let output = Command::new("pwsh")
        .args(["-NoProfile", "-NonInteractive", "-File"])
        .arg(&path)
        .output()
        .unwrap();
    fs::remove_dir_all(dir).unwrap();
    output
}
#[cfg(windows)]
fn studio_protocol_free_nonce() -> String {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).unwrap();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[cfg(windows)]
#[test]
fn powershell_source_roundtrips_smart_quotes_as_data() {
    for quote in ['\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}', '\''] {
        let source = format!("C:\\x{quote};Write-Output INJECTED;#\\runner.exe");
        let script = format!(
            "$ErrorActionPreference = 'Stop'\n[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)\n$s = {}\n[Console]::Out.Write($s)\n",
            powershell_quote(&source).unwrap()
        );
        let output = powershell_test(&script);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8(output.stdout).unwrap(), source);
    }
}
#[cfg(windows)]
#[test]
fn staging_directory_is_protected_before_any_later_acl_update() {
    use std::fs;
    let dir = std::env::temp_dir().join(format!("studio-inherit-{}", studio_protocol_free_nonce()));
    fs::create_dir(&dir).unwrap();
    let source = dir.join("source.exe");
    fs::write(&source, b"not executed; installation bytes only").unwrap();
    let hash = studio_platform::trusted::file_hash(&source).unwrap();
    let generated = install_script(source.to_str().unwrap(), &hash).unwrap();
    let prefix = generated
        .split("\n$base = ")
        .next()
        .unwrap()
        .replace("#requires -RunAsAdministrator", "");
    let tail = generated.split_once("\n$destination = ").unwrap().1;
    // Use current-user ownership only inside this private fixture so the test
    // runs without elevation. Inherit-only AU write grants model the reviewed
    // accepted-parent case. The production installer's staging sequence is used.
    let setup = format!(
        r#"
$fixture = {}
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$trusted += $sid
$base = Join-Path $fixture 'parent'
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm("O:${{sid}}G:BUD:P(A;;FA;;;$sid)(A;;FA;;;SY)(A;;FA;;;BA)(A;OICIIO;FA;;;AU)")
[IO.FileSystemAclExtensions]::CreateDirectory($acl, $base) | Out-Null
Assert-TrustedDirectory $base
function Set-Acl {{
    param([string] $LiteralPath, $AclObject)
    $before = Get-Acl -LiteralPath $LiteralPath
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($before.GetSecurityDescriptorBinaryForm(), 0)
    foreach ($ace in $raw.DiscretionaryAcl) {{
        if ($ace.AceFlags -band [Security.AccessControl.AceFlags]::InheritOnly) {{ continue }}
        if ($ace.AceType -eq [Security.AccessControl.AceType]::AccessAllowed -and $ace.SecurityIdentifier.Value -eq 'S-1-5-11' -and ($ace.AccessMask -band 0x500D0156)) {{
            throw 'Regression: staging existed with unprivileged write access before ACL hardening'
        }}
    }}
    Microsoft.PowerShell.Security\Set-Acl -LiteralPath $LiteralPath -AclObject $AclObject
}}
"#,
        powershell_quote(dir.to_str().unwrap()).unwrap()
    );
    // Replace only the descriptor literal in the fixture, not the creation or
    // hardening sequence being tested. Preserve the production protected DACL.
    let prefix = prefix
        .replace("'O:BAG:BAD:P", "\"O:${sid}G:BUD:P(A;OICI;FA;;;$sid)")
        .replace(";;;BU)'", ";;;BU)\"");
    let tail = tail
        .replace("'O:BAG:BAD:P", "\"O:${sid}G:BUD:P(A;;FA;;;$sid)")
        .replace(";;;BU)'", ";;;BU)\"");
    let output = powershell_test(&format!("{prefix}\n{setup}\n$destination = {tail}"));
    fs::remove_dir_all(&dir).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
