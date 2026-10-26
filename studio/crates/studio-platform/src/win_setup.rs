//! Reviewable, one-time Windows operating-system installation. No UAC launcher.
type Result<T> = std::result::Result<T, String>;
pub fn validate_hash(hash: &str) -> Result<()> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("Invalid runner SHA-256".into());
    }
    Ok(())
}
pub fn powershell_quote(value: &str) -> Result<String> {
    if value.contains('\0') {
        return Err("NUL in installation argument".into());
    }
    Ok(format!("'{}'", value.replace('\'', "''")))
}
pub fn install_script(source: &str, hash: &str) -> Result<String> {
    validate_hash(hash)?;
    let bytes = source.as_bytes();
    if bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || &bytes[1..3] != b":\\"
        || source[3..].contains(':')
    {
        return Err("Runner source must be an absolute local drive path without streams".into());
    }
    let source = powershell_quote(source)?;
    Ok(format!(
        r#"#requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([IntPtr]::Size -ne 8) {{ throw 'Use 64-bit PowerShell' }}
$source = {source}
$hash = '{hash}'
$trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
function Assert-TrustedDirectory([string] $path) {{
    $item = Get-Item -LiteralPath $path
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {{ throw "Untrusted directory type: $path" }}
    $acl = Get-Acl -LiteralPath $path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $trusted) {{ throw "Untrusted owner: $path" }}
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $raw.DiscretionaryAcl) {{ throw "Null DACL: $path" }}
    [uint32] $danger = 0x500D0156
    if ([IO.Path]::GetPathRoot($path) -eq $path) {{ $danger = 0x500D0152 }}
    foreach ($ace in $raw.DiscretionaryAcl) {{
        if ($ace.AceFlags -band [Security.AccessControl.AceFlags]::InheritOnly) {{ continue }}
        if ($ace.AceType -eq [Security.AccessControl.AceType]::AccessDenied) {{ continue }}
        if ($ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed) {{ throw "Unsupported DACL entry: $path" }}
        if ($ace.SecurityIdentifier.Value -notin $trusted -and ($ace.AccessMask -band $danger)) {{ throw "Unprivileged write access: $path" }}
    }}
}}
function Protect-Directory([string] $path) {{
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)')
    Set-Acl -LiteralPath $path -AclObject $acl
    Assert-TrustedDirectory $path
}}
$base = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
if (-not $base) {{ throw 'System Program Files unavailable' }}
$cursor = [IO.DirectoryInfo]::new($base)
while ($null -ne $cursor) {{ Assert-TrustedDirectory $cursor.FullName; $cursor = $cursor.Parent }}
foreach ($part in @('Masscan Studio', 'Runner')) {{
    $base = Join-Path $base $part
    if (Test-Path -LiteralPath $base) {{ Assert-TrustedDirectory $base }}
    else {{ [IO.Directory]::CreateDirectory($base) | Out-Null; Protect-Directory $base }}
}}
$destination = Join-Path $base $hash
if (Test-Path -LiteralPath $destination) {{ throw 'Version already exists. No overwrite.' }}
$stage = Join-Path $base ('.install-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($stage) | Out-Null
try {{
    Protect-Directory $stage
    $copy = Join-Path $stage 'studio-runner.exe'
    [IO.File]::Copy($source, $copy, $false)
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)')
    Set-Acl -LiteralPath $copy -AclObject $acl
    if ((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) {{ throw 'Runner hash mismatch' }}
    [IO.Directory]::Move($stage, $destination)
    Write-Output "Installed $destination\studio-runner.exe"
}} finally {{
    if ([IO.Directory]::Exists($stage)) {{
        $copy = Join-Path $stage 'studio-runner.exe'
        if ([IO.File]::Exists($copy)) {{ [IO.File]::Delete($copy) }}
        [IO.Directory]::Delete($stage)
    }}
}}
"#
    ))
}
