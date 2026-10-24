<#
.SYNOPSIS
  Builds the reproducible x64 release package of the Windows wire lab harness.

.DESCRIPTION
  Run from the rmasscan workspace (the directory that holds Cargo.toml) on Windows x64
  with the pinned Rust toolchain (MSVC). The source can be a git checkout or a
  `git archive` extraction (no .git needed); the commit is then given with -Commit.

  Output (in -OutDir, default .\dist):
    rmasscan-wire-windows-x64-<commit12>.zip
    rmasscan-wire-windows-x64-<commit12>.zip.sha256

  ZIP contents: wire_scan.exe, windows-wire-lab.ps1, README.txt, SHA256SUMS, LICENSE,
  NOTICE, SOURCE_COMMIT. The Npcap DLL or installer is NOT included. The name carries the
  commit, never "latest". The ZIP container is deterministic (fixed timestamps, sorted
  entries, fixed compression), so the same EXE always gives the same ZIP.

  Compatible with Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Commit
  40-hex source commit. Default: `git rev-parse HEAD` when run inside a git checkout.

.PARAMETER SkipBuild
  Package an already built target\release\examples\wire_scan.exe (it must have been built
  with RMASSCAN_SOURCE_COMMIT equal to -Commit and RUSTFLAGS='-C target-feature=+crt-static').
#>
[CmdletBinding()]
param(
    [string]$Commit,
    [string]$OutDir = (Join-Path (Get-Location).Path 'dist'),
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$Root = (Get-Location).Path
if (-not (Test-Path -LiteralPath (Join-Path $Root 'Cargo.toml'))) {
    throw 'run this script from the rmasscan workspace directory (the one with Cargo.toml)'
}
if (-not $Commit) {
    $Commit = (& git -C $Root rev-parse HEAD 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $Commit) { throw 'not a git checkout: pass -Commit <40-hex>' }
}
$Commit = $Commit.Trim().ToLowerInvariant()
if ($Commit -notmatch '^[0-9a-f]{40}$') { throw "bad -Commit '$Commit' (need 40 hex digits)" }
$short = $Commit.Substring(0, 12)
$Name = "rmasscan-wire-windows-x64-$short"

if (-not $SkipBuild) {
    $env:RMASSCAN_SOURCE_COMMIT = $Commit
    # Static MSVC CRT: the EXE then needs neither VCRUNTIME140.dll nor the Visual C++
    # Redistributable on a stock Windows 11 (no C/C++ code of ours is added; this only
    # selects how the Rust runtime links Microsoft's own CRT).
    $prevFlags = $env:RUSTFLAGS
    $env:RUSTFLAGS = '-C target-feature=+crt-static'
    try {
        & cargo build --locked --release -p rmasscan-net --example wire_scan
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
    }
    finally { $env:RUSTFLAGS = $prevFlags }
}
$exe = Join-Path $Root 'target\release\examples\wire_scan.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "missing $exe" }

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("rmasscan-pkg-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    Copy-Item -LiteralPath $exe -Destination (Join-Path $stage 'wire_scan.exe')
    Copy-Item -LiteralPath (Join-Path $Root 'scripts\windows-wire-lab.ps1') -Destination $stage
    Copy-Item -LiteralPath (Join-Path $Root 'LICENSE') -Destination $stage
    Copy-Item -LiteralPath (Join-Path $Root 'NOTICE') -Destination $stage

    $sourceCommit = @"
$Commit

Source of exactly this build (run in a clone of the repository that holds this commit):

  git archive --format=tar --prefix=rmasscan-$short/ $Commit rmasscan | tar -x

Rebuild (Windows x64, Rust toolchain from rmasscan/rust-toolchain.toml, MSVC):

  cd rmasscan-$short\rmasscan
  powershell -NoProfile -File scripts\package-windows-wire.ps1 -Commit $Commit

The EXE embeds this commit (RMASSCAN_SOURCE_COMMIT) and reports it, together with its own
SHA-256, in every JSON it prints.
"@
    [System.IO.File]::WriteAllText((Join-Path $stage 'SOURCE_COMMIT'), ($sourceCommit -replace "`r?`n", "`r`n"), $Utf8NoBom)

    $readme = @"
rmasscan Windows wire lab harness  (commit $short)

WHAT THIS IS
  A lab test harness for the rmasscan Windows/Npcap adapter. It is not a general
  scanner. It sends SYN probes only to targets you name, in the private lab ranges
  10/8, 172.16/12, 192.168/16 and 198.18/15, through an Npcap adapter you name.
  Use it only on an isolated test link that you own.

REQUIREMENTS
  Windows 11 x64, Npcap installed by you (https://npcap.com; this package does not
  contain or install it), Windows PowerShell 5.1 (built in) or PowerShell 7.
  If Npcap was installed in "Administrators only" mode, start PowerShell with
  "Run as administrator".

CHECK THE PACKAGE
  Get-FileHash .\wire_scan.exe -Algorithm SHA256   (compare with SHA256SUMS)

STAGE 1: INVENTORY (no adapter is opened, nothing is sent)
  powershell -NoProfile -ExecutionPolicy Bypass -File .\windows-wire-lab.ps1 -Mode Inventory

  It lists Npcap, the driver, the adapters (use the \Device\NPF_{GUID} name below)
  and this build's identity. Result: wire-result-<time>.zip

STAGE 2: EXPLICIT WIRE RUN (sends packets)
  powershell -NoProfile -ExecutionPolicy Bypass -File .\windows-wire-lab.ps1 ``
    -Mode Run -ConfirmClosedLab ``
    -Interface '\Device\NPF_{GUID}' -SourceIp 198.18.0.1 -RouterMac aa:bb:cc:dd:ee:ff ``
    -Targets 198.18.0.2 -Ports 22,80,443 -Seed 12345

  Every parameter above is required; there are no defaults for a scan. The source MAC is
  the MAC of the chosen adapter. A different -SourceMac is refused (replies would never
  arrive) unless you add -AllowForeignSourceMac.

RESULT
  A folder and a ZIP with inventory.json, reference.pcap, run.json, run.log and
  verdict.txt. The verdict is PASS, FAIL or NOT RUN. Nothing is uploaded or e-mailed:
  send the ZIP yourself if asked.

WHAT THE SCRIPT NEVER DOES
  It never changes UAC, the Npcap driver or service, the firewall, routes, or any
  adapter setting, and it never installs or downloads anything.

SOURCE AND LICENSE
  AGPL-3.0-only, see LICENSE and NOTICE. Source: see SOURCE_COMMIT.
"@
    [System.IO.File]::WriteAllText((Join-Path $stage 'README.txt'), ($readme -replace "`r?`n", "`r`n"), $Utf8NoBom)

    # SHA256SUMS over everything else, sorted by name, LF endings.
    $files = Get-ChildItem -LiteralPath $stage -File | Sort-Object { $_.Name }
    $sumLines = foreach ($f in $files) {
        $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$h *$($f.Name)"
    }
    [System.IO.File]::WriteAllText((Join-Path $stage 'SHA256SUMS'), (($sumLines -join "`n") + "`n"), $Utf8NoBom)

    # Deterministic ZIP.
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $zipPath = Join-Path (Resolve-Path -LiteralPath $OutDir).Path "$Name.zip"
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    Add-Type -AssemblyName System.IO.Compression
    $fs = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::CreateNew)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            $stamp = New-Object System.DateTimeOffset(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
            foreach ($f in (Get-ChildItem -LiteralPath $stage -File | Sort-Object { $_.Name })) {
                $entry = $zip.CreateEntry("$Name/$($f.Name)", [System.IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $stamp
                $es = $entry.Open()
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
                    $es.Write($bytes, 0, $bytes.Length)
                }
                finally { $es.Dispose() }
            }
        }
        finally { $zip.Dispose() }
    }
    finally { $fs.Dispose() }

    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText("$zipPath.sha256", "$zipHash *$Name.zip`n", $Utf8NoBom)
    Write-Host "ZIP:    $zipPath"
    Write-Host "SHA256: $zipHash"
}
finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
