param([string]$Checkout = "$HOME\studio-integration-20261025")
$ErrorActionPreference = 'Stop'
function Checked([scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "Command failed: $Command (exit $LASTEXITCODE)" }
}
Set-Location (Join-Path $Checkout 'studio')
. "$PSScriptRoot\windows-sqlite.ps1"
New-Item -ItemType Directory -Force verification | Out-Null
Checked { cargo xtask test }
Checked { cargo xtask build }
$package = Get-ChildItem dist -Directory | Sort-Object Name -Descending | Select-Object -First 1
$env:STUDIO_DATA_DIR = Join-Path $env:TEMP ('studio-smoke-' + [guid]::NewGuid().ToString('N'))
$env:SLINT_BACKEND = 'winit-software'
$env:STUDIO_SCREENSHOT = Join-Path $PWD 'verification\windows.png'
Checked { & (Join-Path $package.FullName 'studio-ui.exe') --smoke-pause }
Write-Host 'PASS: packaged Studio Start/Pause/Resume/Stop, software rendering. Simulation only.'
