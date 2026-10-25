# Guest helper of rmasscan-lab windows-suite: creates the per-suite input and checkpoint directories.
# Run as a file (pwsh -NoProfile -File), never through -Command, so no shell layer re-parses the arguments.
#   pwsh -NoProfile -File windows_wire_prepare.ps1 -Suite functional -RunId r0123...
param(
    [Parameter(Mandatory)][string]$Suite,
    [Parameter(Mandatory)][string]$RunId
)
$ErrorActionPreference = 'Stop'
foreach ($v in @($Suite, $RunId)) {
    if ($v -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$' -or $v.Contains('..')) { throw "unsafe identifier: $v" }
}
$root = 'C:\Users\lab\t4'
New-Item -ItemType Directory -Force -Path (Join-Path $root 'in'), (Join-Path $root "cp\$Suite\$RunId") | Out-Null
