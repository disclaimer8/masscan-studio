# Guest helper of rmasscan-lab windows-suite: prints the sha256 (lower case) and the size of one file. pwsh 7.
param([Parameter(Mandatory)][string]$Path)
$ErrorActionPreference = 'Stop'
(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
(Get-Item -LiteralPath $Path).Length
