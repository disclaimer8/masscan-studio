$ErrorActionPreference='Stop'
$sha='931f69fd1eaa0affd160d047b39855843c8cb152'
$out='C:\Users\lab\src\pkg-931f69f'
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
Set-Location C:\Users\lab\src\rmasscan-931f69f\rmasscan
& pwsh -NoProfile -ExecutionPolicy Bypass -File scripts\package-windows-wire.ps1 -Commit $sha -OutDir $out
if ($LASTEXITCODE -ne 0) { throw "package failed $LASTEXITCODE" }
Get-ChildItem $out | Format-Table Name,Length
