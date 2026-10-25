$ErrorActionPreference='Stop'
$p='C:\Users\lab\src\pkg-931f69f'
$z="$p\rmasscan-wire-windows-x64-931f69fd1eaa.zip"
(Get-Content "$z.sha256")
(Get-FileHash $z -Algorithm SHA256).Hash
$x="$p\x"
if (Test-Path $x) { Remove-Item -Recurse -Force $x }
Expand-Archive -LiteralPath $z -DestinationPath $x
$d=(Get-ChildItem $x -Directory | Select-Object -First 1).FullName
$d
$bad=0
foreach ($l in (Get-Content "$d\SHA256SUMS")) {
  $h,$n = $l -split ' \*',2
  $a=(Get-FileHash "$d\$n" -Algorithm SHA256).Hash.ToLower()
  if ($a -eq $h) { "OK $n $a" } else { "MISMATCH $n"; $bad++ }
}
if ($bad) { throw "sums bad" }
Copy-Item -Force "$d\wire_scan.exe" C:\Users\lab\t4\wire_scan.exe
"t4 exe: " + (Get-FileHash C:\Users\lab\t4\wire_scan.exe -Algorithm SHA256).Hash
& pwsh -NoProfile -ExecutionPolicy Bypass -File C:\Users\lab\src\rmasscan-931f69f\rmasscan\scripts\check-dll-search-flag.ps1 -Exe C:\Users\lab\t4\wire_scan.exe
"dllflag exit $LASTEXITCODE"
