$ErrorActionPreference='Stop'
$d='C:\Users\lab\src\rmasscan-931f69f'
if (Test-Path $d) { Remove-Item -Recurse -Force $d }
New-Item -ItemType Directory -Path $d | Out-Null
tar -xf C:\Users\lab\src\src-931f69f.tar -C $d
if ($LASTEXITCODE -ne 0) { throw "tar failed" }
Get-ChildItem $d | Select-Object -ExpandProperty Name
(Get-FileHash C:\Users\lab\src\src-931f69f.tar -Algorithm SHA256).Hash
