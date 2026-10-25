$ErrorActionPreference='Stop'
$t='C:\Users\lab\src\plant-931f69f'
if (Test-Path $t) { Remove-Item -Recurse -Force $t }
New-Item -ItemType Directory $t | Out-Null
Copy-Item C:\Users\lab\t4\wire_scan.exe $t\wire_scan.exe
$o = & $t\wire_scan.exe --help 2>&1 | Out-String
"CONTROL exit=$LASTEXITCODE"; ($o -split "`n" | Select-Object -First 3) -join "`n"
foreach ($n in 'version.dll','iphlpapi.dll') {
  [IO.File]::WriteAllText("$t\$n", "this is not a dll, planted by lab check`n")
  $o = & $t\wire_scan.exe --help 2>&1 | Out-String
  "PLANT $n exit=$LASTEXITCODE len=$($o.Length)"; ($o -split "`n" | Select-Object -First 3) -join "`n"
  Remove-Item "$t\$n"
}
Remove-Item -Recurse -Force $t
"scratch removed: " + (-not (Test-Path $t))
