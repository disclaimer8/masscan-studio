<#
.SYNOPSIS
  Fails unless a Windows image carries Dependent Load Flag 0x800 (LOAD_LIBRARY_SEARCH_SYSTEM32).

.DESCRIPTION
  Reads the image's load config with dumpbin from the newest Visual Studio C++ tools (found through
  vswhere) and throws unless the "Dependent Load Flag" line shows 0x800. Used by CI on the packaged
  wire_scan.exe and by the live lab re-check on the guest. Sends nothing and changes nothing.
#>
param(
  [Parameter(Mandatory = $true)][string]$Exe
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { throw "no such file: $Exe" }
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw "vswhere not found: $vswhere" }
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'no Visual Studio installation with the C++ x64 tools' }
$dumpbin = Get-ChildItem -Path (Join-Path $vs 'VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe') |
  Sort-Object FullName | Select-Object -Last 1
if (-not $dumpbin) { throw "dumpbin.exe not found under $vs" }
$out = & $dumpbin.FullName /nologo /loadconfig $Exe
if ($LASTEXITCODE -ne 0) { throw "dumpbin failed ($LASTEXITCODE)" }
$line = $out | Select-String -Pattern 'Dependent Load Flag' | Select-Object -First 1
if (-not $line) { throw "no Dependent Load Flag line in the load config of $Exe" }
if ($line.Line -notmatch '(^|\s)0*800(\s|$)') { throw "Dependent Load Flag is not 0x800: $($line.Line.Trim())" }
Write-Output "OK $Exe : $($line.Line.Trim())"
