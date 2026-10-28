param([string]$Destination = "$env:LOCALAPPDATA\MasscanStudioBuild\sqlite-3.54.1")
$ErrorActionPreference = 'Stop'
# Official prebuilt library: no SQLite C sources or compiler invocation.
$url = 'https://www.sqlite.org/2026/sqlite-dll-win-x64-3540100.zip'
$sha256 = 'f436f53ad8f965af43f3817b42c99c0689e6787f6b7ace208fe38dab7ffc4971'
New-Item -ItemType Directory -Force -Path $Destination | Out-Null
$archive = Join-Path $Destination 'sqlite.zip'
if (!(Test-Path $archive)) { Invoke-WebRequest -Uri $url -OutFile $archive }
if ((Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant() -ne $sha256) {
    throw 'SQLite archive SHA-256 mismatch'
}
Expand-Archive -Path $archive -DestinationPath $Destination -Force
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vs) { throw 'Install the MSVC x64 build tools first' }
$lib = Get-ChildItem "$vs\VC\Tools\MSVC\*\bin\Hostx64\x64\lib.exe" | Sort-Object FullName -Descending | Select-Object -First 1
if (!$lib) { throw 'MSVC lib.exe unavailable' }
& $lib.FullName /nologo /machine:x64 "/def:$Destination\sqlite3.def" "/out:$Destination\sqlite3.lib"
if ($LASTEXITCODE -ne 0) { throw 'Cannot create SQLite import library' }
$env:SQLITE3_LIB_DIR = $Destination
$env:PATH = "$Destination;$env:PATH"
Write-Host "External SQLite ready: $Destination (archive SHA-256 verified)"
