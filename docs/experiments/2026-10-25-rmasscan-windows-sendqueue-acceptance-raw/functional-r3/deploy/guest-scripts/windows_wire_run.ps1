# Guest side of rmasscan-lab windows-suite (stage 2B-Windows, task 4A). pwsh 7:
#   pwsh -NoProfile -File windows_wire_run.ps1 -ArgvFile in\TAG.argv.json -OutDir out\TAG
# Reads {"exe": "...", "argv": ["--iface", ...]} and runs the EXE with the argv ARRAY: no shell quoting, no
# Invoke-Expression. Writes stdout.txt, stderr.txt, exit.txt and runner.json (exe sha256, UTC times) into OutDir.
# Never changes firewall, routes, adapters, services or the Npcap driver.
param(
    [Parameter(Mandatory)][string]$ArgvFile,
    [Parameter(Mandatory)][string]$OutDir,
    [string]$NicName = 'Ethernet 2'
)
$ErrorActionPreference = 'Stop'
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$spec = Get-Content -Raw -LiteralPath $ArgvFile | ConvertFrom-Json
$exe = [string]$spec.exe
$argv = @($spec.argv | ForEach-Object { [string]$_ })
if (Test-Path -LiteralPath $OutDir) { throw 'Refusing to reuse a previous run output directory' }
New-Item -ItemType Directory -Path $OutDir | Out-Null
# Receive statistics of the lab NIC before and after: an independent count (NIC driver level, not Npcap) used to
# cross-check the measured Npcap drops of the RX overflow run. A failure to read them is recorded, never hidden.
function Get-NicSample {
    try {
        $st = Get-NetAdapterStatistics -Name $NicName -ErrorAction Stop |
            Select-Object ReceivedUnicastPackets, ReceivedMulticastPackets, ReceivedBroadcastPackets, ReceivedDiscardedPackets, ReceivedPacketErrors, SentUnicastPackets
        return [ordered]@{ utc = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0; stats = $st }
    }
    catch { return [ordered]@{ utc = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0; error = "$($_.Exception.Message)" } }
}
$nicBefore = Get-NicSample
$exeHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
$t0 = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
$err = Join-Path $OutDir 'stderr.txt'
$ErrorActionPreference = 'Continue'
$out = @(& $exe @argv 2> $err)
$code = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
$nicAfter = Get-NicSample
$t1 = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
[System.IO.File]::WriteAllText((Join-Path $OutDir 'stdout.txt'), (($out | ForEach-Object { [string]$_ }) -join "`n") + "`n", $Utf8)
[System.IO.File]::WriteAllText((Join-Path $OutDir 'exit.txt'), "$code`n", $Utf8)
[System.IO.File]::WriteAllText((Join-Path $OutDir 'nic.json'), ([ordered]@{ nic = $NicName; before = $nicBefore; after = $nicAfter } | ConvertTo-Json -Depth 5), $Utf8)
$runner = [ordered]@{ exe = $exe; exe_sha256 = $exeHash; argc = $argv.Count; times = [ordered]@{ started_utc = $t0; finished_utc = $t1 } }
[System.IO.File]::WriteAllText((Join-Path $OutDir 'runner.json'), ($runner | ConvertTo-Json -Depth 4), $Utf8)
exit 0
