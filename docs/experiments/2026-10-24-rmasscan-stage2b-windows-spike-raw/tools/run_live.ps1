# Guest side: runs one opt-in live test of the exact built commit. pwsh 7.
param(
    [Parameter(Mandatory)][string]$Tag,
    [Parameter(Mandatory)][string]$Test,
    [Parameter(Mandatory)][string]$Cond,
    [Parameter(Mandatory)][string]$Sha,
    [string]$Extra = '',
    [switch]$SampleStatus
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$out = "C:\Users\lab\spike\out\$Tag"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$exe = Get-ChildItem "C:\Users\lab\src\rmasscan-$Sha\rmasscan\target\debug\deps\rmasscan_net-*.exe" |
    Where-Object { $_.Extension -eq '.exe' } | Sort-Object LastWriteTime | Select-Object -Last 1
$env:RMASSCAN_NPCAP_LAB_DEVICE = '\Device\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}'
$env:RMASSCAN_NPCAP_LAB_SRC_MAC = '52:54:00:04:80:a9'
$env:RMASSCAN_NPCAP_LAB_PEER_MAC = '02:57:4c:3d:2e:9b'
$env:RMASSCAN_NPCAP_OUT_DIR = $out
$env:RMASSCAN_NPCAP_COND = $Cond
foreach ($kv in ($Extra -split ',' | Where-Object { $_ })) {
    $k, $v = $kv -split '=', 2
    Set-Item -Path "env:$k" -Value $v
}
function Nic {
    $s = Get-NetAdapterStatistics -Name 'Ethernet 2' | Select-Object ReceivedBytes, ReceivedUnicastPackets, ReceivedDiscardedPackets, ReceivedPacketErrors, SentBytes, SentUnicastPackets, OutboundDiscardedPackets, OutboundPacketErrors
    $a = Get-NetAdapter -Name 'Ethernet 2' | Select-Object Status, LinkSpeed, MediaConnectionState
    [pscustomobject]@{ utc_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); stats = $s; adapter = $a } | ConvertTo-Json -Compress -Depth 4
}
"exe: $($exe.FullName)" | Out-File "$out\$Test.run.txt" -Encoding utf8
"nic_before: $(Nic)" | Out-File "$out\$Test.run.txt" -Append -Encoding utf8
$sampler = $null
if ($SampleStatus) {
    $sampler = Start-ThreadJob -ScriptBlock {
        param($path)
        while ($true) {
            $a = Get-NetAdapter -Name 'Ethernet 2' | Select-Object -ExpandProperty Status
            "$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) $a" | Out-File $path -Append -Encoding ascii
            Start-Sleep -Milliseconds 500
        }
    } -ArgumentList "$out\$Test.nic-status.txt"
}
$sw = [Diagnostics.Stopwatch]::StartNew()
& $exe.FullName --ignored --exact "windows::live::$Test" --nocapture --test-threads=1 *> "$out\$Test.log"
$code = $LASTEXITCODE
$sw.Stop()
if ($sampler) { Stop-Job $sampler; Remove-Job $sampler -Force }
"exit_code: $code elapsed_ms: $($sw.ElapsedMilliseconds)" | Out-File "$out\$Test.run.txt" -Append -Encoding utf8
"nic_after: $(Nic)" | Out-File "$out\$Test.run.txt" -Append -Encoding utf8
Get-Process -Name 'rmasscan_net-*' -ErrorAction SilentlyContinue | ForEach-Object { "LEFTOVER process $($_.Id)" | Out-File "$out\$Test.run.txt" -Append -Encoding utf8 }
Write-Output "exit_code=$code elapsed_ms=$($sw.ElapsedMilliseconds)"
exit $code
