<#
.SYNOPSIS
  User-facing wrapper for the rmasscan Windows wire lab harness (wire_scan.exe).
  Works on Windows PowerShell 5.1 (the only PowerShell on a stock Windows 11) and on PowerShell 7.

.DESCRIPTION
  Two explicit stages. Nothing here runs a scan by default.

  Stage 1: -Mode Inventory
    Lists Npcap, adapters, versions and the build identity. No adapter is opened and no
    packet is sent. Result: <OutDir>\inventory.json, verdict.txt, <OutDir>.zip

  Stage 2: -Mode Run -ConfirmClosedLab ...
    Sends SYN probes ONLY to the explicitly given lab targets, through the explicitly given
    Npcap adapter. Targets must be private/lab addresses (10/8, 172.16/12, 192.168/16,
    198.18/15) and at most 65536 addresses. The source MAC defaults to the MAC of the chosen
    adapter; a different MAC is refused (replies would never arrive) unless
    -AllowForeignSourceMac is given.
    Result: inventory.json, reference.pcap, run.json, run.log, verdict.txt (PASS / FAIL /
    NOT RUN), packed into <OutDir>.zip. Nothing is uploaded or e-mailed.

  This script never changes UAC, the Npcap driver or service, the firewall, routes or any
  adapter setting. When rights are missing it prints instructions and exits non-zero.

  Exit codes: 0 PASS (or inventory ok), 1 FAIL, 2 NOT RUN, 5 Npcap missing or access denied.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\windows-wire-lab.ps1 -Mode Inventory

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\windows-wire-lab.ps1 -Mode Run -ConfirmClosedLab `
    -Interface '\Device\NPF_{11111111-2222-3333-4444-555555555555}' -SourceIp 198.18.0.1 `
    -RouterMac 02:00:00:00:00:22 -Targets 198.18.0.2 -Ports 22,80,443 -Seed 12345
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Inventory', 'Run')][string]$Mode,
    [string]$Interface,
    [string]$SourceIp,
    [string]$SourceMac,
    [switch]$AllowForeignSourceMac,
    [string]$RouterMac,
    [string]$Targets,
    [string]$Ports,
    [UInt64]$Seed = 0,
    [double]$Rate = 100,
    [int]$Wait = 3,
    [string]$SourcePort = '40000',
    [switch]$ConfirmClosedLab,
    [string]$OutDir,
    [string]$ExePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
# Not a param() default: $PSScriptRoot is empty there on Windows PowerShell 5.1.
if (-not $ExePath) { $ExePath = Join-Path $PSScriptRoot 'wire_scan.exe' }
$script:Notes = New-Object System.Collections.Generic.List[string]

function Write-Text([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, $Text, $Utf8NoBom)
}

function Write-Instructions {
    Write-Host ''
    Write-Host 'Npcap is missing, or this session has no right to use it.' -ForegroundColor Yellow
    Write-Host '  * Nothing was changed. This script never edits UAC, the driver, services or the firewall.'
    Write-Host '  * If Npcap is not installed: install it yourself from https://npcap.com (this package'
    Write-Host '    does not contain or download it).'
    Write-Host '  * If Npcap was installed in "Administrators only" mode: close this window, open'
    Write-Host '    PowerShell with "Run as administrator" (right click) and run the same command again.'
    Write-Host '  * A restricted or non-elevated token cannot use an Administrators-only Npcap; that is by design.'
    Write-Host ''
}

function Finish([string]$Verdict, [string[]]$Reasons, [int]$Code) {
    $lines = @($Verdict) + @($Reasons | ForEach-Object { "- $_" }) + @($script:Notes | ForEach-Object { "note: $_" })
    Write-Text (Join-Path $OutDir 'verdict.txt') (($lines -join "`r`n") + "`r`n")
    $zip = "$OutDir.zip"
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $zip -Force
    Write-Host ''
    Write-Host "RESULT: $Verdict"
    foreach ($r in $Reasons) { Write-Host "  - $r" }
    Write-Host "Archive: $zip"
    Write-Host 'Nothing was uploaded or sent. Attach the archive to your report yourself if asked.'
    exit $Code
}

# ---------------------------------------------------------------- validation ----

function ConvertTo-IpNumber([string]$Text) {
    if ($Text -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') { throw "not an IPv4 address: '$Text'" }
    $v = [uint64]0
    foreach ($i in 1..4) {
        $o = [int]$Matches[$i]
        if ($o -gt 255) { throw "not an IPv4 address: '$Text'" }
        $v = $v * 256 + $o
    }
    return $v
}

function Test-LabAddress([uint64]$A) {
    $ranges = @(
        @('10.0.0.0', '10.255.255.255'),
        @('172.16.0.0', '172.31.255.255'),
        @('192.168.0.0', '192.168.255.255'),
        @('198.18.0.0', '198.19.255.255'))
    foreach ($r in $ranges) {
        if ($A -ge (ConvertTo-IpNumber $r[0]) -and $A -le (ConvertTo-IpNumber $r[1])) { return $true }
    }
    return $false
}

function Test-LabTargets([string]$Text) {
    $total = [uint64]0
    foreach ($tok in $Text.Split(',')) {
        $t = $tok.Trim()
        if ($t -match '^([\d.]+)/(\d{1,2})$') {
            $len = [int]$Matches[2]
            if ($len -lt 16 -or $len -gt 32) { throw "target '$t': prefix length must be 16..32" }
            $size = [uint64][math]::Pow(2, 32 - $len)
            $base = ConvertTo-IpNumber $Matches[1]
            $lo = $base - ($base % $size)
            $hi = $lo + $size - 1
        }
        elseif ($t -match '^([\d.]+)-([\d.]+)$') {
            $lo = ConvertTo-IpNumber $Matches[1]
            $hi = ConvertTo-IpNumber $Matches[2]
            if ($hi -lt $lo) { throw "target '$t': range end is below its start" }
        }
        else {
            $lo = ConvertTo-IpNumber $t
            $hi = $lo
        }
        if (-not (Test-LabAddress $lo) -or -not (Test-LabAddress $hi)) {
            throw "target '$t' is outside the allowed lab ranges (10/8, 172.16/12, 192.168/16, 198.18/15)"
        }
        $total += ($hi - $lo + 1)
    }
    if ($total -gt 65536) { throw "targets cover $total addresses; the limit is 65536" }
}

function Test-Ports([string]$Text) {
    if ($Text -notmatch '^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$') { throw "bad -Ports '$Text' (use 80,443 or 1-1024)" }
    $count = 0
    foreach ($tok in $Text.Split(',')) {
        $p = $tok.Split('-')
        $a = [int]$p[0]
        $b = [int]$p[$p.Length - 1]
        if ($a -lt 1 -or $b -gt 65535 -or $b -lt $a) { throw "bad port range '$tok'" }
        $count += ($b - $a + 1)
    }
    if ($count -gt 4096) { throw "-Ports selects $count ports; the limit is 4096" }
}

function ConvertTo-MacText([string]$Text, [string]$Name) {
    if ($Text -notmatch '^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$') { throw "bad $Name '$Text' (use aa:bb:cc:dd:ee:ff)" }
    return ($Text.Replace('-', ':')).ToLowerInvariant()
}

# ------------------------------------------------------------------- setup ----

if (-not $OutDir) {
    $OutDir = Join-Path (Get-Location).Path ('wire-result-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
}
$OutDir = [System.IO.Path]::GetFullPath($OutDir)
if (Test-Path -LiteralPath $OutDir) {
    if ((Get-ChildItem -LiteralPath $OutDir -Force | Measure-Object).Count -ne 0) {
        Write-Host "Refusing to reuse a non-empty result directory: $OutDir" -ForegroundColor Red
        exit 2
    }
}
else {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}
$logPath = Join-Path $OutDir 'run.log'
Write-Text $logPath ''
function Log([string]$m) {
    [System.IO.File]::AppendAllText($logPath, ([DateTime]::UtcNow.ToString('o') + ' ' + $m + "`r`n"), $Utf8NoBom)
}
Log "wrapper start mode=$Mode powershell=$($PSVersionTable.PSVersion)"

# Package integrity: the EXE must match SHA256SUMS shipped next to it.
if (-not (Test-Path -LiteralPath $ExePath)) {
    Finish 'NOT RUN' @("wire_scan.exe not found at $ExePath") 2
}
$exeHash = (Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash.ToLowerInvariant()
$sums = Join-Path (Split-Path -Parent $ExePath) 'SHA256SUMS'
if (Test-Path -LiteralPath $sums) {
    $expected = $null
    foreach ($line in Get-Content -LiteralPath $sums) {
        if ($line -match '^([0-9a-fA-F]{64}) \*?(.+)$' -and $Matches[2] -eq (Split-Path -Leaf $ExePath)) { $expected = $Matches[1].ToLowerInvariant() }
    }
    if ($expected -and $expected -ne $exeHash) {
        Finish 'NOT RUN' @("wire_scan.exe does not match SHA256SUMS (expected $expected, found $exeHash); the package is damaged or modified") 2
    }
    if (-not $expected) { $script:Notes.Add('SHA256SUMS has no entry for the EXE') }
}
else {
    $script:Notes.Add('SHA256SUMS not found next to the EXE; integrity not verified')
}
Log "exe sha256=$exeHash"

function Invoke-Harness([string[]]$ArgList, [string]$StdoutFile) {
    # Argument ARRAY: no Invoke-Expression, no command line built from strings.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $errFile = $StdoutFile + '.stderr'
        # Capture into a variable and write UTF-8 ourselves: on Windows PowerShell 5.1 the
        # redirection operator writes UTF-16.
        $out = @(& $ExePath @ArgList 2> $errFile)
        $code = $LASTEXITCODE
        Write-Text $StdoutFile ((($out | ForEach-Object { [string]$_ }) -join "`n") + "`n")
        if (Test-Path -LiteralPath $errFile) {
            $e = Get-Content -Raw -LiteralPath $errFile
            if ($e) { Log ("stderr: " + $e.Trim()) }
            Remove-Item -LiteralPath $errFile -Force
        }
    }
    finally { $ErrorActionPreference = $prev }
    return $code
}

# ------------------------------------------------------------ stage 1: inventory ----

$invFile = Join-Path $OutDir 'inventory.json'
$invCode = Invoke-Harness @('--inventory') $invFile
Log "inventory exit=$invCode"
$inv = $null
if (Test-Path -LiteralPath $invFile) {
    $raw = Get-Content -Raw -LiteralPath $invFile
    if ($raw) { try { $inv = $raw | ConvertFrom-Json } catch { $inv = $null } }
}

if ($invCode -eq 5) {
    Write-Instructions
    Finish 'NOT RUN' @('Npcap is missing or access is denied (see the instructions printed above)') 5
}
if ($invCode -ne 0 -or $null -eq $inv) {
    Finish 'NOT RUN' @("inventory failed with exit code $invCode (see inventory.json)") 2
}

Write-Host "Npcap:     $($inv.npcap.lib_version)"
Write-Host "Driver:    $($inv.npcap.driver_version)"
Write-Host "Source:    $($inv.identity.source_commit)"
Write-Host "EXE sha256 $($inv.identity.binary_sha256)"
Write-Host "Elevated:  $($inv.identity.elevated)   restricted token: $($inv.identity.restricted_token)"
Write-Host 'Adapters (use the NPF name with -Interface):'
foreach ($d in $inv.devices) {
    $loop = ''
    if ($d.loopback) { $loop = ' [loopback, not usable]' }
    Write-Host ("  {0}  mac={1}  {2}{3}" -f $d.name, $d.mac, $d.description, $loop)
}

if ($Mode -eq 'Inventory') {
    Finish 'PASS' @('inventory completed; no adapter was opened and no packet was sent') 0
}

# ---------------------------------------------------------------- stage 2: run ----

if (-not $ConfirmClosedLab) {
    Finish 'NOT RUN' @('-ConfirmClosedLab is required: this stage sends packets and may only be used on an isolated lab link') 2
}
$missing = @()
foreach ($n in 'Interface', 'SourceIp', 'RouterMac', 'Targets', 'Ports') {
    if (-not (Get-Variable -Name $n -ValueOnly)) { $missing += "-$n" }
}
if ($Seed -eq 0) { $missing += '-Seed (non-zero)' }
if ($missing.Count -gt 0) {
    Finish 'NOT RUN' @("explicit parameters are required, missing: $($missing -join ', ')") 2
}

try {
    if ($Interface -notmatch '^\\Device\\NPF_\{[0-9A-Fa-f-]{36}\}$') { throw "bad -Interface '$Interface' (expected \Device\NPF_{GUID} from the inventory list)" }
    $srcIpNumber = ConvertTo-IpNumber $SourceIp
    if (-not (Test-LabAddress $srcIpNumber)) { throw "-SourceIp $SourceIp is outside the allowed lab ranges" }
    Test-LabTargets $Targets
    Test-Ports $Ports
    $routerMacText = ConvertTo-MacText $RouterMac '-RouterMac'
    if ($Rate -le 0 -or $Rate -gt 100000) { throw '-Rate must be in 1..100000 packets per second' }
    if ($Wait -lt 0 -or $Wait -gt 120) { throw '-Wait must be in 0..120 seconds' }
}
catch {
    Finish 'NOT RUN' @($_.Exception.Message) 2
}

$device = $null
foreach ($d in $inv.devices) { if ($d.name -ieq $Interface) { $device = $d } }
if ($null -eq $device) { Finish 'NOT RUN' @("adapter $Interface is not in the inventory") 2 }
if ($device.loopback) { Finish 'NOT RUN' @("adapter $Interface is the Npcap loopback adapter") 2 }

if ($SourceMac) { $srcMacText = ConvertTo-MacText $SourceMac '-SourceMac' }
elseif ($device.mac) { $srcMacText = [string]$device.mac }
else { Finish 'NOT RUN' @("the MAC of $Interface could not be determined; pass -SourceMac") 2 }

$common = @(
    '--iface', $Interface,
    '--src-ip', $SourceIp,
    '--src-mac', $srcMacText,
    '--router-mac', $routerMacText,
    '--targets', $Targets,
    '--ports', $Ports,
    '--seed', [string]$Seed,
    '--rate', [string]$Rate,
    '--wait', [string]$Wait,
    '--source-port', $SourcePort
)
if ($AllowForeignSourceMac) { $common += '--allow-foreign-source-mac' }

# Reference frames first: offline, no adapter, no DLL.
$refJson = Join-Path $OutDir 'reference.json'
$refPcap = Join-Path $OutDir 'reference.pcap'
$refCode = Invoke-Harness ($common + @('--write-reference-pcap', $refPcap)) $refJson
Log "reference exit=$refCode"
if ($refCode -ne 0) {
    Finish 'NOT RUN' @("the reference pcap could not be produced (exit $refCode, see reference.json); nothing was sent") 2
}

$runFile = Join-Path $OutDir 'run.json'
$runCode = Invoke-Harness $common $runFile
Log "run exit=$runCode"
$run = $null
if (Test-Path -LiteralPath $runFile) {
    $raw = Get-Content -Raw -LiteralPath $runFile
    if ($raw) { try { $run = $raw | ConvertFrom-Json } catch { $run = $null } }
}

if ($runCode -eq 5) {
    Write-Instructions
    Finish 'NOT RUN' @('Npcap access was denied when opening the adapter; nothing was sent') 5
}
if ($runCode -eq 6) {
    $m = ''
    if ($run) { $m = $run.message }
    Finish 'NOT RUN' @("source MAC refused: $m") 2
}
if ($runCode -ne 0 -and $runCode -ne 3) {
    $m = ''
    if ($run) { $m = $run.message }
    Finish 'NOT RUN' @("the harness did not start the scan (exit $runCode): $m") 2
}
if ($null -eq $run) { Finish 'FAIL' @("run.json is missing or not valid JSON (exit $runCode)") 1 }

$problems = @()
if ($run.status -ne 'ok') { $problems += "status is '$($run.status)'" }
if ($run.reason -ne 'Completed') { $problems += "reason is '$($run.reason)' $($run.fail_detail)" }
if ($run.status -eq 'ok') {
    if ($run.sent -ne $run.expected_total) { $problems += "sent $($run.sent) of $($run.expected_total) probes" }
    if ($run.net.tx_uncertain -ne 0) { $problems += "tx_uncertain=$($run.net.tx_uncertain)" }
    if ($run.net.tx_errors -ne 0) { $problems += "tx_errors=$($run.net.tx_errors)" }
    if ($run.net.rx_errors -ne 0) { $problems += "rx_errors=$($run.net.rx_errors)" }
    if ($null -eq $run.rx_health.kernel_drops) { $problems += 'receive drops are unknown (null)' }
    elseif ($run.rx_health.kernel_drops -ne 0) { $problems += "receive drops=$($run.rx_health.kernel_drops)" }
    if ($run.reply_total -eq 0) { $problems += 'no replies at all: check the peer, the router MAC and the source MAC' }
}
if ($problems.Count -gt 0) { Finish 'FAIL' $problems 1 }
Finish 'PASS' @("sent $($run.sent) probes, $($run.reply_total) replies, no TX uncertainty, no receive drops") 0
