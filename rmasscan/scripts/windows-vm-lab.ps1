# Guest side of the isolated Windows VM lab (stage 2B-Windows, task 2). Run with pwsh 7+:
#   pwsh -NoProfile -File windows-vm-lab.ps1 -Manifest manifest.json -Action Inventory|Configure|Verify
# Inventory: list adapters (MAC, GUID, NPF name, IPs, default route) -> <Manifest>.inventory.json
# Configure: find the lab NIC by the manifest MAC (must be unique), assign ONLY lab IP /30,
#            no gateway, no DNS; refuse when the match is the management NIC. -> <Manifest>.guest.json
# Verify:    lab NIC Status Up (same GUID/MAC), lab IP present, no gateway/DNS on lab NIC, management NIC + default route unchanged.
# Never touches firewall, other adapters, default routes or DNS of the management NIC. No secrets.
param(
    [Parameter(Mandatory)][string]$Manifest,
    [Parameter(Mandatory)][ValidateSet('Inventory', 'Configure', 'Verify')][string]$Action
)
$ErrorActionPreference = 'Stop'
$m = Get-Content -Raw -LiteralPath $Manifest | ConvertFrom-Json
$labMac = ($m.names.windows_mac -replace ':', '-').ToUpper()
$labIp = $m.lab.windows_ip
$prefix = [int]$m.lab.prefix
$mgmtPrefix = '10.0.2.'
$mgmtMac = '52-54-00-12-34-56'   # QEMU default MAC of the management NIC

function Get-Inventory {
    $adapters = @(Get-NetAdapter -Physical:$false -IncludeHidden:$false | ForEach-Object {
            $ips = @(Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
            [pscustomobject]@{
                Name = $_.Name; ifIndex = $_.ifIndex; MacAddress = $_.MacAddress; Status = "$($_.Status)"
                InterfaceGuid = $_.InterfaceGuid; Npf = "\Device\NPF_$($_.InterfaceGuid)"; IPv4 = $ips
            } })
    $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            ForEach-Object { [pscustomobject]@{ ifIndex = $_.ifIndex; NextHop = $_.NextHop; Metric = $_.RouteMetric } })
    [pscustomobject]@{ adapters = $adapters; default_routes = $routes }
}

function Select-Lab($inv) {
    $hits = @($inv.adapters | Where-Object { $_.MacAddress -eq $labMac })
    if ($hits.Count -gt 1) { throw "lab NIC ambiguous: $($hits.Count) adapters match MAC $labMac" }
    if ($hits.Count -eq 0) { throw "lab NIC not found by MAC $labMac" }
    if ($labMac -eq $mgmtMac) { throw 'refusing: manifest MAC is the management NIC' }
    $hits[0]
}

$inv = Get-Inventory
switch ($Action) {
    'Inventory' {
        $inv | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$Manifest.inventory.json" -Encoding utf8
        $inv | ConvertTo-Json -Depth 6
    }
    'Configure' {
        $lab = Select-Lab $inv
        if (@($lab.IPv4 | Where-Object { $_ -like "$mgmtPrefix*" }).Count -gt 0) { throw "refusing: matched adapter carries the management address" }
        if (@($inv.default_routes | Where-Object { $_.ifIndex -eq $lab.ifIndex }).Count -gt 0) { throw "refusing: lab NIC owns a default route" }
        $before = $inv
        Get-NetIPAddress -InterfaceIndex $lab.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -ne $labIp } | Remove-NetIPAddress -Confirm:$false
        if (-not (Get-NetIPAddress -InterfaceIndex $lab.ifIndex -IPAddress $labIp -ErrorAction SilentlyContinue)) {
            New-NetIPAddress -InterfaceIndex $lab.ifIndex -IPAddress $labIp -PrefixLength $prefix | Out-Null   # no -DefaultGateway
        }
        Set-DnsClientServerAddress -InterfaceIndex $lab.ifIndex -ResetServerAddresses
        Set-DnsClient -InterfaceIndex $lab.ifIndex -RegisterThisConnectionsAddress $false
        $after = Get-Inventory
        $out = [pscustomobject]@{ lab = (Select-Lab $after); adapters = $after.adapters; default_routes_before = $before.default_routes; default_routes_after = $after.default_routes }
        $out | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$Manifest.guest.json" -Encoding utf8
        $out.lab | ConvertTo-Json -Depth 4
    }
    'Verify' {
        $lab = Select-Lab $inv
        $errs = @()
        if ($lab.Status -ne 'Up') { $errs += "lab NIC Status is '$($lab.Status)', expected 'Up'" }
        if ($m.guest.guid -and $lab.InterfaceGuid -ne $m.guest.guid) { $errs += "lab NIC GUID $($lab.InterfaceGuid) differs from recorded $($m.guest.guid)" }
        if ($lab.IPv4 -notcontains "$labIp/$prefix") { $errs += "lab IP $labIp/$prefix missing" }
        $extra = @($lab.IPv4 | Where-Object { $_ -ne "$labIp/$prefix" -and $_ -notlike '169.254.*' })   # APIPA link-local is not routable off-link
        if ($extra.Count -gt 0) { $errs += "lab NIC has extra IPv4 addresses: $($extra -join ',')" }
        if (@($inv.default_routes | Where-Object { $_.ifIndex -eq $lab.ifIndex }).Count -gt 0) { $errs += 'lab NIC has a default route/gateway' }
        $dns = @((Get-DnsClientServerAddress -InterfaceIndex $lab.ifIndex -AddressFamily IPv4).ServerAddresses)
        if ($dns.Count -gt 0) { $errs += "lab NIC has DNS servers: $($dns -join ',')" }
        $mgmt = @($inv.adapters | Where-Object { $_.IPv4 | Where-Object { $_ -like "$mgmtPrefix*" } })
        if ($mgmt.Count -ne 1) { $errs += "management NIC (10.0.2.x) count = $($mgmt.Count)" }
        if (@($inv.default_routes | Where-Object { $mgmt.Count -eq 1 -and $_.ifIndex -eq $mgmt[0].ifIndex }).Count -ne 1) { $errs += 'default route is not exactly via the management NIC' }
        $res = [pscustomobject]@{ ok = ($errs.Count -eq 0); errors = $errs; lab = $lab; npf = $lab.Npf }
        $res | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath "$Manifest.verify.json" -Encoding utf8
        $res | ConvertTo-Json -Depth 4
        if ($errs.Count) { exit 1 }
    }
}
