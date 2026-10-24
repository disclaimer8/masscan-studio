$ErrorActionPreference = 'Stop'
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$tools = [ordered]@{}
foreach ($name in @('pwsh', 'rustc', 'cargo', 'git', 'cmake', 'cl', 'nmap')) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
    $tools[$name] = if ($cmd) { $cmd.Source } else { $null }
}
$drivers = @(Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -match '^(npcap|npf)(_|$)' } | Select-Object Name, State, StartMode, PathName)
$dlls = @()
foreach ($path in @("$env:windir\System32\Npcap\wpcap.dll", "$env:windir\System32\Npcap\Packet.dll")) {
    if (Test-Path -LiteralPath $path) {
        $f = Get-Item -LiteralPath $path
        $dlls += [ordered]@{ path = $f.FullName; version = $f.VersionInfo.FileVersion; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
    }
}
$npcap = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\npcap\Parameters' -ErrorAction SilentlyContinue
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$inventory = [ordered]@{
    collected_utc = [DateTime]::UtcNow.ToString('o')
    computer = $env:COMPUTERNAME
    user = $identity.Name
    administrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    os = [ordered]@{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber; architecture = $os.OSArchitecture }
    cpu = $cpu.Name
    memory_gib = [Math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    powershell = $PSVersionTable.PSVersion.ToString()
    tools = $tools
    known_install_locations = [ordered]@{
        pwsh7 = Test-Path -LiteralPath "$env:ProgramFiles\PowerShell\7\pwsh.exe"
        cargo = Test-Path -LiteralPath "$env:USERPROFILE\.cargo\bin\cargo.exe"
        git = Test-Path -LiteralPath "$env:ProgramFiles\Git\cmd\git.exe"
        vswhere = Test-Path -LiteralPath "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        windows_sdk = Test-Path -LiteralPath "${env:ProgramFiles(x86)}\Windows Kits\10\Include"
    }
    npcap_drivers = $drivers
    npcap_dlls = $dlls
    npcap_admin_only = if ($npcap) { $npcap.AdminOnly } else { $null }
    adapters = @(Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed)
    ipv4 = @(Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, PrefixLength)
    disk = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID, Size, FreeSpace)
}
$inventory | ConvertTo-Json -Depth 6
