[Console]::OutputEncoding=[Text.Encoding]::UTF8
"os: $((Get-CimInstance Win32_OperatingSystem).Caption) $((Get-CimInstance Win32_OperatingSystem).Version)"
"npcap.sys: $((Get-Item C:\Windows\System32\drivers\npcap.sys).VersionInfo.FileVersion)"
"wpcap.dll: $((Get-Item C:\Windows\System32\Npcap\wpcap.dll).VersionInfo.FileVersion) sha256 $((Get-FileHash C:\Windows\System32\Npcap\wpcap.dll).Hash.ToLower())"
"Packet.dll: $((Get-Item C:\Windows\System32\Npcap\Packet.dll).VersionInfo.FileVersion)"
"npcap service: $((Get-Service npcap).Status)"
"AdminOnly: $((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\npcap\Parameters' -ErrorAction SilentlyContinue).AdminOnly)"
"rustc: $(rustc --version)"
"nic: $((Get-NetAdapter -Name 'Ethernet 2').InterfaceDescription) $((Get-NetAdapter -Name 'Ethernet 2').LinkSpeed)"
