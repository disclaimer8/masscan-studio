[Console]::OutputEncoding=[Text.Encoding]::UTF8
(Get-FileHash C:\Users\lab\npcap-1.90.exe).Hash
Get-AuthenticodeSignature C:\Users\lab\npcap-1.90.exe | % { $_.Status; $_.SignerCertificate.Subject }
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\npcap\Parameters | Format-List
Get-Service npcap | % Status
foreach($f in 'wpcap.dll','Packet.dll'){ $p="C:\Windows\System32\Npcap\$f"; "$f $((Get-Item $p).VersionInfo.FileVersion) $((Get-FileHash $p).Hash) $((Get-AuthenticodeSignature $p).Status)" }
Get-Process | ? Name -match 'npcap'
