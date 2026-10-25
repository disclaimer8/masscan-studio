[Console]::OutputEncoding=[Text.Encoding]::UTF8
"captured_utc=" + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
"os=" + (Get-CimInstance Win32_OperatingSystem).Version + " (captured after update 26300.9711)"
"--- registry HKLM:\SYSTEM\CurrentControlSet\Services\npcap\Parameters"
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\npcap\Parameters | Select AdminOnly,WinPcapCompatible,Dot11Support,LoopbackSupport | Format-List
"service=" + (Get-Service npcap).Status
foreach($p in 'C:\Windows\System32\Npcap\wpcap.dll','C:\Windows\System32\Npcap\Packet.dll','C:\Windows\System32\drivers\npcap.sys'){
  $i=Get-Item $p; $s=Get-AuthenticodeSignature $p
  "$p version=$($i.VersionInfo.FileVersion) sha256=$((Get-FileHash $p).Hash) sig=$($s.Status) signer=$($s.SignerCertificate.Subject)"
}
"legacy System32\wpcap.dll present=" + (Test-Path C:\Windows\System32\wpcap.dll) + "; System32\Packet.dll present=" + (Test-Path C:\Windows\System32\Packet.dll)
"--- installer"
$p='C:\Users\lab\npcap-1.90.exe'; "$p sha256=$((Get-FileHash $p).Hash) sig=$((Get-AuthenticodeSignature $p).Status) signer=$((Get-AuthenticodeSignature $p).SignerCertificate.Subject)"
