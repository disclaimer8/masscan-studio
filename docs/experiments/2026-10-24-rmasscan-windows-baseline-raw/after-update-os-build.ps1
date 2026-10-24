"captured_utc=" + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$k=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
"CurrentBuild=$($k.CurrentBuild) UBR=$($k.UBR) DisplayVersion=$($k.DisplayVersion)"
