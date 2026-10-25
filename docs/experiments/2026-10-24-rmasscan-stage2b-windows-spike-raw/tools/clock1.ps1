tzutil /s "UTC"
tzutil /g
Start-Service w32time
Start-Sleep 2
w32tm /resync /force
Start-Sleep 2
w32tm /query /status
Get-Date -Format o
[DateTime]::UtcNow.ToString('o')
