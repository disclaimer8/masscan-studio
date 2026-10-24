Get-Date -Format o
[DateTime]::UtcNow.ToString('o')
tzutil /g
(Get-Service w32time).Status
(Get-Service w32time).StartType
w32tm /query /status
$PSVersionTable.PSVersion.ToString()
