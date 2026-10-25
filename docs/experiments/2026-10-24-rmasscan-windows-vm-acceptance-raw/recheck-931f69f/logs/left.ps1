Get-Process wire_scan -ErrorAction SilentlyContinue | Select-Object Id,Path
"guest wire_scan procs: " + @(Get-Process wire_scan -ErrorAction SilentlyContinue).Count
Get-ChildItem C:\Users\lab\t4 | Select-Object Name | Format-Table -HideTableHeaders
