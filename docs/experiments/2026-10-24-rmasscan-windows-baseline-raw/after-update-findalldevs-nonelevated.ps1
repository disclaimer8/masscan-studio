# launch fd-ts.ps1 with a limited (non-elevated) token; output to file
Remove-Item C:\Users\lab\fd-nonelev.out -ErrorAction SilentlyContinue
$p = Start-Process -FilePath cmd.exe -ArgumentList '/c runas /trustlevel:0x20000 "cmd /c pwsh -NoProfile -File C:\Users\lab\fd-ts.ps1 > C:\Users\lab\fd-nonelev.out 2>&1"' -PassThru -WindowStyle Hidden
$p.WaitForExit(20000) | Out-Null
Start-Sleep 8
if(Test-Path C:\Users\lab\fd-nonelev.out){ Get-Content C:\Users\lab\fd-nonelev.out } else { "NO OUTPUT; runas exit=$($p.ExitCode)" }
