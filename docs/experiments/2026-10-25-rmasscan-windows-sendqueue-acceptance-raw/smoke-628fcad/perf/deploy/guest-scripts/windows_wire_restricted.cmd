@echo off
rem Guest helper of rmasscan-lab windows-suite: runs the argv-array runner (pwsh 7) inside whatever token started this
rem script (the suite starts it with: runas /trustlevel:0x20000 "cmd /c windows_wire_restricted.cmd ARGVFILE OUTDIR").
rem The full pwsh path is used because the reduced-trust process does not get the interactive PATH.
"C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -File "%~dp0windows_wire_run.ps1" -ArgvFile "%~1" -OutDir "%~2" > "%~2.runner.log" 2>&1
echo %errorlevel% > "%~2.runner.rc"
