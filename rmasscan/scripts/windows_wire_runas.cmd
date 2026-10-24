@echo off
rem Guest helper of windows-wire-suite.py: start windows_wire_restricted.cmd under a RESTRICTED token (runas
rem /trustlevel:0x20000) and keep THIS session alive until it has finished: the ssh session's job object kills
rem processes that outlive the session. Usage: windows_wire_runas.cmd ARGVFILE OUTDIR [TIMEOUT_SECONDS]
setlocal
set OUT=%~2
set LIMIT=%~3
if "%LIMIT%"=="" set LIMIT=120
if not exist "%OUT%" mkdir "%OUT%"
if exist "%OUT%\runner.rc" del "%OUT%\runner.rc"
runas /trustlevel:0x20000 "cmd /c %~dp0windows_wire_restricted.cmd %~1 %~2"
set /a n=0
:wait
if exist "%OUT%\runner.rc" goto done
set /a n+=1
if %n% gtr %LIMIT% goto timeout
ping -n 2 127.0.0.1 >nul
goto wait
:done
exit /b 0
:timeout
echo TIMEOUT waiting for the restricted run
exit /b 1
