@echo off
rem Guest helper of rmasscan-lab windows-suite: start windows_wire_restricted.cmd under a RESTRICTED token (runas
rem /trustlevel:0x20000) and keep THIS session alive until it has finished: the ssh session's job object kills
rem processes that outlive the session. Usage: windows_wire_runas.cmd ARGVFILE OUTDIR [TIMEOUT_SECONDS]
setlocal
set OUT=%~2
set LIMIT=%~3
if "%LIMIT%"=="" set LIMIT=120
if exist "%OUT%" exit /b 2
if exist "%OUT%.runner.rc" exit /b 2
if exist "%OUT%.runner.log" exit /b 2
for %%I in ("%OUT%") do if not exist "%%~dpI" mkdir "%%~dpI"
runas /trustlevel:0x20000 "cmd /c %~dp0windows_wire_restricted.cmd %~1 %~2"
if errorlevel 1 exit /b 1
set /a n=0
:wait
if exist "%OUT%.runner.rc" goto done
set /a n+=1
if %n% gtr %LIMIT% goto timeout
ping -n 2 127.0.0.1 >nul
goto wait
:done
set /p RC=<"%OUT%.runner.rc"
exit /b %RC%
:timeout
echo TIMEOUT waiting for the restricted run
exit /b 1
