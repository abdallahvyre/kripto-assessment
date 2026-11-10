@echo off
setlocal
color 0F
cd /d "%~dp0"
title K R Y P T O

if defined KRIPTO_NO_ELEVATE goto run

net session >nul 2>&1
if not errorlevel 1 goto run

mshta "javascript:var s=new ActiveXObject('Shell.Application');s.ShellExecute('%~f0','','%~dp0','runas',1);close();"
if errorlevel 1 (
    echo Elevation was cancelled or failed.
    timeout /t 3 >nul
)
exit /b 0

:run
title K R Y P T O
prompt Enter Your Command Krypto !$G
chcp 65001 >nul
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
set "COLORTERM=truecolor"
set "TERM=xterm-256color"
set "NO_COLOR="
set "KRIPTO_LAUNCHER=1"
if not defined WT_SESSION mode con: cols=144 lines=44 >nul 2>&1

set "PY=python"
where python >nul 2>&1 || set "PY=py -3"

%PY% "%~dp0main.py" %*
set "KRIPTO_EXIT_CODE=%errorlevel%"

if defined KRIPTO_NO_PAUSE exit /b %KRIPTO_EXIT_CODE%
echo.
pause
exit /b %KRIPTO_EXIT_CODE%
