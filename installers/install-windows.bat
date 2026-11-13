@echo off
title Aegis-Guard Windows Installer (v1.2.0)
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Requesting Administrator privileges via UAC...
    powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

if exist "%~dp0install-windows.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows.ps1" %*
) else (
    echo [!] install-windows.ps1 not found; fetching latest Windows installer...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-windows.ps1 | iex"
)

pause
endlocal
