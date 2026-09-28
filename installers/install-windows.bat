@echo off
:: Aegis-Guard — elevate and run PowerShell installer

setlocal
cd /d "%~dp0"

if exist "%~dp0install-windows.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows.ps1"
) else (
    echo [!] Missing install-windows.ps1 in installers\
    pause
    exit /b 1
)

endlocal
