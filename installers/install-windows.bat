@echo off
:: install-windows.bat - Quick one-click administrator wrapper for Windows
:: Aegis-Guard Endpoint & Network Defense

title Aegis-Guard Installer
color 0b

echo.
echo  ==============================================================
echo            AEGIS-GUARD - WINDOWS INSTALLER WRAPPER
echo  ==============================================================
echo.

:: Check for Administrative rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Requesting administrative privileges...
    powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo [+] Elevated permissions granted. Running installation script...
echo.

if exist "%~dp0install-windows.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows.ps1"
) else if exist "%~dp0installers\install-windows.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installers\install-windows.ps1"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-windows.ps1 | iex"
)

echo.
echo Press any key to exit installer...
pause >nul
