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
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo [+] Elevated permissions granted. Running installation script...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows.ps1"

echo.
echo Press any key to exit installer...
pause >nul
