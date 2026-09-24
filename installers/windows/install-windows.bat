@echo off
:: ==============================================================================
::  Aegis-Guard 1-Click Auto Installer for Windows
::  Standard approved Windows deployment script with UAC auto-elevation
:: ==============================================================================

title Aegis-Guard Windows Installer
color 0b

echo.
echo  ==============================================================
echo            AEGIS-GUARD -- WINDOWS SECURITY SUITE
echo             Automated Service ^& Desktop Deployment
echo  ==============================================================
echo.

:: 1. Self-Elevate to Administrator if not already running as Admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Administrator privileges required to configure system services and drivers.
    echo [*] Requesting UAC elevation...
    powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo [+] Administrator privileges verified.
echo [*] Launching PowerShell installer engine...
echo.

:: 2. Execute PowerShell installer script
if exist "%~dp0install-windows.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows.ps1"
) else if exist "%~dp0..\install-windows.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\install-windows.ps1"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/windows/install-windows.ps1 | iex"
)

echo.
echo [OK] Installation script finished.
pause
