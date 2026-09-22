@echo off
:: ==============================================================================
::  Aegis-Guard 1-Click Auto Installer for Windows
::  Automatically prompts for UAC Administrator permissions, verifies runtime,
::  configures firewall, registers service, deploys dashboard, and launches app.
:: ==============================================================================

title Aegis-Guard 1-Click Installer
color 0b

echo.
echo  ==============================================================
echo            AEGIS-GUARD -- 1-CLICK WINDOWS DEPLOYMENT
echo  ==============================================================
echo.

:: 1. Self-Elevate to Administrator if not already running as Admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Administrator privileges required for kernel monitoring and firewall hooks.
    echo [*] Prompting for UAC Elevation...
    powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo [+] Elevated Administrator privileges verified.
echo [*] Executing deployment pipeline...
echo.

:: 2. Run PowerShell installer
if exist "%~dp0installers\install-windows.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installers\install-windows.ps1"
) else if exist "%~dp0install-windows.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows.ps1"
) else (
    echo [*] Fetching latest installer from official repository...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-windows.ps1 | iex"
)

echo.
echo [OK] Aegis-Guard deployment completed!
timeout /t 5
