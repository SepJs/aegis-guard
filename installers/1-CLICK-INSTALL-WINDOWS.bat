@echo off
:: ==============================================================================
::  Aegis-Guard 1-Click Auto Installer for Windows
::  Automatically prompts for UAC Administrator permissions, verifies runtime,
::  configures firewall, registers service, and adds Desktop Icon.
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

:: 2. Run PowerShell installer with full bypass
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows.ps1"

echo.
echo [OK] Aegis-Guard has been successfully installed and armed!
echo Desktop icon has been placed. You can now close this window.
timeout /t 5
