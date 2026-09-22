@echo off
:: install-windows.bat - Quick root wrapper for Windows
:: Aegis-Guard Endpoint & Network Defense

title Aegis-Guard Installer
color 0b

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Requesting administrative privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

if exist "%~dp0installers\install-windows.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installers\install-windows.ps1"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-windows.ps1 | iex"
)

pause
