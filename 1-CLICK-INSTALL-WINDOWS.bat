@echo off
:: ==============================================================================
::  Aegis-Guard 1-Click Auto Installer for Windows
:: ==============================================================================

title Aegis-Guard 1-Click Installer
color 0b

net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

if exist "%~dp0installers\windows\install-windows.bat" (
    call "%~dp0installers\windows\install-windows.bat"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/windows/install-windows.ps1 | iex"
)
