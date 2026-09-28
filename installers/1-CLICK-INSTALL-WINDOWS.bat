@echo off
:: Aegis-Guard — one-click Windows installer launcher
:: Runs install-windows.ps1 with Administrator elevation.

setlocal
cd /d "%~dp0"

echo.
echo   ================================================================
echo            AEGIS-GUARD -- 1-CLICK WINDOWS DEPLOYMENT
echo   ================================================================
echo.

if exist "%~dp0install-windows.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows.ps1"
) else (
    echo [!] install-windows.ps1 not found next to this script.
    echo     Expected: installers\install-windows.ps1
    pause
    exit /b 1
)

endlocal
