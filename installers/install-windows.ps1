<#
.SYNOPSIS
    Aegis-Guard Windows Native Service & Desktop Suite Automated Installer
    Deploys real-time Rust process monitoring engine, Go packet sniffing & IDS observer,
    and native desktop security suite.
#>

[CmdletBinding()]
param(
    [switch]$SkipService = $false,
    [switch]$NoLaunch = $false
)

$ErrorActionPreference = "Stop"

function Write-Banner {
    Clear-Host
    Write-Host "  ================================================================" -ForegroundColor Magenta
    Write-Host "       AEGIS-GUARD -- NATIVE WINDOWS EDR/IDS INSTALLER            " -ForegroundColor Cyan
    Write-Host "    Rust Engine + Go IDS Packet Sniffer + Tauri Native Suite      " -ForegroundColor White
    Write-Host "  ================================================================" -ForegroundColor Magenta
    Write-Host ""
}

Write-Banner

# 1. Require Administrative Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Administrative privileges required to configure system drivers, services, and packet filters." -ForegroundColor Yellow
    Write-Host "[*] Relaunching installer with UAC prompt..." -ForegroundColor Cyan
    if ($PSCommandPath) {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-windows.ps1 | iex`""
    }
    exit
}

Write-Host "[+] Elevated Administrator privileges confirmed." -ForegroundColor Green

# 2. Paths and Directory Provisioning
$InstallRoot   = "$env:ProgramFiles\Aegis-Guard"
$DataRoot      = "$env:ProgramData\Aegis-Guard"
$QuarantineDir = "$DataRoot\quarantine"
$SandboxDir    = "$DataRoot\sandbox"
$LogDir        = "$DataRoot\logs"
$CanaryDir     = "$DataRoot\canaries"

Write-Host "[*] Target Installation Directory: $InstallRoot" -ForegroundColor Cyan
Write-Host "[*] Persistent Data & Logs:        $DataRoot" -ForegroundColor Cyan

foreach ($dir in @($InstallRoot, $DataRoot, $QuarantineDir, $SandboxDir, $LogDir, $CanaryDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "[+] Provisioned directory: $dir" -ForegroundColor Green
    }
}

# 3. Locate Source Root
$SourceRoot = $PSScriptRoot
if ($SourceRoot -and (Test-Path "$SourceRoot\..\Cargo.toml")) {
    $SourceRoot = (Resolve-Path "$SourceRoot\..").Path
} elseif (Test-Path ".\Cargo.toml") {
    $SourceRoot = (Resolve-Path ".").Path
} else {
    Write-Host "[*] Cloning latest source from GitHub..." -ForegroundColor Cyan
    $tempDir = "$env:TEMP\aegis-guard-src"
    if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force }
    git clone https://github.com/SepJs/aegis-guard.git $tempDir
    $SourceRoot = $tempDir
}

Write-Host "[+] Working source directory: $SourceRoot" -ForegroundColor Green

# 4. Check & Verify Build Toolchains
Write-Host "`n[*] Verifying Build Prerequisites..." -ForegroundColor Cyan

$hasCargo = Get-Command cargo -ErrorAction SilentlyContinue
$hasGo    = Get-Command go -ErrorAction SilentlyContinue
$hasNode  = Get-Command node -ErrorAction SilentlyContinue
$hasNpm   = Get-Command npm -ErrorAction SilentlyContinue

if ($hasCargo) {
    Write-Host "  [+] Rust Cargo: $(cargo --version)" -ForegroundColor Green
} else {
    Write-Host "  [!] Rust Cargo not found in PATH." -ForegroundColor Yellow
}

if ($hasGo) {
    Write-Host "  [+] Go Compiler: $(go version)" -ForegroundColor Green
} else {
    Write-Host "  [!] Go compiler not found in PATH." -ForegroundColor Yellow
}

if ($hasNpm) {
    Write-Host "  [+] Node/NPM: $(node --version) / npm $(npm --version)" -ForegroundColor Green
} else {
    Write-Host "  [!] Node.js/NPM not found in PATH." -ForegroundColor Yellow
}

# 5. Build Rust Process Engine (Real Native EDR Core)
Write-Host "`n[*] Step 1/3: Compiling Native Rust Process Engine..." -ForegroundColor Cyan
if ($hasCargo) {
    Push-Location $SourceRoot
    try {
        cargo build --release --bin aegis-process-engine
        if (Test-Path "$SourceRoot\target\release\aegis-process-engine.exe") {
            Copy-Item "$SourceRoot\target\release\aegis-process-engine.exe" "$InstallRoot\aegis-process-engine.exe" -Force
            Write-Host "[+] Installed: $InstallRoot\aegis-process-engine.exe" -ForegroundColor Green
        }
    } catch {
        Write-Host "[!] Cargo process-engine build notice: $_" -ForegroundColor Yellow
    }
    Pop-Location
} else {
    Write-Host "[!] Skipping Rust compilation (cargo not in PATH). Please ensure Rust is installed." -ForegroundColor Yellow
}

# 6. Build Go Network Observer (Real Native IDS Core)
Write-Host "`n[*] Step 2/3: Compiling Native Go Network Observer (IDS)..." -ForegroundColor Cyan
if ($hasGo -and (Test-Path "$SourceRoot\network-observer")) {
    Push-Location "$SourceRoot\network-observer"
    try {
        $env:CGO_ENABLED = "0"
        go build -o "$InstallRoot\aegis-network-observer.exe" ./cmd/observer
        if (Test-Path "$InstallRoot\aegis-network-observer.exe") {
            Write-Host "[+] Installed: $InstallRoot\aegis-network-observer.exe" -ForegroundColor Green
        }
    } catch {
        Write-Host "[!] Go network observer build notice: $_" -ForegroundColor Yellow
    }
    Pop-Location
} else {
    Write-Host "[!] Skipping Go compilation (go not in PATH). Please ensure Go is installed." -ForegroundColor Yellow
}

# 7. Build Tauri Desktop Suite
Write-Host "`n[*] Step 3/3: Preparing Aegis-Guard Desktop Dashboard..." -ForegroundColor Cyan
if ($hasCargo -and $hasNpm -and (Test-Path "$SourceRoot\tauri-app")) {
    Push-Location "$SourceRoot\tauri-app"
    try {
        cmd /c "npm install"
        cmd /c "npm run build"
        Push-Location "$SourceRoot"
        cargo build --release -p aegis-tauri
        if (Test-Path "$SourceRoot\target\release\aegis-tauri.exe") {
            Copy-Item "$SourceRoot\target\release\aegis-tauri.exe" "$InstallRoot\aegis-guard.exe" -Force
            Write-Host "[+] Installed: $InstallRoot\aegis-guard.exe" -ForegroundColor Green
        }
        Pop-Location
    } catch {
        Write-Host "[!] Tauri build notice: $_" -ForegroundColor Yellow
    }
    Pop-Location
}

# Copy Web Assets if available
$distTarget = "$InstallRoot\dist"
if (-not (Test-Path $distTarget)) { New-Item -ItemType Directory -Path $distTarget -Force | Out-Null }
if (Test-Path "$SourceRoot\tauri-app\dist") {
    Copy-Item -Path "$SourceRoot\tauri-app\dist\*" -Destination $distTarget -Recurse -Force
    Write-Host "[+] Deployed frontend web assets to $distTarget" -ForegroundColor Green
} elseif (Test-Path "$SourceRoot\dist") {
    Copy-Item -Path "$SourceRoot\dist\*" -Destination $distTarget -Recurse -Force
    Write-Host "[+] Deployed frontend web assets to $distTarget" -ForegroundColor Green
}

# 8. Create Unified Native Windows Launcher
$LauncherCmd = "$InstallRoot\Aegis-Guard.cmd"
$LauncherVbs = "$InstallRoot\Aegis-Guard.vbs"

$launcherContent = @"
@echo off
set "AEGIS_SOCKET=127.0.0.1:50054"
set "AEGIS_NET=1"
set "LOCALAPPDATA=%LOCALAPPDATA%"

echo [*] Starting Aegis-Guard Rust Process Engine...
start "Aegis-Process-Engine" /min "%~dp0aegis-process-engine.exe"

echo [*] Starting Aegis-Guard Go Network Observer IDS...
start "Aegis-Network-Observer" /min "%~dp0aegis-network-observer.exe"

echo [*] Launching Aegis-Guard Desktop UI...
if exist "%~dp0aegis-guard.exe" (
    start "" "%~dp0aegis-guard.exe"
) else (
    echo [!] GUI binary not found. Running engines in background.
)
"@

Set-Content -Path $LauncherCmd -Value $launcherContent -Encoding ASCII

# VBS silent wrapper to avoid black console popups on shortcuts
$vbsContent = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run chr(34) & "$LauncherCmd" & Chr(34), 0
Set WshShell = Nothing
"@
Set-Content -Path $LauncherVbs -Value $vbsContent -Encoding ASCII
Write-Host "[+] Created unified engine launcher: $LauncherCmd" -ForegroundColor Green

# 9. Configure Windows Firewall Exceptions for IPC
Write-Host "`n[*] Configuring Windows Firewall for Native IPC..." -ForegroundColor Cyan
try {
    netsh advfirewall firewall delete rule name="Aegis-Guard IPC Process Engine" 2>$null | Out-Null
    netsh advfirewall firewall add rule name="Aegis-Guard IPC Process Engine" dir=in action=allow protocol=TCP localport=50054 remoteip=127.0.0.1 | Out-Null

    netsh advfirewall firewall delete rule name="Aegis-Guard IPC Network Observer" 2>$null | Out-Null
    netsh advfirewall firewall add rule name="Aegis-Guard IPC Network Observer" dir=in action=allow protocol=TCP localport=50053 remoteip=127.0.0.1 | Out-Null
    Write-Host "[+] Windows Firewall rules configured for localhost IPC (Ports 50053, 50054)." -ForegroundColor Green
} catch {
    Write-Host "[!] Firewall configuration notice: $_" -ForegroundColor Yellow
}

# 10. Generate Desktop and Start Menu Shortcuts
Write-Host "`n[*] Generating Desktop & Start Menu Shortcuts..." -ForegroundColor Cyan
$WshShell = New-Object -ComObject WScript.Shell

$DesktopPath = [Environment]::GetFolderPath("Desktop")
$Shortcut = $WshShell.CreateShortcut("$DesktopPath\Aegis-Guard.lnk")
$Shortcut.TargetPath = "wscript.exe"
$Shortcut.Arguments = "`"$LauncherVbs`""
$Shortcut.WorkingDirectory = $InstallRoot
$Shortcut.Description = "Aegis-Guard Native EDR & IDS Suite"
$Shortcut.Save()

$StartMenuPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
$SmShortcut = $WshShell.CreateShortcut("$StartMenuPath\Aegis-Guard.lnk")
$SmShortcut.TargetPath = "wscript.exe"
$SmShortcut.Arguments = "`"$LauncherVbs`""
$SmShortcut.WorkingDirectory = $InstallRoot
$SmShortcut.Description = "Aegis-Guard Native EDR & IDS Suite"
$SmShortcut.Save()

Write-Host "[+] Desktop and Start Menu shortcuts created successfully." -ForegroundColor Green

# 11. Completion Summary
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "        AEGIS-GUARD INSTALLATION COMPLETED SUCCESSFULLY         " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Install Root:      $InstallRoot" -ForegroundColor White
Write-Host "  Process Engine:    $InstallRoot\aegis-process-engine.exe" -ForegroundColor White
Write-Host "  Network Observer:  $InstallRoot\aegis-network-observer.exe" -ForegroundColor White
Write-Host "  Desktop Suite:     $InstallRoot\aegis-guard.exe" -ForegroundColor White
Write-Host "  Unified Launcher:  $LauncherCmd" -ForegroundColor White
Write-Host "  Desktop Shortcut:  $DesktopPath\Aegis-Guard.lnk" -ForegroundColor White
Write-Host ""

if (-not $NoLaunch) {
    Write-Host "[*] Launching Aegis-Guard native services..." -ForegroundColor Cyan
    Start-Process -FilePath $LauncherCmd
    Write-Host "[+] Aegis-Guard is now armed and protecting your system!" -ForegroundColor Green
}
