<#
.SYNOPSIS
    Aegis-Guard Windows Console & Native Desktop Automated Installer (v1.2.0)
    Supports both headless console server mode (-ConsoleOnly) and full Rust + Go + Tauri desktop deployment.
#>

[CmdletBinding()]
param(
    [switch]$ConsoleOnly = $false,
    [switch]$NoLaunch = $false
)

$ErrorActionPreference = "Stop"

function Write-Banner {
    Clear-Host
    Write-Host "  ================================================================" -ForegroundColor Magenta
    Write-Host "       AEGIS-GUARD -- WINDOWS INSTALLER (v1.2.0)                  " -ForegroundColor Cyan
    Write-Host "    Endpoint Telemetry + Go Packet Observer + Console/Desktop UI  " -ForegroundColor White
    Write-Host "  ================================================================" -ForegroundColor Magenta
    Write-Host ""
}

Write-Banner

# 1. Require Administrative Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Administrative privileges required. Relaunching with UAC elevation..." -ForegroundColor Yellow
    if ($PSCommandPath) {
        $argStr = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        if ($ConsoleOnly) { $argStr += " -ConsoleOnly" }
        if ($NoLaunch) { $argStr += " -NoLaunch" }
        Start-Process powershell.exe -Verb RunAs -ArgumentList $argStr
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-windows.ps1 | iex`""
    }
    exit
}

Write-Host "[+] Elevated Administrator privileges confirmed." -ForegroundColor Green

# 2. Directory Provisioning + Standard User Write Permissions
$InstallRoot   = "$env:ProgramFiles\Aegis-Guard"
$DataRoot      = "$env:ProgramData\Aegis-Guard"
$QuarantineDir = "$DataRoot\quarantine"
$SandboxDir    = "$DataRoot\sandbox"
$LogDir        = "$DataRoot\logs"
$CanaryDir     = "$DataRoot\canaries"

foreach ($dir in @($InstallRoot, $DataRoot, $QuarantineDir, $SandboxDir, $LogDir, $CanaryDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
try {
    icacls $DataRoot /grant "Users:(OI)(CI)M" /T /Q | Out-Null
    icacls $InstallRoot /grant "Users:(OI)(CI)M" /T /Q | Out-Null
} catch {}
Write-Host "[+] Provisioned runtime vault: $DataRoot" -ForegroundColor Green

# 3. Locate or Clone Source Root
$SourceRoot = $PSScriptRoot
if ($SourceRoot -and (Test-Path "$SourceRoot\..\package.json")) {
    $SourceRoot = (Resolve-Path "$SourceRoot\..").Path
} elseif (Test-Path ".\package.json") {
    $SourceRoot = (Resolve-Path ".").Path
} else {
    Write-Host "[*] Cloning Aegis-Guard source from GitHub..." -ForegroundColor Cyan
    $repoDir = "$InstallRoot\src"
    if (Test-Path "$repoDir\.git") {
        git -C $repoDir pull --ff-only
    } else {
        if (Test-Path $repoDir) { Remove-Item -Path $repoDir -Recurse -Force }
        git clone --depth 1 https://github.com/SepJs/aegis-guard.git $repoDir
    }
    $SourceRoot = $repoDir
}
try { icacls $SourceRoot /grant "Users:(OI)(CI)M" /T /Q | Out-Null } catch {}
Write-Host "[+] Working source directory: $SourceRoot" -ForegroundColor Green

# 4. Verify Toolchains
$hasCargo = Get-Command cargo -ErrorAction SilentlyContinue
$hasGo    = Get-Command go -ErrorAction SilentlyContinue
$hasNode  = Get-Command node -ErrorAction SilentlyContinue
$hasNpm   = Get-Command npm -ErrorAction SilentlyContinue

if (-not $hasNode -or -not $hasNpm) {
    Write-Host "[!] Node.js 20+ and npm are required. Install from https://nodejs.org and retry." -ForegroundColor Red
    exit 1
}
Write-Host "  [+] Node/NPM: $(node --version) / npm $(npm --version)" -ForegroundColor Green

# 5. Build Web Dashboard & Server Dependencies
Write-Host "`n[*] Step 1/4: Installing npm dependencies and building UI..." -ForegroundColor Cyan
Push-Location $SourceRoot
try {
    cmd /c "npm install --no-audit --no-fund"
    cmd /c "npm run build"
    Write-Host "[+] Web dashboard bundle ready." -ForegroundColor Green
} finally {
    Pop-Location
}

# 6. Build Go Network Observer
Write-Host "`n[*] Step 2/4: Building Go Network Observer (IDS)..." -ForegroundColor Cyan
if ($hasGo -and (Test-Path "$SourceRoot\network-observer")) {
    Push-Location "$SourceRoot\network-observer"
    try {
        $env:CGO_ENABLED = "0"
        go build -ldflags="-s -w" -o "$InstallRoot\aegis-network-observer.exe" ./cmd/observer
        if (Test-Path "$InstallRoot\aegis-network-observer.exe") {
            Write-Host "[+] Installed: $InstallRoot\aegis-network-observer.exe" -ForegroundColor Green
        }
    } catch {
        Write-Host "[!] Go observer skipped: $_" -ForegroundColor Yellow
    }
    Pop-Location
} else {
    Write-Host "[*] Go compiler not found; skipping native Go observer build." -ForegroundColor Yellow
}

# 7. Build Native Rust Binaries (Desktop + Process Engine + Optional GTK Installer)
Write-Host "`n[*] Step 3/4: Building Native Rust Engines (Optional if Rust installed)..." -ForegroundColor Cyan
if (-not $ConsoleOnly -and $hasCargo) {
    Push-Location $SourceRoot
    try {
        cargo build --release -p process-engine
        if (Test-Path "$SourceRoot\target\release\aegis-process-engine.exe") {
            Copy-Item "$SourceRoot\target\release\aegis-process-engine.exe" "$InstallRoot\aegis-process-engine.exe" -Force
            Write-Host "[+] Installed: $InstallRoot\aegis-process-engine.exe" -ForegroundColor Green
        }
        cargo build --release -p aegis-guard
        if (Test-Path "$SourceRoot\target\release\Aegis-Guard.exe") {
            Copy-Item "$SourceRoot\target\release\Aegis-Guard.exe" "$InstallRoot\Aegis-Guard.exe" -Force
            Write-Host "[+] Installed: $InstallRoot\Aegis-Guard.exe" -ForegroundColor Green
        }
        if ((Get-Command pkg-config -ErrorAction SilentlyContinue)) {
            cmd /c "pkg-config --exists gtk+-3.0 2>nul"
            if ($LASTEXITCODE -eq 0) {
                cargo build --release -p aegis-installer
                if (Test-Path "$SourceRoot\target\release\aegis-installer.exe") {
                    Copy-Item "$SourceRoot\target\release\aegis-installer.exe" "$InstallRoot\aegis-installer.exe" -Force
                    Write-Host "[+] Installed GTK GUI Installer: $InstallRoot\aegis-installer.exe" -ForegroundColor Green
                }
            }
        }
    } catch {
        Write-Host "[!] Rust desktop build skipped: $_" -ForegroundColor Yellow
    }
    Pop-Location
} else {
    Write-Host "[*] Running in Web/Console runtime configuration." -ForegroundColor Yellow
}

# 8. Deploy Console + Desktop Unified Launchers
Write-Host "`n[*] Step 4/4: Creating Console CLI & Windows Launchers..." -ForegroundColor Cyan
$ConsoleCmd = "$InstallRoot\aegis-guard.cmd"
$consoleScript = @"
@echo off
cd /d "$SourceRoot"
set "AEGIS_DATA_DIR=$DataRoot"
if exist "$InstallRoot\aegis-network-observer.exe" (
    start "Aegis-Network-Observer" /min "$InstallRoot\aegis-network-observer.exe"
)
echo [*] Starting Aegis-Guard Console & Web UI on http://127.0.0.1:3000 ...
set NODE_ENV=production
start "" /B powershell -NoProfile -Command "for(`$i=0;`$i -lt 30;`$i++){try{`$c=New-Object Net.Sockets.TcpClient('127.0.0.1',3000);`$c.Close();Start-Process 'http://127.0.0.1:3000';break}catch{Start-Sleep -Milliseconds 400}}"
call npm start
"@
Set-Content -Path $ConsoleCmd -Value $consoleScript -Encoding ASCII

$LauncherCmd = "$InstallRoot\Aegis-Guard-Desktop.cmd"
$desktopScript = @"
@echo off
set "AEGIS_SOCKET=127.0.0.1:50054"
set "AEGIS_NET=1"
set "AEGIS_DATA_DIR=$DataRoot"
if exist "%~dp0aegis-process-engine.exe" start "Aegis-Process-Engine" /min "%~dp0aegis-process-engine.exe"
if exist "%~dp0aegis-network-observer.exe" start "Aegis-Network-Observer" /min "%~dp0aegis-network-observer.exe"
if exist "%~dp0Aegis-Guard.exe" (
    start "" "%~dp0Aegis-Guard.exe"
) else (
    call "%~dp0aegis-guard.cmd"
)
"@
Set-Content -Path $LauncherCmd -Value $desktopScript -Encoding ASCII

# Add InstallRoot to System PATH cleanly if absent
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$InstallRoot*") {
    [Environment]::SetEnvironmentVariable("Path", "$machinePath;$InstallRoot", "Machine")
    Write-Host "[+] Added $InstallRoot to System PATH (available as 'aegis-guard' in new terminals)." -ForegroundColor Green
}

# Firewall rules for localhost Go & Rust IPC bridges + Console port
try {
    netsh advfirewall firewall delete rule name="Aegis-Guard IPC Process Engine" 2>$null | Out-Null
    netsh advfirewall firewall add rule name="Aegis-Guard IPC Process Engine" dir=in action=allow protocol=TCP localport=50054 remoteip=127.0.0.1 | Out-Null
    netsh advfirewall firewall delete rule name="Aegis-Guard IPC Network Observer" 2>$null | Out-Null
    netsh advfirewall firewall add rule name="Aegis-Guard IPC Network Observer" dir=in action=allow protocol=TCP localport=50053 remoteip=127.0.0.1 | Out-Null
} catch {}

# Create Start Menu & Desktop Shortcuts with icon
$IconSrc = "$SourceRoot\tauri-app\src-tauri\icons\icon.ico"
$IconDst = "$InstallRoot\aegis-guard.ico"
if (Test-Path $IconSrc) {
    Copy-Item $IconSrc $IconDst -Force
}

try {
    $WshShell = New-Object -ComObject WScript.Shell
    $DesktopPath = [Environment]::GetFolderPath("Desktop")
    $Shortcut = $WshShell.CreateShortcut("$DesktopPath\Aegis-Guard.lnk")
    $Shortcut.TargetPath = $LauncherCmd
    $Shortcut.WorkingDirectory = $InstallRoot
    $Shortcut.Description = "Aegis-Guard Endpoint Security & IDS Suite"
    if (Test-Path $IconDst) { $Shortcut.IconLocation = $IconDst }
    $Shortcut.Save()

    $StartMenuPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
    $SmShortcut = $WshShell.CreateShortcut("$StartMenuPath\Aegis-Guard.lnk")
    $SmShortcut.TargetPath = $LauncherCmd
    $SmShortcut.WorkingDirectory = $InstallRoot
    $SmShortcut.Description = "Aegis-Guard Endpoint Security & IDS Suite"
    if (Test-Path $IconDst) { $SmShortcut.IconLocation = $IconDst }
    $SmShortcut.Save()
    Write-Host "[+] Desktop & Start Menu shortcuts installed." -ForegroundColor Green
} catch {}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "     AEGIS-GUARD v1.2.0 INSTALLATION COMPLETED                  " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Console Command:   aegis-guard (in any new CMD/PowerShell)" -ForegroundColor White
Write-Host "  Install Folder:    $InstallRoot" -ForegroundColor White
Write-Host ""

if (-not $NoLaunch) {
    Write-Host "[*] Launching Aegis-Guard..." -ForegroundColor Cyan
    Start-Process -FilePath $LauncherCmd
}
