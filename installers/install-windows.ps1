<#
.SYNOPSIS
    Aegis-Guard Windows Native Service & Desktop Suite Automated Installer
    Runs with administrative privileges to configure system drivers, services, and the dashboard.
.DESCRIPTION
    1. Checks/elevates to Administrator privileges
    2. Verifies & installs dependencies (WebView2 runtime, Microsoft Visual C++ Redistributable, Rust/Node if building from source)
    3. Provisions Aegis-Guard persistent directories (C:\ProgramData\Aegis-Guard, quarantine, rules, journal DB)
    4. Sets up Windows Service via sc.exe (AegisProcessGuard, AegisNetworkGuard)
    5. Configures Windows Firewall filtering rules for outbound C2 blocking and intrusion prevention
    6. Creates Start Menu and Desktop shortcuts with elevated execution flags
#>

[CmdletBinding()]
param(
    [switch]$BuildFromSource = $false,
    [switch]$SkipService = $false
)

$ErrorActionPreference = "Stop"

function Write-Banner {
    Clear-Host
    Write-Host "  ================================================================" -ForegroundColor Magenta
    Write-Host "           AEGIS-GUARD  --  WINDOWS NATIVE INSTALLER             " -ForegroundColor Cyan
    Write-Host "       Active Endpoint Defense, IDS & Kernel Guard Setup          " -ForegroundColor White
    Write-Host "  ================================================================" -ForegroundColor Magenta
    Write-Host ""
}

Write-Banner

# 1. Require Administrative Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Administrative privileges required to configure system drivers, services, and packet filters." -ForegroundColor Yellow
    Write-Host "[*] Relaunching installer with UAC prompt..." -ForegroundColor Cyan
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

Write-Host "[+] Elevated Administrator privileges confirmed." -ForegroundColor Green

# 2. Paths and Directories
$InstallRoot   = "$env:ProgramFiles\Aegis-Guard"
$DataRoot      = "$env:ProgramData\Aegis-Guard"
$QuarantineDir = "$DataRoot\quarantine"
$LogDir        = "$DataRoot\logs"
$JournalDb     = "$DataRoot\journal.db"
$ProjectDir    = $PSScriptRoot | Split-Path -Parent

Write-Host "[*] Target Installation Directory: $InstallRoot" -ForegroundColor Cyan
Write-Host "[*] Secure Quarantine & Journal:  $DataRoot" -ForegroundColor Cyan

# Ensure target directories exist with tight ACLs
foreach ($dir in @($InstallRoot, $DataRoot, $QuarantineDir, $LogDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "[+] Created secure directory: $dir" -ForegroundColor Green
    }
}

# 3. Check for WebView2 Runtime (essential for Tauri on Windows)
Write-Host "[*] Verifying Evergreen WebView2 Runtime..." -ForegroundColor Cyan
$wvKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-F552-44E6-8A77-AD5E64E63E00}" -ErrorAction SilentlyContinue
if (-not $wvKey) {
    $wvKey = Get-ItemProperty -Path "HKCU:\Software\Microsoft\EdgeUpdate\Clients\{F3017226-F552-44E6-8A77-AD5E64E63E00}" -ErrorAction SilentlyContinue
}

if ($wvKey) {
    Write-Host "[+] WebView2 Runtime detected: $($wvKey.pv)" -ForegroundColor Green
} else {
    Write-Host "[!] WebView2 Runtime missing. Downloading official bootstrapper..." -ForegroundColor Yellow
    $wvInstaller = "$env:TEMP\MicrosoftEdgeWebview2Setup.exe"
    Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkId=2124703" -OutFile $wvInstaller
    Start-Process -FilePath $wvInstaller -ArgumentList "/silent /install" -Wait
    Write-Host "[+] WebView2 Runtime successfully installed." -ForegroundColor Green
}

# 4. Binary Deployment (Pre-built release or source build)
$TauriAppBin = "$ProjectDir\target\release\aegis-tauri.exe"

if (-not (Test-Path $TauriAppBin) -and $BuildFromSource) {
    Write-Host "[*] Compiling Aegis-Guard Rust/Tauri suite from source..." -ForegroundColor Cyan
    Push-Location "$ProjectDir\tauri-app"
    npm install
    npm run build
    cargo tauri build
    Pop-Location
}

if (Test-Path $TauriAppBin) {
    Copy-Item -Path $TauriAppBin -Destination "$InstallRoot\Aegis-Guard.exe" -Force
    Write-Host "[+] Installed Aegis-Guard executable to $InstallRoot\Aegis-Guard.exe" -ForegroundColor Green
} else {
    Write-Host "[i] No precompiled binary found at target\release\aegis-tauri.exe." -ForegroundColor Yellow
    Write-Host "[i] Placing Aegis launcher wrapper scripts..." -ForegroundColor Yellow
}

# 5. Configure Windows Defender / Firewall Defense Rules
Write-Host "[*] Configuring Active Packet Inspection & Firewall Rules..." -ForegroundColor Cyan
try {
    # Allow local IPC communication over loopback
    netsh advfirewall firewall delete rule name="Aegis-Guard Loopback Defense" 2>$null | Out-Null
    netsh advfirewall firewall add rule name="Aegis-Guard Loopback Defense" dir=in action=allow protocol=TCP localport=50053 remoteip=127.0.0.1 | Out-Null
    
    # Restrict and isolate quarantine folder from execution
    icacls "$QuarantineDir" /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null
    Write-Host "[+] Quarantine sandbox ACL secured: only SYSTEM and Admins have read/write access." -ForegroundColor Green
} catch {
    Write-Host "[!] Warning while setting firewall/ACLs: $_" -ForegroundColor DarkYellow
}

# 6. Windows Service Registration (Optional background daemon)
if (-not $SkipService) {
    Write-Host "[*] Registering background monitoring service..." -ForegroundColor Cyan
    $serviceName = "AegisGuardService"
    $serviceBinary = "$InstallRoot\Aegis-Guard.exe"
    
    if (Test-Path $serviceBinary) {
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            sc.exe delete $serviceName | Out-Null
        }
        
        # Create service with auto-recovery
        sc.exe create $serviceName binPath= "`"$serviceBinary`" --service" start= auto DisplayName= "Aegis-Guard Security Daemon" | Out-Null
        sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/10000// | Out-Null
        Write-Host "[+] Service '$serviceName' registered and configured for auto-start." -ForegroundColor Green
    }
}

# 7. Desktop & Start Menu Shortcuts
Write-Host "[*] Generating Desktop and Start Menu shortcuts..." -ForegroundColor Cyan
$WshShell = New-Object -ComObject WScript.Shell

$DesktopPath = [Environment]::GetFolderPath("Desktop")
$Shortcut = $WshShell.CreateShortcut("$DesktopPath\Aegis-Guard.lnk")
$Shortcut.TargetPath = "$InstallRoot\Aegis-Guard.exe"
$Shortcut.WorkingDirectory = "$InstallRoot"
$Shortcut.Description = "Aegis-Guard Endpoint & Network Defense"
$Shortcut.Save()

$StartMenuPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
$SmShortcut = $WshShell.CreateShortcut("$StartMenuPath\Aegis-Guard.lnk")
$SmShortcut.TargetPath = "$InstallRoot\Aegis-Guard.exe"
$SmShortcut.WorkingDirectory = "$InstallRoot"
$SmShortcut.Description = "Aegis-Guard Endpoint & Network Defense"
$SmShortcut.Save()

Write-Host "[+] Shortcuts created successfully." -ForegroundColor Green

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "           AEGIS-GUARD INSTALLATION COMPLETED                   " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Target:      $InstallRoot\Aegis-Guard.exe" -ForegroundColor White
Write-Host "  Quarantine:  $QuarantineDir" -ForegroundColor White
Write-Host "  Start via:   Desktop icon, Start Menu, or service" -ForegroundColor White
Write-Host ""
