#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploys Sysmon with a SOC-tuned configuration for endpoint telemetry.

.DESCRIPTION
    Installs or updates Sysmon (System Monitor) on lab endpoints using the
    project's XML configuration. Sysmon generates detailed Windows event logs
    for process creation, network connections, file changes, registry
    modifications, and DNS queries — essential telemetry for SOC monitoring.

    - If Sysmon is not installed: installs with the lab config
    - If Sysmon is already installed: updates to the latest config
    - Verifies the service, event log channel, and config hash after deployment

    NOTE: The Sysmon binary is not included in this repository. You must
    download Sysmon64.exe from Microsoft Sysinternals before running this script.

.PARAMETER SysmonPath
    Path to Sysmon64.exe. Defaults to ..\sysmon\Sysmon64.exe relative to the
    script directory.

.PARAMETER ConfigPath
    Path to the Sysmon XML configuration file. Defaults to ..\sysmon\sysmon-config.xml
    relative to the script directory.
#>

# Sysmon (System Monitor) — a Microsoft Sysinternals tool that hooks into the
# Windows kernel to log detailed endpoint activity that the built-in event log misses:
# process creation with full command lines, network connections with ports and IPs,
# file creation timestamps, registry modifications, and DNS queries.
#
# Why Sysmon matters for SOC — Windows native Security logging records WHO logged in
# and WHAT files were accessed, but not HOW processes were launched or which command-line
# arguments were used. Without Sysmon, a SOC analyst can't see that "powershell.exe
# -enc <base64>" was executed — they only see that PowerShell ran.

param(
    [string]$SysmonPath  = "$PSScriptRoot\..\sysmon\Sysmon64.exe",
    [string]$ConfigPath  = "$PSScriptRoot\..\sysmon\sysmon-config.xml"
)

# ── Resolve paths ─────────────────────────────────────────────────────
$SysmonPath = (Resolve-Path $SysmonPath -ErrorAction SilentlyContinue).Path
$ConfigPath = (Resolve-Path $ConfigPath -ErrorAction SilentlyContinue).Path

# ── Validate config file ─────────────────────────────────────────────
# The XML config controls which events Sysmon logs and which it filters out.
# Without tuning, Sysmon generates enormous volumes of noise (every process on the
# system). A good config filters out known-safe activity and keeps only events that
# are security-relevant — this is the "signal vs noise" tuning that makes Sysmon useful.
if (-not $ConfigPath -or -not (Test-Path $ConfigPath)) {
    Write-Host "[-] Sysmon config not found: $PSScriptRoot\..\sysmon\sysmon-config.xml" -ForegroundColor Red
    Write-Host "[-] Ensure sysmon-config.xml exists in the sysmon/ directory." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Sysmon Deployment" -ForegroundColor Cyan
Write-Host "    Config: $ConfigPath" -ForegroundColor White

# ── Check if Sysmon is already installed ──────────────────────────────
$SysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $SysmonService) {
    $SysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
}

if ($SysmonService) {
    # ── Update existing installation ──────────────────────────────────
    Write-Host "[*] Sysmon is already installed (service: $($SysmonService.Name)). Updating configuration..." -ForegroundColor Cyan

    # Find the installed Sysmon binary
    $InstalledSysmon = (Get-WmiObject Win32_Service -Filter "Name='$($SysmonService.Name)'" |
        Select-Object -ExpandProperty PathName).Trim('"')

    if (-not $InstalledSysmon -or -not (Test-Path $InstalledSysmon)) {
        Write-Host "[-] Cannot locate installed Sysmon binary. Attempting with Sysmon64.exe from PATH..." -ForegroundColor Yellow
        $InstalledSysmon = "Sysmon64.exe"
    }

    Write-Host "[*] Running: $InstalledSysmon -c $ConfigPath" -ForegroundColor Cyan
    & $InstalledSysmon -c $ConfigPath

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Sysmon configuration updated successfully." -ForegroundColor Green
    } else {
        Write-Host "[-] Sysmon configuration update failed (exit code: $LASTEXITCODE)." -ForegroundColor Red
        exit 1
    }
} else {
    # ── Fresh installation ────────────────────────────────────────────
    Write-Host "[*] Sysmon is not installed. Performing fresh installation..." -ForegroundColor Cyan

    # Validate Sysmon binary exists
    if (-not $SysmonPath -or -not (Test-Path $SysmonPath)) {
        Write-Host "[-] Sysmon64.exe not found." -ForegroundColor Red
        Write-Host "" -ForegroundColor White
        Write-Host "[i] Sysmon is a Microsoft Sysinternals tool and must be downloaded manually." -ForegroundColor Yellow
        Write-Host "    Download from: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon" -ForegroundColor White
        Write-Host "" -ForegroundColor White
        Write-Host "    Steps:" -ForegroundColor Yellow
        Write-Host "      1. Download Sysmon.zip from the URL above" -ForegroundColor White
        Write-Host "      2. Extract Sysmon64.exe to the sysmon/ directory in this repo" -ForegroundColor White
        Write-Host "      3. Re-run this script" -ForegroundColor White
        Write-Host "" -ForegroundColor White
        Write-Host "    Expected path: $PSScriptRoot\..\sysmon\Sysmon64.exe" -ForegroundColor DarkGray
        exit 1
    }

    # -accepteula — Sysinternals tools prompt for EULA acceptance on first run.
    # This flag accepts it silently, which is required for unattended/scripted installs.
    # -i — install Sysmon as a service with the specified XML configuration.
    Write-Host "[*] Running: $SysmonPath -accepteula -i $ConfigPath" -ForegroundColor Cyan
    & $SysmonPath -accepteula -i $ConfigPath

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Sysmon installed successfully." -ForegroundColor Green
    } else {
        Write-Host "[-] Sysmon installation failed (exit code: $LASTEXITCODE)." -ForegroundColor Red
        exit 1
    }
}

# ── Verify installation ──────────────────────────────────────────────
Write-Host "`n[*] Verifying Sysmon deployment..." -ForegroundColor Cyan

# Check service status
$SysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $SysmonService) {
    $SysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
}

if ($SysmonService -and $SysmonService.Status -eq "Running") {
    Write-Host "[+] Service: $($SysmonService.Name) is Running" -ForegroundColor Green
} else {
    Write-Host "[-] Sysmon service is not running. Check Event Viewer for errors." -ForegroundColor Red
    exit 1
}

# Check event log channel exists
$LogName = "Microsoft-Windows-Sysmon/Operational"
$EventLog = Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue
if ($EventLog) {
    Write-Host "[+] Event log channel: $LogName (enabled)" -ForegroundColor Green
} else {
    Write-Host "[!] Event log channel not found: $LogName" -ForegroundColor Yellow
}

# Config Hash Verification — the SHA256 hash serves as an integrity check. If the
# config was tampered with (e.g., an attacker adding exclusions to hide their activity),
# the hash would change. Compare this hash against your known-good baseline.
$ConfigHash = (Get-FileHash -Path $ConfigPath -Algorithm SHA256).Hash
Write-Host "[+] Config hash (SHA256): $ConfigHash" -ForegroundColor Green

# ── Summary ───────────────────────────────────────────────────────────
Write-Host "`n[*] Sysmon deployment complete." -ForegroundColor Cyan
Write-Host "    Service:      $($SysmonService.Name) ($($SysmonService.Status))" -ForegroundColor White
Write-Host "    Config:       $ConfigPath" -ForegroundColor White
Write-Host "    Event log:    $LogName" -ForegroundColor White
Write-Host "[*] View events:  Get-WinEvent -LogName '$LogName' -MaxEvents 10" -ForegroundColor Cyan
