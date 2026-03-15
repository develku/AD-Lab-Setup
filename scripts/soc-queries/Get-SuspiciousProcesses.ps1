#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Queries Sysmon process creation events for suspicious execution patterns.

.DESCRIPTION
    Retrieves Sysmon Event ID 1 (Process Create) and filters for patterns
    commonly associated with malicious activity:
    - PowerShell with encoded commands (-enc, -EncodedCommand)
    - cmd.exe spawned by Microsoft Office processes (macro execution)
    - Processes running from Temp, Downloads, or AppData directories
    - Use of living-off-the-land binaries (LOLBins): certutil, bitsadmin,
      mshta, regsvr32, rundll32, wscript, cscript

    These patterns are high-fidelity indicators of initial access, execution,
    and defense evasion techniques used by real-world threat actors.

    MITRE ATT&CK:
    - T1059 - Command and Scripting Interpreter
      https://attack.mitre.org/techniques/T1059/
    - T1218 - System Binary Proxy Execution (LOLBins)
      https://attack.mitre.org/techniques/T1218/

.PARAMETER Hours
    Number of hours to look back. Default: 24.

.PARAMETER ComputerName
    Remote computer to query. Default: local machine.

.EXAMPLE
    .\Get-SuspiciousProcesses.ps1
    Query the last 24 hours for suspicious process creation events.

.EXAMPLE
    .\Get-SuspiciousProcesses.ps1 -Hours 48 -ComputerName WS01
    Query WS01 for suspicious processes in the last 48 hours.
#>

param(
    [int]$Hours        = 24,
    [string]$ComputerName
)

$StartTime = (Get-Date).AddHours(-$Hours)

Write-Host "[*] Querying Sysmon process creation events (Event ID 1)..." -ForegroundColor Cyan
Write-Host "    Time range: last $Hours hours (since $($StartTime.ToString('yyyy-MM-dd HH:mm')))" -ForegroundColor White

# ── Suspicious patterns ─────────────────────────────────────────────────
# Office parent processes that should never spawn cmd/powershell
$OfficeProcesses = @("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE", "MSACCESS.EXE")

# Living-off-the-land binaries (LOLBins) commonly abused by attackers
$LOLBins = @("certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
             "rundll32.exe", "wscript.exe", "cscript.exe")

# Suspicious execution directories
$SuspiciousPaths = @("\\Temp\\", "\\Downloads\\", "\\AppData\\Local\\Temp\\",
                      "\\AppData\\Roaming\\", "\\ProgramData\\")

# ── Build query parameters ─────────────────────────────────────────────
$FilterHash = @{
    LogName   = "Microsoft-Windows-Sysmon/Operational"
    Id        = 1
    StartTime = $StartTime
}

$QueryParams = @{
    FilterHashtable = $FilterHash
    ErrorAction     = "SilentlyContinue"
}
if ($ComputerName) {
    $QueryParams.ComputerName = $ComputerName
    Write-Host "    Target:     $ComputerName" -ForegroundColor White
}

# ── Retrieve events ────────────────────────────────────────────────────
$Events = Get-WinEvent @QueryParams

if (-not $Events -or $Events.Count -eq 0) {
    Write-Host "[+] No Sysmon process creation events found." -ForegroundColor Green
    Write-Host "[i] Ensure Sysmon is installed (scripts/08-Deploy-Sysmon.ps1)." -ForegroundColor Yellow
    return
}

Write-Host "[*] Analyzing $($Events.Count) process creation event(s)..." -ForegroundColor Cyan

# ── Parse and filter for suspicious patterns ────────────────────────────
$SuspiciousEvents = foreach ($Event in $Events) {
    $Xml = [xml]$Event.ToXml()
    $Data = $Xml.Event.EventData.Data

    $Image       = ($Data | Where-Object { $_.Name -eq "Image" }).'#text'
    $CommandLine = ($Data | Where-Object { $_.Name -eq "CommandLine" }).'#text'
    $ParentImage = ($Data | Where-Object { $_.Name -eq "ParentImage" }).'#text'
    $User        = ($Data | Where-Object { $_.Name -eq "User" }).'#text'

    $ImageName  = if ($Image) { Split-Path $Image -Leaf } else { "" }
    $ParentName = if ($ParentImage) { Split-Path $ParentImage -Leaf } else { "" }

    $Flags = @()

    # Check 1: PowerShell with encoded commands (T1059.001)
    if ($ImageName -like "*powershell*" -and $CommandLine -match "-[Ee](nc|ncodedCommand)") {
        $Flags += "Encoded PowerShell"
    }

    # Check 2: Office process spawning cmd/powershell (T1059.001, T1059.003)
    if ($ParentName -in $OfficeProcesses -and
        ($ImageName -like "*cmd.exe*" -or $ImageName -like "*powershell*")) {
        $Flags += "Office child process"
    }

    # Check 3: Execution from suspicious directories
    foreach ($sp in $SuspiciousPaths) {
        if ($Image -like "*$sp*") {
            $Flags += "Suspicious path"
            break
        }
    }

    # Check 4: LOLBin usage (T1218)
    if ($ImageName.ToLower() -in $LOLBins) {
        $Flags += "LOLBin"
    }

    # Only output events that matched at least one pattern
    if ($Flags.Count -gt 0) {
        [PSCustomObject]@{
            TimeCreated = $Event.TimeCreated
            User        = $User
            ParentImage = $ParentName
            Image       = $ImageName
            CommandLine = if ($CommandLine.Length -gt 120) { $CommandLine.Substring(0, 120) + "..." } else { $CommandLine }
            Flags       = $Flags -join ", "
        }
    }
}

# ── Display results ────────────────────────────────────────────────────
if (-not $SuspiciousEvents -or @($SuspiciousEvents).Count -eq 0) {
    Write-Host "[+] No suspicious process patterns detected." -ForegroundColor Green
    Write-Host "    Analyzed: $($Events.Count) process creation events" -ForegroundColor White
    return
}

$SuspiciousCount = @($SuspiciousEvents).Count
Write-Host "`n[!] Found $SuspiciousCount suspicious process event(s):" -ForegroundColor Red

$SuspiciousEvents | Format-Table TimeCreated, User, ParentImage, Image, Flags -AutoSize

# ── Display command lines separately (they are often long) ──────────────
Write-Host "[*] Command line details:" -ForegroundColor Cyan
foreach ($se in $SuspiciousEvents) {
    Write-Host "    [$($se.TimeCreated.ToString('HH:mm:ss'))] $($se.Image)" -ForegroundColor Yellow
    Write-Host "    CMD: $($se.CommandLine)" -ForegroundColor White
    Write-Host ""
}

# ── Flag summary by category ───────────────────────────────────────────
Write-Host "[*] Detection category summary:" -ForegroundColor Cyan
$AllFlags = $SuspiciousEvents | ForEach-Object { $_.Flags -split ", " }
$AllFlags | Group-Object | Sort-Object Count -Descending |
    Select-Object @{N="Category";E={$_.Name}}, Count |
    Format-Table Category, Count -AutoSize

Write-Host "[*] Investigation steps:" -ForegroundColor Cyan
Write-Host "    1. Review full command lines for encoded payloads or suspicious arguments" -ForegroundColor White
Write-Host "    2. Check parent-child process relationships for abnormal chains" -ForegroundColor White
Write-Host "    3. Verify if the user account should be running these processes" -ForegroundColor White
Write-Host "    4. Correlate with network connection events (Sysmon EID 3)" -ForegroundColor White
Write-Host "    5. Check VirusTotal for file hashes if binaries are unknown" -ForegroundColor White
Write-Host "    References: MITRE ATT&CK T1059 (Command and Scripting Interpreter)," -ForegroundColor DarkGray
Write-Host "                T1218 (System Binary Proxy Execution)" -ForegroundColor DarkGray
