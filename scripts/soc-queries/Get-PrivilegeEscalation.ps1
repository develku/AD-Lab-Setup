#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Queries privilege escalation events including special logons and group changes.

.DESCRIPTION
    Retrieves Security Event IDs related to privilege escalation:
    - 4672: Special privileges assigned to new logon (admin logon)
    - 4728: Member added to a security-enabled global group
    - 4732: Member added to a security-enabled local group

    Flags activity where non-standard accounts receive elevated privileges or
    are added to sensitive groups (Domain Admins, Administrators, etc.). This
    detects both legitimate privilege grants that should be reviewed and
    unauthorized privilege escalation by attackers.

    MITRE ATT&CK:
    - T1078 - Valid Accounts (abusing legitimate credentials for elevated access)
      https://attack.mitre.org/techniques/T1078/
    - T1098 - Account Manipulation (modifying accounts to maintain persistence)
      https://attack.mitre.org/techniques/T1098/

.PARAMETER Hours
    Number of hours to look back. Default: 24.

.PARAMETER ComputerName
    Remote computer to query. Default: local machine.

.EXAMPLE
    .\Get-PrivilegeEscalation.ps1
    Query the last 24 hours for privilege escalation events.

.EXAMPLE
    .\Get-PrivilegeEscalation.ps1 -Hours 168
    Query the last 7 days for privilege escalation events.
#>

param(
    [int]$Hours        = 24,
    [string]$ComputerName
)

$StartTime = (Get-Date).AddHours(-$Hours)

Write-Host "[*] Querying privilege escalation events (Event IDs 4672, 4728, 4732)..." -ForegroundColor Cyan
Write-Host "    Time range: last $Hours hours (since $($StartTime.ToString('yyyy-MM-dd HH:mm')))" -ForegroundColor White

# Known system/service accounts to exclude from 4672 alerts (reduce noise)
$ExcludedAccounts = @("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "DWM-2", "UMFD-0", "UMFD-1")

# Sensitive groups that warrant investigation when modified
$SensitiveGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins",
                      "Administrators", "Account Operators", "Backup Operators",
                      "Server Operators", "Print Operators")

# ── Build query parameters ─────────────────────────────────────────────
$FilterHash = @{
    LogName   = "Security"
    Id        = @(4672, 4728, 4732)
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
    Write-Host "[+] No privilege escalation events found in the specified time range." -ForegroundColor Green
    return
}

Write-Host "[*] Processing $($Events.Count) event(s)..." -ForegroundColor Cyan

# ── Parse special privilege logon events (4672) ────────────────────────
$PrivilegeEvents = foreach ($Event in ($Events | Where-Object { $_.Id -eq 4672 })) {
    $Xml = [xml]$Event.ToXml()
    $Data = $Xml.Event.EventData.Data

    $SubjectUser   = ($Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
    $SubjectDomain = ($Data | Where-Object { $_.Name -eq "SubjectDomainName" }).'#text'
    $PrivilegeList = ($Data | Where-Object { $_.Name -eq "PrivilegeList" }).'#text'

    # Skip known system accounts to reduce noise
    if ($SubjectUser -in $ExcludedAccounts) { continue }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        EventType   = "Special Logon"
        Account     = "$SubjectDomain\$SubjectUser"
        Detail      = ($PrivilegeList -replace "`n", ", " -replace "\s+", " ").Trim()
    }
}

# ── Parse group membership changes (4728, 4732) ────────────────────────
$GroupEvents = foreach ($Event in ($Events | Where-Object { $_.Id -in @(4728, 4732) })) {
    $Xml = [xml]$Event.ToXml()
    $Data = $Xml.Event.EventData.Data

    $SubjectUser = ($Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
    $MemberSid   = ($Data | Where-Object { $_.Name -eq "MemberSid" }).'#text'
    $MemberName  = ($Data | Where-Object { $_.Name -eq "MemberName" }).'#text'
    $GroupName   = ($Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'

    $EventLabel = if ($Event.Id -eq 4728) { "Global Group Add" } else { "Local Group Add" }
    $MemberDisplay = if ($MemberName) { $MemberName } else { $MemberSid }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        EventType   = $EventLabel
        Account     = $MemberDisplay
        Detail      = "Added to '$GroupName' by $SubjectUser"
    }
}

# ── Display all privilege events ───────────────────────────────────────
$AllEvents = @()
if ($PrivilegeEvents) { $AllEvents += $PrivilegeEvents }
if ($GroupEvents)     { $AllEvents += $GroupEvents }

if ($AllEvents.Count -eq 0) {
    Write-Host "[+] No notable privilege events (system accounts excluded)." -ForegroundColor Green
    return
}

Write-Host "`n[*] Privilege escalation events:" -ForegroundColor Cyan
$AllEvents | Sort-Object TimeCreated -Descending |
    Format-Table TimeCreated, EventType, Account, Detail -AutoSize -Wrap

# ── Flag sensitive group modifications ─────────────────────────────────
if ($GroupEvents) {
    $SensitiveChanges = $GroupEvents | Where-Object {
        foreach ($sg in $SensitiveGroups) {
            if ($_.Detail -like "*$sg*") { return $true }
        }
        return $false
    }

    if ($SensitiveChanges) {
        Write-Host "[!] ALERT: Sensitive group membership changes detected:" -ForegroundColor Red
        $SensitiveChanges | Format-Table TimeCreated, Account, Detail -AutoSize -Wrap
        Write-Host "[!] Review immediately — unauthorized group changes indicate compromise." -ForegroundColor Red
        Write-Host "    MITRE ATT&CK: T1098 (Account Manipulation)" -ForegroundColor DarkGray
    }
}

# ── Summary ────────────────────────────────────────────────────────────
Write-Host "`n[*] Event type summary:" -ForegroundColor Cyan
$AllEvents | Group-Object EventType |
    Select-Object @{N="EventType";E={$_.Name}}, Count |
    Format-Table EventType, Count -AutoSize

Write-Host "[*] Investigation steps:" -ForegroundColor Cyan
Write-Host "    1. Verify group changes were authorized via change management" -ForegroundColor White
Write-Host "    2. Check if admin logons (4672) correspond to maintenance windows" -ForegroundColor White
Write-Host "    3. Look for unusual timing (after hours, weekends)" -ForegroundColor White
Write-Host "    4. Correlate with VPN/remote access logs if applicable" -ForegroundColor White
Write-Host "    References: MITRE ATT&CK T1078 (Valid Accounts), T1098 (Account Manipulation)" -ForegroundColor DarkGray
