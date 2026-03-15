#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Queries failed logon events and identifies potential brute-force activity.

.DESCRIPTION
    Retrieves Security Event ID 4625 (failed logon) from the event log, groups
    results by source IP and target username, and flags accounts or sources
    exceeding the specified threshold. This is a primary indicator of credential
    brute-force or password spraying attacks.

    Output columns: TimeCreated, TargetUserName, SourceIP, LogonType, FailureReason

    LogonType reference:
      2  = Interactive (console)
      3  = Network (SMB, mapped drives)
      7  = Unlock
      10 = RemoteInteractive (RDP)

    MITRE ATT&CK: T1110 - Brute Force
    https://attack.mitre.org/techniques/T1110/

.PARAMETER Hours
    Number of hours to look back. Default: 24.

.PARAMETER ComputerName
    Remote computer to query. Default: local machine.

.PARAMETER Threshold
    Number of failed logons from a single source/user combination before
    flagging as suspicious. Default: 5.

.EXAMPLE
    .\Get-FailedLogons.ps1
    Query the last 24 hours for failed logon events.

.EXAMPLE
    .\Get-FailedLogons.ps1 -Hours 48 -Threshold 3
    Query the last 48 hours, flag any source/user with 3+ failures.

.EXAMPLE
    .\Get-FailedLogons.ps1 -ComputerName DC01
    Query failed logons on DC01.
#>

param(
    [int]$Hours        = 24,
    [string]$ComputerName,
    [int]$Threshold    = 5
)

$StartTime = (Get-Date).AddHours(-$Hours)

Write-Host "[*] Querying failed logon events (Event ID 4625)..." -ForegroundColor Cyan
Write-Host "    Time range: last $Hours hours (since $($StartTime.ToString('yyyy-MM-dd HH:mm')))" -ForegroundColor White

# ── Build query parameters ─────────────────────────────────────────────
$FilterHash = @{
    LogName   = "Security"
    Id        = 4625
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
    Write-Host "[+] No failed logon events found in the specified time range." -ForegroundColor Green
    return
}

Write-Host "[!] Found $($Events.Count) failed logon event(s)." -ForegroundColor Yellow

# ── Parse event data ───────────────────────────────────────────────────
$ParsedEvents = foreach ($Event in $Events) {
    $Xml = [xml]$Event.ToXml()
    $Data = $Xml.Event.EventData.Data

    $TargetUser  = ($Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
    $SourceIP    = ($Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
    $LogonType   = ($Data | Where-Object { $_.Name -eq "LogonType" }).'#text'
    $Status      = ($Data | Where-Object { $_.Name -eq "Status" }).'#text'
    $SubStatus   = ($Data | Where-Object { $_.Name -eq "SubStatus" }).'#text'

    # Map common failure reason codes
    $FailureReason = switch ($SubStatus) {
        "0xC0000064" { "User does not exist" }
        "0xC000006A" { "Wrong password" }
        "0xC0000072" { "Account disabled" }
        "0xC000006F" { "Outside logon hours" }
        "0xC0000070" { "Workstation restriction" }
        "0xC0000071" { "Password expired" }
        "0xC0000234" { "Account locked out" }
        default      { $SubStatus }
    }

    # Map logon type to human-readable label
    $LogonLabel = switch ($LogonType) {
        "2"  { "Interactive" }
        "3"  { "Network" }
        "7"  { "Unlock" }
        "10" { "RDP" }
        default { "Type $LogonType" }
    }

    [PSCustomObject]@{
        TimeCreated    = $Event.TimeCreated
        TargetUserName = $TargetUser
        SourceIP       = $SourceIP
        LogonType      = $LogonLabel
        FailureReason  = $FailureReason
    }
}

# ── Display all events ─────────────────────────────────────────────────
Write-Host "`n[*] Failed logon details:" -ForegroundColor Cyan
$ParsedEvents | Format-Table TimeCreated, TargetUserName, SourceIP, LogonType, FailureReason -AutoSize

# ── Group and flag suspicious sources ──────────────────────────────────
Write-Host "[*] Grouping by source IP and username (threshold: $Threshold)..." -ForegroundColor Cyan

$Grouped = $ParsedEvents | Group-Object SourceIP, TargetUserName |
    Where-Object { $_.Count -ge $Threshold } |
    Sort-Object Count -Descending |
    Select-Object @{N="SourceIP";E={($_.Name -split ", ")[0]}},
                  @{N="TargetUserName";E={($_.Name -split ", ")[1]}},
                  Count

if ($Grouped) {
    Write-Host "[!] ALERT: The following source/user combinations exceed the threshold:" -ForegroundColor Red
    $Grouped | Format-Table SourceIP, TargetUserName, Count -AutoSize
    Write-Host "[!] Possible brute-force activity detected (MITRE ATT&CK: T1110)." -ForegroundColor Red
} else {
    Write-Host "[+] No source/user combinations exceed the threshold of $Threshold." -ForegroundColor Green
}
