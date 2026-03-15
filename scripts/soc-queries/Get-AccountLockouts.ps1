#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Queries account lockout events and cross-references with failed logon sources.

.DESCRIPTION
    Retrieves Security Event ID 4740 (account lockout) from the event log and
    shows which accounts were locked, when, and from which computer the lockout
    originated. Cross-references with Event ID 4625 (failed logon) to identify
    the source IP that triggered the lockout.

    Account lockouts are often the visible consequence of brute-force attacks.
    Correlating the lockout with the failed logon source reveals the attacker's
    origin and distinguishes genuine brute-force from a user who simply forgot
    their password.

    MITRE ATT&CK: T1110 - Brute Force (consequence of credential attacks)
    https://attack.mitre.org/techniques/T1110/

.PARAMETER Hours
    Number of hours to look back. Default: 24.

.PARAMETER ComputerName
    Remote computer to query. Default: local machine.

.EXAMPLE
    .\Get-AccountLockouts.ps1
    Query the last 24 hours for account lockout events.

.EXAMPLE
    .\Get-AccountLockouts.ps1 -Hours 72 -ComputerName DC01
    Query DC01 for lockouts in the last 72 hours.
#>

param(
    [int]$Hours        = 24,
    [string]$ComputerName
)

$StartTime = (Get-Date).AddHours(-$Hours)

Write-Host "[*] Querying account lockout events (Event ID 4740)..." -ForegroundColor Cyan
Write-Host "    Time range: last $Hours hours (since $($StartTime.ToString('yyyy-MM-dd HH:mm')))" -ForegroundColor White

# ── Build query parameters ─────────────────────────────────────────────
$FilterHash = @{
    LogName   = "Security"
    Id        = 4740
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

# ── Retrieve lockout events ────────────────────────────────────────────
$LockoutEvents = Get-WinEvent @QueryParams

if (-not $LockoutEvents -or $LockoutEvents.Count -eq 0) {
    Write-Host "[+] No account lockout events found in the specified time range." -ForegroundColor Green
    return
}

Write-Host "[!] Found $($LockoutEvents.Count) account lockout event(s)." -ForegroundColor Yellow

# ── Parse lockout events ───────────────────────────────────────────────
$ParsedLockouts = foreach ($Event in $LockoutEvents) {
    $Xml = [xml]$Event.ToXml()
    $Data = $Xml.Event.EventData.Data

    $TargetUser     = ($Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
    $CallerComputer = ($Data | Where-Object { $_.Name -eq "TargetDomainName" }).'#text'

    [PSCustomObject]@{
        TimeCreated    = $Event.TimeCreated
        TargetUserName = $TargetUser
        CallerComputer = $CallerComputer
    }
}

Write-Host "`n[*] Account lockout details:" -ForegroundColor Cyan
$ParsedLockouts | Format-Table TimeCreated, TargetUserName, CallerComputer -AutoSize

# ── Cross-reference with failed logons (4625) ──────────────────────────
Write-Host "[*] Cross-referencing with failed logon events (Event ID 4625)..." -ForegroundColor Cyan

$FailedLogonFilter = @{
    LogName   = "Security"
    Id        = 4625
    StartTime = $StartTime
}

$FailedQueryParams = @{
    FilterHashtable = $FailedLogonFilter
    ErrorAction     = "SilentlyContinue"
}
if ($ComputerName) {
    $FailedQueryParams.ComputerName = $ComputerName
}

$FailedLogons = Get-WinEvent @FailedQueryParams

if ($FailedLogons -and $FailedLogons.Count -gt 0) {
    # Parse failed logons to find matching usernames
    $LockedUserNames = $ParsedLockouts | Select-Object -ExpandProperty TargetUserName -Unique

    foreach ($LockedUser in $LockedUserNames) {
        $MatchingFailures = foreach ($Event in $FailedLogons) {
            $Xml = [xml]$Event.ToXml()
            $Data = $Xml.Event.EventData.Data
            $TargetUser = ($Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'

            if ($TargetUser -eq $LockedUser) {
                $SourceIP = ($Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
                [PSCustomObject]@{
                    TimeCreated = $Event.TimeCreated
                    SourceIP    = $SourceIP
                }
            }
        }

        if ($MatchingFailures) {
            $SourceIPs = ($MatchingFailures | Select-Object -ExpandProperty SourceIP -Unique) -join ", "
            $FailCount = $MatchingFailures.Count
            Write-Host "[!] User '$LockedUser': $FailCount failed logon(s) from: $SourceIPs" -ForegroundColor Red
        } else {
            Write-Host "[?] User '$LockedUser': No matching failed logon events found." -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "[i] No failed logon events found for cross-reference." -ForegroundColor Yellow
}

# ── Summary ────────────────────────────────────────────────────────────
Write-Host "`n[*] Lockout summary:" -ForegroundColor Cyan
$ParsedLockouts | Group-Object TargetUserName | Sort-Object Count -Descending |
    Select-Object @{N="UserName";E={$_.Name}}, Count |
    Format-Table UserName, Count -AutoSize

Write-Host "[*] Investigation steps:" -ForegroundColor Cyan
Write-Host "    1. Check if the source IP is a known workstation or external" -ForegroundColor White
Write-Host "    2. Review failed logon reasons (wrong password vs. account disabled)" -ForegroundColor White
Write-Host "    3. Contact the user to verify if lockout was self-inflicted" -ForegroundColor White
Write-Host "    4. If brute-force suspected, block source IP and reset password" -ForegroundColor White
Write-Host "    Reference: MITRE ATT&CK T1110 (Brute Force)" -ForegroundColor DarkGray
