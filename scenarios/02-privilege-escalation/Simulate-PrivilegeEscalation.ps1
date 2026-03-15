#Requires -RunAsAdministrator
#Requires -Module ActiveDirectory
<#
.SYNOPSIS
    Simulates insider threat privilege escalation for SOC detection training.

.DESCRIPTION
    TRAINING TOOL — Generates realistic privilege escalation telemetry by
    performing suspicious logon, AD reconnaissance, unauthorized group
    membership changes, and persistence account creation in the lab domain.

    This creates the following events in the Security event log:
    - Event ID 4624: Successful logon (initial access)
    - Event ID 4672: Special privileges assigned to new logon
    - Event ID 4728: Member added to a security-enabled global group
    - Event ID 4732: Member added to a security-enabled local group
    - Event ID 4720: User account created (persistence)

    The generated telemetry can then be detected using the SOC query scripts in
    scripts/soc-queries/, specifically Get-PrivilegeEscalation.ps1.

    WARNING: This script is designed for use in the lab.local training environment
    ONLY. Do not run this against production Active Directory domains.

    MITRE ATT&CK References:
      T1078 — Valid Accounts
      https://attack.mitre.org/techniques/T1078/

      T1098 — Account Manipulation
      https://attack.mitre.org/techniques/T1098/

      T1136 — Create Account
      https://attack.mitre.org/techniques/T1136/

      T1087 — Account Discovery
      https://attack.mitre.org/techniques/T1087/

.PARAMETER TargetUser
    The "compromised" account to simulate with. Default: bob.williams.

.PARAMETER DomainController
    Domain controller to run against. Default: DC01.lab.local.

.EXAMPLE
    .\Simulate-PrivilegeEscalation.ps1
    Run the full privilege escalation simulation with default settings.

.EXAMPLE
    .\Simulate-PrivilegeEscalation.ps1 -TargetUser "carol.davis"
    Simulate privilege escalation using a specific target account.

.EXAMPLE
    .\Simulate-PrivilegeEscalation.ps1 -TargetUser "alice.johnson" -DomainController "DC01.lab.local"
    Run against a specific DC with a specific target user.
#>

param(
    [string]$TargetUser       = "bob.williams",
    [string]$DomainController = "DC01.lab.local"
)

# ── Configuration ─────────────────────────────────────────────────────
$Domain     = "lab.local"
$DomainDN   = "DC=lab,DC=local"
$BackdoorUser        = "svc-update"
$BackdoorPassword    = "B@ckd00r2024!"
$BackdoorDescription = "Windows Update Service"

# ── Banner ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "║    PRIVILEGE ESCALATION SIMULATION — TRAINING ONLY         ║" -ForegroundColor Red
Write-Host "║  Generates Event IDs 4624/4672/4720/4728/4732 for SOC labs ║" -ForegroundColor Red
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
Write-Host ""

Write-Host "[*] Target user:       $TargetUser" -ForegroundColor Cyan
Write-Host "[*] Domain Controller: $DomainController" -ForegroundColor Cyan
Write-Host "[*] Domain:            $Domain" -ForegroundColor Cyan
Write-Host "[*] MITRE ATT&CK:     T1078, T1098, T1136, T1087" -ForegroundColor Cyan
Write-Host ""

# ── Validate target user exists ───────────────────────────────────────
$TargetADUser = Get-ADUser -Identity $TargetUser -ErrorAction SilentlyContinue
if (-not $TargetADUser) {
    Write-Host "[!] ERROR: User '$TargetUser' not found in Active Directory." -ForegroundColor Red
    Write-Host "[i] Run scripts\03-Create-Users.ps1 first to provision lab users." -ForegroundColor Yellow
    return
}

Write-Host "[+] Verified target user exists: $($TargetADUser.DistinguishedName)" -ForegroundColor Green
Write-Host ""

# ── Validate domain ──────────────────────────────────────────────────
$CurrentDomain = (Get-ADDomain -ErrorAction SilentlyContinue).DNSRoot
if ($CurrentDomain -ne $Domain) {
    Write-Host "[!] ERROR: Current domain is '$CurrentDomain', expected '$Domain'." -ForegroundColor Red
    Write-Host "[!] This script is designed for the lab.local training environment only." -ForegroundColor Red
    return
}

$StartTime = Get-Date

# ── Execute Simulation (with guaranteed cleanup) ─────────────────────
try {
    # ── Step 1: Suspicious Logon (T1078 — Valid Accounts) ─────────────
    Write-Host "[*] Step 1/5: Suspicious logon — LDAP bind as $TargetUser" -ForegroundColor Yellow
    Write-Host "    Generates: Event ID 4624 (Successful Logon)" -ForegroundColor White
    Write-Host "    ATT&CK:   T1078 — Valid Accounts" -ForegroundColor DarkGray

    try {
        $SecurePass = (Get-ADUser -Identity $TargetUser -ErrorAction Stop | Out-Null)
        # Perform LDAP bind to generate 4624 event
        $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://$DomainController",
            "$Domain\$TargetUser",
            "LabPass2024!"
        )
        try {
            $null = $DirectoryEntry.distinguishedName
            Write-Host "    [+] LDAP bind succeeded — Event ID 4624 generated" -ForegroundColor Green
        } catch {
            Write-Host "    [+] LDAP bind attempted — Event ID 4625 generated (expected if password wrong)" -ForegroundColor Green
            Write-Host "    [i] The logon attempt itself generates detectable telemetry" -ForegroundColor DarkGray
        } finally {
            if ($DirectoryEntry) { $DirectoryEntry.Dispose() }
        }
    } catch {
        Write-Host "    [!] LDAP bind error: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""
    Start-Sleep -Seconds 2

    # ── Step 2: Reconnaissance (T1087 — Account Discovery) ────────────
    Write-Host "[*] Step 2/5: AD reconnaissance — enumerating domain objects" -ForegroundColor Yellow
    Write-Host "    Generates: AD query patterns detectable in DC debug logs" -ForegroundColor White
    Write-Host "    ATT&CK:   T1087 — Account Discovery" -ForegroundColor DarkGray

    Write-Host "    [*] Enumerating domain users..." -ForegroundColor White
    $UserCount = (Get-ADUser -Filter * -Server $DomainController -ErrorAction SilentlyContinue).Count
    Write-Host "    [+] Found $UserCount user accounts" -ForegroundColor Green

    Write-Host "    [*] Enumerating domain groups..." -ForegroundColor White
    $GroupCount = (Get-ADGroup -Filter * -Server $DomainController -ErrorAction SilentlyContinue).Count
    Write-Host "    [+] Found $GroupCount groups" -ForegroundColor Green

    Write-Host "    [*] Enumerating domain computers..." -ForegroundColor White
    $ComputerCount = (Get-ADComputer -Filter * -Server $DomainController -ErrorAction SilentlyContinue).Count
    Write-Host "    [+] Found $ComputerCount computer accounts" -ForegroundColor Green

    Write-Host ""
    Start-Sleep -Seconds 2

    # ── Step 3: Privilege Escalation (T1098 — Account Manipulation) ───
    Write-Host "[*] Step 3/5: Privilege escalation — adding $TargetUser to Domain Admins" -ForegroundColor Yellow
    Write-Host "    Generates: Event ID 4728 (Member added to security-enabled global group)" -ForegroundColor White
    Write-Host "    ATT&CK:   T1098 — Account Manipulation" -ForegroundColor DarkGray

    Add-ADGroupMember -Identity "Domain Admins" -Members $TargetUser -Server $DomainController -ErrorAction Stop
    Write-Host "    [+] $TargetUser added to Domain Admins — Event ID 4728 generated" -ForegroundColor Green
    Write-Host "    [!] This is the critical event — a non-admin in a privileged group" -ForegroundColor Red

    Write-Host ""
    Write-Host "    [*] Waiting 5 seconds for event log to record..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 5

    # ── Step 4: Persistence (T1136 — Create Account) ──────────────────
    Write-Host "[*] Step 4/5: Persistence — creating backdoor account '$BackdoorUser'" -ForegroundColor Yellow
    Write-Host "    Generates: Event ID 4720 (User account created)" -ForegroundColor White
    Write-Host "    ATT&CK:   T1136 — Create Account" -ForegroundColor DarkGray

    $BackdoorSecurePass = ConvertTo-SecureString $BackdoorPassword -AsPlainText -Force

    New-ADUser -Name $BackdoorUser `
        -SamAccountName $BackdoorUser `
        -UserPrincipalName "$BackdoorUser@$Domain" `
        -Description $BackdoorDescription `
        -AccountPassword $BackdoorSecurePass `
        -Enabled $true `
        -Path "CN=Users,$DomainDN" `
        -Server $DomainController `
        -ErrorAction Stop

    Write-Host "    [+] Account '$BackdoorUser' created — Event ID 4720 generated" -ForegroundColor Green
    Write-Host "    [i] Description: '$BackdoorDescription' (designed to blend in)" -ForegroundColor DarkGray

    Start-Sleep -Seconds 2

    Write-Host "    [*] Adding '$BackdoorUser' to SG-Remote-Desktop-Users..." -ForegroundColor White
    Add-ADGroupMember -Identity "SG-Remote-Desktop-Users" -Members $BackdoorUser -Server $DomainController -ErrorAction Stop
    Write-Host "    [+] '$BackdoorUser' added to SG-Remote-Desktop-Users — Event ID 4732 generated" -ForegroundColor Green

    Write-Host ""
    Start-Sleep -Seconds 2

} finally {
    # ── Step 5: Cleanup (restore lab state) ───────────────────────────
    Write-Host "[*] Step 5/5: Cleanup — restoring lab to original state" -ForegroundColor Yellow
    Write-Host ""

    # Remove target from Domain Admins
    try {
        Remove-ADGroupMember -Identity "Domain Admins" -Members $TargetUser -Server $DomainController -Confirm:$false -ErrorAction Stop
        Write-Host "    [+] Removed $TargetUser from Domain Admins" -ForegroundColor Green
    } catch {
        Write-Host "    [!] WARNING: Failed to remove $TargetUser from Domain Admins: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "    [!] MANUAL FIX: Remove-ADGroupMember -Identity 'Domain Admins' -Members '$TargetUser' -Confirm:`$false" -ForegroundColor Red
    }

    # Remove backdoor account
    try {
        $BackdoorExists = Get-ADUser -Identity $BackdoorUser -Server $DomainController -ErrorAction SilentlyContinue
        if ($BackdoorExists) {
            Remove-ADUser -Identity $BackdoorUser -Server $DomainController -Confirm:$false -ErrorAction Stop
            Write-Host "    [+] Removed backdoor account '$BackdoorUser'" -ForegroundColor Green
        }
    } catch {
        Write-Host "    [!] WARNING: Failed to remove backdoor account '$BackdoorUser': $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "    [!] MANUAL FIX: Remove-ADUser -Identity '$BackdoorUser' -Confirm:`$false" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "    [*] Lab state restored. Events remain in Security log for investigation." -ForegroundColor Cyan
}

$EndTime  = Get-Date
$Duration = $EndTime - $StartTime

# ── Summary ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    SIMULATION COMPLETE                      ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "[*] Results:" -ForegroundColor Cyan
Write-Host "    Target user:   $TargetUser" -ForegroundColor White
Write-Host "    Backdoor user: $BackdoorUser (created and removed)" -ForegroundColor White
Write-Host "    Duration:      $($Duration.ToString('mm\:ss'))" -ForegroundColor White
Write-Host "    Kill chain:    Initial Access -> Discovery -> Privilege Escalation -> Persistence" -ForegroundColor White
Write-Host ""
Write-Host "[*] Events generated:" -ForegroundColor Cyan
Write-Host "    4624 — Logon (suspicious access)" -ForegroundColor White
Write-Host "    4728 — Added to Domain Admins (privilege escalation)" -ForegroundColor White
Write-Host "    4720 — Account created: $BackdoorUser (persistence)" -ForegroundColor White
Write-Host "    4732 — Added to SG-Remote-Desktop-Users (lateral movement prep)" -ForegroundColor White
Write-Host ""
Write-Host "[*] Simulation complete. To investigate this activity, run:" -ForegroundColor Green
Write-Host "    .\scripts\soc-queries\Get-PrivilegeEscalation.ps1 -Hours 1" -ForegroundColor White
Write-Host "    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} -MaxEvents 5" -ForegroundColor White
Write-Host ""
Write-Host "[*] For the full detection playbook, see:" -ForegroundColor Green
Write-Host "    scenarios\02-privilege-escalation\PLAYBOOK.md" -ForegroundColor White
Write-Host ""
