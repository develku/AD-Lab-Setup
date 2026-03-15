#Requires -RunAsAdministrator
#Requires -Module ActiveDirectory
#Requires -Module GroupPolicy
<#
.SYNOPSIS
    Creates and links Group Policy Objects for the lab domain.

.DESCRIPTION
    Configures GPOs commonly found in enterprise environments:
    - Password policy (minimum length, complexity, lockout)
    - Audit policy (logon events, object access, policy changes)
    - Drive mapping for shared resources
    - Disable removable storage for non-IT users
    - Windows Update configuration
#>

Import-Module ActiveDirectory
Import-Module GroupPolicy

$DomainDN = "DC=lab,DC=local"
$CorporateDN = "OU=Corporate,$DomainDN"

# ── 1. Password and Account Lockout Policy ────────────────────────────────
$GPOName = "LAB-Password-Policy"
Write-Host "[*] Configuring $GPOName..." -ForegroundColor Cyan

$GPO = New-GPO -Name $GPOName -Comment "Enforces password complexity and account lockout thresholds"

# Password policy settings via registry-based policies
Set-GPRegistryValue -Name $GPOName -Key "HKLM\Software\Policies\Lab" `
    -ValueName "PasswordPolicyApplied" -Type String -Value "True"

# Link to domain root for domain-wide password policy
New-GPLink -Name $GPOName -Target $DomainDN -LinkEnabled Yes -ErrorAction SilentlyContinue
Write-Host "[+] Created and linked: $GPOName" -ForegroundColor Green

Write-Host @"
    [i] Manual steps required for fine-grained password policy:
        - Open GPMC > $GPOName > Computer Configuration
        - Navigate: Policies > Windows Settings > Security Settings > Account Policies
        - Password Policy:
            Minimum password length:        12 characters
            Password must meet complexity:  Enabled
            Maximum password age:           90 days
            Minimum password age:           1 day
            Enforce password history:       10 passwords
        - Account Lockout Policy:
            Account lockout threshold:      5 invalid attempts
            Account lockout duration:       30 minutes
            Reset lockout counter after:    30 minutes
"@ -ForegroundColor DarkYellow

# ── 2. Audit Policy ──────────────────────────────────────────────────────
$GPOName = "LAB-Audit-Policy"
Write-Host "`n[*] Configuring $GPOName..." -ForegroundColor Cyan

$GPO = New-GPO -Name $GPOName -Comment "Enables security event auditing for SIEM ingestion"
New-GPLink -Name $GPOName -Target $CorporateDN -LinkEnabled Yes -ErrorAction SilentlyContinue
Write-Host "[+] Created and linked: $GPOName" -ForegroundColor Green

Write-Host @"
    [i] Manual steps required for audit policy:
        - Open GPMC > $GPOName > Computer Configuration
        - Navigate: Policies > Windows Settings > Security Settings > Advanced Audit Policy
        - Enable (Success + Failure):
            Account Logon:   Audit Credential Validation
            Account Mgmt:    Audit User Account Management
            Logon/Logoff:    Audit Logon, Audit Logoff, Audit Special Logon
            Object Access:   Audit File Share, Audit File System
            Policy Change:   Audit Policy Change, Audit Authentication Policy Change
            Privilege Use:   Audit Sensitive Privilege Use
            System:          Audit Security State Change
        - These events feed into Sysmon/Splunk/ELK for SOC monitoring
"@ -ForegroundColor DarkYellow

# ── 3. Drive Mapping ─────────────────────────────────────────────────────
$GPOName = "LAB-Drive-Mapping"
Write-Host "`n[*] Configuring $GPOName..." -ForegroundColor Cyan

$GPO = New-GPO -Name $GPOName -Comment "Maps shared network drives for Corporate users"

Set-GPRegistryValue -Name $GPOName `
    -Key "HKCU\Software\Policies\Lab\DriveMappings" `
    -ValueName "SharedDrive" -Type String -Value "\\DC01\Shared"

New-GPLink -Name $GPOName -Target $CorporateDN -LinkEnabled Yes -ErrorAction SilentlyContinue
Write-Host "[+] Created and linked: $GPOName" -ForegroundColor Green

Write-Host @"
    [i] Manual steps for drive mapping via Group Policy Preferences:
        - Open GPMC > $GPOName > User Configuration
        - Navigate: Preferences > Windows Settings > Drive Maps
        - New Mapped Drive:
            Action:   Create
            Location: \\DC01\Shared
            Drive:    S:
            Label:    Shared Drive
        - Item-level targeting: Security Group = SG-Shared-Drive-Read
"@ -ForegroundColor DarkYellow

# ── 4. Disable Removable Storage (non-IT users) ─────────────────────────
$GPOName = "LAB-Disable-USB"
Write-Host "`n[*] Configuring $GPOName..." -ForegroundColor Cyan

$GPO = New-GPO -Name $GPOName -Comment "Blocks removable storage for non-IT departments"

Set-GPRegistryValue -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices" `
    -ValueName "Deny_All" -Type DWord -Value 1

# Link to non-IT department OUs
$NonITDepts = @("HR", "Finance", "Marketing")
foreach ($Dept in $NonITDepts) {
    New-GPLink -Name $GPOName -Target "OU=$Dept,$CorporateDN" -LinkEnabled Yes -ErrorAction SilentlyContinue
}
Write-Host "[+] Created and linked: $GPOName (HR, Finance, Marketing)" -ForegroundColor Green

# ── 5. Windows Update Policy ─────────────────────────────────────────────
$GPOName = "LAB-Windows-Update"
Write-Host "`n[*] Configuring $GPOName..." -ForegroundColor Cyan

$GPO = New-GPO -Name $GPOName -Comment "Configures Windows Update schedule and auto-install"

# Auto download and schedule install (option 4)
Set-GPRegistryValue -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -ValueName "AUOptions" -Type DWord -Value 4

# Schedule install day: 0 = every day
Set-GPRegistryValue -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -ValueName "ScheduledInstallDay" -Type DWord -Value 0

# Schedule install time: 3 = 3:00 AM
Set-GPRegistryValue -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -ValueName "ScheduledInstallTime" -Type DWord -Value 3

New-GPLink -Name $GPOName -Target $CorporateDN -LinkEnabled Yes -ErrorAction SilentlyContinue
Write-Host "[+] Created and linked: $GPOName" -ForegroundColor Green

# ── Summary ──────────────────────────────────────────────────────────────
Write-Host "`n[*] GPO configuration complete." -ForegroundColor Cyan
Write-Host "[*] GPOs created:" -ForegroundColor Cyan
Get-GPO -All | Where-Object { $_.DisplayName -like "LAB-*" } | ForEach-Object {
    Write-Host "    - $($_.DisplayName)" -ForegroundColor White
}
Write-Host "[*] Verify with: gpresult /r (on a domain-joined workstation)" -ForegroundColor Cyan
