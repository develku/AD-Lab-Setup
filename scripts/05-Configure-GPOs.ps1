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

# Group Policy Objects (GPOs) — centralized configuration settings pushed from the
# domain controller to all domain-joined machines. GPOs can enforce security settings,
# deploy software, configure registry values, and more — ensuring every machine in
# the domain complies with organizational standards without manual configuration.
$DomainDN = "DC=lab,DC=local"
$CorporateDN = "OU=Corporate,$DomainDN"

# ── 1. Password and Account Lockout Policy ────────────────────────────────
# Account Policies (password length, complexity, lockout) must be applied via
# a secedit security template (GptTmpl.inf), NOT via Set-GPRegistryValue.
# Registry-based policies do not control Account Policies — Windows stores
# these in the GPO's GptTmpl.inf under [System Access].
$GPOName = "LAB-Password-Policy"
Write-Host "[*] Configuring $GPOName..." -ForegroundColor Cyan

$GPO = New-GPO -Name $GPOName -Comment "Enforces password complexity and account lockout thresholds"

# GPO Linking — a GPO only takes effect when linked to an OU, domain, or site.
# Password policies MUST be linked to the domain root — this is a Windows requirement.
# Account Policies (password length, lockout) linked to an OU are silently ignored.
New-GPLink -Name $GPOName -Target $DomainDN -LinkEnabled Yes -ErrorAction SilentlyContinue
Write-Host "[+] Created and linked: $GPOName" -ForegroundColor Green

# SYSVOL — a shared folder on every DC that stores GPO files, logon scripts, and
# policies. It is automatically replicated to all DCs via DFS-R so that every DC
# serves the same policy files regardless of which one a client contacts.
$GPOId = $GPO.Id
$GPOPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$GPOId}\Machine\Microsoft\Windows NT\SecEdit"
New-Item -Path $GPOPath -ItemType Directory -Force | Out-Null
Copy-Item "$PSScriptRoot\security-templates\password-policy.inf" "$GPOPath\GptTmpl.inf" -Force

# Force Group Policy replication
Invoke-GPUpdate -Force -ErrorAction SilentlyContinue

Write-Host "[+] Applied password and lockout policy via security template:" -ForegroundColor Green
Write-Host "      Minimum password length:      12 characters" -ForegroundColor White
Write-Host "      Password complexity:           Enabled" -ForegroundColor White
Write-Host "      Maximum password age:          90 days" -ForegroundColor White
Write-Host "      Minimum password age:          1 day" -ForegroundColor White
Write-Host "      Enforce password history:      10 passwords" -ForegroundColor White
Write-Host "      Account lockout threshold:     5 invalid attempts" -ForegroundColor White
Write-Host "      Account lockout duration:      30 minutes" -ForegroundColor White
Write-Host "      Reset lockout counter after:   30 minutes" -ForegroundColor White

# ── 2. Audit Policy ──────────────────────────────────────────────────────
# Advanced Audit Policy is applied by writing audit.csv directly into the GPO's
# Audit directory. This sets domain-wide policy (not local). The registry flag
# SCENoApplyLegacyAuditPolicy ensures Advanced Audit overrides legacy settings.
# These events feed into Sysmon/Splunk/ELK for SOC monitoring and SIEM ingestion.
$GPOName = "LAB-Audit-Policy"
Write-Host "`n[*] Configuring $GPOName..." -ForegroundColor Cyan

$GPO = New-GPO -Name $GPOName -Comment "Enables security event auditing for SIEM ingestion"
New-GPLink -Name $GPOName -Target $CorporateDN -LinkEnabled Yes -ErrorAction SilentlyContinue
Write-Host "[+] Created and linked: $GPOName" -ForegroundColor Green

# Enable Advanced Audit Policy (override legacy audit settings)
Set-GPRegistryValue -Name $GPOName `
    -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
    -ValueName "SCENoApplyLegacyAuditPolicy" -Type DWord -Value 1

# Define audit subcategories — essential for SOC monitoring / SIEM ingestion
$AuditCategories = @(
    @{ Subcategory = "Credential Validation";          Setting = "Success and Failure" }
    @{ Subcategory = "User Account Management";        Setting = "Success and Failure" }
    @{ Subcategory = "Logon";                          Setting = "Success and Failure" }
    @{ Subcategory = "Logoff";                         Setting = "Success" }
    @{ Subcategory = "Special Logon";                  Setting = "Success and Failure" }
    @{ Subcategory = "File Share";                     Setting = "Success and Failure" }
    @{ Subcategory = "File System";                    Setting = "Success and Failure" }
    @{ Subcategory = "Audit Policy Change";            Setting = "Success and Failure" }
    @{ Subcategory = "Authentication Policy Change";   Setting = "Success" }
    @{ Subcategory = "Sensitive Privilege Use";        Setting = "Success and Failure" }
    @{ Subcategory = "Security State Change";          Setting = "Success" }
)

# audit.csv — the file format Windows uses for Advanced Audit Policy configuration
# within GPOs. Each row maps a subcategory to a setting value (1=Success, 2=Failure,
# 3=Both, 0=None). This file is placed in the GPO's Audit directory in SYSVOL.
$GPOId = $GPO.Id
$AuditPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$GPOId}\Machine\Microsoft\Windows NT\Audit"
New-Item -Path $AuditPath -ItemType Directory -Force | Out-Null

$CsvContent = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value`n"
foreach ($cat in $AuditCategories) {
    $settingValue = switch ($cat.Setting) {
        "Success"             { 1 }
        "Failure"             { 2 }
        "Success and Failure" { 3 }
        "No Auditing"         { 0 }
    }
    $CsvContent += ",$($cat.Subcategory),,,$($cat.Setting),,$settingValue`n"
}
$CsvContent | Set-Content "$AuditPath\audit.csv" -Encoding Unicode

Write-Host "[+] Applied advanced audit policy via audit.csv:" -ForegroundColor Green
foreach ($cat in $AuditCategories) {
    Write-Host "      $($cat.Subcategory): $($cat.Setting)" -ForegroundColor White
}

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
# Removable Storage Blocking — prevents users from using USB drives, external hard
# disks, and other removable media. This mitigates two major risks:
#   - Data exfiltration: an insider copying sensitive files to a USB drive
#   - Malware delivery: infected USB drives dropped in parking lots (a real attack vector)
# IT is excluded because they may need USB access for legitimate administration.
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

# AUOptions value 4 — "Auto download and schedule the install." Other values:
#   2 = Notify before download, 3 = Auto download + notify before install,
#   5 = Allow local admin to choose. Value 4 is the enterprise standard —
#   updates download silently and install on a schedule to avoid disrupting users.
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
