#Requires -RunAsAdministrator
#Requires -Module ActiveDirectory
<#
.SYNOPSIS
    Creates security groups and assigns members based on department.

.DESCRIPTION
    Creates department-based security groups and role-based groups (e.g., VPN Access,
    Remote Desktop Users). Assigns users to groups based on their OU membership.
#>

Import-Module ActiveDirectory

$DomainDN = "DC=lab,DC=local"
$CorporateDN = "OU=Corporate,$DomainDN"

# ── Department Security Groups ────────────────────────────────────────────
# Security Groups — collections of users (or computers) used to assign permissions
# in bulk. Instead of granting file share access to 50 individual users, you grant
# it to one group and add users to that group. Two types exist in AD:
#   - Security groups: can be assigned permissions (file shares, GPOs, etc.)
#   - Distribution groups: used only for email distribution lists, no permissions
#
# SG- Prefix — a naming convention that identifies security groups at a glance.
# Enterprise environments use prefixes (SG-, DL-, OU-) to distinguish object types
# when browsing AD or writing scripts.
$DepartmentGroups = @(
    @{ Name = "SG-IT";        Description = "IT Department members";        OU = "IT" }
    @{ Name = "SG-HR";        Description = "HR Department members";        OU = "HR" }
    @{ Name = "SG-Finance";   Description = "Finance Department members";   OU = "Finance" }
    @{ Name = "SG-Marketing"; Description = "Marketing Department members"; OU = "Marketing" }
)

# ── Role-Based Security Groups ────────────────────────────────────────────
# RBAC (Role-Based Access Control) — instead of assigning permissions per user,
# you define roles (VPN Access, RDP Access) and assign users to the role. This
# makes onboarding/offboarding simple: add or remove group membership, and all
# associated permissions follow automatically.
$RoleGroups = @(
    @{ Name = "SG-VPN-Access";           Description = "Users permitted VPN access" }
    @{ Name = "SG-Remote-Desktop-Users"; Description = "Users permitted RDP access to servers" }
    @{ Name = "SG-Shared-Drive-Read";    Description = "Read access to shared network drives" }
    @{ Name = "SG-Shared-Drive-Write";   Description = "Write access to shared network drives" }
    @{ Name = "SG-Printer-Access";       Description = "Access to network printers" }
)

# ── Create Department Groups and Add Members ──────────────────────────────
foreach ($Group in $DepartmentGroups) {
    $GroupPath = $CorporateDN

    if (-not (Get-ADGroup -Filter "Name -eq '$($Group.Name)'" -ErrorAction SilentlyContinue)) {
        # GroupScope Global — can contain members from the same domain and be used
        # to assign permissions anywhere in the forest. Global groups are the standard
        # choice for department/role groups in single-domain environments.
        # GroupCategory Security — makes this group usable for permissions (vs Distribution).
        New-ADGroup -Name $Group.Name `
            -GroupScope Global `
            -GroupCategory Security `
            -Description $Group.Description `
            -Path $GroupPath

        Write-Host "[+] Created group: $($Group.Name)" -ForegroundColor Green
    }
    else {
        Write-Host "[=] Group already exists: $($Group.Name)" -ForegroundColor Yellow
    }

    # Auto-populate group membership from OU — ensures group membership stays aligned
    # with the organizational structure. When a user is placed in the IT OU, they
    # automatically get added to SG-IT.
    $OUPath = "OU=$($Group.OU),$CorporateDN"
    $Users = Get-ADUser -Filter * -SearchBase $OUPath -ErrorAction SilentlyContinue

    foreach ($User in $Users) {
        Add-ADGroupMember -Identity $Group.Name -Members $User -ErrorAction SilentlyContinue
        Write-Host "    [+] Added $($User.SamAccountName) to $($Group.Name)" -ForegroundColor DarkGreen
    }
}

# ── Create Role-Based Groups ─────────────────────────────────────────────
foreach ($Group in $RoleGroups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$($Group.Name)'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $Group.Name `
            -GroupScope Global `
            -GroupCategory Security `
            -Description $Group.Description `
            -Path $CorporateDN

        Write-Host "[+] Created group: $($Group.Name)" -ForegroundColor Green
    }
    else {
        Write-Host "[=] Group already exists: $($Group.Name)" -ForegroundColor Yellow
    }
}

# ── Default Role Assignments ─────────────────────────────────────────────
# Principle of Least Privilege — users should only have the minimum access required
# for their role. IT staff need VPN and RDP to manage infrastructure remotely, but
# HR/Finance/Marketing do not — giving everyone RDP would expand the attack surface.
$ITUsers = Get-ADUser -Filter * -SearchBase "OU=IT,$CorporateDN" -ErrorAction SilentlyContinue
foreach ($User in $ITUsers) {
    Add-ADGroupMember -Identity "SG-VPN-Access" -Members $User -ErrorAction SilentlyContinue
    Add-ADGroupMember -Identity "SG-Remote-Desktop-Users" -Members $User -ErrorAction SilentlyContinue
}

# All Corporate users get shared drive read + printer access — these are baseline
# resources that every employee needs to perform their job.
$AllUsers = Get-ADUser -Filter * -SearchBase $CorporateDN -ErrorAction SilentlyContinue
foreach ($User in $AllUsers) {
    Add-ADGroupMember -Identity "SG-Shared-Drive-Read" -Members $User -ErrorAction SilentlyContinue
    Add-ADGroupMember -Identity "SG-Printer-Access" -Members $User -ErrorAction SilentlyContinue
}

Write-Host "`n[*] Security groups created and members assigned." -ForegroundColor Cyan
Write-Host "[*] Verify with: Get-ADGroup -Filter 'Name -like \"SG-*\"' | Select Name" -ForegroundColor Cyan
