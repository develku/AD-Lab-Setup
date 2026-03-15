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
$DepartmentGroups = @(
    @{ Name = "SG-IT";        Description = "IT Department members";        OU = "IT" }
    @{ Name = "SG-HR";        Description = "HR Department members";        OU = "HR" }
    @{ Name = "SG-Finance";   Description = "Finance Department members";   OU = "Finance" }
    @{ Name = "SG-Marketing"; Description = "Marketing Department members"; OU = "Marketing" }
)

# ── Role-Based Security Groups ────────────────────────────────────────────
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

    # Add all users from the matching OU to the group
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
# IT staff get VPN + RDP access
$ITUsers = Get-ADUser -Filter * -SearchBase "OU=IT,$CorporateDN" -ErrorAction SilentlyContinue
foreach ($User in $ITUsers) {
    Add-ADGroupMember -Identity "SG-VPN-Access" -Members $User -ErrorAction SilentlyContinue
    Add-ADGroupMember -Identity "SG-Remote-Desktop-Users" -Members $User -ErrorAction SilentlyContinue
}

# All Corporate users get shared drive read + printer access
$AllUsers = Get-ADUser -Filter * -SearchBase $CorporateDN -ErrorAction SilentlyContinue
foreach ($User in $AllUsers) {
    Add-ADGroupMember -Identity "SG-Shared-Drive-Read" -Members $User -ErrorAction SilentlyContinue
    Add-ADGroupMember -Identity "SG-Printer-Access" -Members $User -ErrorAction SilentlyContinue
}

Write-Host "`n[*] Security groups created and members assigned." -ForegroundColor Cyan
Write-Host "[*] Verify with: Get-ADGroup -Filter 'Name -like \"SG-*\"' | Select Name" -ForegroundColor Cyan
