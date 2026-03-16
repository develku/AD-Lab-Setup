#Requires -RunAsAdministrator
#Requires -Module ActiveDirectory
<#
.SYNOPSIS
    Creates the Organisational Unit hierarchy for lab.local.

.DESCRIPTION
    Builds a structured OU tree reflecting a small enterprise:
    - Corporate (top-level)
      - IT, HR, Finance, Marketing (departmental)
      - Workstations, Servers (computer OUs)
      - Service Accounts
    - Disabled (for offboarded accounts)
#>

Import-Module ActiveDirectory

# Distinguished Name (DN) — the full LDAP path that uniquely identifies an object
# in Active Directory. The format reads right-to-left: DC=lab,DC=local means the
# "lab.local" domain. OUs are prepended: OU=IT,OU=Corporate,DC=lab,DC=local.
$DomainDN = "DC=lab,DC=local"

# ── Define OU Structure ───────────────────────────────────────────────────
# Organizational Units (OUs) — containers in AD used to organize objects (users,
# computers, groups) into a logical hierarchy. OUs serve three key purposes:
#   1. Delegation — assign admin rights over a subset of objects (e.g., IT manages IT OU)
#   2. GPO Targeting — Group Policies link to OUs, so different departments get different settings
#   3. Organization — mirrors the company structure for easy navigation and management
$OUs = @(
    # Corporate — top-level OU that mirrors a real enterprise structure. All active
    # business objects live under here, making it the primary GPO target.
    @{ Name = "Corporate";        Path = $DomainDN }

    # Disabled — a separate OU for offboarded user/computer accounts. Accounts are
    # moved here (not deleted) to preserve the audit trail and allow recovery if
    # the offboarding was a mistake. A restrictive GPO can be linked here to block all access.
    @{ Name = "Disabled";         Path = $DomainDN }

    # Department OUs under Corporate
    @{ Name = "IT";               Path = "OU=Corporate,$DomainDN" }
    @{ Name = "HR";               Path = "OU=Corporate,$DomainDN" }
    @{ Name = "Finance";          Path = "OU=Corporate,$DomainDN" }
    @{ Name = "Marketing";        Path = "OU=Corporate,$DomainDN" }

    # Computer OUs — separated from user OUs because computers and users receive
    # different Group Policies. Server GPOs (e.g., hardening, audit policies) should
    # not apply to workstations, and vice versa.
    @{ Name = "Workstations";     Path = "OU=Corporate,$DomainDN" }
    @{ Name = "Servers";          Path = "OU=Corporate,$DomainDN" }

    # Service Accounts — isolated in their own OU so they can receive distinct
    # password policies, be easily audited, and be monitored separately from
    # human user accounts (service accounts are high-value targets for attackers).
    @{ Name = "Service Accounts"; Path = "OU=Corporate,$DomainDN" }
)

# ── Create OUs ────────────────────────────────────────────────────────────
foreach ($OU in $OUs) {
    $ouDN = "OU=$($OU.Name),$($OU.Path)"

    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouDN'" -ErrorAction SilentlyContinue)) {
        # ProtectedFromAccidentalDeletion — an AD safety feature that prevents an OU
        # from being deleted without first unchecking this flag. Accidentally deleting
        # an OU would delete every object inside it (users, computers, groups).
        New-ADOrganizationalUnit -Name $OU.Name `
            -Path $OU.Path `
            -ProtectedFromAccidentalDeletion $true

        Write-Host "[+] Created OU: $ouDN" -ForegroundColor Green
    }
    else {
        Write-Host "[=] OU already exists: $ouDN" -ForegroundColor Yellow
    }
}

Write-Host "`n[*] OU structure created successfully." -ForegroundColor Cyan
Write-Host "[*] Verify with: Get-ADOrganizationalUnit -Filter * | Select Name, DistinguishedName" -ForegroundColor Cyan
