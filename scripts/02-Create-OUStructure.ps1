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

$DomainDN = "DC=lab,DC=local"

# ── Define OU Structure ───────────────────────────────────────────────────
$OUs = @(
    # Top-level OUs
    @{ Name = "Corporate";        Path = $DomainDN }
    @{ Name = "Disabled";         Path = $DomainDN }

    # Department OUs under Corporate
    @{ Name = "IT";               Path = "OU=Corporate,$DomainDN" }
    @{ Name = "HR";               Path = "OU=Corporate,$DomainDN" }
    @{ Name = "Finance";          Path = "OU=Corporate,$DomainDN" }
    @{ Name = "Marketing";        Path = "OU=Corporate,$DomainDN" }

    # Computer OUs under Corporate
    @{ Name = "Workstations";     Path = "OU=Corporate,$DomainDN" }
    @{ Name = "Servers";          Path = "OU=Corporate,$DomainDN" }

    # Service accounts
    @{ Name = "Service Accounts"; Path = "OU=Corporate,$DomainDN" }
)

# ── Create OUs ────────────────────────────────────────────────────────────
foreach ($OU in $OUs) {
    $ouDN = "OU=$($OU.Name),$($OU.Path)"

    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouDN'" -ErrorAction SilentlyContinue)) {
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
