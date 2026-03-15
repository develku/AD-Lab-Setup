#Requires -RunAsAdministrator
#Requires -Module ActiveDirectory
<#
.SYNOPSIS
    Creates service accounts in the Service Accounts OU.

.DESCRIPTION
    Provisions standard service accounts used by lab infrastructure services
    (backup, SQL, SIEM, vulnerability scanner). Accounts are created with
    generated passwords displayed to the console — passwords are NOT stored
    on disk.

    Service accounts are configured with PasswordNeverExpires and
    CannotChangePassword, following common enterprise patterns for
    non-interactive accounts.
#>

Import-Module ActiveDirectory

# Load the assembly needed for password generation
Add-Type -AssemblyName System.Web

$DomainDN = "DC=lab,DC=local"
$ServiceAccountOU = "OU=Service Accounts,OU=Corporate,$DomainDN"

# ── Verify target OU exists ─────────────────────────────────────────────
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ServiceAccountOU'" -ErrorAction SilentlyContinue)) {
    Write-Host "[-] Service Accounts OU not found: $ServiceAccountOU" -ForegroundColor Red
    Write-Host "[-] Run 02-Create-OUStructure.ps1 first." -ForegroundColor Red
    exit 1
}

# ── Define service accounts ─────────────────────────────────────────────
$ServiceAccounts = @(
    @{
        Name        = "svc-backup"
        DisplayName = "Backup Service Account"
        Description = "Used by backup software to read all shares and system state"
    }
    @{
        Name        = "svc-sql"
        DisplayName = "SQL Service Account"
        Description = "Used by database services (SQL Server agent and engine)"
    }
    @{
        Name        = "svc-siem"
        DisplayName = "SIEM Collection Account"
        Description = "Used by log collector to read Security and System event logs"
    }
    @{
        Name        = "svc-scan"
        DisplayName = "Vulnerability Scanner Account"
        Description = "Used by security scanner for authenticated vulnerability assessments"
    }
)

# ── Create service accounts ─────────────────────────────────────────────
$Created = 0
$Skipped = 0

foreach ($Svc in $ServiceAccounts) {
    $SamAccountName = $Svc.Name

    # Check if account already exists
    if (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue) {
        Write-Host "[=] Service account already exists: $SamAccountName" -ForegroundColor Yellow
        $Skipped++
        continue
    }

    # Generate a secure random password
    $Password = [System.Web.Security.Membership]::GeneratePassword(16, 4)
    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force

    New-ADUser `
        -SamAccountName $SamAccountName `
        -UserPrincipalName "$SamAccountName@lab.local" `
        -Name $Svc.DisplayName `
        -DisplayName $Svc.DisplayName `
        -Description $Svc.Description `
        -Path $ServiceAccountOU `
        -AccountPassword $SecurePassword `
        -PasswordNeverExpires $true `
        -CannotChangePassword $true `
        -ChangePasswordAtLogon $false `
        -Enabled $true

    Write-Host "[+] Created service account: $SamAccountName — $($Svc.Description)" -ForegroundColor Green
    Write-Host "    Temporary password: $Password" -ForegroundColor DarkGray
    $Created++
}

Write-Host "`n[*] Service account provisioning complete. Created: $Created | Skipped: $Skipped" -ForegroundColor Cyan
Write-Host "[!] Passwords were auto-generated. Note them from above — they are not saved to disk." -ForegroundColor Yellow
