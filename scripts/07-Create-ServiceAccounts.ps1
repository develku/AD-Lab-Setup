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

# Service Accounts — AD accounts used by applications and services, not by humans.
# They run background processes (backups, database engines, log collectors) that need
# domain credentials to access network resources. They live in their own OU for:
#   - Distinct password policies (often longer, more complex than user passwords)
#   - Easier auditing (any interactive logon by a service account is suspicious)
#   - Separate GPO targeting (lock down interactive logon rights)
$ServiceAccountOU = "OU=Service Accounts,OU=Corporate,$DomainDN"

# ── Verify target OU exists ─────────────────────────────────────────────
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ServiceAccountOU'" -ErrorAction SilentlyContinue)) {
    Write-Host "[-] Service Accounts OU not found: $ServiceAccountOU" -ForegroundColor Red
    Write-Host "[-] Run 02-Create-OUStructure.ps1 first." -ForegroundColor Red
    exit 1
}

# ── Define service accounts ─────────────────────────────────────────────
# Each account maps to a real-world infrastructure service:
#   svc-backup — backup agent that needs read access to all file shares and system state
#   svc-sql    — SQL Server engine/agent; runs the database process under this identity
#   svc-siem   — SIEM log collector (e.g., Splunk forwarder, Wazuh agent) that reads event logs
#   svc-scan   — vulnerability scanner (e.g., Nessus, Qualys) that performs authenticated scans
#
# Enterprise Alternative: Group Managed Service Accounts (gMSA) — AD can automatically
# rotate service account passwords (every 30 days by default) without human intervention.
# gMSAs eliminate the risk of stale credentials, but require Server 2012+ DCs and
# application support. This lab uses standard accounts for simplicity.
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

    # Credential Hygiene — passwords are generated at runtime and displayed once.
    # They are never written to disk or committed to source control, reducing the
    # risk of credential exposure through file leaks or repo history.
    $Password = [System.Web.Security.Membership]::GeneratePassword(16, 4)
    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force

    # PasswordNeverExpires — service accounts need this because no human monitors them
    # for password expiry. If the password expired, the service would silently fail.
    # CannotChangePassword — prevents the running service from accidentally rotating
    # its own credential, which would break other systems that use the same password.
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
