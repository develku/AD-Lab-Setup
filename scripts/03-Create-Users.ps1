#Requires -RunAsAdministrator
#Requires -Module ActiveDirectory
<#
.SYNOPSIS
    Bulk-provisions AD user accounts from a CSV file.

.DESCRIPTION
    Reads users.csv and creates accounts in the appropriate department OUs.
    Sets standard attributes: display name, email, title, department.
    Accounts are created enabled with password-change-at-next-logon.

    Passwords are generated at runtime — they are NOT stored in the CSV or
    any file tracked by source control. This follows the security best
    practice of never committing credentials to a repository.

.PARAMETER CsvPath
    Path to the CSV file. Defaults to users.csv in the same directory.

.PARAMETER DefaultPassword
    Optional default password to use for all accounts (lab convenience).
    If omitted, a unique 16-character random password is generated per user.
#>

param(
    [string]$CsvPath = "$PSScriptRoot\users.csv",
    [string]$DefaultPassword
)

Import-Module ActiveDirectory

# System.Web.Security.Membership — a .NET class that provides cryptographically
# secure password generation. GeneratePassword(16, 4) creates a 16-character password
# with at least 4 non-alphanumeric characters, meeting most complexity requirements.
Add-Type -AssemblyName System.Web

$DomainDN = "DC=lab,DC=local"
$DomainSuffix = "lab.local"

if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV file not found: $CsvPath"
    exit 1
}

$Users = Import-Csv -Path $CsvPath
$Created = 0
$Skipped = 0

foreach ($User in $Users) {
    # SamAccountName — the legacy "flat" logon name (e.g., alice.johnson) used by
    # older Windows protocols (NTLM). Limited to 20 characters, no domain suffix.
    $SamAccountName = ("$($User.FirstName).$($User.LastName)").ToLower()

    # UPN (User Principal Name) — the modern email-style logon format
    # (alice.johnson@lab.local). Used for Kerberos authentication and is the
    # preferred way to log into Windows and cloud services (like Azure AD).
    $UPN = "$SamAccountName@$DomainSuffix"
    $DisplayName = "$($User.FirstName) $($User.LastName)"

    # The Path determines which OU the user is created in. This controls which
    # GPOs apply to them and which admins can manage their account.
    $OUPath = "OU=$($User.Department),OU=Corporate,$DomainDN"

    # Check if user already exists
    if (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue) {
        Write-Host "[=] User already exists: $SamAccountName" -ForegroundColor Yellow
        $Skipped++
        continue
    }

    # Verify target OU exists
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OUPath'" -ErrorAction SilentlyContinue)) {
        Write-Host "[-] OU not found for $SamAccountName : $OUPath — skipping" -ForegroundColor Red
        $Skipped++
        continue
    }

    # Passwords generated at runtime, never stored in the CSV or source control.
    # This follows the security principle of separating secrets from code — if the
    # repo is leaked, no credentials are exposed.
    if ($DefaultPassword) {
        $Password = $DefaultPassword
    }
    else {
        $Password = [System.Web.Security.Membership]::GeneratePassword(16, 4)
    }

    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force

    # ChangePasswordAtLogon — forces the user to set their own password at first
    # login. This ensures only the user knows their password (the admin-set
    # temporary password is immediately replaced), supporting non-repudiation.
    New-ADUser `
        -SamAccountName $SamAccountName `
        -UserPrincipalName $UPN `
        -Name $DisplayName `
        -GivenName $User.FirstName `
        -Surname $User.LastName `
        -DisplayName $DisplayName `
        -Title $User.Title `
        -Department $User.Department `
        -EmailAddress "$SamAccountName@$DomainSuffix" `
        -Path $OUPath `
        -AccountPassword $SecurePassword `
        -ChangePasswordAtLogon $true `
        -Enabled $true

    Write-Host "[+] Created user: $SamAccountName ($DisplayName) in $($User.Department)" -ForegroundColor Green
    Write-Host "    Temporary password: $Password" -ForegroundColor DarkGray
    $Created++
}

Write-Host "`n[*] User provisioning complete. Created: $Created | Skipped: $Skipped" -ForegroundColor Cyan
if (-not $DefaultPassword) {
    Write-Host "[!] Passwords were auto-generated. Note them from above — they are not saved to disk." -ForegroundColor Yellow
}
