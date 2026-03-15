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

# Load the assembly needed for password generation
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
    $SamAccountName = ("$($User.FirstName).$($User.LastName)").ToLower()
    $UPN = "$SamAccountName@$DomainSuffix"
    $DisplayName = "$($User.FirstName) $($User.LastName)"
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

    # Generate or use the supplied password
    if ($DefaultPassword) {
        $Password = $DefaultPassword
    }
    else {
        $Password = [System.Web.Security.Membership]::GeneratePassword(16, 4)
    }

    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force

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
