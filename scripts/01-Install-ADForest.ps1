#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Promotes a Windows Server to a Domain Controller and creates a new AD forest.

.DESCRIPTION
    Installs AD DS role, creates the lab.local forest, and configures DNS.
    The server will reboot automatically after promotion.

.NOTES
    Run this on a clean Windows Server 2022 installation.
    Ensure a static IP (192.168.10.10/24) is configured before running.
#>

$DomainName = "lab.local"
$NetBIOSName = "LAB"
$SafeModePassword = Read-Host -AsSecureString -Prompt "Enter DSRM (Safe Mode) password"

# ── Set Static IP ──────────────────────────────────────────────────────────
Write-Host "[*] Configuring static IP address..." -ForegroundColor Cyan
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

New-NetIPAddress -InterfaceIndex $adapter.ifIndex `
    -IPAddress "192.168.10.10" `
    -PrefixLength 24 `
    -DefaultGateway "192.168.10.1" -ErrorAction SilentlyContinue

Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
    -ServerAddresses "127.0.0.1", "8.8.8.8"

# ── Rename Server ──────────────────────────────────────────────────────────
Write-Host "[*] Renaming server to DC01..." -ForegroundColor Cyan
Rename-Computer -NewName "DC01" -Force -ErrorAction SilentlyContinue

# ── Install AD DS Role ─────────────────────────────────────────────────────
Write-Host "[*] Installing Active Directory Domain Services role..." -ForegroundColor Cyan
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# ── Promote to Domain Controller ──────────────────────────────────────────
Write-Host "[*] Promoting server to Domain Controller..." -ForegroundColor Cyan
Write-Host "[*] Domain: $DomainName" -ForegroundColor Yellow
Write-Host "[!] Server will reboot after promotion completes." -ForegroundColor Red

Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $NetBIOSName `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns:$true `
    -SafeModeAdministratorPassword $SafeModePassword `
    -Force:$true

# Server reboots automatically after promotion
