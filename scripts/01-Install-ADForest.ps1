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

# Active Directory (AD) — Microsoft's centralized identity and access management
# system. It stores user accounts, computers, groups, and policies in a database
# that the entire network relies on for authentication ("who are you?") and
# authorization ("what are you allowed to do?").

# Forest — the top-level security boundary in AD. A forest contains one or more
# domains that share a common schema and trust each other. lab.local is both
# the forest root and the only domain in this lab.
$DomainName = "lab.local"

# NetBIOS Name — a legacy flat name (no dots) used for backward compatibility with
# older Windows protocols. When you see "LAB\alice.johnson", "LAB" is the NetBIOS name.
$NetBIOSName = "LAB"

# DSRM (Directory Services Restore Mode) — a special boot mode used to repair or
# recover the AD database when the domain controller can't start normally. This
# password is the only way in if AD is corrupted, so it must be stored securely.
$SafeModePassword = Read-Host -AsSecureString -Prompt "Enter DSRM (Safe Mode) password"

# ── Set Static IP ──────────────────────────────────────────────────────────
# A Domain Controller must have a static IP because every domain-joined machine
# points to it for DNS and authentication. If the DC's IP changed via DHCP,
# all clients would lose contact with AD.
Write-Host "[*] Configuring static IP address..." -ForegroundColor Cyan
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

New-NetIPAddress -InterfaceIndex $adapter.ifIndex `
    -IPAddress "192.168.10.10" `
    -PrefixLength 24 `
    -DefaultGateway "192.168.10.1" -ErrorAction SilentlyContinue

# DNS set to 127.0.0.1 first — the DC will be its own DNS server once AD is installed.
# AD depends entirely on DNS to locate services (e.g., clients find DCs via SRV records
# like _ldap._tcp.lab.local). 8.8.8.8 is a fallback for external name resolution.
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
    -ServerAddresses "127.0.0.1", "8.8.8.8"

# ── Rename Server ──────────────────────────────────────────────────────────
Write-Host "[*] Renaming server to DC01..." -ForegroundColor Cyan
Rename-Computer -NewName "DC01" -Force -ErrorAction SilentlyContinue

# ── Install AD DS Role ─────────────────────────────────────────────────────
# This installs the AD DS binaries but does NOT create the domain yet.
# The actual domain creation happens in the "promote" step below.
Write-Host "[*] Installing Active Directory Domain Services role..." -ForegroundColor Cyan
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# ── Promote to Domain Controller ──────────────────────────────────────────
# "Promoting" a server means transforming a regular Windows Server into a Domain
# Controller (DC). After promotion, this server hosts the AD database (NTDS.dit),
# handles authentication requests, and replicates directory data.
Write-Host "[*] Promoting server to Domain Controller..." -ForegroundColor Cyan
Write-Host "[*] Domain: $DomainName" -ForegroundColor Yellow
Write-Host "[!] Server will reboot after promotion completes." -ForegroundColor Red

# ForestMode "WinThreshold" — sets the forest functional level to Windows Server 2016.
# This determines which AD features are available. Higher levels enable newer features
# but require all DCs in the forest to run at least that Windows Server version.
# -InstallDns installs the DNS Server role alongside AD — required because AD
# uses DNS as its service locator (clients find DCs through DNS SRV records).
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $NetBIOSName `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns:$true `
    -SafeModeAdministratorPassword $SafeModePassword `
    -Force:$true

# Server reboots automatically after promotion
