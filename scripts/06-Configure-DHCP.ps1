#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs and configures DHCP on the Domain Controller.

.DESCRIPTION
    Installs the DHCP Server role, authorises it in AD, and creates scopes
    for the lab VLANs. Configures standard options (gateway, DNS, domain name).
#>

$DCIPAddress = "192.168.10.10"
$DomainName = "lab.local"

# ── Install DHCP Role ────────────────────────────────────────────────────
Write-Host "[*] Installing DHCP Server role..." -ForegroundColor Cyan
Install-WindowsFeature -Name DHCP -IncludeManagementTools

# ── Authorise DHCP in Active Directory ────────────────────────────────────
Write-Host "[*] Authorising DHCP server in Active Directory..." -ForegroundColor Cyan
Add-DhcpServerInDC -DnsName "DC01.$DomainName" -IPAddress $DCIPAddress

# Suppress post-install configuration flag
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12" `
    -Name "ConfigurationState" -Value 2 -ErrorAction SilentlyContinue

# ── VLAN 10: Server Scope ────────────────────────────────────────────────
$ScopeName = "VLAN10-Servers"
Write-Host "`n[*] Creating scope: $ScopeName..." -ForegroundColor Cyan

Add-DhcpServerv4Scope `
    -Name $ScopeName `
    -StartRange 192.168.10.100 `
    -EndRange 192.168.10.200 `
    -SubnetMask 255.255.255.0 `
    -LeaseDuration (New-TimeSpan -Days 8) `
    -State Active

# Exclude DC and infrastructure IPs from DHCP
Add-DhcpServerv4ExclusionRange -ScopeId 192.168.10.0 `
    -StartRange 192.168.10.1 -EndRange 192.168.10.20

# Set scope options
Set-DhcpServerv4OptionValue -ScopeId 192.168.10.0 `
    -Router 192.168.10.1 `
    -DnsServer $DCIPAddress `
    -DnsDomain $DomainName

Write-Host "[+] Scope created: 192.168.10.100-200 (excluding .1-.20)" -ForegroundColor Green

# ── VLAN 20: Workstation Scope ───────────────────────────────────────────
$ScopeName = "VLAN20-Workstations"
Write-Host "`n[*] Creating scope: $ScopeName..." -ForegroundColor Cyan

Add-DhcpServerv4Scope `
    -Name $ScopeName `
    -StartRange 192.168.20.100 `
    -EndRange 192.168.20.250 `
    -SubnetMask 255.255.255.0 `
    -LeaseDuration (New-TimeSpan -Days 8) `
    -State Active

Set-DhcpServerv4OptionValue -ScopeId 192.168.20.0 `
    -Router 192.168.20.1 `
    -DnsServer $DCIPAddress `
    -DnsDomain $DomainName

Write-Host "[+] Scope created: 192.168.20.100-250" -ForegroundColor Green

# ── VLAN 30: Management Scope ────────────────────────────────────────────
$ScopeName = "VLAN30-Management"
Write-Host "`n[*] Creating scope: $ScopeName..." -ForegroundColor Cyan

Add-DhcpServerv4Scope `
    -Name $ScopeName `
    -StartRange 192.168.30.100 `
    -EndRange 192.168.30.150 `
    -SubnetMask 255.255.255.0 `
    -LeaseDuration (New-TimeSpan -Days 1) `
    -State Active

Set-DhcpServerv4OptionValue -ScopeId 192.168.30.0 `
    -Router 192.168.30.1 `
    -DnsServer $DCIPAddress `
    -DnsDomain $DomainName

Write-Host "[+] Scope created: 192.168.30.100-150" -ForegroundColor Green

# ── Summary ──────────────────────────────────────────────────────────────
Write-Host "`n[*] DHCP configuration complete." -ForegroundColor Cyan
Write-Host "[*] Active scopes:" -ForegroundColor Cyan
Get-DhcpServerv4Scope | Format-Table Name, ScopeId, StartRange, EndRange, State -AutoSize
