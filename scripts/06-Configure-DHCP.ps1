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
# DHCP (Dynamic Host Configuration Protocol) — automatically assigns IP addresses
# to devices on the network. Without DHCP, every machine would need its IP, subnet
# mask, gateway, and DNS server configured manually — impractical at scale.
Write-Host "[*] Installing DHCP Server role..." -ForegroundColor Cyan
Install-WindowsFeature -Name DHCP -IncludeManagementTools

# ── Authorise DHCP in Active Directory ────────────────────────────────────
# Rogue DHCP Prevention — In an AD environment, a DHCP server must be explicitly
# authorized in Active Directory before it can lease addresses. This prevents
# unauthorized DHCP servers from handing out wrong IPs or rogue gateways, which
# could redirect traffic (a man-in-the-middle attack vector).
Write-Host "[*] Authorising DHCP server in Active Directory..." -ForegroundColor Cyan
Add-DhcpServerInDC -DnsName "DC01.$DomainName" -IPAddress $DCIPAddress

# Server Manager shows a post-install "configuration required" warning for DHCP.
# Setting ConfigurationState to 2 suppresses this cosmetic nag in the dashboard.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12" `
    -Name "ConfigurationState" -Value 2 -ErrorAction SilentlyContinue

# ── VLAN 10: Server Scope ────────────────────────────────────────────────
# DHCP Scope — a scope defines the range of IP addresses that DHCP can hand out
# for a given subnet. Each VLAN gets its own scope so devices on different network
# segments receive addresses in their own range.
#
# VLANs (Virtual LANs) — separate broadcast domains on the same physical network.
# Servers, workstations, and management devices are isolated into VLANs so that
# a compromised workstation can't directly reach server infrastructure (defense in depth).
$ScopeName = "VLAN10-Servers"
Write-Host "`n[*] Creating scope: $ScopeName..." -ForegroundColor Cyan

# Lease Duration — how long a device keeps its assigned IP before it must renew.
# Servers get longer leases (8 days) because they rarely move or change networks.
Add-DhcpServerv4Scope `
    -Name $ScopeName `
    -StartRange 192.168.10.100 `
    -EndRange 192.168.10.200 `
    -SubnetMask 255.255.255.0 `
    -LeaseDuration (New-TimeSpan -Days 8) `
    -State Active

# Exclusion Range — reserves IPs that DHCP must never hand out. The DC (.10),
# the gateway (.1), and other infrastructure devices use static IPs. Without
# exclusions, DHCP could assign these addresses to another device, causing conflicts.
Add-DhcpServerv4ExclusionRange -ScopeId 192.168.10.0 `
    -StartRange 192.168.10.1 -EndRange 192.168.10.20

# Scope Options — additional network settings DHCP pushes to clients alongside
# the IP address: the default gateway (Router) for reaching other networks,
# the DNS server for name resolution, and the domain suffix for DNS searches.
Set-DhcpServerv4OptionValue -ScopeId 192.168.10.0 `
    -Router 192.168.10.1 `
    -DnsServer $DCIPAddress `
    -DnsDomain $DomainName

Write-Host "[+] Scope created: 192.168.10.100-200 (excluding .1-.20)" -ForegroundColor Green

# ── VLAN 20: Workstation Scope ───────────────────────────────────────────
# Workstations get a larger range (.100-.250) because there are typically more
# end-user devices than servers. Same lease duration as servers for lab simplicity.
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
# Management VLAN — used for network switches, access points, and admin interfaces.
# Shorter lease (1 day) because management devices may be temporary or transient,
# and shorter leases free up addresses faster when devices disconnect.
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
