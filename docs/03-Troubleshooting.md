# Troubleshooting Guide

Common issues encountered during AD lab setup and their resolutions.

## AD DS / Domain Controller

### DC promotion fails with "prerequisite check failed"

**Cause:** DNS delegation or network configuration issue.

**Fix:**
```powershell
# Ensure DNS points to localhost
Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object Status -eq "Up" | Select -First 1).ifIndex -ServerAddresses "127.0.0.1"

# Verify no conflicting DNS zones
Get-DnsServerZone
```

### Cannot log in after DC promotion

**Cause:** Must use domain credentials post-promotion.

**Fix:** Log in as `LAB\Administrator` (not `.\Administrator`).

### SYSVOL or NETLOGON shares not available

**Cause:** DFS Replication not yet initialised.

**Fix:**
```powershell
# Check share status
Get-SmbShare | Where-Object { $_.Name -match "SYSVOL|NETLOGON" }

# If missing, restart DFS
Restart-Service DFSR
# Wait 5 minutes and check again
```

## DNS

### Workstation cannot resolve domain name

**Cause:** Workstation DNS not pointing to DC.

**Fix:**
```powershell
# On the workstation
Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object Status -eq "Up" | Select -First 1).ifIndex -ServerAddresses "192.168.10.10"

# Flush DNS cache
Clear-DnsClientCache

# Test resolution
Resolve-DnsName lab.local
```

### Reverse DNS lookup fails

**Cause:** Reverse lookup zone not created automatically.

**Fix:**
```powershell
# On DC01
Add-DnsServerPrimaryZone -NetworkId "192.168.10.0/24" -ReplicationScope Domain
```

## DHCP

The lab uses three DHCP scopes (one per VLAN):

| Scope | VLAN | Range | Purpose |
|---|---|---|---|
| 192.168.10.0 | 10 | .100–.200 | Servers |
| 192.168.20.0 | 20 | .100–.250 | Workstations |
| 192.168.30.0 | 30 | .100–.150 | Management |

### Clients not receiving IP addresses

**Cause:** DHCP not authorised in AD, or scope not active.

**Fix:**
```powershell
# Check authorisation
Get-DhcpServerInDC

# Check scope status — all three scopes should be Active
Get-DhcpServerv4Scope | Select ScopeId, State

# Activate the appropriate scope if inactive
Set-DhcpServerv4Scope -ScopeId 192.168.20.0 -State Active   # Workstations
Set-DhcpServerv4Scope -ScopeId 192.168.30.0 -State Active   # Management
Set-DhcpServerv4Scope -ScopeId 192.168.10.0 -State Active   # Servers
```

### IP conflict detected

**Cause:** Static IP overlaps with DHCP range.

**Fix:**
```powershell
# Check current leases (use the scope matching the conflicting subnet)
Get-DhcpServerv4Lease -ScopeId 192.168.20.0   # Workstations
Get-DhcpServerv4Lease -ScopeId 192.168.10.0   # Servers

# Add exclusion for the conflicting IP (example for workstation VLAN)
Add-DhcpServerv4ExclusionRange -ScopeId 192.168.20.0 -StartRange 192.168.20.50 -EndRange 192.168.20.50
```

## Group Policy

### GPO not applying to a user or computer

**Cause:** Object in wrong OU, or GPO link disabled.

**Fix:**
```powershell
# On the target machine
gpresult /r
# Check "Applied Group Policy Objects" and "Denied Group Policy Objects"

# On DC — verify OU placement
Get-ADUser -Identity "alice.johnson" | Select DistinguishedName
Get-ADComputer -Identity "WS01" | Select DistinguishedName

# Verify GPO is linked
Get-GPInheritance -Target "OU=Corporate,DC=lab,DC=local"
```

### Changes to GPO not taking effect

**Cause:** Group Policy cache or replication delay.

**Fix:**
```powershell
# Force GP update on target machine
gpupdate /force

# If still not applied, clear the GP cache (use with caution)
# Reboot is the safest option
Restart-Computer
```

## User Accounts

### Account locked out

**Cause:** Exceeded lockout threshold (5 invalid attempts per GPO).

**Fix:**
```powershell
# Check lockout status
Get-ADUser -Identity "alice.johnson" -Properties LockedOut | Select LockedOut

# Unlock the account
Unlock-ADAccount -Identity "alice.johnson"

# Find lockout source
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740} -MaxEvents 5 |
    Select TimeCreated, @{N='User';E={$_.Properties[0].Value}}, @{N='Source';E={$_.Properties[1].Value}}
```

### Password expired or must change at next logon

**Fix:**
```powershell
# Reset password
Set-ADAccountPassword -Identity "alice.johnson" -Reset -NewPassword (ConvertTo-SecureString "NewP@ssw0rd!" -AsPlainText -Force)

# Remove change-at-logon flag if needed
Set-ADUser -Identity "alice.johnson" -ChangePasswordAtLogon $false
```

## Network Connectivity

### Cannot ping between VMs

**Cause:** Windows Firewall blocking ICMP, or VMs on different virtual networks.

**Fix:**
```powershell
# Enable ICMP (ping) through Windows Firewall
New-NetFirewallRule -DisplayName "Allow ICMPv4" -Protocol ICMPv4 -IcmpType 8 -Action Allow -Direction Inbound

# Verify both VMs are on the same virtual switch/network
Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.InterfaceAlias -notlike "Loopback*" }
```
