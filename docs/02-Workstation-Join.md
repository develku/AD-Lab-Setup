# Domain Join Procedure

## Prerequisites

- Domain Controller (DC01) is running and accessible
- Workstation VM: Windows 10 or 11, 2 vCPUs, 4 GB RAM, 40 GB disk
- Network connectivity to DC01 (192.168.10.10)
- Workstations should be on **VLAN 20** (192.168.20.0/24) — DHCP will assign addresses from the range 192.168.20.100–250

## Step 1: Configure Workstation Network

Workstations live on **VLAN 20** (192.168.20.0/24) and receive their IP via DHCP.
DNS must still point to the Domain Controller on VLAN 10:

```powershell
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "192.168.10.10"
```

> **Note:** If DHCP is active, DNS will be set automatically via the DHCP scope options
> (VLAN 20 scope pushes 192.168.10.10 as DNS server).

Verify DNS resolution:

```powershell
nslookup lab.local
# Should resolve to 192.168.10.10

Test-Connection DC01.lab.local
# Should succeed
```

## Step 2: Join the Domain

### Option A: GUI

1. Open **System Properties** > **Computer Name** > **Change**
2. Select **Domain** and enter `lab.local`
3. Authenticate with `LAB\Administrator` credentials
4. Restart when prompted

### Option B: PowerShell

```powershell
# Rename and join in one step
Add-Computer -DomainName "lab.local" `
    -NewName "WS01" `
    -Credential (Get-Credential LAB\Administrator) `
    -Restart
```

## Step 3: Verify Domain Join

After reboot, log in with a domain account (e.g., `LAB\alice.johnson`):

```powershell
# Verify domain membership
(Get-WmiObject Win32_ComputerSystem).Domain
# Expected: lab.local

# Check computer object in AD (run from DC01)
Get-ADComputer -Identity "WS01" | Select Name, DNSHostName, DistinguishedName

# Verify Group Policy application
gpresult /r
# Should show applied GPOs under "Applied Group Policy Objects"

# Verify DHCP lease
ipconfig /all
# Should show DHCP-assigned IP, DNS pointing to 192.168.10.10
```

## Step 4: Move Computer to Correct OU

By default, new computers land in the `Computers` container. Move to the Workstations OU:

```powershell
# Run on DC01
$Computer = Get-ADComputer "WS01"
Move-ADObject -Identity $Computer -TargetPath "OU=Workstations,OU=Corporate,DC=lab,DC=local"
```

Force a Group Policy update on the workstation:

```powershell
gpupdate /force
```

## Troubleshooting

| Issue | Check |
|---|---|
| Cannot resolve `lab.local` | Verify DNS is set to 192.168.10.10 |
| "Domain not found" error | Ensure DC01 is running and DNS service is active |
| Authentication fails | Verify user account exists and is enabled in AD |
| GPO not applying | Run `gpresult /r`, check OU placement, run `gpupdate /force` |
| DHCP not assigning IP | Verify DHCP scope is active, check exclusion ranges |
