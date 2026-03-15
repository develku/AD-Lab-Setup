# Domain Controller Setup Guide

## Prerequisites

- Windows Server 2022 ISO (Evaluation: 180-day trial from Microsoft Evaluation Center)
- Hypervisor: VirtualBox, Hyper-V, or VMware Workstation
- VM specs: 2 vCPUs, 4 GB RAM, 60 GB disk

## Step 1: Create the Virtual Machine

1. Create a new VM with the specs above
2. Attach the Windows Server 2022 ISO
3. Install Windows Server 2022 **Desktop Experience**
4. Set the local Administrator password

## Step 2: Configure Networking

Before promoting to DC, set a static IP:

1. Open **Network and Sharing Center** > adapter settings
2. Set IPv4 properties:
   - IP: `192.168.10.10`
   - Subnet: `255.255.255.0`
   - Gateway: `192.168.10.1`
   - DNS: `127.0.0.1` (will point to itself after AD DS install)

Or via PowerShell:

```powershell
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress "192.168.10.10" -PrefixLength 24 -DefaultGateway "192.168.10.1"
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "127.0.0.1","8.8.8.8"
```

## Step 3: Promote to Domain Controller

Run the automated script:

```powershell
.\scripts\01-Install-ADForest.ps1
```

This will:
1. Rename the server to `DC01`
2. Install the AD DS role
3. Create the `lab.local` forest
4. Configure integrated DNS
5. Reboot the server

## Step 4: Post-Promotion Verification

After reboot, log in as `LAB\Administrator` and verify:

```powershell
# Verify AD DS is running
Get-Service NTDS, DNS, Netlogon | Select Name, Status

# Verify domain
Get-ADDomain | Select DNSRoot, DomainMode, InfrastructureMaster

# Verify DNS
Resolve-DnsName lab.local
Resolve-DnsName DC01.lab.local

# Verify forest
Get-ADForest | Select Name, ForestMode, RootDomain
```

Expected output:
- All services should show `Running`
- Domain should be `lab.local` with `WinThreshold` mode
- DNS should resolve both the domain and the DC hostname

## Step 5: Run Provisioning Scripts

Once the DC is verified, run the remaining scripts in order:

```powershell
.\scripts\02-Create-OUStructure.ps1
.\scripts\03-Create-Users.ps1
.\scripts\04-Create-SecurityGroups.ps1
.\scripts\05-Configure-GPOs.ps1
.\scripts\06-Configure-DHCP.ps1
```

## Next Steps

- [Join workstations to the domain](02-Workstation-Join.md)
- Test Group Policy application with `gpresult /r`
- Verify DHCP leases on workstations with `ipconfig /all`
