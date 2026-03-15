# AD-Lab-Setup

Home lab Active Directory environment with automated provisioning scripts. Built to simulate a small enterprise domain for practising IT support, systems administration, and security operations.

## Lab Overview

| Component | Details |
|---|---|
| Domain Controller | Windows Server 2022, `lab.local` |
| Workstations | Windows 10/11 (domain-joined) |
| Network | 192.168.10.0/24, VLAN-segmented |
| Services | AD DS, DNS, DHCP, Group Policy |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   lab.local Domain                   │
│                                                     │
│  ┌──────────────┐    ┌──────────────────────────┐   │
│  │  DC01         │    │  Network Services        │   │
│  │  192.168.10.10│    │  DNS:  192.168.10.10     │   │
│  │  AD DS        │    │  DHCP: 192.168.10.100-200│   │
│  │  DNS / DHCP   │    │  GW:   192.168.10.1      │   │
│  └──────────────┘    └──────────────────────────┘   │
│                                                     │
│  ┌──────────────┐    ┌──────────────┐               │
│  │  WS01         │    │  WS02         │              │
│  │  Win 10       │    │  Win 11       │              │
│  │  IT Support   │    │  End User     │              │
│  │  192.168.10.x │    │  192.168.10.x │              │
│  └──────────────┘    └──────────────┘               │
│                                                     │
│  VLANs:                                             │
│  ├── VLAN 10: Servers    (192.168.10.0/24)          │
│  ├── VLAN 20: Workstations (192.168.20.0/24)        │
│  └── VLAN 30: Management   (192.168.30.0/24)        │
└─────────────────────────────────────────────────────┘
```

See [diagrams/](diagrams/) for detailed draw.io network diagrams.

## Repository Structure

```
AD-Lab-Setup/
├── scripts/
│   ├── 01-Install-ADForest.ps1       # Promote server to DC and create forest
│   ├── 02-Create-OUStructure.ps1     # Build OU hierarchy
│   ├── 03-Create-Users.ps1           # Bulk user provisioning from CSV
│   ├── 04-Create-SecurityGroups.ps1  # Security groups and membership
│   ├── 05-Configure-GPOs.ps1         # Group Policy Objects
│   ├── 06-Configure-DHCP.ps1         # DHCP scope and options
│   └── users.csv                     # Sample user data
├── diagrams/
│   └── network-topology.drawio       # Network diagram (draw.io)
├── docs/
│   ├── 01-DC-Setup.md                # Domain Controller build guide
│   ├── 02-Workstation-Join.md        # Domain join procedure
│   └── 03-Troubleshooting.md         # Common issues and fixes
└── README.md
```

## Quick Start

### Prerequisites

- Windows Server 2022 (evaluation ISO works)
- Hypervisor: VirtualBox, Hyper-V, or VMware
- At least 8 GB RAM for DC + 1 workstation

### Step 1: Promote Domain Controller

```powershell
# Run as Administrator on Windows Server
.\scripts\01-Install-ADForest.ps1
# Server will reboot automatically
```

### Step 2: Build OU Structure and Provision Users

```powershell
# After reboot, run in order:
.\scripts\02-Create-OUStructure.ps1
.\scripts\03-Create-Users.ps1
.\scripts\04-Create-SecurityGroups.ps1
.\scripts\05-Configure-GPOs.ps1
.\scripts\06-Configure-DHCP.ps1
```

### Step 3: Join Workstations

Follow [docs/02-Workstation-Join.md](docs/02-Workstation-Join.md) to join Windows clients to the domain.

## What This Demonstrates

- **AD DS Administration:** Forest/domain creation, OU design, user lifecycle management
- **Group Policy:** Password policies, drive mappings, software restrictions, audit policies
- **Network Services:** DNS, DHCP scoping, VLAN segmentation
- **Automation:** PowerShell-based provisioning for repeatable deployments
- **Documentation:** Step-by-step build guides and troubleshooting procedures
