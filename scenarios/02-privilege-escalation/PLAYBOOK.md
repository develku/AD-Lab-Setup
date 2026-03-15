# Privilege Escalation Detection Playbook

SOC detection and response playbook for investigating suspicious logon activity and unauthorized privilege escalation in the lab.local domain.

---

## 1. Scenario Overview

| Field | Details |
|---|---|
| **Attack Type** | Insider Threat / Compromised Account with Privilege Escalation |
| **MITRE ATT&CK** | [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/), [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/), [T1136 — Create Account](https://attack.mitre.org/techniques/T1136/), [T1087 — Account Discovery](https://attack.mitre.org/techniques/T1087/) |
| **Severity** | High (privilege escalation is always high severity) |
| **Data Sources** | Windows Security Event Log |
| **Key Event IDs** | 4624 (Logon), 4672 (Special Logon), 4720 (Account Created), 4728 (Global Group Add), 4732 (Local Group Add) |
| **Kill Chain** | Initial Access -> Discovery -> Privilege Escalation -> Persistence |
| **Detection Scripts** | `scripts/soc-queries/Get-PrivilegeEscalation.ps1`, `scripts/soc-queries/Get-SuspiciousProcesses.ps1` |

### What Makes This Scenario Important

Privilege escalation is a high-severity event in every SOC. Unlike brute force (which may fail), a successful privilege escalation means the attacker already has valid credentials and is actively expanding their access. This scenario covers the full kill chain from initial access through persistence:

1. Detect when a non-admin account is added to a privileged group
2. Identify backdoor accounts created for persistence
3. Build a timeline of the full attack chain
4. Execute containment and remediation actions

This is a core Tier 2 SOC analyst investigation — connecting multiple events into a coherent attack narrative.

---

## 2. Attack Simulation

### Running the Simulation

```powershell
# Default: simulate privilege escalation using bob.williams
.\scenarios\02-privilege-escalation\Simulate-PrivilegeEscalation.ps1

# Simulate with a specific target user
.\scenarios\02-privilege-escalation\Simulate-PrivilegeEscalation.ps1 -TargetUser "carol.davis"
```

### What Each Step Generates

| Step | Action | Event IDs | ATT&CK Technique |
|---|---|---|---|
| 1. Suspicious Logon | LDAP bind as target user | 4624 (Logon) | T1078 — Valid Accounts |
| 2. Reconnaissance | Enumerate users, groups, computers | AD query patterns | T1087 — Account Discovery |
| 3. Privilege Escalation | Add target user to Domain Admins | 4728 (Global Group Add) | T1098 — Account Manipulation |
| 4. Persistence | Create backdoor account `svc-update`, add to SG-Remote-Desktop-Users | 4720 (Account Created), 4732 (Local Group Add) | T1136 — Create Account |
| 5. Cleanup | Remove escalation and backdoor | (reversal events) | N/A — lab restoration |

### Expected Timeline

The simulation runs in approximately 15 seconds and generates events in this order:

```
T+0s   — 4624: Logon as target user (initial access)
T+2s   — AD enumeration queries (discovery)
T+4s   — 4728: Target user added to Domain Admins (escalation)
T+9s   — 4720: svc-update account created (persistence)
T+11s  — 4732: svc-update added to SG-Remote-Desktop-Users (persistence)
T+13s  — Cleanup: group membership removed, backdoor account deleted
```

Events remain in the Security event log after cleanup for investigation practice.

---

## 3. Detection

### Step 1: Run the Privilege Escalation Detection Script

```powershell
.\scripts\soc-queries\Get-PrivilegeEscalation.ps1 -Hours 1
```

Expected output after simulation:

```
[*] Querying privilege escalation events (Event IDs 4672, 4728, 4732)...
    Time range: last 1 hours

[*] Privilege escalation events:
TimeCreated           EventType        Account              Detail
-----------           ---------        -------              ------
2024-03-15 14:32:09   Global Group Add bob.williams         Added to 'Domain Admins' by Administrator
2024-03-15 14:32:20   Local Group Add  svc-update           Added to 'SG-Remote-Desktop-Users' by Administrator

[!] ALERT: Sensitive group membership changes detected:
TimeCreated           Account          Detail
-----------           -------          ------
2024-03-15 14:32:09   bob.williams     Added to 'Domain Admins' by Administrator
```

### Step 2: Check for New Account Creation

```powershell
# Query for account creation events (Event ID 4720)
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4720
    StartTime = (Get-Date).AddHours(-1)
} -MaxEvents 10 | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    $Data = $Xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        NewAccount  = ($Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
        CreatedBy   = ($Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
        Domain      = ($Data | Where-Object { $_.Name -eq "TargetDomainName" }).'#text'
    }
} | Format-Table -AutoSize
```

### Key Indicators to Watch For

| Indicator | Why It Matters | Event ID |
|---|---|---|
| Non-admin account added to Domain Admins or Enterprise Admins | Direct privilege escalation — highest severity | 4728 |
| New user account created outside provisioning workflow | Possible backdoor for persistence | 4720 |
| Account with service-like name (svc-*) not from provisioning script | Attackers use service account naming to blend in | 4720 |
| Logon followed by immediate AD enumeration queries | Reconnaissance pattern before lateral movement | 4624 |
| Account added to remote access groups (RDP, VPN) | Setting up alternative access paths | 4732 |
| Special logon (4672) for an account that is not normally admin | Account may have been escalated | 4672 |

### Raw Detection Queries

For analysts who want to build custom detections:

```powershell
# Detect Domain Admins membership changes (Event ID 4728)
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4728
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    $Data = $Xml.Event.EventData.Data
    $GroupName = ($Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
    if ($GroupName -in @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")) {
        [PSCustomObject]@{
            Time      = $_.TimeCreated
            Group     = $GroupName
            MemberSid = ($Data | Where-Object { $_.Name -eq "MemberSid" }).'#text'
            ChangedBy = ($Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
        }
    }
} | Format-Table -AutoSize

# Detect new accounts with suspicious naming patterns
Get-ADUser -Filter { whenCreated -gt $((Get-Date).AddHours(-1)) } -Properties Description, whenCreated |
    Where-Object { $_.SamAccountName -like "svc-*" -or $_.SamAccountName -like "admin*" -or $_.SamAccountName -like "test*" } |
    Select-Object SamAccountName, Description, whenCreated
```

---

## 4. Investigation

Once privilege escalation activity is detected, build a complete attack timeline by working through these steps. The goal is to reconstruct the full kill chain.

### Step 1: When Did the Suspicious Logon Occur?

Identify when the compromised account first authenticated:

```powershell
# Find logon events for the suspected compromised account
$SuspectUser = "bob.williams"

Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4624
    StartTime = (Get-Date).AddHours(-2)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    $Data = $Xml.Event.EventData.Data
    $User = ($Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'

    if ($User -eq $SuspectUser) {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            User        = $User
            LogonType   = ($Data | Where-Object { $_.Name -eq "LogonType" }).'#text'
            SourceIP    = ($Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
            LogonId     = ($Data | Where-Object { $_.Name -eq "TargetLogonId" }).'#text'
        }
    }
} | Format-Table -AutoSize
```

**What to look for:**
- Logon from an unusual source IP or workstation
- Logon outside business hours (nights, weekends)
- LogonType 3 (Network) or 10 (RemoteInteractive/RDP) from unexpected sources

### Step 2: What Was the Source Machine?

Determine where the access originated:

```powershell
# Resolve the source IP to a hostname
$SourceIP = "192.168.20.10"  # Replace with actual IP from Step 1
Resolve-DnsName -Name $SourceIP -ErrorAction SilentlyContinue

# Check DHCP leases to identify the machine
Get-DhcpServerv4Lease -ScopeId "192.168.20.0" -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -eq $SourceIP } |
    Select-Object IPAddress, HostName, ClientId
```

### Step 3: What Reconnaissance Was Performed?

Check for AD enumeration activity that indicates discovery:

```powershell
# Check for bulk AD queries (Directory Service Access events)
# Event ID 4662 logs directory service access — high volume indicates enumeration
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4662
    StartTime = (Get-Date).AddHours(-1)
} -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    $Data = $Xml.Event.EventData.Data
    $User = ($Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'

    if ($User -eq $SuspectUser) {
        [PSCustomObject]@{
            Time       = $_.TimeCreated
            User       = $User
            ObjectType = ($Data | Where-Object { $_.Name -eq "ObjectType" }).'#text'
            AccessMask = ($Data | Where-Object { $_.Name -eq "AccessMask" }).'#text'
        }
    }
} | Format-Table -AutoSize
```

### Step 4: What Privilege Changes Were Made?

Identify exactly which group memberships were modified:

```powershell
# Get all group membership changes in the attack window
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = @(4728, 4732)
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    $Data = $Xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventId     = $_.Id
        EventType   = if ($_.Id -eq 4728) { "Global Group Add" } else { "Local Group Add" }
        GroupName   = ($Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
        MemberAdded = ($Data | Where-Object { $_.Name -eq "MemberName" }).'#text'
        MemberSid   = ($Data | Where-Object { $_.Name -eq "MemberSid" }).'#text'
        ChangedBy   = ($Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
    }
} | Format-Table -AutoSize
```

**Critical check:** Was the user added to any of these high-value groups?
- Domain Admins, Enterprise Admins, Schema Admins
- Administrators, Account Operators, Backup Operators

### Step 5: Were Any New Accounts Created?

Check for persistence through account creation:

```powershell
# Check for accounts created during the attack window (Event ID 4720)
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4720
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    $Data = $Xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated   = $_.TimeCreated
        NewAccount    = ($Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
        CreatedBy     = ($Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
        AccountDomain = ($Data | Where-Object { $_.Name -eq "TargetDomainName" }).'#text'
    }
} | Format-Table -AutoSize

# Cross-check: does the account still exist? (simulation cleans up, real attacks won't)
Get-ADUser -Filter { whenCreated -gt $((Get-Date).AddHours(-1)) } -Properties Description, whenCreated, MemberOf |
    Select-Object SamAccountName, Description, whenCreated, @{N="Groups";E={($_.MemberOf | ForEach-Object { ($_ -split ",")[0] -replace "CN=" }) -join ", "}}
```

### Step 6: Did the Attacker Achieve Elevated Access?

Check for special logon events (4672) that confirm the escalated privileges were used:

```powershell
# Look for special logon events for the suspected account
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4672
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    $Data = $Xml.Event.EventData.Data
    $User = ($Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'

    if ($User -notin @("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "DWM-2", "UMFD-0", "UMFD-1")) {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            User        = "$($($Data | Where-Object { $_.Name -eq 'SubjectDomainName' }).'#text')\$User"
            Privileges  = (($Data | Where-Object { $_.Name -eq "PrivilegeList" }).'#text' -replace "`n", ", " -replace "\s+", " ").Trim()
        }
    }
} | Format-Table -AutoSize
```

### Correlating Events by LogonId

Link all events from the same logon session to build a complete attack chain:

```powershell
# Extract the LogonId from the suspicious 4624 event, then find all related events
$SuspiciousLogonId = "0x12345"  # Replace with actual LogonId from Step 1

Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    StartTime = (Get-Date).AddHours(-1)
} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object {
    $Xml = [xml]$_.ToXml()
    $Data = $Xml.Event.EventData.Data
    $LogonId = ($Data | Where-Object { $_.Name -eq "SubjectLogonId" -or $_.Name -eq "TargetLogonId" }).'#text'
    $LogonId -eq $SuspiciousLogonId
} | Select-Object TimeCreated, Id, @{N="Summary";E={$_.Message.Split("`n")[0]}} |
    Sort-Object TimeCreated | Format-Table -AutoSize
```

---

## 5. Response Actions

### Immediate Actions (First 15 Minutes)

**Remove unauthorized group memberships:**

```powershell
# Remove the compromised user from privileged groups
Remove-ADGroupMember -Identity "Domain Admins" -Members "bob.williams" -Confirm:$false
Remove-ADGroupMember -Identity "Enterprise Admins" -Members "bob.williams" -Confirm:$false -ErrorAction SilentlyContinue

# Verify removal
Get-ADUser -Identity "bob.williams" -Properties MemberOf |
    Select-Object -ExpandProperty MemberOf | ForEach-Object { ($_ -split ",")[0] -replace "CN=" }
```

**Disable the compromised account:**

```powershell
# Disable the compromised account immediately
Disable-ADAccount -Identity "bob.williams"

# Verify the account is disabled
Get-ADUser -Identity "bob.williams" -Properties Enabled | Select-Object Name, Enabled
```

**Disable and remove backdoor accounts:**

```powershell
# Find and disable any backdoor accounts
$SuspiciousAccounts = Get-ADUser -Filter { whenCreated -gt $((Get-Date).AddHours(-2)) } -Properties Description, whenCreated
foreach ($Account in $SuspiciousAccounts) {
    Write-Host "[!] Suspicious account: $($Account.SamAccountName) — Created: $($Account.whenCreated) — Description: $($Account.Description)" -ForegroundColor Red
    Disable-ADAccount -Identity $Account.SamAccountName
    Write-Host "    [+] Account disabled" -ForegroundColor Green
}
```

### Containment (First Hour)

**Force password reset and revoke active sessions:**

```powershell
# Force password reset for the compromised account
Set-ADAccountPassword -Identity "bob.williams" -Reset -NewPassword (
    Read-Host "Enter new password for bob.williams" -AsSecureString
)

# Force password change at next logon
Set-ADUser -Identity "bob.williams" -ChangePasswordAtLogon $true

# Purge Kerberos tickets to revoke active sessions
# Run this on the compromised workstation:
klist purge

# If you have remote access to the workstation:
Invoke-Command -ComputerName "WS01" -ScriptBlock { klist purge }
```

**Isolate the source machine:**

```powershell
# Disable the computer account to prevent domain authentication
Disable-ADAccount -Identity "WS01$"

# Or move to a quarantine OU with restricted GPO
Move-ADObject -Identity (Get-ADComputer "WS01").DistinguishedName `
    -TargetPath "OU=Quarantine,DC=lab,DC=local"
```

### Forensics — Evidence Preservation

**Export relevant event logs before they rotate:**

```powershell
# Export Security event log for the attack window
$ExportPath = "C:\ForensicEvidence\Security-$(Get-Date -Format 'yyyyMMdd-HHmmss').evtx"
New-Item -Path (Split-Path $ExportPath) -ItemType Directory -Force | Out-Null

wevtutil epl Security $ExportPath

Write-Host "[+] Security log exported to $ExportPath" -ForegroundColor Green

# Export specific events for the incident report
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = @(4624, 4672, 4720, 4728, 4732)
    StartTime = (Get-Date).AddHours(-2)
} -ErrorAction SilentlyContinue |
    Export-Csv "C:\ForensicEvidence\PrivEsc-Events-$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
```

### Recovery

**Audit all group membership changes in the last N days:**

```powershell
# Use the SOC query script for a broader look
.\scripts\soc-queries\Get-PrivilegeEscalation.ps1 -Hours 168

# Check for any other persistence mechanisms
# New scheduled tasks
Get-ScheduledTask | Where-Object {
    $_.Date -and [DateTime]$_.Date -gt (Get-Date).AddDays(-1)
} | Select-Object TaskName, TaskPath, Date, Author

# New services
Get-WinEvent -FilterHashtable @{
    LogName   = "System"
    Id        = 7045
    StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        ServiceName = $_.Properties[0].Value
        ImagePath   = $_.Properties[1].Value
        AccountName = $_.Properties[4].Value
    }
} | Format-Table -AutoSize

# Check for suspicious processes that may indicate ongoing compromise
.\scripts\soc-queries\Get-SuspiciousProcesses.ps1 -Hours 24
```

**Verify no other persistence exists:**

```powershell
# List all accounts created in the last 7 days
Get-ADUser -Filter { whenCreated -gt $((Get-Date).AddDays(-7)) } -Properties Description, whenCreated, MemberOf |
    Select-Object SamAccountName, Description, whenCreated

# List all group membership changes in the last 7 days
.\scripts\soc-queries\Get-PrivilegeEscalation.ps1 -Hours 168

# Check for accounts in high-value groups that don't belong
$HighValueGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
foreach ($Group in $HighValueGroups) {
    Write-Host "`n[*] Members of $Group`:" -ForegroundColor Cyan
    Get-ADGroupMember -Identity $Group | Select-Object Name, SamAccountName, objectClass | Format-Table -AutoSize
}
```

### Post-Incident

**Strengthen defenses based on findings:**

```powershell
# Review who currently has privileged access
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName

# Implement privileged group change alerting:
# The Get-PrivilegeEscalation.ps1 script should be scheduled to run periodically
# Example: Run every 15 minutes via Task Scheduler and alert on new findings

# Review least-privilege policies:
# - Are there accounts in Domain Admins that don't need to be?
# - Are service accounts using privileged groups unnecessarily?
# - Is there a process for approving privileged group changes?

# Document the incident:
# - Timeline of attacker actions
# - How access was gained (initial access vector)
# - What privileges were obtained
# - What persistence was established
# - Actions taken to contain and remediate
# - Recommendations for prevention
```

---

## 6. Key Takeaways

### Why Privilege Escalation Is Always High Severity

Privilege escalation means the attacker has already bypassed initial defenses and is actively expanding access. Unlike brute-force attempts (which may fail), privilege escalation indicates:

- **Valid credentials were obtained** — the initial access was successful
- **The attacker has domain knowledge** — they know which groups to target
- **Impact is immediate** — Domain Admin access enables full domain compromise
- **Persistence is likely** — attackers who escalate privileges typically establish backup access

Every privilege escalation event warrants immediate investigation, even if it turns out to be a legitimate administrative action.

### SOC Analyst Skills Demonstrated

| Skill | How This Scenario Uses It |
|---|---|
| **Event correlation** | Linking 4624, 4672, 4720, 4728, and 4732 events into a single attack chain |
| **Timeline reconstruction** | Building the chronological sequence from initial access through persistence |
| **Kill chain analysis** | Mapping observed events to Initial Access, Discovery, Privilege Escalation, and Persistence stages |
| **MITRE ATT&CK mapping** | Identifying T1078, T1087, T1098, and T1136 techniques from event data |
| **Incident response** | Executing containment (disable account, revoke sessions) and recovery (audit, persistence check) |
| **PowerShell forensics** | Parsing event log XML, querying AD, and building investigation scripts |

### How This Maps to Real-World SOC Work

**Tier 1 (Alert Triage):**
- Receive alert for sensitive group membership change (4728 for Domain Admins)
- Run `scripts/soc-queries/Get-PrivilegeEscalation.ps1` to confirm
- Verify the change was not part of an approved change request
- Escalate to Tier 2 with initial timeline

**Tier 2 (Investigation):**
- Build full attack timeline from event logs (Steps 1-6 above)
- Determine scope: which accounts were affected, what was accessed
- Check for persistence: backdoor accounts, scheduled tasks, services
- Execute containment: disable accounts, revoke sessions, isolate hosts
- Coordinate with system administrators for recovery

**Post-Incident:**
- Document the complete attack chain for the incident report
- Recommend monitoring improvements (automated alerting on 4728 for sensitive groups)
- Review least-privilege policies and privileged access management
- Update detection rules based on observed attacker techniques

### Connection to Compliance Frameworks

Detecting unauthorized privilege escalation is required by most security standards:

- **NIST 800-53 AC-6** — Least Privilege: monitor for privilege escalation attempts
- **CIS Controls 5/6** — Account Management: detect unauthorized account changes
- **PCI DSS 10.2.5** — Log all changes to identification and authentication mechanisms
- **SOC 2 CC6.1** — Logical access controls: detect and respond to unauthorized access
