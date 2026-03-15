# Brute Force Detection Playbook

SOC detection and response playbook for credential brute-force and password spraying attacks in the lab.local domain.

---

## 1. Scenario Overview

| Field | Details |
|---|---|
| **Attack Type** | Brute Force / Password Spraying |
| **MITRE ATT&CK** | [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/), [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| **Severity** | Medium-High |
| **Data Sources** | Windows Security Event Log |
| **Key Event IDs** | 4625 (Failed Logon), 4740 (Account Lockout), 4624 (Successful Logon) |
| **Detection Scripts** | `scripts/soc-queries/Get-FailedLogons.ps1`, `scripts/soc-queries/Get-AccountLockouts.ps1` |

### What Makes This Scenario Important

Brute-force attacks are the most common credential attack SOC analysts encounter. They appear in every environment — from automated botnets scanning RDP to targeted password spraying against VPN portals. A SOC analyst must be able to:

1. Detect the attack pattern in event logs
2. Distinguish brute force from password spraying
3. Determine if any credentials were compromised
4. Execute containment and response actions

---

## 2. Attack Simulation

### Brute Force Mode (Default)

Cycles through all passwords for one user before moving to the next. This creates a burst of failed logons for each account and typically triggers account lockout.

```powershell
# Default: 8 attempts per user against 3 accounts
.\scenarios\01-brute-force\Simulate-BruteForce.ps1

# Custom targets with fewer attempts (stays below lockout threshold)
.\scenarios\01-brute-force\Simulate-BruteForce.ps1 -TargetUsers @("emma.wilson", "frank.taylor") -AttemptsPerUser 4
```

### Password Spray Mode

Tries one password against all users before moving to the next password. This is harder to detect because each account only sees one failure per round.

```powershell
# Password spray with default timing
.\scenarios\01-brute-force\Simulate-BruteForce.ps1 -SprayMode

# Low-and-slow spray — simulates a careful attacker
.\scenarios\01-brute-force\Simulate-BruteForce.ps1 -SprayMode -AttemptsPerUser 3 -DelaySeconds 10
```

### Expected Telemetry

| Mode | Event IDs Generated | Pattern |
|---|---|---|
| Brute Force | 4625 (many per user), 4740 (lockout) | Burst of failures for one account, then the next |
| Password Spray | 4625 (spread across users) | One failure per account per round, evenly spaced |

---

## 3. Detection

### Step 1: Check for Failed Logons

Run the failed logon detection script to identify accounts with excessive failures:

```powershell
.\scripts\soc-queries\Get-FailedLogons.ps1 -Hours 1 -Threshold 3
```

Expected output for a brute-force attack:

```
[!] Found 24 failed logon event(s).

[*] Failed logon details:
TimeCreated           TargetUserName  SourceIP       LogonType  FailureReason
-----------           --------------  --------       ---------  -------------
2024-03-15 14:32:01   alice.johnson   192.168.20.10  Network    Wrong password
2024-03-15 14:32:03   alice.johnson   192.168.20.10  Network    Wrong password
...

[!] ALERT: The following source/user combinations exceed the threshold:
SourceIP       TargetUserName  Count
--------       --------------  -----
192.168.20.10  alice.johnson   8
192.168.20.10  bob.williams    8
192.168.20.10  carol.davis     8
```

### Step 2: Check for Account Lockouts

```powershell
.\scripts\soc-queries\Get-AccountLockouts.ps1 -Hours 1
```

Lockouts confirm the attack exceeded the threshold and accounts are now locked — this is both a detection signal and a user impact indicator.

### Step 3: Identify the Attack Pattern

**Brute Force Indicators:**
- Many failed logons (>5) for the same account from the same source
- Failures clustered in a short time window
- Account lockout events following the burst

**Password Spray Indicators:**
- Failed logons spread across multiple accounts
- Only 1-2 failures per account (below lockout threshold)
- Same source IP targeting many different usernames
- Failures evenly spaced over time

### Raw Event Log Queries

For analysts who want to understand the underlying queries or need to modify them:

```powershell
# Query failed logons directly (Event ID 4625)
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4625
    StartTime = (Get-Date).AddHours(-1)
} | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    $Data = $Xml.Event.EventData.Data
    [PSCustomObject]@{
        Time     = $_.TimeCreated
        User     = ($Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
        SourceIP = ($Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
        Reason   = ($Data | Where-Object { $_.Name -eq "SubStatus" }).'#text'
    }
}

# Query account lockouts directly (Event ID 4740)
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4740
    StartTime = (Get-Date).AddHours(-1)
} | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    $Data = $Xml.Event.EventData.Data
    [PSCustomObject]@{
        Time   = $_.TimeCreated
        User   = ($Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
        Source = ($Data | Where-Object { $_.Name -eq "TargetDomainName" }).'#text'
    }
}

# Count failures per source IP (detect spraying across accounts)
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4625
    StartTime = (Get-Date).AddHours(-1)
} | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
} | Group-Object | Sort-Object Count -Descending | Select-Object Name, Count
```

---

## 4. Investigation

Once a brute-force or spray attack is detected, work through these investigation steps to determine scope and impact.

### Step 1: Identify the Source

Determine whether the source IP belongs to an internal host or an external attacker:

```powershell
# Resolve the source IP to a hostname
Resolve-DnsName -Name "192.168.20.10" -ErrorAction SilentlyContinue

# Check if the IP is in the lab network ranges
# VLAN 10: 192.168.10.0/24 (Servers)
# VLAN 20: 192.168.20.0/24 (Workstations)
# VLAN 30: 192.168.30.0/24 (Management)

# List all DHCP leases to identify the host
Get-DhcpServerv4Lease -ScopeId "192.168.20.0" | Where-Object { $_.IPAddress -eq "192.168.20.10" }
```

**If internal:** The host may be compromised and used as a pivot point. Investigate who is logged into that machine and look for malware indicators.

**If external:** The attacker is reaching the domain controller from outside the network. Check firewall logs and VPN access logs.

### Step 2: Check for Successful Logon After Failures

This is the critical question — did the attacker guess a correct password?

```powershell
# Look for Event ID 4624 (successful logon) following 4625 (failed logon)
# for the same target users
$TargetUsers = @("alice.johnson", "bob.williams", "carol.davis")

$SuccessfulLogons = Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4624
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    $Data = $Xml.Event.EventData.Data
    $User = ($Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
    $IP   = ($Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
    $Type = ($Data | Where-Object { $_.Name -eq "LogonType" }).'#text'

    if ($User -in $TargetUsers) {
        [PSCustomObject]@{
            TimeCreated    = $_.TimeCreated
            TargetUserName = $User
            SourceIP       = $IP
            LogonType      = $Type
        }
    }
}

if ($SuccessfulLogons) {
    Write-Host "[!] CRITICAL: Successful logon detected for targeted accounts:" -ForegroundColor Red
    $SuccessfulLogons | Format-Table -AutoSize
} else {
    Write-Host "[+] No successful logons found for targeted accounts." -ForegroundColor Green
}
```

### Step 3: Build the Attack Timeline

Understand when the attack started, how long it lasted, and how many accounts were targeted:

```powershell
# Get the timeline of the attack
$FailedEvents = Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4625
    StartTime = (Get-Date).AddHours(-2)
} -ErrorAction SilentlyContinue

$FirstAttempt = ($FailedEvents | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
$LastAttempt  = ($FailedEvents | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
$UniqueUsers  = ($FailedEvents | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
} | Select-Object -Unique).Count

Write-Host "[*] Attack timeline:" -ForegroundColor Cyan
Write-Host "    First attempt:  $FirstAttempt" -ForegroundColor White
Write-Host "    Last attempt:   $LastAttempt" -ForegroundColor White
Write-Host "    Duration:       $(($LastAttempt - $FirstAttempt).ToString('hh\:mm\:ss'))" -ForegroundColor White
Write-Host "    Total attempts: $($FailedEvents.Count)" -ForegroundColor White
Write-Host "    Unique users:   $UniqueUsers" -ForegroundColor White
```

### Step 4: Check for Lateral Movement

If a successful logon was detected, check whether the compromised account was used to access other systems:

```powershell
# Check for logon events on other machines from the compromised account
# Run this from DC01 to check forwarded events
$CompromisedUser = "alice.johnson"

Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4624
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    $Data = $Xml.Event.EventData.Data
    $User = ($Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'

    if ($User -eq $CompromisedUser) {
        [PSCustomObject]@{
            Time      = $_.TimeCreated
            User      = $User
            SourceIP  = ($Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
            LogonType = ($Data | Where-Object { $_.Name -eq "LogonType" }).'#text'
            Computer  = $_.MachineName
        }
    }
} | Format-Table -AutoSize

# Check for privilege escalation by the compromised account
.\scripts\soc-queries\Get-PrivilegeEscalation.ps1 -Hours 1
```

---

## 5. Response Actions

### Immediate Actions (First 15 Minutes)

**Reset compromised passwords and unlock accounts:**

```powershell
# Unlock the targeted accounts
Unlock-ADAccount -Identity "alice.johnson"
Unlock-ADAccount -Identity "bob.williams"
Unlock-ADAccount -Identity "carol.davis"

# If a successful logon was detected, force password reset immediately
Set-ADAccountPassword -Identity "alice.johnson" -Reset -NewPassword (
    Read-Host "Enter new password for alice.johnson" -AsSecureString
)

# Verify account status
Get-ADUser -Identity "alice.johnson" -Properties LockedOut, PasswordLastSet |
    Select-Object Name, LockedOut, PasswordLastSet
```

### Containment (First Hour)

**Block the source if external, isolate if internal:**

```powershell
# If the source is an external IP — block at the firewall
# (Example using Windows Firewall on the DC; adapt for perimeter firewall)
New-NetFirewallRule -DisplayName "Block Brute Force Source" `
    -Direction Inbound -RemoteAddress "192.168.20.10" `
    -Action Block -Profile Any

# If the source is an internal workstation — disable the computer account
# to prevent domain authentication while investigating
Disable-ADAccount -Identity "WS01$"

# Alternatively, quarantine by moving to a restricted OU
Move-ADObject -Identity (Get-ADComputer "WS01").DistinguishedName `
    -TargetPath "OU=Quarantine,DC=lab,DC=local"
```

### Recovery

**Verify no persistence mechanisms were installed:**

```powershell
# Check for new scheduled tasks created during the attack window
Get-ScheduledTask | Where-Object {
    $_.Date -and [DateTime]$_.Date -gt (Get-Date).AddHours(-2)
} | Select-Object TaskName, TaskPath, Date, Author

# Check for new services created during the attack window
Get-WinEvent -FilterHashtable @{
    LogName   = "System"
    Id        = 7045
    StartTime = (Get-Date).AddHours(-2)
} -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        ServiceName = $_.Properties[0].Value
        ImagePath   = $_.Properties[1].Value
        AccountName = $_.Properties[4].Value
    }
} | Format-Table -AutoSize

# Check for new user accounts created during the attack window
Get-ADUser -Filter { whenCreated -gt $((Get-Date).AddHours(-2)) } |
    Select-Object Name, SamAccountName, whenCreated

# Check group membership changes using the SOC query script
.\scripts\soc-queries\Get-PrivilegeEscalation.ps1 -Hours 2
```

### Post-Incident

**Update defenses based on findings:**

```powershell
# Review current lockout policy
Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutDuration, LockoutObservationWindow

# If the spray attack stayed below threshold, consider lowering it
# (balance security vs. user impact)
# Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 3

# Document the incident
# - Source IP/host
# - Targeted accounts
# - Whether any credentials were compromised
# - Timeline (start, end, duration)
# - Actions taken
```

---

## 6. Key Takeaways

### SOC Analyst Skills Demonstrated

| Skill | How This Scenario Uses It |
|---|---|
| **Log analysis** | Parsing Event IDs 4625, 4740, and 4624 from Security event logs |
| **Pattern recognition** | Distinguishing brute force (burst per account) from password spraying (spread across accounts) |
| **Threat correlation** | Cross-referencing failed logons with successful logons and lateral movement |
| **MITRE ATT&CK mapping** | Identifying T1110.001 and T1110.003 attack techniques |
| **Incident response** | Following a structured detect, investigate, contain, recover workflow |
| **PowerShell proficiency** | Using `Get-WinEvent`, `Get-ADUser`, and event log XML parsing |

### How This Maps to Real-World SOC Work

**Tier 1 (Alert Triage):**
- Receive alert for excessive failed logons
- Run detection scripts to confirm the pattern
- Classify as brute force or password spray
- Escalate with initial findings

**Tier 2 (Investigation):**
- Determine if any credentials were compromised (4624 after 4625)
- Identify and attribute the source
- Build the attack timeline
- Check for lateral movement and persistence
- Execute containment actions

**Post-Incident:**
- Document findings and actions
- Recommend defensive improvements (lockout policy, monitoring rules)
- Update detection thresholds based on the observed attack pattern
