#Requires -RunAsAdministrator
#Requires -Module ActiveDirectory
#Requires -Module GroupPolicy
<#
.SYNOPSIS
    Configures Windows Event Forwarding with DC01 as the centralized collector.

.DESCRIPTION
    Sets up source-initiated Windows Event Forwarding (WEF) so that all domain
    workstations push security-relevant logs to DC01's "Forwarded Events" log.

    Subscriptions created:
    - Security: Failed/successful logons, lockouts, account changes, privilege use
    - Sysmon: All process, network, and file telemetry from endpoints
    - PowerShell: Script block logging and module logging events
    - System: Service installations and unexpected shutdowns

    This script also creates a GPO to configure workstation WinRM services to
    forward events to DC01 automatically.

    WHY SOURCE-INITIATED SUBSCRIPTIONS:
    Source-initiated subscriptions (workstations push to collector) are the
    standard enterprise pattern. They scale better than collector-initiated
    because the collector does not need to enumerate or contact each source.
    They work across subnets and VLANs without firewall exceptions from the
    collector to every endpoint. New machines automatically start forwarding
    once they receive the GPO — no collector reconfiguration needed.

    WHY THESE EVENTS MATTER FOR SOC:
    - Security log: Failed logons (4625) reveal brute-force attempts; account
      lockouts (4740) show the impact; privilege use (4672) catches admin abuse;
      account management (4720-4726) detects persistence via new accounts.
    - Sysmon: Process creation, network connections, and registry changes provide
      the endpoint telemetry that a SIEM or analyst needs for threat hunting.
    - PowerShell: Script block logging (4104) captures the actual code executed,
      even if obfuscated — critical for detecting fileless malware.
    - System: Service installations (7045) are a common persistence mechanism.

    HOW THIS FEEDS INTO PHASE 3 SOC SCENARIOS:
    The SOC query scripts in scripts/soc-queries/ run against the Forwarded Events
    log on DC01, providing a single-pane view across all endpoints. Phase 3
    attack simulations generate events that flow through WEF to the collector,
    where analysts can detect and investigate them.

.NOTES
    Run this script on DC01 (the domain controller that will act as the collector).
    Workstations will begin forwarding after they receive the GPO and perform
    a group policy refresh (gpupdate /force).
#>

Import-Module ActiveDirectory
Import-Module GroupPolicy

$DomainDN    = "DC=lab,DC=local"
$CorporateDN = "OU=Corporate,$DomainDN"
$DomainFQDN  = "lab.local"
$CollectorURL = "Server=http://DC01.$DomainFQDN`:5985/wsman/SubscriptionManager/WEC"

# ── 1. Enable Windows Event Collector Service ─────────────────────────
Write-Host "[*] Enabling Windows Event Collector service..." -ForegroundColor Cyan

$WecService = Get-Service -Name "Wecsvc" -ErrorAction SilentlyContinue
if ($WecService -and $WecService.Status -eq "Running") {
    Write-Host "[+] Windows Event Collector service is already running." -ForegroundColor Green
} else {
    # wecutil qc enables the service and configures it for delayed auto-start
    & wecutil qc /q
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Windows Event Collector service enabled." -ForegroundColor Green
    } else {
        Write-Host "[-] Failed to enable Windows Event Collector service." -ForegroundColor Red
        exit 1
    }
}

# ── 2. Configure WinRM Service ────────────────────────────────────────
# WinRM (Windows Remote Management) — Microsoft's implementation of the WS-Management
# protocol. It's the transport layer that carries event data from source workstations
# to the collector. WEF rides on top of WinRM over HTTP port 5985 (or HTTPS 5986).
Write-Host "`n[*] Configuring WinRM service for event forwarding..." -ForegroundColor Cyan

$WinRMService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
if ($WinRMService -and $WinRMService.Status -eq "Running") {
    Write-Host "[+] WinRM service is already running." -ForegroundColor Green
} else {
    & winrm quickconfig -q 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] WinRM service configured." -ForegroundColor Green
    } else {
        Write-Host "[!] WinRM configuration returned warnings (may already be configured)." -ForegroundColor Yellow
    }
}

# ── 3. Create Event Subscriptions ─────────────────────────────────────
Write-Host "`n[*] Creating event forwarding subscriptions..." -ForegroundColor Cyan

# Helper function to create a source-initiated subscription via XML
function New-WEFSubscription {
    param(
        [string]$Name,
        [string]$Description,
        [string]$QueryXml,
        [string]$LogFile = "ForwardedEvents"
    )

    # Check if subscription already exists
    $existing = & wecutil gs $Name 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Subscription '$Name' already exists. Skipping." -ForegroundColor Green
        return
    }

    # Build the subscription XML for source-initiated delivery
    $subscriptionXml = @"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>$Name</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>$Description</Description>
    <Enabled>true</Enabled>
    <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
    <!-- ConfigurationMode "Normal" — balanced between latency and bandwidth.
         MinLatency would forward events within seconds (real-time, high overhead).
         MinBandwidth batches events over hours (low overhead, but stale data).
         Normal is the standard enterprise choice for SOC monitoring. -->
    <ConfigurationMode>Normal</ConfigurationMode>
    <Delivery Mode="Push">
        <Batching>
            <!-- MaxLatencyTime 60000ms (1 minute) — events batch on the source
                 for up to 60 seconds before being pushed to the collector. This
                 balances near-real-time visibility with network efficiency. -->
            <MaxLatencyTime>60000</MaxLatencyTime>
        </Batching>
    </Delivery>
    <Query>
        <![CDATA[
$QueryXml
        ]]>
    </Query>
    <ReadExistingEvents>false</ReadExistingEvents>
    <TransportName>HTTP</TransportName>
    <ContentFormat>RenderedText</ContentFormat>
    <Locale Language="en-US"/>
    <LogFile>$LogFile</LogFile>
    <!-- SDDL (Security Descriptor Definition Language) — an access control string
         that defines who can push events to this subscription.
         (A;;GA;;;DC) = Allow Generic All to Domain Computers
         (A;;GA;;;NS) = Allow Generic All to Network Service
         This means any domain-joined computer can forward events to this collector. -->
    <AllowedSourceDomainComputers>O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)</AllowedSourceDomainComputers>
</Subscription>
"@

    # Write subscription XML to a temp file and create via wecutil
    $tempFile = [System.IO.Path]::GetTempFileName()
    $subscriptionXml | Set-Content -Path $tempFile -Encoding UTF8

    & wecutil cs $tempFile 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Created subscription: $Name" -ForegroundColor Green
    } else {
        Write-Host "[-] Failed to create subscription: $Name" -ForegroundColor Red
    }

    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
}

# ── 3a. Security Log Subscription ─────────────────────────────────────
# Event IDs: 4624 (logon), 4625 (failed logon), 4740 (lockout),
#            4720/4722/4725/4726 (account management), 4672 (privilege use),
#            4719 (audit policy change)
Write-Host "[*] Subscription: SOC-Security-Events" -ForegroundColor Cyan

$SecurityQuery = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624 or EventID=4625 or EventID=4740 or
                EventID=4720 or EventID=4722 or EventID=4725 or
                EventID=4726 or EventID=4672 or EventID=4719 or
                EventID=4728 or EventID=4732)]]
    </Select>
  </Query>
</QueryList>
"@

New-WEFSubscription -Name "SOC-Security-Events" `
    -Description "Failed/successful logons, lockouts, account changes, privilege use, policy changes" `
    -QueryXml $SecurityQuery

# ── 3b. Sysmon Subscription ───────────────────────────────────────────
# All Sysmon events from endpoints that have Sysmon installed (script 08)
Write-Host "[*] Subscription: SOC-Sysmon-Events" -ForegroundColor Cyan

$SysmonQuery = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
  </Query>
</QueryList>
"@

New-WEFSubscription -Name "SOC-Sysmon-Events" `
    -Description "All Sysmon telemetry (process creation, network, file, registry events)" `
    -QueryXml $SysmonQuery

# ── 3c. PowerShell Subscription ───────────────────────────────────────
# Event ID 4104: Script block logging captures actual PowerShell code executed
# Module logging events provide additional coverage
Write-Host "[*] Subscription: SOC-PowerShell-Events" -ForegroundColor Cyan

$PowerShellQuery = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-PowerShell/Operational">
    <Select Path="Microsoft-Windows-PowerShell/Operational">
      *[System[(EventID=4104 or EventID=4103)]]
    </Select>
  </Query>
</QueryList>
"@

New-WEFSubscription -Name "SOC-PowerShell-Events" `
    -Description "Script block logging (4104) and module logging (4103) for fileless malware detection" `
    -QueryXml $PowerShellQuery

# ── 3d. System Log Subscription ───────────────────────────────────────
# Event ID 7045: New service installation (persistence mechanism)
# Event ID 6008: Unexpected shutdown (may indicate tampering)
Write-Host "[*] Subscription: SOC-System-Events" -ForegroundColor Cyan

$SystemQuery = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">
      *[System[(EventID=7045 or EventID=6008)]]
    </Select>
  </Query>
</QueryList>
"@

New-WEFSubscription -Name "SOC-System-Events" `
    -Description "Service installations (7045) and unexpected shutdowns (6008)" `
    -QueryXml $SystemQuery

# ── 4. Configure Workstation GPO for Event Forwarding ──────────────────
Write-Host "`n[*] Configuring GPO for workstation event forwarding..." -ForegroundColor Cyan

$GPOName = "LAB-Event-Forwarding"

# Check if GPO already exists
$ExistingGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
if ($ExistingGPO) {
    Write-Host "[+] GPO '$GPOName' already exists. Updating settings..." -ForegroundColor Green
} else {
    $ExistingGPO = New-GPO -Name $GPOName -Comment "Configures workstations to forward events to DC01 via WEF"
    Write-Host "[+] Created GPO: $GPOName" -ForegroundColor Green
}

# Set the Subscription Manager URL — tells workstations where to send events
Set-GPRegistryValue -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" `
    -ValueName "1" -Type String -Value $CollectorURL

# Enable WinRM service on workstations via GPO
Set-GPRegistryValue -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" `
    -ValueName "AllowAutoConfig" -Type DWord -Value 1

# Allow WinRM on all IPs (IPv4 and IPv6 filters)
Set-GPRegistryValue -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" `
    -ValueName "IPv4Filter" -Type String -Value "*"

Set-GPRegistryValue -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" `
    -ValueName "IPv6Filter" -Type String -Value "*"

# Link to Corporate OU (covers all workstation OUs)
New-GPLink -Name $GPOName -Target $CorporateDN -LinkEnabled Yes -ErrorAction SilentlyContinue
Write-Host "[+] Linked '$GPOName' to $CorporateDN" -ForegroundColor Green

Write-Host "[+] Workstation GPO configured:" -ForegroundColor Green
Write-Host "      Subscription Manager: $CollectorURL" -ForegroundColor White
Write-Host "      WinRM auto-config:    Enabled" -ForegroundColor White
Write-Host "      Target OU:            $CorporateDN" -ForegroundColor White

# ── 5. Display Subscription Status and Verification ───────────────────
Write-Host "`n[*] Windows Event Forwarding configuration complete." -ForegroundColor Cyan
Write-Host "[*] Subscriptions created:" -ForegroundColor Cyan

$Subscriptions = @("SOC-Security-Events", "SOC-Sysmon-Events", "SOC-PowerShell-Events", "SOC-System-Events")
foreach ($sub in $Subscriptions) {
    Write-Host "    - $sub" -ForegroundColor White
}

Write-Host "`n[*] Verification commands:" -ForegroundColor Cyan
Write-Host "    List subscriptions:     wecutil es" -ForegroundColor White
Write-Host "    Subscription details:   wecutil gs SOC-Security-Events" -ForegroundColor White
Write-Host "    Check sources:          wecutil gr SOC-Security-Events" -ForegroundColor White
Write-Host "    View forwarded events:  Get-WinEvent -LogName ForwardedEvents -MaxEvents 10" -ForegroundColor White
Write-Host "    Force GP refresh:       gpupdate /force (on workstations)" -ForegroundColor White
Write-Host "`n[*] Workstations will begin forwarding after group policy refresh." -ForegroundColor Cyan
